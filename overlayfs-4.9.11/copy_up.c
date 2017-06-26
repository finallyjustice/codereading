/*
 *
 * Copyright (C) 2011 Novell Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/splice.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/fdtable.h>
#include <linux/ratelimit.h>
#include "overlayfs.h"

#define OVL_COPY_UP_CHUNK_SIZE (1 << 20)

static bool __read_mostly ovl_check_copy_up;
module_param_named(check_copy_up, ovl_check_copy_up, bool,
		   S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(ovl_check_copy_up,
		 "Warn on copy-up when causing process also has a R/O fd open");

/* called only by ovl_do_check_copy_up() */
static int ovl_check_fd(const void *data, struct file *f, unsigned int fd)
{
	const struct dentry *dentry = data;

	if (f->f_inode == d_inode(dentry))
		pr_warn_ratelimited("overlayfs: Warning: Copying up %pD, but open R/O on fd %u which will cease to be coherent [pid=%d %s]\n",
				    f, fd, current->pid, current->comm);
	return 0;
}

/*
 * Check the fds open by this process and warn if something like the following
 * scenario is about to occur:
 *
 *	fd1 = open("foo", O_RDONLY);
 *	fd2 = open("foo", O_RDWR);
 */
/* called only by ovl_copy_up_one() */
static void ovl_do_check_copy_up(struct dentry *dentry)
{
	/* for each fd do ovl_check_fd() */
	if (ovl_check_copy_up)
		iterate_fd(current->files, 0, ovl_check_fd, dentry);
}

/*
 * called by:
 * - ovl_copy_up_locked()
 * - ovl_clear_empty()
 *
 * 把old的xattr copy给new
 */
int ovl_copy_xattr(struct dentry *old, struct dentry *new)
{
	ssize_t list_size, size, value_size = 0;
	char *buf, *name, *value = NULL;
	int uninitialized_var(error);
	size_t slen;

	if (!(old->d_inode->i_opflags & IOP_XATTR) ||
	    !(new->d_inode->i_opflags & IOP_XATTR))
		return 0;

	list_size = vfs_listxattr(old, NULL, 0);
	if (list_size <= 0) {
		if (list_size == -EOPNOTSUPP)
			return 0;
		return list_size;
	}

	buf = kzalloc(list_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	list_size = vfs_listxattr(old, buf, list_size);
	if (list_size <= 0) {
		error = list_size;
		goto out;
	}

	for (name = buf; list_size; name += slen) {
		slen = strnlen(name, list_size) + 1;

		/* underlying fs providing us with an broken xattr list? */
		if (WARN_ON(slen > list_size)) {
			error = -EIO;
			break;
		}
		list_size -= slen;

		if (ovl_is_private_xattr(name))
			continue;
retry:
		size = vfs_getxattr(old, name, value, value_size);
		if (size == -ERANGE)
			size = vfs_getxattr(old, name, NULL, 0);

		if (size < 0) {
			error = size;
			break;
		}

		if (size > value_size) {
			void *new;

			new = krealloc(value, size, GFP_KERNEL);
			if (!new) {
				error = -ENOMEM;
				break;
			}
			value = new;
			value_size = size;
			goto retry;
		}

		error = security_inode_copy_up_xattr(name);
		if (error < 0 && error != -EOPNOTSUPP)
			break;
		if (error == 1) {
			error = 0;
			continue; /* Discard */
		}
		error = vfs_setxattr(new, name, value, size, 0);
		if (error)
			break;
	}
	kfree(value);
out:
	kfree(buf);
	return error;
}

/* called only by ovl_copy_up_locked() */
/* 把old的文件数据copy给new */
static int ovl_copy_up_data(struct path *old, struct path *new, loff_t len)
{
	struct file *old_file;
	struct file *new_file;
	loff_t old_pos = 0;
	loff_t new_pos = 0;
	int error = 0;

	if (len == 0)
		return 0;

	old_file = ovl_path_open(old, O_LARGEFILE | O_RDONLY);
	if (IS_ERR(old_file))
		return PTR_ERR(old_file);

	new_file = ovl_path_open(new, O_LARGEFILE | O_WRONLY);
	if (IS_ERR(new_file)) {
		error = PTR_ERR(new_file);
		goto out_fput;
	}

	/* FIXME: copy up sparse files efficiently */
	while (len) {
		size_t this_len = OVL_COPY_UP_CHUNK_SIZE;
		long bytes;

		if (len < this_len)
			this_len = len;

		if (signal_pending_state(TASK_KILLABLE, current)) {
			error = -EINTR;
			break;
		}

		/* splices data directly between two files */
		bytes = do_splice_direct(old_file, &old_pos,
					 new_file, &new_pos,
					 this_len, SPLICE_F_MOVE);
		if (bytes <= 0) {
			error = bytes;
			break;
		}
		WARN_ON(old_pos != new_pos);

		len -= bytes;
	}

	if (!error)
		error = vfs_fsync(new_file, 0);
	fput(new_file);
out_fput:
	fput(old_file);
	return error;
}

/*
 * called by:
 * - ovl_set_attr()
 * - ovl_copy_up_one()
 */
static int ovl_set_timestamps(struct dentry *upperdentry, struct kstat *stat)
{
	struct iattr attr = {
		.ia_valid =
		     ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET | ATTR_MTIME_SET,
		.ia_atime = stat->atime,
		.ia_mtime = stat->mtime,
	};

	/* modify attributes of a filesytem object */
	return notify_change(upperdentry, &attr, NULL);
}

/*
 * called by:
 * - ovl_copy_up_locked()
 * - ovl_clear_empty()
 */
/* 为upperdentry设置stat */
int ovl_set_attr(struct dentry *upperdentry, struct kstat *stat)
{
	int err = 0;

	if (!S_ISLNK(stat->mode)) {
		struct iattr attr = {
			.ia_valid = ATTR_MODE,
			.ia_mode = stat->mode,
		};
		/* modify attributes of a filesytem object */
		err = notify_change(upperdentry, &attr, NULL);
	}
	if (!err) {
		struct iattr attr = {
			.ia_valid = ATTR_UID | ATTR_GID,
			.ia_uid = stat->uid,
			.ia_gid = stat->gid,
		};
		/* modify attributes of a filesytem object */
		err = notify_change(upperdentry, &attr, NULL);
	}
	if (!err)
		ovl_set_timestamps(upperdentry, stat);

	return err;
}

/* called only by ovl_copy_up_one() */
/*
 * 把merged中的dentry的lower的文件(lowerpath)拷贝到upperdir
 * 先在workdir创建临时文件再一次性rename到upperdir
 *
 * upperdir是父文件夹在upper中的dentry 不是merged中的
 * dentry是merged中的 要把其lower copy到upper
 * lowerpath是dentry的lower信息
 *
 * 如果dentry不是文件夹 会设置为opaque!
 */
static int ovl_copy_up_locked(struct dentry *workdir, struct dentry *upperdir,
			      struct dentry *dentry, struct path *lowerpath,
			      struct kstat *stat, const char *link)
{
	struct inode *wdir = workdir->d_inode;
	/* upperdir是父文件夹在upper中的dentry 不是merged中的 */
	struct inode *udir = upperdir->d_inode;
	struct dentry *newdentry = NULL;
	struct dentry *upper = NULL;
	umode_t mode = stat->mode;
	int err;
	const struct cred *old_creds = NULL;
	struct cred *new_creds = NULL;

	/*
	 * ovl_lookup_temp函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 * 第二个参数dentry根本就没用到 文件名基于workdir自己的变量生成的
	 *
	 * K1: 在workdir下创建一个临时dentry,一会儿信息先写入临时dentry,
	 *     再拷贝(rename)到下面的最终dentry
	 */
	newdentry = ovl_lookup_temp(workdir, dentry);
	err = PTR_ERR(newdentry);
	if (IS_ERR(newdentry))
		goto out;

	/*
	 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 *
	 * K2: 在upperdir下创建一个最终dentry
	 */
	upper = lookup_one_len(dentry->d_name.name, upperdir,
			       dentry->d_name.len);
	err = PTR_ERR(upper);
	if (IS_ERR(upper))
		goto out1;

	err = security_inode_copy_up(dentry, &new_creds);
	if (err < 0)
		goto out2;

	if (new_creds)
		old_creds = override_creds(new_creds);

	/* Can't properly set mode on creation because of the umask */
	stat->mode &= S_IFMT;
	/* 在wdir创建newdentry */
	err = ovl_create_real(wdir, newdentry, stat, link, NULL, true);
	stat->mode = mode;

	if (new_creds) {
		revert_creds(old_creds);
		put_cred(new_creds);
	}

	if (err)
		goto out2;

	if (S_ISREG(stat->mode)) {
		struct path upperpath;

		ovl_path_upper(dentry, &upperpath);
		BUG_ON(upperpath.dentry != NULL);
		/* newdentry是在upper新创建的dentry */
		upperpath.dentry = newdentry;

		/* 把数据从lower copy到upper */
		err = ovl_copy_up_data(lowerpath, &upperpath, stat->size);
		if (err)
			goto out_cleanup;
	}

	err = ovl_copy_xattr(lowerpath->dentry, newdentry);
	if (err)
		goto out_cleanup;

	inode_lock(newdentry->d_inode);
	err = ovl_set_attr(newdentry, stat);
	inode_unlock(newdentry->d_inode);
	if (err)
		goto out_cleanup;

	/* 
	 * 核心: 把为upper新创建的文件从workdir放入upper
	 */
	err = ovl_do_rename(wdir, newdentry, udir, upper, 0);
	if (err)
		goto out_cleanup;

	/*
	 * dentry是merged中的dentry
	 * newdentry是upperdir中的dentry
	 */
	/* 把newdentry(upperdir)设置为dentry(merged)的upper */
	ovl_dentry_update(dentry, newdentry);
	/* 把newdentry的inode写入inode(merged)的私有数据 */
	ovl_inode_update(d_inode(dentry), d_inode(newdentry));
	newdentry = NULL;

	/*
	 * Non-directores become opaque when copied up.
	 */
	if (!S_ISDIR(stat->mode))
		ovl_dentry_set_opaque(dentry, true);
out2:
	dput(upper);
out1:
	dput(newdentry);
out:
	return err;

out_cleanup:
	ovl_cleanup(wdir, newdentry);
	goto out2;
}

/*
 * Copy up a single dentry
 *
 * Directory renames only allowed on "pure upper" (already created on
 * upper filesystem, never copied up).  Directories which are on lower or
 * are merged may not be renamed.  For these -EXDEV is returned and
 * userspace has to deal with it.  This means, when copying up a
 * directory we can rely on it and ancestors being stable.
 *
 * Non-directory renames start with copy up of source if necessary.  The
 * actual rename will only proceed once the copy up was successful.  Copy
 * up uses upper parent i_mutex for exclusion.  Since rename can change
 * d_parent it is possible that the copy up will lock the old parent.  At
 * that point the file will have already been copied up anyway.
 */
/*
 * called by:
 * - ovl_copy_up()
 * - ovl_copy_up_truncate()
 */
/*
 * 把dentry的lowerpath的文件拷贝到upperdir
 *
 * dentry是merged中的 要把其lower copy到upper
 * parent是在merged中的dentry的父文件夹
 * parent是dentry的父文件夹
 * lowerpath是dentry的lower信息
 */
int ovl_copy_up_one(struct dentry *parent, struct dentry *dentry,
		    struct path *lowerpath, struct kstat *stat)
{
	DEFINE_DELAYED_CALL(done);
	struct dentry *workdir = ovl_workdir(dentry);
	int err;
	struct kstat pstat;
	struct path parentpath;
	struct dentry *lowerdentry = lowerpath->dentry;
	struct dentry *upperdir;
	struct dentry *upperdentry;
	const char *link = NULL;

	if (WARN_ON(!workdir))
		return -EROFS;

	ovl_do_check_copy_up(lowerdentry);

	/* 把parent的upper的信息放入path parent是在merged中的dentry的父文件夹 */
	ovl_path_upper(parent, &parentpath);
	/* upperdir是父文件夹在upper中的dentry 不是merged中的 */
	upperdir = parentpath.dentry;

	err = vfs_getattr(&parentpath, &pstat);
	if (err)
		return err;

	if (S_ISLNK(stat->mode)) {
		link = vfs_get_link(lowerdentry, &done);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}

	err = -EIO;
	/* 在rename操作中,对source与target各自的父目录进行加锁的函数是lock_rename() */
	if (lock_rename(workdir, upperdir) != NULL) {
		pr_err("overlayfs: failed to lock workdir+upperdir\n");
		goto out_unlock;
	}
	upperdentry = ovl_dentry_upper(dentry);
	/* 因为还没copyup, upperdentry应该还是NULL */
	if (upperdentry) {
		/* Raced with another copy-up?  Nothing to do, then... */
		err = 0;
		goto out_unlock;
	}

	/*
	 * upperdir是父文件夹在upper中的dentry 不是merged中的
	 * dentry是merged中的 要把其lower copy到upper
	 * lowerpath是dentry的lower信息
	 */
	err = ovl_copy_up_locked(workdir, upperdir, dentry, lowerpath,
				 stat, link);
	if (!err) {
		/* Restore timestamps on parent (best effort) */
		ovl_set_timestamps(upperdir, &pstat);
	}
out_unlock:
	unlock_rename(workdir, upperdir);
	do_delayed_call(&done);

	return err;
}

/*
 * called by:
 * - ovl_create_or_link()
 * - ovl_link()
 * - ovl_do_remove()
 * - ovl_rename2()
 * - ovl_copy_up_truncate()
 * - ovl_setattr()
 * - ovl_xattr_set()
 * - ovl_open_maybe_copy_up()
 *
 * 把文件从lower copy到 upper
 * 如果dentry的祖先文件夹不在upper就先把祖先文件夹copy到upper
 */
int ovl_copy_up(struct dentry *dentry)
{
	int err = 0;
	const struct cred *old_cred = ovl_override_creds(dentry->d_sb);

	/* while的每次iteration都从头从dentry往祖先节点找 */
	while (!err) {
		struct dentry *next;
		struct dentry *parent;
		struct path lowerpath;
		struct kstat stat;
		/* type可能包含__OVL_PATH_PURE,__OVL_PATH_MERGE, __OVL_PATH_UPPER */
		enum ovl_path_type type = ovl_path_type(dentry);

		/* 如果已经有upper了就不用copy up了 */
		if (OVL_TYPE_UPPER(type))
			break;

		next = dget(dentry);
		/* find the topmost dentry not yet copied up */
		for (;;) {
			parent = dget_parent(next);

			type = ovl_path_type(parent);
			/* 找到第一个有upper的parent dentry */
			if (OVL_TYPE_UPPER(type))
				break;

			dput(next);
			next = parent;
		}

		/* 此时next是第一个没有upper的dentry */
		/* 把merged中dentry (next)的lower的信息读入path (lowerpath) */
		ovl_path_lower(next, &lowerpath);
		err = vfs_getattr(&lowerpath, &stat);
		if (!err) // lowerpath是next的path
			err = ovl_copy_up_one(parent, next, &lowerpath, &stat);

		dput(parent);
		dput(next);
	}
	revert_creds(old_cred);

	return err;
}

/*
 * 文件是在以下情况copy up的
 * vfs_open()-->
 * struct dentry_operations.d_real()=ovl_d_real()-->
 * ovl_open_maybe_copy_up()-->
 * ovl_copy_up()
 */
