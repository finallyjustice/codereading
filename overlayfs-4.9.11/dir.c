/*
 *
 * Copyright (C) 2011 Novell Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/atomic.h>
#include "overlayfs.h"

/* 在父文件夹wdir中删除子文件(夹)wdentry */
void ovl_cleanup(struct inode *wdir, struct dentry *wdentry)
{
	int err;

	dget(wdentry);
	if (d_is_dir(wdentry))
		err = ovl_do_rmdir(wdir, wdentry); // 调用vfs_rmdir()
	else
		err = ovl_do_unlink(wdir, wdentry); // 调用vfs_unlink()
	dput(wdentry);

	if (err) {
		pr_err("overlayfs: cleanup of '%pd2' failed (%i)\n",
		       wdentry, err);
	}
}

/* 
 * ovl_lookup_temp函数首先在父目录下根据名字查找dentry结构,
 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
 * 第二个参数dentry根本就没用到 文件名基于workdir自己的变量生成的
 */
struct dentry *ovl_lookup_temp(struct dentry *workdir, struct dentry *dentry)
{
	struct dentry *temp;
	char name[20];
	static atomic_t temp_id = ATOMIC_INIT(0);

	/* counter is allowed to wrap, since temp dentries are ephemeral */
	snprintf(name, sizeof(name), "#%x", atomic_inc_return(&temp_id));

	/* 
	 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 */
	temp = lookup_one_len(name, workdir, strlen(name));
	if (!IS_ERR(temp) && temp->d_inode) {
		pr_err("overlayfs: workdir/%s already exists\n", name);
		dput(temp);
		temp = ERR_PTR(-EIO);
	}

	return temp;
}

/* caller holds i_mutex on workdir */
/* called only by ovl_remove_and_whiteout() */
static struct dentry *ovl_whiteout(struct dentry *workdir,
				   struct dentry *dentry)
{
	int err;
	struct dentry *whiteout;
	struct inode *wdir = workdir->d_inode;

	/* 
	 * ovl_lookup_temp函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 * 第二个参数dentry根本就没用到 文件名基于workdir自己的变量生成的
	 */
	whiteout = ovl_lookup_temp(workdir, dentry);
	if (IS_ERR(whiteout))
		return whiteout;

	/* 似乎就是为dentry在dir中创建一个0,0的char dev文件 */
	err = ovl_do_whiteout(wdir, whiteout);
	if (err) {
		dput(whiteout);
		whiteout = ERR_PTR(err);
	}

	return whiteout;
}

/*
 * called by:
 * - ovl_copy_up_locked()
 * - ovl_create_upper()
 * - ovl_clear_empty()
 * - ovl_create_over_whiteout()
 * - ovl_workdir_create()
 *
 * 在dir创建newdentry的文件实体
 */
int ovl_create_real(struct inode *dir, struct dentry *newdentry,
		    struct kstat *stat, const char *link,
		    struct dentry *hardlink, bool debug)
{
	int err;

	if (newdentry->d_inode)
		return -ESTALE;

	if (hardlink) {
		err = ovl_do_link(hardlink, dir, newdentry, debug);
	} else {
		switch (stat->mode & S_IFMT) {
		case S_IFREG:
			err = ovl_do_create(dir, newdentry, stat->mode, debug); // 调用vfs_create()
			break;

		case S_IFDIR:
			err = ovl_do_mkdir(dir, newdentry, stat->mode, debug); // 调用vfs_mkdir()
			break;

		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
		case S_IFSOCK:
			err = ovl_do_mknod(dir, newdentry,
					   stat->mode, stat->rdev, debug); // 调用vfs_mknod()
			break;

		case S_IFLNK:
			err = ovl_do_symlink(dir, newdentry, link, debug); // 调用vfs_symlink()
			break;

		default:
			err = -EPERM;
		}
	}
	if (!err && WARN_ON(!newdentry->d_inode)) {
		/*
		 * Not quite sure if non-instantiated dentry is legal or not.
		 * VFS doesn't seem to care so check and warn here.
		 */
		err = -ENOENT;
	}
	return err;
}

/* 通过vfs_setxattr() */
static int ovl_set_opaque(struct dentry *upperdentry)
{
	/* 调用 vfs_setxattr() */
	return ovl_do_setxattr(upperdentry, OVL_XATTR_OPAQUE, "y", 1, 0);
}

/* 通过vfs_removexattr() */
static void ovl_remove_opaque(struct dentry *upperdentry)
{
	int err;

	/* 调用 vfs_removexattr() */
	err = ovl_do_removexattr(upperdentry, OVL_XATTR_OPAQUE);
	if (err) {
		pr_warn("overlayfs: failed to remove opaque from '%s' (%i)\n",
			upperdentry->d_name.name, err);
	}
}

/* struct inode_operations ovl_dir_inode_operations.getattr() */
/* 获得merged dentry真实的lower或upper的attr到stat*/
/* mnt就没用到 */
static int ovl_dir_getattr(struct vfsmount *mnt, struct dentry *dentry,
			 struct kstat *stat)
{
	int err;
	enum ovl_path_type type;
	struct path realpath;
	const struct cred *old_cred;

	/*
	 * dentry是merged中的dentry
	 * 如果没有upper则把lower的信息写入path
	 * 否则把upper的信息写入path
	 */
	type = ovl_path_real(dentry, &realpath);
	old_cred = ovl_override_creds(dentry->d_sb);
	err = vfs_getattr(&realpath, stat);
	revert_creds(old_cred);
	if (err)
		return err;

	stat->dev = dentry->d_sb->s_dev;
	stat->ino = dentry->d_inode->i_ino;

	/*
	 * It's probably not worth it to count subdirs to get the
	 * correct link count.  nlink=1 seems to pacify 'find' and
	 * other utilities.
	 */
	if (OVL_TYPE_MERGE(type))
		stat->nlink = 1;

	return 0;
}

/* Common operations required to be done after creation of file on upper */
/* d_instantiate() - Fill in inode information in the entry */
/* called by:
 * - ovl_create_upper()
 * - ovl_create_over_whiteout()
 */
static void ovl_instantiate(struct dentry *dentry, struct inode *inode,
			    struct dentry *newdentry, bool hardlink)
{
	ovl_dentry_version_inc(dentry->d_parent);
	/*
	 * dentry是merged中的dentry
	 * newdentry是upperdir中的dentry
	 * 把newdentry设置为dentry的upper
	 */
	ovl_dentry_update(dentry, newdentry);
	if (!hardlink) {
		/*
		 * inode是merged中的inode
		 */
		ovl_inode_update(inode, d_inode(newdentry));
		ovl_copyattr(newdentry->d_inode, inode);
	} else {
		WARN_ON(ovl_inode_real(inode, NULL) != d_inode(newdentry));
		inc_nlink(inode);
	}
	/* Fill in inode information in the entry */
	/* 会把dentry的d_inode设置成inode */
	d_instantiate(dentry, inode);
}

/* called only by ovl_create_or_link() */
/*
 * dentry是merged dentry
 *
 * 为dentry在upperdir创建对应的文件
 */
static int ovl_create_upper(struct dentry *dentry, struct inode *inode,
			    struct kstat *stat, const char *link,
			    struct dentry *hardlink)
{
	struct dentry *upperdir = ovl_dentry_upper(dentry->d_parent);
	struct inode *udir = upperdir->d_inode;
	struct dentry *newdentry;
	int err;

	if (!hardlink && !IS_POSIXACL(udir))
		stat->mode &= ~current_umask();

	inode_lock_nested(udir, I_MUTEX_PARENT);
	/*
	 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 *
	 * upperdir是merged dentry的parent在upper的文件夹
	 *
	 * !!!!!!newdentry是为upperdir创建的dentry!!!!!!
	 */
	newdentry = lookup_one_len(dentry->d_name.name, upperdir,
				   dentry->d_name.len);
	err = PTR_ERR(newdentry);
	if (IS_ERR(newdentry))
		goto out_unlock;
	/*
	 * udir是upper的文件夹的inode
	 * newdentry是要在upperdir创建的文件
	 * 调用vfs_xxx创建真实的upper的文件
	 *
	 * link只有在ovl_do_symlink()-->vfs_symlink()的时候才用
	 */
	err = ovl_create_real(udir, newdentry, stat, link, hardlink, false);
	if (err)
		goto out_dput;

	/* Common operations required to be done after creation of file on upper */
	/*
	 * !!!!!!newdentry是为upperdir创建的dentry!!!!!!
	 * dentry是在merged中的dentry
	 * inode是之前分配了还没用上的inode
	 */
	ovl_instantiate(dentry, inode, newdentry, !!hardlink);
	newdentry = NULL;
out_dput:
	dput(newdentry);
out_unlock:
	inode_unlock(udir);
	return err;
}

static int ovl_lock_rename_workdir(struct dentry *workdir,
				   struct dentry *upperdir)
{
	/* Workdir should not be the same as upperdir */
	if (workdir == upperdir)
		goto err;

	/* Workdir should not be subdir of upperdir and vice versa */
	/* 在rename操作中,对source与target各自的父目录进行加锁的函数是lock_rename() */
	if (lock_rename(workdir, upperdir) != NULL)
		goto err_unlock;

	return 0;

err_unlock:
	unlock_rename(workdir, upperdir);
err:
	pr_err("overlayfs: failed to lock workdir+upperdir\n");
	return -EIO;
}

/* called only by ovl_check_empty_and_clear() */
/*
 * 在workdir创建一个opaque的文件夹 然后rename到upper的文件夹
 */
static struct dentry *ovl_clear_empty(struct dentry *dentry,
				      struct list_head *list)
{
	/* 根据merged dentry找到其superblock返回私有数据的workdir的dentry */
	struct dentry *workdir = ovl_workdir(dentry);
	struct inode *wdir = workdir->d_inode;
	/* 返回merged中的dentry的的parent的upper dentry */
	struct dentry *upperdir = ovl_dentry_upper(dentry->d_parent);
	struct inode *udir = upperdir->d_inode;
	struct path upperpath;
	struct dentry *upper;
	struct dentry *opaquedir;
	struct kstat stat;
	int err;

	if (WARN_ON(!workdir))
		return ERR_PTR(-EROFS);

	/* 调用lock_rename() */
	err = ovl_lock_rename_workdir(workdir, upperdir);
	if (err)
		goto out;

	/* 把merged的dentry的upper的信息写入path */
	ovl_path_upper(dentry, &upperpath);
	err = vfs_getattr(&upperpath, &stat);
	if (err)
		goto out_unlock;

	err = -ESTALE;
	/* 当前的dentry必须是dir */
	if (!S_ISDIR(stat.mode))
		goto out_unlock;
	/* upper是该merged dentry在upperdir对应的dentry */
	upper = upperpath.dentry;
	if (upper->d_parent->d_inode != udir)
		goto out_unlock;

	/*
	 * ovl_lookup_temp函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 * 第二个参数dentry根本就没用到 文件名基于workdir自己的变量生成的
	 */
	/* 在workdir中生成一个临时的opqeuedir */
	opaquedir = ovl_lookup_temp(workdir, dentry);
	err = PTR_ERR(opaquedir);
	if (IS_ERR(opaquedir))
		goto out_unlock;

	err = ovl_create_real(wdir, opaquedir, &stat, NULL, NULL, true);
	if (err)
		goto out_dput;

	/* upper是该merged dentry在upperdir对应的dentry */
	err = ovl_copy_xattr(upper, opaquedir);
	if (err)
		goto out_cleanup;

	/* 通过vfs_setxattr() OVL_XATTR_OPAQUE */
	err = ovl_set_opaque(opaquedir);
	if (err)
		goto out_cleanup;

	inode_lock(opaquedir->d_inode);
	err = ovl_set_attr(opaquedir, &stat);
	inode_unlock(opaquedir->d_inode);
	if (err)
		goto out_cleanup;

	/* 通过vfs_rename() */
	/*
	 * upper是该merged dentry在upperdir对应的dentry 
	 *
	 * RENAME_EXCHANGE: xchange source and dest
	 * RENAME_NOREPLACE: don't overwrite target
	 * RENAME_WHITEOUT: whiteout source
	 */
	err = ovl_do_rename(wdir, opaquedir, udir, upper, RENAME_EXCHANGE);
	if (err)
		goto out_cleanup;

	ovl_cleanup_whiteouts(upper, list);
	ovl_cleanup(wdir, upper);
	unlock_rename(workdir, upperdir);

	/* dentry's upper doesn't match now, get rid of it */
	d_drop(dentry);

	return opaquedir;

out_cleanup:
	ovl_cleanup(wdir, opaquedir);
out_dput:
	dput(opaquedir);
out_unlock:
	unlock_rename(workdir, upperdir);
out:
	return ERR_PTR(err);
}

/*
 * called by:
 * - ovl_remove_and_whiteout()
 * - ovl_rename2()
 */
static struct dentry *ovl_check_empty_and_clear(struct dentry *dentry)
{
	int err;
	struct dentry *ret = NULL;
	/* 返回merged中dentry的类型 */
	enum ovl_path_type type = ovl_path_type(dentry);
	LIST_HEAD(list);

	/*
	 * 检查dentry代表的文件夹下是不是空的(空表示文件要么是.和.. 要么是whiteout的)
	 * 所有的文件会被读取到list中
	 *
	 * dentry是merged中的dentry
	 */
	err = ovl_check_empty_dir(dentry, &list);
	if (err) {
		ret = ERR_PTR(err);
		goto out_free;
	}

	/*
	 * When removing an empty opaque directory, then it makes no sense to
	 * replace it with an exact replica of itself.
	 *
	 * If no upperdentry then skip clearing whiteouts.
	 *
	 * Can race with copy-up, since we don't hold the upperdir mutex.
	 * Doesn't matter, since copy-up can't create a non-empty directory
	 * from an empty one.
	 */
	/* 在workdir创建一个opaque的文件夹 然后rename到upper的文件夹 */
	if (OVL_TYPE_UPPER(type) && OVL_TYPE_MERGE(type))
		ret = ovl_clear_empty(dentry, &list);

out_free:
	/*
	 * 把list上的ovl_cache_entry全部kfree()
	 * 这里kfree是回收内存 没别的目的
	 */
	ovl_cache_free(&list);

	return ret;
}

static int ovl_set_upper_acl(struct dentry *upperdentry, const char *name,
			     const struct posix_acl *acl)
{
	void *buffer;
	size_t size;
	int err;

	if (!IS_ENABLED(CONFIG_FS_POSIX_ACL) || !acl)
		return 0;

	size = posix_acl_to_xattr(NULL, acl, NULL, 0);
	buffer = kmalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	size = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
	err = size;
	if (err < 0)
		goto out_free;

	err = vfs_setxattr(upperdentry, name, buffer, size, XATTR_CREATE);
out_free:
	kfree(buffer);
	return err;
}

/*
 * called only by ovl_create_or_link()
 *
 * dentry是merged中的dentry, inode是为merged分配的inode
 */
static int ovl_create_over_whiteout(struct dentry *dentry, struct inode *inode,
				    struct kstat *stat, const char *link,
				    struct dentry *hardlink)
{
	/* 根据merged dentry找到其superblock返回私有数据的workdir的dentry */
	struct dentry *workdir = ovl_workdir(dentry);
	struct inode *wdir = workdir->d_inode;
	/* upperdir是dentry的父文件夹在upper的表示 */
	struct dentry *upperdir = ovl_dentry_upper(dentry->d_parent);
	struct inode *udir = upperdir->d_inode;
	struct dentry *upper;
	struct dentry *newdentry;
	int err;
	struct posix_acl *acl, *default_acl;

	if (WARN_ON(!workdir))
		return -EROFS;

	if (!hardlink) {
		/* 根据指定文件的权限和ACL属性来创建一个新的ACL,并释放原来的ACL */
		err = posix_acl_create(dentry->d_parent->d_inode,
				       &stat->mode, &default_acl, &acl);
		if (err)
			return err;
	}

	err = ovl_lock_rename_workdir(workdir, upperdir);
	if (err)
		goto out;

	/*
	 * ovl_lookup_temp函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 * 第二个参数dentry根本就没用到 文件名基于workdir自己的变量生成的
	 *
	 * newdentry是在workdir随机生成的dentry
	 */
	newdentry = ovl_lookup_temp(workdir, dentry);
	err = PTR_ERR(newdentry);
	if (IS_ERR(newdentry))
		goto out_unlock;

	/*
	 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 */
	upper = lookup_one_len(dentry->d_name.name, upperdir,
			       dentry->d_name.len);
	err = PTR_ERR(upper);
	if (IS_ERR(upper))
		goto out_dput;

	/* 在wdir创建newdentry的文件实体 */
	err = ovl_create_real(wdir, newdentry, stat, link, hardlink, true);
	if (err)
		goto out_dput2;

	/*
	 * mode could have been mutilated due to umask (e.g. sgid directory)
	 */
	if (!hardlink &&
	    !S_ISLNK(stat->mode) && newdentry->d_inode->i_mode != stat->mode) {
		struct iattr attr = {
			.ia_valid = ATTR_MODE,
			.ia_mode = stat->mode,
		};
		inode_lock(newdentry->d_inode);
		err = notify_change(newdentry, &attr, NULL);
		inode_unlock(newdentry->d_inode);
		if (err)
			goto out_cleanup;
	}
	if (!hardlink) {
		err = ovl_set_upper_acl(newdentry, XATTR_NAME_POSIX_ACL_ACCESS,
					acl);
		if (err)
			goto out_cleanup;

		err = ovl_set_upper_acl(newdentry, XATTR_NAME_POSIX_ACL_DEFAULT,
					default_acl);
		if (err)
			goto out_cleanup;
	}

	if (!hardlink && S_ISDIR(stat->mode)) {
		err = ovl_set_opaque(newdentry);
		if (err)
			goto out_cleanup;

		err = ovl_do_rename(wdir, newdentry, udir, upper,
				    RENAME_EXCHANGE);
		if (err)
			goto out_cleanup;

		ovl_cleanup(wdir, upper);
	} else {
		err = ovl_do_rename(wdir, newdentry, udir, upper, 0);
		if (err)
			goto out_cleanup;
	}
	ovl_instantiate(dentry, inode, newdentry, !!hardlink);
	newdentry = NULL;
out_dput2:
	dput(upper);
out_dput:
	dput(newdentry);
out_unlock:
	unlock_rename(workdir, upperdir);
out:
	if (!hardlink) {
		posix_acl_release(acl);
		posix_acl_release(default_acl);
	}
	return err;

out_cleanup:
	ovl_cleanup(wdir, newdentry);
	goto out_dput2;
}

/*
 * 如果最上面被ovl_symlink()调用: 创建link的文件指向dentry
 */
static int ovl_create_or_link(struct dentry *dentry, struct inode *inode,
			      struct kstat *stat, const char *link,
			      struct dentry *hardlink)
{
	int err;
	const struct cred *old_cred;
	struct cred *override_cred;

	/*
	 * 把文件从lower copy到 upper
	 * 如果dentry的祖先文件夹不在upper就先把祖先文件夹copy到upper
	 * 这里copy的是文件的父文件夹
	 */
	err = ovl_copy_up(dentry->d_parent);
	if (err)
		return err;

	old_cred = ovl_override_creds(dentry->d_sb);
	err = -ENOMEM;
	override_cred = prepare_creds();
	if (override_cred) {
		override_cred->fsuid = inode->i_uid;
		override_cred->fsgid = inode->i_gid;
		if (!hardlink) {
			err = security_dentry_create_files_as(dentry,
					stat->mode, &dentry->d_name, old_cred,
					override_cred);
			if (err) {
				put_cred(override_cred);
				goto out_revert_creds;
			}
		}
		put_cred(override_creds(override_cred));
		put_cred(override_cred);

		/*
		 * dentry是merged dentry
		 * 为dentry在upperdir创建对应的文件
		 *
		 * dentry的私有数据ovl_entry存着是否opaque
		 */
		if (!ovl_dentry_is_opaque(dentry))
			err = ovl_create_upper(dentry, inode, stat, link,
						hardlink);
		else
			err = ovl_create_over_whiteout(dentry, inode, stat,
							link, hardlink);
	}
out_revert_creds:
	revert_creds(old_cred);
	if (!err) {
		struct inode *realinode = d_inode(ovl_dentry_upper(dentry));

		WARN_ON(inode->i_mode != realinode->i_mode);
		WARN_ON(!uid_eq(inode->i_uid, realinode->i_uid));
		WARN_ON(!gid_eq(inode->i_gid, realinode->i_gid));
	}
	return err;
}

/*
 * 如果被ovl_symlink()调用: 在merged中创建link的文件指向dentry
 */
static int ovl_create_object(struct dentry *dentry, int mode, dev_t rdev,
			     const char *link)
{
	int err;
	struct inode *inode;
	struct kstat stat = {
		.rdev = rdev,
	};

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	err = -ENOMEM;
	/* 最终调用alloc_inode(), 因为overlay sb没有alloc_inode()指针,所以在slab分配 */
	/* 这个inode应该是给merged中用的 */
	inode = ovl_new_inode(dentry->d_sb, mode);
	if (!inode)
		goto out_drop_write;

	/* Init uid,gid,mode for new inode according to posix standards */
	inode_init_owner(inode, dentry->d_parent->d_inode, mode);
	stat.mode = inode->i_mode;

	/*
	 * 如果最上面被ovl_symlink()调用: 创建link的文件指向dentry
	 */
	err = ovl_create_or_link(dentry, inode, &stat, link, NULL);
	if (err)
		iput(inode);

out_drop_write:
	ovl_drop_write(dentry);
out:
	return err;
}

/* struct inode_operations ovl_dir_inode_operations.create() */
static int ovl_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		      bool excl)
{
	return ovl_create_object(dentry, (mode & 07777) | S_IFREG, 0, NULL);
}

/* struct inode_operations ovl_dir_inode_operations.mkdir() */
static int ovl_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return ovl_create_object(dentry, (mode & 07777) | S_IFDIR, 0, NULL);
}

/* struct inode_operations ovl_dir_inode_operations.mknod() */
static int ovl_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		     dev_t rdev)
{
	/* Don't allow creation of "whiteout" on overlay */
	if (S_ISCHR(mode) && rdev == WHITEOUT_DEV)
		return -EPERM;

	return ovl_create_object(dentry, mode, rdev, NULL);
}

/* struct inode_operations ovl_dir_inode_operations.symlink() */
/*
 * to create a symbolic link named link to
 * the file represented by dentry in the directory dir
 *
 * 在merged中创建一个指向dentry的名为link的软链接
 */
static int ovl_symlink(struct inode *dir, struct dentry *dentry,
		       const char *link)
{
	return ovl_create_object(dentry, S_IFLNK, 0, link);
}

/* struct inode_operations ovl_dir_inode_operations.link() */
static int ovl_link(struct dentry *old, struct inode *newdir,
		    struct dentry *new)
{
	int err;
	struct inode *inode;

	err = ovl_want_write(old);
	if (err)
		goto out;

	err = ovl_copy_up(old);
	if (err)
		goto out_drop_write;

	inode = d_inode(old);
	ihold(inode);

	err = ovl_create_or_link(new, inode, NULL, NULL, ovl_dentry_upper(old));
	if (err)
		iput(inode);

out_drop_write:
	ovl_drop_write(old);
out:
	return err;
}

/* called only by ovl_do_remove() */
/*
 * dentry是merged中的dentry
 */
static int ovl_remove_and_whiteout(struct dentry *dentry, bool is_dir)
{
	/* 根据merged dentry找到其superblock返回私有数据的workdir的dentry */
	struct dentry *workdir = ovl_workdir(dentry);
	struct inode *wdir = workdir->d_inode;
	/* merged中的dentry的父文件夹的upper dentry */
	struct dentry *upperdir = ovl_dentry_upper(dentry->d_parent);
	/* merged中的dentry的父文件夹的upper dentry的inode */
	struct inode *udir = upperdir->d_inode;
	struct dentry *whiteout;
	struct dentry *upper;
	struct dentry *opaquedir = NULL;
	int err;
	int flags = 0;

	if (WARN_ON(!workdir))
		return -EROFS;

	if (is_dir) {
		opaquedir = ovl_check_empty_and_clear(dentry);
		err = PTR_ERR(opaquedir);
		if (IS_ERR(opaquedir))
			goto out;
	}

	err = ovl_lock_rename_workdir(workdir, upperdir);
	if (err)
		goto out_dput;

	/*
	 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 */
	upper = lookup_one_len(dentry->d_name.name, upperdir,
			       dentry->d_name.len);
	err = PTR_ERR(upper);
	if (IS_ERR(upper))
		goto out_unlock;

	err = -ESTALE;
	if ((opaquedir && upper != opaquedir) ||
	    (!opaquedir && ovl_dentry_upper(dentry) &&
	     upper != ovl_dentry_upper(dentry))) {
		goto out_dput_upper;
	}

	/* 在workdir中创建0,0的char dev */
	whiteout = ovl_whiteout(workdir, dentry);
	err = PTR_ERR(whiteout);
	if (IS_ERR(whiteout))
		goto out_dput_upper;

	if (d_is_dir(upper))
		flags = RENAME_EXCHANGE;

	/* 把0,0的dev rename到upper dir */
	err = ovl_do_rename(wdir, whiteout, udir, upper, flags);
	if (err)
		goto kill_whiteout;
	if (flags)
		ovl_cleanup(wdir, upper);

	ovl_dentry_version_inc(dentry->d_parent);
out_d_drop:
	d_drop(dentry); // ---> 在这里merged中的dentry就用不到了??
	dput(whiteout);
out_dput_upper:
	dput(upper);
out_unlock:
	unlock_rename(workdir, upperdir);
out_dput:
	dput(opaquedir);
out:
	return err;

kill_whiteout:
	ovl_cleanup(wdir, whiteout);
	goto out_d_drop;
}

/*
 * 删除upper中的文件 dentry是merged中的dentry
 */
static int ovl_remove_upper(struct dentry *dentry, bool is_dir)
{
	/* 返回merged中的dentry的父文件夹的upper dentry */
	struct dentry *upperdir = ovl_dentry_upper(dentry->d_parent);
	/* merged中的dentry的父文件夹的upper dentry的inode */
	struct inode *dir = upperdir->d_inode;
	struct dentry *upper;
	int err;

	inode_lock_nested(dir, I_MUTEX_PARENT);
	/*
	 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
	 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
	 */
	upper = lookup_one_len(dentry->d_name.name, upperdir,
			       dentry->d_name.len);
	err = PTR_ERR(upper);
	if (IS_ERR(upper))
		goto out_unlock;

	err = -ESTALE;
	/*
	 * upper是merged中dentry在upper中对应的dentry
	 * dir是merged中的dentry的父文件夹的upper dentry的inode
	 */
	if (upper == ovl_dentry_upper(dentry)) {
		if (is_dir)
			err = vfs_rmdir(dir, upper);
		else
			err = vfs_unlink(dir, upper, NULL);
		ovl_dentry_version_inc(dentry->d_parent);
	}
	dput(upper);

	/*
	 * Keeping this dentry hashed would mean having to release
	 * upperpath/lowerpath, which could only be done if we are the
	 * sole user of this dentry.  Too tricky...  Just unhash for
	 * now.
	 */
	if (!err)
		d_drop(dentry);
out_unlock:
	inode_unlock(dir);

	return err;
}

static inline int ovl_check_sticky(struct dentry *dentry)
{
	struct inode *dir = ovl_dentry_real(dentry->d_parent)->d_inode;
	struct inode *inode = ovl_dentry_real(dentry)->d_inode;

	if (check_sticky(dir, inode))
		return -EPERM;

	return 0;
}

/*
 * called by:
 * - ovl_unlink()
 * - ovl_rmdir()
 *
 * is_dir表示要删除的是不是dir
 * dentry是merged中的dentry
 */
static int ovl_do_remove(struct dentry *dentry, bool is_dir)
{
	enum ovl_path_type type;
	int err;
	const struct cred *old_cred;


	err = ovl_check_sticky(dentry);
	if (err)
		goto out;

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	/* 把merged中的dentry的父文件夹copy up */
	err = ovl_copy_up(dentry->d_parent);
	if (err)
		goto out_drop_write;

	type = ovl_path_type(dentry);

	old_cred = ovl_override_creds(dentry->d_sb);
	if (OVL_TYPE_PURE_UPPER(type)) // 如果是纯upper的 删掉就好
		err = ovl_remove_upper(dentry, is_dir);
	else // 如果是lower的 则要whiteout
		err = ovl_remove_and_whiteout(dentry, is_dir);
	revert_creds(old_cred);
	if (!err) {
		if (is_dir)
			clear_nlink(dentry->d_inode); // directly zero an inode's link count
		else
			drop_nlink(dentry->d_inode);
	}
out_drop_write:
	ovl_drop_write(dentry);
out:
	return err;
}

/* struct inode_operations ovl_dir_inode_operations.unlink() */
static int ovl_unlink(struct inode *dir, struct dentry *dentry)
{
	return ovl_do_remove(dentry, false);
}

/* struct inode_operations ovl_dir_inode_operations.rmdir() */
static int ovl_rmdir(struct inode *dir, struct dentry *dentry)
{
	return ovl_do_remove(dentry, true);
}

/* struct inode_operations ovl_dir_inode_operations.rename() */
static int ovl_rename2(struct inode *olddir, struct dentry *old,
		       struct inode *newdir, struct dentry *new,
		       unsigned int flags)
{
	int err;
	enum ovl_path_type old_type;
	enum ovl_path_type new_type;
	struct dentry *old_upperdir;
	struct dentry *new_upperdir;
	struct dentry *olddentry;
	struct dentry *newdentry;
	struct dentry *trap;
	bool old_opaque;
	bool new_opaque;
	bool cleanup_whiteout = false;
	bool overwrite = !(flags & RENAME_EXCHANGE);
	bool is_dir = d_is_dir(old);
	bool new_is_dir = false;
	struct dentry *opaquedir = NULL;
	const struct cred *old_cred = NULL;

	err = -EINVAL;
	if (flags & ~(RENAME_EXCHANGE | RENAME_NOREPLACE))
		goto out;

	flags &= ~RENAME_NOREPLACE;

	/* 对一个目录设置了sticky-bit之后,存放在该目录的文件仅准许其属主执行删除,移动等操作 */
	err = ovl_check_sticky(old);
	if (err)
		goto out;

	/* Don't copy up directory trees */
	old_type = ovl_path_type(old);
	err = -EXDEV;
	if (OVL_TYPE_MERGE_OR_LOWER(old_type) && is_dir)
		goto out;

	if (new->d_inode) {
		err = ovl_check_sticky(new);
		if (err)
			goto out;

		if (d_is_dir(new))
			new_is_dir = true;

		new_type = ovl_path_type(new);
		err = -EXDEV;
		if (!overwrite && OVL_TYPE_MERGE_OR_LOWER(new_type) && new_is_dir)
			goto out;

		err = 0;
		if (!OVL_TYPE_UPPER(new_type) && !OVL_TYPE_UPPER(old_type)) {
			if (ovl_dentry_lower(old)->d_inode ==
			    ovl_dentry_lower(new)->d_inode)
				goto out;
		}
		if (OVL_TYPE_UPPER(new_type) && OVL_TYPE_UPPER(old_type)) {
			if (ovl_dentry_upper(old)->d_inode ==
			    ovl_dentry_upper(new)->d_inode)
				goto out;
		}
	} else {
		if (ovl_dentry_is_opaque(new))
			new_type = __OVL_PATH_UPPER;
		else
			new_type = __OVL_PATH_UPPER | __OVL_PATH_PURE;
	}

	err = ovl_want_write(old);
	if (err)
		goto out;

	err = ovl_copy_up(old);
	if (err)
		goto out_drop_write;

	err = ovl_copy_up(new->d_parent);
	if (err)
		goto out_drop_write;
	if (!overwrite) {
		err = ovl_copy_up(new);
		if (err)
			goto out_drop_write;
	}

	old_opaque = !OVL_TYPE_PURE_UPPER(old_type);
	new_opaque = !OVL_TYPE_PURE_UPPER(new_type);

	old_cred = ovl_override_creds(old->d_sb);

	if (overwrite && OVL_TYPE_MERGE_OR_LOWER(new_type) && new_is_dir) {
		opaquedir = ovl_check_empty_and_clear(new);
		err = PTR_ERR(opaquedir);
		if (IS_ERR(opaquedir)) {
			opaquedir = NULL;
			goto out_revert_creds;
		}
	}

	if (overwrite) {
		if (old_opaque) {
			if (new->d_inode || !new_opaque) {
				/* Whiteout source */
				flags |= RENAME_WHITEOUT;
			} else {
				/* Switch whiteouts */
				flags |= RENAME_EXCHANGE;
			}
		} else if (is_dir && !new->d_inode && new_opaque) {
			flags |= RENAME_EXCHANGE;
			cleanup_whiteout = true;
		}
	}

	old_upperdir = ovl_dentry_upper(old->d_parent);
	new_upperdir = ovl_dentry_upper(new->d_parent);

	/* 在rename操作中,对source与target各自的父目录进行加锁的函数是lock_rename() */
	trap = lock_rename(new_upperdir, old_upperdir);


	olddentry = lookup_one_len(old->d_name.name, old_upperdir,
				   old->d_name.len);
	err = PTR_ERR(olddentry);
	if (IS_ERR(olddentry))
		goto out_unlock;

	err = -ESTALE;
	if (olddentry != ovl_dentry_upper(old))
		goto out_dput_old;

	newdentry = lookup_one_len(new->d_name.name, new_upperdir,
				   new->d_name.len);
	err = PTR_ERR(newdentry);
	if (IS_ERR(newdentry))
		goto out_dput_old;

	err = -ESTALE;
	if (ovl_dentry_upper(new)) {
		if (opaquedir) {
			if (newdentry != opaquedir)
				goto out_dput;
		} else {
			if (newdentry != ovl_dentry_upper(new))
				goto out_dput;
		}
	} else {
		if (!d_is_negative(newdentry) &&
		    (!new_opaque || !ovl_is_whiteout(newdentry)))
			goto out_dput;
	}

	if (olddentry == trap)
		goto out_dput;
	if (newdentry == trap)
		goto out_dput;

	if (is_dir && !old_opaque && new_opaque) {
		err = ovl_set_opaque(olddentry);
		if (err)
			goto out_dput;
	}
	if (!overwrite && new_is_dir && old_opaque && !new_opaque) {
		err = ovl_set_opaque(newdentry);
		if (err)
			goto out_dput;
	}

	if (old_opaque || new_opaque) {
		err = ovl_do_rename(old_upperdir->d_inode, olddentry,
				    new_upperdir->d_inode, newdentry,
				    flags);
	} else {
		/* No debug for the plain case */
		BUG_ON(flags & ~RENAME_EXCHANGE);
		err = vfs_rename(old_upperdir->d_inode, olddentry,
				 new_upperdir->d_inode, newdentry,
				 NULL, flags);
	}

	if (err) {
		if (is_dir && !old_opaque && new_opaque)
			ovl_remove_opaque(olddentry);
		if (!overwrite && new_is_dir && old_opaque && !new_opaque)
			ovl_remove_opaque(newdentry);
		goto out_dput;
	}

	if (is_dir && old_opaque && !new_opaque)
		ovl_remove_opaque(olddentry);
	if (!overwrite && new_is_dir && !old_opaque && new_opaque)
		ovl_remove_opaque(newdentry);

	/*
	 * Old dentry now lives in different location. Dentries in
	 * lowerstack are stale. We cannot drop them here because
	 * access to them is lockless. This could be only pure upper
	 * or opaque directory - numlower is zero. Or upper non-dir
	 * entry - its pureness is tracked by flag opaque.
	 */
	if (old_opaque != new_opaque) {
		ovl_dentry_set_opaque(old, new_opaque);
		if (!overwrite)
			ovl_dentry_set_opaque(new, old_opaque);
	}

	if (cleanup_whiteout)
		ovl_cleanup(old_upperdir->d_inode, newdentry);

	ovl_dentry_version_inc(old->d_parent);
	ovl_dentry_version_inc(new->d_parent);

out_dput:
	dput(newdentry);
out_dput_old:
	dput(olddentry);
out_unlock:
	unlock_rename(new_upperdir, old_upperdir);
out_revert_creds:
	revert_creds(old_cred);
out_drop_write:
	ovl_drop_write(old);
out:
	dput(opaquedir);
	return err;
}

const struct inode_operations ovl_dir_inode_operations = {
	.lookup		= ovl_lookup,
	.mkdir		= ovl_mkdir,
	.symlink	= ovl_symlink,
	.unlink		= ovl_unlink,
	.rmdir		= ovl_rmdir,
	.rename		= ovl_rename2,
	.link		= ovl_link,
	.setattr	= ovl_setattr,
	.create		= ovl_create,
	.mknod		= ovl_mknod,
	.permission	= ovl_permission,
	.getattr	= ovl_dir_getattr,
	.listxattr	= ovl_listxattr,
	.get_acl	= ovl_get_acl,
	.update_time	= ovl_update_time,
};

/*
 * 在容器内读文件时,如果upperdir(container layer)存在,就从container layer读取;
 * 如果不存在,就从lowerlar(image layer)读取
 *
 * 写容器内文件时,如果upperdir不存在,overlay则会发起copy_up操作,从lowerdir拷贝
 * 文件到upperdir.由于拷贝发生文件系统层面,而不是块层,会拷贝整个文件,即使只修改
 * 文件很小一部分.如果文件很大,会导致效率低下.但好在拷贝只会在第一次打开时发生.
 * 另外,由于overlay只有2层,所以性能影响也很小.
 *
 * 删除容器内文件时,upperdir会创建一个whiteout文件,它会隐藏lowerdir的文件(不会
 * 删除.同样,删除目录时,upperdir会创建一个opaque directory,隐藏lowerdir的目录.
 */
