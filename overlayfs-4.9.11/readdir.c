/*
 *
 * Copyright (C) 2011 Novell Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/rbtree.h>
#include <linux/security.h>
#include <linux/cred.h>
#include "overlayfs.h"

struct ovl_cache_entry {
	unsigned int len;
	unsigned int type;
	u64 ino;
	struct list_head l_node;
	struct rb_node node;
	struct ovl_cache_entry *next_maybe_whiteout; // 用于在ovl_readdir_data.first_maybe_whiteout中当作node
	bool is_whiteout;
	char name[];
};

struct ovl_dir_cache {
	long refcount;
	u64 version;
	struct list_head entries; // 保存着merged文件夹下所有的文件
};

struct ovl_readdir_data {
	struct dir_context ctx;
	struct dentry *dentry;
	bool is_lowest;
	struct rb_root root;
	struct list_head *list;
	struct list_head middle;
	struct ovl_cache_entry *first_maybe_whiteout; // 链表 所有可能whiteout的struct ovl_cache_entry
	int count;
	int err;
	bool d_type_supported;
};

/* struct file的私有数据 */
struct ovl_dir_file {
	bool is_real;
	bool is_upper;
	struct ovl_dir_cache *cache; // 保存着merged文件夹下所有的文件
	struct list_head *cursor; // 和ovl_dir_cache.entries有关
	struct file *realfile;
	struct file *upperfile;
};

/*
 * 根据rb_node找到struct ovl_cache_entry
 * struct rb_node node是struct ovl_cache_entry一部分
 */
static struct ovl_cache_entry *ovl_cache_entry_from_node(struct rb_node *n)
{
	return container_of(n, struct ovl_cache_entry, node);
}

/* called only by ovl_fill_lowest() */
/*
 * 在root代表的rb tree中寻找和name相等的ovl_cache_entry 
 * 遍历rbtree
 *
 * root是ovl_readdir_data.root
 */
static struct ovl_cache_entry *ovl_cache_entry_find(struct rb_root *root,
						    const char *name, int len)
{
	struct rb_node *node = root->rb_node;
	int cmp;

	while (node) {
		/* 根据rb_node找到struct ovl_cache_entry */
		struct ovl_cache_entry *p = ovl_cache_entry_from_node(node);

		cmp = strncmp(name, p->name, len);
		if (cmp > 0)
			node = p->node.rb_right;
		else if (cmp < 0 || len < p->len)
			node = p->node.rb_left;
		else
			return p;
	}

	return NULL;
}

/* 
 * alloc一个struct ovl_cache_entry并填充相关信息(name, len)
 * 如果是char类型文件 则链入(存所有可能whiteout的struct ovl_cache_entry的)链表
 */
static struct ovl_cache_entry *ovl_cache_entry_new(struct ovl_readdir_data *rdd,
						   const char *name, int len,
						   u64 ino, unsigned int d_type)
{
	struct ovl_cache_entry *p;
	/* 计算struct ovl_cache_entry的实际size */
	size_t size = offsetof(struct ovl_cache_entry, name[len + 1]);

	/* 分配struct ovl_cache_entry */
	p = kmalloc(size, GFP_KERNEL);
	if (!p)
		return NULL;

	memcpy(p->name, name, len);
	p->name[len] = '\0';
	p->len = len;
	p->type = d_type;
	p->ino = ino;
	p->is_whiteout = false;

	if (d_type == DT_CHR) {
		/* 链入链表 存所有可能whiteout的struct ovl_cache_entry */
		p->next_maybe_whiteout = rdd->first_maybe_whiteout;
		rdd->first_maybe_whiteout = p;
	}
	return p;
}

/* called only by ovl_fill_merge() */
/* 分配并填充struct ovl_cache_entry并加入ovl_readdir_data的rbtree和链表 */
static int ovl_cache_entry_add_rb(struct ovl_readdir_data *rdd,
				  const char *name, int len, u64 ino,
				  unsigned int d_type)
{
	struct rb_node **newp = &rdd->root.rb_node;
	struct rb_node *parent = NULL;
	struct ovl_cache_entry *p;

	while (*newp) {
		int cmp;
		struct ovl_cache_entry *tmp;

		parent = *newp;
		/* 根据rb_node找到struct ovl_cache_entry */
		tmp = ovl_cache_entry_from_node(*newp);
		cmp = strncmp(name, tmp->name, len);
		if (cmp > 0)
			newp = &tmp->node.rb_right;
		else if (cmp < 0 || len < tmp->len)
			newp = &tmp->node.rb_left;
		else
			return 0;
	}

	/* alloc一个struct ovl_cache_entry并填充相关信息(name, len) */
	p = ovl_cache_entry_new(rdd, name, len, ino, d_type);
	if (p == NULL)
		return -ENOMEM;

	list_add_tail(&p->l_node, rdd->list);
	rb_link_node(&p->node, parent, newp);
	rb_insert_color(&p->node, &rdd->root);

	return 0;
}

/* called only by ovl_fill_merge() (是readdir的.ctx.actor) */
/* 根据name查询已有或分配一个struct ovl_cache_entry, 链入rdd->middle */
static int ovl_fill_lowest(struct ovl_readdir_data *rdd,
			   const char *name, int namelen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	struct ovl_cache_entry *p;

	/* 在root代表的rb tree中寻找和name相等的ovl_cache_entry */
	p = ovl_cache_entry_find(&rdd->root, name, namelen);
	if (p) {
		/* delete from one list and add as another's tail */
		list_move_tail(&p->l_node, &rdd->middle);
	} else {
		/*
		 * alloc一个struct ovl_cache_entry并填充相关信息(name, len)
		 * 如果是char类型文件 则链入(存所有可能whiteout的struct ovl_cache_entry的)链表
		 */
		p = ovl_cache_entry_new(rdd, name, namelen, ino, d_type);
		if (p == NULL)
			rdd->err = -ENOMEM;
		else
			list_add_tail(&p->l_node, &rdd->middle);
	}

	return rdd->err;
}

/* 把list上的ovl_cache_entry全部kfree() */
void ovl_cache_free(struct list_head *list)
{
	struct ovl_cache_entry *p;
	struct ovl_cache_entry *n;

	list_for_each_entry_safe(p, n, list, l_node)
		kfree(p);

	INIT_LIST_HEAD(list);
}

/* 利用cache->refcount */
static void ovl_cache_put(struct ovl_dir_file *od, struct dentry *dentry)
{
	struct ovl_dir_cache *cache = od->cache;

	WARN_ON(cache->refcount <= 0);
	cache->refcount--;
	if (!cache->refcount) {
		if (ovl_dir_cache(dentry) == cache)
			ovl_set_dir_cache(dentry, NULL);

		ovl_cache_free(&cache->entries);
		kfree(cache);
	}
}

/* readdir的.ctx.actor */
static int ovl_fill_merge(struct dir_context *ctx, const char *name,
			  int namelen, loff_t offset, u64 ino,
			  unsigned int d_type)
{
	struct ovl_readdir_data *rdd =
		container_of(ctx, struct ovl_readdir_data, ctx);

	rdd->count++;
	if (!rdd->is_lowest) // 分配并填充struct ovl_cache_entry并加入ovl_readdir_data的rbtree和链表
		return ovl_cache_entry_add_rb(rdd, name, namelen, ino, d_type);
	else // 根据name查询已有或分配一个struct ovl_cache_entry, 链入rdd->middle
		return ovl_fill_lowest(rdd, name, namelen, offset, ino, d_type);
}

/* called by ovl_dir_read() */
/* 为rdd的每一个ovl_cache_entry设置is_whiteout */
static int ovl_check_whiteouts(struct dentry *dir, struct ovl_readdir_data *rdd)
{
	int err;
	struct ovl_cache_entry *p;
	struct dentry *dentry;
	const struct cred *old_cred;

	old_cred = ovl_override_creds(rdd->dentry->d_sb);

	/* lock for writing */
	err = down_write_killable(&dir->d_inode->i_rwsem);
	if (!err) {
		while (rdd->first_maybe_whiteout) {
			p = rdd->first_maybe_whiteout;
			rdd->first_maybe_whiteout = p->next_maybe_whiteout;
			/*
			 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
			 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
			 */
			dentry = lookup_one_len(p->name, dir, p->len);
			if (!IS_ERR(dentry)) {
				p->is_whiteout = ovl_is_whiteout(dentry);
				dput(dentry);
			}
		}
		inode_unlock(dir->d_inode);
	}
	revert_creds(old_cred);

	return err;
}

/* 从realpath代表的文件夹遍历文件 */
static inline int ovl_dir_read(struct path *realpath,
			       struct ovl_readdir_data *rdd)
{
	struct file *realfile;
	int err;

	/* 打开path指向的文件 创建struct file */
	realfile = ovl_path_open(realpath, O_RDONLY | O_DIRECTORY);
	if (IS_ERR(realfile))
		return PTR_ERR(realfile);

	rdd->first_maybe_whiteout = NULL;
	rdd->ctx.pos = 0;
	do {
		rdd->count = 0;
		rdd->err = 0;
		err = iterate_dir(realfile, &rdd->ctx);
		if (err >= 0)
			err = rdd->err;
	} while (!err && rdd->count);

	if (!err && rdd->first_maybe_whiteout && rdd->dentry)
		/* 为rdd的每一个ovl_cache_entry设置is_whiteout */
		err = ovl_check_whiteouts(realpath->dentry, rdd);

	fput(realfile);

	return err;
}

/* 把file私有数据清空 */
static void ovl_dir_reset(struct file *file)
{
	struct ovl_dir_file *od = file->private_data;
	struct ovl_dir_cache *cache = od->cache;
	struct dentry *dentry = file->f_path.dentry;
	enum ovl_path_type type = ovl_path_type(dentry);

	if (cache && ovl_dentry_version_get(dentry) != cache->version) {
		ovl_cache_put(od, dentry);
		od->cache = NULL;
		od->cursor = NULL;
	}
	WARN_ON(!od->is_real && !OVL_TYPE_MERGE(type));
	if (od->is_real && OVL_TYPE_MERGE(type))
		od->is_real = false;
}

/*
 * called by:
 * - ovl_cache_get() --> list是ovl_dir_cache.entries
 * - ovl_check_empty_dir()
 *
 * dentry是merged中的dentry
 *
 * 把dentry文件夹下所有的文件(包括whiteout的和.与..读入list)
 */
static int ovl_dir_read_merged(struct dentry *dentry, struct list_head *list)
{
	int err;
	struct path realpath;
	struct ovl_readdir_data rdd = {
		.ctx.actor = ovl_fill_merge,
		.dentry = dentry, // dentry是merged中的dentry
		.list = list, // 当被ovl_cache_get()调用时 list是ovl_dir_cache.entries
		.root = RB_ROOT,
		.is_lowest = false,
	};
	int idx, next;

	for (idx = 0; idx != -1; idx = next) {
		/*
		 * 如果idx是0就把merged的dentry的upper的信息写入realpath
		 * 如果idx不等于0, 就把merged的dentry的lower的信息写入realpath
		 */
		next = ovl_path_next(idx, dentry, &realpath);

		if (next != -1) {
			/* 从realpath代表的文件夹遍历文件 ctx.actor=ovl_fill_merge() */
			err = ovl_dir_read(&realpath, &rdd);
			if (err)
				break;
		} else {
			/*
			 * Insert lowest layer entries before upper ones, this
			 * allows offsets to be reasonably constant
			 */
			list_add(&rdd.middle, rdd.list);
			rdd.is_lowest = true;
			/* 从realpath代表的文件夹遍历文件 ctx.actor=ovl_fill_merge() */
			err = ovl_dir_read(&realpath, &rdd);
			list_del(&rdd.middle);
		}
	}
	return err;
}

static void ovl_seek_cursor(struct ovl_dir_file *od, loff_t pos)
{
	struct list_head *p;
	loff_t off = 0;

	list_for_each(p, &od->cache->entries) {
		if (off >= pos)
			break;
		off++;
	}
	/* Cursor is safe since the cache is stable */
	od->cursor = p;
}

/* dentry是merged中文件夹的dentry */
/* 核心函数是ovl_dir_read_merged() */
static struct ovl_dir_cache *ovl_cache_get(struct dentry *dentry)
{
	int res;
	/* ovl_dir_cache.entries将会保存merged文件夹下所有的文件 */
	struct ovl_dir_cache *cache;

	/* 获取merged中dentry的私有数据中的cache */
	cache = ovl_dir_cache(dentry);
	if (cache && ovl_dentry_version_get(dentry) == cache->version) {
		cache->refcount++;
		return cache;
	}
	/* 把merged中dentry的私有数据中的cache设置为NULL */
	ovl_set_dir_cache(dentry, NULL);

	cache = kzalloc(sizeof(struct ovl_dir_cache), GFP_KERNEL);
	if (!cache)
		return ERR_PTR(-ENOMEM);

	cache->refcount = 1;
	/* ovl_dir_cache.entries将会保存merged文件夹下所有的文件 */
	INIT_LIST_HEAD(&cache->entries);

	res = ovl_dir_read_merged(dentry, &cache->entries);
	if (res) {
		/* 把ovl_dir_cache.entries上的ovl_cache_entry全部kfree() */
		ovl_cache_free(&cache->entries);
		kfree(cache);
		return ERR_PTR(res);
	}

	cache->version = ovl_dentry_version_get(dentry);
	/* 设置merged中dentry的私有数据中的cache */
	ovl_set_dir_cache(dentry, cache);

	return cache;
}

/* struct file_operations ovl_dir_operations.iterate() */
static int ovl_iterate(struct file *file, struct dir_context *ctx)
{
	/* file是merged中的file */
	struct ovl_dir_file *od = file->private_data;
	/* dentry是merged中的dentry */
	struct dentry *dentry = file->f_path.dentry;
	struct ovl_cache_entry *p;

	if (!ctx->pos)
		ovl_dir_reset(file);

	/* 如果文件夹不是merged 直接遍历lower或者upper */
	if (od->is_real)
		return iterate_dir(od->realfile, ctx);

	if (!od->cache) {
		struct ovl_dir_cache *cache;

		cache = ovl_cache_get(dentry);
		if (IS_ERR(cache))
			return PTR_ERR(cache);

		od->cache = cache;
		ovl_seek_cursor(od, ctx->pos);
	}

	/* od->cache->entries保存着merged文件夹下所有的文件 */
	while (od->cursor != &od->cache->entries) {
		p = list_entry(od->cursor, struct ovl_cache_entry, l_node);
		/* 如果不是whiteout的 则执行dir_emit放入返回buffer中 */
		if (!p->is_whiteout)
			/* 对于getdent64来说 .ctx.actor = filldir64 */
			if (!dir_emit(ctx, p->name, p->len, p->ino, p->type))
				break;
		od->cursor = p->l_node.next;
		ctx->pos++;
	}
	return 0;
}

/* struct file_operations ovl_dir_operations.llseek() */
static loff_t ovl_dir_llseek(struct file *file, loff_t offset, int origin)
{
	loff_t res;
	struct ovl_dir_file *od = file->private_data;

	inode_lock(file_inode(file));
	if (!file->f_pos)
		ovl_dir_reset(file);

	if (od->is_real) {
		res = vfs_llseek(od->realfile, offset, origin);
		file->f_pos = od->realfile->f_pos;
	} else {
		res = -EINVAL;

		switch (origin) {
		case SEEK_CUR:
			offset += file->f_pos;
			break;
		case SEEK_SET:
			break;
		default:
			goto out_unlock;
		}
		if (offset < 0)
			goto out_unlock;

		if (offset != file->f_pos) {
			file->f_pos = offset;
			if (od->cache)
				ovl_seek_cursor(od, offset);
		}
		res = offset;
	}
out_unlock:
	inode_unlock(file_inode(file));

	return res;
}

/* struct file_operations ovl_dir_operations.fsync() */
static int ovl_dir_fsync(struct file *file, loff_t start, loff_t end,
			 int datasync)
{
	struct ovl_dir_file *od = file->private_data;
	struct dentry *dentry = file->f_path.dentry;
	struct file *realfile = od->realfile;

	/*
	 * Need to check if we started out being a lower dir, but got copied up
	 */
	if (!od->is_upper && OVL_TYPE_UPPER(ovl_path_type(dentry))) {
		struct inode *inode = file_inode(file);

		realfile = lockless_dereference(od->upperfile);
		if (!realfile) {
			struct path upperpath;

			ovl_path_upper(dentry, &upperpath);
			realfile = ovl_path_open(&upperpath, O_RDONLY);
			smp_mb__before_spinlock();
			inode_lock(inode);
			if (!od->upperfile) {
				if (IS_ERR(realfile)) {
					inode_unlock(inode);
					return PTR_ERR(realfile);
				}
				od->upperfile = realfile;
			} else {
				/* somebody has beaten us to it */
				if (!IS_ERR(realfile))
					fput(realfile);
				realfile = od->upperfile;
			}
			inode_unlock(inode);
		}
	}

	return vfs_fsync_range(realfile, start, end, datasync);
}

/* struct file_operations ovl_dir_operations.release() */
static int ovl_dir_release(struct inode *inode, struct file *file)
{
	struct ovl_dir_file *od = file->private_data;

	if (od->cache) {
		inode_lock(inode);
		ovl_cache_put(od, file->f_path.dentry);
		inode_unlock(inode);
	}
	fput(od->realfile);
	if (od->upperfile)
		fput(od->upperfile);
	kfree(od);

	return 0;
}

/* struct file_operations ovl_dir_operations.open() */
static int ovl_dir_open(struct inode *inode, struct file *file)
{
	struct path realpath;
	struct file *realfile;
	struct ovl_dir_file *od; // merged file的private_data
	enum ovl_path_type type;

	od = kzalloc(sizeof(struct ovl_dir_file), GFP_KERNEL);
	if (!od)
		return -ENOMEM;

	/*
	 * dentry是merged中的dentry
	 * 如果没有upper则把lower的信息写入path
	 * 否则把upper的信息写入path
	 */
	type = ovl_path_real(file->f_path.dentry, &realpath);
	/* 打开path指向的文件 创建struct file */
	realfile = ovl_path_open(&realpath, file->f_flags);
	if (IS_ERR(realfile)) {
		kfree(od);
		return PTR_ERR(realfile);
	}
	od->realfile = realfile;
	od->is_real = !OVL_TYPE_MERGE(type);
	od->is_upper = OVL_TYPE_UPPER(type);
	file->private_data = od;

	return 0;
}

const struct file_operations ovl_dir_operations = {
	.read		= generic_read_dir,
	.open		= ovl_dir_open,
	.iterate	= ovl_iterate,
	.llseek		= ovl_dir_llseek,
	.fsync		= ovl_dir_fsync,
	.release	= ovl_dir_release,
};

/*
 * dentry是merged中的dentry
 *
 * 检查dentry代表的文件夹下是不是空的(空表示文件要么是.和.. 要么是whiteout的)
 * 所有的文件会被读取到list中
 */
int ovl_check_empty_dir(struct dentry *dentry, struct list_head *list)
{
	int err;
	struct ovl_cache_entry *p;

	/* 把dentry文件夹下所有的文件(包括whiteout的和.与..读入list) */
	err = ovl_dir_read_merged(dentry, list);
	if (err)
		return err;

	err = 0;

	list_for_each_entry(p, list, l_node) {
		if (p->is_whiteout)
			continue;

		if (p->name[0] == '.') {
			if (p->len == 1)
				continue;
			if (p->len == 2 && p->name[1] == '.')
				continue;
		}
		err = -ENOTEMPTY;
		break;
	}

	return err;
}

/* called only by ovl_clear_empty() */
/* 在upper中把list中的whiteout文件全部删除 */
void ovl_cleanup_whiteouts(struct dentry *upper, struct list_head *list)
{
	struct ovl_cache_entry *p;

	inode_lock_nested(upper->d_inode, I_MUTEX_CHILD);
	list_for_each_entry(p, list, l_node) {
		struct dentry *dentry;

		if (!p->is_whiteout)
			continue;

		dentry = lookup_one_len(p->name, upper, p->len);
		if (IS_ERR(dentry)) {
			pr_err("overlayfs: lookup '%s/%.*s' failed (%i)\n",
			       upper->d_name.name, p->len, p->name,
			       (int) PTR_ERR(dentry));
			continue;
		}
		if (dentry->d_inode)
			ovl_cleanup(upper->d_inode, dentry); // 在父文件夹中删除子文件(夹)
		dput(dentry);
	}
	inode_unlock(upper->d_inode);
}

static int ovl_check_d_type(struct dir_context *ctx, const char *name,
			  int namelen, loff_t offset, u64 ino,
			  unsigned int d_type)
{
	struct ovl_readdir_data *rdd =
		container_of(ctx, struct ovl_readdir_data, ctx);

	/* Even if d_type is not supported, DT_DIR is returned for . and .. */
	if (!strncmp(name, ".", namelen) || !strncmp(name, "..", namelen))
		return 0;

	if (d_type != DT_UNKNOWN)
		rdd->d_type_supported = true;

	return 0;
}

/*
 * Returns 1 if d_type is supported, 0 not supported/unknown. Negative values
 * if error is encountered.
 */
int ovl_check_d_type_supported(struct path *realpath)
{
	int err;
	struct ovl_readdir_data rdd = {
		.ctx.actor = ovl_check_d_type,
		.d_type_supported = false,
	};

	err = ovl_dir_read(realpath, &rdd);
	if (err)
		return err;

	return rdd.d_type_supported;
}

/* 貌似是把path代表的文件夹下所有的文件(文件夹)全部都删除 */
static void ovl_workdir_cleanup_recurse(struct path *path, int level)
{
	int err;
	struct inode *dir = path->dentry->d_inode;
	LIST_HEAD(list);
	struct ovl_cache_entry *p;
	struct ovl_readdir_data rdd = {
		.ctx.actor = ovl_fill_merge,
		.dentry = NULL,
		.list = &list,
		.root = RB_ROOT,
		.is_lowest = false,
	};

	err = ovl_dir_read(path, &rdd);
	if (err)
		goto out;

	inode_lock_nested(dir, I_MUTEX_PARENT);
	list_for_each_entry(p, &list, l_node) {
		struct dentry *dentry;

		if (p->name[0] == '.') {
			if (p->len == 1)
				continue;
			if (p->len == 2 && p->name[1] == '.')
				continue;
		}
		/*
		 * lookup_one_len函数首先在父目录下根据名字查找dentry结构,
		 * 如果存在同名的dentry结构就返回指针,如果不存在就创建一个dentry
		 */
		dentry = lookup_one_len(p->name, path->dentry, p->len);
		if (IS_ERR(dentry))
			continue;
		/* 在dir中删除dentry dentry可以是文件 也可以是文件夹 */
		if (dentry->d_inode)
			ovl_workdir_cleanup(dir, path->mnt, dentry, level);
		dput(dentry);
	}
	inode_unlock(dir);
out:
	ovl_cache_free(&list);
}

/* 在dir中删除dentry dentry可以是文件 也可以是文件夹 */
void ovl_workdir_cleanup(struct inode *dir, struct vfsmount *mnt,
			 struct dentry *dentry, int level)
{
	int err;

	/* 如果dentry不是dir */
	if (!d_is_dir(dentry) || level > 1) {
		/* 在父文件夹dir中删除子文件(夹)dentry */
		ovl_cleanup(dir, dentry);
		return;
	}

	/* 调用vfs_rmdir()在dir中删除dentry */
	err = ovl_do_rmdir(dir, dentry);
	if (err) {
		struct path path = { .mnt = mnt, .dentry = dentry };

		inode_unlock(dir);
		ovl_workdir_cleanup_recurse(&path, level + 1);
		inode_lock_nested(dir, I_MUTEX_PARENT);
		/* 在父文件夹dir中删除子文件(夹)dentry */
		ovl_cleanup(dir, dentry);
	}
}
