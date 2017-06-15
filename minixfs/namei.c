/*
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include "minix.h"

/* 
 * called by:
 * - minix_mknod()   : for files and dev
 * - minix_symlink() : for softlink
 * - minix_link()    : for hardlink
 */
/* 
 * 修改一个dentry(在disk的结构) 使其指向一个inode
 * 如果是普通文件, 则inode是新文件本身的inode
 * 如果是hardlink, 则inode是共享的inode
 * 如果是softlink, 则inode是softlink自己本身的inode
 */
static int add_nondir(struct dentry *dentry, struct inode *inode)
{
	// 为文件(dentry)在文件夹对应的数据(block)创建对应实体
	// 在创建hardlink时, dentry是hardlink, inode是要指向的目标
	int err = minix_add_link(dentry, inode);
	if (!err) {
		// Fill in inode information in the dentry
		d_instantiate(dentry, inode);
		return 0;
	}
	// 后面应该是上面失败才执行的
	inode_dec_link_count(inode);
	iput(inode);
	return err;
}

/* struct inode_operations minix_dir_inode_operations.lookup() */
/* 
 * lookup finds the inode instance of a filesystem object by reference to its name
 * 在特定文件夹中寻找索引节点，该索引节点要对应于dentry中给出的文件名
 */
/* 
 * 先根据dentry, 找到其父文件夹存储的该dentry的inode number,
 * 然后根据ino,分配一个通用struct inode,再根据ino从disk读出raw inode来填充struct inode
 * 返回的inode在dentry里链接好了
 */
static struct dentry *minix_lookup(struct inode * dir, struct dentry *dentry, unsigned int flags)
{
	struct inode * inode = NULL;
	ino_t ino;

	if (dentry->d_name.len > minix_sb(dir->i_sb)->s_namelen)
		return ERR_PTR(-ENAMETOOLONG);

	// 根据dentry, 找到其父文件夹存储的该dentry的inode number
	ino = minix_inode_by_name(dentry);
	if (ino) {
		// 根据ino,分配一个通用struct inode,再根据ino从disk读出raw inode来填充struct inode
		inode = minix_iget(dir->i_sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	// This adds the entry to the hash queues and initializes inode
	d_add(dentry, inode);
	return NULL;
}

/* struct inode_operations minix_dir_inode_operations.mknod() */
/* 在dir下,根据dentry创建inode */
static int minix_mknod(struct inode * dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	int error;
	struct inode *inode;

	// check if acceptable for old filesystems
	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = minix_new_inode(dir, mode, &error);

	if (inode) {
		minix_set_inode(inode, rdev);
		mark_inode_dirty(inode);
		error = add_nondir(dentry, inode);
	}
	return error;
}

/* struct inode_operations minix_dir_inode_operations.tmpfile() */
static int minix_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int error;
	struct inode *inode = minix_new_inode(dir, mode, &error);
	if (inode) {
		minix_set_inode(inode, 0);
		mark_inode_dirty(inode);
		d_tmpfile(dentry, inode);
	}
	return error;
}

/* struct inode_operations minix_dir_inode_operations.create() */
/* 为dentry对象创造一个新的索引节点 */
static int minix_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	return minix_mknod(dir, dentry, mode, 0);
}

/* struct inode_operations minix_dir_inode_operations.symlink() */
/* create a symbolic link named symname to the file represented by dentry in the directory dir */
static int minix_symlink(struct inode * dir, struct dentry *dentry,
	  const char * symname)
{
	int err = -ENAMETOOLONG;
	int i = strlen(symname)+1;
	struct inode * inode;

	if (i > dir->i_sb->s_blocksize)
		goto out;

	// 在dir下创建新的inode, 在s_imap_blocks(inode表的位图块数)中找到新的free的inode
	inode = minix_new_inode(dir, S_IFLNK | 0777, &err);
	if (!inode)
		goto out;

	minix_set_inode(inode, 0);
	err = page_symlink(inode, symname, i);
	if (err)
		goto out_fail;

	err = add_nondir(dentry, inode);
out:
	return err;

out_fail:
	inode_dec_link_count(inode);
	iput(inode);
	goto out;
}

/* struct inode_operations minix_dir_inode_operations.link() */
/* create a hard link of the file old_dentry in the directory dir with the new filename dentry */
static int minix_link(struct dentry * old_dentry, struct inode * dir,
	struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);

	inode->i_ctime = current_time(inode);
	inode_inc_link_count(inode);
	ihold(inode);
	return add_nondir(dentry, inode);
}

/* struct inode_operations minix_dir_inode_operations.mkdir() */
static int minix_mkdir(struct inode * dir, struct dentry *dentry, umode_t mode)
{
	struct inode * inode;
	int err;

	inode_inc_link_count(dir);

	/*
	 * 在dir下创建新的inode
	 * 在s_imap_blocks(inode表的位图块数)中找到新的free的inode
	 */
	inode = minix_new_inode(dir, S_IFDIR | mode, &err);
	if (!inode)
		goto out_dir;

	minix_set_inode(inode, 0);

	inode_inc_link_count(inode);

	err = minix_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = minix_add_link(dentry, inode);
	if (err)
		goto out_fail;

	// fill in inode information for a dentry
	d_instantiate(dentry, inode);
out:
	return err;

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	iput(inode);
out_dir:
	inode_dec_link_count(dir);
	goto out;
}

/* struct inode_operations minix_dir_inode_operations.unlink() */
/* remove the inode specified by the directory entry dentry from the directory dir */
static int minix_unlink(struct inode * dir, struct dentry *dentry)
{
	int err = -ENOENT;
	struct inode * inode = d_inode(dentry);
	struct page * page;
	struct minix_dir_entry * de;

	de = minix_find_entry(dentry, &page);
	if (!de)
		goto end_unlink;

	err = minix_delete_entry(de, page);
	if (err)
		goto end_unlink;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
end_unlink:
	return err;
}

/* struct inode_operations minix_dir_inode_operations.rmdir() */
static int minix_rmdir(struct inode * dir, struct dentry *dentry)
{
	struct inode * inode = d_inode(dentry);
	int err = -ENOTEMPTY;

	if (minix_empty_dir(inode)) {
		err = minix_unlink(dir, dentry);
		if (!err) {
			inode_dec_link_count(dir);
			inode_dec_link_count(inode);
		}
	}
	return err;
}

/* struct inode_operations minix_dir_inode_operations.rename() */
/* 
 * move the file specified by old_dentry from the old_dir directory
 * to the directory new_dir , with the filename specified by new_dentry
 */
static int minix_rename(struct inode * old_dir, struct dentry *old_dentry,
			struct inode * new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	struct inode * old_inode = d_inode(old_dentry);
	struct inode * new_inode = d_inode(new_dentry);
	struct page * dir_page = NULL;
	struct minix_dir_entry * dir_de = NULL;
	struct page * old_page;
	struct minix_dir_entry * old_de;
	int err = -ENOENT;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	old_de = minix_find_entry(old_dentry, &old_page);
	if (!old_de)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = minix_dotdot(old_inode, &dir_page);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct page * new_page;
		struct minix_dir_entry * new_de;

		err = -ENOTEMPTY;
		if (dir_de && !minix_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = minix_find_entry(new_dentry, &new_page);
		if (!new_de)
			goto out_dir;
		minix_set_link(new_de, new_page, old_inode);
		new_inode->i_ctime = current_time(new_inode);
		if (dir_de)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		err = minix_add_link(new_dentry, old_inode);
		if (err)
			goto out_dir;
		if (dir_de)
			inode_inc_link_count(new_dir);
	}

	minix_delete_entry(old_de, old_page);
	mark_inode_dirty(old_inode);

	if (dir_de) {
		minix_set_link(dir_de, dir_page, new_dir);
		inode_dec_link_count(old_dir);
	}
	return 0;

out_dir:
	if (dir_de) {
		kunmap(dir_page);
		put_page(dir_page);
	}
out_old:
	kunmap(old_page);
	put_page(old_page);
out:
	return err;
}

/*
 * directories can handle most operations...
 */
const struct inode_operations minix_dir_inode_operations = {
	.create		= minix_create, // 为dentry对象创造一个新的索引节点
	.lookup		= minix_lookup, // lookup finds the inode instance of a filesystem object by reference to its name 在特定文件夹中寻找索引节点，该索引节点要对应于dentry中给出的文件名
	.link		= minix_link, // create a hard link of the file old_dentry in the directory dir with the new filename dentry
	.unlink		= minix_unlink, // remove the inode specified by the directory entry dentry from the directory dir .
	.symlink	= minix_symlink, // create a symbolic link named symname to the file represented by dentry in the directory dir
	.mkdir		= minix_mkdir,
	.rmdir		= minix_rmdir,
	.mknod		= minix_mknod,
	.rename		= minix_rename, // move the file specified by old_dentry from the old_dir directory to the directory new_dir , with the filename specified by new_dentry
	.getattr	= minix_getattr,
	.tmpfile	= minix_tmpfile,
};
