/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"

/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

/* struct inode_operations minix_file_inode_operations.setattr() */
static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	/* Check if we are allowed to change the attributes contained in @attr in the given dentry. */
	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	/* inode.i_size is the file length in bytes, i_block is file length in blocks */
	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		/* inode_newsize_ok will check filesystem limits and ulimits to check
		 * that the new inode size is within limits
		 */
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		/* update inode and pagecache for a new file size */
		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	/* setattr_copy updates the inode's metadata with that specified in attr */
	setattr_copy(inode, attr);
	/* Put the inode on the super block's dirty list */
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr, // 在fs/minix/inode.c
};
