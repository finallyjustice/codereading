#include <linux/buffer_head.h>
#include <linux/slab.h>
#include "minix.h"

enum {DEPTH = 3, DIRECT = 7};	/* Only double indirect */

typedef u16 block_t;	/* 16 bit, host order */

static inline unsigned long block_to_cpu(block_t n)
{
	return n;
}

static inline block_t cpu_to_block(unsigned long n)
{
	return n;
}

/* mem和disk的inode信息都在struct minix_inode_info中,都不是指针 */
static inline block_t *i_data(struct inode *inode)
{
	return (block_t *)minix_i(inode)->u.i1_data;
}

// 这里的block是文件中的block位移
/*
 * 0 -> direct block x 1
 * 1 -> direct block x 1
 * 2 -> direct block x 1
 * 3 -> direct block x 1
 * 4 -> direct block x 1
 * 5 -> direct block x 1
 * 6 -> direct block x 1
 * 7 -> indirect block (each slot is to a direct block)
 * 8 -> indirect block (each slot is to an indirect block as in 7)
 *
 * BLOCK_SIZE是1024,一个间接块有512个slot,每个u16 (2个byte)
 */
/* 给定block的idx, 填充offsets. offsets数组是要获取这个block所用到的直接或者间接块的block idx 
 * 返回值是数组用了基层(几个slot) */
static int block_to_path(struct inode * inode, long block, int offsets[DEPTH])
{
	int n = 0;

	if (block < 0) {
		printk("MINIX-fs: block_to_path: block %ld < 0 on dev %pg\n",
			block, inode->i_sb->s_bdev);
	} else if (block >= (minix_sb(inode->i_sb)->s_max_size/BLOCK_SIZE)) {
		if (printk_ratelimit())
			printk("MINIX-fs: block_to_path: "
			       "block %ld too big on dev %pg\n",
				block, inode->i_sb->s_bdev);
	} else if (block < 7) {
		offsets[n++] = block;
	} else if ((block -= 7) < 512) {
		offsets[n++] = 7;
		offsets[n++] = block;
	} else {
		block -= 512;
		offsets[n++] = 8;
		offsets[n++] = block>>9;
		offsets[n++] = block & 511;
	}
	return n;
}

#include "itree_common.c"

/* called by minix_get_block() */
int V1_minix_get_block(struct inode * inode, long block,
			struct buffer_head *bh_result, int create)
{
	return get_block(inode, block, bh_result, create);
}

void V1_minix_truncate(struct inode * inode)
{
	truncate(inode);
}

/* size是文件的长度 
 * 计算文件有多少block 在minix_getattr用
 */
unsigned V1_minix_blocks(loff_t size, struct super_block *sb)
{
	return nblocks(size, sb);
}
