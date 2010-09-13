/*
    ext2.h -- ext2 header
    Copyright (C) 1998-2000, 2007 Free Software Foundation, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _EXT2_H
#define _EXT2_H

#include <parted/parted.h>
#include <parted/debug.h>
#include <sys/types.h>
#include "tune.h"

#if HAVE_INTTYPES_H
#  include <inttypes.h>
#endif

#if ENABLE_NLS
#  include <libintl.h>
#  define _(String) dgettext (PACKAGE, String)
#else
#  define _(String) (String)
#endif /* ENABLE_NLS */


/* Ehrm.... sorry, pedanticists! :-) */
#ifndef offsetof
#  define offsetof(type, field) ((size_t)(&(((type *)0)->field)))
#endif

#ifdef __BEOS__
  typedef off_t loff_t;
#endif

#if defined(__sun)
typedef off_t loff_t;
typedef uint32_t blk_t;
#else
typedef u_int32_t blk_t;
#endif

#ifdef HAVE_LINUX_EXT2_FS_H
#define _LINUX_TYPES_H
#define i_version i_generation
#include <linux/ext2_fs.h>
#else
#include "ext2_fs.h"
#endif

extern unsigned char _bitmap[8];

struct ext2_buffer_cache
{
	struct ext2_buffer_head	 *cache;
	struct ext2_buffer_head  *heads;
	struct ext2_buffer_head **hash;
	struct ext2_fs		 *fs;

	int			  size;
	int			  numalloc;
	unsigned char		 *buffermem;
};

struct ext2_buffer_head
{
	struct ext2_buffer_head  *next;
	struct ext2_buffer_head  *prev;
	unsigned char		 *data;
	blk_t			  block;

	int			  usecount;
	int			  dirty;

	struct ext2_buffer_cache *bc;
	int			  alloc;
};

struct ext2_dev_ops
{
	int	(*close)(void *cookie);
	blk_t	(*get_size)(void *cookie);
	int	(*read)(void *cookie, void *ptr, blk_t block, blk_t num);
	int	(*set_blocksize)(void *cookie, int logsize);
	int	(*sync)(void *cookie);
	int	(*write)(void *cookie, void *ptr, blk_t block, blk_t num);
};

struct ext2_dev_handle
{
	struct ext2_dev_ops	*ops;
	void			*cookie;
};

struct ext2_fs
{      
	struct ext2_dev_handle		 *devhandle;

	struct ext2_super_block		  sb;
	struct ext2_group_desc		 *gd;
	struct ext2_buffer_cache	 *bc;
	int				  metadirty;			/* 0:all sb&gd copies clean
									   1:all sb&gd copies dirty
									   2:only first sb&gd copy clean */

	int				  dynamic_version;
	int				  sparse;			/* sparse superblocks */
	int				  has_journal;			/* journal */
	int				  has_internal_journal;

	int				  blocksize;
	int				  logsize;
	blk_t				  adminblocks;
	blk_t				  gdblocks;
	blk_t				  itoffset;
	blk_t				  inodeblocks;
	int				  numgroups;
	int				  r_frac;			/* reserved % of blocks */

	unsigned char			 *relocator_pool;
	unsigned char			 *relocator_pool_end;

	int				 opt_debug;
	int				 opt_safe;
	int				 opt_verbose;

	void				 *journal;
};


#define EXT2_ACTION_ADD		1
#define EXT2_ACTION_DELETE	2
#define EXT2_ACTION_FIND	3

#define EXT2_META_CLEAN		0
#define EXT2_META_PRIMARY_SB	1
#define EXT2_META_BACKUP_SB	2
#define EXT2_META_PRIMARY_GD	4
#define EXT2_META_BACKUP_GD	8

#define EXT2_META_PRIMARY	(EXT2_META_PRIMARY_SB | EXT2_META_PRIMARY_GD)
#define EXT2_META_BACKUP	(EXT2_META_BACKUP_SB | EXT2_META_BACKUP_GD)
#define EXT2_META_SB		(EXT2_META_PRIMARY_SB | EXT2_META_BACKUP_SB)
#define EXT2_META_GD		(EXT2_META_PRIMARY_GD | EXT2_META_BACKUP_GD)

/* generic stuff */
int		ext2_copy_block			(struct ext2_fs *fs, blk_t from, blk_t to);
void		ext2_close			(struct ext2_fs *fs);
int		ext2_commit_metadata		(struct ext2_fs *fs, int copies);
off_t		ext2_get_inode_offset		(struct ext2_fs *fs, ino_t inode, blk_t *block);
blk_t		ext2_find_free_block		(struct ext2_fs *fs);
ino_t		ext2_find_free_inode		(struct ext2_fs *fs);
int		ext2_get_inode_state		(struct ext2_fs *fs, ino_t inode);
int		ext2_is_group_sparse		(struct ext2_fs *fs, int group);
int		ext2_move_blocks		(struct ext2_fs *fs, blk_t src, blk_t num, blk_t dest);
struct ext2_fs *ext2_open			(struct ext2_dev_handle *handle, int state);
int		ext2_read_blocks		(struct ext2_fs *fs, void *ptr, blk_t block, blk_t numblocks);
int		ext2_read_inode			(struct ext2_fs *fs, ino_t inode, struct ext2_inode *inodep);
int		ext2_set_inode_state		(struct ext2_fs *fs, ino_t inode, int state, int updatemetadata);
int		ext2_do_inode			(struct ext2_fs *fs, struct ext2_inode *inode, blk_t block, int action);
int		ext2_sync			(struct ext2_fs *fs);
int		ext2_write_blocks		(struct ext2_fs *fs, void *ptr, blk_t block, blk_t numblocks);
int		ext2_write_inode		(struct ext2_fs *fs, ino_t inode, const struct ext2_inode *inodep);
int		ext2_zero_blocks		(struct ext2_fs *fs, blk_t block, blk_t num);
int		ext2_zero_inode			(struct ext2_fs *fs, ino_t inode);

/* block related */
void		ext2_bgbitmap_cache_deinit	(struct ext2_fs *fs);
int		ext2_bgbitmap_cache_flush	(struct ext2_fs *fs);
int		ext2_bgbitmap_cache_init	(struct ext2_fs *fs);
int		ext2_get_block_state		(struct ext2_fs *, blk_t block);
int		ext2_set_block_state		(struct ext2_fs *, blk_t block, int state, int updatemetadata);

/* block relocator */
int		ext2_block_relocate		(struct ext2_fs *fs, blk_t newsize);

/* buffer */
void		ext2_bcache_deinit		(struct ext2_fs *fs);
void		ext2_bcache_dump		(struct ext2_fs *fs);
int		ext2_bcache_flush		(struct ext2_fs *fs, blk_t block);
int		ext2_bcache_flush_range		(struct ext2_fs *fs, blk_t first, blk_t last);
int 		ext2_bcache_init		(struct ext2_fs *fs);
int		ext2_bcache_sync		(struct ext2_fs *fs);
struct ext2_buffer_head *ext2_bcreate		(struct ext2_fs *fs, blk_t block);
struct ext2_buffer_head *ext2_bread		(struct ext2_fs *fs, blk_t block);
int		ext2_brelse			(struct ext2_buffer_head *bh, int forget);

/* inode relocator */
int		ext2_inode_relocate		(struct ext2_fs *fs, int newgroups);

/* journalling */
void		ext2_journal_deinit		(struct ext2_fs *fs);
int		ext2_journal_init		(struct ext2_fs *fs);

/* metadata mover */
int		ext2_metadata_push		(struct ext2_fs *fs, blk_t newsize);

/* fs creation */
struct ext2_fs *ext2_mkfs			(struct ext2_dev_handle *handle, blk_t numblocks, int log_block_size, blk_t blocks_per_group, int inodes_per_group, int sparse_sb, int reserved_block_percentage, PedTimer* timer);

/* resize */
int		ext2_resize_fs			(struct ext2_fs *fs, blk_t newsize, PedTimer* timer);

/* unix I/O */
struct ext2_dev_handle *ext2_make_dev_handle_from_file(char *dev);




static __inline__ int ext2_is_data_block(struct ext2_fs *fs, blk_t block)
{
	blk_t blk;
	int   group;

	PED_ASSERT (block >= EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb), return 0);
	PED_ASSERT (block < EXT2_SUPER_BLOCKS_COUNT(fs->sb), return 0);

	blk = block - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);

	group = blk / EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
	blk %= EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

	if (ext2_is_group_sparse(fs, group) && blk <= fs->gdblocks)
		return 0;

	if (block == EXT2_GROUP_BLOCK_BITMAP(fs->gd[group]) ||
	    block == EXT2_GROUP_INODE_BITMAP(fs->gd[group]))
		return 0;

	if (block >= EXT2_GROUP_INODE_TABLE(fs->gd[group]) &&
	    block < EXT2_GROUP_INODE_TABLE(fs->gd[group]) + fs->inodeblocks)
		return 0;

	return 1;
}

#endif
