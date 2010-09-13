/*
    ext2.c -- generic ext2 stuff
    Copyright (C) 1998, 1999, 2000, 2001, 2007 Free Software Foundation, Inc.

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

#include <config.h>

#ifndef DISCOVER_ONLY

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>
#include "ext2.h"

/* ext2 stuff ****************************************************************/

unsigned char _bitmap[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

int ext2_copy_block(struct ext2_fs *fs, blk_t from, blk_t to)
{
	unsigned char* buf = ped_malloc (fs->blocksize);

	if (!ext2_bcache_flush(fs, from)) return 0;
	if (!ext2_bcache_flush(fs, to)) return 0;

	if (!ext2_read_blocks(fs, buf, from, 1)) return 0;
	if (!ext2_write_blocks(fs, buf, to, 1)) return 0;

	return 1;
}

int ext2_get_block_state(struct ext2_fs *fs, blk_t block)
{
	struct ext2_buffer_head *bh;
	int group;
	int offset;
	int state;

	block -= EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
	group = block / EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
	offset = block % EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

	bh = ext2_bread(fs, EXT2_GROUP_BLOCK_BITMAP(fs->gd[group]));
	state = bh->data[offset>>3] & _bitmap[offset&7];
	ext2_brelse(bh, 0);

	return state;
}

blk_t ext2_find_free_block(struct ext2_fs *fs)
{
	int i;

	for (i=0;i<fs->numgroups;i++)
		if (EXT2_GROUP_FREE_BLOCKS_COUNT(fs->gd[i]))
		{
			blk_t j;
			blk_t offset;

			offset = i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb)
				 + EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
			for (j=fs->adminblocks;
			     j<EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
			     j++)
				if (ext2_is_data_block(fs, offset + j) &&
				    !ext2_get_block_state(fs, offset + j))
					return offset + j;

			ped_exception_throw (PED_EXCEPTION_ERROR,
				PED_EXCEPTION_CANCEL,
				_("Inconsistent group descriptors!"));
		}

	ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			     _("File system full!"));
	return 0;
}

ino_t ext2_find_free_inode(struct ext2_fs *fs)
{
	int i;

	for (i=0;i<fs->numgroups;i++)
		if (EXT2_GROUP_FREE_INODES_COUNT(fs->gd[i]))
		{
			ino_t j;
			ino_t offset;

			offset = i * EXT2_SUPER_INODES_PER_GROUP(fs->sb) + 1;
			for (j=0;j<EXT2_SUPER_INODES_PER_GROUP(fs->sb);j++)
				if (!ext2_get_inode_state(fs, offset + j))
					return offset + j;

			ped_exception_throw (PED_EXCEPTION_ERROR,
				PED_EXCEPTION_CANCEL,
				_("Inconsistent group descriptors!"));
		}

	ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			     _("File system full!"));
	return 0;
}

int ext2_move_blocks(struct ext2_fs *fs, blk_t src, blk_t num, blk_t dest)
{
	unsigned char *buf;
	blk_t i;

	ped_exception_fetch_all();
	if ((buf = ped_malloc(num << fs->logsize)) != NULL)
	{
		ped_exception_leave_all();

		if (!ext2_bcache_flush_range(fs, src, num)) return 0;
		if (!ext2_bcache_flush_range(fs, dest, num)) return 0;

		if (!ext2_read_blocks(fs, buf, src, num)) return 0;
		if (!ext2_write_blocks(fs, buf, dest, num)) return 0;

		ped_free(buf);
		return 1;
	}
	ped_exception_catch();
	ped_exception_leave_all();

	if (src > dest)
	{
		for (i=0;i<num;i++)
			if (!ext2_copy_block(fs, src+i, dest+i))
				return 0;
	}
	else
	{
		for (i=num;i>0;i--)
			if (!ext2_copy_block(fs, src+i, dest+i))
				return 0;
	}
	return 1;
}

int ext2_read_blocks(struct ext2_fs *fs, void *ptr, blk_t block, blk_t num)
{
	return fs->devhandle->ops->read(fs->devhandle->cookie, ptr, block, num);
}

int ext2_set_block_state(struct ext2_fs *fs, blk_t block, int state, int updatemetadata)
{
	struct ext2_buffer_head *bh;
	int                      group;
	int                      offset;

	block -= EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
	group = block / EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
	offset = block % EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

	bh = ext2_bread(fs, EXT2_GROUP_BLOCK_BITMAP(fs->gd[group]));
	bh->dirty = 1;
	if (state)
		bh->data[offset>>3] |= _bitmap[offset&7];
	else
		bh->data[offset>>3] &= ~_bitmap[offset&7];
	ext2_brelse(bh, 0);

	if (updatemetadata)
	{
		int diff;

		diff = state ? -1 : 1;

		fs->gd[group].bg_free_blocks_count = PED_CPU_TO_LE16
			(EXT2_GROUP_FREE_BLOCKS_COUNT(fs->gd[group]) + diff);
		fs->sb.s_free_blocks_count = PED_CPU_TO_LE32
			(EXT2_SUPER_FREE_BLOCKS_COUNT(fs->sb) + diff);
		fs->metadirty |= EXT2_META_SB | EXT2_META_GD;
	}
	return 1;
}

int ext2_write_blocks(struct ext2_fs *fs, void *ptr, blk_t block, blk_t num)
{
	return fs->devhandle->ops->write(fs->devhandle->cookie, ptr, block, num);
}

int ext2_zero_blocks(struct ext2_fs *fs, blk_t block, blk_t num)
{
	unsigned char *buf;
	blk_t i;

	ped_exception_fetch_all();
	buf = ped_malloc (num << fs->logsize);
	if (buf)
	{
		ped_exception_leave_all();

		memset(buf, 0, num << fs->logsize);
		if (!ext2_bcache_flush_range(fs, block, num))
			goto error_free_buf;
		if (!ext2_write_blocks(fs, buf, block, num))
			goto error_free_buf;
		ped_free(buf);
		return 1;
	}
	ped_exception_catch();

	buf = ped_malloc (fs->blocksize);
	if (buf)
	{
		ped_exception_leave_all();

		memset(buf, 0, fs->blocksize);

		for (i=0;i<num;i++)
		{
			if (!ext2_bcache_flush(fs, block+i))
				goto error_free_buf;
			if (!ext2_write_blocks(fs, buf, block+i, 1))
				goto error_free_buf;
		}

		ped_free(buf);
		return 1;
	}
	ped_exception_catch();
	ped_exception_leave_all();

	for (i=0;i<num;i++)
	{
		struct ext2_buffer_head *bh;

		bh = ext2_bcreate(fs, block+i);
		if (!bh)
			goto error;
		bh->dirty = 1;
		if (!ext2_brelse(bh, 1))
			goto error;
	}
	return 1;

error_free_buf:
	ped_free(buf);
error:
	return 0;
}

off_t ext2_get_inode_offset(struct ext2_fs *fs, ino_t inode, blk_t *block)
{
	int group;
	int offset;

	inode--;

	group = inode / EXT2_SUPER_INODES_PER_GROUP(fs->sb);
	offset = (inode % EXT2_SUPER_INODES_PER_GROUP(fs->sb))
	       	 * sizeof(struct ext2_inode);

	*block = EXT2_GROUP_INODE_TABLE(fs->gd[group])
	         + (offset >> fs->logsize);

	return offset & (fs->blocksize - 1);
}

int ext2_get_inode_state(struct ext2_fs *fs, ino_t inode)
{
	struct ext2_buffer_head *bh;
	int                      group;
	int                      offset;
	int                      ret;

	inode--;
	group = inode / EXT2_SUPER_INODES_PER_GROUP(fs->sb);
	offset = inode % EXT2_SUPER_INODES_PER_GROUP(fs->sb);

	bh = ext2_bread(fs, EXT2_GROUP_INODE_BITMAP(fs->gd[group]));
	ret = bh->data[offset>>3] & _bitmap[offset&7];
	ext2_brelse(bh, 0);

	return ret;
}

int ext2_read_inode(struct ext2_fs *fs, ino_t inode, struct ext2_inode *data)
{
	struct ext2_buffer_head *bh;
	blk_t			 blk;
	off_t			 off;

	off = ext2_get_inode_offset(fs, inode, &blk);

	bh = ext2_bread(fs, blk);
	if (!bh)
		return 0;

	memcpy(data, bh->data + off, sizeof(struct ext2_inode));
	ext2_brelse(bh, 0);
	return 1;
}

int ext2_set_inode_state(struct ext2_fs *fs, ino_t inode, int state, int updatemetadata)
{
	struct ext2_buffer_head *bh;
	int                      group;
	int                      offset;

	inode--;
	group = inode / EXT2_SUPER_INODES_PER_GROUP(fs->sb);
	offset = inode % EXT2_SUPER_INODES_PER_GROUP(fs->sb);

	bh = ext2_bread(fs, EXT2_GROUP_INODE_BITMAP(fs->gd[group]));
	if (!bh)
		return 0;
	bh->dirty = 1;
	if (state)
		bh->data[offset>>3] |= _bitmap[offset&7];
	else
		bh->data[offset>>3] &= ~_bitmap[offset&7];
	ext2_brelse(bh, 0);

	if (updatemetadata)
	{
		int diff;

		diff = state ? -1 : 1;

		fs->gd[group].bg_free_inodes_count = PED_CPU_TO_LE16
			(EXT2_GROUP_FREE_INODES_COUNT(fs->gd[group]) + diff);
		fs->sb.s_free_inodes_count = PED_CPU_TO_LE32
			(EXT2_SUPER_FREE_INODES_COUNT(fs->sb) + diff);
		fs->metadirty = EXT2_META_SB | EXT2_META_GD;
	}
	return 1;
}

static void
_inode_update_size(struct ext2_fs *fs, struct ext2_inode *inode, int delta)
{
	int		i512perblock = 1 << (fs->logsize - 9);
	uint64_t	size;

	/* i_blocks is in 512 byte blocks */
	inode->i_blocks = PED_CPU_TO_LE32(EXT2_INODE_BLOCKS(*inode)
		       			  + delta * i512perblock);
	size = EXT2_INODE_SIZE(*inode) + delta * fs->blocksize;
	inode->i_size = PED_CPU_TO_LE32(size % (1LL << 32));
	inode->i_size_high = PED_CPU_TO_LE32(size / (1LL << 32));
	inode->i_mtime = PED_CPU_TO_LE32(time(NULL));
}

int ext2_do_inode(struct ext2_fs *fs, struct ext2_inode *inode, blk_t block,
		   int action)
{
	struct ext2_buffer_head *bh;
	uint32_t		*udata;
	blk_t			 count = 0;
	int			 i;
	int			 u32perblock = fs->blocksize >> 2;
	int			 i512perblock = 1 << (fs->logsize - 9);

	if (block == 0 || EXT2_INODE_MODE(*inode) == 0)
		return -1;

	if (fs->opt_debug)
		switch (action)
		{
			case EXT2_ACTION_ADD:
				fprintf(stderr,"adding 0x%04x to inode\n",
					block);
				break;
			case EXT2_ACTION_DELETE:
				fprintf(stderr,"deleting 0x%04x from inode\n",
					block);
				break;
			case EXT2_ACTION_FIND:
				fprintf(stderr,"finding 0x%04x in inode\n",
					block);
				break;
		}

	/* Direct blocks for first 12 blocks */
	for (i = 0; i < EXT2_NDIR_BLOCKS; i++)
	{
		if (action == EXT2_ACTION_ADD && !EXT2_INODE_BLOCK(*inode, i))
		{
			inode->i_block[i] = PED_CPU_TO_LE32(block);
			_inode_update_size (fs, inode, 1);
			ext2_set_block_state(fs, block, 1, 1);
			return i;
		}
		if (EXT2_INODE_BLOCK(*inode, i) == block)
		{
			if (action == EXT2_ACTION_DELETE)
			{
				inode->i_block[i] = 0;
				_inode_update_size (fs, inode, -1);
				ext2_set_block_state(fs, block, 0, 1);
			}
			return i;
		}
		if (EXT2_INODE_BLOCK(*inode, i))
			count += i512perblock;
	}

	count += EXT2_INODE_BLOCK(*inode, EXT2_IND_BLOCK) ? i512perblock : 0;
	count += EXT2_INODE_BLOCK(*inode, EXT2_DIND_BLOCK) ? i512perblock : 0;
	count += EXT2_INODE_BLOCK(*inode, EXT2_TIND_BLOCK) ? i512perblock : 0;

	if (!EXT2_INODE_BLOCK(*inode, EXT2_IND_BLOCK) ||
	    (count >= EXT2_INODE_BLOCKS(*inode) && action != EXT2_ACTION_ADD))
		return -1;

	bh = ext2_bread(fs, EXT2_INODE_BLOCK(*inode, EXT2_IND_BLOCK));
	udata = (uint32_t *)bh->data;

	/* Indirect blocks for next 256/512/1024 blocks (for 1k/2k/4k blocks) */
	for (i = 0; i < u32perblock; i++) {
		if (action == EXT2_ACTION_ADD && !udata[i]) {
			bh->dirty = 1;
			udata[i] = PED_CPU_TO_LE32(block);
			_inode_update_size (fs, inode, 1);
			ext2_set_block_state(fs, block, 1, 1);
			ext2_brelse(bh, 0);
			return EXT2_NDIR_BLOCKS + i;
		}
		if (PED_LE32_TO_CPU(udata[i]) == block) {
			if (action == EXT2_ACTION_DELETE) {
				bh->dirty = 1;
				udata[i] = 0;
				_inode_update_size (fs, inode, -1);
				ext2_set_block_state(fs, block, 0, 1);
			}
			ext2_brelse(bh, 0);
			return EXT2_NDIR_BLOCKS + i;
		}
		if (udata[i])
		{
			count += i512perblock;
			if (count >= EXT2_INODE_BLOCKS(*inode) &&
			    action != EXT2_ACTION_ADD)
				return -1;
		}
	}

	ext2_brelse(bh, 0);

	if (!EXT2_INODE_BLOCK(*inode, EXT2_DIND_BLOCK) ||
	    (count >= EXT2_INODE_BLOCKS(*inode) && action != EXT2_ACTION_ADD))
		return -1;
	bh = ext2_bread(fs, EXT2_INODE_BLOCK(*inode, EXT2_DIND_BLOCK));
	udata = (uint32_t *)bh->data;

	/* Double indirect blocks for next 2^16/2^18/2^20 1k/2k/4k blocks */
	for (i = 0; i < u32perblock; i++) {
		struct ext2_buffer_head	*bh2;
		uint32_t			*udata2;
		int			 j;

		if (!udata[i]) {
			ext2_brelse(bh, 0);
			return -1;
		}
		bh2 = ext2_bread(fs, PED_LE32_TO_CPU(udata[i]));
		udata2 = (uint32_t *)bh2->data;
		count += i512perblock;

		for (j = 0; j < u32perblock; j++) {
			if (action == EXT2_ACTION_ADD && !udata2[j]) {
				bh2->dirty = 1;
				udata2[j] = PED_CPU_TO_LE32(block);
				_inode_update_size (fs, inode, 1);
				ext2_set_block_state(fs, block, 1, 1);
				ext2_brelse(bh, 0);
				ext2_brelse(bh2, 0);
				return EXT2_NDIR_BLOCKS + i * u32perblock + j;
			}
			if (PED_LE32_TO_CPU(udata2[j]) == block) {
				if (action == EXT2_ACTION_DELETE) {
					bh2->dirty = 1;
					udata2[j] = 0;
					_inode_update_size (fs, inode, -1);
					ext2_set_block_state(fs, block, 0, 1);
				}
				ext2_brelse(bh, 0);
				ext2_brelse(bh2, 0);
				return EXT2_NDIR_BLOCKS + i * u32perblock + j;
			}
			if (udata2[j])
			{
				count += i512perblock;
				if (count >= EXT2_INODE_BLOCKS(*inode) &&
				    action != EXT2_ACTION_ADD)
					return -1;
			}
		}
		ext2_brelse(bh2, 0);
	}
	ext2_brelse(bh, 0);

	/* FIXME: we should check for triple-indirect blocks here, but it
	 * would be nice to have a better routine to traverse blocks, and
	 * file systems that need triple-indirect blocks for the resize
	 * inode are too big to worry about yet.
	 */

	return -1;
}

int ext2_write_inode(struct ext2_fs *fs, ino_t inode, const struct ext2_inode *data)
{
	struct ext2_buffer_head *bh;
	blk_t			 blk;
	off_t			 off;

	off = ext2_get_inode_offset(fs, inode, &blk);

	bh = ext2_bread(fs, blk);
	if (!bh)
		return 0;
	bh->dirty = 1;
	memcpy(bh->data + off, data, sizeof(struct ext2_inode));
	ext2_brelse(bh, 0);

	return 1;
}

int ext2_zero_inode(struct ext2_fs *fs, ino_t inode)
{
	struct ext2_inode buf;

	memset(&buf, 0, sizeof(struct ext2_inode));
	return ext2_write_inode(fs, inode, &buf);
}





/* check whether y is root of x
 * (formula grabbed from linux ext2 kernel source) */
static int is_root(int x, int y)
{
	if (!x)
		return 1;

	while (1)
	{
		if (x == 1)
			return 1;

		if (x % y)
			return 0;

		x /= y;
	}
}

/* check whether group contains a superblock copy on file systems
 * where not all groups have one (sparse superblock feature) */
int ext2_is_group_sparse(struct ext2_fs *fs, int group)
{       
	if (!fs->sparse)
		return 1;

	if (is_root(group, 3) || is_root(group, 5) || is_root(group, 7))
		return 1;

	return 0;
}

void ext2_close(struct ext2_fs *fs)
{
	ext2_commit_metadata(fs, EXT2_META_PRIMARY | EXT2_META_BACKUP);
	ext2_sync(fs);

	ext2_bcache_deinit(fs);

	fs->devhandle->ops->close(fs->devhandle->cookie);

	ped_free(fs->gd);
	ped_free(fs);
}

int ext2_commit_metadata(struct ext2_fs *fs, int copies)
{
	int		i;
	int		num;
	int		wmeta = fs->metadirty & copies;
	unsigned char*	sb = ped_malloc(fs->blocksize);
	struct ext2_super_block *sb_for_io;
	int		sb_block;

	/* See if there is even anything to write... */
	if (wmeta == EXT2_META_CLEAN)
		return 1;

	fs->sb.s_r_blocks_count = PED_CPU_TO_LE32 (
		fs->r_frac * (loff_t)EXT2_SUPER_BLOCKS_COUNT(fs->sb)
				  / 100);

	if (!ext2_read_blocks (fs, sb, 0, 1))
		return 0;

	if (EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb)) {
		memcpy(sb, &fs->sb, 1024);
		sb_for_io = (struct ext2_super_block *) sb;
	} else {
		memcpy(sb+1024, &fs->sb, 1024);
		sb_for_io = (struct ext2_super_block *) (sb + 1024);
	}

	num = copies & EXT2_META_BACKUP ? fs->numgroups : 1;

	for (i = 0, sb_block = EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb); i < num;
	     i++, sb_block += EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
	{

		if (!ext2_is_group_sparse(fs, i))
			continue;

		if (fs->dynamic_version)
			sb_for_io->s_block_group_nr = PED_CPU_TO_LE16 (i);

		if ((i == 0 && wmeta & EXT2_META_PRIMARY_SB) ||
		    (i != 0 && wmeta & EXT2_META_SB))
		{
			if (!ext2_bcache_flush_range(fs, sb_block, 1))
				return 0;
			if (!ext2_write_blocks(fs, sb, sb_block, 1))
				return 0;
		}
		if ((i == 0 && wmeta & EXT2_META_PRIMARY_GD) ||
		    (i != 0 && wmeta & EXT2_META_GD))
		{
			if (!ext2_bcache_flush_range(fs, sb_block + 1,
						     fs->gdblocks))
				return 0;
			if (!ext2_write_blocks(fs, fs->gd, sb_block + 1,
					       fs->gdblocks))
				return 0;
		}
	}

	sb_for_io->s_block_group_nr = 0;

	/* Clear the flags of the components we just finished writing. */
	fs->metadirty &= ~copies;

	return 1;
}

int ext2_sync(struct ext2_fs *fs)
{
	if (!ext2_commit_metadata(fs, EXT2_META_PRIMARY)) return 0;
	if (!ext2_bcache_sync(fs)) return 0;
	if (!fs->devhandle->ops->sync(fs->devhandle->cookie)) return 0;
	return 1;
}

struct ext2_fs *ext2_open(struct ext2_dev_handle *handle, int state)
{
	struct ext2_fs *fs;

	if ((fs = (struct ext2_fs *) ped_malloc(sizeof(struct ext2_fs)))
		== NULL)
		goto error;

	handle->ops->set_blocksize(handle->cookie, 10);

	if (!handle->ops->read(handle->cookie, &fs->sb, 1, 1)
	    || EXT2_SUPER_MAGIC(fs->sb) != EXT2_SUPER_MAGIC_CONST)
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("Invalid superblock.  Are you sure this is an ext2 "
			  "file system?"));
		goto error_free_fs;
	}


	fs->opt_debug = 1;
	fs->opt_safe = 1;
	fs->opt_verbose = 0;

	if (EXT2_SUPER_STATE(fs->sb) & EXT2_ERROR_FS & ~(state & EXT2_ERROR_FS))
	{
		if (ped_exception_throw (
			PED_EXCEPTION_WARNING, PED_EXCEPTION_IGNORE_CANCEL,
			_("File system has errors!  You should run e2fsck."))
				== PED_EXCEPTION_CANCEL)
			goto error_free_fs;
	}

	if (!((EXT2_SUPER_STATE(fs->sb) | state) & EXT2_VALID_FS)
	    || (EXT2_SUPER_FEATURE_INCOMPAT(fs->sb)
		& EXT3_FEATURE_INCOMPAT_RECOVER))
	{
		if (ped_exception_throw (
			PED_EXCEPTION_ERROR, PED_EXCEPTION_IGNORE_CANCEL,
			_("File system was not cleanly unmounted!  "
			  "You should run e2fsck.  Modifying an unclean "
			  "file system could cause severe corruption."))
				!= PED_EXCEPTION_IGNORE)
			goto error_free_fs;
	}

	fs->dynamic_version = EXT2_SUPER_REV_LEVEL (fs->sb) > 0;

	if ((EXT2_SUPER_FEATURE_COMPAT(fs->sb)
	                & ~(EXT3_FEATURE_COMPAT_HAS_JOURNAL |
			    EXT2_FEATURE_COMPAT_HAS_DIR_INDEX)) ||
	    (EXT2_SUPER_FEATURE_INCOMPAT(fs->sb)
	    		& ~(EXT2_FEATURE_INCOMPAT_FILETYPE |
			    EXT3_FEATURE_INCOMPAT_RECOVER)) ||
	    (EXT2_SUPER_FEATURE_RO_COMPAT(fs->sb)
			& ~(EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER |
			    EXT2_FEATURE_RO_COMPAT_LARGE_FILE)))
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
		     _("File system has an incompatible feature enabled."));
		goto error_free_fs;
	}

	fs->devhandle = handle;
	fs->logsize = EXT2_SUPER_LOG_BLOCK_SIZE(fs->sb) + 10;
	handle->ops->set_blocksize(handle->cookie, fs->logsize);

	if (!ext2_bcache_init(fs))
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
				     _("Error allocating buffer cache."));
		goto error_free_fs;
	}

	fs->blocksize = 1 << fs->logsize;

	fs->numgroups = ped_div_round_up (EXT2_SUPER_BLOCKS_COUNT(fs->sb)
		       		- EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb),
				EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb));
	fs->gdblocks = ped_div_round_up (fs->numgroups
                        * sizeof(struct ext2_group_desc),
			       fs->blocksize);
	fs->inodeblocks = ped_div_round_up (EXT2_SUPER_INODES_PER_GROUP(fs->sb)
		       		  * sizeof(struct ext2_inode),
				  fs->blocksize);
	fs->r_frac = ped_div_round_up (100 * (loff_t)EXT2_SUPER_R_BLOCKS_COUNT(fs->sb),
		       	     EXT2_SUPER_BLOCKS_COUNT(fs->sb));
	fs->adminblocks = 3 + fs->gdblocks + fs->inodeblocks;

	fs->sparse = 0;
	if (EXT2_SUPER_FEATURE_RO_COMPAT(fs->sb)
			& EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER)
		fs->sparse = 1;

	fs->has_journal = 0 < (EXT2_SUPER_FEATURE_COMPAT(fs->sb)
			       & EXT3_FEATURE_COMPAT_HAS_JOURNAL);
	fs->has_internal_journal
		= fs->has_journal
			&& uuid_is_null(EXT2_SUPER_JOURNAL_UUID(fs->sb))
			&& EXT2_SUPER_JOURNAL_INUM(fs->sb);

	fs->gd = ped_malloc (fs->numgroups * sizeof (struct ext2_group_desc)
			     	+ fs->blocksize);
	if (!fs->gd)
		goto error_deinit_bcache;

	ext2_read_blocks(fs, fs->gd, EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb) + 1,
			 fs->gdblocks);
                
	fs->metadirty = 0;
	return fs;

	ped_free(fs->gd);
error_deinit_bcache:
	ext2_bcache_deinit(fs);
error_free_fs:
	ped_free(fs);
error:
	return NULL;
}

#endif /* !DISCOVER_ONLY */
