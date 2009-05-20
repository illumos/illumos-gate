/*
    ext2_mkfs.c -- ext2 fs creator
    Copyright (C) 1999, 2000, 2001, 2007 Free Software Foundation, Inc.

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

#define USE_EXT2_IS_DATA_BLOCK

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "ext2.h"

/* formula grabbed from linux ext2 kernel source
 * 
 * returns 1 iff:
 * 	x == y^N,       N is some natural number
 * OR	x == 0
 */
static __inline__ int is_root(int x, int y)
{
	if (!x) return 1;

	while (1)
	{
		if (x == 1) return 1;

		if (x % y) return 0;

		x /= y;
	}
}

static __inline__ int is_group_sparse(int sparsesbfs, int group)
{
	if (!sparsesbfs)
		return 1;

	if (is_root(group, 3) || is_root(group, 5) || is_root(group, 7))
		return 1;

	return 0;
}

/* has implicit parameter 'sb' !! */
#define is_sparse(group) is_group_sparse(EXT2_SUPER_FEATURE_RO_COMPAT(*sb) \
	       			& EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER, (group))

static int ext2_mkfs_write_main(struct ext2_dev_handle *handle,
				struct ext2_super_block *sb,
				struct ext2_group_desc *gd)
{
	int freeit;
	int i;
	int numgroups;
	int gdblocks;
	unsigned char *sbbuf;
	struct ext2_super_block *sb_for_io;

	freeit = 0;
	sbbuf = (unsigned char *)sb;
	sb_for_io = sb;
	if (EXT2_SUPER_LOG_BLOCK_SIZE(*sb))
	{
		sbbuf = ped_malloc(1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb));
		if (!(handle->ops->read)(handle->cookie, sbbuf, 0, 1))
			return 0;
		memcpy (sbbuf+1024, sb, 1024);
		freeit = 1;
		sb_for_io = (struct ext2_super_block*) (sbbuf + 1024);
	}

	numgroups = ped_div_round_up (EXT2_SUPER_BLOCKS_COUNT(*sb)
			        - EXT2_SUPER_FIRST_DATA_BLOCK(*sb),
			    EXT2_SUPER_BLOCKS_PER_GROUP(*sb));
	gdblocks = ped_div_round_up (numgroups * sizeof(struct ext2_group_desc),
			   1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb));

	for (i=0;i<numgroups;i++)
	{
		if (is_sparse(i))
		{
			int offset;

			offset = EXT2_SUPER_FIRST_DATA_BLOCK(*sb)
				 + i * EXT2_SUPER_BLOCKS_PER_GROUP(*sb);

			sb_for_io->s_block_group_nr = PED_CPU_TO_LE16 (i);

			if (!handle->ops->write(handle->cookie, sbbuf,
					        offset, 1))
				return 0;
			if (!handle->ops->write(handle->cookie, gd, offset+1,
						gdblocks))
				return 0;
		}
	}

	sb_for_io->s_block_group_nr = 0;

	if (freeit)
		ped_free(sbbuf);
	return 1;
}

static int ext2_mkfs_write_meta(struct ext2_dev_handle *handle,
				struct ext2_super_block *sb,
				struct ext2_group_desc *gd,
				PedTimer* timer)
{
	int blocksize;
	int gdtsize;
	int i;
	int itsize;
	int numgroups;
	unsigned char *bb;
	unsigned char *ib;
	unsigned char *zero;

	blocksize = 1 << (EXT2_SUPER_LOG_BLOCK_SIZE(*sb) + 13);

	numgroups = ped_div_round_up (EXT2_SUPER_BLOCKS_COUNT(*sb)
				- EXT2_SUPER_FIRST_DATA_BLOCK(*sb),
			    EXT2_SUPER_BLOCKS_PER_GROUP(*sb));
	itsize = ped_div_round_up (sizeof(struct ext2_inode)
				* EXT2_SUPER_INODES_PER_GROUP(*sb),
			 (1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb)));
	gdtsize = ped_div_round_up (sizeof(struct ext2_group_desc) * numgroups,
			  (1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb)));

	bb = ped_malloc(1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb));
	if (!bb) goto error;
	ib = ped_malloc(1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb));
	if (!ib) goto error_free_bb;
	zero = ped_malloc((1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb)) * itsize);
	if (!zero) goto error_free_zero;

	memset(zero, 0, (1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb)) * itsize);

	ped_timer_reset (timer);
	ped_timer_set_state_name (timer, _("writing per-group metadata"));

	for (i=0;i<numgroups;i++)
	{
		int admin;
		blk_t bbblock;
		int groupsize;
		int groupoffset;
		blk_t ibblock;
		int j;

		ped_timer_update (timer, 1.0 * i / numgroups);

		groupoffset = i*EXT2_SUPER_BLOCKS_PER_GROUP(*sb)
			      + EXT2_SUPER_FIRST_DATA_BLOCK(*sb);
		groupsize = PED_MIN(EXT2_SUPER_BLOCKS_COUNT(*sb) - groupoffset,
				    EXT2_SUPER_BLOCKS_PER_GROUP(*sb));

		admin = itsize + 2;
		bbblock = groupoffset;
		ibblock = groupoffset + 1;
		if (is_sparse(i))
		{
			admin += gdtsize + 1;
			bbblock = groupoffset + gdtsize + 1;
			ibblock = groupoffset + gdtsize + 2;
		}

		{
			memset(bb, 0, 1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb));
			if (is_sparse(i))
				for (j=0;j<gdtsize+1;j++)
					bb[j>>3] |= _bitmap[j&7];

			j = bbblock - groupoffset;
			bb[j>>3] |= _bitmap[j&7];

			j = ibblock - groupoffset;
			bb[j>>3] |= _bitmap[j&7];

			for (j=0;j<itsize;j++)
			{
				int k = j + gdtsize + 3;

				bb[k>>3] |= _bitmap[k&7];
			}

			for (j=groupsize;j<blocksize;j++)
				bb[j>>3] |= _bitmap[j&7];

			if (!handle->ops->write(handle->cookie, bb, bbblock, 1))
				goto error_free_zero;
		}

		{
			memset(ib, 0, 1024 << EXT2_SUPER_LOG_BLOCK_SIZE(*sb));

			for (j=EXT2_SUPER_INODES_PER_GROUP(*sb);j<blocksize;j++)
				bb[j>>3] |= _bitmap[j&7];

			if (!handle->ops->write(handle->cookie, ib, ibblock, 1))
				goto error_free_zero;
		}

		if (!handle->ops->write(handle->cookie, zero,
					groupoffset + gdtsize + 3, itsize))
			goto error_free_zero;

		gd[i].bg_block_bitmap = PED_CPU_TO_LE32(bbblock);
		gd[i].bg_inode_bitmap = PED_CPU_TO_LE32(ibblock);
		gd[i].bg_inode_table = PED_CPU_TO_LE32(groupoffset + gdtsize
						       + 3);
		gd[i].bg_free_blocks_count = PED_CPU_TO_LE16(groupsize - admin);
		gd[i].bg_free_inodes_count = PED_CPU_TO_LE16(
			EXT2_SUPER_INODES_PER_GROUP(*sb));
		gd[i].bg_used_dirs_count = 0;
		gd[i].bg_used_dirs_count = 0;
		gd[i].bg_pad = 0;
		gd[i].bg_reserved[0] = 0;
		gd[i].bg_reserved[1] = 0;
		gd[i].bg_reserved[2] = 0;

		sb->s_free_blocks_count = PED_CPU_TO_LE32 (
			EXT2_SUPER_FREE_BLOCKS_COUNT(*sb)
			+ EXT2_GROUP_FREE_BLOCKS_COUNT(gd[i]));
	}

	ped_timer_update (timer, 1.0);

	ped_free(zero);
	ped_free(ib);
	ped_free(bb);
	return 1;

error_free_zero:
	ped_free(zero);
	ped_free(ib);
error_free_bb:
	ped_free(bb);
error:
	return 0;
}

/* returns the offset into the buffer of the start of the next dir entry */
static int _set_dirent(void* buf, int offset, int block_size, int is_last,
		       uint32_t inode, char* name, int file_type)
{
	struct ext2_dir_entry_2 *dirent = (void*) (((char*)buf) + offset);
	int name_len = strlen(name);
	int rec_len;

	if (is_last)
		rec_len = block_size - offset;
	else
		rec_len = ped_round_up_to(name_len + 1 + 8, 4);

	memset (dirent, 0, rec_len);

	dirent->inode = PED_CPU_TO_LE32(inode);
	dirent->name_len = name_len;
	dirent->rec_len = PED_CPU_TO_LE16(rec_len);
	dirent->file_type = file_type;
	strcpy(dirent->name, name);

	return offset + rec_len;
}

static int ext2_mkfs_create_lost_and_found_inode(struct ext2_fs *fs)
{
	struct ext2_buffer_head *bh;
	blk_t blocks[12];
	uint32_t* data = ped_malloc ((fs->blocksize / 4) * sizeof(uint32_t));
	int i;
	struct ext2_inode inode;
	int offset;

	for (i=0;i<12;i++)
	{
		if (!(blocks[i] = ext2_find_free_block(fs)))
			return 0;

		if (!ext2_set_block_state(fs, blocks[i], 1, 1))
			return 0;
	}

	/* create the directory entries, preallocating lots of blocks */
	/* first block contains . and .. */
	bh = ext2_bcreate(fs, blocks[0]);
	if (!bh)
		return 0;
	memset(bh->data, 0, fs->blocksize);
	offset = _set_dirent(bh->data, 0, fs->blocksize, 0,
			     11, ".", EXT2_FT_DIR);
	offset = _set_dirent(bh->data, offset, fs->blocksize, 1,
			     EXT2_ROOT_INO, "..", EXT2_FT_DIR);
	bh->dirty = 1;
	ext2_brelse(bh, 1);

	/* subsequent blocks are empty */
	memset(data, 0, fs->blocksize);
	data[0] = 0;
	data[1] = PED_CPU_TO_LE32(fs->blocksize);
	for (i=1;i<12;i++)
	{
		bh = ext2_bcreate(fs, blocks[i]);
		memcpy(bh->data, data, fs->blocksize);
		bh->dirty = 1;
		ext2_brelse(bh, 1);
	}

	/* create inode */
	memset(&inode, 0, sizeof(struct ext2_inode));
	inode.i_mode = PED_CPU_TO_LE16(S_IFDIR | 0755);
	inode.i_uid = 0;
	inode.i_size = PED_CPU_TO_LE32(12 * fs->blocksize);
	inode.i_atime = PED_CPU_TO_LE32(time(NULL));
	inode.i_ctime = PED_CPU_TO_LE32(time(NULL));
	inode.i_mtime = PED_CPU_TO_LE32(time(NULL));
	inode.i_dtime = 0;
	inode.i_gid = 0;
	inode.i_links_count = PED_CPU_TO_LE16(2);
	inode.i_blocks = PED_CPU_TO_LE32((12 * fs->blocksize) >> 9);
	inode.i_flags = 0;
	for (i=0;i<12;i++)
		inode.i_block[i] = PED_CPU_TO_LE32(blocks[i]);

	if (!ext2_write_inode(fs, 11, &inode))
		return 0;
	fs->gd[0].bg_used_dirs_count = PED_CPU_TO_LE16(
		EXT2_GROUP_USED_DIRS_COUNT(fs->gd[0]) + 1);
	fs->metadirty |= EXT2_META_GD;

	return 1;
}

static int ext2_mkfs_create_root_inode(struct ext2_fs *fs)
{
	struct ext2_buffer_head *bh;
	blk_t block;
	struct ext2_inode inode;
	int offset;

	if (!(block = ext2_find_free_block(fs)))
		return 0;
	if (!ext2_set_block_state(fs, block, 1, 1))
		return 0;

	/* create directory entries */
	bh = ext2_bcreate(fs, block);
	memset(bh->data, 0, fs->blocksize);
	offset = _set_dirent(bh->data, 0, fs->blocksize, 0,
			     EXT2_ROOT_INO, ".", EXT2_FT_DIR);
	offset = _set_dirent(bh->data, offset, fs->blocksize, 0,
			     EXT2_ROOT_INO, "..", EXT2_FT_DIR);
	offset = _set_dirent(bh->data, offset, fs->blocksize, 1,
			     11, "lost+found", EXT2_FT_DIR);
	bh->dirty = 1;
	if (!ext2_brelse(bh, 1))
		return 0;

	/* create inode */
	memset(&inode, 0, sizeof(struct ext2_inode));
	inode.i_mode = PED_CPU_TO_LE16(S_IFDIR | 0755);
	inode.i_uid = 0;
	inode.i_size = PED_CPU_TO_LE32(fs->blocksize);
	inode.i_atime = PED_CPU_TO_LE32(time(NULL));
	inode.i_ctime = PED_CPU_TO_LE32(time(NULL));
	inode.i_mtime = PED_CPU_TO_LE32(time(NULL));
	inode.i_dtime = 0;
	inode.i_gid = 0;
	inode.i_links_count = PED_CPU_TO_LE16(3);
	inode.i_blocks = PED_CPU_TO_LE32(fs->blocksize >> 9);
	inode.i_flags = 0;
	inode.i_block[0] = PED_CPU_TO_LE32(block);

	if (!ext2_write_inode(fs, 2, &inode))
		return 0;
	fs->gd[0].bg_used_dirs_count = PED_CPU_TO_LE16 (
		EXT2_GROUP_USED_DIRS_COUNT(fs->gd[0]) + 1);
	fs->metadirty |= EXT2_META_GD;

	return 1;
}

static int ext2_reserve_inodes(struct ext2_fs *fs)
{
	int i;

	for (i=1;i<12;i++)
		if (!ext2_set_inode_state(fs, i, 1, 1))
			return 0;
	return 1;
}

static int ext2_mkfs_init_sb (struct ext2_super_block *sb, blk_t numblocks,
			      int numgroups, int first_block,
			      int log_block_size, blk_t blocks_per_group,
			      int inodes_per_group, int sparse_sb,
			      int reserved_block_percentage)
{
	/* catch a bug in gcc 2.95.2 */
	PED_ASSERT(numgroups != 0, return 0);

	memset(sb, 0, 1024);

	sb->s_inodes_count = PED_CPU_TO_LE32(numgroups * inodes_per_group);
	sb->s_blocks_count = PED_CPU_TO_LE32(numblocks);
	sb->s_r_blocks_count = PED_CPU_TO_LE32(((uint64_t)numblocks
				* reserved_block_percentage) / 100);

	/* hack: this get's inc'd as we go through each group in
	 * ext2_mkfs_write_meta()
	 */
	sb->s_free_blocks_count = 0;
	sb->s_free_inodes_count = PED_CPU_TO_LE32 (numgroups
							* inodes_per_group);
	sb->s_first_data_block = PED_CPU_TO_LE32(first_block);
	sb->s_log_block_size = PED_CPU_TO_LE32(log_block_size - 10);
	sb->s_log_frag_size = sb->s_log_block_size;
	sb->s_blocks_per_group = PED_CPU_TO_LE32(blocks_per_group);
	sb->s_frags_per_group = PED_CPU_TO_LE32(blocks_per_group);
	sb->s_inodes_per_group = PED_CPU_TO_LE32(inodes_per_group);
	sb->s_mtime = 0;
	sb->s_wtime = 0;
	sb->s_mnt_count = 0;
	sb->s_max_mnt_count = PED_CPU_TO_LE16(30);
	sb->s_magic = PED_CPU_TO_LE16(0xEF53);
	sb->s_state = PED_CPU_TO_LE16(EXT2_VALID_FS);
	sb->s_errors = PED_CPU_TO_LE16(EXT2_ERRORS_DEFAULT);
	sb->s_minor_rev_level = 0;
	sb->s_lastcheck = 0;
	sb->s_checkinterval = 0;
	sb->s_creator_os = 0;
	sb->s_rev_level = PED_CPU_TO_LE32(1);
	sb->s_def_resuid = 0;
	sb->s_def_resgid = 0;
	sb->s_first_ino = PED_CPU_TO_LE32(11);
	sb->s_inode_size = PED_CPU_TO_LE16(128);
	sb->s_block_group_nr = 0;
	sb->s_feature_compat = 0;
	sb->s_feature_incompat = 0;
	sb->s_feature_ro_compat = 0;
	if (sparse_sb)
		sb->s_feature_ro_compat
			|= PED_CPU_TO_LE32(EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER);

/* FIXME: let the user decide? _set_dirent() assumes FILETYPE */
	sb->s_feature_incompat
		|= PED_CPU_TO_LE32(EXT2_FEATURE_INCOMPAT_FILETYPE);

	uuid_generate(sb->s_uuid);
	memset(sb->s_volume_name, 0, 16);
	memset(sb->s_last_mounted, 0, 64);
	sb->s_algorithm_usage_bitmap = 0;
	sb->s_prealloc_blocks = 0;
	sb->s_prealloc_dir_blocks = 0;
	sb->s_padding1 = 0;

	return 1;
}

/* Given these five inputs, compute the three outputs.  */
static void
compute_block_counts (blk_t numblocks, int numgroups, int log_block_size,
                      int sparse_sb, blk_t blocks_per_group,
                      int *last_group_blocks,
                      int *last_group_admin,
                      int *inodes_per_group)
{
        int first_block = (log_block_size == 10) ? 1 : 0;
        size_t block_size = 1 << log_block_size;

        *last_group_blocks = ((numblocks - first_block) % blocks_per_group);
        if (!*last_group_blocks)
                *last_group_blocks = blocks_per_group;
        *inodes_per_group = ped_round_up_to (numblocks / numgroups / 2,
                                             (block_size
                                              / sizeof(struct ext2_inode)));
        *last_group_admin = (2 + *inodes_per_group * sizeof(struct ext2_inode)
                             / block_size);
        if (is_group_sparse(sparse_sb, numgroups - 1)) {
                *last_group_admin +=
                  (ped_div_round_up (numgroups * sizeof(struct ext2_group_desc),
                                     block_size));
        }
}

struct ext2_fs *ext2_mkfs(struct ext2_dev_handle *handle,
			  blk_t numblocks,
			  int log_block_size,
			  blk_t blocks_per_group,
			  int inodes_per_group,
			  int sparse_sb,
			  int reserved_block_percentage,
			  PedTimer* timer)
{
	struct ext2_fs *fs;
	struct ext2_super_block sb;
	struct ext2_group_desc *gd;
	int numgroups;
	int first_block;
	int last_group_blocks;
	int last_group_admin;
        
	/* if the FS is > 512Mb, use 4k blocks, otherwise 1k blocks */
	if (log_block_size == 0) {
		handle->ops->set_blocksize(handle->cookie, 12);
		if (handle->ops->get_size(handle->cookie) > (512 * 1024))
			log_block_size = 12;
		else
			log_block_size = 10;
	}

        /* FIXME: block size must be > MAX(logicalbs, physicalbs)
         * to avoid modify-on-write.
         *      -- Leslie
         */ 

        
	handle->ops->set_blocksize(handle->cookie, log_block_size);

	if (numblocks == 0)
		numblocks = handle->ops->get_size(handle->cookie);
        if (numblocks == 0)
                goto diagnose_fs_too_small;

	if (blocks_per_group == (unsigned int) 0)
		blocks_per_group = 8 << log_block_size;

	first_block = (log_block_size == 10) ? 1 : 0;

	numgroups = ped_div_round_up (numblocks
                        - first_block, blocks_per_group);

	if (sparse_sb == -1)
		sparse_sb = 1;

        /* FIXME: 5% not appropriate for modern drive sizes */
	if (reserved_block_percentage == -1)
		reserved_block_percentage = 5;

        compute_block_counts (numblocks, numgroups, log_block_size, sparse_sb,
                              blocks_per_group, &last_group_blocks,
                              &last_group_admin, &inodes_per_group);

	int fs_too_small = 0;
	if (last_group_admin + 1 >= last_group_blocks)
          {
            numgroups--;
            if (numgroups == 0)
              fs_too_small = 1;
            else
              {
		numblocks -= last_group_blocks;
                compute_block_counts (numblocks, numgroups, log_block_size,
                                      sparse_sb, blocks_per_group,
                                      &last_group_blocks, &last_group_admin,
                                      &inodes_per_group);
              }
          }

        if (numgroups == 1
            && (last_group_blocks - last_group_admin < 8
                || inodes_per_group < 16
                /* This final term ensures that we detect
                   mkpartfs primary ext2 10KB 27650B as invalid.  */
                || (inodes_per_group == 16
                    && last_group_blocks - last_group_admin < 14)))
          fs_too_small = 1;

	if (fs_too_small) {
	diagnose_fs_too_small:
		ped_exception_throw (
			PED_EXCEPTION_ERROR,
			PED_EXCEPTION_CANCEL,
			_("File system too small for ext2."));
		goto error;
	}

	gd = ped_malloc(numgroups * sizeof(struct ext2_group_desc)
			+ (1 << log_block_size));
	if (!gd)
		goto error;

	if (!ext2_mkfs_init_sb(&sb, numblocks, numgroups, first_block,
			       log_block_size, blocks_per_group,
			       inodes_per_group, sparse_sb,
			       reserved_block_percentage))
       		goto error_free_gd;
	if (!ext2_mkfs_write_meta(handle, &sb, gd, timer))
       		goto error_free_gd;
	if (!ext2_mkfs_write_main(handle, &sb, gd))
       		goto error_free_gd;

	fs = ext2_open(handle, 0);
	if (!fs) goto error_close_fs;
	if (!ext2_reserve_inodes(fs)) goto error_close_fs;
	if (!ext2_mkfs_create_root_inode(fs)) goto error_close_fs;
	if (!ext2_mkfs_create_lost_and_found_inode(fs))
		goto error_close_fs;
	if (!ext2_sync(fs)) goto error_close_fs;
	ped_free(gd);
	return fs;

error_close_fs:
	ext2_close(fs);
error_free_gd:
	ped_free (gd);
error:
	return NULL;
}
#endif /* !DISCOVER_ONLY */
