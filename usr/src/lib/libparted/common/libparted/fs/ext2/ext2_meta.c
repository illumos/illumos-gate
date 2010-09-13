/*
    ext2_meta.c -- ext2 metadata mover
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

#include <config.h>

#ifndef DISCOVER_ONLY

#include <stdio.h>
#include <stdlib.h>
#include "ext2.h"

int ext2_metadata_push(struct ext2_fs *fs, blk_t newsize)
{
	int   i;
	int   newgdblocks;
	blk_t newitoffset;

	newgdblocks = ped_div_round_up (newsize
                        - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb),
			      EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb));
	newgdblocks = ped_div_round_up (newgdblocks
                        * sizeof(struct ext2_group_desc),
			      fs->blocksize);
	newitoffset = newgdblocks + 3;

	if (newitoffset <= fs->itoffset)
		return 1;

	for (i=0;i<fs->numgroups;i++)
	{
		blk_t diff;
		blk_t j;
		blk_t fromblock;
		blk_t start;

		start = (i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
			+ EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);

		if (EXT2_GROUP_INODE_TABLE(fs->gd[i]) >= start + newitoffset
		    && EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]) >= start + newitoffset - 2
		    && EXT2_GROUP_INODE_BITMAP(fs->gd[i]) >= start + newitoffset - 1)
			continue;

		diff = newitoffset - (EXT2_GROUP_INODE_TABLE(fs->gd[i]) - start);

		/* inode table */
		fromblock = EXT2_GROUP_INODE_TABLE(fs->gd[i]) + fs->inodeblocks;

		if (fs->opt_debug)
		{
			for (j=0;j<diff;j++)
				if (!ext2_get_block_state(fs, fromblock+j))
				{
					fprintf(stderr,
						"error: block relocator "
						"should have relocated "
						"%i\n",
						fromblock);

					return 0;
				}
		}

		for (j=0;j<diff;j++)
			if (!ext2_set_block_state(fs, fromblock+j, 1, 0))
				return 0;

		if (!ext2_move_blocks(fs,
				      EXT2_GROUP_INODE_TABLE(fs->gd[i]),
				      fs->inodeblocks,
				      EXT2_GROUP_INODE_TABLE(fs->gd[i]) + diff))
			return 0;
		fs->gd[i].bg_inode_table = PED_CPU_TO_LE32 (
			EXT2_GROUP_INODE_TABLE(fs->gd[i]) + diff);
		fs->metadirty |= EXT2_META_GD;

		if (fs->opt_safe)
			if (!ext2_sync(fs))
				return 0;

		/* block bitmap and inode bitmap */
		fromblock = EXT2_GROUP_INODE_TABLE(fs->gd[i]);
		if (ext2_is_group_sparse(fs, i))
		{
			if (!ext2_copy_block(fs,
				EXT2_GROUP_INODE_BITMAP(fs->gd[i]),
				EXT2_GROUP_INODE_BITMAP(fs->gd[i]) + diff))
				return 0;
			fs->gd[i].bg_inode_bitmap = PED_CPU_TO_LE32 (
				EXT2_GROUP_INODE_BITMAP(fs->gd[i]) + diff);
                        fs->metadirty |= EXT2_META_GD;

			if (fs->opt_safe)
				if (!ext2_sync(fs))
					return 0;

			if (!ext2_copy_block(fs,
				EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]),
				EXT2_GROUP_BLOCK_BITMAP(fs->gd[i])+diff))
				return 0;
			fs->gd[i].bg_block_bitmap = PED_CPU_TO_LE32 (
				EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]) + diff);
			fs->metadirty |= EXT2_META_GD;

			if (fs->opt_safe)
				if (!ext2_sync(fs))
					return 0;

			fromblock = EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]);
		}

		ext2_zero_blocks(fs, fromblock-diff, diff);
		for (j=0;j<diff;j++)
			if (!ext2_set_block_state(fs, fromblock+j-diff, 0, 0))
				return 0;

		if (fs->opt_verbose)
			fprintf(stderr,
				"ext2_metadata_push: group %i/%i\r",
				i+1, fs->numgroups);
	}

	fs->itoffset = newitoffset;

	if (fs->opt_verbose)
                fputc ('\n', stderr);

	return 1;
}
#endif /* !DISCOVER_ONLY */
