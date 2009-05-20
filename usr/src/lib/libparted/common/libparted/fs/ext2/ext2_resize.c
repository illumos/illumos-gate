/*
    ext2_resize.c -- ext2 resizer
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

static int ext2_add_group(struct ext2_fs *fs, blk_t groupsize)
{
	blk_t admin;
	int   group;
	blk_t groupstart;
	blk_t newgdblocks;
	int   sparse;

	if (fs->opt_verbose)
                fputs ("ext2_add_group\n", stderr);

	if (!ped_realloc ((void*) &fs->gd,
			  (fs->numgroups+1) * sizeof(struct ext2_group_desc)
			      + fs->blocksize))
		return 0;

	if (fs->opt_debug)
	{
		if (EXT2_SUPER_BLOCKS_COUNT(fs->sb) !=
		    EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb)
		    + fs->numgroups * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
		{
                        fputs ("ext2_add_group: last (existing) group "
                               "isn't complete!\n", stderr);

			return 0;
		}
	}

	group = fs->numgroups;
	sparse = ext2_is_group_sparse(fs, group);
	groupstart = EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb)
		     + group * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

	admin = fs->adminblocks;
	if (!sparse)
		admin -= fs->gdblocks + 1;

	if (fs->opt_debug)
	{
		if (groupsize < fs->adminblocks ||
		    groupsize > EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
		{
			fprintf(stderr,
				"ext2_add_group: groups of %i blocks are "
				"impossible!\n", groupsize);

			return 0;
		}
	}

	newgdblocks = ped_div_round_up((fs->numgroups + 1)
					* sizeof(struct ext2_group_desc),
			      fs->blocksize);
	if (newgdblocks != fs->gdblocks)
	{
		int i;

		for (i=0;i<fs->numgroups;i++)
			if (ext2_is_group_sparse(fs, i))
			{
				blk_t start;

				start = EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb)
				      + i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
				ext2_set_block_state(fs,
						start + fs->gdblocks + 1, 1, 1);
			}

		fs->gdblocks++;
		fs->adminblocks++;
		if (sparse)
			admin++;
	}

	fs->numgroups++;

	fs->sb.s_inodes_count = PED_CPU_TO_LE32(
		EXT2_SUPER_INODES_COUNT(fs->sb)
		+ EXT2_SUPER_INODES_PER_GROUP(fs->sb));
	fs->sb.s_blocks_count = PED_CPU_TO_LE32(
		EXT2_SUPER_BLOCKS_COUNT(fs->sb) + groupsize);
	fs->sb.s_free_blocks_count = PED_CPU_TO_LE32(
		EXT2_SUPER_FREE_BLOCKS_COUNT(fs->sb) + groupsize - admin);
	fs->sb.s_free_inodes_count = PED_CPU_TO_LE32(
		EXT2_SUPER_FREE_INODES_COUNT(fs->sb)
	        + EXT2_SUPER_INODES_PER_GROUP(fs->sb));
	fs->metadirty |= EXT2_META_SB;

	{
		blk_t off;
		blk_t sparseoff;

		off = groupstart;
		sparseoff = off + fs->itoffset - 2;

		if (sparse)
		{
			fs->gd[group].bg_block_bitmap
				= PED_CPU_TO_LE32(sparseoff);
			fs->gd[group].bg_inode_bitmap
				= PED_CPU_TO_LE32(sparseoff + 1);
		}
		else
		{
			fs->gd[group].bg_block_bitmap
				= PED_CPU_TO_LE32(off);
			fs->gd[group].bg_inode_bitmap
				= PED_CPU_TO_LE32(off + 1);
		}

		/* Hey, I don't know _why_ either */
		fs->gd[group].bg_inode_table = PED_CPU_TO_LE32(sparseoff + 2);
	}

	fs->gd[group].bg_free_blocks_count = PED_CPU_TO_LE16(groupsize - admin);
	fs->gd[group].bg_free_inodes_count = PED_CPU_TO_LE16(
		EXT2_SUPER_INODES_PER_GROUP(fs->sb));
	fs->gd[group].bg_used_dirs_count = 0;
	fs->metadirty |= EXT2_META_SB | EXT2_META_GD;

	{
		struct ext2_buffer_head *bh;
		blk_t i;

		bh = ext2_bcreate(fs, EXT2_GROUP_BLOCK_BITMAP(fs->gd[group]));
		if (!bh)
			return 0;

		if (sparse)
		{
			bh->data[0] |= _bitmap[0];
			for (i=1;i<=fs->gdblocks;i++)
				bh->data[i>>3] |= _bitmap[i&7];
		}

		i = EXT2_GROUP_BLOCK_BITMAP(fs->gd[group]) - groupstart;
		bh->data[i>>3] |= _bitmap[i&7];

		i = EXT2_GROUP_INODE_BITMAP(fs->gd[group]) - groupstart;
		bh->data[i>>3] |= _bitmap[i&7];

		for (i=0;i<fs->inodeblocks;i++)
		{
			blk_t j;

			j = EXT2_GROUP_INODE_TABLE(fs->gd[group])
			    - groupstart + i;
			bh->data[j>>3] |= _bitmap[j&7];
		}

		for (i=groupsize;i<EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);i++)
			bh->data[i>>3] |= _bitmap[i&7];

		ext2_brelse(bh, 0);         /* this is a block bitmap */
	}

	if (!ext2_zero_blocks(fs, EXT2_GROUP_INODE_BITMAP(fs->gd[group]), 1))
		return 0;
	if (!ext2_zero_blocks(fs, EXT2_GROUP_INODE_TABLE(fs->gd[group]),
			      fs->inodeblocks))
		return 0;

	if (fs->opt_safe)
		if (!ext2_sync(fs))
			return 0;

	return 1;
}

static int ext2_del_group(struct ext2_fs *fs)
{
	blk_t admin;
	int   group;
	blk_t groupsize;
	blk_t newgdblocks;
	int   sparse;

	if (fs->opt_verbose)
                fputs ("ext2_del_group\n", stderr);

	group = fs->numgroups - 1;
	sparse = ext2_is_group_sparse(fs, group);

	admin = fs->adminblocks;
	if (!sparse)
		admin -= fs->gdblocks + 1;

	groupsize = EXT2_SUPER_BLOCKS_COUNT(fs->sb)
		  - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb)
		  - group * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

	if (EXT2_SUPER_FREE_BLOCKS_COUNT(fs->sb) < groupsize - admin)
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("File system is too full to remove a group!"));

		return 0;
	}

	if (EXT2_SUPER_FREE_INODES_COUNT(fs->sb)
		< EXT2_SUPER_INODES_PER_GROUP(fs->sb))
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("File system has too many allocated inodes to "
			  "remove a group!"));
		return 0;
	}

	if (fs->opt_debug)
	{
		if (EXT2_GROUP_FREE_INODES_COUNT(fs->gd[group]) !=
		    EXT2_SUPER_INODES_PER_GROUP(fs->sb))
		{
                        fputs ("ext2_del_group: this should not "
                               "happen anymore!\n", stderr);

			return 0;
		}
	}

	newgdblocks = ped_div_round_up((fs->numgroups - 1) *
			      sizeof(struct ext2_group_desc), fs->blocksize);

	if (newgdblocks != fs->gdblocks)
	{
		int i;

		for (i=0;i<fs->numgroups;i++)
			if (ext2_is_group_sparse(fs, i))
			{
				blk_t start;

				start = EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb) +
					i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
				ext2_set_block_state(fs,
						     start + fs->gdblocks,
						     0, 1);
			}

		fs->gdblocks--;
		fs->adminblocks--;
		if (sparse)
			admin--;
	}

	if (fs->opt_debug)
	{
		if (EXT2_GROUP_FREE_BLOCKS_COUNT(fs->gd[group])
				!= groupsize - admin)
		{
			blk_t i;
			blk_t num;
			blk_t offset;

			offset = EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb) +
				group * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
			num = EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

			for (i=0;i<num;i++)
				if (ext2_is_data_block(fs, offset+i) &&
				    ext2_get_block_state(fs, offset+i))
				{
					fprintf(stderr,
						"error: block relocator "
						"should have relocated "
						"%i\n",
						offset+i);

					return 0;
				}
		}
	}

	fs->numgroups--;

	fs->sb.s_inodes_count = PED_CPU_TO_LE32(
		EXT2_SUPER_INODES_COUNT(fs->sb)
		- EXT2_SUPER_INODES_PER_GROUP(fs->sb));
	fs->sb.s_blocks_count = PED_CPU_TO_LE32(
		EXT2_SUPER_BLOCKS_COUNT(fs->sb) - groupsize);
	fs->sb.s_free_blocks_count = PED_CPU_TO_LE32(
		EXT2_SUPER_FREE_BLOCKS_COUNT(fs->sb) - (groupsize - admin));
	fs->sb.s_free_inodes_count = PED_CPU_TO_LE32(
		EXT2_SUPER_FREE_INODES_COUNT(fs->sb)
	        - EXT2_SUPER_INODES_PER_GROUP(fs->sb));
	fs->metadirty |= EXT2_META_SB;

	if (fs->opt_safe)
		ext2_sync(fs);

	ped_realloc ((void*) &fs->gd,
		     fs->numgroups * sizeof(struct ext2_group_desc)
			      + fs->blocksize);

	return 1;
}

static int ext2_grow_group(struct ext2_fs *fs, blk_t newsize)
{
	int   group;
	blk_t groupoff;
	blk_t gblocks;
	blk_t i;

	if (fs->opt_verbose)
                fputs ("ext2_grow_group\n", stderr);

	group = fs->numgroups - 1;
	groupoff = group * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb)
		   + EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
	gblocks = EXT2_SUPER_BLOCKS_COUNT(fs->sb) - groupoff;

	if (fs->opt_debug)
	{
		if (newsize < gblocks)
		{
                        fputs ("ext2_grow_group: called to shrink group!\n",
                               stderr);

			return 0;
		}

		if (gblocks == newsize)
		{
                        fputs ("ext2_grow_group: nothing to do!\n", stderr);
			return 0;
		}
	}

	for (i=gblocks;i<newsize;i++)
		ext2_set_block_state(fs, groupoff + i, 0, 1);

	fs->sb.s_blocks_count = PED_CPU_TO_LE32(
		EXT2_SUPER_BLOCKS_COUNT(fs->sb) + newsize - gblocks);
	fs->metadirty |= EXT2_META_SB;

	if (fs->opt_safe)
		ext2_sync(fs);

	return 1;
}

static int ext2_shrink_group(struct ext2_fs *fs, blk_t newsize)
{
	blk_t admin;
	int   group;
	blk_t groupoff;
	blk_t gblocks;
	blk_t i;

	if (fs->opt_verbose)
                fputs ("ext2_shrink_group\n", stderr);

	group = fs->numgroups - 1;

	admin = fs->adminblocks;
	if (!ext2_is_group_sparse(fs, group))
		admin -= fs->gdblocks + 1;

	groupoff = group * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb)
		   + EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
	gblocks = EXT2_SUPER_BLOCKS_COUNT(fs->sb) - groupoff;

	if (fs->opt_debug)
	{
		if (newsize < admin)
		{
			fprintf(stderr,
				"ext2_shrink_group: cant shrink a group "
				"to %i blocks\n", newsize);

			return 0;
		}

		if (newsize > gblocks)
		{
                        fputs ("ext2_shrink_group: called to grow group!\n",
                               stderr);

			return 0;
		}

		if (gblocks == newsize)
		{
                        fputs ("ext2_shrink_group: nothing to do!\n",
                               stderr);

			return 0;
		}
	}

	for (i=newsize;i<gblocks;i++)
	{
		if (fs->opt_debug && ext2_get_block_state(fs, groupoff + i))
		{
			fprintf(stderr,
				"error: block relocator should have relocated "
				"%i\n",
				groupoff + i);

			return 0;
		}

		ext2_set_block_state(fs, groupoff + i, 1, 0);
	}

	i = gblocks - newsize;
	fs->sb.s_blocks_count = PED_CPU_TO_LE32(
		EXT2_SUPER_BLOCKS_COUNT(fs->sb) - i);
	fs->sb.s_free_blocks_count = PED_CPU_TO_LE32(
		EXT2_SUPER_FREE_BLOCKS_COUNT(fs->sb) - i);
	fs->gd[group].bg_free_blocks_count = PED_CPU_TO_LE16(
		EXT2_GROUP_FREE_BLOCKS_COUNT(fs->gd[group]) - i);

	fs->metadirty |= EXT2_META_SB | EXT2_META_GD;

	if (fs->opt_safe)
		ext2_sync(fs);

	return 1;
}






static int ext2_grow_fs(struct ext2_fs *fs, blk_t newsize, PedTimer* timer)
{
	blk_t diff;
	blk_t sizelast;
	blk_t origsize = EXT2_SUPER_BLOCKS_COUNT(fs->sb);

	if (fs->opt_verbose)
                fputs ("ext2_grow_fs\n", stderr);

	if (!ext2_block_relocate(fs, newsize))
		return 0;

	if (!ext2_metadata_push(fs, newsize))
		return 0;

	diff = newsize - EXT2_SUPER_BLOCKS_COUNT(fs->sb);
	sizelast = EXT2_SUPER_BLOCKS_COUNT(fs->sb)
		   - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb)
		   - (fs->numgroups-1) * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

	if (sizelast != EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
	{
		blk_t growto;

		growto = sizelast + diff;
		if (growto > EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
			growto = EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

		if (!ext2_grow_group(fs, growto))
			return 0;

		diff -= growto - sizelast;
	}

	ped_timer_reset (timer);
	ped_timer_set_state_name (timer, _("adding groups"));

	while (diff)
	{
		ped_timer_update (timer,
			          1.0 - 1.0 * diff / (newsize - origsize));

		sizelast = PED_MIN(diff, EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb));
		if (!ext2_add_group(fs, sizelast))
			return 0;

		diff -= sizelast;
	}

	ped_timer_update (timer, 1.0);

	return 1;
}

static int ext2_shrink_fs(struct ext2_fs *fs, blk_t newsize,
			  PedTimer* timer)
{
	blk_t origsize = EXT2_SUPER_BLOCKS_COUNT (fs->sb);
	blk_t diff;
	int newgroups;
	blk_t sizelast;

	if (fs->opt_verbose)
                fputs ("ext2_shrink_fs\n", stderr);

	newgroups = ped_div_round_up (newsize
                                - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb),
		        EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb));
	if (EXT2_SUPER_BLOCKS_COUNT(fs->sb)
	    - EXT2_SUPER_FREE_BLOCKS_COUNT(fs->sb) > newsize)
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("Your file system is too full to resize it to %i "
			  "blocks.  Sorry."), newsize);
		return 0;
	}

	if (EXT2_SUPER_INODES_COUNT(fs->sb)
	    - EXT2_SUPER_FREE_INODES_COUNT(fs->sb)
	    		> newgroups * EXT2_SUPER_INODES_PER_GROUP(fs->sb))
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("Your file system has too many occupied inodes to "
			  "resize it to %i blocks.  Sorry."), newsize);
		return 0;
	}

	if (!ext2_inode_relocate(fs, newgroups))
		return 0;

	if (!ext2_block_relocate(fs, newsize))
		return 0;

	diff = EXT2_SUPER_BLOCKS_COUNT(fs->sb) - newsize;

	ped_timer_reset (timer);
	ped_timer_set_state_name (timer, _("shrinking"));

	while (diff > 0)
	{
		ped_timer_update (timer,
				  1.0 - 1.0 * diff / (origsize - newsize));

		sizelast = EXT2_SUPER_BLOCKS_COUNT(fs->sb)
			   - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb) -
			   (fs->numgroups - 1)
			   	* EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);

		if (diff < sizelast)
		{
			if (!ext2_shrink_group(fs, sizelast - diff))
				return 0;

			diff = 0;
		}
		else
		{
			if (!ext2_del_group(fs))
				return 0;

			diff -= sizelast;
		}
	}
	
	ped_timer_update (timer, 1.0);

	return 1;
}

int ext2_determine_itoffset(struct ext2_fs *fs)
{
	int i;

	fs->itoffset = EXT2_GROUP_INODE_TABLE(fs->gd[0])
		       - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);

        /*PED_DEBUG (0x20, "itoffset is %d", fs->itoffset);
        
        PED_DEBUG (0x20, "walking %d groups", fs->numgroups);*/

	for (i=0;i<fs->numgroups;i++)
	{
		blk_t start;
		blk_t bb;
		blk_t ib;
		blk_t it;

		start = EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb)
			+ (i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb));
		it = start + fs->itoffset;

                /*PED_DEBUG (0x21, "start = %d, it = %d", start, it);*/

		if (ext2_is_group_sparse(fs, i))
		{
                        /*PED_DEBUG (0x21, "%d has a superblock copy", i);*/
			bb = it - 2;
			ib = it - 1;
		}
		else
		{
                        /*PED_DEBUG (0x21, "%d doesn't have a superblock copy",
                            i);*/
			bb = start;
			ib = start + 1;
		}

		if (EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]) != bb ||
		    EXT2_GROUP_INODE_BITMAP(fs->gd[i]) != ib ||
		    EXT2_GROUP_INODE_TABLE(fs->gd[i]) != it)
		{
		/*	ped_exception_throw (PED_EXCEPTION_NO_FEATURE,
				PED_EXCEPTION_CANCEL,
			_("This ext2 file system has a rather strange layout!  "
			  "Parted can't resize this (yet)."));*/

                 /*       PED_DEBUG (0x21, "calculated block bitmap to be %d, "
                                         "but fs says %d.", bb,
                                         EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]));
                        PED_DEBUG (0x21, "calculated inode bitmap to be %d, "
                                         "but fs says %d.", ib,
                                         EXT2_GROUP_INODE_BITMAP(fs->gd[i]));
                        PED_DEBUG (0x21, "calculated inode table to be %d, "
                                         "but fs says %d.", it,
                                         EXT2_GROUP_INODE_TABLE(fs->gd[i]));*/
                        
			return 0;
		}
	}

	return 1;
}

int ext2_resize_fs(struct ext2_fs *fs, blk_t newsize, PedTimer* timer)
{
	blk_t residue;
	int status;

	if (EXT2_SUPER_STATE(fs->sb) & EXT2_ERROR_FS)
	{
		ped_exception_throw (
			PED_EXCEPTION_WARNING, PED_EXCEPTION_CANCEL,
			_("File system has errors!  You should run e2fsck."));
		return 0;
	}

	if (!(EXT2_SUPER_STATE(fs->sb) & EXT2_VALID_FS))
	{
		ped_exception_throw (
			PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("File system was not cleanly unmounted!  "
			  "You should run e2fsck."));
		return 0;
	}

	if (EXT2_SUPER_FEATURE_COMPAT(fs->sb)
			& EXT2_FEATURE_COMPAT_HAS_DIR_INDEX) {
		if (ped_exception_throw (
			PED_EXCEPTION_WARNING, PED_EXCEPTION_IGNORE_CANCEL,
			_("The file system has the 'dir_index' feature "
			  "enabled.  Parted can only resize the file system "
			  "if it disables this feature.  You can enable it "
			  "later by running 'tune2fs -O dir_index DEVICE' "
			  "and then 'e2fsck -fD DEVICE'."))
				!= PED_EXCEPTION_IGNORE)
			return 0;
		fs->sb.s_feature_compat
			= PED_CPU_TO_LE32(EXT2_SUPER_FEATURE_COMPAT(fs->sb)
					  & ~EXT2_FEATURE_COMPAT_HAS_DIR_INDEX);
		fs->metadirty |= EXT2_META_SB;
	}

	if (!ext2_determine_itoffset(fs) && ped_exception_throw (
                        PED_EXCEPTION_WARNING,
                        PED_EXCEPTION_OK_CANCEL,
                        _("A resize operation on this file system will "
                          "use EXPERIMENTAL code\n"
                          "that MAY CORRUPT it (although no one has "
                          "reported any such damage yet).\n"
                          "You should at least backup your data first, "
                          "and run 'e2fsck -f' afterwards."))
                == PED_EXCEPTION_CANCEL)
        {
	        return 0;
        }

	if (fs->opt_verbose)
                fputs ("ext2_resize_fs\n", stderr);

	residue = (newsize - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb))
		   % EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
	if (residue && residue <= fs->adminblocks)
		newsize -= residue;

	if (newsize == EXT2_SUPER_BLOCKS_COUNT(fs->sb))
		return 1;

	fs->relocator_pool
		= (unsigned char *)ped_malloc(ext2_relocator_pool_size << 10);
	if (!fs->relocator_pool)
		return 0;
	fs->relocator_pool_end
		= fs->relocator_pool + (ext2_relocator_pool_size << 10);

	if (newsize < EXT2_SUPER_BLOCKS_COUNT(fs->sb))
		status = ext2_shrink_fs(fs, newsize, timer);
	else
		status = ext2_grow_fs(fs, newsize, timer);

	ped_free(fs->relocator_pool);
	fs->relocator_pool = NULL;
	fs->relocator_pool_end = NULL;

	return status;
}
#endif /* !DISCOVER_ONLY */
