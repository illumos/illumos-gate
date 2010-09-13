/*
    ext2_block_relocator.c -- ext2 block relocator
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


/* This struct describes a single block that will be relocated.  The
 * block's original location is "num", and its new location is "dest".
 * The block is presumebly referred to by some other block in the file
 * system, which is recorded as "refblock".  (Only one reference to
 * the block is allowed by the block relocator.)  "refoffset" describes
 * the location within the refblock in which the block is referenced.
 * "isindirect" is 0 for direct, 1 for single-indirect, 2 for
 * double-indirect, etc.
 *
 * The algorithms in the file fill the entries of this struct in this order:
 * num, refblock/refoffset/isindirectblock, dest.
 */
struct ext2_block_entry
{
	blk_t		num;
	blk_t		dest;
	blk_t		refblock;
	unsigned	refoffset:16;
	unsigned	isindirectblock:16;
};

/* This struct contains all data structures relevant to the block relocator.
 * 	- newallocoffset is the distance between the start of a block group,
 * 	and the first data block in the group.  This can change when a
 * 	filesystem is resized, because the size of the group descriptors is
 * 	proportional to the size of the filesystem.
 * 
 * 	- allocentries is the size of the "block" array.  It is a tuneable
 * 	parameter that determines how many blocks can be moved in each
 * 	pass.
 * 
 * 	- usedentries says how many entries of the "block" array have been
 * 	used.  That is, how many blocks have been scheduled so far to
 * 	be moved.
 *
 * 	- resolvedentries is the number of blocks whose referencing block
 * 	has been found and recorded in block[.]->refblock, etc.
 *
 * 	- block is an array that records which blocks need to be moved, and
 * 	where they will be moved to, etc.  At some point in the algorithm, this
 * 	array gets sorted (grep for qsort!) by indirectness.
 *
 * 	- start: each entry in this array corresponds to a level of
 * 	indirectness (0-3).  Each level has two items: dst and num.  "num"
 * 	is the number of blocks inside "block" of that level of indirectness.
 * 	After doscan() is finished, and the level of indirectness of each
 * 	block is known, "block" is sorted (see above).  The "dst" pointer
 * 	is a pointer inside "block" that indicates the start of the portion
 * 	of the array containg blocks of that level of indirectness.
 */
struct ext2_block_relocator_state
{
	blk_t			 newallocoffset;
	blk_t			 allocentries;
	blk_t			 usedentries;
	blk_t			 resolvedentries;
	struct ext2_block_entry *block;

	struct {
		struct ext2_block_entry *dst;
		int			 num;
	} start[4];
};



static int compare_block_entries(const void *x0, const void *x1)
{
	const struct ext2_block_entry *b0;
	const struct ext2_block_entry *b1;

	b0 = (const struct ext2_block_entry *)x0;
	b1 = (const struct ext2_block_entry *)x1;

	if (b0->num < b1->num)
		return -1;

	if (b0->num > b1->num)
		return 1;

	return 0;
}

static int compare_block_entries_ind(const void *x0, const void *x1)
{
	const struct ext2_block_entry *b0;
	const struct ext2_block_entry *b1;

	b0 = (const struct ext2_block_entry *)x0;
	b1 = (const struct ext2_block_entry *)x1;

	if (b0->isindirectblock > b1->isindirectblock)
		return -1;

	if (b0->isindirectblock < b1->isindirectblock)
		return 1;

	return 0;
}

static int compare_block_entries_ref(const void *x0, const void *x1)
{
	const struct ext2_block_entry *b0;
	const struct ext2_block_entry *b1;

	b0 = (const struct ext2_block_entry *)x0;
	b1 = (const struct ext2_block_entry *)x1;

	if (b0->refblock < b1->refblock)
		return -1;

	if (b0->refblock > b1->refblock)
		return 1;

	return 0;
}

struct ext2_block_entry *findit(struct ext2_block_relocator_state *state, blk_t block)
{
	int			 min;
	int			 max;
	struct ext2_block_entry *retv;
	int			 t;
	blk_t			 tval;

	max = state->usedentries - 1;
	min = 0;
	retv = NULL;

 repeat:
	if (min > max)
		goto out;

	t = (min + max) >> 1;
	tval = state->block[t].num;

	if (tval > block)
		max = t - 1;

	if (tval < block)
		min = t + 1;

	if (tval != block)
		goto repeat;

	retv = &state->block[t];

 out:
	return retv;
}

/* This function adds records a reference to a block ("blk"), if that
 * block is scheduled to be moved.
 */
static int doblock(struct ext2_fs *fs,
		   struct ext2_block_relocator_state *state,
		   blk_t blk,
		   blk_t refblock,
		   off_t refoffset,
		   int indirect)
{
	struct ext2_block_entry *ent;

	if ((ent = findit(state, blk)) == NULL)
		return 1;

	if (ent->refblock)
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("Cross-linked blocks found!  Better go run e2fsck "
			  "first!"));
		return 0;
	}

	ent->refblock = refblock;
	ent->refoffset = refoffset;
	ent->isindirectblock = indirect;

	state->resolvedentries++;
	state->start[indirect].num++;

	return 1;
}

static int doindblock(struct ext2_fs *fs,
		      struct ext2_block_relocator_state *state,
		      blk_t blk,
		      blk_t refblock,
		      off_t refoffset)
{
	struct ext2_buffer_head *bh;
	int			 i;
	uint32_t		*uptr;

	if (!doblock(fs, state, blk, refblock, refoffset, 1))
		return 0;

	bh = ext2_bread(fs, blk);
	if (!bh)
		return 0;
	uptr = (uint32_t *)bh->data;

	for (i=0;i<(fs->blocksize >> 2);i++)
		if (uptr[i])
			if (!doblock(fs, state, PED_LE32_TO_CPU(uptr[i]), blk,
				     i<<2, 0))
				return 0;

	if (!ext2_brelse(bh, 0))
		return 0;

	return 1;
}

static int dodindblock(struct ext2_fs *fs,
		       struct ext2_block_relocator_state *state,
		       blk_t blk,
		       blk_t refblock,
		       off_t refoffset)
{
	struct ext2_buffer_head *bh;
	int			 i;
	uint32_t		*uptr;

	if (!doblock(fs, state, blk, refblock, refoffset, 2))
		return 0;

	bh = ext2_bread(fs, blk);
	if (!bh)
		return 0;
	uptr = (uint32_t *)bh->data;

	for (i=0;i<(fs->blocksize >> 2);i++)
		if (uptr[i])
			if (!doindblock(fs, state, PED_LE32_TO_CPU(uptr[i]),
					blk, i<<2))
				return 0;

	if (!ext2_brelse(bh, 0))
		return 0;

	return 1;
}

static int dotindblock(struct ext2_fs *fs,
		       struct ext2_block_relocator_state *state,
		       blk_t blk,
		       blk_t refblock,
		       off_t refoffset)
{
	struct ext2_buffer_head *bh;
	int			 i;
	uint32_t		*uptr;

	if (!doblock(fs, state, blk, refblock, refoffset, 3))
		return 0;

	bh = ext2_bread(fs, blk);
	if (!bh)
		return 0;
	uptr = (uint32_t *)bh->data;

	for (i=0;i<(fs->blocksize >> 2);i++)
		if (uptr[i])
			if (!dodindblock(fs, state, PED_LE32_TO_CPU(uptr[i]),
					 blk, i<<2))
				return 0;

	if (!ext2_brelse(bh, 0))
		return 0;

	return 1;
}


/* This function records any block references from an inode to blocks that are
 * scheduled to be moved.
 */
static int doinode(struct ext2_fs *fs, struct ext2_block_relocator_state *state, int inode)
{
	struct ext2_inode buf;

	if (!ext2_read_inode(fs, inode, &buf))
		return 0;

	if (EXT2_INODE_BLOCKS(buf))
	{
		blk_t blk;
		int   i;
		off_t inodeoffset;
		blk_t inodeblock;

		inodeoffset = ext2_get_inode_offset(fs, inode, &inodeblock);

		/* do Hurd block, if there is one... */
		if (EXT2_SUPER_CREATOR_OS(fs->sb) == EXT2_OS_HURD
		    && EXT2_INODE_TRANSLATOR(buf)) {
			if (!doblock(fs,
				     state,
				     EXT2_INODE_TRANSLATOR(buf),
				     inodeblock,
				     inodeoffset + offsetof(struct ext2_inode,
						osd1.hurd1.h_i_translator),
				     0))
				return 0;
		}

		for (i=0;i<EXT2_NDIR_BLOCKS;i++)
			if ((blk = EXT2_INODE_BLOCK(buf, i)) != 0)
				if (!doblock(fs,
					     state,
					     blk,
					     inodeblock,
					     inodeoffset + offsetof(struct ext2_inode, i_block[i]),
					     0))
					return 0;

		if ((blk = EXT2_INODE_BLOCK(buf, EXT2_IND_BLOCK)) != 0)
			if (!doindblock(fs,
					state,
					blk,
					inodeblock,
					inodeoffset + offsetof(struct ext2_inode, i_block[EXT2_IND_BLOCK])))
				return 0;

		if ((blk = EXT2_INODE_BLOCK(buf, EXT2_DIND_BLOCK)) != 0)
			if (!dodindblock(fs,
					 state,
					 blk,
					 inodeblock,
					 inodeoffset + offsetof(struct ext2_inode, i_block[EXT2_DIND_BLOCK])))
				return 0;

		if ((blk = EXT2_INODE_BLOCK(buf, EXT2_TIND_BLOCK)) != 0)
			if (!dotindblock(fs,
					 state,
					 blk,
					 inodeblock,
					 inodeoffset + offsetof(struct ext2_inode, i_block[EXT2_TIND_BLOCK])))
				return 0;

	}

	return 1;
}

/* This function scans the entire filesystem, to find all references to blocks
 * that are scheduled to be moved.
 */
static int doscan(struct ext2_fs *fs, struct ext2_block_relocator_state *state)
{
	int i;

	state->start[0].num = 0;
	state->start[1].num = 0;
	state->start[2].num = 0;
	state->start[3].num = 0;

	for (i=0;i<fs->numgroups;i++)
	{
		struct ext2_buffer_head *bh;
		unsigned int		 j;
		int			 offset;

		if (fs->opt_verbose)
		{
			fprintf(stderr, " scanning group %i.... ", i);
			fflush(stderr);
		}

		bh = ext2_bread(fs, EXT2_GROUP_INODE_BITMAP(fs->gd[i]));
		if (!bh)
			return 0;
		offset = i * EXT2_SUPER_INODES_PER_GROUP(fs->sb) + 1;

		for (j=0;j<EXT2_SUPER_INODES_PER_GROUP(fs->sb);j++)
			if (bh->data[j>>3] & _bitmap[j&7])
			{
				if (!doinode(fs, state, offset + j))
				{
					ext2_brelse(bh, 0);
					return 0;
				}

				if (state->resolvedentries == state->usedentries)
					break;
			}

		ext2_brelse(bh, 0);

		if (fs->opt_verbose)
		{
			fprintf(stderr, "%i/%i blocks resolved\r",
				state->resolvedentries,
				state->usedentries);
			fflush(stderr);
		}

		if (state->resolvedentries == state->usedentries)
			break;
	}

	if (fs->opt_verbose)
                fputc('\n', stderr);

	state->start[3].dst = state->block;
	state->start[2].dst = state->start[3].dst + state->start[3].num;
	state->start[1].dst = state->start[2].dst + state->start[2].num;
	state->start[0].dst = state->start[1].dst + state->start[1].num;

	return 1;
}





static int ext2_block_relocator_copy(struct ext2_fs *fs, struct ext2_block_relocator_state *state)
{
	unsigned char *buf;

	ped_exception_fetch_all();
	buf = (unsigned char *) ped_malloc(MAXCONT << fs->logsize);
	if (buf)
	{
		int num;
		int numleft;
		struct ext2_block_entry *ptr;

		ped_exception_leave_all();

		numleft = state->usedentries;
		ptr = state->block;
		while (numleft)
		{
			num = PED_MIN(numleft, MAXCONT);
			while (num != 1)
			{
				if (ptr[0].num + num-1 == ptr[num-1].num &&
				    ptr[0].dest + num-1 == ptr[num-1].dest)
					break;

				num >>= 1;
			}

			if (!ext2_bcache_flush_range(fs, ptr[0].num, num))
				goto error_free_buf;
			if (!ext2_bcache_flush_range(fs, ptr[0].dest, num))
				goto error_free_buf;

			if (!ext2_read_blocks(fs, buf, ptr[0].num, num))
				goto error_free_buf;
			if (!ext2_write_blocks(fs, buf, ptr[0].dest, num))
				goto error_free_buf;

			ptr += num;
			numleft -= num;

			if (fs->opt_verbose)
			{
				fprintf(stderr, "copied %i/%i blocks\r",
					state->usedentries - numleft,
					state->usedentries);
				fflush(stderr);
			}
		}

		ped_free(buf);

		if (fs->opt_safe)
			ext2_sync(fs);

		if (fs->opt_verbose)
                        fputc('\n', stderr);
	}
	else
	{
		blk_t i;

		ped_exception_catch();
		ped_exception_leave_all();

		for (i=0;i<state->usedentries;i++)
		{
			struct ext2_block_entry *block;

			block = &state->block[i];
			if (!ext2_copy_block(fs, block->num, block->dest))
				goto error;
		}
	}

	return 1;

error_free_buf:
	ped_free(buf);
error:
	return 0;
}

static int ext2_block_relocator_ref(struct ext2_fs *fs, struct ext2_block_relocator_state *state, struct ext2_block_entry *block)
{
	struct ext2_buffer_head	*bh;
	static int numerrors = 0;

	if (!(block->refblock || block->refoffset))
	{
		ped_exception_throw (PED_EXCEPTION_BUG, PED_EXCEPTION_CANCEL,
				     _("Block %i has no reference?  Weird."),
				     block->num);
		return 0;
	}

	bh = ext2_bread(fs, block->refblock);
	if (!bh)
		return 0;

	if (fs->opt_debug)
	{
		if (PED_LE32_TO_CPU(*((uint32_t *)(bh->data + block->refoffset)))
				!= block->num) {
			fprintf(stderr,
				"block %i ref error! (->%i {%i, %i})\n",
				block->num,
				block->dest,
				block->refblock,
				block->refoffset);
			ext2_brelse(bh, 0);

			if (numerrors++ < 4)
				return 1;

			fputs("all is not well!\n", stderr);
			return 0;
		}
	}

	*((uint32_t *)(bh->data + block->refoffset))
		= PED_LE32_TO_CPU(block->dest);
	bh->dirty = 1;
	ext2_brelse(bh, 0);

	ext2_set_block_state(fs, block->dest, 1, 1);
	ext2_set_block_state(fs, block->num, 0, 1);

	if (block->isindirectblock)
	{
		struct ext2_block_entry *dst;
		int			 i;
		int			 num;

		dst = state->start[block->isindirectblock-1].dst;
		num = state->start[block->isindirectblock-1].num;

		for (i=0;i<num;i++)
			if (dst[i].refblock == block->num)
				dst[i].refblock = block->dest;
	}

	return 1;
}

/* This function allocates new locations for blocks that are scheduled to move
 * (inside state->blocks).
 *
 * FIXME: doesn't seem to handle sparse block groups.  That is, there might be
 * some free space that could be exploited in resizing that currently isn't...
 *
 * FIXME: should throw an exception if it fails to allocate blocks.
 */
static int ext2_block_relocator_grab_blocks(struct ext2_fs *fs, struct ext2_block_relocator_state *state)
{
	int i;
	blk_t ptr;

	ptr = 0;

	for (i=0;i<fs->numgroups;i++)
		if (EXT2_GROUP_FREE_BLOCKS_COUNT(fs->gd[i]))
		{
			struct ext2_buffer_head *bh;
			unsigned int j;
			int offset;

			bh = ext2_bread(fs, EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]));
			offset = i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb)
				 + EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);

			for (j=state->newallocoffset;
			     j<EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
			     j++)
				if (!(bh->data[j>>3] & _bitmap[j&7]))
				{
					state->block[ptr++].dest = offset + j;

					if (ptr == state->usedentries)
					{
						ext2_brelse(bh, 0);
						return 1;
					}
				}

			ext2_brelse(bh, 0);
		}

	return 0;
}

static int ext2_block_relocator_flush(struct ext2_fs *fs, struct ext2_block_relocator_state *state)
{
	int i;

	if (!state->usedentries)
		return 1;

	if (fs->opt_verbose)
                fputs("ext2_block_relocator_flush\n", stderr);

	if (fs->opt_debug)
	{
	again:

		for (i=0; (unsigned int) i < state->usedentries-1; i++)
			if (state->block[i].num >= state->block[i+1].num)
			{
				fputs("ext2_block_relocator_flush: "
				      "blocks not in order!\n", stderr);

				qsort(state->block,
				      state->usedentries,
				      sizeof(struct ext2_block_entry),
				      compare_block_entries);
				goto again;
			}
	}

	if (!doscan(fs, state))
		return 0;

	if (!ext2_block_relocator_grab_blocks(fs, state))
		return 0;

	if (!ext2_block_relocator_copy(fs, state))
		return 0;

	qsort(state->block,
	      state->usedentries,
	      sizeof(struct ext2_block_entry),
	      compare_block_entries_ind);

	for (i=3;i>=0;i--)
	{
		struct ext2_block_entry *dst;
		int			 j;
		int			 num;

		dst = state->start[i].dst;
		num = state->start[i].num;

		if (!num)
			continue;

		if (fs->opt_verbose)
		{
			/* FIXXXME gross hack */
			fprintf(stderr, "relocating %s blocks",
				((char *[4]){"direct",
						     "singly indirect",
						     "doubly indirect",
						     "triply indirect"})[i]);
			fflush(stderr);
		}

		qsort(dst,
		      num,
		      sizeof(struct ext2_block_entry),
		      compare_block_entries_ref);

		for (j=0;j<num;j++)
			if (!ext2_block_relocator_ref(fs, state, &dst[j]))
				return 0;

		if (fs->opt_safe) {
			if (!ext2_sync(fs))
				return 0;
		}

		if (fs->opt_verbose)
		        fputc('\n', stderr);
	}

	state->usedentries = 0;
	state->resolvedentries = 0;

	return 1;
}

static int ext2_block_relocator_mark(struct ext2_fs *fs, struct ext2_block_relocator_state *state, blk_t block)
{
	int i;

	if (fs->opt_debug)
	{
		if (!ext2_get_block_state(fs, block) ||
		    !ext2_is_data_block(fs, block))
		{
			ped_exception_throw (PED_EXCEPTION_WARNING,
				PED_EXCEPTION_IGNORE,
				_("Block %i shouldn't have been marked "
                                  "(%d, %d)!"), block,
                                ext2_get_block_state(fs, block),
                                ext2_is_data_block(fs, block));
		}
	}

	if (state->usedentries == state->allocentries - 1)
		if (!ext2_block_relocator_flush(fs, state))
			return 0;

	i = state->usedentries;
	state->block[i].num = block;
	state->block[i].dest = 0;
	state->block[i].refblock = 0;
	state->block[i].refoffset = 0;

	state->usedentries++;
	return 1;
}

static int ext2_block_relocate_grow(struct ext2_fs *fs, struct ext2_block_relocator_state *state, blk_t newsize)
{
	blk_t newgdblocks;
	blk_t newitoffset;
	int   i;

	newgdblocks = ped_div_round_up (newsize
                        - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb),
			      EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb));
	newgdblocks = ped_div_round_up (newgdblocks
                        * sizeof(struct ext2_group_desc),
			      fs->blocksize);
	if (newgdblocks == fs->gdblocks)
		return 1;

	newitoffset = newgdblocks + 3;
	state->newallocoffset = newitoffset + fs->inodeblocks;

	for (i=0;i<fs->numgroups;i++)
	{
		struct ext2_buffer_head *bh;
		blk_t			 diff;
		blk_t			 j;
		blk_t			 start;
		int			 sparse;

		bh = ext2_bread(fs, EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]));
		start = (i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
			+ EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
		sparse = ext2_is_group_sparse(fs, i);

		if (EXT2_GROUP_INODE_TABLE(fs->gd[i]) < start + newitoffset
		    || (sparse && ((EXT2_GROUP_BLOCK_BITMAP(fs->gd[i])
						< start + newitoffset - 2)
			       || (EXT2_GROUP_INODE_BITMAP(fs->gd[i])
						< start + newitoffset - 1))))
		{
			diff = newitoffset - (EXT2_GROUP_INODE_TABLE(fs->gd[i])
					      - start);

			for (j=0;j<diff;j++)
			{
				blk_t block;
				blk_t k;

				k = EXT2_GROUP_INODE_TABLE(fs->gd[i])
                                        + fs->inodeblocks + j;
				block = k % EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
				if (bh->data[block>>3] & _bitmap[block&7]) {
					k += EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
					if (!ext2_block_relocator_mark(fs,
							    state, k))
					{
						ext2_brelse(bh, 0);
						return 0;
					}
				}
			}
		}

		ext2_brelse(bh, 0);
	}

	if (!ext2_block_relocator_flush(fs, state))
		return 0;

	return 1;
}

static int ext2_block_relocate_shrink(struct ext2_fs *fs, struct ext2_block_relocator_state *state, blk_t newsize)
{
	int diff;
	int i;

	diff = ped_div_round_up (newsize - EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb),
		       EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb));
	diff = ped_div_round_up (diff * sizeof(struct ext2_group_desc),
                        fs->blocksize);
	diff = fs->gdblocks - diff;

	state->newallocoffset = fs->itoffset + fs->inodeblocks;

	for (i=0;i<fs->numgroups;i++)
	{
		struct ext2_buffer_head *bh;
		blk_t			 groupsize;
		blk_t			 j;
		blk_t			 offset;
		int			 sparse;
		blk_t			 start;
		int			 type;

		offset = i * EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb)
			 + EXT2_SUPER_FIRST_DATA_BLOCK(fs->sb);
		sparse = ext2_is_group_sparse(fs, i);

		if (newsize >= offset + EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb))
			continue;		/* group will survive */

		bh = ext2_bread(fs, EXT2_GROUP_BLOCK_BITMAP(fs->gd[i]));

		if (newsize <= offset)
			type = 2;		/* group is fully chopped off */
		else
			type = 1;		/* group is partly chopped off */

		if (!sparse && type == 2)
		{
			for (j=EXT2_GROUP_INODE_BITMAP(fs->gd[i])+1;
			     j<EXT2_GROUP_INODE_TABLE(fs->gd[i]);
			     j++)
			{
				blk_t k;

				k = j - offset;
				if (bh->data[k>>3] & _bitmap[k&7])
					if (!ext2_block_relocator_mark(fs, state, j))
					{
						ext2_brelse(bh, 0);
						return 0;
					}
			}
		}

		start = newsize;
		if (type == 2)
			start = EXT2_GROUP_INODE_TABLE(fs->gd[i])
				+ fs->inodeblocks;

		start -= offset;

		groupsize = EXT2_SUPER_BLOCKS_PER_GROUP(fs->sb);
		if (offset + groupsize > EXT2_SUPER_BLOCKS_COUNT(fs->sb))
			groupsize = EXT2_SUPER_BLOCKS_COUNT(fs->sb) - offset;

		for (j=start;j<groupsize;j++)
			if (bh->data[j>>3] & _bitmap[j&7])
				if (!ext2_block_relocator_mark(fs, state,
							       offset + j))
				{
					ext2_brelse(bh, 0);
					return 0;
				}

		ext2_brelse(bh, 0);
	}

	return ext2_block_relocator_flush(fs, state);
}

int ext2_block_relocate(struct ext2_fs *fs, blk_t newsize)
{
	struct ext2_block_relocator_state state;

	if (fs->opt_verbose)
                fputs("relocating blocks....\n", stderr);

	state.newallocoffset = 0;
	state.allocentries = (ext2_relocator_pool_size << 10) /
		sizeof(struct ext2_block_entry);
	state.usedentries = 0;
	state.resolvedentries = 0;
	state.block = (struct ext2_block_entry *)fs->relocator_pool;

	if (newsize < EXT2_SUPER_BLOCKS_COUNT(fs->sb))
		return ext2_block_relocate_shrink(fs, &state, newsize);

	return ext2_block_relocate_grow(fs, &state, newsize);
}

#endif /* !DISCOVER_ONLY */
