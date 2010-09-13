/*
    ext2_inode_relocator.c -- ext2 inode relocator
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
#include <sys/stat.h>	/* for S_ISDIR */
#include "ext2.h"






struct ext2_reference
{
	blk_t			 block;
	off_t			 offset;
};

struct ext2_inode_entry
{
	ino_t			 num;
	ino_t			 dest;
	unsigned		 numreferences:16;
	unsigned		 isdir:1;
	struct ext2_reference	*ref;
};

struct ext2_inode_relocator_state
{
	int			 usedentries;
	int			 resolvedentries;
	struct ext2_inode_entry	*inode;
	struct ext2_reference	*last;
};





static struct ext2_inode_entry *findit(struct ext2_inode_relocator_state *state, ino_t inode)
{
	int			 min;
	int			 max;
	struct ext2_inode_entry *retv;
	int			 t;
	blk_t			 tval;

	max = state->usedentries - 1;
	min = 0;
	retv = NULL;

 repeat:
	if (min > max)
		goto out;

	t = (min + max) >> 1;
	tval = state->inode[t].num;

	t--;
	if (tval > inode)
		max = t;

	t += 2;
	if (tval < inode)
		min = t;

	t--;

	if (tval != inode)
		goto repeat;

	retv = &state->inode[t];

 out:
	return retv;
}

static int addref(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, ino_t inode, blk_t block, off_t offset)
{
	struct ext2_inode_entry *ent;
	int i;

	if ((ent = findit(state, inode)) == NULL)
		return 1;

	for (i=0;i<ent->numreferences;i++)
		if (!ent->ref[i].block)
			break;

	if (i == ent->numreferences)
	{
		ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			_("Found an inode with a incorrect link count.  "
			  "Better go run e2fsck first!"));
		return 0;
	}

	if (i == ent->numreferences - 1)
		state->resolvedentries++;

	ent->ref[i].block = block;
	ent->ref[i].offset = offset;

	return 1;
}

static int doblock(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, blk_t blockno)
{
	struct ext2_buffer_head *bh;
	off_t                    offset;

	bh = ext2_bread(fs, blockno);
	if (!bh)
		return 0;

	offset = 0;
	do
	{
		struct ext2_dir_entry_2 *ptr;

		ptr = (struct ext2_dir_entry_2 *)(bh->data + offset);

		if (ptr->name_len)
			if (!addref(fs, state, EXT2_DIRENT_INODE(*ptr), blockno,
				    offset))
				return 0;

		PED_ASSERT (ptr->rec_len > 0, return 0);
		offset += EXT2_DIRENT_REC_LEN (*ptr);
	} while (offset < fs->blocksize);

	ext2_brelse(bh, 0);
	return 1;
}

static int doindblock(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, blk_t blockno)
{
	struct ext2_buffer_head *bh;
	blk_t			 blk;
	int                      i;

	bh = ext2_bread(fs, blockno);

	for (i=0;i<(fs->blocksize>>2);i++)
		if ((blk = PED_LE32_TO_CPU(((uint32_t *)bh->data)[i])) != 0)
			if (!doblock(fs, state, blk))
				return 0;

	ext2_brelse(bh, 0);
	return 1;
}

static int dodindblock(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, blk_t blockno)
{
	struct ext2_buffer_head *bh;
	blk_t			 blk;
	int                      i;

	bh = ext2_bread(fs, blockno);
	if (!bh)
		return 0;

	for (i=0;i<(fs->blocksize>>2);i++)
		if ((blk = PED_LE32_TO_CPU(((uint32_t *)bh->data)[i])) != 0)
			if (!doindblock(fs, state, blk))
				return 0;

	ext2_brelse(bh, 0);
	return 1;
}

static int dotindblock(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, blk_t blockno)
{
	struct ext2_buffer_head *bh;
	blk_t			 blk;
	int                      i;

	bh = ext2_bread(fs, blockno);
	if (!bh)
		return 0;

	for (i=0;i<(fs->blocksize>>2);i++)
		if ((blk = PED_LE32_TO_CPU(((uint32_t *)bh->data)[i])) != 0)
			if (!dodindblock(fs, state, blk))
				return 0;

	ext2_brelse(bh, 0);
	return 1;
}

static int doinode(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, ino_t inode)
{
	struct ext2_inode buf;
	int		  i;

	if (!ext2_read_inode(fs, inode, &buf))
		return 0;
	if (S_ISDIR(EXT2_INODE_MODE(buf)))
	{
		blk_t blk;

		for (i=0;i<EXT2_NDIR_BLOCKS;i++)
			if ((blk = EXT2_INODE_BLOCK(buf, i)) != 0)
				if (!doblock(fs, state, blk))
					return 0;

		if ((blk = EXT2_INODE_BLOCK(buf, EXT2_IND_BLOCK)) != 0)
			if (!doindblock(fs, state, blk))
				return 0;

		if ((blk = EXT2_INODE_BLOCK(buf, EXT2_DIND_BLOCK)) != 0)
			if (!dodindblock(fs, state, blk))
				return 0;

		if ((blk = EXT2_INODE_BLOCK(buf, EXT2_TIND_BLOCK)) != 0)
			if (!dotindblock(fs, state, blk))
				return 0;
	}

	return 1;
}

static int doscangroup(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, int group)
{
	struct ext2_buffer_head *bh;
	unsigned int		 i;
	int			 offset;

	if (fs->opt_verbose)
		fprintf(stderr, " scanning group %i.... ", group);

	bh = ext2_bread(fs, EXT2_GROUP_INODE_BITMAP(fs->gd[group]));
	offset = group * EXT2_SUPER_INODES_PER_GROUP(fs->sb) + 1;

	for (i=0;i<EXT2_SUPER_INODES_PER_GROUP(fs->sb);i++)
		if (bh->data[i>>3] & _bitmap[i&7])
		{
			if (!doinode(fs, state, offset + i))
			{
				ext2_brelse(bh, 0);
				return 0;
			}

			if (state->resolvedentries == state->usedentries)
				break;
		}

	ext2_brelse(bh, 0);

	if (fs->opt_verbose)
		fprintf(stderr,
			"%i/%i inodes resolved\r",
			state->resolvedentries,
			state->usedentries);

	return 1;
}

/* basically: this builds a dependency graph of the inodes in the entire file
 * system.  inodes are only referenced by the directory tree (or the magic
 * ones implicitly, like the bad blocks inode), so we just walk the directory
 * tree adding references.
 */
static int doscan(struct ext2_fs *fs, struct ext2_inode_relocator_state *state)
{
	int i;

	/* while the journal will usually be inode 8 (and therefore will never
	 * need to be moved), we don't have any guarantee (grrr).  So, we
	 * need to be prepared to move it... (and update the reference in the
	 * super block)
	 */
	if (fs->has_internal_journal)
		addref(fs, state, EXT2_SUPER_JOURNAL_INUM(fs->sb),
		       1, offsetof(struct ext2_super_block, s_journal_inum));

	if (!doscangroup(fs, state, 0))
		return 0;

	if (state->resolvedentries != state->usedentries)
		for (i=fs->numgroups-1;i>0;i--)
		{
			if (!doscangroup(fs, state, i))
				return 0;

			if (state->resolvedentries == state->usedentries)
				break;
		}

	if (fs->opt_verbose)
                fputc ('\n', stderr);

	return 1;
}







static int ext2_inode_relocator_copy(struct ext2_fs *fs, struct ext2_inode_relocator_state *state)
{
	int i;

	for (i=0;i<state->usedentries;i++)
	{
		struct ext2_inode buf;
		struct ext2_inode_entry *entry;

		entry = &state->inode[i];

		if (fs->opt_debug)
			if (!ext2_get_inode_state(fs, entry->num) ||
			    ext2_get_inode_state(fs, entry->dest))
                                fputs ("inodebitmaperror\n", stderr);

		if (!ext2_read_inode(fs, entry->num, &buf))
			return 0;
		if (!ext2_write_inode(fs, entry->dest, &buf))
			return 0;

		entry->isdir = S_ISDIR(EXT2_INODE_MODE(buf))?1:0;
	}

	if (fs->opt_safe)
		if (!ext2_sync(fs))
			return 0;
	return 1;
}

static int ext2_inode_relocator_finish(struct ext2_fs *fs, struct ext2_inode_relocator_state *state)
{
	int i;

	for (i=0;i<state->usedentries;i++)
	{
		struct ext2_inode_entry *entry;

		entry = &state->inode[i];
		ext2_set_inode_state(fs, entry->dest, 1, 1);
		ext2_set_inode_state(fs, entry->num, 0, 1);
		ext2_zero_inode(fs, entry->num);
	}

	if (fs->opt_safe)
		if (!ext2_sync(fs))
			return 0;
	return 1;
}

static int ext2_inode_relocator_ref(struct ext2_fs *fs, struct ext2_inode_relocator_state *state)
{
	int		i;
	static int	numerrors = 0;

	for (i=0;i<state->usedentries;i++)
	{
		struct ext2_inode_entry *entry;
		int			 j;
		uint32_t		 t;

		entry = &state->inode[i];
		t = entry->dest;

		for (j=0;j<entry->numreferences;j++)
		{
			struct ext2_buffer_head *bh;

			bh = ext2_bread(fs, entry->ref[j].block);
			if (!bh)
				return 0;

			if (fs->opt_debug)
			{
				if (PED_LE32_TO_CPU((*((uint32_t *)(bh->data + entry->ref[j].offset)))) != entry->num)
				{
 					fprintf(stderr,
 						"inode %li ref error! (->%li, [%i]={%i, %i})\n",
						(long) entry->num,
						(long) entry->dest,
 						j,
 						entry->ref[j].block,
						(int) entry->ref[j].offset);
					ext2_brelse(bh, 0);

					if (numerrors++ < 4)
						continue;

					fputs ("all is not well!\n", stderr);
					return 0;
				}
			}

			*((uint32_t *)(bh->data + entry->ref[j].offset))
				= PED_CPU_TO_LE32(t);
			bh->dirty = 1;

			ext2_brelse(bh, 0);
		}

		if (entry->isdir)
		{
			int oldgroup;
			int newgroup;

			oldgroup = (entry->num  - 1)
					/ EXT2_SUPER_INODES_PER_GROUP(fs->sb);
			newgroup = (entry->dest - 1)
					/ EXT2_SUPER_INODES_PER_GROUP(fs->sb);

			fs->gd[oldgroup].bg_used_dirs_count = PED_CPU_TO_LE16 (
				EXT2_GROUP_USED_DIRS_COUNT(fs->gd[oldgroup])
				- 1);
			fs->gd[newgroup].bg_used_dirs_count = PED_CPU_TO_LE16 (
				EXT2_GROUP_USED_DIRS_COUNT(fs->gd[newgroup])
				+ 1);

			fs->metadirty = EXT2_META_GD;
		}
	}

	if (fs->opt_safe)
		if (!ext2_sync(fs))
			return 0;

	return 1;
}

static int ext2_inode_relocator_grab_inodes(struct ext2_fs *fs, struct ext2_inode_relocator_state *state)
{
	int i;
	int ptr;

	ptr = 0;

	for (i=0;i<fs->numgroups;i++)
		if (EXT2_GROUP_FREE_INODES_COUNT(fs->gd[i]))
		{
			struct ext2_buffer_head *bh;
			unsigned int j;
			int offset;

			bh = ext2_bread(fs, EXT2_GROUP_INODE_BITMAP(fs->gd[i]));
			if (!bh)
				return 0;
			offset = i * EXT2_SUPER_INODES_PER_GROUP(fs->sb) + 1;

			j = i ? 0 : 13;
			for (;j<EXT2_SUPER_INODES_PER_GROUP(fs->sb);j++)
				if (!(bh->data[j>>3] & _bitmap[j&7]))
				{
					state->inode[ptr++].dest = offset + j;

					if (ptr == state->usedentries)
					{
						ext2_brelse(bh, 0);
						return 1;
					}
				}

			ext2_brelse(bh, 0);
		}

	ped_exception_throw (PED_EXCEPTION_ERROR, PED_EXCEPTION_CANCEL,
			     _("Not enough free inodes!"));
	return 0;
}

static int ext2_inode_relocator_flush(struct ext2_fs *fs, struct ext2_inode_relocator_state *state)
{
	if (!state->usedentries)
		return 1;

	if (!doscan(fs, state))
		return 0;

	if (!ext2_inode_relocator_grab_inodes(fs, state))
		return 0;

	if (!ext2_inode_relocator_copy(fs, state))
		return 0;

	if (!ext2_inode_relocator_ref(fs, state))
		return 0;

	if (!ext2_inode_relocator_finish(fs, state))
		return 0;

	state->usedentries = 0;
	state->resolvedentries = 0;
	state->last = (struct ext2_reference *)fs->relocator_pool_end;

	if (fs->opt_safe)
		if (!ext2_sync(fs))
			return 0;

	return 1;
}

static int ext2_inode_relocator_mark(struct ext2_fs *fs, struct ext2_inode_relocator_state *state, ino_t inode)
{
	struct ext2_inode	 buf;
	struct ext2_inode_entry *ent;
	int			 i;

	if (!ext2_read_inode(fs, inode, &buf))
		return 0;

	{
		register void *adv;
		register void *rec;

		adv = state->inode + state->usedentries + 1;
		rec = state->last - EXT2_INODE_LINKS_COUNT(buf);

		if (adv >= rec)
			ext2_inode_relocator_flush(fs, state);
	}

	state->last -= EXT2_INODE_LINKS_COUNT(buf);

	ent = &state->inode[state->usedentries];
	ent->num = inode;
	ent->dest = 0;
	ent->numreferences = EXT2_INODE_LINKS_COUNT(buf);
	ent->ref = state->last;

	for (i=0;i<ent->numreferences;i++)
	{
		ent->ref[i].block = 0;
		ent->ref[i].offset = 0;
	}

	state->usedentries++;

	return 1;
}


int ext2_inode_relocate(struct ext2_fs *fs, int newgroups)
{
	int i;
	struct ext2_inode_relocator_state state;

	if (fs->opt_verbose)
                fputs ("ext2_inode_relocate\n", stderr);

	state.usedentries = 0;
	state.resolvedentries = 0;
	state.inode = (struct ext2_inode_entry *)fs->relocator_pool;
	state.last = (struct ext2_reference *)fs->relocator_pool_end;

	for (i=newgroups;i<fs->numgroups;i++)
	{
		struct ext2_buffer_head *bh;
		unsigned int		 j;
		int			 offset;

		bh = ext2_bread(fs, EXT2_GROUP_INODE_BITMAP(fs->gd[i]));
		if (!bh)
			return 0;
		offset = i * EXT2_SUPER_INODES_PER_GROUP(fs->sb) + 1;

		for (j=0;j<EXT2_SUPER_INODES_PER_GROUP(fs->sb);j++)
			if (bh->data[j>>3] & _bitmap[j&7])
				ext2_inode_relocator_mark(fs, &state,
							  offset + j);

		ext2_brelse(bh, 0);
	}

	if (!ext2_inode_relocator_flush(fs, &state))
		return 0;

	return 1;
}
#endif /* !DISCOVER_ONLY */

