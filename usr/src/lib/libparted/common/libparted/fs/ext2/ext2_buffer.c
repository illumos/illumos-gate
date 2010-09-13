/*
    ext2_buffer.c -- ext2 buffer cache
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
#include <string.h>
#include "ext2.h"

/* pseudo-header */

static __inline__ int ext2_block_hash(blk_t block)
{
	unsigned long x;

	x = block ^ (block >> 8) ^ (block >> 16) ^ (block >> 24);
	return x & ((1 << ext2_hash_bits) - 1);
}

static struct ext2_buffer_head *ext2_bh_alloc   (struct ext2_buffer_cache *, blk_t);
static void                     ext2_bh_dealloc (struct ext2_buffer_head *);
static struct ext2_buffer_head *ext2_bh_find    (struct ext2_buffer_cache *, blk_t);
static int                      ext2_bh_do_read (struct ext2_buffer_head *);
static int                      ext2_bh_do_write(struct ext2_buffer_head *);
static void                     ext2_bh_hash    (struct ext2_buffer_head *);
static void                     ext2_bh_unhash  (struct ext2_buffer_head *);



static int try_to_flush(struct ext2_buffer_cache *bc)
{
	int i;

	for (i=0;i<bc->size;i++)
	{
		struct ext2_buffer_head *bh;

		bh = &bc->heads[i];
	
		if (bh->alloc && !bh->usecount && !bh->dirty)
		{
			ext2_bh_dealloc(bh);
			return 1;
		}
	}

	for (i=0;i<bc->size;i++)
	{
		struct ext2_buffer_head *bh;

		bh = &bc->heads[i];

		if (bh->alloc && !bh->usecount && bh->dirty)
		{
			ext2_bh_do_write(bh);
			ext2_bh_dealloc(bh);
			return 1;
		}
	}

	if (ped_exception_throw (PED_EXCEPTION_ERROR,
				 PED_EXCEPTION_IGNORE_CANCEL,
				 _("Couldn't flush buffer cache!"))
			!= PED_EXCEPTION_IGNORE)
		return 0;
	return 1;
}





static struct ext2_buffer_head *ext2_bh_alloc(struct ext2_buffer_cache *bc, blk_t block)
{
	struct ext2_buffer_head *bh;
	int i;

	bh = NULL;

 tryagain:
	for (i=0;i<bc->size;i++)
	{
		bh = &bc->heads[i];

		if (!bh->alloc)
			break;
	}

	if (i == bc->size)
	{
		try_to_flush(bc);
		goto tryagain;
	}

	bh = &bc->heads[i];

	bh->next = NULL;
	bh->prev = NULL;
	bh->block = block;
	bh->usecount = 0;
	bh->dirty = 0;
	bh->alloc = 1;
	bc->numalloc++;

	ext2_bh_hash(bh);

	return bh;
}

static void ext2_bh_dealloc(struct ext2_buffer_head *bh)
{
	if (bh->dirty)
		ped_exception_throw (PED_EXCEPTION_BUG, PED_EXCEPTION_IGNORE,
			"deallocing() a dirty buffer! %i\n", bh->block);

	ext2_bh_unhash(bh);
	bh->alloc = 0;
	bh->bc->numalloc--;
}

static struct ext2_buffer_head *ext2_bh_find(struct ext2_buffer_cache *bc, blk_t block)
{
	struct ext2_buffer_head *a;
	struct ext2_buffer_head *b;
	int			 hash;

	hash = ext2_block_hash(block);
	a = bc->hash[hash];

	if (a != NULL)
	{
		b = a;
		do
		{
			if (a->block == block)
				return a;

			a = a->next;
		} while (a != b);
	}

	return NULL;
}

static int ext2_bh_do_read(struct ext2_buffer_head *bh)
{
	return ext2_read_blocks(bh->bc->fs, bh->data, bh->block, 1);
}

static int ext2_bh_do_write(struct ext2_buffer_head *bh)
{
	if (!bh->alloc) {
		ped_exception_throw (PED_EXCEPTION_BUG, PED_EXCEPTION_CANCEL,
			"Attempt to write unallocated buffer.");
		return 0;
	}

	ext2_write_blocks(bh->bc->fs, bh->data, bh->block, 1);
	bh->dirty = 0;
	return 1;
}

static void ext2_bh_hash(struct ext2_buffer_head *bh)
{
	int hash;

	hash = ext2_block_hash(bh->block);
	if (bh->bc->hash[hash] != NULL)
	{
		bh->next = bh->bc->hash[hash];
		bh->prev = bh->next->prev;
		bh->next->prev = bh;
		bh->prev->next = bh;
		return;
	}

	bh->bc->hash[hash] = bh;
	bh->next = bh->prev = bh;
}

static void ext2_bh_unhash(struct ext2_buffer_head *bh)
{
	int hash;

	hash = ext2_block_hash(bh->block);

	bh->prev->next = bh->next;
	bh->next->prev = bh->prev;

	if (bh->bc->hash[hash] == bh)
	{
		if (bh->next != bh)
			bh->bc->hash[hash] = bh->next;
		else
			bh->bc->hash[hash] = NULL;
	}

	bh->next = NULL;
	bh->prev = NULL;
}







static int breadimmhits = 0;
static int breadindhits = 0;
static int breadmisses = 0;

void ext2_bcache_deinit(struct ext2_fs *fs)
{
	ext2_bcache_sync(fs);
	ped_free(fs->bc->buffermem);
	ped_free(fs->bc->hash);
	ped_free(fs->bc->heads);
	ped_free(fs->bc);

	if (fs->opt_verbose)
		fprintf(stderr,
			"direct hits: %i, indirect hits: %i, misses: %i\n",
			breadimmhits,
			breadindhits,
			breadmisses);
}

void ext2_bcache_dump(struct ext2_fs *fs)
{
	int i;

	fputs ("buffer cache dump:\n", stderr);

	for (i=0;i<(1<<ext2_hash_bits);i++)
		if (fs->bc->hash[i] != NULL)
		{
			struct ext2_buffer_head *a;
			struct ext2_buffer_head *b;

			fprintf(stderr, "%i: ", i);

			a = b = fs->bc->hash[i];
			do
			{
				fprintf(stderr, "%i ", a->block);
				a = a->next;
			} while (a != b);

			fputc ('\n', stderr);
		}
}

int ext2_bcache_flush(struct ext2_fs *fs, blk_t block)
{
	struct ext2_buffer_head *bh;

	if ((bh = ext2_bh_find(fs->bc, block)) == NULL)
		return 1;

	if (bh->usecount) {
		ped_exception_throw (PED_EXCEPTION_BUG, PED_EXCEPTION_CANCEL,
			"Attempt to flush a buffer that's in use! [%i,%i]",
			bh->block, bh->usecount);
		return 0;
	}

	if (bh->dirty) {
		if (!ext2_bh_do_write(bh))
			return 0;
	}

	ext2_bh_dealloc(bh);
	return 1;
}

int ext2_bcache_flush_range(struct ext2_fs *fs, blk_t block, blk_t num)
{
	blk_t end = block + num;

	for (; block < end; block++) {
		if (!ext2_bcache_flush(fs, block))
			return 0;
	}
	return 1;
}

int ext2_bcache_init(struct ext2_fs *fs)
{
	struct ext2_buffer_cache *bc;
	int i;
	int size;

	size = ext2_buffer_cache_pool_size >> (fs->logsize - 10);

	if ((bc = (struct ext2_buffer_cache *) ped_malloc(sizeof(struct ext2_buffer_cache))) == NULL)
		return 0;

	if ((bc->heads = (struct ext2_buffer_head *) ped_malloc(size * sizeof(struct ext2_buffer_head))) == NULL)
		return 0;

	if ((bc->hash = (struct ext2_buffer_head **) ped_malloc(sizeof(struct ext2_buffer_head *) << ext2_hash_bits)) == NULL)
	{
		ped_free(bc->heads);
		ped_free(bc);
		return 0;
	}

	if ((bc->buffermem = (unsigned char *) ped_malloc(ext2_buffer_cache_pool_size << 10)) == NULL)
	{
		ped_free(bc->hash);
		ped_free(bc->heads);
		ped_free(bc);
		return 0;
	}

	bc->cache = &bc->heads[0];
	bc->fs = fs;
	bc->size = size;
	bc->numalloc = 0;

	for (i=0;i<size;i++)
	{
		bc->heads[i].data = bc->buffermem + (i << fs->logsize);
		bc->heads[i].bc = bc;
		bc->heads[i].alloc = 0;
	}

	for (i=0;i<(1<<ext2_hash_bits);i++)
		bc->hash[i] = NULL;

	fs->bc = bc;

	return 1;
}

int ext2_bcache_sync(struct ext2_fs *fs)
{
	int i;

	for (i=0;i<fs->bc->size;i++)
	{
		struct ext2_buffer_head *bh;

		bh = &fs->bc->heads[i];

		if (bh->alloc && bh->dirty) {
			if (!ext2_bh_do_write(bh))
				return 0;
		}
	}
	return 1;
}








struct ext2_buffer_head *ext2_bcreate(struct ext2_fs *fs, blk_t block)
{
	struct ext2_buffer_head *bh;

	if ((bh = ext2_bh_find(fs->bc, block)) != NULL)
	{
		bh->usecount++;
	}
	else
	{
		bh = ext2_bh_alloc(fs->bc, block);
		bh->usecount = 1;
	}

	memset(bh->data, 0, fs->blocksize);
	bh->dirty = 1;

	return bh;
}

struct ext2_buffer_head *ext2_bread(struct ext2_fs *fs, blk_t block)
{
	struct ext2_buffer_head *bh;

	if ((bh = fs->bc->cache)->block == block)
	{
		breadimmhits++;
		bh->usecount++;
		return bh;
	}

	if ((bh = ext2_bh_find(fs->bc, block)) != NULL)
	{
		fs->bc->cache = bh;
		breadindhits++;
		bh->usecount++;
		return bh;
	}

	breadmisses++;

	bh = ext2_bh_alloc(fs->bc, block);
	fs->bc->cache = bh;
	bh->usecount = 1;
	if (!ext2_bh_do_read(bh)) {
		ext2_bh_dealloc(bh);
		return NULL;
	}

	return bh;
}

int ext2_brelse(struct ext2_buffer_head *bh, int forget)
{
	if (bh->usecount-- == 1 && forget)
	{
		if (bh->dirty) {
			if (!ext2_bh_do_write(bh))
				return 0;
		}

		ext2_bh_dealloc(bh);
	}
	return 1;
}

#endif /* !DISCOVER_ONLY */

