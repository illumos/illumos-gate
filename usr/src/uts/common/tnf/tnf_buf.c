/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1994-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>		/* for bzero */
#include <sys/machlock.h>
#include <sys/spl.h>
#include <sys/promif.h>
#include <sys/debug.h>

#include "tnf_buf.h"

/*
 * Defines
 */

#define	TNFW_B_ALLOC_LO		0x1
#define	TNFW_B_MAXALLOCTRY 	32

#define	TNF_MAXALLOC		(TNF_BLOCK_SIZE - sizeof (tnf_block_header_t))

/*
 * Globals
 */

TNFW_B_STATE tnfw_b_state = TNFW_B_NOBUFFER | TNFW_B_STOPPED;

/*
 * Locals
 */

static int	spinlock_spl;

/*
 * Declarations
 */

static tnf_block_header_t *tnfw_b_alloc_block(tnf_buf_file_header_t *,
    enum tnf_alloc_mode);

/*
 * (Private) Allocate a new block.  Return NULL on failure and mark
 * tracing as broken.  'istag' is non-zero if the block is to be
 * non-reclaimable.  All blocks are returned A-locked.
 */

static tnf_block_header_t *
tnfw_b_alloc_block(tnf_buf_file_header_t *fh, enum tnf_alloc_mode istag)
{
	tnf_block_header_t 	*block;
	ulong_t			bcount;
	ulong_t			tmp_bn, bn, new_bn;
	ulong_t			tmp_gen, gen, new_gen;
	ulong_t			next;
	int			i;
	lock_t			*lp;
	ushort_t		spl;

	if (tnfw_b_state != TNFW_B_RUNNING)
		return (NULL);

	lp = &fh->lock;

	/*
	 * Check reserved area first for tag block allocations
	 * Tag allocations are rare, so we move the code out of line
	 */
	if (istag)
		goto try_reserved;

try_loop:
	/*
	 * Search for a block, using hint as starting point.
	 */

	bcount = fh->com.block_count;	/* total block count */

	gen = fh->next_alloc.gen;
	bn = fh->next_alloc.block[gen & TNFW_B_ALLOC_LO];

	for (i = 0; i < TNFW_B_MAXALLOCTRY; i++) {

		/*
		 * Calculate next (not this) block to look for.
		 * Needed for updating the hint.
		 */
		if ((new_bn = bn + 1) >= bcount) {
			new_bn = TNFW_B_DATA_BLOCK_BEGIN >> TNF_BLOCK_SHIFT;
			new_gen = gen + 1;
		} else
			new_gen = gen;

		/*
		 * Try to reserve candidate block
		 */
		/* LINTED pointer cast may result in improper alignment */
		block = (tnf_block_header_t *)
			((char *)fh + (bn << TNF_BLOCK_SHIFT));

		if (lock_try(&block->A_lock))
			if (block->generation < gen &&
			    lock_try(&block->B_lock))
				goto update_hint;
			else
				lock_clear(&block->A_lock);

		/* Reload hint values */
		gen = fh->next_alloc.gen;
		bn = fh->next_alloc.block[gen & TNFW_B_ALLOC_LO];

		/* adjust if we know a little better than the hint */
		if ((new_bn > bn && new_gen == gen) || new_gen > gen) {
			gen = new_gen;
			bn = new_bn;
		}
	}

	goto loop_fail;

update_hint:
	/*
	 * Re-read the hint and update it only if we'll be increasing it.
	 */
	lock_set_spl(lp, spinlock_spl, &spl);
	tmp_gen = fh->next_alloc.gen;
	tmp_bn = fh->next_alloc.block[tmp_gen & TNFW_B_ALLOC_LO];

	if ((new_gen == tmp_gen && new_bn > tmp_bn) || new_gen > tmp_gen) {
		/*
		 * Order is important here!  It is the write to
		 * next_alloc.gen that atomically records the new
		 * value.
		 */
		fh->next_alloc.block[new_gen & TNFW_B_ALLOC_LO] = new_bn;
		fh->next_alloc.gen = new_gen;
	}
	lock_clear_splx(lp, spl);

got_block:
	/*
	 * Initialize and return the block
	 */
	/* ASSERT(block->tag == TNF_BLOCK_HEADER_TAG); */
	block->bytes_valid = sizeof (tnf_block_header_t);
	block->next_block = NULL;
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	block->generation = istag ? TNF_TAG_GENERATION_NUM : gen;
	/* ASSERT(LOCK_HELD(&block->A_lock); */
	lock_clear(&block->B_lock);
	return (block);

try_reserved:
	/*
	 * Look for a free tag block in reserved area
	 */
	next = fh->next_tag_alloc;
	while (next < (TNFW_B_DATA_BLOCK_BEGIN >> TNF_BLOCK_SHIFT)) {
		/* LINTED pointer cast may result in improper alignment */
		block = (tnf_block_header_t *)
			((char *)fh + (next << TNF_BLOCK_SHIFT));
		next++;
		/*
		 * See if block is unclaimed.
		 * Don't bother clearing the A-lock if the
		 * block was claimed and released, since it
		 * will never be reallocated anyway.
		 */
		if (lock_try(&block->A_lock) &&
		    block->generation == 0) {
			lock_set_spl(lp, spinlock_spl, &spl);
			if (next > fh->next_tag_alloc)
				fh->next_tag_alloc = next;
			lock_clear_splx(lp, spl);
			goto got_block;
		}
	}
	goto try_loop;

loop_fail:
	/*
	 * Only get here if we failed the for loop
	 */
	ASSERT(i == TNFW_B_MAXALLOCTRY);
	tnfw_b_state = TNFW_B_BROKEN;
#ifdef DEBUG
	prom_printf("kernel probes: alloc_block failed\n");
#endif
	return (NULL);

}

/*
 * Allocate size bytes from the trace buffer.  Return NULL on failure,
 * and mark tracing as broken.  We're guaranteed that the buffer will
 * not be deallocated while we're in this routine.
 * Allocation requests must be word-sized and are word-aligned.
 */

void *
tnfw_b_alloc(TNFW_B_WCB *wcb, size_t size, enum tnf_alloc_mode istag)
{
	TNFW_B_POS 		*pos;
	ushort_t		offset;
	void 			*destp;
	tnf_block_header_t	*block, *new_block;

	pos = &wcb->tnfw_w_pos;	/* common case */
	if (istag)
		pos = &wcb->tnfw_w_tag_pos;
	block = pos->tnfw_w_block;
	offset = pos->tnfw_w_write_off;
	/* Round size up to a multiple of 8. */
	size = (size + 7) & ~7;

	if (block == NULL || offset + size > TNF_BLOCK_SIZE) {

		/* Get a new block */
		/* LINTED pointer cast may result in improper alignment */
		new_block = tnfw_b_alloc_block(TNF_FILE_HEADER(), istag);
		if (new_block == NULL)
			/* tracing has been marked as broken at this point */
			return (NULL);

		/* ASSERT(size <= TNF_MAXALLOC); */

		/*
		 * If the old block is clean (i.e., we're in a new
		 * transaction), just release it.  Else, pad it out
		 * and attach it to the list of uncommitted blocks.
		 */
		if (block != NULL) {
			if (block->bytes_valid == offset &&
			    !pos->tnfw_w_dirty) {
				/* block is clean: release it */
				lock_clear(&block->A_lock);
			} else {
				/* block is dirty */
				ulong_t *p, *q;

				/* LINTED pointer cast */
				p = (ulong_t *)((char *)block + offset);
				/* LINTED pointer cast */
				q = (ulong_t *)((char *)block + TNF_BLOCK_SIZE);
				while (p < q)
					*p++ = TNF_NULL;

				/* append block to release list */
				new_block->next_block = block;

				/* we have at least one dirty block */
				pos->tnfw_w_dirty = 1;
			}
		}

		/* make new_block the current block */
		pos->tnfw_w_block = block = new_block;
		/* write_off is updated below */
		offset = sizeof (tnf_block_header_t);
		/* ASSERT(new_block->bytes_valid == offset); */
	}

	destp = (char *)block + offset;
	/* update write_off */
	pos->tnfw_w_write_off = offset + size;
	/*
	 * Unconditionally write a 0 into the last word allocated,
	 * in case we left an alignment gap.  (Assume that doing an
	 * unconditional write is cheaper than testing and branching
	 * around the write half the time.)
	 */
	/* LINTED pointer cast may result in improper alignment */
	*((int *)((char *)destp + size - sizeof (int))) = 0;
	return (destp);
}

/*
 * Allocate a directory entry.
 */

/*ARGSUSED0*/
void *
tnfw_b_fw_alloc(TNFW_B_WCB *wcb)
{
	tnf_buf_file_header_t	*fh;
	lock_t			*lp;
	ushort_t		spl;
	caddr_t			cell;
	ulong_t			next;

	/* LINTED pointer cast may result in improper alignment */
	fh = TNF_FILE_HEADER();
	lp = &fh->lock;

	lock_set_spl(lp, spinlock_spl, &spl);
	next = fh->next_fw_alloc;
	if (next < TNFW_B_FW_ZONE) {
		cell = (caddr_t)fh + next;
		fh->next_fw_alloc = next + sizeof (tnf_ref32_t);
	} else
		cell = NULL;
	lock_clear_splx(lp, spl);

	return (cell);
}

/*
 * Initialize a buffer.
 */

void
tnfw_b_init_buffer(caddr_t buf, size_t size)
{
	int 	gen_shift;
	int 	i;
	ulong_t	b;
	ulong_t	blocks;
	tnf_block_header_t *block;
	tnf_buf_file_header_t *fh;

	/* Compute platform-specific spinlock_spl */
	spinlock_spl = __ipltospl(LOCK_LEVEL + 1);

	/* LINTED pointer cast may result in improper alignment */
	fh = (tnf_buf_file_header_t *)buf;

	/* LINTED logical expression always true: op "||" */
	ASSERT(TNF_DIRECTORY_SIZE > TNF_BLOCK_SIZE);

	/*
	 * This assertion is needed because we cannot change
	 * sys/tnf_com.h this late in the release cycle, but we need the
	 * interface in sys/machlock.h for locking operations.
	 */
	/* LINTED logical expression always true: op "||" */
	ASSERT(sizeof (tnf_byte_lock_t) == sizeof (lock_t));

	/* Calculate number of blocks */
	blocks = size >> TNF_BLOCK_SHIFT;

	/* Calculate generation shift */
	gen_shift = 0;
	b = 1;
	while (b < blocks) {
		b <<= 1;
		++gen_shift;
	}
	ASSERT(gen_shift < 32);

	/* fill in file header */
	/* magic number comes last */
	/* LINTED constant truncated by assignment */
	fh->com.tag = TNF_FILE_HEADER_TAG;
	fh->com.file_version = TNF_FILE_VERSION;
	fh->com.file_header_size = sizeof (tnf_file_header_t);
	fh->com.file_log_size = gen_shift + TNF_BLOCK_SHIFT;
	fh->com.block_header_size = sizeof (tnf_block_header_t);
	fh->com.block_size = TNF_BLOCK_SIZE;
	fh->com.directory_size = TNF_DIRECTORY_SIZE;
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	fh->com.block_count = blocks;
	/* com.blocks_valid is unused */
	fh->next_alloc.gen = 1;
	fh->next_alloc.block[0] = 0;
	fh->next_alloc.block[1] = TNFW_B_DATA_BLOCK_BEGIN >> TNF_BLOCK_SHIFT;
	fh->next_tag_alloc = TNF_DIRECTORY_SIZE >> TNF_BLOCK_SHIFT;
	fh->next_fw_alloc = TNF_DIRENT_LAST + 4;
	LOCK_INIT_CLEAR(&fh->lock);

	(void) bzero(buf + sizeof (*fh), TNF_DIRECTORY_SIZE - sizeof (*fh));
	i = TNF_DIRECTORY_SIZE >> TNF_BLOCK_SHIFT;
	for (; i < blocks; ++i) {
		/* LINTED pointer cast may result in improper alignment */
		block =	(tnf_block_header_t *)(buf + (i << TNF_BLOCK_SHIFT));
		block->tag = (tnf_ref32_t)TNF_BLOCK_HEADER_TAG;
		block->generation = 0;
		block->bytes_valid = sizeof (tnf_block_header_t);
		LOCK_INIT_CLEAR(&block->A_lock);
		LOCK_INIT_CLEAR(&block->B_lock);
	}

	/* snap in magic number */
	fh->magic = TNF_MAGIC;
}
