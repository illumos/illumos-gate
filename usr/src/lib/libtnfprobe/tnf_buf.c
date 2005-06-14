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
 *  Copyright 1994-2003 Sun Microsytems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#ifdef _KERNEL
#include <sys/systm.h>		/* for bzero */
#include <sys/spl.h>
#include <sys/cmn_err.h>
#else  /* _KERNEL */
#include <string.h>		/* for memset */
#endif /* _KERNEL */

#include "tnf_buf.h"

#ifdef TNFWB_DEBUG
#ifdef _KERNEL
#error TNFWB_DEBUG
#else  /* _KERNEL */
#include <stdio.h>
#include <thread.h>
#endif /* _KERNEL */
#endif /* TNFW_DEBUG */

/*
 * Defines
 */

#define	TNFW_B_FW_INVALID 		0xffffffff
#define	TNFW_B_ALLOC_LO_SELECTOR 	0x1
#define	TNFW_B_MAXALLOCTRY 		200

#ifdef TNF_BLOCK_STATS
static struct {
	int tnf_block_allocs;
	int tnf_block_tries;
	int tnf_max_block_tries;
	int tnf_tag_blocks;
	int tnf_generation_laps;
	int tnf_a_locks;
	int tnf_b_locks;
} tnf_block_stats;
#endif

/*
 * Regular record tag pointer - CAUTION - has to be in sync with tnf_tag
 * macro in writer.h
 */
#define	TNFW_B_TAG_DIFF(item, ref)				\
	((TNF_REF32_MAKE_PERMANENT((tnf_ref32_t)		\
	    ((char *)(item) - (char *)(ref)))) | TNF_REF32_T_TAG)

/*
 * Exported interface by buffering layer to indicate where fowarding ptrs
 * for file header and block header are.
 */
static tnf_buf_header_t forwarding_ptrs = {NULL, NULL, NULL};
tnf_buf_header_t *_tnf_buf_headers_p = &forwarding_ptrs;

#ifdef _KERNEL
extern volatile caddr_t tnf_buf;

static kmutex_t hintlock;
#endif

/*
 * (Private) Allocate a new block.  Return NULL on failure.  'istag'
 * is true if the block is to be non-reclaimable.
 */
static tnf_block_header_t *
tnfw_b_alloc_block(TNFW_B_WCB *wcb, enum tnf_alloc_mode istag)
{
	tnf_block_header_t 	*block;
	uint_t 			hint_hi, hint_lo;
	uint_t			new_hint_hi, new_hint_lo;
	uint_t 			generation;
	uint_t			blocknum;
	uint_t 			prev_gen = 0;
	uint_t			prev_block = 0;
	uint_t			i, b;
	boolean_t 		gotit = B_FALSE;
	volatile tnf_buf_file_header_t 	*fh;
#ifdef TNF_BLOCK_STATS
	register int tag_blocks = 0, generation_laps = 0, a_locks = 0,
		b_locks = 0;
#endif

#ifdef _TNF_VERBOSE
	fprintf(stderr, "tnfw_b_alloc_block: \n");
#endif

	if (_tnfw_b_control->tnf_state != TNFW_B_RUNNING) {
#ifndef _KERNEL
		if (_tnfw_b_control->tnf_state == TNFW_B_NOBUFFER)
			if (_tnfw_b_control->tnf_init_callback() == 0)
				return (NULL);
#endif /* _KERNEL */
		if (TNFW_B_IS_STOPPED(_tnfw_b_control->tnf_state))
			return (NULL);
		if (_tnfw_b_control->tnf_state == TNFW_B_BROKEN)
			return (NULL);
	}

	/* LINTED pointer cast may result in improper alignment */
	fh = (volatile tnf_buf_file_header_t *)_tnfw_b_control->tnf_buffer;
	if (!wcb->tnfw_w_initialized) {
		/* Get the block shift and generation shift values. */
		b = 1;
		wcb->tnfw_w_block_shift = wcb->tnfw_w_gen_shift = 0;
		while (b != fh->com.block_size) {
			b <<= 1;
			++wcb->tnfw_w_block_shift;
		}
		b = 1;
		while (b < fh->com.block_count) {
			b <<= 1;
			++wcb->tnfw_w_gen_shift;
		}
		wcb->tnfw_w_pid = _tnfw_b_control->tnf_pid;
		wcb->tnfw_w_initialized = B_TRUE;
	}

	/*
	 * If we need a tag block, check the reserved tag block space
	 * first.  fh->next_tag_alloc is only a hint; it is updated
	 * without concurrency control.
	 */
	if (istag && fh->next_tag_alloc < TNFW_B_DATA_BLOCK_BEGIN) {
		i = fh->next_tag_alloc;
		do {
			/* LINTED pointer cast */
			block = (tnf_block_header_t *) ((char *) fh + i);
			if (!tnfw_b_get_lock(&block->A_lock) &&
			    block->generation == 0)
				break;
			i += fh->com.block_size;
		} while (i < TNFW_B_DATA_BLOCK_BEGIN);
		if (i < TNFW_B_DATA_BLOCK_BEGIN) {
			if (i > fh->next_tag_alloc)
				fh->next_tag_alloc = i;
			blocknum = i >> wcb->tnfw_w_block_shift;
			if (blocknum > fh->com.blocks_valid)
				fh->com.blocks_valid = blocknum;
			/* LINTED pointer subtraction casted to 32 bits */
			block->tag = TNFW_B_TAG_DIFF(
			    forwarding_ptrs.fw_block_header, fh);
			/* LINTED constant truncated by assignment */
			block->generation = TNF_TAG_GENERATION_NUM;
			block->bytes_valid = sizeof (tnf_block_header_t);
			block->next_block = NULL;
			tnfw_b_clear_lock(&block->A_lock);
			return (block);
		}
	}

	for (i = 0; !gotit && i != TNFW_B_MAXALLOCTRY; ++i) {
		hint_hi = fh->next_alloc.hi;
		hint_lo = (hint_hi & TNFW_B_ALLOC_LO_SELECTOR)
			? fh->next_alloc.lo[1] : fh->next_alloc.lo[0];
		generation = (hint_hi << (32 - wcb->tnfw_w_gen_shift)) |
			(hint_lo >> wcb->tnfw_w_gen_shift);
		blocknum = hint_lo & ((1 << wcb->tnfw_w_gen_shift) - 1);
#ifdef TNFWB_DEBUG
		fprintf(stderr, "alloc_block (%d): read hint (%d, %d)\n",
		    thr_self(), generation, blocknum);
#endif
		if ((prev_gen == generation && prev_block > blocknum) ||
		    prev_gen > generation) {
			generation = prev_gen;
			blocknum = prev_block;
		}
#ifdef TNFWB_DEBUG
		fprintf(stderr,
		    "alloc_block (%d): trying blocknum = %d, gen %d\n",
		    thr_self(), blocknum, generation);
#endif
		block = (tnf_block_header_t *)
		/* LINTED pointer cast may result in improper alignment */
			((char *)fh + blocknum * fh->com.block_size);
#ifdef TNF_BLOCK_STATS
		if (block->generation == TNF_TAG_GENERATION_NUM)
			++tag_blocks;
		else if (block->generation >= generation)
			++generation_laps;
		else if (tnfw_b_get_lock(&block->A_lock))
			++a_locks;
		else if (block->generation == TNF_TAG_GENERATION_NUM)
			++tag_blocks;
		else if (block->generation >= generation)
			++generation_laps;
		else if (tnfw_b_get_lock(&block->B_lock)) {
			tnfw_b_clear_lock(&block->A_lock);
			++b_locks;
		} else
			gotit = B_TRUE;

#else
		if (block->generation < generation &&
		    !tnfw_b_get_lock(&block->A_lock)) {
			if (block->generation < generation &&
			    !tnfw_b_get_lock(&block->B_lock)) {
				gotit = B_TRUE;
			} else {
				tnfw_b_clear_lock(&block->A_lock);
			}
		}
#endif
		prev_block = blocknum + 1;
		prev_gen = generation;
		if (prev_block == fh->com.block_count) {
			prev_block =
			    TNFW_B_DATA_BLOCK_BEGIN >> wcb->tnfw_w_block_shift;
			++prev_gen;
		}
		if (blocknum > fh->com.blocks_valid) {
			fh->com.blocks_valid = blocknum;
		}
	}

	if (i == TNFW_B_MAXALLOCTRY) {
		_tnfw_b_control->tnf_state = TNFW_B_BROKEN;
		return (NULL);
	}
#ifdef TNFWB_DEBUG
	fprintf(stderr,
	    "alloc_block (%d): got blocknum = %d, gen %d, block at 0x%x\n",
	    thr_self(), blocknum, generation, block);
#endif
	/* LINTED pointer subtraction casted to 32 bits */
	block->tag = TNFW_B_TAG_DIFF(forwarding_ptrs.fw_block_header, fh);
	block->generation = (istag) ? TNF_TAG_GENERATION_NUM : generation;
	block->bytes_valid = sizeof (tnf_block_header_t);
	block->next_block = NULL;
	if (istag) {
		tnfw_b_clear_lock(&block->A_lock);
	}
	tnfw_b_clear_lock(&block->B_lock);

	/*
	 * Read the hint one more time, only update it if we'll be increasing
	 * it
	 */
	new_hint_hi = prev_gen >> (32 - wcb->tnfw_w_gen_shift);
	new_hint_lo = prev_block | (prev_gen << wcb->tnfw_w_gen_shift);
#ifdef _KERNEL
	mutex_enter(&hintlock);
#endif
	hint_hi = fh->next_alloc.hi;
	hint_lo = (hint_hi & TNFW_B_ALLOC_LO_SELECTOR) ?
		fh->next_alloc.lo[1] : fh->next_alloc.lo[0];

	if ((new_hint_hi == hint_hi && new_hint_lo > hint_lo) ||
	    new_hint_hi > hint_hi) {
		/*
		 * Order is important here!  It is the write to next_alloc.hi
		 * that atomically records the new value.
		 */
		if (new_hint_hi & TNFW_B_ALLOC_LO_SELECTOR)
			fh->next_alloc.lo[1] = new_hint_lo;
		else
			fh->next_alloc.lo[0] = new_hint_lo;
		fh->next_alloc.hi = new_hint_hi;
#ifdef TNFWB_DEBUG
		fprintf(stderr, "alloc_block (%d): wrote hint (%d, %d)\n",
		    thr_self(), prev_gen, prev_block);
#endif
	}
#ifdef _KERNEL
	mutex_exit(&hintlock);
#endif
#ifdef TNF_BLOCK_STATS
	++tnf_block_stats.tnf_block_allocs;
	tnf_block_stats.tnf_block_tries += i;
	if (i > tnf_block_stats.tnf_max_block_tries) {
		tnf_block_stats.tnf_max_block_tries = i;
		tnf_block_stats.tnf_tag_blocks = tag_blocks;
		tnf_block_stats.tnf_generation_laps = generation_laps;
		tnf_block_stats.tnf_a_locks = a_locks;
		tnf_block_stats.tnf_b_locks = b_locks;
	}
#endif
	return (block);
}

static void release_block_from_pos(TNFW_B_POS * pos)
{
	if (pos->tnfw_w_block == NULL)
		return;
	if (pos->tnfw_w_uncommitted != NULL)
		return;
	tnfw_b_clear_lock(&pos->tnfw_w_block->A_lock);
	pos->tnfw_w_block = NULL;
}

void
tnfw_b_release_block(TNFW_B_WCB * wcb)
{
	if (wcb == NULL)
		return;
	release_block_from_pos(&wcb->tnfw_w_tag_pos);
	release_block_from_pos(&wcb->tnfw_w_pos);
}

/*
 * Initialize a buffer.  NOT RE-ENTRANT!  Block sizes other than 512
 * are currently rejected.  The code "ought to work" with any block
 * size that is an integral power of 2.  'zfod' states whether we
 * can assume that the buffer is zero-filled (or paged-in zero-fill-on-demand).
 */
TNFW_B_STATUS
tnfw_b_init_buffer(char *buf, int blocks, int block_size, boolean_t zfod)

{
	int 	block_shift, gen_shift;
	int 	i;
	int	file_size;
	unsigned b;
	tnf_block_header_t *block;
	/* LINTED pointer cast may result in improper alignment */
	tnf_buf_file_header_t *fh = (tnf_buf_file_header_t *)buf;

#ifdef _TNF_VERBOSE
	fprintf(stderr, "tnfw_b_init_buffer: \n");
#endif

	/* Check for 512 could go away. */
	if (block_size != 512 || block_size < sizeof (tnf_buf_file_header_t))
		return (TNFW_B_BAD_BLOCK_SIZE);
	/*
	 * Check to see if block size is a power of 2, and get
	 * log2(block size).
	 */
	for (b = (unsigned)block_size, block_shift = 0; (b & 1) == 0; b >>= 1)
		++block_shift;
	if (b != 1)
		return (TNFW_B_BAD_BLOCK_SIZE);
	gen_shift = 0;
	while (b < blocks) {
		b <<= 1;
		++gen_shift;
	}
	/* reserve first two words for file header tag and block header tag */
	forwarding_ptrs.fw_file_header  = (char *)fh + block_size;
	forwarding_ptrs.fw_block_header = (char *)fh + block_size +
		sizeof (tnf_ref32_t);
	forwarding_ptrs.fw_root = (char *)fh + block_size +
		(2 * sizeof (tnf_ref32_t));
	/* LINTED size of tnf_ref_32_t known to be 32 */
	fh->next_fw_alloc = block_size + (3 * sizeof (tnf_ref32_t));
	/* fill in rest of file header */
	fh->magic = TNF_MAGIC;
	/* Self relative pointer to tag */
	/* LINTED pointer subtraction casted to 32 bits */
	fh->com.tag = TNFW_B_TAG_DIFF(forwarding_ptrs.fw_file_header, fh);
	fh->com.file_version = TNF_FILE_VERSION;
	fh->com.file_header_size = sizeof (tnf_file_header_t);
	/* fill in fh->com.file_log_size */
	b = 1;
	file_size = blocks * block_size;
	fh->com.file_log_size = 0;
	while (b < file_size) {
		b <<= 1;
		++fh->com.file_log_size;
	}

	fh->com.block_header_size = sizeof (tnf_block_header_t);
	fh->com.block_size = block_size;
	fh->com.directory_size = TNFW_B_FW_ZONE;
	fh->com.block_count = blocks;
	fh->com.blocks_valid = TNFW_B_FW_ZONE >> block_shift;
	if (fh->com.blocks_valid == 0)
		fh->com.blocks_valid = 1;
	fh->next_tag_alloc = TNFW_B_FW_ZONE;
	fh->next_alloc.hi = 0;
	fh->next_alloc.lo[0] =
	    (1 << gen_shift) | (TNFW_B_DATA_BLOCK_BEGIN >> block_shift);
#ifdef TNFWB_DEBUG
	fprintf(stderr, "gen_shift = %d, blocks_valid = %d\n",
	    gen_shift, fh->com.blocks_valid);
	fprintf(stderr, "alloc hint initialized to (%d, %d, %d)\n",
	    fh->next_alloc.hi, fh->next_alloc.lo[0], fh->next_alloc.lo[1]);
#endif
	if (!zfod) {
		for (i = 1; i < (TNFW_B_FW_ZONE >> block_shift); ++i) {
#ifdef _KERNEL
			bzero(buf + (i << block_shift), block_size);
#else
			(void) memset(buf + (i << block_shift), 0, block_size);
#endif
		}
		for (; i != blocks; ++i) {
			block =	(tnf_block_header_t *)
				/* LINTED pointer cast */
				(buf + (i << block_shift));
			block->tag = 0;
			block->generation = 0;
			tnfw_b_clear_lock(&block->A_lock);
			tnfw_b_clear_lock(&block->B_lock);
		}
	}
#ifdef _KERNEL
	mutex_init(&hintlock, "tnf buffer hint lock", MUTEX_SPIN_DEFAULT,
	    (void *) ipltospl(LOCK_LEVEL));
#endif
	return (TNFW_B_OK);
}

/*
 *
 */
void *
tnfw_b_alloc(TNFW_B_WCB *wcb, size_t size, enum tnf_alloc_mode istag)
{
	TNFW_B_POS 	*pos;
	int 		offset;
	void 		*destp;
	volatile tnf_buf_file_header_t *fh;
	tnf_block_header_t *block, *new_block;

#ifdef _TNF_VERBOSE
	fprintf(stderr, "tnfw_b_alloc: \n");
#endif

	if (_tnfw_b_control->tnf_state != TNFW_B_RUNNING) {
		if (TNFW_B_IS_STOPPED(_tnfw_b_control->tnf_state))
			return (NULL);
		if (_tnfw_b_control->tnf_state == TNFW_B_FORKED &&
		    _tnfw_b_control->tnf_pid != wcb->tnfw_w_pid) {
			wcb->tnfw_w_pos.tnfw_w_block =
				wcb->tnfw_w_pos.tnfw_w_uncommitted =
				wcb->tnfw_w_tag_pos.tnfw_w_block =
				wcb->tnfw_w_tag_pos.tnfw_w_uncommitted = NULL;
			wcb->tnfw_w_pid = _tnfw_b_control->tnf_pid;
			_tnfw_b_control->tnf_fork_callback();
		}
	}

	/* Round size up to a multiple of 8. */
	size = (size + 7) & ~7;

	/* LINTED pointer cast may result in improper alignment */
	fh = (volatile tnf_buf_file_header_t *)_tnfw_b_control->tnf_buffer;
	pos = (istag) ? &wcb->tnfw_w_tag_pos : &wcb->tnfw_w_pos;
	block = pos->tnfw_w_block;
	/* Check size within range. */
#ifdef TNFWB_SAFER
	if (size > fh->com.block_size - sizeof (tnf_block_header_t))
		/* TNFW_B_RECORD_TOO_BIG */
		return (NULL);
#endif
	offset = pos->tnfw_w_write_off;
#ifdef TNFWB_MAY_RELEASE_A_LOCK
	if (block != NULL && wcb->tnfw_w_a_lock_released) {
		/* re-acquire the A-lock for the current block */
		if (!tnfw_b_get_lock(&block->A_lock)) {
			wcb->tnfw_w_a_lock_released = B_FALSE;
			if (wcb->tnfw_w_generation != block->generation) {
				tnfw_b_clear_lock(&block->A_lock);
				wcb->tnfw_w_pos.tnfw_w_block = NULL;
			}
		} else {
			wcb->tnfw_w_pos.tnfw_w_block = NULL;
		}
	}
#endif
	if (block == NULL || offset + size > fh->com.block_size) {
		new_block = tnfw_b_alloc_block(wcb, istag);
		if (new_block == NULL) {
			/* TNFW_B_ACKPHT */
			return (NULL);
		}
#ifdef TNFWB_DEBUG
		fprintf(stderr,
		    "wcb 0x%x: new block at 0x%x, old block is 0x%x, "
		    "uncommitted is 0x%x\n",
		    wcb, new_block, block, pos->tnfw_w_uncommitted);
#endif
		if (block != NULL) {
			/* XXXX is this what we want for padding? */
#ifdef _KERNEL
			(void) bzero((char *)block + offset,
			    fh->com.block_size - offset);
#else
			(void) memset((char *)block + offset, 0,
			    fh->com.block_size - offset);
#endif
			if (pos->tnfw_w_uncommitted == NULL) {
#ifdef TNFWB_MAY_RELEASE_A_LOCK
				/* Could still be holding the A-lock on block */
				if (!wcb->tnfw_w_a_lock_released)
					tnfw_b_clear_lock(&block->A_lock);
#else
				/* Definitely still holding the A-lock */
				tnfw_b_clear_lock(&block->A_lock);
#endif	/* TNFWB_MAY_RELEASE_A_LOCK */
			}
		}
		/* Add new_block to the list of uncommitted blocks. */
		if (pos->tnfw_w_uncommitted == NULL) {
			pos->tnfw_w_uncommitted = new_block;
		} else {
			/* Assert(block != NULL); */
			block->next_block = new_block;
		}
		pos->tnfw_w_block = new_block;
		pos->tnfw_w_write_off = new_block->bytes_valid;
	} else if (pos->tnfw_w_uncommitted == NULL) {
		pos->tnfw_w_uncommitted = block;
	}
	destp = (char *)pos->tnfw_w_block + pos->tnfw_w_write_off;
	pos->tnfw_w_write_off += size;
	/*
	 * Unconditionally write a 0 into the last word allocated,
	 * in case we left an alignment gap.  (Assume that doing an
	 * unconditional write is cheaper than testing and branching
	 * around the write half the time.)
	 */
	/* LINTED pointer cast may result in improper alignment */
	*((int *)((char *) destp + size - sizeof (int))) = 0;

#ifdef _TNF_VERBOSE
	fprintf(stderr, "tnfw_b_alloc returning %p\n", destp);
#endif
	return (destp);
}

/*
 *
 */
TNFW_B_STATUS
tnfw_b_xcommit(TNFW_B_WCB *wcb)
{
	TNFW_B_POS *pos;
	tnf_block_header_t *block;
	volatile tnf_buf_file_header_t *fh =
		/* LINTED pointer cast may result in improper alignment */
		(volatile tnf_buf_file_header_t *)_tnfw_b_control->tnf_buffer;

#ifdef TNFWB_DEBUG
	fprintf(stderr, "tnfw_b_xcommit \n");
#endif

	/*
	 * cope with the normal record block(s) first
	 */

	pos = &wcb->tnfw_w_pos;
	block = pos->tnfw_w_uncommitted;
	while (block && (block != pos->tnfw_w_block)) {
#ifdef TNFWB_DEBUG
		fprintf(stderr, "commit %d: block = 0x%x, last = 0x%x\n",
		    block->generation, block, pos->tnfw_w_block);
#endif
		block->bytes_valid = fh->com.block_size;
		pos->tnfw_w_uncommitted = block->next_block;
		tnfw_b_clear_lock(&block->A_lock);
		block = pos->tnfw_w_uncommitted;
	}
	if (block != NULL) {
#ifdef TNFWB_DEBUG
		fprintf(stderr, "commit last %d: block = 0x%x, offset = 0x%x\n",
		    block->generation, block, pos->tnfw_w_write_off);
#endif
		block->bytes_valid = pos->tnfw_w_write_off;
	}
	pos->tnfw_w_uncommitted = NULL;
#ifdef TNFWB_MAY_RELEASE_A_LOCK
	if (0) {	/* XXXX Do we or don't we clear this lock? */
		wcb->tnfw_w_generation = block->generation;
		tnfw_b_clear_lock(&block->A_lock);
		wcb->tnfw_w_a_lock_released = B_TRUE;
	}
#endif

	/*
	 * cope with the tag block(s)
	 */

	pos = &wcb->tnfw_w_tag_pos;
	block = pos->tnfw_w_uncommitted;
	while (block && (block != pos->tnfw_w_block)) {
#ifdef TNFWB_DEBUG
		fprintf(stderr, "commit %d: block = 0x%x, last = 0x%x\n",
		    thr_self(), block, pos->tnfw_w_block);
#endif
		block->bytes_valid = fh->com.block_size;
		pos->tnfw_w_uncommitted = block->next_block;
		block = pos->tnfw_w_uncommitted;
	}
	if (block != NULL)
		block->bytes_valid = pos->tnfw_w_write_off;
	pos->tnfw_w_uncommitted = NULL;
	return (TNFW_B_OK);
}

/*
 *
 */
TNFW_B_STATUS
tnfw_b_xabort(TNFW_B_WCB *wcb)
{
	TNFW_B_POS *pos = &wcb->tnfw_w_pos;
	tnf_block_header_t *block, *next;
	volatile tnf_buf_file_header_t *fh =
		/* LINTED pointer cast may result in improper alignment */
		(volatile tnf_buf_file_header_t *)_tnfw_b_control->tnf_buffer;

	block = pos->tnfw_w_block = pos->tnfw_w_uncommitted;
	if (block != NULL) {
		pos->tnfw_w_write_off = block->bytes_valid;
#ifdef TNFWB_MAY_RELEASE_A_LOCK
		if (0) {		/* XXXX */
			tnfw_b_clear_lock(&block->A_lock);
			wcb->tnfw_w_generation = block->generation;
			wcb->tnfw_w_a_lock_released = B_TRUE;
		}
#endif
		block = block->next_block;
	}
	while (block != NULL) {
		next = block->next_block;
		tnfw_b_clear_lock(&block->A_lock);
		block = next;
	}
	pos->tnfw_w_uncommitted = NULL;
	pos = &wcb->tnfw_w_tag_pos;
	block = pos->tnfw_w_uncommitted;
	while (block && (block != pos->tnfw_w_block)) {
		block->bytes_valid = fh->com.block_size;
		pos->tnfw_w_uncommitted = block->next_block;
		block = pos->tnfw_w_uncommitted;
	}
	if (block != NULL)
		block->bytes_valid = pos->tnfw_w_write_off;
	pos->tnfw_w_uncommitted = NULL;
	return (TNFW_B_OK);
}

/*
 * The kernel version is different because we can use a spin mutex
 * in the kernel, and not all SPARC systems support the SWAP instruction.
 */
#ifdef _KERNEL
/*ARGSUSED0*/
tnf_uint32_t *
tnfw_b_fw_alloc(TNFW_B_WCB *wcb)
{
	tnf_uint32_t *ret_val;
	volatile tnf_buf_file_header_t *fh =
		/* LINTED pointer cast may result in improper alignment */
		(volatile tnf_buf_file_header_t *)_tnfw_b_control->tnf_buffer;
	tnf_uint32_t *zone_end = (tnf_uint32_t *)((char *)fh + TNFW_B_FW_ZONE);
	mutex_enter(&hintlock);
	ret_val = (tnf_uint32_t *)((char *)fh + fh->next_fw_alloc);
	if (ret_val != zone_end)
		fh->next_fw_alloc += sizeof (tnf_uint32_t);
	mutex_exit(&hintlock);
	return ((ret_val != zone_end) ? ret_val : NULL);
}

#else

/*ARGSUSED0*/
tnf_uint32_t *
tnfw_b_fw_alloc(TNFW_B_WCB *wcb)
{
	volatile tnf_buf_file_header_t *fh =
		/* LINTED pointer cast may result in improper alignment */
		(volatile tnf_buf_file_header_t *)_tnfw_b_control->tnf_buffer;
	/* LINTED pointer cast may result in improper alignment */
	uint_t *hint = (uint_t *)((uintptr_t)fh + fh->next_fw_alloc);
	/* LINTED pointer cast may result in improper alignment */
	ulong_t *zone_end = (ulong_t *)((uintptr_t)fh + TNFW_B_FW_ZONE);
	u_long swapin;
	char tmp_buf[512];
	tnf_uint32_t *retval;

#ifdef VERYVERBOSE
	    sprintf(tmp_buf, "tnfw_b_vw_alloc: begin\n");
	    (void) write(2, tmp_buf, strlen(tmp_buf));
#endif

#ifdef VERYVERBOSE
	    sprintf(tmp_buf, "tnfw_b_vw_alloc: (1)hint=%p\n", hint);
	    (void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	while ((uintptr_t)hint != (uintptr_t)zone_end) {
#ifdef VERYVERBOSE
	    sprintf(tmp_buf, "tnfw_b_vw_alloc: (2)hint=%p,zone_end=%p\n",
		    hint, zone_end);
	    (void) write(2, tmp_buf, strlen(tmp_buf));
#endif

#ifdef VERYVERBOSE
	sprintf(tmp_buf, "tnfw_b_fw_alloc: fh = %p, next->alloc = %d\n",
		fh, fh->next_fw_alloc);
	(void) write(2, tmp_buf, strlen(tmp_buf));

	    sprintf(tmp_buf, "tnfw_b_vw_alloc: about to deref hint\n");
	    (void) write(2, tmp_buf, strlen(tmp_buf));

	    sprintf(tmp_buf, "tnfw_b_vw_alloc: *hint=%ld\n", *hint);
	    (void) write(2, tmp_buf, strlen(tmp_buf));
#endif
		if (*hint == 0) {
			swapin = tnfw_b_atomic_swap(hint, TNFW_B_FW_INVALID);
			if (swapin != 0) {
				if (swapin != (unsigned)TNFW_B_FW_INVALID) {
					/* restore */
					*hint = swapin;
				}
			} else {
				break;
			}
		}
		++hint;
#ifdef VERYVERBOSE
	    sprintf(tmp_buf, "tnfw_b_vw_alloc: (3)hint=%p\n", hint);
	    (void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	}
	/* LINTED pointer subtraction casted to 32 bits */
	fh->next_fw_alloc = (uint_t) ((char *)hint - (char *)fh);
	retval = (((uintptr_t)hint != (uintptr_t)zone_end) ?
		(tnf_uint32_t *)hint : NULL);

#ifdef VERYVERBOSE
	sprintf(tmp_buf, "tnfw_b_vw_alloc: returning %p", retval);
	(void) write(2, tmp_buf, strlen(tmp_buf));
#endif

	return (retval);
}

#endif	/* _KERNEL */
