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
 * Copyright (c) 1994,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _TNF_BUF_H
#define	_TNF_BUF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/tnf_com.h>
#include <sys/machlock.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Size of a TNF buffer block
 */

#define	TNF_BLOCK_SIZE		512
#define	TNF_BLOCK_SHIFT		9
#define	TNF_BLOCK_MASK		~(TNF_BLOCK_SIZE - 1)

/*
 * Size of the file header and forwarding pointer (directory) area combined.
 * Tag and data blocks start this many bytes into the file.
 * The maximum size of this area is 64KB.
 */

#define	TNF_DIRECTORY_SIZE		(4 * 1024)
#define	TNFW_B_FW_ZONE			TNF_DIRECTORY_SIZE

/*
 * Reserved space for tag blocks, after directory area.
 */

#define	TNFW_B_TAG_RESERVE		(28 * 1024)

#define	TNFW_B_DATA_BLOCK_BEGIN		(TNFW_B_FW_ZONE + TNFW_B_TAG_RESERVE)

/*
 * Reserved directory entries, and their precomputed tags.  These are byte
 * offsets from start of file.
 */

#define	TNF_DIRENT_FILE_HEADER	(TNF_BLOCK_SIZE + 0)
#define	TNF_DIRENT_BLOCK_HEADER	(TNF_BLOCK_SIZE	+ 4)
#define	TNF_DIRENT_ROOT		(TNF_BLOCK_SIZE	+ 8)
#define	TNF_DIRENT_LAST		TNF_DIRENT_ROOT

#define	TNF_FILE_HEADER_TAG			\
	(TNF_REF32_MAKE_PERMANENT(TNF_DIRENT_FILE_HEADER) | TNF_REF32_T_TAG)

#define	TNF_BLOCK_HEADER_TAG			\
	(TNF_REF32_MAKE_PERMANENT(TNF_DIRENT_BLOCK_HEADER) | TNF_REF32_T_TAG)

#define	TNF_ROOT_TAG				\
	(TNF_REF32_MAKE_PERMANENT(TNF_DIRENT_ROOT) | TNF_REF32_T_TAG)

/*
 * Allocation type: permanent or reusable
 */

enum tnf_alloc_mode {
	TNF_ALLOC_REUSABLE = 0,
	TNF_ALLOC_FIXED = 1
};

/*
 * Buffer status
 */

typedef enum {
	TNFW_B_RUNNING = 0,
	TNFW_B_NOBUFFER,
	TNFW_B_BROKEN
} TNFW_B_STATE;

/*
 * The STOPPED bit may be or-ed into the state field.
 */
#define	TNFW_B_STOPPED  16
#define	TNFW_B_SET_STOPPED(state)	((state) |= TNFW_B_STOPPED)
#define	TNFW_B_UNSET_STOPPED(state)	((state) &= ~TNFW_B_STOPPED)
#define	TNFW_B_IS_STOPPED(state)	((state) & TNFW_B_STOPPED)

/*
 * Layout of the first block of TNF file (file header)
 */

typedef struct {
	tnf_uint32_t		magic;		/* magic number */
	tnf_file_header_t	com;		/* common header */
	struct {
		volatile ulong_t gen;		/* generation */
		volatile ulong_t block[2];	/* block number */
	} next_alloc;
	ulong_t			next_tag_alloc;	/* block counter */
	ulong_t			next_fw_alloc;	/* byte offset */
	lock_t			lock;		/* protects hint updates */
	/* Padding to end of block */
} tnf_buf_file_header_t;

/*
 * Per-thread write-control information
 */

typedef struct tnfw_b_pos {
	tnf_block_header_t	*tnfw_w_block;
	ushort_t		tnfw_w_write_off;
	uchar_t			tnfw_w_dirty;
} TNFW_B_POS;

typedef struct tnfw_b_wcb {
	struct tnfw_b_pos 	tnfw_w_pos;
	struct tnfw_b_pos 	tnfw_w_tag_pos;
} TNFW_B_WCB;

/*
 * Global tracing state
 */

extern TNFW_B_STATE tnfw_b_state;

/*
 * Global trace buffer
 */

extern caddr_t tnf_buf;

#define	TNF_FILE_HEADER()	((tnf_buf_file_header_t *)tnf_buf)

/*
 * External interface
 */

/*
 * Allocate 'size' data bytes using 'wcb'; store result into 'buf'.
 * This inlines the common trace case.
 */
#define	TNFW_B_ALLOC(wcb, size, buf, typ)			\
{								\
	TNFW_B_POS 		*xx_pos;			\
	ushort_t		xx_off, xx_nof;			\
	tnf_block_header_t	*xx_blk;			\
	size_t			xx_size;			\
								\
	/* Round size up to a multiple of 8. */			\
	xx_size = (size + 7) & ~7;				\
	xx_pos = &(wcb)->tnfw_w_pos;				\
	xx_blk = xx_pos->tnfw_w_block;				\
	xx_off = xx_pos->tnfw_w_write_off;			\
	xx_nof = xx_off + xx_size;				\
	if (xx_blk != NULL && xx_nof <= TNF_BLOCK_SIZE) {	\
		buf = (typ)((char *)xx_blk + xx_off);		\
		xx_pos->tnfw_w_write_off = xx_nof;		\
		/* LINTED */					\
		*((int *)((char *)buf + xx_size - sizeof (int))) = 0;	\
	} else							\
		buf = tnfw_b_alloc((wcb), xx_size, TNF_ALLOC_REUSABLE);\
}

/*
 * Giveback words after new_pos.
 */
#define	TNFW_B_GIVEBACK(wcb, new_pos) 				\
	((wcb)->tnfw_w_pos.tnfw_w_write_off = 			\
	    (((char *)(new_pos)					\
		- (char *)((wcb)->tnfw_w_pos.tnfw_w_block) + 7)	\
		& ~7), *(int *)(new_pos) = 0)

/*
 * Commit transaction bytes allocated via 'pos'
 */
#define	TNFW_B_COMMIT(pos)					\
{								\
	tnf_block_header_t *xx_blk, *xx_nxt;			\
								\
	xx_blk = (pos)->tnfw_w_block;				\
	if (xx_blk != NULL) {					\
		xx_blk->bytes_valid = (pos)->tnfw_w_write_off;	\
		if ((pos)->tnfw_w_dirty) {			\
			xx_nxt = xx_blk->next_block;		\
			while (xx_nxt != NULL) {		\
				xx_blk->next_block = NULL;	\
				xx_blk = xx_nxt;		\
				xx_nxt = xx_blk->next_block;	\
				xx_blk->bytes_valid = TNF_BLOCK_SIZE;\
				lock_clear(&xx_blk->A_lock);	\
			}					\
			(pos)->tnfw_w_dirty = 0;		\
		}						\
	}							\
}

/*
 * Rollback transaction bytes allocated via 'pos'
 */
#define	TNFW_B_ROLLBACK(pos)					\
{								\
	tnf_block_header_t *xx_blk, *xx_nxt;			\
								\
	xx_blk = (pos)->tnfw_w_block;				\
	if (xx_blk != NULL) {					\
		(pos)->tnfw_w_write_off = xx_blk->bytes_valid;	\
		if ((pos)->tnfw_w_dirty) {			\
			xx_nxt = xx_blk->next_block;		\
			while (xx_nxt != NULL) {		\
				xx_blk->next_block = NULL;	\
				xx_blk = xx_nxt;		\
				xx_nxt = xx_blk->next_block;	\
				lock_clear(&xx_blk->A_lock);	\
			}					\
			(pos)->tnfw_w_dirty = 0;		\
		}						\
	}							\
}

extern void tnfw_b_init_buffer(caddr_t, size_t);
extern void *tnfw_b_alloc(TNFW_B_WCB *, size_t, enum tnf_alloc_mode);
extern void *tnfw_b_fw_alloc(TNFW_B_WCB *);

#ifdef __cplusplus
}
#endif

#endif /* _TNF_BUF_H */
