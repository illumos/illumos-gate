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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "libtnf.h"

/*
 * Unoptimized versions, always dereference a cell through _GET_INT32()
 *
 */

#define	LONG_SIGN_BIT	0x80000000

static tnf_ref32_t *vaddr_to_phys(TNF *, tnf_ref32_t *, tnf_ref32_t);

/*
 * Return target cell referred to via src_val from src_cell, after
 * checking that target is valid (block was not reused).  Return NULL
 * otherwise.
 *
 * NOTE: We must check if the destination is within the valid_bytes
 * range of its block, so as to correctly handle tnfxtract'ed files:
 * the block containing the target cell may have been copied out
 * before the block containing the source cell.
 */

static tnf_ref32_t *
vaddr_to_phys(TNF *tnf, tnf_ref32_t *src_cell, tnf_ref32_t src_val)
{
	char		*base;
	unsigned	shft, mask;
	tnf_uint32_t	src_gen, dst_gen, exp_gen;
	tnf_int32_t	gen_delta;
	tnf_ref32_t	src_off, exp_off, dst_off, *dst_blk, *dst_cell;
	tnf_uint32_t	bytes_valid;

	base = tnf->file_start;
	shft = tnf->generation_shift;
	mask = tnf->address_mask;

	/* Generation of source cell */
	/* LINTED pointer cast */
	src_gen = _GET_BLOCK_GENERATION(tnf, _GET_BLOCK(tnf, src_cell));
	/* Physical file offset of source cell */
	src_off = (tnf_ref32_t)((char *)src_cell - base);
	/* Expected (unadjusted) file offset of destination cell */
	exp_off = src_off + src_val;
	/* Generation delta */
	gen_delta = (tnf_int32_t)((unsigned)exp_off >> shft);
	if ((exp_off & LONG_SIGN_BIT) == LONG_SIGN_BIT) {
		/* sign bit was a 1 - so restore sign */
		gen_delta |= ((unsigned)mask << (32 - shft));
	}
	/* Expected destination generation */
	exp_gen = src_gen + gen_delta;
	/* Physical file offset of destination cell */
	dst_off = (tnf_ref32_t)((unsigned)exp_off & mask);

	/* Destination cell */
	/* LINTED pointer cast */
	dst_cell = (tnf_ref32_t *)(base + dst_off);
	/* Destination block */
	/* LINTED pointer cast */
	dst_blk = _GET_BLOCK(tnf, dst_cell);
	/* Generation of destination cell */
	/* LINTED pointer cast */
	dst_gen = _GET_BLOCK_GENERATION(tnf, dst_blk);
	/* Bytes valid in destination block */
	/* LINTED pointer cast */
	bytes_valid = _GET_BLOCK_BYTES_VALID(tnf, dst_blk);

	if ((src_gen == (tnf_uint32_t)TNF_TAG_GENERATION_NUM) ||
	    (dst_gen == (tnf_uint32_t)TNF_TAG_GENERATION_NUM) ||
	    ((dst_gen == exp_gen) &&
		((char *)dst_cell - (char *)dst_blk) < bytes_valid))
		return (dst_cell);

	return ((tnf_ref32_t *)NULL);
}

/*
 * Return the target referent of a cell, chasing forwarding references.
 * Return TNF_NULL if cell is a TNF_NULL forwarding reference.
 */

tnf_ref32_t *
_tnf_get_ref32(TNF *tnf, tnf_ref32_t *cell)
{
	tnf_ref32_t 	ref32, reftemp;

	ref32 = _GET_INT32(tnf, cell);

	if (TNF_REF32_IS_NULL(ref32))
		return (TNF_NULL);

	if (TNF_REF32_IS_RSVD(ref32)) {
		_tnf_error(tnf, TNF_ERR_BADREFTYPE);
		return (TNF_NULL);
	}

	if (TNF_REF32_IS_PAIR(ref32)) {
		/* We chase the high (tag) half */
		tnf_ref16_t	tag16;

		tag16 = TNF_REF32_TAG16(ref32);

		if (TNF_TAG16_IS_ABS(tag16)) {
			cell = (tnf_ref32_t *)
				((char *)tnf->file_start
/* LINTED pointer cast may result in improper alignment */
				+ TNF_TAG16_ABS16(tag16));
			ref32 = _GET_INT32(tnf, cell);

		} else if (TNF_TAG16_IS_REL(tag16)) {
			cell = vaddr_to_phys(tnf, cell,
					(tnf_ref32_t) TNF_TAG16_REF16(tag16));
			if (cell == TNF_NULL)
				return (TNF_NULL);
			ref32 = _GET_INT32(tnf, cell);

		} else {
			_tnf_error(tnf, TNF_ERR_BADREFTYPE);
			return (TNF_NULL);
		}

	} else if (TNF_REF32_IS_PERMANENT(ref32)) {
		/* permanent space pointer */
		reftemp = TNF_REF32_VALUE(ref32);
		reftemp = TNF_REF32_SIGN_EXTEND(reftemp);
		/* LINTED pointer cast may result in improper alignment */
		cell = (tnf_ref32_t *) ((char *)tnf->file_start + reftemp);
		ref32 = _GET_INT32(tnf, cell);

	} else {		/* full/tag reclaimable space reference */
		cell = vaddr_to_phys(tnf, cell, TNF_REF32_VALUE(ref32));
		if (cell == TNF_NULL)
			return (TNF_NULL);
		ref32 = _GET_INT32(tnf, cell);
	}

	/* chase intermediate forwarding references */
	while (ref32 && TNF_REF32_IS_FWD(ref32)) {
		if (TNF_REF32_IS_PERMANENT(ref32)) {
			reftemp = TNF_REF32_VALUE(ref32);
			reftemp = TNF_REF32_SIGN_EXTEND(reftemp);
			cell = (tnf_ref32_t *) ((char *)tnf->file_start +
		/* LINTED pointer cast may result in improper alignment */
							reftemp);

		} else {
			cell = vaddr_to_phys(tnf, cell, TNF_REF32_VALUE(ref32));
			if (cell == TNF_NULL)
				return (TNF_NULL);
		}
		ref32 = _GET_INT32(tnf, cell);
	}

	return (cell);
}

/*
 * Return the target referent of ref16 contained in cell.
 * Return TNF_NULL if cell doesn't have a ref16.
 */

tnf_ref32_t *
_tnf_get_ref16(TNF *tnf, tnf_ref32_t *cell)
{
	tnf_ref32_t 	ref32, reftemp;

	ref32 = _GET_INT32(tnf, cell);

	if (TNF_REF32_IS_PAIR(ref32)) {
		tnf_ref16_t	ref16;

		ref16 = TNF_REF32_REF16(ref32);

		if (TNF_REF16_VALUE(ref16) == TNF_NULL)
			/* No ref16 was stored */
			return (TNF_NULL);
		else {
			cell = vaddr_to_phys(tnf, cell,
					(tnf_ref32_t) TNF_REF16_VALUE(ref16));
			if (cell == TNF_NULL)
				return (TNF_NULL);
			ref32 = _GET_INT32(tnf, cell);
		}
	} else			/* not a pair pointer */
		return (TNF_NULL);

	/* chase intermediate forwarding references */
	while (ref32 && TNF_REF32_IS_FWD(ref32)) {
		if (TNF_REF32_IS_PERMANENT(ref32)) {
			reftemp = TNF_REF32_VALUE(ref32);
			reftemp = TNF_REF32_SIGN_EXTEND(reftemp);
			cell = (tnf_ref32_t *) ((char *)tnf->file_start +
		/* LINTED pointer cast may result in improper alignment */
							reftemp);

		} else {
			cell = vaddr_to_phys(tnf, cell, TNF_REF32_VALUE(ref32));
			if (cell == TNF_NULL)
				return (TNF_NULL);
		}
		ref32 = _GET_INT32(tnf, cell);
	}

	return (cell);
}
