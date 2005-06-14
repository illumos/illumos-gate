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
 * File header operations
 */

tnf_datum_t
tnf_get_file_header(TNF *tnf)
{
	return (DATUM(tnf->file_header_info, (caddr_t)tnf->file_header));
}

/*
 * Block access operations
 */

unsigned
tnf_get_block_count(TNF *tnf)
{
	return (tnf->block_count);
}

tnf_datum_t
tnf_get_block_absolute(TNF *tnf, unsigned index)
{
	if (index >= tnf->block_count)
		/*
		 * access to non-existent block:
		 * no error as per spec
		 */
		return (TNF_DATUM_NULL);
	else
		/*
		 * XXX Require a single block header tag
		 */
		/* LINTED pointer cast may result in improper alignment */
		return (DATUM(tnf->block_header_info,
			    (caddr_t)_GET_INDEX_BLOCK(tnf, index)));
}

tnf_datum_t
tnf_get_block_relative(tnf_datum_t datum, int adjust)
{
	TNF		*tnf;
	tnf_ref32_t	*bhdr;
	unsigned	index;

	CHECK_DATUM(datum);

	tnf 	= DATUM_TNF(datum);
	bhdr 	= _GET_BLOCK(tnf, DATUM_VAL(datum));
	index	= _GET_BLOCK_INDEX(tnf, bhdr);

	return (tnf_get_block_absolute(tnf, index + adjust));
}

int
tnf_is_block_header(tnf_datum_t datum)
{
	struct taginfo	*info;
	caddr_t		val;
	tnf_ref32_t	*bhdr;

	CHECK_DATUM(datum);

	info	= DATUM_INFO(datum);
	val	= DATUM_VAL(datum);
	bhdr	= _GET_BLOCK(info->tnf, val);

	return (((caddr_t)bhdr == val) &&
		(info == info->tnf->block_header_info));
}

tnf_datum_t
tnf_get_block_header(tnf_datum_t datum)
{
	TNF	*tnf;
	caddr_t	val;

	CHECK_DATUM(datum);

	tnf 	= DATUM_TNF(datum);
	val	= DATUM_VAL(datum);
	/*
	 * XXX Require a single block header tag
	 */
	return (DATUM(tnf->block_header_info, (caddr_t)_GET_BLOCK(tnf, val)));
}

/*
 * Sequential record access
 */

tnf_datum_t
tnf_get_next_record(tnf_datum_t datum)
{
	TNF		*tnf;
	tnf_ref32_t	*bhdr, *cell, ref32;
	caddr_t		val, nval, bval, blim;
	size_t		size, bytes;

	CHECK_RECORD(datum);

	tnf	= DATUM_TNF(datum);
	val	= DATUM_VAL(datum);

	size	= tnf_get_size(datum);
	nval	= val + size;

	/* Check file bounds */
	if (nval < tnf->data_start)
		return (tnf_get_block_absolute(tnf, 0));
	else if (nval >= tnf->file_end)
		return (TNF_DATUM_NULL);

	/*
	 * OK, nval is in data area, start looking in block
	 */
	bhdr 	= _GET_BLOCK(tnf, nval);
	/* LINTED pointer cast may result in improper alignment */
	bytes	= _GET_BLOCK_BYTES_VALID(tnf, bhdr);
	bval 	= (caddr_t)bhdr;
	blim  	= bval + bytes;

	/* sequentially examine valid cells in block from nval onwards */
	while (nval < blim) {
		/* LINTED pointer cast may result in improper alignment */
		cell 	= (tnf_ref32_t *)nval;
		ref32 	= _GET_INT32(tnf, cell);

		switch (TNF_REF32_TYPE(ref32)) {
		case TNF_REF32_T_FWD: /* skip forwarding cells */
			nval += sizeof (tnf_ref32_t);
			break;
		case TNF_REF32_T_RSVD: /* catch bogus cells */
			_tnf_error(tnf, TNF_ERR_BADTNF);
			return (TNF_DATUM_NULL);
		default:	/* PAIR or TAG: record header */
			return (RECORD_DATUM(tnf, cell));
		}
	}

	/*
	 * Couldn't find it: return next non-zero block header
	 */
	while ((bval += tnf->block_size) < tnf->file_end)
		/* Gotta check that there is a real bhdr here */
		/* LINTED pointer cast may result in improper alignment */
		if (*(tnf_ref32_t *)bval != TNF_NULL)
		/* LINTED pointer cast may result in improper alignment */
			return (RECORD_DATUM(tnf, (tnf_ref32_t *)bval));

	/*
	 * default: we're off the end of the file
	 */
	return (TNF_DATUM_NULL);
}
