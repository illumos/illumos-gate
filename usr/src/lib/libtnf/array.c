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
 * XXX This module assumes that all arrays are self-sized records.
 */

/*
 *
 */

static struct taginfo *	get_array_info(
	tnf_datum_t,
	struct taginfo **base,
	struct taginfo **elt,
	struct taginfo **elt_base);

/*
 * XXX Assumes arrays are (self-sized) records
 */

void
_tnf_check_array(tnf_datum_t datum)
{
	struct taginfo	*info;

	CHECK_RECORD(datum);		/* XXX */

	info = DATUM_INFO(datum);

	if (!INFO_ARRAY(info))
		_tnf_error(DATUM_TNF(datum), TNF_ERR_TYPEMISMATCH);

}

/*
 * Helper
 */

static struct taginfo *
get_array_info(
	tnf_datum_t datum,
	struct taginfo **basep,
	struct taginfo **eltp,
	struct taginfo **elt_basep)
{
	struct taginfo	*info, *base, *elt, *elt_base;

	info	= DATUM_INFO(datum);
	base	= INFO_DERIVED(info) ? info->base : info;

	if (INFO_DERIVED(base) || (!INFO_ARRAY(base)))
		_tnf_error(DATUM_TNF(datum), TNF_ERR_INTERNAL);

	elt 	= base->base;	/* XXX base slot is reused for elttype */
	elt_base = INFO_DERIVED(elt) ? elt->base : elt;

	*basep	= base;
	*eltp	= elt;
	*elt_basep = elt_base;
	return (info);
}

/*
 * Return number of elements in array
 */

unsigned
tnf_get_element_count(tnf_datum_t datum)
{
	size_t		hdr_size, elt_size, self_size;
	struct taginfo	*base, *elt, *elt_base;

	CHECK_ARRAY(datum);

	(void) get_array_info(datum, &base, &elt, &elt_base);
	hdr_size	= base->hdrsize;
	elt_size	= INFO_ELEMENT_SIZE(elt_base);
	self_size	= _tnf_get_self_size(DATUM_TNF(datum),
		/* LINTED pointer cast may result in improper alignment */
				DATUM_RECORD(datum));
	return (((self_size - hdr_size) / elt_size));
}

/*
 * Fetch indexed element
 */

tnf_datum_t
tnf_get_element(tnf_datum_t datum, unsigned index)
{
	size_t		hdr_size, elt_size, self_size;
	struct taginfo	*base, *elt, *elt_base;
	unsigned	count, offset;

	CHECK_ARRAY(datum);

	(void) get_array_info(datum, &base, &elt, &elt_base);
	hdr_size	= base->hdrsize;
	elt_size	= INFO_ELEMENT_SIZE(elt_base);
	self_size	= _tnf_get_self_size(DATUM_TNF(datum),
		/* LINTED pointer cast may result in improper alignment */
				DATUM_RECORD(datum));

	count		= (self_size - hdr_size) / elt_size;

	if (index >= count)
		_tnf_error(DATUM_TNF(datum), TNF_ERR_BADINDEX);

	offset		= hdr_size + (index * elt_size);

	/*
	 * If tagged, use the tag to construct datum
	 */
	if (INFO_TAGGED(elt)) {
		TNF		*tnf;
		tnf_ref32_t	*rec;

		tnf = DATUM_TNF(datum);
		/* LINTED pointer cast may result in improper alignment */
		rec = _GET_REF32(tnf, (tnf_ref32_t *)
			(DATUM_VAL(datum) + offset));
		/* NULL elements are allowed */
		return ((rec == TNF_NULL)? TNF_DATUM_NULL :
			RECORD_DATUM(tnf, rec));
	} else
		return (DATUM(elt, DATUM_VAL(datum) + offset));
}

/*
 * Return element type of array
 */

tnf_datum_t
tnf_get_element_type(tnf_datum_t datum)
{
	struct taginfo	*base, *elt, *elt_base;

	CHECK_ARRAY(datum);

	(void) get_array_info(datum, &base, &elt, &elt_base);

	return (RECORD_DATUM(DATUM_TNF(datum), elt->tag));
}

/*
 * Return a char pointer for string record
 */

char *
tnf_get_chars(tnf_datum_t datum)
{
	struct taginfo	*info, *base, *elt, *elt_base;

	CHECK_ARRAY(datum);

	info = get_array_info(datum, &base, &elt, &elt_base);

	if (!INFO_STRING(info))
		_tnf_error(DATUM_TNF(datum), TNF_ERR_TYPEMISMATCH);

	return (DATUM_VAL(datum) + base->hdrsize);
}

/*
 * Return the base pointer of array
 */

caddr_t
tnf_get_elements(tnf_datum_t datum)
{
	struct taginfo	*base, *elt, *elt_base;

	CHECK_ARRAY(datum);

	(void) get_array_info(datum, &base, &elt, &elt_base);

	return ((caddr_t)(DATUM_VAL(datum) + base->hdrsize));
}
