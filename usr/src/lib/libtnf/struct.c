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
 *
 */

static struct slotinfo *get_slotinfo(tnf_datum_t);
static struct slot *	get_slot_named(struct slotinfo *, char *);
static struct slot *	get_slot_indexed(struct slotinfo *, unsigned);
static tnf_datum_t	get_slot(tnf_datum_t, struct slot *);

/*
 *
 */

void
_tnf_check_slots(tnf_datum_t datum)
{
	struct taginfo	*info;

	CHECK_DATUM(datum);

	info = DATUM_INFO(datum);

	/* Must be an aggregate */
	if (!(INFO_STRUCT(info) || INFO_ARRAY(info)))
		_tnf_error(DATUM_TNF(datum), TNF_ERR_TYPEMISMATCH);
}

/*
 * Helpers
 */

static struct slotinfo *
get_slotinfo(tnf_datum_t datum)
{
	struct taginfo	*info, *base_info;

	info 		= DATUM_INFO(datum);
	base_info	= INFO_DERIVED(info)? info->base: info;

	/* XXX base must not be a scalar tag */
	if (INFO_SCALAR(base_info))
		_tnf_error(DATUM_TNF(datum), TNF_ERR_BADTNF);

	return (base_info->slotinfo);
}

static struct slot *
get_slot_indexed(struct slotinfo *slotinfo, unsigned index)
{
	unsigned 	count;

	count 		= slotinfo->slot_count;
	if (index >= count)
		return (NULL);
	else
		return (&slotinfo->slots[index]);
}

static struct slot *
get_slot_named(struct slotinfo *slotinfo, char *name)
{
	unsigned 	count, i;

	count 		= slotinfo->slot_count;

	for (i = 0; i < count; i++)
		if (strcmp(name, slotinfo->slots[i].slot_name) == 0)
			return (&slotinfo->slots[i]);

	return (NULL);
}

static tnf_datum_t
get_slot(tnf_datum_t datum, struct slot *slot)
{
	if (slot == NULL) {
		_tnf_error(DATUM_TNF(datum), TNF_ERR_BADSLOT); /* XXX */
		return (TNF_DATUM_NULL);

	} else if (INFO_TAGGED(slot->slot_type)) {
		TNF		*tnf;
		tnf_ref32_t	*rec;

		tnf = DATUM_TNF(datum);
		/* LINTED pointer cast may result in improper alignment */
		rec = _GET_REF32(tnf, (tnf_ref32_t *)
			(DATUM_VAL(datum) + slot->slot_offset));
		/* NULL slots are allowed */
		return ((rec == TNF_NULL)? TNF_DATUM_NULL :
			RECORD_DATUM(tnf, rec));

	} else			/* inline */
		return DATUM(slot->slot_type,
			DATUM_VAL(datum) + slot->slot_offset);
}

/*
 *
 */

unsigned
tnf_get_slot_count(tnf_datum_t datum)
{
	struct slotinfo	*slotinfo;

	CHECK_SLOTS(datum);

	slotinfo = get_slotinfo(datum);
	return (slotinfo->slot_count);
}

/*
 *
 */

unsigned
tnf_get_slot_index(tnf_datum_t datum, char *name)
{
	struct slotinfo	*slotinfo;
	struct slot	*slot;

	CHECK_SLOTS(datum);

	slotinfo = get_slotinfo(datum);
	slot	 = get_slot_named(slotinfo, name);

	if (slot == NULL) {
		_tnf_error(DATUM_TNF(datum), TNF_ERR_BADSLOT); /* XXX */
		return (((unsigned)-1));
	} else
		return (((char *)slot - (char *)&slotinfo->slots[0])
			/ sizeof (struct slot));
}

/*
 *
 */

char *
tnf_get_slot_name(tnf_datum_t datum, unsigned index)
{
	struct slotinfo	*slotinfo;
	struct slot	*slot;

	CHECK_SLOTS(datum);

	slotinfo 	= get_slotinfo(datum);
	slot		= get_slot_indexed(slotinfo, index);

	if (slot == NULL) {
		_tnf_error(DATUM_TNF(datum), TNF_ERR_BADSLOT); /* XXX */
		return ((char *)NULL);
	} else
		return (slot->slot_name);
}

/*
 *
 */

tnf_datum_t
tnf_get_slot_named(tnf_datum_t datum, char *name)
{
	struct slotinfo	*slotinfo;
	struct slot	*slot;

	CHECK_SLOTS(datum);

	slotinfo 	= get_slotinfo(datum);
	slot		= get_slot_named(slotinfo, name);

	return (get_slot(datum, slot));
}

/*
 *
 */

tnf_datum_t
tnf_get_slot_indexed(tnf_datum_t datum, unsigned index)
{
	struct slotinfo	*slotinfo;
	struct slot	*slot;

	CHECK_SLOTS(datum);

	slotinfo 	= get_slotinfo(datum);
	slot		= get_slot_indexed(slotinfo, index);

	return (get_slot(datum, slot));
}
