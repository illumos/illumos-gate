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

#define	TAG_INDEX(x)	(TNF_TAG16_ABS16(x) / sizeof (tnf_ref32_t))

/*
 *
 */

static struct taginfo *	add_info(TNF *, tnf_ref32_t *);

static struct taginfo *
init_abstract_info(TNF *, tnf_ref32_t *, struct taginfo *);

static struct taginfo *
init_derived_info(TNF *, tnf_ref32_t *, struct taginfo *);

static struct taginfo *
init_scalar_info(TNF *, tnf_ref32_t *, struct taginfo *);

static struct taginfo *
init_struct_info(TNF *, tnf_ref32_t *, struct taginfo *);

static struct taginfo *
init_array_info(TNF *, tnf_ref32_t *, struct taginfo *);

static void init_slots(TNF *, tnf_ref32_t *, struct taginfo *);

/*
 * Allocate tag table and directory
 */

tnf_errcode_t
_tnf_init_tags(TNF *tnf)
{
	if ((tnf->tag_table = calloc(TAGTABCNT, sizeof (struct taginfo *)))
	    == NULL)
		return (TNF_ERR_ALLOCFAIL);
	if ((tnf->tag_directory = calloc(TAGDIRCNT(tnf->directory_size),
						sizeof (struct taginfo *)))
	    == NULL)
		return (TNF_ERR_ALLOCFAIL);
	return (TNF_ERR_NONE);
}

/*
 * Deallocate all taginfos and tables associated with TNF handle
 */

tnf_errcode_t
_tnf_fini_tags(TNF *tnf)
{
	int		i;
	struct taginfo	*info, *link;

	/*
	 * free taginfos
	 */
	for (i = 0; i < TAGTABCNT; i++) {
		info = tnf->tag_table[i];
		while (info) {
			/* remember link */
			link = info->link;
			/* free slot information */
			if (info->slotinfo)
				free(info->slotinfo);
			/* free taginfo */
			free(info);
			/* next in hash chain */
			info = link;
		}
	}
	/*
	 * free the tables
	 */
	free(tnf->tag_table);
	tnf->tag_table = NULL;
	free(tnf->tag_directory);
	tnf->tag_directory = NULL;

	return (TNF_ERR_NONE);
}

/*
 * Get info for supplied tag
 */

struct taginfo *
_tnf_get_info(TNF *tnf, tnf_ref32_t *tag)
{
	struct taginfo	*bucket, *info;

	bucket = tnf->tag_table[TAGHASH(tnf, tag)];
	for (info = bucket; info; info = info->link)
		if (info->tag == tag)
			return (info); /* found it */

	/* default: not there, create */
	return (add_info(tnf, tag));
}

/*
 * Get info for supplied record
 * Use fast lookup, if possible
 */

struct taginfo *
_tnf_record_info(TNF *tnf, tnf_ref32_t *record)
{
	tnf_ref32_t	ref32;
	tnf_ref16_t	tag16;
	tnf_abs16_t	index;
	struct taginfo	*info;

	ref32 = _GET_INT32(tnf, record);

	index = 0;
	if (TNF_REF32_IS_PAIR(ref32)) {
		tag16 = TNF_REF32_TAG16(ref32);
		if (TNF_TAG16_IS_ABS(tag16))
			index = TAG_INDEX(tag16);
	}

	if (index) {
		if ((info = tnf->tag_directory[index]) != NULL)
			return (info);
		else {		/* not in directory yet */
			info = _tnf_get_info(tnf, _tnf_get_tag(tnf, record));
			/* enter into tag directory */
			return ((tnf->tag_directory[index] = info));
		}
	}

	/* default: not referenced via index */
	return (_tnf_get_info(tnf, _tnf_get_tag(tnf, record)));
}

/*
 * Add a new taginfo for tag
 */

static struct taginfo *
add_info(TNF *tnf, tnf_ref32_t *tag)
{
	struct taginfo 	*info, *bucket;
	unsigned	hash;
	tnf_ref32_t	*meta;

	info = (struct taginfo *)calloc(1, sizeof (struct taginfo));

	/* Initialize members */
	info->tnf 	= tnf;
	info->tag 	= tag;
	info->name	= _tnf_get_name(tnf, tag);
	info->props	= _tnf_get_props(tnf, tag);
	info->kind	= _tnf_get_kind(tnf, tag);
	info->size	= _tnf_get_storage_size(tnf, tag);
	info->align	= _tnf_get_align(tnf, tag);

	/* Add it to table */
	hash 		= TAGHASH(tnf, tag);
	bucket 		= tnf->tag_table[hash];
	info->link 	= bucket;
	tnf->tag_table[hash] = info;

	/* Ensure meta info is available */
	meta		= _tnf_get_tag(tnf, tag);
	info->meta	= _tnf_get_info(tnf, meta);

	/*
	 * Initialize info
	 * Derived must be first clause due to property inheritance
	 */

	if (INFO_DERIVED(info))
		return (init_derived_info(tnf, tag, info));
	else if (INFO_STRUCT(info))
		return (init_struct_info(tnf, tag, info));
	else if (INFO_ARRAY(info))
		return (init_array_info(tnf, tag, info));
	else if (INFO_SCALAR(info))
		return (init_scalar_info(tnf, tag, info));
	else			/* XXX assume abstract type */
		return (init_abstract_info(tnf, tag, info));
}


/*
 * Initialize info for an abstract tag
 */

static struct taginfo *
/* ARGSUSED */
init_abstract_info(TNF *tnf, tnf_ref32_t *tag, struct taginfo *info)
{
	if (INFO_SCALAR(info) || INFO_DERIVED(info) ||
	    INFO_STRUCT(info) || INFO_ARRAY(info))
		_tnf_error(tnf, TNF_ERR_INTERNAL);
	if (info->size == (size_t)-1)
		_tnf_error(tnf, TNF_ERR_BADTNF);
	return (info);
}

/*
 * Initialize info for a derived tag
 */

static struct taginfo *
init_derived_info(TNF *tnf, tnf_ref32_t *tag, struct taginfo *info)
{
	tnf_ref32_t	*base_tag;

	if (!INFO_DERIVED(info))
		_tnf_error(tnf, TNF_ERR_INTERNAL);

	/* Ensure ultimate base information is available */
	base_tag 	= _tnf_get_base_tag(tnf, tag);
	info->base 	= _tnf_get_info(tnf, base_tag);

	return (info);
}

/*
 * Initialize info for a scalar tag
 */

static struct taginfo *
/* ARGSUSED */
init_scalar_info(TNF *tnf, tnf_ref32_t *tag, struct taginfo *info)
{
	if ((!INFO_SCALAR(info)) ||
	    (INFO_DERIVED(info) || INFO_ARRAY(info) || INFO_STRUCT(info)))
		_tnf_error(tnf, TNF_ERR_INTERNAL);
	if (info->size == (size_t)-1)
		_tnf_error(tnf, TNF_ERR_BADTNF);

	/* XXX alignment already done */

	return (info);
}

/*
 * Initialize info for a struct tag
 */

static struct taginfo *
init_struct_info(TNF *tnf, tnf_ref32_t *tag, struct taginfo *info)
{
	if ((!INFO_STRUCT(info)) ||
	    (INFO_DERIVED(info) || INFO_ARRAY(info) || INFO_SCALAR(info)))
		_tnf_error(tnf, TNF_ERR_INTERNAL);
	if (info->size == (size_t)-1)
		_tnf_error(tnf, TNF_ERR_BADTNF);

	/* Get slot information */
	init_slots(tnf, tag, info);

	return (info);
}

/*
 * Initialize info for an array tag
 */

static struct taginfo *
init_array_info(TNF *tnf, tnf_ref32_t *tag, struct taginfo *info)
{
	tnf_ref32_t	*elt_tag;
	int		defeat;

	if ((!INFO_ARRAY(info)) ||
	    (INFO_DERIVED(info) || INFO_STRUCT(info) || INFO_SCALAR(info)))
		_tnf_error(tnf, TNF_ERR_INTERNAL);

	/* XXX special-case abstract array tag */
	defeat = (strcmp(info->name, TNF_N_ARRAY) == 0);

	/* Require all arrays to be self-sized records */
	if (!(INFO_TAGGED(info) && (info->size == (size_t)-1)))
		if (!defeat)
			_tnf_error(tnf, TNF_ERR_BADTNF);

	/* Store array header size */
	info->hdrsize = _tnf_get_header_size(tnf, tag);
	/* XXX Temporary sanity check */
	if (info->hdrsize != sizeof (struct tnf_array_hdr))
		if (!defeat)
			_tnf_error(tnf, TNF_ERR_BADTNF);

	/* Get slot information */
	init_slots(tnf, tag, info);

	/* Get info for element type */
	elt_tag = (tnf_ref32_t *)_tnf_get_slot_typed(tnf, tag,
		/* LINTED pointer cast may result in improper alignment */
						    TNF_N_ELEMENT_TYPE);
	/* XXX tnf_array has element_type == NULL */
	info->base = elt_tag ? _tnf_get_info(tnf, elt_tag): NULL;

	return (info);
}

/*
 * Initialize slot information for aggregate tag
 */

static void
init_slots(TNF *tnf, tnf_ref32_t *tag, struct taginfo *info)
{
	tnf_ref32_t	*slot_types, *slot_names;
	tnf_ref32_t	*types, *names;
	unsigned	count, i, offset;
	struct slotinfo	*slotinfo;

	slot_types = (tnf_ref32_t *)
		/* LINTED pointer cast may result in improper alignment */
		_tnf_get_slot_typed(tnf, tag, TNF_N_SLOT_TYPES);
	slot_names = (tnf_ref32_t *)
		/* LINTED pointer cast may result in improper alignment */
		_tnf_get_slot_typed(tnf, tag, TNF_N_SLOT_NAMES);

	/* abstract tags have no slots */
	if (slot_types == TNF_NULL)
		return;

	count = _tnf_get_element_count(tnf, slot_types, sizeof (tnf_ref32_t));
	/* LINTED pointer cast may result in improper alignment */
	types = (tnf_ref32_t *)_tnf_get_elements(tnf, slot_types);
	names = ((slot_names == TNF_NULL) ? TNF_NULL :
		/* LINTED pointer cast may result in improper alignment */
			(tnf_ref32_t *)_tnf_get_elements(tnf, slot_names));

	slotinfo = (struct slotinfo *)
		calloc(1, sizeof (unsigned) + (count * sizeof (struct slot)));
	if (slotinfo == (struct slotinfo *)NULL)
		_tnf_error(tnf, TNF_ERR_ALLOCFAIL);

	slotinfo->slot_count = count;
	offset 	= 0;

	for (i = 0; i < count; i++) {
		tnf_ref32_t	*type_elt, *name_elt;
		struct taginfo	*elt_info;
		size_t		ref_size, align;

		/* XXX No checks here for missing tags */
		type_elt = _GET_REF32(tnf, &types[i]);
		name_elt = names ? _GET_REF32(tnf, &names[i]) : TNF_NULL;

		/* Resolve slot tag into taginfo */
		elt_info = _tnf_get_info(tnf, type_elt);
		slotinfo->slots[i].slot_type = elt_info;
		slotinfo->slots[i].slot_name =
			((name_elt != TNF_NULL) ?
				_tnf_get_chars(tnf, name_elt) :
				_tnf_get_name(tnf, type_elt));

		/* Get cached reference size */
		ref_size = INFO_REF_SIZE(elt_info);

		/* Get cached alignment */
		align = INFO_ALIGN(elt_info); /* XXX */

		/* Adjust offset to account for alignment, if needed */
		offset = ALIGN(offset, align);

		slotinfo->slots[i].slot_offset = offset;

		/* Bump offset by reference size */
		offset += ref_size;
	}

	info->slotinfo = slotinfo;
}
