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
 * Operations based on ABI bootstrap assumptions
 */

#define	_GET_TAG(tnf, p)		\
	_GET_REF32(tnf, p)

#define	_GET_TAG_ARG(tnf, p)		\
	_GET_REF16(tnf, p)

#define	_GET_SELF_SIZE(tnf, p) 		\
	_GET_UINT32(tnf, &((struct tnf_array_hdr *)(p))->self_size)

#define	_GET_NAME(tnf, p)		\
	_GET_REF32(tnf, &((struct tnf_type_hdr *)(p))->name)

#define	_GET_PROPERTIES(tnf, p)		\
	_GET_REF32(tnf, &((struct tnf_type_hdr *)(p))->properties)

#define	_GET_SLOT_TYPES(tnf, p)		\
	_GET_REF32(tnf, &((struct tnf_struct_type_hdr *)(p))->slot_types)

#define	_GET_TYPE_SIZE(tnf, p)		\
	_GET_UINT32(tnf, &((struct tnf_struct_type_hdr *)(p))->type_size)

#define	_GET_HEADER_SIZE(tnf, p)	\
	_GET_UINT32(tnf, &((struct tnf_array_type_hdr *)(p))->header_size)

#define	_GET_DERIVED_BASE(tnf, p)	\
	_GET_REF32(tnf, &((struct tnf_derived_type_hdr *)(p))->derived_base)

/*
 * Static declarations
 */

static caddr_t	fetch_slot(TNF *, caddr_t, tnf_ref32_t *);

/*
 * retrieve tag slot from a record
 */

tnf_ref32_t *
_tnf_get_tag(TNF *tnf, tnf_ref32_t *record)
{
	return (_GET_TAG(tnf, record));
}

/*
 * Retrieve tag_arg from tag slot of a record
 */

tnf_ref32_t *
_tnf_get_tag_arg(TNF *tnf, tnf_ref32_t *record)
{
	return (_GET_TAG_ARG(tnf, record));
}

/*
 * Retrieve the self_size slot of an ABI array record
 */

size_t
_tnf_get_self_size(TNF *tnf, tnf_ref32_t *array)
{
	return (_GET_SELF_SIZE(tnf, array));
}

/*
 * Calculate the number of elements in ABI array record
 */

unsigned
_tnf_get_element_count(TNF *tnf, tnf_ref32_t *array, unsigned eltsize)
{
	size_t		size, hdrsize;
#ifdef INFINITE_RECURSION_ARRAY
	tnf_ref32_t	*base_tag;

	size 		= _tnf_get_self_size(tnf, array);
	base_tag 	= _tnf_get_base_tag(tnf, _tnf_get_tag(tnf, array));
	hdrsize		= _tnf_get_header_size(tnf, base_tag);
	return (((size - hdrsize) / eltsize));
#else
	size 		= _tnf_get_self_size(tnf, array);
	hdrsize		= sizeof (struct tnf_array_hdr);
	return (((size - hdrsize) / eltsize));
#endif
}

/*
 * Retrieve the base pointer of an ABI array record
 */

caddr_t
/* ARGSUSED */
_tnf_get_elements(TNF *tnf, tnf_ref32_t *array)
{
#ifdef INFINITE_RECURSION_ARRAY
	size_t		hdrsize;
	tnf_ref32_t	*base_tag;

	base_tag	= _tnf_get_base_tag(tnf, _tnf_get_tag(tnf, array));
	hdrsize		= _tnf_get_header_size(tnf, base_tag);
	return ((caddr_t)((char *)array + hdrsize));
#else
	return ((caddr_t)((char *)array + sizeof (struct tnf_array_hdr)));
#endif
}

/*
 * Retrieve the chars in an ABI string record
 */

char *
_tnf_get_chars(TNF *tnf, tnf_ref32_t *string)
{
	return ((char *)_tnf_get_elements(tnf, string));
}

/*
 * Retrieve the string in the name slot of a type record
 */

char *
_tnf_get_name(TNF *tnf, tnf_ref32_t *tag)
{
	return (_tnf_get_chars(tnf, _GET_NAME(tnf, tag)));
}

/*
 * Retrieve the properties array slot of a type record
 */

tnf_ref32_t *
_tnf_get_properties(TNF *tnf, tnf_ref32_t *tag)
{
	return (_GET_PROPERTIES(tnf, tag));
}

/*
 * Retrieve the slot_types slot of struct_type or array_type record
 */

tnf_ref32_t *
_tnf_get_slot_types(TNF *tnf, tnf_ref32_t *tag)
{
	return (_GET_SLOT_TYPES(tnf, tag));
}

/*
 * Retrieve the header_size slot of an array_type record
 */

size_t
_tnf_get_header_size(TNF *tnf, tnf_ref32_t *tag)
{
	return (_GET_HEADER_SIZE(tnf, tag));
}

/*
 * Retrieve the derived_base slot of a derived_type record
 */

tnf_ref32_t *
_tnf_get_derived_base(TNF *tnf, tnf_ref32_t *tag)
{
	return (_GET_DERIVED_BASE(tnf, tag));
}


/*
 * Find the root (self-tagged) type record
 */

tnf_ref32_t *
_tnf_get_root_tag(TNF *tnf, tnf_ref32_t *record)
{
	if (tnf->root_tag)
		return (tnf->root_tag);
	else {
		tnf_ref32_t	*p1, *p2;
		p1 = record;
		while ((p2 = _tnf_get_tag(tnf, p1)) != p1)
			p1 = p2;
		tnf->root_tag = p2;
		return (p2);
	}
}

/*
 * Search ABI type array for a type named name
 */

tnf_ref32_t *
_tnf_get_element_named(TNF *tnf, tnf_ref32_t *array, char *name)
{
	unsigned	count, i;
	tnf_ref32_t	*elts;

	count 	= _tnf_get_element_count(tnf, array, sizeof (tnf_ref32_t));
	/* LINTED pointer cast may result in improper alignment */
	elts	= (tnf_ref32_t *)_tnf_get_elements(tnf, array);

	for (i = 0; i < count; i++) {
		tnf_ref32_t	*type_elt;

		if ((type_elt = _GET_REF32(tnf, &elts[i])) == TNF_NULL) {
			/* Can't have missing type records */
			_tnf_error(tnf, TNF_ERR_BADTNF);
			return (TNF_NULL);
		}

		if (strcmp(name, _tnf_get_name(tnf, type_elt)) == 0)
			/* Found a type record named name */
			return (type_elt);
	}
	return (TNF_NULL);
}

/*
 * Look in type record's properties for named type.
 * Recursively look at derived_base properties as well.
 */

tnf_ref32_t *
_tnf_get_property(TNF *tnf, tnf_ref32_t *tag, char *name)
{
	tnf_ref32_t	*properties, *property;

	if (strcmp(name, _tnf_get_name(tnf, tag)) == 0)
		/* name is type name */
		return (tag);

	if ((properties = _tnf_get_properties(tnf, tag)) == TNF_NULL)
		/* no properties */
		return (TNF_NULL);

	if ((property = _tnf_get_element_named(tnf, properties, name))
	    != TNF_NULL)
		/* found property named name */
		return (property);

	/*
	 * Recursively check base type of derived types
	 */
	if (_tnf_get_element_named(tnf, properties, TNF_N_DERIVED)
	    != TNF_NULL) {
		/* tag is a derived type: check its derived_base */
		tnf_ref32_t	*base_tag;

		base_tag = _tnf_get_derived_base(tnf, tag);
		/* tnf_derived has derived_base == TNF_NULL */
		if (base_tag != TNF_NULL)
			return (_tnf_get_property(tnf, base_tag, name));
	}

	return (TNF_NULL);
}

/*
 * Get the ultimate base type of a type record
 */

tnf_ref32_t *
_tnf_get_base_tag(TNF *tnf, tnf_ref32_t *tag)
{
	tnf_ref32_t	*properties;

	if ((properties = _tnf_get_properties(tnf, tag)) == TNF_NULL)
		/* no properties */
		return (tag);

	if (_tnf_get_element_named(tnf, properties, TNF_N_DERIVED)
	    != TNF_NULL) {
		tnf_ref32_t	*base_tag;

		if ((base_tag = _tnf_get_derived_base(tnf, tag)) != TNF_NULL)
			return (_tnf_get_base_tag(tnf, base_tag));
	}

	return (tag);
}

/*
 * Calculate the reference size of an object with type==tag
 */

size_t
_tnf_get_ref_size(TNF *tnf, tnf_ref32_t *tag)
{
	if (HAS_PROPERTY(tnf, tag, TNF_N_TAGGED)) {
		/* Tagged objects occupy 4 bytes for reference */
		return ((sizeof (tnf_ref32_t)));
	} else if (HAS_PROPERTY(tnf, tag, TNF_N_INLINE)) {
		/* Inline slots cannot be self sized */
		return (_tnf_get_storage_size(tnf, tag));
	} else {
		/* Illegal to have references to abstract objects */
		_tnf_error(tnf, TNF_ERR_BADTNF);
		return ((0));
	}
}

/*
 * Calculate storage size of an object with type==tag
 */

size_t
_tnf_get_storage_size(TNF *tnf, tnf_ref32_t *tag)
{
	if (_tnf_get_tag(tnf, tag) == _tnf_get_root_tag(tnf, tag))
		return (_GET_TYPE_SIZE(tnf, tag));
	else {
		tnf_ref32_t	*base_tag; /* implementation tag */
		caddr_t		sizep;
		tnf_ref32_t	*slot_types;

#ifndef INFINITE_RECURSION_SIZE
		char		*base_name;
		static struct n2s {
			char	*name;
			size_t	size;
		} n2s[] = {
		{ TNF_N_CHAR, 		sizeof (tnf_char_t) },
		{ TNF_N_INT8,		sizeof (tnf_int8_t) },
		{ TNF_N_INT16,		sizeof (tnf_int16_t) },
		{ TNF_N_INT32,		sizeof (tnf_int32_t) },
		{ TNF_N_UINT8,		sizeof (tnf_uint8_t) },
		{ TNF_N_UINT16,		sizeof (tnf_uint16_t) },
		{ TNF_N_UINT32,		sizeof (tnf_uint32_t) },
		{ TNF_N_INT64,		sizeof (tnf_int64_t) },
		{ TNF_N_UINT64,		sizeof (tnf_uint64_t) },
		{ TNF_N_FLOAT32,	sizeof (tnf_float32_t) },
		{ TNF_N_FLOAT64,	sizeof (tnf_float64_t) },
		{ NULL,			0 }
		};
		struct n2s	*p;
#endif

		base_tag 	= _tnf_get_base_tag(tnf, tag);

#ifndef INFINITE_RECURSION_SIZE
		base_name 	= _tnf_get_name(tnf, base_tag);

		/* XXX Why are we in this mess? */
		p = n2s;
		while (p->name) {
			if (strcmp(p->name, base_name) == 0)
				return (p->size);
			p++;
		}
#endif

		sizep = _tnf_get_slot_typed(tnf, base_tag, TNF_N_TYPE_SIZE);
		if (sizep)
			/* Type sized */
		/* LINTED pointer cast may result in improper alignment */
			return (_GET_UINT32(tnf, (tnf_uint32_t *)sizep));

		slot_types = (tnf_ref32_t *)
		/* LINTED pointer cast may result in improper alignment */
		    _tnf_get_slot_typed(tnf, base_tag, TNF_N_SLOT_TYPES);
		if (slot_types &&
		    _tnf_get_element_named(tnf, slot_types, TNF_N_SELF_SIZE))
			/* Self sized */
			return ((size_t)-1);
		else
			/* Abstract */
			return (0);
	}
}

/*
 * Return the alignment restriction for any tag
 */

unsigned
_tnf_get_align(TNF *tnf, tnf_ref32_t *tag)
{
	if (HAS_PROPERTY(tnf, tag, TNF_N_SCALAR)) {
		tnf_ref32_t	*base_tag;
		caddr_t		alignp;

		base_tag = _tnf_get_base_tag(tnf, tag);
		alignp   = _tnf_get_slot_typed(tnf, base_tag, TNF_N_ALIGN);
		if (alignp)
		/* LINTED pointer cast may result in improper alignment */
			return (_GET_UINT32(tnf, (tnf_uint32_t *)alignp));
	}
	/* default: word alignment */
	return ((4));
}

/*
 * Only works for records
 * Doesn't check for slot_names in tag
 * Tag records, for example, never have named slots
 */

caddr_t
_tnf_get_slot_typed(TNF *tnf, tnf_ref32_t *record, char *name)
{
	tnf_ref32_t 	*tag, *base_tag;
	tnf_ref32_t	*slot_types, *types;
	unsigned	count, i;
	unsigned 	offset;

	tag 		= _tnf_get_tag(tnf, record);
	base_tag 	= _tnf_get_base_tag(tnf, tag);

	/*
	 * The position of slot_types is ABI fixed
	 * XXX Assume it is present in tag
	 */
	slot_types = _tnf_get_slot_types(tnf, base_tag);
	count = _tnf_get_element_count(tnf, slot_types, sizeof (tnf_ref32_t));
	/* LINTED pointer cast may result in improper alignment */
	types = (tnf_ref32_t *)_tnf_get_elements(tnf, slot_types);

	offset 	= 0;

	for (i = 0; i < count; i++) {
		tnf_ref32_t	*type_elt;
		size_t		ref_size, align;

		/* Find the type record for slot */
		if ((type_elt = _GET_REF32(tnf, &types[i])) == TNF_NULL) {
			/* Can't have missing type records */
			_tnf_error(tnf, TNF_ERR_BADTNF);
			return ((caddr_t)NULL);
		}

		/* See similar hack in init_slots() */

		/* Calculate reference size */
		ref_size = _tnf_get_ref_size(tnf, type_elt);

		/*
		 * Calculate alignment
		 * XXX Prevent infinite recursion by assuming that
		 * a reference size of 4 implies word alignment
		 */
		align = (ref_size == 4)? 4: _tnf_get_align(tnf, type_elt);

		/* Adjust offset to account for alignment, if needed */
		offset = ALIGN(offset, align);

		/* Check whether name corresponds to type name */
		if (strcmp(name, _tnf_get_name(tnf, type_elt)) == 0)
			/* Found the slot */
			return (fetch_slot(tnf, (caddr_t)record + offset,
					type_elt));

		/* Bump offset by reference size */
		offset += ref_size;
	}

	return ((caddr_t)NULL);
}

/*
 * Only works for records
 */

caddr_t
_tnf_get_slot_named(TNF *tnf, tnf_ref32_t *record, char *name)
{
	tnf_ref32_t 	*tag, *base_tag;
	tnf_ref32_t	*slot_types, *slot_names, *types, *names;
	unsigned	count, i;
	unsigned 	offset;

	tag 		= _tnf_get_tag(tnf, record);
	base_tag 	= _tnf_get_base_tag(tnf, tag);

	/*
	 * slot_names are optional
	 */
	slot_names = (tnf_ref32_t *)
		/* LINTED pointer cast may result in improper alignment */
	    _tnf_get_slot_typed(tnf, base_tag, TNF_N_SLOT_NAMES);

	/* no slot_names; use _tnf_get_slot_typed() */
	if (slot_names == TNF_NULL)
		return (_tnf_get_slot_typed(tnf, record, name));

	/*
	 * The position of slot_types is ABI fixed
	 * XXX Assume it is present in tag
	 */
	slot_types = _tnf_get_slot_types(tnf, base_tag);
	count = _tnf_get_element_count(tnf, slot_types, sizeof (tnf_ref32_t));
	/* LINTED pointer cast may result in improper alignment */
	types = (tnf_ref32_t *)_tnf_get_elements(tnf, slot_types);
	/* LINTED pointer cast may result in improper alignment */
	names = (tnf_ref32_t *)_tnf_get_elements(tnf, slot_names);

	offset 	= 0;

	for (i = 0; i < count; i++) {
		tnf_ref32_t	*type_elt, *name_elt;
		size_t		ref_size, align;

		/* Find the type record for slot */
		if ((type_elt = _GET_REF32(tnf, &types[i])) == TNF_NULL) {
			/* Can't have missing type records */
			_tnf_error(tnf, TNF_ERR_BADTNF);
			return ((caddr_t)NULL);
		}

		/* XXX Keep consistent with init_slots() */

		/* Calculate reference size */
		ref_size = _tnf_get_ref_size(tnf, type_elt);

		/*
		 * Calculate alignment
		 * XXX Prevent infinite recursion by assuming that
		 * a reference size of 4 implies word alignment
		 */
		align = (ref_size == 4)? 4: _tnf_get_align(tnf, type_elt);

		/* Adjust offset to account for alignment, if needed */
		offset = ALIGN(offset, align);

		/* First check slot name, then type name */
		if ((((name_elt = _GET_REF32(tnf, &names[i])) != TNF_NULL) &&
			(strcmp(name, _tnf_get_chars(tnf, name_elt)) == 0)) ||
			(strcmp(name, _tnf_get_name(tnf, type_elt)) == 0))
			/* Found slot */
			return (fetch_slot(tnf, (caddr_t)record + offset,
				    type_elt));

		/* Bump offset by reference size */
		offset += ref_size;
	}

	return ((caddr_t)NULL);
}

static caddr_t
fetch_slot(TNF *tnf, caddr_t p, tnf_ref32_t *tag)
{
	if (HAS_PROPERTY(tnf, tag, TNF_N_INLINE))
		return (p);
	else			/* XXX assume tagged */
		/* LINTED pointer cast may result in improper alignment */
		return ((caddr_t)_GET_REF32(tnf, (tnf_ref32_t *)p));
}
