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
 *	Copyright (c) 1994,1998 by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#ifndef	_TNF_TYPES_H
#define	_TNF_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/tnf_com.h>
#include <sys/tnf_writer.h>
#include <sys/tnf_probe.h>
#include "tnf_buf.h"
#else  /* _KERNEL */
#include <tnf/com.h>
#include <tnf/writer.h>
#include <tnf/probe.h>
#endif /* _KERNEL */

#ifdef	__cplusplus
extern "C" {
#endif

extern struct tnf_probe_version __tnf_probe_version_1_info;

/*
 * Defines
 */

#define	TAG_DATA(type)		type##_tag_data
#define	_TAG_DATA(type)		_##type##_tag_data

#define	TAG_SNAP(type)		TAG_DATA(type) = &_TAG_DATA(type)
#define	TAG_EXPORT(type)	tnf_tag_data_t *TAG_SNAP(type)

/*
 * String limits
 */

/* XXX tie into TNF_BLOCK_SIZE */
#define	TNF_STRING_LIMIT	255	/* excludes terminating NUL */
#define	TNF_STRING_ROUNDUP(sz)	(((sz) + 3) & ~3)

/*
 * XXX Semi-private
 */

#ifdef _KERNEL

#define	TAG_SET(type)		TAG_SNAP(type)
#define	BUF_ALLOC(ops)		tnfw_b_alloc

#else	/* _KERNEL */

#define	TAG_SET(type)		TAG_EXPORT(type)
#define	BUF_ALLOC(ops)		ops->alloc

#endif	/* _KERNEL */

#define	ASSIGN(buf, slot, val)						\
	buf->slot = tnf_##slot(ops, val, (tnf_record_p) &buf->slot)

#define	ASSIGN2(buf, slot, val, func)					\
	buf->slot = tnf_##func(ops, val, (tnf_record_p)&buf->slot)

#define	ALLOC(ops, size, mem, index_p, saved_mode)			\
	mem = BUF_ALLOC(ops)(&(ops->wcb), size, ops->mode);		\
	if (mem == TNF_NULL) {						\
		ops->mode = saved_mode;					\
		return (TNF_NULL);					\
	}								\
	index_p = (tnf_record_p)mem

#define	ALLOC2(ops, size, mem, saved_mode)				\
	mem = BUF_ALLOC(ops)(&(ops->wcb), size, ops->mode);		\
	if (mem == TNF_NULL) {						\
		ops->mode = saved_mode;					\
		return (TNF_NULL);					\
	}

/*
 * NOTE: These macros DO NOT export the tags.  In the kernel, tag data
 * pointers are initialized to NULL in tnf_res.c, and are snapped by
 * tnf_tag_XXX_init() when the driver is loaded.  In user land
 * they are exported by another macro.
 */

/*
 * Initializing abstract tags
 */

#define	TNF_ABSTRACT_TAG(type)					\
static tnf_tag_data_t	_TAG_DATA(type) = {			\
	TNF_TAG_VERSION,					\
	&tnf_abstract_tag_1, 					\
	0, 							\
	TNF_STRINGIFY(type) }

/*
 * Initializing scalar tags
 */

#define	TNF_SCALAR_TAG(type, size, align, kind)			\
static tnf_tag_data_t	_TAG_DATA(type) = {			\
	TNF_TAG_VERSION, 					\
	&tnf_scalar_tag_1, 					\
	0, 							\
	TNF_STRINGIFY(type),					\
	&tnf_scalar_properties,					\
	size,							\
	align,							\
	size,							\
	kind }

#define	TNF_STD_SCALAR_TAG(type, kind)				\
	TNF_SCALAR_TAG(type, sizeof (type##_t),			\
		TNF_ALIGN(type##_t), kind)

/*
 * Initializing array tags
 * Assumes all arrays are `records'
 */

#define	TNF_ARRAY_TAG(type, eltag, props, slots, kind)		\
static tnf_tag_data_t	_TAG_DATA(type) = {			\
	TNF_TAG_VERSION, 					\
	&tnf_array_tag_1, 					\
	0, 							\
	TNF_STRINGIFY(type),					\
	&props,							\
	ARRAY_HDR_SIZE,						\
	TNF_ALIGN(tnf_ref32_t),					\
	sizeof (tnf_ref32_t), 					\
	kind,	 						\
	eltag,							\
	slots }

#define	TNF_STD_ARRAY_TAG(type, eltype, kind)			\
	TNF_ARRAY_TAG(type, &TAG_DATA(eltype),			\
		tnf_array_properties, tnf_array_slots, kind)

/*
 * Initializing derived tags
 */

#define	TNF_DERIVED_TAG(type, basetag, props, size, align, kind)	\
static tnf_tag_data_t	_TAG_DATA(type) = {			\
	TNF_TAG_VERSION,					\
	&tnf_derived_tag_1,	 				\
	0,	 						\
	TNF_STRINGIFY(type),					\
	&props,		 					\
	0,	 						\
	align,			 				\
	size,							\
	kind,		 					\
	basetag }

#define	TNF_STD_DERIVED_TAG(type, base, props, kind)		\
	TNF_DERIVED_TAG(type, &TAG_DATA(base), props, 		\
		sizeof (type##_t), TNF_ALIGN(type##_t), kind)

/*
 * Initializing structure tags
 * Assumes all structs are `records'
 */

#define	TNF_STRUCT_TAG(type, props, slots, names, size)		\
static tnf_tag_data_t	_TAG_DATA(type) = {			\
	TNF_TAG_VERSION,					\
	&tnf_struct_tag_1,					\
	0,							\
	TNF_STRINGIFY(type),					\
	&props,							\
	size,							\
	TNF_ALIGN(tnf_ref32_t),					\
	sizeof (tnf_ref32_t),					\
	TNF_STRUCT,						\
	0,							\
	slots,							\
	names }

#define	TNF_STD_STRUCT_TAG(type, slots, names, size)		\
	TNF_STRUCT_TAG(type, tnf_struct_properties, slots, names, size)

/*
 * Initializing metatags
 * Size is initialized assuming NULL-terminated array of words and
 * each element has a reference size of one word.
 */

#define	TNF_METATAG(type, props, slots, desc)			\
static tnf_tag_data_t	_TAG_DATA(type) = {			\
	TNF_TAG_VERSION,					\
	&desc,							\
	0,							\
	TNF_STRINGIFY(type),					\
	&props,							\
	(sizeof (slots) - sizeof (slots[0])) *  	        \
	(sizeof (tnf_uint32_t))/(sizeof (char *)),	        \
	TNF_ALIGN(tnf_ref32_t),					\
	sizeof (tnf_ref32_t),					\
	TNF_STRUCT,						\
	0,							\
	slots,							\
	0 }

/*
 * TNF internal types
 */

extern tnf_tag_data_t		*tnf_tag_arg_tag_data;
typedef tnf_ref32_t		tnf_tag_arg_t; /* tag qualifier */

extern tnf_tag_data_t		*tnf_inline_tag_data; /* abstract */

extern tnf_tag_data_t		*tnf_tagged_tag_data; /* abstract */

extern tnf_tag_data_t		*tnf_scalar_tag_data; /* abstract scalar */

extern tnf_tag_data_t		*tnf_array_tag_data; /* abstract array */

extern tnf_tag_data_t		*tnf_derived_tag_data; /* abstract derived */

extern tnf_tag_data_t		*tnf_derived_base_tag_data;
typedef tnf_reference_t		tnf_derived_base_t;
#define	tnf_derived_base(ops, item, ref)\
	tnf_tag_element_1(ops, item, ref, tnf_derived_base_tag_data)

extern tnf_tag_data_t		*tnf_element_type_tag_data;
typedef tnf_reference_t		tnf_element_type_t;
#define	tnf_element_type(ops, item, ref)\
	tnf_tag_element_1(ops, item, ref, tnf_element_type_tag_data)

extern tnf_tag_data_t		*tnf_type_array_tag_data;
typedef tnf_reference_t		tnf_type_array_t;
#define	tnf_type_array(ops, item, ref)	\
	tnf_tag_array_1(ops, item, ref, tnf_type_array_tag_data)

extern tnf_tag_data_t		*tnf_slot_types_tag_data;
typedef tnf_type_array_t	tnf_slot_types_t;
#define	tnf_slot_types(ops, item, ref)	\
	tnf_tag_array_1(ops, item, ref, tnf_slot_types_tag_data)

extern tnf_tag_data_t		*tnf_properties_tag_data;
typedef tnf_type_array_t	tnf_properties_t;
#define	tnf_properties(ops, item, ref) 	\
	tnf_tag_properties_1(ops, item, ref, tnf_properties_tag_data)

extern tnf_tag_data_t		*tnf_name_array_tag_data;
typedef tnf_reference_t		tnf_name_array_t;
#define	tnf_name_array(ops, item, ref)	\
	tnf_string_array_1(ops, item, ref, tnf_name_array_tag_data)

extern tnf_tag_data_t		*tnf_slot_names_tag_data;
typedef tnf_name_array_t	tnf_slot_names_t;
#define	tnf_slot_names(ops, item, ref)	\
	tnf_string_array_1(ops, item, ref, tnf_slot_names_tag_data)

extern tnf_tag_data_t		*tnf_align_tag_data;
typedef tnf_uint32_t		tnf_align_t;
#define	tnf_align(ops, item, ref)	\
	tnf_uint32(ops, item, ref)

extern tnf_tag_data_t		*tnf_self_size_tag_data;
typedef tnf_uint32_t		tnf_self_size_t;
#define	tnf_self_size(ops, item, ref) 	\
	tnf_uint32(ops, item, ref)

extern tnf_tag_data_t		*tnf_type_size_tag_data;
typedef tnf_uint32_t		tnf_type_size_t;
#define	tnf_type_size(ops, item, ref) 	\
	tnf_uint32(ops, item, ref)

extern tnf_tag_data_t		*tnf_header_size_tag_data;
typedef tnf_uint32_t		tnf_header_size_t;
#define	tnf_header_size(ops, item, ref) \
	tnf_uint32(ops, item, ref)

extern tnf_tag_data_t		*tnf_struct_tag_data; /* abstract struct */

extern tnf_tag_data_t		*tnf_type_tag_data; /* abstract type */

extern tnf_tag_data_t		*tnf_scalar_type_tag_data;

extern tnf_tag_data_t		*tnf_derived_type_tag_data;

extern tnf_tag_data_t		*tnf_array_type_tag_data;

extern tnf_tag_data_t		*tnf_struct_type_tag_data;

/*
 * Concrete struct types
 */

extern tnf_tag_data_t		*tnf_file_header_tag_data;

extern tnf_tag_data_t		*tnf_block_header_tag_data;

/*
 * Exported slots
 */

extern tnf_tag_data_t		**tnf_array_slots[];

/*
 * Exported properties
 */

extern tnf_tag_data_t		***tnf_no_properties;
extern tnf_tag_data_t		***tnf_scalar_properties;
extern tnf_tag_data_t		***tnf_array_properties;
extern tnf_tag_data_t		***tnf_derived_properties;
extern tnf_tag_data_t		***tnf_struct_properties;
extern tnf_tag_data_t		***tnf_type_properties;

/*
 * Binary layout of standard array header
 */

typedef struct {
	tnf_tag_t		tag;
	tnf_self_size_t		self_size;
} tnf_array_header_t;

#define	ARRAY_HDR_SIZE	sizeof (tnf_array_header_t)

/*
 * Binary layouts of TNF tags
 */

typedef struct {
	tnf_tag_t		tag;
	tnf_name_t		name;
	tnf_properties_t	properties;
} tnf_type_prototype_t;

typedef struct {
	tnf_tag_t		tag;
	tnf_name_t		name;
	tnf_properties_t	properties;
	tnf_type_size_t		type_size;
	tnf_align_t		align;
} tnf_scalar_type_prototype_t;

typedef struct {
	tnf_tag_t		tag;
	tnf_name_t		name;
	tnf_properties_t	properties;
	tnf_derived_base_t	derived_base;
} tnf_derived_type_prototype_t;

typedef struct {
	tnf_tag_t		tag;
	tnf_name_t		name;
	tnf_properties_t	properties;
	tnf_slot_types_t	slot_types;
	tnf_header_size_t	header_size;
	tnf_element_type_t	element_type;
} tnf_array_type_prototype_t;

typedef struct {
	tnf_tag_t		tag;
	tnf_name_t		name;
	tnf_properties_t	properties;
	tnf_slot_types_t	slot_types;
	tnf_type_size_t		type_size;
	tnf_slot_names_t	slot_names;
} tnf_struct_type_prototype_t;

/*
 * Data encoders
 */

extern tnf_reference_t	tnf_tag_element_1(tnf_ops_t *,
					tnf_tag_data_t **,
					tnf_record_p,
					tnf_tag_data_t *);

extern tnf_reference_t	tnf_tag_array_1(tnf_ops_t *,
					tnf_tag_data_t ***,
					tnf_record_p,
					tnf_tag_data_t *);

extern tnf_reference_t	tnf_tag_properties_1(tnf_ops_t *,
					tnf_tag_data_t ****,
					tnf_record_p,
					tnf_tag_data_t *);

extern tnf_reference_t	tnf_string_array_1(tnf_ops_t *,
					char **,
					tnf_record_p,
					tnf_tag_data_t *);

/*
 * Tag descriptors
 */

extern tnf_record_p tnf_abstract_tag_1(tnf_ops_t *, tnf_tag_data_t *);
extern tnf_record_p tnf_scalar_tag_1(tnf_ops_t *, tnf_tag_data_t *);
extern tnf_record_p tnf_derived_tag_1(tnf_ops_t *, tnf_tag_data_t *);
extern tnf_record_p tnf_array_tag_1(tnf_ops_t *, tnf_tag_data_t *);

#ifdef _KERNEL
/*
 * Tag pointer initializers, called when driver loaded to snap all
 * tag data pointers.
 */

extern void tnf_tag_core_init(void);	/* initialize core tags */
extern void tnf_tag_trace_init(void);	/* initialize trace tags */
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _TNF_TYPES_H */
