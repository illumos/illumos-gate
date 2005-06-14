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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef DEBUG
#define	NDEBUG	1
#endif

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/tnf_com.h>
#include <sys/tnf_writer.h>
#include <sys/debug.h>
#include "tnf_types.h"
#include "tnf_trace.h"
#else	/* _KERNEL */
#include <stdlib.h>
#include <string.h>
#include <tnf/com.h>
#include <tnf/writer.h>
#include <assert.h>
#include "tnf_types.h"
#include <tnf_trace.h>
#endif	/* _KERNEL */

/*
 * Defines
 */

#ifdef _KERNEL
#define	TNF_ASSERT(expr)	ASSERT(expr)
#else
#define	TNF_ASSERT(expr)	assert(expr)
#endif

/*
 * Local functions
 */

static tnf_record_p tnf_root_tag_1(tnf_ops_t *, tnf_tag_data_t *);

/*
 * TNF tag version 1
 */

tnf_tag_version_t __tnf_tag_version_1_info =  {
	sizeof (tnf_tag_version_t),
	sizeof (tnf_tag_data_t)
};

/*
 * Pure abstract types
 */

TNF_ABSTRACT_TAG(tnf_inline);
TNF_ABSTRACT_TAG(tnf_tagged);

/*
 * Scalar types
 */

static tnf_tag_data_t	**std_scalar_properties[] = {
	&TAG_DATA(tnf_inline),
	&TAG_DATA(tnf_scalar),
	0};

tnf_tag_data_t	***tnf_scalar_properties = std_scalar_properties;

TNF_SCALAR_TAG(tnf_scalar, 0, 0, TNF_UNKNOWN);

TNF_STD_SCALAR_TAG(tnf_char, TNF_UNKNOWN); /* XXX */
TNF_STD_SCALAR_TAG(tnf_int8, TNF_INT32);
TNF_STD_SCALAR_TAG(tnf_uint8, TNF_UINT32);
TNF_STD_SCALAR_TAG(tnf_int16, TNF_INT32);
TNF_STD_SCALAR_TAG(tnf_uint16, TNF_UINT32);
TNF_STD_SCALAR_TAG(tnf_int32, TNF_INT32);
TNF_STD_SCALAR_TAG(tnf_uint32, TNF_UINT32);
TNF_STD_SCALAR_TAG(tnf_int64, TNF_INT64);
TNF_STD_SCALAR_TAG(tnf_uint64, TNF_UINT64);

TNF_STD_SCALAR_TAG(tnf_float32, TNF_FLOAT32);
TNF_STD_SCALAR_TAG(tnf_float64, TNF_FLOAT64);

/*
 * Array types
 */

static tnf_tag_data_t	**array_properties[] = {
	&TAG_DATA(tnf_array),
	0
};
static tnf_tag_data_t	***abstract_array_properties = array_properties;

static tnf_tag_data_t	**std_array_properties[] = {
	&TAG_DATA(tnf_array),
	&TAG_DATA(tnf_tagged),
	0
};
/* Exported */
tnf_tag_data_t	***tnf_array_properties = std_array_properties;

/* Exported */
tnf_tag_data_t	**tnf_array_slots[] = {
	&TAG_DATA(tnf_tag),
	&TAG_DATA(tnf_self_size),
	0
};

TNF_ARRAY_TAG(tnf_array, TNF_NULL, abstract_array_properties,
			TNF_NULL, TNF_UNKNOWN);

TNF_STD_ARRAY_TAG(tnf_string, tnf_char, TNF_STRING);
TNF_STD_ARRAY_TAG(tnf_type_array, tnf_type, TNF_ARRAY);
TNF_STD_ARRAY_TAG(tnf_name_array, tnf_name, TNF_ARRAY);

/*
 * Derived types
 */

static tnf_tag_data_t	**derived_properties[] = {
	&TAG_DATA(tnf_derived),
	0
};
/* Exported */
tnf_tag_data_t	***tnf_derived_properties = derived_properties;

TNF_DERIVED_TAG(tnf_derived, TNF_NULL,
		tnf_derived_properties, TNF_NULL, TNF_NULL, TNF_UNKNOWN);

TNF_STD_DERIVED_TAG(tnf_align, tnf_uint32,
		tnf_derived_properties, TNF_UINT32);

TNF_STD_DERIVED_TAG(tnf_derived_base, tnf_type,
		tnf_derived_properties, TNF_OPAQUE);

TNF_STD_DERIVED_TAG(tnf_element_type, tnf_type,
		tnf_derived_properties, TNF_OPAQUE);

TNF_STD_DERIVED_TAG(tnf_header_size, tnf_uint32,
		tnf_derived_properties, TNF_UINT32);

TNF_STD_DERIVED_TAG(tnf_name, tnf_string,
		tnf_derived_properties, TNF_STRING);

#if defined(_LP64)

TNF_STD_DERIVED_TAG(tnf_opaque, tnf_uint64,
		tnf_derived_properties, TNF_OPAQUE);

#else

TNF_STD_DERIVED_TAG(tnf_opaque, tnf_uint32,
		tnf_derived_properties, TNF_OPAQUE);

#endif /* defined(_LP64) */

TNF_STD_DERIVED_TAG(tnf_properties, tnf_type_array,
		tnf_derived_properties, TNF_ARRAY);

TNF_STD_DERIVED_TAG(tnf_self_size, tnf_uint32,
		tnf_derived_properties, TNF_UINT32);

TNF_STD_DERIVED_TAG(tnf_size, tnf_ulong,
		tnf_derived_properties, TNF_ULONG);

TNF_STD_DERIVED_TAG(tnf_slot_names, tnf_name_array,
		tnf_derived_properties, TNF_ARRAY);

TNF_STD_DERIVED_TAG(tnf_slot_types, tnf_type_array,
		tnf_derived_properties, TNF_ARRAY);

TNF_STD_DERIVED_TAG(tnf_tag, tnf_type,
		tnf_derived_properties, TNF_OPAQUE);

TNF_STD_DERIVED_TAG(tnf_tag_arg, tnf_tagged,
		tnf_derived_properties, TNF_OPAQUE);

TNF_STD_DERIVED_TAG(tnf_type_size, tnf_uint32,
		tnf_derived_properties, TNF_UINT32);

/*
 * Struct types
 */

static tnf_tag_data_t	**no_properties[] = { 0 };
tnf_tag_data_t	***tnf_no_properties = no_properties;

static tnf_tag_data_t	**no_slots[] = { 0 };

static tnf_tag_data_t	**std_struct_properties[] = {
	&TAG_DATA(tnf_tagged),
	&TAG_DATA(tnf_struct),
	0};
/* Exported */
tnf_tag_data_t	***tnf_struct_properties = std_struct_properties;

TNF_STRUCT_TAG(tnf_struct, tnf_no_properties, no_slots, 0, 0);

/*
 * File header - CAUTION - has to be in sync with com.h
 */

static char	*file_header_slot_names[] = {
	TNF_N_TAG,
	TNF_N_FILE_VERSION,
	TNF_N_FILE_HEADER_SIZE,
	TNF_N_FILE_LOGICAL_SIZE,
	TNF_N_BLOCK_HEADER_SIZE,
	TNF_N_BLOCK_SIZE,
	TNF_N_DIRECTORY_SIZE,
	TNF_N_BLOCK_COUNT,
	TNF_N_BLOCKS_VALID,
	/* XXX add writer-specific opaque slots here for reader */
	0};

static tnf_tag_data_t	**file_header_slots[] = {
	&TAG_DATA(tnf_tag),		/* tag			*/
	&TAG_DATA(tnf_uint32),		/* file_version 	*/
	&TAG_DATA(tnf_uint32),		/* file_header_size	*/
	&TAG_DATA(tnf_uint32),		/* file_logical_size	*/
	&TAG_DATA(tnf_uint32),		/* block_header_size 	*/
	&TAG_DATA(tnf_uint32),		/* block_size 		*/
	&TAG_DATA(tnf_uint32),		/* directory_size 	*/
	&TAG_DATA(tnf_uint32),		/* block_count 		*/
	&TAG_DATA(tnf_uint32),		/* blocks_valid 	*/
	/* XXX add writer-specific opaque slots here for reader */
	0};

/* size of tnf_file_header has the size of the magic number subtracted */
TNF_STD_STRUCT_TAG(tnf_file_header,
		file_header_slots,
		file_header_slot_names,
		sizeof (tnf_buf_file_header_t) - sizeof (tnf_uint32_t));

/*
 * Block header - CAUTION - has to be in sync with com.h
 */

static char	*block_header_slot_names[] = {
	TNF_N_TAG,
	TNF_N_GENERATION,
	TNF_N_BYTES_VALID,
	"A_lock",			/* XXX */
	"B_lock",			/* XXX */
	"next_block",			/* XXX */
	0};

static tnf_tag_data_t	**block_header_slots[] = {
	&TAG_DATA(tnf_tag),		/* tag			*/
	&TAG_DATA(tnf_uint32),		/* generation		*/
	&TAG_DATA(tnf_uint16),		/* bytes_valid		*/
	&TAG_DATA(tnf_uint8),		/* A_lock 		*/
	&TAG_DATA(tnf_uint8),		/* B_lock		*/
	&TAG_DATA(tnf_opaque),		/* next_block 		*/
	0};

TNF_STD_STRUCT_TAG(tnf_block_header,
		block_header_slots,
		block_header_slot_names,
		sizeof (tnf_block_header_t));

/*
 * Metatypes
 */

static tnf_tag_data_t	**type_properties[] = {
	&TAG_DATA(tnf_tagged),
	&TAG_DATA(tnf_struct),
	&TAG_DATA(tnf_type),
	0};
/* Exported */
tnf_tag_data_t	***tnf_type_properties = type_properties;

static tnf_tag_data_t	**type_slots[] = {
	&TAG_DATA(tnf_tag),
	&TAG_DATA(tnf_name),
	&TAG_DATA(tnf_properties),
	0};

TNF_METATAG(tnf_type, tnf_type_properties, type_slots, tnf_struct_tag_1);

static tnf_tag_data_t	**array_type_slots[] = {
	&TAG_DATA(tnf_tag),
	&TAG_DATA(tnf_name),
	&TAG_DATA(tnf_properties),
	&TAG_DATA(tnf_slot_types),
	&TAG_DATA(tnf_header_size),
	&TAG_DATA(tnf_element_type),
	0};

TNF_METATAG(tnf_array_type, tnf_type_properties,
		array_type_slots, tnf_struct_tag_1);

static tnf_tag_data_t	**derived_type_slots[] = {
	&TAG_DATA(tnf_tag),
	&TAG_DATA(tnf_name),
	&TAG_DATA(tnf_properties),
	&TAG_DATA(tnf_derived_base),
	0};

TNF_METATAG(tnf_derived_type, tnf_type_properties,
		derived_type_slots, tnf_struct_tag_1);

static tnf_tag_data_t	**scalar_type_slots[] = {
	&TAG_DATA(tnf_tag),
	&TAG_DATA(tnf_name),
	&TAG_DATA(tnf_properties),
	&TAG_DATA(tnf_type_size),
	&TAG_DATA(tnf_align),
	0};

TNF_METATAG(tnf_scalar_type, tnf_type_properties,
		scalar_type_slots, tnf_struct_tag_1);

static tnf_tag_data_t	**struct_type_slots[] = {
	&TAG_DATA(tnf_tag),
	&TAG_DATA(tnf_name),
	&TAG_DATA(tnf_properties),
	&TAG_DATA(tnf_slot_types),
	&TAG_DATA(tnf_type_size),
	&TAG_DATA(tnf_slot_names),
	0};

TNF_METATAG(tnf_struct_type, tnf_type_properties,
		struct_type_slots, tnf_root_tag_1);


/*
 * Generic tnf reference - does checking on whether destination is
 * a permanent block or not
 */

#ifdef _KERNEL

/*ARGSUSED0*/
tnf_ref32_t
tnf_ref32_1(tnf_ops_t *ops, tnf_record_p item, tnf_record_p reference)
{
	tnf_ref32_t 		offset_delta, gen_delta;
	tnf_block_header_t	*dest_header_p, *src_header_p;
	tnf_ref32_t		result;
	unsigned int		offset_shift =
		/* LINTED pointer cast may result in improper alignment */
		((tnf_buf_file_header_t *)tnf_buf)->com.file_log_size;

	dest_header_p = (tnf_block_header_t *)
		((uintptr_t)item & TNF_BLOCK_MASK);

	if (((char *)dest_header_p < (tnf_buf + TNF_DIRECTORY_SIZE)) ||
	    (dest_header_p->generation == TNF_TAG_GENERATION_NUM)) {
		/* reference to a permanent block */
		/* LINTED ast from 64-bit integer to 32-bit integer */
		offset_delta = (tnf_ref32_t)(item - tnf_buf);

		return (TNF_REF32_MAKE_PERMANENT(offset_delta));
	} else {
		/* reference to a reclaimable block */
		/* LINTED ast from 64-bit integer to 32-bit integer */
		offset_delta = (tnf_ref32_t)(item - reference);

		src_header_p =  (tnf_block_header_t *)
			((uintptr_t)reference & TNF_BLOCK_MASK);
		gen_delta = dest_header_p->generation -
			src_header_p->generation;

		result = (gen_delta << offset_shift) + offset_delta;
		return (TNF_REF32_MAKE_RECLAIMABLE(result));
	}
}

#else

/*ARGSUSED0*/
tnf_ref32_t
tnf_ref32_1(tnf_ops_t *ops, tnf_record_p item, tnf_record_p reference)
{
	volatile char 		*file_start = _tnfw_b_control->tnf_buffer;
	tnf_ref32_t 		offset_delta, gen_delta;
	tnf_block_header_t	*dest_header_p, *src_header_p;
	tnf_ref32_t		result;
	unsigned int		offset_shift =
		/* LINTED pointer cast may result in improper alignment */
		((tnf_buf_file_header_t *)file_start)->com.file_log_size;

	dest_header_p = (tnf_block_header_t *)
		((uintptr_t)item & TNF_BLOCK_MASK);

	if (((char *)dest_header_p < (file_start + TNFW_B_FW_ZONE)) ||
	    (dest_header_p->generation == TNF_TAG_GENERATION_NUM)) {
		/* reference to a permanent block */
		/* LINTED ast from 64-bit integer to 32-bit integer */
		offset_delta = (tnf_ref32_t)(item - (tnf_record_p) file_start);

		return (TNF_REF32_MAKE_PERMANENT(offset_delta));
	} else {
		/* reference to a reclaimable block */
		/* LINTED ast from 64-bit integer to 32-bit integer */
		offset_delta = (tnf_ref32_t)(item - reference);

		src_header_p =  (tnf_block_header_t *)
			((uintptr_t)reference & TNF_BLOCK_MASK);
		gen_delta = dest_header_p->generation -
			src_header_p->generation;

		result = (gen_delta << offset_shift) + offset_delta;
		return (TNF_REF32_MAKE_RECLAIMABLE(result));
	}
}

#endif

/*
 * Tag descriptors
 */

/*
 * Write instances of tnf_type
 */

tnf_record_p
tnf_abstract_tag_1(tnf_ops_t *ops, tnf_tag_data_t *tag_data)
{
	tnf_tag_data_t		*metatag_data;
	tnf_record_p		metatag_index;
	tnf_type_prototype_t	*buffer;
	enum tnf_alloc_mode	saved_mode;

	saved_mode = ops->mode;
	ops->mode = TNF_ALLOC_FIXED;
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ALLOC(ops, sizeof (*buffer), buffer, tag_data->tag_index,
		saved_mode);

	metatag_data = TAG_DATA(tnf_type);
	metatag_index = metatag_data->tag_index ? metatag_data->tag_index :
		metatag_data->tag_desc(ops, metatag_data);

	ASSIGN(buffer, tag,		metatag_index);
	ASSIGN(buffer, name, 		tag_data->tag_name);
	ASSIGN(buffer, properties,	tag_data->tag_props);
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ops->mode = saved_mode;
	return (tag_data->tag_index);
}

/*
 * Write instances of tnf_scalar_type
 */

tnf_record_p
tnf_scalar_tag_1(tnf_ops_t *ops, tnf_tag_data_t *tag_data)
{
	tnf_tag_data_t		*metatag_data;
	tnf_record_p		metatag_index;
	enum tnf_alloc_mode	saved_mode;
	tnf_scalar_type_prototype_t *buffer;

	saved_mode = ops->mode;
	ops->mode = TNF_ALLOC_FIXED;
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ALLOC(ops, sizeof (*buffer), buffer, tag_data->tag_index,
	    saved_mode);

	metatag_data = TAG_DATA(tnf_scalar_type);
	metatag_index = metatag_data->tag_index ? metatag_data->tag_index :
		metatag_data->tag_desc(ops, metatag_data);

	ASSIGN(buffer, tag, 		metatag_index);
	ASSIGN(buffer, name, 		tag_data->tag_name);
	ASSIGN(buffer, properties, 	tag_data->tag_props);
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ASSIGN(buffer, type_size, 	tag_data->tag_size);
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	ASSIGN(buffer, align, 		tag_data->tag_align);

	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ops->mode = saved_mode;
	return (tag_data->tag_index);
}

/*
 * Write instances of tnf_derived_type
 */

tnf_record_p
tnf_derived_tag_1(tnf_ops_t *ops, tnf_tag_data_t *tag_data)
{
	tnf_tag_data_t		*metatag_data;
	tnf_record_p		metatag_index;
	enum tnf_alloc_mode	saved_mode;
	tnf_derived_type_prototype_t *buffer;

	saved_mode = ops->mode;
	ops->mode = TNF_ALLOC_FIXED;
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ALLOC(ops, sizeof (*buffer), buffer, tag_data->tag_index,
	    saved_mode);

	metatag_data = TAG_DATA(tnf_derived_type);
	metatag_index = metatag_data->tag_index ? metatag_data->tag_index:
		metatag_data->tag_desc(ops, metatag_data);

	ASSIGN(buffer, tag,		metatag_index);
	ASSIGN(buffer, name,		tag_data->tag_name);
	ASSIGN(buffer, properties, 	tag_data->tag_props);
	ASSIGN(buffer, derived_base,	tag_data->tag_base);
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ops->mode = saved_mode;
	return (tag_data->tag_index);
}

/*
 * Write instances of tnf_struct_type (except root)
 */

tnf_record_p
tnf_struct_tag_1(tnf_ops_t *ops, tnf_tag_data_t *tag_data)
{
	tnf_tag_data_t		*metatag_data;
	tnf_record_p		metatag_index;
	enum tnf_alloc_mode	saved_mode;
	tnf_struct_type_prototype_t *buffer;

	saved_mode = ops->mode;
	ops->mode = TNF_ALLOC_FIXED;
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ALLOC(ops, sizeof (*buffer), buffer, tag_data->tag_index,
	    saved_mode);

	metatag_data = TAG_DATA(tnf_struct_type);
	metatag_index = metatag_data->tag_index ? metatag_data->tag_index:
		metatag_data->tag_desc(ops, metatag_data);

	ASSIGN(buffer, tag,		metatag_index);
	ASSIGN(buffer, name,		tag_data->tag_name);
	ASSIGN(buffer, properties, 	tag_data->tag_props);
	ASSIGN(buffer, slot_types, 	tag_data->tag_slots);
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	ASSIGN(buffer, type_size, 	tag_data->tag_size);
	ASSIGN(buffer, slot_names, 	tag_data->tag_slot_names);
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ops->mode = saved_mode;
	return (tag_data->tag_index);
}

/*
 * Write instances of tnf_array_type
 */

tnf_record_p
tnf_array_tag_1(tnf_ops_t *ops, tnf_tag_data_t	*tag_data)
{
	tnf_tag_data_t 		*metatag_data;
	tnf_record_p 		metatag_index;
	enum tnf_alloc_mode	saved_mode;
	tnf_array_type_prototype_t 	*buffer;

	saved_mode = ops->mode;
	ops->mode = TNF_ALLOC_FIXED;
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ALLOC(ops, sizeof (*buffer), buffer, tag_data->tag_index,
	    saved_mode);

	metatag_data = TAG_DATA(tnf_array_type);
	metatag_index = metatag_data->tag_index ? metatag_data->tag_index :
		metatag_data->tag_desc(ops, metatag_data);

	ASSIGN(buffer, tag, 		metatag_index);
	ASSIGN(buffer, name, 		tag_data->tag_name);
	ASSIGN(buffer, properties, 	tag_data->tag_props);
	ASSIGN(buffer, slot_types, 	tag_data->tag_slots);
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	ASSIGN(buffer, header_size, 	tag_data->tag_size);
	ASSIGN(buffer, element_type, 	tag_data->tag_base);
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ops->mode = saved_mode;
	return (tag_data->tag_index);
}

/*
 * Write the root metatype, and some critical bootstrap types
 */

static tnf_record_p
tnf_root_tag_1(tnf_ops_t *ops, tnf_tag_data_t *tag_data)
{
	enum tnf_alloc_mode	saved_mode;
	tnf_tag_t		*fw_p;
	tnf_struct_type_prototype_t *buffer;

	saved_mode = ops->mode;
	ops->mode = TNF_ALLOC_FIXED;
	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ALLOC(ops, sizeof (*buffer), buffer, tag_data->tag_index,
	    saved_mode);

	/*
	 * update the root forwarding pointer to point to this root
	 * CAUTION: Do this before anything else...
	 */

#ifdef _KERNEL
	/* LINTED pointer cast may result in improper alignment */
	fw_p = (tnf_tag_t *)(tnf_buf + TNF_DIRENT_ROOT);
	*fw_p = tnf_ref32(ops, tag_data->tag_index, (tnf_record_p)fw_p);
	tag_data->tag_index = (tnf_record_p)fw_p;
#else
	/* LINTED pointer cast may result in improper alignment */
	fw_p = (tnf_tag_t *)_tnf_buf_headers_p->fw_root;
	if (fw_p) {
		*fw_p = tnf_ref32(ops, tag_data->tag_index,
		    (tnf_record_p) fw_p);
		tag_data->tag_index = (tnf_record_p)fw_p;
	}
#endif

#ifdef _KERNEL
	/* LINTED constant truncated by assignment */
	buffer->tag = TNF_ROOT_TAG;
#else
	ASSIGN(buffer, tag,		tag_data->tag_index); /* ROOT */
#endif
	ASSIGN(buffer, name,		tag_data->tag_name);
	ASSIGN(buffer, properties, 	tag_data->tag_props);
	ASSIGN(buffer, slot_types, 	tag_data->tag_slots);
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	ASSIGN(buffer, type_size, 	tag_data->tag_size);
	ASSIGN(buffer, slot_names, 	tag_data->tag_slot_names);

	/*
	 * Write some additional bootstrap types
	 */
	{
		static tnf_tag_data_t *bootstrap_types[] = {
			&_TAG_DATA(tnf_uint16),
			&_TAG_DATA(tnf_int32),
			&_TAG_DATA(tnf_tag),
			&_TAG_DATA(tnf_file_header),
			&_TAG_DATA(tnf_block_header),
			0};
		tnf_tag_data_t **list_p, *tag_p;

		list_p = bootstrap_types;

		while (tag_p = *list_p++) {
			if (!tag_p->tag_index) /* not written */
				tag_p->tag_desc(ops, tag_p);
		}
	}


	/*
	 * fix for circularity in filling in file header tag and block
	 * header tag.  REMIND: should also fix tag_index of
	 * file_header.
	 */

#ifdef _KERNEL

	/* LINTED pointer cast may result in improper alignment */
	fw_p = (tnf_tag_t *)(tnf_buf + TNF_DIRENT_FILE_HEADER);
	*fw_p = tnf_ref32(ops, _TAG_DATA(tnf_file_header).tag_index,
	    (tnf_record_p)fw_p);

	/* LINTED pointer cast may result in improper alignment */
	fw_p = (tnf_tag_t *)(tnf_buf + TNF_DIRENT_BLOCK_HEADER);
	*fw_p = tnf_ref32(ops, _TAG_DATA(tnf_block_header).tag_index,
	    (tnf_record_p)fw_p);

#else

	/* LINTED pointer cast may result in improper alignment */
	fw_p = (tnf_tag_t *)_tnf_buf_headers_p->fw_file_header;
	if (fw_p) {
		*fw_p = tnf_ref32(ops, _TAG_DATA(tnf_file_header).tag_index,
		    (tnf_record_p)fw_p);
	}
	/* LINTED pointer cast may result in improper alignment */
	fw_p = (tnf_tag_t *)_tnf_buf_headers_p->fw_block_header;
	if (fw_p) {
		*fw_p = tnf_ref32(ops, _TAG_DATA(tnf_block_header).tag_index,
		    (tnf_record_p) fw_p);
	}

#endif

	/* LINTED assignment of 32-bit integer to 8-bit integer */
	ops->mode = saved_mode;
	return (tag_data->tag_index);
}


/*
 * Data encoders
 */

/*
 * Strings and derivatives
 */

tnf_reference_t
tnf_string_1(tnf_ops_t *ops, const char *string, tnf_record_p reference,
		tnf_tag_data_t	*tag_data)
{
	tnf_record_p 	tag_index;
	size_t		string_size, record_size;
	tnf_array_header_t *bufhdr;

	tag_index = tag_data->tag_index ? tag_data->tag_index :
		tag_data->tag_desc(ops, tag_data);

	if (!string)
		return ((tnf_reference_t)TNF_NULL);

	string_size = strlen(string); /* excludes terminating NUL */
	if (string_size > TNF_STRING_LIMIT)
		string_size = TNF_STRING_LIMIT;
	/* Allocate space for terminating NUL as well */
	record_size = sizeof (*bufhdr) + TNF_STRING_ROUNDUP(string_size + 1);

	ALLOC2(ops, record_size, bufhdr, ops->mode);

	ASSIGN(bufhdr, tag, 		tag_index);
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	ASSIGN(bufhdr, self_size, 	record_size);

#ifdef _KERNEL
	(void) bcopy((caddr_t)string, (char *)bufhdr + sizeof (*bufhdr),
	    string_size);
#else
	(void) memcpy((char *)bufhdr + sizeof (*bufhdr), string, string_size);
#endif
	/* NUL-terminate */
	((char *)bufhdr + sizeof (*bufhdr))[string_size] = '\0';

	return (tnf_ref32(ops, (tnf_record_p)bufhdr, reference));
}

/*
 * Array of strings and derivatives
 */

tnf_reference_t
tnf_string_array_1(tnf_ops_t *ops, char	**strings, tnf_record_p reference,
			tnf_tag_data_t	*tag_data)
{
	tnf_record_p 	tag_index;
	size_t		record_size;
	char		**tmp;
	tnf_reference_t	*ref_p;
	tnf_array_header_t 	*bufhdr;

	tag_index = tag_data->tag_index ? tag_data->tag_index :
		tag_data->tag_desc(ops, tag_data);

	if (!strings)
		return ((tnf_reference_t)TNF_NULL);

	record_size = sizeof (*bufhdr);
	tmp = strings;
	while (*tmp++)
		record_size += sizeof (tnf_string_t);

	ALLOC2(ops, record_size, bufhdr, ops->mode);

	ASSIGN(bufhdr, tag, 		tag_index);
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	ASSIGN(bufhdr, self_size, 	record_size);

	tmp = strings;
	/* LINTED pointer cast may result in improper alignment */
	ref_p = (tnf_reference_t *)((char *)bufhdr + sizeof (*bufhdr));
	while (*tmp) {
		*ref_p = tnf_string(ops, *tmp, (tnf_record_p)ref_p);
		tmp++;
		ref_p++;
	}

	return (tnf_ref32(ops, (tnf_record_p) bufhdr, reference));
}

/*
 * Type record as generic (not tag) reference
 */

tnf_reference_t
tnf_tag_element_1(tnf_ops_t *ops, tnf_tag_data_t **tag_data_p,
		tnf_record_p reference, tnf_tag_data_t *aux_tag_data)
{
	tnf_tag_data_t	*tag_data;

	if (aux_tag_data)
		if (!aux_tag_data->tag_index)
			aux_tag_data->tag_desc(ops, aux_tag_data);

	/* tnf_derived has derived_base == TNF_NULL */
	if (!tag_data_p)
		return ((tnf_reference_t)TNF_NULL);

	tag_data = *tag_data_p;
	if (!tag_data->tag_index)
		tag_data->tag_desc(ops, tag_data);

	return (tnf_ref32(ops, tag_data->tag_index, reference));
}


/*
 * Array of type records as generic (not tag) references
 */

tnf_reference_t
tnf_tag_array_1(tnf_ops_t		*ops,
		tnf_tag_data_t		***tag_data_array,
		tnf_record_p		reference,
		tnf_tag_data_t		*tag_data)
{
	tnf_record_p 	tag_index;
	size_t		record_size;
	tnf_array_header_t 	*bufhdr;
	tnf_tag_data_t	***tmp;
	tnf_reference_t	*ref_p;

	tag_index = tag_data->tag_index ? tag_data->tag_index :
		tag_data->tag_desc(ops, tag_data);

	if (!tag_data_array)
		return ((tnf_reference_t)TNF_NULL);

	record_size = sizeof (*bufhdr);
	tmp = tag_data_array;
	while (*tmp++)
		record_size += sizeof (tnf_reference_t);

	ALLOC2(ops, record_size, bufhdr, ops->mode);

	ASSIGN(bufhdr, tag, 		tag_index);
	/* LINTED assignment of 64-bit integer to 32-bit integer */
	ASSIGN(bufhdr, self_size, 	record_size);

	tmp = tag_data_array;
	/* LINTED pointer cast may result in improper alignment */
	ref_p = (tnf_reference_t *)((char *)bufhdr + sizeof (*bufhdr));
	while (*tmp) {
		*ref_p = tnf_tag_element_1(ops, *tmp, (tnf_record_p)ref_p,
		    TNF_NULL);
		tmp++;
		ref_p++;
	}

	return (tnf_ref32(ops, (tnf_record_p)bufhdr, reference));
}

/*
 * Array of properties (type records)
 */

tnf_reference_t
tnf_tag_properties_1(tnf_ops_t		*ops,
		tnf_tag_data_t		****tag_data_array,
		tnf_record_p		reference,
		tnf_tag_data_t		*tag_data)
{
	if (!(tag_data->tag_index))
		tag_data->tag_desc(ops, tag_data);

	if (!tag_data_array)
		return ((tnf_reference_t)TNF_NULL);

	return (tnf_tag_array_1(ops, *tag_data_array, reference, tag_data));
}

#ifdef _KERNEL
/*
 * Initialize all core tag pointers defined in this file.
 * CAUTION: tnf_tag_core_init is a function for kernel compilation.
 */

void
tnf_tag_core_init(void)
{
#endif
	TAG_SET(tnf_inline);
	TAG_SET(tnf_tagged);

	TAG_SET(tnf_scalar);
	TAG_SET(tnf_char);
	TAG_SET(tnf_int8);
	TAG_SET(tnf_uint8);
	TAG_SET(tnf_int16);
	TAG_SET(tnf_uint16);
	TAG_SET(tnf_int32);
	TAG_SET(tnf_uint32);
	TAG_SET(tnf_int64);
	TAG_SET(tnf_uint64);

	TAG_SET(tnf_float32);
	TAG_SET(tnf_float64);

	TAG_SET(tnf_array);
	TAG_SET(tnf_string);
	TAG_SET(tnf_type_array);
	TAG_SET(tnf_name_array);

	TAG_SET(tnf_derived);
	TAG_SET(tnf_align);
	TAG_SET(tnf_derived_base);
	TAG_SET(tnf_element_type);
	TAG_SET(tnf_header_size);
	TAG_SET(tnf_name);
	TAG_SET(tnf_opaque);
	TAG_SET(tnf_properties);
	TAG_SET(tnf_self_size);
	TAG_SET(tnf_size);
	TAG_SET(tnf_slot_names);
	TAG_SET(tnf_slot_types);
	TAG_SET(tnf_tag);
	TAG_SET(tnf_tag_arg);
	TAG_SET(tnf_type_size);

	TAG_SET(tnf_struct);
	TAG_SET(tnf_file_header);
	TAG_SET(tnf_block_header);

	TAG_SET(tnf_type);
	TAG_SET(tnf_array_type);
	TAG_SET(tnf_derived_type);
	TAG_SET(tnf_scalar_type);
	TAG_SET(tnf_struct_type);

#ifdef _KERNEL

	/* Snap exported properties */
	tnf_user_struct_properties = std_struct_properties;

}

#else	/* _KERNEL */

tnf_tag_data_t ***tnf_user_struct_properties = std_struct_properties;

#endif	/* _KERNEL */
