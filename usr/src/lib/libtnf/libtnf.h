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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBTNF_H
#define	_LIBTNF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "tnf/tnf.h"
#include "machlibtnf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Info flags
 */

typedef unsigned long	tag_props_t;

#define	TAG_PROP_INLINE		(1<<0)
#define	TAG_PROP_TAGGED		(1<<1)
#define	TAG_PROP_SCALAR		(1<<2)
#define	TAG_PROP_DERIVED	(1<<3)
#define	TAG_PROP_ARRAY		(1<<4)
#define	TAG_PROP_STRING		(1<<5)
#define	TAG_PROP_STRUCT		(1<<6)
#define	TAG_PROP_TYPE		(1<<7)

/*
 * Type tag information
 */

struct taginfo {
	struct taginfo	*link;		/* hash link */
#define	INFO_MEMBER_0	link
	TNF		*tnf;		/* TNF handle */
	tnf_ref32_t	*tag;		/* tag record in file */
	char		*name;		/* chars in file */
	tnf_kind_t	kind;		/* data classification */
	tag_props_t	props;		/* tag property flags */
	struct taginfo	*meta;		/* meta tag info */
	struct taginfo	*base;		/* last derived base or elttype */
	size_t		size;		/* storage size or -1 */
	size_t		align;		/* slot alignment */
	size_t		hdrsize;	/* array header size */
	struct slotinfo {		/* aggregate slot information */
		unsigned	slot_count;
		/* Embedded array */
		struct slot {
			struct taginfo	*slot_type;
			char		*slot_name;
			unsigned	slot_offset;
		} slots[1];
	} *slotinfo;
};

#define	INFO_PROP(ip, p)	((ip)->props & (p))

#define	INFO_INLINE(ip)		INFO_PROP(ip, TAG_PROP_INLINE)
#define	INFO_TAGGED(ip)		INFO_PROP(ip, TAG_PROP_TAGGED)
#define	INFO_SCALAR(ip)		INFO_PROP(ip, TAG_PROP_SCALAR)
#define	INFO_DERIVED(ip)	INFO_PROP(ip, TAG_PROP_DERIVED)
#define	INFO_ARRAY(ip)		INFO_PROP(ip, TAG_PROP_ARRAY)
#define	INFO_STRING(ip)		INFO_PROP(ip, TAG_PROP_STRING)
#define	INFO_STRUCT(ip)		INFO_PROP(ip, TAG_PROP_STRUCT)
#define	INFO_TYPE(ip)		INFO_PROP(ip, TAG_PROP_TYPE)

#define	INFO_REF_SIZE(ip)	(INFO_TAGGED(ip)? 4: (ip)->size)
#define	INFO_ELEMENT_SIZE(ip)	INFO_REF_SIZE(ip)

/* Alignment is stored for all but records and derivations thereof */
#define	INFO_ALIGN(ip)		(INFO_TAGGED(ip)? 4: (ip)->align)

#define	ALIGN(n, a)		\
	(((a) == 0) ? (n) : (((n) + (a) - 1) & ~((a) - 1)))

/*
 * Tag lookup
 */

/* Number of directory entries */
#define	TAGDIRCNT(x) 	((x) / sizeof (tnf_ref32_t))

/* Number of hash table buckets */
#define	TAGTABCNT	1024
#define	TAGTABMASK	(TAGTABCNT-1)

/* A tag is at least 32 bytes; with strings & props, assume 128 bytes */
#define	TAGTABSHIFT	7

/* Hash tag by bits 17:7 of offset within data area */
#define	TAGOFF(tnf, p)	((unsigned)((caddr_t)(p) - (tnf)->data_start))
#define	TAGHASH(tnf, p)	((TAGOFF(tnf, p) >> TAGTABSHIFT) & TAGTABMASK)

/*
 * TNF handle
 */

struct TNF {
	/*
	 * Client-supplied bounds
	 */
	caddr_t		file_start;
	size_t		file_size;
	caddr_t		file_end;	/* file_start + file_size */

	/*
	 * File information
	 */
	unsigned	file_magic;	/* magic number of file */
	int		file_native;	/* endian flag */

	/* file header */
	tnf_ref32_t	*file_header;	/* first record in file */
	size_t		block_size;	/* size of a block */
	size_t		directory_size;	/* size of directory area */

	unsigned	block_count;	/* number of data blocks */
	caddr_t		data_start;	/* file_start + 64KB */

	unsigned	generation_shift;
	unsigned	address_mask;

	/* block headers */
	unsigned	block_shift;	/* index -> bhdr */
	unsigned	block_mask;	/* ptr -> bhdr */
	unsigned	block_generation_offset;
	unsigned	block_bytes_valid_offset;

	/* root tag */
	tnf_ref32_t	*root_tag;

	/* important taginfo */
	struct taginfo	*file_header_info;
	struct taginfo	*block_header_info;

	/* tag lookup tables */
	struct taginfo	**tag_table;	/* by address */
	struct taginfo	**tag_directory; /* by index */

};

/*
 * File operations for reading integers
 */

#define	_GET_UINT32(tnf, ptr)				\
	((tnf)->file_native ?				\
		*(tnf_uint32_t *)(ptr) :		\
		_tnf_swap32(*(tnf_uint32_t *)(ptr)))

#define	_GET_INT32(tnf, ptr)				\
	((tnf_int32_t)_GET_UINT32(tnf, ptr))

#define	_GET_UINT16(tnf, ptr)				\
	((tnf)->file_native ?				\
		*(tnf_uint16_t *)(ptr) :		\
		_tnf_swap16(*(tnf_uint16_t *)(ptr)))

#define	_GET_INT16(tnf, ptr)				\
	((tnf_int16_t)_GET_UINT16(tnf, ptr))

/*
 * TNF reference-chasing operations
 */

tnf_ref32_t * _tnf_get_ref32(TNF *, tnf_ref32_t *);
tnf_ref32_t * _tnf_get_ref16(TNF *, tnf_ref32_t *);

#define	_GET_REF32(tnf, ptr)	_tnf_get_ref32(tnf, ptr)
#define	_GET_REF16(tnf, ptr)	_tnf_get_ref16(tnf, ptr)

/*
 * Block header record operations
 * Only applicable in data area
 */

#define	_GET_BLOCK(tnf, ptr)					\
	((tnf_ref32_t *)((unsigned)(ptr) & (tnf)->block_mask))

#define	_GET_BLOCK_INDEX(tnf, bhdr)				\
	(((caddr_t)(bhdr) - (tnf)->data_start) >> (tnf)->block_shift)

#define	_GET_INDEX_BLOCK(tnf, index)				\
	((tnf_ref32_t *)((tnf)->data_start + ((index) << (tnf)->block_shift)))

#define	_GET_BLOCK_GENERATION(tnf, bhdr)			\
	_GET_UINT32(tnf, (caddr_t)bhdr + tnf->block_generation_offset)

#define	_GET_BLOCK_BYTES_VALID(tnf, bhdr)			\
	(!(bhdr) ? 0 : _GET_UINT16(tnf, (caddr_t)bhdr +		\
				tnf->block_bytes_valid_offset))

/*
 * Datum operations
 */

#ifndef	_DATUM_MACROS

tnf_datum_t _tnf_datum(struct taginfo *, caddr_t);
struct taginfo * _tnf_datum_info(tnf_datum_t);
caddr_t	_tnf_datum_val(tnf_datum_t);

#define	DATUM(x, y)	_tnf_datum(x, y)
#define	DATUM_INFO(x)	_tnf_datum_info(x)
#define	DATUM_VAL(x)	_tnf_datum_val(x)

#else  /* _DATUM_MACROS */

/* Some degree of type safety: */
#define	DATUM(x, y)	_DATUM((uintptr_t)&(x)->INFO_MEMBER_0, y)
#define	DATUM_INFO(d)	((struct taginfo *)_DATUM_HI(d))
#define	DATUM_VAL(d)	((caddr_t)_DATUM_LO(d))

#endif /* _DATUM_MACROS */

#define	_DATUM(hi, lo)	(((unsigned long long)(hi) << 32) | (unsigned)(lo))
#define	_DATUM_HI(x) 	((unsigned) ((x) >> 32))
#define	_DATUM_LO(x) 	((unsigned) (x))

#define	DATUM_RECORD(x)		\
	((tnf_ref32_t *)DATUM_VAL(x))

#define	RECORD_DATUM(tnf, rec)	\
	DATUM(_tnf_record_info(tnf, rec), (caddr_t)rec)

#define	DATUM_TNF(x)		DATUM_INFO(x)->tnf
#define	DATUM_TAG(x)		DATUM_INFO(x)->tag

/*
 * Type checking operations
 */

void _tnf_check_datum(tnf_datum_t);
#define	CHECK_DATUM(x)	_tnf_check_datum(x)

void _tnf_check_record(tnf_datum_t);
#define	CHECK_RECORD(x)	_tnf_check_record(x)

void _tnf_check_slots(tnf_datum_t);
#define	CHECK_SLOTS(x)	_tnf_check_slots(x)

void _tnf_check_array(tnf_datum_t);
#define	CHECK_ARRAY(x)	_tnf_check_array(x)

void _tnf_check_type(tnf_datum_t);
#define	CHECK_TYPE(x)	_tnf_check_type(x)

/*
 * Operations based on ABI layouts and bootstrap assumptions
 */

tnf_ref32_t * _tnf_get_tag(TNF *, tnf_ref32_t *);
tnf_ref32_t * _tnf_get_tag_arg(TNF *, tnf_ref32_t *);
size_t _tnf_get_self_size(TNF *, tnf_ref32_t *);
unsigned _tnf_get_element_count(TNF *, tnf_ref32_t *, unsigned);
caddr_t _tnf_get_elements(TNF *, tnf_ref32_t *);
char * _tnf_get_chars(TNF *, tnf_ref32_t *);
char * _tnf_get_name(TNF *, tnf_ref32_t *);
tnf_ref32_t * _tnf_get_properties(TNF *, tnf_ref32_t *);
tnf_ref32_t * _tnf_get_slot_types(TNF *, tnf_ref32_t *);
size_t _tnf_get_header_size(TNF *, tnf_ref32_t *);
tnf_ref32_t * _tnf_get_derived_base(TNF *, tnf_ref32_t *);

tnf_ref32_t * _tnf_get_root_tag(TNF *, tnf_ref32_t *);
tnf_ref32_t * _tnf_get_property(TNF *, tnf_ref32_t *, char *);
tnf_ref32_t * _tnf_get_element_named(TNF *, tnf_ref32_t *, char *);
tnf_ref32_t * _tnf_get_base_tag(TNF *, tnf_ref32_t *);

size_t _tnf_get_storage_size(TNF *, tnf_ref32_t *);
size_t _tnf_get_ref_size(TNF *, tnf_ref32_t *);

unsigned _tnf_get_align(TNF *, tnf_ref32_t *);

caddr_t	_tnf_get_slot_typed(TNF *, tnf_ref32_t *, char *);
caddr_t	_tnf_get_slot_named(TNF *, tnf_ref32_t *, char *);

#define	HAS_PROPERTY(tnf, tag, name)	\
	(_tnf_get_property(tnf, tag, name) != TNF_NULL)

/*
 * Call the installed error handler with installed arg
 */

void _tnf_error(TNF *, tnf_errcode_t);

/*
 * Tag lookup operations
 */

struct taginfo * _tnf_get_info(TNF *, tnf_ref32_t *);
struct taginfo * _tnf_record_info(TNF *, tnf_ref32_t *);

tnf_errcode_t _tnf_init_tags(TNF *);
tnf_errcode_t _tnf_fini_tags(TNF *);

/*
 * Classify a tag into its props and data kind
 */

tag_props_t _tnf_get_props(TNF *, tnf_ref32_t *);
tnf_kind_t _tnf_get_kind(TNF *, tnf_ref32_t *);

caddr_t	_tnf_get_member(TNF *, caddr_t, struct taginfo *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBTNF_H */
