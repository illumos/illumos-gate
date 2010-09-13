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

#ifndef	_SYS_TNF_COM_H
#define	_SYS_TNF_COM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NOTE: All types are in host (not necessarily file) format.
 * Readers are responsible for endian or other transformation.
 */

/*
 * Magic number(s): first word of TNF file.
 *
 * A writer stores the native unsigned 32-bit integer TNF_MAGIC.
 * A same-endian reader will load it as TNF_MAGIC.
 * A different-endian reader will load it as TNF_MAGIC_1.
 */

#define	TNF_MAGIC		0x544e4600
#define	TNF_MAGIC_1		0x00464e54

/*
 * Fundamental types.  Machine dependent.
 */

typedef char			tnf_char_t;
typedef signed char		tnf_int8_t;
typedef unsigned char		tnf_uint8_t;
typedef short			tnf_int16_t;
typedef unsigned short		tnf_uint16_t;
typedef int			tnf_int32_t;
typedef unsigned int		tnf_uint32_t;
typedef longlong_t		tnf_int64_t;
typedef u_longlong_t		tnf_uint64_t;
typedef float			tnf_float32_t;
typedef double			tnf_float64_t;

/*
 * TNF references
 */

typedef tnf_int32_t		tnf_ref32_t; /* self-relative, 32 bits */
typedef tnf_int16_t		tnf_ref16_t; /* self-relative, 16 bits */
typedef tnf_uint16_t		tnf_abs16_t; /* absolute, 16 bits */

/* Generation number for tag blocks */
#define	TNF_TAG_GENERATION_NUM	0xffffffff

/* definition of space values */
#define	TNF_SPACE_MASK		0x80000000
#define	TNF_SPACE_PERMANENT	0x80000000
#define	TNF_SPACE_RECLAIMABLE	0x0
#define	TNF_SPACE_SIGN_BIT	0x40000000

/* Macros on setting or checking space values */
#define	TNF_REF32_MAKE_PERMANENT(x)	((x) | TNF_SPACE_PERMANENT)
#define	TNF_REF32_MAKE_RECLAIMABLE(x)	((x) & ~TNF_SPACE_MASK)
#define	TNF_REF32_SPACE(x)	\
	((tnf_uint32_t)(x) & TNF_SPACE_MASK)
#define	TNF_REF32_IS_PERMANENT(x)	\
	(TNF_REF32_SPACE(x) == TNF_SPACE_PERMANENT)
#define	TNF_REF32_IS_RECLAIMABLE(x)	\
	(TNF_REF32_SPACE(x) == TNF_SPACE_RECLAIMABLE)
#define	TNF_REF32_SIGN_EXTEND(x)	\
	((((tnf_uint32_t)(x) & TNF_SPACE_SIGN_BIT) == TNF_SPACE_SIGN_BIT) ? \
		((tnf_ref32_t)((tnf_uint32_t)(x) | TNF_SPACE_MASK)) :   \
		(x))

/* definition of references */
#define	TNF_REF32_TYPE_MASK	0x3
#define	TNF_REF32_T_FULL	0x0
#define	TNF_REF32_T_FWD		TNF_REF32_T_FULL
#define	TNF_REF32_T_PAIR	0x1
#define	TNF_REF32_T_TAG		0x2
#define	TNF_REF32_T_RSVD	0x3

#define	TNF_REF32_REF16_MASK	0xffff

#define	TNF_REF32_TAG16_SHIFT	16
#define	TNF_REF32_TAG16_MASK	0xffff

#define	TNF_REF16_TYPE_MASK	0x3

#define	TNF_TAG16_TYPE_MASK	0x3
#define	TNF_TAG16_T_ABS		TNF_REF32_T_PAIR
#define	TNF_TAG16_T_REL		TNF_REF32_T_FWD

#define	TNF_NULL		0

/* Macros on tnf_ref32_t values: */

#define	TNF_REF32_TYPE(x)	\
	((tnf_uint32_t)(x) & TNF_REF32_TYPE_MASK)
#define	TNF_REF32_VALUE(x)	\
	((tnf_ref32_t)(((tnf_uint32_t)(x) & ~TNF_REF32_TYPE_MASK) & \
					~TNF_SPACE_MASK))

#define	TNF_REF32_IS_FULL(x)	(TNF_REF32_TYPE(x) == TNF_REF32_T_FULL)
#define	TNF_REF32_IS_FWD(x)	(TNF_REF32_TYPE(x) == TNF_REF32_T_FWD)
#define	TNF_REF32_IS_PAIR(x)	(TNF_REF32_TYPE(x) == TNF_REF32_T_PAIR)
#define	TNF_REF32_IS_TAG(x)	(TNF_REF32_TYPE(x) == TNF_REF32_T_TAG)
#define	TNF_REF32_IS_RSVD(x)	(TNF_REF32_TYPE(x) == TNF_REF32_T_RSVD)
#define	TNF_REF32_IS_NULL(x)	((x) == TNF_NULL)

#define	TNF_REF32_REF16(x)	\
	((tnf_ref16_t)((tnf_uint32_t)(x) & TNF_REF32_REF16_MASK))

#define	TNF_REF32_TAG16(x)	\
	((tnf_ref16_t)(((tnf_uint32_t)(x) >> TNF_REF32_TAG16_SHIFT)	\
				& TNF_REF32_TAG16_MASK))

/* Macros on tnf_ref16_t values: */

#define	TNF_REF16_TYPE(x)	\
	((tnf_uint32_t)(x) & TNF_REF16_TYPE_MASK)
#define	TNF_REF16_VALUE(x)	\
	((tnf_ref16_t)((tnf_uint32_t)(x) & ~TNF_REF16_TYPE_MASK))

#define	TNF_TAG16_TYPE(x)	\
	((tnf_uint32_t)(x) & TNF_TAG16_TYPE_MASK)

#define	TNF_TAG16_IS_REL(x)	(TNF_TAG16_TYPE(x) == TNF_TAG16_T_REL)
#define	TNF_TAG16_IS_ABS(x)	(TNF_TAG16_TYPE(x) == TNF_TAG16_T_ABS)

/* The two kinds of values a tag16 can have: */

#define	TNF_TAG16_REF16(x)	\
	((tnf_ref16_t)((tnf_uint32_t)(x) & ~TNF_TAG16_TYPE_MASK))
#define	TNF_TAG16_ABS16(x)	\
	((tnf_abs16_t)((tnf_uint32_t)(x) & ~TNF_TAG16_TYPE_MASK))

/*
 * TNF binary layouts
 */

struct tnf_tagged_hdr {
	tnf_ref32_t	tag;		/* type record */
};

struct tnf_array_hdr {
	tnf_ref32_t	tag;		/* type record */
	tnf_uint32_t 	self_size;	/* total size */
};

struct tnf_type_hdr {
	tnf_ref32_t	tag;		/* type record */
	tnf_ref32_t	name;		/* string record */
	tnf_ref32_t	properties;	/* array of type records */
};

struct tnf_struct_type_hdr {
	tnf_ref32_t	tag;		/* type record */
	tnf_ref32_t	name;		/* string record */
	tnf_ref32_t	properties;	/* array of type records */
	tnf_ref32_t	slot_types;	/* array of type records */
	tnf_uint32_t	type_size;	/* size of struct */
};

struct tnf_array_type_hdr {
	tnf_ref32_t	tag;		/* type record */
	tnf_ref32_t	name;		/* string record */
	tnf_ref32_t	properties;	/* array of type records */
	tnf_ref32_t	slot_types;	/* array of type records */
	tnf_uint32_t	header_size;	/* size of array header */
};

struct tnf_derived_type_hdr {
	tnf_ref32_t	tag;		/* type record */
	tnf_ref32_t	name;		/* string record */
	tnf_ref32_t	properties;	/* array of type records */
	tnf_ref32_t	derived_base;	/* type record */
};

/*
 * File header, after magic #
 */

#define	TNF_FILE_VERSION	1

typedef struct tnf_file_header {
	tnf_ref32_t	tag;
	tnf_uint32_t	file_version;	/* TNF_FILE_VERSION */
	tnf_uint32_t	file_header_size;
	tnf_uint32_t	file_log_size;
	tnf_uint32_t	block_header_size;
	tnf_uint32_t	block_size;
	tnf_uint32_t	directory_size;
	tnf_uint32_t	block_count;
	tnf_uint32_t	blocks_valid;
	/* writer-specific information after this	*/
	/* zero padding to end of block 		*/
} tnf_file_header_t;

/*
 * Block header
 */

typedef unsigned char		tnf_byte_lock_t;

typedef struct tnf_block_header {
	tnf_ref32_t		tag;
	tnf_uint32_t		generation; /* (-1) => tag block */
	tnf_uint16_t		bytes_valid;
	tnf_byte_lock_t		A_lock;
	tnf_byte_lock_t		B_lock;
	struct tnf_block_header	*next_block; /* release list */
} tnf_block_header_t;

/*
 * TNF type names
 */

#define	TNF_N_INLINE		"tnf_inline"
#define	TNF_N_TAGGED		"tnf_tagged"

#define	TNF_N_SCALAR		"tnf_scalar"
#define	TNF_N_CHAR		"tnf_char"
#define	TNF_N_INT8 		"tnf_int8"
#define	TNF_N_UINT8		"tnf_uint8"
#define	TNF_N_INT16		"tnf_int16"
#define	TNF_N_UINT16		"tnf_uint16"
#define	TNF_N_INT32		"tnf_int32"
#define	TNF_N_UINT32		"tnf_uint32"
#define	TNF_N_INT64		"tnf_int64"
#define	TNF_N_UINT64		"tnf_uint64"
#define	TNF_N_FLOAT32		"tnf_float32"
#define	TNF_N_FLOAT64		"tnf_float64"

#define	TNF_N_ARRAY		"tnf_array"
#define	TNF_N_STRING 		"tnf_string"
#define	TNF_N_TYPE_ARRAY	"tnf_type_array"
#define	TNF_N_NAME_ARRAY	"tnf_name_array"

#define	TNF_N_ALIGN		"tnf_align"
#define	TNF_N_DERIVED		"tnf_derived"
#define	TNF_N_DERIVED_BASE	"tnf_derived_base"
#define	TNF_N_ELEMENT_TYPE	"tnf_element_type"
#define	TNF_N_HEADER_SIZE	"tnf_header_size"
#define	TNF_N_NAME		"tnf_name"
#define	TNF_N_OPAQUE		"tnf_opaque"
#define	TNF_N_PROPERTIES	"tnf_properties"
#define	TNF_N_SELF_SIZE		"tnf_self_size"
#define	TNF_N_SIZE		"tnf_size"
#define	TNF_N_SLOT_NAMES	"tnf_slot_names"
#define	TNF_N_SLOT_TYPES	"tnf_slot_types"
#define	TNF_N_TAG		"tnf_tag"
#define	TNF_N_TAG_ARG		"tnf_tag_arg"
#define	TNF_N_TYPE_SIZE		"tnf_type_size"

#define	TNF_N_STRUCT		"tnf_struct"

#define	TNF_N_ARRAY_TYPE	"tnf_array_type"
#define	TNF_N_DERIVED_TYPE	"tnf_derived_type"
#define	TNF_N_SCALAR_TYPE	"tnf_scalar_type"
#define	TNF_N_STRUCT_TYPE	"tnf_struct_type"
#define	TNF_N_TYPE		"tnf_type"

/*
 * Reserved names for block and file header information
 */

#define	TNF_N_FILE_HEADER	"tnf_file_header"
#define	TNF_N_FILE_VERSION	"file_version"
#define	TNF_N_FILE_HEADER_SIZE	"file_header_size"
#define	TNF_N_FILE_LOGICAL_SIZE	"file_logical_size"
#define	TNF_N_BLOCK_HEADER_SIZE	"block_header_size"
#define	TNF_N_BLOCK_SIZE	"block_size"
#define	TNF_N_DIRECTORY_SIZE	"directory_size"
#define	TNF_N_BLOCK_COUNT	"block_count"
#define	TNF_N_BLOCKS_VALID	"blocks_valid"

#define	TNF_N_BLOCK_HEADER	"tnf_block_header"
#define	TNF_N_GENERATION	"generation"
#define	TNF_N_BYTES_VALID	"bytes_valid"

/*
 * Reserved names for schedule record information
 */

#define	TNF_N_USER_SCHEDULE	"tnf_user_schedule"
#define	TNF_N_KERNEL_SCHEDULE	"tnf_kernel_schedule"

#define	TNF_N_PID		"pid"
#define	TNF_N_LWPID		"lwpid"
#define	TNF_N_TID		"tid"
#define	TNF_N_TIME_BASE		"time_base"
#define	TNF_N_TIME_DELTA	"time_delta"

/* XXX TODO: kernel type names */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_TNF_COM_H */
