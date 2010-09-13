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

#ifndef _TNF_TNF_H
#define	_TNF_TNF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <tnf/com.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque TNF handle
 */

typedef struct TNF	TNF;

/*
 * Opaque data handle
 */

typedef	unsigned long long	tnf_datum_t;

#define	TNF_DATUM_NULL	((tnf_datum_t)0)

/*
 * Reader data classification
 */

typedef enum {
	TNF_K_UNKNOWN,			/* unknown or error */
	TNF_K_SCALAR,			/* unclassified scalar */
	TNF_K_CHAR,			/* char */
	TNF_K_INT8,			/* int8 */
	TNF_K_INT16,			/* int16 */
	TNF_K_INT32,			/* int32 */
	TNF_K_UINT8,			/* uint8 */
	TNF_K_UINT16,			/* uint16 */
	TNF_K_UINT32,			/* uint32 */
	TNF_K_INT64,			/* int64 */
	TNF_K_UINT64,			/* uint64 */
	TNF_K_FLOAT32,			/* float32 */
	TNF_K_FLOAT64,			/* float64 */
	TNF_K_ARRAY,			/* array */
	TNF_K_STRING,			/* string */
	TNF_K_STRUCT,			/* struct */
	TNF_K_TYPE			/* type */
} tnf_kind_t;

/*
 * Error codes
 */

typedef enum {
	TNF_ERR_NONE = 0,

	/* 1 through 1023 reserved for errno values */
#define	TNF_ERRNO_MAX 		1023

	TNF_ERR_NOTTNF 		= 1024,	/* not TNF file */
	TNF_ERR_BADDATUM 	= 1025,	/* bad or NULL data handle */
	TNF_ERR_TYPEMISMATCH 	= 1026,	/* type mismatch */
	TNF_ERR_BADINDEX 	= 1027,	/* array index out of bounds */
	TNF_ERR_BADSLOT 	= 1028,	/* slot missing */
	TNF_ERR_BADREFTYPE 	= 1029,	/* invalid reference type  */
	TNF_ERR_ALLOCFAIL 	= 1030,	/* memory allocation failure */
	TNF_ERR_BADTNF 		= 1031,	/* bad TNF file */
	TNF_ERR_INTERNAL 	= 1032	/* internal error */
} tnf_errcode_t;

typedef void 	tnf_error_handler_t(void *, TNF *, tnf_errcode_t);

/*
 * TNF file interface
 */

tnf_errcode_t	tnf_reader_begin(caddr_t, size_t, TNF **);
tnf_errcode_t	tnf_reader_end(TNF *);

/*
 * Error interface
 */

void		tnf_set_error_handler(tnf_error_handler_t *, void *);
char *		tnf_error_message(tnf_errcode_t);

tnf_error_handler_t	tnf_default_error_handler;

/*
 * Data block access
 */

unsigned	tnf_get_block_count(TNF *);
tnf_datum_t	tnf_get_block_absolute(TNF *, unsigned);
tnf_datum_t	tnf_get_block_relative(tnf_datum_t, int);
int		tnf_is_block_header(tnf_datum_t);

/*
 * Record access
 */

tnf_datum_t	tnf_get_next_record(tnf_datum_t);
tnf_datum_t	tnf_get_block_header(tnf_datum_t);
tnf_datum_t	tnf_get_file_header(TNF *);

/*
 * Data classification predicates
 */

int		tnf_is_inline(tnf_datum_t);
int		tnf_is_scalar(tnf_datum_t);
int		tnf_is_record(tnf_datum_t);
int		tnf_is_array(tnf_datum_t);
int		tnf_is_string(tnf_datum_t);
int		tnf_is_struct(tnf_datum_t);
int		tnf_is_type(tnf_datum_t);

/*
 * Data operations
 */

tnf_kind_t	tnf_get_kind(tnf_datum_t);
size_t		tnf_get_size(tnf_datum_t);
tnf_datum_t	tnf_get_type(tnf_datum_t);
char *		tnf_get_type_name(tnf_datum_t);
caddr_t		tnf_get_raw(tnf_datum_t);

/*
 * Record operations
 */

tnf_datum_t	tnf_get_tag_arg(tnf_datum_t);

/*
 * Array operations
 */

unsigned	tnf_get_element_count(tnf_datum_t);
tnf_datum_t	tnf_get_element(tnf_datum_t, unsigned);
tnf_datum_t	tnf_get_element_type(tnf_datum_t);
caddr_t		tnf_get_elements(tnf_datum_t);
char *		tnf_get_chars(tnf_datum_t);

/*
 * Struct operations
 */

unsigned	tnf_get_slot_count(tnf_datum_t);
char *		tnf_get_slot_name(tnf_datum_t, unsigned);
unsigned	tnf_get_slot_index(tnf_datum_t, char *);
tnf_datum_t	tnf_get_slot_named(tnf_datum_t, char *);
tnf_datum_t	tnf_get_slot_indexed(tnf_datum_t, unsigned);

/*
 * Scalar data conversions
 */

char		tnf_get_char(tnf_datum_t);
tnf_int8_t	tnf_get_int8(tnf_datum_t);
tnf_int16_t	tnf_get_int16(tnf_datum_t);
tnf_int32_t	tnf_get_int32(tnf_datum_t);
tnf_int64_t	tnf_get_int64(tnf_datum_t);
tnf_float32_t	tnf_get_float32(tnf_datum_t);
tnf_float64_t	tnf_get_float64(tnf_datum_t);

/*
 * Type (tag) record operations
 */

tnf_kind_t	tnf_type_get_kind(tnf_datum_t);
char *		tnf_type_get_name(tnf_datum_t);
size_t		tnf_type_get_size(tnf_datum_t);
tnf_datum_t	tnf_type_get_property(tnf_datum_t, char *);
tnf_datum_t	tnf_type_get_base(tnf_datum_t);

#ifdef __cplusplus
}
#endif

#endif /* _TNF_TNF_H */
