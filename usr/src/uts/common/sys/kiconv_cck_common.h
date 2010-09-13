/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_KICONV_CCK_COMMON_H
#define	_SYS_KICONV_CCK_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/* The start value of leading byte of EUC encoding. */
#define	KICONV_EUC_START		(0xA1)

/* Valid EUC range or not. */
#define	KICONV_IS_VALID_EUC_BYTE(v)	((v) >= 0xA1 &&	(v) <= 0xFE)

/* Is ASCII character or not: 0x00 - 0x7F. */
#define	KICONV_IS_ASCII(c)		(((uchar_t)(c)) <= 0x7F)

/* UTF-8 replacement character for non-identicals and its length. */
#define	KICONV_UTF8_REPLACEMENT_CHAR1		(0xEF)
#define	KICONV_UTF8_REPLACEMENT_CHAR2		(0xBF)
#define	KICONV_UTF8_REPLACEMENT_CHAR3		(0xBD)
#define	KICONV_UTF8_REPLACEMENT_CHAR		(0xefbfbd)
#define	KICONV_UTF8_REPLACEMENT_CHAR_LEN	(3)

/*
 * Whether the 2nd byte of 3 or 4 bytes UTF-8 character is invalid or not.
 */
#define	KICONV_IS_INVALID_UTF8_SECOND_BYTE(second, first)		\
	    ((second) < u8_valid_min_2nd_byte[(first)] ||		\
	    (second) > u8_valid_max_2nd_byte[(first)])

/*
 * If we haven't checked on the UTF-8 signature BOM character in
 * the beginning of the conversion data stream, we check it and if
 * find one, we skip it since we have no use for it.
 */
#define	KICONV_CHECK_UTF8_BOM(ib, ibtail)				\
	if (((kiconv_state_t)kcd)->bom_processed == 0 &&		\
		((ibtail) - (ib)) >= 3 && *(ib) == 0xef &&		\
		*((ib) + 1) == 0xbb &&	*((ib) + 2) == 0xbf) {		\
		(ib) += 3;						\
	}								\
	((kiconv_state_t)kcd)->bom_processed = 1

/*
 * Check BOM of UTF-8 without state information.
 */
#define	KICONV_CHECK_UTF8_BOM_WITHOUT_STATE(ib, ibtail)			\
	if (((ibtail) - (ib)) >= 3 && *(ib) == 0xef &&			\
		*((ib) + 1) == 0xbb && *((ib) + 2) == 0xbf) {		\
		(ib) += 3;						\
	}

/*
 * Set errno and break.
 */
#define	KICONV_SET_ERRNO_AND_BREAK(err)					\
	*errno = (err);							\
	ret_val = (size_t)-1;						\
	break

/*
 * Handling flag, advance input buffer, set errno and break.
 */
#define	KICONV_SET_ERRNO_WITH_FLAG(advance, err)			\
	if (flag & KICONV_REPLACE_INVALID) {				\
		ib += (advance);					\
		goto REPLACE_INVALID;					\
	}								\
	KICONV_SET_ERRNO_AND_BREAK((err))

/* Conversion table for UTF-8 -> CCK encoding. */
typedef struct {
	uint32_t key;
	uint32_t value;
} kiconv_table_t;

/* Conversion table for CCK encoding -> utf8. */
typedef struct {
	uint32_t key;
	uchar_t u8[4];
} kiconv_table_array_t;

/*
 * Function prototype for UTF-8 -> GB18030/BIG5/EUC-TW/UHC...
 * Currently parameter ib/ibtail are used by BIG5HKSCS only.
 */
typedef int8_t (*kiconv_utf8tocck_t)(uint32_t utf8, uchar_t **ib,
	uchar_t *ibtail, uchar_t *ob, uchar_t *obtail, size_t *ret_val);

/* Common open and close function for UTF-8 to CCK conversion. */
void * 	kiconv_open_to_cck(void);
int    	kiconv_close_to_cck(void *);

/* Binary search funciton. */
size_t	kiconv_binsearch(uint32_t key, void *tbl, size_t nitems);

/* Wrapper for conversion from UTF-8 to GB18030/BIG5/EUC-TW/UHC... */
size_t 	kiconv_utf8_to_cck(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno,
	kiconv_utf8tocck_t ptr_utf8tocck);

/*
 * Wrapper for string based conversion from UTF-8 to GB18030/BIG5/EUC-TW/UHC...
 */
size_t 	kiconvstr_utf8_to_cck(uchar_t *inarray, size_t *inlen,
	uchar_t *outarray, size_t *outlen, int flag, int *errno,
	kiconv_utf8tocck_t ptr_utf8tocck);

/*
 * The following tables are coming from u8_textprep.c. We use them to
 * check on validity of UTF-8 characters and their bytes.
 */
extern const int8_t u8_number_of_bytes[];
extern const uint8_t u8_valid_min_2nd_byte[];
extern const uint8_t u8_valid_max_2nd_byte[];

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_KICONV_CCK_COMMON_H */
