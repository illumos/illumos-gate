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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/u8_textprep.h>
#include <sys/kiconv.h>
#include <sys/kiconv_cck_common.h>
#include <sys/kiconv_tc.h>
#include <sys/kiconv_big5_utf8.h>
#include <sys/kiconv_euctw_utf8.h>
#include <sys/kiconv_hkscs_utf8.h>
#include <sys/kiconv_cp950hkscs_utf8.h>
#include <sys/kiconv_utf8_big5.h>
#include <sys/kiconv_utf8_euctw.h>
#include <sys/kiconv_utf8_cp950hkscs.h>
#include <sys/kiconv_utf8_hkscs.h>

/* 4 HKSCS-2004 code points map to 2 Unicode code points separately. */
static uchar_t hkscs_special_sequence[][4] = {
	{ 0xc3, 0x8a, 0xcc, 0x84 },	/* 0x8862 */
	{ 0xc3, 0x8a, 0xcc, 0x8c },	/* 0x8864 */
	{ 0xc3, 0xaa, 0xcc, 0x84 },	/* 0x88a3 */
	{ 0xc3, 0xaa, 0xcc, 0x8c } 	/* 0x88a5 */
};

/* 4 Unicode code point pair map to 1 HKSCS-2004 code point. */
static uint32_t ucs_special_sequence[] = {
	0x8866,		/* U+00ca */
	0x8862,		/* U+00ca U+0304 */
	0x8864,		/* U+00ca U+030c */
	0x88a7,		/* U+00ea */
	0x88a3,		/* U+00ea U+0304 */
	0x88a5		/* U+00ea U+030c */
};

typedef int8_t (*kiconv_big5toutf8_t)(uint32_t value, uchar_t *ob,
	uchar_t *obtail, size_t *ret_val);

static int8_t utf8_to_big5(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val);
static int8_t utf8_to_euctw(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val);
static int8_t utf8_to_cp950hkscs(uint32_t utf8, uchar_t **inbuf,
	uchar_t *ibtail, uchar_t *ob, uchar_t *obtail, size_t *ret_val);
static int8_t utf8_to_big5hkscs(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val);
static int8_t big5_to_utf8(uint32_t big5_val, uchar_t *ob, uchar_t *obtail,
	size_t *ret_val);
static int8_t big5hkscs_to_utf8(uint32_t hkscs_val, uchar_t *ob,
	uchar_t *obtail, size_t *ret_val);
static int8_t cp950hkscs_to_utf8(uint32_t hkscs_val, uchar_t *ob,
	uchar_t *obtail, size_t *ret_val);
static int8_t euctw_to_utf8(size_t plane_no, uint32_t euctw_val,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val);
static uint32_t get_unicode_from_UDA(size_t plane_no, uchar_t byte1,
	uchar_t byte2);

#define	KICONV_TC_BIG5		(0x01)
#define	KICONV_TC_BIG5HKSCS	(0x02)
#define	KICONV_TC_CP950HKSCS	(0x03)
#define	KICONV_TC_EUCTW		(0x04)
#define	KICONV_TC_MAX_MAGIC_ID	(0x04)

static void *
open_fr_big5()
{
	return ((void *)KICONV_TC_BIG5);
}

static void *
open_fr_big5hkscs()
{
	return ((void *)KICONV_TC_BIG5HKSCS);
}

static void *
open_fr_cp950hkscs()
{
	return ((void *)KICONV_TC_CP950HKSCS);
}

static void *
open_fr_euctw()
{
	return ((void *)KICONV_TC_EUCTW);
}

static int
close_fr_tc(void *s)
{
	if ((uintptr_t)s > KICONV_TC_MAX_MAGIC_ID)
		return (EBADF);

	return (0);
}

/*
 * Common convertor from BIG5/HKSCS(BIG5-HKSCS or CP950-HKSCS) to UTF-8.
 */
static size_t
kiconv_fr_big5_common(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno,
	kiconv_big5toutf8_t ptr_big5touf8)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	big5_val;

	/* Check on the kiconv code conversion descriptor. */
	if (kcd == NULL || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/* If this is a state reset request, process and return. */
	if (inbuf == NULL || *inbuf == NULL) {
		return (0);
	}

	ret_val = 0;
	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbytesleft;
	obtail = ob + *outbytesleft;

	while (ib < ibtail) {
		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		/*
		 * Issue EILSEQ error if the first byte is not a
		 * valid BIG5/HKSCS leading byte.
		 */
		if (! KICONV_TC_IS_BIG5_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		/*
		 * Issue EINVAL error if input buffer has an incomplete
		 * character at the end of the buffer.
		 */
		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_AND_BREAK(EINVAL);
		}

		/*
		 * Issue EILSEQ error if the remaining bytes is not
		 * a valid BIG5/HKSCS byte.
		 */
		if (! KICONV_TC_IS_BIG5_2nd_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		/* Now we have a valid BIG5/HKSCS character. */
		big5_val = (uint32_t)(*ib) << 8 | *(ib + 1);
		sz = ptr_big5touf8(big5_val, ob, obtail, &ret_val);

		if (sz < 0) {
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ib += 2;
		ob += sz;
	}

	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}

/*
 * String based Common convertor from BIG5/HKSCS(BIG5-HKSCS or CP950-HKSCS)
 * to UTF-8.
 */
static size_t
kiconvstr_fr_big5_common(uchar_t *ib, size_t *inlen, uchar_t *ob,
    size_t *outlen, int flag, int *errno,
    kiconv_big5toutf8_t ptr_big5touf8)
{
	uchar_t		*oldib;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	big5_val;
	boolean_t	do_not_ignore_null;

	ret_val = 0;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ib < ibtail) {
		if (*ib == '\0' && do_not_ignore_null)
			break;

		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		oldib = ib;

		if (! KICONV_TC_IS_BIG5_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EINVAL);
		}

		if (! KICONV_TC_IS_BIG5_2nd_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_WITH_FLAG(2, EILSEQ);
		}

		big5_val = *ib++;
		big5_val = (big5_val << 8) | *ib++;
		sz = ptr_big5touf8(big5_val, ob, obtail, &ret_val);

		if (sz < 0) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ob += sz;
		continue;

REPLACE_INVALID:
		if (obtail - ob < KICONV_UTF8_REPLACEMENT_CHAR_LEN) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR1;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR2;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR3;
		ret_val++;
	}

	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * Encoding convertor from BIG5 to UTF-8.
 */
static size_t
kiconv_fr_big5(void *kcd, char **inbuf, size_t *inbytesleft, char **outbuf,
	size_t *outbytesleft, int *errno)
{
	return (kiconv_fr_big5_common(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, big5_to_utf8));
}

/*
 * String based encoding convertor from BIG5 to UTF-8.
 */
static size_t
kiconvstr_fr_big5(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_big5_common((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno,
	    big5_to_utf8));
}

/*
 * Encoding convertor from BIG5-HKSCS to UTF-8.
 */
static size_t
kiconv_fr_big5hkscs(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	return kiconv_fr_big5_common(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, big5hkscs_to_utf8);
}

/*
 * String based encoding convertor from BIG5-HKSCS to UTF-8.
 */
static size_t
kiconvstr_fr_big5hkscs(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return kiconvstr_fr_big5_common((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, big5hkscs_to_utf8);
}

/*
 * Encoding convertor from CP950-HKSCS to UTF-8.
 */
static size_t
kiconv_fr_cp950hkscs(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	return kiconv_fr_big5_common(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, cp950hkscs_to_utf8);
}

/*
 * String based encoding convertor from CP950-HKSCS to UTF-8.
 */
static size_t
kiconvstr_fr_cp950hkscs(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return kiconvstr_fr_big5_common((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, cp950hkscs_to_utf8);
}

/*
 * Encoding convertor from EUC-TW to UTF-8.
 */
static size_t
kiconv_fr_euctw(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	size_t		plane_no;
	int8_t		sz;
	uint32_t	euctw_val;
	boolean_t	isplane1;

	/* Check on the kiconv code conversion descriptor. */
	if (kcd == NULL || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/* If this is a state reset request, process and return. */
	if (inbuf == NULL || *inbuf == NULL) {
		return (0);
	}

	ret_val = 0;
	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbytesleft;
	obtail = ob + *outbytesleft;

	while (ib < ibtail) {
		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		/*
		 * Issue EILSEQ error if the first byte is not a
		 * valid EUC-TW leading byte.
		 */
		if (! KICONV_TC_IS_EUCTW_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		isplane1 = (*ib == KICONV_TC_EUCTW_MBYTE) ?
		    B_FALSE : B_TRUE;

		/*
		 * Issue EINVAL error if input buffer has an incomplete
		 * character at the end of the buffer.
		 */
		if (ibtail - ib < (isplane1 ? 2 : 4)) {
			KICONV_SET_ERRNO_AND_BREAK(EINVAL);
		}

		oldib = ib;
		plane_no = isplane1 ? 1 : *(ib + 1) - KICONV_TC_EUCTW_PMASK;

		/*
		 * Issue EILSEQ error if the remaining bytes are not
		 * valid EUC-TW bytes.
		 */
		if (! KICONV_TC_IS_VALID_EUCTW_SEQ(ib)) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		if (! isplane1)
			ib += 2;

		/* Now we have a valid EUC-TW character. */
		euctw_val = *ib++;
		euctw_val = (euctw_val << 8) | *ib++;
		sz = euctw_to_utf8(plane_no, euctw_val, ob, obtail, &ret_val);

		if (sz < 0) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ob += sz;
	}

	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}

/*
 * String based encoding convertor from EUC-TW to UTF-8.
 */
static size_t
kiconvstr_fr_euctw(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	size_t		plane_no;
	int8_t		sz;
	uint32_t	euctw_val;
	boolean_t	isplane1;
	boolean_t	do_not_ignore_null;

	ret_val = 0;
	ib = (uchar_t *)inarray;
	ob = (uchar_t *)outarray;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ib < ibtail) {
		if (*ib == '\0' && do_not_ignore_null)
			break;

		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		oldib = ib;

		if (! KICONV_TC_IS_EUCTW_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		isplane1 = (*ib == KICONV_TC_EUCTW_MBYTE) ?
		    B_FALSE : B_TRUE;

		if (ibtail - ib < (isplane1 ? 2 : 4)) {
			if (flag & KICONV_REPLACE_INVALID) {
				ib = ibtail;
				goto REPLACE_INVALID;
			}

			KICONV_SET_ERRNO_AND_BREAK(EINVAL);
		}

		plane_no = isplane1 ? 1 : *(ib + 1) - KICONV_TC_EUCTW_PMASK;

		if (! KICONV_TC_IS_VALID_EUCTW_SEQ(ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(isplane1 ? 2 : 4, EILSEQ);
		}

		if (! isplane1)
			ib += 2;

		euctw_val = *ib++;
		euctw_val = (euctw_val << 8) | *ib++;
		sz = euctw_to_utf8(plane_no, euctw_val, ob, obtail, &ret_val);

		if (sz < 0) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ob += sz;
		continue;

REPLACE_INVALID:
		if (obtail - ob < KICONV_UTF8_REPLACEMENT_CHAR_LEN) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR1;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR2;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR3;
		ret_val++;
	}

	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * Encoding convertor from UTF-8 to BIG5.
 */
static size_t
kiconv_to_big5(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	return kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_big5);
}

/*
 * String based encoding convertor from UTF-8 to BIG5.
 */
static size_t
kiconvstr_to_big5(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_big5);
}

/*
 * Encoding convertor from UTF-8 to EUC-TW.
 */
static size_t
kiconv_to_euctw(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	return kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_euctw);
}

/*
 * String based encoding convertor from UTF-8 to EUC-TW.
 */
static size_t
kiconvstr_to_euctw(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_euctw);
}

/*
 * Encoding convertor from UTF-8 to CP950HKSCS.
 */
static size_t
kiconv_to_cp950hkscs(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	return kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_cp950hkscs);
}

/*
 * String based encoding convertor from UTF-8 to CP950HKSCS.
 */
static size_t
kiconvstr_to_cp950hkscs(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_cp950hkscs);
}

/*
 * Encoding convertor from UTF-8 to BIG5HKSCS(HKSCS-2004).
 */
static size_t
kiconv_to_big5hkscs(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	return kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_big5hkscs);
}

/*
 * String based encoding convertor from UTF-8 to BIG5HKSCS(HKSCS-2004).
 */
static size_t
kiconvstr_to_big5hkscs(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_big5hkscs);
}

/*
 * Common convertor from single BIG5/CP950-HKSCS character to UTF-8.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
static int8_t
big5_to_utf8_common(uint32_t big5_val, uchar_t *ob, uchar_t *obtail,
	size_t *ret_val, kiconv_table_array_t *table, size_t nitems)
{
	size_t	index;
	int8_t	sz;
	uchar_t	*u8;

	index = kiconv_binsearch(big5_val, table, nitems);
	u8 = table[index].u8;
	sz = u8_number_of_bytes[u8[0]];

	if (obtail - ob < sz) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret_val)++;	/* Non-identical conversion */

	for (index = 0; index < sz; index++)
		*ob++ = u8[index];

	return (sz);
}

/*
 * Convert single BIG5 character to UTF-8.
 */
static int8_t
big5_to_utf8(uint32_t big5_val, uchar_t *ob, uchar_t *obtail, size_t *ret_val)
{
	return (big5_to_utf8_common(big5_val, ob, obtail, ret_val,
	    kiconv_big5_utf8, KICONV_BIG5_UTF8_MAX));
}

/*
 * Convert single CP950-HKSCS character to UTF-8.
 */
static int8_t
cp950hkscs_to_utf8(uint32_t hkscs_val, uchar_t *ob, uchar_t *obtail,
	size_t *ret_val)
{
	return (big5_to_utf8_common(hkscs_val, ob, obtail, ret_val,
	    kiconv_cp950hkscs_utf8, KICONV_CP950HKSCS_UTF8_MAX));
}

/*
 * Calculate unicode value for some CNS planes which fall in Unicode
 * UDA range.
 */
static uint32_t
get_unicode_from_UDA(size_t plane_no, uchar_t b1, uchar_t b2)
{
	/*
	 * CNS Plane 15 is pre-allocated, so need move Plane 16 to back 15
	 * to compute the Unicode value.
	 */
	if (plane_no == 16)
		--plane_no;

	/* 0xF0000 + (plane_no - 12) * 8836 + (b1 - 0xA1) * 94 + (b2 - 0xA1) */
	return (8836 * plane_no + 94 * b1 + b2 + 0xD2611);
}

/*
 * Convert single EUC-TW character to UTF-8.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
static int8_t
euctw_to_utf8(size_t plane_no, uint32_t euctw_val, uchar_t *ob,
	uchar_t *obtail, size_t *ret_val)
{
	uint32_t u32;
	size_t	index;
	int8_t	sz;
	uchar_t	udc[4];
	uchar_t	*u8;

	switch (plane_no) {
	case 1:
		index = kiconv_binsearch(euctw_val, kiconv_cns1_utf8,
		    KICONV_CNS1_UTF8_MAX);
		u8 = kiconv_cns1_utf8[index].u8;
		break;
	case 2:
		index = kiconv_binsearch(euctw_val, kiconv_cns2_utf8,
		    KICONV_CNS2_UTF8_MAX);
		u8 = kiconv_cns2_utf8[index].u8;
		break;
	case 3:
		index = kiconv_binsearch(euctw_val, kiconv_cns3_utf8,
		    KICONV_CNS3_UTF8_MAX);
		u8 = kiconv_cns3_utf8[index].u8;
		break;
	case 4:
		index = kiconv_binsearch(euctw_val, kiconv_cns4_utf8,
		    KICONV_CNS4_UTF8_MAX);
		u8 = kiconv_cns4_utf8[index].u8;
		break;
	case 5:
		index = kiconv_binsearch(euctw_val, kiconv_cns5_utf8,
		    KICONV_CNS5_UTF8_MAX);
		u8 = kiconv_cns5_utf8[index].u8;
		break;
	case 6:
		index = kiconv_binsearch(euctw_val, kiconv_cns6_utf8,
		    KICONV_CNS6_UTF8_MAX);
		u8 = kiconv_cns6_utf8[index].u8;
		break;
	case 7:
		index = kiconv_binsearch(euctw_val, kiconv_cns7_utf8,
		    KICONV_CNS7_UTF8_MAX);
		u8 = kiconv_cns7_utf8[index].u8;
		break;
	case 12:
	case 13:
	case 14:
	case 16:
		u32 = get_unicode_from_UDA(plane_no,
		    (euctw_val & 0xFF00) >> 8, euctw_val & 0xFF);
		/*
		 * As U+F0000 <= u32 <= U+F8A0F, so its UTF-8 sequence
		 * will occupy 4 bytes.
		 */
		udc[0] = 0xF3;
		udc[1] = (uchar_t)(0x80 | (u32 & 0x03F000) >> 12);
		udc[2] = (uchar_t)(0x80 | (u32 & 0x000FC0) >> 6);
		udc[3] = (uchar_t)(0x80 | (u32 & 0x00003F));
		u8 = udc;
		index = 1;
		break;
	case 15:
		index = kiconv_binsearch(euctw_val, kiconv_cns15_utf8,
		    KICONV_CNS15_UTF8_MAX);
		u8 = kiconv_cns15_utf8[index].u8;
		break;
	default:
		index = 0;
		u8 = kiconv_cns1_utf8[index].u8;
	}

	sz = u8_number_of_bytes[u8[0]];
	if (obtail - ob < sz) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret_val)++;

	for (index = 0; index < sz; index++)
		*ob++ = u8[index];

	return (sz);
}

/*
 * Convert single HKSCS character to UTF-8.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
static int8_t
big5hkscs_to_utf8(uint32_t hkscs_val, uchar_t *ob, uchar_t *obtail,
	size_t *ret_val)
{
	size_t	index;
	int8_t	sz;
	uchar_t	*u8;

	index = kiconv_binsearch(hkscs_val, kiconv_hkscs_utf8,
	    KICONV_HKSCS_UTF8_MAX);
	u8 = kiconv_hkscs_utf8[index].u8;

	/*
	 * Single HKSCS-2004 character may map to 2 Unicode
	 * code points.
	 */
	if (u8[0] == 0xFF) {
		u8 = hkscs_special_sequence[u8[1]];
		sz = 4;
	} else {
		sz = u8_number_of_bytes[u8[0]];
	}

	if (obtail - ob < sz) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret_val)++;	/* Non-identical conversion. */

	for (index = 0; index < sz; index++)
		*ob++ = u8[index];

	return (sz);
}

/*
 * Convert single UTF-8 character to EUC-TW.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
/* ARGSUSED */
static int8_t
utf8_to_euctw(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val)
{
	size_t		index;
	size_t		plane_no;
	uchar_t		byte1;
	uchar_t		byte2;

	if (utf8 >= KICONV_TC_UDA_UTF8_START &&
	    utf8 <= KICONV_TC_UDA_UTF8_END) {
		/*
		 * Calculate EUC-TW code if utf8 is in Unicode
		 * Private Plane 15.
		 */
		index = (((utf8 & 0x7000000) >> 6) | ((utf8 & 0x3F0000) >> 4) |
		    ((utf8 & 0x3F00) >> 2) | (utf8 & 0x3F)) -
		    KICONV_TC_UDA_UCS4_START;
		plane_no = 12 + index / 8836;
		byte1 = 0xA1 + (index % 8836) / 94;
		byte2 = 0xA1 + index % 94;

		/* CNS Plane 15 is pre-allocated, so place it into Plane 16. */
		if (plane_no == 15)
			plane_no = 16;
	} else {
		uint32_t	euctw_val;

		index = kiconv_binsearch(utf8, kiconv_utf8_euctw,
		    KICONV_UTF8_EUCTW_MAX);

		if (index == 0) {
			if (ob >= obtail) {
				*ret_val = (size_t)-1;
				return (-1);
			}

			*ob++ = KICONV_ASCII_REPLACEMENT_CHAR;
			(*ret_val)++;

			return (1);
		}

		euctw_val = kiconv_utf8_euctw[index].value;
		byte1 = (euctw_val & 0xFF00) >> 8;
		byte2 = euctw_val & 0xFF;
		plane_no = euctw_val >> 16;
	}

	if (obtail - ob < (plane_no == 1 ? 2 : 4)) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (plane_no != 1) {
		*ob++ = KICONV_TC_EUCTW_MBYTE;
		*ob++ = KICONV_TC_EUCTW_PMASK + plane_no;
	}

	*ob++ = byte1;
	*ob = byte2;

	return (plane_no == 1 ? 2 : 4);
}

/*
 * Convert single UTF-8 character to BIG5-HKSCS
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
static int8_t
utf8_to_big5hkscs(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
    uchar_t *ob, uchar_t *obtail, size_t *ret_val)
{
	size_t		index;
	int8_t		hkscslen;
	uint32_t	hkscscode;
	boolean_t	special_sequence = B_FALSE;

	index = kiconv_binsearch(utf8, kiconv_utf8_hkscs,
	    KICONV_UTF8_HKSCS_MAX);
	hkscscode = kiconv_utf8_hkscs[index].value;

	/*
	 * There are 4 special code points in HKSCS-2004 which mapped
	 * to 2 UNICODE code points.
	 */
	if ((int32_t)hkscscode < 0) {
		size_t special_index = (-(int32_t)hkscscode - 1) * 3;

		/* Check the following 2 bytes. */
		if (ibtail - *inbuf >= 2 && **inbuf == 0xcc &&
		    (*(*inbuf + 1) == 0x84 || *(*inbuf + 1) == 0x8c)) {
			special_index += (*(*inbuf + 1) == 0x84 ? 1 : 2);
			special_sequence = B_TRUE;
		}

		hkscscode = ucs_special_sequence[special_index];
	}

	hkscslen = (hkscscode <= 0xFF) ? 1 : 2;
	if (obtail - ob < hkscslen) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret_val)++;

	if (hkscslen > 1)
		*ob++ = (uchar_t)(hkscscode >> 8);
	*ob = (uchar_t)(hkscscode & 0xFF);

	if (special_sequence) {		/* Advance for special sequence */
		(*inbuf) += 2;
	}

	return (hkscslen);
}

/*
 * Common convertor for UTF-8 to BIG5/CP950-HKSCS.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
static int8_t
utf8_to_big5_common(uint32_t utf8, uchar_t *ob, uchar_t *obtail,
	size_t *ret_val, kiconv_table_t *table, size_t nitems)
{
	size_t		index;
	int8_t		big5len;
	uint32_t	big5code;

	index = kiconv_binsearch(utf8, table, nitems);
	big5code = table[index].value;
	big5len = (big5code <= 0xFF) ? 1 : 2;

	if (obtail - ob < big5len) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret_val)++;

	if (big5len > 1)
		*ob++ = (uchar_t)(big5code >> 8);
	*ob = (uchar_t)(big5code & 0xFF);

	return (big5len);
}

/*
 * Convert single UTF-8 character to BIG5.
 */
/* ARGSUSED */
static int8_t
utf8_to_big5(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val)
{
	return (utf8_to_big5_common(utf8, ob, obtail, ret_val,
	    kiconv_utf8_big5, KICONV_UTF8_BIG5_MAX));
}

/*
 * Convert single UTF-8 character to CP950-HKSCS for Windows compatibility.
 */
/* ARGSUSED */
static int8_t
utf8_to_cp950hkscs(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val)
{
	return (utf8_to_big5_common(utf8, ob, obtail, ret_val,
	    kiconv_utf8_cp950hkscs, KICONV_UTF8_CP950HKSCS));
}

static kiconv_ops_t kiconv_tc_ops_tbl[] = {
	{
		"big5", "utf-8", kiconv_open_to_cck, kiconv_to_big5,
		kiconv_close_to_cck, kiconvstr_to_big5
	},
	{
		"utf-8", "big5", open_fr_big5, kiconv_fr_big5,
		close_fr_tc, kiconvstr_fr_big5
	},

	{
		"big5-hkscs", "utf-8", kiconv_open_to_cck, kiconv_to_big5hkscs,
		kiconv_close_to_cck, kiconvstr_to_big5hkscs
	},
	{
		"utf-8", "big5-hkscs", open_fr_big5hkscs, kiconv_fr_big5hkscs,
		close_fr_tc, kiconvstr_fr_big5hkscs
	},

	{
		"euc-tw", "utf-8", kiconv_open_to_cck, kiconv_to_euctw,
		kiconv_close_to_cck, kiconvstr_to_euctw
	},
	{
		"utf-8", "euc-tw", open_fr_euctw, kiconv_fr_euctw,
		close_fr_tc, kiconvstr_fr_euctw
	},

	{
		"cp950-hkscs", "utf-8", kiconv_open_to_cck,
		kiconv_to_cp950hkscs, kiconv_close_to_cck,
		kiconvstr_to_cp950hkscs
	},
	{
		"utf-8", "cp950-hkscs", open_fr_cp950hkscs,
		kiconv_fr_cp950hkscs, close_fr_tc, kiconvstr_fr_cp950hkscs
	},
};

static kiconv_module_info_t kiconv_tc_info = {
	"kiconv_tc",		/* module name */
	sizeof (kiconv_tc_ops_tbl) / sizeof (kiconv_tc_ops_tbl[0]),
	kiconv_tc_ops_tbl,
	0,
	NULL,
	NULL,
	0
};

static struct modlkiconv modlkiconv_tc = {
	&mod_kiconvops,
	"kiconv Traditional Chinese module 1.0",
	&kiconv_tc_info
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlkiconv_tc,
	NULL
};

int
_init(void)
{
	int err;

	err = mod_install(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_tc: failed to load kernel module");

	return (err);
}

int
_fini(void)
{
	int err;

	/*
	 * If this module is being used, then, we cannot remove the module.
	 * The following checking will catch pretty much all usual cases.
	 *
	 * Any remaining will be catached by the kiconv_unregister_module()
	 * during mod_remove() at below.
	 */
	if (kiconv_module_ref_count(KICONV_MODULE_ID_TC))
		return (EBUSY);

	err = mod_remove(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_tc: failed to remove kernel module");

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
