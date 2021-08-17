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
#include <sys/kiconv.h>
#include <sys/u8_textprep.h>
#include <sys/kiconv_cck_common.h>
#include <sys/kiconv_sc.h>
#include <sys/kiconv_gb18030_utf8.h>
#include <sys/kiconv_gb2312_utf8.h>
#include <sys/kiconv_utf8_gb18030.h>
#include <sys/kiconv_utf8_gb2312.h>

static int8_t gb2312_to_utf8(uchar_t byte1, uchar_t byte2, uchar_t *ob,
	uchar_t *obtail, size_t *ret_val);
static int8_t gbk_to_utf8(uint32_t gbk_val, uchar_t *ob, uchar_t *obtail,
	size_t *ret_val, boolean_t isgbk4);
static int8_t utf8_to_gb2312(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret);
static int8_t utf8_to_gbk(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret);
static int8_t utf8_to_gb18030(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret);

#define	KICONV_SC_GB18030		(0x01)
#define	KICONV_SC_GBK			(0x02)
#define	KICONV_SC_EUCCN			(0x03)
#define	KICONV_SC_MAX_MAGIC_ID		(0x03)

static void *
open_fr_gb18030()
{
	return ((void *)KICONV_SC_GB18030);
}

static void *
open_fr_gbk()
{
	return ((void *)KICONV_SC_GBK);
}

static void *
open_fr_euccn()
{
	return ((void *)KICONV_SC_EUCCN);
}

static int
close_fr_sc(void *s)
{
	if ((uintptr_t)s > KICONV_SC_MAX_MAGIC_ID)
		return (EBADF);

	return (0);
}

/*
 * Encoding convertor from UTF-8 to GB18030.
 */
size_t
kiconv_to_gb18030(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{

	return kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_gb18030);
}

/*
 * String based encoding convertor from UTF-8 to GB18030.
 */
size_t
kiconvstr_to_gb18030(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_gb18030);
}

/*
 * Encoding convertor from GB18030 to UTF-8.
 */
size_t
kiconv_fr_gb18030(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	gb_val;
	boolean_t	isgbk4;

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
		 * valid GB18030 leading byte.
		 */
		if (! KICONV_SC_IS_GBK_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		isgbk4 = (ibtail - ib < 2) ? B_FALSE :
		    KICONV_SC_IS_GB18030_2nd_BYTE(*(ib + 1));

		if (isgbk4) {
			if (ibtail - ib < 4) {
				KICONV_SET_ERRNO_AND_BREAK(EINVAL);
			}

			if (! (KICONV_SC_IS_GB18030_2nd_BYTE(*(ib + 1)) &&
			    KICONV_SC_IS_GB18030_3rd_BYTE(*(ib + 2)) &&
			    KICONV_SC_IS_GB18030_4th_BYTE(*(ib + 3)))) {
				KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
			}

			gb_val = (uint32_t)(*ib) << 24 |
			    (uint32_t)(*(ib + 1)) << 16 |
			    (uint32_t)(*(ib + 2)) << 8 | *(ib + 3);
		} else {
			if (ibtail - ib < 2) {
				KICONV_SET_ERRNO_AND_BREAK(EINVAL);
			}

			if (! KICONV_SC_IS_GBK_2nd_BYTE(*(ib + 1))) {
				KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
			}

			gb_val = (uint32_t)(*ib) << 8 | *(ib + 1);
		}

		sz = gbk_to_utf8(gb_val, ob, obtail, &ret_val, isgbk4);
		if (sz < 0) {
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ib += isgbk4 ? 4 : 2;
		ob += sz;
	}

	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}

/*
 * String based encoding convertor from GB18030 to UTF-8.
 */
size_t
kiconvstr_fr_gb18030(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	gb_val;
	boolean_t	isgbk4;
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

		if (! KICONV_SC_IS_GBK_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		isgbk4 = (ibtail - ib < 2) ? B_FALSE :
		    KICONV_SC_IS_GB18030_2nd_BYTE(*(ib + 1));

		if (isgbk4) {
			if (ibtail - ib < 4) {
				if (flag & KICONV_REPLACE_INVALID) {
					ib = ibtail;
					goto REPLACE_INVALID;
				}

				KICONV_SET_ERRNO_AND_BREAK(EINVAL);
			}

			if (! (KICONV_SC_IS_GB18030_2nd_BYTE(*(ib + 1)) &&
			    KICONV_SC_IS_GB18030_3rd_BYTE(*(ib + 2)) &&
			    KICONV_SC_IS_GB18030_4th_BYTE(*(ib + 3)))) {
				KICONV_SET_ERRNO_WITH_FLAG(4, EILSEQ);
			}

			gb_val = (uint32_t)(*ib) << 24 |
			    (uint32_t)(*(ib + 1)) << 16 |
			    (uint32_t)(*(ib + 2)) << 8 | *(ib + 3);
		} else {
			if (ibtail - ib < 2) {
				if (flag & KICONV_REPLACE_INVALID) {
					ib = ibtail;
					goto REPLACE_INVALID;
				}

				KICONV_SET_ERRNO_AND_BREAK(EINVAL);
			}

			if (! KICONV_SC_IS_GBK_2nd_BYTE(*(ib + 1))) {
				KICONV_SET_ERRNO_WITH_FLAG(2, EILSEQ);
			}

			gb_val = (uint32_t)(*ib) << 8 | *(ib + 1);
		}

		sz = gbk_to_utf8(gb_val, ob, obtail, &ret_val, isgbk4);
		if (sz < 0) {
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ib += isgbk4 ? 4 : 2;
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
 * Encoding convertor from UTF-8 to GBK.
 */
size_t
kiconv_to_gbk(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{

	return kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_gbk);
}

/*
 * String based encoding convertor from UTF-8 to GBK.
 */
size_t
kiconvstr_to_gbk(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_gbk);
}

/*
 * Encoding convertor from GBK to UTF-8.
 */
size_t
kiconv_fr_gbk(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	gb_val;

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
		 * valid GBK leading byte.
		 */
		if (! KICONV_SC_IS_GBK_1st_BYTE(*ib)) {
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
		 * Issue EILSEQ error if the remaining byte is not
		 * a valid GBK byte.
		 */
		if (! KICONV_SC_IS_GBK_2nd_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		/* Now we have a valid GBK character. */
		gb_val = (uint32_t)(*ib) << 8 | *(ib + 1);
		sz = gbk_to_utf8(gb_val, ob, obtail, &ret_val, B_FALSE);

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
 * String based encoding convertor from GBK to UTF-8.
 */
size_t
kiconvstr_fr_gbk(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	gb_val;
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

		if (! KICONV_SC_IS_GBK_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EINVAL);
		}

		if (! KICONV_SC_IS_GBK_2nd_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_WITH_FLAG(2, EILSEQ);
		}

		gb_val = (uint32_t)(*ib << 8) | *(ib + 1);
		sz = gbk_to_utf8(gb_val, ob, obtail, &ret_val, B_FALSE);

		if (sz < 0) {
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ib += 2;
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
 * Encoding convertor from UTF-8 to EUC-CN.
 */
size_t
kiconv_to_euccn(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	return kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_gb2312);
}

/*
 * String based encoding convertor from UTF-8 to EUC-CN.
 */
size_t
kiconvstr_to_euccn(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_gb2312);
}

/*
 * Encoding converto from EUC-CN to UTF-8 code.
 */
size_t
kiconv_fr_euccn(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	size_t		ret_val;
	int8_t		sz;

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
		 * valid GB2312 leading byte.
		 */
		if (! KICONV_SC_IS_GB2312_BYTE(*ib)) {
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
		 * Issue EILSEQ error if the remaining byte is not
		 * a valid GB2312 byte.
		 */
		if (! KICONV_SC_IS_GB2312_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		/* Now we have a valid GB2312 character */
		sz = gb2312_to_utf8(*ib, *(ib + 1), ob, obtail, &ret_val);
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
 * String based encoding convertor from EUC-CN to UTF-8.
 */
size_t
kiconvstr_fr_euccn(char *inarray, size_t *inlen, char *outarray,
    size_t *outlen, int flag, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	int8_t		sz;
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

		if (! KICONV_SC_IS_GB2312_BYTE(*ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EINVAL);
		}

		if (! KICONV_SC_IS_GB2312_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_WITH_FLAG(2, EILSEQ);
		}

		sz = gb2312_to_utf8(*ib, *(ib + 1), ob, obtail, &ret_val);
		if (sz < 0) {
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ib += 2;
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
 * Convert single GB2312 character to UTF-8.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
static int8_t
gb2312_to_utf8(uchar_t b1, uchar_t b2, uchar_t *ob, uchar_t *obtail,
    size_t *ret_val)
{
	size_t	index;
	int8_t	sz;
	uchar_t	*u8;

	/* index = (b1 - KICONV_EUC_START) * 94 + b2 - KICONV_EUC_START; */
	index = b1 * 94 + b2 - 0x3BBF;

	if (index >= KICONV_GB2312_UTF8_MAX)
		index = KICONV_GB2312_UTF8_MAX - 1;	/* Map to 0xEFBFBD */

	u8 = kiconv_gb2312_utf8[index];
	sz = u8_number_of_bytes[u8[0]];

	if (obtail - ob < sz) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	for (index = 0; index < sz; index++)
		*ob++ = u8[index];

	/*
	 * As kiconv_gb2312_utf8 contain muliple KICONV_UTF8_REPLACEMENT_CHAR
	 * elements, so need to ckeck more.
	 */
	if (sz == KICONV_UTF8_REPLACEMENT_CHAR_LEN &&
	    u8[0] == KICONV_UTF8_REPLACEMENT_CHAR1 &&
	    u8[1] == KICONV_UTF8_REPLACEMENT_CHAR2 &&
	    u8[2] == KICONV_UTF8_REPLACEMENT_CHAR3)
		(*ret_val)++;

	return (sz);
}

/*
 * Convert single GB18030 or GBK character to UTF-8.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
static int8_t
gbk_to_utf8(uint32_t gbk_val, uchar_t *ob, uchar_t *obtail, size_t *ret_val,
    boolean_t isgbk4)
{
	size_t	index;
	int8_t	sz;
	uchar_t	u8array[4];
	uchar_t	*u8;

	if (isgbk4) {
		if (gbk_val >= KICONV_SC_PLANE1_GB18030_START) {
			uint32_t	u32;

			/*
			 * u32 = ((gbk_val >> 24) - 0x90) * 12600 +
			 *   (((gbk_val & 0xFF0000) >> 16) - 0x30) * 1260 +
			 *   (((gbk_val & 0xFF00) >> 8) - 0x81) * 10 +
			 *   (gbk_val & 0xFF - 0x30)+
			 *   KICONV_SC_PLANE1_UCS4_START;
			 */
			u32 = (gbk_val >> 24) * 12600 +
			    ((gbk_val & 0xFF0000) >> 16) * 1260 +
			    ((gbk_val & 0xFF00) >> 8) * 10 +
			    (gbk_val & 0xFF) - 0x1BA0FA;
			u8array[0] = (uchar_t)(0xF0 | ((u32 & 0x1C0000) >> 18));
			u8array[1] = (uchar_t)(0x80 | ((u32 & 0x03F000) >> 12));
			u8array[2] = (uchar_t)(0x80 | ((u32 & 0x000FC0) >> 6));
			u8array[3] = (uchar_t)(0x80 | (u32 & 0x00003F));
			u8 = u8array;
			index = 1;
		} else {
			index = kiconv_binsearch(gbk_val,
			    kiconv_gbk4_utf8, KICONV_GBK4_UTF8_MAX);
			u8 = kiconv_gbk4_utf8[index].u8;
		}
	} else {
		index = kiconv_binsearch(gbk_val,
		    kiconv_gbk_utf8, KICONV_GBK_UTF8_MAX);
		u8 = kiconv_gbk_utf8[index].u8;
	}

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
 * Convert single UTF-8 character to GB18030.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
/* ARGSUSED */
static int8_t
utf8_to_gb18030(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
    uchar_t *ob, uchar_t *obtail, size_t *ret)
{
	size_t		index;
	int8_t		gbklen;
	uint32_t	gbkcode;

	if (utf8 >= KICONV_SC_PLANE1_UTF8_START) {
		/* Four bytes GB18030 [0x90308130, 0xe339fe39] handling. */
		uint32_t	u32;

		u32 = (((utf8 & 0x07000000) >> 6) | ((utf8 & 0x3F0000) >> 4) |
		    ((utf8 & 0x3F00) >> 2) | (utf8 & 0x3F)) -
		    KICONV_SC_PLANE1_UCS4_START;
		gbkcode = ((u32 / 12600 + 0x90) << 24) |
		    (((u32 % 12600) / 1260 + 0x30) << 16) |
		    (((u32 % 1260) / 10 + 0x81) << 8) | (u32 % 10 + 0x30);
		gbklen = 4;
		index = 1;
	} else {
		index = kiconv_binsearch(utf8, kiconv_utf8_gb18030,
		    KICONV_UTF8_GB18030_MAX);
		gbkcode = kiconv_utf8_gb18030[index].value;
		KICONV_SC_GET_GB_LEN(gbkcode, gbklen);
	}

	if (obtail - ob < gbklen) {
		*ret = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret)++;		/* Non-identical conversion */

	if (gbklen == 2) {
		*ob++ = (uchar_t)(gbkcode >> 8);
	} else if (gbklen == 4) {
		*ob++ = (uchar_t)(gbkcode >> 24);
		*ob++ = (uchar_t)(gbkcode >> 16);
		*ob++ = (uchar_t)(gbkcode >> 8);
	}
	*ob = (uchar_t)(gbkcode & 0xFF);

	return (gbklen);
}

/*
 * Convert single UTF-8 character to GBK.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
/* ARGSUSED */
static int8_t
utf8_to_gbk(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
    uchar_t *ob, uchar_t *obtail, size_t *ret)
{
	size_t		index;
	int8_t		gbklen;
	uint32_t	gbkcode;

	index = kiconv_binsearch(utf8, kiconv_utf8_gb18030,
	    KICONV_UTF8_GB18030_MAX);
	gbkcode = kiconv_utf8_gb18030[index].value;
	KICONV_SC_GET_GB_LEN(gbkcode, gbklen);

	/* GBK and GB18030 share the same table, so check the length. */
	if (gbklen == 4) {
		index = 0;
		gbkcode = kiconv_utf8_gb18030[index].value;
		gbklen = 1;
	}

	if (obtail - ob < gbklen) {
		*ret = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret)++;		/* Non-identical conversion */

	if (gbklen > 1)
		*ob++ = (uchar_t)(gbkcode >> 8);
	*ob = (uchar_t)(gbkcode & 0xFF);

	return (gbklen);
}

/*
 * Convert single UTF-8 character to GB2312.
 * Return: > 0  - Converted successfully
 *         = -1 - E2BIG
 */
/* ARGSUSED */
static int8_t
utf8_to_gb2312(uint32_t utf8, uchar_t **inbuf, uchar_t *intail,
    uchar_t *ob, uchar_t *obtail, size_t *ret)
{
	size_t		index;
	int8_t		gblen;
	uint32_t	gbcode;

	index = kiconv_binsearch(utf8, kiconv_utf8_gb2312,
	    KICONV_UTF8_GB2312_MAX);
	gbcode = kiconv_utf8_gb2312[index].value;
	gblen = (gbcode <= 0xFF) ? 1 : 2;

	if (obtail - ob < gblen) {
		*ret = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret)++;

	if (gblen > 1)
		*ob++ = (uchar_t)(gbcode >> 8);
	*ob = (uchar_t)(gbcode & 0xFF);

	return (gblen);
}

static kiconv_ops_t kiconv_sc_ops_tbl[] = {
	{
		"gb18030", "utf-8", kiconv_open_to_cck, kiconv_to_gb18030,
		kiconv_close_to_cck, kiconvstr_to_gb18030
	},
	{
		"utf-8", "gb18030", open_fr_gb18030, kiconv_fr_gb18030,
		close_fr_sc, kiconvstr_fr_gb18030
	},
	{
		"gbk", "utf-8", kiconv_open_to_cck, kiconv_to_gbk,
		kiconv_close_to_cck, kiconvstr_to_gbk
	},
	{
		"utf-8", "gbk", open_fr_gbk, kiconv_fr_gbk,
		close_fr_sc, kiconvstr_fr_gbk
	},
	{
		"euccn", "utf-8", kiconv_open_to_cck, kiconv_to_euccn,
		kiconv_close_to_cck, kiconvstr_to_euccn
	},
	{
		"utf-8", "euccn", open_fr_euccn, kiconv_fr_euccn,
		close_fr_sc, kiconvstr_fr_euccn
	},
};

static kiconv_module_info_t kiconv_sc_info = {
	"kiconv_sc",		/* module name */
	sizeof (kiconv_sc_ops_tbl) / sizeof (kiconv_sc_ops_tbl[0]),
	kiconv_sc_ops_tbl,
	0,
	NULL,
	NULL,
	0
};

static struct modlkiconv modlkiconv_sc = {
	&mod_kiconvops,
	"kiconv Simplified Chinese module 1.0",
	&kiconv_sc_info
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlkiconv_sc,
	NULL
};

int
_init(void)
{
	int err;

	err = mod_install(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_sc: failed to load kernel module");

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
	if (kiconv_module_ref_count(KICONV_MODULE_ID_SC))
		return (EBUSY);

	err = mod_remove(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_sc: failed to remove kernel module");

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
