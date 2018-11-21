/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "utf8_to_utf_ebcdic.h"

void *
_icv_open()
{
	return((void *)MAGIC_NUMBER);
}


void
_icv_close(int *cd)
{
	if (! cd || cd != (int *)MAGIC_NUMBER)
		errno = EBADF;
}


#define	OUTBUF_SIZE_CHECK(sz) \
	if ((obtail - ob) < (sz)) { \
		ib = ib_org; \
		errno = E2BIG; \
		ret_val = (size_t)-1; \
		break; \
	}

#define I8_UTFEBICDIC(i8) i8_to_utf_ebcdic[(i8)]

size_t
_icv_iconv(int *cd, char **inbuf, size_t *inbufleft, char **outbuf,
                size_t *outbufleft)
{
	size_t ret_val = 0;
	uchar_t *ib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;

	if (cd != (int *)MAGIC_NUMBER) {
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
		return((size_t)0);

	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail) {
		uchar_t *ib_org;
		uint_t u4;
		uint_t first_byte;
		signed char sz;

		sz = number_of_bytes_in_utf8_char[*ib];
		if (sz == ICV_TYPE_ILLEGAL_CHAR) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if ((ibtail - ib) < sz) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		ib_org = ib;
		first_byte = *ib;
		u4 = (uint_t)(*ib++ & masks_tbl[sz]);
		for (; sz > 1; sz--) {
			if (first_byte) {
				if (((uchar_t)*ib) <
					valid_min_2nd_byte[first_byte] ||
				    ((uchar_t)*ib) >
					valid_max_2nd_byte[first_byte]) {
					ib = ib_org;
					errno = EILSEQ;
					ret_val = (size_t)-1;
					goto ILLEGAL_CHAR_ERR;
				}
				first_byte = 0;
			} else if (((uint_t)*ib) < 0x80 ||
				   ((uint_t)*ib) > 0xbf) {
				ib = ib_org;
				errno = EILSEQ;
				ret_val = (size_t)-1;
				goto ILLEGAL_CHAR_ERR;
			}
			u4 = (u4 << ICV_UTF8_BIT_SHIFT) |
				(((uint_t)*ib) & ICV_UTF8_BIT_MASK);
			ib++;
		}

		/* Check against known non-characters. */
		if ((u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_fffe ||
		    (u4 & ICV_UTF32_NONCHAR_mask) == ICV_UTF32_NONCHAR_ffff ||
		    u4 > ICV_UTF32_LAST_VALID_CHAR ||
		    (u4 >= ICV_UTF32_SURROGATE_START_d800 &&
		    u4 <= ICV_UTF32_SURROGATE_END_dfff) ||
		    (u4 >= ICV_UTF32_ARABIC_NONCHAR_START_fdd0 &&
		    u4 <= ICV_UTF32_ARABIC_NONCHAR_END_fdef)) {
			ib = ib_org;
			errno = EILSEQ;
			ret_val = (size_t)-1;
			goto ILLEGAL_CHAR_ERR;
		}

		if (u4 <= 0x7f) {
			OUTBUF_SIZE_CHECK(1);
			*ob++ = I8_UTFEBICDIC(u4);
		} else if (u4 <= 0x9f) {
			OUTBUF_SIZE_CHECK(1);
			*ob++ = I8_UTFEBICDIC(u4);
		} else if (u4 <= 0x3ff) {
			OUTBUF_SIZE_CHECK(2);
			*ob++ = I8_UTFEBICDIC(0xc0 | ((u4 & 0x03e0) >> 5));
			*ob++ = I8_UTFEBICDIC(0xa0 |  (u4 & 0x001f));
		} else if (u4 <= 0x3fff) {
			OUTBUF_SIZE_CHECK(3);
			*ob++ = I8_UTFEBICDIC(0xe0 | ((u4 & 0x3c00) >> 10));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x03e0) >> 5));
			*ob++ = I8_UTFEBICDIC(0xa0 |  (u4 & 0x001f));
		} else if (u4 <= 0x3ffff) {
			OUTBUF_SIZE_CHECK(4);
			*ob++ = I8_UTFEBICDIC(0xf0 | ((u4 & 0x38000) >> 15));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x07c00) >> 10));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x003e0) >> 5));
			*ob++ = I8_UTFEBICDIC(0xa0 |  (u4 & 0x0001f));
		} else if (u4 <= 0x3fffff) {
			OUTBUF_SIZE_CHECK(5);
			*ob++ = I8_UTFEBICDIC(0xf8 | ((u4 & 0x300000) >> 20));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x0f8000) >> 15));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x007c00) >> 10));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x0003e0) >> 5));
			*ob++ = I8_UTFEBICDIC(0xa0 |  (u4 & 0x00001f));
		} else if (u4 <= 0x3ffffff) {
			OUTBUF_SIZE_CHECK(6);
			*ob++ = I8_UTFEBICDIC(0xfc | ((u4 & 0x2000000) >> 25));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x1f00000) >> 20));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x00f8000) >> 15));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x0007c00) >> 10));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x00003e0) >> 5));
			*ob++ = I8_UTFEBICDIC(0xa0 |  (u4 & 0x000001f));
		} else if (u4 <= 0x7fffffff) {
			OUTBUF_SIZE_CHECK(7);
			*ob++ = I8_UTFEBICDIC(0xfe | ((u4 & 0x40000000) >> 30));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x3e000000) >> 25));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x01f00000) >> 20));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x000f8000) >> 15));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x00007c00) >> 10));
			*ob++ = I8_UTFEBICDIC(0xa0 | ((u4 & 0x000003e0) >> 5));
			*ob++ = I8_UTFEBICDIC(0xa0 |  (u4 & 0x0000001f));
		} else {
			ib = ib_org;
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
	}

ILLEGAL_CHAR_ERR:
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
