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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "utf_ebcdic_to_utf8.h"

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
		ib = ib_org;\
		errno = E2BIG; \
		ret_val = (size_t)-1; \
		break; \
	}

#define UTFEBICDIC_I8(utfe) utf_ebcdic_to_i8[(utfe)]

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
		signed char sz; /* must be signed for loop condition */

		sz = number_of_bytes_in_utf_ebcidc[*ib];
		if ((sz > UTF_EBCDIC_LEAD_OCTET_MAX) ||
			(sz < UTF_EBCDIC_LEAD_OCTET_MIN)) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
		/* sz == 0 means control character. and it need 1 byte */
		if ((ibtail - ib) < ((sz == 0)? 1: sz)) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		ib_org = ib;

		u4 = (UTFEBICDIC_I8(*ib++) & utf_ebcdic_masks_tbl[sz]);

		/* correct size */
		if (sz == 0){
			sz = 1;
		}
		for (; sz > 1; sz--) {
			if (number_of_bytes_in_utf_ebcidc[*ib] !=
				UTF_EBCDIC_TRAILING_OCTET) {
				ib = ib_org;
				errno = EILSEQ;
				ret_val = (size_t)-1;
				goto illegal_char_err;
			}
			u4 = ((u4 << UTF_EBCDIC_BIT_SHIFT) |
				(((uint_t)(UTFEBICDIC_I8(*ib)))
				& UTF_EBCDIC_BIT_MASK));
			ib++;
		}

		if (u4 <= 0x7f) {
			OUTBUF_SIZE_CHECK(1);
			*ob++ = (uchar_t)u4;
		} else if (u4 <= 0x7ff) {
			OUTBUF_SIZE_CHECK(2);
			*ob++ = (uchar_t)(0xc0 | ((u4 & 0x07c0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x003f));
		} else if (u4 <= 0xd7ff) {
			OUTBUF_SIZE_CHECK(3);
			*ob++ = (uchar_t)(0xe0 | ((u4 & 0x0f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x0003f));
		} else if (u4 <= 0x00dfff) {
			/* S zone */
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		} else if (u4 <= 0x00fffd) {
			OUTBUF_SIZE_CHECK(3);
			*ob++ = (uchar_t)(0xe0 | ((u4 & 0x0f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x0003f));
		} else if (u4 <= 0x00ffff) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		} else if (u4 <= 0x1fffff) {
			OUTBUF_SIZE_CHECK(4);
			*ob++ = (uchar_t)(0xf0 | ((u4 & 0x01c0000) >> 18));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x003f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x0000fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x000003f));
		} else if (u4 <= 0x3ffffff) {
			OUTBUF_SIZE_CHECK(5);
			*ob++ = (uchar_t)(0xf8 | ((u4 & 0x03000000) >> 24));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0000) >> 18));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x0003f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00000fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x0000003f));
		} else if (u4 <= 0x7fffffff) {
			OUTBUF_SIZE_CHECK(6);
			*ob++ = (uchar_t)(0xfc | ((u4 & 0x40000000) >> 30));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x3f000000) >> 24));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00fc0000) >> 18));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x0003f000) >> 12));
			*ob++ = (uchar_t)(0x80 | ((u4 & 0x00000fc0) >> 6));
			*ob++ = (uchar_t)(0x80 |  (u4 & 0x0000003f));

		} else {
			ib = ib_org;
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
	}

illegal_char_err:
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
