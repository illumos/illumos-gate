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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This is for UTF-8 to UTF-8 code conversion; it simply passes through
 * all things with UTF-8 byte sequence checking to screen out any illegal
 * and thus potentially harmful bytes.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "common_defs.h"


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


size_t
_icv_iconv(int *cd, char **inbuf, size_t *inbufleft, char **outbuf,
                size_t *outbufleft)
{
	size_t ret_val = 0;
	uchar_t *ib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;
	uchar_t *ib_copy;
	uint_t u4;
	uint_t first_byte;
	signed char sz;
	signed char obsz;

	if (! cd || cd != (int *)MAGIC_NUMBER) {
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
		sz = number_of_bytes_in_utf8_char[*ib];
		if (sz == ICV_TYPE_ILLEGAL_CHAR) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}
		obsz = sz;

		if ((ibtail - ib) < sz) {
			errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		ib_copy = ib;
		first_byte = *ib_copy++;
		u4 = first_byte & (uint_t)masks_tbl[sz];
		for (; sz > 1; sz--) {
			if (first_byte) {
				if (((uchar_t)*ib_copy) <
					valid_min_2nd_byte[first_byte] ||
				    ((uchar_t)*ib_copy) >
					valid_max_2nd_byte[first_byte]) {
					errno = EILSEQ;
					ret_val = (size_t)-1;
					goto ILLEGAL_CHAR_ERR;
				}
				first_byte = 0;
			} else if (((uint_t)*ib_copy) < 0x80 ||
				   ((uint_t)*ib_copy) > 0xbf) {
				errno = EILSEQ;
				ret_val = (size_t)-1;
				goto ILLEGAL_CHAR_ERR;
			}
			u4 = (u4 << ICV_UTF8_BIT_SHIFT) |
				(((uint_t)*ib_copy) & ICV_UTF8_BIT_MASK);
			ib_copy++;
		}

		/*
		 * Check some more illegal characters and noncharacters from
		 * the input buffer. Surrogate pairs (U+D800 - U+DFFF) are
		 * checked at the above for loop.
		 */
		if ((u4 & 0xffff) == 0x00fffe || (u4 & 0xffff) == 0x00ffff ||
		    (u4 >= 0x00fdd0 && u4 <= 0x00fdef) || u4 > 0x10fffd) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			goto ILLEGAL_CHAR_ERR;
		}

		if ((obtail - ob) < obsz) {
			errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		for (; obsz >= 1; obsz--)
			*ob++ = *ib++;
	}

ILLEGAL_CHAR_ERR:
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
