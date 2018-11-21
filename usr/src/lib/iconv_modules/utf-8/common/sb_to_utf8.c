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
 * This program assumes that all single byte coded characters will be either
 * map to UTF-8 coded characters or illegal characters. Thus no replacement is
 * assumed at the moment.
 *
 * This particular file is to cover conversions from various single byte
 * codesets to UTF-8.
 */


#include <stdlib.h>
#include <errno.h>
#include "sb_to_utf8.h"


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
	unsigned char *ib;
	unsigned char *ob;
	unsigned char *ibtail;
	unsigned char *obtail;

	if (cd != (int *)MAGIC_NUMBER) {
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
		return((size_t)0);

	ib = (unsigned char *)*inbuf;
	ob = (unsigned char *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail) {
		register int i;
		unsigned long u8;
		signed char sz;

		u8 = (unsigned long)sb_u8_tbl[*ib].u8;
		sz = sb_u8_tbl[*ib].size;

		if (sz == ICV_TYPE_ILLEGAL_CHAR) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if ((u8 & ICV_UTF8_REPRESENTATION_ffff_mask) ==
		    ICV_UTF8_REPRESENTATION_fffe ||
		    (u8 & ICV_UTF8_REPRESENTATION_ffff_mask) ==
		    ICV_UTF8_REPRESENTATION_ffff ||
		    u8 > ICV_UTF8_REPRESENTATION_10fffd ||
		    (u8 >= ICV_UTF8_REPRESENTATION_d800 &&
		    u8 <= ICV_UTF8_REPRESENTATION_dfff) ||
		    (u8 >= ICV_UTF8_REPRESENTATION_fdd0 &&
		    u8 <= ICV_UTF8_REPRESENTATION_fdef)) {
			/* This should not happen, if sb_u8_tbl is right. */
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if ((obtail - ob) < sz) {
			errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		for (i = 1; i <= sz; i++)
			*ob++ = (unsigned int)((u8 >> ((sz - i) * 8)) & 0xff);
		ib++;
	}

	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
