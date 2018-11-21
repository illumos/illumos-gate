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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <errno.h>
#include "euro.h"


void *
_icv_open()
{
	return ((void *) MAGIC_NUMBER);
}


void
_icv_close(int *cd)
{
	if (! cd || cd != (int *)MAGIC_NUMBER)
		errno = EBADF;
}


size_t
_icv_iconv(int *cd, char **inbuf, size_t *inbytesleft,
		char **outbuf, size_t *outbytesleft)
{
	size_t ret_val;
	unsigned char c;
	unsigned char *ib;
	unsigned char *ob;
	unsigned char *ibtail;
	unsigned char *obtail;

	if (cd != (int *)MAGIC_NUMBER) {
		errno = EBADF;
		return ((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
		return ((size_t)0);

	ret_val = 0;
	ib = (unsigned char *)*inbuf;
	ob = (unsigned char *)*outbuf;
	ibtail = ib + *inbytesleft;
	obtail = ob + *outbytesleft;

	while (ib < ibtail) {
		c = *ib;

		if (tbl[c].sz == ICV_TYPE_ILLEGAL_CHAR) {
			errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if (obtail <= ob) {
			errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		*ob++ = tbl[c].ch;
		ib++;
	}

	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}
