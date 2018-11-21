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
 * Copyright (c) 1994, 1995 by Sun Microsystems, Inc.
 * Copyright (c) 1994, Nihon Sun Microsystems K.K.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#define MAGIC_NUMBER	(0x216513)
#define ERR_RETURN      (-1)            /* result code on error */

#define GET(c)          ((c) = *ip, ip++, ileft--)
#define PUT(c)          (*op = (c), op++, oleft--)
#define UNGET()         (ip--, ileft++)


/*
 * Open; called from iconv_open()
 */
void *
_icv_open()
{
	return ((void*)MAGIC_NUMBER);
}


/*
 * Close; called from iconv_close
 */
void
_icv_close(int* cd)
{
	if (!cd || cd != (int*)MAGIC_NUMBER)
		errno = EBADF;
}


/*
 * Actual conversion; called from iconv()
 */
size_t
_icv_iconv(int* cd, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	unsigned char	*ip, ic, *op;
	size_t			ileft, oleft;
	size_t			retval = 0;

	if (!cd || cd != (int*)MAGIC_NUMBER)
	{
		errno = EBADF;
		return((size_t)ERR_RETURN);
	}

	if ((inbuf == 0) || (*inbuf == 0))
		return((size_t)0);

	ip = (unsigned char*)*inbuf;
	op = (unsigned char *)*outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/*
	 * Main loop; basically 1 loop per 1 input byte
	 */

	while (ileft > 0) {
		GET(ic);
		if (oleft < 1) {
			UNGET();
			errno = E2BIG;
			retval = ERR_RETURN;
			goto ret;
		}
		if (isascii(ic))
			PUT(ic);
		else {
			PUT('_');
			retval++;
		}
	}

ret:
	*inbuf = (char *)ip;
	*inbytesleft = ileft;
	*outbuf = (char *)op;
	*outbytesleft = oleft;

	return (retval);
}
