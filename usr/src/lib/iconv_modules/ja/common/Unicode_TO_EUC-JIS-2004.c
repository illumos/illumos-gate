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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <errno.h>
#include <euc.h>

#include "japanese.h"
#include "jfp_iconv_unicode.h"

#define	JFP_U2E_ICONV_X0213
#include "jfp_ucs2_to_euc16.h"

#define	DEF_SINGLE	'?'

void *
_icv_open(void)
{
	return (_icv_open_unicode((size_t)0));
}

void
_icv_close(void *cd)
{
	_icv_close_unicode(cd);
	return;
}

size_t
_icv_iconv(void *cd, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	unsigned int	u32;		/* UTF-32 */
	unsigned short	e16;		/* 16-bit EUC */
	unsigned char	ic;
	size_t		rv = (size_t)0;

	unsigned char	*ip;
        size_t		ileft;
	char		*op;
        size_t		oleft;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		_icv_reset_unicode(cd);
		return ((size_t)0);
	}

	ip = (unsigned char *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		GETU(&u32)

		e16 = _jfp_u32_to_euc16(u32);

		switch (e16 & 0x8080) {
		case 0x0000:	/* CS0 */
			ic = (unsigned char)e16;
			NPUT(ic, "CS0");
			break;
		case 0x8080:	/* CS1 */
			ic = (unsigned char)((e16 >> 8) & 0xff);
			NPUT(ic, "CS1-1");
			ic = (unsigned char)(e16 & 0xff);
			NPUT(ic, "CS1-2");
			break;
		case 0x0080:	/* CS2 */
			NPUT(SS2, "CS2-1");
			ic = (unsigned char)e16;
			NPUT(ic, "CS2-2");
			break;
		case 0x8000:	/* CS3 */
			NPUT(SS3, "CS3-1");
			ic = (unsigned char)((e16 >> 8) & 0xff);
			NPUT(ic, "CS3-2");
			ic = (unsigned char)(e16 & 0xff);
			NPUT(ic | CMSB, "CS3-3");
			break;
		}

next:
		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbuf = (char *)ip;
		*inbytesleft = ileft;
		*outbuf = op;
		*outbytesleft = oleft;
	}

ret:

	DEBUGPRINTERROR

	/*
	 * Return value for successful return is not defined by XPG
	 * so return same as *inbytesleft as existing codes do.
	 */
	return ((rv == (size_t)-1) ? rv : *inbytesleft);
}
