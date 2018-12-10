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
 * COPYRIGHT AND PERMISSION NOTICE
 *
 * Copyright (c) 1991-2005 Unicode, Inc. All rights reserved. Distributed
 * under the Terms of Use in http://www.unicode.org/copyright.html.
 *
 * This file has been modified by Sun Microsystems, Inc.
 */
/*
 * Copyright 1999-2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#if	defined(DEBUG)
#include <stdio.h>
#endif	/* DEBUG */
#include <stdlib.h>
#include <errno.h>

#define	JFP_ICONV_STATELESS
#include "japanese.h"
#include "jfp_iconv_unicode.h"

void *
_icv_open(void)
{
	return (_icv_open_stateless());
}

void
_icv_close(void *cd)
{
	_icv_close_stateless(cd);
	return;
}

size_t
_icv_iconv(void *cd, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	size_t		rv = (size_t)0;
	unsigned int	ucs4;

	unsigned char	*ip;
        size_t		ileft;
	char		*op;
        size_t		oleft;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		/* nothing to do here for this module */
		return ((size_t)0);
	}

	ip = (unsigned char *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		if (utf8_ucs(&ucs4, &ip, &ileft) == (size_t)-1) {
			/* errno has been set in utf8_ucs() */
			rv = (size_t)-1;
			goto ret;
		}

		if (ucs4 == 0x301c)		/* WAVE DASH */
			ucs4 = 0xff5e;		/* FULLWIDTH TILDE */
		else if (ucs4 == 0x2016)	/* DOUBLE VERTICAL BAR/LINE */
			ucs4 = 0x2225;		/* PARALLEL TO */
		else if (ucs4 == 0x2212)	/* MINUS SIGN */
			ucs4 = 0xff0d;		/* FULLWIDTH MINUS SIGN */
		else if (ucs4 == 0x00a2)	/* CENT SIGN */
			ucs4 = 0xffe0;		/* FULLWIDTH CENT SIGN */
		else if (ucs4 == 0x00a3)	/* POUND SIGN */
			ucs4 = 0xffe1;		/* FULLWIDTH POUND SIGN */
		else if (ucs4 == 0x00ac)	/* NOT SIGN */
			ucs4 = 0xffe2;		/* FULLWIDTH NOT SIGN */

		PUTUCS2((unsigned short)ucs4, "E2BIG");

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

#if	defined(DEBUG)
	if (rv == (size_t)-1) {
		fprintf(stderr, "DEBUG: errno=%d: %s\n", errno, debugmsg);
	}
#endif	/* DEBUG */

	/*
	 * Return value for successful return is not defined by XPG
	 * so return same as *inbytesleft as existing codes do.
	 */
	return ((rv == (size_t)-1) ? rv : *inbytesleft);
}
