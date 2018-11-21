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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <euc.h>

#include "japanese.h"
#include "jfp_iconv_unicode.h"

#ifdef JAVA_CONV_COMPAT
#define	JFP_U2E_ICONV_JAVA
#elif	JFP_ICONV_MS932
#define	JFP_U2E_ICONV_MS932
#else
#define	JFP_U2E_ICONV
#endif
#include "jfp_ucs2_to_euc16.h"

#define	DEF_SINGLE	'?'

static unsigned short lookuptbl(unsigned short);

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
	unsigned char	ic;
	size_t		rv = (size_t)0;
	unsigned int	ucs4;
	unsigned short	euc16;
	unsigned short	dest;

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
		GETU(&ucs4);

		if (ucs4 > 0xffff) {
			/* non-BMP */
			NPUT((unsigned char)DEF_SINGLE, "non-BMP(replaced)");
		} else {
			euc16 = _jfp_ucs2_to_euc16((unsigned short)ucs4);

			switch (euc16 & 0x8080) {
			case 0x0000:	/* CS0 */
				if (ISC1CTRL((unsigned char)euc16)) {
					NPUT((unsigned char)'?',
						"CS0-C1CTRL(replaced)")
				} else {
					ic = (unsigned char)euc16;
					NPUT(ic, "CS0-1");
				}
				break;
			case 0x8080:	/* CS1 */
				ic = (unsigned short)((euc16 >> 8) & 0x7f);
				NPUT(jis208tosj1[ic], "CS1-1");
				/*
				 * for even number row (Ku), add 0x80 to
				 * look latter half of jistosj2[] array
				 */
				ic = (unsigned char)((euc16 & 0x7f)
					+ (((ic % 2) == 0) ? 0x80 : 0x00));
				NPUT(jistosj2[ic], "CS1-2");
				break;
			case 0x0080:	/* CS2 */
				ic = (unsigned char)euc16;
				NPUT(ic, "CS2-1");
				break;
			case 0x8000:	/* CS3 */
				ic = (unsigned short)((euc16 >> 8) & 0x7f);
				if (euc16 == 0xa271) {
					/* NUMERO SIGN */
					NPUT(0x87, "CS3-NUMERO-1");
					NPUT(0x82, "CS3-NUMERO-2");
				} else if (ic < 0x75) { /* check if IBM VDC */
					dest = lookuptbl(euc16 & 0x7f7f);
					if (dest == 0xffff) {
						NPUT((unsigned char)'?',
							"CS3-NoSJIS(replaced)")
					} else {
#ifdef	JAVA_CONV_COMPAT
						NPUT((unsigned char)'?',
							"CS3-IBM(replaced)")
#else	/* !JAVA_CONV_COMPAT */
						/* avoid putting NUL ('\0') */
						if (dest > 0xff) {
							NPUT((dest >> 8) & 0xff,
								"CS3-IBM-1");
							NPUT(dest & 0xff,
								"CS3-IBM-2");
						} else {
							NPUT(dest & 0xff,
								"CS3-IBM-1");
						}
#endif	/* JAVA_CONV_COMPAT */
					}
				} else {
					NPUT(jis212tosj1[ic], "CS3-1");
					/*
					 * for even number row (Ku), add 0x80 to
					 * look latter half of jistosj2[] array
					 */
					ic = (unsigned short)((euc16 & 0x7f)
						+ (((ic % 2) == 0) ?
						0x80 : 0x00));
					NPUT(jistosj2[ic], "CS3-2");
				}
				break;
			}
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

/*
 * lookuptbl()
 * Return the index number if its index-ed number
 * is the same as dest value.
 */
static unsigned short
lookuptbl(unsigned short dest)
{
	unsigned short tmp;
	int i;
	int sz = (sizeof (sjtoibmext) / sizeof (sjtoibmext[0]));

	for (i = 0; i < sz; i++) {
		tmp = (sjtoibmext[i] & 0x7f7f);
		if (tmp == dest)
			return ((i + 0xfa40 + ((i / 0xc0) * 0x40)));
	}
	return (0x3f);
}
