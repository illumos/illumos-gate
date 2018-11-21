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
 *  ICU License - ICU 1.8.1 and later
 *
 *  COPYRIGHT AND PERMISSION NOTICE
 *
 * Copyright (c) 1995-2005 International Business Machines Corporation and others
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 *
 * --------------------------------------------------------------------------
 * All trademarks and registered trademarks mentioned herein are the property
 * of their respective owners.
 */

/*
 * Copyright (c) 1994, 1995 by Sun Microsystems, Inc.
 * Copyright (c) 1994, Nihon Sun Microsystems K.K.
 * All Rights Reserved.
 */

/*
  Converts ASCII ISO 8859-1 to EBCDIC IBM-037.
  By Greg Nakhimovsky, Sun Microsystems.
  April, 1996.
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

	static unsigned char map[256] = {
		0x00 , 0x01 , 0x02 , 0x03 , 0x37 , 0x2D , 0x2E , 0x2F , 0x16 , 0x05 ,
		0x25 , 0x0B , 0x0C , 0x0D , 0x0E , 0x0F , 0x10 , 0x11 , 0x12 , 0x13 ,
		0x3C , 0x3D , 0x32 , 0x26 , 0x18 , 0x19 , 0x3F , 0x27 , 0x1C , 0x1D ,
		0x1E , 0x1F , 0x40 , 0x5A , 0x7F , 0x7B , 0x5B , 0x6C , 0x50 , 0x7D ,
		0x4D , 0x5D , 0x5C , 0x4E , 0x6B , 0x60 , 0x4B , 0x61 , 0xF0 , 0xF1 ,
		0xF2 , 0xF3 , 0xF4 , 0xF5 , 0xF6 , 0xF7 , 0xF8 , 0xF9 , 0x7A , 0x5E ,
		0x4C , 0x7E , 0x6E , 0x6F , 0x7C , 0xC1 , 0xC2 , 0xC3 , 0xC4 , 0xC5 ,
		0xC6 , 0xC7 , 0xC8 , 0xC9 , 0xD1 , 0xD2 , 0xD3 , 0xD4 , 0xD5 , 0xD6 ,
		0xD7 , 0xD8 , 0xD9 , 0xE2 , 0xE3 , 0xE4 , 0xE5 , 0xE6 , 0xE7 , 0xE8 ,
		0xE9 , 0xBA , 0xE0 , 0xBB , 0xB0 , 0x6D , 0x79 , 0x81 , 0x82 , 0x83 ,
		0x84 , 0x85 , 0x86 , 0x87 , 0x88 , 0x89 , 0x91 , 0x92 , 0x93 , 0x94 ,
		0x95 , 0x96 , 0x97 , 0x98 , 0x99 , 0xA2 , 0xA3 , 0xA4 , 0xA5 , 0xA6 ,
		0xA7 , 0xA8 , 0xA9 , 0xC0 , 0x4F , 0xD0 , 0xA1 , 0x3F , 0x3F , 0x3F ,
		0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F ,
		0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F ,
		0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F , 0x3F ,
		0x41 , 0xAA , 0x4A , 0xB1 , 0x9F , 0xB2 , 0x6A , 0xB5 , 0xBD , 0xB4 ,
		0x9A , 0x8A , 0x5F , 0xCA , 0xAF , 0xBC , 0x90 , 0x8F , 0xEA , 0xFA ,
		0xBE , 0xA0 , 0xB6 , 0xB3 , 0x9D , 0xDA , 0x9B , 0x8B , 0xB7 , 0xB8 ,
		0xB9 , 0xAB , 0x64 , 0x65 , 0x62 , 0x66 , 0x63 , 0x67 , 0x9E , 0x68 ,
		0x74 , 0x71 , 0x72 , 0x73 , 0x78 , 0x75 , 0x76 , 0x77 , 0xAC , 0x69 ,
		0xED , 0xEE , 0xEB , 0xEF , 0xEC , 0xBF , 0x80 , 0xFD , 0xFE , 0xFB ,
		0xFC , 0xAD , 0xAE , 0x59 , 0x44 , 0x45 , 0x42 , 0x46 , 0x43 , 0x47 ,
		0x9C , 0x48 , 0x54 , 0x51 , 0x52 , 0x53 , 0x58 , 0x55 , 0x56 , 0x57 ,
		0x8C , 0x49 , 0xCD , 0xCE , 0xCB , 0xCF , 0xCC , 0xE1 , 0x70 , 0xDD ,
		0xDE , 0xDB , 0xDC , 0x8D , 0x8E , 0xDF};

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
		PUT(map[ic]);
		retval++;
	}

ret:
	*inbuf = (char *)ip;
	*inbytesleft = ileft;
	*outbuf = (char *)op;
	*outbytesleft = oleft;

	return (retval);
}
