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
 * Copyright (c) 1994, Sun Microsystems, Inc.
 * Copyright (c) 1994, Nihon Sun Microsystems K.K.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <euc.h>
#include "japanese.h"
#include "table.IBM-500.8859-1.c"

/*
 * struct _cv_state; to keep status
 */
struct _icv_state {
	int	_st_cset;
	int	_st_stat;
};

extern int errno;

/*
 * Open; called from iconv_open(); as taken unchanged from @(#)ISO-2022-JP%SJIS.
 */
void *
_icv_open()
{
	struct _icv_state *st;

	if ((st = (struct _icv_state *)malloc(sizeof(struct _icv_state)))
									== NULL)
		return ((void *)ERR_RETURN);

	st->_st_cset = CS_0;
	st->_st_stat = ST_INIT;

	return (st);
}


/*
 * Close; called from iconv_close();  as taken unchanged from @(#)ISO-2022-JP%SJIS.
 */
void
_icv_close(struct _icv_state *st)
{
	free(st);
}



/*
 * Actual conversion; called from iconv()
 */
size_t
_icv_iconv(struct _icv_state *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	int				cset, stat;
	unsigned char	*op, ic;
	char			*ip;
	size_t			ileft, oleft;
	size_t			retval;

	cset = st->_st_cset;
	stat = st->_st_stat;

	if ((inbuf == 0) || (*inbuf == 0)) {
		cset = CS_0;
		stat = ST_INIT;
		op = (unsigned char *)*outbuf;
		oleft = *outbytesleft;
		retval = 0;
		goto ret2;
	}

	ip = *inbuf;
	op = (unsigned char *)*outbuf;
	ileft = *inbytesleft;
	oleft = *outbytesleft;

	/* Everything down to here was taken unchanged from  @(#)ISO-2022-JP%SJIS.
	   =======================================================================

	 *
	 * Main loop; basically 1 loop per 1 input byte
	 */

	while (ileft > 0)
	{
		GET(ic);
	/*
		If the char is one of the following [ / ] { | } then convert
		it to its corresponding value. In all other cases if the char
		is greater than octal \178 ( ie a high bit char) convert it
		to an underscore (_), as it has no mapping to 7 bit ASCII.
		Otrherwise the char is the same in both cose sets.
	*/
		ic=__cp500_to_iso[ic];


		PUT(ic);
	/*
		Put the converted character into the output buffer, and decrement
		the count of chars left in both the in and out buffers.
		If we have no space left in the out buffer, but we have no reached
		the end of the input buffer. We return what we have, and set the
		errno (Error) to E2BIG.
	*/
		if ((oleft < 1)	 && (ileft > 0))
		{
			errno = E2BIG;
			retval = ERR_RETURN;
			goto ret;
		}


	}
/*
We only get here if the end of the in buffer has been reached, we therefore return the
value 0 to denote that we have sucesfully converted the inbuffer.
*/
	retval = ileft;

/*  Taken unchanged from   @(#)ISO-2022-JP%SJIS.  */

ret:
	st->_st_cset = cset;
	st->_st_stat = stat;
	*inbuf = ip;
	*inbytesleft = ileft;
ret2:
	*outbuf = (char *)op;
	*outbytesleft = oleft;

	return (retval);
}
