/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#include	"uucp.h"
#include <rpc/trace.h> 

/*
	strecpy(output, input, except)
	strccpy copys the input string to the output string expanding
	any non-graphic character with the C escape sequence.
	Esacpe sequences produced are those defined in "The C Programming
	Language" pages 180-181.
	Characters in the except string will not be expanded.
*/

GLOBAL char *
strecpy(pout, pin, except)
register char	*pout;
register char	*pin;
char	*except;
{
	register unsigned	c;
	register char		*output;

	trace1(TR_strecpy, 0);
	output = pout;
	while ((c = *pin++) != 0) {
		if (!isprint(c)  &&  (!except  ||  !strchr(except, c))) {
			*pout++ = '\\';
			switch(c) {
			case '\n':
				*pout++ = 'n';
				continue;
			case '\t':
				*pout++ = 't';
				continue;
			case '\b':
				*pout++ = 'b';
				continue;
			case '\r':
				*pout++ = 'r';
				continue;
			case '\f':
				*pout++ = 'f';
				continue;
			case '\v':
				*pout++ = 'v';
				continue;
			case '\\':
				continue;
			default:
				sprintf(pout, "%.3o", c);
				pout += 3;
				continue;
			}
		}
		if (c == '\\'  &&  (!except  ||  !strchr(except, c)))
			*pout++ = '\\';
		*pout++ = (char) c;
	}
	*pout = '\0';
	trace1(TR_strecpy, 1);
	return  (output);
}
