/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <libgen.h>

/*
 *	strccpy(output, input)
 *	strccpy copys the input string to the output string compressing
 *	any C-like escape sequences to the real character.
 *	Escape sequences recognized are those defined in "The C Programming
 *	Language" by Kernighan and Ritchie.  strccpy returns the output
 *	argument.
 *
 *	strcadd(output, input)
 *	Identical to strccpy() except returns address of null-byte at end
 *	of output.  Useful for concatenating strings.
 */

char *
strccpy(char *pout, const char *pin)
{
	(void) strcadd(pout, pin);
	return (pout);
}


char *
strcadd(char *pout, const char *pin)
{
	char	c;
	int	count;
	int	wd;

	while (c = *pin++) {
		if (c == '\\')
			switch (c = *pin++) {
			case 'n':
				*pout++ = '\n';
				continue;
			case 't':
				*pout++ = '\t';
				continue;
			case 'b':
				*pout++ = '\b';
				continue;
			case 'r':
				*pout++ = '\r';
				continue;
			case 'f':
				*pout++ = '\f';
				continue;
			case 'v':
				*pout++ = '\v';
				continue;
			case 'a':
				*pout++ = '\007';
				continue;
			case '\\':
				*pout++ = '\\';
				continue;
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
				wd = c - '0';
				count = 0;
				while ((c = *pin++) >= '0' && c <= '7') {
					wd <<= 3;
					wd |= (c - '0');
					if (++count > 1) {   /* 3 digits max */
						pin++;
						break;
					}
				}
				*pout++ = (char)wd;
				--pin;
				continue;
			default:
				*pout++ = c;
				continue;
		}
		*pout++ = c;
	}
	*pout = '\0';
	return (pout);
}
