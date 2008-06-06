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
#include <ctype.h>
#include <string.h>
#include <stdio.h>

/*
 *	strecpy(output, input, except)
 *	strecpy copies the input string to the output string expanding
 *	any non-graphic character with the C escape sequence.  Escape
 *	sequences produced are those defined in "The C Programming
 *	Language" by Kernighan and Ritchie.
 *	Characters in the `except' string will not be expanded.
 *	Returns the first argument.
 *
 *	streadd( output, input, except )
 *	Identical to strecpy() except returns address of null-byte at end
 *	of output.  Useful for concatenating strings.
 */


char *
strecpy(char *pout, const char *pin, const char *except)
{
	(void) streadd(pout, pin, except);
	return (pout);
}


char *
streadd(char *pout, const char *pin, const char *except)
{
	unsigned	c;

	while ((c = *pin++) != 0) {
		if (!isprint(c) && (!except || !strchr(except, c))) {
			*pout++ = '\\';
			switch (c) {
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
			case '\007':
				*pout++ = 'a';
				continue;
			case '\\':
				continue;
			default:
				(void) sprintf(pout, "%.3o", c);
				pout += 3;
				continue;
			}
		}
		if (c == '\\' && (!except || !strchr(except, c)))
			*pout++ = '\\';
		*pout++ = (char)c;
	}
	*pout = '\0';
	return (pout);
}
