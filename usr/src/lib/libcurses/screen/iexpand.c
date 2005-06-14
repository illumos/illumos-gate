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
/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdio.h>

/*
 *	Convert a character, making appropriate changes to make it printable
 *	for a terminfo source entry. Change escape to \E, tab to \t, backspace
 *	to \b, formfeed to \f, newline to \n, and return to \r. Change other
 *	control characters into ^X notation. Change meta characters into octal
 *	(\nnn) notation. Also place a backslash in front of commas,
 *	carets(^), and backslashes(\). Return the number of characters printed.
 */

#define	BACKSLASH	'\\'
#define	BACKBACK	"\\\\"

static char retbuffer[1024];

/*
 *  Expand a string taking terminfo sequences into consideration.
 */
char
*iexpand(char *string)
{
	int	c;
	char	*retptr = retbuffer;

	retbuffer[0] = '\0';
	while ((c = *string++) != 0) {
		/* should check here to make sure that there is enough room */
		/* in retbuffer and realloc it if necessary. */
		c &= 0377;
		/* we ignore the return value from sprintf because BSD/V7 */
		/* systems return a (char *) rather than an int. */
		if (c >= 0200) {
			(void) sprintf(retptr, "\\%.3o", c); retptr += 4; }
		else if (c == '\033') {
			(void) sprintf(retptr, "\\E"); retptr += 2; }
		else if (c == '\t') {
			(void) sprintf(retptr, "\\t"); retptr += 2; }
		else if (c == '\b') {
			(void) sprintf(retptr, "\\b"); retptr += 2; }
		else if (c == '\f') {
			(void) sprintf(retptr, "\\f"); retptr += 2; }
		else if (c == '\n') {
			(void) sprintf(retptr, "\\n"); retptr += 2; }
		else if (c == '\r') {
			(void) sprintf(retptr, "\\r"); retptr += 2; }
		else if (c == ',') {
			(void) sprintf(retptr, "\\,"); retptr += 2; }
		else if (c == '^') {
			(void) sprintf(retptr, "\\^"); retptr += 2; }
		else if (c == BACKSLASH) {
			(void) sprintf(retptr, BACKBACK); retptr += 2; }
		else if (c == ' ') {
			(void) sprintf(retptr, "\\s"); retptr += 2; }
		else if (c < ' ' || c == 0177) {
			(void) sprintf(retptr, "^%c", c ^ 0100); retptr += 2; }
		else {
			(void) sprintf(retptr, "%c", c); retptr++; }
	}
	*retptr = '\0';
	return (retbuffer);
}

/*
 *  Print out a string onto a stream, changing unprintables into
 *  terminfo printables.
 */
void
tpr(FILE *stream, char *string)
{
	if (string != NULL)
		(void) fprintf(stream, "%s", iexpand(string));
}
