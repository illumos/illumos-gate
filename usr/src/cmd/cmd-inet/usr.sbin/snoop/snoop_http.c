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
 * Copyright (c) 1996-1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Protocol interpreter for the Hypertext Transfer Protocol (HTTP)
 *
 * Relevant standards:
 *	Berners-Lee, T., et al: Hypertext Transfer Protocol -- HTTP/1.0.
 *	    RFC 1945, May 1996
 *	Fielding, R., et al: Hypertext Transfer Protocol -- HTTP/1.1.
 *	    RFC 2068, June 1999
 */

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "snoop.h"

#define	CR	13			/* "carriage return" character */
#define	LF	10			/* "line feed" character */

/*
 * Summary lines: packet contents starting with less than MINCHARS
 * printable characters will not be printed. MAXCHARS is the maximum
 * number of characters printed.
 * Detail lines: NLINES is the maximum number of content lines to print
 */
#define	MINCHARS	10
#define	MAXCHARS	80
#define	NLINES		5

#define	MIN(a, b) (((a) < (b)) ? (a) : (b))

static int printable(const char *line, const char *endp);

int
interpret_http(int flags, char *line, int fraglen)
{
	char *p, *q, *endp;
	int c;
	int lineno;

	endp = line + fraglen;

	if (flags & F_SUM) {
		c = printable(line, endp - 1);
		if (c < MINCHARS) {
			(void) snprintf(get_sum_line(), MAXLINE,
				"HTTP (body)");
		} else {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "HTTP %.*s", MIN(c, MAXCHARS), line);
		}
	}

	if (flags & F_DTAIL) {
		show_header("HTTP: ", "HyperText Transfer Protocol", fraglen);
		show_space();

		lineno = 0;
		for (p = line; p < endp && lineno < NLINES; p = q + 1) {
			c = printable(p, endp - 1);

			/* stop if no printables, except if at line end */
			if (c == 0 && *p != CR && *p != LF)
				break;

			/*
			 * A line may be terminated either by an CR LF sequence
			 * (DOS, Mac), or by LF alone
			 */

			q = memchr(p, CR, (endp - p));
			if (q != NULL) {
			    if (q < endp - 1 && q[1] == LF)
				++q;	/* ignore subsequent LF character */
			} else {
			    q = memchr(p, LF, (endp - p));
			    /* no CR/LF: use end of buffer */
			    if (q == NULL)
				q = endp - 1;
			}

			/* truncate lines containing non-printable characters */
			(void) snprintf(get_line(0, c), get_line_remain(),
			    "%.*s", c, p);
			++lineno;
		}

		if (p < endp)	/* there was more data to be printed */
			(void) snprintf(get_line(0, 5), get_line_remain(),
			    "[...]");

		show_space();
	}

	return (fraglen);
}

/*
 * Return the length of the initial string starting with "startp" and
 * ending with "endp" (inclusively) consisting only of printable
 * characters.
 */

static int
printable(const char *startp, const char *endp)
{
	const char *p = startp;

	while (p <= endp && (isprint(*p) || *p == '\t'))
		p++;

	return (p - startp);
}
