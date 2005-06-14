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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <locale.h>

int
main(int argc, char *argv[])
{

	register char	*cp;
	register int	i, wd;
	int	j;
	wchar_t		wc;
	int		b_len;
	char		*ep;

#ifdef	_iBCS2
	int		no_nl = 0;
#endif
	(void) setlocale(LC_ALL, "");

	if (--argc == 0) {
		(void) putchar('\n');
		if (fflush(stdout) != 0)
			return (1);
		return (0);
	}

#ifdef	_iBCS2
	/* If SYSV3 is set, check for ISC/SCO style -n option parsing. */
	if (getenv("SYSV3")) {
		if (strcmp(argv[1], "-n") == 0)
			no_nl ++;
	}
	for (i = 1 + no_nl; i <= argc; i++) {
#else
	for (i = 1; i <= argc; i++) {
#endif	/*  _iBCS2 */
		for (cp = argv[i], ep = cp + (int)strlen(cp);
			cp < ep; cp += b_len) {
		if ((b_len = mbtowc(&wc, cp, MB_CUR_MAX)) <= 0) {
			(void) putchar(*cp);
			b_len = 1;
			continue;
		}

		if (wc != '\\') {
			(void) putwchar(wc);
			continue;
		}

			cp += b_len;
			b_len = 1;
			switch (*cp) {
				case 'a':	/* alert - XCU4 */
					(void) putchar('\a');
					continue;

				case 'b':
					(void) putchar('\b');
					continue;

				case 'c':
					if (fflush(stdout) != 0)
						return (1);
					return (0);

				case 'f':
					(void) putchar('\f');
					continue;

				case 'n':
					(void) putchar('\n');
					continue;

				case 'r':
					(void) putchar('\r');
					continue;

				case 't':
					(void) putchar('\t');
					continue;

				case 'v':
					(void) putchar('\v');
					continue;

				case '\\':
					(void) putchar('\\');
					continue;
				case '0':
					j = wd = 0;
					while ((*++cp >= '0' && *cp <= '7') &&
						j++ < 3) {
						wd <<= 3;
						wd |= (*cp - '0');
					}
					(void) putchar(wd);
					--cp;
					continue;

				default:
					cp--;
					(void) putchar(*cp);
			}
		}
#ifdef	_iBCS2
		if (!(no_nl && i == argc))
#endif	/* _iBCS2 */
			(void) putchar(i == argc? '\n': ' ');
			if (fflush(stdout) != 0)
				return (1);
	}
	return (0);
}
