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

#include <sys/types.h>
#include <sys/promif.h>

int
getchar(void)
{
	register int c;

	while ((c = prom_mayget()) == -1)
		;
	if (c == '\r') {
		prom_putchar(c);
		c = '\n';
	}
	if (c == 0177 || c == '\b') {
		prom_putchar('\b');
		prom_putchar(' ');
		c = '\b';
	}
	prom_putchar(c);
	return (c);
}

int
cons_gets(char *buf, int n)
{
	char *lp;
	char *limit;
	int c;

	lp = buf;
	limit = &buf[n - 1];
	for (;;) {
		c = getchar() & 0177;
		switch (c) {
		case '\n':
		case '\r':
			*lp = '\0';
			return (0);
		case '\b':
			if (lp > buf)
				lp--;
			continue;
		case 'u'&037:			/* ^U */
			lp = buf;
			prom_putchar('\r');
			prom_putchar('\n');
			continue;
		default:
			if (lp < limit)
				*lp++ = (char)c;
			else
				prom_putchar('\a');	/* bell */
		}
	}
}
