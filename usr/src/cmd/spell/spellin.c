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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include "hash.h"
#include "huff.h"

int	encode(long, long *);

#define	S (BYTE * sizeof (long))
#define	B (BYTE * sizeof (unsigned))
unsigned *table;
int hindex[NI];
unsigned wp;		/* word pointer */
int bp = B;		/* bit pointer */
static int ignore;
static int extra;

static int
append(register unsigned w1, register int i)
{
	while (wp < ND - 1) {
		table[wp] |= w1>>(B-bp);
		i -= bp;
		if (i < 0) {
			bp = -i;
			return (1);
		}
		w1 <<= bp;
		bp = B;
		wp++;
	}
	return (0);
}


/*
 *	usage: hashin N
 *	where N is number of words in dictionary
 *	and standard input contains sorted, unique
 *	hashed words in octal
 */

int
main(int argc, char **argv)
{
	long h, k, d;
	int  i;
	long count;
	long w1;
	long x;
	int t, u;
	double z;

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	k = 0;
	u = 0;
	if (argc != 2) {
		(void) fprintf(stderr, gettext("%s: arg count\n"), argv[0]);
		exit(1);
	}
	table = (unsigned *)malloc(ND * sizeof (*table));
	if (table == 0) {
		(void) fprintf(stderr, gettext("%s: no space for table\n"),
		    argv[0]);
		exit(1);
	}
	if ((atof(argv[1])) == 0.0) {
		(void) fprintf(stderr, gettext("%s: illegal count"), argv[0]);
		exit(1);
	}

	z = huff((1L<<HASHWIDTH)/atof(argv[1]));
	(void) fprintf(stderr, gettext("%s: expected code widths = %f\n"),
	    argv[0], z);
	for (count = 0; scanf("%lo", (unsigned long *)&h) == 1; ++count) {
		if ((t = h >> (HASHWIDTH - INDEXWIDTH)) != u) {
			if (bp != B)
				wp++;
			bp = B;
			while (u < t)
				hindex[++u] = wp;
			k =  (long)t<<(HASHWIDTH-INDEXWIDTH);
		}
		d = h-k;
		k = h;
		for (;;) {
			for (x = d; ; x /= 2) {
				i = encode(x, &w1);
				if (i > 0)
					break;
			}
			if (i > B) {
				if (!(append((unsigned)(w1>>(long) (i-B)), B) &&
				    append((unsigned)(w1<<(long) (B+B-i)),
				    i-B)))
					ignore++;
			} else
				if (!append((unsigned)(w1<<(long)(B-i)), i))
					ignore++;
			d -= x;
			if (d > 0)
				extra++;
			else
				break;
		}
	}
	if (bp != B)
		wp++;
	while (++u < NI)
		hindex[u] = wp;
	whuff();
	(void) fwrite((char *)hindex, sizeof (*hindex), NI, stdout);
	(void) fwrite((char *)table, sizeof (*table), wp, stdout);
	(void) fprintf(stderr,
	    gettext("%s: %ld items, %d ignored, %d extra, %u words occupied\n"),
	    argv[0], count, ignore, extra, wp);
	count -= ignore;
	(void) fprintf(stderr, "%s: %f table bits/item, %f table+index bits\n",
	    argv[0], (((float)BYTE * wp) * sizeof (*table) / count),
	    (BYTE * ((float)wp * sizeof (*table) + sizeof (hindex)) / count));
	return (0);
}
