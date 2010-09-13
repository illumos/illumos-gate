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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <locale.h>
#include "hash.h"
#include "huff.h"

int	decode(long, long *);

int hindex[NI];
unsigned *table;
unsigned wp;
int bp;
#define	U (BYTE*sizeof (unsigned))
#define	L (BYTE*sizeof (long))

static long
fetch(void)
{
	long w1;
	long y = 0;
	int empty = L;
	int i = bp;
	int tp = wp;
	while (empty >= i) {
		empty -= i;
		i = U;
		y |= (long)table[tp++] << empty;
	}
	if (empty > 0)
		y |= table[tp]>>i-empty;
	i = decode((y >> 1) &
	    (((unsigned long)1 << (BYTE * sizeof (y) - 1)) - 1), &w1);
	bp -= i;
	while (bp <= 0) {
		bp += U;
		wp++;
	}
	return (w1);
}


/* ARGSUSED */
int
main(int argc, char **argv)
{
	int i;
	long v;
	long a;

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) rhuff(stdin);
	(void) fread((char *)hindex, sizeof (*hindex), NI, stdin);
	table = (unsigned *)malloc(hindex[NI-1]*sizeof (*table));
	(void) fread((char *)table, sizeof (*table), hindex[NI-1], stdin);
	for (i = 0; i < NI-1; i++) {
		bp = U;
		v = (long)i<<(HASHWIDTH-INDEXWIDTH);
		for (wp = hindex[i]; wp < hindex[i+1]; ) {
			if (wp == hindex[i] && bp == U)
				a = fetch();
			else {
				a = fetch();
				if (a == 0)
					break;
			}
			if (wp > hindex[i+1] ||
				wp == hindex[i+1] && bp < U)
				break;
			v += a;
			(void) printf("%.9lo\n", v);
		}
	}
	return (0);
}
