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

#define	BYTE 8
#define	QW 1		/* width of bas-q digit in bits */

/*
 * this stuff should be local and hidden; it was made
 * accessible outside for dirty reasons: 20% faster spell
 */
#include "huff.h"
struct huff huffcode;

/*
 * Infinite Huffman code
 *
 * Let the messages be exponentially distributed with ratio r:
 * 	P {message k} = r^k*(1-r),	k = 0, 1, ...
 * Let the messages be coded in base q, and suppose
 * 	r^n = 1/q
 * If each decade(base q) contains n codes, then
 * the messages assigned to each decade will be q times
 * as probable as the next. Moreover the code for the tail of
 * the distribution after truncating one decade should look
 * just like the original, but longer by one leading digit q-1.
 * 	q(z+n) = z + (q-1)q^w
 * where z is first code of decade, w is width of code, in shortest
 * full decade. Examples, base 2:
 * 	r^1 = 1/2	r^5 = 1/2
 * 	0		0110
 * 	10		0111
 * 	110		1000
 * 	1110		1001
 * 	...		1010
 * 			10110
 * 	w = 1, z = 0		w = 4, z = 0110
 * Rewriting slightly
 * 	(q-1)z + q*n = (q-1)q^w
 * whence z is a multiple of q and n is a multiple of q-1. Let
 * 	z = cq, n = d(q-1)
 * We pick w to be the least integer such that
 * 	d = n/(q-1) <= q^(w-1)
 * Then solve for c
 * 	c = q^(w-1) - d
 * If c is not zero, the first decade may be preceded by
 * even shorter (w-1)-digit codes 0, 1, ..., c-1. Thus
 * the example code with r^5 = 1/2 becomes
 * 	000
 * 	001
 * 	010
 * 	0110
 * 	0111
 * 	1000
 * 	1001
 * 	1010
 * 	10110
 * 	...
 * 	110110
 * 	...
 * The expected number of base-q digits in a codeword is then
 *	w - 1 + r^c/(1-r^n)
 * The present routines require q to be a power of 2
 */
/*
 * There is a lot of hanky-panky with left justification against
 * sign instead of simple left justification because
 * unsigned long is not available
 */
#define	L (BYTE*(sizeof (long))-1)	/* length of signless long */
#define	MASK (~((unsigned long)1<<L))	/* mask out sign */

/*
 * decode the prefix of word y (which is left justified against sign)
 * place mesage number into place pointed to by kp
 * return length (in bits) of decoded prefix or 0 if code is out of
 * range
 */
int
decode(long y, long *pk)
{
	int l;
	long v;
	if (y < cs) {
		*pk = y >> (long)(L+QW-w);
		return (w-QW);
	}
	for (l = w, v = v0; y >= qcs;
	    y = ((unsigned long)y << QW) & MASK, v += n)
		if ((l += QW) > L)
			return (0);
	*pk = v + (y>>(long)(L-w));
	return (l);
}

/*
 * encode message k and put result (right justified) into
 * place pointed to by py.
 * return length (in bits) of result,
 * or 0 if code is too long
 */

int
encode(long k, long *py)
{
	int l;
	long y;
	if (k < c) {
		*py = k;
		return (w-QW);
	}
	for (k -= c, y = 1, l = w; k >= n; k -= n, y <<= QW)
		if ((l += QW) > L)
			return (0);
	*py = ((y-1)<<w) + cq + k;
	return (l);
}


/*
 * Initialization code, given expected value of k
 * E(k) = r/(1-r) = a
 * and given base width b
 * return expected length of coded messages
 */
static struct qlog {
	long p;
	double u;
} z;

static struct qlog
qlog(double x, double y, long p, double u)	/* find smallest p so x^p<=y */
{

	if (u/x <= y) {
		z.p = 0;
		z.u = 1;
	} else {
		z = qlog(x, y, p+p, u*u);
		if (u*z.u/x > y) {
			z.p += p;
			z.u *= u;
		}
	}
	return (z);
}

double
huff(float a)
{
	int i, q;
	long d, j;
	double r = a/(1.0 + a);
	double rc, rq;

	for (i = 0, q = 1, rq = r; i < QW; i++, q *= 2, rq *= rq)
		continue;
	rq /= r;	/* rq = r^(q-1) */
	(void) qlog(rq, 1./q, 1L, rq);
	d = z.p;
	n = d*(q-1);
	if (n != d * (q - 1))
		abort();	/* time to make n long */
	for (w = QW, j = 1; j < d; w += QW, j *= q)
		continue;
	c = j - d;
	cq = c*q;
	cs = cq<<(L-w);
	qcs = (((long)(q-1)<<w) + cq) << (L-QW-w);
	v0 = c - cq;
	for (i = 0, rc = 1; i < c; i++, rc *= r)	/* rc = r^c */
		continue;
	return (w + QW*(rc/(1-z.u) - 1));
}

void
whuff(void)
{
	(void) fwrite((char *) & huffcode, sizeof (huffcode), 1, stdout);
}

int
rhuff(FILE *f)
{
	return (read(fileno(f), (char *)&huffcode, sizeof (huffcode)) ==
	    sizeof (huffcode));
}
