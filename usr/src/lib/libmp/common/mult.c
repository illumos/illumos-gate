/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
/* 	Portions Copyright(c) 1988, Sun Microsystems Inc.	*/
/*	All Rights Reserved					*/

/*
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/* LINTLIBRARY */

#include <mp.h>
#include <sys/types.h>
#include "libmp.h"

static void m_mult(MINT *, MINT *, MINT *);

void
mp_mult(MINT *a, MINT *b, MINT *c)
{
	struct mint x, y;
	int sign;

	_mp_mcan(a);
	_mp_mcan(b);
	if (a->len == 0 || b->len == 0) {
		_mp_xfree(c);
		return;
	}
	sign = 1;
	x.len = y.len = 0;
	_mp_move(a, &x);
	_mp_move(b, &y);
	if (a->len < 0) {
		x.len = -x.len;
		sign = -sign;
	}
	if (b->len < 0) {
		y.len = -y.len;
		sign = -sign;
	}
	_mp_xfree(c);
	if (x.len < y.len) {
		m_mult(&x, &y, c);
	} else {
		m_mult(&y, &x, c);
	}
	if (sign < 0)
		c->len = -c->len;
	if (c->len == 0)
		_mp_xfree(c);
	_mp_xfree(&x);
	_mp_xfree(&y);
}

/*
 * Knuth  4.3.1, Algorithm M
 */
static void
m_mult(MINT *a, MINT *b, MINT *c)
{
	int i, j;
	int sum;
	short bcache;
	short *aptr;
	short *bptr;
	short *cptr;
	short fifteen = 15;
	int alen;
	int blen;

#define	BASEBITS	(8 * (unsigned int)sizeof (short) - 1)
#define	BASE		(1 << BASEBITS)
#define	LOWBITS 	(BASE - 1)

	alen = a->len;
	blen = b->len;

	c->len = alen + blen;
	c->val = _mp_xalloc(c->len, "m_mult");

	aptr = a->val;
	bptr = b->val;
	cptr = c->val;

	sum = 0;
	bcache = *bptr++;
	for (i = alen; i > 0; i--) {
		sum += *aptr++ * bcache;
		*cptr++ = (short)(sum & LOWBITS);
		if (sum >= 0)
			sum >>= fifteen;
		else
			sum = 0xfffe0000 | (sum >> fifteen);
	}
	*cptr = (short)sum;
	aptr -= alen;
	cptr -= alen;
	cptr++;

	for (j = blen - 1; j > 0; j--) {
		sum = 0;
		bcache = *bptr++;
		for (i = alen; i > 0; i--) {
			sum += *aptr++ * bcache + *cptr;
			*cptr++ = (short)(sum & LOWBITS);
			if (sum >= 0)
				sum >>= fifteen;
			else
				sum = 0xfffe0000 | (sum >> fifteen);
		}
		*cptr = (short)sum;
		aptr -= alen;
		cptr -= alen;
		cptr++;
	}
	if (c->val[c->len-1] == 0) {
		c->len--;
	}
}
