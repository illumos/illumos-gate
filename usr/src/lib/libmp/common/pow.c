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

#include <stdio.h>
#include <sys/types.h>

/* LINTLIBRARY */

#include <mp.h>
#include "libmp.h"

void
mp_pow(MINT *a, MINT *b, MINT *c, MINT *d)
{
	int i, j, n;
	MINT x, y;
	MINT a0, b0, c0;

	a0.len = b0.len = c0.len = x.len = y.len = 0;
	_mp_move(a, &a0);
	_mp_move(b, &b0);
	_mp_move(c, &c0);
	_mp_xfree(d);
	d->len = 1;
	d->val = _mp_xalloc(1, "mp_pow");
	*d->val = 1;
	for (j = 0; j < b0.len; j++) {
		n = b0.val[b0.len - j - 1];
		for (i = 0; i < 15; i++) {
			mp_mult(d, d, &x);
			mp_mdiv(&x, &c0, &y, d);
			if ((n = n << 1) & 0100000) {
				mp_mult(&a0, d, &x);
				mp_mdiv(&x, &c0, &y, d);
			}
		}
	}
	_mp_xfree(&x);
	_mp_xfree(&y);
	_mp_xfree(&a0);
	_mp_xfree(&b0);
	_mp_xfree(&c0);
}

void
mp_rpow(MINT *a, short n, MINT *b)
{
	MINT x, y;
	int	i;

	x.len = 1;
	x.val = _mp_xalloc(1, "mp_rpow");
	*x.val = n;
	y.len = n * a->len + 4;
	y.val = _mp_xalloc(y.len, "mp_rpow2");
	for (i = 0; i < y.len; i++)
		y.val[i] = 0;
	y.val[y.len - 1] = 010000;
	mp_pow(a, &x, &y, b);
	_mp_xfree(&x);
	_mp_xfree(&y);
}
