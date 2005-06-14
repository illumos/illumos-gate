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

int
mp_msqrt(MINT *a, MINT *b, MINT *r)
{
	MINT a0, x, junk, y;
	int j;

	a0.len = junk.len = y.len = 0;
	if (a->len < 0)
		_mp_fatal("mp_msqrt: neg arg");
	if (a->len == 0) {
		b->len = 0;
		r->len = 0;
		return (0);
	}
	if (a->len % 2 == 1)
		x.len = (1 + a->len) / 2;
	else
		x.len = 1 + a->len / 2;
	x.val = _mp_xalloc(x.len, "mp_msqrt");
	for (j = 0; j < x.len; x.val[j++] = 0)
		;
	if (a->len % 2 == 1)
		x.val[x.len - 1] = 0400;
	else
		x.val[x.len - 1] = 1;
	_mp_move(a, &a0);
	_mp_xfree(b);
	_mp_xfree(r);
loop:
	mp_mdiv(&a0, &x, &y, &junk);
	_mp_xfree(&junk);
	mp_madd(&x, &y, &y);
	mp_sdiv(&y, 2, &y, (short *) &j);
	if (mp_mcmp(&x, &y) > 0) {
		_mp_xfree(&x);
		_mp_move(&y, &x);
		_mp_xfree(&y);
		goto loop;
	}
	_mp_xfree(&y);
	_mp_move(&x, b);
	mp_mult(&x, &x, &x);
	mp_msub(&a0, &x, r);
	_mp_xfree(&x);
	_mp_xfree(&a0);
	return (r->len);
}
