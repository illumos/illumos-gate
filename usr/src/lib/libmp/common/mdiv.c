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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/* LINTLIBRARY */

#include <mp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "libmp.h"

static void m_div(MINT *, MINT *, MINT *, MINT *);

void
mp_mdiv(MINT *a, MINT *b, MINT *q, MINT *r)
{
	MINT x, y;
	int sign;

	sign = 1;
	x.len = y.len = 0;
	_mp_move(a, &x);
	_mp_move(b, &y);
	if (x.len < 0) {
		sign = -1;
		x.len = -x.len;
	}
	if (y.len < 0) {
		sign = -sign;
		y.len = -y.len;
	}
	_mp_xfree(q);
	_mp_xfree(r);
	m_div(&x, &y, q, r);
	if (sign == -1) {
		q->len = -q->len;
		r->len = -r->len;
	}
	_mp_xfree(&x);
	_mp_xfree(&y);
}

static int
m_dsb(int qx, int n, short *a, short *b)
{
	int borrow;
	int s3b2shit;
	int j;
	short fifteen = 15;
	short *aptr, *bptr;
#ifdef DEBUGDSB
	(void) printf("m_dsb %d %d %d %d\n", qx, n, *a, *b);
#endif

	borrow = 0;
	aptr = a;
	bptr = b;
	for (j = n; j > 0; j--) {
#ifdef DEBUGDSB
		(void) printf("1 borrow=%x %d %d %d\n", borrow, (*aptr * qx),
		    *bptr, *aptr);
#endif
		borrow -= (*aptr++) * qx - *bptr;
#ifdef DEBUGDSB
		(void) printf("2 borrow=%x %d %d %d\n", borrow, (*aptr * qx),
		    *bptr, *aptr);
#endif
		*bptr++ = (short)(borrow & 077777);
#ifdef DEBUGDSB
		(void) printf("3 borrow=%x %d %d %d\n", borrow, (*aptr * qx),
		    *bptr, *aptr);
#endif
		if (borrow >= 0) borrow >>= fifteen; /* 3b2 */
		else borrow = 0xfffe0000 | (borrow >> fifteen);
#ifdef DEBUGDSB
		(void) printf("4 borrow=%x %d %d %d\n", borrow, (*aptr * qx),
		    *bptr, *aptr);
#endif
	}
	borrow += *bptr;
	*bptr = (short)(borrow & 077777);
	if (borrow >= 0) s3b2shit = borrow >> fifteen; /* 3b2 */
	else s3b2shit = 0xfffe0000 | (borrow >> fifteen);
	if (s3b2shit == 0) {
#ifdef DEBUGDSB
	(void) printf("mdsb 0\n");
#endif
		return (0);
	}
	borrow = 0;
	aptr = a;
	bptr = b;
	for (j = n; j > 0; j--) {
		borrow += *aptr++ + *bptr;
		*bptr++ = (short)(borrow & 077777);
		if (borrow >= 0) borrow >>= fifteen; /* 3b2 */
		else borrow = 0xfffe0000 | (borrow >>fifteen);
	}
#ifdef DEBUGDSB
	(void) printf("mdsb 1\n");
#endif
	return (1);
}

static int
m_trq(short v1, short v2, short u1, short u2, short u3)
{
	short d;
	int x1;
	int c1;

	c1 = u1 * 0100000 + u2;
	if (u1 == v1) {
		d = 077777;
	} else {
		d = (short)(c1 / v1);
	}
	do {
		x1 = c1 - v1 * d;
		x1 = x1 * 0100000 + u3 - v2 * d;
		--d;
	} while (x1 < 0);
#ifdef DEBUGMTRQ
	(void) printf("mtrq %d %d %d %d %d %d\n", v1, v2, u1, u2, u3, (d+1));
#endif
	return ((int)d + 1);
}

static void
m_div(MINT *a, MINT *b, MINT *q, MINT *r)
{
	MINT u, v, x, w;
	short d;
	short *qval;
	short *uval;
	int j;
	int qq;
	int n;
	short v1;
	short v2;

	u.len = v.len = x.len = w.len = 0;
	if (b->len == 0) {
		_mp_fatal("mdiv divide by zero");
		return;
	}
	if (b->len == 1) {
		r->val = _mp_xalloc(1, "m_div1");
		mp_sdiv(a, b->val[0], q, r->val);
		if (r->val[0] == 0) {
			free(r->val);
			r->len = 0;
		} else {
			r->len = 1;
		}
		return;
	}
	if (a -> len < b -> len) {
		q->len = 0;
		r->len = a->len;
		r->val = _mp_xalloc(r->len, "m_div2");
		for (qq = 0; qq < r->len; qq++) {
			r->val[qq] = a->val[qq];
		}
		return;
	}
	x.len = 1;
	x.val = &d;
	n = b->len;
	d = 0100000 / (b->val[n - 1] + 1);
	mp_mult(a, &x, &u); /* subtle: relies on mult allocing extra space */
	mp_mult(b, &x, &v);
#ifdef DEBUG_MDIV
	(void) printf("  u=%s\n", mtox(&u));
	(void) printf("  v=%s\n", mtox(&v));
#endif
	v1 = v.val[n - 1];
	v2 = v.val[n - 2];
	qval = _mp_xalloc(a -> len - n + 1, "m_div3");
	uval = u.val;
	for (j = a->len - n; j >= 0; j--) {
		qq = m_trq(v1, v2, uval[j + n], uval[j + n - 1],
							uval[j + n - 2]);
		if (m_dsb(qq, n, v.val, uval + j))
			qq -= 1;
		qval[j] = (short)qq;
	}
	x.len = n;
	x.val = u.val;
	_mp_mcan(&x);
#ifdef DEBUG_MDIV
	(void) printf("  x=%s\n", mtox(&x));
	(void) printf("  d(in)=%d\n", (d));
#endif
	mp_sdiv(&x, d, &w, &d);
#ifdef DEBUG_MDIV
	(void) printf("  w=%s\n", mtox(&w));
	(void) printf("  d(out)=%d\n", (d));
#endif
	r->len = w.len;
	r->val = w.val;
	q->val = qval;
	qq = a->len - n + 1;
	if (qq > 0 && qval[qq - 1] == 0)
		qq -= 1;
	q->len = qq;
	if (qq == 0)
		free(qval);
	if (x.len != 0)
		_mp_xfree(&u);
	_mp_xfree(&v);
}
