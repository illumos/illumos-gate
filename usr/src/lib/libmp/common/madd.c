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
#include "libmp.h"
#include <sys/types.h>
#include <stdlib.h>

static void
m_add(MINT *a, MINT *b, MINT *c)
{
	int carry, i;
	int x;
	short *cval;

	cval = _mp_xalloc(a->len + 1, "m_add");
	carry = 0;
	for (i = 0; i < b->len; i++) {
		x = carry + a->val[i] + b->val[i];
		if (x & 0100000) {
			carry = 1;
			cval[i] = (short)(x & 077777);
		} else {
			carry = 0;
			cval[i] = (short)x;
		}
	}
	for (; i < a->len; i++) {
		x = carry + a->val[i];
		if (x & 0100000) {
			cval[i] = (short)(x & 077777);
		} else {
			carry = 0;
			cval[i] = (short)x;
		}
	}
	if (carry == 1) {
		cval[i] = 1;
		c->len = i + 1;
	} else {
		c->len = a->len;
	}
	c->val = cval;
	if (c->len == 0) {
		free(cval);
	}
}

void
mp_madd(MINT *a, MINT *b, MINT *c)
{
	MINT x, y;
	int sign;

	x.len = y.len = 0;
	_mp_move(a, &x);
	_mp_move(b, &y);
	_mp_xfree(c);
	sign = 1;
	if (x.len >= 0) {
		if (y.len >= 0) {
			if (x.len >= y.len) {
				m_add(&x, &y, c);
			} else {
				m_add(&y, &x, c);
			}
		} else {
			y.len = -y.len;
			mp_msub(&x, &y, c);
		}
	} else {
		if (y.len <= 0) {
			x.len = -x.len;
			y.len = -y.len;
			sign = -1;
			mp_madd(&x, &y, c);
		} else {
			x.len = -x.len;
			mp_msub(&y, &x, c);
		}
	}
	c->len = sign * c->len;
	_mp_xfree(&x);
	_mp_xfree(&y);
}

static void
m_sub(MINT *a, MINT *b, MINT *c)
{
	int x, i;
	int borrow;
	short one;
	MINT mone;

	one = 1;
	mone.len = 1;
	mone.val = &one;
	c->val = _mp_xalloc(a->len, "m_sub");
	borrow = 0;
	for (i = 0; i < b->len; i++) {
		x = borrow + a->val[i] - b->val[i];
		if (x & 0100000) {
			borrow = -1;
			c->val[i] = (short)(x & 077777);
		} else {
			borrow = 0;
			c->val[i] = (short)x;
		}
	}
	for (; i < a->len; i++) {
		x = borrow + a->val[i];
		if (x & 0100000) {
			c->val[i] = (short)(x & 077777);
		} else {
			borrow = 0;
			c->val[i] = (short)x;
		}
	}
	if (borrow < 0) {
		for (i = 0; i < a->len; i++) {
			c->val[i] ^= 077777;
		}
		c->len = a->len;
		mp_madd(c, &mone, c);
	}
	for (i = a->len-1; i >= 0; --i) {
		if (c->val[i] > 0) {
			if (borrow == 0) {
				c->len = i + 1;
			} else {
				c->len = -i - 1;
			}
			return;
		}
	}
	free(c->val);
}

void
mp_msub(MINT *a, MINT *b, MINT *c)
{
	MINT x, y;
	int sign;

	x.len = y.len = 0;
	_mp_move(a, &x);
	_mp_move(b, &y);
	_mp_xfree(c);
	sign = 1;
	if (x.len >= 0) {
		if (y.len >= 0) {
			if (x.len >= y.len) {
				m_sub(&x, &y, c);
			} else {
				sign = -1;
				mp_msub(&y, &x, c);
			}
		} else {
			y.len = -y.len;
			mp_madd(&x, &y, c);
		}
	} else {
		if (y.len <= 0) {
			x.len = -x.len;
			y.len = -y.len;
			mp_msub(&y, &x, c);
		} else {
			x.len = -x.len;
			mp_madd(&x, &y, c);
			sign = -1;
		}
	}
	c->len = sign * c->len;
	_mp_xfree(&x);
	_mp_xfree(&y);
}
