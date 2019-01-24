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

#include <stdio.h>
#include <mp.h>
#include <sys/types.h>
#include "libmp.h"
#include <stdlib.h>

static int
m_in(MINT *a, short b, FILE *f)
{
	MINT x, y, ten;
	int sign, c;
	short qten, qy;

	_mp_xfree(a);
	sign = 1;
	ten.len = 1;
	ten.val = &qten;
	qten = b;
	x.len = 0;
	y.len = 1;
	y.val = &qy;
	while ((c = getc(f)) != EOF) {
		switch (c) {

		case '\\':
			(void) getc(f);
			continue;
		case '\t':
		case '\n':
			a->len *= sign;
			_mp_xfree(&x);
			return (0);
		case ' ':
			continue;
		case '-':
			sign = -sign;
			continue;
		default:
			if (c >= '0' && c <= '9') {
				qy = c - '0';
				mp_mult(&x, &ten, a);
				mp_madd(a, &y, a);
				_mp_move(a, &x);
				continue;
			} else {
				(void) ungetc(c, stdin);
				a->len *= sign;
				return (0);
			}
		}
	}

	return (EOF);
}

static void
m_out(MINT *a, short b, FILE *f)
{
	int sign, xlen, i;
	short r;
	MINT x;

	char *obuf;
	char *bp;

	if (a == NULL)
		return;
	sign = 1;
	xlen = a->len;
	if (xlen < 0) {
		xlen = -xlen;
		sign = -1;
	}
	if (xlen == 0) {
		(void) fprintf(f, "0\n");
		return;
	}
	x.len = xlen;
	x.val = _mp_xalloc(xlen, "m_out");
	for (i = 0; i < xlen; i++)
		x.val[i] = a->val[i];
	obuf = malloc(7 * (size_t)xlen);
	bp = obuf + 7 * xlen - 1;
	*bp-- = 0;
	while (x.len > 0) {
		for (i = 0; i < 10 && x.len > 0; i++) {
			mp_sdiv(&x, b, &x, &r);
			*bp-- = (char)(r + '0');
		}
		if (x.len > 0)
			*bp-- = ' ';
	}
	if (sign == -1)
		*bp-- = '-';
	(void) fprintf(f, "%s\n", bp + 1);
	free(obuf);
	_mp_xfree(&x);
}

static void s_div(MINT *, short, MINT *, short *);

void
mp_sdiv(MINT *a, short n, MINT *q, short *r)
{
	MINT x, y;
	short sign;

	sign = 1;
	x.len = a->len;
	x.val = a->val;
	if (n < 0) {
		sign = -sign;
		n = -n;
	}
	if (x.len < 0) {
		sign = -sign;
		x.len = -x.len;
	}
	s_div(&x, n, &y, r);
	_mp_xfree(q);
	q->val = y.val;
	q->len = sign * y.len;
	*r = *r * sign;
}

static void
s_div(MINT *a, short n, MINT *q, short *r)
{
	int qlen;
	int i;
	int x;
	short *qval;
	short *aval;

	x = 0;
	qlen = a->len;
	q->val = _mp_xalloc(qlen, "s_div");
	aval = a->val + qlen;
	qval = q->val + qlen;
	for (i = qlen - 1; i >= 0; i--) {
		x = x * 0100000 + *--aval;
		*--qval = (short)(x / n);
		x = x % n;
	}
	*r = (short)x;
	if (qlen && q->val[qlen-1] == 0)
		qlen--;
	q->len = qlen;
	if (qlen == 0)
		free(q->val);
}

int
mp_min(MINT *a)
{
	return (m_in(a, 10, stdin));
}

int
mp_omin(MINT *a)
{
	return (m_in(a, 8, stdin));
}

void
mp_mout(MINT *a)
{
	m_out(a, 10, stdout);
}

void
mp_omout(MINT *a)
{
	m_out(a, 8, stdout);
}

void
mp_fmout(MINT *a, FILE *f)
{
	m_out(a, 10, f);
}

int
mp_fmin(MINT *a, FILE *f)
{
	return (m_in(a, 10, f));
}
