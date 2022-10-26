/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
/*	Portions Copyright(c) 1988, Sun Microsystems Inc.	*/
/*	All Rights Reserved					*/

/*
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <mp.h>
#include <sys/types.h>
#include "libmp.h"
#include <stdlib.h>
#include <unistd.h>

void
_mp_move(MINT *a, MINT *b)
{
	int i, j;

	_mp_xfree(b);
	b->len = a->len;
	if ((i = a->len) < 0) {
		i = -i;
	}
	if (i == 0) {
		return;
	}
	b->val = _mp_xalloc(i, "_mp_move");
	for (j = 0; j < i; j++) {
		b->val[j] = a->val[j];
	}
}

short *
_mp_xalloc(int nint, char *s __unused)
{
	short *i;

	i = malloc(sizeof (short) * ((unsigned)nint + 2)); /* ??? 2 ??? */
#ifdef DEBUG
	(void) fprintf(stderr, "%s: %p\n", s, i);
#endif
	if (i == NULL) {
		_mp_fatal("mp: no free space");
	}
	return (i);
}

void
_mp_fatal(char *s)
{
	(void) fprintf(stderr, "%s\n", s);
	(void) fflush(stdout);
	(void) sleep(2);
	abort();
}

void
_mp_xfree(MINT *c)
{
#ifdef DBG
	(void) fprintf(stderr, "xfree ");
#endif
	if (c->len != 0) {
		free(c->val);
		c->len = 0;
	}
}

void
_mp_mcan(MINT *a)
{
	int i, j;

	if ((i = a->len) == 0) {
		return;
	}
	if (i < 0) {
		i = -i;
	}
	for (j = i; j > 0 && a->val[j-1] == 0; j--)
		;
	if (j == i) {
		return;
	}
	if (j == 0) {
		_mp_xfree(a);
		return;
	}
	if (a->len > 0) {
		a->len = j;
	} else {
		a->len = -j;
	}
}


MINT *
mp_itom(short n)
{
	MINT *a;

	a = malloc(sizeof (MINT));
	if (n > 0) {
		a->len = 1;
		a->val = _mp_xalloc(1, "mp_itom1");
		*a->val = n;
	} else if (n < 0) {
		a->len = -1;
		a->val = _mp_xalloc(1, "mp_itom2");
		*a->val = -n;
	} else {
		a->len = 0;
	}
	return (a);
}

int
mp_mcmp(MINT *a, MINT *b)
{
	MINT c;
	int res;

	_mp_mcan(a);
	_mp_mcan(b);
	if (a->len != b->len) {
		return (a->len - b->len);
	}
	c.len = 0;
	mp_msub(a, b, &c);
	res = c.len;
	_mp_xfree(&c);
	return (res);
}

/*
 * Convert hex digit to binary value
 */
static short
xtoi(char c)
{
	if (c >= '0' && c <= '9') {
		return (c - '0');
	} else if (c >= 'a' && c <= 'f') {
		return (c - 'a' + 10);
	} else if (c >= 'A' && c <= 'F') {
		return (c - 'A' + 10);
	} else {
		return (-1);
	}
}


/*
 * Convert hex key to MINT key
 */
MINT *
mp_xtom(char *key)
{
	short digit;
	MINT *m = mp_itom(0);
	MINT *d;
	MINT *sixteen;

	sixteen = mp_itom(16);
	for (; *key; key++) {
		digit = xtoi(*key);
		if (digit < 0) {
			return (NULL);
		}
		d = mp_itom(digit);
		mp_mult(m, sixteen, m);
		mp_madd(m, d, m);
		mp_mfree(d);
	}
	mp_mfree(sixteen);
	return (m);
}

static char
itox(short d)
{
	d &= 15;
	if (d < 10) {
		return ('0' + d);
	} else {
		return ('a' - 10 + d);
	}
}

/*
 * Convert MINT key to hex key
 */
char *
mp_mtox(MINT *key)
{
	MINT *m = mp_itom(0);
	MINT *zero = mp_itom(0);
	short r;
	char *p;
	char c;
	char *s;
	char *hex;
	int size;

#define	BASEBITS	(8 * (unsigned int)sizeof (short) - 1)

	if (key->len >= 0) {
		size = key->len;
	} else {
		size = -key->len;
	}
	hex = malloc((size_t)((size * BASEBITS + 3)) / 4 + (size ? 1 : 2));
	if (hex == NULL) {
		return (NULL);
	}
	_mp_move(key, m);
	p = hex;
	do {
		mp_sdiv(m, 16, m, &r);
		*p++ = itox(r);
	} while (mp_mcmp(m, zero) != 0);
	mp_mfree(m);
	mp_mfree(zero);

	*p = 0;
	for (p--, s = hex; s < p; s++, p--) {
		c = *p;
		*p = *s;
		*s = c;
	}
	return (hex);
}

/*
 * Deallocate a multiple precision integer
 */
void
mp_mfree(MINT *a)
{
	_mp_xfree(a);
	free(a);
}
