/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
/* 	Portions Copyright(c) 1996, Sun Microsystems Inc.	*/
/*	All Rights Reserved					*/

/*
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* fix for bugid 1240660 redefine old libmp interfaces to go to the new */
/* mp_*() interfaces */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/* LINTLIBRARY */

#include <mp.h>
#include <sys/types.h>
#include "libmp.h"

void gcd(MINT *a, MINT *b, MINT *c) { mp_gcd(a, b, c); }

void madd(MINT *a, MINT *b, MINT *c) { mp_madd(a, b, c); }

void msub(MINT *a, MINT *b, MINT *c) { mp_msub(a, b, c); }

void mdiv(MINT *a, MINT *b, MINT *q, MINT *r) { mp_mdiv(a, b, q, r); }

void sdiv(MINT *a, short n, MINT *q, short *r) { mp_sdiv(a, n, q, r); }

int min(MINT *a) { return (mp_min(a)); }

void mout(MINT *a) { mp_mout(a); }

int msqrt(MINT *a, MINT *b, MINT *r) { return (mp_msqrt(a, b, r)); }

void mult(MINT *a, MINT *b, MINT *c) { mp_mult(a, b, c); }

void pow(MINT *a, MINT *b, MINT *c, MINT *d) { mp_pow(a, b, c, d); }

void rpow(MINT *a, short n, MINT *b) { mp_rpow(a, n, b); }

MINT *itom(short n) { return (mp_itom(n)); }

int mcmp(MINT *a, MINT *b) { return (mp_mcmp(a, b)); }

MINT *xtom(char *key) { return (mp_xtom(key)); }

char *mtox(MINT *key) { return (mp_mtox(key)); }

void mfree(MINT *a) { mp_mfree(a); }

/* VARARGS */
short *xalloc(int nint, char *s) { return (_mp_xalloc(nint, s)); }

void xfree(MINT *c) { _mp_xfree(c); }
