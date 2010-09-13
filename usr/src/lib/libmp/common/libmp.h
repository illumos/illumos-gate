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
 * Copyright (c) 1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * This is where all the interfaces that are internal to libmp
 * which do not have a better home live
 */

#ifndef _LIBMP_H
#define	_LIBMP_H

#ident	"%Z%%M%	%I%	%E% SMI"

#include <mp.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

extern short *_mp_xalloc(int, char *);
extern void _mp_xfree(MINT *);
extern void _mp_move(MINT *, MINT *);
extern void mp_invert(MINT *, MINT *, MINT *);
extern void _mp_fatal(char *);
extern void _mp_mcan(MINT *);
extern char *mtox(MINT *);
extern int mp_omin(MINT *);
extern void mp_omout(MINT *);
extern void mp_fmout(MINT *, FILE *);
extern int mp_fmin(MINT *, FILE *);

/*
 * old libmp interfaces
 */
extern void gcd(MINT *, MINT *, MINT *);
extern void madd(MINT *, MINT *, MINT *);
extern void msub(MINT *, MINT *, MINT *);
extern void mdiv(MINT *, MINT *, MINT *, MINT *);
extern void sdiv(MINT *, short, MINT *, short *);
extern int min(MINT *);
extern void mout(MINT *);
extern int msqrt(MINT *, MINT *, MINT *);
extern void mult(MINT *, MINT *, MINT *);
extern void pow(MINT *, MINT *, MINT *, MINT *);
extern void rpow(MINT *, short, MINT *);
extern MINT *itom(short);
extern int mcmp(MINT *, MINT *);
extern MINT *xtom(char *);
extern char *mtox(MINT *);
extern void mfree(MINT *);
extern short *xalloc(int, char *);
extern void xfree(MINT *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMP_H */
