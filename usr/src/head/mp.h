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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _MP_H
#define	_MP_H

#ifdef	__cplusplus
extern "C" {
#endif

struct mint {
	int len;
	short *val;
};
typedef struct mint MINT;


extern void mp_gcd(MINT *, MINT *, MINT *);
extern void mp_madd(MINT *, MINT *, MINT *);
extern void mp_msub(MINT *, MINT *, MINT *);
extern void mp_mdiv(MINT *, MINT *, MINT *, MINT *);
extern void mp_sdiv(MINT *, short, MINT *, short *);
extern int mp_min(MINT *);
extern void mp_mout(MINT *);
extern int mp_msqrt(MINT *, MINT *, MINT *);
extern void mp_mult(MINT *, MINT *, MINT *);
extern void mp_pow(MINT *, MINT *, MINT *, MINT *);
extern void mp_rpow(MINT *, short, MINT *);
extern MINT *mp_itom(short);
extern int mp_mcmp(MINT *, MINT *);
extern MINT *mp_xtom(char *);
extern char *mp_mtox(MINT *);
extern void mp_mfree(MINT *);

#define	FREE(x)	_mp_xfree(&(x))		/* Compatibility */

#ifdef	__cplusplus
}
#endif

#endif /* _MP_H */
