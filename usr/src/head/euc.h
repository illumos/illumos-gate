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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _EUC_H
#define	_EUC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/euc.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	__STDC__
extern int csetcol(int n);	/* Returns # of columns for codeset n. */
extern int csetlen(int n);	/* Returns # of bytes excluding SSx. */
extern int euclen(const unsigned char *s);
extern int euccol(const unsigned char *s);
extern int eucscol(const unsigned char *str);
#else	/* __STDC__ */
extern int csetlen(), csetcol();
extern int euclen(), euccol(), eucscol();
#endif	/* __STDC__ */

/* Returns code set number for the first byte of an EUC char. */
#define	csetno(c) \
	(((c)&0x80)?(((c)&0xff) == SS2)?2:((((c)&0xff) == SS3)?3:1):0)

/*
 * Copied from _wchar.h of SVR4
 */
#if defined(__STDC__)
#define	multibyte	(__ctype[520] > 1)
#define	eucw1		__ctype[514]
#define	eucw2		__ctype[515]
#define	eucw3		__ctype[516]
#define	scrw1		__ctype[517]
#define	scrw2		__ctype[518]
#define	scrw3		__ctype[519]
#else
#define	multibyte	(_ctype[520] > 1)
#define	eucw1		_ctype[514]
#define	eucw2		_ctype[515]
#define	eucw3		_ctype[516]
#define	scrw1		_ctype[517]
#define	scrw2		_ctype[518]
#define	scrw3		_ctype[519]
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _EUC_H */
