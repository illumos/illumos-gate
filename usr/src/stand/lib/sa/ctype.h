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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SA_CTYPE_H
#define	_SA_CTYPE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Exported interfaces for standalone's subset of libc's <ctype.h>.
 * All standalone code *must* use this header rather than libc's.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	_U	0x00000001	/* Upper case */
#define	_L	0x00000002	/* Lower case */
#define	_N	0x00000004	/* Numeral (digit) */
#define	_S	0x00000008	/* Spacing character */
#define	_P	0x00000010	/* Punctuation */
#define	_C	0x00000020	/* Control character */
#define	_B	0x00000040	/* Blank */
#define	_X	0x00000080	/* heXadecimal digit */

#define	isalpha(c)	((__ctype + 1)[c] & (_U | _L))
#define	isupper(c)	((__ctype + 1)[c] & _U)
#define	islower(c)	((__ctype + 1)[c] & _L)
#define	isdigit(c)	((__ctype + 1)[c] & _N)
#define	isxdigit(c)	((__ctype + 1)[c] & _X)
#define	isalnum(c)	((__ctype + 1)[c] & (_U | _L | _N))
#define	isspace(c)	((__ctype + 1)[c] & _S)
#define	ispunct(c)	((__ctype + 1)[c] & _P)
#define	isprint(c)	((__ctype + 1)[c] & (_P | _U | _L | _N | _B))
#define	isgraph(c)	((__ctype + 1)[c] & (_P | _U | _L | _N))
#define	iscntrl(c)	((__ctype + 1)[c] & _C)
#define	isascii(c)	(!((c) & ~0177))

extern unsigned char __ctype[];

/*
 * Some header files define their own macros for tolower/toupper which mangle
 * our prototypes -- thus only provide ours if no macros have been defined.
 */
#ifndef tolower
extern int tolower(int);
#endif
#ifndef toupper
extern int toupper(int);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SA_CTYPE_H */
