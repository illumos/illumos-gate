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

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <ctype.h>.
 */

#ifndef _ISO_CTYPE_ISO_H
#define	_ISO_CTYPE_ISO_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
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

#define	_ISUPPER	_U
#define	_ISLOWER	_L
#define	_ISDIGIT	_N
#define	_ISSPACE	_S
#define	_ISPUNCT	_P
#define	_ISCNTRL	_C
#define	_ISBLANK	_B
#define	_ISXDIGIT	_X
#define	_ISGRAPH	0x00002000
#define	_ISALPHA	0x00004000
#define	_ISPRINT	0x00008000
#define	_ISALNUM	(_ISALPHA | _ISDIGIT)

extern unsigned char	__ctype[];
extern unsigned int	__ctype_mask[];
extern int		__trans_upper[];
extern int		__trans_lower[];

#if __cplusplus >= 199711L
namespace std {
#endif

/*
 * These used to be macros, which while more efficient, precludes operation
 * with thread specific locales.  The old macros will still work, but new
 * code compiles to use functions.  This is specifically permitted by the
 * various standards.  Only _tolower and _toupper were required to be
 * delivered in macro form.
 */
extern int isalnum(int);
extern int isalpha(int);
extern int iscntrl(int);
extern int isdigit(int);
extern int isgraph(int);
extern int islower(int);
extern int isprint(int);
extern int ispunct(int);
extern int isspace(int);
extern int isupper(int);
extern int isxdigit(int);
#if defined(_XPG6) || defined(_STDC_C99) || !defined(_STRICT_SYMBOLS)
extern int isblank(int);
#endif

extern int tolower(int);
extern int toupper(int);

#if __cplusplus >= 199711L
} /* end of namespace std */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_CTYPE_ISO_H */
