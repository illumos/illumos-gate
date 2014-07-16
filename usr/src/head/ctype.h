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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef _CTYPE_H
#define	_CTYPE_H

#include <iso/ctype_iso.h>

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/ctype_iso.h>.
 */
#if __cplusplus >= 199711L
using std::isalnum;
using std::isalpha;
using std::iscntrl;
using std::isdigit;
using std::isgraph;
using std::islower;
using std::isprint;
using std::ispunct;
using std::isspace;
using std::isupper;
using std::isxdigit;
using std::tolower;
using std::toupper;
#if _cplusplus >= 201103L
using std::isblank;
#endif
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__STDC__)

#if defined(__EXTENSIONS__) || \
	((!defined(_STRICT_STDC) && !defined(_POSIX_C_SOURCE)) || \
	defined(_XOPEN_SOURCE))

extern int isascii(int);
extern int toascii(int);
extern int _tolower(int);
extern int _toupper(int);

#endif /* defined(__EXTENSIONS__) || ((!defined(_STRICT_STDC) ... */

#if !defined(__lint)

#if defined(__EXTENSIONS__) || \
	((!defined(_STRICT_STDC) && !defined(_POSIX_C_SOURCE)) || \
	defined(_XOPEN_SOURCE)) || defined(__XPG4_CHAR_CLASS__)
#define	isascii(c)	(!(((int)(c)) & ~0177))
#define	toascii(c)	(((int)(c)) & 0177)
#define	_toupper(c)	(toupper(c))
#define	_tolower(c)	(tolower(c))

#endif /* defined(__EXTENSIONS__) || ((!defined(_STRICT_STDC) ... */

#endif	/* !defined(__lint) */

#if defined(_XPG7) || !defined(_STRICT_SYMBOLS)

#ifndef _LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif

extern int isalnum_l(int, locale_t);
extern int isalpha_l(int, locale_t);
extern int isblank_l(int, locale_t);
extern int iscntrl_l(int, locale_t);
extern int isdigit_l(int, locale_t);
extern int isgraph_l(int, locale_t);
extern int islower_l(int, locale_t);
extern int isprint_l(int, locale_t);
extern int ispunct_l(int, locale_t);
extern int isspace_l(int, locale_t);
extern int isupper_l(int, locale_t);
extern int isxdigit_l(int, locale_t);

#endif /* defined(_XPG7) || !defined(_STRICT_SYMBOLS) */

#else	/* defined(__STDC__) */

#if !defined(__lint)

#define	isascii(c)	(!(((int)(c)) & ~0177))
#define	_toupper(c)	(isascii(c) ? __trans_upper[(int)(c)] : toupper(c))
#define	_tolower(c)	(isascii(c) ? __trans_lower[(int)(c)] : tolower(c))
#define	toascii(c)	(((int)(c)) & 0177)

#endif	/* !defined(__lint) */

#endif	/* defined(__STDC__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _CTYPE_H */
