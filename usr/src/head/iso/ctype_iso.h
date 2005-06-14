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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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


#if defined(__STDC__)

#if __cplusplus < 199711L  /* Use inline functions instead for ANSI C++ */

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

#endif /* __cplusplus < 199711L */

#if __cplusplus >= 199711L
namespace std {
#endif

extern int tolower(int);
extern int toupper(int);

#if __cplusplus >= 199711L
} /* end of namespace std */
#endif

extern unsigned char	__ctype[];
extern unsigned int	*__ctype_mask;
extern int		*__trans_upper;
extern int		*__trans_lower;

#if !defined(__lint)

#if __cplusplus >= 199711L
namespace std {

#if defined(__XPG4_CHAR_CLASS__) || defined(_XPG4)

inline int isalpha(int c) { return (__ctype_mask[c] & _ISALPHA); }
inline int isupper(int c) { return (__ctype_mask[c] & _ISUPPER); }
inline int islower(int c) { return (__ctype_mask[c] & _ISLOWER); }
inline int isdigit(int c) { return (__ctype_mask[c] & _ISDIGIT); }
inline int isxdigit(int c) { return (__ctype_mask[c] & _ISXDIGIT); }
inline int isalnum(int c) { return (__ctype_mask[c] & _ISALNUM); }
inline int isspace(int c) { return (__ctype_mask[c] & _ISSPACE); }
inline int ispunct(int c) { return (__ctype_mask[c] & _ISPUNCT); }
inline int isprint(int c) { return (__ctype_mask[c] & _ISPRINT); }
inline int isgraph(int c) { return (__ctype_mask[c] & _ISGRAPH); }
inline int iscntrl(int c) { return (__ctype_mask[c] & _ISCNTRL); }
#else
inline int isalpha(int c) { return ((__ctype + 1)[c] & (_U | _L)); }
inline int isupper(int c) { return ((__ctype + 1)[c] & _U); }
inline int islower(int c) { return ((__ctype + 1)[c] & _L); }
inline int isdigit(int c) { return ((__ctype + 1)[c] & _N); }
inline int isxdigit(int c) { return ((__ctype + 1)[c] & _X); }
inline int isalnum(int c) { return ((__ctype + 1)[c] & (_U | _L | _N)); }
inline int isspace(int c) { return ((__ctype + 1)[c] & _S); }
inline int ispunct(int c) { return ((__ctype + 1)[c] & _P); }
inline int isprint(int c) {
	return ((__ctype + 1)[c] & (_P | _U | _L | _N | _B)); }
inline int isgraph(int c) { return ((__ctype + 1)[c] & (_P | _U | _L | _N)); }
inline int iscntrl(int c) { return ((__ctype + 1)[c] & _C); }
#endif  /* defined(__XPG4_CHAR_CLASS__) || defined(_XPG4) */

} /* end of namespace std */

#else /* __cplusplus >= 199711L */

#if defined(__XPG4_CHAR_CLASS__) || defined(_XPG4)
#define	isalpha(c)	(__ctype_mask[(int)(c)] & _ISALPHA)
#define	isupper(c)	(__ctype_mask[(int)(c)] & _ISUPPER)
#define	islower(c)	(__ctype_mask[(int)(c)] & _ISLOWER)
#define	isdigit(c)	(__ctype_mask[(int)(c)] & _ISDIGIT)
#define	isxdigit(c)	(__ctype_mask[(int)(c)] & _ISXDIGIT)
#define	isalnum(c)	(__ctype_mask[(int)(c)] & _ISALNUM)
#define	isspace(c)	(__ctype_mask[(int)(c)] & _ISSPACE)
#define	ispunct(c)	(__ctype_mask[(int)(c)] & _ISPUNCT)
#define	isprint(c)	(__ctype_mask[(int)(c)] & _ISPRINT)
#define	isgraph(c)	(__ctype_mask[(int)(c)] & _ISGRAPH)
#define	iscntrl(c)	(__ctype_mask[(int)(c)] & _ISCNTRL)
#else
#define	isalpha(c)	((__ctype + 1)[(int)(c)] & (_U | _L))
#define	isupper(c)	((__ctype + 1)[(int)(c)] & _U)
#define	islower(c)	((__ctype + 1)[(int)(c)] & _L)
#define	isdigit(c)	((__ctype + 1)[(int)(c)] & _N)
#define	isxdigit(c)	((__ctype + 1)[(int)(c)] & _X)
#define	isalnum(c)	((__ctype + 1)[(int)(c)] & (_U | _L | _N))
#define	isspace(c)	((__ctype + 1)[(int)(c)] & _S)
#define	ispunct(c)	((__ctype + 1)[(int)(c)] & _P)
#define	isprint(c)	((__ctype + 1)[(int)(c)] & (_P | _U | _L | _N | _B))
#define	isgraph(c)	((__ctype + 1)[(int)(c)] & (_P | _U | _L | _N))
#define	iscntrl(c)	((__ctype + 1)[(int)(c)] & _C)

#endif  /* defined(__XPG4_CHAR_CLASS__) || defined(_XPG4) */

#endif	/* __cplusplus >= 199711L */

#endif	/* !defined(__lint) */

#else	/* defined(__STDC__) */

extern unsigned char	_ctype[];

#if !defined(__lint)

#define	isalpha(c)	((_ctype + 1)[(int)(c)] & (_U | _L))
#define	isupper(c)	((_ctype + 1)[(int)(c)] & _U)
#define	islower(c)	((_ctype + 1)[(int)(c)] & _L)
#define	isdigit(c)	((_ctype + 1)[(int)(c)] & _N)
#define	isxdigit(c)	((_ctype + 1)[(int)(c)] & _X)
#define	isalnum(c)	((_ctype + 1)[(int)(c)] & (_U | _L | _N))
#define	isspace(c)	((_ctype + 1)[(int)(c)] & _S)
#define	ispunct(c)	((_ctype + 1)[(int)(c)] & _P)
#define	isprint(c)	((_ctype + 1)[(int)(c)] & (_P | _U | _L | _N | _B))
#define	isgraph(c)	((_ctype + 1)[(int)(c)] & (_P | _U | _L | _N))
#define	iscntrl(c)	((_ctype + 1)[(int)(c)] & _C)

#endif	/* !defined(__lint) */

#endif	/* defined(__STDC__) */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_CTYPE_ISO_H */
