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
/*	wctype.h	1.13 89/11/02 SMI; JLE	*/
/*	from AT&T JAE 2.1			*/
/*	definitions for international functions	*/

/*
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_WCTYPE_H
#define	_WCTYPE_H

#include <sys/feature_tests.h>
#include <iso/wctype_iso.h>
#ifndef _STRICT_SYMBOLS
#include <ctype.h>
#include <wchar.h>
#endif

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/wctype_iso.h>.
 */
#if __cplusplus >= 199711L
using std::wint_t;
using std::wctrans_t;
using std::iswalnum;
using std::iswalpha;
using std::iswcntrl;
using std::iswdigit;
using std::iswgraph;
using std::iswlower;
using std::iswprint;
using std::iswpunct;
using std::iswspace;
using std::iswupper;
using std::iswxdigit;
using std::towlower;
using std::towupper;
using std::wctrans;
using std::towctrans;
using std::iswctype;
using std::wctype;
#if (__cplusplus >= 201103L) || defined(_STDC_C99) || defined(_XPG6) || \
	!defined(_STRICT_SYMBOLS)
using std::iswblank;
#endif
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/* do not allow any of the following in a strictly conforming application */
#ifndef _STRICT_SYMBOLS

/*
 * data structure for supplementary code set
 * for character class and conversion
 */
struct	_wctype {
	wchar_t	tmin;		/* minimum code for wctype */
	wchar_t	tmax;		/* maximum code for wctype */
	unsigned char  *index;	/* class index */
	unsigned int   *type;	/* class type */
	wchar_t	cmin;		/* minimum code for conversion */
	wchar_t	cmax;		/* maximum code for conversion */
	wchar_t *code;		/* conversion code */
};


#ifdef	_ILLUMOS_PRIVATE
extern	int __iswrune(wint_t);
extern	wint_t __nextwctype(wint_t, wctype_t);
#define	iswrune(c)		__iswrune(c)
#define	nextwctype(c, t)	__nextwctype(c, t)
#endif

/* character classification functions */

/* iswascii is still a macro */
#define	iswascii(c)	isascii(c)

/* isw*, except iswascii(), are not macros any more.  They become functions */

/* is* also become functions */
extern	int isphonogram(wint_t);
extern	int isideogram(wint_t);
extern	int isenglish(wint_t);
extern	int isnumber(wint_t);
extern	int isspecial(wint_t);
/* From BSD/MacOS */
extern	int iswideogram(wint_t);
extern	int iswphonogram(wint_t);
extern	int iswnumber(wint_t);
extern	int iswhexnumber(wint_t);
extern	int iswspecial(wint_t);

#define	iscodeset0(c)	isascii(c)
#define	iscodeset1(c)	(((c) & WCHAR_CSMASK) == WCHAR_CS1)
#define	iscodeset2(c)	(((c) & WCHAR_CSMASK) == WCHAR_CS2)
#define	iscodeset3(c)	(((c) & WCHAR_CSMASK) == WCHAR_CS3)

#endif /* !defined(_STRICT_SYMBOLS)... */


/* XPG7 extended locale support */
#if defined(_XPG7) || !defined(_STRICT_SYMBOLS)

#ifndef	_LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif

extern wint_t towlower_l(wint_t, locale_t);
extern wint_t towupper_l(wint_t, locale_t);
extern wint_t towctrans_l(wint_t, wctrans_t, locale_t);
extern int iswctype_l(wint_t, wctype_t, locale_t);
extern int iswalnum_l(wint_t, locale_t);
extern int iswalpha_l(wint_t, locale_t);
extern int iswblank_l(wint_t, locale_t);
extern int iswcntrl_l(wint_t, locale_t);
extern int iswdigit_l(wint_t, locale_t);
extern int iswgraph_l(wint_t, locale_t);
extern int iswlower_l(wint_t, locale_t);
extern int iswprint_l(wint_t, locale_t);
extern int iswpunct_l(wint_t, locale_t);
extern int iswspace_l(wint_t, locale_t);
extern int iswupper_l(wint_t, locale_t);
extern int iswxdigit_l(wint_t, locale_t);
extern wctrans_t wctrans_l(const char *, locale_t);
extern wctype_t wctype_l(const char *, locale_t);
#endif /* defined(_XPG7) || !defined(_STRICT_SYMBOLS) */

#ifdef	__cplusplus
}
#endif

#endif	/* _WCTYPE_H */
