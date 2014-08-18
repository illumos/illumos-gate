/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_WCHAR_H
#define	_WCHAR_H

#include <sys/feature_tests.h>
#include <iso/wchar_iso.h>
#include <iso/wchar_c99.h>

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/wchar_iso.h>.
 */
#if __cplusplus >= 199711L
using std::FILE;
using std::wint_t;
using std::clock_t;
using std::size_t;
using std::time_t;
using std::tm;
using std::mbstate_t;
using std::fgetwc;
using std::fgetws;
using std::fputwc;
using std::fputws;
using std::ungetwc;
using std::getwc;
using std::getwchar;
using std::putwc;
using std::putwchar;
using std::wcstod;
using std::wcstol;
using std::wcstoul;
using std::wcscat;
using std::wcschr;
using std::wcscmp;
using std::wcscoll;
using std::wcscpy;
using std::wcscspn;
using std::wcslen;
using std::wcsncat;
using std::wcsncmp;
using std::wcsncpy;
using std::wcspbrk;
using std::wcsrchr;
using std::wcsspn;
using std::wcsxfrm;
using std::wcstok;
using std::wcsftime;
/* not XPG4 and not XPG4v2 */
#if (!defined(_XPG4) && !defined(_XPG4_2) || defined(_XPG5))
using std::btowc;
using std::fwprintf;
using std::fwscanf;
using std::fwide;
using std::mbsinit;
using std::mbrlen;
using std::mbrtowc;
using std::mbsrtowcs;
using std::swprintf;
using std::swscanf;
using std::vfwprintf;
using std::vwprintf;
using std::vswprintf;
using std::wcrtomb;
using std::wcsrtombs;
using std::wcsstr;
using std::wctob;
using std::wmemchr;
using std::wmemcmp;
using std::wmemcpy;
using std::wmemmove;
using std::wmemset;
using std::wprintf;
using std::wscanf;
#endif /* not XPG4 and not XPG4v2 */
#endif /* __cplusplus >= 199711L */

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_STRICT_STDC) || defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#if !defined(_WCTYPE_T) || __cplusplus >= 199711L
#define	_WCTYPE_T
typedef	int	wctype_t;
#endif
#endif /* !defined(_STRICT_STDC) || defined(_XOPEN_SOURCE)... */

/*
 * XPG6 requires that va_list be defined as defined in <stdarg.h>,
 * however, inclusion of <stdarg.h> breaks Standard C namespace.
 */
#if defined(_XPG6) && !defined(_VA_LIST)
#define	_VA_LIST
typedef __va_list va_list;
#endif  /* defined(_XPG6) && !defined(_VA_LIST) */

#if !defined(_STRICT_STDC) || defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#if __cplusplus >= 199711L
namespace std {
#endif
extern int iswalpha(wint_t);
extern int iswupper(wint_t);
extern int iswlower(wint_t);
extern int iswdigit(wint_t);
extern int iswxdigit(wint_t);
extern int iswalnum(wint_t);
extern int iswspace(wint_t);
extern int iswpunct(wint_t);
extern int iswprint(wint_t);
extern int iswgraph(wint_t);
extern int iswcntrl(wint_t);
extern int iswctype(wint_t, wctype_t);
extern wint_t towlower(wint_t);
extern wint_t towupper(wint_t);
extern wchar_t *wcswcs(const wchar_t *, const wchar_t *);
extern int wcswidth(const wchar_t *, size_t);
extern int wcwidth(wchar_t);
extern wctype_t wctype(const char *);
#if __cplusplus >= 199711L
} /* namespace std */

using std::iswalpha;
using std::iswupper;
using std::iswlower;
using std::iswdigit;
using std::iswxdigit;
using std::iswalnum;
using std::iswspace;
using std::iswpunct;
using std::iswprint;
using std::iswgraph;
using std::iswcntrl;
using std::iswctype;
using std::towlower;
using std::towupper;
using std::wcswcs;
using std::wcswidth;
using std::wcwidth;
using std::wctype;
#endif
#endif /* !defined(_STRICT_STDC) || defined(_XOPEN_SOURCE)... */

#if defined(_XPG7) || !defined(_STRICT_SYMBOLS)

#ifndef _LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif

extern size_t wcsnlen(const wchar_t *, size_t);
extern wchar_t *wcpcpy(wchar_t *_RESTRICT_KYWD, const wchar_t *_RESTRICT_KYWD);
extern wchar_t *wcpncpy(wchar_t *_RESTRICT_KYWD, const wchar_t *_RESTRICT_KYWD,
    size_t);
extern size_t wcsxfrm_l(wchar_t *_RESTRICT_KYWD, const wchar_t *_RESTRICT_KYWD,
    size_t, locale_t);
extern int wcscoll_l(const wchar_t *, const wchar_t *, locale_t);
extern wchar_t *wcsdup(const wchar_t *);
extern int wcscasecmp(const wchar_t *, const wchar_t *);
extern int wcscasecmp_l(const wchar_t *, const wchar_t *, locale_t);
extern int wcsncasecmp(const wchar_t *, const wchar_t *, size_t);
extern int wcsncasecmp_l(const wchar_t *, const wchar_t *, size_t, locale_t);
extern size_t mbsnrtowcs(wchar_t *_RESTRICT_KYWD, const char **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD);

#endif	/* defined(_XPG7) || !defined(_STRICT_SYMBOLS) */

#ifdef	__cplusplus
}
#endif

#endif	/* _WCHAR_H */
