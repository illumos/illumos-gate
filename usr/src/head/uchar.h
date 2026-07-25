/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _UCHAR_H
#define	_UCHAR_H

/*
 * C11+ Unicode utilities support.
 */

#include <sys/isa_defs.h>
#include <sys/feature_tests.h>
#include <wchar_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Declare our version.
 */
#define	__STDC_VERSION_UCHAR_H__	202311L

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64)
typedef	unsigned long size_t;	/* size of something in bytes */
#else
typedef	unsigned int size_t;	/* (historical version) */
#endif
#endif	/* _SIZE_T */

#if !defined(_MBSTATE_T) || __cplusplus >= 199711L
#define	_MBSTATE_T
typedef __mbstate_t	mbstate_t;
#endif	/* _MBSTATE_T */

/*
 * These types must match the uint_least16_t and uint_least32_t. They are
 * defined in terms of the same type so as to minimize the needed includes.
 * C++11 also defines these types and they are considered built in, so we should
 * not define them in that context.
 */
#if __cplusplus < 201103L
typedef unsigned short	char16_t;
typedef unsigned int	char32_t;
#endif

extern size_t mbrtoc16(char16_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD);
extern size_t mbrtoc32(char32_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD);
extern size_t c16rtomb(char *_RESTRICT_KYWD, char16_t,
    mbstate_t *_RESTRICT_KYWD);
extern size_t c32rtomb(char *_RESTRICT_KYWD, char32_t,
    mbstate_t *_RESTRICT_KYWD);

/*
 * C23 added variants and types that operate on UTF-8 based encodings. C++20
 * added the char8_t type hence the guards below. Because these weren't reserved
 * symbols, C11 strictly speaking isn't supposed to see these, hence why we have
 * _STRICT_SYMBOLS checks. Unlike the types above which are in terms of the
 * uint_leastXX_t, this is strictly defined in terms of an unsigned char.
 */
#if !defined(_STRICT_SYMBOLS) || defined(_STDC_C23)
#if __cplusplus < 202002L
typedef unsigned char	char8_t;
#endif

extern size_t mbrtoc8(char8_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD);
extern size_t c8rtomb(char *_RESTRICT_KYWD, char8_t, mbstate_t *_RESTRICT_KYWD);
#endif	/* !_STRICT_SYMBOLS || _STDC_C23 */

/*
 * We provide locale aware versions of all of the functions in a non-strict
 * compilation environment.
 */
#if !defined(_STRICT_SYMBOLS)

#ifndef _LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif

extern size_t mbrtoc8_l(char8_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD, locale_t _RESTRICT_KWYD);
extern size_t mbrtoc16_l(char16_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD, locale_t _RESTRICT_KWYD);
extern size_t mbrtoc32_l(char32_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD, locale_t _RESTRICT_KWYD);

extern size_t c8rtomb_l(char *_RESTRICT_KYWD, char8_t,
    mbstate_t *_RESTRICT_KYWD, locale_t _RESTRICT_KYWD);
extern size_t c16rtomb_l(char *_RESTRICT_KYWD, char16_t,
    mbstate_t *_RESTRICT_KYWD, locale_t _RESTRICT_KYWD);
extern size_t c32rtomb_l(char *_RESTRICT_KYWD, char32_t,
    mbstate_t *_RESTRICT_KYWD, locale_t _RESTRICT_KYWD);
#endif	/* !_STRICT_SYMBOLS */

#ifdef __cplusplus
}
#endif

#endif /* _UCHAR_H */
