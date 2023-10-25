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
 * Copyright 2020 Robert Mustacchi
 */

#ifndef _UCHAR_H
#define	_UCHAR_H

/*
 * C11 Unicode utilities support.
 *
 * Note, we do not define either __STDC_UTF_16__ or __STDC_UTF_32__. While the
 * functions that are implemented work in that fashion, the ability to represent
 * any UTF-16 or UTF-32 code point depends on the current locale. Though in
 * practice they function that way.
 */

#include <sys/isa_defs.h>
#include <sys/feature_tests.h>
#include <wchar_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
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

#ifdef __cplusplus
}
#endif

#endif /* _UCHAR_H */
