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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other illumos headers.
 *
 * The contents of this header is limited to identifiers specified in
 * the C11 standard and in conflict with the C++ implementation of the
 * standard header.  The C++ standard may adopt the C11 standard at
 * which point it is expected that the symbols included here will
 * become part of the C++ std namespace.
 */

#ifndef _ISO_STDLIB_C11_H
#define	_ISO_STDLIB_C11_H

#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

/*
 * The following have been added as a result of the ISO/IEC 9899:2011
 * standard. For a strictly conforming C application, visibility is
 * contingent on the value of __STDC_VERSION__ (see sys/feature_tests.h).
 * For non-strictly conforming C applications, there are no restrictions
 * on the C namespace.
 */

/*
 * Work around fix-includes and other bad actors with using multiple headers.
 */
#if !defined(_NORETURN_KYWD)
#if __STDC_VERSION__ - 0 >= 201112L
#define	_NORETURN_KYWD	_Noreturn
#else
#define	_NORETURN_KYWD
#endif	/* __STDC_VERSION__ - 0 >= 201112L */
#endif	/* !defined(_NORETURN_KYWD) */

#if !defined(_STRICT_SYMBOLS) || defined(_STDC_C11)
extern void *aligned_alloc(size_t, size_t);
#endif /* !_STRICT_SYMBOLS || _STDC_C11 */

#if !defined(_STRICT_SYMBOLS) || defined(_STDC_C11) || __cplusplus >= 201103L
extern int at_quick_exit(void (*)(void));
extern _NORETURN_KYWD void quick_exit(int);
#endif /* !_STRICT_SYMBOLS || _STDC_C11 || __cplusplus >= 201103L */

#if __cplusplus >= 199711L
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ISO_STDLIB_C11_H */
