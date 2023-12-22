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
 * Copyright 2013 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _COMPAT_FREEBSD_SYS_CDEFS_H_
#define	_COMPAT_FREEBSD_SYS_CDEFS_H_

/*
 * Testing against Clang-specific extensions.
 */
#ifndef __has_extension
#define	__has_extension		__has_feature
#endif
#ifndef __has_feature
#define	__has_feature(x)	0
#endif

/*
 * Macro to test if we're using a specific version of gcc or later.
 */
#if defined(__GNUC__) && !defined(__INTEL_COMPILER)
#define __GNUC_PREREQ__(ma, mi) \
	(__GNUC__ > (ma) || __GNUC__ == (ma) && __GNUC_MINOR__ >= (mi))
#else
#define __GNUC_PREREQ__(ma, mi) 0
#endif

#ifdef	__GNUC__
#define	asm		__asm
#define	inline		__inline

#define	__GNUCLIKE___SECTION		1

#define	__dead2		__attribute__((__noreturn__))
#define	__used		__attribute__((__used__))
#define	__packed	__attribute__((__packed__))
#define	__aligned(x)	__attribute__((__aligned__(x)))
#define	__section(x)	__attribute__((__section__(x)))
#define	__weak_symbol   __attribute__((__weak__))
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L || defined(lint)

#if defined(__cplusplus) && __cplusplus >= 201103L
#define	_Alignof(x)		alignof(x)
#else
#define	_Alignof(x)		__alignof(x)
#endif

#if defined(__cplusplus) && __cplusplus >= 201103L
#define	_Noreturn		[[noreturn]]
#else
#define	_Noreturn		__dead2
#endif

#if !__has_extension(c_static_assert)
#if (defined(__cplusplus) && __cplusplus >= 201103L) || \
    __has_extension(cxx_static_assert)
#define _Static_assert(x, y)    static_assert(x, y)
#elif __GNUC_PREREQ__(4,6)
/* Nothing, gcc 4.6 and higher has _Static_assert built-in */
#elif defined(__COUNTER__)
#define _Static_assert(x, y)    __Static_assert(x, __COUNTER__)
#define __Static_assert(x, y)   ___Static_assert(x, y)
#define ___Static_assert(x, y)  typedef char __assert_ ## y[(x) ? 1 : -1] \
                                __unused
#else
#define _Static_assert(x, y)    struct __hack
#endif
#endif
#define	static_assert(x, y)	_Static_assert(x, y)

#endif /* __STDC_VERSION__ || __STDC_VERSION__ < 201112L */

#if __GNUC_PREREQ__(4, 1)
#define	__offsetof(type, field)	 __builtin_offsetof(type, field)
#else
#ifndef __cplusplus
#define	__offsetof(type, field) \
	((__size_t)(__uintptr_t)((const volatile void *)&((type *)0)->field))
#else
#define	__offsetof(type, field)					\
  (__offsetof__ (reinterpret_cast <__size_t>			\
                 (&reinterpret_cast <const volatile char &>	\
                  (static_cast<type *> (0)->field))))
#endif
#endif

#ifndef __DECONST
#define	__DECONST(type, var)	((type)(uintptr_t)(const void *)(var))
#endif

#endif	/* _COMPAT_FREEBSD_SYS_CDEFS_H_ */
