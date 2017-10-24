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

#define	__FBSDID(s)

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

/*
 * The __CONCAT macro is used to concatenate parts of symbol names, e.g.
 * with "#define OLD(foo) __CONCAT(old,foo)", OLD(foo) produces oldfoo.
 * The __CONCAT macro is a bit tricky to use if it must work in non-ANSI
 * mode -- there must be no spaces between its arguments, and for nested
 * __CONCAT's, all the __CONCAT's must be at the left.  __CONCAT can also
 * concatenate double-quoted strings produced by the __STRING macro, but
 * this only works with ANSI C.
 *
 * __XSTRING is like __STRING, but it expands any macros in its argument
 * first.  It is only available with ANSI C.
 */
#if defined(__STDC__) || defined(__cplusplus)
#define	__P(protos)	protos		/* full-blown ANSI C */
#define	__CONCAT1(x,y)	x ## y
#define	__CONCAT(x,y)	__CONCAT1(x,y)
#define	__STRING(x)	#x		/* stringify without expanding x */
#define	__XSTRING(x)	__STRING(x)	/* expand x, then stringify */
#else	/* !(__STDC__ || __cplusplus) */
#define	__P(protos)	()		/* traditional C preprocessor */
#define	__CONCAT(x,y)	x/**/y
#define	__STRING(x)	"x"
#endif	/* !(__STDC__ || __cplusplus) */

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L || defined(lint)

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

#endif	/* _COMPAT_FREEBSD_SYS_CDEFS_H_ */
