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
 * Copyright 2017 Jason King
 * Copyright 2019 Joyent, Inc.
 */
#ifndef _DEMANGLE_INT_H
#define	_DEMANGLE_INT_H

#include <inttypes.h>
#include <stdio.h>
#include <sys/byteorder.h>
#include <sys/ctype.h> /* Use ASCII ISXXXX() macros */
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/isa_defs.h>
#include "demangle-sys.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __CHECKER__
/*
 * smatch seems to have a bug which chokes on the builtins, so
 * we just have it fallback to the non-builtin definitions
 */
#elif __GNUC__ >= 5 && __GNUC_MINOR__ > 1
#define	USE_BUILTIN_OVERFLOW
#elif defined(__clang__)
#define	USE_BUILTIN_OVERFLOW
#endif

#ifdef USE_BUILTIN_OVERFLOW
static inline boolean_t
mul_overflow(uint64_t a, uint64_t b, uint64_t *v)
{
	return (__builtin_mul_overflow(a, b, v));
}

static inline boolean_t
add_overflow(uint64_t a, uint64_t b, uint64_t *v)
{
	return (__builtin_add_overflow(a, b, v));
}

static inline boolean_t
sub_overflow(uint64_t a, uint64_t b, uint64_t *v)
{
	return (__builtin_sub_overflow(a, b, v));
}
#else
static inline boolean_t
mul_overflow(uint64_t a, uint64_t b, uint64_t *v)
{
	uint64_t val = a * b;

	if (a != 0 && val / a != b)
		return (B_TRUE);
	*v = val;
	return (B_FALSE);
}

static inline boolean_t
add_overflow(uint64_t a, uint64_t b, uint64_t *v)
{
	uint64_t val = a + b;

	if (val < a || val < b)
		return (B_TRUE);
	*v = val;
	return (B_FALSE);
}

static inline boolean_t
sub_overflow(uint64_t a, uint64_t b, uint64_t *v)
{
	uint64_t val = a - b;

	if (val > a)
		return (B_TRUE);
	*v = val;
	return (B_FALSE);
}
#endif

extern sysdem_ops_t *sysdem_ops_default;

char *cpp_demangle(const char *, size_t, sysdem_ops_t *);
char *rust_demangle(const char *, size_t, sysdem_ops_t *);

struct custr_alloc;

void *zalloc(sysdem_ops_t *, size_t);
void *xcalloc(sysdem_ops_t *, size_t, size_t);
void *xrealloc(sysdem_ops_t *, void *, size_t, size_t);
void xfree(sysdem_ops_t *, void *, size_t);
char *xstrdup(sysdem_ops_t *, const char *);

extern volatile boolean_t demangle_debug;

/*
 * gcc seems to get unhappy with the ASSERT() style definition (also borrowed
 * for the DEMDEBUG macro unless demdebug() is returns a non-void value
 * (despite the return value never being used).
 */
int demdebug(const char *, ...);

#define	DEMDEBUG(s, ...) \
	((void)(demangle_debug && demdebug(s, ## __VA_ARGS__)))

#ifdef __cplusplus
}
#endif

#endif /* _DEMANGLE_INT_H */
