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
 * Copyright 2019, Joyent, Inc.
 */
#ifndef _DEMANGLE_INT_H
#define	_DEMANGLE_INT_H

#include <stdio.h>
#include "demangle-sys.h"

#ifdef __cplusplus
extern "C" {
#endif

extern sysdem_ops_t *sysdem_ops_default;

char *cpp_demangle(const char *, size_t, sysdem_ops_t *);
char *rust_demangle(const char *, size_t, sysdem_ops_t *);

void *zalloc(sysdem_ops_t *, size_t);
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
