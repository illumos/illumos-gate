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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _FAKEKERNEL_H
#define	_FAKEKERNEL_H

#include <sys/types.h>
#include <sys/varargs.h>

#ifdef __cplusplus
extern "C" {
#endif

void fakekernel_init(void);
void fakekernel_putlog(char *, size_t, int);
void fakekernel_cprintf(const char *, va_list, int,
	const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _FAKEKERNEL_H */
