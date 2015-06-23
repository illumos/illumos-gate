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

#ifndef _SYS_USER_H
#define	_SYS_USER_H

/*
 * libfakekernel version of sys/user.h
 * typically pulled in by sys/file.h
 */

#include <sys/types.h>
#include <sys/signal.h>

#ifdef __cplusplus
extern "C" {
#endif

struct exdata;
#if defined(_KERNEL) || defined(_FAKE_KERNEL) || defined(_KMEMUSER)
typedef struct uf_info uf_info_t;
#endif
typedef struct user user_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USER_H */
