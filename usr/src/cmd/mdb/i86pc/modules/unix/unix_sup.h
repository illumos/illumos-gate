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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _UNIX_SUP_H
#define	_UNIX_SUP_H

/*
 * Support routines for unix.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern ulong_t kmdb_unix_getcr0(void);
extern ulong_t kmdb_unix_getcr2(void);
extern ulong_t kmdb_unix_getcr3(void);
extern ulong_t kmdb_unix_getcr4(void);

#ifdef __cplusplus
}
#endif

#endif /* _UNIX_SUP_H */
