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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _PTOOLS_COMMON_H
#define	_PTOOLS_COMMON_H

#include <sys/feature_tests.h>

/*
 * Common functions for the ptools.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int proc_snprintf(char *_RESTRICT_KYWD, size_t,
    const char *_RESTRICT_KYWD, ...);

#ifdef __cplusplus
}
#endif

#endif /* _PTOOLS_COMMON_H */
