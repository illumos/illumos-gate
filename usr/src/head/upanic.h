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
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _UPANIC_H
#define	_UPANIC_H

/*
 * Support for guaranteed user process abort-like termination.
 */

#include <sys/feature_tests.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern _NORETURN_KYWD void upanic(const char *, size_t) __NORETURN;

#ifdef __cplusplus
}
#endif

#endif /* _UPANIC_H */
