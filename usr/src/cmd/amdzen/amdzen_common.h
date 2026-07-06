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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _AMDZEN_COMMON_H
#define	_AMDZEN_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#define	EXIT_USAGE	2

extern int amdzen_open_device(const char *, const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _AMDZEN_COMMON_H */
