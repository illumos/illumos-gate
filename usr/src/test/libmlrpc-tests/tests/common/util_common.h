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
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 */

#ifndef _UTIL_COMMON_H
#define	_UTIL_COMMON_H

/*
 * Common utilities for libmlrpc tests.
 */

#ifdef __cplusplus
extern "C" {
#endif

uchar_t *read_buf_from_file(char *, uint32_t *);
void smb_syslog(int, const char *, ...);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_COMMON_H */
