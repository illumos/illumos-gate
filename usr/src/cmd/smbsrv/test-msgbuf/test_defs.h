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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _TEST_DEFS_H
#define	_TEST_DEFS_H

/*
 * Describe the purpose of the file here.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern void hexdump(const uchar_t *buf, int len);
extern void test_conv(void);
extern void test_mbmarshal(void);
extern void test_msgbuf(void);

#ifdef __cplusplus
}
#endif

#endif /* _TEST_DEFS_H */
