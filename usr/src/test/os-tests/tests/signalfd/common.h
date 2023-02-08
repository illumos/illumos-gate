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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef	_COMMON_H_
#define	_COMMON_H_

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>

void test_fail(const char *, ...);
void test_pass(void);
int test_basic_prep(int);

#endif	/* _COMMON_H_ */
