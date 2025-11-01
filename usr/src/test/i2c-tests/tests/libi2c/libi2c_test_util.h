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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _LIBI2C_TEST_UTIL_H
#define	_LIBI2C_TEST_UTIL_H

/*
 * Misc. utility functions for libi2c tests.
 */

#include <stdbool.h>
#include <libi2c.h>
#include <sys/ccompile.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void libi2c_test_warn(i2c_hdl_t *, const char *, ...) __PRINTFLIKE(2);
extern void libi2c_test_fatal(i2c_hdl_t *, const char *, ...) __PRINTFLIKE(2);

#ifdef __cplusplus
}
#endif

#endif /* _LIBI2C_TEST_UTIL_H */
