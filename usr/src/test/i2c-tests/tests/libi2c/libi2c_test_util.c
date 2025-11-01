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

/*
 * Misc. test utilities.
 */

#include <stdarg.h>

#include "libi2c_test_util.h"

/*
 * For any test linked against libumem, ensure that umem debugging is enabled by
 * default. Many tests use umem_setmtbf() and we need to make sure there is no
 * per-thread cache.
 */
const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}

static void
libi2c_test_vwarn(i2c_hdl_t *hdl, const char *fmt, va_list ap)
{
	(void) fprintf(stderr, "TEST FAILED: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libi2c: 0x%x, sys: %d)\n",
	    i2c_errmsg(hdl), i2c_errtostr(hdl, i2c_err(hdl)),
	    i2c_err(hdl), i2c_syserr(hdl));
}

void
libi2c_test_warn(i2c_hdl_t *hdl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libi2c_test_vwarn(hdl, fmt, ap);
	va_end(ap);
}

void
libi2c_test_fatal(i2c_hdl_t *hdl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libi2c_test_vwarn(hdl, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}
