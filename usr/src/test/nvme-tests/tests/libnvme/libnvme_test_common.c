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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Common utilities for libnvme tests.
 */

#include <err.h>
#include <stdlib.h>

#include "libnvme_test_common.h"

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
libnvme_test_hdl_vwarn(nvme_t *nvme, const char *fmt, va_list ap)
{
	(void) fprintf(stderr, "TEST FAILED: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libnvme: 0x%x, sys: %d)\n",
	    nvme_errmsg(nvme), nvme_errtostr(nvme, nvme_err(nvme)),
	    nvme_err(nvme), nvme_syserr(nvme));
}

static void
libnvme_test_ctrl_vwarn(nvme_ctrl_t *ctrl, const char *fmt, va_list ap)
{
	(void) fprintf(stderr, "TEST FAILED: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libnvme: 0x%x, sys: %d)\n",
	    nvme_ctrl_errmsg(ctrl), nvme_ctrl_errtostr(ctrl,
	    nvme_ctrl_err(ctrl)), nvme_ctrl_err(ctrl), nvme_ctrl_syserr(ctrl));
}

static void
libnvme_test_ctrl_info_vwarn(nvme_ctrl_info_t *info, const char *fmt,
    va_list ap)
{
	(void) fprintf(stderr, "TEST FAILED: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libnvme info: 0x%x, sys: %d)\n",
	    nvme_ctrl_info_errmsg(info), nvme_ctrl_info_errtostr(info,
	    nvme_ctrl_info_err(info)), nvme_ctrl_info_err(info),
	    nvme_ctrl_info_syserr(info));
}

static void
libnvme_test_ns_info_vwarn(nvme_ns_info_t *info, const char *fmt,
    va_list ap)
{
	(void) fprintf(stderr, "TEST FAILED: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libnvme info: 0x%x, sys: %d)\n",
	    nvme_ns_info_errmsg(info), nvme_ns_info_errtostr(info,
	    nvme_ns_info_err(info)), nvme_ns_info_err(info),
	    nvme_ns_info_syserr(info));
}

void
libnvme_test_hdl_warn(nvme_t *nvme, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libnvme_test_hdl_vwarn(nvme, fmt, ap);
	va_end(ap);
}

void __NORETURN
libnvme_test_hdl_fatal(nvme_t *nvme, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libnvme_test_hdl_vwarn(nvme, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

void
libnvme_test_ctrl_warn(nvme_ctrl_t *ctrl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libnvme_test_ctrl_vwarn(ctrl, fmt, ap);
	va_end(ap);
}

void __NORETURN
libnvme_test_ctrl_fatal(nvme_ctrl_t *ctrl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libnvme_test_ctrl_vwarn(ctrl, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

void
libnvme_test_ctrl_info_warn(nvme_ctrl_info_t *info, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libnvme_test_ctrl_info_vwarn(info, fmt, ap);
	va_end(ap);
}

void
libnvme_test_ns_info_warn(nvme_ns_info_t *info, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libnvme_test_ns_info_vwarn(info, fmt, ap);
	va_end(ap);
}

void __NORETURN
libnvme_test_ctrl_info_fatal(nvme_ctrl_info_t *info, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	libnvme_test_ctrl_info_vwarn(info, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

void
libnvme_test_init(nvme_t **nvmep, nvme_ctrl_t **ctrlp)
{
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	const char *dev;

	nvme = nvme_init();
	if (nvme == NULL) {
		err(EXIT_FAILURE, "failed to create libnvme handle");
	}

	dev = getenv(NVME_TEST_DEV_ENVVAR);
	if (dev == NULL) {
		errx(EXIT_FAILURE, "cannot run test, missing required NVMe "
		    "device, please set the %s environment variable",
		    NVME_TEST_DEV_ENVVAR);
	}

	if (!nvme_ctrl_ns_init(nvme, dev, &ctrl, NULL)) {
		libnvme_test_hdl_fatal(nvme, "failed to open %s", dev);
	}

	*nvmep = nvme;
	*ctrlp = ctrl;
}
