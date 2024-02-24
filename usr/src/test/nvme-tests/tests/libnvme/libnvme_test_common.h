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

#ifndef _LIBNVME_TEST_COMMON_H
#define	_LIBNVME_TEST_COMMON_H

#include <stdbool.h>
#include <libnvme.h>
#include <sys/ccompile.h>

/*
 * Common definitions and functions for the libnvme tests.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NVME_TEST_DEV_ENVVAR	"NVME_TEST_DEVICE"

extern void libnvme_test_init(nvme_t **, nvme_ctrl_t **);

/*
 * Warnings and fatal errors from the surrounding tests.
 */
extern void libnvme_test_hdl_warn(nvme_t *, const char *,
    ...) __PRINTFLIKE(2);
extern void libnvme_test_ctrl_warn(nvme_ctrl_t *, const char *,
    ...) __PRINTFLIKE(2);
extern void libnvme_test_ctrl_info_warn(nvme_ctrl_info_t *, const char *,
    ...) __PRINTFLIKE(2);
extern void libnvme_test_ns_info_warn(nvme_ns_info_t *, const char *,
    ...) __PRINTFLIKE(2);
extern void libnvme_test_hdl_fatal(nvme_t *, const char *,
    ...) __PRINTFLIKE(2) __NORETURN;
extern void libnvme_test_ctrl_fatal(nvme_ctrl_t *, const char *,
    ...) __PRINTFLIKE(2) __NORETURN;
extern void libnvme_test_ctrl_info_fatal(nvme_ctrl_info_t *, const char *,
    ...) __PRINTFLIKE(2) __NORETURN;

#ifdef __cplusplus
}
#endif

#endif /* _LIBNVME_TEST_COMMON_H */
