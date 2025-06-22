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

/*
 * Target default LBA size and namespace size in bytes. We default to a 1 GiB
 * namespace when using common test code. In the future we may need to look at
 * the namespace granularity instead.
 */
#define	NVME_TEST_LBA_SIZE	4096
#define	NVME_TEST_NS_SIZE	(1ULL * 1024ULL * 1024ULL * 1024ULL)

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

/*
 * Misc. utilities.
 */
extern bool libnvme_test_ctrl_err(nvme_ctrl_t *, uint32_t, uint32_t,
    const char *);
extern bool libnvme_test_lbaf(nvme_ctrl_info_t *, uint32_t, uint32_t *);
extern bool libnvme_test_setup_ns(nvme_ctrl_t *, nvme_ns_disc_level_t,
    uint32_t, uint32_t);

/*
 * Basic namespace routines. These will normally return true if they complete
 * successfully. If the error pointer is passed then they will return true as
 * long as the error pointer is valid and it will be up to the caller to figure
 * out what to do with it.
 */
extern bool libnvme_test_ns_delete(nvme_ctrl_t *, uint32_t, nvme_err_t *);
extern bool libnvme_test_ns_create(nvme_ctrl_t *, uint64_t, uint32_t,
    uint32_t *, nvme_err_t *);
extern bool libnvme_test_ctrl_attach(nvme_ctrl_t *, uint32_t, uint32_t,
    nvme_err_t *);
extern bool libnvme_test_ns_blkdev(nvme_ctrl_t *, uint32_t, bool, nvme_err_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBNVME_TEST_COMMON_H */
