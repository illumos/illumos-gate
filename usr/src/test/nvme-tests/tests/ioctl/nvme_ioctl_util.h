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

#ifndef _NVME_IOCTL_UTIL_H
#define	_NVME_IOCTL_UTIL_H

#include <stdint.h>
#include <sys/stdbool.h>
#include <sys/nvme.h>
#include <thread.h>

/*
 * Common definitions and functions for the NVMe ioctl tests.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NVME_TEST_DEV_ENVVAR	"NVME_TEST_DEVICE"

/*
 * Base locking structures to help facilitate locking tests.
 */
extern const nvme_ioctl_lock_t nvme_test_ctrl_wrlock;
extern const nvme_ioctl_lock_t nvme_test_ctrl_rdlock;
extern const nvme_ioctl_lock_t nvme_test_ns_wrlock;
extern const nvme_ioctl_lock_t nvme_test_ns_rdlock;
extern const nvme_ioctl_unlock_t nvme_test_ctrl_unlock;
extern const nvme_ioctl_unlock_t nvme_test_ns_unlock;

extern int nvme_ioctl_test_get_fd(uint32_t);
extern int nvme_ioctl_test_get_fd_flags(uint32_t, int);
extern void nvme_ioctl_test_lock(int, const nvme_ioctl_lock_t *);
extern bool nvme_ioctl_test_thr_blocked(thread_t);

extern const char *nvme_ioctl_test_cmdstr(int);

#ifdef __cplusplus
}
#endif

#endif /* _NVME_IOCTL_UTIL_H */
