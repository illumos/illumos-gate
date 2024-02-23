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
 * Perform basic GET LOG PAGE commands just to prove that this works end to
 * work. This is not intended to be an exhaustive set of tests, merely proving
 * that things work. We utilize the SMART / Health information and the Firmware
 * Slot information because these two pages have existed since NVMe 1.0 and both
 * are the same fixed size (512 bytes). They both have useful pieces of expected
 * non-zero data: the current temperature and firmware slot respectively. These
 * are both within the first u32, so we just check that the entire u32 is
 * non-zero and not all 1s.
 *
 * It's quite probably virtualized devices will lie about these. When they do,
 * we should add specific devices to an exception list.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysmacros.h>

#include "nvme_ioctl_util.h"

typedef struct {
	const char *lt_desc;
	uint32_t lt_lid;
	size_t lt_len;
} log_test_t;

static const log_test_t basic_log_tests[] = {
	{ "Health/SMART log page", NVME_LOGPAGE_HEALTH, 512 },
	{ "Firmware log page", NVME_LOGPAGE_FWSLOT, 512 },
};

static bool
basic_get_one_log(int fd, const log_test_t *test)
{
	bool ret = true;
	nvme_ioctl_get_logpage_t log;
	void *data;

	if ((data = calloc(test->lt_len, 1)) == NULL) {
		err(EXIT_FAILURE, "%s: failed to allocate %zu bytes for "
		    "log page data", test->lt_desc, test->lt_len);
	}

	(void) memset(&log, 0, sizeof (log));
	log.nigl_csi = NVME_CSI_NVM;
	log.nigl_lid = test->lt_lid;
	log.nigl_len = test->lt_len;
	log.nigl_data = (uintptr_t)data;

	if (ioctl(fd, NVME_IOC_GET_LOGPAGE, &log) != 0) {
		warn("TEST FAILED: %s: failed to issue get log page ioctl",
		    test->lt_desc);
		ret = false;
	} else if (log.nigl_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		warnx("TEST FAILED: %s: get log page ioctl set error to 0x%x, "
		    "but expected success", test->lt_desc,
		    log.nigl_common.nioc_drv_err);
		ret = false;
	} else {
		uint32_t t;

		(void) printf("TEST PASSED: %s: successfully issued get log "
		    "page command\n", test->lt_desc);
		(void) memcpy(&t, data, sizeof (t));
		if (t == 0 || t == UINT32_MAX) {
			warnx("TEST FAILED: %s: uint32_t at word 0 looks like "
			    "invalid data, found 0x%x", test->lt_desc, t);
			ret = false;
		} else {
			(void) printf("TEST PASSED: %s: returned data passes "
			    "initial scrutiny\n", test->lt_desc);
		}
	}

	free(data);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int fd = nvme_ioctl_test_get_fd(0);

	for (size_t i = 0; i < ARRAY_SIZE(basic_log_tests); i++) {
		if (!basic_get_one_log(fd, &basic_log_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	VERIFY0(close(fd));
	return (ret);
}
