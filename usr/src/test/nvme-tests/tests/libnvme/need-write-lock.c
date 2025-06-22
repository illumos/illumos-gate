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
 * Various destructive options require a write lock. These include:
 *
 *  - namespace creation and deletion
 *  - attaching or detaching a controller to a namespace
 *  - manipulating blkdev state
 *  - formatting a namespace
 *
 * While firmware operations also require this, that is harder to test in this
 * case as we don't have valid firmware files or want to manipulate the device.
 * We check that operations fail in sevearl different situations:
 *
 * 1) With no locks held.
 * 2) With a namespace read lock.
 * 3) With a controller read lock.
 * 4) With a namespace write lock (note, some items succeed here).
 *
 * This test starts from the device-empty profile.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include "libnvme_test_common.h"

#define	LOCK_NSID	1

static uint32_t lock_lbaf;

typedef enum {
	LOCK_NONE,
	LOCK_NS_RD,
	LOCK_NS_WR,
	LOCK_CTRL_RD,
	LOCK_MAX
} lock_type_t;

typedef struct write_test {
	const char *wt_desc;
	nvme_err_t wt_errs[LOCK_MAX];
	nvme_ns_disc_level_t wt_disc;
	bool (*wt_func)(nvme_ctrl_t *, const char *, nvme_err_t);
} write_test_t;

static bool
write_lock_ns_create(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp)
{
	uint64_t create_size = NVME_TEST_NS_SIZE / NVME_TEST_LBA_SIZE;
	uint32_t nsid;
	nvme_err_t act;

	if (!libnvme_test_ns_create(ctrl, create_size, lock_lbaf, &nsid,
	    &act)) {
		warnx("TEST FAILED: failed to initialize namespace create"
		    "request in lock %s iteration", desc);
		return (false);
	} else if (act != exp) {
		warnx("TEST FAILED: namespace create with %s returned %s "
		    "(0x%x), but expected %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, act), act,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
		return (false);
	}

	(void) printf("TEST PASSED: namespace delete with %s returned %s\n",
	    desc, nvme_ctrl_errtostr(ctrl, act));

	return (true);
}

static bool
write_lock_ns_delete(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp)
{
	nvme_err_t act;

	if (!libnvme_test_ns_delete(ctrl, LOCK_NSID, &act)) {
		warnx("TEST FAILED: failed to initialize namespace delete "
		    "request in lock %s iteration", desc);
		return (false);
	} else if (act != exp) {
		warnx("TEST FAILED: namespace delete with %s returned %s "
		    "(0x%x), but expected %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, act), act,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
		return (false);
	}

	(void) printf("TEST PASSED: namespace delete with %s returned %s\n",
	    desc, nvme_ctrl_errtostr(ctrl, act));
	return (true);
}

static bool
write_lock_ctrl_detach(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp)
{
	nvme_err_t act;

	if (!libnvme_test_ctrl_attach(ctrl, LOCK_NSID,
	    NVME_NS_ATTACH_CTRL_DETACH, &act)) {
		warnx("TEST FAILED: failed to initialize controller detach "
		    "request in lock %s iteration", desc);
		return (false);
	} else if (act != exp) {
		warnx("TEST FAILED: controller detach with %s returned %s "
		    "(0x%x), but expected %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, act), act,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
		return (false);
	}

	(void) printf("TEST PASSED: controller detach with %s returned %s\n",
	    desc, nvme_ctrl_errtostr(ctrl, act));
	return (true);
}

static bool
write_lock_ctrl_attach(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp)
{
	nvme_err_t act;

	if (!libnvme_test_ctrl_attach(ctrl, LOCK_NSID,
	    NVME_NS_ATTACH_CTRL_ATTACH, &act)) {
		warnx("TEST FAILED: failed to initialize controller attach "
		    "request in lock %s iteration", desc);
		return (false);
	} else if (act != exp) {
		warnx("TEST FAILED: controller attach with %s returned %s "
		    "(0x%x), but expected %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, act), act,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
		return (false);
	}

	(void) printf("TEST PASSED: controller attach with %s returned %s\n",
	    desc, nvme_ctrl_errtostr(ctrl, act));
	return (true);
}

static bool
write_lock_blkdev_detach(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp)
{
	nvme_err_t act;

	if (!libnvme_test_ns_blkdev(ctrl, LOCK_NSID, false, &act)) {
		warnx("TEST FAILED: failed to initialize blkdev detach "
		    "request in lock %s iteration", desc);
		return (false);
	} else if (act != exp) {
		warnx("TEST FAILED: blkdev detach with %s returned %s (0x%x), "
		    "but expected %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, act), act,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
		return (false);
	}

	(void) printf("TEST PASSED: blkdev detach with %s returned %s\n", desc,
	    nvme_ctrl_errtostr(ctrl, act));
	return (true);
}

static bool
write_lock_blkdev_attach(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp)
{
	nvme_err_t act;

	if (!libnvme_test_ns_blkdev(ctrl, LOCK_NSID, true, &act)) {
		warnx("TEST FAILED: failed to initialize blkdev attach "
		    "request in lock %s iteration", desc);
		return (false);
	} else if (act != exp) {
		warnx("TEST FAILED: blkdev attach with %s returned %s (0x%x), "
		    "but expected %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, act), act,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
		return (false);
	}

	(void) printf("TEST PASSED: blkdev attach with %s returned %s\n", desc,
	    nvme_ctrl_errtostr(ctrl, act));
	return (true);
}

static const write_test_t write_tests[] = { {
	.wt_desc = "namespace create",
	.wt_errs = {
		[LOCK_NONE] = NVME_ERR_NEED_CTRL_WRLOCK,
		[LOCK_NS_RD] = NVME_ERR_NEED_CTRL_WRLOCK,
		[LOCK_NS_WR] = NVME_ERR_NEED_CTRL_WRLOCK,
		[LOCK_CTRL_RD] = NVME_ERR_NEED_CTRL_WRLOCK
	},
	.wt_disc = NVME_NS_DISC_F_ALL,
	.wt_func = write_lock_ns_create
}, {
	.wt_desc = "namespace delete",
	.wt_errs = {
		[LOCK_NONE] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_RD] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_WR] = NVME_ERR_OK,
		[LOCK_CTRL_RD] = NVME_ERR_NEED_NS_WRLOCK
	},
	.wt_disc = NVME_NS_DISC_F_ALLOCATED,
	.wt_func = write_lock_ns_delete
}, {
	.wt_desc = "controller attach",
	.wt_errs = {
		[LOCK_NONE] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_RD] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_WR] = NVME_ERR_OK,
		[LOCK_CTRL_RD] = NVME_ERR_NEED_NS_WRLOCK
	},
	.wt_disc = NVME_NS_DISC_F_ALLOCATED,
	.wt_func = write_lock_ctrl_attach
}, {
	.wt_desc = "controller detach",
	.wt_errs = {
		[LOCK_NONE] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_RD] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_WR] = NVME_ERR_OK,
		[LOCK_CTRL_RD] = NVME_ERR_NEED_NS_WRLOCK
	},
	.wt_disc = NVME_NS_DISC_F_ACTIVE,
	.wt_func = write_lock_ctrl_detach
}, {
	.wt_desc = "blkdev attach",
	.wt_errs = {
		[LOCK_NONE] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_RD] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_WR] = NVME_ERR_OK,
		[LOCK_CTRL_RD] = NVME_ERR_NEED_NS_WRLOCK
	},
	.wt_disc = NVME_NS_DISC_F_NOT_IGNORED,
	.wt_func = write_lock_blkdev_attach
}, {
	.wt_desc = "blkdev detach",
	.wt_errs = {
		[LOCK_NONE] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_RD] = NVME_ERR_NEED_NS_WRLOCK,
		[LOCK_NS_WR] = NVME_ERR_OK,
		[LOCK_CTRL_RD] = NVME_ERR_NEED_NS_WRLOCK
	},
	.wt_disc = NVME_NS_DISC_F_BLKDEV,
	.wt_func = write_lock_blkdev_detach
} };

typedef struct lock_info {
	const char *li_desc;
	bool (*li_lock_f)(nvme_ctrl_t *, nvme_ns_t *);
	void (*li_unlock_f)(nvme_ctrl_t *, nvme_ns_t *);
} lock_info_t;

static bool
lock_none_lock(nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
	return (true);
}

static bool
lock_ns_read_lock(nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
	return (nvme_ns_lock(ns, NVME_LOCK_L_READ, NVME_LOCK_F_DONT_BLOCK));
}

static bool
lock_ns_write_lock(nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
	return (nvme_ns_lock(ns, NVME_LOCK_L_WRITE, NVME_LOCK_F_DONT_BLOCK));
}

static bool
lock_ctrl_read_lock(nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
	return (nvme_ctrl_lock(ctrl, NVME_LOCK_L_READ, NVME_LOCK_F_DONT_BLOCK));
}

static void
lock_none_unlock(nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
}

static void
lock_ns_unlock(nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
	nvme_ns_unlock(ns);
}

static void
lock_ctrl_unlock(nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
	nvme_ctrl_unlock(ctrl);
}

lock_info_t lock_info[LOCK_MAX] = {
	[LOCK_NONE] = {
		.li_desc = "no lock",
		.li_lock_f = lock_none_lock,
		.li_unlock_f = lock_none_unlock,
	},
	[LOCK_NS_RD] = {
		.li_desc = "namespace read lock",
		.li_lock_f = lock_ns_read_lock,
		.li_unlock_f = lock_ns_unlock,
	},
	[LOCK_NS_WR] = {
		.li_desc = "namespace write lock",
		.li_lock_f = lock_ns_write_lock,
		.li_unlock_f = lock_ns_unlock,
	},
	[LOCK_CTRL_RD] = {
		.li_desc = "controller read lock",
		.li_lock_f = lock_ctrl_read_lock,
		.li_unlock_f = lock_ctrl_unlock,
	}

};

static bool
write_test_one(const write_test_t *test, nvme_ctrl_t *ctrl, nvme_ns_t *ns)
{
	bool ret = true;

	for (lock_type_t i = LOCK_NONE; i < LOCK_MAX; i++) {
		if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE,
		    NVME_LOCK_F_DONT_BLOCK)) {
			libnvme_test_ctrl_fatal(ctrl, "failed to obtain write "
			    "lock");
		}

		if (!libnvme_test_setup_ns(ctrl, test->wt_disc, LOCK_NSID,
		    lock_lbaf)) {
			libnvme_test_ctrl_fatal(ctrl, "failed to change state "
			    "to 0x%x", test->wt_disc);
		}

		nvme_ctrl_unlock(ctrl);

		if (!lock_info[i].li_lock_f(ctrl, ns)) {
			ret = false;
			continue;
		}

		if (!test->wt_func(ctrl, lock_info[i].li_desc,
		    test->wt_errs[i])) {
			ret = false;
		}

		lock_info[i].li_unlock_f(ctrl, ns);
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_ctrl_info_t *info;
	nvme_ns_t *ns;

	libnvme_test_init(&nvme, &ctrl);

	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to get info snapshot");
	}

	if (!nvme_ns_init(ctrl, LOCK_NSID, &ns)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to create ns %u "
		    "nvme_ns_t", LOCK_NSID);
	}

	if (!libnvme_test_lbaf(info, NVME_TEST_LBA_SIZE, &lock_lbaf)) {
		errx(EXIT_FAILURE, "failed to find 4K LBA format, cannot "
		    "continue");
	}

	for (size_t i = 0; i < ARRAY_SIZE(write_tests); i++) {
		if (!write_test_one(&write_tests[i], ctrl, ns))
			ret = EXIT_FAILURE;
	}

	nvme_ns_fini(ns);
	nvme_ctrl_info_free(info);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
