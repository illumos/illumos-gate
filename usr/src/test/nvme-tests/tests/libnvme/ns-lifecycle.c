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
 * This test goes through the lifecycle of a namespace and verifies that when we
 * try to take transitions that it does not support, we can generate the
 * expected errors.
 *
 * This test expects to start from the device-empty profile.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

#include "libnvme_test_common.h"

/*
 * We expect that we should always be issued NSID 1.
 */
#define	NS_LC_NSID	1

/*
 * This is a list of actions we can take in a given state against a namespace.
 * There is no namespace create in this list as there is no way to specify a
 * namespace to take action against.
 */
typedef enum {
	NS_ACT_NS_DELETE,
	NS_ACT_CTRL_ATTACH,
	NS_ACT_CTRL_DETACH,
	NS_ACT_BD_ATTACH,
	NS_ACT_BD_DETACH
} ns_act_t;

#define	NS_LC_NACTS	(NS_ACT_BD_DETACH + 1)

nvme_err_t nvme_unalloc_errs[NS_LC_NACTS] = {
	[NS_ACT_NS_DELETE] = NVME_ERR_NS_UNALLOC,
	[NS_ACT_CTRL_ATTACH] = NVME_ERR_NS_UNALLOC,
	[NS_ACT_CTRL_DETACH] = NVME_ERR_NS_UNALLOC,
	[NS_ACT_BD_ATTACH] = NVME_ERR_NS_UNALLOC,
	[NS_ACT_BD_DETACH] = NVME_ERR_NS_UNALLOC
};

nvme_err_t nvme_alloc_errs[NS_LC_NACTS] = {
	[NS_ACT_NS_DELETE] = NVME_ERR_OK,
	[NS_ACT_CTRL_ATTACH] = NVME_ERR_OK,
	[NS_ACT_CTRL_DETACH] = NVME_ERR_NS_CTRL_NOT_ATTACHED,
	[NS_ACT_BD_ATTACH] = NVME_ERR_NS_CTRL_NOT_ATTACHED,
	[NS_ACT_BD_DETACH] = NVME_ERR_NS_CTRL_NOT_ATTACHED
};

nvme_err_t nvme_attach_errs[NS_LC_NACTS] = {
	[NS_ACT_NS_DELETE] = NVME_ERR_NS_CTRL_ATTACHED,
	[NS_ACT_CTRL_ATTACH] = NVME_ERR_NS_CTRL_ATTACHED,
	[NS_ACT_CTRL_DETACH] = NVME_ERR_OK,
	[NS_ACT_BD_ATTACH] = NVME_ERR_OK,
	[NS_ACT_BD_DETACH] = NVME_ERR_NS_CTRL_ATTACHED
};

nvme_err_t nvme_blkdev_errs[NS_LC_NACTS] = {
	[NS_ACT_NS_DELETE] = NVME_ERR_NS_BLKDEV_ATTACH,
	[NS_ACT_CTRL_ATTACH] = NVME_ERR_NS_BLKDEV_ATTACH,
	[NS_ACT_CTRL_DETACH] = NVME_ERR_NS_BLKDEV_ATTACH,
	[NS_ACT_BD_ATTACH] = NVME_ERR_NS_BLKDEV_ATTACH,
	[NS_ACT_BD_DETACH] = NVME_ERR_OK
};

static bool
ns_life_err_comp(nvme_ctrl_t *ctrl, nvme_err_t exp, nvme_err_t act,
    const char *desc, const char *state)
{
	if (act != exp) {
		warnx("TEST FAILED: %s in state %s returned %s (0x%x), but "
		    "expected %s (0x%x)", desc, state,
		    nvme_ctrl_errtostr(ctrl, act), act,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
	} else {
		(void) printf("TEST PASSED: %s in state %s correctly returned "
		    "%s\n", desc, state, nvme_ctrl_errtostr(ctrl, act));
	}

	return (act == exp);
}

static bool
ns_life_ns_delete(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_err_t exp,
    const char *state)
{
	nvme_err_t act;

	if (!libnvme_test_ns_delete(ctrl, nsid, &act)) {
		return (false);
	}

	return (ns_life_err_comp(ctrl, exp, act, "namespace delete", state));
}

static bool
ns_life_ctrl_attach(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_err_t exp,
    const char *state)
{
	nvme_err_t act;

	if (!libnvme_test_ctrl_attach(ctrl, nsid, NVME_NS_ATTACH_CTRL_ATTACH,
	    &act)) {
		return (false);
	}

	return (ns_life_err_comp(ctrl, exp, act, "controller attach", state));
}

static bool
ns_life_ctrl_detach(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_err_t exp,
    const char *state)
{
	nvme_err_t act;

	if (!libnvme_test_ctrl_attach(ctrl, nsid, NVME_NS_ATTACH_CTRL_DETACH,
	    &act)) {
		return (false);
	}

	return (ns_life_err_comp(ctrl, exp, act, "controller detach", state));
}

static bool
ns_life_blkdev_attach(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_err_t exp,
    const char *state)
{
	nvme_err_t act;

	if (!libnvme_test_ns_blkdev(ctrl, nsid, true, &act)) {
		return (false);
	}

	return (ns_life_err_comp(ctrl, exp, act, "blkdev attach", state));
}

static bool
ns_life_blkdev_detach(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_err_t exp,
    const char *state)
{
	nvme_err_t act;

	if (!libnvme_test_ns_blkdev(ctrl, nsid, false, &act)) {
		return (false);
	}

	return (ns_life_err_comp(ctrl, exp, act, "blkdev detach", state));
}

typedef bool (*ns_life_f)(nvme_ctrl_t *, uint32_t, nvme_err_t,
    const char *);

static const ns_life_f ns_lf_funcs[NS_LC_NACTS] = {
	[NS_ACT_NS_DELETE] = ns_life_ns_delete,
	[NS_ACT_CTRL_ATTACH] = ns_life_ctrl_attach,
	[NS_ACT_CTRL_DETACH] = ns_life_ctrl_detach,
	[NS_ACT_BD_ATTACH] = ns_life_blkdev_attach,
	[NS_ACT_BD_DETACH] = ns_life_blkdev_detach
};

typedef struct ns_life_test {
	nvme_ns_disc_level_t nlt_disc;
	const char *nlt_desc;
	nvme_err_t *nlt_errs;
	size_t nlt_nerrs;
} ns_life_test_t;

static const ns_life_test_t ns_life_tests[] = { {
	.nlt_disc = NVME_NS_DISC_F_ALL,
	.nlt_desc = "unallocated",
	.nlt_errs = nvme_unalloc_errs,
	.nlt_nerrs = ARRAY_SIZE(nvme_unalloc_errs)
}, {
	.nlt_disc = NVME_NS_DISC_F_ALLOCATED,
	.nlt_desc = "allocated",
	.nlt_errs = nvme_alloc_errs,
	.nlt_nerrs = ARRAY_SIZE(nvme_alloc_errs)
}, {
	.nlt_disc = NVME_NS_DISC_F_NOT_IGNORED,
	.nlt_desc = "active",
	.nlt_errs = nvme_attach_errs,
	.nlt_nerrs = ARRAY_SIZE(nvme_attach_errs)
}, {
	.nlt_disc = NVME_NS_DISC_F_BLKDEV,
	.nlt_desc = "blkdev",
	.nlt_errs = nvme_blkdev_errs,
	.nlt_nerrs = ARRAY_SIZE(nvme_blkdev_errs)
} };

static bool
ns_life_run_one(nvme_ctrl_t *ctrl, uint32_t lbaf, const ns_life_test_t *test)
{
	bool ret = true;

	for (size_t i = 0; i < test->nlt_nerrs; i++) {
		if (!libnvme_test_setup_ns(ctrl, test->nlt_disc, NS_LC_NSID,
		    lbaf)) {
			warnx("TEST FAILED: failed to transition ns to %s",
			    test->nlt_desc);
			ret = false;
		}

		if (!ns_lf_funcs[i](ctrl, NS_LC_NSID, test->nlt_errs[i],
		    test->nlt_desc)) {
			ret = false;
		}
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
	uint32_t lbaf;

	libnvme_test_init(&nvme, &ctrl);
	if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE, NVME_LOCK_F_DONT_BLOCK)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to obtain write lock");
	}

	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to get info snapshot");
	}

	if (!libnvme_test_lbaf(info, NVME_TEST_LBA_SIZE, &lbaf)) {
		errx(EXIT_FAILURE, "failed to find 4K LBA format, cannot "
		    "continue");
	}

	for (size_t i = 0; i < ARRAY_SIZE(ns_life_tests); i++) {
		if (!ns_life_run_one(ctrl, lbaf, &ns_life_tests[i]))
			ret = EXIT_FAILURE;
	}

	nvme_ctrl_info_free(info);
	nvme_ctrl_unlock(ctrl);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
