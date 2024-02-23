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
 * Iterate over the namespaces and ensure that the information we get in the
 * discovery is the same as when we take a snapshot. To ensure that nothing
 * changes out from under us, we take a controller write lock which will ensure
 * that no modifications can occur.
 *
 * In addition, we want to test that discovery filters work so we first go
 * through and count the different levels.
 */

#include <err.h>
#include <string.h>
#include <umem.h>

#include "libnvme_test_common.h"

static bool
ns_disc_count_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc, void *arg)
{
	uint32_t *valp = arg;
	*valp = *valp + 1;
	return (true);
}

static bool
ns_disc_count(nvme_ctrl_t *ctrl, nvme_ns_disc_level_t level, uint32_t exp)
{
	uint32_t count = 0;

	if (!nvme_ns_discover(ctrl, level, ns_disc_count_cb, &count)) {
		libnvme_test_ctrl_warn(ctrl, "failed to discover at level %u",
		    level);
		return (false);
	} else if (count != exp) {
		warnx("TEST FAILED: ns discovery level %u found 0x%x "
		    "namespaces, but expected 0x%x", level, count, exp);
		return (false);
	} else {
		(void) printf("TEST PASSED: ns discovery level %u had correct "
		    "count (0x%x)\n", level, exp);
		return (true);
	}
}

static bool
ns_disc_blkdev_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc, void *arg)
{
	int *ret = arg;
	nvme_ns_info_t *info;
	const uint32_t nsid = nvme_ns_disc_nsid(disc);
	const char *addr;

	if (nvme_ns_disc_level(disc) < NVME_NS_DISC_F_BLKDEV) {
		warnx("TEST FAILED: ns %u has level %u, but filtering on "
		    "blkdev (%u)", nsid, nvme_ns_disc_level(disc),
		    NVME_NS_DISC_F_BLKDEV);
		*ret = EXIT_FAILURE;
		return (true);
	}

	if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &info)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get info snapshot for "
		    "nsid %u", nsid);
		*ret = EXIT_FAILURE;
		return (true);
	}

	if (!nvme_ns_info_bd_addr(info, &addr)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get bd addr for nsid "
		    "%u", nsid);
		*ret = EXIT_FAILURE;
	} else if (addr[0] == '\0') {
		warnx("TEST FAILED: nsid %u has invalid bd addr", nsid);
		*ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: nsid %u bd addr valid\n", nsid);
	}

	nvme_ns_info_free(info);
	return (true);
}

static bool
ns_disc_guids_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc, void *arg)
{
	int *ret = arg;
	nvme_ns_info_t *info;
	const uint32_t nsid = nvme_ns_disc_nsid(disc);
	const nvme_ns_disc_flags_t flags = nvme_ns_disc_flags(disc);
	uint8_t id[16];
	bool bret;

	if (nvme_ns_disc_level(disc) < NVME_NS_DISC_F_ACTIVE) {
		warnx("TEST FAILED: ns %u has level %u, but filtering on "
		    "active (%u)", nsid, nvme_ns_disc_level(disc),
		    NVME_NS_DISC_F_ACTIVE);
		*ret = EXIT_FAILURE;
		return (true);
	}

	if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &info)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get info snapshot for "
		    "nsid %u", nsid);
		*ret = EXIT_FAILURE;
		return (true);
	}

	bret = nvme_ns_info_eui64(info, id);
	if (bret != ((flags & NVME_NS_DISC_F_EUI64_VALID) != 0)) {
		warnx("TEST FAILED: nvme_ns_info_eui64() returned %s, but "
		    "expected %s from discovery information for nsid %u",
		    bret ? "true" : "false",
		    (flags & NVME_NS_DISC_F_EUI64_VALID) != 0 ? "true" :
		    "false", nsid);
		*ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: namespace snapshot and discovery "
		    "agreed on EUI64 presence for nsid %u\n", nsid);
	}

	if (bret) {
		const uint8_t *eui64 = nvme_ns_disc_eui64(disc);
		const uint8_t zero[8] = { 0 };

		if (memcmp(eui64, id, sizeof (zero)) != 0) {
			warnx("TEST FAILED: EUI64 differs between "
			    "discovery and info snapshot for nsid %u", nsid);
			*ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: EUI64 equal between "
			    "discovery and info snapshot for nsid %u\n", nsid);
		}

		if (memcmp(id, zero, sizeof (zero)) == 0) {
			warnx("TEST FAILED: Found invalid zero EUI64 for nsid "
			    "%u", nsid);
			*ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: EUI64 is non-zero for "
			    "nsid %u\n", nsid);
		}
	} else {
		if (nvme_ns_disc_eui64(disc) != NULL) {
			warnx("TEST FAILED: discovery EUI64 was valid, but "
			    "should be NULL for nsid %u", nsid);
			*ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: discovery EUI64 correctly "
			    "returned NULL for nsid %u\n", nsid);
		}

		switch (nvme_ns_info_err(info)) {
		case NVME_INFO_ERR_VERSION:
		case NVME_INFO_ERR_MISSING_CAP:
			(void) printf("TEST PASSED: nvme_ns_info_eui64() "
			    "returned a valid error for nsid %u\n", nsid);
			break;
		default:
			warnx("TEST FAILED: nvme_ns_info_eui64() returned an "
			    "invalid error for nsid %u: %s (%u)", nsid,
			    nvme_ns_info_errtostr(info, nvme_ns_info_err(info)),
			    nvme_ns_info_err(info));
			*ret = EXIT_FAILURE;
			break;
		}
	}

	bret = nvme_ns_info_nguid(info, id);
	if (bret != ((flags & NVME_NS_DISC_F_NGUID_VALID) != 0)) {
		warnx("TEST FAILED: nvme_ns_info_nguid() returned %s, but "
		    "expected %s from discovery information for nsid %u",
		    bret ? "true" : "false",
		    (flags & NVME_NS_DISC_F_NGUID_VALID) != 0 ? "true" :
		    "false", nsid);
		*ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: namespace snapshot and discovery "
		    "agreed on NGUID presence for nsid %u\n", nsid);
	}

	if (bret) {
		const uint8_t *nguid = nvme_ns_disc_nguid(disc);
		const uint8_t zero[16] = { 0 };

		if (memcmp(nguid, id, sizeof (zero)) != 0) {
			warnx("TEST FAILED: NGUID differs between "
			    "discovery and info snapshot for nsid %u", nsid);
			*ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: NGUID equal between "
			    "discovery and info snapshot for nsid %u\n", nsid);
		}

		if (memcmp(id, zero, sizeof (zero)) == 0) {
			warnx("TEST FAILED: Found invalid zero NGUID for nsid "
			    "%u", nsid);
			*ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: NGUID is non-zero for "
			    "nsid %u\n", nsid);
		}
	} else {
		if (nvme_ns_disc_nguid(disc) != NULL) {
			warnx("TEST FAILED: discovery NGUID was valid, but "
			    "should be NULL for nsid %u", nsid);
			*ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: discovery NGUID correctly "
			    "returned NULL for nsid %u\n", nsid);
		}

		switch (nvme_ns_info_err(info)) {
		case NVME_INFO_ERR_VERSION:
		case NVME_INFO_ERR_MISSING_CAP:
			(void) printf("TEST PASSED: nvme_ns_info_nguid() "
			    "returned a valid error for nsid %u\n", nsid);
			break;
		default:
			warnx("TEST FAILED: nvme_ns_info_nguid() returned an "
			    "invalid error for nsid %u: %s (%u)", nsid,
			    nvme_ns_info_errtostr(info, nvme_ns_info_err(info)),
			    nvme_ns_info_err(info));
			*ret = EXIT_FAILURE;
			break;
		}
	}
	nvme_ns_info_free(info);
	return (true);
}

static bool
ns_disc_level_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc, void *arg)
{
	int *ret = arg;
	nvme_ns_info_t *info;
	const uint32_t nsid = nvme_ns_disc_nsid(disc);

	if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &info)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get info snapshot for "
		    "nsid %u", nsid);
		*ret = EXIT_FAILURE;
		return (true);
	}

	if (nvme_ns_disc_level(disc) != nvme_ns_info_level(info)) {
		warnx("TEST FAILED: discovery and ns info snapshot disagree "
		    "on discovery level: disc has %u, info has %u",
		    nvme_ns_disc_level(disc), nvme_ns_info_level(info));
		*ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: discovery and ns info snapshot "
		    "agree for nsid %u\n", nsid);
	}

	nvme_ns_info_free(info);
	return (true);
}

static bool
ns_disc_bad_disc_init(nvme_ctrl_t *ctrl, nvme_ns_disc_level_t level,
    nvme_ns_iter_t **iterp, nvme_err_t exp_err, const char *desc)
{
	if (nvme_ns_discover_init(ctrl, level, iterp)) {
		warnx("TEST FAILED: nvme_ns_discover_init() erroneously "
		    "passed despite %s", desc);
		nvme_ns_discover_fini(*iterp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_ns_discover_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ns_discover_init() failed "
		    "correctly for %s\n", desc);
		return (true);
	}
}

static bool
ns_disc_bad_disc(nvme_ctrl_t *ctrl, nvme_ns_disc_level_t level,
    nvme_ns_disc_f func, nvme_err_t exp_err, const char *desc)
{
	if (nvme_ns_discover(ctrl, level, func, NULL)) {
		warnx("TEST FAILED: nvme_ns_discover() erroneously "
		    "passed despite %s", desc);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_ns_discover() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ns_discover() failed "
		    "correctly for %s\n", desc);
		return (true);
	}
}

static bool
ns_disc_nop_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc, void *arg)
{
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_ctrl_info_t *info;
	nvme_iter_t iret;
	nvme_ns_iter_t *iter;
	const nvme_ns_disc_t *disc;
	uint32_t nbd = 0, nni = 0, nact = 0, nalloc = 0, nns = 0;

	libnvme_test_init(&nvme, &ctrl);
	if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE, NVME_LOCK_F_DONT_BLOCK)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to obtain write lock");
	}

	if (!nvme_ns_discover_init(ctrl, NVME_NS_DISC_F_ALL, &iter)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to initialize initial "
		    "ns discovery");
	}

	while ((iret = nvme_ns_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		switch (nvme_ns_disc_level(disc)) {
		case NVME_NS_DISC_F_BLKDEV:
			nbd++;
			/* FALLTHROUGH */
		case NVME_NS_DISC_F_NOT_IGNORED:
			nni++;
			/* FALLTHROUGH */
		case NVME_NS_DISC_F_ACTIVE:
			nact++;
			/* FALLTHROUGH */
		case NVME_NS_DISC_F_ALLOCATED:
			nalloc++;
			/* FALLTHROUGH */
		case NVME_NS_DISC_F_ALL:
			nns++;
			break;
		}
	}

	nvme_ns_discover_fini(iter);
	if (iret != NVME_ITER_DONE) {
		libnvme_test_ctrl_fatal(ctrl, "initial ns discovery failed");
	}

	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to get info snapshot");
	}

	if (nns != nvme_ctrl_info_nns(info)) {
		warnx("TEST FAILED: discovery found %u namespaces, but the "
		    "identify controller suggests there are %u", nns,
		    nvme_ctrl_info_nns(info));
	}

	if (!ns_disc_count(ctrl, NVME_NS_DISC_F_BLKDEV, nbd)) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_count(ctrl, NVME_NS_DISC_F_NOT_IGNORED, nni)) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_count(ctrl, NVME_NS_DISC_F_ACTIVE, nact)) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_count(ctrl, NVME_NS_DISC_F_ALLOCATED, nalloc)) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_count(ctrl, NVME_NS_DISC_F_ALL, nns)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * For anything that has a blkdev address, ensure that our info snapshot
	 * has a valid blkdev address.
	 */
	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_BLKDEV, ns_disc_blkdev_cb,
	    &ret)) {
		libnvme_test_ctrl_warn(ctrl, "discovery failed for blkdev "
		    "test");
		ret = EXIT_FAILURE;
	}

	/*
	 * For anything active, check if there are guids and that the
	 * information snapshot matches the same logic.
	 */
	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ACTIVE, ns_disc_guids_cb,
	    &ret)) {
		libnvme_test_ctrl_warn(ctrl, "discovery failed for guids "
		    "test");
		ret = EXIT_FAILURE;
	}

	/*
	 * For everything, make sure the levels match.
	 */
	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ALL, ns_disc_level_cb,
	    &ret)) {
		libnvme_test_ctrl_warn(ctrl, "discovery failed for levels "
		    "test");
		ret = EXIT_FAILURE;
	}

	nvme_ctrl_unlock(ctrl);

	if (!ns_disc_bad_disc_init(ctrl, INT32_MAX, &iter, NVME_ERR_BAD_FLAG,
	    "invalid level")) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_bad_disc_init(ctrl, NVME_NS_DISC_F_ALL, NULL,
	    NVME_ERR_BAD_PTR, "invalid iter pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_bad_disc(ctrl, UINT32_MAX, ns_disc_nop_cb,
	    NVME_ERR_BAD_FLAG, "invalid level")) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_bad_disc(ctrl, NVME_NS_DISC_F_ALL, NULL,
	    NVME_ERR_BAD_PTR, "invalid function pointer")) {
		ret = EXIT_FAILURE;
	}

	umem_setmtbf(1);
	if (!ns_disc_bad_disc_init(ctrl, NVME_NS_DISC_F_ALL, &iter,
	    NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!ns_disc_bad_disc(ctrl, NVME_NS_DISC_F_ALL, ns_disc_nop_cb,
	    NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}
	umem_setmtbf(0);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	nvme_ctrl_info_free(info);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);
	return (ret);
}
