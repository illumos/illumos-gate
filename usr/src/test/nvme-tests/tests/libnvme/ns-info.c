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
 * Test namespace information snapshots. Because devices are all different, we
 * mostly try to get a device's identify namespace and then compare that to the
 * fields we have here.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <umem.h>

#include "libnvme_test_common.h"

static bool
ns_info_test_inactive(nvme_ns_info_t *info, uint32_t nsid)
{
	uint8_t guid[16];
	bool ret = true;
	uint64_t val;
	const nvme_nvm_lba_fmt_t *fmt;
	const char *bd;

	if (nvme_ns_info_nguid(info, guid)) {
		warnx("TEST FAILED: ns %u returned a namespace guid in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_INACTIVE) {
		warnx("TEST FAILED: ns %u nvme_ns_info_nguid() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_INACTIVE "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_INACTIVE);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_nguid() "
		    "returned NVME_INFO_ERR_NS_INACTIVE\n", nsid);
	}

	if (nvme_ns_info_eui64(info, guid)) {
		warnx("TEST FAILED: ns %u returned a namespace eui64 in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_INACTIVE) {
		warnx("TEST FAILED: ns %u nvme_ns_info_eui64() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_INACTIVE "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_INACTIVE);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_eui64() "
		    "returned NVME_INFO_ERR_NS_INACTIVE\n", nsid);
	}

	if (nvme_ns_info_size(info, &val)) {
		warnx("TEST FAILED: ns %u returned a namespace size in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_INACTIVE) {
		warnx("TEST FAILED: ns %u nvme_ns_info_size() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_INACTIVE "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_INACTIVE);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_size() "
		    "returned NVME_INFO_ERR_NS_INACTIVE\n", nsid);
	}

	if (nvme_ns_info_cap(info, &val)) {
		warnx("TEST FAILED: ns %u returned a namespace cap in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_INACTIVE) {
		warnx("TEST FAILED: ns %u nvme_ns_info_cap() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_INACTIVE "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_INACTIVE);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_cap() "
		    "returned NVME_INFO_ERR_NS_INACTIVE\n", nsid);
	}

	if (nvme_ns_info_use(info, &val)) {
		warnx("TEST FAILED: ns %u returned a namespace use in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_INACTIVE) {
		warnx("TEST FAILED: ns %u nvme_ns_info_use() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_INACTIVE "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_INACTIVE);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_use() "
		    "returned NVME_INFO_ERR_NS_INACTIVE\n", nsid);
	}

	if (nvme_ns_info_curformat(info, &fmt)) {
		warnx("TEST FAILED: ns %u returned a current format in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_INACTIVE) {
		warnx("TEST FAILED: ns %u nvme_ns_info_curformat() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_INACTIVE "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_INACTIVE);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_curformat() "
		    "returned NVME_INFO_ERR_NS_INACTIVE\n", nsid);
	}

	if (nvme_ns_info_format(info, 0, &fmt)) {
		warnx("TEST FAILED: ns %u returned format 0 in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_INACTIVE) {
		warnx("TEST FAILED: ns %u nvme_ns_info_format() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_INACTIVE "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_INACTIVE);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_curformat() "
		    "returned NVME_INFO_ERR_NS_INACTIVE\n", nsid);
	}

	if (nvme_ns_info_bd_addr(info, &bd)) {
		warnx("TEST FAILED: ns %u returned a blkdev address in error",
		    nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_NS_NO_BLKDEV) {
		warnx("TEST FAILED: ns %u nvme_ns_info_bd_addr() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_NS_NO_BLKDEV "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_NS_NO_BLKDEV);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_curformat() "
		    "returned NVME_INFO_ERR_NS_NO_BLKDEV\n", nsid);
	}

	return (ret);
}

static bool
ns_info_test_size(nvme_ns_info_t *info,
    bool (*func)(nvme_ns_info_t *, uint64_t *), uint64_t exp_size,
    const char *name, uint32_t nsid)
{
	uint64_t val;

	if (!func(info, &val)) {
		libnvme_test_ns_info_warn(info, "ns %u nvme_ns_info_%s() "
		    "unexpected failed", nsid, name);
		return (false);
	} else if (val != exp_size) {
		warnx("TEST FAILED: ns %u: nvme_ns_info_%s() value was 0x%"
		    PRIx64 ", but expected 0x%" PRIx64, nsid, name, val,
		    exp_size);
		return (false);
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_%s() returned "
		    "correct value\n", nsid, name);
		return (true);
	}
}

static bool
ns_info_test(nvme_ctrl_t *ctrl, const nvme_version_t *vers, uint32_t nsid)
{
	bool ret = true;
	nvme_ns_t *ns = NULL;
	nvme_ns_info_t *info = NULL;
	nvme_ns_disc_level_t level;
	const nvme_identify_nsid_t *idns;
	const nvme_nvm_lba_fmt_t *fmt;
	uint32_t nfmt;

	/*
	 * We do this to test both ways of taking a snapshot.
	 */
	if ((nsid % 2) == 0) {
		if (!nvme_ns_init(ctrl, nsid, &ns)) {
			libnvme_test_ctrl_warn(ctrl, "failed to init ns %u",
			    nsid);
			ret = false;
			goto done;
		}

		if (!nvme_ns_info_snap(ns, &info)) {
			libnvme_test_ctrl_warn(ctrl, "failed to take snapshot "
			    "of ns %u", nsid);
			ret = false;
			goto done;
		}
	} else {
		if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &info)) {
			libnvme_test_ctrl_warn(ctrl, "failed to take snapshot "
			    "of ns %u", nsid);
			ret = false;
			goto done;
		}
	}

	(void) printf("TEST PASSED: ns %u: successfully got info snapshot\n",
	    nsid);
	if (nvme_ns_info_nsid(info) != nsid) {
		warnx("TEST FAILED: nsid %u info snapshot returned wrong "
		    "nsid: %u", nsid, nvme_ns_info_nsid(info));
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: info snapshot had correct "
		    "nsid\n", nsid);
	}

	/*
	 * The rest of the information snapshot APIs depend on if the namespace
	 * is active in the controller. If it is not, then we expect each
	 * function to fail. Even if we have an active namespace, this may fail
	 * if a controller isn't of a sufficient version.
	 */
	level = nvme_ns_info_level(info);
	if (level < NVME_NS_DISC_F_ACTIVE) {
		if (!ns_info_test_inactive(info, nsid)) {
			ret = false;
		}
		goto done;
	}

	idns = nvme_ns_info_identify(info);

	/*
	 * We don't explicitly test the GUID logic or blkdev address here. That
	 * is done in the ns-disc.c test.
	 */

	if (!ns_info_test_size(info, nvme_ns_info_size, idns->id_nsize, "size",
	    nsid)) {
		ret = false;
	}

	if (!ns_info_test_size(info, nvme_ns_info_cap, idns->id_ncap, "cap",
	    nsid)) {
		ret = false;
	}

	if (!ns_info_test_size(info, nvme_ns_info_use, idns->id_nuse, "use",
	    nsid)) {
		ret = false;
	}

	if (!nvme_ns_info_curformat(info, &fmt)) {
		libnvme_test_ns_info_warn(info, "ns %u failed to get current "
		    "format", nsid);
		ret = false;
	} else if (nvme_nvm_lba_fmt_id(fmt) != idns->id_flbas.lba_format) {
		warnx("TEST FAILED: current LBA format 0x%x does not match "
		    "identify namespace 0x%x", nvme_nvm_lba_fmt_id(fmt),
		    idns->id_flbas.lba_format);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_curformat() "
		    "returned correct format\n", nsid);
	}

	if (!nvme_ns_info_nformats(info, &nfmt)) {
		libnvme_test_ns_info_warn(info, "ns %u failed to get number "
		    "of formats", nsid);
		ret = false;
	} else if (nfmt != idns->id_nlbaf + 1) {
		warnx("TEST FAILED: number of LBA formats 0x%x does not match "
		    "identify namespace 0x%x", nvme_nvm_lba_fmt_id(fmt),
		    idns->id_nlbaf + 1);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: nvme_ns_info_nformats() "
		    "returned correct number of formats\n", nsid);
	}

	if (nvme_ns_info_format(info, 0x7777, &fmt)) {
		warnx("TEST FAILED: ns %u erroneously returned info for format "
		    "0x7777", nsid);
		ret = false;
	} else if (nvme_ns_info_err(info) != NVME_INFO_ERR_BAD_FMT) {
		warnx("TEST FAILED: ns %u nvme_ns_info_format() returned "
		    "wrong error %s (0x%x), not NVME_INFO_ERR_BAD_FMT "
		    "(0x%x)", nsid, nvme_ns_info_errtostr(info,
		    nvme_ns_info_err(info)), nvme_ns_info_err(info),
		    NVME_INFO_ERR_BAD_FMT);
		ret = false;
	} else {
		(void) printf("TEST PASSED: ns %u: invalid format id 0x7777 "
		    "correctly rejected\n", nsid);
	}

done:
	nvme_ns_info_free(info);
	nvme_ns_fini(ns);
	return (ret);
}

static bool
ns_info_bad_snap(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_ns_info_t **infop,
    nvme_err_t exp_err, const char *desc)
{
	if (nvme_ctrl_ns_info_snap(ctrl, nsid, infop)) {
		warnx("TEST FAILED: nvme_ctrl_ns_info_snap() erroneously "
		    "passed despite %s", desc);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_ctrl_ns_info_snap() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);

		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ctrl_ns_info_snap() failed "
		    "correctly for %s\n", desc);
		return (true);
	}
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_ctrl_info_t *info;
	nvme_ns_info_t *ns_info;
	uint32_t nns;
	const nvme_version_t *vers;

	libnvme_test_init(&nvme, &ctrl);

	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to take information "
		    "snapshot");
	}

	nns = nvme_ctrl_info_nns(info);
	if (nns == 0) {
		errx(EXIT_FAILURE, "TEST FAILED: somehow discovered 0 "
		    "namespaces");
	}

	vers = nvme_ctrl_info_version(info);
	for (uint32_t i = 1; i <= nns; i++) {
		if (!ns_info_test(ctrl, vers, i)) {
			ret = EXIT_FAILURE;
		}
	}

	/*
	 * Explicitly verify a few failures of namespace information snapshots.
	 */
	if (!ns_info_bad_snap(ctrl, NVME_NSID_BCAST, &ns_info,
	    NVME_ERR_NS_RANGE, "invalid nsid")) {
		ret = EXIT_FAILURE;
	}

	if (!ns_info_bad_snap(ctrl, 1, NULL, NVME_ERR_BAD_PTR,
	    "invalid output pointer")) {
		ret = EXIT_FAILURE;
	}

	umem_setmtbf(1);
	if (!ns_info_bad_snap(ctrl, 1, &ns_info, NVME_ERR_NO_MEM,
	    "no memory")) {
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
