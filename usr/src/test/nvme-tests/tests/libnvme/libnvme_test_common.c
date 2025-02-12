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
 * Common utilities for libnvme tests.
 */

#include <err.h>
#include <stdlib.h>
#include <time.h>

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

bool
libnvme_test_lbaf(nvme_ctrl_info_t *info, uint32_t size, uint32_t *lbap)
{
	uint32_t nfmts, fmt = UINT32_MAX, fmt_rp = UINT32_MAX;

	nfmts = nvme_ctrl_info_nformats(info);
	if (nfmts == 0) {
		warnx("no LBA formats found on device");
		return (false);
	}

	for (uint32_t i = 0; i < nfmts; i++) {
		const nvme_nvm_lba_fmt_t *lba;
		uint32_t rp;

		if (!nvme_ctrl_info_format(info, i, &lba)) {
			libnvme_test_ctrl_info_warn(info, "failed to get LBA "
			    "format %u", i);
			continue;
		}

		if (nvme_nvm_lba_fmt_meta_size(lba) != 0)
			continue;

		if (nvme_nvm_lba_fmt_data_size(lba) != size)
			continue;

		rp = nvme_nvm_lba_fmt_rel_perf(lba);
		if (rp < fmt_rp) {
			fmt = i;
			fmt_rp = rp;
		}
	}

	if (fmt != UINT32_MAX) {
		*lbap = fmt;
		return (true);
	}

	return (false);
}

bool
libnvme_test_ns_create(nvme_ctrl_t *ctrl, uint64_t size, uint32_t lbaf,
    uint32_t *nsid, nvme_err_t *err)
{
	nvme_ns_create_req_t *req;
	bool ret = false;

	if (!nvme_ns_create_req_init_by_csi(ctrl, NVME_CSI_NVM, &req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize namespace "
		    "create request");
		goto done;
	}

	if (!nvme_ns_create_req_set_flbas(req, lbaf)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set flbas for "
		    "namespace create request to 0x%x", lbaf);
		goto done;
	}

	if (!nvme_ns_create_req_set_nsze(req, size)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set nsze for "
		    "namespace create request to 0x%" PRIx64, size);
		goto done;
	}

	if (!nvme_ns_create_req_set_ncap(req, size)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set ncap for "
		    "namespace create request to 0x%" PRIx64, size);
		goto done;
	}

	if (!nvme_ns_create_req_set_nmic(req, NVME_NS_NMIC_T_NONE)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set nmic for "
		    "namespace create request");
		goto done;
	}

	ret = nvme_ns_create_req_exec(req);
	if (err != NULL) {
		*err = nvme_ctrl_err(ctrl);
		ret = true;
		if (*err != NVME_ERR_OK)
			goto done;
	} else if (!ret) {
		libnvme_test_ctrl_warn(ctrl, "failed to execute namespace "
		    "create request");
		goto done;
	}

	if (nsid != NULL) {
		ret = nvme_ns_create_req_get_nsid(req, nsid);
		if (!ret) {
			libnvme_test_ctrl_warn(ctrl, "failed to retrieve "
			    "created namespace id");
		}
	}

done:
	nvme_ns_create_req_fini(req);
	return (ret);
}

bool
libnvme_test_ns_delete(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_err_t *err)
{
	bool ret = true;
	nvme_ns_delete_req_t *req;

	if (!nvme_ns_delete_req_init(ctrl, &req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize namespace "
		    "delete request for namespace %u", nsid);
		return (false);
	}

	if (!nvme_ns_delete_req_set_nsid(req, nsid)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set namespace for "
		    "ns %u delete request", nsid);
		ret = false;
		goto done;
	}

	ret = nvme_ns_delete_req_exec(req);
	if (err != NULL) {
		*err = nvme_ctrl_err(ctrl);
		ret = true;
	} else if (!ret) {
		libnvme_test_ctrl_warn(ctrl, "failed to execute namespace "
		    "delete request for namespace %u", nsid);
	}

done:
	nvme_ns_delete_req_fini(req);
	return (ret);
}

bool
libnvme_test_ctrl_attach(nvme_ctrl_t *ctrl, uint32_t nsid, uint32_t type,
    nvme_err_t *err)
{
	nvme_ns_attach_req_t *req = NULL;
	const char *desc;
	bool ret = true;

	VERIFY(type == NVME_NS_ATTACH_CTRL_DETACH ||
	    type == NVME_NS_ATTACH_CTRL_ATTACH);
	if (type == NVME_NS_ATTACH_CTRL_DETACH) {
		desc = "detach";
	} else {
		desc = "attach";
	}

	if (!nvme_ns_attach_req_init_by_sel(ctrl, type, &req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize controller "
		    "%s request for ns 0x%x", desc, nsid);
		ret = false;
		goto done;
	}

	if (!nvme_ns_attach_req_set_nsid(req, nsid)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set namespace for "
		    "ns 0x%x controller %s request", nsid, desc);
		ret = false;
		goto done;
	}

	if (!nvme_ns_attach_req_set_ctrlid_self(req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set controller for "
		    "ns 0x%x controller %s request", nsid, desc);
		ret = false;
		goto done;

	}

	ret = nvme_ns_attach_req_exec(req);
	if (err != NULL) {
		*err = nvme_ctrl_err(ctrl);
		ret = true;
	} else if (!ret) {
		libnvme_test_ctrl_warn(ctrl, "failed to execute controller "
		    "%s request for ns 0x%x", desc, nsid);
	}

done:
	nvme_ns_attach_req_fini(req);
	return (ret);
}

bool
libnvme_test_ns_blkdev(nvme_ctrl_t *ctrl, uint32_t nsid, bool attach,
    nvme_err_t *err)
{
	nvme_ns_t *ns;
	bool ret;

	if (!nvme_ns_init(ctrl, nsid, &ns)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize namespace "
		    "%u", nsid);
		return (false);
	}

	if (attach) {
		ret = nvme_ns_bd_attach(ns);
	} else {
		/*
		 * Occasionally we've seen a race on blkdev detach during tests
		 * where we have what is most likely a transient reference. If
		 * we get that the kernel failed to detach, try up to 5 times
		 * and wait 10ms between attempts to just smooth it over.
		 */
		for (uint32_t i = 0; i < 5; i++) {
			struct timespec t;

			ret = nvme_ns_bd_detach(ns);
			if (ret || nvme_ctrl_err(ctrl) !=
			    NVME_ERR_DETACH_KERN) {
				break;
			}

			t.tv_sec = 0;
			t.tv_nsec = MSEC2NSEC(10);
			(void) nanosleep(&t, NULL);
		}
	}

	if (err != NULL) {
		*err = nvme_ctrl_err(ctrl);
		ret = true;
	} else if (!ret) {
		libnvme_test_ctrl_warn(ctrl, "failed to %s namespace %u",
		    attach ? "attach" : "detach", nsid);
	}
	nvme_ns_fini(ns);

	return (ret);
}

/*
 * Non-fatally ensure that the requested NS is in the state that is asked for.
 * We assume that the caller already has a lock on the device.
 */
bool
libnvme_test_setup_ns(nvme_ctrl_t *ctrl, nvme_ns_disc_level_t level,
    uint32_t nsid, uint32_t lbaf)
{
	nvme_ns_info_t *info;
	nvme_ns_disc_level_t cur;
	uint32_t nsid_out;
	uint64_t create_size = NVME_TEST_NS_SIZE / NVME_TEST_LBA_SIZE;

	if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &info)) {
		libnvme_test_ctrl_warn(ctrl, "failed to take snapshot of "
		    "namespace %u", nsid);
		return (false);
	}
	cur = nvme_ns_info_level(info);
	nvme_ns_info_free(info);

	/*
	 * Whether we end up active or not ignored is basically dependent on
	 * device data. Tests that care ultimately need to check themselves.
	 */
	if (level == NVME_NS_DISC_F_NOT_IGNORED)
		level = NVME_NS_DISC_F_ACTIVE;

	while (cur > level) {
		switch (cur) {
		case NVME_NS_DISC_F_BLKDEV:
			if (!libnvme_test_ns_blkdev(ctrl, nsid, false, NULL)) {
				return (false);
			}
			cur = NVME_NS_DISC_F_NOT_IGNORED;
			break;
		case NVME_NS_DISC_F_NOT_IGNORED:
		case NVME_NS_DISC_F_ACTIVE:
			if (!libnvme_test_ctrl_attach(ctrl, nsid,
			    NVME_NS_ATTACH_CTRL_DETACH, NULL)) {
				return (false);
			}
			cur = NVME_NS_DISC_F_ALLOCATED;
			break;
		case NVME_NS_DISC_F_ALLOCATED:
			if (!libnvme_test_ns_delete(ctrl, nsid, NULL)) {
				return (false);
			}
			cur = NVME_NS_DISC_F_ALL;
			break;

		case NVME_NS_DISC_F_ALL:
			abort();
		}
	}

	while (cur < level) {
		switch (cur) {
		case NVME_NS_DISC_F_BLKDEV:
			abort();
		case NVME_NS_DISC_F_NOT_IGNORED:
		case NVME_NS_DISC_F_ACTIVE:
			if (!libnvme_test_ns_blkdev(ctrl, nsid, true, NULL)) {
				return (false);
			}
			cur = NVME_NS_DISC_F_BLKDEV;
			break;
		case NVME_NS_DISC_F_ALLOCATED:
			if (!libnvme_test_ctrl_attach(ctrl, nsid,
			    NVME_NS_ATTACH_CTRL_ATTACH, NULL)) {
				return (false);
			}
			cur = NVME_NS_DISC_F_ACTIVE;
			break;
		case NVME_NS_DISC_F_ALL:
			if (!libnvme_test_ns_create(ctrl, create_size, lbaf,
			    &nsid_out, NULL)) {
				return (false);
			}

			if (nsid_out != nsid) {
				warnx("namespace creation resulted in NSID "
				    "%u, but expected %u to be created", nsid,
				    nsid_out);
				return (false);
			}

			cur = NVME_NS_DISC_F_ALLOCATED;
			break;
		}
	}

	return (true);
}

bool
libnvme_test_ctrl_err(nvme_ctrl_t *ctrl, uint32_t exp_sct, uint32_t exp_sc,
    const char *desc)
{
	uint32_t sct, sc;
	nvme_err_t err = nvme_ctrl_err(ctrl);

	if (err != NVME_ERR_CONTROLLER) {
		warnx("TEST FAILED: %s: got wrong error: found "
		    "%s (0x%x), not NVME_ERR_CONTROLLER (0x%x)",
		    desc, nvme_ctrl_errtostr(ctrl, err), err,
		    NVME_ERR_CONTROLLER);
		return (false);
	}

	nvme_ctrl_deverr(ctrl, &sct, &sc);
	if (sct != exp_sct && sc != exp_sc) {
		warnx("TEST FAILED: %s: got incorrect controller error: found "
		    "%s/%s (0x%x/0x%x), but expected %s/%s (0x%x/0x%x)", desc,
		    nvme_scttostr(ctrl, sct),
		    nvme_sctostr(ctrl, NVME_CSI_NVM, sct, sc), sct, sc,
		    nvme_scttostr(ctrl, exp_sct),
		    nvme_sctostr(ctrl, NVME_CSI_NVM, exp_sct, exp_sc), exp_sct,
		    exp_sc);
		return (false);
	}

	(void) printf("TEST PASSED: %s: got correct controller error\n", desc);
	return (true);
}
