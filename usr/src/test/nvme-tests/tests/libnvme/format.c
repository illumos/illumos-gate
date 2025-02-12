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
 * Test basic features around formatting namespaces and secure erase. In
 * particular we want to make sure that we can do the following:
 *
 *  - Format a single namespace
 *  - Broadcast format all active namespaces
 *  - Secure erase (whether broadcast or serially)
 *
 * We create two 1 GiB namespaces that we use for this. The namespace size
 * hopefully keeps format and secure erase timing reasonable. We end up writing
 * a message to sector 0 of each namespace to try to verify data was actually
 * erased.
 *
 * This test starts from the device-empty profile so we can control the size and
 * space of namespaces.
 */

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libdevinfo.h>
#include <fcntl.h>
#include <unistd.h>

#include "libnvme_test_common.h"

#define	NSID_BASE	1
#define	NNSIDS		2

/*
 * Because we use the raw block device, our size needs to be a multiple of both
 * of the sector sizes we use (4k, 512), which gives us a 4k buffer.
 */
#define	FMT_BUF_SIZE	4096

static const char *format_msgs[NNSIDS] = {
	"Those Who Fight Further",
	"Those Who Deny the Dawn"
};

/*
 * Check the results of a format / erase namespace and verify that our old data
 * is gone. Write new data.
 */
static bool
format_io_verify(int fd, uint32_t nsid)
{
	uint8_t buf[FMT_BUF_SIZE];
	const char *msg = format_msgs[nsid - 1];
	size_t msglen = strlen(msg) + 1;

	if (pread(fd, buf, sizeof (buf), 0) != sizeof (buf)) {
		warn("TEST FAILED: failed to read from nsid %u", nsid);
		return (false);
	}

	/*
	 * These contents should never match our message.
	 */
	if (memcmp(buf, msg, msglen) != 0) {
		(void) printf("TEST PASSED: namespace %u data successfully "
		    "cleared\n", nsid);
	} else {
		warnx("TEST FAILED: nsid %u data was not successfully erased",
		    nsid);
		(void) printf("Unexpected data: found\n");
		for (size_t i = 0; i < msglen; i++) {
			(void) printf("buf[%u]: %02x\n", i, buf[i]);
		}

		return (false);
	}

	(void) memset(buf, 0x77, sizeof (buf));
	(void) memcpy(buf, msg, msglen);
	if (pwrite(fd, buf, sizeof (buf), 0) != sizeof (buf)) {
		warnx("TEST FAILED: failed to write updated buffer to nsid "
		    "%u", nsid);
		return (false);
	}

	if (fsync(fd) != 0) {
		warn("TEST FAILED: failed to synchronize raw device write "
		    "to ns %u", nsid);
	}

	(void) memset(buf, 0, sizeof (buf));
	if (pread(fd, buf, sizeof (buf), 0) != sizeof (buf)) {
		warnx("TEST FAILED: failed to read back data written to %u",
		    nsid);
		return (false);
	}

	if (memcmp(buf, msg, msglen) != 0) {
		warnx("TEST FAILED: did not get back data written to nsid %u",
		    nsid);
		(void) printf("Mismatched data: found/expected\n");
		for (size_t i = 0; i < msglen; i++) {
			(void) printf("buf[%u]: %02x/%02x\n", i, buf[i],
			    msg[i]);
		}
		return (false);
	}

	(void) printf("TEST PASSED: successfully wrote message to nsid %u\n",
	    nsid);
	return (true);
}

/*
 * Used after another namespace has been formatted to check that the other is
 * still okay and its data hasn't been overwritten.
 */
static bool
format_io_check(int fd, uint32_t nsid)
{
	uint8_t buf[FMT_BUF_SIZE];
	const char *msg = format_msgs[nsid - 1];
	size_t msglen = strlen(msg) + 1;

	if (pread(fd, buf, sizeof (buf), 0) != sizeof (buf)) {
		warnx("TEST FAILED: failed to read back data on nsid %u",
		    nsid);
		return (false);
	}

	if (memcmp(buf, msg, msglen) != 0) {
		warnx("TEST FAILED: data on nsid %u changed after format of "
		    "other namespace", nsid);
		(void) printf("Mismatched data: found/expected\n");
		for (size_t i = 0; i < msglen; i++) {
			(void) printf("buf[%u]: %02x/%02x\n", i, buf[i],
			    msg[i]);
		}
		return (false);
	}

	(void) printf("TEST PASSED: verified prior message on nsid %u\n",
	    nsid);
	return (true);
}

/*
 * Get the file descripto that corresponds to the raw whole disk device which is
 * generally s2 or 'c,raw'.
 */
static int
format_blkdev_fd(const char *bd_addr)
{
	int fd = -1;
	di_node_t root;

	root = di_init("/", DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		warnx("failed to take devinfo snapshot");
		return (-1);
	}

	for (di_node_t n = di_drv_first_node("blkdev", root); n != DI_NODE_NIL;
	    n = di_drv_next_node(n)) {
		char *devfs, path[PATH_MAX];
		const char *addr = di_bus_addr(n);

		if (addr == NULL) {
			continue;
		}

		if (strcmp(bd_addr, addr) != 0)
			continue;

		devfs = di_devfs_path(n);
		if (devfs == NULL) {
			warn("failed to get devfs path for blkdev %s", bd_addr);
			goto out;
		}

		if (snprintf(path, sizeof (path), "/devices/%s:c,raw", devfs) >=
		    sizeof (path)) {
			di_devfs_path_free(devfs);
			warnx("Construction of blkdev %s minor path exceeded "
			    "internal buffer", bd_addr);
			goto out;
		}

		/*
		 * We need to use O_NDELAY here to convince the system that it's
		 * okay that there isn't valid CMLB information yet, which is
		 * fine because we're trashing this device.
		 */
		di_devfs_path_free(devfs);
		fd = open(path, O_RDWR | O_NDELAY);
		if (fd < 0) {
			warn("failed to open %s", path);
			goto out;
		}
	}

	if (fd == -1) {
		warnx("failed to find di_node_t that matches %s", bd_addr);
	}

out:
	di_fini(root);
	return (fd);
}

/*
 * Leave a message in sector 0 of each device that we can later verify is there
 * or not.
 */
static bool
format_nsid_io(nvme_ctrl_t *ctrl, uint32_t nsid, bool (*cb)(int, uint32_t))
{
	int fd;
	nvme_ns_info_t *ns = NULL;
	const char *bd_addr;
	bool ret = false;

	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_BLKDEV, nsid,
	    UINT32_MAX)) {
		libnvme_test_ctrl_warn(ctrl, "failed to attach blkdev to "
		    "nsid %u", nsid);
		return (false);
	}

	if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &ns)) {
		libnvme_test_ctrl_warn(ctrl, "failed to take namespace %u "
		    "info snapshot", nsid);
		goto out;
	}

	if (!nvme_ns_info_bd_addr(ns, &bd_addr)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get blkdev address "
		    "for namespace %u", nsid);
		goto out;
	}

	if ((fd = format_blkdev_fd(bd_addr)) < 0) {
		warnx("TEST FAILED: failed to acquire blkdev fd for nsid %u "
		    "to write data", nsid);
		goto out;
	}

	ret = cb(fd, nsid);
	VERIFY0(close(fd));

out:
	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_NOT_IGNORED, nsid,
	    UINT32_MAX)) {
		libnvme_test_ctrl_warn(ctrl, "failed to detach blkdev from "
		    "nsid %u", nsid);
		ret = false;
	}

	nvme_ns_info_free(ns);
	return (ret);
}

/*
 * Verify that a given namespace has the expected LBA format.
 */
static bool
format_check_lbaf(nvme_ctrl_t *ctrl, uint32_t nsid, uint32_t lbaf)
{
	bool ret = false;
	nvme_ns_info_t *info;
	const nvme_nvm_lba_fmt_t *lba;

	if (!nvme_ctrl_ns_info_snap(ctrl, nsid, &info)) {
		libnvme_test_ctrl_warn(ctrl, "failed to take namespace %u "
		    "info snapshot", nsid);
		return (false);
	}

	if (!nvme_ns_info_curformat(info, &lba)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get namespace %u "
		    "current lba format", nsid);
		goto out;
	}

	if (nvme_nvm_lba_fmt_id(lba) == lbaf) {
		(void) printf("TEST PASSED: Succesfully formatted namespace %u "
		    "to format %u (0x%" PRIx64 ")\n", nsid, lbaf,
		    nvme_nvm_lba_fmt_data_size(lba));
		ret = true;
	} else {
		warnx("TEST FAILED: Formatted namespace %u ended up with LBA "
		    "format %u (0x%" PRIx64 " bytes), not %u", nsid,
		    nvme_nvm_lba_fmt_id(lba), nvme_nvm_lba_fmt_data_size(lba),
		    lbaf);
	}

out:
	nvme_ns_info_free(info);
	return (ret);
}

static bool
format_ns(nvme_ctrl_t *ctrl, uint32_t nsid, uint32_t ses, uint32_t lbaf)
{
	bool ret = true;
	nvme_format_req_t *req;

	if (!nvme_format_req_init(ctrl, &req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize format "
		    "request");
		ret = false;
		goto done;
	}

	if (!nvme_format_req_set_lbaf(req, lbaf)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set format lbaf to "
		    "0x%x", lbaf);
		ret = false;
		goto done;
	}

	if (!nvme_format_req_set_ses(req, ses)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set format ses to 0x%x",
		    ses);
		ret = false;
		goto done;
	}

	if (!nvme_format_req_set_nsid(req, nsid)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set format nsid to "
		    "0x%x", nsid);
		ret = false;
		goto done;
	}

	if (!nvme_format_req_exec(req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to execute format "
		    "namespace for nsid %u", nsid);
		ret = false;
		goto done;
	}

	for (uint32_t i = 0; i < NNSIDS; i++) {
		if (nsid == NVME_NSID_BCAST || nsid == (NSID_BASE + i)) {
			if (!format_check_lbaf(ctrl, NSID_BASE + i, lbaf)) {
				ret = false;
			}
		}
	}

done:
	nvme_format_req_fini(req);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_ctrl_info_t *info;
	uint32_t lbaf_4k, lbaf_512, ses;
	const nvme_identify_ctrl_t *id;

	libnvme_test_init(&nvme, &ctrl);
	if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE, NVME_LOCK_F_DONT_BLOCK)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to obtain write lock");
	}

	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to get info snapshot");
	}

	if (!libnvme_test_lbaf(info, 4096, &lbaf_4k)) {
		errx(EXIT_FAILURE, "failed to find 4K LBA format, cannot "
		    "continue");
	}

	if (!libnvme_test_lbaf(info, 512, &lbaf_512)) {
		errx(EXIT_FAILURE, "failed to find 512 byte LBA format, cannot "
		    "continue");
	}
	(void) printf("LBA indexes: 512/4k %u/%u\n", lbaf_512, lbaf_4k);

	/*
	 * Start by creating a single 512 byte namespace. We only create a
	 * single one for now because we expect that many devices don't like
	 * having namespaces with different LBA formats despite indicating in
	 * the format NVM attributes that namespaces are independent.
	 */
	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_ACTIVE, 1, lbaf_512)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to create initial "
		    "namespaces");
	}

	/*
	 * Because the namespaces was created as part of this (we assume we
	 * started from the empty device-reset profile), nothing should be here.
	 */
	if (!format_nsid_io(ctrl, 1, format_io_verify))
		ret = EXIT_FAILURE;

	/*
	 * Format it to itself and make sure that data is gone.
	 */
	if (!format_ns(ctrl, 1, NVME_FRMT_SES_NONE, lbaf_512))
		ret = EXIT_FAILURE;

	if (!format_nsid_io(ctrl, 1, format_io_verify))
		ret = EXIT_FAILURE;

	/*
	 * Transform it to 4K now.
	 */
	if (!format_ns(ctrl, 1, NVME_FRMT_SES_NONE, lbaf_4k))
		ret = EXIT_FAILURE;
	if (!format_nsid_io(ctrl, 1, format_io_verify))
		ret = EXIT_FAILURE;

	/*
	 * Now create a second namespace. At this point we are constrained to
	 * 4k.
	 */
	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_ACTIVE, 2, lbaf_4k)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to create second "
		    "namespace");
	}

	if (!format_nsid_io(ctrl, 2, format_io_verify))
		ret = EXIT_FAILURE;
	if (!format_nsid_io(ctrl, 1, format_io_check))
		ret = EXIT_FAILURE;

	/*
	 * Now reformat 1 and make sure its data is gone and 2's data is intact.
	 */
	if (!format_ns(ctrl, 2, NVME_FRMT_SES_NONE, lbaf_4k))
		ret = EXIT_FAILURE;
	if (!format_nsid_io(ctrl, 1, format_io_check))
		ret = EXIT_FAILURE;
	if (!format_nsid_io(ctrl, 2, format_io_verify))
		ret = EXIT_FAILURE;

	/*
	 * Perform a broadcast format back to 512.
	 */
	if (!format_ns(ctrl, NVME_NSID_BCAST, NVME_FRMT_SES_NONE, lbaf_512))
		ret = EXIT_FAILURE;

	if (!format_nsid_io(ctrl, 1, format_io_verify))
		ret = EXIT_FAILURE;
	if (!format_nsid_io(ctrl, 2, format_io_verify))
		ret = EXIT_FAILURE;

	/*
	 * All devices that support format in theory support secure-erase. Check
	 * to see if they support cryptographic secure erase as that should
	 * speed things up due to per-key usage. Secure erase may only work
	 * globally or operate per-namespace. Regardless of this, we assume that
	 * if we're changing the format, that has to be done globally.
	 */
	id = nvme_ctrl_info_identify(info);
	if (id->id_fna.fn_crypt_erase != 0) {
		ses = NVME_FRMT_SES_CRYPTO;
	} else {
		ses = NVME_FRMT_SES_USER;
	}

	if (!format_ns(ctrl, NVME_NSID_BCAST, ses, lbaf_4k))
		ret = EXIT_FAILURE;
	if (!format_nsid_io(ctrl, 1, format_io_verify))
		ret = EXIT_FAILURE;
	if (!format_nsid_io(ctrl, 2, format_io_verify))
		ret = EXIT_FAILURE;

	if (id->id_fna.fn_sec_erase == 0) {
		if (!format_ns(ctrl, 1, ses, lbaf_4k))
			ret = EXIT_FAILURE;
		if (!format_nsid_io(ctrl, 2, format_io_check))
			ret = EXIT_FAILURE;
		if (!format_nsid_io(ctrl, 1, format_io_verify))
			ret = EXIT_FAILURE;

		if (!format_ns(ctrl, 2, ses, lbaf_4k))
			ret = EXIT_FAILURE;
		if (!format_nsid_io(ctrl, 2, format_io_verify))
			ret = EXIT_FAILURE;
		if (!format_nsid_io(ctrl, 1, format_io_check))
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
