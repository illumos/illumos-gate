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
 * This program is used to check everything about a device before we continue
 * execution.
 *
 * 1) We will check that there are no blkdev attached namespaces. That is it is
 * up to the user of this program to ensure that this is already the case. This
 * helps make sure that we don't end up in an awkward spot with tests that issue
 * blkdev detaches and related.
 *
 * 2) We will verify that the device supports namespace management and format
 * commands. All of our destructive tests require this.
 *
 * 3) After doing this, we will confirm with the user that this is explicitly
 * what they asked for!
 */

#include <err.h>
#include <string.h>
#include <pcidb.h>
#include "libnvme_test_common.h"

static bool
check_blkdev_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc, void *arg)
{
	if (nvme_ns_disc_level(disc) < NVME_NS_DISC_F_BLKDEV) {
		return (true);
	}

	(void) fprintf(stderr, "\nDevice not suitable: Encountered blkdev "
	    "on namespace %u\n", nvme_ns_disc_nsid(disc));

	(void) fprintf(stderr, "\nThis test will erase all data found on the "
	    "requested device! To\nindicate that you intend to use this device "
	    "for destructive testing,\nyou must manually detach blkdev from "
	    "all namespaces on this device!\n\nALL DATA ON THIS DEVICE WILL BE "
	    "LOST!\n");
	exit(EXIT_FAILURE);
}

static void
check_feats(nvme_ctrl_info_t *info)
{
	const nvme_version_t *vers = nvme_ctrl_info_version(info);
	const nvme_identify_ctrl_t *id = nvme_ctrl_info_identify(info);

	(void) printf("NVMe Version: %u.%u\n", vers->v_major, vers->v_minor);

	if (!NVME_VERSION_ATLEAST(vers, 1, 2)) {
		(void) fprintf(stderr, "\nDevice not suitable: device revision "
		    "must be at least NVMe 1.2\nto support NVMe namespace "
		    "management! Namespace management is required for "
		    "destructive tests!");
		exit(EXIT_FAILURE);
	}

	(void) printf("Format NVM: %s\n", id->id_oacs.oa_format != 0 ?
	    "supported" : "unsupported");
	(void) printf("Namespace Management: %s\n", id->id_oacs.oa_nsmgmt ?
	    "supported" : "unsupported");

	if (id->id_oacs.oa_format == 0 || id->id_oacs.oa_nsmgmt == 0) {
		(void) fprintf(stderr, "\nDevice not suitable: missing "
		    "required command set support!\nPlease pick another "
		    "device.\n");
		exit(EXIT_FAILURE);
	}

	(void) printf("Namespace Count: %u\n", id->id_nn);
	if (id->id_nn <= 1) {
		(void) fprintf(stderr, "\nDevice not suitable: at least "
		    "two namespaces required!\nPlease pick another "
		    "device.\n");
		exit(EXIT_FAILURE);
	}
}

int
main(void)
{
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_ctrl_info_t *info;
	pcidb_hdl_t *pcidb;
	pcidb_vendor_t *vendor;
	char buf[64];

	if ((pcidb = pcidb_open(PCIDB_VERSION)) == NULL) {
		err(EXIT_FAILURE, "failed to initialize PCI DB handle");
	}

	libnvme_test_init(&nvme, &ctrl);
	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to get controller "
		    "information snapshot");
	}

	(void) printf("Checking NVMe device %s for destructive test "
	    "suitability\n", getenv(NVME_TEST_DEV_ENVVAR));
	vendor = pcidb_lookup_vendor(pcidb, nvme_ctrl_info_vendor(info));
	if (vendor != NULL) {
		(void) printf("Vendor: %s (0x%x)\n", pcidb_vendor_name(vendor),
		    nvme_ctrl_info_vendor(info));
	} else {
		(void) printf("Vendor ID: 0x%x\n", nvme_ctrl_info_vendor(info));
	}
	(void) printf("Model: %s\n", nvme_ctrl_info_model(info));
	(void) printf("Serial: %s\n", nvme_ctrl_info_serial(info));
	(void) printf("Firmware Revision: %s\n", nvme_ctrl_info_fwrev(info));

	if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE, NVME_LOCK_F_DONT_BLOCK)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to obtain write lock");
	}

	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ALL, check_blkdev_cb,
	    NULL)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to discover namespaces");
	}

	check_feats(info);

	(void) printf("\nALL DATA ON THE ABOVE DEVICE WILL BE LOST!!\n");
	(void) printf("Continue [yes/No]: ");
	(void) fflush(stdout);
	if (fgets(buf, sizeof (buf), stdin) == NULL) {
		errx(EXIT_FAILURE, "aborting: failed to read from stdin\n");
	}

	if (strcmp(buf, "yes\n") != 0) {
		(void) printf("Aborting on user request\n");
		exit(EXIT_FAILURE);
	}

	nvme_ctrl_info_free(info);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);
	return (EXIT_SUCCESS);
}
