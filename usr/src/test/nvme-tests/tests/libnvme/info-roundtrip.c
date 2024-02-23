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
 * Take a controller snapshot. Roundtrip it through a save and restore and make
 * sure that all the data is the same across the two.
 */

#include <err.h>
#include <string.h>

#include "libnvme_test_common.h"

static bool
info_roundtrip_pci(nvme_ctrl_info_t *info, nvme_ctrl_info_t *rest_info)
{
	bool ret = true;
	uint32_t id32, rest_id32;
	uint16_t id16, rest_id16;
	uint8_t id8, rest_id8;

	if (!nvme_ctrl_info_pci_vid(info, &id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI vendor "
		    "from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_vid(rest_info, &rest_id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI vendor "
		    "from restored snapshot");
		ret = false;
	} else if (id16 != rest_id16) {
		warnx("TEST FAILED: PCI vendor mismatch: was %u now %u",
		    id16, rest_id16);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI vendor successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_pci_did(info, &id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI device "
		    "from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_did(rest_info, &rest_id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI device "
		    "from restored snapshot");
		ret = false;
	} else if (id16 != rest_id16) {
		warnx("TEST FAILED: PCI device mismatch: was %u now %u",
		    id16, rest_id16);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI device successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_pci_subvid(info, &id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI subsystem "
		    "vendor from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_subvid(rest_info, &rest_id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI subsystem "
		    "vendor from restored snapshot");
		ret = false;
	} else if (id16 != rest_id16) {
		warnx("TEST FAILED: PCI subsystem vendor mismatch: was %u "
		    "now %u", id16, rest_id16);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI subsystem vendor successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_pci_subsys(info, &id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI subsystem "
		    "id from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_subsys(rest_info, &rest_id16)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI subsystem "
		    "id from restored snapshot");
		ret = false;
	} else if (id16 != rest_id16) {
		warnx("TEST FAILED: PCI subsystem id mismatch: was %u "
		    "now %u", id16, rest_id16);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI subsystem id successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_pci_rev(info, &id8)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI revision "
		    "from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_rev(rest_info, &rest_id8)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI revision "
		    "from restored snapshot");
		ret = false;
	} else if (id8 != rest_id8) {
		warnx("TEST FAILED: PCI revision mismatch: was %u now %u",
		    id8, rest_id8);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI revision successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_pci_mps_min(info, &id32)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI MPS min "
		    "from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_mps_min(rest_info, &rest_id32)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI MPS min "
		    "from restored snapshot");
		ret = false;
	} else if (id32 != rest_id32) {
		warnx("TEST FAILED: PCI MPS min mismatch: was %u now %u",
		    id32, rest_id32);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI MPS min successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_pci_mps_max(info, &id32)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI MPS max "
		    "from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_mps_max(rest_info, &rest_id32)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI MPS max "
		    "from restored snapshot");
		ret = false;
	} else if (id32 != rest_id32) {
		warnx("TEST FAILED: PCI MPS max mismatch: was %u now %u",
		    id32, rest_id32);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI MPS max successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_pci_nintrs(info, &id32)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI intr "
		    "count from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_pci_nintrs(rest_info, &rest_id32)) {
		libnvme_test_ctrl_info_warn(info, "failed to get PCI intr "
		    "count from restored snapshot");
		ret = false;
	} else if (id32 != rest_id32) {
		warnx("TEST FAILED: PCI intr count mismatch: was %u now %u",
		    id32, rest_id32);
		ret = false;
	} else {
		(void) printf("TEST PASSED: PCI intr count successfully "
		    "restored\n");
	}

	return (ret);
}

static bool
info_roundtrip_ns(nvme_ctrl_info_t *info, nvme_ctrl_info_t *rest_info)
{
	bool ret = true;
	nvme_uint128_t u128, rest_u128;
	const nvme_identify_nsid_t *idns, *rest_idns;

	if (!nvme_ctrl_info_cap(info, &u128)) {
		libnvme_test_ctrl_info_warn(info, "failed to get NVM capacity "
		    "from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_cap(rest_info, &rest_u128)) {
		libnvme_test_ctrl_info_warn(info, "failed to get NVM capacity "
		    "from restored snapshot");
		ret = false;
	} else if (memcmp(&u128, &rest_u128, sizeof (nvme_uint128_t)) != 0) {
		warnx("TEST FAILED: NVM capacity mismatch");
		ret = false;
	} else {
		(void) printf("TEST PASSED: NVM capacity successfully "
		    "restored\n");
	}

	if (!nvme_ctrl_info_unalloc_cap(info, &u128)) {
		libnvme_test_ctrl_info_warn(info, "failed to get NVM "
		    "unallocated capacity from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_unalloc_cap(rest_info, &rest_u128)) {
		libnvme_test_ctrl_info_warn(info, "failed to get NVM "
		    "unallocated capacity from restored snapshot");
		ret = false;
	} else if (memcmp(&u128, &rest_u128, sizeof (nvme_uint128_t)) != 0) {
		warnx("TEST FAILED: NVM unallocated capacity mismatch");
		ret = false;
	} else {
		(void) printf("TEST PASSED: NVM unallocated capacity "
		    "successfully restored\n");
	}

	if (!nvme_ctrl_info_common_ns(info, &idns)) {
		libnvme_test_ctrl_info_warn(info, "failed to get common ns "
		    "from original snapshot");
		ret = false;
	} else if (!nvme_ctrl_info_common_ns(rest_info, &rest_idns)) {
		libnvme_test_ctrl_info_warn(info, "failed to get common ns "
		    "from restored snapshot");
		ret = false;
	} else if (memcmp(idns, rest_idns,
	    sizeof (nvme_identify_nsid_t)) != 0) {
		warnx("TEST FAILED: Common Identify Namespace mismatch");
		ret = false;
	} else {
		(void) printf("TEST PASSED: common identify namespace "
		    "successfully restored\n");
	}

	return (ret);
}

static bool
info_roundtrip_lba(nvme_ctrl_info_t *info, nvme_ctrl_info_t *rest_info)
{
	bool ret = true;
	const uint32_t nlbas = nvme_ctrl_info_nformats(info);

	for (uint32_t i = 0; i < nlbas; i++) {
		const nvme_nvm_lba_fmt_t *fmt, *rest_fmt;

		if (!nvme_ctrl_info_format(info, i, &fmt)) {
			/*
			 * Some devices like the Kioxia KCD6XLUL3T84 have holes
			 * in their LBA space. Skip such instances.
			 */
			if (nvme_ctrl_info_err(info) == NVME_INFO_ERR_BAD_FMT) {
				continue;
			}

			libnvme_test_ctrl_info_warn(info, "failed to get "
			    "LBA format %u from original snapshot", i);
			ret = false;
			continue;
		}

		if (!nvme_ctrl_info_format(rest_info, i, &rest_fmt)) {
			libnvme_test_ctrl_info_warn(info, "failed to get "
			    "LBA format %u from restored snapshot", i);
			ret = false;
			continue;
		}

		(void) printf("TEST PASSED: successfully got LBA format %u\n",
		    i);
		if (nvme_nvm_lba_fmt_id(fmt) != i) {
			warnx("TEST FAILED: format %u from original snapshot "
			    "has wrong format id: %u\n", i,
			    nvme_nvm_lba_fmt_id(fmt));
			ret = false;
		}

		if (nvme_nvm_lba_fmt_id(rest_fmt) != i) {
			warnx("TEST FAILED: format %u from restored snapshot "
			    "has wrong format id: %u\n", i,
			    nvme_nvm_lba_fmt_id(rest_fmt));
			ret = false;
		}

		if (nvme_nvm_lba_fmt_meta_size(fmt) !=
		    nvme_nvm_lba_fmt_meta_size(rest_fmt)) {
			warnx("TEST FAILED: LBA %u metadata size mismatch: "
			    "was %u, now %u", i,
			    nvme_nvm_lba_fmt_meta_size(fmt),
			    nvme_nvm_lba_fmt_meta_size(rest_fmt));
			ret = false;
		} else {
			(void) printf("TEST PASSED: LBA %u metadata "
			    "successfully restored\n", i);
		}

		if (nvme_nvm_lba_fmt_data_size(fmt) !=
		    nvme_nvm_lba_fmt_data_size(rest_fmt)) {
			warnx("TEST FAILED: LBA %u data size mismatch: "
			    "was %" PRIu64 ", now %" PRIu64, i,
			    nvme_nvm_lba_fmt_data_size(fmt),
			    nvme_nvm_lba_fmt_data_size(rest_fmt));
			ret = false;
		} else {
			(void) printf("TEST PASSED: LBA %u data size "
			    "successfully restored\n", i);
		}

		if (nvme_nvm_lba_fmt_rel_perf(fmt) !=
		    nvme_nvm_lba_fmt_rel_perf(rest_fmt)) {
			warnx("TEST FAILED: LBA %u relative perf mismatch: "
			    "was %u, now %u", i,
			    nvme_nvm_lba_fmt_rel_perf(fmt),
			    nvme_nvm_lba_fmt_rel_perf(rest_fmt));
			ret = false;
		} else {
			(void) printf("TEST PASSED: LBA %u relative perf "
			    "successfully restored\n", i);
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
	nvme_ctrl_info_t *info, *rest_info;
	nvlist_t *nvl;
	const nvme_identify_ctrl_t *ctrlid, *rest_ctrlid;
	const nvme_version_t *vers, *rest_vers;

	libnvme_test_init(&nvme, &ctrl);
	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to take a snapshot");
	}

	if (!nvme_ctrl_info_persist(info, &nvl)) {
		libnvme_test_ctrl_info_fatal(info, "failed to persist the "
		    "controller snapshot");
	}

	if (!nvme_ctrl_info_restore(nvme, nvl, &rest_info)) {
		libnvme_test_hdl_fatal(nvme, "failed to restore controller "
		    "snapshot");
	}

	if (nvme_ctrl_info_vendor(info) != nvme_ctrl_info_vendor(rest_info)) {
		warnx("TEST FAILED: vendor mismatch: orig 0x%x, restored: 0x%x",
		    nvme_ctrl_info_vendor(info),
		    nvme_ctrl_info_vendor(rest_info));
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: successfully matched vendor id\n");
	}

	ctrlid = nvme_ctrl_info_identify(info);
	rest_ctrlid = nvme_ctrl_info_identify(rest_info);
	if (memcmp(ctrlid, rest_ctrlid, sizeof (nvme_identify_ctrl_t)) != 0) {
		warnx("TEST FAILED: Identify info mismatched after restore");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: identify controller successfully "
		    "restored\n");
	}

	vers = nvme_ctrl_info_version(info);
	rest_vers = nvme_ctrl_info_version(rest_info);
	if (vers->v_major != rest_vers->v_major) {
		warnx("TEST FAILED: mismatched major version: was %u, found %u",
		    vers->v_major, rest_vers->v_major);
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: major version successfully "
		    "restored\n");
	}

	if (vers->v_minor != rest_vers->v_minor) {
		warnx("TEST FAILED: mismatched minor version: was %u, found %u",
		    vers->v_minor, rest_vers->v_minor);
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: minor version successfully "
		    "restored\n");
	}

	if (strcmp(nvme_ctrl_info_model(info),
	    nvme_ctrl_info_model(rest_info)) != 0) {
		warnx("TEST FAILED: model string mismatch");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: model successfully restored\n");
	}

	if (strcmp(nvme_ctrl_info_serial(info),
	    nvme_ctrl_info_serial(rest_info)) != 0) {
		warnx("TEST FAILED: serial string mismatch");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: serial successfully restored\n");
	}

	if (strcmp(nvme_ctrl_info_fwrev(info),
	    nvme_ctrl_info_fwrev(rest_info)) != 0) {
		warnx("TEST FAILED: fwrev string mismatch");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: fwrev successfully restored\n");
	}

	if (nvme_ctrl_info_nns(info) != nvme_ctrl_info_nns(rest_info)) {
		warnx("TEST FAILED: number of namespaces mismatch: was %u, "
		    "now %u", nvme_ctrl_info_nns(info),
		    nvme_ctrl_info_nns(rest_info));
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: number of namespaces successfully "
		    "restored\n");
	}

	if (nvme_ctrl_info_type(info) != nvme_ctrl_info_type(rest_info)) {
		warnx("TEST FAILED: controller type mismatch: was %u, "
		    "now %u", nvme_ctrl_info_type(info),
		    nvme_ctrl_info_type(rest_info));
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: controller type successfully "
		    "restored\n");
	}

	if (nvme_ctrl_info_transport(info) !=
	    nvme_ctrl_info_transport(rest_info)) {
		warnx("TEST FAILED: controller transport mismatch: was %u, "
		    "now %u", nvme_ctrl_info_transport(info),
		    nvme_ctrl_info_transport(rest_info));
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: controller transport successfully "
		    "restored\n");
	}

	if (nvme_ctrl_info_transport(info) == NVME_CTRL_TRANSPORT_PCI &&
	    !info_roundtrip_pci(info, rest_info)) {
		ret = EXIT_FAILURE;
	}

	if (ctrlid->id_oacs.oa_nsmgmt != 0 && !info_roundtrip_ns(info,
	    rest_info)) {
		ret = EXIT_FAILURE;
	}

	if (nvme_ctrl_info_nformats(info) !=
	    nvme_ctrl_info_nformats(rest_info)) {
		warnx("TEST FAILED: number of LBA formats mismatch: was %u, "
		    "now %u", nvme_ctrl_info_nformats(info),
		    nvme_ctrl_info_nformats(rest_info));
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: number of LBA formats successfully "
		    "restored\n");
	}

	if (nvme_ctrl_info_nformats(info) > 0 && !info_roundtrip_lba(info,
	    rest_info)) {
		ret = EXIT_FAILURE;
	}

	nvme_ctrl_info_free(rest_info);
	nvme_ctrl_info_free(info);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests exited successfully\n");
	}

	return (ret);
}
