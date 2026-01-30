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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * libnvme pieces specific to Sandisk.
 *
 * Sandisk was spun out of WDC. The controller family changed in approximately
 * the SN861 family versus the prior SNx40 and SNx50 parts. We use this as a
 * somewhat arbitrary delimiter between the two devices and thus add
 * vendor-specific commands starting with this family with the 'sandisk' name.
 */

#include <sys/sysmacros.h>
#include <sys/nvme/wdc.h>

#include "libnvme_impl.h"

/*
 * This is a default timeout (seconds) that we think should be good enough for
 * most of these operations. As we expand this, this should become more fine
 * grained.
 */
static const uint32_t nvme_sndk_timeout = 20;

static const nvme_vsd_ident_t sandisk_sn861_idents[] = {
	{
		.nvdi_vid = WDC_PCI_VID,
		.nvdi_did = WDC_SN861_DID_U2,
		.nvdi_human = "SanDisk DC SN861 U.2",
	}, {
		.nvdi_vid = WDC_PCI_VID,
		.nvdi_did = WDC_SN861_DID_E3,
		.nvdi_human = "SanDisk DC SN861 E3.S",
	}, {
		.nvdi_vid = WDC_PCI_VID,
		.nvdi_did = WDC_SN861_DID_E1,
		.nvdi_human = "SanDisk DC SN861 E1.S",
	}
};

static const nvme_log_page_info_t *sandisk_sn861_log_pages[] = {
	&ocp_log_smart, &ocp_log_errrec, &ocp_log_fwact, &ocp_log_lat,
	&ocp_log_devcap, &ocp_log_unsup
};

static const nvme_vuc_disc_t sndk_sn861_vuc[] = { {
	.nvd_short = "sandisk/pci-eye",
	.nvd_desc = "per-lane PCI eye diagram",
	.nvd_opc = WDC_SN861_VUC_EYE_OPC,
	.nvd_dt = NVME_VUC_DISC_IO_OUTPUT,
	.nvd_lock = NVME_VUC_DISC_LOCK_NONE
}, {
	.nvd_short = "sandisk/hwrev",
	.nvd_desc = "print hardware revision",
	.nvd_opc = WDC_SN861_VUC_HWREV_OPC,
	.nvd_dt = NVME_VUC_DISC_IO_OUTPUT,
	.nvd_lock = NVME_VUC_DISC_LOCK_NONE
} };

const nvme_vsd_t sandisk_sn861 = {
	.nvd_ident = sandisk_sn861_idents,
	.nvd_nident = ARRAY_SIZE(sandisk_sn861_idents),
	.nvd_logs = sandisk_sn861_log_pages,
	.nvd_nlogs = ARRAY_SIZE(sandisk_sn861_log_pages),
	.nvd_vuc = sndk_sn861_vuc,
	.nvd_nvuc = ARRAY_SIZE(sndk_sn861_vuc)
};

bool
nvme_sndk_pci_eye(nvme_ctrl_t *ctrl, uint8_t lane, void *buf, size_t len)
{
	nvme_vuc_req_t *req = NULL;

	if (buf == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid eye diagram buffer output pointer: %p",
		    buf));
	}

	if (len < WDC_SN861_VUC_EYE_LEN) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_PCIE_EYE_BUF_RANGE, 0,
		    "eye diagram buffer output size is too small: found 0x%zx "
		    "bytes, but need at least 0x%x", len,
		    WDC_SN861_VUC_EYE_LEN));
	}

	if (lane >= 4) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_PCIE_LANE_RANGE, 0,
		    "invalid PCIe lane %u: must be between 0-3", lane));
	}

	if (!nvme_vendor_vuc_supported(ctrl, "sandisk/pci-eye")) {
		return (false);
	}

	if (!nvme_vuc_req_init(ctrl, &req)) {
		return (false);
	}


	if (!nvme_vuc_req_set_opcode(req, WDC_SN861_VUC_EYE_OPC) ||
	    !nvme_vuc_req_set_cdw12(req, WDC_SN861_VUC_EYE_CDW12) ||
	    !nvme_vuc_req_set_cdw13(req, lane) ||
	    !nvme_vuc_req_set_timeout(req, nvme_sndk_timeout) ||
	    !nvme_vuc_req_set_output(req, buf, len) ||
	    !nvme_vuc_req_exec(req)) {
		nvme_vuc_req_fini(req);
		return (false);
	}

	nvme_vuc_req_fini(req);
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_sndk_hw_rev(nvme_ctrl_t *ctrl, uint8_t *majorp, uint8_t *minorp)
{
	uint32_t vers;
	nvme_vuc_req_t *req = NULL;

	if (majorp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid major number output pointer: %p",
		    majorp));
	}

	if (minorp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid minor number output pointer: %p",
		    majorp));
	}

	if (!nvme_vendor_vuc_supported(ctrl, "sandisk/hwrev")) {
		return (false);
	}

	if (!nvme_vuc_req_init(ctrl, &req)) {
		return (false);
	}

	if (!nvme_vuc_req_set_opcode(req, WDC_SN861_VUC_HWREV_OPC) ||
	    !nvme_vuc_req_set_cdw12(req, WDC_SN861_VUC_HWREV_CDW12) ||
	    !nvme_vuc_req_set_timeout(req, nvme_sndk_timeout) ||
	    !nvme_vuc_req_set_output(req, &vers, sizeof (vers)) ||
	    !nvme_vuc_req_exec(req)) {
		nvme_vuc_req_fini(req);
		return (false);
	}
	nvme_vuc_req_fini(req);

	/*
	 * The major and minor version are the first and second 10s digit of
	 * this value. If we have something that is larger than that then we are
	 * going to treat this as an error.
	 */
	if (vers > 100) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_INTERNAL, 0, "returned "
		    "version is in an unexpected format and cannot be parsed "
		    "into its major and minor number: 0x%x", vers));
	}

	*minorp = vers % 10;
	*majorp = (vers / 10) % 10;

	return (nvme_ctrl_success(ctrl));
}
