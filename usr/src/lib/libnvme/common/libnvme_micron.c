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
 * libnvme logic specific to Micron device families. Currently this has support
 * for the Micron 7300, 7400, 7450, 6500, 7500, and 9550 device generations.
 * Right now we only have support for some of the device-specific log pages.
 */

#include <sys/sysmacros.h>
#include <sys/nvme/micron.h>

#include "libnvme_impl.h"

static const nvme_log_page_info_t micron_7300_log_smart = {
	.nlpi_short = "micron/smart",
	.nlpi_human = "Vendor Unique SMART",
	.nlpi_lid = MICRON_7300_LOG_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (micron_vul_smart_t)
};

static const nvme_log_page_info_t micron_7300_log_extsmart = {
	.nlpi_short = "micron/extsmart",
	.nlpi_human = "Extended SMART",
	.nlpi_lid = MICRON_7300_LOG_EXT_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (micron_vul_ext_smart_t)
};

static const nvme_log_page_info_t *micron_7300_log_pages[] = {
	&micron_7300_log_smart, &micron_7300_log_extsmart
};

static const nvme_log_page_info_t micron_74x0_log_extsmart = {
	.nlpi_short = "micron/extsmart",
	.nlpi_human = "Extended SMART",
	.nlpi_lid = MICRON_74x0_LOG_EXT_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (micron_vul_ext_smart_t)
};

static const nvme_log_page_info_t *micron_74x0_log_pages[] = {
	&micron_74x0_log_extsmart
};

static const nvme_log_page_info_t *micron_x500_log_pages[] = {
	&ocp_log_smart, &ocp_log_errrec, &ocp_log_fwact, &ocp_log_lat,
	&ocp_log_devcap, &ocp_log_unsup
};

static const nvme_log_page_info_t *micron_9550_log_pages[] = {
	&ocp_log_smart, &ocp_log_errrec, &ocp_log_fwact, &ocp_log_lat,
	&ocp_log_devcap, &ocp_log_unsup, &ocp_log_telstr
};

static const nvme_vsd_ident_t micron_7300_idents[] = {
	{
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7300_PRO_DID,
		.nvdi_human = "Micron 7300 Pro",
	}, {
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7300_MAX_DID,
		.nvdi_human = "Micron 7300 Max",
	}
};

const nvme_vsd_t micron_7300 = {
	.nvd_ident = micron_7300_idents,
	.nvd_nident = ARRAY_SIZE(micron_7300_idents),
	.nvd_logs = micron_7300_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_7300_log_pages)
};

static const nvme_vsd_ident_t micron_74x0_idents[] = {
	{
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7400_PRO_DID,
		.nvdi_human = "Micron 7400 Pro",
	}, {
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7400_MAX_DID,
		.nvdi_human = "Micron 7400 Max",
	}, {
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7450_PRO_DID,
		.nvdi_human = "Micron 7450 Pro",
	}, {
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7450_MAX_DID,
		.nvdi_human = "Micron 7450 Max",
	}
};

const nvme_vsd_t micron_74x0 = {
	.nvd_ident = micron_74x0_idents,
	.nvd_nident = ARRAY_SIZE(micron_74x0_idents),
	.nvd_logs = micron_74x0_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_74x0_log_pages)
};

static const nvme_vsd_ident_t micron_x500_idents[] = {
	{
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_6500_ION_DID,
		.nvdi_human = "Micron 6500 ION"
	}, {
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7500_PRO_DID,
		.nvdi_human = "Micron 7500 Pro"
	}, {
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_7500_MAX_DID,
		.nvdi_human = "Micron 7500 Max"
	}
};

const nvme_vsd_t micron_x500 = {
	.nvd_ident = micron_x500_idents,
	.nvd_nident = ARRAY_SIZE(micron_x500_idents),
	.nvd_logs = micron_x500_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_x500_log_pages)
};

static const nvme_vsd_ident_t micron_9550_idents[] = {
	{
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_9550_PRO_DID,
		.nvdi_human = "Micron 9550 Pro",
	}, {
		.nvdi_vid = MICRON_PCI_VID,
		.nvdi_did = MICRON_9550_MAX_DID,
		.nvdi_human = "Micron 9550 Max",
	}
};

const nvme_vsd_t micron_9550 = {
	.nvd_ident = micron_9550_idents,
	.nvd_nident = ARRAY_SIZE(micron_9550_idents),
	.nvd_logs = micron_9550_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_9550_log_pages)
};
