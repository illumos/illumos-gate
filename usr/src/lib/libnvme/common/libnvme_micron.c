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
 * libnvme logic specific to Micron device families. Currently this has support
 * for the Micron 7300, 7400, and 7450 device generations. Right now we only
 * have support for some of the device-specific log pages.
 */

#include <sys/sysmacros.h>
#include <sys/nvme/micron.h>

#include "libnvme_impl.h"

static const nvme_log_page_info_t micron_7300_log_pages[] = { {
	.nlpi_short = "micron/smart",
	.nlpi_human = "Vendor Unique SMART",
	.nlpi_lid = MICRON_7300_LOG_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (micron_vul_smart_t)
}, {
	.nlpi_short = "micron/extsmart",
	.nlpi_human = "Extended SMART",
	.nlpi_lid = MICRON_7300_LOG_EXT_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (micron_vul_ext_smart_t)
} };

static const nvme_log_page_info_t micron_74x0_log_pages[] = { {
	.nlpi_short = "micron/extsmart",
	.nlpi_human = "Extended SMART",
	.nlpi_lid = MICRON_74x0_LOG_EXT_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (micron_vul_ext_smart_t)
} };

const nvme_vsd_t micron_7300_pro = {
	.nvd_vid = MICRON_PCI_VID,
	.nvd_did = MICRON_7300_PRO_DID,
	.nvd_human = "Micron 7300 Pro",
	.nvd_logs = micron_7300_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_7300_log_pages)
};

const nvme_vsd_t micron_7300_max = {
	.nvd_vid = MICRON_PCI_VID,
	.nvd_did = MICRON_7300_MAX_DID,
	.nvd_human = "Micron 7300 Max",
	.nvd_logs = micron_7300_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_7300_log_pages)
};

const nvme_vsd_t micron_7400_pro = {
	.nvd_vid = MICRON_PCI_VID,
	.nvd_did = MICRON_7400_PRO_DID,
	.nvd_human = "Micron 7400 Pro",
	.nvd_logs = micron_74x0_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_74x0_log_pages)
};

const nvme_vsd_t micron_7400_max = {
	.nvd_vid = MICRON_PCI_VID,
	.nvd_did = MICRON_7400_MAX_DID,
	.nvd_human = "Micron 7400 Max",
	.nvd_logs = micron_74x0_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_74x0_log_pages)
};

const nvme_vsd_t micron_7450_pro = {
	.nvd_vid = MICRON_PCI_VID,
	.nvd_did = MICRON_7450_PRO_DID,
	.nvd_human = "Micron 7450 Pro",
	.nvd_logs = micron_74x0_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_74x0_log_pages)
};

const nvme_vsd_t micron_7450_max = {
	.nvd_vid = MICRON_PCI_VID,
	.nvd_did = MICRON_7450_MAX_DID,
	.nvd_human = "Micron 7450 Max",
	.nvd_logs = micron_74x0_log_pages,
	.nvd_nlogs = ARRAY_SIZE(micron_74x0_log_pages)
};
