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
 * libnvme logic specific to Kioxia devices. This currently supports the Kioxia
 * CD8 and CD8P.
 */

#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/nvme/kioxia.h>

#include "libnvme_impl.h"

static const nvme_vsd_ident_t kioxia_cd8_idents[] = {
	{
		.nvdi_vid = KIOXIA_PCI_VID,
		.nvdi_did = KIOXIA_CD8_DID,
		.nvdi_human = "Kioxia CD8"
	}, {
		.nvdi_vid = KIOXIA_PCI_VID,
		.nvdi_did = KIOXIA_CD8P_DID,
		.nvdi_human = "Kioxia CD8P"
	}
};

static const nvme_log_page_info_t kioxia_cd8_log_extsmart = {
	.nlpi_short = "kioxia/extsmart",
	.nlpi_human = "Extended SMART",
	.nlpi_lid = KIOXIA_CD8_LOG_EXTSMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (kioxia_vul_cd8_smart_t)
};

static const nvme_log_page_info_t *kioxia_cd8_log_pages[] = {
	&ocp_log_smart, &ocp_log_errrec, &ocp_log_fwact, &ocp_log_lat,
	&ocp_log_devcap, &ocp_log_unsup, &kioxia_cd8_log_extsmart
};

const nvme_vsd_t kioxia_cd8 = {
	.nvd_ident = kioxia_cd8_idents,
	.nvd_nident = ARRAY_SIZE(kioxia_cd8_idents),
	.nvd_logs = kioxia_cd8_log_pages,
	.nvd_nlogs = ARRAY_SIZE(kioxia_cd8_log_pages)
};
