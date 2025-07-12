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
 * libnvme logic specific to Samsung devices. This currently supports the
 * Samsung PM9D3a.
 */

#include <sys/sysmacros.h>
#include <sys/nvme/samsung.h>

#include "libnvme_impl.h"

static const nvme_vsd_ident_t samsung_pm9d3a_idents[] = {
	{
		.nvdi_vid = SAMSUNG_PCI_VID,
		.nvdi_did = SAMSUNG_PM9D3_DID,
		.nvdi_human = "Samsung PM9D3a"
	}
};

static const nvme_log_page_info_t *samsung_pm9d3a_log_pages[] = {
	&ocp_log_smart, &ocp_log_errrec, &ocp_log_fwact, &ocp_log_lat,
	&ocp_log_devcap, &ocp_log_unsup, &ocp_log_telstr
};

const nvme_vsd_t samsung_pm9d3a = {
	.nvd_ident = samsung_pm9d3a_idents,
	.nvd_nident = ARRAY_SIZE(samsung_pm9d3a_idents),
	.nvd_logs = samsung_pm9d3a_log_pages,
	.nvd_nlogs = ARRAY_SIZE(samsung_pm9d3a_log_pages)
};
