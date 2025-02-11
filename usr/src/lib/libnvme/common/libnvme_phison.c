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
 * libnvme logic specific to Phison devices. This currently supports the Phison
 * X200.
 */

#include <sys/sysmacros.h>
#include <sys/nvme/phison.h>

#include "libnvme_impl.h"

static const nvme_vsd_ident_t phison_x200_idents[] = {
	{
		.nvdi_vid = PHISON_PCI_VID,
		.nvdi_did = PHISON_X200_DID,
		.nvdi_human = "Phison X200"
	}
};

static const nvme_log_page_info_t *phison_x200_log_pages[] = {
	&ocp_log_smart, &ocp_log_errrec, &ocp_log_fwact, &ocp_log_lat,
	&ocp_log_devcap, &ocp_log_unsup
};

const nvme_vsd_t phison_x200 = {
	.nvd_ident = phison_x200_idents,
	.nvd_nident = ARRAY_SIZE(phison_x200_idents),
	.nvd_logs = phison_x200_log_pages,
	.nvd_nlogs = ARRAY_SIZE(phison_x200_log_pages)
};
