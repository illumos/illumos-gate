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
 * Implements logic to map a device to a vendor-specific entity.
 */

#include <libdevinfo.h>
#include <sys/sysmacros.h>
#include <string.h>

#include "libnvme_impl.h"

const nvme_vsd_t *const nvme_vsd_devices[] = {
	&wdc_sn840,
	&wdc_sn650,
	&wdc_sn655,
	&micron_7300_pro,
	&micron_7300_max,
	&micron_7400_pro,
	&micron_7400_max,
	&micron_7450_pro,
	&micron_7450_max,
	&micron_6500_ion,
	&micron_7500_pro,
	&micron_7500_max
};

/*
 * Our job is to attempt to map a given device to vendor specific information,
 * if it exists. It may not.
 */
void
nvme_vendor_map_ctrl(nvme_ctrl_t *ctrl)
{
	int *vid, *did;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, ctrl->nc_devi, "vendor-id",
	    &vid) != 1 || di_prop_lookup_ints(DDI_DEV_T_ANY, ctrl->nc_devi,
	    "device-id", &did) != 1) {
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(nvme_vsd_devices); i++) {
		if (nvme_vsd_devices[i]->nvd_vid == vid[0] &&
		    nvme_vsd_devices[i]->nvd_did == did[0]) {
			ctrl->nc_vsd = nvme_vsd_devices[i];
			return;
		}
	}
}

bool
nvme_vendor_vuc_supported(nvme_ctrl_t *ctrl, const char *name)
{
	if (ctrl->nc_vsd != NULL) {
		for (size_t i = 0; i < ctrl->nc_vsd->nvd_nvuc; i++) {
			if (strcmp(name, ctrl->nc_vsd->nvd_vuc[i].nvd_short) ==
			    0) {
				return (true);
			}
		}
	}

	return (nvme_ctrl_error(ctrl, NVME_ERR_VU_FUNC_UNSUP_BY_DEV, 0,
	    "device missing support for vendor unique command %s", name));
}
