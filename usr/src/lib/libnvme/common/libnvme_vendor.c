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
 * Implements logic to map a device to a vendor-specific entity.
 */

#include <libdevinfo.h>
#include <sys/sysmacros.h>
#include <string.h>

#include "libnvme_impl.h"

const nvme_vsd_t *const nvme_vsd_devices[] = {
	&wdc_sn840,
	&wdc_sn65x,
	&wdc_sn861,
	&micron_7300,
	&micron_74x0,
	&micron_x500,
	&micron_9550,
	&intel_p5510,
	&solidigm_p5x20,
	&solidigm_ps10x0,
	&kioxia_cd8,
	&phison_x200
};

/*
 * Our job is to attempt to map a given device to vendor specific information,
 * if it exists. It may not.
 */
void
nvme_vendor_map_ctrl(nvme_ctrl_t *ctrl)
{
	int *vid, *did, *svidp, *sdidp;
	uint16_t svid = UINT16_MAX, sdid = UINT16_MAX;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, ctrl->nc_devi, "vendor-id",
	    &vid) != 1 || di_prop_lookup_ints(DDI_DEV_T_ANY, ctrl->nc_devi,
	    "device-id", &did) != 1) {
		return;
	}

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, ctrl->nc_devi,
	    "subsystem-vendor-id", &svidp) == 1) {
		svid = (uint16_t)*svidp;
	}

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, ctrl->nc_devi, "subsystem-id",
	    &sdidp) == 1) {
		sdid = (uint16_t)*sdidp;
	}

	for (size_t dev = 0; dev < ARRAY_SIZE(nvme_vsd_devices); dev++) {
		const nvme_vsd_t *vsd = nvme_vsd_devices[dev];

		for (size_t i = 0; i < vsd->nvd_nident; i++) {
			const nvme_vsd_ident_t *ident = &vsd->nvd_ident[i];
			if (ident->nvdi_vid != (uint16_t)vid[0] ||
			    ident->nvdi_did != (uint16_t)did[0]) {
				continue;
			}

			if (ident->nvdi_subsys && (ident->nvdi_svid != svid ||
			    ident->nvdi_sdid != sdid)) {
				continue;
			}

			ctrl->nc_vsd = nvme_vsd_devices[dev];
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
