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
 * libnvme logic that covers the OCP Datacenter NVMe SSD specification.
 */

#include <string.h>
#include <sys/sysmacros.h>
#include <sys/nvme/ocp.h>

#include "libnvme_impl.h"

static bool
nvme_ocp_telstr_var_len(uint64_t *outp, const void *data, size_t len)
{
	ocp_vul_telstr_t telstr;
	size_t need = offsetof(ocp_vul_telstr_t, ots_rsvd40);

	if (len < offsetof(ocp_vul_telstr_t, ots_rsvd40)) {
		return (false);
	}

	(void) memcpy(&telstr, data, need);
	if (telstr.ots_sls / sizeof (uint32_t) >= SIZE_MAX) {
		return (false);
	}
	*outp = telstr.ots_sls * sizeof (uint32_t);
	return (true);
}

static bool
nvme_ocp_hwcomp_var_len(uint64_t *outp, const void *data, size_t len)
{
	ocp_vul_hw_comp_t comp;
	uint32_t dlen;
	uint64_t mult;

	if (len < sizeof (ocp_vul_hw_comp_t)) {
		return (false);
	}


	(void) memcpy(&comp, data, sizeof (ocp_vul_hw_comp_t));

	/*
	 * The hardware component log has a 16-byte number that is used to
	 * indicate the log page length. In version 1 of the log page this is a
	 * value of uint32_t's. In version 2 of the log page this is in bytes.
	 * Because of these changes we require a known version to know how to
	 * deal with these things.
	 *
	 * When we encounter a log page with more than 4 GiB of data in it, we
	 * can come back to this as we're going to need to improve the logic
	 * elsewhere to stream this rather than use a single buffer.
	 */
	switch (comp.ohc_vers) {
	case 1:
		mult = sizeof (uint32_t);
		break;
	case 2:
		mult = 1;
		break;
	default:
		return (false);
	}

	for (size_t i = 4; i < 16; i++) {
		if (comp.ohc_len[i] != 0) {
			return (false);
		}
	}

	(void) memcpy(&dlen, comp.ohc_len, sizeof (dlen));
	*outp = (uint64_t)dlen * mult;
	if (*outp < sizeof (ocp_vul_hw_comp_t)) {
		return (false);
	}

	return (true);
}

const nvme_log_page_info_t ocp_log_smart = {
	.nlpi_short = "ocp/smart",
	.nlpi_human = "OCP SMART / Health Information",
	.nlpi_lid = OCP_LOG_DSSD_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (ocp_vul_smart_t),
};

const nvme_log_page_info_t ocp_log_errrec = {
	.nlpi_short = "ocp/errrec",
	.nlpi_human = "OCP Error Recovery",
	.nlpi_lid = OCP_LOG_DSSD_ERROR_REC,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (ocp_vul_errrec_t),
};

const nvme_log_page_info_t ocp_log_fwact = {
	.nlpi_short = "ocp/fwact",
	.nlpi_human = "OCP Firmware Activation",
	.nlpi_lid = OCP_LOG_DSSD_FWACT,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (ocp_vul_fwact_t),
};

const nvme_log_page_info_t ocp_log_lat = {
	.nlpi_short = "ocp/latency",
	.nlpi_human = "OCP Latency Monitor",
	.nlpi_lid = OCP_LOG_DSSD_LATENCY,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (ocp_vul_lat_t),
};

const nvme_log_page_info_t ocp_log_devcap = {
	.nlpi_short = "ocp/devcap",
	.nlpi_human = "OCP Device Capabilities",
	.nlpi_lid = OCP_LOG_DSSD_DEV_CAP,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (ocp_vul_devcap_t),
};

const nvme_log_page_info_t ocp_log_unsup = {
	.nlpi_short = "ocp/unsup",
	.nlpi_human = "OCP Unsupported Requirements",
	.nlpi_lid = OCP_LOG_DSSD_UNSUP_REQ,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (ocp_vul_unsup_req_t),
};

const nvme_log_page_info_t ocp_log_hwcomp = {
	.nlpi_short = "ocp/hwcomp",
	.nlpi_human = "Hardware Component",
	.nlpi_lid = OCP_LOG_DSSD_HW_COMP,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (ocp_vul_hw_comp_t),
	.nlpi_var_func = nvme_ocp_hwcomp_var_len
};

const nvme_log_page_info_t ocp_log_telstr = {
	.nlpi_short = "ocp/telstr",
	.nlpi_human = "OCP Telemetry String",
	.nlpi_lid = OCP_LOG_DSSD_TELEMETRY,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = offsetof(ocp_vul_telstr_t, ots_rsvd40),
	.nlpi_var_func = nvme_ocp_telstr_var_len
};
