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

const nvme_feat_info_t ocp_feat_errinj = {
	.nfeat_short = "ocp/errinj",
	.nfeat_spec = "OCP Error Injection",
	.nfeat_fid = OCP_FEAT_DSSD_ERR_INJ,
	.nfeat_kind = NVME_FEAT_VENDOR_SPECIFIC,
	.nfeat_scope = NVME_FEAT_SCOPE_NVM,
	.nfeat_csi = NVME_FEAT_CSI_NONE,
	.nfeat_in_get = NVME_GET_FEAT_F_DATA,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11 | NVME_SET_FEAT_F_DATA,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0 | NVME_FEAT_OUTPUT_DATA,
	/*
	 * The OCP specification reqiurement SERRI-9 says that this must always
	 * be a 4K payload that has [0, 127] entries.
	 */
	.nfeat_len = (OCP_ERRINJ_MAX_INJECT + 1) * sizeof (ocp_vuf_errinj_t)
};

/*
 * This was originally called the EOL/PLP Failure Mode, but the EOL was dropped
 * starting in version 2.6 of the OCP DSSD NVMe specification.
 */
const nvme_feat_info_t ocp_feat_plpfail = {
	.nfeat_short = "ocp/plpfail",
	.nfeat_spec = "OCP PLP Failure Mode",
	.nfeat_fid = OCP_FEAT_DSSD_EOLPLP,
	.nfeat_kind = NVME_FEAT_VENDOR_SPECIFIC,
	.nfeat_scope = NVME_FEAT_SCOPE_NVM,
	.nfeat_csi = NVME_FEAT_CSI_NONE,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
};

const nvme_feat_info_t ocp_feat_plphealth = {
	.nfeat_short = "ocp/plphealth",
	.nfeat_spec = "OCP PLP Health Check Interval",
	.nfeat_fid = OCP_FEAT_DSSD_PLP_HEALTH,
	.nfeat_kind = NVME_FEAT_VENDOR_SPECIFIC,
	.nfeat_scope = NVME_FEAT_SCOPE_NVM,
	.nfeat_csi = NVME_FEAT_CSI_NONE,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
};

typedef enum {
	NVME_OCP_ERRINJ_FIELD_TYPE	= 0,
	NVME_OCP_ERRINJ_FIELD_NRTDE,
	NVME_OCP_ERRINJ_FIELD_LD
} nvme_ocp_errinj_req_field_t;

const nvme_field_info_t nvme_ocp_errinj_fields[] = {
	[NVME_OCP_ERRINJ_FIELD_TYPE] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT16_MAX,
		.nlfi_spec = "eit",
		.nlfi_human = "error injection type",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_OCP_ERRINJ_FIELD_NRTDE] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT16_MAX,
		.nlfi_spec = "nrtde",
		.nlfi_human = "number of reads to trigger device panic",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	/*
	 * This field was added in OCP DSSD v2.7. It only applies to event 0xe.
	 * While we could get the DSSD spec version out of the health and error
	 * reporting to see if this is supported as part of a version check, for
	 * now we just let it be set and allow the device to allow or deny it.
	 */
	[NVME_OCP_ERRINJ_FIELD_LD] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT32_MAX,
		.nlfi_spec = "ld",
		.nlfi_human = "latency duration",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	}
};

void
nvme_ocp_errinj_req_fini(nvme_ocp_errinj_req_t *req)
{
	if (req != NULL) {
		nvme_set_feat_req_fini(req->oer_feat);
		free(req);
	}
}

bool
nvme_ocp_errinj_req_init(nvme_ctrl_t *ctrl, nvme_ocp_errinj_req_t **reqp)
{
	nvme_ocp_errinj_req_t *req;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ocp_errinj_req_t output pointer: "
		    "%p", reqp));
	}

	req = calloc(1, sizeof (nvme_ocp_errinj_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvm_ocp_errinj_req_t: %s",
		    strerror(e)));
	}

	if (!nvme_vendor_feature_supported(ctrl, "ocp/errinj") ||
	    !nvme_set_feat_req_init_by_name(ctrl, "ocp/errinj", 0, NULL,
	    &req->oer_feat)) {
		nvme_ocp_errinj_req_fini(req);
		return (false);
	}

	for (size_t i = 0; i < ARRAY_SIZE(nvme_ocp_errinj_fields); i++) {
		if (nvme_ocp_errinj_fields[i].nlfi_def_req) {
			req->oer_need |= 1 << i;
		}

		if (nvme_ocp_errinj_fields[i].nlfi_def_allow) {
			req->oer_allow |= 1 << i;
		}
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_ocp_errinj_req_clear_need(nvme_ocp_errinj_req_t *req,
    nvme_ocp_errinj_req_field_t field)
{
	req->oer_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_ocp_errinj_check_type = {
	nvme_ocp_errinj_fields, NVME_OCP_ERRINJ_FIELD_TYPE,
	NVME_ERR_OCP_ERRINJ_TYPE_RANGE, 0, 0
};

bool
nvme_ocp_errinj_req_set_type(nvme_ocp_errinj_req_t *req, uint32_t type)
{
	nvme_ctrl_t *ctrl = req->oer_feat->sfr_ctrl;

	if (!nvme_field_check_one(ctrl, type, "ocp error injection",
	    &nvme_ocp_errinj_check_type, req->oer_allow)) {
		return (false);
	}

	req->oer_err[0].oei_type = (uint16_t)type;
	nvme_ocp_errinj_req_clear_need(req, NVME_OCP_ERRINJ_FIELD_TYPE);
	return (nvme_ctrl_success(ctrl));
}

static const nvme_field_check_t nvme_ocp_errinj_check_nread = {
	nvme_ocp_errinj_fields, NVME_OCP_ERRINJ_FIELD_NRTDE,
	NVME_ERR_OCP_ERRINJ_NRTDE_RANGE, 0, 0
};

bool
nvme_ocp_errinj_req_set_nrtde(nvme_ocp_errinj_req_t *req, uint32_t nreads)
{
	nvme_ctrl_t *ctrl = req->oer_feat->sfr_ctrl;

	if (!nvme_field_check_one(ctrl, nreads, "ocp error injection",
	    &nvme_ocp_errinj_check_nread, req->oer_allow)) {
		return (false);
	}

	req->oer_err[0].oei_nrtde = (uint16_t)nreads;
	nvme_ocp_errinj_req_clear_need(req, NVME_OCP_ERRINJ_FIELD_NRTDE);
	return (nvme_ctrl_success(ctrl));
}

static const nvme_field_check_t nvme_ocp_errinj_check_ld = {
	nvme_ocp_errinj_fields, NVME_OCP_ERRINJ_FIELD_LD,
	NVME_ERR_OCP_ERRINJ_LD_RANGE, NVME_ERR_OCP_ERRINJ_LD_UNSUP,
	NVME_ERR_OCP_ERRINJ_LD_UNUSE
};

/*
 * We can't check if this field can be set until after an event is set. We defer
 * checking it right now until exec. We don't have a copy of the OCP
 * SMART/Health log which means we can't right now send the unsupported error
 * check. The error constant exists so we can figure out a means of doing so in
 * the future if that makes sense.
 */
bool
nvme_ocp_errinj_req_set_ld(nvme_ocp_errinj_req_t *req, uint32_t lat)
{
	nvme_ctrl_t *ctrl = req->oer_feat->sfr_ctrl;

	if (!nvme_field_check_one(ctrl, lat, "ocp error injection",
	    &nvme_ocp_errinj_check_ld, req->oer_allow)) {
		return (false);
	}

	req->oer_err[0].oei_lat = lat;
	nvme_ocp_errinj_req_clear_need(req, NVME_OCP_ERRINJ_FIELD_LD);
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_ocp_errinj_req_exec(nvme_ocp_errinj_req_t *req)
{
	nvme_ctrl_t *ctrl = req->oer_feat->sfr_ctrl;

	if (req->oer_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_ocp_errinj_fields,
		    ARRAY_SIZE(nvme_ocp_errinj_fields),
		    NVME_ERR_OCP_ERRINJ_REQ_MISSING_FIELDS,
		    "ocp error injection", req->oer_need));
	}

	/*
	 * Now that we know the tpye of request, check that the type makes sense
	 * and evaluate if the latency duration makes sense.
	 */
	if (req->oer_err[0].oei_lat != 0 && req->oer_err[0].oei_type !=
	    OCP_ERRINJ_T_LATENCY_SPIKE) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_OCP_ERRINJ_LD_UNUSE, 0,
		    "the latency duration field may only be used with the "
		    "latency spike event type (0x%x): found 0x%x",
		    OCP_ERRINJ_T_LATENCY_SPIKE, req->oer_err[0].oei_type));
	}

	/*
	 * Beginning in OCP DSSD version 2.7 injecting a single event and
	 * ensuring only a single instance was present became required. This is
	 * likely a constraint of older devices which is why we only allow a
	 * single event to be injected and always set that.
	 */
	req->oer_err[0].oei_flags = OCP_ERRINJ_F_ENABLE | OCP_ERRINJ_F_SINGLE;
	if (!nvme_set_feat_req_set_cdw11(req->oer_feat, 1) ||
	    !nvme_set_feat_req_set_input(req->oer_feat, req->oer_err,
	    sizeof (req->oer_err))) {
		return (false);
	}

	return (nvme_set_feat_req_exec(req->oer_feat));
}

/*
 * Send a request to clear all pending errors.
 */
bool
nvme_ocp_errinj_clear(nvme_ctrl_t *ctrl)
{
	nvme_set_feat_req_t *req;
	bool ret = false;
	ocp_vuf_errinj_t table[OCP_ERRINJ_MAX_INJECT + 1];

	if (!nvme_vendor_feature_supported(ctrl, "ocp/errinj") ||
	    !nvme_set_feat_req_init_by_name(ctrl, "ocp/errinj", 0, NULL,
	    &req)) {
		return (false);
	}

	/*
	 * The specification isn't quite clear if no table should be sent if the
	 * event count is zero, so we always send this regardless. A zeroed
	 * table suggests no entries are valid and coincides with the cdw11
	 * value.
	 */
	(void) memset(table, 0, sizeof (table));
	if (nvme_set_feat_req_set_cdw11(req, 0) &&
	    nvme_set_feat_req_set_input(req, table, sizeof (table)) &&
	    nvme_set_feat_req_exec(req)) {
		ret = nvme_ctrl_success(ctrl);
	}

	nvme_set_feat_req_fini(req);
	return (ret);
}
