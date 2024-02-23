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
 * libnvme pieces specific to WDC.
 *
 * Currently this defines several common log pages that are found in a few
 * generations of WDC devices such as the SN840 and SN65x. There is also support
 * for a few of the vendor specific commands in the device.
 *
 * Currently there is support for two commands in library form: getting an e6
 * log and performing a device resize. Because there are a few different
 * parameters needed to issue the e6 request, we end up structuring it like the
 * library's other request structures, even though it just uses the vendor
 * unique commands. We do not use the full field validation structures for this
 * because a portion of that is used by the vendor unique subsystem. Instead we
 * manually validate the offset and track fields being set.
 */

#include <string.h>
#include <sys/sysmacros.h>
#include <sys/nvme/wdc.h>

#include "libnvme_impl.h"

/*
 * The amount of time that this command takes appears to somewhat relate to the
 * size of the overall device and transformations that are going on. This value
 * is an attempt to get through most resize testing plus a little slack in
 * all of our testing to date.
 */
static const uint32_t nvme_wdc_resize_timeout = 30;

/*
 * We expect a given read of a region of an e6 log to take this amount of time
 * in seconds.
 */
static const uint32_t nvme_wdc_e6_timeout = 30;

typedef enum {
	NVME_WDC_E6_REQ_FIELD_OFFSET	= 0,
	NVME_WDC_E6_REQ_FIELD_LEN
} nvme_wdc_e6_req_field_t;

static bool
nvme_wdc_e6_field_valid_offset(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t off, char *msg, size_t msglen)
{
	uint64_t max;

	if ((off % NVME_DWORD_SIZE) != 0) {
		(void) snprintf(msg, msglen, "field %s (%s) value 0x%" PRIx64
		    "must be %u-byte aligned", field->nlfi_human,
		    field->nlfi_spec, off, NVME_DWORD_SIZE);
		return (false);
	}

	max = (uint64_t)UINT32_MAX << NVME_DWORD_SHIFT;
	return (nvme_field_range_check(field, 0, max, msg, msglen, off));
}

const nvme_field_info_t nvme_wdc_e6_req_fields[] = {
	[NVME_WDC_E6_REQ_FIELD_OFFSET] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_wdc_e6_field_valid_offset,
		.nlfi_spec = "offset",
		.nlfi_human = "e6 log offset",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	/*
	 * Note there is no validation of this field because we rely on the
	 * underlying vendor unique command output length to do so.
	 */
	[NVME_WDC_E6_REQ_FIELD_LEN] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_spec = "length",
		.nlfi_human = "data transfer length",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
};

static bool
nvme_wdc_log_dev_mgmt_var_len(uint64_t *outp, const void *data, size_t len)
{
	wdc_vsd_t vsd;

	if (len < sizeof (vsd)) {
		return (false);
	}

	(void) memcpy(&vsd, data, sizeof (vsd));
	*outp = vsd.vsd_len;
	return (true);
}

static bool
nvme_wdc_log_samples_var_len(uint64_t *outp, const void *data, size_t len)
{
	uint32_t nsamp;

	if (len < sizeof (uint32_t)) {
		return (false);
	}

	(void) memcpy(&nsamp, data, sizeof (uint32_t));
	*outp = (uint64_t)nsamp * sizeof (uint32_t);
	return (true);
}

static bool
nvme_wdc_sn840_fw_act_var_len(uint64_t *outp, const void *data, size_t len)
{
	wdc_vul_sn840_fw_act_hdr_t hdr;

	if (len < sizeof (wdc_vul_sn840_fw_act_hdr_t)) {
		return (false);
	}

	(void) memcpy(&hdr, data, sizeof (uint32_t));
	*outp = (uint64_t)hdr.fah_nent * hdr.fah_entlen;
	return (true);
}

static const nvme_log_page_info_t wdc_sn840_log_pages[] = { {
	.nlpi_short = "wdc/eol",
	.nlpi_human = "EOL",
	.nlpi_lid = WDC_SN840_LOG_EOL,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (wdc_vul_sn840_eol_t)
}, {
	.nlpi_short = "wdc/devmgmt",
	.nlpi_human = "Device Manageability",
	.nlpi_lid = WDC_SN840_LOG_DEV_MANAGE,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL | NVME_LOG_SCOPE_NS,
	.nlpi_len = sizeof (wdc_vsd_t),
	.nlpi_var_func = nvme_wdc_log_dev_mgmt_var_len
}, {
	.nlpi_short = "wdc/pciesi",
	.nlpi_human = "PCIe Signal Integrity",
	.nlpi_lid = WDC_SN840_LOG_PCIE_SI,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_disc = NVME_LOG_DISC_F_NEED_LSP,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL
}, {
	.nlpi_short = "wdc/power",
	.nlpi_human = "Power Samples",
	.nlpi_lid = WDC_SN840_LOG_POWER,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (uint32_t),
	.nlpi_var_func = nvme_wdc_log_samples_var_len
}, {
	.nlpi_short = "wdc/temp",
	.nlpi_human = "Temperature Samples",
	.nlpi_lid = WDC_SN840_LOG_TEMP,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (uint32_t),
	.nlpi_var_func = nvme_wdc_log_samples_var_len
}, {
	.nlpi_short = "wdc/fwact",
	.nlpi_human = "Firmware Activation",
	.nlpi_lid = WDC_SN840_LOG_FW_ACT,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (wdc_vul_sn840_fw_act_hdr_t),
	.nlpi_var_func = nvme_wdc_sn840_fw_act_var_len
}, {
	.nlpi_short = "wdc/ccds",
	.nlpi_human = "CCDS Build Information",
	.nlpi_lid = WDC_SN840_LOG_CCDS,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (wdc_vul_sn840_ccds_info_t)
} };

static const nvme_log_page_info_t wdc_sn65x_log_pages[] = { {
	.nlpi_short = "wdc/power",
	.nlpi_human = "Power Samples",
	.nlpi_lid = WDC_SN65X_LOG_POWER,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (uint32_t),
	.nlpi_var_func = nvme_wdc_log_samples_var_len
}, {
	.nlpi_short = "wdc/temp",
	.nlpi_human = "Temperature Samples",
	.nlpi_lid = WDC_SN65X_LOG_TEMP,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (uint32_t),
	.nlpi_var_func = nvme_wdc_log_samples_var_len
}, {
	.nlpi_short = "wdc/cusmart",
	.nlpi_human = "Customer Unique SMART",
	.nlpi_lid = WDC_SN65X_LOG_UNIQUE_SMART,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (wdc_vul_sn65x_smart_t)
} };

/*
 * Currently these commands are shared across the SN840, SN650, and SN655.
 * This will likely need to be split up and redone when we end up with more
 * device-specific commands that aren't shared across controller generations.
 * When we get to that we should choose whether we want to redefine the vuc like
 * we have with log pages or if we should move to a shared structure that is
 * incorporated as an array of pointers.
 */
static const nvme_vuc_disc_t wdc_sn840_sn65x_vuc[] = { {
	.nvd_short = "wdc/resize",
	.nvd_desc = "drive resize",
	.nvd_opc = WDC_VUC_RESIZE_OPC,
	.nvd_impact = NVME_VUC_DISC_IMPACT_DATA | NVME_VUC_DISC_IMPACT_NS,
	.nvd_dt = NVME_VUC_DISC_IO_NONE,
	.nvd_lock = NVME_VUC_DISC_LOCK_WRITE
}, {
	.nvd_short = "wdc/e6dump",
	.nvd_desc = "dump e6 diagnostic data",
	.nvd_opc = WDC_VUC_E6_DUMP_OPC,
	.nvd_dt = NVME_VUC_DISC_IO_OUTPUT,
	.nvd_lock = NVME_VUC_DISC_LOCK_READ
} };

const nvme_vsd_t wdc_sn840 = {
	.nvd_vid = WDC_PCI_VID,
	.nvd_did = WDC_SN840_DID,
	.nvd_human = "WDC Ultrastar DC SN840",
	.nvd_logs = wdc_sn840_log_pages,
	.nvd_nlogs = ARRAY_SIZE(wdc_sn840_log_pages),
	.nvd_vuc = wdc_sn840_sn65x_vuc,
	.nvd_nvuc = ARRAY_SIZE(wdc_sn840_sn65x_vuc)
};

const nvme_vsd_t wdc_sn650 = {
	.nvd_vid = WDC_PCI_VID,
	.nvd_did = WDC_SN650_DID,
	.nvd_human = "WDC Ultrastar DC SN650",
	.nvd_logs = wdc_sn65x_log_pages,
	.nvd_nlogs = ARRAY_SIZE(wdc_sn65x_log_pages),
	.nvd_vuc = wdc_sn840_sn65x_vuc,
	.nvd_nvuc = ARRAY_SIZE(wdc_sn840_sn65x_vuc)
};

const nvme_vsd_t wdc_sn655 = {
	.nvd_vid = WDC_PCI_VID,
	.nvd_did = WDC_SN655_DID,
	.nvd_human = "WDC Ultrastar DC SN655",
	.nvd_logs = wdc_sn65x_log_pages,
	.nvd_nlogs = ARRAY_SIZE(wdc_sn65x_log_pages),
	.nvd_vuc = wdc_sn840_sn65x_vuc,
	.nvd_nvuc = ARRAY_SIZE(wdc_sn840_sn65x_vuc)
};

static nvme_vuc_req_t *
nvme_wdc_resize_vuc(nvme_ctrl_t *ctrl, uint8_t subcmd, uint32_t gib)
{
	nvme_vuc_req_t *req = NULL;
	uint32_t cdw12 = WDC_VUC_RESIZE_CMD | ((uint32_t)subcmd << 8);

	if (!nvme_vendor_vuc_supported(ctrl, "wdc/resize")) {
		return (false);
	}

	if (!nvme_vuc_req_init(ctrl, &req)) {
		return (false);
	}

	if (!nvme_vuc_req_set_opcode(req, WDC_VUC_RESIZE_OPC) ||
	    !nvme_vuc_req_set_cdw12(req, cdw12) ||
	    !nvme_vuc_req_set_cdw13(req, gib) ||
	    !nvme_vuc_req_set_timeout(req, nvme_wdc_resize_timeout)) {
		nvme_vuc_req_fini(req);
		return (false);
	}

	return (req);
}

bool
nvme_wdc_resize_get(nvme_ctrl_t *ctrl, uint32_t *gbp)
{
	nvme_vuc_req_t *vuc;

	if (gbp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid uint32_t pointer: %p", gbp));
	}

	if ((vuc = nvme_wdc_resize_vuc(ctrl, WDC_VUC_RESIZE_SUB_GET, 0)) ==
	    NULL) {
		return (false);
	}

	if (!nvme_vuc_req_exec(vuc)) {
		nvme_vuc_req_fini(vuc);
		return (false);
	}

	if (!nvme_vuc_req_get_cdw0(vuc, gbp)) {
		nvme_vuc_req_fini(vuc);
		return (false);
	}

	return (nvme_ctrl_success(ctrl));
}

bool
nvme_wdc_resize_set(nvme_ctrl_t *ctrl, uint32_t gb)
{
	nvme_vuc_req_t *vuc;

	if ((vuc = nvme_wdc_resize_vuc(ctrl, WDC_VUC_RESIZE_SUB_SET, gb)) ==
	    NULL) {
		return (false);
	}

	if (!nvme_vuc_req_set_impact(vuc, NVME_VUC_DISC_IMPACT_DATA |
	    NVME_VUC_DISC_IMPACT_NS)) {
		nvme_vuc_req_fini(vuc);
		return (false);
	}

	if (!nvme_vuc_req_exec(vuc)) {
		nvme_vuc_req_fini(vuc);
		return (false);
	}

	nvme_vuc_req_fini(vuc);
	return (nvme_ctrl_success(ctrl));
}

void
nvme_wdc_e6_req_fini(nvme_wdc_e6_req_t *req)
{
	if (req == NULL) {
		return;
	}

	nvme_vuc_req_fini(req->wer_vuc);
	req->wer_vuc = NULL;
	free(req);
}

bool
nvme_wdc_e6_req_init(nvme_ctrl_t *ctrl, nvme_wdc_e6_req_t **reqp)
{
	nvme_wdc_e6_req_t *req;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_commit_req_t output pointer: %p",
		    reqp));
	}

	if (!nvme_vendor_vuc_supported(ctrl, "wdc/e6dump")) {
		return (false);
	}

	req = calloc(1, sizeof (nvme_wdc_e6_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_wdc_e6_req_t: %s",
		    strerror(e)));
	}

	if (!nvme_vuc_req_init(ctrl, &req->wer_vuc)) {
		nvme_wdc_e6_req_fini(req);
		return (false);
	}

	/*
	 * The documentation suggests we must explicitly set the mode in cdw12
	 * to zero. While that should be the default, we do anyways.
	 */
	if (!nvme_vuc_req_set_opcode(req->wer_vuc, WDC_VUC_E6_DUMP_OPC) ||
	    !nvme_vuc_req_set_cdw12(req->wer_vuc, 0) ||
	    !nvme_vuc_req_set_timeout(req->wer_vuc, nvme_wdc_e6_timeout)) {
		nvme_wdc_e6_req_fini(req);
		return (false);
	}

	for (size_t i = 0; i < ARRAY_SIZE(nvme_wdc_e6_req_fields); i++) {
		if (nvme_wdc_e6_req_fields[i].nlfi_def_req) {
			req->wer_need |= 1 << i;
		}
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_wdc_e6_req_clear_need(nvme_wdc_e6_req_t *req,
    nvme_wdc_e6_req_field_t field)
{
	req->wer_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_wdc_e6_check_off = {
	nvme_wdc_e6_req_fields, NVME_WDC_E6_REQ_FIELD_OFFSET,
	NVME_ERR_WDC_E6_OFFSET_RANGE, 0, 0
};

bool
nvme_wdc_e6_req_set_offset(nvme_wdc_e6_req_t *req, uint64_t off)
{
	nvme_ctrl_t *ctrl = req->wer_vuc->nvr_ctrl;
	uint32_t ndw;

	if (!nvme_field_check_one(ctrl, off, "e6 dump", &nvme_wdc_e6_check_off,
	    0)) {
		return (false);
	}

	ndw = off >> 2;
	if (!nvme_vuc_req_set_cdw13(req->wer_vuc, ndw)) {
		return (false);
	}

	nvme_wdc_e6_req_clear_need(req, NVME_WDC_E6_REQ_FIELD_OFFSET);
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_wdc_e6_req_set_output(nvme_wdc_e6_req_t *req, void *buf, size_t len)
{
	nvme_ctrl_t *ctrl = req->wer_vuc->nvr_ctrl;

	/*
	 * The set output validation handling takes care of all the actual
	 * normal field validation work that we need.
	 */
	if (!nvme_vuc_req_set_output(req->wer_vuc, buf, len)) {
		return (false);
	}

	nvme_wdc_e6_req_clear_need(req, NVME_WDC_E6_REQ_FIELD_LEN);
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_wdc_e6_req_exec(nvme_wdc_e6_req_t *req)
{
	nvme_ctrl_t *ctrl = req->wer_vuc->nvr_ctrl;

	if (req->wer_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_wdc_e6_req_fields,
		    ARRAY_SIZE(nvme_wdc_e6_req_fields),
		    NVME_ERR_WDC_E6_REQ_MISSING_FIELDS, "wdc e6",
		    req->wer_need));
	}

	if (!nvme_vuc_req_exec(req->wer_vuc)) {
		return (false);
	}

	return (nvme_ctrl_success(ctrl));
}
