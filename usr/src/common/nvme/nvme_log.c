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
 * This file deals with validating and issuing various log page requests to an
 * NVMe target. This contains information about all spec-based log pages. The
 * get log page command has added a number of fields that have evolved over
 * time. We validate that we're only sending commands to a device that we expect
 * it to have a chance of understanding. In general, we only allow through
 * unknown log pages that correspond to vendor-specific commands.
 *
 * We have two different tables of information that we use to drive and validate
 * things here:
 *
 * 1) We have a list of fields that exist which include minimum controller
 * versions and related functionality validation routines that operate off of
 * the nvme_t. While tihs list includes things like the CSI and LID, these are
 * things that may only be specified when we have a non-standard log page.
 *
 * 2) We then have a table of log pages that are supported which list which
 * fields we allow for the device. Not all of this can be static.
 *
 * This file has been designed to be shareable between both userland and the
 * kernel since the logic that libnvme wants to use is quite similar.
 */

#include "nvme_common.h"

#include <sys/sysmacros.h>
#ifdef	_KERNEL
#include <sys/sunddi.h>
#include <sys/stdint.h>
#else
#include <stdio.h>
#include <inttypes.h>
#include <strings.h>
#endif

static bool
nvme_log_field_valid_lsp(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t lsp, char *msg, size_t msglen)
{
	uint64_t max;

	if (nvme_field_atleast(data, &nvme_vers_2v0)) {
		max = NVME_LOG_MAX_LSP_2v0;
	} else {
		max = NVME_LOG_MAX_LSP;
	}

	return (nvme_field_range_check(field, 0, max, msg, msglen, lsp));
}

static bool
nvme_log_field_supported_offset(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, char *msg, size_t msglen)
{
	if (data->vcd_id->id_lpa.lp_extsup != 0) {
		return (true);
	}

	(void) snprintf(msg, msglen, "controller does not support field %s "
	    "(%s): missing extended data support in Log Page Attributes (LPA)",
	    field->nlfi_human, field->nlfi_spec);
	return (false);
}

/*
 * The offset is a full 64-bit byte value; however, it must be 4-byte aligned.
 */
static bool
nvme_log_field_valid_offset(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t size, char *msg, size_t msglen)
{
	if ((size % NVME_DWORD_SIZE) != 0) {
		(void) snprintf(msg, msglen, "%s (%s) value 0x%" PRIx64 " is "
		    "invalid: value must be %u-byte aligned", field->nlfi_human,
		    field->nlfi_spec, size, NVME_DWORD_SIZE);
		return (false);
	}

	return (true);
}

static bool
nvme_log_field_valid_size(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t size, char *msg, size_t msglen)
{
	uint64_t max = NVME_LOG_MAX_SIZE;

	if (nvme_field_atleast(data, &nvme_vers_1v2) &&
	    data->vcd_id->id_lpa.lp_extsup != 0) {
		max = NVME_LOG_MAX_SIZE_1v2;
	}

	/*
	 * The NVMe specification operates in terms of uint32_t (dword) units.
	 * Make sure that we are operating within that constraint.
	 */
	if ((size % 4) != 0) {
		(void) snprintf(msg, msglen, "%s (%s) value 0x%" PRIx64 " is "
		    "invalid: value must be 4-byte aligned", field->nlfi_human,
		    field->nlfi_spec, size);
		return (false);
	}

	return (nvme_field_range_check(field, 4, max, msg, msglen, size));
}

const nvme_field_info_t nvme_log_fields[] = {
	[NVME_LOG_REQ_FIELD_LID] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = NVME_LOG_MAX_LID,
		.nlfi_spec = "lid",
		.nlfi_human = "log ID",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_LOG_REQ_FIELD_LSP] = {
		.nlfi_vers = &nvme_vers_1v3,
		.nlfi_valid = nvme_log_field_valid_lsp,
		.nlfi_spec = "lsp",
		.nlfi_human = "log specific field",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_LOG_REQ_FIELD_LSI] = {
		.nlfi_vers = &nvme_vers_1v4,
		.nlfi_max_size = NVME_LOG_MAX_LSI,
		.nlfi_spec = "lsi",
		.nlfi_human = "log specific ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_LOG_REQ_FIELD_SIZE] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_log_field_valid_size,
		.nlfi_spec = "dptr/numd",
		.nlfi_human = "output",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_LOG_REQ_FIELD_CSI] = {
		.nlfi_vers = &nvme_vers_2v0,
		/*
		 * This has the field's maximum range right now, though NVMe 2.0
		 * only defines a few values. Because the kernel only allows
		 * through known log pages, we don't really bother to check the
		 * condensed range and allow vendor-specific logs to go wild.
		 */
		.nlfi_max_size = NVME_LOG_MAX_CSI,
		.nlfi_spec = "csi",
		.nlfi_human = "command set ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_LOG_REQ_FIELD_RAE] = {
		.nlfi_vers = &nvme_vers_1v3,
		.nlfi_max_size = NVME_LOG_MAX_RAE,
		.nlfi_spec = "rae",
		.nlfi_human = "retain asynchronous event",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_LOG_REQ_FIELD_OFFSET] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_sup = nvme_log_field_supported_offset,
		.nlfi_valid = nvme_log_field_valid_offset,
		.nlfi_max_size = NVME_LOG_MAX_OFFSET,
		.nlfi_spec = "lpo",
		.nlfi_human = "log offset",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_LOG_REQ_FIELD_NSID] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_field_valid_nsid,
		.nlfi_spec = "nsid",
		.nlfi_human = "namespace ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	}
};

size_t nvme_log_nfields = ARRAY_SIZE(nvme_log_fields);

static uint64_t
nvme_lpd_error_len(const nvme_valid_ctrl_data_t *data,
    const nvme_log_page_info_t *lpi)
{
	const uint64_t nents = data->vcd_id->id_elpe + 1;
	const uint64_t logsz = nents * sizeof (nvme_error_log_entry_t);

	return (logsz);
}

static nvme_log_disc_scope_t
nvme_lpd_health_scope(const nvme_valid_ctrl_data_t *data,
    const nvme_log_page_info_t *lpi)
{
	nvme_log_disc_scope_t ret = NVME_LOG_SCOPE_CTRL;

	if (nvme_field_atleast(data, &nvme_vers_1v0) &&
	    data->vcd_id->id_lpa.lp_smart != 0) {
		ret |= NVME_LOG_SCOPE_NS;
	}

	return (ret);
}

static bool
nvme_lpd_changens_sup(const nvme_valid_ctrl_data_t *data,
    const nvme_log_page_info_t *lpi)
{
	return (nvme_field_atleast(data, &nvme_vers_1v2) &&
	    data->vcd_id->id_oaes.oaes_nsan != 0);
}

static bool
nvme_lpd_cmdeff_sup(const nvme_valid_ctrl_data_t *data,
    const nvme_log_page_info_t *lpi)
{
	return (nvme_field_atleast(data, &nvme_vers_1v2) &&
	    data->vcd_id->id_lpa.lp_cmdeff != 0);
}

static bool
nvme_lpd_pev_sup(const nvme_valid_ctrl_data_t *data,
    const nvme_log_page_info_t *lpi)
{
	return (nvme_field_atleast(data, &nvme_vers_1v4) &&
	    data->vcd_id->id_lpa.lp_persist != 0);
}

static bool
nvme_lpd_pev_len(uint64_t *outp, const void *data, size_t len)
{
	nvme_pev_log_t pev;

	if (len < sizeof (pev)) {
		return (false);
	}

	(void) memcpy(&pev, data, sizeof (pev));
	*outp = pev.pel_tll;
	return (true);
}

/*
 * The short names here correspond to the well defined names in nvmeadm(8) and
 * libnvme(3LIB) that users expect to be able to use. Please do not change them
 * without accounting for aliases and backwards compatibility.
 */
const nvme_log_page_info_t nvme_std_log_pages[] = { {
	.nlpi_short = "suplog",
	.nlpi_human = "Supported Log Pages",
	.nlpi_lid = NVME_LOGPAGE_SUP,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_vers = &nvme_vers_2v0,
	.nlpi_kind = NVME_LOG_ID_MANDATORY,
	.nlpi_source = NVME_LOG_DISC_S_SPEC,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (nvme_suplog_log_t)
}, {
	.nlpi_short = "error",
	.nlpi_human = "Error information",
	.nlpi_lid = NVME_LOGPAGE_ERROR,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_vers = &nvme_vers_1v0,
	.nlpi_kind = NVME_LOG_ID_MANDATORY,
	.nlpi_source = NVME_LOG_DISC_S_SPEC,
	.nlpi_disc = NVME_LOG_DISC_F_NEED_RAE,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len_func = nvme_lpd_error_len
}, {
	.nlpi_short = "health",
	.nlpi_human = "SMART / Health information",
	.nlpi_lid = NVME_LOGPAGE_HEALTH,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_vers = &nvme_vers_1v0,
	.nlpi_kind = NVME_LOG_ID_MANDATORY,
	.nlpi_source = NVME_LOG_DISC_S_SPEC | NVME_LOG_DISC_S_ID_CTRL,
	.nlpi_disc = NVME_LOG_DISC_F_NEED_RAE,
	.nlpi_scope_func = nvme_lpd_health_scope,
	.nlpi_len = sizeof (nvme_health_log_t)
}, {
	.nlpi_short = "firmware",
	.nlpi_human = "Firmware Slot Information",
	.nlpi_lid = NVME_LOGPAGE_FWSLOT,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_vers = &nvme_vers_1v0,
	.nlpi_kind = NVME_LOG_ID_MANDATORY,
	.nlpi_source = NVME_LOG_DISC_S_SPEC,
	.nlpi_disc = 0,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (nvme_fwslot_log_t),
}, {
	.nlpi_short = "changens",
	.nlpi_human = "changed namespaces",
	.nlpi_lid = NVME_LOGPAGE_NSCHANGE,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_vers = &nvme_vers_1v2,
	.nlpi_sup_func = nvme_lpd_changens_sup,
	.nlpi_kind = NVME_LOG_ID_OPTIONAL,
	.nlpi_source = NVME_LOG_DISC_S_ID_CTRL,
	.nlpi_disc = NVME_LOG_DISC_F_NEED_RAE,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (nvme_nschange_list_t)
}, {
	.nlpi_short = "cmdeff",
	.nlpi_human = "commands supported and effects",
	.nlpi_lid = NVME_LOGPAGE_CMDSUP,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_vers = &nvme_vers_1v2,
	.nlpi_sup_func = nvme_lpd_cmdeff_sup,
	.nlpi_kind = NVME_LOG_ID_OPTIONAL,
	.nlpi_source = NVME_LOG_DISC_S_ID_CTRL,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (nvme_cmdeff_log_t)
}, {
	.nlpi_short = "pev",
	.nlpi_human = "persistent event log",
	.nlpi_lid = NVME_LOGPAGE_PEV,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_vers = &nvme_vers_1v4,
	.nlpi_sup_func = nvme_lpd_pev_sup,
	.nlpi_kind = NVME_LOG_ID_OPTIONAL,
	.nlpi_source = NVME_LOG_DISC_S_ID_CTRL,
	.nlpi_disc = NVME_LOG_DISC_F_NEED_LSP,
	.nlpi_scope = NVME_LOG_SCOPE_NVM,
	.nlpi_len = sizeof (nvme_pev_log_t),
	.nlpi_var_func = nvme_lpd_pev_len
} };

size_t nvme_std_log_npages = ARRAY_SIZE(nvme_std_log_pages);

nvme_log_disc_scope_t
nvme_log_page_info_scope(const nvme_log_page_info_t *info,
    const nvme_valid_ctrl_data_t *data)
{
	if (info->nlpi_scope_func != NULL) {
		return (info->nlpi_scope_func(data, info));
	} else {
		return (info->nlpi_scope);
	}
}

uint64_t
nvme_log_page_info_size(const nvme_log_page_info_t *info,
    const nvme_valid_ctrl_data_t *data, bool *var)
{
	uint64_t len;
	*var = info->nlpi_var_func != NULL;

	if (info->nlpi_len_func != NULL) {
		len = info->nlpi_len_func(data, info);
	} else {
		len = info->nlpi_len;
	}

	/*
	 * Some vendor-specific log pages are not documented to have 4-byte
	 * aligned lengths. This means that to get the full log page you must
	 * round this up to ensure that you end up with a valid request. We opt
	 * to do this here rather than have to check every single log page data
	 * structure and fix it up manually. While it means consumers that are
	 * using this to ignore information about the type itself may
	 * erroneously display extra bytes (e.g. nvmeadm's default hex dumper),
	 * that's better than getting an error or truncating the data.
	 */
	return (P2ROUNDUP(len, NVME_DWORD_SIZE));
}

bool
nvme_log_page_info_supported(const nvme_log_page_info_t *info,
    const nvme_valid_ctrl_data_t *data)
{
	bool vers, sup_func;

	if (info->nlpi_vers != NULL) {
		vers = nvme_field_atleast(data, info->nlpi_vers);
	} else {
		vers = true;
	}

	if (info->nlpi_sup_func != NULL) {
		sup_func = info->nlpi_sup_func(data, info);
	} else {
		sup_func = true;
	}

	return (vers && sup_func);
}
