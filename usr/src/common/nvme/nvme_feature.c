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
 * This file deals with all the knowledge related to supported, standard NVMe
 * features as well as validation of other requests related to features. While
 * there are vendor-specific features, we currently don't support issuing them
 * to the kernel.
 *
 * Like other parts of the common NVMe logic, we have two different sets of data
 * tables to help us drive validation:
 *
 * 1) We have a list of fields that are supported in the kernel ioctl interface
 * and libnvme for features. There are some fields like allowing a specification
 * via UUID which are not currently supported. The field tables are split up
 * among get and set features because they are somewhat different in terms of
 * what they allow (i.e. set features may use cdw12, cdw13, cdw15, etc.) and
 * because the kernel doesn't support issuing set features from userland today.
 *
 * 2) We have a table of NVMe specified required and optional features. This
 * table has dynamic properties related to whether things are supported and the
 * set of fields that are usable because some aspects of this change with the
 * specification version (e.g. the temperature threshold feature had no input
 * argument in cdw11 in NVMe 1.0).
 */

#include "nvme_common.h"

#include <sys/sysmacros.h>
#ifdef	_KERNEL
#include <sys/sunddi.h>
#include <sys/stdint.h>
#else
#include <stdio.h>
#include <inttypes.h>
#endif

static bool
nvme_get_feat_supported_sel(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, char *msg, size_t msglen)
{
	if (data->vcd_id->id_oncs.on_save != 0) {
		return (true);
	}

	(void) snprintf(msg, msglen, "controller does not support field %s "
	    "(%s): missing extended data support in Log Page Attributes (LPA)",
	    field->nlfi_human, field->nlfi_spec);
	return (false);
}

/*
 * An astute observer will note that there is no instance for the DPTR here.
 * While a buffer is required for this command, the common code does not
 * validate buffers. In other pieces we use a length as a proxy for checking the
 * buffer; however, there is no length argument here. The buffer is expected by
 * the controller to be of sufficient size. This is validated by the kernel in
 * nvme_validate_get_feature().
 */
const nvme_field_info_t nvme_get_feat_fields[] = {
	[NVME_GET_FEAT_REQ_FIELD_FID] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = NVME_FEAT_MAX_FID,
		.nlfi_spec = "fid",
		.nlfi_human = "feature identifier",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_GET_FEAT_REQ_FIELD_SEL] = {
		.nlfi_vers = &nvme_vers_1v1,
		.nlfi_sup = nvme_get_feat_supported_sel,
		.nlfi_max_size = NVME_FEAT_MAX_SEL,
		.nlfi_spec = "sel",
		.nlfi_human = "select",
		/*
		 * Because this field was introduced in NVMe 1.1 and because
		 * most of the time we want to assume folks are looking for the
		 * current value, we end up opting to make this a non-required
		 * field and default to getting the current value.
		 */
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_GET_FEAT_REQ_FIELD_CDW11] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT32_MAX,
		.nlfi_spec = "cdw11",
		.nlfi_human = "control dword 11",
		/*
		 * While this isn't required by default, we will end up setting
		 * it as required based on the specifics of the feature and its
		 * version.
		 */
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_GET_FEAT_REQ_FIELD_NSID] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_field_valid_nsid,
		.nlfi_spec = "nsid",
		.nlfi_human = "namespace ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	}
};

size_t nvme_get_feat_nfields = ARRAY_SIZE(nvme_get_feat_fields);

static bool
nvme_feat_write_cache_sup(const nvme_valid_ctrl_data_t *data,
    const nvme_feat_info_t *feat)
{
	return (data->vcd_id->id_vwc.vwc_present != 0);
}

static bool
nvme_feat_apst_sup(const nvme_valid_ctrl_data_t *data,
    const nvme_feat_info_t *feat)
{
	return (data->vcd_id->id_apsta.ap_sup != 0);
}

/*
 * Note, many of these short names come from the history of nvmeadm(8). If you
 * wish to change them, then you must figure out a way to make sure we can still
 * honor the original names. Most fields here try to use a value of 0 as
 * reasonable default so if something's not specified we'll get a reasonable
 * value. For example, NVME_FEAT_MANDATORY, NVME_FEAT_CSI_NONE, etc. all have a
 * value of zero so when that field isn't present we get something reasonable.
 * This leads us to generally define fields that are exceptions to the norm
 * (e.g. when a feature is specific to the NVM feature set).
 */
const nvme_feat_info_t nvme_std_feats[] = { {
	.nfeat_short = "arb",
	.nfeat_spec = "Arbitration",
	.nfeat_fid = NVME_FEAT_ARBITRATION,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "pm",
	.nfeat_spec = "Power Management",
	.nfeat_fid = NVME_FEAT_POWER_MGMT,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "range",
	.nfeat_spec = "LBA Range Type",
	.nfeat_fid = NVME_FEAT_LBA_RANGE,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_OPTIONAL,
	.nfeat_scope = NVME_FEAT_SCOPE_NS,
	.nfeat_csi = NVME_FEAT_CSI_NVM,
	.nfeat_in_get = NVME_GET_FEAT_F_NSID | NVME_GET_FEAT_F_DATA,
	.nfeat_in_set = NVME_SET_FEAT_F_NSID | NVME_SET_FEAT_F_CDW11 |
	    NVME_SET_FEAT_F_DATA,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0 | NVME_FEAT_OUTPUT_DATA,
	.nfeat_len = NVME_LBA_RANGE_BUFSIZE
}, {
	.nfeat_short = "temp",
	.nfeat_spec = "Temperature Threshold",
	.nfeat_fid = NVME_FEAT_TEMPERATURE,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	/*
	 * In NVMe 1.0 and NVMe 1.1, there was only a single temperature sensor
	 * that the spec defined and was present in the threshold feature.
	 * However, starting in NVMe 1.2, this was changed so that a sensor was
	 * required to be specified in NVMe 1.2 to identify the sensor. As such
	 * we always end up saying that this is required.
	 */
	.nfeat_in_get = NVME_GET_FEAT_F_CDW11,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "errrec",
	.nfeat_spec = "Error Recovery",
	.nfeat_fid = NVME_FEAT_ERROR,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_csi = NVME_FEAT_CSI_NVM,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	/*
	 * The scope of this feature has a bit of a complicated history.
	 * Originally we always got this on the controller and that works for
	 * most NVMe 1.0-1.2 devices. The introduction of both namespace
	 * management and of the DULBE option which is namespace specific, made
	 * this more nuanced. The NVMe 1.4 specification makes it clear that
	 * this is namespace specific; however, if we ask for this feature on
	 * many NVMe 1.3 devices with namespace support and some NVMe 1.2, it'll
	 * generate an error about missing namespace information. Unfortunately
	 * namespace management is not a good proxy for this as for example the
	 * Samsung 980 Pro is an NVMe 1.3 device without namespace management
	 * and it will error with invalid namespace if we specify zeros.
	 *
	 * However, most devices that we've surveyed will always answer a GET
	 * FEATURES request with a namespace specified. Therefore, given the
	 * changes that have happened, for now we're going to phrase it scoped
	 * to a namespace and requiring a namespace ID.
	 */
	.nfeat_scope = NVME_FEAT_SCOPE_NS,
	.nfeat_in_get = NVME_GET_FEAT_F_NSID,
	.nfeat_in_set = NVME_SET_FEAT_F_NSID | NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "cache",
	.nfeat_spec = "Volatile Write Cache",
	.nfeat_fid = NVME_FEAT_WRITE_CACHE,
	.nfeat_sup_func = nvme_feat_write_cache_sup,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_OPTIONAL,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "queues",
	.nfeat_spec = "Number of Queues",
	.nfeat_fid = NVME_FEAT_NQUEUES,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	/*
	 * The interrupt coalescing and the interrupt vector configuration
	 * features are required for all PCIe controllers; however, they are not
	 * supported for other types of controllers. As we only support NVMe
	 * PCIe controllers with this library right now we don't do anything
	 * special to denote that. If we do, we will probably want to create an
	 * optional function for determining the kind of feature and leverage
	 * the existing nfeat_sup_func.
	 */
	.nfeat_short = "coalescing",
	.nfeat_spec = "Interrupt Coalescing",
	.nfeat_fid = NVME_FEAT_INTR_COAL,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "vector",
	.nfeat_spec = "Interrupt Vector Configuration",
	.nfeat_fid = NVME_FEAT_INTR_VECT,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_get = NVME_GET_FEAT_F_CDW11,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "atomicity",
	.nfeat_spec = "Write Atomicity",
	.nfeat_fid = NVME_FEAT_WRITE_ATOM,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "event",
	.nfeat_spec = "Asynchronous Event Configuration",
	.nfeat_fid = NVME_FEAT_ASYNC_EVENT,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_MANDATORY,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
}, {
	.nfeat_short = "apst",
	.nfeat_spec = "Autonomous Power State Transition",
	.nfeat_fid = NVME_FEAT_AUTO_PST,
	.nfeat_vers = &nvme_vers_1v1,
	.nfeat_sup_func = nvme_feat_apst_sup,
	.nfeat_kind = NVME_FEAT_OPTIONAL,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_get = NVME_GET_FEAT_F_DATA,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11 | NVME_SET_FEAT_F_DATA,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0 | NVME_FEAT_OUTPUT_DATA,
	.nfeat_len = NVME_AUTO_PST_BUFSIZE
}, {
	.nfeat_short = "progress",
	.nfeat_spec = "Software Progress Marker",
	.nfeat_fid = NVME_FEAT_PROGRESS,
	.nfeat_vers = &nvme_vers_1v0,
	.nfeat_kind = NVME_FEAT_OPTIONAL,
	.nfeat_scope = NVME_FEAT_SCOPE_CTRL,
	.nfeat_in_set = NVME_SET_FEAT_F_CDW11,
	.nfeat_out_get = NVME_FEAT_OUTPUT_CDW0
} };

size_t nvme_std_nfeats = ARRAY_SIZE(nvme_std_feats);

/*
 * Now it's time to answer the only hard question here: is this feature actually
 * supported by the controller. Prior to NVMe 2.x and the Feature Identifiers
 * Supported and Effects page, we have to use a heuristic for this. Our
 * heuristics rules are as follows:
 *
 * 1) If this is a vendor-specific feature that we have identified is present on
 * this controller based on a datasheet, we assume it's present.
 *
 * 2) If the feature was introduced in an NVMe spec version newer than our
 * controller, then it's clearly unsupported.
 *
 * 3) If it is a mandatory feature, we have the right controller type, and we
 * are past the minimum version, then this is supported.
 *
 * 4) If the feature is optional and has an explicit feature bit that indicates
 * whether it's present or not, then we can use that to determine if it's
 * implemented or not.
 *
 * Otherwise we must conclude that we don't know.
 */
nvme_feat_impl_t
nvme_feat_supported(const nvme_feat_info_t *info,
    const nvme_valid_ctrl_data_t *data)
{
	if (info->nfeat_kind == NVME_FEAT_VENDOR_SPECIFIC) {
		return (NVME_FEAT_IMPL_SUPPORTED);
	}

	if (info->nfeat_vers != NULL &&
	    !nvme_vers_atleast(data->vcd_vers, info->nfeat_vers)) {
		return (NVME_FEAT_IMPL_UNSUPPORTED);
	}

	if (info->nfeat_kind == NVME_FEAT_MANDATORY) {
		ASSERT3P(info->nfeat_sup_func, ==, NULL);
		return (NVME_FEAT_IMPL_SUPPORTED);
	}

	if (info->nfeat_sup_func != NULL) {
		if (info->nfeat_sup_func(data, info)) {
			return (NVME_FEAT_IMPL_SUPPORTED);
		}

		return (NVME_FEAT_IMPL_UNSUPPORTED);
	}

	return (NVME_FEAT_IMPL_UNKNOWN);
}
