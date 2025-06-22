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
 * Perform various validation checks for user and kernel initiated requests.
 * This file focuses on the validation of NVMe semantic operations. It assumes
 * that any necessary permission checks (privileges, exclusive access, etc.)
 * are being taken care of separately.
 *
 * Log Pages
 * ---------
 *
 * Log page requests come into the kernel and we have a few different
 * constraints that we need to consider while performing validation. There are a
 * few different gotchas:
 *
 * 1) The arguments that one can pass to a get log page command have changed
 * over the different device revisions. While specifying the log page ID (lid)
 * has always been supported, a log-specific field (lsp) was added in NVMe 1.3,
 * and the ability to specify a command-set identifier (csi) was added in NVMe
 * 2.0. Regardless of whether this is a vendor-specific command or not, we need
 * to be able to validate that we're not going to send parameters to the
 * controller that will cause the command to be rejected.
 *
 * 2) There are going to be log pages that we know about and some that we don't.
 * At the moment, we constrain non-admin pass through log pages to be log pages
 * that the kernel knows about and therefore has an expected size for. This
 * means that there is a lot more that we can check and enforce, such as whether
 * or not specific pages support an lsp, lsi, etc. Conversely, for log pages
 * that are admin pass-through commands, there's not a whole lot that we can
 * actually do and will only do the version-specific checking.
 *
 * For any log page request that comes in, we'll try to identify which of the
 * different types of log pages that it is, and go through and validate it
 * appropriately.
 *
 * Get Feature
 * -----------
 *
 * Currently, the kernel only allows standard features to be requested that it
 * knows about. This will be loosened and look a little bit more like log pages
 * when we have support for vendor-unique features.
 *
 * Like with log pages, in addition to the set of features having evolved, the
 * arguments to the get features command has also changed to include additions
 * like whether you want the default or saved value of a feature rather than its
 * current value.
 *
 * One general complication with features is that for a number of optional
 * features, there is no good way to know whether or not the device supports
 * said feature other than asking for it.
 *
 * The last bit we need to be cognizant of is the fact that only a handful of
 * features accept a namespace ID. Those that do, may not even support the use
 * of a broadcast namespace ID. While the controller node may ask for any
 * feature, those using a namespace node are limited in terms of what they can
 * actually issue.
 *
 * Identify
 * --------
 *
 * The kernel currently knows about the various identify data structure commands
 * that it supports. It does this to enforce checking the version and if certain
 * fields are set. The most complicated form of this is related to the namespace
 * due to the fact that identify commands come in a few forms:
 *
 * 1) Identify commands that do not use a namespace ID at all (like identify
 * controller).
 * 2) Identify commands that are used to list namespaces. These allow a zero to
 * be listed in the namespace ID field to ensure all namespaces are captured.
 * 3) Identify commands that require a valid namespace and allow the broadcast
 * namespace ID to be specified.
 * 4) Identify commands that require a valid namespace and do not allow for a
 * broadcast namespace ID to be specified.
 *
 * The cases here are identified based on flags in the nvme_identify_info_t. We
 * must check the entire validity here.
 *
 * Vendor Unique Commands
 * ----------------------
 *
 * When it comes to vendor unique commands, the main things that we try to
 * validate are limited to what the specification requires of the shape of these
 * commands and the constraints that we have. While there is discovery
 * functionality in libnvme, we explicitly are not trying to leverage and know
 * what those are here. This makes things fairly different to both identify
 * commands and log pages.
 *
 * Format Requests
 * ---------------
 *
 * There are a few different things that we need to check before we allow a
 * format request to proceed. Note, some of these are artificial constraints
 * that we have opted to place in the driver right now. In particular, right now
 * we don't support any namespaces with metadata or protection. There is no way
 * to set this right now in our ioctl interface. Therefore, this stuff is not
 * verified.
 *
 * 1) First we must verify that the controller actually supports the Format NVM
 * command at all.
 *
 * 2) Once that is good, we must validate the secure erase settings and that the
 * LBA format is valid.
 *
 * 3) A controller can limit whether a secure erase or a format must impact the
 * whole device or not.
 *
 * Firmware Download and Commit
 * ----------------------------
 *
 * Validating a firmware download request is fairly straightforward. Here we're
 * mostly checking that the requested sizes and offsets have the proper
 * alignment and aren't beyond the underlying command's maximum sizes. We also
 * verify whether or not the device actually supports firmware download requests
 * at all. We don't try to validate the contents of the data or ask if there are
 * other ongoing things or if we've skipped gaps in the download by changing
 * offsets.
 *
 * When we opt to perform a firmware commit, then all we check is that the
 * command is supported, that we aren't going to a read-only slot when saving,
 * or related.
 *
 * Namesapce Management
 * --------------------
 *
 * Namespace management consists of four commands: namespace create, namespace
 * delete, controller attach, and controller detach. Namespace create is the
 * most complicated of these. A namespace create must first validate that we
 * support namespace management. After that, we have to validate all of the
 * different fields that will be submitted through the identify namespace data
 * structure.
 *
 * We do not attempt to validate whether or not there is sufficient capacity to
 * create the namespace and leave that to the controller and the backend.
 * However, we do verify if the request does require thin provisioning support.
 * Most other fields are basic range checks against what's supported in the
 * version. We are looser on the LBA format for a create namespace to allow for
 * more flexibility and just require that the LBA is within range for the
 * device.
 *
 * The most notable piece here is the CSI. Create namespace adds the notion of a
 * CSI starting in NVME 2.0. Prior to this, it is implicitly the NVM CSI. Right
 * now the kernel only supports the NVM command set and therefore restricts
 * namespace creation to that CSI.
 *
 * Namespace delete is straightforward. The only thing that we need to validate
 * is that the device supports namespace commands as the surrounding kernel code
 * ensures that the namespace is both valid and in the correct state. Attaching
 * and detaching a controller to a namespace is the same as we currently only
 * support attaching and detaching with the controller that we're talking
 * through.
 */

#include <sys/sysmacros.h>
#include <sys/nvme.h>

#include "nvme_reg.h"
#include "nvme_var.h"

typedef struct nvme_validate_info {
	const nvme_field_info_t		*err_fields;
	size_t				err_index;
	uint32_t			err_unuse_bit;
	nvme_ioctl_errno_t		err_field_range;
	nvme_ioctl_errno_t		err_field_unsup;
	nvme_ioctl_errno_t		err_field_unuse;
} nvme_validate_info_t;

static boolean_t
nvme_validate_one_field(nvme_ioctl_common_t *com, uint64_t val,
    const nvme_validate_info_t *info, const nvme_valid_ctrl_data_t *data,
    uint32_t valid)
{
	const nvme_field_info_t *field = &info->err_fields[info->err_index];
	nvme_field_error_t err;

	if (val == 0) {
		return (B_TRUE);
	}

	if (valid != 0 && info->err_unuse_bit != 0 &&
	    (valid & info->err_unuse_bit) == 0) {
		VERIFY3U(info->err_field_unuse, !=, 0);
		return (nvme_ioctl_error(com, info->err_field_unuse, 0, 0));
	}

	err = nvme_field_validate(field, data, val, NULL, 0);
	switch (err) {
	case NVME_FIELD_ERR_UNSUP_VERSION:
	case NVME_FIELD_ERR_UNSUP_FIELD:
		VERIFY3U(info->err_field_unsup, !=, 0);
		return (nvme_ioctl_error(com, info->err_field_unsup, 0, 0));
	case NVME_FIELD_ERR_BAD_VALUE:
		VERIFY3U(info->err_field_range, !=, 0);
		return (nvme_ioctl_error(com, info->err_field_range, 0, 0));
	case NVME_FIELD_ERR_OK:
		return (B_TRUE);
	default:
		panic("unsupported nvme_field_validate() value: 0x%x", err);
	}
}

/*
 * NVMe devices specify log page requests in units of uint32_t's. The original
 * spec had a zeros based value that was 12 bits wide, providing a little over
 * 16 KiB for a log page. In NVMe 1.3, this was changed and a device could
 * optionally support a 32-bit wide length argument. We opt to support a smaller
 * amount than the NVMe 1.3 maximum: 1 MiB, which is a fairly arbitrary sized
 * value.
 */
uint32_t nvme_log_page_max_size = 1 * 1024 * 1024;

static boolean_t
nvme_logpage_is_vendor(nvme_ioctl_get_logpage_t *log)
{
	return (log->nigl_lid >= NVME_LOGPAGE_VEND_MIN &&
	    log->nigl_lid <= NVME_LOGPAGE_VEND_MAX);
}

static const nvme_validate_info_t nvme_valid_log_csi = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_CSI, 0,
	NVME_IOCTL_E_LOG_CSI_RANGE, 0, NVME_IOCTL_E_LOG_CSI_UNSUP
};

static const nvme_validate_info_t nvme_valid_log_lid = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_LID, 0,
	NVME_IOCTL_E_LOG_LID_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_log_lsp = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_LSP,
	NVME_LOG_DISC_F_NEED_LSP, NVME_IOCTL_E_LOG_LSP_RANGE,
	NVME_IOCTL_E_LOG_LSP_UNSUP, NVME_IOCTL_E_LOG_LSP_UNUSE
};

static const nvme_validate_info_t nvme_valid_log_lsi = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_LSI,
	NVME_LOG_DISC_F_NEED_LSI, NVME_IOCTL_E_LOG_LSI_RANGE,
	NVME_IOCTL_E_LOG_LSI_UNSUP, NVME_IOCTL_E_LOG_LSI_UNUSE
};

static const nvme_validate_info_t nvme_valid_log_rae = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_RAE,
	NVME_LOG_DISC_F_NEED_RAE, NVME_IOCTL_E_LOG_RAE_RANGE,
	NVME_IOCTL_E_LOG_RAE_UNSUP, NVME_IOCTL_E_LOG_RAE_UNUSE
};

static const nvme_validate_info_t nvme_valid_log_size = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_SIZE, 0,
	NVME_IOCTL_E_LOG_SIZE_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_log_offset = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_OFFSET, 0,
	NVME_IOCTL_E_LOG_OFFSET_RANGE, 0, NVME_IOCTL_E_LOG_OFFSET_UNSUP
};

/*
 * Validate all of the fields that are present in a log request. The only one we
 * don't take care of here is the namespace ID, because we have already checked
 * it prior to this as part of nvme_ioctl_check().
 */
static boolean_t
nvme_validate_logpage_fields(nvme_ioctl_get_logpage_t *log,
    const nvme_valid_ctrl_data_t *ctrl_data, const nvme_log_page_info_t *info)
{
	uint32_t disc = 0;

	if (info != NULL) {
		disc = info->nlpi_disc;
	}

	if (!nvme_validate_one_field(&log->nigl_common, log->nigl_csi,
	    &nvme_valid_log_csi, ctrl_data, disc)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&log->nigl_common, log->nigl_lid,
	    &nvme_valid_log_lid, ctrl_data, disc)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&log->nigl_common, log->nigl_lsp,
	    &nvme_valid_log_lsp, ctrl_data, disc)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&log->nigl_common, log->nigl_lsi,
	    &nvme_valid_log_lsi, ctrl_data, disc)) {
		return (B_FALSE);
	}

	/*
	 * Just like the LID, we treat the size as having two of the same error
	 * type right now as it's always been supported since NVMe 1.0. The
	 * common check confirms that the value is non-zero and that it is
	 * 4-byte aligned.
	 */
	if (!nvme_validate_one_field(&log->nigl_common, log->nigl_len,
	    &nvme_valid_log_size, ctrl_data, disc)) {
		return (B_FALSE);
	}

	/*
	 * Ensure that the log page does not exceed the kernel's maximum size
	 * that one can get in one request.
	 */
	if (log->nigl_len > nvme_log_page_max_size) {
		return (nvme_ioctl_error(&log->nigl_common,
		    NVME_IOCTL_E_LOG_SIZE_RANGE, 0, 0));
	}

	if (!nvme_validate_one_field(&log->nigl_common, log->nigl_rae,
	    &nvme_valid_log_rae, ctrl_data, disc)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&log->nigl_common, log->nigl_offset,
	    &nvme_valid_log_offset, ctrl_data, disc)) {
		return (B_FALSE);
	}

	/*
	 * Log pages may either have a known fixed size, a variable size, or an
	 * unknown size. If we have a log page with a known, fixed size, then we
	 * require that the requested size match that and we do not allow an
	 * offset to be specified at this time. Otherwise, there is nothing to
	 * check for a variable length page as we have constrained everything by
	 * the maximum size above. As we encounter fixed size log pages that
	 * exceed the kernel's maximum value, we will likely have to change this
	 * in the future.
	 */
	if (info != NULL) {
		bool var;
		size_t targ = nvme_log_page_info_size(info, ctrl_data, &var);

		if (!var) {
			if (targ != 0 && targ != log->nigl_len) {
				return (nvme_ioctl_error(&log->nigl_common,
				    NVME_IOCTL_E_LOG_SIZE_RANGE, 0, 0));
			}

			if (log->nigl_offset != 0) {
				return (nvme_ioctl_error(&log->nigl_common,
				    NVME_IOCTL_E_LOG_OFFSET_RANGE, 0, 0));
			}
		}
	}

	return (B_TRUE);
}

/*
 * Validating a log page comes in a series of a few different steps. Once we
 * identify that this is a known log page, we first validate that our controller
 * actually supports the command. Once we know that, then we'll move onto the
 * question of whether we have an appropriate scope. After that we go through
 * and make sure all of the fields are set appropriately for the log page.
 */
boolean_t
nvme_validate_logpage(nvme_t *nvme, nvme_ioctl_get_logpage_t *log)
{
	const nvme_log_page_info_t *info = NULL;
	nvme_valid_ctrl_data_t ctrl_data;
	nvme_log_disc_scope_t scope, req_scope;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	if (nvme_logpage_is_vendor(log)) {
		return (nvme_validate_logpage_fields(log, &ctrl_data, NULL));
	}

	for (size_t i = 0; i < nvme_std_log_npages; i++) {
		if (nvme_std_log_pages[i].nlpi_csi == log->nigl_csi &&
		    nvme_std_log_pages[i].nlpi_lid == log->nigl_lid) {
			info = &nvme_std_log_pages[i];
			break;
		}
	}

	if (info == NULL) {
		return (nvme_ioctl_error(&log->nigl_common,
		    NVME_IOCTL_E_UNKNOWN_LOG_PAGE, 0, 0));
	}

	if (!nvme_log_page_info_supported(info, &ctrl_data)) {
		return (nvme_ioctl_error(&log->nigl_common,
		    NVME_IOCTL_E_UNSUP_LOG_PAGE, 0, 0));
	}

	scope = nvme_log_page_info_scope(info, &ctrl_data);
	if (log->nigl_common.nioc_nsid == NVME_NSID_BCAST) {
		req_scope = NVME_LOG_SCOPE_CTRL | NVME_LOG_SCOPE_NVM;
	} else {
		req_scope = NVME_LOG_SCOPE_NS;
	}

	if ((scope & req_scope) == 0) {
		return (nvme_ioctl_error(&log->nigl_common,
		    NVME_IOCTL_E_BAD_LOG_SCOPE, 0, 0));
	}

	return (nvme_validate_logpage_fields(log, &ctrl_data, info));
}

static const nvme_validate_info_t nvme_valid_get_feat_sel = {
	nvme_get_feat_fields, NVME_GET_FEAT_REQ_FIELD_SEL, 0,
	NVME_IOCTL_E_GET_FEAT_SEL_RANGE, NVME_IOCTL_E_GET_FEAT_SEL_UNSUP, 0
};

static const nvme_validate_info_t nvme_valid_get_feat_cdw11 = {
	nvme_get_feat_fields, NVME_GET_FEAT_REQ_FIELD_CDW11,
	NVME_GET_FEAT_F_CDW11, NVME_IOCTL_E_GET_FEAT_CDW11_RANGE,
	0, NVME_IOCTL_E_GET_FEAT_CDW11_UNUSE
};

/*
 * To validate a feature we take the following high-level steps:
 *
 * 1) First, we have to determine that this is a feature that we know about.
 * 2) Ensure that this feature is actually supported. We may not be able to
 * confirm that it is, but we can sometimes confirm that it is not. Do not
 * execute any unsupported features.
 * 3) We have to determine whether we can actually issue this feature with the
 * specified namespace or not.
 * 4) Go through and validate all the remaining fields.
 */
boolean_t
nvme_validate_get_feature(nvme_t *nvme, nvme_ioctl_get_feature_t *get)
{
	const nvme_feat_info_t *feat = NULL;
	const uint32_t nsid = get->nigf_common.nioc_nsid;
	nvme_valid_ctrl_data_t ctrl_data;
	nvme_feat_impl_t impl;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	for (size_t i = 0; i < nvme_std_nfeats; i++) {
		if (nvme_std_feats[i].nfeat_fid == get->nigf_fid) {
			feat = &nvme_std_feats[i];
			break;
		}
	}

	if (feat == NULL) {
		return (nvme_ioctl_error(&get->nigf_common,
		    NVME_IOCTL_E_UNKNOWN_FEATURE, 0, 0));
	}

	/*
	 * Before we do anything else, determine if this is supported. For
	 * things that are unknown, there is naught we can do, but try.
	 */
	impl = nvme_feat_supported(feat, &ctrl_data);
	if (impl == NVME_FEAT_IMPL_UNSUPPORTED) {
		return (nvme_ioctl_error(&get->nigf_common,
		    NVME_IOCTL_E_UNSUP_FEATURE, 0, 0));
	}

	/*
	 * To check the namespace related information we rely on whether the get
	 * fields indicates a namespace is required or not. We prefer to use
	 * this rather than the scope as we've seen log pages that end up
	 * supporting multiple scopes. If a namespace is specified, but there is
	 * not one required for the feature, then we assume that this is an
	 * attempt to read something from the controller node. After that we
	 * must check if the broadcast namespace is allowed.
	 *
	 * Conversely, if a namespace is required, then we can't be on the
	 * generic controller node with the namespace left as 0.
	 */
	if ((feat->nfeat_in_get & NVME_GET_FEAT_F_NSID) != 0) {
		if (nsid == 0 || (nsid == NVME_NSID_BCAST &&
		    (feat->nfeat_flags & NVME_FEAT_F_GET_BCAST_NSID) == 0)) {
			return (nvme_ioctl_error(&get->nigf_common,
			    NVME_IOCTL_E_NS_RANGE, 0, 0));
		}
	} else {
		if (nsid != 0) {
			return (nvme_ioctl_error(&get->nigf_common,
			    NVME_IOCTL_E_NS_UNUSE, 0, 0));
		}
	}

	/*
	 * The last step is to perform field validation. Note, we've already
	 * validated the nsid above and we skip validating the fid because we've
	 * already taken care of that by selecting for a valid feature. For a
	 * get features, this leaves us with cdw11, a data pointer, and the
	 * 'sel' field. We validate the sel field first. If we find a request
	 * that is asking for the supported capabilities, then we will change
	 * our validation policy and require that the other fields explicitly be
	 * zero to proceed.
	 */
	if (!nvme_validate_one_field(&get->nigf_common, get->nigf_sel,
	    &nvme_valid_get_feat_sel, &ctrl_data, feat->nfeat_in_get)) {
		return (B_FALSE);
	}

	if (get->nigf_sel == NVME_FEATURE_SEL_SUPPORTED) {
		if (get->nigf_cdw11 != 0) {
			return (nvme_ioctl_error(&get->nigf_common,
			    NVME_IOCTL_E_GET_FEAT_CDW11_UNUSE, 0, 0));
		}

		if (get->nigf_data != 0 || get->nigf_len != 0) {
			return (nvme_ioctl_error(&get->nigf_common,
			    NVME_IOCTL_E_GET_FEAT_DATA_UNUSE, 0, 0));
		}

		return (B_TRUE);
	}

	if (!nvme_validate_one_field(&get->nigf_common, get->nigf_cdw11,
	    &nvme_valid_get_feat_cdw11, &ctrl_data, feat->nfeat_in_get)) {
		return (B_FALSE);
	}

	/*
	 * The last piece we need to do here is validate the size that we've
	 * been given. There are no size/offset fields in the get feature
	 * request unlike with get log page. Therefore we must be given a data
	 * buffer that matches exactly what the feature requires.
	 */
	if ((feat->nfeat_in_get & NVME_GET_FEAT_F_DATA) == 0) {
		if (get->nigf_data != 0 || get->nigf_len != 0) {
			return (nvme_ioctl_error(&get->nigf_common,
			    NVME_IOCTL_E_GET_FEAT_DATA_UNUSE, 0, 0));
		}
	} else {
		if (get->nigf_data == 0 || get->nigf_len != feat->nfeat_len) {
			return (nvme_ioctl_error(&get->nigf_common,
			    NVME_IOCTL_E_GET_FEAT_DATA_RANGE, 0, 0));
		}
	}

	/*
	 * In the past, the driver also checked a few of the specific values of
	 * cdw11 against information that the kernel had such as the maximum
	 * number of interrupts that we had configured or the valid temperature
	 * types in the temperature thrshold. In the future, if we wanted to add
	 * a cdw11-specific validation, this is where we'd want to insert it
	 * roughly.
	 */

	return (B_TRUE);
}

static const nvme_validate_info_t nvme_valid_identify_nsid = {
	nvme_identify_fields, NVME_ID_REQ_F_NSID,
	1 << NVME_ID_REQ_F_NSID, NVME_IOCTL_E_NS_RANGE, 0,
	NVME_IOCTL_E_NS_UNUSE
};

static const nvme_validate_info_t nvme_valid_identify_ctrlid = {
	nvme_identify_fields, NVME_ID_REQ_F_CTRLID,
	1 << NVME_ID_REQ_F_CTRLID, NVME_IOCTL_E_IDENTIFY_CTRLID_RANGE,
	NVME_IOCTL_E_IDENTIFY_CTRLID_UNSUP, NVME_IOCTL_E_IDENTIFY_CTRLID_UNUSE
};

boolean_t
nvme_validate_identify(nvme_t *nvme, nvme_ioctl_identify_t *id,
    boolean_t ns_minor)
{
	const nvme_identify_info_t *info = NULL;
	nvme_valid_ctrl_data_t ctrl_data;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	for (size_t i = 0; i < nvme_identify_ncmds; i++) {
		if (nvme_identify_cmds[i].nii_csi == NVME_CSI_NVM &&
		    nvme_identify_cmds[i].nii_cns == id->nid_cns) {
			info = &nvme_identify_cmds[i];
			break;
		}
	}

	if (info == NULL) {
		return (nvme_ioctl_error(&id->nid_common,
		    NVME_IOCTL_E_UNKNOWN_IDENTIFY, 0, 0));
	}

	if (!nvme_identify_info_supported(info, &ctrl_data)) {
		return (nvme_ioctl_error(&id->nid_common,
		    NVME_IOCTL_E_UNSUP_IDENTIFY, 0, 0));
	}

	/*
	 * Now it's time for our favorite thing, checking the namespace. Unlike
	 * other validation routines, we can't rely on the general ioctl
	 * checking logic due to all the variations of namespace usage in
	 * commands. See the Identify Commands section of the theory statement
	 * for more information.
	 *
	 * Note: we do not explicitly test the CNS field for validity as we do
	 * the others below as we only allow known CNS values which are
	 * determined above. In addition, we don't use the full generic field
	 * validation for the nsid because it was valid in NVMe 1.0 and its size
	 * hasn't changed throughout.
	 *
	 * First, check that if we're issuing a command that doesn't allow a
	 * namespace to call it, that we've not specified one. In particular, a
	 * namespace minor would already have had its nsid set here, so this is
	 * what would cause us to fail that.
	 */
	if ((info->nii_flags & NVME_IDENTIFY_INFO_F_NS_OK) == 0 && ns_minor) {
		return (nvme_ioctl_error(&id->nid_common, NVME_IOCTL_E_NOT_CTRL,
		    0, 0));
	}

	/*
	 * If we've been told that the broadcast namespace is usable here,
	 * translate that first if we can use it. Otherwise we need to try and
	 * translate this to a namespace ID that'll hopefully have some
	 * information, which means we try nsid 1.
	 */
	if ((info->nii_flags & NVME_IDENTIFY_INFO_F_BCAST) != 0 &&
	    id->nid_common.nioc_nsid == 0) {
		if (nvme_ctrl_atleast(nvme, &nvme_vers_1v2) &&
		    nvme->n_idctl->id_oacs.oa_nsmgmt != 0) {
			id->nid_common.nioc_nsid = NVME_NSID_BCAST;
		} else {
			id->nid_common.nioc_nsid = 1;
		}
	}

	/*
	 * Perform namespace ID check. We have three different groups of
	 * commands here that we need to consider and all have different
	 * handling:
	 *
	 * 1) Commands that must not have a namespace specified.
	 * 2) Commands which require a namespace ID, but whether the
	 *    broadcast namespace can be used is variable.
	 * 3) Commands which are listing namespaces and therefore can take any
	 *    value in the namespace list.
	 *
	 * In addition, because of all the weird semantics above, we have not
	 * leveraged our common ioctl logic for checking whether or not the
	 * namespace is valid. In addition, the general field checking logic
	 * allows a zero here. So for case (1) and (2) we start with the normal
	 * field check. Then we verify a non-zero and broadcast namespace check
	 * for (2). For (3), anything goes. Note, we've already verified the
	 * minor is allowed to use this.
	 */
	if ((info->nii_flags & NVME_IDENTIFY_INFO_F_NSID_LIST) == 0 &&
	    !nvme_validate_one_field(&id->nid_common, id->nid_common.nioc_nsid,
	    &nvme_valid_identify_nsid, &ctrl_data, info->nii_fields)) {
		return (B_FALSE);
	}

	if ((info->nii_fields & (1 << NVME_ID_REQ_F_NSID)) != 0 &&
	    (info->nii_flags & NVME_IDENTIFY_INFO_F_NSID_LIST) == 0) {
		const uint32_t ns = id->nid_common.nioc_nsid;
		boolean_t allow_bcast = (info->nii_flags &
		    NVME_IDENTIFY_INFO_F_BCAST) != 0;

		if (ns == 0 || ns > nvme->n_namespace_count) {
			if (ns != NVME_NSID_BCAST) {
				return (nvme_ioctl_error(&id->nid_common,
				    NVME_IOCTL_E_NS_RANGE, 0, 0));
			} else if (!allow_bcast) {
				return (nvme_ioctl_error(&id->nid_common,
				    NVME_IOCTL_E_NO_BCAST_NS, 0, 0));
			}
		}
	}

	if (!nvme_validate_one_field(&id->nid_common, id->nid_ctrlid,
	    &nvme_valid_identify_ctrlid, &ctrl_data, info->nii_fields)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static const nvme_validate_info_t nvme_valid_vuc_opcode = {
	nvme_vuc_fields, NVME_VUC_REQ_FIELD_OPC, 0,
	NVME_IOCTL_E_VUC_OPCODE_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_vuc_nsid = {
	nvme_vuc_fields, NVME_VUC_REQ_FIELD_NSID, 0,
	NVME_IOCTL_E_NS_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_vuc_ndt = {
	nvme_vuc_fields, NVME_VUC_REQ_FIELD_NDT, 0,
	NVME_IOCTL_E_VUC_NDT_RANGE, 0, 0
};

boolean_t
nvme_validate_vuc(nvme_t *nvme, nvme_ioctl_passthru_t *pass)
{
	nvme_valid_ctrl_data_t ctrl_data;
	const uint32_t all_flags = NVME_PASSTHRU_READ | NVME_PASSTHRU_WRITE;
	const uint32_t all_impact = NVME_IMPACT_NS;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	/*
	 * If there's no controller support, there's nothing that we can do.
	 */
	if (nvme->n_idctl->id_nvscc.nv_spec == 0) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_CTRL_VUC_UNSUP, 0, 0));
	}

	/*
	 * We don't use the common validation code for the timeout because
	 * there's no way for it to know the kernel's max value right now.
	 */
	if (pass->npc_timeout == 0 ||
	    pass->npc_timeout > nvme_vendor_specific_admin_cmd_max_timeout) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_VUC_TIMEOUT_RANGE, 0, 0));
	}

	if (!nvme_validate_one_field(&pass->npc_common, pass->npc_opcode,
	    &nvme_valid_vuc_opcode, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&pass->npc_common,
	    pass->npc_common.nioc_nsid, &nvme_valid_vuc_nsid, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	/*
	 * Ensure that the flags and impact fields only have known values.
	 */
	if ((pass->npc_flags & ~all_flags) != 0) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_VUC_FLAGS_RANGE, 0, 0));
	}

	if ((pass->npc_impact & ~all_impact) != 0) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_VUC_IMPACT_RANGE, 0, 0));
	}

	/*
	 * We need to validate several different things related to the buffer
	 * and its length:
	 *
	 *  - The buffer length must be a multiple of 4 bytes (checked by common
	 *    code).
	 *  - The buffer length cannot exceed the hardware max (checked by
	 *    common code).
	 *  - The buffer length cannot exceed our maximum size.
	 *  - That if the buffer is present, a length is set.
	 *  - That if there is no buffer, the length is zero.
	 *  - That if a buffer is set, we have the direction flags set.
	 *  - That both direction flags aren't set at the same time.
	 *
	 * We only fall into the normal validation code after all this to make
	 * sure there is nothing additional weird here.
	 */
	if (!nvme_validate_one_field(&pass->npc_common, pass->npc_buflen,
	    &nvme_valid_vuc_ndt, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	if (pass->npc_buflen > nvme_vendor_specific_admin_cmd_size) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_VUC_NDT_RANGE, 0, 0));
	}

	if ((pass->npc_buflen != 0 && pass->npc_buf == 0) ||
	    (pass->npc_buflen == 0 && pass->npc_buf != 0)) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_INCONSIST_VUC_BUF_NDT, 0, 0));
	}

	if ((pass->npc_buflen != 0 && pass->npc_flags == 0) ||
	    ((pass->npc_buflen == 0 && pass->npc_flags != 0))) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_INCONSIST_VUC_FLAGS_NDT, 0, 0));
	}

	if ((pass->npc_flags & NVME_PASSTHRU_READ) != 0 &&
	    (pass->npc_flags & NVME_PASSTHRU_WRITE) != 0) {
		return (nvme_ioctl_error(&pass->npc_common,
		    NVME_IOCTL_E_VUC_FLAGS_RANGE, 0, 0));
	}

	return (B_TRUE);
}

static const nvme_validate_info_t nvme_valid_format_lbaf = {
	nvme_format_fields, NVME_FORMAT_REQ_FIELD_LBAF, 0,
	NVME_IOCTL_E_FORMAT_LBAF_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_format_ses = {
	nvme_format_fields, NVME_FORMAT_REQ_FIELD_SES, 0,
	NVME_IOCTL_E_FORMAT_SES_RANGE, 0, 0
};

boolean_t
nvme_validate_format(nvme_t *nvme, nvme_ioctl_format_t *ioc)
{
	nvme_valid_ctrl_data_t ctrl_data;
	const nvme_identify_nsid_t *idns;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	if (!nvme_format_cmds_supported(&ctrl_data)) {
		return (nvme_ioctl_error(&ioc->nif_common,
		    NVME_IOCTL_E_CTRL_FORMAT_UNSUP, 0, 0));
	}

	if (!nvme_validate_one_field(&ioc->nif_common, ioc->nif_lbaf,
	    &nvme_valid_format_lbaf, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&ioc->nif_common, ioc->nif_ses,
	    &nvme_valid_format_ses, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	/*
	 * Now we need to determine if this LBA format is actually one that is
	 * supported by the controller and by the operating system. Note, the
	 * number of LBA formats is considered a zeros values (that is the
	 * actual value is what's there plus one). In the future we should
	 * consider pulling the id_nlbaf check into the common validation code
	 * and passing the common namespace information there as well.
	 */
	idns = nvme->n_idcomns;
	if (ioc->nif_lbaf > idns->id_nlbaf) {
		return (nvme_ioctl_error(&ioc->nif_common,
		    NVME_IOCTL_E_FORMAT_LBAF_RANGE, 0, 0));
	}

	if (idns->id_lbaf[ioc->nif_lbaf].lbaf_ms != 0) {
		return (nvme_ioctl_error(&ioc->nif_common,
		    NVME_IOCTL_E_UNSUP_LBAF_META, 0, 0));
	}

	if (ioc->nif_ses == NVME_FRMT_SES_CRYPTO &&
	    nvme->n_idctl->id_fna.fn_crypt_erase == 0) {
		return (nvme_ioctl_error(&ioc->nif_common,
		    NVME_IOCTL_E_CTRL_CRYPTO_SE_UNSUP, 0, 0));
	}

	/*
	 * The remaining checks only apply to cases where we're targeting a
	 * single namespace.
	 */
	if (ioc->nif_common.nioc_nsid == NVME_NSID_BCAST) {
		return (B_TRUE);
	}

	if (nvme->n_idctl->id_fna.fn_format != 0) {
		return (nvme_ioctl_error(&ioc->nif_common,
		    NVME_IOCTL_E_CTRL_NS_FORMAT_UNSUP, 0, 0));
	}

	if (ioc->nif_ses != NVME_FRMT_SES_NONE &&
	    nvme->n_idctl->id_fna.fn_sec_erase != 0) {
		return (nvme_ioctl_error(&ioc->nif_common,
		    NVME_IOCTL_E_CTRL_NS_SE_UNSUP, 0, 0));
	}

	return (B_TRUE);
}

static const nvme_validate_info_t nvme_valid_fw_load_numd = {
	nvme_fw_load_fields, NVME_FW_LOAD_REQ_FIELD_NUMD, 0,
	NVME_IOCTL_E_FW_LOAD_LEN_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_fw_load_offset = {
	nvme_fw_load_fields, NVME_FW_LOAD_REQ_FIELD_OFFSET, 0,
	NVME_IOCTL_E_FW_LOAD_OFFSET_RANGE, 0, 0
};

boolean_t
nvme_validate_fw_load(nvme_t *nvme, nvme_ioctl_fw_load_t *fw)
{
	nvme_valid_ctrl_data_t ctrl_data;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	if (!nvme_fw_cmds_supported(&ctrl_data)) {
		return (nvme_ioctl_error(&fw->fwl_common,
		    NVME_IOCTL_E_CTRL_FW_UNSUP, 0, 0));
	}

	if (!nvme_validate_one_field(&fw->fwl_common, fw->fwl_len,
	    &nvme_valid_fw_load_numd, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&fw->fwl_common, fw->fwl_off,
	    &nvme_valid_fw_load_offset, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static const nvme_validate_info_t nvme_valid_fw_commit_slot = {
	nvme_fw_commit_fields, NVME_FW_COMMIT_REQ_FIELD_SLOT, 0,
	NVME_IOCTL_E_FW_COMMIT_SLOT_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_fw_commit_act = {
	nvme_fw_commit_fields, NVME_FW_COMMIT_REQ_FIELD_ACT, 0,
	NVME_IOCTL_E_FW_COMMIT_ACTION_RANGE, 0, 0
};

boolean_t
nvme_validate_fw_commit(nvme_t *nvme, nvme_ioctl_fw_commit_t *fw)
{
	nvme_valid_ctrl_data_t ctrl_data;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	if (!nvme_fw_cmds_supported(&ctrl_data)) {
		return (nvme_ioctl_error(&fw->fwc_common,
		    NVME_IOCTL_E_CTRL_FW_UNSUP, 0, 0));
	}

	if (!nvme_validate_one_field(&fw->fwc_common, fw->fwc_slot,
	    &nvme_valid_fw_commit_slot, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&fw->fwc_common, fw->fwc_action,
	    &nvme_valid_fw_commit_act, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	/*
	 * Do not allow someone to explicitly download an image to a read-only
	 * firmware slot. The specification only allows slot 1 to be marked
	 * read-only.
	 */
	if (fw->fwc_slot == 1 && nvme->n_idctl->id_frmw.fw_readonly &&
	    (fw->fwc_action == NVME_FWC_SAVE ||
	    fw->fwc_action == NVME_FWC_SAVE_ACTIVATE)) {
		return (nvme_ioctl_error(&fw->fwc_common,
		    NVME_IOCTL_E_RO_FW_SLOT, 0, 0));
	}

	return (B_TRUE);
}

/*
 * Right now we do not allow a controller list to be specified and only will
 * ever insert our own local controller's ID into the list.
 */
boolean_t
nvme_validate_ctrl_attach_detach_ns(nvme_t *nvme, nvme_ioctl_common_t *com)
{
	nvme_valid_ctrl_data_t ctrl_data;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	if (!nvme_fw_cmds_supported(&ctrl_data)) {
		return (nvme_ioctl_error(com, NVME_IOCTL_E_CTRL_NS_MGMT_UNSUP,
		    0, 0));
	}

	return (B_TRUE);
}

boolean_t
nvme_validate_ns_delete(nvme_t *nvme, nvme_ioctl_common_t *com)
{
	nvme_valid_ctrl_data_t ctrl_data;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	if (!nvme_fw_cmds_supported(&ctrl_data)) {
		return (nvme_ioctl_error(com, NVME_IOCTL_E_CTRL_NS_MGMT_UNSUP,
		    0, 0));
	}

	return (B_TRUE);
}

static const nvme_validate_info_t nvme_valid_ns_create_nsze = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_NSZE, 0,
	NVME_IOCTL_E_NS_CREATE_NSZE_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_ns_create_ncap = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_NCAP, 0,
	NVME_IOCTL_E_NS_CREATE_NCAP_RANGE, 0, 0
};

static const nvme_validate_info_t nvme_valid_ns_create_csi = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_CSI, 0,
	NVME_IOCTL_E_NS_CREATE_CSI_RANGE, NVME_IOCTL_E_NS_CREATE_CSI_UNSUP, 0
};

static const nvme_validate_info_t nvme_valid_ns_create_nmic = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_NMIC, 0,
	NVME_IOCTL_E_NS_CREATE_NMIC_RANGE, 0, 0
};

boolean_t
nvme_validate_ns_create(nvme_t *nvme, nvme_ioctl_ns_create_t *ioc)
{
	const nvme_identify_nsid_t *idns = nvme->n_idcomns;
	nvme_valid_ctrl_data_t ctrl_data;

	ctrl_data.vcd_vers = &nvme->n_version;
	ctrl_data.vcd_id = nvme->n_idctl;

	if (!nvme_nsmgmt_cmds_supported(&ctrl_data)) {
		return (nvme_ioctl_error(&ioc->nnc_common,
		    NVME_IOCTL_E_CTRL_NS_MGMT_UNSUP, 0, 0));
	}

	if (!nvme_validate_one_field(&ioc->nnc_common, ioc->nnc_nsze,
	    &nvme_valid_ns_create_nsze, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	if (!nvme_validate_one_field(&ioc->nnc_common, ioc->nnc_ncap,
	    &nvme_valid_ns_create_ncap, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	/*
	 * Verify whether or not thin provisioning is supported. Thin
	 * provisioning was added in version 1.0. Because we have already
	 * validated NS management commands are supported, which requires
	 * version 1.2, we can just check the identify controller bit.
	 */
	if (ioc->nnc_nsze > ioc->nnc_ncap && idns->id_nsfeat.f_thin == 0) {
		return (nvme_ioctl_error(&ioc->nnc_common,
		    NVME_IOCTL_E_CTRL_THIN_PROV_UNSUP, 0, 0));
	}

	/*
	 * We do CSI validation in two parts. The first is a standard CSI
	 * validation technique to see if we have a non-zero value that we have
	 * a minimum version that we support, etc. The second is then the
	 * constraint that we have today in the driver that we only support
	 * creating namespaces whose CSI are of type NVM.
	 */
	if (!nvme_validate_one_field(&ioc->nnc_common, ioc->nnc_csi,
	    &nvme_valid_ns_create_csi, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	if (ioc->nnc_csi != NVME_CSI_NVM) {
		return (nvme_ioctl_error(&ioc->nnc_common,
		    NVME_IOCTL_E_DRV_CSI_UNSUP, 0, 0));
	}

	/*
	 * See our notes around the LBA format in nvme_validate_format(). Unlike
	 * format, today we don't validate that the driver can actually use it.
	 * We try to be a little more flexible and just ensure that this is a
	 * valid choice. However, we currently treat the field as just
	 * indicating the LBA format and currently don't support the NVMe 2.0
	 * host behavior around the extended LBA format size.
	 */
	if (ioc->nnc_flbas > idns->id_nlbaf) {
		return (nvme_ioctl_error(&ioc->nnc_common,
		    NVME_IOCTL_E_NS_CREATE_FLBAS_RANGE, 0, 0));
	}

	if (!nvme_validate_one_field(&ioc->nnc_common, ioc->nnc_nmic,
	    &nvme_valid_ns_create_nmic, &ctrl_data, 0)) {
		return (B_FALSE);
	}

	return (B_TRUE);
}
