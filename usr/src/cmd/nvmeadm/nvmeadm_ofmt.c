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
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * nvmeadm output formatting for ofmt based rendering
 */

#include <strings.h>
#include <sys/sysmacros.h>
#include <err.h>

#include "nvmeadm.h"

typedef struct {
	uint32_t	nb_flag;
	const char	*nb_str;
} nvmeadm_bitstr_t;

static boolean_t
nvmeadm_bits_to_str(uint32_t val, const nvmeadm_bitstr_t *strs, size_t nstrs,
    char *buf, size_t buflen)
{
	boolean_t comma = B_FALSE;

	buf[0] = '\0';
	for (size_t i = 0; i < nstrs; i++) {
		if ((val & strs[i].nb_flag) != strs[i].nb_flag)
			continue;
		if (comma && strlcat(buf, ",", buflen) >= buflen)
			return (B_FALSE);
		if (strlcat(buf, strs[i].nb_str, buflen) >= buflen)
			return (B_FALSE);
		comma = true;
	}

	if (buf[0] == '\0') {
		if (strlcat(buf, "--", buflen) >= buflen)
			return (B_FALSE);
	}

	return (B_TRUE);
}

typedef enum nvme_list_ofmt_field {
	NVME_LIST_MODEL,
	NVME_LIST_SERIAL,
	NVME_LIST_FWREV,
	NVME_LIST_VERSION,
	NVME_LIST_SIZE,
	NVME_LIST_CAPACITY,
	NVME_LIST_USED,
	NVME_LIST_INSTANCE,
	NVME_LIST_NAMESPACE,
	NVME_LIST_DISK,
	NVME_LIST_UNALLOC,
	NVME_LIST_NS_STATE,
	NVME_LIST_CTRLPATH,
	NVME_LIST_NS_FORMAT,
	NVME_LIST_NS_FMTID,
	NVME_LIST_NS_FMTDS,
	NVME_LIST_NS_FMTMS
} nvme_list_ofmt_field_t;

static boolean_t
nvmeadm_list_common_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	nvmeadm_list_ofmt_arg_t *list = ofmt_arg->ofmt_cbarg;
	nvme_ctrl_info_t *ctrl = list->nloa_ctrl;
	const nvme_version_t *vers;
	char *path;
	size_t ret;

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_MODEL:
		ret = strlcpy(buf, nvme_ctrl_info_model(ctrl), buflen);
		break;
	case NVME_LIST_SERIAL:
		ret = strlcpy(buf, nvme_ctrl_info_serial(ctrl), buflen);
		break;
	case NVME_LIST_FWREV:
		ret = strlcpy(buf, nvme_ctrl_info_fwrev(ctrl), buflen);
		break;
	case NVME_LIST_VERSION:
		vers = nvme_ctrl_info_version(ctrl);
		ret = snprintf(buf, buflen, "%u.%u", vers->v_major,
		    vers->v_minor);
		break;
	case NVME_LIST_INSTANCE:
		ret = strlcpy(buf, list->nloa_name, buflen);
		break;
	case NVME_LIST_CTRLPATH:
		if (list->nloa_dip == DI_NODE_NIL) {
			return (B_FALSE);
		}

		path = di_devfs_path(list->nloa_dip);
		if (path == NULL) {
			return (B_FALSE);
		}
		ret = strlcat(buf, path, buflen);
		di_devfs_path_free(path);
		break;
	default:
		warnx("internal programmer error: encountered unknown ofmt "
		    "argument id 0x%x", ofmt_arg->ofmt_id);
		abort();
	}
	if (ret >= buflen) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
nvmeadm_list_ctrl_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	nvmeadm_list_ofmt_arg_t *list = ofmt_arg->ofmt_cbarg;
	nvme_ctrl_info_t *ctrl = list->nloa_ctrl;
	nvme_uint128_t u128;
	size_t ret;

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_CAPACITY:
		if (nvme_ctrl_info_cap(ctrl, &u128)) {
			ret = nvme_snprint_uint128(buf, buflen, u128, 0, 0);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_UNALLOC:
		if (nvme_ctrl_info_unalloc_cap(ctrl, &u128)) {
			ret = nvme_snprint_uint128(buf, buflen, u128, 0, 0);
		} else {
			return (B_FALSE);
		}
		break;
	default:
		warnx("internal programmer error: encountered unknown ofmt "
		    "argument id 0x%x", ofmt_arg->ofmt_id);
		abort();
	}

	if (ret >= buflen) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
nvmeadm_list_nsid_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	nvmeadm_list_ofmt_arg_t *list = ofmt_arg->ofmt_cbarg;
	nvme_ns_info_t *ns = list->nloa_ns;
	const nvme_nvm_lba_fmt_t *fmt = NULL;
	const nvme_ns_disc_level_t level = nvme_ns_info_level(ns);
	uint64_t val;
	size_t ret;

	(void) nvme_ns_info_curformat(ns, &fmt);

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_NAMESPACE:
		ret = snprintf(buf, buflen, "%u", nvme_ns_info_nsid(ns));
		break;
	case NVME_LIST_DISK:
		if (list->nloa_disk != NULL) {
			ret = strlcpy(buf, list->nloa_disk, buflen);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_SIZE:
		if (nvme_ns_info_size(ns, &val) && fmt != NULL) {
			val *= nvme_nvm_lba_fmt_data_size(fmt);
			ret = snprintf(buf, buflen, "%" PRIu64, val);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_CAPACITY:
		if (nvme_ns_info_size(ns, &val) && fmt != NULL) {
			val *= nvme_nvm_lba_fmt_data_size(fmt);
			ret = snprintf(buf, buflen, "%" PRIu64, val);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_USED:
		if (nvme_ns_info_size(ns, &val) && fmt != NULL) {
			val *= nvme_nvm_lba_fmt_data_size(fmt);
			ret = snprintf(buf, buflen, "%" PRIu64, val);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_NS_STATE:
		ret = strlcpy(buf, list->nloa_state, buflen);
		break;
	case NVME_LIST_NS_FORMAT:
		if (fmt != NULL) {
			ret = snprintf(buf, buflen, "%u+%u",
			    nvme_nvm_lba_fmt_data_size(fmt),
			    nvme_nvm_lba_fmt_meta_size(fmt));
		} else if (level < NVME_NS_DISC_F_ACTIVE) {
			ret = strlcpy(buf, "-", buflen);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_NS_FMTID:
		if (fmt != NULL) {
			ret = snprintf(buf, buflen, "%u",
			    nvme_nvm_lba_fmt_id(fmt));
		} else if (level < NVME_NS_DISC_F_ACTIVE) {
			ret = strlcpy(buf, "-", buflen);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_NS_FMTDS:
		if (fmt != NULL) {
			ret = snprintf(buf, buflen, "%u",
			    nvme_nvm_lba_fmt_data_size(fmt));
		} else if (level < NVME_NS_DISC_F_ACTIVE) {
			ret = strlcpy(buf, "-", buflen);
		} else {
			return (B_FALSE);
		}
		break;
	case NVME_LIST_NS_FMTMS:
		if (fmt != NULL) {
			ret = snprintf(buf, buflen, "%u",
			    nvme_nvm_lba_fmt_meta_size(fmt));
		} else if (level < NVME_NS_DISC_F_ACTIVE) {
			ret = strlcpy(buf, "-", buflen);
		} else {
			return (B_FALSE);
		}
		break;
	default:
		warnx("internal programmer error: encountered unknown ofmt "
		    "argument id 0x%x", ofmt_arg->ofmt_id);
		abort();
	}

	if (ret >= buflen) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

const ofmt_field_t nvmeadm_list_ctrl_ofmt[] = {
	{ "MODEL", 30, NVME_LIST_MODEL, nvmeadm_list_common_ofmt_cb },
	{ "SERIAL", 30, NVME_LIST_SERIAL, nvmeadm_list_common_ofmt_cb },
	{ "FWREV", 10, NVME_LIST_FWREV, nvmeadm_list_common_ofmt_cb },
	{ "VERSION", 10, NVME_LIST_VERSION, nvmeadm_list_common_ofmt_cb },
	{ "CAPACITY", 15, NVME_LIST_CAPACITY, nvmeadm_list_ctrl_ofmt_cb },
	{ "INSTANCE", 10, NVME_LIST_INSTANCE, nvmeadm_list_common_ofmt_cb },
	{ "UNALLOCATED", 15, NVME_LIST_UNALLOC, nvmeadm_list_ctrl_ofmt_cb },
	{ "CTRLPATH", 30, NVME_LIST_CTRLPATH, nvmeadm_list_common_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

const ofmt_field_t nvmeadm_list_nsid_ofmt[] = {
	{ "MODEL", 30, NVME_LIST_MODEL, nvmeadm_list_common_ofmt_cb },
	{ "SERIAL", 30, NVME_LIST_SERIAL, nvmeadm_list_common_ofmt_cb },
	{ "FWREV", 10, NVME_LIST_FWREV, nvmeadm_list_common_ofmt_cb },
	{ "VERSION", 10, NVME_LIST_VERSION, nvmeadm_list_common_ofmt_cb },
	{ "SIZE", 15, NVME_LIST_SIZE, nvmeadm_list_nsid_ofmt_cb },
	{ "CAPACITY", 15, NVME_LIST_CAPACITY, nvmeadm_list_nsid_ofmt_cb },
	{ "USED", 15, NVME_LIST_USED, nvmeadm_list_nsid_ofmt_cb },
	{ "INSTANCE", 10, NVME_LIST_INSTANCE, nvmeadm_list_common_ofmt_cb },
	{ "NAMESPACE", 10, NVME_LIST_NAMESPACE, nvmeadm_list_nsid_ofmt_cb },
	{ "DISK", 15, NVME_LIST_DISK, nvmeadm_list_nsid_ofmt_cb },
	{ "NS-STATE", 10, NVME_LIST_NS_STATE, nvmeadm_list_nsid_ofmt_cb },
	{ "CTRLPATH", 30, NVME_LIST_CTRLPATH, nvmeadm_list_common_ofmt_cb },
	{ "FORMAT", 12, NVME_LIST_NS_FORMAT, nvmeadm_list_nsid_ofmt_cb },
	{ "FMTID", 8, NVME_LIST_NS_FMTID, nvmeadm_list_nsid_ofmt_cb },
	{ "FMTDS", 8, NVME_LIST_NS_FMTDS, nvmeadm_list_nsid_ofmt_cb },
	{ "FMTMS", 8, NVME_LIST_NS_FMTMS, nvmeadm_list_nsid_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

typedef enum {
	NVME_LIST_LOGS_DEVICE,
	NVME_LIST_LOGS_NAME,
	NVME_LIST_LOGS_DESC,
	NVME_LIST_LOGS_SCOPE,
	NVME_LIST_LOGS_FIELDS,
	NVME_LIST_LOGS_CSI,
	NVME_LIST_LOGS_LID,
	NVME_LIST_LOGS_SIZE,
	NVME_LIST_LOGS_MINSIZE,
	NVME_LIST_LOGS_IMPL,
	NVME_LIST_LOGS_SOURCES,
	NVME_LIST_LOGS_KIND
} nvme_list_logs_ofmt_field_t;

static const nvmeadm_bitstr_t nvmeadm_log_scopes[] = {
	{ NVME_LOG_SCOPE_CTRL, "controller" },
	{ NVME_LOG_SCOPE_NVM, "nvm" },
	{ NVME_LOG_SCOPE_NS, "namespace" }
};

static const nvmeadm_bitstr_t nvmeadm_log_fields[] = {
	{ NVME_LOG_DISC_F_NEED_LSP, "lsp" },
	{ NVME_LOG_DISC_F_NEED_LSI, "lsi" },
	{ NVME_LOG_DISC_F_NEED_RAE, "rae" }
};

static const nvmeadm_bitstr_t nvmeadm_log_sources[] = {
	{ NVME_LOG_DISC_S_SPEC, "spec" },
	{ NVME_LOG_DISC_S_ID_CTRL, "identify-controller" },
	{ NVME_LOG_DISC_S_DB, "internal-db" },
	{ NVME_LOG_DISC_S_CMD, "command" }
};

static boolean_t
nvmeadm_list_logs_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	const nvmeadm_list_logs_ofmt_arg_t *list = ofmt_arg->ofmt_cbarg;
	const nvme_log_disc_t *disc = list->nlloa_disc;
	uint64_t alloc;
	size_t ret;
	nvme_log_size_kind_t kind;

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_LOGS_DEVICE:
		ret = strlcpy(buf, list->nlloa_name, buflen);
		break;
	case NVME_LIST_LOGS_NAME:
		ret = strlcpy(buf, nvme_log_disc_name(disc), buflen);
		break;
	case NVME_LIST_LOGS_DESC:
		ret = strlcpy(buf, nvme_log_disc_desc(disc), buflen);
		break;
	case NVME_LIST_LOGS_SCOPE:
		return (nvmeadm_bits_to_str(nvme_log_disc_scopes(disc),
		    nvmeadm_log_scopes, ARRAY_SIZE(nvmeadm_log_scopes), buf,
		    buflen));
	case NVME_LIST_LOGS_FIELDS:
		return (nvmeadm_bits_to_str(nvme_log_disc_fields(disc),
		    nvmeadm_log_fields, ARRAY_SIZE(nvmeadm_log_fields), buf,
		    buflen));
		break;
	case NVME_LIST_LOGS_CSI:
		switch (nvme_log_disc_csi(disc)) {
		case NVME_CSI_NVM:
			ret = strlcpy(buf, "nvm", buflen);
			break;
		case NVME_CSI_KV:
			ret = strlcpy(buf, "kv", buflen);
			break;
		case NVME_CSI_ZNS:
			ret = strlcpy(buf, "zns", buflen);
			break;
		default:
			ret = snprintf(buf, buflen, "unknown (0x%x)",
			    nvme_log_disc_csi(disc));
			break;
		}
		break;
	case NVME_LIST_LOGS_LID:
		ret = snprintf(buf, buflen, "0x%x", nvme_log_disc_lid(disc));
		break;
	case NVME_LIST_LOGS_SIZE:
	case NVME_LIST_LOGS_MINSIZE:
		kind = nvme_log_disc_size(disc, &alloc);

		if (kind == NVME_LOG_SIZE_K_UNKNOWN) {
			return (B_FALSE);
		}

		if (kind == NVME_LOG_SIZE_K_VAR &&
		    ofmt_arg->ofmt_id == NVME_LIST_LOGS_SIZE) {
			return (B_FALSE);
		}

		ret = snprintf(buf, buflen, "%" PRIu64, alloc);
		break;
	case NVME_LIST_LOGS_IMPL:
		ret = strlcpy(buf, nvme_log_disc_impl(disc) ? "yes" : "no",
		    buflen);
		break;
	case NVME_LIST_LOGS_SOURCES:
		return (nvmeadm_bits_to_str(nvme_log_disc_sources(disc),
		    nvmeadm_log_sources, ARRAY_SIZE(nvmeadm_log_sources), buf,
		    buflen));
		break;
	case NVME_LIST_LOGS_KIND:
		switch (nvme_log_disc_kind(disc)) {
		case NVME_LOG_ID_MANDATORY:
			ret = strlcpy(buf, "mandatory", buflen);
			break;
		case NVME_LOG_ID_OPTIONAL:
			ret = strlcpy(buf, "optional", buflen);
			break;
		case NVME_LOG_ID_VENDOR_SPECIFIC:
			ret = strlcpy(buf, "vendor-specific", buflen);
			break;
		default:
			ret = snprintf(buf, buflen, "unknown (0x%x)",
			    nvme_log_disc_kind(disc));
			break;
		}
		break;
	default:
		warnx("internal programmer error: encountered unknown ofmt "
		    "argument id 0x%x", ofmt_arg->ofmt_id);
		abort();
	}

	return (ret < buflen);
}

const char *nvmeadm_list_logs_fields = "device,name,scope,fields,desc";
const char *nvmeadm_list_logs_fields_impl = "device,name,scope,impl,fields,"
	"desc";
const ofmt_field_t nvmeadm_list_logs_ofmt[] = {
	{ "DEVICE", 8, NVME_LIST_LOGS_DEVICE, nvmeadm_list_logs_ofmt_cb },
	{ "NAME", 18, NVME_LIST_LOGS_NAME, nvmeadm_list_logs_ofmt_cb },
	{ "DESC", 30, NVME_LIST_LOGS_DESC, nvmeadm_list_logs_ofmt_cb },
	{ "SCOPE", 14, NVME_LIST_LOGS_SCOPE, nvmeadm_list_logs_ofmt_cb },
	{ "FIELDS", 10, NVME_LIST_LOGS_FIELDS, nvmeadm_list_logs_ofmt_cb },
	{ "CSI", 6, NVME_LIST_LOGS_CSI, nvmeadm_list_logs_ofmt_cb },
	{ "LID", 6, NVME_LIST_LOGS_LID, nvmeadm_list_logs_ofmt_cb },
	{ "SIZE", 10, NVME_LIST_LOGS_SIZE, nvmeadm_list_logs_ofmt_cb },
	{ "MINSIZE", 10, NVME_LIST_LOGS_MINSIZE, nvmeadm_list_logs_ofmt_cb },
	{ "IMPL", 6, NVME_LIST_LOGS_IMPL, nvmeadm_list_logs_ofmt_cb },
	{ "SOURCES", 20, NVME_LIST_LOGS_SOURCES, nvmeadm_list_logs_ofmt_cb },
	{ "KIND", 16, NVME_LIST_LOGS_KIND, nvmeadm_list_logs_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

typedef enum {
	NVME_LIST_FEATS_DEVICE,
	NVME_LIST_FEATS_SHORT,
	NVME_LIST_FEATS_SPEC,
	NVME_LIST_FEATS_FID,
	NVME_LIST_FEATS_SCOPE,
	NVME_LIST_FEATS_KIND,
	NVME_LIST_FEATS_CSI,
	NVME_LIST_FEATS_FLAGS,
	NVME_LIST_FEATS_GET_IN,
	NVME_LIST_FEATS_SET_IN,
	NVME_LIST_FEATS_GET_OUT,
	NVME_LIST_FEATS_SET_OUT,
	NVME_LIST_FEATS_DATA_LEN,
	NVME_LIST_FEATS_IMPL
} nvme_list_features_ofmt_field_t;

static const nvmeadm_bitstr_t nvmeadm_feat_scopes[] = {
	{ NVME_FEAT_SCOPE_CTRL, "controller" },
	{ NVME_FEAT_SCOPE_NS, "namespace" }
};

static const nvmeadm_bitstr_t nvmeadm_feat_get_in[] = {
	{ NVME_GET_FEAT_F_CDW11, "cdw11" },
	{ NVME_GET_FEAT_F_DATA, "data" },
	{ NVME_GET_FEAT_F_NSID, "nsid" }
};

static const nvmeadm_bitstr_t nvmeadm_feat_set_in[] = {
	{ NVME_SET_FEAT_F_CDW11, "cdw11" },
	{ NVME_SET_FEAT_F_CDW12, "cdw12" },
	{ NVME_SET_FEAT_F_CDW13, "cdw13" },
	{ NVME_SET_FEAT_F_CDW14, "cdw14" },
	{ NVME_SET_FEAT_F_CDW15, "cdw15" },
	{ NVME_SET_FEAT_F_DATA, "data" },
	{ NVME_SET_FEAT_F_NSID, "nsid" }
};

static const nvmeadm_bitstr_t nvmeadm_feat_output[] = {
	{ NVME_FEAT_OUTPUT_CDW0, "cdw0" },
	{ NVME_FEAT_OUTPUT_DATA, "data" }
};

static const nvmeadm_bitstr_t nvmeadm_feat_flags[] = {
	{ NVME_FEAT_F_GET_BCAST_NSID, "get-bcastns" },
	{ NVME_FEAT_F_SET_BCAST_NSID, "set-bcastns" }
};

static const nvmeadm_bitstr_t nvmeadm_feat_csi[] = {
	{ NVME_FEAT_CSI_NVM, "nvm" }
};

static boolean_t
nvmeadm_list_features_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	const nvmeadm_list_features_ofmt_arg_t *nlfo = ofmt_arg->ofmt_cbarg;
	const nvme_feat_disc_t *feat = nlfo->nlfoa_feat;
	size_t ret;

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_FEATS_DEVICE:
		ret = strlcpy(buf, nlfo->nlfoa_name, buflen);
		break;
	case NVME_LIST_FEATS_SHORT:
		ret = strlcpy(buf, nvme_feat_disc_short(feat), buflen);
		break;
	case NVME_LIST_FEATS_SPEC:
		ret = strlcpy(buf, nvme_feat_disc_spec(feat), buflen);
		break;
	case NVME_LIST_FEATS_FID:
		ret = snprintf(buf, buflen, "0x%x", nvme_feat_disc_fid(feat));
		break;
	case NVME_LIST_FEATS_SCOPE:
		return (nvmeadm_bits_to_str(nvme_feat_disc_scope(feat),
		    nvmeadm_feat_scopes, ARRAY_SIZE(nvmeadm_feat_scopes), buf,
		    buflen));
	case NVME_LIST_FEATS_KIND:
		switch (nvme_feat_disc_kind(feat)) {
		case NVME_FEAT_MANDATORY:
			ret = strlcpy(buf, "mandatory", buflen);
			break;
		case NVME_FEAT_OPTIONAL:
			ret = strlcpy(buf, "optional", buflen);
			break;
		case NVME_FEAT_VENDOR_SPECIFIC:
			ret = strlcpy(buf, "vendor-specific", buflen);
			break;
		default:
			ret = snprintf(buf, buflen, "unknown (0x%x)",
			    nvme_feat_disc_kind(feat));
			break;
		}
		break;
	case NVME_LIST_FEATS_CSI:
		if (nvme_feat_disc_csi(feat) == NVME_FEAT_CSI_NONE) {
			ret = strlcpy(buf, "none", buflen);
			break;
		}

		return (nvmeadm_bits_to_str(nvme_feat_disc_csi(feat),
		    nvmeadm_feat_csi, ARRAY_SIZE(nvmeadm_feat_csi), buf,
		    buflen));
	case NVME_LIST_FEATS_FLAGS:
		return (nvmeadm_bits_to_str(nvme_feat_disc_flags(feat),
		    nvmeadm_feat_flags, ARRAY_SIZE(nvmeadm_feat_flags), buf,
		    buflen));
	case NVME_LIST_FEATS_GET_IN:
		return (nvmeadm_bits_to_str(nvme_feat_disc_fields_get(feat),
		    nvmeadm_feat_get_in, ARRAY_SIZE(nvmeadm_feat_get_in), buf,
		    buflen));
	case NVME_LIST_FEATS_SET_IN:
		return (nvmeadm_bits_to_str(nvme_feat_disc_fields_set(feat),
		    nvmeadm_feat_set_in, ARRAY_SIZE(nvmeadm_feat_set_in), buf,
		    buflen));
	case NVME_LIST_FEATS_GET_OUT:
		return (nvmeadm_bits_to_str(nvme_feat_disc_output_get(feat),
		    nvmeadm_feat_output, ARRAY_SIZE(nvmeadm_feat_output), buf,
		    buflen));
	case NVME_LIST_FEATS_SET_OUT:
		return (nvmeadm_bits_to_str(nvme_feat_disc_output_set(feat),
		    nvmeadm_feat_output, ARRAY_SIZE(nvmeadm_feat_output), buf,
		    buflen));
	case NVME_LIST_FEATS_DATA_LEN:
		if (nvme_feat_disc_data_size(feat) == 0) {
			ret = strlcpy(buf, "-", buflen);
		} else {
			ret = snprintf(buf, buflen, "%" PRIu64,
			    nvme_feat_disc_data_size(feat));
		}
		break;
	case NVME_LIST_FEATS_IMPL:
		switch (nvme_feat_disc_impl(feat)) {
		case NVME_FEAT_IMPL_UNKNOWN:
			ret = strlcpy(buf, "unknown", buflen);
			break;
		case NVME_FEAT_IMPL_UNSUPPORTED:
			ret = strlcpy(buf, "no", buflen);
			break;
		case NVME_FEAT_IMPL_SUPPORTED:
			ret = strlcpy(buf, "yes", buflen);
			break;
		default:
			ret = snprintf(buf, buflen, "unknown (0x%x)",
			    nvme_feat_disc_impl(feat));
			break;
		}
		break;
	default:
		warnx("internal programmer error: encountered unknown ofmt "
		    "argument id 0x%x", ofmt_arg->ofmt_id);
		abort();
	}

	return (ret < buflen);
}

const char *nvmeadm_list_features_fields = "device,short,scope,impl,spec";
const ofmt_field_t nvmeadm_list_features_ofmt[] = {
	{ "DEVICE", 8, NVME_LIST_FEATS_DEVICE, nvmeadm_list_features_ofmt_cb },
	{ "SHORT", 14, NVME_LIST_FEATS_SHORT, nvmeadm_list_features_ofmt_cb },
	{ "SPEC", 30, NVME_LIST_FEATS_SPEC, nvmeadm_list_features_ofmt_cb },
	{ "FID", 6, NVME_LIST_FEATS_FID, nvmeadm_list_features_ofmt_cb },
	{ "SCOPE", 14, NVME_LIST_FEATS_SCOPE, nvmeadm_list_features_ofmt_cb },
	{ "KIND", 16, NVME_LIST_FEATS_KIND, nvmeadm_list_features_ofmt_cb },
	{ "CSI", 6, NVME_LIST_FEATS_CSI, nvmeadm_list_features_ofmt_cb },
	{ "FLAGS", 14, NVME_LIST_FEATS_FLAGS, nvmeadm_list_features_ofmt_cb },
	{ "GET-IN", 14, NVME_LIST_FEATS_GET_IN, nvmeadm_list_features_ofmt_cb },
	{ "SET-IN", 14, NVME_LIST_FEATS_SET_IN, nvmeadm_list_features_ofmt_cb },
	{ "GET-OUT", 14, NVME_LIST_FEATS_GET_OUT,
	    nvmeadm_list_features_ofmt_cb },
	{ "SET-OUT", 14, NVME_LIST_FEATS_SET_OUT,
	    nvmeadm_list_features_ofmt_cb },
	{ "DATALEN", 8, NVME_LIST_FEATS_DATA_LEN,
	    nvmeadm_list_features_ofmt_cb },
	{ "IMPL", 8, NVME_LIST_FEATS_IMPL, nvmeadm_list_features_ofmt_cb },
	{ NULL, 0, 0, NULL }
};
