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

#ifndef _NVME_COMMON_H
#define	_NVME_COMMON_H

/*
 * Collection of common files and utilities that can be used for NVMe related
 * functionality. Broadly, these are meant so that the kernel and userland have
 * consistent validation routines.
 *
 * When we perform error checking and validation we use the kernel's set of
 * ioctl errors for more semantic errors. These semantic errors are translated
 * into ones that the library wishes to expose. Our goal is to try to use a
 * mostly uniform error checking framework between the two entities.
 *
 * A consumer must build nvme_version.o and nvme_field.o. Other pieces can be
 * added based on their needs.
 */

#include <sys/stdbool.h>
#include <sys/nvme.h>
#include <sys/nvme/discovery.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Version related pieces from nvme_version.c. The main idea is that consumers
 * such as the kernel and libnvme will wrap up the nvme_vers_atleast() function
 * with an object that contains an NVMe version, thus reducing the likelihood
 * that we'll confuse versions.
 */
extern const nvme_version_t nvme_vers_1v0;
extern const nvme_version_t nvme_vers_1v1;
extern const nvme_version_t nvme_vers_1v2;
extern const nvme_version_t nvme_vers_1v3;
extern const nvme_version_t nvme_vers_1v4;
extern const nvme_version_t nvme_vers_2v0;
extern const nvme_version_t nvme_vers_2v1;

extern bool nvme_vers_atleast(const nvme_version_t *, const nvme_version_t *);

/*
 * This structure contains information about the controller that must be
 * supplied to the various validation functions.
 */
typedef struct nvme_valid_ctrl_data {
	const nvme_version_t *vcd_vers;
	const nvme_identify_ctrl_t *vcd_id;
} nvme_valid_ctrl_data_t;

/*
 * This structure is used to represent a field that is in use in a given
 * command. This allows us to use common validation logic for different classes
 * of commands such as IDENTIFY, GET LOG PAGE, etc. If everything is fine about
 * a field, then it should return true. Otherwise, it should return false and
 * fill out the error message. It is optional to override the specifics of the
 * nvme_ioctl_err_t with a more specific error where appropriate and known. If
 * it is not filled in, the validation default will be used.
 */
struct nvme_field_info;
typedef bool (*nvme_field_sup_f)(const struct nvme_field_info *,
    const nvme_valid_ctrl_data_t *, char *, size_t);
typedef bool (*nvme_field_valid_f)(const struct nvme_field_info *,
    const nvme_valid_ctrl_data_t *, uint64_t, char *, size_t);

typedef struct nvme_field_info {
	const nvme_version_t *nlfi_vers;
	nvme_field_sup_f nlfi_sup;
	uint64_t nlfi_max_size;
	nvme_field_valid_f nlfi_valid;
	/*
	 * Fields below this point are mostly meant to be used by libnvme and by
	 * our printing logic, which we assume is not executed in the kernel.
	 */
	const char *nlfi_spec;
	const char *nlfi_human;
	bool nlfi_def_req;
	bool nlfi_def_allow;
} nvme_field_info_t;

typedef enum {
	NVME_FIELD_ERR_OK = 0,
	NVME_FIELD_ERR_UNSUP_VERSION,
	NVME_FIELD_ERR_UNSUP_FIELD,
	NVME_FIELD_ERR_BAD_VALUE
} nvme_field_error_t;

extern nvme_field_error_t nvme_field_validate(const nvme_field_info_t *,
    const nvme_valid_ctrl_data_t *, uint64_t, char *, size_t);

/*
 * Various common utility routines for field validation and implementation. This
 * version of NSID checking treats the NSID as valid. Currently checking for the
 * validity of the broadcast namespace ID is left to consumers.
 */
extern bool nvme_field_atleast(const nvme_valid_ctrl_data_t *,
    const nvme_version_t *);
extern bool nvme_field_valid_nsid(const nvme_field_info_t *,
    const nvme_valid_ctrl_data_t *, uint64_t, char *, size_t);
extern bool nvme_field_range_check(const nvme_field_info_t *, uint64_t,
    uint64_t, char *, size_t, uint64_t);
extern bool nvme_field_mask_check(const nvme_field_info_t *, uint64_t, char *,
    size_t, uint64_t);

/*
 * Log page request information. The goal with these structures and fields is to
 * be able to validate whether something is valid, both in user/kernel context.
 * This phrasing also makes this much easier to unit test. Because information
 * is shared between libnvme and the kernel, some things are not needed for the
 * kernel. We do not ifdef it out for the moment, to simplify things.
 */

/*
 * This is the set of fields that the driver knows about how to validate that
 * can end up in an NVMe log request. Items should be added here once the kernel
 * knows how to put them in a log request command.
 */
typedef enum {
	NVME_LOG_REQ_FIELD_LID	= 0,
	NVME_LOG_REQ_FIELD_LSP,
	NVME_LOG_REQ_FIELD_LSI,
	NVME_LOG_REQ_FIELD_SIZE,
	NVME_LOG_REQ_FIELD_CSI,
	NVME_LOG_REQ_FIELD_RAE,
	NVME_LOG_REQ_FIELD_OFFSET,
	NVME_LOG_REQ_FIELD_NSID
} nvme_log_req_field_t;

extern const nvme_field_info_t nvme_log_fields[];
extern const size_t nvme_log_nfields;

/*
 * We now use the field based information to have a common structure to define
 * information about standard log pages.
 */
typedef struct nvme_log_page_info nvme_log_page_info_t;
typedef bool (*nvme_log_page_sup_f)(const nvme_valid_ctrl_data_t *,
    const nvme_log_page_info_t *);
typedef uint64_t (*nvme_log_page_len_f)(const nvme_valid_ctrl_data_t *,
    const nvme_log_page_info_t *);
typedef nvme_log_disc_scope_t (*nvme_log_page_scope_f)(
    const nvme_valid_ctrl_data_t *, const nvme_log_page_info_t *);
typedef bool (*nvme_log_page_var_len_f)(uint64_t *, const void *, size_t);

struct nvme_log_page_info {
	const char *nlpi_short;
	const char *nlpi_human;
	uint32_t nlpi_lid;
	nvme_csi_t nlpi_csi;
	/*
	 * These two entries can be used to determine whether a log page is
	 * supported based upon its version or with a supplemental function. A
	 * NULL item means it doesn't need to be checked. This would be the case
	 * for vendor-specific logs.
	 */
	const nvme_version_t *nlpi_vers;
	const nvme_log_page_sup_f nlpi_sup_func;
	nvme_log_disc_kind_t nlpi_kind;
	nvme_log_disc_source_t nlpi_source;
	nvme_log_disc_fields_t nlpi_disc;
	/*
	 * Log pages are valid in certain contexts. This is generally static
	 * information, but if the scope function is implemented, we will use
	 * that and ignore the contents of nlpi_scope.
	 */
	nvme_log_disc_scope_t nlpi_scope;
	nvme_log_page_scope_f nlpi_scope_func;
	/*
	 * The lengths for a log page come in three forms. The first form is
	 * ones where we can determine based on information in the controller
	 * (or at build time) the length of the log page. Many log pages have a
	 * fixed length or they include information in the identify controller
	 * data structure as to their length (e.g. the error log page). To
	 * communicate the log page's length, we will first check if
	 * nlpi_len_func is non-NULL and call that to determine the log page
	 * length. Otherwise we will use the value in nlpi_len. If these return
	 * a non-zero value, the NVME_LOG_DISC_F_SIZE_FIXED will be set
	 * automatically.
	 *
	 * The second form of log pages are those whose length is variable, but
	 * we cannot determine it based on information present in the
	 * controller. Rather we must read some amount of data from the log page
	 * to figure this out at all. For example, many vendor specific logs
	 * have a first uint32_t that indicates the number of valid samples and
	 * therefore you must read that to determine the overall length of the
	 * log page. This case follows the same path as the first case; however,
	 * one must also set the nlpi_var_func function pointer. This results
	 * in the NVME_LOG_DISC_F_SIZE_VAR flag being set.
	 *
	 * The third set of these are ones we just don't know about. In this
	 * case, leave nlpi_len set to zero and nlpi_len_func to NULL. If this
	 * happens or neither path returns a valid size (i.e. 0) then we will
	 * set this to a general size that should be large enough (i.e. the
	 * non-extended NVMe log page size) and not set either size flag.
	 */
	uint64_t nlpi_len;
	nvme_log_page_len_f nlpi_len_func;
	nvme_log_page_var_len_f nlpi_var_func;
};

extern const nvme_log_page_info_t nvme_std_log_pages[];
extern const size_t nvme_std_log_npages;

/*
 * These are functions that can be used to compute information about what's
 * supported and similar information that sometimes requires dynamic support.
 */
extern nvme_log_disc_scope_t nvme_log_page_info_scope(
    const nvme_log_page_info_t *, const nvme_valid_ctrl_data_t *);
extern uint64_t nvme_log_page_info_size(const nvme_log_page_info_t *,
    const nvme_valid_ctrl_data_t *, bool *);
extern bool nvme_log_page_info_supported(const nvme_log_page_info_t *,
    const nvme_valid_ctrl_data_t *);

/*
 * This next section identifies the various fields that make up the NVMe
 * IDENTIFY command and the corresponding pieces that are in use throughout.
 */
typedef enum {
	NVME_ID_REQ_F_CNS = 0,
	NVME_ID_REQ_F_NSID,
	NVME_ID_REQ_F_CTRLID,
	NVME_ID_REQ_F_BUF,
} nvme_identify_req_field_t;

typedef enum {
	/*
	 * Indicates that we allow this identify command to operate on a
	 * namespace minor.
	 */
	NVME_IDENTIFY_INFO_F_NS_OK		= 1 << 0,
	/*
	 * Indicates that if we support namespace management we should attempt
	 * to use the broadcast nsid when asking about the controller.
	 */
	NVME_IDENTIFY_INFO_F_BCAST		= 1 << 1,
	/*
	 * This indicates that we are performing an operation which lists
	 * namespace IDs. As such, we don't need to validate the namespace
	 * against the controller's list. In addition, a zero namespace ID is
	 * allowed.
	 */
	NVME_IDENTIFY_INFO_F_NSID_LIST		= 1 << 2
} nvme_identify_info_flags_t;

typedef struct nvme_identify_info nvme_identify_info_t;
typedef bool (*nvme_identify_sup_f)(const nvme_valid_ctrl_data_t *);
struct nvme_identify_info {
	const char			*nii_name;
	nvme_csi_t			nii_csi;
	uint32_t			nii_cns;
	const nvme_version_t		*nii_vers;
	nvme_identify_sup_f		nii_sup_func;
	nvme_identify_req_field_t	nii_fields;
	nvme_identify_info_flags_t	nii_flags;
};

extern const nvme_field_info_t nvme_identify_fields[];
extern const size_t nvme_identify_nfields;
extern const nvme_identify_info_t nvme_identify_cmds[];
extern const size_t nvme_identify_ncmds;

extern bool nvme_identify_info_supported(const nvme_identify_info_t *,
    const nvme_valid_ctrl_data_t *);

/*
 * NVMe Vendor Unique Commands. Note, unlike others this hasn't really changed
 * since it was introduced in NVMe 1.0. While libnvme wraps these up a bit to
 * construct commands, there is no common vendor unique command discovery
 * information as the kernel more or less stays out of it.
 */
typedef enum {
	NVME_VUC_REQ_FIELD_OPC = 0,
	NVME_VUC_REQ_FIELD_NSID,
	NVME_VUC_REQ_FIELD_CDW12,
	NVME_VUC_REQ_FIELD_CDW13,
	NVME_VUC_REQ_FIELD_CDW14,
	NVME_VUC_REQ_FIELD_CDW15,
	NVME_VUC_REQ_FIELD_NDT,
	/*
	 * While the timeout field here is not actually part of the standard, we
	 * require it as part of the command execution and therefore include it
	 * in here.
	 */
	NVME_VUC_REQ_FIELD_TO
} nvme_vuc_req_field_t;

extern const nvme_field_info_t nvme_vuc_fields[];
extern const size_t nvme_vuc_nfields;

/*
 * Firmware download and commit related fields and routines.
 */
typedef enum {
	NVME_FW_LOAD_REQ_FIELD_NUMD = 0,
	NVME_FW_LOAD_REQ_FIELD_OFFSET
} nvme_fw_load_req_field_t;

extern const nvme_field_info_t nvme_fw_load_fields[];
extern const size_t nvme_fw_load_nfields;

extern bool nvme_fw_cmds_supported(const nvme_valid_ctrl_data_t *);
extern uint32_t nvme_fw_load_granularity(const nvme_valid_ctrl_data_t *);

typedef enum {
	NVME_FW_COMMIT_REQ_FIELD_SLOT = 0,
	NVME_FW_COMMIT_REQ_FIELD_ACT
} nvme_fw_commit_req_field_t;

extern const nvme_field_info_t nvme_fw_commit_fields[];
extern const size_t nvme_fw_commit_nfields;

/*
 * Format NVM operations
 */
typedef enum {
	NVME_FORMAT_REQ_FIELD_LBAF	= 0,
	NVME_FORMAT_REQ_FIELD_SES,
	NVME_FORMAT_REQ_FIELD_NSID
} nvme_format_req_field_t;

extern const nvme_field_info_t nvme_format_fields[];
extern const size_t nvme_format_nfields;

extern bool nvme_format_cmds_supported(const nvme_valid_ctrl_data_t *);

/*
 * Feature related requests
 */
typedef enum {
	NVME_GET_FEAT_REQ_FIELD_FID		= 0,
	NVME_GET_FEAT_REQ_FIELD_SEL,
	NVME_GET_FEAT_REQ_FIELD_DPTR,
	NVME_GET_FEAT_REQ_FIELD_CDW11,
	NVME_GET_FEAT_REQ_FIELD_NSID
} nvme_get_feat_req_field_t;

extern const nvme_field_info_t nvme_get_feat_fields[];
extern const size_t nvme_get_feat_nfields;

/*
 * Common feature information.
 */
typedef struct nvme_feat_info nvme_feat_info_t;
typedef bool (*nvme_feat_sup_f)(const nvme_valid_ctrl_data_t *,
    const nvme_feat_info_t *);

struct nvme_feat_info {
	const char *nfeat_short;
	const char *nfeat_spec;
	uint32_t nfeat_fid;
	/*
	 * These three entries can be used to determine whether a feature is
	 * supported or not based upon its version or supplemental information.
	 */
	const nvme_version_t *nfeat_vers;
	const nvme_feat_sup_f nfeat_sup_func;
	nvme_feat_kind_t nfeat_kind;
	/*
	 * These describe whether the feature operates on namespaces or the
	 * controller and misc. flags and information about them.
	 */
	nvme_feat_scope_t nfeat_scope;
	nvme_feat_csi_t nfeat_csi;
	nvme_feat_flags_t nfeat_flags;
	/*
	 * These four entries describe what an NVMe device uses as input and
	 * output fields.
	 */
	nvme_get_feat_fields_t nfeat_in_get;
	nvme_set_feat_fields_t nfeat_in_set;
	nvme_feat_output_t nfeat_out_get;
	nvme_feat_output_t nfeat_out_set;
	/*
	 * Feature data size. This should be zero if the feature does not use a
	 * data payload. Right now we assume the get and set sizes are identical
	 * as that's how this normally works.
	 */
	uint64_t nfeat_len;
};

extern const nvme_feat_info_t nvme_std_feats[];
extern const size_t nvme_std_nfeats;

extern nvme_feat_impl_t nvme_feat_supported(const nvme_feat_info_t *,
    const nvme_valid_ctrl_data_t *);

/*
 * Namespace Management and Namespace Attach Commands.
 *
 * These operations have their own sets of NVMe admin operations codes.
 * Separately, they then each have a means of selecting what they operate on in
 * dw10. Unlike other operations like Get Features or Get Log Page, these are
 * broken into separate ioctls in the kernel. In libnvme, namespace attach has a
 * single command, but namespace create and delete are treated separately.
 */

typedef enum {
	NVME_NS_CREATE_REQ_FIELD_CSI = 0,
	NVME_NS_CREATE_REQ_FIELD_NSZE,
	NVME_NS_CREATE_REQ_FIELD_NCAP,
	NVME_NS_CREATE_REQ_FIELD_FLBAS,
	NVME_NS_CREATE_REQ_FIELD_NMIC
} nvme_ns_create_req_field_t;

typedef enum {
	NVME_NS_DELETE_REQ_FIELD_NSID = 0
} nvme_ns_delete_req_field_t;

/*
 * Strictly speaking some of these fields, such as the controller list, are
 * specific to the type of sub-command put into the SEL field.
 */
typedef enum {
	NVME_NS_ATTACH_REQ_FIELD_SEL = 0,
	NVME_NS_ATTACH_REQ_FIELD_NSID,
	NVME_NS_ATTACH_REQ_FIELD_DPTR
} nvme_ns_attach_req_field_t;

extern bool nvme_nsmgmt_cmds_supported(const nvme_valid_ctrl_data_t *);
extern const nvme_field_info_t nvme_ns_attach_fields[];
extern const size_t nvme_ns_attach_nfields;
extern const nvme_field_info_t nvme_ns_create_fields[];
extern const size_t nvme_ns_create_nfields;
extern const nvme_field_info_t nvme_ns_delete_fields[];
extern const size_t nvme_ns_delete_nfields;

/*
 * Allowed and required fields by CSI.
 */
extern const nvme_ns_create_req_field_t nvme_ns_create_fields_nvm_req[];
extern const size_t nvme_ns_create_fields_nvm_nreq;
extern const nvme_ns_create_req_field_t nvme_ns_create_fields_nvm_allow[];
extern const size_t nvme_ns_create_fields_nvm_nallow;

#ifdef __cplusplus
}
#endif

#endif /* _NVME_COMMON_H */
