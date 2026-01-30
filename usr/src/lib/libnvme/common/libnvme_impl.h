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

#ifndef _LIBNVME_IMPL_H
#define	_LIBNVME_IMPL_H

/*
 * Implementation structures and related for libnvme.
 */

#include <libnvme.h>
#include <libdevinfo.h>
#include <stdbool.h>
#include <nvme_common.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum size of an internal error message.
 */
#define	NVME_ERR_LEN	1024

typedef struct nvme_err_data {
	nvme_err_t ne_err;
	int32_t ne_syserr;
	char ne_errmsg[NVME_ERR_LEN];
	size_t ne_errlen;
	uint32_t ne_ctrl_sct;
	uint32_t ne_ctrl_sc;
} nvme_err_data_t;

struct nvme {
	nvme_err_data_t nh_err;
	di_node_t nh_devinfo;
};

struct nvme_ctrl_disc {
	di_node_t ncd_devi;
	di_minor_t ncd_minor;
};

struct nvme_ctrl_iter {
	nvme_t *ni_nvme;
	bool ni_done;
	di_node_t ni_cur;
	nvme_ctrl_disc_t ni_disc;
};

typedef enum {
	/*
	 * This indicates that we have attempted to fill in the NVMe 2.0
	 * supported logs page information and therefore can use it as part of
	 * log page discovery. This is filled in lazily on a handle and will
	 * persist as long as a handle does. If the log page is not supported or
	 * an error occurred then the VALID flag will be set, but the
	 * nc_sup_logs member will be set to NULL to indicate that we don't have
	 * the information.
	 *
	 * When the log page is supported, but something has gone wrong, we will
	 * set the FAILED flag to indicate that. Presuming it wasn't a memory
	 * failure, then we try to save a copy of the resulting nvme_err_data_t.
	 * This information isn't exposed outside of the library, but is kept on
	 * the handle to aid debugging.
	 */
	NVME_CTRL_F_SUP_LOGS_VALID	= 1 << 0,
	NVME_CTRL_F_SUP_LOGS_FAILED	= 1 << 1
} nvme_ctrl_flags_t;

struct nvme_ctrl {
	nvme_t *nc_nvme;
	nvme_err_data_t nc_err;
	di_node_t nc_devi;
	di_minor_t nc_minor;
	char *nc_devi_path;
	int32_t nc_inst;
	int nc_fd;
	nvme_version_t nc_vers;
	nvme_identify_ctrl_t nc_info;
	const struct nvme_vsd *nc_vsd;
	nvme_ctrl_flags_t nc_flags;
	nvme_suplog_log_t *nc_sup_logs;
	nvme_err_data_t *nc_sup_logs_err;
};

struct nvme_ns_disc {
	uint32_t nnd_nsid;
	nvme_ns_disc_level_t nnd_level;
	nvme_ns_disc_flags_t nnd_flags;
	uint8_t nnd_eui64[8];
	uint8_t nnd_nguid[16];
};

struct nvme_ns_iter {
	nvme_ctrl_t *nni_ctrl;
	nvme_ns_disc_level_t nni_level;
	bool nni_err;
	bool nni_done;
	size_t nni_cur_idx;
	nvme_ns_disc_t nni_disc;
};

struct nvme_ns {
	nvme_ctrl_t *nn_ctrl;
	uint32_t nn_nsid;
};

struct nvme_nvm_lba_fmt {
	uint32_t nnlf_id;
	uint32_t nnlf_ms;
	uint64_t nnlf_lbasz;
	uint32_t nnlf_rel;
};

struct nvme_ctrl_info {
	nvme_info_err_t nci_err;
	int32_t nci_syserr;
	char nci_errmsg[NVME_ERR_LEN];
	size_t nci_errlen;
	/*
	 * The NVMe strings are generally ASCII strings that have trailing
	 * spaces on them ala SCSI. We transform that into a C style string
	 * without trailing padding. The +1 assumes we need to add a terminator.
	 */
	char nci_serial[NVME_SERIAL_SZ + 1];
	char nci_model[NVME_MODEL_SZ + 1];
	char nci_fwrev[NVME_FWVER_SZ + 1];
	bool nci_lbaf_valid[NVME_MAX_LBAF];
	nvme_nvm_lba_fmt_t nci_lbaf[NVME_MAX_LBAF];
	/*
	 * Only information below here should be persisted. That is, the above
	 * information is meant to be specific to the library.
	 */
	nvme_version_t nci_vers;
	int32_t nci_inst;
	char nci_dev_path[PATH_MAX];
	nvme_identify_ctrl_t nci_info;
	nvme_identify_nsid_t nci_ns;
	nvme_ctrl_transport_t nci_tport;
	uint16_t nci_vid;
	uint16_t nci_did;
	uint16_t nci_subvid;
	uint16_t nci_subsys;
	uint8_t nci_rev;
	uint32_t nci_mps_min;
	uint32_t nci_mps_max;
	uint32_t nci_nintrs;
};

/*
 * Internal nvlist_t keys for control information.
 */
#define	NVME_NVL_CI_VERS	"version"
#define	NVME_NVL_CI_VERS_0	0
#define	NVME_NVL_CI_INST	"inst"
#define	NVME_NVL_CI_MAJOR	"nvme-major-version"
#define	NVME_NVL_CI_MINOR	"nvme-minor-version"
#define	NVME_NVL_CI_DEV_PATH	"dev-path"
#define	NVME_NVL_CI_ID_CTRL	"identify-controller"
#define	NVME_NVL_CI_ID_NS	"identify-namespace"
#define	NVME_NVL_CI_TPORT	"transport"
#define	NVME_NVL_CI_PCI_VID	"pci-vendor-id"
#define	NVME_NVL_CI_PCI_DID	"pci-device-id"
#define	NVME_NVL_CI_PCI_SUBVID	"pci-subsystem-vendor-id"
#define	NVME_NVL_CI_PCI_SUBSYS	"pci-subsystem-id"
#define	NVME_NVL_CI_PCI_REV	"pci-revision-id"
#define	NVME_NVL_CI_PCI_MPSMIN	"pci-memory-page-size-min"
#define	NVME_NVL_CI_PCI_MPSMAX	"pci-memory-page-size-max"
#define	NVME_NVL_CI_PCI_NINTRS	"pci-num-interrupts"

struct nvme_ns_info {
	nvme_info_err_t nni_err;
	int32_t nni_syserr;
	char nni_errmsg[NVME_ERR_LEN];
	size_t nni_errlen;
	uint32_t nni_nsid;
	nvme_version_t nni_vers;
	nvme_ns_disc_level_t nni_level;
	nvme_ioctl_ns_info_t nni_info;
	bool nni_lbaf_valid[NVME_MAX_LBAF];
	nvme_nvm_lba_fmt_t nni_lbaf[NVME_MAX_LBAF];
};

typedef enum {
	NVME_LOG_REQ_F_RAE		= 1 << 0,
	NVME_LOG_REQ_F_BCAST_NS_OK	= 1 << 1
} nvme_log_req_flags_t;

struct nvme_log_req {
	nvme_ctrl_t *nlr_ctrl;
	uint32_t nlr_need;
	uint32_t nlr_allow;
	nvme_csi_t nlr_csi;
	uint32_t nlr_lid;
	uint32_t nlr_lsp;
	uint32_t nlr_lsi;
	uint32_t nlr_nsid;
	nvme_log_req_flags_t nlr_flags;
	void *nlr_output;
	size_t nlr_output_len;
	uint64_t nlr_offset;
};

/*
 * This structure is used internally to describe information about a given log
 * page.
 */
typedef enum {
	/*
	 * This indicates that the log page is actually implemented.
	 */
	NVME_LOG_DISC_F_IMPL		= 1 << 0
} nvme_log_disc_flags_t;

struct nvme_log_disc {
	const char		*nld_short;
	const char		*nld_desc;
	uint32_t		nld_lid;
	nvme_csi_t		nld_csi;
	nvme_log_disc_kind_t	nld_kind;
	nvme_log_disc_source_t	nld_srcs;
	nvme_log_disc_fields_t	nld_fields;
	nvme_log_disc_scope_t	nld_scope;
	nvme_log_disc_flags_t	nld_flags;
	nvme_log_size_kind_t	nld_size_kind;
	uint64_t		nld_alloc_len;
	nvme_log_page_var_len_f	nld_var_func;
};

struct nvme_log_iter {
	nvme_ctrl_t *nli_ctrl;
	nvme_log_disc_scope_t nli_scope;
	bool nli_std_done;
	bool nli_vs_done;
	size_t nli_cur_idx;
	nvme_log_disc_t nli_nld;
};

/*
 * Feature discovery and iteration.
 */
struct nvme_feat_disc {
	const char *nfd_short;
	const char *nfd_spec;
	uint32_t nfd_fid;
	nvme_feat_kind_t nfd_kind;
	nvme_feat_scope_t nfd_scope;
	nvme_feat_flags_t nfd_flags;
	nvme_feat_csi_t nfd_csi;
	nvme_get_feat_fields_t nfd_in_get;
	nvme_set_feat_fields_t nfd_in_set;
	nvme_feat_output_t nfd_out_get;
	nvme_feat_output_t nfd_out_set;
	uint64_t nfd_len;
	nvme_feat_impl_t nfd_impl;
};

struct nvme_feat_iter {
	nvme_ctrl_t *nfi_ctrl;
	nvme_feat_scope_t nfi_scope;
	size_t nfi_cur_idx;
	nvme_feat_disc_t nfi_disc;
};

struct nvme_get_feat_req {
	nvme_ctrl_t *gfr_ctrl;
	uint32_t gfr_need;
	uint32_t gfr_allow;
	nvme_feat_flags_t gfr_flags;
	uint32_t gfr_fid;
	uint32_t gfr_sel;
	uint32_t gfr_nsid;
	uint32_t gfr_cdw11;
	void *gfr_buf;
	size_t gfr_len;
	uint64_t gfr_targ_len;
	/*
	 * The following are set on exec.
	 */
	bool gfr_results_valid;
	uint32_t gfr_cdw0;
};

/*
 * Identify command request
 */
struct nvme_id_req {
	nvme_ctrl_t *nir_ctrl;
	const nvme_identify_info_t *nir_info;
	nvme_identify_req_field_t nir_need;
	nvme_identify_req_field_t nir_allow;
	uint32_t nir_nsid;
	uint32_t nir_ctrlid;
	void *nir_buf;
};

/*
 * Vendor unique command support.
 */
struct nvme_vuc_disc {
	const char *nvd_short;
	const char *nvd_desc;
	uint8_t nvd_opc;
	nvme_vuc_disc_impact_t nvd_impact;
	nvme_vuc_disc_io_t nvd_dt;
	nvme_vuc_disc_lock_t nvd_lock;
};

struct nvme_vuc_iter {
	nvme_ctrl_t *nvi_ctrl;
	size_t nvi_cur_idx;
};

struct nvme_vuc_req {
	nvme_ctrl_t *nvr_ctrl;
	uint32_t nvr_need;
	uint32_t nvr_opcode;
	uint32_t nvr_timeout;
	uint32_t nvr_nsid;
	uint32_t nvr_cdw12;
	uint32_t nvr_cdw13;
	uint32_t nvr_cdw14;
	uint32_t nvr_cdw15;
	uint32_t nvr_impact;
	size_t nvr_outlen;
	size_t nvr_inlen;
	void *nvr_output;
	const void *nvr_input;
	/*
	 * The following values are set on exec.
	 */
	bool nvr_results_valid;
	uint32_t nvr_cdw0;
};

/*
 * If we ever support updating the boot partition ID, our expectation is that we
 * end up doing that through other library interfaces even if it uses the same
 * underlying ioctl. That ultimately will keep things simpler from a consumer
 * perspective.
 */
struct nvme_fw_commit_req {
	nvme_ctrl_t *fwc_ctrl;
	uint32_t fwc_need;
	uint32_t fwc_slot;
	uint32_t fwc_action;
};

/*
 * Format request data.
 */
struct nvme_format_req {
	nvme_ctrl_t *nfr_ctrl;
	uint32_t nfr_need;
	bool nfr_ns;
	uint32_t nfr_lbaf;
	uint32_t nfr_ses;
	uint32_t nfr_nsid;
};

/*
 * Namespace Attach request.
 */
struct nvme_ns_attach_req {
	nvme_ctrl_t *nar_ctrl;
	uint32_t nar_need;
	uint32_t nar_nsid;
	uint32_t nar_sel;
};

/*
 * Namespace Delete request.
 */
struct nvme_ns_delete_req {
	nvme_ctrl_t *ndr_ctrl;
	uint32_t ndr_need;
	uint32_t ndr_nsid;
};

/*
 * Namespace Create request.
 */
struct nvme_ns_create_req {
	nvme_ctrl_t *ncr_ctrl;
	nvme_csi_t ncr_csi;
	uint32_t ncr_need;
	uint32_t ncr_allow;
	uint64_t ncr_nsze;
	uint64_t ncr_ncap;
	uint32_t ncr_flbas;
	uint32_t ncr_nmic;
	/*
	 * The following are set on exec.
	 */
	bool ncr_results_valid;
	uint32_t ncr_nsid;
};

/*
 * WDC e6 request. This was made an opaque request style structure to try to
 * safeguard us against future changes where something like the optional mode
 * byte was required (right now it's just always zero).
 */
struct nvme_wdc_e6_req {
	uint32_t wer_need;
	nvme_vuc_req_t *wer_vuc;
};

/*
 * Common interfaces for operation success and failure. There are currently
 * errors that can exist on four different objects in the library and there is
 * one success() and error() function for each of them. See the theory statement
 * section on errors in libnvme.c for more information. Note, all namespace and
 * request structures set errors on the controller.
 *
 * The controller has an extra error path that is used for converting ioctls to
 * semantic errors. It takes care of translating the different kinds of kernel
 * errors to the library's errors. Our goal is to never programmatically leak
 * the kernel ioctls and their error codes as they do not promise stability
 * unlike our aspirations. It also doesn't allow for variable arguments and only
 * takes a single description.
 */
extern bool nvme_error(nvme_t *, nvme_err_t, int32_t, const char *,
    ...)  __PRINTFLIKE(4);
extern bool nvme_success(nvme_t *);

extern bool nvme_ctrl_error(nvme_ctrl_t *, nvme_err_t, int32_t, const char *,
    ...)  __PRINTFLIKE(4);
extern bool nvme_ioctl_error(nvme_ctrl_t *, const nvme_ioctl_common_t *,
    const char *);
extern bool nvme_ioctl_syserror(nvme_ctrl_t *, int, const char *);
extern bool nvme_ctrl_success(nvme_ctrl_t *);

extern bool nvme_info_error(nvme_ctrl_info_t *, nvme_info_err_t, int32_t,
    const char *, ...)  __PRINTFLIKE(4);
extern bool nvme_info_success(nvme_ctrl_info_t *);

extern bool nvme_ns_info_error(nvme_ns_info_t *, nvme_info_err_t, int32_t,
    const char *, ...)  __PRINTFLIKE(4);
extern bool nvme_ns_info_success(nvme_ns_info_t *);

/*
 * Common functions for preserving and restoring error data. This comes up when
 * utilizing callback functions for discovery where we call libnvme functions.
 */
extern void nvme_err_save(const nvme_t *, nvme_err_data_t *);
extern void nvme_err_set(nvme_t *, const nvme_err_data_t *);
extern void nvme_ctrl_err_save(const nvme_ctrl_t *, nvme_err_data_t *);
extern void nvme_ctrl_err_set(nvme_ctrl_t *, const nvme_err_data_t *);

/*
 * Common functions for issuing ioctls to a controller.
 */
extern bool nvme_ioc_ctrl_info(nvme_ctrl_t *, nvme_ioctl_ctrl_info_t *);
extern bool nvme_ioc_ns_info(nvme_ctrl_t *, uint32_t, nvme_ioctl_ns_info_t *);

/*
 * Common validation template functions.
 */
extern bool nvme_field_miss_err(nvme_ctrl_t *, const nvme_field_info_t *,
    size_t, nvme_err_t, const char *, uint32_t);

typedef struct {
	const nvme_field_info_t *chk_fields;
	size_t chk_index;
	nvme_err_t chk_field_range;
	nvme_err_t chk_field_unsup;
	nvme_err_t chk_field_unuse;
} nvme_field_check_t;

extern bool nvme_field_check_one(nvme_ctrl_t *, uint64_t, const char *,
    const nvme_field_check_t *, uint32_t allow);

/*
 * Misc. functions.
 */
extern const char *nvme_tporttostr(nvme_ctrl_transport_t);
extern nvme_ns_disc_level_t nvme_ns_state_to_disc_level(nvme_ns_state_t);
extern const char *nvme_nsleveltostr(nvme_ns_disc_level_t);

/*
 * Version related information and functions. There are statically declared
 * version structures in the library for use for internal comparisons. Note, we
 * have attempted to avoid a general comparison function in the internal API so
 * that way it's always clear what we're comparing to a version and can't
 * reverse things.
 */
extern const nvme_version_t nvme_vers_1v0;
extern const nvme_version_t nvme_vers_1v1;
extern const nvme_version_t nvme_vers_1v2;
extern const nvme_version_t nvme_vers_1v3;
extern const nvme_version_t nvme_vers_1v4;
extern const nvme_version_t nvme_vers_2v0;

extern bool nvme_vers_ctrl_atleast(const nvme_ctrl_t *, const nvme_version_t *);
extern bool nvme_vers_ctrl_info_atleast(const nvme_ctrl_info_t *,
    const nvme_version_t *);
extern bool nvme_vers_ns_info_atleast(const nvme_ns_info_t *,
    const nvme_version_t *);

/*
 * Vendor-specific information.
 */
typedef struct nvme_vsd_ident {
	const char *nvdi_human;
	bool nvdi_subsys;
	uint16_t nvdi_vid;
	uint16_t nvdi_did;
	uint16_t nvdi_svid;
	uint16_t nvdi_sdid;
} nvme_vsd_ident_t;

typedef struct nvme_vsd {
	const nvme_vsd_ident_t *nvd_ident;
	size_t nvd_nident;
	const nvme_log_page_info_t *const *nvd_logs;
	size_t nvd_nlogs;
	const nvme_vuc_disc_t *nvd_vuc;
	size_t nvd_nvuc;
} nvme_vsd_t;

extern const nvme_log_page_info_t ocp_log_smart;
extern const nvme_log_page_info_t ocp_log_errrec;
extern const nvme_log_page_info_t ocp_log_fwact;
extern const nvme_log_page_info_t ocp_log_lat;
extern const nvme_log_page_info_t ocp_log_devcap;
extern const nvme_log_page_info_t ocp_log_unsup;
extern const nvme_log_page_info_t ocp_log_telstr;

extern const nvme_vsd_t wdc_sn840;
extern const nvme_vsd_t wdc_sn65x;
extern const nvme_vsd_t sandisk_sn861;
extern const nvme_vsd_t micron_7300;
extern const nvme_vsd_t micron_74x0;
extern const nvme_vsd_t micron_x500;
extern const nvme_vsd_t micron_9550;
extern const nvme_vsd_t intel_p5510;
extern const nvme_vsd_t solidigm_p5x20;
extern const nvme_vsd_t solidigm_ps10x0;
extern const nvme_vsd_t kioxia_cd8;
extern const nvme_vsd_t phison_x200;
extern const nvme_vsd_t samsung_pm9d3a;

extern void nvme_vendor_map_ctrl(nvme_ctrl_t *);
extern bool nvme_vendor_vuc_supported(nvme_ctrl_t *, const char *);

/*
 * Internal formatting functions that probably could be external.
 */
#define	NVME_NGUID_NAMELEN	33
#define	NVME_EUI64_NAMELEN	17

extern int nvme_format_nguid(const uint8_t [16], char *, size_t);
extern int nvme_format_eui64(const uint8_t [8], char *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBNVME_IMPL_H */
