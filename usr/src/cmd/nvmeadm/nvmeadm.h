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
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

#ifndef _NVMEADM_H
#define	_NVMEADM_H

#include <stdio.h>
#include <libdevinfo.h>
#include <libnvme.h>
#include <nvme_common.h>
#include <nvme_reg.h>
#include <ofmt.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int verbose;
extern int debug;

/* Common structures */
typedef struct nvme_process_arg nvme_process_arg_t;
typedef struct nvmeadm_feature nvmeadm_feature_t;
typedef struct nvmeadm_cmd nvmeadm_cmd_t;

#define	NVMEADM_C_MULTI	1
#define	NVMEADM_C_EXCL	2

/*
 * General command structure
 */
struct nvmeadm_cmd {
	const char *c_name;
	const char *c_desc;
	const char *c_flagdesc;
	const char *c_fielddesc;
	int (*c_func)(const nvme_process_arg_t *);
	void (*c_usage)(const char *);
	void (*c_optparse)(nvme_process_arg_t *);
	int c_flags;
};

/*
 * This is used to represent information for getting and printing specific
 * features.
 */
struct nvmeadm_feature {
	uint8_t f_feature;
	boolean_t (*f_get)(const nvme_process_arg_t *, const nvme_feat_disc_t *,
	    const nvmeadm_feature_t *);
	void (*f_print)(uint32_t, void *, size_t, const nvme_identify_ctrl_t *,
	    const nvme_version_t *);
};

struct nvme_process_arg {
	nvme_t *npa_nvme;
	nvme_ctrl_t *npa_ctrl;
	nvme_ns_t *npa_ns;
	nvme_ctrl_info_t *npa_ctrl_info;
	nvme_ns_info_t *npa_ns_info;
	int npa_argc;
	char **npa_argv;
	char *npa_name;
	const char *npa_ctrl_name;
	boolean_t npa_excl;
	uint32_t npa_cmdflags;
	const nvmeadm_cmd_t *npa_cmd;
	const nvme_identify_ctrl_t *npa_idctl;
	const nvme_version_t *npa_version;
	ofmt_handle_t npa_ofmt;
	void *npa_cmd_arg;
};

/*
 * Command-specific arguments
 */
typedef struct {
	boolean_t nll_unimpl;
	nvme_log_disc_scope_t nll_scope;
	uint32_t nll_nprint;
	int nll_nfilts;
	char *const *nll_filts;
	boolean_t *nll_used;
} nvmeadm_list_logs_t;

typedef struct {
	boolean_t nf_unimpl;
	uint32_t nf_nprint;
	uint32_t nf_nfilts;
	char *const *nf_filts;
	boolean_t *nf_used;
} nvmeadm_features_t;

typedef struct {
	boolean_t ncn_use_flbas;
	nvme_csi_t ncn_csi;
	uint64_t ncn_size;
	uint64_t ncn_cap;
	uint32_t ncn_lba;
	uint32_t ncn_nmic;
} nvmeadm_create_ns_t;

typedef struct {
	const char *ngl_output;
} nvmeadm_get_logpage_t;

/* Version checking */
extern boolean_t nvme_version_check(const nvme_process_arg_t *,
    const nvme_version_t *);

/* printing functions */
extern int nvme_strlen(const char *, int);
extern void nvme_print(int, const char *, int, const char *, ...);
extern int nvme_snprint_uint128(char *, size_t, nvme_uint128_t, int, int);
extern void nvme_print_ctrl_summary(nvme_ctrl_info_t *);
extern void nvme_print_nsid_summary(nvme_ns_info_t *);
extern void nvme_print_identify_ctrl(const nvme_identify_ctrl_t *, uint32_t,
    const nvme_version_t *);
extern void nvme_print_identify_nsid(const nvme_identify_nsid_t *,
    const nvme_version_t *);
extern void nvme_print_identify_nsid_list(const char *,
    const nvme_identify_nsid_list_t *);
extern void nvme_print_identify_nsid_desc(void *);
extern void nvme_print_identify_ctrl_list(const char *,
    const nvme_identify_ctrl_list_t *);
extern void nvme_print_error_log(int, const nvme_error_log_entry_t *,
    const nvme_version_t *);
extern void nvme_print_health_log(const nvme_health_log_t *,
    const nvme_identify_ctrl_t *,
    const nvme_version_t *);
extern void nvme_print_fwslot_log(const nvme_fwslot_log_t *,
    const nvme_identify_ctrl_t *);

extern void nvme_print_feat_unknown(nvme_feat_output_t, uint32_t, void *,
    size_t);
extern void nvme_print_feat_arbitration(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_power_mgmt(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_lba_range(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_temperature(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_error(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_write_cache(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_nqueues(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_intr_coal(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_intr_vect(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_write_atom(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_async_event(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_auto_pst(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_progress(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);
extern void nvme_print_feat_host_behavior(uint32_t, void *, size_t,
    const nvme_identify_ctrl_t *, const nvme_version_t *);

extern void nvmeadm_dump_hex(const uint8_t *, size_t);

/*
 * ofmt related
 */
typedef struct {
	const char *nloa_name;
	di_node_t nloa_dip;
	nvme_ctrl_info_t *nloa_ctrl;
	nvme_ns_info_t *nloa_ns;
	const char *nloa_disk;
	const char *nloa_state;
} nvmeadm_list_ofmt_arg_t;

extern const ofmt_field_t nvmeadm_list_ctrl_ofmt[];
extern const ofmt_field_t nvmeadm_list_nsid_ofmt[];

typedef struct {
	const char *nlloa_name;
	const nvme_log_disc_t *nlloa_disc;
} nvmeadm_list_logs_ofmt_arg_t;

extern const char *nvmeadm_list_logs_fields;
extern const char *nvmeadm_list_logs_fields_impl;
extern const ofmt_field_t nvmeadm_list_logs_ofmt[];

typedef struct {
	const char *nlfoa_name;
	const nvme_feat_disc_t *nlfoa_feat;
} nvmeadm_list_features_ofmt_arg_t;

extern const char *nvmeadm_list_features_fields;
extern const ofmt_field_t nvmeadm_list_features_ofmt[];

/*
 * Log pages that have special handling.
 */
extern int do_get_logpage_telemetry(const nvme_process_arg_t *,
    const nvme_log_disc_t *, nvme_log_req_t *);

/*
 * Warning and error cases. The default nvmeadm ones assume a libnvme related
 * issue. Most errors are on the nvme_ctrl_t, which are the versions without any
 * args. The ones that operate on the nvme_t handle have hdl in the name.
 */
extern void nvmeadm_warn(const nvme_process_arg_t *, const char *,
    ...) __PRINTFLIKE(2);
extern void nvmeadm_fatal(const nvme_process_arg_t *, const char *,
    ...) __PRINTFLIKE(2) __NORETURN;
extern void nvmeadm_hdl_warn(const nvme_process_arg_t *, const char *,
    ...) __PRINTFLIKE(2);
extern void nvmeadm_hdl_fatal(const nvme_process_arg_t *, const char *,
    ...) __PRINTFLIKE(2) __NORETURN;

/*
 * Namespace Management Commands
 */
extern int do_create_ns(const nvme_process_arg_t *);
extern void optparse_create_ns(nvme_process_arg_t *);
extern void usage_create_ns(const char *);

extern int do_delete_ns(const nvme_process_arg_t *);
extern void usage_delete_ns(const char *);

extern int do_attach_ns(const nvme_process_arg_t *);
extern void usage_attach_ns(const char *);

extern int do_detach_ns(const nvme_process_arg_t *);
extern void usage_detach_ns(const char *);

/*
 * Vendor specific commands.
 *
 * All vendor commands must first call nvmeadm_vuc_validate() which will
 * validate that a given vendor unique command is useable by the device and then
 * proceed to take any necessary locks that the command suggests.
 */
extern nvme_vuc_disc_t *nvmeadm_vuc_init(const nvme_process_arg_t *,
    const char *);
extern void nvmeadm_vuc_fini(const nvme_process_arg_t *, nvme_vuc_disc_t *);

extern int do_wdc_e6dump(const nvme_process_arg_t *);
extern void optparse_wdc_e6dump(nvme_process_arg_t *);
extern void usage_wdc_e6dump(const char *);

extern int do_wdc_resize(const nvme_process_arg_t *);
extern void optparse_wdc_resize(nvme_process_arg_t *);
extern void usage_wdc_resize(const char *);

extern int do_wdc_clear_assert(const nvme_process_arg_t *);
extern void usage_wdc_clear_assert(const char *);

extern int do_wdc_inject_assert(const nvme_process_arg_t *);
extern void usage_wdc_inject_assert(const char *);

#ifdef __cplusplus
}
#endif

#endif /* _NVMEADM_H */
