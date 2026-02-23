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

typedef enum {
	/*
	 * Indicates a command that is allowed to run on multiple controllers.
	 */
	NVMEADM_C_MULTI	= 1 << 0,
	/*
	 * Indicates a command that requires exclusive access to the device.
	 */
	NVMEADM_C_EXCL = 1 << 1,
	/*
	 * Indicates a command that does not run on a controller and therefore
	 * processing should not assume this.
	 */
	NVMEADM_C_NOCTRL = 1 << 2
} nvmeadm_cmd_flags_t;

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
	nvmeadm_cmd_flags_t c_flags;
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
	bool ngl_hex;
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
 * Physical Eye Commands
 */
extern int do_measure_phyeye_cmd(const nvme_process_arg_t *);
extern void optparse_measure_phyeye_cmd(nvme_process_arg_t *);
extern void usage_measure_phyeye_cmd(const char *);
extern int do_report_phyeye_cmd(const nvme_process_arg_t *);
extern void optparse_report_phyeye_cmd(nvme_process_arg_t *);
extern void usage_report_phyeye_cmd(const char *);

/*
 * Locking functions
 */
extern void nvmeadm_excl(const nvme_process_arg_t *, nvme_lock_level_t);

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
extern int do_vendor_cmd(const nvme_process_arg_t *);
extern void optparse_vendor_cmd(nvme_process_arg_t *);
extern void usage_vendor_cmd(const char *);

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

extern int do_sandisk_hwrev(const nvme_process_arg_t *);
extern void usage_sandisk_hwrev(const char *);

extern int do_sandisk_pcieye(const nvme_process_arg_t *);
extern void optparse_sandisk_pcieye(nvme_process_arg_t *);
extern void usage_sandisk_pcieye(const char *);

/*
 * This is an arbitrary maximum that we use for what we expect the likely size
 * of a log page may end up being. We use 128 MiB as a rough upper bound for
 * what we'll mmap. This is a somewhat arbitrary value, but if we end up having
 * a larger file, then we'll want to be more conscious of memory and probably
 * read in a file in a buffer over time instead of mmap.
 */
#define	NVMEADM_MAX_MMAP	(1ULL << 27)

/*
 * Field slicing and dicing. This is logic that is similar to pcieadm's
 * show-cfgspace which allows us to select specific fields based on the short
 * name of the log from the spec.
 */
typedef struct {
	const char *nff_str;
	size_t nff_len;
	bool nff_used;
} nvmeadm_field_filt_t;

typedef enum nvmeadm_field_type_t {
	/*
	 * Print as a raw hexadecimal value. The optional addend may be set to
	 * modify the value.
	 */
	NVMEADM_FT_HEX,
	/*
	 * A number that should take the same shift as above, but have a
	 * particular unscaled unit applied.
	 */
	NVMEADM_FT_UNIT,
	/*
	 * The raw value maps to a string of some kind.
	 */
	NVMEADM_FT_STRMAP,
	/*
	 * Treat as a power of 2 number of bytes. Raw value is the full hex
	 * value. Otherwise this should be humanized.
	 */
	NVMEADM_FT_BYTES,
	/*
	 * Indicates that this is a nested structure with a series of bitfields
	 * that we should print.
	 */
	NVMEADM_FT_BITS,
	/*
	 * Indicate that there are a series of fields inside of this. Similar in
	 * spirit to BITS above, but generally meant to be used to help separate
	 * stuff which can be a little weirder such as the OCP telemetry string
	 * log or the various extended SMART items. Containers are only included
	 * in human readable output and are not part of the machine parsable
	 * output as they have no value.
	 */
	NVMEADM_FT_CONTAINER,
	/*
	 * Indicates that this field is a normalized percentage. Note, this may
	 * result in a value > 100%.
	 */
	NVMEADM_FT_PERCENT,
	/*
	 * A 16-byte style UUID.
	 */
	NVMEADM_FT_GUID,
	/*
	 * A series of characters that are supposed to be ASCII strings. The
	 * ASCIIZ says that these are NUL padded where as ASCII
	 * is probably space padded. Either way padding is not guaranteed.
	 */
	NVMEADM_FT_ASCII,
	NVMEADM_FT_ASCIIZ
} nvmeadm_field_type_t;

typedef struct {
	uint8_t nfa_shift;
	int64_t nfa_addend;
	const char *nfa_unit;
} nvmeadm_field_addend_t;

typedef struct nvmeadm_field_bit nvmeadm_field_bit_t;
struct nvmeadm_field_bit {
	uint8_t nfb_lowbit;
	uint8_t nfb_hibit;
	const char *nfb_short;
	const char *nfb_desc;
	uint8_t nfb_rev;
	uint8_t nfb_maxrev;
	const nvme_version_t *nfb_vers;
	nvmeadm_field_type_t nfb_type;
	/*
	 * Enough space for up to an 8-bit fields worth of values
	 * (though we expect most to be sparse).
	 */
	const char *nfb_strs[128];
	const nvmeadm_field_bit_t *nfb_bits;
	size_t nfb_nbits;
	nvmeadm_field_addend_t nfb_addend;
};

typedef struct nvmeadm_field nvmeadm_field_t;
struct nvmeadm_field {
	uint32_t nf_off;
	uint32_t nf_len;
	const char *nf_short;
	const char *nf_desc;
	uint32_t nf_rev;
	uint32_t nf_maxrev;
	const nvme_version_t *nf_vers;
	nvmeadm_field_type_t nf_type;
	/*
	 * Enough space for up to an 8-bit fields worth of values
	 * (though we expect most to be sparse).
	 */
	const char *nf_strs[128];
	const nvmeadm_field_bit_t *nf_bits;
	size_t nf_nbits;
	nvmeadm_field_addend_t nf_addend;
	const nvmeadm_field_t *nf_fields;
	size_t nf_nfields;
};

typedef struct nvmeadm_field_print {
	/*
	 * fp_header provides a header when printing this data.  In general,
	 * 'fp_header' should only be used if we are breaking up a single log
	 * page or similar into multiple disjoint tables. This is used when
	 * there's a header for a log page and then a variable set of body
	 * entries (e.g. the PHY Eye Measurement).
	 *
	 * This header is paired with a 'base' string that corresponds to the
	 * short name for this region of the file. This should be set in fp_base
	 * and is required if fp_header is set.
	 */
	const char *fp_header;
	/*
	 * Optional field revision and NVMe version information. If this is
	 * present, the field will be skipped if the object revision or the
	 * controller version is not sufficient. If this is against a file then
	 * the version checks are ignored by default.
	 */
	uint32_t fp_rev;
	const nvme_version_t *fp_vers;
	/*
	 * These are the set of fields to actually print.
	 */
	const nvmeadm_field_t *fp_fields;
	size_t fp_nfields;
	/*
	 * This represents the initial portion of the 'short' path. This will be
	 * prepended to all the different fields in here. This may be NULL if
	 * there is nothing here. When it is NULL, the header should be as well.
	 */
	const char *fp_base;
	/*
	 * The data pointer and its corresponding length of valid data. Note,
	 * fp_off is a logical offset to be added. There is no relationship
	 * assumed between the data pointer and the fp_off. When a field is
	 * processed its embedded offset is always relative to the start of
	 * data. fp_off exists when manually driving so when a data pointer
	 * points to the start of some region that is offset, e.g. a pointer to
	 * the start of some variable length data after a header, then the
	 * logical offset in the overall structure can still be applied when
	 * telling the user about offsets.
	 */
	const void *fp_data;
	size_t fp_dlen;
	size_t fp_off;
	/*
	 * Filters that are checked against.
	 */
	size_t fp_nfilts;
	nvmeadm_field_filt_t *fp_filts;
	ofmt_handle_t fp_ofmt;
	/*
	 * Internal data used for indentation purposes.
	 */
	uint32_t fp_indent;
} nvmeadm_field_print_t;

/*
 * Functions and data to reach the field printing logic.
 */
extern const ofmt_field_t nvmeadm_field_ofmt[];
extern void nvmeadm_field_print(nvmeadm_field_print_t *);

/*
 * This is the internal function used by log processing code to reach the
 * filtering / ofmt log formatting logic.
 */
typedef enum {
	/*
	 * Indicates that this is the first time that a log page name is being
	 * checked. If it isn't found, then we should warn about it. This'll
	 * result in the command failing. This is mean to be used by
	 * print-logpage.
	 */
	NVMEADM_LFF_CHECK_NAME	= 1 << 0
} nvmeadm_log_field_flag_t;
extern bool nvmeadm_log_page_fields(const nvme_process_arg_t *, const char *,
    const void *, size_t, nvmeadm_field_filt_t *, size_t,
    nvmeadm_log_field_flag_t);

/*
 * Convenience macros to set a field type and consistent members. This should be
 * used in the implementation of field information.
 */
#define	NVMEADM_F_BITS(bits)		\
	.nf_type = NVMEADM_FT_BITS,	\
	.nf_bits = bits,		\
	.nf_nbits = ARRAY_SIZE(bits)
#define	NVMEADM_FB_BITS(bits)		\
	.nfb_type = NVMEADM_FT_BITS,	\
	.nfb_bits = bits,		\
	.nfb_nbits = ARRAY_SIZE(bits)
#define	NVMEADM_F_FIELDS(f)			\
	.nf_type = NVMEADM_FT_CONTAINER,	\
	.nf_fields = f,				\
	.nf_nfields = ARRAY_SIZE(f)

/*
 * Defined field structures.
 */
typedef struct {
	const char *nlfi_log;
	const nvmeadm_field_t *const nlfi_fields;
	const size_t nlfi_nfields;
	const size_t nlfi_min;
	/*
	 * Return the revision of the log field. Callers are guaranteed that at
	 * least nlfi_min byte are already present,
	 */
	uint32_t (*nlfi_getrev)(const void *, size_t len);
	/*
	 * Run the process of walking through the log data and providing field
	 * callbacks. This should be used for logs that have a fixed header and
	 * variable contents.
	 */
	bool (*nlfi_drive)(nvmeadm_field_print_t *, const void *, size_t);
} nvmeadm_log_field_info_t;

extern const nvmeadm_log_field_info_t suplog_field_info;
extern const nvmeadm_log_field_info_t supcmd_field_info;
extern const nvmeadm_log_field_info_t supmicmd_field_info;
extern const nvmeadm_log_field_info_t supfeat_field_info;
extern const nvmeadm_log_field_info_t phyeye_field_info;
extern const nvmeadm_log_field_info_t ocp_vul_smart_field_info;
extern const nvmeadm_log_field_info_t ocp_vul_errrec_field_info;
extern const nvmeadm_log_field_info_t ocp_vul_devcap_field_info;
extern const nvmeadm_log_field_info_t ocp_vul_unsup_field_info;
extern const nvmeadm_log_field_info_t ocp_vul_telstr_field_info;

#ifdef __cplusplus
}
#endif

#endif /* _NVMEADM_H */
