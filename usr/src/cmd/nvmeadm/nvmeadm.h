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
 * Copyright 2023 Oxide Computer Company
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

#ifndef _NVMEADM_H
#define	_NVMEADM_H

#include <stdio.h>
#include <libdevinfo.h>
#include <sys/nvme.h>
#include <nvme_reg.h>
#include <ofmt.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int verbose;
extern int debug;

/* Common structures */
typedef struct nvme_process_arg nvme_process_arg_t;
typedef struct nvme_feature nvme_feature_t;
typedef struct nvmeadm_cmd nvmeadm_cmd_t;

struct nvme_process_arg {
	int npa_argc;
	char **npa_argv;
	char *npa_name;
	char *npa_nsid;
	char *npa_eui64;
	char *npa_nguid;
	int npa_found;
	boolean_t npa_excl;
	boolean_t npa_isns;
	boolean_t npa_interactive;
	uint32_t npa_cmdflags;
	const nvmeadm_cmd_t *npa_cmd;
	di_node_t npa_node;
	di_minor_t npa_minor;
	char *npa_dsk;
	nvme_ns_state_t npa_ns_state;
	nvme_identify_ctrl_t *npa_idctl;
	nvme_identify_nsid_t *npa_idns;
	nvme_identify_nsid_list_t *npa_idnslist;
	nvme_version_t *npa_version;
	ofmt_handle_t npa_ofmt;
};

/* Version checking */
extern boolean_t nvme_version_check(nvme_version_t *, uint_t, uint_t);

/* printing functions */
extern int nvme_strlen(const char *, int);
extern void nvme_print(int, const char *, int, const char *, ...);
extern int nvme_snprint_uint128(char *, size_t, nvme_uint128_t, int, int);
extern void nvme_print_ctrl_summary(nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_nsid_summary(nvme_identify_nsid_t *);
extern void nvme_print_identify_ctrl(nvme_identify_ctrl_t *,
    nvme_capabilities_t *, nvme_version_t *);
extern void nvme_print_identify_nsid(nvme_identify_nsid_t *, nvme_version_t *);
extern void nvme_print_identify_nsid_list(const char *,
    nvme_identify_nsid_list_t *);
extern void nvme_print_identify_nsid_desc(void *);
extern void nvme_print_identify_ctrl_list(const char *,
    nvme_identify_ctrl_list_t *);
extern void nvme_print_error_log(int, nvme_error_log_entry_t *,
    nvme_version_t *);
extern void nvme_print_health_log(nvme_health_log_t *, nvme_identify_ctrl_t *,
    nvme_version_t *);
extern void nvme_print_fwslot_log(nvme_fwslot_log_t *, nvme_identify_ctrl_t *);

extern void nvme_print_feat_arbitration(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_power_mgmt(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_lba_range(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_temperature(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_error(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_write_cache(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_nqueues(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_intr_coal(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_intr_vect(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_write_atom(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_async_event(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_auto_pst(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_feat_progress(uint64_t, void *, size_t,
    nvme_identify_ctrl_t *, nvme_version_t *);
extern const char *nvme_fw_error(int, int);

/* device node functions */
extern int nvme_open(di_minor_t, boolean_t);
extern void nvme_close(int);
extern nvme_version_t *nvme_version(int);
extern nvme_capabilities_t *nvme_capabilities(int);
extern void *nvme_identify(int, uint8_t);
extern void *nvme_get_logpage(int, uint8_t, size_t *);
extern boolean_t nvme_get_feature(int, uint8_t, uint32_t, uint64_t *, size_t *,
    void **);
extern int nvme_intr_cnt(int);
extern boolean_t nvme_format_nvm(int, uint8_t, uint8_t);
extern boolean_t nvme_detach(int);
extern boolean_t nvme_attach(int);
extern boolean_t nvme_firmware_load(int, void *, size_t, offset_t, uint16_t *);
extern boolean_t nvme_firmware_commit(int, int, int, uint16_t *);
extern nvme_ns_state_t nvme_namespace_state(int);

/*
 * ofmt related
 */
extern const ofmt_field_t nvme_list_ctrl_ofmt[];
extern const ofmt_field_t nvme_list_nsid_ofmt[];

#ifdef __cplusplus
}
#endif

#endif /* _NVMEADM_H */
