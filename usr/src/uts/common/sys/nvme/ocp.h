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

#ifndef _SYS_NVME_OCP_H
#define	_SYS_NVME_OCP_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This covers the OCP Datacenter NVMe SSD Specification versions 2.0 and 2.5.
 * Version 1.0 of this specification was previously called the OCP NVMe Cloud
 * SSD Specification.
 */

#include <sys/isa_defs.h>
#include <sys/debug.h>
#include <sys/stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	/*
	 * This is the OCP variant of SMART information. Present since v1.0.
	 * Scoped to the NVM subsystem. Tracked by the ocp_vul_smart_t.
	 */
	OCP_LOG_DSSD_SMART	= 0xc0,
	/*
	 * Error recovery information. Present since v1.0. Scoped to the NVM
	 * subsystem.
	 */
	OCP_LOG_DSSD_ERROR_REC	= 0xc1,
	/*
	 * This log page covers firmware activation history. It was added in
	 * v1.0 of the specification, but v2.5 removed this as obsolete. Scoped
	 * to the NVM subsystem.
	 */
	OCP_LOG_DSSD_FWACT	= 0xc2,
	/*
	 * This is the latency monitor log page that has information in tandem
	 * with the Latency monitor feature (0xc5). Added in v2.0. Scoped to the
	 * controller.
	 */
	OCP_LOG_DSSD_LATENCY	= 0xc3,
	/*
	 * This log page indicates various device capabilities. Added in v2.0.
	 * Scoped to the NVM subsystem.
	 */
	OCP_LOG_DSSD_DEV_CAP	= 0xc4,
	/*
	 * This log page indicates which requirements aren't actually
	 * implemented by a device. Added in v2.0. Scoped to the NVM subsystem.
	 */
	OCP_LOG_DSSD_UNSUP_REQ	= 0xc5,
	/*
	 * This log page covers various trusted computing group configuration.
	 * Added in v2.5. Scoped to the NVM subsystem.
	 */
	OCP_LOG_DSSD_TCG	= 0xc7,
	/*
	 * This is the telemetry string log. Added in v2.5. Scoped to the NVM
	 * subsystem.
	 */
	OCP_LOG_DSSD_TELEMTRY	= 0xc9
} ocp_vul_t;

typedef enum {
	/*
	 * Error injection feature. Added in v1.0. Scoped to the NVM subsystem.
	 */
	OCP_FEAT_DSSD_ERR_INJ		= 0xc0,
	/*
	 * Clear the firmware activation and update history log. Added in v1.0,
	 * but marked obsolete in v2.5. Scoped to the NVM subsystem.
	 */
	OCP_FEAT_DSSD_CLEAR_FWACT	= 0xc1,
	/*
	 * Controls the failure mode on device EOL or power loss protection
	 * (PLP) failure. Added in v1.0. Scoped to the NVM subsystem.
	 */
	OCP_FEAT_DSSD_EOLPLP		= 0xc2,
	/*
	 * Clears the PCIe correctable error counters. Added in v1.0. Scoped to
	 * the controller.
	 */
	OCP_FEAT_DSSD_CLEAR_PCIE_ERRCOR	= 0xc3,
	/*
	 * Manipulates the IEEE1667 silo which ties into the OPAL security
	 * feature set. Added in v1.0. Scoped to the NVM subsystem.
	 */
	OCP_FEAT_DSSD_IEEE1667		= 0xc4,
	/*
	 * Controls the latency monitor feature. Added in v2.0. Scoped to the
	 * controller.
	 */
	OCP_FEAT_DSSD_LATENCY		= 0xc5,
	/*
	 * Controls the PLP health check interval. Added in v2.0. Scoped to the
	 * NVM subsystem.
	 */
	OCP_FEAT_DSSD_PLP_HEALTH	= 0xc6,
	/*
	 * Controls the power state that the device is in. Added in v2.0. Scoped
	 * to the NVM subsystem.
	 */
	OCP_FEAT_DSSD_POWER_STATE	= 0xc7,
	/*
	 * Controls the OCP DSSD telemetry profile that should be active. Added
	 * in v2.5. Scoped to the NVM subsystem.
	 */
	OCP_FEAT_DSSD_TEL_PROFILE	= 0xc8,
	/*
	 * Controls whether additional spec-specific events should be sent with
	 * the asynchronous event commands.
	 */
	OCP_FEAT_DSSD_ASYNC_EVENT	= 0xc9
} ocp_vuf_t;

/*
 * All data structures must be packed to account for the layout from the various
 * specifications. All fields are required to be in little endian.
 */
#pragma pack(1)

/*
 * OCP SMART / Health log page. A number in parentheses like (2.0) indicates the
 * version something was added in if it was not v1.0.
 */
typedef struct {
	/*
	 * Physical media units read and written.
	 */
	uint8_t	osh_pmed_write[16];
	uint8_t osh_pmed_read[16];
	/*
	 * Bad user and system NAND blocks. Both a raw count and normalized
	 * value (percentage remaining).
	 */
	uint8_t osh_bunb_raw[6];
	uint16_t osh_bunb_norm;
	uint8_t osh_bsnb_raw[6];
	uint16_t osh_bsnb_norm;
	/*
	 * Various error and recovery metrics:
	 * - XOR
	 * - Uncorrectable reads
	 * - Soft ECC errors
	 * - End to end errors detected and corrected
	 */
	uint64_t osh_xor_rec;
	uint64_t osh_read_unrec;
	uint64_t osh_soft_ecc_err;
	uint32_t osh_e2e_det;
	uint32_t osh_e2e_corr;
	/*
	 * Tracks the normalized percent used of the device by estimated erase
	 * cycles per block.
	 */
	uint8_t osh_sys_used;
	/*
	 * This is the count of blocks that have been refreshed.
	 */
	uint8_t osh_refresh[7];
	/*
	 * Tracks the maximum and minimum erase count across NAND reserved for
	 * the user.
	 */
	uint32_t osh_udec_max;
	uint32_t osh_udec_min;
	/*
	 * The number of events and the current level of throttling.
	 */
	uint8_t osh_therm_event;
	uint8_t osh_throt_level;
	/*
	 * DSSD versioning for the device. (2.0).
	 */
	uint8_t osh_vers_errata;
	uint16_t osh_vers_point;
	uint16_t osh_vers_minor;
	uint8_t osh_vers_major;
	/*
	 * PCIe Correctable error count.
	 */
	uint64_t osh_pcie_errcor;
	/*
	 * Incomplete shutdowns.
	 */
	uint32_t osh_inc_shut;
	uint8_t osh_rsvd116[4];
	/*
	 * Normalized free percentage.
	 */
	uint8_t osh_free;
	uint8_t osh_rsvd121[7];
	/*
	 * Capacitor health as a percentage.
	 */
	uint16_t osh_cap_health;
	/*
	 * NVMe base spec errata version (2.0).
	 * NVMe cmd spec errata version (2.5).
	 */
	uint8_t osh_nvme_base_errata;
	uint8_t osh_nvme_cmd_errata;
	uint8_t osh_rsvd132[4];
	/*
	 * Quantity of unaligned I/O
	 */
	uint64_t osh_unaligned;
	/*
	 * An incrementing integer representing a security version that
	 * shouldn't be rolled back across.
	 */
	uint64_t osh_sec_vers;
	/*
	 * Namespace utilization.
	 */
	uint64_t osh_nuse;
	/*
	 * Count of events where PLP kicked in.
	 */
	uint8_t osh_plp_start[16];
	/*
	 * Estimation of total data that can be written to the device in bytes.
	 */
	uint8_t osh_endurnace[16];
	/*
	 * Count of PCIe retraining events (2.0).
	 */
	uint64_t osh_pcie_retrain;
	/*
	 * Count of power state changes, regardless of initiator. (2.0).
	 */
	uint64_t osh_ps_change;
	/*
	 * Minimum permitted firmware version for rollback purposes.
	 */
	uint64_t osh_min_fwrev;
	uint8_t osh_rsvd216[278];
	/*
	 * v1.0: 2, v2.0: 3, v2.5: 4
	 */
	uint16_t osh_vers;
	/*
	 * Log page GUID: AFD514C97C6F4F9CA4f2BFEA2810AFC5h.
	 */
	uint8_t osh_guid[16];
} ocp_vul_smart_t;

/*
 * OCP Error Recovery log.
 */
typedef struct {
	/*
	 * Time in ms to wait for a reset to complete.
	 */
	uint16_t oer_prwt;
	/*
	 * List of reset actions we should consider taking. See ocp_errrec_pra_t
	 * for bit meanings.
	 */
	uint8_t oer_pra;
	/*
	 * List of steps to take to handle the device's recovery from a given
	 * situation. See ocp_errrec_dra_t for bit meanings.
	 */
	uint8_t oer_dra;
	uint64_t oer_panic_id;
	/*
	 * See ocp_errrec_devcap_t for more information.
	 */
	uint32_t oer_devcap;
	/*
	 * Information for how to send the vendor specific recovery command. The
	 * timout was added in 2.0.
	 */
	uint8_t oer_vsr_opcode;
	uint8_t oer_rsvd17[3];
	uint32_t oer_vsr_cdw12;
	uint32_t oer_vsr_cdw13;
	uint8_t oer_vsr_to;
	/*
	 * Secondary recovery actions post-reset (2.5). Uses the same bits as
	 * ocp_errrec_dra_t.
	 */
	uint8_t oer_dra2;
	uint8_t oer_dra2_to;
	uint8_t oer_npanic;
	uint64_t oer_old_panics[4];
	uint8_t oer_rsvd54[430];
	/*
	 * V1.0: 1, V2.0: 2, V2.5: 3
	 */
	uint16_t oer_vers;
	/*
	 * Log page GUID: 5A1983BA3DFD4DABAE3430FE2131D944h.
	 */
	uint8_t oer_guid[16];
} ocp_vul_errrec_t;

/*
 * List of panic reset actions that should be taken to recover.
 */
typedef enum {
	/* NVMe Controller Reset */
	OCP_LOG_ERRREC_F_PRA_CTRL	= 1 << 0,
	/* NVM Subsystem Reset */
	OCP_LOG_ERRREC_F_PRA_SUBSYS	= 1 << 1,
	/* PCIe Function Level Reset */
	OCP_LOG_ERRREC_F_PRA_FLR	= 1 << 2,
	/* ASSERT #PERST (PCIe Fundamental Reset) */
	OCP_LOG_ERRREC_F_PRA_PERST	= 1 << 3,
	/* Power cycle the device */
	OCP_LOG_ERRREC_F_PRA_POWER	= 1 << 4,
	/* PCIe conventional hot reset */
	OCP_LOG_ERRREC_F_PRA_HOT	= 1 << 5
} ocp_errrec_pra_t;

typedef enum {
	/* Do nothing */
	OCP_LOG_ERRREC_F_DRA_NONE	= 1 << 0,
	/* Format required */
	OCP_LOG_ERRREC_F_DRA_FMT	= 1 << 1,
	/* Vendor specific commad */
	OCP_LOG_ERRREC_F_DRA_VSC	= 1 << 2,
	/* Vendor analysis required */
	OCP_LOG_ERRREC_F_DRA_VAR	= 1 << 3,
	/* Replace the device */
	OCP_LOG_ERRREC_F_DRA_REPLACE	= 1 << 4,
	/* Sanitize required */
	OCP_LOG_ERRREC_F_DRA_SANITIZE	= 1 << 5,
	/*
	 * Indicates that there is permanent data loss in some LBAs. The LBAs
	 * are identified by the LBA Status log 0xe.
	 */
	OCP_LOG_ERRREC_F_DRA_DATALOSS	= 1 << 6,
} ocp_errrec_dra_t;

/*
 * Device capabilities. Used to indicate how a message about a panic can be sent
 * today.
 */
typedef enum {
	OCP_LOG_ERRREC_F_DEVCAP_AEN	= 1 << 0,
	OCP_LOG_ERRREC_F_DEVCAP_CFS	= 1 << 1
} ocp_errrec_devcap_t;

/*
 * OCP Firmware Activation. Present in 1.0 and 2.0. Removed in 2.5.
 */
typedef struct {
	uint8_t ofe_vers;
	uint8_t ofe_len;
	uint8_t ofe_rsvd2[2];
	uint16_t ofe_count;
	uint64_t ofe_ts;
	uint8_t ofe_rsvd14[8];
	uint64_t ofe_pcc;
	uint64_t ofe_prev_fw;
	uint64_t ofe_new_fw;
	uint8_t ofe_slot;
	uint8_t ofe_ctype;
	uint16_t ofe_res;
	uint8_t ofe_rsvd50[14];
} ocp_fwact_entry_t;

typedef struct {
	uint8_t ofw_lid;
	uint8_t ofw_rsvd1[3];
	uint32_t ofw_nents;
	ocp_fwact_entry_t ofw_hist[20];
	uint8_t ofw_rsvd1288[2790];
	/*
	 * V1.0: 1, V2.0: 1
	 */
	uint16_t ofw_vers;
	/*
	 * Log Page GUID: 3AC8AB24DE2A3F6DAB4769A796Dh.
	 */
	uint8_t ofw_guid[16];
} ocp_vul_fwact_t;

/*
 * Latency Monitor log. Added in V2.0.
 */
typedef struct {
	uint32_t obc_read;
	uint32_t obc_write;
	uint32_t obc_dealloc;
	uint32_t obc_rsvd;
} ocp_lat_bkt_ctr_t;

typedef struct {
	uint64_t ola_read;
	uint64_t ola_write;
	uint64_t ola_dealloc;
} ocp_lat_alts_t;

typedef struct {
	uint16_t olm_read;
	uint16_t olm_write;
	uint16_t olm_dealloc;
} ocp_lat_aml_t;

typedef struct {
	/*
	 * Latency monitor features. See ocp_lat_lmfs_t.
	 */
	uint8_t ol_lmfs;
	uint8_t ol_rsvd1[1];
	/*
	 * Active bucket timer, its threshold, and general thresholds.
	 */
	uint16_t ol_abt;
	uint16_t ol_abt_thresh;
	uint8_t ol_thresh_a;
	uint8_t ol_thresh_b;
	uint8_t ol_thresh_c;
	uint8_t ol_thresh_d;
	/*
	 * Active latency configuration. See ocp_lat_alc_t.
	 */
	uint16_t ol_alc;
	uint8_t ol_alw_min;
	uint8_t ol_rsvd13[19];
	/*
	 * Active bucket counters.
	 */
	ocp_lat_bkt_ctr_t ol_ctr0;
	ocp_lat_bkt_ctr_t ol_ctr1;
	ocp_lat_bkt_ctr_t ol_ctr2;
	ocp_lat_bkt_ctr_t ol_ctr3;
	/*
	 * Active Latency Stamps. These contain 64-bit timestamps for when
	 * events occurred. Grouped by bucket.
	 */
	ocp_lat_alts_t ol_ts0;
	ocp_lat_alts_t ol_ts1;
	ocp_lat_alts_t ol_ts2;
	ocp_lat_alts_t ol_ts3;
	/*
	 * Active Measured Latency. Grouped by bucket.
	 */
	ocp_lat_aml_t ol_aml0;
	ocp_lat_aml_t ol_aml1;
	ocp_lat_aml_t ol_aml2;
	ocp_lat_aml_t ol_aml3;
	uint16_t ol_als_units;
	uint8_t ol_rsvd218[22];
	/*
	 * Static versions of everything above.
	 */
	ocp_lat_bkt_ctr_t ol_sb0;
	ocp_lat_bkt_ctr_t ol_sb1;
	ocp_lat_bkt_ctr_t ol_sb2;
	ocp_lat_bkt_ctr_t ol_sb3;
	ocp_lat_alts_t ol_sts0;
	ocp_lat_alts_t ol_sts1;
	ocp_lat_alts_t ol_sts2;
	ocp_lat_alts_t ol_sts3;
	ocp_lat_aml_t ol_saml0;
	ocp_lat_aml_t ol_saml1;
	ocp_lat_aml_t ol_saml2;
	ocp_lat_aml_t ol_saml3;
	uint16_t ol_als_sunits;
	uint8_t ol_rsvd426[10];
	/*
	 * Debug log related fields. The number of dword fields is specific to
	 * v2.5.
	 */
	uint8_t ol_dbg_ndw[12];
	uint16_t ol_dbg_trig;
	uint16_t ol_dbg_ml;
	uint64_t ol_dbg_ts;
	uint16_t ol_dbg_ptr;
	uint16_t ol_dbg_src;
	uint8_t ol_dbg_units;
	uint8_t ol_rsvd465[29];
	/*
	 * V2.0: 1, V2.5: 4
	 */
	uint16_t ol_vers;
	/*
	 * Log page GUID: 85D45E58D4E643709C6C84D08CC07A92h.
	 */
	uint8_t ol_guid[16];
} ocp_vul_lat_t;

typedef enum {
	OPC_LOG_LAT_F_LFMS_EN		= 1 << 0,
	OPC_LOG_LAT_F_LFMS_ALC_SUP	= 1 << 1,
	OPC_LOG_LAT_F_LFMS_AML_SUP	= 1 << 2,
} ocp_lat_lmfs_t;

typedef enum {
	OCP_LOG_LAT_F_ALC_B0_READ	= 1 << 0,
	OCP_LOG_LAT_F_ALC_B0_WRITE	= 1 << 1,
	OCP_LOG_LAT_F_ALC_B0_DEALLOC	= 1 << 2,
	OCP_LOG_LAT_F_ALC_B1_READ	= 1 << 3,
	OCP_LOG_LAT_F_ALC_B1_WRITE	= 1 << 4,
	OCP_LOG_LAT_F_ALC_B1_DEALLOC	= 1 << 5,
	OCP_LOG_LAT_F_ALC_B2_READ	= 1 << 6,
	OCP_LOG_LAT_F_ALC_B2_WRITE	= 1 << 7,
	OCP_LOG_LAT_F_ALC_B2_DEALLOC	= 1 << 8,
	OCP_LOG_LAT_F_ALC_B3_READ	= 1 << 9,
	OCP_LOG_LAT_F_ALC_B3_WRITE	= 1 << 10,
	OCP_LOG_LAT_F_ALC_B3_DEALLOC	= 1 << 11
} ocp_lat_alc_t;

/*
 * Device Capabilities Log. Introduced in v2.0.
 */
typedef struct {
#ifdef	_BIT_FIELDS_LTOH
	uint8_t odp_nps:5;
	uint8_t odp_rsvd5:2;
	uint8_t odp_valid:1;
#else
	uint8_t odp_valid:1;
	uint8_t odp_rsvd5:2;
	uint8_t odp_nps:5;
#endif	/* _BIT_FIELDS_LTOH */
} ocp_dssd_ps_t;

typedef struct {
	uint16_t odc_nports;
	uint16_t odc_oob_sup;
	uint16_t odc_wz_sup;
	uint16_t odc_san_sup;
	uint16_t odc_dsmgmt_sup;
	uint16_t odc_wunc_sup;
	uint16_t odc_fuse_sup;
	uint16_t odc_dssd_min_valid;
	ocp_dssd_ps_t odc_dssd[128];
	uint8_t odc_rsvd144[3934];
	/*
	 * V2.0: 1, V2.5: 1
	 */
	uint16_t odc_vers;
	/*
	 * Log page GUID: B7053C914B58495D98C9E1D10D054297h
	 */
	uint8_t odc_guid[16];
} ocp_vul_devcap_t;

typedef enum {
	/* PCIe VDM Supported */
	OCP_LOG_DEVCAP_F_OOB_VDM	= 1 << 0,
	/* NVMe Basic Management Command supported */
	OCP_LOG_DEVCAP_F_OOB_BMC	= 1 << 1,
	/* Passed compliance testing */
	OCP_LOG_DEVCAP_F_OOB_COMPLY	= 1 << 15,
} ocp_devcap_oob_t;

typedef enum {
	/* Write Zeros command supported */
	OCP_LOG_DEVCAP_F_WZ_SUP		= 1 << 0,
	/* Write Zeros deallocate bit */
	OCP_LOG_DEVCAP_F_WZ_DEAC	= 1 << 1,
	/* Write Zeros force unit access */
	OCP_LOG_DEVCAP_F_WZ_FUA		= 1 << 2,
	/* Adheres to spec req NVME-IO-5 */
	OCP_LOG_DEVCAP_F_WZ_IO5		= 1 << 3,
	/* Adheres to spec req NVME-IO-6 */
	OCP_LOG_DEVCAP_F_WZ_IO6		= 1 << 4,
	/* Passed compliance testing */
	OCP_LOG_DEVCAP_F_WZ_COMPLY	= 1 << 15
} ocp_devcap_wz_t;

typedef enum {
	/* Dataset Management command supported */
	OCP_LOG_DEVCAP_F_DSMGMT_SUP	= 1 << 0,
	/* Attribute deallocate supported */
	OCP_LOG_DEVCAP_F_DSMGMT_AD	= 1 << 1,
	/* Passed compliance testing */
	OCP_LOG_DEVCAP_F_DSMGMT_COMPLY	= 1 << 15
} ocp_devcap_dsmgmt_t;

typedef enum {
	/* Write uncorrectable supported */
	OCP_LOG_DEVCAP_F_WUNC_SUP	= 1 << 0,
	/* Works with a single LBA */
	OCP_LOG_DEVCAP_F_WUNC_ONE	= 1 << 1,
	/* Works with max LBAs per NVMe spec */
	OCP_LOG_DEVCAP_F_WUNC_MAX	= 1 << 2,
	/* Adheres to spec req NVME-IO-14 */
	OCP_LOG_DEVCAP_F_WUNC_IO14	= 1 << 3,
	/* Passed compliance testing */
	OCP_LOG_DEVCAP_F_WUNC_COMPLY	= 1 << 15
} ocp_devcap_wunc_t;

typedef enum {
	/* Fused operation supported */
	OCP_LOG_DEVCAP_F_FUSE_SUP	= 1 << 0,
	/* Passed compliance testing */
	OCP_LOG_DEVCAP_F_FUSE_COMPLY	= 1 << 15
} ocp_devcap_fuse_t;

/*
 * Unsupported Requirements log. This log is structured such that each
 * unimplemented requirement must fit into a single 16 byte array which should
 * be padded with zeros (but nothing in the spec suggests it guarantees
 * termination). We keep the requirements string as a uint8_t as opposed to a
 * char to indicate that this should not be trusted and must be parsed.
 */
typedef struct {
	uint8_t ors_str[16];
} ocp_req_str_t;

typedef struct {
	uint16_t our_nunsup;
	uint8_t our_rsvd2[14];
	ocp_req_str_t ors_reqs[253];
	uint8_t our_rsvd4064[14];
	/*
	 * V2.0: 1, V2.5: 1
	 */
	uint16_t our_vers;
	/*
	 * Log page GUID: C7BB98B7D0324863BB2C23990E9C722Fh
	 */
	uint8_t our_guid[16];
} ocp_vul_unsup_req_t;

/*
 * Our current version of smatch cannot handle packed structures.
 */
#ifndef __CHECKER__
CTASSERT(sizeof (ocp_vul_smart_t) == 512);
CTASSERT(offsetof(ocp_vul_smart_t, osh_therm_event) == 96);
CTASSERT(offsetof(ocp_vul_smart_t, osh_vers) == 494);
CTASSERT(sizeof (ocp_vul_errrec_t) == 512);
CTASSERT(offsetof(ocp_vul_errrec_t, oer_npanic) == 31);
CTASSERT(offsetof(ocp_vul_errrec_t, oer_npanic) == 31);
CTASSERT(sizeof (ocp_fwact_entry_t) == 64);
CTASSERT(offsetof(ocp_fwact_entry_t, ofe_rsvd50) == 50);
CTASSERT(sizeof (ocp_vul_fwact_t) == 4096);
CTASSERT(offsetof(ocp_vul_fwact_t, ofw_rsvd1288) == 1288);
CTASSERT(offsetof(ocp_vul_fwact_t, ofw_vers) == 4078);
CTASSERT(sizeof (ocp_lat_bkt_ctr_t) == 16);
CTASSERT(sizeof (ocp_lat_alts_t) == 24);
CTASSERT(sizeof (ocp_lat_aml_t) == 6);
CTASSERT(offsetof(ocp_vul_lat_t, ol_aml0) == 192);
CTASSERT(offsetof(ocp_vul_lat_t, ol_rsvd218) == 218);
CTASSERT(offsetof(ocp_vul_lat_t, ol_als_sunits) == 424);
CTASSERT(sizeof (ocp_vul_lat_t) == 512);
CTASSERT(sizeof (ocp_vul_devcap_t) == 4096);
CTASSERT(offsetof(ocp_vul_devcap_t, odc_rsvd144) == 144);
CTASSERT(sizeof (ocp_req_str_t) == 16);
CTASSERT(sizeof (ocp_vul_unsup_req_t) == 4096);
#endif

#pragma	pack()	/* pack(1) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_OCP_H */
