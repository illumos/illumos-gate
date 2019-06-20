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
 * Copyright 2016 Nexenta Systems, Inc.
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2019 Western Digital Corporation
 */

#ifndef _SYS_NVME_H
#define	_SYS_NVME_H

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/types32.h>
#else
#include <stdint.h>
#endif

/*
 * Declarations used for communication between nvmeadm(1M) and nvme(7D)
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NVMe ioctl definitions
 */

#define	NVME_IOC			(('N' << 24) | ('V' << 16) | ('M' << 8))
#define	NVME_IOC_IDENTIFY_CTRL		(NVME_IOC | 1)
#define	NVME_IOC_IDENTIFY_NSID		(NVME_IOC | 2)
#define	NVME_IOC_CAPABILITIES		(NVME_IOC | 3)
#define	NVME_IOC_GET_LOGPAGE		(NVME_IOC | 4)
#define	NVME_IOC_GET_FEATURES		(NVME_IOC | 5)
#define	NVME_IOC_INTR_CNT		(NVME_IOC | 6)
#define	NVME_IOC_VERSION		(NVME_IOC | 7)
#define	NVME_IOC_FORMAT			(NVME_IOC | 8)
#define	NVME_IOC_DETACH			(NVME_IOC | 9)
#define	NVME_IOC_ATTACH			(NVME_IOC | 10)
#define	NVME_IOC_FIRMWARE_DOWNLOAD	(NVME_IOC | 11)
#define	NVME_IOC_FIRMWARE_COMMIT	(NVME_IOC | 12)
#define	NVME_IOC_MAX			NVME_IOC_FIRMWARE_COMMIT

#define	IS_NVME_IOC(x)			((x) > NVME_IOC && (x) <= NVME_IOC_MAX)
#define	NVME_IOC_CMD(x)			((x) & 0xff)

typedef struct {
	size_t		n_len;
	uintptr_t	n_buf;
	uint64_t	n_arg;
} nvme_ioctl_t;

#ifdef _KERNEL
typedef struct {
	size32_t	n_len;
	uintptr32_t	n_buf;
	uint64_t	n_arg;
} nvme_ioctl32_t;
#endif

/*
 * NVMe capabilities
 */
typedef struct {
	uint32_t mpsmax;		/* Memory Page Size Maximum */
	uint32_t mpsmin;		/* Memory Page Size Minimum */
} nvme_capabilities_t;

/*
 * NVMe version
 */
typedef struct {
	uint16_t v_minor;
	uint16_t v_major;
} nvme_version_t;

#define	NVME_VERSION_ATLEAST(v, maj, min) \
	(((v)->v_major) > (maj) || \
	((v)->v_major == (maj) && (v)->v_minor >= (min)))

#define	NVME_VERSION_HIGHER(v, maj, min) \
	(((v)->v_major) > (maj) || \
	((v)->v_major == (maj) && (v)->v_minor > (min)))


#pragma pack(1)

/*
 * NVMe Identify data structures
 */

#define	NVME_IDENTIFY_BUFSIZE	4096	/* buffer size for Identify */

/* NVMe Queue Entry Size bitfield */
typedef struct {
	uint8_t qes_min:4;		/* minimum entry size */
	uint8_t qes_max:4;		/* maximum entry size */
} nvme_idctl_qes_t;

/* NVMe Power State Descriptor */
typedef struct {
	uint16_t psd_mp;		/* Maximum Power */
	uint8_t psd_rsvd1;
	uint8_t psd_mps:1;		/* Max Power Scale (1.1) */
	uint8_t psd_nops:1;		/* Non-Operational State (1.1) */
	uint8_t psd_rsvd2:6;
	uint32_t psd_enlat;		/* Entry Latency */
	uint32_t psd_exlat;		/* Exit Latency */
	uint8_t psd_rrt:5;		/* Relative Read Throughput */
	uint8_t psd_rsvd3:3;
	uint8_t psd_rrl:5;		/* Relative Read Latency */
	uint8_t psd_rsvd4:3;
	uint8_t psd_rwt:5;		/* Relative Write Throughput */
	uint8_t	psd_rsvd5:3;
	uint8_t psd_rwl:5;		/* Relative Write Latency */
	uint8_t psd_rsvd6:3;
	uint16_t psd_idlp;		/* Idle Power (1.2) */
	uint8_t psd_rsvd7:6;
	uint8_t psd_ips:2;		/* Idle Power Scale (1.2) */
	uint8_t psd_rsvd8;
	uint16_t psd_actp;		/* Active Power (1.2) */
	uint8_t psd_apw:3;		/* Active Power Workload (1.2) */
	uint8_t psd_rsvd9:3;
	uint8_t psd_aps:2;		/* Active Power Scale */
	uint8_t psd_rsvd10[9];
} nvme_idctl_psd_t;

/* NVMe Identify Controller Data Structure */
typedef struct {
	/* Controller Capabilities & Features */
	uint16_t id_vid;		/* PCI vendor ID */
	uint16_t id_ssvid;		/* PCI subsystem vendor ID */
	char id_serial[20];		/* Serial Number */
	char id_model[40];		/* Model Number */
	char id_fwrev[8];		/* Firmware Revision */
	uint8_t id_rab;			/* Recommended Arbitration Burst */
	uint8_t id_oui[3];		/* vendor IEEE OUI */
	struct {			/* Multi-Interface Capabilities */
		uint8_t m_multi_pci:1;	/* HW has multiple PCIe interfaces */
		uint8_t m_multi_ctrl:1; /* HW has multiple controllers (1.1) */
		uint8_t m_sr_iov:1;	/* controller is SR-IOV virt fn (1.1) */
		uint8_t m_rsvd:5;
	} id_mic;
	uint8_t	id_mdts;		/* Maximum Data Transfer Size */
	uint16_t id_cntlid;		/* Unique Controller Identifier (1.1) */
	/* Added in NVMe 1.2 */
	uint32_t id_ver;		/* Version */
	uint32_t id_rtd3r;		/* RTD3 Resume Latency */
	uint32_t id_rtd3e;		/* RTD3 Entry Latency */
	uint32_t id_oaes;		/* Optional Asynchronous Events */
	/* Added in NVMe 1.3 */
	uint32_t id_ctratt;		/* Controller Attributes */
	uint8_t id_rsvd_cc[12];
	uint8_t id_frguid[16];		/* FRU GUID */
	uint8_t id_rsvd2_cc[240 - 128];
	uint8_t id_rsvd_nvmemi[255 - 240];
	uint8_t id_mec;			/* Management Endpiont Capabilities */

	/* Admin Command Set Attributes */
	struct {			/* Optional Admin Command Support */
		uint16_t oa_security:1;	/* Security Send & Receive */
		uint16_t oa_format:1;	/* Format NVM */
		uint16_t oa_firmware:1;	/* Firmware Activate & Download */
		uint16_t oa_rsvd:13;
	} id_oacs;
	uint8_t	id_acl;			/* Abort Command Limit */
	uint8_t id_aerl;		/* Asynchronous Event Request Limit */
	struct {			/* Firmware Updates */
		uint8_t fw_readonly:1;	/* Slot 1 is Read-Only */
		uint8_t	fw_nslot:3;	/* number of firmware slots */
		uint8_t fw_rsvd:4;
	} id_frmw;
	struct {			/* Log Page Attributes */
		uint8_t lp_smart:1;	/* SMART/Health information per NS */
		uint8_t lp_rsvd:7;
	} id_lpa;
	uint8_t id_elpe;		/* Error Log Page Entries */
	uint8_t	id_npss;		/* Number of Power States */
	struct {			/* Admin Vendor Specific Command Conf */
		uint8_t av_spec:1;	/* use format from spec */
		uint8_t av_rsvd:7;
	} id_avscc;
	struct {			/* Autonomous Power State Trans (1.1) */
		uint8_t ap_sup:1;	/* APST supported (1.1) */
		uint8_t ap_rsvd:7;
	} id_apsta;
	/* Added in NVMe 1.2 */
	uint16_t ap_wctemp;		/* Warning Composite Temperature */
	uint16_t ap_cctemp;		/* Critical Composite Temperature */
	uint16_t ap_mtfa;		/* Maximum Firmware Activation Time */
	uint32_t ap_hmpre;		/* Host Memory Buffer Preferred Size */
	uint32_t ap_hmmin;		/* Host Memory Buffer Min Size */
	uint8_t ap_tnvmcap[16];		/* Total NVM Capacity in Bytes */
	uint8_t ap_unvmcap[16];		/* Unallocated NVM Capacity */
	uint32_t ap_rpmbs;		/* Replay Protected Memory Block */
	/* Added in NVMe 1.3 */
	uint16_t ap_edstt;		/* Extended Device Self-test time */
	uint8_t ap_dsto;		/* Device Self-test Options */
	uint8_t ap_fwug;		/* Firmware Update Granularity */
	uint16_t ap_kas;		/* Keep Alive Support */
	uint16_t ap_hctma;		/* Host Thermal Management */
	uint16_t ap_mntmt;		/* Minimum Thermal Temperature */
	uint16_t ap_mxtmt;		/* Maximum Thermal Temperature */
	uint32_t ap_sanitize;		/* Sanitize Caps */
	uint8_t id_rsvd_ac[512 - 332];

	/* NVM Command Set Attributes */
	nvme_idctl_qes_t id_sqes;	/* Submission Queue Entry Size */
	nvme_idctl_qes_t id_cqes;	/* Completion Queue Entry Size */
	uint16_t id_maxcmd;		/* Max Outstanding Commands (1.3) */
	uint32_t id_nn;			/* Number of Namespaces */
	struct {			/* Optional NVM Command Support */
		uint16_t on_compare:1;	/* Compare */
		uint16_t on_wr_unc:1;	/* Write Uncorrectable */
		uint16_t on_dset_mgmt:1; /* Dataset Management */
		uint16_t on_wr_zero:1;	/* Write Zeros (1.1) */
		uint16_t on_save:1;	/* Save/Select in Get/Set Feat (1.1) */
		uint16_t on_reserve:1;	/* Reservations (1.1) */
		uint16_t on_rsvd:10;
	} id_oncs;
	struct {			/* Fused Operation Support */
		uint16_t f_cmp_wr:1;	/* Compare and Write */
		uint16_t f_rsvd:15;
	} id_fuses;
	struct {			/* Format NVM Attributes */
		uint8_t fn_format:1;	/* Format applies to all NS */
		uint8_t fn_sec_erase:1;	/* Secure Erase applies to all NS */
		uint8_t fn_crypt_erase:1; /* Cryptographic Erase supported */
		uint8_t fn_rsvd:5;
	} id_fna;
	struct {			/* Volatile Write Cache */
		uint8_t vwc_present:1;	/* Volatile Write Cache present */
		uint8_t rsvd:7;
	} id_vwc;
	uint16_t id_awun;		/* Atomic Write Unit Normal */
	uint16_t id_awupf;		/* Atomic Write Unit Power Fail */
	struct {			/* NVM Vendor Specific Command Conf */
		uint8_t nv_spec:1;	/* use format from spec */
		uint8_t nv_rsvd:7;
	} id_nvscc;
	uint8_t id_rsvd_nc_2;
	uint16_t id_acwu;		/* Atomic Compare & Write Unit (1.1) */
	uint16_t id_rsvd_nc_3;
	struct {			/* SGL Support (1.1) */
		uint16_t sgl_sup:1;	/* SGL Supported in NVM cmds (1.1) */
		uint16_t sgl_rsvd1:15;
		uint16_t sgl_bucket:1;	/* SGL Bit Bucket supported (1.1) */
		uint16_t sgl_rsvd2:15;
	} id_sgls;
	uint8_t id_rsvd_nc_4[768 - 540];

	/* I/O Command Set Attributes */
	uint8_t id_subnqn[1024 - 768];	/* Subsystem Qualified Name (1.2.1+) */
	uint8_t id_rsvd_ioc[1792 - 1024];
	uint8_t id_nvmof[2048 - 1792];	/* NVMe over Fabrics */

	/* Power State Descriptors */
	nvme_idctl_psd_t id_psd[32];

	/* Vendor Specific */
	uint8_t id_vs[1024];
} nvme_identify_ctrl_t;

/* NVMe Identify Namespace LBA Format */
typedef struct {
	uint16_t lbaf_ms;		/* Metadata Size */
	uint8_t lbaf_lbads;		/* LBA Data Size */
	uint8_t lbaf_rp:2;		/* Relative Performance */
	uint8_t lbaf_rsvd1:6;
} nvme_idns_lbaf_t;

/* NVMe Identify Namespace Data Structure */
typedef struct {
	uint64_t id_nsize;		/* Namespace Size */
	uint64_t id_ncap;		/* Namespace Capacity */
	uint64_t id_nuse;		/* Namespace Utilization */
	struct {			/* Namespace Features */
		uint8_t f_thin:1;	/* Thin Provisioning */
		uint8_t f_rsvd:7;
	} id_nsfeat;
	uint8_t id_nlbaf;		/* Number of LBA formats */
	struct {			/* Formatted LBA size */
		uint8_t lba_format:4;	/* LBA format */
		uint8_t lba_extlba:1;	/* extended LBA (includes metadata) */
		uint8_t lba_rsvd:3;
	} id_flbas;
	struct {			/* Metadata Capabilities */
		uint8_t mc_extlba:1;	/* extended LBA transfers */
		uint8_t mc_separate:1;	/* separate metadata transfers */
		uint8_t mc_rsvd:6;
	} id_mc;
	struct {			/* Data Protection Capabilities */
		uint8_t dp_type1:1;	/* Protection Information Type 1 */
		uint8_t dp_type2:1;	/* Protection Information Type 2 */
		uint8_t dp_type3:1;	/* Protection Information Type 3 */
		uint8_t dp_first:1;	/* first 8 bytes of metadata */
		uint8_t dp_last:1;	/* last 8 bytes of metadata */
		uint8_t dp_rsvd:3;
	} id_dpc;
	struct {			/* Data Protection Settings */
		uint8_t dp_pinfo:3;	/* Protection Information enabled */
		uint8_t dp_first:1;	/* first 8 bytes of metadata */
		uint8_t dp_rsvd:4;
	} id_dps;
	struct {			/* NS Multi-Path/Sharing Cap (1.1) */
		uint8_t nm_shared:1;	/* NS is shared (1.1) */
		uint8_t nm_rsvd:7;
	} id_nmic;
	struct {			/* Reservation Capabilities (1.1) */
		uint8_t rc_persist:1;	/* Persist Through Power Loss (1.1) */
		uint8_t rc_wr_excl:1;	/* Write Exclusive (1.1) */
		uint8_t rc_excl:1;	/* Exclusive Access (1.1) */
		uint8_t rc_wr_excl_r:1;	/* Wr Excl - Registrants Only (1.1) */
		uint8_t rc_excl_r:1;	/* Excl Acc - Registrants Only (1.1) */
		uint8_t rc_wr_excl_a:1;	/* Wr Excl - All Registrants (1.1) */
		uint8_t rc_excl_a:1;	/* Excl Acc - All Registrants (1.1) */
		uint8_t rc_rsvd:1;
	} id_rescap;
	uint8_t id_fpi;			/* Format Progress Indicator (1.2) */
	uint8_t id_dfleat;		/* Deallocate Log. Block (1.3) */
	uint16_t id_nawun;		/* Atomic Write Unit Normal (1.2) */
	uint16_t id_nawupf;		/* Atomic Write Unit Power Fail (1.2) */
	uint16_t id_nacwu;		/* Atomic Compare & Write Unit (1.2) */
	uint16_t id_nabsn;		/* Atomic Boundary Size Normal (1.2) */
	uint16_t id_nbao;		/* Atomic Boundary Offset (1.2) */
	uint16_t id_nabspf;		/* Atomic Boundary Size Fail (1.2) */
	uint16_t id_noiob;		/* Optimal I/O Bondary (1.3) */
	uint8_t id_nvmcap[16];		/* NVM Capacity */
	uint8_t id_rsvd1[104 - 64];
	uint8_t id_nguid[16];		/* Namespace GUID (1.2) */
	uint8_t id_eui64[8];		/* IEEE Extended Unique Id (1.1) */
	nvme_idns_lbaf_t id_lbaf[16];	/* LBA Formats */

	uint8_t id_rsvd2[384 - 192];

	uint8_t id_vs[4096 - 384];	/* Vendor Specific */
} nvme_identify_nsid_t;

/* NVMe Identify Primary Controller Capabilities */
typedef struct {
	uint16_t	nipc_cntlid;	/* Controller ID */
	uint16_t	nipc_portid;	/* Port Identifier */
	uint8_t		nipc_crt;	/* Controller Resource Types */
	uint8_t		nipc_rsvd0[32 - 5];
	uint32_t	nipc_vqfrt;	/* VQ Resources Flexible Total */
	uint32_t	nipc_vqrfa;	/* VQ Resources Flexible Assigned */
	uint16_t	nipc_vqrfap;	/* VQ Resources to Primary */
	uint16_t	nipc_vqprt;	/* VQ Resources Private Total */
	uint16_t	nipc_vqfrsm;	/* VQ Resources Secondary Max */
	uint16_t	nipc_vqgran;	/* VQ Flexible Resource Gran */
	uint8_t		nipc_rvsd1[64 - 48];
	uint32_t	nipc_vifrt;	/* VI Flexible total */
	uint32_t	nipc_virfa;	/* VI Flexible Assigned */
	uint16_t	nipc_virfap;	/* VI Flexible Allocatd to Primary */
	uint16_t	nipc_viprt;	/* VI Resources Private Total */
	uint16_t	nipc_vifrsm;	/* VI Resources Secondary Max */
	uint16_t	nipc_vigran;	/* VI Flexible Granularity */
	uint8_t		nipc_rsvd2[4096 - 80];
} nvme_identify_primary_caps_t;

/*
 * NVMe completion queue entry status field
 */
typedef struct {
	uint16_t sf_p:1;		/* Phase Tag */
	uint16_t sf_sc:8;		/* Status Code */
	uint16_t sf_sct:3;		/* Status Code Type */
	uint16_t sf_rsvd2:2;
	uint16_t sf_m:1;		/* More */
	uint16_t sf_dnr:1;		/* Do Not Retry */
} nvme_cqe_sf_t;


/*
 * NVMe Get Log Page
 */
#define	NVME_LOGPAGE_ERROR	0x1	/* Error Information */
#define	NVME_LOGPAGE_HEALTH	0x2	/* SMART/Health Information */
#define	NVME_LOGPAGE_FWSLOT	0x3	/* Firmware Slot Information */

typedef struct {
	uint64_t el_count;		/* Error Count */
	uint16_t el_sqid;		/* Submission Queue ID */
	uint16_t el_cid;		/* Command ID */
	nvme_cqe_sf_t el_sf;		/* Status Field */
	uint8_t	el_byte;		/* Parameter Error Location byte */
	uint8_t	el_bit:3;		/* Parameter Error Location bit */
	uint8_t el_rsvd1:5;
	uint64_t el_lba;		/* Logical Block Address */
	uint32_t el_nsid;		/* Namespace ID */
	uint8_t	el_vendor;		/* Vendor Specific Information avail */
	uint8_t el_rsvd2[64 - 29];
} nvme_error_log_entry_t;

typedef struct {
	uint64_t lo;
	uint64_t hi;
} nvme_uint128_t;

typedef struct {
	struct {			/* Critical Warning */
		uint8_t cw_avail:1;	/* available space too low */
		uint8_t cw_temp:1;	/* temperature too high */
		uint8_t cw_reliab:1;	/* degraded reliability */
		uint8_t cw_readonly:1;	/* media is read-only */
		uint8_t cw_volatile:1;	/* volatile memory backup failed */
		uint8_t cw_rsvd:3;
	} hl_crit_warn;
	uint16_t hl_temp;		/* Temperature */
	uint8_t hl_avail_spare;		/* Available Spare */
	uint8_t hl_avail_spare_thr;	/* Available Spare Threshold */
	uint8_t hl_used;		/* Percentage Used */
	uint8_t hl_rsvd1[32 - 6];
	nvme_uint128_t hl_data_read;	/* Data Units Read */
	nvme_uint128_t hl_data_write;	/* Data Units Written */
	nvme_uint128_t hl_host_read;	/* Host Read Commands */
	nvme_uint128_t hl_host_write;	/* Host Write Commands */
	nvme_uint128_t hl_ctrl_busy;	/* Controller Busy Time */
	nvme_uint128_t hl_power_cycles;	/* Power Cycles */
	nvme_uint128_t hl_power_on_hours; /* Power On Hours */
	nvme_uint128_t hl_unsafe_shutdn; /* Unsafe Shutdowns */
	nvme_uint128_t hl_media_errors;	/* Media Errors */
	nvme_uint128_t hl_errors_logged; /* Number of errors logged */
	uint8_t hl_rsvd2[512 - 192];
} nvme_health_log_t;

typedef struct {
	uint8_t fw_afi:3;		/* Active Firmware Slot */
	uint8_t fw_rsvd1:1;
	uint8_t fw_next:3;		/* Next Active Firmware Slot */
	uint8_t fw_rsvd2:1;
	uint8_t fw_rsvd3[7];
	char fw_frs[7][8];		/* Firmware Revision / Slot */
	uint8_t fw_rsvd4[512 - 64];
} nvme_fwslot_log_t;


/*
 * NVMe Format NVM
 */
#define	NVME_FRMT_SES_NONE	0
#define	NVME_FRMT_SES_USER	1
#define	NVME_FRMT_SES_CRYPTO	2
#define	NVME_FRMT_MAX_SES	2

#define	NVME_FRMT_MAX_LBAF	15

typedef union {
	struct {
		uint32_t fm_lbaf:4;		/* LBA Format */
		uint32_t fm_ms:1;		/* Metadata Settings */
		uint32_t fm_pi:3;		/* Protection Information */
		uint32_t fm_pil:1;		/* Prot. Information Location */
		uint32_t fm_ses:3;		/* Secure Erase Settings */
		uint32_t fm_resvd:20;
	} b;
	uint32_t r;
} nvme_format_nvm_t;


/*
 * NVMe Get / Set Features
 */
#define	NVME_FEAT_ARBITRATION	0x1	/* Command Arbitration */
#define	NVME_FEAT_POWER_MGMT	0x2	/* Power Management */
#define	NVME_FEAT_LBA_RANGE	0x3	/* LBA Range Type */
#define	NVME_FEAT_TEMPERATURE	0x4	/* Temperature Threshold */
#define	NVME_FEAT_ERROR		0x5	/* Error Recovery */
#define	NVME_FEAT_WRITE_CACHE	0x6	/* Volatile Write Cache */
#define	NVME_FEAT_NQUEUES	0x7	/* Number of Queues */
#define	NVME_FEAT_INTR_COAL	0x8	/* Interrupt Coalescing */
#define	NVME_FEAT_INTR_VECT	0x9	/* Interrupt Vector Configuration */
#define	NVME_FEAT_WRITE_ATOM	0xa	/* Write Atomicity */
#define	NVME_FEAT_ASYNC_EVENT	0xb	/* Asynchronous Event Configuration */
#define	NVME_FEAT_AUTO_PST	0xc	/* Autonomous Power State Transition */
					/* (1.1) */

#define	NVME_FEAT_PROGRESS	0x80	/* Software Progress Marker */

/* Arbitration Feature */
typedef union {
	struct {
		uint8_t arb_ab:3;	/* Arbitration Burst */
		uint8_t arb_rsvd:5;
		uint8_t arb_lpw;	/* Low Priority Weight */
		uint8_t arb_mpw;	/* Medium Priority Weight */
		uint8_t arb_hpw;	/* High Priority Weight */
	} b;
	uint32_t r;
} nvme_arbitration_t;

/* Power Management Feature */
typedef union {
	struct {
		uint32_t pm_ps:5;	/* Power State */
		uint32_t pm_rsvd:27;
	} b;
	uint32_t r;
} nvme_power_mgmt_t;

/* LBA Range Type Feature */
typedef union {
	struct {
		uint32_t lr_num:6;	/* Number of LBA ranges */
		uint32_t lr_rsvd:26;
	} b;
	uint32_t r;
} nvme_lba_range_type_t;

typedef struct {
	uint8_t lr_type;		/* Type */
	struct {			/* Attributes */
		uint8_t lr_write:1;	/* may be overwritten */
		uint8_t lr_hidden:1;	/* hidden from OS/EFI/BIOS */
		uint8_t lr_rsvd1:6;
	} lr_attr;
	uint8_t lr_rsvd2[14];
	uint64_t lr_slba;		/* Starting LBA */
	uint64_t lr_nlb;		/* Number of Logical Blocks */
	uint8_t lr_guid[16];		/* Unique Identifier */
	uint8_t lr_rsvd3[16];
} nvme_lba_range_t;

#define	NVME_LBA_RANGE_BUFSIZE	4096

/* Temperature Threshold Feature */
typedef union {
	struct {
		uint16_t tt_tmpth;	/* Temperature Threshold */
		uint16_t tt_rsvd;
	} b;
	uint32_t r;
} nvme_temp_threshold_t;

/* Error Recovery Feature */
typedef union {
	struct {
		uint16_t er_tler;	/* Time-Limited Error Recovery */
		uint16_t er_rsvd;
	} b;
	uint32_t r;
} nvme_error_recovery_t;

/* Volatile Write Cache Feature */
typedef union {
	struct {
		uint32_t wc_wce:1;	/* Volatile Write Cache Enable */
		uint32_t wc_rsvd:31;
	} b;
	uint32_t r;
} nvme_write_cache_t;

/* Number of Queues Feature */
typedef union {
	struct {
		uint16_t nq_nsq;	/* Number of Submission Queues */
		uint16_t nq_ncq;	/* Number of Completion Queues */
	} b;
	uint32_t r;
} nvme_nqueues_t;

/* Interrupt Coalescing Feature */
typedef union {
	struct {
		uint8_t ic_thr;		/* Aggregation Threshold */
		uint8_t ic_time;	/* Aggregation Time */
		uint16_t ic_rsvd;
	} b;
	uint32_t r;
} nvme_intr_coal_t;

/* Interrupt Configuration Features */
typedef union {
	struct {
		uint16_t iv_iv;		/* Interrupt Vector */
		uint16_t iv_cd:1;	/* Coalescing Disable */
		uint16_t iv_rsvd:15;
	} b;
	uint32_t r;
} nvme_intr_vect_t;

/* Write Atomicity Feature */
typedef union {
	struct {
		uint32_t wa_dn:1;	/* Disable Normal */
		uint32_t wa_rsvd:31;
	} b;
	uint32_t r;
} nvme_write_atomicity_t;

/* Asynchronous Event Configuration Feature */
typedef union {
	struct {
		uint8_t aec_avail:1;	/* available space too low */
		uint8_t aec_temp:1;	/* temperature too high */
		uint8_t aec_reliab:1;	/* degraded reliability */
		uint8_t aec_readonly:1;	/* media is read-only */
		uint8_t aec_volatile:1;	/* volatile memory backup failed */
		uint8_t aec_rsvd1:3;
		uint8_t aec_rsvd2[3];
	} b;
	uint32_t r;
} nvme_async_event_conf_t;

/* Autonomous Power State Transition Feature (1.1) */
typedef union {
	struct {
		uint8_t	apst_apste:1;	/* APST enabled */
		uint8_t apst_rsvd:7;
	} b;
	uint8_t r;
} nvme_auto_power_state_trans_t;

typedef struct {
	uint32_t apst_rsvd1:3;
	uint32_t apst_itps:5;	/* Idle Transition Power State */
	uint32_t apst_itpt:24;	/* Idle Time Prior to Transition */
	uint32_t apst_rsvd2;
} nvme_auto_power_state_t;

#define	NVME_AUTO_PST_BUFSIZE	256

/* Software Progress Marker Feature */
typedef union {
	struct {
		uint8_t spm_pbslc;	/* Pre-Boot Software Load Count */
		uint8_t spm_rsvd[3];
	} b;
	uint32_t r;
} nvme_software_progress_marker_t;

/*
 * Firmware Commit - Command Dword 10
 */
#define	NVME_FWC_SAVE		0x0	/* Save image only */
#define	NVME_FWC_SAVE_ACTIVATE	0x1	/* Save and activate at next reset */
#define	NVME_FWC_ACTIVATE	0x2	/* Activate slot at next reset */
#define	NVME_FWC_ACTIVATE_IMMED	0x3	/* Activate slot immediately */

/*
 * Firmware slot number is only 3 bits, and zero is not allowed.
 * Valid range is 1 to 7.
 */
#define	NVME_FW_SLOT_MIN	1	/* lowest allowable slot number ... */
#define	NVME_FW_SLOT_MAX	7	/* ... and highest */

/*
 * Some constants to make verification of DWORD variables and arguments easier.
 * A DWORD is 4 bytes.
 */
#define	NVME_DWORD_SHIFT	2
#define	NVME_DWORD_SIZE		(1 << NVME_DWORD_SHIFT)
#define	NVME_DWORD_MASK		(NVME_DWORD_SIZE - 1)

/*
 * Maximum offset a firmware image can be load at is the number of
 * DWORDS in a 32 bit field. Expressed in bytes its is:
 */
#define	NVME_FW_OFFSETB_MAX	((u_longlong_t)UINT32_MAX << NVME_DWORD_SHIFT)

typedef union {
	struct {
		uint32_t fc_slot:3;	/* Firmware slot */
		uint32_t fc_action:3;	/* Commit action */
		uint32_t fc_rsvd:26;
	} b;
	uint32_t r;
} nvme_firmware_commit_dw10_t;

#pragma pack() /* pack(1) */

/* NVMe completion status code type */
#define	NVME_CQE_SCT_GENERIC	0	/* Generic Command Status */
#define	NVME_CQE_SCT_SPECIFIC	1	/* Command Specific Status */
#define	NVME_CQE_SCT_INTEGRITY	2	/* Media and Data Integrity Errors */
#define	NVME_CQE_SCT_VENDOR	7	/* Vendor Specific */

/* NVMe completion status code (generic) */
#define	NVME_CQE_SC_GEN_SUCCESS		0x0	/* Successful Completion */
#define	NVME_CQE_SC_GEN_INV_OPC		0x1	/* Invalid Command Opcode */
#define	NVME_CQE_SC_GEN_INV_FLD		0x2	/* Invalid Field in Command */
#define	NVME_CQE_SC_GEN_ID_CNFL		0x3	/* Command ID Conflict */
#define	NVME_CQE_SC_GEN_DATA_XFR_ERR	0x4	/* Data Transfer Error */
#define	NVME_CQE_SC_GEN_ABORT_PWRLOSS	0x5	/* Cmds Aborted / Pwr Loss */
#define	NVME_CQE_SC_GEN_INTERNAL_ERR	0x6	/* Internal Error */
#define	NVME_CQE_SC_GEN_ABORT_REQUEST	0x7	/* Command Abort Requested */
#define	NVME_CQE_SC_GEN_ABORT_SQ_DEL	0x8	/* Cmd Aborted / SQ deletion */
#define	NVME_CQE_SC_GEN_ABORT_FUSE_FAIL	0x9	/* Cmd Aborted / Failed Fused */
#define	NVME_CQE_SC_GEN_ABORT_FUSE_MISS	0xa	/* Cmd Aborted / Missing Fusd */
#define	NVME_CQE_SC_GEN_INV_NS		0xb	/* Inval Namespace or Format */
#define	NVME_CQE_SC_GEN_CMD_SEQ_ERR	0xc	/* Command Sequence Error */
#define	NVME_CQE_SC_GEN_INV_SGL_LAST	0xd	/* Inval SGL Last Seg Desc */
#define	NVME_CQE_SC_GEN_INV_SGL_NUM	0xe	/* Inval Number of SGL Desc */
#define	NVME_CQE_SC_GEN_INV_DSGL_LEN	0xf	/* Data SGL Length Invalid */
#define	NVME_CQE_SC_GEN_INV_MSGL_LEN	0x10	/* Metadata SGL Length Inval */
#define	NVME_CQE_SC_GEN_INV_SGL_DESC	0x11	/* SGL Descriptor Type Inval */
#define	NVME_CQE_SC_GEN_INV_USE_CMB	0x12	/* Inval use of Ctrl Mem Buf */
#define	NVME_CQE_SC_GEN_INV_PRP_OFF	0x13	/* PRP Offset Invalid */
#define	NVME_CQE_SC_GEN_AWU_EXCEEDED	0x14	/* Atomic Write Unit Exceeded */

/* NVMe completion status code (generic NVM commands) */
#define	NVME_CQE_SC_GEN_NVM_LBA_RANGE	0x80	/* LBA Out Of Range */
#define	NVME_CQE_SC_GEN_NVM_CAP_EXC	0x81	/* Capacity Exceeded */
#define	NVME_CQE_SC_GEN_NVM_NS_NOTRDY	0x82	/* Namespace Not Ready */
#define	NVME_CQE_SC_GEN_NVM_RSV_CNFLCT	0x83	/* Reservation Conflict */

/* NVMe completion status code (command specific) */
#define	NVME_CQE_SC_SPC_INV_CQ		0x0	/* Completion Queue Invalid */
#define	NVME_CQE_SC_SPC_INV_QID		0x1	/* Invalid Queue Identifier */
#define	NVME_CQE_SC_SPC_MAX_QSZ_EXC	0x2	/* Max Queue Size Exceeded */
#define	NVME_CQE_SC_SPC_ABRT_CMD_EXC	0x3	/* Abort Cmd Limit Exceeded */
#define	NVME_CQE_SC_SPC_ASYNC_EVREQ_EXC	0x5	/* Async Event Request Limit */
#define	NVME_CQE_SC_SPC_INV_FW_SLOT	0x6	/* Invalid Firmware Slot */
#define	NVME_CQE_SC_SPC_INV_FW_IMG	0x7	/* Invalid Firmware Image */
#define	NVME_CQE_SC_SPC_INV_INT_VECT	0x8	/* Invalid Interrupt Vector */
#define	NVME_CQE_SC_SPC_INV_LOG_PAGE	0x9	/* Invalid Log Page */
#define	NVME_CQE_SC_SPC_INV_FORMAT	0xa	/* Invalid Format */
#define	NVME_CQE_SC_SPC_FW_RESET	0xb	/* FW Application Reset Reqd */
#define	NVME_CQE_SC_SPC_INV_Q_DEL	0xc	/* Invalid Queue Deletion */
#define	NVME_CQE_SC_SPC_FEAT_SAVE	0xd	/* Feature Id Not Saveable */
#define	NVME_CQE_SC_SPC_FEAT_CHG	0xe	/* Feature Not Changeable */
#define	NVME_CQE_SC_SPC_FEAT_NS_SPEC	0xf	/* Feature Not Namespace Spec */
#define	NVME_CQE_SC_SPC_FW_NSSR		0x10	/* FW Application NSSR Reqd */
#define	NVME_CQE_SC_SPC_FW_NEXT_RESET	0x11	/* FW Application Next Reqd */
#define	NVME_CQE_SC_SPC_FW_MTFA		0x12	/* FW Application Exceed MTFA */
#define	NVME_CQE_SC_SPC_FW_PROHIBITED	0x13	/* FW Application Prohibited */
#define	NVME_CQE_SC_SPC_FW_OVERLAP	0x14	/* Overlapping FW ranges */

/* NVMe completion status code (NVM command specific */
#define	NVME_CQE_SC_SPC_NVM_CNFL_ATTR	0x80	/* Conflicting Attributes */
#define	NVME_CQE_SC_SPC_NVM_INV_PROT	0x81	/* Invalid Protection */
#define	NVME_CQE_SC_SPC_NVM_READONLY	0x82	/* Write to Read Only Range */

/* NVMe completion status code (data / metadata integrity) */
#define	NVME_CQE_SC_INT_NVM_WRITE	0x80	/* Write Fault */
#define	NVME_CQE_SC_INT_NVM_READ	0x81	/* Unrecovered Read Error */
#define	NVME_CQE_SC_INT_NVM_GUARD	0x82	/* Guard Check Error */
#define	NVME_CQE_SC_INT_NVM_APPL_TAG	0x83	/* Application Tag Check Err */
#define	NVME_CQE_SC_INT_NVM_REF_TAG	0x84	/* Reference Tag Check Err */
#define	NVME_CQE_SC_INT_NVM_COMPARE	0x85	/* Compare Failure */
#define	NVME_CQE_SC_INT_NVM_ACCESS	0x86	/* Access Denied */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_H */
