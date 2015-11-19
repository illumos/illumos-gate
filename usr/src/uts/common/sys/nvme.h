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
#define	NVME_IOC_MAX			NVME_IOC_ATTACH

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
	uint8_t psd_rsvd7[16];
} nvme_idctl_psd_t;

/* NVMe Identify Controller Data Structure */
typedef struct {
	/* Controller Capabilities & Features */
	uint16_t id_vid;		/* PCI vendor ID */
	uint16_t id_ssvid; 		/* PCI subsystem vendor ID */
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
	uint8_t id_rsvd_cc[256 - 80];

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
	uint8_t id_rsvd_ac[256 - 10];

	/* NVM Command Set Attributes */
	nvme_idctl_qes_t id_sqes;	/* Submission Queue Entry Size */
	nvme_idctl_qes_t id_cqes;	/* Completion Queue Entry Size */
	uint16_t id_rsvd_nc_1;
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
	uint8_t id_rsvd_nc_4[192 - 28];

	/* I/O Command Set Attributes */
	uint8_t id_rsvd_ioc[1344];

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
	uint8_t id_rsvd1[120 - 32];
	uint8_t id_eui64[8];		/* IEEE Extended Unique Id (1.1) */
	nvme_idns_lbaf_t id_lbaf[16];	/* LBA Formats */

	uint8_t id_rsvd2[192];

	uint8_t id_vs[3712];		/* Vendor Specific */
} nvme_identify_nsid_t;


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
	uint8_t fw_rsvd1:5;
	uint8_t fw_rsvd2[7];
	char fw_frs[7][8];		/* Firmware Revision / Slot */
	uint8_t fw_rsvd3[512 - 64];
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

#pragma pack() /* pack(1) */


#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_H */
