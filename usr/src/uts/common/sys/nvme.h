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
 * Copyright 2020 Joyent, Inc.
 * Copyright 2019 Western Digital Corporation
 * Copyright 2023 Oxide Computer Company
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _SYS_NVME_H
#define	_SYS_NVME_H

#include <sys/types.h>
#include <sys/debug.h>

#ifdef _KERNEL
#include <sys/types32.h>
#else
#include <sys/uuid.h>
#include <stdint.h>
#endif

/*
 * Declarations used for communication between nvmeadm(8) and nvme(4D)
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NVMe ioctl definitions
 */

#define	NVME_IOC			(('N' << 24) | ('V' << 16) | ('M' << 8))
#define	NVME_IOC_IDENTIFY		(NVME_IOC | 1)
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
#define	NVME_IOC_PASSTHRU		(NVME_IOC | 13)
#define	NVME_IOC_NS_INFO		(NVME_IOC | 14)
#define	NVME_IOC_MAX			NVME_IOC_NS_INFO

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

typedef struct {
	uint64_t lo;
	uint64_t hi;
} nvme_uint128_t;

/*
 * NVMe Identify data structures
 */

#define	NVME_IDENTIFY_BUFSIZE	4096	/* buffer size for Identify */

/* NVMe Identify parameters (cdw10) */
#define	NVME_IDENTIFY_NSID		0x0	/* Identify Namespace */
#define	NVME_IDENTIFY_CTRL		0x1	/* Identify Controller */
#define	NVME_IDENTIFY_NSID_LIST		0x2	/* List Active Namespaces */
#define	NVME_IDENTIFY_NSID_DESC		0x3	/* Namespace ID Descriptors */

#define	NVME_IDENTIFY_NSID_ALLOC_LIST	0x10	/* List Allocated NSID */
#define	NVME_IDENTIFY_NSID_ALLOC	0x11	/* Identify Allocated NSID */
#define	NVME_IDENTIFY_NSID_CTRL_LIST	0x12	/* List Controllers on NSID */
#define	NVME_IDENTIFY_CTRL_LIST		0x13	/* Controller List */
#define	NVME_IDENTIFY_PRIMARY_CAPS	0x14	/* Primary Controller Caps */


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

#define	NVME_SERIAL_SZ	20
#define	NVME_MODEL_SZ	40

/* NVMe Identify Controller Data Structure */
typedef struct {
	/* Controller Capabilities & Features */
	uint16_t id_vid;		/* PCI vendor ID */
	uint16_t id_ssvid;		/* PCI subsystem vendor ID */
	char id_serial[NVME_SERIAL_SZ];	/* Serial Number */
	char id_model[NVME_MODEL_SZ];	/* Model Number */
	char id_fwrev[8];		/* Firmware Revision */
	uint8_t id_rab;			/* Recommended Arbitration Burst */
	uint8_t id_oui[3];		/* vendor IEEE OUI */
	struct {			/* Multi-Interface Capabilities */
		uint8_t m_multi_pci:1;	/* HW has multiple PCIe interfaces */
		uint8_t m_multi_ctrl:1; /* HW has multiple controllers (1.1) */
		uint8_t m_sr_iov:1;	/* Controller is SR-IOV virt fn (1.1) */
		uint8_t m_anar_sup:1;	/* ANA Reporting Supported (1.4) */
		uint8_t m_rsvd:4;
	} id_mic;
	uint8_t	id_mdts;		/* Maximum Data Transfer Size */
	uint16_t id_cntlid;		/* Unique Controller Identifier (1.1) */
	/* Added in NVMe 1.2 */
	uint32_t id_ver;		/* Version (1.2) */
	uint32_t id_rtd3r;		/* RTD3 Resume Latency (1.2) */
	uint32_t id_rtd3e;		/* RTD3 Entry Latency (1.2) */
	struct {
		uint32_t oaes_rsvd0:8;
		uint32_t oaes_nsan:1;	/* Namespace Attribute Notices (1.2) */
		uint32_t oaes_fwact:1;	/* Firmware Activation Notices (1.2) */
		uint32_t oaes_rsvd1:1;
		uint32_t oaes_ansacn:1;	/* Asymmetric NS Access Change (1.4) */
		uint32_t oaes_plat:1;	/* Predictable Lat Event Agg. (1.4) */
		uint32_t oaes_lbasi:1;	/* LBA Status Information (1.4) */
		uint32_t oaes_egeal:1;	/* Endurance Group Event Agg. (1.4) */
		uint32_t oaes_rsvd2:17;
	} id_oaes;
	struct {
		uint32_t ctrat_hid:1;	/* 128-bit Host Identifier (1.2)  */
		uint32_t ctrat_nops:1;	/* Non-Operational Power State (1.3) */
		uint32_t ctrat_nvmset:1; /* NVMe Sets (1.4) */
		uint32_t ctrat_rrl:1;	/* Read Recovery Levels (1.4) */
		uint32_t ctrat_engrp:1; /* Endurance Groups (1.4) */
		uint32_t ctrat_plm:1;	/* Predictable Latency Mode (1.4) */
		uint32_t ctrat_tbkas:1;	/* Traffic Based Keep Alive (1.4) */
		uint32_t ctrat_nsg:1;	/* Namespace Granularity (1.4) */
		uint32_t ctrat_sqass:1;	/* SQ Associations (1.4) */
		uint32_t ctrat_uuid:1;	/* UUID List (1.4) */
		uint32_t ctrat_rsvd:22;
	} id_ctratt;
	uint16_t id_rrls;		/* Read Recovery Levels (1.4) */
	uint8_t id_rsvd_cc[111-102];
	uint8_t id_cntrltype;		/* Controller Type (1.4) */
	uint8_t id_frguid[16];		/* FRU GUID (1.3) */
	uint16_t id_crdt1;		/* Command Retry Delay Time 1 (1.4) */
	uint16_t id_crdt2;		/* Command Retry Delay Time 2 (1.4) */
	uint16_t id_crdt3;		/* Command Retry Delay Time 3 (1.4) */
	uint8_t id_rsvd2_cc[240 - 134];
	uint8_t id_rsvd_nvmemi[253 - 240];
	/* NVMe-MI region */
	struct {			/* NVMe Subsystem Report */
		uint8_t nvmsr_nvmesd:1;	/* NVMe Storage Device */
		uint8_t nvmsr_nvmee:1;	/* NVMe Enclosure */
		uint8_t nvmsr_rsvd:6;
	} id_nvmsr;
	struct {			/* VPD Write Cycle Information */
		uint8_t vwci_crem:7;	/* Write Cycles Remaining */
		uint8_t vwci_valid:1;	/* Write Cycles Remaining Valid */
	} id_vpdwc;
	struct {			/* Management Endpoint Capabilities */
		uint8_t mec_smbusme:1;	/* SMBus Port Management Endpoint */
		uint8_t mec_pcieme:1;	/* PCIe Port Management Endpoint */
		uint8_t mec_rsvd:6;
	} id_mec;

	/* Admin Command Set Attributes */
	struct {			/* Optional Admin Command Support */
		uint16_t oa_security:1;	/* Security Send & Receive */
		uint16_t oa_format:1;	/* Format NVM */
		uint16_t oa_firmware:1;	/* Firmware Activate & Download */
		uint16_t oa_nsmgmt:1;	/* Namespace Management (1.2) */
		uint16_t oa_selftest:1;	/* Self Test (1.3) */
		uint16_t oa_direct:1;	/* Directives (1.3) */
		uint16_t oa_nvmemi:1;	/* MI-Send/Recv (1.3) */
		uint16_t oa_virtmgmt:1;	/* Virtualization Management (1.3) */
		uint16_t oa_doorbell:1;	/* Doorbell Buffer Config (1.3) */
		uint16_t oa_lbastat:1;	/* LBA Status (1.4) */
		uint16_t oa_rsvd:6;
	} id_oacs;
	uint8_t	id_acl;			/* Abort Command Limit */
	uint8_t id_aerl;		/* Asynchronous Event Request Limit */
	struct {			/* Firmware Updates */
		uint8_t fw_readonly:1;	/* Slot 1 is Read-Only */
		uint8_t	fw_nslot:3;	/* number of firmware slots */
		uint8_t fw_norst:1;	/* Activate w/o reset (1.2) */
		uint8_t fw_rsvd:3;
	} id_frmw;
	struct {			/* Log Page Attributes */
		uint8_t lp_smart:1;	/* SMART/Health information per NS */
		uint8_t lp_cmdeff:1;	/* Command Effects (1.2) */
		uint8_t lp_extsup:1;	/* Extended Get Log Page (1.2) */
		uint8_t lp_telemetry:1;	/* Telemetry Log Pages (1.3) */
		uint8_t lp_persist:1;	/* Persistent Log Page (1.4) */
		uint8_t lp_rsvd:3;
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
	uint16_t ap_wctemp;		/* Warning Composite Temp. (1.2) */
	uint16_t ap_cctemp;		/* Critical Composite Temp. (1.2) */
	uint16_t ap_mtfa;		/* Maximum Firmware Activation (1.2) */
	uint32_t ap_hmpre;		/* Host Memory Buf Pref Size (1.2) */
	uint32_t ap_hmmin;		/* Host Memory Buf Min Size (1.2) */
	nvme_uint128_t ap_tnvmcap;	/* Total NVM Capacity in Bytes (1.2) */
	nvme_uint128_t ap_unvmcap;	/* Unallocated NVM Capacity (1.2) */
	struct {			/* Replay Protected Mem. Block (1.2) */
		uint32_t rpmbs_units:3;	/* Number of targets */
		uint32_t rpmbs_auth:3;	/* Auth method */
		uint32_t rpmbs_rsvd:10;
		uint32_t rpmbs_tot:8;	/* Total size in 128KB */
		uint32_t rpmbs_acc:8;	/* Access size in 512B */
	} ap_rpmbs;
	/* Added in NVMe 1.3 */
	uint16_t ap_edstt;		/* Ext. Device Self-test time (1.3) */
	struct {			/* Device Self-test Options */
		uint8_t dsto_sub:1;	/* Subsystem level self-test (1.3) */
		uint8_t dsto_rsvd:7;
	} ap_dsto;
	uint8_t ap_fwug;		/* Firmware Update Granularity (1.3) */
	uint16_t ap_kas;		/* Keep Alive Support (1.2) */
	struct {			/* Host Thermal Management (1.3) */
		uint16_t hctma_hctm:1;	/* Host Controlled (1.3) */
		uint16_t hctma_rsvd:15;
	} ap_hctma;
	uint16_t ap_mntmt;		/* Minimum Thermal Temperature (1.3) */
	uint16_t ap_mxtmt;		/* Maximum Thermal Temperature (1.3) */
	struct {			/* Sanitize Caps */
		uint32_t san_ces:1;	/* Crypto Erase Support (1.3) */
		uint32_t san_bes:1;	/* Block Erase Support (1.3) */
		uint32_t san_ows:1;	/* Overwite Support (1.3) */
		uint32_t san_rsvd:26;
		uint32_t san_ndi:1;	/* No-deallocate Inhibited (1.4) */
		uint32_t san_nodmmas:2;	/* No-Deallocate Modifies Media (1.4) */
	} ap_sanitize;
	uint32_t ap_hmminds;		/* Host Mem Buf Min Desc Entry (1.4) */
	uint16_t ap_hmmaxd;		/* How Mem Max Desc Entries (1.4) */
	uint16_t ap_nsetidmax;		/* Max NVMe set identifier (1.4) */
	uint16_t ap_engidmax;		/* Max Endurance Group ID (1.4) */
	uint8_t ap_anatt;		/* ANA Transition Time (1.4) */
	struct {			/* Asymmetric Namespace Access Caps */
		uint8_t anacap_opt:1;	/* Optimized State (1.4) */
		uint8_t anacap_unopt:1;	/* Un-optimized State (1.4) */
		uint8_t anacap_inacc:1;	/* Inaccessible State (1.4) */
		uint8_t anacap_ploss:1;	/* Persistent Loss (1.4) */
		uint8_t anacap_chg:1;	/* Change State (1.4 ) */
		uint8_t anacap_rsvd:1;
		uint8_t anacap_grpns:1;	/* ID Changes with NS Attach (1.4) */
		uint8_t anacap_grpid:1;	/* Supports Group ID (1.4) */
	} ap_anacap;
	uint32_t ap_anagrpmax;		/* ANA Group ID Max (1.4) */
	uint32_t ap_nanagrpid;		/* Number of ANA Group IDs (1.4) */
	uint32_t ap_pels;		/* Persistent Event Log Size (1.4) */
	uint8_t id_rsvd_ac[512 - 356];

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
		uint16_t on_ts:1;	/* Timestamp (1.3) */
		uint16_t on_verify:1;	/* Verify (1.4) */
		uint16_t on_rsvd:8;
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
		uint8_t vwc_nsflush:2;	/* Flush with NS ffffffff (1.4) */
		uint8_t rsvd:5;
	} id_vwc;
	uint16_t id_awun;		/* Atomic Write Unit Normal */
	uint16_t id_awupf;		/* Atomic Write Unit Power Fail */
	struct {			/* NVM Vendor Specific Command Conf */
		uint8_t nv_spec:1;	/* use format from spec */
		uint8_t nv_rsvd:7;
	} id_nvscc;
	struct {			/* Namespace Write Protection Caps */
		uint8_t nwpc_base:1;	/* Base support (1.4) */
		uint8_t nwpc_wpupc:1;	/* Write prot until power cycle (1.4) */
		uint8_t nwpc_permwp:1;	/* Permanent write prot (1.4) */
		uint8_t nwpc_rsvd:5;
	} id_nwpc;
	uint16_t id_acwu;		/* Atomic Compare & Write Unit (1.1) */
	uint16_t id_rsvd_nc_3;
	struct {			/* SGL Support (1.1) */
		uint16_t sgl_sup:2;	/* SGL Supported in NVM cmds (1.3) */
		uint16_t sgl_keyed:1;	/* Keyed SGL Support (1.2) */
		uint16_t sgl_rsvd1:13;
		uint16_t sgl_bucket:1;	/* SGL Bit Bucket supported (1.1) */
		uint16_t sgl_balign:1;	/* SGL Byte Aligned (1.2) */
		uint16_t sgl_sglgtd:1;	/* SGL Length Longer than Data (1.2) */
		uint16_t sgl_mptr:1;	/* SGL MPTR w/ SGL (1.2) */
		uint16_t sgl_offset:1;	/* SGL Address is offset (1.2) */
		uint16_t sgl_tport:1;	/* Transport SGL Data Block (1.4) */
		uint16_t sgl_rsvd2:10;
	} id_sgls;
	uint32_t id_mnan;		/* Maximum Number of Allowed NSes */
	uint8_t id_rsvd_nc_4[768 - 544];

	/* I/O Command Set Attributes */
	uint8_t id_subnqn[1024 - 768];	/* Subsystem Qualified Name (1.2.1+) */
	uint8_t id_rsvd_ioc[1792 - 1024];
	uint8_t id_nvmof[2048 - 1792];	/* NVMe over Fabrics */

	/* Power State Descriptors */
	nvme_idctl_psd_t id_psd[32];

	/* Vendor Specific */
	uint8_t id_vs[1024];
} nvme_identify_ctrl_t;

/*
 * NVMe Controller Types
 */
#define	NVME_CNTRLTYPE_RSVD	0
#define	NVME_CNTRLTYPE_IO	1
#define	NVME_CNTRLTYPE_DISC	2
#define	NVME_CNTRLTYPE_ADMIN	3

/*
 * RPMBS Authentication Types
 */
#define	NVME_RPMBS_AUTH_HMAC_SHA256	0

/*
 * NODMMAS Values
 */
#define	NVME_NODMMAS_UNDEF	0x00
#define	NVME_NODMMAS_NOMOD	0x01
#define	NVME_NODMMAS_DOMOD	0x02

/*
 * VWC NSID flushes
 */
#define	NVME_VWCNS_UNKNOWN	0x00
#define	NVME_VWCNS_UNSUP	0x02
#define	NVME_VWCNS_SUP		0x03

/*
 * SGL Support Values
 */
#define	NVME_SGL_UNSUP		0x00
#define	NVME_SGL_SUP_UNALIGN	0x01
#define	NVME_SGL_SUP_ALIGN	0x02

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
		uint8_t f_nsabp:1;	/* Namespace atomics (1.2) */
		uint8_t f_dae:1;	/* Deallocated errors supported (1.2) */
		uint8_t f_uidreuse:1;	/* GUID reuse impossible (1.3) */
		uint8_t f_optperf:1;	/* Namespace I/O opt (1.4) */
		uint8_t f_rsvd:3;
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
		uint8_t rc_ign_ekey:1;	/* Ignore Existing Key (1.3) */
	} id_rescap;
	struct {			/* Format Progress Indicator (1.2) */
		uint8_t fpi_remp:7;	/* Percent NVM Format Remaining (1.2) */
		uint8_t fpi_sup:1;	/* Supported (1.2) */
	} id_fpi;
	uint8_t id_dfleat;		/* Deallocate Log. Block (1.3) */
	uint16_t id_nawun;		/* Atomic Write Unit Normal (1.2) */
	uint16_t id_nawupf;		/* Atomic Write Unit Power Fail (1.2) */
	uint16_t id_nacwu;		/* Atomic Compare & Write Unit (1.2) */
	uint16_t id_nabsn;		/* Atomic Boundary Size Normal (1.2) */
	uint16_t id_nbao;		/* Atomic Boundary Offset (1.2) */
	uint16_t id_nabspf;		/* Atomic Boundary Size Fail (1.2) */
	uint16_t id_noiob;		/* Optimal I/O Bondary (1.3) */
	nvme_uint128_t id_nvmcap;	/* NVM Capacity */
	uint16_t id_npwg;		/* NS Pref. Write Gran. (1.4) */
	uint16_t id_npwa;		/* NS Pref. Write Align. (1.4) */
	uint16_t id_npdg;		/* NS Pref. Deallocate Gran. (1.4) */
	uint16_t id_npda;		/* NS Pref. Deallocate Align. (1.4) */
	uint16_t id_nows;		/* NS. Optimal Write Size (1.4) */
	uint8_t id_rsvd1[92 - 74];
	uint32_t id_anagrpid;		/* ANA Group Identifier (1.4) */
	uint8_t id_rsvd2[99 - 96];
	struct {
		uint8_t nsa_wprot:1;	/* Write Protected (1.4) */
		uint8_t nsa_rsvd:7;
	} id_nsattr;
	uint16_t id_nvmsetid;		/* NVM Set Identifier (1.4) */
	uint16_t id_endgid;		/* Endurance Group Identifier (1.4) */
	uint8_t id_nguid[16];		/* Namespace GUID (1.2) */
	uint8_t id_eui64[8];		/* IEEE Extended Unique Id (1.1) */
	nvme_idns_lbaf_t id_lbaf[16];	/* LBA Formats */

	uint8_t id_rsvd3[384 - 192];

	uint8_t id_vs[4096 - 384];	/* Vendor Specific */
} nvme_identify_nsid_t;

/* NVMe Identify Namespace ID List */
typedef struct {
					/* Ordered list of Namespace IDs */
	uint32_t nl_nsid[NVME_IDENTIFY_BUFSIZE / sizeof (uint32_t)];
} nvme_identify_nsid_list_t;

/* NVME Identify Controller ID List */
typedef struct {
	uint16_t	cl_nid;		/* Number of controller entries */
					/* unique controller identifiers */
	uint16_t	cl_ctlid[NVME_IDENTIFY_BUFSIZE / sizeof (uint16_t) - 1];
} nvme_identify_ctrl_list_t;

/* NVMe Identify Namespace Descriptor */
typedef struct {
	uint8_t nd_nidt;		/* Namespace Identifier Type */
	uint8_t nd_nidl;		/* Namespace Identifier Length */
	uint8_t nd_resv[2];
	uint8_t nd_nid[];		/* Namespace Identifier */
} nvme_identify_nsid_desc_t;

#define	NVME_NSID_DESC_EUI64	1
#define	NVME_NSID_DESC_NGUID	2
#define	NVME_NSID_DESC_NUUID	3
#define	NVME_NSID_DESC_MIN	NVME_NSID_DESC_EUI64
#define	NVME_NSID_DESC_MAX	NVME_NSID_DESC_NUUID

#define	NVME_NSID_DESC_LEN_EUI64	8
#define	NVME_NSID_DESC_LEN_NGUID	16
#define	NVME_NSID_DESC_LEN_NUUID	UUID_LEN

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
	uint16_t	nipc_virfap;	/* VI Flexible Allocated to Primary */
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
#define	NVME_LOGPAGE_NSCHANGE	0x4	/* Changed namespace (1.2) */

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
	/* Added in NVMe 1.2 */
	uint32_t hl_warn_temp_time;	/* Warning Composite Temp Time */
	uint32_t hl_crit_temp_time;	/* Critical Composite Temp Time */
	uint16_t hl_temp_sensor_1;	/* Temperature Sensor 1 */
	uint16_t hl_temp_sensor_2;	/* Temperature Sensor 2 */
	uint16_t hl_temp_sensor_3;	/* Temperature Sensor 3 */
	uint16_t hl_temp_sensor_4;	/* Temperature Sensor 4 */
	uint16_t hl_temp_sensor_5;	/* Temperature Sensor 5 */
	uint16_t hl_temp_sensor_6;	/* Temperature Sensor 6 */
	uint16_t hl_temp_sensor_7;	/* Temperature Sensor 7 */
	uint16_t hl_temp_sensor_8;	/* Temperature Sensor 8 */
	/* Added in NVMe 1.3 */
	uint32_t hl_tmtemp_1_tc;	/* Thermal Mgmt Temp 1 Transition # */
	uint32_t hl_tmtemp_2_tc;	/* Thermal Mgmt Temp 1 Transition # */
	uint32_t hl_tmtemp_1_time;	/* Time in Thermal Mgmt Temp 1 */
	uint32_t hl_tmtemp_2_time;	/* Time in Thermal Mgmt Temp 2 */
	uint8_t hl_rsvd2[512 - 232];
} nvme_health_log_t;

/*
 * The NVMe spec allows for up to seven firmware slots.
 */
#define	NVME_MAX_FWSLOTS	7
#define	NVME_FWVER_SZ		8

typedef struct {
	/* Active Firmware Slot */
	uint8_t fw_afi:3;
	uint8_t fw_rsvd1:1;
	/* Next Active Firmware Slot */
	uint8_t fw_next:3;
	uint8_t fw_rsvd2:1;
	uint8_t fw_rsvd3[7];
	/* Firmware Revision / Slot */
	char fw_frs[NVME_MAX_FWSLOTS][NVME_FWVER_SZ];
	uint8_t fw_rsvd4[512 - 64];
} nvme_fwslot_log_t;

/*
 * The NVMe spec specifies that the changed namespace list contains up to
 * 1024 entries.
 */
#define	NVME_NSCHANGE_LIST_SIZE	1024

typedef struct {
	uint32_t	nscl_ns[NVME_NSCHANGE_LIST_SIZE];
} nvme_nschange_list_t;

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
		uint16_t tt_tmpsel:4;	/* Temperature Select */
		uint16_t tt_thsel:2;	/* Temperature Type */
		uint16_t tt_resv:10;
	} b;
	uint32_t r;
} nvme_temp_threshold_t;

#define	NVME_TEMP_THRESH_MAX_SENSOR	8
#define	NVME_TEMP_THRESH_ALL	0xf
#define	NVME_TEMP_THRESH_OVER	0x00
#define	NVME_TEMP_THRESH_UNDER	0x01

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
		uint8_t aec_avail:1;	/* Available space too low */
		uint8_t aec_temp:1;	/* Temperature too high */
		uint8_t aec_reliab:1;	/* Degraded reliability */
		uint8_t aec_readonly:1;	/* Media is read-only */
		uint8_t aec_volatile:1;	/* Volatile memory backup failed */
		uint8_t aec_rsvd1:3;
		uint8_t aec_nsan:1;	/* Namespace attribute notices (1.2) */
		uint8_t aec_fwact:1;	/* Firmware activation notices (1.2) */
		uint8_t aec_telln:1;	/* Telemetry log notices (1.3) */
		uint8_t aec_ansacn:1;	/* Asymm. NS access change (1.4) */
		uint8_t aec_plat:1;	/* Predictable latency ev. agg. (1.4) */
		uint8_t aec_lbasi:1;	/* LBA status information (1.4) */
		uint8_t aec_egeal:1;	/* Endurance group ev. agg. (1.4) */
		uint8_t aec_rsvd2:1;
		uint8_t aec_rsvd3[2];
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
#define	NVME_CQE_SC_GEN_NVM_FORMATTING	0x84	/* Format in progress (1.2) */

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

/* Flags for NVMe passthru commands. */
#define	NVME_PASSTHRU_READ	0x1 /* Read from device */
#define	NVME_PASSTHRU_WRITE	0x2 /* Write to device */

/* Error codes for NVMe passthru command validation. */
/* Must be sizeof(nvme_passthru_cmd_t) */
#define	NVME_PASSTHRU_ERR_CMD_SIZE	0x01
#define	NVME_PASSTHRU_ERR_NOT_SUPPORTED	0x02	/* Not supported on device */
#define	NVME_PASSTHRU_ERR_INVALID_OPCODE	0x03
#define	NVME_PASSTHRU_ERR_READ_AND_WRITE	0x04	/* Must read ^ write */
#define	NVME_PASSTHRU_ERR_INVALID_TIMEOUT	0x05

/*
 * Must be
 * - multiple of 4 bytes in length
 * - non-null iff length is non-zero
 * - null if neither reading nor writing
 * - non-null if either reading or writing
 * - <= `nvme_vendor_specific_admin_cmd_size` in length, 16 MiB
 * - <= UINT32_MAX in length
 */
#define	NVME_PASSTHRU_ERR_INVALID_BUFFER	0x06


/* Generic struct for passing through vendor-unique commands to a device. */
typedef struct {
	uint8_t npc_opcode;	/* Command opcode. */
	uint8_t npc_status;	/* Command completion status code. */
	uint8_t npc_err;	/* Error-code if validation fails. */
	uint8_t npc_rsvd0;	/* Align to 4 bytes */
	uint32_t npc_timeout;	/* Command timeout, in seconds. */
	uint32_t npc_flags;	/* Flags for the command. */
	uint32_t npc_cdw0;	/* Command-specific result DWord 0 */
	uint32_t npc_cdw12;	/* Command-specific DWord 12 */
	uint32_t npc_cdw13;	/* Command-specific DWord 13 */
	uint32_t npc_cdw14;	/* Command-specific DWord 14 */
	uint32_t npc_cdw15;	/* Command-specific DWord 15 */
	size_t npc_buflen;	/* Size of npc_buf. */
	uintptr_t npc_buf;	/* I/O source or destination */
} nvme_passthru_cmd_t;

#ifdef _KERNEL
typedef struct {
	uint8_t npc_opcode;	/* Command opcode. */
	uint8_t npc_status;	/* Command completion status code. */
	uint8_t npc_err;	/* Error-code if validation fails. */
	uint8_t npc_rsvd0;	/* Align to 4 bytes */
	uint32_t npc_timeout;	/* Command timeout, in seconds. */
	uint32_t npc_flags;	/* Flags for the command. */
	uint32_t npc_cdw0;	/* Command-specific result DWord 0 */
	uint32_t npc_cdw12;	/* Command-specific DWord 12 */
	uint32_t npc_cdw13;	/* Command-specific DWord 13 */
	uint32_t npc_cdw14;	/* Command-specific DWord 14 */
	uint32_t npc_cdw15;	/* Command-specific DWord 15 */
	size32_t npc_buflen;	/* Size of npc_buf. */
	uintptr32_t npc_buf;	/* I/O source or destination */
} nvme_passthru_cmd32_t;
#endif

/*
 * NVME namespace state flags.
 *
 * The values are defined entirely by the driver. Some states correspond to
 * namespace states described by the NVMe specification r1.3 section 6.1, others
 * are specific to the implementation of this driver. These are present in the
 * nvme_ns_info_t that is used with the NVME_IOC_NS_INFO ioctl.
 *
 * The states are as follows:
 * - ALLOCATED: the namespace exists in the controller as per the NVMe spec
 * - ACTIVE: the namespace exists and is attached to this controller as per the
 *   NVMe spec. Any namespace that is ACTIVE is also ALLOCATED. This must not be
 *   confused with the ATTACHED state.
 * - ATTACHED: the driver has attached a blkdev(4D) instance to this namespace.
 *   This state can be changed by userspace with the ioctls NVME_IOC_ATTACH and
 *   NVME_IOC_DETACH. A namespace can only be ATTACHED when it is not IGNORED.
 * - IGNORED: the driver ignores this namespace, it never attaches a blkdev(4D).
 *   Namespaces are IGNORED when they are not ACTIVE, or if they are ACTIVE but
 *   have certain properties that the driver cannot handle.
 */
typedef enum {
	NVME_NS_STATE_ALLOCATED	=	1 << 0,
	NVME_NS_STATE_ACTIVE	=	1 << 1,
	NVME_NS_STATE_ATTACHED	=	1 << 2,
	NVME_NS_STATE_IGNORED	=	1 << 3
} nvme_ns_state_t;

/*
 * This is the maximum length of the NVMe namespace's blkdev address. This is
 * only valid in the structure with the NVME_NS_STATE_ATTACHED flag is set.
 * Otherwise the entry will be all zeros. This is useful when you need to
 * determine what the corresponding blkdev instance in libdevinfo for the
 * device.
 */
#define	NVME_BLKDEV_NAMELEN	128

typedef struct {
	nvme_ns_state_t	nni_state;
	char nni_addr[NVME_BLKDEV_NAMELEN];
	nvme_identify_nsid_t nni_id;
} nvme_ns_info_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_H */
