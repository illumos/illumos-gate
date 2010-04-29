/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/* Copyright 2010 QLogic Corporation */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _QL_XIOCTL_H
#define	_QL_XIOCTL_H

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2010 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <exioct.h>

/* 0xFFFFFA Mgmt Server */
#define	MANAGEMENT_SERVER_LOOP_ID	0xfe
#define	MANAGEMENT_SERVER_24XX_LOOP_ID	0x7ef

/* Returned Mailbox registers. */
typedef struct ql_mbx_ret {
	uint16_t	mb[MAX_MBOX_COUNT];
} ql_mbx_ret_t;

/*
 * Name type defines for use with ql_scsi_passthru() and
 * elsewhere when searching for name matches.
 * NOTE that these defines are used both as flags and values.
 */
#define	QLNT_NODE		0x01
#define	QLNT_PORT		0x02
#define	QLNT_BOTH		(QLNT_NODE | QLNT_PORT)
#define	QLNT_PID		0x04
#define	QLNT_LOOP_ID		0x08
#define	QLNT_MASK		0x0F

/*
 * CT information unit basic preamble.
 */
typedef struct ql_ct_iu_preamble {
	uint8_t		revision;
	uint8_t		in_id[3];
	uint8_t		gs_type;
	uint8_t		gs_subtype;
	uint8_t		options;
	uint8_t		reserved;
	uint16_t	command_response_code;
	uint16_t	max_residual_size;
	uint8_t		fragment_id;
	uint8_t		reason_code;
	uint8_t		reason_code_explanation;
	uint8_t		vendor_specific;
} ql_ct_iu_preamble_t;

#define	GS_TYPE_DIR_SERVER	0xFC

/*
 * Link Status Counts structure
 *
 * Counts are BIG ENDIAN
 */
typedef struct ql_link_stats {
	uint32_t	link_fail_cnt;
	uint32_t	sync_loss_cnt;
	uint32_t	signal_loss_cnt;
	uint32_t	prot_err_cnt;	/* Primitive seq protocol errors */
	uint32_t	inv_xmit_cnt;	/* Invalid transmission word count */
	uint32_t	inv_crc_cnt;	/* Invalid CRC count */
} ql_link_stats_t;

/*
 * Report LUN definitions.
 */
typedef struct ql_rpt_hdr {
	uint32_t	len;
	uint32_t	rsrv;
} ql_rpt_hdr_t;

typedef struct ql_rpt_lun {
	struct {
		uint8_t		b : 6;
		uint8_t		address_method : 2;
	} msb;
	uint8_t		lsb;
	uint8_t		unused[6];
} ql_rpt_lun_t;

typedef struct ql_rpt_lun_lst {
	ql_rpt_hdr_t	hdr;
	ql_rpt_lun_t	lst[MAX_LUNS];
} ql_rpt_lun_lst_t;

#define	INQ_DATA_SIZE	8

/*
 * Flash definitions.
 */
typedef struct ql_flash_info {
	uint32_t	type;		/* flash type */
	uint32_t	size;		/* length in bytes of flash */
	uint32_t	sec_mask;	/* sector number mask */
	uint8_t		man_id;		/* flash chip manufacturer id */
	uint8_t		id;		/* flash chip id */
	uint8_t		cap;		/* flash chip capacity */
} ql_flash_info_t;

/*
 * Flash Description Table
 */
#define	FLASH_DESC_VERSION	1
#define	FLASH_DESC_VAILD	0x44494C51	/* "QLID" */
typedef struct flash_desc {
	uint32_t	flash_valid;
	uint16_t	flash_version;
	uint16_t	flash_len;
	uint16_t	flash_checksum;
	uint16_t	flash_unused;
	uint8_t		flash_model[16];
	uint16_t	flash_manuf;
	uint16_t	flash_id;
	uint8_t		flash_flag;
	uint8_t		erase_cmd;
	uint8_t		alt_erase_cmd;
	uint8_t		write_enable_cmd;
	uint8_t		write_enable_bits;
	uint8_t		write_statusreg_cmd;
	uint8_t		unprotect_sector_cmd;
	uint8_t		read_manuf_cmd;
	uint32_t	block_size;
	uint32_t	alt_block_size;
	uint32_t	flash_size;
	uint32_t	write_enable_data;
	uint8_t		readid_address_len;
	uint8_t		write_disable_bits;
	uint8_t		read_device_id_len;
	uint8_t		chip_erase_cmd;
	uint16_t	read_timeout;
	uint8_t		protect_sector_cmd;
	uint8_t		exp_reserved[65];
} flash_desc_t;

/* flash manufacturer id's */
#define	AMD_FLASH		0x01	/* AMD / Spansion */
#define	ST_FLASH		0x20	/* ST Electronics */
#define	SST_FLASH		0xbf	/* SST Electronics */
#define	MXIC_FLASH		0xc2	/* Macronix (MXIC) */
#define	ATMEL_FLASH		0x1f	/* Atmel (AT26DF081A) */
#define	WINBOND_FLASH		0xef	/* Winbond (W25X16) */
#define	INTEL_FLASH		0x89	/* Intel (QB25F016S33B8) */

/* flash id defines */
#define	AMD_FLASHID_128K	0x6e	/* 128k AMD flash chip */
#define	AMD_FLASHID_512K	0x4f	/* 512k AMD flash chip */
#define	AMD_FLASHID_512Kt	0xb9	/* 512k AMD flash chip - top boot blk */
#define	AMD_FLASHID_512Kb	0xba	/* 512k AMD flash chip - btm boot blk */
#define	AMD_FLASHID_1024K	0x38	/* 1 MB AMD flash chip */
#define	ST_FLASHID_128K		0x23	/* 128k ST flash chip */
#define	ST_FLASHID_512K		0xe3	/* 512k ST flash chip */
#define	ST_FLASHID_M25PXX	0x20	/* M25Pxx ST flash chip */
#define	SST_FLASHID_128K	0xd5	/* 128k SST flash chip */
#define	SST_FLASHID_1024K	0xd8	/* 1 MB SST flash chip */
#define	SST_FLASHID_1024K_A	0x80	/* 1 MB SST 25LF080A flash chip */
#define	SST_FLASHID_1024K_B	0x8e	/* 1 MB SST 25VF080B flash chip */
#define	SST_FLASHID_2048K	0x25	/* 2 MB SST 25VF016B flash chip */
#define	MXIC_FLASHID_512K	0x4f	/* 512k MXIC flash chip */
#define	MXIC_FLASHID_1024K	0x38	/* 1 MB MXIC flash chip */
#define	MXIC_FLASHID_25LXX	0x20	/* 25Lxx MXIC flash chip */
#define	ATMEL_FLASHID_1024K	0x45	/* 1 MB ATMEL flash chip */
#define	SPAN_FLASHID_2048K	0x02	/* 2 MB Spansion flash chip */
#define	WINBOND_FLASHID		0x30	/* Winbond W25Xxx flash chip */
#define	INTEL_FLASHID		0x89	/* Intel QB25F016S33B8 flash chip */

/* flash type defines */
#define	FLASH128	BIT_0
#define	FLASH512	BIT_1
#define	FLASH512S	BIT_2
#define	FLASH1024	BIT_3
#define	FLASH2048	BIT_4
#define	FLASH4096	BIT_5
#define	FLASH8192	BIT_6
#define	FLASH_PAGE	BIT_31
#define	FLASH_LEGACY	(FLASH128 | FLASH512S)

typedef struct ql_ledstate {
	uint32_t		BeaconState;
	uint32_t		LEDflags;
	uint32_t		flags;
} ql_ledstate_t;

/*
 * ledstate flags definitions
 */
#define	LED_ACTIVE	BIT_0

/*
 * ledstate BeaconState definitions
 */
#define	BEACON_OFF	0
#define	BEACON_ON	BIT_0

/*
 * ledstate LEDflags definitions
 */
#define	LED_ALL_OFF	0
#define	LED_RED		BIT_0
#define	LED_GREEN	BIT_6
#define	LED_AMBER	BIT_7
#define	LED_MASK	(LED_AMBER | LED_GREEN | LED_RED)

/*
 * 24xx ledstate LEDflags definitions
 */
#define	LED_MASK_UPDATE_24	(BIT_20 | BIT_19 | BIT_18)
#define	LED_YELLOW_24		BIT_2
#define	LED_GREEN_24		BIT_3
#define	LED_AMBER_24		BIT_4
#define	LED_MASK_COLORS_24	(LED_AMBER_24 | LED_GREEN_24 | LED_YELLOW_24)

typedef struct {
	uint8_t		signature[2];
	uint8_t		reserved[0x16];
	uint8_t		dataoffset[2];
	uint8_t		pad[6];
} pci_header_t;

typedef struct {
	uint8_t		 signature[4];
	uint8_t		 vid[2];
	uint8_t		 did[2];
	uint8_t		 reserved0[2];
	uint8_t		 pcidatalen[2];
	uint8_t		 pcidatarev;
	uint8_t		 classcode[3];
	uint8_t		 imagelength[2];   /* In sectors */
	uint8_t		 revisionlevel[2];
	uint8_t		 codetype;
	uint8_t		 indicator;
	uint8_t		 reserved1[2];
	uint8_t		 pad[8];
} pci_data_t;

#define	PCI_HEADER0		0x55
#define	PCI_HEADER1		0xAA
#define	PCI_DATASIG		"PCIR"
#define	PCI_SECTOR_SIZE		0x200
#define	PCI_CODE_X86PC		0
#define	PCI_CODE_FCODE		1
#define	PCI_CODE_HPPA		2
#define	PCI_CODE_EFI		3
#define	PCI_CODE_FW		0xfe
#define	PCI_IND_LAST_IMAGE	0x80
#define	SBUS_CODE_FCODE		0xf1

typedef struct ql_fcache {
	struct ql_fcache	*next;
	uint32_t		type;
	int8_t			verstr[FCHBA_OPTION_ROM_VERSION_LEN];
	uint32_t		buflen;
	uint8_t			*buf;
} ql_fcache_t;

/* fcache types */
#define	FTYPE_UNKNOWN	0
#define	FTYPE_FCODE	BIT_0
#define	FTYPE_BIOS	BIT_1
#define	FTYPE_EFI	BIT_2
#define	FTYPE_FW	BIT_3
#define	FTYPE_HPPA	BIT_4

#define	FBUFSIZE	100

/*
 * Flash Layout Table definitions.
 */
typedef struct ql_flash_layout_pointer {
	uint8_t		sig[4];
	uint8_t		addr[4];
	uint8_t		version;
	uint8_t		reserved[5];
	uint8_t		checksum[2];
} ql_flt_ptr_t;

typedef struct ql_flash_layout_header {
	uint8_t		version[2];
	uint8_t		len[2];
	uint8_t		checksum[2];
	uint8_t		reserved[2];
} ql_flt_hdr_t;

typedef struct ql_flash_layout_region {
	uint8_t		region;
	uint8_t		reserved;
	uint8_t		attribute;
	uint8_t		reserved_1;
	uint8_t		size[4];
	uint8_t		beg_addr[4];
	uint8_t		end_addr[4];
} ql_flt_region_t;

typedef struct ql_fp_cfg_hdr {
	uint8_t		version[2];
	uint8_t		len[2];
	uint8_t		checksum[2];
	uint8_t		NumberEntries[2];
	uint8_t		SizeEntry[2];
	uint8_t		unused[2];
	uint8_t		Signature[4];
} ql_fp_cfg_hdr_t;

typedef struct ql_fp_cfg {
	uint8_t		FunctionNumber[2];
	uint8_t		FunctionType;
	uint8_t		PortConfigIndex;
	uint8_t		ConfigRegion;
	uint8_t		VpdRegion;
	uint8_t		DCBXRegion;
	uint8_t		Reserved;
} ql_fp_cfg_t;

#define	FT_NIC		0
#define	FT_FC		1
#define	FT_ISCSI	2
#define	FT_VNIC		3

typedef struct ql_fp_cfg_map {
	ql_fp_cfg_hdr_t	hdr;
	ql_fp_cfg_t	cfg[6];
} ql_fp_cfg_map_t;

#define	FLASH_FW_REGION			0x01
#define	FLASH_VPD_0_REGION		0x14
#define	FLASH_NVRAM_0_REGION		0x15
#define	FLASH_VPD_1_REGION		0x16
#define	FLASH_NVRAM_1_REGION		0x17
#define	FLASH_DESC_TABLE_REGION		0x1A
#define	FLASH_ERROR_LOG_0_REGION	0x1D
#define	FLASH_ERROR_LOG_1_REGION	0x1F
#define	FLASH_GOLDEN_FW_REGION		0x2F

#define	FLASH_8021_FW_REGION		0x74
#define	FLASH_8021_GOLDEN_FW_REGION	0x75
#define	FLASH_8021_BOOTLOADER_REGION	0x72
#define	FLASH_8021_VPD_REGION		0x81

#define	FLASH_LAYOUT_TABLE_SIZE		4096

/*
 * Per instance XIOCTL context defintions.
 */
typedef struct ql_xioctl {
	/* Driver context */
	flash_desc_t	fdesc;

	/* Adapter I/O statistics */
	uint32_t		ControllerErrorCount;
	uint32_t		DeviceErrorCount;
	uint32_t		TotalLipResets;
	uint32_t		TotalInterrupts;

	uint64_t		BytesRequested;
	uint64_t		IosRequested;

	/* SNIA stat counters */
	int64_t			IOInputRequests;
	int64_t			IOOutputRequests;
	int64_t			IOControlRequests;
	int64_t			IOOutputMByteCnt;	/* # of mb's */
	int64_t			IOInputMByteCnt;	/* # of mb's */

	/* SNIA intermediate (less than 1mb) counters  */
	int64_t			IOOutputByteCnt;
	int64_t			IOInputByteCnt;

	/* Adapter LED state */
	ql_ledstate_t		ledstate;

	/* Async event context */
	void			*aen_tracking_queue;
	uint8_t			aen_q_head;
	uint8_t			aen_q_tail;

	uint32_t		flags;
} ql_xioctl_t;

/*
 * ql adapter flag defintions.
 */
#define	QL_AEN_TRACKING_ENABLE		BIT_0
#define	QL_MGMT_SERVER_LOGIN		BIT_1

/*
 * Global Data in ql_xioctl.c source file.
 */

/*
 * Global Function Prototypes in ql_xioctl.c source file.
 */
int ql_alloc_xioctl_resource(ql_adapter_state_t *);
void ql_free_xioctl_resource(ql_adapter_state_t *);
int ql_xioctl(ql_adapter_state_t *, int, intptr_t, int, cred_t *, int *);
void ql_enqueue_aen(ql_adapter_state_t *, uint16_t, void *);
int ql_setup_fcache(ql_adapter_state_t *);
void ql_blink_led(ql_adapter_state_t *);
void ql_fcache_rel(ql_fcache_t *);
ql_fcache_t *ql_get_fbuf(ql_fcache_t *, uint32_t);
int ql_dump_fcode(ql_adapter_state_t *, uint8_t *, uint32_t, uint32_t);
int ql_pci_dump(ql_adapter_state_t *, uint32_t *, uint32_t, int);
int ql_load_fcode(ql_adapter_state_t *, uint8_t *, uint32_t, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _QL_XIOCTL_H */
