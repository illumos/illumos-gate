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
 * Copyright 2023 Racktop Systems, Inc.
 */
#ifndef _LMRC_REG_H
#define	_LMRC_REG_H

#include <sys/bitext.h>
#include <sys/debug.h>
#include <sys/stddef.h>

typedef struct lmrc_raid_mfa_io_req_desc	lmrc_raid_mfa_io_req_desc_t;
typedef union lmrc_atomic_req_desc		lmrc_atomic_req_desc_t;
typedef union lmrc_req_desc			lmrc_req_desc_t;

typedef union lmrc_mfi_cap		lmrc_mfi_cap_t;
typedef union lmrc_mfi_sgl		lmrc_mfi_sgl_t;
typedef struct lmrc_mfi_header		lmrc_mfi_header_t;
typedef	struct lmrc_mfi_init_payload	lmrc_mfi_init_payload_t;
typedef struct lmrc_mfi_io_payload	lmrc_mfi_io_payload_t;
typedef struct lmrc_mfi_pthru_payload	lmrc_mfi_pthru_payload_t;
typedef struct lmrc_mfi_dcmd_payload	lmrc_mfi_dcmd_payload_t;
typedef struct lmrc_mfi_abort_payload	lmrc_mfi_abort_payload_t;
typedef struct lmrc_mfi_frame		lmrc_mfi_frame_t;

typedef struct lmrc_aen			lmrc_aen_t;
typedef union lmrc_evt_class_locale	lmrc_evt_class_locale_t;
typedef struct lmrc_evt_log_info	lmrc_evt_log_info_t;
typedef struct lmrc_evtarg_ld		lmrc_evtarg_ld_t;
typedef struct lmrc_evtarg_pd		lmrc_evtarg_pd_t;
typedef struct lmrc_evt			lmrc_evt_t;

typedef struct lmrc_ctrl_prop		lmrc_ctrl_prop_t;
typedef struct lmrc_image_comp		lmrc_image_comp_t;
typedef struct lmrc_ctrl_info		lmrc_ctrl_info_t;

#include "lmrc_raid.h"

/* PCI device IDs of Gen 3.5 Controllers */
#define	LMRC_VENTURA		0x0014
#define	LMRC_CRUSADER		0x0015
#define	LMRC_HARPOON		0x0016
#define	LMRC_TOMCAT		0x0017
#define	LMRC_VENTURA_4PORT	0x001B
#define	LMRC_CRUSADER_4PORT	0x001C
#define	LMRC_AERO_10E0		0x10E0
#define	LMRC_AERO_10E1		0x10E1
#define	LMRC_AERO_10E2		0x10E2
#define	LMRC_AERO_10E3		0x10E3
#define	LMRC_AERO_10E4		0x10E4
#define	LMRC_AERO_10E5		0x10E5
#define	LMRC_AERO_10E6		0x10E6
#define	LMRC_AERO_10E7		0x10E7

/*
 * Message Frame Defines
 */
#define	LMRC_SENSE_LEN		96

#define	MFI_FUSION_ENABLE_INTERRUPT_MASK	0x00000009


#define	LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE	256

#define	LMRC_SPECIFIC_MPI2_FUNCTION(x)		\
	(MPI2_FUNCTION_MIN_PRODUCT_SPECIFIC + (x))
#define	LMRC_MPI2_FUNCTION_PASSTHRU_IO_REQUEST	LMRC_SPECIFIC_MPI2_FUNCTION(0)
#define	LMRC_MPI2_FUNCTION_LD_IO_REQUEST	LMRC_SPECIFIC_MPI2_FUNCTION(1)


#define	LMRC_MAX_MFI_CMDS			16
#define	LMRC_MAX_IOCTL_CMDS			3

/*
 * Firmware Status Register
 * For Ventura and Aero controllers, this is outbound scratch pad register 0.
 */
#define	LMRC_FW_RESET_REQUIRED(reg)		(bitx32((reg), 0, 0) != 0)
#define	LMRC_FW_RESET_ADAPTER(reg)		(bitx32((reg), 1, 1) != 0)
#define	LMRC_FW_MAX_CMD(reg)			bitx32((reg), 15, 0)
#define	LMRC_FW_MSIX_ENABLED(reg)		(bitx32((reg), 26, 26) != 0)
#define	LMRC_FW_STATE(reg)			bitx32((reg), 31, 28)

/* outbound scratch pad register 1 */
#define	LMRC_MAX_CHAIN_SIZE(reg)		bitx32((reg), 9, 5)
#define	LMRC_MAX_REPLY_QUEUES_EXT(reg)		bitx32((reg), 21, 14)
#define	LMRC_EXT_CHAIN_SIZE_SUPPORT(reg)	(bitx32((reg), 22, 22) != 0)
#define	LMRC_RDPQ_MODE_SUPPORT(reg)		(bitx32((reg), 23, 23) != 0)
#define	LMRC_SYNC_CACHE_SUPPORT(reg)		(bitx32((reg), 24, 24) != 0)
#define	LMRC_ATOMIC_DESCRIPTOR_SUPPORT(reg)	(bitx32((reg), 24, 24) != 0)
#define	LMRC_64BIT_DMA_SUPPORT(reg)		(bitx32((reg), 25, 25) != 0)
#define	LMRC_INTR_COALESCING_SUPPORT(reg)	(bitx32((reg), 26, 26) != 0)

#define	LMRC_256K_IO				128
#define	LMRC_1MB_IO				(LMRC_256K_IO * 4)

/* outbound scratch pad register 2 */
#define	LMRC_MAX_RAID_MAP_SZ(reg)		bitx32((reg), 24, 16)

/* outbound scratch pad register 3 */
#define	LMRC_NVME_PAGE_SHIFT(reg)		bitx32((reg), 7, 0)
#define	LMRC_DEFAULT_NVME_PAGE_SHIFT		12

/*
 * Firmware Interface
 *
 * MFI stands for MegaRAID SAS FW Interface. This is just a moniker
 * for the protocol between the software and the firmware. Commands are
 * issued using "message frames".
 */
/*
 * FW posts its state in the upper 4 bits of the status register, extracted
 * with LMRC_FW_STATE(reg).
 */
#define	LMRC_FW_STATE_UNDEFINED			0x0
#define	LMRC_FW_STATE_BB_INIT			0x1
#define	LMRC_FW_STATE_FW_INIT			0x4
#define	LMRC_FW_STATE_WAIT_HANDSHAKE		0x6
#define	LMRC_FW_STATE_FW_INIT_2			0x7
#define	LMRC_FW_STATE_DEVICE_SCAN		0x8
#define	LMRC_FW_STATE_BOOT_MSG_PENDING		0x9
#define	LMRC_FW_STATE_FLUSH_CACHE		0xa
#define	LMRC_FW_STATE_READY			0xb
#define	LMRC_FW_STATE_OPERATIONAL		0xc
#define	LMRC_FW_STATE_FAULT			0xf

/*
 * During FW init, clear pending cmds & reset state using the doorbell register
 *
 * ABORT:		Abort all pending cmds
 * READY:		Move from OPERATIONAL to READY state; discard queue info
 * MFIMODE:		Discard (possible) low MFA posted in 64-bit mode (??)
 * CLEAR_HANDSHAKE:	FW is waiting for HANDSHAKE from BIOS or Driver
 * HOTPLUG:		Resume from Hotplug
 * MFI_STOP_ADP:	Send signal to FW to stop processing
 */
#define	MFI_INIT_ABORT			0x00000001
#define	MFI_INIT_READY			0x00000002
#define	MFI_INIT_MFIMODE		0x00000004
#define	MFI_INIT_CLEAR_HANDSHAKE	0x00000008
#define	MFI_INIT_HOTPLUG		0x00000010
#define	MFI_STOP_ADP			0x00000020
#define	MFI_RESET_FLAGS		(MFI_INIT_READY|MFI_INIT_MFIMODE|MFI_INIT_ABORT)

/*
 * MFI frame flags
 */
#define	MFI_FRAME_DONT_POST_IN_REPLY_QUEUE	0x0001
#define	MFI_FRAME_SGL64			0x0002
#define	MFI_FRAME_SENSE64		0x0004
#define	MFI_FRAME_DIR_NONE		0
#define	MFI_FRAME_DIR_WRITE		0x0008
#define	MFI_FRAME_DIR_READ		0x0010
#define	MFI_FRAME_DIR_BOTH		0x0018
#define	MFI_FRAME_IEEE			0x0020

/*
 * MFI command opcodes
 */
#define	MFI_CMD_INIT			0x00
#define	MFI_CMD_LD_READ			0x01
#define	MFI_CMD_LD_WRITE		0x02
#define	MFI_CMD_LD_SCSI_IO		0x03
#define	MFI_CMD_PD_SCSI_IO		0x04
#define	MFI_CMD_DCMD			0x05
#define	MFI_CMD_ABORT			0x06
#define	MFI_CMD_SMP			0x07
#define	MFI_CMD_STP			0x08
#define	MFI_CMD_INVALID			0xff

/*
 * MFI command status completion codes
 */
#define	MFI_STAT_OK				0x00
#define	MFI_STAT_INVALID_CMD			0x01
#define	MFI_STAT_INVALID_DCMD			0x02
#define	MFI_STAT_INVALID_PARAMETER		0x03
#define	MFI_STAT_INVALID_SEQUENCE_NUMBER	0x04
#define	MFI_STAT_ABORT_NOT_POSSIBLE		0x05
#define	MFI_STAT_APP_HOST_CODE_NOT_FOUND	0x06
#define	MFI_STAT_APP_IN_USE			0x07
#define	MFI_STAT_APP_NOT_INITIALIZED		0x08
#define	MFI_STAT_ARRAY_INDEX_INVALID		0x09
#define	MFI_STAT_ARRAY_ROW_NOT_EMPTY		0x0a
#define	MFI_STAT_CONFIG_RESOURCE_CONFLICT	0x0b
#define	MFI_STAT_DEVICE_NOT_FOUND		0x0c
#define	MFI_STAT_DRIVE_TOO_SMALL		0x0d
#define	MFI_STAT_FLASH_ALLOC_FAIL		0x0e
#define	MFI_STAT_FLASH_BUSY			0x0f
#define	MFI_STAT_FLASH_ERROR			0x10
#define	MFI_STAT_FLASH_IMAGE_BAD		0x11
#define	MFI_STAT_FLASH_IMAGE_INCOMPLETE		0x12
#define	MFI_STAT_FLASH_NOT_OPEN			0x13
#define	MFI_STAT_FLASH_NOT_STARTED		0x14
#define	MFI_STAT_FLUSH_FAILED			0x15
#define	MFI_STAT_HOST_CODE_NOT_FOUNT		0x16
#define	MFI_STAT_LD_CC_IN_PROGRESS		0x17
#define	MFI_STAT_LD_INIT_IN_PROGRESS		0x18
#define	MFI_STAT_LD_LBA_OUT_OF_RANGE		0x19
#define	MFI_STAT_LD_MAX_CONFIGURED		0x1a
#define	MFI_STAT_LD_NOT_OPTIMAL			0x1b
#define	MFI_STAT_LD_RBLD_IN_PROGRESS		0x1c
#define	MFI_STAT_LD_RECON_IN_PROGRESS		0x1d
#define	MFI_STAT_LD_WRONG_RAID_LEVEL		0x1e
#define	MFI_STAT_MAX_SPARES_EXCEEDED		0x1f
#define	MFI_STAT_MEMORY_NOT_AVAILABLE		0x20
#define	MFI_STAT_MFC_HW_ERROR			0x21
#define	MFI_STAT_NO_HW_PRESENT			0x22
#define	MFI_STAT_NOT_FOUND			0x23
#define	MFI_STAT_NOT_IN_ENCL			0x24
#define	MFI_STAT_PD_CLEAR_IN_PROGRESS		0x25
#define	MFI_STAT_PD_TYPE_WRONG			0x26
#define	MFI_STAT_PR_DISABLED			0x27
#define	MFI_STAT_ROW_INDEX_INVALID		0x28
#define	MFI_STAT_SAS_CONFIG_INVALID_ACTION	0x29
#define	MFI_STAT_SAS_CONFIG_INVALID_DATA	0x2a
#define	MFI_STAT_SAS_CONFIG_INVALID_PAGE	0x2b
#define	MFI_STAT_SAS_CONFIG_INVALID_TYPE	0x2c
#define	MFI_STAT_SCSI_DONE_WITH_ERROR		0x2d
#define	MFI_STAT_SCSI_IO_FAILED			0x2e
#define	MFI_STAT_SCSI_RESERVATION_CONFLICT	0x2f
#define	MFI_STAT_SHUTDOWN_FAILED		0x30
#define	MFI_STAT_TIME_NOT_SET			0x31
#define	MFI_STAT_WRONG_STATE			0x32
#define	MFI_STAT_LD_OFFLINE			0x33
#define	MFI_STAT_PEER_NOTIFICATION_REJECTED	0x34
#define	MFI_STAT_PEER_NOTIFICATION_FAILED	0x35
#define	MFI_STAT_RESERVATION_IN_PROGRESS	0x36
#define	MFI_STAT_I2C_ERRORS_DETECTED		0x37
#define	MFI_STAT_PCI_ERRORS_DETECTED		0x38
#define	MFI_STAT_CONFIG_SEQ_MISMATCH		0x67

#define	MFI_STAT_INVALID_STATUS			0xFF

/*
 * MFI DCMDs
 */
#define	LMRC_DCMD_CTRL_GET_INFO			0x01010000
#define	LMRC_DCMD_CTRL_EVENT_GET_INFO		0x01040100
#define	LMRC_DCMD_CTRL_EVENT_WAIT		0x01040500
#define	LMRC_DCMD_CTRL_SHUTDOWN			0x01050000
#define	LMRC_DCMD_PD_GET_INFO			0x02020000
#define	LMRC_DCMD_PD_LIST_QUERY			0x02010100
#define	LMRC_DCMD_SYSTEM_PD_MAP_GET_INFO	0x0200e102
#define	LMRC_DCMD_LD_MAP_GET_INFO		0x0300e101
#define	LMRC_DCMD_LD_GET_LIST			0x03010000
#define	LMRC_DCMD_LD_LIST_QUERY			0x03010100

#define	LMRC_PD_QUERY_TYPE_ALL			0
#define	LMRC_PD_QUERY_TYPE_STATE		1
#define	LMRC_PD_QUERY_TYPE_POWER_STATE		2
#define	LMRC_PD_QUERY_TYPE_MEDIA_TYPE		3
#define	LMRC_PD_QUERY_TYPE_SPEED		4
#define	LMRC_PD_QUERY_TYPE_EXPOSED_TO_HOST	5

#define	LMRC_LD_QUERY_TYPE_ALL			0
#define	LMRC_LD_QUERY_TYPE_EXPOSED_TO_HOST	1
#define	LMRC_LD_QUERY_TYPE_USED_TGT_IDS		2
#define	LMRC_LD_QUERY_TYPE_CLUSTER_ACCESS	3
#define	LMRC_LD_QUERY_TYPE_CLUSTER_LOCALE	4

#define	LMRC_DCMD_MBOX_PEND_FLAG	0x01

#define	LMRC_MAX_PD_CHANNELS		1
#define	LMRC_MAX_LD_CHANNELS		1
#define	LMRC_MAX_DEV_PER_CHANNEL	256
#define	LMRC_MAX_PD			\
	(LMRC_MAX_PD_CHANNELS * LMRC_MAX_DEV_PER_CHANNEL)
#define	LMRC_MAX_LD			\
	(LMRC_MAX_LD_CHANNELS * LMRC_MAX_DEV_PER_CHANNEL)
#define	LMRC_MAX_TM_TARGETS		(LMRC_MAX_PD + LMRC_MAX_LD)

#define	LMRC_DEFAULT_INIT_ID		-1
#define	LMRC_MAX_LUN			8
#define	LMRC_DEFAULT_CMD_PER_LUN	256

/*
 * Register offsets
 */
#define	LMRC_DOORBELL			0x0000
#define	LMRC_WRITE_SEQUENCE		0x0004
#define	LMRC_HOST_DIAG			0x0008

#define	LMRC_IB_MSG0			0x0010
#define	LMRC_IB_MSG1			0x0014
#define	LMRC_OB_MSG0			0x0018
#define	LMRC_OB_MSG1			0x001C

#define	LMRC_IB_DOORBELL		0x0020
#define	LMRC_IB_INTR_STATUS		0x0024
#define	LMRC_IB_INTR_MASK		0x0028

#define	LMRC_OB_DOORBELL		0x002C
#define	LMRC_OB_INTR_STATUS		0x0030
#define	LMRC_OB_INTR_MASK		0x0034

#define	LMRC_IB_QUEUE_PORT		0x0040
#define	LMRC_OB_QUEUE_PORT		0x0044

#define	LMRC_REPLY_POST_HOST_INDEX	0x006C

#define	LMRC_OB_DOORBELL_CLR		0x00A0

#define	LMRC_OB_SCRATCH_PAD(x)		(0x00B0 + (x) * 4)

#define	LMRC_IB_LO_QUEUE_PORT		0x00C0
#define	LMRC_IB_HI_QUEUE_PORT		0x00C4
#define	LMRC_IB_SINGLE_QUEUE_PORT	0x00C8

#define	LMRC_SUP_REPLY_POST_HOST_INDEX	0x030C

#define	LMRC_MAX_REPLY_POST_HOST_INDEX	16


/* By default, the firmware programs for 8k of memory */
#define	LMRC_MFI_MIN_MEM	4096
#define	LMRC_MFI_DEF_MEM	8192
#define	LMRC_MFI_MAX_CMD	16

#define	LMRC_MAX_SGE_CNT	0x50


#pragma pack(1)

/*
 * MPT RAID MFA IO Descriptor.
 *
 * Note: The use of the lowest 8 bits for flags implies that an alignment
 * of 256 bytes is required for the physical address.
 */
struct lmrc_raid_mfa_io_req_desc {
	uint32_t RequestFlags:8;
	uint32_t MessageAddress1:24;	/* bits 31:8 */
	uint32_t MessageAddress2;	/* bits 61:32 */
};

/*
 * unions of Request Descriptors
 */
union lmrc_atomic_req_desc {
	Mpi26AtomicRequestDescriptor_t rd_atomic;
	uint32_t rd_reg;
};

union lmrc_req_desc {
	uint64_t	rd_reg;

	struct {
		uint32_t	rd_reg_lo;
		uint32_t	rd_reg_hi;
	};

	lmrc_atomic_req_desc_t		rd_atomic;
	lmrc_raid_mfa_io_req_desc_t	rd_mfa_io;
};


union lmrc_mfi_cap {
	struct {
		uint32_t mc_support_fp_remote_lun:1;
		uint32_t mc_support_additional_msix:1;
		uint32_t mc_support_fastpath_wb:1;
		uint32_t mc_support_max_255lds:1;
		uint32_t mc_support_ndrive_r1_lb:1;
		uint32_t mc_support_core_affinity:1;
		uint32_t mc_support_security_protocol_cmds_fw:1;
		uint32_t mc_support_ext_queue_depth:1;
		uint32_t mc_support_ext_io_size:1;
		uint32_t mc_reserved:23;
	};
	uint32_t	mc_reg;
};
CTASSERT(sizeof (lmrc_mfi_cap_t) == 4);

union lmrc_mfi_sgl {
	struct {
		uint32_t	ms32_phys_addr;
		uint32_t	ms32_length;
	};
	struct {
		uint64_t	ms64_phys_addr;
		uint32_t	ms64_length;
	};
};

struct lmrc_mfi_header {
	uint8_t		mh_cmd;				/* 0x00 */
	uint8_t		mh_sense_len;			/* 0x01 */
	uint8_t		mh_cmd_status;			/* 0x02 */
	uint8_t		mh_scsi_status;			/* 0x03 */

	union {
		lmrc_mfi_cap_t	mh_drv_opts;		/* 0x04 */
		struct {
			uint8_t	mh_target_id;		/* 0x04 */
			union {
				uint8_t	mh_lun;		/* 0x05 */
				uint8_t mh_access_byte;	/* 0x05 */
			};
			uint8_t mh_cdb_len;		/* 0x06 */
			uint8_t mh_sge_count;		/* 0x07 */
		};
	};

	uint32_t	mh_context;			/* 0x08 */
	uint32_t	mh_pad_0;			/* 0x0c */

	uint16_t	mh_flags;			/* 0x10 */
	uint16_t	mh_timeout;			/* 0x12 */
	union {
		uint32_t mh_data_xfer_len;		/* 0x14 */
		uint32_t mh_lba_count;			/* 0x14 */
	};
};

struct lmrc_mfi_init_payload {
	uint64_t	mi_queue_info_new_phys_addr;	/* 0x18 */
	uint64_t	mi_queue_info_old_phys_addr;	/* 0x20 */
	uint64_t	mi_driver_ver_phys_addr;	/* 0x28 */
};

struct lmrc_mfi_io_payload {
	uint64_t	mio_sense_buf_phys_addr;	/* 0x18 */
	uint64_t	mio_start_lba;			/* 0x20 */
	lmrc_mfi_sgl_t	mio_sgl;			/* 0x28 */
};

struct lmrc_mfi_pthru_payload {
	uint64_t	mp_sense_buf_phys_addr;		/* 0x18 */
	uint8_t		mp_cdb[16];			/* 0x20 */
	lmrc_mfi_sgl_t	mp_sgl;				/* 0x30 */
};

struct lmrc_mfi_dcmd_payload {
	uint32_t	md_opcode;			/* 0x18 */

	union {						/* 0x1c */
		uint8_t		md_mbox_8[12];
		uint16_t	md_mbox_16[6];
		uint32_t	md_mbox_32[3];
	};

	lmrc_mfi_sgl_t	md_sgl;				/* 0x28 */
};

struct lmrc_mfi_abort_payload {
	uint32_t	ma_abort_context;		/* 0x18 */
	uint32_t	ma_pad_1;			/* 0x1c */
	uint64_t	ma_abort_mfi_phys_addr;		/* 0x20 */
};

struct lmrc_mfi_frame {
	lmrc_mfi_header_t	mf_hdr;
	union {
		lmrc_mfi_init_payload_t		mf_init;
		lmrc_mfi_io_payload_t		mf_io;
		lmrc_mfi_pthru_payload_t	mf_pthru;
		lmrc_mfi_dcmd_payload_t		mf_dcmd;
		lmrc_mfi_abort_payload_t	mf_abort;
		uint8_t mf_raw[64 - sizeof (lmrc_mfi_header_t)];
	};
};
CTASSERT(offsetof(lmrc_mfi_frame_t, mf_init) == 0x18);
CTASSERT(sizeof (lmrc_mfi_frame_t) == 64);

struct lmrc_aen {
	uint16_t	aen_host_no;
	uint16_t	aen_cmd_status;
	uint32_t	aen_seqnum;
	uint32_t	aen_class_locale_word;
};

/*
 * Asynchronous Event Notifications
 */
#define	LMRC_EVT_CFG_CLEARED			0x0004
#define	LMRC_EVT_CTRL_PATROL_READ_COMPLETE	0x0023
#define	LMRC_EVT_CTRL_PATROL_READ_RESUMED	0x0026
#define	LMRC_EVT_CTRL_PATROL_READ_START		0x0027
#define	LMRC_EVT_LD_BG_INIT_PROGRESS		0x0034
#define	LMRC_EVT_LD_CC_COMPLETE			0x003a
#define	LMRC_EVT_LD_CC_PROGRESS			0x0041
#define	LMRC_EVT_LD_CC_STARTED			0x0042
#define	LMRC_EVT_LD_INIT_ABORTED		0x0043
#define	LMRC_EVT_LD_INIT_PROGRESS		0x0045
#define	LMRC_EVT_LD_FAST_INIT_STARTED		0x0046
#define	LMRC_EVT_LD_FULL_INIT_STARTED		0x0047
#define	LMRC_EVT_LD_INIT_COMPLETE		0x0048
#define	LMRC_EVT_LD_PROP_CHANGED		0x0049
#define	LMRC_EVT_LD_STATE_CHANGE		0x0051
#define	LMRC_EVT_PD_INSERTED			0x005b
#define	LMRC_EVT_PD_PATROL_READ_PROGRESS	0x005e
#define	LMRC_EVT_PD_REMOVED			0x0070
#define	LMRC_EVT_PD_CHANGED			0x0072
#define	LMRC_EVT_LD_CREATED			0x008a
#define	LMRC_EVT_LD_DELETED			0x008b
#define	LMRC_EVT_FOREIGN_CFG_IMPORTED		0x00db
#define	LMRC_EVT_LD_OPTIMAL			0x00f9
#define	LMRC_EVT_LD_OFFLINE			0x00fc
#define	LMRC_EVT_PD_RESET			0x010c
#define	LMRC_EVT_CTRL_PATROL_READ_CANT_START	0x0124
#define	LMRC_EVT_CTRL_PROP_CHANGED		0x012f
#define	LMRC_EVT_LD_BBT_CLEARED			0x014f
#define	LMRC_EVT_CTRL_HOST_BUS_SCAN_REQD	0x0152
#define	LMRC_EVT_LD_AVAILABLE			0x0172
#define	LMRC_EVT_CTRL_PERF_COLLECTION		0x017e
#define	LMRC_EVT_CTRL_BOOTDEV_SET		0x01ec
#define	LMRC_EVT_CTRL_BOOTDEV_RESET		0x01f3
#define	LMRC_EVT_CTRL_PERSONALITY_CHANGE	0x0206
#define	LMRC_EVT_CTRL_PERSONALITY_CHANGE_PEND	0x0222
#define	LMRC_EVT_CTRL_NR_OF_VALID_SNAPDUMP	0x024e

#define	LMRC_EVT_CLASS_DEBUG			-2
#define	LMRC_EVT_CLASS_PROGRESS			-1
#define	LMRC_EVT_CLASS_INFO			0
#define	LMRC_EVT_CLASS_WARNING			1
#define	LMRC_EVT_CLASS_CRITICAL			2
#define	LMRC_EVT_CLASS_FATAL			3
#define	LMRC_EVT_CLASS_DEAD			4

#define	LMRC_EVT_LOCALE_LD			0x0001
#define	LMRC_EVT_LOCALE_PD			0x0002
#define	LMRC_EVT_LOCALE_ENCL			0x0004
#define	LMRC_EVT_LOCALE_BBU			0x0008
#define	LMRC_EVT_LOCALE_SAS			0x0010
#define	LMRC_EVT_LOCALE_CTRL			0x0020
#define	LMRC_EVT_LOCALE_CONFIG			0x0040
#define	LMRC_EVT_LOCALE_CLUSTER			0x0080
#define	LMRC_EVT_LOCALE_ALL			0xffff

union lmrc_evt_class_locale {
	struct {
		uint16_t	ecl_locale;
		uint8_t		ecl_rsvd;
		int8_t		ecl_class;
	};
	uint32_t	ecl_word;
};

struct lmrc_evt_log_info {
	uint32_t	eli_newest_seqnum;
	uint32_t	eli_oldest_seqnum;
	uint32_t	eli_clear_seqnum;
	uint32_t	eli_shutdown_seqnum;
	uint32_t	eli_boot_seqnum;
};

struct lmrc_evtarg_ld {
	uint16_t	el_tgtid;
	uint8_t		el_ld_id;
	uint8_t		el_rsvd;
};

struct lmrc_evtarg_pd {
	uint16_t	ep_dev_id;
	uint8_t		ep_enc_id;
	uint8_t		ep_slot;
};

struct lmrc_evt {
	uint32_t	evt_seqnum;
	uint32_t	evt_timestamp;
	uint32_t	evt_code;
	uint16_t	evt_locale;
	uint8_t		evt_rsvd;
	int8_t		evt_class;
	uint8_t		evt_argtype;
	uint8_t		evt_rsvd2[15];
	union {
		lmrc_evtarg_ld_t	evt_ld;
		lmrc_evtarg_pd_t	evt_pd;
		char			evt_str[96];
	};
	char		evt_descr[128];
};
CTASSERT(sizeof (lmrc_evt_t) == 256);

/*
 * SAS controller properties
 */
struct lmrc_ctrl_prop {
	uint16_t cp_seq_num;
	uint16_t cp_pred_fail_poll_interval;
	uint16_t cp_intr_throttle_count;
	uint16_t cp_intr_throttle_timeouts;
	uint8_t cp_rebuild_rate;
	uint8_t cp_patrol_read_rate;
	uint8_t cp_bgi_rate;
	uint8_t cp_cc_rate;
	uint8_t cp_recon_rate;
	uint8_t cp_cache_flush_interval;
	uint8_t cp_spinup_drv_count;
	uint8_t cp_spinup_delay;
	uint8_t cp_cluster_enable;
	uint8_t cp_coercion_mode;
	uint8_t cp_alarm_enable;
	uint8_t cp_disable_auto_rebuild;
	uint8_t cp_disable_battery_warn;
	uint8_t cp_ecc_bucket_size;
	uint16_t cp_ecc_bucket_leak_rate;
	uint8_t cp_restore_hotspare_on_insertion;
	uint8_t cp_expose_encl_devices;
	uint8_t cp_maintain_pd_fail_history;
	uint8_t cp_disallow_host_request_reordering;
	uint8_t cp_abort_cc_on_error;
	uint8_t cp_load_balance_mode;
	uint8_t cp_disable_auto_detect_backplane;
	uint8_t cp_snap_vd_space;

	struct {
		uint32_t cp_copy_back_disabled:1;
		uint32_t cp_smarter_enabled:1;
		uint32_t cp_pr_correct_unconfigured_areas:1;
		uint32_t cp_use_FDE_only:1;
		uint32_t cp_disable_NCQ:1;
		uint32_t cp_SSD_smarter_enabled:1;
		uint32_t cp_SSD_patrol_read_enabled:1;
		uint32_t cp_enable_spin_down_unconfigured:1;
		uint32_t cp_auto_enhanced_import:1;
		uint32_t cp_enable_secret_key_control:1;
		uint32_t cp_disable_online_ctrl_reset:1;
		uint32_t cp_allow_boot_with_pinned_cache:1;
		uint32_t cp_disable_spin_down_HS:1;
		uint32_t cp_enable_JBOD:1;
		uint32_t cp_disable_cache_bypass:1;
		uint32_t cp_use_disk_activity_for_locate:1;
		uint32_t cp_enable_PI:1;
		uint32_t cp_prevent_PI_import:1;
		uint32_t cp_use_global_spares_for_emergency:1;
		uint32_t cp_use_unconf_good_for_emergency:1;
		uint32_t cp_use_emergency_spares_for_smarter:1;
		uint32_t cp_force_sgpio_for_quad_only:1;
		uint32_t cp_enable_config_auto_balance:1;
		uint32_t cp_enable_virtual_cache:1;
		uint32_t cp_enable_auto_lock_recovery:1;
		uint32_t cp_disable_immediate_io:1;
		uint32_t cp_disable_T10_rebuild_assist:1;
		uint32_t cp_ignore64_ld_restriction:1;
		uint32_t cp_enable_sw_zone:1;
		uint32_t cp_limit_max_rate_SATA_3G:1;
		uint32_t cp_reserved:2;
	};
	uint8_t cp_auto_snap_vd_space;
	uint8_t cp_view_space;
	uint16_t cp_spin_down_time;
	uint8_t cp_reserved2[24];
};

struct lmrc_image_comp {
	char ic_name[8];
	char ic_version[32];
	char ic_build_date[16];
	char ic_built_time[16];
};

/*
 * SAS controller information
 */
struct lmrc_ctrl_info {
	/* PCI device information */
	struct {
		uint16_t pci_vendor_id;
		uint16_t pci_device_id;
		uint16_t pci_sub_vendor_id;
		uint16_t pci_sub_device_id;
		uint8_t pci_reserved[24];
	} ci_pci;

	/* Host interface information */
	struct {
		uint8_t hi_PCIX:1;
		uint8_t hi_PCIE:1;
		uint8_t hi_iSCSI:1;
		uint8_t hi_SAS_3G:1;
		uint8_t hi_reserved_0:4;
		uint8_t hi_reserved_1[6];
		uint8_t hi_port_count;
		uint64_t hi_port_addr[8];
	} ci_host_interface;

	/* Target interface information */
	struct {
		uint8_t di_SPI:1;
		uint8_t di_SAS_3G:1;
		uint8_t di_SATA_1_5G:1;
		uint8_t di_SATA_3G:1;
		uint8_t di_reserved_0:4;
		uint8_t di_reserved_1[6];
		uint8_t di_port_count;
		uint64_t di_port_addr[8];
	} ci_device_interface;

	uint32_t ci_image_check_word;

	uint32_t ci_image_component_count;
	lmrc_image_comp_t ci_image_component[8];

	uint32_t ci_pending_image_component_count;
	lmrc_image_comp_t ci_pending_image_component[8];

	uint8_t ci_max_arms;
	uint8_t ci_max_spans;
	uint8_t ci_max_arrays;
	uint8_t ci_max_lds;
	char ci_product_name[80];
	char ci_serial_no[32];

	/*
	 * Hardware features
	 */
	struct {
		uint32_t hw_bbu:1;
		uint32_t hw_alarm:1;
		uint32_t hw_nvram:1;
		uint32_t hw_uart:1;
		uint32_t hw_reserved:28;
	} ci_hw_present;

	uint32_t current_fw_time;

	/* Maximum data transfer sizes */
	uint16_t ci_max_concurrent_cmds;
	uint16_t ci_max_sge_count;
	uint32_t ci_max_request_size;

	/* Logical and physical device counts */
	uint16_t ci_ld_present_count;
	uint16_t ci_ld_degraded_count;
	uint16_t ci_ld_offline_count;

	uint16_t ci_pd_present_count;
	uint16_t ci_pd_disk_present_count;
	uint16_t ci_pd_disk_pred_failure_count;
	uint16_t ci_pd_disk_failed_count;

	/* Memory size information */
	uint16_t ci_nvram_size;
	uint16_t ci_memory_size;
	uint16_t ci_flash_size;

	/* Error counters */
	uint16_t ci_mem_correctable_error_count;
	uint16_t ci_mem_uncorrectable_error_count;

	/* Cluster information */
	uint8_t ci_cluster_permitted;
	uint8_t ci_cluster_active;

	/* Additional max data transfer sizes */
	uint16_t ci_max_stripes_per_io;

	/* Controller capabilities structures */
	struct {
		uint32_t rl_raid_level_0:1;
		uint32_t rl_raid_level_1:1;
		uint32_t rl_raid_level_5:1;
		uint32_t rl_raid_level_1E:1;
		uint32_t rl_raid_level_6:1;
		uint32_t rl_reserved:27;
	} ci_raid_levels;

	struct {
		uint32_t ao_rbld_rate:1;
		uint32_t ao_cc_rate:1;
		uint32_t ao_bgi_rate:1;
		uint32_t ao_recon_rate:1;
		uint32_t ao_patrol_rate:1;
		uint32_t ao_alarm_control:1;
		uint32_t ao_cluster_supported:1;
		uint32_t ao_bbu:1;
		uint32_t ao_spanning_allowed:1;
		uint32_t ao_dedicated_hotspares:1;
		uint32_t ao_revertible_hotspares:1;
		uint32_t ao_foreign_config_import:1;
		uint32_t ao_self_diagnostic:1;
		uint32_t ao_mixed_redundancy_arr:1;
		uint32_t ao_global_hot_spares:1;
		uint32_t ao_reserved:17;
	} ci_adapter_opts;

	struct {
		uint32_t ld_read_policy:1;
		uint32_t ld_write_policy:1;
		uint32_t ld_io_policy:1;
		uint32_t ld_access_policy:1;
		uint32_t ld_disk_cache_policy:1;
		uint32_t ld_reserved:27;
	} ci_ld_opts;

	struct {
		uint8_t raid_stripe_sz_min;
		uint8_t raid_stripe_sz_max;
		uint8_t raid_reserved[2];
	} ci_raid_opts;

	struct {
		uint32_t pd_force_online:1;
		uint32_t pd_force_offline:1;
		uint32_t pd_force_rebuild:1;
		uint32_t pd_reserved:29;
	} ci_pd_opts;

	struct {
		uint32_t pd_ctrl_supports_sas:1;
		uint32_t pd_ctrl_supports_sata:1;
		uint32_t pd_allow_mix_in_encl:1;
		uint32_t pd_allow_mix_in_ld:1;
		uint32_t pd_allow_sata_in_cluster:1;
		uint32_t pd_reserved:27;
	} ci_pd_mix_support;

	/* ECC single-bit error bucket information */
	uint8_t ci_ecc_bucket_count;
	uint8_t ci_reserved_2[11];

	/* Controller properties */
	lmrc_ctrl_prop_t ci_prop;

	char ci_package_version[0x60];

	uint64_t ci_device_interface_port_addr2[8];
	uint8_t ci_reserved3[128];

	struct {
		uint16_t pd_min_pd_raid_level_0:4;
		uint16_t pd_max_pd_raid_level_0:12;

		uint16_t pd_min_pd_raid_level_1:4;
		uint16_t pd_max_pd_raid_level_1:12;

		uint16_t pd_min_pd_raid_level_5:4;
		uint16_t pd_max_pd_raid_level_5:12;

		uint16_t pd_min_pd_raid_level_1E:4;
		uint16_t pd_max_pd_raid_level_1E:12;

		uint16_t pd_min_pd_raid_level_6:4;
		uint16_t pd_max_pd_raid_level_6:12;

		uint16_t pd_min_pd_raid_level_10:4;
		uint16_t pd_max_pd_raid_level_10:12;

		uint16_t pd_min_pd_raid_level_50:4;
		uint16_t pd_max_pd_raid_level_50:12;

		uint16_t pd_min_pd_raid_level_60:4;
		uint16_t pd_max_pd_raid_level_60:12;

		uint16_t pd_min_pd_raid_level_1E_RLQ0:4;
		uint16_t pd_max_pd_raid_level_1E_RLQ0:12;

		uint16_t pd_min_pd_raid_level_1E0_RLQ0:4;
		uint16_t pd_max_pd_raid_level_1E0_RLQ0:12;

		uint16_t pd_reserved[6];
	} ci_pds_for_raid_levels;

	uint16_t ci_max_pds;			/* 0x780 */
	uint16_t ci_max_ded_HSPs;		/* 0x782 */
	uint16_t ci_max_global_HSPs;		/* 0x784 */
	uint16_t ci_ddf_size;			/* 0x786 */
	uint8_t ci_max_lds_per_array;		/* 0x788 */
	uint8_t ci_partitions_in_DDF;		/* 0x789 */
	uint8_t ci_lock_key_binding;		/* 0x78a */
	uint8_t ci_max_PITs_per_ld;		/* 0x78b */
	uint8_t ci_max_views_per_ld;		/* 0x78c */
	uint8_t ci_max_target_id;		/* 0x78d */
	uint16_t ci_max_bvl_vd_size;		/* 0x78e */

	uint16_t ci_max_configurable_SSC_size;	/* 0x790 */
	uint16_t ci_current_SSC_size;		/* 0x792 */

	char ci_expander_fw_version[12];	/* 0x794 */

	uint16_t ci_PFK_trial_time_remaining;	/* 0x7A0 */

	uint16_t ci_cache_memory_size;		/* 0x7A2 */

	struct {				/* 0x7A4 */
		uint32_t ao2_support_PI_controller:1;
		uint32_t ao2_support_ld_PI_type1:1;
		uint32_t ao2_support_ld_PI_type2:1;
		uint32_t ao2_support_ld_PI_type3:1;
		uint32_t ao2_support_ld_BBM_info:1;
		uint32_t ao2_support_shield_state:1;
		uint32_t ao2_block_SSD_write_cache_change:1;
		uint32_t ao2_support_suspend_resume_b_Gops:1;
		uint32_t ao2_support_emergency_spares:1;
		uint32_t ao2_support_set_link_speed:1;
		uint32_t ao2_support_boot_time_PFK_change:1;
		uint32_t ao2_support_JBOD:1;
		uint32_t ao2_disable_online_PFK_change:1;
		uint32_t ao2_support_perf_tuning:1;
		uint32_t ao2_support_SSD_patrol_read:1;
		uint32_t ao2_real_time_scheduler:1;

		uint32_t ao2_support_reset_now:1;
		uint32_t ao2_support_emulated_drives:1;
		uint32_t ao2_headless_mode:1;
		uint32_t ao2_dedicated_hot_spares_limited:1;

		uint32_t ao2_support_uneven_spans:1;
		uint32_t ao2_reserved:11;
	} ci_adapter_opts2;

	uint8_t ci_driver_version[32];		/* 0x7A8 */
	uint8_t ci_max_DAP_d_count_spinup60;	/* 0x7C8 */
	uint8_t ci_temperature_ROC;		/* 0x7C9 */
	uint8_t ci_temperature_ctrl;		/* 0x7CA */
	uint8_t ci_reserved4;			/* 0x7CB */
	uint16_t ci_max_configurable_pds;	/* 0x7CC */

	uint8_t ci_reserved5[2];		/* 0x7CD reserved */

	struct {
		uint32_t cl_peer_is_present:1;
		uint32_t cl_peer_is_incompatible:1;

		uint32_t cl_hw_incompatible:1;
		uint32_t cl_fw_version_mismatch:1;
		uint32_t cl_ctrl_prop_incompatible:1;
		uint32_t cl_premium_feature_mismatch:1;
		uint32_t cl_reserved:26;
	} ci_cluster;

	char ci_cluster_id[16];			/* 0x7D4 */

	char ci_reserved6[4];			/* 0x7E4 RESERVED FOR IOV */

	struct {				/* 0x7E8 */
		uint32_t ao3_support_personality_change:2;
		uint32_t ao3_support_thermal_poll_interval:1;
		uint32_t ao3_support_disable_immediate_IO:1;
		uint32_t ao3_support_T10_rebuild_assist:1;
		uint32_t ao3_support_max_ext_lds:1;
		uint32_t ao3_support_crash_dump:1;
		uint32_t ao3_support_sw_zone:1;
		uint32_t ao3_support_debug_queue:1;
		uint32_t ao3_support_NV_cache_erase:1;
		uint32_t ao3_support_force_to_512e:1;
		uint32_t ao3_support_HOQ_rebuild:1;
		uint32_t ao3_support_allowed_opsfor_drv_removal:1;
		uint32_t ao3_support_drv_activity_LED_setting:1;
		uint32_t ao3_support_NVDRAM:1;
		uint32_t ao3_support_force_flash:1;
		uint32_t ao3_support_disable_SES_monitoring:1;
		uint32_t ao3_support_cache_bypass_modes:1;
		uint32_t ao3_support_securityon_JBOD:1;
		uint32_t ao3_discard_cache_during_ld_delete:1;
		uint32_t ao3_support_TTY_log_compression:1;
		uint32_t ao3_support_CPLD_update:1;
		uint32_t ao3_support_disk_cache_setting_for_sys_pds:1;
		uint32_t ao3_support_extended_SSC_size:1;
		uint32_t ao3_use_seq_num_jbod_FP:1;
		uint32_t ao3_reserved:7;
	} ci_adapter_opts3;

	uint8_t ci_pad_cpld[16];

	struct {
		uint16_t ao4_ctrl_info_ext_supported:1;
		uint16_t ao4_support_ibutton_less:1;
		uint16_t ao4_supported_enc_algo:1;
		uint16_t ao4_support_encrypted_mfc:1;
		uint16_t ao4_image_upload_supported:1;
		uint16_t ao4_support_SES_ctrl_in_multipath_cfg:1;
		uint16_t ao4_support_pd_map_target_id:1;
		uint16_t ao4_fw_swaps_bbu_vpd_info:1;
		uint16_t ao4_reserved:8;
	} ci_adapter_opts4;

	uint8_t ci_pad[0x800 - 0x7FE];	/* 0x7FE */
};

#pragma pack(0)

/*
 * Request descriptor types, in addition to those defined by mpi2.h
 *
 * FreeBSD and Linux drivers shift these, while mpi2.h defines them
 * pre-shifted. The latter seems more sensible.
 *
 * XXX: LMRC_REQ_DESCRIPT_FLAGS_MFA has the same value as
 * MPI2_REQ_DESCRIPT_FLAGS_SCSI_TARGET. Why?
 */
#define	LMRC_REQ_DESCRIPT_FLAGS_MFA		0x02
#define	LMRC_REQ_DESCRIPT_FLAGS_NO_LOCK		0x04
#define	LMRC_REQ_DESCRIPT_FLAGS_LD_IO		0x0e

#define	MPI2_TYPE_CUDA				0x2

#endif /* _LMRC_REG_H */
