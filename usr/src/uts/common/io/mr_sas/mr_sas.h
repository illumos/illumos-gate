/*
 * mr_sas.h: header for mr_sas
 *
 * Solaris MegaRAID driver for SAS2.0 controllers
 * Copyright (c) 2008-2012, LSI Logic Corporation.
 * All rights reserved.
 *
 * Version:
 * Author:
 *		Swaminathan K S
 *		Arun Chandrashekhar
 *		Manju R
 *		Rasheed
 *		Shakeel Bukhari
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 * Copyright 2017 Citrus IT Limited. All rights reserved.
 */

#ifndef	_MR_SAS_H_
#define	_MR_SAS_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/scsi.h>
#include "mr_sas_list.h"
#include "ld_pd_map.h"

/*
 * MegaRAID SAS2.0 Driver meta data
 */
#define	MRSAS_VERSION				"6.503.00.00ILLUMOS-20170421"
#define	MRSAS_RELDATE				"April 21, 2017"

#define	MRSAS_TRUE				1
#define	MRSAS_FALSE				0

#define	ADAPTER_RESET_NOT_REQUIRED		0
#define	ADAPTER_RESET_REQUIRED			1

#define	PDSUPPORT	1

/*
 * MegaRAID SAS2.0 device id conversion definitions.
 */
#define	INST2LSIRDCTL(x)		((x) << INST_MINOR_SHIFT)
#define	MRSAS_GET_BOUNDARY_ALIGNED_LEN(len, new_len, boundary_len)  { \
	int rem; \
	rem = (len / boundary_len); \
	if ((rem * boundary_len) != len) { \
		new_len = len + ((rem + 1) * boundary_len - len); \
	} else { \
		new_len = len; \
	} \
}


/*
 * MegaRAID SAS2.0 supported controllers
 */

/* Skinny */
#define	PCI_DEVICE_ID_LSI_SKINNY		0x0071
#define	PCI_DEVICE_ID_LSI_SKINNY_NEW		0x0073
/* Liberator series (Gen2) */
#define	PCI_DEVICE_ID_LSI_2108VDE		0x0078
#define	PCI_DEVICE_ID_LSI_2108V			0x0079
/* Thunderbolt series */
#define	PCI_DEVICE_ID_LSI_TBOLT			0x005b
/* Invader series (Gen3) */
#define	PCI_DEVICE_ID_LSI_INVADER		0x005d
#define	PCI_DEVICE_ID_LSI_FURY			0x005f
#define	PCI_DEVICE_ID_LSI_INTRUDER		0x00ce
#define	PCI_DEVICE_ID_LSI_INTRUDER_24		0x00cf
#define	PCI_DEVICE_ID_LSI_CUTLASS_52		0x0052
#define	PCI_DEVICE_ID_LSI_CUTLASS_53		0x0053
/* Ventura series not yet supported */

/*
 * Register Index for 2108 Controllers.
 */
#define	REGISTER_SET_IO_2108			(2)

#define	MRSAS_MAX_SGE_CNT			0x50
#define	MRSAS_APP_RESERVED_CMDS			32
#define	MRSAS_APP_MIN_RESERVED_CMDS		4

#define	MRSAS_IOCTL_DRIVER			0x12341234
#define	MRSAS_IOCTL_FIRMWARE			0x12345678
#define	MRSAS_IOCTL_AEN				0x87654321

#define	MRSAS_1_SECOND				1000000

#ifdef PDSUPPORT

#define	UNCONFIGURED_GOOD			0x0
#define	PD_SYSTEM				0x40
#define	MR_EVT_PD_STATE_CHANGE			0x0072
#define	MR_EVT_PD_REMOVED_EXT		0x00f8
#define	MR_EVT_PD_INSERTED_EXT		0x00f7
#define	MR_DCMD_PD_GET_INFO			0x02020000
#define	MRSAS_TBOLT_PD_LUN		1
#define	MRSAS_TBOLT_PD_TGT_MAX	255
#define	MRSAS_TBOLT_GET_PD_MAX(s)	((s)->mr_tbolt_pd_max)

#endif

/* Raid Context Flags */
#define	MR_RAID_CTX_RAID_FLAGS_IO_SUB_TYPE_SHIFT 0x4
#define	MR_RAID_CTX_RAID_FLAGS_IO_SUB_TYPE_MASK 0x30
typedef enum MR_RAID_FLAGS_IO_SUB_TYPE {
	MR_RAID_FLAGS_IO_SUB_TYPE_NONE = 0,
	MR_RAID_FLAGS_IO_SUB_TYPE_SYSTEM_PD = 1
} MR_RAID_FLAGS_IO_SUB_TYPE;

/* Dynamic Enumeration Flags */
#define	MRSAS_LD_LUN		0
#define	WWN_STRLEN		17
#define	LD_SYNC_BIT	1
#define	LD_SYNC_SHIFT	14
/* ThunderBolt (TB) specific */
#define	MRSAS_THUNDERBOLT_MSG_SIZE		256
#define	MRSAS_THUNDERBOLT_MAX_COMMANDS		1024
#define	MRSAS_THUNDERBOLT_MAX_REPLY_COUNT	1024
#define	MRSAS_THUNDERBOLT_REPLY_SIZE		8
#define	MRSAS_THUNDERBOLT_MAX_CHAIN_COUNT	1

#define	MPI2_FUNCTION_PASSTHRU_IO_REQUEST	0xF0
#define	MPI2_FUNCTION_LD_IO_REQUEST		0xF1

#define	MR_EVT_LD_FAST_PATH_IO_STATUS_CHANGED	(0xFFFF)

#define	MR_INTERNAL_MFI_FRAMES_SMID		1
#define	MR_CTRL_EVENT_WAIT_SMID			2
#define	MR_INTERNAL_DRIVER_RESET_SMID		3


/*
 * =====================================
 * MegaRAID SAS2.0 MFI firmware definitions
 * =====================================
 */
/*
 * MFI stands for  MegaRAID SAS2.0 FW Interface. This is just a moniker for
 * protocol between the software and firmware. Commands are issued using
 * "message frames"
 */

/*
 * FW posts its state in upper 4 bits of outbound_msg_0 register
 */
#define	MFI_STATE_MASK				0xF0000000
#define	MFI_STATE_UNDEFINED			0x00000000
#define	MFI_STATE_BB_INIT			0x10000000
#define	MFI_STATE_FW_INIT			0x40000000
#define	MFI_STATE_WAIT_HANDSHAKE		0x60000000
#define	MFI_STATE_FW_INIT_2			0x70000000
#define	MFI_STATE_DEVICE_SCAN			0x80000000
#define	MFI_STATE_BOOT_MESSAGE_PENDING		0x90000000
#define	MFI_STATE_FLUSH_CACHE			0xA0000000
#define	MFI_STATE_READY				0xB0000000
#define	MFI_STATE_OPERATIONAL			0xC0000000
#define	MFI_STATE_FAULT				0xF0000000

#define	MRMFI_FRAME_SIZE			64

/*
 * During FW init, clear pending cmds & reset state using inbound_msg_0
 *
 * ABORT	: Abort all pending cmds
 * READY	: Move from OPERATIONAL to READY state; discard queue info
 * MFIMODE	: Discard (possible) low MFA posted in 64-bit mode (??)
 * CLR_HANDSHAKE: FW is waiting for HANDSHAKE from BIOS or Driver
 */
#define	MFI_INIT_ABORT				0x00000001
#define	MFI_INIT_READY				0x00000002
#define	MFI_INIT_MFIMODE			0x00000004
#define	MFI_INIT_CLEAR_HANDSHAKE		0x00000008
#define	MFI_INIT_HOTPLUG			0x00000010
#define	MFI_STOP_ADP				0x00000020
#define	MFI_RESET_FLAGS		MFI_INIT_READY|MFI_INIT_MFIMODE|MFI_INIT_ABORT

/*
 * MFI frame flags
 */
#define	MFI_FRAME_POST_IN_REPLY_QUEUE		0x0000
#define	MFI_FRAME_DONT_POST_IN_REPLY_QUEUE	0x0001
#define	MFI_FRAME_SGL32				0x0000
#define	MFI_FRAME_SGL64				0x0002
#define	MFI_FRAME_SENSE32			0x0000
#define	MFI_FRAME_SENSE64			0x0004
#define	MFI_FRAME_DIR_NONE			0x0000
#define	MFI_FRAME_DIR_WRITE			0x0008
#define	MFI_FRAME_DIR_READ			0x0010
#define	MFI_FRAME_DIR_BOTH			0x0018
#define	MFI_FRAME_IEEE				0x0020

/*
 * Definition for cmd_status
 */
#define	MFI_CMD_STATUS_POLL_MODE		0xFF
#define	MFI_CMD_STATUS_SYNC_MODE		0xFF

/*
 * MFI command opcodes
 */
#define	MFI_CMD_OP_INIT				0x00
#define	MFI_CMD_OP_LD_READ			0x01
#define	MFI_CMD_OP_LD_WRITE			0x02
#define	MFI_CMD_OP_LD_SCSI			0x03
#define	MFI_CMD_OP_PD_SCSI			0x04
#define	MFI_CMD_OP_DCMD				0x05
#define	MFI_CMD_OP_ABORT			0x06
#define	MFI_CMD_OP_SMP				0x07
#define	MFI_CMD_OP_STP				0x08

#define	MR_DCMD_CTRL_GET_INFO			0x01010000

#define	MR_DCMD_CTRL_CACHE_FLUSH		0x01101000
#define	MR_FLUSH_CTRL_CACHE			0x01
#define	MR_FLUSH_DISK_CACHE			0x02

#define	MR_DCMD_CTRL_SHUTDOWN			0x01050000
#define	MRSAS_ENABLE_DRIVE_SPINDOWN		0x01

#define	MR_DCMD_CTRL_EVENT_GET_INFO		0x01040100
#define	MR_DCMD_CTRL_EVENT_GET			0x01040300
#define	MR_DCMD_CTRL_EVENT_WAIT			0x01040500
#define	MR_DCMD_LD_GET_PROPERTIES		0x03030000

/*
 * Solaris Specific MAX values
 */
#define	MAX_SGL					24

/*
 * MFI command completion codes
 */
enum MFI_STAT {
	MFI_STAT_OK				= 0x00,
	MFI_STAT_INVALID_CMD			= 0x01,
	MFI_STAT_INVALID_DCMD			= 0x02,
	MFI_STAT_INVALID_PARAMETER		= 0x03,
	MFI_STAT_INVALID_SEQUENCE_NUMBER	= 0x04,
	MFI_STAT_ABORT_NOT_POSSIBLE		= 0x05,
	MFI_STAT_APP_HOST_CODE_NOT_FOUND	= 0x06,
	MFI_STAT_APP_IN_USE			= 0x07,
	MFI_STAT_APP_NOT_INITIALIZED		= 0x08,
	MFI_STAT_ARRAY_INDEX_INVALID		= 0x09,
	MFI_STAT_ARRAY_ROW_NOT_EMPTY		= 0x0a,
	MFI_STAT_CONFIG_RESOURCE_CONFLICT	= 0x0b,
	MFI_STAT_DEVICE_NOT_FOUND		= 0x0c,
	MFI_STAT_DRIVE_TOO_SMALL		= 0x0d,
	MFI_STAT_FLASH_ALLOC_FAIL		= 0x0e,
	MFI_STAT_FLASH_BUSY			= 0x0f,
	MFI_STAT_FLASH_ERROR			= 0x10,
	MFI_STAT_FLASH_IMAGE_BAD		= 0x11,
	MFI_STAT_FLASH_IMAGE_INCOMPLETE		= 0x12,
	MFI_STAT_FLASH_NOT_OPEN			= 0x13,
	MFI_STAT_FLASH_NOT_STARTED		= 0x14,
	MFI_STAT_FLUSH_FAILED			= 0x15,
	MFI_STAT_HOST_CODE_NOT_FOUNT		= 0x16,
	MFI_STAT_LD_CC_IN_PROGRESS		= 0x17,
	MFI_STAT_LD_INIT_IN_PROGRESS		= 0x18,
	MFI_STAT_LD_LBA_OUT_OF_RANGE		= 0x19,
	MFI_STAT_LD_MAX_CONFIGURED		= 0x1a,
	MFI_STAT_LD_NOT_OPTIMAL			= 0x1b,
	MFI_STAT_LD_RBLD_IN_PROGRESS		= 0x1c,
	MFI_STAT_LD_RECON_IN_PROGRESS		= 0x1d,
	MFI_STAT_LD_WRONG_RAID_LEVEL		= 0x1e,
	MFI_STAT_MAX_SPARES_EXCEEDED		= 0x1f,
	MFI_STAT_MEMORY_NOT_AVAILABLE		= 0x20,
	MFI_STAT_MFC_HW_ERROR			= 0x21,
	MFI_STAT_NO_HW_PRESENT			= 0x22,
	MFI_STAT_NOT_FOUND			= 0x23,
	MFI_STAT_NOT_IN_ENCL			= 0x24,
	MFI_STAT_PD_CLEAR_IN_PROGRESS		= 0x25,
	MFI_STAT_PD_TYPE_WRONG			= 0x26,
	MFI_STAT_PR_DISABLED			= 0x27,
	MFI_STAT_ROW_INDEX_INVALID		= 0x28,
	MFI_STAT_SAS_CONFIG_INVALID_ACTION	= 0x29,
	MFI_STAT_SAS_CONFIG_INVALID_DATA	= 0x2a,
	MFI_STAT_SAS_CONFIG_INVALID_PAGE	= 0x2b,
	MFI_STAT_SAS_CONFIG_INVALID_TYPE	= 0x2c,
	MFI_STAT_SCSI_DONE_WITH_ERROR		= 0x2d,
	MFI_STAT_SCSI_IO_FAILED			= 0x2e,
	MFI_STAT_SCSI_RESERVATION_CONFLICT	= 0x2f,
	MFI_STAT_SHUTDOWN_FAILED		= 0x30,
	MFI_STAT_TIME_NOT_SET			= 0x31,
	MFI_STAT_WRONG_STATE			= 0x32,
	MFI_STAT_LD_OFFLINE			= 0x33,
	MFI_STAT_INVALID_STATUS			= 0xFF
};

enum MR_EVT_CLASS {
	MR_EVT_CLASS_DEBUG		= -2,
	MR_EVT_CLASS_PROGRESS		= -1,
	MR_EVT_CLASS_INFO		=  0,
	MR_EVT_CLASS_WARNING		=  1,
	MR_EVT_CLASS_CRITICAL		=  2,
	MR_EVT_CLASS_FATAL		=  3,
	MR_EVT_CLASS_DEAD		=  4
};

enum MR_EVT_LOCALE {
	MR_EVT_LOCALE_LD		= 0x0001,
	MR_EVT_LOCALE_PD		= 0x0002,
	MR_EVT_LOCALE_ENCL		= 0x0004,
	MR_EVT_LOCALE_BBU		= 0x0008,
	MR_EVT_LOCALE_SAS		= 0x0010,
	MR_EVT_LOCALE_CTRL		= 0x0020,
	MR_EVT_LOCALE_CONFIG		= 0x0040,
	MR_EVT_LOCALE_CLUSTER		= 0x0080,
	MR_EVT_LOCALE_ALL		= 0xffff
};

enum MR_EVT_ARGS {
	MR_EVT_ARGS_NONE,
	MR_EVT_ARGS_CDB_SENSE,
	MR_EVT_ARGS_LD,
	MR_EVT_ARGS_LD_COUNT,
	MR_EVT_ARGS_LD_LBA,
	MR_EVT_ARGS_LD_OWNER,
	MR_EVT_ARGS_LD_LBA_PD_LBA,
	MR_EVT_ARGS_LD_PROG,
	MR_EVT_ARGS_LD_STATE,
	MR_EVT_ARGS_LD_STRIP,
	MR_EVT_ARGS_PD,
	MR_EVT_ARGS_PD_ERR,
	MR_EVT_ARGS_PD_LBA,
	MR_EVT_ARGS_PD_LBA_LD,
	MR_EVT_ARGS_PD_PROG,
	MR_EVT_ARGS_PD_STATE,
	MR_EVT_ARGS_PCI,
	MR_EVT_ARGS_RATE,
	MR_EVT_ARGS_STR,
	MR_EVT_ARGS_TIME,
	MR_EVT_ARGS_ECC
};

#define	MR_EVT_CFG_CLEARED		0x0004
#define	MR_EVT_LD_CREATED		0x008a
#define	MR_EVT_LD_DELETED		0x008b
#define	MR_EVT_CFG_FP_CHANGE		0x017B

enum LD_STATE {
	LD_OFFLINE		= 0,
	LD_PARTIALLY_DEGRADED	= 1,
	LD_DEGRADED		= 2,
	LD_OPTIMAL		= 3,
	LD_INVALID		= 0xFF
};

enum MRSAS_EVT {
	MRSAS_EVT_CONFIG_TGT	= 0,
	MRSAS_EVT_UNCONFIG_TGT	= 1,
	MRSAS_EVT_UNCONFIG_SMP	= 2
};

#define	DMA_OBJ_ALLOCATED	1
#define	DMA_OBJ_REALLOCATED	2
#define	DMA_OBJ_FREED		3

/*
 * dma_obj_t	- Our DMA object
 * @param buffer	: kernel virtual address
 * @param size		: size of the data to be allocated
 * @param acc_handle	: access handle
 * @param dma_handle	: dma handle
 * @param dma_cookie	: scatter-gather list
 * @param dma_attr	: dma attributes for this buffer
 *
 * Our DMA object. The caller must initialize the size and dma attributes
 * (dma_attr) fields before allocating the resources.
 */
typedef struct {
	caddr_t			buffer;
	uint32_t		size;
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
	ddi_dma_cookie_t	dma_cookie[MRSAS_MAX_SGE_CNT];
	ddi_dma_attr_t		dma_attr;
	uint8_t			status;
	uint8_t			reserved[3];
} dma_obj_t;

struct mrsas_eventinfo {
	struct mrsas_instance	*instance;
	int 			tgt;
	int 			lun;
	int 			event;
	uint64_t		wwn;
};

struct mrsas_ld {
	dev_info_t		*dip;
	uint8_t 		lun_type;
	uint8_t			flag;
	uint8_t 		reserved[2];
};


#ifdef PDSUPPORT
struct mrsas_tbolt_pd {
	dev_info_t		*dip;
	uint8_t 		lun_type;
	uint8_t 		dev_id;
	uint8_t 		flag;
	uint8_t 		reserved;
};
struct mrsas_tbolt_pd_info {
	uint16_t	deviceId;
	uint16_t	seqNum;
	uint8_t		inquiryData[96];
	uint8_t		vpdPage83[64];
	uint8_t		notSupported;
	uint8_t		scsiDevType;
	uint8_t		a;
	uint8_t		device_speed;
	uint32_t	mediaerrcnt;
	uint32_t	other;
	uint32_t	pred;
	uint32_t	lastpred;
	uint16_t	fwState;
	uint8_t		disabled;
	uint8_t		linkspwwd;
	uint32_t	ddfType;
	struct {
		uint8_t	count;
		uint8_t	isPathBroken;
		uint8_t	connectorIndex[2];
		uint8_t	reserved[4];
		uint64_t sasAddr[2];
		uint8_t	reserved2[16];
	} pathInfo;
};
#endif

typedef struct mrsas_instance {
	uint32_t	*producer;
	uint32_t	*consumer;

	uint32_t	*reply_queue;
	dma_obj_t	mfi_internal_dma_obj;
	uint16_t	adapterresetinprogress;
	uint16_t	deadadapter;
	/* ThunderBolt (TB) specific */
	dma_obj_t	mpi2_frame_pool_dma_obj;
	dma_obj_t	request_desc_dma_obj;
	dma_obj_t	reply_desc_dma_obj;
	dma_obj_t	ld_map_obj[2];

	uint8_t		init_id;
	uint8_t		flag_ieee;
	uint8_t		disable_online_ctrl_reset;
	uint8_t		fw_fault_count_after_ocr;

	uint16_t	max_num_sge;
	uint16_t	max_fw_cmds;
	uint32_t	max_sectors_per_req;

	struct mrsas_cmd **cmd_list;

	mlist_t		cmd_pool_list;
	kmutex_t	cmd_pool_mtx;
	kmutex_t	sync_map_mtx;

	mlist_t		app_cmd_pool_list;
	kmutex_t	app_cmd_pool_mtx;
	mlist_t		cmd_app_pool_list;
	kmutex_t	cmd_app_pool_mtx;


	mlist_t		cmd_pend_list;
	kmutex_t	cmd_pend_mtx;

	dma_obj_t	mfi_evt_detail_obj;
	struct mrsas_cmd *aen_cmd;

	uint32_t	aen_seq_num;
	uint32_t	aen_class_locale_word;

	scsi_hba_tran_t		*tran;

	kcondvar_t	int_cmd_cv;
	kmutex_t	int_cmd_mtx;

	kcondvar_t	aen_cmd_cv;
	kmutex_t	aen_cmd_mtx;

	kcondvar_t	abort_cmd_cv;
	kmutex_t	abort_cmd_mtx;

	kmutex_t	reg_write_mtx;
	kmutex_t	chip_mtx;

	dev_info_t		*dip;
	ddi_acc_handle_t	pci_handle;

	timeout_id_t	timeout_id;
	uint32_t	unique_id;
	uint16_t	fw_outstanding;
	caddr_t		regmap;
	ddi_acc_handle_t	regmap_handle;
	uint8_t		isr_level;
	ddi_iblock_cookie_t	iblock_cookie;
	ddi_iblock_cookie_t	soft_iblock_cookie;
	ddi_softintr_t		soft_intr_id;
	uint8_t		softint_running;
	uint8_t		tbolt_softint_running;
	kmutex_t	completed_pool_mtx;
	mlist_t		completed_pool_list;

	caddr_t		internal_buf;
	uint32_t	internal_buf_dmac_add;
	uint32_t	internal_buf_size;

	uint16_t	vendor_id;
	uint16_t	device_id;
	uint16_t	subsysvid;
	uint16_t	subsysid;
	int		instance;
	int		baseaddress;
	char		iocnode[16];

	int		fm_capabilities;
	/*
	 * Driver resources unroll flags.  The flag is set for resources that
	 * are needed to be free'd at detach() time.
	 */
	struct _unroll {
		uint8_t softs;		/* The software state was allocated. */
		uint8_t regs;		/* Controller registers mapped. */
		uint8_t intr;		/* Interrupt handler added. */
		uint8_t reqs;		/* Request structs allocated. */
		uint8_t mutexs;		/* Mutex's allocated. */
		uint8_t taskq;		/* Task q's created. */
		uint8_t tran;		/* Tran struct allocated */
		uint8_t tranSetup;	/* Tran attached to the ddi. */
		uint8_t devctl;		/* Device nodes for cfgadm created. */
		uint8_t scsictl;	/* Device nodes for cfgadm created. */
		uint8_t ioctl;		/* Device nodes for ioctl's created. */
		uint8_t timer;		/* Timer started. */
		uint8_t aenPend;	/* AEN cmd pending f/w. */
		uint8_t mapUpdate_pend; /* LD MAP update cmd pending f/w. */
		uint8_t soft_isr;	/* Soft interrupt handler allocated. */
		uint8_t ldlist_buff;	/* Logical disk list allocated. */
		uint8_t pdlist_buff;	/* Physical disk list allocated. */
		uint8_t syncCmd;	/* Sync map command allocated. */
		uint8_t verBuff;	/* 2108 MFI buffer allocated. */
		uint8_t alloc_space_mfi;  /* Allocated space for 2108 MFI. */
		uint8_t alloc_space_mpi2; /* Allocated space for 2208 MPI2. */
	} unroll;


	/* function template pointer */
	struct mrsas_function_template *func_ptr;


	/* MSI interrupts specific */
	ddi_intr_handle_t *intr_htable;		/* Interrupt handle array */
	size_t		intr_htable_size;	/* Int. handle array size */
	int		intr_type;
	int		intr_cnt;
	uint_t		intr_pri;
	int		intr_cap;

	ddi_taskq_t	*taskq;
	struct mrsas_ld	*mr_ld_list;
	kmutex_t	config_dev_mtx;
	/* ThunderBolt (TB) specific */
	ddi_softintr_t	tbolt_soft_intr_id;

#ifdef PDSUPPORT
	uint32_t	mr_tbolt_pd_max;
	struct mrsas_tbolt_pd *mr_tbolt_pd_list;
#endif

	uint8_t		fast_path_io;

	uint8_t		skinny;
	uint8_t		tbolt;
	uint8_t		gen3;
	uint16_t	reply_read_index;
	uint16_t	reply_size; 		/* Single Reply struct size */
	uint16_t	raid_io_msg_size; 	/* Single message size */
	uint32_t	io_request_frames_phy;
	uint8_t 	*io_request_frames;
	/* Virtual address of request desc frame pool */
	MRSAS_REQUEST_DESCRIPTOR_UNION	*request_message_pool;
	/* Physical address of request desc frame pool */
	uint32_t	request_message_pool_phy;
	/* Virtual address of reply Frame */
	MPI2_REPLY_DESCRIPTORS_UNION	*reply_frame_pool;
	/* Physical address of reply Frame */
	uint32_t	reply_frame_pool_phy;
	uint8_t		*reply_pool_limit;	/* Last reply frame address */
	/* Physical address of Last reply frame */
	uint32_t	reply_pool_limit_phy;
	uint32_t	reply_q_depth;		/* Reply Queue Depth */
	uint8_t		max_sge_in_main_msg;
	uint8_t		max_sge_in_chain;
	uint8_t    	chain_offset_io_req;
	uint8_t		chain_offset_mpt_msg;
	MR_FW_RAID_MAP_ALL *ld_map[2];
	uint32_t 	ld_map_phy[2];
	uint32_t	size_map_info;
	uint64_t 	map_id;
	LD_LOAD_BALANCE_INFO load_balance_info[MAX_LOGICAL_DRIVES];
	struct mrsas_cmd *map_update_cmd;
	uint32_t	SyncRequired;
	kmutex_t	ocr_flags_mtx;
	dma_obj_t	drv_ver_dma_obj;
} mrsas_t;


/*
 * Function templates for various controller specific functions
 */
struct mrsas_function_template {
	uint32_t (*read_fw_status_reg)(struct mrsas_instance *);
	void (*issue_cmd)(struct mrsas_cmd *, struct mrsas_instance *);
	int (*issue_cmd_in_sync_mode)(struct mrsas_instance *,
	    struct mrsas_cmd *);
	int (*issue_cmd_in_poll_mode)(struct mrsas_instance *,
	    struct mrsas_cmd *);
	void (*enable_intr)(struct mrsas_instance *);
	void (*disable_intr)(struct mrsas_instance *);
	int (*intr_ack)(struct mrsas_instance *);
	int (*init_adapter)(struct mrsas_instance *);
/*	int (*reset_adapter)(struct mrsas_instance *); */
};

/*
 * ### Helper routines ###
 */

/*
 * con_log() - console log routine
 * @param level		: indicates the severity of the message.
 * @fparam mt		: format string
 *
 * con_log displays the error messages on the console based on the current
 * debug level. Also it attaches the appropriate kernel severity level with
 * the message.
 *
 *
 * console messages debug levels
 */
#define	CL_NONE		0	/* No debug information */
#define	CL_ANN		1	/* print unconditionally, announcements */
#define	CL_ANN1		2	/* No-op  */
#define	CL_DLEVEL1	3	/* debug level 1, informative */
#define	CL_DLEVEL2	4	/* debug level 2, verbose */
#define	CL_DLEVEL3	5	/* debug level 3, very verbose */

#ifdef __SUNPRO_C
#define	__func__ ""
#endif

#define	con_log(level, fmt) { if (debug_level_g >= level) cmn_err fmt; }

/*
 * ### SCSA definitions ###
 */
#define	PKT2TGT(pkt)	((pkt)->pkt_address.a_target)
#define	PKT2LUN(pkt)	((pkt)->pkt_address.a_lun)
#define	PKT2TRAN(pkt)	((pkt)->pkt_adress.a_hba_tran)
#define	ADDR2TRAN(ap)	((ap)->a_hba_tran)

#define	TRAN2MR(tran)	(struct mrsas_instance *)(tran)->tran_hba_private)
#define	ADDR2MR(ap)	(TRAN2MR(ADDR2TRAN(ap))

#define	PKT2CMD(pkt)	((struct scsa_cmd *)(pkt)->pkt_ha_private)
#define	CMD2PKT(sp)	((sp)->cmd_pkt)
#define	PKT2REQ(pkt)	(&(PKT2CMD(pkt)->request))

#define	CMD2ADDR(cmd)	(&CMD2PKT(cmd)->pkt_address)
#define	CMD2TRAN(cmd)	(CMD2PKT(cmd)->pkt_address.a_hba_tran)
#define	CMD2MR(cmd)	(TRAN2MR(CMD2TRAN(cmd)))

#define	CFLAG_DMAVALID		0x0001	/* requires a dma operation */
#define	CFLAG_DMASEND		0x0002	/* Transfer from the device */
#define	CFLAG_CONSISTENT	0x0040	/* consistent data transfer */

/*
 * ### Data structures for ioctl inteface and internal commands ###
 */

/*
 * Data direction flags
 */
#define	UIOC_RD		0x00001
#define	UIOC_WR		0x00002

#define	SCP2HOST(scp)		(scp)->device->host	/* to host */
#define	SCP2HOSTDATA(scp)	SCP2HOST(scp)->hostdata	/* to soft state */
#define	SCP2CHANNEL(scp)	(scp)->device->channel	/* to channel */
#define	SCP2TARGET(scp)		(scp)->device->id	/* to target */
#define	SCP2LUN(scp)		(scp)->device->lun	/* to LUN */

#define	SCSIHOST2ADAP(host)	(((caddr_t *)(host->hostdata))[0])
#define	SCP2ADAPTER(scp)				\
	(struct mrsas_instance *)SCSIHOST2ADAP(SCP2HOST(scp))

#define	MRDRV_IS_LOGICAL_SCSA(instance, acmd)		\
	(acmd->device_id < MRDRV_MAX_LD) ? 1 : 0
#define	MRDRV_IS_LOGICAL(ap)				\
	((ap->a_target < MRDRV_MAX_LD) && (ap->a_lun == 0)) ? 1 : 0
#define	MAP_DEVICE_ID(instance, ap)			\
	(ap->a_target)

#define	HIGH_LEVEL_INTR			1
#define	NORMAL_LEVEL_INTR		0

#define		IO_TIMEOUT_VAL		0
#define		IO_RETRY_COUNT		3
#define		MAX_FW_RESET_COUNT	3
/*
 * scsa_cmd  - Per-command mr private data
 * @param cmd_dmahandle		:  dma handle
 * @param cmd_dmacookies	:  current dma cookies
 * @param cmd_pkt		:  scsi_pkt reference
 * @param cmd_dmacount		:  dma count
 * @param cmd_cookie		:  next cookie
 * @param cmd_ncookies		:  cookies per window
 * @param cmd_cookiecnt		:  cookies per sub-win
 * @param cmd_nwin		:  number of dma windows
 * @param cmd_curwin		:  current dma window
 * @param cmd_dma_offset	:  current window offset
 * @param cmd_dma_len		:  current window length
 * @param cmd_flags		:  private flags
 * @param cmd_cdblen		:  length of cdb
 * @param cmd_scblen		:  length of scb
 * @param cmd_buf		:  command buffer
 * @param channel		:  channel for scsi sub-system
 * @param target		:  target for scsi sub-system
 * @param lun			:  LUN for scsi sub-system
 *
 * - Allocated at same time as scsi_pkt by scsi_hba_pkt_alloc(9E)
 * - Pointed to by pkt_ha_private field in scsi_pkt
 */
struct scsa_cmd {
	ddi_dma_handle_t	cmd_dmahandle;
	ddi_dma_cookie_t	cmd_dmacookies[MRSAS_MAX_SGE_CNT];
	struct scsi_pkt		*cmd_pkt;
	ulong_t			cmd_dmacount;
	uint_t			cmd_cookie;
	uint_t			cmd_ncookies;
	uint_t			cmd_cookiecnt;
	uint_t			cmd_nwin;
	uint_t			cmd_curwin;
	off_t			cmd_dma_offset;
	ulong_t			cmd_dma_len;
	ulong_t			cmd_flags;
	uint_t			cmd_cdblen;
	uint_t			cmd_scblen;
	struct buf		*cmd_buf;
	ushort_t		device_id;
	uchar_t			islogical;
	uchar_t			lun;
	struct mrsas_device	*mrsas_dev;
};


struct mrsas_cmd {
	/*
	 * ThunderBolt(TB) We would be needing to have a placeholder
	 * for RAID_MSG_IO_REQUEST inside this structure. We are
	 * supposed to embed the mr_frame inside the RAID_MSG and post
	 * it down to the firmware.
	 */
	union mrsas_frame	*frame;
	uint32_t		frame_phys_addr;
	uint8_t			*sense;
	uint8_t			*sense1;
	uint32_t		sense_phys_addr;
	uint32_t		sense_phys_addr1;
	dma_obj_t		frame_dma_obj;
	uint8_t			frame_dma_obj_status;
	uint32_t		index;
	uint8_t			sync_cmd;
	uint8_t			cmd_status;
	uint16_t		abort_aen;
	mlist_t			list;
	uint32_t		frame_count;
	struct scsa_cmd		*cmd;
	struct scsi_pkt		*pkt;
	Mpi2RaidSCSIIORequest_t *scsi_io_request;
	Mpi2SGEIOUnion_t	*sgl;
	uint32_t		sgl_phys_addr;
	uint32_t		scsi_io_request_phys_addr;
	MRSAS_REQUEST_DESCRIPTOR_UNION	*request_desc;
	uint16_t		SMID;
	uint16_t		retry_count_for_ocr;
	uint16_t		drv_pkt_time;
	uint16_t		load_balance_flag;

};

#define	MAX_MGMT_ADAPTERS			1024
#define	IOC_SIGNATURE				"MR-SAS"

#define	IOC_CMD_FIRMWARE			0x0
#define	MRSAS_DRIVER_IOCTL_COMMON		0xF0010000
#define	MRSAS_DRIVER_IOCTL_DRIVER_VERSION	0xF0010100
#define	MRSAS_DRIVER_IOCTL_PCI_INFORMATION	0xF0010200
#define	MRSAS_DRIVER_IOCTL_MRRAID_STATISTICS	0xF0010300


#define	MRSAS_MAX_SENSE_LENGTH			32

struct mrsas_mgmt_info {

	uint16_t			count;
	struct mrsas_instance		*instance[MAX_MGMT_ADAPTERS];
	uint16_t			map[MAX_MGMT_ADAPTERS];
	int				max_index;
};


#pragma pack(1)
/*
 * SAS controller properties
 */
struct mrsas_ctrl_prop {
	uint16_t	seq_num;
	uint16_t	pred_fail_poll_interval;
	uint16_t	intr_throttle_count;
	uint16_t	intr_throttle_timeouts;

	uint8_t		rebuild_rate;
	uint8_t		patrol_read_rate;
	uint8_t		bgi_rate;
	uint8_t		cc_rate;
	uint8_t		recon_rate;

	uint8_t		cache_flush_interval;

	uint8_t		spinup_drv_count;
	uint8_t		spinup_delay;

	uint8_t		cluster_enable;
	uint8_t		coercion_mode;
	uint8_t		alarm_enable;

	uint8_t		reserved_1[13];
	uint32_t	on_off_properties;
	uint8_t		reserved_4[28];
};


/*
 * SAS controller information
 */
struct mrsas_ctrl_info {
	/* PCI device information */
	struct {
		uint16_t	vendor_id;
		uint16_t	device_id;
		uint16_t	sub_vendor_id;
		uint16_t	sub_device_id;
		uint8_t	reserved[24];
	} pci;

	/* Host interface information */
	struct {
		uint8_t	PCIX		: 1;
		uint8_t	PCIE		: 1;
		uint8_t	iSCSI		: 1;
		uint8_t	SAS_3G		: 1;
		uint8_t	reserved_0	: 4;
		uint8_t	reserved_1[6];
		uint8_t	port_count;
		uint64_t	port_addr[8];
	} host_interface;

	/* Device (backend) interface information */
	struct {
		uint8_t	SPI		: 1;
		uint8_t	SAS_3G		: 1;
		uint8_t	SATA_1_5G	: 1;
		uint8_t	SATA_3G		: 1;
		uint8_t	reserved_0	: 4;
		uint8_t	reserved_1[6];
		uint8_t	port_count;
		uint64_t	port_addr[8];
	} device_interface;

	/* List of components residing in flash. All str are null terminated */
	uint32_t	image_check_word;
	uint32_t	image_component_count;

	struct {
		char	name[8];
		char	version[32];
		char	build_date[16];
		char	built_time[16];
	} image_component[8];

	/*
	 * List of flash components that have been flashed on the card, but
	 * are not in use, pending reset of the adapter. This list will be
	 * empty if a flash operation has not occurred. All stings are null
	 * terminated
	 */
	uint32_t	pending_image_component_count;

	struct {
		char	name[8];
		char	version[32];
		char	build_date[16];
		char	build_time[16];
	} pending_image_component[8];

	uint8_t		max_arms;
	uint8_t		max_spans;
	uint8_t		max_arrays;
	uint8_t		max_lds;

	char		product_name[80];
	char		serial_no[32];

	/*
	 * Other physical/controller/operation information. Indicates the
	 * presence of the hardware
	 */
	struct {
		uint32_t	bbu		: 1;
		uint32_t	alarm		: 1;
		uint32_t	nvram		: 1;
		uint32_t	uart		: 1;
		uint32_t	reserved	: 28;
	} hw_present;

	uint32_t	current_fw_time;

	/* Maximum data transfer sizes */
	uint16_t		max_concurrent_cmds;
	uint16_t		max_sge_count;
	uint32_t		max_request_size;

	/* Logical and physical device counts */
	uint16_t		ld_present_count;
	uint16_t		ld_degraded_count;
	uint16_t		ld_offline_count;

	uint16_t		pd_present_count;
	uint16_t		pd_disk_present_count;
	uint16_t		pd_disk_pred_failure_count;
	uint16_t		pd_disk_failed_count;

	/* Memory size information */
	uint16_t		nvram_size;
	uint16_t		memory_size;
	uint16_t		flash_size;

	/* Error counters */
	uint16_t		mem_correctable_error_count;
	uint16_t		mem_uncorrectable_error_count;

	/* Cluster information */
	uint8_t		cluster_permitted;
	uint8_t		cluster_active;
	uint8_t		reserved_1[2];

	/* Controller capabilities structures */
	struct {
		uint32_t	raid_level_0	: 1;
		uint32_t	raid_level_1	: 1;
		uint32_t	raid_level_5	: 1;
		uint32_t	raid_level_1E	: 1;
		uint32_t	reserved	: 28;
	} raid_levels;

	struct {
		uint32_t	rbld_rate		: 1;
		uint32_t	cc_rate			: 1;
		uint32_t	bgi_rate		: 1;
		uint32_t	recon_rate		: 1;
		uint32_t	patrol_rate		: 1;
		uint32_t	alarm_control		: 1;
		uint32_t	cluster_supported	: 1;
		uint32_t	bbu			: 1;
		uint32_t	spanning_allowed	: 1;
		uint32_t	dedicated_hotspares	: 1;
		uint32_t	revertible_hotspares	: 1;
		uint32_t	foreign_config_import	: 1;
		uint32_t	self_diagnostic		: 1;
		uint32_t	reserved		: 19;
	} adapter_operations;

	struct {
		uint32_t	read_policy	: 1;
		uint32_t	write_policy	: 1;
		uint32_t	io_policy	: 1;
		uint32_t	access_policy	: 1;
		uint32_t	reserved	: 28;
	} ld_operations;

	struct {
		uint8_t	min;
		uint8_t	max;
		uint8_t	reserved[2];
	} stripe_size_operations;

	struct {
		uint32_t	force_online	: 1;
		uint32_t	force_offline	: 1;
		uint32_t	force_rebuild	: 1;
		uint32_t	reserved	: 29;
	} pd_operations;

	struct {
		uint32_t	ctrl_supports_sas	: 1;
		uint32_t	ctrl_supports_sata	: 1;
		uint32_t	allow_mix_in_encl	: 1;
		uint32_t	allow_mix_in_ld		: 1;
		uint32_t	allow_sata_in_cluster	: 1;
		uint32_t	reserved		: 27;
	} pd_mix_support;

	/* Include the controller properties (changeable items) */
	uint8_t				reserved_2[12];
	struct mrsas_ctrl_prop		properties;

	uint8_t				pad[0x800 - 0x640];
};

/*
 * ==================================
 * MegaRAID SAS2.0 driver definitions
 * ==================================
 */
#define	MRDRV_MAX_NUM_CMD			1024

#define	MRDRV_MAX_PD_CHANNELS			2
#define	MRDRV_MAX_LD_CHANNELS			2
#define	MRDRV_MAX_CHANNELS			(MRDRV_MAX_PD_CHANNELS + \
						MRDRV_MAX_LD_CHANNELS)
#define	MRDRV_MAX_DEV_PER_CHANNEL		128
#define	MRDRV_DEFAULT_INIT_ID			-1
#define	MRDRV_MAX_CMD_PER_LUN			1000
#define	MRDRV_MAX_LUN				1
#define	MRDRV_MAX_LD				64

#define	MRDRV_RESET_WAIT_TIME			300
#define	MRDRV_RESET_NOTICE_INTERVAL		5

#define	MRSAS_IOCTL_CMD				0

#define	MRDRV_TGT_VALID				1

/*
 * FW can accept both 32 and 64 bit SGLs. We want to allocate 32/64 bit
 * SGLs based on the size of dma_addr_t
 */
#define	IS_DMA64		(sizeof (dma_addr_t) == 8)

#define	RESERVED0_REGISTER		0x00	/* XScale */
#define	IB_MSG_0_OFF			0x10	/* XScale */
#define	OB_MSG_0_OFF			0x18	/* XScale */
#define	IB_DOORBELL_OFF			0x20	/* XScale & ROC */
#define	OB_INTR_STATUS_OFF		0x30	/* XScale & ROC */
#define	OB_INTR_MASK_OFF		0x34	/* XScale & ROC */
#define	IB_QPORT_OFF			0x40	/* XScale & ROC */
#define	OB_DOORBELL_CLEAR_OFF		0xA0	/* ROC */
#define	OB_SCRATCH_PAD_0_OFF		0xB0	/* ROC */
#define	OB_INTR_MASK			0xFFFFFFFF
#define	OB_DOORBELL_CLEAR_MASK		0xFFFFFFFF
#define	SYSTOIOP_INTERRUPT_MASK		0x80000000
#define	OB_SCRATCH_PAD_2_OFF		0xB4
#define	WRITE_TBOLT_SEQ_OFF		0x00000004
#define	DIAG_TBOLT_RESET_ADAPTER	0x00000004
#define	HOST_TBOLT_DIAG_OFF		0x00000008
#define	RESET_TBOLT_STATUS_OFF		0x000003C3
#define	WRITE_SEQ_OFF			0x000000FC
#define	HOST_DIAG_OFF			0x000000F8
#define	DIAG_RESET_ADAPTER		0x00000004
#define	DIAG_WRITE_ENABLE		0x00000080
#define	SYSTOIOP_INTERRUPT_MASK		0x80000000

#define	WR_IB_WRITE_SEQ(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + WRITE_SEQ_OFF), (v))

#define	RD_OB_DRWE(instance) 		ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + HOST_DIAG_OFF))

#define	WR_IB_DRWE(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + HOST_DIAG_OFF), (v))

#define	IB_LOW_QPORT			0xC0
#define	IB_HIGH_QPORT			0xC4
#define	OB_DOORBELL_REGISTER		0x9C	/* 1078 implementation */

/*
 * All MFI register set macros accept mrsas_register_set*
 */
#define	WR_IB_MSG_0(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + IB_MSG_0_OFF), (v))

#define	RD_OB_MSG_0(instance) 		ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_MSG_0_OFF))

#define	WR_IB_DOORBELL(v, instance)	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + IB_DOORBELL_OFF), (v))

#define	RD_IB_DOORBELL(instance)	ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + IB_DOORBELL_OFF))

#define	WR_OB_INTR_STATUS(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_INTR_STATUS_OFF), (v))

#define	RD_OB_INTR_STATUS(instance) 	ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_INTR_STATUS_OFF))

#define	WR_OB_INTR_MASK(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_INTR_MASK_OFF), (v))

#define	RD_OB_INTR_MASK(instance) 	ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_INTR_MASK_OFF))

#define	WR_IB_QPORT(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + IB_QPORT_OFF), (v))

#define	WR_OB_DOORBELL_CLEAR(v, instance) ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_DOORBELL_CLEAR_OFF), \
	(v))

#define	RD_OB_SCRATCH_PAD_0(instance) 	ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_SCRATCH_PAD_0_OFF))

/* Thunderbolt specific registers */
#define	RD_OB_SCRATCH_PAD_2(instance)	ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_SCRATCH_PAD_2_OFF))

#define	WR_TBOLT_IB_WRITE_SEQ(v, instance) \
	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + WRITE_TBOLT_SEQ_OFF), (v))

#define	RD_TBOLT_HOST_DIAG(instance)	ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + HOST_TBOLT_DIAG_OFF))

#define	WR_TBOLT_HOST_DIAG(v, instance)	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + HOST_TBOLT_DIAG_OFF), (v))

#define	RD_TBOLT_RESET_STAT(instance)	ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + RESET_TBOLT_STATUS_OFF))


#define	WR_MPI2_REPLY_POST_INDEX(v, instance)\
	ddi_put32((instance)->regmap_handle,\
	(uint32_t *)\
	((uintptr_t)(instance)->regmap + MPI2_REPLY_POST_HOST_INDEX_OFFSET),\
	(v))


#define	RD_MPI2_REPLY_POST_INDEX(instance)\
	ddi_get32((instance)->regmap_handle,\
	(uint32_t *)\
	((uintptr_t)(instance)->regmap + MPI2_REPLY_POST_HOST_INDEX_OFFSET))

#define	WR_IB_LOW_QPORT(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + IB_LOW_QPORT), (v))

#define	WR_IB_HIGH_QPORT(v, instance) 	ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + IB_HIGH_QPORT), (v))

#define	WR_OB_DOORBELL_REGISTER_CLEAR(v, instance)\
	ddi_put32((instance)->regmap_handle,\
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_DOORBELL_REGISTER), \
	(v))

#define	WR_RESERVED0_REGISTER(v, instance) ddi_put32((instance)->regmap_handle,\
	(uint32_t *)((uintptr_t)(instance)->regmap + RESERVED0_REGISTER), \
	(v))

#define	RD_RESERVED0_REGISTER(instance) ddi_get32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + RESERVED0_REGISTER))



/*
 * When FW is in MFI_STATE_READY or MFI_STATE_OPERATIONAL, the state data
 * of Outbound Msg Reg 0 indicates max concurrent cmds supported, max SGEs
 * supported per cmd and if 64-bit MFAs (M64) is enabled or disabled.
 */
#define	MFI_OB_INTR_STATUS_MASK		0x00000002

/*
 * This MFI_REPLY_2108_MESSAGE_INTR flag is used also
 * in enable_intr_ppc also. Hence bit 2, i.e. 0x4 has
 * been set in this flag along with bit 1.
 */
#define	MFI_REPLY_2108_MESSAGE_INTR		0x00000001
#define	MFI_REPLY_2108_MESSAGE_INTR_MASK	0x00000005

/* Fusion interrupt mask */
#define	MFI_FUSION_ENABLE_INTERRUPT_MASK	(0x00000008)

#define	MFI_POLL_TIMEOUT_SECS		60

#define	MFI_ENABLE_INTR(instance)  ddi_put32((instance)->regmap_handle, \
	(uint32_t *)((uintptr_t)(instance)->regmap + OB_INTR_MASK_OFF), 1)
#define	MFI_DISABLE_INTR(instance)					\
{									\
	uint32_t disable = 1;						\
	uint32_t mask =  ddi_get32((instance)->regmap_handle, 		\
	    (uint32_t *)((uintptr_t)(instance)->regmap + OB_INTR_MASK_OFF));\
	mask &= ~disable;						\
	ddi_put32((instance)->regmap_handle, (uint32_t *)		\
	    (uintptr_t)((instance)->regmap + OB_INTR_MASK_OFF), mask);	\
}

/* By default, the firmware programs for 8 Kbytes of memory */
#define	DEFAULT_MFI_MEM_SZ	8192
#define	MINIMUM_MFI_MEM_SZ	4096

/* DCMD Message Frame MAILBOX0-11 */
#define	DCMD_MBOX_SZ		12

/*
 * on_off_property of mrsas_ctrl_prop
 * bit0-9, 11-31 are reserved
 */
#define	DISABLE_OCR_PROP_FLAG   0x00000400 /* bit 10 */

struct mrsas_register_set {
	uint32_t	reserved_0[4];			/* 0000h */

	uint32_t	inbound_msg_0;			/* 0010h */
	uint32_t	inbound_msg_1;			/* 0014h */
	uint32_t	outbound_msg_0;			/* 0018h */
	uint32_t	outbound_msg_1;			/* 001Ch */

	uint32_t	inbound_doorbell;		/* 0020h */
	uint32_t	inbound_intr_status;		/* 0024h */
	uint32_t	inbound_intr_mask;		/* 0028h */

	uint32_t	outbound_doorbell;		/* 002Ch */
	uint32_t	outbound_intr_status;		/* 0030h */
	uint32_t	outbound_intr_mask;		/* 0034h */

	uint32_t	reserved_1[2];			/* 0038h */

	uint32_t	inbound_queue_port;		/* 0040h */
	uint32_t	outbound_queue_port;		/* 0044h */

	uint32_t 	reserved_2[22];			/* 0048h */

	uint32_t 	outbound_doorbell_clear;	/* 00A0h */

	uint32_t 	reserved_3[3];			/* 00A4h */

	uint32_t 	outbound_scratch_pad;		/* 00B0h */

	uint32_t 	reserved_4[3];			/* 00B4h */

	uint32_t 	inbound_low_queue_port;		/* 00C0h */

	uint32_t 	inbound_high_queue_port;	/* 00C4h */

	uint32_t 	reserved_5;			/* 00C8h */
	uint32_t 	index_registers[820];		/* 00CCh */
};

struct mrsas_sge32 {
	uint32_t	phys_addr;
	uint32_t	length;
};

struct mrsas_sge64 {
	uint64_t	phys_addr;
	uint32_t	length;
};

struct mrsas_sge_ieee {
	uint64_t 	phys_addr;
	uint32_t	length;
	uint32_t	flag;
};

union mrsas_sgl {
	struct mrsas_sge32	sge32[1];
	struct mrsas_sge64	sge64[1];
	struct mrsas_sge_ieee	sge_ieee[1];
};

struct mrsas_header {
	uint8_t		cmd;				/* 00h */
	uint8_t		sense_len;			/* 01h */
	uint8_t		cmd_status;			/* 02h */
	uint8_t		scsi_status;			/* 03h */

	uint8_t		target_id;			/* 04h */
	uint8_t		lun;				/* 05h */
	uint8_t		cdb_len;			/* 06h */
	uint8_t		sge_count;			/* 07h */

	uint32_t	context;			/* 08h */
	uint8_t		req_id;				/* 0Ch */
	uint8_t		msgvector;			/* 0Dh */
	uint16_t	pad_0;				/* 0Eh */

	uint16_t	flags;				/* 10h */
	uint16_t	timeout;			/* 12h */
	uint32_t	data_xferlen;			/* 14h */
};

union mrsas_sgl_frame {
	struct mrsas_sge32	sge32[8];
	struct mrsas_sge64	sge64[5];
};

struct mrsas_init_frame {
	uint8_t		cmd;				/* 00h */
	uint8_t		reserved_0;			/* 01h */
	uint8_t		cmd_status;			/* 02h */

	uint8_t		reserved_1;			/* 03h */
	uint32_t	reserved_2;			/* 04h */

	uint32_t	context;			/* 08h */
	uint8_t		req_id;				/* 0Ch */
	uint8_t		msgvector;			/* 0Dh */
	uint16_t	pad_0;				/* 0Eh */

	uint16_t	flags;				/* 10h */
	uint16_t	reserved_3;			/* 12h */
	uint32_t	data_xfer_len;			/* 14h */

	uint32_t	queue_info_new_phys_addr_lo;	/* 18h */
	uint32_t	queue_info_new_phys_addr_hi;	/* 1Ch */
	uint32_t	queue_info_old_phys_addr_lo;	/* 20h */
	uint32_t	queue_info_old_phys_addr_hi;	/* 24h */
	uint64_t 	driverversion;			/* 28h */
	uint32_t	reserved_4[4];			/* 30h */
};

struct mrsas_init_queue_info {
	uint32_t		init_flags;			/* 00h */
	uint32_t		reply_queue_entries;		/* 04h */

	uint32_t		reply_queue_start_phys_addr_lo;	/* 08h */
	uint32_t		reply_queue_start_phys_addr_hi;	/* 0Ch */
	uint32_t		producer_index_phys_addr_lo;	/* 10h */
	uint32_t		producer_index_phys_addr_hi;	/* 14h */
	uint32_t		consumer_index_phys_addr_lo;	/* 18h */
	uint32_t		consumer_index_phys_addr_hi;	/* 1Ch */
};

struct mrsas_io_frame {
	uint8_t			cmd;			/* 00h */
	uint8_t			sense_len;		/* 01h */
	uint8_t			cmd_status;		/* 02h */
	uint8_t			scsi_status;		/* 03h */

	uint8_t			target_id;		/* 04h */
	uint8_t			access_byte;		/* 05h */
	uint8_t			reserved_0;		/* 06h */
	uint8_t			sge_count;		/* 07h */

	uint32_t		context;		/* 08h */
	uint8_t			req_id;			/* 0Ch */
	uint8_t			msgvector;		/* 0Dh */
	uint16_t		pad_0;			/* 0Eh */

	uint16_t		flags;			/* 10h */
	uint16_t		timeout;		/* 12h */
	uint32_t		lba_count;		/* 14h */

	uint32_t		sense_buf_phys_addr_lo;	/* 18h */
	uint32_t		sense_buf_phys_addr_hi;	/* 1Ch */

	uint32_t		start_lba_lo;		/* 20h */
	uint32_t		start_lba_hi;		/* 24h */

	union mrsas_sgl		sgl;			/* 28h */
};

struct mrsas_pthru_frame {
	uint8_t			cmd;			/* 00h */
	uint8_t			sense_len;		/* 01h */
	uint8_t			cmd_status;		/* 02h */
	uint8_t			scsi_status;		/* 03h */

	uint8_t			target_id;		/* 04h */
	uint8_t			lun;			/* 05h */
	uint8_t			cdb_len;		/* 06h */
	uint8_t			sge_count;		/* 07h */

	uint32_t		context;		/* 08h */
	uint8_t			req_id;			/* 0Ch */
	uint8_t			msgvector;		/* 0Dh */
	uint16_t		pad_0;			/* 0Eh */

	uint16_t		flags;			/* 10h */
	uint16_t		timeout;		/* 12h */
	uint32_t		data_xfer_len;		/* 14h */

	uint32_t		sense_buf_phys_addr_lo;	/* 18h */
	uint32_t		sense_buf_phys_addr_hi;	/* 1Ch */

	uint8_t			cdb[16];		/* 20h */
	union mrsas_sgl		sgl;			/* 30h */
};

struct mrsas_dcmd_frame {
	uint8_t			cmd;			/* 00h */
	uint8_t			reserved_0;		/* 01h */
	uint8_t			cmd_status;		/* 02h */
	uint8_t			reserved_1[4];		/* 03h */
	uint8_t			sge_count;		/* 07h */

	uint32_t		context;		/* 08h */
	uint8_t			req_id;			/* 0Ch */
	uint8_t			msgvector;		/* 0Dh */
	uint16_t		pad_0;			/* 0Eh */

	uint16_t		flags;			/* 10h */
	uint16_t		timeout;		/* 12h */

	uint32_t		data_xfer_len;		/* 14h */
	uint32_t		opcode;			/* 18h */

	/* uint8_t		mbox[DCMD_MBOX_SZ]; */	/* 1Ch */
	union {						/* 1Ch */
		uint8_t b[DCMD_MBOX_SZ];
		uint16_t s[6];
		uint32_t w[3];
	} mbox;

	union mrsas_sgl		sgl;			/* 28h */
};

struct mrsas_abort_frame {
	uint8_t		cmd;				/* 00h */
	uint8_t		reserved_0;			/* 01h */
	uint8_t		cmd_status;			/* 02h */

	uint8_t		reserved_1;			/* 03h */
	uint32_t	reserved_2;			/* 04h */

	uint32_t	context;			/* 08h */
	uint8_t		req_id;				/* 0Ch */
	uint8_t		msgvector;			/* 0Dh */
	uint16_t	pad_0;				/* 0Eh */

	uint16_t	flags;				/* 10h */
	uint16_t	reserved_3;			/* 12h */
	uint32_t	reserved_4;			/* 14h */

	uint32_t	abort_context;			/* 18h */
	uint32_t	pad_1;				/* 1Ch */

	uint32_t	abort_mfi_phys_addr_lo;		/* 20h */
	uint32_t	abort_mfi_phys_addr_hi;		/* 24h */

	uint32_t	reserved_5[6];			/* 28h */
};

struct mrsas_smp_frame {
	uint8_t		cmd;				/* 00h */
	uint8_t		reserved_1;			/* 01h */
	uint8_t		cmd_status;			/* 02h */
	uint8_t		connection_status;		/* 03h */

	uint8_t		reserved_2[3];			/* 04h */
	uint8_t		sge_count;			/* 07h */

	uint32_t	context;			/* 08h */
	uint8_t		req_id;				/* 0Ch */
	uint8_t		msgvector;			/* 0Dh */
	uint16_t	pad_0;				/* 0Eh */

	uint16_t	flags;				/* 10h */
	uint16_t	timeout;			/* 12h */

	uint32_t	data_xfer_len;			/* 14h */

	uint64_t	sas_addr;			/* 20h */

	union mrsas_sgl	sgl[2];				/* 28h */
};

struct mrsas_stp_frame {
	uint8_t		cmd;				/* 00h */
	uint8_t		reserved_1;			/* 01h */
	uint8_t		cmd_status;			/* 02h */
	uint8_t		connection_status;		/* 03h */

	uint8_t		target_id;			/* 04h */
	uint8_t		reserved_2[2];			/* 04h */
	uint8_t		sge_count;			/* 07h */

	uint32_t	context;			/* 08h */
	uint8_t		req_id;				/* 0Ch */
	uint8_t		msgvector;			/* 0Dh */
	uint16_t	pad_0;				/* 0Eh */

	uint16_t	flags;				/* 10h */
	uint16_t	timeout;			/* 12h */

	uint32_t	data_xfer_len;			/* 14h */

	uint16_t	fis[10];			/* 28h */
	uint32_t	stp_flags;			/* 3C */
	union mrsas_sgl	sgl;				/* 40 */
};

union mrsas_frame {
	struct mrsas_header		hdr;
	struct mrsas_init_frame		init;
	struct mrsas_io_frame		io;
	struct mrsas_pthru_frame	pthru;
	struct mrsas_dcmd_frame		dcmd;
	struct mrsas_abort_frame	abort;
	struct mrsas_smp_frame		smp;
	struct mrsas_stp_frame		stp;

	uint8_t			raw_bytes[64];
};

typedef struct mrsas_pd_address {
	uint16_t	device_id;
	uint16_t	encl_id;

	union {
		struct {
			uint8_t encl_index;
			uint8_t slot_number;
		} pd_address;
		struct {
			uint8_t	encl_position;
			uint8_t	encl_connector_index;
		} encl_address;
	}address;

	uint8_t	scsi_dev_type;

	union {
		uint8_t		port_bitmap;
		uint8_t		port_numbers;
	} connected;

	uint64_t		sas_addr[2];
} mrsas_pd_address_t;

union mrsas_evt_class_locale {
	struct {
		uint16_t	locale;
		uint8_t		reserved;
		int8_t		class;
	} members;

	uint32_t	word;
};

struct mrsas_evt_log_info {
	uint32_t	newest_seq_num;
	uint32_t	oldest_seq_num;
	uint32_t	clear_seq_num;
	uint32_t	shutdown_seq_num;
	uint32_t	boot_seq_num;
};

struct mrsas_progress {
	uint16_t	progress;
	uint16_t	elapsed_seconds;
};

struct mrsas_evtarg_ld {
	uint16_t	target_id;
	uint8_t		ld_index;
	uint8_t		reserved;
};

struct mrsas_evtarg_pd {
	uint16_t	device_id;
	uint8_t		encl_index;
	uint8_t		slot_number;
};

struct mrsas_evt_detail {
	uint32_t	seq_num;
	uint32_t	time_stamp;
	uint32_t	code;
	union mrsas_evt_class_locale	cl;
	uint8_t		arg_type;
	uint8_t		reserved1[15];

	union {
		struct {
			struct mrsas_evtarg_pd	pd;
			uint8_t			cdb_length;
			uint8_t			sense_length;
			uint8_t			reserved[2];
			uint8_t			cdb[16];
			uint8_t			sense[64];
		} cdbSense;

		struct mrsas_evtarg_ld		ld;

		struct {
			struct mrsas_evtarg_ld	ld;
			uint64_t		count;
		} ld_count;

		struct {
			uint64_t		lba;
			struct mrsas_evtarg_ld	ld;
		} ld_lba;

		struct {
			struct mrsas_evtarg_ld	ld;
			uint32_t		prevOwner;
			uint32_t		newOwner;
		} ld_owner;

		struct {
			uint64_t		ld_lba;
			uint64_t		pd_lba;
			struct mrsas_evtarg_ld	ld;
			struct mrsas_evtarg_pd	pd;
		} ld_lba_pd_lba;

		struct {
			struct mrsas_evtarg_ld	ld;
			struct mrsas_progress	prog;
		} ld_prog;

		struct {
			struct mrsas_evtarg_ld	ld;
			uint32_t		prev_state;
			uint32_t		new_state;
		} ld_state;

		struct {
			uint64_t		strip;
			struct mrsas_evtarg_ld	ld;
		} ld_strip;

		struct mrsas_evtarg_pd		pd;

		struct {
			struct mrsas_evtarg_pd	pd;
			uint32_t		err;
		} pd_err;

		struct {
			uint64_t		lba;
			struct mrsas_evtarg_pd	pd;
		} pd_lba;

		struct {
			uint64_t		lba;
			struct mrsas_evtarg_pd	pd;
			struct mrsas_evtarg_ld	ld;
		} pd_lba_ld;

		struct {
			struct mrsas_evtarg_pd	pd;
			struct mrsas_progress	prog;
		} pd_prog;

		struct {
			struct mrsas_evtarg_pd	pd;
			uint32_t		prevState;
			uint32_t		newState;
		} pd_state;

		struct {
			uint16_t	vendorId;
			uint16_t	deviceId;
			uint16_t	subVendorId;
			uint16_t	subDeviceId;
		} pci;

		uint32_t	rate;
		char		str[96];

		struct {
			uint32_t	rtc;
			uint32_t	elapsedSeconds;
		} time;

		struct {
			uint32_t	ecar;
			uint32_t	elog;
			char		str[64];
		} ecc;

		mrsas_pd_address_t	pd_addr;

		uint8_t		b[96];
		uint16_t	s[48];
		uint32_t	w[24];
		uint64_t	d[12];
	} args;

	char	description[128];

};

/* only 63 are usable by the application */
#define	MAX_LOGICAL_DRIVES			64
/* only 255 physical devices may be used */
#define	MAX_PHYSICAL_DEVICES			256
#define	MAX_PD_PER_ENCLOSURE			64
/* maximum disks per array */
#define	MAX_ROW_SIZE				32
/* maximum spans per logical drive */
#define	MAX_SPAN_DEPTH				8
/* maximum number of arrays a hot spare may be dedicated to */
#define	MAX_ARRAYS_DEDICATED			16
/* maximum number of arrays which may exist */
#define	MAX_ARRAYS				128
/* maximum number of foreign configs that may ha managed at once */
#define	MAX_FOREIGN_CONFIGS			8
/* maximum spares (global and dedicated combined) */
#define	MAX_SPARES_FOR_THE_CONTROLLER		MAX_PHYSICAL_DEVICES
/* maximum possible Target IDs (i.e. 0 to 63) */
#define	MAX_TARGET_ID				63
/* maximum number of supported enclosures */
#define	MAX_ENCLOSURES				32
/* maximum number of PHYs per controller */
#define	MAX_PHYS_PER_CONTROLLER			16
/* maximum number of LDs per array (due to DDF limitations) */
#define	MAX_LDS_PER_ARRAY			16

/*
 * -----------------------------------------------------------------------------
 * -----------------------------------------------------------------------------
 *
 * Logical Drive commands
 *
 * -----------------------------------------------------------------------------
 * -----------------------------------------------------------------------------
 */
#define	MR_DCMD_LD	0x03000000,	/* Logical Device (LD) opcodes */

/*
 * Input:	dcmd.opcode	- MR_DCMD_LD_GET_LIST
 *		dcmd.mbox	- reserved
 *		dcmd.sge IN	- ptr to returned MR_LD_LIST structure
 * Desc:	Return the logical drive list structure
 * Status:	No error
 */

/*
 * defines the logical drive reference structure
 */
typedef	union _MR_LD_REF {	/* LD reference structure */
	struct {
		uint8_t	targetId; /* LD target id (0 to MAX_TARGET_ID) */
		uint8_t	reserved; /* reserved for in line with MR_PD_REF */
		uint16_t seqNum;  /* Sequence Number */
	} ld_ref;
	uint32_t ref;		/* shorthand reference to full 32-bits */
} MR_LD_REF;			/* 4 bytes */

/*
 * defines the logical drive list structure
 */
typedef struct _MR_LD_LIST {
	uint32_t	ldCount;	/* number of LDs */
	uint32_t	reserved;	/* pad to 8-byte boundary */
	struct {
		MR_LD_REF ref;	/* LD reference */
		uint8_t	state;		/* current LD state (MR_LD_STATE) */
		uint8_t	reserved[3];	/* pad to 8-byte boundary */
		uint64_t size;		/* LD size */
	} ldList[MAX_LOGICAL_DRIVES];
} MR_LD_LIST;

struct mrsas_drv_ver {
	uint8_t	signature[12];
	uint8_t	os_name[16];
	uint8_t	os_ver[12];
	uint8_t	drv_name[20];
	uint8_t	drv_ver[32];
	uint8_t	drv_rel_date[20];
};

#define	PCI_TYPE0_ADDRESSES		6
#define	PCI_TYPE1_ADDRESSES		2
#define	PCI_TYPE2_ADDRESSES		5

struct mrsas_pci_common_header {
	uint16_t	vendorID;		/* (ro) */
	uint16_t	deviceID;		/* (ro) */
	uint16_t	command;		/* Device control */
	uint16_t	status;
	uint8_t		revisionID;		/* (ro) */
	uint8_t		progIf;			/* (ro) */
	uint8_t		subClass;		/* (ro) */
	uint8_t		baseClass;		/* (ro) */
	uint8_t		cacheLineSize;		/* (ro+) */
	uint8_t		latencyTimer;		/* (ro+) */
	uint8_t		headerType;		/* (ro) */
	uint8_t		bist;			/* Built in self test */

	union {
	    struct {
		uint32_t	baseAddresses[PCI_TYPE0_ADDRESSES];
		uint32_t	cis;
		uint16_t	subVendorID;
		uint16_t	subSystemID;
		uint32_t	romBaseAddress;
		uint8_t		capabilitiesPtr;
		uint8_t		reserved1[3];
		uint32_t	reserved2;
		uint8_t		interruptLine;
		uint8_t		interruptPin;	/* (ro) */
		uint8_t		minimumGrant;	/* (ro) */
		uint8_t		maximumLatency;	/* (ro) */
	    } type_0;

	    struct {
		uint32_t	baseAddresses[PCI_TYPE1_ADDRESSES];
		uint8_t		primaryBus;
		uint8_t		secondaryBus;
		uint8_t		subordinateBus;
		uint8_t		secondaryLatency;
		uint8_t		ioBase;
		uint8_t		ioLimit;
		uint16_t	secondaryStatus;
		uint16_t	memoryBase;
		uint16_t	memoryLimit;
		uint16_t	prefetchBase;
		uint16_t	prefetchLimit;
		uint32_t	prefetchBaseUpper32;
		uint32_t	prefetchLimitUpper32;
		uint16_t	ioBaseUpper16;
		uint16_t	ioLimitUpper16;
		uint8_t		capabilitiesPtr;
		uint8_t		reserved1[3];
		uint32_t	romBaseAddress;
		uint8_t		interruptLine;
		uint8_t		interruptPin;
		uint16_t	bridgeControl;
	    } type_1;

	    struct {
		uint32_t	socketRegistersBaseAddress;
		uint8_t		capabilitiesPtr;
		uint8_t		reserved;
		uint16_t	secondaryStatus;
		uint8_t		primaryBus;
		uint8_t		secondaryBus;
		uint8_t		subordinateBus;
		uint8_t		secondaryLatency;
		struct {
			uint32_t	base;
			uint32_t	limit;
		} range[PCI_TYPE2_ADDRESSES-1];
		uint8_t		interruptLine;
		uint8_t		interruptPin;
		uint16_t	bridgeControl;
	    } type_2;
	} header;
};

struct mrsas_pci_link_capability {
	union {
	    struct {
		uint32_t linkSpeed		:4;
		uint32_t linkWidth		:6;
		uint32_t aspmSupport		:2;
		uint32_t losExitLatency		:3;
		uint32_t l1ExitLatency		:3;
		uint32_t rsvdp			:6;
		uint32_t portNumber		:8;
	    } bits;

	    uint32_t asUlong;
	} cap;

};

struct mrsas_pci_link_status_capability {
	union {
	    struct {
		uint16_t linkSpeed		:4;
		uint16_t negotiatedLinkWidth	:6;
		uint16_t linkTrainingError	:1;
		uint16_t linkTraning		:1;
		uint16_t slotClockConfig	:1;
		uint16_t rsvdZ			:3;
	    } bits;

	    uint16_t asUshort;
	} stat_cap;

	uint16_t reserved;

};

struct mrsas_pci_capabilities {
	struct mrsas_pci_link_capability	linkCapability;
	struct mrsas_pci_link_status_capability linkStatusCapability;
};

struct mrsas_pci_information
{
	uint32_t		busNumber;
	uint8_t			deviceNumber;
	uint8_t			functionNumber;
	uint8_t			interruptVector;
	uint8_t			reserved;
	struct mrsas_pci_common_header pciHeaderInfo;
	struct mrsas_pci_capabilities capability;
	uint8_t			reserved2[32];
};

struct mrsas_ioctl {
	uint16_t	version;
	uint16_t	controller_id;
	uint8_t		signature[8];
	uint32_t	reserved_1;
	uint32_t	control_code;
	uint32_t	reserved_2[2];
	uint8_t		frame[64];
	union mrsas_sgl_frame sgl_frame;
	uint8_t		sense_buff[MRSAS_MAX_SENSE_LENGTH];
	uint8_t		data[1];
};

struct mrsas_aen {
	uint16_t	host_no;
	uint16_t	cmd_status;
	uint32_t	seq_num;
	uint32_t	class_locale_word;
};

#pragma pack()

#ifndef	DDI_VENDOR_LSI
#define	DDI_VENDOR_LSI		"LSI"
#endif /* DDI_VENDOR_LSI */

int mrsas_config_scsi_device(struct mrsas_instance *,
    struct scsi_device *, dev_info_t **);

#ifdef PDSUPPORT
int mrsas_tbolt_config_pd(struct mrsas_instance *, uint16_t,
    uint8_t, dev_info_t **);
#endif

dev_info_t *mrsas_find_child(struct mrsas_instance *, uint16_t, uint8_t);
int mrsas_service_evt(struct mrsas_instance *, int, int, int, uint64_t);
void return_raid_msg_pkt(struct mrsas_instance *, struct mrsas_cmd *);
struct mrsas_cmd *get_raid_msg_mfi_pkt(struct mrsas_instance *);
void return_raid_msg_mfi_pkt(struct mrsas_instance *, struct mrsas_cmd *);

int	alloc_space_for_mpi2(struct mrsas_instance *);
void	fill_up_drv_ver(struct mrsas_drv_ver *dv);

int	mrsas_issue_init_mpi2(struct mrsas_instance *);
struct scsi_pkt *mrsas_tbolt_tran_init_pkt(struct scsi_address *, register
		    struct scsi_pkt *, struct buf *, int, int, int, int,
		    int (*)(), caddr_t);
int	mrsas_tbolt_tran_start(struct scsi_address *,
		    register struct scsi_pkt *);
uint32_t tbolt_read_fw_status_reg(struct mrsas_instance *);
void 	tbolt_issue_cmd(struct mrsas_cmd *, struct mrsas_instance *);
int	tbolt_issue_cmd_in_poll_mode(struct mrsas_instance *,
		    struct mrsas_cmd *);
int	tbolt_issue_cmd_in_sync_mode(struct mrsas_instance *,
		    struct mrsas_cmd *);
void	tbolt_enable_intr(struct mrsas_instance *);
void	tbolt_disable_intr(struct mrsas_instance *);
int	tbolt_intr_ack(struct mrsas_instance *);
uint_t	mr_sas_tbolt_process_outstanding_cmd(struct mrsas_instance *);
    uint_t tbolt_softintr();
int 	mrsas_tbolt_dma(struct mrsas_instance *, uint32_t, int, int (*)());
int	mrsas_check_dma_handle(ddi_dma_handle_t handle);
int	mrsas_check_acc_handle(ddi_acc_handle_t handle);
int	mrsas_dma_alloc(struct mrsas_instance *, struct scsi_pkt *,
		    struct buf *, int, int (*)());
int	mrsas_dma_move(struct mrsas_instance *,
			struct scsi_pkt *, struct buf *);
int	mrsas_alloc_dma_obj(struct mrsas_instance *, dma_obj_t *,
		    uchar_t);
void 	mr_sas_tbolt_build_mfi_cmd(struct mrsas_instance *, struct mrsas_cmd *);
int 	mrsas_dma_alloc_dmd(struct mrsas_instance *, dma_obj_t *);
void 	tbolt_complete_cmd_in_sync_mode(struct mrsas_instance *,
	struct mrsas_cmd *);
int 	alloc_req_rep_desc(struct mrsas_instance *);
int		mrsas_mode_sense_build(struct scsi_pkt *);
void		push_pending_mfi_pkt(struct mrsas_instance *,
			struct mrsas_cmd *);
int	mrsas_issue_pending_cmds(struct mrsas_instance *);
int 	mrsas_print_pending_cmds(struct mrsas_instance *);
int  	mrsas_complete_pending_cmds(struct mrsas_instance *);

int	create_mfi_frame_pool(struct mrsas_instance *);
void	destroy_mfi_frame_pool(struct mrsas_instance *);
int 	create_mfi_mpi_frame_pool(struct mrsas_instance *);
void 	destroy_mfi_mpi_frame_pool(struct mrsas_instance *);
int 	create_mpi2_frame_pool(struct mrsas_instance *);
void 	destroy_mpi2_frame_pool(struct mrsas_instance *);
int	mrsas_free_dma_obj(struct mrsas_instance *, dma_obj_t);
void 	mrsas_tbolt_free_additional_dma_buffer(struct mrsas_instance *);
void 	free_req_desc_pool(struct mrsas_instance *);
void 	free_space_for_mpi2(struct mrsas_instance *);
void 	mrsas_dump_reply_desc(struct mrsas_instance *);
void 	tbolt_complete_cmd(struct mrsas_instance *, struct mrsas_cmd *);
void	display_scsi_inquiry(caddr_t);
void	service_mfi_aen(struct mrsas_instance *, struct mrsas_cmd *);
int	mrsas_mode_sense_build(struct scsi_pkt *);
int 	mrsas_tbolt_get_ld_map_info(struct mrsas_instance *);
struct mrsas_cmd *mrsas_tbolt_build_poll_cmd(struct mrsas_instance *,
	struct scsi_address *, struct scsi_pkt *, uchar_t *);
int	mrsas_tbolt_reset_ppc(struct mrsas_instance *instance);
void	mrsas_tbolt_kill_adapter(struct mrsas_instance *instance);
int 	abort_syncmap_cmd(struct mrsas_instance *, struct mrsas_cmd *);
void	mrsas_tbolt_prepare_cdb(struct mrsas_instance *instance, U8 cdb[],
    struct IO_REQUEST_INFO *, Mpi2RaidSCSIIORequest_t *, U32);


int mrsas_init_adapter_ppc(struct mrsas_instance *instance);
int mrsas_init_adapter_tbolt(struct mrsas_instance *instance);
int mrsas_init_adapter(struct mrsas_instance *instance);

int mrsas_alloc_cmd_pool(struct mrsas_instance *instance);
void mrsas_free_cmd_pool(struct mrsas_instance *instance);

void mrsas_print_cmd_details(struct mrsas_instance *, struct mrsas_cmd *, int);
struct mrsas_cmd *get_raid_msg_pkt(struct mrsas_instance *);

int mfi_state_transition_to_ready(struct mrsas_instance *);

struct mrsas_cmd *mrsas_get_mfi_pkt(struct mrsas_instance *);
void mrsas_return_mfi_pkt(struct mrsas_instance *, struct mrsas_cmd *);


/* FMA functions. */
int mrsas_common_check(struct mrsas_instance *, struct  mrsas_cmd *);
void mrsas_fm_ereport(struct mrsas_instance *, char *);


#ifdef	__cplusplus
}
#endif

#endif /* _MR_SAS_H_ */
