/*
 * dr_sas.h: header for dr_sas
 *
 * Solaris MegaRAID driver for SAS2.0 controllers
 * Copyright (c) 2008-2009, LSI Logic Corporation.
 * All rights reserved.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_DR_SAS_H_
#define	_DR_SAS_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/scsi.h>
#include "dr_sas_list.h"

/*
 * MegaRAID SAS2.0 Driver meta data
 */
#define	DRSAS_VERSION				"LSIv2.0"
#define	DRSAS_RELDATE				"Jan 9, 2009"

#define	DRSAS_TRUE				1
#define	DRSAS_FALSE				0

/*
 * MegaRAID SAS2.0 device id conversion definitions.
 */
#define	INST2LSIRDCTL(x)		((x) << INST_MINOR_SHIFT)

/*
 * MegaRAID SAS2.0 supported controllers
 */
#define	PCI_DEVICE_ID_LSI_2108VDE		0x0078
#define	PCI_DEVICE_ID_LSI_2108V			0x0079

/*
 * Register Index for 2108 Controllers.
 */
#define	REGISTER_SET_IO_2108			(2)

#define	DRSAS_MAX_SGE_CNT			0x50

#define	DRSAS_IOCTL_DRIVER			0x12341234
#define	DRSAS_IOCTL_FIRMWARE			0x12345678
#define	DRSAS_IOCTL_AEN				0x87654321

#define	DRSAS_1_SECOND				1000000

/* Dynamic Enumeration Flags */
#define	DRSAS_PD_LUN		1
#define	DRSAS_LD_LUN		0
#define	DRSAS_PD_TGT_MAX	255
#define	DRSAS_GET_PD_MAX(s)	((s)->dr_pd_max)
#define	WWN_STRLEN		17

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
#define	MFI_STATE_SHIFT 			28
#define	MFI_STATE_MASK				((uint32_t)0xF<<MFI_STATE_SHIFT)
#define	MFI_STATE_UNDEFINED			((uint32_t)0x0<<MFI_STATE_SHIFT)
#define	MFI_STATE_BB_INIT			((uint32_t)0x1<<MFI_STATE_SHIFT)
#define	MFI_STATE_FW_INIT			((uint32_t)0x4<<MFI_STATE_SHIFT)
#define	MFI_STATE_WAIT_HANDSHAKE		((uint32_t)0x6<<MFI_STATE_SHIFT)
#define	MFI_STATE_FW_INIT_2			((uint32_t)0x7<<MFI_STATE_SHIFT)
#define	MFI_STATE_DEVICE_SCAN			((uint32_t)0x8<<MFI_STATE_SHIFT)
#define	MFI_STATE_BOOT_MESSAGE_PENDING		((uint32_t)0x9<<MFI_STATE_SHIFT)
#define	MFI_STATE_FLUSH_CACHE			((uint32_t)0xA<<MFI_STATE_SHIFT)
#define	MFI_STATE_READY				((uint32_t)0xB<<MFI_STATE_SHIFT)
#define	MFI_STATE_OPERATIONAL			((uint32_t)0xC<<MFI_STATE_SHIFT)
#define	MFI_STATE_FAULT				((uint32_t)0xF<<MFI_STATE_SHIFT)

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

#define	DR_DCMD_CTRL_GET_INFO			0x01010000

#define	DR_DCMD_CTRL_CACHE_FLUSH		0x01101000
#define	DR_FLUSH_CTRL_CACHE			0x01
#define	DR_FLUSH_DISK_CACHE			0x02

#define	DR_DCMD_CTRL_SHUTDOWN			0x01050000
#define	DRSAS_ENABLE_DRIVE_SPINDOWN		0x01

#define	DR_DCMD_CTRL_EVENT_GET_INFO		0x01040100
#define	DR_DCMD_CTRL_EVENT_GET			0x01040300
#define	DR_DCMD_CTRL_EVENT_WAIT			0x01040500
#define	DR_DCMD_LD_GET_PROPERTIES		0x03030000
#define	DR_DCMD_PD_GET_INFO			0x02020000

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
	/* UNUSED: 0x34 to 0xfe */
	MFI_STAT_INVALID_STATUS			= 0xFF
};

enum DR_EVT_CLASS {
	DR_EVT_CLASS_DEBUG		= -2,
	DR_EVT_CLASS_PROGRESS		= -1,
	DR_EVT_CLASS_INFO		=  0,
	DR_EVT_CLASS_WARNING		=  1,
	DR_EVT_CLASS_CRITICAL		=  2,
	DR_EVT_CLASS_FATAL		=  3,
	DR_EVT_CLASS_DEAD		=  4
};

enum DR_EVT_LOCALE {
	DR_EVT_LOCALE_LD		= 0x0001,
	DR_EVT_LOCALE_PD		= 0x0002,
	DR_EVT_LOCALE_ENCL		= 0x0004,
	DR_EVT_LOCALE_BBU		= 0x0008,
	DR_EVT_LOCALE_SAS		= 0x0010,
	DR_EVT_LOCALE_CTRL		= 0x0020,
	DR_EVT_LOCALE_CONFIG		= 0x0040,
	DR_EVT_LOCALE_CLUSTER		= 0x0080,
	DR_EVT_LOCALE_ALL		= 0xffff
};

#define	DR_EVT_CFG_CLEARED		0x0004
#define	DR_EVT_LD_CREATED		0x008a
#define	DR_EVT_LD_DELETED		0x008b
#define	DR_EVT_PD_REMOVED_EXT		0x00f8
#define	DR_EVT_PD_INSERTED_EXT		0x00f7

enum LD_STATE {
	LD_OFFLINE		= 0,
	LD_PARTIALLY_DEGRADED	= 1,
	LD_DEGRADED		= 2,
	LD_OPTIMAL		= 3,
	LD_INVALID		= 0xFF
};

enum DRSAS_EVT {
	DRSAS_EVT_CONFIG_TGT	= 0,
	DRSAS_EVT_UNCONFIG_TGT	= 1,
	DRSAS_EVT_UNCONFIG_SMP	= 2
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
 * Our DMA object. The caller must initialize the size and dma attributes
 * (dma_attr) fields before allocating the resources.
 */
typedef struct {
	caddr_t			buffer;
	uint32_t		size;
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
	ddi_dma_cookie_t	dma_cookie[DRSAS_MAX_SGE_CNT];
	ddi_dma_attr_t		dma_attr;
	uint8_t			status;
	uint8_t			reserved[3];
} dma_obj_t;

struct drsas_eventinfo {
	struct drsas_instance	*instance;
	int 			tgt;
	int 			lun;
	int 			event;
};

struct drsas_ld {
	dev_info_t		*dip;
	uint8_t 		lun_type;
	uint8_t 		reserved[3];
};

struct drsas_pd {
	dev_info_t		*dip;
	uint8_t 		lun_type;
	uint8_t 		dev_id;
	uint8_t 		flags;
	uint8_t 		reserved;
};

struct drsas_pd_info {
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

typedef struct drsas_instance {
	uint32_t	*producer;
	uint32_t	*consumer;

	uint32_t	*reply_queue;
	dma_obj_t	mfi_internal_dma_obj;

	uint8_t		init_id;
	uint8_t		reserved[3];

	uint16_t	max_num_sge;
	uint16_t	max_fw_cmds;
	uint32_t	max_sectors_per_req;

	struct drsas_cmd **cmd_list;

	mlist_t		cmd_pool_list;
	kmutex_t	cmd_pool_mtx;

	mlist_t		cmd_pend_list;
	kmutex_t	cmd_pend_mtx;

	dma_obj_t	mfi_evt_detail_obj;
	struct drsas_cmd *aen_cmd;

	uint32_t	aen_seq_num;
	uint32_t	aen_class_locale_word;

	scsi_hba_tran_t		*tran;

	kcondvar_t	int_cmd_cv;
	kmutex_t	int_cmd_mtx;

	kcondvar_t	aen_cmd_cv;
	kmutex_t	aen_cmd_mtx;

	kcondvar_t	abort_cmd_cv;
	kmutex_t	abort_cmd_mtx;

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

	struct drsas_func_ptr *func_ptr;
	/* MSI interrupts specific */
	ddi_intr_handle_t *intr_htable;
	int		intr_type;
	int		intr_cnt;
	size_t		intr_size;
	uint_t		intr_pri;
	int		intr_cap;

	ddi_taskq_t	*taskq;
	struct drsas_ld	*dr_ld_list;
} drsas_t;

struct drsas_func_ptr {
	int (*read_fw_status_reg)(struct drsas_instance *);
	void (*issue_cmd)(struct drsas_cmd *, struct drsas_instance *);
	int (*issue_cmd_in_sync_mode)(struct drsas_instance *,
	    struct drsas_cmd *);
	int (*issue_cmd_in_poll_mode)(struct drsas_instance *,
	    struct drsas_cmd *);
	void (*enable_intr)(struct drsas_instance *);
	void (*disable_intr)(struct drsas_instance *);
	int (*intr_ack)(struct drsas_instance *);
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
#define	CL_ANN1		2	/* No o/p  */
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

#define	TRAN2MR(tran)	(struct drsas_instance *)(tran)->tran_hba_private)
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
	(struct drsas_instance *)SCSIHOST2ADAP(SCP2HOST(scp))

#define	MRDRV_IS_LOGICAL_SCSA(instance, acmd)		\
	(acmd->device_id < MRDRV_MAX_LD) ? 1 : 0
#define	MRDRV_IS_LOGICAL(ap)				\
	((ap->a_target < MRDRV_MAX_LD) && (ap->a_lun == 0)) ? 1 : 0
#define	MAP_DEVICE_ID(instance, ap)			\
	(ap->a_target)

#define	HIGH_LEVEL_INTR			1
#define	NORMAL_LEVEL_INTR		0

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
	ddi_dma_cookie_t	cmd_dmacookies[DRSAS_MAX_SGE_CNT];
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
	struct drsas_device	*drsas_dev;
};


struct drsas_cmd {
	union drsas_frame	*frame;
	uint32_t		frame_phys_addr;
	uint8_t			*sense;
	uint32_t		sense_phys_addr;
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
};

#define	MAX_MGMT_ADAPTERS			1024
#define	IOC_SIGNATURE				"MR-SAS"

#define	IOC_CMD_FIRMWARE			0x0
#define	DRSAS_DRIVER_IOCTL_COMMON		0xF0010000
#define	DRSAS_DRIVER_IOCTL_DRIVER_VERSION	0xF0010100
#define	DRSAS_DRIVER_IOCTL_PCI_INFORMATION	0xF0010200
#define	DRSAS_DRIVER_IOCTL_MRRAID_STATISTICS	0xF0010300


#define	DRSAS_MAX_SENSE_LENGTH			32

struct drsas_mgmt_info {

	uint16_t			count;
	struct drsas_instance		*instance[MAX_MGMT_ADAPTERS];
	uint16_t			map[MAX_MGMT_ADAPTERS];
	int				max_index;
};

#pragma pack(1)

/*
 * SAS controller properties
 */
struct drsas_ctrl_prop {
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
	uint8_t		disk_write_cache_disable;
	uint8_t		alarm_enable;

	uint8_t		reserved[44];
};

/*
 * SAS controller information
 */
struct drsas_ctrl_info {
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
	struct drsas_ctrl_prop		properties;

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

#define	DRSAS_IOCTL_CMD				0

/*
 * FW can accept both 32 and 64 bit SGLs. We want to allocate 32/64 bit
 * SGLs based on the size of dma_addr_t
 */
#define	IS_DMA64		(sizeof (dma_addr_t) == 8)

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

/*
 * All MFI register set macros accept drsas_register_set*
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


struct drsas_register_set {
	uint32_t	reserved_0[4];

	uint32_t	inbound_msg_0;
	uint32_t	inbound_msg_1;
	uint32_t	outbound_msg_0;
	uint32_t	outbound_msg_1;

	uint32_t	inbound_doorbell;
	uint32_t	inbound_intr_status;
	uint32_t	inbound_intr_mask;

	uint32_t	outbound_doorbell;
	uint32_t	outbound_intr_status;
	uint32_t	outbound_intr_mask;

	uint32_t	reserved_1[2];

	uint32_t	inbound_queue_port;
	uint32_t	outbound_queue_port;

	uint32_t 	reserved_2[22];

	uint32_t 	outbound_doorbell_clear;

	uint32_t 	reserved_3[3];

	uint32_t 	outbound_scratch_pad;

	uint32_t 	reserved_4[3];

	uint32_t 	inbound_low_queue_port;

	uint32_t 	inbound_high_queue_port;

	uint32_t 	reserved_5;
	uint32_t 	index_registers[820];
};

struct drsas_sge32 {
	uint32_t	phys_addr;
	uint32_t	length;
};

struct drsas_sge64 {
	uint64_t	phys_addr;
	uint32_t	length;
};

union drsas_sgl {
	struct drsas_sge32	sge32[1];
	struct drsas_sge64	sge64[1];
};

struct drsas_header {
	uint8_t		cmd;
	uint8_t		sense_len;
	uint8_t		cmd_status;
	uint8_t		scsi_status;

	uint8_t		target_id;
	uint8_t		lun;
	uint8_t		cdb_len;
	uint8_t		sge_count;

	uint32_t	context;
	uint8_t		req_id;
	uint8_t		msgvector;
	uint16_t	pad_0;

	uint16_t	flags;
	uint16_t	timeout;
	uint32_t	data_xferlen;
};

union drsas_sgl_frame {
	struct drsas_sge32	sge32[8];
	struct drsas_sge64	sge64[5];
};

struct drsas_init_frame {
	uint8_t		cmd;
	uint8_t		reserved_0;
	uint8_t		cmd_status;

	uint8_t		reserved_1;
	uint32_t	reserved_2;

	uint32_t	context;
	uint8_t		req_id;
	uint8_t		msgvector;
	uint16_t	pad_0;

	uint16_t	flags;
	uint16_t	reserved_3;
	uint32_t	data_xfer_len;

	uint32_t	queue_info_new_phys_addr_lo;
	uint32_t	queue_info_new_phys_addr_hi;
	uint32_t	queue_info_old_phys_addr_lo;
	uint32_t	queue_info_old_phys_addr_hi;

	uint32_t	reserved_4[6];
};

struct drsas_init_queue_info {
	uint32_t		init_flags;
	uint32_t		reply_queue_entries;

	uint32_t		reply_queue_start_phys_addr_lo;
	uint32_t		reply_queue_start_phys_addr_hi;
	uint32_t		producer_index_phys_addr_lo;
	uint32_t		producer_index_phys_addr_hi;
	uint32_t		consumer_index_phys_addr_lo;
	uint32_t		consumer_index_phys_addr_hi;
};

struct drsas_io_frame {
	uint8_t			cmd;
	uint8_t			sense_len;
	uint8_t			cmd_status;
	uint8_t			scsi_status;

	uint8_t			target_id;
	uint8_t			access_byte;
	uint8_t			reserved_0;
	uint8_t			sge_count;

	uint32_t		context;
	uint8_t			req_id;
	uint8_t			msgvector;
	uint16_t		pad_0;

	uint16_t		flags;
	uint16_t		timeout;
	uint32_t		lba_count;

	uint32_t		sense_buf_phys_addr_lo;
	uint32_t		sense_buf_phys_addr_hi;

	uint32_t		start_lba_lo;
	uint32_t		start_lba_hi;

	union drsas_sgl		sgl;
};

struct drsas_pthru_frame {
	uint8_t			cmd;
	uint8_t			sense_len;
	uint8_t			cmd_status;
	uint8_t			scsi_status;

	uint8_t			target_id;
	uint8_t			lun;
	uint8_t			cdb_len;
	uint8_t			sge_count;

	uint32_t		context;
	uint8_t			req_id;
	uint8_t			msgvector;
	uint16_t		pad_0;

	uint16_t		flags;
	uint16_t		timeout;
	uint32_t		data_xfer_len;

	uint32_t		sense_buf_phys_addr_lo;
	uint32_t		sense_buf_phys_addr_hi;

	uint8_t			cdb[16];
	union drsas_sgl		sgl;
};

struct drsas_dcmd_frame {
	uint8_t			cmd;
	uint8_t			reserved_0;
	uint8_t			cmd_status;
	uint8_t			reserved_1[4];
	uint8_t			sge_count;

	uint32_t		context;
	uint8_t			req_id;
	uint8_t			msgvector;
	uint16_t		pad_0;

	uint16_t		flags;
	uint16_t		timeout;

	uint32_t		data_xfer_len;
	uint32_t		opcode;

	union {
		uint8_t b[DCMD_MBOX_SZ];
		uint16_t s[6];
		uint32_t w[3];
	} mbox;

	union drsas_sgl		sgl;
};

struct drsas_abort_frame {
	uint8_t		cmd;
	uint8_t		reserved_0;
	uint8_t		cmd_status;

	uint8_t		reserved_1;
	uint32_t	reserved_2;

	uint32_t	context;
	uint8_t		req_id;
	uint8_t		msgvector;
	uint16_t	pad_0;

	uint16_t	flags;
	uint16_t	reserved_3;
	uint32_t	reserved_4;

	uint32_t	abort_context;
	uint32_t	pad_1;

	uint32_t	abort_mfi_phys_addr_lo;
	uint32_t	abort_mfi_phys_addr_hi;

	uint32_t	reserved_5[6];
};

struct drsas_smp_frame {
	uint8_t		cmd;
	uint8_t		reserved_1;
	uint8_t		cmd_status;
	uint8_t		connection_status;

	uint8_t		reserved_2[3];
	uint8_t		sge_count;

	uint32_t	context;
	uint8_t		req_id;
	uint8_t		msgvector;
	uint16_t	pad_0;

	uint16_t	flags;
	uint16_t	timeout;

	uint32_t	data_xfer_len;

	uint64_t	sas_addr;

	union drsas_sgl	sgl[2];
};

struct drsas_stp_frame {
	uint8_t		cmd;
	uint8_t		reserved_1;
	uint8_t		cmd_status;
	uint8_t		connection_status;

	uint8_t		target_id;
	uint8_t		reserved_2[2];
	uint8_t		sge_count;

	uint32_t	context;
	uint8_t		req_id;
	uint8_t		msgvector;
	uint16_t	pad_0;

	uint16_t	flags;
	uint16_t	timeout;

	uint32_t	data_xfer_len;

	uint16_t	fis[10];
	uint32_t	stp_flags;
	union drsas_sgl	sgl;
};

union drsas_frame {
	struct drsas_header		hdr;
	struct drsas_init_frame		init;
	struct drsas_io_frame		io;
	struct drsas_pthru_frame	pthru;
	struct drsas_dcmd_frame		dcmd;
	struct drsas_abort_frame	abort;
	struct drsas_smp_frame		smp;
	struct drsas_stp_frame		stp;

	uint8_t			raw_bytes[64];
};

typedef struct drsas_pd_address {
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
} drsas_pd_address_t;

union drsas_evt_class_locale {
	struct {
		uint16_t	locale;
		uint8_t		reserved;
		int8_t		class;
	} members;

	uint32_t	word;
};

struct drsas_evt_log_info {
	uint32_t	newest_seq_num;
	uint32_t	oldest_seq_num;
	uint32_t	clear_seq_num;
	uint32_t	shutdown_seq_num;
	uint32_t	boot_seq_num;
};

struct drsas_progress {
	uint16_t	progress;
	uint16_t	elapsed_seconds;
};

struct drsas_evtarg_ld {
	uint16_t	target_id;
	uint8_t		ld_index;
	uint8_t		reserved;
};

struct drsas_evtarg_pd {
	uint16_t	device_id;
	uint8_t		encl_index;
	uint8_t		slot_number;
};

struct drsas_evt_detail {
	uint32_t	seq_num;
	uint32_t	time_stamp;
	uint32_t	code;
	union drsas_evt_class_locale	cl;
	uint8_t		arg_type;
	uint8_t		reserved1[15];

	union {
		struct {
			struct drsas_evtarg_pd	pd;
			uint8_t			cdb_length;
			uint8_t			sense_length;
			uint8_t			reserved[2];
			uint8_t			cdb[16];
			uint8_t			sense[64];
		} cdbSense;

		struct drsas_evtarg_ld		ld;

		struct {
			struct drsas_evtarg_ld	ld;
			uint64_t		count;
		} ld_count;

		struct {
			uint64_t		lba;
			struct drsas_evtarg_ld	ld;
		} ld_lba;

		struct {
			struct drsas_evtarg_ld	ld;
			uint32_t		prevOwner;
			uint32_t		newOwner;
		} ld_owner;

		struct {
			uint64_t		ld_lba;
			uint64_t		pd_lba;
			struct drsas_evtarg_ld	ld;
			struct drsas_evtarg_pd	pd;
		} ld_lba_pd_lba;

		struct {
			struct drsas_evtarg_ld	ld;
			struct drsas_progress	prog;
		} ld_prog;

		struct {
			struct drsas_evtarg_ld	ld;
			uint32_t		prev_state;
			uint32_t		new_state;
		} ld_state;

		struct {
			uint64_t		strip;
			struct drsas_evtarg_ld	ld;
		} ld_strip;

		struct drsas_evtarg_pd		pd;

		struct {
			struct drsas_evtarg_pd	pd;
			uint32_t		err;
		} pd_err;

		struct {
			uint64_t		lba;
			struct drsas_evtarg_pd	pd;
		} pd_lba;

		struct {
			uint64_t		lba;
			struct drsas_evtarg_pd	pd;
			struct drsas_evtarg_ld	ld;
		} pd_lba_ld;

		struct {
			struct drsas_evtarg_pd	pd;
			struct drsas_progress	prog;
		} pd_prog;

		struct {
			struct drsas_evtarg_pd	pd;
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

		drsas_pd_address_t	pd_addr;

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
#define	DR_DCMD_LD	0x03000000,	/* Logical Device (LD) opcodes */

/*
 * Input:	dcmd.opcode	- DR_DCMD_LD_GET_LIST
 *		dcmd.mbox	- reserved
 *		dcmd.sge IN	- ptr to returned DR_LD_LIST structure
 * Desc:	Return the logical drive list structure
 * Status:	No error
 */

/*
 * defines the logical drive reference structure
 */
typedef	union _DR_LD_REF {	/* LD reference structure */
	struct {
		uint8_t	targetId; /* LD target id (0 to MAX_TARGET_ID) */
		uint8_t	reserved; /* reserved for in line with DR_PD_REF */
		uint16_t seqNum;  /* Sequence Number */
	} ld_ref;
	uint32_t ref;		/* shorthand reference to full 32-bits */
} DR_LD_REF;			/* 4 bytes */

/*
 * defines the logical drive list structure
 */
typedef struct _DR_LD_LIST {
	uint32_t	ldCount;	/* number of LDs */
	uint32_t	reserved;	/* pad to 8-byte boundary */
	struct {
		DR_LD_REF ref;	/* LD reference */
		uint8_t	state;		/* current LD state (DR_LD_STATE) */
		uint8_t	reserved[3];	/* pad to 8-byte boundary */
		uint64_t size;		/* LD size */
	} ldList[MAX_LOGICAL_DRIVES];
} DR_LD_LIST;

struct drsas_drv_ver {
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

struct drsas_pci_common_header {
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

struct drsas_pci_link_capability {
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

struct drsas_pci_link_status_capability {
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

struct drsas_pci_capabilities {
	struct drsas_pci_link_capability	linkCapability;
	struct drsas_pci_link_status_capability linkStatusCapability;
};

struct drsas_pci_information
{
	uint32_t		busNumber;
	uint8_t			deviceNumber;
	uint8_t			functionNumber;
	uint8_t			interruptVector;
	uint8_t			reserved;
	struct drsas_pci_common_header pciHeaderInfo;
	struct drsas_pci_capabilities capability;
	uint8_t			reserved2[32];
};

struct drsas_ioctl {
	uint16_t	version;
	uint16_t	controller_id;
	uint8_t		signature[8];
	uint32_t	reserved_1;
	uint32_t	control_code;
	uint32_t	reserved_2[2];
	uint8_t		frame[64];
	union drsas_sgl_frame sgl_frame;
	uint8_t		sense_buff[DRSAS_MAX_SENSE_LENGTH];
	uint8_t		data[1];
};

struct drsas_aen {
	uint16_t	host_no;
	uint16_t	cmd_status;
	uint32_t	seq_num;
	uint32_t	class_locale_word;
};
#pragma pack()

#ifndef	DDI_VENDOR_LSI
#define	DDI_VENDOR_LSI		"LSI"
#endif /* DDI_VENDOR_LSI */

static int	drsas_getinfo(dev_info_t *, ddi_info_cmd_t,  void *, void **);
static int	drsas_attach(dev_info_t *, ddi_attach_cmd_t);
static int	drsas_reset(dev_info_t *, ddi_reset_cmd_t);
static int	drsas_detach(dev_info_t *, ddi_detach_cmd_t);
static int	drsas_open(dev_t *, int, int, cred_t *);
static int	drsas_close(dev_t, int, int, cred_t *);
static int	drsas_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int	drsas_tran_tgt_init(dev_info_t *, dev_info_t *,
		    scsi_hba_tran_t *, struct scsi_device *);
static struct scsi_pkt *drsas_tran_init_pkt(struct scsi_address *, register
		    struct scsi_pkt *, struct buf *, int, int, int, int,
		    int (*)(), caddr_t);
static int	drsas_tran_start(struct scsi_address *,
		    register struct scsi_pkt *);
static int	drsas_tran_abort(struct scsi_address *, struct scsi_pkt *);
static int	drsas_tran_reset(struct scsi_address *, int);
static int	drsas_tran_getcap(struct scsi_address *, char *, int);
static int	drsas_tran_setcap(struct scsi_address *, char *, int, int);
static void	drsas_tran_destroy_pkt(struct scsi_address *,
		    struct scsi_pkt *);
static void	drsas_tran_dmafree(struct scsi_address *, struct scsi_pkt *);
static void	drsas_tran_sync_pkt(struct scsi_address *, struct scsi_pkt *);
static uint_t	drsas_isr();
static uint_t	drsas_softintr();

static int	init_mfi(struct drsas_instance *);
static int	drsas_free_dma_obj(struct drsas_instance *, dma_obj_t);
static int	drsas_alloc_dma_obj(struct drsas_instance *, dma_obj_t *,
		    uchar_t);
static struct drsas_cmd *get_mfi_pkt(struct drsas_instance *);
static void	return_mfi_pkt(struct drsas_instance *,
		    struct drsas_cmd *);

static void	free_space_for_mfi(struct drsas_instance *);
static void	free_additional_dma_buffer(struct drsas_instance *);
static int	alloc_additional_dma_buffer(struct drsas_instance *);
static int	read_fw_status_reg_ppc(struct drsas_instance *);
static void	issue_cmd_ppc(struct drsas_cmd *, struct drsas_instance *);
static int	issue_cmd_in_poll_mode_ppc(struct drsas_instance *,
		    struct drsas_cmd *);
static int	issue_cmd_in_sync_mode_ppc(struct drsas_instance *,
		    struct drsas_cmd *);
static void	enable_intr_ppc(struct drsas_instance *);
static void	disable_intr_ppc(struct drsas_instance *);
static int	intr_ack_ppc(struct drsas_instance *);
static int	mfi_state_transition_to_ready(struct drsas_instance *);
static void	destroy_mfi_frame_pool(struct drsas_instance *);
static int	create_mfi_frame_pool(struct drsas_instance *);
static int	drsas_dma_alloc(struct drsas_instance *, struct scsi_pkt *,
		    struct buf *, int, int (*)());
static int	drsas_dma_move(struct drsas_instance *,
			struct scsi_pkt *, struct buf *);
static void	flush_cache(struct drsas_instance *instance);
static void	display_scsi_inquiry(caddr_t);
static int	start_mfi_aen(struct drsas_instance *instance);
static int	handle_drv_ioctl(struct drsas_instance *instance,
		    struct drsas_ioctl *ioctl, int mode);
static int	handle_mfi_ioctl(struct drsas_instance *instance,
		    struct drsas_ioctl *ioctl, int mode);
static int	handle_mfi_aen(struct drsas_instance *instance,
		    struct drsas_aen *aen);
static void	fill_up_drv_ver(struct drsas_drv_ver *dv);
static struct drsas_cmd *build_cmd(struct drsas_instance *instance,
		    struct scsi_address *ap, struct scsi_pkt *pkt,
		    uchar_t *cmd_done);
static int	register_mfi_aen(struct drsas_instance *instance,
		    uint32_t seq_num, uint32_t class_locale_word);
static int	issue_mfi_pthru(struct drsas_instance *instance, struct
		    drsas_ioctl *ioctl, struct drsas_cmd *cmd, int mode);
static int	issue_mfi_dcmd(struct drsas_instance *instance, struct
		    drsas_ioctl *ioctl, struct drsas_cmd *cmd, int mode);
static int	issue_mfi_smp(struct drsas_instance *instance, struct
		    drsas_ioctl *ioctl, struct drsas_cmd *cmd, int mode);
static int	issue_mfi_stp(struct drsas_instance *instance, struct
		    drsas_ioctl *ioctl, struct drsas_cmd *cmd, int mode);
static int	abort_aen_cmd(struct drsas_instance *instance,
		    struct drsas_cmd *cmd_to_abort);

static int	drsas_common_check(struct drsas_instance *instance,
		    struct  drsas_cmd *cmd);
static void	drsas_fm_init(struct drsas_instance *instance);
static void	drsas_fm_fini(struct drsas_instance *instance);
static int	drsas_fm_error_cb(dev_info_t *, ddi_fm_error_t *,
		    const void *);
static void	drsas_fm_ereport(struct drsas_instance *instance,
		    char *detail);
static int	drsas_check_dma_handle(ddi_dma_handle_t handle);
static int	drsas_check_acc_handle(ddi_acc_handle_t handle);

static void	drsas_rem_intrs(struct drsas_instance *instance);
static int	drsas_add_intrs(struct drsas_instance *instance, int intr_type);

static void	drsas_tran_tgt_free(dev_info_t *, dev_info_t *,
		    scsi_hba_tran_t *, struct scsi_device *);
static int	drsas_tran_bus_config(dev_info_t *, uint_t,
		    ddi_bus_config_op_t, void *, dev_info_t **);
static int	drsas_parse_devname(char *, int *, int *);
static int	drsas_config_all_devices(struct drsas_instance *);
static int 	drsas_config_scsi_device(struct drsas_instance *,
		    struct scsi_device *, dev_info_t **);
static int 	drsas_config_ld(struct drsas_instance *, uint16_t,
				uint8_t, dev_info_t **);
static dev_info_t *drsas_find_child(struct drsas_instance *, uint16_t,
			uint8_t);
static int	drsas_name_node(dev_info_t *, char *, int);
static void	drsas_issue_evt_taskq(struct drsas_eventinfo *);
static int	drsas_service_evt(struct drsas_instance *, int, int, int);
static void	drsas_mode_sense_build(struct scsi_pkt *);

#ifdef	__cplusplus
}
#endif

#endif /* _DR_SAS_H_ */
