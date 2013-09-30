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
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 */

#ifndef	_CPQARY3_H
#define	_CPQARY3_H

#include <sys/types.h>
#include <sys/pci.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/map.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/scsi/scsi.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <cpqary3_ciss.h>
#include <cpqary3_bd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Ioctl Commands
 */
#define	CPQARY3_IOCTL_CMD		('c' << 4)
#define	CPQARY3_IOCTL_DRIVER_INFO	CPQARY3_IOCTL_CMD | 0x01
#define	CPQARY3_IOCTL_CTLR_INFO		CPQARY3_IOCTL_CMD | 0x02
#define	CPQARY3_IOCTL_BMIC_PASS		CPQARY3_IOCTL_CMD | 0x04
#define	CPQARY3_IOCTL_SCSI_PASS		CPQARY3_IOCTL_CMD | 0x08

/* Driver Revision : Used in Ioctl */
#define	CPQARY3_MINOR_REV_NO	00
#define	CPQARY3_MAJOR_REV_NO	01
#define	CPQARY3_REV_DATE	05
#define	CPQARY3_REV_MONTH	04
#define	CPQARY3_REV_YEAR	2001

/* Some Useful definations */
#define	CPQARY3_FAILURE		0
#define	CPQARY3_SUCCESS		1
#define	CPQARY3_SENT		2
#define	CPQARY3_SUBMITTED	3
#define	CPQARY3_NO_SIG		4

#define	CPQARY3_TRUE		1
#define	CPQARY3_FALSE		0

#define	CTLR_SCSI_ID		7
#define	CPQARY3_LD_FAILED	1
/*
 * Defines for cleanup in cpqary3_attach and cpqary3_detach.
 */
#define	CPQARY3_HBA_TRAN_ALLOC_DONE	0x0001
#define	CPQARY3_HBA_TRAN_ATTACH_DONE	0x0002
#define	CPQARY3_CTLR_CONFIG_DONE	0x0004
#define	CPQARY3_INTR_HDLR_SET		0x0008
#define	CPQARY3_CREATE_MINOR_NODE	0x0010
#define	CPQARY3_SOFTSTATE_ALLOC_DONE	0x0020
#define	CPQARY3_MUTEX_INIT_DONE		0x0040
#define	CPQARY3_TICK_TMOUT_REGD		0x0080
#define	CPQARY3_MEM_MAPPED		0x0100
#define	CPQARY3_SW_INTR_HDLR_SET	0x0200
#define	CPQARY3_SW_MUTEX_INIT_DONE	0x0400
#define	CPQARY3_NOE_INIT_DONE		0x0800

#define	CPQARY3_CLEAN_ALL		0x0FFF

#define	CPQARY3_TICKTMOUT_VALUE		180000000    /* 180 seconds */

/*
 * Defines for Maximum and Default Settings.
 */

#define	MAX_LOGDRV		64	/* Max supported Logical Drivers */
#define	MAX_CTLRS		8	/* Max supported Controllers */
#define	MAX_TAPE		28
/*
 * NOTE: When changing the below two entries, Max SG count in cpqary3_ciss.h
 * should also be changed.
 */
/* SG */
#define	MAX_PERF_SG_CNT		64	/* Maximum S/G in performant mode */
#define	CPQARY3_SG_CNT		30	/* minimum S/G in simple mode */
#define	CPQARY3_PERF_SG_CNT	31	/* minimum S/G for performant mode */
/* SG */


#define	CPQARY3_MAX_TGT		(MAX_LOGDRV + MAX_TAPE + 1)

/*
 * SCSI Capabilities Related IDs
 */
#define	CPQARY3_CAP_DISCON_ENABLED		0x01
#define	CPQARY3_CAP_SYNC_ENABLED		0x02
#define	CPQARY3_CAP_WIDE_XFER_ENABLED		0x04
#define	CPQARY3_CAP_ARQ_ENABLED			0x08
#define	CPQARY3_CAP_TAG_QING_ENABLED		0x10
#define	CPQARY3_CAP_TAG_QING_SUPP		0x20
#define	CPQARY3_CAP_UNTAG_DRV_QING_ENABLED	0x40

/*
 * Defines for HBA
 */
#define	CAP_NOT_DEFINED		-1
#define	CAP_CHG_NOT_ALLOWED	0
#define	CAP_CHG_SUCCESS		1

/*
 * Macros for Data Access
 */

/* SCSI Addr to Per Controller */
#define	SA2CTLR(saddr)	((cpqary3_t *)((saddr)->a_hba_tran->tran_hba_private))
#define	SA2TGT(sa)	(sa)->a_target	/* SCSI Addr to Target ID */
#define	SD2TGT(sd)	(sd)->sd_address.a_target /* SCSI Dev to Target ID */
#define	SD2LUN(sd)	(sd)->sd_address.a_lun	/* SCSI Dev to Lun */
#define	SD2SA(sd)	((sd)->sd_address)	/* SCSI Dev to SCSI Addr */

/* SCSI Dev to Per Controller */
#define	SD2CTLR(sd)	\
	((cpqary3_t *)sd->sd_address.a_hba_tran->tran_hba_private)

#define	PKT2PVTPKT(sp)  	((cpqary3_pkt_t *)((sp)->pkt_ha_private))
#define	PVTPKT2MEM(p)		((cpqary3_cmdpvt_t *)p->memp)
#define	MEM2CMD(m)		((CommandList_t *)m->cmdlist_memaddr)
#define	SP2CMD(sp)		MEM2CMD(PVTPKT2MEM(PKT2PVTPKT(sp)))
#define	CTLR2MEMLISTP(ctlr)	((cpqary3_cmdmemlist_t *)ctlr->cmdmemlistp)
#define	MEM2PVTPKT(m)		((cpqary3_pkt_t *)m->pvt_pkt)
#define	MEM2DRVPVT(m)		((cpqary3_private_t *)m->driverdata)
#define	TAG2MEM(ctlr, tag)	\
	((cpqary3_cmdpvt_t *)(CTLR2MEMLISTP(ctlr)->pool[tag]))

/* MACROS */
#define	CPQARY3_MIN(x, y)    		(x < y ? x : y)
#define	CPQARY3_SWAP(val)   		((val >> 8) | ((val & 0xff) << 8))
#define	RETURN_VOID_IF_NULL(x)  	if (NULL == x) return
#define	RETURN_NULL_IF_NULL(x)  	if (NULL == x) return (NULL)
#define	RETURN_FAILURE_IF_NULL(x)	if (NULL == x) return (CPQARY3_FAILURE)

/*
 * Macros for memory allocation/deallocations
 */
#define	MEM_ZALLOC(x)		kmem_zalloc(x, KM_NOSLEEP)
#define	MEM_SFREE(x, y)		if (x) kmem_free((void*)x, y)

/*
 * Convenient macros for reading/writing Configuration table registers
 */
#define	DDI_GET8(ctlr, regp)	 		\
	ddi_get8((ctlr)->ct_handle, (uint8_t *)(regp))
#define	DDI_PUT8(ctlr, regp, value)		\
	ddi_put8((ctlr)->ct_handle, (uint8_t *)(regp), (value))
#define	DDI_GET16(ctlr, regp)	 		\
	ddi_get16((ctlr)->ct_handle, (uint16_t *)(regp))
#define	DDI_PUT16(ctlr, regp, value)	\
	ddi_put16((ctlr)->ct_handle, (uint16_t *)(regp), (value))
#define	DDI_GET32(ctlr, regp)	 		\
	ddi_get32((ctlr)->ct_handle, (uint32_t *)(regp))
#define	DDI_PUT32(ctlr, regp, value) 	\
	ddi_put32((ctlr)->ct_handle, (uint32_t *)(regp), (value))
			/* PERF */
#define	DDI_PUT32_CP(ctlr, regp, value)   \
	ddi_put32((ctlr)->cp_handle, (uint32_t *)(regp), (value))
			/* PERF */

#define	CPQARY3_BUFFER_ERROR_CLEAR	0x0	/* to be used with bioerror */
#define	CPQARY3_DMA_NO_CALLBACK		0x0	/* to be used with DMA calls */
#define	CPQARY3_DMA_ALLOC_HANDLE_DONE	0x01
#define	CPQARY3_DMA_ALLOC_MEM_DONE	0x02
#define	CPQARY3_DMA_BIND_ADDR_DONE	0x04
#define	CPQARY3_FREE_PHYCTG_MEM		0x07
#define	CPQARY3_SYNCCMD_SEND_WAITSIG	(0x0001)

/*
 * Include the driver specific relevant header files here.
 */
#include "cpqary3_ciss.h"
#include "cpqary3_q_mem.h"
#include "cpqary3_noe.h"
#include "cpqary3_scsi.h"
#include "cpqary3_ioctl.h"

/*
 * Per Target Structure
 */

typedef struct cpqary3_target {
	uint32_t	logical_id : 30; /* at most 64 : 63 drives + 1 CTLR */
	uint32_t	type : 2;	/* NONE, CTLR, LOGICAL DRIVE, TAPE */
	PhysDevAddr_t	PhysID;
	union {
		struct {
			uint8_t	id;
			uint8_t	bus;
		} scsi;		/* To support tapes */
		struct {
			uint8_t	heads;
			uint8_t	sectors;
		} drive;	/* Logical drives */
	} properties;

	uint32_t	ctlr_flags;
	dev_info_t	*tgt_dip;
	ddi_dma_attr_t	dma_attrs;
} cpqary3_tgt_t;


/*
 * Values for the type field in the Per Target Structure (above)
 */
#define	CPQARY3_TARGET_NONE		0	/* No Device */
#define	CPQARY3_TARGET_CTLR		1	/* Controller */
#define	CPQARY3_TARGET_LOG_VOL		2	/* Logical Volume */
#define	CPQARY3_TARGET_TAPE		3	/* SCSI Device - Tape */

/*
 * Index into PCI Configuration Registers for Base Address Registers(BAR)
 * Currently, only index for BAR 0 and BAR 1 are defined
 */
#define	INDEX_PCI_BASE0			1	/* offset 0x10 */
#define	INDEX_PCI_BASE1			2	/* offset 0x14 */

/* Offset Values for IO interface from BAR 0 */
#define	INBOUND_DOORBELL		0x20
#define	OUTBOUND_LIST_STATUS		0x30
#define	OUTBOUND_INTERRUPT_MASK		0x34
#define	INBOUND_QUEUE			0x40
#define	OUTBOUND_QUEUE			0x44

/* Offset Values for IO interface from BAR 1 */
#define	CONFIGURATION_TABLE		0x00

#define	INTR_DISABLE_5300_MASK		0x00000008l
#define	INTR_DISABLE_5I_MASK		0x00000004l

#define	OUTBOUND_LIST_5300_EXISTS	0x00000008l
#define	OUTBOUND_LIST_5I_EXISTS		0x00000004l

#define	INTR_PERF_MASK			0x00000001l

#define	INTR_PERF_LOCKUP_MASK		0x00000004l

#define	INTR_E200_PERF_MASK		0x00000004l

#define	INTR_SIMPLE_MASK		0x00000008l
#define	INTR_SIMPLE_LOCKUP_MASK		0x0000000cl


#define	INTR_SIMPLE_5I_MASK		0x00000004l
#define	INTR_SIMPLE_5I_LOCKUP_MASK	0x0000000cl

typedef struct cpqary3_per_controller CTLR;
/*
 * Per Controller Structure
 */
typedef struct cpqary3_per_controller {
	/* System Dependent Entities */
	uint8_t			bus;
	uint8_t			dev : 5;
	uint8_t			fun : 3;
	uint32_t		instance;
	dev_info_t		*dip;

	/* Controller Specific Information */
	int8_t			hba_name[38];
	ulong_t			num_of_targets;
	uint32_t		heartbeat;
	uint32_t		board_id;
	cpqary3_bd_t		*bddef;

	/* Condition Variables used */
	kcondvar_t		cv_immediate_wait;
	kcondvar_t		cv_noe_wait;
	kcondvar_t		cv_flushcache_wait;
	kcondvar_t		cv_abort_wait;
	kcondvar_t		cv_ioctl_wait; /* Variable for ioctls */

	/*
	 * CPQary3 driver related entities related to :
	 * 	Hardware & Software Interrupts, Cookies & Mutex.
	 * 	Timeout Handler
	 *	Driver Transport Layer/Structure
	 *	Database for the per-controller Command Memory Pool
	 *	Target List for the per-controller
	 */
	uint8_t			irq;		/* h/w IRQ */
	ddi_iblock_cookie_t	hw_iblock_cookie; /* cookie for h/w intr */
	kmutex_t		hw_mutex;	/* h/w mutex */
	ddi_iblock_cookie_t	sw_iblock_cookie; /* cookie for s/w intr */
	kmutex_t		sw_mutex;	/* s/w mutex */
	ddi_softintr_t		cpqary3_softintr_id; /* s/w intr identifier */
	uint8_t			swintr_flag;
	timeout_id_t		tick_tmout_id;	/* timeout identifier */
	uint8_t			cpqary3_tick_hdlr;
	scsi_hba_tran_t		*hba_tran;	/* transport structure */
	cpqary3_cmdmemlist_t	*cmdmemlistp;	/* database - Memory Pool */
	cpqary3_tgt_t		*cpqary3_tgtp[CPQARY3_MAX_TGT];
	cpqary3_drvr_replyq_t	*drvr_replyq;


	uint8_t			(*check_ctlr_intr)(CTLR *);

	/*
	 * PCI Configuration Registers
	 * 0x10	Primary I2O Memory BAR 	- for Host Interface
	 * 0x14	Primary DRAM 1 BAR	- for Transport Configuration Table
	 *
	 * Host Interface Registers
	 * Offset from Primary I2O Memory BAR
	 * 0x20 Inbound Doorbell	- for interrupting controller
	 * 0x30	Outbound List Status 	- for signalling status of Reply Q
	 * 0x34	Outbound Interrupt Mask	- for masking Interrupts to host
	 * 0x40	Host Inbound Queue	- Request Q
	 * 0x44	Host Outbound Queue	- reply Q
	 *
	 * Offset from Primary DRAM 1 BAR
	 * 0x00	Configuration Table 	- for Controller Transport Layer
	 */

	uint32_t		*idr;
	ddi_acc_handle_t	idr_handle;

	/* LOCKUP CODE */
	uint32_t		*spr0;
	ddi_acc_handle_t    	spr0_handle;
	/* LOCKUP CODE */

	uint32_t		*odr;
	ddi_acc_handle_t	odr_handle;

	uint32_t		*odr_cl;
	ddi_acc_handle_t	odr_cl_handle;

	uint32_t		*isr;
	ddi_acc_handle_t	isr_handle;

	uint32_t		*imr;
	ddi_acc_handle_t	imr_handle;

	uint32_t		*ipq;
	ddi_acc_handle_t	ipq_handle;

	uint32_t		*opq;
	ddi_acc_handle_t	opq_handle;

	CfgTable_t		*ct;
	ddi_acc_handle_t	ct_handle;

	CfgTrans_Perf_t		*cp;
	ddi_acc_handle_t	cp_handle;

	uint32_t		legacy_mapping;
	uint32_t		noe_support;
	/* SG */
	uint32_t		sg_cnt;
	/* SG */
	uint32_t		ctlr_maxcmds;
	uint32_t		host_support;
	uint8_t			controller_lockup;
	uint8_t			lockup_logged;
	uint32_t		poll_flag;
} cpqary3_t;


/*
 * Private Structure for Self Issued Commands
 */

typedef struct cpqary3_driver_private {
	void				*sg;
	cpqary3_phyctg_t	*phyctgp;
}cpqary3_private_t;

/* cmd_flags */
#define	CFLAG_DMASEND	0x01
#define	CFLAG_CMDIOPB	0x02
#define	CFLAG_DMAVALID	0x04

/*
 * Driver Private Packet
 */
typedef struct cpqary3_pkt {
	struct scsi_pkt		*scsi_cmd_pkt;
	ddi_dma_win_t		prev_winp;
	ddi_dma_seg_t		prev_segp;
	clock_t			cmd_start_time;
	/* SG */
	ddi_dma_cookie_t	cmd_dmacookies[MAX_PERF_SG_CNT];
	/* SG */
	uint32_t		cmd_ncookies;
	uint32_t		cmd_cookie;
	uint32_t		cmd_cookiecnt;
	uint32_t		cmd_nwin;
	uint32_t		cmd_curwin;
	off_t			cmd_dma_offset;
	size_t			cmd_dma_len;
	size_t			cmd_dmacount;
	struct buf		*bf;
	ddi_dma_handle_t   	cmd_dmahandle;
	uint32_t		bytes;
	uint32_t		cmd_flags;
	uint32_t		cdb_len;
	uint32_t		scb_len;
	cpqary3_cmdpvt_t	*memp;
} cpqary3_pkt_t;

#pragma pack(1)

typedef struct cpqary3_ioctlresp {
	/* Driver Revision */
	struct cpqary3_revision {
		uint8_t		minor; /* Version */
		uint8_t		major;
		uint8_t		mm;    /* Revision Date */
		uint8_t		dd;
		uint16_t	yyyy;
	} cpqary3_drvrev;

	/* HBA Info */
	struct cpqary3_ctlr {
		uint8_t		num_of_tgts; /* No of Logical Drive */
		uint8_t		*name;
	} cpqary3_ctlr;
} cpqary3_ioctlresp_t;

typedef struct cpqary3_ioctlreq {
	cpqary3_ioctlresp_t	*cpqary3_ioctlrespp;
} cpqary3_ioctlreq_t;

#pragma pack()

/* Driver function definitions */

void cpqary3_init_hbatran(cpqary3_t *);
void cpqary3_read_conf_file(dev_info_t *, cpqary3_t *);
void cpqary3_tick_hdlr(void *);
void cpqary3_flush_cache(cpqary3_t *);
void cpqary3_intr_onoff(cpqary3_t *, uint8_t);
void cpqary3_lockup_intr_onoff(cpqary3_t *, uint8_t);
uint8_t cpqary3_disable_NOE_command(cpqary3_t *);
uint8_t cpqary3_send_NOE_command(cpqary3_t *, cpqary3_cmdpvt_t *, uint8_t);
uint16_t cpqary3_init_ctlr_resource(cpqary3_t *);
uint32_t cpqary3_hw_isr(caddr_t);
uint32_t cpqary3_sw_isr(caddr_t);
int32_t cpqary3_ioctl_driver_info(uintptr_t, int);
int32_t cpqary3_ioctl_ctlr_info(uintptr_t, cpqary3_t *, int);
int32_t cpqary3_ioctl_bmic_pass(uintptr_t, cpqary3_t *, int);
int32_t cpqary3_ioctl_scsi_pass(uintptr_t, cpqary3_t *, int);
uint8_t cpqary3_probe4targets(cpqary3_t *);
void cpqary3_cmdlist_release(cpqary3_cmdpvt_t *, uint8_t);
int32_t cpqary3_submit(cpqary3_t *, uint32_t);
void cpqary3_free_phyctgs_mem(cpqary3_phyctg_t *, uint8_t);
caddr_t cpqary3_alloc_phyctgs_mem(cpqary3_t *, size_t, uint32_t *,
    cpqary3_phyctg_t *);
cpqary3_cmdpvt_t *cpqary3_cmdlist_occupy(cpqary3_t *);
void cpqary3_synccmd_complete(cpqary3_cmdpvt_t *);
void cpqary3_NOE_handler(cpqary3_cmdpvt_t *);
uint8_t cpqary3_retrieve(cpqary3_t *);
void cpqary3_synccmd_cleanup(cpqary3_cmdpvt_t *);
int cpqary3_target_geometry(struct scsi_address *);
uint8_t cpqary3_send_abortcmd(cpqary3_t *, uint16_t, CommandList_t *);
void cpqary3_memfini(cpqary3_t *, uint8_t);
uint8_t cpqary3_init_ctlr(cpqary3_t *);
int16_t cpqary3_meminit(cpqary3_t *);
void cpqary3_noe_complete(cpqary3_cmdpvt_t *cpqary3_cmdpvtp);
cpqary3_cmdpvt_t *cpqary3_synccmd_alloc(cpqary3_t *, size_t);
void cpqary3_synccmd_free(cpqary3_t *, cpqary3_cmdpvt_t *);
int cpqary3_synccmd_send(cpqary3_t *, cpqary3_cmdpvt_t *, clock_t, int);
uint8_t cpqary3_poll_retrieve(cpqary3_t *cpqary3p, uint32_t poll_tag);
uint8_t cpqary3_build_cmdlist(cpqary3_cmdpvt_t *cpqary3_cmdpvtp, uint32_t tid);

#ifdef	__cplusplus
}
#endif

#endif	/* _CPQARY3_H */
