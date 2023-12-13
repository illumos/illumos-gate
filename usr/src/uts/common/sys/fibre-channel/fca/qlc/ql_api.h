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

/* Copyright 2015 QLogic Corporation */

/*
 * Copyright (c) 2008, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_QL_API_H
#define	_QL_API_H

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

/* OS include files. */
#include <sys/scsi/scsi_types.h>
#include <sys/byteorder.h>
#include <sys/pci.h>
#include <sys/utsname.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/ddifm.h>
#include <sys/sunddi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/ddi.h>
#include <ql_open.h>

#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>

#ifndef	DDI_INTR_TYPE_FIXED
#define	DDI_INTR_TYPE_FIXED	0x1
#endif
#ifndef	DDI_INTR_TYPE_MSI
#define	DDI_INTR_TYPE_MSI	0x2
#endif
#ifndef	DDI_INTR_TYPE_MSIX
#define	DDI_INTR_TYPE_MSIX	0x4
#endif
#ifndef	DDI_INTR_FLAG_BLOCK
#define	DDI_INTR_FLAG_BLOCK	0x100
#endif
#ifndef	DDI_INTR_ALLOC_NORMAL
#define	DDI_INTR_ALLOC_NORMAL	0
#endif
#ifndef	DDI_INTR_ALLOC_STRICT
#define	DDI_INTR_ALLOC_STRICT	1
#endif

#define	PCI_PCIE_DEVICE_CONTROL		0x8	/* Device control reg offset */
#define	PCI_MSI_CONTROL			0x2	/* MSI Control reg offset */
#define	PCI_MSI_MSG_ADDR		0x4	/* MSI Msg Addr reg offset */
#define	PCI_MSI_MSG_UPPER_ADDR		0x8	/* MSI MSI Msg Upper Addr reg */
/* offset */
#define	PCI_MSI_MSG_DATA		0xc	/* MSI Msg Data reg offset */
#define	PCI_MSI_X_CONTROL		0x2	/* MSI-X Control reg offset */
#define	MSI_X_TABLE_SIZE_MASK		0x7ff	/* MSI-X Table Size mask */

#define	PCIE_EXT_CAP_PTR		0x100
#define	PCIE_EXT_CAP_NEXT_SHIFT		20
#define	PCIE_EXT_CAP_ID_SRIOV		0x0010	/* SRIOV capabilities offset */
#define	PCIE_EXT_CAP_SRIOV_TOTAL_VFS	0xe
#define	PCIE_SRIOV_PAGE_SIZE_MULTIPLIER	4096

/*
 * NPIV defines
 */
#ifndef	FC_NPIV_FDISC_FAILED
#define	FC_NPIV_FDISC_FAILED	0x45
#endif
#ifndef	FC_NPIV_FDISC_WWN_INUSE
#define	FC_NPIV_FDISC_WWN_INUSE	0x46
#endif
#ifndef	FC_NPIV_NOT_SUPPORTED
#define	FC_NPIV_NOT_SUPPORTED	0x47
#endif
#ifndef	FC_NPIV_WRONG_TOPOLOGY
#define	FC_NPIV_WRONG_TOPOLOGY	0x48
#endif
#ifndef	FC_NPIV_NPIV_BOUND
#define	FC_NPIV_NPIV_BOUND	0x49
#endif
#ifndef	FC_HBA_PORTSPEED_32GBIT
#define	FC_HBA_PORTSPEED_32GBIT	64
#endif

#pragma weak ddi_intr_get_supported_types
#pragma weak ddi_intr_get_nintrs
#pragma weak ddi_intr_alloc
#pragma weak ddi_intr_free
#pragma weak ddi_intr_get_pri
#pragma weak ddi_intr_add_handler
#pragma weak ddi_intr_dup_handler
#pragma weak ddi_intr_get_navail
#pragma weak ddi_intr_block_disable
#pragma weak ddi_intr_block_enable
#pragma weak ddi_intr_disable
#pragma weak ddi_intr_enable
#pragma weak ddi_intr_get_cap
#pragma weak ddi_intr_remove_handler
extern int ddi_intr_get_supported_types();
extern int ddi_intr_get_nintrs();
extern int ddi_intr_alloc();
extern int ddi_intr_free();
extern int ddi_intr_get_pri();
extern int ddi_intr_add_handler();
extern int ddi_intr_dup_handler();
extern int ddi_intr_get_navail();
extern int ddi_intr_block_disable();
extern int ddi_intr_block_enable();
extern int ddi_intr_disable();
extern int ddi_intr_enable();
extern int ddi_intr_get_cap();
extern int ddi_intr_remove_handler();

#define	QL_CLEAR_DMA_HANDLE(x)	((ddi_dma_impl_t *)x)->dmai_fault_notify = 0; \
				((ddi_dma_impl_t *)x)->dmai_fault_check = 0; \
				((ddi_dma_impl_t *)x)->dmai_fault	= 0

#ifndef	FC_STATE_1GBIT_SPEED
#define	FC_STATE_1GBIT_SPEED	0x0100	/* 1 Gbit/sec */
#endif
#ifndef	FC_STATE_2GBIT_SPEED
#define	FC_STATE_2GBIT_SPEED	0x0400	/* 2 Gbit/sec */
#endif
#ifndef	FC_STATE_4GBIT_SPEED
#define	FC_STATE_4GBIT_SPEED	0x0500	/* 4 Gbit/sec */
#endif
#ifndef FC_STATE_8GBIT_SPEED
#define	FC_STATE_8GBIT_SPEED	0x0700	/* 8 Gbit/sec */
#endif
#ifndef FC_STATE_10GBIT_SPEED
#define	FC_STATE_10GBIT_SPEED	0x0600	/* 10 Gbit/sec */
#endif
#ifndef FC_STATE_16GBIT_SPEED
#define	FC_STATE_16GBIT_SPEED	0x0800	/* 16 Gbit/sec */
#endif
#ifndef FC_STATE_32GBIT_SPEED
#define	FC_STATE_32GBIT_SPEED	0x1000	/* 32 Gbit/sec */
#endif

/*
 * Data bit definitions.
 */
#define	BIT_0	0x1
#define	BIT_1	0x2
#define	BIT_2	0x4
#define	BIT_3	0x8
#define	BIT_4	0x10
#define	BIT_5	0x20
#define	BIT_6	0x40
#define	BIT_7	0x80
#define	BIT_8	0x100
#define	BIT_9	0x200
#define	BIT_10	0x400
#define	BIT_11	0x800
#define	BIT_12	0x1000
#define	BIT_13	0x2000
#define	BIT_14	0x4000
#define	BIT_15	0x8000
#define	BIT_16	0x10000
#define	BIT_17	0x20000
#define	BIT_18	0x40000
#define	BIT_19	0x80000
#define	BIT_20	0x100000
#define	BIT_21	0x200000
#define	BIT_22	0x400000
#define	BIT_23	0x800000
#define	BIT_24	0x1000000
#define	BIT_25	0x2000000
#define	BIT_26	0x4000000
#define	BIT_27	0x8000000
#define	BIT_28	0x10000000
#define	BIT_29	0x20000000
#define	BIT_30	0x40000000
#define	BIT_31	0x80000000
#define	BIT_32	0x100000000
#define	BIT_33	0x200000000
#define	BIT_34	0x400000000
#define	BIT_35	0x800000000
#define	BIT_36	0x1000000000
#define	BIT_37	0x2000000000
#define	BIT_38	0x4000000000
#define	BIT_39	0x8000000000
#define	BIT_40	0x10000000000
#define	BIT_41	0x20000000000
#define	BIT_42	0x40000000000
#define	BIT_43	0x80000000000
#define	BIT_44	0x100000000000
#define	BIT_45	0x200000000000
#define	BIT_46	0x400000000000
#define	BIT_47	0x800000000000
#define	BIT_48	0x1000000000000
#define	BIT_49	0x2000000000000
#define	BIT_50	0x4000000000000
#define	BIT_51	0x8000000000000
#define	BIT_52	0x10000000000000
#define	BIT_53	0x20000000000000
#define	BIT_54	0x40000000000000
#define	BIT_55	0x80000000000000
#define	BIT_56	0x100000000000000
#define	BIT_57	0x200000000000000
#define	BIT_58	0x400000000000000
#define	BIT_59	0x800000000000000
#define	BIT_60	0x1000000000000000
#define	BIT_61	0x2000000000000000
#define	BIT_62	0x4000000000000000
#define	BIT_63	0x8000000000000000

/*
 *  Local Macro Definitions.
 */
#ifndef TRUE
#define	TRUE	B_TRUE
#endif

#ifndef FALSE
#define	FALSE	B_FALSE
#endif

/*
 * I/O register
 */
#define	RD_REG_BYTE(ha, addr) \
	(uint8_t)ddi_get8(ha->dev_handle, (uint8_t *)(addr))
#define	RD_REG_WORD(ha, addr) \
	(uint16_t)ddi_get16(ha->dev_handle, (uint16_t *)(addr))
#define	RD_REG_DWORD(ha, addr) \
	(uint32_t)ddi_get32(ha->dev_handle, (uint32_t *)(addr))
#define	RD_REG_DDWORD(ha, addr) \
	(uint64_t)ddi_get64(ha->dev_handle, (uint64_t *)(addr))

#define	WRT_REG_BYTE(ha, addr, data) \
	ddi_put8(ha->dev_handle, (uint8_t *)(addr), (uint8_t)(data))
#define	WRT_REG_WORD(ha, addr, data) \
	ddi_put16(ha->dev_handle, (uint16_t *)(addr), (uint16_t)(data))
#define	WRT_REG_DWORD(ha, addr, data) \
	ddi_put32(ha->dev_handle, (uint32_t *)(addr), (uint32_t)(data))
#define	WRT_REG_DDWORD(ha, addr, data) \
	ddi_put64(ha->dev_handle, (uint64_t *)(addr), (uint64_t)(data))

#define	RD8_IO_REG(ha, regname) \
	RD_REG_BYTE(ha, (ha->iobase + ha->reg_off->regname))
#define	RD16_IO_REG(ha, regname) \
	RD_REG_WORD(ha, (ha->iobase + ha->reg_off->regname))
#define	RD32_IO_REG(ha, regname) \
	RD_REG_DWORD(ha, (ha->iobase + ha->reg_off->regname))

#define	WRT8_IO_REG(ha, regname, data) \
	WRT_REG_BYTE(ha, (ha->iobase + ha->reg_off->regname), (data))
#define	WRT16_IO_REG(ha, regname, data) \
	WRT_REG_WORD(ha, (ha->iobase + ha->reg_off->regname), (data))
#define	WRT32_IO_REG(ha, regname, data) \
	WRT_REG_DWORD(ha, (ha->iobase + ha->reg_off->regname), (data))

#define	RD_IOREG_BYTE(ha, addr) \
	(uint8_t)ddi_get8(ha->iomap_dev_handle, (uint8_t *)(addr))
#define	RD_IOREG_WORD(ha, addr) \
	(uint16_t)ddi_get16(ha->iomap_dev_handle, (uint16_t *)(addr))
#define	RD_IOREG_DWORD(ha, addr) \
	(uint32_t)ddi_get32(ha->iomap_dev_handle, (uint32_t *)(addr))

#define	WRT_IOREG_BYTE(ha, addr, data) \
	ddi_put8(ha->iomap_dev_handle, (uint8_t *)addr, (uint8_t)(data))
#define	WRT_IOREG_WORD(ha, addr, data) \
	ddi_put16(ha->iomap_dev_handle, (uint16_t *)addr, (uint16_t)(data))
#define	WRT_IOREG_DWORD(ha, addr, data) \
	ddi_put32(ha->iomap_dev_handle, (uint32_t *)addr, (uint32_t)(data))

#define	RD8_IOMAP_REG(ha, regname) \
	RD_IOREG_BYTE(ha, (ha->iomap_iobase + ha->reg_off->regname))
#define	RD16_IOMAP_REG(ha, regname) \
	RD_IOREG_WORD(ha, (ha->iomap_iobase + ha->reg_off->regname))
#define	RD32_IOMAP_REG(ha, regname) \
	RD_IOREG_DWORD(ha, (ha->iomap_iobase + ha->reg_off->regname))

#define	WRT8_IOMAP_REG(ha, regname, data) \
	WRT_IOREG_BYTE(ha, (ha->iomap_iobase + ha->reg_off->regname), (data))
#define	WRT16_IOMAP_REG(ha, regname, data) \
	WRT_IOREG_WORD(ha, (ha->iomap_iobase + ha->reg_off->regname), (data))
#define	WRT32_IOMAP_REG(ha, regname, data) \
	WRT_IOREG_DWORD(ha, (ha->iomap_iobase + ha->reg_off->regname), (data))

#define	RD8_MBAR_REG(ha, ofst) \
	(uint8_t)ddi_get8(ha->mbar_dev_handle, \
	(uint8_t *)(ha->mbar + (ofst)))
#define	RD16_MBAR_REG(ha, ofst) \
	(uint16_t)ddi_get16(ha->mbar_dev_handle, \
	(uint16_t *)(ha->mbar + (ofst)))
#define	RD32_MBAR_REG(ha, ofst) \
	(uint32_t)ddi_get32(ha->mbar_dev_handle, \
	(uint32_t *)(ha->mbar + (ofst)))
#define	RD64_MBAR_REG(ha, ofst) \
	(uint64_t)ddi_get64(ha->mbar_dev_handle, \
	(uint64_t *)(ha->mbar + (ofst)))

#define	WR8_MBAR_REG(ha, ofst, data) \
	ddi_put8(ha->mbar_dev_handle, \
	(uint8_t *)(ha->mbar + (ofst)), \
	(uint8_t)(data))
#define	WR16_MBAR_REG(ha, ofst, data) \
	ddi_put16(ha->mbar_dev_handle, \
	(uint16_t *)(ha->mbar + (ofst)), \
	(uint16_t)(data))
#define	WR32_MBAR_REG(ha, ofst, data) \
	ddi_put32(ha->mbar_dev_handle, \
	(uint32_t *)(ha->mbar + (ofst)), \
	(uint32_t)(data))
#define	WR64_MBAR_REG(ha, ofst, data) \
	ddi_put64(ha->mbar_dev_handle, \
	(uint64_t *)(ha->mbar + (ofst)), \
	(uint64_t)(data))

/*
 * FCA definitions
 */
#define	MAX_LUNS	16384
#define	QL_FCA_BRAND	0x0fca2200

/* Following to be removed when defined by OS. */
/* ************************************************************************ */
#define	LA_ELS_FARP_REQ		0x54
#define	LA_ELS_FARP_REPLY	0x55
#define	LA_ELS_LPC		0x71
#define	LA_ELS_LSTS		0x72

typedef struct {
	ls_code_t ls_code;
	uint8_t rsvd[3];
	uint8_t port_control;
	uint8_t lpb[16];
	uint8_t lpe[16];
} ql_lpc_t;

typedef struct {
	ls_code_t ls_code;
} ql_acc_rjt_t;

typedef	fc_linit_resp_t ql_lpc_resp_t;
typedef	fc_scr_resp_t ql_rscn_resp_t;

typedef struct {
	uint16_t    class_valid_svc_opt;
	uint16_t    initiator_ctl;
	uint16_t    recipient_ctl;
	uint16_t    rcv_data_size;
	uint16_t    conc_sequences;
	uint16_t    n_port_end_to_end_credit;
	uint16_t    open_sequences_per_exch;
	uint16_t    unused;
} class_svc_param_t;

typedef struct {
	uint8_t    type;
	uint8_t    rsvd;
	uint16_t    process_assoc_flags;
	uint32_t    originator_process;
	uint32_t    responder_process;
	uint32_t    process_flags;
} prli_svc_param_t;
/* *********************************************************************** */

/*
 * Fibre Channel device definitions.
 */
#define	MAX_22_FIBRE_DEVICES	256
#define	MAX_24_FIBRE_DEVICES	2048
#define	MAX_24_VIRTUAL_PORTS	127
#define	MAX_25_VIRTUAL_PORTS	254
#define	MAX_27_VIRTUAL_PORTS	252
#define	MAX_8021_VIRTUAL_PORTS	63
#define	MAX_81XX_VIRTUAL_PORTS	254
#define	MAX_83_VIRTUAL_PORTS	254

#define	LAST_LOCAL_LOOP_ID		 0x7d
#define	FL_PORT_LOOP_ID			 0x7e /* FFFFFE Fabric F_Port */
#define	SWITCH_FABRIC_CONTROLLER_LOOP_ID 0x7f /* FFFFFD Fabric Controller */
#define	SIMPLE_NAME_SERVER_LOOP_ID	 0x80 /* FFFFFC Directory Server */
#define	SNS_FIRST_LOOP_ID		 0x81
#define	SNS_LAST_LOOP_ID		 0xfe
#define	IP_BROADCAST_LOOP_ID		 0xff /* FFFFFF Broadcast */
#define	BROADCAST_ADDR			 0xffffff /* FFFFFF Broadcast */

/*
 * Fibre Channel 24xx device definitions.
 */
#define	LAST_N_PORT_HDL		0x7ef
#define	SNS_24XX_HDL		0x7FC	/* SNS FFFFFCh */
#define	SFC_24XX_HDL		0x7FD	/* fabric controller FFFFFDh */
#define	FL_PORT_24XX_HDL	0x7FE	/* F_Port FFFFFEh */
#define	BROADCAST_24XX_HDL	0x7FF	/* IP broadcast FFFFFFh */

/* Loop ID's used as flags, must be higher than any valid Loop ID */
#define	PORT_NO_LOOP_ID		0x8000	/* Device does not have loop ID. */
#define	PORT_LOST_ID		0x4000	/* Device has been lost. */

/* Fibre Channel Topoploy. */
#define	QL_N_PORT		BIT_0
#define	QL_NL_PORT		BIT_1
#define	QL_F_PORT		BIT_2
#define	QL_FL_PORT		BIT_3
#define	QL_LOOP_CONNECTION	(QL_NL_PORT | QL_FL_PORT)
#define	QL_P2P_CONNECTION	(QL_F_PORT | QL_N_PORT)
#define	QL_FABRIC_CONNECTION	(QL_F_PORT | QL_FL_PORT)

/* Timeout timer counts in seconds (must greater than 1 second). */
#define	WATCHDOG_TIME		5			/* 0 - 255 */
#define	PORT_RETRY_TIME		2			/* 0 - 255 */
#define	LOOP_DOWN_TIMER_OFF	0
#define	LOOP_DOWN_TIMER_START	240			/* 0 - 255 */
#define	LOOP_DOWN_TIMER_END	1
#define	LOOP_DOWN_RESET		(LOOP_DOWN_TIMER_START - 45)	/* 0 - 255 */
#define	R_A_TOV_DEFAULT		20			/* 0 - 65535 */
#define	IDLE_CHECK_TIMER	300			/* 0 - 65535 */
#define	MAX_DEVICE_LOST_RETRY	16			/* 0 - 255 */
#define	TIMEOUT_THRESHOLD	16			/* 0 - 255 */

/* Maximum outstanding commands in ISP queues (1-4095) */
#define	OSC_INDEX_MASK		0xfff
#define	OSC_INDEX_SHIFT		12

/* Maximum unsolicited buffers (1-65535) */
#define	QL_UB_LIMIT	256

/* ISP request, response and receive buffer entry counts */
#define	REQUEST_ENTRY_CNT	512	/* Request entries (205-65535) */
#define	RESPONSE_ENTRY_CNT	256	/* Response entries (1-65535) */
#define	RCVBUF_CONTAINER_CNT	64	/* Rcv buffer containers (8-1024) */

/*
 * ISP request, response, mailbox and receive buffer queue sizes
 */
#define	SHADOW_ENTRY_SIZE	4
#define	REQUEST_ENTRY_SIZE	64
#define	REQUEST_QUEUE_SIZE	(REQUEST_ENTRY_SIZE * REQUEST_ENTRY_CNT)

#define	RESPONSE_ENTRY_SIZE	64
#define	RESPONSE_QUEUE_SIZE	(RESPONSE_ENTRY_SIZE * RESPONSE_ENTRY_CNT)

#define	RCVBUF_CONTAINER_SIZE	12
#define	RCVBUF_QUEUE_SIZE	(RCVBUF_CONTAINER_SIZE * RCVBUF_CONTAINER_CNT)

/*
 * DMA attributes definitions.
 */
#define	QL_DMA_LOW_ADDRESS		(uint64_t)0
#define	QL_DMA_HIGH_64BIT_ADDRESS	(uint64_t)0xffffffffffffffff
#define	QL_DMA_HIGH_32BIT_ADDRESS	(uint64_t)0xffffffff
#define	QL_DMA_XFER_COUNTER		(uint64_t)0xffffffff
#define	QL_DMA_ADDRESS_ALIGNMENT	(uint64_t)8
#define	QL_DMA_ALIGN_8_BYTE_BOUNDARY	(uint64_t)BIT_3
#define	QL_DMA_RING_ADDRESS_ALIGNMENT	(uint64_t)64
#define	QL_DMA_ALIGN_64_BYTE_BOUNDARY	(uint64_t)BIT_6
#define	QL_DMA_BURSTSIZES		0xff
#define	QL_DMA_MIN_XFER_SIZE		1
#define	QL_DMA_MAX_XFER_SIZE		(uint64_t)0xffffffff
#define	QL_DMA_SEGMENT_BOUNDARY		(uint64_t)0xffffffff

#ifdef __sparc
#define	QL_DMA_SG_LIST_LENGTH	1
#define	QL_FCSM_CMD_SGLLEN	1
#define	QL_FCSM_RSP_SGLLEN	1
#define	QL_FCIP_CMD_SGLLEN	1
#define	QL_FCIP_RSP_SGLLEN	1
#define	QL_FCP_CMD_SGLLEN	1
#define	QL_FCP_RSP_SGLLEN	1
#else
#define	QL_DMA_SG_LIST_LENGTH	1024
#define	QL_FCSM_CMD_SGLLEN	1
#define	QL_FCSM_RSP_SGLLEN	6
/*
 * QL_FCIP_CMD_SGLLEN needs to be increased as we changed the max fcip packet
 * size to about 64K. With this, we need to increase the maximum number of
 * scatter-gather elements allowable from the existing 7. We want it to be more
 * like 17 (max fragments for an fcip packet that is unaligned). (64K / 4K) + 1
 * or whatever. Otherwise the DMA breakup routines will give bad results.
 */
#define	QL_FCIP_CMD_SGLLEN	17
#define	QL_FCIP_RSP_SGLLEN	1
#define	QL_FCP_CMD_SGLLEN	1
#define	QL_FCP_RSP_SGLLEN	1
#endif

#ifndef	DDI_DMA_RELAXED_ORDERING
#define	DDI_DMA_RELAXED_ORDERING	0x400
#endif

#define	QL_DMA_GRANULARITY	1
#define	QL_DMA_XFER_FLAGS	0

typedef union {
	uint64_t size64;	/* 1 X 64 bit number */
	uint32_t size32[2];	/* 2 x 32 bit number */
	uint16_t size16[4];	/* 4 x 16 bit number */
	uint8_t	 size8[8];	/* 8 x  8 bit number */
} conv_num_t;

/*
 *  Device register offsets.
 */
#define	MAX_MBOX_COUNT		32
typedef struct {
	uint16_t flash_address;	/* Flash BIOS address */
	uint16_t flash_data;	/* Flash BIOS data */
	uint16_t ctrl_status;	/* Control/Status */
	uint16_t ictrl;		/* Interrupt control */
	uint16_t istatus;	/* Interrupt status */
	uint16_t semaphore;	/* Semaphore */
	uint16_t nvram;		/* NVRAM register. */
	uint16_t req_in;		/* for 2200 MBX 4 Write */
	uint16_t req_out;	/* for 2200 MBX 4 read */
	uint16_t resp_in;	/* for 2200 MBX 5 Read */
	uint16_t resp_out;	/* for 2200 MBX 5 Write */
	uint16_t risc2host;
	uint16_t mbox_cnt;	/* Number of mailboxes */
	uint16_t mailbox_in[MAX_MBOX_COUNT]; /* Mailbox registers */
	uint16_t mailbox_out[MAX_MBOX_COUNT]; /* Mailbox registers */
	uint16_t fpm_diag_config;
	uint16_t pcr;		/* Processor Control Register. */
	uint16_t mctr;		/* Memory Configuration and Timing. */
	uint16_t fb_cmd;
	uint16_t hccr;		/* Host command & control register. */
	uint16_t gpiod;		/* GPIO Data register. */
	uint16_t gpioe;		/* GPIO Enable register. */
	uint16_t host_to_host_sema;	/* 2312 resource lock register */
	uint16_t pri_req_in;	/* 2400 */
	uint16_t pri_req_out;	/* 2400 */
	uint16_t atio_req_in;	/* 2400 */
	uint16_t atio_req_out;	/* 2400 */
	uint16_t io_base_addr;	/* 2400 */
	uint16_t nx_host_int;	/* NetXen */
	uint16_t nx_risc_int;	/* NetXen */
} reg_off_t;

/*
 * Multi-Queue, Mem BAR 2 definition.
 */
#define	MBAR2_REQ_IN		0x0
#define	MBAR2_REQ_OUT		0x4
#define	MBAR2_RESP_IN		0x8
#define	MBAR2_RESP_OUT		0xc
#define	MBAR2_MULTI_Q_MAX	256
#define	MBAR2_REG_OFFSET	4096

/*
 * Mbox-8 read maximum debounce count.
 * Reading Mbox-8 could be debouncing, before getting stable value.
 * This is the recommended driver fix from Qlogic along with firmware fix.
 * During testing, maximum count did not cross 3.
 */
#define	QL_MAX_DEBOUNCE	10

/*
 * Control Status register definitions
 */
#define	ISP_FUNC_NUM_MASK	(BIT_15 | BIT_14)
#define	ISP_FLASH_64K_BANK	BIT_3	/* Flash BIOS 64K Bank Select */
#define	ISP_FLASH_ENABLE	BIT_1	/* Flash BIOS Read/Write enable */
#define	ISP_RESET		BIT_0	/* ISP soft reset */

/*
 * Control Status 24xx register definitions
 */
#define	FLASH_NVRAM_ACCESS_ERROR	BIT_18
#define	DMA_ACTIVE			BIT_17
#define	DMA_SHUTDOWN			BIT_16
#define	FUNCTION_NUMBER			BIT_15

#define	MWB_4096_BYTES			(BIT_5 | BIT_4)
#define	MWB_2048_BYTES			BIT_5
#define	MWB_1024_BYTES			BIT_4
#define	MWB_512_BYTES			0

/*
 * Interrupt Control register definitions
 */
#define	ISP_EN_INT		BIT_15	/* ISP enable interrupts. */
#define	ISP_EN_RISC		BIT_3	/* ISP enable RISC interrupts. */

/*
 * Interrupt Status register definitions
 */
#define	RISC_INT		BIT_3	/* RISC interrupt */

/*
 * NetXen Host/Risc Interrupt register definitions
 */
#define	NX_MBX_CMD		BIT_0	/* Mailbox command present */
#define	NX_RISC_INT		BIT_0	/* RISC interrupt present */

/*
 * NVRAM register definitions.
 */
#define	NV_DESELECT		0
#define	NV_CLOCK		BIT_0
#define	NV_SELECT		BIT_1
#define	NV_DATA_OUT		BIT_2
#define	NV_DATA_IN		BIT_3
#define	NV_PR_ENABLE		BIT_13	/* protection register enable */
#define	NV_WR_ENABLE		BIT_14	/* write enable */
#define	NV_BUSY			BIT_15

/*
 * Flash/NVRAM 24xx definitions
 */
#define	FLASH_DATA_FLAG		BIT_31
#define	FLASH_CONF_ADDR		0x7FFD0000
#define	FLASH_24_25_DATA_ADDR	0x7FF00000
#define	FLASH_8100_DATA_ADDR	0x7F800000
#define	FLASH_8300_DATA_ADDR	0x7F800000
#define	FLASH_2700_DATA_ADDR	0x7F800000
#define	FLASH_ADDR_MASK		0x7FFF0000

#define	NVRAM_CONF_ADDR		0x7FFF0000
#define	NVRAM_DATA_ADDR		0x7FFE0000

#define	NVRAM_2200_FUNC0_ADDR		0x0
#define	NVRAM_2300_FUNC0_ADDR		0x0
#define	NVRAM_2300_FUNC1_ADDR		0x80
#define	NVRAM_2400_FUNC0_ADDR		0x80
#define	NVRAM_2400_FUNC1_ADDR		0x180
#define	NVRAM_2500_FUNC0_ADDR		0x48080
#define	NVRAM_2500_FUNC1_ADDR		0x48180
#define	NVRAM_8100_FUNC0_ADDR		0xD0080
#define	NVRAM_8100_FUNC1_ADDR		0xD0180
#define	NVRAM_8021_FUNC0_ADDR		0xF0080
#define	NVRAM_8021_FUNC1_ADDR		0xF0180
#define	NVRAM_8300_FC_FUNC0_ADDR	0x270080
#define	NVRAM_8300_FC_FUNC1_ADDR	0x270180
#define	NVRAM_8300_FCOE_FUNC0_ADDR	0x274080
#define	NVRAM_8300_FCOE_FUNC1_ADDR	0x274180
#define	NVRAM_2700_FUNC0_ADDR		0x270080
#define	NVRAM_2700_FUNC1_ADDR		0x270180
#define	NVRAM_2700_FUNC2_ADDR		0x270280
#define	NVRAM_2700_FUNC3_ADDR		0x270380

#define	VPD_2400_FUNC0_ADDR		0
#define	VPD_2400_FUNC1_ADDR		0x100
#define	VPD_2500_FUNC0_ADDR		0x48000
#define	VPD_2500_FUNC1_ADDR		0x48100
#define	VPD_8100_FUNC0_ADDR		0xD0000
#define	VPD_8100_FUNC1_ADDR		0xD0400
#define	VPD_8021_FUNC0_ADDR		0xFA300
#define	VPD_8021_FUNC1_ADDR		0xFA300
#define	VPD_8300_FC_FUNC0_ADDR		0x270000
#define	VPD_8300_FC_FUNC1_ADDR		0x270100
#define	VPD_8300_FCOE_FUNC0_ADDR	0xFA300
#define	VPD_8300_FCOE_FUNC1_ADDR	0xFA300
#define	VPD_2700_FUNC0_ADDR		0x270000
#define	VPD_2700_FUNC1_ADDR		0x270100
#define	VPD_2700_FUNC2_ADDR		0x270200
#define	VPD_2700_FUNC3_ADDR		0x270300
#define	VPD_SIZE			0x80

#define	FLASH_2200_FIRMWARE_ADDR	0x20000
#define	FLASH_2300_FIRMWARE_ADDR	0x20000
#define	FLASH_2400_FIRMWARE_ADDR	0x20000
#define	FLASH_2500_FIRMWARE_ADDR	0x20000
#define	FLASH_8100_FIRMWARE_ADDR	0xA0000
#define	FLASH_8021_FIRMWARE_ADDR	0x40000
#define	FLASH_8021_FIRMWARE_SIZE	0x80000
#define	FLASH_8300_FC_FIRMWARE_ADDR	0x240000
#define	FLASH_8300_FCOE_FIRMWARE_ADDR	0x220000
#define	FLASH_8300_FIRMWARE_SIZE	0x20000
#define	FLASH_2700_FIRMWARE_ADDR	0x240000
#define	FLASH_2700_FIRMWARE_SIZE	0x20000

#define	FLASH_8021_BOOTLOADER_ADDR	0x4000
#define	FLASH_8021_BOOTLOADER_SIZE	0x8000
#define	FLASH_8300_BOOTLOADER_ADDR	0x4000
#define	FLASH_8300_BOOTLOADER_SIZE	0x8000

#define	FLASH_2200_BOOT_CODE_ADDR	0
#define	FLASH_2300_BOOT_CODE_ADDR	0
#define	FLASH_2400_BOOT_CODE_ADDR	0
#define	FLASH_2500_BOOT_CODE_ADDR	0
#define	FLASH_2700_BOOT_CODE_ADDR	0x200000
#define	FLASH_8100_BOOT_CODE_ADDR	0x80000
#define	FLASH_8021_BOOT_CODE_ADDR	0x20000
#define	FLASH_8300_BOOT_CODE_ADDR	0x200000

#define	BEACON_8300_FC_FUNC0_ADDR	0x00201320
#define	BEACON_8300_FC_FUNC1_ADDR	0x00201328
#define	BEACON_8300_FCOE_FUNC0_ADDR	0x00201324
#define	BEACON_8300_FCOE_FUNC1_ADDR	0x0020132c
#define	BEACON_2700_FUNC0_ADDR		0x00201320
#define	BEACON_2700_FUNC1_ADDR		0x00201328
#define	BEACON_2700_FUNC2_ADDR		0x00201330
#define	BEACON_2700_FUNC3_ADDR		0x00201338

#define	FLASH_2400_ERRLOG_START_ADDR_0	0
#define	FLASH_2400_ERRLOG_START_ADDR_1	0
#define	FLASH_2500_ERRLOG_START_ADDR_0	0x54000
#define	FLASH_2500_ERRLOG_START_ADDR_1	0x54400
#define	FLASH_8100_ERRLOG_START_ADDR_0	0xDC000
#define	FLASH_8100_ERRLOG_START_ADDR_1	0xDC400
#define	FLASH_8300_ERRLOG_START_ADDR_0	0x280000
#define	FLASH_8300_ERRLOG_START_ADDR_1	0x280400
#define	FLASH_ERRLOG_SIZE		0x200
#define	FLASH_ERRLOG_ENTRY_SIZE		4

#define	FLASH_2400_DESCRIPTOR_TABLE	0
#define	FLASH_2500_DESCRIPTOR_TABLE	0x50000
#define	FLASH_8100_DESCRIPTOR_TABLE	0xD8000
#define	FLASH_8021_DESCRIPTOR_TABLE	0
#define	FLASH_8300_DESCRIPTOR_TABLE	0xFC000
#define	FLASH_2700_DESCRIPTOR_TABLE	0xFC000

#define	FLASH_2400_LAYOUT_TABLE		0x11400
#define	FLASH_2500_LAYOUT_TABLE		0x50400
#define	FLASH_8100_LAYOUT_TABLE		0xD8400
#define	FLASH_8021_LAYOUT_TABLE		0xFC400
#define	FLASH_8300_LAYOUT_TABLE		0xFC400
#define	FLASH_2700_LAYOUT_TABLE		0xFC400

/*
 * Flash Error Log Event Codes.
 */
#define	FLASH_ERRLOG_AEN_8002		0x8002
#define	FLASH_ERRLOG_AEN_8003		0x8003
#define	FLASH_ERRLOG_AEN_8004		0x8004
#define	FLASH_ERRLOG_RESET_ERR		0xF00B
#define	FLASH_ERRLOG_ISP_ERR		0xF020
#define	FLASH_ERRLOG_PARITY_ERR		0xF022
#define	FLASH_ERRLOG_NVRAM_CHKSUM_ERR	0xF023
#define	FLASH_ERRLOG_FLASH_FW_ERR	0xF024

#define	VPD_TAG_END		0x78
#define	VPD_TAG_CHKSUM		"RV"
#define	VPD_TAG_SN		"SN"
#define	VPD_TAG_PN		"PN"
#define	VPD_TAG_PRODID		"\x82"
#define	VPD_TAG_LRT		0x90
#define	VPD_TAG_LRTC		0x91

/*
 * RISC to Host Status register definitions.
 */
#define	RH_RISC_INT		BIT_15		/* RISC to Host Intrpt Req */
#define	RH_RISC_PAUSED		BIT_8		/* RISC Paused bit. */

/*
 * RISC to Host Status register status field definitions.
 */
#define	ROM_MBX_SUCCESS		0x01
#define	ROM_MBX_ERR		0x02
#define	MBX_SUCCESS		0x10
#define	MBX_ERR			0x11
#define	ASYNC_EVENT		0x12
#define	RESP_UPDATE		0x13
#define	MULTI_Q_RSP_UPDATE	0x14
#define	SCSI_FAST_POST_16	0x15
#define	SCSI_FAST_POST_32	0x16
#define	CTIO_FAST_POST		0x17
#define	IP_FAST_POST_XMT	0x18
#define	IP_FAST_POST_RCV	0x19
#define	IP_FAST_POST_BRD	0x1a
#define	IP_FAST_POST_RCV_ALN	0x1b
#define	ATIO_UPDATE		0x1c
#define	ATIO_RESP_UPDATE	0x1d

/*
 * HCCR commands.
 */
#define	HC_RESET_RISC		0x1000	/* Reset RISC */
#define	HC_PAUSE_RISC		0x2000	/* Pause RISC */
#define	HC_RELEASE_RISC		0x3000	/* Release RISC from reset. */
#define	HC_DISABLE_PARITY_PAUSE	0x4001	/* qla2200/2300 - disable parity err */
					/* RISC pause. */
#define	HC_SET_HOST_INT		0x5000	/* Set host interrupt */
#define	HC_CLR_HOST_INT		0x6000	/* Clear HOST interrupt */
#define	HC_CLR_RISC_INT		0x7000	/* Clear RISC interrupt */
#define	HC_HOST_INT		BIT_7	/* Host interrupt bit */
#define	HC_RISC_PAUSE		BIT_5	/* Pause mode bit */

/*
 * HCCR commands for 24xx and 25xx.
 */
#define	HC24_RESET_RISC		0x10000000	/* Reset RISC */
#define	HC24_CLEAR_RISC_RESET	0x20000000	/* Release RISC from reset. */
#define	HC24_PAUSE_RISC		0x30000000	/* Pause RISC */
#define	HC24_RELEASE_PAUSE	0x40000000	/* Release RISC from pause */
#define	HC24_SET_HOST_INT	0x50000000	/* Set host interrupt */
#define	HC24_CLR_HOST_INT	0x60000000	/* Clear HOST interrupt */
#define	HC24_CLR_RISC_INT	0xA0000000	/* Clear RISC interrupt */
#define	HC24_HOST_INT		BIT_6		/* Host to RISC intrpt bit */
#define	HC24_RISC_RESET		BIT_5		/* RISC Reset mode bit. */

/*
 * ISP Initialization Control Blocks.
 * Little endian except where noted.
 */
#define	ICB_VERSION		1
typedef struct ql_init_cb {
	uint8_t version;
	uint8_t reserved;

	/*
	 * LSB BIT 0  = enable_hard_loop_id
	 * LSB BIT 1  = enable_fairness
	 * LSB BIT 2  = enable_full_duplex
	 * LSB BIT 3  = enable_fast_posting
	 * LSB BIT 4  = enable_target_mode
	 * LSB BIT 5  = disable_initiator_mode
	 * LSB BIT 6  = enable_adisc
	 * LSB BIT 7  = enable_target_inquiry_data
	 *
	 * MSB BIT 0  = enable_port_update_ae
	 * MSB BIT 1  = disable_initial_lip
	 * MSB BIT 2  = enable_decending_soft_assign
	 * MSB BIT 3  = previous_assigned_addressing
	 * MSB BIT 4  = enable_stop_q_on_full
	 * MSB BIT 5  = enable_full_login_on_lip
	 * MSB BIT 6  = enable_node_name
	 * MSB BIT 7  = extended_control_block
	 */
	uint8_t firmware_options[2];

	uint8_t max_frame_length[2];
	uint8_t max_iocb_allocation[2];
	uint8_t execution_throttle[2];
	uint8_t login_retry_count;
	uint8_t retry_delay;			/* unused */
	uint8_t port_name[8];			/* Big endian. */
	uint8_t hard_address[2];		/* option bit 0 */
	uint8_t inquiry;			/* option bit 7 */
	uint8_t login_timeout;
	uint8_t node_name[8];			/* Big endian */
	uint8_t request_q_outpointer[2];
	uint8_t response_q_inpointer[2];
	uint8_t request_q_length[2];
	uint8_t response_q_length[2];
	uint8_t request_q_address[8];
	uint8_t response_q_address[8];
	uint8_t lun_enables[2];
	uint8_t command_resouce_count;
	uint8_t immediate_notify_resouce_count;
	uint8_t timeout[2];
	uint8_t reserved_2[2];

	/*
	 * LSB BIT 0 = Timer operation mode bit 0
	 * LSB BIT 1 = Timer operation mode bit 1
	 * LSB BIT 2 = Timer operation mode bit 2
	 * LSB BIT 3 = Timer operation mode bit 3
	 * LSB BIT 4 = P2P Connection option bit 0
	 * LSB BIT 5 = P2P Connection option bit 1
	 * LSB BIT 6 = P2P Connection option bit 2
	 * LSB BIT 7 = Enable Non part on LIHA failure
	 *
	 * MSB BIT 0 = Enable class 2
	 * MSB BIT 1 = Enable ACK0
	 * MSB BIT 2 =
	 * MSB BIT 3 =
	 * MSB BIT 4 = FC Tape Enable
	 * MSB BIT 5 = Enable FC Confirm
	 * MSB BIT 6 = Enable CRN
	 * MSB BIT 7 =
	 */
	uint8_t	add_fw_opt[2];

	uint8_t	response_accumulation_timer;
	uint8_t	interrupt_delay_timer;

	/*
	 * LSB BIT 0 = Enable Read xfr_rdy
	 * LSB BIT 1 = Soft ID only
	 * LSB BIT 2 =
	 * LSB BIT 3 =
	 * LSB BIT 4 = FCP RSP Payload [0]
	 * LSB BIT 5 = FCP RSP Payload [1] / Sbus enable - 2200
	 * LSB BIT 6 =
	 * LSB BIT 7 =
	 *
	 * MSB BIT 0 = Sbus enable - 2300
	 * MSB BIT 1 =
	 * MSB BIT 2 =
	 * MSB BIT 3 =
	 * MSB BIT 4 =
	 * MSB BIT 5 = enable 50 ohm termination
	 * MSB BIT 6 = Data Rate (2300 only)
	 * MSB BIT 7 = Data Rate (2300 only)
	 */
	uint8_t	special_options[2];

	uint8_t	reserved_3[26];
} ql_init_cb_t;

/*
 * Virtual port definition.
 */
typedef struct ql_vp_cfg {
	uint8_t	reserved[2];
	uint8_t	options;
	uint8_t	hard_prev_addr;
	uint8_t	port_name[8];
	uint8_t	node_name[8];
} ql_vp_cfg_t;

/*
 * VP options.
 */
#define	VPO_ENABLE_SNS_LOGIN_SCR	BIT_6
#define	VPO_TARGET_MODE_DISABLED	BIT_5
#define	VPO_INITIATOR_MODE_ENABLED	BIT_4
#define	VPO_ENABLED			BIT_3
#define	VPO_ID_NOT_ACQUIRED		BIT_2
#define	VPO_PREVIOUSLY_ASSIGNED_ID	BIT_1
#define	VPO_HARD_ASSIGNED_ID		BIT_0

#define	ICB_24XX_VERSION	1
typedef struct ql_init_24xx_cb {
	uint8_t version[2];
	uint8_t reserved_1[2];
	uint8_t max_frame_length[2];
	uint8_t execution_throttle[2];
	uint8_t exchange_count[2];
	uint8_t hard_address[2];
	uint8_t port_name[8];	/* Big endian. */
	uint8_t node_name[8];	/* Big endian. */

	uint8_t response_q_inpointer[2];
	uint8_t request_q_outpointer[2];

	uint8_t login_retry_count[2];

	uint8_t prio_request_q_outpointer[2];

	uint8_t response_q_length[2];
	uint8_t request_q_length[2];

	uint8_t link_down_on_nos[2];

	uint8_t prio_request_q_length[2];
	uint8_t request_q_address[8];
	uint8_t response_q_address[8];
	uint8_t prio_request_q_address[8];
	uint8_t msi_x_vector[2];
	uint8_t reserved_2[6];
	uint8_t atio_q_inpointer[2];
	uint8_t atio_q_length[2];
	uint8_t atio_q_address[8];

	uint8_t interrupt_delay_timer[2];	/* 100us per */
	uint8_t login_timeout[2];
	/*
	 * BIT 0  = Hard Assigned Loop ID
	 * BIT 1  = Enable Fairness
	 * BIT 2  = Enable Full-Duplex
	 * BIT 3  = Reserved
	 * BIT 4  = Target Mode Enable
	 * BIT 5  = Initiator Mode Disable
	 * BIT 6  = Reserved
	 * BIT 7  = Reserved
	 *
	 * BIT 8  = Reserved
	 * BIT 9  = Disable Initial LIP
	 * BIT 10 = Descending Loop ID Search
	 * BIT 11 = Previous Assigned Loop ID
	 * BIT 12 = Reserved
	 * BIT 13 = Full Login after LIP
	 * BIT 14 = Node Name Option
	 * BIT 15-31 = Reserved
	 */
	uint8_t	firmware_options_1[4];

	/*
	 * BIT 0  = Operation Mode bit 0
	 * BIT 1  = Operation Mode bit 1
	 * BIT 2  = Operation Mode bit 2
	 * BIT 3  = Operation Mode bit 3
	 * BIT 4  = Connection Options bit 0
	 * BIT 5  = Connection Options bit 1
	 * BIT 6  = Connection Options bit 2
	 * BIT 7  = Enable Non part on LIHA failure
	 *
	 * BIT 8  = Enable Class 2
	 * BIT 9  = Enable ACK0
	 * BIT 10 = Reserved
	 * BIT 11 = Enable FC-SP Security
	 * BIT 12 = FC Tape Enable
	 * BIT 13 = Reserved
	 * BIT 14 = Target PRLI Control
	 * BIT 15 = Reserved
	 *
	 * BIT 16  = Enable Emulated MSIX
	 * BIT 17  = Reserved
	 * BIT 18  = Enable Alternate Device Number
	 * BIT 19  = Enable Alternate Bus Number
	 * BIT 20  = Enable Translated Address
	 * BIT 21  = Enable VM Security
	 * BIT 22  = Enable Interrupt Handshake
	 * BIT 23  = Enable Multiple Queue
	 *
	 * BIT 24  = IOCB Security
	 * BIT 25  = qos
	 * BIT 26-31 = Reserved
	 */
	uint8_t firmware_options_2[4];

	/*
	 * BIT 0  = Reserved
	 * BIT 1  = Soft ID only
	 * BIT 2  = Reserved
	 * BIT 3  = Reserved
	 * BIT 4  = FCP RSP Payload bit 0
	 * BIT 5  = FCP RSP Payload bit 1
	 * BIT 6  = Enable Rec Out-of-Order data frame handling
	 * BIT 7  = Disable Automatic PLOGI on Local Loop
	 *
	 * BIT 8  = Reserved
	 * BIT 9  = Enable Out-of-Order FCP_XFER_RDY relative
	 *	    offset handling
	 * BIT 10 = Reserved
	 * BIT 11 = Reserved
	 * BIT 12 = Reserved
	 * BIT 13 = Data Rate bit 0
	 * BIT 14 = Data Rate bit 1
	 * BIT 15 = Data Rate bit 2
	 *
	 * BIT 16 = 75-ohm Termination Select
	 * BIT 17 = Enable Multiple FCFs
	 * BIT 18 = MAC Addressing Mode
	 * BIT 19 = MAC Addressing Mode
	 * BIT 20 = MAC Addressing Mode
	 * BIT 21 = Ethernet Data Rate
	 * BIT 22 = Ethernet Data Rate
	 * BIT 23 = Ethernet Data Rate
	 *
	 * BIT 24 = Ethernet Data Rate
	 * BIT 25 = Ethernet Data Rate
	 * BIT 26 = Enable Ethernet Header ATIO Queue
	 * BIT 27 = Enable Ethernet Header Response Queue
	 * BIT 28 = SPMA Selection
	 * BIT 29 = SPMA Selection
	 * BIT 30 = Reserved
	 * BIT 31 = Reserved
	 */
	uint8_t firmware_options_3[4];

	uint8_t	qos[2];
	uint8_t	rid[2];

	uint8_t	reserved_3[4];

	uint8_t	enode_mac_addr[6];

	uint8_t	reserved_4[10];

	/*
	 * Multi-ID firmware.
	 */
	uint8_t	vp_count[2];

	/*
	 * BIT 1  = Allows mode 2 connection option
	 */
	uint8_t		global_vp_option[2];

	ql_vp_cfg_t	vpc[MAX_25_VIRTUAL_PORTS + 1];

	/*
	 * Extended Initialization Control Block
	 */
	ql_ext_icb_8100_t	ext_blk;
} ql_init_24xx_cb_t;

typedef union ql_comb_init_cb {
	ql_init_cb_t		cb;
	ql_init_24xx_cb_t	cb24;
} ql_comb_init_cb_t;

/*
 * ISP IP Initialization Control Block.
 * Little endian except where noted.
 */
#define	IP_ICB_VERSION	1
typedef struct ql_ip_init_cb {
	uint8_t	version;
	uint8_t	reserved;

	/*
	 * LSB BIT 0  = receive_buffer_address_length
	 * LSB BIT 1  = fast post broadcast received
	 * LSB BIT 2  = allow out of receive buffers AE
	 */
	uint8_t ip_firmware_options[2];
	uint8_t ip_header_size[2];
	uint8_t mtu_size[2];			/* max value is 65280 */
	uint8_t buf_size[2];
	uint8_t reserved_1[8];
	uint8_t queue_size[2];			/* 8-1024 */
	uint8_t low_water_mark[2];
	uint8_t queue_address[8];
	uint8_t queue_inpointer[2];
	uint8_t fast_post_reg_count[2];		/* 0-14 */
	uint8_t cc[2];
	uint8_t reserved_2[28];
} ql_ip_init_cb_t;

#define	IP_ICB_24XX_VERSION	1
typedef struct ql_ip_init_24xx_cb {
	uint8_t	version;
	uint8_t	reserved;
	/*
	 * LSB BIT 2  = allow out of receive buffers AE
	 */
	uint8_t ip_firmware_options[2];
	uint8_t ip_header_size[2];
	uint8_t mtu_size[2];
	uint8_t buf_size[2];
	uint8_t reserved_1[10];
	uint8_t low_water_mark[2];
	uint8_t reserved_3[12];
	uint8_t cc[2];
	uint8_t reserved_2[28];
} ql_ip_init_24xx_cb_t;

typedef union ql_comb_ip_init_cb {
	ql_ip_init_cb_t		cb;
	ql_ip_init_24xx_cb_t	cb24;
} ql_comb_ip_init_cb_t;

/*
 * f/w module table
 */
struct fw_table {
	uint32_t	fw_class;
	int8_t		*fw_version;
};

/*
 * DMA memory type.
 */
typedef enum mem_alloc_type {
	UNKNOWN_MEMORY,
	TASK_MEMORY,
	LITTLE_ENDIAN_DMA,
	BIG_ENDIAN_DMA,
	KERNEL_MEM,
	NO_SWAP_DMA
} mem_alloc_type_t;

/*
 * DMA memory alignment type.
 */
typedef enum men_align_type {
	QL_DMA_DATA_ALIGN,
	QL_DMA_RING_ALIGN,
} mem_alignment_t;

/*
 * DMA memory object.
 */
typedef struct dma_mem {
	uint64_t		alignment;
	void			*bp;
	ddi_dma_cookie_t	*cookies;
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
	ddi_dma_cookie_t	cookie;
	uint32_t		max_cookie_count;
	uint32_t		cookie_count;
	uint32_t		size;
	uint32_t		memflags;
	mem_alloc_type_t	type;
	uint32_t		flags;		/* Solaris DMA flags. */
} dma_mem_t;

/*
 * 24 bit port ID type definition.
 */
typedef union {
	struct {
		uint8_t d_id[3];
		uint8_t rsvd_1;
	}r;

	uint32_t	b24 : 24;

#if defined(_BIT_FIELDS_LTOH)
	struct {
		uint8_t al_pa;
		uint8_t area;
		uint8_t domain;
		uint8_t rsvd_1;
	}b;
#elif defined(_BIT_FIELDS_HTOL)
	struct {
		uint8_t domain;
		uint8_t area;
		uint8_t al_pa;
		uint8_t rsvd_1;
	}b;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
} port_id_t;

/*
 * Link list definitions.
 */
typedef struct ql_link {
	struct ql_link	*prev;
	struct ql_link	*next;
	void		*base_address;
	struct ql_head	*head;	/* the queue this link is on */
} ql_link_t;

typedef struct ql_head {
	ql_link_t	*first;
	ql_link_t	*last;
} ql_head_t;

/*
 * ISP request queue context
 */
typedef struct ql_request_q {
	struct cmd_entry	*req_ring_ptr;
	dma_mem_t		req_ring;
	uint32_t		*req_out_shadow_ptr;
	uint32_t		req_out_shadow_ofst;
	uint32_t		mbar_req_in;
	uint32_t		mbar_req_out;
	uint16_t		req_ring_index;
	uint16_t		req_entry_cnt;
	uint16_t		req_q_cnt;	/* # of available entries. */
	uint16_t		req_q_number;
} ql_request_q_t;

/*
 * ISP response queue context
 */
typedef struct ql_response_q {
	struct ql_srb		*status_srb;
	struct sts_entry	*rsp_ring_ptr;
	dma_mem_t		rsp_ring;
	kmutex_t		intr_mutex;
	uint32_t		*rsp_in_shadow_ptr;
	uint32_t		rsp_in_shadow_ofst;
	uint32_t		mbar_rsp_in;
	uint32_t		mbar_rsp_out;
	uint16_t		rsp_ring_index;
	uint16_t		rsp_entry_cnt;
	uint16_t		isp_rsp_index;
	uint16_t		rsp_q_number;
	uint16_t		msi_x_vector;
} ql_response_q_t;

/*
 * This is the per-command structure
 */
typedef struct ql_srb {
	/* Command link. */
	ql_link_t		cmd;

	/* Watchdog link and timer. */
	ql_link_t		wdg;
	time_t			wdg_q_time;
	time_t			init_wdg_q_time;
	uint16_t		isp_timeout;

	/* FCA and FC Transport data. */
	fc_packet_t		*pkt;
	struct ql_adapter_state	*ha;
	uint32_t		magic_number;

	/* unsolicited buffer context. */
	dma_mem_t		ub_buffer;
	uint32_t		ub_type;
	uint32_t		ub_size;

	/* FCP command. */
	fcp_cmd_t		*fcp;

	/* Request sense. */
	uint32_t		request_sense_length;
	caddr_t			request_sense_ptr;

	/* Device queue pointer. */
	struct ql_lun		*lun_queue;

	/* Command state/status flags. */
	volatile uint32_t	flags;

	/* Command IOCB context. */
	void			(*iocb)(struct ql_adapter_state *,
	    ql_request_q_t *, struct ql_srb *, void *);
	struct cmd_entry	*request_ring_ptr;
	uint32_t		handle;
	uint16_t		req_q_number;
	uint16_t		req_cnt;
	uint8_t			retry_count;
	uint8_t			rsp_q_number;
	dma_mem_t		sg_dma;
} ql_srb_t;

#define	SRB_ISP_STARTED		BIT_0 /* Command sent to ISP. */
#define	SRB_ISP_COMPLETED	BIT_1 /* ISP finished with command. */
#define	SRB_RETRY		BIT_2 /* Driver retrying command. */
#define	SRB_POLL		BIT_3 /* Poll for completion. */

#define	SRB_WATCHDOG_ENABLED	BIT_4 /* Command on watchdog list. */
#define	SRB_ELS_PKT		BIT_5 /* Extended Link Services pkt */
#define	SRB_UB_IN_FCA		BIT_6 /* FCA holds unsolicited buffer */
#define	SRB_UB_IN_ISP		BIT_7 /* ISP holds unsolicited buffer */

#define	SRB_UB_CALLBACK		BIT_8 /* Unsolicited callback needed. */
#define	SRB_UB_RSCN		BIT_9 /* Unsolicited RSCN callback. */
#define	SRB_UB_FCP		BIT_10 /* Unsolicited RSCN callback. */
#define	SRB_FCP_CMD_PKT		BIT_11 /* FCP command type packet. */

#define	SRB_FCP_DATA_PKT	BIT_12 /* FCP data type packet. */
#define	SRB_FCP_RSP_PKT		BIT_13 /* FCP response type packet. */
#define	SRB_IP_PKT		BIT_14 /* IP type packet. */
#define	SRB_GENERIC_SERVICES_PKT BIT_15 /* Generic services type packet */

#define	SRB_COMMAND_TIMEOUT	BIT_16 /* Command timed out. */
#define	SRB_ABORTING		BIT_17 /* SRB aborting. */
#define	SRB_IN_DEVICE_QUEUE	BIT_18 /* In Device Queue */
#define	SRB_IN_TOKEN_ARRAY	BIT_19 /* In Token Array */

#define	SRB_UB_FREE_REQUESTED	BIT_20 /* UB Free requested */
#define	SRB_UB_ACQUIRED		BIT_21 /* UB selected for upcall */
#define	SRB_MS_PKT		BIT_22 /* Management Service pkt */

/*
 * This byte will be used to define flags for the LUN on the target.
 * Presently, we have untagged-command as one flag. Others can be
 * added later, if needed.
 */
typedef struct tgt_lun_flags {
	uint8_t
		untagged_pending:1,
		unused_bits:7;
} tgt_lun_flags_t;

#define	QL_IS_UNTAGGED_PENDING(q, lun_num) \
	((q->lun_flags[lun_num].untagged_pending == TRUE) ? 1 : 0)
#define	QL_SET_UNTAGGED_PENDING(q, lun_num) \
	(q->lun_flags[lun_num].untagged_pending = TRUE)
#define	QL_CLEAR_UNTAGGED_PENDING(q, lun_num) \
	(q->lun_flags[lun_num].untagged_pending = FALSE)

/*
 * Fibre Channel LUN Queue structure
 */
typedef struct ql_lun {
	/* Head command link. */
	ql_head_t		cmd;

	struct ql_target	*target_queue;

	uint32_t		flags;

	/* LUN execution throttle. */
	uint16_t		lun_outcnt;

	/* LUN number as reported by REPORT LUNS */
	uint16_t		lun_no;

	/*
	 * Logical unit number in SCSI3 format, also
	 * referred to as FCP lun or FCP entity address.
	 */
	uint64_t		lun_addr;

	ql_link_t		link;
} ql_lun_t;

/*
 * LUN Queue flags
 */
#define	LQF_UNTAGGED_PENDING	BIT_0

/*
 * SCSI standard defined lun addressing methods.
 */
#define	QL_LUN_AM_MASK		0xC0	/* Address Method Mask */
#define	QL_LUN_AM_PDEV		0x00	/* Peripheral device AM */
#define	QL_LUN_AM_FLAT		0x40	/* Flat space AM */
#define	QL_LUN_AM_LUN		0x80	/* Logical unit AM */
#define	QL_LUN_AM_EFLAT		0xC0	/* Extended flat space AM */
#define	QL_LUN_AM_ELUN		0xC0	/* Extended logical unit AM */

/*
 * Fibre Channel Device Queue structure
 */
typedef struct ql_target {
	/* Device queue lock. */
	kmutex_t		mutex;

	volatile uint32_t	flags;
	port_id_t		d_id;
	uint16_t		loop_id;
	volatile uint16_t	outcnt;		/* # of cmds running in ISP */
	uint32_t		iidma_rate;

	/* Device link. */
	ql_link_t		device;

	/* Head watchdog link. */
	ql_head_t		wdg;

	/* Unsolicited buffer IP data. */
	uint32_t		ub_frame_ro;
	uint16_t		ub_sequence_length;
	uint16_t		ub_loop_id;
	uint8_t			ub_total_seg_cnt;
	uint8_t			ub_seq_cnt;
	uint8_t			ub_seq_id;

	/* Port down retry counter. */
	uint16_t		port_down_retry_count;
	uint16_t		qfull_retry_count;

	/* logout sent state */
	uint8_t			logout_sent;

	/* Data from Port database matches machine type. */
	uint8_t			master_state;
	uint8_t			slave_state;
	port_id_t		hard_addr;
	uint8_t			port_name[8];
	uint8_t			node_name[8];
	uint16_t		cmn_features;
	uint16_t		conc_sequences;
	uint16_t		relative_offset;
	uint16_t		class3_recipient_ctl;
	uint16_t		class3_rcv_data_size;
	uint16_t		class3_conc_sequences;
	uint16_t		class3_open_sequences_per_exch;
	uint16_t		prli_payload_length;
	uint16_t		prli_svc_param_word_0;
	uint16_t		prli_svc_param_word_3;

	/* LUN context. */
	ql_head_t		lun_queues;
	ql_lun_t		*last_lun_queue;
} ql_tgt_t;

/*
 * Target Queue flags
 */
#define	TQF_TAPE_DEVICE		BIT_0
#define	TQF_QUEUE_SUSPENDED	BIT_1  /* Queue suspended. */
#define	TQF_FABRIC_DEVICE	BIT_2
#define	TQF_INITIATOR_DEVICE	BIT_3
#define	TQF_RSCN_RCVD		BIT_4
#define	TQF_NEED_AUTHENTICATION	BIT_5
#define	TQF_PLOGI_PROGRS	BIT_6
#define	TQF_IIDMA_NEEDED	BIT_7
#define	TQF_LOGIN_NEEDED	BIT_8

/*
 * Tempoary N_Port information
 */
typedef struct ql_n_port_info {
	uint16_t	n_port_handle;
	uint8_t		port_name[8];	/* Big endian. */
	uint8_t		node_name[8];	/* Big endian. */
	port_id_t	d_id;
} ql_n_port_info_t;

/*
 * iiDMA
 */
#define	IIDMA_RATE_INIT		0xffffffff	/* init state */
#define	IIDMA_RATE_NDEF		0xfffffffe	/* not defined in conf file */
#define	IIDMA_RATE_1GB		0x0
#define	IIDMA_RATE_2GB		0x1
#define	IIDMA_RATE_AUTO		0x2
#define	IIDMA_RATE_4GB		0x3
#define	IIDMA_RATE_8GB		0x4
#define	IIDMA_RATE_16GB		0x5
#define	IIDMA_RATE_32GB		0x6
#define	IIDMA_RATE_10GB		0x13
#define	IIDMA_RATE_MAX		IIDMA_RATE_10GB

/*
 * Kernel statistic structure definitions.
 */
typedef struct ql_device_stat {
	int logouts_recvd;
	int task_mgmt_failures;
	int data_ro_mismatches;
	int dl_len_mismatches;
} ql_device_stat_t;

typedef struct ql_adapter_24xx_stat {
	int version;			/* version of this struct */
	int lip_count;			/* lips forced  */
	int ncmds;			/* outstanding commands */
	ql_adapter_revlvl_t revlvl;	/* adapter revision levels */
	ql_device_stat_t d_stats[MAX_24_FIBRE_DEVICES]; /* per device stats */
} ql_adapter_stat_t;

/*
 * Firmware code segment.
 */
#define	MAX_RISC_CODE_SEGMENTS 3
typedef struct fw_code {
	caddr_t			code;
	uint32_t		addr;
	uint32_t		length;
} ql_fw_code_t;

/* diagnostic els ECHO defines */
#define	QL_ECHO_CMD		0x10000000	/* echo opcode */
#define	QL_ECHO_CMD_LENGTH	220		/* command length */

/* DUMP state flags. */
#define	QL_DUMPING		BIT_0
#define	QL_DUMP_VALID		BIT_1
#define	QL_DUMP_UPLOADED	BIT_2

#define	QL_LOG_ENTRIES	256		/* max # of EL entries */
#define	QL_LOG_LENGTH	128		/* max # of bytes in each EL entry */

typedef struct ql_trace_entry {
	timespec_t	hs_time;	/* high resolution timestamp */
	char		buf[QL_LOG_LENGTH];
} ql_trace_entry_t;

/* per instance based extended logging trace descriptor */
typedef struct el_trace_desc {
	kmutex_t	mutex;
	uint32_t	nentries; /* max number of entries */
	uint16_t	nindex;	/* next index to fill */
	uint32_t	start;	/* starting point */
	uint32_t	end;	/* ending point */
	uint32_t	csize;	/* current filled queue size */
	uint32_t	count;	/* sequence number */
	size_t		trace_buffer_size;
	ql_trace_entry_t *trace_buffer;
} ql_trace_desc_t;

/*
 * NVRAM cache descriptor.
 */
typedef struct nvram_cache_desc {
	uint32_t	valid;
	uint32_t	size;
	void		*cache;
} nvram_cache_desc_t;

/*
 * Plogi retry parameters
 */
typedef struct plogi_params_desc {
	uint32_t	retry_cnt;
	uint32_t	retry_dly_usec;
} plogi_params_desc_t;

/*
 * ql attach progress indication
 */
#define	QL_SOFT_STATE_ALLOCED		BIT_0
#define	QL_REGS_MAPPED			BIT_1
#define	QL_HBA_BUFFER_SETUP		BIT_2
#define	QL_MUTEX_CV_INITED		BIT_3
#define	QL_INTR_ADDED			BIT_4
#define	QL_CONFIG_SPACE_SETUP		BIT_5
#define	QL_TASK_DAEMON_STARTED		BIT_6
#define	QL_KSTAT_CREATED		BIT_7
#define	QL_MINOR_NODE_CREATED		BIT_8
#define	QL_FCA_TRAN_ALLOCED		BIT_9
#define	QL_FCA_ATTACH_DONE		BIT_10
#define	QL_IOMAP_IOBASE_MAPPED		BIT_11
#define	QL_N_PORT_INFO_CREATED		BIT_12
#define	QL_DB_IOBASE_MAPPED		BIT_13
#define	QL_FCA_INIT_FM			BIT_14
#define	QL_NVRAM_CACHE_CREATED		BIT_15
#define	QL_PLOGI_PARAMS_CREATED		BIT_16

/* Device queue head list size (based on AL_PA address). */
#define	DEVICE_HEAD_LIST_SIZE	0x81

struct legacy_intr_set {
	uint32_t	int_vec_bit;
	uint32_t	tgt_status_reg;
	uint32_t	tgt_mask_reg;
	uint32_t	pci_int_reg;
};

/* Returned Mailbox registers. */
typedef struct ql_mbx_data {
	uint16_t	mb[MAX_MBOX_COUNT];
} ql_mbx_data_t;

typedef struct ql_ledstate {
	uint32_t	BeaconState;
	uint32_t	LEDflags;
	uint32_t	flags;
	uint32_t	led_blink_on;
	uint32_t	select;
	ql_mbx_data_t	cfg;
} ql_ledstate_t;

/*
 * Adapter state structure.
 */
typedef struct ql_adapter_state {
	ql_link_t		hba;

	kmutex_t		mutex;
	volatile uint64_t	flags;			/* State flags. */
	uint32_t		state;
	port_id_t		d_id;
	uint16_t		loop_id;
	uint16_t		sfp_stat;
	uint16_t		idle_timer;
	uint16_t		r_a_tov;	    /* 2 * R_A_TOV + 5 */
	uint8_t			topology;
	uint8_t			bbcr_runtime;
	uint8_t			bbcr_initial;
	uint8_t			loop_down_abort_time;
	uint8_t			port_retry_timer;
	uint8_t			loop_down_timer;
	uint8_t			watchdog_timer;

	/* Task Daemon context. */
	ql_head_t		unsol_callback_queue;
	ddi_taskq_t		*driver_thread_taskq;
	kmutex_t		task_daemon_mutex;
	kcondvar_t		cv_task_daemon;
	kcondvar_t		cv_dr_suspended;
	volatile uint64_t	task_daemon_flags;
	uint32_t		driver_thread_awake;
	uint64_t		df;
	uint64_t		sf;
	uint64_t		cf;

	/* Completion thread context */
	ddi_taskq_t		*completion_taskq;
	ql_head_t		comp_q;
	kmutex_t		comp_q_mutex;
	kcondvar_t		cv_comp_thread;
	uint8_t			comp_thds_active;
	uint8_t			comp_thds_awake;
	uint8_t			completion_thds;

	/* Interrupt context. */
	ddi_iblock_cookie_t	iblock_cookie;
	ddi_intr_handle_t	*htable;
	uint32_t		hsize;
	int32_t			intr_cnt;
	void			*intr_pri;
	int32_t			intr_cap;
	uint32_t		iflags;
	volatile uint8_t	intr_claimed;
	uint8_t			mq_msix_vectors;
	uint8_t			interrupt_count;

	/* Outstanding ISP commands. */
	ql_head_t		pending_cmds;
	ql_srb_t		**outstanding_cmds;
	uint16_t		osc_index;
	uint16_t		osc_max_cnt;

	/* ISP request queue context. */
	kmutex_t		req_ring_mutex;
	ql_request_q_t		*req_q[2];

	/* ISP response queue context. */
	ql_response_q_t		**rsp_queues;
	uint32_t		rsp_queues_size;
	uint8_t			rsp_queues_cnt;
	uint8_t			rsp_q_number;
	uint8_t			io_min_rsp_q_number;

	/* IP receive buffer queue context. */
	ql_tgt_t		*rcv_dev_q;
	dma_mem_t		rcv_ring;
	struct rcvbuf		*rcvbuf_ring_ptr;
	uint16_t		rcvbuf_ring_index;

	/* Mailbox context. */
	kmutex_t		mbx_mutex;
	struct mbx_cmd		*mcp;
	kcondvar_t		cv_mbx_wait;
	kcondvar_t		cv_mbx_intr;
	volatile uint8_t	mailbox_flags;

	/* Unsolicited buffer data. */
	uint16_t		ub_outcnt;
	uint8_t			ub_seq_id;
	uint8_t			ub_command_count;
	uint8_t			ub_notify_count;
	uint32_t		ub_allocated;
	kmutex_t		ub_mutex;
	kcondvar_t		cv_ub;
	fc_unsol_buf_t		**ub_array;

	/* Head of device queue list. */
	ql_head_t		*dev;

	/* Kernel statistics. */
	kstat_t			*k_stats;
	ql_adapter_stat_t	*adapter_stats;

	/* PCI context */
	ddi_acc_handle_t	pci_handle;	/* config space */
	ddi_acc_handle_t	dev_handle;
	caddr_t			iobase;
	ddi_acc_handle_t	iomap_dev_handle;
	caddr_t			iomap_iobase;
	ddi_acc_handle_t	mbar_dev_handle;
	caddr_t			mbar;
	uint32_t		mbar_size;
	uint32_t		mbar_queue_offset;
	uint16_t		device_id;
	uint16_t		subsys_id;
	uint16_t		subven_id;
	uint16_t		ven_id;
	uint16_t		pci_max_read_req;
	uint8_t			rev_id;
	uint8_t			pci_function_number;

	/* Solaris adapter configuration data */
	dev_info_t		*dip;
	fc_fca_tran_t		*tran;
	uint32_t		instance;
	int8_t			*devpath;
	uint32_t		fru_hba_index;
	uint32_t		fru_port_index;
	uint8_t			adapInfo[18];

	/* Adapter context */
	la_els_logi_t		loginparams;
	fc_fca_bind_info_t	bind_info;
	ddi_modhandle_t		fw_module;
	uint32_t		fw_major_version;
	uint32_t		fw_minor_version;
	uint32_t		fw_subminor_version;
	uint32_t		fw_attributes;
	uint32_t		fw_ext_attributes;
	uint32_t		fw_ext_memory_end;
	uint32_t		fw_ext_memory_size;
	uint32_t		fw_shared_ram_start;
	uint32_t		fw_shared_ram_end;
	uint32_t		fw_ddr_ram_start;
	uint32_t		fw_ddr_ram_end;
	uint32_t		parity_pause_errors;
	boolean_t		log_parity_pause;
	uint32_t		fw_class;
	uint16_t		fw_state[7];
	uint16_t		rom_status;
	ql_ledstate_t		ledstate;
	uint16_t		parity_hccr_err;
	uint32_t		parity_stat_err;
	reg_off_t		*reg_off;
	caddr_t			risc_code;
	uint32_t		risc_code_size;
	ql_fw_code_t		risc_fw[MAX_RISC_CODE_SEGMENTS];
	uint32_t		risc_dump_size;
	void			(*fcp_cmd)(struct ql_adapter_state *,
				ql_request_q_t *, ql_srb_t *, void *);
	void			(*ip_cmd)(struct ql_adapter_state *,
				ql_request_q_t *, ql_srb_t *, void *);
	void			(*ms_cmd)(struct ql_adapter_state *,
				ql_request_q_t *, ql_srb_t *, void *);
	void			(*els_cmd)(struct ql_adapter_state *,
				ql_request_q_t *, ql_srb_t *, void *);
	uint8_t			cmd_segs;
	uint8_t			cmd_cont_segs;

	/* NVRAM configuration data */
	uint64_t		cfg_flags;
	ql_comb_init_cb_t	init_ctrl_blk;
	ql_comb_ip_init_cb_t	ip_init_ctrl_blk;
	uint32_t		fw_transfer_size;
	uint16_t		adapter_features;
	uint16_t		execution_throttle;
	uint16_t		port_down_retry_count;
	uint16_t		serdes_param[4];
	uint16_t		maximum_luns_per_target;
	uint8_t			port_down_retry_delay;
	uint8_t			qfull_retry_count;
	uint8_t			qfull_retry_delay;
	uint8_t			loop_reset_delay;

	/* Power management context. */
	kmutex_t		pm_mutex;
	uint32_t		pm_busy;
	uint8_t			power_level;
	uint8_t			pm_capable;
	uint8_t			config_saved;
	uint8_t			lip_on_panic;

	/* sbus card data */
	caddr_t			sbus_fpga_iobase;
	ddi_acc_handle_t	sbus_fpga_dev_handle;
	ddi_acc_handle_t	sbus_config_handle;
	caddr_t			sbus_config_base;

	/* XIOCTL context pointer. */
	struct ql_xioctl	*xioctl;

	struct ql_fcache	*fcache;
	int8_t			*vcache;
	nvram_cache_desc_t	*nvram_cache;

	/* f/w dump mutex */
	uint32_t		ql_dump_size;
	uint32_t		ql_dump_state;
	void			*ql_dump_ptr;
	kmutex_t		dump_mutex;

	uint8_t			fwwait;

	dma_mem_t		fwexttracebuf;		/* extended trace  */
	dma_mem_t		fwfcetracebuf;		/* event trace */
	ql_mbx_data_t		fw_fce_trace_enable;
	uint32_t		fwfcetraceopt;
	uint32_t		flash_errlog_start;	/* 32bit word addr */
	uint32_t		flash_errlog_ptr;	/* 32bit word addr */
	uint8_t			send_plogi_timer;

	/* Plogi retry parameters */
	plogi_params_desc_t	*plogi_params;

	/* Virtual port context. */
	fca_port_attrs_t	*pi_attrs;
	struct ql_adapter_state	*pha;
	struct ql_adapter_state *vp_next;
	uint8_t			vp_index;
	uint8_t			max_vports;

	uint16_t		free_loop_id;

	/* Tempoary N_Port information */
	struct ql_n_port_info	*n_port;

	ql_trace_desc_t		*ql_trace_desc;

	uint32_t		flash_data_addr;
	uint32_t		flash_fw_addr;
	uint32_t		flash_golden_fw_addr;
	uint32_t		boot_code_addr;
	uint32_t		flash_vpd_addr;
	uint32_t		flash_nvram_addr;
	uint32_t		flash_desc_addr;
	uint32_t		mpi_capability_list;
	uint8_t			phy_fw_major_version;
	uint8_t			phy_fw_minor_version;
	uint8_t			phy_fw_subminor_version;
	uint8_t			mpi_fw_major_version;
	uint8_t			mpi_fw_minor_version;
	uint8_t			mpi_fw_subminor_version;

	uint16_t		idc_mb[8];
	uint8_t			idc_restart_timer;

	/* VLAN ID and MAC address */
	uint8_t			fcoe_vnport_mac[6];
	uint16_t		fabric_params;
	uint16_t		fcoe_vlan_id;
	uint16_t		fcoe_fcf_idx;

	/* NetXen context */
	ddi_acc_handle_t	db_dev_handle;
	caddr_t			db_iobase;
	caddr_t			nx_pcibase;	/* BAR0 base I/O address */
	uint32_t		qdr_sn_window;
	uint32_t		*nx_req_in;
	caddr_t			db_read;
	uint32_t		pci_bus_addr;
	struct legacy_intr_set	nx_legacy_intr;
	uint32_t		bootloader_size;
	uint32_t		bootloader_addr;
	uint32_t		flash_fw_size;
	uint32_t		dev_state;
	uint32_t		fw_heartbeat_counter;
	dma_mem_t		dmp_template;
	uint32_t		md_capture_mask;
	uint32_t		md_capture_size;
	uint16_t		iidma_rate;
	uint8_t			function_number;
	uint8_t			timeout_cnt;
	uint8_t			seconds_since_last_heartbeat;

	/* default dma attributes */
	ddi_dma_attr_t		bit32_io_dma_attr;
	ddi_dma_attr_t		bit64_io_dma_attr;

	ddi_dma_attr_t		io_dma_attr;
	ddi_dma_attr_t		fcsm_cmd_dma_attr;
	ddi_dma_attr_t		fcsm_rsp_dma_attr;
	ddi_dma_attr_t		fcip_cmd_dma_attr;
	ddi_dma_attr_t		fcip_rsp_dma_attr;
	ddi_dma_attr_t		fcp_cmd_dma_attr;
	ddi_dma_attr_t		fcp_rsp_dma_attr;
	ddi_dma_attr_t		fcp_data_dma_attr;

	int			fm_capabilities;
	uint16_t		errlog[4];
} ql_adapter_state_t;

/*
 * adapter state flags
 */
#define	FCA_BOUND			(uint64_t)BIT_0
#define	QL_OPENED			(uint64_t)BIT_1
#define	ONLINE				(uint64_t)BIT_2
#define	INTERRUPTS_ENABLED		(uint64_t)BIT_3

#define	ABORT_CMDS_LOOP_DOWN_TMO	(uint64_t)BIT_4
#define	POINT_TO_POINT			(uint64_t)BIT_5
#define	IP_ENABLED			(uint64_t)BIT_6
#define	IP_INITIALIZED			(uint64_t)BIT_7

#define	MENLO_LOGIN_OPERATIONAL		(uint64_t)BIT_8
#define	ADAPTER_SUSPENDED		(uint64_t)BIT_9
#define	FW_DUMP_NEEDED			(uint64_t)BIT_10
#define	PARITY_ERROR			(uint64_t)BIT_11

#define	FLASH_ERRLOG_MARKER		(uint64_t)BIT_12
#define	VP_ENABLED			(uint64_t)BIT_13
#define	FDISC_ENABLED			(uint64_t)BIT_14
#define	MULTI_QUEUE			(uint64_t)BIT_15

#define	MPI_RESET_NEEDED		(uint64_t)BIT_16
#define	VP_ID_NOT_ACQUIRED		(uint64_t)BIT_17
#define	IDC_STALL_NEEDED		(uint64_t)BIT_18
#define	POLL_INTR			(uint64_t)BIT_19

#define	IDC_RESTART_NEEDED		(uint64_t)BIT_20
#define	IDC_ACK_NEEDED			(uint64_t)BIT_21
#define	LOOPBACK_ACTIVE			(uint64_t)BIT_22
#define	QUEUE_SHADOW_PTRS		(uint64_t)BIT_23

#define	NO_INTR_HANDSHAKE		(uint64_t)BIT_24
#define	COMP_THD_TERMINATE		(uint64_t)BIT_25
#define	DISABLE_NIC_FW_DMP		(uint64_t)BIT_26
#define	MULTI_CHIP_ADAPTER		(uint64_t)BIT_27

/*
 * task daemon flags
 */
#define	TASK_DAEMON_STOP_FLG		(uint64_t)BIT_0
#define	TASK_DAEMON_SLEEPING_FLG	(uint64_t)BIT_1
#define	TASK_DAEMON_ALIVE_FLG		(uint64_t)BIT_2
#define	TASK_DAEMON_IDLE_CHK_FLG	(uint64_t)BIT_3

#define	SUSPENDED_WAKEUP_FLG		(uint64_t)BIT_4
#define	FC_STATE_CHANGE			(uint64_t)BIT_5
#define	NEED_UNSOLICITED_BUFFERS	(uint64_t)BIT_6
#define	MARKER_NEEDED			(uint64_t)BIT_7

#define	MARKER_ACTIVE			(uint64_t)BIT_8
#define	ISP_ABORT_NEEDED		(uint64_t)BIT_9
#define	ABORT_ISP_ACTIVE		(uint64_t)BIT_10
#define	LOOP_RESYNC_NEEDED		(uint64_t)BIT_11

#define	LOOP_RESYNC_ACTIVE		(uint64_t)BIT_12
#define	LOOP_DOWN			(uint64_t)BIT_13
#define	DRIVER_STALL			(uint64_t)BIT_14
#define	COMMAND_WAIT_NEEDED		(uint64_t)BIT_15

#define	COMMAND_WAIT_ACTIVE		(uint64_t)BIT_16
#define	STATE_ONLINE			(uint64_t)BIT_17
#define	ABORT_QUEUES_NEEDED		(uint64_t)BIT_18
#define	TASK_DAEMON_STALLED_FLG		(uint64_t)BIT_19

#define	SEND_PLOGI			(uint64_t)BIT_20
#define	FIRMWARE_UP			(uint64_t)BIT_21
#define	IDC_POLL_NEEDED			(uint64_t)BIT_22
#define	FIRMWARE_LOADED			(uint64_t)BIT_23

#define	RSCN_UPDATE_NEEDED		(uint64_t)BIT_24
#define	HANDLE_PORT_BYPASS_CHANGE	(uint64_t)BIT_25
#define	PORT_RETRY_NEEDED		(uint64_t)BIT_26
#define	TASK_DAEMON_POWERING_DOWN	(uint64_t)BIT_27

#define	TD_IIDMA_NEEDED			(uint64_t)BIT_28
#define	WATCHDOG_NEEDED			(uint64_t)BIT_29
#define	LED_BLINK			(uint64_t)BIT_30

#define	DTF_EL_MSG_SKIP_FLGS	(IDC_POLL_NEEDED | WATCHDOG_NEEDED | \
    TASK_DAEMON_IDLE_CHK_FLG | LED_BLINK)
/*
 * Mailbox flags
 */
#define	MBX_WANT_FLG				BIT_0
#define	MBX_BUSY_FLG				BIT_1
#define	MBX_INTERRUPT				BIT_2
#define	MBX_ABORT				BIT_3

/*
 * Configuration flags
 */
#define	CFG_CTRL_27XX				(uint64_t)BIT_0
#define	CFG_ENABLE_64BIT_ADDRESSING		(uint64_t)BIT_1
#define	CFG_ENABLE_LIP_RESET			(uint64_t)BIT_2
#define	CFG_ENABLE_FULL_LIP_LOGIN		(uint64_t)BIT_3

#define	CFG_ENABLE_TARGET_RESET			(uint64_t)BIT_4
#define	CFG_ENABLE_LINK_DOWN_REPORTING		(uint64_t)BIT_5
#define	CFG_LR_SUPPORT				(uint64_t)BIT_6
#define	CFG_ENABLE_FCP_2_SUPPORT		(uint64_t)BIT_7

#define	CFG_CTRL_83XX				(uint64_t)BIT_8
#define	CFG_SBUS_CARD				(uint64_t)BIT_9
#define	CFG_CTRL_23XX				(uint64_t)BIT_10
#define	CFG_CTRL_63XX				(uint64_t)BIT_11

#define	CFG_CTRL_22XX				(uint64_t)BIT_12
#define	CFG_CTRL_24XX				(uint64_t)BIT_13
#define	CFG_CTRL_25XX				(uint64_t)BIT_14
#define	CFG_ENABLE_EXTENDED_LOGGING		(uint64_t)BIT_15

#define	CFG_DISABLE_RISC_CODE_LOAD		(uint64_t)BIT_16
#define	CFG_SET_CACHE_LINE_SIZE_1		(uint64_t)BIT_17
#define	CFG_CTRL_MENLO				(uint64_t)BIT_18
#define	CFG_EXT_FW_INTERFACE			(uint64_t)BIT_19

#define	CFG_LOAD_FLASH_FW			(uint64_t)BIT_20
#define	CFG_DUMP_MAILBOX_TIMEOUT		(uint64_t)BIT_21
#define	CFG_DUMP_ISP_SYSTEM_ERROR		(uint64_t)BIT_22
#define	CFG_DUMP_DRIVER_COMMAND_TIMEOUT		(uint64_t)BIT_23

#define	CFG_DUMP_LOOP_OFFLINE_TIMEOUT		(uint64_t)BIT_24
#define	CFG_ENABLE_FWEXTTRACE			(uint64_t)BIT_25
#define	CFG_ENABLE_FWFCETRACE			(uint64_t)BIT_26
#define	CFG_CTRL_80XX				(uint64_t)BIT_27

#define	CFG_CTRL_81XX				(uint64_t)BIT_28
#define	CFG_CTRL_82XX				(uint64_t)BIT_29
#define	CFG_FAST_TIMEOUT			(uint64_t)BIT_30

#define	CFG_CTRL_2363		(CFG_CTRL_23XX | CFG_CTRL_63XX)
#define	CFG_CTRL_2425		(CFG_CTRL_24XX | CFG_CTRL_25XX)
#define	CFG_CTRL_2783		(CFG_CTRL_27XX | CFG_CTRL_83XX)
#define	CFG_CTRL_8081		(CFG_CTRL_80XX | CFG_CTRL_81XX)
#define	CFG_CTRL_278083		(CFG_CTRL_80XX | CFG_CTRL_2783)
#define	CFG_CTRL_27808183	(CFG_CTRL_8081 | CFG_CTRL_2783)
#define	CFG_CTRL_2527808183	(CFG_CTRL_25XX | CFG_CTRL_27808183)
#define	CFG_CTRL_252780818283	(CFG_CTRL_82XX | CFG_CTRL_2527808183)

#define	CFG_ISP_FW_TYPE_1	(CFG_CTRL_22XX | CFG_CTRL_2363)
#define	CFG_ISP_FW_TYPE_2	(CFG_CTRL_24XX | CFG_CTRL_252780818283)
#define	CFG_FCIP_TYPE_1		(CFG_CTRL_22XX | CFG_CTRL_23XX)
#define	CFG_FCIP_SUPPORT	(CFG_FCIP_TYPE_1 | CFG_CTRL_24XX)
#define	CFG_FCOE_SUPPORT	(CFG_CTRL_82XX | CFG_CTRL_8081)
#define	CFG_N2N_SUPPORT		(CFG_CTRL_2425 | CFG_CTRL_2783)
#define	CFG_FC_TYPE_1		(CFG_CTRL_22XX | CFG_CTRL_2363)
#define	CFG_FC_TYPE_2		(CFG_CTRL_2425 | CFG_CTRL_2783)
#define	CFG_FC_TYPE		(CFG_FC_TYPE_1 | CFG_FC_TYPE_2)
#define	CFG_NO_INTR_HSHAKE_SUP	(CFG_CTRL_27808183)
#define	CFG_MWB_4096_SUPPORT	(CFG_CTRL_2425 | CFG_CTRL_81XX)
#define	CFG_IIDMA_SUPPORT	(CFG_CTRL_8081 | CFG_FC_TYPE_2)
#define	CFG_FLASH_ACC_SUPPORT	(CFG_CTRL_27808183)
#define	CFG_FLASH_DMA_SUPPORT	(CFG_CTRL_2527808183)
#define	CFG_LOOP_POINT_SUPPORT	(CFG_CTRL_8081)
#define	CFG_LB_ECHO_SUPPORT	(CFG_CTRL_2363 | CFG_ISP_FW_TYPE_2)
#define	CFG_SET_LEDS_SUPPORT	(CFG_CTRL_2363 | CFG_ISP_FW_TYPE_2)
#define	CFG_SERDES_SUPPORT	(CFG_CTRL_2783)
#define	CFG_BBCR_SUPPORT	(CFG_CTRL_2783)
#define	CFG_MSI_SUPPORT		(CFG_CTRL_2425 | CFG_CTRL_81XX | CFG_CTRL_82XX)


#define	CFG_IST(ha, cfgflags)	(ha->cfg_flags & (cfgflags))

/*
 * Interrupt configuration flags
 */
#define	IFLG_INTR_LEGACY			BIT_0
#define	IFLG_INTR_FIXED				BIT_1
#define	IFLG_INTR_MSI				BIT_2
#define	IFLG_INTR_MSIX				BIT_3

#define	IFLG_INTR_AIF	(IFLG_INTR_MSI | IFLG_INTR_FIXED | IFLG_INTR_MSIX)

/*
 * Macros to help code, maintain, etc.
 */
#define	LSB(x)		(uint8_t)(x)
#define	MSB(x)		(uint8_t)((uint16_t)(x) >> 8)
#define	MSW(x)		(uint16_t)((uint32_t)(x) >> 16)
#define	LSW(x)		(uint16_t)(x)
#define	LSD(x)		(uint32_t)(x)
#define	MSD(x)		(uint32_t)((uint64_t)(x) >> 32)

#define	LONG_TO_LLONG(lsl, msl) (uint64_t)((uint64_t)(msl) << 32 | \
	(uint32_t)(lsl))
#define	SHORT_TO_LONG(lsw, msw) (uint32_t)((uint32_t)msw << 16 | (uint16_t)lsw)
#define	CHAR_TO_SHORT(lsb, msb) (uint16_t)((uint16_t)msb << 8 | (uint8_t)lsb)
#define	CHAR_TO_LONG(lsb, b1, b2, msb) \
	(uint32_t)(SHORT_TO_LONG(CHAR_TO_SHORT(lsb, b1), \
	CHAR_TO_SHORT(b2, msb)))

/* Little endian machine correction defines. */
#ifdef _LITTLE_ENDIAN
#define	LITTLE_ENDIAN_16(x)
#define	LITTLE_ENDIAN_24(x)
#define	LITTLE_ENDIAN_32(x)
#define	LITTLE_ENDIAN_64(x)
#define	LITTLE_ENDIAN(bp, bytes)
#define	BIG_ENDIAN_16(x)	ql_chg_endian((uint8_t *)x, 2)
#define	BIG_ENDIAN_24(x)	ql_chg_endian((uint8_t *)x, 3)
#define	BIG_ENDIAN_32(x)	ql_chg_endian((uint8_t *)x, 4)
#define	BIG_ENDIAN_64(x)	ql_chg_endian((uint8_t *)x, 8)
#define	BIG_ENDIAN(bp, bytes)	ql_chg_endian((uint8_t *)bp, bytes)
#endif /* _LITTLE_ENDIAN */

/* Big endian machine correction defines. */
#ifdef _BIG_ENDIAN
#define	LITTLE_ENDIAN_16(x)		ql_chg_endian((uint8_t *)x, 2)
#define	LITTLE_ENDIAN_24(x)		ql_chg_endian((uint8_t *)x, 3)
#define	LITTLE_ENDIAN_32(x)		ql_chg_endian((uint8_t *)x, 4)
#define	LITTLE_ENDIAN_64(x)		ql_chg_endian((uint8_t *)x, 8)
#define	LITTLE_ENDIAN(bp, bytes)	ql_chg_endian((uint8_t *)bp, bytes)
#define	BIG_ENDIAN_16(x)
#define	BIG_ENDIAN_24(x)
#define	BIG_ENDIAN_32(x)
#define	BIG_ENDIAN_64(x)
#define	BIG_ENDIAN(bp, bytes)
#endif /* _BIG_ENDIAN */

#define	LOCAL_LOOP_ID(x)	(x <= LAST_LOCAL_LOOP_ID)

#define	FABRIC_LOOP_ID(x)	(x == FL_PORT_LOOP_ID || \
    x == SIMPLE_NAME_SERVER_LOOP_ID)

#define	SNS_LOOP_ID(x)		(x >= SNS_FIRST_LOOP_ID && \
    x <= SNS_LAST_LOOP_ID)

#define	BROADCAST_LOOP_ID(x)	(x == IP_BROADCAST_LOOP_ID)

#define	VALID_LOOP_ID(x)	(LOCAL_LOOP_ID(x) || SNS_LOOP_ID(x) || \
    FABRIC_LOOP_ID(x) || BROADCAST_LOOP_ID(x))

#define	VALID_N_PORT_HDL(x)	(x <= LAST_N_PORT_HDL || \
	(x >= SNS_24XX_HDL && x <= BROADCAST_24XX_HDL))

#define	VALID_DEVICE_ID(ha, x)	(CFG_IST(ha, CFG_ISP_FW_TYPE_2) ? \
	VALID_N_PORT_HDL(x) : VALID_LOOP_ID(x))

#define	VALID_TARGET_ID(ha, x)	(CFG_IST(ha, CFG_ISP_FW_TYPE_2) ? \
	(x <= LAST_N_PORT_HDL) : (LOCAL_LOOP_ID(x) || SNS_LOOP_ID(x)))

#define	RESERVED_LOOP_ID(ha, x) (CFG_IST(ha, CFG_ISP_FW_TYPE_2) ? \
	(x > LAST_N_PORT_HDL && x <= FL_PORT_24XX_HDL) : \
	(x >= FL_PORT_LOOP_ID && x <= SIMPLE_NAME_SERVER_LOOP_ID))

#define	QL_LOOP_TRANSITION	(MARKER_NEEDED | MARKER_ACTIVE | \
				ISP_ABORT_NEEDED | ABORT_ISP_ACTIVE | \
				LOOP_RESYNC_NEEDED | LOOP_RESYNC_ACTIVE | \
				COMMAND_WAIT_NEEDED | COMMAND_WAIT_ACTIVE)

#define	LOOP_RECONFIGURE(ha)	(ha->task_daemon_flags & (QL_LOOP_TRANSITION | \
				DRIVER_STALL))

#define	DRIVER_SUSPENDED(ha)	(ha->task_daemon_flags & (LOOP_DOWN | \
				QL_LOOP_TRANSITION | DRIVER_STALL))

#define	LOOP_NOT_READY(ha)	(ha->task_daemon_flags & (QL_LOOP_TRANSITION | \
				LOOP_DOWN))

#define	LOOP_READY(ha)		(LOOP_NOT_READY(ha) == 0)

#define	QL_TASK_PENDING(ha)	( \
    ha->task_daemon_flags & (QL_LOOP_TRANSITION | ABORT_QUEUES_NEEDED | \
    PORT_RETRY_NEEDED) || ha->unsol_callback_queue.first != NULL)

#define	QL_DAEMON_NOT_ACTIVE(ha)	( \
	!(ha->task_daemon_flags & TASK_DAEMON_ALIVE_FLG) || \
	ha->task_daemon_flags & (TASK_DAEMON_SLEEPING_FLG | \
	TASK_DAEMON_STOP_FLG))

#define	QL_ABORTED_SRB(ha)	((ql_srb_t *)ha)

#define	INTERRUPT_PENDING(ha)	(CFG_IST(ha, CFG_CTRL_82XX) ? \
				RD32_IO_REG(ha, nx_risc_int) & NX_RISC_INT : \
				RD16_IO_REG(ha, istatus) & RISC_INT)
/*
 * Locking Macro Definitions
 */
#define	GLOBAL_STATE_LOCK()		mutex_enter(&ql_global_mutex)
#define	GLOBAL_STATE_UNLOCK()		mutex_exit(&ql_global_mutex)

#define	GLOBAL_TIMER_LOCK()		mutex_enter(&ql_global_timer_mutex)
#define	GLOBAL_TIMER_UNLOCK()		mutex_exit(&ql_global_timer_mutex)

#define	TRY_DEVICE_QUEUE_LOCK(q)	mutex_tryenter(&q->mutex)
#define	DEVICE_QUEUE_LOCK(q)		mutex_enter(&q->mutex)
#define	DEVICE_QUEUE_UNLOCK(q)		mutex_exit(&q->mutex)

#define	TRY_MBX_REGISTER_LOCK(ha)	mutex_tryenter(&ha->pha->mbx_mutex)
#define	MBX_REGISTER_LOCK_OWNER(ha)	mutex_owner(&ha->pha->mbx_mutex)
#define	MBX_REGISTER_LOCK(ha)		mutex_enter(&ha->pha->mbx_mutex)
#define	MBX_REGISTER_UNLOCK(ha)		mutex_exit(&ha->pha->mbx_mutex)

#define	INTR_LOCK(ha)			ql_intr_lock(ha->pha)
#define	INTR_UNLOCK(ha)			ql_intr_unlock(ha->pha)

#define	INDX_INTR_LOCK(ha, i)	mutex_enter(&ha->pha->rsp_queues[i]->intr_mutex)
#define	INDX_INTR_UNLOCK(ha, i)	mutex_exit(&ha->pha->rsp_queues[i]->intr_mutex)

#define	TASK_DAEMON_LOCK(ha)		mutex_enter(&ha->pha->task_daemon_mutex)
#define	TASK_DAEMON_UNLOCK(ha)		mutex_exit(&ha->pha->task_daemon_mutex)

#define	REQUEST_RING_LOCK(ha)		mutex_enter(&ha->pha->req_ring_mutex)
#define	REQUEST_RING_UNLOCK(ha)		mutex_exit(&ha->pha->req_ring_mutex)

#define	COMP_Q_LOCK(ha)			mutex_enter(&ha->pha->comp_q_mutex)
#define	COMP_Q_UNLOCK(ha)		mutex_exit(&ha->pha->comp_q_mutex)

#define	ADAPTER_STATE_LOCK(ha)		mutex_enter(&ha->pha->mutex)
#define	ADAPTER_STATE_UNLOCK(ha)	mutex_exit(&ha->pha->mutex)

#define	QL_DUMP_LOCK(ha)		mutex_enter(&ha->pha->dump_mutex)
#define	QL_DUMP_UNLOCK(ha)		mutex_exit(&ha->pha->dump_mutex)

#define	QL_PM_LOCK(ha)			mutex_enter(&ha->pha->pm_mutex)
#define	QL_PM_UNLOCK(ha)		mutex_exit(&ha->pha->pm_mutex)

#define	QL_UB_LOCK(ha)			mutex_enter(&ha->pha->ub_mutex)
#define	QL_UB_UNLOCK(ha)		mutex_exit(&ha->pha->ub_mutex)

#define	GLOBAL_HW_LOCK()		mutex_enter(&ql_global_hw_mutex)
#define	GLOBAL_HW_UNLOCK()		mutex_exit(&ql_global_hw_mutex)

/*
 * PCI power management control/status register location
 */
#define	QL_PM_CS_REG			0x48

/*
 * ql component
 */
#define	QL_POWER_COMPONENT		0

typedef struct ql_config_space {
	uint16_t	chs_command;
	uint8_t		chs_cache_line_size;
	uint8_t		chs_latency_timer;
	uint8_t		chs_header_type;
	uint8_t		chs_sec_latency_timer;
	uint8_t		chs_bridge_control;
	uint32_t	chs_base0;
	uint32_t	chs_base1;
	uint32_t	chs_base2;
	uint32_t	chs_base3;
	uint32_t	chs_base4;
	uint32_t	chs_base5;
} ql_config_space_t;

#ifdef	USE_DDI_INTERFACES

#define	QL_SAVE_CONFIG_REGS(dip)		pci_save_config_regs(dip)
#define	QL_RESTORE_CONFIG_REGS(dip)		pci_restore_config_regs(dip)

#else /* USE_DDI_INTERFACES */

#define	QL_SAVE_CONFIG_REGS(dip)		ql_save_config_regs(dip)
#define	QL_RESTORE_CONFIG_REGS(dip)		ql_restore_config_regs(dip)

#endif /* USE_DDI_INTERFACES */

/*
 * QL local function return status codes
 */
#define	QL_SUCCESS			0x4000
#define	QL_INVALID_COMMAND		0x4001
#define	QL_INTERFACE_ERROR		0x4002
#define	QL_TEST_FAILED			0x4003
#define	QL_COMMAND_ERROR		0x4005
#define	QL_PARAMETER_ERROR		0x4006
#define	QL_PORT_ID_USED			0x4007
#define	QL_LOOP_ID_USED			0x4008
#define	QL_ALL_IDS_IN_USE		0x4009
#define	QL_NOT_LOGGED_IN		0x400A
#define	QL_LOOP_DOWN			0x400B
#define	QL_LOOP_BACK_ERROR		0x400C
#define	QL_CHECKSUM_ERROR		0x4010
#define	QL_CONSUMED			0x4011

#define	QL_FUNCTION_TIMEOUT		0x100
#define	QL_FUNCTION_PARAMETER_ERROR	0x101
#define	QL_FUNCTION_FAILED		0x102
#define	QL_MEMORY_ALLOC_FAILED		0x103
#define	QL_FABRIC_NOT_INITIALIZED	0x104
#define	QL_LOCK_TIMEOUT			0x105
#define	QL_ABORTED			0x106
#define	QL_FUNCTION_SUSPENDED		0x107
#define	QL_END_OF_DATA			0x108
#define	QL_IP_UNSUPPORTED		0x109
#define	QL_PM_ERROR			0x10a
#define	QL_DATA_EXISTS			0x10b
#define	QL_NOT_SUPPORTED		0x10c
#define	QL_MEMORY_FULL			0x10d
#define	QL_FW_NOT_SUPPORTED		0x10e
#define	QL_FWMODLOAD_FAILED		0x10f
#define	QL_FWSYM_NOT_FOUND		0x110
#define	QL_LOGIN_NOT_SUPPORTED		0x111

/*
 * SBus card FPGA register offsets.
 */
#define	FPGA_CONF		0x100
#define	FPGA_EEPROM_LOADDR	0x102
#define	FPGA_EEPROM_HIADDR	0x104
#define	FPGA_EEPROM_DATA	0x106
#define	FPGA_REVISION		0x108

#define	SBUS_FLASH_WRITE_ENABLE	0x0080
#define	QL_SBUS_FCODE_SIZE	0x30000
#define	QL_FCODE_OFFSET		0
#define	QL_FPGA_SIZE		0x40000
#define	QL_FPGA_OFFSET		0x40000

#define	READ_PORT_ID(addr)	((uint32_t)((((uint32_t)((addr)[0])) << 16) | \
					(((uint32_t)((addr)[1])) << 8) | \
					(((uint32_t)((addr)[2])))))
#define	READ_PORT_NAME(addr) ((u_longlong_t)((((uint64_t)((addr)[0])) << 56) | \
					(((uint64_t)((addr)[1])) << 48) | \
					(((uint64_t)((addr)[2])) << 40) | \
					(((uint64_t)((addr)[3])) << 32) | \
					(((uint64_t)((addr)[4])) << 24) | \
					(((uint64_t)((addr)[5])) << 16) | \
					(((uint64_t)((addr)[6])) << 8) | \
					(((uint64_t)((addr)[7])))))
/*
 * Structure used to associate cmds with strings which describe them.
 */
typedef struct cmd_table_entry {
	uint16_t cmd;
	char    *string;
} cmd_table_t;

/*
 * ELS command table initializer
 */
#define	ELS_CMD_TABLE()					\
{							\
	{LA_ELS_RJT, "LA_ELS_RJT"},			\
	{LA_ELS_ACC, "LA_ELS_ACC"},			\
	{LA_ELS_PLOGI, "LA_ELS_PLOGI"},			\
	{LA_ELS_PDISC, "LA_ELS_PDISC"},			\
	{LA_ELS_FLOGI, "LA_ELS_FLOGI"},			\
	{LA_ELS_FDISC, "LA_ELS_FDISC"},			\
	{LA_ELS_LOGO, "LA_ELS_LOGO"},			\
	{LA_ELS_PRLI, "LA_ELS_PRLI"},			\
	{LA_ELS_PRLO, "LA_ELS_PRLO"},			\
	{LA_ELS_ADISC, "LA_ELS_ADISC"},			\
	{LA_ELS_LINIT, "LA_ELS_LINIT"},			\
	{LA_ELS_LPC, "LA_ELS_LPC"},			\
	{LA_ELS_LSTS, "LA_ELS_LSTS"},			\
	{LA_ELS_SCR, "LA_ELS_SCR"},			\
	{LA_ELS_RSCN, "LA_ELS_RSCN"},			\
	{LA_ELS_FARP_REQ, "LA_ELS_FARP_REQ"},		\
	{LA_ELS_FARP_REPLY, "LA_ELS_FARP_REPLY"},	\
	{LA_ELS_RLS, "LA_ELS_RLS"},			\
	{LA_ELS_RNID, "LA_ELS_RNID"},			\
	{0, NULL}					\
}

/*
 * ELS Passthru IOCB data segment descriptor.
 */
typedef struct data_seg_desc {
	uint32_t addr[2];
	uint32_t length;
} data_seg_desc_t;

/*
 * ELS descriptor used to abstract the hosts fibre channel packet
 * from the ISP ELS code.
 */
typedef struct els_desc {
	uint8_t			els;		/* the ELS command code */
	ddi_acc_handle_t	els_handle;
	uint16_t		n_port_handle;
	port_id_t		d_id;
	port_id_t		s_id;
	uint16_t		control_flags;
	uint32_t		cmd_byte_count;
	uint32_t		rsp_byte_count;
	data_seg_desc_t		tx_dsd;		/* FC frame payload */
	data_seg_desc_t		rx_dsd;		/* ELS resp payload buffer */
} els_descriptor_t;

typedef struct prli_svc_pram_resp_page {
	uint8_t		type_code;
	uint8_t		type_code_ext;
	uint16_t	prli_resp_flags;
	uint32_t	orig_process_associator;
	uint32_t	resp_process_associator;
	uint32_t	common_parameters;
} prli_svc_pram_resp_page_t;

/*
 * PRLI accept Service Parameter Page Word 3
 */
#define	PRLI_W3_WRITE_FCP_XFR_RDY_DISABLED	BIT_0
#define	PRLI_W3_READ_FCP_XFR_RDY_DISABLED	BIT_1
#define	PRLI_W3_OBSOLETE_BIT_2			BIT_2
#define	PRLI_W3_OBSOLETE_BIT_3			BIT_3
#define	PRLI_W3_TARGET_FUNCTION			BIT_4
#define	PRLI_W3_INITIATOR_FUNCTION		BIT_5
#define	PRLI_W3_DATA_OVERLAY_ALLOWED		BIT_6
#define	PRLI_W3_CONFIRMED_COMP_ALLOWED		BIT_7
#define	PRLI_W3_RETRY				BIT_8
#define	PRLI_W3_TASK_RETRY_ID_REQUESTED		BIT_9

typedef struct prli_acc_resp {
	uint8_t				ls_code;
	uint8_t				page_length;
	uint16_t			payload_length;
	struct prli_svc_pram_resp_page	svc_params;
} prli_acc_resp_t;

#define	EL_TRACE_BUF_SIZE		8192

#define	QL_PORT_ID_MASK			0xffffff

#define	QL_PLOGI_RETRY_CNT		(5)
#define	QL_PLOGI_RETRY_DLY_USEC		(10 * MILLISEC)

/*
 * Global Data in ql_api.c source file.
 */
extern void		*ql_state;		/* for soft state routine */
extern uint32_t		ql_os_release_level;
extern ql_head_t	ql_hba;
extern kmutex_t		ql_global_mutex;
extern kmutex_t		ql_global_hw_mutex;
extern kmutex_t		ql_global_el_mutex;
extern uint8_t		ql_ip_fast_post_count;
extern uint32_t		ql_ip_buffer_count;
extern uint32_t		ql_ip_low_water;
extern uint8_t		ql_alpa_to_index[];
extern uint32_t		ql_gfru_hba_index;
extern uint32_t		ql_enable_ets;
extern uint16_t		ql_osc_wait_count;

/*
 * Global Function Prototypes in ql_api.c source file.
 */
void ql_chg_endian(uint8_t *, size_t);
void ql_populate_hba_fru_details(ql_adapter_state_t *, fc_fca_port_info_t *);
void ql_setup_fruinfo(ql_adapter_state_t *);
uint16_t ql_pci_config_get16(ql_adapter_state_t *, off_t);
uint32_t ql_pci_config_get32(ql_adapter_state_t *, off_t);
void ql_pci_config_put8(ql_adapter_state_t *, off_t, uint8_t);
void ql_pci_config_put16(ql_adapter_state_t *, off_t, uint16_t);
void ql_delay(ql_adapter_state_t *, clock_t);
void ql_awaken_task_daemon(ql_adapter_state_t *, ql_srb_t *, uint64_t,
    uint64_t);
int ql_abort_device(ql_adapter_state_t *, ql_tgt_t *, int);
int ql_binary_fw_dump(ql_adapter_state_t *, int);
void ql_done(ql_link_t *, boolean_t);
int ql_24xx_flash_id(ql_adapter_state_t *);
int ql_24xx_load_flash(ql_adapter_state_t *, uint8_t *, uint32_t, uint32_t);
int ql_poll_flash(ql_adapter_state_t *, uint32_t, uint8_t);
void ql_flash_disable(ql_adapter_state_t *);
void ql_flash_enable(ql_adapter_state_t *);
int ql_erase_flash(ql_adapter_state_t *, int);
void ql_write_flash_byte(ql_adapter_state_t *, uint32_t, uint8_t);
uint8_t ql_read_flash_byte(ql_adapter_state_t *, uint32_t);
int ql_24xx_read_flash(ql_adapter_state_t *, uint32_t, uint32_t *);
int ql_24xx_write_flash(ql_adapter_state_t *, uint32_t, uint32_t);
fc_unsol_buf_t *ql_get_unsolicited_buffer(ql_adapter_state_t *, uint32_t);
int ql_dump_firmware(ql_adapter_state_t *);
size_t ql_ascii_fw_dump(ql_adapter_state_t *, caddr_t);
void ql_add_link_b(ql_head_t *, ql_link_t *);
void ql_add_link_t(ql_head_t *, ql_link_t *);
void ql_remove_link(ql_head_t *, ql_link_t *);
void ql_next(ql_adapter_state_t *, ql_lun_t *);
void ql_send_logo(ql_adapter_state_t *, ql_tgt_t *, ql_head_t *);
void ql_cthdr_endian(ddi_acc_handle_t, caddr_t, boolean_t);
ql_tgt_t *ql_d_id_to_queue(ql_adapter_state_t *, port_id_t);
ql_tgt_t *ql_loop_id_to_queue(ql_adapter_state_t *, uint16_t);
void ql_cmd_wait(ql_adapter_state_t *);
void ql_loop_online(ql_adapter_state_t *);
ql_tgt_t *ql_dev_init(ql_adapter_state_t *, port_id_t, uint16_t);
int ql_ub_frame_hdr(ql_adapter_state_t *, ql_tgt_t *, uint16_t, ql_head_t *);
void ql_rcv_rscn_els(ql_adapter_state_t *, uint16_t *, ql_head_t *);
int ql_stall_driver(ql_adapter_state_t *, uint32_t);
void ql_restart_driver(ql_adapter_state_t *);
int ql_load_flash(ql_adapter_state_t *, uint8_t *, uint32_t);
int ql_get_dma_mem(ql_adapter_state_t *, dma_mem_t *, uint32_t,
    mem_alloc_type_t, mem_alignment_t);
void ql_free_dma_resource(ql_adapter_state_t *, dma_mem_t *);
int ql_alloc_phys(ql_adapter_state_t *, dma_mem_t *, int);
void ql_free_phys(ql_adapter_state_t *, dma_mem_t *);
void ql_24xx_protect_flash(ql_adapter_state_t *);
uint8_t ql_pci_config_get8(ql_adapter_state_t *, off_t);
void ql_pci_config_put32(ql_adapter_state_t *, off_t, uint32_t);
int ql_24xx_unprotect_flash(ql_adapter_state_t *);
char *els_cmd_text(int);
char *mbx_cmd_text(int);
char *cmd_text(cmd_table_t *, int);
uint32_t ql_fwmodule_resolve(ql_adapter_state_t *);
void ql_port_state(ql_adapter_state_t *, uint32_t, uint32_t);
void ql_isp_els_handle_cmd_endian(ql_adapter_state_t *ha, ql_srb_t *srb);
void ql_isp_els_handle_rsp_endian(ql_adapter_state_t *ha, ql_srb_t *srb);
void ql_isp_els_handle_endian(ql_adapter_state_t *ha, uint8_t *ptr,
    uint8_t ls_code);
void ql_el_trace_alloc(ql_adapter_state_t *);
void ql_el_trace_dealloc(ql_adapter_state_t *);
int ql_nvram_cache_desc_ctor(ql_adapter_state_t *);
int ql_nvram_cache_desc_dtor(ql_adapter_state_t *);
int ql_plogi_params_desc_ctor(ql_adapter_state_t *);
int ql_plogi_params_desc_dtor(ql_adapter_state_t *);
int ql_wwn_cmp(ql_adapter_state_t *, la_wwn_t *, la_wwn_t *);
void ql_dev_free(ql_adapter_state_t *, ql_tgt_t *);
void ql_restart_queues(ql_adapter_state_t *);
void ql_abort_queues(ql_adapter_state_t *);
void ql_requeue_pending_cmds(ql_adapter_state_t *, ql_tgt_t *);
void ql_toggle_loop_state(ql_adapter_state_t *);
void ql_els_24xx_iocb(ql_adapter_state_t *, ql_request_q_t *, ql_srb_t *,
    void *);
int ql_get_cap_ofst(ql_adapter_state_t *, uint8_t);
void ql_intr_lock(ql_adapter_state_t *);
void ql_intr_unlock(ql_adapter_state_t *);
void ql_io_comp(ql_srb_t *sp);
uint64_t ql_get_lun_addr(ql_tgt_t *, uint16_t);
int ql_2700_get_flash_dmp_template(ql_adapter_state_t *);
int ql_2700_get_module_dmp_template(ql_adapter_state_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _QL_API_H */
