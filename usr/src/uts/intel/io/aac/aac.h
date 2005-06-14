/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2000 Michael Smith
 * Copyright (c) 2001 Scott Long
 * Copyright (c) 2000 BSDi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      $FreeBSD: src/sys/dev/aac/aacvar.h,v 1.41 2004/02/18 21:36:51 phk Exp $
 */

#ifndef	_AAC_H_
#define	_AAC_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	AACOK	0
#define	AACERR	-1

/* for mode sense */
#define	MODE_FORMAT_SIZE	(sizeof (struct mode_format))

#ifndef	SD_MODE_SENSE_PAGE3_CODE
#define	SD_MODE_SENSE_PAGE3_CODE 0x03
#endif

#ifndef	SD_MODE_SENSE_PAGE4_CODE
#define	SD_MODE_SENSE_PAGE4_CODE 0x04
#endif

#ifndef	SCMD_SYNCHRONIZE_CACHE
#define	SCMD_SYNCHRONIZE_CACHE	0x35
#endif

#define	AAC_SECTOR_SIZE		512
#define	AAC_NUMBER_OF_HEADS	255
#define	AAC_SECTORS_PER_TRACK	63
#define	AAC_ROTATION_SPEED	10000
#define	AAC_MAX_PFN		0xfffff

#define	AAC_ADDITIONAL_LEN	31
#define	AAC_ANSI_VER		2
#define	AAC_RESP_DATA_FORMAT	2

struct aac_card_type {
	uint16_t	vendor;
	uint16_t	device;
	uint16_t	subvendor;
	uint16_t	subsys;
	char *desc;
};

struct aac_container {
	uint16_t valid;
	uint16_t id;
	uint32_t size;
};

struct sync_mode_res {
	struct aac_fib *fib;
	uint32_t fib_phyaddr;
	kmutex_t mutex;
};

struct aac_cmd_queue {
	struct aac_cmd *q_head;
	struct aac_cmd *q_tail;
};

struct aac_slot {
	int next;
	int index;
	time_t cmd_time;
	ddi_acc_handle_t fib_acc_handle;
	ddi_dma_handle_t fib_dma_handle;
	uint32_t fib_phyaddr;
	struct aac_cmd *acp;
	struct aac_fib *fibp;
};

/* flags for aac_attach */
#define	AAC_SOFT_STATE_ALLOCED		(1 << 0)
#define	AAC_CARD_DETECTED		(1 << 1)
#define	AAC_PCI_MEM_MAPPED		(1 << 2)
#define	AAC_SOFT_INTR_SETUP		(1 << 3)
#define	AAC_SCSI_TRAN_SETUP		(1 << 4)
#define	AAC_SYNC_DMA_HANDLE_ALLOCED	(1 << 5)
#define	AAC_KMUTEX_INITED		(1 << 6)
#define	AAC_STOPPED			(1 << 7)

struct aac_softstate {
	int card;
	uint32_t support_opt;
	dev_info_t *devinfo_p;
	ddi_iblock_cookie_t  iblock_cookie;

	ddi_acc_handle_t pci_mem_handle;
	char *pci_mem_base_addr;

	struct aac_container container[AAC_MAX_LD];

	struct sync_mode_res sync_mode;

	/* the following is communication space */
	struct aac_comm_space *comm_space;
	ddi_acc_handle_t comm_space_acc_handle;
	ddi_dma_handle_t comm_space_dma_handle;

	/* the following is about aac queues */
	struct aac_queue_table *qtablep;
	struct aac_queue_entry *qentries[AAC_QUEUE_COUNT];

	/* the following is used for soft int */
	ddi_softintr_t softint_id;

	/* aac command queues */
	struct aac_cmd_queue q_comp;
	struct aac_cmd_queue q_wait;
	kmutex_t q_comp_mutex;
	kmutex_t q_wait_mutex;

	/* aac I/O slots */
	int total_slotn;
	struct aac_slot io_slot[AAC_HOST_FIBS];
	int free_io_slot_head;
	int free_io_slot_tail;
	kmutex_t slot_mutex;

	kmutex_t tran_mutex;
	kmutex_t fib_mutex;
	kmutex_t timeout_mutex;
	timeout_id_t timeout_id;

	int flags;
};

#define	AAC_CMD_CONSISTENT		1
#define	AAC_CMD_DMA_PARTIAL		1 << 1
#define	AAC_CMD_DMA_VALID		1 << 3
#define	AAC_CMD_BUF_READ		1 << 4
#define	AAC_CMD_BUF_WRITE		1 << 5
#define	AAC_CMD_SOFT_INTR		1 << 6
#define	AAC_CMD_NO_INTR			1 << 7
#define	AAC_CMD_HARD_INTR		1 << 8
struct aac_cmd {
	struct aac_cmd *next;
	struct scsi_pkt *pkt;
	int cmdlen;
	int flags;
	struct buf *bp;
	ddi_dma_handle_t buf_dma_handle;
	ddi_dma_cookie_t cookie;
	uint_t left_cookien;
	uint_t cur_win;
	uint_t total_nwin;
	size_t total_xfer;
	struct aac_slot *slotp;
	struct aac_fib fib;
};

/* SCSI inquiry data */
struct inquiry_data {
	uint8_t inqd_pdt;	/* Peripheral qualifier | */
				/* Peripheral Device Type */
	uint8_t inqd_dtq;	/* RMB | Device Type Qualifier */
	uint8_t inqd_ver;	/* ISO version | ECMA version | */
				/* ANSI-approved version */
	uint8_t inqd_rdf;	/* AENC | TrmIOP | Response data format */
	uint8_t inqd_len;	/* Additional length (n-4) */
	uint8_t inqd_pad1[2];	/* Reserved - must be zero */
	uint8_t inqd_pad2;	/* RelAdr | WBus32 | WBus16 |  Sync  | */
				/* Linked |Reserved| CmdQue | SftRe */
	uint8_t inqd_vid[8];	/* Vendor ID */
	uint8_t inqd_pid[16];	/* Product ID */
	uint8_t inqd_prl[4];	/* Product Revision Level */
};

#ifdef	__cplusplus
}
#endif

#endif /* _AAC_H_ */
