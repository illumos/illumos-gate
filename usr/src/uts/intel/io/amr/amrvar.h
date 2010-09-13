/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1999,2000 Michael Smith
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
 * Copyright (c) 2002 Eric Moore
 * Copyright (c) 2002 LSI Logic Corporation
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
 * 3. The party using or redistributing the source code and binary forms
 *    agrees to the disclaimer below and the terms and conditions set forth
 *    herein.
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
 */

#ifndef _AMRVAR_H
#define	_AMRVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	AMR_DEBUG
#ifdef AMR_DEBUG
#define	AMRDB_PRINT(fmt) if (amr_debug_var) cmn_err fmt
#else
#define	AMRDB_PRINT(fmt)
#endif

#define	AMRDB_PANIC(fmt) cmn_err fmt

#define	AMR_PERIODIC_TIMEOUT		60
#define	AMR_RETRYCOUNT			10000

/* for scsi commands */
#ifndef	SD_MODE_SENSE_PAGE3_CODE
#define	SD_MODE_SENSE_PAGE3_CODE	0x03
#endif

#ifndef	SD_MODE_SENSE_PAGE4_CODE
#define	SD_MODE_SENSE_PAGE4_CODE	0x04
#endif

#ifndef	SCMD_SYNCHRONIZE_CACHE
#define	SCMD_SYNCHRONIZE_CACHE		0x35
#endif

#define	AMR_DEFAULT_SECTORS		512
#define	AMR_DEFAULT_HEADS		255
#define	AMR_DEFAULT_CYLINDERS		63
#define	AMR_DEFAULT_ROTATIONS		10000

#define	AMR_INQ_ADDITIONAL_LEN		31
#define	AMR_INQ_ANSI_VER		2
#define	AMR_INQ_RESP_DATA_FORMAT	2

#define	AMR_PRODUCT_INFO_SIZE \
			sizeof (((struct scsi_inquiry *)(NULL))->inq_pid)
#define	AMR_FIRMWARE_VER_SIZE \
			sizeof (((struct scsi_inquiry *)(NULL))->inq_revision)

#define	AMR_LAST_COOKIE_TAG		0xffffffff

/*
 * Per-logical-drive datastructure
 */
struct amr_logdrive
{
	uint32_t	al_size;
	uint8_t		al_state;
	uint8_t		al_properties;
};

/*
 * Per-command control structure.
 */
struct amr_command
{

	struct amr_command	*ac_prev;
	struct amr_command	*ac_next;

	struct amr_softs	*ac_softs;
	uint8_t			ac_slot;

	uint8_t			ac_status;
	uint32_t		ac_flags;

	struct buf		*ac_buf;
	uint32_t		cmdlen;
	struct scsi_pkt		*pkt;

	void			*ac_data;
	size_t			ac_length;
	uint32_t		ac_dataphys;

	ddi_dma_handle_t	sg_dma_handle;
	ddi_dma_cookie_t	sg_dma_cookie;
	uint_t			sg_dma_cookien;

	ddi_dma_handle_t	buffer_dma_handle;
	ddi_dma_cookie_t	buffer_dma_cookie;
	ddi_acc_handle_t	buffer_acc_handle;
	uint_t			num_of_cookie;
	uint_t			num_of_win;
	uint_t			current_cookie;
	uint_t			current_win;
	uint32_t		data_transfered;
	uint32_t		transfer_size;

	struct amr_mailbox	mailbox;
	struct amr_sgentry	sgtable[AMR_NSEG];

	time_t			ac_timestamp;
};

/*
 * ac_flags values in amr_command
 */
#define	AMR_CMD_DATAIN		(1<<0)
#define	AMR_CMD_DATAOUT		(1<<1)
#define	AMR_CMD_CCB_DATAIN	(1<<2)
#define	AMR_CMD_CCB_DATAOUT	(1<<3)
#define	AMR_CMD_PRIORITY	(1<<4)
#define	AMR_CMD_MAPPED		(1<<5)
#define	AMR_CMD_SLEEP		(1<<6)
#define	AMR_CMD_BUSY		(1<<7)
#define	AMR_CMD_PKT_CONSISTENT	(1<<8)
#define	AMR_CMD_PKT_DMA_PARTIAL	(1<<9)
#define	AMR_CMD_GOT_SLOT	(1<<10)

struct sg_item {
	struct amr_sgentry	*sg_table;
	ddi_dma_handle_t	sg_handle;
	ddi_acc_handle_t	sg_acc_handle;
	uint32_t		sg_phyaddr;
};

struct product_info {
	uint8_t			pi_firmware_ver[AMR_FIRMWARE_VER_SIZE+1];
	uint8_t			pi_product_name[AMR_PRODUCT_INFO_SIZE+1];
};

/*
 * Per-controller-instance data
 */
struct amr_softs
{
	/* bus attachments */
	dev_info_t		*dev_info_p;
	ddi_acc_handle_t	pciconfig_handle;
	ddi_acc_handle_t	regsmap_handle;
	ddi_iblock_cookie_t	iblock_cookiep;

	ddi_dma_handle_t	mbox_dma_handle;
	ddi_acc_handle_t	mbox_acc_handle;
	ddi_dma_cookie_t	mbox_dma_cookie;
	uint_t			mbox_dma_cookien;

	/* controller limits and features */
	uint8_t			maxio; /* maximum number of I/O transactions */
	uint8_t			maxdrives; /* max number of logical drives */
	uint8_t			maxchan; /* count of SCSI channels */

	uint8_t			amr_nlogdrives;

	/* connected logical drives */
	struct amr_logdrive	logic_drive[AMR_MAXLD];

	/* product info of the card */
	struct product_info	amr_product_info;

	/* controller state */
	uint32_t		state;

	struct amr_mailbox	*mailbox;
	void			*mbox;
	uint32_t		mbox_phyaddr;

	/* per-controller poll command */
	kmutex_t		cmd_mutex;
	kcondvar_t		cmd_cv;

	uint32_t		amr_busyslots;
	struct amr_command	*busycmd[AMR_MAXCMD];
	struct sg_item		sg_items[AMR_MAXCMD];
	uint32_t		sg_max_count;
	struct amr_command	*waiting_q_head;
	struct amr_command	*waiting_q_tail;
	kmutex_t		queue_mutex;

	/* periodic status check */
	timeout_id_t		timeout_t;
	kmutex_t		periodic_mutex;

	scsi_hba_tran_t		*hba_tran;

	ddi_taskq_t		*amr_taskq;
	uint32_t		amr_interrupts_counter;
};

/*
 * state values in amr_softs
 */
#define	AMR_STATE_OPEN			(1<<0)
#define	AMR_STATE_SUSPEND		(1<<1)
#define	AMR_STATE_CARD_DETECTED		(1<<2)
#define	AMR_STATE_BUS_MASTER_ENABLED	(1<<3)
#define	AMR_STATE_SOFT_STATE_SETUP	(1<<4)
#define	AMR_STATE_PCI_CONFIG_SETUP	(1<<5)
#define	AMR_STATE_PCI_MEM_MAPPED	(1<<6)
#define	AMR_STATE_KMUTEX_INITED		(1<<7)
#define	AMR_STATE_MAILBOX_SETUP		(1<<8)
#define	AMR_STATE_SG_TABLES_SETUP	(1<<9)
#define	AMR_STATE_INTR_SETUP		(1<<10)
#define	AMR_STATE_TASKQ_SETUP		(1<<11)
#define	AMR_STATE_TRAN_SETUP		(1<<12)
#define	AMR_STATE_TIMEOUT_ENABLED	(1<<13)

#ifdef	__cplusplus
}
#endif

#endif /* _AMRVAR_H */
