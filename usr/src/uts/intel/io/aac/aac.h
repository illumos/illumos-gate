/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2005-06 Adaptec, Inc.
 * Copyright (c) 2005-06 Adaptec Inc., Achim Leubner
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
 *    $FreeBSD: src/sys/dev/aac/aacvar.h,v 1.47 2005/10/08 15:55:09 scottl Exp $
 */

#ifndef	_AAC_H_
#define	_AAC_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* #define AAC_DEBUG	0 */

#ifdef AAC_DEBUG
extern void aac_print_fib(struct aac_fib *);
#define	AACDB_PRINT(fmt)		cmn_err fmt
#define	AACDB_PRINT_FUNC() \
	AACDB_PRINT((CE_NOTE, "**%s called**", "" /* __func__ */))
#define	AACDB_PRINT_FIB(x)		aac_print_fib(x)
#define	AACDB_PRINT_SCMD(x)		aac_print_scmd(x)
#define	AACDB_PRINT_AIF(x)		aac_print_aif(x)
#define	DBCALLED(lev) \
	do { \
_NOTE(CONSTCOND) if (lev <= AAC_DEBUG) \
			AACDB_PRINT_FUNC(); \
_NOTE(CONSTCOND) } while (0)
#else
#define	AACDB_PRINT(fmt)
#define	AACDB_PRINT_FIB(x)
#define	AACDB_PRINT_SCMD(x)
#define	AACDB_PRINT_AIF(x)
#define	DBCALLED(lev)
#endif /* AAC_DEBUG */

#define	AAC_ROUNDUP(x, y)		(((x) + (y) - 1) / (y) * (y))

#define	AAC_TYPE_DEVO			1
#define	AAC_TYPE_ALPHA			2
#define	AAC_TYPE_BETA			3
#define	AAC_TYPE_RELEASE		4

#ifndef	AAC_DRIVER_BUILD
#define	AAC_DRIVER_BUILD		1
#endif

#define	AAC_DRIVER_MAJOR_VERSION	2
#define	AAC_DRIVER_MINOR_VERSION	1
#define	AAC_DRIVER_BUGFIX_LEVEL		10
#define	AAC_DRIVER_TYPE			AAC_TYPE_RELEASE

#define	AACOK				0
#define	AACERR				-1

#define	AAC_MAX_ADAPTERS		64

/* Definitions for mode sense */
#define	MODE_FORMAT_SIZE		(sizeof (struct mode_format))

#ifndef	SD_MODE_SENSE_PAGE3_CODE
#define	SD_MODE_SENSE_PAGE3_CODE	0x03
#endif

#ifndef	SD_MODE_SENSE_PAGE4_CODE
#define	SD_MODE_SENSE_PAGE4_CODE	0x04
#endif

#ifndef	SCMD_SYNCHRONIZE_CACHE
#define	SCMD_SYNCHRONIZE_CACHE		0x35
#endif

#define	AAC_SECTOR_SIZE			512
#define	AAC_NUMBER_OF_HEADS		255
#define	AAC_SECTORS_PER_TRACK		63
#define	AAC_ROTATION_SPEED		10000
#define	AAC_MAX_PFN			0xfffff

#define	AAC_ADDITIONAL_LEN		31
#define	AAC_ANSI_VER			2
#define	AAC_RESP_DATA_FORMAT		2

/*
 * The controller reports status events in AIFs. We hang on to a number of
 * these in order to pass them out to user-space management tools.
 */
#define	AAC_AIFQ_LENGTH			64

#define	AAC_IMMEDIATE_TIMEOUT		30	/* seconds */
#define	AAC_FWUP_TIMEOUT		180	/* wait up to 3 minutes */
#define	AAC_IOCTL_TIMEOUT		180	/* wait up to 3 minutes */

/* Adapter hardware interface types */
#define	AAC_HWIF_UNKNOWN		0
#define	AAC_HWIF_I960RX			1
#define	AAC_HWIF_RKT			2

#define	AAC_TYPE_UNKNOWN		0
#define	AAC_TYPE_SCSI			1
#define	AAC_TYPE_SATA			2
#define	AAC_TYPE_SAS			3

struct aac_card_type {
	uint16_t vendor;	/* PCI Vendor ID */
	uint16_t device;	/* PCI Device ID */
	uint16_t subvendor;	/* PCI Subsystem Vendor ID */
	uint16_t subsys;	/* PCI Subsystem ID */
	uint16_t hwif;		/* card chip type: i960 or Rocket */
	uint16_t quirks;	/* card odd limits */
	uint16_t type;		/* hard drive type */
	char *vid;		/* ASCII data for INQUIRY command vendor id */
	char *desc;		/* ASCII data for INQUIRY command product id */
};

struct aac_container {
	uint16_t valid;
	uint32_t cid;		/* container id */
	uint32_t uid;		/* container uid */
	uint64_t size;		/* 64-bit LBA */
	uint16_t locked;
	uint16_t deleted;
	uint16_t reset;		/* container is being reseted */
};

struct sync_mode_res {
	struct aac_fib *fib;
	uint64_t fib_phyaddr;
	kmutex_t mutex;
};

struct aac_cmd_queue {
	kmutex_t q_mutex;
	struct aac_cmd *q_head;
	struct aac_cmd *q_tail;
	uint32_t q_len;
};

/*
 * The firmware can support a lot of outstanding commands. Each aac_slot
 * is corresponding to one of such commands. It records the command and
 * associated DMA resource for FIB command.
 */
struct aac_slot {
	int next;		/* index of next slot */
	int index;		/* index of this slot if used, or -1 if free */
	ddi_acc_handle_t fib_acc_handle;
	ddi_dma_handle_t fib_dma_handle;
	uint64_t fib_phyaddr;	/* physical address of FIB memory */
	struct aac_cmd *acp;	/* command using this slot */
	struct aac_fib *fibp;	/* virtual address of FIB memory */
};

/* flags for attach tracking */
#define	AAC_ATTACH_SOFTSTATE_ALLOCED	(1 << 0)
#define	AAC_ATTACH_CARD_DETECTED	(1 << 1)
#define	AAC_ATTACH_PCI_MEM_MAPPED	(1 << 2)
#define	AAC_ATTACH_KMUTEX_INITED	(1 << 3)
#define	AAC_ATTACH_HARD_INTR_SETUP	(1 << 4)
#define	AAC_ATTACH_SOFT_INTR_SETUP	(1 << 5)
#define	AAC_ATTACH_SCSI_TRAN_SETUP	(1 << 6)
#define	AAC_ATTACH_COMM_SPACE_SETUP	(1 << 7)
#define	AAC_ATTACH_CREATE_DEVCTL	(1 << 8)
#define	AAC_ATTACH_CREATE_SCSI		(1 << 9)

/* driver running states */
#define	AAC_STATE_STOPPED		0
#define	AAC_STATE_RUN			1
#define	AAC_STATE_QUIESCE		2
#define	AAC_STATE_RESET			3
#define	AAC_STATE_DEAD			4

/* flags for aac firmware */
#define	AAC_FLAGS_SG_64BIT	(1 << 0) /* Use 64-bit S/G addresses */
#define	AAC_FLAGS_4GB_WINDOW	(1 << 1) /* Can access host mem 2-4GB range */
#define	AAC_FLAGS_NO4GB		(1 << 2) /* Can't access host mem >2GB */
#define	AAC_FLAGS_256FIBS	(1 << 3) /* Can only do 256 commands */
#define	AAC_FLAGS_NEW_COMM	(1 << 4) /* New comm. interface supported */
#define	AAC_FLAGS_RAW_IO	(1 << 5) /* Raw I/O interface */
#define	AAC_FLAGS_ARRAY_64BIT	(1 << 6) /* 64-bit array size */
#define	AAC_FLAGS_LBA_64BIT	(1 << 7) /* 64-bit LBA supported */
#define	AAC_FLAGS_PERC		(1 << 8) /* PERC has much shorter S/G len */

struct aac_softstate;
struct aac_interface {
	int (*aif_get_fwstatus)(struct aac_softstate *);
	int (*aif_get_mailbox)(struct aac_softstate *, int mb);
	void (*aif_set_mailbox)(struct aac_softstate *, uint32_t command,
		uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3);
};

struct aac_fib_context {
	uint32_t unique;
	int ctx_idx;
	int ctx_wrap;
	struct aac_fib_context *next, *prev;
};

struct aac_softstate {
	int card;		/* index to aac_cards */
	uint32_t support_opt;	/* firmware features */
	uint32_t atu_size;	/* actual size of PCI mem space */
	uint32_t map_size;	/* mapped PCI mem space size */
	uint32_t map_size_min;	/* minimum size of PCI mem that must be */
				/* mapped to address the card */
	dev_info_t *devinfo_p;

	/* dma attributes */
	ddi_dma_attr_t buf_dma_attr;
	ddi_dma_attr_t addr_dma_attr;

	ddi_acc_handle_t pci_mem_handle;
	char *pci_mem_base_addr;

	/* adapter hardware interface */
	struct aac_interface aac_if;

	struct aac_container container[AAC_MAX_LD];
	int container_count;	/* max container id */

	struct sync_mode_res sync_mode;

	/* the following is communication space */
	struct aac_comm_space *comm_space;
	ddi_acc_handle_t comm_space_acc_handle;
	ddi_dma_handle_t comm_space_dma_handle;
	uint32_t comm_space_phyaddr;

	/* the following is about message queues */
	struct aac_queue_table *qtablep;
	struct aac_queue_entry *qentries[AAC_QUEUE_COUNT];

	/* the following is used for soft int */
	ddi_softintr_t softint_id;

	/*
	 * Command queues
	 * Each aac command flows through wait(or wait_sync) queue,
	 * io_slot and comp queue sequentially.
	 */
	struct aac_cmd_queue q_wait_sync;	/* for sync FIB requests */
	struct aac_cmd_queue q_wait;		/* for async FIB requests */
	struct aac_cmd_queue q_comp;		/* for completed io requests */

	/* aac I/O slots and FIBs */
	int total_slots;		/* total slots allocated */
	int total_fibs;			/* total FIBs allocated */
	struct aac_slot *io_slot;	/* static list for allocated slots */
	int free_io_slot_head;
	int free_io_slot_tail;
	int free_io_slot_len;
	int slot_hold;			/* hold slots from being used */
	kmutex_t slot_mutex;		/* for io_slot */

	kmutex_t fib_mutex;		/* for message queues */
	timeout_id_t timeout_id;
	uint32_t timeout_count;

	int flags;			/* firmware features enabled */
	int state;			/* driver state */
	krwlock_t errlock;		/* hold IO requests at reset */

	/* for ioctl_send_fib() */
	kmutex_t event_mutex;
	kcondvar_t event;

	/* AIF */
	kmutex_t aifq_mutex;		/* for AIF queue aifq */
	kcondvar_t aifv;
	struct aac_fib aifq[AAC_AIFQ_LENGTH];
	int aifq_idx;
	int aifq_filled;
	struct aac_fib_context *fibctx;
	int devcfg_wait_on;		/* AIF event waited for rescan */

	/* new comm. interface */
	uint32_t aac_max_fibs;		/* max. FIB count */
	uint32_t aac_max_fib_size;	/* max. FIB size */
	uint32_t aac_sg_tablesize;	/* max. sg count from host */
	uint32_t aac_max_sectors;	/* max. I/O size from host (blocks) */

	ddi_iblock_cookie_t iblock_cookie;
};

/* aac_cmd flags */
#define	AAC_CMD_CONSISTENT		(1 << 0)
#define	AAC_CMD_DMA_PARTIAL		(1 << 1)
#define	AAC_CMD_DMA_VALID		(1 << 3)
#define	AAC_CMD_BUF_READ		(1 << 4)
#define	AAC_CMD_BUF_WRITE		(1 << 5)
#define	AAC_CMD_SOFT_INTR		(1 << 6) /* poll IO */
#define	AAC_CMD_NO_INTR			(1 << 7) /* no interrupt to sd */
#define	AAC_CMD_HARD_INTR		(1 << 8) /* interrupt IO */
#define	AAC_CMD_TIMEOUT			(1 << 9)

/* aac_cmd states */
#define	AAC_CMD_INCMPLT			0
#define	AAC_CMD_CMPLT			1
#define	AAC_CMD_ABORT			2

struct aac_cmd {
	struct aac_cmd *next;
	struct scsi_pkt *pkt;
	int cmdlen;
	int flags;
	int state;
	time_t start_time;	/* time when the cmd is sent to the adapter */
	time_t timeout;		/* max time in seconds for cmd to complete */
	struct buf *bp;
	ddi_dma_handle_t buf_dma_handle;

	/* For non-aligned buffer and SRB */
	caddr_t abp;
	ddi_acc_handle_t abh;

	ddi_dma_cookie_t cookie;
	uint_t left_cookien;
	uint_t cur_win;
	uint_t total_nwin;
	size_t total_xfer;
	struct aac_slot *slotp;	/* slot used by this command */

	/*
	 * NOTE: should be the last field, because New Comm. FIBs may
	 * take more space than sizeof (struct aac_fib).
	 */
	struct aac_fib fib;	/* FIB for this IO command */
};

#ifdef	__cplusplus
}
#endif

#endif /* _AAC_H_ */
