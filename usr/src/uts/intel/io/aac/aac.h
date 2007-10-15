/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#define	AAC_DRIVER_BUGFIX_LEVEL		18
#define	AAC_DRIVER_TYPE			AAC_TYPE_RELEASE

#define	STR(s)				# s
#define	AAC_VERSION(a, b, c)		STR(a.b.c)
#define	AAC_DRIVER_VERSION		AAC_VERSION(AAC_DRIVER_MAJOR_VERSION, \
					AAC_DRIVER_MINOR_VERSION, \
					AAC_DRIVER_BUGFIX_LEVEL)

#define	AACOK				0
#define	AACERR				-1

#define	AAC_MAX_ADAPTERS		64

/* Definitions for mode sense */
#ifndef	SD_MODE_SENSE_PAGE3_CODE
#define	SD_MODE_SENSE_PAGE3_CODE	0x03
#endif

#ifndef	SD_MODE_SENSE_PAGE4_CODE
#define	SD_MODE_SENSE_PAGE4_CODE	0x04
#endif

#ifndef	SCMD_SYNCHRONIZE_CACHE
#define	SCMD_SYNCHRONIZE_CACHE		0x35
#endif

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

/*
 * AAC_CMDQ_SYNC should be 0 and AAC_CMDQ_ASYNC be 1 for Sync FIB io
 * to be served before async FIB io, see aac_start_waiting_io().
 * So that io requests sent by interactive userland commands get
 * responded asap.
 */
enum aac_cmdq {
	AAC_CMDQ_SYNC,	/* sync FIB queue */
	AAC_CMDQ_ASYNC,	/* async FIB queue */
	AAC_CMDQ_NUM
};

/*
 * IO command flags
 */
#define	AAC_IOCMD_SYNC		(1 << AAC_CMDQ_SYNC)
#define	AAC_IOCMD_ASYNC		(1 << AAC_CMDQ_ASYNC)
#define	AAC_IOCMD_OUTSTANDING	(1 << AAC_CMDQ_NUM)
#define	AAC_IOCMD_ALL		(AAC_IOCMD_SYNC | AAC_IOCMD_ASYNC | \
				AAC_IOCMD_OUTSTANDING)

struct aac_cmd_queue {
	struct aac_cmd *q_head; /* also as the header of aac_cmd */
	struct aac_cmd *q_tail;
};

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

/* Array description */
struct aac_container {
	uint8_t valid;
	uint32_t cid;		/* container id */
	uint32_t uid;		/* container uid */
	uint64_t size;		/* in block */
	uint8_t locked;
	uint8_t deleted;
	uint8_t reset;		/* container is being reseted */
	int ncmds[AAC_CMDQ_NUM];	/* outstanding cmds of the device */
	int throttle[AAC_CMDQ_NUM];	/* hold IO cmds for the device */
};

struct sync_mode_res {
	struct aac_fib *fib;
	uint64_t fib_phyaddr;
	kmutex_t mutex;
};

_NOTE(MUTEX_PROTECTS_DATA(sync_mode_res::mutex, sync_mode_res))

/*
 * The firmware can support a lot of outstanding commands. Each aac_slot
 * is corresponding to one of such commands. It records the command and
 * associated DMA resource for FIB command.
 */
struct aac_slot {
	struct aac_slot *next;	/* next slot in the free slot list */
	int index;		/* index of this slot */
	ddi_acc_handle_t fib_acc_handle;
	ddi_dma_handle_t fib_dma_handle;
	uint64_t fib_phyaddr;	/* physical address of FIB memory */
	struct aac_cmd *acp;	/* command using this slot */
	struct aac_fib *fibp;	/* virtual address of FIB memory */
};

/* Flags for attach tracking */
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

/* Driver running states */
#define	AAC_STATE_STOPPED	0
#define	AAC_STATE_RUN		(1 << 0)
#define	AAC_STATE_RESET		(1 << 1)
#define	AAC_STATE_QUIESCED	(1 << 2)
#define	AAC_STATE_DEAD		(1 << 3)

/*
 * Flags for aac firmware
 * Note: Quirks are only valid for the older cards. These cards only supported
 * old comm. Thus they are not valid for any cards that support new comm.
 */
#define	AAC_FLAGS_SG_64BIT	(1 << 0) /* Use 64-bit S/G addresses */
#define	AAC_FLAGS_4GB_WINDOW	(1 << 1) /* Can access host mem 2-4GB range */
#define	AAC_FLAGS_NO4GB	(1 << 2)	/* quirk: FIB addresses must reside */
					/*	  between 0x2000 & 0x7FFFFFFF */
#define	AAC_FLAGS_256FIBS	(1 << 3) /* quirk: Can only do 256 commands */
#define	AAC_FLAGS_NEW_COMM	(1 << 4) /* New comm. interface supported */
#define	AAC_FLAGS_RAW_IO	(1 << 5) /* Raw I/O interface */
#define	AAC_FLAGS_ARRAY_64BIT	(1 << 6) /* 64-bit array size */
#define	AAC_FLAGS_LBA_64BIT	(1 << 7) /* 64-bit LBA supported */
#define	AAC_FLAGS_17SG		(1 << 8) /* quirk: 17 scatter gather maximum */
#define	AAC_FLAGS_34SG		(1 << 9) /* quirk: 34 scatter gather maximum */

struct aac_softstate;
struct aac_interface {
	int (*aif_get_fwstatus)(struct aac_softstate *);
	int (*aif_get_mailbox)(struct aac_softstate *, int);
	void (*aif_set_mailbox)(struct aac_softstate *, uint32_t,
	    uint32_t, uint32_t, uint32_t, uint32_t);
};

struct aac_fib_context {
	uint32_t unique;
	int ctx_idx;
	int ctx_filled;		/* aifq is full for this fib context */
	struct aac_fib_context *next, *prev;
};

typedef void (*aac_cmd_fib_t)(struct aac_softstate *, struct aac_cmd *, int);

#define	AAC_VENDOR_LEN		8
#define	AAC_PRODUCT_LEN		16

struct aac_softstate {
	int card;		/* index to aac_cards */
	uint16_t hwif;		/* card chip type: i960 or Rocket */
	char vendor_name[AAC_VENDOR_LEN + 1];
	char product_name[AAC_PRODUCT_LEN + 1];
	uint32_t support_opt;	/* firmware features */
	uint32_t atu_size;	/* actual size of PCI mem space */
	uint32_t map_size;	/* mapped PCI mem space size */
	uint32_t map_size_min;	/* minimum size of PCI mem that must be */
				/* mapped to address the card */
	int flags;		/* firmware features enabled */
	int instance;
	dev_info_t *devinfo_p;
	int slen;

	/* DMA attributes */
	ddi_dma_attr_t buf_dma_attr;
	ddi_dma_attr_t addr_dma_attr;

	/* PCI spaces */
	ddi_acc_handle_t pci_mem_handle;
	char *pci_mem_base_vaddr;
	uint32_t pci_mem_base_paddr;

	struct aac_interface aac_if;	/* adapter hardware interface */

	struct sync_mode_res sync_mode;	/* sync FIB */

	/* Communication space */
	struct aac_comm_space *comm_space;
	ddi_acc_handle_t comm_space_acc_handle;
	ddi_dma_handle_t comm_space_dma_handle;
	uint32_t comm_space_phyaddr;

	/* Old Comm. interface: message queues */
	struct aac_queue_table *qtablep;
	struct aac_queue_entry *qentries[AAC_QUEUE_COUNT];

	/* New Comm. interface */
	uint32_t aac_max_fibs;		/* max. FIB count */
	uint32_t aac_max_fib_size;	/* max. FIB size */
	uint32_t aac_sg_tablesize;	/* max. sg count from host */
	uint32_t aac_max_sectors;	/* max. I/O size from host (blocks) */

	aac_cmd_fib_t aac_cmd_fib;	/* IO cmd FIB construct function */

	ddi_iblock_cookie_t iblock_cookie;
	ddi_softintr_t softint_id;	/* soft intr */

	kmutex_t io_lock;
	int state;			/* driver state */

	struct aac_container container[AAC_MAX_LD];
	int container_count;		/* max container id + 1 */

	/*
	 * Command queues
	 * Each aac command flows through wait(or wait_sync) queue,
	 * busy queue, and complete queue sequentially.
	 */
	struct aac_cmd_queue q_wait[AAC_CMDQ_NUM];
	struct aac_cmd_queue q_busy;	/* outstanding cmd queue */
	kmutex_t q_comp_mutex;
	struct aac_cmd_queue q_comp;	/* completed io requests */

	/* I/O slots and FIBs */
	int total_slots;		/* total slots allocated */
	int total_fibs;			/* total FIBs allocated */
	struct aac_slot *io_slot;	/* static list for allocated slots */
	struct aac_slot *free_io_slot_head;

	timeout_id_t timeout_id;	/* for timeout daemon */

	kcondvar_t event;		/* for ioctl_send_fib() and sync IO */

	int bus_ncmds[AAC_CMDQ_NUM];	/* total outstanding async cmds */
	int bus_throttle[AAC_CMDQ_NUM];	/* hold IO cmds for the bus */
	int ndrains;			/* number of draining threads */
	timeout_id_t drain_timeid;	/* for outstanding cmd drain */
	kcondvar_t drain_cv;		/* for quiesce drain */

	/* AIF */
	kmutex_t aifq_mutex;		/* for AIF queue aifq */
	kcondvar_t aifv;
	struct aac_fib aifq[AAC_AIFQ_LENGTH];
	int aifq_idx;			/* slot for next new AIF */
	int aifq_wrap;			/* AIF queue has ever been wrapped */
	struct aac_fib_context *fibctx;
	int devcfg_wait_on;		/* AIF event waited for rescan */

	int fm_capabilities;

#ifdef DEBUG
	/* UART trace printf variables */
	uint32_t debug_flags;		/* debug print flags bitmap */
	uint32_t debug_fw_flags;	/* FW debug flags */
	uint32_t debug_buf_offset;	/* offset from DPMEM start */
	uint32_t debug_buf_size;	/* FW debug buffer size in bytes */
	uint32_t debug_header_size;	/* size of debug header */
#endif
};

_NOTE(SCHEME_PROTECTS_DATA("stable data", aac_softstate::{flags slen \
    buf_dma_attr pci_mem_handle pci_mem_base_vaddr sync_mode \
    comm_space_acc_handle comm_space_dma_handle aac_max_fib_size \
    aac_sg_tablesize aac_cmd_fib debug_flags debug_fw_flags debug_buf_offset \
    debug_buf_size debug_header_size}))
_NOTE(MUTEX_PROTECTS_DATA(aac_softstate::io_lock, aac_softstate::{ \
    state container container_count q_wait q_busy total_slots total_fibs \
    io_slot free_io_slot_head timeout_id drain_timeid ndrains drain_cv event}))
_NOTE(MUTEX_PROTECTS_DATA(aac_softstate::q_comp_mutex, aac_softstate::q_comp))
_NOTE(MUTEX_PROTECTS_DATA(aac_softstate::aifq_mutex, aac_softstate::{ \
    aifv aifq aifq_idx aifq_wrap fibctx devcfg_wait_on}))

/* aac_cmd flags */
#define	AAC_CMD_CONSISTENT		(1 << 0)
#define	AAC_CMD_DMA_PARTIAL		(1 << 1)
#define	AAC_CMD_DMA_VALID		(1 << 2)
#define	AAC_CMD_BUF_READ		(1 << 3)
#define	AAC_CMD_BUF_WRITE		(1 << 4)
#define	AAC_CMD_SYNC			(1 << 5) /* use sync FIB */
#define	AAC_CMD_NO_INTR			(1 << 6) /* poll IO, no intr */
#define	AAC_CMD_NO_CB			(1 << 7) /* sync IO, no callback */
#define	AAC_CMD_NTAG			(1 << 8)
#define	AAC_CMD_CMPLT			(1 << 9) /* cmd exec'ed by driver/fw */
#define	AAC_CMD_ABORT			(1 << 10)
#define	AAC_CMD_TIMEOUT			(1 << 11)
#define	AAC_CMD_ERR			(1 << 12)

struct aac_cmd {
	/*
	 * Note: should be the first member for aac_cmd_queue to work
	 * correctly.
	 */
	struct aac_cmd *next;
	struct aac_cmd *prev;

	struct scsi_pkt *pkt;
	int cmdlen;
	int flags;
	uint32_t timeout; /* time when the cmd should have completed */
	struct buf *bp;
	ddi_dma_handle_t buf_dma_handle;

	/* For non-aligned buffer and SRB */
	caddr_t abp;
	ddi_acc_handle_t abh;

	/* Data transfer state */
	ddi_dma_cookie_t cookie;
	uint_t left_cookien;
	uint_t cur_win;
	uint_t total_nwin;
	size_t total_xfer;
	uint64_t blkno;
	uint32_t bcount;	/* buffer size in byte */

	/* Call back function for completed command */
	void (*ac_comp)(struct aac_softstate *, struct aac_cmd *);

	struct aac_slot *slotp;	/* slot used by this command */
	struct aac_container *dvp;	/* target device */

	/* FIB for this IO command */
	int fib_kmsz; /* size of kmem_alloc'ed FIB */
	int fib_size; /* size of the FIB xferred to/from the card */
	struct aac_fib *fibp;
};

#ifdef DEBUG

#define	AACDB_FLAGS_MASK		0x0000ffff
#define	AACDB_FLAGS_KERNEL_PRINT	0x00000001
#define	AACDB_FLAGS_FW_PRINT		0x00000002

#define	AACDB_FLAGS_MISC		0x00000004
#define	AACDB_FLAGS_FUNC1		0x00000008
#define	AACDB_FLAGS_FUNC2		0x00000010
#define	AACDB_FLAGS_SCMD		0x00000020
#define	AACDB_FLAGS_AIF			0x00000040
#define	AACDB_FLAGS_FIB			0x00000080
#define	AACDB_FLAGS_IOCTL		0x00000100

extern uint32_t aac_debug_flags;
extern int aac_dbflag_on(struct aac_softstate *, int);
extern void aac_printf(struct aac_softstate *, uint_t, const char *, ...);
extern void aac_print_fib(struct aac_softstate *, struct aac_fib *);

#define	AACDB_PRINT(s, lev, ...) { \
	if (aac_dbflag_on((s), AACDB_FLAGS_MISC)) \
		aac_printf((s), (lev), __VA_ARGS__); }

#define	AACDB_PRINT_IOCTL(s, ...) { \
	if (aac_dbflag_on((s), AACDB_FLAGS_IOCTL)) \
		aac_printf((s), CE_NOTE, __VA_ARGS__); }

#define	AACDB_PRINT_TRAN(s, ...) { \
	if (aac_dbflag_on((s), AACDB_FLAGS_SCMD)) \
		aac_printf((s), CE_NOTE, __VA_ARGS__); }

#define	DBCALLED(s, n) { \
	if (aac_dbflag_on((s), AACDB_FLAGS_FUNC ## n)) \
		aac_printf((s), CE_NOTE, "--- %s() called ---", __func__); }

#define	AACDB_PRINT_SCMD(s, x) { \
	if (aac_dbflag_on((s), AACDB_FLAGS_SCMD)) aac_print_scmd((s), (x)); }

#define	AACDB_PRINT_AIF(s, x) { \
	if (aac_dbflag_on((s), AACDB_FLAGS_AIF)) aac_print_aif((s), (x)); }

#define	AACDB_PRINT_FIB(s, x) { \
	if (aac_dbflag_on((s), AACDB_FLAGS_FIB)) aac_print_fib((s), (x)); }

#else /* DEBUG */

#define	AACDB_PRINT(s, lev, ...)
#define	AACDB_PRINT_IOCTL(s, ...)
#define	AACDB_PRINT_TRAN(s, ...)
#define	AACDB_PRINT_FIB(s, x)
#define	AACDB_PRINT_SCMD(s, x)
#define	AACDB_PRINT_AIF(s, x)
#define	DBCALLED(s, n)

#endif /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif /* _AAC_H_ */
