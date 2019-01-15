/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2005-08 Adaptec, Inc.
 * Copyright (c) 2005-08 Adaptec Inc., Achim Leubner
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
 */
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/pci.h>
#include <sys/types.h>
#include <sys/ddidmareq.h>
#include <sys/scsi/scsi.h>
#include <sys/ksynch.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include "aac_regs.h"
#include "aac.h"

/*
 * FMA header files
 */
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

/*
 * For minor nodes created by the SCSA framework, minor numbers are
 * formed by left-shifting instance by INST_MINOR_SHIFT and OR in a
 * number less than 64.
 *
 * To support cfgadm, need to confirm the SCSA framework by creating
 * devctl/scsi and driver specific minor nodes under SCSA format,
 * and calling scsi_hba_xxx() functions aacordingly.
 */

#define	AAC_MINOR		32
#define	INST2AAC(x)		(((x) << INST_MINOR_SHIFT) | AAC_MINOR)
#define	AAC_SCSA_MINOR(x)	((x) & TRAN_MINOR_MASK)
#define	AAC_IS_SCSA_NODE(x)	((x) == DEVCTL_MINOR || (x) == SCSI_MINOR)

#define	SD2TRAN(sd)		((sd)->sd_address.a_hba_tran)
#define	AAC_TRAN2SOFTS(tran) ((struct aac_softstate *)(tran)->tran_hba_private)
#define	AAC_DIP2TRAN(dip)	((scsi_hba_tran_t *)ddi_get_driver_private(dip))
#define	AAC_DIP2SOFTS(dip)	(AAC_TRAN2SOFTS(AAC_DIP2TRAN(dip)))
#define	SD2AAC(sd)		(AAC_TRAN2SOFTS(SD2TRAN(sd)))
#define	AAC_PD(t)		((t) - AAC_MAX_LD)
#define	AAC_DEV(softs, t)	(((t) < AAC_MAX_LD) ? \
				&(softs)->containers[(t)].dev : \
				((t) < AAC_MAX_DEV(softs)) ? \
				&(softs)->nondasds[AAC_PD(t)].dev : NULL)
#define	AAC_DEVCFG_BEGIN(softs, tgt) \
				aac_devcfg((softs), (tgt), 1)
#define	AAC_DEVCFG_END(softs, tgt) \
				aac_devcfg((softs), (tgt), 0)
#define	PKT2AC(pkt)		((struct aac_cmd *)(pkt)->pkt_ha_private)
#define	AAC_BUSYWAIT(cond, timeout /* in millisecond */) { \
		if (!(cond)) { \
			int count = (timeout) * 10; \
			while (count) { \
				drv_usecwait(100); \
				if (cond) \
					break; \
				count--; \
			} \
			(timeout) = (count + 9) / 10; \
		} \
	}

#define	AAC_SENSE_DATA_DESCR_LEN \
	(sizeof (struct scsi_descr_sense_hdr) + \
	sizeof (struct scsi_information_sense_descr))
#define	AAC_ARQ64_LENGTH \
	(sizeof (struct scsi_arq_status) + \
	AAC_SENSE_DATA_DESCR_LEN - SENSE_LENGTH)

/* NOTE: GETG4ADDRTL(cdbp) is int32_t */
#define	AAC_GETGXADDR(cmdlen, cdbp) \
	((cmdlen == 6) ? GETG0ADDR(cdbp) : \
	(cmdlen == 10) ? (uint32_t)GETG1ADDR(cdbp) : \
	((uint64_t)GETG4ADDR(cdbp) << 32) | (uint32_t)GETG4ADDRTL(cdbp))

#define	AAC_CDB_INQUIRY_CMDDT	0x02
#define	AAC_CDB_INQUIRY_EVPD	0x01
#define	AAC_VPD_PAGE_CODE	1
#define	AAC_VPD_PAGE_LENGTH	3
#define	AAC_VPD_PAGE_DATA	4
#define	AAC_VPD_ID_CODESET	0
#define	AAC_VPD_ID_TYPE		1
#define	AAC_VPD_ID_LENGTH	3
#define	AAC_VPD_ID_DATA		4

#define	AAC_SCSI_RPTLUNS_HEAD_SIZE			0x08
#define	AAC_SCSI_RPTLUNS_ADDR_SIZE			0x08
#define	AAC_SCSI_RPTLUNS_ADDR_MASK			0xC0
/* 00b - peripheral device addressing method */
#define	AAC_SCSI_RPTLUNS_ADDR_PERIPHERAL		0x00
/* 01b - flat space addressing method */
#define	AAC_SCSI_RPTLUNS_ADDR_FLAT_SPACE		0x40
/* 10b - logical unit addressing method */
#define	AAC_SCSI_RPTLUNS_ADDR_LOGICAL_UNIT		0x80

/* Return the size of FIB with data part type data_type */
#define	AAC_FIB_SIZEOF(data_type) \
	(sizeof (struct aac_fib_header) + sizeof (data_type))
/* Return the container size defined in mir */
#define	AAC_MIR_SIZE(softs, acc, mir) \
	(((softs)->flags & AAC_FLAGS_LBA_64BIT) ? \
	(uint64_t)ddi_get32((acc), &(mir)->MntObj.Capacity) + \
	((uint64_t)ddi_get32((acc), &(mir)->MntObj.CapacityHigh) << 32) : \
	(uint64_t)ddi_get32((acc), &(mir)->MntObj.Capacity))

/* The last entry of aac_cards[] is for unknown cards */
#define	AAC_UNKNOWN_CARD \
	(sizeof (aac_cards) / sizeof (struct aac_card_type) - 1)
#define	CARD_IS_UNKNOWN(i)	(i == AAC_UNKNOWN_CARD)
#define	BUF_IS_READ(bp)		((bp)->b_flags & B_READ)
#define	AAC_IS_Q_EMPTY(q)	((q)->q_head == NULL)
#define	AAC_CMDQ(acp)		(!((acp)->flags & AAC_CMD_SYNC))

#define	PCI_MEM_GET32(softs, off) \
	ddi_get32((softs)->pci_mem_handle, \
	    (void *)((softs)->pci_mem_base_vaddr + (off)))
#define	PCI_MEM_PUT32(softs, off, val) \
	ddi_put32((softs)->pci_mem_handle, \
	    (void *)((softs)->pci_mem_base_vaddr + (off)), \
	    (uint32_t)(val))
#define	PCI_MEM_GET16(softs, off) \
	ddi_get16((softs)->pci_mem_handle, \
	(void *)((softs)->pci_mem_base_vaddr + (off)))
#define	PCI_MEM_PUT16(softs, off, val) \
	ddi_put16((softs)->pci_mem_handle, \
	(void *)((softs)->pci_mem_base_vaddr + (off)), (uint16_t)(val))
/* Write host data at valp to device mem[off] repeatedly count times */
#define	PCI_MEM_REP_PUT8(softs, off, valp, count) \
	ddi_rep_put8((softs)->pci_mem_handle, (uint8_t *)(valp), \
	    (uint8_t *)((softs)->pci_mem_base_vaddr + (off)), \
	    count, DDI_DEV_AUTOINCR)
/* Read device data at mem[off] to host addr valp repeatedly count times */
#define	PCI_MEM_REP_GET8(softs, off, valp, count) \
	ddi_rep_get8((softs)->pci_mem_handle, (uint8_t *)(valp), \
	    (uint8_t *)((softs)->pci_mem_base_vaddr + (off)), \
	    count, DDI_DEV_AUTOINCR)
#define	AAC_GET_FIELD8(acc, d, s, field) \
	(d)->field = ddi_get8(acc, (uint8_t *)&(s)->field)
#define	AAC_GET_FIELD32(acc, d, s, field) \
	(d)->field = ddi_get32(acc, (uint32_t *)&(s)->field)
#define	AAC_GET_FIELD64(acc, d, s, field) \
	(d)->field = ddi_get64(acc, (uint64_t *)&(s)->field)
#define	AAC_REP_GET_FIELD8(acc, d, s, field, r) \
	ddi_rep_get8((acc), (uint8_t *)&(d)->field, \
	    (uint8_t *)&(s)->field, (r), DDI_DEV_AUTOINCR)
#define	AAC_REP_GET_FIELD32(acc, d, s, field, r) \
	ddi_rep_get32((acc), (uint32_t *)&(d)->field, \
	    (uint32_t *)&(s)->field, (r), DDI_DEV_AUTOINCR)

#define	AAC_ENABLE_INTR(softs) { \
		if (softs->flags & AAC_FLAGS_NEW_COMM) \
			PCI_MEM_PUT32(softs, AAC_OIMR, ~AAC_DB_INTR_NEW); \
		else \
			PCI_MEM_PUT32(softs, AAC_OIMR, ~AAC_DB_INTR_BITS); \
		softs->state |= AAC_STATE_INTR; \
	}

#define	AAC_DISABLE_INTR(softs)	{ \
		PCI_MEM_PUT32(softs, AAC_OIMR, ~0); \
		softs->state &= ~AAC_STATE_INTR; \
	}
#define	AAC_STATUS_CLR(softs, mask)	PCI_MEM_PUT32(softs, AAC_ODBR, mask)
#define	AAC_STATUS_GET(softs)		PCI_MEM_GET32(softs, AAC_ODBR)
#define	AAC_NOTIFY(softs, val)		PCI_MEM_PUT32(softs, AAC_IDBR, val)
#define	AAC_OUTB_GET(softs)		PCI_MEM_GET32(softs, AAC_OQUE)
#define	AAC_OUTB_SET(softs, val)	PCI_MEM_PUT32(softs, AAC_OQUE, val)
#define	AAC_FWSTATUS_GET(softs)	\
	((softs)->aac_if.aif_get_fwstatus(softs))
#define	AAC_MAILBOX_GET(softs, mb) \
	((softs)->aac_if.aif_get_mailbox((softs), (mb)))
#define	AAC_MAILBOX_SET(softs, cmd, arg0, arg1, arg2, arg3) \
	((softs)->aac_if.aif_set_mailbox((softs), (cmd), \
	    (arg0), (arg1), (arg2), (arg3)))

#define	AAC_MGT_SLOT_NUM	2
#define	AAC_THROTTLE_DRAIN	-1

#define	AAC_QUIESCE_TICK	1	/* 1 second */
#define	AAC_QUIESCE_TIMEOUT	180	/* 180 seconds */
#define	AAC_DEFAULT_TICK	10	/* 10 seconds */
#define	AAC_SYNC_TICK		(30*60)	/* 30 minutes */

/* Poll time for aac_do_poll_io() */
#define	AAC_POLL_TIME		60	/* 60 seconds */

/* IOP reset */
#define	AAC_IOP_RESET_SUCCEED		0	/* IOP reset succeed */
#define	AAC_IOP_RESET_FAILED		-1	/* IOP reset failed */
#define	AAC_IOP_RESET_ABNORMAL		-2	/* Reset operation abnormal */

/*
 * Hardware access functions
 */
static int aac_rx_get_fwstatus(struct aac_softstate *);
static int aac_rx_get_mailbox(struct aac_softstate *, int);
static void aac_rx_set_mailbox(struct aac_softstate *, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t);
static int aac_rkt_get_fwstatus(struct aac_softstate *);
static int aac_rkt_get_mailbox(struct aac_softstate *, int);
static void aac_rkt_set_mailbox(struct aac_softstate *, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t);

/*
 * SCSA function prototypes
 */
static int aac_attach(dev_info_t *, ddi_attach_cmd_t);
static int aac_detach(dev_info_t *, ddi_detach_cmd_t);
static int aac_reset(dev_info_t *, ddi_reset_cmd_t);
static int aac_quiesce(dev_info_t *);
static int aac_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/*
 * Interrupt handler functions
 */
static int aac_query_intrs(struct aac_softstate *, int);
static int aac_add_intrs(struct aac_softstate *);
static void aac_remove_intrs(struct aac_softstate *);
static int aac_enable_intrs(struct aac_softstate *);
static int aac_disable_intrs(struct aac_softstate *);
static uint_t aac_intr_old(caddr_t);
static uint_t aac_intr_new(caddr_t);
static uint_t aac_softintr(caddr_t);

/*
 * Internal functions in attach
 */
static int aac_check_card_type(struct aac_softstate *);
static int aac_check_firmware(struct aac_softstate *);
static int aac_common_attach(struct aac_softstate *);
static void aac_common_detach(struct aac_softstate *);
static int aac_probe_containers(struct aac_softstate *);
static int aac_alloc_comm_space(struct aac_softstate *);
static int aac_setup_comm_space(struct aac_softstate *);
static void aac_free_comm_space(struct aac_softstate *);
static int aac_hba_setup(struct aac_softstate *);

/*
 * Sync FIB operation functions
 */
int aac_sync_mbcommand(struct aac_softstate *, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t *);
static int aac_sync_fib(struct aac_softstate *, uint16_t, uint16_t);

/*
 * Command queue operation functions
 */
static void aac_cmd_initq(struct aac_cmd_queue *);
static void aac_cmd_enqueue(struct aac_cmd_queue *, struct aac_cmd *);
static struct aac_cmd *aac_cmd_dequeue(struct aac_cmd_queue *);
static void aac_cmd_delete(struct aac_cmd_queue *, struct aac_cmd *);

/*
 * FIB queue operation functions
 */
static int aac_fib_enqueue(struct aac_softstate *, int, uint32_t, uint32_t);
static int aac_fib_dequeue(struct aac_softstate *, int, int *);

/*
 * Slot operation functions
 */
static int aac_create_slots(struct aac_softstate *);
static void aac_destroy_slots(struct aac_softstate *);
static void aac_alloc_fibs(struct aac_softstate *);
static void aac_destroy_fibs(struct aac_softstate *);
static struct aac_slot *aac_get_slot(struct aac_softstate *);
static void aac_release_slot(struct aac_softstate *, struct aac_slot *);
static int aac_alloc_fib(struct aac_softstate *, struct aac_slot *);
static void aac_free_fib(struct aac_slot *);

/*
 * Internal functions
 */
static void aac_cmd_fib_header(struct aac_softstate *, struct aac_cmd *,
    uint16_t);
static void aac_cmd_fib_rawio(struct aac_softstate *, struct aac_cmd *);
static void aac_cmd_fib_brw64(struct aac_softstate *, struct aac_cmd *);
static void aac_cmd_fib_brw(struct aac_softstate *, struct aac_cmd *);
static void aac_cmd_fib_sync(struct aac_softstate *, struct aac_cmd *);
static void aac_cmd_fib_scsi32(struct aac_softstate *, struct aac_cmd *);
static void aac_cmd_fib_scsi64(struct aac_softstate *, struct aac_cmd *);
static void aac_cmd_fib_startstop(struct aac_softstate *, struct aac_cmd *);
static void aac_start_waiting_io(struct aac_softstate *);
static void aac_drain_comp_q(struct aac_softstate *);
int aac_do_io(struct aac_softstate *, struct aac_cmd *);
static int aac_sync_fib_slot_bind(struct aac_softstate *, struct aac_cmd *);
static void aac_sync_fib_slot_release(struct aac_softstate *, struct aac_cmd *);
static void aac_start_io(struct aac_softstate *, struct aac_cmd *);
static int aac_do_poll_io(struct aac_softstate *, struct aac_cmd *);
static int aac_do_sync_io(struct aac_softstate *, struct aac_cmd *);
static int aac_send_command(struct aac_softstate *, struct aac_slot *);
static void aac_cmd_timeout(struct aac_softstate *, struct aac_cmd *);
static int aac_dma_sync_ac(struct aac_cmd *);
static int aac_shutdown(struct aac_softstate *);
static int aac_reset_adapter(struct aac_softstate *);
static int aac_do_quiesce(struct aac_softstate *softs);
static int aac_do_unquiesce(struct aac_softstate *softs);
static void aac_unhold_bus(struct aac_softstate *, int);
static void aac_set_throttle(struct aac_softstate *, struct aac_device *,
    int, int);

/*
 * Adapter Initiated FIB handling function
 */
static void aac_save_aif(struct aac_softstate *, ddi_acc_handle_t,
    struct aac_fib *, int);
static int aac_handle_aif(struct aac_softstate *, struct aac_aif_command *);

/*
 * Event handling related functions
 */
static void aac_timer(void *);
static void aac_event_thread(struct aac_softstate *);
static void aac_event_disp(struct aac_softstate *, int);

/*
 * IOCTL interface related functions
 */
static int aac_open(dev_t *, int, int, cred_t *);
static int aac_close(dev_t, int, int, cred_t *);
static int aac_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern int aac_do_ioctl(struct aac_softstate *, dev_t, int, intptr_t, int);

/*
 * FMA Prototypes
 */
static void aac_fm_init(struct aac_softstate *);
static void aac_fm_fini(struct aac_softstate *);
static int aac_fm_error_cb(dev_info_t *, ddi_fm_error_t *, const void *);
int aac_check_acc_handle(ddi_acc_handle_t);
int aac_check_dma_handle(ddi_dma_handle_t);
void aac_fm_ereport(struct aac_softstate *, char *);

/*
 * Auto enumeration functions
 */
static dev_info_t *aac_find_child(struct aac_softstate *, uint16_t, uint8_t);
static int aac_tran_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *, dev_info_t **);
static int aac_handle_dr(struct aac_softstate *, int, int, int);

extern pri_t minclsyspri;

#ifdef DEBUG
/*
 * UART	debug output support
 */

#define	AAC_PRINT_BUFFER_SIZE		512
#define	AAC_PRINT_TIMEOUT		250	/* 1/4 sec. = 250 msec. */

#define	AAC_FW_DBG_STRLEN_OFFSET	0x00
#define	AAC_FW_DBG_FLAGS_OFFSET		0x04
#define	AAC_FW_DBG_BLED_OFFSET		0x08

static int aac_get_fw_debug_buffer(struct aac_softstate *);
static void aac_print_scmd(struct aac_softstate *, struct aac_cmd *);
static void aac_print_aif(struct aac_softstate *, struct aac_aif_command *);

static char aac_prt_buf[AAC_PRINT_BUFFER_SIZE];
static char aac_fmt[] = " %s";
static char aac_fmt_header[] = " %s.%d: %s";
static kmutex_t aac_prt_mutex;

/*
 * Debug flags to be put into the softstate flags field
 * when initialized
 */
uint32_t aac_debug_flags =
/*    AACDB_FLAGS_KERNEL_PRINT | */
/*    AACDB_FLAGS_FW_PRINT |	*/
/*    AACDB_FLAGS_MISC |	*/
/*    AACDB_FLAGS_FUNC1 |	*/
/*    AACDB_FLAGS_FUNC2 |	*/
/*    AACDB_FLAGS_SCMD |	*/
/*    AACDB_FLAGS_AIF |		*/
/*    AACDB_FLAGS_FIB |		*/
/*    AACDB_FLAGS_IOCTL |	*/
0;
uint32_t aac_debug_fib_flags =
/*    AACDB_FLAGS_FIB_RW |	*/
/*    AACDB_FLAGS_FIB_IOCTL |	*/
/*    AACDB_FLAGS_FIB_SRB |	*/
/*    AACDB_FLAGS_FIB_SYNC |	*/
/*    AACDB_FLAGS_FIB_HEADER |	*/
/*    AACDB_FLAGS_FIB_TIMEOUT |	*/
0;

#endif /* DEBUG */

static struct cb_ops aac_cb_ops = {
	aac_open,	/* open */
	aac_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	aac_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,		/* streamtab */
	D_64BIT | D_NEW | D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,		/* cb_rev */
	nodev,		/* async I/O read entry point */
	nodev		/* async I/O write entry point */
};

static struct dev_ops aac_dev_ops = {
	DEVO_REV,
	0,
	aac_getinfo,
	nulldev,
	nulldev,
	aac_attach,
	aac_detach,
	aac_reset,
	&aac_cb_ops,
	NULL,
	NULL,
	aac_quiesce,
};

static struct modldrv aac_modldrv = {
	&mod_driverops,
	"AAC Driver " AAC_DRIVER_VERSION,
	&aac_dev_ops,
};

static struct modlinkage aac_modlinkage = {
	MODREV_1,
	&aac_modldrv,
	NULL
};

static struct aac_softstate  *aac_softstatep;

/*
 * Supported card list
 * ordered in vendor id, subvendor id, subdevice id, and device id
 */
static struct aac_card_type aac_cards[] = {
	{0x1028, 0x1, 0x1028, 0x1, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x1028, 0x2, 0x1028, 0x2, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x1028, 0x3, 0x1028, 0x3, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Si"},
	{0x1028, 0x8, 0x1028, 0xcf, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x1028, 0x4, 0x1028, 0xd0, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Si"},
	{0x1028, 0x2, 0x1028, 0xd1, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x1028, 0x2, 0x1028, 0xd9, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x106, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x11b, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x121, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG, AAC_TYPE_SCSI,
	    "Dell", "PERC 3/Di"},
	{0x9005, 0x285, 0x1028, 0x287, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
	    "Dell", "PERC 320/DC"},
	{0x9005, 0x285, 0x1028, 0x291, AAC_HWIF_I960RX,
	    AAC_FLAGS_17SG, AAC_TYPE_SATA, "Dell", "CERC SR2"},

	{0x9005, 0x285, 0x1014, 0x2f2, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SCSI, "IBM", "ServeRAID 8i"},
	{0x9005, 0x285, 0x1014, 0x34d, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "IBM", "ServeRAID 8s"},
	{0x9005, 0x286, 0x1014, 0x9580, AAC_HWIF_RKT,
	    0, AAC_TYPE_SAS, "IBM", "ServeRAID 8k"},

	{0x9005, 0x285, 0x103c, 0x3227, AAC_HWIF_I960RX,
	    AAC_FLAGS_17SG, AAC_TYPE_SATA, "Adaptec", "2610SA"},
	{0x9005, 0x285, 0xe11, 0x295, AAC_HWIF_I960RX,
	    AAC_FLAGS_17SG, AAC_TYPE_SATA, "Adaptec", "2610SA"},

	{0x9005, 0x285, 0x9005, 0x285, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
	    "Adaptec", "2200S"},
	{0x9005, 0x285, 0x9005, 0x286, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
	    "Adaptec", "2120S"},
	{0x9005, 0x285, 0x9005, 0x287, AAC_HWIF_I960RX,
	    AAC_FLAGS_NO4GB | AAC_FLAGS_34SG | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
	    "Adaptec", "2200S"},
	{0x9005, 0x285, 0x9005, 0x288, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SCSI, "Adaptec", "3230S"},
	{0x9005, 0x285, 0x9005, 0x289, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SCSI, "Adaptec", "3240S"},
	{0x9005, 0x285, 0x9005, 0x28a, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SCSI, "Adaptec", "2020ZCR"},
	{0x9005, 0x285, 0x9005, 0x28b, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SCSI, "Adaptec", "2025ZCR"},
	{0x9005, 0x286, 0x9005, 0x28c, AAC_HWIF_RKT,
	    0, AAC_TYPE_SCSI, "Adaptec", "2230S"},
	{0x9005, 0x286, 0x9005, 0x28d, AAC_HWIF_RKT,
	    0, AAC_TYPE_SCSI, "Adaptec", "2130S"},
	{0x9005, 0x285, 0x9005, 0x28e, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SATA, "Adaptec", "2020SA"},
	{0x9005, 0x285, 0x9005, 0x28f, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SATA, "Adaptec", "2025SA"},
	{0x9005, 0x285, 0x9005, 0x290, AAC_HWIF_I960RX,
	    AAC_FLAGS_17SG, AAC_TYPE_SATA, "Adaptec", "2410SA"},
	{0x9005, 0x285, 0x9005, 0x292, AAC_HWIF_I960RX,
	    AAC_FLAGS_17SG, AAC_TYPE_SATA, "Adaptec", "2810SA"},
	{0x9005, 0x285, 0x9005, 0x293, AAC_HWIF_I960RX,
	    AAC_FLAGS_17SG, AAC_TYPE_SATA, "Adaptec", "21610SA"},
	{0x9005, 0x285, 0x9005, 0x294, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SATA, "Adaptec", "2026ZCR"},
	{0x9005, 0x285, 0x9005, 0x296, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SCSI, "Adaptec", "2240S"},
	{0x9005, 0x285, 0x9005, 0x297, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "Adaptec", "4005SAS"},
	{0x9005, 0x285, 0x9005, 0x298, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "Adaptec", "RAID 4000"},
	{0x9005, 0x285, 0x9005, 0x299, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "Adaptec", "4800SAS"},
	{0x9005, 0x285, 0x9005, 0x29a, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "Adaptec", "4805SAS"},
	{0x9005, 0x286, 0x9005, 0x29b, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "Adaptec", "2820SA"},
	{0x9005, 0x286, 0x9005, 0x29c, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "Adaptec", "2620SA"},
	{0x9005, 0x286, 0x9005, 0x29d, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "Adaptec", "2420SA"},
	{0x9005, 0x286, 0x9005, 0x29e, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "ICP", "9024RO"},
	{0x9005, 0x286, 0x9005, 0x29f, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "ICP", "9014RO"},
	{0x9005, 0x286, 0x9005, 0x2a0, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "ICP", "9047MA"},
	{0x9005, 0x286, 0x9005, 0x2a1, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "ICP", "9087MA"},
	{0x9005, 0x285, 0x9005, 0x2a4, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "ICP", "9085LI"},
	{0x9005, 0x285, 0x9005, 0x2a5, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "ICP", "5085BR"},
	{0x9005, 0x286, 0x9005, 0x2a6, AAC_HWIF_RKT,
	    0, AAC_TYPE_SATA, "ICP", "9067MA"},
	{0x9005, 0x285, 0x9005, 0x2b5, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "Adaptec", "RAID 5445"},
	{0x9005, 0x285, 0x9005, 0x2b6, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "Adaptec", "RAID 5805"},
	{0x9005, 0x285, 0x9005, 0x2b7, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "Adaptec", "RAID 5085"},
	{0x9005, 0x285, 0x9005, 0x2b8, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "ICP", "RAID ICP5445SL"},
	{0x9005, 0x285, 0x9005, 0x2b9, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "ICP", "RAID ICP5085SL"},
	{0x9005, 0x285, 0x9005, 0x2ba, AAC_HWIF_I960RX,
	    0, AAC_TYPE_SAS, "ICP", "RAID ICP5805SL"},

	{0, 0, 0, 0, AAC_HWIF_UNKNOWN,
	    0, AAC_TYPE_UNKNOWN, "Unknown", "AAC card"},
};

/*
 * Hardware access functions for i960 based cards
 */
static struct aac_interface aac_rx_interface = {
	aac_rx_get_fwstatus,
	aac_rx_get_mailbox,
	aac_rx_set_mailbox
};

/*
 * Hardware access functions for Rocket based cards
 */
static struct aac_interface aac_rkt_interface = {
	aac_rkt_get_fwstatus,
	aac_rkt_get_mailbox,
	aac_rkt_set_mailbox
};

ddi_device_acc_attr_t aac_acc_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static struct {
	int	size;
	int	notify;
} aac_qinfo[] = {
	{AAC_HOST_NORM_CMD_ENTRIES, AAC_DB_COMMAND_NOT_FULL},
	{AAC_HOST_HIGH_CMD_ENTRIES, 0},
	{AAC_ADAP_NORM_CMD_ENTRIES, AAC_DB_COMMAND_READY},
	{AAC_ADAP_HIGH_CMD_ENTRIES, 0},
	{AAC_HOST_NORM_RESP_ENTRIES, AAC_DB_RESPONSE_NOT_FULL},
	{AAC_HOST_HIGH_RESP_ENTRIES, 0},
	{AAC_ADAP_NORM_RESP_ENTRIES, AAC_DB_RESPONSE_READY},
	{AAC_ADAP_HIGH_RESP_ENTRIES, 0}
};

/*
 * Default aac dma attributes
 */
static ddi_dma_attr_t aac_dma_attr = {
	DMA_ATTR_V0,
	0,		/* lowest usable address */
	0xffffffffull,	/* high DMA address range */
	0xffffffffull,	/* DMA counter register */
	AAC_DMA_ALIGN,	/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xffffffffull,	/* max DMA xfer size */
	0xffffffffull,	/* segment boundary */
	1,		/* s/g list length */
	AAC_BLK_SIZE,	/* granularity of device */
	0		/* DMA transfer flags */
};

static int aac_tick = AAC_DEFAULT_TICK;	/* tick for the internal timer */
static uint32_t aac_timebase = 0;	/* internal timer in seconds */

/*
 * Warlock directives
 *
 * Different variables with the same types have to be protected by the
 * same mutex; otherwise, warlock will complain with "variables don't
 * seem to be protected consistently". For example,
 * aac_softstate::{q_wait, q_comp} are type of aac_cmd_queue, and protected
 * by aac_softstate::{io_lock, q_comp_mutex} respectively. We have to
 * declare them as protected explictly at aac_cmd_dequeue().
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", scsi_pkt scsi_cdb scsi_status \
    scsi_arq_status scsi_descr_sense_hdr scsi_information_sense_descr \
    mode_format mode_geometry mode_header aac_cmd))
_NOTE(SCHEME_PROTECTS_DATA("unique per aac_cmd", aac_fib ddi_dma_cookie_t \
    aac_sge))
_NOTE(SCHEME_PROTECTS_DATA("unique per aac_fib", aac_blockread aac_blockwrite \
    aac_blockread64 aac_raw_io aac_sg_entry aac_sg_entry64 aac_sg_entryraw \
    aac_sg_table aac_srb))
_NOTE(SCHEME_PROTECTS_DATA("unique to sync fib and cdb", scsi_inquiry))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device scsi_address))
_NOTE(SCHEME_PROTECTS_DATA("unique to scsi_transport", buf))

int
_init(void)
{
	int rval = 0;

#ifdef DEBUG
	mutex_init(&aac_prt_mutex, NULL, MUTEX_DRIVER, NULL);
#endif
	DBCALLED(NULL, 1);

	if ((rval = ddi_soft_state_init((void *)&aac_softstatep,
	    sizeof (struct aac_softstate), 0)) != 0)
		goto error;

	if ((rval = scsi_hba_init(&aac_modlinkage)) != 0) {
		ddi_soft_state_fini((void *)&aac_softstatep);
		goto error;
	}

	if ((rval = mod_install(&aac_modlinkage)) != 0) {
		ddi_soft_state_fini((void *)&aac_softstatep);
		scsi_hba_fini(&aac_modlinkage);
		goto error;
	}
	return (rval);

error:
	AACDB_PRINT(NULL, CE_WARN, "Mod init error!");
#ifdef DEBUG
	mutex_destroy(&aac_prt_mutex);
#endif
	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	DBCALLED(NULL, 1);
	return (mod_info(&aac_modlinkage, modinfop));
}

/*
 * An HBA driver cannot be unload unless you reboot,
 * so this function will be of no use.
 */
int
_fini(void)
{
	int rval;

	DBCALLED(NULL, 1);

	if ((rval = mod_remove(&aac_modlinkage)) != 0)
		goto error;

	scsi_hba_fini(&aac_modlinkage);
	ddi_soft_state_fini((void *)&aac_softstatep);
#ifdef DEBUG
	mutex_destroy(&aac_prt_mutex);
#endif
	return (0);

error:
	AACDB_PRINT(NULL, CE_WARN, "AAC is busy, cannot unload!");
	return (rval);
}

static int
aac_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance, i;
	struct aac_softstate *softs = NULL;
	int attach_state = 0;
	char *data;

	DBCALLED(NULL, 1);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_FAILURE);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/* Get soft state */
	if (ddi_soft_state_zalloc(aac_softstatep, instance) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN, "Cannot alloc soft state");
		goto error;
	}
	softs = ddi_get_soft_state(aac_softstatep, instance);
	attach_state |= AAC_ATTACH_SOFTSTATE_ALLOCED;

	softs->instance = instance;
	softs->devinfo_p = dip;
	softs->buf_dma_attr = softs->addr_dma_attr = aac_dma_attr;
	softs->addr_dma_attr.dma_attr_granular = 1;
	softs->acc_attr = aac_acc_attr;
	softs->reg_attr = aac_acc_attr;
	softs->card = AAC_UNKNOWN_CARD;
#ifdef DEBUG
	softs->debug_flags = aac_debug_flags;
	softs->debug_fib_flags = aac_debug_fib_flags;
#endif

	/* Initialize FMA */
	aac_fm_init(softs);

	/* Check the card type */
	if (aac_check_card_type(softs) == AACERR) {
		AACDB_PRINT(softs, CE_WARN, "Card not supported");
		goto error;
	}
	/* We have found the right card and everything is OK */
	attach_state |= AAC_ATTACH_CARD_DETECTED;

	/* Map PCI mem space */
	if (ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&softs->pci_mem_base_vaddr, 0,
	    softs->map_size_min, &softs->reg_attr,
	    &softs->pci_mem_handle) != DDI_SUCCESS)
		goto error;

	softs->map_size = softs->map_size_min;
	attach_state |= AAC_ATTACH_PCI_MEM_MAPPED;

	AAC_DISABLE_INTR(softs);

	/* Init mutexes and condvars */
	mutex_init(&softs->io_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(softs->intr_pri));
	mutex_init(&softs->q_comp_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(softs->intr_pri));
	mutex_init(&softs->time_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(softs->intr_pri));
	mutex_init(&softs->ev_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(softs->intr_pri));
	mutex_init(&softs->aifq_mutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(softs->intr_pri));
	cv_init(&softs->event, NULL, CV_DRIVER, NULL);
	cv_init(&softs->sync_fib_cv, NULL, CV_DRIVER, NULL);
	cv_init(&softs->drain_cv, NULL, CV_DRIVER, NULL);
	cv_init(&softs->event_wait_cv, NULL, CV_DRIVER, NULL);
	cv_init(&softs->event_disp_cv, NULL, CV_DRIVER, NULL);
	cv_init(&softs->aifq_cv, NULL, CV_DRIVER, NULL);
	attach_state |= AAC_ATTACH_KMUTEX_INITED;

	/* Init the cmd queues */
	for (i = 0; i < AAC_CMDQ_NUM; i++)
		aac_cmd_initq(&softs->q_wait[i]);
	aac_cmd_initq(&softs->q_busy);
	aac_cmd_initq(&softs->q_comp);

	/* Check for legacy device naming support */
	softs->legacy = 1; /* default to use legacy name */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    "legacy-name-enable", &data) == DDI_SUCCESS)) {
		if (strcmp(data, "no") == 0) {
			AACDB_PRINT(softs, CE_NOTE, "legacy-name disabled");
			softs->legacy = 0;
		}
		ddi_prop_free(data);
	}

	/*
	 * Everything has been set up till now,
	 * we will do some common attach.
	 */
	mutex_enter(&softs->io_lock);
	if (aac_common_attach(softs) == AACERR) {
		mutex_exit(&softs->io_lock);
		goto error;
	}
	mutex_exit(&softs->io_lock);
	attach_state |= AAC_ATTACH_COMM_SPACE_SETUP;

	/* Check for buf breakup support */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
	    "breakup-enable", &data) == DDI_SUCCESS)) {
		if (strcmp(data, "yes") == 0) {
			AACDB_PRINT(softs, CE_NOTE, "buf breakup enabled");
			softs->flags |= AAC_FLAGS_BRKUP;
		}
		ddi_prop_free(data);
	}
	softs->dma_max = softs->buf_dma_attr.dma_attr_maxxfer;
	if (softs->flags & AAC_FLAGS_BRKUP) {
		softs->dma_max = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "dma-max", softs->dma_max);
	}

	if (aac_hba_setup(softs) != AACOK)
		goto error;
	attach_state |= AAC_ATTACH_SCSI_TRAN_SETUP;

	/* Create devctl/scsi nodes for cfgadm */
	if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    INST2DEVCTL(instance), DDI_NT_SCSI_NEXUS, 0) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN, "failed to create devctl node");
		goto error;
	}
	attach_state |= AAC_ATTACH_CREATE_DEVCTL;

	if (ddi_create_minor_node(dip, "scsi", S_IFCHR, INST2SCSI(instance),
	    DDI_NT_SCSI_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN, "failed to create scsi node");
		goto error;
	}
	attach_state |= AAC_ATTACH_CREATE_SCSI;

	/* Create aac node for app. to issue ioctls */
	if (ddi_create_minor_node(dip, "aac", S_IFCHR, INST2AAC(instance),
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN, "failed to create aac node");
		goto error;
	}

	/* Common attach is OK, so we are attached! */
	softs->state |= AAC_STATE_RUN;

	/* Create event thread */
	softs->fibctx_p = &softs->aifctx;
	if ((softs->event_thread = thread_create(NULL, 0, aac_event_thread,
	    softs, 0, &p0, TS_RUN, minclsyspri)) == NULL) {
		AACDB_PRINT(softs, CE_WARN, "aif thread create failed");
		softs->state &= ~AAC_STATE_RUN;
		goto error;
	}

	aac_unhold_bus(softs, AAC_IOCMD_SYNC | AAC_IOCMD_ASYNC);

	/* Create a thread for command timeout */
	softs->timeout_id = timeout(aac_timer, (void *)softs,
	    (aac_tick * drv_usectohz(1000000)));

	/* Common attach is OK, so we are attached! */
	ddi_report_dev(dip);
	AACDB_PRINT(softs, CE_NOTE, "aac attached ok");
	return (DDI_SUCCESS);

error:
	if (attach_state & AAC_ATTACH_CREATE_SCSI)
		ddi_remove_minor_node(dip, "scsi");
	if (attach_state & AAC_ATTACH_CREATE_DEVCTL)
		ddi_remove_minor_node(dip, "devctl");
	if (attach_state & AAC_ATTACH_COMM_SPACE_SETUP)
		aac_common_detach(softs);
	if (attach_state & AAC_ATTACH_SCSI_TRAN_SETUP) {
		(void) scsi_hba_detach(dip);
		scsi_hba_tran_free(AAC_DIP2TRAN(dip));
	}
	if (attach_state & AAC_ATTACH_KMUTEX_INITED) {
		mutex_destroy(&softs->io_lock);
		mutex_destroy(&softs->q_comp_mutex);
		mutex_destroy(&softs->time_mutex);
		mutex_destroy(&softs->ev_lock);
		mutex_destroy(&softs->aifq_mutex);
		cv_destroy(&softs->event);
		cv_destroy(&softs->sync_fib_cv);
		cv_destroy(&softs->drain_cv);
		cv_destroy(&softs->event_wait_cv);
		cv_destroy(&softs->event_disp_cv);
		cv_destroy(&softs->aifq_cv);
	}
	if (attach_state & AAC_ATTACH_PCI_MEM_MAPPED)
		ddi_regs_map_free(&softs->pci_mem_handle);
	aac_fm_fini(softs);
	if (attach_state & AAC_ATTACH_CARD_DETECTED)
		softs->card = AACERR;
	if (attach_state & AAC_ATTACH_SOFTSTATE_ALLOCED)
		ddi_soft_state_free(aac_softstatep, instance);
	return (DDI_FAILURE);
}

static int
aac_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	scsi_hba_tran_t *tran = AAC_DIP2TRAN(dip);
	struct aac_softstate *softs = AAC_TRAN2SOFTS(tran);

	DBCALLED(softs, 1);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_FAILURE);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&softs->io_lock);
	AAC_DISABLE_INTR(softs);
	softs->state = AAC_STATE_STOPPED;

	ddi_remove_minor_node(dip, "aac");
	ddi_remove_minor_node(dip, "scsi");
	ddi_remove_minor_node(dip, "devctl");
	mutex_exit(&softs->io_lock);

	aac_common_detach(softs);

	mutex_enter(&softs->io_lock);
	(void) scsi_hba_detach(dip);
	scsi_hba_tran_free(tran);
	mutex_exit(&softs->io_lock);

	/* Stop timer */
	mutex_enter(&softs->time_mutex);
	if (softs->timeout_id) {
		timeout_id_t tid = softs->timeout_id;
		softs->timeout_id = 0;

		mutex_exit(&softs->time_mutex);
		(void) untimeout(tid);
		mutex_enter(&softs->time_mutex);
	}
	mutex_exit(&softs->time_mutex);

	/* Destroy event thread */
	mutex_enter(&softs->ev_lock);
	cv_signal(&softs->event_disp_cv);
	cv_wait(&softs->event_wait_cv, &softs->ev_lock);
	mutex_exit(&softs->ev_lock);

	cv_destroy(&softs->aifq_cv);
	cv_destroy(&softs->event_disp_cv);
	cv_destroy(&softs->event_wait_cv);
	cv_destroy(&softs->drain_cv);
	cv_destroy(&softs->sync_fib_cv);
	cv_destroy(&softs->event);
	mutex_destroy(&softs->aifq_mutex);
	mutex_destroy(&softs->ev_lock);
	mutex_destroy(&softs->time_mutex);
	mutex_destroy(&softs->q_comp_mutex);
	mutex_destroy(&softs->io_lock);

	ddi_regs_map_free(&softs->pci_mem_handle);
	aac_fm_fini(softs);
	softs->hwif = AAC_HWIF_UNKNOWN;
	softs->card = AAC_UNKNOWN_CARD;
	ddi_soft_state_free(aac_softstatep, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
aac_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	struct aac_softstate *softs = AAC_DIP2SOFTS(dip);

	DBCALLED(softs, 1);

	mutex_enter(&softs->io_lock);
	AAC_DISABLE_INTR(softs);
	(void) aac_shutdown(softs);
	mutex_exit(&softs->io_lock);

	return (DDI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
aac_quiesce(dev_info_t *dip)
{
	struct aac_softstate *softs = AAC_DIP2SOFTS(dip);

	if (softs == NULL)
		return (DDI_FAILURE);

	_NOTE(ASSUMING_PROTECTED(softs->state))
	AAC_DISABLE_INTR(softs);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
aac_getinfo(dev_info_t *self, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)(MINOR2INST(getminor((dev_t)arg)));
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * Bring the controller down to a dormant state and detach all child devices.
 * This function is called before detach or system shutdown.
 * Note: we can assume that the q_wait on the controller is empty, as we
 * won't allow shutdown if any device is open.
 */
static int
aac_shutdown(struct aac_softstate *softs)
{
	ddi_acc_handle_t acc;
	struct aac_close_command *cc;
	int rval;

	(void) aac_sync_fib_slot_bind(softs, &softs->sync_ac);
	acc = softs->sync_ac.slotp->fib_acc_handle;

	cc = (struct aac_close_command *)&softs->sync_ac.slotp->fibp->data[0];

	ddi_put32(acc, &cc->Command, VM_CloseAll);
	ddi_put32(acc, &cc->ContainerId, 0xfffffffful);

	/* Flush all caches, set FW to write through mode */
	rval = aac_sync_fib(softs, ContainerCommand,
	    AAC_FIB_SIZEOF(struct aac_close_command));
	aac_sync_fib_slot_release(softs, &softs->sync_ac);

	AACDB_PRINT(softs, CE_NOTE,
	    "shutting down aac %s", (rval == AACOK) ? "ok" : "fail");
	return (rval);
}

static uint_t
aac_softintr(caddr_t arg)
{
	struct aac_softstate *softs = (void *)arg;

	if (!AAC_IS_Q_EMPTY(&softs->q_comp)) {
		aac_drain_comp_q(softs);
	}
	return (DDI_INTR_CLAIMED);
}

/*
 * Setup auto sense data for pkt
 */
static void
aac_set_arq_data(struct scsi_pkt *pkt, uchar_t key,
    uchar_t add_code, uchar_t qual_code, uint64_t info)
{
	struct scsi_arq_status *arqstat = (void *)(pkt->pkt_scbp);

	*pkt->pkt_scbp = STATUS_CHECK; /* CHECK CONDITION */
	pkt->pkt_state |= STATE_ARQ_DONE;

	*(uint8_t *)&arqstat->sts_rqpkt_status = STATUS_GOOD;
	arqstat->sts_rqpkt_reason = CMD_CMPLT;
	arqstat->sts_rqpkt_resid = 0;
	arqstat->sts_rqpkt_state =
	    STATE_GOT_BUS |
	    STATE_GOT_TARGET |
	    STATE_SENT_CMD |
	    STATE_XFERRED_DATA;
	arqstat->sts_rqpkt_statistics = 0;

	if (info <= 0xfffffffful) {
		arqstat->sts_sensedata.es_valid = 1;
		arqstat->sts_sensedata.es_class = CLASS_EXTENDED_SENSE;
		arqstat->sts_sensedata.es_code = CODE_FMT_FIXED_CURRENT;
		arqstat->sts_sensedata.es_key = key;
		arqstat->sts_sensedata.es_add_code = add_code;
		arqstat->sts_sensedata.es_qual_code = qual_code;

		arqstat->sts_sensedata.es_info_1 = (info >> 24) & 0xFF;
		arqstat->sts_sensedata.es_info_2 = (info >> 16) & 0xFF;
		arqstat->sts_sensedata.es_info_3 = (info >>  8) & 0xFF;
		arqstat->sts_sensedata.es_info_4 = info & 0xFF;
	} else { /* 64-bit LBA */
		struct scsi_descr_sense_hdr *dsp;
		struct scsi_information_sense_descr *isd;

		dsp = (struct scsi_descr_sense_hdr *)&arqstat->sts_sensedata;
		dsp->ds_class = CLASS_EXTENDED_SENSE;
		dsp->ds_code = CODE_FMT_DESCR_CURRENT;
		dsp->ds_key = key;
		dsp->ds_add_code = add_code;
		dsp->ds_qual_code = qual_code;
		dsp->ds_addl_sense_length =
		    sizeof (struct scsi_information_sense_descr);

		isd = (struct scsi_information_sense_descr *)(dsp+1);
		isd->isd_descr_type = DESCR_INFORMATION;
		isd->isd_valid = 1;
		isd->isd_information[0] = (info >> 56) & 0xFF;
		isd->isd_information[1] = (info >> 48) & 0xFF;
		isd->isd_information[2] = (info >> 40) & 0xFF;
		isd->isd_information[3] = (info >> 32) & 0xFF;
		isd->isd_information[4] = (info >> 24) & 0xFF;
		isd->isd_information[5] = (info >> 16) & 0xFF;
		isd->isd_information[6] = (info >>  8) & 0xFF;
		isd->isd_information[7] = (info) & 0xFF;
	}
}

/*
 * Setup auto sense data for HARDWARE ERROR
 */
static void
aac_set_arq_data_hwerr(struct aac_cmd *acp)
{
	union scsi_cdb *cdbp;
	uint64_t err_blkno;

	cdbp = (void *)acp->pkt->pkt_cdbp;
	err_blkno = AAC_GETGXADDR(acp->cmdlen, cdbp);
	aac_set_arq_data(acp->pkt, KEY_HARDWARE_ERROR, 0x00, 0x00, err_blkno);
}

/*
 * Send a command to the adapter in New Comm. interface
 */
static int
aac_send_command(struct aac_softstate *softs, struct aac_slot *slotp)
{
	uint32_t index, device;

	index = PCI_MEM_GET32(softs, AAC_IQUE);
	if (index == 0xffffffffUL) {
		index = PCI_MEM_GET32(softs, AAC_IQUE);
		if (index == 0xffffffffUL)
			return (AACERR);
	}

	device = index;
	PCI_MEM_PUT32(softs, device,
	    (uint32_t)(slotp->fib_phyaddr & 0xfffffffful));
	device += 4;
	PCI_MEM_PUT32(softs, device, (uint32_t)(slotp->fib_phyaddr >> 32));
	device += 4;
	PCI_MEM_PUT32(softs, device, slotp->acp->fib_size);
	PCI_MEM_PUT32(softs, AAC_IQUE, index);
	return (AACOK);
}

static void
aac_end_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_device *dvp = acp->dvp;
	int q = AAC_CMDQ(acp);

	if (acp->slotp) { /* outstanding cmd */
		if (!(acp->flags & AAC_CMD_IN_SYNC_SLOT)) {
			aac_release_slot(softs, acp->slotp);
			acp->slotp = NULL;
		}
		if (dvp) {
			dvp->ncmds[q]--;
			if (dvp->throttle[q] == AAC_THROTTLE_DRAIN &&
			    dvp->ncmds[q] == 0 && q == AAC_CMDQ_ASYNC)
				aac_set_throttle(softs, dvp, q,
				    softs->total_slots);
			/*
			 * Setup auto sense data for UNIT ATTENTION
			 * Each lun should generate a unit attention
			 * condition when reset.
			 * Phys. drives are treated as logical ones
			 * during error recovery.
			 */
			if (dvp->type == AAC_DEV_LD) {
				struct aac_container *ctp =
				    (struct aac_container *)dvp;
				if (ctp->reset == 0)
					goto noreset;

				AACDB_PRINT(softs, CE_NOTE,
				    "Unit attention: reset");
				ctp->reset = 0;
				aac_set_arq_data(acp->pkt, KEY_UNIT_ATTENTION,
				    0x29, 0x02, 0);
			}
		}
noreset:
		softs->bus_ncmds[q]--;
		aac_cmd_delete(&softs->q_busy, acp);
	} else { /* cmd in waiting queue */
		aac_cmd_delete(&softs->q_wait[q], acp);
	}

	if (!(acp->flags & (AAC_CMD_NO_CB | AAC_CMD_NO_INTR))) { /* async IO */
		mutex_enter(&softs->q_comp_mutex);
		aac_cmd_enqueue(&softs->q_comp, acp);
		mutex_exit(&softs->q_comp_mutex);
	} else if (acp->flags & AAC_CMD_NO_CB) { /* sync IO */
		cv_broadcast(&softs->event);
	}
}

static void
aac_handle_io(struct aac_softstate *softs, int index)
{
	struct aac_slot *slotp;
	struct aac_cmd *acp;
	uint32_t fast;

	fast = index & AAC_SENDERADDR_MASK_FAST_RESPONSE;
	index >>= 2;

	/* Make sure firmware reported index is valid */
	ASSERT(index >= 0 && index < softs->total_slots);
	slotp = &softs->io_slot[index];
	ASSERT(slotp->index == index);
	acp = slotp->acp;

	if (acp == NULL || acp->slotp != slotp) {
		cmn_err(CE_WARN,
		    "Firmware error: invalid slot index received from FW");
		return;
	}

	acp->flags |= AAC_CMD_CMPLT;
	(void) ddi_dma_sync(slotp->fib_dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);

	if (aac_check_dma_handle(slotp->fib_dma_handle) == DDI_SUCCESS) {
		/*
		 * For fast response IO, the firmware do not return any FIB
		 * data, so we need to fill in the FIB status and state so that
		 * FIB users can handle it correctly.
		 */
		if (fast) {
			uint32_t state;

			state = ddi_get32(slotp->fib_acc_handle,
			    &slotp->fibp->Header.XferState);
			/*
			 * Update state for CPU not for device, no DMA sync
			 * needed
			 */
			ddi_put32(slotp->fib_acc_handle,
			    &slotp->fibp->Header.XferState,
			    state | AAC_FIBSTATE_DONEADAP);
			ddi_put32(slotp->fib_acc_handle,
			    (void *)&slotp->fibp->data[0], ST_OK);
		}

		/* Handle completed ac */
		acp->ac_comp(softs, acp);
	} else {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		acp->flags |= AAC_CMD_ERR;
		if (acp->pkt) {
			acp->pkt->pkt_reason = CMD_TRAN_ERR;
			acp->pkt->pkt_statistics = 0;
		}
	}
	aac_end_io(softs, acp);
}

/*
 * Interrupt handler for New Comm. interface
 * New Comm. interface use a different mechanism for interrupt. No explict
 * message queues, and driver need only accesses the mapped PCI mem space to
 * find the completed FIB or AIF.
 */
static int
aac_process_intr_new(struct aac_softstate *softs)
{
	uint32_t index;

	index = AAC_OUTB_GET(softs);
	if (index == 0xfffffffful)
		index = AAC_OUTB_GET(softs);
	if (aac_check_acc_handle(softs->pci_mem_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		return (0);
	}
	if (index != 0xfffffffful) {
		do {
			if ((index & AAC_SENDERADDR_MASK_AIF) == 0) {
				aac_handle_io(softs, index);
			} else if (index != 0xfffffffeul) {
				struct aac_fib *fibp;	/* FIB in AIF queue */
				uint16_t fib_size;

				/*
				 * 0xfffffffe means that the controller wants
				 * more work, ignore it for now. Otherwise,
				 * AIF received.
				 */
				index &= ~2;

				fibp = (struct aac_fib *)(softs-> \
				    pci_mem_base_vaddr + index);
				fib_size = PCI_MEM_GET16(softs, index + \
				    offsetof(struct aac_fib, Header.Size));

				aac_save_aif(softs, softs->pci_mem_handle,
				    fibp, fib_size);

				/*
				 * AIF memory is owned by the adapter, so let it
				 * know that we are done with it.
				 */
				AAC_OUTB_SET(softs, index);
				AAC_STATUS_CLR(softs, AAC_DB_RESPONSE_READY);
			}

			index = AAC_OUTB_GET(softs);
		} while (index != 0xfffffffful);

		/*
		 * Process waiting cmds before start new ones to
		 * ensure first IOs are serviced first.
		 */
		aac_start_waiting_io(softs);
		return (AAC_DB_COMMAND_READY);
	} else {
		return (0);
	}
}

static uint_t
aac_intr_new(caddr_t arg)
{
	struct aac_softstate *softs = (void *)arg;
	uint_t rval;

	mutex_enter(&softs->io_lock);
	if (aac_process_intr_new(softs))
		rval = DDI_INTR_CLAIMED;
	else
		rval = DDI_INTR_UNCLAIMED;
	mutex_exit(&softs->io_lock);

	aac_drain_comp_q(softs);
	return (rval);
}

/*
 * Interrupt handler for old interface
 * Explicit message queues are used to send FIB to and get completed FIB from
 * the adapter. Driver and adapter maitain the queues in the producer/consumer
 * manner. The driver has to query the queues to find the completed FIB.
 */
static int
aac_process_intr_old(struct aac_softstate *softs)
{
	uint16_t status;

	status = AAC_STATUS_GET(softs);
	if (aac_check_acc_handle(softs->pci_mem_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		return (DDI_INTR_UNCLAIMED);
	}
	if (status & AAC_DB_RESPONSE_READY) {
		int slot_idx;

		/* ACK the intr */
		AAC_STATUS_CLR(softs, AAC_DB_RESPONSE_READY);
		(void) AAC_STATUS_GET(softs);
		while (aac_fib_dequeue(softs, AAC_HOST_NORM_RESP_Q,
		    &slot_idx) == AACOK)
			aac_handle_io(softs, slot_idx);

		/*
		 * Process waiting cmds before start new ones to
		 * ensure first IOs are serviced first.
		 */
		aac_start_waiting_io(softs);
		return (AAC_DB_RESPONSE_READY);
	} else if (status & AAC_DB_COMMAND_READY) {
		int aif_idx;

		AAC_STATUS_CLR(softs, AAC_DB_COMMAND_READY);
		(void) AAC_STATUS_GET(softs);
		if (aac_fib_dequeue(softs, AAC_HOST_NORM_CMD_Q, &aif_idx) ==
		    AACOK) {
			ddi_acc_handle_t acc = softs->comm_space_acc_handle;
			struct aac_fib *fibp;	/* FIB in communication space */
			uint16_t fib_size;
			uint32_t fib_xfer_state;
			uint32_t addr, size;

			ASSERT((aif_idx >= 0) && (aif_idx < AAC_ADAPTER_FIBS));

#define	AAC_SYNC_AIF(softs, aif_idx, type) \
	{ (void) ddi_dma_sync((softs)->comm_space_dma_handle, \
	    offsetof(struct aac_comm_space, \
	    adapter_fibs[(aif_idx)]), AAC_FIB_SIZE, \
	    (type)); }

			/* Copy AIF from adapter to the empty AIF slot */
			AAC_SYNC_AIF(softs, aif_idx, DDI_DMA_SYNC_FORCPU);
			fibp = &softs->comm_space->adapter_fibs[aif_idx];
			fib_size = ddi_get16(acc, &fibp->Header.Size);

			aac_save_aif(softs, acc, fibp, fib_size);

			/* Complete AIF back to adapter with good status */
			fib_xfer_state = LE_32(fibp->Header.XferState);
			if (fib_xfer_state & AAC_FIBSTATE_FROMADAP) {
				ddi_put32(acc, &fibp->Header.XferState,
				    fib_xfer_state | AAC_FIBSTATE_DONEHOST);
				ddi_put32(acc, (void *)&fibp->data[0], ST_OK);
				if (fib_size > AAC_FIB_SIZE)
					ddi_put16(acc, &fibp->Header.Size,
					    AAC_FIB_SIZE);
				AAC_SYNC_AIF(softs, aif_idx,
				    DDI_DMA_SYNC_FORDEV);
			}

			/* Put the AIF response on the response queue */
			addr = ddi_get32(acc,
			    &softs->comm_space->adapter_fibs[aif_idx]. \
			    Header.SenderFibAddress);
			size = (uint32_t)ddi_get16(acc,
			    &softs->comm_space->adapter_fibs[aif_idx]. \
			    Header.Size);
			ddi_put32(acc,
			    &softs->comm_space->adapter_fibs[aif_idx]. \
			    Header.ReceiverFibAddress, addr);
			if (aac_fib_enqueue(softs, AAC_ADAP_NORM_RESP_Q,
			    addr, size) == AACERR)
				cmn_err(CE_NOTE, "!AIF ack failed");
		}
		return (AAC_DB_COMMAND_READY);
	} else if (status & AAC_DB_PRINTF_READY) {
		/* ACK the intr */
		AAC_STATUS_CLR(softs, AAC_DB_PRINTF_READY);
		(void) AAC_STATUS_GET(softs);
		(void) ddi_dma_sync(softs->comm_space_dma_handle,
		    offsetof(struct aac_comm_space, adapter_print_buf),
		    AAC_ADAPTER_PRINT_BUFSIZE, DDI_DMA_SYNC_FORCPU);
		if (aac_check_dma_handle(softs->comm_space_dma_handle) ==
		    DDI_SUCCESS)
			cmn_err(CE_NOTE, "MSG From Adapter: %s",
			    softs->comm_space->adapter_print_buf);
		else
			ddi_fm_service_impact(softs->devinfo_p,
			    DDI_SERVICE_UNAFFECTED);
		AAC_NOTIFY(softs, AAC_DB_PRINTF_READY);
		return (AAC_DB_PRINTF_READY);
	} else if (status & AAC_DB_COMMAND_NOT_FULL) {
		/*
		 * Without these two condition statements, the OS could hang
		 * after a while, especially if there are a lot of AIF's to
		 * handle, for instance if a drive is pulled from an array
		 * under heavy load.
		 */
		AAC_STATUS_CLR(softs, AAC_DB_COMMAND_NOT_FULL);
		return (AAC_DB_COMMAND_NOT_FULL);
	} else if (status & AAC_DB_RESPONSE_NOT_FULL) {
		AAC_STATUS_CLR(softs, AAC_DB_COMMAND_NOT_FULL);
		AAC_STATUS_CLR(softs, AAC_DB_RESPONSE_NOT_FULL);
		return (AAC_DB_RESPONSE_NOT_FULL);
	} else {
		return (0);
	}
}

static uint_t
aac_intr_old(caddr_t arg)
{
	struct aac_softstate *softs = (void *)arg;
	int rval;

	mutex_enter(&softs->io_lock);
	if (aac_process_intr_old(softs))
		rval = DDI_INTR_CLAIMED;
	else
		rval = DDI_INTR_UNCLAIMED;
	mutex_exit(&softs->io_lock);

	aac_drain_comp_q(softs);
	return (rval);
}

/*
 * Query FIXED or MSI interrupts
 */
static int
aac_query_intrs(struct aac_softstate *softs, int intr_type)
{
	dev_info_t *dip = softs->devinfo_p;
	int avail, actual, count;
	int i, flag, ret;

	AACDB_PRINT(softs, CE_NOTE,
	    "aac_query_intrs:interrupt type 0x%x", intr_type);

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		AACDB_PRINT(softs, CE_WARN,
		    "ddi_intr_get_nintrs() failed, ret %d count %d",
		    ret, count);
		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		AACDB_PRINT(softs, CE_WARN,
		    "ddi_intr_get_navail() failed, ret %d avail %d",
		    ret, avail);
		return (DDI_FAILURE);
	}

	AACDB_PRINT(softs, CE_NOTE,
	    "ddi_intr_get_nvail returned %d, navail() returned %d",
	    count, avail);

	/* Allocate an array of interrupt handles */
	softs->intr_size = count * sizeof (ddi_intr_handle_t);
	softs->htable = kmem_alloc(softs->intr_size, KM_SLEEP);

	if (intr_type == DDI_INTR_TYPE_MSI) {
		count = 1; /* only one vector needed by now */
		flag = DDI_INTR_ALLOC_STRICT;
	} else { /* must be DDI_INTR_TYPE_FIXED */
		flag = DDI_INTR_ALLOC_NORMAL;
	}

	/* Call ddi_intr_alloc() */
	ret = ddi_intr_alloc(dip, softs->htable, intr_type, 0,
	    count, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		AACDB_PRINT(softs, CE_WARN,
		    "ddi_intr_alloc() failed, ret = %d", ret);
		actual = 0;
		goto error;
	}

	if (actual < count) {
		AACDB_PRINT(softs, CE_NOTE,
		    "Requested: %d, Received: %d", count, actual);
		goto error;
	}

	softs->intr_cnt = actual;

	/* Get priority for first msi, assume remaining are all the same */
	if ((ret = ddi_intr_get_pri(softs->htable[0],
	    &softs->intr_pri)) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "ddi_intr_get_pri() failed, ret = %d", ret);
		goto error;
	}

	/* Test for high level mutex */
	if (softs->intr_pri >= ddi_intr_get_hilevel_pri()) {
		AACDB_PRINT(softs, CE_WARN,
		    "aac_query_intrs: Hi level interrupt not supported");
		goto error;
	}

	return (DDI_SUCCESS);

error:
	/* Free already allocated intr */
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(softs->htable[i]);

	kmem_free(softs->htable, softs->intr_size);
	return (DDI_FAILURE);
}


/*
 * Register FIXED or MSI interrupts, and enable them
 */
static int
aac_add_intrs(struct aac_softstate *softs)
{
	int i, ret;
	int actual;
	ddi_intr_handler_t *aac_intr;

	actual = softs->intr_cnt;
	aac_intr = (ddi_intr_handler_t *)((softs->flags & AAC_FLAGS_NEW_COMM) ?
	    aac_intr_new : aac_intr_old);

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(softs->htable[i],
		    aac_intr, (caddr_t)softs, NULL)) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "ddi_intr_add_handler() failed ret = %d", ret);

			/* Free already allocated intr */
			for (i = 0; i < actual; i++)
				(void) ddi_intr_free(softs->htable[i]);

			kmem_free(softs->htable, softs->intr_size);
			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(softs->htable[0], &softs->intr_cap))
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_intr_get_cap() failed, ret = %d", ret);

		/* Free already allocated intr */
		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(softs->htable[i]);

		kmem_free(softs->htable, softs->intr_size);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Unregister FIXED or MSI interrupts
 */
static void
aac_remove_intrs(struct aac_softstate *softs)
{
	int i;

	/* Disable all interrupts */
	(void) aac_disable_intrs(softs);
	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < softs->intr_cnt; i++) {
		(void) ddi_intr_remove_handler(softs->htable[i]);
		(void) ddi_intr_free(softs->htable[i]);
	}

	kmem_free(softs->htable, softs->intr_size);
}

static int
aac_enable_intrs(struct aac_softstate *softs)
{
	int rval = AACOK;

	if (softs->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* for MSI block enable */
		if (ddi_intr_block_enable(softs->htable, softs->intr_cnt) !=
		    DDI_SUCCESS)
			rval = AACERR;
	} else {
		int i;

		/* Call ddi_intr_enable() for legacy/MSI non block enable */
		for (i = 0; i < softs->intr_cnt; i++) {
			if (ddi_intr_enable(softs->htable[i]) != DDI_SUCCESS)
				rval = AACERR;
		}
	}
	return (rval);
}

static int
aac_disable_intrs(struct aac_softstate *softs)
{
	int rval = AACOK;

	if (softs->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		if (ddi_intr_block_disable(softs->htable, softs->intr_cnt) !=
		    DDI_SUCCESS)
			rval = AACERR;
	} else {
		int i;

		for (i = 0; i < softs->intr_cnt; i++) {
			if (ddi_intr_disable(softs->htable[i]) != DDI_SUCCESS)
				rval = AACERR;
		}
	}
	return (rval);
}

/*
 * Set pkt_reason and OR in pkt_statistics flag
 */
static void
aac_set_pkt_reason(struct aac_softstate *softs, struct aac_cmd *acp,
    uchar_t reason, uint_t stat)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(softs))
#endif
	if (acp->pkt->pkt_reason == CMD_CMPLT)
		acp->pkt->pkt_reason = reason;
	acp->pkt->pkt_statistics |= stat;
}

/*
 * Handle a finished pkt of soft SCMD
 */
static void
aac_soft_callback(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ASSERT(acp->pkt);

	acp->flags |= AAC_CMD_CMPLT;

	acp->pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET | \
	    STATE_SENT_CMD | STATE_GOT_STATUS;
	if (acp->pkt->pkt_state & STATE_XFERRED_DATA)
		acp->pkt->pkt_resid = 0;

	/* AAC_CMD_NO_INTR means no complete callback */
	if (!(acp->flags & AAC_CMD_NO_INTR)) {
		mutex_enter(&softs->q_comp_mutex);
		aac_cmd_enqueue(&softs->q_comp, acp);
		mutex_exit(&softs->q_comp_mutex);
		ddi_trigger_softintr(softs->softint_id);
	}
}

/*
 * Handlers for completed IOs, common to aac_intr_new() and aac_intr_old()
 */

/*
 * Handle completed logical device IO command
 */
/*ARGSUSED*/
static void
aac_ld_complete(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp = acp->slotp;
	struct aac_blockread_response *resp;
	uint32_t status;

	ASSERT(!(acp->flags & AAC_CMD_SYNC));
	ASSERT(!(acp->flags & AAC_CMD_NO_CB));

	acp->pkt->pkt_state |= STATE_GOT_STATUS;

	/*
	 * block_read/write has a similar response header, use blockread
	 * response for both.
	 */
	resp = (struct aac_blockread_response *)&slotp->fibp->data[0];
	status = ddi_get32(slotp->fib_acc_handle, &resp->Status);
	if (status == ST_OK) {
		acp->pkt->pkt_resid = 0;
		acp->pkt->pkt_state |= STATE_XFERRED_DATA;
	} else {
		aac_set_arq_data_hwerr(acp);
	}
}

/*
 * Handle completed phys. device IO command
 */
static void
aac_pd_complete(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_fib *fibp = acp->slotp->fibp;
	struct scsi_pkt *pkt = acp->pkt;
	struct aac_srb_reply *resp;
	uint32_t resp_status;

	ASSERT(!(acp->flags & AAC_CMD_SYNC));
	ASSERT(!(acp->flags & AAC_CMD_NO_CB));

	resp = (struct aac_srb_reply *)&fibp->data[0];
	resp_status = ddi_get32(acc, &resp->status);

	/* First check FIB status */
	if (resp_status == ST_OK) {
		uint32_t scsi_status;
		uint32_t srb_status;
		uint32_t data_xfer_length;

		scsi_status = ddi_get32(acc, &resp->scsi_status);
		srb_status = ddi_get32(acc, &resp->srb_status);
		data_xfer_length = ddi_get32(acc, &resp->data_xfer_length);

		*pkt->pkt_scbp = (uint8_t)scsi_status;
		pkt->pkt_state |= STATE_GOT_STATUS;
		if (scsi_status == STATUS_GOOD) {
			uchar_t cmd = ((union scsi_cdb *)(void *)
			    (pkt->pkt_cdbp))->scc_cmd;

			/* Next check SRB status */
			switch (srb_status & 0x3f) {
			case SRB_STATUS_DATA_OVERRUN:
				AACDB_PRINT(softs, CE_NOTE, "DATA_OVERRUN: " \
				    "scmd=%d, xfer=%d, buflen=%d",
				    (uint32_t)cmd, data_xfer_length,
				    acp->bcount);

				switch (cmd) {
				case SCMD_READ:
				case SCMD_WRITE:
				case SCMD_READ_G1:
				case SCMD_WRITE_G1:
				case SCMD_READ_G4:
				case SCMD_WRITE_G4:
				case SCMD_READ_G5:
				case SCMD_WRITE_G5:
					aac_set_pkt_reason(softs, acp,
					    CMD_DATA_OVR, 0);
					break;
				}
				/*FALLTHRU*/
			case SRB_STATUS_ERROR_RECOVERY:
			case SRB_STATUS_PENDING:
			case SRB_STATUS_SUCCESS:
				/*
				 * pkt_resid should only be calculated if the
				 * status is ERROR_RECOVERY/PENDING/SUCCESS/
				 * OVERRUN/UNDERRUN
				 */
				if (data_xfer_length) {
					pkt->pkt_state |= STATE_XFERRED_DATA;
					pkt->pkt_resid = acp->bcount - \
					    data_xfer_length;
					ASSERT(pkt->pkt_resid >= 0);
				}
				break;
			case SRB_STATUS_ABORTED:
				AACDB_PRINT(softs, CE_NOTE,
				    "SRB_STATUS_ABORTED, xfer=%d, resid=%d",
				    data_xfer_length, pkt->pkt_resid);
				aac_set_pkt_reason(softs, acp, CMD_ABORTED,
				    STAT_ABORTED);
				break;
			case SRB_STATUS_ABORT_FAILED:
				AACDB_PRINT(softs, CE_NOTE,
				    "SRB_STATUS_ABORT_FAILED, xfer=%d, " \
				    "resid=%d", data_xfer_length,
				    pkt->pkt_resid);
				aac_set_pkt_reason(softs, acp, CMD_ABORT_FAIL,
				    0);
				break;
			case SRB_STATUS_PARITY_ERROR:
				AACDB_PRINT(softs, CE_NOTE,
				    "SRB_STATUS_PARITY_ERROR, xfer=%d, " \
				    "resid=%d", data_xfer_length,
				    pkt->pkt_resid);
				aac_set_pkt_reason(softs, acp, CMD_PER_FAIL, 0);
				break;
			case SRB_STATUS_NO_DEVICE:
			case SRB_STATUS_INVALID_PATH_ID:
			case SRB_STATUS_INVALID_TARGET_ID:
			case SRB_STATUS_INVALID_LUN:
			case SRB_STATUS_SELECTION_TIMEOUT:
#ifdef DEBUG
				if (AAC_DEV_IS_VALID(acp->dvp)) {
					AACDB_PRINT(softs, CE_NOTE,
					    "SRB_STATUS_NO_DEVICE(%d), " \
					    "xfer=%d, resid=%d ",
					    srb_status & 0x3f,
					    data_xfer_length, pkt->pkt_resid);
				}
#endif
				aac_set_pkt_reason(softs, acp, CMD_DEV_GONE, 0);
				break;
			case SRB_STATUS_COMMAND_TIMEOUT:
			case SRB_STATUS_TIMEOUT:
				AACDB_PRINT(softs, CE_NOTE,
				    "SRB_STATUS_COMMAND_TIMEOUT, xfer=%d, " \
				    "resid=%d", data_xfer_length,
				    pkt->pkt_resid);
				aac_set_pkt_reason(softs, acp, CMD_TIMEOUT,
				    STAT_TIMEOUT);
				break;
			case SRB_STATUS_BUS_RESET:
				AACDB_PRINT(softs, CE_NOTE,
				    "SRB_STATUS_BUS_RESET, xfer=%d, " \
				    "resid=%d", data_xfer_length,
				    pkt->pkt_resid);
				aac_set_pkt_reason(softs, acp, CMD_RESET,
				    STAT_BUS_RESET);
				break;
			default:
				AACDB_PRINT(softs, CE_NOTE, "srb_status=%d, " \
				    "xfer=%d, resid=%d", srb_status & 0x3f,
				    data_xfer_length, pkt->pkt_resid);
				aac_set_pkt_reason(softs, acp, CMD_TRAN_ERR, 0);
				break;
			}
		} else if (scsi_status == STATUS_CHECK) {
			/* CHECK CONDITION */
			struct scsi_arq_status *arqstat =
			    (void *)(pkt->pkt_scbp);
			uint32_t sense_data_size;

			pkt->pkt_state |= STATE_ARQ_DONE;

			*(uint8_t *)&arqstat->sts_rqpkt_status = STATUS_GOOD;
			arqstat->sts_rqpkt_reason = CMD_CMPLT;
			arqstat->sts_rqpkt_resid = 0;
			arqstat->sts_rqpkt_state =
			    STATE_GOT_BUS |
			    STATE_GOT_TARGET |
			    STATE_SENT_CMD |
			    STATE_XFERRED_DATA;
			arqstat->sts_rqpkt_statistics = 0;

			sense_data_size = ddi_get32(acc,
			    &resp->sense_data_size);
			ASSERT(sense_data_size <= AAC_SENSE_BUFFERSIZE);
			AACDB_PRINT(softs, CE_NOTE,
			    "CHECK CONDITION: sense len=%d, xfer len=%d",
			    sense_data_size, data_xfer_length);

			if (sense_data_size > SENSE_LENGTH)
				sense_data_size = SENSE_LENGTH;
			ddi_rep_get8(acc, (uint8_t *)&arqstat->sts_sensedata,
			    (uint8_t *)resp->sense_data, sense_data_size,
			    DDI_DEV_AUTOINCR);
		} else {
			AACDB_PRINT(softs, CE_WARN, "invaild scsi status: " \
			    "scsi_status=%d, srb_status=%d",
			    scsi_status, srb_status);
			aac_set_pkt_reason(softs, acp, CMD_TRAN_ERR, 0);
		}
	} else {
		AACDB_PRINT(softs, CE_NOTE, "SRB failed: fib status %d",
		    resp_status);
		aac_set_pkt_reason(softs, acp, CMD_TRAN_ERR, 0);
	}
}

/*
 * Handle completed IOCTL command
 */
/*ARGSUSED*/
void
aac_ioctl_complete(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp = acp->slotp;

	/*
	 * NOTE: Both aac_ioctl_send_fib() and aac_send_raw_srb()
	 * may wait on softs->event, so use cv_broadcast() instead
	 * of cv_signal().
	 */
	ASSERT(acp->flags & AAC_CMD_SYNC);
	ASSERT(acp->flags & AAC_CMD_NO_CB);

	/* Get the size of the response FIB from its FIB.Header.Size field */
	acp->fib_size = ddi_get16(slotp->fib_acc_handle,
	    &slotp->fibp->Header.Size);

	ASSERT(acp->fib_size <= softs->aac_max_fib_size);
	ddi_rep_get8(slotp->fib_acc_handle, (uint8_t *)acp->fibp,
	    (uint8_t *)slotp->fibp, acp->fib_size, DDI_DEV_AUTOINCR);
}

/*
 * Handle completed sync fib command
 */
/*ARGSUSED*/
void
aac_sync_complete(struct aac_softstate *softs, struct aac_cmd *acp)
{
}

/*
 * Handle completed Flush command
 */
/*ARGSUSED*/
static void
aac_synccache_complete(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp = acp->slotp;
	ddi_acc_handle_t acc = slotp->fib_acc_handle;
	struct aac_synchronize_reply *resp;
	uint32_t status;

	ASSERT(!(acp->flags & AAC_CMD_SYNC));

	acp->pkt->pkt_state |= STATE_GOT_STATUS;

	resp = (struct aac_synchronize_reply *)&slotp->fibp->data[0];
	status = ddi_get32(acc, &resp->Status);
	if (status != CT_OK)
		aac_set_arq_data_hwerr(acp);
}

/*ARGSUSED*/
static void
aac_startstop_complete(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp = acp->slotp;
	ddi_acc_handle_t acc = slotp->fib_acc_handle;
	struct aac_Container_resp *resp;
	uint32_t status;

	ASSERT(!(acp->flags & AAC_CMD_SYNC));

	acp->pkt->pkt_state |= STATE_GOT_STATUS;

	resp = (struct aac_Container_resp *)&slotp->fibp->data[0];
	status = ddi_get32(acc, &resp->Status);
	if (status != 0) {
		AACDB_PRINT(softs, CE_WARN, "Cannot start/stop a unit");
		aac_set_arq_data_hwerr(acp);
	}
}

/*
 * Access PCI space to see if the driver can support the card
 */
static int
aac_check_card_type(struct aac_softstate *softs)
{
	ddi_acc_handle_t pci_config_handle;
	int card_index;
	uint32_t pci_cmd;

	/* Map pci configuration space */
	if ((pci_config_setup(softs->devinfo_p, &pci_config_handle)) !=
	    DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN, "Cannot setup pci config space");
		return (AACERR);
	}

	softs->vendid = pci_config_get16(pci_config_handle, PCI_CONF_VENID);
	softs->devid = pci_config_get16(pci_config_handle, PCI_CONF_DEVID);
	softs->subvendid = pci_config_get16(pci_config_handle,
	    PCI_CONF_SUBVENID);
	softs->subsysid = pci_config_get16(pci_config_handle,
	    PCI_CONF_SUBSYSID);

	card_index = 0;
	while (!CARD_IS_UNKNOWN(card_index)) {
		if ((aac_cards[card_index].vendor == softs->vendid) &&
		    (aac_cards[card_index].device == softs->devid) &&
		    (aac_cards[card_index].subvendor == softs->subvendid) &&
		    (aac_cards[card_index].subsys == softs->subsysid)) {
			break;
		}
		card_index++;
	}

	softs->card = card_index;
	softs->hwif = aac_cards[card_index].hwif;

	/*
	 * Unknown aac card
	 * do a generic match based on the VendorID and DeviceID to
	 * support the new cards in the aac family
	 */
	if (CARD_IS_UNKNOWN(card_index)) {
		if (softs->vendid != 0x9005) {
			AACDB_PRINT(softs, CE_WARN,
			    "Unknown vendor 0x%x", softs->vendid);
			goto error;
		}
		switch (softs->devid) {
		case 0x285:
			softs->hwif = AAC_HWIF_I960RX;
			break;
		case 0x286:
			softs->hwif = AAC_HWIF_RKT;
			break;
		default:
			AACDB_PRINT(softs, CE_WARN,
			    "Unknown device \"pci9005,%x\"", softs->devid);
			goto error;
		}
	}

	/* Set hardware dependent interface */
	switch (softs->hwif) {
	case AAC_HWIF_I960RX:
		softs->aac_if = aac_rx_interface;
		softs->map_size_min = AAC_MAP_SIZE_MIN_RX;
		break;
	case AAC_HWIF_RKT:
		softs->aac_if = aac_rkt_interface;
		softs->map_size_min = AAC_MAP_SIZE_MIN_RKT;
		break;
	default:
		AACDB_PRINT(softs, CE_WARN,
		    "Unknown hardware interface %d", softs->hwif);
		goto error;
	}

	/* Set card names */
	(void *)strncpy(softs->vendor_name, aac_cards[card_index].vid,
	    AAC_VENDOR_LEN);
	(void *)strncpy(softs->product_name, aac_cards[card_index].desc,
	    AAC_PRODUCT_LEN);

	/* Set up quirks */
	softs->flags = aac_cards[card_index].quirks;

	/* Force the busmaster enable bit on */
	pci_cmd = pci_config_get16(pci_config_handle, PCI_CONF_COMM);
	if ((pci_cmd & PCI_COMM_ME) == 0) {
		pci_cmd |= PCI_COMM_ME;
		pci_config_put16(pci_config_handle, PCI_CONF_COMM, pci_cmd);
		pci_cmd = pci_config_get16(pci_config_handle, PCI_CONF_COMM);
		if ((pci_cmd & PCI_COMM_ME) == 0) {
			cmn_err(CE_CONT, "?Cannot enable busmaster bit");
			goto error;
		}
	}

	/* Set memory base to map */
	softs->pci_mem_base_paddr = 0xfffffff0UL & \
	    pci_config_get32(pci_config_handle, PCI_CONF_BASE0);

	pci_config_teardown(&pci_config_handle);

	return (AACOK); /* card type detected */
error:
	pci_config_teardown(&pci_config_handle);
	return (AACERR); /* no matched card found */
}

/*
 * Do the usual interrupt handler setup stuff.
 */
static int
aac_register_intrs(struct aac_softstate *softs)
{
	dev_info_t *dip;
	int intr_types;

	ASSERT(softs->devinfo_p);
	dip = softs->devinfo_p;

	/* Get the type of device intrrupts */
	if (ddi_intr_get_supported_types(dip, &intr_types) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "ddi_intr_get_supported_types() failed");
		return (AACERR);
	}
	AACDB_PRINT(softs, CE_NOTE,
	    "ddi_intr_get_supported_types() ret: 0x%x", intr_types);

	/* Query interrupt, and alloc/init all needed struct */
	if (intr_types & DDI_INTR_TYPE_MSI) {
		if (aac_query_intrs(softs, DDI_INTR_TYPE_MSI)
		    != DDI_SUCCESS) {
			AACDB_PRINT(softs, CE_WARN,
			    "MSI interrupt query failed");
			return (AACERR);
		}
		softs->intr_type = DDI_INTR_TYPE_MSI;
	} else if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (aac_query_intrs(softs, DDI_INTR_TYPE_FIXED)
		    != DDI_SUCCESS) {
			AACDB_PRINT(softs, CE_WARN,
			    "FIXED interrupt query failed");
			return (AACERR);
		}
		softs->intr_type = DDI_INTR_TYPE_FIXED;
	} else {
		AACDB_PRINT(softs, CE_WARN,
		    "Device cannot suppport both FIXED and MSI interrupts");
		return (AACERR);
	}

	/* Connect interrupt handlers */
	if (aac_add_intrs(softs) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Interrupt registration failed, intr type: %s",
		    softs->intr_type == DDI_INTR_TYPE_MSI ? "MSI" : "FIXED");
		return (AACERR);
	}
	(void) aac_enable_intrs(softs);

	if (ddi_add_softintr(dip, DDI_SOFTINT_LOW, &softs->softint_id,
	    NULL, NULL, aac_softintr, (caddr_t)softs) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Can not setup soft interrupt handler!");
		aac_remove_intrs(softs);
		return (AACERR);
	}

	return (AACOK);
}

static void
aac_unregister_intrs(struct aac_softstate *softs)
{
	aac_remove_intrs(softs);
	ddi_remove_softintr(softs->softint_id);
}

/*
 * Check the firmware to determine the features to support and the FIB
 * parameters to use.
 */
static int
aac_check_firmware(struct aac_softstate *softs)
{
	uint32_t options;
	uint32_t atu_size;
	ddi_acc_handle_t pci_handle;
	uint8_t *data;
	uint32_t max_fibs;
	uint32_t max_fib_size;
	uint32_t sg_tablesize;
	uint32_t max_sectors;
	uint32_t status;

	/* Get supported options */
	if ((aac_sync_mbcommand(softs, AAC_MONKER_GETINFO, 0, 0, 0, 0,
	    &status)) != AACOK) {
		if (status != SRB_STATUS_INVALID_REQUEST) {
			cmn_err(CE_CONT,
			    "?Fatal error: request adapter info error");
			return (AACERR);
		}
		options = 0;
		atu_size = 0;
	} else {
		options = AAC_MAILBOX_GET(softs, 1);
		atu_size = AAC_MAILBOX_GET(softs, 2);
	}

	if (softs->state & AAC_STATE_RESET) {
		if ((softs->support_opt == options) &&
		    (softs->atu_size == atu_size))
			return (AACOK);

		cmn_err(CE_WARN,
		    "?Fatal error: firmware changed, system needs reboot");
		return (AACERR);
	}

	/*
	 * The following critical settings are initialized only once during
	 * driver attachment.
	 */
	softs->support_opt = options;
	softs->atu_size = atu_size;

	/* Process supported options */
	if ((options & AAC_SUPPORTED_4GB_WINDOW) != 0 &&
	    (softs->flags & AAC_FLAGS_NO4GB) == 0) {
		AACDB_PRINT(softs, CE_NOTE, "!Enable FIB map 4GB window");
		softs->flags |= AAC_FLAGS_4GB_WINDOW;
	} else {
		/*
		 * Quirk AAC_FLAGS_NO4GB is for FIB address and thus comm space
		 * only. IO is handled by the DMA engine which does not suffer
		 * from the ATU window programming workarounds necessary for
		 * CPU copy operations.
		 */
		softs->addr_dma_attr.dma_attr_addr_lo = 0x2000ull;
		softs->addr_dma_attr.dma_attr_addr_hi = 0x7fffffffull;
	}

	if ((options & AAC_SUPPORTED_SGMAP_HOST64) != 0) {
		AACDB_PRINT(softs, CE_NOTE, "!Enable SG map 64-bit address");
		softs->buf_dma_attr.dma_attr_addr_hi = 0xffffffffffffffffull;
		softs->buf_dma_attr.dma_attr_seg = 0xffffffffffffffffull;
		softs->flags |= AAC_FLAGS_SG_64BIT;
	}

	if (options & AAC_SUPPORTED_64BIT_ARRAYSIZE) {
		softs->flags |= AAC_FLAGS_ARRAY_64BIT;
		AACDB_PRINT(softs, CE_NOTE, "!Enable 64-bit array size");
	}

	if (options & AAC_SUPPORTED_NONDASD) {
		if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, softs->devinfo_p, 0,
		    "nondasd-enable", (char **)&data) == DDI_SUCCESS)) {
			if (strcmp((char *)data, "yes") == 0) {
				AACDB_PRINT(softs, CE_NOTE,
				    "!Enable Non-DASD access");
				softs->flags |= AAC_FLAGS_NONDASD;
			}
			ddi_prop_free(data);
		}
	}

	/* Read preferred settings */
	max_fib_size = 0;
	if ((aac_sync_mbcommand(softs, AAC_MONKER_GETCOMMPREF,
	    0, 0, 0, 0, NULL)) == AACOK) {
		options = AAC_MAILBOX_GET(softs, 1);
		max_fib_size = (options & 0xffff);
		max_sectors = (options >> 16) << 1;
		options = AAC_MAILBOX_GET(softs, 2);
		sg_tablesize = (options >> 16);
		options = AAC_MAILBOX_GET(softs, 3);
		max_fibs = (options & 0xffff);
	}

	/* Enable new comm. and rawio at the same time */
	if ((softs->support_opt & AAC_SUPPORTED_NEW_COMM) &&
	    (max_fib_size != 0)) {
		/* read out and save PCI MBR */
		if ((atu_size > softs->map_size) &&
		    (ddi_regs_map_setup(softs->devinfo_p, 1,
		    (caddr_t *)&data, 0, atu_size, &softs->reg_attr,
		    &pci_handle) == DDI_SUCCESS)) {
			ddi_regs_map_free(&softs->pci_mem_handle);
			softs->pci_mem_handle = pci_handle;
			softs->pci_mem_base_vaddr = data;
			softs->map_size = atu_size;
		}
		if (atu_size == softs->map_size) {
			softs->flags |= AAC_FLAGS_NEW_COMM;
			AACDB_PRINT(softs, CE_NOTE,
			    "!Enable New Comm. interface");
		}
	}

	/* Set FIB parameters */
	if (softs->flags & AAC_FLAGS_NEW_COMM) {
		softs->aac_max_fibs = max_fibs;
		softs->aac_max_fib_size = max_fib_size;
		softs->aac_max_sectors = max_sectors;
		softs->aac_sg_tablesize = sg_tablesize;

		softs->flags |= AAC_FLAGS_RAW_IO;
		AACDB_PRINT(softs, CE_NOTE, "!Enable RawIO");
	} else {
		softs->aac_max_fibs =
		    (softs->flags & AAC_FLAGS_256FIBS) ? 256 : 512;
		softs->aac_max_fib_size = AAC_FIB_SIZE;
		softs->aac_max_sectors = 128;	/* 64K */
		if (softs->flags & AAC_FLAGS_17SG)
			softs->aac_sg_tablesize = 17;
		else if (softs->flags & AAC_FLAGS_34SG)
			softs->aac_sg_tablesize = 34;
		else if (softs->flags & AAC_FLAGS_SG_64BIT)
			softs->aac_sg_tablesize = (AAC_FIB_DATASIZE -
			    sizeof (struct aac_blockwrite64) +
			    sizeof (struct aac_sg_entry64)) /
			    sizeof (struct aac_sg_entry64);
		else
			softs->aac_sg_tablesize = (AAC_FIB_DATASIZE -
			    sizeof (struct aac_blockwrite) +
			    sizeof (struct aac_sg_entry)) /
			    sizeof (struct aac_sg_entry);
	}

	if ((softs->flags & AAC_FLAGS_RAW_IO) &&
	    (softs->flags & AAC_FLAGS_ARRAY_64BIT)) {
		softs->flags |= AAC_FLAGS_LBA_64BIT;
		AACDB_PRINT(softs, CE_NOTE, "!Enable 64-bit array");
	}
	softs->buf_dma_attr.dma_attr_sgllen = softs->aac_sg_tablesize;
	softs->buf_dma_attr.dma_attr_maxxfer = softs->aac_max_sectors << 9;
	/*
	 * 64K maximum segment size in scatter gather list is controlled by
	 * the NEW_COMM bit in the adapter information. If not set, the card
	 * can only accept a maximum of 64K. It is not recommended to permit
	 * more than 128KB of total transfer size to the adapters because
	 * performance is negatively impacted.
	 *
	 * For new comm, segment size equals max xfer size. For old comm,
	 * we use 64K for both.
	 */
	softs->buf_dma_attr.dma_attr_count_max =
	    softs->buf_dma_attr.dma_attr_maxxfer - 1;

	/* Setup FIB operations */
	if (softs->flags & AAC_FLAGS_RAW_IO)
		softs->aac_cmd_fib = aac_cmd_fib_rawio;
	else if (softs->flags & AAC_FLAGS_SG_64BIT)
		softs->aac_cmd_fib = aac_cmd_fib_brw64;
	else
		softs->aac_cmd_fib = aac_cmd_fib_brw;
	softs->aac_cmd_fib_scsi = (softs->flags & AAC_FLAGS_SG_64BIT) ? \
	    aac_cmd_fib_scsi64 : aac_cmd_fib_scsi32;

	/* 64-bit LBA needs descriptor format sense data */
	softs->slen = sizeof (struct scsi_arq_status);
	if ((softs->flags & AAC_FLAGS_LBA_64BIT) &&
	    softs->slen < AAC_ARQ64_LENGTH)
		softs->slen = AAC_ARQ64_LENGTH;

	AACDB_PRINT(softs, CE_NOTE,
	    "!max_fibs %d max_fibsize 0x%x max_sectors %d max_sg %d",
	    softs->aac_max_fibs, softs->aac_max_fib_size,
	    softs->aac_max_sectors, softs->aac_sg_tablesize);

	return (AACOK);
}

static void
aac_fsa_rev(struct aac_softstate *softs, struct FsaRev *fsarev0,
    struct FsaRev *fsarev1)
{
	ddi_acc_handle_t acc = softs->sync_ac.slotp->fib_acc_handle;

	AAC_GET_FIELD8(acc, fsarev1, fsarev0, external.comp.dash);
	AAC_GET_FIELD8(acc, fsarev1, fsarev0, external.comp.type);
	AAC_GET_FIELD8(acc, fsarev1, fsarev0, external.comp.minor);
	AAC_GET_FIELD8(acc, fsarev1, fsarev0, external.comp.major);
	AAC_GET_FIELD32(acc, fsarev1, fsarev0, buildNumber);
}

/*
 * The following function comes from Adaptec:
 *
 * Query adapter information and supplement adapter information
 */
static int
aac_get_adapter_info(struct aac_softstate *softs,
    struct aac_adapter_info *ainfr, struct aac_supplement_adapter_info *sinfr)
{
	struct aac_cmd *acp = &softs->sync_ac;
	ddi_acc_handle_t acc;
	struct aac_fib *fibp;
	struct aac_adapter_info *ainfp;
	struct aac_supplement_adapter_info *sinfp;
	int rval;

	(void) aac_sync_fib_slot_bind(softs, acp);
	acc = acp->slotp->fib_acc_handle;
	fibp = acp->slotp->fibp;

	ddi_put8(acc, &fibp->data[0], 0);
	if (aac_sync_fib(softs, RequestAdapterInfo,
	    AAC_FIB_SIZEOF(struct aac_adapter_info)) != AACOK) {
		AACDB_PRINT(softs, CE_WARN, "RequestAdapterInfo failed");
		rval = AACERR;
		goto finish;
	}
	ainfp = (struct aac_adapter_info *)fibp->data;
	if (ainfr) {
		AAC_GET_FIELD32(acc, ainfr, ainfp, SupportedOptions);
		AAC_GET_FIELD32(acc, ainfr, ainfp, PlatformBase);
		AAC_GET_FIELD32(acc, ainfr, ainfp, CpuArchitecture);
		AAC_GET_FIELD32(acc, ainfr, ainfp, CpuVariant);
		AAC_GET_FIELD32(acc, ainfr, ainfp, ClockSpeed);
		AAC_GET_FIELD32(acc, ainfr, ainfp, ExecutionMem);
		AAC_GET_FIELD32(acc, ainfr, ainfp, BufferMem);
		AAC_GET_FIELD32(acc, ainfr, ainfp, TotalMem);
		aac_fsa_rev(softs, &ainfp->KernelRevision,
		    &ainfr->KernelRevision);
		aac_fsa_rev(softs, &ainfp->MonitorRevision,
		    &ainfr->MonitorRevision);
		aac_fsa_rev(softs, &ainfp->HardwareRevision,
		    &ainfr->HardwareRevision);
		aac_fsa_rev(softs, &ainfp->BIOSRevision,
		    &ainfr->BIOSRevision);
		AAC_GET_FIELD32(acc, ainfr, ainfp, ClusteringEnabled);
		AAC_GET_FIELD32(acc, ainfr, ainfp, ClusterChannelMask);
		AAC_GET_FIELD64(acc, ainfr, ainfp, SerialNumber);
		AAC_GET_FIELD32(acc, ainfr, ainfp, batteryPlatform);
		AAC_GET_FIELD32(acc, ainfr, ainfp, SupportedOptions);
		AAC_GET_FIELD32(acc, ainfr, ainfp, OemVariant);
	}
	if (sinfr) {
		if (!(softs->support_opt &
		    AAC_SUPPORTED_SUPPLEMENT_ADAPTER_INFO)) {
			AACDB_PRINT(softs, CE_WARN,
			    "SupplementAdapterInfo not supported");
			rval = AACERR;
			goto finish;
		}
		ddi_put8(acc, &fibp->data[0], 0);
		if (aac_sync_fib(softs, RequestSupplementAdapterInfo,
		    AAC_FIB_SIZEOF(struct aac_supplement_adapter_info))
		    != AACOK) {
			AACDB_PRINT(softs, CE_WARN,
			    "RequestSupplementAdapterInfo failed");
			rval = AACERR;
			goto finish;
		}
		sinfp = (struct aac_supplement_adapter_info *)fibp->data;
		AAC_REP_GET_FIELD8(acc, sinfr, sinfp, AdapterTypeText[0], 17+1);
		AAC_REP_GET_FIELD8(acc, sinfr, sinfp, Pad[0], 2);
		AAC_GET_FIELD32(acc, sinfr, sinfp, FlashMemoryByteSize);
		AAC_GET_FIELD32(acc, sinfr, sinfp, FlashImageId);
		AAC_GET_FIELD32(acc, sinfr, sinfp, MaxNumberPorts);
		AAC_GET_FIELD32(acc, sinfr, sinfp, Version);
		AAC_GET_FIELD32(acc, sinfr, sinfp, FeatureBits);
		AAC_GET_FIELD8(acc, sinfr, sinfp, SlotNumber);
		AAC_REP_GET_FIELD8(acc, sinfr, sinfp, ReservedPad0[0], 3);
		AAC_REP_GET_FIELD8(acc, sinfr, sinfp, BuildDate[0], 12);
		AAC_GET_FIELD32(acc, sinfr, sinfp, CurrentNumberPorts);
		AAC_REP_GET_FIELD8(acc, sinfr, sinfp, VpdInfo,
		    sizeof (struct vpd_info));
		aac_fsa_rev(softs, &sinfp->FlashFirmwareRevision,
		    &sinfr->FlashFirmwareRevision);
		AAC_GET_FIELD32(acc, sinfr, sinfp, RaidTypeMorphOptions);
		aac_fsa_rev(softs, &sinfp->FlashFirmwareBootRevision,
		    &sinfr->FlashFirmwareBootRevision);
		AAC_REP_GET_FIELD8(acc, sinfr, sinfp, MfgPcbaSerialNo,
		    MFG_PCBA_SERIAL_NUMBER_WIDTH);
		AAC_REP_GET_FIELD8(acc, sinfr, sinfp, MfgWWNName[0],
		    MFG_WWN_WIDTH);
		AAC_GET_FIELD32(acc, sinfr, sinfp, SupportedOptions2);
		AAC_GET_FIELD32(acc, sinfr, sinfp, ExpansionFlag);
		if (sinfr->ExpansionFlag == 1) {
			AAC_GET_FIELD32(acc, sinfr, sinfp, FeatureBits3);
			AAC_GET_FIELD32(acc, sinfr, sinfp,
			    SupportedPerformanceMode);
			AAC_REP_GET_FIELD32(acc, sinfr, sinfp,
			    ReservedGrowth[0], 80);
		}
	}
	rval = AACOK;
finish:
	aac_sync_fib_slot_release(softs, acp);
	return (rval);
}

static int
aac_get_bus_info(struct aac_softstate *softs, uint32_t *bus_max,
    uint32_t *tgt_max)
{
	struct aac_cmd *acp = &softs->sync_ac;
	ddi_acc_handle_t acc;
	struct aac_fib *fibp;
	struct aac_ctcfg *c_cmd;
	struct aac_ctcfg_resp *c_resp;
	uint32_t scsi_method_id;
	struct aac_bus_info *cmd;
	struct aac_bus_info_response *resp;
	int rval;

	(void) aac_sync_fib_slot_bind(softs, acp);
	acc = acp->slotp->fib_acc_handle;
	fibp = acp->slotp->fibp;

	/* Detect MethodId */
	c_cmd = (struct aac_ctcfg *)&fibp->data[0];
	ddi_put32(acc, &c_cmd->Command, VM_ContainerConfig);
	ddi_put32(acc, &c_cmd->cmd, CT_GET_SCSI_METHOD);
	ddi_put32(acc, &c_cmd->param, 0);
	rval = aac_sync_fib(softs, ContainerCommand,
	    AAC_FIB_SIZEOF(struct aac_ctcfg));
	c_resp = (struct aac_ctcfg_resp *)&fibp->data[0];
	if (rval != AACOK || ddi_get32(acc, &c_resp->Status) != 0) {
		AACDB_PRINT(softs, CE_WARN,
		    "VM_ContainerConfig command fail");
		rval = AACERR;
		goto finish;
	}
	scsi_method_id = ddi_get32(acc, &c_resp->param);

	/* Detect phys. bus count and max. target id first */
	cmd = (struct aac_bus_info *)&fibp->data[0];
	ddi_put32(acc, &cmd->Command, VM_Ioctl);
	ddi_put32(acc, &cmd->ObjType, FT_DRIVE); /* physical drive */
	ddi_put32(acc, &cmd->MethodId, scsi_method_id);
	ddi_put32(acc, &cmd->ObjectId, 0);
	ddi_put32(acc, &cmd->CtlCmd, GetBusInfo);
	/*
	 * For VM_Ioctl, the firmware uses the Header.Size filled from the
	 * driver as the size to be returned. Therefore the driver has to use
	 * sizeof (struct aac_bus_info_response) because it is greater than
	 * sizeof (struct aac_bus_info).
	 */
	rval = aac_sync_fib(softs, ContainerCommand,
	    AAC_FIB_SIZEOF(struct aac_bus_info_response));
	resp = (struct aac_bus_info_response *)cmd;

	/* Scan all coordinates with INQUIRY */
	if ((rval != AACOK) || (ddi_get32(acc, &resp->Status) != 0)) {
		AACDB_PRINT(softs, CE_WARN, "GetBusInfo command fail");
		rval = AACERR;
		goto finish;
	}
	*bus_max = ddi_get32(acc, &resp->BusCount);
	*tgt_max = ddi_get32(acc, &resp->TargetsPerBus);

finish:
	aac_sync_fib_slot_release(softs, acp);
	return (AACOK);
}

/*
 * The following function comes from Adaptec:
 *
 * Routine to be called during initialization of communications with
 * the adapter to handle possible adapter configuration issues. When
 * the adapter first boots up, it examines attached drives, etc, and
 * potentially comes up with a new or revised configuration (relative to
 * what's stored in it's NVRAM). Additionally it may discover problems
 * that make the current physical configuration unworkable (currently
 * applicable only to cluster configuration issues).
 *
 * If there are no configuration issues or the issues are considered
 * trival by the adapter, it will set it's configuration status to
 * "FSACT_CONTINUE" and execute the "commit confiuguration" action
 * automatically on it's own.
 *
 * However, if there are non-trivial issues, the adapter will set it's
 * internal configuration status to "FSACT_PAUSE" or "FASCT_ABORT"
 * and wait for some agent on the host to issue the "\ContainerCommand
 * \VM_ContainerConfig\CT_COMMIT_CONFIG" FIB command to cause the
 * adapter to commit the new/updated configuration and enable
 * un-inhibited operation.  The host agent should first issue the
 * "\ContainerCommand\VM_ContainerConfig\CT_GET_CONFIG_STATUS" FIB
 * command to obtain information about config issues detected by
 * the adapter.
 *
 * Normally the adapter's PC BIOS will execute on the host following
 * adapter poweron and reset and will be responsible for querring the
 * adapter with CT_GET_CONFIG_STATUS and issuing the CT_COMMIT_CONFIG
 * command if appropriate.
 *
 * However, with the introduction of IOP reset support, the adapter may
 * boot up without the benefit of the adapter's PC BIOS host agent.
 * This routine is intended to take care of these issues in situations
 * where BIOS doesn't execute following adapter poweron or reset.  The
 * CT_COMMIT_CONFIG command is a no-op if it's already been issued, so
 * there is no harm in doing this when it's already been done.
 */
static int
aac_handle_adapter_config_issues(struct aac_softstate *softs)
{
	struct aac_cmd *acp = &softs->sync_ac;
	ddi_acc_handle_t acc;
	struct aac_fib *fibp;
	struct aac_Container *cmd;
	struct aac_Container_resp *resp;
	struct aac_cf_status_header *cfg_sts_hdr;
	uint32_t resp_status;
	uint32_t ct_status;
	uint32_t cfg_stat_action;
	int rval;

	(void) aac_sync_fib_slot_bind(softs, acp);
	acc = acp->slotp->fib_acc_handle;
	fibp = acp->slotp->fibp;

	/* Get adapter config status */
	cmd = (struct aac_Container *)&fibp->data[0];

	bzero(cmd, sizeof (*cmd) - CT_PACKET_SIZE);
	ddi_put32(acc, &cmd->Command, VM_ContainerConfig);
	ddi_put32(acc, &cmd->CTCommand.command, CT_GET_CONFIG_STATUS);
	ddi_put32(acc, &cmd->CTCommand.param[CNT_SIZE],
	    sizeof (struct aac_cf_status_header));
	rval = aac_sync_fib(softs, ContainerCommand,
	    AAC_FIB_SIZEOF(struct aac_Container));
	resp = (struct aac_Container_resp *)cmd;
	cfg_sts_hdr = (struct aac_cf_status_header *)resp->CTResponse.data;

	resp_status = ddi_get32(acc, &resp->Status);
	ct_status = ddi_get32(acc, &resp->CTResponse.param[0]);
	if ((rval == AACOK) && (resp_status == 0) && (ct_status == CT_OK)) {
		cfg_stat_action = ddi_get32(acc, &cfg_sts_hdr->action);

		/* Commit configuration if it's reasonable to do so. */
		if (cfg_stat_action <= CFACT_PAUSE) {
			bzero(cmd, sizeof (*cmd) - CT_PACKET_SIZE);
			ddi_put32(acc, &cmd->Command, VM_ContainerConfig);
			ddi_put32(acc, &cmd->CTCommand.command,
			    CT_COMMIT_CONFIG);
			rval = aac_sync_fib(softs, ContainerCommand,
			    AAC_FIB_SIZEOF(struct aac_Container));

			resp_status = ddi_get32(acc, &resp->Status);
			ct_status = ddi_get32(acc, &resp->CTResponse.param[0]);
			if ((rval == AACOK) && (resp_status == 0) &&
			    (ct_status == CT_OK))
				/* Successful completion */
				rval = AACMPE_OK;
			else
				/* Auto-commit aborted due to error(s). */
				rval = AACMPE_COMMIT_CONFIG;
		} else {
			/*
			 * Auto-commit aborted due to adapter indicating
			 * configuration issue(s) too dangerous to auto-commit.
			 */
			rval = AACMPE_CONFIG_STATUS;
		}
	} else {
		cmn_err(CE_WARN, "!Configuration issue, auto-commit aborted");
		rval = AACMPE_CONFIG_STATUS;
	}

	aac_sync_fib_slot_release(softs, acp);
	return (rval);
}

/*
 * Hardware initialization and resource allocation
 */
static int
aac_common_attach(struct aac_softstate *softs)
{
	uint32_t status;
	int i;
	struct aac_supplement_adapter_info sinf;

	DBCALLED(softs, 1);

	/*
	 * Do a little check here to make sure there aren't any outstanding
	 * FIBs in the message queue. At this point there should not be and
	 * if there are they are probably left over from another instance of
	 * the driver like when the system crashes and the crash dump driver
	 * gets loaded.
	 */
	while (AAC_OUTB_GET(softs) != 0xfffffffful)
		;

	/*
	 * Wait the card to complete booting up before do anything that
	 * attempts to communicate with it.
	 */
	status = AAC_FWSTATUS_GET(softs);
	if (status == AAC_SELF_TEST_FAILED || status == AAC_KERNEL_PANIC)
		goto error;
	i = AAC_FWUP_TIMEOUT * 1000; /* set timeout */
	AAC_BUSYWAIT(AAC_FWSTATUS_GET(softs) & AAC_KERNEL_UP_AND_RUNNING, i);
	if (i == 0) {
		cmn_err(CE_CONT, "?Fatal error: controller not ready");
		aac_fm_ereport(softs, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	/* Read and set card supported options and settings */
	if (aac_check_firmware(softs) == AACERR) {
		aac_fm_ereport(softs, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	/* Add interrupt handlers */
	if (aac_register_intrs(softs) == AACERR) {
		cmn_err(CE_CONT,
		    "?Fatal error: interrupts register failed");
		goto error;
	}

	/* Setup communication space with the card */
	if (softs->comm_space_dma_handle == NULL) {
		if (aac_alloc_comm_space(softs) != AACOK)
			goto error;
	}
	if (aac_setup_comm_space(softs) != AACOK) {
		cmn_err(CE_CONT, "?Setup communication space failed");
		aac_fm_ereport(softs, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

#ifdef DEBUG
	if (aac_get_fw_debug_buffer(softs) != AACOK)
		cmn_err(CE_CONT, "?firmware UART trace not supported");
#endif

	/* Allocate slots */
	if ((softs->total_slots == 0) && (aac_create_slots(softs) != AACOK)) {
		cmn_err(CE_CONT, "?Fatal error: slots allocate failed");
		goto error;
	}
	AACDB_PRINT(softs, CE_NOTE, "%d slots allocated", softs->total_slots);

	/* Allocate FIBs */
	if (softs->total_fibs < softs->total_slots) {
		aac_alloc_fibs(softs);
		if (softs->total_fibs == 0)
			goto error;
		AACDB_PRINT(softs, CE_NOTE, "%d fibs allocated",
		    softs->total_fibs);
	}

	AAC_STATUS_CLR(softs, ~0); /* Clear out all interrupts */
	AAC_ENABLE_INTR(softs); /* Enable the interrupts we can handle */

	if (aac_get_adapter_info(softs, NULL, &sinf) == AACOK) {
		softs->feature_bits = sinf.FeatureBits;
		softs->support_opt2 = sinf.SupportedOptions2;

		/* Get adapter names */
		if (CARD_IS_UNKNOWN(softs->card)) {
			char *p, *p0, *p1;

			/*
			 * Now find the controller name in supp_adapter_info->
			 * AdapterTypeText. Use the first word as the vendor
			 * and the other words as the product name.
			 */
			AACDB_PRINT(softs, CE_NOTE, "sinf.AdapterTypeText = "
			    "\"%s\"", sinf.AdapterTypeText);
			p = sinf.AdapterTypeText;
			p0 = p1 = NULL;
			/* Skip heading spaces */
			while (*p && (*p == ' ' || *p == '\t'))
				p++;
			p0 = p;
			while (*p && (*p != ' ' && *p != '\t'))
				p++;
			/* Remove middle spaces */
			while (*p && (*p == ' ' || *p == '\t'))
				*p++ = 0;
			p1 = p;
			/* Remove trailing spaces */
			p = p1 + strlen(p1) - 1;
			while (p > p1 && (*p == ' ' || *p == '\t'))
				*p-- = 0;
			if (*p0 && *p1) {
				(void *)strncpy(softs->vendor_name, p0,
				    AAC_VENDOR_LEN);
				(void *)strncpy(softs->product_name, p1,
				    AAC_PRODUCT_LEN);
			} else {
				cmn_err(CE_WARN,
				    "?adapter name mis-formatted\n");
				if (*p0)
					(void *)strncpy(softs->product_name,
					    p0, AAC_PRODUCT_LEN);
			}
		}
	} else {
		cmn_err(CE_CONT, "?Query adapter information failed");
	}


	cmn_err(CE_NOTE,
	    "!aac driver %d.%02d.%02d-%d, found card: " \
	    "%s %s(pci0x%x.%x.%x.%x) at 0x%x",
	    AAC_DRIVER_MAJOR_VERSION,
	    AAC_DRIVER_MINOR_VERSION,
	    AAC_DRIVER_BUGFIX_LEVEL,
	    AAC_DRIVER_BUILD,
	    softs->vendor_name, softs->product_name,
	    softs->vendid, softs->devid, softs->subvendid, softs->subsysid,
	    softs->pci_mem_base_paddr);

	/* Perform acceptance of adapter-detected config changes if possible */
	if (aac_handle_adapter_config_issues(softs) != AACMPE_OK) {
		cmn_err(CE_CONT, "?Handle adapter config issues failed");
		aac_fm_ereport(softs, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	/* Setup containers (logical devices) */
	if (aac_probe_containers(softs) != AACOK) {
		cmn_err(CE_CONT, "?Fatal error: get container info error");
		goto error;
	}

	/* Check for JBOD support. Default disable */
	char *data;
	if (softs->feature_bits & AAC_FEATURE_SUPPORTED_JBOD) {
		if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, softs->devinfo_p,
		    0, "jbod-enable", &data) == DDI_SUCCESS)) {
			if (strcmp(data, "yes") == 0) {
				AACDB_PRINT(softs, CE_NOTE,
				    "Enable JBOD access");
				softs->flags |= AAC_FLAGS_JBOD;
			}
			ddi_prop_free(data);
		}
	}

	/* Setup phys. devices */
	if (softs->flags & (AAC_FLAGS_NONDASD | AAC_FLAGS_JBOD)) {
		uint32_t bus_max, tgt_max;
		uint32_t bus, tgt;
		int index;

		if (aac_get_bus_info(softs, &bus_max, &tgt_max) != AACOK) {
			cmn_err(CE_CONT, "?Fatal error: get bus info error");
			goto error;
		}
		AACDB_PRINT(softs, CE_NOTE, "bus_max=%d, tgt_max=%d",
		    bus_max, tgt_max);
		if (bus_max != softs->bus_max || tgt_max != softs->tgt_max) {
			if (softs->state & AAC_STATE_RESET) {
				cmn_err(CE_WARN,
				    "?Fatal error: bus map changed");
				goto error;
			}
			softs->bus_max = bus_max;
			softs->tgt_max = tgt_max;
			if (softs->nondasds) {
				kmem_free(softs->nondasds, AAC_MAX_PD(softs) * \
				    sizeof (struct aac_nondasd));
			}
			softs->nondasds = kmem_zalloc(AAC_MAX_PD(softs) * \
			    sizeof (struct aac_nondasd), KM_SLEEP);

			index = 0;
			for (bus = 0; bus < softs->bus_max; bus++) {
				for (tgt = 0; tgt < softs->tgt_max; tgt++) {
					struct aac_nondasd *dvp =
					    &softs->nondasds[index++];
					dvp->dev.type = AAC_DEV_PD;
					dvp->bus = bus;
					dvp->tid = tgt;
				}
			}
		}
	}

	/* Check dma & acc handles allocated in attach */
	if (aac_check_dma_handle(softs->comm_space_dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	if (aac_check_acc_handle(softs->pci_mem_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	for (i = 0; i < softs->total_slots; i++) {
		if (aac_check_dma_handle(softs->io_slot[i].fib_dma_handle) !=
		    DDI_SUCCESS) {
			ddi_fm_service_impact(softs->devinfo_p,
			    DDI_SERVICE_LOST);
			goto error;
		}
	}

	return (AACOK);
error:
	if (softs->state & AAC_STATE_RESET)
		return (AACERR);
	if (softs->nondasds) {
		kmem_free(softs->nondasds, AAC_MAX_PD(softs) * \
		    sizeof (struct aac_nondasd));
		softs->nondasds = NULL;
	}
	if (softs->total_fibs > 0)
		aac_destroy_fibs(softs);
	if (softs->total_slots > 0)
		aac_destroy_slots(softs);
	if (softs->comm_space_dma_handle)
		aac_free_comm_space(softs);
	return (AACERR);
}

/*
 * Hardware shutdown and resource release
 */
static void
aac_common_detach(struct aac_softstate *softs)
{
	DBCALLED(softs, 1);

	aac_unregister_intrs(softs);

	mutex_enter(&softs->io_lock);
	(void) aac_shutdown(softs);

	if (softs->nondasds) {
		kmem_free(softs->nondasds, AAC_MAX_PD(softs) * \
		    sizeof (struct aac_nondasd));
		softs->nondasds = NULL;
	}
	aac_destroy_fibs(softs);
	aac_destroy_slots(softs);
	aac_free_comm_space(softs);
	mutex_exit(&softs->io_lock);
}

/*
 * Send a synchronous command to the controller and wait for a result.
 * Indicate if the controller completed the command with an error status.
 */
int
aac_sync_mbcommand(struct aac_softstate *softs, uint32_t cmd,
    uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3,
    uint32_t *statusp)
{
	int timeout;
	uint32_t status;

	if (statusp != NULL)
		*statusp = SRB_STATUS_SUCCESS;

	/* Fill in mailbox */
	AAC_MAILBOX_SET(softs, cmd, arg0, arg1, arg2, arg3);

	/* Ensure the sync command doorbell flag is cleared */
	AAC_STATUS_CLR(softs, AAC_DB_SYNC_COMMAND);

	/* Then set it to signal the adapter */
	AAC_NOTIFY(softs, AAC_DB_SYNC_COMMAND);

	/* Spin waiting for the command to complete */
	timeout = AAC_IMMEDIATE_TIMEOUT * 1000;
	AAC_BUSYWAIT(AAC_STATUS_GET(softs) & AAC_DB_SYNC_COMMAND, timeout);
	if (!timeout) {
		AACDB_PRINT(softs, CE_WARN,
		    "Sync command timed out after %d seconds (0x%x)!",
		    AAC_IMMEDIATE_TIMEOUT, AAC_FWSTATUS_GET(softs));
		return (AACERR);
	}

	/* Clear the completion flag */
	AAC_STATUS_CLR(softs, AAC_DB_SYNC_COMMAND);

	/* Get the command status */
	status = AAC_MAILBOX_GET(softs, 0);
	if (statusp != NULL)
		*statusp = status;
	if (status != SRB_STATUS_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Sync command fail: status = 0x%x", status);
		return (AACERR);
	}

	return (AACOK);
}

/*
 * Send a synchronous FIB to the adapter and wait for its completion
 */
static int
aac_sync_fib(struct aac_softstate *softs, uint16_t cmd, uint16_t fibsize)
{
	struct aac_cmd *acp = &softs->sync_ac;

	acp->flags = AAC_CMD_SYNC | AAC_CMD_IN_SYNC_SLOT;
	if (softs->state & AAC_STATE_INTR)
		acp->flags |= AAC_CMD_NO_CB;
	else
		acp->flags |= AAC_CMD_NO_INTR;

	acp->ac_comp = aac_sync_complete;
	acp->timeout = AAC_SYNC_TIMEOUT;
	acp->fib_size = fibsize;

	/*
	 * Only need to setup sync fib header, caller should have init
	 * fib data
	 */
	aac_cmd_fib_header(softs, acp, cmd);

	(void) ddi_dma_sync(acp->slotp->fib_dma_handle, 0, fibsize,
	    DDI_DMA_SYNC_FORDEV);

	aac_start_io(softs, acp);

	if (softs->state & AAC_STATE_INTR)
		return (aac_do_sync_io(softs, acp));
	else
		return (aac_do_poll_io(softs, acp));
}

static void
aac_cmd_initq(struct aac_cmd_queue *q)
{
	q->q_head = NULL;
	q->q_tail = (struct aac_cmd *)&q->q_head;
}

/*
 * Remove a cmd from the head of q
 */
static struct aac_cmd *
aac_cmd_dequeue(struct aac_cmd_queue *q)
{
	struct aac_cmd *acp;

	_NOTE(ASSUMING_PROTECTED(*q))

	if ((acp = q->q_head) != NULL) {
		if ((q->q_head = acp->next) != NULL)
			acp->next = NULL;
		else
			q->q_tail = (struct aac_cmd *)&q->q_head;
		acp->prev = NULL;
	}
	return (acp);
}

/*
 * Add a cmd to the tail of q
 */
static void
aac_cmd_enqueue(struct aac_cmd_queue *q, struct aac_cmd *acp)
{
	ASSERT(acp->next == NULL);
	acp->prev = q->q_tail;
	q->q_tail->next = acp;
	q->q_tail = acp;
}

/*
 * Remove the cmd ac from q
 */
static void
aac_cmd_delete(struct aac_cmd_queue *q, struct aac_cmd *acp)
{
	if (acp->prev) {
		if ((acp->prev->next = acp->next) != NULL) {
			acp->next->prev = acp->prev;
			acp->next = NULL;
		} else {
			q->q_tail = acp->prev;
		}
		acp->prev = NULL;
	}
	/* ac is not in the queue */
}

/*
 * Atomically insert an entry into the nominated queue, returns 0 on success or
 * AACERR if the queue is full.
 *
 * Note: it would be more efficient to defer notifying the controller in
 *	 the case where we may be inserting several entries in rapid succession,
 *	 but implementing this usefully may be difficult (it would involve a
 *	 separate queue/notify interface).
 */
static int
aac_fib_enqueue(struct aac_softstate *softs, int queue, uint32_t fib_addr,
    uint32_t fib_size)
{
	ddi_dma_handle_t dma = softs->comm_space_dma_handle;
	ddi_acc_handle_t acc = softs->comm_space_acc_handle;
	uint32_t pi, ci;

	DBCALLED(softs, 2);

	ASSERT(queue == AAC_ADAP_NORM_CMD_Q || queue == AAC_ADAP_NORM_RESP_Q);

	/* Get the producer/consumer indices */
	(void) ddi_dma_sync(dma, (uintptr_t)softs->qtablep->qt_qindex[queue] - \
	    (uintptr_t)softs->comm_space, sizeof (uint32_t) * 2,
	    DDI_DMA_SYNC_FORCPU);
	if (aac_check_dma_handle(dma) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		return (AACERR);
	}

	pi = ddi_get32(acc,
	    &softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX]);
	ci = ddi_get32(acc,
	    &softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX]);

	/*
	 * Wrap the queue first before we check the queue to see
	 * if it is full
	 */
	if (pi >= aac_qinfo[queue].size)
		pi = 0;

	/* XXX queue full */
	if ((pi + 1) == ci)
		return (AACERR);

	/* Fill in queue entry */
	ddi_put32(acc, &((softs->qentries[queue] + pi)->aq_fib_size), fib_size);
	ddi_put32(acc, &((softs->qentries[queue] + pi)->aq_fib_addr), fib_addr);
	(void) ddi_dma_sync(dma, (uintptr_t)(softs->qentries[queue] + pi) - \
	    (uintptr_t)softs->comm_space, sizeof (struct aac_queue_entry),
	    DDI_DMA_SYNC_FORDEV);

	/* Update producer index */
	ddi_put32(acc, &softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX],
	    pi + 1);
	(void) ddi_dma_sync(dma,
	    (uintptr_t)&softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX] - \
	    (uintptr_t)softs->comm_space, sizeof (uint32_t),
	    DDI_DMA_SYNC_FORDEV);

	if (aac_qinfo[queue].notify != 0)
		AAC_NOTIFY(softs, aac_qinfo[queue].notify);
	return (AACOK);
}

/*
 * Atomically remove one entry from the nominated queue, returns 0 on
 * success or AACERR if the queue is empty.
 */
static int
aac_fib_dequeue(struct aac_softstate *softs, int queue, int *idxp)
{
	ddi_acc_handle_t acc = softs->comm_space_acc_handle;
	ddi_dma_handle_t dma = softs->comm_space_dma_handle;
	uint32_t pi, ci;
	int unfull = 0;

	DBCALLED(softs, 2);

	ASSERT(idxp);

	/* Get the producer/consumer indices */
	(void) ddi_dma_sync(dma, (uintptr_t)softs->qtablep->qt_qindex[queue] - \
	    (uintptr_t)softs->comm_space, sizeof (uint32_t) * 2,
	    DDI_DMA_SYNC_FORCPU);
	pi = ddi_get32(acc,
	    &softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX]);
	ci = ddi_get32(acc,
	    &softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX]);

	/* Check for queue empty */
	if (ci == pi)
		return (AACERR);

	if (pi >= aac_qinfo[queue].size)
		pi = 0;

	/* Check for queue full */
	if (ci == pi + 1)
		unfull = 1;

	/*
	 * The controller does not wrap the queue,
	 * so we have to do it by ourselves
	 */
	if (ci >= aac_qinfo[queue].size)
		ci = 0;

	/* Fetch the entry */
	(void) ddi_dma_sync(dma, (uintptr_t)(softs->qentries[queue] + pi) - \
	    (uintptr_t)softs->comm_space, sizeof (struct aac_queue_entry),
	    DDI_DMA_SYNC_FORCPU);
	if (aac_check_dma_handle(dma) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		return (AACERR);
	}

	switch (queue) {
	case AAC_HOST_NORM_RESP_Q:
	case AAC_HOST_HIGH_RESP_Q:
		*idxp = ddi_get32(acc,
		    &(softs->qentries[queue] + ci)->aq_fib_addr);
		break;

	case AAC_HOST_NORM_CMD_Q:
	case AAC_HOST_HIGH_CMD_Q:
		*idxp = ddi_get32(acc,
		    &(softs->qentries[queue] + ci)->aq_fib_addr) / AAC_FIB_SIZE;
		break;

	default:
		cmn_err(CE_NOTE, "!Invalid queue in aac_fib_dequeue()");
		return (AACERR);
	}

	/* Update consumer index */
	ddi_put32(acc, &softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX],
	    ci + 1);
	(void) ddi_dma_sync(dma,
	    (uintptr_t)&softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX] - \
	    (uintptr_t)softs->comm_space, sizeof (uint32_t),
	    DDI_DMA_SYNC_FORDEV);

	if (unfull && aac_qinfo[queue].notify != 0)
		AAC_NOTIFY(softs, aac_qinfo[queue].notify);
	return (AACOK);
}

static struct aac_mntinforesp *
aac_get_mntinfo(struct aac_softstate *softs, int cid)
{
	ddi_acc_handle_t acc = softs->sync_ac.slotp->fib_acc_handle;
	struct aac_fib *fibp = softs->sync_ac.slotp->fibp;
	struct aac_mntinfo *mi = (struct aac_mntinfo *)&fibp->data[0];
	struct aac_mntinforesp *mir;

	ddi_put32(acc, &mi->Command, /* Use 64-bit LBA if enabled */
	    (softs->flags & AAC_FLAGS_LBA_64BIT) ?
	    VM_NameServe64 : VM_NameServe);
	ddi_put32(acc, &mi->MntType, FT_FILESYS);
	ddi_put32(acc, &mi->MntCount, cid);

	if (aac_sync_fib(softs, ContainerCommand,
	    AAC_FIB_SIZEOF(struct aac_mntinfo)) == AACERR) {
		AACDB_PRINT(softs, CE_WARN, "Error probe container %d", cid);
		return (NULL);
	}

	mir = (struct aac_mntinforesp *)&fibp->data[0];
	if (ddi_get32(acc, &mir->Status) == ST_OK)
		return (mir);
	return (NULL);
}

static int
aac_get_container_count(struct aac_softstate *softs, int *count)
{
	ddi_acc_handle_t acc;
	struct aac_mntinforesp *mir;
	int rval;

	(void) aac_sync_fib_slot_bind(softs, &softs->sync_ac);
	acc = softs->sync_ac.slotp->fib_acc_handle;

	if ((mir = aac_get_mntinfo(softs, 0)) == NULL) {
		rval = AACERR;
		goto finish;
	}
	*count = ddi_get32(acc, &mir->MntRespCount);
	if (*count > AAC_MAX_LD) {
		AACDB_PRINT(softs, CE_CONT,
		    "container count(%d) > AAC_MAX_LD", *count);
		rval = AACERR;
		goto finish;
	}
	rval = AACOK;

finish:
	aac_sync_fib_slot_release(softs, &softs->sync_ac);
	return (rval);
}

static int
aac_get_container_uid(struct aac_softstate *softs, uint32_t cid, uint32_t *uid)
{
	ddi_acc_handle_t acc = softs->sync_ac.slotp->fib_acc_handle;
	struct aac_Container *ct = (struct aac_Container *) \
	    &softs->sync_ac.slotp->fibp->data[0];

	bzero(ct, sizeof (*ct) - CT_PACKET_SIZE);
	ddi_put32(acc, &ct->Command, VM_ContainerConfig);
	ddi_put32(acc, &ct->CTCommand.command, CT_CID_TO_32BITS_UID);
	ddi_put32(acc, &ct->CTCommand.param[0], cid);

	if (aac_sync_fib(softs, ContainerCommand,
	    AAC_FIB_SIZEOF(struct aac_Container)) == AACERR)
		return (AACERR);
	if (ddi_get32(acc, &ct->CTCommand.param[0]) != CT_OK)
		return (AACERR);

	*uid = ddi_get32(acc, &ct->CTCommand.param[1]);
	return (AACOK);
}

/*
 * Request information of the container cid
 */
static struct aac_mntinforesp *
aac_get_container_info(struct aac_softstate *softs, int cid)
{
	ddi_acc_handle_t acc = softs->sync_ac.slotp->fib_acc_handle;
	struct aac_mntinforesp *mir;
	int rval_uid;
	uint32_t uid;

	/* Get container UID first so that it will not overwrite mntinfo */
	rval_uid = aac_get_container_uid(softs, cid, &uid);

	/* Get container basic info */
	if ((mir = aac_get_mntinfo(softs, cid)) == NULL) {
		AACDB_PRINT(softs, CE_CONT,
		    "query container %d info failed", cid);
		return (NULL);
	}
	if (ddi_get32(acc, &mir->MntObj.VolType) == CT_NONE)
		return (mir);
	if (rval_uid != AACOK) {
		AACDB_PRINT(softs, CE_CONT,
		    "query container %d uid failed", cid);
		return (NULL);
	}

	ddi_put32(acc, &mir->Status, uid);
	return (mir);
}

static enum aac_cfg_event
aac_probe_container(struct aac_softstate *softs, uint32_t cid)
{
	enum aac_cfg_event event = AAC_CFG_NULL_NOEXIST;
	struct aac_container *dvp = &softs->containers[cid];
	struct aac_mntinforesp *mir;
	ddi_acc_handle_t acc;

	(void) aac_sync_fib_slot_bind(softs, &softs->sync_ac);
	acc = softs->sync_ac.slotp->fib_acc_handle;

	/* Get container basic info */
	if ((mir = aac_get_container_info(softs, cid)) == NULL) {
		/* AAC_CFG_NULL_NOEXIST */
		goto finish;
	}

	if (ddi_get32(acc, &mir->MntObj.VolType) == CT_NONE) {
		if (AAC_DEV_IS_VALID(&dvp->dev)) {
			AACDB_PRINT(softs, CE_NOTE,
			    ">>> Container %d deleted", cid);
			dvp->dev.flags &= ~AAC_DFLAG_VALID;
			event = AAC_CFG_DELETE;
		}
		/* AAC_CFG_NULL_NOEXIST */
	} else {
		uint64_t size;
		uint32_t uid;

		event = AAC_CFG_NULL_EXIST;

		size = AAC_MIR_SIZE(softs, acc, mir);
		uid = ddi_get32(acc, &mir->Status);
		if (AAC_DEV_IS_VALID(&dvp->dev)) {
			if (dvp->uid != uid) {
				AACDB_PRINT(softs, CE_WARN,
				    ">>> Container %u uid changed to %d",
				    cid, uid);
				dvp->uid = uid;
				event = AAC_CFG_CHANGE;
			}
			if (dvp->size != size) {
				AACDB_PRINT(softs, CE_NOTE,
				    ">>> Container %u size changed to %"PRIu64,
				    cid, size);
				dvp->size = size;
				event = AAC_CFG_CHANGE;
			}
		} else { /* Init new container */
			AACDB_PRINT(softs, CE_NOTE,
			    ">>> Container %d added: " \
			    "size=0x%x.%08x, type=%d, name=%s",
			    cid,
			    ddi_get32(acc, &mir->MntObj.CapacityHigh),
			    ddi_get32(acc, &mir->MntObj.Capacity),
			    ddi_get32(acc, &mir->MntObj.VolType),
			    mir->MntObj.FileSystemName);
			dvp->dev.flags |= AAC_DFLAG_VALID;
			dvp->dev.type = AAC_DEV_LD;

			dvp->cid = cid;
			dvp->uid = uid;
			dvp->size = size;
			dvp->locked = 0;
			dvp->deleted = 0;

			event = AAC_CFG_ADD;
		}
	}

finish:
	aac_sync_fib_slot_release(softs, &softs->sync_ac);
	return (event);
}

/*
 * Do a rescan of all the possible containers and update the container list
 * with newly online/offline containers, and prepare for autoconfiguration.
 */
static int
aac_probe_containers(struct aac_softstate *softs)
{
	int i, count, total;

	/* Loop over possible containers */
	count = softs->container_count;
	if (aac_get_container_count(softs, &count) == AACERR)
		return (AACERR);

	for (i = total = 0; i < count; i++) {
		enum aac_cfg_event event = aac_probe_container(softs, i);
		if ((event != AAC_CFG_NULL_NOEXIST) &&
		    (event != AAC_CFG_NULL_EXIST)) {
			(void) aac_handle_dr(softs, i, -1, event);
			total++;
		}
	}

	if (count < softs->container_count) {
		struct aac_container *dvp;

		for (dvp = &softs->containers[count];
		    dvp < &softs->containers[softs->container_count]; dvp++) {
			if (!AAC_DEV_IS_VALID(&dvp->dev))
				continue;
			AACDB_PRINT(softs, CE_NOTE, ">>> Container %d deleted",
			    dvp->cid);
			dvp->dev.flags &= ~AAC_DFLAG_VALID;
			(void) aac_handle_dr(softs, dvp->cid, -1,
			    AAC_CFG_DELETE);
		}
	}

	softs->container_count = count;
	AACDB_PRINT(softs, CE_CONT, "?Total %d container(s) found", total);
	return (AACOK);
}

static int
aac_probe_jbod(struct aac_softstate *softs, int tgt, int event)
{
	ASSERT(AAC_MAX_LD <= tgt);
	ASSERT(tgt < AAC_MAX_DEV(softs));
	struct aac_device *dvp;
	dvp = AAC_DEV(softs, tgt);

	switch (event) {
	case AAC_CFG_ADD:
		AACDB_PRINT(softs, CE_NOTE,
		    ">>> Jbod %d added", tgt - AAC_MAX_LD);
		dvp->flags |= AAC_DFLAG_VALID;
		dvp->type = AAC_DEV_PD;
		break;
	case AAC_CFG_DELETE:
		AACDB_PRINT(softs, CE_NOTE,
		    ">>> Jbod %d deleted", tgt - AAC_MAX_LD);
		dvp->flags &= ~AAC_DFLAG_VALID;
		break;
	default:
		return (AACERR);
	}
	(void) aac_handle_dr(softs, tgt, 0, event);
	return (AACOK);
}

static int
aac_alloc_comm_space(struct aac_softstate *softs)
{
	size_t rlen;
	ddi_dma_cookie_t cookie;
	uint_t cookien;

	/* Allocate DMA for comm. space */
	if (ddi_dma_alloc_handle(
	    softs->devinfo_p,
	    &softs->addr_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &softs->comm_space_dma_handle) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Cannot alloc dma handle for communication area");
		goto error;
	}
	if (ddi_dma_mem_alloc(
	    softs->comm_space_dma_handle,
	    sizeof (struct aac_comm_space),
	    &softs->acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&softs->comm_space,
	    &rlen,
	    &softs->comm_space_acc_handle) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Cannot alloc mem for communication area");
		goto error;
	}
	if (ddi_dma_addr_bind_handle(
	    softs->comm_space_dma_handle,
	    NULL,
	    (caddr_t)softs->comm_space,
	    sizeof (struct aac_comm_space),
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &cookie,
	    &cookien) != DDI_DMA_MAPPED) {
		AACDB_PRINT(softs, CE_WARN,
		    "DMA bind failed for communication area");
		goto error;
	}
	softs->comm_space_phyaddr = cookie.dmac_address;

	return (AACOK);
error:
	if (softs->comm_space_acc_handle) {
		ddi_dma_mem_free(&softs->comm_space_acc_handle);
		softs->comm_space_acc_handle = NULL;
	}
	if (softs->comm_space_dma_handle) {
		ddi_dma_free_handle(&softs->comm_space_dma_handle);
		softs->comm_space_dma_handle = NULL;
	}
	return (AACERR);
}

static void
aac_free_comm_space(struct aac_softstate *softs)
{

	(void) ddi_dma_unbind_handle(softs->comm_space_dma_handle);
	ddi_dma_mem_free(&softs->comm_space_acc_handle);
	softs->comm_space_acc_handle = NULL;
	ddi_dma_free_handle(&softs->comm_space_dma_handle);
	softs->comm_space_dma_handle = NULL;
	softs->comm_space_phyaddr = NULL;
}

/*
 * Initialize the data structures that are required for the communication
 * interface to operate
 */
static int
aac_setup_comm_space(struct aac_softstate *softs)
{
	ddi_dma_handle_t dma = softs->comm_space_dma_handle;
	ddi_acc_handle_t acc = softs->comm_space_acc_handle;
	uint32_t comm_space_phyaddr;
	struct aac_adapter_init *initp;
	int qoffset;

	comm_space_phyaddr = softs->comm_space_phyaddr;

	/* Setup adapter init struct */
	initp = &softs->comm_space->init_data;
	bzero(initp, sizeof (struct aac_adapter_init));

	ddi_put32(acc, &initp->InitStructRevision, AAC_INIT_STRUCT_REVISION);
	ddi_put32(acc, &initp->HostElapsedSeconds, ddi_get_time());

	/* Setup new/old comm. specific data */
	if (softs->flags & AAC_FLAGS_RAW_IO) {
		uint32_t init_flags = 0;

		if (softs->flags & AAC_FLAGS_NEW_COMM)
			init_flags |= AAC_INIT_FLAGS_NEW_COMM_SUPPORTED;
		/* AAC_SUPPORTED_POWER_MANAGEMENT */
		init_flags |= AAC_INIT_FLAGS_DRIVER_SUPPORTS_PM;
		init_flags |= AAC_INIT_FLAGS_DRIVER_USES_UTC_TIME;

		ddi_put32(acc, &initp->InitStructRevision,
		    AAC_INIT_STRUCT_REVISION_4);
		ddi_put32(acc, &initp->InitFlags, init_flags);
		/* Setup the preferred settings */
		ddi_put32(acc, &initp->MaxIoCommands, softs->aac_max_fibs);
		ddi_put32(acc, &initp->MaxIoSize,
		    (softs->aac_max_sectors << 9));
		ddi_put32(acc, &initp->MaxFibSize, softs->aac_max_fib_size);
	} else {
		/*
		 * Tells the adapter about the physical location of various
		 * important shared data structures
		 */
		ddi_put32(acc, &initp->AdapterFibsPhysicalAddress,
		    comm_space_phyaddr + \
		    offsetof(struct aac_comm_space, adapter_fibs));
		ddi_put32(acc, &initp->AdapterFibsVirtualAddress, 0);
		ddi_put32(acc, &initp->AdapterFibAlign, AAC_FIB_SIZE);
		ddi_put32(acc, &initp->AdapterFibsSize,
		    AAC_ADAPTER_FIBS * AAC_FIB_SIZE);
		ddi_put32(acc, &initp->PrintfBufferAddress,
		    comm_space_phyaddr + \
		    offsetof(struct aac_comm_space, adapter_print_buf));
		ddi_put32(acc, &initp->PrintfBufferSize,
		    AAC_ADAPTER_PRINT_BUFSIZE);
		ddi_put32(acc, &initp->MiniPortRevision,
		    AAC_INIT_STRUCT_MINIPORT_REVISION);
		ddi_put32(acc, &initp->HostPhysMemPages, AAC_MAX_PFN);

		qoffset = (comm_space_phyaddr + \
		    offsetof(struct aac_comm_space, qtable)) % \
		    AAC_QUEUE_ALIGN;
		if (qoffset)
			qoffset = AAC_QUEUE_ALIGN - qoffset;
		softs->qtablep = (struct aac_queue_table *) \
		    ((char *)&softs->comm_space->qtable + qoffset);
		ddi_put32(acc, &initp->CommHeaderAddress, comm_space_phyaddr + \
		    offsetof(struct aac_comm_space, qtable) + qoffset);

		/* Init queue table */
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_NORM_CMD_Q][AAC_PRODUCER_INDEX],
		    AAC_HOST_NORM_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_NORM_CMD_Q][AAC_CONSUMER_INDEX],
		    AAC_HOST_NORM_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_HIGH_CMD_Q][AAC_PRODUCER_INDEX],
		    AAC_HOST_HIGH_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_HIGH_CMD_Q][AAC_CONSUMER_INDEX],
		    AAC_HOST_HIGH_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_NORM_CMD_Q][AAC_PRODUCER_INDEX],
		    AAC_ADAP_NORM_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_NORM_CMD_Q][AAC_CONSUMER_INDEX],
		    AAC_ADAP_NORM_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_HIGH_CMD_Q][AAC_PRODUCER_INDEX],
		    AAC_ADAP_HIGH_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_HIGH_CMD_Q][AAC_CONSUMER_INDEX],
		    AAC_ADAP_HIGH_CMD_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_NORM_RESP_Q][AAC_PRODUCER_INDEX],
		    AAC_HOST_NORM_RESP_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_NORM_RESP_Q][AAC_CONSUMER_INDEX],
		    AAC_HOST_NORM_RESP_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_HIGH_RESP_Q][AAC_PRODUCER_INDEX],
		    AAC_HOST_HIGH_RESP_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_HOST_HIGH_RESP_Q][AAC_CONSUMER_INDEX],
		    AAC_HOST_HIGH_RESP_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_NORM_RESP_Q][AAC_PRODUCER_INDEX],
		    AAC_ADAP_NORM_RESP_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_NORM_RESP_Q][AAC_CONSUMER_INDEX],
		    AAC_ADAP_NORM_RESP_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_HIGH_RESP_Q][AAC_PRODUCER_INDEX],
		    AAC_ADAP_HIGH_RESP_ENTRIES);
		ddi_put32(acc, &softs->qtablep-> \
		    qt_qindex[AAC_ADAP_HIGH_RESP_Q][AAC_CONSUMER_INDEX],
		    AAC_ADAP_HIGH_RESP_ENTRIES);

		/* Init queue entries */
		softs->qentries[AAC_HOST_NORM_CMD_Q] =
		    &softs->qtablep->qt_HostNormCmdQueue[0];
		softs->qentries[AAC_HOST_HIGH_CMD_Q] =
		    &softs->qtablep->qt_HostHighCmdQueue[0];
		softs->qentries[AAC_ADAP_NORM_CMD_Q] =
		    &softs->qtablep->qt_AdapNormCmdQueue[0];
		softs->qentries[AAC_ADAP_HIGH_CMD_Q] =
		    &softs->qtablep->qt_AdapHighCmdQueue[0];
		softs->qentries[AAC_HOST_NORM_RESP_Q] =
		    &softs->qtablep->qt_HostNormRespQueue[0];
		softs->qentries[AAC_HOST_HIGH_RESP_Q] =
		    &softs->qtablep->qt_HostHighRespQueue[0];
		softs->qentries[AAC_ADAP_NORM_RESP_Q] =
		    &softs->qtablep->qt_AdapNormRespQueue[0];
		softs->qentries[AAC_ADAP_HIGH_RESP_Q] =
		    &softs->qtablep->qt_AdapHighRespQueue[0];
	}
	(void) ddi_dma_sync(dma, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* Send init structure to the card */
	if (aac_sync_mbcommand(softs, AAC_MONKER_INITSTRUCT,
	    comm_space_phyaddr + \
	    offsetof(struct aac_comm_space, init_data),
	    0, 0, 0, NULL) == AACERR) {
		AACDB_PRINT(softs, CE_WARN,
		    "Cannot send init structure to adapter");
		return (AACERR);
	}

	return (AACOK);
}

static uchar_t *
aac_vendor_id(struct aac_softstate *softs, uchar_t *buf)
{
	(void) memset(buf, ' ', AAC_VENDOR_LEN);
	bcopy(softs->vendor_name, buf, strlen(softs->vendor_name));
	return (buf + AAC_VENDOR_LEN);
}

static uchar_t *
aac_product_id(struct aac_softstate *softs, uchar_t *buf)
{
	(void) memset(buf, ' ', AAC_PRODUCT_LEN);
	bcopy(softs->product_name, buf, strlen(softs->product_name));
	return (buf + AAC_PRODUCT_LEN);
}

/*
 * Construct unit serial number from container uid
 */
static uchar_t *
aac_lun_serialno(struct aac_softstate *softs, int tgt, uchar_t *buf)
{
	int i, d;
	uint32_t uid;

	ASSERT(tgt >= 0 && tgt < AAC_MAX_LD);

	uid = softs->containers[tgt].uid;
	for (i = 7; i >= 0; i--) {
		d = uid & 0xf;
		buf[i] = d > 9 ? 'A' + (d - 0xa) : '0' + d;
		uid >>= 4;
	}
	return (buf + 8);
}

/*
 * SPC-3 7.5 INQUIRY command implementation
 */
static void
aac_inquiry(struct aac_softstate *softs, struct scsi_pkt *pkt,
    union scsi_cdb *cdbp, struct buf *bp)
{
	int tgt = pkt->pkt_address.a_target;
	char *b_addr = NULL;
	uchar_t page = cdbp->cdb_opaque[2];

	if (cdbp->cdb_opaque[1] & AAC_CDB_INQUIRY_CMDDT) {
		/* Command Support Data is not supported */
		aac_set_arq_data(pkt, KEY_ILLEGAL_REQUEST, 0x24, 0x00, 0);
		return;
	}

	if (bp && bp->b_un.b_addr && bp->b_bcount) {
		if (bp->b_flags & (B_PHYS | B_PAGEIO))
			bp_mapin(bp);
		b_addr = bp->b_un.b_addr;
	}

	if (cdbp->cdb_opaque[1] & AAC_CDB_INQUIRY_EVPD) {
		uchar_t *vpdp = (uchar_t *)b_addr;
		uchar_t *idp, *sp;

		/* SPC-3 8.4 Vital product data parameters */
		switch (page) {
		case 0x00:
			/* Supported VPD pages */
			if (vpdp == NULL ||
			    bp->b_bcount < (AAC_VPD_PAGE_DATA + 3))
				return;
			bzero(vpdp, AAC_VPD_PAGE_LENGTH);
			vpdp[AAC_VPD_PAGE_CODE] = 0x00;
			vpdp[AAC_VPD_PAGE_LENGTH] = 3;

			vpdp[AAC_VPD_PAGE_DATA] = 0x00;
			vpdp[AAC_VPD_PAGE_DATA + 1] = 0x80;
			vpdp[AAC_VPD_PAGE_DATA + 2] = 0x83;

			pkt->pkt_state |= STATE_XFERRED_DATA;
			break;

		case 0x80:
			/* Unit serial number page */
			if (vpdp == NULL ||
			    bp->b_bcount < (AAC_VPD_PAGE_DATA + 8))
				return;
			bzero(vpdp, AAC_VPD_PAGE_LENGTH);
			vpdp[AAC_VPD_PAGE_CODE] = 0x80;
			vpdp[AAC_VPD_PAGE_LENGTH] = 8;

			sp = &vpdp[AAC_VPD_PAGE_DATA];
			(void) aac_lun_serialno(softs, tgt, sp);

			pkt->pkt_state |= STATE_XFERRED_DATA;
			break;

		case 0x83:
			/* Device identification page */
			if (vpdp == NULL ||
			    bp->b_bcount < (AAC_VPD_PAGE_DATA + 32))
				return;
			bzero(vpdp, AAC_VPD_PAGE_LENGTH);
			vpdp[AAC_VPD_PAGE_CODE] = 0x83;

			idp = &vpdp[AAC_VPD_PAGE_DATA];
			bzero(idp, AAC_VPD_ID_LENGTH);
			idp[AAC_VPD_ID_CODESET] = 0x02;
			idp[AAC_VPD_ID_TYPE] = 0x01;

			/*
			 * SPC-3 Table 111 - Identifier type
			 * One recommanded method of constructing the remainder
			 * of identifier field is to concatenate the product
			 * identification field from the standard INQUIRY data
			 * field and the product serial number field from the
			 * unit serial number page.
			 */
			sp = &idp[AAC_VPD_ID_DATA];
			sp = aac_vendor_id(softs, sp);
			sp = aac_product_id(softs, sp);
			sp = aac_lun_serialno(softs, tgt, sp);
			idp[AAC_VPD_ID_LENGTH] = (uintptr_t)sp - \
			    (uintptr_t)&idp[AAC_VPD_ID_DATA];

			vpdp[AAC_VPD_PAGE_LENGTH] = (uintptr_t)sp - \
			    (uintptr_t)&vpdp[AAC_VPD_PAGE_DATA];
			pkt->pkt_state |= STATE_XFERRED_DATA;
			break;

		default:
			aac_set_arq_data(pkt, KEY_ILLEGAL_REQUEST,
			    0x24, 0x00, 0);
			break;
		}
	} else {
		struct scsi_inquiry *inqp = (struct scsi_inquiry *)b_addr;
		size_t len = sizeof (struct scsi_inquiry);

		if (page != 0) {
			aac_set_arq_data(pkt, KEY_ILLEGAL_REQUEST,
			    0x24, 0x00, 0);
			return;
		}
		if (inqp == NULL || bp->b_bcount < len)
			return;

		bzero(inqp, len);
		inqp->inq_len = AAC_ADDITIONAL_LEN;
		inqp->inq_ansi = AAC_ANSI_VER;
		inqp->inq_rdf = AAC_RESP_DATA_FORMAT;
		(void) aac_vendor_id(softs, (uchar_t *)inqp->inq_vid);
		(void) aac_product_id(softs, (uchar_t *)inqp->inq_pid);
		bcopy("V1.0", inqp->inq_revision, 4);
		inqp->inq_cmdque = 1; /* enable tagged-queuing */
		/*
		 * For "sd-max-xfer-size" property which may impact performance
		 * when IO threads increase.
		 */
		inqp->inq_wbus32 = 1;

		pkt->pkt_state |= STATE_XFERRED_DATA;
	}
}

/*
 * SPC-3 7.10 MODE SENSE command implementation
 */
static void
aac_mode_sense(struct aac_softstate *softs, struct scsi_pkt *pkt,
    union scsi_cdb *cdbp, struct buf *bp, int capacity)
{
	uchar_t pagecode;
	struct mode_header *headerp;
	struct mode_header_g1 *g1_headerp;
	unsigned int ncyl;
	caddr_t sense_data;
	caddr_t next_page;
	size_t sdata_size;
	size_t pages_size;
	int unsupport_page = 0;

	ASSERT(cdbp->scc_cmd == SCMD_MODE_SENSE ||
	    cdbp->scc_cmd == SCMD_MODE_SENSE_G1);

	if (!(bp && bp->b_un.b_addr && bp->b_bcount))
		return;

	if (bp->b_flags & (B_PHYS | B_PAGEIO))
		bp_mapin(bp);
	pkt->pkt_state |= STATE_XFERRED_DATA;
	pagecode = cdbp->cdb_un.sg.scsi[0] & 0x3F;

	/* calculate the size of needed buffer */
	if (cdbp->scc_cmd == SCMD_MODE_SENSE)
		sdata_size = MODE_HEADER_LENGTH;
	else /* must be SCMD_MODE_SENSE_G1 */
		sdata_size = MODE_HEADER_LENGTH_G1;

	pages_size = 0;
	switch (pagecode) {
	case SD_MODE_SENSE_PAGE3_CODE:
		pages_size += sizeof (struct mode_format);
		break;

	case SD_MODE_SENSE_PAGE4_CODE:
		pages_size += sizeof (struct mode_geometry);
		break;

	case MODEPAGE_CTRL_MODE:
		if (softs->flags & AAC_FLAGS_LBA_64BIT) {
			pages_size += sizeof (struct mode_control_scsi3);
		} else {
			unsupport_page = 1;
		}
		break;

	case MODEPAGE_ALLPAGES:
		if (softs->flags & AAC_FLAGS_LBA_64BIT) {
			pages_size += sizeof (struct mode_format) +
			    sizeof (struct mode_geometry) +
			    sizeof (struct mode_control_scsi3);
		} else {
			pages_size += sizeof (struct mode_format) +
			    sizeof (struct mode_geometry);
		}
		break;

	default:
		/* unsupported pages */
		unsupport_page = 1;
	}

	/* allocate buffer to fill the send data */
	sdata_size += pages_size;
	sense_data = kmem_zalloc(sdata_size, KM_SLEEP);

	if (cdbp->scc_cmd == SCMD_MODE_SENSE) {
		headerp = (struct mode_header *)sense_data;
		headerp->length = MODE_HEADER_LENGTH + pages_size -
		    sizeof (headerp->length);
		headerp->bdesc_length = 0;
		next_page = sense_data + sizeof (struct mode_header);
	} else {
		g1_headerp = (void *)sense_data;
		g1_headerp->length = BE_16(MODE_HEADER_LENGTH_G1 + pages_size -
		    sizeof (g1_headerp->length));
		g1_headerp->bdesc_length = 0;
		next_page = sense_data + sizeof (struct mode_header_g1);
	}

	if (unsupport_page)
		goto finish;

	if (pagecode == SD_MODE_SENSE_PAGE3_CODE ||
	    pagecode == MODEPAGE_ALLPAGES) {
		/* SBC-3 7.1.3.3 Format device page */
		struct mode_format *page3p;

		page3p = (void *)next_page;
		page3p->mode_page.code = SD_MODE_SENSE_PAGE3_CODE;
		page3p->mode_page.length = sizeof (struct mode_format);
		page3p->data_bytes_sect = BE_16(AAC_SECTOR_SIZE);
		page3p->sect_track = BE_16(AAC_SECTORS_PER_TRACK);

		next_page += sizeof (struct mode_format);
	}

	if (pagecode == SD_MODE_SENSE_PAGE4_CODE ||
	    pagecode == MODEPAGE_ALLPAGES) {
		/* SBC-3 7.1.3.8 Rigid disk device geometry page */
		struct mode_geometry *page4p;

		page4p = (void *)next_page;
		page4p->mode_page.code = SD_MODE_SENSE_PAGE4_CODE;
		page4p->mode_page.length = sizeof (struct mode_geometry);
		page4p->heads = AAC_NUMBER_OF_HEADS;
		page4p->rpm = BE_16(AAC_ROTATION_SPEED);
		ncyl = capacity / (AAC_NUMBER_OF_HEADS * AAC_SECTORS_PER_TRACK);
		page4p->cyl_lb = ncyl & 0xff;
		page4p->cyl_mb = (ncyl >> 8) & 0xff;
		page4p->cyl_ub = (ncyl >> 16) & 0xff;

		next_page += sizeof (struct mode_geometry);
	}

	if ((pagecode == MODEPAGE_CTRL_MODE || pagecode == MODEPAGE_ALLPAGES) &&
	    softs->flags & AAC_FLAGS_LBA_64BIT) {
		/* 64-bit LBA need large sense data */
		struct mode_control_scsi3 *mctl;

		mctl = (void *)next_page;
		mctl->mode_page.code = MODEPAGE_CTRL_MODE;
		mctl->mode_page.length =
		    sizeof (struct mode_control_scsi3) -
		    sizeof (struct mode_page);
		mctl->d_sense = 1;
	}

finish:
	/* copyout the valid data. */
	bcopy(sense_data, bp->b_un.b_addr, min(sdata_size, bp->b_bcount));
	kmem_free(sense_data, sdata_size);
}

static int
aac_name_node(dev_info_t *dip, char *name, int len)
{
	int tgt, lun;

	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "target", -1);
	if (tgt == -1)
		return (DDI_FAILURE);
	lun = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "lun", -1);
	if (lun == -1)
		return (DDI_FAILURE);

	(void) snprintf(name, len, "%x,%x", tgt, lun);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
aac_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(tran);
#if defined(DEBUG) || defined(__lock_lint)
	int ctl = ddi_get_instance(softs->devinfo_p);
#endif
	uint16_t tgt = sd->sd_address.a_target;
	uint8_t lun = sd->sd_address.a_lun;
	struct aac_device *dvp;

	DBCALLED(softs, 2);

	if (ndi_dev_is_persistent_node(tgt_dip) == 0) {
		/*
		 * If no persistent node exist, we don't allow .conf node
		 * to be created.
		 */
		if (aac_find_child(softs, tgt, lun) != NULL) {
			if (ndi_merge_node(tgt_dip, aac_name_node) !=
			    DDI_SUCCESS)
				/* Create this .conf node */
				return (DDI_SUCCESS);
		}
		return (DDI_FAILURE);
	}

	/*
	 * Only support container/phys. device that has been
	 * detected and valid
	 */
	mutex_enter(&softs->io_lock);
	if (tgt >= AAC_MAX_DEV(softs)) {
		AACDB_PRINT_TRAN(softs,
		    "aac_tran_tgt_init: c%dt%dL%d out", ctl, tgt, lun);
		mutex_exit(&softs->io_lock);
		return (DDI_FAILURE);
	}

	if (tgt < AAC_MAX_LD) {
		dvp = (struct aac_device *)&softs->containers[tgt];
		if (lun != 0 || !AAC_DEV_IS_VALID(dvp)) {
			AACDB_PRINT_TRAN(softs, "aac_tran_tgt_init: c%dt%dL%d",
			    ctl, tgt, lun);
			mutex_exit(&softs->io_lock);
			return (DDI_FAILURE);
		}
		/*
		 * Save the tgt_dip for the given target if one doesn't exist
		 * already. Dip's for non-existance tgt's will be cleared in
		 * tgt_free.
		 */
		if (softs->containers[tgt].dev.dip == NULL &&
		    strcmp(ddi_driver_name(sd->sd_dev), "sd") == 0)
			softs->containers[tgt].dev.dip = tgt_dip;
	} else {
		dvp = (struct aac_device *)&softs->nondasds[AAC_PD(tgt)];
		/*
		 * Save the tgt_dip for the given target if one doesn't exist
		 * already. Dip's for non-existance tgt's will be cleared in
		 * tgt_free.
		 */

		if (softs->nondasds[AAC_PD(tgt)].dev.dip  == NULL &&
		    strcmp(ddi_driver_name(sd->sd_dev), "sd") == 0)
			softs->nondasds[AAC_PD(tgt)].dev.dip  = tgt_dip;
	}

	if (softs->flags & AAC_FLAGS_BRKUP) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, tgt_dip,
		    "buf_break", 1) != DDI_PROP_SUCCESS) {
			cmn_err(CE_CONT, "unable to create "
			    "property for t%dL%d (buf_break)", tgt, lun);
		}
	}

	AACDB_PRINT(softs, CE_NOTE,
	    "aac_tran_tgt_init: c%dt%dL%d ok (%s)", ctl, tgt, lun,
	    (dvp->type == AAC_DEV_PD) ? "pd" : "ld");
	mutex_exit(&softs->io_lock);
	return (DDI_SUCCESS);
}

static void
aac_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(hba_dip, tgt_dip, hba_tran))
#endif

	struct aac_softstate *softs = SD2AAC(sd);
	int tgt = sd->sd_address.a_target;

	mutex_enter(&softs->io_lock);
	if (tgt < AAC_MAX_LD) {
		if (softs->containers[tgt].dev.dip == tgt_dip)
			softs->containers[tgt].dev.dip = NULL;
	} else {
		if (softs->nondasds[AAC_PD(tgt)].dev.dip == tgt_dip)
			softs->nondasds[AAC_PD(tgt)].dev.dip = NULL;
		softs->nondasds[AAC_PD(tgt)].dev.flags &= ~AAC_DFLAG_VALID;
	}
	mutex_exit(&softs->io_lock);
}

/*
 * Check if the firmware is Up And Running. If it is in the Kernel Panic
 * state, (BlinkLED code + 1) is returned.
 *    0 -- firmware up and running
 *   -1 -- firmware dead
 *   >0 -- firmware kernel panic
 */
static int
aac_check_adapter_health(struct aac_softstate *softs)
{
	int rval;

	rval = PCI_MEM_GET32(softs, AAC_OMR0);

	if (rval & AAC_KERNEL_UP_AND_RUNNING) {
		rval = 0;
	} else if (rval & AAC_KERNEL_PANIC) {
		cmn_err(CE_WARN, "firmware panic");
		rval = ((rval >> 16) & 0xff) + 1; /* avoid 0 as return value */
	} else {
		cmn_err(CE_WARN, "firmware dead");
		rval = -1;
	}
	return (rval);
}

static void
aac_abort_iocmd(struct aac_softstate *softs, struct aac_cmd *acp,
    uchar_t reason)
{
	acp->flags |= AAC_CMD_ABORT;

	if (acp->pkt) {
		if (acp->slotp) { /* outstanding cmd */
			acp->pkt->pkt_state |= STATE_GOT_STATUS;
		}

		switch (reason) {
		case CMD_TIMEOUT:
			AACDB_PRINT(softs, CE_NOTE, "CMD_TIMEOUT: acp=0x%p",
			    acp);
			aac_set_pkt_reason(softs, acp, CMD_TIMEOUT,
			    STAT_TIMEOUT | STAT_BUS_RESET);
			break;
		case CMD_RESET:
			/* aac support only RESET_ALL */
			AACDB_PRINT(softs, CE_NOTE, "CMD_RESET: acp=0x%p", acp);
			aac_set_pkt_reason(softs, acp, CMD_RESET,
			    STAT_BUS_RESET);
			break;
		case CMD_ABORTED:
			AACDB_PRINT(softs, CE_NOTE, "CMD_ABORTED: acp=0x%p",
			    acp);
			aac_set_pkt_reason(softs, acp, CMD_ABORTED,
			    STAT_ABORTED);
			break;
		}
	}
	aac_end_io(softs, acp);
}

/*
 * Abort all the pending commands of type iocmd or just the command pkt
 * corresponding to pkt
 */
static void
aac_abort_iocmds(struct aac_softstate *softs, int iocmd, struct scsi_pkt *pkt,
    int reason)
{
	struct aac_cmd *ac_arg, *acp;
	int i;

	if (pkt == NULL) {
		ac_arg = NULL;
	} else {
		ac_arg = PKT2AC(pkt);
		iocmd = (ac_arg->flags & AAC_CMD_SYNC) ?
		    AAC_IOCMD_SYNC : AAC_IOCMD_ASYNC;
	}

	/*
	 * a) outstanding commands on the controller
	 * Note: should abort outstanding commands only after one
	 * IOP reset has been done.
	 */
	if (iocmd & AAC_IOCMD_OUTSTANDING) {
		struct aac_cmd *acp;

		for (i = 0; i < AAC_MAX_LD; i++) {
			if (AAC_DEV_IS_VALID(&softs->containers[i].dev))
				softs->containers[i].reset = 1;
		}
		while ((acp = softs->q_busy.q_head) != NULL)
			aac_abort_iocmd(softs, acp, reason);
	}

	/* b) commands in the waiting queues */
	for (i = 0; i < AAC_CMDQ_NUM; i++) {
		if (iocmd & (1 << i)) {
			if (ac_arg) {
				aac_abort_iocmd(softs, ac_arg, reason);
			} else {
				while ((acp = softs->q_wait[i].q_head) != NULL)
					aac_abort_iocmd(softs, acp, reason);
			}
		}
	}
}

/*
 * The draining thread is shared among quiesce threads. It terminates
 * when the adapter is quiesced or stopped by aac_stop_drain().
 */
static void
aac_check_drain(void *arg)
{
	struct aac_softstate *softs = arg;

	mutex_enter(&softs->io_lock);
	if (softs->ndrains) {
		softs->drain_timeid = 0;
		/*
		 * If both ASYNC and SYNC bus throttle are held,
		 * wake up threads only when both are drained out.
		 */
		if ((softs->bus_throttle[AAC_CMDQ_ASYNC] > 0 ||
		    softs->bus_ncmds[AAC_CMDQ_ASYNC] == 0) &&
		    (softs->bus_throttle[AAC_CMDQ_SYNC] > 0 ||
		    softs->bus_ncmds[AAC_CMDQ_SYNC] == 0))
			cv_broadcast(&softs->drain_cv);
		else
			softs->drain_timeid = timeout(aac_check_drain, softs,
			    AAC_QUIESCE_TICK * drv_usectohz(1000000));
	}
	mutex_exit(&softs->io_lock);
}

/*
 * If not draining the outstanding cmds, drain them. Otherwise,
 * only update ndrains.
 */
static void
aac_start_drain(struct aac_softstate *softs)
{
	if (softs->ndrains == 0) {
		ASSERT(softs->drain_timeid == 0);
		softs->drain_timeid = timeout(aac_check_drain, softs,
		    AAC_QUIESCE_TICK * drv_usectohz(1000000));
	}
	softs->ndrains++;
}

/*
 * Stop the draining thread when no other threads use it any longer.
 * Side effect: io_lock may be released in the middle.
 */
static void
aac_stop_drain(struct aac_softstate *softs)
{
	softs->ndrains--;
	if (softs->ndrains == 0) {
		if (softs->drain_timeid != 0) {
			timeout_id_t tid = softs->drain_timeid;

			softs->drain_timeid = 0;
			mutex_exit(&softs->io_lock);
			(void) untimeout(tid);
			mutex_enter(&softs->io_lock);
		}
	}
}

/*
 * The following function comes from Adaptec:
 *
 * Once do an IOP reset, basically the driver have to re-initialize the card
 * as if up from a cold boot, and the driver is responsible for any IO that
 * is outstanding to the adapter at the time of the IOP RESET. And prepare
 * for IOP RESET by making the init code modular with the ability to call it
 * from multiple places.
 */
static int
aac_reset_adapter(struct aac_softstate *softs)
{
	int health;
	uint32_t status;
	int rval = AAC_IOP_RESET_FAILED;

	DBCALLED(softs, 1);

	ASSERT(softs->state & AAC_STATE_RESET);

	ddi_fm_acc_err_clear(softs->pci_mem_handle, DDI_FME_VER0);
	/* Disable interrupt */
	AAC_DISABLE_INTR(softs);

	health = aac_check_adapter_health(softs);
	if (health == -1) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto finish;
	}
	if (health == 0) /* flush drives if possible */
		(void) aac_shutdown(softs);

	/* Execute IOP reset */
	if ((aac_sync_mbcommand(softs, AAC_IOP_RESET, 0, 0, 0, 0,
	    &status)) != AACOK) {
		ddi_acc_handle_t acc;
		struct aac_fib *fibp;
		struct aac_pause_command *pc;

		if ((status & 0xf) == 0xf) {
			uint32_t wait_count;

			/*
			 * Sunrise Lake has dual cores and we must drag the
			 * other core with us to reset simultaneously. There
			 * are 2 bits in the Inbound Reset Control and Status
			 * Register (offset 0x38) of the Sunrise Lake to reset
			 * the chip without clearing out the PCI configuration
			 * info (COMMAND & BARS).
			 */
			PCI_MEM_PUT32(softs, AAC_IRCSR, AAC_IRCSR_CORES_RST);

			/*
			 * We need to wait for 5 seconds before accessing the MU
			 * again 10000 * 100us = 1000,000us = 1000ms = 1s
			 */
			wait_count = 5 * 10000;
			while (wait_count) {
				drv_usecwait(100); /* delay 100 microseconds */
				wait_count--;
			}
		} else {
			if (status == SRB_STATUS_INVALID_REQUEST)
				cmn_err(CE_WARN, "!IOP_RESET not supported");
			else /* probably timeout */
				cmn_err(CE_WARN, "!IOP_RESET failed");

			/* Unwind aac_shutdown() */
			(void) aac_sync_fib_slot_bind(softs, &softs->sync_ac);
			acc = softs->sync_ac.slotp->fib_acc_handle;

			fibp = softs->sync_ac.slotp->fibp;
			pc = (struct aac_pause_command *)&fibp->data[0];

			bzero(pc, sizeof (*pc));
			ddi_put32(acc, &pc->Command, VM_ContainerConfig);
			ddi_put32(acc, &pc->Type, CT_PAUSE_IO);
			ddi_put32(acc, &pc->Timeout, 1);
			ddi_put32(acc, &pc->Min, 1);
			ddi_put32(acc, &pc->NoRescan, 1);

			(void) aac_sync_fib(softs, ContainerCommand,
			    AAC_FIB_SIZEOF(struct aac_pause_command));
			aac_sync_fib_slot_release(softs, &softs->sync_ac);

			if (aac_check_adapter_health(softs) != 0)
				ddi_fm_service_impact(softs->devinfo_p,
				    DDI_SERVICE_LOST);
			else
				/*
				 * IOP reset not supported or IOP not reseted
				 */
				rval = AAC_IOP_RESET_ABNORMAL;
			goto finish;
		}
	}

	/*
	 * Re-read and renegotiate the FIB parameters, as one of the actions
	 * that can result from an IOP reset is the running of a new firmware
	 * image.
	 */
	if (aac_common_attach(softs) != AACOK)
		goto finish;

	rval = AAC_IOP_RESET_SUCCEED;

finish:
	AAC_ENABLE_INTR(softs);
	return (rval);
}

static void
aac_set_throttle(struct aac_softstate *softs, struct aac_device *dvp, int q,
    int throttle)
{
	/*
	 * If the bus is draining/quiesced, no changes to the throttles
	 * are allowed. All throttles should have been set to 0.
	 */
	if ((softs->state & AAC_STATE_QUIESCED) || softs->ndrains)
		return;
	dvp->throttle[q] = throttle;
}

static void
aac_hold_bus(struct aac_softstate *softs, int iocmds)
{
	int i, q;

	/* Hold bus by holding every device on the bus */
	for (q = 0; q < AAC_CMDQ_NUM; q++) {
		if (iocmds & (1 << q)) {
			softs->bus_throttle[q] = 0;
			for (i = 0; i < AAC_MAX_LD; i++)
				aac_set_throttle(softs,
				    &softs->containers[i].dev, q, 0);
			for (i = 0; i < AAC_MAX_PD(softs); i++)
				aac_set_throttle(softs,
				    &softs->nondasds[i].dev, q, 0);
		}
	}
}

static void
aac_unhold_bus(struct aac_softstate *softs, int iocmds)
{
	int i, q, max_throttle;

	for (q = 0; q < AAC_CMDQ_NUM; q++) {
		if (iocmds & (1 << q)) {
			/*
			 * Should not unhold AAC_IOCMD_ASYNC bus, if it has been
			 * quiesced or being drained by possibly some quiesce
			 * threads.
			 */
			if (q == AAC_CMDQ_ASYNC && ((softs->state &
			    AAC_STATE_QUIESCED) || softs->ndrains))
				continue;
			if (q == AAC_CMDQ_ASYNC)
				max_throttle = softs->total_slots -
				    AAC_MGT_SLOT_NUM;
			else
				max_throttle = softs->total_slots - 1;
			softs->bus_throttle[q] = max_throttle;
			for (i = 0; i < AAC_MAX_LD; i++)
				aac_set_throttle(softs,
				    &softs->containers[i].dev,
				    q, max_throttle);
			for (i = 0; i < AAC_MAX_PD(softs); i++)
				aac_set_throttle(softs, &softs->nondasds[i].dev,
				    q, max_throttle);
		}
	}
}

static int
aac_do_reset(struct aac_softstate *softs)
{
	int health;
	int rval;

	softs->state |= AAC_STATE_RESET;
	health = aac_check_adapter_health(softs);

	/*
	 * Hold off new io commands and wait all outstanding io
	 * commands to complete.
	 */
	if (health == 0) {
		int sync_cmds = softs->bus_ncmds[AAC_CMDQ_SYNC];
		int async_cmds = softs->bus_ncmds[AAC_CMDQ_ASYNC];

		if (sync_cmds == 0 && async_cmds == 0) {
			rval = AAC_IOP_RESET_SUCCEED;
			goto finish;
		}
		/*
		 * Give the adapter up to AAC_QUIESCE_TIMEOUT more seconds
		 * to complete the outstanding io commands
		 */
		int timeout = AAC_QUIESCE_TIMEOUT * 1000 * 10;
		int (*intr_handler)(struct aac_softstate *);

		aac_hold_bus(softs, AAC_IOCMD_SYNC | AAC_IOCMD_ASYNC);
		/*
		 * Poll the adapter by ourselves in case interrupt is disabled
		 * and to avoid releasing the io_lock.
		 */
		intr_handler = (softs->flags & AAC_FLAGS_NEW_COMM) ?
		    aac_process_intr_new : aac_process_intr_old;
		while ((softs->bus_ncmds[AAC_CMDQ_SYNC] ||
		    softs->bus_ncmds[AAC_CMDQ_ASYNC]) && timeout) {
			drv_usecwait(100);
			(void) intr_handler(softs);
			timeout--;
		}
		aac_unhold_bus(softs, AAC_IOCMD_SYNC | AAC_IOCMD_ASYNC);

		if (softs->bus_ncmds[AAC_CMDQ_SYNC] == 0 &&
		    softs->bus_ncmds[AAC_CMDQ_ASYNC] == 0) {
			/* Cmds drained out */
			rval = AAC_IOP_RESET_SUCCEED;
			goto finish;
		} else if (softs->bus_ncmds[AAC_CMDQ_SYNC] < sync_cmds ||
		    softs->bus_ncmds[AAC_CMDQ_ASYNC] < async_cmds) {
			/* Cmds not drained out, adapter overloaded */
			rval = AAC_IOP_RESET_ABNORMAL;
			goto finish;
		}
	}

	/*
	 * If a longer waiting time still can't drain any outstanding io
	 * commands, do IOP reset.
	 */
	if ((rval = aac_reset_adapter(softs)) == AAC_IOP_RESET_FAILED)
		softs->state |= AAC_STATE_DEAD;

finish:
	softs->state &= ~AAC_STATE_RESET;
	return (rval);
}

static int
aac_tran_reset(struct scsi_address *ap, int level)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	int rval;

	DBCALLED(softs, 1);

	if (level != RESET_ALL) {
		cmn_err(CE_NOTE, "!reset target/lun not supported");
		return (0);
	}

	mutex_enter(&softs->io_lock);
	switch (rval = aac_do_reset(softs)) {
	case AAC_IOP_RESET_SUCCEED:
		aac_abort_iocmds(softs, AAC_IOCMD_OUTSTANDING | AAC_IOCMD_ASYNC,
		    NULL, CMD_RESET);
		aac_start_waiting_io(softs);
		break;
	case AAC_IOP_RESET_FAILED:
		/* Abort IOCTL cmds when adapter is dead */
		aac_abort_iocmds(softs, AAC_IOCMD_ALL, NULL, CMD_RESET);
		break;
	case AAC_IOP_RESET_ABNORMAL:
		aac_start_waiting_io(softs);
	}
	mutex_exit(&softs->io_lock);

	aac_drain_comp_q(softs);
	return (rval == 0);
}

static int
aac_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);

	DBCALLED(softs, 1);

	mutex_enter(&softs->io_lock);
	aac_abort_iocmds(softs, 0, pkt, CMD_ABORTED);
	mutex_exit(&softs->io_lock);

	aac_drain_comp_q(softs);
	return (1);
}

void
aac_free_dmamap(struct aac_cmd *acp)
{
	/* Free dma mapping */
	if (acp->flags & AAC_CMD_DMA_VALID) {
		ASSERT(acp->buf_dma_handle);
		(void) ddi_dma_unbind_handle(acp->buf_dma_handle);
		acp->flags &= ~AAC_CMD_DMA_VALID;
	}

	if (acp->abp != NULL) { /* free non-aligned buf DMA */
		ASSERT(acp->buf_dma_handle);
		if ((acp->flags & AAC_CMD_BUF_WRITE) == 0 && acp->bp)
			ddi_rep_get8(acp->abh, (uint8_t *)acp->bp->b_un.b_addr,
			    (uint8_t *)acp->abp, acp->bp->b_bcount,
			    DDI_DEV_AUTOINCR);
		ddi_dma_mem_free(&acp->abh);
		acp->abp = NULL;
	}

	if (acp->buf_dma_handle) {
		ddi_dma_free_handle(&acp->buf_dma_handle);
		acp->buf_dma_handle = NULL;
	}
}

static void
aac_unknown_scmd(struct aac_softstate *softs, struct aac_cmd *acp)
{
	AACDB_PRINT(softs, CE_CONT, "SCMD 0x%x not supported",
	    ((union scsi_cdb *)(void *)acp->pkt->pkt_cdbp)->scc_cmd);
	aac_free_dmamap(acp);
	aac_set_arq_data(acp->pkt, KEY_ILLEGAL_REQUEST, 0x20, 0x00, 0);
	aac_soft_callback(softs, acp);
}

/*
 * Handle command to logical device
 */
static int
aac_tran_start_ld(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_container *dvp;
	struct scsi_pkt *pkt;
	union scsi_cdb *cdbp;
	struct buf *bp;
	int rval;

	dvp = (struct aac_container *)acp->dvp;
	pkt = acp->pkt;
	cdbp = (void *)pkt->pkt_cdbp;
	bp = acp->bp;

	switch (cdbp->scc_cmd) {
	case SCMD_INQUIRY: /* inquiry */
		aac_free_dmamap(acp);
		aac_inquiry(softs, pkt, cdbp, bp);
		aac_soft_callback(softs, acp);
		rval = TRAN_ACCEPT;
		break;

	case SCMD_READ_CAPACITY: /* read capacity */
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			struct scsi_capacity cap;
			uint64_t last_lba;

			/* check 64-bit LBA */
			last_lba = dvp->size - 1;
			if (last_lba > 0xffffffffull) {
				cap.capacity = 0xfffffffful;
			} else {
				cap.capacity = BE_32(last_lba);
			}
			cap.lbasize = BE_32(AAC_SECTOR_SIZE);

			aac_free_dmamap(acp);
			if (bp->b_flags & (B_PHYS|B_PAGEIO))
				bp_mapin(bp);
			bcopy(&cap, bp->b_un.b_addr, min(bp->b_bcount, 8));
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		aac_soft_callback(softs, acp);
		rval = TRAN_ACCEPT;
		break;

	case SCMD_SVC_ACTION_IN_G4: /* read capacity 16 */
		/* Check if containers need 64-bit LBA support */
		if (cdbp->cdb_opaque[1] == SSVC_ACTION_READ_CAPACITY_G4) {
			if (bp && bp->b_un.b_addr && bp->b_bcount) {
				struct scsi_capacity_16 cap16;
				int cap_len = sizeof (struct scsi_capacity_16);

				bzero(&cap16, cap_len);
				cap16.sc_capacity = BE_64(dvp->size - 1);
				cap16.sc_lbasize = BE_32(AAC_SECTOR_SIZE);

				aac_free_dmamap(acp);
				if (bp->b_flags & (B_PHYS | B_PAGEIO))
					bp_mapin(bp);
				bcopy(&cap16, bp->b_un.b_addr,
				    min(bp->b_bcount, cap_len));
				pkt->pkt_state |= STATE_XFERRED_DATA;
			}
			aac_soft_callback(softs, acp);
		} else {
			aac_unknown_scmd(softs, acp);
		}
		rval = TRAN_ACCEPT;
		break;

	case SCMD_READ_G4: /* read_16 */
	case SCMD_WRITE_G4: /* write_16 */
		if (softs->flags & AAC_FLAGS_RAW_IO) {
			/* NOTE: GETG4ADDRTL(cdbp) is int32_t */
			acp->blkno = ((uint64_t) \
			    GETG4ADDR(cdbp) << 32) | \
			    (uint32_t)GETG4ADDRTL(cdbp);
			goto do_io;
		}
		AACDB_PRINT(softs, CE_WARN, "64-bit LBA not supported");
		aac_unknown_scmd(softs, acp);
		rval = TRAN_ACCEPT;
		break;

	case SCMD_READ: /* read_6 */
	case SCMD_WRITE: /* write_6 */
		acp->blkno = GETG0ADDR(cdbp);
		goto do_io;

	case SCMD_READ_G5: /* read_12 */
	case SCMD_WRITE_G5: /* write_12 */
		acp->blkno = GETG5ADDR(cdbp);
		goto do_io;

	case SCMD_READ_G1: /* read_10 */
	case SCMD_WRITE_G1: /* write_10 */
		acp->blkno = (uint32_t)GETG1ADDR(cdbp);
do_io:
		if (acp->flags & AAC_CMD_DMA_VALID) {
			uint64_t cnt_size = dvp->size;

			/*
			 * If LBA > array size AND rawio, the
			 * adapter may hang. So check it before
			 * sending.
			 * NOTE: (blkno + blkcnt) may overflow
			 */
			if ((acp->blkno < cnt_size) &&
			    ((acp->blkno + acp->bcount /
			    AAC_BLK_SIZE) <= cnt_size)) {
				rval = aac_do_io(softs, acp);
			} else {
			/*
			 * Request exceeds the capacity of disk,
			 * set error block number to last LBA
			 * + 1.
			 */
				aac_set_arq_data(pkt,
				    KEY_ILLEGAL_REQUEST, 0x21,
				    0x00, cnt_size);
				aac_soft_callback(softs, acp);
				rval = TRAN_ACCEPT;
			}
		} else if (acp->bcount == 0) {
			/* For 0 length IO, just return ok */
			aac_soft_callback(softs, acp);
			rval = TRAN_ACCEPT;
		} else {
			rval = TRAN_BADPKT;
		}
		break;

	case SCMD_MODE_SENSE: /* mode_sense_6 */
	case SCMD_MODE_SENSE_G1: { /* mode_sense_10 */
		int capacity;

		aac_free_dmamap(acp);
		if (dvp->size > 0xffffffffull)
			capacity = 0xfffffffful; /* 64-bit LBA */
		else
			capacity = dvp->size;
		aac_mode_sense(softs, pkt, cdbp, bp, capacity);
		aac_soft_callback(softs, acp);
		rval = TRAN_ACCEPT;
		break;
	}

	case SCMD_START_STOP:
		if (softs->support_opt2 & AAC_SUPPORTED_POWER_MANAGEMENT) {
			acp->aac_cmd_fib = aac_cmd_fib_startstop;
			acp->ac_comp = aac_startstop_complete;
			rval = aac_do_io(softs, acp);
			break;
		}
	/* FALLTHRU */
	case SCMD_TEST_UNIT_READY:
	case SCMD_REQUEST_SENSE:
	case SCMD_FORMAT:
		aac_free_dmamap(acp);
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			if (acp->flags & AAC_CMD_BUF_READ) {
				if (bp->b_flags & (B_PHYS|B_PAGEIO))
					bp_mapin(bp);
				bzero(bp->b_un.b_addr, bp->b_bcount);
			}
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		aac_soft_callback(softs, acp);
		rval = TRAN_ACCEPT;
		break;

	case SCMD_SYNCHRONIZE_CACHE:
		acp->flags |= AAC_CMD_NTAG;
		acp->aac_cmd_fib = aac_cmd_fib_sync;
		acp->ac_comp = aac_synccache_complete;
		rval = aac_do_io(softs, acp);
		break;

	case SCMD_DOORLOCK:
		aac_free_dmamap(acp);
		dvp->locked = (pkt->pkt_cdbp[4] & 0x01) ? 1 : 0;
		aac_soft_callback(softs, acp);
		rval = TRAN_ACCEPT;
		break;

	default: /* unknown command */
		aac_unknown_scmd(softs, acp);
		rval = TRAN_ACCEPT;
		break;
	}

	return (rval);
}

static int
aac_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	struct aac_cmd *acp = PKT2AC(pkt);
	struct aac_device *dvp = acp->dvp;
	int rval;

	DBCALLED(softs, 2);

	/*
	 * Reinitialize some fields of ac and pkt; the packet may
	 * have been resubmitted
	 */
	acp->flags &= AAC_CMD_CONSISTENT | AAC_CMD_DMA_PARTIAL | \
	    AAC_CMD_BUF_READ | AAC_CMD_BUF_WRITE | AAC_CMD_DMA_VALID;
	acp->timeout = acp->pkt->pkt_time;
	if (pkt->pkt_flags & FLAG_NOINTR)
		acp->flags |= AAC_CMD_NO_INTR;
#ifdef DEBUG
	acp->fib_flags = AACDB_FLAGS_FIB_SCMD;
#endif
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;
	*pkt->pkt_scbp = STATUS_GOOD; /* clear arq scsi_status */

	if (acp->flags & AAC_CMD_DMA_VALID) {
		pkt->pkt_resid = acp->bcount;
		/* Consistent packets need to be sync'ed first */
		if ((acp->flags & AAC_CMD_CONSISTENT) &&
		    (acp->flags & AAC_CMD_BUF_WRITE))
			if (aac_dma_sync_ac(acp) != AACOK) {
				ddi_fm_service_impact(softs->devinfo_p,
				    DDI_SERVICE_UNAFFECTED);
				return (TRAN_BADPKT);
			}
	} else {
		pkt->pkt_resid = 0;
	}

	mutex_enter(&softs->io_lock);
	AACDB_PRINT_SCMD(softs, acp);
	if ((dvp->flags & (AAC_DFLAG_VALID | AAC_DFLAG_CONFIGURING)) &&
	    !(softs->state & AAC_STATE_DEAD)) {
		if (dvp->type == AAC_DEV_LD) {
			if (ap->a_lun == 0)
				rval = aac_tran_start_ld(softs, acp);
			else
				goto error;
		} else {
			rval = aac_do_io(softs, acp);
		}
	} else {
error:
#ifdef DEBUG
		if (!(softs->state & AAC_STATE_DEAD)) {
			AACDB_PRINT_TRAN(softs,
			    "Cannot send cmd to target t%dL%d: %s",
			    ap->a_target, ap->a_lun,
			    "target invalid");
		} else {
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot send cmd to target t%dL%d: %s",
			    ap->a_target, ap->a_lun,
			    "adapter dead");
		}
#endif
		rval = TRAN_FATAL_ERROR;
	}
	mutex_exit(&softs->io_lock);
	return (rval);
}

static int
aac_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	struct aac_device *dvp;
	int rval;

	DBCALLED(softs, 2);

	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT(softs, CE_WARN,
		    "GetCap> %s not supported: whom=%d", cap, whom);
		return (-1);
	}

	mutex_enter(&softs->io_lock);
	dvp = AAC_DEV(softs, ap->a_target);
	if (dvp == NULL || !AAC_DEV_IS_VALID(dvp)) {
		mutex_exit(&softs->io_lock);
		AACDB_PRINT_TRAN(softs, "Bad target t%dL%d to getcap",
		    ap->a_target, ap->a_lun);
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ: /* auto request sense */
		rval = 1;
		break;
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		rval = 1;
		break;
	case SCSI_CAP_DMA_MAX:
		rval = softs->dma_max;
		break;
	default:
		rval = -1;
		break;
	}
	mutex_exit(&softs->io_lock);

	AACDB_PRINT_TRAN(softs, "GetCap> %s t%dL%d: rval=%d",
	    cap, ap->a_target, ap->a_lun, rval);
	return (rval);
}

/*ARGSUSED*/
static int
aac_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	struct aac_device *dvp;
	int rval;

	DBCALLED(softs, 2);

	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT(softs, CE_WARN,
		    "SetCap> %s not supported: whom=%d", cap, whom);
		return (-1);
	}

	mutex_enter(&softs->io_lock);
	dvp = AAC_DEV(softs, ap->a_target);
	if (dvp == NULL || !AAC_DEV_IS_VALID(dvp)) {
		mutex_exit(&softs->io_lock);
		AACDB_PRINT_TRAN(softs, "Bad target t%dL%d to setcap",
		    ap->a_target, ap->a_lun);
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		/* Force auto request sense */
		rval = (value == 1) ? 1 : 0;
		break;
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		rval = (value == 1) ? 1 : 0;
		break;
	default:
		rval = -1;
		break;
	}
	mutex_exit(&softs->io_lock);

	AACDB_PRINT_TRAN(softs, "SetCap> %s t%dL%d val=%d: rval=%d",
	    cap, ap->a_target, ap->a_lun, value, rval);
	return (rval);
}

static void
aac_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_cmd *acp = PKT2AC(pkt);

	DBCALLED(NULL, 2);

	if (acp->sgt) {
		kmem_free(acp->sgt, sizeof (struct aac_sge) * \
		    acp->left_cookien);
	}
	aac_free_dmamap(acp);
	ASSERT(acp->slotp == NULL);
	scsi_hba_pkt_free(ap, pkt);
}

int
aac_cmd_dma_alloc(struct aac_softstate *softs, struct aac_cmd *acp,
    struct buf *bp, int flags, int (*cb)(), caddr_t arg)
{
	int kf = (cb == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP;
	uint_t oldcookiec;
	int bioerr;
	int rval;

	oldcookiec = acp->left_cookien;

	/* Move window to build s/g map */
	if (acp->total_nwin > 0) {
		if (++acp->cur_win < acp->total_nwin) {
			off_t off;
			size_t len;

			rval = ddi_dma_getwin(acp->buf_dma_handle, acp->cur_win,
			    &off, &len, &acp->cookie, &acp->left_cookien);
			if (rval == DDI_SUCCESS)
				goto get_dma_cookies;
			AACDB_PRINT(softs, CE_WARN,
			    "ddi_dma_getwin() fail %d", rval);
			return (AACERR);
		}
		AACDB_PRINT(softs, CE_WARN, "Nothing to transfer");
		return (AACERR);
	}

	/* We need to transfer data, so we alloc DMA resources for this pkt */
	if (bp && bp->b_bcount != 0 && !(acp->flags & AAC_CMD_DMA_VALID)) {
		uint_t dma_flags = 0;
		struct aac_sge *sge;

		/*
		 * We will still use this point to fake some
		 * infomation in tran_start
		 */
		acp->bp = bp;

		/* Set dma flags */
		if (BUF_IS_READ(bp)) {
			dma_flags |= DDI_DMA_READ;
			acp->flags |= AAC_CMD_BUF_READ;
		} else {
			dma_flags |= DDI_DMA_WRITE;
			acp->flags |= AAC_CMD_BUF_WRITE;
		}
		if (flags & PKT_CONSISTENT)
			dma_flags |= DDI_DMA_CONSISTENT;
		if (flags & PKT_DMA_PARTIAL)
			dma_flags |= DDI_DMA_PARTIAL;

		/* Alloc buf dma handle */
		if (!acp->buf_dma_handle) {
			rval = ddi_dma_alloc_handle(softs->devinfo_p,
			    &softs->buf_dma_attr, cb, arg,
			    &acp->buf_dma_handle);
			if (rval != DDI_SUCCESS) {
				AACDB_PRINT(softs, CE_WARN,
				    "Can't allocate DMA handle, errno=%d",
				    rval);
				goto error_out;
			}
		}

		/* Bind buf */
		if (((uintptr_t)bp->b_un.b_addr & AAC_DMA_ALIGN_MASK) == 0) {
			rval = ddi_dma_buf_bind_handle(acp->buf_dma_handle,
			    bp, dma_flags, cb, arg, &acp->cookie,
			    &acp->left_cookien);
		} else {
			size_t bufsz;

			AACDB_PRINT_TRAN(softs,
			    "non-aligned buffer: addr=0x%p, cnt=%lu",
			    (void *)bp->b_un.b_addr, bp->b_bcount);
			if (bp->b_flags & (B_PAGEIO|B_PHYS))
				bp_mapin(bp);

			rval = ddi_dma_mem_alloc(acp->buf_dma_handle,
			    AAC_ROUNDUP(bp->b_bcount, AAC_DMA_ALIGN),
			    &softs->acc_attr, DDI_DMA_STREAMING,
			    cb, arg, &acp->abp, &bufsz, &acp->abh);

			if (rval != DDI_SUCCESS) {
				AACDB_PRINT(softs, CE_NOTE,
				    "Cannot alloc DMA to non-aligned buf");
				bioerr = 0;
				goto error_out;
			}

			if (acp->flags & AAC_CMD_BUF_WRITE)
				ddi_rep_put8(acp->abh,
				    (uint8_t *)bp->b_un.b_addr,
				    (uint8_t *)acp->abp, bp->b_bcount,
				    DDI_DEV_AUTOINCR);

			rval = ddi_dma_addr_bind_handle(acp->buf_dma_handle,
			    NULL, acp->abp, bufsz, dma_flags, cb, arg,
			    &acp->cookie, &acp->left_cookien);
		}

		switch (rval) {
		case DDI_DMA_PARTIAL_MAP:
			if (ddi_dma_numwin(acp->buf_dma_handle,
			    &acp->total_nwin) == DDI_FAILURE) {
				AACDB_PRINT(softs, CE_WARN,
				    "Cannot get number of DMA windows");
				bioerr = 0;
				goto error_out;
			}
			AACDB_PRINT_TRAN(softs, "buf bind, %d seg(s)",
			    acp->left_cookien);
			acp->cur_win = 0;
			break;

		case DDI_DMA_MAPPED:
			AACDB_PRINT_TRAN(softs, "buf bind, %d seg(s)",
			    acp->left_cookien);
			acp->cur_win = 0;
			acp->total_nwin = 1;
			break;

		case DDI_DMA_NORESOURCES:
			bioerr = 0;
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot bind buf for DMA: DDI_DMA_NORESOURCES");
			goto error_out;
		case DDI_DMA_BADATTR:
		case DDI_DMA_NOMAPPING:
			bioerr = EFAULT;
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot bind buf for DMA: DDI_DMA_NOMAPPING");
			goto error_out;
		case DDI_DMA_TOOBIG:
			bioerr = EINVAL;
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot bind buf for DMA: DDI_DMA_TOOBIG(%d)",
			    bp->b_bcount);
			goto error_out;
		default:
			bioerr = EINVAL;
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot bind buf for DMA: %d", rval);
			goto error_out;
		}
		acp->flags |= AAC_CMD_DMA_VALID;

get_dma_cookies:
		ASSERT(acp->left_cookien > 0);
		if (acp->left_cookien > softs->aac_sg_tablesize) {
			AACDB_PRINT(softs, CE_NOTE, "large cookiec received %d",
			    acp->left_cookien);
			bioerr = EINVAL;
			goto error_out;
		}
		if (oldcookiec != acp->left_cookien && acp->sgt != NULL) {
			kmem_free(acp->sgt, sizeof (struct aac_sge) * \
			    oldcookiec);
			acp->sgt = NULL;
		}
		if (acp->sgt == NULL) {
			acp->sgt = kmem_alloc(sizeof (struct aac_sge) * \
			    acp->left_cookien, kf);
			if (acp->sgt == NULL) {
				AACDB_PRINT(softs, CE_WARN,
				    "sgt kmem_alloc fail");
				bioerr = ENOMEM;
				goto error_out;
			}
		}

		sge = &acp->sgt[0];
		sge->bcount = acp->cookie.dmac_size;
		sge->addr.ad64.lo = AAC_LS32(acp->cookie.dmac_laddress);
		sge->addr.ad64.hi = AAC_MS32(acp->cookie.dmac_laddress);
		acp->bcount = acp->cookie.dmac_size;
		for (sge++; sge < &acp->sgt[acp->left_cookien]; sge++) {
			ddi_dma_nextcookie(acp->buf_dma_handle, &acp->cookie);
			sge->bcount = acp->cookie.dmac_size;
			sge->addr.ad64.lo = AAC_LS32(acp->cookie.dmac_laddress);
			sge->addr.ad64.hi = AAC_MS32(acp->cookie.dmac_laddress);
			acp->bcount += acp->cookie.dmac_size;
		}

		/*
		 * Note: The old DMA engine do not correctly handle
		 * dma_attr_maxxfer attribute. So we have to ensure
		 * it by ourself.
		 */
		if (acp->bcount > softs->buf_dma_attr.dma_attr_maxxfer) {
			AACDB_PRINT(softs, CE_NOTE,
			    "large xfer size received %d\n", acp->bcount);
			bioerr = EINVAL;
			goto error_out;
		}

		acp->total_xfer += acp->bcount;

		if (acp->pkt) {
			/* Return remaining byte count */
			if (acp->total_xfer <= bp->b_bcount) {
				acp->pkt->pkt_resid = bp->b_bcount - \
				    acp->total_xfer;
			} else {
				/*
				 * Allocated DMA size is greater than the buf
				 * size of bp. This is caused by devices like
				 * tape. we have extra bytes allocated, but
				 * the packet residual has to stay correct.
				 */
				acp->pkt->pkt_resid = 0;
			}
			AACDB_PRINT_TRAN(softs,
			    "bp=0x%p, xfered=%d/%d, resid=%d",
			    (void *)bp->b_un.b_addr, (int)acp->total_xfer,
			    (int)bp->b_bcount, (int)acp->pkt->pkt_resid);
		}
	}
	return (AACOK);

error_out:
	bioerror(bp, bioerr);
	return (AACERR);
}

static struct scsi_pkt *
aac_tran_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback)(), caddr_t arg)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	struct aac_cmd *acp, *new_acp;

	DBCALLED(softs, 2);

	/* Allocate pkt */
	if (pkt == NULL) {
		int slen;

		/* Force auto request sense */
		slen = (statuslen > softs->slen) ? statuslen : softs->slen;
		pkt = scsi_hba_pkt_alloc(softs->devinfo_p, ap, cmdlen,
		    slen, tgtlen, sizeof (struct aac_cmd), callback, arg);
		if (pkt == NULL) {
			AACDB_PRINT(softs, CE_WARN, "Alloc scsi pkt failed");
			return (NULL);
		}
		acp = new_acp = PKT2AC(pkt);
		acp->pkt = pkt;
		acp->cmdlen = cmdlen;

		if (ap->a_target < AAC_MAX_LD) {
			acp->dvp = &softs->containers[ap->a_target].dev;
			acp->aac_cmd_fib = softs->aac_cmd_fib;
			acp->ac_comp = aac_ld_complete;
		} else {
			_NOTE(ASSUMING_PROTECTED(softs->nondasds))

			acp->dvp = &softs->nondasds[AAC_PD(ap->a_target)].dev;
			acp->aac_cmd_fib = softs->aac_cmd_fib_scsi;
			acp->ac_comp = aac_pd_complete;
		}
	} else {
		acp = PKT2AC(pkt);
		new_acp = NULL;
	}

	if (aac_cmd_dma_alloc(softs, acp, bp, flags, callback, arg) == AACOK)
		return (pkt);

	if (new_acp)
		aac_tran_destroy_pkt(ap, pkt);
	return (NULL);
}

/*
 * tran_sync_pkt(9E) - explicit DMA synchronization
 */
/*ARGSUSED*/
static void
aac_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_cmd *acp = PKT2AC(pkt);

	DBCALLED(NULL, 2);

	if (aac_dma_sync_ac(acp) != AACOK)
		ddi_fm_service_impact(
		    (AAC_TRAN2SOFTS(ap->a_hba_tran))->devinfo_p,
		    DDI_SERVICE_UNAFFECTED);
}

/*
 * tran_dmafree(9E) - deallocate DMA resources allocated for command
 */
/*ARGSUSED*/
static void
aac_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_cmd *acp = PKT2AC(pkt);

	DBCALLED(NULL, 2);

	aac_free_dmamap(acp);
}

static int
aac_do_quiesce(struct aac_softstate *softs)
{
	aac_hold_bus(softs, AAC_IOCMD_ASYNC);
	if (softs->bus_ncmds[AAC_CMDQ_ASYNC]) {
		aac_start_drain(softs);
		do {
			if (cv_wait_sig(&softs->drain_cv,
			    &softs->io_lock) == 0) {
				/* Quiesce has been interrupted */
				aac_stop_drain(softs);
				aac_unhold_bus(softs, AAC_IOCMD_ASYNC);
				aac_start_waiting_io(softs);
				return (AACERR);
			}
		} while (softs->bus_ncmds[AAC_CMDQ_ASYNC]);
		aac_stop_drain(softs);
	}

	softs->state |= AAC_STATE_QUIESCED;
	return (AACOK);
}

static int
aac_tran_quiesce(dev_info_t *dip)
{
	struct aac_softstate *softs = AAC_DIP2SOFTS(dip);
	int rval;

	DBCALLED(softs, 1);

	mutex_enter(&softs->io_lock);
	if (aac_do_quiesce(softs) == AACOK)
		rval = 0;
	else
		rval = 1;
	mutex_exit(&softs->io_lock);
	return (rval);
}

static int
aac_do_unquiesce(struct aac_softstate *softs)
{
	softs->state &= ~AAC_STATE_QUIESCED;
	aac_unhold_bus(softs, AAC_IOCMD_ASYNC);

	aac_start_waiting_io(softs);
	return (AACOK);
}

static int
aac_tran_unquiesce(dev_info_t *dip)
{
	struct aac_softstate *softs = AAC_DIP2SOFTS(dip);
	int rval;

	DBCALLED(softs, 1);

	mutex_enter(&softs->io_lock);
	if (aac_do_unquiesce(softs) == AACOK)
		rval = 0;
	else
		rval = 1;
	mutex_exit(&softs->io_lock);
	return (rval);
}

static int
aac_hba_setup(struct aac_softstate *softs)
{
	scsi_hba_tran_t *hba_tran;
	int rval;

	hba_tran = scsi_hba_tran_alloc(softs->devinfo_p, SCSI_HBA_CANSLEEP);
	if (hba_tran == NULL)
		return (AACERR);
	hba_tran->tran_hba_private = softs;
	hba_tran->tran_tgt_init = aac_tran_tgt_init;
	hba_tran->tran_tgt_free = aac_tran_tgt_free;
	hba_tran->tran_tgt_probe = scsi_hba_probe;
	hba_tran->tran_start = aac_tran_start;
	hba_tran->tran_getcap = aac_tran_getcap;
	hba_tran->tran_setcap = aac_tran_setcap;
	hba_tran->tran_init_pkt = aac_tran_init_pkt;
	hba_tran->tran_destroy_pkt = aac_tran_destroy_pkt;
	hba_tran->tran_reset = aac_tran_reset;
	hba_tran->tran_abort = aac_tran_abort;
	hba_tran->tran_sync_pkt = aac_tran_sync_pkt;
	hba_tran->tran_dmafree = aac_tran_dmafree;
	hba_tran->tran_quiesce = aac_tran_quiesce;
	hba_tran->tran_unquiesce = aac_tran_unquiesce;
	hba_tran->tran_bus_config = aac_tran_bus_config;
	rval = scsi_hba_attach_setup(softs->devinfo_p, &softs->buf_dma_attr,
	    hba_tran, 0);
	if (rval != DDI_SUCCESS) {
		scsi_hba_tran_free(hba_tran);
		AACDB_PRINT(softs, CE_WARN, "aac_hba_setup failed");
		return (AACERR);
	}

	softs->hba_tran = hba_tran;
	return (AACOK);
}

/*
 * FIB setup operations
 */

/*
 * Init FIB header
 */
static void
aac_cmd_fib_header(struct aac_softstate *softs, struct aac_cmd *acp,
    uint16_t cmd)
{
	struct aac_slot *slotp = acp->slotp;
	ddi_acc_handle_t acc = slotp->fib_acc_handle;
	struct aac_fib *fibp = slotp->fibp;
	uint32_t xfer_state;

	xfer_state =
	    AAC_FIBSTATE_HOSTOWNED |
	    AAC_FIBSTATE_INITIALISED |
	    AAC_FIBSTATE_EMPTY |
	    AAC_FIBSTATE_FAST_RESPONSE | /* enable fast io */
	    AAC_FIBSTATE_FROMHOST |
	    AAC_FIBSTATE_REXPECTED |
	    AAC_FIBSTATE_NORM;

	if (!(acp->flags & AAC_CMD_SYNC))
		xfer_state |= AAC_FIBSTATE_ASYNC;

	ddi_put32(acc, &fibp->Header.XferState, xfer_state);
	ddi_put16(acc, &fibp->Header.Command, cmd);
	ddi_put8(acc, &fibp->Header.StructType, AAC_FIBTYPE_TFIB);
	ddi_put8(acc, &fibp->Header.Flags, 0); /* don't care */
	ddi_put16(acc, &fibp->Header.Size, acp->fib_size);
	ddi_put16(acc, &fibp->Header.SenderSize, softs->aac_max_fib_size);
	ddi_put32(acc, &fibp->Header.SenderFibAddress, (slotp->index << 2));
	ddi_put32(acc, &fibp->Header.ReceiverFibAddress, slotp->fib_phyaddr);
	ddi_put32(acc, &fibp->Header.SenderData, 0); /* don't care */
}

/*
 * Init FIB for raw IO command
 */
static void
aac_cmd_fib_rawio(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_raw_io *io = (struct aac_raw_io *)&acp->slotp->fibp->data[0];
	struct aac_sg_entryraw *sgp;
	struct aac_sge *sge;

	/* Calculate FIB size */
	acp->fib_size = sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_raw_io) + (acp->left_cookien - 1) * \
	    sizeof (struct aac_sg_entryraw);

	aac_cmd_fib_header(softs, acp, RawIo);

	ddi_put16(acc, &io->Flags, (acp->flags & AAC_CMD_BUF_READ) ? 1 : 0);
	ddi_put16(acc, &io->BpTotal, 0);
	ddi_put16(acc, &io->BpComplete, 0);

	ddi_put32(acc, AAC_LO32(&io->BlockNumber), AAC_LS32(acp->blkno));
	ddi_put32(acc, AAC_HI32(&io->BlockNumber), AAC_MS32(acp->blkno));
	ddi_put16(acc, &io->ContainerId,
	    ((struct aac_container *)acp->dvp)->cid);

	/* Fill SG table */
	ddi_put32(acc, &io->SgMapRaw.SgCount, acp->left_cookien);
	ddi_put32(acc, &io->ByteCount, acp->bcount);

	for (sge = &acp->sgt[0], sgp = &io->SgMapRaw.SgEntryRaw[0];
	    sge < &acp->sgt[acp->left_cookien]; sge++, sgp++) {
		ddi_put32(acc, AAC_LO32(&sgp->SgAddress), sge->addr.ad64.lo);
		ddi_put32(acc, AAC_HI32(&sgp->SgAddress), sge->addr.ad64.hi);
		ddi_put32(acc, &sgp->SgByteCount, sge->bcount);
		sgp->Next = 0;
		sgp->Prev = 0;
		sgp->Flags = 0;
	}
}

/* Init FIB for 64-bit block IO command */
static void
aac_cmd_fib_brw64(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_blockread64 *br = (struct aac_blockread64 *) \
	    &acp->slotp->fibp->data[0];
	struct aac_sg_entry64 *sgp;
	struct aac_sge *sge;

	acp->fib_size = sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_blockread64) + (acp->left_cookien - 1) * \
	    sizeof (struct aac_sg_entry64);

	aac_cmd_fib_header(softs, acp, ContainerCommand64);

	/*
	 * The definitions for aac_blockread64 and aac_blockwrite64
	 * are the same.
	 */
	ddi_put32(acc, &br->BlockNumber, (uint32_t)acp->blkno);
	ddi_put16(acc, &br->ContainerId,
	    ((struct aac_container *)acp->dvp)->cid);
	ddi_put32(acc, &br->Command, (acp->flags & AAC_CMD_BUF_READ) ?
	    VM_CtHostRead64 : VM_CtHostWrite64);
	ddi_put16(acc, &br->Pad, 0);
	ddi_put16(acc, &br->Flags, 0);

	/* Fill SG table */
	ddi_put32(acc, &br->SgMap64.SgCount, acp->left_cookien);
	ddi_put16(acc, &br->SectorCount, acp->bcount / AAC_BLK_SIZE);

	for (sge = &acp->sgt[0], sgp = &br->SgMap64.SgEntry64[0];
	    sge < &acp->sgt[acp->left_cookien]; sge++, sgp++) {
		ddi_put32(acc, AAC_LO32(&sgp->SgAddress), sge->addr.ad64.lo);
		ddi_put32(acc, AAC_HI32(&sgp->SgAddress), sge->addr.ad64.hi);
		ddi_put32(acc, &sgp->SgByteCount, sge->bcount);
	}
}

/* Init FIB for block IO command */
static void
aac_cmd_fib_brw(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_blockread *br = (struct aac_blockread *) \
	    &acp->slotp->fibp->data[0];
	struct aac_sg_entry *sgp;
	struct aac_sge *sge = &acp->sgt[0];

	if (acp->flags & AAC_CMD_BUF_READ) {
		acp->fib_size = sizeof (struct aac_fib_header) + \
		    sizeof (struct aac_blockread) + (acp->left_cookien - 1) * \
		    sizeof (struct aac_sg_entry);

		ddi_put32(acc, &br->Command, VM_CtBlockRead);
		ddi_put32(acc, &br->SgMap.SgCount, acp->left_cookien);
		sgp = &br->SgMap.SgEntry[0];
	} else {
		struct aac_blockwrite *bw = (struct aac_blockwrite *)br;

		acp->fib_size = sizeof (struct aac_fib_header) + \
		    sizeof (struct aac_blockwrite) + (acp->left_cookien - 1) * \
		    sizeof (struct aac_sg_entry);

		ddi_put32(acc, &bw->Command, VM_CtBlockWrite);
		ddi_put32(acc, &bw->Stable, CUNSTABLE);
		ddi_put32(acc, &bw->SgMap.SgCount, acp->left_cookien);
		sgp = &bw->SgMap.SgEntry[0];
	}
	aac_cmd_fib_header(softs, acp, ContainerCommand);

	/*
	 * aac_blockread and aac_blockwrite have the similar
	 * structure head, so use br for bw here
	 */
	ddi_put32(acc, &br->BlockNumber, (uint32_t)acp->blkno);
	ddi_put32(acc, &br->ContainerId,
	    ((struct aac_container *)acp->dvp)->cid);
	ddi_put32(acc, &br->ByteCount, acp->bcount);

	/* Fill SG table */
	for (sge = &acp->sgt[0];
	    sge < &acp->sgt[acp->left_cookien]; sge++, sgp++) {
		ddi_put32(acc, &sgp->SgAddress, sge->addr.ad32);
		ddi_put32(acc, &sgp->SgByteCount, sge->bcount);
	}
}

/*ARGSUSED*/
void
aac_cmd_fib_copy(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp = acp->slotp;
	struct aac_fib *fibp = slotp->fibp;
	ddi_acc_handle_t acc = slotp->fib_acc_handle;

	ddi_rep_put8(acc, (uint8_t *)acp->fibp, (uint8_t *)fibp,
	    acp->fib_size,   /* only copy data of needed length */
	    DDI_DEV_AUTOINCR);
	ddi_put32(acc, &fibp->Header.ReceiverFibAddress, slotp->fib_phyaddr);
	ddi_put32(acc, &fibp->Header.SenderFibAddress, slotp->index << 2);
}

static void
aac_cmd_fib_sync(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_synchronize_command *sync =
	    (struct aac_synchronize_command *)&acp->slotp->fibp->data[0];

	acp->fib_size = AAC_FIB_SIZEOF(struct aac_synchronize_command);

	aac_cmd_fib_header(softs, acp, ContainerCommand);
	ddi_put32(acc, &sync->Command, VM_ContainerConfig);
	ddi_put32(acc, &sync->Type, (uint32_t)CT_FLUSH_CACHE);
	ddi_put32(acc, &sync->Cid, ((struct aac_container *)acp->dvp)->cid);
	ddi_put32(acc, &sync->Count,
	    sizeof (((struct aac_synchronize_reply *)0)->Data));
}

/*
 * Start/Stop unit (Power Management)
 */
static void
aac_cmd_fib_startstop(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_Container *cmd =
	    (struct aac_Container *)&acp->slotp->fibp->data[0];
	union scsi_cdb *cdbp = (void *)acp->pkt->pkt_cdbp;

	acp->fib_size = AAC_FIB_SIZEOF(struct aac_Container);

	aac_cmd_fib_header(softs, acp, ContainerCommand);
	bzero(cmd, sizeof (*cmd) - CT_PACKET_SIZE);
	ddi_put32(acc, &cmd->Command, VM_ContainerConfig);
	ddi_put32(acc, &cmd->CTCommand.command, CT_PM_DRIVER_SUPPORT);
	ddi_put32(acc, &cmd->CTCommand.param[0], cdbp->cdb_opaque[4] & 1 ? \
	    AAC_PM_DRIVERSUP_START_UNIT : AAC_PM_DRIVERSUP_STOP_UNIT);
	ddi_put32(acc, &cmd->CTCommand.param[1],
	    ((struct aac_container *)acp->dvp)->cid);
	ddi_put32(acc, &cmd->CTCommand.param[2], cdbp->cdb_opaque[1] & 1);
}

/*
 * Init FIB for pass-through SCMD
 */
static void
aac_cmd_fib_srb(struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_srb *srb = (struct aac_srb *)&acp->slotp->fibp->data[0];
	uint8_t *cdb;

	ddi_put32(acc, &srb->function, SRBF_ExecuteScsi);
	ddi_put32(acc, &srb->retry_limit, 0);
	ddi_put32(acc, &srb->cdb_size, acp->cmdlen);
	ddi_put32(acc, &srb->timeout, 0); /* use driver timeout */
	if (acp->fibp == NULL) {
		if (acp->flags & AAC_CMD_BUF_READ)
			ddi_put32(acc, &srb->flags, SRB_DataIn);
		else if (acp->flags & AAC_CMD_BUF_WRITE)
			ddi_put32(acc, &srb->flags, SRB_DataOut);
		ddi_put32(acc, &srb->channel,
		    ((struct aac_nondasd *)acp->dvp)->bus);
		ddi_put32(acc, &srb->id, ((struct aac_nondasd *)acp->dvp)->tid);
		ddi_put32(acc, &srb->lun, 0);
		cdb = acp->pkt->pkt_cdbp;
	} else {
		struct aac_srb *srb0 = (struct aac_srb *)&acp->fibp->data[0];

		ddi_put32(acc, &srb->flags, srb0->flags);
		ddi_put32(acc, &srb->channel, srb0->channel);
		ddi_put32(acc, &srb->id, srb0->id);
		ddi_put32(acc, &srb->lun, srb0->lun);
		cdb = srb0->cdb;
	}
	ddi_rep_put8(acc, cdb, srb->cdb, acp->cmdlen, DDI_DEV_AUTOINCR);
}

static void
aac_cmd_fib_scsi32(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_srb *srb = (struct aac_srb *)&acp->slotp->fibp->data[0];
	struct aac_sg_entry *sgp;
	struct aac_sge *sge;

	acp->fib_size = sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_srb) - sizeof (struct aac_sg_entry) + \
	    acp->left_cookien * sizeof (struct aac_sg_entry);

	/* Fill FIB and SRB headers, and copy cdb */
	aac_cmd_fib_header(softs, acp, ScsiPortCommand);
	aac_cmd_fib_srb(acp);

	/* Fill SG table */
	ddi_put32(acc, &srb->sg.SgCount, acp->left_cookien);
	ddi_put32(acc, &srb->count, acp->bcount);

	for (sge = &acp->sgt[0], sgp = &srb->sg.SgEntry[0];
	    sge < &acp->sgt[acp->left_cookien]; sge++, sgp++) {
		ddi_put32(acc, &sgp->SgAddress, sge->addr.ad32);
		ddi_put32(acc, &sgp->SgByteCount, sge->bcount);
	}
}

static void
aac_cmd_fib_scsi64(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ddi_acc_handle_t acc = acp->slotp->fib_acc_handle;
	struct aac_srb *srb = (struct aac_srb *)&acp->slotp->fibp->data[0];
	struct aac_sg_entry64 *sgp;
	struct aac_sge *sge;

	acp->fib_size = sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_srb) - sizeof (struct aac_sg_entry) + \
	    acp->left_cookien * sizeof (struct aac_sg_entry64);

	/* Fill FIB and SRB headers, and copy cdb */
	aac_cmd_fib_header(softs, acp, ScsiPortCommandU64);
	aac_cmd_fib_srb(acp);

	/* Fill SG table */
	ddi_put32(acc, &srb->sg.SgCount, acp->left_cookien);
	ddi_put32(acc, &srb->count, acp->bcount);

	for (sge = &acp->sgt[0],
	    sgp = &((struct aac_sg_table64 *)&srb->sg)->SgEntry64[0];
	    sge < &acp->sgt[acp->left_cookien]; sge++, sgp++) {
		ddi_put32(acc, AAC_LO32(&sgp->SgAddress), sge->addr.ad64.lo);
		ddi_put32(acc, AAC_HI32(&sgp->SgAddress), sge->addr.ad64.hi);
		ddi_put32(acc, &sgp->SgByteCount, sge->bcount);
	}
}

static int
aac_cmd_slot_bind(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp;

	if (slotp = aac_get_slot(softs)) {
		acp->slotp = slotp;
		slotp->acp = acp;
		acp->aac_cmd_fib(softs, acp);
		(void) ddi_dma_sync(slotp->fib_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		return (AACOK);
	}
	return (AACERR);
}

static int
aac_bind_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_device *dvp = acp->dvp;
	int q = AAC_CMDQ(acp);

	if (softs->bus_ncmds[q] < softs->bus_throttle[q]) {
		if (dvp) {
			if (dvp->ncmds[q] < dvp->throttle[q]) {
				if (!(acp->flags & AAC_CMD_NTAG) ||
				    dvp->ncmds[q] == 0) {
					return (aac_cmd_slot_bind(softs, acp));
				}
				ASSERT(q == AAC_CMDQ_ASYNC);
				aac_set_throttle(softs, dvp, AAC_CMDQ_ASYNC,
				    AAC_THROTTLE_DRAIN);
			}
		} else {
			return (aac_cmd_slot_bind(softs, acp));
		}
	}
	return (AACERR);
}

static int
aac_sync_fib_slot_bind(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp;

	while (softs->sync_ac.slotp)
		cv_wait(&softs->sync_fib_cv, &softs->io_lock);

	if (slotp = aac_get_slot(softs)) {
		ASSERT(acp->slotp == NULL);

		acp->slotp = slotp;
		slotp->acp = acp;
		return (AACOK);
	}
	return (AACERR);
}

static void
aac_sync_fib_slot_release(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ASSERT(acp->slotp);

	aac_release_slot(softs, acp->slotp);
	acp->slotp->acp = NULL;
	acp->slotp = NULL;

	cv_signal(&softs->sync_fib_cv);
}

static void
aac_start_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp = acp->slotp;
	int q = AAC_CMDQ(acp);
	int rval;

	/* Set ac and pkt */
	if (acp->pkt) { /* ac from ioctl has no pkt */
		acp->pkt->pkt_state |=
		    STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD;
	}
	if (acp->timeout) /* 0 indicates no timeout */
		acp->timeout += aac_timebase + aac_tick;

	if (acp->dvp)
		acp->dvp->ncmds[q]++;
	softs->bus_ncmds[q]++;
	aac_cmd_enqueue(&softs->q_busy, acp);

	AACDB_PRINT_FIB(softs, slotp);

	if (softs->flags & AAC_FLAGS_NEW_COMM) {
		rval = aac_send_command(softs, slotp);
	} else {
		/*
		 * If fib can not be enqueued, the adapter is in an abnormal
		 * state, there will be no interrupt to us.
		 */
		rval = aac_fib_enqueue(softs, AAC_ADAP_NORM_CMD_Q,
		    slotp->fib_phyaddr, acp->fib_size);
	}

	if (aac_check_dma_handle(slotp->fib_dma_handle) != DDI_SUCCESS)
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);

	/*
	 * NOTE: We send command only when slots availabe, so should never
	 * reach here.
	 */
	if (rval != AACOK) {
		AACDB_PRINT(softs, CE_NOTE, "SCMD send failed");
		if (acp->pkt) {
			acp->pkt->pkt_state &= ~STATE_SENT_CMD;
			aac_set_pkt_reason(softs, acp, CMD_INCOMPLETE, 0);
		}
		aac_end_io(softs, acp);
		if (!(acp->flags & (AAC_CMD_NO_INTR | AAC_CMD_NO_CB)))
			ddi_trigger_softintr(softs->softint_id);
	}
}

static void
aac_start_waitq(struct aac_softstate *softs, struct aac_cmd_queue *q)
{
	struct aac_cmd *acp, *next_acp;

	/* Serve as many waiting io's as possible */
	for (acp = q->q_head; acp; acp = next_acp) {
		next_acp = acp->next;
		if (aac_bind_io(softs, acp) == AACOK) {
			aac_cmd_delete(q, acp);
			aac_start_io(softs, acp);
		}
		if (softs->free_io_slot_head == NULL)
			break;
	}
}

static void
aac_start_waiting_io(struct aac_softstate *softs)
{
	/*
	 * Sync FIB io is served before async FIB io so that io requests
	 * sent by interactive userland commands get responded asap.
	 */
	if (softs->q_wait[AAC_CMDQ_SYNC].q_head)
		aac_start_waitq(softs, &softs->q_wait[AAC_CMDQ_SYNC]);
	if (softs->q_wait[AAC_CMDQ_ASYNC].q_head)
		aac_start_waitq(softs, &softs->q_wait[AAC_CMDQ_ASYNC]);
}

static void
aac_drain_comp_q(struct aac_softstate *softs)
{
	struct aac_cmd *acp;
	struct scsi_pkt *pkt;

	/*CONSTCOND*/
	while (1) {
		mutex_enter(&softs->q_comp_mutex);
		acp = aac_cmd_dequeue(&softs->q_comp);
		mutex_exit(&softs->q_comp_mutex);
		if (acp != NULL) {
			ASSERT(acp->pkt != NULL);
			pkt = acp->pkt;

			if (pkt->pkt_reason == CMD_CMPLT) {
				/*
				 * Consistent packets need to be sync'ed first
				 */
				if ((acp->flags & AAC_CMD_CONSISTENT) &&
				    (acp->flags & AAC_CMD_BUF_READ)) {
					if (aac_dma_sync_ac(acp) != AACOK) {
						ddi_fm_service_impact(
						    softs->devinfo_p,
						    DDI_SERVICE_UNAFFECTED);
						pkt->pkt_reason = CMD_TRAN_ERR;
						pkt->pkt_statistics = 0;
					}
				}
				if ((aac_check_acc_handle(softs-> \
				    comm_space_acc_handle) != DDI_SUCCESS) ||
				    (aac_check_acc_handle(softs-> \
				    pci_mem_handle) != DDI_SUCCESS)) {
					ddi_fm_service_impact(softs->devinfo_p,
					    DDI_SERVICE_UNAFFECTED);
					ddi_fm_acc_err_clear(softs-> \
					    pci_mem_handle, DDI_FME_VER0);
					pkt->pkt_reason = CMD_TRAN_ERR;
					pkt->pkt_statistics = 0;
				}
				if (aac_check_dma_handle(softs-> \
				    comm_space_dma_handle) != DDI_SUCCESS) {
					ddi_fm_service_impact(softs->devinfo_p,
					    DDI_SERVICE_UNAFFECTED);
					pkt->pkt_reason = CMD_TRAN_ERR;
					pkt->pkt_statistics = 0;
				}
			}
			scsi_hba_pkt_comp(pkt);
		} else {
			break;
		}
	}
}

static int
aac_alloc_fib(struct aac_softstate *softs, struct aac_slot *slotp)
{
	size_t rlen;
	ddi_dma_cookie_t cookie;
	uint_t cookien;

	/* Allocate FIB dma resource */
	if (ddi_dma_alloc_handle(
	    softs->devinfo_p,
	    &softs->addr_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &slotp->fib_dma_handle) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Cannot alloc dma handle for slot fib area");
		goto error;
	}
	if (ddi_dma_mem_alloc(
	    slotp->fib_dma_handle,
	    softs->aac_max_fib_size,
	    &softs->acc_attr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&slotp->fibp,
	    &rlen,
	    &slotp->fib_acc_handle) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Cannot alloc mem for slot fib area");
		goto error;
	}
	if (ddi_dma_addr_bind_handle(
	    slotp->fib_dma_handle,
	    NULL,
	    (caddr_t)slotp->fibp,
	    softs->aac_max_fib_size,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &cookie,
	    &cookien) != DDI_DMA_MAPPED) {
		AACDB_PRINT(softs, CE_WARN,
		    "dma bind failed for slot fib area");
		goto error;
	}

	/* Check dma handles allocated in fib attach */
	if (aac_check_dma_handle(slotp->fib_dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	/* Check acc handles allocated in fib attach */
	if (aac_check_acc_handle(slotp->fib_acc_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	slotp->fib_phyaddr = cookie.dmac_laddress;
	return (AACOK);

error:
	if (slotp->fib_acc_handle) {
		ddi_dma_mem_free(&slotp->fib_acc_handle);
		slotp->fib_acc_handle = NULL;
	}
	if (slotp->fib_dma_handle) {
		ddi_dma_free_handle(&slotp->fib_dma_handle);
		slotp->fib_dma_handle = NULL;
	}
	return (AACERR);
}

static void
aac_free_fib(struct aac_slot *slotp)
{
	(void) ddi_dma_unbind_handle(slotp->fib_dma_handle);
	ddi_dma_mem_free(&slotp->fib_acc_handle);
	slotp->fib_acc_handle = NULL;
	ddi_dma_free_handle(&slotp->fib_dma_handle);
	slotp->fib_dma_handle = NULL;
	slotp->fib_phyaddr = 0;
}

static void
aac_alloc_fibs(struct aac_softstate *softs)
{
	int i;
	struct aac_slot *slotp;

	for (i = 0; i < softs->total_slots &&
	    softs->total_fibs < softs->total_slots; i++) {
		slotp = &(softs->io_slot[i]);
		if (slotp->fib_phyaddr)
			continue;
		if (aac_alloc_fib(softs, slotp) != AACOK)
			break;

		/* Insert the slot to the free slot list */
		aac_release_slot(softs, slotp);
		softs->total_fibs++;
	}
}

static void
aac_destroy_fibs(struct aac_softstate *softs)
{
	struct aac_slot *slotp;

	while ((slotp = softs->free_io_slot_head) != NULL) {
		ASSERT(slotp->fib_phyaddr);
		softs->free_io_slot_head = slotp->next;
		aac_free_fib(slotp);
		ASSERT(slotp->index == (slotp - softs->io_slot));
		softs->total_fibs--;
	}
	ASSERT(softs->total_fibs == 0);
}

static int
aac_create_slots(struct aac_softstate *softs)
{
	int i;

	softs->total_slots = softs->aac_max_fibs;
	softs->io_slot = kmem_zalloc(sizeof (struct aac_slot) * \
	    softs->total_slots, KM_SLEEP);
	if (softs->io_slot == NULL) {
		AACDB_PRINT(softs, CE_WARN, "Cannot allocate slot");
		return (AACERR);
	}
	for (i = 0; i < softs->total_slots; i++)
		softs->io_slot[i].index = i;
	softs->free_io_slot_head = NULL;
	softs->total_fibs = 0;
	return (AACOK);
}

static void
aac_destroy_slots(struct aac_softstate *softs)
{
	ASSERT(softs->free_io_slot_head == NULL);

	kmem_free(softs->io_slot, sizeof (struct aac_slot) * \
	    softs->total_slots);
	softs->io_slot = NULL;
	softs->total_slots = 0;
}

struct aac_slot *
aac_get_slot(struct aac_softstate *softs)
{
	struct aac_slot *slotp;

	if ((slotp = softs->free_io_slot_head) != NULL) {
		softs->free_io_slot_head = slotp->next;
		slotp->next = NULL;
	}
	return (slotp);
}

static void
aac_release_slot(struct aac_softstate *softs, struct aac_slot *slotp)
{
	ASSERT((slotp->index >= 0) && (slotp->index < softs->total_slots));
	ASSERT(slotp == &softs->io_slot[slotp->index]);

	slotp->acp = NULL;
	slotp->next = softs->free_io_slot_head;
	softs->free_io_slot_head = slotp;
}

int
aac_do_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	if (aac_bind_io(softs, acp) == AACOK)
		aac_start_io(softs, acp);
	else
		aac_cmd_enqueue(&softs->q_wait[AAC_CMDQ(acp)], acp);

	if (!(acp->flags & (AAC_CMD_NO_CB | AAC_CMD_NO_INTR)))
		return (TRAN_ACCEPT);
	/*
	 * Because sync FIB is always 512 bytes and used for critical
	 * functions, async FIB is used for poll IO.
	 */
	if (acp->flags & AAC_CMD_NO_INTR) {
		if (aac_do_poll_io(softs, acp) == AACOK)
			return (TRAN_ACCEPT);
	} else {
		if (aac_do_sync_io(softs, acp) == AACOK)
			return (TRAN_ACCEPT);
	}
	return (TRAN_BADPKT);
}

static int
aac_do_poll_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	int (*intr_handler)(struct aac_softstate *);

	/*
	 * Interrupt is disabled, we have to poll the adapter by ourselves.
	 */
	intr_handler = (softs->flags & AAC_FLAGS_NEW_COMM) ?
	    aac_process_intr_new : aac_process_intr_old;
	while (!(acp->flags & (AAC_CMD_CMPLT | AAC_CMD_ABORT))) {
		int i = AAC_POLL_TIME * 1000;

		AAC_BUSYWAIT((intr_handler(softs) != AAC_DB_RESPONSE_READY), i);
		if (i == 0)
			aac_cmd_timeout(softs, acp);
	}

	ddi_trigger_softintr(softs->softint_id);

	if ((acp->flags & AAC_CMD_CMPLT) && !(acp->flags & AAC_CMD_ERR))
		return (AACOK);
	return (AACERR);
}

static int
aac_do_sync_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	ASSERT(softs && acp);

	while (!(acp->flags & (AAC_CMD_CMPLT | AAC_CMD_ABORT)))
		cv_wait(&softs->event, &softs->io_lock);

	if (acp->flags & AAC_CMD_CMPLT)
		return (AACOK);
	return (AACERR);
}

static int
aac_dma_sync_ac(struct aac_cmd *acp)
{
	if (acp->buf_dma_handle) {
		if (acp->flags & AAC_CMD_BUF_WRITE) {
			if (acp->abp != NULL)
				ddi_rep_put8(acp->abh,
				    (uint8_t *)acp->bp->b_un.b_addr,
				    (uint8_t *)acp->abp, acp->bp->b_bcount,
				    DDI_DEV_AUTOINCR);
			(void) ddi_dma_sync(acp->buf_dma_handle, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			(void) ddi_dma_sync(acp->buf_dma_handle, 0, 0,
			    DDI_DMA_SYNC_FORCPU);
			if (aac_check_dma_handle(acp->buf_dma_handle) !=
			    DDI_SUCCESS)
				return (AACERR);
			if (acp->abp != NULL)
				ddi_rep_get8(acp->abh,
				    (uint8_t *)acp->bp->b_un.b_addr,
				    (uint8_t *)acp->abp, acp->bp->b_bcount,
				    DDI_DEV_AUTOINCR);
		}
	}
	return (AACOK);
}

/*
 * Copy AIF from adapter to the empty AIF slot and inform AIF threads
 */
static void
aac_save_aif(struct aac_softstate *softs, ddi_acc_handle_t acc,
    struct aac_fib *fibp0, int fib_size0)
{
	struct aac_fib *fibp;	/* FIB in AIF queue */
	int fib_size;
	uint16_t fib_command;
	int current, next;

	/* Ignore non AIF messages */
	fib_command = ddi_get16(acc, &fibp0->Header.Command);
	if (fib_command != AifRequest) {
		cmn_err(CE_WARN, "!Unknown command from controller");
		return;
	}

	mutex_enter(&softs->aifq_mutex);

	/* Save AIF */
	fibp = &softs->aifq[softs->aifq_idx].d;
	fib_size = (fib_size0 > AAC_FIB_SIZE) ? AAC_FIB_SIZE : fib_size0;
	ddi_rep_get8(acc, (uint8_t *)fibp, (uint8_t *)fibp0, fib_size,
	    DDI_DEV_AUTOINCR);

	if (aac_check_acc_handle(softs->pci_mem_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p,
		    DDI_SERVICE_UNAFFECTED);
		mutex_exit(&softs->aifq_mutex);
		return;
	}

	AACDB_PRINT_AIF(softs, (struct aac_aif_command *)&fibp->data[0]);

	/* Modify AIF contexts */
	current = softs->aifq_idx;
	next = (current + 1) % AAC_AIFQ_LENGTH;
	if (next == 0) {
		struct aac_fib_context *ctx_p;

		softs->aifq_wrap = 1;
		for (ctx_p = softs->fibctx_p; ctx_p; ctx_p = ctx_p->next) {
			if (next == ctx_p->ctx_idx) {
				ctx_p->ctx_flags |= AAC_CTXFLAG_FILLED;
			} else if (current == ctx_p->ctx_idx &&
			    (ctx_p->ctx_flags & AAC_CTXFLAG_FILLED)) {
				ctx_p->ctx_idx = next;
				ctx_p->ctx_overrun++;
			}
		}
	}
	softs->aifq_idx = next;

	/* Wakeup AIF threads */
	cv_broadcast(&softs->aifq_cv);
	mutex_exit(&softs->aifq_mutex);

	/* Wakeup event thread to handle aif */
	aac_event_disp(softs, AAC_EVENT_AIF);
}

static int
aac_return_aif_common(struct aac_softstate *softs, struct aac_fib_context *ctx,
    struct aac_fib **fibpp)
{
	int current;

	current = ctx->ctx_idx;
	if (current == softs->aifq_idx &&
	    !(ctx->ctx_flags & AAC_CTXFLAG_FILLED))
		return (EAGAIN); /* Empty */

	*fibpp = &softs->aifq[current].d;

	ctx->ctx_flags &= ~AAC_CTXFLAG_FILLED;
	ctx->ctx_idx = (current + 1) % AAC_AIFQ_LENGTH;
	return (0);
}

int
aac_return_aif(struct aac_softstate *softs, struct aac_fib_context *ctx,
    struct aac_fib **fibpp)
{
	int rval;

	mutex_enter(&softs->aifq_mutex);
	rval = aac_return_aif_common(softs, ctx, fibpp);
	mutex_exit(&softs->aifq_mutex);
	return (rval);
}

int
aac_return_aif_wait(struct aac_softstate *softs, struct aac_fib_context *ctx,
    struct aac_fib **fibpp)
{
	int rval;

	mutex_enter(&softs->aifq_mutex);
	rval = aac_return_aif_common(softs, ctx, fibpp);
	if (rval == EAGAIN) {
		AACDB_PRINT(softs, CE_NOTE, "Waiting for AIF");
		rval = cv_wait_sig(&softs->aifq_cv, &softs->aifq_mutex);
	}
	mutex_exit(&softs->aifq_mutex);
	return ((rval > 0) ? 0 : EINTR);
}

/*
 * The following function comes from Adaptec:
 *
 * When driver sees a particular event that means containers are changed, it
 * will rescan containers. However a change may not be complete until some
 * other event is received. For example, creating or deleting an array will
 * incur as many as six AifEnConfigChange events which would generate six
 * container rescans. To diminish rescans, driver set a flag to wait for
 * another particular event. When sees that events come in, it will do rescan.
 */
static int
aac_handle_aif(struct aac_softstate *softs, struct aac_aif_command *aif)
{
	ddi_acc_handle_t acc = softs->comm_space_acc_handle;
	int en_type;
	int devcfg_needed;
	int cid;
	uint32_t bus_id, tgt_id;
	enum aac_cfg_event event = AAC_CFG_NULL_EXIST;

	devcfg_needed = 0;
	en_type = LE_32((uint32_t)aif->data.EN.type);

	switch (LE_32((uint32_t)aif->command)) {
	case AifCmdDriverNotify: {
		cid = LE_32(aif->data.EN.data.ECC.container[0]);

		switch (en_type) {
		case AifDenMorphComplete:
		case AifDenVolumeExtendComplete:
			if (AAC_DEV_IS_VALID(&softs->containers[cid].dev))
				softs->devcfg_wait_on = AifEnConfigChange;
			break;
		}
		if (softs->devcfg_wait_on == en_type)
			devcfg_needed = 1;
		break;
	}

	case AifCmdEventNotify:
		cid = LE_32(aif->data.EN.data.ECC.container[0]);
		switch (en_type) {
		case AifEnAddContainer:
		case AifEnDeleteContainer:
			softs->devcfg_wait_on = AifEnConfigChange;
			break;
		case AifEnContainerChange:
			if (!softs->devcfg_wait_on)
				softs->devcfg_wait_on = AifEnConfigChange;
			break;
		case AifEnContainerEvent:
			if (ddi_get32(acc, &aif-> \
			    data.EN.data.ECE.eventType) == CT_PUP_MISSING_DRIVE)
				devcfg_needed = 1;
			break;
		case AifEnAddJBOD:
			if (!(softs->flags & AAC_FLAGS_JBOD))
				return (AACERR);
			event = AAC_CFG_ADD;
			bus_id = (cid >> 24) & 0xf;
			tgt_id = cid & 0xffff;
			break;
		case AifEnDeleteJBOD:
			if (!(softs->flags & AAC_FLAGS_JBOD))
				return (AACERR);
			event = AAC_CFG_DELETE;
			bus_id = (cid >> 24) & 0xf;
			tgt_id = cid & 0xffff;
			break;
		}
		if (softs->devcfg_wait_on == en_type)
			devcfg_needed = 1;
		break;

	case AifCmdJobProgress:
		if (LE_32((uint32_t)aif->data.PR[0].jd.type) == AifJobCtrZero) {
			int pr_status;
			uint32_t pr_ftick, pr_ctick;

			pr_status = LE_32((uint32_t)aif->data.PR[0].status);
			pr_ctick = LE_32(aif->data.PR[0].currentTick);
			pr_ftick = LE_32(aif->data.PR[0].finalTick);

			if ((pr_ctick == pr_ftick) ||
			    (pr_status == AifJobStsSuccess))
				softs->devcfg_wait_on = AifEnContainerChange;
			else if ((pr_ctick == 0) &&
			    (pr_status == AifJobStsRunning))
				softs->devcfg_wait_on = AifEnContainerChange;
		}
		break;
	}

	if (devcfg_needed) {
		softs->devcfg_wait_on = 0;
		(void) aac_probe_containers(softs);
	}

	if (event != AAC_CFG_NULL_EXIST) {
		ASSERT(en_type == AifEnAddJBOD || en_type == AifEnDeleteJBOD);
		(void) aac_probe_jbod(softs,
		    AAC_P2VTGT(softs, bus_id, tgt_id), event);
	}
	return (AACOK);
}


/*
 * Check and handle AIF events
 */
static void
aac_aif_event(struct aac_softstate *softs)
{
	struct aac_fib *fibp;

	/*CONSTCOND*/
	while (1) {
		if (aac_return_aif(softs, &softs->aifctx, &fibp) != 0)
			break; /* No more AIFs to handle, end loop */

		/* AIF overrun, array create/delete may missed. */
		if (softs->aifctx.ctx_overrun) {
			softs->aifctx.ctx_overrun = 0;
		}

		/* AIF received, handle it */
		struct aac_aif_command *aifp =
		    (struct aac_aif_command *)&fibp->data[0];
		uint32_t aif_command = LE_32((uint32_t)aifp->command);

		if (aif_command == AifCmdDriverNotify ||
		    aif_command == AifCmdEventNotify ||
		    aif_command == AifCmdJobProgress)
			(void) aac_handle_aif(softs, aifp);
	}
}

/*
 * Timeout recovery
 */
/*ARGSUSED*/
static void
aac_cmd_timeout(struct aac_softstate *softs, struct aac_cmd *acp)
{
#ifdef DEBUG
	acp->fib_flags |= AACDB_FLAGS_FIB_TIMEOUT;
	AACDB_PRINT(softs, CE_WARN, "acp %p timed out", acp);
	AACDB_PRINT_FIB(softs, acp->slotp);
#endif

	/*
	 * Besides the firmware in unhealthy state, an overloaded
	 * adapter may also incur pkt timeout.
	 * There is a chance for an adapter with a slower IOP to take
	 * longer than 60 seconds to process the commands, such as when
	 * to perform IOs. So the adapter is doing a build on a RAID-5
	 * while being required longer completion times should be
	 * tolerated.
	 */
	switch (aac_do_reset(softs)) {
	case AAC_IOP_RESET_SUCCEED:
		aac_abort_iocmds(softs, AAC_IOCMD_OUTSTANDING, NULL, CMD_RESET);
		aac_start_waiting_io(softs);
		break;
	case AAC_IOP_RESET_FAILED:
		/* Abort all waiting cmds when adapter is dead */
		aac_abort_iocmds(softs, AAC_IOCMD_ALL, NULL, CMD_TIMEOUT);
		break;
	case AAC_IOP_RESET_ABNORMAL:
		aac_start_waiting_io(softs);
	}
}

/*
 * The following function comes from Adaptec:
 *
 * Time sync. command added to synchronize time with firmware every 30
 * minutes (required for correct AIF timestamps etc.)
 */
static void
aac_sync_tick(struct aac_softstate *softs)
{
	ddi_acc_handle_t acc;
	int rval;

	mutex_enter(&softs->time_mutex);
	ASSERT(softs->time_sync <= softs->timebase);
	softs->time_sync = 0;
	mutex_exit(&softs->time_mutex);

	/* Time sync. with firmware every AAC_SYNC_TICK */
	(void) aac_sync_fib_slot_bind(softs, &softs->sync_ac);
	acc = softs->sync_ac.slotp->fib_acc_handle;

	ddi_put32(acc, (void *)&softs->sync_ac.slotp->fibp->data[0],
	    ddi_get_time());
	rval = aac_sync_fib(softs, SendHostTime, AAC_FIB_SIZEOF(uint32_t));
	aac_sync_fib_slot_release(softs, &softs->sync_ac);

	mutex_enter(&softs->time_mutex);
	softs->time_sync = softs->timebase;
	if (rval != AACOK)
		/* retry shortly */
		softs->time_sync += aac_tick << 1;
	else
		softs->time_sync += AAC_SYNC_TICK;
	mutex_exit(&softs->time_mutex);
}

/*
 * Timeout checking and handling
 */
static void
aac_daemon(struct aac_softstate *softs)
{
	int time_out; /* set if timeout happened */
	int time_adjust;
	uint32_t softs_timebase;

	mutex_enter(&softs->time_mutex);
	ASSERT(softs->time_out <= softs->timebase);
	softs->time_out = 0;
	softs_timebase = softs->timebase;
	mutex_exit(&softs->time_mutex);

	/* Check slots for timeout pkts */
	time_adjust = 0;
	do {
		struct aac_cmd *acp;

		time_out = 0;
		for (acp = softs->q_busy.q_head; acp; acp = acp->next) {
			if (acp->timeout == 0)
				continue;

			/*
			 * If timeout happened, update outstanding cmds
			 * to be checked later again.
			 */
			if (time_adjust) {
				acp->timeout += time_adjust;
				continue;
			}

			if (acp->timeout <= softs_timebase) {
				aac_cmd_timeout(softs, acp);
				time_out = 1;
				time_adjust = aac_tick * drv_usectohz(1000000);
				break; /* timeout happened */
			} else {
				break; /* no timeout */
			}
		}
	} while (time_out);

	mutex_enter(&softs->time_mutex);
	softs->time_out = softs->timebase + aac_tick;
	mutex_exit(&softs->time_mutex);
}

/*
 * The event thread handles various tasks serially for the other parts of
 * the driver, so that they can run fast.
 */
static void
aac_event_thread(struct aac_softstate *softs)
{
	int run = 1;

	DBCALLED(softs, 1);

	mutex_enter(&softs->ev_lock);
	while (run) {
		int events;

		if ((events = softs->events) == 0) {
			cv_wait(&softs->event_disp_cv, &softs->ev_lock);
			events = softs->events;
		}
		softs->events = 0;
		mutex_exit(&softs->ev_lock);

		mutex_enter(&softs->io_lock);
		if ((softs->state & AAC_STATE_RUN) &&
		    (softs->state & AAC_STATE_DEAD) == 0) {
			if (events & AAC_EVENT_TIMEOUT)
				aac_daemon(softs);
			if (events & AAC_EVENT_SYNCTICK)
				aac_sync_tick(softs);
			if (events & AAC_EVENT_AIF)
				aac_aif_event(softs);
		} else {
			run = 0;
		}
		mutex_exit(&softs->io_lock);

		mutex_enter(&softs->ev_lock);
	}

	cv_signal(&softs->event_wait_cv);
	mutex_exit(&softs->ev_lock);
}

/*
 * Internal timer. It is only responsbile for time counting and report time
 * related events. Events handling is done by aac_event_thread(), so that
 * the timer itself could be as precise as possible.
 */
static void
aac_timer(void *arg)
{
	struct aac_softstate *softs = arg;
	int events = 0;

	mutex_enter(&softs->time_mutex);

	/* If timer is being stopped, exit */
	if (softs->timeout_id) {
		softs->timeout_id = timeout(aac_timer, (void *)softs,
		    (aac_tick * drv_usectohz(1000000)));
	} else {
		mutex_exit(&softs->time_mutex);
		return;
	}

	/* Time counting */
	softs->timebase += aac_tick;

	/* Check time related events */
	if (softs->time_out && softs->time_out <= softs->timebase)
		events |= AAC_EVENT_TIMEOUT;
	if (softs->time_sync && softs->time_sync <= softs->timebase)
		events |= AAC_EVENT_SYNCTICK;

	mutex_exit(&softs->time_mutex);

	if (events)
		aac_event_disp(softs, events);
}

/*
 * Dispatch events to daemon thread for handling
 */
static void
aac_event_disp(struct aac_softstate *softs, int events)
{
	mutex_enter(&softs->ev_lock);
	softs->events |= events;
	cv_broadcast(&softs->event_disp_cv);
	mutex_exit(&softs->ev_lock);
}

/*
 * Architecture dependent functions
 */
static int
aac_rx_get_fwstatus(struct aac_softstate *softs)
{
	return (PCI_MEM_GET32(softs, AAC_OMR0));
}

static int
aac_rx_get_mailbox(struct aac_softstate *softs, int mb)
{
	return (PCI_MEM_GET32(softs, AAC_RX_MAILBOX + mb * 4));
}

static void
aac_rx_set_mailbox(struct aac_softstate *softs, uint32_t cmd,
    uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
	PCI_MEM_PUT32(softs, AAC_RX_MAILBOX, cmd);
	PCI_MEM_PUT32(softs, AAC_RX_MAILBOX + 4, arg0);
	PCI_MEM_PUT32(softs, AAC_RX_MAILBOX + 8, arg1);
	PCI_MEM_PUT32(softs, AAC_RX_MAILBOX + 12, arg2);
	PCI_MEM_PUT32(softs, AAC_RX_MAILBOX + 16, arg3);
}

static int
aac_rkt_get_fwstatus(struct aac_softstate *softs)
{
	return (PCI_MEM_GET32(softs, AAC_OMR0));
}

static int
aac_rkt_get_mailbox(struct aac_softstate *softs, int mb)
{
	return (PCI_MEM_GET32(softs, AAC_RKT_MAILBOX + mb *4));
}

static void
aac_rkt_set_mailbox(struct aac_softstate *softs, uint32_t cmd,
    uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
	PCI_MEM_PUT32(softs, AAC_RKT_MAILBOX, cmd);
	PCI_MEM_PUT32(softs, AAC_RKT_MAILBOX + 4, arg0);
	PCI_MEM_PUT32(softs, AAC_RKT_MAILBOX + 8, arg1);
	PCI_MEM_PUT32(softs, AAC_RKT_MAILBOX + 12, arg2);
	PCI_MEM_PUT32(softs, AAC_RKT_MAILBOX + 16, arg3);
}

/*
 * cb_ops functions
 */
static int
aac_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	struct aac_softstate *softs;
	int minor0, minor;
	int instance;

	DBCALLED(NULL, 2);

	if (otyp != OTYP_BLK && otyp != OTYP_CHR)
		return (EINVAL);

	minor0 = getminor(*devp);
	minor = AAC_SCSA_MINOR(minor0);

	if (AAC_IS_SCSA_NODE(minor))
		return (scsi_hba_open(devp, flag, otyp, cred));

	instance = MINOR2INST(minor0);
	if (instance >= AAC_MAX_ADAPTERS)
		return (ENXIO);

	softs = ddi_get_soft_state(aac_softstatep, instance);
	if (softs == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
aac_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	int minor0, minor;
	int instance;

	DBCALLED(NULL, 2);

	if (otyp != OTYP_BLK && otyp != OTYP_CHR)
		return (EINVAL);

	minor0 = getminor(dev);
	minor = AAC_SCSA_MINOR(minor0);

	if (AAC_IS_SCSA_NODE(minor))
		return (scsi_hba_close(dev, flag, otyp, cred));

	instance = MINOR2INST(minor0);
	if (instance >= AAC_MAX_ADAPTERS)
		return (ENXIO);

	return (0);
}

static int
aac_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
    int *rval_p)
{
	struct aac_softstate *softs;
	int minor0, minor;
	int instance;

	DBCALLED(NULL, 2);

	if (drv_priv(cred_p) != 0)
		return (EPERM);

	minor0 = getminor(dev);
	minor = AAC_SCSA_MINOR(minor0);

	if (AAC_IS_SCSA_NODE(minor))
		return (scsi_hba_ioctl(dev, cmd, arg, flag, cred_p, rval_p));

	instance = MINOR2INST(minor0);
	if (instance < AAC_MAX_ADAPTERS) {
		softs = ddi_get_soft_state(aac_softstatep, instance);
		return (aac_do_ioctl(softs, dev, cmd, arg, flag));
	}
	return (ENXIO);
}

/*
 * The IO fault service error handling callback function
 */
/*ARGSUSED*/
static int
aac_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

/*
 * aac_fm_init - initialize fma capabilities and register with IO
 *               fault services.
 */
static void
aac_fm_init(struct aac_softstate *softs)
{
	/*
	 * Need to change iblock to priority for new MSI intr
	 */
	ddi_iblock_cookie_t fm_ibc;

	softs->fm_capabilities = ddi_getprop(DDI_DEV_T_ANY, softs->devinfo_p,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	/* Only register with IO Fault Services if we have some capability */
	if (softs->fm_capabilities) {
		/* Adjust access and dma attributes for FMA */
		softs->reg_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		softs->addr_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		softs->buf_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;

		/*
		 * Register capabilities with IO Fault Services.
		 * fm_capabilities will be updated to indicate
		 * capabilities actually supported (not requested.)
		 */
		ddi_fm_init(softs->devinfo_p, &softs->fm_capabilities, &fm_ibc);

		/*
		 * Initialize pci ereport capabilities if ereport
		 * capable (should always be.)
		 */
		if (DDI_FM_EREPORT_CAP(softs->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(softs->fm_capabilities)) {
			pci_ereport_setup(softs->devinfo_p);
		}

		/*
		 * Register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(softs->fm_capabilities)) {
			ddi_fm_handler_register(softs->devinfo_p,
			    aac_fm_error_cb, (void *) softs);
		}
	}
}

/*
 * aac_fm_fini - Releases fma capabilities and un-registers with IO
 *               fault services.
 */
static void
aac_fm_fini(struct aac_softstate *softs)
{
	/* Only unregister FMA capabilities if registered */
	if (softs->fm_capabilities) {
		/*
		 * Un-register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(softs->fm_capabilities)) {
			ddi_fm_handler_unregister(softs->devinfo_p);
		}

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(softs->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(softs->fm_capabilities)) {
			pci_ereport_teardown(softs->devinfo_p);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(softs->devinfo_p);

		/* Adjust access and dma attributes for FMA */
		softs->reg_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		softs->addr_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		softs->buf_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	}
}

int
aac_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

int
aac_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

void
aac_fm_ereport(struct aac_softstate *softs, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(softs->fm_capabilities)) {
		ddi_fm_ereport_post(softs->devinfo_p, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERSION, NULL);
	}
}

/*
 * Autoconfiguration support
 */
static int
aac_parse_devname(char *devnm, int *tgt, int *lun)
{
	char devbuf[SCSI_MAXNAMELEN];
	char *addr;
	char *p,  *tp, *lp;
	long num;

	/* Parse dev name and address */
	(void) strcpy(devbuf, devnm);
	addr = "";
	for (p = devbuf; *p != '\0'; p++) {
		if (*p == '@') {
			addr = p + 1;
			*p = '\0';
		} else if (*p == ':') {
			*p = '\0';
			break;
		}
	}

	/* Parse taget and lun */
	for (p = tp = addr, lp = NULL; *p != '\0'; p++) {
		if (*p == ',') {
			lp = p + 1;
			*p = '\0';
			break;
		}
	}
	if (tgt && tp) {
		if (ddi_strtol(tp, NULL, 0x10, &num))
			return (AACERR);
		*tgt = (int)num;
	}
	if (lun && lp) {
		if (ddi_strtol(lp, NULL, 0x10, &num))
			return (AACERR);
		*lun = (int)num;
	}
	return (AACOK);
}

static dev_info_t *
aac_find_child(struct aac_softstate *softs, uint16_t tgt, uint8_t lun)
{
	dev_info_t *child = NULL;
	char addr[SCSI_MAXNAMELEN];
	char tmp[MAXNAMELEN];

	if (tgt < AAC_MAX_LD) {
		if (lun == 0) {
			struct aac_device *dvp = &softs->containers[tgt].dev;

			child = dvp->dip;
		}
	} else {
		(void) sprintf(addr, "%x,%x", tgt, lun);
		for (child = ddi_get_child(softs->devinfo_p);
		    child; child = ddi_get_next_sibling(child)) {
			/* We don't care about non-persistent node */
			if (ndi_dev_is_persistent_node(child) == 0)
				continue;

			if (aac_name_node(child, tmp, MAXNAMELEN) !=
			    DDI_SUCCESS)
				continue;
			if (strcmp(addr, tmp) == 0)
				break;
		}
	}
	return (child);
}

static int
aac_config_child(struct aac_softstate *softs, struct scsi_device *sd,
    dev_info_t **dipp)
{
	char *nodename = NULL;
	char **compatible = NULL;
	int ncompatible = 0;
	char *childname;
	dev_info_t *ldip = NULL;
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;
	int dtype = sd->sd_inq->inq_dtype & DTYPE_MASK;
	int rval;

	DBCALLED(softs, 2);

	scsi_hba_nodename_compatible_get(sd->sd_inq, NULL, dtype,
	    NULL, &nodename, &compatible, &ncompatible);
	if (nodename == NULL) {
		AACDB_PRINT(softs, CE_WARN,
		    "found no comptible driver for t%dL%d", tgt, lun);
		rval = NDI_FAILURE;
		goto finish;
	}
	childname = (softs->legacy && dtype == DTYPE_DIRECT) ? "sd" : nodename;

	/* Create dev node */
	rval = ndi_devi_alloc(softs->devinfo_p, childname, DEVI_SID_NODEID,
	    &ldip);
	if (rval == NDI_SUCCESS) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "target", tgt)
		    != DDI_PROP_SUCCESS) {
			AACDB_PRINT(softs, CE_WARN, "unable to create "
			    "property for t%dL%d (target)", tgt, lun);
			rval = NDI_FAILURE;
			goto finish;
		}
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "lun", lun)
		    != DDI_PROP_SUCCESS) {
			AACDB_PRINT(softs, CE_WARN, "unable to create "
			    "property for t%dL%d (lun)", tgt, lun);
			rval = NDI_FAILURE;
			goto finish;
		}
		if (ndi_prop_update_string_array(DDI_DEV_T_NONE, ldip,
		    "compatible", compatible, ncompatible)
		    != DDI_PROP_SUCCESS) {
			AACDB_PRINT(softs, CE_WARN, "unable to create "
			    "property for t%dL%d (compatible)", tgt, lun);
			rval = NDI_FAILURE;
			goto finish;
		}

		rval = ndi_devi_online(ldip, NDI_ONLINE_ATTACH);
		if (rval != NDI_SUCCESS) {
			AACDB_PRINT(softs, CE_WARN, "unable to online t%dL%d",
			    tgt, lun);
			ndi_prop_remove_all(ldip);
			(void) ndi_devi_free(ldip);
		}
	}
finish:
	if (dipp)
		*dipp = ldip;

	scsi_hba_nodename_compatible_free(nodename, compatible);
	return (rval);
}

/*ARGSUSED*/
static int
aac_probe_lun(struct aac_softstate *softs, struct scsi_device *sd)
{
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;

	DBCALLED(softs, 2);

	if (tgt < AAC_MAX_LD) {
		enum aac_cfg_event event;

		if (lun == 0) {
			mutex_enter(&softs->io_lock);
			event = aac_probe_container(softs, tgt);
			mutex_exit(&softs->io_lock);
			if ((event != AAC_CFG_NULL_NOEXIST) &&
			    (event != AAC_CFG_DELETE)) {
				if (scsi_hba_probe(sd, NULL) ==
				    SCSIPROBE_EXISTS)
					return (NDI_SUCCESS);
			}
		}
		return (NDI_FAILURE);
	} else {
		int dtype;
		int qual; /* device qualifier */

		if (scsi_hba_probe(sd, NULL) != SCSIPROBE_EXISTS)
			return (NDI_FAILURE);

		dtype = sd->sd_inq->inq_dtype & DTYPE_MASK;
		qual = dtype >> 5;

		AACDB_PRINT(softs, CE_NOTE,
		    "Phys. device found: tgt %d dtype %d: %s",
		    tgt, dtype, sd->sd_inq->inq_vid);

		/* Only non-DASD and JBOD mode DASD are allowed exposed */
		if (dtype == DTYPE_RODIRECT /* CDROM */ ||
		    dtype == DTYPE_SEQUENTIAL /* TAPE */ ||
		    dtype == DTYPE_ESI /* SES */) {
			if (!(softs->flags & AAC_FLAGS_NONDASD))
				return (NDI_FAILURE);
			AACDB_PRINT(softs, CE_NOTE, "non-DASD %d found", tgt);

		} else if (dtype == DTYPE_DIRECT) {
			if (!(softs->flags & AAC_FLAGS_JBOD) || qual != 0)
				return (NDI_FAILURE);
			AACDB_PRINT(softs, CE_NOTE, "JBOD DASD %d found", tgt);
		}

		mutex_enter(&softs->io_lock);
		softs->nondasds[AAC_PD(tgt)].dev.flags |= AAC_DFLAG_VALID;
		mutex_exit(&softs->io_lock);
		return (NDI_SUCCESS);
	}
}

static int
aac_config_lun(struct aac_softstate *softs, uint16_t tgt, uint8_t lun,
    dev_info_t **ldip)
{
	struct scsi_device sd;
	dev_info_t *child;
	int rval;

	DBCALLED(softs, 2);

	if ((child = aac_find_child(softs, tgt, lun)) != NULL) {
		if (ldip)
			*ldip = child;
		return (NDI_SUCCESS);
	}

	bzero(&sd, sizeof (struct scsi_device));
	sd.sd_address.a_hba_tran = softs->hba_tran;
	sd.sd_address.a_target = (uint16_t)tgt;
	sd.sd_address.a_lun = (uint8_t)lun;
	if ((rval = aac_probe_lun(softs, &sd)) == NDI_SUCCESS)
		rval = aac_config_child(softs, &sd, ldip);
	/* scsi_unprobe is blank now. Free buffer manually */
	if (sd.sd_inq) {
		kmem_free(sd.sd_inq, SUN_INQSIZE);
		sd.sd_inq = (struct scsi_inquiry *)NULL;
	}
	return (rval);
}

static int
aac_config_tgt(struct aac_softstate *softs, int tgt)
{
	struct scsi_address ap;
	struct buf *bp = NULL;
	int buf_len = AAC_SCSI_RPTLUNS_HEAD_SIZE + AAC_SCSI_RPTLUNS_ADDR_SIZE;
	int list_len = 0;
	int lun_total = 0;
	dev_info_t *ldip;
	int i;

	ap.a_hba_tran = softs->hba_tran;
	ap.a_target = (uint16_t)tgt;
	ap.a_lun = 0;

	for (i = 0; i < 2; i++) {
		struct scsi_pkt *pkt;
		uchar_t *cdb;
		uchar_t *p;
		uint32_t data;

		if (bp == NULL) {
			if ((bp = scsi_alloc_consistent_buf(&ap, NULL,
			    buf_len, B_READ, NULL_FUNC, NULL)) == NULL)
				return (AACERR);
		}
		if ((pkt = scsi_init_pkt(&ap, NULL, bp, CDB_GROUP5,
		    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT,
		    NULL, NULL)) == NULL) {
			scsi_free_consistent_buf(bp);
			return (AACERR);
		}
		cdb = pkt->pkt_cdbp;
		bzero(cdb, CDB_GROUP5);
		cdb[0] = SCMD_REPORT_LUNS;

		/* Convert buffer len from local to LE_32 */
		data = buf_len;
		for (p = &cdb[9]; p > &cdb[5]; p--) {
			*p = data & 0xff;
			data >>= 8;
		}

		if (scsi_poll(pkt) < 0 ||
		    ((struct scsi_status *)pkt->pkt_scbp)->sts_chk) {
			scsi_destroy_pkt(pkt);
			break;
		}

		/* Convert list_len from LE_32 to local */
		for (p = (uchar_t *)bp->b_un.b_addr;
		    p < (uchar_t *)bp->b_un.b_addr + 4; p++) {
			data <<= 8;
			data |= *p;
		}
		list_len = data;
		if (buf_len < list_len + AAC_SCSI_RPTLUNS_HEAD_SIZE) {
			scsi_free_consistent_buf(bp);
			bp = NULL;
			buf_len = list_len + AAC_SCSI_RPTLUNS_HEAD_SIZE;
		}
		scsi_destroy_pkt(pkt);
	}
	if (i >= 2) {
		uint8_t *buf = (uint8_t *)(bp->b_un.b_addr +
		    AAC_SCSI_RPTLUNS_HEAD_SIZE);

		for (i = 0; i < (list_len / AAC_SCSI_RPTLUNS_ADDR_SIZE); i++) {
			uint16_t lun;

			/* Determine report luns addressing type */
			switch (buf[0] & AAC_SCSI_RPTLUNS_ADDR_MASK) {
			/*
			 * Vendors in the field have been found to be
			 * concatenating bus/target/lun to equal the
			 * complete lun value instead of switching to
			 * flat space addressing
			 */
			case AAC_SCSI_RPTLUNS_ADDR_PERIPHERAL:
			case AAC_SCSI_RPTLUNS_ADDR_LOGICAL_UNIT:
			case AAC_SCSI_RPTLUNS_ADDR_FLAT_SPACE:
				lun = ((buf[0] & 0x3f) << 8) | buf[1];
				if (lun > UINT8_MAX) {
					AACDB_PRINT(softs, CE_WARN,
					    "abnormal lun number: %d", lun);
					break;
				}
				if (aac_config_lun(softs, tgt, lun, &ldip) ==
				    NDI_SUCCESS)
					lun_total++;
				break;
			}

			buf += AAC_SCSI_RPTLUNS_ADDR_SIZE;
		}
	} else {
		/* The target may do not support SCMD_REPORT_LUNS. */
		if (aac_config_lun(softs, tgt, 0, &ldip) == NDI_SUCCESS)
			lun_total++;
	}
	scsi_free_consistent_buf(bp);
	return (lun_total);
}

static void
aac_devcfg(struct aac_softstate *softs, int tgt, int en)
{
	struct aac_device *dvp;

	mutex_enter(&softs->io_lock);
	dvp = AAC_DEV(softs, tgt);
	if (en)
		dvp->flags |= AAC_DFLAG_CONFIGURING;
	else
		dvp->flags &= ~AAC_DFLAG_CONFIGURING;
	mutex_exit(&softs->io_lock);
}

static int
aac_tran_bus_config(dev_info_t *parent, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **childp)
{
	struct aac_softstate *softs;
	int circ = 0;
	int rval;

	if ((softs = ddi_get_soft_state(aac_softstatep,
	    ddi_get_instance(parent))) == NULL)
		return (NDI_FAILURE);

	/* Commands for bus config should be blocked as the bus is quiesced */
	mutex_enter(&softs->io_lock);
	if (softs->state & AAC_STATE_QUIESCED) {
		AACDB_PRINT(softs, CE_NOTE,
		    "bus_config abroted because bus is quiesced");
		mutex_exit(&softs->io_lock);
		return (NDI_FAILURE);
	}
	mutex_exit(&softs->io_lock);

	DBCALLED(softs, 1);

	/* Hold the nexus across the bus_config */
	ndi_devi_enter(parent, &circ);
	switch (op) {
	case BUS_CONFIG_ONE: {
		int tgt, lun;

		if (aac_parse_devname(arg, &tgt, &lun) != AACOK) {
			rval = NDI_FAILURE;
			break;
		}
		if (tgt >= AAC_MAX_LD) {
			if (tgt >= AAC_MAX_DEV(softs)) {
				rval = NDI_FAILURE;
				break;
			}
		}

		AAC_DEVCFG_BEGIN(softs, tgt);
		rval = aac_config_lun(softs, tgt, lun, childp);
		AAC_DEVCFG_END(softs, tgt);
		break;
	}

	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL: {
		uint32_t bus, tgt;
		int index, total;

		for (tgt = 0; tgt < AAC_MAX_LD; tgt++) {
			AAC_DEVCFG_BEGIN(softs, tgt);
			(void) aac_config_lun(softs, tgt, 0, NULL);
			AAC_DEVCFG_END(softs, tgt);
		}

		/* Config the non-DASD devices connected to the card */
		total = 0;
		index = AAC_MAX_LD;
		for (bus = 0; bus < softs->bus_max; bus++) {
			AACDB_PRINT(softs, CE_NOTE, "bus %d:", bus);
			for (tgt = 0; tgt < softs->tgt_max; tgt++, index++) {
				AAC_DEVCFG_BEGIN(softs, index);
				if (aac_config_tgt(softs, index))
					total++;
				AAC_DEVCFG_END(softs, index);
			}
		}
		AACDB_PRINT(softs, CE_CONT,
		    "?Total %d phys. device(s) found", total);
		rval = NDI_SUCCESS;
		break;
	}
	}

	if (rval == NDI_SUCCESS)
		rval = ndi_busop_bus_config(parent, flags, op, arg, childp, 0);
	ndi_devi_exit(parent, circ);
	return (rval);
}

/*ARGSUSED*/
static int
aac_handle_dr(struct aac_softstate *softs, int tgt, int lun, int event)
{
	struct aac_device *dvp;
	dev_info_t *dip;
	int valid;
	int circ1 = 0;

	DBCALLED(softs, 1);

	/* Hold the nexus across the bus_config */
	dvp = AAC_DEV(softs, tgt);
	valid = AAC_DEV_IS_VALID(dvp);
	dip = dvp->dip;
	if (!(softs->state & AAC_STATE_RUN))
		return (AACERR);
	mutex_exit(&softs->io_lock);

	switch (event) {
	case AAC_CFG_ADD:
	case AAC_CFG_DELETE:
		/* Device onlined */
		if (dip == NULL && valid) {
			ndi_devi_enter(softs->devinfo_p, &circ1);
			(void) aac_config_lun(softs, tgt, 0, NULL);
			AACDB_PRINT(softs, CE_NOTE, "c%dt%dL%d onlined",
			    softs->instance, tgt, lun);
			ndi_devi_exit(softs->devinfo_p, circ1);
		}
		/* Device offlined */
		if (dip && !valid) {
			mutex_enter(&softs->io_lock);
			(void) aac_do_reset(softs);
			mutex_exit(&softs->io_lock);

			(void) ndi_devi_offline(dip, NDI_DEVI_REMOVE);
			AACDB_PRINT(softs, CE_NOTE, "c%dt%dL%d offlined",
			    softs->instance, tgt, lun);
		}
		break;
	}

	mutex_enter(&softs->io_lock);
	return (AACOK);
}

#ifdef DEBUG

/* -------------------------debug aid functions-------------------------- */

#define	AAC_FIB_CMD_KEY_STRINGS \
	TestCommandResponse, "TestCommandResponse", \
	TestAdapterCommand, "TestAdapterCommand", \
	LastTestCommand, "LastTestCommand", \
	ReinitHostNormCommandQueue, "ReinitHostNormCommandQueue", \
	ReinitHostHighCommandQueue, "ReinitHostHighCommandQueue", \
	ReinitHostHighRespQueue, "ReinitHostHighRespQueue", \
	ReinitHostNormRespQueue, "ReinitHostNormRespQueue", \
	ReinitAdapNormCommandQueue, "ReinitAdapNormCommandQueue", \
	ReinitAdapHighCommandQueue, "ReinitAdapHighCommandQueue", \
	ReinitAdapHighRespQueue, "ReinitAdapHighRespQueue", \
	ReinitAdapNormRespQueue, "ReinitAdapNormRespQueue", \
	InterfaceShutdown, "InterfaceShutdown", \
	DmaCommandFib, "DmaCommandFib", \
	StartProfile, "StartProfile", \
	TermProfile, "TermProfile", \
	SpeedTest, "SpeedTest", \
	TakeABreakPt, "TakeABreakPt", \
	RequestPerfData, "RequestPerfData", \
	SetInterruptDefTimer, "SetInterruptDefTimer", \
	SetInterruptDefCount, "SetInterruptDefCount", \
	GetInterruptDefStatus, "GetInterruptDefStatus", \
	LastCommCommand, "LastCommCommand", \
	NuFileSystem, "NuFileSystem", \
	UFS, "UFS", \
	HostFileSystem, "HostFileSystem", \
	LastFileSystemCommand, "LastFileSystemCommand", \
	ContainerCommand, "ContainerCommand", \
	ContainerCommand64, "ContainerCommand64", \
	ClusterCommand, "ClusterCommand", \
	ScsiPortCommand, "ScsiPortCommand", \
	ScsiPortCommandU64, "ScsiPortCommandU64", \
	AifRequest, "AifRequest", \
	CheckRevision, "CheckRevision", \
	FsaHostShutdown, "FsaHostShutdown", \
	RequestAdapterInfo, "RequestAdapterInfo", \
	IsAdapterPaused, "IsAdapterPaused", \
	SendHostTime, "SendHostTime", \
	LastMiscCommand, "LastMiscCommand"

#define	AAC_CTVM_SUBCMD_KEY_STRINGS \
	VM_Null, "VM_Null", \
	VM_NameServe, "VM_NameServe", \
	VM_ContainerConfig, "VM_ContainerConfig", \
	VM_Ioctl, "VM_Ioctl", \
	VM_FilesystemIoctl, "VM_FilesystemIoctl", \
	VM_CloseAll, "VM_CloseAll", \
	VM_CtBlockRead, "VM_CtBlockRead", \
	VM_CtBlockWrite, "VM_CtBlockWrite", \
	VM_SliceBlockRead, "VM_SliceBlockRead", \
	VM_SliceBlockWrite, "VM_SliceBlockWrite", \
	VM_DriveBlockRead, "VM_DriveBlockRead", \
	VM_DriveBlockWrite, "VM_DriveBlockWrite", \
	VM_EnclosureMgt, "VM_EnclosureMgt", \
	VM_Unused, "VM_Unused", \
	VM_CtBlockVerify, "VM_CtBlockVerify", \
	VM_CtPerf, "VM_CtPerf", \
	VM_CtBlockRead64, "VM_CtBlockRead64", \
	VM_CtBlockWrite64, "VM_CtBlockWrite64", \
	VM_CtBlockVerify64, "VM_CtBlockVerify64", \
	VM_CtHostRead64, "VM_CtHostRead64", \
	VM_CtHostWrite64, "VM_CtHostWrite64", \
	VM_NameServe64, "VM_NameServe64"

#define	AAC_CT_SUBCMD_KEY_STRINGS \
	CT_Null, "CT_Null", \
	CT_GET_SLICE_COUNT, "CT_GET_SLICE_COUNT", \
	CT_GET_PARTITION_COUNT, "CT_GET_PARTITION_COUNT", \
	CT_GET_PARTITION_INFO, "CT_GET_PARTITION_INFO", \
	CT_GET_CONTAINER_COUNT, "CT_GET_CONTAINER_COUNT", \
	CT_GET_CONTAINER_INFO_OLD, "CT_GET_CONTAINER_INFO_OLD", \
	CT_WRITE_MBR, "CT_WRITE_MBR", \
	CT_WRITE_PARTITION, "CT_WRITE_PARTITION", \
	CT_UPDATE_PARTITION, "CT_UPDATE_PARTITION", \
	CT_UNLOAD_CONTAINER, "CT_UNLOAD_CONTAINER", \
	CT_CONFIG_SINGLE_PRIMARY, "CT_CONFIG_SINGLE_PRIMARY", \
	CT_READ_CONFIG_AGE, "CT_READ_CONFIG_AGE", \
	CT_WRITE_CONFIG_AGE, "CT_WRITE_CONFIG_AGE", \
	CT_READ_SERIAL_NUMBER, "CT_READ_SERIAL_NUMBER", \
	CT_ZERO_PAR_ENTRY, "CT_ZERO_PAR_ENTRY", \
	CT_READ_MBR, "CT_READ_MBR", \
	CT_READ_PARTITION, "CT_READ_PARTITION", \
	CT_DESTROY_CONTAINER, "CT_DESTROY_CONTAINER", \
	CT_DESTROY2_CONTAINER, "CT_DESTROY2_CONTAINER", \
	CT_SLICE_SIZE, "CT_SLICE_SIZE", \
	CT_CHECK_CONFLICTS, "CT_CHECK_CONFLICTS", \
	CT_MOVE_CONTAINER, "CT_MOVE_CONTAINER", \
	CT_READ_LAST_DRIVE, "CT_READ_LAST_DRIVE", \
	CT_WRITE_LAST_DRIVE, "CT_WRITE_LAST_DRIVE", \
	CT_UNMIRROR, "CT_UNMIRROR", \
	CT_MIRROR_DELAY, "CT_MIRROR_DELAY", \
	CT_GEN_MIRROR, "CT_GEN_MIRROR", \
	CT_GEN_MIRROR2, "CT_GEN_MIRROR2", \
	CT_TEST_CONTAINER, "CT_TEST_CONTAINER", \
	CT_MOVE2, "CT_MOVE2", \
	CT_SPLIT, "CT_SPLIT", \
	CT_SPLIT2, "CT_SPLIT2", \
	CT_SPLIT_BROKEN, "CT_SPLIT_BROKEN", \
	CT_SPLIT_BROKEN2, "CT_SPLIT_BROKEN2", \
	CT_RECONFIG, "CT_RECONFIG", \
	CT_BREAK2, "CT_BREAK2", \
	CT_BREAK, "CT_BREAK", \
	CT_MERGE2, "CT_MERGE2", \
	CT_MERGE, "CT_MERGE", \
	CT_FORCE_ERROR, "CT_FORCE_ERROR", \
	CT_CLEAR_ERROR, "CT_CLEAR_ERROR", \
	CT_ASSIGN_FAILOVER, "CT_ASSIGN_FAILOVER", \
	CT_CLEAR_FAILOVER, "CT_CLEAR_FAILOVER", \
	CT_GET_FAILOVER_DATA, "CT_GET_FAILOVER_DATA", \
	CT_VOLUME_ADD, "CT_VOLUME_ADD", \
	CT_VOLUME_ADD2, "CT_VOLUME_ADD2", \
	CT_MIRROR_STATUS, "CT_MIRROR_STATUS", \
	CT_COPY_STATUS, "CT_COPY_STATUS", \
	CT_COPY, "CT_COPY", \
	CT_UNLOCK_CONTAINER, "CT_UNLOCK_CONTAINER", \
	CT_LOCK_CONTAINER, "CT_LOCK_CONTAINER", \
	CT_MAKE_READ_ONLY, "CT_MAKE_READ_ONLY", \
	CT_MAKE_READ_WRITE, "CT_MAKE_READ_WRITE", \
	CT_CLEAN_DEAD, "CT_CLEAN_DEAD", \
	CT_ABORT_MIRROR_COMMAND, "CT_ABORT_MIRROR_COMMAND", \
	CT_SET, "CT_SET", \
	CT_GET, "CT_GET", \
	CT_GET_NVLOG_ENTRY, "CT_GET_NVLOG_ENTRY", \
	CT_GET_DELAY, "CT_GET_DELAY", \
	CT_ZERO_CONTAINER_SPACE, "CT_ZERO_CONTAINER_SPACE", \
	CT_GET_ZERO_STATUS, "CT_GET_ZERO_STATUS", \
	CT_SCRUB, "CT_SCRUB", \
	CT_GET_SCRUB_STATUS, "CT_GET_SCRUB_STATUS", \
	CT_GET_SLICE_INFO, "CT_GET_SLICE_INFO", \
	CT_GET_SCSI_METHOD, "CT_GET_SCSI_METHOD", \
	CT_PAUSE_IO, "CT_PAUSE_IO", \
	CT_RELEASE_IO, "CT_RELEASE_IO", \
	CT_SCRUB2, "CT_SCRUB2", \
	CT_MCHECK, "CT_MCHECK", \
	CT_CORRUPT, "CT_CORRUPT", \
	CT_GET_TASK_COUNT, "CT_GET_TASK_COUNT", \
	CT_PROMOTE, "CT_PROMOTE", \
	CT_SET_DEAD, "CT_SET_DEAD", \
	CT_CONTAINER_OPTIONS, "CT_CONTAINER_OPTIONS", \
	CT_GET_NV_PARAM, "CT_GET_NV_PARAM", \
	CT_GET_PARAM, "CT_GET_PARAM", \
	CT_NV_PARAM_SIZE, "CT_NV_PARAM_SIZE", \
	CT_COMMON_PARAM_SIZE, "CT_COMMON_PARAM_SIZE", \
	CT_PLATFORM_PARAM_SIZE, "CT_PLATFORM_PARAM_SIZE", \
	CT_SET_NV_PARAM, "CT_SET_NV_PARAM", \
	CT_ABORT_SCRUB, "CT_ABORT_SCRUB", \
	CT_GET_SCRUB_ERROR, "CT_GET_SCRUB_ERROR", \
	CT_LABEL_CONTAINER, "CT_LABEL_CONTAINER", \
	CT_CONTINUE_DATA, "CT_CONTINUE_DATA", \
	CT_STOP_DATA, "CT_STOP_DATA", \
	CT_GET_PARTITION_TABLE, "CT_GET_PARTITION_TABLE", \
	CT_GET_DISK_PARTITIONS, "CT_GET_DISK_PARTITIONS", \
	CT_GET_MISC_STATUS, "CT_GET_MISC_STATUS", \
	CT_GET_CONTAINER_PERF_INFO, "CT_GET_CONTAINER_PERF_INFO", \
	CT_GET_TIME, "CT_GET_TIME", \
	CT_READ_DATA, "CT_READ_DATA", \
	CT_CTR, "CT_CTR", \
	CT_CTL, "CT_CTL", \
	CT_DRAINIO, "CT_DRAINIO", \
	CT_RELEASEIO, "CT_RELEASEIO", \
	CT_GET_NVRAM, "CT_GET_NVRAM", \
	CT_GET_MEMORY, "CT_GET_MEMORY", \
	CT_PRINT_CT_LOG, "CT_PRINT_CT_LOG", \
	CT_ADD_LEVEL, "CT_ADD_LEVEL", \
	CT_NV_ZERO, "CT_NV_ZERO", \
	CT_READ_SIGNATURE, "CT_READ_SIGNATURE", \
	CT_THROTTLE_ON, "CT_THROTTLE_ON", \
	CT_THROTTLE_OFF, "CT_THROTTLE_OFF", \
	CT_GET_THROTTLE_STATS, "CT_GET_THROTTLE_STATS", \
	CT_MAKE_SNAPSHOT, "CT_MAKE_SNAPSHOT", \
	CT_REMOVE_SNAPSHOT, "CT_REMOVE_SNAPSHOT", \
	CT_WRITE_USER_FLAGS, "CT_WRITE_USER_FLAGS", \
	CT_READ_USER_FLAGS, "CT_READ_USER_FLAGS", \
	CT_MONITOR, "CT_MONITOR", \
	CT_GEN_MORPH, "CT_GEN_MORPH", \
	CT_GET_SNAPSHOT_INFO, "CT_GET_SNAPSHOT_INFO", \
	CT_CACHE_SET, "CT_CACHE_SET", \
	CT_CACHE_STAT, "CT_CACHE_STAT", \
	CT_TRACE_START, "CT_TRACE_START", \
	CT_TRACE_STOP, "CT_TRACE_STOP", \
	CT_TRACE_ENABLE, "CT_TRACE_ENABLE", \
	CT_TRACE_DISABLE, "CT_TRACE_DISABLE", \
	CT_FORCE_CORE_DUMP, "CT_FORCE_CORE_DUMP", \
	CT_SET_SERIAL_NUMBER, "CT_SET_SERIAL_NUMBER", \
	CT_RESET_SERIAL_NUMBER, "CT_RESET_SERIAL_NUMBER", \
	CT_ENABLE_RAID5, "CT_ENABLE_RAID5", \
	CT_CLEAR_VALID_DUMP_FLAG, "CT_CLEAR_VALID_DUMP_FLAG", \
	CT_GET_MEM_STATS, "CT_GET_MEM_STATS", \
	CT_GET_CORE_SIZE, "CT_GET_CORE_SIZE", \
	CT_CREATE_CONTAINER_OLD, "CT_CREATE_CONTAINER_OLD", \
	CT_STOP_DUMPS, "CT_STOP_DUMPS", \
	CT_PANIC_ON_TAKE_A_BREAK, "CT_PANIC_ON_TAKE_A_BREAK", \
	CT_GET_CACHE_STATS, "CT_GET_CACHE_STATS", \
	CT_MOVE_PARTITION, "CT_MOVE_PARTITION", \
	CT_FLUSH_CACHE, "CT_FLUSH_CACHE", \
	CT_READ_NAME, "CT_READ_NAME", \
	CT_WRITE_NAME, "CT_WRITE_NAME", \
	CT_TOSS_CACHE, "CT_TOSS_CACHE", \
	CT_LOCK_DRAINIO, "CT_LOCK_DRAINIO", \
	CT_CONTAINER_OFFLINE, "CT_CONTAINER_OFFLINE", \
	CT_SET_CACHE_SIZE, "CT_SET_CACHE_SIZE", \
	CT_CLEAN_SHUTDOWN_STATUS, "CT_CLEAN_SHUTDOWN_STATUS", \
	CT_CLEAR_DISKLOG_ON_DISK, "CT_CLEAR_DISKLOG_ON_DISK", \
	CT_CLEAR_ALL_DISKLOG, "CT_CLEAR_ALL_DISKLOG", \
	CT_CACHE_FAVOR, "CT_CACHE_FAVOR", \
	CT_READ_PASSTHRU_MBR, "CT_READ_PASSTHRU_MBR", \
	CT_SCRUB_NOFIX, "CT_SCRUB_NOFIX", \
	CT_SCRUB2_NOFIX, "CT_SCRUB2_NOFIX", \
	CT_FLUSH, "CT_FLUSH", \
	CT_REBUILD, "CT_REBUILD", \
	CT_FLUSH_CONTAINER, "CT_FLUSH_CONTAINER", \
	CT_RESTART, "CT_RESTART", \
	CT_GET_CONFIG_STATUS, "CT_GET_CONFIG_STATUS", \
	CT_TRACE_FLAG, "CT_TRACE_FLAG", \
	CT_RESTART_MORPH, "CT_RESTART_MORPH", \
	CT_GET_TRACE_INFO, "CT_GET_TRACE_INFO", \
	CT_GET_TRACE_ITEM, "CT_GET_TRACE_ITEM", \
	CT_COMMIT_CONFIG, "CT_COMMIT_CONFIG", \
	CT_CONTAINER_EXISTS, "CT_CONTAINER_EXISTS", \
	CT_GET_SLICE_FROM_DEVT, "CT_GET_SLICE_FROM_DEVT", \
	CT_OPEN_READ_WRITE, "CT_OPEN_READ_WRITE", \
	CT_WRITE_MEMORY_BLOCK, "CT_WRITE_MEMORY_BLOCK", \
	CT_GET_CACHE_PARAMS, "CT_GET_CACHE_PARAMS", \
	CT_CRAZY_CACHE, "CT_CRAZY_CACHE", \
	CT_GET_PROFILE_STRUCT, "CT_GET_PROFILE_STRUCT", \
	CT_SET_IO_TRACE_FLAG, "CT_SET_IO_TRACE_FLAG", \
	CT_GET_IO_TRACE_STRUCT, "CT_GET_IO_TRACE_STRUCT", \
	CT_CID_TO_64BITS_UID, "CT_CID_TO_64BITS_UID", \
	CT_64BITS_UID_TO_CID, "CT_64BITS_UID_TO_CID", \
	CT_PAR_TO_64BITS_UID, "CT_PAR_TO_64BITS_UID", \
	CT_CID_TO_32BITS_UID, "CT_CID_TO_32BITS_UID", \
	CT_32BITS_UID_TO_CID, "CT_32BITS_UID_TO_CID", \
	CT_PAR_TO_32BITS_UID, "CT_PAR_TO_32BITS_UID", \
	CT_SET_FAILOVER_OPTION, "CT_SET_FAILOVER_OPTION", \
	CT_GET_FAILOVER_OPTION, "CT_GET_FAILOVER_OPTION", \
	CT_STRIPE_ADD2, "CT_STRIPE_ADD2", \
	CT_CREATE_VOLUME_SET, "CT_CREATE_VOLUME_SET", \
	CT_CREATE_STRIPE_SET, "CT_CREATE_STRIPE_SET", \
	CT_VERIFY_CONTAINER, "CT_VERIFY_CONTAINER", \
	CT_IS_CONTAINER_DEAD, "CT_IS_CONTAINER_DEAD", \
	CT_GET_CONTAINER_OPTION, "CT_GET_CONTAINER_OPTION", \
	CT_GET_SNAPSHOT_UNUSED_STRUCT, "CT_GET_SNAPSHOT_UNUSED_STRUCT", \
	CT_CLEAR_SNAPSHOT_UNUSED_STRUCT, "CT_CLEAR_SNAPSHOT_UNUSED_STRUCT", \
	CT_GET_CONTAINER_INFO, "CT_GET_CONTAINER_INFO", \
	CT_CREATE_CONTAINER, "CT_CREATE_CONTAINER", \
	CT_CHANGE_CREATIONINFO, "CT_CHANGE_CREATIONINFO", \
	CT_CHECK_CONFLICT_UID, "CT_CHECK_CONFLICT_UID", \
	CT_CONTAINER_UID_CHECK, "CT_CONTAINER_UID_CHECK", \
	CT_IS_CONTAINER_MEATADATA_STANDARD, \
	    "CT_IS_CONTAINER_MEATADATA_STANDARD", \
	CT_IS_SLICE_METADATA_STANDARD, "CT_IS_SLICE_METADATA_STANDARD", \
	CT_GET_IMPORT_COUNT, "CT_GET_IMPORT_COUNT", \
	CT_CANCEL_ALL_IMPORTS, "CT_CANCEL_ALL_IMPORTS", \
	CT_GET_IMPORT_INFO, "CT_GET_IMPORT_INFO", \
	CT_IMPORT_ARRAY, "CT_IMPORT_ARRAY", \
	CT_GET_LOG_SIZE, "CT_GET_LOG_SIZE", \
	CT_ALARM_GET_STATE, "CT_ALARM_GET_STATE", \
	CT_ALARM_SET_STATE, "CT_ALARM_SET_STATE", \
	CT_ALARM_ON_OFF, "CT_ALARM_ON_OFF", \
	CT_GET_EE_OEM_ID, "CT_GET_EE_OEM_ID", \
	CT_GET_PPI_HEADERS, "CT_GET_PPI_HEADERS", \
	CT_GET_PPI_DATA, "CT_GET_PPI_DATA", \
	CT_GET_PPI_ENTRIES, "CT_GET_PPI_ENTRIES", \
	CT_DELETE_PPI_BUNDLE, "CT_DELETE_PPI_BUNDLE", \
	CT_GET_PARTITION_TABLE_2, "CT_GET_PARTITION_TABLE_2", \
	CT_GET_PARTITION_INFO_2, "CT_GET_PARTITION_INFO_2", \
	CT_GET_DISK_PARTITIONS_2, "CT_GET_DISK_PARTITIONS_2", \
	CT_QUIESCE_ADAPTER, "CT_QUIESCE_ADAPTER", \
	CT_CLEAR_PPI_TABLE, "CT_CLEAR_PPI_TABLE"

#define	AAC_CL_SUBCMD_KEY_STRINGS \
	CL_NULL, "CL_NULL", \
	DS_INIT, "DS_INIT", \
	DS_RESCAN, "DS_RESCAN", \
	DS_CREATE, "DS_CREATE", \
	DS_DELETE, "DS_DELETE", \
	DS_ADD_DISK, "DS_ADD_DISK", \
	DS_REMOVE_DISK, "DS_REMOVE_DISK", \
	DS_MOVE_DISK, "DS_MOVE_DISK", \
	DS_TAKE_OWNERSHIP, "DS_TAKE_OWNERSHIP", \
	DS_RELEASE_OWNERSHIP, "DS_RELEASE_OWNERSHIP", \
	DS_FORCE_OWNERSHIP, "DS_FORCE_OWNERSHIP", \
	DS_GET_DISK_SET_PARAM, "DS_GET_DISK_SET_PARAM", \
	DS_GET_DRIVE_PARAM, "DS_GET_DRIVE_PARAM", \
	DS_GET_SLICE_PARAM, "DS_GET_SLICE_PARAM", \
	DS_GET_DISK_SETS, "DS_GET_DISK_SETS", \
	DS_GET_DRIVES, "DS_GET_DRIVES", \
	DS_SET_DISK_SET_PARAM, "DS_SET_DISK_SET_PARAM", \
	DS_ONLINE, "DS_ONLINE", \
	DS_OFFLINE, "DS_OFFLINE", \
	DS_ONLINE_CONTAINERS, "DS_ONLINE_CONTAINERS", \
	DS_FSAPRINT, "DS_FSAPRINT", \
	CL_CFG_SET_HOST_IDS, "CL_CFG_SET_HOST_IDS", \
	CL_CFG_SET_PARTNER_HOST_IDS, "CL_CFG_SET_PARTNER_HOST_IDS", \
	CL_CFG_GET_CLUSTER_CONFIG, "CL_CFG_GET_CLUSTER_CONFIG", \
	CC_CLI_CLEAR_MESSAGE_BUFFER, "CC_CLI_CLEAR_MESSAGE_BUFFER", \
	CC_SRV_CLEAR_MESSAGE_BUFFER, "CC_SRV_CLEAR_MESSAGE_BUFFER", \
	CC_CLI_SHOW_MESSAGE_BUFFER, "CC_CLI_SHOW_MESSAGE_BUFFER", \
	CC_SRV_SHOW_MESSAGE_BUFFER, "CC_SRV_SHOW_MESSAGE_BUFFER", \
	CC_CLI_SEND_MESSAGE, "CC_CLI_SEND_MESSAGE", \
	CC_SRV_SEND_MESSAGE, "CC_SRV_SEND_MESSAGE", \
	CC_CLI_GET_MESSAGE, "CC_CLI_GET_MESSAGE", \
	CC_SRV_GET_MESSAGE, "CC_SRV_GET_MESSAGE", \
	CC_SEND_TEST_MESSAGE, "CC_SEND_TEST_MESSAGE", \
	CC_GET_BUSINFO, "CC_GET_BUSINFO", \
	CC_GET_PORTINFO, "CC_GET_PORTINFO", \
	CC_GET_NAMEINFO, "CC_GET_NAMEINFO", \
	CC_GET_CONFIGINFO, "CC_GET_CONFIGINFO", \
	CQ_QUORUM_OP, "CQ_QUORUM_OP"

#define	AAC_AIF_SUBCMD_KEY_STRINGS \
	AifCmdEventNotify, "AifCmdEventNotify", \
	AifCmdJobProgress, "AifCmdJobProgress", \
	AifCmdAPIReport, "AifCmdAPIReport", \
	AifCmdDriverNotify, "AifCmdDriverNotify", \
	AifReqJobList, "AifReqJobList", \
	AifReqJobsForCtr, "AifReqJobsForCtr", \
	AifReqJobsForScsi, "AifReqJobsForScsi", \
	AifReqJobReport, "AifReqJobReport", \
	AifReqTerminateJob, "AifReqTerminateJob", \
	AifReqSuspendJob, "AifReqSuspendJob", \
	AifReqResumeJob, "AifReqResumeJob", \
	AifReqSendAPIReport, "AifReqSendAPIReport", \
	AifReqAPIJobStart, "AifReqAPIJobStart", \
	AifReqAPIJobUpdate, "AifReqAPIJobUpdate", \
	AifReqAPIJobFinish, "AifReqAPIJobFinish"

#define	AAC_IOCTL_SUBCMD_KEY_STRINGS \
	Reserved_IOCTL, "Reserved_IOCTL", \
	GetDeviceHandle, "GetDeviceHandle", \
	BusTargetLun_to_DeviceHandle, "BusTargetLun_to_DeviceHandle", \
	DeviceHandle_to_BusTargetLun, "DeviceHandle_to_BusTargetLun", \
	RescanBus, "RescanBus", \
	GetDeviceProbeInfo, "GetDeviceProbeInfo", \
	GetDeviceCapacity, "GetDeviceCapacity", \
	GetContainerProbeInfo, "GetContainerProbeInfo", \
	GetRequestedMemorySize, "GetRequestedMemorySize", \
	GetBusInfo, "GetBusInfo", \
	GetVendorSpecific, "GetVendorSpecific", \
	EnhancedGetDeviceProbeInfo, "EnhancedGetDeviceProbeInfo", \
	EnhancedGetBusInfo, "EnhancedGetBusInfo", \
	SetupExtendedCounters, "SetupExtendedCounters", \
	GetPerformanceCounters, "GetPerformanceCounters", \
	ResetPerformanceCounters, "ResetPerformanceCounters", \
	ReadModePage, "ReadModePage", \
	WriteModePage, "WriteModePage", \
	ReadDriveParameter, "ReadDriveParameter", \
	WriteDriveParameter, "WriteDriveParameter", \
	ResetAdapter, "ResetAdapter", \
	ResetBus, "ResetBus", \
	ResetBusDevice, "ResetBusDevice", \
	ExecuteSrb, "ExecuteSrb", \
	Create_IO_Task, "Create_IO_Task", \
	Delete_IO_Task, "Delete_IO_Task", \
	Get_IO_Task_Info, "Get_IO_Task_Info", \
	Check_Task_Progress, "Check_Task_Progress", \
	InjectError, "InjectError", \
	GetDeviceDefectCounts, "GetDeviceDefectCounts", \
	GetDeviceDefectInfo, "GetDeviceDefectInfo", \
	GetDeviceStatus, "GetDeviceStatus", \
	ClearDeviceStatus, "ClearDeviceStatus", \
	DiskSpinControl, "DiskSpinControl", \
	DiskSmartControl, "DiskSmartControl", \
	WriteSame, "WriteSame", \
	ReadWriteLong, "ReadWriteLong", \
	FormatUnit, "FormatUnit", \
	TargetDeviceControl, "TargetDeviceControl", \
	TargetChannelControl, "TargetChannelControl", \
	FlashNewCode, "FlashNewCode", \
	DiskCheck, "DiskCheck", \
	RequestSense, "RequestSense", \
	DiskPERControl, "DiskPERControl", \
	Read10, "Read10", \
	Write10, "Write10"

#define	AAC_AIFEN_KEY_STRINGS \
	AifEnGeneric, "Generic", \
	AifEnTaskComplete, "TaskComplete", \
	AifEnConfigChange, "Config change", \
	AifEnContainerChange, "Container change", \
	AifEnDeviceFailure, "device failed", \
	AifEnMirrorFailover, "Mirror failover", \
	AifEnContainerEvent, "container event", \
	AifEnFileSystemChange, "File system changed", \
	AifEnConfigPause, "Container pause event", \
	AifEnConfigResume, "Container resume event", \
	AifEnFailoverChange, "Failover space assignment changed", \
	AifEnRAID5RebuildDone, "RAID5 rebuild finished", \
	AifEnEnclosureManagement, "Enclosure management event", \
	AifEnBatteryEvent, "battery event", \
	AifEnAddContainer, "Add container", \
	AifEnDeleteContainer, "Delete container", \
	AifEnSMARTEvent, "SMART Event", \
	AifEnBatteryNeedsRecond, "battery needs reconditioning", \
	AifEnClusterEvent, "cluster event", \
	AifEnDiskSetEvent, "disk set event occured", \
	AifDenMorphComplete, "morph operation completed", \
	AifDenVolumeExtendComplete, "VolumeExtendComplete"

struct aac_key_strings {
	int key;
	char *message;
};

extern struct scsi_key_strings scsi_cmds[];

static struct aac_key_strings aac_fib_cmds[] = {
	AAC_FIB_CMD_KEY_STRINGS,
	-1,			NULL
};

static struct aac_key_strings aac_ctvm_subcmds[] = {
	AAC_CTVM_SUBCMD_KEY_STRINGS,
	-1,			NULL
};

static struct aac_key_strings aac_ct_subcmds[] = {
	AAC_CT_SUBCMD_KEY_STRINGS,
	-1,			NULL
};

static struct aac_key_strings aac_cl_subcmds[] = {
	AAC_CL_SUBCMD_KEY_STRINGS,
	-1,			NULL
};

static struct aac_key_strings aac_aif_subcmds[] = {
	AAC_AIF_SUBCMD_KEY_STRINGS,
	-1,			NULL
};

static struct aac_key_strings aac_ioctl_subcmds[] = {
	AAC_IOCTL_SUBCMD_KEY_STRINGS,
	-1,			NULL
};

static struct aac_key_strings aac_aifens[] = {
	AAC_AIFEN_KEY_STRINGS,
	-1,			NULL
};

/*
 * The following function comes from Adaptec:
 *
 * Get the firmware print buffer parameters from the firmware,
 * if the command was successful map in the address.
 */
static int
aac_get_fw_debug_buffer(struct aac_softstate *softs)
{
	if (aac_sync_mbcommand(softs, AAC_MONKER_GETDRVPROP,
	    0, 0, 0, 0, NULL) == AACOK) {
		uint32_t mondrv_buf_paddrl = AAC_MAILBOX_GET(softs, 1);
		uint32_t mondrv_buf_paddrh = AAC_MAILBOX_GET(softs, 2);
		uint32_t mondrv_buf_size = AAC_MAILBOX_GET(softs, 3);
		uint32_t mondrv_hdr_size = AAC_MAILBOX_GET(softs, 4);

		if (mondrv_buf_size) {
			uint32_t offset = mondrv_buf_paddrl - \
			    softs->pci_mem_base_paddr;

			/*
			 * See if the address is already mapped in, and
			 * if so set it up from the base address
			 */
			if ((mondrv_buf_paddrh == 0) &&
			    (offset + mondrv_buf_size < softs->map_size)) {
				mutex_enter(&aac_prt_mutex);
				softs->debug_buf_offset = offset;
				softs->debug_header_size = mondrv_hdr_size;
				softs->debug_buf_size = mondrv_buf_size;
				softs->debug_fw_flags = 0;
				softs->debug_flags &= ~AACDB_FLAGS_FW_PRINT;
				mutex_exit(&aac_prt_mutex);

				return (AACOK);
			}
		}
	}
	return (AACERR);
}

int
aac_dbflag_on(struct aac_softstate *softs, int flag)
{
	int debug_flags = softs ? softs->debug_flags : aac_debug_flags;

	return ((debug_flags & (AACDB_FLAGS_FW_PRINT | \
	    AACDB_FLAGS_KERNEL_PRINT)) && (debug_flags & flag));
}

static void
aac_cmn_err(struct aac_softstate *softs, uint_t lev, char sl, int noheader)
{
	if (noheader) {
		if (sl) {
			aac_fmt[0] = sl;
			cmn_err(lev, aac_fmt, aac_prt_buf);
		} else {
			cmn_err(lev, &aac_fmt[1], aac_prt_buf);
		}
	} else {
		if (sl) {
			aac_fmt_header[0] = sl;
			cmn_err(lev, aac_fmt_header,
			    softs->vendor_name, softs->instance,
			    aac_prt_buf);
		} else {
			cmn_err(lev, &aac_fmt_header[1],
			    softs->vendor_name, softs->instance,
			    aac_prt_buf);
		}
	}
}

/*
 * The following function comes from Adaptec:
 *
 * Format and print out the data passed in to UART or console
 * as specified by debug flags.
 */
void
aac_printf(struct aac_softstate *softs, uint_t lev, const char *fmt, ...)
{
	va_list args;
	char sl; /* system log character */

	mutex_enter(&aac_prt_mutex);
	/* Set up parameters and call sprintf function to format the data */
	if (strchr("^!?", fmt[0]) == NULL) {
		sl = 0;
	} else {
		sl = fmt[0];
		fmt++;
	}
	va_start(args, fmt);
	(void) vsprintf(aac_prt_buf, fmt, args);
	va_end(args);

	/* Make sure the softs structure has been passed in for this section */
	if (softs) {
		if ((softs->debug_flags & AACDB_FLAGS_FW_PRINT) &&
		    /* If we are set up for a Firmware print */
		    (softs->debug_buf_size)) {
			uint32_t count, i;

			/* Make sure the string size is within boundaries */
			count = strlen(aac_prt_buf);
			if (count > softs->debug_buf_size)
				count = (uint16_t)softs->debug_buf_size;

			/*
			 * Wait for no more than AAC_PRINT_TIMEOUT for the
			 * previous message length to clear (the handshake).
			 */
			for (i = 0; i < AAC_PRINT_TIMEOUT; i++) {
				if (!PCI_MEM_GET32(softs,
				    softs->debug_buf_offset + \
				    AAC_FW_DBG_STRLEN_OFFSET))
					break;

				drv_usecwait(1000);
			}

			/*
			 * If the length is clear, copy over the message, the
			 * flags, and the length. Make sure the length is the
			 * last because that is the signal for the Firmware to
			 * pick it up.
			 */
			if (!PCI_MEM_GET32(softs, softs->debug_buf_offset + \
			    AAC_FW_DBG_STRLEN_OFFSET)) {
				PCI_MEM_REP_PUT8(softs,
				    softs->debug_buf_offset + \
				    softs->debug_header_size,
				    aac_prt_buf, count);
				PCI_MEM_PUT32(softs,
				    softs->debug_buf_offset + \
				    AAC_FW_DBG_FLAGS_OFFSET,
				    softs->debug_fw_flags);
				PCI_MEM_PUT32(softs,
				    softs->debug_buf_offset + \
				    AAC_FW_DBG_STRLEN_OFFSET, count);
			} else {
				cmn_err(CE_WARN, "UART output fail");
				softs->debug_flags &= ~AACDB_FLAGS_FW_PRINT;
			}
		}

		/*
		 * If the Kernel Debug Print flag is set, send it off
		 * to the Kernel Debugger
		 */
		if (softs->debug_flags & AACDB_FLAGS_KERNEL_PRINT)
			aac_cmn_err(softs, lev, sl,
			    (softs->debug_flags & AACDB_FLAGS_NO_HEADERS));
	} else {
		/* Driver not initialized yet, no firmware or header output */
		if (aac_debug_flags & AACDB_FLAGS_KERNEL_PRINT)
			aac_cmn_err(softs, lev, sl, 1);
	}
	mutex_exit(&aac_prt_mutex);
}

/*
 * Translate command number to description string
 */
static char *
aac_cmd_name(int cmd, struct aac_key_strings *cmdlist)
{
	int i;

	for (i = 0; cmdlist[i].key != -1; i++) {
		if (cmd == cmdlist[i].key)
			return (cmdlist[i].message);
	}
	return (NULL);
}

static void
aac_print_scmd(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct scsi_pkt *pkt = acp->pkt;
	struct scsi_address *ap = &pkt->pkt_address;
	int is_pd = 0;
	int ctl = ddi_get_instance(softs->devinfo_p);
	int tgt = ap->a_target;
	int lun = ap->a_lun;
	union scsi_cdb *cdbp = (void *)pkt->pkt_cdbp;
	uchar_t cmd = cdbp->scc_cmd;
	char *desc;

	if (tgt >= AAC_MAX_LD) {
		is_pd = 1;
		ctl = ((struct aac_nondasd *)acp->dvp)->bus;
		tgt = ((struct aac_nondasd *)acp->dvp)->tid;
		lun = 0;
	}

	if ((desc = aac_cmd_name(cmd,
	    (struct aac_key_strings *)scsi_cmds)) == NULL) {
		aac_printf(softs, CE_NOTE,
		    "SCMD> Unknown(0x%2x) --> c%dt%dL%d %s",
		    cmd, ctl, tgt, lun, is_pd ? "(pd)" : "");
		return;
	}

	switch (cmd) {
	case SCMD_READ:
	case SCMD_WRITE:
		aac_printf(softs, CE_NOTE,
		    "SCMD> %s 0x%x[%d] %s --> c%dt%dL%d %s",
		    desc, GETG0ADDR(cdbp), GETG0COUNT(cdbp),
		    (acp->flags & AAC_CMD_NO_INTR) ? "poll" : "intr",
		    ctl, tgt, lun, is_pd ? "(pd)" : "");
		break;
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
		aac_printf(softs, CE_NOTE,
		    "SCMD> %s 0x%x[%d] %s --> c%dt%dL%d %s",
		    desc, GETG1ADDR(cdbp), GETG1COUNT(cdbp),
		    (acp->flags & AAC_CMD_NO_INTR) ? "poll" : "intr",
		    ctl, tgt, lun, is_pd ? "(pd)" : "");
		break;
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
		aac_printf(softs, CE_NOTE,
		    "SCMD> %s 0x%x.%08x[%d] %s --> c%dt%dL%d %s",
		    desc, GETG4ADDR(cdbp), GETG4ADDRTL(cdbp),
		    GETG4COUNT(cdbp),
		    (acp->flags & AAC_CMD_NO_INTR) ? "poll" : "intr",
		    ctl, tgt, lun, is_pd ? "(pd)" : "");
		break;
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
		aac_printf(softs, CE_NOTE,
		    "SCMD> %s 0x%x[%d] %s --> c%dt%dL%d %s",
		    desc, GETG5ADDR(cdbp), GETG5COUNT(cdbp),
		    (acp->flags & AAC_CMD_NO_INTR) ? "poll" : "intr",
		    ctl, tgt, lun, is_pd ? "(pd)" : "");
		break;
	default:
		aac_printf(softs, CE_NOTE, "SCMD> %s --> c%dt%dL%d %s",
		    desc, ctl, tgt, lun, is_pd ? "(pd)" : "");
	}
}

void
aac_print_fib(struct aac_softstate *softs, struct aac_slot *slotp)
{
	struct aac_cmd *acp = slotp->acp;
	struct aac_fib *fibp = slotp->fibp;
	ddi_acc_handle_t acc = slotp->fib_acc_handle;
	uint16_t fib_size;
	uint32_t fib_cmd, sub_cmd;
	char *cmdstr, *subcmdstr;
	char *caller;
	int i;

	if (acp) {
		if (!(softs->debug_fib_flags & acp->fib_flags))
			return;
		if (acp->fib_flags & AACDB_FLAGS_FIB_SCMD)
			caller = "SCMD";
		else if (acp->fib_flags & AACDB_FLAGS_FIB_IOCTL)
			caller = "IOCTL";
		else if (acp->fib_flags & AACDB_FLAGS_FIB_SRB)
			caller = "SRB";
		else
			return;
	} else {
		if (!(softs->debug_fib_flags & AACDB_FLAGS_FIB_SYNC))
			return;
		caller = "SYNC";
	}

	fib_cmd = ddi_get16(acc, &fibp->Header.Command);
	cmdstr = aac_cmd_name(fib_cmd, aac_fib_cmds);
	sub_cmd = (uint32_t)-1;
	subcmdstr = NULL;

	/* Print FIB header */
	if (softs->debug_fib_flags & AACDB_FLAGS_FIB_HEADER) {
		aac_printf(softs, CE_NOTE, "FIB> from %s", caller);
		aac_printf(softs, CE_NOTE, "     XferState  %d",
		    ddi_get32(acc, &fibp->Header.XferState));
		aac_printf(softs, CE_NOTE, "     Command    %d",
		    ddi_get16(acc, &fibp->Header.Command));
		aac_printf(softs, CE_NOTE, "     StructType %d",
		    ddi_get8(acc, &fibp->Header.StructType));
		aac_printf(softs, CE_NOTE, "     Flags      0x%x",
		    ddi_get8(acc, &fibp->Header.Flags));
		aac_printf(softs, CE_NOTE, "     Size       %d",
		    ddi_get16(acc, &fibp->Header.Size));
		aac_printf(softs, CE_NOTE, "     SenderSize %d",
		    ddi_get16(acc, &fibp->Header.SenderSize));
		aac_printf(softs, CE_NOTE, "     SenderAddr 0x%x",
		    ddi_get32(acc, &fibp->Header.SenderFibAddress));
		aac_printf(softs, CE_NOTE, "     RcvrAddr   0x%x",
		    ddi_get32(acc, &fibp->Header.ReceiverFibAddress));
		aac_printf(softs, CE_NOTE, "     SenderData 0x%x",
		    ddi_get32(acc, &fibp->Header.SenderData));
	}

	/* Print FIB data */
	switch (fib_cmd) {
	case ContainerCommand:
		sub_cmd = ddi_get32(acc,
		    (void *)&(((uint32_t *)(void *)&fibp->data[0])[0]));
		subcmdstr = aac_cmd_name(sub_cmd, aac_ctvm_subcmds);
		if (subcmdstr == NULL)
			break;

		switch (sub_cmd) {
		case VM_ContainerConfig: {
			struct aac_Container *pContainer =
			    (struct aac_Container *)fibp->data;

			fib_cmd = sub_cmd;
			cmdstr = subcmdstr;
			sub_cmd = (uint32_t)-1;
			subcmdstr = NULL;

			sub_cmd = ddi_get32(acc,
			    &pContainer->CTCommand.command);
			subcmdstr = aac_cmd_name(sub_cmd, aac_ct_subcmds);
			if (subcmdstr == NULL)
				break;
			aac_printf(softs, CE_NOTE, "FIB> %s (0x%x, 0x%x, 0x%x)",
			    subcmdstr,
			    ddi_get32(acc, &pContainer->CTCommand.param[0]),
			    ddi_get32(acc, &pContainer->CTCommand.param[1]),
			    ddi_get32(acc, &pContainer->CTCommand.param[2]));
			return;
		}

		case VM_Ioctl:
			fib_cmd = sub_cmd;
			cmdstr = subcmdstr;
			sub_cmd = (uint32_t)-1;
			subcmdstr = NULL;

			sub_cmd = ddi_get32(acc,
			    (void *)&(((uint32_t *)(void *)&fibp->data[0])[4]));
			subcmdstr = aac_cmd_name(sub_cmd, aac_ioctl_subcmds);
			break;

		case VM_CtBlockRead:
		case VM_CtBlockWrite: {
			struct aac_blockread *br =
			    (struct aac_blockread *)fibp->data;
			struct aac_sg_table *sg = &br->SgMap;
			uint32_t sgcount = ddi_get32(acc, &sg->SgCount);

			aac_printf(softs, CE_NOTE,
			    "FIB> %s Container %d  0x%x/%d", subcmdstr,
			    ddi_get32(acc, &br->ContainerId),
			    ddi_get32(acc, &br->BlockNumber),
			    ddi_get32(acc, &br->ByteCount));
			for (i = 0; i < sgcount; i++)
				aac_printf(softs, CE_NOTE,
				    "     %d: 0x%08x/%d", i,
				    ddi_get32(acc, &sg->SgEntry[i].SgAddress),
				    ddi_get32(acc, &sg->SgEntry[i]. \
				    SgByteCount));
			return;
		}
		}
		break;

	case ContainerCommand64: {
		struct aac_blockread64 *br =
		    (struct aac_blockread64 *)fibp->data;
		struct aac_sg_table64 *sg = &br->SgMap64;
		uint32_t sgcount = ddi_get32(acc, &sg->SgCount);
		uint64_t sgaddr;

		sub_cmd = br->Command;
		subcmdstr = NULL;
		if (sub_cmd == VM_CtHostRead64)
			subcmdstr = "VM_CtHostRead64";
		else if (sub_cmd == VM_CtHostWrite64)
			subcmdstr = "VM_CtHostWrite64";
		else
			break;

		aac_printf(softs, CE_NOTE,
		    "FIB> %s Container %d  0x%x/%d", subcmdstr,
		    ddi_get16(acc, &br->ContainerId),
		    ddi_get32(acc, &br->BlockNumber),
		    ddi_get16(acc, &br->SectorCount));
		for (i = 0; i < sgcount; i++) {
			sgaddr = ddi_get64(acc,
			    &sg->SgEntry64[i].SgAddress);
			aac_printf(softs, CE_NOTE,
			    "     %d: 0x%08x.%08x/%d", i,
			    AAC_MS32(sgaddr), AAC_LS32(sgaddr),
			    ddi_get32(acc, &sg->SgEntry64[i]. \
			    SgByteCount));
		}
		return;
	}

	case RawIo: {
		struct aac_raw_io *io = (struct aac_raw_io *)fibp->data;
		struct aac_sg_tableraw *sg = &io->SgMapRaw;
		uint32_t sgcount = ddi_get32(acc, &sg->SgCount);
		uint64_t sgaddr;

		aac_printf(softs, CE_NOTE,
		    "FIB> RawIo Container %d  0x%llx/%d 0x%x",
		    ddi_get16(acc, &io->ContainerId),
		    ddi_get64(acc, &io->BlockNumber),
		    ddi_get32(acc, &io->ByteCount),
		    ddi_get16(acc, &io->Flags));
		for (i = 0; i < sgcount; i++) {
			sgaddr = ddi_get64(acc, &sg->SgEntryRaw[i].SgAddress);
			aac_printf(softs, CE_NOTE, "     %d: 0x%08x.%08x/%d", i,
			    AAC_MS32(sgaddr), AAC_LS32(sgaddr),
			    ddi_get32(acc, &sg->SgEntryRaw[i].SgByteCount));
		}
		return;
	}

	case ClusterCommand:
		sub_cmd = ddi_get32(acc,
		    (void *)&(((uint32_t *)(void *)fibp->data)[0]));
		subcmdstr = aac_cmd_name(sub_cmd, aac_cl_subcmds);
		break;

	case AifRequest:
		sub_cmd = ddi_get32(acc,
		    (void *)&(((uint32_t *)(void *)fibp->data)[0]));
		subcmdstr = aac_cmd_name(sub_cmd, aac_aif_subcmds);
		break;

	default:
		break;
	}

	fib_size = ddi_get16(acc, &(fibp->Header.Size));
	if (subcmdstr)
		aac_printf(softs, CE_NOTE, "FIB> %s, sz=%d",
		    subcmdstr, fib_size);
	else if (cmdstr && sub_cmd == (uint32_t)-1)
		aac_printf(softs, CE_NOTE, "FIB> %s, sz=%d",
		    cmdstr, fib_size);
	else if (cmdstr)
		aac_printf(softs, CE_NOTE, "FIB> %s: Unknown(0x%x), sz=%d",
		    cmdstr, sub_cmd, fib_size);
	else
		aac_printf(softs, CE_NOTE, "FIB> Unknown(0x%x), sz=%d",
		    fib_cmd, fib_size);
}

static void
aac_print_aif(struct aac_softstate *softs, struct aac_aif_command *aif)
{
	int aif_command;
	uint32_t aif_seqnumber;
	int aif_en_type;
	char *str;

	aif_command = LE_32(aif->command);
	aif_seqnumber = LE_32(aif->seqNumber);
	aif_en_type = LE_32(aif->data.EN.type);

	switch (aif_command) {
	case AifCmdEventNotify:
		str = aac_cmd_name(aif_en_type, aac_aifens);
		if (str)
			aac_printf(softs, CE_NOTE, "AIF! %s", str);
		else
			aac_printf(softs, CE_NOTE, "AIF! Unknown(0x%x)",
			    aif_en_type);
		break;

	case AifCmdJobProgress:
		switch (LE_32(aif->data.PR[0].status)) {
		case AifJobStsSuccess:
			str = "success"; break;
		case AifJobStsFinished:
			str = "finished"; break;
		case AifJobStsAborted:
			str = "aborted"; break;
		case AifJobStsFailed:
			str = "failed"; break;
		case AifJobStsSuspended:
			str = "suspended"; break;
		case AifJobStsRunning:
			str = "running"; break;
		default:
			str = "unknown"; break;
		}
		aac_printf(softs, CE_NOTE,
		    "AIF! JobProgress (%d) - %s (%d, %d)",
		    aif_seqnumber, str,
		    LE_32(aif->data.PR[0].currentTick),
		    LE_32(aif->data.PR[0].finalTick));
		break;

	case AifCmdAPIReport:
		aac_printf(softs, CE_NOTE, "AIF! APIReport (%d)",
		    aif_seqnumber);
		break;

	case AifCmdDriverNotify:
		aac_printf(softs, CE_NOTE, "AIF! DriverNotify (%d)",
		    aif_seqnumber);
		break;

	default:
		aac_printf(softs, CE_NOTE, "AIF! AIF %d (%d)",
		    aif_command, aif_seqnumber);
		break;
	}
}

#endif /* DEBUG */
