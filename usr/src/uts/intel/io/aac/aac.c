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
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

char _depends_on[] = "misc/scsi";

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

#define	AACOFFSET(type, member)	((size_t)(&((type *)0)->member))
#define	AAC_TRAN2SOFTS(tran) ((struct aac_softstate *)(tran)->tran_hba_private)
#define	AAC_DIP2TRAN(dip)	((scsi_hba_tran_t *)ddi_get_driver_private(dip))
#define	AAC_DIP2SOFTS(dip)	(AAC_TRAN2SOFTS(AAC_DIP2TRAN(dip)))
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

#define	AAC_MIR_SIZE(softs, mir) \
	(((softs)->flags & AAC_FLAGS_LBA_64BIT) ? \
	(uint64_t)(mir)->MntObj.Capacity + \
	((uint64_t)(mir)->MntObj.CapacityHigh << 32) : \
	(uint64_t)(mir)->MntObj.Capacity)

/* The last entry of aac_cards[] is for unknown cards */
#define	AAC_UNKNOWN_CARD \
	(sizeof (aac_cards) / sizeof (struct aac_card_type) - 1)
#define	CARD_IS_UNKNOWN(i)	(i == AAC_UNKNOWN_CARD)
#define	BUF_IS_READ(bp)		((bp)->b_flags & B_READ)
#define	AAC_IS_Q_EMPTY(q)	((q)->q_head == NULL)
#define	AAC_CMDQ(acp)		(!((acp)->flags & AAC_CMD_SYNC))

#define	PCI_MEM_GET32(softs, off) \
	ddi_get32((softs)->pci_mem_handle, \
	    (uint32_t *)((softs)->pci_mem_base_vaddr + (off)))
#define	PCI_MEM_PUT32(softs, off, val) \
	ddi_put32((softs)->pci_mem_handle, \
	    (uint32_t *)((softs)->pci_mem_base_vaddr + (off)), \
	    (uint32_t)(val))
/* Write host data at valp to device mem[i][off] repeatedly count times */
#define	PCI_MEM_REP_PUT8(softs, off, valp, count) \
	ddi_rep_put8((softs)->pci_mem_handle, (uint8_t *)(valp), \
	    (uint8_t *)((softs)->pci_mem_base_vaddr + (off)), \
	    count, DDI_DEV_AUTOINCR)

#define	AAC_ENABLE_INTR(softs) { \
		if (softs->flags & AAC_FLAGS_NEW_COMM) \
			PCI_MEM_PUT32(softs, AAC_OIMR, ~AAC_DB_INTR_NEW); \
		else \
			PCI_MEM_PUT32(softs, AAC_OIMR, ~AAC_DB_INTR_BITS); \
	}

#define	AAC_DISABLE_INTR(softs)		PCI_MEM_PUT32(softs, AAC_OIMR, ~0)
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

/* Operations to init FIB */
#define	AAC_SET_FIBSIZE		0
#define	AAC_SET_SGTABLE		1
#define	AAC_SET_BLKNO		2
#define	AAC_SET_DISKNO		3

#define	AAC_THROTTLE_DRAIN	-1

#define	AAC_QUIESCE_TICK	1	/* 1 second */
#define	AAC_QUIESCE_TIMEOUT	60	/* 60 seconds */
#define	AAC_DEFAULT_TICK	10	/* 10 seconds */

/* Poll time for aac_do_poll_io() */
#define	AAC_POLL_TIME		60	/* 60 seconds */

/*
 * Hardware access functions
 */
static int aac_rx_get_fwstatus(struct aac_softstate *);
static int aac_rx_get_mailbox(struct aac_softstate *, int);
static void aac_rx_set_mailbox(struct aac_softstate *, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t);
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

/*
 * Interrupt handler functions
 */
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
static int aac_get_containers(struct aac_softstate *);
static int aac_alloc_comm_space(struct aac_softstate *);
static int aac_setup_comm_space(struct aac_softstate *);
static void aac_free_comm_space(struct aac_softstate *);
static int aac_hba_setup(struct aac_softstate *);

/*
 * Sync FIB operation functions
 */
int aac_sync_mbcommand(struct aac_softstate *, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t *);
static int aac_sync_fib(struct aac_softstate *, uint16_t, struct aac_fib *,
    uint16_t);
static struct aac_fib *aac_grab_sync_fib(struct aac_softstate *);
static void aac_release_sync_fib(struct aac_softstate *);

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
static void aac_destroy_fibs(struct aac_softstate *);
static struct aac_slot *aac_get_slot(struct aac_softstate *);
static void aac_release_slot(struct aac_softstate *, struct aac_slot *);
static int aac_alloc_fib(struct aac_softstate *, struct aac_slot *);
static void aac_free_fib(struct aac_slot *);

/*
 * Internal functions
 */
static void aac_cmd_fib_header(struct aac_softstate *, struct aac_cmd *);
static void aac_cmd_fib_rawio(struct aac_softstate *, struct aac_cmd *, int);
static void aac_cmd_fib_brw64(struct aac_softstate *, struct aac_cmd *, int);
static void aac_cmd_fib_brw(struct aac_softstate *, struct aac_cmd *, int);
static void aac_start_waiting_io(struct aac_softstate *);
static void aac_drain_comp_q(struct aac_softstate *);
int aac_do_io(struct aac_softstate *, struct aac_cmd *);
static int aac_do_poll_io(struct aac_softstate *, struct aac_cmd *);
static int aac_do_sync_io(struct aac_softstate *, struct aac_cmd *);
static int aac_send_command(struct aac_softstate *, struct aac_slot *);
static void aac_cmd_timeout(struct aac_softstate *);
static int aac_dma_sync_ac(struct aac_cmd *);
static int aac_shutdown(struct aac_softstate *);
static int aac_reset_adapter(struct aac_softstate *);
static int aac_do_quiesce(struct aac_softstate *softs);
static int aac_do_unquiesce(struct aac_softstate *softs);
static void aac_unhold_bus(struct aac_softstate *, int);
static void aac_set_throttle(struct aac_softstate *, struct aac_container *,
    int, int);

/*
 * Adapter Initiated FIB handling function
 */
static int aac_handle_aif(struct aac_softstate *, struct aac_fib *);

/*
 * Timeout handling thread function
 */
static void aac_daemon(void *);

/*
 * IOCTL interface related functions
 */
static int aac_open(dev_t *, int, int, cred_t *);
static int aac_close(dev_t, int, int, cred_t *);
static int aac_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern int aac_do_ioctl(struct aac_softstate *, int, intptr_t, int);

/*
 * FMA Prototypes
 */
static void aac_fm_init(struct aac_softstate *);
static void aac_fm_fini(struct aac_softstate *);
static int aac_fm_error_cb(dev_info_t *, ddi_fm_error_t *, const void *);
int aac_check_acc_handle(ddi_acc_handle_t);
int aac_check_dma_handle(ddi_dma_handle_t);
void aac_fm_ereport(struct aac_softstate *, char *);

#ifdef DEBUG
/*
 * UART	debug output support
 */

#define	AAC_PRINT_BUFFER_SIZE		512
#define	AAC_PRINT_TIMEOUT		250	/* 1/4 sec. = 250 msec. */

#define	AAC_FW_DBG_STRLEN_OFFSET	0x00
#define	AAC_FW_DBG_FLAGS_OFFSET		0x04
#define	AAC_FW_DBG_BLED_OFFSET		0x08
#define	AAC_FW_DBG_FLAGS_NO_HEADERS	0x01

static int aac_get_fw_debug_buffer(struct aac_softstate *);
static void aac_print_scmd(struct aac_softstate *, struct aac_cmd *);
static void aac_print_aif(struct aac_softstate *, struct aac_aif_command *);

static char aac_prt_buf[AAC_PRINT_BUFFER_SIZE];
static kmutex_t aac_prt_mutex;
_NOTE(MUTEX_PROTECTS_DATA(aac_prt_mutex, aac_prt_buf))

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
	nodev,
	nulldev,
	nulldev,
	aac_attach,
	aac_detach,
	aac_reset,
	&aac_cb_ops,
	NULL,
	NULL
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
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
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
	DDI_DMA_FLAGERR	/* DMA transfer flags */
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
_NOTE(SCHEME_PROTECTS_DATA("unique per aac_cmd", aac_fib ddi_dma_cookie_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per aac_fib", aac_blockread aac_blockwrite \
    aac_blockread64 aac_raw_io aac_sg_entry aac_sg_entry64 aac_sg_entryraw \
    aac_sg_table aac_srb))
_NOTE(SCHEME_PROTECTS_DATA("unique to sync fib and cdb", scsi_inquiry))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device scsi_address))
_NOTE(SCHEME_PROTECTS_DATA("local data", aac_Container))

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
	softs->card = AAC_UNKNOWN_CARD;
#ifdef DEBUG
	softs->debug_flags = aac_debug_flags;
#endif

	/* Check the card type */
	if (aac_check_card_type(softs) == AACERR) {
		AACDB_PRINT(softs, CE_WARN, "Card not supported");
		goto error;
	}
	/* We have found the right card and everything is OK */
	attach_state |= AAC_ATTACH_CARD_DETECTED;

	/*
	 * Initialize FMA
	 */
	softs->fm_capabilities = ddi_getprop(DDI_DEV_T_ANY, softs->devinfo_p,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	aac_fm_init(softs);

	/* Map PCI mem space */
	if (ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&softs->pci_mem_base_vaddr, 0,
	    softs->map_size_min, &aac_acc_attr,
	    &softs->pci_mem_handle) != DDI_SUCCESS)
		goto error;

	softs->map_size = softs->map_size_min;
	attach_state |= AAC_ATTACH_PCI_MEM_MAPPED;

	AAC_DISABLE_INTR(softs);

	if (ddi_intr_hilevel(dip, 0)) {
		AACDB_PRINT(softs, CE_WARN,
		    "High level interrupt is not supported!");
		goto error;
	}

	/* Init mutexes */
	if (ddi_get_iblock_cookie(dip, 0, &softs->iblock_cookie) !=
	    DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Can not get interrupt block cookie!");
		goto error;
	}
	mutex_init(&softs->sync_mode.mutex, NULL,
	    MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->q_comp_mutex, NULL,
	    MUTEX_DRIVER, (void *)softs->iblock_cookie);
	cv_init(&softs->event, NULL, CV_DRIVER, NULL);
	mutex_init(&softs->aifq_mutex, NULL,
	    MUTEX_DRIVER, (void *)softs->iblock_cookie);
	cv_init(&softs->aifv, NULL, CV_DRIVER, NULL);
	cv_init(&softs->drain_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&softs->io_lock, NULL, MUTEX_DRIVER,
	    (void *)softs->iblock_cookie);
	attach_state |= AAC_ATTACH_KMUTEX_INITED;

	/*
	 * Everything has been set up till now,
	 * we will do some common attach.
	 */
	if (aac_common_attach(softs) == AACERR)
		goto error;
	attach_state |= AAC_ATTACH_COMM_SPACE_SETUP;

	/* Init the cmd queues */
	for (i = 0; i < AAC_CMDQ_NUM; i++)
		aac_cmd_initq(&softs->q_wait[i]);
	aac_cmd_initq(&softs->q_busy);
	aac_cmd_initq(&softs->q_comp);

	if (aac_hba_setup(softs) != AACOK)
		goto error;
	attach_state |= AAC_ATTACH_SCSI_TRAN_SETUP;

	/* Connect interrupt handlers */
	if (ddi_add_softintr(dip, DDI_SOFTINT_LOW, &softs->softint_id,
	    NULL, NULL, aac_softintr, (caddr_t)softs) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN,
		    "Can not setup soft interrupt handler!");
		goto error;
	}
	attach_state |= AAC_ATTACH_SOFT_INTR_SETUP;

	if (ddi_add_intr(dip, 0, &softs->iblock_cookie,
	    (ddi_idevice_cookie_t *)0,
	    (softs->flags & AAC_FLAGS_NEW_COMM) ?
	    aac_intr_new : aac_intr_old, (caddr_t)softs) != DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN, "Can not setup interrupt handler!");
		goto error;
	}
	attach_state |= AAC_ATTACH_HARD_INTR_SETUP;

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

	aac_unhold_bus(softs, AAC_IOCMD_SYNC | AAC_IOCMD_ASYNC);
	softs->state = AAC_STATE_RUN;

	/* Create a thread for command timeout */
	softs->timeout_id = timeout(aac_daemon, (void *)softs,
	    (60 * drv_usectohz(1000000)));

	/* Common attach is OK, so we are attached! */
	AAC_ENABLE_INTR(softs);
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
	if (attach_state & AAC_ATTACH_HARD_INTR_SETUP)
		ddi_remove_intr(dip, 0, softs->iblock_cookie);
	if (attach_state & AAC_ATTACH_SOFT_INTR_SETUP)
		ddi_remove_softintr(softs->softint_id);
	if (attach_state & AAC_ATTACH_KMUTEX_INITED) {
		mutex_destroy(&softs->sync_mode.mutex);
		mutex_destroy(&softs->q_comp_mutex);
		cv_destroy(&softs->event);
		mutex_destroy(&softs->aifq_mutex);
		cv_destroy(&softs->aifv);
		cv_destroy(&softs->drain_cv);
		mutex_destroy(&softs->io_lock);
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

	mutex_exit(&softs->io_lock);
	(void) untimeout(softs->timeout_id);
	mutex_enter(&softs->io_lock);
	softs->timeout_id = 0;

	ddi_remove_minor_node(dip, "aac");
	ddi_remove_minor_node(dip, "scsi");
	ddi_remove_minor_node(dip, "devctl");

	mutex_exit(&softs->io_lock);
	ddi_remove_intr(dip, 0, softs->iblock_cookie);
	ddi_remove_softintr(softs->softint_id);

	aac_common_detach(softs);

	(void) scsi_hba_detach(dip);
	scsi_hba_tran_free(tran);

	mutex_destroy(&softs->sync_mode.mutex);
	mutex_destroy(&softs->q_comp_mutex);
	cv_destroy(&softs->event);
	mutex_destroy(&softs->aifq_mutex);
	cv_destroy(&softs->aifv);
	cv_destroy(&softs->drain_cv);
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

	(void) aac_shutdown(softs);

	return (DDI_SUCCESS);
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
	struct aac_fib *fibp;
	struct aac_close_command *cc;
	int rval;

	fibp = aac_grab_sync_fib(softs);
	cc = (struct aac_close_command *)&fibp->data[0];

	cc->Command = VM_CloseAll;
	cc->ContainerId = 0xfffffffful;

	/* Flush all caches, set FW to write through mode */
	rval = aac_sync_fib(softs, ContainerCommand, fibp,
	    sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_close_command));

	AACDB_PRINT(softs, CE_NOTE,
	    "shutting down aac %s", (rval == AACOK) ? "ok" : "fail");

	aac_release_sync_fib(softs);
	return (rval);
}

static uint_t
aac_softintr(caddr_t arg)
{
	struct aac_softstate *softs = (struct aac_softstate *)arg;

	if (!AAC_IS_Q_EMPTY(&softs->q_comp)) {
		aac_drain_comp_q(softs);
		return (DDI_INTR_CLAIMED);
	} else {
		return (DDI_INTR_UNCLAIMED);
	}
}

/*
 * Setup auto sense data for pkt
 */
static void
aac_set_arq_data(struct scsi_pkt *pkt, uchar_t key,
    uchar_t add_code, uchar_t qual_code, uint64_t info)
{
	struct scsi_arq_status *arqstat;

	pkt->pkt_state |= STATE_GOT_STATUS | STATE_ARQ_DONE;

	arqstat = (struct scsi_arq_status *)(pkt->pkt_scbp);
	arqstat->sts_status.sts_chk = 1; /* CHECK CONDITION */
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

	cdbp = (union scsi_cdb *)acp->pkt->pkt_cdbp;
	err_blkno = AAC_GETGXADDR(acp->cmdlen, cdbp);
	aac_set_arq_data(acp->pkt, KEY_HARDWARE_ERROR, 0x00, 0x00, err_blkno);
}

/*
 * Setup auto sense data for UNIT ATTENTION
 */
/*ARGSUSED*/
static void
aac_set_arq_data_reset(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_container *dvp = acp->dvp;

	if (dvp->reset) {
		dvp->reset = 0;
		aac_set_arq_data(acp->pkt, KEY_UNIT_ATTENTION, 0x29, 0x02, 0);
	}
}

/*
 * Send a command to the adapter in New Comm. interface
 */
static int
aac_send_command(struct aac_softstate *softs, struct aac_slot *slotp)
{
	uint32_t index, device;

	index = PCI_MEM_GET32(softs, AAC_IQUE);
	if (index == 0xffffffffUL)
		index = PCI_MEM_GET32(softs, AAC_IQUE);
	if (index == 0xffffffffUL)
		return (AACERR);

	device = index;
	PCI_MEM_PUT32(softs, device,
	    (uint32_t)(slotp->fib_phyaddr & 0xfffffffful));
	device += 4;
	PCI_MEM_PUT32(softs, device, (uint32_t)(slotp->fib_phyaddr >> 32));
	device += 4;
	PCI_MEM_PUT32(softs, device, slotp->fibp->Header.Size);
	PCI_MEM_PUT32(softs, AAC_IQUE, index);
	return (AACOK);
}

static void
aac_end_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_container *dvp = acp->dvp;
	int q = AAC_CMDQ(acp);

	if (acp->slotp) { /* outstanding cmd */
		aac_release_slot(softs, acp->slotp);
		acp->slotp = NULL;
		if (dvp) {
			dvp->ncmds[q]--;
			if (dvp->throttle[q] == AAC_THROTTLE_DRAIN &&
			    dvp->ncmds[q] == 0 && q == AAC_CMDQ_ASYNC)
				aac_set_throttle(softs, dvp, q,
				    softs->total_slots);
		}
		softs->bus_ncmds[q]--;
		(void) aac_cmd_delete(&softs->q_busy, acp);
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
	ASSERT(acp != NULL && acp->slotp == slotp);

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

			state = slotp->fibp->Header.XferState;
			/*
			 * Update state for CPU not for device, no DMA sync
			 * needed
			 */
			slotp->fibp->Header.XferState =
			    state | AAC_FIBSTATE_DONEADAP;
			*((uint32_t *)(slotp->fibp->data)) = ST_OK;
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
		return (DDI_INTR_UNCLAIMED);
	}
	if (index != 0xfffffffful) {
		do {
			if ((index & AAC_SENDERADDR_MASK_AIF) == 0) {
				aac_handle_io(softs, index);
			} else if (index != 0xfffffffeul) {
				struct aac_fib *fibp;	/* FIB in AIF queue */
				int i;

				/*
				 * 0xfffffffe means that the controller wants
				 * more work, ignore it for now. Otherwise,
				 * AIF received.
				 */
				index &= ~2;

				mutex_enter(&softs->aifq_mutex);
				/* AIF received */
				fibp = &softs->comm_space->adapter_fibs[0];
				for (i = 0; i < sizeof (struct aac_fib)/4; ++i)
					((uint32_t *)fibp)[i] =
					    PCI_MEM_GET32(softs, index+i*4);

				if (aac_check_acc_handle(softs-> \
				    pci_mem_handle) == DDI_SUCCESS)
					(void) aac_handle_aif(softs, fibp);
				else
					ddi_fm_service_impact(softs->devinfo_p,
					    DDI_SERVICE_UNAFFECTED);
				mutex_exit(&softs->aifq_mutex);

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
	struct aac_softstate *softs = (struct aac_softstate *)arg;
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
			struct aac_fib *fibp;
			uint32_t addr, size;

			ASSERT((aif_idx >= 0) && (aif_idx < AAC_ADAPTER_FIBS));

			mutex_enter(&softs->aifq_mutex);
			fibp = &softs->comm_space->adapter_fibs[aif_idx];
			(void) aac_handle_aif(softs, fibp);
			mutex_exit(&softs->aifq_mutex);

			/* Complete AIF back to adapter with good status */
			if (fibp->Header.XferState & AAC_FIBSTATE_FROMADAP) {
				fibp->Header.XferState |= AAC_FIBSTATE_DONEHOST;
				((int *)fibp->data)[0] = ST_OK;
				if (fibp->Header.Size > sizeof (struct aac_fib))
					fibp->Header.Size =
					    sizeof (struct aac_fib);
			}

			/* Put the AIF response on the response queue */
			addr = softs->comm_space->adapter_fibs[aif_idx]. \
			    Header.SenderFibAddress;
			size = softs->comm_space->adapter_fibs[aif_idx]. \
			    Header.Size;
			softs->comm_space->adapter_fibs[aif_idx]. \
			    Header.ReceiverFibAddress = addr;
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
		    AACOFFSET(struct aac_comm_space, adapter_print_buf),
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
	struct aac_softstate *softs = (struct aac_softstate *)arg;
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
 * Set pkt_reason and OR in pkt_statistics flag
 */
static void
aac_set_pkt_reason(struct aac_softstate *softs, struct aac_cmd *acp,
    uchar_t reason, uint_t stat)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(softs))
#endif
	AACDB_PRINT(softs, CE_NOTE, "acp=0x%p, reason=%x, stat=%x",
	    (void *)acp, reason, stat);
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
	    STATE_SENT_CMD;
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

	ASSERT(!(acp->flags & AAC_CMD_SYNC));
	ASSERT(!(acp->flags & AAC_CMD_NO_CB));

	/*
	 * block_read/write has a similar response header, use blockread
	 * response for both.
	 */
	resp = (struct aac_blockread_response *)&slotp->fibp->data[0];
	if (resp->Status == ST_OK) {
		acp->pkt->pkt_resid = 0;
		acp->pkt->pkt_state |= STATE_XFERRED_DATA;
	} else {
		aac_set_arq_data_hwerr(acp);
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
	acp->fib_size = slotp->fibp->Header.Size;

	ASSERT(acp->fib_size <= softs->aac_max_fib_size);
	bcopy(slotp->fibp, acp->fibp, acp->fib_size);
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

	resp = (struct aac_synchronize_reply *)&slotp->fibp->data[0];
	status = ddi_get32(acc, &resp->Status);
	if (status != CT_OK)
		aac_set_arq_data_hwerr(acp);
}

/*
 * Access PCI space to see if the driver can support the card
 */
static int
aac_check_card_type(struct aac_softstate *softs)
{
	ddi_acc_handle_t pci_config_handle;
	uint16_t vendid, subvendid, devid, subsysid;
	int card_index;
	uint32_t pci_cmd;

	/* Map pci configuration space */
	if ((pci_config_setup(softs->devinfo_p, &pci_config_handle)) !=
	    DDI_SUCCESS) {
		AACDB_PRINT(softs, CE_WARN, "Cannot setup pci config space");
		return (AACERR);
	}

	vendid = pci_config_get16(pci_config_handle, PCI_CONF_VENID);
	devid = pci_config_get16(pci_config_handle, PCI_CONF_DEVID);
	subvendid = pci_config_get16(pci_config_handle, PCI_CONF_SUBVENID);
	subsysid = pci_config_get16(pci_config_handle, PCI_CONF_SUBSYSID);
	card_index = 0;
	while (!CARD_IS_UNKNOWN(card_index)) {
		if ((aac_cards[card_index].vendor == vendid) &&
		    (aac_cards[card_index].device == devid) &&
		    (aac_cards[card_index].subvendor == subvendid) &&
		    (aac_cards[card_index].subsys == subsysid)) {
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
		if (vendid != 0x9005) {
			AACDB_PRINT(softs, CE_WARN,
			    "Unknown vendor 0x%x", vendid);
			goto error;
		}
		switch (devid) {
		case 0x285:
			softs->hwif = AAC_HWIF_I960RX;
			break;
		case 0x286:
			softs->hwif = AAC_HWIF_RKT;
			break;
		default:
			AACDB_PRINT(softs, CE_WARN,
			    "Unknown device \"pci9005,%x\"", devid);
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

	cmn_err(CE_NOTE,
	    "!aac driver %d.%02d.%02d-%d, found card: " \
	    "%s %s(pci0x%x.%x.%x.%x) at 0x%x",
	    AAC_DRIVER_MAJOR_VERSION,
	    AAC_DRIVER_MINOR_VERSION,
	    AAC_DRIVER_BUGFIX_LEVEL,
	    AAC_DRIVER_BUILD,
	    softs->vendor_name, softs->product_name,
	    vendid, devid, subvendid, subsysid,
	    softs->pci_mem_base_paddr);
	return (AACOK); /* card type detected */

error:
	pci_config_teardown(&pci_config_handle);
	return (AACERR); /* no matched card found */
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
	char *pci_mbr;
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
		cmn_err(CE_NOTE, "!Enable FIB map 4GB window");
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
		cmn_err(CE_NOTE, "!Enable SG map 64-bit address");
		softs->buf_dma_attr.dma_attr_addr_hi = 0xffffffffffffffffull;
		softs->buf_dma_attr.dma_attr_seg = 0xffffffffffffffffull;
		softs->flags |= AAC_FLAGS_SG_64BIT;
	}

	if (options & AAC_SUPPORTED_64BIT_ARRAYSIZE) {
		softs->flags |= AAC_FLAGS_ARRAY_64BIT;
		cmn_err(CE_NOTE, "!Enable 64-bit array size");
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
		if ((atu_size > softs->map_size) &&
		    (ddi_regs_map_setup(softs->devinfo_p, 1,
		    (caddr_t *)&pci_mbr, 0, atu_size, &aac_acc_attr,
		    &pci_handle) == DDI_SUCCESS)) {
			ddi_regs_map_free(&softs->pci_mem_handle);
			softs->pci_mem_handle = pci_handle;
			softs->pci_mem_base_vaddr = pci_mbr;
			softs->map_size = atu_size;
		}
		if (atu_size == softs->map_size) {
			softs->flags |= AAC_FLAGS_NEW_COMM;
			cmn_err(CE_NOTE, "!Enable New Comm. interface");
		}
	}

	/* Set FIB parameters */
	if (softs->flags & AAC_FLAGS_NEW_COMM) {
		softs->aac_max_fibs = max_fibs;
		softs->aac_max_fib_size = max_fib_size;
		softs->aac_max_sectors = max_sectors;
		softs->aac_sg_tablesize = sg_tablesize;

		softs->flags |= AAC_FLAGS_RAW_IO;
		cmn_err(CE_NOTE, "!Enable RawIO");
	} else {
		softs->aac_max_fibs =
		    (softs->flags & AAC_FLAGS_256FIBS) ? 256 : 512;
		softs->aac_max_fib_size = sizeof (struct aac_fib);
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
		cmn_err(CE_NOTE, "!Enable 64-bit array");
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

	/* Setup FIB operations for logical devices */
	if (softs->flags & AAC_FLAGS_RAW_IO)
		softs->aac_cmd_fib = aac_cmd_fib_rawio;
	else if (softs->flags & AAC_FLAGS_SG_64BIT)
		softs->aac_cmd_fib = aac_cmd_fib_brw64;
	else
		softs->aac_cmd_fib = aac_cmd_fib_brw;

	/* 64-bit LBA needs descriptor format sense data */
	softs->slen = sizeof (struct scsi_arq_status);
	if ((softs->flags & AAC_FLAGS_LBA_64BIT) &&
	    softs->slen < AAC_ARQ64_LENGTH)
		softs->slen = AAC_ARQ64_LENGTH;

	cmn_err(CE_NOTE,
	    "!max_fibs %d max_fibsize 0x%x max_sectors %d max_sg %d",
	    softs->aac_max_fibs, softs->aac_max_fib_size,
	    softs->aac_max_sectors, softs->aac_sg_tablesize);

	return (AACOK);
}

/*
 * The following function comes from Adaptec:
 *
 * Query adapter information and supplement adapter information
 */
static int
aac_get_adapter_info(struct aac_softstate *softs,
    struct aac_adapter_info *ainfr,
    struct aac_supplement_adapter_info *sinfr)
{
	struct aac_fib *fibp;
	struct aac_adapter_info *ainfp;
	struct aac_supplement_adapter_info *sinfp;

	fibp = aac_grab_sync_fib(softs);
	fibp->data[0] = 0;
	if (aac_sync_fib(softs, RequestAdapterInfo, fibp,
	    sizeof (struct aac_fib_header)) != AACOK) {
		AACDB_PRINT(softs, CE_WARN, "RequestAdapterInfo failed");
		aac_release_sync_fib(softs);
		return (AACERR);
	}
	ainfp = (struct aac_adapter_info *)fibp->data;
	if (ainfr) {
		*ainfr = *ainfp;
	}
	if (sinfr) {
		if (!(softs->support_opt &
		    AAC_SUPPORTED_SUPPLEMENT_ADAPTER_INFO)) {
			AACDB_PRINT(softs, CE_WARN,
			    "SupplementAdapterInfo not supported");
			aac_release_sync_fib(softs);
			return (AACERR);
		}
		fibp->data[0] = 0;
		if (aac_sync_fib(softs, RequestSupplementAdapterInfo, fibp,
		    sizeof (struct aac_fib_header)) != AACOK) {
			AACDB_PRINT(softs, CE_WARN,
			    "RequestSupplementAdapterInfo failed");
			aac_release_sync_fib(softs);
			return (AACERR);
		}
		sinfp = (struct aac_supplement_adapter_info *)fibp->data;
		*sinfr = *sinfp;
	}

	aac_release_sync_fib(softs);
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
	struct aac_fib *fibp;
	struct aac_Container *cmd;
	struct aac_Container_resp *resp;
	struct aac_cf_status_header *cfg_sts_hdr;
	uint32_t cfg_stat_action;
	int rval;

	fibp = aac_grab_sync_fib(softs);
	/* Get adapter config status */
	cmd = (struct aac_Container *)&fibp->data[0];

	bzero(cmd, sizeof (*cmd) - CT_PACKET_SIZE);
	cmd->Command = VM_ContainerConfig;
	cmd->CTCommand.command = CT_GET_CONFIG_STATUS;
	cmd->CTCommand.param[CNT_SIZE] = sizeof (struct aac_cf_status_header);
	rval = aac_sync_fib(softs, ContainerCommand, fibp,
	    sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_Container));
	resp = (struct aac_Container_resp *)cmd;
	cfg_sts_hdr = (struct aac_cf_status_header *)resp->CTResponse.data;

	if ((rval == AACOK) && (*(uint32_t *)resp == 0) &&
	    (resp->CTResponse.param[0] == CT_OK)) {
		cfg_stat_action = cfg_sts_hdr->action;

		/* Commit configuration if it's reasonable to do so. */
		if (cfg_stat_action <= CFACT_PAUSE) {
			bzero(cmd, sizeof (struct aac_Container) - \
			    CT_PACKET_SIZE);
			cmd->Command = VM_ContainerConfig;
			cmd->CTCommand.command = CT_COMMIT_CONFIG;
			rval = aac_sync_fib(softs, ContainerCommand, fibp,
			    sizeof (struct aac_fib_header) + \
			    sizeof (struct aac_Container));
			if ((rval == AACOK) && (*(uint32_t *)resp == 0) &&
			    (resp->CTResponse.param[0] == CT_OK))
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

	aac_release_sync_fib(softs);
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
	struct aac_slot *slotp;

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

	/* Clear out all interrupts */
	AAC_STATUS_CLR(softs, ~0);

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
	if (aac_get_fw_debug_buffer(softs) != AACOK) {
		cmn_err(CE_CONT, "?firmware UART trace not supported");
		softs->debug_flags &= ~AACDB_FLAGS_FW_PRINT;
	}
#endif

	/* Allocate slots */
	if ((softs->total_slots == 0) && (aac_create_slots(softs) != AACOK)) {
		cmn_err(CE_CONT, "?Fatal error: slots allocate failed");
		goto error;
	}
	AACDB_PRINT(softs, CE_NOTE, "%d slots allocated", softs->total_slots);

	/* Allocate FIBs */
	for (i = 0; i < softs->total_slots &&
	    softs->total_fibs < softs->aac_max_fibs; i++) {
		slotp = &(softs->io_slot[i]);
		if (slotp->fib_phyaddr)
			continue;
		if (aac_alloc_fib(softs, slotp) != AACOK)
			break;

		/* Insert the slot to the free slot list */
		aac_release_slot(softs, slotp);
		softs->total_fibs++;
	}
	if (softs->total_fibs == 0)
		goto error;
	AACDB_PRINT(softs, CE_NOTE, "%d fibs allocated", softs->total_fibs);

	/* Get adapter names */
	if (CARD_IS_UNKNOWN(softs->card)) {
		struct aac_supplement_adapter_info sinf;

		if (aac_get_adapter_info(softs, NULL, &sinf) != AACOK) {
			cmn_err(CE_CONT, "?Query adapter information failed");
		} else {
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
			AACDB_PRINT(softs, CE_NOTE,
			    "adapter: vendor = \"%s\", product = \"%s\"",
			    softs->vendor_name, softs->product_name);
		}
	}

	/* Perform acceptance of adapter-detected config changes if possible */
	if (aac_handle_adapter_config_issues(softs) != AACMPE_OK) {
		cmn_err(CE_CONT, "?Handle adapter config issues failed");
		aac_fm_ereport(softs, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_LOST);
		goto error;
	}

	/* Setup containers */
	if (aac_get_containers(softs) != AACOK) {
		cmn_err(CE_CONT, "?Fatal error: get container info error");
		goto error;
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

	(void) aac_shutdown(softs);

	aac_destroy_fibs(softs);
	aac_destroy_slots(softs);
	aac_free_comm_space(softs);
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
aac_sync_fib(struct aac_softstate *softs, uint16_t cmd,
    struct aac_fib *fibp, uint16_t fibsize)
{
	uint32_t status;
	int rval;

	/* Sync fib only supports 512 bytes */
	if (fibsize > AAC_FIB_SIZE)
		return (AACERR);

	/* Setup sync fib */
	fibp->Header.XferState =
	    AAC_FIBSTATE_HOSTOWNED |
	    AAC_FIBSTATE_INITIALISED |
	    AAC_FIBSTATE_EMPTY |
	    AAC_FIBSTATE_FROMHOST |
	    AAC_FIBSTATE_NORM;
	fibp->Header.Command = cmd;
	fibp->Header.StructType = AAC_FIBTYPE_TFIB;
	fibp->Header.Flags = 0;
	fibp->Header.Size = fibsize;
	fibp->Header.SenderSize = sizeof (struct aac_fib); /* syncfib 512B */
	fibp->Header.SenderFibAddress = 0;
	fibp->Header.ReceiverFibAddress = softs->sync_mode.fib_phyaddr;
	fibp->Header.SenderData = 0;

	(void) ddi_dma_sync(softs->comm_space_dma_handle,
	    AACOFFSET(struct aac_comm_space, sync_fib), AAC_FIB_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	/* Give the FIB to the controller, wait for a response. */
	rval = aac_sync_mbcommand(softs, AAC_MONKER_SYNCFIB,
	    fibp->Header.ReceiverFibAddress, 0, 0, 0, &status);
	if (rval == AACERR) {
		AACDB_PRINT(softs, CE_WARN,
		    "Send sync fib to controller failed");
		return (AACERR);
	}

	(void) ddi_dma_sync(softs->comm_space_dma_handle,
	    AACOFFSET(struct aac_comm_space, sync_fib), AAC_FIB_SIZE,
	    DDI_DMA_SYNC_FORCPU);

	if ((aac_check_acc_handle(softs->pci_mem_handle) != DDI_SUCCESS) ||
	    (aac_check_dma_handle(softs->comm_space_dma_handle) !=
	    DDI_SUCCESS)) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		return (AACERR);
	}

	return (AACOK);
}

static struct aac_fib *
aac_grab_sync_fib(struct aac_softstate *softs)
{
	_NOTE(MUTEX_ACQUIRED_AS_SIDE_EFFECT(&softs->sync_mode.mutex))
	mutex_enter(&softs->sync_mode.mutex);
	return (softs->sync_mode.fib);
}

static void
aac_release_sync_fib(struct aac_softstate *softs)
{
	_NOTE(LOCK_RELEASED_AS_SIDE_EFFECT(&softs->sync_mode.mutex))
	mutex_exit(&softs->sync_mode.mutex);
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
	uint32_t pi, ci;

	DBCALLED(softs, 2);

	ASSERT(queue == AAC_ADAP_NORM_CMD_Q || queue == AAC_ADAP_NORM_RESP_Q);

	/* Get the producer/consumer indices */
	(void) ddi_dma_sync(softs->comm_space_dma_handle,
	    (uint8_t *)softs->qtablep->qt_qindex[queue] - \
	    (uint8_t *)softs->comm_space, sizeof (uint32_t) * 2,
	    DDI_DMA_SYNC_FORCPU);
	if (aac_check_dma_handle(softs->comm_space_dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		return (AACERR);
	}

	pi = softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX];
	ci = softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX];

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
	(softs->qentries[queue] + pi)->aq_fib_size = fib_size;
	(softs->qentries[queue] + pi)->aq_fib_addr = fib_addr;

	/* Update producer index */
	softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX] = pi + 1;
	(void) ddi_dma_sync(softs->comm_space_dma_handle,
	    (uint8_t *)&softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX] - \
	    (uint8_t *)softs->comm_space, sizeof (uint32_t),
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
	uint32_t pi, ci;
	int unfull = 0;

	DBCALLED(softs, 2);

	ASSERT(idxp);

	/* Get the producer/consumer indices */
	(void) ddi_dma_sync(softs->comm_space_dma_handle,
	    (uint8_t *)softs->qtablep->qt_qindex[queue] - \
	    (uint8_t *)softs->comm_space, sizeof (uint32_t) * 2,
	    DDI_DMA_SYNC_FORCPU);
	pi = softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX];
	ci = softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX];

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
	(void) ddi_dma_sync(softs->comm_space_dma_handle,
	    (uint8_t *)(softs->qentries[queue] + pi) - \
	    (uint8_t *)softs->comm_space, sizeof (struct aac_queue_entry),
	    DDI_DMA_SYNC_FORCPU);
	if (aac_check_dma_handle(softs->comm_space_dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(softs->devinfo_p, DDI_SERVICE_UNAFFECTED);
		return (AACERR);
	}

	switch (queue) {
	case AAC_HOST_NORM_RESP_Q:
	case AAC_HOST_HIGH_RESP_Q:
		*idxp = (softs->qentries[queue] + ci)->aq_fib_addr;
		break;

	case AAC_HOST_NORM_CMD_Q:
	case AAC_HOST_HIGH_CMD_Q:
		*idxp = (softs->qentries[queue] + ci)->aq_fib_addr /
		    sizeof (struct aac_fib);
		break;

	default:
		cmn_err(CE_NOTE, "!Invalid queue in aac_fib_dequeue()");
		return (AACERR);
	}

	/* Update consumer index */
	softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX] = ci + 1;
	(void) ddi_dma_sync(softs->comm_space_dma_handle,
	    (uint8_t *)&softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX] - \
	    (uint8_t *)softs->comm_space, sizeof (uint32_t),
	    DDI_DMA_SYNC_FORDEV);

	if (unfull && aac_qinfo[queue].notify != 0)
		AAC_NOTIFY(softs, aac_qinfo[queue].notify);
	return (AACOK);
}


/*
 * Request information of the container cid
 */
static struct aac_mntinforesp *
aac_get_container_info(struct aac_softstate *softs, struct aac_fib *fibp,
    int cid)
{
	struct aac_mntinfo *mi;
	struct aac_mntinforesp *mir;

	mi = (struct aac_mntinfo *)&fibp->data[0];
	mi->Command = /* Use 64-bit LBA if enabled */
	    (softs->flags & AAC_FLAGS_LBA_64BIT) ?
	    VM_NameServe64 : VM_NameServe;
	mi->MntType = FT_FILESYS;
	mi->MntCount = cid;

	if (aac_sync_fib(softs, ContainerCommand, fibp,
	    sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_mntinfo)) == AACERR) {
		AACDB_PRINT(softs, CE_WARN, "Error probe container %d", cid);
		return (NULL);
	}

	mir = (struct aac_mntinforesp *)&fibp->data[0];
	if (mir->Status == ST_OK)
		return (mir);
	return (NULL);
}

static int
aac_get_container_uid(struct aac_softstate *softs, struct aac_fib *fibp,
    uint32_t cid, uint32_t *uid)
{
	struct aac_Container *ct;

	ct = (struct aac_Container *)&fibp->data[0];

	bzero(ct, sizeof (*ct) - CT_PACKET_SIZE);
	ct->Command = VM_ContainerConfig;
	ct->CTCommand.command = CT_CID_TO_32BITS_UID;
	ct->CTCommand.param[0] = cid;

	if (aac_sync_fib(softs, ContainerCommand, fibp,
	    sizeof (struct aac_fib_header) + \
	    sizeof (struct aac_Container)) == AACERR)
		return (AACERR);
	if (ct->CTCommand.param[0] != CT_OK)
		return (AACERR);

	*uid = ct->CTCommand.param[1];
	return (AACOK);
}

static void
aac_init_container(struct aac_softstate *softs, uint32_t cid, uint32_t uid,
    uint64_t size)
{
	struct aac_container *dvp = &softs->container[cid];

	dvp->valid = 1;
	dvp->cid = cid;
	dvp->uid = uid;
	dvp->size = size;
	dvp->locked = 0;
	dvp->deleted = 0;
}

static int
aac_get_containers(struct aac_softstate *softs)
{
	struct aac_fib *fibp;
	struct aac_mntinforesp *mir;
	int i, count, total;
	uint32_t uid;
	uint64_t size;

	bzero(softs->container, sizeof (softs->container));
	fibp = aac_grab_sync_fib(softs);

	/* Loop over possible containers */
	i = count = total = 0;
	do {
		/* Get container basic info */
		if ((mir = aac_get_container_info(softs, fibp, i)) == NULL)
			goto next;

		if (i == 0) /* the first time */
			count = mir->MntRespCount;

		if (mir->MntObj.VolType == CT_NONE)
			goto next;

		size = AAC_MIR_SIZE(softs, mir);
		AACDB_PRINT(softs, CE_NOTE, "Container #%d found: " \
		    "size=0x%x.%08x, type=%d, name=%s",
		    i,
		    mir->MntObj.CapacityHigh,
		    mir->MntObj.Capacity,
		    mir->MntObj.VolType,
		    mir->MntObj.FileSystemName);

		/* Get container UID */
		if (aac_get_container_uid(softs, fibp, i, &uid) == AACERR)
			goto next;
		AACDB_PRINT(softs, CE_CONT, "uid=0x%08x", uid);

		/* Init container */
		aac_init_container(softs, i, uid, size);
		total++;
next:
		i++;
	} while ((i < count) && (i < AAC_MAX_LD));

	softs->container_count = count;
	aac_release_sync_fib(softs);
	cmn_err(CE_CONT, "?Total %d container(s) found", total);

	return (AACOK);
}

/*
 * Do a rescan of all the possible containers and update the container list
 * with newly online/offline containers.
 */
static void
aac_rescan_containers(struct aac_softstate *softs)
{
	int cid;
	struct aac_container *dvp;
	struct aac_fib *fibp;
	int count;
	int found;

	DBCALLED(softs, 1);

	cid = found = 0;
	dvp = &softs->container[0];
	fibp = aac_grab_sync_fib(softs);

	do {
		struct aac_mntinforesp *mir;
		uint64_t ct_size;
		uint32_t uid;

		if ((mir = aac_get_container_info(softs, fibp, cid)) == NULL)
			goto next;

		count = mir->MntRespCount;
		if (mir->MntObj.VolType == CT_NONE)
			goto next;

		found = 1;
		ct_size = AAC_MIR_SIZE(softs, mir);
		if (dvp->valid == 0) {
			if (aac_get_container_uid(softs, fibp, cid,
			    &uid) == AACERR)
				goto next;

			AACDB_PRINT(softs, CE_NOTE,
			    ">>> Container %d added", cid);

			aac_init_container(softs, cid, uid, ct_size);
			if ((cid + 1) > softs->container_count)
				softs->container_count = cid + 1;
		} else {
			if (dvp->size != ct_size) {
				AACDB_PRINT(softs, CE_NOTE,
				    ">>> Container %u size changed to %"PRIu64,
				    cid, ct_size);
				dvp->size = ct_size;
			}
		}

next:
		if ((found == 0) && dvp->valid) {
			AACDB_PRINT(softs, CE_NOTE,
			    ">>> Container %d deleted", cid);
			dvp->valid = 0;
		}

		found = 0;
		cid++;
		dvp++;
	} while ((cid < count) && (cid < AAC_MAX_LD));

	if (count < softs->container_count) {
		for (dvp = &softs->container[count];
		    dvp < &softs->container[softs->container_count]; dvp++) {
			if (dvp->valid == 0)
				continue;
			AACDB_PRINT(softs, CE_NOTE, ">>> Container %d deleted",
			    dvp->cid);
			dvp->valid = 0;
		}
		softs->container_count = count;
	}

	aac_release_sync_fib(softs);
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
	    &aac_acc_attr,
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

	/* Setup sync FIB space */
	softs->sync_mode.fib = &softs->comm_space->sync_fib;
	softs->sync_mode.fib_phyaddr = softs->comm_space_phyaddr + \
	    AACOFFSET(struct aac_comm_space, sync_fib);

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
}

/*
 * Initialize the data structures that are required for the communication
 * interface to operate
 */
static int
aac_setup_comm_space(struct aac_softstate *softs)
{
	uint32_t comm_space_phyaddr;
	struct aac_adapter_init *initp;
	int qoffset;

	comm_space_phyaddr = softs->comm_space_phyaddr;

	/* Setup adapter init struct */
	initp = &softs->comm_space->init_data;
	bzero(initp, sizeof (struct aac_adapter_init));
	initp->InitStructRevision = AAC_INIT_STRUCT_REVISION;
	initp->HostElapsedSeconds = ddi_get_time();

	/* Setup new/old comm. specific data */
	if (softs->flags & AAC_FLAGS_RAW_IO) {
		initp->InitStructRevision = AAC_INIT_STRUCT_REVISION_4;
		initp->InitFlags = 0;
		if (softs->flags & AAC_FLAGS_NEW_COMM)
			initp->InitFlags |= AAC_INIT_FLAGS_NEW_COMM_SUPPORTED;
		/* Setup the preferred settings */
		initp->MaxIoCommands = softs->aac_max_fibs;
		initp->MaxIoSize = (softs->aac_max_sectors << 9);
		initp->MaxFibSize = softs->aac_max_fib_size;
	} else {
		/*
		 * Tells the adapter about the physical location of various
		 * important shared data structures
		 */
		initp->AdapterFibsPhysicalAddress = comm_space_phyaddr + \
		    AACOFFSET(struct aac_comm_space, adapter_fibs);
		initp->AdapterFibsVirtualAddress = 0;
		initp->AdapterFibAlign = sizeof (struct aac_fib);
		initp->AdapterFibsSize = AAC_ADAPTER_FIBS * \
		    sizeof (struct aac_fib);
		initp->PrintfBufferAddress = comm_space_phyaddr + \
		    AACOFFSET(struct aac_comm_space, adapter_print_buf);
		initp->PrintfBufferSize = AAC_ADAPTER_PRINT_BUFSIZE;
		initp->MiniPortRevision = AAC_INIT_STRUCT_MINIPORT_REVISION;
		initp->HostPhysMemPages = AAC_MAX_PFN;

		qoffset = (comm_space_phyaddr + \
		    AACOFFSET(struct aac_comm_space, qtable)) % \
		    AAC_QUEUE_ALIGN;
		if (qoffset)
			qoffset = AAC_QUEUE_ALIGN - qoffset;
		softs->qtablep = (struct aac_queue_table *) \
		    ((char *)&softs->comm_space->qtable + qoffset);
		initp->CommHeaderAddress = comm_space_phyaddr + \
		    AACOFFSET(struct aac_comm_space, qtable) + qoffset;

		/* Init queue table */
		softs->qtablep->qt_qindex[AAC_HOST_NORM_CMD_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_HOST_NORM_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_HOST_NORM_CMD_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_HOST_NORM_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_HOST_HIGH_CMD_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_HOST_HIGH_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_HOST_HIGH_CMD_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_HOST_HIGH_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_NORM_CMD_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_ADAP_NORM_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_NORM_CMD_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_ADAP_NORM_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_HIGH_CMD_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_ADAP_HIGH_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_HIGH_CMD_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_ADAP_HIGH_CMD_ENTRIES;
		softs->qtablep->qt_qindex[AAC_HOST_NORM_RESP_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_HOST_NORM_RESP_ENTRIES;
		softs->qtablep->qt_qindex[AAC_HOST_NORM_RESP_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_HOST_NORM_RESP_ENTRIES;
		softs->qtablep->qt_qindex[AAC_HOST_HIGH_RESP_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_HOST_HIGH_RESP_ENTRIES;
		softs->qtablep->qt_qindex[AAC_HOST_HIGH_RESP_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_HOST_HIGH_RESP_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_NORM_RESP_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_ADAP_NORM_RESP_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_NORM_RESP_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_ADAP_NORM_RESP_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_HIGH_RESP_Q] \
		    [AAC_PRODUCER_INDEX] = AAC_ADAP_HIGH_RESP_ENTRIES;
		softs->qtablep->qt_qindex[AAC_ADAP_HIGH_RESP_Q] \
		    [AAC_CONSUMER_INDEX] = AAC_ADAP_HIGH_RESP_ENTRIES;

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

	/* Send init structure to the card */
	if (aac_sync_mbcommand(softs, AAC_MONKER_INITSTRUCT,
	    comm_space_phyaddr + \
	    AACOFFSET(struct aac_comm_space, init_data),
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
	uint32_t uid = softs->container[tgt].uid;

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
			if (vpdp == NULL)
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
			if (vpdp == NULL)
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
			if (vpdp == NULL)
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
			idp[AAC_VPD_ID_LENGTH] = sp - &idp[AAC_VPD_ID_DATA];

			vpdp[AAC_VPD_PAGE_LENGTH] =
			    sp - &vpdp[AAC_VPD_PAGE_DATA];
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
		if (inqp == NULL)
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
	struct mode_format *page3p;
	struct mode_geometry *page4p;
	struct mode_header *headerp;
	unsigned int ncyl;

	if (!(bp && bp->b_un.b_addr && bp->b_bcount))
		return;

	if (bp->b_flags & (B_PHYS | B_PAGEIO))
		bp_mapin(bp);
	pkt->pkt_state |= STATE_XFERRED_DATA;
	pagecode = cdbp->cdb_un.sg.scsi[0];
	headerp = (struct mode_header *)(bp->b_un.b_addr);
	headerp->bdesc_length = MODE_BLK_DESC_LENGTH;

	switch (pagecode) {
	/* SBC-3 7.1.3.3 Format device page */
	case SD_MODE_SENSE_PAGE3_CODE:
		page3p = (struct mode_format *)((caddr_t)headerp +
		    MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
		page3p->mode_page.code = SD_MODE_SENSE_PAGE3_CODE;
		page3p->mode_page.length = sizeof (struct mode_format);
		page3p->data_bytes_sect = BE_16(AAC_SECTOR_SIZE);
		page3p->sect_track = BE_16(AAC_SECTORS_PER_TRACK);
		break;

	/* SBC-3 7.1.3.8 Rigid disk device geometry page */
	case SD_MODE_SENSE_PAGE4_CODE:
		page4p = (struct mode_geometry *)((caddr_t)headerp +
		    MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
		page4p->mode_page.code = SD_MODE_SENSE_PAGE4_CODE;
		page4p->mode_page.length = sizeof (struct mode_geometry);
		page4p->heads = AAC_NUMBER_OF_HEADS;
		page4p->rpm = BE_16(AAC_ROTATION_SPEED);
		ncyl = capacity / (AAC_NUMBER_OF_HEADS * AAC_SECTORS_PER_TRACK);
		page4p->cyl_lb = ncyl & 0xff;
		page4p->cyl_mb = (ncyl >> 8) & 0xff;
		page4p->cyl_ub = (ncyl >> 16) & 0xff;
		break;

	case MODEPAGE_CTRL_MODE: /* 64-bit LBA need large sense data */
		if (softs->flags & AAC_FLAGS_LBA_64BIT) {
			struct mode_control_scsi3 *mctl;

			mctl = (struct mode_control_scsi3 *)((caddr_t)headerp +
			    MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
			mctl->mode_page.code = MODEPAGE_CTRL_MODE;
			mctl->mode_page.length =
			    sizeof (struct mode_control_scsi3) -
			    sizeof (struct mode_page);
			mctl->d_sense = 1;
		} else {
			bzero(bp->b_un.b_addr, bp->b_bcount);
		}
		break;

	default:
		bzero(bp->b_un.b_addr, bp->b_bcount);
		break;
	}
}

/*ARGSUSED*/
static int
aac_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(tran);
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;
	struct aac_container *dvp;

	DBCALLED(softs, 2);

	if ((0 > tgt) || (tgt >= AAC_MAX_LD)) {
		AACDB_PRINT(softs, CE_NOTE,
		    "aac_tran_tgt_init: t%dL%d out", tgt, lun);
		return (DDI_FAILURE);
	}

	/*
	 * Only support container that has been detected and valid
	 */
	mutex_enter(&softs->io_lock);
	dvp = &softs->container[tgt];
	if (dvp->valid && lun == 0) {
		AACDB_PRINT_TRAN(softs, "aac_tran_tgt_init: t%dL%d ok",
		    tgt, lun);
		mutex_exit(&softs->io_lock);
		return (DDI_SUCCESS);
	} else {
		AACDB_PRINT_TRAN(softs, "aac_tran_tgt_init: t%dL%d",
		    tgt, lun);
		mutex_exit(&softs->io_lock);
		return (DDI_FAILURE);
	}
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

	if (rval & AAC_KERNEL_UP_AND_RUNNING)
		rval = 0;
	else if (rval & AAC_KERNEL_PANIC)
		rval = ((rval >> 16) & 0xff) + 1; /* avoid 0 as return value */
	else
		rval = -1;

	return (rval);
}

static void
aac_abort_iocmd(struct aac_softstate *softs, struct aac_cmd *acp,
    uchar_t reason)
{
	acp->flags |= AAC_CMD_ABORT;

	if (acp->pkt) {
		/*
		 * Each lun should generate a unit attention
		 * condition when reset.
		 * Phys. drives are treated as logical ones
		 * during error recovery.
		 */
		if (softs->flags & AAC_STATE_RESET)
			aac_set_arq_data_reset(softs, acp);

		switch (reason) {
		case CMD_TIMEOUT:
			aac_set_pkt_reason(softs, acp, CMD_TIMEOUT,
			    STAT_TIMEOUT | STAT_BUS_RESET);
			break;
		case CMD_RESET:
			/* aac support only RESET_ALL */
			aac_set_pkt_reason(softs, acp, CMD_RESET,
			    STAT_BUS_RESET);
			break;
		case CMD_ABORTED:
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
			if (softs->container[i].valid)
				softs->container[i].reset = 1;
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
	int rval = AACERR;

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
			fibp = aac_grab_sync_fib(softs);
			pc = (struct aac_pause_command *)&fibp->data[0];

			bzero(pc, sizeof (*pc));
			pc->Command = VM_ContainerConfig;
			pc->Type = CT_PAUSE_IO;
			pc->Timeout = 1;
			pc->Min = 1;
			pc->NoRescan = 1;

			(void) aac_sync_fib(softs, ContainerCommand, fibp,
			    sizeof (struct aac_fib_header) + \
			    sizeof (struct aac_pause_command));
			aac_release_sync_fib(softs);

			ddi_fm_service_impact(softs->devinfo_p,
			    DDI_SERVICE_LOST);
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

	rval = AACOK;

finish:
	AAC_ENABLE_INTR(softs);
	return (rval);
}

static void
aac_set_throttle(struct aac_softstate *softs, struct aac_container *dvp, int q,
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
				aac_set_throttle(softs, &softs->container[i],
				    q, 0);
		}
	}
}

static void
aac_unhold_bus(struct aac_softstate *softs, int iocmds)
{
	int i, q;

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
			softs->bus_throttle[q] = softs->total_slots;
			for (i = 0; i < AAC_MAX_LD; i++)
				aac_set_throttle(softs, &softs->container[i],
				    q, softs->total_slots);
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
	if (health == 0 && (softs->bus_ncmds[AAC_CMDQ_SYNC] ||
	    softs->bus_ncmds[AAC_CMDQ_ASYNC])) {
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
	}

	/*
	 * If a longer waiting time still can't drain all outstanding io
	 * commands, do IOP reset.
	 */
	if (softs->bus_ncmds[AAC_CMDQ_SYNC] ||
	    softs->bus_ncmds[AAC_CMDQ_ASYNC]) {
		if ((rval = aac_reset_adapter(softs)) != AACOK)
			softs->state |= AAC_STATE_DEAD;
	} else {
		rval = AACOK;
	}

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
	rval = (aac_do_reset(softs) == AACOK) ? 1 : 0;
	if (rval == 1 && !ddi_in_panic()) {
		aac_abort_iocmds(softs, AAC_IOCMD_OUTSTANDING | AAC_IOCMD_ASYNC,
		    NULL, CMD_RESET);
		aac_start_waiting_io(softs);
	} else {
		/* Abort IOCTL cmds when system panic or adapter dead */
		aac_abort_iocmds(softs, AAC_IOCMD_ALL, NULL, CMD_RESET);
	}
	mutex_exit(&softs->io_lock);

	aac_drain_comp_q(softs);
	return (rval);
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
	    ((union scsi_cdb *)acp->pkt->pkt_cdbp)->scc_cmd);
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

	dvp = acp->dvp;
	pkt = acp->pkt;
	cdbp = (union scsi_cdb *)pkt->pkt_cdbp;
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
			bcopy(&cap, bp->b_un.b_addr, 8);
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
				cap16.sc_capacity =
				    BE_64(dvp->size);
				cap16.sc_lbasize = BE_32(AAC_SECTOR_SIZE);

				aac_free_dmamap(acp);
				if (bp->b_flags & (B_PHYS | B_PAGEIO))
					bp_mapin(bp);
				bcopy(&cap16, bp->b_un.b_addr, cap_len);
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

	case SCMD_READ_G1: /* read_10 */
	case SCMD_WRITE_G1: /* write_10 */
		acp->blkno = (uint32_t)GETG1ADDR(cdbp);
do_io:
		if (acp->flags & AAC_CMD_DMA_VALID) {
			uint64_t cnt_size =
			    dvp->size;

			/*
			 * If LBA > array size AND rawio, the
			 * adapter may hang. So check it before
			 * sending.
			 * NOTE: (blkno + blkcnt) may overflow
			 */
			if ((acp->blkno < cnt_size) &&
			    ((acp->blkno + acp->bcount /
			    AAC_BLK_SIZE) <= cnt_size)) {
				softs->aac_cmd_fib(softs, acp,
				    AAC_SET_BLKNO);
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

	case SCMD_TEST_UNIT_READY:
	case SCMD_REQUEST_SENSE:
	case SCMD_FORMAT:
	case SCMD_START_STOP:
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

	case SCMD_SYNCHRONIZE_CACHE: {
		struct aac_synchronize_command *sync;

		/*
		 * Need a FIB to send a command (Flush) to the
		 * firmware, allocate it here. It will be freed
		 * at aac_tran_destroy_pkt().
		 */
		if (acp->fibp == NULL) {
			acp->fib_size = sizeof (struct aac_fib);
			acp->fib_kmsz = acp->fib_size;
			acp->fibp = kmem_alloc(acp->fib_kmsz, KM_SLEEP);
		}

		/* Fill Flush command */
		aac_cmd_fib_header(softs, acp);
		acp->fibp->Header.Size = sizeof (struct aac_fib_header) +
		    sizeof (struct aac_synchronize_command);
		acp->fibp->Header.Command = ContainerCommand;
		sync = (struct aac_synchronize_command *)&acp->fibp->data[0];
		sync->Command = VM_ContainerConfig;
		sync->Type = (uint32_t)CT_FLUSH_CACHE;
		sync->Cid = dvp->cid;
		sync->Count =
		    sizeof (((struct aac_synchronize_reply *)0)->Data);

		/* Sync cache */
		acp->flags |= AAC_CMD_NTAG;
		acp->ac_comp = aac_synccache_complete;
		rval = aac_do_io(softs, acp);
		break;
	}

	case SCMD_DOORLOCK:
		aac_free_dmamap(acp);
		if (pkt->pkt_cdbp[4] & 0x01)
			dvp->locked = 1;
		else
			dvp->locked = 0;
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
	struct aac_container *dvp = acp->dvp;
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
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;
	*pkt->pkt_scbp = 0; /* clear arq scsi_status */

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
	if (dvp->valid && ap->a_lun == 0 && !(softs->state & AAC_STATE_DEAD)) {
		rval = aac_tran_start_ld(softs, acp);
	} else {
		AACDB_PRINT(softs, CE_WARN,
		    "Cannot send cmd to target t%dL%d: %s",
		    ap->a_target, ap->a_lun,
		    (softs->state & AAC_STATE_DEAD) ?
		    "adapter dead" : "target invalid");
		rval = TRAN_FATAL_ERROR;
	}
	mutex_exit(&softs->io_lock);
	return (rval);
}

static int
aac_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	struct aac_container *dvp;
	int rval;

	DBCALLED(softs, 2);

	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT(softs, CE_WARN,
		    "GetCap> %s not supported: whom=%d", cap, whom);
		return (-1);
	}

	dvp = &softs->container[ap->a_target];
	mutex_enter(&softs->io_lock);
	if (!dvp->valid || (ap->a_lun != 0)) {
		mutex_exit(&softs->io_lock);
		AACDB_PRINT(softs, CE_WARN, "Bad target to getcap");
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ: /* auto request sense */
		rval = 1;
		break;
	case SCSI_CAP_GEOMETRY:
		rval = (AAC_NUMBER_OF_HEADS << 16) | AAC_SECTORS_PER_TRACK;
		break;
	case SCSI_CAP_SECTOR_SIZE:
		rval = AAC_SECTOR_SIZE;
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		/* Number of sectors */
		if (dvp->size > 0xffffffffull)
			rval = 0xfffffffful; /* 64-bit LBA */
		else
			rval = dvp->size;
		break;
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		rval = 1;
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
	struct aac_container *dvp;
	int rval;

	DBCALLED(softs, 2);

	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT(softs, CE_WARN,
		    "SetCap> %s not supported: whom=%d", cap, whom);
		return (-1);
	}

	dvp = &softs->container[ap->a_target];
	mutex_enter(&softs->io_lock);
	if (!dvp->valid || (ap->a_lun != 0)) {
		mutex_exit(&softs->io_lock);
		AACDB_PRINT(softs, CE_WARN, "Bad target to setcap");
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		rval = (value == 1) ? 1 : 0;
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		if (dvp->size > 0xffffffffull) {
			rval = -1; /* 64-bit LBA */
		} else {
			dvp->size = (uint_t)value;
			rval = 1;
		}
		break;
	case SCSI_CAP_SECTOR_SIZE:
		rval = 0;
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

	if (acp->fibp) {
		kmem_free(acp->fibp, acp->fib_kmsz);
		acp->fibp = NULL;
		acp->fib_kmsz = 0;
	}
	aac_free_dmamap(acp);
	ASSERT(acp->slotp == NULL);
	scsi_hba_pkt_free(ap, pkt);
}

static struct scsi_pkt *
aac_tran_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg)
{
	struct aac_softstate *softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	struct aac_cmd *acp, *new_acp;
	uint_t dma_flags = 0;
	int (*cb)(caddr_t);
	int kf;
	aac_cmd_fib_t aac_cmd_fib;
	int rval;

	DBCALLED(softs, 2);

	if (callback == SLEEP_FUNC) {
		cb = DDI_DMA_SLEEP;
		kf = KM_SLEEP;
	} else {
		cb = DDI_DMA_DONTWAIT;
		kf = KM_NOSLEEP;
	}

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

		/*
		 * We will still use this point to fake some
		 * infomation in tran_start
		 */
		acp->bp = bp;

		/* Set cmd flags according to pkt alloc flags */
		if (flags & PKT_CONSISTENT)
			acp->flags |= AAC_CMD_CONSISTENT;
		if (flags & PKT_DMA_PARTIAL)
			acp->flags |= AAC_CMD_DMA_PARTIAL;

		acp->dvp = &softs->container[ap->a_target];
		acp->ac_comp = aac_ld_complete;
	} else {
		acp = PKT2AC(pkt);
		new_acp = NULL;
	}

	if (bp == NULL || (bp->b_bcount == 0))
		return (pkt);

	/* We need to transfer data, so we alloc DMA resources for this pkt */
	if (!(acp->flags & AAC_CMD_DMA_VALID)) {

		ASSERT(new_acp != NULL); /* pkt is reused without init */

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
		rval = DDI_SUCCESS;
		if (!acp->buf_dma_handle)
			rval = ddi_dma_alloc_handle(softs->devinfo_p,
			    &softs->buf_dma_attr, cb, arg,
			    &acp->buf_dma_handle);
		if (rval != DDI_SUCCESS) {
			AACDB_PRINT(softs, CE_WARN,
			    "Can't allocate DMA handle, errno=%d", rval);
			goto error_out;
		}

		/* Bind buf */
		if ((((uintptr_t)bp->b_un.b_addr & AAC_DMA_ALIGN_MASK) == 0) &&
		    ((bp->b_bcount & AAC_DMA_ALIGN_MASK) == 0)) {
			rval = ddi_dma_buf_bind_handle(acp->buf_dma_handle,
			    bp, dma_flags, cb, arg,
			    &acp->cookie, &acp->left_cookien);
		} else {
			size_t bufsz;

			AACDB_PRINT_TRAN(softs,
			    "non-aligned buffer: addr=0x%p, cnt=%lu",
			    (void *)bp->b_un.b_addr, bp->b_bcount);
			if (bp->b_flags & (B_PAGEIO|B_PHYS))
				bp_mapin(bp);

			rval = ddi_dma_mem_alloc(acp->buf_dma_handle,
			    AAC_ROUNDUP(bp->b_bcount, AAC_DMA_ALIGN),
			    &aac_acc_attr, DDI_DMA_STREAMING,
			    cb, arg, &acp->abp, &bufsz, &acp->abh);

			if (rval != DDI_SUCCESS) {
				AACDB_PRINT(softs, CE_NOTE,
				    "Cannot alloc DMA to non-aligned buf");
				bioerror(bp, 0);
				goto error_out;
			}

			if (acp->flags & AAC_CMD_BUF_WRITE)
				bcopy(bp->b_un.b_addr, acp->abp, bp->b_bcount);

			rval = ddi_dma_addr_bind_handle(acp->buf_dma_handle,
			    NULL, acp->abp, bufsz, dma_flags, cb, arg,
			    &acp->cookie, &acp->left_cookien);
		}

		switch (rval) {
		case DDI_DMA_PARTIAL_MAP:
			acp->flags |= AAC_CMD_DMA_VALID;
			if (ddi_dma_numwin(acp->buf_dma_handle,
			    &acp->total_nwin) == DDI_FAILURE) {
				AACDB_PRINT(softs, CE_WARN,
				    "Cannot get number of DMA windows");
				bioerror(bp, 0);
				goto error_out;
			}
			AACDB_PRINT_TRAN(softs, "buf bind, %d segs",
			    acp->left_cookien);
			acp->cur_win = 0;
			break;

		case DDI_DMA_MAPPED:
			AACDB_PRINT_TRAN(softs, "buf bind, %d segs",
			    acp->left_cookien);
			acp->flags |= AAC_CMD_DMA_VALID;
			acp->cur_win = 0;
			acp->total_nwin = 1;
			break;

		case DDI_DMA_NORESOURCES:
			bioerror(bp, 0);
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot bind buf for DMA: DDI_DMA_NORESOURCES");
			goto error_out;
		case DDI_DMA_BADATTR:
		case DDI_DMA_NOMAPPING:
			bioerror(bp, EFAULT);
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot bind buf for DMA: DDI_DMA_NOMAPPING");
			goto error_out;
		case DDI_DMA_TOOBIG:
		default:
			bioerror(bp, EINVAL);
			AACDB_PRINT(softs, CE_WARN,
			    "Cannot bind buf for DMA: %d", rval);
			goto error_out;
		}
	}

	/* Move window to build s/g map */
	if (acp->left_cookien == 0) {
		if ((acp->cur_win + 1) < acp->total_nwin) {
			off_t off;
			size_t len;

			acp->cur_win++;
			rval = ddi_dma_getwin(acp->buf_dma_handle, acp->cur_win,
			    &off, &len, &acp->cookie, &acp->left_cookien);
			if (rval != DDI_SUCCESS) {
				AACDB_PRINT(softs, CE_WARN,
				    "ddi_dma_getwin() fail %d", rval);
				return (NULL);
			}
		} else {
			AACDB_PRINT(softs, CE_WARN, "Nothing to transfer");
			return (NULL);
		}
	}

	ASSERT(acp->left_cookien > 0);
	if (acp->left_cookien > softs->aac_sg_tablesize) {
		AACDB_PRINT(softs, CE_NOTE, "large cookiec received %d\n",
		    acp->left_cookien);
		bioerror(bp, EINVAL);
		goto error_out;
	}

	aac_cmd_fib = softs->aac_cmd_fib;

	aac_cmd_fib(softs, acp, AAC_SET_FIBSIZE);
	if (acp->fibp && acp->fib_kmsz < acp->fib_size) {
		kmem_free(acp->fibp, acp->fib_kmsz);
		acp->fibp = NULL;
		acp->fib_kmsz = 0;
	}
	if (acp->fibp == NULL) {
		acp->fibp = kmem_alloc(acp->fib_size, kf);
		if (acp->fibp == NULL) {
			AACDB_PRINT(softs, CE_WARN,
			    "fail to kmem_alloc memory for ac fib");
			bioerror(bp, ENOMEM);
			goto error_out;
		}
		acp->fib_kmsz = acp->fib_size;
	}
	aac_cmd_fib(softs, acp, AAC_SET_SGTABLE);
	/*
	 * Note: The old DMA engine do not correctly handle
	 * dma_attr_maxxfer attribute. So we have to ensure
	 * it by ourself.
	 */
	if (acp->bcount > softs->buf_dma_attr.dma_attr_maxxfer) {
		AACDB_PRINT(softs, CE_NOTE, "large xfer size received %d\n",
		    acp->bcount);
		bioerror(bp, EINVAL);
		goto error_out;
	}

	acp->total_xfer += acp->bcount;

	/* Return remaining byte count */
	pkt->pkt_resid = bp->b_bcount - acp->total_xfer;

	AACDB_PRINT_TRAN(softs, "bp=0x%p, xfered=%d/%d, resid=%d",
	    (void *)bp->b_un.b_addr, (int)acp->total_xfer,
	    (int)bp->b_bcount, (int)pkt->pkt_resid);

	ASSERT((pkt->pkt_resid >= 0) ||
	    ((bp->b_bcount & AAC_DMA_ALIGN_MASK) != 0));

	if (pkt->pkt_resid < 0)
		pkt->pkt_resid = 0;
	return (pkt);

error_out:
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
	rval = scsi_hba_attach_setup(softs->devinfo_p, &softs->buf_dma_attr,
	    hba_tran, 0);
	if (rval != DDI_SUCCESS) {
		scsi_hba_tran_free(hba_tran);
		AACDB_PRINT(softs, CE_WARN, "aac_hba_setup failed");
		return (AACERR);
	}

	return (AACOK);
}

/*
 * FIB setup operations
 */

/*
 * Init FIB header
 */
static void
aac_cmd_fib_header(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_fib *fibp = acp->fibp;

	fibp->Header.XferState = (uint32_t)(
	    AAC_FIBSTATE_HOSTOWNED |
	    AAC_FIBSTATE_INITIALISED |
	    AAC_FIBSTATE_EMPTY |
	    AAC_FIBSTATE_FROMHOST |
	    AAC_FIBSTATE_REXPECTED |
	    AAC_FIBSTATE_NORM |
	    AAC_FIBSTATE_ASYNC |
	    AAC_FIBSTATE_FAST_RESPONSE /* enable fast io */);
	fibp->Header.StructType = AAC_FIBTYPE_TFIB;
	fibp->Header.Flags = 0; /* don't care */
	fibp->Header.SenderSize = softs->aac_max_fib_size;
	fibp->Header.SenderData = 0; /* don't care */
}

/*
 * Init FIB for raw IO command
 */
static void
aac_cmd_fib_rawio(struct aac_softstate *softs, struct aac_cmd *acp, int op)
{
	struct aac_fib *fibp = acp->fibp;
	struct aac_raw_io *io = (struct aac_raw_io *)&fibp->data[0];

	if (op == AAC_SET_FIBSIZE) {
		acp->fib_size = sizeof (struct aac_fib_header) + \
		    sizeof (struct aac_raw_io) + (acp->left_cookien - 1) * \
		    sizeof (struct aac_sg_entryraw);
	} else if (op == AAC_SET_BLKNO) {
		_NOTE(ASSUMING_PROTECTED(*acp->dvp))

		io->BlockNumber = acp->blkno;
		io->ContainerId = acp->dvp->cid;
	} else if (op == AAC_SET_SGTABLE) {
		struct aac_sg_entryraw *sgentp = io->SgMapRaw.SgEntryRaw;

		aac_cmd_fib_header(softs, acp);
		fibp->Header.Size = acp->fib_size;
		fibp->Header.Command = RawIo;

		io->Flags = (acp->flags & AAC_CMD_BUF_READ) ? 1 : 0;
		io->BpTotal = 0;
		io->BpComplete = 0;

		/* Fill SG table */
		io->SgMapRaw.SgCount = acp->left_cookien;

		acp->bcount = 0;
		do {
			sgentp->SgAddress = acp->cookie.dmac_laddress;
			sgentp->SgByteCount = acp->cookie.dmac_size;
			sgentp->Next = 0;
			sgentp->Prev = 0;
			sgentp->Flags = 0;
			sgentp++;

			acp->bcount += acp->cookie.dmac_size;
			acp->left_cookien--;
			if (acp->left_cookien > 0)
				ddi_dma_nextcookie(acp->buf_dma_handle,
				    &acp->cookie);
			else
				break;
		/*CONSTCOND*/
		} while (1);

		io->ByteCount = acp->bcount;
	}
}

/* Init FIB for 64-bit block IO command */
static void
aac_cmd_fib_brw64(struct aac_softstate *softs, struct aac_cmd *acp, int op)
{
	struct aac_fib *fibp = acp->fibp;
	struct aac_blockread64 *br = (struct aac_blockread64 *)&fibp->data[0];

	if (op == AAC_SET_FIBSIZE) {
		acp->fib_size = sizeof (struct aac_fib_header) + \
		    sizeof (struct aac_blockread64) + \
		    (acp->left_cookien - 1) * \
		    sizeof (struct aac_sg_entry64);
	} else if (op == AAC_SET_BLKNO) {
		_NOTE(ASSUMING_PROTECTED(*acp->dvp))

		br->BlockNumber = (uint32_t)acp->blkno;
		br->ContainerId = acp->dvp->cid;
	} else if (op == AAC_SET_SGTABLE) {
		struct aac_sg_entry64 *sgentp = br->SgMap64.SgEntry64;

		aac_cmd_fib_header(softs, acp);
		fibp->Header.Size = acp->fib_size;
		fibp->Header.Command = ContainerCommand64;

		/*
		 * The definitions for aac_blockread64 and aac_blockwrite64
		 * are the same.
		 */
		br->Command = (acp->flags & AAC_CMD_BUF_READ) ?
		    VM_CtHostRead64 : VM_CtHostWrite64;
		br->Pad = 0;
		br->Flags = 0;

		/* Fill SG table */
		br->SgMap64.SgCount = acp->left_cookien;

		acp->bcount = 0;
		do {
			sgentp->SgAddress = acp->cookie.dmac_laddress;
			sgentp->SgByteCount = acp->cookie.dmac_size;
			sgentp++;

			acp->bcount += acp->cookie.dmac_size;
			acp->left_cookien--;
			if (acp->left_cookien > 0)
				ddi_dma_nextcookie(acp->buf_dma_handle,
				    &acp->cookie);
			else
				break;
		/*CONSTCOND*/
		} while (1);

		br->SectorCount = acp->bcount / AAC_BLK_SIZE;
	}
}

/* Init FIB for block IO command */
static void
aac_cmd_fib_brw(struct aac_softstate *softs, struct aac_cmd *acp, int op)
{
	struct aac_fib *fibp = acp->fibp;
	struct aac_blockread *br = (struct aac_blockread *)&fibp->data[0];

	if (op == AAC_SET_FIBSIZE) {
		if (acp->flags & AAC_CMD_BUF_READ) {
			acp->fib_size = sizeof (struct aac_fib_header) + \
			    sizeof (struct aac_blockread) + \
			    (acp->left_cookien - 1) * \
			    sizeof (struct aac_sg_entry);
		} else {
			acp->fib_size = sizeof (struct aac_fib_header) + \
			    sizeof (struct aac_blockwrite) + \
			    (acp->left_cookien - 1) * \
			    sizeof (struct aac_sg_entry);
		}
	} else if (op == AAC_SET_BLKNO) {
		_NOTE(ASSUMING_PROTECTED(*acp->dvp))

		/*
		 * aac_blockread and aac_blockwrite have the similar
		 * structure head, so use br for bw here
		 */
		br->BlockNumber = (uint32_t)acp->blkno;
		br->ContainerId = acp->dvp->cid;
	} else if (op == AAC_SET_SGTABLE) {
		struct aac_sg_table *sgmap;
		struct aac_sg_entry *sgentp;

		aac_cmd_fib_header(softs, acp);
		fibp->Header.Size = acp->fib_size;
		fibp->Header.Command = ContainerCommand;

		if (acp->flags & AAC_CMD_BUF_READ) {
			br->Command = VM_CtBlockRead;
			sgmap = &br->SgMap;
		} else {
			struct aac_blockwrite *bw = (struct aac_blockwrite *)br;

			bw->Command = VM_CtBlockWrite;
			bw->Stable = CUNSTABLE;
			sgmap = &bw->SgMap;
		}

		/* Fill SG table */
		sgmap->SgCount = acp->left_cookien;
		sgentp = sgmap->SgEntry;

		acp->bcount = 0;
		do {
			sgentp->SgAddress = acp->cookie.dmac_laddress;
			sgentp->SgByteCount = acp->cookie.dmac_size;
			sgentp++;

			acp->bcount += acp->cookie.dmac_size;
			acp->left_cookien--;
			if (acp->left_cookien > 0)
				ddi_dma_nextcookie(acp->buf_dma_handle,
				    &acp->cookie);
			else
				break;
		/*CONSTCOND*/
		} while (1);

		br->ByteCount = acp->bcount;
	}
}

static int
aac_cmd_slot_bind(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp;

	if (slotp = aac_get_slot(softs)) {
		acp->slotp = slotp;
		slotp->acp = acp;
		acp->fibp->Header.ReceiverFibAddress = slotp->fib_phyaddr;
		acp->fibp->Header.SenderFibAddress = slotp->index << 2;
		bcopy(acp->fibp, slotp->fibp,
		    acp->fib_size); /* only copy data of needed length */
		(void) ddi_dma_sync(slotp->fib_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		return (AACOK);
	}
	return (AACERR);
}

static int
aac_bind_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_container *dvp = acp->dvp;
	int q = AAC_CMDQ(acp);

	if (dvp) {
		if (dvp->ncmds[q] < dvp->throttle[q]) {
			if (!(acp->flags & AAC_CMD_NTAG) ||
			    dvp->ncmds[q] == 0) {
do_bind:
				return (aac_cmd_slot_bind(softs, acp));
			}
			ASSERT(q == AAC_CMDQ_ASYNC);
			aac_set_throttle(softs, dvp, AAC_CMDQ_ASYNC,
			    AAC_THROTTLE_DRAIN);
		}
	} else {
		if (softs->bus_ncmds[q] < softs->bus_throttle[q])
			goto do_bind;
	}
	return (AACERR);
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

	if (softs->flags & AAC_FLAGS_NEW_COMM) {
		rval = aac_send_command(softs, slotp);
	} else {
		uint32_t addr, size;

		/*
		 * If fib can not be enqueued, the adapter is in an abnormal
		 * state, there will be no interrupt to us.
		 */
		addr = slotp->fibp->Header.ReceiverFibAddress;
		size = slotp->fibp->Header.Size;
		rval = aac_fib_enqueue(softs, AAC_ADAP_NORM_CMD_Q,
		    addr, size);
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
			(*pkt->pkt_comp)(pkt);
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
	    &aac_acc_attr,
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

	softs->io_slot = kmem_zalloc(sizeof (struct aac_slot) * \
	    softs->aac_max_fibs, KM_SLEEP);
	if (softs->io_slot == NULL) {
		AACDB_PRINT(softs, CE_WARN, "Cannot allocate slot");
		return (AACERR);
	}
	softs->total_slots = softs->aac_max_fibs;
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
			aac_cmd_timeout(softs);
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
aac_handle_aif(struct aac_softstate *softs, struct aac_fib *fibp)
{
	struct aac_aif_command *aif;
	int devcfg_needed;
	int current, next;

	if (fibp->Header.Command != AifRequest) {
		cmn_err(CE_NOTE, "!Unknown command from controller: 0x%x",
		    fibp->Header.Command);
		return (AACERR);
	}

	/* Update internal container state */
	aif = (struct aac_aif_command *)&fibp->data[0];

	AACDB_PRINT_AIF(softs, aif);

	devcfg_needed = 0;

	switch (aif->command) {
	case AifCmdDriverNotify: {
		int cid = aif->data.EN.data.ECC.container[0];

		switch (aif->data.EN.type) {
		case AifDenMorphComplete:
		case AifDenVolumeExtendComplete:
			if (softs->container[cid].valid)
				softs->devcfg_wait_on = AifEnConfigChange;
			break;
		}
		if (softs->devcfg_wait_on == aif->data.EN.type)
			devcfg_needed = 1;
		break;
	}

	case AifCmdEventNotify:
		switch (aif->data.EN.type) {
		case AifEnAddContainer:
		case AifEnDeleteContainer:
			softs->devcfg_wait_on = AifEnConfigChange;
			break;
		case AifEnContainerChange:
			if (!softs->devcfg_wait_on)
				softs->devcfg_wait_on = AifEnConfigChange;
			break;
		case AifEnContainerEvent:
			if (aif->data.EN.data.ECE.eventType ==
			    CT_PUP_MISSING_DRIVE)
				devcfg_needed = 1;
			break;
		}
		if (softs->devcfg_wait_on == aif->data.EN.type)
			devcfg_needed = 1;
		break;

	case AifCmdJobProgress:
		if (aif->data.PR[0].jd.type == AifJobCtrZero) {
			if ((aif->data.PR[0].currentTick ==
			    aif->data.PR[0].finalTick) ||
			    (aif->data.PR[0].status == AifJobStsSuccess))
				softs->devcfg_wait_on = AifEnContainerChange;
			else if ((aif->data.PR[0].currentTick == 0) &&
			    (aif->data.PR[0].status == AifJobStsRunning))
				softs->devcfg_wait_on = AifEnContainerChange;
		}
		break;
	}

	if (devcfg_needed)
		aac_rescan_containers(softs);

	/* Copy AIF data to AIF queue */
	current = softs->aifq_idx;
	next = (current + 1) % AAC_AIFQ_LENGTH;
	if (next == 0)
		softs->aifq_wrap = 1;
	bcopy(fibp, &softs->aifq[current], sizeof (struct aac_fib));

	/* Modify AIF contexts */
	if (softs->aifq_wrap) {
		struct aac_fib_context *ctx;

		for (ctx = softs->fibctx; ctx; ctx = ctx->next) {
			if (next == ctx->ctx_idx) {
				ctx->ctx_filled = 1;
			} else if (current == ctx->ctx_idx && ctx->ctx_filled) {
				ctx->ctx_idx = next;
				AACDB_PRINT(softs, CE_NOTE,
				    "-- AIF queue(%x) overrun", ctx->unique);
			}
		}
	}
	softs->aifq_idx = next;

	/* Wakeup applications */
	cv_broadcast(&softs->aifv);
	return (AACOK);
}

/*
 * Timeout recovery
 */
static void
aac_cmd_timeout(struct aac_softstate *softs)
{
	/*
	 * Besides the firmware in unhealthy state, an overloaded
	 * adapter may also incur pkt timeout.
	 * There is a chance for an adapter with a slower IOP to take
	 * longer than 60 seconds to process the commands, such as when
	 * to perform IOs. So the adapter is doing a build on a RAID-5
	 * while being required longer completion times should be
	 * tolerated.
	 */
	if (aac_do_reset(softs) == AACOK) {
		aac_abort_iocmds(softs, AAC_IOCMD_OUTSTANDING, NULL,
		    CMD_RESET);
		aac_start_waiting_io(softs);
	} else {
		/* Abort all waiting cmds when adapter is dead */
		aac_abort_iocmds(softs, AAC_IOCMD_ALL, NULL,
		    CMD_TIMEOUT);
	}
}

static void
aac_daemon(void *arg)
{
	struct aac_softstate *softs = (struct aac_softstate *)arg;
	struct aac_cmd *acp;

	DBCALLED(softs, 2);

	mutex_enter(&softs->io_lock);
	/* Check slot for timeout pkts */
	aac_timebase += aac_tick;
	for (acp = softs->q_busy.q_head; acp; acp = acp->next) {
		if (acp->timeout) {
			if (acp->timeout <= aac_timebase) {
				aac_cmd_timeout(softs);
				ddi_trigger_softintr(softs->softint_id);
			}
			break;
		}
	}

	if ((softs->state & AAC_STATE_RUN) && (softs->timeout_id != 0))
		softs->timeout_id = timeout(aac_daemon, (void *)softs,
		    (aac_tick * drv_usectohz(1000000)));
	mutex_exit(&softs->io_lock);
}

/*
 * Architecture dependent functions
 */
static int
aac_rx_get_fwstatus(struct aac_softstate *softs)
{
	return (PCI_MEM_GET32(softs, AAC_RX_FWSTATUS));
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
	return (PCI_MEM_GET32(softs, AAC_RKT_FWSTATUS));
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
		return (aac_do_ioctl(softs, cmd, arg, flag));
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

	/* Only register with IO Fault Services if we have some capability */
	if (softs->fm_capabilities) {
		/* Adjust access and dma attributes for FMA */
		aac_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		softs->buf_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
		softs->addr_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;

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
	} else {
		/* Clear FMA if no capabilities */
		aac_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		softs->buf_dma_attr.dma_attr_flags = 0;
		softs->addr_dma_attr.dma_attr_flags = 0;
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
				softs->debug_buf_offset = offset;
				softs->debug_header_size = mondrv_hdr_size;
				softs->debug_buf_size = mondrv_buf_size;
				softs->debug_fw_flags = 0;

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

	mutex_enter(&aac_prt_mutex);
	/*
	 * Set up parameters and call sprintf function to
	 * format the data
	 */
	va_start(args, fmt);
	(void) vsprintf(aac_prt_buf, fmt, args);
	va_end(args);

	/*
	 * Make sure the softs structure has been passed in
	 * for this section
	 */
	if ((softs != NULL) && (softs->debug_flags & AACDB_FLAGS_FW_PRINT) &&
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
	if (softs != NULL) {
		if (softs->debug_flags & AACDB_FLAGS_KERNEL_PRINT) {
			if (softs->debug_fw_flags & AAC_FW_DBG_FLAGS_NO_HEADERS)
				cmn_err(lev, "%s", aac_prt_buf);
			else
				cmn_err(lev, "%s.%d: %s", softs->vendor_name,
				    softs->instance, aac_prt_buf);
		}
	} else if (aac_debug_flags & AACDB_FLAGS_KERNEL_PRINT) {
		cmn_err(lev, "%s", aac_prt_buf);
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
	int ctl = ddi_get_instance(softs->devinfo_p);
	int tgt = ap->a_target;
	int lun = ap->a_lun;
	union scsi_cdb *cdbp = (union scsi_cdb *)pkt->pkt_cdbp;
	uchar_t cmd = cdbp->scc_cmd;
	char *desc;

	if ((desc = aac_cmd_name(cmd,
	    (struct aac_key_strings *)scsi_cmds)) == NULL) {
		aac_printf(softs, CE_NOTE,
		    "SCMD> Unknown(0x%2x) --> c%dt%dL%d",
		    cmd, ctl, tgt, lun);
		return;
	}

	switch (cmd) {
	case SCMD_READ:
	case SCMD_WRITE:
		aac_printf(softs, CE_NOTE,
		    "SCMD> %s 0x%x[%d] %s --> c%dt%dL%d",
		    desc, GETG0ADDR(cdbp), GETG0COUNT(cdbp),
		    (acp->flags & AAC_CMD_NO_INTR) ? "poll" : "intr",
		    ctl, tgt, lun);
		break;
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
		aac_printf(softs, CE_NOTE,
		    "SCMD> %s 0x%x[%d] %s --> c%dt%dL%d",
		    desc, GETG1ADDR(cdbp), GETG1COUNT(cdbp),
		    (acp->flags & AAC_CMD_NO_INTR) ? "poll" : "intr",
		    ctl, tgt, lun);
		break;
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
		aac_printf(softs, CE_NOTE,
		    "SCMD> %s 0x%x.%08x[%d] %s --> c%dt%dL%d",
		    desc, GETG4ADDR(cdbp), GETG4ADDRTL(cdbp),
		    GETG4COUNT(cdbp),
		    (acp->flags & AAC_CMD_NO_INTR) ? "poll" : "intr",
		    ctl, tgt, lun);
		break;
	default:
		aac_printf(softs, CE_NOTE, "SCMD> %s --> c%dt%dL%d",
		    desc, ctl, tgt, lun);
	}
}

void
aac_print_fib(struct aac_softstate *softs, struct aac_fib *fibp)
{
	int32_t fib_cmd, sub_cmd;
	char *cmdstr, *subcmdstr;
	struct aac_Container *pContainer;

	fib_cmd = fibp->Header.Command;
	cmdstr = aac_cmd_name(fib_cmd, aac_fib_cmds);
	sub_cmd = -1;
	subcmdstr = NULL;

	switch (fib_cmd) {
	case ContainerCommand:
		pContainer = (struct aac_Container *)fibp->data;
		sub_cmd = pContainer->Command;
		subcmdstr = aac_cmd_name(sub_cmd, aac_ctvm_subcmds);
		if (subcmdstr == NULL)
			break;
		fib_cmd = sub_cmd;
		cmdstr = subcmdstr;
		sub_cmd = -1;
		subcmdstr = NULL;

		switch (pContainer->Command) {
		case VM_ContainerConfig:
			sub_cmd = pContainer->CTCommand.command;
			subcmdstr = aac_cmd_name(sub_cmd, aac_ct_subcmds);
			if (subcmdstr == NULL)
				break;
			aac_printf(softs, CE_NOTE, "FIB> %s (0x%x, 0x%x, 0x%x)",
			    subcmdstr,
			    pContainer->CTCommand.param[0],
			    pContainer->CTCommand.param[1],
			    pContainer->CTCommand.param[2]);
			return;
		case VM_Ioctl:
			sub_cmd = ((int32_t *)pContainer)[4];
			subcmdstr = aac_cmd_name(sub_cmd, aac_ioctl_subcmds);
			break;
		}
		break;

	case ClusterCommand:
		sub_cmd = fibp->data[0];
		subcmdstr = aac_cmd_name(sub_cmd, aac_cl_subcmds);
		break;

	case AifRequest:
		sub_cmd = fibp->data[0];
		subcmdstr = aac_cmd_name(sub_cmd, aac_aif_subcmds);
		break;

	default:
		break;
	}

	if (subcmdstr)
		aac_printf(softs, CE_NOTE, "FIB> %s, sz=%d",
		    subcmdstr, fibp->Header.Size);
	else if (cmdstr && sub_cmd == -1)
		aac_printf(softs, CE_NOTE, "FIB> %s, sz=%d",
		    cmdstr, fibp->Header.Size);
	else if (cmdstr)
		aac_printf(softs, CE_NOTE, "FIB> %s: Unknown(0x%x), sz=%d",
		    cmdstr, sub_cmd, fibp->Header.Size);
	else
		aac_printf(softs, CE_NOTE, "FIB> Unknown(0x%x), sz=%d",
		    fib_cmd, fibp->Header.Size);
}

static void
aac_print_aif(struct aac_softstate *softs, struct aac_aif_command *aif)
{
	char *str;

	switch (aif->command) {
	case AifCmdEventNotify:
		str = aac_cmd_name(aif->data.EN.type, aac_aifens);
		if (str)
			aac_printf(softs, CE_NOTE, "AIF! %s", str);
		else
			aac_printf(softs, CE_NOTE, "AIF! Unknown(0x%x)",
			    aif->data.EN.type);
		break;

	case AifCmdJobProgress:
		switch (aif->data.PR[0].status) {
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
		    aif->seqNumber, str,
		    aif->data.PR[0].currentTick,
		    aif->data.PR[0].finalTick);
		break;

	case AifCmdAPIReport:
		aac_printf(softs, CE_NOTE, "AIF! APIReport (%d)",
		    aif->seqNumber);
		break;

	case AifCmdDriverNotify:
		aac_printf(softs, CE_NOTE, "AIF! DriverNotify (%d)",
		    aif->seqNumber);
		break;

	default:
		aac_printf(softs, CE_NOTE, "AIF! AIF %d (%d)",
		    aif->command, aif->seqNumber);
		break;
	}
}

#endif /* DEBUG */
