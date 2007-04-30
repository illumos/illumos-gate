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

#define	AACOFFSET(type, member) ((size_t)(&((type *)0)->member))
#define	AAC_TRAN2SOFTS(tran) ((struct aac_softstate *)(tran)->tran_hba_private)
#define	PKT2AC(pkt) ((struct aac_cmd *)(pkt)->pkt_ha_private)
#define	AAC_BUSYWAIT(cond, timeout /* in millisecond */) \
	do { \
		int count = 0; \
		while (!(cond)) { \
			drv_usecwait(100); \
			if (count > ((timeout) * 10)) { \
				break; \
			} \
			count++; \
		} \
_NOTE(CONSTCOND) } while (0)

#define	AAC_SENSE_DATA_DESCR_LEN (sizeof (struct scsi_descr_sense_hdr) + \
	sizeof (struct scsi_information_sense_descr))
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
#define	AAC_IS_Q_EMPTY(q) (((q)->q_head == NULL) ? 1 : 0)

#define	PCI_MEM_GET32(softs, off) ddi_get32((softs)->pci_mem_handle, \
	(uint32_t *)((softs)->pci_mem_base_addr + (off)))
#define	PCI_MEM_PUT32(softs, off, val)	ddi_put32((softs)->pci_mem_handle, \
	(uint32_t *)((softs)->pci_mem_base_addr + (off)), (uint32_t)(val))

#define	AAC_ENABLE_INTR(softs) \
	do { \
		if (softs->flags & AAC_FLAGS_NEW_COMM) \
			PCI_MEM_PUT32(softs, AAC_OIMR, ~AAC_DB_INTR_NEW); \
		else \
			PCI_MEM_PUT32(softs, AAC_OIMR, ~AAC_DB_INTR_BITS); \
_NOTE(CONSTCOND) } while (0)
#define	AAC_DISABLE_INTR(softs)	PCI_MEM_PUT32(softs, AAC_OIMR, ~0)
#define	AAC_STATUS_CLR(softs, mask) PCI_MEM_PUT32(softs, AAC_ODBR, mask)
#define	AAC_STATUS_GET(softs) PCI_MEM_GET32(softs, AAC_ODBR)
#define	AAC_NOTIFY(softs, val) PCI_MEM_PUT32(softs, AAC_IDBR, val)
#define	AAC_OUTB_GET(softs) PCI_MEM_GET32(softs, AAC_OQUE)
#define	AAC_OUTB_SET(softs, val) PCI_MEM_PUT32(softs, AAC_OQUE, val)
#define	AAC_FWSTATUS_GET(softs)	\
	((softs)->aac_if.aif_get_fwstatus((softs)))
#define	AAC_MAILBOX_GET(softs, mb) \
	((softs)->aac_if.aif_get_mailbox((softs), (mb)))
#define	AAC_MAILBOX_SET(softs, cmd, arg0, arg1, arg2, arg3) \
	((softs)->aac_if.aif_set_mailbox((softs), (cmd), \
	(arg0), (arg1), (arg2), (arg3)))

#define	AAC_IOCMD_SYNC		(1 << 0)
#define	AAC_IOCMD_ASYNC		(1 << 1)
#define	AAC_IOCMD_OUTSTANDING	(1 << 2)
#define	AAC_IOCMD_ALL		(AAC_IOCMD_SYNC | AAC_IOCMD_ASYNC | \
				AAC_IOCMD_OUTSTANDING)

/*
 * Hardware access functions
 */
static int aac_rx_get_fwstatus(struct aac_softstate *);
static int aac_rx_get_mailbox(struct aac_softstate *, int);
static void aac_rx_set_mailbox(struct aac_softstate *, uint32_t,
	uint32_t, uint32_t, uint32_t, uint32_t);
static struct aac_interface aac_rx_interface = {
	aac_rx_get_fwstatus,
	aac_rx_get_mailbox,
	aac_rx_set_mailbox
};

static int aac_rkt_get_fwstatus(struct aac_softstate *);
static int aac_rkt_get_mailbox(struct aac_softstate *, int);
static void aac_rkt_set_mailbox(struct aac_softstate *, uint32_t, uint32_t,
	uint32_t, uint32_t, uint32_t);
static struct aac_interface aac_rkt_interface = {
	aac_rkt_get_fwstatus,
	aac_rkt_get_mailbox,
	aac_rkt_set_mailbox
};

/*
 * SCSA function prototypes
 */
static int aac_attach(dev_info_t *, ddi_attach_cmd_t);
static int aac_detach(dev_info_t *, ddi_detach_cmd_t);
static int aac_reset(dev_info_t *, ddi_reset_cmd_t);

/*
 * Interrupt handler funtions
 */
static uint_t aac_intr_old(caddr_t);
static uint_t aac_intr_new(caddr_t);
static uint_t aac_softintr(caddr_t);

/*
 * Internal function in attach
 */
static void aac_intr_norm(struct aac_softstate *, struct aac_cmd *);
static int aac_check_card_type(struct aac_softstate *);
static int aac_check_firmware(struct aac_softstate *);
static int aac_common_attach(struct aac_softstate *);
static void aac_common_detach(struct aac_softstate *);
static int aac_get_container(struct aac_softstate *);
static int aac_alloc_comm_space(struct aac_softstate *);
static int aac_setup_comm_space(struct aac_softstate *);
static void aac_free_comm_space(struct aac_softstate *);
static int aac_hba_setup(struct aac_softstate *);

/*
 * Sync FIB operation functions
 */
int aac_sync_mbcommand(struct aac_softstate *, uint32_t, uint32_t,
	uint32_t, uint32_t, uint32_t, uint32_t *);
static int aac_sync_fib(struct aac_softstate *, uint32_t, struct aac_fib *,
	uint16_t);
static struct aac_fib *aac_grab_sync_fib(struct aac_softstate *,
	int (*)(caddr_t));
static void aac_release_sync_fib(struct aac_softstate *);

/*
 * Waiting/complete queue operation funcitons
 */
static void aac_cmd_enqueue(struct aac_cmd_queue *, struct aac_cmd *);
static struct aac_cmd *aac_cmd_dequeue(struct aac_cmd_queue *);

/*
 * fib queue operation functions
 */
static int aac_fib_enqueue(struct aac_softstate *, int, struct aac_fib *);
static int aac_resp_enqueue(struct aac_softstate *, int, struct aac_fib *);
static int aac_fib_dequeue(struct aac_softstate *, int, struct aac_fib **,
	struct aac_cmd **);

/*
 * slot operation functions
 */
static int aac_create_slots(struct aac_softstate *);
static void aac_destroy_slots(struct aac_softstate *);
static struct aac_slot *aac_get_slot(struct aac_softstate *);
static void aac_release_slot(struct aac_softstate *, struct aac_slot *);
static int aac_alloc_fib(struct aac_softstate *, struct aac_slot *);
static void aac_free_fib(struct aac_slot *);

/*
 * Internal funcitons
 */
static void aac_print_scmd(struct scsi_pkt *);
static void aac_print_aif(struct aac_aif_command *);
static size_t aac_cmd_fib(struct aac_softstate *, struct aac_cmd *);
static void aac_start_waiting_io(struct aac_softstate *);
static void aac_drain_comp_q(struct aac_softstate *);
static int aac_do_poll_io(struct aac_softstate *, struct aac_cmd *);
int aac_do_async_io(struct aac_softstate *, struct aac_cmd *);
static int aac_send_command(struct aac_softstate *, struct aac_slot *);
static void aac_dma_sync(ddi_dma_handle_t, off_t, size_t, uint_t);
static int aac_shutdown(struct aac_softstate *);
static int aac_reset_adapter(struct aac_softstate *);

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
	nodev,		/* cb_prop_op */
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
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x1028, 0x2, 0x1028, 0x2, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x1028, 0x3, 0x1028, 0x3, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Si"},
	{0x1028, 0x8, 0x1028, 0xcf, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x1028, 0x4, 0x1028, 0xd0, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Si"},
	{0x1028, 0x2, 0x1028, 0xd1, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x1028, 0x2, 0x1028, 0xd9, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x106, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x11b, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x121, AAC_HWIF_I960RX,
		AAC_FLAGS_PERC, AAC_TYPE_SCSI, "Dell", "PERC 3/Di"},
	{0x9005, 0x285, 0x1028, 0x287, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
		"Dell", "PERC 320/DC"},
	{0x9005, 0x285, 0x1028, 0x291, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB, AAC_TYPE_SATA, "Dell", "CERC SR2"},

	{0x9005, 0x285, 0x1014, 0x2f2, AAC_HWIF_I960RX,
		0, AAC_TYPE_SCSI, "IBM", "ServeRAID 8i"},
	{0x9005, 0x285, 0x1014, 0x34d, AAC_HWIF_I960RX,
		0, AAC_TYPE_SAS, "IBM", "ServeRAID 8s"},
	{0x9005, 0x286, 0x1014, 0x9580, AAC_HWIF_RKT,
		0, AAC_TYPE_SAS, "IBM", "ServeRAID 8k"},

	{0x9005, 0x285, 0x103c, 0x3227, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB, AAC_TYPE_SATA, "Adaptec", "2610SA"},

	{0x9005, 0x285, 0x9005, 0x285, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
		"Adaptec", "2200S"},
	{0x9005, 0x285, 0x9005, 0x286, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
		"Adaptec", "2120S"},
	{0x9005, 0x285, 0x9005, 0x287, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB | AAC_FLAGS_256FIBS, AAC_TYPE_SCSI,
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
		AAC_FLAGS_NO4GB, AAC_TYPE_SATA, "Adaptec", "2410SA"},
	{0x9005, 0x285, 0x9005, 0x292, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB, AAC_TYPE_SATA, "Adaptec", "2810SA"},
	{0x9005, 0x285, 0x9005, 0x293, AAC_HWIF_I960RX,
		AAC_FLAGS_NO4GB, AAC_TYPE_SATA, "Adaptec", "21610SA"},
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

ddi_device_acc_attr_t aac_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
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
static ddi_dma_attr_t aac_buf_dma_attr = {
		DMA_ATTR_V0,
		0x2000ull,	/* lowest usable address */
				/* (2200 and 2120 cannot do DMA below 8192) */
		0xffffffffull,	/* high DMA address range */
		0x0000ffffull,	/* DMA counter register */
		AAC_DMA_ALIGN,	/* DMA address alignment */
		1,		/* DMA burstsizes */
		1,		/* min effective DMA size */
		0xffffffffull,	/* max DMA xfer size */
		0xffffffffull,	/* segment boundary */
		AAC_NSEG,	/* s/g list length */
		AAC_BLK_SIZE,	/* granularity of device */
		0,		/* DMA transfer flags */
};

static ddi_dma_attr_t aac_addr_dma_attr = {
		DMA_ATTR_V0,
		0x2000ull,	/* lowest usable address */
				/* (2200 and 2120 cannot do DMA below 8192) */
		0x7fffffffull,	/* high DMA address range */
		0x0000ffffull,	/* DMA counter register */
		AAC_DMA_ALIGN,	/* DMA address alignment */
		1,		/* DMA burstsizes */
		1,		/* min effective DMA size */
		0x7fffffffull,	/* max DMA xfer size */
		0x7fffffffull,	/* segment boundary */
		1,		/* s/g list length */
		1,		/* granularity of device */
		0,		/* DMA transfer flags */
};

int
_init(void)
{
	int retval = 0;

	DBCALLED(1);

	if ((retval = ddi_soft_state_init((void *)&aac_softstatep,
		sizeof (struct aac_softstate), 0)) != 0)
		goto error;

	if ((retval = scsi_hba_init(&aac_modlinkage)) != 0) {
		ddi_soft_state_fini((void*)&aac_softstatep);
		goto error;
	}

	if ((retval = mod_install(&aac_modlinkage)) != 0) {
		ddi_soft_state_fini((void*)&aac_softstatep);
		scsi_hba_fini(&aac_modlinkage);
		goto error;
	}
	return (retval);

error:
	AACDB_PRINT((CE_WARN, "Mod init error!"));
	return (retval);
}

int
_info(struct modinfo *modinfop)
{
	DBCALLED(1);
	return (mod_info(&aac_modlinkage, modinfop));
}

/*
 * An HBA driver cannot be unload unless you reboot,
 * so this function will be of no use.
 */
int
_fini(void)
{
	int err;

	DBCALLED(1);

	if ((err = mod_remove(&aac_modlinkage)) != 0)
		goto error;

	scsi_hba_fini(&aac_modlinkage);
	ddi_soft_state_fini((void*)&aac_softstatep);

	return (0);

error:
	AACDB_PRINT((CE_WARN, "AAC is busy, cannot unload!"));
	return (err);
}

static int
aac_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	struct aac_softstate  *softs;
	scsi_hba_tran_t *tran;
	int attach_state = 0;

	DBCALLED(1);

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
		AACDB_PRINT((CE_WARN, "Cannot alloc soft state"));
		goto error;
	}
	softs = ddi_get_soft_state(aac_softstatep, instance);
	attach_state |= AAC_ATTACH_SOFTSTATE_ALLOCED;

	softs->devinfo_p = dip;
	softs->buf_dma_attr = aac_buf_dma_attr;
	softs->addr_dma_attr = aac_addr_dma_attr;
	softs->card = AAC_UNKNOWN_CARD;

	/* Check the card type */
	if (aac_check_card_type(softs) == AACERR) {
		AACDB_PRINT((CE_WARN, "Card not supported"));
		goto error;
	}
	/* We have found the right card and everything is OK */
	attach_state |= AAC_ATTACH_CARD_DETECTED;

	/* Map PCI mem space */
	if (ddi_regs_map_setup(dip, 1,
		(caddr_t *)&softs->pci_mem_base_addr, 0,
		softs->map_size_min, &aac_acc_attr,
		&softs->pci_mem_handle) != DDI_SUCCESS)
		goto error;

	softs->map_size = softs->map_size_min;
	attach_state |= AAC_ATTACH_PCI_MEM_MAPPED;

	AAC_DISABLE_INTR(softs);

	if (ddi_intr_hilevel(dip, 0)) {
		AACDB_PRINT((CE_WARN,
			"High level interrupt is not supported!"));
		goto error;
	}

	/* Init mutexes */
	if (ddi_get_iblock_cookie(dip, 0, &softs->iblock_cookie)
		!= DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN,
			"Can not get interrupt block cookie!"));
		goto error;
	}
	mutex_init(&softs->sync_mode.mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->q_wait_sync.q_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->q_wait.q_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->q_comp.q_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->slot_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->fib_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	cv_init(&softs->event, NULL, CV_DRIVER, NULL);
	mutex_init(&softs->event_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	cv_init(&softs->aifv, NULL, CV_DRIVER, NULL);
	mutex_init(&softs->aifq_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	rw_init(&softs->errlock, NULL, RW_DRIVER,
		(void *)softs->iblock_cookie);
	attach_state |= AAC_ATTACH_KMUTEX_INITED;

	/*
	 * Everything has been set up till now,
	 * we will do some common attach.
	 */
	if (aac_common_attach(softs) == AACERR) {
		if (softs->pci_mem_handle == NULL)
			attach_state &= ~AAC_ATTACH_PCI_MEM_MAPPED;
		goto error;
	}
	attach_state |= AAC_ATTACH_COMM_SPACE_SETUP;

	if (aac_hba_setup(softs) != AACOK)
		goto error;
	attach_state |= AAC_ATTACH_SCSI_TRAN_SETUP;

	/* Connect interrupt handler */
	if (ddi_add_intr(dip, 0, &softs->iblock_cookie,
		(ddi_idevice_cookie_t *)0,
		(softs->flags & AAC_FLAGS_NEW_COMM) ?
		aac_intr_new : aac_intr_old, (caddr_t)softs) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN,
			"Can not setup interrupt handler!"));
		goto error;
	}
	attach_state |= AAC_ATTACH_HARD_INTR_SETUP;

	if (ddi_add_softintr(dip, DDI_SOFTINT_LOW, &softs->softint_id,
		NULL, NULL, aac_softintr, (caddr_t)softs) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "Can not setup soft interrupt handler!"));
		goto error;
	}
	attach_state |= AAC_ATTACH_SOFT_INTR_SETUP;

	/* Create devctl/scsi nodes for cfgadm */
	if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
		INST2DEVCTL(instance),
		DDI_NT_SCSI_NEXUS, 0) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "failed to create devctl node"));
		goto error;
	}
	attach_state |= AAC_ATTACH_CREATE_DEVCTL;

	if (ddi_create_minor_node(dip, "scsi", S_IFCHR,
		INST2SCSI(instance),
		DDI_NT_SCSI_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "failed to create scsi node"));
		goto error;
	}
	attach_state |= AAC_ATTACH_CREATE_SCSI;

	/* create aac node for app. to issue ioctls */
	if (ddi_create_minor_node(dip, "aac", S_IFCHR,
		INST2AAC(instance), DDI_PSEUDO, 0) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "failed to create aac node"));
		goto error;
	}

	softs->state = AAC_STATE_RUN;
	/* Create a thread for command timeout */
	softs->timeout_id = timeout(aac_daemon, (void*)softs,
		(60 * drv_usectohz(1000000)));

	/* Common attach is OK, so we are attached! */
	AAC_ENABLE_INTR(softs);
	ddi_report_dev(dip);
	AACDB_PRINT((CE_NOTE, "aac attached ok"));
	return (DDI_SUCCESS);

error:
	if (attach_state & AAC_ATTACH_CREATE_SCSI)
		ddi_remove_minor_node(dip, "scsi");
	if (attach_state & AAC_ATTACH_CREATE_DEVCTL)
		ddi_remove_minor_node(dip, "devctl");
	if (attach_state & AAC_ATTACH_COMM_SPACE_SETUP)
		aac_common_detach(softs);
	if (attach_state & AAC_ATTACH_SCSI_TRAN_SETUP) {
		tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
		(void) scsi_hba_detach(dip);
		scsi_hba_tran_free(tran);
	}
	if (attach_state & AAC_ATTACH_HARD_INTR_SETUP)
		ddi_remove_intr(dip, 0, softs->iblock_cookie);
	if (attach_state & AAC_ATTACH_SOFT_INTR_SETUP)
		ddi_remove_softintr(softs->softint_id);
	if (attach_state & AAC_ATTACH_KMUTEX_INITED) {
		mutex_destroy(&softs->sync_mode.mutex);
		mutex_destroy(&softs->q_wait_sync.q_mutex);
		mutex_destroy(&softs->q_wait.q_mutex);
		mutex_destroy(&softs->q_comp.q_mutex);
		mutex_destroy(&softs->slot_mutex);
		mutex_destroy(&softs->fib_mutex);
		mutex_destroy(&softs->event_mutex);
		cv_destroy(&softs->event);
		mutex_destroy(&softs->aifq_mutex);
		cv_destroy(&softs->aifv);
		rw_destroy(&softs->errlock);
	}
	if (attach_state & AAC_ATTACH_PCI_MEM_MAPPED)
		ddi_regs_map_free(&softs->pci_mem_handle);
	if (attach_state & AAC_ATTACH_CARD_DETECTED)
		softs->card = AACERR;
	if (attach_state & AAC_ATTACH_SOFTSTATE_ALLOCED)
		ddi_soft_state_free(aac_softstatep, instance);
	return (DDI_FAILURE);
}

static int
aac_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	struct aac_softstate *softs;
	scsi_hba_tran_t *tran;

	DBCALLED(1);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_FAILURE);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	softs = AAC_TRAN2SOFTS(tran);
	ddi_remove_minor_node(dip, "aac");
	ddi_remove_minor_node(dip, "scsi");
	ddi_remove_minor_node(dip, "devctl");

	softs->state = AAC_STATE_STOPPED;
	(void) untimeout(softs->timeout_id);
	softs->timeout_id = 0;

	AAC_DISABLE_INTR(softs);
	ddi_remove_intr(dip, 0, softs->iblock_cookie);
	ddi_remove_softintr(softs->softint_id);

	aac_common_detach(softs);

	(void) scsi_hba_detach(dip);
	scsi_hba_tran_free(tran);
	mutex_destroy(&softs->sync_mode.mutex);
	mutex_destroy(&softs->q_wait_sync.q_mutex);
	mutex_destroy(&softs->q_wait.q_mutex);
	mutex_destroy(&softs->q_comp.q_mutex);
	mutex_destroy(&softs->slot_mutex);
	mutex_destroy(&softs->fib_mutex);
	mutex_destroy(&softs->event_mutex);
	cv_destroy(&softs->event);
	mutex_destroy(&softs->aifq_mutex);
	cv_destroy(&softs->aifv);
	rw_destroy(&softs->errlock);

	ddi_regs_map_free(&softs->pci_mem_handle);
	softs->hwif = AAC_HWIF_UNKNOWN;
	softs->card = AAC_UNKNOWN_CARD;
	ddi_soft_state_free(aac_softstatep, instance);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
aac_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	struct aac_softstate *softs;
	scsi_hba_tran_t *tran;

	DBCALLED(1);

	tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	softs = AAC_TRAN2SOFTS(tran);
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
	int status;
	struct aac_fib *fib;
	struct aac_close_command *cc;

	fib = aac_grab_sync_fib(softs, SLEEP_FUNC);
	cc = (struct aac_close_command *)&fib->data[0];

	cc->Command = VM_CloseAll;
	cc->ContainerId = 0xffffffff;

	/* flush all caches, set FW to write through mode */
	status = aac_sync_fib(softs, ContainerCommand, fib,
		sizeof (struct aac_fib_header) + \
		sizeof (struct aac_close_command));

	AACDB_PRINT((CE_NOTE,
		"shutting down aac %s", (status == AACOK) ? "ok" : "fail"));

	aac_release_sync_fib(softs);
	return (status);
}

static uint_t
aac_softintr(caddr_t arg)
{
	struct aac_softstate *softs;

	softs = (struct aac_softstate *)arg;
	if (!AAC_IS_Q_EMPTY(&softs->q_comp)) {
		aac_drain_comp_q(softs);
		return (DDI_INTR_CLAIMED);
	} else
		return (DDI_INTR_UNCLAIMED);
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

	if (info <= 0xffffffff) {
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
static void
aac_set_arq_data_reset(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct scsi_address *ap = &acp->pkt->pkt_address;

	if (softs->container[ap->a_target].reset) {
		softs->container[ap->a_target].reset = 0;
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
		(uint32_t)(slotp->fib_phyaddr & 0xffffffffUL));
	device += 4;
	PCI_MEM_PUT32(softs, device, (uint32_t)(slotp->fib_phyaddr >> 32));
	device += 4;
	PCI_MEM_PUT32(softs, device, slotp->fibp->Header.Size);
	PCI_MEM_PUT32(softs, AAC_IQUE, index);
	return (AACOK);
}

/*
 * Interrupt handler for New Comm. interface
 * New Comm. interface use a different mechanism for interrupt. No explict
 * message queues, and driver need only accesses the mapped PCI mem space to
 * find the completed FIB or AIF.
 */
static uint_t
aac_intr_new(caddr_t arg)
{
	struct aac_softstate *softs;
	struct aac_cmd *acp;
	struct aac_fib *fibp;
	uint32_t index, fast;

	/* AACDB_PRINT((CE_NOTE, "INTR! new")); */
	softs = (struct aac_softstate *)arg;
	index = AAC_OUTB_GET(softs);
	if (index == 0xffffffff)
		index = AAC_OUTB_GET(softs);
	if (index == 0xffffffff)
		return (DDI_INTR_UNCLAIMED);
	do {
		if (index & AAC_SENDERADDR_MASK_AIF) {
			int i;

			if (index == 0xfffffffe)
				return (DDI_INTR_CLAIMED);
			/* AIF received */
			fibp = &softs->comm_space->adapter_fibs[0];
			index &= ~2;
			for (i = 0; i < sizeof (struct aac_fib)/4; ++i)
				((uint32_t *)fibp)[i] =
					PCI_MEM_GET32(softs, index+i*4);
			(void) aac_handle_aif(softs, fibp);
			/*
			 * AIF memory is owned by the adapter, so let it
			 * know that we are done with it.
			 */
			AAC_OUTB_SET(softs, index);
			AAC_STATUS_CLR(softs, AAC_DB_RESPONSE_READY);
		} else {
			fast = index & AAC_SENDERADDR_MASK_FAST_RESPONSE;
			index >>= 2;

			/* Make sure firmware reported index is valid */
			ASSERT(index >= 0 && index < softs->total_slots);
			ASSERT(softs->io_slot[index].index != -1);

			acp = softs->io_slot[index].acp;
			ASSERT(acp != NULL);
			if (fast) {
				fibp = softs->io_slot[index].fibp;
				fibp->Header.XferState |=
					AAC_FIBSTATE_DONEADAP;
				*((uint32_t *)(fibp->data)) = 0;
			}
			aac_intr_norm(softs, acp);
		}
		index = AAC_OUTB_GET(softs);
	} while (index != 0xffffffff);

	aac_start_waiting_io(softs);
	ddi_trigger_softintr(softs->softint_id);

	return (DDI_INTR_CLAIMED);
}

/*
 * Interrupt handler for old interface
 * Explicit message queues are used to send FIB to and get completed FIB from
 * the adapter. Driver and adapter maitain the queues in the producer/consumer
 * manner. The driver has to query the queues to find the completed FIB.
 */
static uint_t
aac_intr_old(caddr_t arg)
{
	struct aac_softstate *softs;
	struct aac_cmd *acp;
	struct aac_fib *fibp;
	uint16_t status;
	int rval;

	/* AACDB_PRINT((CE_NOTE, "INTR! old")); */
	softs = (struct aac_softstate *)arg;
	status = AAC_STATUS_GET(softs);
	if (status & AAC_DB_RESPONSE_READY) {
		/* ACK the intr */
		AAC_STATUS_CLR(softs, AAC_DB_RESPONSE_READY);
		(void) AAC_STATUS_GET(softs);
		do {
			rval = aac_fib_dequeue(softs,
				AAC_HOST_NORM_RESP_Q,
				&fibp, &acp);
			if (rval == 0 && acp)
				aac_intr_norm(softs, acp);
		} while (rval == 0);

		aac_start_waiting_io(softs);
		ddi_trigger_softintr(softs->softint_id);
		return (DDI_INTR_CLAIMED);
	} else if (status & AAC_DB_PRINTF_READY) {
		/* ACK the intr */
		AAC_STATUS_CLR(softs, AAC_DB_PRINTF_READY);
		(void) AAC_STATUS_GET(softs);
		aac_dma_sync(softs->comm_space_dma_handle,
			AACOFFSET(struct aac_comm_space, adapter_print_buf),
			AAC_ADAPTER_PRINT_BUFSIZE,
			DDI_DMA_SYNC_FORCPU);
		cmn_err(CE_NOTE, "MSG From Adapter: %s",
			softs->comm_space->adapter_print_buf);
		AAC_NOTIFY(softs, AAC_DB_PRINTF_READY);
		return (DDI_INTR_CLAIMED);
	} else if (status & AAC_DB_COMMAND_READY) {
		AAC_STATUS_CLR(softs, AAC_DB_COMMAND_READY);
		(void) AAC_STATUS_GET(softs);
		rval = aac_fib_dequeue(softs, AAC_HOST_NORM_CMD_Q,
			&fibp, &acp);
		if (rval == 0 && fibp) {
			(void) aac_handle_aif(softs, fibp);
			if (aac_resp_enqueue(softs, AAC_ADAP_NORM_RESP_Q, fibp)
				== AACERR)
				cmn_err(CE_NOTE, "!AIF ack failed");
		}
		return (DDI_INTR_CLAIMED);
	} else if (status & AAC_DB_COMMAND_NOT_FULL) {
		/*
		 * Without these two condition statements, the OS could hang
		 * after a while, especially if there are a lot of AIF's to
		 * handle, for instance if a drive is pulled from an array
		 * under heavy load.
		 */
		AAC_STATUS_CLR(softs, AAC_DB_COMMAND_NOT_FULL);
		return (DDI_INTR_CLAIMED);
	} else if (status & AAC_DB_RESPONSE_NOT_FULL) {
		AAC_STATUS_CLR(softs, AAC_DB_COMMAND_NOT_FULL);
		AAC_STATUS_CLR(softs, AAC_DB_RESPONSE_NOT_FULL);
		return (DDI_INTR_CLAIMED);
	} else
		return (DDI_INTR_UNCLAIMED);
}

/*
 * Handle a finished pkt of AAC_CMD_HARD_INTR mode
 */
static void
aac_hard_callback(struct aac_softstate *softs, struct aac_cmd *ac,
	uchar_t reason)
{
	ac->pkt->pkt_reason = reason;
	aac_cmd_enqueue(&softs->q_comp, ac);
}

/*
 * Handle a finished pkt of non AAC_CMD_HARD_INTR mode
 */
static void
aac_soft_callback(struct aac_softstate *softs, struct aac_cmd *ac,
	uchar_t reason)
{
	struct scsi_pkt *pkt = ac->pkt;

	/* AAC_CMD_NO_INTR means no complete callback */
	ASSERT(!(ac->flags & AAC_CMD_NO_INTR) || (reason == CMD_CMPLT));

	pkt->pkt_reason = reason;
	if (reason == CMD_CMPLT)
		pkt->pkt_state |=
			STATE_GOT_BUS |
			STATE_GOT_TARGET |
			STATE_SENT_CMD;

	if (!(ac->flags & AAC_CMD_NO_INTR)) {
		aac_cmd_enqueue(&softs->q_comp, ac);
		ddi_trigger_softintr(softs->softint_id);
	}
}

/*
 * Handle a complete IO, common to aac_intr_new() and aac_intr_old()
 */
static void
aac_intr_norm(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_slot *slotp;
	uint8_t status;

	ASSERT(acp != NULL);
	ASSERT(acp->slotp != NULL);
	ASSERT(acp->flags & AAC_CMD_HARD_INTR);

	slotp = acp->slotp;
	aac_dma_sync(slotp->fib_dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);

	if (slotp->fibp->Header.XferState & AAC_FIBSTATE_ASYNC) {
		status = slotp->fibp->data[0];
		aac_release_slot(softs, slotp);
		acp->slotp = NULL;
		if (status == 0)
			acp->pkt->pkt_state |= STATE_XFERRED_DATA;
		else
			aac_set_arq_data_hwerr(acp);
		acp->state = AAC_CMD_CMPLT;

		aac_hard_callback(softs, acp, CMD_CMPLT);
	} else if (slotp->fibp->Header.XferState & AAC_FIBSTATE_REXPECTED) {
		/*
		 * NOTE: use ASYNC to differentiate fibcmd & sendfib,
		 * see ioctl_send_fib().
		 */
		struct aac_fib *fibp;

		fibp = &acp->fib;
		ASSERT(fibp->Header.Size <= softs->aac_max_fib_size);

		bcopy(slotp->fibp, fibp, fibp->Header.Size);
		aac_release_slot(softs, acp->slotp);
		acp->slotp = NULL;
		acp->state = AAC_CMD_CMPLT;

		mutex_enter(&softs->event_mutex);
		/*
		 * NOTE: Both aac_ioctl_send_fib() and aac_send_raw_srb()
		 * may wait on softs->event, so use cv_broadcast() instead
		 * of cv_signal().
		 */
		cv_broadcast(&softs->event);
		mutex_exit(&softs->event_mutex);
	} else {
		/* Hardware error */
		aac_release_slot(softs, acp->slotp);
		acp->slotp = NULL;
		aac_set_arq_data_hwerr(acp);
		acp->state = AAC_CMD_CMPLT;

		aac_hard_callback(softs, acp, CMD_CMPLT);
	}
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
	uint32_t mem_base;

	/* Map pci configuration space */
	if ((pci_config_setup(softs->devinfo_p, &pci_config_handle))
		!= DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "Cannot setup pci config space"));
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
			/*
			 * SATA RAID adapter's DMA capability is worse
			 * than SCSI RAID adapter.  So we need to change
			 * dma_attr_count_max from 0xffff to 0xfff to meet
			 * the requirement.
			 */
			if (aac_cards[card_index].type == AAC_TYPE_SATA)
				softs->buf_dma_attr.dma_attr_count_max =
					0xfffull;
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
			AACDB_PRINT((CE_WARN,
				"Unknown vendor 0x%x", vendid));
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
			AACDB_PRINT((CE_WARN,
				"Unknown device \"pci9005,%x\"", devid));
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
		AACDB_PRINT((CE_WARN,
			"Unknown hardware interface %d", softs->hwif));
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
		pci_config_put16(pci_config_handle, PCI_CONF_COMM,
			pci_cmd);
		pci_cmd = pci_config_get16(pci_config_handle,
			PCI_CONF_COMM);
		if ((pci_cmd & PCI_COMM_ME) == 0) {
			cmn_err(CE_CONT,
				"?Cannot enable busmaster bit");
			goto error;
		}
	}

	/* Set memory base to map */
	mem_base = pci_config_get32(pci_config_handle, PCI_CONF_BASE0);

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
		mem_base);
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
	if ((aac_sync_mbcommand(softs, AAC_MONKER_GETINFO, 0, 0, 0, 0, &status))
		!= AACOK) {
		if (status != AAC_SRB_STS_INVALID_REQUEST) {
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

	if (softs->flags & AAC_FLAGS_PERC)
		options = 0;

	if ((softs->state == AAC_STATE_RESET)) {
		if ((softs->support_opt == options) &&
			(softs->atu_size == atu_size))
			return (AACOK);

		cmn_err(CE_WARN,
			"?Fatal error: firmware changed, system needs reboot");
		return (AACERR);
	}

	softs->support_opt = options;
	softs->atu_size = atu_size;

	/* Process supported options */
	if ((options & AAC_SUPPORTED_4GB_WINDOW) != 0 &&
		(softs->flags & AAC_FLAGS_NO4GB) == 0) {
		cmn_err(CE_NOTE, "!Enable FIB map 4GB window");
		softs->addr_dma_attr.dma_attr_addr_hi = 0xffffffffull;
		softs->addr_dma_attr.dma_attr_maxxfer = 0xffffffffull;
		softs->addr_dma_attr.dma_attr_seg = 0xffffffffull;
		softs->flags |= AAC_FLAGS_4GB_WINDOW;
	}

	if ((options & AAC_SUPPORTED_SGMAP_HOST64) != 0) {
		cmn_err(CE_NOTE, "!Enable SG map 64-bit address");
		softs->buf_dma_attr.dma_attr_addr_hi = 0xffffffffffffffffull;
		softs->buf_dma_attr.dma_attr_maxxfer = 0xffffffffffffffffull;
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
			(caddr_t *)&pci_mbr, 0,
			atu_size, &aac_acc_attr, &pci_handle)
			== DDI_SUCCESS)) {
			ddi_regs_map_free(&softs->pci_mem_handle);
			softs->pci_mem_handle = pci_handle;
			softs->pci_mem_base_addr = pci_mbr;
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
		softs->aac_max_sectors = 128;
		if (softs->flags & AAC_FLAGS_PERC)
			softs->aac_sg_tablesize = AAC_NSEG;
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
	struct aac_fib *fib;
	struct aac_adapter_info *ainfp;
	struct aac_supplement_adapter_info *sinfp;

	fib = aac_grab_sync_fib(softs, SLEEP_FUNC);
	fib->data[0] = 0;
	if (aac_sync_fib(softs, RequestAdapterInfo, fib,
		sizeof (struct aac_fib_header)) != AACOK) {
		AACDB_PRINT((CE_WARN, "RequestAdapterInfo failed"));
		aac_release_sync_fib(softs);
		return (AACERR);
	}
	ainfp = (struct aac_adapter_info *)fib->data;
	if (ainfr) {
		*ainfr = *ainfp;
	}
	if (sinfr) {
		if (!(softs->support_opt &
			AAC_SUPPORTED_SUPPLEMENT_ADAPTER_INFO)) {
			AACDB_PRINT((CE_WARN,
				"SupplementAdapterInfo not supported"));
			aac_release_sync_fib(softs);
			return (AACERR);
		}
		fib->data[0] = 0;
		if (aac_sync_fib(softs, RequestSupplementAdapterInfo, fib,
			sizeof (struct aac_fib_header)) != AACOK) {
			AACDB_PRINT((CE_WARN,
				"RequestSupplementAdapterInfo failed"));
			aac_release_sync_fib(softs);
			return (AACERR);
		}
		sinfp = (struct aac_supplement_adapter_info *)fib->data;
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
	struct aac_fib *fib;
	struct aac_Container *cmd;
	struct aac_Container_resp *rsp;
	struct aac_cf_status_header *cfg_sts_hdr;
	uint32_t cfg_stat_action;
	int status;
	int ret;

	/*
	 * Get adapter config status
	 */
	fib = aac_grab_sync_fib(softs, SLEEP_FUNC);
	cmd = (struct aac_Container *)&fib->data[0];
	rsp = (struct aac_Container_resp *)cmd;
	cfg_sts_hdr = (struct aac_cf_status_header *)rsp->CTResponse.data;

	cmd->Command = VM_ContainerConfig;
	cmd->CTCommand.command = CT_GET_CONFIG_STATUS;
	cmd->CTCommand.param[CNT_SIZE] = sizeof (struct aac_cf_status_header);
	status = aac_sync_fib(softs, ContainerCommand, fib,
		sizeof (struct aac_fib_header) + \
		sizeof (struct aac_Container));

	if ((status == AACOK) &&
		(*(uint32_t *)rsp == 0) &&
		(rsp->CTResponse.param[0] == CT_OK)) {
		cfg_stat_action = cfg_sts_hdr->action;

		/*
		 * Commit configuration if it's reasonable to do so.
		 */
		if (cfg_stat_action <= CFACT_PAUSE) {
			bzero(cmd, sizeof (struct aac_Container) - \
				CT_PACKET_SIZE);
			cmd->Command = VM_ContainerConfig;
			cmd->CTCommand.command = CT_COMMIT_CONFIG;
			status = aac_sync_fib(softs, ContainerCommand, fib,
				sizeof (struct aac_fib_header) + \
				sizeof (struct aac_Container));
			if ((status == AACOK) &&
				(*(uint32_t *)rsp == 0) &&
				(rsp->CTResponse.param[0] == CT_OK))
					/* Successful completion */
					ret = AACMPE_OK;
				else
					/*
					 * Auto-commit aborted due to error(s).
					 */
					ret = AACMPE_COMMIT_CONFIG;
		} else {
			/*
			 * Auto-commit aborted due to adapter indicating
			 * configuration issue(s) too dangerous to auto-commit.
			 */
			ret = AACMPE_CONFIG_STATUS;
		}
	} else {
		cmn_err(CE_WARN, "!Configuration issue, auto-commit aborted");
		ret = AACMPE_CONFIG_STATUS;
	}

	aac_release_sync_fib(softs);
	return (ret);
}

/*
 * Hardware initialization and resource allocation
 */
static int
aac_common_attach(struct aac_softstate *softs)
{
	int i;
	struct aac_slot *slotp;

	DBCALLED(1);

	/*
	 * Wait the card to complete booting up before do anything that
	 * attempts to communicate with it.
	 */
	AAC_BUSYWAIT(AAC_FWSTATUS_GET(softs) & AAC_KERNEL_UP_AND_RUNNING,
		AAC_FWUP_TIMEOUT * 1000);
	if (!(AAC_FWSTATUS_GET(softs) & AAC_KERNEL_UP_AND_RUNNING)) {
		cmn_err(CE_CONT, "?Fatal error: controller not ready");
		goto error;
	}

	/* Read and set card supported options and settings */
	if (aac_check_firmware(softs) == AACERR)
		goto error;

	/* Clear out all interrupts */
	AAC_STATUS_CLR(softs, ~0);

	/* Setup communication space with the card */
	if (softs->comm_space_dma_handle == NULL) {
		if (aac_alloc_comm_space(softs) != AACOK)
			goto error;
	}
	if (aac_setup_comm_space(softs) != AACOK) {
		cmn_err(CE_CONT, "?Setup communication space failed");
		goto error;
	}

	/* Allocate slots */
	if ((softs->total_slots == 0) &&
		(aac_create_slots(softs) != AACOK)) {
		cmn_err(CE_CONT, "?Fatal error: slots allocate failed");
		goto error;
	}
	AACDB_PRINT((CE_NOTE, "%d slots allocated", softs->total_slots));

	/* Allocate FIBs */
	for (i = 0; i < softs->total_slots &&
		softs->total_fibs < softs->aac_max_fibs; i++) {
		slotp = &(softs->io_slot[i]);
		if (slotp->fib_phyaddr)
			continue;
		if (aac_alloc_fib(softs, slotp) != AACOK)
			break;
		slotp->index = i;
		aac_release_slot(softs, slotp);
		softs->total_fibs++;
	}
	if (softs->total_fibs == 0)
		goto error;
	AACDB_PRINT((CE_NOTE, "%d fibs allocated", softs->total_fibs));

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
			AACDB_PRINT((CE_NOTE, "sinf.AdapterTypeText = "
				"\"%s\"", sinf.AdapterTypeText));
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
			AACDB_PRINT((CE_NOTE,
				"adapter: vendor = \"%s\", product = \"%s\"",
				softs->vendor_name, softs->product_name));
		}
	}

	/* Perform acceptance of adapter-detected config changes if possible */
	if (aac_handle_adapter_config_issues(softs) != AACMPE_OK) {
		cmn_err(CE_CONT, "?Handle adapter config issues failed");
		goto error;
	}

	/* Setup containers */
	if (aac_get_container(softs) != AACOK) {
		cmn_err(CE_CONT, "?Fatal error: get container info error");
		goto error;
	}

	return (AACOK);

error:
	if (softs->state == AAC_STATE_RESET)
		return (AACERR);
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
	int i;
	struct aac_slot *slotp;

	DBCALLED(1);

	(void) aac_shutdown(softs);

	/* Release FIBs */
	for (i = 0; i < softs->total_slots; i++) {
		slotp = &(softs->io_slot[i]);
		if (slotp->fib_phyaddr == 0)
			continue;
		aac_free_fib(slotp);
		slotp->index = -1;
		softs->total_fibs--;
	}
	ASSERT(softs->total_fibs == 0);
	softs->free_io_slot_head = -1;
	softs->free_io_slot_tail = -1;
	softs->free_io_slot_len = 0;

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
	uint32_t status;

	if (statusp != NULL)
		*statusp = AAC_SRB_STS_SUCCESS;

	/* Fill in mailbox */
	AAC_MAILBOX_SET(softs, cmd, arg0, arg1, arg2, arg3);

	/* Ensure the sync command doorbell flag is cleared */
	AAC_STATUS_CLR(softs, AAC_DB_SYNC_COMMAND);

	/* Then set it to signal the adapter */
	AAC_NOTIFY(softs, AAC_DB_SYNC_COMMAND);

	/* Spin waiting for the command to complete */
	AAC_BUSYWAIT(AAC_STATUS_GET(softs) & AAC_DB_SYNC_COMMAND,
		AAC_IMMEDIATE_TIMEOUT * 1000);
	if (!(AAC_STATUS_GET(softs) & AAC_DB_SYNC_COMMAND)) {
		AACDB_PRINT((CE_WARN,
			"Sync command timed out after %d seconds (0x%x)!",
			AAC_IMMEDIATE_TIMEOUT, AAC_FWSTATUS_GET(softs)));
		return (AACERR);
	}

	/* Clear the completion flag */
	AAC_STATUS_CLR(softs, AAC_DB_SYNC_COMMAND);

	/* Get the command status */
	status = AAC_MAILBOX_GET(softs, 0);
	if (statusp != NULL)
		*statusp = status;
	if (status != AAC_SRB_STS_SUCCESS) {
		AACDB_PRINT((CE_WARN,
			"Sync command fail: status = 0x%x", status));
		return (AACERR);
	}

	return (AACOK);
}

/*
 * Send a synchronous FIB to the adapter and wait for its completion
 */
static int
aac_sync_fib(struct aac_softstate *softs, uint32_t cmd,
	struct aac_fib *fib, uint16_t fibsize)
{
	int err;
	uint32_t status;

	/* Sync fib only supports 512 bytes */
	if (fibsize > AAC_FIB_SIZE)
		return (AACERR);

	/* Setup sync fib */
	fib->Header.XferState =
		AAC_FIBSTATE_HOSTOWNED |
		AAC_FIBSTATE_INITIALISED |
		AAC_FIBSTATE_EMPTY |
		AAC_FIBSTATE_FROMHOST |
		AAC_FIBSTATE_NORM;
	fib->Header.Command = cmd;
	fib->Header.StructType = AAC_FIBTYPE_TFIB;
	fib->Header.Flags = 0;
	fib->Header.Size = fibsize;
	fib->Header.SenderSize = sizeof (struct aac_fib); /* syncfib 512B */
	fib->Header.SenderFibAddress = 0;
	fib->Header.ReceiverFibAddress = softs->sync_mode.fib_phyaddr;
	fib->Header.SenderData = 0;

	aac_dma_sync(softs->comm_space_dma_handle,
		AACOFFSET(struct aac_comm_space, sync_fib), AAC_FIB_SIZE,
		DDI_DMA_SYNC_FORDEV);

	/* Give the FIB to the controller, wait for a response. */
	err = aac_sync_mbcommand(softs, AAC_MONKER_SYNCFIB,
		fib->Header.ReceiverFibAddress, 0, 0, 0, &status);
	if (err == AACERR) {
		AACDB_PRINT((CE_WARN, "Send sync fib to controller failed"));
		return (AACERR);
	}

	return (AACOK);
}

static struct aac_fib *
aac_grab_sync_fib(struct aac_softstate *softs,
	int (*callback)(caddr_t))
{
	struct aac_fib *fib = NULL;

	if (callback == NULL_FUNC) {
		if (!mutex_tryenter(&softs->sync_mode.mutex))
			return (NULL);
	} else
		mutex_enter(&softs->sync_mode.mutex);

	fib = softs->sync_mode.fib;
	bzero(fib, sizeof (struct aac_fib));
	return (fib);
}

static void
aac_release_sync_fib(struct aac_softstate *softs)
{
	mutex_exit(&softs->sync_mode.mutex);
}

/*
 * Remove cmd from queue
 */
static struct aac_cmd *
aac_cmd_dequeue(struct aac_cmd_queue *q)
{
	struct aac_cmd *ac = NULL;

	mutex_enter(&q->q_mutex);
	if (q->q_head) {
		ac = q->q_head;
		q->q_head = ac->next;
		ac->next = NULL;
		if (q->q_head == NULL)
			q->q_tail = NULL;
		q->q_len--;
	}
	mutex_exit(&q->q_mutex);

	return (ac);
}

/*
 * Add a cmd to the tail of q
 */
static void
aac_cmd_enqueue(struct aac_cmd_queue *q, struct aac_cmd *ac)
{
	mutex_enter(&q->q_mutex);
	ac->next = NULL;
	if (!q->q_head) /* empty queue */
		q->q_head = ac;
	else
		q->q_tail->next = ac;
	q->q_tail = ac;
	q->q_len++;
	mutex_exit(&q->q_mutex);
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
aac_fib_enqueue(struct aac_softstate *softs, int queue,
	struct aac_fib *fibp)
{
	uint32_t pi, ci;
	uint32_t fib_size;
	uint32_t fib_addr;

	DBCALLED(2);

	mutex_enter(&softs->fib_mutex);
	fib_size = fibp->Header.Size;
	fib_addr = fibp->Header.ReceiverFibAddress;

	/* Get the producer/consumer indices */
	pi = softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX];
	ci = softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX];

	/*
	 * Wrap the queue first before we check the queue to see
	 * if it is full
	 */
	if (pi >= aac_qinfo[queue].size)
		pi = 0;

	/* XXX queue full */
	if ((pi + 1) == ci) {
		mutex_exit(&softs->fib_mutex);
		return (AACERR);
	}

	/* Fill in queue entry */
	(softs->qentries[queue] + pi)->aq_fib_size = fib_size;
	(softs->qentries[queue] + pi)->aq_fib_addr = fib_addr;

	/* Update producer index */
	softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX] = pi + 1;

	mutex_exit(&softs->fib_mutex);

	if (aac_qinfo[queue].notify != 0)
		AAC_NOTIFY(softs, aac_qinfo[queue].notify);

	return (AACOK);
}

/*
 * Put our response to an AIF on the response queue
 */
static int
aac_resp_enqueue(struct aac_softstate *softs, int queue,
	struct aac_fib *fibp)
{
	uint32_t pi, ci;
	uint32_t fib_size;
	uint32_t fib_addr;

	DBCALLED(2);

	/* Tell the adapter where the FIB is */
	fib_size = fibp->Header.Size;
	fib_addr = fibp->Header.SenderFibAddress;
	fibp->Header.ReceiverFibAddress = fib_addr;

	/* Get the producer/consumer indices */
	pi = softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX];
	ci = softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX];

	/*
	 * Wrap the queue first before we check the queue to see
	 * if it is full
	 */
	if (pi >= aac_qinfo[queue].size)
		pi = 0;

	/* XXX queue full */
	if ((pi + 1) == ci) {
		return (AACERR);
	}

	/* Fill in queue entry */
	(softs->qentries[queue] + pi)->aq_fib_size = fib_size;
	(softs->qentries[queue] + pi)->aq_fib_addr = fib_addr;

	/* Update producer index */
	softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX] = pi + 1;

	if (aac_qinfo[queue].notify != 0)
		AAC_NOTIFY(softs, aac_qinfo[queue].notify);

	return (AACOK);
}

/*
 * Atomically remove one entry from the nominated queue, returns 0 on
 * success or AACERR if the queue is empty.
 */
static int
aac_fib_dequeue(struct aac_softstate *softs, int queue, struct aac_fib **fibpp,
	struct aac_cmd **acpp)
{
	uint32_t pi, ci, index, fast;
	int error = 0, unfull = 0;

	DBCALLED(2);

	mutex_enter(&softs->fib_mutex);

	/* Get the producer/consumer indices */
	pi = softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX];
	ci = softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX];

	/* Check for queue empty */
	if (ci == pi) {
		error = AACERR;
		goto out;
	}

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
	switch (queue) {
	case AAC_HOST_NORM_CMD_Q:
	case AAC_HOST_HIGH_CMD_Q:
		index = (softs->qentries[queue] + ci)->aq_fib_addr /
			sizeof (struct aac_fib);
		ASSERT((index >= 0) && (index < AAC_ADAPTER_FIBS));
		*fibpp = &softs->comm_space->adapter_fibs[index];
		ASSERT(*fibpp != NULL);
		*acpp = NULL;
		break;

	case AAC_HOST_NORM_RESP_Q:
	case AAC_HOST_HIGH_RESP_Q:
		index = (softs->qentries[queue] + ci)->aq_fib_addr;
		fast = (index & 1);
		index >>= 2;
		ASSERT((index >= 0) && (index < softs->total_fibs));
		*acpp = softs->io_slot[index].acp;
		ASSERT(*acpp != NULL);
		*fibpp = softs->io_slot[index].fibp;
		if (fast) {
			(*fibpp)->Header.XferState |=
				AAC_FIBSTATE_DONEADAP;
			*((uint32_t *)((*fibpp)->data)) = 0;
		}
		break;
	default:
		cmn_err(CE_NOTE, "!Invalid queue in aac_fib_dequeue()");
		error = AACERR;
		break;
	}

	/* Update consumer index */
	softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX] = ci + 1;

out:
	mutex_exit(&softs->fib_mutex);
	if (unfull && aac_qinfo[queue].notify != 0)
		AAC_NOTIFY(softs, aac_qinfo[queue].notify);

	return (error);
}


/*
 * Request information of the container cid
 */
static struct aac_mntinforesp *
aac_get_container_info(struct aac_softstate *softs, struct aac_fib *fib,
	int cid)
{
	struct aac_mntinfo *mi;

	mi = (struct aac_mntinfo *)&fib->data[0];
	mi->Command = /* Use 64-bit LBA if enabled */
		(softs->flags & AAC_FLAGS_LBA_64BIT) ?
		VM_NameServe64 : VM_NameServe;
	mi->MntType = FT_FILESYS;
	mi->MntCount = cid;

	if (aac_sync_fib(softs, ContainerCommand, fib,
		sizeof (struct aac_fib_header) + \
		sizeof (struct aac_mntinfo)) == AACERR) {
		AACDB_PRINT((CE_WARN, "Error probe container %d", cid));
		return (NULL);
	}

	return ((struct aac_mntinforesp *)&fib->data[0]);
}

static struct aac_Container *
aac_get_container_uid(struct aac_softstate *softs, struct aac_fib *fib,
	uint32_t cid)
{
	struct aac_Container *ct;

	ct = (struct aac_Container *)&fib->data[0];
	ct->Command = VM_ContainerConfig;
	ct->CTCommand.command = CT_CID_TO_32BITS_UID;
	ct->CTCommand.param[0] = cid;

	if (aac_sync_fib(softs, ContainerCommand, fib,
		sizeof (struct aac_fib_header) + \
		sizeof (struct aac_Container)) == AACERR)
		return (NULL);
	return (ct);
}

static void
aac_init_container(struct aac_softstate *softs, uint32_t cid, uint32_t uid,
	uint64_t size)
{
	softs->container[cid].cid = cid;
	softs->container[cid].uid = uid;
	softs->container[cid].size = size;
	softs->container[cid].valid = 1;
	softs->container[cid].locked = 0;
	softs->container[cid].deleted = 0;
}

static int
aac_get_container(struct aac_softstate *softs)
{
	struct aac_fib *fib;
	struct aac_mntinforesp *mir;
	int i = 0, count = 0, total = 0;
	struct aac_Container *ct;
	uint32_t uid;
	uint64_t size;

	bzero(softs->container, sizeof (softs->container));
	fib = aac_grab_sync_fib(softs, SLEEP_FUNC);

	/* Loop over possible containers */
	do {
		if ((mir = aac_get_container_info(softs, fib, i)) == NULL)
			goto next;

		if (i == 0) /* the first time */
			count = mir->MntRespCount;

		if ((mir->Status != 0) || (mir->MntObj.VolType == CT_NONE))
			goto next;

		size = AAC_MIR_SIZE(softs, mir);
		if ((ct = aac_get_container_uid(softs, fib, i)) == NULL)
			goto next;
		if (ct->CTCommand.param[0] != CT_OK)
			goto next;

		uid = ct->CTCommand.param[1];
		aac_init_container(softs, i, uid, size);
		total++;
		AACDB_PRINT((CE_NOTE, "Container #%d found: " \
			"uid=0x%08x, size=0x%x.%08x, type=%d, name=%s",
			i, uid,
			mir->MntObj.CapacityHigh,
			mir->MntObj.Capacity,
			mir->MntObj.VolType,
			mir->MntObj.FileSystemName));
next:
		bzero(mir, sizeof (struct aac_mntinforesp));
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
aac_rescan_container(struct aac_softstate *softs)
{
	int cid;
	struct aac_fib *fib;
	struct aac_mntinforesp *mir;
	int count;
	uint64_t ct_size;
	int found;
	struct aac_Container *ct;

	AACDB_PRINT((CE_NOTE, "--- rescan containers ---"));

	cid = 0; found = 0;
	fib = aac_grab_sync_fib(softs, SLEEP_FUNC);

	do {
		if ((mir = aac_get_container_info(softs, fib, cid)) == NULL)
			goto next;

		count = mir->MntRespCount;
		if ((mir->Status != 0) || (mir->MntObj.VolType == CT_NONE))
			goto next;

		found = 1;
		ct_size = AAC_MIR_SIZE(softs, mir);
		if (softs->container[cid].valid == 0) {
			if ((ct = aac_get_container_uid(softs, fib, cid))
				== NULL)
				goto next;
			if (ct->CTCommand.param[0] != CT_OK)
				goto next;

			AACDB_PRINT((CE_NOTE, ">>> Container %d added", cid));
			aac_init_container(softs,
				cid, ct->CTCommand.param[1], ct_size);
			if ((cid + 1) > softs->container_count)
				softs->container_count = cid + 1;
		} else {
			if (softs->container[cid].size != ct_size) {
#ifdef	_LP64
				AACDB_PRINT((CE_NOTE,
					">>> Container %u size changed to %lu",
					cid, ct_size));
#else
				AACDB_PRINT((CE_NOTE,
					">>> Container %u size changed to %llu",
					cid, ct_size));
#endif
				softs->container[cid].size = ct_size;
			}
		}

next:
		if ((found == 0) && softs->container[cid].valid) {
			AACDB_PRINT((CE_NOTE, ">>> Container %d deleted", cid));
			bzero(&softs->container[cid],
				sizeof (struct aac_container));
		}

		if (mir)
			bzero(mir, sizeof (struct aac_mntinforesp));
		cid++;
		found = 0;
	} while ((cid < count) && (cid < AAC_MAX_LD));

	if (count < softs->container_count) {
		for (cid = count; cid < softs->container_count; cid++) {
			if (softs->container[cid].valid == 0)
				continue;
			AACDB_PRINT((CE_NOTE, ">>> Container %d deleted", cid));
			bzero(&softs->container[cid],
				sizeof (struct aac_container));
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
		AACDB_PRINT((CE_WARN,
			"Cannot alloc dma handle for communication area"));
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
		AACDB_PRINT((CE_WARN,
			"Cannot alloc mem for communication area"));
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
		AACDB_PRINT((CE_WARN,
			"DMA bind failed for communication area"));
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
	if (aac_sync_mbcommand(softs,
		AAC_MONKER_INITSTRUCT,
		comm_space_phyaddr + \
		AACOFFSET(struct aac_comm_space, init_data),
		0, 0, 0, NULL) == AACERR) {
		AACDB_PRINT((CE_WARN,
			"Cannot send init structrue to adapter"));
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
			idp[AAC_VPD_ID_LENGTH] =
				sp - &idp[AAC_VPD_ID_DATA];

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
		struct scsi_inquiry *inqp =
			(struct scsi_inquiry *)b_addr;
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
		} else
			bzero(bp->b_un.b_addr, bp->b_bcount);
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
	struct aac_softstate  *softs;
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;

	DBCALLED(2);

	if ((0 > tgt) || (tgt >= AAC_MAX_LD)) {
		AACDB_PRINT((CE_NOTE,
			"aac_tran_tgt_init: t%dL%d out", tgt, lun));
		return (DDI_FAILURE);
	}
	softs = AAC_TRAN2SOFTS(tran);
	if (softs->container[tgt].valid && (lun == 0)) {
		/* Only support container that has been detected and valid */
		AACDB_PRINT((CE_NOTE,
			"aac_tran_tgt_init: t%dL%d ok", tgt, lun));
		return (DDI_SUCCESS);
	} else {
		AACDB_PRINT((CE_NOTE,
			"aac_tran_tgt_init: t%dL%d", tgt, lun));
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
	int ret;

	ret = PCI_MEM_GET32(softs, AAC_OMR0);

	if (ret & AAC_KERNEL_UP_AND_RUNNING)
		ret = 0;
	else if (ret & AAC_KERNEL_PANIC)
		ret = ((ret >> 16) & 0xff) + 1; /* avoid 0 as return value */
	else
		ret = -1;

	return (ret);
}

static int
aac_quiesce_adapter(struct aac_softstate *softs)
{
	int ret = AACERR;
	int count = 0;

	ASSERT(rw_read_locked(&softs->errlock) == 0);

	/*
	 * Hold off new io commands and wait all outstanding io
	 * commands to complete
	 */
	while (aac_check_adapter_health(softs) == 0) {
		if ((softs->q_wait_sync.q_len == 0) &&
			(softs->slot_hold == 1 || softs->q_wait.q_len == 0) &&
			(softs->free_io_slot_len == softs->total_fibs)) {
			ret = AACOK;
			break;
		}
		/*
		 * Give the adapter up to 60 more seconds to complete
		 * the io commands
		 */
		if (count > 100*60)
			break;
		drv_usecwait(1000*10);
		count++;
	}

	return (ret);
}

/*
 * Abort pending commands
 */
static void
aac_abort_iocmds(struct aac_softstate *softs, int iocmd)
{
	int i;
	int reason;
	struct aac_cmd *acp;
	struct aac_slot *slotp;

	ASSERT(rw_read_locked(&softs->errlock) == 0);

	reason = (softs->state == AAC_STATE_RESET) ? CMD_RESET : CMD_ABORTED;

	/* a) outstanding commands on the controller */
	if (iocmd & AAC_IOCMD_OUTSTANDING) {
		/*
		 * NOTE: interrupt should have been fully disabled before
		 * aborting outstanding commands when doing IOP reset
		 */
		for (i = 0; i < AAC_MAX_LD; i++)
			if (softs->container[i].valid)
				softs->container[i].reset = 1;
		for (i = 0; i < softs->total_fibs; i++) {
			/*
			 * Now no other will touch the free slot queue entries,
			 * so mutex is not necessary.
			 */
			slotp = &softs->io_slot[i];
			if (slotp->index == -1)
				continue;
			acp = slotp->acp;
			ASSERT(acp != NULL);

			aac_release_slot(softs, slotp);
			acp->slotp = NULL;
			acp->state = AAC_CMD_ABORT;

			if ((slotp->fibp->Header.XferState &
				AAC_FIBSTATE_ASYNC) == 0) {
				/* IOCTL */
				mutex_enter(&softs->event_mutex);
				cv_broadcast(&softs->event);
				mutex_exit(&softs->event_mutex);
			} else {
				/*
				 * Each lun should generate a unit attention
				 * condition when reseted.
				 */
				aac_set_arq_data_reset(softs, acp);
				aac_hard_callback(softs, acp, reason);
			}
		}
	}

	/* b) in the sync FIB waiting queue */
	if (iocmd & AAC_IOCMD_SYNC) {
		while ((acp = aac_cmd_dequeue(&softs->q_wait_sync)) != NULL) {
			/* IOCTL */
			acp->state = AAC_CMD_ABORT;

			mutex_enter(&softs->event_mutex);
			cv_broadcast(&softs->event);
			mutex_exit(&softs->event_mutex);
		}
	}

	/* c) in the async FIB waiting queue */
	if (iocmd & AAC_IOCMD_ASYNC) {
		while ((acp = aac_cmd_dequeue(&softs->q_wait)) != NULL) {
			aac_set_arq_data_reset(softs, acp);
			acp->state = AAC_CMD_ABORT;

			aac_hard_callback(softs, acp, reason);
		}
	}

	ddi_trigger_softintr(softs->softint_id);
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

	AACDB_PRINT((CE_NOTE, "--- aac_reset_adapter ---"));

	ASSERT(rw_read_locked(&softs->errlock) == 0);

	/* Disable interrupt */
	AAC_DISABLE_INTR(softs);

	aac_abort_iocmds(softs, AAC_IOCMD_ALL);

	health = aac_check_adapter_health(softs);
	if (health == -1)
		goto finish;
	if (health == 0) /* flush drives if possible */
		(void) aac_shutdown(softs);

	/* Execute IOP reset */
	if ((aac_sync_mbcommand(softs, AAC_IOP_RESET, 0, 0, 0, 0, &status))
		!= AACOK) {
		struct aac_fib *fib;
		struct aac_pause_command *pc;

		if (status == AAC_SRB_STS_INVALID_REQUEST)
			cmn_err(CE_WARN, "!IOP_RESET not supported");
		else /* probably timeout */
			cmn_err(CE_WARN, "!IOP_RESET failed");

		/* Unwind aac_shutdown() */
		fib = aac_grab_sync_fib(softs, SLEEP_FUNC);
		pc = (struct aac_pause_command *)&fib->data[0];
		pc->Command = VM_ContainerConfig;
		pc->Type = CT_PAUSE_IO;
		pc->Timeout = 1;
		pc->Min = 1;
		pc->NoRescan = 1;

		(void) aac_sync_fib(softs, ContainerCommand, fib,
			sizeof (struct aac_fib_header) + \
			sizeof (struct aac_pause_command));
		aac_release_sync_fib(softs);

		goto finish;
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

static int
aac_do_reset(struct aac_softstate *softs)
{
	int ret = AACOK;
	int old_state;

	rw_enter(&softs->errlock, RW_WRITER);
	old_state = softs->state;
	softs->state = AAC_STATE_RESET;

	/*
	 * If a longer waiting time still can't drain all pending IOs,
	 * do IOP reset.
	 */
	if (aac_quiesce_adapter(softs) != AACOK) {
		if (aac_reset_adapter(softs) != AACOK)
			ret = AACERR;
	} else if (softs->q_wait.q_len > 0) {
		aac_abort_iocmds(softs, AAC_IOCMD_ASYNC);
	}

	softs->state = (ret == AACERR) ? AAC_STATE_DEAD : old_state;
	rw_exit(&softs->errlock);

	return (ret);
}

/*ARGSUSED*/
static int
aac_tran_reset(struct scsi_address *ap, int level)
{
	struct aac_softstate *softs;

	DBCALLED(1);

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);

	/*
	 * Core dump is a crucial method to analyze problems after panic,
	 * however if tran_reset() return FAILURE to sd driver, the OS
	 * will not continue to dump the core. So always return SUCCESS
	 * when core dump is being done.
	 */
	if (ddi_in_panic()) {
		if ((softs->flags & AAC_FLAGS_NEW_COMM) == 0) {
			uint32_t *pip, *cip;

			pip = &(softs->qtablep->qt_qindex
				[AAC_ADAP_NORM_CMD_Q][AAC_PRODUCER_INDEX]);
			cip = &(softs->qtablep->qt_qindex
				[AAC_ADAP_NORM_CMD_Q][AAC_CONSUMER_INDEX]);
			AAC_BUSYWAIT(*pip == *cip, 6 * 1000);
			if (*pip != *cip)
				return (0);
		}

		return (1);
	}

	if (level != RESET_ALL) {
		cmn_err(CE_NOTE, "!reset target/lun not supported");
		return (0);
	}

	if (aac_do_reset(softs) != AACOK)
		return (0);

	return (1);
}

static int
aac_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_softstate *softs;
	int old_slot_hold;

	DBCALLED(1);

	if (pkt != NULL)
		return (0);

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	rw_enter(&softs->errlock, RW_WRITER);

	old_slot_hold = softs->slot_hold;
	softs->slot_hold = 1;
	aac_abort_iocmds(softs, AAC_IOCMD_ASYNC);
	softs->slot_hold = old_slot_hold;

	rw_exit(&softs->errlock);
	return (1);
}

static void
aac_free_dmamap(struct aac_cmd *ac)
{
	/* Free dma mapping */
	if (ac->flags & AAC_CMD_DMA_VALID) {
		ASSERT(ac->buf_dma_handle);
		(void) ddi_dma_unbind_handle(ac->buf_dma_handle);
		ac->flags &= ~AAC_CMD_DMA_VALID;
	}

	if (ac->abp != NULL) { /* free non-aligned buf DMA */
		ASSERT(ac->buf_dma_handle);
		ddi_dma_mem_free(&ac->abh);
		ac->abp = NULL;
	}

	if (ac->buf_dma_handle) {
		ddi_dma_free_handle(&ac->buf_dma_handle);
		ac->buf_dma_handle = NULL;
	}
}

static int
aac_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_softstate *softs;
	struct aac_cmd *ac;
	struct aac_fib *fibp;
	struct buf *bp;
	union scsi_cdb *cdbp;
	uchar_t cmd;
	int ret_val;
	int target = ap->a_target;
	int lun = ap->a_lun;
	int capacity;
	uint64_t blkno;
	uint32_t blkcnt;

	DBCALLED(2);

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);

	if (!softs->container[target].valid || lun != 0 ||
		softs->state == AAC_STATE_DEAD) {
		AACDB_PRINT((CE_WARN,
			"Cannot send cmd to target t%dL%d: %s",
			target, lun,
			(softs->state == AAC_STATE_DEAD) ?
			"adapter dead" : "target invalid"));
		return (TRAN_FATAL_ERROR);
	}

	rw_enter(&softs->errlock, RW_READER);

	/* Init ac and pkt */
	ac = PKT2AC(pkt);
	cdbp = (union scsi_cdb *)pkt->pkt_cdbp;
	bp = ac->bp;
	cmd = cdbp->scc_cmd;
	ac->flags |= (pkt->pkt_flags & FLAG_NOINTR) ? AAC_CMD_NO_INTR : 0;
	ac->state = AAC_CMD_INCMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = STAT_SYNC;
	*pkt->pkt_scbp = 0; /* clear arq scsi_status */

	AACDB_PRINT_SCMD(pkt);

	switch (cmd) {
	case SCMD_INQUIRY: /* inquiry */
		ac->flags |= AAC_CMD_SOFT_INTR;
		aac_free_dmamap(ac);
		aac_inquiry(softs, pkt, cdbp, bp);
		aac_soft_callback(softs, ac, CMD_CMPLT);
		ret_val = TRAN_ACCEPT;
		break;

	case SCMD_READ_CAPACITY: /* read capacity */
		ac->flags |= AAC_CMD_SOFT_INTR;
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			struct scsi_capacity cap;
			uint64_t last_lba;

			/* check 64-bit LBA */
			last_lba = softs->container[target].size - 1;
			if (last_lba > 0xffffffffull) {
				cap.capacity = 0xffffffff;
			} else {
				cap.capacity = BE_32(last_lba);
			}
			cap.lbasize = BE_32(AAC_SECTOR_SIZE);

			aac_free_dmamap(ac);
			if (bp->b_flags & (B_PHYS|B_PAGEIO))
				bp_mapin(bp);
			bcopy(&cap, bp->b_un.b_addr, 8);
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		aac_soft_callback(softs, ac, CMD_CMPLT);
		ret_val = TRAN_ACCEPT;
		break;

	case SCMD_SVC_ACTION_IN_G4: /* read capacity 16 */
		/* Check if containers need 64-bit LBA support */
		if (cdbp->cdb_opaque[1] != SSVC_ACTION_READ_CAPACITY_G4)
			goto unknown;

		ac->flags |= AAC_CMD_SOFT_INTR;
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			struct scsi_capacity_16 cap16;
			int cap_len = sizeof (struct scsi_capacity_16);

			bzero(&cap16, cap_len);
			cap16.sc_capacity =
				BE_64(softs->container[target].size);
			cap16.sc_lbasize = BE_32(AAC_SECTOR_SIZE);

			aac_free_dmamap(ac);
			if (bp->b_flags & (B_PHYS | B_PAGEIO))
				bp_mapin(bp);
			bcopy(&cap16, bp->b_un.b_addr, cap_len);
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		aac_soft_callback(softs, ac, CMD_CMPLT);
		ret_val = TRAN_ACCEPT;
		break;

	case SCMD_READ_G4: /* read_16 */
	case SCMD_WRITE_G4: /* write_16 */
		if ((softs->flags & AAC_FLAGS_RAW_IO) == 0) {
			AACDB_PRINT((CE_WARN, "64-bit LBA not supported"));
			goto unknown;
		}
		/*FALLTHRU*/

	case SCMD_READ: /* read_6 */
	case SCMD_READ_G1: /* read_10 */
	case SCMD_WRITE: /* write_6 */
	case SCMD_WRITE_G1: /* write_10 */
		ac->flags |= AAC_CMD_HARD_INTR;
		if (!(ac->flags & AAC_CMD_DMA_VALID) ||
			!(ac->fib.Header.XferState &
			AAC_FIBSTATE_HOSTOWNED)) {
			ret_val = TRAN_BADPKT;
			break;
		}

		blkno = AAC_GETGXADDR(ac->cmdlen, cdbp);
		fibp = &ac->fib;
		if (softs->flags & AAC_FLAGS_RAW_IO) {
			/* Fill in correct blkno */
			struct aac_raw_io *io =
				(struct aac_raw_io *)&fibp->data[0];
			io->BlockNumber = blkno;
			io->Flags = (ac->flags & AAC_CMD_BUF_READ) ? 1:0;
			blkcnt = io->ByteCount / AAC_BLK_SIZE;
		} else if (softs->flags & AAC_FLAGS_SG_64BIT) {
			/* Fill in correct blkno */
			if (ac->flags & AAC_CMD_BUF_READ) {
				struct aac_blockread64 *br =
					(struct aac_blockread64 *) \
					&fibp->data[0];
				br->BlockNumber = (uint32_t)blkno;
				blkcnt = br->SectorCount;
			} else {
				struct aac_blockwrite64 *bw =
					(struct aac_blockwrite64 *) \
					&fibp->data[0];
				bw->BlockNumber = (uint32_t)blkno;
				blkcnt = bw->SectorCount;
			}
		} else {
			/* Fill in correct blkno */
			if (ac->flags & AAC_CMD_BUF_READ) {
				struct aac_blockread *br =
					(struct aac_blockread *)&fibp->data[0];
				br->BlockNumber = (uint32_t)blkno;
				blkcnt = br->ByteCount / AAC_BLK_SIZE;
			} else {
				struct aac_blockwrite *bw =
					(struct aac_blockwrite *)&fibp->data[0];
				bw->BlockNumber = (uint32_t)blkno;
				blkcnt = bw->ByteCount / AAC_BLK_SIZE;
			}
		}

		/*
		 * If lba > array size AND rawio, the adapter may hang. So
		 * check it before sending.
		 * NOTE: (blkno + blkcnt) may overflow
		 */
		if ((blkno >= softs->container[target].size) ||
			((blkno + blkcnt) > softs->container[target].size)) {
			/*
			 * Request exceed the capacity of disk set error
			 * block number to last LBA + 1
			 */
			aac_set_arq_data(pkt, KEY_ILLEGAL_REQUEST,
				0x21, 0x00, softs->container[target].size);
			aac_soft_callback(softs, ac, CMD_CMPLT);
			ret_val = TRAN_ACCEPT;
			break;
		}

		if ((ac->flags & AAC_CMD_NO_INTR) ||
			(ac->flags & AAC_CMD_SOFT_INTR)) {
			/* Poll pkt */
			if (aac_do_poll_io(softs, ac) == AACOK) {
				aac_soft_callback(softs, ac, CMD_CMPLT);
				ret_val = TRAN_ACCEPT;
			} else
				ret_val = TRAN_BADPKT;
		} else {
			/* Async pkt */
			if (aac_do_async_io(softs, ac) == AACOK)
				ret_val = TRAN_ACCEPT;
			else
				ret_val = TRAN_BUSY;
		}
		break;

	case SCMD_MODE_SENSE: /* mode_sense_6 */
	case SCMD_MODE_SENSE_G1: /* mode_sense_10 */
		ac->flags |= AAC_CMD_SOFT_INTR;
		aac_free_dmamap(ac);
		if (softs->container[target].size > 0xffffffffull)
			capacity = 0xffffffff; /* 64-bit LBA */
		else
			capacity = softs->container[target].size;
		aac_mode_sense(softs, pkt, cdbp, bp, capacity);
		aac_soft_callback(softs, ac, CMD_CMPLT);
		ret_val = TRAN_ACCEPT;
		break;

	case SCMD_TEST_UNIT_READY:
	case SCMD_REQUEST_SENSE:
	case SCMD_FORMAT:
	case SCMD_START_STOP:
	case SCMD_SYNCHRONIZE_CACHE:
		ac->flags |= AAC_CMD_SOFT_INTR;
		aac_free_dmamap(ac);
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			if (ac->flags & AAC_CMD_BUF_READ) {
				if (bp->b_flags & (B_PHYS|B_PAGEIO))
					bp_mapin(bp);
				bzero(bp->b_un.b_addr, bp->b_bcount);
			}
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		aac_soft_callback(softs, ac, CMD_CMPLT);
		ret_val = TRAN_ACCEPT;
		break;

	case SCMD_DOORLOCK:
		ac->flags |= AAC_CMD_SOFT_INTR;
		aac_free_dmamap(ac);
		if (pkt->pkt_cdbp[4] & 0x01)
			softs->container[target].locked = 1;
		else
			softs->container[target].locked = 0;
		aac_soft_callback(softs, ac, CMD_CMPLT);
		ret_val = TRAN_ACCEPT;
		break;

	default: /* unknown command */
unknown:
		AACDB_PRINT((CE_CONT, "SCMD not supported"));
		aac_free_dmamap(ac);
		aac_set_arq_data(pkt, KEY_ILLEGAL_REQUEST, 0x20, 0x00, 0);
		aac_soft_callback(softs, ac, CMD_CMPLT);
		ret_val = TRAN_ACCEPT;
		break;
	}

	rw_exit(&softs->errlock);
	return (ret_val);
}

static int
aac_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int rval;
	struct aac_softstate *softs;
	int target = ap->a_target;
	int lun = ap->a_lun;

	DBCALLED(1);

	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT((CE_WARN,
			"GetCap> %s not supported: whom=%d", cap, whom));
		return (-1);
	}

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	if (!softs->container[target].valid || !(lun == 0)) {
		AACDB_PRINT((CE_WARN, "Bad target to getcap"));
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
		if (softs->container[target].size > 0xffffffffull)
			rval = 0xffffffff; /* 64-bit LBA */
		else
			rval = softs->container[target].size;
		break;
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		rval = 1;
		break;
	default:
		rval = -1;
		break;
	}
	AACDB_PRINT((CE_NOTE, "GetCap> %s t%dL%d: rval=%d",
		cap, ap->a_target, ap->a_lun, rval));

	return (rval);
}

/*ARGSUSED*/
static int
aac_tran_setcap(struct scsi_address *ap, char *cap, int value,
	int whom)
{
	int rval;
	struct aac_softstate *softs;
	int target = ap->a_target;
	int lun = ap->a_lun;

	DBCALLED(1);

	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT((CE_WARN,
			"SetCap> %s not supported: whom=%d", cap, whom));
		return (-1);
	}

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);

	if (!softs->container[target].valid || !(lun == 0)) {
		AACDB_PRINT((CE_WARN, "Bad target to setcap"));
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		rval = (value == 1) ? 1 : 0;
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		if (softs->container[target].size > 0xffffffffull) {
			rval = -1; /* 64-bit LBA */
		} else {
			softs->container[target].size = (uint_t)value;
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
	AACDB_PRINT((CE_NOTE, "SetCap> %s t%dL%d val=%d: rval=%d",
		cap, ap->a_target, ap->a_lun, value, rval));

	return (rval);
}

static void
aac_tran_destroy_pkt(struct scsi_address *ap,
	struct scsi_pkt *pkt)
{
	struct aac_cmd *ac = PKT2AC(pkt);

	DBCALLED(2);

	aac_free_dmamap(ac);
	ASSERT(ac->slotp == NULL);
	scsi_hba_pkt_free(ap, pkt);
}

static struct scsi_pkt *
aac_tran_init_pkt(struct scsi_address *ap,
	struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
	int tgtlen, int flags, int (*callback)(), caddr_t arg)
{
	struct aac_softstate *softs;
	struct aac_cmd *ac, *new_ac = NULL;
	int err;
	uint_t dma_flags = 0;
	int (*cb) (caddr_t);
	int slen, hbalen;
	size_t transfer_num;

	DBCALLED(2);

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);

	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	/* Allocate pkt */
	if (pkt == NULL) {
		/* Force auto request sense */
		/* 64-bit LBA needs descriptor format sense data */
		slen = (sizeof (struct scsi_extended_sense) <
			AAC_SENSE_DATA_DESCR_LEN) ?
			(sizeof (struct scsi_arq_status) +
			AAC_SENSE_DATA_DESCR_LEN -
			sizeof (struct scsi_extended_sense)) :
			sizeof (struct scsi_arq_status);
		if (statuslen > slen)
			slen = statuslen;
		hbalen = sizeof (struct aac_cmd) - sizeof (struct aac_fib) +
			softs->aac_max_fib_size;
		pkt = scsi_hba_pkt_alloc(softs->devinfo_p, ap, cmdlen,
			slen, tgtlen, hbalen, callback, arg);
		if (pkt == NULL) {
			AACDB_PRINT((CE_WARN, "Alloc scsi pkt failed"));
			return (NULL);
		}
		ac = new_ac = PKT2AC(pkt);
		ac->pkt = pkt;
		ac->cmdlen = cmdlen;
		ac->slotp = NULL;

		/*
		 * We will still use this point to fake some
		 * infomation in tran_start
		 */
		ac->bp = bp;

		/* Set cmd flags according to pkt alloc flags */
		if (flags & PKT_CONSISTENT)
			ac->flags |= AAC_CMD_CONSISTENT;
		if (flags & PKT_DMA_PARTIAL)
			ac->flags |= AAC_CMD_DMA_PARTIAL;
	}
	if (bp == NULL || (bp->b_bcount == 0))
		return (pkt);

	/* We need to transfer data, so we alloc DMA resources for this pkt */
	ac = PKT2AC(pkt);
	if (!(ac->flags & AAC_CMD_DMA_VALID)) {

		ASSERT(new_ac != NULL); /* pkt is reused without init */

		/* Set dma flags */
		if (BUF_IS_READ(bp)) {
			dma_flags |= DDI_DMA_READ;
			ac->flags |= AAC_CMD_BUF_READ;
		} else {
			dma_flags |= DDI_DMA_WRITE;
			ac->flags |= AAC_CMD_BUF_WRITE;
		}
		if (flags & PKT_CONSISTENT)
			dma_flags |= DDI_DMA_CONSISTENT;
		if (flags & PKT_DMA_PARTIAL)
			dma_flags |= DDI_DMA_PARTIAL;

		/* Alloc buf dma handle */
		err = DDI_SUCCESS;
		if (!ac->buf_dma_handle)
			err = ddi_dma_alloc_handle(softs->devinfo_p,
				&softs->buf_dma_attr, cb, NULL,
				&ac->buf_dma_handle);
		if (err != DDI_SUCCESS) {
			AACDB_PRINT((CE_WARN,
				"Can't allocate DMA handle, errno=%d", err));
			if (new_ac)
				scsi_hba_pkt_free(ap, pkt);
			return (NULL);
		}

		/* Bind buf */
		if ((((uintptr_t)bp->b_un.b_addr & AAC_DMA_ALIGN_MASK) == 0) &&
			((bp->b_bcount & AAC_DMA_ALIGN_MASK) == 0)) {
			err = ddi_dma_buf_bind_handle(ac->buf_dma_handle,
				bp, dma_flags, DDI_DMA_SLEEP, NULL,
				&ac->cookie, &ac->left_cookien);
		} else {
			size_t bufsz;

			AACDB_PRINT((CE_WARN,
				"non-aligned buffer: addr=0x%p, cnt=%lu",
				(void *)bp->b_un.b_addr, bp->b_bcount));
			if (bp->b_flags & (B_PAGEIO|B_PHYS))
				bp_mapin(bp);

			err = ddi_dma_mem_alloc(ac->buf_dma_handle,
				AAC_ROUNDUP(bp->b_bcount, AAC_DMA_ALIGN),
				&aac_acc_attr, DDI_DMA_STREAMING,
				DDI_DMA_SLEEP, NULL,
				&ac->abp, &bufsz, &ac->abh);

			if (err != DDI_SUCCESS) {
				AACDB_PRINT((CE_NOTE,
					"Cannot alloc DMA to non-aligned buf"));
				bioerror(bp, 0);
				goto error_out;
			}

			if (ac->flags & AAC_CMD_BUF_WRITE)
				bcopy(bp->b_un.b_addr, ac->abp, bp->b_bcount);

			err = ddi_dma_addr_bind_handle(ac->buf_dma_handle, NULL,
				ac->abp, bufsz, dma_flags, DDI_DMA_SLEEP, 0,
				&ac->cookie, &ac->left_cookien);
		}

		switch (err) {
		case DDI_DMA_PARTIAL_MAP:
			ac->flags |= AAC_CMD_DMA_VALID;
			if (ddi_dma_numwin(ac->buf_dma_handle, &ac->total_nwin)
				== DDI_FAILURE) {
				AACDB_PRINT((CE_WARN,
					"Cannot get number of DMA windows"));
				bioerror(bp, 0);
				goto error_out;
			}
			AACDB_PRINT((CE_NOTE,
				"buf bind, %d segs", ac->left_cookien));
			ac->cur_win = 0;
			break;

		case DDI_DMA_MAPPED:
			AACDB_PRINT((CE_NOTE,
				"buf bind, %d segs", ac->left_cookien));
			ac->flags |= AAC_CMD_DMA_VALID;
			ac->cur_win = 0;
			ac->total_nwin = 1;
			break;

		case DDI_DMA_NORESOURCES:
			bioerror(bp, 0);
			goto error_out;
		case DDI_DMA_BADATTR:
		case DDI_DMA_NOMAPPING:
			bioerror(bp, EFAULT);
			goto error_out;
		case DDI_DMA_TOOBIG:
		default:
			bioerror(bp, EINVAL);
			goto error_out;
		}
	}

	/* Build FIB for this ac/pkt and return remaining byte count */
	transfer_num = aac_cmd_fib(softs, ac);
	if (transfer_num == 0)
		goto error_out;
	pkt->pkt_resid = bp->b_bcount - transfer_num;

	AACDB_PRINT((CE_NOTE,
		"bp=0x%p, xfered=%d/%d, resid=%d",
		(void *)bp->b_un.b_addr,
		(int)ac->total_xfer, (int)bp->b_bcount, (int)pkt->pkt_resid));

	ASSERT((pkt->pkt_resid >= 0) ||
		((bp->b_bcount & AAC_DMA_ALIGN_MASK) != 0));

	if (pkt->pkt_resid < 0)
		pkt->pkt_resid = 0;

	return (pkt);

error_out:
	AACDB_PRINT((CE_WARN, "Cannot bind buf for DMA"));
	aac_free_dmamap(ac);
	if (new_ac)
		scsi_hba_pkt_free(ap, pkt);
	return (NULL);
}

/*
 * tran_sync_pkt(9E) - explicit DMA synchronization
 */
/*ARGSUSED*/
static void
aac_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_cmd *ac = PKT2AC(pkt);
	struct buf *bp;

	DBCALLED(2);

	if (ac->buf_dma_handle) {
		aac_dma_sync(ac->buf_dma_handle, 0, 0,
			(ac->flags & AAC_CMD_BUF_WRITE) ?
			DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
		if (ac->abp != NULL) {
			bp = ac->bp;
			bcopy(ac->abp, bp->b_un.b_addr, bp->b_bcount);
		}
	}
}

/*
 * tran_dmafree(9E) - deallocate DMA resources allocated for command
 */
/*ARGSUSED*/
static void
aac_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_cmd *ac = PKT2AC(pkt);

	DBCALLED(2);

	aac_free_dmamap(ac);
}

/*ARGSUSED*/
static int
aac_tran_quiesce(dev_info_t *dip)
{
	struct aac_softstate *softs;
	scsi_hba_tran_t *tran;
	int ret = 1;

	DBCALLED(1);

	tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	softs = AAC_TRAN2SOFTS(tran);

	rw_enter(&softs->errlock, RW_WRITER);
	if (softs->state != AAC_STATE_RUN)
		goto finish;

	softs->slot_hold = 1;
	if (aac_quiesce_adapter(softs) == AACOK) {
		softs->state = AAC_STATE_QUIESCE;
		ret = 0;
	} else {
		softs->slot_hold = 0;
	}

finish:
	rw_exit(&softs->errlock);
	return (ret);
}

/*ARGSUSED*/
static int
aac_tran_unquiesce(dev_info_t *dip)
{
	struct aac_softstate *softs;
	scsi_hba_tran_t *tran;

	DBCALLED(1);

	tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	softs = AAC_TRAN2SOFTS(tran);

	rw_enter(&softs->errlock, RW_WRITER);

	if (softs->state != AAC_STATE_QUIESCE) {
		rw_exit(&softs->errlock);
		return (1);
	}

	softs->slot_hold = 0;
	softs->state = AAC_STATE_RUN;

	rw_exit(&softs->errlock);

	aac_start_waiting_io(softs);
	return (0);
}

static int
aac_hba_setup(struct aac_softstate *softs)
{
	scsi_hba_tran_t *hba_tran = NULL;
	int err;

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
	err = scsi_hba_attach_setup(softs->devinfo_p, &softs->buf_dma_attr,
		hba_tran, SCSI_HBA_TRAN_CLONE);
	if (err != DDI_SUCCESS) {
		scsi_hba_tran_free(hba_tran);
		AACDB_PRINT((CE_WARN, "aac_hba_setup failed"));
		return (AACERR);
	}

	return (AACOK);
}

static size_t
aac_cmd_fib(struct aac_softstate *softs, struct aac_cmd *ac)
{
	int count, sgelem;
	off_t off;
	size_t len;
	struct aac_sg_table *sgmap;
	struct aac_sg_table64 *sgmap64;
	struct aac_sg_tableraw *sgmapraw;
	ddi_dma_handle_t dma_handle;
	ddi_dma_cookie_t *cookiep;
	uint_t cookien;
	uint32_t *bytecountp, *sgcountp, cur_total_xfer, next_total_xfer;
	struct scsi_pkt *pkt;
	struct scsi_address *ap;
	struct aac_fib *fibp;
	uint16_t *seccountp, *fib_datasizep;

	fibp = &ac->fib;
	pkt = ac->pkt;
	ap = &pkt->pkt_address;
	dma_handle = ac->buf_dma_handle;
	cookiep = &ac->cookie;
	cookien = ac->left_cookien;

	if (cookien == 0 && ac->total_nwin == 1)
		return (0); /* nothing to be transfered */
	/* Fill in fib header */
	fibp->Header.XferState =
		AAC_FIBSTATE_HOSTOWNED |
		AAC_FIBSTATE_INITIALISED |
		AAC_FIBSTATE_EMPTY |
		AAC_FIBSTATE_FROMHOST |
		AAC_FIBSTATE_REXPECTED |
		AAC_FIBSTATE_NORM |
		AAC_FIBSTATE_ASYNC |
		AAC_FIBSTATE_FAST_RESPONSE; /* enable fast io */
	fibp->Header.Command = ContainerCommand;
	fibp->Header.StructType = AAC_FIBTYPE_TFIB;
	fibp->Header.Flags = 0; /* don't care */
	fibp->Header.Size = sizeof (struct aac_fib_header);
	fibp->Header.SenderSize = softs->aac_max_fib_size;
	fibp->Header.ReceiverFibAddress = 0;
	fibp->Header.SenderData = 0; /* don't care */
	fib_datasizep = &fibp->Header.Size; /* will be filled in later */

	if (softs->flags & AAC_FLAGS_RAW_IO) {
		/* Fill in fib data */
		struct aac_raw_io *io;

		fibp->Header.Command = RawIo;
		io = (struct aac_raw_io *)&fibp->data[0];
		*fib_datasizep += sizeof (struct aac_raw_io);
		io->ContainerId =
			AAC_TRAN2SOFTS(ap->a_hba_tran)-> \
			container[ap->a_target].cid;
		io->BpTotal = 0;
		io->BpComplete = 0;
		sgmapraw = &io->SgMapRaw;
		bytecountp = &io->ByteCount;
		sgcountp = &sgmapraw->SgCount;
		sgelem = sizeof (struct aac_sg_entryraw);
	} else if (softs->flags & AAC_FLAGS_SG_64BIT) {
		fibp->Header.Command = ContainerCommand64;
		/* Fill in fib data */
		if (ac->flags & AAC_CMD_BUF_READ) {
			struct aac_blockread64 *br;

			br = (struct aac_blockread64 *)&fibp->data[0];
			*fib_datasizep += sizeof (struct aac_blockread64);
			br->Command = VM_CtHostRead64;
			br->ContainerId =
				AAC_TRAN2SOFTS(ap->a_hba_tran)-> \
				container[ap->a_target].cid;
			br->Pad = 0;
			br->Flags = 0;
			sgmap64 = &br->SgMap64;
			seccountp = &br->SectorCount;
		} else {
			struct aac_blockwrite64 *bw;

			bw = (struct aac_blockwrite64 *)&fibp->data[0];
			*fib_datasizep += sizeof (struct aac_blockwrite64);
			bw->Command = VM_CtHostWrite64;
			bw->ContainerId =
				AAC_TRAN2SOFTS(ap->a_hba_tran)-> \
				container[ap->a_target].cid;
			bw->Pad = 0;
			bw->Flags = 0;
			sgmap64 = &bw->SgMap64;
			seccountp = &bw->SectorCount;
		}
		sgcountp = &sgmap64->SgCount;
		sgelem = sizeof (struct aac_sg_entry64);
	} else {
		fibp->Header.Command = ContainerCommand;
		/* Fill in fib data */
		if (ac->flags & AAC_CMD_BUF_READ) {
			struct aac_blockread *br;

			br = (struct aac_blockread *)&fibp->data[0];
			*fib_datasizep += sizeof (struct aac_blockread);
			br->Command = VM_CtBlockRead;
			br->ContainerId =
				AAC_TRAN2SOFTS(ap->a_hba_tran)-> \
				container[ap->a_target].cid;
			sgmap = &br->SgMap;
			bytecountp = &br->ByteCount;
		} else {
			struct aac_blockwrite *bw;

			bw = (struct aac_blockwrite *)&fibp->data[0];
			*fib_datasizep += sizeof (struct aac_blockwrite);
			bw->Command = VM_CtBlockWrite;
			bw->ContainerId =
				AAC_TRAN2SOFTS(ap->a_hba_tran)-> \
				container[ap->a_target].cid;
			bw->Stable = CUNSTABLE;
			sgmap = &bw->SgMap;
			bytecountp = &bw->ByteCount;
		}
		sgcountp = &sgmap->SgCount;
		sgelem = sizeof (struct aac_sg_entry);
	}

	/* Move cookie and window to build s/g map */
	if (cookien == 0) { /* we need to move window */
		if ((ac->cur_win + 1) < ac->total_nwin) {
			int err;
			ac->cur_win++;
			err = ddi_dma_getwin(ac->buf_dma_handle, ac->cur_win,
				&off, &len, cookiep, &cookien);
			if (err != DDI_SUCCESS)
				return (0);
		} else
			return (0);
	}

	count = 0;
	cur_total_xfer = 0;
	next_total_xfer = cookiep->dmac_size;
	/*
	 * Cookie loop
	 * Note: The old DMA engine do not correctly handle dma_attr_maxxfer
	 * attribute. So we have to ensure it by ourself.
	 */
	while (count < softs->aac_sg_tablesize &&
		next_total_xfer <= softs->buf_dma_attr.dma_attr_maxxfer) {
		if (softs->flags & AAC_FLAGS_RAW_IO) {
			sgmapraw->SgEntryRaw[count].SgAddress =
				cookiep->dmac_laddress;
			sgmapraw->SgEntryRaw[count].SgByteCount =
				cookiep->dmac_size;
			sgmapraw->SgEntryRaw[count].Next = 0;
			sgmapraw->SgEntryRaw[count].Prev = 0;
			sgmapraw->SgEntryRaw[count].Flags = 0;
		} else if (softs->flags & AAC_FLAGS_SG_64BIT) {
			sgmap64->SgEntry64[count].SgAddress =
				cookiep->dmac_laddress;
			sgmap64->SgEntry64[count].SgByteCount =
				cookiep->dmac_size;
		} else {
			sgmap->SgEntry[count].SgAddress =
				cookiep->dmac_laddress;
			sgmap->SgEntry[count].SgByteCount =
				cookiep->dmac_size;
		}

		count++;
		cur_total_xfer = next_total_xfer;
		cookien--;
		if (cookien > 0)
			ddi_dma_nextcookie(dma_handle, cookiep);
		else
			break;
		next_total_xfer += cookiep->dmac_size;
	}

	if ((softs->flags & AAC_FLAGS_SG_64BIT) &&
		(softs->flags & AAC_FLAGS_RAW_IO) == 0)
		*seccountp = (uint16_t)(cur_total_xfer/AAC_BLK_SIZE);
	else
		*bytecountp = cur_total_xfer;
	*sgcountp = count;

	ac->left_cookien = cookien;
	ac->total_xfer += cur_total_xfer;
	AACDB_PRINT((CE_NOTE, "    blks xfered=%d", cur_total_xfer >> 9));

	/* Calculate fib data size */
	*fib_datasizep += (count - 1) * sgelem;

	return (ac->total_xfer);
}

static void
aac_start_io(struct aac_softstate *softs, struct aac_slot *slotp,
	struct aac_cmd *ac)
{
	int status;

	/* Set ac and pkt */
	ac->slotp = slotp;
	ac->fib.Header.ReceiverFibAddress = slotp->fib_phyaddr;
	ac->fib.Header.SenderFibAddress = slotp->index << 2;
	bcopy(&ac->fib, slotp->fibp,
		ac->fib.Header.Size); /* only copy data of needed length */
	aac_dma_sync(slotp->fib_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);
	if (ac->pkt) { /* ac from ioctl has no pkt */
		ac->pkt->pkt_state =
			STATE_GOT_BUS |
			STATE_GOT_TARGET |
			STATE_SENT_CMD;
		ac->timeout = ac->pkt->pkt_time;
	} else
		ac->timeout = AAC_IOCTL_TIMEOUT;
	ac->start_time = ddi_get_time();

	/*
	 * NOTE: Assigning ac to acp should be done after ac has been inited
	 * and before the slot being sent for aac_daemon() to check timeout.
	 * This way no seperate busy queue and en/de-queue operations are
	 * needed.
	 */
	slotp->acp = ac;

	if (softs->flags & AAC_FLAGS_NEW_COMM) {
		status = aac_send_command(softs, slotp);
	} else {
		/*
		 * If fib can not be enqueued, the adapter is in an abnormal
		 * state, there will be no interrupt to us.
		 */
		status = aac_fib_enqueue(softs,
			AAC_ADAP_NORM_CMD_Q, slotp->fibp);
	}

	/*
	 * NOTE: We send command only when slots availabe, so should never
	 * reach here.
	 */
	if (status != AACOK) {
		AACDB_PRINT((CE_NOTE, "SCMD send failed"));
		aac_release_slot(softs, ac->slotp);
		ac->slotp = NULL;
		ac->pkt->pkt_state &= ~STATE_SENT_CMD;
		aac_hard_callback(softs, ac, CMD_INCOMPLETE);
		ddi_trigger_softintr(softs->softint_id);
	}
}

static void
aac_start_waiting_io(struct aac_softstate *softs)
{
	struct aac_cmd *ac;
	struct aac_slot *slotp;

	/* Serve as many waiting io's as possible */
	while ((slotp = aac_get_slot(softs)) != NULL) {
		/*
		 * Sync FIB io is served before async FIB io so that io requests
		 * sent by interactive userland commands get responded asap.
		 */
		if ((ac = aac_cmd_dequeue(&softs->q_wait_sync)) == NULL &&
			(softs->slot_hold == 1 ||
			(ac = aac_cmd_dequeue(&softs->q_wait)) == NULL)) {
			aac_release_slot(softs, slotp);
			break;
		}

		aac_start_io(softs, slotp, ac);
	}
}

static void
aac_drain_comp_q(struct aac_softstate *softs)
{
	struct aac_cmd *ac;
	struct scsi_pkt *pkt;

	while ((ac = aac_cmd_dequeue(&softs->q_comp)) != NULL) {
		ASSERT(ac->pkt != NULL);
		pkt = ac->pkt;

		switch (pkt->pkt_reason) {
		case CMD_TIMEOUT:
			pkt->pkt_statistics |= STAT_TIMEOUT;
			break;
		case CMD_RESET:
			/* aac support only RESET_ALL */
			pkt->pkt_statistics |= STAT_BUS_RESET;
			if (ac->flags & AAC_CMD_TIMEOUT) {
				pkt->pkt_statistics |= STAT_TIMEOUT;
				pkt->pkt_reason = CMD_TIMEOUT;
			}
			break;
		case CMD_ABORTED:
			pkt->pkt_statistics |= STAT_ABORTED;
			if (ac->flags & AAC_CMD_TIMEOUT) {
				pkt->pkt_statistics |= STAT_TIMEOUT;
				pkt->pkt_reason = CMD_TIMEOUT;
			}
			break;
		}

		if (ac->pkt->pkt_comp)
			(*ac->pkt->pkt_comp)(ac->pkt);
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
		AACDB_PRINT((CE_WARN,
			"Cannot alloc dma handle for slot fib area"));
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
		AACDB_PRINT((CE_WARN,
			"Cannot alloc mem for slot fib area"));
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
		AACDB_PRINT((CE_WARN,
			"dma bind failed for slot fib area"));
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

static int
aac_create_slots(struct aac_softstate *softs)
{
	int i;

	softs->io_slot = kmem_zalloc(sizeof (struct aac_slot) * \
		softs->aac_max_fibs, KM_SLEEP);
	if (softs->io_slot == NULL) {
		AACDB_PRINT((CE_WARN, "Cannot allocate slot"));
		return (AACERR);
	}
	for (i = 0; i < softs->aac_max_fibs; i++)
		softs->io_slot[i].index = -1;
	softs->total_slots = softs->aac_max_fibs;
	softs->free_io_slot_head = -1;
	softs->free_io_slot_tail = -1;
	softs->free_io_slot_len = 0;
	softs->total_fibs = 0;
	return (AACOK);
}

static void
aac_destroy_slots(struct aac_softstate *softs)
{
	ASSERT(softs->total_fibs == 0);

	kmem_free(softs->io_slot, sizeof (struct aac_slot) * \
		softs->total_slots);
	softs->io_slot = NULL;
	softs->total_slots = 0;
}

struct aac_slot *
aac_get_slot(struct aac_softstate *softs)
{
	struct aac_slot *slotp = NULL;
	int i;

	mutex_enter(&softs->slot_mutex);
	if (softs->free_io_slot_head != -1) {
		i = softs->free_io_slot_head;
		slotp = &softs->io_slot[i];
		softs->free_io_slot_head = slotp->next;
		slotp->next = -1;

		if (softs->free_io_slot_head == -1)
			softs->free_io_slot_tail = -1;
		softs->free_io_slot_len--;
	}
	mutex_exit(&softs->slot_mutex);

	if (slotp)
		slotp->index = i;

	return (slotp);
}

void
aac_release_slot(struct aac_softstate *softs, struct aac_slot *slotp)
{
	int index;

	index = slotp->index;
	ASSERT((index >= 0) && (index < softs->total_slots));
	ASSERT(slotp == &softs->io_slot[index]);

	slotp->acp = NULL;
	slotp->index = -1;

	mutex_enter(&softs->slot_mutex);
	slotp->next = -1;
	if (softs->free_io_slot_tail == -1)
		softs->free_io_slot_head = index;
	else
		softs->io_slot[softs->free_io_slot_tail].next = index;
	softs->free_io_slot_tail = index;
	softs->free_io_slot_len++;
	mutex_exit(&softs->slot_mutex);
}

static int
aac_do_poll_io(struct aac_softstate *softs, struct aac_cmd *acp)
{
	struct aac_fib *ac_fibp, *sync_fibp;
	int ret_val;

	ASSERT(acp);
	ASSERT(softs);

	ac_fibp = &acp->fib;

	/*
	 * When new comm. enabled, large FIBs are used for IO requests.
	 * Since sync FIB is always 512 bytes, async FIB is used with
	 * new comm. for poll IO.
	 */
	if (softs->flags & AAC_FLAGS_NEW_COMM) {
		ret_val = AACOK;
		ac_fibp->Header.XferState &= ~AAC_FIBSTATE_ASYNC;

		if (aac_do_async_io(softs, acp) != AACOK) {
			AACDB_PRINT((CE_CONT, "Poll IO failed"));
			return (AACERR);
		}

		/*
		 * Interrupt is disabled in panic mode, we have to poll
		 * the adapter by ourselves.
		 */
		if (ddi_in_panic()) {
			while (acp->state == AAC_CMD_INCMPLT)
				(void) aac_intr_new((caddr_t)softs);
			if (acp->state == AAC_CMD_ABORT)
				ret_val = AACERR;
		} else {
			ac_fibp->Header.XferState &= ~AAC_FIBSTATE_ASYNC;
			mutex_enter(&softs->event_mutex);
			while (acp->state == AAC_CMD_INCMPLT)
				cv_wait(&softs->event, &softs->event_mutex);
			if (acp->state == AAC_CMD_ABORT)
				ret_val = AACERR;
			mutex_exit(&softs->event_mutex);
		}
	} else {
		sync_fibp = aac_grab_sync_fib(softs, SLEEP_FUNC);
		/* Only copy data of needed length */
		bcopy(ac_fibp, sync_fibp, ac_fibp->Header.Size);

		ret_val = aac_sync_fib(softs, ContainerCommand, sync_fibp,
			ac_fibp->Header.Size);
		aac_release_sync_fib(softs);
	}

	return (ret_val);
}

/*
 * Io requests have to be queued up in q_wait(_sync) to ensure that
 * they are executed in order. Out-of-order execution of io requests
 * is not allowed.
 */
int
aac_do_async_io(struct aac_softstate *softs, struct aac_cmd *ac)
{
	int retval = AACOK;

	if (ac->fib.Header.XferState & AAC_FIBSTATE_ASYNC)
		/* Async FIB io request enters q_wait */
		aac_cmd_enqueue(&softs->q_wait, ac);
	else
		/* Sync FIB io request enters q_wait_sync */
		aac_cmd_enqueue(&softs->q_wait_sync, ac);

	aac_start_waiting_io(softs);

	return (retval);
}

static void
aac_dma_sync(ddi_dma_handle_t handle, off_t offset, size_t length, uint_t type)
{
	if (ddi_dma_sync(handle, offset, length, type) == DDI_FAILURE)
		cmn_err(CE_WARN, "!DMA sync failed");
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
	int cid;
	int devcfg_needed;
	struct aac_fib_context *ctx;
	int current, next;

	ASSERT(softs != NULL);
	ASSERT(fibp != NULL);

	if (fibp->Header.Command != AifRequest) {
		cmn_err(CE_NOTE, "!Unknown command from controller: 0x%x",
			fibp->Header.Command);
		return (AACERR);
	}

	aif = (struct aac_aif_command *)&fibp->data[0];

	AACDB_PRINT_AIF(aif);

	cid = aif->data.EN.data.ECC.container[0];
	devcfg_needed = 0;

	switch (aif->command) {
	case AifCmdDriverNotify:
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
			if (aif->data.EN.data.ECE.eventType == \
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
		aac_rescan_container(softs);

	/* Copy AIF data to AIF queue */
	mutex_enter(&softs->aifq_mutex);
	current = softs->aifq_idx;
	next = (current + 1) % AAC_AIFQ_LENGTH;
	if (next == 0) {
		softs->aifq_filled = 1;
		AACDB_PRINT((CE_NOTE, "-- AIF queue overrun"));
	}
	bcopy(fibp, &softs->aifq[current], sizeof (struct aac_fib));

	/* Modify AIF contexts */
	if (softs->aifq_filled) {
		for (ctx = softs->fibctx; ctx; ctx = ctx->next) {
			if (next == ctx->ctx_idx)
				ctx->ctx_wrap = 1;
			else if (current == ctx->ctx_idx && ctx->ctx_wrap)
				ctx->ctx_idx = next;
		}
	}
	softs->aifq_idx = next;

	/* Wakeup applications */
	cv_broadcast(&softs->aifv);
	mutex_exit(&softs->aifq_mutex);

	if (fibp->Header.XferState & AAC_FIBSTATE_FROMADAP) {
		fibp->Header.XferState |= AAC_FIBSTATE_DONEHOST;
		((int *)fibp->data)[0] = 0; /* ST_OK */
		if (fibp->Header.Size > sizeof (struct aac_fib))
			fibp->Header.Size = sizeof (struct aac_fib);
	}
	return (AACOK);
}

static void
aac_daemon(void* arg)
{
	int i;
	uint32_t t_flag;
	uint32_t curtime;
	struct aac_softstate *softs = (struct aac_softstate *)arg;
	struct aac_slot *slotp;
	struct aac_cmd *acp;

	/* Check slot for timeout pkts */
	rw_enter(&softs->errlock, RW_READER);
	for (i = 0; i < softs->total_slots; i++) {
		slotp = &softs->io_slot[i];
		if (slotp->index == -1)
			continue;

		mutex_enter(&softs->slot_mutex);
		if (slotp->index == -1) {
			mutex_exit(&softs->slot_mutex);
			continue;
		}
		acp = slotp->acp;
		if (acp == NULL) {
			/* Slot is being launched */
			mutex_exit(&softs->slot_mutex);
			continue;
		}
		if (acp->timeout == 0) {
			/* No timeout */
			mutex_exit(&softs->slot_mutex);
			continue;
		}
		t_flag = (uint32_t)acp->timeout + (uint32_t)acp->start_time;
		curtime = (uint32_t)ddi_get_time();
		if (t_flag >= curtime) {
			mutex_exit(&softs->slot_mutex);
			continue;
		}

		acp->flags |= AAC_CMD_TIMEOUT;
		AACDB_PRINT((CE_NOTE, "timeout=%d,startime=%d;curtime=%d",
			(uint32_t)acp->timeout,	(uint32_t)acp->start_time,
			curtime));

		mutex_exit(&softs->slot_mutex);
		softs->timeout_count++;
		break;
	}
	rw_exit(&softs->errlock);

	/*
	 * Besides the firmware in unhealthy state, an overloaded adapter may
	 * also incur pkt timeout.
	 * There is a chance for an adapter with a slower IOP to take longer
	 * than 60 seconds to process the commands, such as when the adapter is
	 * doing a build on a RAID-5 while being required to perform IOs. So
	 * longer completion times should be tolerated.
	 */
	if (softs->timeout_count) {
		(void) aac_do_reset(softs);
		softs->timeout_count = 0;
	}

	if ((softs->timeout_id != 0) &&
		(softs->state != AAC_STATE_STOPPED))
		softs->timeout_id = timeout(aac_daemon, (void*)softs,
			(60 * drv_usectohz(1000000)));
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

	DBCALLED(1);

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

	DBCALLED(1);

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
aac_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
	cred_t *cred_p, int *rval_p)
{
	struct aac_softstate *softs;
	int minor0, minor;
	int instance;

	DBCALLED(1);

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

#ifdef AAC_DEBUG

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
aac_print_scmd(struct scsi_pkt *pkt)
{
	struct scsi_address *ap = &pkt->pkt_address;
	int tgt = ap->a_target;
	int lun = ap->a_lun;
	union scsi_cdb *cdbp = (union scsi_cdb *)pkt->pkt_cdbp;
	uchar_t cmd = cdbp->scc_cmd;
	struct aac_cmd *ac = PKT2AC(pkt);
	char *desc;

	if ((desc = aac_cmd_name(cmd,
		(struct aac_key_strings *)scsi_cmds)) == NULL) {
		cmn_err(CE_NOTE, "SCMD> Unknown(0x%2x) to t%dL%d",
			cmd, tgt, lun);
		return;
	}

	switch (cmd) {
	case SCMD_READ:
	case SCMD_WRITE:
		cmn_err(CE_NOTE, "SCMD> %s t%dL%d 0x%x %s",
			desc, tgt, lun,	GETG0ADDR(cdbp),
			((ac->flags & AAC_CMD_NO_INTR) ||
			(ac->flags & AAC_CMD_SOFT_INTR)) ?
				"poll" : "intr");
		break;
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
		cmn_err(CE_NOTE, "SCMD> %s t%dL%d 0x%x %s",
			desc, tgt, lun, GETG1ADDR(cdbp),
			((ac->flags & AAC_CMD_NO_INTR) ||
			(ac->flags & AAC_CMD_SOFT_INTR)) ?
				"poll" : "intr");
		break;
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
		cmn_err(CE_NOTE, "SCMD> %s t%dL%d 0x%x.%08x %s",
			desc, tgt, lun,
			GETG4ADDR(cdbp), GETG4ADDRTL(cdbp),
			((ac->flags & AAC_CMD_NO_INTR) ||
			(ac->flags & AAC_CMD_SOFT_INTR)) ?
				"poll" : "intr");
		break;
	default:
		cmn_err(CE_NOTE, "SCMD> %s t%dL%d",
			desc, tgt, lun);
	}
}

void
aac_print_fib(struct aac_fib *fibp)
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
			cmn_err(CE_NOTE, "FIB> %s (0x%x, 0x%x, 0x%x)",
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
		cmn_err(CE_NOTE, "FIB> %s, sz=%d", subcmdstr,
			fibp->Header.Size);
	else if (cmdstr && sub_cmd == -1)
		cmn_err(CE_NOTE, "FIB> %s, sz=%d", cmdstr,
			fibp->Header.Size);
	else if (cmdstr)
		cmn_err(CE_NOTE, "FIB> %s: Unknown(0x%x), sz=%d", cmdstr,
			sub_cmd, fibp->Header.Size);
	else
		cmn_err(CE_NOTE, "FIB> Unknown(0x%x), sz=%d", fib_cmd,
			fibp->Header.Size);
}

static void
aac_print_aif(struct aac_aif_command *aif)
{
	char *str;

	switch (aif->command) {
	case AifCmdEventNotify:
		str = aac_cmd_name(aif->data.EN.type, aac_aifens);
		if (str)
			cmn_err(CE_NOTE, "AIF! %s", str);
		else
			cmn_err(CE_NOTE, "AIF! Unknown(0x%x)",
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
		cmn_err(CE_NOTE, "AIF! JobProgress (%d) - %s (%d, %d)",
			aif->seqNumber, str,
			aif->data.PR[0].currentTick,
			aif->data.PR[0].finalTick);
		break;

	case AifCmdAPIReport:
		cmn_err(CE_NOTE, "AIF! APIReport (%d)", aif->seqNumber);
		break;

	case AifCmdDriverNotify:
		cmn_err(CE_NOTE, "AIF! DriverNotify (%d)", aif->seqNumber);
		break;

	default:
		cmn_err(CE_NOTE,
			"AIF! AIF %d (%d)", aif->command, aif->seqNumber);
		break;
	}
}

#endif
