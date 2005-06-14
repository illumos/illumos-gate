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

/* #define	AAC_DEBUG */

#ifdef AAC_DEBUG

#define	AACDB_PRINT(fmt) cmn_err fmt
static char *get_cmd_desc(uchar_t);

#else

#define	AACDB_PRINT(fmt)

#endif /* ifdef AAC_DEBUG */

#define	DBCALLED() AACDB_PRINT((CE_NOTE, "**%s called**", "" /* __func__ */))

#define	AACOFFSET(type, member) ((size_t)(&((type *)0)->member))
#define	AAC_TRAN2SOFTS(tran) ((struct aac_softstate *)(tran)->tran_hba_private)
#define	PKT2AC(pkt) ((struct aac_cmd *)(pkt)->pkt_ha_private)
#define	AAC_BUSYWAIT(cond, timeout /* in millisecond */) /* */ { \
		int count = 0; \
		while (!(cond)) { \
			drv_usecwait(1); \
			if ((count) > (timeout * 1000)) { \
				break; \
			} \
			(count)++; \
		} \
	}

#define	PCI_MEM_GET32(softs, off) ddi_get32((softs)->pci_mem_handle, \
	(uint32_t *)((softs)->pci_mem_base_addr + (off)))
#define	PCI_MEM_PUT32(softs, off, val)	ddi_put32((softs)->pci_mem_handle, \
	(uint32_t *)((softs)->pci_mem_base_addr + (off)), (uint32_t)(val))
#define	BUF_IS_READ(bp) ((bp)->b_flags & B_READ)

#define	AAC_ENABLE_INTR(softs)	PCI_MEM_PUT32 \
	(softs, AAC_OIMR, ~AAC_DB_INTR_BITS)
#define	AAC_DISABLE_INTR(softs)	PCI_MEM_PUT32 \
	(softs, AAC_OIMR, ~0)
#define	AAC_MAILBOX_GET(softs, reg) PCI_MEM_GET32 \
	(softs, AAC_MAILBOX + reg * 4)
#define	AAC_MAILBOX_SET(softs, cmd, arg0, arg1, arg2, arg3) 	\
		PCI_MEM_PUT32(softs, AAC_MAILBOX, cmd);		\
		PCI_MEM_PUT32(softs, AAC_MAILBOX + 4, arg0);	\
		PCI_MEM_PUT32(softs, AAC_MAILBOX + 8, arg1);	\
		PCI_MEM_PUT32(softs, AAC_MAILBOX + 12, arg2);	\
		PCI_MEM_PUT32(softs, AAC_MAILBOX + 16, arg3)
#define	AAC_STATUS_CLR(softs, mask) PCI_MEM_PUT32(softs, AAC_ODBR, mask)
#define	AAC_STATUS_GET(softs) PCI_MEM_GET32(softs, AAC_ODBR)
#define	AAC_FWSTATUS_GET(softs) PCI_MEM_GET32(softs, AAC_FWSTATUS)
#define	AAC_NOTIFY(softs, val) PCI_MEM_PUT32(softs, AAC_IDBR, val)
#define	AAC_IS_Q_EMPTY(q) ((q)->q_head == NULL) ? 1 : 0

/*
 * SCSA function prototypes
 */
static int aac_attach(dev_info_t *, ddi_attach_cmd_t);
static int aac_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Interrupt handler funtions
 */
static uint_t aac_intr(caddr_t);
static uint_t aac_softintr(caddr_t);

/*
 * Internal funciton in attach
 */
static int aac_check_card_type(struct aac_softstate *);
static int aac_common_attach(struct aac_softstate *);
static int aac_sync_mbcommand(struct aac_softstate *, uint32_t, uint32_t,
	uint32_t, uint32_t, uint32_t, uint32_t *);
static int aac_get_container(struct aac_softstate *);
static int aac_setup_comm_space(struct aac_softstate *);
static int aac_hba_setup(struct aac_softstate *);

/*
 * Internal funciton in attach
 */
static int aac_check_card_type(struct aac_softstate *);
static int aac_sync_fib(struct aac_softstate *, uint32_t, struct aac_fib *,
	uint16_t);
static struct aac_fib *aac_grab_sync_fib(struct aac_softstate *,
	int (*)(caddr_t));
static void aac_release_sync_fib(struct aac_softstate *);

/*
 * hardware queue operation funcitons
 */
static void aac_cmd_enqueue(struct aac_cmd_queue *, struct aac_cmd *);
static struct aac_cmd *aac_cmd_dequeue(struct aac_cmd_queue *);

/*
 * fib queue operation functions
 */
static int aac_fib_enqueue(struct aac_softstate *, int, struct aac_fib *);
static struct aac_cmd *aac_fib_dequeue(struct aac_softstate *, int);

/*
 * slot operation functions
 */
static int aac_create_slots(struct aac_softstate *);
static void aac_destroy_slots(struct aac_softstate *);
static struct aac_slot *aac_get_slot(struct aac_softstate *);
static void aac_release_slot(struct aac_softstate *, struct aac_slot **);
static void aac_do_release_slot(struct aac_softstate *, struct aac_slot **);

/*
 * Internal funcitons
 */
static size_t aac_cmd_fib(struct aac_cmd *);
static void aac_start_waiting_io(struct aac_softstate *);
static void aac_drain_comp_q(struct aac_softstate *);
static int aac_do_poll_io(struct aac_softstate *, struct aac_cmd *);
static int aac_do_async_io(struct aac_softstate *, struct aac_cmd *);
static void aac_dma_sync(ddi_dma_handle_t handle, off_t offset, size_t length,
	uint_t type);

/*
 * timeout handling thread function
 */
static void aac_daemon(void*);

static struct dev_ops aac_dev_ops = {
	DEVO_REV,
	0,
	nodev,
	nulldev,
	nulldev,
	aac_attach,
	aac_detach,
	nodev,
	NULL,
	NULL,
	NULL
};

static struct modldrv aac_modldrv = {
	&mod_driverops,
	"AAC Driver %I%",
	&aac_dev_ops,
};

static struct modlinkage aac_modlinkage = {
	MODREV_1,
	&aac_modldrv,
	NULL
};

static struct aac_softstate  *aac_softstatep;

/* desc will be used in inquiry(0x12) command the length should be 16 bytes */
static struct aac_card_type aac_cards[] = {
	{0x9005, 0x285, 0x9005, 0x285, "Adatpec 2200S   "},
	{0x9005, 0x285, 0x9005, 0x286, "Adaptec 2120S   "},
	{0x9005, 0x285, 0x9005, 0x290, "Adaptec 2410SA  "},
	{0x9005, 0x285, 0x1028, 0x287, "Dell PERC 320/DC"},
	{0x1028, 0xa, 0x1028, 0x121, "Dell PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x11b, "Dell PERC 3/Di"},
	{0x1028, 0xa, 0x1028, 0x106, "Dell PERC 3/Di"},
	{0x1028, 0x8, 0x1028, 0xcf, "Dell PERC 3/Di"},
	{0x1028, 0x2, 0x1028, 0xd9, "Dell PERC 3/Di"},
	{0x1028, 0x2, 0x1028, 0xd1, "Dell PERC 3/Di"},
	{0x1028, 0x4, 0x1028, 0xd0, "Dell PERC 3/Si"},
	{0x1028, 0x3, 0x1028, 0x3, "Dell PERC 3/Si"},
	{0x1028, 0x2, 0x1028, 0x2, "Dell PERC 3/Di"},
	{0x1028, 0x1, 0x1028, 0x1, "Dell PERC 3/Di"},
	{0, 0, 0, 0, "AAC card      "},
	{0, 0, 0, 0, NULL}
};

static ddi_device_acc_attr_t aac_acc_attr = {
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

/* dma attribute */
ddi_dma_attr_t aac_buf_dma_attr = {
		DMA_ATTR_V0,
		0x2000ull,	/* lowest usable address */
				/* (2200 and 2120 cannot dma below 8192 */
		0xffffffffull,	/* high DMA address range */
		0x0000ffffull,	/* DMA counter register */
		4,		/* DMA address alignment */
		1,		/* DMA burstsizes */
		1,		/* min effective DMA size */
		0xffffffffull,	/* max DMA xfer size */
		0xffffffffull,	/* segment boundary */
		AAC_NSEG,	/* s/g list length */
		512,		/* granularity of device */
		0,		/* DMA transfer flags */
};

ddi_dma_attr_t aac_addr_dma_attr = {
		DMA_ATTR_V0,
		0x2000ull,	/* lowest usable address */
				/* (2200 and 2120 cannot dma below 8192 */
		0xffffffffull,	/* high DMA address range */
		0x0000ffffull,	/* DMA counter register */
		4,		/* DMA address alignment */
		1,		/* DMA burstsizes */
		1,		/* min effective DMA size */
		0xffffffffull,	/* max DMA xfer size */
		0xffffffffull,	/* segment boundary */
		1,		/* s/g list length */
		1,		/* granularity of device */
		0,		/* DMA transfer flags */
};

int
_init(void)
{
	int retval = 0;

	DBCALLED();
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
	DBCALLED();
	return (mod_info(&aac_modlinkage, modinfop));
}

/*
 * an HBA driver cannot be unload unless you reboot,
 * so this function will be of no use
 */
int
_fini(void)
{
	int err;

	DBCALLED();
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

	DBCALLED();

	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME:
			return (DDI_FAILURE);
		default:
			return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/* get soft state */
	if (ddi_soft_state_zalloc(aac_softstatep, instance) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "Cannot alloc soft state"));
		goto error;
	}
	attach_state |= AAC_SOFT_STATE_ALLOCED;
	softs = ddi_get_soft_state(aac_softstatep, instance);
	softs->devinfo_p = dip;

	/* check the card type */
	if ((softs->card = aac_check_card_type(softs)) != AACERR) {
		/* we have found the right card and everything is OK */
		attach_state |= AAC_CARD_DETECTED;
	} else
		goto error;

	/* map pci mem space */
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&softs->pci_mem_base_addr, 0,
		0, &aac_acc_attr, &softs->pci_mem_handle) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "Cannot map pci mem space"));
		goto error;
	}
	attach_state |= AAC_PCI_MEM_MAPPED;

	AAC_DISABLE_INTR(softs);

	/* Connect interrupt handler */
	if (ddi_intr_hilevel(dip, 0)) {
		AACDB_PRINT((CE_WARN,
			"High level interrupt is not supported!"));
		goto error;
	}

	if (ddi_get_iblock_cookie(dip, 0, &softs->iblock_cookie)
		!= DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN,
			"Can not get interrupt block cookie!"));
		goto error;
	}
	/* init mutexes */
	mutex_init(&softs->sync_mode.mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->q_comp_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->q_wait_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->slot_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->fib_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->timeout_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	mutex_init(&softs->tran_mutex, NULL,
		MUTEX_DRIVER, (void *)softs->iblock_cookie);
	attach_state |= AAC_KMUTEX_INITED;

	if (ddi_add_intr(dip, 0, &softs->iblock_cookie,
		(ddi_idevice_cookie_t *)0, aac_intr, (caddr_t)softs)
		!= DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN,
			"Can not setup interrupt handler!"));
		goto error;
	}
	if (ddi_add_softintr(dip, DDI_SOFTINT_LOW,
		&softs->softint_id, NULL, NULL, aac_softintr, (caddr_t)softs)
		!= DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN,
			"Can not setup soft interrupt handler!"));
		ddi_remove_intr(dip, 0, softs->iblock_cookie);
		goto error;
	}
	attach_state |= AAC_SOFT_INTR_SETUP;

	if (aac_hba_setup(softs) != AACOK)
		goto error;
	attach_state |= AAC_SCSI_TRAN_SETUP;

	/*
	 * everything has been set up till now,
	 * we will do some common attach
	 */
	if (aac_common_attach(softs) == AACERR)
		goto error;

	/* common attach is OK, so we are attached! */
	AAC_ENABLE_INTR(softs);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

error:
	if (attach_state & AAC_SCSI_TRAN_SETUP) {
		tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
		(void) scsi_hba_detach(dip);
		scsi_hba_tran_free(tran);
	}
	if (attach_state & AAC_SOFT_INTR_SETUP) {
		ddi_remove_softintr(softs->softint_id);
		ddi_remove_intr(dip, 0, softs->iblock_cookie);
	}
	if (attach_state & AAC_KMUTEX_INITED) {
		mutex_destroy(&softs->sync_mode.mutex);
		mutex_destroy(&softs->q_comp_mutex);
		mutex_destroy(&softs->q_wait_mutex);
		mutex_destroy(&softs->slot_mutex);
		mutex_destroy(&softs->fib_mutex);
		mutex_destroy(&softs->timeout_mutex);
		mutex_destroy(&softs->tran_mutex);
	}
	if (attach_state & AAC_PCI_MEM_MAPPED)
		ddi_regs_map_free(&softs->pci_mem_handle);
	if (attach_state & AAC_CARD_DETECTED)
		softs->card = AACERR;
	if (attach_state & AAC_SOFT_STATE_ALLOCED)
		ddi_soft_state_free(aac_softstatep, instance);
	return (DDI_FAILURE);
}

static int
aac_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	struct aac_softstate *softs;
	scsi_hba_tran_t *tran;

	DBCALLED();

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
	mutex_enter(&softs->timeout_mutex);
	if (softs->timeout_id != 0) {
		softs->flags |= AAC_STOPPED;
		mutex_exit(&softs->timeout_mutex);
		(void) untimeout(softs->timeout_id);
		mutex_enter(&softs->timeout_mutex);
		softs->flags &= ~AAC_STOPPED;
		softs->timeout_id = 0;
		mutex_exit(&softs->timeout_mutex);
	} else
		mutex_exit(&softs->timeout_mutex);
	AAC_DISABLE_INTR(softs);
	aac_destroy_slots(softs);
	(void) ddi_dma_unbind_handle(softs->comm_space_dma_handle);
	ddi_dma_mem_free(&softs->comm_space_acc_handle);
	softs->comm_space_acc_handle = NULL;
	ddi_dma_free_handle(&softs->comm_space_dma_handle);
	softs->comm_space_dma_handle = NULL;
	(void) scsi_hba_detach(dip);
	scsi_hba_tran_free(tran);
	ddi_remove_softintr(softs->softint_id);
	ddi_remove_intr(dip, 0, softs->iblock_cookie);
	mutex_destroy(&softs->sync_mode.mutex);
	mutex_destroy(&softs->q_comp_mutex);
	mutex_destroy(&softs->q_wait_mutex);
	mutex_destroy(&softs->slot_mutex);
	mutex_destroy(&softs->fib_mutex);
	mutex_destroy(&softs->timeout_mutex);
	mutex_destroy(&softs->tran_mutex);
	ddi_regs_map_free(&softs->pci_mem_handle);
	softs->card = AACERR;
	ddi_soft_state_free(aac_softstatep, instance);

	return (DDI_SUCCESS);
}

static uint_t
aac_softintr(caddr_t arg)
{
	struct aac_softstate *softs;

	softs = (struct aac_softstate *)arg;
	if (!AAC_IS_Q_EMPTY(&softs->q_comp)) {
		mutex_enter(&softs->q_comp_mutex);
		aac_drain_comp_q(softs);
		mutex_exit(&softs->q_comp_mutex);
		return (DDI_INTR_CLAIMED);
	} else
		return (DDI_INTR_UNCLAIMED);
}

void
aac_set_arq_data(struct scsi_pkt *pkt, uchar_t key)
{
	struct scsi_arq_status *arqstat;

	arqstat = (struct scsi_arq_status *)(pkt->pkt_scbp);
	arqstat->sts_status.sts_chk = 1; /* CHECK CONDITION */
	arqstat->sts_rqpkt_reason = CMD_CMPLT;
	arqstat->sts_rqpkt_resid = 0;
	arqstat->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		STATE_SENT_CMD | STATE_XFERRED_DATA;
	arqstat->sts_rqpkt_statistics = 0;
	arqstat->sts_sensedata.es_valid = 1;
	arqstat->sts_sensedata.es_class = CLASS_EXTENDED_SENSE;
	arqstat->sts_sensedata.es_key = key;
}

static uint_t
aac_intr(caddr_t arg)
{
	struct aac_cmd *acp;
	struct aac_softstate *softs;
	uint16_t status;

	softs = (struct aac_softstate *)arg;
	status = AAC_STATUS_GET(softs);
	if (status & AAC_DB_RESPONSE_READY) { /* got work to do */
		/* ack the int */
		AAC_STATUS_CLR(softs, AAC_DB_RESPONSE_READY);
		(void) AAC_STATUS_GET(softs);
		mutex_enter(&softs->q_comp_mutex);
		do {
			acp = aac_fib_dequeue(softs, AAC_HOST_NORM_RESP_Q);
			if (acp) {
				struct aac_slot *slotp = acp->slotp;
				ASSERT(acp->slotp != NULL);
				ASSERT(acp->flags & AAC_CMD_HARD_INTR);
				aac_dma_sync(slotp->fib_dma_handle, 0, 0,
					DDI_DMA_SYNC_FORCPU);
				if (slotp->fibp->data[0] != 0) {
					acp->pkt->pkt_reason = CMD_INCOMPLETE;
					acp->pkt->pkt_state = STATE_GOT_BUS |
						STATE_GOT_TARGET |
						STATE_SENT_CMD |
						STATE_GOT_STATUS |
						STATE_ARQ_DONE;
					aac_set_arq_data(acp->pkt,
						KEY_HARDWARE_ERROR);
				}
				aac_release_slot(softs, &acp->slotp);
				aac_cmd_enqueue(&softs->q_comp, acp);
			}
		} while (acp);
		aac_drain_comp_q(softs);
		mutex_exit(&softs->q_comp_mutex);
		aac_start_waiting_io(softs);
		return (DDI_INTR_CLAIMED);
	} else if (status & AAC_DB_PRINTF_READY) { /* got work to do */
		/* ack the int */
		AAC_STATUS_CLR(softs, AAC_DB_PRINTF_READY);
		(void) AAC_STATUS_GET(softs);
		aac_dma_sync(softs->comm_space_dma_handle,
			AACOFFSET(struct aac_comm_space, adapter_print_buf),
			AAC_ADAPTER_PRINT_BUFSIZE,
			DDI_DMA_SYNC_FORCPU);
		cmn_err(CE_NOTE, "MSG From Adapter: %s",
			softs->comm_space->adapter_print_buf);
		return (DDI_INTR_CLAIMED);
	} else if (status & AAC_DB_COMMAND_READY) {
		AAC_STATUS_CLR(softs, AAC_DB_COMMAND_READY);
		(void) AAC_STATUS_GET(softs);
		cmn_err(CE_NOTE, "!Fib received from adapter!");
		return (DDI_INTR_CLAIMED);
	} else
		return (DDI_INTR_UNCLAIMED);
}

static int
aac_check_card_type(struct aac_softstate *softs)
{
	uint16_t vendid, subvendid, devid, subsysid;
	int card_type_index;
	uint32_t pci_cmd;
	int card_found;
	dev_info_t *dip = softs->devinfo_p;
	ddi_acc_handle_t pci_config_handle;

	/* map pci configuration space */
	if ((pci_config_setup(dip, &pci_config_handle)) != DDI_SUCCESS) {
		AACDB_PRINT((CE_WARN, "Cannot setup pci config space"));
		return (AACERR);
	}

	vendid = pci_config_get16(pci_config_handle, PCI_CONF_VENID);
	devid = pci_config_get16(pci_config_handle, PCI_CONF_DEVID);
	subvendid = pci_config_get16(pci_config_handle, PCI_CONF_SUBVENID);
	subsysid = pci_config_get16(pci_config_handle, PCI_CONF_SUBSYSID);
	card_type_index = 0;
	card_found = 0;
	while (aac_cards[card_type_index].desc != NULL) {
		if ((aac_cards[card_type_index].vendor == vendid) &&
			(aac_cards[card_type_index].device == devid) &&
			(aac_cards[card_type_index].subvendor == subvendid) &&
			(aac_cards[card_type_index].subsys == subsysid)) {
			card_found = 1;
			break;
		}
		card_type_index++;
	}

	/* make sure we can talk to this board */
	if (card_found) {
		pci_cmd = pci_config_get16(pci_config_handle, PCI_CONF_COMM);
		if ((pci_cmd & PCI_COMM_ME) == 0) {
			/* force the busmaster enable bit on */
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
		if ((pci_cmd & PCI_COMM_MAE) == 0) {
			AACDB_PRINT((CE_WARN, "Memory window not available"));
			goto error;
		}
	} else
		card_type_index--;

	pci_config_teardown(&pci_config_handle);
	cmn_err(CE_CONT, "?Found card: %s", aac_cards[card_type_index].desc);
	return (card_type_index); /* card type detected */

error:
	pci_config_teardown(&pci_config_handle);
	return (AACERR); /* Not found a matched card */
}

static int
aac_common_attach(struct aac_softstate *softs)
{
	DBCALLED();

	/* wait card to be ready */
	AAC_BUSYWAIT(AAC_FWSTATUS_GET(softs) & AAC_READY, 60 * 1000);

	if (!(AAC_FWSTATUS_GET(softs) & AAC_READY)) {
		cmn_err(CE_CONT, "?Fatal error: controller not ready");
		goto error;
	}

	/* get supported options */
	if ((aac_sync_mbcommand(softs, AAC_MONKER_GETINFO, 0, 0, 0, 0, NULL))
		!= AACOK) {
		cmn_err(CE_CONT, "?Fatal error: request adapter info error");
		goto error;
	}
	softs->support_opt = AAC_MAILBOX_GET(softs, 1);

	/* Setup communication space with the card */
	if (aac_setup_comm_space(softs) != AACOK) {
		cmn_err(CE_CONT, "?Setup communication space failed");
		goto error;
	}

	/* setup containers */
	if (aac_get_container(softs) != AACOK) {
		cmn_err(CE_CONT, "?Fatal error: get container info error");
		goto error;
	}

	/* create a thread for command timeout */
	softs->timeout_id = timeout(aac_daemon, (void*)softs,
		(60 * drv_usectohz(1000000)));
	softs->flags &= ~AAC_STOPPED;

	return (AACOK);

error:
	return (AACERR);
}

static int
aac_sync_mbcommand(struct aac_softstate *softs, uint32_t cmd,
	uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3,
	uint32_t *statusp)
{
	uint32_t status;

	/* fill in mailbox */
	AAC_MAILBOX_SET(softs, cmd, arg0, arg1, arg2, arg3);

	/* ensure the sync command doorbell flag is cleared */
	AAC_STATUS_CLR(softs, AAC_DB_SYNC_COMMAND);

	/* then set it to signal the adapter */
	AAC_NOTIFY(softs, AAC_DB_SYNC_COMMAND);

	/* spin waiting for the command to complete */
	AAC_BUSYWAIT(AAC_STATUS_GET(softs) & AAC_DB_SYNC_COMMAND, 10 * 1000);
	if (!(AAC_STATUS_GET(softs) & AAC_DB_SYNC_COMMAND)) {
			AACDB_PRINT((CE_WARN,
				"Sent sync command timed out!"));
			return (AACERR);
	}

	/* clear the completion flag */
	AAC_STATUS_CLR(softs, AAC_DB_SYNC_COMMAND);

	/* get the command status */
	status = AAC_MAILBOX_GET(softs, 0);
	if (status != 1)
		return (AACERR);

	if (statusp != NULL)
		*statusp = status;
	return (AACOK);
}

static int
aac_sync_fib(struct aac_softstate *softs, uint32_t cmd,
	struct aac_fib *fib, uint16_t datasize)
{
	int err;
	uint32_t status;

	if (datasize > AAC_FIB_SIZE)
		return (AACERR);

	/* setup sync fib */
	fib->Header.XferState =
		AAC_FIBSTATE_HOSTOWNED	 |
		AAC_FIBSTATE_INITIALISED |
		AAC_FIBSTATE_EMPTY	 |
		AAC_FIBSTATE_FROMHOST	 |
		AAC_FIBSTATE_NORM;
	fib->Header.Command = cmd;
	fib->Header.StructType = AAC_FIBTYPE_TFIB;
	fib->Header.Flags = 0;
	fib->Header.Size = datasize;
	fib->Header.SenderSize = sizeof (struct aac_fib);
	fib->Header.SenderFibAddress = 0;
	fib->Header.ReceiverFibAddress = softs->sync_mode.fib_phyaddr;
	fib->Header.SenderData = 0;

	aac_dma_sync(softs->comm_space_dma_handle,
		AACOFFSET(struct aac_comm_space, sync_fib), AAC_FIB_SIZE,
		DDI_DMA_SYNC_FORDEV);
	/* Give the FIB to the controller, wait for a response. */
	err = aac_sync_mbcommand(softs, AAC_MONKER_SYNCFIB,
		fib->Header.ReceiverFibAddress, 0, 0, 0, &status);
	AACDB_PRINT((CE_NOTE, "Sync fib status: 0x%x", status));
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

/* remove cmd from queue */
static struct aac_cmd *
aac_cmd_dequeue(struct aac_cmd_queue *q)
{
	struct aac_cmd *ac = NULL;

	if (q->q_head) {
		ac = q->q_head;
		q->q_head = ac->next;
		ac->next = NULL;
		if (q->q_head == NULL)
			q->q_tail = NULL;
	}

	return (ac);
}

/* add a cmd to the tail of q */
static void
aac_cmd_enqueue(struct aac_cmd_queue *q, struct aac_cmd *ac)
{
	if (!q->q_head) { /* empty queue */
		q->q_tail = ac;
		q->q_head = ac;
	} else {
		q->q_tail->next = ac;
		q->q_tail = ac;
	}
}

static int
aac_fib_enqueue(struct aac_softstate *softs, int queue,
	struct aac_fib *fibp)
{
	uint32_t pi, ci;
	uint32_t fib_size;
	uint32_t fib_addr;

	DBCALLED();

	mutex_enter(&softs->fib_mutex);
	fib_size = fibp->Header.Size;
	fib_addr = fibp->Header.ReceiverFibAddress;

	/* get the producer/consumer indices */
	pi = softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX];
	ci = softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX];

	/*
	 * wrap the queue first before we check the queue to see
	 * if it is full
	 */
	if (pi >= aac_qinfo[queue].size)
		pi = 0;

	/* xxx queue full */
	if ((pi + 1) == ci) {
		mutex_exit(&softs->fib_mutex);
		return (AACERR);
	}

	/* fill in queue entry */
	(softs->qentries[queue] + pi)->aq_fib_size = fib_size;
	(softs->qentries[queue] + pi)->aq_fib_addr = fib_addr;

	/* update producer index */
	softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX] = pi + 1;

	mutex_exit(&softs->fib_mutex);
	AAC_NOTIFY(softs, aac_qinfo[AAC_ADAP_NORM_CMD_Q].notify);

	return (AACOK);
}

static struct aac_cmd *
aac_fib_dequeue(struct aac_softstate *softs, int queue)
{
	uint32_t pi, ci;
	uint32_t slot_index;
	struct aac_cmd *acp = NULL;
	int unfull = 0;

	DBCALLED();

	mutex_enter(&softs->fib_mutex);

	/* get the producer/consumer indices */
	pi = softs->qtablep->qt_qindex[queue][AAC_PRODUCER_INDEX];
	ci = softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX];

	/* check for queue empty */
	if (ci == pi) {
		goto out;
	}

	/* check for queue full */
	if (ci == pi + 1)
		unfull = 1;

	/*
	 * the controller does not wrap the queue,
	 * so we have to do it by ourselves
	 */
	if (ci >= aac_qinfo[queue].size)
		ci = 0;

	/* fetch the entry */
	slot_index = (softs->qentries[queue] + ci)->aq_fib_addr >> 1;
	acp = softs->io_slot[slot_index].acp;
	ASSERT((slot_index >= 0) && (slot_index < softs->total_slotn));
	ASSERT(acp != NULL);

	/* update consumer index */
	softs->qtablep->qt_qindex[queue][AAC_CONSUMER_INDEX] = ci + 1;

out:
	mutex_exit(&softs->fib_mutex);
	if (unfull)
		AAC_NOTIFY(softs, aac_qinfo[AAC_HOST_NORM_RESP_Q].notify);

	return (acp);
}

static int
aac_get_container(struct aac_softstate *softs)
{
	struct aac_fib *fib;
	struct aac_mntinfo *mi;
	struct aac_mntinforesp *mir = NULL;
	int i = 0, count = 0;

	fib = aac_grab_sync_fib(softs, SLEEP_FUNC);
	mi = (struct aac_mntinfo *)&fib->data[0];

	/* loop over possible containers */
	do {
		mi->Command = VM_NameServe;
		mi->MntType = FT_FILESYS;

		/* request information on #i container */
		mi->MntCount = i;
		if (aac_sync_fib(softs, ContainerCommand, fib,
			sizeof (struct aac_fib_header) + \
			sizeof (struct aac_mntinfo)) == AACERR) {
			AACDB_PRINT((CE_WARN,
				"Error probe container %d", i));
			continue;
		}

		mir = (struct aac_mntinforesp *)&fib->data[0];
		if (i == 0) { /* the first time */
			count = mir->MntRespCount;
		}
		if ((mir->Status == 0) && (mir->MntObj.VolType != 0)) {
			softs->container[i].id = mir->MntObj.ObjectId;
			softs->container[i].size = mir->MntObj.Capacity;
			softs->container[i].valid = 1;
			AACDB_PRINT((CE_NOTE,
			"Container found: id=%d, size=%u, type=%d, name=%s",
				mir->MntObj.ObjectId, mir->MntObj.Capacity,
				mir->MntObj.VolType,
				mir->MntObj.FileSystemName));
		}
		bzero(mir, sizeof (struct aac_mntinforesp));
		i++;
	} while ((i < count) && (i < AAC_MAX_LD));
	aac_release_sync_fib(softs);
	cmn_err(CE_CONT, "?Total %d container(s) found", count);

	return (AACOK);
}

static int
aac_setup_comm_space(struct aac_softstate *softs)
{
	size_t rlen;
	uint32_t comm_space_phyaddr;
	ddi_dma_cookie_t cookie;
	uint_t cookien;
	int qoffset;
	struct aac_adapter_init *initp;

	if (ddi_dma_alloc_handle(
		softs->devinfo_p,
		&aac_addr_dma_attr,
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
	cookien = 0;
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
			"dma bind failed for communication area"));
		cookien = 0;
		goto error;
	}
	comm_space_phyaddr = cookie.dmac_address;
	softs->sync_mode.fib = &softs->comm_space->sync_fib;
	softs->sync_mode.fib_phyaddr = comm_space_phyaddr + \
		AACOFFSET(struct aac_comm_space, sync_fib);
	/* init slot */
	if (aac_create_slots(softs) < 1)
		goto error;

	qoffset = (comm_space_phyaddr + \
		AACOFFSET(struct aac_comm_space, qtable))
		% AAC_QUEUE_ALIGN;
	if (qoffset)
		qoffset = AAC_QUEUE_ALIGN - qoffset;
	softs->qtablep = (struct aac_queue_table *) \
		((char *)&softs->comm_space->qtable + qoffset);
	initp = &softs->comm_space->init_data;
	initp->AdapterFibsPhysicalAddress = comm_space_phyaddr + \
		AACOFFSET(struct aac_comm_space, adapter_fibs);
	initp->AdapterFibAlign = sizeof (struct aac_fib);
	initp->AdapterFibsSize = AAC_ADAPTER_FIBS * sizeof (struct aac_fib);
	initp->PrintfBufferAddress = comm_space_phyaddr + \
		AACOFFSET(struct aac_comm_space, adapter_print_buf);
	initp->PrintfBufferSize = AAC_ADAPTER_PRINT_BUFSIZE;
	initp->InitStructRevision = AAC_INIT_STRUCT_REVISION;
	initp->MiniPortRevision = AAC_INIT_STRUCT_MINIPORT_REVISION;
	initp->HostElapsedSeconds = ddi_get_time();
	initp->CommHeaderAddress = comm_space_phyaddr + \
		AACOFFSET(struct aac_comm_space, qtable) + qoffset;
	initp->HostPhysMemPages = AAC_MAX_PFN;

	/* init queue table */
	softs->qtablep->qt_qindex[AAC_HOST_NORM_CMD_Q][AAC_PRODUCER_INDEX]
		= AAC_HOST_NORM_CMD_ENTRIES;
	softs->qtablep->qt_qindex[AAC_HOST_NORM_CMD_Q][AAC_CONSUMER_INDEX]
		= AAC_HOST_NORM_CMD_ENTRIES;
	softs->qtablep->qt_qindex[AAC_HOST_HIGH_CMD_Q][AAC_PRODUCER_INDEX]
		= AAC_HOST_HIGH_CMD_ENTRIES;
	softs->qtablep->qt_qindex[AAC_HOST_HIGH_CMD_Q][AAC_CONSUMER_INDEX]
		= AAC_HOST_HIGH_CMD_ENTRIES;
	softs->qtablep->qt_qindex[AAC_ADAP_NORM_CMD_Q][AAC_PRODUCER_INDEX]
		= AAC_ADAP_NORM_CMD_ENTRIES;
	softs->qtablep->qt_qindex[AAC_ADAP_NORM_CMD_Q][AAC_CONSUMER_INDEX]
		= AAC_ADAP_NORM_CMD_ENTRIES;
	softs->qtablep->qt_qindex[AAC_ADAP_HIGH_CMD_Q][AAC_PRODUCER_INDEX]
		= AAC_ADAP_HIGH_CMD_ENTRIES;
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

	/* init queue entries */
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


	/* Send init structure to the card */
	if (aac_sync_mbcommand(softs,
		AAC_MONKER_INITSTRUCT,
		comm_space_phyaddr + \
		AACOFFSET(struct aac_comm_space, init_data),
		0, 0, 0, NULL) == AACERR) {
		AACDB_PRINT((CE_WARN,
			"Cannot send init structrue to adapter"));
		goto error;
	}

	return (AACOK);

error:
	if (cookien)
		(void) ddi_dma_unbind_handle(softs->comm_space_dma_handle);
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
aac_mode_sense(struct scsi_pkt *pkt, union scsi_cdb *cdbp, struct buf *bp,
			int capacity)
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
	pkt->pkt_state = STATE_XFERRED_DATA;
	pagecode = cdbp->cdb_un.sg.scsi[0];
	headerp = (struct mode_header *)(bp->b_un.b_addr);
	headerp->bdesc_length = MODE_BLK_DESC_LENGTH;

	switch (pagecode) {
	case SD_MODE_SENSE_PAGE3_CODE:
		page3p = (struct mode_format *)((caddr_t)headerp +
			MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
		page3p->mode_page.code = SD_MODE_SENSE_PAGE3_CODE;
		page3p->mode_page.length = sizeof (struct mode_format);
		page3p->data_bytes_sect = BE_16(AAC_SECTOR_SIZE);
		page3p->sect_track = BE_16(AAC_SECTORS_PER_TRACK);
		break;

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
	int target = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;

	DBCALLED();

	AACDB_PRINT((CE_NOTE, "aac_tran_tgt_init: target = %d, lun = %d",
		target, lun));
	softs = AAC_TRAN2SOFTS(tran);
	if (softs->container[target].valid && (lun == 0))
		/* only support container that has been detected and valid */
		return (DDI_SUCCESS);
	else
		return (DDI_FAILURE);
}

/*
 * tran_reset() will reset the adapter to support the fault recovery
 * functionality. Till now there is no firmware manual available from
 * Adaptec. We have requested IHV team for further documents and support
 * from Adaptec, there is no result yet.
 *
 * If the tran_reset() return a FAILURE to the sd, the system will not
 * continue to dump the core. But core dump is an crucial method to analyze
 * problems in panic. Now we adopt a work around solution, that is return
 * a fake SUCCESS to sd during panic, which will force the system continue
 * to dump core though the core may have problems in some situtation because
 * some on-the-fly commands will continue DMAing data to the memory.
 * In addition, the work around core dump method may not be performed
 * successfully if the panic is caused by the HBA itself. So the work around
 * solution is not a good example for the implementation of tran_reset(),
 * the most reasonable approach should be to reset the adapter.
 *
 * IHV team is continue seeking support from Adaptec. Once further support
 * from Adaptec is available, we will implement a true reset function in
 * tran_reset().
 */
/*ARGSUSED*/
static int
aac_tran_reset(struct scsi_address *ap, int level)
{
	struct aac_softstate *softs;
	uint32_t *pip, *cip;

	if (ddi_in_panic()) {
		softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
		pip = &(softs->qtablep->qt_qindex
			[AAC_ADAP_NORM_CMD_Q][AAC_PRODUCER_INDEX]);
		cip = &(softs->qtablep->qt_qindex
			[AAC_ADAP_NORM_CMD_Q][AAC_CONSUMER_INDEX]);
		AAC_BUSYWAIT(*pip == *cip, 6 * 1000);
		if (*pip != *cip)
			return (0);
		/*
		 * If the system is in panic, the tran_reset() will return a
		 * fake SUCCESS to sd, then the system would continue dump the
		 * core by poll commands. This is a work around for dumping
		 * core in panic.
		 *
		 * Note: Some on-the-fly command will continue DMAing data to
		 *	 the memory when the core is dumping, which may cause
		 *	 some flaws in the dumped core file, so a cmn_err()
		 *	 will be printed out to warn users. However, for most
		 *	 cases, the core file will be fine.
		 */
		cmn_err(CE_WARN, "This system contains a scsi hba "
				"card/driver that doesn't support software "
				"reset. This means that memory being used "
				"by the hba for DMA based reads could have "
				"been updated after we panic'd.");
		return (1);
	}
	else
		return (0);
}

static void
aac_soft_callback(struct aac_softstate *softs, struct scsi_pkt *pkt,
			uchar_t reason)
{
	struct aac_cmd *ac;

	ac = PKT2AC(pkt);
	pkt->pkt_reason = reason;
	pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
				STATE_SENT_CMD;
	*pkt->pkt_scbp = 0;
	if (reason == CMD_INCOMPLETE)
		aac_set_arq_data(pkt, KEY_ILLEGAL_REQUEST);
	if (!(ac->flags & AAC_CMD_NO_INTR)) {
		mutex_enter(&softs->q_comp_mutex);
		aac_cmd_enqueue(&softs->q_comp, ac);
		mutex_exit(&softs->q_comp_mutex);
		ddi_trigger_softintr(softs->softint_id);
	}
}

static void
aac_free_dmamap(struct aac_cmd *ac)
{
	/* free dma mapping */
	if (ac->buf_dma_handle) {
		(void) ddi_dma_unbind_handle(ac->buf_dma_handle);
		ddi_dma_free_handle(&ac->buf_dma_handle);
		ac->buf_dma_handle = NULL;
		ac->flags &= ~AAC_CMD_DMA_VALID;
	}
}

static int
aac_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_softstate  *softs;
	struct aac_cmd *ac;
	struct buf *bp;
	union scsi_cdb *cdbp;
	uchar_t cmd;
	int ret_val;
	int target = ap->a_target;
	int lun = ap->a_lun;
	int capacity;

	DBCALLED();
	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	ac = PKT2AC(pkt);
	if (!softs->container[target].valid || lun != 0) {
		AACDB_PRINT((CE_WARN,
			"Cannot send cmd to invalid target: %d and lun: %d",
			target, lun));
		return (TRAN_FATAL_ERROR);
	}

	cdbp = (union scsi_cdb *)pkt->pkt_cdbp;
	bp = ac->bp;
	cmd = cdbp->scc_cmd;
	ac->flags |= (pkt->pkt_flags & FLAG_NOINTR) ? AAC_CMD_NO_INTR : 0;

	AACDB_PRINT((CE_NOTE, "%s(0x%x) cmd to target=%d, lun=%d",
		get_cmd_desc(cdbp->scc_cmd), cmd, target, lun));

	switch (cmd) {
		case SCMD_INQUIRY: /* inquiry */
			ac->flags |= AAC_CMD_SOFT_INTR;
			if (bp && bp->b_un.b_addr && bp->b_bcount) {
				struct scsi_inquiry inq;
				size_t len = sizeof (struct scsi_inquiry);

				bzero(&inq, len);
				if (((char *)cdbp)[1] || ((char *)cdbp)[2]) {
					/* The EVDP and pagecode is not */
					/* supported */
					uint8_t *inqp = (uint8_t *)&inq;
					inqp[1] = 0xFF;
					inqp[2] = 0x0;
				} else {
					inq.inq_len = AAC_ADDITIONAL_LEN;
					inq.inq_ansi = AAC_ANSI_VER;
					inq.inq_rdf = AAC_RESP_DATA_FORMAT;
					bcopy("AAC     ", inq.inq_vid, 8);
					bcopy(aac_cards[softs->card].desc,
						inq.inq_pid, 16);
					bcopy("V1.0", inq.inq_revision, 4);
				}
				aac_free_dmamap(ac);
				if (bp->b_flags & (B_PHYS | B_PAGEIO)) {
					bp_mapin(bp);
					bcopy(&inq, bp->b_un.b_addr, len);
				} else
					bcopy(&inq, bp->b_un.b_addr, len);
				pkt->pkt_state = STATE_XFERRED_DATA;
			}
			aac_soft_callback(softs, pkt, CMD_CMPLT);
			ret_val = TRAN_ACCEPT;
			break;
		case SCMD_READ_CAPACITY: /* read capacity */
			ac->flags |= AAC_CMD_SOFT_INTR;
			if (bp && bp->b_un.b_addr && bp->b_bcount) {
				struct scsi_capacity cp;

				capacity = softs->container[target].size;
				cp.capacity = BE_32(capacity);
				cp.lbasize = BE_32(AAC_SECTOR_SIZE);

				aac_free_dmamap(ac);
				if (bp->b_flags & (B_PHYS|B_PAGEIO)) {
					bp_mapin(bp);
					bcopy(&cp, bp->b_un.b_addr, 8);
				} else
					bcopy(&cp, bp->b_un.b_addr, 8);
				pkt->pkt_state = STATE_XFERRED_DATA;
			}
			aac_soft_callback(softs, pkt, CMD_CMPLT);
			ret_val = TRAN_ACCEPT;
			break;
		case SCMD_READ: /* read_6 */
		case SCMD_READ_G1: /* read_10 */
		case SCMD_WRITE: /* write_6 */
		case SCMD_WRITE_G1: /* write_10 */
			ac->flags |= AAC_CMD_HARD_INTR;
			if ((ac->flags & AAC_CMD_DMA_VALID) &&
				(ac->fib.Header.XferState &
				AAC_FIBSTATE_HOSTOWNED)) {
				struct aac_fib *ac_fibp;

				/* fill in correct blkno */
				ac_fibp = &ac->fib;
				if (ac->flags & AAC_CMD_BUF_READ) {
					struct aac_blockread *br =
						(struct aac_blockread *) \
						&ac_fibp->data[0];
					br->BlockNumber =
						(ac->cmdlen == 10) ?
						GETG1ADDR(cdbp):GETG0ADDR(cdbp);
				} else {
					struct aac_blockwrite *bw =
						(struct aac_blockwrite *) \
						&ac_fibp->data[0];
					bw->BlockNumber =
						(ac->cmdlen == 10) ?
						GETG1ADDR(cdbp):GETG0ADDR(cdbp);
				}

				pkt->pkt_reason = CMD_CMPLT;
				pkt->pkt_state |= STATE_GOT_BUS |
					STATE_GOT_TARGET	|
					STATE_SENT_CMD		|
					STATE_XFERRED_DATA;
				pkt->pkt_statistics = STAT_SYNC;
				*pkt->pkt_scbp = 0;
				if ((ac->flags & AAC_CMD_NO_INTR) ||
					(ac->flags & AAC_CMD_SOFT_INTR)) {
					/* poll pkt */
					if (aac_do_poll_io(softs, ac)
							== AACOK) {
						ret_val = TRAN_ACCEPT;
					} else {
						ret_val = TRAN_BADPKT;
					}
				} else {
					/* async pkt */
					ret_val = aac_do_async_io(softs, ac);
					if (ret_val == AACOK)
						ret_val = TRAN_ACCEPT;
					else
						ret_val = TRAN_BUSY;
				}
			} else
				ret_val = TRAN_BADPKT;
			break;
		case SCMD_MODE_SENSE: /* mode_sense_6 */
		case SCMD_MODE_SENSE_G1: /* mode_sense_10 */
			ac->flags |= AAC_CMD_SOFT_INTR;
			aac_free_dmamap(ac);
			capacity = softs->container[target].size;
			aac_mode_sense(pkt, cdbp, bp, capacity);
			aac_soft_callback(softs, pkt, CMD_CMPLT);
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
					if (bp->b_flags & (B_PHYS|B_PAGEIO)) {
						bp_mapin(bp);
						bzero(bp->b_un.b_addr,
							bp->b_bcount);
					} else
						bzero(bp->b_un.b_addr,
							bp->b_bcount);
				}
				pkt->pkt_state |= STATE_XFERRED_DATA;
			}
			aac_soft_callback(softs, pkt, CMD_CMPLT);
			ret_val = TRAN_ACCEPT;
			break;
		default: /* unknown command */
			aac_free_dmamap(ac);
			pkt->pkt_state = (STATE_GOT_STATUS | STATE_ARQ_DONE);
			aac_soft_callback(softs, pkt, CMD_INCOMPLETE);
			ret_val = TRAN_ACCEPT;
			break;
	}

	return (ret_val);
}

static int
aac_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int rval;
	struct aac_softstate *softs;
	int target = ap->a_target;
	int lun = ap->a_lun;

	DBCALLED();

	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT((CE_WARN,
			"Get Cap not supported: cap=%p, whom=%d", cap, whom));
		return (-1);
	}

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	if (!softs->container[target].valid || !(lun == 0)) {
		AACDB_PRINT((CE_WARN, "Bad target to get cap"));
		return (-1);
	}

	mutex_enter(&softs->tran_mutex);
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		rval = 1;
		break;
	case SCSI_CAP_GEOMETRY:
		rval = (AAC_NUMBER_OF_HEADS << 16) | AAC_SECTORS_PER_TRACK;
		break;
	case SCSI_CAP_SECTOR_SIZE:
		rval = AAC_SECTOR_SIZE;
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		/* number of sectors */
		rval = softs->container[target].size;
		break;
	default:
		rval = -1;
		break;
	}
	mutex_exit(&softs->tran_mutex);
	AACDB_PRINT((CE_NOTE, "Get Cap string = %s, rval=%d", cap, rval));

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

	DBCALLED();

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	/* We don't allow inquiring about capabilities for other targets */
	if (cap == NULL || whom == 0) {
		AACDB_PRINT((CE_WARN,
			"Set Cap not supported, string = %s, whom=%d",
			cap, whom));
		return (-1);
	}

	AACDB_PRINT((CE_NOTE, "Set Cap string = %s, value=%d", cap, value));
	mutex_enter(&softs->tran_mutex);
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		rval = 1;
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		softs->container[target].size = value;
		rval = 1;
		break;
	case SCSI_CAP_SECTOR_SIZE:
		rval = 0;
		break;
	default:
		rval = -1;
		break;
	}
	mutex_exit(&softs->tran_mutex);

	return (rval);
}

static void
aac_tran_destroy_pkt(struct scsi_address *ap,
	struct scsi_pkt *pkt)
{
	struct aac_cmd *ac = PKT2AC(pkt);

	DBCALLED();

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
	struct aac_cmd *ac;
	int err;
	uint_t dma_flags = 0;
	int testflag = 0;
	int (*cb) (caddr_t);
	int slen;
	size_t transfer_num;

	DBCALLED();

	softs = AAC_TRAN2SOFTS(ap->a_hba_tran);
	if (!softs->container[ap->a_target].valid)
		return (NULL);

	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	/* alloc pkt */
	if (pkt == NULL) {
		testflag = 1;
		/* force auto request sense */
		slen = statuslen < sizeof (struct scsi_arq_status) ?
			sizeof (struct scsi_arq_status) : statuslen;

		pkt = scsi_hba_pkt_alloc(softs->devinfo_p, ap, cmdlen,
			slen, tgtlen, sizeof (struct aac_cmd), callback,
			arg);
		if (pkt == NULL) {
			AACDB_PRINT((CE_WARN, "Alloc scsi pkt failed"));
			return (NULL);
		}
		ac = PKT2AC(pkt);
		ac->pkt = pkt;
		ac->cmdlen = cmdlen;
		ac->slotp = NULL;
		/*
		 * we will still use this point for we
		 * want to fake some infomation in tran_start
		 */
		ac->bp = bp;

		/* set cmd flags according to pkt alloc flags */
		if (flags & PKT_CONSISTENT)
			ac->flags |= AAC_CMD_CONSISTENT;
		if (flags & PKT_DMA_PARTIAL)
			ac->flags |= AAC_CMD_DMA_PARTIAL;
	}
	if (bp == NULL || (bp->b_bcount == 0))
		return (pkt);

	/* we need to transfer data, so we alloc dma resources for this pkt */
	ac = PKT2AC(pkt);
	if (!(ac->flags & AAC_CMD_DMA_VALID)) {

		ASSERT(testflag != 0); /* pkt is reused without init */

		/* set dma flags */
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

		/* alloc buf dma handle */
		err = DDI_SUCCESS;
		if (!ac->buf_dma_handle)
			err = ddi_dma_alloc_handle(softs->devinfo_p,
				&aac_buf_dma_attr, cb, NULL,
				&ac->buf_dma_handle);
		if (err != DDI_SUCCESS) {
			AACDB_PRINT((CE_WARN,
				"Can't allocate dma handle, errorno=%d", err));
			scsi_hba_pkt_free(ap, pkt);
			return (NULL);
		}

		/* bind buf */
		err = ddi_dma_buf_bind_handle(ac->buf_dma_handle, bp, dma_flags,
			DDI_DMA_SLEEP, NULL, &ac->cookie, &ac->left_cookien);
		switch (err) {
		case DDI_DMA_PARTIAL_MAP:
			if (ddi_dma_numwin(ac->buf_dma_handle, &ac->total_nwin)
				== DDI_FAILURE) {
				AACDB_PRINT((CE_WARN,
					"Cannot get number of DMA windows"));
				(void) ddi_dma_unbind_handle(
						ac->buf_dma_handle);
				goto error_out;
			}
			AACDB_PRINT((CE_NOTE,
				"buf bind, %d segs", ac->left_cookien));
			ac->cur_win = 0;
			break;

		case DDI_DMA_MAPPED:
			AACDB_PRINT((CE_NOTE,
				"buf bind, %d segs", ac->left_cookien));
			ac->cur_win = 0;
			ac->total_nwin = 1;
			break;

		default:
			AACDB_PRINT((CE_WARN, "Cannot bind buf for dma"));
error_out:
			ddi_dma_free_handle(&ac->buf_dma_handle);
			ac->buf_dma_handle = NULL;
			scsi_hba_pkt_free(ap, pkt);
			return (NULL);
		}
		ac->flags |= AAC_CMD_DMA_VALID;
	}

	/* build fib for this ac/pkt and return remaining byte count */
	transfer_num = aac_cmd_fib(ac);
	if (transfer_num == 0) {
		aac_tran_destroy_pkt(ap, pkt);
		return (NULL);
	}
	pkt->pkt_resid = bp->b_bcount - transfer_num;
	AACDB_PRINT((CE_NOTE,
		"b_bcount=%d, total_xfer=%d, pkt_resid = %d",
		bp->b_bcount, ac->total_xfer, pkt->pkt_resid));
	ASSERT(pkt->pkt_resid >= 0);

	return (pkt);
}

/*
 * tran_sync_pkt(9E) - explicit DMA synchronization
 */
/*ARGSUSED*/
static void
aac_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct aac_cmd *ac = PKT2AC(pkt);

	DBCALLED();

	if (ac->buf_dma_handle) {
		aac_dma_sync(ac->buf_dma_handle, 0, 0,
			(ac->flags & AAC_CMD_BUF_WRITE) ?
			DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
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

	DBCALLED();

	if (ac->flags & AAC_CMD_DMA_VALID) {
		(void) ddi_dma_unbind_handle(ac->buf_dma_handle);
		ddi_dma_free_handle(&ac->buf_dma_handle);
		ac->buf_dma_handle = NULL;
		ac->flags &= ~AAC_CMD_DMA_VALID;
	}
}

/*ARGSUSED*/
static int
aac_tran_quiesce(dev_info_t *dip)
{
	return (0);
}

/*ARGSUSED*/
static int
aac_tran_unquiesce(dev_info_t *dip)
{
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
	hba_tran->tran_sync_pkt = aac_tran_sync_pkt;
	hba_tran->tran_dmafree = aac_tran_dmafree;
	hba_tran->tran_quiesce = aac_tran_quiesce;
	hba_tran->tran_unquiesce = aac_tran_unquiesce;
	err = scsi_hba_attach_setup(softs->devinfo_p, &aac_buf_dma_attr,
		hba_tran, SCSI_HBA_TRAN_CLONE);
	if (err != DDI_SUCCESS) {
		scsi_hba_tran_free(hba_tran);
		AACDB_PRINT((CE_WARN, "aac_hba_setup failed"));
		return (AACERR);
	}

	return (AACOK);
}

static size_t
aac_cmd_fib(struct aac_cmd *ac)
{
	int count;
	off_t off;
	size_t len;
	struct aac_sg_table *sgmap;
	ddi_dma_handle_t dma_handle;
	ddi_dma_cookie_t *cookiep;
	uint_t cookien;
	uint32_t *bytecountp, cur_total_xfer;
	struct scsi_pkt *pkt;
	struct scsi_address *ap;
	struct aac_fib *fibp;
	uint16_t *fib_datasizep;

	fibp = &ac->fib;
	pkt = ac->pkt;
	ap = &pkt->pkt_address;
	dma_handle = ac->buf_dma_handle;
	cookiep = &ac->cookie;
	cookien = ac->left_cookien;

	if (cookien == 0 && ac->total_nwin == 1)
		return (0); /* nothing to be transfered */
	/* fill in fib header */
	fibp->Header.XferState =
		AAC_FIBSTATE_HOSTOWNED   |
		AAC_FIBSTATE_INITIALISED |
		AAC_FIBSTATE_EMPTY	 |
		AAC_FIBSTATE_FROMHOST	 |
		AAC_FIBSTATE_REXPECTED   |
		AAC_FIBSTATE_NORM	 |
		AAC_FIBSTATE_ASYNC;
	fibp->Header.Command = ContainerCommand;
	fibp->Header.StructType = AAC_FIBTYPE_TFIB;
	fibp->Header.Flags = 0; /* don't care */
	fib_datasizep = &fibp->Header.Size; /* will be filled in later */
	fibp->Header.SenderSize = sizeof (struct aac_fib);
	fibp->Header.ReceiverFibAddress = 0;
	fibp->Header.SenderData = 0; /* don't care */
	*fib_datasizep = sizeof (struct aac_fib_header);

	/* fill in fib data */
	if (ac->flags & AAC_CMD_BUF_READ) {
		struct aac_blockread *br;

		br = (struct aac_blockread *)&fibp->data[0];
		*fib_datasizep += sizeof (struct aac_blockread);
		br->Command = VM_CtBlockRead;
		br->ContainerId =
			AAC_TRAN2SOFTS(ap->a_hba_tran)-> \
			container[ap->a_target].id;
		sgmap = &br->SgMap;
		bytecountp = &br->ByteCount;
	} else {
		struct aac_blockwrite *bw;

		bw = (struct aac_blockwrite *)&fibp->data[0];
		*fib_datasizep += sizeof (struct aac_blockwrite);
		bw->Command = VM_CtBlockWrite;
		bw->ContainerId =
			AAC_TRAN2SOFTS(ap->a_hba_tran)->container \
			[ap->a_target].id;
		bw->Stable = CUNSTABLE;
		bytecountp = &bw->ByteCount;
		sgmap = &bw->SgMap;
	}

	cur_total_xfer = 0;
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

	/* move cookie and window to build s/g map */
	count = 0;
	while (count < AAC_NSEG) { /* cookie loop */
		sgmap->SgEntry[count].SgAddress =
			cookiep->dmac_address;
		sgmap->SgEntry[count].SgByteCount =
			cookiep->dmac_size;
		count++;
		cur_total_xfer += cookiep->dmac_size;
		cookien--;
		if (cookien > 0)
			ddi_dma_nextcookie(dma_handle, cookiep);
		else
			break;
	}

	*bytecountp = cur_total_xfer;
	sgmap->SgCount = count;

	ac->left_cookien = cookien;
	ac->total_xfer += cur_total_xfer;

	/* calculate fib data size */
	*fib_datasizep += (count - 1) * sizeof (struct aac_sg_entry);

	return (ac->total_xfer);
}

static void
aac_start_waiting_io(struct aac_softstate *softs)
{
	struct aac_cmd *ac;
	struct aac_slot *slotp;

	/* check wait queue, if this function do not be called only in */
	/* aac_intr we will enter q_wait_mutex to check q_head again */
	mutex_enter(&softs->q_wait_mutex);
	if ((!AAC_IS_Q_EMPTY(&softs->q_wait)) &&
		((slotp = aac_get_slot(softs)) != NULL)) {
		ac = aac_cmd_dequeue(&softs->q_wait);
		mutex_exit(&softs->q_wait_mutex);
		slotp->acp = ac;
		ac->slotp = slotp;
		ac->fib.Header.ReceiverFibAddress = slotp->fib_phyaddr;
		ac->fib.Header.SenderFibAddress = slotp->index << 1;
		bcopy(&ac->fib, slotp->fibp, sizeof (struct aac_fib));
		aac_dma_sync(slotp->fib_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);
		/* if fib can not enqueu, the card is in a abnormal */
		/* status, there will be no interrupt to us */
		(void) aac_fib_enqueue(softs, AAC_ADAP_NORM_CMD_Q, slotp->fibp);
		return;
	}
	mutex_exit(&softs->q_wait_mutex);
}

static void
aac_drain_comp_q(struct aac_softstate *softs)
{
	struct aac_cmd *ac = NULL;

	ASSERT(mutex_owned(&softs->q_comp_mutex));

	do {
		ac = aac_cmd_dequeue(&softs->q_comp);
		if (ac && ac->pkt && ac->pkt->pkt_comp) {
			mutex_exit(&softs->q_comp_mutex);
			(*ac->pkt->pkt_comp)(ac->pkt);
			mutex_enter(&softs->q_comp_mutex);
		}
	} while (ac);
}

static int
aac_create_slots(struct aac_softstate *softs)
{
	int i;
	struct aac_slot *slotp;
	size_t rlen;
	ddi_dma_cookie_t cookie;
	uint_t cookien;

	bzero(softs->io_slot, sizeof (struct aac_slot) * AAC_HOST_FIBS);
	for (i = 0; i < AAC_HOST_FIBS; i++) {
		slotp = &(softs->io_slot[i]);
		if (ddi_dma_alloc_handle(
			softs->devinfo_p,
			&aac_addr_dma_attr,
			DDI_DMA_SLEEP,
			NULL,
			&slotp->fib_dma_handle) != DDI_SUCCESS) {
			AACDB_PRINT((CE_WARN,
				"Cannot alloc dma handle for slot fib area"));
			break;
		}
		if (ddi_dma_mem_alloc(
			slotp->fib_dma_handle,
			AAC_FIB_SIZE,
			&aac_acc_attr,
			DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			DDI_DMA_SLEEP,
			NULL,
			(caddr_t *)&slotp->fibp,
			&rlen,
			&slotp->fib_acc_handle) != DDI_SUCCESS) {
			AACDB_PRINT((CE_WARN,
				"Cannot alloc mem for slot fib area"));
			ddi_dma_free_handle(&slotp->fib_dma_handle);
			slotp->fib_dma_handle = NULL;
			break;
		}
		if (ddi_dma_addr_bind_handle(
			slotp->fib_dma_handle,
			NULL,
			(caddr_t)slotp->fibp,
			AAC_FIB_SIZE,
			DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			DDI_DMA_SLEEP,
			NULL,
			&cookie,
			&cookien) != DDI_DMA_MAPPED) {
			AACDB_PRINT((CE_WARN,
				"dma bind failed for slot fib area"));
			ddi_dma_mem_free(&slotp->fib_acc_handle);
			slotp->fib_acc_handle = NULL;
			ddi_dma_free_handle(&slotp->fib_dma_handle);
			slotp->fib_dma_handle = NULL;
			break;
		}
		slotp->next = i + 1;
		slotp->index = -1;
		slotp->fib_phyaddr = cookie.dmac_address;
	}
	softs->io_slot[i].next = -1;
	softs->free_io_slot_head = 0;
	softs->free_io_slot_tail = i - 1;
	softs->total_slotn = i;
	return (i);
}

static void
aac_destroy_slots(struct aac_softstate *softs)
{
	int i;
	struct aac_slot *slotp;

	for (i = 0; i < AAC_HOST_FIBS; i++) {
		slotp = &(softs->io_slot[i]);
		if (slotp->fib_phyaddr) {
			(void) ddi_dma_unbind_handle(slotp->fib_dma_handle);
			ddi_dma_mem_free(&slotp->fib_acc_handle);
			slotp->fib_acc_handle = NULL;
			ddi_dma_free_handle(&slotp->fib_dma_handle);
			slotp->fib_dma_handle = NULL;
			slotp->fib_phyaddr = 0;
		}
	}
	bzero(softs->io_slot, sizeof (struct aac_slot) * AAC_HOST_FIBS);
}

static struct aac_slot *
aac_get_slot(struct aac_softstate *softs)
{
	int i;

	mutex_enter(&softs->slot_mutex);
	if (softs->free_io_slot_head == -1) {
		mutex_exit(&softs->slot_mutex);
		return (NULL);
	}
	i = softs->free_io_slot_head;
	softs->free_io_slot_head = softs->io_slot[i].next;
	softs->io_slot[i].index = i;
	softs->io_slot[i].next = -1;
	softs->io_slot[i].cmd_time = ddi_get_time();
	if (softs->free_io_slot_head == -1)
		softs->free_io_slot_tail = -1;
	mutex_exit(&softs->slot_mutex);

	return (&softs->io_slot[i]);
}


static void
aac_release_slot(struct aac_softstate *softs, struct aac_slot **slotpp)
{
	struct aac_slot *slotp = *slotpp;
	int index = slotp->index;

	ASSERT((index >= 0) && (index < softs->total_slotn));
	mutex_enter(&softs->slot_mutex);
	aac_do_release_slot(softs, slotpp);
	mutex_exit(&softs->slot_mutex);
}


static void
aac_do_release_slot(struct aac_softstate *softs, struct aac_slot **slotpp)
{
	struct aac_slot *slotp = *slotpp;
	int index = slotp->index;

	ASSERT(mutex_owned(&softs->slot_mutex));
	softs->io_slot[index].index = -1;
	softs->io_slot[index].acp = NULL;
	softs->io_slot[index].cmd_time = 0;
	if (softs->free_io_slot_tail == -1)
		softs->free_io_slot_head = index;
	else
		softs->io_slot[softs->free_io_slot_tail].next = index;
	softs->io_slot[index].next = -1;
	softs->free_io_slot_tail = index;
	*slotpp = NULL;
}


static int
aac_do_poll_io(struct aac_softstate *softs, struct aac_cmd *ac)
{
	struct aac_fib *ac_fibp, *sync_fibp;
	int ret_val;

	ASSERT(ac);
	ASSERT(softs);

	ac_fibp = &ac->fib;
	sync_fibp = aac_grab_sync_fib(softs, SLEEP_FUNC);
	bcopy(ac_fibp, sync_fibp, ac_fibp->Header.Size);
	ret_val = aac_sync_fib(softs, ContainerCommand, sync_fibp,
		ac_fibp->Header.Size);
	aac_release_sync_fib(softs);
	if (ret_val != AACERR) { /* handle callback of this pkt */
		if (!(ac->flags & AAC_CMD_NO_INTR)) {
			mutex_enter(&softs->q_comp_mutex);
			aac_cmd_enqueue(&softs->q_comp, ac);
			mutex_exit(&softs->q_comp_mutex);
			ddi_trigger_softintr(softs->softint_id);
		}
	}

	return (ret_val);
}

static int
aac_do_async_io(struct aac_softstate *softs, struct aac_cmd *ac)
{
	struct aac_slot *slotp;
	int retval = AACOK;
	ASSERT(ac);
	ASSERT(softs);

	ASSERT(ac->slotp == NULL);
	slotp = ac->slotp = aac_get_slot(softs);
	if (ac->slotp == NULL) {
		mutex_enter(&softs->q_wait_mutex);
		aac_cmd_enqueue(&softs->q_wait, ac);
		mutex_exit(&softs->q_wait_mutex);
	} else {
		slotp->acp = ac;
		ac->fib.Header.ReceiverFibAddress = slotp->fib_phyaddr;
		ac->fib.Header.SenderFibAddress = slotp->index << 1;
		bcopy(&ac->fib, slotp->fibp, sizeof (struct aac_fib));
		aac_dma_sync(slotp->fib_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);
		retval = aac_fib_enqueue(softs, AAC_ADAP_NORM_CMD_Q,
				slotp->fibp);
	}
	return (retval);
}

static void
aac_dma_sync(ddi_dma_handle_t handle, off_t offset, size_t length, uint_t type)
{
	if (ddi_dma_sync(handle, offset, length, type) == DDI_FAILURE)
		cmn_err(CE_WARN, "!DMA sync failed");
}

static void
aac_daemon(void* arg)
{
	int i, i_do = 0;
	uint32_t t_flag;
	struct aac_softstate *softs = (struct aac_softstate *)arg;
	struct aac_cmd *acp;
	/* check slot */
	for (i = 0; i < softs->total_slotn; i++) {
		if (softs->io_slot[i].index == -1)
			continue;
		mutex_enter(&softs->slot_mutex);
		if (softs->io_slot[i].index == -1) {
			mutex_exit(&softs->slot_mutex);
			continue;
		}
		acp = softs->io_slot[i].acp;
		ASSERT(acp != NULL);
		if (acp->pkt->pkt_time == 0) {
			mutex_exit(&softs->slot_mutex);
			continue;
		}
		t_flag = (uint32_t)acp->pkt->pkt_time +
			(uint32_t)softs->io_slot[i].cmd_time;
		if (t_flag >= (uint32_t)ddi_get_time()) {
			mutex_exit(&softs->slot_mutex);
			continue;
		}
		ASSERT(acp->slotp != NULL);
		aac_do_release_slot(softs, &acp->slotp);
		mutex_exit(&softs->slot_mutex);
		mutex_enter(&softs->q_comp_mutex);
		acp->pkt->pkt_reason = CMD_TIMEOUT;
		acp->pkt->pkt_statistics = STAT_TIMEOUT;
		aac_cmd_enqueue(&softs->q_comp, acp);
		mutex_exit(&softs->q_comp_mutex);
		i_do = 1;
	}

	if (i_do == 1) {
		mutex_enter(&softs->q_comp_mutex);
		aac_drain_comp_q(softs);
		mutex_exit(&softs->q_comp_mutex);
		i_do = 0;
	}

	mutex_enter(&softs->timeout_mutex);
	if ((softs->timeout_id != 0) &&
		(softs->flags & AAC_STOPPED) == 0)
		softs->timeout_id = timeout(aac_daemon, (void*)softs,
			(60 * drv_usectohz(1000000)));
	mutex_exit(&softs->timeout_mutex);

}

#ifdef AAC_DEBUG

/* -------------------------debug aid functions-------------------------- */
char g_szCmdDesc[][30] = {
	"UNKNOWN", "TEST UNIT READY", "INQUIRY",
	"START STOP UNIT", "READ CAPACITY", "MODE SENSE",
	"SCMD PRINT", "READ_6", "WRITE_6", "SYNCHRONIZE CACHE",
	"READ_10", "WRITE_10", "PREVENT/ALLOW MEDIUM REMOVAL"
};

static char *
get_cmd_desc(uchar_t cmd)
{
	switch (cmd) {
		case 0:
			return (g_szCmdDesc[1]);
		case 0x12:
			return (g_szCmdDesc[2]);
		case 0x1b:
			return (g_szCmdDesc[3]);
		case 0x25:
			return (g_szCmdDesc[4]);
		case 0x1a:
			return (g_szCmdDesc[5]);
		case 0x5e:
			return (g_szCmdDesc[6]);
		case 0x08:
			return (g_szCmdDesc[7]);
		case 0x0a:
			return (g_szCmdDesc[8]);
		case 0x35:
			return (g_szCmdDesc[9]);
		case 0x28:
			return (g_szCmdDesc[10]);
		case 0x2a:
			return (g_szCmdDesc[11]);
		case 0x1e:
			return (g_szCmdDesc[12]);
		default:
			return (g_szCmdDesc[0]);
	}
}

#endif
