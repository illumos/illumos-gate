/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
 */
/*
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

#include <sys/int_types.h>
#include <sys/scsi/scsi.h>
#include <sys/dkbad.h>
#include <sys/dklabel.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/mhd.h>
#include <sys/vtoc.h>
#include <sys/dktp/fdisk.h>
#include <sys/scsi/targets/sddef.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/ksynch.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/byteorder.h>

#include "amrreg.h"
#include "amrvar.h"

/* dynamic debug symbol */
int	amr_debug_var = 0;

#define	AMR_DELAY(cond, count, done_flag) { \
		int local_counter = 0; \
		done_flag = 1; \
		while (!(cond)) { \
			delay(drv_usectohz(100)); \
			if ((local_counter) > count) { \
				done_flag = 0; \
				break; \
			} \
			(local_counter)++; \
		} \
	}

#define	AMR_BUSYWAIT(cond, count, done_flag) { \
		int local_counter = 0; \
		done_flag = 1; \
		while (!(cond)) { \
			drv_usecwait(100); \
			if ((local_counter) > count) { \
				done_flag = 0; \
				break; \
			} \
			(local_counter)++; \
		} \
	}

/*
 * driver interfaces
 */
char _depends_on[] = "misc/scsi";

static uint_t amr_intr(caddr_t arg);
static void amr_done(struct amr_softs *softs);

static int amr_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
			void *arg, void **result);
static int amr_attach(dev_info_t *, ddi_attach_cmd_t);
static int amr_detach(dev_info_t *, ddi_detach_cmd_t);

static int amr_setup_mbox(struct amr_softs *softs);
static int amr_setup_sg(struct amr_softs *softs);

/*
 * Command wrappers
 */
static int amr_query_controller(struct amr_softs *softs);
static void *amr_enquiry(struct amr_softs *softs, size_t bufsize,
			uint8_t cmd, uint8_t cmdsub, uint8_t cmdqual);
static int amr_flush(struct amr_softs *softs);

/*
 * Command processing.
 */
static void amr_rw_command(struct amr_softs *softs,
			struct scsi_pkt *pkt, int lun);
static void amr_mode_sense(union scsi_cdb *cdbp, struct buf *bp,
			unsigned int capacity);
static void amr_set_arq_data(struct scsi_pkt *pkt, uchar_t key);
static int amr_enquiry_mapcmd(struct amr_command *ac, uint32_t data_size);
static void amr_enquiry_unmapcmd(struct amr_command *ac);
static int amr_mapcmd(struct amr_command *ac, int (*callback)(), caddr_t arg);
static void amr_unmapcmd(struct amr_command *ac);

/*
 * Status monitoring
 */
static void amr_periodic(void *data);

/*
 * Interface-specific shims
 */
static int amr_poll_command(struct amr_command *ac);
static void amr_start_waiting_queue(void *softp);
static void amr_call_pkt_comp(struct amr_command *head);

/*
 * SCSI interface
 */
static int amr_setup_tran(dev_info_t  *dip, struct amr_softs *softp);

/*
 * Function prototypes
 *
 * SCSA functions exported by means of the transport table
 */
static int amr_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *tran, struct scsi_device *sd);
static int amr_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int amr_tran_reset(struct scsi_address *ap, int level);
static int amr_tran_getcap(struct scsi_address *ap, char *cap, int whom);
static int amr_tran_setcap(struct scsi_address *ap, char *cap, int value,
    int whom);
static struct scsi_pkt *amr_tran_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg);
static void amr_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static void amr_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt);
static void amr_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);

static ddi_dma_attr_t buffer_dma_attr = {
		DMA_ATTR_V0,	/* version of this structure */
		0,		/* lowest usable address */
		0xffffffffull,	/* highest usable address */
		0x00ffffffull,	/* maximum DMAable byte count */
		4,		/* alignment */
		1,		/* burst sizes */
		1,		/* minimum transfer */
		0xffffffffull,	/* maximum transfer */
		0xffffffffull,	/* maximum segment length */
		AMR_NSEG,	/* maximum number of segments */
		AMR_BLKSIZE,	/* granularity */
		0,		/* flags (reserved) */
};

static ddi_dma_attr_t addr_dma_attr = {
		DMA_ATTR_V0,	/* version of this structure */
		0,		/* lowest usable address */
		0xffffffffull,	/* highest usable address */
		0x7fffffff,	/* maximum DMAable byte count */
		4,		/* alignment */
		1,		/* burst sizes */
		1,		/* minimum transfer */
		0xffffffffull,	/* maximum transfer */
		0xffffffffull,	/* maximum segment length */
		1,		/* maximum number of segments */
		1,		/* granularity */
		0,		/* flags (reserved) */
};


static struct dev_ops   amr_ops = {
	DEVO_REV,	/* devo_rev, */
	0,		/* refcnt  */
	amr_info,	/* info */
	nulldev,	/* identify */
	nulldev,	/* probe */
	amr_attach,	/* attach */
	amr_detach,	/* detach */
	nodev,		/* reset */
	NULL,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	0,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. driver here */
	"AMR Driver",		/* Name of the module. */
	&amr_ops,		/* Driver ops vector */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/* DMA access attributes */
static ddi_device_acc_attr_t accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

static struct amr_softs  *amr_softstatep;


int
_init(void)
{
	int		error;

	error = ddi_soft_state_init((void *)&amr_softstatep,
	    sizeof (struct amr_softs), 0);

	if (error != 0)
		goto error_out;

	if ((error = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini((void*)&amr_softstatep);
		goto error_out;
	}

	error = mod_install(&modlinkage);
	if (error != 0) {
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini((void*)&amr_softstatep);
		goto error_out;
	}

	return (error);

error_out:
	cmn_err(CE_NOTE, "_init failed");
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	error;

	if ((error = mod_remove(&modlinkage)) != 0) {
		return (error);
	}

	scsi_hba_fini(&modlinkage);

	ddi_soft_state_fini((void*)&amr_softstatep);
	return (error);
}


static int
amr_attach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
	struct amr_softs	*softs;
	int			error;
	uint32_t		command, i;
	int			instance;
	caddr_t			cfgaddr;

	instance = ddi_get_instance(dev);

	switch (cmd) {
		case DDI_ATTACH:
			break;

		case DDI_RESUME:
			return (DDI_FAILURE);

		default:
			return (DDI_FAILURE);
	}

	/*
	 * Initialize softs.
	 */
	if (ddi_soft_state_zalloc(amr_softstatep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	softs = ddi_get_soft_state(amr_softstatep, instance);
	softs->state |= AMR_STATE_SOFT_STATE_SETUP;

	softs->dev_info_p = dev;

	AMRDB_PRINT((CE_NOTE, "softs: %p; busy_slot addr: %p",
	    (void *)softs, (void *)&(softs->amr_busyslots)));

	if (pci_config_setup(dev, &(softs->pciconfig_handle))
	    != DDI_SUCCESS) {
		goto error_out;
	}
	softs->state |= AMR_STATE_PCI_CONFIG_SETUP;

	error = ddi_regs_map_setup(dev, 1, &cfgaddr, 0, 0,
	    &accattr, &(softs->regsmap_handle));
	if (error != DDI_SUCCESS) {
		goto error_out;
	}
	softs->state |= AMR_STATE_PCI_MEM_MAPPED;

	/*
	 * Determine board type.
	 */
	command = pci_config_get16(softs->pciconfig_handle, PCI_CONF_COMM);

	/*
	 * Make sure we are going to be able to talk to this board.
	 */
	if ((command & PCI_COMM_MAE) == 0) {
		AMRDB_PRINT((CE_NOTE,  "memory window not available"));
		goto error_out;
	}

	/* force the busmaster enable bit on */
	if (!(command & PCI_COMM_ME)) {
		command |= PCI_COMM_ME;
		pci_config_put16(softs->pciconfig_handle,
		    PCI_CONF_COMM, command);
		command = pci_config_get16(softs->pciconfig_handle,
		    PCI_CONF_COMM);
		if (!(command & PCI_COMM_ME))
			goto error_out;
	}

	/*
	 * Allocate and connect our interrupt.
	 */
	if (ddi_intr_hilevel(dev, 0) != 0) {
		AMRDB_PRINT((CE_NOTE,
		    "High level interrupt is not supported!"));
		goto error_out;
	}

	if (ddi_get_iblock_cookie(dev, 0,  &softs->iblock_cookiep)
	    != DDI_SUCCESS) {
		goto error_out;
	}

	mutex_init(&softs->cmd_mutex, NULL, MUTEX_DRIVER,
	    softs->iblock_cookiep); /* should be used in interrupt */
	mutex_init(&softs->queue_mutex, NULL, MUTEX_DRIVER,
	    softs->iblock_cookiep); /* should be used in interrupt */
	mutex_init(&softs->periodic_mutex, NULL, MUTEX_DRIVER,
	    softs->iblock_cookiep); /* should be used in interrupt */
	/* sychronize waits for the busy slots via this cv */
	cv_init(&softs->cmd_cv, NULL, CV_DRIVER, NULL);
	softs->state |= AMR_STATE_KMUTEX_INITED;

	/*
	 * Do bus-independent initialisation, bring controller online.
	 */
	if (amr_setup_mbox(softs) != DDI_SUCCESS)
		goto error_out;
	softs->state |= AMR_STATE_MAILBOX_SETUP;

	if (amr_setup_sg(softs) != DDI_SUCCESS)
		goto error_out;

	softs->state |= AMR_STATE_SG_TABLES_SETUP;

	if (amr_query_controller(softs) != DDI_SUCCESS)
		goto error_out;

	/*
	 * A taskq is created for dispatching the waiting queue processing
	 * thread. The threads number equals to the logic drive number and
	 * the thread number should be 1 if there is no logic driver is
	 * configured for this instance.
	 */
	if ((softs->amr_taskq = ddi_taskq_create(dev, "amr_taskq",
	    MAX(softs->amr_nlogdrives, 1), TASKQ_DEFAULTPRI, 0)) == NULL) {
		goto error_out;
	}
	softs->state |= AMR_STATE_TASKQ_SETUP;

	if (ddi_add_intr(dev, 0, &softs->iblock_cookiep, NULL,
	    amr_intr, (caddr_t)softs) != DDI_SUCCESS) {
		goto error_out;
	}
	softs->state |= AMR_STATE_INTR_SETUP;

	/* set up the tran interface */
	if (amr_setup_tran(softs->dev_info_p, softs) != DDI_SUCCESS) {
		AMRDB_PRINT((CE_NOTE, "setup tran failed"));
		goto error_out;
	}
	softs->state |= AMR_STATE_TRAN_SETUP;

	/* schedule a thread for periodic check */
	mutex_enter(&softs->periodic_mutex);
	softs->timeout_t = timeout(amr_periodic, (void *)softs,
	    drv_usectohz(500000*AMR_PERIODIC_TIMEOUT));
	softs->state |= AMR_STATE_TIMEOUT_ENABLED;
	mutex_exit(&softs->periodic_mutex);

	/* print firmware information in verbose mode */
	cmn_err(CE_CONT, "?MegaRaid %s %s attached.",
	    softs->amr_product_info.pi_product_name,
	    softs->amr_product_info.pi_firmware_ver);

	/* clear any interrupts */
	AMR_QCLEAR_INTR(softs);
	return (DDI_SUCCESS);

error_out:
	if (softs->state & AMR_STATE_INTR_SETUP) {
		ddi_remove_intr(dev, 0, softs->iblock_cookiep);
	}
	if (softs->state & AMR_STATE_TASKQ_SETUP) {
		ddi_taskq_destroy(softs->amr_taskq);
	}
	if (softs->state & AMR_STATE_SG_TABLES_SETUP) {
		for (i = 0; i < softs->sg_max_count; i++) {
			(void) ddi_dma_unbind_handle(
			    softs->sg_items[i].sg_handle);
			(void) ddi_dma_mem_free(
			    &((softs->sg_items[i]).sg_acc_handle));
			(void) ddi_dma_free_handle(
			    &(softs->sg_items[i].sg_handle));
		}
	}
	if (softs->state & AMR_STATE_MAILBOX_SETUP) {
		(void) ddi_dma_unbind_handle(softs->mbox_dma_handle);
		(void) ddi_dma_mem_free(&softs->mbox_acc_handle);
		(void) ddi_dma_free_handle(&softs->mbox_dma_handle);
	}
	if (softs->state & AMR_STATE_KMUTEX_INITED) {
		mutex_destroy(&softs->queue_mutex);
		mutex_destroy(&softs->cmd_mutex);
		mutex_destroy(&softs->periodic_mutex);
		cv_destroy(&softs->cmd_cv);
	}
	if (softs->state & AMR_STATE_PCI_MEM_MAPPED)
		ddi_regs_map_free(&softs->regsmap_handle);
	if (softs->state & AMR_STATE_PCI_CONFIG_SETUP)
		pci_config_teardown(&softs->pciconfig_handle);
	if (softs->state & AMR_STATE_SOFT_STATE_SETUP)
		ddi_soft_state_free(amr_softstatep, instance);
	return (DDI_FAILURE);
}

/*
 * Bring the controller down to a dormant state and detach all child devices.
 * This function is called during detach, system shutdown.
 *
 * Note that we can assume that the bufq on the controller is empty, as we won't
 * allow shutdown if any device is open.
 */
/*ARGSUSED*/
static int amr_detach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
	struct amr_softs	*softs;
	int			instance;
	uint32_t		i, done_flag;

	instance = ddi_get_instance(dev);
	softs = ddi_get_soft_state(amr_softstatep, instance);

	/* flush the controllor */
	if (amr_flush(softs) != 0) {
		AMRDB_PRINT((CE_NOTE, "device shutdown failed"));
		return (EIO);
	}

	/* release the amr timer */
	mutex_enter(&softs->periodic_mutex);
	softs->state &= ~AMR_STATE_TIMEOUT_ENABLED;
	if (softs->timeout_t) {
		(void) untimeout(softs->timeout_t);
		softs->timeout_t = 0;
	}
	mutex_exit(&softs->periodic_mutex);

	for (i = 0; i < softs->sg_max_count; i++) {
		(void) ddi_dma_unbind_handle(
		    softs->sg_items[i].sg_handle);
		(void) ddi_dma_mem_free(
		    &((softs->sg_items[i]).sg_acc_handle));
		(void) ddi_dma_free_handle(
		    &(softs->sg_items[i].sg_handle));
	}

	(void) ddi_dma_unbind_handle(softs->mbox_dma_handle);
	(void) ddi_dma_mem_free(&softs->mbox_acc_handle);
	(void) ddi_dma_free_handle(&softs->mbox_dma_handle);

	/* disconnect the interrupt handler */
	ddi_remove_intr(softs->dev_info_p,  0, softs->iblock_cookiep);

	/* wait for the completion of current in-progress interruptes */
	AMR_DELAY((softs->amr_interrupts_counter == 0), 1000, done_flag);
	if (!done_flag) {
		cmn_err(CE_WARN, "Suspicious interrupts in-progress.");
	}

	ddi_taskq_destroy(softs->amr_taskq);

	(void) scsi_hba_detach(dev);
	scsi_hba_tran_free(softs->hba_tran);
	ddi_regs_map_free(&softs->regsmap_handle);
	pci_config_teardown(&softs->pciconfig_handle);

	mutex_destroy(&softs->queue_mutex);
	mutex_destroy(&softs->cmd_mutex);
	mutex_destroy(&softs->periodic_mutex);
	cv_destroy(&softs->cmd_cv);

	/* print firmware information in verbose mode */
	cmn_err(CE_NOTE, "?MegaRaid %s %s detached.",
	    softs->amr_product_info.pi_product_name,
	    softs->amr_product_info.pi_firmware_ver);

	ddi_soft_state_free(amr_softstatep, instance);

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int amr_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result)
{
	struct amr_softs	*softs;
	int			instance;

	instance = ddi_get_instance(dip);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			softs = ddi_get_soft_state(amr_softstatep, instance);
			if (softs != NULL) {
				*result = softs->dev_info_p;
				return (DDI_SUCCESS);
			} else {
				*result = NULL;
				return (DDI_FAILURE);
			}
		case DDI_INFO_DEVT2INSTANCE:
			*(int *)result = instance;
			break;
		default:
			break;
	}
	return (DDI_SUCCESS);
}

/*
 * Take an interrupt, or be poked by other code to look for interrupt-worthy
 * status.
 */
static uint_t
amr_intr(caddr_t arg)
{
	struct amr_softs *softs = (struct amr_softs *)arg;

	softs->amr_interrupts_counter++;

	if (AMR_QGET_ODB(softs) != AMR_QODB_READY) {
		softs->amr_interrupts_counter--;
		return (DDI_INTR_UNCLAIMED);
	}

	/* collect finished commands, queue anything waiting */
	amr_done(softs);

	softs->amr_interrupts_counter--;

	return (DDI_INTR_CLAIMED);

}

/*
 * Setup the amr mailbox
 */
static int
amr_setup_mbox(struct amr_softs *softs)
{
	uint32_t	move;
	size_t		mbox_len;

	if (ddi_dma_alloc_handle(
	    softs->dev_info_p,
	    &addr_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &softs->mbox_dma_handle) != DDI_SUCCESS) {
		AMRDB_PRINT((CE_NOTE, "Cannot alloc dma handle for mailbox"));
		goto error_out;
	}

	if (ddi_dma_mem_alloc(
	    softs->mbox_dma_handle,
	    sizeof (struct amr_mailbox) + 16,
	    &accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)(&softs->mbox),
	    &mbox_len,
	    &softs->mbox_acc_handle) !=
	    DDI_SUCCESS) {

		AMRDB_PRINT((CE_WARN, "Cannot alloc dma memory for mailbox"));
		goto error_out;
	}

	if (ddi_dma_addr_bind_handle(
	    softs->mbox_dma_handle,
	    NULL,
	    (caddr_t)softs->mbox,
	    mbox_len,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &softs->mbox_dma_cookie,
	    &softs->mbox_dma_cookien) != DDI_DMA_MAPPED) {

		AMRDB_PRINT((CE_NOTE, "Cannot bind dma memory for mailbox"));
		goto error_out;
	}

	if (softs->mbox_dma_cookien != 1)
		goto error_out;

	/* The phy address of mailbox must be aligned on a 16-byte boundary */
	move = 16 - (((uint32_t)softs->mbox_dma_cookie.dmac_address)&0xf);
	softs->mbox_phyaddr =
	    (softs->mbox_dma_cookie.dmac_address + move);

	softs->mailbox =
	    (struct amr_mailbox *)(((uintptr_t)softs->mbox) + move);

	AMRDB_PRINT((CE_NOTE, "phraddy=%x, mailbox=%p, softs->mbox=%p, move=%x",
	    softs->mbox_phyaddr, (void *)softs->mailbox,
	    softs->mbox, move));

	return (DDI_SUCCESS);

error_out:
	if (softs->mbox_dma_cookien)
		(void) ddi_dma_unbind_handle(softs->mbox_dma_handle);
	if (softs->mbox_acc_handle) {
		(void) ddi_dma_mem_free(&(softs->mbox_acc_handle));
		softs->mbox_acc_handle = NULL;
	}
	if (softs->mbox_dma_handle) {
		(void) ddi_dma_free_handle(&softs->mbox_dma_handle);
		softs->mbox_dma_handle = NULL;
	}

	return (DDI_FAILURE);
}

/*
 * Perform a periodic check of the controller status
 */
static void
amr_periodic(void *data)
{
	uint32_t		i;
	struct amr_softs	*softs = (struct amr_softs *)data;
	struct scsi_pkt 	*pkt;
	register struct amr_command	*ac;

	for (i = 0; i < softs->sg_max_count; i++) {
		if (softs->busycmd[i] == NULL)
			continue;

		mutex_enter(&softs->cmd_mutex);

		if (softs->busycmd[i] == NULL) {
			mutex_exit(&softs->cmd_mutex);
			continue;
		}

		pkt = softs->busycmd[i]->pkt;

		if ((pkt->pkt_time != 0) &&
		    (ddi_get_time() -
		    softs->busycmd[i]->ac_timestamp >
		    pkt->pkt_time)) {

			cmn_err(CE_WARN,
			    "!timed out packet detected,\
				sc = %p, pkt = %p, index = %d, ac = %p",
			    (void *)softs,
			    (void *)pkt,
			    i,
			    (void *)softs->busycmd[i]);

			ac = softs->busycmd[i];
			ac->ac_next = NULL;

			/* pull command from the busy index */
			softs->busycmd[i] = NULL;
			if (softs->amr_busyslots > 0)
				softs->amr_busyslots--;
			if (softs->amr_busyslots == 0)
				cv_broadcast(&softs->cmd_cv);

			mutex_exit(&softs->cmd_mutex);

			pkt = ac->pkt;
			*pkt->pkt_scbp = 0;
			pkt->pkt_statistics |= STAT_TIMEOUT;
			pkt->pkt_reason = CMD_TIMEOUT;
			if (!(pkt->pkt_flags &
			    FLAG_NOINTR) && pkt->pkt_comp) {
				/* call pkt callback */
				(*pkt->pkt_comp)(pkt);
			}

		} else {
			mutex_exit(&softs->cmd_mutex);
		}
	}

	/* restart the amr timer */
	mutex_enter(&softs->periodic_mutex);
	if (softs->state & AMR_STATE_TIMEOUT_ENABLED)
		softs->timeout_t = timeout(amr_periodic, (void *)softs,
		    drv_usectohz(500000*AMR_PERIODIC_TIMEOUT));
	mutex_exit(&softs->periodic_mutex);
}

/*
 * Interrogate the controller for the operational parameters we require.
 */
static int
amr_query_controller(struct amr_softs *softs)
{
	struct amr_enquiry3	*aex;
	struct amr_prodinfo	*ap;
	struct amr_enquiry	*ae;
	uint32_t		ldrv;
	int			instance;

	/*
	 * If we haven't found the real limit yet, let us have a couple of
	 * commands in order to be able to probe.
	 */
	if (softs->maxio == 0)
		softs->maxio = 2;

	instance = ddi_get_instance(softs->dev_info_p);

	/*
	 * Try to issue an ENQUIRY3 command
	 */
	if ((aex = amr_enquiry(softs, AMR_ENQ_BUFFER_SIZE, AMR_CMD_CONFIG,
	    AMR_CONFIG_ENQ3, AMR_CONFIG_ENQ3_SOLICITED_FULL)) != NULL) {

		AMRDB_PRINT((CE_NOTE, "First enquiry"));

		for (ldrv = 0; ldrv < aex->ae_numldrives; ldrv++) {
			softs->logic_drive[ldrv].al_size =
			    aex->ae_drivesize[ldrv];
			softs->logic_drive[ldrv].al_state =
			    aex->ae_drivestate[ldrv];
			softs->logic_drive[ldrv].al_properties =
			    aex->ae_driveprop[ldrv];
			AMRDB_PRINT((CE_NOTE,
			    "  drive %d: size: %d state %x properties %x\n",
			    ldrv,
			    softs->logic_drive[ldrv].al_size,
			    softs->logic_drive[ldrv].al_state,
			    softs->logic_drive[ldrv].al_properties));

			if (softs->logic_drive[ldrv].al_state ==
			    AMR_LDRV_OFFLINE)
				cmn_err(CE_NOTE,
				    "!instance %d log-drive %d is offline",
				    instance, ldrv);
			else
				softs->amr_nlogdrives++;
		}
		kmem_free(aex, AMR_ENQ_BUFFER_SIZE);

		if ((ap = amr_enquiry(softs, AMR_ENQ_BUFFER_SIZE,
		    AMR_CMD_CONFIG, AMR_CONFIG_PRODUCT_INFO, 0)) == NULL) {
			AMRDB_PRINT((CE_NOTE,
			    "Cannot obtain product data from controller"));
			return (EIO);
		}

		softs->maxdrives = AMR_40LD_MAXDRIVES;
		softs->maxchan = ap->ap_nschan;
		softs->maxio = ap->ap_maxio;

		bcopy(ap->ap_firmware, softs->amr_product_info.pi_firmware_ver,
		    AMR_FIRMWARE_VER_SIZE);
		softs->amr_product_info.
		    pi_firmware_ver[AMR_FIRMWARE_VER_SIZE] = 0;

		bcopy(ap->ap_product, softs->amr_product_info.pi_product_name,
		    AMR_PRODUCT_INFO_SIZE);
		softs->amr_product_info.
		    pi_product_name[AMR_PRODUCT_INFO_SIZE] = 0;

		kmem_free(ap, AMR_ENQ_BUFFER_SIZE);
		AMRDB_PRINT((CE_NOTE, "maxio=%d", softs->maxio));
	} else {

		AMRDB_PRINT((CE_NOTE, "First enquiry failed, \
				so try another way"));

		/* failed, try the 8LD ENQUIRY commands */
		if ((ae = (struct amr_enquiry *)amr_enquiry(softs,
		    AMR_ENQ_BUFFER_SIZE, AMR_CMD_EXT_ENQUIRY2, 0, 0))
		    == NULL) {

			if ((ae = (struct amr_enquiry *)amr_enquiry(softs,
			    AMR_ENQ_BUFFER_SIZE, AMR_CMD_ENQUIRY, 0, 0))
			    == NULL) {
				AMRDB_PRINT((CE_NOTE,
				    "Cannot obtain configuration data"));
				return (EIO);
			}
			ae->ae_signature = 0;
		}

		/*
		 * Fetch current state of logical drives.
		 */
		for (ldrv = 0; ldrv < ae->ae_ldrv.al_numdrives; ldrv++) {
			softs->logic_drive[ldrv].al_size =
			    ae->ae_ldrv.al_size[ldrv];
			softs->logic_drive[ldrv].al_state =
			    ae->ae_ldrv.al_state[ldrv];
			softs->logic_drive[ldrv].al_properties =
			    ae->ae_ldrv.al_properties[ldrv];
			AMRDB_PRINT((CE_NOTE,
			    " ********* drive %d: %d state %x properties %x",
			    ldrv,
			    softs->logic_drive[ldrv].al_size,
			    softs->logic_drive[ldrv].al_state,
			    softs->logic_drive[ldrv].al_properties));

			if (softs->logic_drive[ldrv].al_state ==
			    AMR_LDRV_OFFLINE)
				cmn_err(CE_NOTE,
				    "!instance %d log-drive %d is offline",
				    instance, ldrv);
			else
				softs->amr_nlogdrives++;
		}

		softs->maxdrives = AMR_8LD_MAXDRIVES;
		softs->maxchan = ae->ae_adapter.aa_channels;
		softs->maxio = ae->ae_adapter.aa_maxio;
		kmem_free(ae, AMR_ENQ_BUFFER_SIZE);
	}

	/*
	 * Mark remaining drives as unused.
	 */
	for (; ldrv < AMR_MAXLD; ldrv++)
		softs->logic_drive[ldrv].al_state = AMR_LDRV_OFFLINE;

	/*
	 * Cap the maximum number of outstanding I/Os.  AMI's driver
	 * doesn't trust the controller's reported value, and lockups have
	 * been seen when we do.
	 */
	softs->maxio = MIN(softs->maxio, AMR_LIMITCMD);

	return (DDI_SUCCESS);
}

/*
 * Run a generic enquiry-style command.
 */
static void *
amr_enquiry(struct amr_softs *softs, size_t bufsize, uint8_t cmd,
				uint8_t cmdsub, uint8_t cmdqual)
{
	struct amr_command	ac;
	void			*result;

	result = NULL;

	bzero(&ac, sizeof (struct amr_command));
	ac.ac_softs = softs;

	/* set command flags */
	ac.ac_flags |= AMR_CMD_DATAOUT;

	/* build the command proper */
	ac.mailbox.mb_command	= cmd;
	ac.mailbox.mb_cmdsub	= cmdsub;
	ac.mailbox.mb_cmdqual	= cmdqual;

	if (amr_enquiry_mapcmd(&ac, bufsize) != DDI_SUCCESS)
		return (NULL);

	if (amr_poll_command(&ac) || ac.ac_status != 0) {
		AMRDB_PRINT((CE_NOTE, "can not poll command, goto out"));
		amr_enquiry_unmapcmd(&ac);
		return (NULL);
	}

	/* allocate the response structure */
	result = kmem_zalloc(bufsize, KM_SLEEP);

	bcopy(ac.ac_data, result, bufsize);

	amr_enquiry_unmapcmd(&ac);
	return (result);
}

/*
 * Flush the controller's internal cache, return status.
 */
static int
amr_flush(struct amr_softs *softs)
{
	struct amr_command	ac;
	int			error = 0;

	bzero(&ac, sizeof (struct amr_command));
	ac.ac_softs = softs;

	ac.ac_flags |= AMR_CMD_DATAOUT;

	/* build the command proper */
	ac.mailbox.mb_command = AMR_CMD_FLUSH;

	/* have to poll, as the system may be going down or otherwise damaged */
	if (error = amr_poll_command(&ac)) {
		AMRDB_PRINT((CE_NOTE, "can not poll this cmd"));
		return (error);
	}

	return (error);
}

/*
 * Take a command, submit it to the controller and wait for it to return.
 * Returns nonzero on error.  Can be safely called with interrupts enabled.
 */
static int
amr_poll_command(struct amr_command *ac)
{
	struct amr_softs	*softs = ac->ac_softs;
	volatile uint32_t	done_flag;

	AMRDB_PRINT((CE_NOTE, "Amr_Poll bcopy(%p, %p, %d)",
	    (void *)&ac->mailbox,
	    (void *)softs->mailbox,
	    (uint32_t)AMR_MBOX_CMDSIZE));

	mutex_enter(&softs->cmd_mutex);

	while (softs->amr_busyslots != 0)
		cv_wait(&softs->cmd_cv, &softs->cmd_mutex);

	/*
	 * For read/write commands, the scatter/gather table should be
	 * filled, and the last entry in scatter/gather table will be used.
	 */
	if ((ac->mailbox.mb_command == AMR_CMD_LREAD) ||
	    (ac->mailbox.mb_command == AMR_CMD_LWRITE)) {
		bcopy(ac->sgtable,
		    softs->sg_items[softs->sg_max_count - 1].sg_table,
		    sizeof (struct amr_sgentry) * AMR_NSEG);

		(void) ddi_dma_sync(
		    softs->sg_items[softs->sg_max_count - 1].sg_handle,
		    0, 0, DDI_DMA_SYNC_FORDEV);

		ac->mailbox.mb_physaddr =
		    softs->sg_items[softs->sg_max_count - 1].sg_phyaddr;
	}

	bcopy(&ac->mailbox, (void *)softs->mailbox, AMR_MBOX_CMDSIZE);

	/* sync the dma memory */
	(void) ddi_dma_sync(softs->mbox_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* clear the poll/ack fields in the mailbox */
	softs->mailbox->mb_ident = AMR_POLL_COMMAND_ID;
	softs->mailbox->mb_nstatus = AMR_POLL_DEFAULT_NSTATUS;
	softs->mailbox->mb_status = AMR_POLL_DEFAULT_STATUS;
	softs->mailbox->mb_poll = 0;
	softs->mailbox->mb_ack = 0;
	softs->mailbox->mb_busy = 1;

	AMR_QPUT_IDB(softs, softs->mbox_phyaddr | AMR_QIDB_SUBMIT);

	/* sync the dma memory */
	(void) ddi_dma_sync(softs->mbox_dma_handle, 0, 0, DDI_DMA_SYNC_FORCPU);

	AMR_DELAY((softs->mailbox->mb_nstatus != AMR_POLL_DEFAULT_NSTATUS),
	    1000, done_flag);
	if (!done_flag) {
		mutex_exit(&softs->cmd_mutex);
		return (1);
	}

	ac->ac_status = softs->mailbox->mb_status;

	AMR_DELAY((softs->mailbox->mb_poll == AMR_POLL_ACK), 1000, done_flag);
	if (!done_flag) {
		mutex_exit(&softs->cmd_mutex);
		return (1);
	}

	softs->mailbox->mb_poll = 0;
	softs->mailbox->mb_ack = AMR_POLL_ACK;

	/* acknowledge that we have the commands */
	AMR_QPUT_IDB(softs, softs->mbox_phyaddr | AMR_QIDB_ACK);

	AMR_DELAY(!(AMR_QGET_IDB(softs) & AMR_QIDB_ACK), 1000, done_flag);
	if (!done_flag) {
		mutex_exit(&softs->cmd_mutex);
		return (1);
	}

	mutex_exit(&softs->cmd_mutex);
	return (ac->ac_status != AMR_STATUS_SUCCESS);
}

/*
 * setup the scatter/gather table
 */
static int
amr_setup_sg(struct amr_softs *softs)
{
	uint32_t		i;
	size_t			len;
	ddi_dma_cookie_t	cookie;
	uint_t			cookien;

	softs->sg_max_count = 0;

	for (i = 0; i < AMR_MAXCMD; i++) {

		/* reset the cookien */
		cookien = 0;

		(softs->sg_items[i]).sg_handle = NULL;
		if (ddi_dma_alloc_handle(
		    softs->dev_info_p,
		    &addr_dma_attr,
		    DDI_DMA_SLEEP,
		    NULL,
		    &((softs->sg_items[i]).sg_handle)) != DDI_SUCCESS) {

			AMRDB_PRINT((CE_WARN,
			"Cannot alloc dma handle for s/g table"));
			goto error_out;
		}

		if (ddi_dma_mem_alloc((softs->sg_items[i]).sg_handle,
		    sizeof (struct amr_sgentry) * AMR_NSEG,
		    &accattr,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL,
		    (caddr_t *)(&(softs->sg_items[i]).sg_table),
		    &len,
		    &(softs->sg_items[i]).sg_acc_handle)
		    != DDI_SUCCESS) {

			AMRDB_PRINT((CE_WARN,
			"Cannot allocate DMA memory"));
			goto error_out;
		}

		if (ddi_dma_addr_bind_handle(
		    (softs->sg_items[i]).sg_handle,
		    NULL,
		    (caddr_t)((softs->sg_items[i]).sg_table),
		    len,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP,
		    NULL,
		    &cookie,
		    &cookien) != DDI_DMA_MAPPED) {

			AMRDB_PRINT((CE_WARN,
			"Cannot bind communication area for s/g table"));
			goto error_out;
		}

		if (cookien != 1)
			goto error_out;

		softs->sg_items[i].sg_phyaddr = cookie.dmac_address;
		softs->sg_max_count++;
	}

	return (DDI_SUCCESS);

error_out:
	/*
	 * Couldn't allocate/initialize all of the sg table entries.
	 * Clean up the partially-initialized entry before returning.
	 */
	if (cookien) {
		(void) ddi_dma_unbind_handle((softs->sg_items[i]).sg_handle);
	}
	if ((softs->sg_items[i]).sg_acc_handle) {
		(void) ddi_dma_mem_free(&((softs->sg_items[i]).sg_acc_handle));
		(softs->sg_items[i]).sg_acc_handle = NULL;
	}
	if ((softs->sg_items[i]).sg_handle) {
		(void) ddi_dma_free_handle(&((softs->sg_items[i]).sg_handle));
		(softs->sg_items[i]).sg_handle = NULL;
	}

	/*
	 * At least two sg table entries are needed. One is for regular data
	 * I/O commands, the other is for poll I/O commands.
	 */
	return (softs->sg_max_count > 1 ? DDI_SUCCESS : DDI_FAILURE);
}

/*
 * Map/unmap (ac)'s data in the controller's addressable space as required.
 *
 * These functions may be safely called multiple times on a given command.
 */
static void
amr_setup_dmamap(struct amr_command *ac, ddi_dma_cookie_t *buffer_dma_cookiep,
		int nsegments)
{
	struct amr_sgentry	*sg;
	uint32_t		i, size;

	sg = ac->sgtable;

	size = 0;

	ac->mailbox.mb_nsgelem = (uint8_t)nsegments;
	for (i = 0; i < nsegments; i++, sg++) {
		sg->sg_addr = buffer_dma_cookiep->dmac_address;
		sg->sg_count = buffer_dma_cookiep->dmac_size;
		size += sg->sg_count;

		/*
		 * There is no next cookie if the end of the current
		 * window is reached. Otherwise, the next cookie
		 * would be found.
		 */
		if ((ac->current_cookie + i + 1) != ac->num_of_cookie)
			ddi_dma_nextcookie(ac->buffer_dma_handle,
			    buffer_dma_cookiep);
	}

	ac->transfer_size = size;
	ac->data_transfered += size;
}


/*
 * map the amr command for enquiry, allocate the DMA resource
 */
static int
amr_enquiry_mapcmd(struct amr_command *ac, uint32_t data_size)
{
	struct amr_softs	*softs = ac->ac_softs;
	size_t			len;
	uint_t			dma_flags;

	AMRDB_PRINT((CE_NOTE, "Amr_enquiry_mapcmd called, ac=%p, flags=%x",
	    (void *)ac, ac->ac_flags));

	if (ac->ac_flags & AMR_CMD_DATAOUT) {
		dma_flags = DDI_DMA_READ;
	} else {
		dma_flags = DDI_DMA_WRITE;
	}

	dma_flags |= DDI_DMA_CONSISTENT;

	/* process the DMA by address bind mode */
	if (ddi_dma_alloc_handle(softs->dev_info_p,
	    &addr_dma_attr, DDI_DMA_SLEEP, NULL,
	    &ac->buffer_dma_handle) !=
	    DDI_SUCCESS) {

		AMRDB_PRINT((CE_WARN,
		"Cannot allocate addr DMA tag"));
		goto error_out;
	}

	if (ddi_dma_mem_alloc(ac->buffer_dma_handle,
	    data_size,
	    &accattr,
	    dma_flags,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&ac->ac_data,
	    &len,
	    &ac->buffer_acc_handle) !=
	    DDI_SUCCESS) {

		AMRDB_PRINT((CE_WARN,
		"Cannot allocate DMA memory"));
		goto error_out;
	}

	if ((ddi_dma_addr_bind_handle(
	    ac->buffer_dma_handle,
	    NULL, ac->ac_data, len, dma_flags,
	    DDI_DMA_SLEEP, NULL, &ac->buffer_dma_cookie,
	    &ac->num_of_cookie)) != DDI_DMA_MAPPED) {

		AMRDB_PRINT((CE_WARN,
		    "Cannot bind addr for dma"));
		goto error_out;
	}

	ac->ac_dataphys = (&ac->buffer_dma_cookie)->dmac_address;

	((struct amr_mailbox *)&(ac->mailbox))->mb_param = 0;
	ac->mailbox.mb_nsgelem = 0;
	ac->mailbox.mb_physaddr = ac->ac_dataphys;

	ac->ac_flags |= AMR_CMD_MAPPED;

	return (DDI_SUCCESS);

error_out:
	if (ac->num_of_cookie)
		(void) ddi_dma_unbind_handle(ac->buffer_dma_handle);
	if (ac->buffer_acc_handle) {
		ddi_dma_mem_free(&ac->buffer_acc_handle);
		ac->buffer_acc_handle = NULL;
	}
	if (ac->buffer_dma_handle) {
		(void) ddi_dma_free_handle(&ac->buffer_dma_handle);
		ac->buffer_dma_handle = NULL;
	}

	return (DDI_FAILURE);
}

/*
 * unmap the amr command for enquiry, free the DMA resource
 */
static void
amr_enquiry_unmapcmd(struct amr_command *ac)
{
	AMRDB_PRINT((CE_NOTE, "Amr_enquiry_unmapcmd called, ac=%p",
	    (void *)ac));

	/* if the command involved data at all and was mapped */
	if ((ac->ac_flags & AMR_CMD_MAPPED) && ac->ac_data) {
		if (ac->buffer_dma_handle)
			(void) ddi_dma_unbind_handle(
			    ac->buffer_dma_handle);
		if (ac->buffer_acc_handle) {
			ddi_dma_mem_free(&ac->buffer_acc_handle);
			ac->buffer_acc_handle = NULL;
		}
		if (ac->buffer_dma_handle) {
			(void) ddi_dma_free_handle(
			    &ac->buffer_dma_handle);
			ac->buffer_dma_handle = NULL;
		}
	}

	ac->ac_flags &= ~AMR_CMD_MAPPED;
}

/*
 * map the amr command, allocate the DMA resource
 */
static int
amr_mapcmd(struct amr_command *ac, int (*callback)(), caddr_t arg)
{
	uint_t	dma_flags;
	off_t	off;
	size_t	len;
	int	error;
	int	(*cb)(caddr_t);

	AMRDB_PRINT((CE_NOTE, "Amr_mapcmd called, ac=%p, flags=%x",
	    (void *)ac, ac->ac_flags));

	if (ac->ac_flags & AMR_CMD_DATAOUT) {
		dma_flags = DDI_DMA_READ;
	} else {
		dma_flags = DDI_DMA_WRITE;
	}

	if (ac->ac_flags & AMR_CMD_PKT_CONSISTENT) {
		dma_flags |= DDI_DMA_CONSISTENT;
	}
	if (ac->ac_flags & AMR_CMD_PKT_DMA_PARTIAL) {
		dma_flags |= DDI_DMA_PARTIAL;
	}

	if ((!(ac->ac_flags & AMR_CMD_MAPPED)) && (ac->ac_buf == NULL)) {
		ac->ac_flags |= AMR_CMD_MAPPED;
		return (DDI_SUCCESS);
	}

	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	/* if the command involves data at all, and hasn't been mapped */
	if (!(ac->ac_flags & AMR_CMD_MAPPED)) {
		/* process the DMA by buffer bind mode */
		error = ddi_dma_buf_bind_handle(ac->buffer_dma_handle,
		    ac->ac_buf,
		    dma_flags,
		    cb,
		    arg,
		    &ac->buffer_dma_cookie,
		    &ac->num_of_cookie);
		switch (error) {
		case DDI_DMA_PARTIAL_MAP:
			if (ddi_dma_numwin(ac->buffer_dma_handle,
			    &ac->num_of_win) == DDI_FAILURE) {

				AMRDB_PRINT((CE_WARN,
				    "Cannot get dma num win"));
				(void) ddi_dma_unbind_handle(
				    ac->buffer_dma_handle);
				(void) ddi_dma_free_handle(
				    &ac->buffer_dma_handle);
				ac->buffer_dma_handle = NULL;
				return (DDI_FAILURE);
			}
			ac->current_win = 0;
			break;

		case DDI_DMA_MAPPED:
			ac->num_of_win = 1;
			ac->current_win = 0;
			break;

		default:
			AMRDB_PRINT((CE_WARN,
			    "Cannot bind buf for dma"));

			(void) ddi_dma_free_handle(
			    &ac->buffer_dma_handle);
			ac->buffer_dma_handle = NULL;
			return (DDI_FAILURE);
		}

		ac->current_cookie = 0;

		ac->ac_flags |= AMR_CMD_MAPPED;
	} else if (ac->current_cookie == AMR_LAST_COOKIE_TAG) {
		/* get the next window */
		ac->current_win++;
		(void) ddi_dma_getwin(ac->buffer_dma_handle,
		    ac->current_win, &off, &len,
		    &ac->buffer_dma_cookie,
		    &ac->num_of_cookie);
		ac->current_cookie = 0;
	}

	if ((ac->num_of_cookie - ac->current_cookie) > AMR_NSEG) {
		amr_setup_dmamap(ac, &ac->buffer_dma_cookie, AMR_NSEG);
		ac->current_cookie += AMR_NSEG;
	} else {
		amr_setup_dmamap(ac, &ac->buffer_dma_cookie,
		    ac->num_of_cookie - ac->current_cookie);
		ac->current_cookie = AMR_LAST_COOKIE_TAG;
	}

	return (DDI_SUCCESS);
}

/*
 * unmap the amr command, free the DMA resource
 */
static void
amr_unmapcmd(struct amr_command *ac)
{
	AMRDB_PRINT((CE_NOTE, "Amr_unmapcmd called, ac=%p",
	    (void *)ac));

	/* if the command involved data at all and was mapped */
	if ((ac->ac_flags & AMR_CMD_MAPPED) &&
	    ac->ac_buf && ac->buffer_dma_handle)
		(void) ddi_dma_unbind_handle(ac->buffer_dma_handle);

	ac->ac_flags &= ~AMR_CMD_MAPPED;
}

static int
amr_setup_tran(dev_info_t  *dip, struct amr_softs *softp)
{
	softp->hba_tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);

	/*
	 * hba_private always points to the amr_softs struct
	 */
	softp->hba_tran->tran_hba_private	= softp;
	softp->hba_tran->tran_tgt_init		= amr_tran_tgt_init;
	softp->hba_tran->tran_tgt_probe		= scsi_hba_probe;
	softp->hba_tran->tran_start		= amr_tran_start;
	softp->hba_tran->tran_reset		= amr_tran_reset;
	softp->hba_tran->tran_getcap		= amr_tran_getcap;
	softp->hba_tran->tran_setcap		= amr_tran_setcap;
	softp->hba_tran->tran_init_pkt		= amr_tran_init_pkt;
	softp->hba_tran->tran_destroy_pkt	= amr_tran_destroy_pkt;
	softp->hba_tran->tran_dmafree		= amr_tran_dmafree;
	softp->hba_tran->tran_sync_pkt		= amr_tran_sync_pkt;
	softp->hba_tran->tran_abort		= NULL;
	softp->hba_tran->tran_tgt_free		= NULL;
	softp->hba_tran->tran_quiesce		= NULL;
	softp->hba_tran->tran_unquiesce		= NULL;
	softp->hba_tran->tran_sd		= NULL;

	if (scsi_hba_attach_setup(dip, &buffer_dma_attr, softp->hba_tran,
	    SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS) {
		scsi_hba_tran_free(softp->hba_tran);
		softp->hba_tran = NULL;
		return (DDI_FAILURE);
	} else {
		return (DDI_SUCCESS);
	}
}

/*ARGSUSED*/
static int
amr_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct amr_softs	*softs;
	ushort_t		target = sd->sd_address.a_target;
	uchar_t			lun = sd->sd_address.a_lun;

	softs = (struct amr_softs *)
	    (sd->sd_address.a_hba_tran->tran_hba_private);

	if ((lun == 0) && (target < AMR_MAXLD))
		if (softs->logic_drive[target].al_state != AMR_LDRV_OFFLINE)
			return (DDI_SUCCESS);

	return (DDI_FAILURE);
}

static int
amr_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct amr_softs	*softs;
	struct buf		*bp = NULL;
	union scsi_cdb		*cdbp = (union scsi_cdb *)pkt->pkt_cdbp;
	int			ret;
	uint32_t		capacity;
	struct amr_command	*ac;

	AMRDB_PRINT((CE_NOTE, "amr_tran_start, cmd=%X,target=%d,lun=%d",
	    cdbp->scc_cmd, ap->a_target, ap->a_lun));

	softs = (struct amr_softs *)(ap->a_hba_tran->tran_hba_private);
	if ((ap->a_lun != 0) || (ap->a_target >= AMR_MAXLD) ||
	    (softs->logic_drive[ap->a_target].al_state ==
	    AMR_LDRV_OFFLINE)) {
		cmn_err(CE_WARN, "target or lun is not correct!");
		ret = TRAN_BADPKT;
		return (ret);
	}

	ac = (struct amr_command *)pkt->pkt_ha_private;
	bp = ac->ac_buf;

	AMRDB_PRINT((CE_NOTE, "scsi cmd accepted, cmd=%X", cdbp->scc_cmd));

	switch (cdbp->scc_cmd) {
	case SCMD_READ:		/* read		*/
	case SCMD_READ_G1:	/* read	g1	*/
	case SCMD_READ_BUFFER:	/* read buffer	*/
	case SCMD_WRITE:	/* write	*/
	case SCMD_WRITE_G1:	/* write g1	*/
	case SCMD_WRITE_BUFFER:	/* write buffer	*/
		amr_rw_command(softs, pkt, ap->a_target);

		if (pkt->pkt_flags & FLAG_NOINTR) {
			(void) amr_poll_command(ac);
			pkt->pkt_state |= (STATE_GOT_BUS
			    | STATE_GOT_TARGET
			    | STATE_SENT_CMD
			    | STATE_XFERRED_DATA);
			*pkt->pkt_scbp = 0;
			pkt->pkt_statistics |= STAT_SYNC;
			pkt->pkt_reason = CMD_CMPLT;
		} else {
			mutex_enter(&softs->queue_mutex);
			if (softs->waiting_q_head == NULL) {
				ac->ac_prev = NULL;
				ac->ac_next = NULL;
				softs->waiting_q_head = ac;
				softs->waiting_q_tail = ac;
			} else {
				ac->ac_next = NULL;
				ac->ac_prev = softs->waiting_q_tail;
				softs->waiting_q_tail->ac_next = ac;
				softs->waiting_q_tail = ac;
			}
			mutex_exit(&softs->queue_mutex);
			amr_start_waiting_queue((void *)softs);
		}
		ret = TRAN_ACCEPT;
		break;

	case SCMD_INQUIRY: /* inquiry */
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			struct scsi_inquiry inqp;
			uint8_t *sinq_p = (uint8_t *)&inqp;

			bzero(&inqp, sizeof (struct scsi_inquiry));

			if (((char *)cdbp)[1] || ((char *)cdbp)[2]) {
				/*
				 * The EVDP and pagecode is
				 * not supported
				 */
				sinq_p[1] = 0xFF;
				sinq_p[2] = 0x0;
			} else {
				inqp.inq_len = AMR_INQ_ADDITIONAL_LEN;
				inqp.inq_ansi = AMR_INQ_ANSI_VER;
				inqp.inq_rdf = AMR_INQ_RESP_DATA_FORMAT;
				/* Enable Tag Queue */
				inqp.inq_cmdque = 1;
				bcopy("MegaRaid", inqp.inq_vid,
				    sizeof (inqp.inq_vid));
				bcopy(softs->amr_product_info.pi_product_name,
				    inqp.inq_pid,
				    AMR_PRODUCT_INFO_SIZE);
				bcopy(softs->amr_product_info.pi_firmware_ver,
				    inqp.inq_revision,
				    AMR_FIRMWARE_VER_SIZE);
			}

			amr_unmapcmd(ac);

			if (bp->b_flags & (B_PHYS | B_PAGEIO))
				bp_mapin(bp);
			bcopy(&inqp, bp->b_un.b_addr,
			    sizeof (struct scsi_inquiry));

			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= (STATE_GOT_BUS
		    | STATE_GOT_TARGET
		    | STATE_SENT_CMD);
		*pkt->pkt_scbp = 0;
		ret = TRAN_ACCEPT;
		if (!(pkt->pkt_flags & FLAG_NOINTR))
			(*pkt->pkt_comp)(pkt);
		break;

	case SCMD_READ_CAPACITY: /* read capacity */
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			struct scsi_capacity cp;

			capacity = softs->logic_drive[ap->a_target].al_size - 1;
			cp.capacity = BE_32(capacity);
			cp.lbasize = BE_32(512);

			amr_unmapcmd(ac);

			if (bp->b_flags & (B_PHYS | B_PAGEIO))
				bp_mapin(bp);
			bcopy(&cp, bp->b_un.b_addr, 8);
		}
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= (STATE_GOT_BUS
		    | STATE_GOT_TARGET
		    | STATE_SENT_CMD
		    | STATE_XFERRED_DATA);
		*pkt->pkt_scbp = 0;
		ret = TRAN_ACCEPT;
		if (!(pkt->pkt_flags & FLAG_NOINTR))
			(*pkt->pkt_comp)(pkt);
		break;

	case SCMD_MODE_SENSE:		/* mode sense */
	case SCMD_MODE_SENSE_G1:	/* mode sense g1 */
		amr_unmapcmd(ac);

		capacity = softs->logic_drive[ap->a_target].al_size - 1;
		amr_mode_sense(cdbp, bp, capacity);

		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= (STATE_GOT_BUS
		    | STATE_GOT_TARGET
		    | STATE_SENT_CMD
		    | STATE_XFERRED_DATA);
		*pkt->pkt_scbp = 0;
		ret = TRAN_ACCEPT;
		if (!(pkt->pkt_flags & FLAG_NOINTR))
			(*pkt->pkt_comp)(pkt);
		break;

	case SCMD_TEST_UNIT_READY:	/* test unit ready */
	case SCMD_REQUEST_SENSE:	/* request sense */
	case SCMD_FORMAT:		/* format */
	case SCMD_START_STOP:		/* start stop */
	case SCMD_SYNCHRONIZE_CACHE:	/* synchronize cache */
		if (bp && bp->b_un.b_addr && bp->b_bcount) {
			amr_unmapcmd(ac);

			if (bp->b_flags & (B_PHYS | B_PAGEIO))
				bp_mapin(bp);
			bzero(bp->b_un.b_addr, bp->b_bcount);

			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= (STATE_GOT_BUS
		    | STATE_GOT_TARGET
		    | STATE_SENT_CMD);
		ret = TRAN_ACCEPT;
		*pkt->pkt_scbp = 0;
		if (!(pkt->pkt_flags & FLAG_NOINTR))
			(*pkt->pkt_comp)(pkt);
		break;

	default: /* any other commands */
		amr_unmapcmd(ac);
		pkt->pkt_reason = CMD_INCOMPLETE;
		pkt->pkt_state = (STATE_GOT_BUS
		    | STATE_GOT_TARGET
		    | STATE_SENT_CMD
		    | STATE_GOT_STATUS
		    | STATE_ARQ_DONE);
		ret = TRAN_ACCEPT;
		*pkt->pkt_scbp = 0;
		amr_set_arq_data(pkt, KEY_ILLEGAL_REQUEST);
		if (!(pkt->pkt_flags & FLAG_NOINTR))
			(*pkt->pkt_comp)(pkt);
		break;
	}

	return (ret);
}

/*
 * tran_reset() will reset the bus/target/adapter to support the fault recovery
 * functionality according to the "level" in interface. However, we got the
 * confirmation from LSI that these HBA cards does not support any commands to
 * reset bus/target/adapter/channel.
 *
 * If the tran_reset() return a FAILURE to the sd, the system will not
 * continue to dump the core. But core dump is an crucial method to analyze
 * problems in panic. Now we adopt a work around solution, that is to return
 * a fake SUCCESS to sd during panic, which will force the system continue
 * to dump core though the core may have problems in some situtation because
 * some on-the-fly commands will continue DMAing data to the memory.
 * In addition, the work around core dump method may not be performed
 * successfully if the panic is caused by the HBA itself. So the work around
 * solution is not a good example for the implementation of tran_reset(),
 * the most reasonable approach should send a reset command to the adapter.
 */
/*ARGSUSED*/
static int
amr_tran_reset(struct scsi_address *ap, int level)
{
	struct amr_softs	*softs;
	volatile uint32_t	done_flag;

	if (ddi_in_panic()) {
		softs = (struct amr_softs *)(ap->a_hba_tran->tran_hba_private);

		/* Acknowledge the card if there are any significant commands */
		while (softs->amr_busyslots > 0) {
			AMR_DELAY((softs->mailbox->mb_busy == 0),
			    AMR_RETRYCOUNT, done_flag);
			if (!done_flag) {
				/*
				 * command not completed, indicate the
				 * problem and continue get ac
				 */
				cmn_err(CE_WARN,
				    "AMR command is not completed");
				return (0);
			}

			AMR_QPUT_IDB(softs, softs->mbox_phyaddr | AMR_QIDB_ACK);

			/* wait for the acknowledge from hardware */
			AMR_BUSYWAIT(!(AMR_QGET_IDB(softs) & AMR_QIDB_ACK),
			    AMR_RETRYCOUNT, done_flag);
			if (!done_flag) {
				/*
				 * command is not completed, return from the
				 * current interrupt and wait for the next one
				 */
				cmn_err(CE_WARN, "No answer from the hardware");

				mutex_exit(&softs->cmd_mutex);
				return (0);
			}

			softs->amr_busyslots -= softs->mailbox->mb_nstatus;
		}

		/* flush the controllor */
		(void) amr_flush(softs);

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
		cmn_err(CE_WARN, "This system contains a SCSI HBA card/driver "
		    "that doesn't support software reset. This "
		    "means that memory being used by the HBA for "
		    "DMA based reads could have been updated after "
		    "we panic'd.");
		return (1);
	} else {
		/* return failure to sd */
		return (0);
	}
}

/*ARGSUSED*/
static int
amr_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	struct amr_softs	*softs;

	/*
	 * We don't allow inquiring about capabilities for other targets
	 */
	if (cap == NULL || whom == 0)
		return (-1);

	softs = ((struct amr_softs *)(ap->a_hba_tran)->tran_hba_private);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		return (1);
	case SCSI_CAP_GEOMETRY:
		return ((AMR_DEFAULT_HEADS << 16) | AMR_DEFAULT_CYLINDERS);
	case SCSI_CAP_SECTOR_SIZE:
		return (AMR_DEFAULT_SECTORS);
	case SCSI_CAP_TOTAL_SECTORS:
		/* number of sectors */
		return (softs->logic_drive[ap->a_target].al_size);
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		return (1);
	default:
		return (-1);
	}
}

/*ARGSUSED*/
static int
amr_tran_setcap(struct scsi_address *ap, char *cap, int value,
		int whom)
{
	/*
	 * We don't allow setting capabilities for other targets
	 */
	if (cap == NULL || whom == 0) {
		AMRDB_PRINT((CE_NOTE,
		    "Set Cap not supported, string = %s, whom=%d",
		    cap, whom));
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		return (1);
	case SCSI_CAP_TOTAL_SECTORS:
		return (1);
	case SCSI_CAP_SECTOR_SIZE:
		return (1);
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_TAGGED_QING:
		return ((value == 1) ? 1 : 0);
	default:
		return (0);
	}
}

static struct scsi_pkt *
amr_tran_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg)
{
	struct amr_softs	*softs;
	struct amr_command	*ac;
	uint32_t		slen;

	softs = (struct amr_softs *)(ap->a_hba_tran->tran_hba_private);

	if ((ap->a_lun != 0)||(ap->a_target >= AMR_MAXLD)||
	    (softs->logic_drive[ap->a_target].al_state ==
	    AMR_LDRV_OFFLINE)) {
		return (NULL);
	}

	if (pkt == NULL) {
		/* force auto request sense */
		slen = MAX(statuslen, sizeof (struct scsi_arq_status));

		pkt = scsi_hba_pkt_alloc(softs->dev_info_p, ap, cmdlen,
		    slen, tgtlen, sizeof (struct amr_command),
		    callback, arg);
		if (pkt == NULL) {
			AMRDB_PRINT((CE_WARN, "scsi_hba_pkt_alloc failed"));
			return (NULL);
		}
		pkt->pkt_address	= *ap;
		pkt->pkt_comp		= (void (*)())NULL;
		pkt->pkt_time		= 0;
		pkt->pkt_resid		= 0;
		pkt->pkt_statistics	= 0;
		pkt->pkt_reason		= 0;

		ac = (struct amr_command *)pkt->pkt_ha_private;
		ac->ac_buf = bp;
		ac->cmdlen = cmdlen;
		ac->ac_softs = softs;
		ac->pkt = pkt;
		ac->ac_flags &= ~AMR_CMD_GOT_SLOT;
		ac->ac_flags &= ~AMR_CMD_BUSY;

		if ((bp == NULL) || (bp->b_bcount == 0)) {
			return (pkt);
		}

		if (ddi_dma_alloc_handle(softs->dev_info_p, &buffer_dma_attr,
		    DDI_DMA_SLEEP, NULL,
		    &ac->buffer_dma_handle) != DDI_SUCCESS) {

			AMRDB_PRINT((CE_WARN,
			    "Cannot allocate buffer DMA tag"));
			scsi_hba_pkt_free(ap, pkt);
			return (NULL);

		}

	} else {
		if ((bp == NULL) || (bp->b_bcount == 0)) {
			return (pkt);
		}
		ac = (struct amr_command *)pkt->pkt_ha_private;
	}

	ASSERT(ac != NULL);

	if (bp->b_flags & B_READ) {
		ac->ac_flags |= AMR_CMD_DATAOUT;
	} else {
		ac->ac_flags |= AMR_CMD_DATAIN;
	}

	if (flags & PKT_CONSISTENT) {
		ac->ac_flags |= AMR_CMD_PKT_CONSISTENT;
	}

	if (flags & PKT_DMA_PARTIAL) {
		ac->ac_flags |= AMR_CMD_PKT_DMA_PARTIAL;
	}

	if (amr_mapcmd(ac, callback, arg) != DDI_SUCCESS) {
		scsi_hba_pkt_free(ap, pkt);
		return (NULL);
	}

	pkt->pkt_resid = bp->b_bcount - ac->data_transfered;

	AMRDB_PRINT((CE_NOTE,
	    "init pkt, pkt_resid=%d, b_bcount=%d, data_transfered=%d",
	    (uint32_t)pkt->pkt_resid, (uint32_t)bp->b_bcount,
	    ac->data_transfered));

	ASSERT(pkt->pkt_resid >= 0);

	return (pkt);
}

static void
amr_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct amr_command *ac = (struct amr_command *)pkt->pkt_ha_private;

	amr_unmapcmd(ac);

	if (ac->buffer_dma_handle) {
		(void) ddi_dma_free_handle(&ac->buffer_dma_handle);
		ac->buffer_dma_handle = NULL;
	}

	scsi_hba_pkt_free(ap, pkt);
	AMRDB_PRINT((CE_NOTE, "Destroy pkt called"));
}

/*ARGSUSED*/
static void
amr_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct amr_command *ac = (struct amr_command *)pkt->pkt_ha_private;

	if (ac->buffer_dma_handle) {
		(void) ddi_dma_sync(ac->buffer_dma_handle, 0, 0,
		    (ac->ac_flags & AMR_CMD_DATAIN) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
	}
}

/*ARGSUSED*/
static void
amr_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct amr_command *ac = (struct amr_command *)pkt->pkt_ha_private;

	if (ac->ac_flags & AMR_CMD_MAPPED) {
		(void) ddi_dma_unbind_handle(ac->buffer_dma_handle);
		(void) ddi_dma_free_handle(&ac->buffer_dma_handle);
		ac->buffer_dma_handle = NULL;
		ac->ac_flags &= ~AMR_CMD_MAPPED;
	}

}

/*ARGSUSED*/
static void
amr_rw_command(struct amr_softs *softs, struct scsi_pkt *pkt, int target)
{
	struct amr_command	*ac = (struct amr_command *)pkt->pkt_ha_private;
	union scsi_cdb		*cdbp = (union scsi_cdb *)pkt->pkt_cdbp;
	uint8_t			cmd;

	if (ac->ac_flags & AMR_CMD_DATAOUT) {
		cmd = AMR_CMD_LREAD;
	} else {
		cmd = AMR_CMD_LWRITE;
	}

	ac->mailbox.mb_command = cmd;
	ac->mailbox.mb_blkcount =
	    (ac->transfer_size + AMR_BLKSIZE - 1)/AMR_BLKSIZE;
	ac->mailbox.mb_lba = (ac->cmdlen == 10) ?
	    GETG1ADDR(cdbp) : GETG0ADDR(cdbp);
	ac->mailbox.mb_drive = (uint8_t)target;
}

static void
amr_mode_sense(union scsi_cdb *cdbp, struct buf *bp, unsigned int capacity)
{
	uchar_t			pagecode;
	struct mode_format	*page3p;
	struct mode_geometry	*page4p;
	struct mode_header	*headerp;
	uint32_t		ncyl;

	if (!(bp && bp->b_un.b_addr && bp->b_bcount))
		return;

	if (bp->b_flags & (B_PHYS | B_PAGEIO))
		bp_mapin(bp);

	pagecode = cdbp->cdb_un.sg.scsi[0];
	switch (pagecode) {
	case SD_MODE_SENSE_PAGE3_CODE:
		headerp = (struct mode_header *)(bp->b_un.b_addr);
		headerp->bdesc_length = MODE_BLK_DESC_LENGTH;

		page3p = (struct mode_format *)((caddr_t)headerp +
		    MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
		page3p->mode_page.code = BE_8(SD_MODE_SENSE_PAGE3_CODE);
		page3p->mode_page.length = BE_8(sizeof (struct mode_format));
		page3p->data_bytes_sect = BE_16(AMR_DEFAULT_SECTORS);
		page3p->sect_track = BE_16(AMR_DEFAULT_CYLINDERS);

		return;

	case SD_MODE_SENSE_PAGE4_CODE:
		headerp = (struct mode_header *)(bp->b_un.b_addr);
		headerp->bdesc_length = MODE_BLK_DESC_LENGTH;

		page4p = (struct mode_geometry *)((caddr_t)headerp +
		    MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
		page4p->mode_page.code = BE_8(SD_MODE_SENSE_PAGE4_CODE);
		page4p->mode_page.length = BE_8(sizeof (struct mode_geometry));
		page4p->heads = BE_8(AMR_DEFAULT_HEADS);
		page4p->rpm = BE_16(AMR_DEFAULT_ROTATIONS);

		ncyl = capacity / (AMR_DEFAULT_HEADS*AMR_DEFAULT_CYLINDERS);
		page4p->cyl_lb = BE_8(ncyl & 0xff);
		page4p->cyl_mb = BE_8((ncyl >> 8) & 0xff);
		page4p->cyl_ub = BE_8((ncyl >> 16) & 0xff);

		return;
	default:
		bzero(bp->b_un.b_addr, bp->b_bcount);
		return;
	}
}

static void
amr_set_arq_data(struct scsi_pkt *pkt, uchar_t key)
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

static void
amr_start_waiting_queue(void *softp)
{
	uint32_t		slot;
	struct amr_command	*ac;
	volatile uint32_t	done_flag;
	struct amr_softs	*softs = (struct amr_softs *)softp;

	/* only one command allowed at the same time */
	mutex_enter(&softs->queue_mutex);
	mutex_enter(&softs->cmd_mutex);

	while ((ac = softs->waiting_q_head) != NULL) {
		/*
		 * Find an available slot, the last slot is
		 * occupied by poll I/O command.
		 */
		for (slot = 0; slot < (softs->sg_max_count - 1); slot++) {
			if (softs->busycmd[slot] == NULL) {
				if (AMR_QGET_IDB(softs) & AMR_QIDB_SUBMIT) {
					/*
					 * only one command allowed at the
					 * same time
					 */
					mutex_exit(&softs->cmd_mutex);
					mutex_exit(&softs->queue_mutex);
					return;
				}

				ac->ac_timestamp = ddi_get_time();

				if (!(ac->ac_flags & AMR_CMD_GOT_SLOT)) {

					softs->busycmd[slot] = ac;
					ac->ac_slot = slot;
					softs->amr_busyslots++;

					bcopy(ac->sgtable,
					    softs->sg_items[slot].sg_table,
					    sizeof (struct amr_sgentry) *
					    AMR_NSEG);

					(void) ddi_dma_sync(
					    softs->sg_items[slot].sg_handle,
					    0, 0, DDI_DMA_SYNC_FORDEV);

					ac->mailbox.mb_physaddr =
					    softs->sg_items[slot].sg_phyaddr;
				}

				/* take the cmd from the queue */
				softs->waiting_q_head = ac->ac_next;

				ac->mailbox.mb_ident = ac->ac_slot + 1;
				ac->mailbox.mb_busy = 1;
				ac->ac_next = NULL;
				ac->ac_prev = NULL;
				ac->ac_flags |= AMR_CMD_GOT_SLOT;

				/* clear the poll/ack fields in the mailbox */
				softs->mailbox->mb_poll = 0;
				softs->mailbox->mb_ack = 0;

				AMR_DELAY((softs->mailbox->mb_busy == 0),
				    AMR_RETRYCOUNT, done_flag);
				if (!done_flag) {
					/*
					 * command not completed, indicate the
					 * problem and continue get ac
					 */
					cmn_err(CE_WARN,
					    "AMR command is not completed");
					break;
				}

				bcopy(&ac->mailbox, (void *)softs->mailbox,
				    AMR_MBOX_CMDSIZE);
				ac->ac_flags |= AMR_CMD_BUSY;

				(void) ddi_dma_sync(softs->mbox_dma_handle,
				    0, 0, DDI_DMA_SYNC_FORDEV);

				AMR_QPUT_IDB(softs,
				    softs->mbox_phyaddr | AMR_QIDB_SUBMIT);

				/*
				 * current ac is submitted
				 * so quit 'for-loop' to get next ac
				 */
				break;
			}
		}

		/* no slot, finish our task */
		if (slot == softs->maxio)
			break;
	}

	/* only one command allowed at the same time */
	mutex_exit(&softs->cmd_mutex);
	mutex_exit(&softs->queue_mutex);
}

static void
amr_done(struct amr_softs *softs)
{

	uint32_t		i, idx;
	volatile uint32_t	done_flag;
	struct amr_mailbox	*mbox, mbsave;
	struct amr_command	*ac, *head, *tail;

	head = tail = NULL;

	AMR_QPUT_ODB(softs, AMR_QODB_READY);

	/* acknowledge interrupt */
	(void) AMR_QGET_ODB(softs);

	mutex_enter(&softs->cmd_mutex);

	if (softs->mailbox->mb_nstatus != 0) {
		(void) ddi_dma_sync(softs->mbox_dma_handle,
		    0, 0, DDI_DMA_SYNC_FORCPU);

		/* save mailbox, which contains a list of completed commands */
		bcopy((void *)(uintptr_t)(volatile void *)softs->mailbox,
		    &mbsave, sizeof (mbsave));

		mbox = &mbsave;

		AMR_QPUT_IDB(softs, softs->mbox_phyaddr | AMR_QIDB_ACK);

		/* wait for the acknowledge from hardware */
		AMR_BUSYWAIT(!(AMR_QGET_IDB(softs) & AMR_QIDB_ACK),
		    AMR_RETRYCOUNT, done_flag);
		if (!done_flag) {
			/*
			 * command is not completed, return from the current
			 * interrupt and wait for the next one
			 */
			cmn_err(CE_WARN, "No answer from the hardware");

			mutex_exit(&softs->cmd_mutex);
			return;
		}

		for (i = 0; i < mbox->mb_nstatus; i++) {
			idx = mbox->mb_completed[i] - 1;
			ac = softs->busycmd[idx];

			if (ac != NULL) {
				/* pull the command from the busy index */
				softs->busycmd[idx] = NULL;
				if (softs->amr_busyslots > 0)
					softs->amr_busyslots--;
				if (softs->amr_busyslots == 0)
					cv_broadcast(&softs->cmd_cv);

				ac->ac_flags &= ~AMR_CMD_BUSY;
				ac->ac_flags &= ~AMR_CMD_GOT_SLOT;
				ac->ac_status = mbox->mb_status;

				/* enqueue here */
				if (head) {
					tail->ac_next = ac;
					tail = ac;
					tail->ac_next = NULL;
				} else {
					tail = head = ac;
					ac->ac_next = NULL;
				}
			} else {
				AMRDB_PRINT((CE_WARN,
				    "ac in mailbox is NULL!"));
			}
		}
	} else {
		AMRDB_PRINT((CE_WARN, "mailbox is not ready for copy out!"));
	}

	mutex_exit(&softs->cmd_mutex);

	if (head != NULL) {
		amr_call_pkt_comp(head);
	}

	/* dispatch a thread to process the pending I/O if there is any */
	if ((ddi_taskq_dispatch(softs->amr_taskq, amr_start_waiting_queue,
	    (void *)softs, DDI_NOSLEEP)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "No memory available to dispatch taskq");
	}
}

static void
amr_call_pkt_comp(register struct amr_command *head)
{
	register struct scsi_pkt	*pkt;
	register struct amr_command	*ac, *localhead;

	localhead = head;

	while (localhead) {
		ac = localhead;
		localhead = ac->ac_next;
		ac->ac_next = NULL;

		pkt = ac->pkt;
		*pkt->pkt_scbp = 0;

		if (ac->ac_status == AMR_STATUS_SUCCESS) {
			pkt->pkt_state |= (STATE_GOT_BUS
			    | STATE_GOT_TARGET
			    | STATE_SENT_CMD
			    | STATE_XFERRED_DATA);
			pkt->pkt_reason = CMD_CMPLT;
		} else {
			pkt->pkt_state |= STATE_GOT_BUS
			    | STATE_ARQ_DONE;
			pkt->pkt_reason = CMD_INCOMPLETE;
			amr_set_arq_data(pkt, KEY_HARDWARE_ERROR);
		}

		if (!(pkt->pkt_flags & FLAG_NOINTR) &&
		    pkt->pkt_comp) {
			(*pkt->pkt_comp)(pkt);
		}
	}
}
