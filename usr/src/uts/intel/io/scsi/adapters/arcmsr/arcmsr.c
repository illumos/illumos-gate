/*
 *       O.S   : Solaris
 *  FILE NAME  : arcmsr.c
 *       BY    : Erich Chen
 *  Description: SCSI RAID Device Driver for
 *               ARECA RAID Host adapter
 *
 *  Copyright (C) 2002,2007 Areca Technology Corporation All rights reserved.
 *  Copyright (C) 2002,2007 Erich Chen
 *	    Web site: www.areca.com.tw
 *	      E-mail: erich@areca.com.tw
 *
 *	Redistribution and use in source and binary forms, with or without
 *	modification, are permitted provided that the following conditions
 *	are met:
 *	1. Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	2. Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *  3. The party using or redistributing the source code and binary forms
 *     agrees to the disclaimer below and the terms and conditions set forth
 *     herein.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ddidmareq.h>
#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/signal.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/policy.h>

#include "arcmsr.h"

static int arcmsr_attach(dev_info_t *dev_info, ddi_attach_cmd_t cmd);
static int arcmsr_cb_ioctl(dev_t dev, int ioctl_cmd, intptr_t arg,
    int mode, cred_t *credp, int *rvalp);
static int arcmsr_detach(dev_info_t *dev_info, ddi_detach_cmd_t cmd);
static int arcmsr_reset(dev_info_t *resetdev, ddi_reset_cmd_t cmd);
static int arcmsr_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int arcmsr_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int arcmsr_tran_reset(struct scsi_address *ap, int level);
static int arcmsr_tran_getcap(struct scsi_address *ap, char *cap, int whom);
static int arcmsr_tran_setcap(struct scsi_address *ap, char *cap, int value,
    int whom);
static int arcmsr_tran_tgt_init(dev_info_t *host_dev_info,
    dev_info_t *target_dev_info, scsi_hba_tran_t *hosttran,
    struct scsi_device *sd);
static void arcmsr_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt);
static void arcmsr_tran_destroy_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static void arcmsr_tran_sync_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static struct scsi_pkt *arcmsr_tran_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg);

static uint_t arcmsr_interrupt(caddr_t arg);
static int arcmsr_initialize(struct ACB *acb);
static int arcmsr_dma_alloc(struct ACB *acb,
    struct scsi_pkt *pkt, struct buf *bp, int flags, int (*callback)());
static int arcmsr_dma_move(struct ACB *acb,
    struct scsi_pkt *pkt, struct buf *bp);
static void arcmsr_pcidev_disattach(struct ACB *acb);
static void arcmsr_ccb_complete(struct CCB *ccb, int flag);
static void arcmsr_iop_init(struct ACB *acb);
static void arcmsr_iop_parking(struct ACB *acb);
static void arcmsr_log(struct ACB *acb, int level, char *fmt, ...);
static struct CCB *arcmsr_get_freeccb(struct ACB *acb);
static void arcmsr_flush_hba_cache(struct ACB *acb);
static void arcmsr_flush_hbb_cache(struct ACB *acb);
static void arcmsr_stop_hba_bgrb(struct ACB *acb);
static void arcmsr_stop_hbb_bgrb(struct ACB *acb);
static void arcmsr_start_hba_bgrb(struct ACB *acb);
static void arcmsr_start_hba_bgrb(struct ACB *acb);
static void arcmsr_polling_hba_ccbdone(struct ACB *acb, struct CCB *poll_ccb);
static void arcmsr_polling_hbb_ccbdone(struct ACB *acb, struct CCB *poll_ccb);
static void arcmsr_build_ccb(struct CCB *ccb);


static struct ACB *ArcMSRHBA[ARCMSR_MAX_ADAPTER];
static int arcmsr_hba_count;
static void *arcmsr_soft_state = NULL;
static kmutex_t arcmsr_global_mutex;

static ddi_dma_attr_t arcmsr_dma_attr = {
	DMA_ATTR_V0,		/* ddi_dma_attr version */
	0,			/* low DMA address range */
	0xffffffff,		/* high DMA address range */
	0x00ffffff,		/* DMA counter counter upper bound */
	1,			/* DMA address alignment requirements */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,	/* burst sizes */
	1,			/* minimum effective DMA size */
	ARCMSR_MAX_XFER_LEN,	/* maximum DMA xfer size */
	/*
	 * The dma_attr_seg field supplies the limit of each Scatter/Gather
	 * list element's "address+length". The Intel IOP331 can not use
	 * segments over the 4G boundary due to segment boundary restrictions
	 */
	0x00ffffff,
	ARCMSR_MAX_SG_ENTRIES,	/* scatter/gather list count */
	1, 			/* device granularity */
	DDI_DMA_FORCE_PHYSICAL	/* Bus specific DMA flags */
};

static ddi_dma_attr_t arcmsr_ccb_attr = {
	DMA_ATTR_V0,	/* ddi_dma_attr version */
	0,		/* low DMA address range */
	0xffffffff,	/* high DMA address range */
	0x00ffffff,	/* DMA counter counter upper bound */
	1,		/* default byte alignment */
	DEFAULT_BURSTSIZE | BURST32 | BURST64,   /* burst sizes */
	1,		/* minimum effective DMA size */
	0xffffffff,	/* maximum DMA xfer size */
	0x00ffffff,	/* max segment size, segment boundary restrictions */
	1,		/* scatter/gather list count */
	1,		/* device granularity */
	DDI_DMA_FORCE_PHYSICAL	/* Bus specific DMA flags */
};

static struct cb_ops arcmsr_cb_ops = {
	scsi_hba_open,		/* open(9E) */
	scsi_hba_close,		/* close(9E) */
	nodev,			/* strategy(9E), returns ENXIO */
	nodev,			/* print(9E) */
	nodev,			/* dump(9E) Cannot be used as a dump device */
	nodev,			/* read(9E) */
	nodev,			/* write(9E) */
	arcmsr_cb_ioctl,	/* ioctl(9E) */
	nodev,			/* devmap(9E) */
	nodev,			/* mmap(9E) */
	nodev,			/* segmap(9E) */
	NULL,			/* chpoll(9E) returns ENXIO */
	nodev,			/* prop_op(9E) */
	NULL,			/* streamtab(9S) */
#ifdef _LP64
	/*
	 * cb_ops cb_flag:
	 *	D_NEW | D_MP	compatibility flags, see conf.h
	 *	D_MP 		flag indicates that the driver is safe for
	 *			multi-threaded operation
	 *	D_64BIT		flag driver properly handles 64-bit offsets
	 */
	D_HOTPLUG | D_MP | D_64BIT,
#else
	D_HOTPLUG | D_MP,
#endif
	CB_REV,
	nodev,			/* aread(9E) */
	nodev			/* awrite(9E) */
};

static struct dev_ops arcmsr_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* reference count */
	nodev,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	arcmsr_attach,		/* attach */
	arcmsr_detach,		/* detach */
	arcmsr_reset,		/* reset, shutdown, reboot notify */
	&arcmsr_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nulldev			/* power */
};

char _depends_on[] = "misc/scsi";

static struct modldrv arcmsr_modldrv = {
	&mod_driverops, 	/* Type of module. This is a driver. */
	ARCMSR_DRIVER_VERSION,  /* module name, from arcmsr.h */
	&arcmsr_ops,		/* driver ops */
};

static struct modlinkage arcmsr_modlinkage = {
	MODREV_1,
	&arcmsr_modldrv,
	NULL
};


int
_init(void) {
	int ret;


	mutex_init(&arcmsr_global_mutex, "arcmsr global mutex",
	    MUTEX_DRIVER, NULL);
	ret = ddi_soft_state_init(&arcmsr_soft_state,
	    sizeof (struct ACB), ARCMSR_MAX_ADAPTER);
	if (ret != 0) {
		return (ret);
	}
	if ((ret = scsi_hba_init(&arcmsr_modlinkage)) != 0) {
		ddi_soft_state_fini(&arcmsr_soft_state);
		return (ret);
	}

	if ((ret = mod_install(&arcmsr_modlinkage)) != 0) {
		mutex_destroy(&arcmsr_global_mutex);
		scsi_hba_fini(&arcmsr_modlinkage);
		if (arcmsr_soft_state != NULL) {
			ddi_soft_state_fini(&arcmsr_soft_state);
		}
	}
	return (ret);
}


int
_fini(void) {
	int ret;

	ret = mod_remove(&arcmsr_modlinkage);
	if (ret == 0) {
		/* if ret = 0 , said driver can remove */
		mutex_destroy(&arcmsr_global_mutex);
		scsi_hba_fini(&arcmsr_modlinkage);
		if (arcmsr_soft_state != NULL) {
			ddi_soft_state_fini(&arcmsr_soft_state);
		}
	}
	return (ret);
}


int
_info(struct modinfo *modinfop) {
	return (mod_info(&arcmsr_modlinkage, modinfop));
}



#if defined(ARCMSR_DEBUG)
static void
arcmsr_dump_scsi_cdb(struct scsi_address *ap, struct scsi_pkt *pkt) {

	static char hex[] = "0123456789abcdef";
	struct ACB *acb =
	    (struct ACB *)ap->a_hba_tran->tran_hba_private;
	struct CCB *ccb =
	    (struct CCB *)pkt->pkt_ha_private;
	uint8_t	*cdb = pkt->pkt_cdbp;
	char buf [256];
	char *p;
	int i;


	(void) sprintf(buf, "arcmsr%d: sgcount=%d <%d, %d> "
	    "cdb ",
	    ddi_get_instance(acb->dev_info), ccb->arcmsr_cdb.sgcount,
	    ap->a_target, ap->a_lun);

	p = buf + strlen(buf);
	*p++ = '[';

	for (i = 0; i < ccb->arcmsr_cdb.CdbLength; i++, cdb++) {
		if (i != 0) {
			*p++ = ' ';
		}
		*p++ = hex[(*cdb >> 4) & 0x0f];
		*p++ = hex[*cdb & 0x0f];
	}
	*p++ = ']';
	*p++ = '.';
	*p = 0;
	cmn_err(CE_CONT, buf);
}
#endif  /* ARCMSR_DEBUG */

static void
arcmsr_ccbs_timeout(void* arg) {

	struct ACB *acb = (struct ACB *)arg;
	struct CCB *ccb;
	int i;
	int current_time = ddi_get_time();


	if (acb->ccboutstandingcount != 0) {
		/* check each ccb */
		i = ddi_dma_sync(acb->ccbs_pool_handle, 0,
		    acb->dma_sync_size, DDI_DMA_SYNC_FORKERNEL);
		if (i != DDI_SUCCESS) {
			if ((acb->timeout_id != 0) &&
			    ((acb->acb_flags & ACB_F_SCSISTOPADAPTER) == 0)) {
				/* do pkt timeout check each 60 secs */
				acb->timeout_id = timeout(arcmsr_ccbs_timeout,
				    (void*)acb,
				    (60 * drv_usectohz(1000000)));
			}
			return;
		}
		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->acb != acb) {
				break;
			}
			if (ccb->startdone == ARCMSR_CCB_DONE) {
				continue;
			}
			if (ccb->pkt == NULL) {
				continue;
			}
			if (ccb->pkt->pkt_time == 0) {
				continue;
			}
			if ((int)ccb->ccb_time >= current_time) {
				continue;
			}
			if (ccb->startdone == ARCMSR_CCB_START) {
				int id = ccb->pkt->pkt_address.a_target;
				int lun = ccb->pkt->pkt_address.a_lun;

				/*
				 * handle outstanding command of timeout ccb
				 */
				ccb->pkt->pkt_reason = CMD_TIMEOUT;
				ccb->pkt->pkt_statistics = STAT_TIMEOUT;

				cmn_err(CE_CONT,
				    "arcmsr%d: scsi target %d lun %d "
				    "outstanding command timeout",
				    ddi_get_instance(acb->dev_info),
				    id, lun);
				cmn_err(CE_CONT,
				    "arcmsr%d: scsi target %d lun %d "
				    "fatal error on target, device is gone",
				    ddi_get_instance(acb->dev_info),
				    id, lun);
				acb->devstate[id][lun] = ARECA_RAID_GONE;
				arcmsr_ccb_complete(ccb, 1);
				continue;
			}
			ccb->ccb_time = (time_t)(ccb->pkt->pkt_time +
			    current_time); /* adjust ccb_time of pending ccb */
		}
	}
	if ((acb->timeout_id != 0) &&
	    ((acb->acb_flags & ACB_F_SCSISTOPADAPTER) == 0)) {
		/* do pkt timeout check each 60 secs */
		acb->timeout_id = timeout(arcmsr_ccbs_timeout,
		    (void*)acb, (60 * drv_usectohz(1000000)));
	}
}


static uint32_t
arcmsr_disable_allintr(struct ACB *acb) {

	uint32_t intmask_org;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A: {
		struct HBA_msgUnit *phbamu =
		    (struct HBA_msgUnit *)acb->pmu;

		/* disable all outbound interrupt */
		/* disable outbound message0 int */
		intmask_org = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intmask) |
		    ARCMSR_MU_OUTBOUND_MESSAGE0_INTMASKENABLE;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intmask,
		    intmask_org|ARCMSR_MU_OUTBOUND_ALL_INTMASKENABLE);
		}
		break;
	case ACB_ADAPTER_TYPE_B: {
		struct HBB_msgUnit *phbbmu =
		    (struct HBB_msgUnit *)acb->pmu;

		/* disable all outbound interrupt */
		/* disable outbound message0 int */
		intmask_org = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell_mask) &
		    (~ARCMSR_IOP2DRV_MESSAGE_CMD_DONE);
		/* disable all interrupts */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell_mask, 0);
		}
		break;
	}
	return (intmask_org);
}


static void
arcmsr_enable_allintr(struct ACB *acb, uint32_t intmask_org) {

	int mask;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A: {
		struct HBA_msgUnit *phbamu =
		    (struct HBA_msgUnit *)acb->pmu;

		/* enable outbound Post Queue, outbound doorbell Interrupt */
		mask = ~(ARCMSR_MU_OUTBOUND_POSTQUEUE_INTMASKENABLE |
		    ARCMSR_MU_OUTBOUND_DOORBELL_INTMASKENABLE);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intmask, intmask_org & mask);
		acb->outbound_int_enable = ~(intmask_org & mask) & 0x000000ff;
		}
		break;
	case ACB_ADAPTER_TYPE_B: {
		struct HBB_msgUnit *phbbmu =
		    (struct HBB_msgUnit *)acb->pmu;

		/* disable ARCMSR_IOP2DRV_MESSAGE_CMD_DONE */
		mask = (ARCMSR_IOP2DRV_DATA_WRITE_OK |
		    ARCMSR_IOP2DRV_DATA_READ_OK | ARCMSR_IOP2DRV_CDB_DONE);
		/* 1=interrupt enable, 0=interrupt disable */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell_mask,
		    intmask_org | mask);
		acb->outbound_int_enable = (intmask_org | mask) & 0x0000000f;
		}
		break;
	}
}


static void
arcmsr_iop_parking(struct ACB *acb) {

	if (acb != NULL) {
		/* stop adapter background rebuild */
		if (acb->acb_flags & ACB_F_MSG_START_BGRB) {
			uint32_t intmask_org;

			acb->acb_flags &= ~ACB_F_MSG_START_BGRB;
			/* disable all outbound interrupt */
			intmask_org = arcmsr_disable_allintr(acb);
			if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
				arcmsr_stop_hba_bgrb(acb);
				arcmsr_flush_hba_cache(acb);
			} else {
				arcmsr_stop_hbb_bgrb(acb);
				arcmsr_flush_hbb_cache(acb);
			}
			/*
			 * enable outbound Post Queue
			 * enable outbound doorbell Interrupt
			 */
			arcmsr_enable_allintr(acb, intmask_org);
		}
	}
}



static int
arcmsr_reset(dev_info_t *resetdev, ddi_reset_cmd_t cmd) {

	struct ACB *acb;
	scsi_hba_tran_t *scsi_hba_transport;

	scsi_hba_transport = (scsi_hba_tran_t *)
	    ddi_get_driver_private(resetdev);

	if (!scsi_hba_transport)
		return (DDI_FAILURE);

	acb = (struct ACB *)
	    scsi_hba_transport->tran_hba_private;

	if (!acb)
		return (DDI_FAILURE);

	if ((cmd == RESET_LUN) ||
	    (cmd == RESET_BUS) ||
	    (cmd == RESET_TARGET))
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: reset op (%d) not supported",
		    ddi_get_instance(resetdev), cmd);

	arcmsr_pcidev_disattach(acb);

	return (DDI_SUCCESS);
}

static int
arcmsr_do_ddi_attach(dev_info_t *dev_info, int instance) {

	scsi_hba_tran_t *hba_trans;
	ddi_device_acc_attr_t dev_acc_attr;
	struct ACB *acb;
	static char buf[256];
	uint16_t wval;
	int raid6 = 1;
	char *type;

	/*
	 * Soft State Structure
	 * The driver should allocate the per-device-instance
	 * soft state structure, being careful to clean up properly if
	 * an error occurs. Allocate data structure.
	 */
	if (ddi_soft_state_zalloc(arcmsr_soft_state, instance)
	    != DDI_SUCCESS) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: ddi_soft_state_zalloc failed",
		    instance);
		return (DDI_FAILURE);
	}

	acb = ddi_get_soft_state(arcmsr_soft_state, instance);
	if (acb == NULL) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: ddi_get_soft_state failed",
		    instance);
		goto error_level_1;
	}

	/* acb is already zalloc()d so we don't need to bzero() it */
	dev_acc_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_acc_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	dev_acc_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;

	acb->dev_info = dev_info;
	acb->dev_acc_attr = dev_acc_attr;

	/*
	 * The driver, if providing DMA, should also check that its hardware is
	 * installed in a DMA-capable slot
	 */
	if (ddi_slaveonly(dev_info) == DDI_SUCCESS) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: hardware is not installed in a "
		    "DMA-capable slot",
		    instance);
		goto error_level_0;
	}
	/* We do not support adapter drivers with high-level interrupts */
	if (ddi_intr_hilevel(dev_info, 0) != 0) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: high-level interrupt not supported",
		    instance);
		goto error_level_0;
	}




	if (pci_config_setup(dev_info, &acb->pci_acc_handle)
	    != DDI_SUCCESS) {
		arcmsr_log(NULL, CE_NOTE,
		    "arcmsr%d: pci_config_setup() failed, attach failed",
		    instance);
		return (DDI_PROBE_FAILURE);
	}

	wval = pci_config_get16(acb->pci_acc_handle, PCI_CONF_VENID);
	if (wval != PCI_VENDOR_ID_ARECA) {
		arcmsr_log(NULL, CE_NOTE,
		    "arcmsr%d: failing attach: 'vendorid (0x%04x) "
		    "does not match 0x%04x (PCI_VENDOR_ID_ARECA)\n",
		    instance, wval, PCI_VENDOR_ID_ARECA);
		return (DDI_PROBE_FAILURE);
	}

	wval = pci_config_get16(acb->pci_acc_handle, PCI_CONF_DEVID);
	switch (wval) {
	case PCI_DEVICE_ID_ARECA_1110:
	case PCI_DEVICE_ID_ARECA_1210:
	case PCI_DEVICE_ID_ARECA_1201:
		raid6 = 0;
		/*FALLTHRU*/
	case PCI_DEVICE_ID_ARECA_1120:
	case PCI_DEVICE_ID_ARECA_1130:
	case PCI_DEVICE_ID_ARECA_1160:
	case PCI_DEVICE_ID_ARECA_1170:
	case PCI_DEVICE_ID_ARECA_1220:
	case PCI_DEVICE_ID_ARECA_1230:
	case PCI_DEVICE_ID_ARECA_1260:
	case PCI_DEVICE_ID_ARECA_1270:
	case PCI_DEVICE_ID_ARECA_1280:
		type = "SATA";
		break;
	case PCI_DEVICE_ID_ARECA_1380:
	case PCI_DEVICE_ID_ARECA_1381:
	case PCI_DEVICE_ID_ARECA_1680:
	case PCI_DEVICE_ID_ARECA_1681:
		type = "SAS";
		break;
	default:
		type = "X-TYPE";
		break;
	}

	(void) sprintf(buf, "Areca %s Host Adapter RAID Controller%s",
	    type, raid6 ? " (RAID6 capable)" : "");
	cmn_err(CE_CONT, "arcmsr%d:%s ", instance, buf);
	cmn_err(CE_CONT, "arcmsr%d:%s ", instance, ARCMSR_DRIVER_VERSION);


	/* we disable iop interrupt here */
	if (arcmsr_initialize(acb) == DDI_FAILURE) {
		arcmsr_log(NULL, CE_WARN, "arcmsr%d: arcmsr_initialize "
		    "failed", instance);
		goto error_level_1;
	}

	/*
	 * The driver must first obtain the iblock cookie to initialize
	 * mutexes used in the driver handler. Only after those mutexes
	 * have been initialized can the interrupt handler be added.
	 */
	if (ddi_get_iblock_cookie(dev_info, 0, &acb->iblock_cookie)
	    != DDI_SUCCESS) {
		arcmsr_log(NULL, CE_WARN, "arcmsr%d: "
		    "ddi_get_iblock_cookie failed", instance);
		goto error_level_2;
	}
	mutex_init(&acb->acb_mutex, NULL, MUTEX_DRIVER,
	    (void *)acb->iblock_cookie);
	mutex_init(&acb->postq_mutex, NULL, MUTEX_DRIVER,
	    (void *)acb->iblock_cookie);
	mutex_init(&acb->workingQ_mutex, NULL, MUTEX_DRIVER,
	    (void *)acb->iblock_cookie);
	mutex_init(&acb->ioctl_mutex, NULL, MUTEX_DRIVER,
	    (void *)acb->iblock_cookie);

	/* Allocate a transport structure */
	hba_trans = scsi_hba_tran_alloc(dev_info, SCSI_HBA_CANSLEEP);
	if (hba_trans == NULL) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: scsi_hba_tran_alloc failed",
		    instance);
		goto error_level_3;
	}
	acb->scsi_hba_transport = hba_trans;
	acb->dev_info = dev_info;
	/* init scsi host adapter transport entry */
	hba_trans->tran_hba_private  = acb;
	hba_trans->tran_tgt_private  = NULL;
	/*
	 * If no per-target initialization is required, the HBA can leave
	 * tran_tgt_init set to NULL.
	 */
	hba_trans->tran_tgt_init = arcmsr_tran_tgt_init;
	hba_trans->tran_tgt_probe = scsi_hba_probe;
	hba_trans->tran_tgt_free = NULL;
	hba_trans->tran_start = arcmsr_tran_start;
	hba_trans->tran_abort = arcmsr_tran_abort;
	hba_trans->tran_reset = arcmsr_tran_reset;
	hba_trans->tran_getcap = arcmsr_tran_getcap;
	hba_trans->tran_setcap = arcmsr_tran_setcap;
	hba_trans->tran_init_pkt = arcmsr_tran_init_pkt;
	hba_trans->tran_destroy_pkt = arcmsr_tran_destroy_pkt;
	hba_trans->tran_dmafree = arcmsr_tran_dmafree;
	hba_trans->tran_sync_pkt = arcmsr_tran_sync_pkt;

	hba_trans->tran_reset_notify = NULL;
	hba_trans->tran_get_bus_addr = NULL;
	hba_trans->tran_get_name = NULL;
	hba_trans->tran_quiesce = NULL;
	hba_trans->tran_unquiesce = NULL;
	hba_trans->tran_bus_reset = NULL;
	hba_trans->tran_add_eventcall = NULL;
	hba_trans->tran_get_eventcookie = NULL;
	hba_trans->tran_post_event = NULL;
	hba_trans->tran_remove_eventcall = NULL;


	/* Adding an Interrupt Handler */
	if (ddi_add_intr(dev_info, 0, &acb->iblock_cookie, 0,
	    arcmsr_interrupt, (caddr_t)acb) != DDI_SUCCESS) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: failed to add interrupt handler",
		    instance);
		goto error_level_4;
	}
	/*
	 * The driver should attach this instance of the device, and
	 * perform error cleanup if necessary
	 */
	if (scsi_hba_attach_setup(dev_info, &arcmsr_dma_attr,
	    hba_trans, SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: scsi_hba_attach_setup failed",
		    instance);
		goto error_level_5;
	}

	/* iop init and enable interrupt here */
	mutex_enter(&arcmsr_global_mutex);
	arcmsr_iop_init(acb);
	mutex_exit(&arcmsr_global_mutex);

	/* Initialize power management bookkeeping. */
	if (pm_create_components(dev_info, 1) == DDI_SUCCESS) {
		if (pm_idle_component(dev_info, 0) == DDI_FAILURE) {
			arcmsr_log(NULL, CE_WARN,
			    "arcmsr%d: pm_idle_component fail",
			    instance);
			goto error_level_8;
		}
		pm_set_normal_power(dev_info, 0, 1);
		/* acb->power_level = 1; */
	} else {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: pm_create_components fail",
		    instance);
		goto error_level_7;
	}

	/*
	 * Since this driver manages devices with "remote" hardware, "
	 * i.e. the devices themselves have no "reg" property, the SUSPEND/
	 * RESUME commands in detach/attach will not be called by the power
	 * management framework unless we request it by creating a
	 * "pm-hardware-state" property and setting it to value
	 * "needs-suspend-resume".
	 */
	if (ddi_prop_update_string(DDI_DEV_T_NONE, dev_info,
	    "pm-hardware-state", "needs-suspend-resume")
	    != DDI_PROP_SUCCESS) {
		arcmsr_log(NULL, CE_WARN,
		    "arcmsr%d: ddi_prop_update(\"pm-hardware-state\")failed",
		    instance);
		goto error_level_8;
	}

	/* active ccbs "timeout" watchdog */
	acb->timeout_id = timeout(arcmsr_ccbs_timeout, (caddr_t)acb,
	    (60 * drv_usectohz(1000000)));
	/* report device info */
	ddi_report_dev(dev_info);
	ArcMSRHBA[arcmsr_hba_count] = acb;
	arcmsr_hba_count++;

	return (DDI_SUCCESS);

error_level_8:
	pm_destroy_components(dev_info);

error_level_7:
	/* Remove any previously allocated minor nodes */
	ddi_remove_minor_node(dev_info, NULL);

error_level_6:
	scsi_hba_tran_free(hba_trans);

error_level_5:
	ddi_remove_intr(dev_info, 0, (void *)acb->iblock_cookie);

error_level_4:
	scsi_hba_tran_free(hba_trans);

error_level_3:
	mutex_destroy(&acb->acb_mutex);
	mutex_destroy(&acb->postq_mutex);
	mutex_destroy(&acb->workingQ_mutex);
	mutex_destroy(&acb->ioctl_mutex);

error_level_2:
	ddi_dma_mem_free(&acb->ccbs_acc_handle);
	ddi_dma_free_handle(&acb->ccbs_pool_handle);

error_level_1:
	ddi_soft_state_free(arcmsr_soft_state, instance);

error_level_0:
	return (DDI_FAILURE);
}



/*
 *      Function: arcmsr_attach(9E)
 *   Description: Set up all device state and allocate data structures,
 *		  mutexes, condition variables, etc. for device operation.
 *		  Set mt_attr property for driver to indicate MT-safety.
 *		  Add interrupts needed.
 *         Input: dev_info_t *dev_info, ddi_attach_cmd_t cmd
 *        Output: Return DDI_SUCCESS if device is ready,
 *		          else return DDI_FAILURE
 */
static int
arcmsr_attach(dev_info_t *dev_info, ddi_attach_cmd_t cmd) {

	scsi_hba_tran_t *hba_trans;
	struct ACB *acb;


#if defined(ARCMSR_DEBUG)
	arcmsr_log(NULL, CE_NOTE,
	    "arcmsr_attach called for device %lx (instance %d)",
	    &dev_info, ddi_get_instance(dev_info));
#endif
	switch (cmd) {
	case DDI_ATTACH:
		return (arcmsr_do_ddi_attach(dev_info,
		    ddi_get_instance(dev_info)));
	case DDI_RESUME:
	case DDI_PM_RESUME:
	/*
	 * There is no hardware state to restart and no timeouts to
	 * restart since we didn't PM_SUSPEND with active cmds or
	 * active timeouts We just need to unblock waiting threads
	 * and restart I/O the code for DDI_RESUME is almost identical
	 * except it uses the suspend flag rather than pm_suspend flag
	 */
	    hba_trans = (scsi_hba_tran_t *)ddi_get_driver_private(dev_info);
	    if (!hba_trans) {
		    return (DDI_FAILURE);
	    }
	    acb = (struct ACB *)
		hba_trans->tran_hba_private;
	    mutex_enter(&acb->acb_mutex);
	    arcmsr_iop_init(acb);

	    /* restart ccbs "timeout" watchdog */
	    acb->timeout_id = timeout(arcmsr_ccbs_timeout,
		(void*)acb, (60 * drv_usectohz(1000000)));
	    mutex_exit(&acb->acb_mutex);
	    return (DDI_SUCCESS);

    default:
	    arcmsr_log(NULL, CE_WARN,
		"arcmsr%d: ddi attach cmd (%d) unsupported",
		cmd, ddi_get_instance(dev_info));
	    return (DDI_FAILURE);
	}
}

/*
 *    Function:	arcmsr_detach(9E)
 * Description: Remove all device allocation and system resources, disable
 *		        device interrupt.
 *       Input: dev_info_t *dev_info
 *		        ddi_detach_cmd_t cmd
 *      Output:	Return DDI_SUCCESS if done,
 *		        else returnDDI_FAILURE
 */
static int
arcmsr_detach(dev_info_t *dev_info, ddi_detach_cmd_t cmd) {

	int instance;
	struct ACB *acb;


	instance = ddi_get_instance(dev_info);
	acb = (struct ACB *)ddi_get_soft_state(arcmsr_soft_state,
	    instance);
	if (!acb) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		mutex_enter(&acb->acb_mutex);
		if (acb->timeout_id != 0) {
			mutex_exit(&acb->acb_mutex);
			(void) untimeout(acb->timeout_id);
			mutex_enter(&acb->acb_mutex);
			acb->timeout_id = 0;
		}
		arcmsr_pcidev_disattach(acb);
		/* Remove interrupt set up by ddi_add_intr */
		ddi_remove_intr(dev_info, 0, acb->iblock_cookie);
		/* unbind mapping object to handle */
		(void) ddi_dma_unbind_handle(acb->ccbs_pool_handle);
		/* Free ccb pool memory */
		ddi_dma_mem_free(&acb->ccbs_acc_handle);
		/* Free DMA handle */
		ddi_dma_free_handle(&acb->ccbs_pool_handle);
		ddi_regs_map_free(&acb->reg_mu_acc_handle0);
		if (scsi_hba_detach(dev_info) != DDI_SUCCESS)
			arcmsr_log(NULL, CE_WARN,
			    "arcmsr%d: Unable to detach instance cleanly "
			    "(should not happen)",
			    ddi_get_instance(dev_info));
		/* free scsi_hba_transport from scsi_hba_tran_alloc */
		scsi_hba_tran_free(acb->scsi_hba_transport);
		ddi_remove_minor_node(dev_info, NULL);
		ddi_prop_remove_all(dev_info);
		mutex_exit(&acb->acb_mutex);
		mutex_destroy(&acb->acb_mutex);
		mutex_destroy(&acb->postq_mutex);
		mutex_destroy(&acb->workingQ_mutex);
		mutex_destroy(&acb->ioctl_mutex);
		pci_config_teardown(&acb->pci_acc_handle);
		ddi_set_driver_private(dev_info, NULL);
		ddi_soft_state_free(arcmsr_soft_state, instance);
		pm_destroy_components(dev_info);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		mutex_enter(&acb->acb_mutex);
		if (acb->timeout_id != 0) {
			acb->acb_flags |= ACB_F_SCSISTOPADAPTER;
			mutex_exit(&acb->acb_mutex);
			(void) untimeout(acb->timeout_id);
			mutex_enter(&acb->acb_mutex);
			acb->timeout_id = 0;
		}
		/* disable all outbound interrupt */
		(void) arcmsr_disable_allintr(acb);
		/* stop adapter background rebuild */
		if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
			arcmsr_stop_hba_bgrb(acb);
			arcmsr_flush_hba_cache(acb);
		} else {
			arcmsr_stop_hbb_bgrb(acb);
			arcmsr_flush_hbb_cache(acb);
		}
		mutex_exit(&acb->acb_mutex);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}



/*
 *    Function:	arcmsr_tran_tgt_init
 * Description: Called when initializing a target device instance. If
 *		        no per-target initialization is required, the HBA
 *		        may leave tran_tgt_init to NULL
 *       Input:
 *		        dev_info_t *host_dev_info,
 *		        dev_info_t *target_dev_info,
 *		        scsi_hba_tran_t *tran,
 *		        struct scsi_device *sd
 *
 *      Return: DDI_SUCCESS if success, else return DDI_FAILURE
 *
 *  entry point enables the HBA to allocate and/or initialize any per-
 *  target resources.
 *  It also enables the HBA to qualify the device's address as valid and
 *  supportable for that particular HBA.
 *  By returning DDI_FAILURE, the instance of the target driver for that
 *  device will not be probed or attached.
 * 	This entry point is not required, and if none is supplied,
 *  the framework will attempt to probe and attach all possible instances
 *  of the appropriate target drivers.
 */
static int
arcmsr_tran_tgt_init(dev_info_t *host_dev_info, dev_info_t *target_dev_info,
    scsi_hba_tran_t *hosttran, struct scsi_device *sd) {
#ifndef __lock_lint
	_NOTE(ARGUNUSED(hosttran, target_dev_info))
#endif


	uint16_t  target;
	uint8_t  lun;

	target = sd->sd_address.a_target;
	lun = sd->sd_address.a_lun;
	if ((target >= ARCMSR_MAX_TARGETID) || (lun >= ARCMSR_MAX_TARGETLUN)) {
		cmn_err(CE_WARN,
		    "arcmsr%d: (target %d, lun %d) exceeds "
		    "maximum supported values (%d, %d)",
		    ddi_get_instance(host_dev_info),
		    target, lun, ARCMSR_MAX_TARGETID, ARCMSR_MAX_TARGETLUN);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 *         Function: arcmsr_tran_getcap(9E)
 *      Description: Get the capability named, and returnits value.
 *    Return Values: current value of capability, ifdefined
 *		             -1 ifcapability is not defined
 * ------------------------------------------------------
 *         Common Capability Strings Array
 * ------------------------------------------------------
 *	#define	SCSI_CAP_DMA_MAX		0
 *	#define	SCSI_CAP_MSG_OUT		1
 *	#define	SCSI_CAP_DISCONNECT		2
 *	#define	SCSI_CAP_SYNCHRONOUS		3
 *	#define	SCSI_CAP_WIDE_XFER		4
 *	#define	SCSI_CAP_PARITY			5
 *	#define	SCSI_CAP_INITIATOR_ID		6
 *	#define	SCSI_CAP_UNTAGGED_QING		7
 *	#define	SCSI_CAP_TAGGED_QING		8
 *	#define	SCSI_CAP_ARQ			9
 *	#define	SCSI_CAP_LINKED_CMDS		10 a
 *	#define	SCSI_CAP_SECTOR_SIZE		11 b
 *	#define	SCSI_CAP_TOTAL_SECTORS		12 c
 *	#define	SCSI_CAP_GEOMETRY		13 d
 *	#define	SCSI_CAP_RESET_NOTIFICATION	14 e
 *	#define	SCSI_CAP_QFULL_RETRIES		15 f
 *	#define	SCSI_CAP_QFULL_RETRY_INTERVAL	16 10
 *	#define	SCSI_CAP_SCSI_VERSION		17 11
 *	#define	SCSI_CAP_INTERCONNECT_TYPE	18 12
 *	#define	SCSI_CAP_LUN_RESET		19 13
 */
static int
arcmsr_tran_getcap(struct scsi_address *ap, char *cap, int whom) {

	int capability = 0;
	struct ACB *acb =
	    (struct ACB *)ap->a_hba_tran->tran_hba_private;


	if (cap == NULL || whom == 0) {
		return (DDI_FAILURE);
	}

	mutex_enter(&arcmsr_global_mutex);
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_SYNCHRONOUS:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_ARQ:
		capability = acb->tgt_scsi_opts[ap->a_target];
		break;
	case SCSI_CAP_SECTOR_SIZE:
		capability = ARCMSR_DEV_SECTOR_SIZE;
		break;
	case SCSI_CAP_DMA_MAX:
		/* Limit to 16MB max transfer */
		capability = ARCMSR_MAX_XFER_LEN;
		break;
	case SCSI_CAP_INITIATOR_ID:
		capability = ARCMSR_SCSI_INITIATOR_ID;
		break;
	case SCSI_CAP_GEOMETRY:
		/* head , track , cylinder */
		capability = (255 << 16) | 63;
		break;
	default:
		capability = -1;
		break;
	}
	mutex_exit(&arcmsr_global_mutex);
	return (capability);
}

/*
 *      Function: arcmsr_tran_setcap(9E)
 *   Description: Set the specific capability.
 * Return Values: 1 - capability exists and can be set to new value
 *		          0 - capability could not be set to new value
 *		         -1 - no such capability
 */
static int
arcmsr_tran_setcap(struct scsi_address *ap, char *cap, int value,
    int whom) {
#ifndef __lock_lint
	_NOTE(ARGUNUSED(value))
#endif


	int supported = 0;
	struct ACB *acb =
	    (struct ACB *)ap->a_hba_tran->tran_hba_private;


	if (cap == NULL || whom == 0) {
		return (-1);
	}

	mutex_enter(&arcmsr_global_mutex);
	switch (supported = scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_DISCONNECT:		/* 2 */
	case SCSI_CAP_SYNCHRONOUS:		/* 3 */
	case SCSI_CAP_TAGGED_QING:		/* 8 */
	case SCSI_CAP_WIDE_XFER:		/* 4 */
	case SCSI_CAP_ARQ:			/* 9 auto request sense */
	case SCSI_CAP_TOTAL_SECTORS:		/* c */
		acb->tgt_scsi_opts[ap->a_target] |= supported;
		supported = 1;
		break;
	case SCSI_CAP_UNTAGGED_QING:   		/* 7 */
	case SCSI_CAP_INITIATOR_ID:		/* 6 */
	case SCSI_CAP_DMA_MAX:			/* 0 */
	case SCSI_CAP_MSG_OUT:			/* 1 */
	case SCSI_CAP_PARITY:			/* 5 */
	case SCSI_CAP_LINKED_CMDS:		/* a */
	case SCSI_CAP_RESET_NOTIFICATION:	/* e */
	case SCSI_CAP_SECTOR_SIZE:		/* b */
		supported = 0;
		break;
	default:
		supported = -1;
		break;
	}
	mutex_exit(&arcmsr_global_mutex);
	return (supported);
}



static void
arcmsr_free_ccb(struct CCB *ccb) {

	struct ACB *acb = ccb->acb;

	ccb->startdone = ARCMSR_CCB_DONE;
	ccb->pkt = NULL;
	ccb->ccb_flags = 0;
	mutex_enter(&acb->workingQ_mutex);
	acb->ccbworkingQ[acb->workingccb_doneindex] = ccb;
	acb->workingccb_doneindex++;
	acb->workingccb_doneindex %= ARCMSR_MAX_FREECCB_NUM;
	mutex_exit(&acb->workingQ_mutex);
}

/*
 *      Function: arcmsr_tran_init_pkt
 * Return Values: pointer to scsi_pkt, or NULL
 *   Description: simultaneously allocate both a scsi_pkt(9S) structure and
 *                DMA resources for that pkt.
 *                Called by kernel on behalf of a target driver
 *		          calling scsi_init_pkt(9F).
 *		          Refer to tran_init_pkt(9E) man page
 *       Context: Can be called from different kernel process threads.
 *		          Can be called by interrupt thread.
 * Allocates SCSI packet and DMA resources
 */
static struct
scsi_pkt *arcmsr_tran_init_pkt(struct scsi_address *ap,
    register struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg) {

	struct CCB *ccb;
	struct ARCMSR_CDB *arcmsr_cdb;
	struct ACB *acb;
	int old_pkt_flag = 1;


	acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;

	if (pkt == NULL) {
		/* get free CCB */
		ccb = arcmsr_get_freeccb(acb);
		if (ccb == (struct CCB *)NULL) {
			return (NULL);
		}

		if (ccb->pkt != NULL) {
			/*
			 * If kmem_flags are turned on, expect to
			 * see a message
			 */
			cmn_err(CE_WARN, "arcmsr%d: invalid pkt",
			    ddi_get_instance(acb->dev_info));
			return (NULL);
		}
		pkt = scsi_hba_pkt_alloc(acb->dev_info, ap, cmdlen,
		    statuslen, tgtlen, sizeof (struct scsi_pkt),
		    callback, arg);
		if (pkt == NULL) {
			cmn_err(CE_WARN,
			    "arcmsr%d: scsi pkt allocation failed",
			    ddi_get_instance(acb->dev_info));
			arcmsr_free_ccb(ccb);
			return (NULL);
		}
		/* Initialize CCB */
		ccb->pkt = pkt;
		ccb->pkt_dma_handle = NULL;
		/* record how many sg are needed to xfer on this pkt */
		ccb->pkt_ncookies = 0;
		/* record how many sg we got from this window */
		ccb->pkt_cookie = 0;
		/* record how many windows have partial dma map set */
		ccb->pkt_nwin = 0;
		/* record current sg window position */
		ccb->pkt_curwin	= 0;
		ccb->pkt_dma_len = 0;
		ccb->pkt_dma_offset = 0;
		ccb->resid_dmacookie.dmac_size = 0;

		/*
		 * we will still use this point for we want to fake some
		 * information in tran_start
		 */
		ccb->bp = bp;

		/* Initialize arcmsr_cdb */
		arcmsr_cdb = (struct ARCMSR_CDB *)&ccb->arcmsr_cdb;
		bzero(arcmsr_cdb, sizeof (struct ARCMSR_CDB));
		arcmsr_cdb->Bus = 0;
		arcmsr_cdb->Function = 1;
		arcmsr_cdb->LUN = ap->a_lun;
		arcmsr_cdb->TargetID = ap->a_target;
		arcmsr_cdb->CdbLength = (uint8_t)cmdlen;
		arcmsr_cdb->Context = (unsigned long)arcmsr_cdb;

		/* Fill in the rest of the structure */
		pkt->pkt_ha_private = ccb;
		pkt->pkt_address = *ap;
		pkt->pkt_comp = (void (*)())NULL;
		pkt->pkt_flags = 0;
		pkt->pkt_time = 0;
		pkt->pkt_resid = 0;
		pkt->pkt_statistics = 0;
		pkt->pkt_reason = 0;
		old_pkt_flag = 0;
	} else {
		ccb = (struct CCB *)pkt->pkt_ha_private;
		/*
		 * you cannot update CdbLength with cmdlen here, it would
		 * cause a data compare error
		 */
		ccb->startdone = ARCMSR_CCB_UNBUILD;
	}

	/* Second step : dma allocation/move */
	if (bp && bp->b_bcount != 0) {
		/*
		 * system had a lot of data trunk need to xfer, from...20 byte
		 * to 819200 byte.
		 * arcmsr_dma_alloc will get pkt_dma_handle (not null) until
		 * this lot of data trunk xfer done this mission will be done
		 * by some of continue READ or WRITE scsi command, till this
		 * lot of data trunk xfer completed.
		 * arcmsr_dma_move do the action repeatedly, and use the same
		 * ccb till this lot of data trunk xfer complete notice.
		 * when after the arcmsr_tran_init_pkt returns the solaris
		 * kernel is by your pkt_resid and its b_bcount to give you
		 * which type of scsi command descriptor to implement the
		 * length of folowing arcmsr_tran_start scsi cdb (data length)
		 *
		 * Each transfer should be aligned on a 512 byte boundary
		 */
		if (ccb->pkt_dma_handle == NULL) {
			if (arcmsr_dma_alloc(acb, pkt, bp, flags,
			    callback) == DDI_FAILURE) {
				/*
				 * the HBA driver is unable to allocate DMA
				 * resources, it must free the allocated
				 * scsi_pkt(9S) before returning
				 */
				cmn_err(CE_WARN, "arcmsr%d: dma allocation "
				    "failure ",
				    ddi_get_instance(acb->dev_info));
				if (old_pkt_flag == 0) {
					cmn_err(CE_WARN, "arcmsr%d: dma "
					    "allocation failed to free scsi "
					    "hba pkt ",
					    ddi_get_instance(acb->dev_info));
					arcmsr_free_ccb(ccb);
					scsi_hba_pkt_free(ap, pkt);
				}
				return ((struct scsi_pkt *)NULL);
			}
		} else {
			/* DMA resources to next DMA window, for old pkt */
			if (arcmsr_dma_move(acb, pkt, bp) == -1) {
				cmn_err(CE_WARN, "arcmsr%d: dma move "
				    "failed ",
				    ddi_get_instance(acb->dev_info));
				return ((struct scsi_pkt *)NULL);
			}
		}
	} else {
		pkt->pkt_resid = 0;
	}
	return (pkt);
}

/*
 * Function name: arcmsr_dma_alloc
 * Return Values: 0 if successful, -1 if failure
 *   Description: allocate DMA resources
 *       Context: Can only be called from arcmsr_tran_init_pkt()
 *     register struct scsi_address	*ap = &((pkt)->pkt_address);
 */
static int
arcmsr_dma_alloc(struct ACB *acb, struct scsi_pkt *pkt,
    struct buf *bp, int flags, int (*callback)()) {

	struct CCB *ccb = pkt->pkt_ha_private;
	int alloc_result, map_method, dma_flags;
	int resid = 0;
	int total_ccb_xferlen = 0;
	int (*cb)(caddr_t);
	uint8_t i;

	/*
	 * at this point the PKT SCSI CDB is empty, and dma xfer length
	 * is bp->b_bcount
	 */

	if (bp->b_flags & B_READ) {
		ccb->ccb_flags &= ~CCB_FLAG_DMAWRITE;
		dma_flags = DDI_DMA_READ;
	} else {
		ccb->ccb_flags |= CCB_FLAG_DMAWRITE;
		dma_flags = DDI_DMA_WRITE;
	}

	if (flags & PKT_CONSISTENT) {
		ccb->ccb_flags |= CCB_FLAG_DMACONSISTENT;
		dma_flags |= DDI_DMA_CONSISTENT;
	}
	if (flags & PKT_DMA_PARTIAL) {
		dma_flags |= DDI_DMA_PARTIAL;
	}

	dma_flags |= DDI_DMA_REDZONE;
	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	if ((alloc_result = ddi_dma_alloc_handle(acb->dev_info,
	    &arcmsr_dma_attr, cb, 0, &ccb->pkt_dma_handle))
	    != DDI_SUCCESS) {
		switch (alloc_result) {
		case DDI_DMA_BADATTR:
			/*
			 * If the system does not support physical DMA,
			 * the return value from ddi_dma_alloc_handle
			 * will be DDI_DMA_BADATTR
			 */
			cmn_err(CE_WARN, "arcmsr%d: dma allocate returned "
			    "'bad attribute'",
			    ddi_get_instance(acb->dev_info));
			bioerror(bp, EFAULT);
			return (DDI_FAILURE);
		case DDI_DMA_NORESOURCES:
			cmn_err(CE_WARN, "arcmsr%d: dma allocate returned "
			    "'no resources'",
			    ddi_get_instance(acb->dev_info));
			bioerror(bp, 0);
			return (DDI_FAILURE);
		default:
			cmn_err(CE_WARN, "arcmsr%d: dma allocate returned "
			    "'unknown failure'",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}
	}

	map_method = ddi_dma_buf_bind_handle(ccb->pkt_dma_handle, bp,
	    dma_flags, cb, 0,
	    &ccb->pkt_dmacookies[0],	/* SG List pointer */
	    &ccb->pkt_ncookies);	/* number of sgl cookies */

	switch (map_method) {
	case DDI_DMA_PARTIAL_MAP:
		/*
		 * When your main memory size larger then 4G
		 * DDI_DMA_PARTIAL_MAP will be touched.
		 *
		 * We've already set DDI_DMA_PARTIAL in dma_flags,
		 * so if it's now missing, there's something screwy
		 * happening. We plow on....
		 */

		if ((dma_flags & DDI_DMA_PARTIAL) == 0) {
			cmn_err(CE_WARN, "arcmsr%d: dma partial mapping lost "
			    "...impossible case!",
			    ddi_get_instance(acb->dev_info));
		}
		if (ddi_dma_numwin(ccb->pkt_dma_handle, &ccb->pkt_nwin) ==
		    DDI_FAILURE) {
			cmn_err(CE_WARN, "arcmsr%d: ddi_dma_numwin() failed",
			    ddi_get_instance(acb->dev_info));
		}

		if (ddi_dma_getwin(ccb->pkt_dma_handle, ccb->pkt_curwin,
		    &ccb->pkt_dma_offset, &ccb->pkt_dma_len,
		    &ccb->pkt_dmacookies[0], &ccb->pkt_ncookies) ==
		    DDI_FAILURE) {
			cmn_err(CE_WARN, "arcmsr%d: ddi_dma_getwin failed",
			    ddi_get_instance(acb->dev_info));
		}

		i = 0;
		/* first cookie is accessed from ccb->pkt_dmacookies[0] */
		total_ccb_xferlen = ccb->pkt_dmacookies[0].dmac_size;
		for (;;) {
			i++;
			if (i == ARCMSR_MAX_SG_ENTRIES ||
			    i == ccb->pkt_ncookies ||
			    total_ccb_xferlen == ARCMSR_MAX_XFER_LEN) {
				break;
			}
			/*
			 * next cookie will be retrieved from
			 * ccb->pkt_dmacookies[i]
			 */
			ddi_dma_nextcookie(ccb->pkt_dma_handle,
			    &ccb->pkt_dmacookies[i]);
			total_ccb_xferlen += ccb->pkt_dmacookies[i].dmac_size;
		}
		ccb->pkt_cookie = i;
		ccb->arcmsr_cdb.sgcount = i;
		if (total_ccb_xferlen > 512) {
			resid = total_ccb_xferlen % 512;
			if (resid != 0) {
				i--;
				total_ccb_xferlen -= resid;
				/* modify last sg length */
				ccb->pkt_dmacookies[i].dmac_size =
				    ccb->pkt_dmacookies[i].dmac_size - resid;
				ccb->resid_dmacookie.dmac_size = resid;
				ccb->resid_dmacookie.dmac_laddress =
				    ccb->pkt_dmacookies[i].dmac_laddress +
				    ccb->pkt_dmacookies[i].dmac_size;
			}
		}
		ccb->total_dmac_size = total_ccb_xferlen;
		ccb->ccb_flags |= CCB_FLAG_DMAVALID;
		pkt->pkt_resid = bp->b_bcount - ccb->total_dmac_size;

		return (DDI_SUCCESS);

	case DDI_DMA_MAPPED:
		ccb->pkt_nwin = 1; /* all mapped, so only one window */
		ccb->pkt_dma_len = 0;
		ccb->pkt_dma_offset = 0;
		i = 0;
		/* first cookie is accessed from ccb->pkt_dmacookies[0] */
		total_ccb_xferlen = ccb->pkt_dmacookies[0].dmac_size;
		for (;;) {
			i++;
			if (i == ARCMSR_MAX_SG_ENTRIES ||
			    i == ccb->pkt_ncookies ||
			    total_ccb_xferlen == ARCMSR_MAX_XFER_LEN) {
				break;
			}
			/*
			 * next cookie will be retrieved from
			 * ccb->pkt_dmacookies[i]
			 */
			ddi_dma_nextcookie(ccb->pkt_dma_handle,
			    &ccb->pkt_dmacookies[i]);
			total_ccb_xferlen += ccb->pkt_dmacookies[i].dmac_size;
		}
		ccb->pkt_cookie = i;
		ccb->arcmsr_cdb.sgcount = i;
		if (total_ccb_xferlen > 512) {
			resid = total_ccb_xferlen % 512;
			    if (resid != 0) {
				i--;
				total_ccb_xferlen -= resid;
				/* modify last sg length */
				ccb->pkt_dmacookies[i].dmac_size =
				    ccb->pkt_dmacookies[i].dmac_size - resid;
				ccb->resid_dmacookie.dmac_size = resid;
				ccb->resid_dmacookie.dmac_laddress =
				    ccb->pkt_dmacookies[i].dmac_laddress +
				    ccb->pkt_dmacookies[i].dmac_size;
			}
		}
		ccb->total_dmac_size = total_ccb_xferlen;
		ccb->ccb_flags |= CCB_FLAG_DMAVALID;
		pkt->pkt_resid = bp->b_bcount - ccb->total_dmac_size;
		return (DDI_SUCCESS);

	case DDI_DMA_NORESOURCES:
		cmn_err(CE_WARN, "arcmsr%d: dma map got 'no resources'",
		    ddi_get_instance(acb->dev_info));
		bioerror(bp, ENOMEM);
		break;

	case DDI_DMA_NOMAPPING:
		cmn_err(CE_WARN, "arcmsr%d: dma map got 'no mapping'",
		    ddi_get_instance(acb->dev_info));
		bioerror(bp, EFAULT);
		break;

	case DDI_DMA_TOOBIG:
		cmn_err(CE_WARN, "arcmsr%d: dma map got 'too big'",
		    ddi_get_instance(acb->dev_info));
		bioerror(bp, EINVAL);
		break;

	case DDI_DMA_INUSE:
		cmn_err(CE_WARN, "arcmsr%d: dma map got 'in use' "
		    "(should not happen)",
		    ddi_get_instance(acb->dev_info));
		break;
	default:
		cmn_err(CE_WARN,
		    "arcmsr%d: dma map got 'unknown failure 0x%x' "
		    "(should not happen)",
		    ddi_get_instance(acb->dev_info), i);
#ifdef ARCMSR_DEBUG
		arcmsr_dump_scsi_cdb(&pkt->pkt_address, pkt);
#endif
		break;
	}

	ddi_dma_free_handle(&ccb->pkt_dma_handle);
	ccb->pkt_dma_handle = NULL;
	ccb->ccb_flags &= ~CCB_FLAG_DMAVALID;
	return (DDI_FAILURE);
}


/*
 * Function name: arcmsr_dma_move
 * Return Values: 0 if successful, -1 if failure
 *   Description: move DMA resources to next DMA window
 *       Context: Can only be called from arcmsr_tran_init_pkt()
 */
static int
arcmsr_dma_move(struct ACB *acb, struct scsi_pkt *pkt,
    struct buf *bp) {

	struct CCB *ccb = pkt->pkt_ha_private;
	uint8_t i = 0;
	int resid = 0;
	int total_ccb_xferlen = 0;

	if (ccb->resid_dmacookie.dmac_size != 0) 	{
		total_ccb_xferlen += ccb->resid_dmacookie.dmac_size;
		ccb->pkt_dmacookies[i].dmac_size =
		    ccb->resid_dmacookie.dmac_size;
		ccb->pkt_dmacookies[i].dmac_laddress =
		    ccb->resid_dmacookie.dmac_laddress;
		i++;
		ccb->resid_dmacookie.dmac_size = 0;
	}
	/*
	 * If there are no more cookies remaining in this window,
	 * move to the next window.
	 */
	if (ccb->pkt_cookie == ccb->pkt_ncookies) {
		/*
		 * only dma map "partial" arrive here
		 */
		if ((ccb->pkt_curwin == ccb->pkt_nwin) &&
		    (ccb->pkt_nwin == 1)) {
			cmn_err(CE_CONT,
			    "arcmsr%d: dma partial set, but only "
			    "one window allocated",
			    ddi_get_instance(acb->dev_info));
			return (DDI_SUCCESS);
		}

		/* At last window, cannot move */
		if (++ccb->pkt_curwin >= ccb->pkt_nwin) {
			cmn_err(CE_WARN,
			    "arcmsr%d: dma partial set, numwin exceeded",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}
		if (ddi_dma_getwin(ccb->pkt_dma_handle, ccb->pkt_curwin,
		    &ccb->pkt_dma_offset, &ccb->pkt_dma_len,
		    &ccb->pkt_dmacookies[i], &ccb->pkt_ncookies) ==
		    DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "arcmsr%d: dma partial set, "
			    "ddi_dma_getwin failure",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}
		/* reset cookie pointer */
		ccb->pkt_cookie = 0;
	} else {
		/*
		 * only dma map "all" arrive here
		 * We still have more cookies in this window,
		 * get the next one
		 * access the pkt_dma_handle remain cookie record at
		 * ccb->pkt_dmacookies array
		 */
		ddi_dma_nextcookie(ccb->pkt_dma_handle,
		    &ccb->pkt_dmacookies[i]);
	}

	/* Get remaining cookies in this window, up to our maximum */
	total_ccb_xferlen += ccb->pkt_dmacookies[i].dmac_size;

	/* retrieve and store cookies, start at ccb->pkt_dmacookies[0] */
	for (;;) {
		i++;
		/* handled cookies count level indicator */
		ccb->pkt_cookie++;
		if (i == ARCMSR_MAX_SG_ENTRIES ||
		    ccb->pkt_cookie == ccb->pkt_ncookies ||
		    total_ccb_xferlen == ARCMSR_MAX_XFER_LEN) {
			break;
		}
		ddi_dma_nextcookie(ccb->pkt_dma_handle,
		    &ccb->pkt_dmacookies[i]);
		total_ccb_xferlen += ccb->pkt_dmacookies[i].dmac_size;
	}

	ccb->arcmsr_cdb.sgcount = i;
	if (total_ccb_xferlen > 512) {
		resid = total_ccb_xferlen % 512;
		if (resid != 0) {
			i--;
			total_ccb_xferlen -= resid;
			/* modify last sg length */
			ccb->pkt_dmacookies[i].dmac_size =
			    ccb->pkt_dmacookies[i].dmac_size - resid;
			ccb->resid_dmacookie.dmac_size = resid;
			ccb->resid_dmacookie.dmac_laddress =
			    ccb->pkt_dmacookies[i].dmac_laddress +
			    ccb->pkt_dmacookies[i].dmac_size;
		}
	}
	ccb->total_dmac_size += total_ccb_xferlen;
	pkt->pkt_resid = bp->b_bcount - ccb->total_dmac_size;

	return (DDI_SUCCESS);
}

/*
 * Function name: arcmsr_tran_destroy_pkt
 * Return Values: none
 *   Description: Called by kernel on behalf of a target driver
 *	          calling scsi_destroy_pkt(9F).
 *	          Refer to tran_destroy_pkt(9E) man page
 *       Context: Can be called from different kernel process threads.
 *	          Can be called by interrupt thread.
 */
static void
arcmsr_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt) {

	struct CCB *ccb = pkt->pkt_ha_private;

	if ((ccb != NULL) && (ccb->pkt == pkt)) {
		struct ACB *acb = ccb->acb;
		if (ccb->ccb_flags & CCB_FLAG_DMAVALID) {
			if (ddi_dma_unbind_handle(ccb->pkt_dma_handle)
			    != DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "arcmsr%d: ddi_dma_unbind_handle() failed",
				    ddi_get_instance(acb->dev_info));
			}
			ddi_dma_free_handle(&ccb->pkt_dma_handle);
			ccb->pkt_dma_handle = NULL;
		}
		arcmsr_free_ccb(ccb);
	}

	scsi_hba_pkt_free(ap, pkt);
}

/*
 * Function name: arcmsr_tran_dmafree()
 * Return Values: none
 *   Description: free dvma resources
 *       Context: Can be called from different kernel process threads.
 *	          Can be called by interrupt thread.
 */
static void
arcmsr_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt) {

	struct CCB *ccb = pkt->pkt_ha_private;

	if (ccb->ccb_flags & CCB_FLAG_DMAVALID) {
		ccb->ccb_flags &= ~CCB_FLAG_DMAVALID;
		if (ddi_dma_unbind_handle(ccb->pkt_dma_handle)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "arcmsr%d: ddi_dma_unbind_handle() failed "
			    "(target %d lun %d)",
			    ddi_get_instance(ccb->acb->dev_info),
			    ap->a_target, ap->a_lun);
		}
		ddi_dma_free_handle(&ccb->pkt_dma_handle);
		ccb->pkt_dma_handle = NULL;
	}
}

/*
 * Function name: arcmsr_tran_sync_pkt()
 * Return Values: none
 *   Description: sync dma
 *       Context: Can be called from different kernel process threads.
 *		  Can be called by interrupt thread.
 */
static void
arcmsr_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt) {

	struct CCB *ccb;

	ccb = pkt->pkt_ha_private;

	if (ccb->ccb_flags & CCB_FLAG_DMAVALID) {
		if (ddi_dma_sync(ccb->pkt_dma_handle,
		    ccb->pkt_dma_offset, ccb->pkt_dma_len,
		    (ccb->ccb_flags & CCB_FLAG_DMAWRITE) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU)
			!= DDI_SUCCESS) {
			cmn_err(CE_WARN, "arcmsr%d: sync pkt failed "
			    "for target %d lun %d",
			    ddi_get_instance(ccb->acb->dev_info),
			    ap->a_target, ap->a_lun);
		}
	}
}


static uint8_t
arcmsr_hba_wait_msgint_ready(struct ACB *acb) {

	uint32_t i;
	uint8_t retries = 0x00;
	struct HBA_msgUnit *phbamu;


	phbamu = (struct HBA_msgUnit *)acb->pmu;

	do {
		for (i = 0; i < 100; i++) {
			if (CHIP_REG_READ32(acb->reg_mu_acc_handle0,
			    &phbamu->outbound_intstatus) &
			    ARCMSR_MU_OUTBOUND_MESSAGE0_INT) {
				/* clear interrupt */
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbamu->outbound_intstatus,
				    ARCMSR_MU_OUTBOUND_MESSAGE0_INT);
				return (TRUE);
			}
			drv_usecwait(10000);
			if (ddi_in_panic()) {
				/* clear interrupts */
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbamu->outbound_intstatus,
				    ARCMSR_MU_OUTBOUND_MESSAGE0_INT);
				return (TRUE);
			}
		} /* max 1 second */
	} while (retries++ < 20); /* max 20 seconds */
	return (FALSE);
}



static uint8_t
arcmsr_hbb_wait_msgint_ready(struct ACB *acb) {

	struct HBB_msgUnit *phbbmu;
	uint32_t i;
	uint8_t retries = 0x00;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	do {
		for (i = 0; i < 100; i++) {
			if (CHIP_REG_READ32(acb->reg_mu_acc_handle0,
			    &phbbmu->hbb_doorbell->iop2drv_doorbell) &
			    ARCMSR_IOP2DRV_MESSAGE_CMD_DONE) {
				/* clear interrupt */
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbbmu->hbb_doorbell->iop2drv_doorbell,
				    ARCMSR_MESSAGE_INT_CLEAR_PATTERN);
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbbmu->hbb_doorbell->drv2iop_doorbell,
				    ARCMSR_DRV2IOP_END_OF_INTERRUPT);
				return (TRUE);
			}
			drv_usecwait(10000);
			if (ddi_in_panic()) {
				/* clear interrupts */
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbbmu->hbb_doorbell->iop2drv_doorbell,
				    ARCMSR_MESSAGE_INT_CLEAR_PATTERN);
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbbmu->hbb_doorbell->drv2iop_doorbell,
				    ARCMSR_DRV2IOP_END_OF_INTERRUPT);
				return (TRUE);
			}
		} /* max 1 second */
	} while (retries++ < 20); /* max 20 seconds */

	return (FALSE);
}


static void
arcmsr_flush_hba_cache(struct ACB *acb) {

	struct HBA_msgUnit *phbamu;
	int retry_count = 30;

	/* enlarge wait flush adapter cache time: 10 minutes */

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbamu->inbound_msgaddr0,
	    ARCMSR_INBOUND_MESG0_FLUSH_CACHE);

	do {
		if (arcmsr_hba_wait_msgint_ready(acb)) {
			break;
		} else {
			retry_count--;
		}
	} while (retry_count != 0);
}



static void
arcmsr_flush_hbb_cache(struct ACB *acb) {

	struct HBB_msgUnit *phbbmu;
	int retry_count = 30;

	/* enlarge wait flush adapter cache time: 10 minutes */

	phbbmu = (struct HBB_msgUnit *)acb->pmu;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_MESSAGE_FLUSH_CACHE);

	do {
		if (arcmsr_hbb_wait_msgint_ready(acb)) {
			break;
		} else {
			retry_count--;
		}
	} while (retry_count != 0);
}


static void
arcmsr_ccb_complete(struct CCB *ccb, int flag) {

	struct ACB *acb = ccb->acb;
	struct scsi_pkt *pkt = ccb->pkt;

	if (flag == 1) {
		acb->ccboutstandingcount--;
	}
	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS);

	if ((ccb->ccb_flags & CCB_FLAG_DMACONSISTENT) &&
	    (pkt->pkt_state & STATE_XFERRED_DATA)) {
		(void) ddi_dma_sync(ccb->pkt_dma_handle,
		    ccb->pkt_dma_offset, ccb->pkt_dma_len,
		    DDI_DMA_SYNC_FORCPU);
	}

	if (pkt->pkt_comp) {
		(*pkt->pkt_comp)(pkt);
	}
}


static void
arcmsr_report_sense_info(struct CCB *ccb) {

	struct scsi_pkt *pkt = ccb->pkt;
	struct scsi_arq_status *arq_status;


	arq_status = (struct scsi_arq_status *)(intptr_t)(pkt->pkt_scbp);
	bzero((caddr_t)arq_status, sizeof (struct scsi_arq_status));
	arq_status->sts_rqpkt_reason = CMD_CMPLT;
	arq_status->sts_rqpkt_state = (STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS);
	arq_status->sts_rqpkt_statistics = pkt->pkt_statistics;
	arq_status->sts_rqpkt_resid = 0;

	pkt->pkt_reason = CMD_CMPLT;
	/* auto rqsense took place */
	pkt->pkt_state = (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_GOT_STATUS | STATE_ARQ_DONE);

	if (&arq_status->sts_sensedata != NULL) {
		struct SENSE_DATA *cdb_sensedata;
		struct scsi_extended_sense *sts_sensedata;

		cdb_sensedata =
		    (struct SENSE_DATA *)ccb->arcmsr_cdb.SenseData;
		sts_sensedata = &arq_status->sts_sensedata;

		sts_sensedata->es_code = cdb_sensedata->ErrorCode;
		/* must eq CLASS_EXTENDED_SENSE (0x07) */
		sts_sensedata->es_class = cdb_sensedata->ErrorClass;
		sts_sensedata->es_valid = cdb_sensedata->Valid;
		sts_sensedata->es_segnum = cdb_sensedata->SegmentNumber;
		sts_sensedata->es_key = cdb_sensedata->SenseKey;
		sts_sensedata->es_ili = cdb_sensedata->IncorrectLength;
		sts_sensedata->es_eom = cdb_sensedata->EndOfMedia;
		sts_sensedata->es_filmk = cdb_sensedata->FileMark;
		sts_sensedata->es_info_1 = cdb_sensedata->Information[0];
		sts_sensedata->es_info_2 = cdb_sensedata->Information[1];
		sts_sensedata->es_info_3 = cdb_sensedata->Information[2];
		sts_sensedata->es_info_4 = cdb_sensedata->Information[3];
		sts_sensedata->es_add_len =
		    cdb_sensedata->AdditionalSenseLength;
		sts_sensedata->es_cmd_info[0] =
		    cdb_sensedata->CommandSpecificInformation[0];
		sts_sensedata->es_cmd_info[1] =
		    cdb_sensedata->CommandSpecificInformation[1];
		sts_sensedata->es_cmd_info[2] =
		    cdb_sensedata->CommandSpecificInformation[2];
		sts_sensedata->es_cmd_info[3] =
		    cdb_sensedata->CommandSpecificInformation[3];
		sts_sensedata->es_add_code =
		    cdb_sensedata->AdditionalSenseCode;
		sts_sensedata->es_qual_code =
		    cdb_sensedata->AdditionalSenseCodeQualifier;
		sts_sensedata->es_fru_code =
		    cdb_sensedata->FieldReplaceableUnitCode;
	}
}



static void
arcmsr_abort_hba_allcmd(struct ACB *acb) {

	struct HBA_msgUnit *phbamu;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbamu->inbound_msgaddr0,
	    ARCMSR_INBOUND_MESG0_ABORT_CMD);

	if (!arcmsr_hba_wait_msgint_ready(acb)) {
		cmn_err(CE_WARN,
		    "arcmsr%d: timeout while waiting for 'abort all "
		    "outstanding commands'",
		    ddi_get_instance(acb->dev_info));
	}
}



static void
arcmsr_abort_hbb_allcmd(struct ACB *acb) {

	struct HBB_msgUnit *phbbmu =
	    (struct HBB_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_MESSAGE_ABORT_CMD);

	if (!arcmsr_hbb_wait_msgint_ready(acb)) {
		cmn_err(CE_WARN,
		    "arcmsr%d: timeout while waiting for 'abort all "
		    "outstanding commands'",
		    ddi_get_instance(acb->dev_info));
	}
}

static void
arcmsr_report_ccb_state(struct ACB *acb,
    struct CCB *ccb, uint32_t flag_ccb) {

	int id, lun;

	id = ccb->pkt->pkt_address.a_target;
	lun = ccb->pkt->pkt_address.a_lun;

	if ((flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR) == 0) {
		if (acb->devstate[id][lun] == ARECA_RAID_GONE) {
			acb->devstate[id][lun] = ARECA_RAID_GOOD;
		}
		ccb->pkt->pkt_reason = CMD_CMPLT;
		ccb->pkt->pkt_state |= STATE_XFERRED_DATA;
		arcmsr_ccb_complete(ccb, 1);
	} else {
		switch (ccb->arcmsr_cdb.DeviceStatus) {
		case ARCMSR_DEV_SELECT_TIMEOUT:
			if (acb->devstate[id][lun] == ARECA_RAID_GOOD) {
				cmn_err(CE_CONT,
				    "arcmsr%d: raid volume was kicked out ",
				    ddi_get_instance(acb->dev_info));
			}
			acb->devstate[id][lun] = ARECA_RAID_GONE;
			ccb->pkt->pkt_reason = CMD_TIMEOUT;
			ccb->pkt->pkt_statistics |= STAT_TIMEOUT;
			arcmsr_ccb_complete(ccb, 1);
			break;
		case ARCMSR_DEV_ABORTED:
		case ARCMSR_DEV_INIT_FAIL:
			cmn_err(CE_CONT,
			    "arcmsr%d: isr got "
			    "'ARCMSR_DEV_ABORTED' 'ARCMSR_DEV_INIT_FAIL'",
			    ddi_get_instance(acb->dev_info));
			cmn_err(CE_CONT, "arcmsr%d: raid volume was kicked "
			    "out", ddi_get_instance(acb->dev_info));
			acb->devstate[id][lun] = ARECA_RAID_GONE;
			ccb->pkt->pkt_reason = CMD_DEV_GONE;
			ccb->pkt->pkt_statistics |= STAT_TERMINATED;
			arcmsr_ccb_complete(ccb, 1);
			break;
		case SCSISTAT_CHECK_CONDITION:
			acb->devstate[id][lun] = ARECA_RAID_GOOD;
			arcmsr_report_sense_info(ccb);
			arcmsr_ccb_complete(ccb, 1);
			break;
		default:
			cmn_err(CE_WARN, "arcmsr%d: target %d lun %d "
			    "isr received CMD_DONE with unknown "
			    "DeviceStatus (0x%x)",
			    ddi_get_instance(acb->dev_info), id, lun,
			    ccb->arcmsr_cdb.DeviceStatus);
			cmn_err(CE_CONT, "arcmsr%d: raid volume was kicked "
			    "out ", ddi_get_instance(acb->dev_info));
			acb->devstate[id][lun] = ARECA_RAID_GONE;
			/* unknown error or crc error just for retry */
			ccb->pkt->pkt_reason = CMD_TRAN_ERR;
			ccb->pkt->pkt_statistics |= STAT_TERMINATED;
			arcmsr_ccb_complete(ccb, 1);
			break;
		}
	}
}


static void
arcmsr_drain_donequeue(struct ACB *acb, uint32_t flag_ccb) {

	struct CCB *ccb;

	/* check if command completed without error */
	ccb = (struct CCB *)(acb->vir2phy_offset +
	    (flag_ccb << 5)); /* frame must be aligned on 32 byte boundary */

	if ((ccb->acb != acb) || (ccb->startdone != ARCMSR_CCB_START)) 	{
		if (ccb->startdone == ARCMSR_CCB_ABORTED) {
			cmn_err(CE_CONT,
			    "arcmsr%d: isr got aborted command "
			    "while draining doneq",
			    ddi_get_instance(acb->dev_info));
			ccb->pkt->pkt_reason = CMD_ABORTED;
			ccb->pkt->pkt_statistics |= STAT_ABORTED;
			arcmsr_ccb_complete(ccb, 1);
			return;
		}

		if (ccb->startdone == ARCMSR_CCB_RESET) {
			cmn_err(CE_CONT,
			    "arcmsr%d: isr got command reset "
			    "while draining doneq",
			    ddi_get_instance(acb->dev_info));
			ccb->pkt->pkt_reason = CMD_RESET;
			ccb->pkt->pkt_statistics |= STAT_BUS_RESET;
			arcmsr_ccb_complete(ccb, 1);
			return;
		}

		cmn_err(CE_WARN, "arcmsr%d: isr got an illegal ccb command "
		    "done while draining doneq",
		    ddi_get_instance(acb->dev_info));
		return;
	}
	arcmsr_report_ccb_state(acb, ccb, flag_ccb);
}


static void
arcmsr_done4abort_postqueue(struct ACB *acb) {

	int i = 0;
	uint32_t flag_ccb;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;
		uint32_t outbound_intstatus;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/* clear and abort all outbound posted Q */
		outbound_intstatus = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intstatus) & acb->outbound_int_enable;
		/* clear interrupt */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intstatus, outbound_intstatus);
		while (((flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_queueport)) != 0xFFFFFFFF) &&
		    (i++ < ARCMSR_MAX_OUTSTANDING_CMD)) {
			arcmsr_drain_donequeue(acb, flag_ccb);
		}
	}
		break;

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;

		/* clear all outbound posted Q */
		/* clear doorbell interrupt */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell,
		    ARCMSR_DOORBELL_INT_CLEAR_PATTERN);
		for (i = 0; i < ARCMSR_MAX_HBB_POSTQUEUE; i++) {
			if ((flag_ccb = phbbmu->done_qbuffer[i]) != 0) {
				phbbmu->done_qbuffer[i] = 0;
				arcmsr_drain_donequeue(acb, flag_ccb);
			}
			phbbmu->post_qbuffer[i] = 0;
		}	/* drain reply FIFO */
		phbbmu->doneq_index = 0;
		phbbmu->postq_index = 0;
		break;
	}
	}
}

/*
 * Routine Description: Reset 80331 iop.
 *           Arguments:
 *        Return Value: Nothing.
 */
static void
arcmsr_iop_reset(struct ACB *acb) {

	struct CCB *ccb;
	uint32_t intmask_org;
	int i = 0;

	if (acb->ccboutstandingcount > 0) {
		/* disable all outbound interrupt */
		intmask_org = arcmsr_disable_allintr(acb);
		/* talk to iop 331 outstanding command aborted */
		if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
			arcmsr_abort_hba_allcmd(acb);
		} else {
			arcmsr_abort_hbb_allcmd(acb);
		}
		/* clear and abort all outbound posted Q */
		arcmsr_done4abort_postqueue(acb);

		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->startdone == ARCMSR_CCB_START) {
				ccb->startdone = ARCMSR_CCB_RESET;
				ccb->pkt->pkt_reason = CMD_RESET;
				ccb->pkt->pkt_statistics |= STAT_BUS_RESET;
				arcmsr_ccb_complete(ccb, 1);
			}
		}
		/* enable all outbound interrupt */
		arcmsr_enable_allintr(acb, intmask_org);
	}
}

/*
 * You can access the DMA address through the #defines:
 * dmac_address for 32-bit addresses and dmac_laddress for 64-bit addresses.
 *	These macros are defined as follows:
 *
 *	#define dmac_laddress   _dmu._dmac_ll
 *	#ifdef _LONG_LONG_HTOL
 *		#define dmac_notused    _dmu._dmac_la[0]
 *		#define dmac_address    _dmu._dmac_la[1]
 *	#else
 *		#define dmac_address    _dmu._dmac_la[0]
 *		#define dmac_notused    _dmu._dmac_la[1]
 *	#endif
 */
/*ARGSUSED*/
static void
arcmsr_build_ccb(struct CCB *ccb) {

	struct scsi_pkt *pkt = ccb->pkt;
	struct ARCMSR_CDB *arcmsr_cdb;
	char *psge;
	uint32_t address_lo, address_hi;
	int arccdbsize = 0x30;
	uint8_t sgcount;

	arcmsr_cdb = (struct ARCMSR_CDB *)&ccb->arcmsr_cdb;
	psge = (char *)&arcmsr_cdb->sgu;

	/* return the current time in seconds */
	ccb->ccb_time = (time_t)(pkt->pkt_time + ddi_get_time());
	bcopy((caddr_t)pkt->pkt_cdbp, arcmsr_cdb->Cdb,
	    arcmsr_cdb->CdbLength);
	sgcount = ccb->arcmsr_cdb.sgcount;

	if (sgcount) {
		int length, i;
		int cdb_sgcount = 0;
		int total_xfer_length = 0;

		/* map stor port SG list to our iop SG List. */
		for (i = 0; i < sgcount; i++) {
			/* Get physaddr of the current data pointer */
			length = ccb->pkt_dmacookies[i].dmac_size;
			total_xfer_length += length;
			address_lo = dma_addr_lo32(
				ccb->pkt_dmacookies[i].dmac_laddress);
			address_hi = dma_addr_hi32(
				ccb->pkt_dmacookies[i].dmac_laddress);

			if (address_hi == 0) {
				struct SG32ENTRY *dma_sg;

				dma_sg = (struct SG32ENTRY *)(intptr_t)psge;

				dma_sg->address = address_lo;
				dma_sg->length = length;
				psge += sizeof (struct SG32ENTRY);
				arccdbsize += sizeof (struct SG32ENTRY);
			} else {
				int sg64s_size = 0;
				int tmplength = length;
				int64_t span4G, length0;
				struct SG64ENTRY *dma_sg;

				/*LINTED*/
				while (1) {
					dma_sg =
					    (struct SG64ENTRY *)(intptr_t)psge;
					span4G =
					    (int64_t)address_lo + tmplength;

					dma_sg->addresshigh = address_hi;
					dma_sg->address = address_lo;
					if (span4G > 0x100000000ULL) {
						/* see if we cross 4G */
						length0 = 0x100000000ULL -
						    address_lo;
						dma_sg->length =
						    (uint32_t)length0 |
						    IS_SG64_ADDR;
						address_hi = address_hi + 1;
						address_lo = 0;
						tmplength = tmplength-
						    (int32_t)length0;
						sg64s_size +=
						    sizeof (struct SG64ENTRY);
						psge +=
						    sizeof (struct SG64ENTRY);
						cdb_sgcount++;
					} else {
						dma_sg->length = tmplength |
						    IS_SG64_ADDR;
						sg64s_size +=
						    sizeof (struct SG64ENTRY);
						psge +=
						    sizeof (struct SG64ENTRY);
						break;
					}
				}
				arccdbsize += sg64s_size;
			}
			cdb_sgcount++;
		}
		arcmsr_cdb->sgcount = (uint8_t)cdb_sgcount;
		arcmsr_cdb->DataLength = total_xfer_length;
		if (arccdbsize > 256) {
			arcmsr_cdb->Flags |= ARCMSR_CDB_FLAG_SGL_BSIZE;
		}
	} else {
		arcmsr_cdb->DataLength = 0;
	}

	if (ccb->ccb_flags & CCB_FLAG_DMAWRITE)
		arcmsr_cdb->Flags |= ARCMSR_CDB_FLAG_WRITE;
}

/*
 * arcmsr_post_ccb - Send a protocol specific ARC send postcard to a AIOC.
 *
 * handle:		Handle of registered ARC protocol driver
 * adapter_id:		AIOC unique identifier(integer)
 * pPOSTCARD_SEND:	Pointer to ARC send postcard
 *
 * This routine posts a ARC send postcard to the request post FIFO of a
 * specific ARC adapter.
 */
static int
arcmsr_post_ccb(struct ACB *acb, struct CCB *ccb) {

	uint32_t cdb_shifted_phyaddr = ccb->cdb_shifted_phyaddr;
	struct scsi_pkt *pkt = ccb->pkt;
	struct ARCMSR_CDB *arcmsr_cdb;

	arcmsr_cdb = (struct ARCMSR_CDB *)&ccb->arcmsr_cdb;

	/* Use correct offset and size for syncing */
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, acb->dma_sync_size,
	    DDI_DMA_SYNC_FORDEV) == DDI_FAILURE)
		return (DDI_FAILURE);

	acb->ccboutstandingcount++;
	ccb->startdone = ARCMSR_CCB_START;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;

		if (arcmsr_cdb->Flags & ARCMSR_CDB_FLAG_SGL_BSIZE) {
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->inbound_queueport,
			    cdb_shifted_phyaddr |
			    ARCMSR_CCBPOST_FLAG_SGL_BSIZE);
		} else {
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->inbound_queueport, cdb_shifted_phyaddr);
		}
		if (pkt->pkt_flags & FLAG_NOINTR)
			arcmsr_polling_hba_ccbdone(acb, ccb);
	}
		break;
	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;
		int ending_index, index;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		mutex_enter(&acb->postq_mutex);
		index = phbbmu->postq_index;
		ending_index = ((index+1)%ARCMSR_MAX_HBB_POSTQUEUE);
		phbbmu->post_qbuffer[ending_index] = 0;
		if (arcmsr_cdb->Flags & ARCMSR_CDB_FLAG_SGL_BSIZE) {
			phbbmu->post_qbuffer[index] =
			    (cdb_shifted_phyaddr|ARCMSR_CCBPOST_FLAG_SGL_BSIZE);
		} else {
			phbbmu->post_qbuffer[index] = cdb_shifted_phyaddr;
		}
		index++;
		/* if last index number set it to 0 */
		index %= ARCMSR_MAX_HBB_POSTQUEUE;
		phbbmu->postq_index = index;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_DRV2IOP_CDB_POSTED);
		mutex_exit(&acb->postq_mutex);
		if (pkt->pkt_flags & FLAG_NOINTR)
			arcmsr_polling_hbb_ccbdone(acb, ccb);
	}
	break;
	}

	return (DDI_SUCCESS);
}




static struct QBUFFER *
arcmsr_get_iop_rqbuffer(struct ACB *acb) {

	struct QBUFFER *qb;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		qb = (struct QBUFFER *)&phbamu->message_rbuffer;
	}
		break;
	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		qb = (struct QBUFFER *)&phbbmu->hbb_rwbuffer->message_rbuffer;
	}
		break;
	}

	return (qb);
}



static struct QBUFFER *
arcmsr_get_iop_wqbuffer(struct ACB *acb) {

	struct QBUFFER *qbuffer = NULL;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		qbuffer = (struct QBUFFER *)&phbamu->message_wbuffer;
	}
	break;
	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		qbuffer =
		    (struct QBUFFER *)&phbbmu->hbb_rwbuffer->message_wbuffer;
	}
	break;
	}
	return (qbuffer);
}



static void
arcmsr_iop_message_read(struct ACB *acb) {

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/* let IOP know the data has been read */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->inbound_doorbell,
		    ARCMSR_INBOUND_DRIVER_DATA_READ_OK);
	}
	break;
	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		/* let IOP know the data has been read */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_DRV2IOP_DATA_READ_OK);
	}
	break;
	}
}



static void
arcmsr_iop_message_wrote(struct ACB *acb) {

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/*
		 * push inbound doorbell tell iop, driver data write ok
		 * and wait reply on next hwinterrupt for next Qbuffer post
		 */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->inbound_doorbell,
		    ARCMSR_INBOUND_DRIVER_DATA_WRITE_OK);
	}
	break;
	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		/*
		 * push inbound doorbell tell iop, driver data was writen
		 * successfully, then await reply on next hwinterrupt for
		 * next Qbuffer post
		 */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_DRV2IOP_DATA_WRITE_OK);
	}
	break;
	}
}



static void
arcmsr_post_ioctldata2iop(struct ACB *acb) {

	uint8_t *pQbuffer;
	struct QBUFFER *pwbuffer;
	uint8_t *iop_data;
	int32_t allxfer_len = 0;

	pwbuffer = arcmsr_get_iop_wqbuffer(acb);
	iop_data = (uint8_t *)pwbuffer->data;
	if (acb->acb_flags & ACB_F_MESSAGE_WQBUFFER_READ) {
		acb->acb_flags &= (~ACB_F_MESSAGE_WQBUFFER_READ);
		while ((acb->wqbuf_firstidx != acb->wqbuf_lastidx) &&
		    (allxfer_len < 124)) {
			pQbuffer = &acb->wqbuffer[acb->wqbuf_firstidx];
			(void) memcpy(iop_data, pQbuffer, 1);
			acb->wqbuf_firstidx++;
			/* if last index number set it to 0 */
			acb->wqbuf_firstidx %= ARCMSR_MAX_QBUFFER;
			iop_data++;
			allxfer_len++;
		}
		pwbuffer->data_len = allxfer_len;
		/*
		 * push inbound doorbell and wait reply at hwinterrupt
		 * routine for next Qbuffer post
		 */
		arcmsr_iop_message_wrote(acb);
	}
}



static void
arcmsr_stop_hba_bgrb(struct ACB *acb) {

	struct HBA_msgUnit *phbamu;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	acb->acb_flags &= ~ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbamu->inbound_msgaddr0,
	    ARCMSR_INBOUND_MESG0_STOP_BGRB);
	if (!arcmsr_hba_wait_msgint_ready(acb))
		cmn_err(CE_WARN,
		    "arcmsr%d: timeout while waiting for background "
		    "rebuild completion",
		    ddi_get_instance(acb->dev_info));
}


static void
arcmsr_stop_hbb_bgrb(struct ACB *acb) {

	struct HBB_msgUnit *phbbmu;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	acb->acb_flags &= ~ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_MESSAGE_STOP_BGRB);

	if (!arcmsr_hbb_wait_msgint_ready(acb))
		cmn_err(CE_WARN,
		    "arcmsr%d: timeout while waiting for background "
		    "rebuild completion",
		    ddi_get_instance(acb->dev_info));
}

static int
arcmsr_iop_message_xfer(struct ACB *acb, struct scsi_pkt *pkt) {

	struct CMD_MESSAGE_FIELD *pcmdmessagefld;
	struct CCB *ccb = pkt->pkt_ha_private;
	struct buf *bp = ccb->bp;
	uint8_t *pQbuffer;
	int retvalue = 0, transfer_len = 0;
	char *buffer;
	uint32_t controlcode;


	/* 4 bytes: Areca io control code */
	controlcode = (uint32_t)pkt->pkt_cdbp[5] << 24 |
	    (uint32_t)pkt->pkt_cdbp[6] << 16 |
	    (uint32_t)pkt->pkt_cdbp[7] << 8 |
	    (uint32_t)pkt->pkt_cdbp[8];

	if (bp->b_flags & (B_PHYS | B_PAGEIO))
		bp_mapin(bp);


	buffer = bp->b_un.b_addr;
	transfer_len = bp->b_bcount;
	if (transfer_len > sizeof (struct CMD_MESSAGE_FIELD)) {
		retvalue = ARCMSR_MESSAGE_FAIL;
		goto message_out;
	}

	pcmdmessagefld = (struct CMD_MESSAGE_FIELD *)(intptr_t)buffer;

	switch (controlcode) {
	case ARCMSR_MESSAGE_READ_RQBUFFER:
	{
		unsigned long *ver_addr;
		uint8_t *ptmpQbuffer;
		int32_t allxfer_len = 0;

		ver_addr = kmem_zalloc(MSGDATABUFLEN, KM_SLEEP);
		if (!ver_addr) {
			retvalue = ARCMSR_MESSAGE_FAIL;
			goto message_out;
		}

		ptmpQbuffer = (uint8_t *)ver_addr;
		while ((acb->rqbuf_firstidx != acb->rqbuf_lastidx) &&
		    (allxfer_len < (MSGDATABUFLEN - 1))) {
			pQbuffer = &acb->rqbuffer[acb->rqbuf_firstidx];
			(void) memcpy(ptmpQbuffer, pQbuffer, 1);
			acb->rqbuf_firstidx++;
			acb->rqbuf_firstidx %= ARCMSR_MAX_QBUFFER;
			ptmpQbuffer++;
			allxfer_len++;
		}

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			struct QBUFFER *prbuffer;
			uint8_t  *iop_data;
			int32_t iop_len;

			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			prbuffer = arcmsr_get_iop_rqbuffer(acb);
			iop_data = (uint8_t *)prbuffer->data;
			iop_len = (int32_t)prbuffer->data_len;

			while (iop_len > 0) {
				pQbuffer = &acb->rqbuffer[acb->rqbuf_lastidx];
				(void) memcpy(pQbuffer, iop_data, 1);
				acb->rqbuf_lastidx++;
				acb->rqbuf_lastidx %= ARCMSR_MAX_QBUFFER;
				iop_data++;
				iop_len--;
			}
			arcmsr_iop_message_read(acb);
		}

		(void) memcpy(pcmdmessagefld->messagedatabuffer,
		    (uint8_t *)ver_addr, allxfer_len);
		pcmdmessagefld->cmdmessage.Length = allxfer_len;
		pcmdmessagefld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;
		kmem_free(ver_addr, MSGDATABUFLEN);
	}
	break;
	case ARCMSR_MESSAGE_WRITE_WQBUFFER:
	{
		unsigned long *ver_addr;
		int32_t my_empty_len, user_len, wqbuf_firstidx, wqbuf_lastidx;
		uint8_t *ptmpuserbuffer;

		ver_addr = kmem_zalloc(MSGDATABUFLEN, KM_SLEEP);
		if (!ver_addr) {
			retvalue = ARCMSR_MESSAGE_FAIL;
			goto message_out;
		}
		ptmpuserbuffer = (uint8_t *)ver_addr;
		user_len = pcmdmessagefld->cmdmessage.Length;
		(void) memcpy(ptmpuserbuffer, pcmdmessagefld->messagedatabuffer,
		    user_len);
		wqbuf_lastidx = acb->wqbuf_lastidx;
		wqbuf_firstidx = acb->wqbuf_firstidx;
		if (wqbuf_lastidx != wqbuf_firstidx) {
			struct scsi_arq_status *arq_status;

			arcmsr_post_ioctldata2iop(acb);
			arq_status =
			    (struct scsi_arq_status *)(intptr_t)
			    (pkt->pkt_scbp);
			bzero((caddr_t)arq_status,
			    sizeof (struct scsi_arq_status));
			arq_status->sts_rqpkt_reason = CMD_CMPLT;
			arq_status->sts_rqpkt_state = (STATE_GOT_BUS |
			    STATE_GOT_TARGET |STATE_SENT_CMD |
			    STATE_XFERRED_DATA | STATE_GOT_STATUS);

			arq_status->sts_rqpkt_statistics = pkt->pkt_statistics;
			arq_status->sts_rqpkt_resid = 0;
			if (&arq_status->sts_sensedata != NULL) {
				struct scsi_extended_sense *sts_sensedata;

				sts_sensedata = &arq_status->sts_sensedata;

				/* has error report sensedata */
				sts_sensedata->es_code = 0x0;
				sts_sensedata->es_valid = 0x01;
				sts_sensedata->es_key = KEY_ILLEGAL_REQUEST;
				/* AdditionalSenseLength */
				sts_sensedata->es_add_len = 0x0A;
				/* AdditionalSenseCode */
				sts_sensedata->es_add_code = 0x20;
			}
			retvalue = ARCMSR_MESSAGE_FAIL;
		} else {
			my_empty_len = (wqbuf_firstidx-wqbuf_lastidx - 1) &
			    (ARCMSR_MAX_QBUFFER - 1);
			if (my_empty_len >= user_len) {
				while (user_len > 0) {
					pQbuffer =
					    &acb->wqbuffer[acb->wqbuf_lastidx];
					(void) memcpy(pQbuffer,
					    ptmpuserbuffer, 1);
					acb->wqbuf_lastidx++;
					acb->wqbuf_lastidx %=
					    ARCMSR_MAX_QBUFFER;
					ptmpuserbuffer++;
					user_len--;
				}
				if (acb->acb_flags &
				    ACB_F_MESSAGE_WQBUFFER_CLEARED) {
					acb->acb_flags &=
					    ~ACB_F_MESSAGE_WQBUFFER_CLEARED;
					arcmsr_post_ioctldata2iop(acb);
				}
			} else {
				struct scsi_arq_status *arq_status;

				/* has error report sensedata */
				arq_status =
				    (struct scsi_arq_status *)
				    (intptr_t)(pkt->pkt_scbp);
				bzero((caddr_t)arq_status,
				    sizeof (struct scsi_arq_status));
				arq_status->sts_rqpkt_reason = CMD_CMPLT;
				arq_status->sts_rqpkt_state = (STATE_GOT_BUS |
				    STATE_GOT_TARGET |STATE_SENT_CMD |
				    STATE_XFERRED_DATA | STATE_GOT_STATUS);
				arq_status->sts_rqpkt_statistics =
				    pkt->pkt_statistics;
				arq_status->sts_rqpkt_resid = 0;
				if (&arq_status->sts_sensedata != NULL) {
					struct scsi_extended_sense
					    *sts_sensedata;

					sts_sensedata =
					    &arq_status->sts_sensedata;

					/* has error report sensedata */
					sts_sensedata->es_code  = 0x0;
					sts_sensedata->es_valid = 0x01;
					sts_sensedata->es_key =
					    KEY_ILLEGAL_REQUEST;
					/* AdditionalSenseLength */
					sts_sensedata->es_add_len = 0x0A;
					/* AdditionalSenseCode */
					sts_sensedata->es_add_code = 0x20;
				}
				retvalue = ARCMSR_MESSAGE_FAIL;
			}
		}
		kmem_free(ver_addr, MSGDATABUFLEN);
	}
	break;
	case ARCMSR_MESSAGE_CLEAR_RQBUFFER:
	{
		pQbuffer = acb->rqbuffer;

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			arcmsr_iop_message_read(acb);
		}
		acb->acb_flags |= ACB_F_MESSAGE_RQBUFFER_CLEARED;
		acb->rqbuf_firstidx = 0;
		acb->rqbuf_lastidx = 0;
		(void) memset(pQbuffer, 0, ARCMSR_MAX_QBUFFER);
		pcmdmessagefld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;
	}
	break;
	case ARCMSR_MESSAGE_CLEAR_WQBUFFER:
	{
		pQbuffer = acb->wqbuffer;

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			arcmsr_iop_message_read(acb);
		}
		acb->acb_flags |= (ACB_F_MESSAGE_WQBUFFER_CLEARED |
		    ACB_F_MESSAGE_WQBUFFER_READ);
		acb->wqbuf_firstidx = 0;
		acb->wqbuf_lastidx = 0;
		(void) memset(pQbuffer, 0, ARCMSR_MAX_QBUFFER);
		pcmdmessagefld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;
	}
	break;
	case ARCMSR_MESSAGE_CLEAR_ALLQBUFFER:
	{

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			arcmsr_iop_message_read(acb);
		}
		acb->acb_flags |= (ACB_F_MESSAGE_WQBUFFER_CLEARED |
		    ACB_F_MESSAGE_RQBUFFER_CLEARED |
		    ACB_F_MESSAGE_WQBUFFER_READ);
		acb->rqbuf_firstidx = 0;
		acb->rqbuf_lastidx = 0;
		acb->wqbuf_firstidx = 0;
		acb->wqbuf_lastidx = 0;
		pQbuffer = acb->rqbuffer;
		(void) memset(pQbuffer, 0, sizeof (struct QBUFFER));
		pQbuffer = acb->wqbuffer;
		(void) memset(pQbuffer, 0, sizeof (struct QBUFFER));
		pcmdmessagefld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;
	}
	break;
	case ARCMSR_MESSAGE_REQUEST_RETURN_CODE_3F:
		pcmdmessagefld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_3F;
		break;
	/*
	 * Not supported - ARCMSR_MESSAGE_SAY_HELLO
	 */
	case ARCMSR_MESSAGE_SAY_GOODBYE:
		arcmsr_iop_parking(acb);
		break;
	case ARCMSR_MESSAGE_FLUSH_ADAPTER_CACHE:
		if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
			arcmsr_flush_hba_cache(acb);
		} else {
			arcmsr_flush_hbb_cache(acb);
		}
		break;
	default:
		retvalue = ARCMSR_MESSAGE_FAIL;
	}

message_out:

	return (retvalue);
}



static int
arcmsr_cb_ioctl(dev_t dev, int ioctl_cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp) {
#ifndef __lock_lint
	_NOTE(ARGUNUSED(rvalp))
#endif

	struct ACB *acb;
	struct CMD_MESSAGE_FIELD *pktioctlfld;
	int retvalue = 0;
	int instance = MINOR2INST(getminor(dev));

	if (instance < 0)
		return (ENXIO);

	if (secpolicy_sys_config(credp, B_FALSE) != 0)
		return (EPERM);

	acb = ddi_get_soft_state(arcmsr_soft_state, instance);
	if (acb == NULL)
		return (ENXIO);

	pktioctlfld = kmem_zalloc(sizeof (struct CMD_MESSAGE_FIELD),
	    KM_SLEEP);
	if (pktioctlfld == NULL)
		return (ENXIO);

	/*
	 * if we got here, we either are a 64-bit app in a 64-bit kernel
	 * or a 32-bit app in a 32-bit kernel. Either way, we can just
	 * copy in the args without any special conversions.
	 */

	mutex_enter(&acb->ioctl_mutex);
	if (ddi_copyin((void *)arg, pktioctlfld,
	    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0) {
		retvalue = ENXIO;
		goto ioctl_out;
	}

	if (memcmp(pktioctlfld->cmdmessage.Signature, "ARCMSR", 6) != 0) {
		/* validity check */
		retvalue = ENXIO;
		goto ioctl_out;
	}

	switch ((unsigned int)ioctl_cmd) {
	case ARCMSR_MESSAGE_READ_RQBUFFER:
	{
		unsigned long *ver_addr;
		uint8_t *pQbuffer, *ptmpQbuffer;
		int32_t allxfer_len = 0;

		ver_addr = kmem_zalloc(MSGDATABUFLEN, KM_SLEEP);
		if (ver_addr == NULL) {
			retvalue = ENXIO;
			goto ioctl_out;
		}

		ptmpQbuffer = (uint8_t *)ver_addr;
		while ((acb->rqbuf_firstidx != acb->rqbuf_lastidx) &&
		    (allxfer_len < (MSGDATABUFLEN - 1))) {
			/* copy READ QBUFFER to srb */
			pQbuffer = &acb->rqbuffer[acb->rqbuf_firstidx];
			(void) memcpy(ptmpQbuffer, pQbuffer, 1);
			acb->rqbuf_firstidx++;
			/* if last index number set it to 0 */
			acb->rqbuf_firstidx %= ARCMSR_MAX_QBUFFER;
			ptmpQbuffer++;
			allxfer_len++;
		}

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			struct QBUFFER *prbuffer;
			uint8_t *pQbuffer;
			uint8_t *iop_data;
			int32_t iop_len;

			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			prbuffer = arcmsr_get_iop_rqbuffer(acb);
			iop_data = (uint8_t *)prbuffer->data;
			iop_len = (int32_t)prbuffer->data_len;
			/*
			 * this iop data does no chance to make me overflow
			 * again here, so just do it
			 */
			while (iop_len > 0) {
				pQbuffer = &acb->rqbuffer[acb->rqbuf_lastidx];
				(void) memcpy(pQbuffer, iop_data, 1);
				acb->rqbuf_lastidx++;
				/* if last index number set it to 0 */
				acb->rqbuf_lastidx %= ARCMSR_MAX_QBUFFER;
				iop_data++;
				iop_len--;
			}
			/* let IOP know data has been read */
			arcmsr_iop_message_read(acb);
		}
		(void) memcpy(pktioctlfld->messagedatabuffer,
		    (uint8_t *)ver_addr, allxfer_len);
		pktioctlfld->cmdmessage.Length = allxfer_len;
		pktioctlfld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;

		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;

		kmem_free(ver_addr, MSGDATABUFLEN);
	}
	break;
	case ARCMSR_MESSAGE_WRITE_WQBUFFER:
	{
		unsigned long *ver_addr;
		int32_t my_empty_len, user_len;
		int32_t wqbuf_firstidx, wqbuf_lastidx;
		uint8_t *pQbuffer, *ptmpuserbuffer;

		ver_addr = kmem_zalloc(MSGDATABUFLEN, KM_SLEEP);

		if (ver_addr == NULL) {
			retvalue = ENXIO;
			goto ioctl_out;
		}

		ptmpuserbuffer = (uint8_t *)ver_addr;
		user_len = pktioctlfld->cmdmessage.Length;
		(void) memcpy(ptmpuserbuffer,
		    pktioctlfld->messagedatabuffer, user_len);
		/*
		 * check ifdata xfer length of this request will overflow
		 * my array qbuffer
		 */
		wqbuf_lastidx = acb->wqbuf_lastidx;
		wqbuf_firstidx = acb->wqbuf_firstidx;
		if (wqbuf_lastidx != wqbuf_firstidx) {
			arcmsr_post_ioctldata2iop(acb);
			pktioctlfld->cmdmessage.ReturnCode =
			    ARCMSR_MESSAGE_RETURNCODE_ERROR;
		} else {
			my_empty_len = (wqbuf_firstidx - wqbuf_lastidx - 1)
			    & (ARCMSR_MAX_QBUFFER - 1);
			if (my_empty_len >= user_len) {
				while (user_len > 0) {
					/* copy srb data to wqbuffer */
					pQbuffer =
					    &acb->wqbuffer[acb->wqbuf_lastidx];
					(void) memcpy(pQbuffer,
					    ptmpuserbuffer, 1);
					acb->wqbuf_lastidx++;
					/* iflast index number set it to 0 */
					acb->wqbuf_lastidx %=
					    ARCMSR_MAX_QBUFFER;
					ptmpuserbuffer++;
					user_len--;
				}
				/* post first Qbuffer */
				if (acb->acb_flags &
				    ACB_F_MESSAGE_WQBUFFER_CLEARED) {
					acb->acb_flags &=
					    ~ACB_F_MESSAGE_WQBUFFER_CLEARED;
					arcmsr_post_ioctldata2iop(acb);
				}
				pktioctlfld->cmdmessage.ReturnCode =
				    ARCMSR_MESSAGE_RETURNCODE_OK;
			} else {
				pktioctlfld->cmdmessage.ReturnCode =
				    ARCMSR_MESSAGE_RETURNCODE_ERROR;
			}
		}
		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;

		kmem_free(ver_addr, MSGDATABUFLEN);
	}
	break;
	case ARCMSR_MESSAGE_CLEAR_RQBUFFER:
	{
		uint8_t *pQbuffer = acb->rqbuffer;

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
				arcmsr_iop_message_read(acb);
		}
		acb->acb_flags |= ACB_F_MESSAGE_RQBUFFER_CLEARED;
		acb->rqbuf_firstidx = 0;
		acb->rqbuf_lastidx = 0;
		bzero(pQbuffer, ARCMSR_MAX_QBUFFER);
		/* report success */
		pktioctlfld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;
		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;

	}
	break;
	case ARCMSR_MESSAGE_CLEAR_WQBUFFER:
	{
		uint8_t *pQbuffer = acb->wqbuffer;

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			arcmsr_iop_message_read(acb);
		}
		acb->acb_flags |= (ACB_F_MESSAGE_WQBUFFER_CLEARED |
		    ACB_F_MESSAGE_WQBUFFER_READ);
		acb->wqbuf_firstidx = 0;
		acb->wqbuf_lastidx = 0;
		bzero(pQbuffer, ARCMSR_MAX_QBUFFER);
		/* report success */
		pktioctlfld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;
		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;

	}
	break;
	case ARCMSR_MESSAGE_CLEAR_ALLQBUFFER:
	{
		uint8_t *pQbuffer;

		if (acb->acb_flags & ACB_F_IOPDATA_OVERFLOW) {
			acb->acb_flags &= ~ACB_F_IOPDATA_OVERFLOW;
			arcmsr_iop_message_read(acb);
		}
		acb->acb_flags |= (ACB_F_MESSAGE_WQBUFFER_CLEARED |
		    ACB_F_MESSAGE_RQBUFFER_CLEARED |
		    ACB_F_MESSAGE_WQBUFFER_READ);
		acb->rqbuf_firstidx = 0;
		acb->rqbuf_lastidx = 0;
		acb->wqbuf_firstidx = 0;
		acb->wqbuf_lastidx = 0;
		pQbuffer = acb->rqbuffer;
		bzero(pQbuffer, sizeof (struct QBUFFER));
		pQbuffer = acb->wqbuffer;
		bzero(pQbuffer, sizeof (struct QBUFFER));
		/* report success */
		pktioctlfld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;
		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;

	}
	break;
	case ARCMSR_MESSAGE_REQUEST_RETURN_CODE_3F:
	{
		pktioctlfld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_3F;
		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;
	}
	break;
	/* Not supported: ARCMSR_MESSAGE_SAY_HELLO */
	case ARCMSR_MESSAGE_SAY_GOODBYE:
		arcmsr_iop_parking(acb);
		break;
	case ARCMSR_MESSAGE_FLUSH_ADAPTER_CACHE:
		if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
			arcmsr_flush_hba_cache(acb);
		} else {
			arcmsr_flush_hbb_cache(acb);
		}
		break;
	default:
		retvalue = ENOTTY;
	}

ioctl_out:
	kmem_free(pktioctlfld, sizeof (struct CMD_MESSAGE_FIELD));
	mutex_exit(&acb->ioctl_mutex);

	return (retvalue);
}



static struct CCB *
arcmsr_get_freeccb(struct ACB *acb) {

	struct CCB *ccb;
	int workingccb_startindex, workingccb_doneindex;


	mutex_enter(&acb->workingQ_mutex);
	workingccb_doneindex = acb->workingccb_doneindex;
	workingccb_startindex = acb->workingccb_startindex;
	ccb = acb->ccbworkingQ[workingccb_startindex];
	workingccb_startindex++;
	workingccb_startindex %= ARCMSR_MAX_FREECCB_NUM;
	if (workingccb_doneindex != workingccb_startindex) {
		acb->workingccb_startindex = workingccb_startindex;
	} else {
		ccb = NULL;
	}

	mutex_exit(&acb->workingQ_mutex);
	return (ccb);
}



static int
arcmsr_seek_cmd2abort(struct ACB *acb,
    struct scsi_pkt *abortpkt) {

	struct CCB *ccb;
	uint32_t intmask_org = 0;
	int i = 0;

	acb->num_aborts++;

	if (abortpkt == NULL) {
		/*
		 * if abortpkt is NULL, the upper layer needs us
		 * to abort all commands
		 */
		if (acb->ccboutstandingcount != 0) {
			/* disable all outbound interrupt */
			intmask_org = arcmsr_disable_allintr(acb);
			/* clear and abort all outbound posted Q */
			arcmsr_done4abort_postqueue(acb);
			/* talk to iop 331 outstanding command aborted */
			if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
				arcmsr_abort_hba_allcmd(acb);
			} else {
				arcmsr_abort_hbb_allcmd(acb);
			}

			for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
				ccb = acb->pccb_pool[i];
				if (ccb->startdone == ARCMSR_CCB_START) {
					/*
					 * this ccb will complete at
					 * hwinterrupt
					 */
					ccb->startdone = ARCMSR_CCB_ABORTED;
					ccb->pkt->pkt_reason = CMD_ABORTED;
					ccb->pkt->pkt_statistics |=
					    STAT_ABORTED;
					arcmsr_ccb_complete(ccb, 1);
				}
			}
			/*
			 * enable outbound Post Queue, outbound
			 * doorbell Interrupt
			 */
			arcmsr_enable_allintr(acb, intmask_org);
		}
		return (DDI_SUCCESS);
	}

	/*
	 * It is the upper layer do abort command this lock
	 * just prior to calling us.
	 * First determine if we currently own this command.
	 * Start by searching the device queue. If not found
	 * at all, and the system wanted us to just abort the
	 * command returnsuccess.
	 */

	if (acb->ccboutstandingcount != 0) {
		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->startdone == ARCMSR_CCB_START) {
				if (ccb->pkt == abortpkt) {
					ccb->startdone =
					    ARCMSR_CCB_ABORTED;
					goto abort_outstanding_cmd;
				}
			}
		}
	}

	return (DDI_FAILURE);

abort_outstanding_cmd:
	/* disable all outbound interrupts */
	intmask_org = arcmsr_disable_allintr(acb);
	if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
		arcmsr_polling_hba_ccbdone(acb, ccb);
	} else {
		arcmsr_polling_hbb_ccbdone(acb, ccb);
	}

	/* enable outbound Post Queue, outbound doorbell Interrupt */
	arcmsr_enable_allintr(acb, intmask_org);
	return (DDI_SUCCESS);
}



static void
arcmsr_pcidev_disattach(struct ACB *acb) {

	struct CCB *ccb;
	int i = 0;

	/* disable all outbound interrupts */
	(void) arcmsr_disable_allintr(acb);
	/* stop adapter background rebuild */
	if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
		arcmsr_stop_hba_bgrb(acb);
		arcmsr_flush_hba_cache(acb);
	} else {
		arcmsr_stop_hbb_bgrb(acb);
		arcmsr_flush_hbb_cache(acb);
	}
	/* abort all outstanding commands */
	acb->acb_flags |= ACB_F_SCSISTOPADAPTER;
	acb->acb_flags &= ~ACB_F_IOP_INITED;

	if (acb->ccboutstandingcount != 0) {
		/* clear and abort all outbound posted Q */
		arcmsr_done4abort_postqueue(acb);
		/* talk to iop 331 outstanding command aborted */
		if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
			arcmsr_abort_hba_allcmd(acb);
		} else {
			arcmsr_abort_hbb_allcmd(acb);
		}

		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->startdone == ARCMSR_CCB_START) {
				ccb->startdone = ARCMSR_CCB_ABORTED;
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
			}
		}
	}
}

/* get firmware miscellaneous data */
static void
arcmsr_get_hba_config(struct ACB *acb) {

	struct HBA_msgUnit *phbamu;

	char *acb_firm_model;
	char *acb_firm_version;
	char *iop_firm_model;
	char *iop_firm_version;
	int count;

	phbamu = (struct HBA_msgUnit *)acb->pmu;
	acb_firm_model = acb->firm_model;
	acb_firm_version = acb->firm_version;
	/* firm_model, 15 */
	iop_firm_model = (char *)
	    (&phbamu->msgcode_rwbuffer[ARCMSR_FW_MODEL_OFFSET]);
	/* firm_version, 17 */
	iop_firm_version =
	    (char *)(&phbamu->msgcode_rwbuffer[ARCMSR_FW_VERS_OFFSET]);

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbamu->inbound_msgaddr0,
	    ARCMSR_INBOUND_MESG0_GET_CONFIG);

	if (!arcmsr_hba_wait_msgint_ready(acb))
		cmn_err(CE_CONT,
		    "arcmsr%d: timeout while waiting for adapter firmware "
		    "miscellaneous data",
		    ddi_get_instance(acb->dev_info));

	count = 8;
	while (count) {
		*acb_firm_model =
		    CHIP_REG_READ8(acb->reg_mu_acc_handle0, iop_firm_model);
		acb_firm_model++;
		iop_firm_model++;
		count--;
	}

	count = 16;
	while (count) {
		*acb_firm_version =
		    CHIP_REG_READ8(acb->reg_mu_acc_handle0, iop_firm_version);
		acb_firm_version++;
		iop_firm_version++;
		count--;
	}

	cmn_err(CE_CONT, "arcmsr%d: ARECA RAID FIRMWARE VERSION %s",
	    ddi_get_instance(acb->dev_info), acb->firm_version);

	/* firm_request_len, 1 */
	acb->firm_request_len = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->msgcode_rwbuffer[1]);
	/* firm_numbers_queue, 2 */
	acb->firm_numbers_queue = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->msgcode_rwbuffer[2]);
	/* firm_sdram_size, 3 */
	acb->firm_sdram_size = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->msgcode_rwbuffer[3]);
	/* firm_ide_channels, 4 */
	acb->firm_ide_channels = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->msgcode_rwbuffer[4]);
}

/* get firmware miscellaneous data */
static void
arcmsr_get_hbb_config(struct ACB *acb) {

	struct HBB_msgUnit *phbbmu;
	char *acb_firm_model;
	char *acb_firm_version;
	char *iop_firm_model;
	char *iop_firm_version;
	int count;


	phbbmu = (struct HBB_msgUnit *)acb->pmu;
	acb_firm_model = acb->firm_model;
	acb_firm_version = acb->firm_version;
	/* firm_model, 15 */
	iop_firm_model = (char *)
	    (&phbbmu->hbb_rwbuffer->msgcode_rwbuffer[ARCMSR_FW_MODEL_OFFSET]);
	/* firm_version, 17 */
	iop_firm_version = (char *)
	    (&phbbmu->hbb_rwbuffer->msgcode_rwbuffer[ARCMSR_FW_VERS_OFFSET]);



	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_MESSAGE_GET_CONFIG);

	if (!arcmsr_hbb_wait_msgint_ready(acb))
		cmn_err(CE_CONT,
		    "arcmsr%d: timeout while waiting for adapter firmware "
		    "miscellaneous data",
		    ddi_get_instance(acb->dev_info));

	count = 8;
	while (count) {
		*acb_firm_model = CHIP_REG_READ8(acb->reg_mu_acc_handle1,
		    iop_firm_model);
		acb_firm_model++;
		iop_firm_model++;
		count--;
	}

	count = 16;
	while (count) {
		*acb_firm_version = CHIP_REG_READ8(acb->reg_mu_acc_handle1,
		    iop_firm_version);
		acb_firm_version++;
		iop_firm_version++;
		count--;
	}

	cmn_err(CE_CONT, "arcmsr%d: ARECA RAID FIRMWARE VERSION %s",
	    ddi_get_instance(acb->dev_info), acb->firm_version);

	/* firm_request_len, 1 */
	acb->firm_request_len = CHIP_REG_READ32(acb->reg_mu_acc_handle1,
		&phbbmu->hbb_rwbuffer->msgcode_rwbuffer[1]);
	/* firm_numbers_queue, 2 */
	acb->firm_numbers_queue = CHIP_REG_READ32(acb->reg_mu_acc_handle1,
	    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[2]);
	/* firm_sdram_size, 3 */
	acb->firm_sdram_size = CHIP_REG_READ32(acb->reg_mu_acc_handle1,
	    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[3]);
	/* firm_ide_channels, 4 */
	acb->firm_ide_channels = CHIP_REG_READ32(acb->reg_mu_acc_handle1,
	    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[4]);
}



/* start background rebuild */
static void
arcmsr_start_hba_bgrb(struct ACB *acb) {

	struct HBA_msgUnit *phbamu;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	acb->acb_flags |= ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbamu->inbound_msgaddr0, ARCMSR_INBOUND_MESG0_START_BGRB);

	if (!arcmsr_hba_wait_msgint_ready(acb))
		cmn_err(CE_WARN,
		    "arcmsr%d: timeout while waiting for background "
		    "rebuild to start",
		    ddi_get_instance(acb->dev_info));
}


static void
arcmsr_start_hbb_bgrb(struct ACB *acb) {

	struct HBB_msgUnit *phbbmu;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	acb->acb_flags |= ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_MESSAGE_START_BGRB);

	if (!arcmsr_hbb_wait_msgint_ready(acb))
		cmn_err(CE_WARN,
		    "arcmsr%d: timeout while waiting for background "
		    "rebuild to start",
		    ddi_get_instance(acb->dev_info));
}


static void
arcmsr_polling_hba_ccbdone(struct ACB *acb, struct CCB *poll_ccb) {

	struct HBA_msgUnit *phbamu;
	struct CCB *ccb;
	uint32_t flag_ccb, outbound_intstatus;
	uint32_t poll_ccb_done = 0;
	uint32_t poll_count = 0;


	phbamu = (struct HBA_msgUnit *)acb->pmu;

polling_ccb_retry:
	poll_count++;
	outbound_intstatus = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_intstatus) & acb->outbound_int_enable;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbamu->outbound_intstatus,
	    outbound_intstatus); /* clear interrupt */

	/* Use correct offset and size for syncing */
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, acb->dma_sync_size,
	    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS)
		return;

	/*LINTED*/
	while (1) {
		if ((flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_queueport)) == 0xFFFFFFFF) {
			if (poll_ccb_done) {
				/* chip FIFO no ccb for completion already */
				break;
			} else {
				drv_usecwait(25000);
				if (poll_count > 100) {
					break;
				}
				goto polling_ccb_retry;
			}
		}

		/* check ifcommand done with no error */
		ccb = (struct CCB *)(acb->vir2phy_offset  +
		    (flag_ccb << 5)); /* frame must be 32 bytes aligned */
		poll_ccb_done = (ccb == poll_ccb) ? 1 : 0;

		if ((ccb->acb != acb) ||
		    (ccb->startdone != ARCMSR_CCB_START)) {
			if (ccb->startdone == ARCMSR_CCB_ABORTED) {
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
				continue;
			}
			cmn_err(CE_WARN, "arcmsr%d: polling op got "
			    "unexpected ccb command done",
			    ddi_get_instance(acb->dev_info));
			continue;
		}
		arcmsr_report_ccb_state(acb, ccb, flag_ccb);
	}	/* drain reply FIFO */
}


static void
arcmsr_polling_hbb_ccbdone(struct ACB *acb,
    struct CCB *poll_ccb) {

	struct HBB_msgUnit *phbbmu;
	struct CCB *ccb;
	uint32_t flag_ccb;
	uint32_t poll_ccb_done = 0;
	uint32_t poll_count = 0;
	int index;


	phbbmu = (struct HBB_msgUnit *)acb->pmu;


polling_ccb_retry:
	poll_count++;
	/* clear doorbell interrupt */
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->iop2drv_doorbell,
	    ARCMSR_DOORBELL_INT_CLEAR_PATTERN);

	/* Use correct offset and size for syncing */
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, acb->dma_sync_size,
	    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS)
		return;


	/*LINTED*/
	while (1) {
		index = phbbmu->doneq_index;
		if ((flag_ccb = phbbmu->done_qbuffer[index]) == 0) {
			if (poll_ccb_done) {
				/* chip FIFO no ccb for completion already */
				break;
			} else {
				drv_usecwait(25000);
				if (poll_count > 100)
					break;

				goto polling_ccb_retry;
			}
		}

		phbbmu->done_qbuffer[index] = 0;
		index++;
		/* if last index number set it to 0 */
		index %= ARCMSR_MAX_HBB_POSTQUEUE;
		phbbmu->doneq_index = index;
		/* check if command done with no error */
		/* frame must be 32 bytes aligned */
		ccb = (struct CCB *)(acb->vir2phy_offset +
		    (flag_ccb << 5));
		poll_ccb_done = (ccb == poll_ccb) ? 1 : 0;
		if ((ccb->acb != acb) || (ccb->startdone != ARCMSR_CCB_START)) {
			if (ccb->startdone == ARCMSR_CCB_ABORTED) {
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
				continue;
			}
			cmn_err(CE_WARN, "arcmsr%d: polling op got"
			    "unexpect ccb command done",
			    ddi_get_instance(acb->dev_info));
			continue;
		}
		arcmsr_report_ccb_state(acb, ccb, flag_ccb);
	}	/* drain reply FIFO */
}


/*
 *    Function: arcmsr_tran_start(9E)
 * Description: Transport the command in pktp to the target device.
 *		The command is not finished when this returns, only
 *		sent to the target; arcmsr_interrupt will call
 *		(*pktp->pkt_comp)(pktp) when the target device has done.
 *
 *       Input: struct scsi_address *ap, struct scsi_pkt *pktp
 *      Output:	TRAN_ACCEPT if pkt is OK and not driver not busy
 *		TRAN_BUSY if driver is
 *		TRAN_BADPKT if pkt is invalid
 */
static int
arcmsr_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt) {

	struct ACB *acb;
	struct CCB *ccb;
	int target = ap->a_target;
	int lun = ap->a_lun;


	acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;
	ccb = pkt->pkt_ha_private;

	if ((ccb->ccb_flags & CCB_FLAG_DMAVALID) &&
	    (ccb->ccb_flags & DDI_DMA_CONSISTENT))
		(void) ddi_dma_sync(ccb->pkt_dma_handle, ccb->pkt_dma_offset,
		    ccb->pkt_dma_len, DDI_DMA_SYNC_FORDEV);


	if (ccb->startdone == ARCMSR_CCB_UNBUILD)
		arcmsr_build_ccb(ccb);


	if (acb->acb_flags & ACB_F_BUS_RESET) {
		cmn_err(CE_CONT,
		    "arcmsr%d: bus reset returned busy",
		    ddi_get_instance(acb->dev_info));
		pkt->pkt_reason = CMD_RESET;
		pkt->pkt_statistics |= STAT_BUS_RESET;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		if ((ccb->ccb_flags & CCB_FLAG_DMACONSISTENT) &&
		    (pkt->pkt_state & STATE_XFERRED_DATA))
			(void) ddi_dma_sync(ccb->pkt_dma_handle,
			    ccb->pkt_dma_offset, ccb->pkt_dma_len,
			    DDI_DMA_SYNC_FORCPU);

		if (pkt->pkt_comp)
			(*pkt->pkt_comp)(pkt);


		return (TRAN_ACCEPT);
	}

	if (acb->devstate[target][lun] == ARECA_RAID_GONE) {
		uint8_t block_cmd;

		block_cmd = pkt->pkt_cdbp[0] & 0x0f;

		if (block_cmd == 0x08 || block_cmd == 0x0a) {
			cmn_err(CE_CONT,
			    "arcmsr%d: block read/write command while raid"
			    "volume missing (cmd %02x for target %d lun %d)",
			    ddi_get_instance(acb->dev_info),
			    block_cmd, target, lun);
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= CMD_TIMEOUT;
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_GOT_STATUS);

			if ((ccb->ccb_flags & CCB_FLAG_DMACONSISTENT) &&
			    (pkt->pkt_state & STATE_XFERRED_DATA))
				(void) ddi_dma_sync(ccb->pkt_dma_handle,
				    ccb->pkt_dma_offset, ccb->pkt_dma_len,
				    DDI_DMA_SYNC_FORCPU);


			if (pkt->pkt_comp)
				(*pkt->pkt_comp)(pkt);


			return (TRAN_ACCEPT);
		}
	}


	/* IMPORTANT: Target 16 is a virtual device for iop message transfer */
	if (target == 16) {

		struct buf *bp = ccb->bp;
		uint8_t scsicmd = pkt->pkt_cdbp[0];

		switch (scsicmd) {
		case SCMD_INQUIRY: {
			if (lun != 0) {
				ccb->pkt->pkt_reason = CMD_TIMEOUT;
				ccb->pkt->pkt_statistics |= STAT_TIMEOUT;
				arcmsr_ccb_complete(ccb, 0);
				return (TRAN_ACCEPT);
			}

			if (bp && bp->b_un.b_addr && bp->b_bcount) {
				uint8_t inqdata[36];

				/* The EVDP and pagecode is not supported */
				if (pkt->pkt_cdbp[1] || pkt->pkt_cdbp[2]) {
					inqdata[1] = 0xFF;
					inqdata[2] = 0x00;
				} else {
					/* Periph Qualifier & Periph Dev Type */
					inqdata[0] = DTYPE_PROCESSOR;
					/* rem media bit & Dev Type Modifier */
					inqdata[1] = 0;
					/* ISO, ECMA, & ANSI versions */
					inqdata[2] = 0;
					/* length of additional data */
					inqdata[4] = 31;
					/* Vendor Identification */
					bcopy("Areca   ",
					    &inqdata[8], VIDLEN);
					/* Product Identification */
					bcopy("RAID controller ",
					    &inqdata[16], PIDLEN);
					/* Product Revision */
					bcopy(&inqdata[32],
					    "R001", REVLEN);
					if (bp->b_flags & (B_PHYS | B_PAGEIO))
						bp_mapin(bp);

					(void) memcpy(bp->b_un.b_addr,
					    inqdata, sizeof (inqdata));
				}
				ccb->pkt->pkt_state |= STATE_XFERRED_DATA;
			}
			arcmsr_ccb_complete(ccb, 0);
			return (TRAN_ACCEPT);
		}
		case SCMD_WRITE_BUFFER:
		case SCMD_READ_BUFFER: {
			if (arcmsr_iop_message_xfer(acb, pkt)) {
				/* error just for retry */
				ccb->pkt->pkt_reason = CMD_TRAN_ERR;
				ccb->pkt->pkt_statistics |= STAT_TERMINATED;
			}
			ccb->pkt->pkt_state |= STATE_XFERRED_DATA;
			arcmsr_ccb_complete(ccb, 0);
			return (TRAN_ACCEPT);
		}
		default:
			ccb->pkt->pkt_state |= STATE_XFERRED_DATA;
			arcmsr_ccb_complete(ccb, 0);
			return (TRAN_ACCEPT);
		}
	}

	if (acb->ccboutstandingcount >= ARCMSR_MAX_OUTSTANDING_CMD) {
		cmn_err(CE_CONT,
		    "arcmsr%d: too many outstanding commands (%d > %d)",
		    ddi_get_instance(acb->dev_info),
		    acb->ccboutstandingcount,
		    ARCMSR_MAX_OUTSTANDING_CMD);
		return (TRAN_BUSY);
	} else if (arcmsr_post_ccb(acb, ccb) == DDI_FAILURE) {
		cmn_err(CE_CONT,
		    "arcmsr%d: post failure, ccboutstandingcount = %d",
		    ddi_get_instance(acb->dev_info),
		    acb->ccboutstandingcount);
		return (TRAN_BUSY);
	}

    return (TRAN_ACCEPT);
}

/*
 * Function: arcmsr_tran_abort(9E)
 * 		SCSA interface routine to abort pkt(s) in progress.
 * 		Aborts the pkt specified.  If NULL pkt, aborts ALL pkts.
 * Output:	Return 1 if success
 *		Return 0 if failure
 */
static int
arcmsr_tran_abort(struct scsi_address *ap, struct scsi_pkt *abortpkt) {

	struct ACB *acb;
	int return_code;

	acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;


	cmn_err(CE_WARN,
	    "arcmsr%d: tran_abort called for target %d lun %d",
	    ddi_get_instance(acb->dev_info), ap->a_target, ap->a_lun);

	while (acb->ccboutstandingcount != 0) {
		drv_usecwait(10000);
	}

	mutex_enter(&acb->acb_mutex);
	return_code = arcmsr_seek_cmd2abort(acb, abortpkt);
	mutex_exit(&acb->acb_mutex);

	if (return_code != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "arcmsr%d: abort command failed for target %d lun %d",
		    ddi_get_instance(acb->dev_info),
		    ap->a_target, ap->a_lun);
		return (0);
	}

	return (1);
}

/*
 * Function: arcmsr_tran_reset(9E)
 *           SCSA interface routine to perform scsi resets on either
 *           a specified target or the bus (default).
 *   Output: Return 1 if success
 *	     Return 0 if failure
 */
static int
arcmsr_tran_reset(struct scsi_address *ap, int level) {

	struct ACB *acb;
	int return_code = 1;
	int retry = 0;


	/* Are we in the middle of dumping core? */
	if (ddi_in_panic())
		return (return_code);

	acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;

	cmn_err(CE_WARN, "arcmsr%d: tran reset (level 0x%x) called "
	    "for target %d lun %d",
	    ddi_get_instance(acb->dev_info), level,
	    ap->a_target, ap->a_lun);
	mutex_enter(&acb->acb_mutex);

	while ((acb->ccboutstandingcount > 0) && (retry < 400)) {
		(void) arcmsr_interrupt((caddr_t)acb);
		drv_usecwait(25000);
		retry++;
	}

	switch (level) {
	case RESET_ALL:		/* level 1 */
		acb->num_resets++;
		acb->acb_flags |= ACB_F_BUS_RESET;
		arcmsr_iop_reset(acb);
		acb->acb_flags &= ~ACB_F_BUS_RESET;
		return_code = 0;
		break;
	case RESET_TARGET:	/* level 0 */
		cmn_err(CE_WARN, "arcmsr%d: target reset not supported",
		    ddi_get_instance(acb->dev_info));
		return_code = 0;
		break;
	default:
		return_code = 0;
	}

	mutex_exit(&acb->acb_mutex);
	return (return_code);
}


static void
arcmsr_log(struct ACB *acb, int level, char *fmt, ...) {

	char	buf[256];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);
	scsi_log(acb ? acb->dev_info : NULL, "arcmsr", level, "%s", buf);
}


static void
arcmsr_iop2drv_data_wrote_handle(struct ACB *acb) {

	struct QBUFFER *prbuffer;
	uint8_t *pQbuffer;
	uint8_t *iop_data;
	int my_empty_len, iop_len;
	int rqbuf_firstidx, rqbuf_lastidx;

	/* check this iop data if overflow my rqbuffer */
	rqbuf_lastidx = acb->rqbuf_lastidx;
	rqbuf_firstidx = acb->rqbuf_firstidx;
	prbuffer = arcmsr_get_iop_rqbuffer(acb);
	iop_data = (uint8_t *)prbuffer->data;
	iop_len = prbuffer->data_len;
	my_empty_len = (rqbuf_firstidx-rqbuf_lastidx - 1) &
	    (ARCMSR_MAX_QBUFFER - 1);

	if (my_empty_len >= iop_len) {
		while (iop_len > 0) {
			pQbuffer = &acb->rqbuffer[rqbuf_lastidx];
			(void) memcpy(pQbuffer, iop_data, 1);
			rqbuf_lastidx++;
			/* if last index number set it to 0 */
			rqbuf_lastidx %= ARCMSR_MAX_QBUFFER;
			iop_data++;
			iop_len--;
		}
		acb->rqbuf_lastidx = rqbuf_lastidx;
		arcmsr_iop_message_read(acb);
		/* signature, let IOP know data has been read */
	} else {
		acb->acb_flags |= ACB_F_IOPDATA_OVERFLOW;
	}
}



static void
arcmsr_iop2drv_data_read_handle(struct ACB *acb) {

	acb->acb_flags |= ACB_F_MESSAGE_WQBUFFER_READ;
	/*
	 * check if there are any mail packages from user space program
	 * in my post bag, now is the time to send them into Areca's firmware
	 */

	if (acb->wqbuf_firstidx != acb->wqbuf_lastidx) {

		uint8_t *pQbuffer;
		struct QBUFFER *pwbuffer;
		uint8_t *iop_data;
		int allxfer_len = 0;

		acb->acb_flags &= (~ACB_F_MESSAGE_WQBUFFER_READ);
		pwbuffer = arcmsr_get_iop_wqbuffer(acb);
		iop_data = (uint8_t *)pwbuffer->data;

		while ((acb->wqbuf_firstidx != acb->wqbuf_lastidx) &&
		    (allxfer_len < 124)) {
			pQbuffer = &acb->wqbuffer[acb->wqbuf_firstidx];
			(void) memcpy(iop_data, pQbuffer, 1);
			acb->wqbuf_firstidx++;
			/* if last index number set it to 0 */
			acb->wqbuf_firstidx %= ARCMSR_MAX_QBUFFER;
			iop_data++;
			allxfer_len++;
		}
		pwbuffer->data_len = allxfer_len;
		/*
		 * push inbound doorbell, tell iop driver data write ok
		 * await reply on next hwinterrupt for next Qbuffer post
		 */
		arcmsr_iop_message_wrote(acb);
	}

	if (acb->wqbuf_firstidx == acb->wqbuf_lastidx)
		acb->acb_flags |= ACB_F_MESSAGE_WQBUFFER_CLEARED;
}


static void
arcmsr_hba_doorbell_isr(struct ACB *acb) {

	uint32_t outbound_doorbell;
	struct HBA_msgUnit *phbamu;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	/*
	 *  Maybe here we need to check wrqbuffer_lock is locked or not
	 *  DOORBELL: ding! dong!
	 *  check if there are any mail need to pack from firmware
	 */

	outbound_doorbell = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_doorbell);
	/* clear doorbell interrupt */
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_doorbell, outbound_doorbell);

	if (outbound_doorbell & ARCMSR_OUTBOUND_IOP331_DATA_WRITE_OK)
		arcmsr_iop2drv_data_wrote_handle(acb);


	if (outbound_doorbell & ARCMSR_OUTBOUND_IOP331_DATA_READ_OK)
		arcmsr_iop2drv_data_read_handle(acb);
}



static void
arcmsr_hba_postqueue_isr(struct ACB *acb) {

	uint32_t flag_ccb;
	struct HBA_msgUnit *phbamu;


	phbamu = (struct HBA_msgUnit *)acb->pmu;

	/* areca cdb command done */
	/* Use correct offset and size for syncing */
	(void) ddi_dma_sync(acb->ccbs_pool_handle, 0, acb->dma_sync_size,
	    DDI_DMA_SYNC_FORKERNEL);

	while ((flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_queueport)) != 0xFFFFFFFF) {
		/* check if command done with no error */
		arcmsr_drain_donequeue(acb, flag_ccb);
	}	/* drain reply FIFO */
}



static void
arcmsr_hbb_postqueue_isr(struct ACB *acb) {

	int index;
	uint32_t flag_ccb;
	struct HBB_msgUnit *phbbmu;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;


	/* areca cdb command done */
	index = phbbmu->doneq_index;

	while ((flag_ccb = phbbmu->done_qbuffer[index]) != 0) {
		phbbmu->done_qbuffer[index] = 0;
		index++;
		/* if last index number set it to 0 */
		index %= ARCMSR_MAX_HBB_POSTQUEUE;
		phbbmu->doneq_index = index;
		/* check if command done with no error */
		arcmsr_drain_donequeue(acb, flag_ccb);
	}	/* drain reply FIFO */
}


static uint_t
arcmsr_handle_hba_isr(struct ACB *acb) {

	uint32_t outbound_intstatus;
	struct HBA_msgUnit *phbamu;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	outbound_intstatus = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_intstatus) & acb->outbound_int_enable;

	if (!outbound_intstatus)
		/* it must be a shared irq */
		return (DDI_INTR_UNCLAIMED);

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbamu->outbound_intstatus,
	    outbound_intstatus); /* clear interrupt */


	/* MU doorbell interrupts */

	if (outbound_intstatus & ARCMSR_MU_OUTBOUND_DOORBELL_INT)
		arcmsr_hba_doorbell_isr(acb);

	/* MU post queue interrupts */
	if (outbound_intstatus & ARCMSR_MU_OUTBOUND_POSTQUEUE_INT)
		arcmsr_hba_postqueue_isr(acb);

	/*
	 * The following block is commented out pending confirmation from
	 * Areca whether it is or is not truly required
	 */
	/* MU message interrupt */
	/*
	 * if (outbound_intstatus & ARCMSR_MU_OUTBOUND_MESSAGE0_INT) {
	 *	arcmsr_hba_message_isr(acb);
	 * }
	 */
	return (DDI_INTR_CLAIMED);
}


static uint_t
arcmsr_handle_hbb_isr(struct ACB *acb) {

	uint32_t outbound_doorbell;
	struct HBB_msgUnit *phbbmu;


	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	outbound_doorbell = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->iop2drv_doorbell) & acb->outbound_int_enable;

	if (!outbound_doorbell)
		/* it must be a shared irq */
		return (DDI_INTR_UNCLAIMED);

	/* clear doorbell interrupt */
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->iop2drv_doorbell, ~outbound_doorbell);
	/* wait a cycle */
	(void) CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->iop2drv_doorbell);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_DRV2IOP_END_OF_INTERRUPT);

	/* MU ioctl transfer doorbell interrupts */
	if (outbound_doorbell & ARCMSR_IOP2DRV_DATA_WRITE_OK)
		arcmsr_iop2drv_data_wrote_handle(acb);

	if (outbound_doorbell & ARCMSR_IOP2DRV_DATA_READ_OK)
		arcmsr_iop2drv_data_read_handle(acb);

	/* MU post queue interrupts */
	if (outbound_doorbell & ARCMSR_IOP2DRV_CDB_DONE)
		arcmsr_hbb_postqueue_isr(acb);

	/*
	 * The following block is commented out pending confirmation from
	 * Areca whether it is or is not truly required
	 */
	/* MU message interrupt */
	/*
	 * if (outbound_doorbell & ARCMSR_IOP2DRV_MESSAGE_CMD_DONE) {
	 *		arcmsr_hbb_message_isr(acb);
	 *	}
	 */
	return (DDI_INTR_CLAIMED);
}


static uint_t
arcmsr_interrupt(caddr_t arg) {


	struct ACB *acb = (struct ACB *)(intptr_t)arg;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
		return (arcmsr_handle_hba_isr(acb));
	case ACB_ADAPTER_TYPE_B:
		return (arcmsr_handle_hbb_isr(acb));
	default:
		cmn_err(CE_WARN, "arcmsr%d: unknown adapter type (%d)",
		    ddi_get_instance(acb->dev_info), acb->adapter_type);
		return (DDI_INTR_UNCLAIMED);
	}
}


static void
arcmsr_wait_firmware_ready(struct ACB *acb) {

	uint32_t firmware_state;

	firmware_state = 0;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		do {
			firmware_state =
			    CHIP_REG_READ32(acb->reg_mu_acc_handle0,
			    &phbamu->outbound_msgaddr1);
		} while ((firmware_state & ARCMSR_OUTBOUND_MESG1_FIRMWARE_OK)
		    == 0);
	}
	break;
	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		do {
			firmware_state =
			    CHIP_REG_READ32(acb->reg_mu_acc_handle0,
				    &phbbmu->hbb_doorbell->iop2drv_doorbell);
		} while ((firmware_state & ARCMSR_MESSAGE_FIRMWARE_OK) == 0);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_DRV2IOP_END_OF_INTERRUPT);
	}
	break;
	}
}

static void
arcmsr_clear_doorbell_queue_buffer(struct ACB *acb) {

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;
		uint32_t outbound_doorbell;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/* empty doorbell Qbuffer if door bell rung */
		outbound_doorbell = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_doorbell);
		/* clear doorbell interrupt */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_doorbell, outbound_doorbell);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->inbound_doorbell,
		    ARCMSR_INBOUND_DRIVER_DATA_READ_OK);
	}
	break;
	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;

		/* clear interrupt and message state */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell,
		    ARCMSR_MESSAGE_INT_CLEAR_PATTERN);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_DRV2IOP_DATA_READ_OK);
		/* let IOP know data has been read */
	}
	break;
	}
}


static uint32_t
arcmsr_iop_confirm(struct ACB *acb) {

	unsigned long ccb_phyaddr;
	uint32_t ccb_phyaddr_hi32;

	/*
	 * here we need to tell iop 331 about our freeccb.HighPart
	 * if freeccb.HighPart is non-zero
	 */
	ccb_phyaddr = (unsigned long)acb->ccb_cookie.dmac_address;
	ccb_phyaddr_hi32 = (uint32_t)((ccb_phyaddr >> 16) >> 16);

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		if (ccb_phyaddr_hi32 != 0) {
			struct HBA_msgUnit *phbamu;

			phbamu = (struct HBA_msgUnit *)acb->pmu;
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->msgcode_rwbuffer[0],
			    ARCMSR_SIGNATURE_SET_CONFIG);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->msgcode_rwbuffer[1], ccb_phyaddr_hi32);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->inbound_msgaddr0,
			    ARCMSR_INBOUND_MESG0_SET_CONFIG);
			if (!arcmsr_hba_wait_msgint_ready(acb)) {
				cmn_err(CE_WARN,
				    "arcmsr%d: timeout setting ccb high "
				    "physical address",
				    ddi_get_instance(acb->dev_info));
				return (FALSE);
			}
		}
	}
	break;

	/* if adapter is type B, set window of "post command queue" */

	case ACB_ADAPTER_TYPE_B:
	{
		uint32_t post_queue_phyaddr;
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		phbbmu->postq_index = 0;
		phbbmu->doneq_index = 0;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_MESSAGE_SET_POST_WINDOW);

		if (!arcmsr_hbb_wait_msgint_ready(acb)) {
			cmn_err(CE_WARN,
			    "arcmsr%d: timeout setting post command "
			    "queue window",
			    ddi_get_instance(acb->dev_info));
			return (FALSE);
		}

		post_queue_phyaddr = ccb_phyaddr +
		    ARCMSR_MAX_FREECCB_NUM *
		    sizeof (struct CCB)
		    + ARCOFFSET(struct HBB_msgUnit, post_qbuffer);
		/* driver "set config" signature */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle1,
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[0],
		    ARCMSR_SIGNATURE_SET_CONFIG);
		/* normal should be zero */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle1,
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[1],
		    ccb_phyaddr_hi32);
		/* postQ size (256+8)*4 */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle1,
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[2],
		    post_queue_phyaddr);
		/* doneQ size (256+8)*4 */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle1,
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[3],
		    post_queue_phyaddr+1056);
		/* ccb maxQ size must be --> [(256+8)*4] */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle1,
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[4], 1056);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_MESSAGE_SET_CONFIG);

		if (!arcmsr_hbb_wait_msgint_ready(acb)) {
			cmn_err(CE_WARN,
			    "arcmsr%d: timeout setting command queue window",
			    ddi_get_instance(acb->dev_info));
			return (FALSE);
		}
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_MESSAGE_START_DRIVER_MODE);

		if (!arcmsr_hbb_wait_msgint_ready(acb)) {
			cmn_err(CE_WARN,
			    "arcmsr%d: timeout in 'start driver mode'",
			    ddi_get_instance(acb->dev_info));
			return (FALSE);
		}
	}
	break;
	}
	return (TRUE);
}


/*
 * ONLY used for Adapter type B
 */
static void
arcmsr_enable_eoi_mode(struct ACB *acb) {

	struct HBB_msgUnit *phbbmu;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_MESSAGE_ACTIVE_EOI_MODE);

	if (!arcmsr_hbb_wait_msgint_ready(acb))
		cmn_err(CE_WARN,
		    "arcmsr%d (Adapter type B): "
		    "'iop enable eoi mode' timeout ",
		    ddi_get_instance(acb->dev_info));

}

/* start background rebuild */
static void
arcmsr_iop_init(struct ACB *acb) {

	uint32_t intmask_org;

	/* disable all outbound interrupt */
	intmask_org = arcmsr_disable_allintr(acb);
	arcmsr_wait_firmware_ready(acb);
	(void) arcmsr_iop_confirm(acb);

	/* start background rebuild */
	if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
		arcmsr_get_hba_config(acb);
		arcmsr_start_hba_bgrb(acb);
	} else {
		arcmsr_get_hbb_config(acb);
		arcmsr_start_hbb_bgrb(acb);
	}

	/* empty doorbell Qbuffer if door bell rang */
	arcmsr_clear_doorbell_queue_buffer(acb);

	if (acb->adapter_type == ACB_ADAPTER_TYPE_B)
		arcmsr_enable_eoi_mode(acb);

	/* enable outbound Post Queue, outbound doorbell Interrupt */
	arcmsr_enable_allintr(acb, intmask_org);
	acb->acb_flags |= ACB_F_IOP_INITED;
}


static int
arcmsr_initialize(struct ACB *acb) {

	struct CCB *pccb_tmp;
	size_t allocated_length;
	uint16_t wval;
	uint32_t wlval;
	uint_t intmask_org, count;
	caddr_t	arcmsr_ccbs_area;
	unsigned long ccb_phyaddr;
	int32_t dma_sync_size;
	int i, id, lun;

	acb->irq = pci_config_get8(acb->pci_acc_handle,
	    ARCMSR_PCI2PCI_PRIMARY_INTERRUPT_LINE_REG);
	wlval = pci_config_get32(acb->pci_acc_handle, 0);
	wval = (uint16_t)((wlval >> 16) & 0xffff);

	if (wval == PCI_DEVICE_ID_ARECA_1201) {
		uint32_t *iop_mu_regs_map0;
		uint32_t *iop_mu_regs_map1;
		struct CCB *freeccb;
		struct HBB_msgUnit *phbbmu;

		acb->adapter_type = ACB_ADAPTER_TYPE_B; /* marvell */
		dma_sync_size = (ARCMSR_MAX_FREECCB_NUM*
		    sizeof (struct CCB) + 0x20) +
		    sizeof (struct HBB_msgUnit);


		/* Allocate memory for the ccb */
		if ((i = ddi_dma_alloc_handle(acb->dev_info,
		    &arcmsr_ccb_attr, DDI_DMA_SLEEP, NULL,
		    &acb->ccbs_pool_handle)) != DDI_SUCCESS) {
			switch (i) {
			case DDI_DMA_BADATTR:
				cmn_err(CE_WARN,
				    "arcmsr%d: ddi_dma_alloc_handle got "
				    "DDI_DMA_BADATTR",
				    ddi_get_instance(acb->dev_info));
				return (DDI_FAILURE);

			case DDI_DMA_NORESOURCES:
				cmn_err(CE_WARN, "arcmsr%d: "
				    "ddi_dma_alloc_handle got "
				    "DDI_DMA_NORESOURCES ",
				    ddi_get_instance(acb->dev_info));
				return (DDI_FAILURE);
			}
			cmn_err(CE_WARN,
			    "arcmsr%d: ddi_dma_alloc_handle got DDI_FAILURE",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}

		if (ddi_dma_mem_alloc(acb->ccbs_pool_handle, dma_sync_size,
		    &acb->dev_acc_attr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, (caddr_t *)&arcmsr_ccbs_area,
		    &allocated_length, &acb->ccbs_acc_handle)
		    != DDI_SUCCESS) {
			cmn_err(CE_CONT,
			    "arcmsr%d: ddi_dma_mem_alloc failed ",
			    ddi_get_instance(acb->dev_info));
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}

		if (ddi_dma_addr_bind_handle(acb->ccbs_pool_handle, NULL,
		    (caddr_t)arcmsr_ccbs_area, dma_sync_size,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
		    NULL, &acb->ccb_cookie, &count) != DDI_DMA_MAPPED) {
			cmn_err(CE_WARN,
			    "arcmsr%d: ddi_dma_addr_bind_handle failed",
			    ddi_get_instance(acb->dev_info));
			ddi_dma_mem_free(&acb->ccbs_acc_handle);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}
		bzero(arcmsr_ccbs_area, dma_sync_size);
		freeccb = (struct CCB *)(intptr_t)arcmsr_ccbs_area;
		acb->pmu = (struct msgUnit *)
		    &freeccb[ARCMSR_MAX_FREECCB_NUM];
		phbbmu = (struct HBB_msgUnit *)acb->pmu;

		/* setup device register */
		if (ddi_regs_map_setup(acb->dev_info, 1,
		    (caddr_t *)&iop_mu_regs_map0, 0,
		    sizeof (struct HBB_DOORBELL), &acb->dev_acc_attr,
		    &acb->reg_mu_acc_handle0) != DDI_SUCCESS) {
			arcmsr_log(NULL, CE_WARN,
			    "arcmsr%d: unable to map PCI device "
			    "base0 address registers",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}

		/* ARCMSR_DRV2IOP_DOORBELL */
		phbbmu->hbb_doorbell =
		    (struct HBB_DOORBELL *)iop_mu_regs_map0;
		if (ddi_regs_map_setup(acb->dev_info, 2,
		    (caddr_t *)&iop_mu_regs_map1, 0,
		    sizeof (struct HBB_RWBUFFER), &acb->dev_acc_attr,
		    &acb->reg_mu_acc_handle1) != DDI_SUCCESS) {
			arcmsr_log(NULL, CE_WARN,
			    "arcmsr%d: unable to map PCI device "
			    "base1 address registers",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}

		/* ARCMSR_MSGCODE_RWBUFFER */
		phbbmu->hbb_rwbuffer =
		    (struct HBB_RWBUFFER *)iop_mu_regs_map1;
	} else {
		uint32_t *iop_mu_regs_map0;

		acb->adapter_type = ACB_ADAPTER_TYPE_A; /* intel */
		dma_sync_size = ARCMSR_MAX_FREECCB_NUM*
		    sizeof (struct CCB) + 0x20;
		if (ddi_regs_map_setup(acb->dev_info, 1,
		    (caddr_t *)&iop_mu_regs_map0, 0,
		    sizeof (struct HBA_msgUnit), &acb->dev_acc_attr,
		    &acb->reg_mu_acc_handle0) != DDI_SUCCESS) {
			arcmsr_log(NULL, CE_WARN,
			    "arcmsr%d: unable to map registers",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}

		if ((i = ddi_dma_alloc_handle(acb->dev_info, &arcmsr_ccb_attr,
		    DDI_DMA_SLEEP, NULL, &acb->ccbs_pool_handle)) !=
		    DDI_SUCCESS) {
			switch (i) {
			case DDI_DMA_BADATTR:
				cmn_err(CE_WARN,
				    "arcmsr%d: ddi_dma_alloc_handle "
				    "got DDI_DMA_BADATTR",
				    ddi_get_instance(acb->dev_info));
				return (DDI_FAILURE);
			case DDI_DMA_NORESOURCES:
				cmn_err(CE_WARN, "arcmsr%d: "
				    "ddi_dma_alloc_handle got "
				    "DDI_DMA_NORESOURCES",
				    ddi_get_instance(acb->dev_info));
				return (DDI_FAILURE);
			}
			cmn_err(CE_WARN,
			    "arcmsr%d: ddi_dma_alloc_handle failed",
			    ddi_get_instance(acb->dev_info));
			return (DDI_FAILURE);
		}

		if (ddi_dma_mem_alloc(acb->ccbs_pool_handle, dma_sync_size,
		    &acb->dev_acc_attr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, (caddr_t *)&arcmsr_ccbs_area,
		    &allocated_length, &acb->ccbs_acc_handle)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "arcmsr%d: ddi_dma_mem_alloc failed",
			    ddi_get_instance(acb->dev_info));
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}

		if (ddi_dma_addr_bind_handle(acb->ccbs_pool_handle, NULL,
		    (caddr_t)arcmsr_ccbs_area, dma_sync_size, DDI_DMA_RDWR |
		    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &acb->ccb_cookie,
		    &count) != DDI_DMA_MAPPED) {
			cmn_err(CE_WARN, "arcmsr%d: ddi_dma_addr_bind_handle "
			    "failed",
			    ddi_get_instance(acb->dev_info));
			ddi_dma_mem_free(&acb->ccbs_acc_handle);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}
		bzero(arcmsr_ccbs_area, dma_sync_size);
		/* ioport base */
		acb->pmu = (struct msgUnit *)(intptr_t)iop_mu_regs_map0;
	}

	/* here we can not access pci configuration again */
	acb->acb_flags |= (ACB_F_MESSAGE_WQBUFFER_CLEARED |
	    ACB_F_MESSAGE_RQBUFFER_CLEARED | ACB_F_MESSAGE_WQBUFFER_READ);
	acb->acb_flags &= ~ACB_F_SCSISTOPADAPTER;
	/* physical address of acb->pccb_pool */
	ccb_phyaddr = acb->ccb_cookie.dmac_address;

	if (((unsigned long)arcmsr_ccbs_area & 0x1F) != 0) {
		/* ccb address must 32 (0x20) boundary */
		arcmsr_ccbs_area = (caddr_t)((unsigned long)arcmsr_ccbs_area +
		    (0x20 - ((unsigned long)arcmsr_ccbs_area & 0x1F)));
		ccb_phyaddr = (unsigned long)ccb_phyaddr +
		    (0x20 - ((unsigned long)ccb_phyaddr & 0x1F));
	}

	pccb_tmp = (struct CCB *)(intptr_t)arcmsr_ccbs_area;

	for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
		pccb_tmp->cdb_shifted_phyaddr = ccb_phyaddr >> 5;
		pccb_tmp->acb = acb;
		acb->ccbworkingQ[i] = acb->pccb_pool[i] = pccb_tmp;
		ccb_phyaddr = ccb_phyaddr + sizeof (struct CCB);
		pccb_tmp++;
	}

	acb->vir2phy_offset = (unsigned long)pccb_tmp -
	    (unsigned long)ccb_phyaddr;

	/* disable all outbound interrupt */
	intmask_org = arcmsr_disable_allintr(acb);

	if (!arcmsr_iop_confirm(acb)) {
		cmn_err(CE_WARN, "arcmsr%d: arcmsr_iop_confirm error",
		    ddi_get_instance(acb->dev_info));
		ddi_dma_mem_free(&acb->ccbs_acc_handle);
		ddi_dma_free_handle(&acb->ccbs_pool_handle);
		return (DDI_FAILURE);
	}

	for (id = 0; id < ARCMSR_MAX_TARGETID; id++) {
		for (lun = 0; lun < ARCMSR_MAX_TARGETLUN; lun++) {
			acb->devstate[id][lun] = ARECA_RAID_GONE;
		}
	}

	/* enable outbound Post Queue, outbound doorbell Interrupt */
	arcmsr_enable_allintr(acb, intmask_org);

	return (0);
}
