/*
 *       O.S   : Solaris
 *  FILE NAME  : arcmsr.c
 *       BY    : Erich Chen, C.L. Huang
 *  Description: SCSI RAID Device Driver for
 *               ARECA RAID Host adapter
 *
 *  Copyright (C) 2002,2010 Areca Technology Corporation All rights reserved.
 *  Copyright (C) 2002,2010 Erich Chen
 *	    Web site: www.areca.com.tw
 *	      E-mail: erich@areca.com.tw; ching2048@areca.com.tw
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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
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
#include <sys/atomic.h>
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
static int arcmsr_config_child(struct ACB *acb, struct scsi_device *sd,
    dev_info_t **dipp);

static int arcmsr_config_lun(struct ACB *acb, uint16_t tgt, uint8_t lun,
    dev_info_t **ldip);
static uint8_t arcmsr_abort_host_command(struct ACB *acb);
static uint8_t arcmsr_get_echo_from_iop(struct ACB *acb);
static uint_t arcmsr_intr_handler(caddr_t arg, caddr_t arg2);
static int arcmsr_initialize(struct ACB *acb);
static int arcmsr_dma_alloc(struct ACB *acb,
    struct scsi_pkt *pkt, struct buf *bp, int flags, int (*callback)());
static int arcmsr_dma_move(struct ACB *acb,
    struct scsi_pkt *pkt, struct buf *bp);
static void arcmsr_handle_iop_bus_hold(struct ACB *acb);
static void arcmsr_hbc_message_isr(struct ACB *acb);
static void arcmsr_pcidev_disattach(struct ACB *acb);
static void arcmsr_ccb_complete(struct CCB *ccb, int flag);
static void arcmsr_iop_init(struct ACB *acb);
static void arcmsr_iop_parking(struct ACB *acb);
/*PRINTFLIKE3*/
static void arcmsr_log(struct ACB *acb, int level, char *fmt, ...);
/*PRINTFLIKE2*/
static void arcmsr_warn(struct ACB *acb, char *fmt, ...);
static void arcmsr_mutex_init(struct ACB *acb);
static void arcmsr_remove_intr(struct ACB *acb);
static void arcmsr_ccbs_timeout(void* arg);
static void arcmsr_devMap_monitor(void* arg);
static void arcmsr_pcidev_disattach(struct ACB *acb);
static void arcmsr_iop_message_read(struct ACB *acb);
static void arcmsr_free_ccb(struct CCB *ccb);
static void arcmsr_post_ioctldata2iop(struct ACB *acb);
static void arcmsr_report_sense_info(struct CCB *ccb);
static void arcmsr_init_list_head(struct list_head *list);
static void arcmsr_enable_allintr(struct ACB *acb, uint32_t intmask_org);
static void arcmsr_done4abort_postqueue(struct ACB *acb);
static void arcmsr_list_add_tail(kmutex_t *list_lock,
    struct list_head *new_one, struct list_head *head);
static int arcmsr_name_node(dev_info_t *dip, char *name, int len);
static int arcmsr_seek_cmd2abort(struct ACB *acb, struct scsi_pkt *abortpkt);
static int arcmsr_iop_message_xfer(struct ACB *acb, struct scsi_pkt *pkt);
static int arcmsr_post_ccb(struct ACB *acb, struct CCB *ccb);
static int arcmsr_parse_devname(char *devnm, int *tgt, int *lun);
static int arcmsr_do_ddi_attach(dev_info_t *dev_info, int instance);
static uint8_t arcmsr_iop_reset(struct ACB *acb);
static uint32_t arcmsr_disable_allintr(struct ACB *acb);
static uint32_t arcmsr_iop_confirm(struct ACB *acb);
static struct CCB *arcmsr_get_freeccb(struct ACB *acb);
static void arcmsr_flush_hba_cache(struct ACB *acb);
static void arcmsr_flush_hbb_cache(struct ACB *acb);
static void arcmsr_flush_hbc_cache(struct ACB *acb);
static void arcmsr_stop_hba_bgrb(struct ACB *acb);
static void arcmsr_stop_hbb_bgrb(struct ACB *acb);
static void arcmsr_stop_hbc_bgrb(struct ACB *acb);
static void arcmsr_start_hba_bgrb(struct ACB *acb);
static void arcmsr_start_hbb_bgrb(struct ACB *acb);
static void arcmsr_start_hbc_bgrb(struct ACB *acb);
static void arcmsr_mutex_destroy(struct ACB *acb);
static void arcmsr_polling_hba_ccbdone(struct ACB *acb, struct CCB *poll_ccb);
static void arcmsr_polling_hbb_ccbdone(struct ACB *acb, struct CCB *poll_ccb);
static void arcmsr_polling_hbc_ccbdone(struct ACB *acb, struct CCB *poll_ccb);
static void arcmsr_build_ccb(struct CCB *ccb);
static int arcmsr_tran_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int arcmsr_name_node(dev_info_t *dip, char *name, int len);
static dev_info_t *arcmsr_find_child(struct ACB *acb, uint16_t tgt,
    uint8_t lun);
static struct QBUFFER *arcmsr_get_iop_rqbuffer(struct ACB *acb);

static int arcmsr_add_intr(struct ACB *, int);

static void *arcmsr_soft_state = NULL;

static ddi_dma_attr_t arcmsr_dma_attr = {
	DMA_ATTR_V0,		/* ddi_dma_attr version */
	0,			/* low DMA address range */
	0xffffffffffffffffull,	/* high DMA address range */
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
	0xffffffff,
	ARCMSR_MAX_SG_ENTRIES,	/* scatter/gather list count */
	1,			/* device granularity */
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
	D_MP,
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
	NULL			/* power */
};

static struct modldrv arcmsr_modldrv = {
	&mod_driverops,			/* Type of module. This is a driver. */
	"ARECA RAID Controller",	/* module name, from arcmsr.h */
	&arcmsr_ops,			/* driver ops */
};

static struct modlinkage arcmsr_modlinkage = {
	MODREV_1,
	&arcmsr_modldrv,
	NULL
};


int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&arcmsr_soft_state, sizeof (struct ACB), 1);
	if (ret != 0) {
		return (ret);
	}
	if ((ret = scsi_hba_init(&arcmsr_modlinkage)) != 0) {
		ddi_soft_state_fini(&arcmsr_soft_state);
		return (ret);
	}

	if ((ret = mod_install(&arcmsr_modlinkage)) != 0) {
		scsi_hba_fini(&arcmsr_modlinkage);
		if (arcmsr_soft_state != NULL) {
			ddi_soft_state_fini(&arcmsr_soft_state);
		}
	}
	return (ret);
}


int
_fini(void)
{
	int ret;

	ret = mod_remove(&arcmsr_modlinkage);
	if (ret == 0) {
		/* if ret = 0 , said driver can remove */
		scsi_hba_fini(&arcmsr_modlinkage);
		if (arcmsr_soft_state != NULL) {
			ddi_soft_state_fini(&arcmsr_soft_state);
		}
	}
	return (ret);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&arcmsr_modlinkage, modinfop));
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
arcmsr_attach(dev_info_t *dev_info, ddi_attach_cmd_t cmd)
{
	scsi_hba_tran_t *hba_trans;
	struct ACB *acb;

	switch (cmd) {
	case DDI_ATTACH:
		return (arcmsr_do_ddi_attach(dev_info,
		    ddi_get_instance(dev_info)));
	case DDI_RESUME:
		/*
		 * There is no hardware state to restart and no
		 * timeouts to restart since we didn't DDI_SUSPEND with
		 * active cmds or active timeouts We just need to
		 * unblock waiting threads and restart I/O the code
		 */
		hba_trans = ddi_get_driver_private(dev_info);
		if (hba_trans == NULL) {
			return (DDI_FAILURE);
		}
		acb = hba_trans->tran_hba_private;
		mutex_enter(&acb->acb_mutex);
		arcmsr_iop_init(acb);

		/* restart ccbs "timeout" watchdog */
		acb->timeout_count = 0;
		acb->timeout_id = timeout(arcmsr_ccbs_timeout, (caddr_t)acb,
		    (ARCMSR_TIMEOUT_WATCH * drv_usectohz(1000000)));
		acb->timeout_sc_id = timeout(arcmsr_devMap_monitor,
		    (caddr_t)acb,
		    (ARCMSR_DEV_MAP_WATCH * drv_usectohz(1000000)));
		mutex_exit(&acb->acb_mutex);
		return (DDI_SUCCESS);

	default:
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
	acb = ddi_get_soft_state(arcmsr_soft_state, instance);
	if (acb == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		mutex_enter(&acb->acb_mutex);
		if (acb->timeout_id != 0) {
			mutex_exit(&acb->acb_mutex);
			(void) untimeout(acb->timeout_id);
			mutex_enter(&acb->acb_mutex);
			acb->timeout_id = 0;
		}
		if (acb->timeout_sc_id != 0) {
			mutex_exit(&acb->acb_mutex);
			(void) untimeout(acb->timeout_sc_id);
			mutex_enter(&acb->acb_mutex);
			acb->timeout_sc_id = 0;
		}
		arcmsr_pcidev_disattach(acb);
		/* Remove interrupt set up by ddi_add_intr */
		arcmsr_remove_intr(acb);
		/* unbind mapping object to handle */
		(void) ddi_dma_unbind_handle(acb->ccbs_pool_handle);
		/* Free ccb pool memory */
		ddi_dma_mem_free(&acb->ccbs_acc_handle);
		/* Free DMA handle */
		ddi_dma_free_handle(&acb->ccbs_pool_handle);
		ddi_regs_map_free(&acb->reg_mu_acc_handle0);
		if (scsi_hba_detach(dev_info) != DDI_SUCCESS)
			arcmsr_warn(acb, "Unable to detach instance cleanly "
			    "(should not happen)");
		/* free scsi_hba_transport from scsi_hba_tran_alloc */
		scsi_hba_tran_free(acb->scsi_hba_transport);
		ddi_taskq_destroy(acb->taskq);
		ddi_prop_remove_all(dev_info);
		mutex_exit(&acb->acb_mutex);
		arcmsr_mutex_destroy(acb);
		pci_config_teardown(&acb->pci_acc_handle);
		ddi_set_driver_private(dev_info, NULL);
		ddi_soft_state_free(arcmsr_soft_state, instance);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		mutex_enter(&acb->acb_mutex);
		if (acb->timeout_id != 0) {
			acb->acb_flags |= ACB_F_SCSISTOPADAPTER;
			mutex_exit(&acb->acb_mutex);
			(void) untimeout(acb->timeout_id);
			(void) untimeout(acb->timeout_sc_id);
			mutex_enter(&acb->acb_mutex);
			acb->timeout_id = 0;
		}

		if (acb->timeout_sc_id != 0) {
			acb->acb_flags |= ACB_F_SCSISTOPADAPTER;
			mutex_exit(&acb->acb_mutex);
			(void) untimeout(acb->timeout_sc_id);
			mutex_enter(&acb->acb_mutex);
			acb->timeout_sc_id = 0;
		}

		/* disable all outbound interrupt */
		(void) arcmsr_disable_allintr(acb);
		/* stop adapter background rebuild */
		switch (acb->adapter_type) {
		case ACB_ADAPTER_TYPE_A:
			arcmsr_stop_hba_bgrb(acb);
			arcmsr_flush_hba_cache(acb);
			break;

		case ACB_ADAPTER_TYPE_B:
			arcmsr_stop_hbb_bgrb(acb);
			arcmsr_flush_hbb_cache(acb);
			break;

		case ACB_ADAPTER_TYPE_C:
			arcmsr_stop_hbc_bgrb(acb);
			arcmsr_flush_hbc_cache(acb);
			break;
		}
		mutex_exit(&acb->acb_mutex);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
arcmsr_reset(dev_info_t *resetdev, ddi_reset_cmd_t cmd)
{
	struct ACB *acb;
	scsi_hba_tran_t *scsi_hba_transport;
	_NOTE(ARGUNUSED(cmd));

	scsi_hba_transport = ddi_get_driver_private(resetdev);
	if (scsi_hba_transport == NULL)
		return (DDI_FAILURE);

	acb = (struct ACB *)scsi_hba_transport->tran_hba_private;
	if (!acb)
		return (DDI_FAILURE);

	arcmsr_pcidev_disattach(acb);

	return (DDI_SUCCESS);
}

static int
arcmsr_cb_ioctl(dev_t dev, int ioctl_cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
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

	pktioctlfld = kmem_zalloc(sizeof (struct CMD_MESSAGE_FIELD), KM_SLEEP);

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
		uint8_t *ver_addr;
		uint8_t *pQbuffer, *ptmpQbuffer;
		int32_t allxfer_len = 0;

		ver_addr = kmem_zalloc(MSGDATABUFLEN, KM_SLEEP);
		ptmpQbuffer = ver_addr;
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
		    ver_addr, allxfer_len);
		pktioctlfld->cmdmessage.Length = allxfer_len;
		pktioctlfld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_OK;

		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;

		kmem_free(ver_addr, MSGDATABUFLEN);
		break;
	}

	case ARCMSR_MESSAGE_WRITE_WQBUFFER:
	{
		uint8_t *ver_addr;
		int32_t my_empty_len, user_len;
		int32_t wqbuf_firstidx, wqbuf_lastidx;
		uint8_t *pQbuffer, *ptmpuserbuffer;

		ver_addr = kmem_zalloc(MSGDATABUFLEN, KM_SLEEP);

		ptmpuserbuffer = ver_addr;
		user_len = min(pktioctlfld->cmdmessage.Length,
		    MSGDATABUFLEN);
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
		break;
	}

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
		break;
	}

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
		break;
	}

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
		break;
	}

	case ARCMSR_MESSAGE_REQUEST_RETURN_CODE_3F:
		pktioctlfld->cmdmessage.ReturnCode =
		    ARCMSR_MESSAGE_RETURNCODE_3F;
		if (ddi_copyout(pktioctlfld, (void *)arg,
		    sizeof (struct CMD_MESSAGE_FIELD), mode) != 0)
			retvalue = ENXIO;
		break;

	/* Not supported: ARCMSR_MESSAGE_SAY_HELLO */
	case ARCMSR_MESSAGE_SAY_GOODBYE:
		arcmsr_iop_parking(acb);
		break;

	case ARCMSR_MESSAGE_FLUSH_ADAPTER_CACHE:
		switch (acb->adapter_type) {
		case ACB_ADAPTER_TYPE_A:
			arcmsr_flush_hba_cache(acb);
			break;
		case ACB_ADAPTER_TYPE_B:
			arcmsr_flush_hbb_cache(acb);
			break;
		case ACB_ADAPTER_TYPE_C:
			arcmsr_flush_hbc_cache(acb);
			break;
		}
		break;

	default:
		mutex_exit(&acb->ioctl_mutex);
		kmem_free(pktioctlfld, sizeof (struct CMD_MESSAGE_FIELD));
		return (scsi_hba_ioctl(dev, ioctl_cmd, arg, mode, credp,
		    rvalp));
	}

ioctl_out:
	kmem_free(pktioctlfld, sizeof (struct CMD_MESSAGE_FIELD));
	mutex_exit(&acb->ioctl_mutex);

	return (retvalue);
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
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	uint16_t  target;
	uint8_t  lun;
	struct ACB *acb = tran->tran_hba_private;

	_NOTE(ARGUNUSED(tran, target_dev_info, host_dev_info))

	target = sd->sd_address.a_target;
	lun = sd->sd_address.a_lun;
	if ((target >= ARCMSR_MAX_TARGETID) || (lun >= ARCMSR_MAX_TARGETLUN)) {
		return (DDI_FAILURE);
	}


	if (ndi_dev_is_persistent_node(target_dev_info) == 0) {
		/*
		 * If no persistent node exist, we don't allow .conf node
		 * to be created.
		 */
		if (arcmsr_find_child(acb, target, lun) != NULL) {
			if ((ndi_merge_node(target_dev_info,
			    arcmsr_name_node) != DDI_SUCCESS)) {
				return (DDI_SUCCESS);
			}
		}
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
arcmsr_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int capability = 0;
	struct ACB *acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;

	if (cap == NULL || whom == 0) {
		return (DDI_FAILURE);
	}

	mutex_enter(&acb->acb_mutex);
	if (acb->devstate[ap->a_target][ap->a_lun] == ARECA_RAID_GONE) {
		mutex_exit(&acb->acb_mutex);
		return (-1);
	}
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_DISCONNECT:
	case SCSI_CAP_WIDE_XFER:
	case SCSI_CAP_TAGGED_QING:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_ARQ:
		capability = 1;
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
	mutex_exit(&acb->acb_mutex);
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
arcmsr_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	_NOTE(ARGUNUSED(value))

	int supported = 0;
	struct ACB *acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;

	if (cap == NULL || whom == 0) {
		return (-1);
	}

	mutex_enter(&acb->acb_mutex);
	if (acb->devstate[ap->a_target][ap->a_lun] == ARECA_RAID_GONE) {
		mutex_exit(&acb->acb_mutex);
		return (-1);
	}
	switch (supported = scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:			/* 9 auto request sense */
	case SCSI_CAP_UNTAGGED_QING:   		/* 7 */
	case SCSI_CAP_TAGGED_QING:		/* 8 */
		/* these are always on, and cannot be turned off */
		supported = (value == 1) ? 1 : 0;
		break;
	case SCSI_CAP_TOTAL_SECTORS:		/* c */
		supported = 1;
		break;
	case SCSI_CAP_DISCONNECT:		/* 2 */
	case SCSI_CAP_WIDE_XFER:		/* 4 */
	case SCSI_CAP_INITIATOR_ID:		/* 6 */
	case SCSI_CAP_DMA_MAX:			/* 0 */
	case SCSI_CAP_MSG_OUT:			/* 1 */
	case SCSI_CAP_PARITY:			/* 5 */
	case SCSI_CAP_LINKED_CMDS:		/* a */
	case SCSI_CAP_RESET_NOTIFICATION:	/* e */
	case SCSI_CAP_SECTOR_SIZE:		/* b */
		/* these are not settable */
		supported = 0;
		break;
	default:
		supported = -1;
		break;
	}
	mutex_exit(&acb->acb_mutex);
	return (supported);
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
    int tgtlen, int flags, int (*callback)(), caddr_t arg)
{
	struct CCB *ccb;
	struct ARCMSR_CDB *arcmsr_cdb;
	struct ACB *acb;
	int old_pkt_flag;

	acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;

	if (acb->acb_flags & ACB_F_BUS_RESET) {
		return (NULL);
	}
	if (pkt == NULL) {
		/* get free CCB */
		(void) ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		ccb = arcmsr_get_freeccb(acb);
		if (ccb == (struct CCB *)NULL) {
			return (NULL);
		}

		if (statuslen < sizeof (struct scsi_arq_status)) {
			statuslen = sizeof (struct scsi_arq_status);
		}
		pkt = scsi_hba_pkt_alloc(acb->dev_info, ap, cmdlen,
		    statuslen, tgtlen, sizeof (void *), callback, arg);
		if (pkt == NULL) {
			arcmsr_warn(acb, "scsi pkt allocation failed");
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
		arcmsr_cdb = &ccb->arcmsr_cdb;
		bzero(arcmsr_cdb, sizeof (struct ARCMSR_CDB));
		arcmsr_cdb->Bus = 0;
		arcmsr_cdb->Function = 1;
		arcmsr_cdb->LUN = ap->a_lun;
		arcmsr_cdb->TargetID = ap->a_target;
		arcmsr_cdb->CdbLength = (uint8_t)cmdlen;
		arcmsr_cdb->Context = (uintptr_t)arcmsr_cdb;

		/* Fill in the rest of the structure */
		pkt->pkt_ha_private = ccb;
		pkt->pkt_address = *ap;
		pkt->pkt_comp = NULL;
		pkt->pkt_flags = 0;
		pkt->pkt_time = 0;
		pkt->pkt_resid = 0;
		pkt->pkt_statistics = 0;
		pkt->pkt_reason = 0;
		old_pkt_flag = 0;
	} else {
		ccb = pkt->pkt_ha_private;
		if (ccb->ccb_state & ARCMSR_ABNORMAL_MASK) {
			if (!(ccb->ccb_state & ARCMSR_CCB_BACK)) {
				return (NULL);
			}
		}

		/*
		 * you cannot update CdbLength with cmdlen here, it would
		 * cause a data compare error
		 */
		ccb->ccb_state = ARCMSR_CCB_UNBUILD;
		old_pkt_flag = 1;
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
			if (arcmsr_dma_alloc(acb, pkt, bp, flags, callback) ==
			    DDI_FAILURE) {
				/*
				 * the HBA driver is unable to allocate DMA
				 * resources, it must free the allocated
				 * scsi_pkt(9S) before returning
				 */
				arcmsr_warn(acb, "dma allocation failure");
				if (old_pkt_flag == 0) {
					arcmsr_warn(acb, "dma "
					    "allocation failed to free "
					    "scsi hba pkt");
					arcmsr_free_ccb(ccb);
					scsi_hba_pkt_free(ap, pkt);
				}
				return (NULL);
			}
		} else {
			/* DMA resources to next DMA window, for old pkt */
			if (arcmsr_dma_move(acb, pkt, bp) == DDI_FAILURE) {
				arcmsr_warn(acb, "dma move failed");
				return (NULL);
			}
		}
	} else {
		pkt->pkt_resid = 0;
	}
	return (pkt);
}

/*
 *    Function: arcmsr_tran_start(9E)
 * Description: Transport the command in pktp to the target device.
 *		The command is not finished when this returns, only
 *		sent to the target; arcmsr_intr_handler will call
 *		scsi_hba_pkt_comp(pktp) when the target device has done.
 *
 *       Input: struct scsi_address *ap, struct scsi_pkt *pktp
 *      Output:	TRAN_ACCEPT if pkt is OK and not driver not busy
 *		TRAN_BUSY if driver is
 *		TRAN_BADPKT if pkt is invalid
 */
static int
arcmsr_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct ACB *acb;
	struct CCB *ccb;
	int target = ap->a_target;
	int lun = ap->a_lun;

	acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;
	ccb = pkt->pkt_ha_private;
	*pkt->pkt_scbp = STATUS_GOOD; /* clear arq scsi_status */

	if ((ccb->ccb_flags & CCB_FLAG_DMAVALID) &&
	    (ccb->ccb_flags & DDI_DMA_CONSISTENT))
		(void) ddi_dma_sync(ccb->pkt_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);

	if (ccb->ccb_state == ARCMSR_CCB_UNBUILD)
		arcmsr_build_ccb(ccb);

	if (acb->acb_flags & ACB_F_BUS_RESET) {
		pkt->pkt_reason = CMD_RESET;
		pkt->pkt_statistics |= STAT_BUS_RESET;
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS);
		if ((ccb->ccb_flags & CCB_FLAG_DMACONSISTENT) &&
		    (pkt->pkt_state & STATE_XFERRED_DATA))
			(void) ddi_dma_sync(ccb->pkt_dma_handle,
			    0, 0, DDI_DMA_SYNC_FORCPU);

		scsi_hba_pkt_comp(pkt);
		return (TRAN_ACCEPT);
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
					inqdata[3] = 0;
					/* length of additional data */
					inqdata[4] = 31;
					/* Vendor Identification */
					bcopy("Areca   ", &inqdata[8], VIDLEN);
					/* Product Identification */
					bcopy("RAID controller ", &inqdata[16],
					    PIDLEN);
					/* Product Revision */
					bcopy(&inqdata[32], "R001", REVLEN);
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

	if (acb->devstate[target][lun] == ARECA_RAID_GONE) {
		uint8_t block_cmd;

		block_cmd = pkt->pkt_cdbp[0] & 0x0f;
		if (block_cmd == 0x08 || block_cmd == 0x0a) {
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= STAT_TIMEOUT;
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_GOT_STATUS);
			if ((ccb->ccb_flags & CCB_FLAG_DMACONSISTENT) &&
			    (pkt->pkt_state & STATE_XFERRED_DATA)) {
				(void) ddi_dma_sync(ccb->pkt_dma_handle,
				    ccb->pkt_dma_offset,
				    ccb->pkt_dma_len, DDI_DMA_SYNC_FORCPU);
			}
			scsi_hba_pkt_comp(pkt);
			return (TRAN_ACCEPT);
		}
	}
	mutex_enter(&acb->postq_mutex);
	if (acb->ccboutstandingcount >= ARCMSR_MAX_OUTSTANDING_CMD) {
		ccb->ccb_state = ARCMSR_CCB_RETRY;
		mutex_exit(&acb->postq_mutex);
		return (TRAN_BUSY);
	} else if (arcmsr_post_ccb(acb, ccb) == DDI_FAILURE) {
		arcmsr_warn(acb, "post ccb failure, ccboutstandingcount = %d",
		    acb->ccboutstandingcount);
		mutex_exit(&acb->postq_mutex);
		return (TRAN_FATAL_ERROR);
	}
	mutex_exit(&acb->postq_mutex);
	return (TRAN_ACCEPT);
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
arcmsr_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct CCB *ccb = pkt->pkt_ha_private;
	ddi_dma_handle_t pkt_dma_handle = ccb->pkt_dma_handle;

	if (ccb == NULL) {
		return;
	}
	if (ccb->pkt != pkt) {
		return;
	}
	if (ccb->ccb_flags & CCB_FLAG_DMAVALID) {
		ccb->ccb_flags &= ~CCB_FLAG_DMAVALID;
		if (pkt_dma_handle) {
			(void) ddi_dma_unbind_handle(ccb->pkt_dma_handle);
		}
	}
	if (pkt_dma_handle) {
		(void) ddi_dma_free_handle(&pkt_dma_handle);
	}
	pkt->pkt_ha_private = NULL;
	if (ccb)	{
		if (ccb->ccb_state & ARCMSR_ABNORMAL_MASK) {
			if (ccb->ccb_state & ARCMSR_CCB_BACK) {
				arcmsr_free_ccb(ccb);
			} else {
				ccb->ccb_state |= ARCMSR_CCB_WAIT4_FREE;
			}
		} else {
			arcmsr_free_ccb(ccb);
		}
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
arcmsr_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct CCB *ccb = pkt->pkt_ha_private;

	if ((ccb == NULL) || (ccb->pkt != pkt)) {
		return;
	}
	if (ccb->ccb_flags & CCB_FLAG_DMAVALID) {
		ccb->ccb_flags &= ~CCB_FLAG_DMAVALID;
		if (ddi_dma_unbind_handle(ccb->pkt_dma_handle) != DDI_SUCCESS) {
			arcmsr_warn(ccb->acb, "ddi_dma_unbind_handle() failed "
			    "(target %d lun %d)", ap->a_target, ap->a_lun);
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
arcmsr_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct CCB *ccb;

	ccb = pkt->pkt_ha_private;
	if ((ccb == NULL) || (ccb->pkt != pkt)) {
		return;
	}
	if (ccb->ccb_flags & CCB_FLAG_DMAVALID) {
		if (ddi_dma_sync(ccb->pkt_dma_handle, 0, 0,
		    (ccb->ccb_flags & CCB_FLAG_DMAWRITE) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU) !=
		    DDI_SUCCESS) {
			arcmsr_warn(ccb->acb,
			    "sync pkt failed for target %d lun %d",
			    ap->a_target, ap->a_lun);
		}
	}
}


/*
 * Function: arcmsr_tran_abort(9E)
 * 		SCSA interface routine to abort pkt(s) in progress.
 * 		Aborts the pkt specified.  If NULL pkt, aborts ALL pkts.
 * Output:	Return 1 if success
 *		Return 0 if failure
 */
static int
arcmsr_tran_abort(struct scsi_address *ap, struct scsi_pkt *abortpkt)
{
	struct ACB *acb;
	int return_code;

	acb = ap->a_hba_tran->tran_hba_private;

	while (acb->ccboutstandingcount != 0) {
		drv_usecwait(10000);
	}

	mutex_enter(&acb->isr_mutex);
	return_code = arcmsr_seek_cmd2abort(acb, abortpkt);
	mutex_exit(&acb->isr_mutex);

	if (return_code != DDI_SUCCESS) {
		arcmsr_warn(acb, "abort command failed for target %d lun %d",
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
	int target = ap->a_target;
	int lun = ap->a_lun;

	/* Are we in the middle of dumping core? */
	if (ddi_in_panic())
		return (return_code);

	acb = (struct ACB *)ap->a_hba_tran->tran_hba_private;
	mutex_enter(&acb->isr_mutex);
	switch (level) {
	case RESET_ALL:		/* 0 */
		acb->num_resets++;
		acb->acb_flags |= ACB_F_BUS_RESET;
		if (acb->timeout_count) {
			if (arcmsr_iop_reset(acb) != 0) {
				arcmsr_handle_iop_bus_hold(acb);
				acb->acb_flags &= ~ACB_F_BUS_HANG_ON;
			}
		}
		acb->acb_flags &= ~ACB_F_BUS_RESET;
		break;
	case RESET_TARGET:	/* 1 */
		if (acb->devstate[target][lun] == ARECA_RAID_GONE)
			return_code = 0;
		break;
	case RESET_BUS:		/* 2 */
		return_code = 0;
		break;
	case RESET_LUN:		/* 3 */
		return_code = 0;
		break;
	default:
		return_code = 0;
	}
	mutex_exit(&acb->isr_mutex);
	return (return_code);
}

static int
arcmsr_tran_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	struct ACB *acb;
	int circ = 0;
	int rval;
	int tgt, lun;

	if ((acb = ddi_get_soft_state(arcmsr_soft_state,
	    ddi_get_instance(parent))) == NULL)
		return (NDI_FAILURE);

	ndi_devi_enter(parent, &circ);
	switch (op) {
	case BUS_CONFIG_ONE:
		if (arcmsr_parse_devname(arg, &tgt, &lun) != 0) {
			rval = NDI_FAILURE;
			break;
		}
		if (acb->device_map[tgt] & 1 << lun) {
			acb->devstate[tgt][lun] = ARECA_RAID_GOOD;
			rval = arcmsr_config_lun(acb, tgt, lun, childp);
		}
		break;

	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		for (tgt = 0; tgt < ARCMSR_MAX_TARGETID; tgt++)
			for (lun = 0; lun < ARCMSR_MAX_TARGETLUN; lun++)
				if (acb->device_map[tgt] & 1 << lun) {
					acb->devstate[tgt][lun] =
					    ARECA_RAID_GOOD;
					(void) arcmsr_config_lun(acb, tgt,
					    lun, NULL);
				}

		rval = NDI_SUCCESS;
		break;
	}
	if (rval == NDI_SUCCESS)
		rval = ndi_busop_bus_config(parent, flags, op, arg, childp, 0);
	ndi_devi_exit(parent, circ);
	return (rval);
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
    struct buf *bp, int flags, int (*callback)())
{
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

	alloc_result = ddi_dma_alloc_handle(acb->dev_info, &arcmsr_dma_attr,
	    cb, 0, &ccb->pkt_dma_handle);
	if (alloc_result != DDI_SUCCESS) {
		arcmsr_warn(acb, "dma allocate failed (%x)", alloc_result);
		return (DDI_FAILURE);
	}

	map_method = ddi_dma_buf_bind_handle(ccb->pkt_dma_handle,
	    bp, dma_flags, cb, 0,
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
			arcmsr_warn(acb,
			    "dma partial mapping lost ...impossible case!");
		}
		if (ddi_dma_numwin(ccb->pkt_dma_handle, &ccb->pkt_nwin) ==
		    DDI_FAILURE) {
			arcmsr_warn(acb, "ddi_dma_numwin() failed");
		}

		if (ddi_dma_getwin(ccb->pkt_dma_handle, ccb->pkt_curwin,
		    &ccb->pkt_dma_offset, &ccb->pkt_dma_len,
		    &ccb->pkt_dmacookies[0], &ccb->pkt_ncookies) ==
		    DDI_FAILURE) {
			arcmsr_warn(acb, "ddi_dma_getwin failed");
		}

		i = 0;
		/* first cookie is accessed from ccb->pkt_dmacookies[0] */
		total_ccb_xferlen = ccb->pkt_dmacookies[0].dmac_size;
		for (;;) {
			i++;
			if ((i == ARCMSR_MAX_SG_ENTRIES) ||
			    (i == ccb->pkt_ncookies) ||
			    (total_ccb_xferlen == ARCMSR_MAX_XFER_LEN)) {
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
			if ((i == ARCMSR_MAX_SG_ENTRIES) ||
			    (i == ccb->pkt_ncookies) ||
			    (total_ccb_xferlen == ARCMSR_MAX_XFER_LEN)) {
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
		arcmsr_warn(acb, "dma map got 'no resources'");
		bioerror(bp, ENOMEM);
		break;

	case DDI_DMA_NOMAPPING:
		arcmsr_warn(acb, "dma map got 'no mapping'");
		bioerror(bp, EFAULT);
		break;

	case DDI_DMA_TOOBIG:
		arcmsr_warn(acb, "dma map got 'too big'");
		bioerror(bp, EINVAL);
		break;

	case DDI_DMA_INUSE:
		arcmsr_warn(acb, "dma map got 'in use' "
		    "(should not happen)");
		break;
	default:
		arcmsr_warn(acb, "dma map failed (0x%x)", i);
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
arcmsr_dma_move(struct ACB *acb, struct scsi_pkt *pkt, struct buf *bp)
{
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
			return (DDI_SUCCESS);
		}

		/* At last window, cannot move */
		if (++ccb->pkt_curwin >= ccb->pkt_nwin) {
			arcmsr_warn(acb, "dma partial set, numwin exceeded");
			return (DDI_FAILURE);
		}
		if (ddi_dma_getwin(ccb->pkt_dma_handle, ccb->pkt_curwin,
		    &ccb->pkt_dma_offset, &ccb->pkt_dma_len,
		    &ccb->pkt_dmacookies[i], &ccb->pkt_ncookies) ==
		    DDI_FAILURE) {
			arcmsr_warn(acb, "ddi_dma_getwin failed");
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
		if ((i == ARCMSR_MAX_SG_ENTRIES) ||
		    (ccb->pkt_cookie == ccb->pkt_ncookies) ||
		    (total_ccb_xferlen == ARCMSR_MAX_XFER_LEN)) {
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


/*ARGSUSED*/
static void
arcmsr_build_ccb(struct CCB *ccb)
{
	struct scsi_pkt *pkt = ccb->pkt;
	struct ARCMSR_CDB *arcmsr_cdb;
	char *psge;
	uint32_t address_lo, address_hi;
	int arccdbsize = 0x30;
	uint8_t sgcount;

	arcmsr_cdb = (struct ARCMSR_CDB *)&ccb->arcmsr_cdb;
	psge = (char *)&arcmsr_cdb->sgu;

	bcopy((caddr_t)pkt->pkt_cdbp, arcmsr_cdb->Cdb, arcmsr_cdb->CdbLength);
	sgcount = ccb->arcmsr_cdb.sgcount;

	if (sgcount != 0) {
		int length, i;
		int cdb_sgcount = 0;
		int total_xfer_length = 0;

		/* map stor port SG list to our iop SG List. */
		for (i = 0; i < sgcount; i++) {
			/* Get physaddr of the current data pointer */
			length = ccb->pkt_dmacookies[i].dmac_size;
			total_xfer_length += length;
			address_lo =
			    dma_addr_lo32(ccb->pkt_dmacookies[i].dmac_laddress);
			address_hi =
			    dma_addr_hi32(ccb->pkt_dmacookies[i].dmac_laddress);

			if (address_hi == 0) {
				struct SG32ENTRY *dma_sg;

				dma_sg = (struct SG32ENTRY *)(intptr_t)psge;
				dma_sg->address = address_lo;
				dma_sg->length = length;
				psge += sizeof (struct SG32ENTRY);
				arccdbsize += sizeof (struct SG32ENTRY);
			} else {
				struct SG64ENTRY *dma_sg;

				dma_sg = (struct SG64ENTRY *)(intptr_t)psge;
				dma_sg->addresshigh = address_hi;
				dma_sg->address = address_lo;
				dma_sg->length = length | IS_SG64_ADDR;
				psge += sizeof (struct SG64ENTRY);
				arccdbsize += sizeof (struct SG64ENTRY);
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
	ccb->arc_cdb_size = arccdbsize;
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
arcmsr_post_ccb(struct ACB *acb, struct CCB *ccb)
{
	uint32_t cdb_phyaddr_pattern = ccb->cdb_phyaddr_pattern;
	struct scsi_pkt *pkt = ccb->pkt;
	struct ARCMSR_CDB *arcmsr_cdb;
	uint_t pkt_flags = pkt->pkt_flags;

	arcmsr_cdb = &ccb->arcmsr_cdb;

	/* TODO: Use correct offset and size for syncing? */
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, 0, DDI_DMA_SYNC_FORDEV) ==
	    DDI_FAILURE)
		return (DDI_FAILURE);

	atomic_add_32(&acb->ccboutstandingcount, 1);
	ccb->ccb_time = (time_t)(ddi_get_time() + pkt->pkt_time);

	ccb->ccb_state = ARCMSR_CCB_START;
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		if (arcmsr_cdb->Flags & ARCMSR_CDB_FLAG_SGL_BSIZE) {
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->inbound_queueport,
			    cdb_phyaddr_pattern |
			    ARCMSR_CCBPOST_FLAG_SGL_BSIZE);
		} else {
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->inbound_queueport, cdb_phyaddr_pattern);
		}
		if (pkt_flags & FLAG_NOINTR)
			arcmsr_polling_hba_ccbdone(acb, ccb);
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;
		int ending_index, index;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		index = phbbmu->postq_index;
		ending_index = ((index+1)%ARCMSR_MAX_HBB_POSTQUEUE);
		phbbmu->post_qbuffer[ending_index] = 0;
		if (arcmsr_cdb->Flags & ARCMSR_CDB_FLAG_SGL_BSIZE) {
			phbbmu->post_qbuffer[index] =
			    (cdb_phyaddr_pattern|ARCMSR_CCBPOST_FLAG_SGL_BSIZE);
		} else {
			phbbmu->post_qbuffer[index] = cdb_phyaddr_pattern;
		}
		index++;
		/* if last index number set it to 0 */
		index %= ARCMSR_MAX_HBB_POSTQUEUE;
		phbbmu->postq_index = index;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_DRV2IOP_CDB_POSTED);

		if (pkt_flags & FLAG_NOINTR)
			arcmsr_polling_hbb_ccbdone(acb, ccb);
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;
		uint32_t ccb_post_stamp, arc_cdb_size;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		arc_cdb_size = (ccb->arc_cdb_size > 0x300) ? 0x300 :
		    ccb->arc_cdb_size;
		ccb_post_stamp = (cdb_phyaddr_pattern |
		    ((arc_cdb_size-1) >> 6) |1);
		if (acb->cdb_phyaddr_hi32) {
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->inbound_queueport_high,
			    acb->cdb_phyaddr_hi32);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->inbound_queueport_low, ccb_post_stamp);
		} else {
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->inbound_queueport_low, ccb_post_stamp);
		}
		if (pkt_flags & FLAG_NOINTR)
			arcmsr_polling_hbc_ccbdone(acb, ccb);
		break;
	}

	}
	return (DDI_SUCCESS);
}


static void
arcmsr_ccb_complete(struct CCB *ccb, int flag)
{
	struct ACB *acb = ccb->acb;
	struct scsi_pkt *pkt = ccb->pkt;

	if (pkt == NULL) {
		return;
	}
	ccb->ccb_state |= ARCMSR_CCB_DONE;
	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_GOT_STATUS);

	if ((ccb->ccb_flags & CCB_FLAG_DMACONSISTENT) &&
	    (pkt->pkt_state & STATE_XFERRED_DATA)) {
		(void) ddi_dma_sync(ccb->pkt_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
	}
	/*
	 * TODO: This represents a potential race condition, and is
	 * ultimately a poor design decision.  Revisit this code
	 * and solve the mutex ownership issue correctly.
	 */
	if (mutex_owned(&acb->isr_mutex)) {
		mutex_exit(&acb->isr_mutex);
		scsi_hba_pkt_comp(pkt);
		mutex_enter(&acb->isr_mutex);
	} else {
		scsi_hba_pkt_comp(pkt);
	}
	if (flag == 1) {
		atomic_add_32(&acb->ccboutstandingcount, -1);
	}
}

static void
arcmsr_report_ccb_state(struct ACB *acb, struct CCB *ccb, boolean_t error)
{
	int id, lun;

	ccb->ccb_state |= ARCMSR_CCB_DONE;
	id = ccb->pkt->pkt_address.a_target;
	lun = ccb->pkt->pkt_address.a_lun;

	if (!error) {
		if (acb->devstate[id][lun] == ARECA_RAID_GONE) {
			acb->devstate[id][lun] = ARECA_RAID_GOOD;
		}
		ccb->pkt->pkt_reason = CMD_CMPLT;
		ccb->pkt->pkt_state |= STATE_XFERRED_DATA;
		arcmsr_list_add_tail(&acb->ccb_complete_list_mutex,
		    &ccb->complete_queue_pointer, &acb->ccb_complete_list);

	} else {
		switch (ccb->arcmsr_cdb.DeviceStatus) {
		case ARCMSR_DEV_SELECT_TIMEOUT:
			if (acb->devstate[id][lun] == ARECA_RAID_GOOD) {
				arcmsr_warn(acb,
				    "target %d lun %d selection "
				    "timeout", id, lun);
			}
			acb->devstate[id][lun] = ARECA_RAID_GONE;
			ccb->pkt->pkt_reason = CMD_TIMEOUT; /* CMD_DEV_GONE; */
			ccb->pkt->pkt_statistics |= STAT_TIMEOUT;
			arcmsr_list_add_tail(&acb->ccb_complete_list_mutex,
			    &ccb->complete_queue_pointer,
			    &acb->ccb_complete_list);
			break;
		case ARCMSR_DEV_ABORTED:
		case ARCMSR_DEV_INIT_FAIL:
			arcmsr_warn(acb, "isr got 'ARCMSR_DEV_ABORTED'"
			    " 'ARCMSR_DEV_INIT_FAIL'");
			arcmsr_log(acb, CE_NOTE, "raid volume was kicked out");
			acb->devstate[id][lun] = ARECA_RAID_GONE;
			ccb->pkt->pkt_reason = CMD_DEV_GONE;
			ccb->pkt->pkt_statistics |= STAT_TERMINATED;
			arcmsr_list_add_tail(&acb->ccb_complete_list_mutex,
			    &ccb->complete_queue_pointer,
			    &acb->ccb_complete_list);
			break;
		case SCSISTAT_CHECK_CONDITION:
			acb->devstate[id][lun] = ARECA_RAID_GOOD;
			arcmsr_report_sense_info(ccb);
			arcmsr_list_add_tail(&acb->ccb_complete_list_mutex,
			    &ccb->complete_queue_pointer,
			    &acb->ccb_complete_list);
			break;
		default:
			arcmsr_warn(acb,
			    "target %d lun %d isr received CMD_DONE"
			    " with unknown DeviceStatus (0x%x)",
			    id, lun, ccb->arcmsr_cdb.DeviceStatus);
			arcmsr_log(acb, CE_NOTE, "raid volume was kicked out");
			acb->devstate[id][lun] = ARECA_RAID_GONE;
			/* unknown error or crc error just for retry */
			ccb->pkt->pkt_reason = CMD_TRAN_ERR;
			ccb->pkt->pkt_statistics |= STAT_TERMINATED;
			arcmsr_list_add_tail(&acb->ccb_complete_list_mutex,
			    &ccb->complete_queue_pointer,
			    &acb->ccb_complete_list);
			break;
		}
	}
}


static void
arcmsr_drain_donequeue(struct ACB *acb, struct CCB *ccb, boolean_t error)
{
	uint16_t	ccb_state;

	if (ccb->acb != acb) {
		return;
	}
	if (ccb->ccb_state != ARCMSR_CCB_START) {
		switch (ccb->ccb_state & ARCMSR_ABNORMAL_MASK) {
		case ARCMSR_CCB_TIMEOUT:
			ccb_state = ccb->ccb_state;
			if (ccb_state & ARCMSR_CCB_WAIT4_FREE)
				arcmsr_free_ccb(ccb);
			else
				ccb->ccb_state |= ARCMSR_CCB_BACK;
			return;

		case ARCMSR_CCB_ABORTED:
			ccb_state = ccb->ccb_state;
			if (ccb_state & ARCMSR_CCB_WAIT4_FREE)
				arcmsr_free_ccb(ccb);
			else
				ccb->ccb_state |= ARCMSR_CCB_BACK;
			return;
		case ARCMSR_CCB_RESET:
			ccb_state = ccb->ccb_state;
			if (ccb_state & ARCMSR_CCB_WAIT4_FREE)
				arcmsr_free_ccb(ccb);
			else
				ccb->ccb_state |= ARCMSR_CCB_BACK;
			return;
		default:
			return;
		}
	}
	arcmsr_report_ccb_state(acb, ccb, error);
}

static void
arcmsr_report_sense_info(struct CCB *ccb)
{
	struct SENSE_DATA *cdb_sensedata;
	struct scsi_pkt *pkt = ccb->pkt;
	struct scsi_arq_status *arq_status;
	union scsi_cdb *cdbp;
	uint64_t err_blkno;

	cdbp = (void *)pkt->pkt_cdbp;
	err_blkno = ARCMSR_GETGXADDR(ccb->arcmsr_cdb.CdbLength, cdbp);

	arq_status = (struct scsi_arq_status *)(intptr_t)(pkt->pkt_scbp);
	bzero((caddr_t)arq_status, sizeof (struct scsi_arq_status));
	*pkt->pkt_scbp = STATUS_CHECK; /* CHECK CONDITION */
	arq_status->sts_rqpkt_reason = CMD_CMPLT;
	arq_status->sts_rqpkt_state = (STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS);
	arq_status->sts_rqpkt_statistics = 0;
	arq_status->sts_rqpkt_resid = 0;

	pkt->pkt_reason = CMD_CMPLT;
	/* auto rqsense took place */
	pkt->pkt_state |= STATE_ARQ_DONE;

	cdb_sensedata = (struct SENSE_DATA *)ccb->arcmsr_cdb.SenseData;
	if (&arq_status->sts_sensedata != NULL) {
		if (err_blkno <= 0xfffffffful) {
			struct scsi_extended_sense *sts_sensedata;

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
			sts_sensedata->es_info_1 = (err_blkno >> 24) & 0xFF;
			sts_sensedata->es_info_2 = (err_blkno >> 16) & 0xFF;
			sts_sensedata->es_info_3 = (err_blkno >>  8) & 0xFF;
			sts_sensedata->es_info_4 = err_blkno & 0xFF;
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
		} else { /* 64-bit LBA */
			struct scsi_descr_sense_hdr *dsp;
			struct scsi_information_sense_descr *isd;

			dsp = (struct scsi_descr_sense_hdr *)
			    &arq_status->sts_sensedata;
			dsp->ds_class = CLASS_EXTENDED_SENSE;
			dsp->ds_code = CODE_FMT_DESCR_CURRENT;
			dsp->ds_key = cdb_sensedata->SenseKey;
			dsp->ds_add_code = cdb_sensedata->AdditionalSenseCode;
			dsp->ds_qual_code =
			    cdb_sensedata->AdditionalSenseCodeQualifier;
			dsp->ds_addl_sense_length =
			    sizeof (struct scsi_information_sense_descr);

			isd = (struct scsi_information_sense_descr *)(dsp+1);
			isd->isd_descr_type = DESCR_INFORMATION;
			isd->isd_valid = 1;
			isd->isd_information[0] = (err_blkno >> 56) & 0xFF;
			isd->isd_information[1] = (err_blkno >> 48) & 0xFF;
			isd->isd_information[2] = (err_blkno >> 40) & 0xFF;
			isd->isd_information[3] = (err_blkno >> 32) & 0xFF;
			isd->isd_information[4] = (err_blkno >> 24) & 0xFF;
			isd->isd_information[5] = (err_blkno >> 16) & 0xFF;
			isd->isd_information[6] = (err_blkno >>  8) & 0xFF;
			isd->isd_information[7] = (err_blkno) & 0xFF;
		}
	}
}


static int
arcmsr_seek_cmd2abort(struct ACB *acb, struct scsi_pkt *abortpkt)
{
	struct CCB *ccb;
	uint32_t intmask_org = 0;
	int i = 0;

	acb->num_aborts++;

	if (abortpkt != NULL) {
		/*
		 * We don't support abort of a single packet.  All
		 * callers in our kernel always do a global abort, so
		 * there is no point in having code to support it
		 * here.
		 */
		return (DDI_FAILURE);
	}

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
		(void) arcmsr_abort_host_command(acb);

		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->ccb_state == ARCMSR_CCB_START) {
				/*
				 * this ccb will complete at
				 * hwinterrupt
				 */
				/* ccb->ccb_state = ARCMSR_CCB_ABORTED; */
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
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
 * Autoconfiguration support
 */
static int
arcmsr_parse_devname(char *devnm, int *tgt, int *lun) {

	char devbuf[SCSI_MAXNAMELEN];
	char *addr;
	char *p,  *tp, *lp;
	long num;

	/* Parse dev name and address */
	(void) strlcpy(devbuf, devnm, sizeof (devbuf));
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

	/* Parse target and lun */
	for (p = tp = addr, lp = NULL; *p != '\0'; p++) {
		if (*p == ',') {
			lp = p + 1;
			*p = '\0';
			break;
		}
	}
	if ((tgt != NULL) && (tp != NULL)) {
		if (ddi_strtol(tp, NULL, 0x10, &num) != 0)
			return (-1);
		*tgt = (int)num;
	}
	if ((lun != NULL) && (lp != NULL)) {
		if (ddi_strtol(lp, NULL, 0x10, &num) != 0)
			return (-1);
		*lun = (int)num;
	}
	return (0);
}

static int
arcmsr_name_node(dev_info_t *dip, char *name, int len)
{
	int tgt, lun;

	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "target",
	    -1);
	if (tgt == -1)
		return (DDI_FAILURE);
	lun = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "lun",
	    -1);
	if (lun == -1)
		return (DDI_FAILURE);
	(void) snprintf(name, len, "%x,%x", tgt, lun);
	return (DDI_SUCCESS);
}

static dev_info_t *
arcmsr_find_child(struct ACB *acb, uint16_t tgt, uint8_t lun)
{
	dev_info_t *child = NULL;
	char addr[SCSI_MAXNAMELEN];
	char tmp[SCSI_MAXNAMELEN];

	(void) sprintf(addr, "%x,%x", tgt, lun);

	for (child = ddi_get_child(acb->dev_info);
	    child;
	    child = ddi_get_next_sibling(child)) {
		/* We don't care about non-persistent node */
		if (ndi_dev_is_persistent_node(child) == 0)
			continue;
		if (arcmsr_name_node(child, tmp, SCSI_MAXNAMELEN) !=
		    DDI_SUCCESS)
			continue;
		if (strcmp(addr, tmp) == 0)
			break;
	}
	return (child);
}

static int
arcmsr_config_child(struct ACB *acb, struct scsi_device *sd, dev_info_t **dipp)
{
	char *nodename = NULL;
	char **compatible = NULL;
	int ncompatible = 0;
	dev_info_t *ldip = NULL;
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;
	int dtype = sd->sd_inq->inq_dtype & DTYPE_MASK;
	int rval;

	scsi_hba_nodename_compatible_get(sd->sd_inq, NULL, dtype,
	    NULL, &nodename, &compatible, &ncompatible);
	if (nodename == NULL) {
		arcmsr_warn(acb, "found no comptible driver for T%dL%d",
		    tgt, lun);
		rval = NDI_FAILURE;
		goto finish;
	}
	/* Create dev node */
	rval = ndi_devi_alloc(acb->dev_info, nodename, DEVI_SID_NODEID, &ldip);
	if (rval == NDI_SUCCESS) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "target", tgt) !=
		    DDI_PROP_SUCCESS) {
			arcmsr_warn(acb,
			    "unable to create target property for T%dL%d",
			    tgt, lun);
			rval = NDI_FAILURE;
			goto finish;
		}
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "lun", lun) !=
		    DDI_PROP_SUCCESS) {
			arcmsr_warn(acb,
			    "unable to create lun property for T%dL%d",
			    tgt, lun);
			rval = NDI_FAILURE;
			goto finish;
		}
		if (ndi_prop_update_string_array(DDI_DEV_T_NONE, ldip,
		    "compatible", compatible, ncompatible) !=
		    DDI_PROP_SUCCESS) {
			arcmsr_warn(acb,
			    "unable to create compatible property for T%dL%d",
			    tgt, lun);
			rval = NDI_FAILURE;
			goto finish;
		}
		rval = ndi_devi_online(ldip, NDI_ONLINE_ATTACH);
		if (rval != NDI_SUCCESS) {
			arcmsr_warn(acb, "unable to online T%dL%d", tgt, lun);
			ndi_prop_remove_all(ldip);
			(void) ndi_devi_free(ldip);
		} else {
			arcmsr_log(acb, CE_NOTE, "T%dL%d onlined", tgt, lun);
		}
	}
finish:
	if (dipp)
		*dipp = ldip;

	scsi_hba_nodename_compatible_free(nodename, compatible);
	return (rval);
}

static int
arcmsr_config_lun(struct ACB *acb, uint16_t tgt, uint8_t lun, dev_info_t **ldip)
{
	struct scsi_device sd;
	dev_info_t *child;
	int rval;

	if ((child = arcmsr_find_child(acb, tgt, lun)) != NULL) {
		if (ldip) {
			*ldip = child;
		}
		return (NDI_SUCCESS);
	}
	bzero(&sd, sizeof (struct scsi_device));
	sd.sd_address.a_hba_tran = acb->scsi_hba_transport;
	sd.sd_address.a_target = tgt;
	sd.sd_address.a_lun = lun;

	rval = scsi_hba_probe(&sd, NULL);
	if (rval == SCSIPROBE_EXISTS)
		rval = arcmsr_config_child(acb, &sd, ldip);
	scsi_unprobe(&sd);
	return (rval);
}


static int
arcmsr_add_intr(struct ACB *acb, int intr_type)
{
	int	rc, count;
	dev_info_t *dev_info;
	const char *type_str;

	switch (intr_type) {
	case DDI_INTR_TYPE_MSI:
		type_str = "MSI";
		break;
	case DDI_INTR_TYPE_MSIX:
		type_str = "MSIX";
		break;
	case DDI_INTR_TYPE_FIXED:
		type_str = "FIXED";
		break;
	default:
		type_str = "unknown";
		break;
	}

	dev_info = acb->dev_info;
	/* Determine number of supported interrupts */
	rc = ddi_intr_get_nintrs(dev_info, intr_type, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		arcmsr_warn(acb,
		    "no interrupts of type %s, rc=0x%x, count=%d",
		    type_str, rc, count);
		return (DDI_FAILURE);
	}
	acb->intr_size = sizeof (ddi_intr_handle_t) * count;
	acb->phandle = kmem_zalloc(acb->intr_size, KM_SLEEP);
	rc = ddi_intr_alloc(dev_info, acb->phandle, intr_type, 0,
	    count, &acb->intr_count, DDI_INTR_ALLOC_NORMAL);
	if ((rc != DDI_SUCCESS) || (acb->intr_count == 0)) {
		arcmsr_warn(acb, "ddi_intr_alloc(%s) failed 0x%x",
		    type_str, rc);
		return (DDI_FAILURE);
	}
	if (acb->intr_count < count) {
		arcmsr_log(acb, CE_NOTE, "Got %d interrupts, but requested %d",
		    acb->intr_count, count);
	}
	/*
	 * Get priority for first msi, assume remaining are all the same
	 */
	if (ddi_intr_get_pri(acb->phandle[0], &acb->intr_pri) != DDI_SUCCESS) {
		arcmsr_warn(acb, "ddi_intr_get_pri failed");
		return (DDI_FAILURE);
	}
	if (acb->intr_pri >= ddi_intr_get_hilevel_pri()) {
		arcmsr_warn(acb,  "high level interrupt not supported");
		return (DDI_FAILURE);
	}

	for (int x = 0; x < acb->intr_count; x++) {
		if (ddi_intr_add_handler(acb->phandle[x], arcmsr_intr_handler,
		    (caddr_t)acb, NULL) != DDI_SUCCESS) {
			arcmsr_warn(acb, "ddi_intr_add_handler(%s) failed",
			    type_str);
			return (DDI_FAILURE);
		}
	}
	(void) ddi_intr_get_cap(acb->phandle[0], &acb->intr_cap);
	if (acb->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI */
		(void) ddi_intr_block_enable(acb->phandle, acb->intr_count);
	} else {
		/* Call ddi_intr_enable() for MSI non block enable */
		for (int x = 0; x < acb->intr_count; x++) {
			(void) ddi_intr_enable(acb->phandle[x]);
		}
	}
	return (DDI_SUCCESS);
}

static void
arcmsr_remove_intr(struct ACB *acb)
{
	int x;

	if (acb->phandle == NULL)
		return;

	/* Disable all interrupts */
	if (acb->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		(void) ddi_intr_block_disable(acb->phandle, acb->intr_count);
	} else {
		for (x = 0; x < acb->intr_count; x++) {
			(void) ddi_intr_disable(acb->phandle[x]);
		}
	}
	/* Call ddi_intr_remove_handler() */
	for (x = 0; x < acb->intr_count; x++) {
		(void) ddi_intr_remove_handler(acb->phandle[x]);
		(void) ddi_intr_free(acb->phandle[x]);
	}
	kmem_free(acb->phandle, acb->intr_size);
	acb->phandle = NULL;
}

static void
arcmsr_mutex_init(struct ACB *acb)
{
	mutex_init(&acb->isr_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&acb->acb_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&acb->postq_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&acb->workingQ_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&acb->ioctl_mutex, NULL, MUTEX_DRIVER, NULL);
}

static void
arcmsr_mutex_destroy(struct ACB *acb)
{
	mutex_destroy(&acb->isr_mutex);
	mutex_destroy(&acb->acb_mutex);
	mutex_destroy(&acb->postq_mutex);
	mutex_destroy(&acb->workingQ_mutex);
	mutex_destroy(&acb->ioctl_mutex);
}

static int
arcmsr_initialize(struct ACB *acb)
{
	struct CCB *pccb_tmp;
	size_t allocated_length;
	uint16_t wval;
	uint_t intmask_org, count;
	caddr_t	arcmsr_ccbs_area;
	uint32_t wlval, cdb_phyaddr, offset, realccb_size;
	int32_t dma_sync_size;
	int i, id, lun, instance;

	instance = ddi_get_instance(acb->dev_info);
	wlval = pci_config_get32(acb->pci_acc_handle, 0);
	wval = (uint16_t)((wlval >> 16) & 0xffff);
	realccb_size = P2ROUNDUP(sizeof (struct CCB), 32);
	switch (wval) {
	case PCI_DEVICE_ID_ARECA_1880:
	case PCI_DEVICE_ID_ARECA_1882:
	{
		uint32_t *iop_mu_regs_map0;

		acb->adapter_type = ACB_ADAPTER_TYPE_C; /* lsi */
		dma_sync_size = ARCMSR_MAX_FREECCB_NUM * realccb_size + 0x20;
		if (ddi_regs_map_setup(acb->dev_info, 2,
		    (caddr_t *)&iop_mu_regs_map0, 0,
		    sizeof (struct HBC_msgUnit), &acb->dev_acc_attr,
		    &acb->reg_mu_acc_handle0) != DDI_SUCCESS) {
			arcmsr_warn(acb, "unable to map registers");
			return (DDI_FAILURE);
		}

		if ((i = ddi_dma_alloc_handle(acb->dev_info, &arcmsr_ccb_attr,
		    DDI_DMA_SLEEP, NULL, &acb->ccbs_pool_handle)) !=
		    DDI_SUCCESS) {
			ddi_regs_map_free(&acb->reg_mu_acc_handle0);
			arcmsr_warn(acb, "ddi_dma_alloc_handle failed");
			return (DDI_FAILURE);
		}

		if (ddi_dma_mem_alloc(acb->ccbs_pool_handle, dma_sync_size,
		    &acb->dev_acc_attr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, (caddr_t *)&arcmsr_ccbs_area,
		    &allocated_length, &acb->ccbs_acc_handle) != DDI_SUCCESS) {
			arcmsr_warn(acb, "ddi_dma_mem_alloc failed");
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			ddi_regs_map_free(&acb->reg_mu_acc_handle0);
			return (DDI_FAILURE);
		}

		if (ddi_dma_addr_bind_handle(acb->ccbs_pool_handle, NULL,
		    (caddr_t)arcmsr_ccbs_area, dma_sync_size, DDI_DMA_RDWR |
		    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &acb->ccb_cookie,
		    &count) != DDI_DMA_MAPPED) {
			arcmsr_warn(acb, "ddi_dma_addr_bind_handle failed");
			ddi_dma_mem_free(&acb->ccbs_acc_handle);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			ddi_regs_map_free(&acb->reg_mu_acc_handle0);
			return (DDI_FAILURE);
		}
		bzero(arcmsr_ccbs_area, dma_sync_size);
		offset = (uint32_t)(P2ROUNDUP(PtrToNum(arcmsr_ccbs_area), 32)
		    - PtrToNum(arcmsr_ccbs_area));
		arcmsr_ccbs_area = arcmsr_ccbs_area + offset;
		/* ioport base */
		acb->pmu = (struct msgUnit *)(intptr_t)iop_mu_regs_map0;
		break;
	}

	case PCI_DEVICE_ID_ARECA_1201:
	{
		uint32_t *iop_mu_regs_map0;
		uint32_t *iop_mu_regs_map1;
		struct HBB_msgUnit *phbbmu;

		acb->adapter_type = ACB_ADAPTER_TYPE_B; /* marvell */
		dma_sync_size =
		    (ARCMSR_MAX_FREECCB_NUM * realccb_size + 0x20) +
		    sizeof (struct HBB_msgUnit);
		/* Allocate memory for the ccb */
		if ((i = ddi_dma_alloc_handle(acb->dev_info, &arcmsr_ccb_attr,
		    DDI_DMA_SLEEP, NULL, &acb->ccbs_pool_handle)) !=
		    DDI_SUCCESS) {
			arcmsr_warn(acb, "ddi_dma_alloc_handle failed");
			return (DDI_FAILURE);
		}

		if (ddi_dma_mem_alloc(acb->ccbs_pool_handle, dma_sync_size,
		    &acb->dev_acc_attr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, (caddr_t *)&arcmsr_ccbs_area,
		    &allocated_length, &acb->ccbs_acc_handle) != DDI_SUCCESS) {
			arcmsr_warn(acb, "ddi_dma_mem_alloc failed");
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}

		if (ddi_dma_addr_bind_handle(acb->ccbs_pool_handle, NULL,
		    (caddr_t)arcmsr_ccbs_area, dma_sync_size,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
		    NULL, &acb->ccb_cookie, &count) != DDI_DMA_MAPPED) {
			arcmsr_warn(acb, "ddi_dma_addr_bind_handle failed");
			ddi_dma_mem_free(&acb->ccbs_acc_handle);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}
		bzero(arcmsr_ccbs_area, dma_sync_size);
		offset = (uint32_t)(P2ROUNDUP(PtrToNum(arcmsr_ccbs_area), 32)
		    - PtrToNum(arcmsr_ccbs_area));
		arcmsr_ccbs_area = arcmsr_ccbs_area + offset;
		acb->pmu = (struct msgUnit *)
		    NumToPtr(PtrToNum(arcmsr_ccbs_area) +
		    (realccb_size*ARCMSR_MAX_FREECCB_NUM));
		phbbmu = (struct HBB_msgUnit *)acb->pmu;

		/* setup device register */
		if (ddi_regs_map_setup(acb->dev_info, 1,
		    (caddr_t *)&iop_mu_regs_map0, 0,
		    sizeof (struct HBB_DOORBELL), &acb->dev_acc_attr,
		    &acb->reg_mu_acc_handle0) != DDI_SUCCESS) {
			arcmsr_warn(acb, "unable to map base0 registers");
			(void) ddi_dma_unbind_handle(acb->ccbs_pool_handle);
			ddi_dma_mem_free(&acb->ccbs_acc_handle);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}

		/* ARCMSR_DRV2IOP_DOORBELL */
		phbbmu->hbb_doorbell = (struct HBB_DOORBELL *)iop_mu_regs_map0;
		if (ddi_regs_map_setup(acb->dev_info, 2,
		    (caddr_t *)&iop_mu_regs_map1, 0,
		    sizeof (struct HBB_RWBUFFER), &acb->dev_acc_attr,
		    &acb->reg_mu_acc_handle1) != DDI_SUCCESS) {
			arcmsr_warn(acb, "unable to map base1 registers");
			ddi_regs_map_free(&acb->reg_mu_acc_handle0);
			(void) ddi_dma_unbind_handle(acb->ccbs_pool_handle);
			ddi_dma_mem_free(&acb->ccbs_acc_handle);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			return (DDI_FAILURE);
		}

		/* ARCMSR_MSGCODE_RWBUFFER */
		phbbmu->hbb_rwbuffer = (struct HBB_RWBUFFER *)iop_mu_regs_map1;
		break;
	}

	case	PCI_DEVICE_ID_ARECA_1110:
	case	PCI_DEVICE_ID_ARECA_1120:
	case	PCI_DEVICE_ID_ARECA_1130:
	case	PCI_DEVICE_ID_ARECA_1160:
	case	PCI_DEVICE_ID_ARECA_1170:
	case	PCI_DEVICE_ID_ARECA_1210:
	case	PCI_DEVICE_ID_ARECA_1220:
	case	PCI_DEVICE_ID_ARECA_1230:
	case	PCI_DEVICE_ID_ARECA_1231:
	case	PCI_DEVICE_ID_ARECA_1260:
	case	PCI_DEVICE_ID_ARECA_1261:
	case	PCI_DEVICE_ID_ARECA_1270:
	case	PCI_DEVICE_ID_ARECA_1280:
	case	PCI_DEVICE_ID_ARECA_1212:
	case	PCI_DEVICE_ID_ARECA_1222:
	case	PCI_DEVICE_ID_ARECA_1380:
	case	PCI_DEVICE_ID_ARECA_1381:
	case	PCI_DEVICE_ID_ARECA_1680:
	case	PCI_DEVICE_ID_ARECA_1681:
	{
		uint32_t *iop_mu_regs_map0;

		acb->adapter_type = ACB_ADAPTER_TYPE_A; /* intel */
		dma_sync_size = ARCMSR_MAX_FREECCB_NUM * realccb_size + 0x20;
		if (ddi_regs_map_setup(acb->dev_info, 1,
		    (caddr_t *)&iop_mu_regs_map0, 0,
		    sizeof (struct HBA_msgUnit), &acb->dev_acc_attr,
		    &acb->reg_mu_acc_handle0) != DDI_SUCCESS) {
			arcmsr_warn(acb, "unable to map registers");
			return (DDI_FAILURE);
		}

		if ((i = ddi_dma_alloc_handle(acb->dev_info, &arcmsr_ccb_attr,
		    DDI_DMA_SLEEP, NULL, &acb->ccbs_pool_handle)) !=
		    DDI_SUCCESS) {
			arcmsr_warn(acb, "ddi_dma_alloc_handle failed");
			ddi_regs_map_free(&acb->reg_mu_acc_handle0);
			return (DDI_FAILURE);
		}

		if (ddi_dma_mem_alloc(acb->ccbs_pool_handle, dma_sync_size,
		    &acb->dev_acc_attr, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, (caddr_t *)&arcmsr_ccbs_area,
		    &allocated_length, &acb->ccbs_acc_handle) != DDI_SUCCESS) {
			arcmsr_warn(acb, "ddi_dma_mem_alloc failed", instance);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			ddi_regs_map_free(&acb->reg_mu_acc_handle0);
			return (DDI_FAILURE);
		}

		if (ddi_dma_addr_bind_handle(acb->ccbs_pool_handle, NULL,
		    (caddr_t)arcmsr_ccbs_area, dma_sync_size, DDI_DMA_RDWR |
		    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &acb->ccb_cookie,
		    &count) != DDI_DMA_MAPPED) {
			arcmsr_warn(acb, "ddi_dma_addr_bind_handle failed");
			ddi_dma_mem_free(&acb->ccbs_acc_handle);
			ddi_dma_free_handle(&acb->ccbs_pool_handle);
			ddi_regs_map_free(&acb->reg_mu_acc_handle0);
			return (DDI_FAILURE);
		}
		bzero(arcmsr_ccbs_area, dma_sync_size);
		offset = (uint32_t)(P2ROUNDUP(PtrToNum(arcmsr_ccbs_area), 32)
		    - PtrToNum(arcmsr_ccbs_area));
		arcmsr_ccbs_area = arcmsr_ccbs_area + offset;
		/* ioport base */
		acb->pmu = (struct msgUnit *)(intptr_t)iop_mu_regs_map0;
		break;
	}

	default:
		arcmsr_warn(acb, "Unknown RAID adapter type!");
		return (DDI_FAILURE);
	}
	arcmsr_init_list_head(&acb->ccb_complete_list);
	/* here we can not access pci configuration again */
	acb->acb_flags |= (ACB_F_MESSAGE_WQBUFFER_CLEARED |
	    ACB_F_MESSAGE_RQBUFFER_CLEARED | ACB_F_MESSAGE_WQBUFFER_READ);
	acb->acb_flags &= ~ACB_F_SCSISTOPADAPTER;
	/* physical address of acb->pccb_pool */
	cdb_phyaddr = acb->ccb_cookie.dmac_address + offset;

	pccb_tmp = (struct CCB *)(intptr_t)arcmsr_ccbs_area;

	for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
		pccb_tmp->cdb_phyaddr_pattern =
		    (acb->adapter_type == ACB_ADAPTER_TYPE_C) ?
		    cdb_phyaddr : (cdb_phyaddr >> 5);
		pccb_tmp->acb = acb;
		acb->ccbworkingQ[i] = acb->pccb_pool[i] = pccb_tmp;
		cdb_phyaddr = cdb_phyaddr + realccb_size;
		pccb_tmp = (struct CCB *)NumToPtr(PtrToNum(pccb_tmp) +
		    realccb_size);
	}
	acb->vir2phy_offset = PtrToNum(pccb_tmp) - cdb_phyaddr;

	/* disable all outbound interrupt */
	intmask_org = arcmsr_disable_allintr(acb);

	if (!arcmsr_iop_confirm(acb)) {
		arcmsr_warn(acb, "arcmsr_iop_confirm error", instance);
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

static int
arcmsr_do_ddi_attach(dev_info_t *dev_info, int instance)
{
	scsi_hba_tran_t *hba_trans;
	ddi_device_acc_attr_t dev_acc_attr;
	struct ACB *acb;
	uint16_t wval;
	int raid6 = 1;
	char *type;
	int intr_types;


	/*
	 * Soft State Structure
	 * The driver should allocate the per-device-instance
	 * soft state structure, being careful to clean up properly if
	 * an error occurs. Allocate data structure.
	 */
	if (ddi_soft_state_zalloc(arcmsr_soft_state, instance) != DDI_SUCCESS) {
		arcmsr_warn(NULL, "ddi_soft_state_zalloc failed");
		return (DDI_FAILURE);
	}

	acb = ddi_get_soft_state(arcmsr_soft_state, instance);
	ASSERT(acb);

	arcmsr_mutex_init(acb);

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
		arcmsr_warn(acb, "hardware is not installed in"
		    " a DMA-capable slot");
		goto error_level_0;
	}
	if (pci_config_setup(dev_info, &acb->pci_acc_handle) != DDI_SUCCESS) {
		arcmsr_warn(acb, "pci_config_setup() failed, attach failed");
		goto error_level_0;
	}

	wval = pci_config_get16(acb->pci_acc_handle, PCI_CONF_VENID);
	if (wval != PCI_VENDOR_ID_ARECA) {
		arcmsr_warn(acb,
		    "'vendorid (0x%04x) does not match 0x%04x "
		    "(PCI_VENDOR_ID_ARECA)",
		    wval, PCI_VENDOR_ID_ARECA);
		goto error_level_0;
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
		type = "SATA 3G";
		break;
	case PCI_DEVICE_ID_ARECA_1380:
	case PCI_DEVICE_ID_ARECA_1381:
	case PCI_DEVICE_ID_ARECA_1680:
	case PCI_DEVICE_ID_ARECA_1681:
		type = "SAS 3G";
		break;
	case PCI_DEVICE_ID_ARECA_1880:
		type = "SAS 6G";
		break;
	default:
		type = "X-TYPE";
		arcmsr_warn(acb, "Unknown Host Adapter RAID Controller!");
		goto error_level_0;
	}

	arcmsr_log(acb, CE_CONT, "Areca %s Host Adapter RAID Controller%s\n",
	    type, raid6 ? " (RAID6 capable)" : "");

	/* we disable iop interrupt here */
	if (arcmsr_initialize(acb) == DDI_FAILURE) {
		arcmsr_warn(acb, "arcmsr_initialize failed");
		goto error_level_1;
	}

	/* Allocate a transport structure */
	hba_trans = scsi_hba_tran_alloc(dev_info, SCSI_HBA_CANSLEEP);
	if (hba_trans == NULL) {
		arcmsr_warn(acb, "scsi_hba_tran_alloc failed");
		goto error_level_2;
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
	hba_trans->tran_bus_config = arcmsr_tran_bus_config;
	hba_trans->tran_add_eventcall = NULL;
	hba_trans->tran_get_eventcookie = NULL;
	hba_trans->tran_post_event = NULL;
	hba_trans->tran_remove_eventcall = NULL;

	/* iop init and enable interrupt here */
	arcmsr_iop_init(acb);

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(dev_info, &intr_types) !=
	    DDI_SUCCESS) {
		arcmsr_warn(acb, "ddi_intr_get_supported_types failed");
		goto error_level_3;
	}
	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (arcmsr_add_intr(acb, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS)
			goto error_level_5;
	} else if (intr_types & DDI_INTR_TYPE_MSI) {
		if (arcmsr_add_intr(acb, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS)
			goto error_level_5;
	}

	/*
	 * The driver should attach this instance of the device, and
	 * perform error cleanup if necessary
	 */
	if (scsi_hba_attach_setup(dev_info, &arcmsr_dma_attr,
	    hba_trans, SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS) {
		arcmsr_warn(acb, "scsi_hba_attach_setup failed");
		goto error_level_5;
	}

	/* Create a taskq for dealing with dr events */
	if ((acb->taskq = ddi_taskq_create(dev_info, "arcmsr_dr_taskq", 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		arcmsr_warn(acb, "ddi_taskq_create failed");
		goto error_level_8;
	}

	acb->timeout_count = 0;
	/* active ccbs "timeout" watchdog */
	acb->timeout_id = timeout(arcmsr_ccbs_timeout, (caddr_t)acb,
	    (ARCMSR_TIMEOUT_WATCH * drv_usectohz(1000000)));
	acb->timeout_sc_id = timeout(arcmsr_devMap_monitor, (caddr_t)acb,
	    (ARCMSR_DEV_MAP_WATCH * drv_usectohz(1000000)));

	/* report device info */
	ddi_report_dev(dev_info);

	return (DDI_SUCCESS);

error_level_8:

error_level_7:
error_level_6:
	(void) scsi_hba_detach(dev_info);

error_level_5:
	arcmsr_remove_intr(acb);

error_level_3:
error_level_4:
	if (acb->scsi_hba_transport)
		scsi_hba_tran_free(acb->scsi_hba_transport);

error_level_2:
	if (acb->ccbs_acc_handle)
		ddi_dma_mem_free(&acb->ccbs_acc_handle);
	if (acb->ccbs_pool_handle)
		ddi_dma_free_handle(&acb->ccbs_pool_handle);

error_level_1:
	if (acb->pci_acc_handle)
		pci_config_teardown(&acb->pci_acc_handle);
	arcmsr_mutex_destroy(acb);
	ddi_soft_state_free(arcmsr_soft_state, instance);

error_level_0:
	return (DDI_FAILURE);
}


static void
arcmsr_vlog(struct ACB *acb, int level, char *fmt, va_list ap)
{
	char	buf[256];

	if (acb != NULL) {
		(void) snprintf(buf, sizeof (buf), "%s%d: %s",
		    ddi_driver_name(acb->dev_info),
		    ddi_get_instance(acb->dev_info), fmt);
		fmt = buf;
	}
	vcmn_err(level, fmt, ap);
}

static void
arcmsr_log(struct ACB *acb, int level, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	arcmsr_vlog(acb, level, fmt, ap);
	va_end(ap);
}

static void
arcmsr_warn(struct ACB *acb, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	arcmsr_vlog(acb, CE_WARN, fmt, ap);
	va_end(ap);
}

static void
arcmsr_init_list_head(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static void
arcmsr_x_list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

static void
arcmsr_x_list_add(struct list_head *new_one,  struct list_head *prev,
    struct list_head *next)
{
	next->prev = new_one;
	new_one->next = next;
	new_one->prev = prev;
	prev->next = new_one;
}

static void
arcmsr_list_add_tail(kmutex_t *list_lock, struct list_head *new_one,
    struct list_head *head)
{
	mutex_enter(list_lock);
	arcmsr_x_list_add(new_one, head->prev, head);
	mutex_exit(list_lock);
}

static struct list_head *
arcmsr_list_get_first(kmutex_t *list_lock, struct list_head *head)
{
	struct list_head *one = NULL;

	mutex_enter(list_lock);
	if (head->next == head)	{
		mutex_exit(list_lock);
		return (NULL);
	}
	one = head->next;
	arcmsr_x_list_del(one->prev, one->next);
	arcmsr_init_list_head(one);
	mutex_exit(list_lock);
	return (one);
}

static struct CCB *
arcmsr_get_complete_ccb_from_list(struct ACB *acb)
{
	struct list_head *first_complete_ccb_list = NULL;
	struct CCB *ccb;

	first_complete_ccb_list =
	    arcmsr_list_get_first(&acb->ccb_complete_list_mutex,
	    &acb->ccb_complete_list);
	if (first_complete_ccb_list == NULL) {
		return (NULL);
	}
	ccb = (void *)((caddr_t)(first_complete_ccb_list) -
	    offsetof(struct CCB, complete_queue_pointer));
	return (ccb);
}

static struct CCB *
arcmsr_get_freeccb(struct ACB *acb)
{
	struct CCB *ccb;
	int ccb_get_index, ccb_put_index;

	mutex_enter(&acb->workingQ_mutex);
	ccb_put_index = acb->ccb_put_index;
	ccb_get_index = acb->ccb_get_index;
	ccb = acb->ccbworkingQ[ccb_get_index];
	ccb_get_index++;
	if (ccb_get_index >= ARCMSR_MAX_FREECCB_NUM)
		ccb_get_index = ccb_get_index - ARCMSR_MAX_FREECCB_NUM;
	if (ccb_put_index != ccb_get_index) {
		acb->ccb_get_index = ccb_get_index;
		arcmsr_init_list_head(&ccb->complete_queue_pointer);
		ccb->ccb_state = ARCMSR_CCB_UNBUILD;
	} else {
		ccb = NULL;
	}
	mutex_exit(&acb->workingQ_mutex);
	return (ccb);
}


static void
arcmsr_free_ccb(struct CCB *ccb)
{
	struct ACB *acb = ccb->acb;

	if (ccb->ccb_state == ARCMSR_CCB_FREE) {
		return;
	}
	mutex_enter(&acb->workingQ_mutex);
	ccb->ccb_state = ARCMSR_CCB_FREE;
	ccb->pkt = NULL;
	ccb->pkt_dma_handle = NULL;
	ccb->ccb_flags = 0;
	acb->ccbworkingQ[acb->ccb_put_index] = ccb;
	acb->ccb_put_index++;
	if (acb->ccb_put_index >= ARCMSR_MAX_FREECCB_NUM)
		acb->ccb_put_index =
		    acb->ccb_put_index - ARCMSR_MAX_FREECCB_NUM;
	mutex_exit(&acb->workingQ_mutex);
}


static void
arcmsr_ccbs_timeout(void* arg)
{
	struct ACB *acb = (struct ACB *)arg;
	struct CCB *ccb;
	int i, instance, timeout_count = 0;
	uint32_t intmask_org;
	time_t current_time = ddi_get_time();

	intmask_org = arcmsr_disable_allintr(acb);
	mutex_enter(&acb->isr_mutex);
	if (acb->ccboutstandingcount != 0) {
		/* check each ccb */
		i = ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		if (i != DDI_SUCCESS) {
			if ((acb->timeout_id != 0) &&
			    ((acb->acb_flags & ACB_F_SCSISTOPADAPTER) == 0)) {
				/* do pkt timeout check each 60 secs */
				acb->timeout_id = timeout(arcmsr_ccbs_timeout,
				    (void*)acb, (ARCMSR_TIMEOUT_WATCH *
				    drv_usectohz(1000000)));
			}
			mutex_exit(&acb->isr_mutex);
			arcmsr_enable_allintr(acb, intmask_org);
			return;
		}
		instance = ddi_get_instance(acb->dev_info);
		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->acb != acb) {
				break;
			}
			if (ccb->ccb_state == ARCMSR_CCB_FREE) {
				continue;
			}
			if (ccb->pkt == NULL) {
				continue;
			}
			if (ccb->pkt->pkt_time == 0) {
				continue;
			}
			if (ccb->ccb_time >= current_time) {
				continue;
			}
			int id = ccb->pkt->pkt_address.a_target;
			int lun = ccb->pkt->pkt_address.a_lun;
			if (ccb->ccb_state == ARCMSR_CCB_START) {
				uint8_t	*cdb = (uint8_t	*)&ccb->arcmsr_cdb.Cdb;

				timeout_count++;
				arcmsr_warn(acb,
				    "scsi target %d lun %d cmd=0x%x "
				    "command timeout, ccb=0x%p",
				    instance, id, lun, *cdb, (void *)ccb);
				ccb->ccb_state = ARCMSR_CCB_TIMEOUT;
				ccb->pkt->pkt_reason = CMD_TIMEOUT;
				ccb->pkt->pkt_statistics = STAT_TIMEOUT;
				/* acb->devstate[id][lun] = ARECA_RAID_GONE; */
				arcmsr_ccb_complete(ccb, 1);
				continue;
			} else if ((ccb->ccb_state & ARCMSR_CCB_CAN_BE_FREE) ==
			    ARCMSR_CCB_CAN_BE_FREE) {
				arcmsr_free_ccb(ccb);
			}
		}
	}
	if ((acb->timeout_id != 0) &&
	    ((acb->acb_flags & ACB_F_SCSISTOPADAPTER) == 0)) {
		/* do pkt timeout check each 60 secs */
		acb->timeout_id = timeout(arcmsr_ccbs_timeout,
		    (void*)acb, (ARCMSR_TIMEOUT_WATCH * drv_usectohz(1000000)));
	}
	mutex_exit(&acb->isr_mutex);
	arcmsr_enable_allintr(acb, intmask_org);
}

static void
arcmsr_abort_dr_ccbs(struct ACB *acb, uint16_t target, uint8_t lun)
{
	struct CCB *ccb;
	uint32_t intmask_org;
	int i;

	/* disable all outbound interrupts */
	intmask_org = arcmsr_disable_allintr(acb);
	for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
		ccb = acb->pccb_pool[i];
		if (ccb->ccb_state == ARCMSR_CCB_START) {
			if ((target == ccb->pkt->pkt_address.a_target) &&
			    (lun == ccb->pkt->pkt_address.a_lun)) {
				ccb->ccb_state = ARCMSR_CCB_ABORTED;
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
				arcmsr_log(acb, CE_NOTE,
				    "abort T%dL%d ccb", target, lun);
			}
		}
	}
	/* enable outbound Post Queue, outbound doorbell Interrupt */
	arcmsr_enable_allintr(acb, intmask_org);
}

static int
arcmsr_scsi_device_probe(struct ACB *acb, uint16_t tgt, uint8_t lun)
{
	struct scsi_device sd;
	dev_info_t *child;
	int rval;

	bzero(&sd, sizeof (struct scsi_device));
	sd.sd_address.a_hba_tran = acb->scsi_hba_transport;
	sd.sd_address.a_target = (uint16_t)tgt;
	sd.sd_address.a_lun = (uint8_t)lun;
	if ((child = arcmsr_find_child(acb, tgt, lun)) != NULL) {
		rval = scsi_hba_probe(&sd, NULL);
		if (rval == SCSIPROBE_EXISTS) {
			rval = ndi_devi_online(child, NDI_ONLINE_ATTACH);
			if (rval != NDI_SUCCESS) {
				arcmsr_warn(acb, "unable to online T%dL%d",
				    tgt, lun);
			} else {
				arcmsr_log(acb, CE_NOTE, "T%dL%d onlined",
				    tgt, lun);
			}
		}
	} else {
		rval = scsi_hba_probe(&sd, NULL);
		if (rval == SCSIPROBE_EXISTS)
			rval = arcmsr_config_child(acb, &sd, NULL);
	}
	scsi_unprobe(&sd);
	return (rval);
}

static void
arcmsr_dr_handle(struct ACB *acb)
{
	char *acb_dev_map = (char *)acb->device_map;
	char *devicemap;
	char temp;
	uint16_t target;
	uint8_t lun;
	char diff;
	int circ = 0;
	dev_info_t *dip;
	ddi_acc_handle_t reg;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		devicemap = (char *)&phbamu->msgcode_rwbuffer[21];
		reg = acb->reg_mu_acc_handle0;
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		devicemap = (char *)
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[21];
		reg = acb->reg_mu_acc_handle1;
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		devicemap = (char *)&phbcmu->msgcode_rwbuffer[21];
		reg = acb->reg_mu_acc_handle0;
		break;
	}

	}

	for (target = 0; target < ARCMSR_MAX_TARGETID - 1; target++) {
		temp = CHIP_REG_READ8(reg, devicemap);
		diff = (*acb_dev_map)^ temp;
		if (diff != 0) {
			*acb_dev_map = temp;
			for (lun = 0; lun < ARCMSR_MAX_TARGETLUN; lun++) {
				if ((temp & 0x01) == 1 && (diff & 0x01) == 1) {
					ndi_devi_enter(acb->dev_info, &circ);
					acb->devstate[target][lun] =
					    ARECA_RAID_GOOD;
					(void) arcmsr_scsi_device_probe(acb,
					    target, lun);
					ndi_devi_exit(acb->dev_info, circ);
					arcmsr_log(acb, CE_NOTE,
					    "T%dL%d on-line", target, lun);
				} else if ((temp & 0x01) == 0 &&
				    (diff & 0x01) == 1) {
					dip = arcmsr_find_child(acb, target,
					    lun);
					if (dip != NULL) {
						acb->devstate[target][lun] =
						    ARECA_RAID_GONE;
						if (mutex_owned(&acb->
						    isr_mutex)) {
							arcmsr_abort_dr_ccbs(
							    acb, target, lun);
							(void)
							    ndi_devi_offline(
							    dip,
							    NDI_DEVI_REMOVE |
							    NDI_DEVI_OFFLINE);
						} else {
							mutex_enter(&acb->
							    isr_mutex);
							arcmsr_abort_dr_ccbs(
							    acb, target, lun);
							(void)
							    ndi_devi_offline(
							    dip,
							    NDI_DEVI_REMOVE |
							    NDI_DEVI_OFFLINE);
							mutex_exit(&acb->
							    isr_mutex);
						}
					}
					arcmsr_log(acb, CE_NOTE,
					    "T%dL%d off-line", target, lun);
				}
				temp >>= 1;
				diff >>= 1;
			}
		}
		devicemap++;
		acb_dev_map++;
	}
}


static void
arcmsr_devMap_monitor(void* arg)
{

	struct ACB *acb = (struct ACB *)arg;
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->inbound_msgaddr0,
		    ARCMSR_INBOUND_MESG0_GET_CONFIG);
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_MESSAGE_GET_CONFIG);
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->inbound_msgaddr0,
		    ARCMSR_INBOUND_MESG0_GET_CONFIG);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->inbound_doorbell,
		    ARCMSR_HBCMU_DRV2IOP_MESSAGE_CMD_DONE);
		break;
	}

	}

	if ((acb->timeout_id != 0) &&
	    ((acb->acb_flags & ACB_F_SCSISTOPADAPTER) == 0)) {
		/* do pkt timeout check each 5 secs */
		acb->timeout_id = timeout(arcmsr_devMap_monitor, (void*)acb,
		    (ARCMSR_DEV_MAP_WATCH * drv_usectohz(1000000)));
	}
}


static uint32_t
arcmsr_disable_allintr(struct ACB *acb) {

	uint32_t intmask_org;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/* disable all outbound interrupt */
		intmask_org = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intmask);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intmask,
		    intmask_org|ARCMSR_MU_OUTBOUND_ALL_INTMASKENABLE);
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		/* disable all outbound interrupt */
		intmask_org = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell_mask);
		/* disable all interrupts */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell_mask, 0);
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		/* disable all outbound interrupt */
		intmask_org = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbcmu->host_int_mask); /* disable outbound message0 int */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->host_int_mask,
		    intmask_org|ARCMSR_HBCMU_ALL_INTMASKENABLE);
		break;
	}

	}
	return (intmask_org);
}


static void
arcmsr_enable_allintr(struct ACB *acb, uint32_t intmask_org) {

	int mask;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/*
		 * enable outbound Post Queue, outbound doorbell message0
		 * Interrupt
		 */
		mask = ~(ARCMSR_MU_OUTBOUND_POSTQUEUE_INTMASKENABLE |
		    ARCMSR_MU_OUTBOUND_DOORBELL_INTMASKENABLE |
		    ARCMSR_MU_OUTBOUND_MESSAGE0_INTMASKENABLE);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_intmask, intmask_org & mask);
		acb->outbound_int_enable = ~(intmask_org & mask) & 0x000000ff;
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		mask = (ARCMSR_IOP2DRV_DATA_WRITE_OK |
		    ARCMSR_IOP2DRV_DATA_READ_OK | ARCMSR_IOP2DRV_CDB_DONE |
		    ARCMSR_IOP2DRV_MESSAGE_CMD_DONE);
		/* 1=interrupt enable, 0=interrupt disable */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->iop2drv_doorbell_mask,
		    intmask_org | mask);
		acb->outbound_int_enable = (intmask_org | mask) & 0x0000000f;
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		/* enable outbound Post Queue,outbound doorbell Interrupt */
		mask = ~(ARCMSR_HBCMU_UTILITY_A_ISR_MASK |
		    ARCMSR_HBCMU_OUTBOUND_DOORBELL_ISR_MASK |
		    ARCMSR_HBCMU_OUTBOUND_POSTQUEUE_ISR_MASK);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->host_int_mask, intmask_org & mask);
		acb->outbound_int_enable = ~(intmask_org & mask) & 0x0000000f;
		break;
	}

	}
}


static void
arcmsr_iop_parking(struct ACB *acb)
{
	/* stop adapter background rebuild */
	if (acb->acb_flags & ACB_F_MSG_START_BGRB) {
		uint32_t intmask_org;

		acb->acb_flags &= ~ACB_F_MSG_START_BGRB;
		/* disable all outbound interrupt */
		intmask_org = arcmsr_disable_allintr(acb);
		switch (acb->adapter_type) {
		case ACB_ADAPTER_TYPE_A:
			arcmsr_stop_hba_bgrb(acb);
			arcmsr_flush_hba_cache(acb);
			break;

		case ACB_ADAPTER_TYPE_B:
			arcmsr_stop_hbb_bgrb(acb);
			arcmsr_flush_hbb_cache(acb);
			break;

		case ACB_ADAPTER_TYPE_C:
			arcmsr_stop_hbc_bgrb(acb);
			arcmsr_flush_hbc_cache(acb);
			break;
		}
		/*
		 * enable outbound Post Queue
		 * enable outbound doorbell Interrupt
		 */
		arcmsr_enable_allintr(acb, intmask_org);
	}
}


static uint8_t
arcmsr_hba_wait_msgint_ready(struct ACB *acb)
{
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
arcmsr_hbb_wait_msgint_ready(struct ACB *acb)
{
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


static uint8_t
arcmsr_hbc_wait_msgint_ready(struct ACB *acb)
{
	uint32_t i;
	uint8_t retries = 0x00;
	struct HBC_msgUnit *phbcmu;
	uint32_t c = ARCMSR_HBCMU_IOP2DRV_MESSAGE_CMD_DONE_DOORBELL_CLEAR;


	phbcmu = (struct HBC_msgUnit *)acb->pmu;

	do {
		for (i = 0; i < 100; i++) {
			if (CHIP_REG_READ32(acb->reg_mu_acc_handle0,
			    &phbcmu->outbound_doorbell) &
			    ARCMSR_HBCMU_IOP2DRV_MESSAGE_CMD_DONE) {
				/* clear interrupt */
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbcmu->outbound_doorbell_clear, c);
				return (TRUE);
			}
			drv_usecwait(10000);
			if (ddi_in_panic()) {
				/* clear interrupts */
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbcmu->outbound_doorbell_clear, c);
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
arcmsr_flush_hbc_cache(struct ACB *acb)
{
	struct HBC_msgUnit *phbcmu;
	int retry_count = 30;

	/* enlarge wait flush adapter cache time: 10 minutes */

	phbcmu = (struct HBC_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbcmu->inbound_msgaddr0,
	    ARCMSR_INBOUND_MESG0_FLUSH_CACHE);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbcmu->inbound_doorbell,
	    ARCMSR_HBCMU_DRV2IOP_MESSAGE_CMD_DONE);
	do {
		if (arcmsr_hbc_wait_msgint_ready(acb)) {
			break;
		} else {
			retry_count--;
		}
	} while (retry_count != 0);
}



static uint8_t
arcmsr_abort_hba_allcmd(struct ACB *acb)
{
	struct HBA_msgUnit *phbamu = (struct HBA_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbamu->inbound_msgaddr0,
	    ARCMSR_INBOUND_MESG0_ABORT_CMD);

	if (!arcmsr_hba_wait_msgint_ready(acb)) {
		arcmsr_warn(acb,
		    "timeout while waiting for 'abort all "
		    "outstanding commands'");
		return (0xff);
	}
	return (0x00);
}



static uint8_t
arcmsr_abort_hbb_allcmd(struct ACB *acb)
{
	struct HBB_msgUnit *phbbmu = (struct HBB_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell, ARCMSR_MESSAGE_ABORT_CMD);

	if (!arcmsr_hbb_wait_msgint_ready(acb)) {
		arcmsr_warn(acb,
		    "timeout while waiting for 'abort all "
		    "outstanding commands'");
		return (0x00);
	}
	return (0x00);
}


static uint8_t
arcmsr_abort_hbc_allcmd(struct ACB *acb)
{
	struct HBC_msgUnit *phbcmu = (struct HBC_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbcmu->inbound_msgaddr0,
	    ARCMSR_INBOUND_MESG0_ABORT_CMD);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbcmu->inbound_doorbell,
	    ARCMSR_HBCMU_DRV2IOP_MESSAGE_CMD_DONE);

	if (!arcmsr_hbc_wait_msgint_ready(acb)) {
		arcmsr_warn(acb,
		    "timeout while waiting for 'abort all "
		    "outstanding commands'");
		return (0xff);
	}
	return (0x00);
}


static void
arcmsr_done4abort_postqueue(struct ACB *acb)
{

	struct CCB *ccb;
	uint32_t flag_ccb;
	int i = 0;
	boolean_t error;

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
			/* frame must be 32 bytes aligned */
			/* the CDB is the first field of the CCB */
			ccb = NumToPtr((acb->vir2phy_offset + (flag_ccb << 5)));
			/* check if command done with no error */
			error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE0) ?
			    B_TRUE : B_FALSE;
			arcmsr_drain_donequeue(acb, ccb, error);
		}
		break;
	}

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
				/* frame must be 32 bytes aligned */
				ccb = NumToPtr((acb->vir2phy_offset +
				    (flag_ccb << 5)));
				/* check if command done with no error */
				error =
				    (flag_ccb &
				    ARCMSR_CCBREPLY_FLAG_ERROR_MODE0) ?
				    B_TRUE : B_FALSE;
				arcmsr_drain_donequeue(acb, ccb, error);
			}
			phbbmu->post_qbuffer[i] = 0;
		}	/* drain reply FIFO */
		phbbmu->doneq_index = 0;
		phbbmu->postq_index = 0;
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;
		uint32_t ccb_cdb_phy;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		while ((CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbcmu->host_int_status) &
		    ARCMSR_HBCMU_OUTBOUND_POSTQUEUE_ISR) &&
		    (i++ < ARCMSR_MAX_OUTSTANDING_CMD)) {
			/* need to do */
			flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
			    &phbcmu->outbound_queueport_low);
			/* frame must be 32 bytes aligned */
			ccb_cdb_phy = (flag_ccb & 0xFFFFFFF0);
			ccb = NumToPtr((acb->vir2phy_offset + ccb_cdb_phy));
			error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE1)?
			    B_TRUE : B_FALSE;
			arcmsr_drain_donequeue(acb, ccb, error);
		}
		break;
	}

	}
}
/*
 * Routine Description: try to get echo from iop.
 *           Arguments:
 *        Return Value: Nothing.
 */
static uint8_t
arcmsr_get_echo_from_iop(struct ACB *acb)
{
	uint32_t intmask_org;
	uint8_t rtnval = 0;

	if (acb->adapter_type == ACB_ADAPTER_TYPE_A) {
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		intmask_org = arcmsr_disable_allintr(acb);
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->inbound_msgaddr0,
		    ARCMSR_INBOUND_MESG0_GET_CONFIG);
		if (!arcmsr_hba_wait_msgint_ready(acb)) {
			arcmsr_warn(acb, "try to get echo from iop,"
			    "... timeout ...");
			acb->acb_flags |= ACB_F_BUS_HANG_ON;
			rtnval = 0xFF;
		}
		/* enable all outbound interrupt */
		arcmsr_enable_allintr(acb, intmask_org);
	}
	return (rtnval);
}

/*
 * Routine Description: Reset 80331 iop.
 *           Arguments:
 *        Return Value: Nothing.
 */
static uint8_t
arcmsr_iop_reset(struct ACB *acb)
{
	struct CCB *ccb;
	uint32_t intmask_org;
	uint8_t rtnval = 0;
	int i = 0;

	if (acb->ccboutstandingcount > 0) {
		/* disable all outbound interrupt */
		intmask_org = arcmsr_disable_allintr(acb);
		/* clear and abort all outbound posted Q */
		arcmsr_done4abort_postqueue(acb);
		/* talk to iop 331 outstanding command aborted */
		rtnval = (acb->acb_flags & ACB_F_BUS_HANG_ON) ?
		    0xFF : arcmsr_abort_host_command(acb);

		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->ccb_state == ARCMSR_CCB_START) {
				/* ccb->ccb_state = ARCMSR_CCB_RESET; */
				ccb->pkt->pkt_reason = CMD_RESET;
				ccb->pkt->pkt_statistics |= STAT_BUS_RESET;
				arcmsr_ccb_complete(ccb, 1);
			}
		}
		atomic_and_32(&acb->ccboutstandingcount, 0);
		/* enable all outbound interrupt */
		arcmsr_enable_allintr(acb, intmask_org);
	} else {
		rtnval = arcmsr_get_echo_from_iop(acb);
	}
	return (rtnval);
}


static struct QBUFFER *
arcmsr_get_iop_rqbuffer(struct ACB *acb)
{
	struct QBUFFER *qb;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		qb = (struct QBUFFER *)&phbamu->message_rbuffer;
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		qb = (struct QBUFFER *)&phbbmu->hbb_rwbuffer->message_rbuffer;
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		qb = (struct QBUFFER *)&phbcmu->message_rbuffer;
		break;
	}

	}
	return (qb);
}


static struct QBUFFER *
arcmsr_get_iop_wqbuffer(struct ACB *acb)
{
	struct QBUFFER *qbuffer = NULL;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		qbuffer = (struct QBUFFER *)&phbamu->message_wbuffer;
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		qbuffer = (struct QBUFFER *)
		    &phbbmu->hbb_rwbuffer->message_wbuffer;
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		qbuffer = (struct QBUFFER *)&phbcmu->message_wbuffer;
		break;
	}

	}
	return (qbuffer);
}



static void
arcmsr_iop_message_read(struct ACB *acb)
{
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/* let IOP know the data has been read */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->inbound_doorbell,
		    ARCMSR_INBOUND_DRIVER_DATA_READ_OK);
		break;
	}

	case ACB_ADAPTER_TYPE_B:
	{
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		/* let IOP know the data has been read */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_DRV2IOP_DATA_READ_OK);
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		/* let IOP know data has been read */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->inbound_doorbell,
		    ARCMSR_HBCMU_DRV2IOP_DATA_READ_OK);
		break;
	}

	}
}



static void
arcmsr_iop_message_wrote(struct ACB *acb)
{
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A: {
		struct HBA_msgUnit *phbamu;

		phbamu = (struct HBA_msgUnit *)acb->pmu;
		/*
		 * push inbound doorbell tell iop, driver data write ok
		 * and wait reply on next hwinterrupt for next Qbuffer post
		 */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->inbound_doorbell,
		    ARCMSR_INBOUND_DRIVER_DATA_WRITE_OK);
		break;
	}

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
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		/*
		 * push inbound doorbell tell iop, driver data write ok
		 * and wait reply on next hwinterrupt for next Qbuffer post
		 */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->inbound_doorbell,
		    ARCMSR_HBCMU_DRV2IOP_DATA_WRITE_OK);
		break;
	}

	}
}



static void
arcmsr_post_ioctldata2iop(struct ACB *acb)
{
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
arcmsr_stop_hba_bgrb(struct ACB *acb)
{
	struct HBA_msgUnit *phbamu;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	acb->acb_flags &= ~ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbamu->inbound_msgaddr0, ARCMSR_INBOUND_MESG0_STOP_BGRB);
	if (!arcmsr_hba_wait_msgint_ready(acb))
		arcmsr_warn(acb,
		    "timeout while waiting for background rebuild completion");
}


static void
arcmsr_stop_hbb_bgrb(struct ACB *acb)
{
	struct HBB_msgUnit *phbbmu;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	acb->acb_flags &= ~ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell, ARCMSR_MESSAGE_STOP_BGRB);

	if (!arcmsr_hbb_wait_msgint_ready(acb))
		arcmsr_warn(acb,
		    "timeout while waiting for background rebuild completion");
}


static void
arcmsr_stop_hbc_bgrb(struct ACB *acb)
{
	struct HBC_msgUnit *phbcmu;

	phbcmu = (struct HBC_msgUnit *)acb->pmu;

	acb->acb_flags &= ~ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->inbound_msgaddr0, ARCMSR_INBOUND_MESG0_STOP_BGRB);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->inbound_doorbell, ARCMSR_HBCMU_DRV2IOP_MESSAGE_CMD_DONE);
	if (!arcmsr_hbc_wait_msgint_ready(acb))
		arcmsr_warn(acb,
		    "timeout while waiting for background rebuild completion");
}


static int
arcmsr_iop_message_xfer(struct ACB *acb, struct scsi_pkt *pkt)
{
	struct CMD_MESSAGE_FIELD *pcmdmessagefld;
	struct CCB *ccb = pkt->pkt_ha_private;
	struct buf *bp = ccb->bp;
	uint8_t *pQbuffer;
	int retvalue = 0, transfer_len = 0;
	char *buffer;
	uint32_t controlcode;


	/* 4 bytes: Areca io control code */
	controlcode =
	    (uint32_t)pkt->pkt_cdbp[5] << 24 |
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
		break;
	}

	case ARCMSR_MESSAGE_WRITE_WQBUFFER:
	{
		uint8_t *ver_addr;
		int32_t my_empty_len, user_len, wqbuf_firstidx,
		    wqbuf_lastidx;
		uint8_t *ptmpuserbuffer;

		ver_addr = kmem_zalloc(MSGDATABUFLEN, KM_SLEEP);

		ptmpuserbuffer = ver_addr;
		user_len = min(pcmdmessagefld->cmdmessage.Length,
		    MSGDATABUFLEN);
		(void) memcpy(ptmpuserbuffer,
		    pcmdmessagefld->messagedatabuffer, user_len);
		wqbuf_lastidx = acb->wqbuf_lastidx;
		wqbuf_firstidx = acb->wqbuf_firstidx;
		if (wqbuf_lastidx != wqbuf_firstidx) {
			struct scsi_arq_status *arq_status;

			arcmsr_post_ioctldata2iop(acb);
			arq_status = (struct scsi_arq_status *)
			    (intptr_t)(pkt->pkt_scbp);
			bzero((caddr_t)arq_status,
			    sizeof (struct scsi_arq_status));
			arq_status->sts_rqpkt_reason = CMD_CMPLT;
			arq_status->sts_rqpkt_state = (STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA | STATE_GOT_STATUS);

			arq_status->sts_rqpkt_statistics =
			    pkt->pkt_statistics;
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
					pQbuffer = &acb->wqbuffer[
					    acb->wqbuf_lastidx];
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
				arq_status = (struct scsi_arq_status *)
				    (intptr_t)(pkt->pkt_scbp);
				bzero((caddr_t)arq_status,
				    sizeof (struct scsi_arq_status));
				arq_status->sts_rqpkt_reason = CMD_CMPLT;
				arq_status->sts_rqpkt_state =
				    (STATE_GOT_BUS |
				    STATE_GOT_TARGET |STATE_SENT_CMD |
				    STATE_XFERRED_DATA | STATE_GOT_STATUS);
				arq_status->sts_rqpkt_statistics =
				    pkt->pkt_statistics;
				arq_status->sts_rqpkt_resid = 0;
				if (&arq_status->sts_sensedata != NULL) {
					struct scsi_extended_sense *
					    sts_sensedata;

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
		break;
	}

	case ARCMSR_MESSAGE_CLEAR_RQBUFFER:
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
		break;
	case ARCMSR_MESSAGE_CLEAR_WQBUFFER:
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
		break;
	case ARCMSR_MESSAGE_CLEAR_ALLQBUFFER:

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
		switch (acb->adapter_type) {
		case ACB_ADAPTER_TYPE_A:
			arcmsr_flush_hba_cache(acb);
			break;
		case ACB_ADAPTER_TYPE_B:
			arcmsr_flush_hbb_cache(acb);
			break;
		case ACB_ADAPTER_TYPE_C:
			arcmsr_flush_hbc_cache(acb);
			break;
		}
		break;
	default:
		retvalue = ARCMSR_MESSAGE_FAIL;
	}

message_out:

	return (retvalue);
}




static void
arcmsr_pcidev_disattach(struct ACB *acb)
{
	struct CCB *ccb;
	int i = 0;

	/* disable all outbound interrupts */
	(void) arcmsr_disable_allintr(acb);
	/* stop adapter background rebuild */
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
		arcmsr_stop_hba_bgrb(acb);
		arcmsr_flush_hba_cache(acb);
		break;
	case ACB_ADAPTER_TYPE_B:
		arcmsr_stop_hbb_bgrb(acb);
		arcmsr_flush_hbb_cache(acb);
		break;
	case ACB_ADAPTER_TYPE_C:
		arcmsr_stop_hbc_bgrb(acb);
		arcmsr_flush_hbc_cache(acb);
		break;
	}
	/* abort all outstanding commands */
	acb->acb_flags |= ACB_F_SCSISTOPADAPTER;
	acb->acb_flags &= ~ACB_F_IOP_INITED;

	if (acb->ccboutstandingcount != 0) {
		/* clear and abort all outbound posted Q */
		arcmsr_done4abort_postqueue(acb);
		/* talk to iop outstanding command aborted */
		(void) arcmsr_abort_host_command(acb);

		for (i = 0; i < ARCMSR_MAX_FREECCB_NUM; i++) {
			ccb = acb->pccb_pool[i];
			if (ccb->ccb_state == ARCMSR_CCB_START) {
				/* ccb->ccb_state = ARCMSR_CCB_ABORTED; */
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
			}
		}
	}
}

/* get firmware miscellaneous data */
static void
arcmsr_get_hba_config(struct ACB *acb)
{
	struct HBA_msgUnit *phbamu;

	char *acb_firm_model;
	char *acb_firm_version;
	char *acb_device_map;
	char *iop_firm_model;
	char *iop_firm_version;
	char *iop_device_map;
	int count;

	phbamu = (struct HBA_msgUnit *)acb->pmu;
	acb_firm_model = acb->firm_model;
	acb_firm_version = acb->firm_version;
	acb_device_map = acb->device_map;
	/* firm_model, 15 */
	iop_firm_model =
	    (char *)(&phbamu->msgcode_rwbuffer[ARCMSR_FW_MODEL_OFFSET]);
	/* firm_version, 17 */
	iop_firm_version =
	    (char *)(&phbamu->msgcode_rwbuffer[ARCMSR_FW_VERS_OFFSET]);

	/* device_map, 21 */
	iop_device_map =
	    (char *)(&phbamu->msgcode_rwbuffer[ARCMSR_FW_MAP_OFFSET]);

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbamu->inbound_msgaddr0, ARCMSR_INBOUND_MESG0_GET_CONFIG);

	if (!arcmsr_hba_wait_msgint_ready(acb))
		arcmsr_warn(acb,
		    "timeout while waiting for adapter firmware "
		    "miscellaneous data");

	count = 8;
	while (count) {
		*acb_firm_model = CHIP_REG_READ8(acb->reg_mu_acc_handle0,
		    iop_firm_model);
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

	count = 16;
	while (count) {
		*acb_device_map =
		    CHIP_REG_READ8(acb->reg_mu_acc_handle0, iop_device_map);
		acb_device_map++;
		iop_device_map++;
		count--;
	}

	arcmsr_log(acb, CE_CONT, "ARECA RAID FIRMWARE VERSION %s\n",
	    acb->firm_version);

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
arcmsr_get_hbb_config(struct ACB *acb)
{
	struct HBB_msgUnit *phbbmu;
	char *acb_firm_model;
	char *acb_firm_version;
	char *acb_device_map;
	char *iop_firm_model;
	char *iop_firm_version;
	char *iop_device_map;
	int count;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;
	acb_firm_model = acb->firm_model;
	acb_firm_version = acb->firm_version;
	acb_device_map = acb->device_map;
	/* firm_model, 15 */
	iop_firm_model = (char *)
	    (&phbbmu->hbb_rwbuffer->msgcode_rwbuffer[ARCMSR_FW_MODEL_OFFSET]);
	/* firm_version, 17 */
	iop_firm_version = (char *)
	    (&phbbmu->hbb_rwbuffer->msgcode_rwbuffer[ARCMSR_FW_VERS_OFFSET]);
	/* device_map, 21 */
	iop_device_map = (char *)
	    (&phbbmu->hbb_rwbuffer->msgcode_rwbuffer[ARCMSR_FW_MAP_OFFSET]);

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell, ARCMSR_MESSAGE_GET_CONFIG);

	if (!arcmsr_hbb_wait_msgint_ready(acb))
		arcmsr_warn(acb,
		    "timeout while waiting for adapter firmware "
		    "miscellaneous data");

	count = 8;
	while (count) {
		*acb_firm_model =
		    CHIP_REG_READ8(acb->reg_mu_acc_handle1, iop_firm_model);
		acb_firm_model++;
		iop_firm_model++;
		count--;
	}
	count = 16;
	while (count) {
		*acb_firm_version =
		    CHIP_REG_READ8(acb->reg_mu_acc_handle1, iop_firm_version);
		acb_firm_version++;
		iop_firm_version++;
		count--;
	}
	count = 16;
	while (count) {
		*acb_device_map =
		    CHIP_REG_READ8(acb->reg_mu_acc_handle1, iop_device_map);
		acb_device_map++;
		iop_device_map++;
		count--;
	}

	arcmsr_log(acb, CE_CONT, "ARECA RAID FIRMWARE VERSION %s\n",
	    acb->firm_version);

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


/* get firmware miscellaneous data */
static void
arcmsr_get_hbc_config(struct ACB *acb)
{
	struct HBC_msgUnit *phbcmu;

	char *acb_firm_model;
	char *acb_firm_version;
	char *acb_device_map;
	char *iop_firm_model;
	char *iop_firm_version;
	char *iop_device_map;
	int count;

	phbcmu = (struct HBC_msgUnit *)acb->pmu;
	acb_firm_model = acb->firm_model;
	acb_firm_version = acb->firm_version;
	acb_device_map = acb->device_map;
	/* firm_model, 15 */
	iop_firm_model =
	    (char *)(&phbcmu->msgcode_rwbuffer[ARCMSR_FW_MODEL_OFFSET]);
	/* firm_version, 17 */
	iop_firm_version =
	    (char *)(&phbcmu->msgcode_rwbuffer[ARCMSR_FW_VERS_OFFSET]);
	/* device_map, 21 */
	iop_device_map =
	    (char *)(&phbcmu->msgcode_rwbuffer[ARCMSR_FW_MAP_OFFSET]);
	/* post "get config" instruction */
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->inbound_msgaddr0, ARCMSR_INBOUND_MESG0_GET_CONFIG);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->inbound_doorbell, ARCMSR_HBCMU_DRV2IOP_MESSAGE_CMD_DONE);
	if (!arcmsr_hbc_wait_msgint_ready(acb))
		arcmsr_warn(acb,
		    "timeout while waiting for adapter firmware "
		    "miscellaneous data");
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

	count = 16;
	while (count) {
		*acb_device_map =
		    CHIP_REG_READ8(acb->reg_mu_acc_handle0, iop_device_map);
		acb_device_map++;
		iop_device_map++;
		count--;
	}

	arcmsr_log(acb, CE_CONT, "ARECA RAID FIRMWARE VERSION %s\n",
	    acb->firm_version);

	/* firm_request_len, 1, 04-07 */
	acb->firm_request_len = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbcmu->msgcode_rwbuffer[1]);
	/* firm_numbers_queue, 2, 08-11 */
	acb->firm_numbers_queue = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbcmu->msgcode_rwbuffer[2]);
	/* firm_sdram_size, 3, 12-15 */
	acb->firm_sdram_size = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbcmu->msgcode_rwbuffer[3]);
	/* firm_ide_channels, 4, 16-19 */
	acb->firm_ide_channels = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbcmu->msgcode_rwbuffer[4]);
	/* firm_cfg_version, 25, 100-103 */
	acb->firm_cfg_version = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbcmu->msgcode_rwbuffer[25]);
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
		arcmsr_warn(acb,
		    "timeout while waiting for background rebuild to start");
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
		arcmsr_warn(acb,
		    "timeout while waiting for background rebuild to start");
}


static void
arcmsr_start_hbc_bgrb(struct ACB *acb) {

	struct HBC_msgUnit *phbcmu;

	phbcmu = (struct HBC_msgUnit *)acb->pmu;

	acb->acb_flags |= ACB_F_MSG_START_BGRB;
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->inbound_msgaddr0, ARCMSR_INBOUND_MESG0_START_BGRB);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->inbound_doorbell, ARCMSR_HBCMU_DRV2IOP_MESSAGE_CMD_DONE);
	if (!arcmsr_hbc_wait_msgint_ready(acb))
		arcmsr_warn(acb,
		    "timeout while waiting for background rebuild to start");
}

static void
arcmsr_polling_hba_ccbdone(struct ACB *acb, struct CCB *poll_ccb)
{
	struct HBA_msgUnit *phbamu;
	struct CCB *ccb;
	boolean_t error;
	uint32_t flag_ccb, outbound_intstatus, intmask_org;
	boolean_t poll_ccb_done = B_FALSE;
	uint32_t poll_count = 0;


	phbamu = (struct HBA_msgUnit *)acb->pmu;

polling_ccb_retry:
	/* TODO: Use correct offset and size for syncing? */
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS)
		return;
	intmask_org = arcmsr_disable_allintr(acb);

	for (;;) {
		if ((flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_queueport)) == 0xFFFFFFFF) {
			if (poll_ccb_done) {
				/* chip FIFO no ccb for completion already */
				break;
			} else {
				drv_usecwait(25000);
				if ((poll_count > 100) && (poll_ccb != NULL)) {
					break;
				}
				if (acb->ccboutstandingcount == 0) {
					break;
				}
				poll_count++;
				outbound_intstatus =
				    CHIP_REG_READ32(acb->reg_mu_acc_handle0,
				    &phbamu->outbound_intstatus) &
				    acb->outbound_int_enable;

				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbamu->outbound_intstatus,
				    outbound_intstatus); /* clear interrupt */
			}
		}

		/* frame must be 32 bytes aligned */
		ccb = NumToPtr((acb->vir2phy_offset + (flag_ccb << 5)));

		/* check if command done with no error */
		error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE0) ?
		    B_TRUE : B_FALSE;
		if (poll_ccb != NULL)
			poll_ccb_done = (ccb == poll_ccb) ? B_TRUE : B_FALSE;

		if (ccb->acb != acb) {
			arcmsr_warn(acb, "ccb got a wrong acb!");
			continue;
		}
		if (ccb->ccb_state != ARCMSR_CCB_START) {
			if (ccb->ccb_state & ARCMSR_ABNORMAL_MASK) {
				ccb->ccb_state |= ARCMSR_CCB_BACK;
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
				continue;
			}
			arcmsr_report_ccb_state(acb, ccb, error);
			arcmsr_warn(acb,
			    "polling op got unexpected ccb command done");
			continue;
		}
		arcmsr_report_ccb_state(acb, ccb, error);
	}	/* drain reply FIFO */
	arcmsr_enable_allintr(acb, intmask_org);
}


static void
arcmsr_polling_hbb_ccbdone(struct ACB *acb, struct CCB *poll_ccb)
{
	struct HBB_msgUnit *phbbmu;
	struct CCB *ccb;
	uint32_t flag_ccb, intmask_org;
	boolean_t error;
	uint32_t poll_count = 0;
	int index;
	boolean_t poll_ccb_done = B_FALSE;


	phbbmu = (struct HBB_msgUnit *)acb->pmu;


polling_ccb_retry:
	/* Use correct offset and size for syncing */
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS)
		return;

	intmask_org = arcmsr_disable_allintr(acb);

	for (;;) {
		index = phbbmu->doneq_index;
		if ((flag_ccb = phbbmu->done_qbuffer[index]) == 0) {
			if (poll_ccb_done) {
				/* chip FIFO no ccb for completion already */
				break;
			} else {
				drv_usecwait(25000);
				if ((poll_count > 100) && (poll_ccb != NULL))
					break;
				if (acb->ccboutstandingcount == 0)
					break;
				poll_count++;
				/* clear doorbell interrupt */
				CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
				    &phbbmu->hbb_doorbell->iop2drv_doorbell,
				    ARCMSR_DOORBELL_INT_CLEAR_PATTERN);
			}
		}

		phbbmu->done_qbuffer[index] = 0;
		index++;
		/* if last index number set it to 0 */
		index %= ARCMSR_MAX_HBB_POSTQUEUE;
		phbbmu->doneq_index = index;
		/* check if command done with no error */
		/* frame must be 32 bytes aligned */
		ccb = NumToPtr((acb->vir2phy_offset + (flag_ccb << 5)));

		/* check if command done with no error */
		error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE0) ?
		    B_TRUE : B_FALSE;

		if (poll_ccb != NULL)
			poll_ccb_done = (ccb == poll_ccb) ? B_TRUE : B_FALSE;
		if (ccb->acb != acb) {
			arcmsr_warn(acb, "ccb got a wrong acb!");
			continue;
		}
		if (ccb->ccb_state != ARCMSR_CCB_START) {
			if (ccb->ccb_state & ARCMSR_ABNORMAL_MASK) {
				ccb->ccb_state |= ARCMSR_CCB_BACK;
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
				continue;
			}
			arcmsr_report_ccb_state(acb, ccb, error);
			arcmsr_warn(acb,
			    "polling op got unexpect ccb command done");
			continue;
		}
		arcmsr_report_ccb_state(acb, ccb, error);
	}	/* drain reply FIFO */
	arcmsr_enable_allintr(acb, intmask_org);
}


static void
arcmsr_polling_hbc_ccbdone(struct ACB *acb, struct CCB *poll_ccb)
{

	struct HBC_msgUnit *phbcmu;
	struct CCB *ccb;
	boolean_t error;
	uint32_t ccb_cdb_phy;
	uint32_t flag_ccb, intmask_org;
	boolean_t poll_ccb_done = B_FALSE;
	uint32_t poll_count = 0;


	phbcmu = (struct HBC_msgUnit *)acb->pmu;

polling_ccb_retry:

	/* Use correct offset and size for syncing */
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS)
		return;

	intmask_org = arcmsr_disable_allintr(acb);

	for (;;) {
		if (!(CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbcmu->host_int_status) &
		    ARCMSR_HBCMU_OUTBOUND_POSTQUEUE_ISR)) {

			if (poll_ccb_done) {
				/* chip FIFO no ccb for completion already */
				break;
			} else {
				drv_usecwait(25000);
				if ((poll_count > 100) && (poll_ccb != NULL)) {
					break;
				}
				if (acb->ccboutstandingcount == 0) {
					break;
				}
				poll_count++;
			}
		}
		flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbcmu->outbound_queueport_low);
		/* frame must be 32 bytes aligned */
		ccb_cdb_phy = (flag_ccb & 0xFFFFFFF0);
		/* the CDB is the first field of the CCB */
		ccb = NumToPtr((acb->vir2phy_offset + ccb_cdb_phy));

		/* check if command done with no error */
		error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE1) ?
		    B_TRUE : B_FALSE;
		if (poll_ccb != NULL)
			poll_ccb_done = (ccb == poll_ccb) ? B_TRUE : B_FALSE;

		if (ccb->acb != acb) {
			arcmsr_warn(acb, "ccb got a wrong acb!");
			continue;
		}
		if (ccb->ccb_state != ARCMSR_CCB_START) {
			if (ccb->ccb_state & ARCMSR_ABNORMAL_MASK) {
				ccb->ccb_state |= ARCMSR_CCB_BACK;
				ccb->pkt->pkt_reason = CMD_ABORTED;
				ccb->pkt->pkt_statistics |= STAT_ABORTED;
				arcmsr_ccb_complete(ccb, 1);
				continue;
			}
			arcmsr_report_ccb_state(acb, ccb, error);
			arcmsr_warn(acb,
			    "polling op got unexpected ccb command done");
			continue;
		}
		arcmsr_report_ccb_state(acb, ccb, error);
	}	/* drain reply FIFO */
	arcmsr_enable_allintr(acb, intmask_org);
}


/*
 * Function: arcmsr_hba_hardware_reset()
 *           Bug Fix for Intel IOP cause firmware hang on.
 *           and kernel panic
 */
static void
arcmsr_hba_hardware_reset(struct ACB *acb)
{
	struct HBA_msgUnit *phbamu;
	uint8_t value[64];
	int i;

	phbamu = (struct HBA_msgUnit *)acb->pmu;
	/* backup pci config data */
	for (i = 0; i < 64; i++) {
		value[i] = pci_config_get8(acb->pci_acc_handle, i);
	}
	/* hardware reset signal */
	if ((PCI_DEVICE_ID_ARECA_1680 ==
	    pci_config_get16(acb->pci_acc_handle, PCI_CONF_DEVID))) {
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbamu->reserved1[0], 0x00000003);
	} else {
		pci_config_put8(acb->pci_acc_handle, 0x84, 0x20);
	}
	drv_usecwait(1000000);
	/* write back pci config data */
	for (i = 0; i < 64; i++) {
		pci_config_put8(acb->pci_acc_handle, i, value[i]);
	}
	drv_usecwait(1000000);
}

/*
 * Function: arcmsr_abort_host_command
 */
static uint8_t
arcmsr_abort_host_command(struct ACB *acb)
{
	uint8_t rtnval = 0;

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
		rtnval = arcmsr_abort_hba_allcmd(acb);
		break;
	case ACB_ADAPTER_TYPE_B:
		rtnval = arcmsr_abort_hbb_allcmd(acb);
		break;
	case ACB_ADAPTER_TYPE_C:
		rtnval = arcmsr_abort_hbc_allcmd(acb);
		break;
	}
	return (rtnval);
}

/*
 * Function: arcmsr_handle_iop_bus_hold
 */
static void
arcmsr_handle_iop_bus_hold(struct ACB *acb)
{

	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
	{
		struct HBA_msgUnit *phbamu;
		int retry_count = 0;

		acb->timeout_count = 0;
		phbamu = (struct HBA_msgUnit *)acb->pmu;
		arcmsr_hba_hardware_reset(acb);
		acb->acb_flags &= ~ACB_F_IOP_INITED;
	sleep_again:
		drv_usecwait(1000000);
		if ((CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbamu->outbound_msgaddr1) &
		    ARCMSR_OUTBOUND_MESG1_FIRMWARE_OK) == 0) {
			if (retry_count > 60) {
				arcmsr_warn(acb,
				    "waiting for hardware"
				    "bus reset return, RETRY TERMINATED!!");
				return;
			}
			retry_count++;
			goto sleep_again;
		}
		arcmsr_iop_init(acb);
		break;
	}

	}
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
arcmsr_hba_doorbell_isr(struct ACB *acb)
{
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
arcmsr_hbc_doorbell_isr(struct ACB *acb)
{
	uint32_t outbound_doorbell;
	struct HBC_msgUnit *phbcmu;

	phbcmu = (struct HBC_msgUnit *)acb->pmu;

	/*
	 *  Maybe here we need to check wrqbuffer_lock is locked or not
	 *  DOORBELL: ding! dong!
	 *  check if there are any mail need to pick from firmware
	 */

	outbound_doorbell = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbcmu->outbound_doorbell);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->outbound_doorbell_clear,
	    outbound_doorbell); /* clear interrupt */
	if (outbound_doorbell & ARCMSR_HBCMU_IOP2DRV_DATA_WRITE_OK) {
		arcmsr_iop2drv_data_wrote_handle(acb);
	}
	if (outbound_doorbell & ARCMSR_HBCMU_IOP2DRV_DATA_READ_OK) {
		arcmsr_iop2drv_data_read_handle(acb);
	}
	if (outbound_doorbell & ARCMSR_HBCMU_IOP2DRV_MESSAGE_CMD_DONE) {
		/* messenger of "driver to iop commands" */
		arcmsr_hbc_message_isr(acb);
	}
}


static void
arcmsr_hba_message_isr(struct ACB *acb)
{
	struct HBA_msgUnit *phbamu = (struct HBA_msgUnit *)acb->pmu;
	uint32_t  *signature = (&phbamu->msgcode_rwbuffer[0]);
	uint32_t outbound_message;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_intstatus, ARCMSR_MU_OUTBOUND_MESSAGE0_INT);

	outbound_message = CHIP_REG_READ32(acb->reg_mu_acc_handle0, signature);
	if (outbound_message == ARCMSR_SIGNATURE_GET_CONFIG)
		if ((ddi_taskq_dispatch(acb->taskq,
		    (void (*)(void *))arcmsr_dr_handle,
		    acb, DDI_NOSLEEP)) != DDI_SUCCESS) {
			arcmsr_warn(acb, "DR task start failed");
		}
}

static void
arcmsr_hbb_message_isr(struct ACB *acb)
{
	struct HBB_msgUnit *phbbmu = (struct HBB_msgUnit *)acb->pmu;
	uint32_t  *signature = (&phbbmu->hbb_rwbuffer->msgcode_rwbuffer[0]);
	uint32_t outbound_message;

	/* clear interrupts */
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->iop2drv_doorbell,
	    ARCMSR_MESSAGE_INT_CLEAR_PATTERN);
	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_DRV2IOP_END_OF_INTERRUPT);

	outbound_message = CHIP_REG_READ32(acb->reg_mu_acc_handle0, signature);
	if (outbound_message == ARCMSR_SIGNATURE_GET_CONFIG)
		if ((ddi_taskq_dispatch(acb->taskq,
		    (void (*)(void *))arcmsr_dr_handle,
		    acb, DDI_NOSLEEP)) != DDI_SUCCESS) {
			arcmsr_warn(acb, "DR task start failed");
		}
}

static void
arcmsr_hbc_message_isr(struct ACB *acb)
{
	struct HBC_msgUnit *phbcmu = (struct HBC_msgUnit *)acb->pmu;
	uint32_t  *signature = (&phbcmu->msgcode_rwbuffer[0]);
	uint32_t outbound_message;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbcmu->outbound_doorbell_clear,
	    ARCMSR_HBCMU_IOP2DRV_MESSAGE_CMD_DONE_DOORBELL_CLEAR);

	outbound_message = CHIP_REG_READ32(acb->reg_mu_acc_handle0, signature);
	if (outbound_message == ARCMSR_SIGNATURE_GET_CONFIG)
		if ((ddi_taskq_dispatch(acb->taskq,
		    (void (*)(void *))arcmsr_dr_handle,
		    acb, DDI_NOSLEEP)) != DDI_SUCCESS) {
			arcmsr_warn(acb, "DR task start failed");
		}
}


static void
arcmsr_hba_postqueue_isr(struct ACB *acb)
{

	struct HBA_msgUnit *phbamu;
	struct CCB *ccb;
	uint32_t flag_ccb;
	boolean_t error;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	/* areca cdb command done */
	/* Use correct offset and size for syncing */
	(void) ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	while ((flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_queueport)) != 0xFFFFFFFF) {
		/* frame must be 32 bytes aligned */
		ccb = NumToPtr((acb->vir2phy_offset+(flag_ccb << 5)));
		/* check if command done with no error */
		error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE0) ?
		    B_TRUE : B_FALSE;
		arcmsr_drain_donequeue(acb, ccb, error);
	}	/* drain reply FIFO */
}


static void
arcmsr_hbb_postqueue_isr(struct ACB *acb)
{
	struct HBB_msgUnit *phbbmu;
	struct CCB *ccb;
	uint32_t flag_ccb;
	boolean_t error;
	int index;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	/* areca cdb command done */
	index = phbbmu->doneq_index;
	if (ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS)
		return;
	while ((flag_ccb = phbbmu->done_qbuffer[index]) != 0) {
		phbbmu->done_qbuffer[index] = 0;
		/* frame must be 32 bytes aligned */

		/* the CDB is the first field of the CCB */
		ccb = NumToPtr((acb->vir2phy_offset + (flag_ccb << 5)));

		/* check if command done with no error */
		error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE0) ?
		    B_TRUE : B_FALSE;
		arcmsr_drain_donequeue(acb, ccb, error);
		index++;
		/* if last index number set it to 0 */
		index %= ARCMSR_MAX_HBB_POSTQUEUE;
		phbbmu->doneq_index = index;
	}	/* drain reply FIFO */
}


static void
arcmsr_hbc_postqueue_isr(struct ACB *acb)
{

	struct HBC_msgUnit *phbcmu;
	struct CCB *ccb;
	uint32_t flag_ccb, ccb_cdb_phy, throttling = 0;
	boolean_t error;

	phbcmu = (struct HBC_msgUnit *)acb->pmu;
	/* areca cdb command done */
	/* Use correct offset and size for syncing */
	(void) ddi_dma_sync(acb->ccbs_pool_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	while (CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbcmu->host_int_status) &
	    ARCMSR_HBCMU_OUTBOUND_POSTQUEUE_ISR) {
		/* check if command done with no error */
		flag_ccb = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbcmu->outbound_queueport_low);
		/* frame must be 32 bytes aligned */
		ccb_cdb_phy = (flag_ccb & 0xFFFFFFF0);

		/* the CDB is the first field of the CCB */
		ccb = NumToPtr((acb->vir2phy_offset + ccb_cdb_phy));

		error = (flag_ccb & ARCMSR_CCBREPLY_FLAG_ERROR_MODE1) ?
		    B_TRUE : B_FALSE;
		/* check if command done with no error */
		arcmsr_drain_donequeue(acb, ccb, error);
		if (throttling == ARCMSR_HBC_ISR_THROTTLING_LEVEL) {
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->inbound_doorbell,
			    ARCMSR_HBCMU_DRV2IOP_POSTQUEUE_THROTTLING);
			break;
		}
		throttling++;
	}	/* drain reply FIFO */
}


static uint_t
arcmsr_handle_hba_isr(struct ACB *acb) {

	uint32_t outbound_intstatus;
	struct HBA_msgUnit *phbamu;

	phbamu = (struct HBA_msgUnit *)acb->pmu;

	outbound_intstatus = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbamu->outbound_intstatus) & acb->outbound_int_enable;

	if (outbound_intstatus == 0)	/* it must be a shared irq */
		return (DDI_INTR_UNCLAIMED);

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0, &phbamu->outbound_intstatus,
	    outbound_intstatus); /* clear interrupt */

	/* MU doorbell interrupts */

	if (outbound_intstatus & ARCMSR_MU_OUTBOUND_DOORBELL_INT)
		arcmsr_hba_doorbell_isr(acb);

	/* MU post queue interrupts */
	if (outbound_intstatus & ARCMSR_MU_OUTBOUND_POSTQUEUE_INT)
		arcmsr_hba_postqueue_isr(acb);

	if (outbound_intstatus & ARCMSR_MU_OUTBOUND_MESSAGE0_INT) {
		arcmsr_hba_message_isr(acb);
	}

	return (DDI_INTR_CLAIMED);
}


static uint_t
arcmsr_handle_hbb_isr(struct ACB *acb) {

	uint32_t outbound_doorbell;
	struct HBB_msgUnit *phbbmu;


	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	outbound_doorbell = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->iop2drv_doorbell) & acb->outbound_int_enable;

	if (outbound_doorbell == 0)		/* it must be a shared irq */
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

	/* MU message interrupt */

	if (outbound_doorbell & ARCMSR_IOP2DRV_MESSAGE_CMD_DONE) {
		arcmsr_hbb_message_isr(acb);
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
arcmsr_handle_hbc_isr(struct ACB *acb)
{
	uint32_t host_interrupt_status;
	struct HBC_msgUnit *phbcmu;

	phbcmu = (struct HBC_msgUnit *)acb->pmu;
	/*  check outbound intstatus */
	host_interrupt_status=
	    CHIP_REG_READ32(acb->reg_mu_acc_handle0, &phbcmu->host_int_status);
	if (host_interrupt_status == 0)	/* it must be share irq */
		return (DDI_INTR_UNCLAIMED);
	/* MU ioctl transfer doorbell interrupts */
	if (host_interrupt_status & ARCMSR_HBCMU_OUTBOUND_DOORBELL_ISR) {
		/* messenger of "ioctl message read write" */
		arcmsr_hbc_doorbell_isr(acb);
	}
	/* MU post queue interrupts */
	if (host_interrupt_status & ARCMSR_HBCMU_OUTBOUND_POSTQUEUE_ISR) {
		/* messenger of "scsi commands" */
		arcmsr_hbc_postqueue_isr(acb);
	}
	return (DDI_INTR_CLAIMED);
}

static uint_t
arcmsr_intr_handler(caddr_t arg, caddr_t arg2)
{
	struct ACB *acb = (void *)arg;
	struct CCB *ccb;
	uint_t retrn = DDI_INTR_UNCLAIMED;
	_NOTE(ARGUNUSED(arg2))

	mutex_enter(&acb->isr_mutex);
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
		retrn = arcmsr_handle_hba_isr(acb);
		break;

	case ACB_ADAPTER_TYPE_B:
		retrn = arcmsr_handle_hbb_isr(acb);
		break;

	case ACB_ADAPTER_TYPE_C:
		retrn = arcmsr_handle_hbc_isr(acb);
		break;

	default:
		/* We should never be here */
		ASSERT(0);
		break;
	}
	mutex_exit(&acb->isr_mutex);
	while ((ccb = arcmsr_get_complete_ccb_from_list(acb)) != NULL) {
		arcmsr_ccb_complete(ccb, 1);
	}
	return (retrn);
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
		break;
	}

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
		break;
	}

	case ACB_ADAPTER_TYPE_C:
	{
		struct HBC_msgUnit *phbcmu;
		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		do {
			firmware_state =
			    CHIP_REG_READ32(acb->reg_mu_acc_handle0,
				&phbcmu->outbound_msgaddr1);
		} while ((firmware_state & ARCMSR_HBCMU_MESSAGE_FIRMWARE_OK)
		    == 0);
		break;
	}

	}
}

static void
arcmsr_clear_doorbell_queue_buffer(struct ACB *acb)
{
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A: {
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
		break;
	}

	case ACB_ADAPTER_TYPE_B: {
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
		break;
	}

	case ACB_ADAPTER_TYPE_C: {
		struct HBC_msgUnit *phbcmu;
		uint32_t outbound_doorbell;

		phbcmu = (struct HBC_msgUnit *)acb->pmu;
		/* empty doorbell Qbuffer if door bell ringed */
		outbound_doorbell = CHIP_REG_READ32(acb->reg_mu_acc_handle0,
		    &phbcmu->outbound_doorbell);
		/* clear outbound doobell isr */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->outbound_doorbell_clear, outbound_doorbell);
		/* let IOP know data has been read */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbcmu->inbound_doorbell,
		    ARCMSR_HBCMU_DRV2IOP_DATA_READ_OK);
		break;
	}

	}
}


static uint32_t
arcmsr_iop_confirm(struct ACB *acb) {

	uint64_t cdb_phyaddr;
	uint32_t cdb_phyaddr_hi32;

	/*
	 * here we need to tell iop 331 about our freeccb.HighPart
	 * if freeccb.HighPart is non-zero
	 */
	cdb_phyaddr = acb->ccb_cookie.dmac_laddress;
	cdb_phyaddr_hi32 = (uint32_t)((cdb_phyaddr >> 16) >> 16);
	acb->cdb_phyaddr_hi32 = cdb_phyaddr_hi32;
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
		if (cdb_phyaddr_hi32 != 0) {
			struct HBA_msgUnit *phbamu;

			phbamu = (struct HBA_msgUnit *)acb->pmu;
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->msgcode_rwbuffer[0],
			    ARCMSR_SIGNATURE_SET_CONFIG);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->msgcode_rwbuffer[1], cdb_phyaddr_hi32);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbamu->inbound_msgaddr0,
			    ARCMSR_INBOUND_MESG0_SET_CONFIG);
			if (!arcmsr_hba_wait_msgint_ready(acb)) {
				arcmsr_warn(acb,
				    "timeout setting ccb "
				    "high physical address");
				return (FALSE);
			}
		}
		break;

	/* if adapter is type B, set window of "post command queue" */
	case ACB_ADAPTER_TYPE_B: {
		uint32_t post_queue_phyaddr;
		struct HBB_msgUnit *phbbmu;

		phbbmu = (struct HBB_msgUnit *)acb->pmu;
		phbbmu->postq_index = 0;
		phbbmu->doneq_index = 0;
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_MESSAGE_SET_POST_WINDOW);

		if (!arcmsr_hbb_wait_msgint_ready(acb)) {
			arcmsr_warn(acb, "timeout setting post command "
			    "queue window");
			return (FALSE);
		}

		post_queue_phyaddr = (uint32_t)cdb_phyaddr +
		    ARCMSR_MAX_FREECCB_NUM * P2ROUNDUP(sizeof (struct CCB), 32)
		    + offsetof(struct HBB_msgUnit, post_qbuffer);
		/* driver "set config" signature */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle1,
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[0],
		    ARCMSR_SIGNATURE_SET_CONFIG);
		/* normal should be zero */
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle1,
		    &phbbmu->hbb_rwbuffer->msgcode_rwbuffer[1],
		    cdb_phyaddr_hi32);
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
			arcmsr_warn(acb,
			    "timeout setting command queue window");
			return (FALSE);
		}
		CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
		    &phbbmu->hbb_doorbell->drv2iop_doorbell,
		    ARCMSR_MESSAGE_START_DRIVER_MODE);

		if (!arcmsr_hbb_wait_msgint_ready(acb)) {
			arcmsr_warn(acb, "timeout in 'start driver mode'");
			return (FALSE);
		}
		break;
	}

	case ACB_ADAPTER_TYPE_C:
		if (cdb_phyaddr_hi32 != 0) {
			struct HBC_msgUnit *phbcmu;

			phbcmu = (struct HBC_msgUnit *)acb->pmu;
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->msgcode_rwbuffer[0],
			    ARCMSR_SIGNATURE_SET_CONFIG);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->msgcode_rwbuffer[1], cdb_phyaddr_hi32);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->inbound_msgaddr0,
			    ARCMSR_INBOUND_MESG0_SET_CONFIG);
			CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
			    &phbcmu->inbound_doorbell,
			    ARCMSR_HBCMU_DRV2IOP_MESSAGE_CMD_DONE);
			if (!arcmsr_hbc_wait_msgint_ready(acb)) {
				arcmsr_warn(acb, "'set ccb "
				    "high part physical address' timeout");
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
arcmsr_enable_eoi_mode(struct ACB *acb)
{
	struct HBB_msgUnit *phbbmu;

	phbbmu = (struct HBB_msgUnit *)acb->pmu;

	CHIP_REG_WRITE32(acb->reg_mu_acc_handle0,
	    &phbbmu->hbb_doorbell->drv2iop_doorbell,
	    ARCMSR_MESSAGE_ACTIVE_EOI_MODE);

	if (!arcmsr_hbb_wait_msgint_ready(acb))
		arcmsr_warn(acb, "'iop enable eoi mode' timeout");
}

/* start background rebuild */
static void
arcmsr_iop_init(struct ACB *acb)
{
	uint32_t intmask_org;

	/* disable all outbound interrupt */
	intmask_org = arcmsr_disable_allintr(acb);
	arcmsr_wait_firmware_ready(acb);
	(void) arcmsr_iop_confirm(acb);

	/* start background rebuild */
	switch (acb->adapter_type) {
	case ACB_ADAPTER_TYPE_A:
		arcmsr_get_hba_config(acb);
		arcmsr_start_hba_bgrb(acb);
		break;
	case ACB_ADAPTER_TYPE_B:
		arcmsr_get_hbb_config(acb);
		arcmsr_start_hbb_bgrb(acb);
		break;
	case ACB_ADAPTER_TYPE_C:
		arcmsr_get_hbc_config(acb);
		arcmsr_start_hbc_bgrb(acb);
		break;
	}
	/* empty doorbell Qbuffer if door bell rang */
	arcmsr_clear_doorbell_queue_buffer(acb);

	if (acb->adapter_type == ACB_ADAPTER_TYPE_B)
		arcmsr_enable_eoi_mode(acb);

	/* enable outbound Post Queue, outbound doorbell Interrupt */
	arcmsr_enable_allintr(acb, intmask_org);
	acb->acb_flags |= ACB_F_IOP_INITED;
}
