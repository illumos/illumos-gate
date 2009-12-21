/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file containing the implementation of the Hardware specific
 * functions
 */

#include <oce_impl.h>
#include <oce_stat.h>
#include <oce_ioctl.h>

static ddi_device_acc_attr_t reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

extern int oce_destroy_q(struct oce_dev *dev, struct oce_mbx *mbx,
    size_t req_size, enum qtype qtype);

/*
 * function to map the device memory
 *
 * dev - handle to device private data structure
 *
 */
int
oce_pci_init(struct oce_dev *dev)
{
	int ret = 0;
	off_t bar_size = 0;

	ASSERT(NULL != dev);
	ASSERT(NULL != dev->dip);

	/* get number of supported bars */
	ret = ddi_dev_nregs(dev->dip, &dev->num_bars);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "%d: could not retrieve num_bars", MOD_CONFIG);
		return (DDI_FAILURE);
	}

	/* verify each bar and map it accordingly */
	/* PCI CFG */
	ret = ddi_dev_regsize(dev->dip, OCE_DEV_CFG_BAR, &bar_size);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not get sizeof BAR %d",
		    OCE_DEV_CFG_BAR);
		return (DDI_FAILURE);
	}

	ret = ddi_regs_map_setup(dev->dip, OCE_DEV_CFG_BAR, &dev->dev_cfg_addr,
	    0, bar_size, &reg_accattr, &dev->dev_cfg_handle);

	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not map bar %d",
		    OCE_DEV_CFG_BAR);
		return (DDI_FAILURE);
	}

	/* CSR */
	ret = ddi_dev_regsize(dev->dip, OCE_PCI_CSR_BAR, &bar_size);

	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not get sizeof BAR %d",
		    OCE_PCI_CSR_BAR);
		return (DDI_FAILURE);
	}

	ret = ddi_regs_map_setup(dev->dip, OCE_PCI_CSR_BAR, &dev->csr_addr,
	    0, bar_size, &reg_accattr, &dev->csr_handle);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not map bar %d",
		    OCE_PCI_CSR_BAR);
		ddi_regs_map_free(&dev->dev_cfg_handle);
		return (DDI_FAILURE);
	}

	/* Doorbells */
	ret = ddi_dev_regsize(dev->dip, OCE_PCI_DB_BAR, &bar_size);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "%d Could not get sizeof BAR %d",
		    ret, OCE_PCI_DB_BAR);
		ddi_regs_map_free(&dev->csr_handle);
		ddi_regs_map_free(&dev->dev_cfg_handle);
		return (DDI_FAILURE);
	}

	ret = ddi_regs_map_setup(dev->dip, OCE_PCI_DB_BAR, &dev->db_addr,
	    0, 0, &reg_accattr, &dev->db_handle);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not map bar %d", OCE_PCI_DB_BAR);
		ddi_regs_map_free(&dev->csr_handle);
		ddi_regs_map_free(&dev->dev_cfg_handle);
		return (DDI_FAILURE);
	}

	dev->fn =  OCE_PCI_FUNC(dev);
	ret = oce_fm_check_acc_handle(dev, dev->dev_cfg_handle);

	if (ret != DDI_FM_OK) {
		oce_pci_fini(dev);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
} /* oce_pci_init */

/*
 * function to free device memory mapping mapped using
 * oce_pci_init
 *
 * dev - handle to device private data
 */
void
oce_pci_fini(struct oce_dev *dev)
{
	ASSERT(NULL != dev);
	ASSERT(NULL != dev->dip);

	ddi_regs_map_free(&dev->db_handle);
	ddi_regs_map_free(&dev->csr_handle);
	ddi_regs_map_free(&dev->dev_cfg_handle);
} /* oce_pci_fini */

/*
 * function to initailise the hardware. This includes creation of queues,
 * interfaces and associated buffers for data movement
 *
 * dev - software handle to the device
 *
 */
int
oce_hw_init(struct oce_dev *dev)
{
	int ret = DDI_SUCCESS;

	/* create an interface for the device with out mac */
	ret = oce_if_create(dev, OCE_DEFAULT_IF_CAP, OCE_DEFAULT_IF_CAP_EN,
	    0, &dev->mac_addr[0], (uint32_t *)&dev->if_id);
	if (ret != 0) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Interface creation failed: 0x%x", ret);
		dev->if_id = OCE_INVAL_IF_ID;
		goto init_fail;
	}

	dev->if_cap_flags = OCE_DEFAULT_IF_CAP_EN;

	/* Enable VLAN Promisc on HW */
	ret = oce_config_vlan(dev, (uint8_t)dev->if_id, NULL, 0,
	    B_TRUE, B_TRUE);
	if (ret != 0) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Config vlan failed: %d", ret);
		goto init_fail;

	}

	/* set default flow control */
	ret = oce_set_flow_control(dev, dev->flow_control);
	if (ret != 0) {
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "Set flow control failed: %d", ret);
	}

	/* set to promiscuous mode */
	ret = oce_set_promiscuous(dev, dev->promisc);

	if (ret != 0) {
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "Set Promisc failed: %d", ret);
	}
	/* this could happen if the  driver is resuming after suspend */
	if (dev->num_mca > 0) {
		ret = oce_set_multicast_table(dev, dev->multi_cast,
		    dev->num_mca, B_FALSE);
		if (ret != 0) {
			oce_log(dev, CE_NOTE, MOD_CONFIG,
			    "Set Multicast failed: %d", ret);
		}
	}

	/* we are done. Now return */
	return (DDI_SUCCESS);

init_fail:
	oce_hw_fini(dev);
	return (DDI_FAILURE);
} /* oce_hw_init */

/*
 * function to return resources allocated in oce_hw_init
 *
 * dev - software handle to the device
 *
 */
void
oce_hw_fini(struct oce_dev *dev)
{
	int i;

	/* release OS resources */
	if (dev->mq != NULL) {
		(void) oce_mq_del(dev, dev->mq);
		dev->mq = NULL;
	}

	if (dev->wq[0] != NULL) {
		(void) oce_wq_del(dev, dev->wq[0]);
		dev->wq[0] = NULL;
	}
	for (i = 0; i < dev->num_vectors; i++) {
		if (dev->eq[i] != NULL) {
			if (oce_eq_del(dev, dev->eq[i])) {
				oce_log(dev, CE_WARN, MOD_CONFIG,
				    "eq[%d] del failed", i);
			}
			dev->eq[i] = NULL;
		}
	}
	if (dev->if_id >= 0) {
		(void) oce_if_del(dev, dev->if_id);
	}

	if (dev->rq[0] != NULL) {
		(void) oce_rq_del(dev, dev->rq[0]);
		dev->rq[0] = NULL;
	}
} /* oce_hw_fini */

int
oce_chip_hw_init(struct oce_dev *dev)
{
	struct oce_wq *wq;
	struct oce_rq *rq;
	struct oce_eq *eq;
	struct oce_mq *mq;
	int i = 0;

	/*
	 * create Event Queues. One event queue per available vector. In
	 * case of INTX, only one vector is available and will handle
	 * event notification for Write Queue (WQ), Receive Queue (RQ) and
	 * Mbox Queue (MQ).
	 *
	 * The EQ is not directly used by the WQ, RQ and MQ. The WQ, RQ and
	 * MQ is composed of a Completion Queue (CQ) that is created per
	 * queue and is dependent on the queue type. The EQ passed is
	 * associated with the CQ at the time of creation.
	 *
	 * In the case of MSIX, there will be one EQ for the RQ and one EQ
	 * shared between the WQ and MQ.
	 */
	for (i = 0; i < dev->num_vectors; i++) {
		eq = oce_eq_create(dev, EQ_LEN_1024, EQE_SIZE_4, 0);
		if (eq == NULL) {
			oce_log(dev, CE_WARN, MOD_CONFIG,
			    "EQ creation(%d) failed ", i);
			goto chip_fail;
		}
		/* Save the eq pointer */
		dev->eq[eq->eq_id % OCE_MAX_EQ] = eq;
	}

	/*
	 * create the Write Queue (WQ). The WQ is the low level sructure for
	 * queueing send packets. It maintains a ring buffer to queue packets
	 * to be sent out on the wire and return the context to the host
	 * when there is a send complete event.
	 *
	 * The WQ uses a Completion Queue (CQ) with an associated EQ for
	 * handling send completion events.
	 */
	wq = oce_wq_create(dev, dev->eq[0],
	    dev->tx_ring_size, NIC_WQ_TYPE_STANDARD);
	if (wq ==  NULL) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "WQ creation failed ");
		goto chip_fail;
	}
	/* store the WQ pointer */
	dev->wq[0] = wq;

	/*
	 * create the Receive Queue (RQ). The RQ is the low level structure
	 * for receiving data from the wire, It implements a ring buffer
	 * that allows the adpater to DMA data onto host buffers.
	 *
	 * The RQ uses a Completion Queue (CQ) with an associated EQ for
	 * handling recieve events when packets are received by the adapter
	 */
	rq = oce_rq_create(dev,
	    ((dev->num_vectors > 1) ? dev->eq[1] : dev->eq[0]),
	    dev->rx_ring_size,
	    OCE_RQ_BUF_SIZE, OCE_RQ_MAX_FRAME_SZ,
	    dev->if_id, B_FALSE);
	if (rq == NULL) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "RQ creation failed ");
		goto chip_fail;
	}
	dev->rq[0] = rq;

	/*
	 * create the Mailbox Queue (MQ). Only one per adapter instance can
	 * be created. The MQ is used for receiving asynchronous adapter
	 * events, like link status updates.
	 *
	 * The MQ uses an Asynchronous CQ (ACQ) with an associated EQ for
	 * handling asynchronous event notification to the host.
	 */
	mq = oce_mq_create(dev, dev->eq[0], 64);
	if (mq == NULL) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "MQ creation failed ");
		goto chip_fail;
	}
	dev->mq = mq;

	return (DDI_SUCCESS);
chip_fail:
	oce_chip_hw_fini(dev);
	return (DDI_FAILURE);
} /* oce_chip_hw_init */


void
oce_chip_hw_fini(struct oce_dev *dev)
{
	struct oce_mbx mbx;
	struct mbx_destroy_common_mq *mq_cmd;
	struct mbx_delete_nic_rq *rq_cmd;
	struct mbx_delete_nic_wq *wq_cmd;
	struct mbx_destroy_common_cq *cq_cmd;
	struct oce_mq *mq = dev->mq;
	struct oce_rq *rq = dev->rq[0];
	struct oce_wq *wq = dev->wq[0];
	struct oce_eq *eq = NULL;
	struct mbx_destroy_common_eq *eq_cmd;
	int i;

	if (mq != NULL) {

		/* send a command to delete the MQ */
		bzero(&mbx, sizeof (struct oce_mbx));
		mq_cmd = (struct mbx_destroy_common_mq *)&mbx.payload;

		mq_cmd->params.req.id = mq->mq_id;
		(void) oce_destroy_q(dev, &mbx,
		    sizeof (struct mbx_destroy_common_cq), QTYPE_MQ);

		/* send a command to delete the MQ_CQ */
		bzero(&mbx, sizeof (struct oce_mbx));
		cq_cmd = (struct mbx_destroy_common_cq *)&mbx.payload;

		cq_cmd->params.req.id = mq->cq->cq_id;
		(void) oce_destroy_q(dev, &mbx,
		    sizeof (struct mbx_destroy_common_cq), QTYPE_CQ);
		mq->ring->pidx = mq->ring->cidx = 0;
	}

	if (rq != NULL) {
		/* send a command to delete the RQ */
		bzero(&mbx, sizeof (struct oce_mbx));

		rq_cmd = (struct mbx_delete_nic_rq *)&mbx.payload;
		rq_cmd->params.req.rq_id = rq->rq_id;

		(void) oce_destroy_q(dev, &mbx,
		    sizeof (struct mbx_delete_nic_rq), QTYPE_RQ);

		rq->ring->cidx = rq->ring->pidx = 0;

		/* send a command to delete the RQ_CQ */
		bzero(&mbx, sizeof (struct oce_mbx));
		cq_cmd = (struct mbx_destroy_common_cq *)&mbx.payload;

		cq_cmd->params.req.id = rq->cq->cq_id;
		(void) oce_destroy_q(dev, &mbx,
		    sizeof (struct mbx_destroy_common_cq), QTYPE_CQ);
		rq->cq->ring->pidx = rq->cq->ring->cidx = 0;
	}

	if (wq != NULL) {
		/* send a command to delete the WQ */
		bzero(&mbx, sizeof (struct oce_mbx));

		/* now fill the command */
		wq_cmd = (struct mbx_delete_nic_wq *)&mbx.payload;
		wq_cmd->params.req.wq_id = wq->wq_id;
		(void) oce_destroy_q(dev, &mbx,
		    sizeof (struct mbx_delete_nic_wq), QTYPE_WQ);

		wq->ring->pidx = wq->ring->cidx = 0;

		/* send a command to delete the WQ_CQ */
		bzero(&mbx, sizeof (struct oce_mbx));
		cq_cmd = (struct mbx_destroy_common_cq *)&mbx.payload;
		cq_cmd->params.req.id = wq->cq->cq_id;
		(void) oce_destroy_q(dev, &mbx,
		    sizeof (struct mbx_destroy_common_cq), QTYPE_CQ);
		wq->cq->ring->pidx = wq->cq->ring->cidx = 0;
	}

	for (i = 0; i < dev->num_vectors; i++) {
		eq = dev->eq[i];
		if (eq != NULL) {
			bzero(&mbx, sizeof (struct oce_mbx));
			/* send a command to delete the EQ */
			eq_cmd = (struct mbx_destroy_common_eq *)&mbx.payload;

			eq_cmd->params.req.id = eq->eq_id;

			(void) oce_destroy_q(dev, &mbx,
			    sizeof (struct mbx_destroy_common_eq), QTYPE_EQ);
			eq->ring->pidx = eq->ring->cidx = 0;
		}
	}
}

/*
 * function to check if a reset is required
 *
 * dev - software handle to the device
 *
 */
boolean_t
oce_is_reset_pci(struct oce_dev *dev)
{
	mpu_ep_semaphore_t post_status;

	ASSERT(dev != NULL);
	ASSERT(dev->dip != NULL);

	post_status.dw0 = 0;
	post_status.dw0 = OCE_CSR_READ32(dev, MPU_EP_SEMAPHORE);

	if (post_status.bits.stage == POST_STAGE_ARMFW_READY) {
		return (B_FALSE);
	} else if ((post_status.bits.stage <= POST_STAGE_AWAITING_HOST_RDY) ||
	    post_status.bits.stage == POST_STAGE_ARMFW_UE) {
		return (B_TRUE);
	}

	return (B_TRUE);
} /* oce_is_reset_pci */

/*
 * function to do a soft reset on the device
 *
 * dev - software handle to the device
 *
 */
int
oce_pci_soft_reset(struct oce_dev *dev)
{
	pcicfg_soft_reset_t soft_rst;
	/* struct mpu_ep_control ep_control; */
	/* struct pcicfg_online1 online1; */
	clock_t tmo;
	clock_t earlier = ddi_get_lbolt();

	ASSERT(dev != NULL);

	/* issue soft reset */
	soft_rst.dw0 = OCE_CFG_READ32(dev, PCICFG_SOFT_RESET);
	soft_rst.bits.soft_reset = 0x01;
	OCE_CFG_WRITE32(dev, PCICFG_SOFT_RESET, soft_rst.dw0);

	/* wait till soft reset bit deasserts */
	tmo = drv_usectohz(60000000); /* 1.0min */
	do {
		if ((ddi_get_lbolt() - earlier) > tmo) {
			tmo = 0;
			break;
		}

		soft_rst.dw0 = OCE_CFG_READ32(dev, PCICFG_SOFT_RESET);
		if (soft_rst.bits.soft_reset)
			drv_usecwait(100);
	} while (soft_rst.bits.soft_reset);

	if (soft_rst.bits.soft_reset) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "0x%x soft_reset"
		    "bit asserted[1]. Reset failed",
		    soft_rst.dw0);
		return (DDI_FAILURE);
	}

	return (oce_POST(dev));
} /* oce_pci_soft_reset */
/*
 * function to trigger a POST on the device
 *
 * dev - software handle to the device
 *
 */
int
oce_POST(struct oce_dev *dev)
{
	mpu_ep_semaphore_t post_status;
	clock_t tmo;
	clock_t earlier = ddi_get_lbolt();

	/* read semaphore CSR */
	post_status.dw0 = OCE_CSR_READ32(dev, MPU_EP_SEMAPHORE);

	/* if host is ready then wait for fw ready else send POST */
	if (post_status.bits.stage <= POST_STAGE_AWAITING_HOST_RDY) {
		post_status.bits.stage = POST_STAGE_CHIP_RESET;
		OCE_CSR_WRITE32(dev, MPU_EP_SEMAPHORE, post_status.dw0);
	}

	/* wait for FW ready */
	tmo = drv_usectohz(60000000); /* 1.0min */
	for (;;) {
		if ((ddi_get_lbolt() - earlier) > tmo) {
			tmo = 0;
			break;
		}

		post_status.dw0 = OCE_CSR_READ32(dev, MPU_EP_SEMAPHORE);
		if (post_status.bits.error) break;
		if (post_status.bits.stage == POST_STAGE_ARMFW_READY)
			break;

		drv_usecwait(100);
	}

	if (post_status.bits.error) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "0x%x POST ERROR!!", post_status.dw0);
		return (DDI_FAILURE);
	} else if (post_status.bits.stage == POST_STAGE_ARMFW_READY) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "0x%x POST SUCCESSFUL",
		    post_status.dw0);
		return (DDI_SUCCESS);
	} else {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "0x%x POST timedout", post_status.dw0);
		return (DDI_FAILURE);
	}
} /* oce_POST */
/*
 * function to modify register access attributes corresponding to the
 * FM capabilities configured by the user
 *
 * fm_caps - fm capability configured by the user and accepted by the driver
 */
void
oce_set_reg_fma_flags(int fm_caps)
{
	if (fm_caps == DDI_FM_NOT_CAPABLE) {
		return;
	}
	if (DDI_FM_ACC_ERR_CAP(fm_caps)) {
		reg_accattr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		reg_accattr.devacc_attr_access = DDI_DEFAULT_ACC;
	}
} /* oce_set_fma_flags */
