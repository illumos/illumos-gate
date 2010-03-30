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
 * Copyright 2010 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file interrupt registration
 * and related helper functions
 */

#include <oce_impl.h>

static int oce_setup_msix(struct oce_dev *dev);
static int oce_teardown_msix(struct oce_dev *dev);
static int oce_add_msix_handlers(struct oce_dev *dev);
static void oce_del_msix_handlers(struct oce_dev *dev);
static uint_t oce_isr(caddr_t arg1, caddr_t arg2);

static int oce_setup_intx(struct oce_dev *dev);
static int oce_teardown_intx(struct oce_dev *dev);
static int oce_add_intx_handlers(struct oce_dev *dev);
static void oce_del_intx_handlers(struct oce_dev *dev);

/*
 * top level function to setup interrupts
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
int
oce_setup_intr(struct oce_dev *dev)
{
	int ret;
	int intr_types = 0;

	/* get supported intr types */
	ret = ddi_intr_get_supported_types(dev->dip, &intr_types);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to retrieve intr types ");
		return (DDI_FAILURE);
	}

	if (intr_types & DDI_INTR_TYPE_MSIX) {
		dev->intr_types = DDI_INTR_TYPE_MSIX;
		dev->num_vectors = 2;
		return (DDI_SUCCESS);
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		dev->intr_types = DDI_INTR_TYPE_FIXED;
		dev->num_vectors = 1;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

int
oce_alloc_intr(struct oce_dev *dev)
{
	if (dev->intr_types == DDI_INTR_TYPE_MSIX) {
		return (oce_setup_msix(dev));
	}
	if (dev->intr_types == DDI_INTR_TYPE_FIXED) {
		return (oce_setup_intx(dev));
	}

	return (DDI_FAILURE);
}

/*
 * top level function to undo initialization in oce_setup_intr
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
int
oce_teardown_intr(struct oce_dev *dev)
{
	if (dev->intr_types ==  DDI_INTR_TYPE_MSIX) {
		return (oce_teardown_msix(dev));
	}

	if (dev->intr_types == DDI_INTR_TYPE_FIXED) {
		return (oce_teardown_intx(dev));
	}

	return (DDI_FAILURE);
}

/*
 * helper function to add ISR based on interrupt type
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
int
oce_setup_handlers(struct oce_dev *dev)
{
	if (dev->intr_types == DDI_INTR_TYPE_MSIX) {
		return (oce_add_msix_handlers(dev));
	}

	if (dev->intr_types == DDI_INTR_TYPE_FIXED) {
		return (oce_add_intx_handlers(dev));
	}

	return (DDI_FAILURE);
}

/*
 * helper function to remove ISRs added in oce_setup_handlers
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
void
oce_remove_handler(struct oce_dev *dev)
{
	if (dev->intr_types == DDI_INTR_TYPE_MSIX) {
		oce_del_msix_handlers(dev);
	}

	if (dev->intr_types == DDI_INTR_TYPE_FIXED) {
		oce_del_intx_handlers(dev);
	}
}

void
oce_chip_ei(struct oce_dev *dev)
{
	uint32_t reg;

	reg =  OCE_CFG_READ32(dev, PCICFG_INTR_CTRL);
	if (oce_fm_check_acc_handle(dev, dev->dev_cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}
	reg |= HOSTINTR_MASK;
	OCE_CFG_WRITE32(dev, PCICFG_INTR_CTRL, reg);
	if (oce_fm_check_acc_handle(dev, dev->dev_cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}
}

/*
 * function to enable interrupts
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
void
oce_ei(struct oce_dev *dev)
{
	int i;
	int ret;

	if (dev->intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(dev->htable, dev->num_vectors);
	} else {

		for (i = 0; i < dev->num_vectors; i++) {
			ret = ddi_intr_enable(dev->htable[i]);
			if (ret != DDI_SUCCESS) {
				for (i--; i >= 0; i--) {
					(void) ddi_intr_disable(dev->htable[i]);
				}
			}
		}
	}
	oce_chip_ei(dev);
} /* oce_ei */

void
oce_chip_di(struct oce_dev *dev)
{
	uint32_t reg;

	reg =  OCE_CFG_READ32(dev, PCICFG_INTR_CTRL);
	if (oce_fm_check_acc_handle(dev, dev->dev_cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}
	reg &= ~HOSTINTR_MASK;
	OCE_CFG_WRITE32(dev, PCICFG_INTR_CTRL, reg);
	if (oce_fm_check_acc_handle(dev, dev->dev_cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}
}

/*
 * function to disable interrupts
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
void
oce_di(struct oce_dev *dev)
{
	int i;
	int ret;

	if (dev->intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(dev->htable, dev->num_vectors);
	} else {
		for (i = 0; i < dev->num_vectors; i++) {
			ret = ddi_intr_disable(dev->htable[i]);
			if (ret != DDI_SUCCESS) {
				oce_log(dev, CE_WARN, MOD_CONFIG,
				    "Failed to disable interrupts 0x%x", ret);
			}
		}
	}
	oce_chip_di(dev);
} /* oce_di */

/*
 * function to setup the MSIX vectors
 *
 * dev - software handle to the device
 *
 * return 0=>success, failure otherwise
 */
static int
oce_setup_msix(struct oce_dev *dev)
{
	int navail = 0;
	int ret = 0;

	ret = ddi_intr_get_nintrs(dev->dip, DDI_INTR_TYPE_MSIX, &navail);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not get nintrs:0x%x %d",
		    navail, ret);
		return (DDI_FAILURE);
	}

	/* get the number of vectors available */
	ret = ddi_intr_get_navail(dev->dip, DDI_INTR_TYPE_MSIX, &navail);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not get msix vectors:0x%x",
		    navail);
		return (DDI_FAILURE);
	}

	if (navail < dev->num_vectors)
		return (DDI_FAILURE);

	/* allocate htable */
	dev->htable = kmem_zalloc(dev->num_vectors *
	    sizeof (ddi_intr_handle_t), KM_NOSLEEP);

	if (dev->htable == NULL)
		return (DDI_FAILURE);

	/* allocate interrupt handlers */
	ret = ddi_intr_alloc(dev->dip, dev->htable, DDI_INTR_TYPE_MSIX,
	    0, dev->num_vectors, &navail, DDI_INTR_ALLOC_NORMAL);

	if (ret != DDI_SUCCESS || navail < dev->num_vectors) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Alloc intr failed: %d %d",
		    navail, ret);
		kmem_free(dev->htable,
		    dev->num_vectors * sizeof (ddi_intr_handle_t));
		return (DDI_FAILURE);
	}

	/* update the actual number of interrupts allocated */
	dev->num_vectors = navail;

	/*
	 * get the interrupt priority. Assumption is that all handlers have
	 * equal priority
	 */

	ret = ddi_intr_get_pri(dev->htable[0], &dev->intr_pri);

	if (ret != DDI_SUCCESS) {
		int i;
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Unable to get intr priority: 0x%x",
		    dev->intr_pri);
		for (i = 0; i < dev->num_vectors; i++) {
			(void) ddi_intr_free(dev->htable[i]);
		}
		kmem_free(dev->htable,
		    dev->num_vectors * sizeof (ddi_intr_handle_t));
		return (DDI_FAILURE);
	}

	(void) ddi_intr_get_cap(dev->htable[0], &dev->intr_cap);
	return (DDI_SUCCESS);
} /* oce_setup_msix */

/*
 * helper function to teardown MSIX interrupts
 *
 * dev - software handle to the device
 *
 * return 0 => success, failure otherwise
 */
static int
oce_teardown_msix(struct oce_dev *dev)
{
	int i;

	/* release handlers */
	for (i = 0; i < dev->num_vectors; i++) {
		(void) ddi_intr_free(dev->htable[i]);
	}

	/* release htable */
	kmem_free(dev->htable,
	    dev->num_vectors * sizeof (ddi_intr_handle_t));

	return (DDI_SUCCESS);
} /* oce_teardown_msix */

/*
 * function to add MSIX handlers to vectors
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
static int
oce_add_msix_handlers(struct oce_dev *dev)
{
	int ret;
	int i;

	for (i = 0; i < dev->neqs; i++) {
		ret = ddi_intr_add_handler(dev->htable[i], oce_isr,
		    (caddr_t)dev->eq[i], NULL);
		if (ret != DDI_SUCCESS) {
			oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
			    "Failed to add interrupt handlers");
			for (i--; i >= 0; i--) {
				(void) ddi_intr_remove_handler(dev->htable[i]);
			}
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
} /* oce_add_msix_handlers */

/*
 * function to disassociate msix handlers added in oce_add_msix_handlers
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
static void
oce_del_msix_handlers(struct oce_dev *dev)
{
	int nvec;

	for (nvec = 0; nvec < dev->num_vectors; nvec++) {
		(void) ddi_intr_remove_handler(dev->htable[nvec]);
	}
} /* oce_del_msix_handlers */

/*
 * command interrupt handler routine added to all vectors
 *
 * arg1 = callback data
 * arg2 - callback data
 *
 * return DDI_INTR_CLAIMED => interrupt was claimed by the ISR
 */
static uint_t
oce_isr(caddr_t arg1, caddr_t arg2)
{
	struct oce_eq *eq;
	struct oce_eqe *eqe;
	uint16_t num_eqe = 0;
	uint16_t cq_id;
	struct oce_cq *cq;
	struct oce_dev  *dev;

	_NOTE(ARGUNUSED(arg2));

	eq = (struct oce_eq *)(void *)(arg1);

	if (eq == NULL) {
		return (DDI_INTR_UNCLAIMED);
	}
	dev = eq->parent;

	/* If device is getting suspended or closing, then return */
	if ((dev == NULL) ||
	    (dev->state & STATE_MAC_STOPPING) ||
	    !(dev->state & STATE_MAC_STARTED) ||
	    dev->suspended) {
		return (DDI_INTR_UNCLAIMED);
	}

	(void) ddi_dma_sync(eq->ring->dbuf->dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	eqe = RING_GET_CONSUMER_ITEM_VA(eq->ring, struct oce_eqe);

	while (eqe->u0.dw0) {

		eqe->u0.dw0 = LE_32(eqe->u0.dw0);

		/* if not CQ then continue else flag an error */
		if (EQ_MAJOR_CODE_COMPLETION != eqe->u0.s.major_code) {
			oce_log(dev, CE_WARN, MOD_ISR,
			    "NOT a CQ event. 0x%x",
			    eqe->u0.s.major_code);
		}

		/* get the cq from the eqe */
		cq_id = eqe->u0.s.resource_id;
		cq = dev->cq[cq_id];

		/* Call the completion handler */
		(void) cq->cq_handler(cq->cb_arg);

		/* clear valid bit and progress eqe */
		eqe->u0.dw0 = 0;
		RING_GET(eq->ring, 1);
		eqe = RING_GET_CONSUMER_ITEM_VA(eq->ring, struct oce_eqe);
		num_eqe++;
	} /* for all EQEs */

	/* ring the eq doorbell, signify that it's done processing  */
	if (num_eqe > 0) {
		oce_arm_eq(dev, eq->eq_id, num_eqe, B_TRUE, B_TRUE);
		return (DDI_INTR_CLAIMED);
	} else {
		return (DDI_INTR_UNCLAIMED);
	}
} /* oce_msix_handler */

static int
oce_setup_intx(struct oce_dev *dev)
{
	int navail = 0;
	int nintr = 0;
	int ret = 0;

	ret = ddi_intr_get_nintrs(dev->dip, DDI_INTR_TYPE_FIXED, &nintr);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "could not get nintrs:0x%x %d",
		    navail, ret);
		return (DDI_FAILURE);
	}

	/* get the number of vectors available */
	ret = ddi_intr_get_navail(dev->dip, DDI_INTR_TYPE_FIXED, &navail);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "could not get intx vectors:0x%x",
		    navail);
		return (DDI_FAILURE);
	}

	/* always 1 */
	if (navail != nintr)
		return (DDI_FAILURE);

	dev->num_vectors = navail;

	/* allocate htable */
	dev->htable = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_NOSLEEP);
	if (dev->htable == NULL) {
		return (DDI_FAILURE);
	}

	/* allocate interrupt handlers */
	ret = ddi_intr_alloc(dev->dip, dev->htable, DDI_INTR_TYPE_FIXED,
	    0, dev->num_vectors, &navail, DDI_INTR_ALLOC_NORMAL);

	if (ret != DDI_SUCCESS || navail != 1) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "alloc intr failed: %d %d",
		    navail, ret);
		kmem_free(dev->htable, sizeof (ddi_intr_handle_t));
		return (DDI_FAILURE);
	}

	/* update the actual number of interrupts allocated */
	dev->num_vectors = navail;

	/*
	 * get the interrupt priority. Assumption is that all handlers have
	 * equal priority
	 */

	ret = ddi_intr_get_pri(dev->htable[0], &dev->intr_pri);

	if (ret != DDI_SUCCESS) {
		int i;
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Unable to get intr priority: 0x%x",
		    dev->intr_pri);
		for (i = 0; i < dev->num_vectors; i++) {
			(void) ddi_intr_free(dev->htable[i]);
		}
		kmem_free(dev->htable, sizeof (ddi_intr_handle_t));
		return (DDI_FAILURE);
	}

	(void) ddi_intr_get_cap(dev->htable[0], &dev->intr_cap);
	return (DDI_SUCCESS);
} /* oce_setup_intx */

static int
oce_teardown_intx(struct oce_dev *dev)
{
	/* release handlers */
	(void) ddi_intr_free(dev->htable[0]);

	/* release htable */
	kmem_free(dev->htable, sizeof (ddi_intr_handle_t));

	return (DDI_FAILURE);
} /* oce_teardown_intx */

static int
oce_add_intx_handlers(struct oce_dev *dev)
{
	int ret;

	ret = ddi_intr_add_handler(dev->htable[0], oce_isr,
	    (caddr_t)dev->eq[0], NULL);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_NOTE, MOD_CONFIG, "%s",
		    "failed to add intr handlers");
		(void) ddi_intr_remove_handler(dev->htable[0]);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
} /* oce_add_intx_handlers */

static void
oce_del_intx_handlers(struct oce_dev *dev)
{
	(void) ddi_intr_remove_handler(dev->htable[0]);
} /* oce_del_intx_handlers */
