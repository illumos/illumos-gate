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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Source file interrupt registration
 * and related helper functions
 */

#include <oce_impl.h>


static uint_t oce_isr(caddr_t arg1, caddr_t arg2);

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
	int navail = 0;
	int nsupported = 0;
	int min = 0;
	int nreqd = 0;
	int nallocd = 0;

	/* get supported intr types */
	ret = ddi_intr_get_supported_types(dev->dip, &intr_types);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to retrieve intr types ");
		return (DDI_FAILURE);
	}

retry_intr:
	if (intr_types & DDI_INTR_TYPE_MSIX) {
		dev->intr_type = DDI_INTR_TYPE_MSIX;
		/* one vector is shared by MCC and Tx */
		nreqd = dev->rx_rings + 1;
		min = OCE_MIN_VECTORS;
	} else if (intr_types & DDI_INTR_TYPE_FIXED) {
		dev->intr_type = DDI_INTR_TYPE_FIXED;
		nreqd = OCE_MIN_VECTORS;
		min = OCE_MIN_VECTORS;
	}

	ret = ddi_intr_get_nintrs(dev->dip, dev->intr_type, &nsupported);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not get nintrs:0x%d", ret);
		return (DDI_FAILURE);
	}

	/* get the number of vectors available */
	ret = ddi_intr_get_navail(dev->dip, dev->intr_type, &navail);
	if (ret != DDI_SUCCESS || navail < min) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not get msix vectors:0x%x",
		    navail);
		return (DDI_FAILURE);
	}

	if (navail < min) {
		return (DDI_FAILURE);
	}

	/* if the requested number is more than available reset reqd */
	if (navail < nreqd) {
		nreqd = navail;
	}

	/* allocate htable */
	dev->hsize  = nreqd *  sizeof (ddi_intr_handle_t);
	dev->htable = kmem_zalloc(dev->hsize,  KM_NOSLEEP);

	if (dev->htable == NULL)
		return (DDI_FAILURE);

	nallocd = 0;
	/* allocate interrupt handlers */
	ret = ddi_intr_alloc(dev->dip, dev->htable, dev->intr_type,
	    0, nreqd, &nallocd, DDI_INTR_ALLOC_NORMAL);

	if (ret != DDI_SUCCESS) {
		goto fail_intr;
	}

	dev->num_vectors = nallocd;
	if (nallocd < min) {
		goto fail_intr;
	}

	/*
	 * get the interrupt priority. Assumption is that all handlers have
	 * equal priority
	 */

	ret = ddi_intr_get_pri(dev->htable[0], &dev->intr_pri);

	if (ret != DDI_SUCCESS) {
		goto fail_intr;
	}

	(void) ddi_intr_get_cap(dev->htable[0], &dev->intr_cap);

	if ((intr_types & DDI_INTR_TYPE_MSIX) && (nallocd > 1)) {
		dev->rx_rings = nallocd - 1;
	} else {
		dev->rx_rings = 1;
	}

	return (DDI_SUCCESS);

fail_intr:
	(void) oce_teardown_intr(dev);
	if ((dev->intr_type == DDI_INTR_TYPE_MSIX) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		intr_types &= ~DDI_INTR_TYPE_MSIX;
		oce_log(dev, CE_NOTE, MOD_CONFIG, "%s",
		    "Could not get MSIX vectors, trying for FIXED vectors");
		goto retry_intr;
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
	int i;

	/* release handlers */
	for (i = 0; i < dev->num_vectors; i++) {
		(void) ddi_intr_free(dev->htable[i]);
	}

	/* release htable */
	kmem_free(dev->htable, dev->hsize);
	dev->htable = NULL;

	return (DDI_SUCCESS);
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
	int i = 0;
	int ret;
	for (i = 0; i < dev->num_vectors; i++) {
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
	int nvec;
	for (nvec = 0; nvec < dev->num_vectors; nvec++) {
		(void) ddi_intr_remove_handler(dev->htable[nvec]);
	}
}

void
oce_chip_ei(struct oce_dev *dev)
{
	uint32_t reg;

	reg =  OCE_CFG_READ32(dev, PCICFG_INTR_CTRL);
	reg |= HOSTINTR_MASK;
	OCE_CFG_WRITE32(dev, PCICFG_INTR_CTRL, reg);
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
	reg &= ~HOSTINTR_MASK;
	OCE_CFG_WRITE32(dev, PCICFG_INTR_CTRL, reg);
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

	oce_chip_di(dev);
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

} /* oce_di */

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

	dev = eq->parent;

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
		cq_id = eqe->u0.s.resource_id % OCE_MAX_CQ;
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
	oce_arm_eq(dev, eq->eq_id, num_eqe, B_TRUE, B_TRUE);
	if (num_eqe > 0) {
		return (DDI_INTR_CLAIMED);
	} else {
		return (DDI_INTR_UNCLAIMED);
	}
} /* oce_msix_handler */
