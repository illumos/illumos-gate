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
 * Source file containing the implementation of the MailBox queue handling
 * and related helper functions
 */

#include <oce_impl.h>

/*
 * function to drain a MCQ and process its CQEs
 *
 * dev - software handle to the device
 * cq - pointer to the cq to drain
 *
 * return the number of CQEs processed
 */
uint16_t
oce_drain_mq_cq(void *arg)
{
	struct oce_mq_cqe *cqe = NULL;
	uint16_t num_cqe = 0;
	link_state_t link_status;
	struct oce_async_cqe_link_state *acqe;
	struct oce_mq *mq;
	struct oce_cq  *cq;
	struct oce_dev *dev;

	/* do while we do not reach a cqe that is not valid */
	mq = (struct oce_mq *)arg;
	cq = mq->cq;
	dev = mq->parent;
	mutex_enter(&mq->lock);
	cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_mq_cqe);
	while (cqe->u0.dw[3]) {
		DW_SWAP(u32ptr(cqe), sizeof (struct oce_mq_cqe));
		if (cqe->u0.s.async_event) {
			acqe = (struct oce_async_cqe_link_state *)cqe;
			if (acqe->u0.s.event_code ==
			    ASYNC_EVENT_CODE_LINK_STATE) {
				link_status = (acqe->u0.s.link_status)?
				    LINK_STATE_UP : LINK_STATE_DOWN;
				mac_link_update(dev->mac_handle, link_status);
			}
		}
		cqe->u0.dw[3] = 0;
		RING_GET(cq->ring, 1);
		cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_mq_cqe);
		num_cqe++;
	} /* for all valid CQE */
	mutex_exit(&mq->lock);
	oce_arm_cq(dev, cq->cq_id, num_cqe, B_TRUE);
	return (num_cqe);
} /* oce_drain_mq_cq */

int
oce_start_mq(struct oce_mq *mq)
{
	oce_arm_cq(mq->parent, mq->cq->cq_id, 0, B_TRUE);
	return (0);
}


void
oce_clean_mq(struct oce_mq *mq)
{
	struct oce_cq  *cq;
	struct oce_dev *dev;
	uint16_t num_cqe = 0;
	struct oce_mq_cqe *cqe = NULL;

	cq = mq->cq;
	dev = mq->parent;
	cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_mq_cqe);
	while (cqe->u0.dw[3]) {
		DW_SWAP(u32ptr(cqe), sizeof (struct oce_mq_cqe));
		cqe->u0.dw[3] = 0;
		RING_GET(cq->ring, 1);
		cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_mq_cqe);
		num_cqe++;
	} /* for all valid CQE */
	if (num_cqe)
		oce_arm_cq(dev, cq->cq_id, num_cqe, B_FALSE);
	/* Drain the Event queue now */
	oce_drain_eq(mq->cq->eq);
}
