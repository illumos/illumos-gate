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
 * Copyright 2024 Oxide Computer Company
 */

#include "ena.h"

/*
 * We currently limit the number of Tx/Rx queues to the number of
 * available interrupts (minus one for the admin queue).
 */
static uint_t
ena_io_intr(caddr_t arg1, caddr_t arg2)
{
	ena_t *ena = (ena_t *)arg1;
	uint16_t vector = (uintptr_t)(void *)arg2;
	ASSERT3U(vector, >, 0);
	ASSERT3U(vector, <, ena->ena_num_intrs);
	ena_txq_t *txq = &ena->ena_txqs[vector - 1];
	ena_rxq_t *rxq = &ena->ena_rxqs[vector - 1];
	uint32_t intr_ctrl;

	if ((ena->ena_state & ENA_STATE_STARTED) == 0)
		return (DDI_INTR_CLAIMED);

	ASSERT3P(txq, !=, NULL);
	ASSERT3P(rxq, !=, NULL);
	ena_tx_intr_work(txq);
	ena_rx_intr_work(rxq);

	/*
	 * The Rx/Tx queue share the same interrupt, only need to
	 * unmask interrupts for one of them.
	 */
	intr_ctrl = ena_hw_abs_read32(ena, txq->et_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(ena, txq->et_cq_unmask_addr, intr_ctrl);
	return (DDI_INTR_CLAIMED);
}

static uint_t
ena_admin_intr(caddr_t arg1, caddr_t arg2)
{
	ena_t *ena = (ena_t *)arg1;

	if ((ena->ena_state & ENA_STATE_STARTED) != 0)
		ena_aenq_work(ena);
	return (DDI_INTR_CLAIMED);
}

void
ena_intr_remove_handlers(ena_t *ena, bool resetting)
{
	VERIFY0(resetting);

	for (int i = 0; i < ena->ena_num_intrs; i++) {
		int ret = ddi_intr_remove_handler(ena->ena_intr_handles[i]);

		/* Nothing we can really do except log. */
		if (ret != DDI_SUCCESS) {
			ena_err(ena, "failed to remove interrupt handler for "
			    "vector %d: %d", i, ret);
		}
	}
}

/*
 * The ena driver uses separate interrupt handlers for the admin queue
 * and I/O queues.
 */
bool
ena_intr_add_handlers(ena_t *ena)
{
	ASSERT3S(ena->ena_num_intrs, >=, 2);
	if (ddi_intr_add_handler(ena->ena_intr_handles[0], ena_admin_intr, ena,
	    (void *)(uintptr_t)0) != DDI_SUCCESS) {
		ena_err(ena, "failed to add admin interrupt handler");
		return (false);
	}

	for (int i = 1; i < ena->ena_num_intrs; i++) {
		caddr_t vector = (void *)(uintptr_t)(i);
		int ret = ddi_intr_add_handler(ena->ena_intr_handles[i],
		    ena_io_intr, ena, vector);

		if (ret != DDI_SUCCESS) {
			ena_err(ena, "failed to add I/O interrupt handler "
			    "for vector %u", i);

			/*
			 * If we fail to add any I/O handler, then all
			 * successfully added handlers are removed,
			 * including the admin handler. For example,
			 * when i=2 we remove handler 1 (the first I/O
			 * handler), and when i=1 we remove handler 0
			 * (the admin handler).
			 */
			while (i >= 1) {
				i--;
				(void) ddi_intr_remove_handler(
				    ena->ena_intr_handles[i]);
			}

			return (false);
		}
	}

	return (true);
}

bool
ena_intrs_disable(ena_t *ena)
{
	int ret;

	if (ena->ena_intr_caps & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_disable(ena->ena_intr_handles,
		    ena->ena_num_intrs)) != DDI_SUCCESS) {
			ena_err(ena, "failed to block disable interrupts: %d",
			    ret);
			return (false);
		}
	} else {
		for (int i = 0; i < ena->ena_num_intrs; i++) {
			ret = ddi_intr_disable(ena->ena_intr_handles[i]);
			if (ret != DDI_SUCCESS) {
				ena_err(ena, "failed to disable interrupt "
				    "%d: %d", i, ret);
				return (false);
			}
		}
	}

	return (true);
}

bool
ena_intrs_enable(ena_t *ena)
{
	int ret;

	if (ena->ena_intr_caps & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_enable(ena->ena_intr_handles,
		    ena->ena_num_intrs)) != DDI_SUCCESS) {
			ena_err(ena, "failed to block enable interrupts: %d",
			    ret);
			return (false);
		}
	} else {
		for (int i = 0; i < ena->ena_num_intrs; i++) {
			if ((ret = ddi_intr_enable(ena->ena_intr_handles[i])) !=
			    DDI_SUCCESS) {
				ena_err(ena, "failed to enable interrupt "
				    "%d: %d", i, ret);

				/*
				 * If we fail to enable any interrupt,
				 * then all interrupts are disabled.
				 */
				while (i >= 1) {
					i--;
					(void) ddi_intr_disable(
					    ena->ena_intr_handles[i]);
				}

				return (false);
			}
		}
	}

	return (true);
}
