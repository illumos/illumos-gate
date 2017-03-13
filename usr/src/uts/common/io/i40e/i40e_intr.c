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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2017 Tegile Systems, Inc.  All rights reserved.
 */

/*
 * -------------------------
 * Interrupt Handling Theory
 * -------------------------
 *
 * There are a couple different sets of interrupts that we need to worry about:
 *
 *   - Interrupts from receive queues
 *   - Interrupts from transmit queues
 *   - 'Other Interrupts', such as the administrative queue
 *
 * 'Other Interrupts' are asynchronous events such as a link status change event
 * being posted to the administrative queue, unrecoverable ECC errors, and more.
 * If we have something being posted to the administrative queue, then we go
 * through and process it, because it's generally enabled as a separate logical
 * interrupt. Note, we may need to do more here eventually. To re-enable the
 * interrupts from the 'Other Interrupts' section, we need to clear the PBA and
 * write ENA to PFINT_ICR0.
 *
 * Interrupts from the transmit and receive queues indicates that our requests
 * have been processed. In the rx case, it means that we have data that we
 * should take a look at and send up the stack. In the tx case, it means that
 * data which we got from MAC has now been sent out on the wire and we can free
 * the associated data. Most of the logic for acting upon the presence of this
 * data can be found in i40e_transciever.c which handles all of the DMA, rx, and
 * tx operations. This file is dedicated to handling and dealing with interrupt
 * processing.
 *
 * All devices supported by this driver support three kinds of interrupts:
 *
 *   o Extended Message Signaled Interrupts (MSI-X)
 *   o Message Signaled Interrupts (MSI)
 *   o Legacy PCI interrupts (INTx)
 *
 * Generally speaking the hardware logically handles MSI and INTx the same and
 * restricts us to only using a single interrupt, which isn't the interesting
 * case. With MSI-X available, each physical function of the device provides the
 * opportunity for multiple interrupts which is what we'll focus on.
 *
 * --------------------
 * Interrupt Management
 * --------------------
 *
 * By default, the admin queue, which consists of the asynchronous other
 * interrupts is always bound to MSI-X vector zero. Next, we spread out all of
 * the other interrupts that we have available to us over the remaining
 * interrupt vectors.
 *
 * This means that there may be multiple queues, both tx and rx, which are
 * mapped to the same interrupt. When the interrupt fires, we'll have to check
 * all of them for servicing, before we go through and indicate that the
 * interrupt is claimed.
 *
 * The hardware provides the means of mapping various queues to MSI-X interrupts
 * by programming the I40E_QINT_RQCTL() and I4OE_QINT_TQCTL() registers. These
 * registers can also be used to enable and disable whether or not the queue is
 * a source of interrupts. As part of this, the hardware requires that we
 * maintain a linked list of queues for each interrupt vector. While it may seem
 * like this is only there for the purproses of ITRs, that's not the case. The
 * first queue must be programmed in I40E_QINT_LNKLSTN(%vector) register. Each
 * queue defines the next one in either the I40E_QINT_RQCTL or I40E_QINT_TQCTL
 * register.
 *
 * Finally, the individual interrupt vector itself has the ability to be enabled
 * and disabled. The overall interrupt is controlled through the
 * I40E_PFINT_DYN_CTLN() register. This is used to turn on and off the interrupt
 * as a whole.
 *
 * Note that this means that both the individual queue and the interrupt as a
 * whole can be toggled and re-enabled.
 *
 * -------------------
 * Non-MSIX Management
 * -------------------
 *
 * We may have a case where the Operating System is unable to actually allocate
 * any MSI-X to the system. In such a world, there is only one transmit/receive
 * queue pair and it is bound to the same interrupt with index zero. The
 * hardware doesn't allow us access to additional interrupt vectors in these
 * modes. Note that technically we could support more transmit/receive queues if
 * we wanted.
 *
 * In this world, because the interrupts for the admin queue and traffic are
 * mixed together, we have to consult ICR0 to determine what has occurred. The
 * QINT_TQCTL and QINT_RQCTL registers have a field, 'MSI-X 0 index' which
 * allows us to set a specific bit in ICR0. There are up to seven such bits;
 * however, we only use the bit 0 and 1 for the rx and tx queue respectively.
 * These are contained by the I40E_INTR_NOTX_{R|T}X_QUEUE and
 * I40E_INTR_NOTX_{R|T}X_MASK registers respectively.
 *
 * Unfortunately, these corresponding queue bits have no corresponding entry in
 * the ICR0_ENA register. So instead, when enabling interrupts on the queues, we
 * end up enabling it on the queue registers rather than on the MSI-X registers.
 * In the MSI-X world, because they can be enabled and disabled, this is
 * different and the queues can always be enabled and disabled, but the
 * interrupts themselves are toggled (ignoring the question of interrupt
 * blanking for polling on rings).
 *
 * Finally, we still have to set up the interrupt linked list, but the list is
 * instead rooted at the register I40E_PFINT_LNKLST0, rather than being tied to
 * one of the other MSI-X registers.
 *
 * --------------------
 * Interrupt Moderation
 * --------------------
 *
 * The XL710 hardware has three different interrupt moderation registers per
 * interrupt. Unsurprisingly, we use these for:
 *
 *   o RX interrupts
 *   o TX interrupts
 *   o 'Other interrupts' (link status change, admin queue, etc.)
 *
 * By default, we throttle 'other interrupts' the most, then TX interrupts, and
 * then RX interrupts. The default values for these were based on trying to
 * reason about both the importance and frequency of events. Generally speaking
 * 'other interrupts' are not very frequent and they're not important for the
 * I/O data path in and of itself (though they may indicate issues with the I/O
 * data path).
 *
 * On the flip side, when we're not polling, RX interrupts are very important.
 * The longer we wait for them, the more latency that we inject into the system.
 * However, if we allow interrupts to occur too frequently, we risk a few
 * problems:
 *
 *  1) Abusing system resources. Without proper interrupt blanking and polling,
 *     we can see upwards of 200k-300k interrupts per second on the system.
 *
 *  2) Not enough data coalescing to enable polling. In other words, the more
 *     data that we allow to build up, the more likely we'll be able to enable
 *     polling mode and allowing us to better handle bulk data.
 *
 * In-between the 'other interrupts' and the TX interrupts we have the
 * reclamation of TX buffers. This operation is not quite as important as we
 * generally size the ring large enough that we should be able to reclaim a
 * substantial amount of the descriptors that we have used per interrupt. So
 * while it's important that this interrupt occur, we don't necessarily need it
 * firing as frequently as RX; it doesn't, on its own, induce additional latency
 * into the system.
 *
 * Based on all this we currently assign static ITR values for the system. While
 * we could move to a dynamic system (the hardware supports that), we'd want to
 * make sure that we're seeing problems from this that we believe would be
 * generally helped by the added complexity.
 *
 * Based on this, the default values that we have allow for the following
 * interrupt thresholds:
 *
 *    o 20k interrupts/s for RX
 *    o 5k interrupts/s for TX
 *    o 2k interupts/s for 'Other Interrupts'
 */

#include "i40e_sw.h"

#define	I40E_INTR_NOTX_QUEUE	0
#define	I40E_INTR_NOTX_INTR	0
#define	I40E_INTR_NOTX_RX_QUEUE	0
#define	I40E_INTR_NOTX_RX_MASK	(1 << I40E_PFINT_ICR0_QUEUE_0_SHIFT)
#define	I40E_INTR_NOTX_TX_QUEUE	1
#define	I40E_INTR_NOTX_TX_MASK	(1 << I40E_PFINT_ICR0_QUEUE_1_SHIFT)

void
i40e_intr_set_itr(i40e_t *i40e, i40e_itr_index_t itr, uint_t val)
{
	int i;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	VERIFY3U(val, <=, I40E_MAX_ITR);
	VERIFY3U(itr, <, I40E_ITR_INDEX_NONE);

	/*
	 * No matter the interrupt mode, the ITR for other interrupts is always
	 * on interrupt zero and the same is true if we're not using MSI-X.
	 */
	if (itr == I40E_ITR_INDEX_OTHER ||
	    i40e->i40e_intr_type != DDI_INTR_TYPE_MSIX) {
		I40E_WRITE_REG(hw, I40E_PFINT_ITR0(itr), val);
		return;
	}

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		I40E_WRITE_REG(hw, I40E_PFINT_ITRN(itr, i), val);
	}
}

/*
 * Re-enable the adminq. Note that the adminq doesn't have a traditional queue
 * associated with it from an interrupt perspective and just lives on ICR0.
 * However when MSI-X interrupts are not being used, then this also enables and
 * disables those interrupts.
 */
static void
i40e_intr_adminq_enable(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint32_t reg;

	reg = I40E_PFINT_DYN_CTL0_INTENA_MASK |
	    I40E_PFINT_DYN_CTL0_CLEARPBA_MASK |
	    (I40E_ITR_INDEX_NONE << I40E_PFINT_DYN_CTL0_ITR_INDX_SHIFT);
	I40E_WRITE_REG(hw, I40E_PFINT_DYN_CTL0, reg);
	i40e_flush(hw);
}

static void
i40e_intr_adminq_disable(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint32_t reg;

	reg = I40E_ITR_INDEX_NONE << I40E_PFINT_DYN_CTL0_ITR_INDX_SHIFT;
	I40E_WRITE_REG(hw, I40E_PFINT_DYN_CTL0, reg);
}

static void
i40e_intr_io_enable(i40e_t *i40e, int vector)
{
	uint32_t reg;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	reg = I40E_PFINT_DYN_CTLN_INTENA_MASK |
	    I40E_PFINT_DYN_CTLN_CLEARPBA_MASK |
	    (I40E_ITR_INDEX_NONE << I40E_PFINT_DYN_CTLN_ITR_INDX_SHIFT);
	I40E_WRITE_REG(hw, I40E_PFINT_DYN_CTLN(vector - 1), reg);
}

static void
i40e_intr_io_disable(i40e_t *i40e, int vector)
{
	uint32_t reg;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	reg = I40E_ITR_INDEX_NONE << I40E_PFINT_DYN_CTLN_ITR_INDX_SHIFT;
	I40E_WRITE_REG(hw, I40E_PFINT_DYN_CTLN(vector - 1), reg);
}

/*
 * When MSI-X interrupts are being used, then we can enable the actual
 * interrupts themselves. However, when they are not, we instead have to turn
 * towards the queue's CAUSE_ENA bit and enable that.
 */
void
i40e_intr_io_enable_all(i40e_t *i40e)
{
	if (i40e->i40e_intr_type == DDI_INTR_TYPE_MSIX) {
		int i;

		for (i = 1; i < i40e->i40e_intr_count; i++) {
			i40e_intr_io_enable(i40e, i);
		}
	} else {
		uint32_t reg;
		i40e_hw_t *hw = &i40e->i40e_hw_space;

		reg = I40E_READ_REG(hw, I40E_QINT_RQCTL(I40E_INTR_NOTX_QUEUE));
		reg |= I40E_QINT_RQCTL_CAUSE_ENA_MASK;
		I40E_WRITE_REG(hw, I40E_QINT_RQCTL(I40E_INTR_NOTX_QUEUE), reg);

		reg = I40E_READ_REG(hw, I40E_QINT_TQCTL(I40E_INTR_NOTX_QUEUE));
		reg |= I40E_QINT_TQCTL_CAUSE_ENA_MASK;
		I40E_WRITE_REG(hw, I40E_QINT_TQCTL(I40E_INTR_NOTX_QUEUE), reg);
	}
}

/*
 * When MSI-X interrupts are being used, then we can disable the actual
 * interrupts themselves. However, when they are not, we instead have to turn
 * towards the queue's CAUSE_ENA bit and disable that.
 */
void
i40e_intr_io_disable_all(i40e_t *i40e)
{
	if (i40e->i40e_intr_type == DDI_INTR_TYPE_MSIX) {
		int i;

		for (i = 1; i < i40e->i40e_intr_count; i++) {
			i40e_intr_io_disable(i40e, i);
		}
	} else {
		uint32_t reg;
		i40e_hw_t *hw = &i40e->i40e_hw_space;

		reg = I40E_READ_REG(hw, I40E_QINT_RQCTL(I40E_INTR_NOTX_QUEUE));
		reg &= ~I40E_QINT_RQCTL_CAUSE_ENA_MASK;
		I40E_WRITE_REG(hw, I40E_QINT_RQCTL(I40E_INTR_NOTX_QUEUE), reg);

		reg = I40E_READ_REG(hw, I40E_QINT_TQCTL(I40E_INTR_NOTX_QUEUE));
		reg &= ~I40E_QINT_TQCTL_CAUSE_ENA_MASK;
		I40E_WRITE_REG(hw, I40E_QINT_TQCTL(I40E_INTR_NOTX_QUEUE), reg);
	}
}

/*
 * As part of disabling the tx and rx queue's we're technically supposed to
 * remove the linked list entries. The simplest way is to clear the LNKLSTN
 * register by setting it to I40E_QUEUE_TYPE_EOL (0x7FF).
 *
 * Note all of the FM register access checks are performed by the caller.
 */
void
i40e_intr_io_clear_cause(i40e_t *i40e)
{
	int i;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	if (i40e->i40e_intr_type != DDI_INTR_TYPE_MSIX) {
		uint32_t reg;
		reg = I40E_QUEUE_TYPE_EOL;
		I40E_WRITE_REG(hw, I40E_PFINT_LNKLST0, reg);
		return;
	}

	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		uint32_t reg;
#ifdef DEBUG
		/*
		 * Verify that the interrupt in question is disabled. This is a
		 * prerequisite of modifying the data in question.
		 */
		reg = I40E_READ_REG(hw, I40E_PFINT_DYN_CTLN(i));
		VERIFY0(reg & I40E_PFINT_DYN_CTLN_INTENA_MASK);
#endif
		reg = I40E_QUEUE_TYPE_EOL;
		I40E_WRITE_REG(hw, I40E_PFINT_LNKLSTN(i), reg);
	}

	i40e_flush(hw);
}

/*
 * Finalize interrupt handling. Mostly this disables the admin queue.
 */
void
i40e_intr_chip_fini(i40e_t *i40e)
{
#ifdef DEBUG
	int i;
	uint32_t reg;

	i40e_hw_t *hw = &i40e->i40e_hw_space;

	/*
	 * Take a look and verify that all other interrupts have been disabled
	 * and the interrupt linked lists have been zeroed.
	 */
	if (i40e->i40e_intr_type == DDI_INTR_TYPE_MSIX) {
		for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
			reg = I40E_READ_REG(hw, I40E_PFINT_DYN_CTLN(i));
			VERIFY0(reg & I40E_PFINT_DYN_CTLN_INTENA_MASK);

			reg = I40E_READ_REG(hw, I40E_PFINT_LNKLSTN(i));
			VERIFY3U(reg, ==, I40E_QUEUE_TYPE_EOL);
		}
	}
#endif

	i40e_intr_adminq_disable(i40e);
}

/*
 * Enable all of the queues and set the corresponding LNKLSTN registers. Note
 * that we always enable queues as interrupt sources, even though we don't
 * enable the MSI-X interrupt vectors.
 */
static void
i40e_intr_init_queue_msix(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint32_t reg;
	int i;

	/*
	 * Map queues to MSI-X interrupts. Queue i is mapped to vector i + 1.
	 * Note that we skip the ITR logic for the moment, just to make our
	 * lives as explicit and simple as possible.
	 */
	for (i = 0; i < i40e->i40e_num_trqpairs; i++) {
		i40e_trqpair_t *itrq = &i40e->i40e_trqpairs[i];

		reg = (i << I40E_PFINT_LNKLSTN_FIRSTQ_INDX_SHIFT) |
		    (I40E_QUEUE_TYPE_RX <<
		    I40E_PFINT_LNKLSTN_FIRSTQ_TYPE_SHIFT);
		I40E_WRITE_REG(hw, I40E_PFINT_LNKLSTN(i), reg);

		reg =
		    (itrq->itrq_rx_intrvec << I40E_QINT_RQCTL_MSIX_INDX_SHIFT) |
		    (I40E_ITR_INDEX_RX << I40E_QINT_RQCTL_ITR_INDX_SHIFT) |
		    (i << I40E_QINT_RQCTL_NEXTQ_INDX_SHIFT) |
		    (I40E_QUEUE_TYPE_TX << I40E_QINT_RQCTL_NEXTQ_TYPE_SHIFT) |
		    I40E_QINT_RQCTL_CAUSE_ENA_MASK;

		I40E_WRITE_REG(hw, I40E_QINT_RQCTL(i), reg);

		reg =
		    (itrq->itrq_tx_intrvec << I40E_QINT_TQCTL_MSIX_INDX_SHIFT) |
		    (I40E_ITR_INDEX_TX << I40E_QINT_RQCTL_ITR_INDX_SHIFT) |
		    (I40E_QUEUE_TYPE_EOL << I40E_QINT_TQCTL_NEXTQ_INDX_SHIFT) |
		    (I40E_QUEUE_TYPE_RX << I40E_QINT_TQCTL_NEXTQ_TYPE_SHIFT) |
		    I40E_QINT_TQCTL_CAUSE_ENA_MASK;

		I40E_WRITE_REG(hw, I40E_QINT_TQCTL(i), reg);
	}

}

/*
 * Set up a single queue to share the admin queue interrupt in the non-MSI-X
 * world. Note we do not enable the queue as an interrupt cause at this time. We
 * don't have any other vector of control here, unlike with the MSI-X interrupt
 * case.
 */
static void
i40e_intr_init_queue_shared(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint32_t reg;

	VERIFY(i40e->i40e_intr_type == DDI_INTR_TYPE_FIXED ||
	    i40e->i40e_intr_type == DDI_INTR_TYPE_MSI);

	reg = (I40E_INTR_NOTX_QUEUE << I40E_PFINT_LNKLST0_FIRSTQ_INDX_SHIFT) |
	    (I40E_QUEUE_TYPE_RX << I40E_PFINT_LNKLSTN_FIRSTQ_TYPE_SHIFT);
	I40E_WRITE_REG(hw, I40E_PFINT_LNKLST0, reg);

	reg = (I40E_INTR_NOTX_INTR << I40E_QINT_RQCTL_MSIX_INDX_SHIFT) |
	    (I40E_ITR_INDEX_RX << I40E_QINT_RQCTL_ITR_INDX_SHIFT) |
	    (I40E_INTR_NOTX_RX_QUEUE << I40E_QINT_RQCTL_MSIX0_INDX_SHIFT) |
	    (I40E_INTR_NOTX_QUEUE << I40E_QINT_RQCTL_NEXTQ_INDX_SHIFT) |
	    (I40E_QUEUE_TYPE_TX << I40E_QINT_RQCTL_NEXTQ_TYPE_SHIFT);

	I40E_WRITE_REG(hw, I40E_QINT_RQCTL(I40E_INTR_NOTX_QUEUE), reg);

	reg = (I40E_INTR_NOTX_INTR << I40E_QINT_TQCTL_MSIX_INDX_SHIFT) |
	    (I40E_ITR_INDEX_TX << I40E_QINT_TQCTL_ITR_INDX_SHIFT) |
	    (I40E_INTR_NOTX_TX_QUEUE << I40E_QINT_TQCTL_MSIX0_INDX_SHIFT) |
	    (I40E_QUEUE_TYPE_EOL << I40E_QINT_TQCTL_NEXTQ_INDX_SHIFT) |
	    (I40E_QUEUE_TYPE_RX << I40E_QINT_TQCTL_NEXTQ_TYPE_SHIFT);

	I40E_WRITE_REG(hw, I40E_QINT_TQCTL(I40E_INTR_NOTX_QUEUE), reg);
}

/*
 * Enable the specified queue as a valid source of interrupts. Note, this should
 * only be used as part of the GLDv3's interrupt blanking routines. The debug
 * build assertions are specific to that.
 */
void
i40e_intr_rx_queue_enable(i40e_t *i40e, uint_t queue)
{
	uint32_t reg;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));
	ASSERT(queue < i40e->i40e_num_trqpairs);

	reg = I40E_READ_REG(hw, I40E_QINT_RQCTL(queue));
	ASSERT0(reg & I40E_QINT_RQCTL_CAUSE_ENA_MASK);
	reg |= I40E_QINT_RQCTL_CAUSE_ENA_MASK;
	I40E_WRITE_REG(hw, I40E_QINT_RQCTL(queue), reg);
}

/*
 * Disable the specified queue as a valid source of interrupts. Note, this
 * should only be used as part of the GLDv3's interrupt blanking routines. The
 * debug build assertions are specific to that.
 */
void
i40e_intr_rx_queue_disable(i40e_t *i40e, uint_t queue)
{
	uint32_t reg;
	i40e_hw_t *hw = &i40e->i40e_hw_space;

	ASSERT(MUTEX_HELD(&i40e->i40e_general_lock));
	ASSERT(queue < i40e->i40e_num_trqpairs);

	reg = I40E_READ_REG(hw, I40E_QINT_RQCTL(queue));
	ASSERT3U(reg & I40E_QINT_RQCTL_CAUSE_ENA_MASK, ==,
	    I40E_QINT_RQCTL_CAUSE_ENA_MASK);
	reg &= ~I40E_QINT_RQCTL_CAUSE_ENA_MASK;
	I40E_WRITE_REG(hw, I40E_QINT_RQCTL(queue), reg);
}

/*
 * Start up the various chip's interrupt handling. We not only configure the
 * adminq here, but we also go through and configure all of the actual queues,
 * the interrupt linked lists, and others.
 */
void
i40e_intr_chip_init(i40e_t *i40e)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint32_t reg;

	/*
	 * Ensure that all non adminq interrupts are disabled at the chip level.
	 */
	i40e_intr_io_disable_all(i40e);

	I40E_WRITE_REG(hw, I40E_PFINT_ICR0_ENA, 0);
	(void) I40E_READ_REG(hw, I40E_PFINT_ICR0);

	/*
	 * Always enable all of the other-class interrupts to be on their own
	 * ITR. This only needs to be set on interrupt zero, which has its own
	 * special setting.
	 */
	reg = I40E_ITR_INDEX_OTHER << I40E_PFINT_STAT_CTL0_OTHER_ITR_INDX_SHIFT;
	I40E_WRITE_REG(hw, I40E_PFINT_STAT_CTL0, reg);

	/*
	 * Enable interrupt types we expect to receive. At the moment, this
	 * is limited to the adminq; however, we'll want to review 11.2.2.9.22
	 * for more types here as we add support for detecting them, handling
	 * them, and resetting the device as appropriate.
	 */
	reg = I40E_PFINT_ICR0_ENA_ADMINQ_MASK;
	I40E_WRITE_REG(hw, I40E_PFINT_ICR0_ENA, reg);

	/*
	 * Always set the interrupt linked list to empty. We'll come back and
	 * change this if MSI-X are actually on the scene.
	 */
	I40E_WRITE_REG(hw, I40E_PFINT_LNKLST0, I40E_QUEUE_TYPE_EOL);

	i40e_intr_adminq_enable(i40e);

	/*
	 * Set up all of the queues and map them to interrupts based on the bit
	 * assignments.
	 */
	if (i40e->i40e_intr_type == DDI_INTR_TYPE_MSIX) {
		i40e_intr_init_queue_msix(i40e);
	} else {
		i40e_intr_init_queue_shared(i40e);
	}

	/*
	 * Finally set all of the default ITRs for the interrupts. Note that the
	 * queues will have been set up above.
	 */
	i40e_intr_set_itr(i40e, I40E_ITR_INDEX_RX, i40e->i40e_rx_itr);
	i40e_intr_set_itr(i40e, I40E_ITR_INDEX_TX, i40e->i40e_tx_itr);
	i40e_intr_set_itr(i40e, I40E_ITR_INDEX_OTHER, i40e->i40e_other_itr);
}

static void
i40e_intr_adminq_work(i40e_t *i40e)
{
	struct i40e_hw *hw = &i40e->i40e_hw_space;
	struct i40e_arq_event_info evt;
	uint16_t remain = 1;

	bzero(&evt, sizeof (struct i40e_arq_event_info));
	evt.buf_len = I40E_ADMINQ_BUFSZ;
	evt.msg_buf = i40e->i40e_aqbuf;

	while (remain != 0) {
		enum i40e_status_code ret;
		uint16_t opcode;

		/*
		 * At the moment, the only error code that seems to be returned
		 * is one saying that there's no work. In such a case we leave
		 * this be.
		 */
		ret = i40e_clean_arq_element(hw, &evt, &remain);
		if (ret != I40E_SUCCESS)
			break;

		opcode = LE_16(evt.desc.opcode);
		switch (opcode) {
		case i40e_aqc_opc_get_link_status:
			mutex_enter(&i40e->i40e_general_lock);
			i40e_link_check(i40e);
			mutex_exit(&i40e->i40e_general_lock);
			break;
		default:
			/*
			 * Longer term we'll want to enable other causes here
			 * and get these cleaned up and doing something.
			 */
			break;
		}
	}
}

static void
i40e_intr_rx_work(i40e_t *i40e, int queue)
{
	mblk_t *mp = NULL;
	i40e_trqpair_t *itrq;

	ASSERT(queue < i40e->i40e_num_trqpairs);
	itrq = &i40e->i40e_trqpairs[queue];

	mutex_enter(&itrq->itrq_rx_lock);
	if (!itrq->itrq_intr_poll)
		mp = i40e_ring_rx(itrq, I40E_POLL_NULL);
	mutex_exit(&itrq->itrq_rx_lock);

	if (mp != NULL) {
		mac_rx_ring(i40e->i40e_mac_hdl, itrq->itrq_macrxring, mp,
		    itrq->itrq_rxgen);
	}
}

static void
i40e_intr_tx_work(i40e_t *i40e, int queue)
{
	i40e_trqpair_t *itrq;

	itrq = &i40e->i40e_trqpairs[queue];
	i40e_tx_recycle_ring(itrq);
}

/*
 * At the moment, the only 'other' interrupt on ICR0 that we handle is the
 * adminq. We should go through and support the other notifications at some
 * point.
 */
static void
i40e_intr_other_work(i40e_t *i40e)
{
	struct i40e_hw *hw = &i40e->i40e_hw_space;
	uint32_t reg;

	reg = I40E_READ_REG(hw, I40E_PFINT_ICR0);
	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_reg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&i40e->i40e_state, I40E_ERROR);
		return;
	}

	if (reg & I40E_PFINT_ICR0_ADMINQ_MASK)
		i40e_intr_adminq_work(i40e);

	/*
	 * Make sure that the adminq interrupt is not masked and then explicitly
	 * enable the adminq and thus the other interrupt.
	 */
	reg = I40E_READ_REG(hw, I40E_PFINT_ICR0_ENA);
	reg |= I40E_PFINT_ICR0_ENA_ADMINQ_MASK;
	I40E_WRITE_REG(hw, I40E_PFINT_ICR0_ENA, reg);

	i40e_intr_adminq_enable(i40e);
}

uint_t
i40e_intr_msix(void *arg1, void *arg2)
{
	i40e_t *i40e = (i40e_t *)arg1;
	int vector_idx = (int)(uintptr_t)arg2;

	/*
	 * When using MSI-X interrupts, vector 0 is always reserved for the
	 * adminq at this time. Though longer term, we'll want to also bridge
	 * some I/O to them.
	 */
	if (vector_idx == 0) {
		i40e_intr_other_work(i40e);
		return (DDI_INTR_CLAIMED);
	}

	i40e_intr_rx_work(i40e, vector_idx - 1);
	i40e_intr_tx_work(i40e, vector_idx - 1);
	i40e_intr_io_enable(i40e, vector_idx);

	return (DDI_INTR_CLAIMED);
}

static uint_t
i40e_intr_notx(i40e_t *i40e, boolean_t shared)
{
	i40e_hw_t *hw = &i40e->i40e_hw_space;
	uint32_t reg;
	int ret = DDI_INTR_CLAIMED;

	if (shared == B_TRUE) {
		mutex_enter(&i40e->i40e_general_lock);
		if (i40e->i40e_state & I40E_SUSPENDED) {
			mutex_exit(&i40e->i40e_general_lock);
			return (DDI_INTR_UNCLAIMED);
		}
		mutex_exit(&i40e->i40e_general_lock);
	}

	reg = I40E_READ_REG(hw, I40E_PFINT_ICR0);
	if (i40e_check_acc_handle(i40e->i40e_osdep_space.ios_reg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(i40e->i40e_dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&i40e->i40e_state, I40E_ERROR);
		return (DDI_INTR_CLAIMED);
	}

	if (reg == 0) {
		if (shared == B_TRUE)
			ret = DDI_INTR_UNCLAIMED;
		goto done;
	}

	if (reg & I40E_PFINT_ICR0_ADMINQ_MASK)
		i40e_intr_adminq_work(i40e);

	if (reg & I40E_INTR_NOTX_RX_MASK)
		i40e_intr_rx_work(i40e, 0);

	if (reg & I40E_INTR_NOTX_TX_MASK)
		i40e_intr_tx_work(i40e, 0);

done:
	i40e_intr_adminq_enable(i40e);
	return (ret);

}

/* ARGSUSED */
uint_t
i40e_intr_msi(void *arg1, void *arg2)
{
	i40e_t *i40e = (i40e_t *)arg1;

	return (i40e_intr_notx(i40e, B_FALSE));
}

/* ARGSUSED */
uint_t
i40e_intr_legacy(void *arg1, void *arg2)
{
	i40e_t *i40e = (i40e_t *)arg1;

	return (i40e_intr_notx(i40e, B_TRUE));
}
