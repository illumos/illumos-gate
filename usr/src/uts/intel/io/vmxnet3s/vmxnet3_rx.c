/*
 * Copyright (C) 2007 VMware, Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common
 * Development and Distribution License (the "License") version 1.0
 * and no later version.  You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 *         http://www.opensource.org/licenses/cddl1.php
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */
/*
 * Copyright (c) 2013, 2016 by Delphix. All rights reserved.
 */

#include <vmxnet3.h>

static void vmxnet3_put_rxbuf(vmxnet3_rxbuf_t *);

/*
 * Allocate a new rxBuf from memory. All its fields are set except
 * for its associated mblk which has to be allocated later.
 *
 * Returns:
 *	A new rxBuf or NULL.
 */
static vmxnet3_rxbuf_t *
vmxnet3_alloc_rxbuf(vmxnet3_softc_t *dp, boolean_t canSleep)
{
	vmxnet3_rxbuf_t *rxBuf;
	int flag = canSleep ? KM_SLEEP : KM_NOSLEEP;
	int err;

	rxBuf = kmem_zalloc(sizeof (vmxnet3_rxbuf_t), flag);
	if (!rxBuf) {
		atomic_inc_32(&dp->rx_alloc_failed);
		return (NULL);
	}

	if ((err = vmxnet3_alloc_dma_mem_1(dp, &rxBuf->dma, (dp->cur_mtu + 18),
	    canSleep)) != 0) {
		VMXNET3_DEBUG(dp, 0, "Failed to allocate %d bytes for rx buf, "
		    "err:%d\n", (dp->cur_mtu + 18), err);
		kmem_free(rxBuf, sizeof (vmxnet3_rxbuf_t));
		atomic_inc_32(&dp->rx_alloc_failed);
		return (NULL);
	}

	rxBuf->freeCB.free_func = vmxnet3_put_rxbuf;
	rxBuf->freeCB.free_arg = (caddr_t)rxBuf;
	rxBuf->dp = dp;

	atomic_inc_32(&dp->rx_num_bufs);
	atomic_inc_32(&dp->rx_alloc_buf);
	return (rxBuf);
}

static void
vmxnet3_free_rxbuf(vmxnet3_softc_t *dp, vmxnet3_rxbuf_t *rxBuf)
{
	vmxnet3_free_dma_mem(&rxBuf->dma);
	kmem_free(rxBuf, sizeof (vmxnet3_rxbuf_t));

#ifndef	DEBUG
	atomic_dec_32(&dp->rx_num_bufs);
#else
	{
		uint32_t nv = atomic_dec_32_nv(&dp->rx_num_bufs);
		ASSERT(nv != (uint32_t)-1);
	}
#endif
}

/*
 * Return a rxBuf to the pool. The init argument, when B_TRUE, indicates
 * that we're being called for the purpose of pool initialization, and
 * therefore, we should place the buffer in the pool even if the device
 * isn't enabled.
 *
 * Returns:
 *	B_TRUE if the buffer was returned to the pool, or B_FALSE if it
 *	wasn't (e.g. if the device is stopped).
 */
static boolean_t
vmxnet3_put_rxpool_buf(vmxnet3_softc_t *dp, vmxnet3_rxbuf_t *rxBuf,
    boolean_t init)
{
	vmxnet3_rxpool_t *rxPool = &dp->rxPool;
	boolean_t returned = B_FALSE;

	mutex_enter(&dp->rxPoolLock);
	ASSERT(rxPool->nBufs <= rxPool->nBufsLimit);
	if ((dp->devEnabled || init) && rxPool->nBufs < rxPool->nBufsLimit) {
		ASSERT((rxPool->listHead == NULL && rxPool->nBufs == 0) ||
		    (rxPool->listHead != NULL && rxPool->nBufs != 0));
		rxBuf->next = rxPool->listHead;
		rxPool->listHead = rxBuf;
		rxPool->nBufs++;
		returned = B_TRUE;
	}
	mutex_exit(&dp->rxPoolLock);
	return (returned);
}

/*
 * Return a rxBuf to the pool or free it.
 */
static void
vmxnet3_put_rxbuf(vmxnet3_rxbuf_t *rxBuf)
{
	vmxnet3_softc_t *dp = rxBuf->dp;

	if (!vmxnet3_put_rxpool_buf(dp, rxBuf, B_FALSE))
		vmxnet3_free_rxbuf(dp, rxBuf);
}

/*
 * Get an unused rxBuf from the pool.
 *
 * Returns:
 *	A rxBuf or NULL if there are no buffers in the pool.
 */
static vmxnet3_rxbuf_t *
vmxnet3_get_rxpool_buf(vmxnet3_softc_t *dp)
{
	vmxnet3_rxpool_t *rxPool = &dp->rxPool;
	vmxnet3_rxbuf_t *rxBuf = NULL;

	mutex_enter(&dp->rxPoolLock);
	if (rxPool->listHead != NULL) {
		rxBuf = rxPool->listHead;
		rxPool->listHead = rxBuf->next;
		rxPool->nBufs--;
		ASSERT((rxPool->listHead == NULL && rxPool->nBufs == 0) ||
		    (rxPool->listHead != NULL && rxPool->nBufs != 0));
	}
	mutex_exit(&dp->rxPoolLock);
	return (rxBuf);
}

/*
 * Fill a rxPool by allocating the maximum number of buffers.
 *
 * Returns:
 *	0 on success, non-zero on failure.
 */
static int
vmxnet3_rxpool_init(vmxnet3_softc_t *dp)
{
	int err = 0;
	vmxnet3_rxbuf_t *rxBuf;

	ASSERT(dp->rxPool.nBufsLimit > 0);
	while (dp->rxPool.nBufs < dp->rxPool.nBufsLimit) {
		if ((rxBuf = vmxnet3_alloc_rxbuf(dp, B_FALSE)) == NULL) {
			err = ENOMEM;
			break;
		}
		VERIFY(vmxnet3_put_rxpool_buf(dp, rxBuf, B_TRUE));
	}

	if (err != 0) {
		while ((rxBuf = vmxnet3_get_rxpool_buf(dp)) != NULL) {
			vmxnet3_free_rxbuf(dp, rxBuf);
		}
	}

	return (err);
}

/*
 * Populate a Rx descriptor with a new rxBuf. If the pool argument is B_TRUE,
 * then try to take a buffer from rxPool. If the pool is empty and the
 * dp->alloc_ok is true, then fall back to dynamic allocation. If pool is
 * B_FALSE, then always allocate a new buffer (this is only used when
 * populating the initial set of buffers in the receive queue during start).
 *
 * Returns:
 *	0 on success, non-zero on failure.
 */
static int
vmxnet3_rx_populate(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq, uint16_t idx,
    boolean_t canSleep, boolean_t pool)
{
	vmxnet3_rxbuf_t *rxBuf = NULL;

	if (pool && (rxBuf = vmxnet3_get_rxpool_buf(dp)) == NULL) {
		/* The maximum number of pool buffers have been allocated. */
		atomic_inc_32(&dp->rx_pool_empty);
		if (!dp->alloc_ok) {
			atomic_inc_32(&dp->rx_alloc_failed);
		}
	}

	if (rxBuf == NULL && (!pool || dp->alloc_ok)) {
		rxBuf = vmxnet3_alloc_rxbuf(dp, canSleep);
	}

	if (rxBuf != NULL) {
		rxBuf->mblk = desballoc((uchar_t *)rxBuf->dma.buf,
		    rxBuf->dma.bufLen, BPRI_MED, &rxBuf->freeCB);
		if (rxBuf->mblk == NULL) {
			if (pool) {
				VERIFY(vmxnet3_put_rxpool_buf(dp, rxBuf,
				    B_FALSE));
			} else {
				vmxnet3_free_rxbuf(dp, rxBuf);
			}
			atomic_inc_32(&dp->rx_alloc_failed);
			return (ENOMEM);
		}

		vmxnet3_cmdring_t *cmdRing = &rxq->cmdRing;
		Vmxnet3_GenericDesc *rxDesc = VMXNET3_GET_DESC(cmdRing, idx);

		rxq->bufRing[idx].rxBuf = rxBuf;
		rxDesc->rxd.addr = rxBuf->dma.bufPA;
		rxDesc->rxd.len = rxBuf->dma.bufLen;
		/* rxDesc->rxd.btype = 0; */
		membar_producer();
		rxDesc->rxd.gen = cmdRing->gen;
	} else {
		return (ENOMEM);
	}

	return (0);
}

/*
 * Initialize a RxQueue by populating the whole Rx ring with rxBufs.
 *
 * Returns:
 *	0 on success, non-zero on failure.
 */
int
vmxnet3_rxqueue_init(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_cmdring_t *cmdRing = &rxq->cmdRing;
	int err;

	dp->rxPool.nBufsLimit = vmxnet3_getprop(dp, "RxBufPoolLimit", 0,
	    cmdRing->size * 10, cmdRing->size * 2);

	do {
		if ((err = vmxnet3_rx_populate(dp, rxq, cmdRing->next2fill,
		    B_TRUE, B_FALSE)) != 0) {
			goto error;
		}
		VMXNET3_INC_RING_IDX(cmdRing, cmdRing->next2fill);
	} while (cmdRing->next2fill);

	/*
	 * Pre-allocate rxPool buffers so that we never have to allocate
	 * new buffers from interrupt context when we need to replace a buffer
	 * in the rxqueue.
	 */
	if ((err = vmxnet3_rxpool_init(dp)) != 0) {
		goto error;
	}

	return (0);

error:
	while (cmdRing->next2fill) {
		VMXNET3_DEC_RING_IDX(cmdRing, cmdRing->next2fill);
		vmxnet3_free_rxbuf(dp, rxq->bufRing[cmdRing->next2fill].rxBuf);
	}

	return (err);
}

/*
 * Finish a RxQueue by freeing all the related rxBufs.
 */
void
vmxnet3_rxqueue_fini(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_rxbuf_t *rxBuf;
	unsigned int i;

	ASSERT(!dp->devEnabled);

	/* First the rxPool */
	while ((rxBuf = vmxnet3_get_rxpool_buf(dp)))
		vmxnet3_free_rxbuf(dp, rxBuf);

	/* Then the ring */
	for (i = 0; i < rxq->cmdRing.size; i++) {
		rxBuf = rxq->bufRing[i].rxBuf;
		ASSERT(rxBuf);
		ASSERT(rxBuf->mblk);
		/*
		 * Here, freemsg() will trigger a call to vmxnet3_put_rxbuf()
		 * which will then call vmxnet3_free_rxbuf() because the
		 * underlying device is disabled.
		 */
		freemsg(rxBuf->mblk);
	}
}

/*
 * Determine if a received packet was checksummed by the Vmxnet3
 * device and tag the mp appropriately.
 */
static void
vmxnet3_rx_hwcksum(vmxnet3_softc_t *dp, mblk_t *mp,
    Vmxnet3_GenericDesc *compDesc)
{
	uint32_t flags = 0;

	if (!compDesc->rcd.cnc) {
		if (compDesc->rcd.v4 && compDesc->rcd.ipc) {
			flags |= HCK_IPV4_HDRCKSUM;
			if ((compDesc->rcd.tcp || compDesc->rcd.udp) &&
			    compDesc->rcd.tuc) {
				flags |= HCK_FULLCKSUM | HCK_FULLCKSUM_OK;
			}
		}

		VMXNET3_DEBUG(dp, 3, "rx cksum flags = 0x%x\n", flags);

		(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0, flags, 0);
	}
}

/*
 * Interrupt handler for Rx. Look if there are any pending Rx and
 * put them in mplist.
 *
 * Returns:
 *	A list of messages to pass to the MAC subystem.
 */
mblk_t *
vmxnet3_rx_intr(vmxnet3_softc_t *dp, vmxnet3_rxqueue_t *rxq)
{
	vmxnet3_compring_t *compRing = &rxq->compRing;
	vmxnet3_cmdring_t *cmdRing = &rxq->cmdRing;
	Vmxnet3_RxQueueCtrl *rxqCtrl = rxq->sharedCtrl;
	Vmxnet3_GenericDesc *compDesc;
	mblk_t *mplist = NULL, **mplistTail = &mplist;

	ASSERT(mutex_owned(&dp->intrLock));

	compDesc = VMXNET3_GET_DESC(compRing, compRing->next2comp);
	while (compDesc->rcd.gen == compRing->gen) {
		mblk_t *mp = NULL, **mpTail = &mp;
		boolean_t mpValid = B_TRUE;
		boolean_t eop;

		ASSERT(compDesc->rcd.sop);

		do {
			uint16_t rxdIdx = compDesc->rcd.rxdIdx;
			vmxnet3_rxbuf_t *rxBuf = rxq->bufRing[rxdIdx].rxBuf;
			mblk_t *mblk = rxBuf->mblk;
			Vmxnet3_GenericDesc *rxDesc;

			while (compDesc->rcd.gen != compRing->gen) {
				/*
				 * H/W may be still be in the middle of
				 * generating this entry, so hold on until
				 * the gen bit is flipped.
				 */
				membar_consumer();
			}
			ASSERT(compDesc->rcd.gen == compRing->gen);
			ASSERT(rxBuf);
			ASSERT(mblk);

			/* Some Rx descriptors may have been skipped */
			while (cmdRing->next2fill != rxdIdx) {
				rxDesc = VMXNET3_GET_DESC(cmdRing,
				    cmdRing->next2fill);
				rxDesc->rxd.gen = cmdRing->gen;
				VMXNET3_INC_RING_IDX(cmdRing,
				    cmdRing->next2fill);
			}

			eop = compDesc->rcd.eop;

			/*
			 * Now we have a piece of the packet in the rxdIdx
			 * descriptor. Grab it only if we achieve to replace
			 * it with a fresh buffer.
			 */
			if (vmxnet3_rx_populate(dp, rxq, rxdIdx, B_FALSE,
			    B_TRUE) == 0) {
				/* Success, we can chain the mblk with the mp */
				mblk->b_wptr = mblk->b_rptr + compDesc->rcd.len;
				*mpTail = mblk;
				mpTail = &mblk->b_cont;
				ASSERT(*mpTail == NULL);

				VMXNET3_DEBUG(dp, 3, "rx 0x%p on [%u]\n",
				    (void *)mblk, rxdIdx);

				if (eop) {
					if (!compDesc->rcd.err) {
						/*
						 * Tag the mp if it was
						 * checksummed by the H/W
						 */
						vmxnet3_rx_hwcksum(dp, mp,
						    compDesc);
					} else {
						mpValid = B_FALSE;
					}
				}
			} else {
				/*
				 * Keep the same buffer, we still need
				 * to flip the gen bit
				 */
				rxDesc = VMXNET3_GET_DESC(cmdRing, rxdIdx);
				rxDesc->rxd.gen = cmdRing->gen;
				mpValid = B_FALSE;
			}

			VMXNET3_INC_RING_IDX(compRing, compRing->next2comp);
			VMXNET3_INC_RING_IDX(cmdRing, cmdRing->next2fill);
			compDesc = VMXNET3_GET_DESC(compRing,
			    compRing->next2comp);
		} while (!eop);

		if (mp) {
			if (mpValid) {
				*mplistTail = mp;
				mplistTail = &mp->b_next;
				ASSERT(*mplistTail == NULL);
			} else {
				/* This message got holes, drop it */
				freemsg(mp);
			}
		}
	}

	if (rxqCtrl->updateRxProd) {
		uint32_t rxprod;

		/*
		 * All buffers are actually available, but we can't tell that to
		 * the device because it may interpret that as an empty ring.
		 * So skip one buffer.
		 */
		if (cmdRing->next2fill) {
			rxprod = cmdRing->next2fill - 1;
		} else {
			rxprod = cmdRing->size - 1;
		}
		VMXNET3_BAR0_PUT32(dp, VMXNET3_REG_RXPROD, rxprod);
	}

	return (mplist);
}
