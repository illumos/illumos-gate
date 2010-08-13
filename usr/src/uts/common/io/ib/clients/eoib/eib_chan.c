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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>

#include <sys/ib/clients/eoib/eib_impl.h>

eib_chan_t *
eib_chan_init(void)
{
	eib_chan_t *chan;

	/*
	 * Allocate a eib_chan_t to store stuff about admin qp and
	 * initialize some basic stuff
	 */
	chan = kmem_zalloc(sizeof (eib_chan_t), KM_SLEEP);

	mutex_init(&chan->ch_pkey_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->ch_cep_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->ch_tx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->ch_rx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->ch_vhub_lock, NULL, MUTEX_DRIVER, NULL);

	cv_init(&chan->ch_cep_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&chan->ch_tx_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&chan->ch_rx_cv, NULL, CV_DEFAULT, NULL);

	return (chan);
}

void
eib_chan_fini(eib_chan_t *chan)
{
	if (chan) {
		cv_destroy(&chan->ch_rx_cv);
		cv_destroy(&chan->ch_tx_cv);
		cv_destroy(&chan->ch_cep_cv);

		mutex_destroy(&chan->ch_vhub_lock);
		mutex_destroy(&chan->ch_rx_lock);
		mutex_destroy(&chan->ch_tx_lock);
		mutex_destroy(&chan->ch_cep_lock);
		mutex_destroy(&chan->ch_pkey_lock);

		kmem_free(chan, sizeof (eib_chan_t));
	}
}

int
eib_chan_post_rx(eib_t *ss, eib_chan_t *chan, uint_t *n_posted)
{
	eib_wqe_t *rwqes[EIB_RWR_CHUNK_SZ];
	ibt_status_t ret;
	uint_t n_got = 0;
	uint_t n_good = 0;
	uint_t limit = 0;
	uint_t room = 0;
	uint_t chunk_sz;
	int wndx;
	int i;

	/*
	 * We don't want to post beyond the maximum rwqe size for this channel
	 */
	room = chan->ch_max_rwqes - chan->ch_rx_posted;
	limit = (room > chan->ch_rwqe_bktsz) ? chan->ch_rwqe_bktsz : room;

	for (wndx = 0; wndx < limit; wndx += chunk_sz) {
		/*
		 * Grab a chunk of rwqes
		 */
		chunk_sz = ((limit - wndx) < EIB_RWR_CHUNK_SZ) ?
		    (limit - wndx) : EIB_RWR_CHUNK_SZ;

		/*
		 * When eib_chan_post_rx() is called to post a bunch of rwqes,
		 * it is either during the vnic setup or when we're refilling
		 * the data channel.  Neither situation is important enough for
		 * us to grab the wqes reserved for sending keepalives of
		 * previously established vnics.
		 */
		ret = eib_rsrc_grab_rwqes(ss, rwqes, chunk_sz, &n_got,
		    EIB_WPRI_LO);
		if (ret != EIB_E_SUCCESS)
			break;

		/*
		 * Post work requests from the rwqes we just grabbed
		 */
		for (i = 0; i < n_got; i++) {
			eib_wqe_t *rwqe = rwqes[i];

			ret = eib_chan_post_recv(ss, chan, rwqe);
			if (ret == EIB_E_SUCCESS) {
				n_good++;
			} else if (rwqe->qe_mp) {
				freemsg(rwqe->qe_mp);
			} else {
				eib_rsrc_return_rwqe(ss, rwqe, NULL);
			}
		}

		/*
		 * If we got less rwqes than we asked for during the grab
		 * earlier, we'll stop asking for more and quit now.
		 */
		if (n_got < chunk_sz)
			break;
	}

	/*
	 * If we posted absolutely nothing, we return failure; otherwise
	 * return success.
	 */
	if (n_good == 0)
		return (EIB_E_FAILURE);

	if (n_posted)
		*n_posted = n_good;

	return (EIB_E_SUCCESS);
}

/*ARGSUSED*/
int
eib_chan_post_recv(eib_t *ss, eib_chan_t *chan, eib_wqe_t *rwqe)
{
	ibt_status_t ret;
	uint8_t *mp_base;
	size_t mp_len;

	rwqe->qe_sgl.ds_va = (ib_vaddr_t)(uintptr_t)rwqe->qe_cpbuf;
	rwqe->qe_sgl.ds_len = rwqe->qe_bufsz;

	/*
	 * If this channel has receive buffer alignment restrictions, make
	 * sure the requirements are met
	 */
	if (chan->ch_ip_hdr_align) {
		rwqe->qe_sgl.ds_va += chan->ch_ip_hdr_align;
		rwqe->qe_sgl.ds_len -= chan->ch_ip_hdr_align;
	}

	/*
	 * If the receive buffer for this channel needs to have an mblk
	 * allocated, do it
	 */
	if (chan->ch_alloc_mp) {
		mp_base = (uint8_t *)(uintptr_t)(rwqe->qe_sgl.ds_va);
		mp_len = rwqe->qe_sgl.ds_len;

		rwqe->qe_mp = desballoc(mp_base, mp_len, 0, &rwqe->qe_frp);
		if (rwqe->qe_mp == NULL) {
			EIB_DPRINTF_ERR(ss->ei_instance, "eib_chan_post_recv: "
			    "desballoc(base=0x%llx, len=0x%llx) failed",
			    mp_base, mp_len);
			return (EIB_E_FAILURE);
		}
	}

	/*
	 * Check if the recv queue is already full or if we can post one more
	 */
	mutex_enter(&chan->ch_rx_lock);
	if (chan->ch_rx_posted > (chan->ch_max_rwqes - 1)) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_chan_post_recv: "
		    "too many rwqes posted already, posted=0x%lx, max=0x%lx",
		    chan->ch_rx_posted, chan->ch_max_rwqes);
		mutex_exit(&chan->ch_rx_lock);
		return (EIB_E_FAILURE);
	}

	rwqe->qe_vnic_inst = chan->ch_vnic_inst;
	rwqe->qe_chan = chan;
	rwqe->qe_info |= EIB_WQE_FLG_POSTED_TO_HCA;

	ret = ibt_post_recv(chan->ch_chan, &(rwqe->qe_wr.recv), 1, NULL);
	if (ret != IBT_SUCCESS) {
		EIB_DPRINTF_ERR(ss->ei_instance, "eib_chan_post_recv: "
		    "ibt_post_recv() failed, ret=%d", ret);
		mutex_exit(&chan->ch_rx_lock);
		return (EIB_E_FAILURE);
	}
	chan->ch_rx_posted++;
	mutex_exit(&chan->ch_rx_lock);

	return (EIB_E_SUCCESS);
}
