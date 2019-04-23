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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
/*
 * Sun elects to include this software in Sun product
 * under the OpenIB BSD license.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/ib/clients/rds/rdsib_cm.h>
#include <sys/ib/clients/rds/rdsib_ib.h>
#include <sys/ib/clients/rds/rdsib_buf.h>
#include <sys/ib/clients/rds/rdsib_ep.h>
#include <sys/ib/clients/rds/rds_kstat.h>

/*
 * This File contains the buffer management code
 */

#define	DUMP_USER_PARAMS()	\
	RDS_DPRINTF3(LABEL, "MaxNodes = %d", MaxNodes); \
	RDS_DPRINTF3(LABEL, "UserBufferSize = %d", UserBufferSize); \
	RDS_DPRINTF3(LABEL, "RdsPktSize = %d", RdsPktSize); \
	RDS_DPRINTF3(LABEL, "MaxDataSendBuffers = %d", MaxDataSendBuffers); \
	RDS_DPRINTF3(LABEL, "MaxDataRecvBuffers = %d", MaxDataRecvBuffers); \
	RDS_DPRINTF3(LABEL, "MaxCtrlSendBuffers = %d", MaxCtrlSendBuffers); \
	RDS_DPRINTF3(LABEL, "MaxCtrlRecvBuffers = %d", MaxCtrlRecvBuffers); \
	RDS_DPRINTF3(LABEL, "DataRecvBufferLWM = %d", DataRecvBufferLWM); \
	RDS_DPRINTF3(LABEL, "PendingRxPktsHWM = %d", PendingRxPktsHWM); \
	RDS_DPRINTF3(LABEL, "MinRnrRetry = %d", MinRnrRetry)

uint_t	rds_nbuffers_to_putback;

static void
rds_free_mblk(char *arg)
{
	rds_buf_t *bp = (rds_buf_t *)(uintptr_t)arg;

	/* Free the recv buffer */
	RDS_DPRINTF4("rds_free_mblk", "Enter: BP(%p)", bp);
	ASSERT(bp->buf_state == RDS_RCVBUF_ONSOCKQ);
	rds_free_recv_buf(bp, 1);
	RDS_DECR_RXPKTS_PEND(1);
	RDS_DPRINTF4("rds_free_mblk", "Return: BP(%p)", bp);
}

void
rds_free_recv_caches(rds_state_t *statep)
{
	rds_hca_t	*hcap;
	int		ret;

	RDS_DPRINTF4("rds_free_recv_caches", "Enter");

	mutex_enter(&rds_dpool.pool_lock);
	if (rds_dpool.pool_memp == NULL) {
		RDS_DPRINTF2("rds_free_recv_caches", "Caches are empty");
		mutex_exit(&rds_dpool.pool_lock);
		return;
	}

	/*
	 * All buffers must have been freed as all sessions are closed
	 * and destroyed
	 */
	ASSERT(rds_dpool.pool_nbusy == 0);
	RDS_DPRINTF2("rds_free_recv_caches", "Data Pool has "
	    "pending buffers: %d", rds_dpool.pool_nbusy);
	while (rds_dpool.pool_nbusy != 0) {
		mutex_exit(&rds_dpool.pool_lock);
		delay(drv_usectohz(1000000));
		mutex_enter(&rds_dpool.pool_lock);
	}

	hcap = statep->rds_hcalistp;
	while (hcap != NULL) {
		if (hcap->hca_mrhdl != NULL) {
			ret = ibt_deregister_mr(hcap->hca_hdl,
			    hcap->hca_mrhdl);
			if (ret == IBT_SUCCESS) {
				hcap->hca_mrhdl = NULL;
				hcap->hca_lkey = 0;
				hcap->hca_rkey = 0;
			} else {
				RDS_DPRINTF2(LABEL, "ibt_deregister_mr "
				    "failed: %d, mrhdl: 0x%p", ret,
				    hcap->hca_mrhdl);
			}
		}
		hcap = hcap->hca_nextp;
	}

	kmem_free(rds_dpool.pool_bufmemp, (rds_dpool.pool_nbuffers +
	    rds_cpool.pool_nbuffers) * sizeof (rds_buf_t));
	rds_dpool.pool_bufmemp = NULL;

	kmem_free(rds_dpool.pool_memp, rds_dpool.pool_memsize);
	rds_dpool.pool_memp = NULL;

	mutex_exit(&rds_dpool.pool_lock);

	RDS_DPRINTF4("rds_free_recv_caches", "Return");
}

int
rds_init_recv_caches(rds_state_t *statep)
{
	uint8_t		*mp;
	rds_buf_t	*bp;
	rds_hca_t	*hcap;
	uint32_t	nsessions;
	uint_t		ix;
	uint_t		nctrlrx;
	uint8_t		*memp;
	uint_t		memsize, nbuf;
	rds_buf_t	*bufmemp;
	ibt_mr_attr_t	mem_attr;
	ibt_mr_desc_t	mem_desc;
	int		ret;

	RDS_DPRINTF4("rds_init_recv_caches", "Enter");

	DUMP_USER_PARAMS();

	mutex_enter(&rds_dpool.pool_lock);
	if (rds_dpool.pool_memp != NULL) {
		RDS_DPRINTF2("rds_init_recv_caches", "Pools are already "
		    "initialized");
		mutex_exit(&rds_dpool.pool_lock);
		return (0);
	}

	/*
	 * High water mark for the receive buffers in the system. If the
	 * number of buffers used crosses this mark then all sockets in
	 * would be stalled. The port quota for the sockets is set based
	 * on this limit.
	 */
	rds_rx_pkts_pending_hwm = (PendingRxPktsHWM * NDataRX)/100;

	rds_nbuffers_to_putback = min(MaxCtrlRecvBuffers, MaxDataRecvBuffers);

	/* nsessions can never be less than 1 */
	nsessions = MaxNodes - 1;
	nctrlrx = (nsessions + 1) * MaxCtrlRecvBuffers * 2;

	RDS_DPRINTF3(LABEL, "Number of Possible Sessions: %d", nsessions);

	/* Add the hdr */
	RdsPktSize = UserBufferSize + RDS_DATA_HDR_SZ;

	memsize = (NDataRX * RdsPktSize) + (nctrlrx * RDS_CTRLPKT_SIZE);
	nbuf = NDataRX + nctrlrx;
	RDS_DPRINTF3(LABEL, "RDS Buffer Pool Memory: %lld", memsize);
	RDS_DPRINTF3(LABEL, "Total Buffers: %d", nbuf);

	memp = (uint8_t *)kmem_zalloc(memsize, KM_NOSLEEP);
	if (memp == NULL) {
		RDS_DPRINTF1(LABEL, "RDS Memory allocation failed");
		mutex_exit(&rds_dpool.pool_lock);
		return (-1);
	}

	RDS_DPRINTF3(LABEL, "RDS Buffer Entries Memory: %lld",
	    nbuf * sizeof (rds_buf_t));

	/* allocate memory for buffer entries */
	bufmemp = (rds_buf_t *)kmem_zalloc(nbuf * sizeof (rds_buf_t),
	    KM_SLEEP);

	/* register the memory with all HCAs */
	mem_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)memp;
	mem_attr.mr_len = memsize;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_ENABLE_LOCAL_WRITE;

	rw_enter(&statep->rds_hca_lock, RW_WRITER);

	hcap = statep->rds_hcalistp;
	while (hcap != NULL) {
		if (hcap->hca_state != RDS_HCA_STATE_OPEN) {
			hcap = hcap->hca_nextp;
			continue;
		}

		ret = ibt_register_mr(hcap->hca_hdl, hcap->hca_pdhdl,
		    &mem_attr, &hcap->hca_mrhdl, &mem_desc);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL, "ibt_register_mr failed: %d", ret);
			hcap = statep->rds_hcalistp;
			while ((hcap) && (hcap->hca_mrhdl != NULL)) {
				ret = ibt_deregister_mr(hcap->hca_hdl,
				    hcap->hca_mrhdl);
				if (ret == IBT_SUCCESS) {
					hcap->hca_mrhdl = NULL;
					hcap->hca_lkey = 0;
					hcap->hca_rkey = 0;
				} else {
					RDS_DPRINTF2(LABEL, "ibt_deregister_mr "
					    "failed: %d, mrhdl: 0x%p", ret,
					    hcap->hca_mrhdl);
				}
				hcap = hcap->hca_nextp;
			}
			kmem_free(bufmemp, nbuf * sizeof (rds_buf_t));
			kmem_free(memp, memsize);
			rw_exit(&statep->rds_hca_lock);
			mutex_exit(&rds_dpool.pool_lock);
			return (-1);
		}

		hcap->hca_state = RDS_HCA_STATE_MEM_REGISTERED;
		hcap->hca_lkey = mem_desc.md_lkey;
		hcap->hca_rkey = mem_desc.md_rkey;

		hcap = hcap->hca_nextp;
	}
	rw_exit(&statep->rds_hca_lock);

	/* Initialize data pool */
	rds_dpool.pool_memp = memp;
	rds_dpool.pool_memsize = memsize;
	rds_dpool.pool_bufmemp = bufmemp;
	rds_dpool.pool_nbuffers = NDataRX;
	rds_dpool.pool_nbusy = 0;
	rds_dpool.pool_nfree = NDataRX;

	/* chain the buffers */
	mp = memp;
	bp = bufmemp;
	for (ix = 0; ix < NDataRX; ix++) {
		bp[ix].buf_nextp = &bp[ix + 1];
		bp[ix].buf_ds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
		bp[ix].buf_state = RDS_RCVBUF_FREE;
		bp[ix].buf_frtn.free_func = rds_free_mblk;
		bp[ix].buf_frtn.free_arg = (char *)&bp[ix];
		mp = mp + RdsPktSize;
	}
	bp[NDataRX - 1].buf_nextp = NULL;
	rds_dpool.pool_headp = &bp[0];
	rds_dpool.pool_tailp = &bp[NDataRX - 1];

	/* Initialize ctrl pool */
	rds_cpool.pool_nbuffers = nctrlrx;
	rds_cpool.pool_nbusy = 0;
	rds_cpool.pool_nfree = nctrlrx;

	/* chain the buffers */
	for (ix = NDataRX; ix < nbuf - 1; ix++) {
		bp[ix].buf_nextp = &bp[ix + 1];
		bp[ix].buf_ds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
		mp = mp + RDS_CTRLPKT_SIZE;
	}
	bp[nbuf - 1].buf_ds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
	bp[nbuf - 1].buf_nextp = NULL;
	rds_cpool.pool_headp = &bp[NDataRX];
	rds_cpool.pool_tailp = &bp[nbuf - 1];

	mutex_exit(&rds_dpool.pool_lock);

	RDS_DPRINTF3(LABEL, "rdsmemp start: %p end: %p", memp, mp);
	RDS_DPRINTF4("rds_init_recv_caches", "Return");
	return (0);
}

rds_hca_t *rds_lkup_hca(ib_guid_t hca_guid);

void
rds_free_send_pool(rds_ep_t *ep)
{
	rds_bufpool_t   *pool;
	rds_hca_t	*hcap;
	int		ret;

	pool = &ep->ep_sndpool;

	mutex_enter(&pool->pool_lock);
	if (pool->pool_memp == NULL) {
		mutex_exit(&pool->pool_lock);
		RDS_DPRINTF2("rds_free_send_pool",
		    "EP(%p) DOUBLE Free on Send Pool", ep);
		return;
	}

	/* get the hcap for the HCA hosting this channel */
	hcap = rds_lkup_hca(ep->ep_hca_guid);
	if (hcap == NULL) {
		RDS_DPRINTF2("rds_free_send_pool", "HCA (0x%llx) not found",
		    ep->ep_hca_guid);
	} else {
		ret = ibt_deregister_mr(hcap->hca_hdl, ep->ep_snd_mrhdl);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2(LABEL,
			    "ibt_deregister_mr failed: %d, mrhdl: 0x%p",
			    ret, ep->ep_snd_mrhdl);
		}

		if (ep->ep_ack_addr) {
			ret = ibt_deregister_mr(hcap->hca_hdl, ep->ep_ackhdl);
			if (ret != IBT_SUCCESS) {
				RDS_DPRINTF2(LABEL,
				    "ibt_deregister_mr ackhdl failed: %d, "
				    "mrhdl: 0x%p", ret, ep->ep_ackhdl);
			}

			kmem_free((void *)ep->ep_ack_addr, sizeof (uintptr_t));
			ep->ep_ack_addr = (uintptr_t)NULL;
		}
	}

	kmem_free(pool->pool_memp, pool->pool_memsize);
	kmem_free(pool->pool_bufmemp,
	    pool->pool_nbuffers * sizeof (rds_buf_t));
	pool->pool_memp = NULL;
	pool->pool_bufmemp = NULL;
	mutex_exit(&pool->pool_lock);
}

int
rds_init_send_pool(rds_ep_t *ep, ib_guid_t hca_guid)
{
	uint8_t		*mp;
	rds_buf_t	*bp;
	rds_hca_t	*hcap;
	uint_t		ix, rcv_len;
	ibt_mr_attr_t   mem_attr;
	ibt_mr_desc_t   mem_desc;
	uint8_t		*memp;
	rds_buf_t	*bufmemp;
	uintptr_t	ack_addr = (uintptr_t)NULL;
	uint_t		memsize;
	uint_t		nbuf;
	rds_bufpool_t   *spool;
	rds_data_hdr_t	*pktp;
	int		ret;

	RDS_DPRINTF2("rds_init_send_pool", "Enter");

	spool = &ep->ep_sndpool;

	ASSERT(spool->pool_memp == NULL);
	ASSERT(ep->ep_hca_guid == 0);

	/* get the hcap for the HCA hosting this channel */
	hcap = rds_get_hcap(rdsib_statep, hca_guid);
	if (hcap == NULL) {
		RDS_DPRINTF2("rds_init_send_pool", "HCA (0x%llx) not found",
		    hca_guid);
		return (-1);
	}

	if (ep->ep_type == RDS_EP_TYPE_DATA) {
		spool->pool_nbuffers = MaxDataSendBuffers;
		spool->pool_nbusy = 0;
		spool->pool_nfree = MaxDataSendBuffers;
		memsize = (MaxDataSendBuffers * RdsPktSize) +
		    sizeof (uintptr_t);
		rcv_len = RdsPktSize;
	} else {
		spool->pool_nbuffers = MaxCtrlSendBuffers;
		spool->pool_nbusy = 0;
		spool->pool_nfree = MaxCtrlSendBuffers;
		memsize = MaxCtrlSendBuffers * RDS_CTRLPKT_SIZE;
		rcv_len = RDS_CTRLPKT_SIZE;
	}
	nbuf = spool->pool_nbuffers;

	RDS_DPRINTF3(LABEL, "RDS Send Pool Memory: %lld", memsize);

	memp = (uint8_t *)kmem_zalloc(memsize, KM_NOSLEEP);
	if (memp == NULL) {
		RDS_DPRINTF1(LABEL, "RDS Send Memory allocation failed");
		return (-1);
	}

	RDS_DPRINTF3(LABEL, "RDS Buffer Entries Memory: %lld",
	    nbuf * sizeof (rds_buf_t));

	/* allocate memory for buffer entries */
	bufmemp = (rds_buf_t *)kmem_zalloc(nbuf * sizeof (rds_buf_t),
	    KM_SLEEP);

	if (ep->ep_type == RDS_EP_TYPE_DATA) {
		ack_addr = (uintptr_t)kmem_zalloc(sizeof (uintptr_t), KM_SLEEP);

		/* register the memory with the HCA for this channel */
		mem_attr.mr_vaddr = (ib_vaddr_t)ack_addr;
		mem_attr.mr_len = sizeof (uintptr_t);
		mem_attr.mr_as = NULL;
		mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE |
		    IBT_MR_ENABLE_REMOTE_WRITE;

		ret = ibt_register_mr(hcap->hca_hdl, hcap->hca_pdhdl,
		    &mem_attr, &ep->ep_ackhdl, &mem_desc);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2("rds_init_send_pool",
			    "EP(%p): ibt_register_mr for ack failed: %d",
			    ep, ret);
			kmem_free(memp, memsize);
			kmem_free(bufmemp, nbuf * sizeof (rds_buf_t));
			kmem_free((void *)ack_addr, sizeof (uintptr_t));
			return (-1);
		}
		ep->ep_ack_rkey = mem_desc.md_rkey;
		ep->ep_ack_addr = ack_addr;
	}

	/* register the memory with the HCA for this channel */
	mem_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)memp;
	mem_attr.mr_len = memsize;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;

	ret = ibt_register_mr(hcap->hca_hdl, hcap->hca_pdhdl,
	    &mem_attr, &ep->ep_snd_mrhdl, &mem_desc);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2("rds_init_send_pool", "EP(%p): ibt_register_mr "
		    "failed: %d", ep, ret);
		kmem_free(memp, memsize);
		kmem_free(bufmemp, nbuf * sizeof (rds_buf_t));
		if (ack_addr != (uintptr_t)NULL)
			kmem_free((void *)ack_addr, sizeof (uintptr_t));
		return (-1);
	}
	ep->ep_snd_lkey = mem_desc.md_lkey;


	/* Initialize the pool */
	spool->pool_memp = memp;
	spool->pool_memsize = memsize;
	spool->pool_bufmemp = bufmemp;
	spool->pool_sqpoll_pending = B_FALSE;

	/* chain the buffers and initialize them */
	mp = memp;
	bp = bufmemp;

	if (ep->ep_type == RDS_EP_TYPE_DATA) {
		for (ix = 0; ix < nbuf - 1; ix++) {
			bp[ix].buf_nextp = &bp[ix + 1];
			bp[ix].buf_ep = ep;
			bp[ix].buf_ds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
			bp[ix].buf_ds.ds_key = ep->ep_snd_lkey;
			bp[ix].buf_state = RDS_SNDBUF_FREE;
			pktp = (rds_data_hdr_t *)(uintptr_t)mp;
			pktp->dh_bufid = (uintptr_t)&bp[ix];
			mp = mp + rcv_len;
		}
		bp[nbuf - 1].buf_nextp = NULL;
		bp[nbuf - 1].buf_ep = ep;
		bp[nbuf - 1].buf_ds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
		bp[nbuf - 1].buf_ds.ds_key = ep->ep_snd_lkey;
		bp[nbuf - 1].buf_state = RDS_SNDBUF_FREE;
		pktp = (rds_data_hdr_t *)(uintptr_t)mp;
		pktp->dh_bufid = (uintptr_t)&bp[nbuf - 1];

		spool->pool_headp = &bp[0];
		spool->pool_tailp = &bp[nbuf - 1];

		mp = mp + rcv_len;
		ep->ep_ackds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
		ep->ep_ackds.ds_key = ep->ep_snd_lkey;
		ep->ep_ackds.ds_len = sizeof (uintptr_t);

		*(uintptr_t *)ep->ep_ack_addr = (uintptr_t)spool->pool_tailp;
	} else {
		/* control send pool */
		for (ix = 0; ix < nbuf - 1; ix++) {
			bp[ix].buf_nextp = &bp[ix + 1];
			bp[ix].buf_ep = ep;
			bp[ix].buf_ds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
			bp[ix].buf_ds.ds_key = ep->ep_snd_lkey;
			bp[ix].buf_state = RDS_SNDBUF_FREE;
			mp = mp + rcv_len;
		}
		bp[nbuf - 1].buf_nextp = NULL;
		bp[nbuf - 1].buf_ep = ep;
		bp[nbuf - 1].buf_ds.ds_va = (ib_vaddr_t)(uintptr_t)mp;
		bp[nbuf - 1].buf_ds.ds_key = ep->ep_snd_lkey;
		bp[nbuf - 1].buf_state = RDS_SNDBUF_FREE;
		spool->pool_headp = &bp[0];
		spool->pool_tailp = &bp[nbuf - 1];
	}

	RDS_DPRINTF3(LABEL, "rdsmemp start: %p end: %p", memp, mp);
	RDS_DPRINTF2("rds_init_send_pool", "Return");

	return (0);
}

int
rds_reinit_send_pool(rds_ep_t *ep, ib_guid_t hca_guid)
{
	rds_buf_t	*bp;
	rds_hca_t	*hcap;
	ibt_mr_attr_t   mem_attr;
	ibt_mr_desc_t   mem_desc;
	rds_bufpool_t   *spool;
	int		ret;

	RDS_DPRINTF2("rds_reinit_send_pool", "Enter: EP(%p)", ep);

	spool = &ep->ep_sndpool;
	ASSERT(spool->pool_memp != NULL);

	/* deregister the send pool memory from the previous HCA */
	hcap = rds_get_hcap(rdsib_statep, ep->ep_hca_guid);
	if (hcap == NULL) {
		RDS_DPRINTF2("rds_reinit_send_pool", "HCA (0x%llx) not found",
		    ep->ep_hca_guid);
	} else {
		if (ep->ep_snd_mrhdl != NULL) {
			(void) ibt_deregister_mr(hcap->hca_hdl,
			    ep->ep_snd_mrhdl);
			ep->ep_snd_mrhdl = NULL;
			ep->ep_snd_lkey = 0;
		}

		if ((ep->ep_type == RDS_EP_TYPE_DATA) &&
		    (ep->ep_ackhdl != NULL)) {
			(void) ibt_deregister_mr(hcap->hca_hdl, ep->ep_ackhdl);
			ep->ep_ackhdl = NULL;
			ep->ep_ack_rkey = 0;
		}

		ep->ep_hca_guid = 0;
	}

	/* get the hcap for the new HCA */
	hcap = rds_get_hcap(rdsib_statep, hca_guid);
	if (hcap == NULL) {
		RDS_DPRINTF2("rds_reinit_send_pool", "HCA (0x%llx) not found",
		    hca_guid);
		return (-1);
	}

	/* register the send memory */
	mem_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)spool->pool_memp;
	mem_attr.mr_len = spool->pool_memsize;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;

	ret = ibt_register_mr(hcap->hca_hdl, hcap->hca_pdhdl,
	    &mem_attr, &ep->ep_snd_mrhdl, &mem_desc);
	if (ret != IBT_SUCCESS) {
		RDS_DPRINTF2("rds_reinit_send_pool",
		    "EP(%p): ibt_register_mr failed: %d", ep, ret);
		return (-1);
	}
	ep->ep_snd_lkey = mem_desc.md_lkey;

	/* register the acknowledgement space */
	if (ep->ep_type == RDS_EP_TYPE_DATA) {
		mem_attr.mr_vaddr = (ib_vaddr_t)ep->ep_ack_addr;
		mem_attr.mr_len = sizeof (uintptr_t);
		mem_attr.mr_as = NULL;
		mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE |
		    IBT_MR_ENABLE_REMOTE_WRITE;

		ret = ibt_register_mr(hcap->hca_hdl, hcap->hca_pdhdl,
		    &mem_attr, &ep->ep_ackhdl, &mem_desc);
		if (ret != IBT_SUCCESS) {
			RDS_DPRINTF2("rds_reinit_send_pool",
			    "EP(%p): ibt_register_mr for ack failed: %d",
			    ep, ret);
			(void) ibt_deregister_mr(hcap->hca_hdl,
			    ep->ep_snd_mrhdl);
			ep->ep_snd_mrhdl = NULL;
			ep->ep_snd_lkey = 0;
			return (-1);
		}
		ep->ep_ack_rkey = mem_desc.md_rkey;

		/* update the LKEY in the acknowledgement WR */
		ep->ep_ackds.ds_key = ep->ep_snd_lkey;
	}

	/* update the LKEY in each buffer */
	bp = spool->pool_headp;
	while (bp) {
		bp->buf_ds.ds_key = ep->ep_snd_lkey;
		bp = bp->buf_nextp;
	}

	ep->ep_hca_guid = hca_guid;

	RDS_DPRINTF2("rds_reinit_send_pool", "Return: EP(%p)", ep);

	return (0);
}

void
rds_free_recv_pool(rds_ep_t *ep)
{
	rds_bufpool_t *pool;

	if (ep->ep_type == RDS_EP_TYPE_DATA) {
		pool = &rds_dpool;
	} else {
		pool = &rds_cpool;
	}

	mutex_enter(&ep->ep_rcvpool.pool_lock);
	if (ep->ep_rcvpool.pool_nfree != 0) {
		rds_free_buf(pool, ep->ep_rcvpool.pool_headp,
		    ep->ep_rcvpool.pool_nfree);
		ep->ep_rcvpool.pool_nfree = 0;
		ep->ep_rcvpool.pool_headp = NULL;
		ep->ep_rcvpool.pool_tailp = NULL;
	}
	mutex_exit(&ep->ep_rcvpool.pool_lock);
}

int
rds_init_recv_pool(rds_ep_t *ep)
{
	rds_bufpool_t	*rpool;
	rds_qp_t	*recvqp;

	recvqp = &ep->ep_recvqp;
	rpool = &ep->ep_rcvpool;
	if (ep->ep_type == RDS_EP_TYPE_DATA) {
		recvqp->qp_depth = MaxDataRecvBuffers;
		recvqp->qp_level = 0;
		recvqp->qp_lwm = (DataRecvBufferLWM * MaxDataRecvBuffers)/100;
		recvqp->qp_taskqpending = B_FALSE;

		rpool->pool_nbuffers = MaxDataRecvBuffers;
		rpool->pool_nbusy = 0;
		rpool->pool_nfree = 0;
	} else {
		recvqp->qp_depth = MaxCtrlRecvBuffers;
		recvqp->qp_level = 0;
		recvqp->qp_lwm = (CtrlRecvBufferLWM * MaxCtrlRecvBuffers)/100;
		recvqp->qp_taskqpending = B_FALSE;

		rpool->pool_nbuffers = MaxCtrlRecvBuffers;
		rpool->pool_nbusy = 0;
		rpool->pool_nfree = 0;
	}

	return (0);
}

/* Free buffers to the global pool, either cpool or dpool */
void
rds_free_buf(rds_bufpool_t *pool, rds_buf_t *bp, uint_t nbuf)
{
	uint_t		ix;

	RDS_DPRINTF4("rds_free_buf", "Enter");

	ASSERT(nbuf != 0);

	mutex_enter(&pool->pool_lock);

	if (pool->pool_nfree != 0) {
		pool->pool_tailp->buf_nextp = bp;
	} else {
		pool->pool_headp = bp;
	}

	if (nbuf == 1) {
		ASSERT(bp->buf_state == RDS_RCVBUF_FREE);
		bp->buf_ep = NULL;
		bp->buf_nextp = NULL;
		pool->pool_tailp = bp;
	} else {
		for (ix = 1; ix < nbuf; ix++) {
			ASSERT(bp->buf_state == RDS_RCVBUF_FREE);
			bp->buf_ep = NULL;
			bp = bp->buf_nextp;
		}
		ASSERT(bp->buf_state == RDS_RCVBUF_FREE);
		bp->buf_ep = NULL;
		bp->buf_nextp = NULL;
		pool->pool_tailp = bp;
	}
	/* tail is always the last buffer */
	pool->pool_tailp->buf_nextp = NULL;

	pool->pool_nfree += nbuf;
	pool->pool_nbusy -= nbuf;

	mutex_exit(&pool->pool_lock);

	RDS_DPRINTF4("rds_free_buf", "Return");
}

/* Get buffers from the global pools, either cpool or dpool */
rds_buf_t *
rds_get_buf(rds_bufpool_t *pool, uint_t nbuf, uint_t *nret)
{
	rds_buf_t	*bp = NULL, *bp1;
	uint_t		ix;

	RDS_DPRINTF4("rds_get_buf", "Enter");

	mutex_enter(&pool->pool_lock);

	RDS_DPRINTF3("rds_get_buf", "Available: %d Needed: %d",
	    pool->pool_nfree, nbuf);

	if (nbuf < pool->pool_nfree) {
		*nret = nbuf;

		bp1 = pool->pool_headp;
		for (ix = 1; ix < nbuf; ix++) {
			bp1 = bp1->buf_nextp;
		}

		bp = pool->pool_headp;
		pool->pool_headp = bp1->buf_nextp;
		bp1->buf_nextp = NULL;

		pool->pool_nfree -= nbuf;
		pool->pool_nbusy += nbuf;
	} else if (nbuf >= pool->pool_nfree) {
		*nret = pool->pool_nfree;

		bp = pool->pool_headp;

		pool->pool_headp = NULL;
		pool->pool_tailp = NULL;

		pool->pool_nbusy += pool->pool_nfree;
		pool->pool_nfree = 0;
	}

	mutex_exit(&pool->pool_lock);

	RDS_DPRINTF4("rds_get_buf", "Return");

	return (bp);
}

boolean_t
rds_is_recvq_empty(rds_ep_t *ep, boolean_t wait)
{
	rds_qp_t	*recvqp;
	rds_bufpool_t	*rpool;
	boolean_t ret = B_TRUE;

	recvqp = &ep->ep_recvqp;
	mutex_enter(&recvqp->qp_lock);
	RDS_DPRINTF2("rds_is_recvq_empty", "EP(%p): QP has %d WRs",
	    ep, recvqp->qp_level);
	if (wait) {
		/* wait until the RQ is empty */
		while (recvqp->qp_level != 0) {
			/* wait one second and try again */
			mutex_exit(&recvqp->qp_lock);
			delay(drv_usectohz(1000000));
			mutex_enter(&recvqp->qp_lock);
		}
	} else if (recvqp->qp_level != 0) {
			ret = B_FALSE;
	}
	mutex_exit(&recvqp->qp_lock);

	rpool = &ep->ep_rcvpool;
	mutex_enter(&rpool->pool_lock);

	/*
	 * During failovers/reconnects, the app may still have some buffers
	 * on thier socket queues. Waiting here for those buffers may
	 * cause a hang. It seems ok for those buffers to get freed later.
	 */
	if (rpool->pool_nbusy != 0) {
		RDS_DPRINTF2("rds_is_recvq_empty", "EP(%p): "
		    "There are %d pending buffers on sockqs", ep,
		    rpool->pool_nbusy);
		ret = B_FALSE;
	}
	mutex_exit(&rpool->pool_lock);

	return (ret);
}

boolean_t
rds_is_sendq_empty(rds_ep_t *ep, uint_t wait)
{
	rds_bufpool_t	*spool;
	rds_buf_t	*bp;
	boolean_t	ret1 = B_TRUE;

	/* check if all the sends completed */
	spool = &ep->ep_sndpool;
	mutex_enter(&spool->pool_lock);
	RDS_DPRINTF2("rds_is_sendq_empty", "EP(%p): "
	    "Send Pool contains: %d", ep, spool->pool_nbusy);
	if (wait) {
		while (spool->pool_nbusy != 0) {
			if (rds_no_interrupts) {
				/* wait one second and try again */
				delay(drv_usectohz(1000000));
				rds_poll_send_completions(ep->ep_sendcq, ep,
				    B_TRUE);
			} else {
				/* wait one second and try again */
				mutex_exit(&spool->pool_lock);
				delay(drv_usectohz(1000000));
				mutex_enter(&spool->pool_lock);
			}
		}

		if ((wait == 2) && (ep->ep_type == RDS_EP_TYPE_DATA)) {
			rds_buf_t	*ackbp;
			rds_buf_t	*prev_ackbp;

			/*
			 * If the last one is acknowledged then everything
			 * is acknowledged
			 */
			bp = spool->pool_tailp;
			ackbp = *(rds_buf_t **)ep->ep_ack_addr;
			prev_ackbp = ackbp;
			RDS_DPRINTF2("rds_is_sendq_empty", "EP(%p): "
			    "Checking for acknowledgements", ep);
			while (bp != ackbp) {
				RDS_DPRINTF2("rds_is_sendq_empty",
				    "EP(%p) BP(0x%p/0x%p) last "
				    "sent/acknowledged", ep, bp, ackbp);
				mutex_exit(&spool->pool_lock);
				delay(drv_usectohz(1000000));
				mutex_enter(&spool->pool_lock);

				bp = spool->pool_tailp;
				ackbp = *(rds_buf_t **)ep->ep_ack_addr;
				if (ackbp == prev_ackbp) {
					RDS_DPRINTF2("rds_is_sendq_empty",
					    "There has been no progress,"
					    "give up and proceed");
					break;
				}
				prev_ackbp = ackbp;
			}
		}
	} else if (spool->pool_nbusy != 0) {
			ret1 = B_FALSE;
	}
	mutex_exit(&spool->pool_lock);

	/* check if all the rdma acks completed */
	mutex_enter(&ep->ep_lock);
	RDS_DPRINTF2("rds_is_sendq_empty", "EP(%p): "
	    "Outstanding RDMA Acks: %d", ep, ep->ep_rdmacnt);
	if (wait) {
		while (ep->ep_rdmacnt != 0) {
			if (rds_no_interrupts) {
				/* wait one second and try again */
				delay(drv_usectohz(1000000));
				rds_poll_send_completions(ep->ep_sendcq, ep,
				    B_FALSE);
			} else {
				/* wait one second and try again */
				mutex_exit(&ep->ep_lock);
				delay(drv_usectohz(1000000));
				mutex_enter(&ep->ep_lock);
			}
		}
	} else if (ep->ep_rdmacnt != 0) {
			ret1 = B_FALSE;
	}
	mutex_exit(&ep->ep_lock);

	return (ret1);
}

/* Get buffers from the send pool */
rds_buf_t *
rds_get_send_buf(rds_ep_t *ep, uint_t nbuf)
{
	rds_buf_t	*bp = NULL, *bp1;
	rds_bufpool_t	*spool;
	uint_t		waittime = rds_waittime_ms * 1000;
	uint_t		ix;
	int		ret;

	RDS_DPRINTF4("rds_get_send_buf", "Enter: EP(%p) Buffers requested: %d",
	    ep, nbuf);

	spool = &ep->ep_sndpool;
	mutex_enter(&spool->pool_lock);

	if (rds_no_interrupts) {
		if ((spool->pool_sqpoll_pending == B_FALSE) &&
		    (spool->pool_nbusy >
		    (spool->pool_nbuffers * rds_poll_percent_full)/100)) {
			spool->pool_sqpoll_pending = B_TRUE;
			mutex_exit(&spool->pool_lock);
			rds_poll_send_completions(ep->ep_sendcq, ep, B_FALSE);
			mutex_enter(&spool->pool_lock);
			spool->pool_sqpoll_pending = B_FALSE;
		}
	}

	if (spool->pool_nfree < nbuf) {
		/* wait for buffers to become available */
		spool->pool_cv_count += nbuf;
		ret = cv_reltimedwait_sig(&spool->pool_cv, &spool->pool_lock,
		    drv_usectohz(waittime), TR_CLOCK_TICK);
		/* ret = cv_wait_sig(&spool->pool_cv, &spool->pool_lock); */
		if (ret == 0) {
			/* signal pending */
			spool->pool_cv_count -= nbuf;
			mutex_exit(&spool->pool_lock);
			return (NULL);
		}

		spool->pool_cv_count -= nbuf;
	}

	/* Have the number of buffers needed */
	if (spool->pool_nfree > nbuf) {
		bp = spool->pool_headp;

		if (ep->ep_type == RDS_EP_TYPE_DATA) {
			rds_buf_t *ackbp;
			ackbp = *(rds_buf_t **)ep->ep_ack_addr;

			/* check if all the needed buffers are acknowledged */
			bp1 = bp;
			for (ix = 0; ix < nbuf; ix++) {
				if ((bp1 == ackbp) ||
				    (bp1->buf_state != RDS_SNDBUF_FREE)) {
					/*
					 * The buffer is not yet signalled or
					 * is not yet acknowledged
					 */
					RDS_DPRINTF5("rds_get_send_buf",
					    "EP(%p) Buffer (%p) not yet "
					    "acked/completed", ep, bp1);
					mutex_exit(&spool->pool_lock);
					return (NULL);
				}

				bp1 = bp1->buf_nextp;
			}
		}

		/* mark the buffers as pending */
		bp1 = bp;
		for (ix = 1; ix < nbuf; ix++) {
			ASSERT(bp1->buf_state == RDS_SNDBUF_FREE);
			bp1->buf_state = RDS_SNDBUF_PENDING;
			bp1 = bp1->buf_nextp;
		}
		ASSERT(bp1->buf_state == RDS_SNDBUF_FREE);
		bp1->buf_state = RDS_SNDBUF_PENDING;

		spool->pool_headp = bp1->buf_nextp;
		bp1->buf_nextp = NULL;
		if (spool->pool_headp == NULL)
			spool->pool_tailp = NULL;
		spool->pool_nfree -= nbuf;
		spool->pool_nbusy += nbuf;
	}
	mutex_exit(&spool->pool_lock);

	RDS_DPRINTF4("rds_get_send_buf", "Return: EP(%p) Buffers requested: %d",
	    ep, nbuf);

	return (bp);
}

#define	RDS_MIN_BUF_TO_WAKE_THREADS	10

void
rds_free_send_buf(rds_ep_t *ep, rds_buf_t *headp, rds_buf_t *tailp, uint_t nbuf,
    boolean_t lock)
{
	rds_bufpool_t	*spool;
	rds_buf_t	*tmp;

	RDS_DPRINTF4("rds_free_send_buf", "Enter");

	ASSERT(nbuf != 0);

	if (tailp == NULL) {
		if (nbuf > 1) {
			tmp = headp;
			while (tmp->buf_nextp) {
				tmp = tmp->buf_nextp;
			}
			tailp = tmp;
		} else {
			tailp = headp;
		}
	}

	spool = &ep->ep_sndpool;

	if (lock == B_FALSE) {
		/* lock is not held outside */
		mutex_enter(&spool->pool_lock);
	}

	if (spool->pool_nfree) {
		spool->pool_tailp->buf_nextp = headp;
	} else {
		spool->pool_headp = headp;
	}
	spool->pool_tailp = tailp;

	spool->pool_nfree += nbuf;
	spool->pool_nbusy -= nbuf;

	if ((spool->pool_cv_count > 0) &&
	    (spool->pool_nfree > RDS_MIN_BUF_TO_WAKE_THREADS)) {
		if (spool->pool_nfree >= spool->pool_cv_count)
			cv_broadcast(&spool->pool_cv);
		else
			cv_signal(&spool->pool_cv);
	}

	if (lock == B_FALSE) {
		mutex_exit(&spool->pool_lock);
	}

	RDS_DPRINTF4("rds_free_send_buf", "Return");
}

void
rds_free_recv_buf(rds_buf_t *bp, uint_t nbuf)
{
	rds_ep_t	*ep;
	rds_bufpool_t	*rpool;
	rds_buf_t	*bp1;
	uint_t		ix;

	RDS_DPRINTF4("rds_free_recv_buf", "Enter");

	ASSERT(nbuf != 0);

	ep = bp->buf_ep;
	rpool = &ep->ep_rcvpool;

	mutex_enter(&rpool->pool_lock);

	/* Add the buffers to the local pool */
	if (rpool->pool_tailp == NULL) {
		ASSERT(rpool->pool_headp == NULL);
		ASSERT(rpool->pool_nfree == 0);
		rpool->pool_headp = bp;
		bp1 = bp;
		for (ix = 1; ix < nbuf; ix++) {
			if (bp1->buf_state == RDS_RCVBUF_ONSOCKQ) {
				rpool->pool_nbusy--;
			}
			bp1->buf_state = RDS_RCVBUF_FREE;
			bp1 = bp1->buf_nextp;
		}
		bp1->buf_nextp = NULL;
		if (bp->buf_state == RDS_RCVBUF_ONSOCKQ) {
			rpool->pool_nbusy--;
		}
		bp->buf_state = RDS_RCVBUF_FREE;
		rpool->pool_tailp = bp1;
		rpool->pool_nfree += nbuf;
	} else {
		bp1 = bp;
		for (ix = 1; ix < nbuf; ix++) {
			if (bp1->buf_state == RDS_RCVBUF_ONSOCKQ) {
				rpool->pool_nbusy--;
			}
			bp1->buf_state = RDS_RCVBUF_FREE;
			bp1 = bp1->buf_nextp;
		}
		bp1->buf_nextp = NULL;
		if (bp->buf_state == RDS_RCVBUF_ONSOCKQ) {
			rpool->pool_nbusy--;
		}
		bp->buf_state = RDS_RCVBUF_FREE;
		rpool->pool_tailp->buf_nextp = bp;
		rpool->pool_tailp = bp1;
		rpool->pool_nfree += nbuf;
	}

	if (rpool->pool_nfree >= rds_nbuffers_to_putback) {
		bp = rpool->pool_headp;
		nbuf = rpool->pool_nfree;
		rpool->pool_headp = NULL;
		rpool->pool_tailp = NULL;
		rpool->pool_nfree = 0;
		mutex_exit(&rpool->pool_lock);

		/* Free the buffers to the global pool */
		if (ep->ep_type == RDS_EP_TYPE_DATA) {
			rds_free_buf(&rds_dpool, bp, nbuf);
		} else {
			rds_free_buf(&rds_cpool, bp, nbuf);
		}

		return;
	}
	mutex_exit(&rpool->pool_lock);

	RDS_DPRINTF4("rds_free_recv_buf", "Return");
}
