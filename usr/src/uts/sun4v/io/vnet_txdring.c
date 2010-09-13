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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/machsystm.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/strsun.h>
#include <sys/callb.h>
#include <sys/sdt.h>
#include <sys/ethernet.h>
#include <sys/mach_descrip.h>
#include <sys/mdeg.h>
#include <sys/vnet.h>
#include <sys/vio_mailbox.h>
#include <sys/vio_common.h>
#include <sys/vnet_common.h>
#include <sys/vnet_mailbox.h>
#include <sys/vio_util.h>
#include <sys/vnet_gen.h>

/*
 * This file contains the implementation of TxDring data transfer mode of VIO
 * Protocol in vnet. The functions in this file are invoked from vnet_gen.c
 * after TxDring mode is negotiated with the peer during attribute phase of
 * handshake. This file contains functions that setup the transmit and receive
 * descriptor rings, and associated resources in TxDring mode. It also contains
 * the transmit and receive data processing functions that are invoked in
 * TxDring mode.
 */

/* Functions exported to vnet_gen.c */
int vgen_create_tx_dring(vgen_ldc_t *ldcp);
void vgen_destroy_tx_dring(vgen_ldc_t *ldcp);
int vgen_map_rx_dring(vgen_ldc_t *ldcp, void *pkt);
void vgen_unmap_rx_dring(vgen_ldc_t *ldcp);
int vgen_dringsend(void *arg, mblk_t *mp);
void vgen_ldc_msg_worker(void *arg);
void vgen_stop_msg_thread(vgen_ldc_t *ldcp);
int vgen_handle_dringdata(void *arg1, void *arg2);
mblk_t *vgen_poll_rcv(vgen_ldc_t *ldcp, int bytes_to_pickup);
int vgen_check_datamsg_seq(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
int vgen_sendmsg(vgen_ldc_t *ldcp, caddr_t msg,  size_t msglen,
    boolean_t caller_holds_lock);

/* Internal functions */
static int vgen_init_multipools(vgen_ldc_t *ldcp);
static int vgen_handle_dringdata_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_process_dringdata(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_dringdata_ack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_dringdata_nack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_rx(vgen_ldc_t *ldcp, mblk_t *bp, mblk_t *bpt);
static int vgen_send_dringdata(vgen_ldc_t *ldcp, uint32_t start, int32_t end);
static int vgen_send_dringack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
    uint32_t start, int32_t end, uint8_t pstate);
static void vgen_reclaim(vgen_ldc_t *ldcp);
static void vgen_reclaim_dring(vgen_ldc_t *ldcp);

/* Functions imported from vnet_gen.c */
extern int vgen_handle_evt_read(vgen_ldc_t *ldcp, vgen_caller_t caller);
extern int vgen_handle_evt_reset(vgen_ldc_t *ldcp, vgen_caller_t caller);
extern void vgen_handle_pkt_data(void *arg1, void *arg2, uint32_t msglen);
extern void vgen_destroy_rxpools(void *arg);

/* Tunables */
extern int vgen_rxpool_cleanup_delay;
extern boolean_t vnet_jumbo_rxpools;
extern uint32_t vnet_num_descriptors;
extern uint32_t vgen_chain_len;
extern uint32_t vgen_ldcwr_retries;
extern uint32_t vgen_recv_delay;
extern uint32_t vgen_recv_retries;
extern uint32_t vgen_rbufsz1;
extern uint32_t vgen_rbufsz2;
extern uint32_t vgen_rbufsz3;
extern uint32_t vgen_rbufsz4;
extern uint32_t vgen_nrbufs1;
extern uint32_t vgen_nrbufs2;
extern uint32_t vgen_nrbufs3;
extern uint32_t vgen_nrbufs4;

#ifdef DEBUG

#define	DEBUG_PRINTF	vgen_debug_printf

extern int vnet_dbglevel;
extern int vgen_inject_err_flag;

extern void vgen_debug_printf(const char *fname, vgen_t *vgenp,
	vgen_ldc_t *ldcp, const char *fmt, ...);
extern boolean_t vgen_inject_error(vgen_ldc_t *ldcp, int error);

#endif

/*
 * Allocate transmit resources for the channel. The resources consist of a
 * transmit descriptor ring and an associated transmit buffer area.
 */
int
vgen_create_tx_dring(vgen_ldc_t *ldcp)
{
	int 			i;
	int 			rv;
	ldc_mem_info_t		minfo;
	uint32_t		txdsize;
	uint32_t		tbufsize;
	vgen_private_desc_t	*tbufp;
	vnet_public_desc_t	*txdp;
	vio_dring_entry_hdr_t	*hdrp;
	caddr_t			datap = NULL;
	int			ci;
	uint32_t		ncookies;
	size_t			data_sz;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);

	ldcp->num_txds = vnet_num_descriptors;
	txdsize = sizeof (vnet_public_desc_t);
	tbufsize = sizeof (vgen_private_desc_t);

	/* allocate transmit buffer ring */
	tbufp = kmem_zalloc(ldcp->num_txds * tbufsize, KM_NOSLEEP);
	if (tbufp == NULL) {
		return (DDI_FAILURE);
	}
	ldcp->tbufp = tbufp;
	ldcp->tbufendp = &((ldcp->tbufp)[ldcp->num_txds]);

	/* create transmit descriptor ring */
	rv = ldc_mem_dring_create(ldcp->num_txds, txdsize,
	    &ldcp->tx_dring_handle);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_dring_create() failed\n");
		goto fail;
	}

	/* get the addr of descriptor ring */
	rv = ldc_mem_dring_info(ldcp->tx_dring_handle, &minfo);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_dring_info() failed\n");
		goto fail;
	}
	ldcp->txdp = (vnet_public_desc_t *)(minfo.vaddr);

	/*
	 * In order to ensure that the number of ldc cookies per descriptor is
	 * limited to be within the default MAX_COOKIES (2), we take the steps
	 * outlined below:
	 *
	 * Align the entire data buffer area to 8K and carve out per descriptor
	 * data buffers starting from this 8K aligned base address.
	 *
	 * We round up the mtu specified to be a multiple of 2K or 4K.
	 * For sizes up to 12K we round up the size to the next 2K.
	 * For sizes > 12K we round up to the next 4K (otherwise sizes such as
	 * 14K could end up needing 3 cookies, with the buffer spread across
	 * 3 8K pages:  8K+6K, 2K+8K+2K, 6K+8K, ...).
	 */
	data_sz = vgenp->max_frame_size + VNET_IPALIGN + VNET_LDCALIGN;
	if (data_sz <= VNET_12K) {
		data_sz = VNET_ROUNDUP_2K(data_sz);
	} else {
		data_sz = VNET_ROUNDUP_4K(data_sz);
	}

	/* allocate extra 8K bytes for alignment */
	ldcp->tx_data_sz = (data_sz * ldcp->num_txds) + VNET_8K;
	datap = kmem_zalloc(ldcp->tx_data_sz, KM_SLEEP);
	ldcp->tx_datap = datap;


	/* align the starting address of the data area to 8K */
	datap = (caddr_t)VNET_ROUNDUP_8K((uintptr_t)datap);

	/*
	 * for each private descriptor, allocate a ldc mem_handle which is
	 * required to map the data during transmit, set the flags
	 * to free (available for use by transmit routine).
	 */

	for (i = 0; i < ldcp->num_txds; i++) {

		tbufp = &(ldcp->tbufp[i]);
		rv = ldc_mem_alloc_handle(ldcp->ldc_handle,
		    &(tbufp->memhandle));
		if (rv) {
			tbufp->memhandle = 0;
			goto fail;
		}

		/*
		 * bind ldc memhandle to the corresponding transmit buffer.
		 */
		ci = ncookies = 0;
		rv = ldc_mem_bind_handle(tbufp->memhandle,
		    (caddr_t)datap, data_sz, LDC_SHADOW_MAP,
		    LDC_MEM_R, &(tbufp->memcookie[ci]), &ncookies);
		if (rv != 0) {
			goto fail;
		}

		/*
		 * successful in binding the handle to tx data buffer.
		 * set datap in the private descr to this buffer.
		 */
		tbufp->datap = datap;

		if ((ncookies == 0) ||
		    (ncookies > MAX_COOKIES)) {
			goto fail;
		}

		for (ci = 1; ci < ncookies; ci++) {
			rv = ldc_mem_nextcookie(tbufp->memhandle,
			    &(tbufp->memcookie[ci]));
			if (rv != 0) {
				goto fail;
			}
		}

		tbufp->ncookies = ncookies;
		datap += data_sz;

		tbufp->flags = VGEN_PRIV_DESC_FREE;
		txdp = &(ldcp->txdp[i]);
		hdrp = &txdp->hdr;
		hdrp->dstate = VIO_DESC_FREE;
		hdrp->ack = B_FALSE;
		tbufp->descp = txdp;

	}

	/*
	 * The descriptors and the associated buffers are all ready;
	 * now bind descriptor ring to the channel.
	 */
	rv = ldc_mem_dring_bind(ldcp->ldc_handle, ldcp->tx_dring_handle,
	    LDC_DIRECT_MAP | LDC_SHADOW_MAP, LDC_MEM_RW,
	    &ldcp->tx_dring_cookie, &ncookies);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_dring_bind failed "
		    "rv(%x)\n", rv);
		goto fail;
	}
	ASSERT(ncookies == 1);
	ldcp->tx_dring_ncookies = ncookies;

	/* reset tbuf walking pointers */
	ldcp->next_tbufp = ldcp->tbufp;
	ldcp->cur_tbufp = ldcp->tbufp;

	/* initialize tx seqnum and index */
	ldcp->next_txseq = VNET_ISS;
	ldcp->next_txi = 0;

	ldcp->resched_peer = B_TRUE;
	ldcp->resched_peer_txi = 0;

	return (VGEN_SUCCESS);

fail:
	vgen_destroy_tx_dring(ldcp);
	return (VGEN_FAILURE);
}

/*
 * Free transmit resources for the channel.
 */
void
vgen_destroy_tx_dring(vgen_ldc_t *ldcp)
{
	int 			i;
	int			tbufsize = sizeof (vgen_private_desc_t);
	vgen_private_desc_t	*tbufp = ldcp->tbufp;

	/* We first unbind the descriptor ring */
	if (ldcp->tx_dring_ncookies != 0) {
		(void) ldc_mem_dring_unbind(ldcp->tx_dring_handle);
		ldcp->tx_dring_ncookies = 0;
	}

	/* Unbind transmit buffers */
	if (ldcp->tbufp != NULL) {
		/* for each tbuf (priv_desc), free ldc mem_handle */
		for (i = 0; i < ldcp->num_txds; i++) {

			tbufp = &(ldcp->tbufp[i]);

			if (tbufp->datap) { /* if bound to a ldc memhandle */
				(void) ldc_mem_unbind_handle(tbufp->memhandle);
				tbufp->datap = NULL;
			}
			if (tbufp->memhandle) {
				(void) ldc_mem_free_handle(tbufp->memhandle);
				tbufp->memhandle = 0;
			}
		}
	}

	/* Free tx data buffer area */
	if (ldcp->tx_datap != NULL) {
		kmem_free(ldcp->tx_datap, ldcp->tx_data_sz);
		ldcp->tx_datap = NULL;
		ldcp->tx_data_sz = 0;
	}

	/* Free transmit descriptor ring */
	if (ldcp->tx_dring_handle != 0) {
		(void) ldc_mem_dring_destroy(ldcp->tx_dring_handle);
		ldcp->tx_dring_handle = 0;
		ldcp->txdp = NULL;
	}

	/* Free transmit buffer ring */
	if (ldcp->tbufp != NULL) {
		kmem_free(ldcp->tbufp, ldcp->num_txds * tbufsize);
		ldcp->tbufp = ldcp->tbufendp = NULL;
	}
}

/*
 * Map the transmit descriptor ring exported
 * by the peer, as our receive descriptor ring.
 */
int
vgen_map_rx_dring(vgen_ldc_t *ldcp, void *pkt)
{
	int			rv;
	ldc_mem_info_t		minfo;
	ldc_mem_cookie_t	dcookie;
	uint32_t		ncookies;
	uint32_t 		num_desc;
	uint32_t		desc_size;
	vio_dring_reg_msg_t	*msg = pkt;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);

	ncookies = msg->ncookies;
	num_desc = msg->num_descriptors;
	desc_size = msg->descriptor_size;
	bcopy(&msg->cookie[0], &dcookie, sizeof (ldc_mem_cookie_t));

	/*
	 * Sanity check.
	 */
	if (num_desc < VGEN_NUM_DESCRIPTORS_MIN ||
	    desc_size < sizeof (vnet_public_desc_t)) {
		goto fail;
	}

	/* Map the remote dring */
	rv = ldc_mem_dring_map(ldcp->ldc_handle, &dcookie, ncookies, num_desc,
	    desc_size, LDC_DIRECT_MAP, &(ldcp->rx_dring_handle));
	if (rv != 0) {
		goto fail;
	}

	/*
	 * Sucessfully mapped, now try to get info about the mapped dring
	 */
	rv = ldc_mem_dring_info(ldcp->rx_dring_handle, &minfo);
	if (rv != 0) {
		goto fail;
	}

	/*
	 * Save ring address, number of descriptors.
	 */
	ldcp->mrxdp = (vnet_public_desc_t *)(minfo.vaddr);
	bcopy(&dcookie, &(ldcp->rx_dring_cookie), sizeof (dcookie));
	ldcp->rx_dring_ncookies = ncookies;
	ldcp->num_rxds = num_desc;

	/* Initialize rx dring indexes and seqnum */
	ldcp->next_rxi = 0;
	ldcp->next_rxseq = VNET_ISS;
	ldcp->dring_mtype = minfo.mtype;

	/* Save peer's dring_info values */
	bcopy(&dcookie, &(ldcp->peer_hparams.dring_cookie),
	    sizeof (ldc_mem_cookie_t));
	ldcp->peer_hparams.num_desc = num_desc;
	ldcp->peer_hparams.desc_size = desc_size;
	ldcp->peer_hparams.dring_ncookies = ncookies;

	/* Set dring_ident for the peer */
	ldcp->peer_hparams.dring_ident = (uint64_t)ldcp->txdp;

	/* Return the dring_ident in ack msg */
	msg->dring_ident = (uint64_t)ldcp->txdp;

	/* alloc rx mblk pools */
	rv = vgen_init_multipools(ldcp);
	if (rv != 0) {
		/*
		 * We do not return failure if receive mblk pools can't
		 * be allocated; instead allocb(9F) will be used to
		 * dynamically allocate buffers during receive.
		 */
		DWARN(vgenp, ldcp,
		    "vnet%d: failed to allocate rx mblk "
		    "pools for channel(0x%lx)\n",
		    vgenp->instance, ldcp->ldc_id);
	}

	return (VGEN_SUCCESS);

fail:
	if (ldcp->rx_dring_handle != 0) {
		(void) ldc_mem_dring_unmap(ldcp->rx_dring_handle);
		ldcp->rx_dring_handle = 0;
	}
	return (VGEN_FAILURE);
}

/*
 * Unmap the receive descriptor ring.
 */
void
vgen_unmap_rx_dring(vgen_ldc_t *ldcp)
{
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vio_mblk_pool_t		*vmp = NULL;

	/* Destroy receive mblk pools */
	vio_destroy_multipools(&ldcp->vmp, &vmp);
	if (vmp != NULL) {
		/*
		 * If we can't destroy the rx pool for this channel,
		 * dispatch a task to retry and clean up. Note that we
		 * don't need to wait for the task to complete. If the
		 * vnet device itself gets detached, it will wait for
		 * the task to complete implicitly in
		 * ddi_taskq_destroy().
		 */
		(void) ddi_taskq_dispatch(vgenp->rxp_taskq,
		    vgen_destroy_rxpools, vmp, DDI_SLEEP);
	}

	/* Unmap peer's dring */
	if (ldcp->rx_dring_handle != 0) {
		(void) ldc_mem_dring_unmap(ldcp->rx_dring_handle);
		ldcp->rx_dring_handle = 0;
	}

	/* clobber rx ring members */
	bzero(&ldcp->rx_dring_cookie, sizeof (ldcp->rx_dring_cookie));
	ldcp->mrxdp = NULL;
	ldcp->next_rxi = 0;
	ldcp->num_rxds = 0;
	ldcp->next_rxseq = VNET_ISS;
}

/* Allocate receive resources */
static int
vgen_init_multipools(vgen_ldc_t *ldcp)
{
	size_t		data_sz;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	int		status;
	uint32_t	sz1 = 0;
	uint32_t	sz2 = 0;
	uint32_t	sz3 = 0;
	uint32_t	sz4 = 0;

	/*
	 * We round up the mtu specified to be a multiple of 2K.
	 * We then create rx pools based on the rounded up size.
	 */
	data_sz = vgenp->max_frame_size + VNET_IPALIGN + VNET_LDCALIGN;
	data_sz = VNET_ROUNDUP_2K(data_sz);

	/*
	 * If pool sizes are specified, use them. Note that the presence of
	 * the first tunable will be used as a hint.
	 */
	if (vgen_rbufsz1 != 0) {

		sz1 = vgen_rbufsz1;
		sz2 = vgen_rbufsz2;
		sz3 = vgen_rbufsz3;
		sz4 = vgen_rbufsz4;

		if (sz4 == 0) { /* need 3 pools */

			ldcp->max_rxpool_size = sz3;
			status = vio_init_multipools(&ldcp->vmp,
			    VGEN_NUM_VMPOOLS, sz1, sz2, sz3, vgen_nrbufs1,
			    vgen_nrbufs2, vgen_nrbufs3);

		} else {

			ldcp->max_rxpool_size = sz4;
			status = vio_init_multipools(&ldcp->vmp,
			    VGEN_NUM_VMPOOLS + 1, sz1, sz2, sz3, sz4,
			    vgen_nrbufs1, vgen_nrbufs2, vgen_nrbufs3,
			    vgen_nrbufs4);
		}
		return (status);
	}

	/*
	 * Pool sizes are not specified. We select the pool sizes based on the
	 * mtu if vnet_jumbo_rxpools is enabled.
	 */
	if (vnet_jumbo_rxpools == B_FALSE || data_sz == VNET_2K) {
		/*
		 * Receive buffer pool allocation based on mtu is disabled.
		 * Use the default mechanism of standard size pool allocation.
		 */
		sz1 = VGEN_DBLK_SZ_128;
		sz2 = VGEN_DBLK_SZ_256;
		sz3 = VGEN_DBLK_SZ_2048;
		ldcp->max_rxpool_size = sz3;

		status = vio_init_multipools(&ldcp->vmp, VGEN_NUM_VMPOOLS,
		    sz1, sz2, sz3,
		    vgen_nrbufs1, vgen_nrbufs2, vgen_nrbufs3);

		return (status);
	}

	switch (data_sz) {

	case VNET_4K:

		sz1 = VGEN_DBLK_SZ_128;
		sz2 = VGEN_DBLK_SZ_256;
		sz3 = VGEN_DBLK_SZ_2048;
		sz4 = sz3 << 1;			/* 4K */
		ldcp->max_rxpool_size = sz4;

		status = vio_init_multipools(&ldcp->vmp, VGEN_NUM_VMPOOLS + 1,
		    sz1, sz2, sz3, sz4,
		    vgen_nrbufs1, vgen_nrbufs2, vgen_nrbufs3, vgen_nrbufs4);
		break;

	default:	/* data_sz:  4K+ to 16K */

		sz1 = VGEN_DBLK_SZ_256;
		sz2 = VGEN_DBLK_SZ_2048;
		sz3 = data_sz >> 1;	/* Jumbo-size/2 */
		sz4 = data_sz;		/* Jumbo-size  */
		ldcp->max_rxpool_size = sz4;

		status = vio_init_multipools(&ldcp->vmp, VGEN_NUM_VMPOOLS + 1,
		    sz1, sz2, sz3, sz4,
		    vgen_nrbufs1, vgen_nrbufs2, vgen_nrbufs3, vgen_nrbufs4);
		break;

	}

	return (status);
}

/*
 * This function transmits normal data frames (non-priority) over the channel.
 * It queues the frame into the transmit descriptor ring and sends a
 * VIO_DRING_DATA message if needed, to wake up the peer to (re)start
 * processing.
 */
int
vgen_dringsend(void *arg, mblk_t *mp)
{
	vgen_ldc_t		*ldcp = (vgen_ldc_t *)arg;
	vgen_private_desc_t	*tbufp;
	vgen_private_desc_t	*rtbufp;
	vnet_public_desc_t	*rtxdp;
	vgen_private_desc_t	*ntbufp;
	vnet_public_desc_t	*txdp;
	vio_dring_entry_hdr_t	*hdrp;
	vgen_stats_t		*statsp;
	struct ether_header	*ehp;
	boolean_t		is_bcast = B_FALSE;
	boolean_t		is_mcast = B_FALSE;
	size_t			mblksz;
	caddr_t			dst;
	mblk_t			*bp;
	size_t			size;
	int			rv = 0;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vgen_hparams_t		*lp = &ldcp->local_hparams;

	statsp = &ldcp->stats;
	size = msgsize(mp);

	DBG1(vgenp, ldcp, "enter\n");

	if (ldcp->ldc_status != LDC_UP) {
		DWARN(vgenp, ldcp, "status(%d), dropping packet\n",
		    ldcp->ldc_status);
		goto dringsend_exit;
	}

	/* drop the packet if ldc is not up or handshake is not done */
	if (ldcp->hphase != VH_DONE) {
		DWARN(vgenp, ldcp, "hphase(%x), dropping packet\n",
		    ldcp->hphase);
		goto dringsend_exit;
	}

	if (size > (size_t)lp->mtu) {
		DWARN(vgenp, ldcp, "invalid size(%d)\n", size);
		goto dringsend_exit;
	}
	if (size < ETHERMIN)
		size = ETHERMIN;

	ehp = (struct ether_header *)mp->b_rptr;
	is_bcast = IS_BROADCAST(ehp);
	is_mcast = IS_MULTICAST(ehp);

	mutex_enter(&ldcp->txlock);
	/*
	 * allocate a descriptor
	 */
	tbufp = ldcp->next_tbufp;
	ntbufp = NEXTTBUF(ldcp, tbufp);
	if (ntbufp == ldcp->cur_tbufp) { /* out of tbufs/txds */

		mutex_enter(&ldcp->tclock);
		/* Try reclaiming now */
		vgen_reclaim_dring(ldcp);
		ldcp->reclaim_lbolt = ddi_get_lbolt();

		if (ntbufp == ldcp->cur_tbufp) {
			/* Now we are really out of tbuf/txds */
			ldcp->tx_blocked_lbolt = ddi_get_lbolt();
			ldcp->tx_blocked = B_TRUE;
			mutex_exit(&ldcp->tclock);

			statsp->tx_no_desc++;
			mutex_exit(&ldcp->txlock);

			return (VGEN_TX_NORESOURCES);
		}
		mutex_exit(&ldcp->tclock);
	}
	/* update next available tbuf in the ring and update tx index */
	ldcp->next_tbufp = ntbufp;
	INCR_TXI(ldcp->next_txi, ldcp);

	/* Mark the buffer busy before releasing the lock */
	tbufp->flags = VGEN_PRIV_DESC_BUSY;
	mutex_exit(&ldcp->txlock);

	/* copy data into pre-allocated transmit buffer */
	dst = tbufp->datap + VNET_IPALIGN;
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblksz = MBLKL(bp);
		bcopy(bp->b_rptr, dst, mblksz);
		dst += mblksz;
	}

	tbufp->datalen = size;

	/* initialize the corresponding public descriptor (txd) */
	txdp = tbufp->descp;
	hdrp = &txdp->hdr;
	txdp->nbytes = size;
	txdp->ncookies = tbufp->ncookies;
	bcopy((tbufp->memcookie), (txdp->memcookie),
	    tbufp->ncookies * sizeof (ldc_mem_cookie_t));

	mutex_enter(&ldcp->wrlock);
	/*
	 * If the flags not set to BUSY, it implies that the clobber
	 * was done while we were copying the data. In such case,
	 * discard the packet and return.
	 */
	if (tbufp->flags != VGEN_PRIV_DESC_BUSY) {
		statsp->oerrors++;
		mutex_exit(&ldcp->wrlock);
		goto dringsend_exit;
	}
	hdrp->dstate = VIO_DESC_READY;

	/* update stats */
	statsp->opackets++;
	statsp->obytes += size;
	if (is_bcast)
		statsp->brdcstxmt++;
	else if (is_mcast)
		statsp->multixmt++;

	/* send dring datamsg to the peer */
	if (ldcp->resched_peer) {

		rtbufp = &ldcp->tbufp[ldcp->resched_peer_txi];
		rtxdp = rtbufp->descp;

		if (rtxdp->hdr.dstate == VIO_DESC_READY) {
			rv = vgen_send_dringdata(ldcp,
			    (uint32_t)ldcp->resched_peer_txi, -1);
			if (rv != 0) {
				/* error: drop the packet */
				DWARN(vgenp, ldcp,
				    "failed sending dringdata msg "
				    "rv(%d) len(%d)\n", rv, size);
				statsp->oerrors++;
			} else {
				ldcp->resched_peer = B_FALSE;
			}

		}

	}

	mutex_exit(&ldcp->wrlock);

dringsend_exit:
	if (rv == ECONNRESET) {
		(void) vgen_handle_evt_reset(ldcp, VGEN_OTHER);
	}
	freemsg(mp);
	DBG1(vgenp, ldcp, "exit\n");
	return (VGEN_TX_SUCCESS);
}

mblk_t *
vgen_poll_rcv(vgen_ldc_t *ldcp, int bytes_to_pickup)
{
	mblk_t	*bp = NULL;
	mblk_t	*bpt = NULL;
	mblk_t	*mp = NULL;
	size_t	mblk_sz = 0;
	size_t	sz = 0;
	uint_t	count = 0;

	mutex_enter(&ldcp->pollq_lock);

	bp = ldcp->pollq_headp;
	while (bp != NULL) {
		/* get the size of this packet */
		mblk_sz = msgdsize(bp);

		/* if adding this pkt, exceeds the size limit, we are done. */
		if (sz + mblk_sz >  bytes_to_pickup) {
			break;
		}

		/* we have room for this packet */
		sz += mblk_sz;

		/* increment the # of packets being sent up */
		count++;

		/* track the last processed pkt */
		bpt = bp;

		/* get the next pkt */
		bp = bp->b_next;
	}

	if (count != 0) {
		/*
		 * picked up some packets; save the head of pkts to be sent up.
		 */
		mp = ldcp->pollq_headp;

		/* move the pollq_headp to skip over the pkts being sent up */
		ldcp->pollq_headp = bp;

		/* picked up all pending pkts in the queue; reset tail also */
		if (ldcp->pollq_headp == NULL) {
			ldcp->pollq_tailp = NULL;
		}

		/* terminate the tail of pkts to be sent up */
		bpt->b_next = NULL;
	}

	/*
	 * We prepend any high priority packets to the chain of packets; note
	 * that if we are already at the bytes_to_pickup limit, we might
	 * slightly exceed that in such cases. That should be ok, as these pkts
	 * are expected to be small in size and arrive at an interval in the
	 * the order of a few seconds.
	 */
	if (ldcp->rx_pktdata == vgen_handle_pkt_data &&
	    ldcp->rx_pri_head != NULL) {
		ldcp->rx_pri_tail->b_next = mp;
		mp = ldcp->rx_pri_head;
		ldcp->rx_pri_head = ldcp->rx_pri_tail = NULL;
	}

	mutex_exit(&ldcp->pollq_lock);

	return (mp);
}

/*
 * Process dring data messages (info/ack/nack)
 */
int
vgen_handle_dringdata(void *arg1, void *arg2)
{
	vgen_ldc_t	*ldcp = (vgen_ldc_t *)arg1;
	vio_msg_tag_t	*tagp = (vio_msg_tag_t *)arg2;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	int		rv = 0;

	DBG1(vgenp, ldcp, "enter\n");
	switch (tagp->vio_subtype) {

	case VIO_SUBTYPE_INFO:
		/*
		 * To reduce the locking contention, release the
		 * cblock here and re-acquire it once we are done
		 * receiving packets.
		 */
		mutex_exit(&ldcp->cblock);
		mutex_enter(&ldcp->rxlock);
		rv = vgen_handle_dringdata_info(ldcp, tagp);
		mutex_exit(&ldcp->rxlock);
		mutex_enter(&ldcp->cblock);
		break;

	case VIO_SUBTYPE_ACK:
		rv = vgen_handle_dringdata_ack(ldcp, tagp);
		break;

	case VIO_SUBTYPE_NACK:
		rv = vgen_handle_dringdata_nack(ldcp, tagp);
		break;
	}
	DBG1(vgenp, ldcp, "exit rv(%d)\n", rv);
	return (rv);
}

static int
vgen_handle_dringdata_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	uint32_t	start;
	int32_t		end;
	int		rv = 0;
	vio_dring_msg_t	*dringmsg = (vio_dring_msg_t *)tagp;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_stats_t	*statsp = &ldcp->stats;
#ifdef VGEN_HANDLE_LOST_PKTS
	uint32_t	rxi;
	int		n;
#endif

	DBG1(vgenp, ldcp, "enter\n");

	start = dringmsg->start_idx;
	end = dringmsg->end_idx;
	/*
	 * received a data msg, which contains the start and end
	 * indices of the descriptors within the rx ring holding data,
	 * the seq_num of data packet corresponding to the start index,
	 * and the dring_ident.
	 * We can now read the contents of each of these descriptors
	 * and gather data from it.
	 */
	DBG1(vgenp, ldcp, "INFO: start(%d), end(%d)\n",
	    start, end);

	/* validate rx start and end indexes */
	if (!(CHECK_RXI(start, ldcp)) || ((end != -1) &&
	    !(CHECK_RXI(end, ldcp)))) {
		DWARN(vgenp, ldcp, "Invalid Rx start(%d) or end(%d)\n",
		    start, end);
		/* drop the message if invalid index */
		return (rv);
	}

	/* validate dring_ident */
	if (dringmsg->dring_ident != ldcp->peer_hparams.dring_ident) {
		DWARN(vgenp, ldcp, "Invalid dring ident 0x%x\n",
		    dringmsg->dring_ident);
		/* invalid dring_ident, drop the msg */
		return (rv);
	}
#ifdef DEBUG
	if (vgen_inject_error(ldcp, VGEN_ERR_RXLOST)) {
		/* drop this msg to simulate lost pkts for debugging */
		vgen_inject_err_flag &= ~(VGEN_ERR_RXLOST);
		return (rv);
	}
#endif

	statsp->dring_data_msgs_rcvd++;

#ifdef	VGEN_HANDLE_LOST_PKTS

	/* receive start index doesn't match expected index */
	if (ldcp->next_rxi != start) {
		DWARN(vgenp, ldcp, "next_rxi(%d) != start(%d)\n",
		    ldcp->next_rxi, start);

		/* calculate the number of pkts lost */
		if (start >= ldcp->next_rxi) {
			n = start - ldcp->next_rxi;
		} else  {
			n = ldcp->num_rxds - (ldcp->next_rxi - start);
		}

		statsp->rx_lost_pkts += n;
		tagp->vio_subtype = VIO_SUBTYPE_NACK;
		tagp->vio_sid = ldcp->local_sid;
		/* indicate the range of lost descriptors */
		dringmsg->start_idx = ldcp->next_rxi;
		rxi = start;
		DECR_RXI(rxi, ldcp);
		dringmsg->end_idx = rxi;
		/* dring ident is left unchanged */
		rv = vgen_sendmsg(ldcp, (caddr_t)tagp,
		    sizeof (*dringmsg), B_FALSE);
		if (rv != VGEN_SUCCESS) {
			DWARN(vgenp, ldcp,
			    "vgen_sendmsg failed, stype:NACK\n");
			return (rv);
		}
		/*
		 * treat this range of descrs/pkts as dropped
		 * and set the new expected value of next_rxi
		 * and continue(below) to process from the new
		 * start index.
		 */
		ldcp->next_rxi = start;
	}

#endif	/* VGEN_HANDLE_LOST_PKTS */

	/* Now receive messages */
	rv = vgen_process_dringdata(ldcp, tagp);

	DBG1(vgenp, ldcp, "exit rv(%d)\n", rv);
	return (rv);
}

static int
vgen_process_dringdata(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	boolean_t		set_ack_start = B_FALSE;
	uint32_t		start;
	uint32_t		ack_end;
	uint32_t		next_rxi;
	uint32_t		rxi;
	int			count = 0;
	int			rv = 0;
	uint32_t		retries = 0;
	vgen_stats_t		*statsp;
	vnet_public_desc_t	rxd;
	vio_dring_entry_hdr_t	*hdrp;
	mblk_t 			*bp = NULL;
	mblk_t 			*bpt = NULL;
	uint32_t		ack_start;
	boolean_t		rxd_err = B_FALSE;
	mblk_t			*mp = NULL;
	vio_mblk_t		*vmp = NULL;
	size_t			nbytes;
	boolean_t		ack_needed = B_FALSE;
	size_t			nread;
	uint64_t		off = 0;
	struct ether_header	*ehp;
	vio_dring_msg_t		*dringmsg = (vio_dring_msg_t *)tagp;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vgen_hparams_t		*lp = &ldcp->local_hparams;

	DBG1(vgenp, ldcp, "enter\n");

	statsp = &ldcp->stats;
	start = dringmsg->start_idx;

	/*
	 * start processing the descriptors from the specified
	 * start index, up to the index a descriptor is not ready
	 * to be processed or we process the entire descriptor ring
	 * and wrap around upto the start index.
	 */

	/* need to set the start index of descriptors to be ack'd */
	set_ack_start = B_TRUE;

	/* index upto which we have ack'd */
	ack_end = start;
	DECR_RXI(ack_end, ldcp);

	next_rxi = rxi =  start;
	do {
vgen_recv_retry:
		rv = vnet_dring_entry_copy(&(ldcp->mrxdp[rxi]), &rxd,
		    ldcp->dring_mtype, ldcp->rx_dring_handle, rxi, rxi);
		if (rv != 0) {
			DWARN(vgenp, ldcp, "ldc_mem_dring_acquire() failed"
			    " rv(%d)\n", rv);
			statsp->ierrors++;
			return (rv);
		}

		hdrp = &rxd.hdr;

		if (hdrp->dstate != VIO_DESC_READY) {
			/*
			 * Before waiting and retry here, send up
			 * the packets that are received already
			 */
			if (bp != NULL) {
				DTRACE_PROBE1(vgen_rcv_msgs, int, count);
				vgen_rx(ldcp, bp, bpt);
				count = 0;
				bp = bpt = NULL;
			}
			/*
			 * descriptor is not ready.
			 * retry descriptor acquire, stop processing
			 * after max # retries.
			 */
			if (retries == vgen_recv_retries)
				break;
			retries++;
			drv_usecwait(vgen_recv_delay);
			goto vgen_recv_retry;
		}
		retries = 0;

		if (set_ack_start) {
			/*
			 * initialize the start index of the range
			 * of descriptors to be ack'd.
			 */
			ack_start = rxi;
			set_ack_start = B_FALSE;
		}

		if ((rxd.nbytes < ETHERMIN) ||
		    (rxd.nbytes > lp->mtu) ||
		    (rxd.ncookies == 0) ||
		    (rxd.ncookies > MAX_COOKIES)) {
			rxd_err = B_TRUE;
		} else {
			/*
			 * Try to allocate an mblk from the free pool
			 * of recv mblks for the channel.
			 * If this fails, use allocb().
			 */
			nbytes = (VNET_IPALIGN + rxd.nbytes + 7) & ~7;
			if (nbytes > ldcp->max_rxpool_size) {
				mp = allocb(VNET_IPALIGN + rxd.nbytes + 8,
				    BPRI_MED);
				vmp = NULL;
			} else {
				vmp = vio_multipool_allocb(&ldcp->vmp, nbytes);
				if (vmp == NULL) {
					statsp->rx_vio_allocb_fail++;
					/*
					 * Data buffer returned by allocb(9F)
					 * is 8byte aligned. We allocate extra
					 * 8 bytes to ensure size is multiple
					 * of 8 bytes for ldc_mem_copy().
					 */
					mp = allocb(VNET_IPALIGN +
					    rxd.nbytes + 8, BPRI_MED);
				} else {
					mp = vmp->mp;
				}
			}
		}
		if ((rxd_err) || (mp == NULL)) {
			/*
			 * rxd_err or allocb() failure,
			 * drop this packet, get next.
			 */
			if (rxd_err) {
				statsp->ierrors++;
				rxd_err = B_FALSE;
			} else {
				statsp->rx_allocb_fail++;
			}

			ack_needed = hdrp->ack;

			/* set descriptor done bit */
			rv = vnet_dring_entry_set_dstate(&(ldcp->mrxdp[rxi]),
			    ldcp->dring_mtype, ldcp->rx_dring_handle, rxi, rxi,
			    VIO_DESC_DONE);
			if (rv != 0) {
				DWARN(vgenp, ldcp,
				    "vnet_dring_entry_set_dstate err rv(%d)\n",
				    rv);
				return (rv);
			}

			if (ack_needed) {
				ack_needed = B_FALSE;
				/*
				 * sender needs ack for this packet,
				 * ack pkts upto this index.
				 */
				ack_end = rxi;

				rv = vgen_send_dringack(ldcp, tagp,
				    ack_start, ack_end,
				    VIO_DP_ACTIVE);
				if (rv != VGEN_SUCCESS) {
					goto error_ret;
				}

				/* need to set new ack start index */
				set_ack_start = B_TRUE;
			}
			goto vgen_next_rxi;
		}

		nread = nbytes;
		rv = ldc_mem_copy(ldcp->ldc_handle,
		    (caddr_t)mp->b_rptr, off, &nread,
		    rxd.memcookie, rxd.ncookies, LDC_COPY_IN);

		/* if ldc_mem_copy() failed */
		if (rv) {
			DWARN(vgenp, ldcp, "ldc_mem_copy err rv(%d)\n", rv);
			statsp->ierrors++;
			freemsg(mp);
			goto error_ret;
		}

		ack_needed = hdrp->ack;

		rv = vnet_dring_entry_set_dstate(&(ldcp->mrxdp[rxi]),
		    ldcp->dring_mtype, ldcp->rx_dring_handle, rxi, rxi,
		    VIO_DESC_DONE);
		if (rv != 0) {
			DWARN(vgenp, ldcp,
			    "vnet_dring_entry_set_dstate err rv(%d)\n", rv);
			freemsg(mp);
			goto error_ret;
		}

		mp->b_rptr += VNET_IPALIGN;

		if (ack_needed) {
			ack_needed = B_FALSE;
			/*
			 * sender needs ack for this packet,
			 * ack pkts upto this index.
			 */
			ack_end = rxi;

			rv = vgen_send_dringack(ldcp, tagp,
			    ack_start, ack_end, VIO_DP_ACTIVE);
			if (rv != VGEN_SUCCESS) {
				freemsg(mp);
				goto error_ret;
			}

			/* need to set new ack start index */
			set_ack_start = B_TRUE;
		}

		if (nread != nbytes) {
			DWARN(vgenp, ldcp,
			    "ldc_mem_copy nread(%lx), nbytes(%lx)\n",
			    nread, nbytes);
			statsp->ierrors++;
			freemsg(mp);
			goto vgen_next_rxi;
		}

		/* point to the actual end of data */
		mp->b_wptr = mp->b_rptr + rxd.nbytes;

		if (vmp != NULL) {
			vmp->state = VIO_MBLK_HAS_DATA;
		}

		/* update stats */
		statsp->ipackets++;
		statsp->rbytes += rxd.nbytes;
		ehp = (struct ether_header *)mp->b_rptr;
		if (IS_BROADCAST(ehp))
			statsp->brdcstrcv++;
		else if (IS_MULTICAST(ehp))
			statsp->multircv++;

		/* build a chain of received packets */
		if (bp == NULL) {
			/* first pkt */
			bp = mp;
			bpt = bp;
			bpt->b_next = NULL;
		} else {
			mp->b_next = NULL;
			bpt->b_next = mp;
			bpt = mp;
		}

		if (count++ > vgen_chain_len) {
			DTRACE_PROBE1(vgen_rcv_msgs, int, count);
			vgen_rx(ldcp, bp, bpt);
			count = 0;
			bp = bpt = NULL;
		}

vgen_next_rxi:
		/* update end index of range of descrs to be ack'd */
		ack_end = rxi;

		/* update the next index to be processed */
		INCR_RXI(next_rxi, ldcp);
		if (next_rxi == start) {
			/*
			 * processed the entire descriptor ring upto
			 * the index at which we started.
			 */
			break;
		}

		rxi = next_rxi;

	_NOTE(CONSTCOND)
	} while (1);

	/*
	 * send an ack message to peer indicating that we have stopped
	 * processing descriptors.
	 */
	if (set_ack_start) {
		/*
		 * We have ack'd upto some index and we have not
		 * processed any descriptors beyond that index.
		 * Use the last ack'd index as both the start and
		 * end of range of descrs being ack'd.
		 * Note: This results in acking the last index twice
		 * and should be harmless.
		 */
		ack_start = ack_end;
	}

	rv = vgen_send_dringack(ldcp, tagp, ack_start, ack_end,
	    VIO_DP_STOPPED);
	if (rv != VGEN_SUCCESS) {
		goto error_ret;
	}

	/* save new recv index of next dring msg */
	ldcp->next_rxi = next_rxi;

error_ret:
	/* send up packets received so far */
	if (bp != NULL) {
		DTRACE_PROBE1(vgen_rcv_msgs, int, count);
		vgen_rx(ldcp, bp, bpt);
		bp = bpt = NULL;
	}
	DBG1(vgenp, ldcp, "exit rv(%d)\n", rv);
	return (rv);

}

static int
vgen_handle_dringdata_ack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	int			rv = 0;
	uint32_t		start;
	int32_t			end;
	uint32_t		txi;
	boolean_t		ready_txd = B_FALSE;
	vgen_stats_t		*statsp;
	vgen_private_desc_t	*tbufp;
	vnet_public_desc_t	*txdp;
	vio_dring_entry_hdr_t	*hdrp;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_msg_t		*dringmsg = (vio_dring_msg_t *)tagp;

	DBG1(vgenp, ldcp, "enter\n");
	start = dringmsg->start_idx;
	end = dringmsg->end_idx;
	statsp = &ldcp->stats;

	/*
	 * received an ack corresponding to a specific descriptor for
	 * which we had set the ACK bit in the descriptor (during
	 * transmit). This enables us to reclaim descriptors.
	 */

	DBG2(vgenp, ldcp, "ACK:  start(%d), end(%d)\n", start, end);

	/* validate start and end indexes in the tx ack msg */
	if (!(CHECK_TXI(start, ldcp)) || !(CHECK_TXI(end, ldcp))) {
		/* drop the message if invalid index */
		DWARN(vgenp, ldcp, "Invalid Tx ack start(%d) or end(%d)\n",
		    start, end);
		return (rv);
	}
	/* validate dring_ident */
	if (dringmsg->dring_ident != ldcp->local_hparams.dring_ident) {
		/* invalid dring_ident, drop the msg */
		DWARN(vgenp, ldcp, "Invalid dring ident 0x%x\n",
		    dringmsg->dring_ident);
		return (rv);
	}
	statsp->dring_data_acks_rcvd++;

	/* reclaim descriptors that are done */
	vgen_reclaim(ldcp);

	if (dringmsg->dring_process_state != VIO_DP_STOPPED) {
		/*
		 * receiver continued processing descriptors after
		 * sending us the ack.
		 */
		return (rv);
	}

	statsp->dring_stopped_acks_rcvd++;

	/* receiver stopped processing descriptors */
	mutex_enter(&ldcp->wrlock);
	mutex_enter(&ldcp->tclock);

	/*
	 * determine if there are any pending tx descriptors
	 * ready to be processed by the receiver(peer) and if so,
	 * send a message to the peer to restart receiving.
	 */
	ready_txd = B_FALSE;

	/*
	 * using the end index of the descriptor range for which
	 * we received the ack, check if the next descriptor is
	 * ready.
	 */
	txi = end;
	INCR_TXI(txi, ldcp);
	tbufp = &ldcp->tbufp[txi];
	txdp = tbufp->descp;
	hdrp = &txdp->hdr;
	if (hdrp->dstate == VIO_DESC_READY) {
		ready_txd = B_TRUE;
	} else {
		/*
		 * descr next to the end of ack'd descr range is not
		 * ready.
		 * starting from the current reclaim index, check
		 * if any descriptor is ready.
		 */

		txi = ldcp->cur_tbufp - ldcp->tbufp;
		tbufp = &ldcp->tbufp[txi];

		txdp = tbufp->descp;
		hdrp = &txdp->hdr;
		if (hdrp->dstate == VIO_DESC_READY) {
			ready_txd = B_TRUE;
		}

	}

	if (ready_txd) {
		/*
		 * we have tx descriptor(s) ready to be
		 * processed by the receiver.
		 * send a message to the peer with the start index
		 * of ready descriptors.
		 */
		rv = vgen_send_dringdata(ldcp, txi, -1);
		if (rv != VGEN_SUCCESS) {
			ldcp->resched_peer = B_TRUE;
			ldcp->resched_peer_txi = txi;
			mutex_exit(&ldcp->tclock);
			mutex_exit(&ldcp->wrlock);
			return (rv);
		}
	} else {
		/*
		 * no ready tx descriptors. set the flag to send a
		 * message to peer when tx descriptors are ready in
		 * transmit routine.
		 */
		ldcp->resched_peer = B_TRUE;
		ldcp->resched_peer_txi = ldcp->cur_tbufp - ldcp->tbufp;
	}

	mutex_exit(&ldcp->tclock);
	mutex_exit(&ldcp->wrlock);
	DBG1(vgenp, ldcp, "exit rv(%d)\n", rv);
	return (rv);
}

static int
vgen_handle_dringdata_nack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	int			rv = 0;
	uint32_t		start;
	int32_t			end;
	uint32_t		txi;
	vnet_public_desc_t	*txdp;
	vio_dring_entry_hdr_t	*hdrp;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_msg_t		*dringmsg = (vio_dring_msg_t *)tagp;

	DBG1(vgenp, ldcp, "enter\n");
	start = dringmsg->start_idx;
	end = dringmsg->end_idx;

	/*
	 * peer sent a NACK msg to indicate lost packets.
	 * The start and end correspond to the range of descriptors
	 * for which the peer didn't receive a dring data msg and so
	 * didn't receive the corresponding data.
	 */
	DWARN(vgenp, ldcp, "NACK: start(%d), end(%d)\n", start, end);

	/* validate start and end indexes in the tx nack msg */
	if (!(CHECK_TXI(start, ldcp)) || !(CHECK_TXI(end, ldcp))) {
		/* drop the message if invalid index */
		DWARN(vgenp, ldcp, "Invalid Tx nack start(%d) or end(%d)\n",
		    start, end);
		return (rv);
	}
	/* validate dring_ident */
	if (dringmsg->dring_ident != ldcp->local_hparams.dring_ident) {
		/* invalid dring_ident, drop the msg */
		DWARN(vgenp, ldcp, "Invalid dring ident 0x%x\n",
		    dringmsg->dring_ident);
		return (rv);
	}
	mutex_enter(&ldcp->txlock);
	mutex_enter(&ldcp->tclock);

	if (ldcp->next_tbufp == ldcp->cur_tbufp) {
		/* no busy descriptors, bogus nack ? */
		mutex_exit(&ldcp->tclock);
		mutex_exit(&ldcp->txlock);
		return (rv);
	}

	/* we just mark the descrs as done so they can be reclaimed */
	for (txi = start; txi <= end; ) {
		txdp = &(ldcp->txdp[txi]);
		hdrp = &txdp->hdr;
		if (hdrp->dstate == VIO_DESC_READY)
			hdrp->dstate = VIO_DESC_DONE;
		INCR_TXI(txi, ldcp);
	}
	mutex_exit(&ldcp->tclock);
	mutex_exit(&ldcp->txlock);
	DBG1(vgenp, ldcp, "exit rv(%d)\n", rv);
	return (rv);
}

/*
 * Send received packets up the stack.
 */
static void
vgen_rx(vgen_ldc_t *ldcp, mblk_t *bp, mblk_t *bpt)
{
	vio_net_rx_cb_t vrx_cb = ldcp->portp->vcb.vio_net_rx_cb;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);

	if (ldcp->msg_thread != NULL) {
		ASSERT(MUTEX_HELD(&ldcp->rxlock));
	} else {
		ASSERT(MUTEX_HELD(&ldcp->cblock));
	}

	mutex_enter(&ldcp->pollq_lock);

	if (ldcp->polling_on == B_TRUE) {
		/*
		 * If we are in polling mode, simply queue
		 * the packets onto the poll queue and return.
		 */
		if (ldcp->pollq_headp == NULL) {
			ldcp->pollq_headp = bp;
			ldcp->pollq_tailp = bpt;
		} else {
			ldcp->pollq_tailp->b_next = bp;
			ldcp->pollq_tailp = bpt;
		}

		mutex_exit(&ldcp->pollq_lock);
		return;
	}

	/*
	 * Prepend any pending mblks in the poll queue, now that we
	 * are in interrupt mode, before sending up the chain of pkts.
	 */
	if (ldcp->pollq_headp != NULL) {
		DBG2(vgenp, ldcp, "vgen_rx(%lx), pending pollq_headp\n",
		    (uintptr_t)ldcp);
		ldcp->pollq_tailp->b_next = bp;
		bp = ldcp->pollq_headp;
		ldcp->pollq_headp = ldcp->pollq_tailp = NULL;
	}

	mutex_exit(&ldcp->pollq_lock);

	if (ldcp->msg_thread != NULL) {
		mutex_exit(&ldcp->rxlock);
	} else {
		mutex_exit(&ldcp->cblock);
	}

	/* Send up the packets */
	vrx_cb(ldcp->portp->vhp, bp);

	if (ldcp->msg_thread != NULL) {
		mutex_enter(&ldcp->rxlock);
	} else {
		mutex_enter(&ldcp->cblock);
	}
}

static void
vgen_reclaim(vgen_ldc_t *ldcp)
{
	mutex_enter(&ldcp->tclock);
	vgen_reclaim_dring(ldcp);
	ldcp->reclaim_lbolt = ddi_get_lbolt();
	mutex_exit(&ldcp->tclock);
}

/*
 * transmit reclaim function. starting from the current reclaim index
 * look for descriptors marked DONE and reclaim the descriptor.
 */
static void
vgen_reclaim_dring(vgen_ldc_t *ldcp)
{
	int			count = 0;
	vnet_public_desc_t	*txdp;
	vgen_private_desc_t	*tbufp;
	vio_dring_entry_hdr_t	*hdrp;

	tbufp = ldcp->cur_tbufp;
	txdp = tbufp->descp;
	hdrp = &txdp->hdr;

	while ((hdrp->dstate == VIO_DESC_DONE) &&
	    (tbufp != ldcp->next_tbufp)) {
		tbufp->flags = VGEN_PRIV_DESC_FREE;
		hdrp->dstate = VIO_DESC_FREE;
		hdrp->ack = B_FALSE;

		tbufp = NEXTTBUF(ldcp, tbufp);
		txdp = tbufp->descp;
		hdrp = &txdp->hdr;
		count++;
	}

	ldcp->cur_tbufp = tbufp;

	/*
	 * Check if mac layer should be notified to restart transmissions
	 */
	if ((ldcp->tx_blocked) && (count > 0)) {
		vio_net_tx_update_t vtx_update =
		    ldcp->portp->vcb.vio_net_tx_update;

		ldcp->tx_blocked = B_FALSE;
		vtx_update(ldcp->portp->vhp);
	}
}

/*
 * Send descriptor ring data message to the peer over ldc.
 */
static int
vgen_send_dringdata(vgen_ldc_t *ldcp, uint32_t start, int32_t end)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_msg_t	dringmsg, *msgp = &dringmsg;
	vio_msg_tag_t	*tagp = &msgp->tag;
	vgen_stats_t	*statsp = &ldcp->stats;
	int		rv;

#ifdef DEBUG
	if (vgen_inject_error(ldcp, VGEN_ERR_TXTIMEOUT)) {
		return (VGEN_SUCCESS);
	}
#endif
	bzero(msgp, sizeof (*msgp));

	tagp->vio_msgtype = VIO_TYPE_DATA;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_DRING_DATA;
	tagp->vio_sid = ldcp->local_sid;

	msgp->dring_ident = ldcp->local_hparams.dring_ident;
	msgp->start_idx = start;
	msgp->end_idx = end;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (dringmsg), B_TRUE);
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg failed\n");
		return (rv);
	}

	statsp->dring_data_msgs_sent++;

	DBG2(vgenp, ldcp, "DRING_DATA_SENT \n");

	return (VGEN_SUCCESS);
}

/*
 * Send dring data ack message.
 */
static int
vgen_send_dringack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp, uint32_t start,
    int32_t end, uint8_t pstate)
{
	int		rv = 0;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_msg_t	*msgp = (vio_dring_msg_t *)tagp;
	vgen_stats_t	*statsp = &ldcp->stats;

	tagp->vio_msgtype = VIO_TYPE_DATA;
	tagp->vio_subtype = VIO_SUBTYPE_ACK;
	tagp->vio_subtype_env = VIO_DRING_DATA;
	tagp->vio_sid = ldcp->local_sid;
	msgp->start_idx = start;
	msgp->end_idx = end;
	msgp->dring_process_state = pstate;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*msgp), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg() failed\n");
	}

	statsp->dring_data_acks_sent++;
	if (pstate == VIO_DP_STOPPED) {
		statsp->dring_stopped_acks_sent++;
	}

	return (rv);
}

/*
 * Wrapper routine to send the given message over ldc using ldc_write().
 */
int
vgen_sendmsg(vgen_ldc_t *ldcp, caddr_t msg,  size_t msglen,
    boolean_t caller_holds_lock)
{
	int			rv;
	size_t			len;
	uint32_t		retries = 0;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vio_msg_tag_t		*tagp = (vio_msg_tag_t *)msg;
	vio_dring_msg_t		*dmsg;
	vio_raw_data_msg_t	*rmsg;
	boolean_t		data_msg = B_FALSE;

	len = msglen;
	if ((len == 0) || (msg == NULL))
		return (VGEN_FAILURE);

	if (!caller_holds_lock) {
		mutex_enter(&ldcp->wrlock);
	}

	if (tagp->vio_subtype == VIO_SUBTYPE_INFO) {
		if (tagp->vio_subtype_env == VIO_DRING_DATA) {
			dmsg = (vio_dring_msg_t *)tagp;
			dmsg->seq_num = ldcp->next_txseq;
			data_msg = B_TRUE;
		} else if (tagp->vio_subtype_env == VIO_PKT_DATA) {
			rmsg = (vio_raw_data_msg_t *)tagp;
			rmsg->seq_num = ldcp->next_txseq;
			data_msg = B_TRUE;
		}
	}

	do {
		len = msglen;
		rv = ldc_write(ldcp->ldc_handle, (caddr_t)msg, &len);
		if (retries++ >= vgen_ldcwr_retries)
			break;
	} while (rv == EWOULDBLOCK);

	if (rv == 0 && data_msg == B_TRUE) {
		ldcp->next_txseq++;
	}

	if (!caller_holds_lock) {
		mutex_exit(&ldcp->wrlock);
	}

	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_write failed: rv(%d)\n",
		    rv, msglen);
		return (rv);
	}

	if (len != msglen) {
		DWARN(vgenp, ldcp, "ldc_write failed: rv(%d) msglen (%d)\n",
		    rv, msglen);
		return (VGEN_FAILURE);
	}

	return (VGEN_SUCCESS);
}

int
vgen_check_datamsg_seq(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vio_raw_data_msg_t	*rmsg;
	vio_dring_msg_t		*dmsg;
	uint64_t		seq_num;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);

	if (tagp->vio_subtype_env == VIO_DRING_DATA) {
		dmsg = (vio_dring_msg_t *)tagp;
		seq_num = dmsg->seq_num;
	} else if (tagp->vio_subtype_env == VIO_PKT_DATA) {
		rmsg = (vio_raw_data_msg_t *)tagp;
		seq_num = rmsg->seq_num;
	} else {
		return (EINVAL);
	}

	if (seq_num != ldcp->next_rxseq) {

		/* seqnums don't match */
		DWARN(vgenp, ldcp,
		    "next_rxseq(0x%lx) != seq_num(0x%lx)\n",
		    ldcp->next_rxseq, seq_num);
		return (EINVAL);

	}

	ldcp->next_rxseq++;

	return (0);
}

/*
 * vgen_ldc_msg_worker -- A per LDC worker thread. This thread is woken up by
 * the LDC interrupt handler to process LDC packets and receive data.
 */
void
vgen_ldc_msg_worker(void *arg)
{
	callb_cpr_t	cprinfo;
	vgen_ldc_t	*ldcp = (vgen_ldc_t *)arg;
	vgen_t 		*vgenp = LDC_TO_VGEN(ldcp);
	int		rv;

	DBG1(vgenp, ldcp, "enter\n");
	CALLB_CPR_INIT(&cprinfo, &ldcp->msg_thr_lock, callb_generic_cpr,
	    "vnet_rcv_thread");
	mutex_enter(&ldcp->msg_thr_lock);
	while (!(ldcp->msg_thr_flags & VGEN_WTHR_STOP)) {

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		/*
		 * Wait until the data is received or a stop
		 * request is received.
		 */
		while (!(ldcp->msg_thr_flags &
		    (VGEN_WTHR_DATARCVD | VGEN_WTHR_STOP))) {
			cv_wait(&ldcp->msg_thr_cv, &ldcp->msg_thr_lock);
		}
		CALLB_CPR_SAFE_END(&cprinfo, &ldcp->msg_thr_lock)

		/*
		 * First process the stop request.
		 */
		if (ldcp->msg_thr_flags & VGEN_WTHR_STOP) {
			DBG2(vgenp, ldcp, "stopped\n");
			break;
		}
		ldcp->msg_thr_flags &= ~VGEN_WTHR_DATARCVD;
		ldcp->msg_thr_flags |= VGEN_WTHR_PROCESSING;
		mutex_exit(&ldcp->msg_thr_lock);
		DBG2(vgenp, ldcp, "calling vgen_handle_evt_read\n");
		rv = vgen_handle_evt_read(ldcp, VGEN_MSG_THR);
		mutex_enter(&ldcp->msg_thr_lock);
		ldcp->msg_thr_flags &= ~VGEN_WTHR_PROCESSING;
		if (rv != 0) {
			/*
			 * Channel has been reset. The thread should now exit.
			 * The thread may be recreated if TxDring is negotiated
			 * on this channel after the channel comes back up
			 * again.
			 */
			ldcp->msg_thr_flags |= VGEN_WTHR_STOP;
			break;
		}
	}

	/*
	 * Update the run status and wakeup the thread that
	 * has sent the stop request.
	 */
	ldcp->msg_thr_flags &= ~VGEN_WTHR_STOP;
	ldcp->msg_thread = NULL;
	CALLB_CPR_EXIT(&cprinfo);

	thread_exit();
	DBG1(vgenp, ldcp, "exit\n");
}

/* vgen_stop_msg_thread -- Co-ordinate with receive thread to stop it */
void
vgen_stop_msg_thread(vgen_ldc_t *ldcp)
{
	kt_did_t	tid = 0;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);

	DBG1(vgenp, ldcp, "enter\n");
	/*
	 * Send a stop request by setting the stop flag and
	 * wait until the receive thread stops.
	 */
	mutex_enter(&ldcp->msg_thr_lock);
	if (ldcp->msg_thread != NULL) {
		tid = ldcp->msg_thread->t_did;
		ldcp->msg_thr_flags |= VGEN_WTHR_STOP;
		cv_signal(&ldcp->msg_thr_cv);
	}
	mutex_exit(&ldcp->msg_thr_lock);

	if (tid != 0) {
		thread_join(tid);
	}
	DBG1(vgenp, ldcp, "exit\n");
}
