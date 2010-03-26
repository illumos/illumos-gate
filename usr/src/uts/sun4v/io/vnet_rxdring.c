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
 * This file contains the implementation of RxDringData transfer mode of VIO
 * Protocol in vnet. The functions in this file are invoked from vnet_gen.c
 * after RxDringData mode is negotiated with the peer during attribute phase of
 * handshake. This file contains functions that setup the transmit and receive
 * descriptor rings, and associated resources in RxDringData mode. It also
 * contains the transmit and receive data processing functions that are invoked
 * in RxDringData mode. The data processing routines in this file have the
 * suffix '_shm' to indicate the shared memory mechanism used in RxDringData
 * mode.
 */

/* Functions exported to vnet_gen.c */
int vgen_create_rx_dring(vgen_ldc_t *ldcp);
void vgen_destroy_rx_dring(vgen_ldc_t *ldcp);
int vgen_map_tx_dring(vgen_ldc_t *ldcp, void *pkt);
void vgen_unmap_tx_dring(vgen_ldc_t *ldcp);
int vgen_map_data(vgen_ldc_t *ldcp, void *pkt);
int vgen_dringsend_shm(void *arg, mblk_t *mp);
int vgen_handle_dringdata_shm(void *arg1, void *arg2);
mblk_t *vgen_poll_rcv_shm(vgen_ldc_t *ldcp, int bytes_to_pickup);
int vgen_send_dringack_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
    uint32_t start, int32_t end, uint8_t pstate);

/* Internal functions */
static int vgen_handle_dringdata_info_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tp);
static int vgen_handle_dringdata_ack_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_dringdata_nack_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tp);
static int vgen_intr_rcv_shm(vgen_ldc_t *ldcp);
static int vgen_receive_packet(vgen_ldc_t *ldcp, mblk_t **bp, uint_t *size);
static int vgen_send_dringdata_shm(vgen_ldc_t *ldcp, uint32_t start,
    int32_t end);
static int vgen_sendmsg_shm(vgen_ldc_t *ldcp, caddr_t msg,  size_t msglen);

/* Functions imported from vnet_gen.c */
extern int vgen_handle_evt_read(vgen_ldc_t *ldcp, vgen_caller_t caller);
extern int vgen_handle_evt_reset(vgen_ldc_t *ldcp, vgen_caller_t caller);
extern void vgen_handle_pkt_data(void *arg1, void *arg2, uint32_t msglen);
extern void vgen_destroy_rxpools(void *arg);

/* Tunables */
extern uint32_t vnet_num_descriptors;
extern uint32_t vgen_chain_len;
extern uint32_t vgen_ldcwr_retries;
extern uint32_t vgen_recv_delay;
extern uint32_t vgen_recv_retries;
extern uint32_t vgen_nrbufs_factor;

#ifdef DEBUG

#define	DEBUG_PRINTF	vgen_debug_printf

extern int vnet_dbglevel;
extern int vgen_inject_err_flag;

extern void vgen_debug_printf(const char *fname, vgen_t *vgenp,
	vgen_ldc_t *ldcp, const char *fmt, ...);
extern boolean_t vgen_inject_error(vgen_ldc_t *ldcp, int error);

#endif

/*
 * Allocate receive resources for the channel. The resources consist of a
 * receive descriptor ring and an associated receive buffer area.
 */
int
vgen_create_rx_dring(vgen_ldc_t *ldcp)
{
	int 				i;
	int 				rv;
	uint32_t			ncookies;
	ldc_mem_info_t			minfo;
	vnet_rx_dringdata_desc_t	*rxdp;
	size_t				data_sz;
	vio_mblk_t			*vmp;
	vio_mblk_t			**rxdp_to_vmp;
	uint32_t			rxdsize;
	caddr_t				datap = NULL;
	vgen_t				*vgenp = LDC_TO_VGEN(ldcp);

	rxdsize = sizeof (vnet_rx_dringdata_desc_t);
	ldcp->num_rxds = vnet_num_descriptors;
	ldcp->num_rbufs = vnet_num_descriptors * vgen_nrbufs_factor;

	/* Create the receive descriptor ring */
	rv = ldc_mem_dring_create(ldcp->num_rxds, rxdsize,
	    &ldcp->rx_dring_handle);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_dring_create() failed\n");
		goto fail;
	}

	/* Get the addr of descriptor ring */
	rv = ldc_mem_dring_info(ldcp->rx_dring_handle, &minfo);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_dring_info() failed\n");
		goto fail;
	}
	ldcp->rxdp = (vnet_rx_dringdata_desc_t *)(minfo.vaddr);
	bzero(ldcp->rxdp, sizeof (*rxdp) * (ldcp->num_rxds));

	/*
	 * Allocate a table that maps descriptor to its associated buffer;
	 * used while receiving to validate that the peer has not changed the
	 * buffer offset provided in the descriptor.
	 */
	rxdp_to_vmp = kmem_zalloc(ldcp->num_rxds * sizeof (uintptr_t),
	    KM_SLEEP);
	ldcp->rxdp_to_vmp = rxdp_to_vmp;

	/*
	 * Allocate a single large buffer that serves as the rx buffer area.
	 * We allocate a ldc memory handle and export the buffer area as shared
	 * memory. We send the ldc memcookie for this buffer space to the peer,
	 * as part of dring registration phase during handshake. We manage this
	 * buffer area as individual buffers of max_frame_size and provide
	 * specific buffer offsets in each descriptor to the peer. Note that
	 * the factor used to compute the # of buffers (above) must be > 1 to
	 * ensure that there are more buffers than the # of descriptors. This
	 * is needed because, while the shared memory buffers are sent up our
	 * stack during receive, the sender needs additional buffers that can
	 * be used for further transmits. This also means there is no one to
	 * one correspondence between the descriptor index and buffer offset.
	 * The sender has to read the buffer offset in the descriptor and use
	 * the specified offset to copy the tx data into the shared buffer. We
	 * (receiver) manage the individual buffers and their state (see
	 * VIO_MBLK_STATEs in vio_util.h).
	 */
	data_sz = vgenp->max_frame_size + VNET_IPALIGN + VNET_LDCALIGN;
	data_sz = VNET_ROUNDUP_2K(data_sz);

	ldcp->rx_data_sz = data_sz * ldcp->num_rbufs;
	ldcp->rx_dblk_sz = data_sz;
	datap = kmem_zalloc(ldcp->rx_data_sz, KM_SLEEP);
	ldcp->rx_datap = datap;

	/* Allocate a ldc memhandle for the entire rx data area */
	rv = ldc_mem_alloc_handle(ldcp->ldc_handle, &ldcp->rx_data_handle);
	if (rv) {
		ldcp->rx_data_handle = 0;
		goto fail;
	}

	/* Allocate memory for the data cookies */
	ldcp->rx_data_cookie = kmem_zalloc(VNET_DATA_AREA_COOKIES *
	    sizeof (ldc_mem_cookie_t), KM_SLEEP);

	/*
	 * Bind ldc memhandle to the corresponding rx data area.
	 */
	ncookies = 0;
	rv = ldc_mem_bind_handle(ldcp->rx_data_handle, (caddr_t)datap,
	    ldcp->rx_data_sz, LDC_DIRECT_MAP, LDC_MEM_W,
	    ldcp->rx_data_cookie, &ncookies);
	if (rv != 0) {
		goto fail;
	}
	if ((ncookies == 0) || (ncookies > VNET_DATA_AREA_COOKIES)) {
		goto fail;
	}
	ldcp->rx_data_ncookies = ncookies;

	/*
	 * Successful in binding the handle to rx data area. Now setup mblks
	 * around each data buffer and setup the descriptors to point to these
	 * rx data buffers. We associate each descriptor with a buffer
	 * by specifying the buffer offset in the descriptor. When the peer
	 * needs to transmit data, this offset is read by the peer to determine
	 * the buffer in the mapped buffer area where the data to be
	 * transmitted should be copied, for a specific descriptor.
	 */
	rv = vio_create_mblks(ldcp->num_rbufs, data_sz, (uint8_t *)datap,
	    &ldcp->rx_vmp);
	if (rv != 0) {
		goto fail;
	}

	for (i = 0; i < ldcp->num_rxds; i++) {
		rxdp = &(ldcp->rxdp[i]);
		/* allocate an mblk around this data buffer */
		vmp = vio_allocb(ldcp->rx_vmp);
		ASSERT(vmp != NULL);
		rxdp->data_buf_offset = VIO_MBLK_DATA_OFF(vmp) + VNET_IPALIGN;
		rxdp->dstate = VIO_DESC_FREE;
		rxdp_to_vmp[i] = vmp;
	}

	/*
	 * The descriptors and the associated buffers are all ready;
	 * now bind descriptor ring to the channel.
	 */
	rv = ldc_mem_dring_bind(ldcp->ldc_handle, ldcp->rx_dring_handle,
	    LDC_DIRECT_MAP | LDC_SHADOW_MAP, LDC_MEM_RW,
	    &ldcp->rx_dring_cookie, &ncookies);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_dring_bind failed "
		    "rv(%x)\n", rv);
		goto fail;
	}
	ASSERT(ncookies == 1);
	ldcp->rx_dring_ncookies = ncookies;

	/* initialize rx seqnum and index */
	ldcp->next_rxseq = VNET_ISS;
	ldcp->next_rxi = 0;

	return (VGEN_SUCCESS);

fail:
	vgen_destroy_rx_dring(ldcp);
	return (VGEN_FAILURE);
}

/*
 * Free receive resources for the channel.
 */
void
vgen_destroy_rx_dring(vgen_ldc_t *ldcp)
{
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

	/* We first unbind the descriptor ring */
	if (ldcp->rx_dring_ncookies != 0) {
		(void) ldc_mem_dring_unbind(ldcp->rx_dring_handle);
		ldcp->rx_dring_ncookies = 0;
	}

	/* Destroy the mblks that are wrapped around the rx data buffers */
	if (ldcp->rx_vmp != NULL) {
		vio_clobber_pool(ldcp->rx_vmp);
		if (vio_destroy_mblks(ldcp->rx_vmp) != 0) {
			/*
			 * If we can't destroy the rx pool for this channel,
			 * dispatch a task to retry and clean up. Note that we
			 * don't need to wait for the task to complete. If the
			 * vnet device itself gets detached, it will wait for
			 * the task to complete implicitly in
			 * ddi_taskq_destroy().
			 */
			(void) ddi_taskq_dispatch(vgenp->rxp_taskq,
			    vgen_destroy_rxpools, ldcp->rx_vmp, DDI_SLEEP);
		}
		ldcp->rx_vmp = NULL;
	}

	/* Free rx data area cookies */
	if (ldcp->rx_data_cookie != NULL) {
		kmem_free(ldcp->rx_data_cookie, VNET_DATA_AREA_COOKIES *
		    sizeof (ldc_mem_cookie_t));
		ldcp->rx_data_cookie = NULL;
	}

	/* Unbind rx data area memhandle */
	if (ldcp->rx_data_ncookies != 0) {
		(void) ldc_mem_unbind_handle(ldcp->rx_data_handle);
		ldcp->rx_data_ncookies = 0;
	}

	/* Free rx data area memhandle */
	if (ldcp->rx_data_handle != 0) {
		(void) ldc_mem_free_handle(ldcp->rx_data_handle);
		ldcp->rx_data_handle = 0;
	}

	/* Now free the rx data area itself */
	if (ldcp->rx_datap != NULL) {
		/* prealloc'd rx data buffer */
		kmem_free(ldcp->rx_datap, ldcp->rx_data_sz);
		ldcp->rx_datap = NULL;
		ldcp->rx_data_sz = 0;
	}

	/* Finally, free the receive descriptor ring */
	if (ldcp->rx_dring_handle != 0) {
		(void) ldc_mem_dring_destroy(ldcp->rx_dring_handle);
		ldcp->rx_dring_handle = 0;
		ldcp->rxdp = NULL;
	}

	if (ldcp->rxdp_to_vmp != NULL) {
		kmem_free(ldcp->rxdp_to_vmp,
		    ldcp->num_rxds * sizeof (uintptr_t));
		ldcp->rxdp_to_vmp = NULL;
	}

	/* Reset rx index and seqnum */
	ldcp->next_rxi = 0;
	ldcp->next_rxseq = VNET_ISS;
}

/*
 * Map the receive descriptor ring exported
 * by the peer, as our transmit descriptor ring.
 */
int
vgen_map_tx_dring(vgen_ldc_t *ldcp, void *pkt)
{
	int				i;
	int				rv;
	ldc_mem_info_t			minfo;
	ldc_mem_cookie_t		dcookie;
	uint32_t			ncookies;
	uint32_t 			num_desc;
	uint32_t			desc_size;
	vnet_rx_dringdata_desc_t	*txdp;
	on_trap_data_t			otd;
	vio_dring_reg_msg_t 		*msg = pkt;

	ncookies = msg->ncookies;
	num_desc = msg->num_descriptors;
	desc_size = msg->descriptor_size;

	/*
	 * Sanity check.
	 */
	if (num_desc < VGEN_NUM_DESCRIPTORS_MIN ||
	    desc_size < sizeof (vnet_rx_dringdata_desc_t) ||
	    ncookies > 1) {
		goto fail;
	}

	bcopy(&msg->cookie[0], &dcookie, sizeof (ldc_mem_cookie_t));

	/* Map the remote dring */
	rv = ldc_mem_dring_map(ldcp->ldc_handle, &dcookie, ncookies, num_desc,
	    desc_size, LDC_DIRECT_MAP, &(ldcp->tx_dring_handle));
	if (rv != 0) {
		goto fail;
	}

	/*
	 * Sucessfully mapped; now try to get info about the mapped dring
	 */
	rv = ldc_mem_dring_info(ldcp->tx_dring_handle, &minfo);
	if (rv != 0) {
		goto fail;
	}

	/*
	 * Save ring address, number of descriptors.
	 */
	ldcp->mtxdp = (vnet_rx_dringdata_desc_t *)(minfo.vaddr);
	bcopy(&dcookie, &(ldcp->tx_dring_cookie), sizeof (dcookie));
	ldcp->tx_dring_ncookies = ncookies;
	ldcp->num_txds = num_desc;

	/* Initialize tx dring indexes and seqnum */
	ldcp->next_txi = ldcp->cur_txi = 0;
	ldcp->next_txseq = VNET_ISS - 1;
	ldcp->resched_peer = B_TRUE;
	ldcp->dring_mtype = minfo.mtype;
	ldcp->dringdata_msgid = 0;

	/* Save peer's dring_info values */
	bcopy(&dcookie, &(ldcp->peer_hparams.dring_cookie),
	    sizeof (ldc_mem_cookie_t));
	ldcp->peer_hparams.num_desc = num_desc;
	ldcp->peer_hparams.desc_size = desc_size;
	ldcp->peer_hparams.dring_ncookies = ncookies;

	/* Set dring_ident for the peer */
	ldcp->peer_hparams.dring_ident = (uint64_t)ldcp->mtxdp;

	/* Return the dring_ident in ack msg */
	msg->dring_ident = (uint64_t)ldcp->mtxdp;

	/*
	 * Mark the descriptor state as 'done'. This is implementation specific
	 * and not required by the protocol. In our implementation, we only
	 * need the descripor to be in 'done' state to be used by the transmit
	 * function and the peer is not aware of it. As the protocol requires
	 * that during initial registration the exporting end point mark the
	 * dstate as 'free', we change it 'done' here. After this, the dstate
	 * in our implementation will keep moving between 'ready', set by our
	 * transmit function; and and 'done', set by the peer (per protocol)
	 * after receiving data.
	 * Setup on_trap() protection before accessing dring shared memory area.
	 */
	rv = LDC_ON_TRAP(&otd);
	if (rv != 0) {
		/*
		 * Data access fault occured down the code path below while
		 * accessing the descriptors. Return failure.
		 */
		goto fail;
	}

	for (i = 0; i < num_desc; i++) {
		txdp = &ldcp->mtxdp[i];
		txdp->dstate = VIO_DESC_DONE;
	}

	(void) LDC_NO_TRAP();
	return (VGEN_SUCCESS);

fail:
	if (ldcp->tx_dring_handle != 0) {
		(void) ldc_mem_dring_unmap(ldcp->tx_dring_handle);
		ldcp->tx_dring_handle = 0;
	}
	return (VGEN_FAILURE);
}

/*
 * Unmap the transmit descriptor ring.
 */
void
vgen_unmap_tx_dring(vgen_ldc_t *ldcp)
{
	/* Unmap mapped tx data area */
	if (ldcp->tx_datap != NULL) {
		(void) ldc_mem_unmap(ldcp->tx_data_handle);
		ldcp->tx_datap = NULL;
	}

	/* Free tx data area handle */
	if (ldcp->tx_data_handle != 0) {
		(void) ldc_mem_free_handle(ldcp->tx_data_handle);
		ldcp->tx_data_handle = 0;
	}

	/* Free tx data area cookies */
	if (ldcp->tx_data_cookie != NULL) {
		kmem_free(ldcp->tx_data_cookie, ldcp->tx_data_ncookies *
		    sizeof (ldc_mem_cookie_t));
		ldcp->tx_data_cookie = NULL;
		ldcp->tx_data_ncookies = 0;
	}

	/* Unmap peer's dring */
	if (ldcp->tx_dring_handle != 0) {
		(void) ldc_mem_dring_unmap(ldcp->tx_dring_handle);
		ldcp->tx_dring_handle = 0;
	}

	/* clobber tx ring members */
	bzero(&ldcp->tx_dring_cookie, sizeof (ldcp->tx_dring_cookie));
	ldcp->mtxdp = NULL;
	ldcp->next_txi = ldcp->cur_txi = 0;
	ldcp->num_txds = 0;
	ldcp->next_txseq = VNET_ISS - 1;
	ldcp->resched_peer = B_TRUE;
}

/*
 * Map the shared memory data buffer area exported by the peer.
 */
int
vgen_map_data(vgen_ldc_t *ldcp, void *pkt)
{
	int			rv;
	vio_dring_reg_ext_msg_t	*emsg;
	vio_dring_reg_msg_t	*msg = (vio_dring_reg_msg_t *)pkt;
	uint8_t			*buf = (uint8_t *)msg->cookie;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);

	/* skip over dring cookies */
	ASSERT(msg->ncookies == 1);
	buf += (msg->ncookies * sizeof (ldc_mem_cookie_t));

	emsg = (vio_dring_reg_ext_msg_t *)buf;
	if (emsg->data_ncookies > VNET_DATA_AREA_COOKIES) {
		return (VGEN_FAILURE);
	}

	/* save # of data area cookies */
	ldcp->tx_data_ncookies = emsg->data_ncookies;

	/* save data area size */
	ldcp->tx_data_sz = emsg->data_area_size;

	/* allocate ldc mem handle for data area */
	rv = ldc_mem_alloc_handle(ldcp->ldc_handle, &ldcp->tx_data_handle);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_alloc_handle() failed: %d\n", rv);
		return (VGEN_FAILURE);
	}

	/* map the data area */
	rv = ldc_mem_map(ldcp->tx_data_handle, emsg->data_cookie,
	    emsg->data_ncookies, LDC_DIRECT_MAP, LDC_MEM_W,
	    (caddr_t *)&ldcp->tx_datap, NULL);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_mem_map() failed: %d\n", rv);
		(void) ldc_mem_free_handle(ldcp->tx_data_handle);
		ldcp->tx_data_handle = 0;
		return (VGEN_FAILURE);
	}

	/* allocate memory for data area cookies */
	ldcp->tx_data_cookie = kmem_zalloc(emsg->data_ncookies *
	    sizeof (ldc_mem_cookie_t), KM_SLEEP);

	/* save data area cookies */
	bcopy(emsg->data_cookie, ldcp->tx_data_cookie,
	    emsg->data_ncookies * sizeof (ldc_mem_cookie_t));

	return (VGEN_SUCCESS);
}

/*
 * This function transmits normal data frames (non-priority) over the channel.
 * It queues the frame into the transmit descriptor ring and sends a
 * VIO_DRING_DATA message if needed, to wake up the peer to (re)start
 * processing.
 */
int
vgen_dringsend_shm(void *arg, mblk_t *mp)
{
	uint32_t			next_txi;
	uint32_t			txi;
	vnet_rx_dringdata_desc_t	*txdp;
	vnet_rx_dringdata_desc_t	*ntxdp;
	struct ether_header		*ehp;
	size_t				mblksz;
	caddr_t				dst;
	mblk_t				*bp;
	size_t				size;
	uint32_t			buf_offset;
	on_trap_data_t			otd;
	int				rv = 0;
	boolean_t			is_bcast = B_FALSE;
	boolean_t			is_mcast = B_FALSE;
	vgen_ldc_t			*ldcp = (vgen_ldc_t *)arg;
	vgen_t				*vgenp = LDC_TO_VGEN(ldcp);
	vgen_stats_t			*statsp = &ldcp->stats;
	vgen_hparams_t			*lp = &ldcp->local_hparams;
	boolean_t			resched_peer = B_FALSE;
	boolean_t			tx_update = B_FALSE;

	/* Drop the packet if ldc is not up or handshake is not done */
	if (ldcp->ldc_status != LDC_UP) {
		DBG2(vgenp, ldcp, "status(%d), dropping packet\n",
		    ldcp->ldc_status);
		goto dringsend_shm_exit;
	}

	if (ldcp->hphase != VH_DONE) {
		DWARN(vgenp, ldcp, "hphase(%x), dropping packet\n",
		    ldcp->hphase);
		goto dringsend_shm_exit;
	}

	size = msgsize(mp);
	if (size > (size_t)lp->mtu) {
		DWARN(vgenp, ldcp, "invalid size(%d)\n", size);
		goto dringsend_shm_exit;
	}
	if (size < ETHERMIN)
		size = ETHERMIN;

	ehp = (struct ether_header *)mp->b_rptr;
	is_bcast = IS_BROADCAST(ehp);
	is_mcast = IS_MULTICAST(ehp);

	/*
	 * Setup on_trap() protection before accessing shared memory areas
	 * (descriptor and data buffer). Note that we enable this protection a
	 * little early and turn it off slightly later, than keeping it enabled
	 * strictly at the points in code below where the descriptor and data
	 * buffer are accessed. This is done for performance reasons:
	 * (a) to avoid calling the trap protection code while holding mutex.
	 * (b) to avoid multiple on/off steps for descriptor and data accesses.
	 */
	rv = LDC_ON_TRAP(&otd);
	if (rv != 0) {
		/*
		 * Data access fault occured down the code path below while
		 * accessing either the descriptor or the data buffer. Release
		 * any locks that we might have acquired in the code below and
		 * return failure.
		 */
		DERR(vgenp, ldcp, "data access fault occured\n");
		statsp->oerrors++;
		if (mutex_owned(&ldcp->txlock)) {
			mutex_exit(&ldcp->txlock);
		}
		if (mutex_owned(&ldcp->wrlock)) {
			mutex_exit(&ldcp->wrlock);
		}
		goto dringsend_shm_exit;
	}

	/*
	 * Allocate a descriptor
	 */
	mutex_enter(&ldcp->txlock);
	txi = next_txi = ldcp->next_txi;
	INCR_TXI(next_txi, ldcp);
	ntxdp = &(ldcp->mtxdp[next_txi]);
	if (ntxdp->dstate != VIO_DESC_DONE) { /* out of descriptors */
		if (ldcp->tx_blocked == B_FALSE) {
			ldcp->tx_blocked_lbolt = ddi_get_lbolt();
			ldcp->tx_blocked = B_TRUE;
		}
		statsp->tx_no_desc++;
		mutex_exit(&ldcp->txlock);
		(void) LDC_NO_TRAP();
		return (VGEN_TX_NORESOURCES);
	}

	if (ldcp->tx_blocked == B_TRUE) {
		ldcp->tx_blocked = B_FALSE;
		tx_update = B_TRUE;
	}

	/* Update descriptor ring index */
	ldcp->next_txi = next_txi;
	mutex_exit(&ldcp->txlock);

	if (tx_update == B_TRUE) {
		vio_net_tx_update_t vtx_update =
		    ldcp->portp->vcb.vio_net_tx_update;

		vtx_update(ldcp->portp->vhp);
	}

	/* Access the descriptor */
	txdp = &(ldcp->mtxdp[txi]);

	/* Ensure load ordering of dstate (above) and data_buf_offset. */
	MEMBAR_CONSUMER();

	/* Get the offset of the buffer to be used */
	buf_offset = txdp->data_buf_offset;

	/* Access the buffer using the offset */
	dst = (caddr_t)ldcp->tx_datap + buf_offset;

	/* Copy data into mapped transmit buffer */
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblksz = MBLKL(bp);
		bcopy(bp->b_rptr, dst, mblksz);
		dst += mblksz;
	}

	/* Set the size of data in the descriptor */
	txdp->nbytes = size;

	/*
	 * Ensure store ordering of nbytes and dstate (below); so that the peer
	 * sees the right nbytes value after it checks that the dstate is READY.
	 */
	MEMBAR_PRODUCER();

	mutex_enter(&ldcp->wrlock);

	/* Mark the descriptor ready */
	txdp->dstate = VIO_DESC_READY;

	/* Check if peer needs wake up (handled below) */
	if (ldcp->resched_peer == B_TRUE) {
		ldcp->resched_peer = B_FALSE;
		resched_peer = B_TRUE;
	}

	/* Update tx stats */
	statsp->opackets++;
	statsp->obytes += size;
	if (is_bcast)
		statsp->brdcstxmt++;
	else if (is_mcast)
		statsp->multixmt++;

	mutex_exit(&ldcp->wrlock);

	/*
	 * We are done accessing shared memory; clear trap protection.
	 */
	(void) LDC_NO_TRAP();

	/*
	 * Need to wake up the peer ?
	 */
	if (resched_peer == B_TRUE) {
		rv = vgen_send_dringdata_shm(ldcp, (uint32_t)txi, -1);
		if (rv != 0) {
			/* error: drop the packet */
			DWARN(vgenp, ldcp, "failed sending dringdata msg "
			    "rv(%d) len(%d)\n", rv, size);
			mutex_enter(&ldcp->wrlock);
			statsp->oerrors++;
			ldcp->resched_peer = B_TRUE;
			mutex_exit(&ldcp->wrlock);
		}
	}

dringsend_shm_exit:
	if (rv == ECONNRESET || rv == EACCES) {
		(void) vgen_handle_evt_reset(ldcp, VGEN_OTHER);
	}
	freemsg(mp);
	return (VGEN_TX_SUCCESS);
}

/*
 * Process dring data messages (info/ack/nack)
 */
int
vgen_handle_dringdata_shm(void *arg1, void *arg2)
{
	vgen_ldc_t	*ldcp = (vgen_ldc_t *)arg1;
	vio_msg_tag_t	*tagp = (vio_msg_tag_t *)arg2;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	int		rv = 0;

	switch (tagp->vio_subtype) {

	case VIO_SUBTYPE_INFO:
		/*
		 * To reduce the locking contention, release the
		 * cblock here and re-acquire it once we are done
		 * receiving packets.
		 */
		mutex_exit(&ldcp->cblock);
		mutex_enter(&ldcp->rxlock);
		rv = vgen_handle_dringdata_info_shm(ldcp, tagp);
		mutex_exit(&ldcp->rxlock);
		mutex_enter(&ldcp->cblock);
		if (rv != 0) {
			DWARN(vgenp, ldcp, "handle_data_info failed(%d)\n", rv);
		}
		break;

	case VIO_SUBTYPE_ACK:
		rv = vgen_handle_dringdata_ack_shm(ldcp, tagp);
		if (rv != 0) {
			DWARN(vgenp, ldcp, "handle_data_ack failed(%d)\n", rv);
		}
		break;

	case VIO_SUBTYPE_NACK:
		rv = vgen_handle_dringdata_nack_shm(ldcp, tagp);
		if (rv != 0) {
			DWARN(vgenp, ldcp, "handle_data_nack failed(%d)\n", rv);
		}
		break;
	}

	return (rv);
}

static int
vgen_handle_dringdata_info_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	uint32_t	start;
	int32_t		end;
	int		rv = 0;
	vio_dring_msg_t	*dringmsg = (vio_dring_msg_t *)tagp;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_stats_t	*statsp = &ldcp->stats;

	start = dringmsg->start_idx;
	end = dringmsg->end_idx;

	DBG1(vgenp, ldcp, "INFO: start(%d), end(%d)\n",
	    start, end);

	if (!(CHECK_RXI(start, ldcp)) ||
	    ((end != -1) && !(CHECK_RXI(end, ldcp)))) {
		DWARN(vgenp, ldcp, "Invalid Rx start(%d) or end(%d)\n",
		    start, end);
		/* drop the message if invalid index */
		return (0);
	}

	/* validate dring_ident */
	if (dringmsg->dring_ident != ldcp->peer_hparams.dring_ident) {
		DWARN(vgenp, ldcp, "Invalid dring ident 0x%x\n",
		    dringmsg->dring_ident);
		/* invalid dring_ident, drop the msg */
		return (0);
	}

	statsp->dring_data_msgs_rcvd++;

	/*
	 * If we are in polling mode, return from here without processing the
	 * dring. We will process the dring in the context of polling thread.
	 */
	if (ldcp->polling_on == B_TRUE) {
		return (0);
	}

	/*
	 * Process the dring and receive packets in intr context.
	 */
	rv = vgen_intr_rcv_shm(ldcp);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "vgen_intr_rcv_shm() failed\n");
	}
	return (rv);
}

/*
 * Process the rx descriptor ring in the context of interrupt thread
 * (vgen_ldc_cb() callback) and send the received packets up the stack.
 */
static int
vgen_intr_rcv_shm(vgen_ldc_t *ldcp)
{
	int		rv;
	uint32_t	end_ix;
	vio_dring_msg_t msg;
	uint_t		mblk_sz;
	int		count = 0;
	int		total_count = 0;
	mblk_t		*bp = NULL;
	mblk_t		*bpt = NULL;
	mblk_t		*mp = NULL;
	vio_net_rx_cb_t vrx_cb = ldcp->portp->vcb.vio_net_rx_cb;

	ASSERT(MUTEX_HELD(&ldcp->rxlock));

	do {
		rv = vgen_receive_packet(ldcp, &mp, &mblk_sz);
		if (rv != 0) {
			if (rv == EINVAL) {
				/* Invalid descriptor error; get next */
				continue;
			}
			DTRACE_PROBE1(vgen_intr_nopkts, vgen_ldc_t *, ldcp);
			break;
		}

		/* Build a chain of received packets */
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

		total_count++;
		count++;

		/*
		 * We are receiving the packets in interrupt context. If we
		 * have gathered vgen_chain_len (tunable) # of packets in the
		 * chain, send them up. (See vgen_poll_rcv_shm() for receiving
		 * in polling thread context).
		 */
		if (count == vgen_chain_len) {
			DTRACE_PROBE2(vgen_intr_pkts, vgen_ldc_t *, ldcp,
			    int, count);
			mutex_exit(&ldcp->rxlock);
			vrx_cb(ldcp->portp->vhp, bp);
			mutex_enter(&ldcp->rxlock);
			bp = bpt = NULL;
			count = 0;
		}

		/*
		 * Stop further processing if we processed the entire dring
		 * once; otherwise continue.
		 */
	} while (total_count < ldcp->num_rxds);

	if (bp != NULL) {
		DTRACE_PROBE2(vgen_intr_pkts, vgen_ldc_t *, ldcp, int, count);
		mutex_exit(&ldcp->rxlock);
		vrx_cb(ldcp->portp->vhp, bp);
		mutex_enter(&ldcp->rxlock);
	}

	if (ldcp->polling_on == B_FALSE) {
		/*
		 * We send a stopped message to peer (sender) while we are in
		 * intr mode only; allowing the peer to send further data intrs
		 * (dring data msgs) to us.
		 */
		end_ix = ldcp->next_rxi;
		DECR_RXI(end_ix, ldcp);
		msg.dring_ident = ldcp->peer_hparams.dring_ident;
		rv = vgen_send_dringack_shm(ldcp, (vio_msg_tag_t *)&msg,
		    VNET_START_IDX_UNSPEC, end_ix, VIO_DP_STOPPED);
		return (rv);
	}

	return (0);
}

/*
 * Process the rx descriptor ring in the context of mac polling thread. Receive
 * packets upto the limit specified by bytes_to_pickup or until there are no
 * more packets, whichever occurs first. Return the chain of received packets.
 */
mblk_t *
vgen_poll_rcv_shm(vgen_ldc_t *ldcp, int bytes_to_pickup)
{
	uint_t		mblk_sz = 0;
	uint_t		sz = 0;
	mblk_t		*bp = NULL;
	mblk_t		*bpt = NULL;
	mblk_t		*mp = NULL;
	int		count = 0;
	int		rv;

	mutex_enter(&ldcp->rxlock);

	if (ldcp->hphase != VH_DONE) {
		/* Channel is being reset and handshake not complete */
		mutex_exit(&ldcp->rxlock);
		return (NULL);
	}

	do {
		rv = vgen_receive_packet(ldcp, &mp, &mblk_sz);
		if (rv != 0) {
			if (rv == EINVAL) {
				/* Invalid descriptor error; get next */
				continue;
			}
			DTRACE_PROBE1(vgen_poll_nopkts, vgen_ldc_t *, ldcp);
			break;
		}

		/* Build a chain of received packets */
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

		/* Compute total size accumulated */
		sz += mblk_sz;
		count++;

		/* Reached the bytes limit; we are done. */
		if (sz >= bytes_to_pickup) {
			break;
		}

	_NOTE(CONSTCOND)
	} while (1);

	/*
	 * We prepend any high priority packets to the chain of packets; note
	 * that if we are already at the bytes_to_pickup limit, we might
	 * slightly exceed that in such cases. That should be ok, as these pkts
	 * are expected to be small in size and arrive at an interval in the
	 * the order of a few seconds.
	 */
	if (ldcp->rx_pktdata == vgen_handle_pkt_data &&
	    ldcp->rx_pri_head != NULL) {
		ldcp->rx_pri_tail->b_next = bp;
		bp = ldcp->rx_pri_head;
		ldcp->rx_pri_head = ldcp->rx_pri_tail = NULL;
	}

	mutex_exit(&ldcp->rxlock);

	DTRACE_PROBE2(vgen_poll_pkts, vgen_ldc_t *, ldcp, int, count);
	DTRACE_PROBE2(vgen_poll_bytes, vgen_ldc_t *, ldcp, uint_t, sz);
	return (bp);
}

/*
 * Process the next index in the rx dring and receive the associated packet.
 *
 * Returns:
 *	bp:	Success: The received packet.
 *		Failure: NULL
 *      size:	Success: Size of received packet.
 *		Failure: 0
 *      retval:
 *		Success: 0
 *		Failure: EAGAIN: Descriptor not ready
 *			 EIO:    Descriptor contents invalid.
 */
static int
vgen_receive_packet(vgen_ldc_t *ldcp, mblk_t **bp, uint_t *size)
{
	uint32_t			rxi;
	vio_mblk_t			*vmp;
	vio_mblk_t			*new_vmp;
	struct ether_header		*ehp;
	vnet_rx_dringdata_desc_t	*rxdp;
	int				err = 0;
	uint32_t			nbytes = 0;
	mblk_t				*mp = NULL;
	mblk_t				*dmp = NULL;
	vgen_stats_t			*statsp = &ldcp->stats;
	vgen_hparams_t			*lp = &ldcp->local_hparams;

	rxi = ldcp->next_rxi;
	rxdp = &(ldcp->rxdp[rxi]);
	vmp = ldcp->rxdp_to_vmp[rxi];

	if (rxdp->dstate != VIO_DESC_READY) {
		/*
		 * Descriptor is not ready.
		 */
		DTRACE_PROBE1(vgen_noready_rxds, vgen_ldc_t *, ldcp);
		return (EAGAIN);
	}

	/*
	 * Ensure load ordering of dstate and nbytes.
	 */
	MEMBAR_CONSUMER();

	nbytes = rxdp->nbytes;

	if ((nbytes < ETHERMIN) ||
	    (nbytes > lp->mtu) ||
	    (rxdp->data_buf_offset !=
	    (VIO_MBLK_DATA_OFF(vmp) + VNET_IPALIGN))) {
		/*
		 * Descriptor contents invalid.
		 */
		statsp->ierrors++;
		rxdp->dstate = VIO_DESC_DONE;
		err = EIO;
		goto done;
	}

	/*
	 * Now allocate a new buffer for this descriptor before sending up the
	 * buffer being processed. If that fails, stop processing; as we are
	 * out of receive buffers.
	 */
	new_vmp = vio_allocb(ldcp->rx_vmp);

	/*
	 * Process the current buffer being received.
	 */
	mp = vmp->mp;

	if (new_vmp == NULL) {
		/*
		 * We failed to get a new mapped buffer that is needed to
		 * refill the descriptor. In that case, leave the current
		 * buffer bound to the descriptor; allocate an mblk dynamically
		 * and copy the contents of the buffer to the mblk. Then send
		 * up this mblk. This way the sender has the same buffer as
		 * before that can be used to send new data.
		 */
		statsp->norcvbuf++;
		dmp = allocb(nbytes + VNET_IPALIGN, BPRI_MED);
		if (dmp == NULL) {
			statsp->ierrors++;
			return (ENOMEM);
		}
		bcopy(mp->b_rptr + VNET_IPALIGN,
		    dmp->b_rptr + VNET_IPALIGN, nbytes);
		mp = dmp;
	} else {
		/* Mark the status of the current rbuf */
		vmp->state = VIO_MBLK_HAS_DATA;

		/* Set the offset of the new buffer in the descriptor */
		rxdp->data_buf_offset =
		    VIO_MBLK_DATA_OFF(new_vmp) + VNET_IPALIGN;
		ldcp->rxdp_to_vmp[rxi] = new_vmp;
	}
	mp->b_rptr += VNET_IPALIGN;
	mp->b_wptr = mp->b_rptr + nbytes;

	/*
	 * Ensure store ordering of data_buf_offset and dstate; so that the
	 * peer sees the right data_buf_offset after it checks that the dstate
	 * is DONE.
	 */
	MEMBAR_PRODUCER();

	/* Now mark the descriptor 'done' */
	rxdp->dstate = VIO_DESC_DONE;

	/* Update stats */
	statsp->ipackets++;
	statsp->rbytes += rxdp->nbytes;
	ehp = (struct ether_header *)mp->b_rptr;
	if (IS_BROADCAST(ehp))
		statsp->brdcstrcv++;
	else if (IS_MULTICAST(ehp))
		statsp->multircv++;
done:
	/* Update the next index to be processed */
	INCR_RXI(rxi, ldcp);

	/* Save the new recv index */
	ldcp->next_rxi = rxi;

	/* Return the packet received */
	*size = nbytes;
	*bp = mp;
	return (err);
}

static int
vgen_handle_dringdata_ack_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	uint32_t			start;
	int32_t				end;
	uint32_t			txi;
	vgen_stats_t			*statsp;
	vnet_rx_dringdata_desc_t	*txdp;
	on_trap_data_t			otd;
	int				rv = 0;
	boolean_t			ready_txd = B_FALSE;
	vgen_t				*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_msg_t			*dringmsg = (vio_dring_msg_t *)tagp;

	start = dringmsg->start_idx;
	end = dringmsg->end_idx;
	statsp = &ldcp->stats;

	/*
	 * Received an ack for our transmits upto a certain dring index. This
	 * enables us to reclaim descriptors. We also send a new dring data msg
	 * to the peer to restart processing if there are pending transmit pkts.
	 */
	DBG2(vgenp, ldcp, "ACK:  start(%d), end(%d)\n", start, end);

	/*
	 * In RxDringData mode (v1.6), start index of -1 can be used by the
	 * peer to indicate that it is unspecified. However, the end index
	 * must be set correctly indicating the last descriptor index processed.
	 */
	if (((start != VNET_START_IDX_UNSPEC) && !(CHECK_TXI(start, ldcp))) ||
	    !(CHECK_TXI(end, ldcp))) {
		/* drop the message if invalid index */
		DWARN(vgenp, ldcp, "Invalid Tx ack start(%d) or end(%d)\n",
		    start, end);
		return (rv);
	}

	/* Validate dring_ident */
	if (dringmsg->dring_ident != ldcp->local_hparams.dring_ident) {
		/* invalid dring_ident, drop the msg */
		DWARN(vgenp, ldcp, "Invalid dring ident 0x%x\n",
		    dringmsg->dring_ident);
		return (rv);
	}
	statsp->dring_data_acks_rcvd++;

	/*
	 * Clear transmit flow control condition
	 * as some descriptors should be free now.
	 */
	mutex_enter(&ldcp->txlock);
	if (ldcp->tx_blocked == B_TRUE) {
		vio_net_tx_update_t vtx_update =
		    ldcp->portp->vcb.vio_net_tx_update;

		ldcp->tx_blocked = B_FALSE;
		vtx_update(ldcp->portp->vhp);
	}
	mutex_exit(&ldcp->txlock);

	if (dringmsg->dring_process_state != VIO_DP_STOPPED) {
		/*
		 * Receiver continued processing
		 * dring after sending us the ack.
		 */
		return (rv);
	}

	/*
	 * Receiver stopped processing descriptors.
	 */
	statsp->dring_stopped_acks_rcvd++;

	/*
	 * Setup on_trap() protection before accessing dring shared memory area.
	 */
	rv = LDC_ON_TRAP(&otd);
	if (rv != 0) {
		/*
		 * Data access fault occured down the code path below while
		 * accessing the descriptors. Release any locks that we might
		 * have acquired in the code below and return failure.
		 */
		if (mutex_owned(&ldcp->wrlock)) {
			mutex_exit(&ldcp->wrlock);
		}
		return (ECONNRESET);
	}

	/*
	 * Determine if there are any pending tx descriptors ready to be
	 * processed by the receiver(peer) and if so, send a message to the
	 * peer to restart receiving.
	 */
	mutex_enter(&ldcp->wrlock);

	ready_txd = B_FALSE;
	txi = end;
	INCR_TXI(txi, ldcp);
	txdp = &ldcp->mtxdp[txi];
	if (txdp->dstate == VIO_DESC_READY) {
		ready_txd = B_TRUE;
	}

	/*
	 * We are done accessing shared memory; clear trap protection.
	 */
	(void) LDC_NO_TRAP();

	if (ready_txd == B_FALSE) {
		/*
		 * No ready tx descriptors. Set the flag to send a message to
		 * the peer when tx descriptors are ready in transmit routine.
		 */
		ldcp->resched_peer = B_TRUE;
		mutex_exit(&ldcp->wrlock);
		return (rv);
	}

	/*
	 * We have some tx descriptors ready to be processed by the receiver.
	 * Send a dring data message to the peer to restart processing.
	 */
	ldcp->resched_peer = B_FALSE;
	mutex_exit(&ldcp->wrlock);
	rv = vgen_send_dringdata_shm(ldcp, txi, -1);
	if (rv != VGEN_SUCCESS) {
		mutex_enter(&ldcp->wrlock);
		ldcp->resched_peer = B_TRUE;
		mutex_exit(&ldcp->wrlock);
	}

	return (rv);
}

static int
vgen_handle_dringdata_nack_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	uint32_t			start;
	int32_t				end;
	uint32_t			txi;
	vnet_rx_dringdata_desc_t	*txdp;
	on_trap_data_t			otd;
	int				rv = 0;
	vgen_t				*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_msg_t			*dringmsg = (vio_dring_msg_t *)tagp;

	DBG1(vgenp, ldcp, "enter\n");
	start = dringmsg->start_idx;
	end = dringmsg->end_idx;

	/*
	 * Peer sent a NACK msg (to indicate bad descriptors ?). The start and
	 * end correspond to the range of descriptors which are being nack'd.
	 */
	DWARN(vgenp, ldcp, "NACK: start(%d), end(%d)\n", start, end);

	/*
	 * In RxDringData mode (v1.6), start index of -1 can be used by
	 * the peer to indicate that it is unspecified. However, the end index
	 * must be set correctly indicating the last descriptor index processed.
	 */
	if (((start != VNET_START_IDX_UNSPEC) && !(CHECK_TXI(start, ldcp))) ||
	    !(CHECK_TXI(end, ldcp))) {
		/* drop the message if invalid index */
		DWARN(vgenp, ldcp, "Invalid Tx nack start(%d) or end(%d)\n",
		    start, end);
		return (rv);
	}

	/* Validate dring_ident */
	if (dringmsg->dring_ident != ldcp->local_hparams.dring_ident) {
		/* invalid dring_ident, drop the msg */
		DWARN(vgenp, ldcp, "Invalid dring ident 0x%x\n",
		    dringmsg->dring_ident);
		return (rv);
	}

	/*
	 * Setup on_trap() protection before accessing dring shared memory area.
	 */
	rv = LDC_ON_TRAP(&otd);
	if (rv != 0) {
		/*
		 * Data access fault occured down the code path below while
		 * accessing the descriptors. Release any locks that we might
		 * have acquired in the code below and return failure.
		 */
		mutex_exit(&ldcp->txlock);
		return (ECONNRESET);
	}

	/* We just mark the descrs as free so they can be reused */
	mutex_enter(&ldcp->txlock);
	for (txi = start; txi <= end; ) {
		txdp = &(ldcp->mtxdp[txi]);
		if (txdp->dstate == VIO_DESC_READY)
			txdp->dstate = VIO_DESC_DONE;
		INCR_TXI(txi, ldcp);
	}

	/*
	 * We are done accessing shared memory; clear trap protection.
	 */
	(void) LDC_NO_TRAP();

	mutex_exit(&ldcp->txlock);

	return (rv);
}

/*
 * Send descriptor ring data message to the peer over LDC.
 */
static int
vgen_send_dringdata_shm(vgen_ldc_t *ldcp, uint32_t start, int32_t end)
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
	msgp->seq_num = atomic_inc_32_nv(&ldcp->dringdata_msgid);

	rv = vgen_sendmsg_shm(ldcp, (caddr_t)tagp, sizeof (dringmsg));
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg_shm() failed\n");
		return (rv);
	}

	statsp->dring_data_msgs_sent++;

	DBG2(vgenp, ldcp, "DRING_DATA_SENT \n");

	return (VGEN_SUCCESS);
}

/*
 * Send dring data ack message.
 */
int
vgen_send_dringack_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp, uint32_t start,
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
	msgp->seq_num = atomic_inc_32_nv(&ldcp->dringdata_msgid);

	rv = vgen_sendmsg_shm(ldcp, (caddr_t)tagp, sizeof (*msgp));
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg_shm() failed\n");
	}

	statsp->dring_data_acks_sent++;
	if (pstate == VIO_DP_STOPPED) {
		statsp->dring_stopped_acks_sent++;
	}

	return (rv);
}

/*
 * Send dring data msgs (info/ack/nack) over LDC.
 */
static int
vgen_sendmsg_shm(vgen_ldc_t *ldcp, caddr_t msg,  size_t msglen)
{
	int			rv;
	size_t			len;
	uint32_t		retries = 0;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);

	len = msglen;
	if ((len == 0) || (msg == NULL))
		return (VGEN_FAILURE);

	do {
		len = msglen;
		rv = ldc_write(ldcp->ldc_handle, (caddr_t)msg, &len);
		if (retries++ >= vgen_ldcwr_retries)
			break;
	} while (rv == EWOULDBLOCK);

	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_write failed: rv(%d) msglen(%d)\n",
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
