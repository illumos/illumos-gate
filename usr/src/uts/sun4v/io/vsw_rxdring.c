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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/mach_descrip.h>
#include <sys/mdeg.h>
#include <net/if.h>
#include <sys/vsw.h>
#include <sys/vio_mailbox.h>
#include <sys/vio_common.h>
#include <sys/vnet_common.h>
#include <sys/vnet_mailbox.h>
#include <sys/vio_util.h>

/*
 * This file contains the implementation of RxDringData transfer mode of VIO
 * Protocol in vsw. The functions in this file are invoked from vsw_ldc.c
 * after RxDringData mode is negotiated with the peer during attribute phase of
 * handshake. This file contains functions that setup the transmit and receive
 * descriptor rings, and associated resources in RxDringData mode. It also
 * contains the transmit and receive data processing functions that are invoked
 * in RxDringData mode. The data processing routines in this file have the
 * suffix '_shm' to indicate the shared memory mechanism used in RxDringData
 * mode.
 */

/* Functions exported to vsw_ldc.c */
vio_dring_reg_msg_t *vsw_create_rx_dring_info(vsw_ldc_t *);
void vsw_destroy_rx_dring(vsw_ldc_t *ldcp);
dring_info_t *vsw_map_tx_dring(vsw_ldc_t *ldcp, void *pkt);
void vsw_unmap_tx_dring(vsw_ldc_t *ldcp);
int vsw_dringsend_shm(vsw_ldc_t *, mblk_t *);
void vsw_ldc_rcv_worker(void *arg);
void vsw_stop_rcv_thread(vsw_ldc_t *ldcp);
void vsw_process_dringdata_shm(void *, void *);

/* Internal functions */
static dring_info_t *vsw_create_rx_dring(vsw_ldc_t *);
static int vsw_setup_rx_dring(vsw_ldc_t *ldcp, dring_info_t *dp);
static void vsw_process_dringdata_info_shm(vsw_ldc_t *ldcp,
	vio_dring_msg_t *msg);
static void vsw_process_dringdata_ack_shm(vsw_ldc_t *ldcp,
	vio_dring_msg_t *msg);
static void vsw_ldc_rcv_shm(vsw_ldc_t *ldcp);
static int vsw_receive_packet(vsw_ldc_t *ldcp, mblk_t **bp);
static int vsw_send_msg_shm(vsw_ldc_t *ldcp, void *msgp, int size,
    boolean_t handle_reset);

/* Functions imported from vsw_ldc.c */
extern void vsw_process_pkt(void *);
extern void vsw_destroy_rxpools(void *);
extern dring_info_t *vsw_map_dring_cmn(vsw_ldc_t *ldcp,
    vio_dring_reg_msg_t *dring_pkt);
extern void vsw_process_conn_evt(vsw_ldc_t *, uint16_t);
extern mblk_t *vsw_vlan_frame_pretag(void *arg, int type, mblk_t *mp);

/* Tunables */
extern int vsw_wretries;
extern int vsw_recv_delay;
extern int vsw_recv_retries;
extern uint32_t vsw_chain_len;
extern uint32_t vsw_num_descriptors;
extern uint32_t vsw_nrbufs_factor;

#define	VSW_SWITCH_FRAMES(vswp, ldcp, bp, bpt, count, total_count)	\
{									\
	DTRACE_PROBE2(vsw_rx_pkts, vsw_ldc_t *, (ldcp), int, (count));	\
	(vswp)->vsw_switch_frame((vswp), (bp), VSW_VNETPORT,		\
	    (ldcp)->ldc_port, NULL);					\
	(bp) = (bpt) = NULL;						\
	(count) = 0;							\
}

vio_dring_reg_msg_t *
vsw_create_rx_dring_info(vsw_ldc_t *ldcp)
{
	vio_dring_reg_msg_t	*mp;
	vio_dring_reg_ext_msg_t	*emsg;
	dring_info_t		*dp;
	uint8_t			*buf;
	vsw_t			*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s enter\n", __func__);

	/*
	 * If we can't create a dring, obviously no point sending
	 * a message.
	 */
	if ((dp = vsw_create_rx_dring(ldcp)) == NULL)
		return (NULL);

	mp = kmem_zalloc(VNET_DRING_REG_EXT_MSG_SIZE(dp->data_ncookies),
	    KM_SLEEP);

	mp->tag.vio_msgtype = VIO_TYPE_CTRL;
	mp->tag.vio_subtype = VIO_SUBTYPE_INFO;
	mp->tag.vio_subtype_env = VIO_DRING_REG;
	mp->tag.vio_sid = ldcp->local_session;

	/* payload */
	mp->num_descriptors = dp->num_descriptors;
	mp->descriptor_size = dp->descriptor_size;
	mp->options = dp->options;
	mp->ncookies = dp->dring_ncookies;
	bcopy(&dp->dring_cookie[0], &mp->cookie[0],
	    sizeof (ldc_mem_cookie_t));

	mp->dring_ident = 0;

	buf = (uint8_t *)mp->cookie;

	/* skip over dring cookies */
	ASSERT(mp->ncookies == 1);
	buf += (mp->ncookies * sizeof (ldc_mem_cookie_t));

	emsg = (vio_dring_reg_ext_msg_t *)buf;

	/* copy data_ncookies in the msg */
	emsg->data_ncookies = dp->data_ncookies;

	/* copy data area size in the msg */
	emsg->data_area_size = dp->data_sz;

	/* copy data area cookies in the msg */
	bcopy(dp->data_cookie, (ldc_mem_cookie_t *)emsg->data_cookie,
	    sizeof (ldc_mem_cookie_t) * dp->data_ncookies);

	D1(vswp, "%s exit\n", __func__);

	return (mp);
}

/*
 * Allocate receive resources for the channel. The resources consist of a
 * receive descriptor ring and an associated receive buffer area.
 */
static dring_info_t *
vsw_create_rx_dring(vsw_ldc_t *ldcp)
{
	vsw_t			*vswp = ldcp->ldc_vswp;
	ldc_mem_info_t		minfo;
	dring_info_t		*dp;

	dp = (dring_info_t *)kmem_zalloc(sizeof (dring_info_t), KM_SLEEP);
	mutex_init(&dp->dlock, NULL, MUTEX_DRIVER, NULL);
	ldcp->lane_out.dringp = dp;

	/* Create the receive descriptor ring */
	if ((ldc_mem_dring_create(vsw_num_descriptors,
	    sizeof (vnet_rx_dringdata_desc_t), &dp->dring_handle)) != 0) {
		DERR(vswp, "vsw_create_rx_dring(%lld): ldc dring create "
		    "failed", ldcp->ldc_id);
		goto fail;
	}

	ASSERT(dp->dring_handle != NULL);

	/* Get the addr of descriptor ring */
	if ((ldc_mem_dring_info(dp->dring_handle, &minfo)) != 0) {
		DERR(vswp, "vsw_create_rx_dring(%lld): dring info failed\n",
		    ldcp->ldc_id);
		goto fail;
	} else {
		ASSERT(minfo.vaddr != 0);
		dp->pub_addr = minfo.vaddr;
	}

	dp->num_descriptors = vsw_num_descriptors;
	dp->descriptor_size = sizeof (vnet_rx_dringdata_desc_t);
	dp->options = VIO_RX_DRING_DATA;
	dp->dring_ncookies = 1;	/* guaranteed by ldc */
	dp->num_bufs = VSW_RXDRING_NRBUFS;

	/*
	 * Allocate a table that maps descriptor to its associated buffer;
	 * used while receiving to validate that the peer has not changed the
	 * buffer offset provided in the descriptor.
	 */
	dp->rxdp_to_vmp = kmem_zalloc(dp->num_descriptors * sizeof (uintptr_t),
	    KM_SLEEP);

	/* Setup the descriptor ring */
	if (vsw_setup_rx_dring(ldcp, dp)) {
		DERR(vswp, "%s: unable to setup ring", __func__);
		goto fail;
	}

	/*
	 * The descriptors and the associated buffers are all ready;
	 * now bind descriptor ring to the channel.
	 */
	if ((ldc_mem_dring_bind(ldcp->ldc_handle, dp->dring_handle,
	    LDC_DIRECT_MAP | LDC_SHADOW_MAP, LDC_MEM_RW,
	    &dp->dring_cookie[0], &dp->dring_ncookies)) != 0) {
		DERR(vswp, "vsw_create_rx_dring: unable to bind to channel "
		    "%lld", ldcp->ldc_id);
		goto fail;
	}

	/* haven't used any descriptors yet */
	dp->end_idx = 0;
	dp->last_ack_recv = -1;
	dp->next_rxi = 0;
	return (dp);

fail:
	vsw_destroy_rx_dring(ldcp);
	return (NULL);
}

/*
 * Setup the descriptors in the rx dring.
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_setup_rx_dring(vsw_ldc_t *ldcp, dring_info_t *dp)
{
	int				i, j;
	int				rv;
	size_t				data_sz;
	vio_mblk_t			*vmp;
	vio_mblk_t			**rxdp_to_vmp;
	vnet_rx_dringdata_desc_t	*rxdp;
	vnet_rx_dringdata_desc_t	*pub_addr;
	vsw_t				*vswp = ldcp->ldc_vswp;
	uint32_t			ncookies = 0;
	static char			*name = "vsw_setup_rx_dring";
	void				*data_addr = NULL;

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
	data_sz = RXDRING_DBLK_SZ(vswp->max_frame_size);

	dp->desc_data_sz = data_sz;
	dp->data_sz = (dp->num_bufs * data_sz);
	data_addr = kmem_zalloc(dp->data_sz, KM_SLEEP);
	dp->data_addr = data_addr;

	D2(vswp, "%s: allocated %lld bytes at 0x%llx\n", name,
	    dp->data_sz, dp->data_addr);

	/* Allocate a ldc memhandle for the entire rx data area */
	rv = ldc_mem_alloc_handle(ldcp->ldc_handle, &dp->data_handle);
	if (rv != 0) {
		DERR(vswp, "%s: alloc mem handle failed", name);
		goto fail;
	}

	/* Allocate memory for the data cookies */
	dp->data_cookie = kmem_zalloc(VNET_DATA_AREA_COOKIES *
	    sizeof (ldc_mem_cookie_t), KM_SLEEP);

	/*
	 * Bind ldc memhandle to the corresponding rx data area.
	 */
	rv = ldc_mem_bind_handle(dp->data_handle, (caddr_t)data_addr,
	    dp->data_sz, LDC_DIRECT_MAP, LDC_MEM_W,
	    dp->data_cookie, &ncookies);
	if (rv != 0) {
		DERR(vswp, "%s(%lld): ldc_mem_bind_handle failed "
		    "(rv %d)", name, ldcp->ldc_id, rv);
		goto fail;
	}
	if ((ncookies == 0) || (ncookies > VNET_DATA_AREA_COOKIES)) {
		goto fail;
	}
	dp->data_ncookies = ncookies;

	for (j = 1; j < ncookies; j++) {
		rv = ldc_mem_nextcookie(dp->data_handle,
		    &(dp->data_cookie[j]));
		if (rv != 0) {
			DERR(vswp, "%s: ldc_mem_nextcookie "
			    "failed rv (%d)", name, rv);
			goto fail;
		}
	}

	/*
	 * Successful in binding the handle to rx data area. Now setup mblks
	 * around each data buffer and setup the descriptors to point to these
	 * rx data buffers. We associate each descriptor with a buffer
	 * by specifying the buffer offset in the descriptor. When the peer
	 * needs to transmit data, this offset is read by the peer to determine
	 * the buffer in the mapped buffer area where the data to be
	 * transmitted should be copied, for a specific descriptor.
	 */
	rv = vio_create_mblks(dp->num_bufs, data_sz, (uint8_t *)data_addr,
	    &dp->rx_vmp);
	if (rv != 0) {
		goto fail;
	}

	pub_addr = dp->pub_addr;
	rxdp_to_vmp = dp->rxdp_to_vmp;
	for (i = 0; i < dp->num_descriptors; i++) {
		rxdp = &pub_addr[i];
		/* allocate an mblk around this data buffer */
		vmp = vio_allocb(dp->rx_vmp);
		ASSERT(vmp != NULL);
		rxdp->data_buf_offset = VIO_MBLK_DATA_OFF(vmp) + VNET_IPALIGN;
		rxdp->dstate = VIO_DESC_FREE;
		rxdp_to_vmp[i] = vmp;
	}

	return (0);

fail:
	/* return failure; caller will cleanup */
	return (1);
}

/*
 * Free receive resources for the channel.
 */
void
vsw_destroy_rx_dring(vsw_ldc_t *ldcp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lp = &ldcp->lane_out;
	dring_info_t	*dp;

	dp = lp->dringp;
	if (dp == NULL) {
		return;
	}

	mutex_enter(&dp->dlock);

	if (dp->rx_vmp != NULL) {
		vio_clobber_pool(dp->rx_vmp);
		/*
		 * If we can't destroy the rx pool for this channel, dispatch a
		 * task to retry and clean up those rx pools. Note that we
		 * don't need to wait for the task to complete. If the vsw
		 * device itself gets detached (vsw_detach()), it will wait for
		 * the task to complete implicitly in ddi_taskq_destroy().
		 */
		if (vio_destroy_mblks(dp->rx_vmp) != 0)  {
			(void) ddi_taskq_dispatch(vswp->rxp_taskq,
			    vsw_destroy_rxpools, dp->rx_vmp, DDI_SLEEP);
		}
	}

	/* Free rx data area cookies */
	if (dp->data_cookie != NULL) {
		kmem_free(dp->data_cookie, VNET_DATA_AREA_COOKIES *
		    sizeof (ldc_mem_cookie_t));
		dp->data_cookie = NULL;
	}

	/* Unbind rx data area memhandle */
	if (dp->data_ncookies != 0) {
		(void) ldc_mem_unbind_handle(dp->data_handle);
		dp->data_ncookies = 0;
	}

	/* Free rx data area memhandle */
	if (dp->data_handle) {
		(void) ldc_mem_free_handle(dp->data_handle);
		dp->data_handle = 0;
	}

	/* Now free the rx data area itself */
	if (dp->data_addr != NULL) {
		kmem_free(dp->data_addr, dp->data_sz);
	}

	/* Finally, free the receive descriptor ring */
	if (dp->dring_handle != 0) {
		(void) ldc_mem_dring_unbind(dp->dring_handle);
		(void) ldc_mem_dring_destroy(dp->dring_handle);
	}

	if (dp->rxdp_to_vmp != NULL) {
		kmem_free(dp->rxdp_to_vmp,
		    dp->num_descriptors * sizeof (uintptr_t));
		dp->rxdp_to_vmp = NULL;
	}

	mutex_exit(&dp->dlock);
	mutex_destroy(&dp->dlock);
	mutex_destroy(&dp->restart_lock);
	kmem_free(dp, sizeof (dring_info_t));
	lp->dringp = NULL;
}

/*
 * Map the receive descriptor ring exported by the peer, as our transmit
 * descriptor ring.
 */
dring_info_t *
vsw_map_tx_dring(vsw_ldc_t *ldcp, void *pkt)
{
	int				i;
	int				rv;
	dring_info_t			*dp;
	vnet_rx_dringdata_desc_t	*txdp;
	on_trap_data_t			otd;
	vio_dring_reg_msg_t		*dring_pkt = pkt;

	dp = vsw_map_dring_cmn(ldcp, dring_pkt);
	if (dp == NULL) {
		return (NULL);
	}

	/* RxDringData mode specific initializations */
	mutex_init(&dp->txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dp->restart_lock, NULL, MUTEX_DRIVER, NULL);
	dp->next_txi = dp->restart_peer_txi = 0;
	dp->restart_reqd = B_TRUE;
	ldcp->dringdata_msgid = 0;
	ldcp->lane_in.dringp = dp;

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

	txdp = (vnet_rx_dringdata_desc_t *)dp->pub_addr;
	for (i = 0; i < dp->num_descriptors; i++) {
		txdp[i].dstate = VIO_DESC_DONE;
	}

	(void) LDC_NO_TRAP();

	return (dp);

fail:
	if (dp->dring_handle != 0) {
		(void) ldc_mem_dring_unmap(dp->dring_handle);
	}
	kmem_free(dp, sizeof (*dp));
	return (NULL);
}

/*
 * Unmap the transmit descriptor ring.
 */
void
vsw_unmap_tx_dring(vsw_ldc_t *ldcp)
{
	lane_t		*lp = &ldcp->lane_in;
	dring_info_t	*dp;

	if ((dp = lp->dringp) == NULL) {
		return;
	}

	/* Unmap tx data area and free data handle */
	if (dp->data_handle != 0) {
		(void) ldc_mem_unmap(dp->data_handle);
		(void) ldc_mem_free_handle(dp->data_handle);
		dp->data_handle = 0;
	}

	/* Free tx data area cookies */
	if (dp->data_cookie != NULL) {
		kmem_free(dp->data_cookie, dp->data_ncookies *
		    sizeof (ldc_mem_cookie_t));
		dp->data_cookie = NULL;
		dp->data_ncookies = 0;
	}

	/* Unmap peer's dring */
	if (dp->dring_handle != 0) {
		(void) ldc_mem_dring_unmap(dp->dring_handle);
		dp->dring_handle = 0;
	}

	mutex_destroy(&dp->txlock);
	kmem_free(dp, sizeof (dring_info_t));
	lp->dringp = NULL;
}

/*
 * A per LDC worker thread to process the rx dring and receive packets. This
 * thread is woken up by the LDC interrupt handler when a dring data info
 * message is received.
 */
void
vsw_ldc_rcv_worker(void *arg)
{
	callb_cpr_t	cprinfo;
	vsw_ldc_t	*ldcp = (vsw_ldc_t *)arg;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	CALLB_CPR_INIT(&cprinfo, &ldcp->rcv_thr_lock, callb_generic_cpr,
	    "vsw_rcv_thread");
	mutex_enter(&ldcp->rcv_thr_lock);
	while (!(ldcp->rcv_thr_flags & VSW_WTHR_STOP)) {

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		/*
		 * Wait until the data is received or a stop
		 * request is received.
		 */
		while (!(ldcp->rcv_thr_flags &
		    (VSW_WTHR_DATARCVD | VSW_WTHR_STOP))) {
			cv_wait(&ldcp->rcv_thr_cv, &ldcp->rcv_thr_lock);
		}
		CALLB_CPR_SAFE_END(&cprinfo, &ldcp->rcv_thr_lock)

		/*
		 * First process the stop request.
		 */
		if (ldcp->rcv_thr_flags & VSW_WTHR_STOP) {
			D2(vswp, "%s(%lld):Rx thread stopped\n",
			    __func__, ldcp->ldc_id);
			break;
		}
		ldcp->rcv_thr_flags &= ~VSW_WTHR_DATARCVD;
		mutex_exit(&ldcp->rcv_thr_lock);
		D1(vswp, "%s(%lld):calling vsw_process_pkt\n",
		    __func__, ldcp->ldc_id);
		vsw_ldc_rcv_shm(ldcp);
		mutex_enter(&ldcp->rcv_thr_lock);
	}

	/*
	 * Update the run status and wakeup the thread that
	 * has sent the stop request.
	 */
	ldcp->rcv_thr_flags &= ~VSW_WTHR_STOP;
	ldcp->rcv_thread = NULL;
	CALLB_CPR_EXIT(&cprinfo);
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
	thread_exit();
}

/*
 * Process the rx descriptor ring in the context of receive worker
 * thread and switch the received packets to their destinations.
 */
static void
vsw_ldc_rcv_shm(vsw_ldc_t *ldcp)
{
	int		rv;
	uint32_t	end_ix;
	vio_dring_msg_t msg;
	vio_dring_msg_t	*msgp = &msg;
	int		count = 0;
	int		total_count = 0;
	uint32_t	retries = 0;
	mblk_t		*bp = NULL;
	mblk_t		*bpt = NULL;
	mblk_t		*mp = NULL;
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lp = &ldcp->lane_out;
	dring_info_t	*dp = lp->dringp;

	do {
again:
		rv = vsw_receive_packet(ldcp, &mp);
		if (rv != 0) {
			if (rv == EINVAL) {
				/* Invalid descriptor error; get next */
				continue;
			}
			if (rv != EAGAIN) {
				break;
			}

			/* Descriptor not ready for processsing */
			if (retries == vsw_recv_retries) {
				DTRACE_PROBE1(vsw_noready_rxds,
				    vsw_ldc_t *, ldcp);
				break;
			}

			/* Switch packets received so far before retrying */
			if (bp != NULL) {
				VSW_SWITCH_FRAMES(vswp, ldcp, bp, bpt, count,
				    total_count);
			}
			retries++;
			drv_usecwait(vsw_recv_delay);
			goto again;
		}
		retries = 0;

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
		 * If we have gathered vsw_chain_len (tunable)
		 * # of packets in the chain, switch them.
		 */
		if (count == vsw_chain_len) {
			VSW_SWITCH_FRAMES(vswp, ldcp, bp, bpt, count,
			    total_count);
		}

		/*
		 * Stop further processing if we processed the entire dring
		 * once; otherwise continue.
		 */
	} while (total_count < dp->num_bufs);

	DTRACE_PROBE2(vsw_rx_total_count, vsw_ldc_t *, ldcp,
	    int, (total_count));
	if (bp != NULL) {
		VSW_SWITCH_FRAMES(vswp, ldcp, bp, bpt, count,
		    total_count);
	}

	/* Send stopped signal to peer (sender) */
	end_ix = lp->dringp->next_rxi;
	DECR_RXI(dp, end_ix);
	msgp->tag.vio_msgtype = VIO_TYPE_DATA;
	msgp->tag.vio_subtype = VIO_SUBTYPE_ACK;
	msgp->tag.vio_subtype_env = VIO_DRING_DATA;
	msgp->dring_ident = ldcp->lane_in.dringp->ident;
	msgp->tag.vio_sid = ldcp->local_session;
	msgp->dring_process_state = VIO_DP_STOPPED;
	msgp->start_idx = VNET_START_IDX_UNSPEC;
	msgp->end_idx = end_ix;

	(void) vsw_send_msg_shm(ldcp, (void *)msgp,
	    sizeof (vio_dring_msg_t), B_TRUE);

	ldcp->ldc_stats.dring_data_acks_sent++;
	ldcp->ldc_stats.dring_stopped_acks_sent++;
}

/*
 * Process the next index in the rx dring and receive the associated packet.
 *
 * Returns:
 *	bp:	Success: The received packet.
 *		Failure: NULL
 *      retval:
 *		Success: 0
 *		Failure: EAGAIN: Descriptor not ready
 *			 EIO:    Descriptor contents invalid.
 */
static int
vsw_receive_packet(vsw_ldc_t *ldcp, mblk_t **bp)
{
	uint32_t			rxi;
	vio_mblk_t			*vmp;
	vio_mblk_t			*new_vmp;
	struct ether_header		*ehp;
	vnet_rx_dringdata_desc_t	*rxdp;
	int				err = 0;
	uint_t				nbytes = 0;
	mblk_t				*mp = NULL;
	mblk_t				*dmp = NULL;
	vgen_stats_t			*statsp = &ldcp->ldc_stats;
	dring_info_t			*dp = ldcp->lane_out.dringp;
	vnet_rx_dringdata_desc_t	*pub_addr = dp->pub_addr;

	rxi = dp->next_rxi;
	rxdp = &(pub_addr[rxi]);
	vmp = dp->rxdp_to_vmp[rxi];

	if (rxdp->dstate != VIO_DESC_READY) {
		/*
		 * Descriptor is not ready.
		 */
		return (EAGAIN);
	}

	/*
	 * Ensure load ordering of dstate and nbytes.
	 */
	MEMBAR_CONSUMER();

	if ((rxdp->nbytes < ETHERMIN) ||
	    (rxdp->nbytes > ldcp->lane_in.mtu) ||
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
	new_vmp = vio_allocb(dp->rx_vmp);

	/*
	 * Process the current buffer being received.
	 */
	nbytes = rxdp->nbytes;
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
		bcopy(mp->b_rptr + VNET_IPALIGN,
		    dmp->b_rptr + VNET_IPALIGN, nbytes);
		mp = dmp;
	} else {
		/* Mark the status of the current rbuf */
		vmp->state = VIO_MBLK_HAS_DATA;

		/* Set the offset of the new buffer in the descriptor */
		rxdp->data_buf_offset =
		    VIO_MBLK_DATA_OFF(new_vmp) + VNET_IPALIGN;
		dp->rxdp_to_vmp[rxi] = new_vmp;
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
	INCR_RXI(dp, rxi);

	/* Save the new recv index */
	dp->next_rxi = rxi;

	/* Return the packet received */
	*bp = mp;
	return (err);
}

void
vsw_stop_rcv_thread(vsw_ldc_t *ldcp)
{
	kt_did_t	tid = 0;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	/*
	 * Send a stop request by setting the stop flag and
	 * wait until the rcv process thread stops.
	 */
	mutex_enter(&ldcp->rcv_thr_lock);
	if (ldcp->rcv_thread != NULL) {
		tid = ldcp->rcv_thread->t_did;
		ldcp->rcv_thr_flags |= VSW_WTHR_STOP;
		cv_signal(&ldcp->rcv_thr_cv);
	}
	mutex_exit(&ldcp->rcv_thr_lock);

	if (tid != 0) {
		thread_join(tid);
	}
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
}

int
vsw_dringsend_shm(vsw_ldc_t *ldcp, mblk_t *mp)
{
	uint32_t			next_txi;
	uint32_t			txi;
	vnet_rx_dringdata_desc_t	*txdp;
	struct ether_header		*ehp;
	size_t				mblksz;
	caddr_t				dst;
	mblk_t				*bp;
	size_t				size;
	on_trap_data_t			otd;
	uint32_t			buf_offset;
	vnet_rx_dringdata_desc_t	*pub_addr;
	vio_dring_msg_t			msg;
	vio_dring_msg_t			*msgp = &msg;
	int				rv = 0;
	boolean_t			resched_peer = B_FALSE;
	boolean_t			is_bcast = B_FALSE;
	boolean_t			is_mcast = B_FALSE;
	vgen_stats_t			*statsp = &ldcp->ldc_stats;
	lane_t				*lane_in = &ldcp->lane_in;
	lane_t				*lane_out = &ldcp->lane_out;
	dring_info_t			*dp = lane_in->dringp;
	vsw_t				*vswp = ldcp->ldc_vswp;

	if ((!(lane_in->lstate & VSW_LANE_ACTIVE)) ||
	    (ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == 0)) {
		DWARN(vswp, "%s(%lld) status(%d) lstate(0x%llx), dropping "
		    "packet\n", __func__, ldcp->ldc_id, ldcp->ldc_status,
		    lane_in->lstate);
		statsp->oerrors++;
		return (LDC_TX_FAILURE);
	}

	if (dp == NULL) {
		DERR(vswp, "%s(%lld): no dring for outbound lane on"
		    " channel %d", __func__, ldcp->ldc_id, ldcp->ldc_id);
		statsp->oerrors++;
		return (LDC_TX_FAILURE);
	}
	pub_addr = dp->pub_addr;

	size = msgsize(mp);

	/*
	 * Note: In RxDringData mode, lane_in is associated with transmit and
	 * lane_out is associated with receive. However, we still keep the
	 * negotiated mtu in lane_out (our exported attributes).
	 */
	if (size > (size_t)lane_out->mtu) {
		DERR(vswp, "%s(%lld) invalid size (%ld)\n", __func__,
		    ldcp->ldc_id, size);
		statsp->oerrors++;
		return (LDC_TX_FAILURE);
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
		DERR(vswp, "%s(%lld) data access fault occured\n",
		    __func__, ldcp->ldc_id);
		statsp->oerrors++;
		if (mutex_owned(&dp->txlock)) {
			mutex_exit(&dp->txlock);
		}
		if (mutex_owned(&dp->restart_lock)) {
			mutex_exit(&dp->restart_lock);
		}
		goto dringsend_shm_exit;
	}

	/*
	 * Allocate a descriptor
	 */
	mutex_enter(&dp->txlock);
	txi = next_txi = dp->next_txi;
	INCR_TXI(dp, next_txi);
	txdp = &(pub_addr[txi]);
	if (txdp->dstate != VIO_DESC_DONE) { /* out of descriptors */
		statsp->tx_no_desc++;
		mutex_exit(&dp->txlock);
		(void) LDC_NO_TRAP();
		return (LDC_TX_NORESOURCES);
	} else {
		txdp->dstate = VIO_DESC_INITIALIZING;
	}

	/* Update descriptor ring index */
	dp->next_txi = next_txi;
	mutex_exit(&dp->txlock);

	/* Ensure load ordering of dstate (above) and data_buf_offset. */
	MEMBAR_CONSUMER();

	/* Get the offset of the buffer to be used */
	buf_offset = txdp->data_buf_offset;

	/* Access the buffer using the offset */
	dst = (caddr_t)dp->data_addr + buf_offset;

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

	mutex_enter(&dp->restart_lock);

	ASSERT(txdp->dstate == VIO_DESC_INITIALIZING);

	/* Mark the descriptor ready */
	txdp->dstate = VIO_DESC_READY;

	/* Check if peer needs wake up (handled below) */
	if (dp->restart_reqd == B_TRUE && dp->restart_peer_txi == txi) {
		dp->restart_reqd = B_FALSE;
		resched_peer = B_TRUE;
	}

	/* Update tx stats */
	statsp->opackets++;
	statsp->obytes += size;
	if (is_bcast)
		statsp->brdcstxmt++;
	else if (is_mcast)
		statsp->multixmt++;

	mutex_exit(&dp->restart_lock);

	/*
	 * We are done accessing shared memory; clear trap protection.
	 */
	(void) LDC_NO_TRAP();

	/*
	 * Need to wake up the peer ?
	 */
	if (resched_peer == B_TRUE) {
		msgp->tag.vio_msgtype = VIO_TYPE_DATA;
		msgp->tag.vio_subtype = VIO_SUBTYPE_INFO;
		msgp->tag.vio_subtype_env = VIO_DRING_DATA;
		msgp->tag.vio_sid = ldcp->local_session;
		msgp->dring_ident = lane_out->dringp->ident;
		msgp->start_idx = txi;
		msgp->end_idx = -1;

		rv = vsw_send_msg_shm(ldcp, (void *)msgp, sizeof (*msgp),
		    B_FALSE);
		if (rv != 0) {
			/* error: drop the packet */
			DERR(vswp, "%s(%lld) failed sending dringdata msg\n",
			    __func__, ldcp->ldc_id);
			mutex_enter(&dp->restart_lock);
			statsp->oerrors++;
			dp->restart_reqd = B_TRUE;
			mutex_exit(&dp->restart_lock);
		}
		statsp->dring_data_msgs_sent++;
	}

dringsend_shm_exit:
	if (rv == ECONNRESET || rv == EACCES) {
		vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
	}
	return (LDC_TX_SUCCESS);
}

void
vsw_process_dringdata_shm(void *arg, void *dpkt)
{
	vsw_ldc_t		*ldcp = arg;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vio_dring_msg_t		*dring_pkt = dpkt;

	switch (dring_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s(%lld): VIO_SUBTYPE_INFO", __func__, ldcp->ldc_id);
		vsw_process_dringdata_info_shm(ldcp, dring_pkt);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s(%lld): VIO_SUBTYPE_ACK", __func__, ldcp->ldc_id);
		vsw_process_dringdata_ack_shm(ldcp, dring_pkt);
		break;

	case VIO_SUBTYPE_NACK:
		DWARN(vswp, "%s(%lld): VIO_SUBTYPE_NACK",
		    __func__, ldcp->ldc_id);
		/*
		 * Something is badly wrong if we are getting NACK's
		 * for our data pkts. So reset the channel.
		 */
		vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
		break;

	default:
		DERR(vswp, "%s(%lld): Unknown vio_subtype %x\n", __func__,
		    ldcp->ldc_id, dring_pkt->tag.vio_subtype);
	}
}

static void
vsw_process_dringdata_info_shm(vsw_ldc_t *ldcp, vio_dring_msg_t *msg)
{
	dring_info_t	*dp = ldcp->lane_in.dringp;
	vsw_t		*vswp = ldcp->ldc_vswp;
	vgen_stats_t	*statsp = &ldcp->ldc_stats;

	if (dp->ident != msg->dring_ident) {
		/* drop the message */
		DERR(vswp, "%s(%lld): Invalid dring ident 0x%llx",
		    __func__, ldcp->ldc_id, msg->dring_ident);
		return;
	}

	statsp->dring_data_msgs_rcvd++;

	/*
	 * Wake up the rcv worker thread to process the rx dring.
	 */
	ASSERT(MUTEX_HELD(&ldcp->ldc_cblock));
	mutex_exit(&ldcp->ldc_cblock);
	mutex_enter(&ldcp->rcv_thr_lock);
	if (!(ldcp->rcv_thr_flags & VSW_WTHR_DATARCVD)) {
		ldcp->rcv_thr_flags |= VSW_WTHR_DATARCVD;
		cv_signal(&ldcp->rcv_thr_cv);
	}
	mutex_exit(&ldcp->rcv_thr_lock);
	mutex_enter(&ldcp->ldc_cblock);
}

static void
vsw_process_dringdata_ack_shm(vsw_ldc_t *ldcp, vio_dring_msg_t *msg)
{
	dring_info_t			*dp;
	uint32_t			start;
	int32_t				end;
	int				rv;
	on_trap_data_t			otd;
	uint32_t			txi;
	vnet_rx_dringdata_desc_t	*txdp;
	vnet_rx_dringdata_desc_t	*pub_addr;
	boolean_t			ready_txd = B_FALSE;
	vsw_t				*vswp = ldcp->ldc_vswp;
	vgen_stats_t			*statsp = &ldcp->ldc_stats;

	dp = ldcp->lane_in.dringp;
	start = msg->start_idx;
	end = msg->end_idx;
	pub_addr = dp->pub_addr;

	/*
	 * In RxDringData mode (v1.6), start index of -1 can be used by the
	 * peer to indicate that it is unspecified. However, the end index
	 * must be set correctly indicating the last descriptor index processed.
	 */
	if (((start != VNET_START_IDX_UNSPEC) && !(CHECK_TXI(dp, start))) ||
	    !(CHECK_TXI(dp, end))) {
		/* drop the message if invalid index */
		DWARN(vswp, "%s(%lld): Invalid Tx ack start(%d) or end(%d)\n",
		    __func__, ldcp->ldc_id, start, end);
		return;
	}

	/* Validate dring_ident */
	if (msg->dring_ident != ldcp->lane_out.dringp->ident) {
		/* invalid dring_ident, drop the msg */
		DWARN(vswp, "%s(%lld): Invalid dring ident 0x%x\n",
		    __func__, ldcp->ldc_id, msg->dring_ident);
		return;
	}
	statsp->dring_data_acks_rcvd++;

	if (msg->dring_process_state != VIO_DP_STOPPED) {
		/*
		 * Receiver continued processing
		 * dring after sending us the ack.
		 */
		return;
	}

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
		if (mutex_owned(&dp->restart_lock)) {
			mutex_exit(&dp->restart_lock);
		}
		return;
	}

	/*
	 * Determine if there are any pending tx descriptors ready to be
	 * processed by the receiver(peer) and if so, send a message to the
	 * peer to restart receiving.
	 */
	mutex_enter(&dp->restart_lock);

	ready_txd = B_FALSE;
	txi = end;
	INCR_TXI(dp, txi);
	txdp = &pub_addr[txi];
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
		dp->restart_reqd = B_TRUE;
		dp->restart_peer_txi = txi;
		mutex_exit(&dp->restart_lock);
		return;
	}

	/*
	 * We have some tx descriptors ready to be processed by the receiver.
	 * Send a dring data message to the peer to restart processing.
	 */
	dp->restart_reqd = B_FALSE;
	mutex_exit(&dp->restart_lock);

	msg->tag.vio_msgtype = VIO_TYPE_DATA;
	msg->tag.vio_subtype = VIO_SUBTYPE_INFO;
	msg->tag.vio_subtype_env = VIO_DRING_DATA;
	msg->tag.vio_sid = ldcp->local_session;
	msg->dring_ident = ldcp->lane_out.dringp->ident;
	msg->start_idx = txi;
	msg->end_idx = -1;
	rv = vsw_send_msg_shm(ldcp, (void *)msg,
	    sizeof (vio_dring_msg_t), B_FALSE);
	statsp->dring_data_msgs_sent++;
	if (rv != 0) {
		mutex_enter(&dp->restart_lock);
		dp->restart_reqd = B_TRUE;
		mutex_exit(&dp->restart_lock);
	}

	if (rv == ECONNRESET) {
		vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
	}
}

/*
 * Send dring data msgs (info/ack/nack) over LDC.
 */
int
vsw_send_msg_shm(vsw_ldc_t *ldcp, void *msgp, int size, boolean_t handle_reset)
{
	int			rv;
	int			retries = vsw_wretries;
	size_t			msglen = size;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vio_dring_msg_t		*dmsg = (vio_dring_msg_t *)msgp;

	D1(vswp, "vsw_send_msg (%lld) enter : sending %d bytes",
	    ldcp->ldc_id, size);

	dmsg->seq_num = atomic_inc_32_nv(&ldcp->dringdata_msgid);

	do {
		msglen = size;
		rv = ldc_write(ldcp->ldc_handle, (caddr_t)msgp, &msglen);
	} while (rv == EWOULDBLOCK && --retries > 0);

	if ((rv != 0) || (msglen != size)) {
		DERR(vswp, "vsw_send_msg_shm:ldc_write failed: "
		    "chan(%lld) rv(%d) size (%d) msglen(%d)\n",
		    ldcp->ldc_id, rv, size, msglen);
		ldcp->ldc_stats.oerrors++;
	}

	/*
	 * If channel has been reset we either handle it here or
	 * simply report back that it has been reset and let caller
	 * decide what to do.
	 */
	if (rv == ECONNRESET) {
		DWARN(vswp, "%s (%lld) channel reset", __func__, ldcp->ldc_id);

		if (handle_reset) {
			vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
		}
	}

	return (rv);
}
