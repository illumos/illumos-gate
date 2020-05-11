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
 * This file contains the implementation of TxDring data transfer mode of VIO
 * Protocol in vsw. The functions in this file are invoked from vsw_ldc.c
 * after TxDring mode is negotiated with the peer during attribute phase of
 * handshake. This file contains functions that setup the transmit and receive
 * descriptor rings, and associated resources in TxDring mode. It also contains
 * the transmit and receive data processing functions that are invoked in
 * TxDring mode.
 */

/* Functions exported to vsw_ldc.c */
vio_dring_reg_msg_t *vsw_create_tx_dring_info(vsw_ldc_t *);
int vsw_setup_tx_dring(vsw_ldc_t *ldcp, dring_info_t *dp);
void vsw_destroy_tx_dring(vsw_ldc_t *ldcp);
dring_info_t *vsw_map_rx_dring(vsw_ldc_t *ldcp, void *pkt);
void vsw_unmap_rx_dring(vsw_ldc_t *ldcp);
int vsw_dringsend(vsw_ldc_t *, mblk_t *);
void vsw_ldc_msg_worker(void *arg);
void vsw_stop_msg_thread(vsw_ldc_t *ldcp);
void vsw_process_dringdata(void *, void *);
int vsw_send_msg(vsw_ldc_t *, void *, int, boolean_t);
int vsw_reclaim_dring(dring_info_t *dp, int start);
int vsw_dring_find_free_desc(dring_info_t *, vsw_private_desc_t **, int *);

/* Internal functions */
static int vsw_init_multipools(vsw_ldc_t *ldcp, vsw_t *vswp);
static dring_info_t *vsw_create_tx_dring(vsw_ldc_t *);

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
extern boolean_t vsw_jumbo_rxpools;
extern uint32_t vsw_chain_len;
extern uint32_t vsw_num_descriptors;
extern uint32_t vsw_mblk_size1;
extern uint32_t vsw_mblk_size2;
extern uint32_t vsw_mblk_size3;
extern uint32_t vsw_mblk_size4;
extern uint32_t vsw_num_mblks1;
extern uint32_t vsw_num_mblks2;
extern uint32_t vsw_num_mblks3;
extern uint32_t vsw_num_mblks4;

#define	VSW_NUM_VMPOOLS		3	/* number of vio mblk pools */

#define	SND_DRING_NACK(ldcp, pkt) \
	pkt->tag.vio_subtype = VIO_SUBTYPE_NACK; \
	pkt->tag.vio_sid = ldcp->local_session; \
	(void) vsw_send_msg(ldcp, (void *)pkt, \
			sizeof (vio_dring_msg_t), B_TRUE);

vio_dring_reg_msg_t *
vsw_create_tx_dring_info(vsw_ldc_t *ldcp)
{
	vio_dring_reg_msg_t	*mp;
	dring_info_t		*dp;
	vsw_t			*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s enter\n", __func__);

	/*
	 * If we can't create a dring, obviously no point sending
	 * a message.
	 */
	if ((dp = vsw_create_tx_dring(ldcp)) == NULL)
		return (NULL);

	mp = kmem_zalloc(sizeof (vio_dring_reg_msg_t), KM_SLEEP);

	mp->tag.vio_msgtype = VIO_TYPE_CTRL;
	mp->tag.vio_subtype = VIO_SUBTYPE_INFO;
	mp->tag.vio_subtype_env = VIO_DRING_REG;
	mp->tag.vio_sid = ldcp->local_session;

	/* payload */
	mp->num_descriptors = dp->num_descriptors;
	mp->descriptor_size = dp->descriptor_size;
	mp->options = dp->options;
	mp->ncookies = dp->dring_ncookies;
	bcopy(&dp->dring_cookie[0], &mp->cookie[0], sizeof (ldc_mem_cookie_t));

	mp->dring_ident = 0;

	D1(vswp, "%s exit\n", __func__);

	return (mp);
}

/*
 * Allocate transmit resources for the channel. The resources consist of a
 * transmit descriptor ring and an associated transmit buffer area.
 */
static dring_info_t *
vsw_create_tx_dring(vsw_ldc_t *ldcp)
{
	vsw_t			*vswp = ldcp->ldc_vswp;
	ldc_mem_info_t		minfo;
	dring_info_t		*dp;

	dp = (dring_info_t *)kmem_zalloc(sizeof (dring_info_t), KM_SLEEP);
	mutex_init(&dp->dlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dp->restart_lock, NULL, MUTEX_DRIVER, NULL);
	ldcp->lane_out.dringp = dp;

	/* create public section of ring */
	if ((ldc_mem_dring_create(vsw_num_descriptors,
	    sizeof (vnet_public_desc_t), &dp->dring_handle)) != 0) {

		DERR(vswp, "vsw_create_tx_dring(%lld): ldc dring create "
		    "failed", ldcp->ldc_id);
		goto fail;
	}
	ASSERT(dp->dring_handle != NULL);

	/*
	 * Get the base address of the public section of the ring.
	 */
	if ((ldc_mem_dring_info(dp->dring_handle, &minfo)) != 0) {
		DERR(vswp, "vsw_create_tx_dring(%lld): dring info failed\n",
		    ldcp->ldc_id);
		goto fail;
	} else {
		ASSERT(minfo.vaddr != 0);
		dp->pub_addr = minfo.vaddr;
	}

	dp->num_descriptors = vsw_num_descriptors;
	dp->descriptor_size = sizeof (vnet_public_desc_t);
	dp->options = VIO_TX_DRING;
	dp->dring_ncookies = 1;	/* guaranteed by ldc */

	/*
	 * create private portion of ring
	 */
	dp->priv_addr = (vsw_private_desc_t *)kmem_zalloc(
	    (sizeof (vsw_private_desc_t) * vsw_num_descriptors), KM_SLEEP);

	if (vsw_setup_tx_dring(ldcp, dp)) {
		DERR(vswp, "%s: unable to setup ring", __func__);
		goto fail;
	}

	/* bind dring to the channel */
	if ((ldc_mem_dring_bind(ldcp->ldc_handle, dp->dring_handle,
	    LDC_DIRECT_MAP | LDC_SHADOW_MAP, LDC_MEM_RW,
	    &dp->dring_cookie[0], &dp->dring_ncookies)) != 0) {
		DERR(vswp, "vsw_create_tx_dring: unable to bind to channel "
		    "%lld", ldcp->ldc_id);
		goto fail;
	}

	/* haven't used any descriptors yet */
	dp->end_idx = 0;
	dp->last_ack_recv = -1;
	dp->restart_reqd = B_TRUE;

	return (dp);

fail:
	vsw_destroy_tx_dring(ldcp);
	return (NULL);
}

/*
 * Setup the descriptors in the tx dring.
 * Returns 0 on success, 1 on failure.
 */
int
vsw_setup_tx_dring(vsw_ldc_t *ldcp, dring_info_t *dp)
{
	vnet_public_desc_t	*pub_addr = NULL;
	vsw_private_desc_t	*priv_addr = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	uint64_t		*tmpp;
	uint64_t		offset = 0;
	uint32_t		ncookies = 0;
	static char		*name = "vsw_setup_ring";
	int			i, j, nc, rv;
	size_t			data_sz;
	void			*data_addr;

	priv_addr = dp->priv_addr;
	pub_addr = dp->pub_addr;

	/* public section may be null but private should never be */
	ASSERT(priv_addr != NULL);

	/*
	 * Allocate the region of memory which will be used to hold
	 * the data the descriptors will refer to.
	 */
	data_sz = vswp->max_frame_size + VNET_IPALIGN + VNET_LDCALIGN;

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
	if (data_sz <= VNET_12K) {
		data_sz = VNET_ROUNDUP_2K(data_sz);
	} else {
		data_sz = VNET_ROUNDUP_4K(data_sz);
	}

	dp->desc_data_sz = data_sz;

	/* allocate extra 8K bytes for alignment */
	dp->data_sz = (vsw_num_descriptors * data_sz) + VNET_8K;
	data_addr = kmem_alloc(dp->data_sz, KM_SLEEP);
	dp->data_addr = data_addr;

	D2(vswp, "%s: allocated %lld bytes at 0x%llx\n", name,
	    dp->data_sz, dp->data_addr);

	/* align the starting address of the data area to 8K */
	data_addr = (void *)VNET_ROUNDUP_8K((uintptr_t)data_addr);

	tmpp = (uint64_t *)data_addr;
	offset = dp->desc_data_sz/sizeof (tmpp);

	/*
	 * Initialise some of the private and public (if they exist)
	 * descriptor fields.
	 */
	for (i = 0; i < vsw_num_descriptors; i++) {
		mutex_init(&priv_addr->dstate_lock, NULL, MUTEX_DRIVER, NULL);

		if ((ldc_mem_alloc_handle(ldcp->ldc_handle,
		    &priv_addr->memhandle)) != 0) {
			DERR(vswp, "%s: alloc mem handle failed", name);
			goto fail;
		}

		priv_addr->datap = (void *)tmpp;

		rv = ldc_mem_bind_handle(priv_addr->memhandle,
		    (caddr_t)priv_addr->datap, dp->desc_data_sz,
		    LDC_SHADOW_MAP, LDC_MEM_R|LDC_MEM_W,
		    &(priv_addr->memcookie[0]), &ncookies);
		if (rv != 0) {
			DERR(vswp, "%s(%lld): ldc_mem_bind_handle failed "
			    "(rv %d)", name, ldcp->ldc_id, rv);
			goto fail;
		}
		priv_addr->bound = 1;

		D2(vswp, "%s: %d: memcookie 0 : addr 0x%llx : size 0x%llx",
		    name, i, priv_addr->memcookie[0].addr,
		    priv_addr->memcookie[0].size);

		if (ncookies >= (uint32_t)(VSW_MAX_COOKIES + 1)) {
			DERR(vswp, "%s(%lld) ldc_mem_bind_handle returned "
			    "invalid num of cookies (%d) for size 0x%llx",
			    name, ldcp->ldc_id, ncookies, VSW_RING_EL_DATA_SZ);

			goto fail;
		} else {
			for (j = 1; j < ncookies; j++) {
				rv = ldc_mem_nextcookie(priv_addr->memhandle,
				    &(priv_addr->memcookie[j]));
				if (rv != 0) {
					DERR(vswp, "%s: ldc_mem_nextcookie "
					    "failed rv (%d)", name, rv);
					goto fail;
				}
				D3(vswp, "%s: memcookie %d : addr 0x%llx : "
				    "size 0x%llx", name, j,
				    priv_addr->memcookie[j].addr,
				    priv_addr->memcookie[j].size);
			}

		}
		priv_addr->ncookies = ncookies;
		priv_addr->dstate = VIO_DESC_FREE;

		if (pub_addr != NULL) {

			/* link pub and private sides */
			priv_addr->descp = pub_addr;

			pub_addr->ncookies = priv_addr->ncookies;

			for (nc = 0; nc < pub_addr->ncookies; nc++) {
				bcopy(&priv_addr->memcookie[nc],
				    &pub_addr->memcookie[nc],
				    sizeof (ldc_mem_cookie_t));
			}

			pub_addr->hdr.dstate = VIO_DESC_FREE;
			pub_addr++;
		}

		/*
		 * move to next element in the dring and the next
		 * position in the data buffer.
		 */
		priv_addr++;
		tmpp += offset;
	}

	return (0);

fail:
	/* return failure; caller will cleanup */
	return (1);
}

/*
 * Free transmit resources for the channel.
 */
void
vsw_destroy_tx_dring(vsw_ldc_t *ldcp)
{
	vsw_private_desc_t	*paddr = NULL;
	int			i;
	lane_t			*lp = &ldcp->lane_out;
	dring_info_t		*dp;

	dp = lp->dringp;
	if (dp == NULL) {
		return;
	}

	mutex_enter(&dp->dlock);

	if (dp->priv_addr != NULL) {
		/*
		 * First unbind and free the memory handles
		 * stored in each descriptor within the ring.
		 */
		for (i = 0; i < vsw_num_descriptors; i++) {
			paddr = (vsw_private_desc_t *)dp->priv_addr + i;
			if (paddr->memhandle != 0) {
				if (paddr->bound == 1) {
					if (ldc_mem_unbind_handle(
					    paddr->memhandle) != 0) {
						DERR(NULL, "error "
						"unbinding handle for "
						"ring 0x%llx at pos %d",
						    dp, i);
						continue;
					}
					paddr->bound = 0;
				}

				if (ldc_mem_free_handle(
				    paddr->memhandle) != 0) {
					DERR(NULL, "error freeing "
					    "handle for ring 0x%llx "
					    "at pos %d", dp, i);
					continue;
				}
				paddr->memhandle = 0;
			}
			mutex_destroy(&paddr->dstate_lock);
		}
		kmem_free(dp->priv_addr,
		    (sizeof (vsw_private_desc_t) * vsw_num_descriptors));
	}

	/*
	 * Now unbind and destroy the ring itself.
	 */
	if (dp->dring_handle != 0) {
		(void) ldc_mem_dring_unbind(dp->dring_handle);
		(void) ldc_mem_dring_destroy(dp->dring_handle);
	}

	if (dp->data_addr != NULL) {
		kmem_free(dp->data_addr, dp->data_sz);
	}

	mutex_exit(&dp->dlock);
	mutex_destroy(&dp->dlock);
	mutex_destroy(&dp->restart_lock);
	kmem_free(dp, sizeof (dring_info_t));
	lp->dringp = NULL;
}

/*
 * Map the transmit descriptor ring exported
 * by the peer, as our receive descriptor ring.
 */
dring_info_t *
vsw_map_rx_dring(vsw_ldc_t *ldcp, void *pkt)
{
	int			rv;
	dring_info_t		*dp;
	vio_dring_reg_msg_t	*dring_pkt = pkt;
	vsw_t			*vswp = ldcp->ldc_vswp;

	dp = vsw_map_dring_cmn(ldcp, dring_pkt);
	if (dp == NULL) {
		return (NULL);
	}

	/* TxDring mode specific initializations */
	dp->end_idx = 0;
	ldcp->lane_in.dringp = dp;

	/* Allocate pools of receive mblks */
	rv = vsw_init_multipools(ldcp, vswp);
	if (rv != 0) {
		/*
		 * We do not return failure if receive mblk pools can't
		 * be allocated, instead allocb(9F) will be used to
		 * dynamically allocate buffers during receive.
		 */
		DWARN(vswp, "%s: unable to create free mblk pools for"
		    " channel %ld (rv %d)", __func__, ldcp->ldc_id, rv);
	}

	return (dp);
}

/*
 * Unmap the receive descriptor ring.
 */
void
vsw_unmap_rx_dring(vsw_ldc_t *ldcp)
{
	vio_mblk_pool_t *fvmp = NULL;
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lp = &ldcp->lane_in;
	dring_info_t	*dp;

	if ((dp = lp->dringp) == NULL) {
		return;
	}

	/*
	 * If we can't destroy all the rx pools for this channel,
	 * dispatch a task to retry and clean up those rx pools. Note
	 * that we don't need to wait for the task to complete. If the
	 * vsw device itself gets detached (vsw_detach()), it will wait
	 * for the task to complete implicitly in ddi_taskq_destroy().
	 */
	vio_destroy_multipools(&ldcp->vmp, &fvmp);
	if (fvmp != NULL) {
		(void) ddi_taskq_dispatch(vswp->rxp_taskq,
		    vsw_destroy_rxpools, fvmp, DDI_SLEEP);
	}

	if (dp->dring_handle != 0) {
		(void) ldc_mem_dring_unmap(dp->dring_handle);
	}
	kmem_free(dp, sizeof (dring_info_t));
	lp->dringp = NULL;
}

static int
vsw_init_multipools(vsw_ldc_t *ldcp, vsw_t *vswp)
{
	size_t		data_sz;
	int		rv;
	uint32_t	sz1 = 0;
	uint32_t	sz2 = 0;
	uint32_t	sz3 = 0;
	uint32_t	sz4 = 0;

	/*
	 * We round up the mtu specified to be a multiple of 2K to limit the
	 * number of rx buffer pools created for a given mtu.
	 */
	data_sz = vswp->max_frame_size + VNET_IPALIGN + VNET_LDCALIGN;
	data_sz = VNET_ROUNDUP_2K(data_sz);

	/*
	 * If pool sizes are specified, use them. Note that the presence of
	 * the first tunable will be used as a hint.
	 */
	if (vsw_mblk_size1 != 0) {
		sz1 = vsw_mblk_size1;
		sz2 = vsw_mblk_size2;
		sz3 = vsw_mblk_size3;
		sz4 = vsw_mblk_size4;

		if (sz4 == 0) { /* need 3 pools */

			ldcp->max_rxpool_size = sz3;
			rv = vio_init_multipools(&ldcp->vmp,
			    VSW_NUM_VMPOOLS, sz1, sz2, sz3,
			    vsw_num_mblks1, vsw_num_mblks2, vsw_num_mblks3);

		} else {

			ldcp->max_rxpool_size = sz4;
			rv = vio_init_multipools(&ldcp->vmp,
			    VSW_NUM_VMPOOLS + 1, sz1, sz2, sz3, sz4,
			    vsw_num_mblks1, vsw_num_mblks2, vsw_num_mblks3,
			    vsw_num_mblks4);

		}

		return (rv);
	}

	/*
	 * Pool sizes are not specified. We select the pool sizes based on the
	 * mtu if vnet_jumbo_rxpools is enabled.
	 */
	if (vsw_jumbo_rxpools == B_FALSE || data_sz == VNET_2K) {
		/*
		 * Receive buffer pool allocation based on mtu is disabled.
		 * Use the default mechanism of standard size pool allocation.
		 */
		sz1 = VSW_MBLK_SZ_128;
		sz2 = VSW_MBLK_SZ_256;
		sz3 = VSW_MBLK_SZ_2048;
		ldcp->max_rxpool_size = sz3;

		rv = vio_init_multipools(&ldcp->vmp, VSW_NUM_VMPOOLS,
		    sz1, sz2, sz3,
		    vsw_num_mblks1, vsw_num_mblks2, vsw_num_mblks3);

		return (rv);
	}

	switch (data_sz) {

	case VNET_4K:

		sz1 = VSW_MBLK_SZ_128;
		sz2 = VSW_MBLK_SZ_256;
		sz3 = VSW_MBLK_SZ_2048;
		sz4 = sz3 << 1;			/* 4K */
		ldcp->max_rxpool_size = sz4;

		rv = vio_init_multipools(&ldcp->vmp, VSW_NUM_VMPOOLS + 1,
		    sz1, sz2, sz3, sz4,
		    vsw_num_mblks1, vsw_num_mblks2, vsw_num_mblks3,
		    vsw_num_mblks4);
		break;

	default:	/* data_sz:  4K+ to 16K */

		sz1 = VSW_MBLK_SZ_256;
		sz2 = VSW_MBLK_SZ_2048;
		sz3 = data_sz >> 1;	/* Jumbo-size/2 */
		sz4 = data_sz;	/* Jumbo-size */
		ldcp->max_rxpool_size = sz4;

		rv = vio_init_multipools(&ldcp->vmp, VSW_NUM_VMPOOLS + 1,
		    sz1, sz2, sz3, sz4,
		    vsw_num_mblks1, vsw_num_mblks2, vsw_num_mblks3,
		    vsw_num_mblks4);
		break;
	}

	return (rv);

}

/*
 * Generic routine to send message out over ldc channel.
 *
 * It is possible that when we attempt to write over the ldc channel
 * that we get notified that it has been reset. Depending on the value
 * of the handle_reset flag we either handle that event here or simply
 * notify the caller that the channel was reset.
 */
int
vsw_send_msg(vsw_ldc_t *ldcp, void *msgp, int size, boolean_t handle_reset)
{
	int			rv;
	size_t			msglen = size;
	vio_msg_tag_t		*tag = (vio_msg_tag_t *)msgp;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vio_dring_msg_t		*dmsg;
	vio_raw_data_msg_t	*rmsg;
	vnet_ibnd_desc_t	*imsg;
	boolean_t		data_msg = B_FALSE;
	int			retries = vsw_wretries;

	D1(vswp, "vsw_send_msg (%lld) enter : sending %d bytes",
	    ldcp->ldc_id, size);

	D2(vswp, "send_msg: type 0x%llx", tag->vio_msgtype);
	D2(vswp, "send_msg: stype 0x%llx", tag->vio_subtype);
	D2(vswp, "send_msg: senv 0x%llx", tag->vio_subtype_env);

	mutex_enter(&ldcp->ldc_txlock);

	if (tag->vio_subtype == VIO_SUBTYPE_INFO) {
		if (tag->vio_subtype_env == VIO_DRING_DATA) {
			dmsg = (vio_dring_msg_t *)tag;
			dmsg->seq_num = ldcp->lane_out.seq_num;
			data_msg = B_TRUE;
		} else if (tag->vio_subtype_env == VIO_PKT_DATA) {
			rmsg = (vio_raw_data_msg_t *)tag;
			rmsg->seq_num = ldcp->lane_out.seq_num;
			data_msg = B_TRUE;
		} else if (tag->vio_subtype_env == VIO_DESC_DATA) {
			imsg = (vnet_ibnd_desc_t *)tag;
			imsg->hdr.seq_num = ldcp->lane_out.seq_num;
			data_msg = B_TRUE;
		}
	}

	do {
		msglen = size;
		rv = ldc_write(ldcp->ldc_handle, (caddr_t)msgp, &msglen);
	} while (rv == EWOULDBLOCK && --retries > 0);

	if (rv == 0 && data_msg == B_TRUE) {
		ldcp->lane_out.seq_num++;
	}

	if ((rv != 0) || (msglen != size)) {
		DERR(vswp, "vsw_send_msg:ldc_write failed: chan(%lld) rv(%d) "
		    "size (%d) msglen(%d)\n", ldcp->ldc_id, rv, size, msglen);
		ldcp->ldc_stats.oerrors++;
	}

	mutex_exit(&ldcp->ldc_txlock);

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

/*
 * A per LDC worker thread to process ldc messages. This thread is woken up by
 * the LDC interrupt handler to process LDC packets and receive data.
 */
void
vsw_ldc_msg_worker(void *arg)
{
	callb_cpr_t	cprinfo;
	vsw_ldc_t	*ldcp = (vsw_ldc_t *)arg;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	CALLB_CPR_INIT(&cprinfo, &ldcp->msg_thr_lock, callb_generic_cpr,
	    "vsw_msg_thread");
	mutex_enter(&ldcp->msg_thr_lock);
	while (!(ldcp->msg_thr_flags & VSW_WTHR_STOP)) {

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		/*
		 * Wait until the data is received or a stop
		 * request is received.
		 */
		while (!(ldcp->msg_thr_flags &
		    (VSW_WTHR_DATARCVD | VSW_WTHR_STOP))) {
			cv_wait(&ldcp->msg_thr_cv, &ldcp->msg_thr_lock);
		}
		CALLB_CPR_SAFE_END(&cprinfo, &ldcp->msg_thr_lock)

		/*
		 * First process the stop request.
		 */
		if (ldcp->msg_thr_flags & VSW_WTHR_STOP) {
			D2(vswp, "%s(%lld):Rx thread stopped\n",
			    __func__, ldcp->ldc_id);
			break;
		}
		ldcp->msg_thr_flags &= ~VSW_WTHR_DATARCVD;
		mutex_exit(&ldcp->msg_thr_lock);
		D1(vswp, "%s(%lld):calling vsw_process_pkt\n",
		    __func__, ldcp->ldc_id);
		mutex_enter(&ldcp->ldc_cblock);
		vsw_process_pkt(ldcp);
		mutex_exit(&ldcp->ldc_cblock);
		mutex_enter(&ldcp->msg_thr_lock);
	}

	/*
	 * Update the run status and wakeup the thread that
	 * has sent the stop request.
	 */
	ldcp->msg_thr_flags &= ~VSW_WTHR_STOP;
	ldcp->msg_thread = NULL;
	CALLB_CPR_EXIT(&cprinfo);
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
	thread_exit();
}

/* Co-ordinate with msg processing thread to stop it */
void
vsw_stop_msg_thread(vsw_ldc_t *ldcp)
{
	kt_did_t	tid = 0;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	/*
	 * Send a stop request by setting the stop flag and
	 * wait until the msg process thread stops.
	 */
	mutex_enter(&ldcp->msg_thr_lock);
	if (ldcp->msg_thread != NULL) {
		tid = ldcp->msg_thread->t_did;
		ldcp->msg_thr_flags |= VSW_WTHR_STOP;
		cv_signal(&ldcp->msg_thr_cv);
	}
	mutex_exit(&ldcp->msg_thr_lock);

	if (tid != 0) {
		thread_join(tid);
	}
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
}

/*
 * Send packet out via descriptor ring to a logical device.
 */
int
vsw_dringsend(vsw_ldc_t *ldcp, mblk_t *mp)
{
	vio_dring_msg_t		dring_pkt;
	dring_info_t		*dp = NULL;
	vsw_private_desc_t	*priv_desc = NULL;
	vnet_public_desc_t	*pub = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	mblk_t			*bp;
	size_t			n, size;
	caddr_t			bufp;
	int			idx;
	int			status = LDC_TX_SUCCESS;
	struct ether_header	*ehp = (struct ether_header *)mp->b_rptr;
	lane_t			*lp = &ldcp->lane_out;

	D1(vswp, "%s(%lld): enter\n", __func__, ldcp->ldc_id);

	/* TODO: make test a macro */
	if ((!(ldcp->lane_out.lstate & VSW_LANE_ACTIVE)) ||
	    (ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == 0)) {
		DWARN(vswp, "%s(%lld) status(%d) lstate(0x%llx), dropping "
		    "packet\n", __func__, ldcp->ldc_id, ldcp->ldc_status,
		    ldcp->lane_out.lstate);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	if ((dp = ldcp->lane_out.dringp) == NULL) {
		DERR(vswp, "%s(%lld): no dring for outbound lane on"
		    " channel %d", __func__, ldcp->ldc_id, ldcp->ldc_id);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	size = msgsize(mp);
	if (size > (size_t)lp->mtu) {
		DERR(vswp, "%s(%lld) invalid size (%ld)\n", __func__,
		    ldcp->ldc_id, size);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	/*
	 * Find a free descriptor
	 *
	 * Note: for the moment we are assuming that we will only
	 * have one dring going from the switch to each of its
	 * peers. This may change in the future.
	 */
	if (vsw_dring_find_free_desc(dp, &priv_desc, &idx) != 0) {
		D2(vswp, "%s(%lld): no descriptor available for ring "
		    "at 0x%llx", __func__, ldcp->ldc_id, dp);

		/* nothing more we can do */
		status = LDC_TX_NORESOURCES;
		ldcp->ldc_stats.tx_no_desc++;
		goto vsw_dringsend_free_exit;
	} else {
		D2(vswp, "%s(%lld): free private descriptor found at pos %ld "
		    "addr 0x%llx\n", __func__, ldcp->ldc_id, idx, priv_desc);
	}

	/* copy data into the descriptor */
	bufp = priv_desc->datap;
	bufp += VNET_IPALIGN;
	for (bp = mp, n = 0; bp != NULL; bp = bp->b_cont) {
		n = MBLKL(bp);
		bcopy(bp->b_rptr, bufp, n);
		bufp += n;
	}

	priv_desc->datalen = (size < (size_t)ETHERMIN) ? ETHERMIN : size;

	pub = priv_desc->descp;
	pub->nbytes = priv_desc->datalen;

	/* update statistics */
	if (IS_BROADCAST(ehp))
		ldcp->ldc_stats.brdcstxmt++;
	else if (IS_MULTICAST(ehp))
		ldcp->ldc_stats.multixmt++;
	ldcp->ldc_stats.opackets++;
	ldcp->ldc_stats.obytes += priv_desc->datalen;

	mutex_enter(&priv_desc->dstate_lock);
	pub->hdr.dstate = VIO_DESC_READY;
	mutex_exit(&priv_desc->dstate_lock);

	/*
	 * Determine whether or not we need to send a message to our
	 * peer prompting them to read our newly updated descriptor(s).
	 */
	mutex_enter(&dp->restart_lock);
	if (dp->restart_reqd) {
		dp->restart_reqd = B_FALSE;
		ldcp->ldc_stats.dring_data_msgs_sent++;
		mutex_exit(&dp->restart_lock);

		/*
		 * Send a vio_dring_msg to peer to prompt them to read
		 * the updated descriptor ring.
		 */
		dring_pkt.tag.vio_msgtype = VIO_TYPE_DATA;
		dring_pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
		dring_pkt.tag.vio_subtype_env = VIO_DRING_DATA;
		dring_pkt.tag.vio_sid = ldcp->local_session;

		/* Note - for now using first ring */
		dring_pkt.dring_ident = dp->ident;

		/*
		 * If last_ack_recv is -1 then we know we've not
		 * received any ack's yet, so this must be the first
		 * msg sent, so set the start to the begining of the ring.
		 */
		mutex_enter(&dp->dlock);
		if (dp->last_ack_recv == -1) {
			dring_pkt.start_idx = 0;
		} else {
			dring_pkt.start_idx =
			    (dp->last_ack_recv + 1) % dp->num_descriptors;
		}
		dring_pkt.end_idx = -1;
		mutex_exit(&dp->dlock);

		D3(vswp, "%s(%lld): dring 0x%llx : ident 0x%llx\n", __func__,
		    ldcp->ldc_id, dp, dring_pkt.dring_ident);
		D3(vswp, "%s(%lld): start %lld : end %lld :\n",
		    __func__, ldcp->ldc_id, dring_pkt.start_idx,
		    dring_pkt.end_idx);

		(void) vsw_send_msg(ldcp, (void *)&dring_pkt,
		    sizeof (vio_dring_msg_t), B_TRUE);

		return (status);

	} else {
		mutex_exit(&dp->restart_lock);
		D2(vswp, "%s(%lld): updating descp %d", __func__,
		    ldcp->ldc_id, idx);
	}

vsw_dringsend_free_exit:

	D1(vswp, "%s(%lld): exit\n", __func__, ldcp->ldc_id);
	return (status);
}

/*
 * Searches the private section of a ring for a free descriptor,
 * starting at the location of the last free descriptor found
 * previously.
 *
 * Returns 0 if free descriptor is available, and updates state
 * of private descriptor to VIO_DESC_READY,  otherwise returns 1.
 *
 * FUTURE: might need to return contiguous range of descriptors
 * as dring info msg assumes all will be contiguous.
 */
int
vsw_dring_find_free_desc(dring_info_t *dringp,
    vsw_private_desc_t **priv_p, int *idx)
{
	vsw_private_desc_t	*addr = NULL;
	int			num = vsw_num_descriptors;
	int			ret = 1;

	D1(NULL, "%s enter\n", __func__);

	ASSERT(dringp->priv_addr != NULL);

	D2(NULL, "%s: searching ring, dringp 0x%llx : start pos %lld",
	    __func__, dringp, dringp->end_idx);

	addr = (vsw_private_desc_t *)dringp->priv_addr + dringp->end_idx;

	mutex_enter(&addr->dstate_lock);
	if (addr->dstate == VIO_DESC_FREE) {
		addr->dstate = VIO_DESC_READY;
		*priv_p = addr;
		*idx = dringp->end_idx;
		dringp->end_idx = (dringp->end_idx + 1) % num;
		ret = 0;

	}
	mutex_exit(&addr->dstate_lock);

	/* ring full */
	if (ret == 1) {
		D2(NULL, "%s: no desp free: started at %d", __func__,
		    dringp->end_idx);
	}

	D1(NULL, "%s: exit\n", __func__);

	return (ret);
}

/* vsw_reclaim_dring -- reclaim descriptors */
int
vsw_reclaim_dring(dring_info_t *dp, int start)
{
	int i, j, len;
	vsw_private_desc_t *priv_addr;
	vnet_public_desc_t *pub_addr;

	pub_addr = (vnet_public_desc_t *)dp->pub_addr;
	priv_addr = (vsw_private_desc_t *)dp->priv_addr;
	len = dp->num_descriptors;

	D2(NULL, "%s: start index %ld\n", __func__, start);

	j = 0;
	for (i = start; j < len; i = (i + 1) % len, j++) {
		pub_addr = (vnet_public_desc_t *)dp->pub_addr + i;
		priv_addr = (vsw_private_desc_t *)dp->priv_addr + i;

		mutex_enter(&priv_addr->dstate_lock);
		if (pub_addr->hdr.dstate != VIO_DESC_DONE) {
			mutex_exit(&priv_addr->dstate_lock);
			break;
		}
		pub_addr->hdr.dstate = VIO_DESC_FREE;
		priv_addr->dstate = VIO_DESC_FREE;
		/* clear all the fields */
		priv_addr->datalen = 0;
		pub_addr->hdr.ack = 0;
		mutex_exit(&priv_addr->dstate_lock);

		D3(NULL, "claiming descp:%d pub state:0x%llx priv state 0x%llx",
		    i, pub_addr->hdr.dstate, priv_addr->dstate);
	}
	return (j);
}

void
vsw_process_dringdata(void *arg, void *dpkt)
{
	vsw_ldc_t		*ldcp = arg;
	vio_dring_msg_t		*dring_pkt;
	vnet_public_desc_t	desc, *pub_addr = NULL;
	vsw_private_desc_t	*priv_addr = NULL;
	dring_info_t		*dp = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	mblk_t			*mp = NULL;
	vio_mblk_t		*vmp = NULL;
	mblk_t			*bp = NULL;
	mblk_t			*bpt = NULL;
	size_t			nbytes = 0;
	uint64_t		chain = 0;
	uint64_t		len;
	uint32_t		pos, start;
	uint32_t		range_start, range_end;
	int32_t			end, num, cnt = 0;
	int			i, rv, rng_rv = 0, msg_rv = 0;
	boolean_t		prev_desc_ack = B_FALSE;
	int			read_attempts = 0;
	struct ether_header	*ehp;
	lane_t			*lp = &ldcp->lane_out;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	/*
	 * We know this is a data/dring packet so
	 * cast it into the correct structure.
	 */
	dring_pkt = (vio_dring_msg_t *)dpkt;

	/*
	 * Switch on the vio_subtype. If its INFO then we need to
	 * process the data. If its an ACK we need to make sure
	 * it makes sense (i.e did we send an earlier data/info),
	 * and if its a NACK then we maybe attempt a retry.
	 */
	switch (dring_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s(%lld): VIO_SUBTYPE_INFO", __func__, ldcp->ldc_id);

		dp = ldcp->lane_in.dringp;
		if (dp->ident != dring_pkt->dring_ident) {
			DERR(vswp, "%s(%lld): unable to find dring from "
			    "ident 0x%llx", __func__, ldcp->ldc_id,
			    dring_pkt->dring_ident);

			SND_DRING_NACK(ldcp, dring_pkt);
			return;
		}

		ldcp->ldc_stats.dring_data_msgs_rcvd++;

		start = pos = dring_pkt->start_idx;
		end = dring_pkt->end_idx;
		len = dp->num_descriptors;

		range_start = range_end = pos;

		D2(vswp, "%s(%lld): start index %ld : end %ld\n",
		    __func__, ldcp->ldc_id, start, end);

		if (end == -1) {
			num = -1;
		} else if (end >= 0) {
			num = end >= pos ? end - pos + 1: (len - pos + 1) + end;

			/* basic sanity check */
			if (end > len) {
				DERR(vswp, "%s(%lld): endpoint %lld outside "
				    "ring length %lld", __func__,
				    ldcp->ldc_id, end, len);

				SND_DRING_NACK(ldcp, dring_pkt);
				return;
			}
		} else {
			DERR(vswp, "%s(%lld): invalid endpoint %lld",
			    __func__, ldcp->ldc_id, end);
			SND_DRING_NACK(ldcp, dring_pkt);
			return;
		}

		while (cnt != num) {
vsw_recheck_desc:
			pub_addr = (vnet_public_desc_t *)dp->pub_addr + pos;

			if ((rng_rv = vnet_dring_entry_copy(pub_addr,
			    &desc, dp->dring_mtype, dp->dring_handle,
			    pos, pos)) != 0) {
				DERR(vswp, "%s(%lld): unable to copy "
				    "descriptor at pos %d: err %d",
				    __func__, pos, ldcp->ldc_id, rng_rv);
				ldcp->ldc_stats.ierrors++;
				break;
			}

			/*
			 * When given a bounded range of descriptors
			 * to process, its an error to hit a descriptor
			 * which is not ready. In the non-bounded case
			 * (end_idx == -1) this simply indicates we have
			 * reached the end of the current active range.
			 */
			if (desc.hdr.dstate != VIO_DESC_READY) {
				/* unbound - no error */
				if (end == -1) {
					if (read_attempts == vsw_recv_retries)
						break;

					delay(drv_usectohz(vsw_recv_delay));
					read_attempts++;
					goto vsw_recheck_desc;
				}

				/* bounded - error - so NACK back */
				DERR(vswp, "%s(%lld): descriptor not READY "
				    "(%d)", __func__, ldcp->ldc_id,
				    desc.hdr.dstate);
				SND_DRING_NACK(ldcp, dring_pkt);
				return;
			}

			DTRACE_PROBE1(read_attempts, int, read_attempts);

			range_end = pos;

			/*
			 * If we ACK'd the previous descriptor then now
			 * record the new range start position for later
			 * ACK's.
			 */
			if (prev_desc_ack) {
				range_start = pos;

				D2(vswp, "%s(%lld): updating range start to be "
				    "%d", __func__, ldcp->ldc_id, range_start);

				prev_desc_ack = B_FALSE;
			}

			D2(vswp, "%s(%lld): processing desc %lld at pos"
			    " 0x%llx : dstate 0x%lx : datalen 0x%lx",
			    __func__, ldcp->ldc_id, pos, &desc,
			    desc.hdr.dstate, desc.nbytes);

			if ((desc.nbytes < ETHERMIN) ||
			    (desc.nbytes > lp->mtu)) {
				/* invalid size; drop the packet */
				ldcp->ldc_stats.ierrors++;
				goto vsw_process_desc_done;
			}

			/*
			 * Ensure that we ask ldc for an aligned
			 * number of bytes. Data is padded to align on 8
			 * byte boundary, desc.nbytes is actual data length,
			 * i.e. minus that padding.
			 */
			nbytes = (desc.nbytes + VNET_IPALIGN + 7) & ~7;
			if (nbytes > ldcp->max_rxpool_size) {
				mp = allocb(desc.nbytes + VNET_IPALIGN + 8,
				    BPRI_MED);
				vmp = NULL;
			} else {
				vmp = vio_multipool_allocb(&ldcp->vmp, nbytes);
				if (vmp == NULL) {
					ldcp->ldc_stats.rx_vio_allocb_fail++;
					/*
					 * No free receive buffers available,
					 * so fallback onto allocb(9F). Make
					 * sure that we get a data buffer which
					 * is a multiple of 8 as this is
					 * required by ldc_mem_copy.
					 */
					DTRACE_PROBE(allocb);
					mp = allocb(desc.nbytes +
					    VNET_IPALIGN + 8, BPRI_MED);
				} else {
					mp = vmp->mp;
				}
			}
			if (mp == NULL) {
				DERR(vswp, "%s(%ld): allocb failed",
				    __func__, ldcp->ldc_id);
				rng_rv = vnet_dring_entry_set_dstate(pub_addr,
				    dp->dring_mtype, dp->dring_handle, pos, pos,
				    VIO_DESC_DONE);
				ldcp->ldc_stats.ierrors++;
				ldcp->ldc_stats.rx_allocb_fail++;
				break;
			}

			rv = ldc_mem_copy(ldcp->ldc_handle,
			    (caddr_t)mp->b_rptr, 0, &nbytes,
			    desc.memcookie, desc.ncookies, LDC_COPY_IN);
			if (rv != 0) {
				DERR(vswp, "%s(%d): unable to copy in data "
				    "from %d cookies in desc %d (rv %d)",
				    __func__, ldcp->ldc_id, desc.ncookies,
				    pos, rv);
				freemsg(mp);

				rng_rv = vnet_dring_entry_set_dstate(pub_addr,
				    dp->dring_mtype, dp->dring_handle, pos, pos,
				    VIO_DESC_DONE);
				ldcp->ldc_stats.ierrors++;
				break;
			} else {
				D2(vswp, "%s(%d): copied in %ld bytes"
				    " using %d cookies", __func__,
				    ldcp->ldc_id, nbytes, desc.ncookies);
			}

			/* adjust the read pointer to skip over the padding */
			mp->b_rptr += VNET_IPALIGN;

			/* point to the actual end of data */
			mp->b_wptr = mp->b_rptr + desc.nbytes;

			if (vmp != NULL) {
				vmp->state = VIO_MBLK_HAS_DATA;
			}

			/* update statistics */
			ehp = (struct ether_header *)mp->b_rptr;
			if (IS_BROADCAST(ehp))
				ldcp->ldc_stats.brdcstrcv++;
			else if (IS_MULTICAST(ehp))
				ldcp->ldc_stats.multircv++;

			ldcp->ldc_stats.ipackets++;
			ldcp->ldc_stats.rbytes += desc.nbytes;

			/*
			 * IPALIGN space can be used for VLAN_TAG
			 */
			(void) vsw_vlan_frame_pretag(ldcp->ldc_port,
			    VSW_VNETPORT, mp);

			/* build a chain of received packets */
			if (bp == NULL) {
				/* first pkt */
				bp = mp;
				bp->b_next = bp->b_prev = NULL;
				bpt = bp;
				chain = 1;
			} else {
				mp->b_next = mp->b_prev = NULL;
				bpt->b_next = mp;
				bpt = mp;
				chain++;
			}

vsw_process_desc_done:
			/* mark we are finished with this descriptor */
			if ((rng_rv = vnet_dring_entry_set_dstate(pub_addr,
			    dp->dring_mtype, dp->dring_handle, pos, pos,
			    VIO_DESC_DONE)) != 0) {
				DERR(vswp, "%s(%lld): unable to update "
				    "dstate at pos %d: err %d",
				    __func__, pos, ldcp->ldc_id, rng_rv);
				ldcp->ldc_stats.ierrors++;
				break;
			}

			/*
			 * Send an ACK back to peer if requested.
			 */
			if (desc.hdr.ack) {
				dring_pkt->start_idx = range_start;
				dring_pkt->end_idx = range_end;

				DERR(vswp, "%s(%lld): processed %d %d, ACK"
				    " requested", __func__, ldcp->ldc_id,
				    dring_pkt->start_idx, dring_pkt->end_idx);

				dring_pkt->dring_process_state = VIO_DP_ACTIVE;
				dring_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
				dring_pkt->tag.vio_sid = ldcp->local_session;

				msg_rv = vsw_send_msg(ldcp, (void *)dring_pkt,
				    sizeof (vio_dring_msg_t), B_FALSE);

				/*
				 * Check if ACK was successfully sent. If not
				 * we break and deal with that below.
				 */
				if (msg_rv != 0)
					break;

				prev_desc_ack = B_TRUE;
				range_start = pos;
			}

			/* next descriptor */
			pos = (pos + 1) % len;
			cnt++;

			/*
			 * Break out of loop here and stop processing to
			 * allow some other network device (or disk) to
			 * get access to the cpu.
			 */
			if (chain > vsw_chain_len) {
				D3(vswp, "%s(%lld): switching chain of %d "
				    "msgs", __func__, ldcp->ldc_id, chain);
				break;
			}
		}

		/* send the chain of packets to be switched */
		if (bp != NULL) {
			DTRACE_PROBE1(vsw_rcv_msgs, int, chain);
			D3(vswp, "%s(%lld): switching chain of %d msgs",
			    __func__, ldcp->ldc_id, chain);
			vswp->vsw_switch_frame(vswp, bp, VSW_VNETPORT,
			    ldcp->ldc_port, NULL);
		}

		/*
		 * If when we encountered an error when attempting to
		 * access an imported dring, initiate a connection reset.
		 */
		if (rng_rv != 0) {
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			break;
		}

		/*
		 * If when we attempted to send the ACK we found that the
		 * channel had been reset then now handle this.
		 */
		if (msg_rv == ECONNRESET) {
			vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
			break;
		}

		DTRACE_PROBE1(msg_cnt, int, cnt);

		/*
		 * We are now finished so ACK back with the state
		 * set to STOPPING so our peer knows we are finished
		 */
		dring_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
		dring_pkt->tag.vio_sid = ldcp->local_session;

		dring_pkt->dring_process_state = VIO_DP_STOPPED;

		DTRACE_PROBE(stop_process_sent);

		/*
		 * We have not processed any more descriptors beyond
		 * the last one we ACK'd.
		 */
		if (prev_desc_ack)
			range_start = range_end;

		dring_pkt->start_idx = range_start;
		dring_pkt->end_idx = range_end;

		D2(vswp, "%s(%lld) processed : %d : %d, now stopping",
		    __func__, ldcp->ldc_id, dring_pkt->start_idx,
		    dring_pkt->end_idx);

		(void) vsw_send_msg(ldcp, (void *)dring_pkt,
		    sizeof (vio_dring_msg_t), B_TRUE);
		ldcp->ldc_stats.dring_data_acks_sent++;
		ldcp->ldc_stats.dring_stopped_acks_sent++;
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s(%lld): VIO_SUBTYPE_ACK", __func__, ldcp->ldc_id);
		/*
		 * Verify that the relevant descriptors are all
		 * marked as DONE
		 */
		dp = ldcp->lane_out.dringp;
		if (dp->ident != dring_pkt->dring_ident) {
			DERR(vswp, "%s: unknown ident in ACK", __func__);
			return;
		}

		start = end = 0;
		start = dring_pkt->start_idx;
		end = dring_pkt->end_idx;
		len = dp->num_descriptors;


		mutex_enter(&dp->dlock);
		dp->last_ack_recv = end;
		ldcp->ldc_stats.dring_data_acks_rcvd++;
		mutex_exit(&dp->dlock);

		(void) vsw_reclaim_dring(dp, start);

		/*
		 * If our peer is stopping processing descriptors then
		 * we check to make sure it has processed all the descriptors
		 * we have updated. If not then we send it a new message
		 * to prompt it to restart.
		 */
		if (dring_pkt->dring_process_state == VIO_DP_STOPPED) {
			DTRACE_PROBE(stop_process_recv);
			D2(vswp, "%s(%lld): got stopping msg : %d : %d",
			    __func__, ldcp->ldc_id, dring_pkt->start_idx,
			    dring_pkt->end_idx);

			/*
			 * Check next descriptor in public section of ring.
			 * If its marked as READY then we need to prompt our
			 * peer to start processing the ring again.
			 */
			i = (end + 1) % len;
			pub_addr = (vnet_public_desc_t *)dp->pub_addr + i;
			priv_addr = (vsw_private_desc_t *)dp->priv_addr + i;

			/*
			 * Hold the restart lock across all of this to
			 * make sure that its not possible for us to
			 * decide that a msg needs to be sent in the future
			 * but the sending code having already checked is
			 * about to exit.
			 */
			mutex_enter(&dp->restart_lock);
			ldcp->ldc_stats.dring_stopped_acks_rcvd++;
			mutex_enter(&priv_addr->dstate_lock);
			if (pub_addr->hdr.dstate == VIO_DESC_READY) {

				mutex_exit(&priv_addr->dstate_lock);

				dring_pkt->tag.vio_subtype = VIO_SUBTYPE_INFO;
				dring_pkt->tag.vio_sid = ldcp->local_session;

				dring_pkt->start_idx = (end + 1) % len;
				dring_pkt->end_idx = -1;

				D2(vswp, "%s(%lld) : sending restart msg:"
				    " %d : %d", __func__, ldcp->ldc_id,
				    dring_pkt->start_idx, dring_pkt->end_idx);

				msg_rv = vsw_send_msg(ldcp, (void *)dring_pkt,
				    sizeof (vio_dring_msg_t), B_FALSE);
				ldcp->ldc_stats.dring_data_msgs_sent++;

			} else {
				mutex_exit(&priv_addr->dstate_lock);
				dp->restart_reqd = B_TRUE;
			}
			mutex_exit(&dp->restart_lock);
		}

		if (msg_rv == ECONNRESET)
			vsw_process_conn_evt(ldcp, VSW_CONN_RESET);

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

	D1(vswp, "%s(%lld) exit", __func__, ldcp->ldc_id);
}
