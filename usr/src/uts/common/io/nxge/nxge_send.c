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

#include <sys/mac_provider.h>
#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_hio.h>
#include <npi_tx_wr64.h>

/* Software LSO required header files */
#include <netinet/tcp.h>
#include <inet/ip_impl.h>
#include <inet/tcp.h>

extern uint64_t mac_pkt_hash(uint_t, mblk_t *mp, uint8_t policy,
    boolean_t is_outbound);

static mblk_t *nxge_lso_eliminate(mblk_t *);
static mblk_t *nxge_do_softlso(mblk_t *mp, uint32_t mss);
static void nxge_lso_info_get(mblk_t *, uint32_t *, uint32_t *);
static void nxge_hcksum_retrieve(mblk_t *,
    uint32_t *, uint32_t *, uint32_t *,
    uint32_t *, uint32_t *);
static uint32_t nxge_csgen(uint16_t *, int);

extern uint32_t		nxge_reclaim_pending;
extern uint32_t 	nxge_bcopy_thresh;
extern uint32_t 	nxge_dvma_thresh;
extern uint32_t 	nxge_dma_stream_thresh;
extern uint32_t		nxge_tx_minfree;
extern uint32_t		nxge_tx_intr_thres;
extern uint32_t		nxge_tx_max_gathers;
extern uint32_t		nxge_tx_tiny_pack;
extern uint32_t		nxge_tx_use_bcopy;
extern nxge_tx_mode_t	nxge_tx_scheme;
uint32_t		nxge_lso_kick_cnt = 2;


void
nxge_tx_ring_task(void *arg)
{
	p_tx_ring_t	ring = (p_tx_ring_t)arg;

	ASSERT(ring->tx_ring_handle != NULL);

	MUTEX_ENTER(&ring->lock);
	(void) nxge_txdma_reclaim(ring->nxgep, ring, 0);
	MUTEX_EXIT(&ring->lock);

	if (!ring->tx_ring_offline) {
		mac_tx_ring_update(ring->nxgep->mach, ring->tx_ring_handle);
	}
}

static void
nxge_tx_ring_dispatch(p_tx_ring_t ring)
{
	/*
	 * Kick the ring task to reclaim some buffers.
	 */
	(void) ddi_taskq_dispatch(ring->taskq,
	    nxge_tx_ring_task, (void *)ring, DDI_SLEEP);
}

mblk_t *
nxge_tx_ring_send(void *arg, mblk_t *mp)
{
	p_nxge_ring_handle_t	nrhp = (p_nxge_ring_handle_t)arg;
	p_nxge_t		nxgep;
	p_tx_ring_t		tx_ring_p;
	int			status, channel;

	ASSERT(nrhp != NULL);
	nxgep = nrhp->nxgep;
	channel = nxgep->pt_config.hw_config.tdc.start + nrhp->index;
	tx_ring_p = nxgep->tx_rings->rings[channel];

	/*
	 * We may be in a transition from offlined DMA to onlined
	 * DMA.
	 */
	if (tx_ring_p == NULL) {
		ASSERT(tx_ring_p != NULL);
		freemsg(mp);
		return ((mblk_t *)NULL);
	}

	/*
	 * Valid DMA?
	 */
	ASSERT(nxgep == tx_ring_p->nxgep);

	/*
	 * Make sure DMA is not offlined.
	 */
	if (isLDOMservice(nxgep) && tx_ring_p->tx_ring_offline) {
		ASSERT(!tx_ring_p->tx_ring_offline);
		freemsg(mp);
		return ((mblk_t *)NULL);
	}

	/*
	 * Transmit the packet.
	 */
	status = nxge_start(nxgep, tx_ring_p, mp);
	if (status) {
		nxge_tx_ring_dispatch(tx_ring_p);
		return (mp);
	}

	return ((mblk_t *)NULL);
}

int
nxge_start(p_nxge_t nxgep, p_tx_ring_t tx_ring_p, p_mblk_t mp)
{
	int 			dma_status, status = 0;
	p_tx_desc_t 		tx_desc_ring_vp;
	npi_handle_t		npi_desc_handle;
	nxge_os_dma_handle_t 	tx_desc_dma_handle;
	p_tx_desc_t 		tx_desc_p;
	p_tx_msg_t 		tx_msg_ring;
	p_tx_msg_t 		tx_msg_p;
	tx_desc_t		tx_desc, *tmp_desc_p;
	tx_desc_t		sop_tx_desc, *sop_tx_desc_p;
	p_tx_pkt_header_t	hdrp;
	tx_pkt_hdr_all_t	tmp_hdrp;
	p_tx_pkt_hdr_all_t	pkthdrp;
	uint8_t			npads = 0;
	uint64_t 		dma_ioaddr;
	uint32_t		dma_flags;
	int			last_bidx;
	uint8_t 		*b_rptr;
	caddr_t 		kaddr;
	uint32_t		nmblks;
	uint32_t		ngathers;
	uint32_t		clen;
	int 			len;
	uint32_t		pkt_len, pack_len, min_len;
	uint32_t		bcopy_thresh;
	int 			i, cur_index, sop_index;
	uint16_t		tail_index;
	boolean_t		tail_wrap = B_FALSE;
	nxge_dma_common_t	desc_area;
	nxge_os_dma_handle_t 	dma_handle;
	ddi_dma_cookie_t 	dma_cookie;
	npi_handle_t		npi_handle;
	p_mblk_t 		nmp;
	p_mblk_t		t_mp;
	uint32_t 		ncookies;
	boolean_t 		good_packet;
	boolean_t 		mark_mode = B_FALSE;
	p_nxge_stats_t 		statsp;
	p_nxge_tx_ring_stats_t tdc_stats;
	t_uscalar_t 		start_offset = 0;
	t_uscalar_t 		stuff_offset = 0;
	t_uscalar_t 		end_offset = 0;
	t_uscalar_t 		value = 0;
	t_uscalar_t 		cksum_flags = 0;
	boolean_t		cksum_on = B_FALSE;
	uint32_t		boff = 0;
	uint64_t		tot_xfer_len = 0;
	boolean_t		header_set = B_FALSE;
#ifdef NXGE_DEBUG
	p_tx_desc_t 		tx_desc_ring_pp;
	p_tx_desc_t 		tx_desc_pp;
	tx_desc_t		*save_desc_p;
	int			dump_len;
	int			sad_len;
	uint64_t		sad;
	int			xfer_len;
	uint32_t		msgsize;
#endif
	p_mblk_t 		mp_chain = NULL;
	boolean_t		is_lso = B_FALSE;
	boolean_t		lso_again;
	int			cur_index_lso;
	p_mblk_t 		nmp_lso_save;
	uint32_t		lso_ngathers;
	boolean_t		lso_tail_wrap = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start: tx dma channel %d", tx_ring_p->tdc));
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start: Starting tdc %d desc pending %d",
	    tx_ring_p->tdc, tx_ring_p->descs_pending));

	statsp = nxgep->statsp;

	if (!isLDOMguest(nxgep)) {
		switch (nxgep->mac.portmode) {
		default:
			if (nxgep->statsp->port_stats.lb_mode ==
			    nxge_lb_normal) {
				if (!statsp->mac_stats.link_up) {
					freemsg(mp);
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_start: "
					    "link not up"));
					goto nxge_start_fail1;
				}
			}
			break;
		case PORT_10G_FIBER:
			/*
			 * For the following modes, check the link status
			 * before sending the packet out:
			 * nxge_lb_normal,
			 * nxge_lb_ext10g,
			 * nxge_lb_ext1000,
			 * nxge_lb_ext100,
			 * nxge_lb_ext10.
			 */
			if (nxgep->statsp->port_stats.lb_mode <
			    nxge_lb_phy10g) {
				if (!statsp->mac_stats.link_up) {
					freemsg(mp);
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_start: "
					    "link not up"));
					goto nxge_start_fail1;
				}
			}
			break;
		}
	}

	if ((!(nxgep->drv_state & STATE_HW_INITIALIZED)) ||
	    (nxgep->nxge_mac_state != NXGE_MAC_STARTED)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "==> nxge_start: hardware not initialized or stopped"));
		freemsg(mp);
		goto nxge_start_fail1;
	}

	if (nxgep->soft_lso_enable) {
		mp_chain = nxge_lso_eliminate(mp);
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "==> nxge_start(0): LSO mp $%p mp_chain $%p",
		    mp, mp_chain));
		if (mp_chain == NULL) {
			NXGE_ERROR_MSG((nxgep, TX_CTL,
			    "==> nxge_send(0): NULL mp_chain $%p != mp $%p",
			    mp_chain, mp));
			goto nxge_start_fail1;
		}
		if (mp_chain != mp) {
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
			    "==> nxge_send(1): IS LSO mp_chain $%p != mp $%p",
			    mp_chain, mp));
			is_lso = B_TRUE;
			mp = mp_chain;
			mp_chain = mp_chain->b_next;
			mp->b_next = NULL;
		}
	}

	mac_hcksum_get(mp, &start_offset, &stuff_offset, &end_offset,
	    &value, &cksum_flags);
	if (!NXGE_IS_VLAN_PACKET(mp->b_rptr)) {
		start_offset += sizeof (ether_header_t);
		stuff_offset += sizeof (ether_header_t);
	} else {
		start_offset += sizeof (struct ether_vlan_header);
		stuff_offset += sizeof (struct ether_vlan_header);
	}

	if (cksum_flags & HCK_PARTIALCKSUM) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "==> nxge_start: mp $%p len %d "
		    "cksum_flags 0x%x (partial checksum) ",
		    mp, MBLKL(mp), cksum_flags));
		cksum_on = B_TRUE;
	}

	pkthdrp = (p_tx_pkt_hdr_all_t)&tmp_hdrp;
	pkthdrp->reserved = 0;
	tmp_hdrp.pkthdr.value = 0;
	nxge_fill_tx_hdr(mp, B_FALSE, cksum_on,
	    0, 0, pkthdrp,
	    start_offset, stuff_offset);

	lso_again = B_FALSE;
	lso_ngathers = 0;

	MUTEX_ENTER(&tx_ring_p->lock);

	if (isLDOMservice(nxgep)) {
		tx_ring_p->tx_ring_busy = B_TRUE;
		if (tx_ring_p->tx_ring_offline) {
			freemsg(mp);
			tx_ring_p->tx_ring_busy = B_FALSE;
			(void) atomic_swap_32(&tx_ring_p->tx_ring_offline,
			    NXGE_TX_RING_OFFLINED);
			MUTEX_EXIT(&tx_ring_p->lock);
			return (status);
		}
	}

	cur_index_lso = tx_ring_p->wr_index;
	lso_tail_wrap = tx_ring_p->wr_index_wrap;
start_again:
	ngathers = 0;
	sop_index = tx_ring_p->wr_index;
#ifdef	NXGE_DEBUG
	if (tx_ring_p->descs_pending) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: "
		    "desc pending %d ", tx_ring_p->descs_pending));
	}

	dump_len = (int)(MBLKL(mp));
	dump_len = (dump_len > 128) ? 128: dump_len;

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start: tdc %d: dumping ...: b_rptr $%p "
	    "(Before header reserve: ORIGINAL LEN %d)",
	    tx_ring_p->tdc,
	    mp->b_rptr,
	    dump_len));

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: dump packets "
	    "(IP ORIGINAL b_rptr $%p): %s", mp->b_rptr,
	    nxge_dump_packet((char *)mp->b_rptr, dump_len)));
#endif

	tdc_stats = tx_ring_p->tdc_stats;
	mark_mode = (tx_ring_p->descs_pending &&
	    (((int)tx_ring_p->tx_ring_size - (int)tx_ring_p->descs_pending) <
	    (int)nxge_tx_minfree));

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "TX Descriptor ring is channel %d mark mode %d",
	    tx_ring_p->tdc, mark_mode));

	if ((tx_ring_p->descs_pending + lso_ngathers) >= nxge_reclaim_pending) {
		if (!nxge_txdma_reclaim(nxgep, tx_ring_p,
		    (nxge_tx_minfree + lso_ngathers))) {
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
			    "TX Descriptor ring is full: channel %d",
			    tx_ring_p->tdc));
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
			    "TX Descriptor ring is full: channel %d",
			    tx_ring_p->tdc));
			if (is_lso) {
				/*
				 * free the current mp and mp_chain if not FULL.
				 */
				tdc_stats->tx_no_desc++;
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "LSO packet: TX Descriptor ring is full: "
				    "channel %d",
				    tx_ring_p->tdc));
				goto nxge_start_fail_lso;
			} else {
				(void) atomic_cas_32(
				    (uint32_t *)&tx_ring_p->queueing, 0, 1);
				tdc_stats->tx_no_desc++;

				if (isLDOMservice(nxgep)) {
					tx_ring_p->tx_ring_busy = B_FALSE;
					if (tx_ring_p->tx_ring_offline) {
						(void) atomic_swap_32(
						    &tx_ring_p->tx_ring_offline,
						    NXGE_TX_RING_OFFLINED);
					}
				}

				MUTEX_EXIT(&tx_ring_p->lock);
				status = 1;
				goto nxge_start_fail1;
			}
		}
	}

	nmp = mp;
	i = sop_index = tx_ring_p->wr_index;
	nmblks = 0;
	ngathers = 0;
	pkt_len = 0;
	pack_len = 0;
	clen = 0;
	last_bidx = -1;
	good_packet = B_TRUE;

	desc_area = tx_ring_p->tdc_desc;
	npi_handle = desc_area.npi_handle;
	npi_desc_handle.regh = (nxge_os_acc_handle_t)
	    DMA_COMMON_ACC_HANDLE(desc_area);
	tx_desc_ring_vp = (p_tx_desc_t)DMA_COMMON_VPTR(desc_area);
	tx_desc_dma_handle = (nxge_os_dma_handle_t)
	    DMA_COMMON_HANDLE(desc_area);
	tx_msg_ring = tx_ring_p->tx_msg_ring;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: wr_index %d i %d",
	    sop_index, i));

#ifdef	NXGE_DEBUG
	msgsize = msgdsize(nmp);
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start(1): wr_index %d i %d msgdsize %d",
	    sop_index, i, msgsize));
#endif
	/*
	 * The first 16 bytes of the premapped buffer are reserved
	 * for header. No padding will be used.
	 */
	pkt_len = pack_len = boff = TX_PKT_HEADER_SIZE;
	if (nxge_tx_use_bcopy && (nxgep->niu_type != N2_NIU)) {
		bcopy_thresh = (nxge_bcopy_thresh - TX_PKT_HEADER_SIZE);
	} else {
		bcopy_thresh = (TX_BCOPY_SIZE - TX_PKT_HEADER_SIZE);
	}
	while (nmp) {
		good_packet = B_TRUE;
		b_rptr = nmp->b_rptr;
		len = MBLKL(nmp);
		if (len <= 0) {
			nmp = nmp->b_cont;
			continue;
		}
		nmblks++;

		NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(1): nmblks %d "
		    "len %d pkt_len %d pack_len %d",
		    nmblks, len, pkt_len, pack_len));
		/*
		 * Hardware limits the transfer length to 4K for NIU and
		 * 4076 (TX_MAX_TRANSFER_LENGTH) for Neptune. But we just
		 * use TX_MAX_TRANSFER_LENGTH as the limit for both.
		 * If len is longer than the limit, then we break nmp into
		 * two chunks: Make the first chunk equal to the limit and
		 * the second chunk for the remaining data. If the second
		 * chunk is still larger than the limit, then it will be
		 * broken into two in the next pass.
		 */
		if (len > TX_MAX_TRANSFER_LENGTH - TX_PKT_HEADER_SIZE) {
			if ((t_mp = dupb(nmp)) != NULL) {
				nmp->b_wptr = nmp->b_rptr +
				    (TX_MAX_TRANSFER_LENGTH
				    - TX_PKT_HEADER_SIZE);
				t_mp->b_rptr = nmp->b_wptr;
				t_mp->b_cont = nmp->b_cont;
				nmp->b_cont = t_mp;
				len = MBLKL(nmp);
			} else {
				if (is_lso) {
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "LSO packet: dupb failed: "
					    "channel %d",
					    tx_ring_p->tdc));
					mp = nmp;
					goto nxge_start_fail_lso;
				} else {
					good_packet = B_FALSE;
					goto nxge_start_fail2;
				}
			}
		}
		tx_desc.value = 0;
		tx_desc_p = &tx_desc_ring_vp[i];
#ifdef	NXGE_DEBUG
		tx_desc_pp = &tx_desc_ring_pp[i];
#endif
		tx_msg_p = &tx_msg_ring[i];
#if defined(__i386)
		npi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
		npi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif
		if (!header_set &&
		    ((!nxge_tx_use_bcopy && (len > TX_BCOPY_SIZE)) ||
		    (len >= bcopy_thresh))) {
			header_set = B_TRUE;
			bcopy_thresh += TX_PKT_HEADER_SIZE;
			boff = 0;
			pack_len = 0;
			kaddr = (caddr_t)DMA_COMMON_VPTR(tx_msg_p->buf_dma);
			hdrp = (p_tx_pkt_header_t)kaddr;
			clen = pkt_len;
			dma_handle = tx_msg_p->buf_dma_handle;
			dma_ioaddr = DMA_COMMON_IOADDR(tx_msg_p->buf_dma);
			(void) ddi_dma_sync(dma_handle,
			    i * nxge_bcopy_thresh, nxge_bcopy_thresh,
			    DDI_DMA_SYNC_FORDEV);

			tx_msg_p->flags.dma_type = USE_BCOPY;
			goto nxge_start_control_header_only;
		}

		pkt_len += len;
		pack_len += len;

		NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(3): "
		    "desc entry %d "
		    "DESC IOADDR $%p "
		    "desc_vp $%p tx_desc_p $%p "
		    "desc_pp $%p tx_desc_pp $%p "
		    "len %d pkt_len %d pack_len %d",
		    i,
		    DMA_COMMON_IOADDR(desc_area),
		    tx_desc_ring_vp, tx_desc_p,
		    tx_desc_ring_pp, tx_desc_pp,
		    len, pkt_len, pack_len));

		if (len < bcopy_thresh) {
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(4): "
			    "USE BCOPY: "));
			if (nxge_tx_tiny_pack) {
				uint32_t blst =
				    TXDMA_DESC_NEXT_INDEX(i, -1,
				    tx_ring_p->tx_wrap_mask);
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "==> nxge_start(5): pack"));
				if ((pack_len <= bcopy_thresh) &&
				    (last_bidx == blst)) {
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_start: pack(6) "
					    "(pkt_len %d pack_len %d)",
					    pkt_len, pack_len));
					i = blst;
					tx_desc_p = &tx_desc_ring_vp[i];
#ifdef	NXGE_DEBUG
					tx_desc_pp = &tx_desc_ring_pp[i];
#endif
					tx_msg_p = &tx_msg_ring[i];
					boff = pack_len - len;
					ngathers--;
				} else if (pack_len > bcopy_thresh &&
				    header_set) {
					pack_len = len;
					boff = 0;
					bcopy_thresh = nxge_bcopy_thresh;
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_start(7): > max NEW "
					    "bcopy thresh %d "
					    "pkt_len %d pack_len %d(next)",
					    bcopy_thresh,
					    pkt_len, pack_len));
				}
				last_bidx = i;
			}
			kaddr = (caddr_t)DMA_COMMON_VPTR(tx_msg_p->buf_dma);
			if ((boff == TX_PKT_HEADER_SIZE) && (nmblks == 1)) {
				hdrp = (p_tx_pkt_header_t)kaddr;
				header_set = B_TRUE;
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "==> nxge_start(7_x2): "
				    "pkt_len %d pack_len %d (new hdrp $%p)",
				    pkt_len, pack_len, hdrp));
			}
			tx_msg_p->flags.dma_type = USE_BCOPY;
			kaddr += boff;
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(8): "
			    "USE BCOPY: before bcopy "
			    "DESC IOADDR $%p entry %d "
			    "bcopy packets %d "
			    "bcopy kaddr $%p "
			    "bcopy ioaddr (SAD) $%p "
			    "bcopy clen %d "
			    "bcopy boff %d",
			    DMA_COMMON_IOADDR(desc_area), i,
			    tdc_stats->tx_hdr_pkts,
			    kaddr,
			    dma_ioaddr,
			    clen,
			    boff));
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: "
			    "1USE BCOPY: "));
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: "
			    "2USE BCOPY: "));
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: "
			    "last USE BCOPY: copy from b_rptr $%p "
			    "to KADDR $%p (len %d offset %d",
			    b_rptr, kaddr, len, boff));

			bcopy(b_rptr, kaddr, len);

#ifdef	NXGE_DEBUG
			dump_len = (len > 128) ? 128: len;
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
			    "==> nxge_start: dump packets "
			    "(After BCOPY len %d)"
			    "(b_rptr $%p): %s", len, nmp->b_rptr,
			    nxge_dump_packet((char *)nmp->b_rptr,
			    dump_len)));
#endif

			dma_handle = tx_msg_p->buf_dma_handle;
			dma_ioaddr = DMA_COMMON_IOADDR(tx_msg_p->buf_dma);
			(void) ddi_dma_sync(dma_handle,
			    i * nxge_bcopy_thresh, nxge_bcopy_thresh,
			    DDI_DMA_SYNC_FORDEV);
			clen = len + boff;
			tdc_stats->tx_hdr_pkts++;
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(9): "
			    "USE BCOPY: "
			    "DESC IOADDR $%p entry %d "
			    "bcopy packets %d "
			    "bcopy kaddr $%p "
			    "bcopy ioaddr (SAD) $%p "
			    "bcopy clen %d "
			    "bcopy boff %d",
			    DMA_COMMON_IOADDR(desc_area),
			    i,
			    tdc_stats->tx_hdr_pkts,
			    kaddr,
			    dma_ioaddr,
			    clen,
			    boff));
		} else {
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(12): "
			    "USE DVMA: len %d", len));
			tx_msg_p->flags.dma_type = USE_DMA;
			dma_flags = DDI_DMA_WRITE;
			if (len < nxge_dma_stream_thresh) {
				dma_flags |= DDI_DMA_CONSISTENT;
			} else {
				dma_flags |= DDI_DMA_STREAMING;
			}

			dma_handle = tx_msg_p->dma_handle;
			dma_status = ddi_dma_addr_bind_handle(dma_handle, NULL,
			    (caddr_t)b_rptr, len, dma_flags,
			    DDI_DMA_DONTWAIT, NULL,
			    &dma_cookie, &ncookies);
			if (dma_status == DDI_DMA_MAPPED) {
				dma_ioaddr = dma_cookie.dmac_laddress;
				len = (int)dma_cookie.dmac_size;
				clen = (uint32_t)dma_cookie.dmac_size;
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "==> nxge_start(12_1): "
				    "USE DVMA: len %d clen %d "
				    "ngathers %d",
				    len, clen,
				    ngathers));
#if defined(__i386)
				npi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
				npi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif
				while (ncookies > 1) {
					ngathers++;
					/*
					 * this is the fix for multiple
					 * cookies, which are basically
					 * a descriptor entry, we don't set
					 * SOP bit as well as related fields
					 */

					(void) npi_txdma_desc_gather_set(
					    npi_desc_handle,
					    &tx_desc,
					    (ngathers -1),
					    mark_mode,
					    ngathers,
					    dma_ioaddr,
					    clen);

					tx_msg_p->tx_msg_size = clen;
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_start:  DMA "
					    "ncookie %d "
					    "ngathers %d "
					    "dma_ioaddr $%p len %d"
					    "desc $%p descp $%p (%d)",
					    ncookies,
					    ngathers,
					    dma_ioaddr, clen,
					    *tx_desc_p, tx_desc_p, i));

					ddi_dma_nextcookie(dma_handle,
					    &dma_cookie);
					dma_ioaddr =
					    dma_cookie.dmac_laddress;

					len = (int)dma_cookie.dmac_size;
					clen = (uint32_t)dma_cookie.dmac_size;
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_start(12_2): "
					    "USE DVMA: len %d clen %d ",
					    len, clen));

					i = TXDMA_DESC_NEXT_INDEX(i, 1,
					    tx_ring_p->tx_wrap_mask);
					tx_desc_p = &tx_desc_ring_vp[i];

#if defined(__i386)
					npi_desc_handle.regp =
					    (uint32_t)tx_desc_p;
#else
					npi_desc_handle.regp =
					    (uint64_t)tx_desc_p;
#endif
					tx_msg_p = &tx_msg_ring[i];
					tx_msg_p->flags.dma_type = USE_NONE;
					tx_desc.value = 0;

					ncookies--;
				}
				tdc_stats->tx_ddi_pkts++;
				NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start:"
				    "DMA: ddi packets %d",
				    tdc_stats->tx_ddi_pkts));
			} else {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "dma mapping failed for %d "
				    "bytes addr $%p flags %x (%d)",
				    len, b_rptr, status, status));
				good_packet = B_FALSE;
				tdc_stats->tx_dma_bind_fail++;
				tx_msg_p->flags.dma_type = USE_NONE;
				if (is_lso) {
					mp = nmp;
					goto nxge_start_fail_lso;
				} else {
					status = 1;
					goto nxge_start_fail2;
				}
			}
		} /* ddi dvma */

		if (is_lso) {
			nmp_lso_save = nmp;
		}
		nmp = nmp->b_cont;
nxge_start_control_header_only:
#if defined(__i386)
		npi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
		npi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif
		ngathers++;

		if (ngathers == 1) {
#ifdef	NXGE_DEBUG
			save_desc_p = &sop_tx_desc;
#endif
			sop_tx_desc_p = &sop_tx_desc;
			sop_tx_desc_p->value = 0;
			sop_tx_desc_p->bits.hdw.tr_len = clen;
			sop_tx_desc_p->bits.hdw.sad = dma_ioaddr >> 32;
			sop_tx_desc_p->bits.ldw.sad = dma_ioaddr & 0xffffffff;
		} else {
#ifdef	NXGE_DEBUG
			save_desc_p = &tx_desc;
#endif
			tmp_desc_p = &tx_desc;
			tmp_desc_p->value = 0;
			tmp_desc_p->bits.hdw.tr_len = clen;
			tmp_desc_p->bits.hdw.sad = dma_ioaddr >> 32;
			tmp_desc_p->bits.ldw.sad = dma_ioaddr & 0xffffffff;

			tx_desc_p->value = tmp_desc_p->value;
		}

		NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(13): "
		    "Desc_entry %d ngathers %d "
		    "desc_vp $%p tx_desc_p $%p "
		    "len %d clen %d pkt_len %d pack_len %d nmblks %d "
		    "dma_ioaddr (SAD) $%p mark %d",
		    i, ngathers,
		    tx_desc_ring_vp, tx_desc_p,
		    len, clen, pkt_len, pack_len, nmblks,
		    dma_ioaddr, mark_mode));

#ifdef NXGE_DEBUG
		npi_desc_handle.nxgep = nxgep;
		npi_desc_handle.function.function = nxgep->function_num;
		npi_desc_handle.function.instance = nxgep->instance;
		sad = (save_desc_p->value & TX_PKT_DESC_SAD_MASK);
		xfer_len = ((save_desc_p->value & TX_PKT_DESC_TR_LEN_MASK) >>
		    TX_PKT_DESC_TR_LEN_SHIFT);


		NXGE_DEBUG_MSG((nxgep, TX_CTL, "\n\t: value 0x%llx\n"
		    "\t\tsad $%p\ttr_len %d len %d\tnptrs %d\t"
		    "mark %d sop %d\n",
		    save_desc_p->value,
		    sad,
		    save_desc_p->bits.hdw.tr_len,
		    xfer_len,
		    save_desc_p->bits.hdw.num_ptr,
		    save_desc_p->bits.hdw.mark,
		    save_desc_p->bits.hdw.sop));

		npi_txdma_dump_desc_one(npi_desc_handle, NULL, i);
#endif

		tx_msg_p->tx_msg_size = clen;
		i = TXDMA_DESC_NEXT_INDEX(i, 1, tx_ring_p->tx_wrap_mask);
		if (ngathers > nxge_tx_max_gathers) {
			good_packet = B_FALSE;
			mac_hcksum_get(mp, &start_offset,
			    &stuff_offset, &end_offset, &value,
			    &cksum_flags);

			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> nxge_start(14): pull msg - "
			    "len %d pkt_len %d ngathers %d",
			    len, pkt_len, ngathers));

			/*
			 * Just give up on this packet.
			 */
			if (is_lso) {
				mp = nmp_lso_save;
				goto nxge_start_fail_lso;
			}
			status = 0;
			goto nxge_start_fail2;
		}
	} /* while (nmp) */

	tx_msg_p->tx_message = mp;
	tx_desc_p = &tx_desc_ring_vp[sop_index];
#if defined(__i386)
	npi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
	npi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif

	pkthdrp = (p_tx_pkt_hdr_all_t)hdrp;
	pkthdrp->reserved = 0;
	hdrp->value = 0;
	bcopy(&tmp_hdrp, hdrp, sizeof (tx_pkt_header_t));

	if (pkt_len > NXGE_MTU_DEFAULT_MAX) {
		tdc_stats->tx_jumbo_pkts++;
	}

	min_len = (ETHERMIN + TX_PKT_HEADER_SIZE + (npads * 2));
	if (pkt_len < min_len) {
		/* Assume we use bcopy to premapped buffers */
		kaddr = (caddr_t)DMA_COMMON_VPTR(tx_msg_p->buf_dma);
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_start(14-1): < (msg_min + 16)"
		    "len %d pkt_len %d min_len %d bzero %d ngathers %d",
		    len, pkt_len, min_len, (min_len - pkt_len), ngathers));
		bzero((kaddr + pkt_len), (min_len - pkt_len));
		pkt_len = tx_msg_p->tx_msg_size = min_len;

		sop_tx_desc_p->bits.hdw.tr_len = min_len;

		NXGE_MEM_PIO_WRITE64(npi_desc_handle, sop_tx_desc_p->value);
		tx_desc_p->value = sop_tx_desc_p->value;

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_start(14-2): < msg_min - "
		    "len %d pkt_len %d min_len %d ngathers %d",
		    len, pkt_len, min_len, ngathers));
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: cksum_flags 0x%x ",
	    cksum_flags));
	{
		uint64_t	tmp_len;

		/* pkt_len already includes 16 + paddings!! */
		/* Update the control header length */
		tot_xfer_len = (pkt_len - TX_PKT_HEADER_SIZE);
		tmp_len = hdrp->value |
		    (tot_xfer_len << TX_PKT_HEADER_TOT_XFER_LEN_SHIFT);

		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "==> nxge_start(15_x1): setting SOP "
		    "tot_xfer_len 0x%llx (%d) pkt_len %d tmp_len "
		    "0x%llx hdrp->value 0x%llx",
		    tot_xfer_len, tot_xfer_len, pkt_len,
		    tmp_len, hdrp->value));
#if defined(_BIG_ENDIAN)
		hdrp->value = ddi_swap64(tmp_len);
#else
		hdrp->value = tmp_len;
#endif
		NXGE_DEBUG_MSG((nxgep,
		    TX_CTL, "==> nxge_start(15_x2): setting SOP "
		    "after SWAP: tot_xfer_len 0x%llx pkt_len %d "
		    "tmp_len 0x%llx hdrp->value 0x%llx",
		    tot_xfer_len, pkt_len,
		    tmp_len, hdrp->value));
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(15): setting SOP "
	    "wr_index %d "
	    "tot_xfer_len (%d) pkt_len %d npads %d",
	    sop_index,
	    tot_xfer_len, pkt_len,
	    npads));

	sop_tx_desc_p->bits.hdw.sop = 1;
	sop_tx_desc_p->bits.hdw.mark = mark_mode;
	sop_tx_desc_p->bits.hdw.num_ptr = ngathers;

	NXGE_MEM_PIO_WRITE64(npi_desc_handle, sop_tx_desc_p->value);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start(16): set SOP done"));

#ifdef NXGE_DEBUG
	npi_desc_handle.nxgep = nxgep;
	npi_desc_handle.function.function = nxgep->function_num;
	npi_desc_handle.function.instance = nxgep->instance;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "\n\t: value 0x%llx\n"
	    "\t\tsad $%p\ttr_len %d len %d\tnptrs %d\tmark %d sop %d\n",
	    save_desc_p->value,
	    sad,
	    save_desc_p->bits.hdw.tr_len,
	    xfer_len,
	    save_desc_p->bits.hdw.num_ptr,
	    save_desc_p->bits.hdw.mark,
	    save_desc_p->bits.hdw.sop));
	(void) npi_txdma_dump_desc_one(npi_desc_handle, NULL, sop_index);

	dump_len = (pkt_len > 128) ? 128: pkt_len;
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start: dump packets(17) (after sop set, len "
	    " (len/dump_len/pkt_len/tot_xfer_len) %d/%d/%d/%d):\n"
	    "ptr $%p: %s", len, dump_len, pkt_len, tot_xfer_len,
	    (char *)hdrp,
	    nxge_dump_packet((char *)hdrp, dump_len)));
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start(18): TX desc sync: sop_index %d",
	    sop_index));
#endif

	if ((ngathers == 1) || tx_ring_p->wr_index < i) {
		(void) ddi_dma_sync(tx_desc_dma_handle,
		    sop_index * sizeof (tx_desc_t),
		    ngathers * sizeof (tx_desc_t),
		    DDI_DMA_SYNC_FORDEV);

		NXGE_DEBUG_MSG((nxgep, TX_CTL, "nxge_start(19): sync 1 "
		    "cs_off = 0x%02X cs_s_off = 0x%02X "
		    "pkt_len %d ngathers %d sop_index %d\n",
		    stuff_offset, start_offset,
		    pkt_len, ngathers, sop_index));
	} else { /* more than one descriptor and wrap around */
		uint32_t nsdescs = tx_ring_p->tx_ring_size - sop_index;
		(void) ddi_dma_sync(tx_desc_dma_handle,
		    sop_index * sizeof (tx_desc_t),
		    nsdescs * sizeof (tx_desc_t),
		    DDI_DMA_SYNC_FORDEV);
		NXGE_DEBUG_MSG((nxgep, TX_CTL, "nxge_start(20): sync 1 "
		    "cs_off = 0x%02X cs_s_off = 0x%02X "
		    "pkt_len %d ngathers %d sop_index %d\n",
		    stuff_offset, start_offset,
		    pkt_len, ngathers, sop_index));

		(void) ddi_dma_sync(tx_desc_dma_handle,
		    0,
		    (ngathers - nsdescs) * sizeof (tx_desc_t),
		    DDI_DMA_SYNC_FORDEV);
		NXGE_DEBUG_MSG((nxgep, TX_CTL, "nxge_start(21): sync 2 "
		    "cs_off = 0x%02X cs_s_off = 0x%02X "
		    "pkt_len %d ngathers %d sop_index %d\n",
		    stuff_offset, start_offset,
		    pkt_len, ngathers, sop_index));
	}

	tail_index = tx_ring_p->wr_index;
	tail_wrap = tx_ring_p->wr_index_wrap;

	tx_ring_p->wr_index = i;
	if (tx_ring_p->wr_index <= tail_index) {
		tx_ring_p->wr_index_wrap = ((tail_wrap == B_TRUE) ?
		    B_FALSE : B_TRUE);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: TX kick: "
	    "channel %d wr_index %d wrap %d ngathers %d desc_pend %d",
	    tx_ring_p->tdc,
	    tx_ring_p->wr_index,
	    tx_ring_p->wr_index_wrap,
	    ngathers,
	    tx_ring_p->descs_pending));

	if (is_lso) {
		lso_ngathers += ngathers;
		if (mp_chain != NULL) {
			mp = mp_chain;
			mp_chain = mp_chain->b_next;
			mp->b_next = NULL;
			if (nxge_lso_kick_cnt == lso_ngathers) {
				tx_ring_p->descs_pending += lso_ngathers;
				{
					tx_ring_kick_t		kick;

					kick.value = 0;
					kick.bits.ldw.wrap =
					    tx_ring_p->wr_index_wrap;
					kick.bits.ldw.tail =
					    (uint16_t)tx_ring_p->wr_index;

					/* Kick the Transmit kick register */
					TXDMA_REG_WRITE64(
					    NXGE_DEV_NPI_HANDLE(nxgep),
					    TX_RING_KICK_REG,
					    (uint8_t)tx_ring_p->tdc,
					    kick.value);
					tdc_stats->tx_starts++;

					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_start: more LSO: "
					    "LSO_CNT %d",
					    lso_ngathers));
				}
				lso_ngathers = 0;
				ngathers = 0;
				cur_index_lso = sop_index = tx_ring_p->wr_index;
				lso_tail_wrap = tx_ring_p->wr_index_wrap;
			}
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
			    "==> nxge_start: lso again: "
			    "lso_gathers %d ngathers %d cur_index_lso %d "
			    "wr_index %d sop_index %d",
			    lso_ngathers, ngathers, cur_index_lso,
			    tx_ring_p->wr_index, sop_index));

			NXGE_DEBUG_MSG((nxgep, TX_CTL,
			    "==> nxge_start: next : count %d",
			    lso_ngathers));
			lso_again = B_TRUE;
			goto start_again;
		}
		ngathers = lso_ngathers;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: TX KICKING: "));

	{
		tx_ring_kick_t		kick;

		kick.value = 0;
		kick.bits.ldw.wrap = tx_ring_p->wr_index_wrap;
		kick.bits.ldw.tail = (uint16_t)tx_ring_p->wr_index;

		/* Kick start the Transmit kick register */
		TXDMA_REG_WRITE64(NXGE_DEV_NPI_HANDLE(nxgep),
		    TX_RING_KICK_REG,
		    (uint8_t)tx_ring_p->tdc,
		    kick.value);
	}

	tx_ring_p->descs_pending += ngathers;
	tdc_stats->tx_starts++;

	if (isLDOMservice(nxgep)) {
		tx_ring_p->tx_ring_busy = B_FALSE;
		if (tx_ring_p->tx_ring_offline) {
			(void) atomic_swap_32(&tx_ring_p->tx_ring_offline,
			    NXGE_TX_RING_OFFLINED);
		}
	}

	MUTEX_EXIT(&tx_ring_p->lock);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_start"));
	return (status);

nxge_start_fail_lso:
	status = 0;
	good_packet = B_FALSE;
	if (mp != NULL)
		freemsg(mp);
	if (mp_chain != NULL)
		freemsgchain(mp_chain);

	if (!lso_again && !ngathers) {
		if (isLDOMservice(nxgep)) {
			tx_ring_p->tx_ring_busy = B_FALSE;
			if (tx_ring_p->tx_ring_offline) {
				(void) atomic_swap_32(
				    &tx_ring_p->tx_ring_offline,
				    NXGE_TX_RING_OFFLINED);
			}
		}

		MUTEX_EXIT(&tx_ring_p->lock);
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "==> nxge_start: lso exit (nothing changed)"));
		goto nxge_start_fail1;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start (channel %d): before lso "
	    "lso_gathers %d ngathers %d cur_index_lso %d "
	    "wr_index %d sop_index %d lso_again %d",
	    tx_ring_p->tdc,
	    lso_ngathers, ngathers, cur_index_lso,
	    tx_ring_p->wr_index, sop_index, lso_again));

	if (lso_again) {
		lso_ngathers += ngathers;
		ngathers = lso_ngathers;
		sop_index = cur_index_lso;
		tx_ring_p->wr_index = sop_index;
		tx_ring_p->wr_index_wrap = lso_tail_wrap;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_start (channel %d): after lso "
	    "lso_gathers %d ngathers %d cur_index_lso %d "
	    "wr_index %d sop_index %d lso_again %d",
	    tx_ring_p->tdc,
	    lso_ngathers, ngathers, cur_index_lso,
	    tx_ring_p->wr_index, sop_index, lso_again));

nxge_start_fail2:
	if (good_packet == B_FALSE) {
		cur_index = sop_index;
		NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: clean up"));
		for (i = 0; i < ngathers; i++) {
			tx_desc_p = &tx_desc_ring_vp[cur_index];
#if defined(__i386)
			npi_handle.regp = (uint32_t)tx_desc_p;
#else
			npi_handle.regp = (uint64_t)tx_desc_p;
#endif
			tx_msg_p = &tx_msg_ring[cur_index];
			(void) npi_txdma_desc_set_zero(npi_handle, 1);
			if (tx_msg_p->flags.dma_type == USE_DVMA) {
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "tx_desc_p = %X index = %d",
				    tx_desc_p, tx_ring_p->rd_index));
				(void) dvma_unload(tx_msg_p->dvma_handle,
				    0, -1);
				tx_msg_p->dvma_handle = NULL;
				if (tx_ring_p->dvma_wr_index ==
				    tx_ring_p->dvma_wrap_mask)
					tx_ring_p->dvma_wr_index = 0;
				else
					tx_ring_p->dvma_wr_index++;
				tx_ring_p->dvma_pending--;
			} else if (tx_msg_p->flags.dma_type == USE_DMA) {
				if (ddi_dma_unbind_handle(
				    tx_msg_p->dma_handle)) {
					cmn_err(CE_WARN, "!nxge_start: "
					    "ddi_dma_unbind_handle failed");
				}
			}
			tx_msg_p->flags.dma_type = USE_NONE;
			cur_index = TXDMA_DESC_NEXT_INDEX(cur_index, 1,
			    tx_ring_p->tx_wrap_mask);

		}
	}

	if (isLDOMservice(nxgep)) {
		tx_ring_p->tx_ring_busy = B_FALSE;
		if (tx_ring_p->tx_ring_offline) {
			(void) atomic_swap_32(&tx_ring_p->tx_ring_offline,
			    NXGE_TX_RING_OFFLINED);
		}
	}

	MUTEX_EXIT(&tx_ring_p->lock);

nxge_start_fail1:
	/* Add FMA to check the access handle nxge_hregh */

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_start"));
	return (status);
}

/* Software LSO starts here */
static void
nxge_hcksum_retrieve(mblk_t *mp,
    uint32_t *start, uint32_t *stuff, uint32_t *end,
    uint32_t *value, uint32_t *flags)
{
	if (mp->b_datap->db_type == M_DATA) {
		if (flags != NULL) {
			*flags = DB_CKSUMFLAGS(mp) & (HCK_IPV4_HDRCKSUM |
			    HCK_PARTIALCKSUM | HCK_FULLCKSUM |
			    HCK_FULLCKSUM_OK);
			if ((*flags & (HCK_PARTIALCKSUM |
			    HCK_FULLCKSUM)) != 0) {
				if (value != NULL)
					*value = (uint32_t)DB_CKSUM16(mp);
				if ((*flags & HCK_PARTIALCKSUM) != 0) {
					if (start != NULL)
						*start =
						    (uint32_t)DB_CKSUMSTART(mp);
					if (stuff != NULL)
						*stuff =
						    (uint32_t)DB_CKSUMSTUFF(mp);
					if (end != NULL)
						*end =
						    (uint32_t)DB_CKSUMEND(mp);
				}
			}
		}
	}
}

static void
nxge_lso_info_get(mblk_t *mp, uint32_t *mss, uint32_t *flags)
{
	ASSERT(DB_TYPE(mp) == M_DATA);

	*mss = 0;
	if (flags != NULL) {
		*flags = DB_CKSUMFLAGS(mp) & HW_LSO;
		if ((*flags != 0) && (mss != NULL)) {
			*mss = (uint32_t)DB_LSOMSS(mp);
		}
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_lso_info_get(flag !=NULL): mss %d *flags 0x%x",
		    *mss, *flags));
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_lso_info_get: mss %d", *mss));
}

/*
 * Do Soft LSO on the oversized packet.
 *
 * 1. Create a chain of message for headers.
 * 2. Fill up header messages with proper information.
 * 3. Copy Eithernet, IP, and TCP headers from the original message to
 *    each new message with necessary adjustments.
 *    * Unchange the ethernet header for DIX frames. (by default)
 *    * IP Total Length field is updated to MSS or less(only for the last one).
 *    * IP Identification value is incremented by one for each packet.
 *    * TCP sequence Number is recalculated according to the payload length.
 *    * Set FIN and/or PSH flags for the *last* packet if applied.
 *    * TCP partial Checksum
 * 4. Update LSO information in the first message header.
 * 5. Release the original message header.
 */
static mblk_t *
nxge_do_softlso(mblk_t *mp, uint32_t mss)
{
	uint32_t	hckflags;
	int		pktlen;
	int		hdrlen;
	int		segnum;
	int		i;
	struct ether_vlan_header *evh;
	int		ehlen, iphlen, tcphlen;
	struct ip	*oiph, *niph;
	struct tcphdr *otcph, *ntcph;
	int		available, len, left;
	uint16_t	ip_id;
	uint32_t	tcp_seq;
#ifdef __sparc
	uint32_t	tcp_seq_tmp;
#endif
	mblk_t		*datamp;
	uchar_t		*rptr;
	mblk_t		*nmp;
	mblk_t		*cmp;
	mblk_t		*mp_chain;
	boolean_t do_cleanup = B_FALSE;
	t_uscalar_t start_offset = 0;
	t_uscalar_t stuff_offset = 0;
	t_uscalar_t value = 0;
	uint16_t	l4_len;
	ipaddr_t	src, dst;
	uint32_t	cksum, sum, l4cksum;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_do_softlso"));
	/*
	 * check the length of LSO packet payload and calculate the number of
	 * segments to be generated.
	 */
	pktlen = msgsize(mp);
	evh = (struct ether_vlan_header *)mp->b_rptr;

	/* VLAN? */
	if (evh->ether_tpid == htons(ETHERTYPE_VLAN))
		ehlen = sizeof (struct ether_vlan_header);
	else
		ehlen = sizeof (struct ether_header);
	oiph = (struct ip *)(mp->b_rptr + ehlen);
	iphlen = oiph->ip_hl * 4;
	otcph = (struct tcphdr *)(mp->b_rptr + ehlen + iphlen);
	tcphlen = otcph->th_off * 4;

	l4_len = pktlen - ehlen - iphlen;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_do_softlso: mss %d oiph $%p "
	    "original ip_sum oiph->ip_sum 0x%x "
	    "original tcp_sum otcph->th_sum 0x%x "
	    "oiph->ip_len %d pktlen %d ehlen %d "
	    "l4_len %d (0x%x) ip_len - iphlen %d ",
	    mss,
	    oiph,
	    oiph->ip_sum,
	    otcph->th_sum,
	    ntohs(oiph->ip_len), pktlen,
	    ehlen,
	    l4_len,
	    l4_len,
	    ntohs(oiph->ip_len) - iphlen));

	/* IPv4 + TCP */
	if (!(oiph->ip_v == IPV4_VERSION)) {
		NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL,
		    "<== nxge_do_softlso: not IPV4 "
		    "oiph->ip_len %d pktlen %d ehlen %d tcphlen %d",
		    ntohs(oiph->ip_len), pktlen, ehlen,
		    tcphlen));
		freemsg(mp);
		return (NULL);
	}

	if (!(oiph->ip_p == IPPROTO_TCP)) {
		NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL,
		    "<== nxge_do_softlso: not TCP "
		    "oiph->ip_len %d pktlen %d ehlen %d tcphlen %d",
		    ntohs(oiph->ip_len), pktlen, ehlen,
		    tcphlen));
		freemsg(mp);
		return (NULL);
	}

	if (!(ntohs(oiph->ip_len) == pktlen - ehlen)) {
		NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL,
		    "<== nxge_do_softlso: len not matched  "
		    "oiph->ip_len %d pktlen %d ehlen %d tcphlen %d",
		    ntohs(oiph->ip_len), pktlen, ehlen,
		    tcphlen));
		freemsg(mp);
		return (NULL);
	}

	otcph = (struct tcphdr *)(mp->b_rptr + ehlen + iphlen);
	tcphlen = otcph->th_off * 4;

	/* TCP flags can not include URG, RST, or SYN */
	VERIFY((otcph->th_flags & (TH_SYN | TH_RST | TH_URG)) == 0);

	hdrlen = ehlen + iphlen + tcphlen;

	VERIFY(MBLKL(mp) >= hdrlen);

	if (MBLKL(mp) > hdrlen) {
		datamp = mp;
		rptr = mp->b_rptr + hdrlen;
	} else { /* = */
		datamp = mp->b_cont;
		rptr = datamp->b_rptr;
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "nxge_do_softlso: otcph $%p pktlen: %d, "
	    "hdrlen %d ehlen %d iphlen %d tcphlen %d "
	    "mblkl(mp): %d, mblkl(datamp): %d",
	    otcph,
	    pktlen, hdrlen, ehlen, iphlen, tcphlen,
	    (int)MBLKL(mp), (int)MBLKL(datamp)));

	hckflags = 0;
	nxge_hcksum_retrieve(mp,
	    &start_offset, &stuff_offset, &value, NULL, &hckflags);

	dst = oiph->ip_dst.s_addr;
	src = oiph->ip_src.s_addr;

	cksum = (dst >> 16) + (dst & 0xFFFF) +
	    (src >> 16) + (src & 0xFFFF);
	l4cksum = cksum + IP_TCP_CSUM_COMP;

	sum = l4_len + l4cksum;
	sum = (sum & 0xFFFF) + (sum >> 16);

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_do_softlso: dst 0x%x src 0x%x sum 0x%x ~new 0x%x "
	    "hckflags 0x%x start_offset %d stuff_offset %d "
	    "value (original) 0x%x th_sum 0x%x "
	    "pktlen %d l4_len %d (0x%x) "
	    "MBLKL(mp): %d, MBLKL(datamp): %d dump header %s",
	    dst, src,
	    (sum & 0xffff), (~sum & 0xffff),
	    hckflags, start_offset, stuff_offset,
	    value, otcph->th_sum,
	    pktlen,
	    l4_len,
	    l4_len,
	    ntohs(oiph->ip_len) - (int)MBLKL(mp),
	    (int)MBLKL(datamp),
	    nxge_dump_packet((char *)evh, 12)));

	/*
	 * Start to process.
	 */
	available = pktlen - hdrlen;
	segnum = (available - 1) / mss + 1;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_do_softlso: pktlen %d "
	    "MBLKL(mp): %d, MBLKL(datamp): %d "
	    "available %d mss %d segnum %d",
	    pktlen, (int)MBLKL(mp), (int)MBLKL(datamp),
	    available,
	    mss,
	    segnum));

	VERIFY(segnum >= 2);

	/*
	 * Try to pre-allocate all header messages
	 */
	mp_chain = NULL;
	for (i = 0; i < segnum; i++) {
		if ((nmp = allocb(hdrlen, 0)) == NULL) {
			/* Clean up the mp_chain */
			while (mp_chain != NULL) {
				nmp = mp_chain;
				mp_chain = mp_chain->b_next;
				freemsg(nmp);
			}
			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "<== nxge_do_softlso: "
			    "Could not allocate enough messages for headers!"));
			freemsg(mp);
			return (NULL);
		}
		nmp->b_next = mp_chain;
		mp_chain = nmp;

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_do_softlso: "
		    "mp $%p nmp $%p mp_chain $%p mp_chain->b_next $%p",
		    mp, nmp, mp_chain, mp_chain->b_next));
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_do_softlso: mp $%p nmp $%p mp_chain $%p",
	    mp, nmp, mp_chain));

	/*
	 * Associate payload with new packets
	 */
	cmp = mp_chain;
	left = available;
	while (cmp != NULL) {
		nmp = dupb(datamp);
		if (nmp == NULL) {
			do_cleanup = B_TRUE;
			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==>nxge_do_softlso: "
			    "Can not dupb(datamp), have to do clean up"));
			goto cleanup_allocated_msgs;
		}

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_do_softlso: (loop) before mp $%p cmp $%p "
		    "dupb nmp $%p len %d left %d msd %d ",
		    mp, cmp, nmp, len, left, mss));

		cmp->b_cont = nmp;
		nmp->b_rptr = rptr;
		len = (left < mss) ? left : mss;
		left -= len;

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_do_softlso: (loop) after mp $%p cmp $%p "
		    "dupb nmp $%p len %d left %d mss %d ",
		    mp, cmp, nmp, len, left, mss));
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "nxge_do_softlso: before available: %d, "
		    "left: %d, len: %d, segnum: %d MBLK(nmp): %d",
		    available, left, len, segnum, (int)MBLKL(nmp)));

		len -= MBLKL(nmp);
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "nxge_do_softlso: after available: %d, "
		    "left: %d, len: %d, segnum: %d MBLK(nmp): %d",
		    available, left, len, segnum, (int)MBLKL(nmp)));

		while (len > 0) {
			mblk_t *mmp = NULL;

			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "nxge_do_softlso: (4) len > 0 available: %d, "
			    "left: %d, len: %d, segnum: %d MBLK(nmp): %d",
			    available, left, len, segnum, (int)MBLKL(nmp)));

			if (datamp->b_cont != NULL) {
				datamp = datamp->b_cont;
				rptr = datamp->b_rptr;
				mmp = dupb(datamp);
				if (mmp == NULL) {
					do_cleanup = B_TRUE;
					NXGE_DEBUG_MSG((NULL, TX_CTL,
					    "==> nxge_do_softlso: "
					    "Can not dupb(datamp) (1), :"
					    "have to do clean up"));
					NXGE_DEBUG_MSG((NULL, TX_CTL,
					    "==> nxge_do_softlso: "
					    "available: %d, left: %d, "
					    "len: %d, MBLKL(nmp): %d",
					    available, left, len,
					    (int)MBLKL(nmp)));
					goto cleanup_allocated_msgs;
				}
			} else {
				NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL,
				    "==> nxge_do_softlso: "
				    "(1)available: %d, left: %d, "
				    "len: %d, MBLKL(nmp): %d",
				    available, left, len,
				    (int)MBLKL(nmp)));
				cmn_err(CE_PANIC,
				    "==> nxge_do_softlso: "
				    "Pointers must have been corrupted!\n"
				    "datamp: $%p, nmp: $%p, rptr: $%p",
				    (void *)datamp,
				    (void *)nmp,
				    (void *)rptr);
			}
			nmp->b_cont = mmp;
			nmp = mmp;
			len -= MBLKL(nmp);
		}
		if (len < 0) {
			nmp->b_wptr += len;
			rptr = nmp->b_wptr;
			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "(5) len < 0 (less than 0)"
			    "available: %d, left: %d, len: %d, MBLKL(nmp): %d",
			    available, left, len, (int)MBLKL(nmp)));

		} else if (len == 0) {
			if (datamp->b_cont != NULL) {
				NXGE_DEBUG_MSG((NULL, TX_CTL,
				    "(5) len == 0"
				    "available: %d, left: %d, len: %d, "
				    "MBLKL(nmp): %d",
				    available, left, len, (int)MBLKL(nmp)));
				datamp = datamp->b_cont;
				rptr = datamp->b_rptr;
			} else {
				NXGE_DEBUG_MSG((NULL, TX_CTL,
				    "(6)available b_cont == NULL : %d, "
				    "left: %d, len: %d, MBLKL(nmp): %d",
				    available, left, len, (int)MBLKL(nmp)));

				VERIFY(cmp->b_next == NULL);
				VERIFY(left == 0);
				break; /* Done! */
			}
		}
		cmp = cmp->b_next;

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "(7) do_softlso: "
		    "next mp in mp_chain available len != 0 : %d, "
		    "left: %d, len: %d, MBLKL(nmp): %d",
		    available, left, len, (int)MBLKL(nmp)));
	}

	/*
	 * From now, start to fill up all headers for the first message
	 * Hardware checksum flags need to be updated separately for FULLCKSUM
	 * and PARTIALCKSUM cases. For full checksum, copy the original flags
	 * into every new packet is enough. But for HCK_PARTIALCKSUM, all
	 * required fields need to be updated properly.
	 */
	nmp = mp_chain;
	bcopy(mp->b_rptr, nmp->b_rptr, hdrlen);
	nmp->b_wptr = nmp->b_rptr + hdrlen;
	niph = (struct ip *)(nmp->b_rptr + ehlen);
	niph->ip_len = htons(mss + iphlen + tcphlen);
	ip_id = ntohs(niph->ip_id);
	ntcph = (struct tcphdr *)(nmp->b_rptr + ehlen + iphlen);
#ifdef __sparc
	bcopy((char *)&ntcph->th_seq, &tcp_seq_tmp, 4);
	tcp_seq = ntohl(tcp_seq_tmp);
#else
	tcp_seq = ntohl(ntcph->th_seq);
#endif

	ntcph->th_flags &= ~(TH_FIN | TH_PUSH | TH_RST);

	DB_CKSUMFLAGS(nmp) = (uint16_t)hckflags;
	DB_CKSUMSTART(nmp) = start_offset;
	DB_CKSUMSTUFF(nmp) = stuff_offset;

	/* calculate IP checksum and TCP pseudo header checksum */
	niph->ip_sum = 0;
	niph->ip_sum = (uint16_t)nxge_csgen((uint16_t *)niph, iphlen);

	l4_len = mss + tcphlen;
	sum = htons(l4_len) + l4cksum;
	sum = (sum & 0xFFFF) + (sum >> 16);
	ntcph->th_sum = (sum & 0xffff);

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_do_softlso: first mp $%p (mp_chain $%p) "
	    "mss %d pktlen %d l4_len %d (0x%x) "
	    "MBLKL(mp): %d, MBLKL(datamp): %d "
	    "ip_sum 0x%x "
	    "th_sum 0x%x sum 0x%x ) "
	    "dump first ip->tcp %s",
	    nmp, mp_chain,
	    mss,
	    pktlen,
	    l4_len,
	    l4_len,
	    (int)MBLKL(mp), (int)MBLKL(datamp),
	    niph->ip_sum,
	    ntcph->th_sum,
	    sum,
	    nxge_dump_packet((char *)niph, 52)));

	cmp = nmp;
	while ((nmp = nmp->b_next)->b_next != NULL) {
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==>nxge_do_softlso: middle l4_len %d ", l4_len));
		bcopy(cmp->b_rptr, nmp->b_rptr, hdrlen);
		nmp->b_wptr = nmp->b_rptr + hdrlen;
		niph = (struct ip *)(nmp->b_rptr + ehlen);
		niph->ip_id = htons(++ip_id);
		niph->ip_len = htons(mss + iphlen + tcphlen);
		ntcph = (struct tcphdr *)(nmp->b_rptr + ehlen + iphlen);
		tcp_seq += mss;

		ntcph->th_flags &= ~(TH_FIN | TH_PUSH | TH_RST | TH_URG);

#ifdef __sparc
		tcp_seq_tmp = htonl(tcp_seq);
		bcopy(&tcp_seq_tmp, (char *)&ntcph->th_seq, 4);
#else
		ntcph->th_seq = htonl(tcp_seq);
#endif
		DB_CKSUMFLAGS(nmp) = (uint16_t)hckflags;
		DB_CKSUMSTART(nmp) = start_offset;
		DB_CKSUMSTUFF(nmp) = stuff_offset;

		/* calculate IP checksum and TCP pseudo header checksum */
		niph->ip_sum = 0;
		niph->ip_sum = (uint16_t)nxge_csgen((uint16_t *)niph, iphlen);
		ntcph->th_sum = (sum & 0xffff);

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_do_softlso: middle ip_sum 0x%x "
		    "th_sum 0x%x "
		    " mp $%p (mp_chain $%p) pktlen %d "
		    "MBLKL(mp): %d, MBLKL(datamp): %d ",
		    niph->ip_sum,
		    ntcph->th_sum,
		    nmp, mp_chain,
		    pktlen, (int)MBLKL(mp), (int)MBLKL(datamp)));
	}

	/* Last segment */
	/*
	 * Set FIN and/or PSH flags if present only in the last packet.
	 * The ip_len could be different from prior packets.
	 */
	bcopy(cmp->b_rptr, nmp->b_rptr, hdrlen);
	nmp->b_wptr = nmp->b_rptr + hdrlen;
	niph = (struct ip *)(nmp->b_rptr + ehlen);
	niph->ip_id = htons(++ip_id);
	niph->ip_len = htons(msgsize(nmp->b_cont) + iphlen + tcphlen);
	ntcph = (struct tcphdr *)(nmp->b_rptr + ehlen + iphlen);
	tcp_seq += mss;
#ifdef __sparc
	tcp_seq_tmp = htonl(tcp_seq);
	bcopy(&tcp_seq_tmp, (char *)&ntcph->th_seq, 4);
#else
	ntcph->th_seq = htonl(tcp_seq);
#endif
	ntcph->th_flags = (otcph->th_flags & ~TH_URG);

	DB_CKSUMFLAGS(nmp) = (uint16_t)hckflags;
	DB_CKSUMSTART(nmp) = start_offset;
	DB_CKSUMSTUFF(nmp) = stuff_offset;

	/* calculate IP checksum and TCP pseudo header checksum */
	niph->ip_sum = 0;
	niph->ip_sum = (uint16_t)nxge_csgen((uint16_t *)niph, iphlen);

	l4_len = ntohs(niph->ip_len) - iphlen;
	sum = htons(l4_len) + l4cksum;
	sum = (sum & 0xFFFF) + (sum >> 16);
	ntcph->th_sum = (sum & 0xffff);

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_do_softlso: last next "
	    "niph->ip_sum 0x%x "
	    "ntcph->th_sum 0x%x sum 0x%x "
	    "dump last ip->tcp %s "
	    "cmp $%p mp $%p (mp_chain $%p) pktlen %d (0x%x) "
	    "l4_len %d (0x%x) "
	    "MBLKL(mp): %d, MBLKL(datamp): %d ",
	    niph->ip_sum,
	    ntcph->th_sum, sum,
	    nxge_dump_packet((char *)niph, 52),
	    cmp, nmp, mp_chain,
	    pktlen, pktlen,
	    l4_len,
	    l4_len,
	    (int)MBLKL(mp), (int)MBLKL(datamp)));

cleanup_allocated_msgs:
	if (do_cleanup) {
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_do_softlso: "
		    "Failed allocating messages, "
		    "have to clean up and fail!"));
		while (mp_chain != NULL) {
			nmp = mp_chain;
			mp_chain = mp_chain->b_next;
			freemsg(nmp);
		}
	}
	/*
	 * We're done here, so just free the original message and return the
	 * new message chain, that could be NULL if failed, back to the caller.
	 */
	freemsg(mp);

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_do_softlso:mp_chain $%p", mp_chain));
	return (mp_chain);
}

/*
 * Will be called before NIC driver do further operation on the message.
 * The input message may include LSO information, if so, go to softlso logic
 * to eliminate the oversized LSO packet for the incapable underlying h/w.
 * The return could be the same non-LSO message or a message chain for LSO case.
 *
 * The driver needs to call this function per packet and process the whole chain
 * if applied.
 */
static mblk_t *
nxge_lso_eliminate(mblk_t *mp)
{
	uint32_t lsoflags;
	uint32_t mss;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==>nxge_lso_eliminate:"));
	nxge_lso_info_get(mp, &mss, &lsoflags);

	if (lsoflags & HW_LSO) {
		mblk_t *nmp;

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==>nxge_lso_eliminate:"
		    "HW_LSO:mss %d mp $%p",
		    mss, mp));
		if ((nmp = nxge_do_softlso(mp, mss)) != NULL) {
			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "<== nxge_lso_eliminate: "
			    "LSO: nmp not NULL nmp $%p mss %d mp $%p",
			    nmp, mss, mp));
			return (nmp);
		} else {
			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "<== nxge_lso_eliminate_ "
			    "LSO: failed nmp NULL nmp $%p mss %d mp $%p",
			    nmp, mss, mp));
			return (NULL);
		}
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_lso_eliminate"));
	return (mp);
}

static uint32_t
nxge_csgen(uint16_t *adr, int len)
{
	int		i, odd;
	uint32_t	sum = 0;
	uint32_t	c = 0;

	odd = len % 2;
	for (i = 0; i < (len / 2); i++) {
		sum += (adr[i] & 0xffff);
	}
	if (odd) {
		sum += adr[len / 2] & 0xff00;
	}
	while ((c = ((sum & 0xffff0000) >> 16)) != 0) {
		sum &= 0xffff;
		sum += c;
	}
	return (~sum & 0xffff);
}
