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

#include <hxge_impl.h>

extern uint32_t hxge_reclaim_pending;
extern uint32_t hxge_bcopy_thresh;
extern uint32_t hxge_dvma_thresh;
extern uint32_t hxge_dma_stream_thresh;
extern uint32_t	hxge_tx_minfree;
extern uint32_t	hxge_tx_intr_thres;
extern uint32_t	hxge_tx_max_gathers;
extern uint32_t	hxge_tx_tiny_pack;
extern uint32_t	hxge_tx_use_bcopy;

static int hxge_start(p_hxge_t hxgep, p_tx_ring_t tx_ring_p, p_mblk_t mp);

void
hxge_tx_ring_task(void *arg)
{
	p_tx_ring_t	ring = (p_tx_ring_t)arg;

	MUTEX_ENTER(&ring->lock);
	(void) hxge_txdma_reclaim(ring->hxgep, ring, 0);
	MUTEX_EXIT(&ring->lock);

	mac_tx_ring_update(ring->hxgep->mach, ring->ring_handle);
}

static void
hxge_tx_ring_dispatch(p_tx_ring_t ring)
{
	/*
	 * Kick the ring task to reclaim some buffers.
	 */
	(void) ddi_taskq_dispatch(ring->taskq,
	    hxge_tx_ring_task, (void *)ring, DDI_SLEEP);
}

mblk_t *
hxge_tx_ring_send(void *arg, mblk_t *mp)
{
	p_hxge_ring_handle_t    rhp = (p_hxge_ring_handle_t)arg;
	p_hxge_t		hxgep;
	p_tx_ring_t		tx_ring_p;
	int			status;

	ASSERT(rhp != NULL);
	ASSERT((rhp->index >= 0) && (rhp->index < HXGE_MAX_TDCS));

	hxgep = rhp->hxgep;
	tx_ring_p = hxgep->tx_rings->rings[rhp->index];
	ASSERT(hxgep == tx_ring_p->hxgep);

	status = hxge_start(hxgep, tx_ring_p, mp);
	if (status != 0) {
		hxge_tx_ring_dispatch(tx_ring_p);
		return (mp);
	}

	return ((mblk_t *)NULL);
}

static int
hxge_start(p_hxge_t hxgep, p_tx_ring_t tx_ring_p, p_mblk_t mp)
{
	int 			dma_status, status = 0;
	p_tx_desc_t 		tx_desc_ring_vp;
	hpi_handle_t		hpi_desc_handle;
	hxge_os_dma_handle_t 	tx_desc_dma_handle;
	p_tx_desc_t 		tx_desc_p;
	p_tx_msg_t 		tx_msg_ring;
	p_tx_msg_t 		tx_msg_p;
	tx_desc_t		tx_desc, *tmp_desc_p;
	tx_desc_t		sop_tx_desc, *sop_tx_desc_p;
	p_tx_pkt_header_t	hdrp;
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
	hxge_dma_common_t	desc_area;
	hxge_os_dma_handle_t 	dma_handle;
	ddi_dma_cookie_t 	dma_cookie;
	hpi_handle_t		hpi_handle;
	p_mblk_t 		nmp;
	p_mblk_t		t_mp;
	uint32_t 		ncookies;
	boolean_t 		good_packet;
	boolean_t 		mark_mode = B_FALSE;
	p_hxge_stats_t 		statsp;
	p_hxge_tx_ring_stats_t	tdc_stats;
	t_uscalar_t 		start_offset = 0;
	t_uscalar_t 		stuff_offset = 0;
	t_uscalar_t 		end_offset = 0;
	t_uscalar_t 		value = 0;
	t_uscalar_t 		cksum_flags = 0;
	boolean_t		cksum_on = B_FALSE;
	uint32_t		boff = 0;
	uint64_t		tot_xfer_len = 0, tmp_len = 0;
	boolean_t		header_set = B_FALSE;
	tdc_tdr_kick_t		kick;
	uint32_t		offset;
#ifdef HXGE_DEBUG
	p_tx_desc_t 		tx_desc_ring_pp;
	p_tx_desc_t 		tx_desc_pp;
	tx_desc_t		*save_desc_p;
	int			dump_len;
	int			sad_len;
	uint64_t		sad;
	int			xfer_len;
	uint32_t		msgsize;
#endif

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start: tx dma channel %d", tx_ring_p->tdc));
	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start: Starting tdc %d desc pending %d",
	    tx_ring_p->tdc, tx_ring_p->descs_pending));

	statsp = hxgep->statsp;

	if (hxgep->statsp->port_stats.lb_mode == hxge_lb_normal) {
		if (!statsp->mac_stats.link_up) {
			freemsg(mp);
			HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start: "
			    "link not up or LB mode"));
			goto hxge_start_fail1;
		}
	}

	mac_hcksum_get(mp, &start_offset, &stuff_offset, &end_offset, &value,
	    &cksum_flags);
	if (!HXGE_IS_VLAN_PACKET(mp->b_rptr)) {
		start_offset += sizeof (ether_header_t);
		stuff_offset += sizeof (ether_header_t);
	} else {
		start_offset += sizeof (struct ether_vlan_header);
		stuff_offset += sizeof (struct ether_vlan_header);
	}

	if (cksum_flags & HCK_PARTIALCKSUM) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_start: mp $%p len %d "
		    "cksum_flags 0x%x (partial checksum) ",
		    mp, MBLKL(mp), cksum_flags));
		cksum_on = B_TRUE;
	}

	MUTEX_ENTER(&tx_ring_p->lock);
start_again:
	ngathers = 0;
	sop_index = tx_ring_p->wr_index;
#ifdef	HXGE_DEBUG
	if (tx_ring_p->descs_pending) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_start: desc pending %d ",
		    tx_ring_p->descs_pending));
	}

	dump_len = (int)(MBLKL(mp));
	dump_len = (dump_len > 128) ? 128: dump_len;

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start: tdc %d: dumping ...: b_rptr $%p "
	    "(Before header reserve: ORIGINAL LEN %d)",
	    tx_ring_p->tdc, mp->b_rptr, dump_len));

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start: dump packets (IP ORIGINAL b_rptr $%p): %s",
	    mp->b_rptr, hxge_dump_packet((char *)mp->b_rptr, dump_len)));
#endif

	tdc_stats = tx_ring_p->tdc_stats;
	mark_mode = (tx_ring_p->descs_pending &&
	    ((tx_ring_p->tx_ring_size - tx_ring_p->descs_pending) <
	    hxge_tx_minfree));

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "TX Descriptor ring is channel %d mark mode %d",
	    tx_ring_p->tdc, mark_mode));

	if (!hxge_txdma_reclaim(hxgep, tx_ring_p, hxge_tx_minfree)) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "TX Descriptor ring is full: channel %d", tx_ring_p->tdc));
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "TX Descriptor ring is full: channel %d", tx_ring_p->tdc));
		(void) atomic_cas_32((uint32_t *)&tx_ring_p->queueing, 0, 1);
		tdc_stats->tx_no_desc++;
		MUTEX_EXIT(&tx_ring_p->lock);
		status = 1;
		goto hxge_start_fail1;
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
	hpi_handle = desc_area.hpi_handle;
	hpi_desc_handle.regh = (hxge_os_acc_handle_t)
	    DMA_COMMON_ACC_HANDLE(desc_area);
	hpi_desc_handle.hxgep = hxgep;
	tx_desc_ring_vp = (p_tx_desc_t)DMA_COMMON_VPTR(desc_area);
#ifdef	HXGE_DEBUG
#if defined(__i386)
	tx_desc_ring_pp = (p_tx_desc_t)(uint32_t)DMA_COMMON_IOADDR(desc_area);
#else
	tx_desc_ring_pp = (p_tx_desc_t)DMA_COMMON_IOADDR(desc_area);
#endif
#endif
	tx_desc_dma_handle = (hxge_os_dma_handle_t)DMA_COMMON_HANDLE(desc_area);
	tx_msg_ring = tx_ring_p->tx_msg_ring;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start: wr_index %d i %d",
	    sop_index, i));

#ifdef	HXGE_DEBUG
	msgsize = msgdsize(nmp);
	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start(1): wr_index %d i %d msgdsize %d",
	    sop_index, i, msgsize));
#endif
	/*
	 * The first 16 bytes of the premapped buffer are reserved
	 * for header. No padding will be used.
	 */
	pkt_len = pack_len = boff = TX_PKT_HEADER_SIZE;
	if (hxge_tx_use_bcopy) {
		bcopy_thresh = (hxge_bcopy_thresh - TX_PKT_HEADER_SIZE);
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

		HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start(1): nmblks %d "
		    "len %d pkt_len %d pack_len %d",
		    nmblks, len, pkt_len, pack_len));
		/*
		 * Hardware limits the transfer length to 4K.
		 * If len is more than 4K, we need to break
		 * nmp into two chunks: Make first chunk smaller
		 * than 4K. The second chunk will be broken into
		 * less than 4K (if needed) during the next pass.
		 */
		if (len > (TX_MAX_TRANSFER_LENGTH - TX_PKT_HEADER_SIZE)) {
			if ((t_mp = dupb(nmp)) != NULL) {
				nmp->b_wptr = nmp->b_rptr +
				    (TX_MAX_TRANSFER_LENGTH -
				    TX_PKT_HEADER_SIZE);
				t_mp->b_rptr = nmp->b_wptr;
				t_mp->b_cont = nmp->b_cont;
				nmp->b_cont = t_mp;
				len = MBLKL(nmp);
			} else {
				good_packet = B_FALSE;
				goto hxge_start_fail2;
			}
		}
		tx_desc.value = 0;
		tx_desc_p = &tx_desc_ring_vp[i];
#ifdef	HXGE_DEBUG
		tx_desc_pp = &tx_desc_ring_pp[i];
#endif
		tx_msg_p = &tx_msg_ring[i];
#if defined(__i386)
		hpi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
		hpi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif
		if (!header_set &&
		    ((!hxge_tx_use_bcopy && (len > TX_BCOPY_SIZE)) ||
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
			offset = tx_msg_p->offset_index * hxge_bcopy_thresh;
			(void) ddi_dma_sync(dma_handle,
			    offset, hxge_bcopy_thresh, DDI_DMA_SYNC_FORDEV);

			tx_msg_p->flags.dma_type = USE_BCOPY;
			goto hxge_start_control_header_only;
		}

		pkt_len += len;
		pack_len += len;

		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_start(3): desc entry %d DESC IOADDR $%p "
		    "desc_vp $%p tx_desc_p $%p desc_pp $%p tx_desc_pp $%p "
		    "len %d pkt_len %d pack_len %d",
		    i,
		    DMA_COMMON_IOADDR(desc_area),
		    tx_desc_ring_vp, tx_desc_p,
		    tx_desc_ring_pp, tx_desc_pp,
		    len, pkt_len, pack_len));

		if (len < bcopy_thresh) {
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_start(4): USE BCOPY: "));
			if (hxge_tx_tiny_pack) {
				uint32_t blst = TXDMA_DESC_NEXT_INDEX(i, -1,
				    tx_ring_p->tx_wrap_mask);
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "==> hxge_start(5): pack"));
				if ((pack_len <= bcopy_thresh) &&
				    (last_bidx == blst)) {
					HXGE_DEBUG_MSG((hxgep, TX_CTL,
					    "==> hxge_start: pack(6) "
					    "(pkt_len %d pack_len %d)",
					    pkt_len, pack_len));
					i = blst;
					tx_desc_p = &tx_desc_ring_vp[i];
#ifdef	HXGE_DEBUG
					tx_desc_pp = &tx_desc_ring_pp[i];
#endif
					tx_msg_p = &tx_msg_ring[i];
					boff = pack_len - len;
					ngathers--;
				} else if (pack_len > bcopy_thresh &&
				    header_set) {
					pack_len = len;
					boff = 0;
					bcopy_thresh = hxge_bcopy_thresh;
					HXGE_DEBUG_MSG((hxgep, TX_CTL,
					    "==> hxge_start(7): > max NEW "
					    "bcopy thresh %d "
					    "pkt_len %d pack_len %d(next)",
					    bcopy_thresh, pkt_len, pack_len));
				}
				last_bidx = i;
			}
			kaddr = (caddr_t)DMA_COMMON_VPTR(tx_msg_p->buf_dma);
			if ((boff == TX_PKT_HEADER_SIZE) && (nmblks == 1)) {
				hdrp = (p_tx_pkt_header_t)kaddr;
				header_set = B_TRUE;
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "==> hxge_start(7_x2): "
				    "pkt_len %d pack_len %d (new hdrp $%p)",
				    pkt_len, pack_len, hdrp));
			}
			tx_msg_p->flags.dma_type = USE_BCOPY;
			kaddr += boff;
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_start(8): USE BCOPY: before bcopy "
			    "DESC IOADDR $%p entry %d bcopy packets %d "
			    "bcopy kaddr $%p bcopy ioaddr (SAD) $%p "
			    "bcopy clen %d bcopy boff %d",
			    DMA_COMMON_IOADDR(desc_area), i,
			    tdc_stats->tx_hdr_pkts, kaddr, dma_ioaddr,
			    clen, boff));
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_start: 1USE BCOPY: "));
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_start: 2USE BCOPY: "));
			HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start: "
			    "last USE BCOPY: copy from b_rptr $%p "
			    "to KADDR $%p (len %d offset %d",
			    b_rptr, kaddr, len, boff));
			bcopy(b_rptr, kaddr, len);
#ifdef	HXGE_DEBUG
			dump_len = (len > 128) ? 128: len;
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_start: dump packets "
			    "(After BCOPY len %d)"
			    "(b_rptr $%p): %s", len, nmp->b_rptr,
			    hxge_dump_packet((char *)nmp->b_rptr,
			    dump_len)));
#endif
			dma_handle = tx_msg_p->buf_dma_handle;
			dma_ioaddr = DMA_COMMON_IOADDR(tx_msg_p->buf_dma);
			offset = tx_msg_p->offset_index * hxge_bcopy_thresh;
			(void) ddi_dma_sync(dma_handle,
			    offset, hxge_bcopy_thresh, DDI_DMA_SYNC_FORDEV);
			clen = len + boff;
			tdc_stats->tx_hdr_pkts++;
			HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start(9): "
			    "USE BCOPY: DESC IOADDR $%p entry %d "
			    "bcopy packets %d bcopy kaddr $%p "
			    "bcopy ioaddr (SAD) $%p bcopy clen %d "
			    "bcopy boff %d",
			    DMA_COMMON_IOADDR(desc_area), i,
			    tdc_stats->tx_hdr_pkts, kaddr, dma_ioaddr,
			    clen, boff));
		} else {
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_start(12): USE DVMA: len %d", len));
			tx_msg_p->flags.dma_type = USE_DMA;
			dma_flags = DDI_DMA_WRITE;
			if (len < hxge_dma_stream_thresh) {
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
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "==> hxge_start(12_1): "
				    "USE DVMA: len %d clen %d ngathers %d",
				    len, clen, ngathers));
#if defined(__i386)
				hpi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
				hpi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif
				while (ncookies > 1) {
					ngathers++;
					/*
					 * this is the fix for multiple
					 * cookies, which are basically
					 * a descriptor entry, we don't set
					 * SOP bit as well as related fields
					 */

					(void) hpi_txdma_desc_gather_set(
					    hpi_desc_handle, &tx_desc,
					    (ngathers -1), mark_mode,
					    ngathers, dma_ioaddr, clen);
					tx_msg_p->tx_msg_size = clen;
					HXGE_DEBUG_MSG((hxgep, TX_CTL,
					    "==> hxge_start:  DMA "
					    "ncookie %d ngathers %d "
					    "dma_ioaddr $%p len %d"
					    "desc $%p descp $%p (%d)",
					    ncookies, ngathers,
					    dma_ioaddr, clen,
					    *tx_desc_p, tx_desc_p, i));

					ddi_dma_nextcookie(dma_handle,
					    &dma_cookie);
					dma_ioaddr = dma_cookie.dmac_laddress;

					len = (int)dma_cookie.dmac_size;
					clen = (uint32_t)dma_cookie.dmac_size;
					HXGE_DEBUG_MSG((hxgep, TX_CTL,
					    "==> hxge_start(12_2): "
					    "USE DVMA: len %d clen %d ",
					    len, clen));

					i = TXDMA_DESC_NEXT_INDEX(i, 1,
					    tx_ring_p->tx_wrap_mask);
					tx_desc_p = &tx_desc_ring_vp[i];

					hpi_desc_handle.regp =
#if defined(__i386)
					    (uint32_t)tx_desc_p;
#else
						(uint64_t)tx_desc_p;
#endif
					tx_msg_p = &tx_msg_ring[i];
					tx_msg_p->flags.dma_type = USE_NONE;
					tx_desc.value = 0;
					ncookies--;
				}
				tdc_stats->tx_ddi_pkts++;
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "==> hxge_start: DMA: ddi packets %d",
				    tdc_stats->tx_ddi_pkts));
			} else {
				HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
				    "dma mapping failed for %d "
				    "bytes addr $%p flags %x (%d)",
				    len, b_rptr, status, status));
				good_packet = B_FALSE;
				tdc_stats->tx_dma_bind_fail++;
				tx_msg_p->flags.dma_type = USE_NONE;
				status = 1;
				goto hxge_start_fail2;
			}
		} /* ddi dvma */

		nmp = nmp->b_cont;
hxge_start_control_header_only:
#if defined(__i386)
		hpi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
		hpi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif
		ngathers++;

		if (ngathers == 1) {
#ifdef	HXGE_DEBUG
			save_desc_p = &sop_tx_desc;
#endif
			sop_tx_desc_p = &sop_tx_desc;
			sop_tx_desc_p->value = 0;
			sop_tx_desc_p->bits.tr_len = clen;
			sop_tx_desc_p->bits.sad = dma_ioaddr >> 32;
			sop_tx_desc_p->bits.sad_l = dma_ioaddr & 0xffffffff;
		} else {
#ifdef	HXGE_DEBUG
			save_desc_p = &tx_desc;
#endif
			tmp_desc_p = &tx_desc;
			tmp_desc_p->value = 0;
			tmp_desc_p->bits.tr_len = clen;
			tmp_desc_p->bits.sad = dma_ioaddr >> 32;
			tmp_desc_p->bits.sad_l = dma_ioaddr & 0xffffffff;

			tx_desc_p->value = tmp_desc_p->value;
		}

		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_start(13): Desc_entry %d ngathers %d "
		    "desc_vp $%p tx_desc_p $%p "
		    "len %d clen %d pkt_len %d pack_len %d nmblks %d "
		    "dma_ioaddr (SAD) $%p mark %d",
		    i, ngathers, tx_desc_ring_vp, tx_desc_p,
		    len, clen, pkt_len, pack_len, nmblks,
		    dma_ioaddr, mark_mode));

#ifdef HXGE_DEBUG
		hpi_desc_handle.hxgep = hxgep;
		hpi_desc_handle.function.function = 0;
		hpi_desc_handle.function.instance = hxgep->instance;
		sad = save_desc_p->bits.sad;
		sad = (sad << 32) | save_desc_p->bits.sad_l;
		xfer_len = save_desc_p->bits.tr_len;

		HXGE_DEBUG_MSG((hxgep, TX_CTL, "\n\t: value 0x%llx\n"
		    "\t\tsad $%p\ttr_len %d len %d\tnptrs %d\t"
		    "mark %d sop %d\n",
		    save_desc_p->value, sad, save_desc_p->bits.tr_len,
		    xfer_len, save_desc_p->bits.num_ptr,
		    save_desc_p->bits.mark, save_desc_p->bits.sop));

		hpi_txdma_dump_desc_one(hpi_desc_handle, NULL, i);
#endif

		tx_msg_p->tx_msg_size = clen;
		i = TXDMA_DESC_NEXT_INDEX(i, 1, tx_ring_p->tx_wrap_mask);
		if (ngathers > hxge_tx_max_gathers) {
			good_packet = B_FALSE;
			mac_hcksum_get(mp, &start_offset, &stuff_offset,
			    &end_offset, &value, &cksum_flags);

			HXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> hxge_start(14): pull msg - "
			    "len %d pkt_len %d ngathers %d",
			    len, pkt_len, ngathers));
			goto hxge_start_fail2;
		}
	} /* while (nmp) */

	tx_msg_p->tx_message = mp;
	tx_desc_p = &tx_desc_ring_vp[sop_index];
#if defined(__i386)
	hpi_desc_handle.regp = (uint32_t)tx_desc_p;
#else
	hpi_desc_handle.regp = (uint64_t)tx_desc_p;
#endif

	pkthdrp = (p_tx_pkt_hdr_all_t)hdrp;
	pkthdrp->reserved = 0;
	hdrp->value = 0;
	(void) hxge_fill_tx_hdr(mp, B_FALSE, cksum_on,
	    (pkt_len - TX_PKT_HEADER_SIZE), npads, pkthdrp);

	/*
	 * Hardware header should not be counted as part of the frame
	 * when determining the frame size
	 */
	if ((pkt_len - TX_PKT_HEADER_SIZE) > (STD_FRAME_SIZE - ETHERFCSL)) {
		tdc_stats->tx_jumbo_pkts++;
	}

	min_len = (hxgep->msg_min + TX_PKT_HEADER_SIZE + (npads * 2));
	if (pkt_len < min_len) {
		/* Assume we use bcopy to premapped buffers */
		kaddr = (caddr_t)DMA_COMMON_VPTR(tx_msg_p->buf_dma);
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_start(14-1): < (msg_min + 16)"
		    "len %d pkt_len %d min_len %d bzero %d ngathers %d",
		    len, pkt_len, min_len, (min_len - pkt_len), ngathers));
		bzero((kaddr + pkt_len), (min_len - pkt_len));
		pkt_len = tx_msg_p->tx_msg_size = min_len;

		sop_tx_desc_p->bits.tr_len = min_len;

		HXGE_MEM_PIO_WRITE64(hpi_desc_handle, sop_tx_desc_p->value);
		tx_desc_p->value = sop_tx_desc_p->value;

		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_start(14-2): < msg_min - "
		    "len %d pkt_len %d min_len %d ngathers %d",
		    len, pkt_len, min_len, ngathers));
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start: cksum_flags 0x%x ",
	    cksum_flags));
	if (cksum_flags & HCK_PARTIALCKSUM) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_start: cksum_flags 0x%x (partial checksum) ",
		    cksum_flags));
		cksum_on = B_TRUE;
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_start: from IP cksum_flags 0x%x "
		    "(partial checksum) "
		    "start_offset %d stuff_offset %d",
		    cksum_flags, start_offset, stuff_offset));
		tmp_len = (uint64_t)(start_offset >> 1);
		hdrp->value |= (tmp_len << TX_PKT_HEADER_L4START_SHIFT);
		tmp_len = (uint64_t)(stuff_offset >> 1);
		hdrp->value |= (tmp_len << TX_PKT_HEADER_L4STUFF_SHIFT);

		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_start: from IP cksum_flags 0x%x "
		    "(partial checksum) "
		    "after SHIFT start_offset %d stuff_offset %d",
		    cksum_flags, start_offset, stuff_offset));
	}

	/*
	 * pkt_len already includes 16 + paddings!!
	 * Update the control header length
	 */

	/*
	 * Note that Hydra is different from Neptune where
	 * tot_xfer_len = (pkt_len - TX_PKT_HEADER_SIZE);
	 */
	tot_xfer_len = pkt_len;
	tmp_len = hdrp->value |
	    (tot_xfer_len << TX_PKT_HEADER_TOT_XFER_LEN_SHIFT);

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start(15_x1): setting SOP "
	    "tot_xfer_len 0x%llx (%d) pkt_len %d tmp_len "
	    "0x%llx hdrp->value 0x%llx",
	    tot_xfer_len, tot_xfer_len, pkt_len, tmp_len, hdrp->value));
#if defined(_BIG_ENDIAN)
	hdrp->value = ddi_swap64(tmp_len);
#else
	hdrp->value = tmp_len;
#endif
	HXGE_DEBUG_MSG((hxgep,
	    TX_CTL, "==> hxge_start(15_x2): setting SOP "
	    "after SWAP: tot_xfer_len 0x%llx pkt_len %d "
	    "tmp_len 0x%llx hdrp->value 0x%llx",
	    tot_xfer_len, pkt_len, tmp_len, hdrp->value));

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start(15): setting SOP "
	    "wr_index %d tot_xfer_len (%d) pkt_len %d npads %d",
	    sop_index, tot_xfer_len, pkt_len, npads));

	sop_tx_desc_p->bits.sop = 1;
	sop_tx_desc_p->bits.mark = mark_mode;
	sop_tx_desc_p->bits.num_ptr = ngathers;

	if (mark_mode)
		tdc_stats->tx_marks++;

	HXGE_MEM_PIO_WRITE64(hpi_desc_handle, sop_tx_desc_p->value);
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start(16): set SOP done"));

#ifdef HXGE_DEBUG
	hpi_desc_handle.hxgep = hxgep;
	hpi_desc_handle.function.function = 0;
	hpi_desc_handle.function.instance = hxgep->instance;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "\n\t: value 0x%llx\n"
	    "\t\tsad $%p\ttr_len %d len %d\tnptrs %d\tmark %d sop %d\n",
	    save_desc_p->value, sad, save_desc_p->bits.tr_len,
	    xfer_len, save_desc_p->bits.num_ptr, save_desc_p->bits.mark,
	    save_desc_p->bits.sop));
	(void) hpi_txdma_dump_desc_one(hpi_desc_handle, NULL, sop_index);

	dump_len = (pkt_len > 128) ? 128: pkt_len;
	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start: dump packets(17) (after sop set, len "
	    " (len/dump_len/pkt_len/tot_xfer_len) %d/%d/%d/%d):\n"
	    "ptr $%p: %s", len, dump_len, pkt_len, tot_xfer_len,
	    (char *)hdrp, hxge_dump_packet((char *)hdrp, dump_len)));
	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_start(18): TX desc sync: sop_index %d", sop_index));
#endif

	if ((ngathers == 1) || tx_ring_p->wr_index < i) {
		(void) ddi_dma_sync(tx_desc_dma_handle,
		    sop_index * sizeof (tx_desc_t),
		    ngathers * sizeof (tx_desc_t), DDI_DMA_SYNC_FORDEV);

		HXGE_DEBUG_MSG((hxgep, TX_CTL, "hxge_start(19): sync 1 "
		    "cs_off = 0x%02X cs_s_off = 0x%02X "
		    "pkt_len %d ngathers %d sop_index %d\n",
		    stuff_offset, start_offset,
		    pkt_len, ngathers, sop_index));
	} else { /* more than one descriptor and wrap around */
		uint32_t nsdescs = tx_ring_p->tx_ring_size - sop_index;
		(void) ddi_dma_sync(tx_desc_dma_handle,
		    sop_index * sizeof (tx_desc_t),
		    nsdescs * sizeof (tx_desc_t), DDI_DMA_SYNC_FORDEV);
		HXGE_DEBUG_MSG((hxgep, TX_CTL, "hxge_start(20): sync 1 "
		    "cs_off = 0x%02X cs_s_off = 0x%02X "
		    "pkt_len %d ngathers %d sop_index %d\n",
		    stuff_offset, start_offset, pkt_len, ngathers, sop_index));

		(void) ddi_dma_sync(tx_desc_dma_handle, 0,
		    (ngathers - nsdescs) * sizeof (tx_desc_t),
		    DDI_DMA_SYNC_FORDEV);
		HXGE_DEBUG_MSG((hxgep, TX_CTL, "hxge_start(21): sync 2 "
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

	tx_ring_p->descs_pending += ngathers;
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start: TX kick: "
	    "channel %d wr_index %d wrap %d ngathers %d desc_pend %d",
	    tx_ring_p->tdc, tx_ring_p->wr_index, tx_ring_p->wr_index_wrap,
	    ngathers, tx_ring_p->descs_pending));
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start: TX KICKING: "));

	kick.value = 0;
	kick.bits.wrap = tx_ring_p->wr_index_wrap;
	kick.bits.tail = (uint16_t)tx_ring_p->wr_index;

	/* Kick start the Transmit kick register */
	TXDMA_REG_WRITE64(HXGE_DEV_HPI_HANDLE(hxgep),
	    TDC_TDR_KICK, (uint8_t)tx_ring_p->tdc, kick.value);
	tdc_stats->tx_starts++;
	MUTEX_EXIT(&tx_ring_p->lock);
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_start"));
	return (status);

hxge_start_fail2:
	if (good_packet == B_FALSE) {
		cur_index = sop_index;
		HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_start: clean up"));
		for (i = 0; i < ngathers; i++) {
			tx_desc_p = &tx_desc_ring_vp[cur_index];
#if defined(__i386)
			hpi_handle.regp = (uint32_t)tx_desc_p;
#else
			hpi_handle.regp = (uint64_t)tx_desc_p;
#endif
			tx_msg_p = &tx_msg_ring[cur_index];
			(void) hpi_txdma_desc_set_zero(hpi_handle, 1);
			if (tx_msg_p->flags.dma_type == USE_DVMA) {
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
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
					cmn_err(CE_WARN, "hxge_start: "
					    "ddi_dma_unbind_handle failed");
				}
			}
			tx_msg_p->flags.dma_type = USE_NONE;
			cur_index = TXDMA_DESC_NEXT_INDEX(cur_index, 1,
			    tx_ring_p->tx_wrap_mask);

		}
	}

	MUTEX_EXIT(&tx_ring_p->lock);

hxge_start_fail1:
	/* Add FMA to check the access handle hxge_hregh */
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_start"));
	return (status);
}
