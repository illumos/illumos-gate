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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/nxge/nxge_impl.h>

extern uint32_t		nxge_reclaim_pending;
extern uint32_t 	nxge_bcopy_thresh;
extern uint32_t 	nxge_dvma_thresh;
extern uint32_t 	nxge_dma_stream_thresh;
extern uint32_t		nxge_tx_minfree;
extern uint32_t		nxge_tx_intr_thres;
extern uint32_t		nxge_tx_max_gathers;
extern uint32_t		nxge_tx_tiny_pack;
extern uint32_t		nxge_tx_use_bcopy;
extern uint32_t		nxge_tx_lb_policy;
extern uint32_t		nxge_no_tx_lb;
extern nxge_tx_mode_t	nxge_tx_scheme;

typedef struct _mac_tx_hint {
	uint16_t	sap;
	uint16_t	vid;
	void		*hash;
} mac_tx_hint_t, *p_mac_tx_hint_t;

int nxge_tx_lb_ring_1(p_mblk_t, uint32_t, p_mac_tx_hint_t);

int
nxge_start(p_nxge_t nxgep, p_tx_ring_t tx_ring_p, p_mblk_t mp)
{
	int 			status = 0;
	p_tx_desc_t 		tx_desc_ring_vp;
	npi_handle_t		npi_desc_handle;
	nxge_os_dma_handle_t 	tx_desc_dma_handle;
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
	uint64_t		tot_xfer_len = 0, tmp_len = 0;
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

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"==> nxge_start: tx dma channel %d", tx_ring_p->tdc));
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"==> nxge_start: Starting tdc %d desc pending %d",
		tx_ring_p->tdc, tx_ring_p->descs_pending));

	statsp = nxgep->statsp;

	if (nxgep->statsp->port_stats.lb_mode == nxge_lb_normal) {
		if (!statsp->mac_stats.link_up) {
			freemsg(mp);
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: "
				"link not up or LB mode"));
			goto nxge_start_fail1;
		}
	}

	hcksum_retrieve(mp, NULL, NULL, &start_offset,
		&stuff_offset, &end_offset, &value, &cksum_flags);
	if (!NXGE_IS_VLAN_PACKET(mp->b_rptr)) {
		start_offset += sizeof (ether_header_t);
		stuff_offset += sizeof (ether_header_t);
	} else {
		start_offset += sizeof (struct ether_vlan_header);
		stuff_offset += sizeof (struct ether_vlan_header);
	}

	if (cksum_flags & HCK_PARTIALCKSUM) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_start: cksum_flags 0x%x (partial checksum) ",
			cksum_flags));
		cksum_on = B_TRUE;
	}

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

	MUTEX_ENTER(&tx_ring_p->lock);
	tdc_stats = tx_ring_p->tdc_stats;
	mark_mode = (tx_ring_p->descs_pending &&
		((tx_ring_p->tx_ring_size - tx_ring_p->descs_pending)
		< nxge_tx_minfree));

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"TX Descriptor ring is channel %d mark mode %d",
		tx_ring_p->tdc, mark_mode));

	if (!nxge_txdma_reclaim(nxgep, tx_ring_p, nxge_tx_minfree)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"TX Descriptor ring is full: channel %d",
			tx_ring_p->tdc));
		cas32((uint32_t *)&tx_ring_p->queueing, 0, 1);
		tdc_stats->tx_no_desc++;
		MUTEX_EXIT(&tx_ring_p->lock);
		if (nxgep->resched_needed && !nxgep->resched_running) {
			nxgep->resched_running = B_TRUE;
			ddi_trigger_softintr(nxgep->resched_id);
		}
		status = 1;
		goto nxge_start_fail1;
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
#ifdef	NXGE_DEBUG
	tx_desc_ring_pp = (p_tx_desc_t)DMA_COMMON_IOADDR(desc_area);
#endif
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
				good_packet = B_FALSE;
				goto nxge_start_fail2;
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
			status = ddi_dma_addr_bind_handle(dma_handle, NULL,
				(caddr_t)b_rptr, len, dma_flags,
				DDI_DMA_DONTWAIT, NULL,
				&dma_cookie, &ncookies);
			if (status == DDI_DMA_MAPPED) {
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
					 * cookies, which are basicaly
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

					npi_desc_handle.regp =
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
				goto nxge_start_fail2;
			}
		} /* ddi dvma */

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
			hcksum_retrieve(mp, NULL, NULL, &start_offset,
				&stuff_offset, &end_offset, &value,
				&cksum_flags);

			NXGE_DEBUG_MSG((NULL, TX_CTL,
				"==> nxge_start(14): pull msg - "
				"len %d pkt_len %d ngathers %d",
				len, pkt_len, ngathers));
			/* Pull all message blocks from b_cont */
			if ((msgpullup(mp, -1)) == NULL) {
				goto nxge_start_fail2;
			}
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
	(void) nxge_fill_tx_hdr(mp, B_FALSE, cksum_on,
		(pkt_len - TX_PKT_HEADER_SIZE), npads, pkthdrp);

	if (pkt_len > NXGE_MTU_DEFAULT_MAX) {
		tdc_stats->tx_jumbo_pkts++;
	}

	min_len = (nxgep->msg_min + TX_PKT_HEADER_SIZE + (npads * 2));
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
	if (cksum_flags & HCK_PARTIALCKSUM) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_start: cksum_flags 0x%x (partial checksum) ",
			cksum_flags));
		cksum_on = B_TRUE;
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_start: from IP cksum_flags 0x%x "
			"(partial checksum) "
			"start_offset %d stuff_offset %d",
			cksum_flags, start_offset, stuff_offset));
		tmp_len = (uint64_t)(start_offset >> 1);
		hdrp->value |= (tmp_len << TX_PKT_HEADER_L4START_SHIFT);
		tmp_len = (uint64_t)(stuff_offset >> 1);
		hdrp->value |= (tmp_len << TX_PKT_HEADER_L4STUFF_SHIFT);

		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_start: from IP cksum_flags 0x%x "
			"(partial checksum) "
			"after SHIFT start_offset %d stuff_offset %d",
			cksum_flags, start_offset, stuff_offset));
	}
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

	tx_ring_p->descs_pending += ngathers;
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_start: TX kick: "
		"channel %d wr_index %d wrap %d ngathers %d desc_pend %d",
		tx_ring_p->tdc,
		tx_ring_p->wr_index,
		tx_ring_p->wr_index_wrap,
		ngathers,
		tx_ring_p->descs_pending));

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

	tdc_stats->tx_starts++;

	MUTEX_EXIT(&tx_ring_p->lock);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_start"));

	return (status);

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

		nxgep->resched_needed = B_TRUE;
	}

	MUTEX_EXIT(&tx_ring_p->lock);

nxge_start_fail1:
	/* Add FMA to check the access handle nxge_hregh */

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_start"));

	return (status);
}

int
nxge_serial_tx(mblk_t *mp, void *arg)
{
	p_tx_ring_t		tx_ring_p = (p_tx_ring_t)arg;
	p_nxge_t		nxgep = tx_ring_p->nxgep;

	return (nxge_start(nxgep, tx_ring_p, mp));
}

boolean_t
nxge_send(p_nxge_t nxgep, mblk_t *mp, p_mac_tx_hint_t hp)
{
	p_tx_ring_t 		*tx_rings;
	uint8_t			ring_index;
	p_tx_ring_t		tx_ring_p;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_send"));

	ASSERT(mp->b_next == NULL);

	ring_index = nxge_tx_lb_ring_1(mp, nxgep->max_tdcs, hp);
	tx_rings = nxgep->tx_rings->rings;
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_tx_msg: tx_rings $%p",
		tx_rings));
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_tx_msg: max_tdcs %d "
		"ring_index %d", nxgep->max_tdcs, ring_index));

	switch (nxge_tx_scheme) {
	case NXGE_USE_START:
		if (nxge_start(nxgep, tx_rings[ring_index], mp)) {
			NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_send: failed "
				"ring index %d", ring_index));
			return (B_FALSE);
		}
		break;

	case NXGE_USE_SERIAL:
	default:
		tx_ring_p = tx_rings[ring_index];
		nxge_serialize_enter(tx_ring_p->serial, mp);
		break;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_send: ring index %d",
		ring_index));

	return (B_TRUE);
}

/*
 * nxge_m_tx() - send a chain of packets
 */
mblk_t *
nxge_m_tx(void *arg, mblk_t *mp)
{
	p_nxge_t 		nxgep = (p_nxge_t)arg;
	mblk_t 			*next;
	mac_tx_hint_t		hint;

	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"==> nxge_m_tx: hardware not initialized"));
		NXGE_DEBUG_MSG((nxgep, DDI_CTL,
			"<== nxge_m_tx"));
		return (mp);
	}

	hint.hash =  NULL;
	hint.vid =  0;
	hint.sap =  0;

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Until Nemo tx resource works, the mac driver
		 * does the load balancing based on TCP port,
		 * or CPU. For debugging, we use a system
		 * configurable parameter.
		 */
		if (!nxge_send(nxgep, mp, &hint)) {
			mp->b_next = next;
			break;
		}

		mp = next;
	}

	return (mp);
}

int
nxge_tx_lb_ring_1(p_mblk_t mp, uint32_t maxtdcs, p_mac_tx_hint_t hp)
{
	uint8_t 		ring_index = 0;
	uint8_t 		*tcp_port;
	p_mblk_t 		nmp;
	size_t 			mblk_len;
	size_t 			iph_len;
	size_t 			hdrs_size;
	uint8_t			hdrs_buf[sizeof (struct  ether_header) +
					IP_MAX_HDR_LENGTH + sizeof (uint32_t)];
				/*
				 * allocate space big enough to cover
				 * the max ip header length and the first
				 * 4 bytes of the TCP/IP header.
				 */

	boolean_t		qos = B_FALSE;

	NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_lb_ring"));

	if (hp->vid) {
		qos = B_TRUE;
	}
	switch (nxge_tx_lb_policy) {
	case NXGE_TX_LB_TCPUDP: /* default IPv4 TCP/UDP */
	default:
		tcp_port = mp->b_rptr;
		if (!nxge_no_tx_lb && !qos &&
			(ntohs(((p_ether_header_t)tcp_port)->ether_type)
				== ETHERTYPE_IP)) {
			nmp = mp;
			mblk_len = MBLKL(nmp);
			tcp_port = NULL;
			if (mblk_len > sizeof (struct ether_header) +
					sizeof (uint8_t)) {
				tcp_port = nmp->b_rptr +
					sizeof (struct ether_header);
				mblk_len -= sizeof (struct ether_header);
				iph_len = ((*tcp_port) & 0x0f) << 2;
				if (mblk_len > (iph_len + sizeof (uint32_t))) {
					tcp_port = nmp->b_rptr;
				} else {
					tcp_port = NULL;
				}
			}
			if (tcp_port == NULL) {
				hdrs_size = 0;
				((p_ether_header_t)hdrs_buf)->ether_type = 0;
				while ((nmp) && (hdrs_size <
						sizeof (hdrs_buf))) {
					mblk_len = MBLKL(nmp);
					if (mblk_len >=
						(sizeof (hdrs_buf) - hdrs_size))
						mblk_len = sizeof (hdrs_buf) -
							hdrs_size;
					bcopy(nmp->b_rptr,
						&hdrs_buf[hdrs_size], mblk_len);
					hdrs_size += mblk_len;
					nmp = nmp->b_cont;
				}
				tcp_port = hdrs_buf;
			}
			tcp_port += sizeof (ether_header_t);
			if (!(tcp_port[6] & 0x3f) && !(tcp_port[7] & 0xff)) {
				switch (tcp_port[9]) {
				case IPPROTO_TCP:
				case IPPROTO_UDP:
				case IPPROTO_ESP:
					tcp_port += ((*tcp_port) & 0x0f) << 2;
					ring_index =
					    ((tcp_port[0] ^
					    tcp_port[1] ^
					    tcp_port[2] ^
					    tcp_port[3]) % maxtdcs);
					break;

				case IPPROTO_AH:
					/* SPI starts at the 4th byte */
					tcp_port += ((*tcp_port) & 0x0f) << 2;
					ring_index =
					    ((tcp_port[4] ^
					    tcp_port[5] ^
					    tcp_port[6] ^
					    tcp_port[7]) % maxtdcs);
					break;

				default:
					ring_index = tcp_port[19] % maxtdcs;
					break;
				}
			} else { /* fragmented packet */
				ring_index = tcp_port[19] % maxtdcs;
			}
		} else {
			ring_index = mp->b_band % maxtdcs;
		}
		break;

	case NXGE_TX_LB_HASH:
		if (hp->hash) {
#if defined(__i386)
			ring_index = ((uint32_t)(hp->hash) % maxtdcs);
#else
			ring_index = ((uint64_t)(hp->hash) % maxtdcs);
#endif
		} else {
			ring_index = mp->b_band % maxtdcs;
		}
		break;

	case NXGE_TX_LB_DEST_MAC: /* Use destination MAC address */
		tcp_port = mp->b_rptr;
		ring_index = tcp_port[5] % maxtdcs;
		break;
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL, "<== nxge_tx_lb_ring"));

	return (ring_index);
}

uint_t
nxge_reschedule(caddr_t arg)
{
	p_nxge_t nxgep;

	nxgep = (p_nxge_t)arg;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_reschedule"));

	if (nxgep->nxge_mac_state == NXGE_MAC_STARTED &&
			nxgep->resched_needed) {
		mac_tx_update(nxgep->mach);
		nxgep->resched_needed = B_FALSE;
		nxgep->resched_running = B_FALSE;
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL, "<== nxge_reschedule"));
	return (DDI_INTR_CLAIMED);
}
