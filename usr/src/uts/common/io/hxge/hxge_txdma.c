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

#include <hxge_impl.h>
#include <hxge_txdma.h>
#include <sys/llc1.h>

uint32_t hxge_reclaim_pending = TXDMA_RECLAIM_PENDING_DEFAULT;
uint32_t hxge_tx_minfree = 64;
uint32_t hxge_tx_intr_thres = 0;
uint32_t hxge_tx_max_gathers = TX_MAX_GATHER_POINTERS;
uint32_t hxge_tx_tiny_pack = 1;
uint32_t hxge_tx_use_bcopy = 1;

extern uint32_t hxge_tx_ring_size;
extern uint32_t hxge_bcopy_thresh;
extern uint32_t hxge_dvma_thresh;
extern uint32_t hxge_dma_stream_thresh;
extern dma_method_t hxge_force_dma;

/* Device register access attributes for PIO.  */
extern ddi_device_acc_attr_t hxge_dev_reg_acc_attr;

/* Device descriptor access attributes for DMA.  */
extern ddi_device_acc_attr_t hxge_dev_desc_dma_acc_attr;

/* Device buffer access attributes for DMA.  */
extern ddi_device_acc_attr_t hxge_dev_buf_dma_acc_attr;
extern ddi_dma_attr_t hxge_desc_dma_attr;
extern ddi_dma_attr_t hxge_tx_dma_attr;

static hxge_status_t hxge_map_txdma(p_hxge_t hxgep);
static void hxge_unmap_txdma(p_hxge_t hxgep);
static hxge_status_t hxge_txdma_hw_start(p_hxge_t hxgep);
static void hxge_txdma_hw_stop(p_hxge_t hxgep);

static hxge_status_t hxge_map_txdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_hxge_dma_common_t *dma_buf_p, p_tx_ring_t *tx_desc_p,
    uint32_t num_chunks, p_hxge_dma_common_t *dma_cntl_p,
    p_tx_mbox_t *tx_mbox_p);
static void hxge_unmap_txdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p);
static hxge_status_t hxge_map_txdma_channel_buf_ring(p_hxge_t hxgep, uint16_t,
    p_hxge_dma_common_t *, p_tx_ring_t *, uint32_t);
static void hxge_unmap_txdma_channel_buf_ring(p_hxge_t hxgep,
    p_tx_ring_t tx_ring_p);
static void hxge_map_txdma_channel_cfg_ring(p_hxge_t, uint16_t,
    p_hxge_dma_common_t *, p_tx_ring_t, p_tx_mbox_t *);
static void hxge_unmap_txdma_channel_cfg_ring(p_hxge_t hxgep,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p);
static hxge_status_t hxge_txdma_start_channel(p_hxge_t hxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p);
static hxge_status_t hxge_txdma_stop_channel(p_hxge_t hxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p);
static p_tx_ring_t hxge_txdma_get_ring(p_hxge_t hxgep, uint16_t channel);
static hxge_status_t hxge_tx_err_evnts(p_hxge_t hxgep, uint_t index,
    p_hxge_ldv_t ldvp, tdc_stat_t cs);
static p_tx_mbox_t hxge_txdma_get_mbox(p_hxge_t hxgep, uint16_t channel);
static hxge_status_t hxge_txdma_fatal_err_recover(p_hxge_t hxgep,
    uint16_t channel, p_tx_ring_t tx_ring_p);
static hxge_status_t hxge_tx_port_fatal_err_recover(p_hxge_t hxgep);

hxge_status_t
hxge_init_txdma_channels(p_hxge_t hxgep)
{
	hxge_status_t	status = HXGE_OK;
	block_reset_t	reset_reg;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_init_txdma_channels"));

	/*
	 * Reset TDC block from PEU to cleanup any unknown configuration.
	 * This may be resulted from previous reboot.
	 */
	reset_reg.value = 0;
	reset_reg.bits.tdc_rst = 1;
	HXGE_REG_WR32(hxgep->hpi_handle, BLOCK_RESET, reset_reg.value);

	HXGE_DELAY(1000);

	status = hxge_map_txdma(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_init_txdma_channels: status 0x%x", status));
		return (status);
	}

	status = hxge_txdma_hw_start(hxgep);
	if (status != HXGE_OK) {
		hxge_unmap_txdma(hxgep);
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_init_txdma_channels: status 0x%x", status));

	return (HXGE_OK);
}

void
hxge_uninit_txdma_channels(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_uninit_txdma_channels"));

	hxge_txdma_hw_stop(hxgep);
	hxge_unmap_txdma(hxgep);

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_uinit_txdma_channels"));
}

void
hxge_setup_dma_common(p_hxge_dma_common_t dest_p, p_hxge_dma_common_t src_p,
    uint32_t entries, uint32_t size)
{
	size_t tsize;
	*dest_p = *src_p;
	tsize = size * entries;
	dest_p->alength = tsize;
	dest_p->nblocks = entries;
	dest_p->block_size = size;
	dest_p->offset += tsize;

	src_p->kaddrp = (caddr_t)dest_p->kaddrp + tsize;
	src_p->alength -= tsize;
	src_p->dma_cookie.dmac_laddress += tsize;
	src_p->dma_cookie.dmac_size -= tsize;
}

hxge_status_t
hxge_reset_txdma_channel(p_hxge_t hxgep, uint16_t channel, uint64_t reg_data)
{
	hpi_status_t	rs = HPI_SUCCESS;
	hxge_status_t	status = HXGE_OK;
	hpi_handle_t	handle;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, " ==> hxge_reset_txdma_channel"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	if ((reg_data & TDC_TDR_RST_MASK) == TDC_TDR_RST_MASK) {
		rs = hpi_txdma_channel_reset(handle, channel);
	} else {
		rs = hpi_txdma_channel_control(handle, TXDMA_RESET, channel);
	}

	if (rs != HPI_SUCCESS) {
		status = HXGE_ERROR | rs;
	}

	/*
	 * Reset the tail (kick) register to 0. (Hardware will not reset it. Tx
	 * overflow fatal error if tail is not set to 0 after reset!
	 */
	TXDMA_REG_WRITE64(handle, TDC_TDR_KICK, channel, 0);

	HXGE_DEBUG_MSG((hxgep, TX_CTL, " <== hxge_reset_txdma_channel"));

	return (status);
}

hxge_status_t
hxge_init_txdma_channel_event_mask(p_hxge_t hxgep, uint16_t channel,
    tdc_int_mask_t *mask_p)
{
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_init_txdma_channel_event_mask"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/*
	 * Mask off tx_rng_oflow since it is a false alarm. The driver
	 * ensures not over flowing the hardware and check the hardware
	 * status.
	 */
	mask_p->bits.tx_rng_oflow = 1;
	rs = hpi_txdma_event_mask(handle, OP_SET, channel, mask_p);
	if (rs != HPI_SUCCESS) {
		status = HXGE_ERROR | rs;
	}

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_init_txdma_channel_event_mask"));
	return (status);
}

hxge_status_t
hxge_enable_txdma_channel(p_hxge_t hxgep,
    uint16_t channel, p_tx_ring_t tx_desc_p, p_tx_mbox_t mbox_p)
{
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_enable_txdma_channel"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	/*
	 * Use configuration data composed at init time. Write to hardware the
	 * transmit ring configurations.
	 */
	rs = hpi_txdma_ring_config(handle, OP_SET, channel,
	    (uint64_t *)&(tx_desc_p->tx_ring_cfig.value));

	if (rs != HPI_SUCCESS) {
		return (HXGE_ERROR | rs);
	}

	/* Write to hardware the mailbox */
	rs = hpi_txdma_mbox_config(handle, OP_SET, channel,
	    (uint64_t *)&mbox_p->tx_mbox.dma_cookie.dmac_laddress);

	if (rs != HPI_SUCCESS) {
		return (HXGE_ERROR | rs);
	}

	/* Start the DMA engine. */
	rs = hpi_txdma_channel_init_enable(handle, channel);
	if (rs != HPI_SUCCESS) {
		return (HXGE_ERROR | rs);
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_enable_txdma_channel"));
	return (status);
}

void
hxge_fill_tx_hdr(p_mblk_t mp, boolean_t fill_len, boolean_t l4_cksum,
    int pkt_len, uint8_t npads, p_tx_pkt_hdr_all_t pkthdrp)
{
	p_tx_pkt_header_t	hdrp;
	p_mblk_t		nmp;
	uint64_t		tmp;
	size_t			mblk_len;
	size_t			iph_len;
	size_t			hdrs_size;
	uint8_t			*ip_buf;
	uint16_t		eth_type;
	uint8_t			ipproto;
	boolean_t		is_vlan = B_FALSE;
	size_t			eth_hdr_size;
	uint8_t hdrs_buf[sizeof (struct ether_header) + 64 + sizeof (uint32_t)];

	HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_fill_tx_hdr: mp $%p", mp));

	/*
	 * Caller should zero out the headers first.
	 */
	hdrp = (p_tx_pkt_header_t)&pkthdrp->pkthdr;

	if (fill_len) {
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_fill_tx_hdr: pkt_len %d npads %d",
		    pkt_len, npads));
		tmp = (uint64_t)pkt_len;
		hdrp->value |= (tmp << TX_PKT_HEADER_TOT_XFER_LEN_SHIFT);

		goto fill_tx_header_done;
	}
	tmp = (uint64_t)npads;
	hdrp->value |= (tmp << TX_PKT_HEADER_PAD_SHIFT);

	/*
	 * mp is the original data packet (does not include the Neptune
	 * transmit header).
	 */
	nmp = mp;
	mblk_len = (size_t)nmp->b_wptr - (size_t)nmp->b_rptr;
	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> hxge_fill_tx_hdr: mp $%p b_rptr $%p len %d",
	    mp, nmp->b_rptr, mblk_len));
	ip_buf = NULL;
	bcopy(nmp->b_rptr, &hdrs_buf[0], sizeof (struct ether_vlan_header));
	eth_type = ntohs(((p_ether_header_t)hdrs_buf)->ether_type);
	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> : hxge_fill_tx_hdr: (value 0x%llx) ether type 0x%x",
	    eth_type, hdrp->value));

	if (eth_type < ETHERMTU) {
		tmp = 1ull;
		hdrp->value |= (tmp << TX_PKT_HEADER_LLC_SHIFT);
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_tx_pkt_hdr_init: LLC value 0x%llx", hdrp->value));
		if (*(hdrs_buf + sizeof (struct ether_header)) ==
		    LLC_SNAP_SAP) {
			eth_type = ntohs(*((uint16_t *)(hdrs_buf +
			    sizeof (struct ether_header) + 6)));
			HXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> hxge_tx_pkt_hdr_init: LLC ether type 0x%x",
			    eth_type));
		} else {
			goto fill_tx_header_done;
		}
	} else if (eth_type == VLAN_ETHERTYPE) {
		tmp = 1ull;
		hdrp->value |= (tmp << TX_PKT_HEADER_VLAN__SHIFT);

		eth_type = ntohs(((struct ether_vlan_header *)
		    hdrs_buf)->ether_type);
		is_vlan = B_TRUE;
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_tx_pkt_hdr_init: VLAN value 0x%llx",
		    hdrp->value));
	}
	if (!is_vlan) {
		eth_hdr_size = sizeof (struct ether_header);
	} else {
		eth_hdr_size = sizeof (struct ether_vlan_header);
	}

	switch (eth_type) {
	case ETHERTYPE_IP:
		if (mblk_len > eth_hdr_size + sizeof (uint8_t)) {
			ip_buf = nmp->b_rptr + eth_hdr_size;
			mblk_len -= eth_hdr_size;
			iph_len = ((*ip_buf) & 0x0f);
			if (mblk_len > (iph_len + sizeof (uint32_t))) {
				ip_buf = nmp->b_rptr;
				ip_buf += eth_hdr_size;
			} else {
				ip_buf = NULL;
			}
		}
		if (ip_buf == NULL) {
			hdrs_size = 0;
			((p_ether_header_t)hdrs_buf)->ether_type = 0;
			while ((nmp) && (hdrs_size < sizeof (hdrs_buf))) {
				mblk_len = (size_t)nmp->b_wptr -
				    (size_t)nmp->b_rptr;
				if (mblk_len >=
				    (sizeof (hdrs_buf) - hdrs_size))
					mblk_len = sizeof (hdrs_buf) -
					    hdrs_size;
				bcopy(nmp->b_rptr,
				    &hdrs_buf[hdrs_size], mblk_len);
				hdrs_size += mblk_len;
				nmp = nmp->b_cont;
			}
			ip_buf = hdrs_buf;
			ip_buf += eth_hdr_size;
			iph_len = ((*ip_buf) & 0x0f);
		}
		ipproto = ip_buf[9];

		tmp = (uint64_t)iph_len;
		hdrp->value |= (tmp << TX_PKT_HEADER_IHL_SHIFT);
		tmp = (uint64_t)(eth_hdr_size >> 1);
		hdrp->value |= (tmp << TX_PKT_HEADER_L3START_SHIFT);

		HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_fill_tx_hdr: IPv4 "
		    " iph_len %d l3start %d eth_hdr_size %d proto 0x%x"
		    "tmp 0x%x", iph_len, hdrp->bits.l3start, eth_hdr_size,
		    ipproto, tmp));
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_tx_pkt_hdr_init: IP value 0x%llx", hdrp->value));
		break;

	case ETHERTYPE_IPV6:
		hdrs_size = 0;
		((p_ether_header_t)hdrs_buf)->ether_type = 0;
		while ((nmp) && (hdrs_size < sizeof (hdrs_buf))) {
			mblk_len = (size_t)nmp->b_wptr - (size_t)nmp->b_rptr;
			if (mblk_len >= (sizeof (hdrs_buf) - hdrs_size))
				mblk_len = sizeof (hdrs_buf) - hdrs_size;
			bcopy(nmp->b_rptr, &hdrs_buf[hdrs_size], mblk_len);
			hdrs_size += mblk_len;
			nmp = nmp->b_cont;
		}
		ip_buf = hdrs_buf;
		ip_buf += eth_hdr_size;

		tmp = 1ull;
		hdrp->value |= (tmp << TX_PKT_HEADER_IP_VER_SHIFT);

		tmp = (eth_hdr_size >> 1);
		hdrp->value |= (tmp << TX_PKT_HEADER_L3START_SHIFT);

		/* byte 6 is the next header protocol */
		ipproto = ip_buf[6];

		HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_fill_tx_hdr: IPv6 "
		    " iph_len %d l3start %d eth_hdr_size %d proto 0x%x",
		    iph_len, hdrp->bits.l3start, eth_hdr_size, ipproto));
		HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_tx_pkt_hdr_init: IPv6 "
		    "value 0x%llx", hdrp->value));
		break;

	default:
		HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_fill_tx_hdr: non-IP"));
		goto fill_tx_header_done;
	}

	switch (ipproto) {
	case IPPROTO_TCP:
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_fill_tx_hdr: TCP (cksum flag %d)", l4_cksum));
		if (l4_cksum) {
			tmp = 1ull;
			hdrp->value |= (tmp << TX_PKT_HEADER_PKT_TYPE_SHIFT);
			HXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> hxge_tx_pkt_hdr_init: TCP CKSUM"
			    "value 0x%llx", hdrp->value));
		}
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_tx_pkt_hdr_init: TCP value 0x%llx", hdrp->value));
		break;

	case IPPROTO_UDP:
		HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_fill_tx_hdr: UDP"));
		if (l4_cksum) {
			tmp = 0x2ull;
			hdrp->value |= (tmp << TX_PKT_HEADER_PKT_TYPE_SHIFT);
		}
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> hxge_tx_pkt_hdr_init: UDP value 0x%llx",
		    hdrp->value));
		break;

	default:
		goto fill_tx_header_done;
	}

fill_tx_header_done:
	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> hxge_fill_tx_hdr: pkt_len %d npads %d value 0x%llx",
	    pkt_len, npads, hdrp->value));
	HXGE_DEBUG_MSG((NULL, TX_CTL, "<== hxge_fill_tx_hdr"));
}

/*ARGSUSED*/
p_mblk_t
hxge_tx_pkt_header_reserve(p_mblk_t mp, uint8_t *npads)
{
	p_mblk_t newmp = NULL;

	if ((newmp = allocb(TX_PKT_HEADER_SIZE, BPRI_MED)) == NULL) {
		HXGE_DEBUG_MSG((NULL, TX_CTL,
		    "<== hxge_tx_pkt_header_reserve: allocb failed"));
		return (NULL);
	}
	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> hxge_tx_pkt_header_reserve: get new mp"));
	DB_TYPE(newmp) = M_DATA;
	newmp->b_rptr = newmp->b_wptr = DB_LIM(newmp);
	linkb(newmp, mp);
	newmp->b_rptr -= TX_PKT_HEADER_SIZE;

	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==>hxge_tx_pkt_header_reserve: b_rptr $%p b_wptr $%p",
	    newmp->b_rptr, newmp->b_wptr));
	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== hxge_tx_pkt_header_reserve: use new mp"));
	return (newmp);
}

int
hxge_tx_pkt_nmblocks(p_mblk_t mp, int *tot_xfer_len_p)
{
	uint_t		nmblks;
	ssize_t		len;
	uint_t		pkt_len;
	p_mblk_t	nmp, bmp, tmp;
	uint8_t		*b_wptr;

	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> hxge_tx_pkt_nmblocks: mp $%p rptr $%p wptr $%p len %d",
	    mp, mp->b_rptr, mp->b_wptr, MBLKL(mp)));

	nmp = mp;
	bmp = mp;
	nmblks = 0;
	pkt_len = 0;
	*tot_xfer_len_p = 0;

	while (nmp) {
		len = MBLKL(nmp);
		HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_tx_pkt_nmblocks: "
		    "len %d pkt_len %d nmblks %d tot_xfer_len %d",
		    len, pkt_len, nmblks, *tot_xfer_len_p));

		if (len <= 0) {
			bmp = nmp;
			nmp = nmp->b_cont;
			HXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> hxge_tx_pkt_nmblocks:"
			    " len (0) pkt_len %d nmblks %d", pkt_len, nmblks));
			continue;
		}
		*tot_xfer_len_p += len;
		HXGE_DEBUG_MSG((NULL, TX_CTL, "==> hxge_tx_pkt_nmblocks: "
		    "len %d pkt_len %d nmblks %d tot_xfer_len %d",
		    len, pkt_len, nmblks, *tot_xfer_len_p));

		if (len < hxge_bcopy_thresh) {
			HXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> hxge_tx_pkt_nmblocks: "
			    "len %d (< thresh) pkt_len %d nmblks %d",
			    len, pkt_len, nmblks));
			if (pkt_len == 0)
				nmblks++;
			pkt_len += len;
			if (pkt_len >= hxge_bcopy_thresh) {
				pkt_len = 0;
				len = 0;
				nmp = bmp;
			}
		} else {
			HXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> hxge_tx_pkt_nmblocks: "
			    "len %d (> thresh) pkt_len %d nmblks %d",
			    len, pkt_len, nmblks));
			pkt_len = 0;
			nmblks++;
			/*
			 * Hardware limits the transfer length to 4K. If len is
			 * more than 4K, we need to break it up to at most 2
			 * more blocks.
			 */
			if (len > TX_MAX_TRANSFER_LENGTH) {
				uint32_t nsegs;

				HXGE_DEBUG_MSG((NULL, TX_CTL,
				    "==> hxge_tx_pkt_nmblocks: "
				    "len %d pkt_len %d nmblks %d nsegs %d",
				    len, pkt_len, nmblks, nsegs));
				nsegs = 1;
				if (len % (TX_MAX_TRANSFER_LENGTH * 2)) {
					++nsegs;
				}
				do {
					b_wptr = nmp->b_rptr +
					    TX_MAX_TRANSFER_LENGTH;
					nmp->b_wptr = b_wptr;
					if ((tmp = dupb(nmp)) == NULL) {
						return (0);
					}
					tmp->b_rptr = b_wptr;
					tmp->b_wptr = nmp->b_wptr;
					tmp->b_cont = nmp->b_cont;
					nmp->b_cont = tmp;
					nmblks++;
					if (--nsegs) {
						nmp = tmp;
					}
				} while (nsegs);
				nmp = tmp;
			}
		}

		/*
		 * Hardware limits the transmit gather pointers to 15.
		 */
		if (nmp->b_cont && (nmblks + TX_GATHER_POINTERS_THRESHOLD) >
		    TX_MAX_GATHER_POINTERS) {
			HXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> hxge_tx_pkt_nmblocks: pull msg - "
			    "len %d pkt_len %d nmblks %d",
			    len, pkt_len, nmblks));
			/* Pull all message blocks from b_cont */
			if ((tmp = msgpullup(nmp->b_cont, -1)) == NULL) {
				return (0);
			}
			freemsg(nmp->b_cont);
			nmp->b_cont = tmp;
			pkt_len = 0;
		}
		bmp = nmp;
		nmp = nmp->b_cont;
	}

	HXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== hxge_tx_pkt_nmblocks: rptr $%p wptr $%p "
	    "nmblks %d len %d tot_xfer_len %d",
	    mp->b_rptr, mp->b_wptr, nmblks, MBLKL(mp), *tot_xfer_len_p));
	return (nmblks);
}

boolean_t
hxge_txdma_reclaim(p_hxge_t hxgep, p_tx_ring_t tx_ring_p, int nmblks)
{
	boolean_t		status = B_TRUE;
	p_hxge_dma_common_t	tx_desc_dma_p;
	hxge_dma_common_t	desc_area;
	p_tx_desc_t		tx_desc_ring_vp;
	p_tx_desc_t		tx_desc_p;
	p_tx_desc_t		tx_desc_pp;
	tx_desc_t		r_tx_desc;
	p_tx_msg_t		tx_msg_ring;
	p_tx_msg_t		tx_msg_p;
	hpi_handle_t		handle;
	tdc_tdr_head_t		tx_head;
	uint32_t		pkt_len;
	uint_t			tx_rd_index;
	uint16_t		head_index, tail_index;
	uint8_t			tdc;
	boolean_t		head_wrap, tail_wrap;
	p_hxge_tx_ring_stats_t	tdc_stats;
	tdc_byte_cnt_t		byte_cnt;
	tdc_tdr_qlen_t		qlen;
	int			rc;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_reclaim"));

	status = ((tx_ring_p->descs_pending < hxge_reclaim_pending) &&
	    (nmblks != 0));
	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_txdma_reclaim: pending %d  reclaim %d nmblks %d",
	    tx_ring_p->descs_pending, hxge_reclaim_pending, nmblks));

	if (!status) {
		tx_desc_dma_p = &tx_ring_p->tdc_desc;
		desc_area = tx_ring_p->tdc_desc;
		tx_desc_ring_vp = tx_desc_dma_p->kaddrp;
		tx_desc_ring_vp = (p_tx_desc_t)DMA_COMMON_VPTR(desc_area);
		tx_rd_index = tx_ring_p->rd_index;
		tx_desc_p = &tx_desc_ring_vp[tx_rd_index];
		tx_msg_ring = tx_ring_p->tx_msg_ring;
		tx_msg_p = &tx_msg_ring[tx_rd_index];
		tdc = tx_ring_p->tdc;
		tdc_stats = tx_ring_p->tdc_stats;
		if (tx_ring_p->descs_pending > tdc_stats->tx_max_pend) {
			tdc_stats->tx_max_pend = tx_ring_p->descs_pending;
		}
		tail_index = tx_ring_p->wr_index;
		tail_wrap = tx_ring_p->wr_index_wrap;

		/*
		 * tdc_byte_cnt reg can be used to get bytes transmitted. It
		 * includes padding too in case of runt packets.
		 */
		handle = HXGE_DEV_HPI_HANDLE(hxgep);
		TXDMA_REG_READ64(handle, TDC_BYTE_CNT, tdc, &byte_cnt.value);
		tdc_stats->obytes_with_pad += byte_cnt.bits.byte_count;

		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_txdma_reclaim: tdc %d tx_rd_index %d "
		    "tail_index %d tail_wrap %d tx_desc_p $%p ($%p) ",
		    tdc, tx_rd_index, tail_index, tail_wrap,
		    tx_desc_p, (*(uint64_t *)tx_desc_p)));

		/*
		 * Read the hardware maintained transmit head and wrap around
		 * bit.
		 */
		TXDMA_REG_READ64(handle, TDC_TDR_HEAD, tdc, &tx_head.value);
		head_index = tx_head.bits.head;
		head_wrap = tx_head.bits.wrap;
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_txdma_reclaim: "
		    "tx_rd_index %d tail %d tail_wrap %d head %d wrap %d",
		    tx_rd_index, tail_index, tail_wrap, head_index, head_wrap));

		/*
		 * For debug only. This can be used to verify the qlen and make
		 * sure the hardware is wrapping the Tdr correctly.
		 */
		TXDMA_REG_READ64(handle, TDC_TDR_QLEN, tdc, &qlen.value);
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_txdma_reclaim: tdr_qlen %d tdr_pref_qlen %d",
		    qlen.bits.tdr_qlen, qlen.bits.tdr_pref_qlen));

		if (head_index == tail_index) {
			if (TXDMA_RING_EMPTY(head_index, head_wrap, tail_index,
			    tail_wrap) && (head_index == tx_rd_index)) {
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "==> hxge_txdma_reclaim: EMPTY"));
				return (B_TRUE);
			}
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: Checking if ring full"));
			if (TXDMA_RING_FULL(head_index, head_wrap, tail_index,
			    tail_wrap)) {
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "==> hxge_txdma_reclaim: full"));
				return (B_FALSE);
			}
		}
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_txdma_reclaim: tx_rd_index and head_index"));

		/* XXXX: limit the # of reclaims */
		tx_desc_pp = &r_tx_desc;
		while ((tx_rd_index != head_index) &&
		    (tx_ring_p->descs_pending != 0)) {
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: Checking if pending"));
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: descs_pending %d ",
			    tx_ring_p->descs_pending));
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: "
			    "(tx_rd_index %d head_index %d (tx_desc_p $%p)",
			    tx_rd_index, head_index, tx_desc_p));

			tx_desc_pp->value = tx_desc_p->value;
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: "
			    "(tx_rd_index %d head_index %d "
			    "tx_desc_p $%p (desc value 0x%llx) ",
			    tx_rd_index, head_index,
			    tx_desc_pp, (*(uint64_t *)tx_desc_pp)));
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: dump desc:"));

			/*
			 * tdc_byte_cnt reg can be used to get bytes
			 * transmitted
			 */
			pkt_len = tx_desc_pp->bits.tr_len;
			tdc_stats->obytes += pkt_len;
			tdc_stats->opackets += tx_desc_pp->bits.sop;
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: pkt_len %d "
			    "tdc channel %d opackets %d",
			    pkt_len, tdc, tdc_stats->opackets));

			if (tx_msg_p->flags.dma_type == USE_DVMA) {
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "tx_desc_p = $%p tx_desc_pp = $%p "
				    "index = %d",
				    tx_desc_p, tx_desc_pp,
				    tx_ring_p->rd_index));
				(void) dvma_unload(tx_msg_p->dvma_handle,
				    0, -1);
				tx_msg_p->dvma_handle = NULL;
				if (tx_ring_p->dvma_wr_index ==
				    tx_ring_p->dvma_wrap_mask) {
					tx_ring_p->dvma_wr_index = 0;
				} else {
					tx_ring_p->dvma_wr_index++;
				}
				tx_ring_p->dvma_pending--;
			} else if (tx_msg_p->flags.dma_type == USE_DMA) {
				HXGE_DEBUG_MSG((hxgep, TX_CTL,
				    "==> hxge_txdma_reclaim: USE DMA"));
				if (rc = ddi_dma_unbind_handle
				    (tx_msg_p->dma_handle)) {
					cmn_err(CE_WARN, "hxge_reclaim: "
					    "ddi_dma_unbind_handle "
					    "failed. status %d", rc);
				}
			}

			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "==> hxge_txdma_reclaim: count packets"));

			/*
			 * count a chained packet only once.
			 */
			if (tx_msg_p->tx_message != NULL) {
				freemsg(tx_msg_p->tx_message);
				tx_msg_p->tx_message = NULL;
			}
			tx_msg_p->flags.dma_type = USE_NONE;
			tx_rd_index = tx_ring_p->rd_index;
			tx_rd_index = (tx_rd_index + 1) &
			    tx_ring_p->tx_wrap_mask;
			tx_ring_p->rd_index = tx_rd_index;
			tx_ring_p->descs_pending--;
			tx_desc_p = &tx_desc_ring_vp[tx_rd_index];
			tx_msg_p = &tx_msg_ring[tx_rd_index];
		}

		status = (nmblks <= ((int)tx_ring_p->tx_ring_size -
		    (int)tx_ring_p->descs_pending - TX_FULL_MARK));
		if (status) {
			(void) atomic_cas_32((uint32_t *)&tx_ring_p->queueing,
			    1, 0);
		}
	} else {
		status = (nmblks <= ((int)tx_ring_p->tx_ring_size -
		    (int)tx_ring_p->descs_pending - TX_FULL_MARK));
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "<== hxge_txdma_reclaim status = 0x%08x", status));
	return (status);
}

uint_t
hxge_tx_intr(caddr_t arg1, caddr_t arg2)
{
	p_hxge_ldv_t	ldvp = (p_hxge_ldv_t)arg1;
	p_hxge_t	hxgep = (p_hxge_t)arg2;
	p_hxge_ldg_t	ldgp;
	uint8_t		channel;
	uint32_t	vindex;
	hpi_handle_t	handle;
	tdc_stat_t	cs;
	p_tx_ring_t	*tx_rings;
	p_tx_ring_t	tx_ring_p;
	hpi_status_t	rs = HPI_SUCCESS;
	uint_t		serviced = DDI_INTR_UNCLAIMED;
	hxge_status_t	status = HXGE_OK;

	if (ldvp == NULL) {
		HXGE_DEBUG_MSG((NULL, INT_CTL,
		    "<== hxge_tx_intr: hxgep $%p ldvp $%p", hxgep, ldvp));
		return (DDI_INTR_UNCLAIMED);
	}

	if (arg2 == NULL || (void *) ldvp->hxgep != arg2) {
		hxgep = ldvp->hxgep;
	}

	/*
	 * If the interface is not started, just swallow the interrupt
	 * and don't rearm the logical device.
	 */
	if (hxgep->hxge_mac_state != HXGE_MAC_STARTED)
		return (DDI_INTR_CLAIMED);

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_tx_intr: hxgep(arg2) $%p ldvp(arg1) $%p", hxgep, ldvp));

	/*
	 * This interrupt handler is for a specific transmit dma channel.
	 */
	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/* Get the control and status for this channel. */
	channel = ldvp->channel;
	ldgp = ldvp->ldgp;
	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_tx_intr: hxgep $%p ldvp (ldvp) $%p channel %d",
	    hxgep, ldvp, channel));

	rs = hpi_txdma_control_status(handle, OP_GET, channel, &cs);
	vindex = ldvp->vdma_index;
	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_tx_intr:channel %d ring index %d status 0x%08x",
	    channel, vindex, rs));

	if (!rs && cs.bits.marked) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_tx_intr:channel %d ring index %d "
		    "status 0x%08x (marked bit set)", channel, vindex, rs));
		tx_rings = hxgep->tx_rings->rings;
		tx_ring_p = tx_rings[vindex];
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_tx_intr:channel %d ring index %d "
		    "status 0x%08x (marked bit set, calling reclaim)",
		    channel, vindex, rs));

		MUTEX_ENTER(&tx_ring_p->lock);
		(void) hxge_txdma_reclaim(hxgep, tx_rings[vindex], 0);
		MUTEX_EXIT(&tx_ring_p->lock);
		mac_tx_update(hxgep->mach);
	}

	/*
	 * Process other transmit control and status. Check the ldv state.
	 */
	status = hxge_tx_err_evnts(hxgep, ldvp->vdma_index, ldvp, cs);

	/* Clear the error bits */
	RXDMA_REG_WRITE64(handle, TDC_STAT, channel, cs.value);

	/*
	 * Rearm this logical group if this is a single device group.
	 */
	if (ldgp->nldvs == 1) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_tx_intr: rearm"));
		if (status == HXGE_OK) {
			(void) hpi_intr_ldg_mgmt_set(handle, ldgp->ldg,
			    B_TRUE, ldgp->ldg_timer);
		}
	}
	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_tx_intr"));
	serviced = DDI_INTR_CLAIMED;
	return (serviced);
}

void
hxge_txdma_stop(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_stop"));

	(void) hxge_tx_vmac_disable(hxgep);
	(void) hxge_txdma_hw_mode(hxgep, HXGE_DMA_STOP);

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_stop"));
}

hxge_status_t
hxge_txdma_hw_mode(p_hxge_t hxgep, boolean_t enable)
{
	int		i, ndmas;
	uint16_t	channel;
	p_tx_rings_t	tx_rings;
	p_tx_ring_t	*tx_desc_rings;
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_txdma_hw_mode: enable mode %d", enable));

	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_mode: not initialized"));
		return (HXGE_ERROR);
	}
	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_mode: NULL global ring pointer"));
		return (HXGE_ERROR);
	}
	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_mode: NULL rings pointer"));
		return (HXGE_ERROR);
	}
	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_txdma_hw_mode: no dma channel allocated"));
		return (HXGE_ERROR);
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_hw_mode: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_desc_rings, ndmas));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		channel = tx_desc_rings[i]->tdc;
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "==> hxge_txdma_hw_mode: channel %d", channel));
		if (enable) {
			rs = hpi_txdma_channel_enable(handle, channel);
			HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
			    "==> hxge_txdma_hw_mode: channel %d (enable) "
			    "rs 0x%x", channel, rs));
		} else {
			/*
			 * Stop the dma channel and waits for the stop done. If
			 * the stop done bit is not set, then force an error so
			 * TXC will stop. All channels bound to this port need
			 * to be stopped and reset after injecting an interrupt
			 * error.
			 */
			rs = hpi_txdma_channel_disable(handle, channel);
			HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
			    "==> hxge_txdma_hw_mode: channel %d (disable) "
			    "rs 0x%x", channel, rs));
		}
	}

	status = ((rs == HPI_SUCCESS) ? HXGE_OK : HXGE_ERROR | rs);

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_txdma_hw_mode: status 0x%x", status));

	return (status);
}

void
hxge_txdma_enable_channel(p_hxge_t hxgep, uint16_t channel)
{
	hpi_handle_t handle;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_txdma_enable_channel: channel %d", channel));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	/* enable the transmit dma channels */
	(void) hpi_txdma_channel_enable(handle, channel);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_txdma_enable_channel"));
}

void
hxge_txdma_disable_channel(p_hxge_t hxgep, uint16_t channel)
{
	hpi_handle_t handle;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_txdma_disable_channel: channel %d", channel));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	/* stop the transmit dma channels */
	(void) hpi_txdma_channel_disable(handle, channel);

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_disable_channel"));
}

int
hxge_txdma_stop_inj_err(p_hxge_t hxgep, int channel)
{
	hpi_handle_t	handle;
	int		status;
	hpi_status_t	rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_stop_inj_err"));

	/*
	 * Stop the dma channel waits for the stop done. If the stop done bit
	 * is not set, then create an error.
	 */
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	rs = hpi_txdma_channel_disable(handle, channel);
	status = ((rs == HPI_SUCCESS) ? HXGE_OK : HXGE_ERROR | rs);
	if (status == HXGE_OK) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_stop_inj_err (channel %d): "
		    "stopped OK", channel));
		return (status);
	}

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "==> hxge_txdma_stop_inj_err (channel): stop failed (0x%x) "
	    " (injected error but still not stopped)", channel, rs));

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_stop_inj_err"));

	return (status);
}

/*ARGSUSED*/
void
hxge_fixup_txdma_rings(p_hxge_t hxgep)
{
	int		index, ndmas;
	uint16_t	channel;
	p_tx_rings_t	tx_rings;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_fixup_txdma_rings"));

	/*
	 * For each transmit channel, reclaim each descriptor and free buffers.
	 */
	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_fixup_txdma_rings: NULL ring pointer"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_fixup_txdma_rings: no channel allocated"));
		return;
	}

	if (tx_rings->rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_fixup_txdma_rings: NULL rings pointer"));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_fixup_txdma_rings: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "==> hxge_fixup_txdma_rings: channel %d", channel));
		hxge_txdma_fixup_channel(hxgep, tx_rings->rings[index],
		    channel);
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_fixup_txdma_rings"));
}

/*ARGSUSED*/
void
hxge_txdma_fix_channel(p_hxge_t hxgep, uint16_t channel)
{
	p_tx_ring_t ring_p;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_fix_channel"));

	ring_p = hxge_txdma_get_ring(hxgep, channel);
	if (ring_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_fix_channel"));
		return;
	}

	if (ring_p->tdc != channel) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fix_channel: channel not matched "
		    "ring tdc %d passed channel", ring_p->tdc, channel));
		return;
	}

	hxge_txdma_fixup_channel(hxgep, ring_p, channel);

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_fix_channel"));
}

/*ARGSUSED*/
void
hxge_txdma_fixup_channel(p_hxge_t hxgep, p_tx_ring_t ring_p, uint16_t channel)
{
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_fixup_channel"));

	if (ring_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fixup_channel: NULL ring pointer"));
		return;
	}
	if (ring_p->tdc != channel) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fixup_channel: channel not matched "
		    "ring tdc %d passed channel", ring_p->tdc, channel));
		return;
	}
	MUTEX_ENTER(&ring_p->lock);
	(void) hxge_txdma_reclaim(hxgep, ring_p, 0);

	ring_p->rd_index = 0;
	ring_p->wr_index = 0;
	ring_p->ring_head.value = 0;
	ring_p->ring_kick_tail.value = 0;
	ring_p->descs_pending = 0;
	MUTEX_EXIT(&ring_p->lock);

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_fixup_channel"));
}

/*ARGSUSED*/
void
hxge_txdma_hw_kick(p_hxge_t hxgep)
{
	int		index, ndmas;
	uint16_t	channel;
	p_tx_rings_t	tx_rings;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_hw_kick"));

	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_kick: NULL ring pointer"));
		return;
	}
	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_kick: no channel allocated"));
		return;
	}
	if (tx_rings->rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_kick: NULL rings pointer"));
		return;
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_hw_kick: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "==> hxge_txdma_hw_kick: channel %d", channel));
		hxge_txdma_hw_kick_channel(hxgep, tx_rings->rings[index],
		    channel);
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_hw_kick"));
}

/*ARGSUSED*/
void
hxge_txdma_kick_channel(p_hxge_t hxgep, uint16_t channel)
{
	p_tx_ring_t ring_p;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_kick_channel"));

	ring_p = hxge_txdma_get_ring(hxgep, channel);
	if (ring_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL, " hxge_txdma_kick_channel"));
		return;
	}

	if (ring_p->tdc != channel) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_kick_channel: channel not matched "
		    "ring tdc %d passed channel", ring_p->tdc, channel));
		return;
	}

	hxge_txdma_hw_kick_channel(hxgep, ring_p, channel);

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_kick_channel"));
}

/*ARGSUSED*/
void
hxge_txdma_hw_kick_channel(p_hxge_t hxgep, p_tx_ring_t ring_p, uint16_t channel)
{
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_hw_kick_channel"));

	if (ring_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_kick_channel: NULL ring pointer"));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_hw_kick_channel"));
}

/*ARGSUSED*/
void
hxge_check_tx_hang(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_check_tx_hang"));

	/*
	 * Needs inputs from hardware for regs: head index had not moved since
	 * last timeout. packets not transmitted or stuffed registers.
	 */
	if (hxge_txdma_hung(hxgep)) {
		hxge_fixup_hung_txdma_rings(hxgep);
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_check_tx_hang"));
}

int
hxge_txdma_hung(p_hxge_t hxgep)
{
	int		index, ndmas;
	uint16_t	channel;
	p_tx_rings_t	tx_rings;
	p_tx_ring_t	tx_ring_p;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_hung"));

	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hung: NULL ring pointer"));
		return (B_FALSE);
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hung: no channel allocated"));
		return (B_FALSE);
	}

	if (tx_rings->rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hung: NULL rings pointer"));
		return (B_FALSE);
	}

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		tx_ring_p = tx_rings->rings[index];
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_txdma_hung: channel %d", channel));
		if (hxge_txdma_channel_hung(hxgep, tx_ring_p, channel)) {
			return (B_TRUE);
		}
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_hung"));

	return (B_FALSE);
}

int
hxge_txdma_channel_hung(p_hxge_t hxgep, p_tx_ring_t tx_ring_p, uint16_t channel)
{
	uint16_t	head_index, tail_index;
	boolean_t	head_wrap, tail_wrap;
	hpi_handle_t	handle;
	tdc_tdr_head_t	tx_head;
	uint_t		tx_rd_index;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_channel_hung"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_txdma_channel_hung: channel %d", channel));
	MUTEX_ENTER(&tx_ring_p->lock);
	(void) hxge_txdma_reclaim(hxgep, tx_ring_p, 0);

	tail_index = tx_ring_p->wr_index;
	tail_wrap = tx_ring_p->wr_index_wrap;
	tx_rd_index = tx_ring_p->rd_index;
	MUTEX_EXIT(&tx_ring_p->lock);

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_txdma_channel_hung: tdc %d tx_rd_index %d "
	    "tail_index %d tail_wrap %d ",
	    channel, tx_rd_index, tail_index, tail_wrap));
	/*
	 * Read the hardware maintained transmit head and wrap around bit.
	 */
	(void) hpi_txdma_ring_head_get(handle, channel, &tx_head);
	head_index = tx_head.bits.head;
	head_wrap = tx_head.bits.wrap;
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_channel_hung: "
	    "tx_rd_index %d tail %d tail_wrap %d head %d wrap %d",
	    tx_rd_index, tail_index, tail_wrap, head_index, head_wrap));

	if (TXDMA_RING_EMPTY(head_index, head_wrap, tail_index, tail_wrap) &&
	    (head_index == tx_rd_index)) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_txdma_channel_hung: EMPTY"));
		return (B_FALSE);
	}
	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "==> hxge_txdma_channel_hung: Checking if ring full"));
	if (TXDMA_RING_FULL(head_index, head_wrap, tail_index, tail_wrap)) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_txdma_channel_hung: full"));
		return (B_TRUE);
	}

	/* If not full, check with hardware to see if it is hung */
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_channel_hung"));

	return (B_FALSE);
}

/*ARGSUSED*/
void
hxge_fixup_hung_txdma_rings(p_hxge_t hxgep)
{
	int		index, ndmas;
	uint16_t	channel;
	p_tx_rings_t	tx_rings;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_fixup_hung_txdma_rings"));
	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_fixup_hung_txdma_rings: NULL ring pointer"));
		return;
	}
	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_fixup_hung_txdma_rings: no channel allocated"));
		return;
	}
	if (tx_rings->rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_fixup_hung_txdma_rings: NULL rings pointer"));
		return;
	}
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_fixup_hung_txdma_rings: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_fixup_hung_txdma_rings: channel %d", channel));
		hxge_txdma_fixup_hung_channel(hxgep, tx_rings->rings[index],
		    channel);
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_fixup_hung_txdma_rings"));
}

/*ARGSUSED*/
void
hxge_txdma_fix_hung_channel(p_hxge_t hxgep, uint16_t channel)
{
	p_tx_ring_t ring_p;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_fix_hung_channel"));
	ring_p = hxge_txdma_get_ring(hxgep, channel);
	if (ring_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fix_hung_channel"));
		return;
	}
	if (ring_p->tdc != channel) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fix_hung_channel: channel not matched "
		    "ring tdc %d passed channel", ring_p->tdc, channel));
		return;
	}
	hxge_txdma_fixup_channel(hxgep, ring_p, channel);

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_fix_hung_channel"));
}

/*ARGSUSED*/
void
hxge_txdma_fixup_hung_channel(p_hxge_t hxgep, p_tx_ring_t ring_p,
    uint16_t channel)
{
	hpi_handle_t	handle;
	int		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_fixup_hung_channel"));

	if (ring_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fixup_hung_channel: NULL ring pointer"));
		return;
	}
	if (ring_p->tdc != channel) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fixup_hung_channel: channel "
		    "not matched ring tdc %d passed channel",
		    ring_p->tdc, channel));
		return;
	}
	/* Reclaim descriptors */
	MUTEX_ENTER(&ring_p->lock);
	(void) hxge_txdma_reclaim(hxgep, ring_p, 0);
	MUTEX_EXIT(&ring_p->lock);

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	/*
	 * Stop the dma channel waits for the stop done. If the stop done bit
	 * is not set, then force an error.
	 */
	status = hpi_txdma_channel_disable(handle, channel);
	if (!(status & HPI_TXDMA_STOP_FAILED)) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fixup_hung_channel: stopped OK "
		    "ring tdc %d passed channel %d", ring_p->tdc, channel));
		return;
	}
	/* Stop done bit will be set as a result of error injection */
	status = hpi_txdma_channel_disable(handle, channel);
	if (!(status & HPI_TXDMA_STOP_FAILED)) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_fixup_hung_channel: stopped again"
		    "ring tdc %d passed channel", ring_p->tdc, channel));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL,
	    "<== hxge_txdma_fixup_hung_channel: stop done still not set!! "
	    "ring tdc %d passed channel", ring_p->tdc, channel));
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_fixup_hung_channel"));
}

/*ARGSUSED*/
void
hxge_reclaim_rings(p_hxge_t hxgep)
{
	int		index, ndmas;
	uint16_t	channel;
	p_tx_rings_t	tx_rings;
	p_tx_ring_t	tx_ring_p;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_reclaim_ring"));
	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_reclain_rimgs: NULL ring pointer"));
		return;
	}
	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_reclain_rimgs: no channel allocated"));
		return;
	}
	if (tx_rings->rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_reclain_rimgs: NULL rings pointer"));
		return;
	}
	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_reclain_rimgs: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> reclain_rimgs: channel %d",
		    channel));
		tx_ring_p = tx_rings->rings[index];
		MUTEX_ENTER(&tx_ring_p->lock);
		(void) hxge_txdma_reclaim(hxgep, tx_ring_p, channel);
		MUTEX_EXIT(&tx_ring_p->lock);
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_reclaim_rings"));
}

/*
 * Static functions start here.
 */
static hxge_status_t
hxge_map_txdma(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_tx_rings_t		tx_rings;
	p_tx_ring_t		*tx_desc_rings;
	p_tx_mbox_areas_t	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;
	p_hxge_dma_pool_t	dma_buf_poolp;
	p_hxge_dma_pool_t	dma_cntl_poolp;
	p_hxge_dma_common_t	*dma_buf_p;
	p_hxge_dma_common_t	*dma_cntl_p;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_map_txdma"));

	dma_buf_poolp = hxgep->tx_buf_pool_p;
	dma_cntl_poolp = hxgep->tx_cntl_pool_p;

	if (!dma_buf_poolp->buf_allocated || !dma_cntl_poolp->buf_allocated) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_map_txdma: buf not allocated"));
		return (HXGE_ERROR);
	}
	ndmas = dma_buf_poolp->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_map_txdma: no dma allocated"));
		return (HXGE_ERROR);
	}
	dma_buf_p = dma_buf_poolp->dma_buf_pool_p;
	dma_cntl_p = dma_cntl_poolp->dma_buf_pool_p;

	tx_rings = (p_tx_rings_t)KMEM_ZALLOC(sizeof (tx_rings_t), KM_SLEEP);
	tx_desc_rings = (p_tx_ring_t *)KMEM_ZALLOC(
	    sizeof (p_tx_ring_t) * ndmas, KM_SLEEP);

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_map_txdma: "
	    "tx_rings $%p tx_desc_rings $%p", tx_rings, tx_desc_rings));

	tx_mbox_areas_p = (p_tx_mbox_areas_t)
	    KMEM_ZALLOC(sizeof (tx_mbox_areas_t), KM_SLEEP);
	tx_mbox_p = (p_tx_mbox_t *)KMEM_ZALLOC(
	    sizeof (p_tx_mbox_t) * ndmas, KM_SLEEP);

	/*
	 * Map descriptors from the buffer pools for each dma channel.
	 */
	for (i = 0; i < ndmas; i++) {
		/*
		 * Set up and prepare buffer blocks, descriptors and mailbox.
		 */
		channel = ((p_hxge_dma_common_t)dma_buf_p[i])->dma_channel;
		status = hxge_map_txdma_channel(hxgep, channel,
		    (p_hxge_dma_common_t *)&dma_buf_p[i],
		    (p_tx_ring_t *)&tx_desc_rings[i],
		    dma_buf_poolp->num_chunks[i],
		    (p_hxge_dma_common_t *)&dma_cntl_p[i],
		    (p_tx_mbox_t *)&tx_mbox_p[i]);
		if (status != HXGE_OK) {
			goto hxge_map_txdma_fail1;
		}
		tx_desc_rings[i]->index = (uint16_t)i;
		tx_desc_rings[i]->tdc_stats = &hxgep->statsp->tdc_stats[i];
	}

	tx_rings->ndmas = ndmas;
	tx_rings->rings = tx_desc_rings;
	hxgep->tx_rings = tx_rings;
	tx_mbox_areas_p->txmbox_areas_p = tx_mbox_p;
	hxgep->tx_mbox_areas_p = tx_mbox_areas_p;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_map_txdma: "
	    "tx_rings $%p rings $%p", hxgep->tx_rings, hxgep->tx_rings->rings));
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_map_txdma: "
	    "tx_rings $%p tx_desc_rings $%p",
	    hxgep->tx_rings, tx_desc_rings));

	goto hxge_map_txdma_exit;

hxge_map_txdma_fail1:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma: uninit tx desc "
	    "(status 0x%x channel %d i %d)", hxgep, status, channel, i));
	i--;
	for (; i >= 0; i--) {
		channel = ((p_hxge_dma_common_t)dma_buf_p[i])->dma_channel;
		hxge_unmap_txdma_channel(hxgep, channel, tx_desc_rings[i],
		    tx_mbox_p[i]);
	}

	KMEM_FREE(tx_desc_rings, sizeof (p_tx_ring_t) * ndmas);
	KMEM_FREE(tx_rings, sizeof (tx_rings_t));
	KMEM_FREE(tx_mbox_p, sizeof (p_tx_mbox_t) * ndmas);
	KMEM_FREE(tx_mbox_areas_p, sizeof (tx_mbox_areas_t));

hxge_map_txdma_exit:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma: (status 0x%x channel %d)", status, channel));

	return (status);
}

static void
hxge_unmap_txdma(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint8_t			channel;
	p_tx_rings_t		tx_rings;
	p_tx_ring_t		*tx_desc_rings;
	p_tx_mbox_areas_t	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;
	p_hxge_dma_pool_t	dma_buf_poolp;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_unmap_txdma"));

	dma_buf_poolp = hxgep->tx_buf_pool_p;
	if (!dma_buf_poolp->buf_allocated) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "==> hxge_unmap_txdma: buf not allocated"));
		return;
	}
	ndmas = dma_buf_poolp->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_unmap_txdma: no dma allocated"));
		return;
	}
	tx_rings = hxgep->tx_rings;
	tx_desc_rings = tx_rings->rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_unmap_txdma: NULL ring pointer"));
		return;
	}
	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_unmap_txdma: NULL ring pointers"));
		return;
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_unmap_txdma: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_desc_rings, ndmas));

	tx_mbox_areas_p = hxgep->tx_mbox_areas_p;
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	for (i = 0; i < ndmas; i++) {
		channel = tx_desc_rings[i]->tdc;
		(void) hxge_unmap_txdma_channel(hxgep, channel,
		    (p_tx_ring_t)tx_desc_rings[i],
		    (p_tx_mbox_t)tx_mbox_p[i]);
	}

	KMEM_FREE(tx_desc_rings, sizeof (p_tx_ring_t) * ndmas);
	KMEM_FREE(tx_rings, sizeof (tx_rings_t));
	KMEM_FREE(tx_mbox_p, sizeof (p_tx_mbox_t) * ndmas);
	KMEM_FREE(tx_mbox_areas_p, sizeof (tx_mbox_areas_t));

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_unmap_txdma"));
}

static hxge_status_t
hxge_map_txdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_hxge_dma_common_t *dma_buf_p, p_tx_ring_t *tx_desc_p,
    uint32_t num_chunks, p_hxge_dma_common_t *dma_cntl_p,
    p_tx_mbox_t *tx_mbox_p)
{
	int status = HXGE_OK;

	/*
	 * Set up and prepare buffer blocks, descriptors and mailbox.
	 */
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel (channel %d)", channel));

	/*
	 * Transmit buffer blocks
	 */
	status = hxge_map_txdma_channel_buf_ring(hxgep, channel,
	    dma_buf_p, tx_desc_p, num_chunks);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_map_txdma_channel (channel %d): "
		    "map buffer failed 0x%x", channel, status));
		goto hxge_map_txdma_channel_exit;
	}
	/*
	 * Transmit block ring, and mailbox.
	 */
	hxge_map_txdma_channel_cfg_ring(hxgep, channel, dma_cntl_p, *tx_desc_p,
	    tx_mbox_p);

	goto hxge_map_txdma_channel_exit;

hxge_map_txdma_channel_fail1:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel: unmap buf"
	    "(status 0x%x channel %d)", status, channel));
	hxge_unmap_txdma_channel_buf_ring(hxgep, *tx_desc_p);

hxge_map_txdma_channel_exit:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_map_txdma_channel: (status 0x%x channel %d)",
	    status, channel));

	return (status);
}

/*ARGSUSED*/
static void
hxge_unmap_txdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p)
{
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_unmap_txdma_channel (channel %d)", channel));

	/* unmap tx block ring, and mailbox.  */
	(void) hxge_unmap_txdma_channel_cfg_ring(hxgep, tx_ring_p, tx_mbox_p);

	/* unmap buffer blocks */
	(void) hxge_unmap_txdma_channel_buf_ring(hxgep, tx_ring_p);

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_unmap_txdma_channel"));
}

/*ARGSUSED*/
static void
hxge_map_txdma_channel_cfg_ring(p_hxge_t hxgep, uint16_t dma_channel,
    p_hxge_dma_common_t *dma_cntl_p, p_tx_ring_t tx_ring_p,
    p_tx_mbox_t *tx_mbox_p)
{
	p_tx_mbox_t		mboxp;
	p_hxge_dma_common_t	cntl_dmap;
	p_hxge_dma_common_t	dmap;
	tdc_tdr_cfg_t		*tx_ring_cfig_p;
	tdc_tdr_kick_t		*tx_ring_kick_p;
	tdc_tdr_cfg_t		*tx_cs_p;
	tdc_int_mask_t		*tx_evmask_p;
	tdc_mbh_t		*mboxh_p;
	tdc_mbl_t		*mboxl_p;
	uint64_t		tx_desc_len;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_cfg_ring"));

	cntl_dmap = *dma_cntl_p;

	dmap = (p_hxge_dma_common_t)&tx_ring_p->tdc_desc;
	hxge_setup_dma_common(dmap, cntl_dmap, tx_ring_p->tx_ring_size,
	    sizeof (tx_desc_t));

	/*
	 * Zero out transmit ring descriptors.
	 */
	bzero((caddr_t)dmap->kaddrp, dmap->alength);
	tx_ring_cfig_p = &(tx_ring_p->tx_ring_cfig);
	tx_ring_kick_p = &(tx_ring_p->tx_ring_kick);
	tx_cs_p = &(tx_ring_p->tx_cs);
	tx_evmask_p = &(tx_ring_p->tx_evmask);
	tx_ring_cfig_p->value = 0;
	tx_ring_kick_p->value = 0;
	tx_cs_p->value = 0;
	tx_evmask_p->value = 0;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_cfg_ring: channel %d des $%p",
	    dma_channel, dmap->dma_cookie.dmac_laddress));

	tx_ring_cfig_p->value = 0;

	/* Hydra len is 11 bits and the lower 5 bits are 0s */
	tx_desc_len = (uint64_t)(tx_ring_p->tx_ring_size >> 5);
	tx_ring_cfig_p->value =
	    (dmap->dma_cookie.dmac_laddress & TDC_TDR_CFG_ADDR_MASK) |
	    (tx_desc_len << TDC_TDR_CFG_LEN_SHIFT);

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_cfg_ring: channel %d cfg 0x%llx",
	    dma_channel, tx_ring_cfig_p->value));

	tx_cs_p->bits.reset = 1;

	/* Map in mailbox */
	mboxp = (p_tx_mbox_t)KMEM_ZALLOC(sizeof (tx_mbox_t), KM_SLEEP);
	dmap = (p_hxge_dma_common_t)&mboxp->tx_mbox;
	hxge_setup_dma_common(dmap, cntl_dmap, 1, sizeof (txdma_mailbox_t));
	mboxh_p = (tdc_mbh_t *)&tx_ring_p->tx_mbox_mbh;
	mboxl_p = (tdc_mbl_t *)&tx_ring_p->tx_mbox_mbl;
	mboxh_p->value = mboxl_p->value = 0;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_cfg_ring: mbox 0x%lx",
	    dmap->dma_cookie.dmac_laddress));

	mboxh_p->bits.mbaddr = ((dmap->dma_cookie.dmac_laddress >>
	    TDC_MBH_ADDR_SHIFT) & TDC_MBH_MASK);
	mboxl_p->bits.mbaddr = ((dmap->dma_cookie.dmac_laddress &
	    TDC_MBL_MASK) >> TDC_MBL_SHIFT);

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_cfg_ring: mbox 0x%lx",
	    dmap->dma_cookie.dmac_laddress));
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_cfg_ring: hmbox $%p mbox $%p",
	    mboxh_p->bits.mbaddr, mboxl_p->bits.mbaddr));

	/*
	 * Set page valid and no mask
	 */
	tx_ring_p->page_hdl.value = 0;

	*tx_mbox_p = mboxp;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_map_txdma_channel_cfg_ring"));
}

/*ARGSUSED*/
static void
hxge_unmap_txdma_channel_cfg_ring(p_hxge_t hxgep,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p)
{
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_unmap_txdma_channel_cfg_ring: channel %d",
	    tx_ring_p->tdc));

	KMEM_FREE(tx_mbox_p, sizeof (tx_mbox_t));

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_unmap_txdma_channel_cfg_ring"));
}

static hxge_status_t
hxge_map_txdma_channel_buf_ring(p_hxge_t hxgep, uint16_t channel,
    p_hxge_dma_common_t *dma_buf_p,
    p_tx_ring_t *tx_desc_p, uint32_t num_chunks)
{
	p_hxge_dma_common_t	dma_bufp, tmp_bufp;
	p_hxge_dma_common_t	dmap;
	hxge_os_dma_handle_t	tx_buf_dma_handle;
	p_tx_ring_t		tx_ring_p;
	p_tx_msg_t		tx_msg_ring;
	hxge_status_t		status = HXGE_OK;
	int			ddi_status = DDI_SUCCESS;
	int			i, j, index;
	uint32_t		size, bsize;
	uint32_t		nblocks, nmsgs;
	char			qname[TASKQ_NAMELEN];

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_buf_ring"));

	dma_bufp = tmp_bufp = *dma_buf_p;
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    " hxge_map_txdma_channel_buf_ring: channel %d to map %d "
	    "chunks bufp $%p", channel, num_chunks, dma_bufp));

	nmsgs = 0;
	for (i = 0; i < num_chunks; i++, tmp_bufp++) {
		nmsgs += tmp_bufp->nblocks;
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "==> hxge_map_txdma_channel_buf_ring: channel %d "
		    "bufp $%p nblocks %d nmsgs %d",
		    channel, tmp_bufp, tmp_bufp->nblocks, nmsgs));
	}
	if (!nmsgs) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_map_txdma_channel_buf_ring: channel %d "
		    "no msg blocks", channel));
		status = HXGE_ERROR;

		goto hxge_map_txdma_channel_buf_ring_exit;
	}

	tx_ring_p = (p_tx_ring_t)KMEM_ZALLOC(sizeof (tx_ring_t), KM_SLEEP);
	tx_ring_p->hxgep = hxgep;
	(void) snprintf(qname, TASKQ_NAMELEN, "hxge_%d_%d",
	    hxgep->instance, channel);
	tx_ring_p->taskq = ddi_taskq_create(hxgep->dip, qname, 1,
	    TASKQ_DEFAULTPRI, 0);
	if (tx_ring_p->taskq == NULL) {
		goto hxge_map_txdma_channel_buf_ring_fail1;
	}

	MUTEX_INIT(&tx_ring_p->lock, NULL, MUTEX_DRIVER,
	    (void *) hxgep->interrupt_cookie);
	/*
	 * Allocate transmit message rings and handles for packets not to be
	 * copied to premapped buffers.
	 */
	size = nmsgs * sizeof (tx_msg_t);
	tx_msg_ring = KMEM_ZALLOC(size, KM_SLEEP);
	for (i = 0; i < nmsgs; i++) {
		ddi_status = ddi_dma_alloc_handle(hxgep->dip, &hxge_tx_dma_attr,
		    DDI_DMA_DONTWAIT, 0, &tx_msg_ring[i].dma_handle);
		if (ddi_status != DDI_SUCCESS) {
			status |= HXGE_DDI_FAILED;
			break;
		}
	}

	if (i < nmsgs) {
		HXGE_DEBUG_MSG((hxgep, HXGE_ERR_CTL,
		    "Allocate handles failed."));

		goto hxge_map_txdma_channel_buf_ring_fail1;
	}
	tx_ring_p->tdc = channel;
	tx_ring_p->tx_msg_ring = tx_msg_ring;
	tx_ring_p->tx_ring_size = nmsgs;
	tx_ring_p->num_chunks = num_chunks;
	if (!hxge_tx_intr_thres) {
		hxge_tx_intr_thres = tx_ring_p->tx_ring_size / 4;
	}
	tx_ring_p->tx_wrap_mask = tx_ring_p->tx_ring_size - 1;
	tx_ring_p->rd_index = 0;
	tx_ring_p->wr_index = 0;
	tx_ring_p->ring_head.value = 0;
	tx_ring_p->ring_kick_tail.value = 0;
	tx_ring_p->descs_pending = 0;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_map_txdma_channel_buf_ring: channel %d "
	    "actual tx desc max %d nmsgs %d (config hxge_tx_ring_size %d)",
	    channel, tx_ring_p->tx_ring_size, nmsgs, hxge_tx_ring_size));

	/*
	 * Map in buffers from the buffer pool.
	 */
	index = 0;
	bsize = dma_bufp->block_size;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_map_txdma_channel_buf_ring: "
	    "dma_bufp $%p tx_rng_p $%p tx_msg_rng_p $%p bsize %d",
	    dma_bufp, tx_ring_p, tx_msg_ring, bsize));

	for (i = 0; i < num_chunks; i++, dma_bufp++) {
		bsize = dma_bufp->block_size;
		nblocks = dma_bufp->nblocks;
		tx_buf_dma_handle = dma_bufp->dma_handle;
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "==> hxge_map_txdma_channel_buf_ring: dma chunk %d "
		    "size %d dma_bufp $%p",
		    i, sizeof (hxge_dma_common_t), dma_bufp));

		for (j = 0; j < nblocks; j++) {
			tx_msg_ring[index].buf_dma_handle = tx_buf_dma_handle;
			tx_msg_ring[index].offset_index = j;
			dmap = &tx_msg_ring[index++].buf_dma;
			HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
			    "==> hxge_map_txdma_channel_buf_ring: j %d"
			    "dmap $%p", i, dmap));
			hxge_setup_dma_common(dmap, dma_bufp, 1, bsize);
		}
	}

	if (i < num_chunks) {
		status = HXGE_ERROR;

		goto hxge_map_txdma_channel_buf_ring_fail1;
	}

	*tx_desc_p = tx_ring_p;

	goto hxge_map_txdma_channel_buf_ring_exit;

hxge_map_txdma_channel_buf_ring_fail1:
	if (tx_ring_p->taskq) {
		ddi_taskq_destroy(tx_ring_p->taskq);
		tx_ring_p->taskq = NULL;
	}

	index--;
	for (; index >= 0; index--) {
		if (tx_msg_ring[index].dma_handle != NULL) {
			ddi_dma_free_handle(&tx_msg_ring[index].dma_handle);
		}
	}
	MUTEX_DESTROY(&tx_ring_p->lock);
	KMEM_FREE(tx_msg_ring, size);
	KMEM_FREE(tx_ring_p, sizeof (tx_ring_t));

	status = HXGE_ERROR;

hxge_map_txdma_channel_buf_ring_exit:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_map_txdma_channel_buf_ring status 0x%x", status));

	return (status);
}

/*ARGSUSED*/
static void
hxge_unmap_txdma_channel_buf_ring(p_hxge_t hxgep, p_tx_ring_t tx_ring_p)
{
	p_tx_msg_t	tx_msg_ring;
	p_tx_msg_t	tx_msg_p;
	int		i;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_unmap_txdma_channel_buf_ring"));
	if (tx_ring_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_unmap_txdma_channel_buf_ring: NULL ringp"));
		return;
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_unmap_txdma_channel_buf_ring: channel %d",
	    tx_ring_p->tdc));

	MUTEX_ENTER(&tx_ring_p->lock);
	tx_msg_ring = tx_ring_p->tx_msg_ring;
	for (i = 0; i < tx_ring_p->tx_ring_size; i++) {
		tx_msg_p = &tx_msg_ring[i];
		if (tx_msg_p->flags.dma_type == USE_DVMA) {
			HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "entry = %d", i));
			(void) dvma_unload(tx_msg_p->dvma_handle, 0, -1);
			tx_msg_p->dvma_handle = NULL;
			if (tx_ring_p->dvma_wr_index ==
			    tx_ring_p->dvma_wrap_mask) {
				tx_ring_p->dvma_wr_index = 0;
			} else {
				tx_ring_p->dvma_wr_index++;
			}
			tx_ring_p->dvma_pending--;
		} else if (tx_msg_p->flags.dma_type == USE_DMA) {
			if (ddi_dma_unbind_handle(tx_msg_p->dma_handle)) {
				cmn_err(CE_WARN, "hxge_unmap_tx_bug_ring: "
				    "ddi_dma_unbind_handle failed.");
			}
		}
		if (tx_msg_p->tx_message != NULL) {
			freemsg(tx_msg_p->tx_message);
			tx_msg_p->tx_message = NULL;
		}
	}

	for (i = 0; i < tx_ring_p->tx_ring_size; i++) {
		if (tx_msg_ring[i].dma_handle != NULL) {
			ddi_dma_free_handle(&tx_msg_ring[i].dma_handle);
		}
	}
	MUTEX_EXIT(&tx_ring_p->lock);

	if (tx_ring_p->taskq) {
		ddi_taskq_destroy(tx_ring_p->taskq);
		tx_ring_p->taskq = NULL;
	}

	MUTEX_DESTROY(&tx_ring_p->lock);
	KMEM_FREE(tx_msg_ring, sizeof (tx_msg_t) * tx_ring_p->tx_ring_size);
	KMEM_FREE(tx_ring_p, sizeof (tx_ring_t));

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "<== hxge_unmap_txdma_channel_buf_ring"));
}

static hxge_status_t
hxge_txdma_hw_start(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_tx_rings_t		tx_rings;
	p_tx_ring_t		*tx_desc_rings;
	p_tx_mbox_areas_t	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;
	hxge_status_t		status = HXGE_OK;
	uint64_t		tmp;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_hw_start"));

	/*
	 * Initialize REORD Table 1. Disable VMAC 2. Reset the FIFO Err Stat.
	 * 3. Scrub memory and check for errors.
	 */
	(void) hxge_tx_vmac_disable(hxgep);

	/*
	 * Clear the error status
	 */
	HXGE_REG_WR64(hxgep->hpi_handle, TDC_FIFO_ERR_STAT, 0x7);

	/*
	 * Scrub the rtab memory for the TDC and reset the TDC.
	 */
	HXGE_REG_WR64(hxgep->hpi_handle, TDC_REORD_TBL_DATA_HI, 0x0ULL);
	HXGE_REG_WR64(hxgep->hpi_handle, TDC_REORD_TBL_DATA_LO, 0x0ULL);

	for (i = 0; i < 256; i++) {
		HXGE_REG_WR64(hxgep->hpi_handle, TDC_REORD_TBL_CMD,
		    (uint64_t)i);

		/*
		 * Write the command register with an indirect read instruction
		 */
		tmp = (0x1ULL << 30) | i;
		HXGE_REG_WR64(hxgep->hpi_handle, TDC_REORD_TBL_CMD, tmp);

		/*
		 * Wait for status done
		 */
		tmp = 0;
		do {
			HXGE_REG_RD64(hxgep->hpi_handle, TDC_REORD_TBL_CMD,
			    &tmp);
		} while (((tmp >> 31) & 0x1ULL) == 0x0);
	}

	for (i = 0; i < 256; i++) {
		/*
		 * Write the command register with an indirect read instruction
		 */
		tmp = (0x1ULL << 30) | i;
		HXGE_REG_WR64(hxgep->hpi_handle, TDC_REORD_TBL_CMD, tmp);

		/*
		 * Wait for status done
		 */
		tmp = 0;
		do {
			HXGE_REG_RD64(hxgep->hpi_handle, TDC_REORD_TBL_CMD,
			    &tmp);
		} while (((tmp >> 31) & 0x1ULL) == 0x0);

		HXGE_REG_RD64(hxgep->hpi_handle, TDC_REORD_TBL_DATA_HI, &tmp);
		if (0x1ff00ULL != (0x1ffffULL & tmp)) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "PANIC ReordTbl "
			    "unexpected data (hi), entry: %x, value: 0x%0llx\n",
			    i, (unsigned long long)tmp));
			status = HXGE_ERROR;
		}

		HXGE_REG_RD64(hxgep->hpi_handle, TDC_REORD_TBL_DATA_LO, &tmp);
		if (tmp != 0) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "PANIC ReordTbl "
			    "unexpected data (lo), entry: %x\n", i));
			status = HXGE_ERROR;
		}

		HXGE_REG_RD64(hxgep->hpi_handle, TDC_FIFO_ERR_STAT, &tmp);
		if (tmp != 0) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "PANIC ReordTbl "
			    "parity error, entry: %x, val 0x%llx\n",
			    i, (unsigned long long)tmp));
			status = HXGE_ERROR;
		}

		HXGE_REG_RD64(hxgep->hpi_handle, TDC_FIFO_ERR_STAT, &tmp);
		if (tmp != 0) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "PANIC ReordTbl "
			    "parity error, entry: %x\n", i));
			status = HXGE_ERROR;
		}
	}

	if (status != HXGE_OK)
		goto hxge_txdma_hw_start_exit;

	/*
	 * Reset FIFO Error Status for the TDC and enable FIFO error events.
	 */
	HXGE_REG_WR64(hxgep->hpi_handle, TDC_FIFO_ERR_STAT, 0x7);
	HXGE_REG_WR64(hxgep->hpi_handle, TDC_FIFO_ERR_MASK, 0x0);

	/*
	 * Initialize the Transmit DMAs.
	 */
	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_start: NULL ring pointer"));
		return (HXGE_ERROR);
	}

	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_start: NULL ring pointers"));
		return (HXGE_ERROR);
	}
	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_start: no dma channel allocated"));
		return (HXGE_ERROR);
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_hw_start: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_desc_rings, ndmas));

	tx_mbox_areas_p = hxgep->tx_mbox_areas_p;
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	/*
	 * Init the DMAs.
	 */
	for (i = 0; i < ndmas; i++) {
		channel = tx_desc_rings[i]->tdc;
		status = hxge_txdma_start_channel(hxgep, channel,
		    (p_tx_ring_t)tx_desc_rings[i],
		    (p_tx_mbox_t)tx_mbox_p[i]);
		if (status != HXGE_OK) {
			goto hxge_txdma_hw_start_fail1;
		}
	}

	(void) hxge_tx_vmac_enable(hxgep);

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_txdma_hw_start: tx_rings $%p rings $%p",
	    hxgep->tx_rings, hxgep->tx_rings->rings));
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_txdma_hw_start: tx_rings $%p tx_desc_rings $%p",
	    hxgep->tx_rings, tx_desc_rings));

	goto hxge_txdma_hw_start_exit;

hxge_txdma_hw_start_fail1:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_txdma_hw_start: disable (status 0x%x channel %d i %d)",
	    status, channel, i));

	for (; i >= 0; i--) {
		channel = tx_desc_rings[i]->tdc,
		    (void) hxge_txdma_stop_channel(hxgep, channel,
		    (p_tx_ring_t)tx_desc_rings[i],
		    (p_tx_mbox_t)tx_mbox_p[i]);
	}

hxge_txdma_hw_start_exit:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_txdma_hw_start: (status 0x%x)", status));

	return (status);
}

static void
hxge_txdma_hw_stop(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_tx_rings_t		tx_rings;
	p_tx_ring_t		*tx_desc_rings;
	p_tx_mbox_areas_t	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_hw_stop"));

	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_stop: NULL ring pointer"));
		return;
	}

	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_stop: NULL ring pointers"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_hw_stop: no dma channel allocated"));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_hw_stop: "
	    "tx_rings $%p tx_desc_rings $%p", tx_rings, tx_desc_rings));

	tx_mbox_areas_p = hxgep->tx_mbox_areas_p;
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	for (i = 0; i < ndmas; i++) {
		channel = tx_desc_rings[i]->tdc;
		(void) hxge_txdma_stop_channel(hxgep, channel,
		    (p_tx_ring_t)tx_desc_rings[i],
		    (p_tx_mbox_t)tx_mbox_p[i]);
	}

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_hw_stop: "
	    "tx_rings $%p tx_desc_rings $%p", tx_rings, tx_desc_rings));
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_txdma_hw_stop"));
}

static hxge_status_t
hxge_txdma_start_channel(p_hxge_t hxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_txdma_start_channel (channel %d)", channel));
	/*
	 * TXDMA/TXC must be in stopped state.
	 */
	(void) hxge_txdma_stop_inj_err(hxgep, channel);

	/*
	 * Reset TXDMA channel
	 */
	tx_ring_p->tx_cs.value = 0;
	tx_ring_p->tx_cs.bits.reset = 1;
	status = hxge_reset_txdma_channel(hxgep, channel,
	    tx_ring_p->tx_cs.value);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_txdma_start_channel (channel %d)"
		    " reset channel failed 0x%x", channel, status));

		goto hxge_txdma_start_channel_exit;
	}

	/*
	 * Initialize the TXDMA channel specific FZC control configurations.
	 * These FZC registers are pertaining to each TX channel (i.e. logical
	 * pages).
	 */
	status = hxge_init_fzc_txdma_channel(hxgep, channel,
	    tx_ring_p, tx_mbox_p);
	if (status != HXGE_OK) {
		goto hxge_txdma_start_channel_exit;
	}

	/*
	 * Initialize the event masks.
	 */
	tx_ring_p->tx_evmask.value = 0;
	status = hxge_init_txdma_channel_event_mask(hxgep,
	    channel, &tx_ring_p->tx_evmask);
	if (status != HXGE_OK) {
		goto hxge_txdma_start_channel_exit;
	}

	/*
	 * Load TXDMA descriptors, buffers, mailbox, initialise the DMA
	 * channels and enable each DMA channel.
	 */
	status = hxge_enable_txdma_channel(hxgep, channel,
	    tx_ring_p, tx_mbox_p);
	if (status != HXGE_OK) {
		goto hxge_txdma_start_channel_exit;
	}

hxge_txdma_start_channel_exit:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_txdma_start_channel"));

	return (status);
}

/*ARGSUSED*/
static hxge_status_t
hxge_txdma_stop_channel(p_hxge_t hxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p)
{
	int status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
	    "==> hxge_txdma_stop_channel: channel %d", channel));

	/*
	 * Stop (disable) TXDMA and TXC (if stop bit is set and STOP_N_GO bit
	 * not set, the TXDMA reset state will not be set if reset TXDMA.
	 */
	(void) hxge_txdma_stop_inj_err(hxgep, channel);

	/*
	 * Reset TXDMA channel
	 */
	tx_ring_p->tx_cs.value = 0;
	tx_ring_p->tx_cs.bits.reset = 1;
	status = hxge_reset_txdma_channel(hxgep, channel,
	    tx_ring_p->tx_cs.value);
	if (status != HXGE_OK) {
		goto hxge_txdma_stop_channel_exit;
	}

hxge_txdma_stop_channel_exit:
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "<== hxge_txdma_stop_channel"));

	return (status);
}

static p_tx_ring_t
hxge_txdma_get_ring(p_hxge_t hxgep, uint16_t channel)
{
	int		index, ndmas;
	uint16_t	tdc;
	p_tx_rings_t	tx_rings;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_get_ring"));

	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_get_ring: NULL ring pointer"));
		return (NULL);
	}
	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_get_ring: no channel allocated"));
		return (NULL);
	}
	if (tx_rings->rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, TX_CTL,
		    "<== hxge_txdma_get_ring: NULL rings pointer"));
		return (NULL);
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_get_ring: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		tdc = tx_rings->rings[index]->tdc;
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "==> hxge_fixup_txdma_rings: channel %d", tdc));
		if (channel == tdc) {
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "<== hxge_txdma_get_ring: tdc %d ring $%p",
			    tdc, tx_rings->rings[index]));
			return (p_tx_ring_t)(tx_rings->rings[index]);
		}
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_get_ring"));

	return (NULL);
}

static p_tx_mbox_t
hxge_txdma_get_mbox(p_hxge_t hxgep, uint16_t channel)
{
	int			index, tdc, ndmas;
	p_tx_rings_t		tx_rings;
	p_tx_mbox_areas_t	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_get_mbox"));

	tx_rings = hxgep->tx_rings;
	if (tx_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_txdma_get_mbox: NULL ring pointer"));
		return (NULL);
	}
	tx_mbox_areas_p = hxgep->tx_mbox_areas_p;
	if (tx_mbox_areas_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_txdma_get_mbox: NULL mbox pointer"));
		return (NULL);
	}
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_txdma_get_mbox: no channel allocated"));
		return (NULL);
	}
	if (tx_rings->rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "<== hxge_txdma_get_mbox: NULL rings pointer"));
		return (NULL);
	}
	HXGE_DEBUG_MSG((hxgep, MEM3_CTL, "==> hxge_txdma_get_mbox: "
	    "tx_rings $%p tx_desc_rings $%p ndmas %d",
	    tx_rings, tx_rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		tdc = tx_rings->rings[index]->tdc;
		HXGE_DEBUG_MSG((hxgep, MEM3_CTL,
		    "==> hxge_txdma_get_mbox: channel %d", tdc));
		if (channel == tdc) {
			HXGE_DEBUG_MSG((hxgep, TX_CTL,
			    "<== hxge_txdma_get_mbox: tdc %d ring $%p",
			    tdc, tx_rings->rings[index]));
			return (p_tx_mbox_t)(tx_mbox_p[index]);
		}
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_get_mbox"));

	return (NULL);
}

/*ARGSUSED*/
static hxge_status_t
hxge_tx_err_evnts(p_hxge_t hxgep, uint_t index, p_hxge_ldv_t ldvp,
    tdc_stat_t cs)
{
	hpi_handle_t		handle;
	uint8_t			channel;
	p_tx_ring_t		*tx_rings;
	p_tx_ring_t		tx_ring_p;
	p_hxge_tx_ring_stats_t	tdc_stats;
	boolean_t		txchan_fatal = B_FALSE;
	hxge_status_t		status = HXGE_OK;
	tdc_drop_cnt_t		drop_cnt;

	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "==> hxge_tx_err_evnts"));
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	channel = ldvp->channel;

	tx_rings = hxgep->tx_rings->rings;
	tx_ring_p = tx_rings[index];
	tdc_stats = tx_ring_p->tdc_stats;

	/* Get the error counts if any */
	TXDMA_REG_READ64(handle, TDC_DROP_CNT, channel, &drop_cnt.value);
	tdc_stats->count_hdr_size_err += drop_cnt.bits.hdr_size_error_count;
	tdc_stats->count_runt += drop_cnt.bits.runt_count;
	tdc_stats->count_abort += drop_cnt.bits.abort_count;

	if (cs.bits.peu_resp_err) {
		tdc_stats->peu_resp_err++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_PEU_RESP_ERR);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: peu_resp_err", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.pkt_size_hdr_err) {
		tdc_stats->pkt_size_hdr_err++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_PKT_SIZE_HDR_ERR);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: pkt_size_hdr_err", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.runt_pkt_drop_err) {
		tdc_stats->runt_pkt_drop_err++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_RUNT_PKT_DROP_ERR);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: runt_pkt_drop_err", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.pkt_size_err) {
		tdc_stats->pkt_size_err++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: pkt_size_err", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.tx_rng_oflow) {
		tdc_stats->tx_rng_oflow++;
		if (tdc_stats->tx_rng_oflow)
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "==> hxge_tx_err_evnts(channel %d): "
			    "fatal error: tx_rng_oflow", channel));
	}

	if (cs.bits.pref_par_err) {
		tdc_stats->pref_par_err++;

		/* Get the address of parity error read data */
		TXDMA_REG_READ64(hxgep->hpi_handle, TDC_PREF_PAR_LOG,
		    channel, &tdc_stats->errlog.value);

		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_PREF_PAR_ERR);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: pref_par_err", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.tdr_pref_cpl_to) {
		tdc_stats->tdr_pref_cpl_to++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_TDR_PREF_CPL_TO);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: tdr_pref_cpl_to", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.pkt_cpl_to) {
		tdc_stats->pkt_cpl_to++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_PKT_CPL_TO);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: pkt_cpl_to", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.invalid_sop) {
		tdc_stats->invalid_sop++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_INVALID_SOP);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: invalid_sop", channel));
		txchan_fatal = B_TRUE;
	}

	if (cs.bits.unexpected_sop) {
		tdc_stats->unexpected_sop++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_TDMC_UNEXPECTED_SOP);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_tx_err_evnts(channel %d): "
		    "fatal error: unexpected_sop", channel));
		txchan_fatal = B_TRUE;
	}

	/* Clear error injection source in case this is an injected error */
	TXDMA_REG_WRITE64(hxgep->hpi_handle, TDC_STAT_INT_DBG, channel, 0);

	if (txchan_fatal) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_tx_err_evnts: "
		    " fatal error on channel %d cs 0x%llx\n",
		    channel, cs.value));
		status = hxge_txdma_fatal_err_recover(hxgep, channel,
		    tx_ring_p);
		if (status == HXGE_OK) {
			FM_SERVICE_RESTORED(hxgep);
		}
	}

	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "<== hxge_tx_err_evnts"));

	return (status);
}

hxge_status_t
hxge_txdma_handle_sys_errors(p_hxge_t hxgep)
{
	hpi_handle_t		handle;
	hxge_status_t		status = HXGE_OK;
	tdc_fifo_err_stat_t	fifo_stat;
	hxge_tdc_sys_stats_t	*tdc_sys_stats;

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "==> hxge_txdma_handle_sys_errors"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/*
	 * The FIFO is shared by all channels.
	 * Get the status of Reorder Buffer and Reorder Table Buffer Errors
	 */
	HXGE_REG_RD64(handle, TDC_FIFO_ERR_STAT, &fifo_stat.value);

	/*
	 * Clear the error bits. Note that writing a 1 clears the bit. Writing
	 * a 0 does nothing.
	 */
	HXGE_REG_WR64(handle, TDC_FIFO_ERR_STAT, fifo_stat.value);

	tdc_sys_stats = &hxgep->statsp->tdc_sys_stats;
	if (fifo_stat.bits.reord_tbl_par_err) {
		tdc_sys_stats->reord_tbl_par_err++;
		HXGE_FM_REPORT_ERROR(hxgep, NULL,
		    HXGE_FM_EREPORT_TDMC_REORD_TBL_PAR);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_txdma_handle_sys_errors: fatal error: "
		    "reord_tbl_par_err"));
	}

	if (fifo_stat.bits.reord_buf_ded_err) {
		tdc_sys_stats->reord_buf_ded_err++;
		HXGE_FM_REPORT_ERROR(hxgep, NULL,
		    HXGE_FM_EREPORT_TDMC_REORD_BUF_DED);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_txdma_handle_sys_errors: "
		    "fatal error: reord_buf_ded_err"));
	}

	if (fifo_stat.bits.reord_buf_sec_err) {
		tdc_sys_stats->reord_buf_sec_err++;
		if (tdc_sys_stats->reord_buf_sec_err == 1)
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "==> hxge_txdma_handle_sys_errors: "
			    "reord_buf_sec_err"));
	}

	if (fifo_stat.bits.reord_tbl_par_err ||
	    fifo_stat.bits.reord_buf_ded_err) {
		status = hxge_tx_port_fatal_err_recover(hxgep);
		if (status == HXGE_OK) {
			FM_SERVICE_RESTORED(hxgep);
		}
	}

	HXGE_DEBUG_MSG((hxgep, TX_CTL, "<== hxge_txdma_handle_sys_errors"));

	return (status);
}

static hxge_status_t
hxge_txdma_fatal_err_recover(p_hxge_t hxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p)
{
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;
	p_tx_mbox_t	tx_mbox_p;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "==> hxge_txdma_fatal_err_recover"));
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "Recovering from TxDMAChannel#%d error...", channel));

	/*
	 * Stop the dma channel waits for the stop done. If the stop done bit
	 * is not set, then create an error.
	 */
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "stopping txdma channel(%d)",
	    channel));
	MUTEX_ENTER(&tx_ring_p->lock);
	rs = hpi_txdma_channel_control(handle, TXDMA_STOP, channel);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_txdma_fatal_err_recover (channel %d): "
		    "stop failed ", channel));

		goto fail;
	}
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "reclaiming txdma channel(%d)",
	    channel));
	(void) hxge_txdma_reclaim(hxgep, tx_ring_p, 0);

	/*
	 * Reset TXDMA channel
	 */
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "resetting txdma channel(%d)",
	    channel));
	if ((rs = hpi_txdma_channel_control(handle, TXDMA_RESET, channel)) !=
	    HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_txdma_fatal_err_recover (channel %d)"
		    " reset channel failed 0x%x", channel, rs));

		goto fail;
	}
	/*
	 * Reset the tail (kick) register to 0. (Hardware will not reset it. Tx
	 * overflow fatal error if tail is not set to 0 after reset!
	 */
	TXDMA_REG_WRITE64(handle, TDC_TDR_KICK, channel, 0);

	/*
	 * Restart TXDMA channel
	 *
	 * Initialize the TXDMA channel specific FZC control configurations.
	 * These FZC registers are pertaining to each TX channel (i.e. logical
	 * pages).
	 */
	tx_mbox_p = hxge_txdma_get_mbox(hxgep, channel);
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "restarting txdma channel(%d)",
	    channel));
	status = hxge_init_fzc_txdma_channel(hxgep, channel,
	    tx_ring_p, tx_mbox_p);
	if (status != HXGE_OK)
		goto fail;

	/*
	 * Initialize the event masks.
	 */
	tx_ring_p->tx_evmask.value = 0;
	status = hxge_init_txdma_channel_event_mask(hxgep, channel,
	    &tx_ring_p->tx_evmask);
	if (status != HXGE_OK)
		goto fail;

	tx_ring_p->wr_index_wrap = B_FALSE;
	tx_ring_p->wr_index = 0;
	tx_ring_p->rd_index = 0;

	/*
	 * Load TXDMA descriptors, buffers, mailbox, initialise the DMA
	 * channels and enable each DMA channel.
	 */
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "enabling txdma channel(%d)",
	    channel));
	status = hxge_enable_txdma_channel(hxgep, channel,
	    tx_ring_p, tx_mbox_p);
	MUTEX_EXIT(&tx_ring_p->lock);
	if (status != HXGE_OK)
		goto fail;

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "Recovery Successful, TxDMAChannel#%d Restored", channel));
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "==> hxge_txdma_fatal_err_recover"));

	return (HXGE_OK);

fail:
	MUTEX_EXIT(&tx_ring_p->lock);
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL,
	    "hxge_txdma_fatal_err_recover (channel %d): "
	    "failed to recover this txdma channel", channel));
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "Recovery failed"));

	return (status);
}

static hxge_status_t
hxge_tx_port_fatal_err_recover(p_hxge_t hxgep)
{
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;
	hxge_status_t	status = HXGE_OK;
	p_tx_ring_t	*tx_desc_rings;
	p_tx_rings_t	tx_rings;
	p_tx_ring_t	tx_ring_p;
	int		i, ndmas;
	uint16_t	channel;
	block_reset_t	reset_reg;

	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL,
	    "==> hxge_tx_port_fatal_err_recover"));
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "Recovering from TxPort error..."));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/* Reset TDC block from PEU for this fatal error */
	reset_reg.value = 0;
	reset_reg.bits.tdc_rst = 1;
	HXGE_REG_WR32(handle, BLOCK_RESET, reset_reg.value);

	HXGE_DELAY(1000);

	/*
	 * Stop the dma channel waits for the stop done. If the stop done bit
	 * is not set, then create an error.
	 */
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "stopping all DMA channels..."));

	tx_rings = hxgep->tx_rings;
	tx_desc_rings = tx_rings->rings;
	ndmas = tx_rings->ndmas;

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		tx_ring_p = tx_rings->rings[i];
		MUTEX_ENTER(&tx_ring_p->lock);
	}

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		channel = tx_desc_rings[i]->tdc;
		tx_ring_p = tx_rings->rings[i];
		rs = hpi_txdma_channel_control(handle, TXDMA_STOP, channel);
		if (rs != HPI_SUCCESS) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "==> hxge_txdma_fatal_err_recover (channel %d): "
			    "stop failed ", channel));

			goto fail;
		}
	}

	/*
	 * Do reclaim on all of th DMAs.
	 */
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL, "reclaiming all DMA channels..."));
	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		tx_ring_p = tx_rings->rings[i];
		(void) hxge_txdma_reclaim(hxgep, tx_ring_p, 0);
	}

	/* Restart the TDC */
	if ((status = hxge_txdma_hw_start(hxgep)) != HXGE_OK)
		goto fail;

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		tx_ring_p = tx_rings->rings[i];
		MUTEX_EXIT(&tx_ring_p->lock);
	}

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "Recovery Successful, TxPort Restored"));
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL,
	    "<== hxge_tx_port_fatal_err_recover"));
	return (HXGE_OK);

fail:
	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		tx_ring_p = tx_rings->rings[i];
		MUTEX_EXIT(&tx_ring_p->lock);
	}

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "Recovery failed"));
	HXGE_DEBUG_MSG((hxgep, TX_ERR_CTL,
	    "hxge_txdma_fatal_err_recover (channel %d): "
	    "failed to recover this txdma channel"));

	return (status);
}
