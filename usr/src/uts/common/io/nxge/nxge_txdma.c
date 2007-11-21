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
#include <sys/nxge/nxge_txdma.h>
#include <sys/llc1.h>

uint32_t 	nxge_reclaim_pending = TXDMA_RECLAIM_PENDING_DEFAULT;
uint32_t	nxge_tx_minfree = 32;
uint32_t	nxge_tx_intr_thres = 0;
uint32_t	nxge_tx_max_gathers = TX_MAX_GATHER_POINTERS;
uint32_t	nxge_tx_tiny_pack = 1;
uint32_t	nxge_tx_use_bcopy = 1;

extern uint32_t 	nxge_tx_ring_size;
extern uint32_t 	nxge_bcopy_thresh;
extern uint32_t 	nxge_dvma_thresh;
extern uint32_t 	nxge_dma_stream_thresh;
extern dma_method_t 	nxge_force_dma;

/* Device register access attributes for PIO.  */
extern ddi_device_acc_attr_t nxge_dev_reg_acc_attr;
/* Device descriptor access attributes for DMA.  */
extern ddi_device_acc_attr_t nxge_dev_desc_dma_acc_attr;
/* Device buffer access attributes for DMA.  */
extern ddi_device_acc_attr_t nxge_dev_buf_dma_acc_attr;
extern ddi_dma_attr_t nxge_desc_dma_attr;
extern ddi_dma_attr_t nxge_tx_dma_attr;

extern int nxge_serial_tx(mblk_t *mp, void *arg);

static nxge_status_t nxge_map_txdma(p_nxge_t);
static void nxge_unmap_txdma(p_nxge_t);

static nxge_status_t nxge_txdma_hw_start(p_nxge_t);
static void nxge_txdma_hw_stop(p_nxge_t);

static nxge_status_t nxge_map_txdma_channel(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *, p_tx_ring_t *,
	uint32_t, p_nxge_dma_common_t *,
	p_tx_mbox_t *);
static void nxge_unmap_txdma_channel(p_nxge_t, uint16_t,
	p_tx_ring_t, p_tx_mbox_t);

static nxge_status_t nxge_map_txdma_channel_buf_ring(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *, p_tx_ring_t *, uint32_t);
static void nxge_unmap_txdma_channel_buf_ring(p_nxge_t, p_tx_ring_t);

static void nxge_map_txdma_channel_cfg_ring(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *, p_tx_ring_t,
	p_tx_mbox_t *);
static void nxge_unmap_txdma_channel_cfg_ring(p_nxge_t,
	p_tx_ring_t, p_tx_mbox_t);

static nxge_status_t nxge_txdma_start_channel(p_nxge_t, uint16_t,
    p_tx_ring_t, p_tx_mbox_t);
static nxge_status_t nxge_txdma_stop_channel(p_nxge_t, uint16_t,
	p_tx_ring_t, p_tx_mbox_t);

static p_tx_ring_t nxge_txdma_get_ring(p_nxge_t, uint16_t);
static nxge_status_t nxge_tx_err_evnts(p_nxge_t, uint_t,
	p_nxge_ldv_t, tx_cs_t);
static p_tx_mbox_t nxge_txdma_get_mbox(p_nxge_t, uint16_t);
static nxge_status_t nxge_txdma_fatal_err_recover(p_nxge_t,
	uint16_t, p_tx_ring_t);

nxge_status_t
nxge_init_txdma_channels(p_nxge_t nxgep)
{
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_init_txdma_channels"));

	status = nxge_map_txdma(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"<== nxge_init_txdma_channels: status 0x%x", status));
		return (status);
	}

	status = nxge_txdma_hw_start(nxgep);
	if (status != NXGE_OK) {
		nxge_unmap_txdma(nxgep);
		return (status);
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_init_txdma_channels: status 0x%x", status));

	return (NXGE_OK);
}

void
nxge_uninit_txdma_channels(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_uninit_txdma_channels"));

	nxge_txdma_hw_stop(nxgep);
	nxge_unmap_txdma(nxgep);

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_uinit_txdma_channels"));
}

void
nxge_setup_dma_common(p_nxge_dma_common_t dest_p, p_nxge_dma_common_t src_p,
	uint32_t entries, uint32_t size)
{
	size_t		tsize;
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

nxge_status_t
nxge_reset_txdma_channel(p_nxge_t nxgep, uint16_t channel, uint64_t reg_data)
{
	npi_status_t		rs = NPI_SUCCESS;
	nxge_status_t		status = NXGE_OK;
	npi_handle_t		handle;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, " ==> nxge_reset_txdma_channel"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if ((reg_data & TX_CS_RST_MASK) == TX_CS_RST_MASK) {
		rs = npi_txdma_channel_reset(handle, channel);
	} else {
		rs = npi_txdma_channel_control(handle, TXDMA_RESET,
				channel);
	}

	if (rs != NPI_SUCCESS) {
		status = NXGE_ERROR | rs;
	}

	/*
	 * Reset the tail (kick) register to 0.
	 * (Hardware will not reset it. Tx overflow fatal
	 * error if tail is not set to 0 after reset!
	 */
	TXDMA_REG_WRITE64(handle, TX_RING_KICK_REG, channel, 0);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, " <== nxge_reset_txdma_channel"));
	return (status);
}

nxge_status_t
nxge_init_txdma_channel_event_mask(p_nxge_t nxgep, uint16_t channel,
		p_tx_dma_ent_msk_t mask_p)
{
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_init_txdma_channel_event_mask"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	rs = npi_txdma_event_mask(handle, OP_SET, channel, mask_p);
	if (rs != NPI_SUCCESS) {
		status = NXGE_ERROR | rs;
	}

	return (status);
}

nxge_status_t
nxge_init_txdma_channel_cntl_stat(p_nxge_t nxgep, uint16_t channel,
	uint64_t reg_data)
{
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_init_txdma_channel_cntl_stat"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	rs = npi_txdma_control_status(handle, OP_SET, channel,
			(p_tx_cs_t)&reg_data);

	if (rs != NPI_SUCCESS) {
		status = NXGE_ERROR | rs;
	}

	return (status);
}

nxge_status_t
nxge_enable_txdma_channel(p_nxge_t nxgep,
	uint16_t channel, p_tx_ring_t tx_desc_p, p_tx_mbox_t mbox_p)
{
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_enable_txdma_channel"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/*
	 * Use configuration data composed at init time.
	 * Write to hardware the transmit ring configurations.
	 */
	rs = npi_txdma_ring_config(handle, OP_SET, channel,
			(uint64_t *)&(tx_desc_p->tx_ring_cfig.value));

	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	/* Write to hardware the mailbox */
	rs = npi_txdma_mbox_config(handle, OP_SET, channel,
		(uint64_t *)&mbox_p->tx_mbox.dma_cookie.dmac_laddress);

	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	/* Start the DMA engine. */
	rs = npi_txdma_channel_init_enable(handle, channel);

	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_enable_txdma_channel"));

	return (status);
}

void
nxge_fill_tx_hdr(p_mblk_t mp, boolean_t fill_len,
		boolean_t l4_cksum, int pkt_len, uint8_t npads,
		p_tx_pkt_hdr_all_t pkthdrp)
{
	p_tx_pkt_header_t	hdrp;
	p_mblk_t 		nmp;
	uint64_t		tmp;
	size_t 			mblk_len;
	size_t 			iph_len;
	size_t 			hdrs_size;
	uint8_t			hdrs_buf[sizeof (struct ether_header) +
					64 + sizeof (uint32_t)];
	uint8_t			*cursor;
	uint8_t 		*ip_buf;
	uint16_t		eth_type;
	uint8_t			ipproto;
	boolean_t		is_vlan = B_FALSE;
	size_t			eth_hdr_size;

	NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_fill_tx_hdr: mp $%p", mp));

	/*
	 * Caller should zero out the headers first.
	 */
	hdrp = (p_tx_pkt_header_t)&pkthdrp->pkthdr;

	if (fill_len) {
		NXGE_DEBUG_MSG((NULL, TX_CTL,
			"==> nxge_fill_tx_hdr: pkt_len %d "
			"npads %d", pkt_len, npads));
		tmp = (uint64_t)pkt_len;
		hdrp->value |= (tmp << TX_PKT_HEADER_TOT_XFER_LEN_SHIFT);
		goto fill_tx_header_done;
	}

	tmp = (uint64_t)npads;
	hdrp->value |= (tmp << TX_PKT_HEADER_PAD_SHIFT);

	/*
	 * mp is the original data packet (does not include the
	 * Neptune transmit header).
	 */
	nmp = mp;
	NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_fill_tx_hdr: "
		"mp $%p b_rptr $%p len %d",
		mp, nmp->b_rptr, MBLKL(nmp)));
	/* copy ether_header from mblk to hdrs_buf */
	cursor = &hdrs_buf[0];
	tmp = sizeof (struct ether_vlan_header);
	while ((nmp != NULL) && (tmp > 0)) {
		size_t buflen;
		mblk_len = MBLKL(nmp);
		buflen = min((size_t)tmp, mblk_len);
		bcopy(nmp->b_rptr, cursor, buflen);
		cursor += buflen;
		tmp -= buflen;
		nmp = nmp->b_cont;
	}

	nmp = mp;
	mblk_len = MBLKL(nmp);
	ip_buf = NULL;
	eth_type = ntohs(((p_ether_header_t)hdrs_buf)->ether_type);
	NXGE_DEBUG_MSG((NULL, TX_CTL, "==> : nxge_fill_tx_hdr: (value 0x%llx) "
		"ether type 0x%x", eth_type, hdrp->value));

	if (eth_type < ETHERMTU) {
		tmp = 1ull;
		hdrp->value |= (tmp << TX_PKT_HEADER_LLC_SHIFT);
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_hdr_init: LLC "
			"value 0x%llx", hdrp->value));
		if (*(hdrs_buf + sizeof (struct ether_header))
				== LLC_SNAP_SAP) {
			eth_type = ntohs(*((uint16_t *)(hdrs_buf +
					sizeof (struct ether_header) + 6)));
			NXGE_DEBUG_MSG((NULL, TX_CTL,
				"==> nxge_tx_pkt_hdr_init: LLC ether type 0x%x",
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
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_hdr_init: VLAN "
			"value 0x%llx", hdrp->value));
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
			while ((nmp) && (hdrs_size <
					sizeof (hdrs_buf))) {
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

		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_fill_tx_hdr: IPv4 "
			" iph_len %d l3start %d eth_hdr_size %d proto 0x%x"
			"tmp 0x%x",
			iph_len, hdrp->bits.hdw.l3start, eth_hdr_size,
			ipproto, tmp));
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_hdr_init: IP "
			"value 0x%llx", hdrp->value));

		break;

	case ETHERTYPE_IPV6:
		hdrs_size = 0;
		((p_ether_header_t)hdrs_buf)->ether_type = 0;
		while ((nmp) && (hdrs_size <
				sizeof (hdrs_buf))) {
			mblk_len = (size_t)nmp->b_wptr - (size_t)nmp->b_rptr;
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

		tmp = 1ull;
		hdrp->value |= (tmp << TX_PKT_HEADER_IP_VER_SHIFT);

		tmp = (eth_hdr_size >> 1);
		hdrp->value |= (tmp << TX_PKT_HEADER_L3START_SHIFT);

		/* byte 6 is the next header protocol */
		ipproto = ip_buf[6];

		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_fill_tx_hdr: IPv6 "
			" iph_len %d l3start %d eth_hdr_size %d proto 0x%x",
			iph_len, hdrp->bits.hdw.l3start, eth_hdr_size,
			ipproto));
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_hdr_init: IPv6 "
			"value 0x%llx", hdrp->value));

		break;

	default:
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_fill_tx_hdr: non-IP"));
		goto fill_tx_header_done;
	}

	switch (ipproto) {
	case IPPROTO_TCP:
		NXGE_DEBUG_MSG((NULL, TX_CTL,
			"==> nxge_fill_tx_hdr: TCP (cksum flag %d)", l4_cksum));
		if (l4_cksum) {
			tmp = 1ull;
			hdrp->value |= (tmp << TX_PKT_HEADER_PKT_TYPE_SHIFT);
			NXGE_DEBUG_MSG((NULL, TX_CTL,
				"==> nxge_tx_pkt_hdr_init: TCP CKSUM"
				"value 0x%llx", hdrp->value));
		}

		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_hdr_init: TCP "
			"value 0x%llx", hdrp->value));
		break;

	case IPPROTO_UDP:
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_fill_tx_hdr: UDP"));
		if (l4_cksum) {
			tmp = 0x2ull;
			hdrp->value |= (tmp << TX_PKT_HEADER_PKT_TYPE_SHIFT);
		}
		NXGE_DEBUG_MSG((NULL, TX_CTL,
			"==> nxge_tx_pkt_hdr_init: UDP"
			"value 0x%llx", hdrp->value));
		break;

	default:
		goto fill_tx_header_done;
	}

fill_tx_header_done:
	NXGE_DEBUG_MSG((NULL, TX_CTL,
		"==> nxge_fill_tx_hdr: pkt_len %d  "
		"npads %d value 0x%llx", pkt_len, npads, hdrp->value));

	NXGE_DEBUG_MSG((NULL, TX_CTL, "<== nxge_fill_tx_hdr"));
}

/*ARGSUSED*/
p_mblk_t
nxge_tx_pkt_header_reserve(p_mblk_t mp, uint8_t *npads)
{
	p_mblk_t 		newmp = NULL;

	if ((newmp = allocb(TX_PKT_HEADER_SIZE, BPRI_MED)) == NULL) {
		NXGE_DEBUG_MSG((NULL, TX_CTL,
			"<== nxge_tx_pkt_header_reserve: allocb failed"));
		return (NULL);
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL,
		"==> nxge_tx_pkt_header_reserve: get new mp"));
	DB_TYPE(newmp) = M_DATA;
	newmp->b_rptr = newmp->b_wptr = DB_LIM(newmp);
	linkb(newmp, mp);
	newmp->b_rptr -= TX_PKT_HEADER_SIZE;

	NXGE_DEBUG_MSG((NULL, TX_CTL, "==>nxge_tx_pkt_header_reserve: "
		"b_rptr $%p b_wptr $%p",
		newmp->b_rptr, newmp->b_wptr));

	NXGE_DEBUG_MSG((NULL, TX_CTL,
		"<== nxge_tx_pkt_header_reserve: use new mp"));

	return (newmp);
}

int
nxge_tx_pkt_nmblocks(p_mblk_t mp, int *tot_xfer_len_p)
{
	uint_t 			nmblks;
	ssize_t			len;
	uint_t 			pkt_len;
	p_mblk_t 		nmp, bmp, tmp;
	uint8_t 		*b_wptr;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
		"==> nxge_tx_pkt_nmblocks: mp $%p rptr $%p wptr $%p "
		"len %d", mp, mp->b_rptr, mp->b_wptr, MBLKL(mp)));

	nmp = mp;
	bmp = mp;
	nmblks = 0;
	pkt_len = 0;
	*tot_xfer_len_p = 0;

	while (nmp) {
		len = MBLKL(nmp);
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_nmblocks: "
			"len %d pkt_len %d nmblks %d tot_xfer_len %d",
			len, pkt_len, nmblks,
			*tot_xfer_len_p));

		if (len <= 0) {
			bmp = nmp;
			nmp = nmp->b_cont;
			NXGE_DEBUG_MSG((NULL, TX_CTL,
				"==> nxge_tx_pkt_nmblocks: "
				"len (0) pkt_len %d nmblks %d",
				pkt_len, nmblks));
			continue;
		}

		*tot_xfer_len_p += len;
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_nmblocks: "
			"len %d pkt_len %d nmblks %d tot_xfer_len %d",
			len, pkt_len, nmblks,
			*tot_xfer_len_p));

		if (len < nxge_bcopy_thresh) {
			NXGE_DEBUG_MSG((NULL, TX_CTL,
				"==> nxge_tx_pkt_nmblocks: "
				"len %d (< thresh) pkt_len %d nmblks %d",
				len, pkt_len, nmblks));
			if (pkt_len == 0)
				nmblks++;
			pkt_len += len;
			if (pkt_len >= nxge_bcopy_thresh) {
				pkt_len = 0;
				len = 0;
				nmp = bmp;
			}
		} else {
			NXGE_DEBUG_MSG((NULL, TX_CTL,
				"==> nxge_tx_pkt_nmblocks: "
				"len %d (> thresh) pkt_len %d nmblks %d",
				len, pkt_len, nmblks));
			pkt_len = 0;
			nmblks++;
			/*
			 * Hardware limits the transfer length to 4K.
			 * If len is more than 4K, we need to break
			 * it up to at most 2 more blocks.
			 */
			if (len > TX_MAX_TRANSFER_LENGTH) {
				uint32_t	nsegs;

				NXGE_DEBUG_MSG((NULL, TX_CTL,
					"==> nxge_tx_pkt_nmblocks: "
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
			NXGE_DEBUG_MSG((NULL, TX_CTL,
				"==> nxge_tx_pkt_nmblocks: pull msg - "
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

	NXGE_DEBUG_MSG((NULL, TX_CTL,
		"<== nxge_tx_pkt_nmblocks: rptr $%p wptr $%p "
		"nmblks %d len %d tot_xfer_len %d",
		mp->b_rptr, mp->b_wptr, nmblks,
		MBLKL(mp), *tot_xfer_len_p));

	return (nmblks);
}

boolean_t
nxge_txdma_reclaim(p_nxge_t nxgep, p_tx_ring_t tx_ring_p, int nmblks)
{
	boolean_t 		status = B_TRUE;
	p_nxge_dma_common_t	tx_desc_dma_p;
	nxge_dma_common_t	desc_area;
	p_tx_desc_t 		tx_desc_ring_vp;
	p_tx_desc_t 		tx_desc_p;
	p_tx_desc_t 		tx_desc_pp;
	tx_desc_t 		r_tx_desc;
	p_tx_msg_t 		tx_msg_ring;
	p_tx_msg_t 		tx_msg_p;
	npi_handle_t		handle;
	tx_ring_hdl_t		tx_head;
	uint32_t 		pkt_len;
	uint_t			tx_rd_index;
	uint16_t		head_index, tail_index;
	uint8_t			tdc;
	boolean_t		head_wrap, tail_wrap;
	p_nxge_tx_ring_stats_t tdc_stats;
	int			rc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_reclaim"));

	status = ((tx_ring_p->descs_pending < nxge_reclaim_pending) &&
			(nmblks != 0));
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"==> nxge_txdma_reclaim: pending %d  reclaim %d nmblks %d",
			tx_ring_p->descs_pending, nxge_reclaim_pending,
			nmblks));
	if (!status) {
		tx_desc_dma_p = &tx_ring_p->tdc_desc;
		desc_area = tx_ring_p->tdc_desc;
		handle = NXGE_DEV_NPI_HANDLE(nxgep);
		tx_desc_ring_vp = tx_desc_dma_p->kaddrp;
		tx_desc_ring_vp =
			(p_tx_desc_t)DMA_COMMON_VPTR(desc_area);
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

		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_reclaim: tdc %d tx_rd_index %d "
			"tail_index %d tail_wrap %d "
			"tx_desc_p $%p ($%p) ",
			tdc, tx_rd_index, tail_index, tail_wrap,
			tx_desc_p, (*(uint64_t *)tx_desc_p)));
		/*
		 * Read the hardware maintained transmit head
		 * and wrap around bit.
		 */
		TXDMA_REG_READ64(handle, TX_RING_HDL_REG, tdc, &tx_head.value);
		head_index =  tx_head.bits.ldw.head;
		head_wrap = tx_head.bits.ldw.wrap;
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_reclaim: "
			"tx_rd_index %d tail %d tail_wrap %d "
			"head %d wrap %d",
			tx_rd_index, tail_index, tail_wrap,
			head_index, head_wrap));

		if (head_index == tail_index) {
			if (TXDMA_RING_EMPTY(head_index, head_wrap,
					tail_index, tail_wrap) &&
					(head_index == tx_rd_index)) {
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
					"==> nxge_txdma_reclaim: EMPTY"));
				return (B_TRUE);
			}

			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: Checking "
					"if ring full"));
			if (TXDMA_RING_FULL(head_index, head_wrap, tail_index,
					tail_wrap)) {
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
					"==> nxge_txdma_reclaim: full"));
				return (B_FALSE);
			}
		}

		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_reclaim: tx_rd_index and head_index"));

		tx_desc_pp = &r_tx_desc;
		while ((tx_rd_index != head_index) &&
			(tx_ring_p->descs_pending != 0)) {

			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: Checking if pending"));

			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: "
				"descs_pending %d ",
				tx_ring_p->descs_pending));

			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: "
				"(tx_rd_index %d head_index %d "
				"(tx_desc_p $%p)",
				tx_rd_index, head_index,
				tx_desc_p));

			tx_desc_pp->value = tx_desc_p->value;
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: "
				"(tx_rd_index %d head_index %d "
				"tx_desc_p $%p (desc value 0x%llx) ",
				tx_rd_index, head_index,
				tx_desc_pp, (*(uint64_t *)tx_desc_pp)));

			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: dump desc:"));

			pkt_len = tx_desc_pp->bits.hdw.tr_len;
			tdc_stats->obytes += pkt_len;
			tdc_stats->opackets += tx_desc_pp->bits.hdw.sop;
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: pkt_len %d "
				"tdc channel %d opackets %d",
				pkt_len,
				tdc,
				tdc_stats->opackets));

			if (tx_msg_p->flags.dma_type == USE_DVMA) {
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
					"tx_desc_p = $%p "
					"tx_desc_pp = $%p "
					"index = %d",
					tx_desc_p,
					tx_desc_pp,
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
			} else if (tx_msg_p->flags.dma_type ==
					USE_DMA) {
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
					"==> nxge_txdma_reclaim: "
					"USE DMA"));
				if (rc = ddi_dma_unbind_handle
					(tx_msg_p->dma_handle)) {
					cmn_err(CE_WARN, "!nxge_reclaim: "
						"ddi_dma_unbind_handle "
						"failed. status %d", rc);
				}
			}
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"==> nxge_txdma_reclaim: count packets"));
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

		status = (nmblks <= (tx_ring_p->tx_ring_size -
				tx_ring_p->descs_pending -
				TX_FULL_MARK));
		if (status) {
			cas32((uint32_t *)&tx_ring_p->queueing, 1, 0);
		}
	} else {
		status = (nmblks <=
			(tx_ring_p->tx_ring_size -
				tx_ring_p->descs_pending -
				TX_FULL_MARK));
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"<== nxge_txdma_reclaim status = 0x%08x", status));

	return (status);
}

uint_t
nxge_tx_intr(void *arg1, void *arg2)
{
	p_nxge_ldv_t		ldvp = (p_nxge_ldv_t)arg1;
	p_nxge_t		nxgep = (p_nxge_t)arg2;
	p_nxge_ldg_t		ldgp;
	uint8_t			channel;
	uint32_t		vindex;
	npi_handle_t		handle;
	tx_cs_t			cs;
	p_tx_ring_t 		*tx_rings;
	p_tx_ring_t 		tx_ring_p;
	npi_status_t		rs = NPI_SUCCESS;
	uint_t 			serviced = DDI_INTR_UNCLAIMED;
	nxge_status_t 		status = NXGE_OK;

	if (ldvp == NULL) {
		NXGE_DEBUG_MSG((NULL, INT_CTL,
			"<== nxge_tx_intr: nxgep $%p ldvp $%p",
			nxgep, ldvp));
		return (DDI_INTR_UNCLAIMED);
	}

	if (arg2 == NULL || (void *)ldvp->nxgep != arg2) {
		nxgep = ldvp->nxgep;
	}
	NXGE_DEBUG_MSG((nxgep, INT_CTL,
		"==> nxge_tx_intr: nxgep(arg2) $%p ldvp(arg1) $%p",
		nxgep, ldvp));
	/*
	 * This interrupt handler is for a specific
	 * transmit dma channel.
	 */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/* Get the control and status for this channel. */
	channel = ldvp->channel;
	ldgp = ldvp->ldgp;
	NXGE_DEBUG_MSG((nxgep, INT_CTL,
		"==> nxge_tx_intr: nxgep $%p ldvp (ldvp) $%p "
		"channel %d",
		nxgep, ldvp, channel));

	rs = npi_txdma_control_status(handle, OP_GET, channel, &cs);
	vindex = ldvp->vdma_index;
	NXGE_DEBUG_MSG((nxgep, INT_CTL,
		"==> nxge_tx_intr:channel %d ring index %d status 0x%08x",
		channel, vindex, rs));
	if (!rs && cs.bits.ldw.mk) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"==> nxge_tx_intr:channel %d ring index %d "
			"status 0x%08x (mk bit set)",
			channel, vindex, rs));
		tx_rings = nxgep->tx_rings->rings;
		tx_ring_p = tx_rings[vindex];
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"==> nxge_tx_intr:channel %d ring index %d "
			"status 0x%08x (mk bit set, calling reclaim)",
			channel, vindex, rs));

		MUTEX_ENTER(&tx_ring_p->lock);
		(void) nxge_txdma_reclaim(nxgep, tx_rings[vindex], 0);
		MUTEX_EXIT(&tx_ring_p->lock);
		mac_tx_update(nxgep->mach);
	}

	/*
	 * Process other transmit control and status.
	 * Check the ldv state.
	 */
	status = nxge_tx_err_evnts(nxgep, ldvp->vdma_index, ldvp, cs);
	/*
	 * Rearm this logical group if this is a single device
	 * group.
	 */
	if (ldgp->nldvs == 1) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
			"==> nxge_tx_intr: rearm"));
		if (status == NXGE_OK) {
			(void) npi_intr_ldg_mgmt_set(handle, ldgp->ldg,
				B_TRUE, ldgp->ldg_timer);
		}
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_tx_intr"));
	serviced = DDI_INTR_CLAIMED;
	return (serviced);
}

void
nxge_txdma_stop(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_stop"));

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_STOP);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_stop"));
}

void
nxge_txdma_stop_start(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_stop_start"));

	(void) nxge_txdma_stop(nxgep);

	(void) nxge_fixup_txdma_rings(nxgep);
	(void) nxge_txdma_hw_mode(nxgep, NXGE_DMA_START);
	(void) nxge_tx_mac_enable(nxgep);
	(void) nxge_txdma_hw_kick(nxgep);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_stop_start"));
}

nxge_status_t
nxge_txdma_hw_mode(p_nxge_t nxgep, boolean_t enable)
{
	int			i, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;
	p_tx_ring_t 		*tx_desc_rings;
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_txdma_hw_mode: enable mode %d", enable));

	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_mode: not initialized"));
		return (NXGE_ERROR);
	}

	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_mode: NULL global ring pointer"));
		return (NXGE_ERROR);
	}

	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_mode: NULL rings pointer"));
		return (NXGE_ERROR);
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"<== nxge_txdma_hw_mode: no dma channel allocated"));
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_mode: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_desc_rings, ndmas));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		channel = tx_desc_rings[i]->tdc;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"==> nxge_txdma_hw_mode: channel %d", channel));
		if (enable) {
			rs = npi_txdma_channel_enable(handle, channel);
			NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				"==> nxge_txdma_hw_mode: channel %d (enable) "
				"rs 0x%x", channel, rs));
		} else {
			/*
			 * Stop the dma channel and waits for the stop done.
			 * If the stop done bit is not set, then force
			 * an error so TXC will stop.
			 * All channels bound to this port need to be stopped
			 * and reset after injecting an interrupt error.
			 */
			rs = npi_txdma_channel_disable(handle, channel);
			NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				"==> nxge_txdma_hw_mode: channel %d (disable) "
				"rs 0x%x", channel, rs));
			{
				tdmc_intr_dbg_t		intr_dbg;

				if (rs != NPI_SUCCESS) {
					/* Inject any error */
					intr_dbg.value = 0;
					intr_dbg.bits.ldw.nack_pref = 1;
					NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
						"==> nxge_txdma_hw_mode: "
						"channel %d (stop failed 0x%x) "
						"(inject err)", rs, channel));
					(void) npi_txdma_inj_int_error_set(
						handle, channel, &intr_dbg);
					rs = npi_txdma_channel_disable(handle,
						channel);
					NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
						"==> nxge_txdma_hw_mode: "
						"channel %d (stop again 0x%x) "
						"(after inject err)",
						rs, channel));
				}
			}
		}
	}

	status = ((rs == NPI_SUCCESS) ? NXGE_OK : NXGE_ERROR | rs);

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_txdma_hw_mode: status 0x%x", status));

	return (status);
}

void
nxge_txdma_enable_channel(p_nxge_t nxgep, uint16_t channel)
{
	npi_handle_t		handle;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"==> nxge_txdma_enable_channel: channel %d", channel));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/* enable the transmit dma channels */
	(void) npi_txdma_channel_enable(handle, channel);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_txdma_enable_channel"));
}

void
nxge_txdma_disable_channel(p_nxge_t nxgep, uint16_t channel)
{
	npi_handle_t		handle;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"==> nxge_txdma_disable_channel: channel %d", channel));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/* stop the transmit dma channels */
	(void) npi_txdma_channel_disable(handle, channel);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_disable_channel"));
}

int
nxge_txdma_stop_inj_err(p_nxge_t nxgep, int channel)
{
	npi_handle_t		handle;
	tdmc_intr_dbg_t		intr_dbg;
	int			status;
	npi_status_t		rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_stop_inj_err"));
	/*
	 * Stop the dma channel waits for the stop done.
	 * If the stop done bit is not set, then create
	 * an error.
	 */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	rs = npi_txdma_channel_disable(handle, channel);
	status = ((rs == NPI_SUCCESS) ? NXGE_OK : NXGE_ERROR | rs);
	if (status == NXGE_OK) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_stop_inj_err (channel %d): "
			"stopped OK", channel));
		return (status);
	}

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		"==> nxge_txdma_stop_inj_err (channel %d): stop failed (0x%x) "
		"injecting error", channel, rs));
	/* Inject any error */
	intr_dbg.value = 0;
	intr_dbg.bits.ldw.nack_pref = 1;
	(void) npi_txdma_inj_int_error_set(handle, channel, &intr_dbg);

	/* Stop done bit will be set as a result of error injection */
	rs = npi_txdma_channel_disable(handle, channel);
	status = ((rs == NPI_SUCCESS) ? NXGE_OK : NXGE_ERROR | rs);
	if (!(rs & NPI_TXDMA_STOP_FAILED)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_stop_inj_err (channel %d): "
			"stopped OK ", channel));
		return (status);
	}

#if	defined(NXGE_DEBUG)
	nxge_txdma_regs_dump_channels(nxgep);
#endif
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		"==> nxge_txdma_stop_inj_err (channel): stop failed (0x%x) "
		" (injected error but still not stopped)", channel, rs));

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_stop_inj_err"));
	return (status);
}

void
nxge_hw_start_tx(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_hw_start_tx"));

	(void) nxge_txdma_hw_start(nxgep);
	(void) nxge_tx_mac_enable(nxgep);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_hw_start_tx"));
}

/*ARGSUSED*/
void
nxge_fixup_txdma_rings(p_nxge_t nxgep)
{
	int			index, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_fixup_txdma_rings"));

	/*
	 * For each transmit channel, reclaim each descriptor and
	 * free buffers.
	 */
	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_fixup_txdma_rings: NULL ring pointer"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_fixup_txdma_rings: no channel allocated"));
		return;
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_fixup_txdma_rings: NULL rings pointer"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_fixup_txdma_rings: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"==> nxge_fixup_txdma_rings: channel %d", channel));

		nxge_txdma_fixup_channel(nxgep, tx_rings->rings[index],
			channel);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_fixup_txdma_rings"));
}

/*ARGSUSED*/
void
nxge_txdma_fix_channel(p_nxge_t nxgep, uint16_t channel)
{
	p_tx_ring_t	ring_p;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_fix_channel"));
	ring_p = nxge_txdma_get_ring(nxgep, channel);
	if (ring_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_fix_channel"));
		return;
	}

	if (ring_p->tdc != channel) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fix_channel: channel not matched "
			"ring tdc %d passed channel",
			ring_p->tdc, channel));
		return;
	}

	nxge_txdma_fixup_channel(nxgep, ring_p, channel);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_fix_channel"));
}

/*ARGSUSED*/
void
nxge_txdma_fixup_channel(p_nxge_t nxgep, p_tx_ring_t ring_p, uint16_t channel)
{
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_fixup_channel"));

	if (ring_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fixup_channel: NULL ring pointer"));
		return;
	}

	if (ring_p->tdc != channel) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fixup_channel: channel not matched "
			"ring tdc %d passed channel",
			ring_p->tdc, channel));
		return;
	}

	MUTEX_ENTER(&ring_p->lock);
	(void) nxge_txdma_reclaim(nxgep, ring_p, 0);
	ring_p->rd_index = 0;
	ring_p->wr_index = 0;
	ring_p->ring_head.value = 0;
	ring_p->ring_kick_tail.value = 0;
	ring_p->descs_pending = 0;
	MUTEX_EXIT(&ring_p->lock);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_fixup_channel"));
}

/*ARGSUSED*/
void
nxge_txdma_hw_kick(p_nxge_t nxgep)
{
	int			index, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_hw_kick"));

	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_kick: NULL ring pointer"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_kick: no channel allocated"));
		return;
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_kick: NULL rings pointer"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_kick: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"==> nxge_txdma_hw_kick: channel %d", channel));
		nxge_txdma_hw_kick_channel(nxgep, tx_rings->rings[index],
			channel);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_hw_kick"));
}

/*ARGSUSED*/
void
nxge_txdma_kick_channel(p_nxge_t nxgep, uint16_t channel)
{
	p_tx_ring_t	ring_p;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_kick_channel"));

	ring_p = nxge_txdma_get_ring(nxgep, channel);
	if (ring_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			    " nxge_txdma_kick_channel"));
		return;
	}

	if (ring_p->tdc != channel) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_kick_channel: channel not matched "
			"ring tdc %d passed channel",
			ring_p->tdc, channel));
		return;
	}

	nxge_txdma_hw_kick_channel(nxgep, ring_p, channel);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_kick_channel"));
}

/*ARGSUSED*/
void
nxge_txdma_hw_kick_channel(p_nxge_t nxgep, p_tx_ring_t ring_p, uint16_t channel)
{

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_hw_kick_channel"));

	if (ring_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_kick_channel: NULL ring pointer"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_hw_kick_channel"));
}

/*ARGSUSED*/
void
nxge_check_tx_hang(p_nxge_t nxgep)
{

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_check_tx_hang"));

	/*
	 * Needs inputs from hardware for regs:
	 *	head index had not moved since last timeout.
	 *	packets not transmitted or stuffed registers.
	 */
	if (nxge_txdma_hung(nxgep)) {
		nxge_fixup_hung_txdma_rings(nxgep);
	}
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_check_tx_hang"));
}

int
nxge_txdma_hung(p_nxge_t nxgep)
{
	int			index, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;
	p_tx_ring_t 		tx_ring_p;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_hung"));
	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hung: NULL ring pointer"));
		return (B_FALSE);
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hung: no channel "
			"allocated"));
		return (B_FALSE);
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hung: NULL rings pointer"));
		return (B_FALSE);
	}

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		tx_ring_p = tx_rings->rings[index];
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_hung: channel %d", channel));
		if (nxge_txdma_channel_hung(nxgep, tx_ring_p, channel)) {
			return (B_TRUE);
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_hung"));

	return (B_FALSE);
}

int
nxge_txdma_channel_hung(p_nxge_t nxgep, p_tx_ring_t tx_ring_p, uint16_t channel)
{
	uint16_t		head_index, tail_index;
	boolean_t		head_wrap, tail_wrap;
	npi_handle_t		handle;
	tx_ring_hdl_t		tx_head;
	uint_t			tx_rd_index;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_channel_hung"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"==> nxge_txdma_channel_hung: channel %d", channel));
	MUTEX_ENTER(&tx_ring_p->lock);
	(void) nxge_txdma_reclaim(nxgep, tx_ring_p, 0);

	tail_index = tx_ring_p->wr_index;
	tail_wrap = tx_ring_p->wr_index_wrap;
	tx_rd_index = tx_ring_p->rd_index;
	MUTEX_EXIT(&tx_ring_p->lock);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"==> nxge_txdma_channel_hung: tdc %d tx_rd_index %d "
		"tail_index %d tail_wrap %d ",
		channel, tx_rd_index, tail_index, tail_wrap));
	/*
	 * Read the hardware maintained transmit head
	 * and wrap around bit.
	 */
	(void) npi_txdma_ring_head_get(handle, channel, &tx_head);
	head_index =  tx_head.bits.ldw.head;
	head_wrap = tx_head.bits.ldw.wrap;
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"==> nxge_txdma_channel_hung: "
		"tx_rd_index %d tail %d tail_wrap %d "
		"head %d wrap %d",
		tx_rd_index, tail_index, tail_wrap,
		head_index, head_wrap));

	if (TXDMA_RING_EMPTY(head_index, head_wrap,
			tail_index, tail_wrap) &&
			(head_index == tx_rd_index)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_channel_hung: EMPTY"));
		return (B_FALSE);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"==> nxge_txdma_channel_hung: Checking if ring full"));
	if (TXDMA_RING_FULL(head_index, head_wrap, tail_index,
			tail_wrap)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_channel_hung: full"));
		return (B_TRUE);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_channel_hung"));

	return (B_FALSE);
}

/*ARGSUSED*/
void
nxge_fixup_hung_txdma_rings(p_nxge_t nxgep)
{
	int			index, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_fixup_hung_txdma_rings"));
	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_fixup_hung_txdma_rings: NULL ring pointer"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_fixup_hung_txdma_rings: no channel "
			"allocated"));
		return;
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_fixup_hung_txdma_rings: NULL rings pointer"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_fixup_hung_txdma_rings: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_fixup_hung_txdma_rings: channel %d",
			channel));

		nxge_txdma_fixup_hung_channel(nxgep, tx_rings->rings[index],
			channel);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_fixup_hung_txdma_rings"));
}

/*ARGSUSED*/
void
nxge_txdma_fix_hung_channel(p_nxge_t nxgep, uint16_t channel)
{
	p_tx_ring_t	ring_p;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_fix_hung_channel"));
	ring_p = nxge_txdma_get_ring(nxgep, channel);
	if (ring_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fix_hung_channel"));
		return;
	}

	if (ring_p->tdc != channel) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fix_hung_channel: channel not matched "
			"ring tdc %d passed channel",
			ring_p->tdc, channel));
		return;
	}

	nxge_txdma_fixup_channel(nxgep, ring_p, channel);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_fix_hung_channel"));
}

/*ARGSUSED*/
void
nxge_txdma_fixup_hung_channel(p_nxge_t nxgep, p_tx_ring_t ring_p,
	uint16_t channel)
{
	npi_handle_t		handle;
	tdmc_intr_dbg_t		intr_dbg;
	int			status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_fixup_hung_channel"));

	if (ring_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fixup_channel: NULL ring pointer"));
		return;
	}

	if (ring_p->tdc != channel) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fixup_hung_channel: channel "
			"not matched "
			"ring tdc %d passed channel",
			ring_p->tdc, channel));
		return;
	}

	/* Reclaim descriptors */
	MUTEX_ENTER(&ring_p->lock);
	(void) nxge_txdma_reclaim(nxgep, ring_p, 0);
	MUTEX_EXIT(&ring_p->lock);

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/*
	 * Stop the dma channel waits for the stop done.
	 * If the stop done bit is not set, then force
	 * an error.
	 */
	status = npi_txdma_channel_disable(handle, channel);
	if (!(status & NPI_TXDMA_STOP_FAILED)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fixup_hung_channel: stopped OK "
			"ring tdc %d passed channel %d",
			ring_p->tdc, channel));
		return;
	}

	/* Inject any error */
	intr_dbg.value = 0;
	intr_dbg.bits.ldw.nack_pref = 1;
	(void) npi_txdma_inj_int_error_set(handle, channel, &intr_dbg);

	/* Stop done bit will be set as a result of error injection */
	status = npi_txdma_channel_disable(handle, channel);
	if (!(status & NPI_TXDMA_STOP_FAILED)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_fixup_hung_channel: stopped again"
			"ring tdc %d passed channel",
			ring_p->tdc, channel));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"<== nxge_txdma_fixup_hung_channel: stop done still not set!! "
		"ring tdc %d passed channel",
		ring_p->tdc, channel));

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_fixup_hung_channel"));
}

/*ARGSUSED*/
void
nxge_reclaim_rings(p_nxge_t nxgep)
{
	int			index, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;
	p_tx_ring_t 		tx_ring_p;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_reclaim_ring"));
	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_reclain_rimgs: NULL ring pointer"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_reclain_rimgs: no channel "
			"allocated"));
		return;
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_reclain_rimgs: NULL rings pointer"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_reclain_rimgs: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> reclain_rimgs: channel %d",
			channel));
		tx_ring_p = tx_rings->rings[index];
		MUTEX_ENTER(&tx_ring_p->lock);
		(void) nxge_txdma_reclaim(nxgep, tx_ring_p, channel);
		MUTEX_EXIT(&tx_ring_p->lock);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_reclaim_rings"));
}

void
nxge_txdma_regs_dump_channels(p_nxge_t nxgep)
{
	int			index, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;
	npi_handle_t		handle;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "==> nxge_txdma_regs_dump_channels"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	(void) npi_txdma_dump_fzc_regs(handle);

	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_regs_dump_channels: NULL ring"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_regs_dump_channels: "
			"no channel allocated"));
		return;
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_regs_dump_channels: NULL rings"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_regs_dump_channels: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_rings->rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_regs_dump_channels: channel %d",
			channel));
		(void) npi_txdma_dump_tdc_regs(handle, channel);
	}

	/* Dump TXC registers */
	(void) npi_txc_dump_fzc_regs(handle);
	(void) npi_txc_dump_port_fzc_regs(handle, nxgep->function_num);

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_regs_dump_channels: channel %d",
			channel));
		(void) npi_txc_dump_tdc_fzc_regs(handle, channel);
	}

	for (index = 0; index < ndmas; index++) {
		channel = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_txdma_regs_dump_channels: channel %d",
			channel));
		nxge_txdma_regs_dump(nxgep, channel);
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_regs_dump"));

}

void
nxge_txdma_regs_dump(p_nxge_t nxgep, int channel)
{
	npi_handle_t		handle;
	tx_ring_hdl_t 		hdl;
	tx_ring_kick_t 		kick;
	tx_cs_t 		cs;
	txc_control_t		control;
	uint32_t		bitmap = 0;
	uint32_t		burst = 0;
	uint32_t		bytes = 0;
	dma_log_page_t		cfg;

	printf("\n\tfunc # %d tdc %d ",
		nxgep->function_num, channel);
	cfg.page_num = 0;
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	(void) npi_txdma_log_page_get(handle, channel, &cfg);
	printf("\n\tlog page func %d valid page 0 %d",
		cfg.func_num, cfg.valid);
	cfg.page_num = 1;
	(void) npi_txdma_log_page_get(handle, channel, &cfg);
	printf("\n\tlog page func %d valid page 1 %d",
		cfg.func_num, cfg.valid);

	(void) npi_txdma_ring_head_get(handle, channel, &hdl);
	(void) npi_txdma_desc_kick_reg_get(handle, channel, &kick);
	printf("\n\thead value is 0x%0llx",
		(long long)hdl.value);
	printf("\n\thead index %d", hdl.bits.ldw.head);
	printf("\n\tkick value is 0x%0llx",
		(long long)kick.value);
	printf("\n\ttail index %d\n", kick.bits.ldw.tail);

	(void) npi_txdma_control_status(handle, OP_GET, channel, &cs);
	printf("\n\tControl statue is 0x%0llx", (long long)cs.value);
	printf("\n\tControl status RST state %d", cs.bits.ldw.rst);

	(void) npi_txc_control(handle, OP_GET, &control);
	(void) npi_txc_port_dma_list_get(handle, nxgep->function_num, &bitmap);
	(void) npi_txc_dma_max_burst(handle, OP_GET, channel, &burst);
	(void) npi_txc_dma_bytes_transmitted(handle, channel, &bytes);

	printf("\n\tTXC port control 0x%0llx",
		(long long)control.value);
	printf("\n\tTXC port bitmap 0x%x", bitmap);
	printf("\n\tTXC max burst %d", burst);
	printf("\n\tTXC bytes xmt %d\n", bytes);

	{
		ipp_status_t status;

		(void) npi_ipp_get_status(handle, nxgep->function_num, &status);
#if defined(__i386)
		printf("\n\tIPP status 0x%llux\n", (uint64_t)status.value);
#else
		printf("\n\tIPP status 0x%lux\n", (uint64_t)status.value);
#endif
	}
}

/*
 * Static functions start here.
 */
static nxge_status_t
nxge_map_txdma(p_nxge_t nxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;
	p_tx_ring_t 		*tx_desc_rings;
	p_tx_mbox_areas_t 	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;
	p_nxge_dma_pool_t	dma_buf_poolp;
	p_nxge_dma_pool_t	dma_cntl_poolp;
	p_nxge_dma_common_t	*dma_buf_p;
	p_nxge_dma_common_t	*dma_cntl_p;
	nxge_status_t		status = NXGE_OK;
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	p_nxge_dma_common_t	t_dma_buf_p;
	p_nxge_dma_common_t	t_dma_cntl_p;
#endif

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma"));

	dma_buf_poolp = nxgep->tx_buf_pool_p;
	dma_cntl_poolp = nxgep->tx_cntl_pool_p;

	if (!dma_buf_poolp->buf_allocated || !dma_cntl_poolp->buf_allocated) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_map_txdma: buf not allocated"));
		return (NXGE_ERROR);
	}

	ndmas = dma_buf_poolp->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_map_txdma: no dma allocated"));
		return (NXGE_ERROR);
	}

	dma_buf_p = dma_buf_poolp->dma_buf_pool_p;
	dma_cntl_p = dma_cntl_poolp->dma_buf_pool_p;

	tx_rings = (p_tx_rings_t)
			KMEM_ZALLOC(sizeof (tx_rings_t), KM_SLEEP);
	tx_desc_rings = (p_tx_ring_t *)KMEM_ZALLOC(
			sizeof (p_tx_ring_t) * ndmas, KM_SLEEP);

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma: "
		"tx_rings $%p tx_desc_rings $%p",
		tx_rings, tx_desc_rings));

	tx_mbox_areas_p = (p_tx_mbox_areas_t)
			KMEM_ZALLOC(sizeof (tx_mbox_areas_t), KM_SLEEP);
	tx_mbox_p = (p_tx_mbox_t *)KMEM_ZALLOC(
			sizeof (p_tx_mbox_t) * ndmas, KM_SLEEP);

	/*
	 * Map descriptors from the buffer pools for each dma channel.
	 */
	for (i = 0; i < ndmas; i++) {
		/*
		 * Set up and prepare buffer blocks, descriptors
		 * and mailbox.
		 */
		channel = ((p_nxge_dma_common_t)dma_buf_p[i])->dma_channel;
		status = nxge_map_txdma_channel(nxgep, channel,
				(p_nxge_dma_common_t *)&dma_buf_p[i],
				(p_tx_ring_t *)&tx_desc_rings[i],
				dma_buf_poolp->num_chunks[i],
				(p_nxge_dma_common_t *)&dma_cntl_p[i],
				(p_tx_mbox_t *)&tx_mbox_p[i]);
		if (status != NXGE_OK) {
			goto nxge_map_txdma_fail1;
		}
		tx_desc_rings[i]->index = (uint16_t)i;
		tx_desc_rings[i]->tdc_stats = &nxgep->statsp->tdc_stats[i];

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
		if (nxgep->niu_type == N2_NIU && NXGE_DMA_BLOCK == 1) {
			tx_desc_rings[i]->hv_set = B_FALSE;
			t_dma_buf_p = (p_nxge_dma_common_t)dma_buf_p[i];
			t_dma_cntl_p = (p_nxge_dma_common_t)dma_cntl_p[i];

			tx_desc_rings[i]->hv_tx_buf_base_ioaddr_pp =
				(uint64_t)t_dma_buf_p->orig_ioaddr_pp;
			tx_desc_rings[i]->hv_tx_buf_ioaddr_size =
				(uint64_t)t_dma_buf_p->orig_alength;

			NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				"==> nxge_map_txdma_channel: "
				"hv data buf base io $%p "
				"size 0x%llx (%d) "
				"buf base io $%p "
				"orig vatopa base io $%p "
				"orig_len 0x%llx (%d)",
				tx_desc_rings[i]->hv_tx_buf_base_ioaddr_pp,
				tx_desc_rings[i]->hv_tx_buf_ioaddr_size,
				tx_desc_rings[i]->hv_tx_buf_ioaddr_size,
				t_dma_buf_p->ioaddr_pp,
				t_dma_buf_p->orig_vatopa,
				t_dma_buf_p->orig_alength,
				t_dma_buf_p->orig_alength));

			tx_desc_rings[i]->hv_tx_cntl_base_ioaddr_pp =
				(uint64_t)t_dma_cntl_p->orig_ioaddr_pp;
			tx_desc_rings[i]->hv_tx_cntl_ioaddr_size =
				(uint64_t)t_dma_cntl_p->orig_alength;

			NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				"==> nxge_map_txdma_channel: "
				"hv cntl base io $%p "
				"orig ioaddr_pp ($%p) "
				"orig vatopa ($%p) "
				"size 0x%llx (%d 0x%x)",
				tx_desc_rings[i]->hv_tx_cntl_base_ioaddr_pp,
				t_dma_cntl_p->orig_ioaddr_pp,
				t_dma_cntl_p->orig_vatopa,
				tx_desc_rings[i]->hv_tx_cntl_ioaddr_size,
				t_dma_cntl_p->orig_alength,
				t_dma_cntl_p->orig_alength));
		}
#endif
	}

	tx_rings->ndmas = ndmas;
	tx_rings->rings = tx_desc_rings;
	nxgep->tx_rings = tx_rings;
	tx_mbox_areas_p->txmbox_areas_p = tx_mbox_p;
	nxgep->tx_mbox_areas_p = tx_mbox_areas_p;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma: "
		"tx_rings $%p rings $%p",
		nxgep->tx_rings, nxgep->tx_rings->rings));
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma: "
		"tx_rings $%p tx_desc_rings $%p",
		nxgep->tx_rings, tx_desc_rings));

	goto nxge_map_txdma_exit;

nxge_map_txdma_fail1:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma: uninit tx desc "
		"(status 0x%x channel %d i %d)",
		nxgep, status, channel, i));
	i--;
	for (; i >= 0; i--) {
		channel = ((p_nxge_dma_common_t)dma_buf_p[i])->dma_channel;
		nxge_unmap_txdma_channel(nxgep, channel,
			tx_desc_rings[i],
			tx_mbox_p[i]);
	}

	KMEM_FREE(tx_desc_rings, sizeof (p_tx_ring_t) * ndmas);
	KMEM_FREE(tx_rings, sizeof (tx_rings_t));
	KMEM_FREE(tx_mbox_p, sizeof (p_tx_mbox_t) * ndmas);
	KMEM_FREE(tx_mbox_areas_p, sizeof (tx_mbox_areas_t));

nxge_map_txdma_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma: "
		"(status 0x%x channel %d)",
		status, channel));

	return (status);
}

static void
nxge_unmap_txdma(p_nxge_t nxgep)
{
	int			i, ndmas;
	uint8_t			channel;
	p_tx_rings_t 		tx_rings;
	p_tx_ring_t 		*tx_desc_rings;
	p_tx_mbox_areas_t 	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;
	p_nxge_dma_pool_t	dma_buf_poolp;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_unmap_txdma"));

	dma_buf_poolp = nxgep->tx_buf_pool_p;
	if (!dma_buf_poolp->buf_allocated) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"==> nxge_unmap_txdma: buf not allocated"));
		return;
	}

	ndmas = dma_buf_poolp->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_unmap_txdma: no dma allocated"));
		return;
	}

	tx_rings = nxgep->tx_rings;
	tx_desc_rings = tx_rings->rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_unmap_txdma: NULL ring pointer"));
		return;
	}

	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_unmap_txdma: NULL ring pointers"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_unmap_txdma: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_desc_rings, ndmas));

	tx_mbox_areas_p = nxgep->tx_mbox_areas_p;
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	for (i = 0; i < ndmas; i++) {
		channel = tx_desc_rings[i]->tdc;
		(void) nxge_unmap_txdma_channel(nxgep, channel,
				(p_tx_ring_t)tx_desc_rings[i],
				(p_tx_mbox_t)tx_mbox_p[i]);
	}

	KMEM_FREE(tx_desc_rings, sizeof (p_tx_ring_t) * ndmas);
	KMEM_FREE(tx_rings, sizeof (tx_rings_t));
	KMEM_FREE(tx_mbox_p, sizeof (p_tx_mbox_t) * ndmas);
	KMEM_FREE(tx_mbox_areas_p, sizeof (tx_mbox_areas_t));

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_unmap_txdma"));
}

static nxge_status_t
nxge_map_txdma_channel(p_nxge_t nxgep, uint16_t channel,
	p_nxge_dma_common_t *dma_buf_p,
	p_tx_ring_t *tx_desc_p,
	uint32_t num_chunks,
	p_nxge_dma_common_t *dma_cntl_p,
	p_tx_mbox_t *tx_mbox_p)
{
	int	status = NXGE_OK;

	/*
	 * Set up and prepare buffer blocks, descriptors
	 * and mailbox.
	 */
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel (channel %d)", channel));
	/*
	 * Transmit buffer blocks
	 */
	status = nxge_map_txdma_channel_buf_ring(nxgep, channel,
			dma_buf_p, tx_desc_p, num_chunks);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_map_txdma_channel (channel %d): "
			"map buffer failed 0x%x", channel, status));
		goto nxge_map_txdma_channel_exit;
	}

	/*
	 * Transmit block ring, and mailbox.
	 */
	nxge_map_txdma_channel_cfg_ring(nxgep, channel, dma_cntl_p, *tx_desc_p,
					tx_mbox_p);

	goto nxge_map_txdma_channel_exit;

nxge_map_txdma_channel_fail1:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel: unmap buf"
		"(status 0x%x channel %d)",
		status, channel));
	nxge_unmap_txdma_channel_buf_ring(nxgep, *tx_desc_p);

nxge_map_txdma_channel_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_map_txdma_channel: "
		"(status 0x%x channel %d)",
		status, channel));

	return (status);
}

/*ARGSUSED*/
static void
nxge_unmap_txdma_channel(p_nxge_t nxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p,
	p_tx_mbox_t tx_mbox_p)
{
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_unmap_txdma_channel (channel %d)", channel));
	/*
	 * unmap tx block ring, and mailbox.
	 */
	(void) nxge_unmap_txdma_channel_cfg_ring(nxgep,
			tx_ring_p, tx_mbox_p);

	/* unmap buffer blocks */
	(void) nxge_unmap_txdma_channel_buf_ring(nxgep, tx_ring_p);

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_unmap_txdma_channel"));
}

/*ARGSUSED*/
static void
nxge_map_txdma_channel_cfg_ring(p_nxge_t nxgep, uint16_t dma_channel,
	p_nxge_dma_common_t *dma_cntl_p,
	p_tx_ring_t tx_ring_p,
	p_tx_mbox_t *tx_mbox_p)
{
	p_tx_mbox_t 		mboxp;
	p_nxge_dma_common_t 	cntl_dmap;
	p_nxge_dma_common_t 	dmap;
	p_tx_rng_cfig_t		tx_ring_cfig_p;
	p_tx_ring_kick_t	tx_ring_kick_p;
	p_tx_cs_t		tx_cs_p;
	p_tx_dma_ent_msk_t	tx_evmask_p;
	p_txdma_mbh_t		mboxh_p;
	p_txdma_mbl_t		mboxl_p;
	uint64_t		tx_desc_len;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_cfg_ring"));

	cntl_dmap = *dma_cntl_p;

	dmap = (p_nxge_dma_common_t)&tx_ring_p->tdc_desc;
	nxge_setup_dma_common(dmap, cntl_dmap, tx_ring_p->tx_ring_size,
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

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_cfg_ring: channel %d des $%p",
		dma_channel,
		dmap->dma_cookie.dmac_laddress));

	tx_ring_cfig_p->value = 0;
	tx_desc_len = (uint64_t)(tx_ring_p->tx_ring_size >> 3);
	tx_ring_cfig_p->value =
		(dmap->dma_cookie.dmac_laddress & TX_RNG_CFIG_ADDR_MASK) |
		(tx_desc_len << TX_RNG_CFIG_LEN_SHIFT);

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_cfg_ring: channel %d cfg 0x%llx",
		dma_channel,
		tx_ring_cfig_p->value));

	tx_cs_p->bits.ldw.rst = 1;

	/* Map in mailbox */
	mboxp = (p_tx_mbox_t)
		KMEM_ZALLOC(sizeof (tx_mbox_t), KM_SLEEP);
	dmap = (p_nxge_dma_common_t)&mboxp->tx_mbox;
	nxge_setup_dma_common(dmap, cntl_dmap, 1, sizeof (txdma_mailbox_t));
	mboxh_p = (p_txdma_mbh_t)&tx_ring_p->tx_mbox_mbh;
	mboxl_p = (p_txdma_mbl_t)&tx_ring_p->tx_mbox_mbl;
	mboxh_p->value = mboxl_p->value = 0;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_cfg_ring: mbox 0x%lx",
		dmap->dma_cookie.dmac_laddress));

	mboxh_p->bits.ldw.mbaddr = ((dmap->dma_cookie.dmac_laddress >>
				TXDMA_MBH_ADDR_SHIFT) & TXDMA_MBH_MASK);

	mboxl_p->bits.ldw.mbaddr = ((dmap->dma_cookie.dmac_laddress &
				TXDMA_MBL_MASK) >> TXDMA_MBL_SHIFT);

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_cfg_ring: mbox 0x%lx",
		dmap->dma_cookie.dmac_laddress));
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_cfg_ring: hmbox $%p "
		"mbox $%p",
		mboxh_p->bits.ldw.mbaddr, mboxl_p->bits.ldw.mbaddr));
	tx_ring_p->page_valid.value = 0;
	tx_ring_p->page_mask_1.value = tx_ring_p->page_mask_2.value = 0;
	tx_ring_p->page_value_1.value = tx_ring_p->page_value_2.value = 0;
	tx_ring_p->page_reloc_1.value = tx_ring_p->page_reloc_2.value = 0;
	tx_ring_p->page_hdl.value = 0;

	tx_ring_p->page_valid.bits.ldw.page0 = 1;
	tx_ring_p->page_valid.bits.ldw.page1 = 1;

	tx_ring_p->max_burst.value = 0;
	tx_ring_p->max_burst.bits.ldw.dma_max_burst = TXC_DMA_MAX_BURST_DEFAULT;

	*tx_mbox_p = mboxp;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				"<== nxge_map_txdma_channel_cfg_ring"));
}

/*ARGSUSED*/
static void
nxge_unmap_txdma_channel_cfg_ring(p_nxge_t nxgep,
	p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p)
{
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_unmap_txdma_channel_cfg_ring: channel %d",
		tx_ring_p->tdc));

	KMEM_FREE(tx_mbox_p, sizeof (tx_mbox_t));

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_unmap_txdma_channel_cfg_ring"));
}

static nxge_status_t
nxge_map_txdma_channel_buf_ring(p_nxge_t nxgep, uint16_t channel,
	p_nxge_dma_common_t *dma_buf_p,
	p_tx_ring_t *tx_desc_p, uint32_t num_chunks)
{
	p_nxge_dma_common_t 	dma_bufp, tmp_bufp;
	p_nxge_dma_common_t 	dmap;
	nxge_os_dma_handle_t	tx_buf_dma_handle;
	p_tx_ring_t 		tx_ring_p;
	p_tx_msg_t 		tx_msg_ring;
	nxge_status_t		status = NXGE_OK;
	int			ddi_status = DDI_SUCCESS;
	int			i, j, index;
	uint32_t		size, bsize;
	uint32_t 		nblocks, nmsgs;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_buf_ring"));

	dma_bufp = tmp_bufp = *dma_buf_p;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		" nxge_map_txdma_channel_buf_ring: channel %d to map %d "
		"chunks bufp $%p",
		channel, num_chunks, dma_bufp));

	nmsgs = 0;
	for (i = 0; i < num_chunks; i++, tmp_bufp++) {
		nmsgs += tmp_bufp->nblocks;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"==> nxge_map_txdma_channel_buf_ring: channel %d "
			"bufp $%p nblocks %d nmsgs %d",
			channel, tmp_bufp, tmp_bufp->nblocks, nmsgs));
	}
	if (!nmsgs) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_map_txdma_channel_buf_ring: channel %d "
			"no msg blocks",
			channel));
		status = NXGE_ERROR;
		goto nxge_map_txdma_channel_buf_ring_exit;
	}

	tx_ring_p = (p_tx_ring_t)
		KMEM_ZALLOC(sizeof (tx_ring_t), KM_SLEEP);
	MUTEX_INIT(&tx_ring_p->lock, NULL, MUTEX_DRIVER,
		(void *)nxgep->interrupt_cookie);

	tx_ring_p->nxgep = nxgep;
	tx_ring_p->serial = nxge_serialize_create(nmsgs,
				nxge_serial_tx, tx_ring_p);
	/*
	 * Allocate transmit message rings and handles for packets
	 * not to be copied to premapped buffers.
	 */
	size = nmsgs * sizeof (tx_msg_t);
	tx_msg_ring = KMEM_ZALLOC(size, KM_SLEEP);
	for (i = 0; i < nmsgs; i++) {
		ddi_status = ddi_dma_alloc_handle(nxgep->dip, &nxge_tx_dma_attr,
				DDI_DMA_DONTWAIT, 0,
				&tx_msg_ring[i].dma_handle);
		if (ddi_status != DDI_SUCCESS) {
			status |= NXGE_DDI_FAILED;
			break;
		}
	}
	if (i < nmsgs) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "Allocate handles failed."));
		goto nxge_map_txdma_channel_buf_ring_fail1;
	}

	tx_ring_p->tdc = channel;
	tx_ring_p->tx_msg_ring = tx_msg_ring;
	tx_ring_p->tx_ring_size = nmsgs;
	tx_ring_p->num_chunks = num_chunks;
	if (!nxge_tx_intr_thres) {
		nxge_tx_intr_thres = tx_ring_p->tx_ring_size/4;
	}
	tx_ring_p->tx_wrap_mask = tx_ring_p->tx_ring_size - 1;
	tx_ring_p->rd_index = 0;
	tx_ring_p->wr_index = 0;
	tx_ring_p->ring_head.value = 0;
	tx_ring_p->ring_kick_tail.value = 0;
	tx_ring_p->descs_pending = 0;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_map_txdma_channel_buf_ring: channel %d "
		"actual tx desc max %d nmsgs %d "
		"(config nxge_tx_ring_size %d)",
		channel, tx_ring_p->tx_ring_size, nmsgs,
		nxge_tx_ring_size));

	/*
	 * Map in buffers from the buffer pool.
	 */
	index = 0;
	bsize = dma_bufp->block_size;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma_channel_buf_ring: "
		"dma_bufp $%p tx_rng_p $%p "
		"tx_msg_rng_p $%p bsize %d",
		dma_bufp, tx_ring_p, tx_msg_ring, bsize));

	tx_buf_dma_handle = dma_bufp->dma_handle;
	for (i = 0; i < num_chunks; i++, dma_bufp++) {
		bsize = dma_bufp->block_size;
		nblocks = dma_bufp->nblocks;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"==> nxge_map_txdma_channel_buf_ring: dma chunk %d "
			"size %d dma_bufp $%p",
			i, sizeof (nxge_dma_common_t), dma_bufp));

		for (j = 0; j < nblocks; j++) {
			tx_msg_ring[index].buf_dma_handle = tx_buf_dma_handle;
			dmap = &tx_msg_ring[index++].buf_dma;
#ifdef TX_MEM_DEBUG
			NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				"==> nxge_map_txdma_channel_buf_ring: j %d"
				"dmap $%p", i, dmap));
#endif
			nxge_setup_dma_common(dmap, dma_bufp, 1,
				bsize);
		}
	}

	if (i < num_chunks) {
		status = NXGE_ERROR;
		goto nxge_map_txdma_channel_buf_ring_fail1;
	}

	*tx_desc_p = tx_ring_p;

	goto nxge_map_txdma_channel_buf_ring_exit;

nxge_map_txdma_channel_buf_ring_fail1:
	if (tx_ring_p->serial) {
		nxge_serialize_destroy(tx_ring_p->serial);
		tx_ring_p->serial = NULL;
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

	status = NXGE_ERROR;

nxge_map_txdma_channel_buf_ring_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_map_txdma_channel_buf_ring status 0x%x", status));

	return (status);
}

/*ARGSUSED*/
static void
nxge_unmap_txdma_channel_buf_ring(p_nxge_t nxgep, p_tx_ring_t tx_ring_p)
{
	p_tx_msg_t 		tx_msg_ring;
	p_tx_msg_t 		tx_msg_p;
	int			i;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_unmap_txdma_channel_buf_ring"));
	if (tx_ring_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_unmap_txdma_channel_buf_ring: NULL ringp"));
		return;
	}
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_unmap_txdma_channel_buf_ring: channel %d",
		tx_ring_p->tdc));

	tx_msg_ring = tx_ring_p->tx_msg_ring;
	for (i = 0; i < tx_ring_p->tx_ring_size; i++) {
		tx_msg_p = &tx_msg_ring[i];
		if (tx_msg_p->flags.dma_type == USE_DVMA) {
			NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				"entry = %d",
				i));
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
		} else if (tx_msg_p->flags.dma_type ==
				USE_DMA) {
			if (ddi_dma_unbind_handle
				(tx_msg_p->dma_handle)) {
				cmn_err(CE_WARN, "!nxge_unmap_tx_bug_ring: "
					"ddi_dma_unbind_handle "
					"failed.");
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

	if (tx_ring_p->serial) {
		nxge_serialize_destroy(tx_ring_p->serial);
		tx_ring_p->serial = NULL;
	}

	MUTEX_DESTROY(&tx_ring_p->lock);
	KMEM_FREE(tx_msg_ring, sizeof (tx_msg_t) * tx_ring_p->tx_ring_size);
	KMEM_FREE(tx_ring_p, sizeof (tx_ring_t));

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"<== nxge_unmap_txdma_channel_buf_ring"));
}

static nxge_status_t
nxge_txdma_hw_start(p_nxge_t nxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;
	p_tx_ring_t 		*tx_desc_rings;
	p_tx_mbox_areas_t 	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_start"));

	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_start: NULL ring pointer"));
		return (NXGE_ERROR);
	}
	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_start: NULL ring pointers"));
		return (NXGE_ERROR);
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_start: no dma channel allocated"));
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_start: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_desc_rings, ndmas));

	tx_mbox_areas_p = nxgep->tx_mbox_areas_p;
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	for (i = 0; i < ndmas; i++) {
		channel = tx_desc_rings[i]->tdc,
		status = nxge_txdma_start_channel(nxgep, channel,
				(p_tx_ring_t)tx_desc_rings[i],
				(p_tx_mbox_t)tx_mbox_p[i]);
		if (status != NXGE_OK) {
			goto nxge_txdma_hw_start_fail1;
		}
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_start: "
		"tx_rings $%p rings $%p",
		nxgep->tx_rings, nxgep->tx_rings->rings));
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_start: "
		"tx_rings $%p tx_desc_rings $%p",
		nxgep->tx_rings, tx_desc_rings));

	goto nxge_txdma_hw_start_exit;

nxge_txdma_hw_start_fail1:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_txdma_hw_start: disable "
		"(status 0x%x channel %d i %d)", status, channel, i));
	for (; i >= 0; i--) {
		channel = tx_desc_rings[i]->tdc,
		(void) nxge_txdma_stop_channel(nxgep, channel,
			(p_tx_ring_t)tx_desc_rings[i],
			(p_tx_mbox_t)tx_mbox_p[i]);
	}

nxge_txdma_hw_start_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_txdma_hw_start: (status 0x%x)", status));

	return (status);
}

static void
nxge_txdma_hw_stop(p_nxge_t nxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_tx_rings_t 		tx_rings;
	p_tx_ring_t 		*tx_desc_rings;
	p_tx_mbox_areas_t 	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_stop"));

	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_stop: NULL ring pointer"));
		return;
	}
	tx_desc_rings = tx_rings->rings;
	if (tx_desc_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_stop: NULL ring pointers"));
		return;
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_hw_stop: no dma channel allocated"));
		return;
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_stop: "
		"tx_rings $%p tx_desc_rings $%p",
		tx_rings, tx_desc_rings));

	tx_mbox_areas_p = nxgep->tx_mbox_areas_p;
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	for (i = 0; i < ndmas; i++) {
		channel = tx_desc_rings[i]->tdc;
		(void) nxge_txdma_stop_channel(nxgep, channel,
				(p_tx_ring_t)tx_desc_rings[i],
				(p_tx_mbox_t)tx_mbox_p[i]);
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_stop: "
		"tx_rings $%p tx_desc_rings $%p",
		tx_rings, tx_desc_rings));

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_txdma_hw_stop"));
}

static nxge_status_t
nxge_txdma_start_channel(p_nxge_t nxgep, uint16_t channel,
    p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p)

{
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_txdma_start_channel (channel %d)", channel));
	/*
	 * TXDMA/TXC must be in stopped state.
	 */
	(void) nxge_txdma_stop_inj_err(nxgep, channel);

	/*
	 * Reset TXDMA channel
	 */
	tx_ring_p->tx_cs.value = 0;
	tx_ring_p->tx_cs.bits.ldw.rst = 1;
	status = nxge_reset_txdma_channel(nxgep, channel,
			tx_ring_p->tx_cs.value);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_txdma_start_channel (channel %d)"
			" reset channel failed 0x%x", channel, status));
		goto nxge_txdma_start_channel_exit;
	}

	/*
	 * Initialize the TXDMA channel specific FZC control
	 * configurations. These FZC registers are pertaining
	 * to each TX channel (i.e. logical pages).
	 */
	status = nxge_init_fzc_txdma_channel(nxgep, channel,
			tx_ring_p, tx_mbox_p);
	if (status != NXGE_OK) {
		goto nxge_txdma_start_channel_exit;
	}

	/*
	 * Initialize the event masks.
	 */
	tx_ring_p->tx_evmask.value = 0;
	status = nxge_init_txdma_channel_event_mask(nxgep,
			channel, &tx_ring_p->tx_evmask);
	if (status != NXGE_OK) {
		goto nxge_txdma_start_channel_exit;
	}

	/*
	 * Load TXDMA descriptors, buffers, mailbox,
	 * initialise the DMA channels and
	 * enable each DMA channel.
	 */
	status = nxge_enable_txdma_channel(nxgep, channel,
			tx_ring_p, tx_mbox_p);
	if (status != NXGE_OK) {
		goto nxge_txdma_start_channel_exit;
	}

nxge_txdma_start_channel_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_txdma_start_channel"));

	return (status);
}

/*ARGSUSED*/
static nxge_status_t
nxge_txdma_stop_channel(p_nxge_t nxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p, p_tx_mbox_t tx_mbox_p)
{
	int		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_txdma_stop_channel: channel %d", channel));

	/*
	 * Stop (disable) TXDMA and TXC (if stop bit is set
	 * and STOP_N_GO bit not set, the TXDMA reset state will
	 * not be set if reset TXDMA.
	 */
	(void) nxge_txdma_stop_inj_err(nxgep, channel);

	/*
	 * Reset TXDMA channel
	 */
	tx_ring_p->tx_cs.value = 0;
	tx_ring_p->tx_cs.bits.ldw.rst = 1;
	status = nxge_reset_txdma_channel(nxgep, channel,
			tx_ring_p->tx_cs.value);
	if (status != NXGE_OK) {
		goto nxge_txdma_stop_channel_exit;
	}

#ifdef HARDWARE_REQUIRED
	/* Set up the interrupt event masks. */
	tx_ring_p->tx_evmask.value = 0;
	status = nxge_init_txdma_channel_event_mask(nxgep,
			channel, &tx_ring_p->tx_evmask);
	if (status != NXGE_OK) {
		goto nxge_txdma_stop_channel_exit;
	}

	/* Initialize the DMA control and status register */
	tx_ring_p->tx_cs.value = TX_ENT_MSK_MK_ALL;
	status = nxge_init_txdma_channel_cntl_stat(nxgep, channel,
			tx_ring_p->tx_cs.value);
	if (status != NXGE_OK) {
		goto nxge_txdma_stop_channel_exit;
	}

	/* Disable channel */
	status = nxge_disable_txdma_channel(nxgep, channel,
			tx_ring_p, tx_mbox_p);
	if (status != NXGE_OK) {
		goto nxge_txdma_start_channel_exit;
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
		"==> nxge_txdma_stop_channel: event done"));

#endif

nxge_txdma_stop_channel_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_txdma_stop_channel"));
	return (status);
}

static p_tx_ring_t
nxge_txdma_get_ring(p_nxge_t nxgep, uint16_t channel)
{
	int			index, ndmas;
	uint16_t		tdc;
	p_tx_rings_t 		tx_rings;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_get_ring"));

	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_get_ring: NULL ring pointer"));
		return (NULL);
	}

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_get_ring: no channel allocated"));
		return (NULL);
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
			"<== nxge_txdma_get_ring: NULL rings pointer"));
		return (NULL);
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_get_ring: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		tdc = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"==> nxge_fixup_txdma_rings: channel %d", tdc));
		if (channel == tdc) {
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"<== nxge_txdma_get_ring: tdc %d "
				"ring $%p",
				tdc, tx_rings->rings[index]));
			return (p_tx_ring_t)(tx_rings->rings[index]);
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_get_ring"));
	return (NULL);
}

static p_tx_mbox_t
nxge_txdma_get_mbox(p_nxge_t nxgep, uint16_t channel)
{
	int			index, tdc, ndmas;
	p_tx_rings_t 		tx_rings;
	p_tx_mbox_areas_t 	tx_mbox_areas_p;
	p_tx_mbox_t		*tx_mbox_p;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_get_mbox"));

	tx_rings = nxgep->tx_rings;
	if (tx_rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_txdma_get_mbox: NULL ring pointer"));
		return (NULL);
	}

	tx_mbox_areas_p = nxgep->tx_mbox_areas_p;
	if (tx_mbox_areas_p == NULL) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_txdma_get_mbox: NULL mbox pointer"));
		return (NULL);
	}

	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	ndmas = tx_rings->ndmas;
	if (!ndmas) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_txdma_get_mbox: no channel allocated"));
		return (NULL);
	}

	if (tx_rings->rings == NULL) {
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"<== nxge_txdma_get_mbox: NULL rings pointer"));
		return (NULL);
	}

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_get_mbox: "
		"tx_rings $%p tx_desc_rings $%p ndmas %d",
		tx_rings, tx_rings, ndmas));

	for (index = 0; index < ndmas; index++) {
		tdc = tx_rings->rings[index]->tdc;
		NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
			"==> nxge_txdma_get_mbox: channel %d", tdc));
		if (channel == tdc) {
			NXGE_DEBUG_MSG((nxgep, TX_CTL,
				"<== nxge_txdma_get_mbox: tdc %d "
				"ring $%p",
				tdc, tx_rings->rings[index]));
			return (p_tx_mbox_t)(tx_mbox_p[index]);
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_get_mbox"));
	return (NULL);
}

/*ARGSUSED*/
static nxge_status_t
nxge_tx_err_evnts(p_nxge_t nxgep, uint_t index, p_nxge_ldv_t ldvp, tx_cs_t cs)
{
	npi_handle_t		handle;
	npi_status_t		rs;
	uint8_t			channel;
	p_tx_ring_t 		*tx_rings;
	p_tx_ring_t 		tx_ring_p;
	p_nxge_tx_ring_stats_t	tdc_stats;
	boolean_t		txchan_fatal = B_FALSE;
	nxge_status_t		status = NXGE_OK;
	tdmc_inj_par_err_t	par_err;
	uint32_t		value;

	NXGE_DEBUG_MSG((nxgep, RX2_CTL, "==> nxge_tx_err_evnts"));
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	channel = ldvp->channel;

	tx_rings = nxgep->tx_rings->rings;
	tx_ring_p = tx_rings[index];
	tdc_stats = tx_ring_p->tdc_stats;
	if ((cs.bits.ldw.pkt_size_err) || (cs.bits.ldw.pref_buf_par_err) ||
		(cs.bits.ldw.nack_pref) || (cs.bits.ldw.nack_pkt_rd) ||
		(cs.bits.ldw.conf_part_err) || (cs.bits.ldw.pkt_prt_err)) {
		if ((rs = npi_txdma_ring_error_get(handle, channel,
					&tdc_stats->errlog)) != NPI_SUCCESS)
			return (NXGE_ERROR | rs);
	}

	if (cs.bits.ldw.mbox_err) {
		tdc_stats->mbox_err++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_MBOX_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: mailbox", channel));
		txchan_fatal = B_TRUE;
	}
	if (cs.bits.ldw.pkt_size_err) {
		tdc_stats->pkt_size_err++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: pkt_size_err", channel));
		txchan_fatal = B_TRUE;
	}
	if (cs.bits.ldw.tx_ring_oflow) {
		tdc_stats->tx_ring_oflow++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_TX_RING_OFLOW);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: tx_ring_oflow", channel));
		txchan_fatal = B_TRUE;
	}
	if (cs.bits.ldw.pref_buf_par_err) {
		tdc_stats->pre_buf_par_err++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_PREF_BUF_PAR_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: pre_buf_par_err", channel));
		/* Clear error injection source for parity error */
		(void) npi_txdma_inj_par_error_get(handle, &value);
		par_err.value = value;
		par_err.bits.ldw.inject_parity_error &= ~(1 << channel);
		(void) npi_txdma_inj_par_error_set(handle, par_err.value);
		txchan_fatal = B_TRUE;
	}
	if (cs.bits.ldw.nack_pref) {
		tdc_stats->nack_pref++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_NACK_PREF);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: nack_pref", channel));
		txchan_fatal = B_TRUE;
	}
	if (cs.bits.ldw.nack_pkt_rd) {
		tdc_stats->nack_pkt_rd++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_NACK_PKT_RD);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: nack_pkt_rd", channel));
		txchan_fatal = B_TRUE;
	}
	if (cs.bits.ldw.conf_part_err) {
		tdc_stats->conf_part_err++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_CONF_PART_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: config_partition_err", channel));
		txchan_fatal = B_TRUE;
	}
	if (cs.bits.ldw.pkt_prt_err) {
		tdc_stats->pkt_part_err++;
		NXGE_FM_REPORT_ERROR(nxgep, nxgep->mac.portnum, channel,
					NXGE_FM_EREPORT_TDMC_PKT_PRT_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_tx_err_evnts(channel %d): "
			"fatal error: pkt_prt_err", channel));
		txchan_fatal = B_TRUE;
	}

	/* Clear error injection source in case this is an injected error */
	TXDMA_REG_WRITE64(nxgep->npi_handle, TDMC_INTR_DBG_REG, channel, 0);

	if (txchan_fatal) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_tx_err_evnts: "
			" fatal error on channel %d cs 0x%llx\n",
			channel, cs.value));
		status = nxge_txdma_fatal_err_recover(nxgep, channel,
								tx_ring_p);
		if (status == NXGE_OK) {
			FM_SERVICE_RESTORED(nxgep);
		}
	}

	NXGE_DEBUG_MSG((nxgep, RX2_CTL, "<== nxge_tx_err_evnts"));

	return (status);
}

static nxge_status_t
nxge_txdma_fatal_err_recover(p_nxge_t nxgep, uint16_t channel,
						p_tx_ring_t tx_ring_p)
{
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;
	p_tx_mbox_t	tx_mbox_p;
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_fatal_err_recover"));
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"Recovering from TxDMAChannel#%d error...", channel));

	/*
	 * Stop the dma channel waits for the stop done.
	 * If the stop done bit is not set, then create
	 * an error.
	 */

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxDMA channel stop..."));
	MUTEX_ENTER(&tx_ring_p->lock);
	rs = npi_txdma_channel_control(handle, TXDMA_STOP, channel);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_txdma_fatal_err_recover (channel %d): "
			"stop failed ", channel));
		goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxDMA channel reclaim..."));
	(void) nxge_txdma_reclaim(nxgep, tx_ring_p, 0);

	/*
	 * Reset TXDMA channel
	 */
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxDMA channel reset..."));
	if ((rs = npi_txdma_channel_control(handle, TXDMA_RESET, channel)) !=
						NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_txdma_fatal_err_recover (channel %d)"
			" reset channel failed 0x%x", channel, rs));
		goto fail;
	}

	/*
	 * Reset the tail (kick) register to 0.
	 * (Hardware will not reset it. Tx overflow fatal
	 * error if tail is not set to 0 after reset!
	 */
	TXDMA_REG_WRITE64(handle, TX_RING_KICK_REG, channel, 0);

	/* Restart TXDMA channel */

	/*
	 * Initialize the TXDMA channel specific FZC control
	 * configurations. These FZC registers are pertaining
	 * to each TX channel (i.e. logical pages).
	 */
	tx_mbox_p = nxge_txdma_get_mbox(nxgep, channel);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxDMA channel restart..."));
	status = nxge_init_fzc_txdma_channel(nxgep, channel,
						tx_ring_p, tx_mbox_p);
	if (status != NXGE_OK)
		goto fail;

	/*
	 * Initialize the event masks.
	 */
	tx_ring_p->tx_evmask.value = 0;
	status = nxge_init_txdma_channel_event_mask(nxgep, channel,
							&tx_ring_p->tx_evmask);
	if (status != NXGE_OK)
		goto fail;

	tx_ring_p->wr_index_wrap = B_FALSE;
	tx_ring_p->wr_index = 0;
	tx_ring_p->rd_index = 0;

	/*
	 * Load TXDMA descriptors, buffers, mailbox,
	 * initialise the DMA channels and
	 * enable each DMA channel.
	 */
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxDMA channel enable..."));
	status = nxge_enable_txdma_channel(nxgep, channel,
						tx_ring_p, tx_mbox_p);
	MUTEX_EXIT(&tx_ring_p->lock);
	if (status != NXGE_OK)
		goto fail;

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"Recovery Successful, TxDMAChannel#%d Restored",
			channel));
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_fatal_err_recover"));

	return (NXGE_OK);

fail:
	MUTEX_EXIT(&tx_ring_p->lock);
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"nxge_txdma_fatal_err_recover (channel %d): "
		"failed to recover this txdma channel", channel));
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "Recovery failed"));

	return (status);
}

nxge_status_t
nxge_tx_port_fatal_err_recover(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;
	nxge_status_t	status = NXGE_OK;
	p_tx_ring_t 	*tx_desc_rings;
	p_tx_rings_t	tx_rings;
	p_tx_ring_t	tx_ring_p;
	p_tx_mbox_t	tx_mbox_p;
	int		i, ndmas;
	uint16_t	channel;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_tx_port_fatal_err_recover"));
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"Recovering from TxPort error..."));

	/*
	 * Stop the dma channel waits for the stop done.
	 * If the stop done bit is not set, then create
	 * an error.
	 */

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxPort stop all DMA channels..."));

	tx_rings = nxgep->tx_rings;
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
		rs = npi_txdma_channel_control(handle, TXDMA_STOP, channel);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"==> nxge_txdma_fatal_err_recover (channel %d): "
			"stop failed ", channel));
			goto fail;
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxPort reclaim all DMA channels..."));

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		tx_ring_p = tx_rings->rings[i];
		(void) nxge_txdma_reclaim(nxgep, tx_ring_p, 0);
	}

	/*
	 * Reset TXDMA channel
	 */
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxPort reset all DMA channels..."));

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		channel = tx_desc_rings[i]->tdc;
		tx_ring_p = tx_rings->rings[i];
		if ((rs = npi_txdma_channel_control(handle, TXDMA_RESET,
				channel)) != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"==> nxge_txdma_fatal_err_recover (channel %d)"
				" reset channel failed 0x%x", channel, rs));
			goto fail;
		}

		/*
		 * Reset the tail (kick) register to 0.
		 * (Hardware will not reset it. Tx overflow fatal
		 * error if tail is not set to 0 after reset!
		 */

		TXDMA_REG_WRITE64(handle, TX_RING_KICK_REG, channel, 0);

	}

	/*
	 * Initialize the TXDMA channel specific FZC control
	 * configurations. These FZC registers are pertaining
	 * to each TX channel (i.e. logical pages).
	 */

	/* Restart TXDMA channels */

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxPort re-start all DMA channels..."));

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		channel = tx_desc_rings[i]->tdc;
		tx_ring_p = tx_rings->rings[i];
		tx_mbox_p = nxge_txdma_get_mbox(nxgep, channel);
		status = nxge_init_fzc_txdma_channel(nxgep, channel,
						tx_ring_p, tx_mbox_p);
		tx_ring_p->tx_evmask.value = 0;
		/*
		 * Initialize the event masks.
		 */
		status = nxge_init_txdma_channel_event_mask(nxgep, channel,
							&tx_ring_p->tx_evmask);

		tx_ring_p->wr_index_wrap = B_FALSE;
		tx_ring_p->wr_index = 0;
		tx_ring_p->rd_index = 0;

		if (status != NXGE_OK)
			goto fail;
		if (status != NXGE_OK)
			goto fail;
	}

	/*
	 * Load TXDMA descriptors, buffers, mailbox,
	 * initialise the DMA channels and
	 * enable each DMA channel.
	 */
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxPort re-enable all DMA channels..."));

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		channel = tx_desc_rings[i]->tdc;
		tx_ring_p = tx_rings->rings[i];
		tx_mbox_p = nxge_txdma_get_mbox(nxgep, channel);
		status = nxge_enable_txdma_channel(nxgep, channel,
						tx_ring_p, tx_mbox_p);
		if (status != NXGE_OK)
			goto fail;
	}

	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		tx_ring_p = tx_rings->rings[i];
		MUTEX_EXIT(&tx_ring_p->lock);
	}

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"Recovery Successful, TxPort Restored"));
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_tx_port_fatal_err_recover"));

	return (NXGE_OK);

fail:
	for (i = 0; i < ndmas; i++) {
		if (tx_desc_rings[i] == NULL) {
			continue;
		}
		tx_ring_p = tx_rings->rings[i];
		MUTEX_EXIT(&tx_ring_p->lock);
	}

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "Recovery failed"));
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
		"nxge_txdma_fatal_err_recover (channel %d): "
		"failed to recover this txdma channel"));

	return (status);
}

void
nxge_txdma_inject_err(p_nxge_t nxgep, uint32_t err_id, uint8_t chan)
{
	tdmc_intr_dbg_t		tdi;
	tdmc_inj_par_err_t	par_err;
	uint32_t		value;
	npi_handle_t		handle;

	switch (err_id) {

	case NXGE_FM_EREPORT_TDMC_PREF_BUF_PAR_ERR:
		handle = NXGE_DEV_NPI_HANDLE(nxgep);
		/* Clear error injection source for parity error */
		(void) npi_txdma_inj_par_error_get(handle, &value);
		par_err.value = value;
		par_err.bits.ldw.inject_parity_error &= ~(1 << chan);
		(void) npi_txdma_inj_par_error_set(handle, par_err.value);

		par_err.bits.ldw.inject_parity_error = (1 << chan);
		(void) npi_txdma_inj_par_error_get(handle, &value);
		par_err.value = value;
		par_err.bits.ldw.inject_parity_error |= (1 << chan);
		cmn_err(CE_NOTE, "!Write 0x%llx to TDMC_INJ_PAR_ERR_REG\n",
				(unsigned long long)par_err.value);
		(void) npi_txdma_inj_par_error_set(handle, par_err.value);
		break;

	case NXGE_FM_EREPORT_TDMC_MBOX_ERR:
	case NXGE_FM_EREPORT_TDMC_NACK_PREF:
	case NXGE_FM_EREPORT_TDMC_NACK_PKT_RD:
	case NXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR:
	case NXGE_FM_EREPORT_TDMC_TX_RING_OFLOW:
	case NXGE_FM_EREPORT_TDMC_CONF_PART_ERR:
	case NXGE_FM_EREPORT_TDMC_PKT_PRT_ERR:
		TXDMA_REG_READ64(nxgep->npi_handle, TDMC_INTR_DBG_REG,
			chan, &tdi.value);
		if (err_id == NXGE_FM_EREPORT_TDMC_PREF_BUF_PAR_ERR)
			tdi.bits.ldw.pref_buf_par_err = 1;
		else if (err_id == NXGE_FM_EREPORT_TDMC_MBOX_ERR)
			tdi.bits.ldw.mbox_err = 1;
		else if (err_id == NXGE_FM_EREPORT_TDMC_NACK_PREF)
			tdi.bits.ldw.nack_pref = 1;
		else if (err_id == NXGE_FM_EREPORT_TDMC_NACK_PKT_RD)
			tdi.bits.ldw.nack_pkt_rd = 1;
		else if (err_id == NXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR)
			tdi.bits.ldw.pkt_size_err = 1;
		else if (err_id == NXGE_FM_EREPORT_TDMC_TX_RING_OFLOW)
			tdi.bits.ldw.tx_ring_oflow = 1;
		else if (err_id == NXGE_FM_EREPORT_TDMC_CONF_PART_ERR)
			tdi.bits.ldw.conf_part_err = 1;
		else if (err_id == NXGE_FM_EREPORT_TDMC_PKT_PRT_ERR)
			tdi.bits.ldw.pkt_part_err = 1;
#if defined(__i386)
		cmn_err(CE_NOTE, "!Write 0x%llx to TDMC_INTR_DBG_REG\n",
				tdi.value);
#else
		cmn_err(CE_NOTE, "!Write 0x%lx to TDMC_INTR_DBG_REG\n",
				tdi.value);
#endif
		TXDMA_REG_WRITE64(nxgep->npi_handle, TDMC_INTR_DBG_REG,
			chan, tdi.value);

		break;
	}
}
