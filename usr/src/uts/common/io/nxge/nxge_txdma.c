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

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_txdma.h>
#include <sys/nxge/nxge_hio.h>
#include <npi_tx_rd64.h>
#include <npi_tx_wr64.h>
#include <sys/llc1.h>

uint32_t 	nxge_reclaim_pending = TXDMA_RECLAIM_PENDING_DEFAULT;
uint32_t	nxge_tx_minfree = 64;
uint32_t	nxge_tx_intr_thres = 0;
uint32_t	nxge_tx_max_gathers = TX_MAX_GATHER_POINTERS;
uint32_t	nxge_tx_tiny_pack = 1;
uint32_t	nxge_tx_use_bcopy = 1;

extern uint32_t 	nxge_tx_ring_size;
extern uint32_t 	nxge_bcopy_thresh;
extern uint32_t 	nxge_dvma_thresh;
extern uint32_t 	nxge_dma_stream_thresh;
extern dma_method_t 	nxge_force_dma;
extern uint32_t		nxge_cksum_offload;

/* Device register access attributes for PIO.  */
extern ddi_device_acc_attr_t nxge_dev_reg_acc_attr;
/* Device descriptor access attributes for DMA.  */
extern ddi_device_acc_attr_t nxge_dev_desc_dma_acc_attr;
/* Device buffer access attributes for DMA.  */
extern ddi_device_acc_attr_t nxge_dev_buf_dma_acc_attr;
extern ddi_dma_attr_t nxge_desc_dma_attr;
extern ddi_dma_attr_t nxge_tx_dma_attr;

extern void nxge_tx_ring_task(void *arg);

static nxge_status_t nxge_map_txdma(p_nxge_t, int);

static nxge_status_t nxge_txdma_hw_start(p_nxge_t, int);

static nxge_status_t nxge_map_txdma_channel(p_nxge_t, uint16_t,
	p_nxge_dma_common_t *, p_tx_ring_t *,
	uint32_t, p_nxge_dma_common_t *,
	p_tx_mbox_t *);
static void nxge_unmap_txdma_channel(p_nxge_t, uint16_t);

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
static nxge_status_t nxge_txdma_stop_channel(p_nxge_t, uint16_t);

static p_tx_ring_t nxge_txdma_get_ring(p_nxge_t, uint16_t);
static nxge_status_t nxge_tx_err_evnts(p_nxge_t, uint_t,
	p_nxge_ldv_t, tx_cs_t);
static p_tx_mbox_t nxge_txdma_get_mbox(p_nxge_t, uint16_t);
static nxge_status_t nxge_txdma_fatal_err_recover(p_nxge_t,
	uint16_t, p_tx_ring_t);

static void nxge_txdma_fixup_hung_channel(p_nxge_t nxgep,
    p_tx_ring_t ring_p, uint16_t channel);

nxge_status_t
nxge_init_txdma_channels(p_nxge_t nxgep)
{
	nxge_grp_set_t	*set = &nxgep->tx_set;
	int		i, tdc, count;
	nxge_grp_t	*group;
	dc_map_t	map;
	int		dev_gindex;

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "==> nxge_init_txdma_channels"));

	for (i = 0, count = 0; i < NXGE_LOGICAL_GROUP_MAX; i++) {
		if ((1 << i) & set->lg.map) {
			group = set->group[i];
			dev_gindex =
			    nxgep->pt_config.hw_config.def_mac_txdma_grpid + i;
			map = nxgep->pt_config.tdc_grps[dev_gindex].map;
			for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
				if ((1 << tdc) & map) {
					if ((nxge_grp_dc_add(nxgep,
					    group, VP_BOUND_TX, tdc)))
						goto init_txdma_channels_exit;
				}
			}
		}
		if (++count == set->lg.count)
			break;
	}

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "<== nxge_init_txdma_channels"));
	return (NXGE_OK);

init_txdma_channels_exit:
	for (i = 0, count = 0; i < NXGE_LOGICAL_GROUP_MAX; i++) {
		if ((1 << i) & set->lg.map) {
			group = set->group[i];
			dev_gindex =
			    nxgep->pt_config.hw_config.def_mac_txdma_grpid + i;
			map = nxgep->pt_config.tdc_grps[dev_gindex].map;
			for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
				if ((1 << tdc) & map) {
					nxge_grp_dc_remove(nxgep,
					    VP_BOUND_TX, tdc);
				}
			}
		}
		if (++count == set->lg.count)
			break;
	}

	return (NXGE_ERROR);

}

nxge_status_t
nxge_init_txdma_channel(
	p_nxge_t nxge,
	int channel)
{
	nxge_status_t status;

	NXGE_DEBUG_MSG((nxge, MEM2_CTL, "==> nxge_init_txdma_channel"));

	status = nxge_map_txdma(nxge, channel);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "<== nxge_init_txdma_channel: status 0x%x", status));
		(void) npi_txdma_dump_tdc_regs(nxge->npi_handle, channel);
		return (status);
	}

	status = nxge_txdma_hw_start(nxge, channel);
	if (status != NXGE_OK) {
		(void) nxge_unmap_txdma_channel(nxge, channel);
		(void) npi_txdma_dump_tdc_regs(nxge->npi_handle, channel);
		return (status);
	}

	if (!nxge->statsp->tdc_ksp[channel])
		nxge_setup_tdc_kstats(nxge, channel);

	NXGE_DEBUG_MSG((nxge, MEM2_CTL, "<== nxge_init_txdma_channel"));

	return (status);
}

void
nxge_uninit_txdma_channels(p_nxge_t nxgep)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "==> nxge_uninit_txdma_channels"));

	if (set->owned.map == 0) {
		NXGE_DEBUG_MSG((nxgep, MEM2_CTL,
		    "nxge_uninit_txdma_channels: no channels"));
		return;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			nxge_grp_dc_remove(nxgep, VP_BOUND_TX, tdc);
		}
	}

	NXGE_DEBUG_MSG((nxgep, MEM2_CTL, "<== nxge_uninit_txdma_channels"));
}

void
nxge_uninit_txdma_channel(p_nxge_t nxgep, int channel)
{
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_uninit_txdma_channel"));

	if (nxgep->statsp->tdc_ksp[channel]) {
		kstat_delete(nxgep->statsp->tdc_ksp[channel]);
		nxgep->statsp->tdc_ksp[channel] = 0;
	}

	if (nxge_txdma_stop_channel(nxgep, channel) != NXGE_OK)
		goto nxge_uninit_txdma_channel_exit;

	nxge_unmap_txdma_channel(nxgep, channel);

nxge_uninit_txdma_channel_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_uninit_txdma_channel"));
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

/*
 * nxge_reset_txdma_channel
 *
 *	Reset a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to reset.
 * 	reg_data	The current TX_CS.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txdma_channel_reset()
 *	npi_txdma_channel_control()
 *
 * Registers accessed:
 *	TX_CS		DMC+0x40028 Transmit Control And Status
 *	TX_RING_KICK	DMC+0x40018 Transmit Ring Kick
 *
 * Context:
 *	Any domain
 */
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

/*
 * nxge_init_txdma_channel_event_mask
 *
 *	Enable interrupts for a set of events.
 *
 * Arguments:
 * 	nxgep
 * 	channel	The channel to map.
 * 	mask_p	The events to enable.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txdma_event_mask()
 *
 * Registers accessed:
 *	TX_ENT_MSK	DMC+0x40020 Transmit Event Mask
 *
 * Context:
 *	Any domain
 */
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

/*
 * nxge_init_txdma_channel_cntl_stat
 *
 *	Stop a TDC.  If at first we don't succeed, inject an error.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to stop.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txdma_control_status()
 *
 * Registers accessed:
 *	TX_CS		DMC+0x40028 Transmit Control And Status
 *
 * Context:
 *	Any domain
 */
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

/*
 * nxge_enable_txdma_channel
 *
 *	Enable a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to enable.
 * 	tx_desc_p	channel's transmit descriptor ring.
 * 	mbox_p		channel's mailbox,
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txdma_ring_config()
 *	npi_txdma_mbox_config()
 *	npi_txdma_channel_init_enable()
 *
 * Registers accessed:
 *	TX_RNG_CFIG	DMC+0x40000 Transmit Ring Configuration
 *	TXDMA_MBH	DMC+0x40030 TXDMA Mailbox High
 *	TXDMA_MBL	DMC+0x40038 TXDMA Mailbox Low
 *	TX_CS		DMC+0x40028 Transmit Control And Status
 *
 * Context:
 *	Any domain
 */
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

	if (isLDOMguest(nxgep)) {
		/* Add interrupt handler for this channel. */
		if (nxge_hio_intr_add(nxgep, VP_BOUND_TX, channel) != NXGE_OK)
			return (NXGE_ERROR);
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
		p_tx_pkt_hdr_all_t pkthdrp,
		t_uscalar_t start_offset,
		t_uscalar_t stuff_offset)
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

	hdrp->value |= (((uint64_t)npads) << TX_PKT_HEADER_PAD_SHIFT);

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
			hdrp->value |= TX_CKSUM_EN_PKT_TYPE_TCP;
			hdrp->value |=
			    (((uint64_t)(start_offset >> 1)) <<
			    TX_PKT_HEADER_L4START_SHIFT);
			hdrp->value |=
			    (((uint64_t)(stuff_offset >> 1)) <<
			    TX_PKT_HEADER_L4STUFF_SHIFT);

			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> nxge_tx_pkt_hdr_init: TCP CKSUM "
			    "value 0x%llx", hdrp->value));
		}

		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_tx_pkt_hdr_init: TCP "
		    "value 0x%llx", hdrp->value));
		break;

	case IPPROTO_UDP:
		NXGE_DEBUG_MSG((NULL, TX_CTL, "==> nxge_fill_tx_hdr: UDP"));
		if (l4_cksum) {
			if (!nxge_cksum_offload) {
				uint16_t	*up;
				uint16_t	cksum;
				t_uscalar_t	stuff_len;

				/*
				 * The checksum field has the
				 * partial checksum.
				 * IP_CSUM() macro calls ip_cksum() which
				 * can add in the partial checksum.
				 */
				cksum = IP_CSUM(mp, start_offset, 0);
				stuff_len = stuff_offset;
				nmp = mp;
				mblk_len = MBLKL(nmp);
				while ((nmp != NULL) &&
				    (mblk_len < stuff_len)) {
					stuff_len -= mblk_len;
					nmp = nmp->b_cont;
					if (nmp)
						mblk_len = MBLKL(nmp);
				}
				ASSERT(nmp);
				up = (uint16_t *)(nmp->b_rptr + stuff_len);

				*up = cksum;
				hdrp->value &= ~TX_CKSUM_EN_PKT_TYPE_UDP;
				NXGE_DEBUG_MSG((NULL, TX_CTL,
				    "==> nxge_tx_pkt_hdr_init: UDP offset %d "
				    "use sw cksum "
				    "write to $%p cksum 0x%x content up 0x%x",
				    stuff_len,
				    up,
				    cksum,
				    *up));
			} else {
				/* Hardware will compute the full checksum */
				hdrp->value |= TX_CKSUM_EN_PKT_TYPE_UDP;
				hdrp->value |=
				    (((uint64_t)(start_offset >> 1)) <<
				    TX_PKT_HEADER_L4START_SHIFT);
				hdrp->value |=
				    (((uint64_t)(stuff_offset >> 1)) <<
				    TX_PKT_HEADER_L4STUFF_SHIFT);

				NXGE_DEBUG_MSG((NULL, TX_CTL,
				    "==> nxge_tx_pkt_hdr_init: UDP offset %d "
				    " use partial checksum "
				    "cksum 0x%x ",
				    "value 0x%llx",
				    stuff_offset,
				    IP_CSUM(mp, start_offset, 0),
				    hdrp->value));
			}
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

				nsegs = 1;
				NXGE_DEBUG_MSG((NULL, TX_CTL,
				    "==> nxge_tx_pkt_nmblocks: "
				    "len %d pkt_len %d nmblks %d nsegs %d",
				    len, pkt_len, nmblks, nsegs));
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
			tdc_stats->obytes += (pkt_len - TX_PKT_HEADER_SIZE);
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

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "<== nxge_txdma_reclaim status = 0x%08x", status));

	return (status);
}

/*
 * nxge_tx_intr
 *
 *	Process a TDC interrupt
 *
 * Arguments:
 * 	arg1	A Logical Device state Vector (LSV) data structure.
 * 	arg2	nxge_t *
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txdma_control_status()
 *	npi_intr_ldg_mgmt_set()
 *
 *	nxge_tx_err_evnts()
 *	nxge_txdma_reclaim()
 *
 * Registers accessed:
 *	TX_CS		DMC+0x40028 Transmit Control And Status
 *	PIO_LDSV
 *
 * Context:
 *	Any domain
 */
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

	if ((!(nxgep->drv_state & STATE_HW_INITIALIZED)) ||
	    (nxgep->nxge_mac_state != NXGE_MAC_STARTED)) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
		    "<== nxge_tx_intr: interface not started or intialized"));
		return (DDI_INTR_CLAIMED);
	}

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

		nxge_tx_ring_task((void *)tx_ring_p);
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
			if (isLDOMguest(nxgep)) {
				nxge_hio_ldgimgn(nxgep, ldgp);
			} else {
				(void) npi_intr_ldg_mgmt_set(handle, ldgp->ldg,
				    B_TRUE, ldgp->ldg_timer);
			}
		}
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_tx_intr"));
	serviced = DDI_INTR_CLAIMED;
	return (serviced);
}

void
nxge_txdma_stop(p_nxge_t nxgep)	/* Dead */
{
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_stop"));

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_STOP);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_stop"));
}

void
nxge_txdma_stop_start(p_nxge_t nxgep) /* Dead */
{
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_stop_start"));

	(void) nxge_txdma_stop(nxgep);

	(void) nxge_fixup_txdma_rings(nxgep);
	(void) nxge_txdma_hw_mode(nxgep, NXGE_DMA_START);
	(void) nxge_tx_mac_enable(nxgep);
	(void) nxge_txdma_hw_kick(nxgep);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_stop_start"));
}

npi_status_t
nxge_txdma_channel_disable(
	nxge_t *nxge,
	int channel)
{
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxge);
	npi_status_t	rs;
	tdmc_intr_dbg_t	intr_dbg;

	/*
	 * Stop the dma channel and wait for the stop-done.
	 * If the stop-done bit is not present, then force
	 * an error so TXC will stop.
	 * All channels bound to this port need to be stopped
	 * and reset after injecting an interrupt error.
	 */
	rs = npi_txdma_channel_disable(handle, channel);
	NXGE_DEBUG_MSG((nxge, MEM3_CTL,
	    "==> nxge_txdma_channel_disable(%d) "
	    "rs 0x%x", channel, rs));
	if (rs != NPI_SUCCESS) {
		/* Inject any error */
		intr_dbg.value = 0;
		intr_dbg.bits.ldw.nack_pref = 1;
		NXGE_DEBUG_MSG((nxge, MEM3_CTL,
		    "==> nxge_txdma_hw_mode: "
		    "channel %d (stop failed 0x%x) "
		    "(inject err)", rs, channel));
		(void) npi_txdma_inj_int_error_set(
		    handle, channel, &intr_dbg);
		rs = npi_txdma_channel_disable(handle, channel);
		NXGE_DEBUG_MSG((nxge, MEM3_CTL,
		    "==> nxge_txdma_hw_mode: "
		    "channel %d (stop again 0x%x) "
		    "(after inject err)",
		    rs, channel));
	}

	return (rs);
}

/*
 * nxge_txdma_hw_mode
 *
 *	Toggle all TDCs on (enable) or off (disable).
 *
 * Arguments:
 * 	nxgep
 * 	enable	Enable or disable a TDC.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txdma_channel_enable(TX_CS)
 *	npi_txdma_channel_disable(TX_CS)
 *	npi_txdma_inj_int_error_set(TDMC_INTR_DBG)
 *
 * Registers accessed:
 *	TX_CS		DMC+0x40028 Transmit Control And Status
 *	TDMC_INTR_DBG	DMC + 0x40060 Transmit DMA Interrupt Debug
 *
 * Context:
 *	Any domain
 */
nxge_status_t
nxge_txdma_hw_mode(p_nxge_t nxgep, boolean_t enable)
{
	nxge_grp_set_t *set = &nxgep->tx_set;

	npi_handle_t	handle;
	nxge_status_t	status;
	npi_status_t	rs;
	int		tdc;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
	    "==> nxge_txdma_hw_mode: enable mode %d", enable));

	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_txdma_mode: not initialized"));
		return (NXGE_ERROR);
	}

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_txdma_hw_mode: NULL ring pointer(s)"));
		return (NXGE_ERROR);
	}

	/* Enable or disable all of the TDCs owned by us. */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				    "==> nxge_txdma_hw_mode: channel %d", tdc));
				if (enable) {
					rs = npi_txdma_channel_enable
					    (handle, tdc);
					NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
					    "==> nxge_txdma_hw_mode: "
					    "channel %d (enable) rs 0x%x",
					    tdc, rs));
				} else {
					rs = nxge_txdma_channel_disable
					    (nxgep, tdc);
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

/*
 * nxge_txdma_stop_inj_err
 *
 *	Stop a TDC.  If at first we don't succeed, inject an error.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to stop.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txdma_channel_disable()
 *	npi_txdma_inj_int_error_set()
 * #if defined(NXGE_DEBUG)
 *	nxge_txdma_regs_dump_channels(nxgep);
 * #endif
 *
 * Registers accessed:
 *	TX_CS		DMC+0x40028 Transmit Control And Status
 *	TDMC_INTR_DBG	DMC + 0x40060 Transmit DMA Interrupt Debug
 *
 * Context:
 *	Any domain
 */
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

/*ARGSUSED*/
void
nxge_fixup_txdma_rings(p_nxge_t nxgep)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_fixup_txdma_rings"));

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_fixup_txdma_rings: NULL ring pointer(s)"));
		return;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				    "==> nxge_fixup_txdma_rings: channel %d",
				    tdc));
				nxge_txdma_fixup_channel(nxgep, ring, tdc);
			}
		}
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
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_hw_kick"));

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_txdma_hw_kick: NULL ring pointer(s)"));
		return;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
				    "==> nxge_txdma_hw_kick: channel %d", tdc));
				nxge_txdma_hw_kick_channel(nxgep, ring, tdc);
			}
		}
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

/*
 * nxge_check_tx_hang
 *
 *	Check the state of all TDCs belonging to nxgep.
 *
 * Arguments:
 * 	nxgep
 *
 * Notes:
 *	Called by nxge_hw.c:nxge_check_hw_state().
 *
 * NPI/NXGE function calls:
 *
 * Registers accessed:
 *
 * Context:
 *	Any domain
 */
/*ARGSUSED*/
void
nxge_check_tx_hang(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_check_tx_hang"));

	if ((!(nxgep->drv_state & STATE_HW_INITIALIZED)) ||
	    (nxgep->nxge_mac_state != NXGE_MAC_STARTED)) {
		goto nxge_check_tx_hang_exit;
	}

	/*
	 * Needs inputs from hardware for regs:
	 *	head index had not moved since last timeout.
	 *	packets not transmitted or stuffed registers.
	 */
	if (nxge_txdma_hung(nxgep)) {
		nxge_fixup_hung_txdma_rings(nxgep);
	}

nxge_check_tx_hang_exit:
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_check_tx_hang"));
}

/*
 * nxge_txdma_hung
 *
 *	Reset a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to reset.
 * 	reg_data	The current TX_CS.
 *
 * Notes:
 *	Called by nxge_check_tx_hang()
 *
 * NPI/NXGE function calls:
 *	nxge_txdma_channel_hung()
 *
 * Registers accessed:
 *
 * Context:
 *	Any domain
 */
int
nxge_txdma_hung(p_nxge_t nxgep)
{
	nxge_grp_set_t	*set = &nxgep->tx_set;
	int		tdc;
	boolean_t	shared;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_hung"));

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_txdma_hung: NULL ring pointer(s)"));
		return (B_FALSE);
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		/*
		 * Grab the shared state of the TDC.
		 */
		if (isLDOMservice(nxgep)) {
			nxge_hio_data_t *nhd =
			    (nxge_hio_data_t *)nxgep->nxge_hw_p->hio;

			MUTEX_ENTER(&nhd->lock);
			shared = nxgep->tdc_is_shared[tdc];
			MUTEX_EXIT(&nhd->lock);
		} else {
			shared = B_FALSE;
		}

		/*
		 * Now, process continue to process.
		 */
		if (((1 << tdc) & set->owned.map) && !shared) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				if (nxge_txdma_channel_hung(nxgep, ring, tdc)) {
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_txdma_hung: TDC %d hung",
					    tdc));
					return (B_TRUE);
				}
			}
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_hung"));

	return (B_FALSE);
}

/*
 * nxge_txdma_channel_hung
 *
 *	Reset a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	ring		<channel>'s ring.
 * 	channel		The channel to reset.
 *
 * Notes:
 *	Called by nxge_txdma.c:nxge_txdma_hung()
 *
 * NPI/NXGE function calls:
 *	npi_txdma_ring_head_get()
 *
 * Registers accessed:
 *	TX_RING_HDL	DMC+0x40010 Transmit Ring Head Low
 *
 * Context:
 *	Any domain
 */
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

/*
 * nxge_fixup_hung_txdma_rings
 *
 *	Disable a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to reset.
 * 	reg_data	The current TX_CS.
 *
 * Notes:
 *	Called by nxge_check_tx_hang()
 *
 * NPI/NXGE function calls:
 *	npi_txdma_ring_head_get()
 *
 * Registers accessed:
 *	TX_RING_HDL	DMC+0x40010 Transmit Ring Head Low
 *
 * Context:
 *	Any domain
 */
/*ARGSUSED*/
void
nxge_fixup_hung_txdma_rings(p_nxge_t nxgep)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_fixup_hung_txdma_rings"));

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_fixup_hung_txdma_rings: NULL ring pointer(s)"));
		return;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				nxge_txdma_fixup_hung_channel(nxgep, ring, tdc);
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "==> nxge_fixup_hung_txdma_rings: TDC %d",
				    tdc));
			}
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_fixup_hung_txdma_rings"));
}

/*
 * nxge_txdma_fixup_hung_channel
 *
 *	'Fix' a hung TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to fix.
 *
 * Notes:
 *	Called by nxge_fixup_hung_txdma_rings()
 *
 *	1. Reclaim the TDC.
 *	2. Disable the TDC.
 *
 * NPI/NXGE function calls:
 *	nxge_txdma_reclaim()
 *	npi_txdma_channel_disable(TX_CS)
 *	npi_txdma_inj_int_error_set(TDMC_INTR_DBG)
 *
 * Registers accessed:
 *	TX_CS		DMC+0x40028 Transmit Control And Status
 *	TDMC_INTR_DBG	DMC + 0x40060 Transmit DMA Interrupt Debug
 *
 * Context:
 *	Any domain
 */
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
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_reclaim_rings"));

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_fixup_hung_txdma_rings: NULL ring pointer(s)"));
		return;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "==> nxge_reclaim_rings: TDC %d", tdc));
				MUTEX_ENTER(&ring->lock);
				(void) nxge_txdma_reclaim(nxgep, ring, 0);
				MUTEX_EXIT(&ring->lock);
			}
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_reclaim_rings"));
}

void
nxge_txdma_regs_dump_channels(p_nxge_t nxgep)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	npi_handle_t handle;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_regs_dump_channels"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	if (!isLDOMguest(nxgep)) {
		(void) npi_txdma_dump_fzc_regs(handle);

		/* Dump TXC registers. */
		(void) npi_txc_dump_fzc_regs(handle);
		(void) npi_txc_dump_port_fzc_regs(handle, nxgep->function_num);
	}

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_fixup_hung_txdma_rings: NULL ring pointer(s)"));
		return;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				NXGE_DEBUG_MSG((nxgep, TX_CTL,
				    "==> nxge_txdma_regs_dump_channels: "
				    "TDC %d", tdc));
				(void) npi_txdma_dump_tdc_regs(handle, tdc);

				/* Dump TXC registers, if able to. */
				if (!isLDOMguest(nxgep)) {
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "==> nxge_txdma_regs_dump_channels:"
					    " FZC TDC %d", tdc));
					(void) npi_txc_dump_tdc_fzc_regs
					    (handle, tdc);
				}
				nxge_txdma_regs_dump(nxgep, tdc);
			}
		}
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
 * nxge_tdc_hvio_setup
 *
 *	I'm not exactly sure what this code does.
 *
 * Arguments:
 * 	nxgep
 * 	channel	The channel to map.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	na
 *
 * Context:
 *	Service domain?
 */
#if defined(sun4v) && defined(NIU_LP_WORKAROUND)
static void
nxge_tdc_hvio_setup(
	nxge_t *nxgep, int channel)
{
	nxge_dma_common_t	*data;
	nxge_dma_common_t	*control;
	tx_ring_t 		*ring;

	ring = nxgep->tx_rings->rings[channel];
	data = nxgep->tx_buf_pool_p->dma_buf_pool_p[channel];

	ring->hv_set = B_FALSE;

	ring->hv_tx_buf_base_ioaddr_pp =
	    (uint64_t)data->orig_ioaddr_pp;
	ring->hv_tx_buf_ioaddr_size =
	    (uint64_t)data->orig_alength;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma_channel: "
	    "hv data buf base io $%p size 0x%llx (%d) buf base io $%p "
	    "orig vatopa base io $%p orig_len 0x%llx (%d)",
	    ring->hv_tx_buf_base_ioaddr_pp,
	    ring->hv_tx_buf_ioaddr_size, ring->hv_tx_buf_ioaddr_size,
	    data->ioaddr_pp, data->orig_vatopa,
	    data->orig_alength, data->orig_alength));

	control = nxgep->tx_cntl_pool_p->dma_buf_pool_p[channel];

	ring->hv_tx_cntl_base_ioaddr_pp =
	    (uint64_t)control->orig_ioaddr_pp;
	ring->hv_tx_cntl_ioaddr_size =
	    (uint64_t)control->orig_alength;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma_channel: "
	    "hv cntl base io $%p orig ioaddr_pp ($%p) "
	    "orig vatopa ($%p) size 0x%llx (%d 0x%x)",
	    ring->hv_tx_cntl_base_ioaddr_pp,
	    control->orig_ioaddr_pp, control->orig_vatopa,
	    ring->hv_tx_cntl_ioaddr_size,
	    control->orig_alength, control->orig_alength));
}
#endif

static nxge_status_t
nxge_map_txdma(p_nxge_t nxgep, int channel)
{
	nxge_dma_common_t	**pData;
	nxge_dma_common_t	**pControl;
	tx_ring_t 		**pRing, *ring;
	tx_mbox_t		**mailbox;
	uint32_t		num_chunks;

	nxge_status_t		status = NXGE_OK;

	NXGE_ERROR_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma"));

	if (!nxgep->tx_cntl_pool_p->buf_allocated) {
		if (nxge_alloc_tx_mem_pool(nxgep) != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "<== nxge_map_txdma: buf not allocated"));
			return (NXGE_ERROR);
		}
	}

	if (nxge_alloc_txb(nxgep, channel) != NXGE_OK)
		return (NXGE_ERROR);

	num_chunks = nxgep->tx_buf_pool_p->num_chunks[channel];
	pData = &nxgep->tx_buf_pool_p->dma_buf_pool_p[channel];
	pControl = &nxgep->tx_cntl_pool_p->dma_buf_pool_p[channel];
	pRing = &nxgep->tx_rings->rings[channel];
	mailbox = &nxgep->tx_mbox_areas_p->txmbox_areas_p[channel];

	NXGE_ERROR_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma: "
	    "tx_rings $%p tx_desc_rings $%p",
	    nxgep->tx_rings, nxgep->tx_rings->rings));

	/*
	 * Map descriptors from the buffer pools for <channel>.
	 */

	/*
	 * Set up and prepare buffer blocks, descriptors
	 * and mailbox.
	 */
	status = nxge_map_txdma_channel(nxgep, channel,
	    pData, pRing, num_chunks, pControl, mailbox);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, MEM3_CTL,
		    "==> nxge_map_txdma(%d): nxge_map_txdma_channel() "
		    "returned 0x%x",
		    nxgep, channel, status));
		return (status);
	}

	ring = *pRing;

	ring->index = (uint16_t)channel;
	ring->tdc_stats = &nxgep->statsp->tdc_stats[channel];

#if defined(sun4v) && defined(NIU_LP_WORKAROUND)
	if (isLDOMguest(nxgep)) {
		(void) nxge_tdc_lp_conf(nxgep, channel);
	} else {
		nxge_tdc_hvio_setup(nxgep, channel);
	}
#endif

	NXGE_ERROR_MSG((nxgep, MEM3_CTL, "==> nxge_map_txdma: "
	    "(status 0x%x channel %d)", status, channel));

	return (status);
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
	NXGE_ERROR_MSG((nxgep, MEM3_CTL,
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
	NXGE_ERROR_MSG((nxgep, MEM3_CTL,
	    "==> nxge_map_txdma_channel: unmap buf"
	    "(status 0x%x channel %d)",
	    status, channel));
	nxge_unmap_txdma_channel_buf_ring(nxgep, *tx_desc_p);

nxge_map_txdma_channel_exit:
	NXGE_ERROR_MSG((nxgep, MEM3_CTL,
	    "<== nxge_map_txdma_channel: "
	    "(status 0x%x channel %d)",
	    status, channel));

	return (status);
}

/*ARGSUSED*/
static void
nxge_unmap_txdma_channel(p_nxge_t nxgep, uint16_t channel)
{
	tx_ring_t *ring;
	tx_mbox_t *mailbox;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
	    "==> nxge_unmap_txdma_channel (channel %d)", channel));
	/*
	 * unmap tx block ring, and mailbox.
	 */
	ring = nxgep->tx_rings->rings[channel];
	mailbox = nxgep->tx_mbox_areas_p->txmbox_areas_p[channel];

	(void) nxge_unmap_txdma_channel_cfg_ring(nxgep, ring, mailbox);

	/* unmap buffer blocks */
	(void) nxge_unmap_txdma_channel_buf_ring(nxgep, ring);

	nxge_free_txb(nxgep, channel);

	/*
	 * Cleanup the reference to the ring now that it does not exist.
	 */
	nxgep->tx_rings->rings[channel] = NULL;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL, "<== nxge_unmap_txdma_channel"));
}

/*
 * nxge_map_txdma_channel_cfg_ring
 *
 *	Map a TDC into our kernel space.
 *	This function allocates all of the per-channel data structures.
 *
 * Arguments:
 * 	nxgep
 * 	dma_channel	The channel to map.
 *	dma_cntl_p
 *	tx_ring_p	dma_channel's transmit ring
 *	tx_mbox_p	dma_channel's mailbox
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	nxge_setup_dma_common()
 *
 * Registers accessed:
 *	none.
 *
 * Context:
 *	Any domain
 */
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

/*
 * nxge_map_txdma_channel_buf_ring
 *
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to map.
 *	dma_buf_p
 *	tx_desc_p	channel's descriptor ring
 *	num_chunks
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	nxge_setup_dma_common()
 *
 * Registers accessed:
 *	none.
 *
 * Context:
 *	Any domain
 */
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
	char			qname[TASKQ_NAMELEN];

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

	(void) atomic_swap_32(&tx_ring_p->tx_ring_offline, NXGE_TX_RING_ONLINE);
	tx_ring_p->tx_ring_busy = B_FALSE;
	tx_ring_p->nxgep = nxgep;
	tx_ring_p->tx_ring_handle = (mac_ring_handle_t)NULL;
	(void) snprintf(qname, TASKQ_NAMELEN, "tx_%d_%d",
	    nxgep->instance, channel);
	tx_ring_p->taskq = ddi_taskq_create(nxgep->dip, qname, 1,
	    TASKQ_DEFAULTPRI, 0);
	if (tx_ring_p->taskq == NULL) {
		goto nxge_map_txdma_channel_buf_ring_fail1;
	}

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

	/*
	 * Since the serialization thread, timer thread and
	 * interrupt thread can all call the transmit reclaim,
	 * the unmapping function needs to acquire the lock
	 * to free those buffers which were transmitted
	 * by the hardware already.
	 */
	MUTEX_ENTER(&tx_ring_p->lock);
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_unmap_txdma_channel_buf_ring (reclaim): "
	    "channel %d",
	    tx_ring_p->tdc));
	(void) nxge_txdma_reclaim(nxgep, tx_ring_p, 0);

	for (i = 0; i < tx_ring_p->tx_ring_size; i++) {
		tx_msg_p = &tx_msg_ring[i];
		if (tx_msg_p->tx_message != NULL) {
			freemsg(tx_msg_p->tx_message);
			tx_msg_p->tx_message = NULL;
		}
	}

	for (i = 0; i < tx_ring_p->tx_ring_size; i++) {
		if (tx_msg_ring[i].dma_handle != NULL) {
			ddi_dma_free_handle(&tx_msg_ring[i].dma_handle);
		}
		tx_msg_ring[i].dma_handle = NULL;
	}

	MUTEX_EXIT(&tx_ring_p->lock);

	if (tx_ring_p->taskq) {
		ddi_taskq_destroy(tx_ring_p->taskq);
		tx_ring_p->taskq = NULL;
	}

	MUTEX_DESTROY(&tx_ring_p->lock);
	KMEM_FREE(tx_msg_ring, sizeof (tx_msg_t) * tx_ring_p->tx_ring_size);
	KMEM_FREE(tx_ring_p, sizeof (tx_ring_t));

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
	    "<== nxge_unmap_txdma_channel_buf_ring"));
}

static nxge_status_t
nxge_txdma_hw_start(p_nxge_t nxgep, int channel)
{
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

	NXGE_ERROR_MSG((nxgep, MEM3_CTL, "==> nxge_txdma_hw_start: "
	    "tx_rings $%p tx_desc_rings $%p", tx_rings, tx_desc_rings));

	tx_mbox_areas_p = nxgep->tx_mbox_areas_p;
	tx_mbox_p = tx_mbox_areas_p->txmbox_areas_p;

	status = nxge_txdma_start_channel(nxgep, channel,
	    (p_tx_ring_t)tx_desc_rings[channel],
	    (p_tx_mbox_t)tx_mbox_p[channel]);
	if (status != NXGE_OK) {
		goto nxge_txdma_hw_start_fail1;
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
	    "(status 0x%x channel %d)", status, channel));

nxge_txdma_hw_start_exit:
	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
	    "==> nxge_txdma_hw_start: (status 0x%x)", status));

	return (status);
}

/*
 * nxge_txdma_start_channel
 *
 *	Start a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to start.
 * 	tx_ring_p	channel's transmit descriptor ring.
 * 	tx_mbox_p	channel' smailbox.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	nxge_reset_txdma_channel()
 *	nxge_init_txdma_channel_event_mask()
 *	nxge_enable_txdma_channel()
 *
 * Registers accessed:
 *	none directly (see functions above).
 *
 * Context:
 *	Any domain
 */
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
	if (!isLDOMguest(nxgep)) {
		status = nxge_init_fzc_txdma_channel(nxgep, channel,
		    tx_ring_p, tx_mbox_p);
		if (status != NXGE_OK) {
			goto nxge_txdma_start_channel_exit;
		}
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

/*
 * nxge_txdma_stop_channel
 *
 *	Stop a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to stop.
 * 	tx_ring_p	channel's transmit descriptor ring.
 * 	tx_mbox_p	channel' smailbox.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	nxge_txdma_stop_inj_err()
 *	nxge_reset_txdma_channel()
 *	nxge_init_txdma_channel_event_mask()
 *	nxge_init_txdma_channel_cntl_stat()
 *	nxge_disable_txdma_channel()
 *
 * Registers accessed:
 *	none directly (see functions above).
 *
 * Context:
 *	Any domain
 */
/*ARGSUSED*/
static nxge_status_t
nxge_txdma_stop_channel(p_nxge_t nxgep, uint16_t channel)
{
	p_tx_ring_t tx_ring_p;
	int status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MEM3_CTL,
	    "==> nxge_txdma_stop_channel: channel %d", channel));

	/*
	 * Stop (disable) TXDMA and TXC (if stop bit is set
	 * and STOP_N_GO bit not set, the TXDMA reset state will
	 * not be set if reset TXDMA.
	 */
	(void) nxge_txdma_stop_inj_err(nxgep, channel);

	if (nxgep->tx_rings == NULL) {
		status = NXGE_ERROR;
		goto nxge_txdma_stop_channel_exit;
	}

	tx_ring_p = nxgep->tx_rings->rings[channel];
	if (tx_ring_p == NULL) {
		status = NXGE_ERROR;
		goto nxge_txdma_stop_channel_exit;
	}

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

	tx_mbox_p = nxgep->tx_mbox_areas_p->txmbox_areas_p[channel];

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

/*
 * nxge_txdma_get_ring
 *
 *	Get the ring for a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *
 * Registers accessed:
 *
 * Context:
 *	Any domain
 */
static p_tx_ring_t
nxge_txdma_get_ring(p_nxge_t nxgep, uint16_t channel)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_get_ring"));

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_txdma_get_ring: NULL ring pointer(s)"));
		goto return_null;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				if (channel == ring->tdc) {
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "<== nxge_txdma_get_ring: "
					    "tdc %d ring $%p", tdc, ring));
					return (ring);
				}
			}
		}
	}

return_null:
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_get_ring: "
	    "ring not found"));

	return (NULL);
}

/*
 * nxge_txdma_get_mbox
 *
 *	Get the mailbox for a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	channel
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *
 * Registers accessed:
 *
 * Context:
 *	Any domain
 */
static p_tx_mbox_t
nxge_txdma_get_mbox(p_nxge_t nxgep, uint16_t channel)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txdma_get_mbox"));

	if (nxgep->tx_mbox_areas_p == 0 ||
	    nxgep->tx_mbox_areas_p->txmbox_areas_p == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_txdma_get_mbox: NULL mailbox pointer(s)"));
		goto return_null;
	}

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_txdma_get_mbox: NULL ring pointer(s)"));
		goto return_null;
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				if (channel == ring->tdc) {
					tx_mbox_t *mailbox = nxgep->
					    tx_mbox_areas_p->
					    txmbox_areas_p[tdc];
					NXGE_DEBUG_MSG((nxgep, TX_CTL,
					    "<== nxge_txdma_get_mbox: tdc %d "
					    "ring $%p", tdc, mailbox));
					return (mailbox);
				}
			}
		}
	}

return_null:
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txdma_get_mbox: "
	    "mailbox not found"));

	return (NULL);
}

/*
 * nxge_tx_err_evnts
 *
 *	Recover a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	index	The index to the TDC ring.
 * 	ldvp	Used to get the channel number ONLY.
 * 	cs	A copy of the bits from TX_CS.
 *
 * Notes:
 *	Calling tree:
 *	 nxge_tx_intr()
 *
 * NPI/NXGE function calls:
 *	npi_txdma_ring_error_get()
 *	npi_txdma_inj_par_error_get()
 *	nxge_txdma_fatal_err_recover()
 *
 * Registers accessed:
 *	TX_RNG_ERR_LOGH	DMC+0x40048 Transmit Ring Error Log High
 *	TX_RNG_ERR_LOGL DMC+0x40050 Transmit Ring Error Log Low
 *	TDMC_INJ_PAR_ERR (FZC_DMC + 0x45040) TDMC Inject Parity Error
 *
 * Context:
 *	Any domain	XXX Remove code which accesses TDMC_INJ_PAR_ERR.
 */
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

	NXGE_DEBUG_MSG((nxgep, TX2_CTL, "==> nxge_tx_err_evnts"));
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

	NXGE_DEBUG_MSG((nxgep, TX2_CTL, "<== nxge_tx_err_evnts"));

	return (status);
}

static nxge_status_t
nxge_txdma_fatal_err_recover(
	p_nxge_t nxgep,
	uint16_t channel,
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

	if (!isLDOMguest(nxgep)) {
		tx_mbox_p = nxge_txdma_get_mbox(nxgep, channel);

		// XXX This is a problem in HIO!
		/*
		 * Initialize the TXDMA channel specific FZC control
		 * configurations. These FZC registers are pertaining
		 * to each TX channel (i.e. logical pages).
		 */
		NXGE_DEBUG_MSG((nxgep, TX_CTL, "TxDMA channel restart..."));
		status = nxge_init_fzc_txdma_channel(nxgep, channel,
		    tx_ring_p, tx_mbox_p);
		if (status != NXGE_OK)
			goto fail;
	}

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

/*
 * nxge_tx_port_fatal_err_recover
 *
 *	Attempt to recover from a fatal port error.
 *
 * Arguments:
 * 	nxgep
 *
 * Notes:
 *	How would a guest do this?
 *
 * NPI/NXGE function calls:
 *
 * Registers accessed:
 *
 * Context:
 *	Service domain
 */
nxge_status_t
nxge_tx_port_fatal_err_recover(p_nxge_t nxgep)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	nxge_channel_t tdc;

	tx_ring_t	*ring;
	tx_mbox_t	*mailbox;

	npi_handle_t	handle;
	nxge_status_t	status;
	npi_status_t	rs;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_tx_port_fatal_err_recover"));
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "Recovering from TxPort error..."));

	if (isLDOMguest(nxgep)) {
		return (NXGE_OK);
	}

	if (!(nxgep->drv_state & STATE_HW_INITIALIZED)) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_tx_port_fatal_err_recover: not initialized"));
		return (NXGE_ERROR);
	}

	if (nxgep->tx_rings == 0 || nxgep->tx_rings->rings == 0) {
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "<== nxge_tx_port_fatal_err_recover: "
		    "NULL ring pointer(s)"));
		return (NXGE_ERROR);
	}

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring)
				MUTEX_ENTER(&ring->lock);
		}
	}

	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	/*
	 * Stop all the TDCs owned by us.
	 * (The shared TDCs will have been stopped by their owners.)
	 */
	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				rs = npi_txdma_channel_control
				    (handle, TXDMA_STOP, tdc);
				if (rs != NPI_SUCCESS) {
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "nxge_tx_port_fatal_err_recover "
					    "(channel %d): stop failed ", tdc));
					goto fail;
				}
			}
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "Reclaiming all TDCs..."));

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				(void) nxge_txdma_reclaim(nxgep, ring, 0);
			}
		}
	}

	/*
	 * Reset all the TDCs.
	 */
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "Resetting all TDCs..."));

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				if ((rs = npi_txdma_channel_control
				    (handle, TXDMA_RESET, tdc))
				    != NPI_SUCCESS) {
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "nxge_tx_port_fatal_err_recover "
					    "(channel %d) reset channel "
					    "failed 0x%x", tdc, rs));
					goto fail;
				}
			}
			/*
			 * Reset the tail (kick) register to 0.
			 * (Hardware will not reset it. Tx overflow fatal
			 * error if tail is not set to 0 after reset!
			 */
			TXDMA_REG_WRITE64(handle, TX_RING_KICK_REG, tdc, 0);
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "Restarting all TDCs..."));

	/* Restart all the TDCs */
	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				mailbox = nxge_txdma_get_mbox(nxgep, tdc);
				status = nxge_init_fzc_txdma_channel(nxgep, tdc,
				    ring, mailbox);
				ring->tx_evmask.value = 0;
				/*
				 * Initialize the event masks.
				 */
				status = nxge_init_txdma_channel_event_mask
				    (nxgep, tdc, &ring->tx_evmask);

				ring->wr_index_wrap = B_FALSE;
				ring->wr_index = 0;
				ring->rd_index = 0;

				if (status != NXGE_OK)
					goto fail;
				if (status != NXGE_OK)
					goto fail;
			}
		}
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "Re-enabling all TDCs..."));

	/* Re-enable all the TDCs */
	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			ring = nxgep->tx_rings->rings[tdc];
			if (ring) {
				mailbox = nxge_txdma_get_mbox(nxgep, tdc);
				status = nxge_enable_txdma_channel(nxgep, tdc,
				    ring, mailbox);
				if (status != NXGE_OK)
					goto fail;
			}
		}
	}

	/*
	 * Unlock all the TDCs.
	 */
	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			tx_ring_t *ring = nxgep->tx_rings->rings[tdc];
			if (ring)
				MUTEX_EXIT(&ring->lock);
		}
	}

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "Tx port recovery succeeded"));
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_tx_port_fatal_err_recover"));

	return (NXGE_OK);

fail:
	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			ring = nxgep->tx_rings->rings[tdc];
			if (ring)
				MUTEX_EXIT(&ring->lock);
		}
	}

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "Tx port recovery failed"));
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_tx_port_fatal_err_recover"));

	return (status);
}

/*
 * nxge_txdma_inject_err
 *
 *	Inject an error into a TDC.
 *
 * Arguments:
 * 	nxgep
 * 	err_id	The error to inject.
 * 	chan	The channel to inject into.
 *
 * Notes:
 *	This is called from nxge_main.c:nxge_err_inject()
 *	Has this ioctl ever been used?
 *
 * NPI/NXGE function calls:
 *	npi_txdma_inj_par_error_get()
 *	npi_txdma_inj_par_error_set()
 *
 * Registers accessed:
 *	TDMC_INJ_PAR_ERR (FZC_DMC + 0x45040) TDMC Inject Parity Error
 *	TDMC_INTR_DBG	DMC + 0x40060 Transmit DMA Interrupt Debug
 *	TDMC_INTR_DBG	DMC + 0x40060 Transmit DMA Interrupt Debug
 *
 * Context:
 *	Service domain
 */
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
