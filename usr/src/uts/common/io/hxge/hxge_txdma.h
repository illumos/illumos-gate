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

#ifndef	_SYS_HXGE_HXGE_TXDMA_H
#define	_SYS_HXGE_HXGE_TXDMA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/taskq.h>
#include <hxge_txdma_hw.h>
#include <hpi_txdma.h>

#define	TXDMA_RECLAIM_PENDING_DEFAULT		64
#define	TX_FULL_MARK				3

/*
 * Transmit load balancing definitions.
 */
#define	HXGE_TX_LB_TCPUDP	0	/* default policy */
#define	HXGE_TX_LB_HASH		1	/* from the hint data */
#define	HXGE_TX_LB_DEST_MAC	2	/* Dest. MAC */

/*
 * Descriptor ring empty:
 *		(1) head index is equal to tail index.
 *		(2) wrapped around bits are the same.
 * Descriptor ring full:
 *		(1) head index is equal to tail index.
 *		(2) wrapped around bits are different.
 *
 */
#define	TXDMA_RING_EMPTY(head, head_wrap, tail, tail_wrap)	\
	((head == tail && head_wrap == tail_wrap) ? B_TRUE : B_FALSE)

#define	TXDMA_RING_FULL(head, head_wrap, tail, tail_wrap)	\
	((head == tail && head_wrap != tail_wrap) ? B_TRUE : B_FALSE)

#define	TXDMA_DESC_NEXT_INDEX(index, entries, wrap_mask) \
			((index + entries) & wrap_mask)

typedef struct _tx_msg_t {
	hxge_os_block_mv_t	flags;		/* DMA, BCOPY, DVMA (?) */
	hxge_os_dma_common_t	buf_dma;	/* premapped buffer blocks */
	hxge_os_dma_handle_t	buf_dma_handle;	/* premapped buffer handle */
	hxge_os_dma_handle_t	dma_handle;	/* DMA handle for normal send */
	hxge_os_dma_handle_t	dvma_handle;	/* Fast DVMA  handle */

	p_mblk_t		tx_message;
	uint32_t		tx_msg_size;
	size_t			bytes_used;
	int			head;
	int			tail;
	int			offset_index;
} tx_msg_t, *p_tx_msg_t;

/*
 * TX  Statistics.
 */
typedef struct _hxge_tx_ring_stats_t {
	uint64_t		opackets;
	uint64_t		obytes;
	uint64_t		obytes_with_pad;
	uint64_t		oerrors;

	uint32_t		tx_inits;
	uint32_t		tx_no_buf;

	uint32_t		peu_resp_err;
	uint32_t		pkt_size_hdr_err;
	uint32_t		runt_pkt_drop_err;
	uint32_t		pkt_size_err;
	uint32_t		tx_rng_oflow;
	uint32_t		pref_par_err;
	uint32_t		tdr_pref_cpl_to;
	uint32_t		pkt_cpl_to;
	uint32_t		invalid_sop;
	uint32_t		unexpected_sop;

	uint64_t		count_hdr_size_err;
	uint64_t		count_runt;
	uint64_t		count_abort;

	uint32_t		tx_starts;
	uint32_t		tx_no_desc;
	uint32_t		tx_dma_bind_fail;
	uint32_t		tx_hdr_pkts;
	uint32_t		tx_ddi_pkts;
	uint32_t		tx_jumbo_pkts;
	uint32_t		tx_max_pend;
	uint32_t		tx_marks;
	tdc_pref_par_log_t	errlog;
} hxge_tx_ring_stats_t, *p_hxge_tx_ring_stats_t;

typedef struct _hxge_tdc_sys_stats {
	uint32_t	reord_tbl_par_err;
	uint32_t	reord_buf_ded_err;
	uint32_t	reord_buf_sec_err;
} hxge_tdc_sys_stats_t, *p_hxge_tdc_sys_stats_t;

typedef struct _tx_ring_t {
	hxge_os_dma_common_t	tdc_desc;
	struct _hxge_t		*hxgep;
	mac_ring_handle_t	ring_handle;
	ddi_taskq_t		*taskq;
	p_tx_msg_t		tx_msg_ring;
	uint32_t		tnblocks;
	tdc_tdr_cfg_t		tx_ring_cfig;
	tdc_tdr_kick_t		tx_ring_kick;
	tdc_tdr_cfg_t		tx_cs;
	tdc_int_mask_t		tx_evmask;
	tdc_mbh_t		tx_mbox_mbh;
	tdc_mbl_t		tx_mbox_mbl;

	tdc_page_handle_t	page_hdl;

	hxge_os_mutex_t		lock;
	uint16_t		index;
	uint16_t		tdc;
	struct hxge_tdc_cfg	*tdc_p;
	uint_t			tx_ring_size;
	uint32_t		num_chunks;

	uint_t			tx_wrap_mask;
	uint_t			rd_index;
	uint_t			wr_index;
	boolean_t		wr_index_wrap;
	uint_t			head_index;
	boolean_t		head_wrap;
	tdc_tdr_head_t		ring_head;
	tdc_tdr_kick_t		ring_kick_tail;
	txdma_mailbox_t		tx_mbox;

	uint_t			descs_pending;
	boolean_t		queueing;

	p_mblk_t		head;
	p_mblk_t		tail;

	p_hxge_tx_ring_stats_t	tdc_stats;

	uint_t			dvma_wr_index;
	uint_t			dvma_rd_index;
	uint_t			dvma_pending;
	uint_t			dvma_available;
	uint_t			dvma_wrap_mask;

	hxge_os_dma_handle_t	*dvma_ring;

	mac_resource_handle_t	tx_mac_resource_handle;
} tx_ring_t, *p_tx_ring_t;


/* Transmit Mailbox */
typedef struct _tx_mbox_t {
	hxge_os_mutex_t		lock;
	uint16_t		index;
	struct _hxge_t		*hxgep;
	uint16_t		tdc;
	hxge_os_dma_common_t	tx_mbox;
	tdc_mbl_t		tx_mbox_l;
	tdc_mbh_t		tx_mbox_h;
} tx_mbox_t, *p_tx_mbox_t;

typedef struct _tx_rings_t {
	p_tx_ring_t		*rings;
	boolean_t		txdesc_allocated;
	uint32_t		ndmas;
	hxge_os_dma_common_t	tdc_dma;
	hxge_os_dma_common_t	tdc_mbox;
} tx_rings_t, *p_tx_rings_t;

typedef struct _tx_mbox_areas_t {
	p_tx_mbox_t		*txmbox_areas_p;
	boolean_t		txmbox_allocated;
} tx_mbox_areas_t, *p_tx_mbox_areas_t;

/*
 * Transmit prototypes.
 */
hxge_status_t hxge_init_txdma_channels(p_hxge_t hxgep);
void hxge_uninit_txdma_channels(p_hxge_t hxgep);
void hxge_setup_dma_common(p_hxge_dma_common_t, p_hxge_dma_common_t,
	uint32_t, uint32_t);
hxge_status_t hxge_reset_txdma_channel(p_hxge_t hxgep, uint16_t channel,
	uint64_t reg_data);
hxge_status_t hxge_init_txdma_channel_event_mask(p_hxge_t hxgep,
	uint16_t channel, tdc_int_mask_t *mask_p);
hxge_status_t hxge_enable_txdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_tx_ring_t tx_desc_p, p_tx_mbox_t mbox_p);

p_mblk_t hxge_tx_pkt_header_reserve(p_mblk_t mp, uint8_t *npads);
	int hxge_tx_pkt_nmblocks(p_mblk_t mp, int *tot_xfer_len_p);
boolean_t hxge_txdma_reclaim(p_hxge_t hxgep,
	p_tx_ring_t tx_ring_p, int nmblks);

void hxge_fill_tx_hdr(p_mblk_t mp, boolean_t fill_len, boolean_t l4_cksum,
	int pkt_len, uint8_t npads, p_tx_pkt_hdr_all_t pkthdrp);

hxge_status_t hxge_txdma_hw_mode(p_hxge_t hxgep, boolean_t enable);
void hxge_txdma_stop(p_hxge_t hxgep);
void hxge_fixup_txdma_rings(p_hxge_t hxgep);
void hxge_txdma_hw_kick(p_hxge_t hxgep);
void hxge_txdma_fix_channel(p_hxge_t hxgep, uint16_t channel);
void hxge_txdma_fixup_channel(p_hxge_t hxgep, p_tx_ring_t ring_p,
	uint16_t channel);
void hxge_txdma_hw_kick_channel(p_hxge_t hxgep, p_tx_ring_t ring_p,
	uint16_t channel);

void hxge_check_tx_hang(p_hxge_t hxgep);
void hxge_fixup_hung_txdma_rings(p_hxge_t hxgep);
void hxge_txdma_fix_hung_channel(p_hxge_t hxgep, uint16_t channel);
void hxge_txdma_fixup_hung_channel(p_hxge_t hxgep, p_tx_ring_t ring_p,
	uint16_t channel);

mblk_t *hxge_tx_ring_send(void *arg, mblk_t *mp);
void hxge_reclaim_rings(p_hxge_t hxgep);
int hxge_txdma_channel_hung(p_hxge_t hxgep,
	p_tx_ring_t tx_ring_p, uint16_t channel);
int hxge_txdma_hung(p_hxge_t hxgep);
int hxge_txdma_stop_inj_err(p_hxge_t hxgep, int channel);
hxge_status_t hxge_txdma_handle_sys_errors(p_hxge_t hxgep);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_HXGE_HXGE_TXDMA_H */
