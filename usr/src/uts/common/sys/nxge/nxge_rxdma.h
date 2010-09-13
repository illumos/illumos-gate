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

#ifndef	_SYS_NXGE_NXGE_RXDMA_H
#define	_SYS_NXGE_NXGE_RXDMA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nxge/nxge_rxdma_hw.h>
#include <npi_rxdma.h>

#define	RXDMA_CK_DIV_DEFAULT		7500 	/* 25 usec */
/*
 * Hardware RDC designer: 8 cache lines during Atlas bringup.
 */
#define	RXDMA_RED_LESS_BYTES		(8 * 64) /* 8 cache line */
#define	RXDMA_RED_LESS_ENTRIES		(RXDMA_RED_LESS_BYTES/8)
#define	RXDMA_RED_WINDOW_DEFAULT	0
#define	RXDMA_RED_THRES_DEFAULT		0

#define	RXDMA_RCR_PTHRES_DEFAULT	0x20
#define	RXDMA_RCR_TO_DEFAULT		0x8

/*
 * hardware workarounds: kick 16 (was 8 before)
 */
#define	NXGE_RXDMA_POST_BATCH		16

#define	RXBUF_START_ADDR(a, index, bsize)	((a & (index * bsize))
#define	RXBUF_OFFSET_FROM_START(a, start)	(start - a)
#define	RXBUF_64B_ALIGNED		64

#define	NXGE_RXBUF_EXTRA		34
/*
 * Receive buffer thresholds and buffer types
 */
#define	NXGE_RX_BCOPY_SCALE	8	/* use 1/8 as lowest granularity */
typedef enum  {
	NXGE_RX_COPY_ALL = 0,		/* do bcopy on every packet	 */
	NXGE_RX_COPY_1,			/* bcopy on 1/8 of buffer posted */
	NXGE_RX_COPY_2,			/* bcopy on 2/8 of buffer posted */
	NXGE_RX_COPY_3,			/* bcopy on 3/8 of buffer posted */
	NXGE_RX_COPY_4,			/* bcopy on 4/8 of buffer posted */
	NXGE_RX_COPY_5,			/* bcopy on 5/8 of buffer posted */
	NXGE_RX_COPY_6,			/* bcopy on 6/8 of buffer posted */
	NXGE_RX_COPY_7,			/* bcopy on 7/8 of buffer posted */
	NXGE_RX_COPY_NONE		/* don't do bcopy at all	 */
} nxge_rxbuf_threshold_t;

typedef enum  {
	NXGE_RBR_TYPE0 = RCR_PKTBUFSZ_0,  /* bcopy buffer size 0 (small) */
	NXGE_RBR_TYPE1 = RCR_PKTBUFSZ_1,  /* bcopy buffer size 1 (medium) */
	NXGE_RBR_TYPE2 = RCR_PKTBUFSZ_2	  /* bcopy buffer size 2 (large) */
} nxge_rxbuf_type_t;

typedef	struct _rdc_errlog {
	rdmc_par_err_log_t	pre_par;
	rdmc_par_err_log_t	sha_par;
	uint8_t			compl_err_type;
} rdc_errlog_t;

/*
 * Receive  Statistics.
 */
typedef struct _nxge_rx_ring_stats_t {
	uint64_t	ipackets;
	uint64_t	ibytes;
	uint32_t	ierrors;
	uint32_t	multircv;
	uint32_t	brdcstrcv;
	uint32_t	norcvbuf;

	uint32_t	rx_inits;
	uint32_t	rx_jumbo_pkts;
	uint32_t	rx_multi_pkts;
	uint32_t	rx_mtu_pkts;
	uint32_t	rx_no_buf;

	/*
	 * Receive buffer management statistics.
	 */
	uint32_t	rx_new_pages;
	uint32_t	rx_new_mtu_pgs;
	uint32_t	rx_new_nxt_pgs;
	uint32_t	rx_reused_pgs;
	uint32_t	rx_mtu_drops;
	uint32_t	rx_nxt_drops;

	/*
	 * Error event stats.
	 */
	uint32_t	rx_rbr_tmout;
	uint32_t	pkt_too_long_err;
	uint32_t	l2_err;
	uint32_t	l4_cksum_err;
	uint32_t	fflp_soft_err;
	uint32_t	zcp_soft_err;
	uint32_t	rcr_unknown_err;
	uint32_t	dcf_err;
	uint32_t 	rbr_tmout;
	uint32_t 	rsp_cnt_err;
	uint32_t 	byte_en_err;
	uint32_t 	byte_en_bus;
	uint32_t 	rsp_dat_err;
	uint32_t 	rcr_ack_err;
	uint32_t 	dc_fifo_err;
	uint32_t 	rcr_sha_par;
	uint32_t 	rbr_pre_par;
	uint32_t 	port_drop_pkt;
	uint32_t 	wred_drop;
	uint32_t 	rbr_pre_empty;
	uint32_t 	rcr_shadow_full;
	uint32_t 	config_err;
	uint32_t 	rcrincon;
	uint32_t 	rcrfull;
	uint32_t 	rbr_empty;
	uint32_t 	rbrfull;
	uint32_t 	rbrlogpage;
	uint32_t 	cfiglogpage;
	uint32_t 	rcrto;
	uint32_t 	rcrthres;
	uint32_t 	mex;
	rdc_errlog_t	errlog;
} nxge_rx_ring_stats_t, *p_nxge_rx_ring_stats_t;

typedef struct _nxge_rdc_sys_stats {
	uint32_t	pre_par;
	uint32_t	sha_par;
	uint32_t	id_mismatch;
	uint32_t	ipp_eop_err;
	uint32_t	zcp_eop_err;
} nxge_rdc_sys_stats_t, *p_nxge_rdc_sys_stats_t;

/*
 * Software reserved buffer offset
 */
typedef struct _nxge_rxbuf_off_hdr_t {
	uint32_t		index;
} nxge_rxbuf_off_hdr_t, *p_nxge_rxbuf_off_hdr_t;


typedef struct _rx_msg_t {
	nxge_os_dma_common_t	buf_dma;
	nxge_os_mutex_t 	lock;
	struct _nxge_t		*nxgep;
	struct _rx_rbr_ring_t	*rx_rbr_p;
	boolean_t 		spare_in_use;
	boolean_t 		free;
	uint32_t 		ref_cnt;
#ifdef RXBUFF_USE_SEPARATE_UP_CNTR
	uint32_t 		pass_up_cnt;
	boolean_t 		release;
#endif
	nxge_os_frtn_t 		freeb;
	size_t 			bytes_arrived;
	size_t 			bytes_expected;
	size_t 			block_size;
	uint32_t		block_index;
	uint32_t 		pkt_buf_size;
	uint32_t 		pkt_buf_size_code;
	uint32_t 		max_pkt_bufs;
	uint32_t		cur_usage_cnt;
	uint32_t		max_usage_cnt;
	uchar_t			*buffer;
	uint32_t 		pri;
	uint32_t 		shifted_addr;
	boolean_t		use_buf_pool;
	p_mblk_t 		rx_mblk_p;
	boolean_t		rx_use_bcopy;
} rx_msg_t, *p_rx_msg_t;

typedef struct _rx_dma_handle_t {
	nxge_os_dma_handle_t	dma_handle;	/* DMA handle	*/
	nxge_os_acc_handle_t	acc_handle;	/* DMA memory handle */
	npi_handle_t		npi_handle;
} rx_dma_handle_t, *p_rx_dma_handle_t;


/* Receive Completion Ring */
typedef struct _rx_rcr_ring_t {
	nxge_os_dma_common_t	rcr_desc;

	struct _nxge_t		*nxgep;

	p_nxge_rx_ring_stats_t	rdc_stats;

	boolean_t		poll_flag;	/* B_TRUE, if polling mode */

	rcrcfig_a_t		rcr_cfga;
	rcrcfig_b_t		rcr_cfgb;

	nxge_os_mutex_t 	lock;
	uint16_t		index;
	uint16_t		rdc;
	boolean_t		full_hdr_flag;	 /* 1: 18 bytes header */
	uint16_t		sw_priv_hdr_len; /* 0 - 192 bytes (SW) */
	uint32_t 		comp_size;	 /* # of RCR entries */
	uint64_t		rcr_addr;
	uint_t 			comp_wrap_mask;
	uint_t 			comp_rd_index;
	uint_t 			comp_wt_index;

	p_rcr_entry_t		rcr_desc_first_p;
	p_rcr_entry_t		rcr_desc_first_pp;
	p_rcr_entry_t		rcr_desc_last_p;
	p_rcr_entry_t		rcr_desc_last_pp;

	p_rcr_entry_t		rcr_desc_rd_head_p;	/* software next read */
	p_rcr_entry_t		rcr_desc_rd_head_pp;

	uint64_t		rcr_tail_pp;
	uint64_t		rcr_head_pp;
	struct _rx_rbr_ring_t	*rx_rbr_p;
	uint32_t		intr_timeout;
	uint32_t		intr_threshold;
	uint64_t		max_receive_pkts;
	mac_ring_handle_t	rcr_mac_handle;
	uint64_t		rcr_gen_num;
	uint32_t		rcvd_pkt_bytes; /* Received bytes of a packet */
	p_nxge_ldv_t		ldvp;
	p_nxge_ldg_t		ldgp;
	boolean_t		started;
} rx_rcr_ring_t, *p_rx_rcr_ring_t;



/* Buffer index information */
typedef struct _rxbuf_index_info_t {
	uint32_t buf_index;
	uint32_t start_index;
	uint32_t buf_size;
	uint64_t dvma_addr;
	uint64_t kaddr;
} rxbuf_index_info_t, *p_rxbuf_index_info_t;

/*
 * Buffer index information
 */
typedef struct _rxring_info_t {
	uint32_t hint[RCR_N_PKTBUF_SZ];
	uint32_t block_size_mask;
	uint16_t max_iterations;
	rxbuf_index_info_t buffer[NXGE_DMA_BLOCK];
} rxring_info_t, *p_rxring_info_t;


typedef enum {
	RBR_POSTING = 1,	/* We may post rx buffers. */
	RBR_UNMAPPING,		/* We are in the process of unmapping. */
	RBR_UNMAPPED		/* The ring is unmapped. */
} rbr_state_t;


/* Receive Buffer Block Ring */
typedef struct _rx_rbr_ring_t {
	nxge_os_dma_common_t	rbr_desc;
	p_rx_msg_t 		*rx_msg_ring;
	p_nxge_dma_common_t 	*dma_bufp;
	rbr_cfig_a_t		rbr_cfga;
	rbr_cfig_b_t		rbr_cfgb;
	rbr_kick_t		rbr_kick;
	log_page_vld_t		page_valid;
	log_page_mask_t		page_mask_1;
	log_page_mask_t		page_mask_2;
	log_page_value_t	page_value_1;
	log_page_value_t	page_value_2;
	log_page_relo_t		page_reloc_1;
	log_page_relo_t		page_reloc_2;
	log_page_hdl_t		page_hdl;

	boolean_t		cfg_set;

	nxge_os_mutex_t		lock;
	nxge_os_mutex_t		post_lock;
	uint16_t		index;
	struct _nxge_t		*nxgep;
	uint16_t		rdc;
	uint16_t		rdc_grp_id;
	uint_t 			rbr_max_size;
	uint64_t		rbr_addr;
	uint_t 			rbr_wrap_mask;
	uint_t 			rbb_max;
	uint_t 			rbb_added;
	uint_t			block_size;
	uint_t			num_blocks;
	uint_t			tnblocks;
	uint_t			pkt_buf_size0;
	uint_t			pkt_buf_size0_bytes;
	uint_t			npi_pkt_buf_size0;
	uint_t			pkt_buf_size1;
	uint_t			pkt_buf_size1_bytes;
	uint_t			npi_pkt_buf_size1;
	uint_t			pkt_buf_size2;
	uint_t			pkt_buf_size2_bytes;
	uint_t			npi_pkt_buf_size2;

	uint32_t		*rbr_desc_vp;

	p_rx_rcr_ring_t		rx_rcr_p;

	uint_t 			rbr_wr_index;
	uint_t 			rbr_rd_index;

	rxring_info_t  *ring_info;
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
	uint64_t		hv_rx_buf_base_ioaddr_pp;
	uint64_t		hv_rx_buf_ioaddr_size;
	uint64_t		hv_rx_cntl_base_ioaddr_pp;
	uint64_t		hv_rx_cntl_ioaddr_size;
	boolean_t		hv_set;
#endif
	uint_t 			rbr_consumed;
	uint_t 			rbr_threshold_hi;
	uint_t 			rbr_threshold_lo;
	nxge_rxbuf_type_t	rbr_bufsize_type;
	boolean_t		rbr_use_bcopy;

	/*
	 * <rbr_ref_cnt> is a count of those receive buffers which
	 * have been loaned to the kernel.  We will not free this
	 * ring until the reference count reaches zero (0).
	 */
	uint32_t		rbr_ref_cnt;
	rbr_state_t		rbr_state; /* POSTING, etc */
	/*
	 * Receive buffer allocation types:
	 *   ddi_dma_mem_alloc(), contig_mem_alloc(), kmem_alloc()
	 */
	buf_alloc_type_t	rbr_alloc_type;
} rx_rbr_ring_t, *p_rx_rbr_ring_t;

/* Receive Mailbox */
typedef struct _rx_mbox_t {
	nxge_os_dma_common_t	rx_mbox;
	rxdma_cfig1_t		rx_cfg1;
	rxdma_cfig2_t		rx_cfg2;
	uint64_t		mbox_addr;
	boolean_t		cfg_set;

	nxge_os_mutex_t 	lock;
	uint16_t		index;
	struct _nxge_t		*nxgep;
	uint16_t		rdc;
} rx_mbox_t, *p_rx_mbox_t;


typedef struct _rx_rbr_rings_t {
	p_rx_rbr_ring_t 	*rbr_rings;
	uint32_t		ndmas;
	boolean_t		rxbuf_allocated;
} rx_rbr_rings_t, *p_rx_rbr_rings_t;

typedef struct _rx_rcr_rings_t {
	p_rx_rcr_ring_t 	*rcr_rings;
	uint32_t		ndmas;
	boolean_t		cntl_buf_allocated;
} rx_rcr_rings_t, *p_rx_rcr_rings_t;

typedef struct _rx_mbox_areas_t {
	p_rx_mbox_t 		*rxmbox_areas;
	uint32_t		ndmas;
	boolean_t		mbox_allocated;
} rx_mbox_areas_t, *p_rx_mbox_areas_t;

/*
 * Global register definitions per chip and they are initialized
 * using the function zero control registers.
 * .
 */

typedef struct _rxdma_globals {
	boolean_t		mode32;
	uint16_t		rxdma_ck_div_cnt;
	uint16_t		rxdma_red_ran_init;
	uint32_t		rxdma_eing_timeout;
} rxdma_globals_t, *p_rxdma_globals;


/*
 * Receive DMA Prototypes.
 */
nxge_status_t nxge_init_rxdma_channels(p_nxge_t);
void nxge_uninit_rxdma_channels(p_nxge_t);

nxge_status_t nxge_init_rxdma_channel(p_nxge_t, int);
void nxge_uninit_rxdma_channel(p_nxge_t, int);

nxge_status_t nxge_init_rxdma_channel_rcrflush(p_nxge_t, uint8_t);
nxge_status_t nxge_reset_rxdma_channel(p_nxge_t, uint16_t);
nxge_status_t nxge_init_rxdma_channel_cntl_stat(p_nxge_t,
	uint16_t, p_rx_dma_ctl_stat_t);
nxge_status_t nxge_enable_rxdma_channel(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t, p_rx_rcr_ring_t,
	p_rx_mbox_t);
nxge_status_t nxge_init_rxdma_channel_event_mask(p_nxge_t,
		uint16_t, p_rx_dma_ent_msk_t);

nxge_status_t nxge_rxdma_hw_mode(p_nxge_t, boolean_t);
void nxge_hw_start_rx(p_nxge_t);
void nxge_fixup_rxdma_rings(p_nxge_t);
nxge_status_t nxge_dump_rxdma_channel(p_nxge_t, uint8_t);

void nxge_rxdma_fix_channel(p_nxge_t, uint16_t);

mblk_t *nxge_rx_poll(void *, int);
int nxge_enable_poll(void *);
int nxge_disable_poll(void *);

void nxge_rxdma_regs_dump_channels(p_nxge_t);
nxge_status_t nxge_rxdma_handle_sys_errors(p_nxge_t);
void nxge_rxdma_inject_err(p_nxge_t, uint32_t, uint8_t);

extern nxge_status_t nxge_alloc_rx_mem_pool(p_nxge_t);
extern nxge_status_t nxge_alloc_rxb(p_nxge_t nxgep, int channel);
extern void nxge_free_rxb(p_nxge_t nxgep, int channel);

int nxge_get_rxring_index(p_nxge_t, int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_RXDMA_H */
