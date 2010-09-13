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

#ifndef	_SYS_HXGE_HXGE_RXDMA_H
#define	_SYS_HXGE_HXGE_RXDMA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <hxge_rdc_hw.h>
#include <hpi_rxdma.h>

#define	RXDMA_CK_DIV_DEFAULT		25000	/* 84 usec */
#define	RXDMA_RCR_PTHRES_DEFAULT	0x1
#define	RXDMA_RCR_TO_DEFAULT		0x1
#define	RXDMA_HDR_SIZE_DEFAULT		2
#define	RXDMA_HDR_SIZE_FULL		6	/* entire header of 6B */

/*
 * Receive Completion Ring (RCR)
 */
#define	RCR_PKT_BUF_ADDR_SHIFT		0			/* bit 37:0 */
#define	RCR_PKT_BUF_ADDR_SHIFT_FULL	6	/* fulll buffer address */
#define	RCR_PKT_BUF_ADDR_MASK		0x0000003FFFFFFFFFULL
#define	RCR_PKTBUFSZ_SHIFT		38			/* bit 39:38 */
#define	RCR_PKTBUFSZ_MASK		0x000000C000000000ULL
#define	RCR_L2_LEN_SHIFT		40			/* bit 53:40 */
#define	RCR_L2_LEN_MASK			0x003fff0000000000ULL
#define	RCR_ERROR_SHIFT			54			/* bit 57:54 */
#define	RCR_ERROR_MASK			0x03C0000000000000ULL
#define	RCR_PKT_TYPE_SHIFT		61			/* bit 62:61 */
#define	RCR_PKT_TYPE_MASK		0x6000000000000000ULL
#define	RCR_MULTI_SHIFT			63			/* bit 63 */
#define	RCR_MULTI_MASK			0x8000000000000000ULL

#define	RCR_PKTBUFSZ_0			0x00
#define	RCR_PKTBUFSZ_1			0x01
#define	RCR_PKTBUFSZ_2			0x02
#define	RCR_SINGLE_BLOCK		0x03
#define	N_PKTSIZE_TYPES			0x04

#define	RCR_NO_ERROR			0x0
#define	RCR_CTRL_FIFO_DED		0x1
#define	RCR_DATA_FIFO_DED		0x2
#define	RCR_ERROR_RESERVE		0x4

#define	RCR_PKT_IS_TCP			0x2000000000000000ULL
#define	RCR_PKT_IS_UDP			0x4000000000000000ULL
#define	RCR_PKT_IS_SCTP			0x6000000000000000ULL

#define	RDC_INT_MASK_RBRFULL_SHIFT	34
#define	RDC_INT_MASK_RBRFULL_MASK	0x0000000400000000ULL
#define	RDC_INT_MASK_RBREMPTY_SHIFT	35
#define	RDC_INT_MASK_RBREMPTY_MASK	0x0000000800000000ULL
#define	RDC_INT_MASK_RCRFULL_SHIFT	36
#define	RDC_INT_MASK_RCRFULL_MASK	0x0000001000000000ULL
#define	RDC_INT_MASK_RCRSH_FULL_SHIFT	39
#define	RDC_INT_MASK_RCRSH_FULL_MASK	0x0000008000000000ULL
#define	RDC_INT_MASK_RBR_PRE_EMPTY_SHIFT	40
#define	RDC_INT_MASK_RBR_PRE_EMPTY_MASK	0x0000010000000000ULL
#define	RDC_INT_MASK_RBR_PRE_PAR_SHIFT	43
#define	RDC_INT_MASK_RBR_PRE_PAR_MASK	0x0000080000000000ULL
#define	RDC_INT_MASK_RCR_SHA_PAR_SHIFT	44
#define	RDC_INT_MASK_RCR_SHA_PAR_MASK	0x0000100000000000ULL
#define	RDC_INT_MASK_RCRTO_SHIFT	45
#define	RDC_INT_MASK_RCRTO_MASK		0x0000200000000000ULL
#define	RDC_INT_MASK_THRES_SHIFT	46
#define	RDC_INT_MASK_THRES_MASK		0x0000400000000000ULL
#define	RDC_INT_MASK_PEU_ERR_SHIFT	52
#define	RDC_INT_MASK_PEU_ERR_MASK	0x0010000000000000ULL
#define	RDC_INT_MASK_RBR_CPL_SHIFT	53
#define	RDC_INT_MASK_RBR_CPL_MASK	0x0020000000000000ULL
#define	RDC_INT_MASK_ALL	(RDC_INT_MASK_RBRFULL_MASK |		\
				RDC_INT_MASK_RBREMPTY_MASK |		\
				RDC_INT_MASK_RCRFULL_MASK |		\
				RDC_INT_MASK_RCRSH_FULL_MASK |		\
				RDC_INT_MASK_RBR_PRE_EMPTY_MASK |	\
				RDC_INT_MASK_RBR_PRE_PAR_MASK |		\
				RDC_INT_MASK_RCR_SHA_PAR_MASK |		\
				RDC_INT_MASK_RCRTO_MASK |		\
				RDC_INT_MASK_THRES_MASK |		\
				RDC_INT_MASK_PEU_ERR_MASK |		\
				RDC_INT_MASK_RBR_CPL_MASK)

#define	RDC_STAT_PKTREAD_SHIFT			0	/* WO, bit 15:0 */
#define	RDC_STAT_PKTREAD_MASK			0x000000000000ffffULL
#define	RDC_STAT_PTRREAD_SHIFT			16	/* WO, bit 31:16 */
#define	RDC_STAT_PTRREAD_MASK			0x00000000FFFF0000ULL

#define	RDC_STAT_RBRFULL_SHIFT			34	/* RO, bit 34 */
#define	RDC_STAT_RBRFULL			0x0000000400000000ULL
#define	RDC_STAT_RBRFULL_MASK			0x0000000400000000ULL
#define	RDC_STAT_RBREMPTY_SHIFT			35	/* RW1C, bit 35 */
#define	RDC_STAT_RBREMPTY			0x0000000800000000ULL
#define	RDC_STAT_RBREMPTY_MASK			0x0000000800000000ULL
#define	RDC_STAT_RCR_FULL_SHIFT			36	/* RW1C, bit 36 */
#define	RDC_STAT_RCR_FULL			0x0000001000000000ULL
#define	RDC_STAT_RCR_FULL_MASK			0x0000001000000000ULL

#define	RDC_STAT_RCR_SHDW_FULL_SHIFT 		39	/* RW1C, bit 39 */
#define	RDC_STAT_RCR_SHDW_FULL 			0x0000008000000000ULL
#define	RDC_STAT_RCR_SHDW_FULL_MASK 		0x0000008000000000ULL
#define	RDC_STAT_RBR_PRE_EMPTY_SHIFT 		40	/* RO, bit 40 */
#define	RDC_STAT_RBR_PRE_EMPTY 			0x0000010000000000ULL
#define	RDC_STAT_RBR_PRE_EMPTY_MASK  		0x0000010000000000ULL

#define	RDC_STAT_RBR_PRE_PAR_SHIFT 		43	/* RO, bit 43 */
#define	RDC_STAT_RBR_PRE_PAR 			0x0000080000000000ULL
#define	RDC_STAT_RBR_PRE_PAR_MASK  		0x0000080000000000ULL
#define	RDC_STAT_RCR_SHA_PAR_SHIFT 		44	/* RO, bit 44 */
#define	RDC_STAT_RCR_SHA_PAR 			0x0000100000000000ULL
#define	RDC_STAT_RCR_SHA_PAR_MASK  		0x0000100000000000ULL

#define	RDC_STAT_RCR_TO_SHIFT			45	/* RW1C, bit 45 */
#define	RDC_STAT_RCR_TO				0x0000200000000000ULL
#define	RDC_STAT_RCR_TO_MASK			0x0000200000000000ULL
#define	RDC_STAT_RCR_THRES_SHIFT		46	/* RO, bit 46 */
#define	RDC_STAT_RCR_THRES			0x0000400000000000ULL
#define	RDC_STAT_RCR_THRES_MASK			0x0000400000000000ULL
#define	RDC_STAT_RCR_MEX_SHIFT			47	/* RW, bit 47 */
#define	RDC_STAT_RCR_MEX			0x0000800000000000ULL
#define	RDC_STAT_RCR_MEX_MASK			0x0000800000000000ULL

#define	RDC_STAT_PEU_ERR_SHIFT			52	/* RO, bit 52 */
#define	RDC_STAT_PEU_ERR			0x0010000000000000ULL
#define	RDC_STAT_PEU_ERR_MASK			0x0010000000000000ULL

#define	RDC_STAT_RBR_CPL_SHIFT			53	/* RO, bit 53 */
#define	RDC_STAT_RBR_CPL			0x0020000000000000ULL
#define	RDC_STAT_RBR_CPL_MASK			0x0020000000000000ULL

#define	RDC_STAT_ERROR 				RDC_INT_MASK_ALL

/* the following are write 1 to clear bits */
#define	RDC_STAT_WR1C		(RDC_STAT_RBREMPTY | 		\
				RDC_STAT_RCR_SHDW_FULL | 	\
				RDC_STAT_RBR_PRE_EMPTY | 	\
				RDC_STAT_RBR_PRE_PAR |		\
				RDC_STAT_RCR_SHA_PAR |		\
				RDC_STAT_RBR_CPL |		\
				RDC_STAT_PEU_ERR)

typedef union _rcr_entry_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t multi:1;
		uint32_t pkt_type:2;
		uint32_t reserved:3;
		uint32_t error:4;
		uint32_t l2_len:14;
		uint32_t pktbufsz:2;
		uint32_t pkt_buf_addr:6;
		uint32_t pkt_buf_addr_l:32;
#else
		uint32_t pkt_buf_addr_l:32;
		uint32_t pkt_buf_addr:6;
		uint32_t pktbufsz:2;
		uint32_t l2_len:14;
		uint32_t error:4;
		uint32_t reserved:3;
		uint32_t pkt_type:2;
		uint32_t multi:1;
#endif
	} bits;
} rcr_entry_t, *p_rcr_entry_t;

#define	RX_DMA_MAILBOX_BYTE_LENGTH	64

typedef struct _rxdma_mailbox_t {
	rdc_stat_t		rxdma_ctl_stat;		/* 8 bytes */
	rdc_rbr_qlen_t		rbr_stat;		/* 8 bytes */
	rdc_rbr_head_t		rbr_hdh;		/* 8 bytes */
	uint64_t		resv_1;
	rdc_rcr_tail_t		rcrstat_c;		/* 8 bytes */
	uint64_t		resv_2;
	rdc_rcr_qlen_t		rcrstat_a;		/* 8 bytes */
	uint64_t		resv_3;
} rxdma_mailbox_t, *p_rxdma_mailbox_t;

/*
 * hardware workarounds: kick 16 (was 8 before)
 */
#define	HXGE_RXDMA_POST_BATCH		16

#define	RXBUF_START_ADDR(a, index, bsize)	((a & (index * bsize))
#define	RXBUF_OFFSET_FROM_START(a, start)	(start - a)
#define	RXBUF_64B_ALIGNED		64

#define	HXGE_RXBUF_EXTRA		34

/*
 * Receive buffer thresholds and buffer types
 */
#define	HXGE_RX_BCOPY_SCALE	8	/* use 1/8 as lowest granularity */

typedef enum  {
	HXGE_RX_COPY_ALL = 0,		/* do bcopy on every packet	 */
	HXGE_RX_COPY_1,			/* bcopy on 1/8 of buffer posted */
	HXGE_RX_COPY_2,			/* bcopy on 2/8 of buffer posted */
	HXGE_RX_COPY_3,			/* bcopy on 3/8 of buffer posted */
	HXGE_RX_COPY_4,			/* bcopy on 4/8 of buffer posted */
	HXGE_RX_COPY_5,			/* bcopy on 5/8 of buffer posted */
	HXGE_RX_COPY_6,			/* bcopy on 6/8 of buffer posted */
	HXGE_RX_COPY_7,			/* bcopy on 7/8 of buffer posted */
	HXGE_RX_COPY_NONE		/* don't do bcopy at all	 */
} hxge_rxbuf_threshold_t;

typedef enum  {
	HXGE_RBR_TYPE0 = RCR_PKTBUFSZ_0,  /* bcopy buffer size 0 (small) */
	HXGE_RBR_TYPE1 = RCR_PKTBUFSZ_1,  /* bcopy buffer size 1 (medium) */
	HXGE_RBR_TYPE2 = RCR_PKTBUFSZ_2	  /* bcopy buffer size 2 (large) */
} hxge_rxbuf_type_t;

typedef	struct _rdc_errlog {
	rdc_pref_par_log_t	pre_par;
	rdc_pref_par_log_t	sha_par;
	uint8_t			compl_err_type;
} rdc_errlog_t;

/*
 * Receive  Statistics.
 */
typedef struct _hxge_rx_ring_stats_t {
	uint64_t	ipackets;
	uint64_t	ibytes;
	uint32_t	ierrors;
	uint32_t	jumbo_pkts;

	/*
	 * Error event stats.
	 */
	uint32_t	rcr_unknown_err;
	uint32_t	ctrl_fifo_ecc_err;
	uint32_t	data_fifo_ecc_err;
	uint32_t	rbr_tmout;		/* rbr_cpl_to */
	uint32_t 	peu_resp_err;		/* peu_resp_err */
	uint32_t 	rcr_sha_par;		/* rcr_shadow_par_err */
	uint32_t 	rbr_pre_par;		/* rbr_prefetch_par_err */
	uint32_t 	rbr_pre_empty;		/* rbr_pre_empty */
	uint32_t 	rcr_shadow_full;	/* rcr_shadow_full */
	uint32_t 	rcrfull;		/* rcr_full */
	uint32_t 	rbr_empty;		/* rbr_empty */
	uint32_t 	rbr_empty_fail;		/* rbr_empty_fail */
	uint32_t 	rbr_empty_restore;	/* rbr_empty_restore */
	uint32_t 	rbrfull;		/* rbr_full */
	/*
	 * RCR invalids: when processing RCR entries, can
	 * run into invalid RCR entries.  This counter provides
	 * a means to account for invalid RCR entries.
	 */
	uint32_t 	rcr_invalids;		/* rcr invalids */
	uint32_t 	rcr_to;			/* rcr_to */
	uint32_t 	rcr_thres;		/* rcr_thres */
	/* Packets dropped in order to prevent rbr_empty condition */
	uint32_t 	pkt_drop;
	rdc_errlog_t	errlog;
} hxge_rx_ring_stats_t, *p_hxge_rx_ring_stats_t;

typedef struct _hxge_rdc_sys_stats {
	uint32_t	ctrl_fifo_sec;
	uint32_t	ctrl_fifo_ded;
	uint32_t	data_fifo_sec;
	uint32_t	data_fifo_ded;
} hxge_rdc_sys_stats_t, *p_hxge_rdc_sys_stats_t;

typedef struct _rx_msg_t {
	hxge_os_dma_common_t	buf_dma;
	hxge_os_mutex_t 	lock;
	struct _hxge_t		*hxgep;
	struct _rx_rbr_ring_t	*rx_rbr_p;
	boolean_t 		free;
	uint32_t 		ref_cnt;
	hxge_os_frtn_t 		freeb;
	size_t 			block_size;
	uint32_t		block_index;
	uint32_t 		pkt_buf_size;
	uint32_t 		pkt_buf_size_code;
	uint32_t		cur_usage_cnt;
	uint32_t		max_usage_cnt;
	uchar_t			*buffer;
	uint32_t 		pri;
	uint32_t 		shifted_addr;
	boolean_t		use_buf_pool;
	p_mblk_t 		rx_mblk_p;
	boolean_t		rx_use_bcopy;
} rx_msg_t, *p_rx_msg_t;

/* Receive Completion Ring */
typedef struct _rx_rcr_ring_t {
	hxge_os_dma_common_t	rcr_desc;
	struct _hxge_t		*hxgep;
	mac_ring_handle_t   	rcr_mac_handle;
	uint64_t		rcr_gen_num;
	boolean_t		poll_flag;
	p_hxge_ldv_t		ldvp;
	p_hxge_ldg_t		ldgp;

	p_hxge_rx_ring_stats_t	rdc_stats;	/* pointer to real kstats */

	rdc_rcr_cfg_a_t		rcr_cfga;
	rdc_rcr_cfg_b_t		rcr_cfgb;

	hxge_os_mutex_t 	lock;
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
	uint64_t		rcr_tail_begin;

	struct _rx_rbr_ring_t	*rx_rbr_p;
	uint32_t		intr_timeout;
	uint32_t		intr_threshold;
	uint32_t		rcvd_pkt_bytes; /* Received bytes of a packet */
} rx_rcr_ring_t, *p_rx_rcr_ring_t;


/* Buffer index information */
typedef struct _rxbuf_index_info_t {
	uint32_t		buf_index;
	uint32_t		start_index;
	uint32_t		buf_size;
	uint64_t		dvma_addr;
	uint64_t		kaddr;
} rxbuf_index_info_t, *p_rxbuf_index_info_t;

/* Buffer index information */

typedef struct _rxring_info_t {
	uint32_t		hint[N_PKTSIZE_TYPES];
	uint32_t		block_size_mask;
	uint16_t		max_iterations;
	rxbuf_index_info_t	buffer[HXGE_DMA_BLOCK];
} rxring_info_t, *p_rxring_info_t;


typedef enum {
	RBR_POSTING = 1,	/* We may post rx buffers. */
	RBR_UNMAPPING,		/* We are in the process of unmapping. */
	RBR_UNMAPPED		/* The ring is unmapped. */
} rbr_state_t;


/* Receive Buffer Block Ring */
typedef struct _rx_rbr_ring_t {
	hxge_os_dma_common_t	rbr_desc;
	p_rx_msg_t 		*rx_msg_ring;
	p_hxge_dma_common_t 	*dma_bufp;
	rdc_rbr_cfg_a_t		rbr_cfga;
	rdc_rbr_cfg_b_t		rbr_cfgb;
	rdc_rbr_kick_t		rbr_kick;
	rdc_page_handle_t	page_hdl;

	hxge_os_mutex_t		lock;
	hxge_os_mutex_t		post_lock;
	boolean_t		rbr_is_empty;
	uint32_t		rbr_used;
	uint16_t		index;
	struct _hxge_t		*hxgep;
	uint16_t		rdc;
	uint_t 			rbr_max_size;
	uint64_t		rbr_addr;
	uint_t 			rbr_wrap_mask;
	uint_t 			rbb_max;
	uint_t			block_size;
	uint_t			num_blocks;
	uint_t			tnblocks;
	uint_t			pkt_buf_size0;
	uint_t			pkt_buf_size0_bytes;
	uint_t			hpi_pkt_buf_size0;
	uint_t			pkt_buf_size1;
	uint_t			pkt_buf_size1_bytes;
	uint_t			hpi_pkt_buf_size1;
	uint_t			pkt_buf_size2;
	uint_t			pkt_buf_size2_bytes;
	uint_t			hpi_pkt_buf_size2;

	uint64_t		rbr_head_pp;
	uint64_t		rbr_tail_pp;
	uint32_t		*rbr_desc_vp;

	p_rx_rcr_ring_t		rx_rcr_p;

	rdc_rbr_head_t		rbr_head;
	uint_t 			rbr_wr_index;
	uint_t 			rbr_rd_index;
	uint_t 			rbr_hw_head_index;
	uint64_t 		rbr_hw_head_ptr;

	rxring_info_t		*ring_info;
	uint_t 			rbr_consumed;
	uint_t 			rbr_threshold_hi;
	uint_t 			rbr_threshold_lo;
	hxge_rxbuf_type_t	rbr_bufsize_type;
	boolean_t		rbr_use_bcopy;

	/*
	 * <rbr_ref_cnt> is a count of those receive buffers which
	 * have been loaned to the kernel.  We will not free this
	 * ring until the reference count reaches zero (0).
	 */
	uint32_t		rbr_ref_cnt;
	rbr_state_t		rbr_state;	/* POSTING, etc */
} rx_rbr_ring_t, *p_rx_rbr_ring_t;

/* Receive Mailbox */
typedef struct _rx_mbox_t {
	hxge_os_dma_common_t	rx_mbox;
	rdc_rx_cfg1_t		rx_cfg1;
	rdc_rx_cfg2_t		rx_cfg2;
	uint64_t		mbox_addr;
	boolean_t		cfg_set;

	hxge_os_mutex_t 	lock;
	uint16_t		index;
	struct _hxge_t		*hxgep;
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
 * Receive DMA Prototypes.
 */
hxge_status_t hxge_init_rxdma_channels(p_hxge_t hxgep);
void hxge_uninit_rxdma_channels(p_hxge_t hxgep);
hxge_status_t hxge_init_rxdma_channel_cntl_stat(p_hxge_t hxgep,
	uint16_t channel, rdc_stat_t *cs_p);
hxge_status_t hxge_enable_rxdma_channel(p_hxge_t hxgep,
	uint16_t channel, p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p,
	p_rx_mbox_t mbox_p, int n_init_kick);
hxge_status_t hxge_rxdma_hw_mode(p_hxge_t hxgep, boolean_t enable);
int hxge_rxdma_get_ring_index(p_hxge_t hxgep, uint16_t channel);
hxge_status_t hxge_rxdma_handle_sys_errors(p_hxge_t hxgep);

extern int hxge_enable_poll(void *arg);
extern int hxge_disable_poll(void *arg);
extern mblk_t *hxge_rx_poll(void *arg, int bytes_to_read);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_RXDMA_H */
