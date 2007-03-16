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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#ifndef _CHELSIO_SGE_H
#define	_CHELSIO_SGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#include "osdep.h"

#define	MBLK_MAX 8

#define	spin_lock mutex_enter
#define	spin_unlock mutex_exit
#define	atomic_sub(a, b) atomic_add_32(b, -(a))
#define	atomic_add(a, b) atomic_add_32(b, (a))
#define	atomic_read(a) (a)
#define	atomic_set(a, b) (*(a) = b)
#define	spinlock_t kmutex_t
#define	dma_addr_t uint64_t
#define	wmb() membar_producer()
#define	doorbell_pio(sge, cmd) sge_ring_doorbell(sge, cmd)
#define	skb_reserve(skb, offset) (skb->b_rptr += offset)
#define	__skb_pull(skb, len) (skb->b_rptr += len)
#define	skb_put(skb, len) ((skb)->b_wptr  = (skb)->b_rptr + (len))
#define	skb_pull(skb, len) (skb->b_rptr += len)
#define	unlikely(a) (a)
#define	likely(a) (a)
#define	SKB_DATA_ALIGN(X) (((X) + (sizeof (long)-1)) & ~(sizeof (long)-1))
#define	t1_is_T1B(adap) adapter_matches_type(adap, CHBT_TERM_T1, TERM_T1B)
#define	t1_is_T1C(adap) adapter_matches_type(adap, CHBT_TERM_T1, TERM_T1C)

#define	SGE_SM_BUF_SZ(sa)	(sa->ch_sm_buf_sz)
#define	SGE_BG_BUF_SZ(sa)	(sa->ch_bg_buf_sz)

#define	SGE_CMDQ_N		2
#define	SGE_FREELQ_N		2
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#define	SGE_CMDQ0_E_N		4096
#define	SGE_CMDQ1_E_N		128
#define	SGE_FREELQ0_E_N		2048
#define	SGE_FREELQ1_E_N		1024
#define	SGE_RESPQ_E_N		7168    /* |CMDQ0| + |FREELQ0| + |FREELQ1| */
#else
#define	SGE_CMDQ0_E_N		2048
#define	SGE_CMDQ1_E_N		128
#define	SGE_FREELQ0_E_N		4096
#define	SGE_FREELQ1_E_N		1024
#define	SGE_RESPQ_E_N		7168    /* |CMDQ0| + |FREELQ0| + |FREELQ1| */
#endif  /* CONFIG_CHELSIO_T1_OFFLOAD */
#define	SGE_BATCH_THRESH	16
#define	SGE_INTR_BUCKETSIZE	100
#define	SGE_INTR_MAXBUCKETS	11
#define	SGE_INTRTIMER0		1
#define	SGE_INTRTIMER1		30
#define	SGE_INTRTIMER_NRES	10000
#define	SGE_RX_COPY_THRESHOLD	256
#define	SGE_RX_OFFSET		2
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#define	SGE_RX_SM_BUF_SIZE(sa)	1536
#else
#define	SGE_RX_SM_BUF_SIZE(sa)	(sa->ch_sm_buf_sz)
#endif

/*
 * CPL5 Defines
 */
#define	FLITSTOBYTES    8

#define	CPL_FORMAT_0_SIZE 8
#define	CPL_FORMAT_1_SIZE 16
#define	CPL_FORMAT_2_SIZE 24
#define	CPL_FORMAT_3_SIZE 32
#define	CPL_FORMAT_4_SIZE 40
#define	CPL_FORMAT_5_SIZE 48

#define	TID_MASK 0xffffff

#define	SZ_CPL_RX_PKT CPL_FORMAT_0_SIZE

#if BYTE_ORDER == BIG_ENDIAN

typedef struct {
	u32 AddrLow;
	u32 GenerationBit: 1;
	u32 BufferLength: 31;
	u32 RespQueueSelector: 4;
	u32 ResponseTokens: 12;
	u32 CmdId: 8;
	u32 Reserved: 3;
	u32 TokenValid: 1;
	u32 Eop: 1;
	u32 Sop: 1;
	u32 DataValid: 1;
	u32 GenerationBit2: 1;
	u32 AddrHigh;
} CmdQueueEntry;


#elif BYTE_ORDER == LITTLE_ENDIAN


typedef struct {
	u32 BufferLength: 31;
	u32 GenerationBit: 1;
	u32 AddrLow;
	u32 AddrHigh;
	u32 GenerationBit2: 1;
	u32 DataValid: 1;
	u32 Sop: 1;
	u32 Eop: 1;
	u32 TokenValid: 1;
	u32 Reserved: 3;
	u32 CmdId: 8;
	u32 ResponseTokens: 12;
	u32 RespQueueSelector: 4;
} CmdQueueEntry;

#endif


typedef CmdQueueEntry cmdQ_e;

#if BYTE_ORDER == BIG_ENDIAN

typedef struct {
	u32 Qsleeping: 4;
	u32 Cmdq1CreditReturn: 5;
	u32 Cmdq1DmaComplete: 5;
	u32 Cmdq0CreditReturn: 5;
	u32 Cmdq0DmaComplete: 5;
	u32 FreelistQid: 2;
	u32 CreditValid: 1;
	u32 DataValid: 1;
	u32 Offload: 1;
	u32 Eop: 1;
	u32 Sop: 1;
	u32 GenerationBit: 1;
	u32 BufferLength;
} ResponseQueueEntry;


#elif BYTE_ORDER == LITTLE_ENDIAN


typedef struct {
	u32 BufferLength;
	u32 GenerationBit: 1;
	u32 Sop: 1;
	u32 Eop: 1;
	u32 Offload: 1;
	u32 DataValid: 1;
	u32 CreditValid: 1;
	u32 FreelistQid: 2;
	u32 Cmdq0DmaComplete: 5;
	u32 Cmdq0CreditReturn: 5;
	u32 Cmdq1DmaComplete: 5;
	u32 Cmdq1CreditReturn: 5;
	u32 Qsleeping: 4;
} ResponseQueueEntry;

#endif

typedef ResponseQueueEntry respQ_e;

#if BYTE_ORDER == BIG_ENDIAN


typedef struct {
	u32 AddrLow;
	u32 GenerationBit: 1;
	u32 BufferLength: 31;
	u32 Reserved: 31;
	u32 GenerationBit2: 1;
	u32 AddrHigh;
} FLQueueEntry;


#elif BYTE_ORDER == LITTLE_ENDIAN


typedef struct {
	u32 BufferLength: 31;
	u32 GenerationBit: 1;
	u32 AddrLow;
	u32 AddrHigh;
	u32 GenerationBit2: 1;
	u32 Reserved: 31;
} FLQueueEntry;


#endif

typedef FLQueueEntry freelQ_e;

/*
 * Command QUEUE meta entry format.
 */
typedef struct cmdQ_ce {
	void *ce_mp;		/* head mblk of pkt */
	free_dh_t *ce_dh;	/* ddi dma handle */
	uint_t ce_flg;		/* flag 0 - NIC descriptor; 1 - TOE */
	uint_t ce_len;		/* length of mblk component */
	uint64_t ce_pa;		/* physical address */
} cmdQ_ce_t;

/*
 * command queue control structure
 */
typedef struct cmdQ {
	u32 cq_credits;		/* # available descriptors for Xmit */
	u32 cq_asleep;		/* HW DMA Fetch status */
	u32 cq_pio_pidx;	/* Variable updated on Doorbell */
	u32 cq_entries_n;	/* # entries for Xmit */
	u32 cq_pidx;		/* producer index (SW) */
	u32 cq_complete;		/* Shadow consumer index (HW) */
	u32 cq_cidx;		/* consumer index (HW) */
	u32 cq_genbit;		/* current generation (=valid) bit */
	cmdQ_e *cq_entries;
	cmdQ_ce_t *cq_centries;
	spinlock_t cq_qlock;
	uint64_t cq_pa;		/* may not be needed */
	ulong_t cq_dh;
	ulong_t cq_ah;		/* may not be needed */
} cmdQ_t;

/*
 * free list queue control structure
 */
typedef struct freelQ {
	u32 fq_id;	/* 0 queue 0, 1 queue 1 */
	u32 fq_credits;	/* # available RX buffer descriptors */
	u32 fq_entries_n;	/* # RX buffer descriptors */
	u32 fq_pidx;	    /* producer index (SW) */
	u32 fq_cidx;	    /* consumer index (HW) */
	u32 fq_genbit;	  /* current generation (=valid) bit */
	u32 fq_rx_buffer_size;  /* size buffer on this freelist */
	freelQ_e *fq_entries;   /* HW freelist descriptor Q */
	struct freelQ_ce *fq_centries;  /* SW freelist conext descriptor Q */
	uint64_t fq_pa;	 /* may not be needed */
	ulong_t fq_dh;
	ulong_t fq_ah;
	u32 fq_pause_on_thresh;
	u32 fq_pause_off_thresh;
} freelQ_t;

/*
 * response queue control structure
 */
typedef struct respQ {
	u32 rq_credits;	 /* # avail response Q entries */
	u32 rq_credits_pend;    /* # not yet returned entries */
	u32 rq_credits_thresh;  /* return threshold */
	u32 rq_entries_n;	/* # response Q descriptors */
	u32 rq_pidx;	    /* producer index (HW) */
	u32 rq_cidx;	    /* consumer index (SW) */
	u32 rq_genbit;	  /* current generation(=valid) bit */
	respQ_e *rq_entries;    /* HW response Q */
	uint64_t rq_pa;	 /* may not be needed */
	ulong_t rq_dh;
	ulong_t rq_ah;
} reapQ_t;

struct sge_intr_counts {
	uint32_t respQ_empty;		/* # times respQ empty */
	uint32_t respQ_overflow;	/* # respQ overflow (fatal) */
	uint32_t freelistQ_empty;	/* # times freelist empty */
	uint32_t pkt_too_big;		/* packet too large (fatal) */
	uint32_t pkt_mismatch;
	uint32_t cmdQ_full[2];		/* not HW intr, host cmdQ[] full */
	uint32_t tx_reclaims[2];
	uint32_t tx_msg_pullups;	/* # of tx pkt coelescing events */
	uint32_t tx_hdr_pullups;	/* # of tx hdr coelescing events */
	uint32_t tx_tcp_ip_frag;	/* # of ip fragmentes for tcp data */
	uint32_t tx_udp_ip_frag;	/* # of ip fragmentes for udp data */
	uint32_t tx_soft_cksums;	/* # of Software checksums done. */
	uint32_t tx_need_cpl_space;	/* # of allocs for cpl header */
	uint32_t tx_multi_mblks;	/* # of Multi mblk packets */
	uint32_t tx_no_dvma1;		/* # of dvma mapping failures */
	uint32_t tx_no_dvma2;		/* # of dvma mapping failures */
	uint32_t tx_no_dma1;		/* # of dma mapping failures */
	uint32_t tx_no_dma2;		/* # of dma mapping failures */
	uint32_t rx_cmdq0;		/* # of Qsleeping CMDQ0's */
	uint32_t rx_cmdq1;		/* # of Qsleeping CMDQ1's */
	uint32_t rx_flq0;		/* # of Qsleeping FL0's */
	uint32_t rx_flq1;		/* # of Qsleeping FL1's */
	uint32_t rx_flq0_sz;		/* size of freelist-0 buffers */
	uint32_t rx_flq1_sz;		/* size of freelist-1 buffers */
	uint32_t rx_pkt_drops;		/* # intentionally dropped packets */
	uint32_t rx_pkt_copied;		/* # times packets copied by sge */
	uint32_t rx_pause_on;		/* # of system pause on's required. */
	uint32_t rx_pause_off;		/* # of system pauses off's required. */
	uint32_t rx_pause_ms;		/* micro seconds while paused */
	uint32_t rx_pause_spike;	/* maximum time paused */
	uint32_t rx_fl_credits;		/* Current free list credit usage. */
	uint32_t rx_flbuf_fails;	/* # of freelist buf alloc fails. */
	uint32_t rx_flbuf_allocs;	/* # of freelist buf allocs. */
	uint32_t rx_badEopSop;		/* # of times bad Eop/Sop received */
	uint32_t rx_flq0_cnt;	/* # of times free list Q 0 entry used */
	uint32_t rx_flq1_cnt;	/* # of times free list Q 1 entry used */
	uint32_t arp_sent;		/* # times arp packet sent */
#ifdef SUN_KSTATS
	uint32_t tx_doorbells;
	uint32_t intr_doorbells;
	uint32_t intr1_doorbells;
	uint32_t sleep_cnt;
	uint32_t pe_allocb_cnt;
	uint32_t tx_descs[MBLK_MAX];
#endif
};

#ifdef SUN_KSTATS
typedef struct sge_intr_counts *p_ch_stats_t;

/*
 * Driver maintained kernel statistics.
 */
typedef struct _ch_kstat_t {
	/*
	 * Link Input/Output stats
	 */
	kstat_named_t respQ_empty;	/* # times respQ empty */
	kstat_named_t respQ_overflow;	/* # respQ overflow (fatal) */
	kstat_named_t freelistQ_empty;	/* # times freelist empty */
	kstat_named_t pkt_too_big;	/* packet too large (fatal) */
	kstat_named_t pkt_mismatch;
	kstat_named_t cmdQ_full[2];	/* not HW intr, host cmdQ[] full */
	kstat_named_t tx_reclaims[2];	/* # of tx reclaims called */
	kstat_named_t tx_msg_pullups;	/* # of tx pkt coelescing events */
	kstat_named_t tx_hdr_pullups;	/* # of tx hdr coelescing events */
	kstat_named_t tx_tcp_ip_frag;	/* # of ip fragmentes for tcp data */
	kstat_named_t tx_udp_ip_frag;	/* # of ip fragmentes for udp data */
	kstat_named_t tx_soft_cksums;	/* # of Software checksums done. */
	kstat_named_t tx_need_cpl_space;	/* # of allocs for cpl header */
	kstat_named_t tx_multi_mblks;	/* # of multi fragment packets */
	kstat_named_t tx_no_dvma1;	/* # of dvma mapping failures */
	kstat_named_t tx_no_dvma2;	/* # of dvma mapping failures */
	kstat_named_t tx_no_dma1;	/* # of dma mapping failures */
	kstat_named_t tx_no_dma2;	/* # of dma mapping failures */
	kstat_named_t rx_cmdq0;		/* # times Qsleeping cmdq0 */
	kstat_named_t rx_cmdq1;		/* # times Qsleeping cmdq1 */
	kstat_named_t rx_flq0;		/* # times Qsleeping flq0 */
	kstat_named_t rx_flq0_sz;	/* size of freelist-0 buffers */
	kstat_named_t rx_flq1;		/* # times Qsleeping flq1 */
	kstat_named_t rx_flq1_sz;	/* size of freelist-1 buffers */
	kstat_named_t rx_pkt_drops;	/* # times packets dropped by sge */
	kstat_named_t rx_pkt_copied;	/* # intentionally copied packets */
	kstat_named_t rx_pause_on;	/* # of system pause on's required. */
	kstat_named_t rx_pause_off;	/* # of system pauses off's required. */
	kstat_named_t rx_pause_ms;	/* micro seconds while paused. */
	kstat_named_t rx_pause_spike;	/* maximum time paused. */
	kstat_named_t rx_fl_credits;	/* Current free list credit usage. */
	kstat_named_t rx_flbuf_fails;	/* # of freelist buf alloc fails. */
	kstat_named_t rx_flbuf_allocs;	/* # of freelist buf allocs. */
	kstat_named_t rx_badEopSop;	/* # of times bad Eop/Sop received */
	kstat_named_t rx_flq0_cnt; /* # of times free list Q 0 entry used */
	kstat_named_t rx_flq1_cnt; /* # of times free list Q 1 entry used */
	kstat_named_t arp_sent;		/* # times arp packet sent */

	kstat_named_t tx_doorbells;
	kstat_named_t intr_doorbells;
	kstat_named_t intr1_doorbells;
	kstat_named_t sleep_cnt;
	kstat_named_t pe_allocb_cnt;
	kstat_named_t tx_descs[MBLK_MAX];
} ch_kstat_t;
typedef ch_kstat_t *p_ch_kstat_t;
#endif

typedef struct _pesge {
	peobj *obj;			/* adapter backpointer */
	struct freelQ freelQ[2];	/* freelist Q(s) */
	struct respQ respQ;		/* response Q instatiation */
	uint32_t rx_pkt_pad;		/* RX padding for T2 packets (hw) */
	uint32_t rx_offset;		/* RX padding for T1 packets (sw) */
	uint32_t jumbo_fl;		/* jumbo freelist Q index */
	uint32_t intrtimer[SGE_INTR_MAXBUCKETS];	/* timer values */
	uint32_t currIndex;		/* current index into intrtimer[] */
	uint32_t intrtimer_nres;	/* no resource interrupt timer value */
	uint32_t sge_control;		/* shadow content of sge control reg */
	struct sge_intr_counts intr_cnt;
#ifdef SUN_KSTATS
	p_kstat_t ksp;
#endif
	ch_cyclic_t espi_wa_cyclic;
	uint32_t ptimeout;
	void *pskb;
	struct cmdQ cmdQ[2];	    /* command Q(s) */
	int do_udp_csum;
	int do_tcp_csum;
} _pesge;

/*
 * ce_flg flag values
 */
#define	DH_DMA  1
#define	DH_DVMA 2
#define	DH_TOE  3
#define	DH_ARP  8

typedef struct freelQ_ce {
	void *fe_mp;		/* head mblk of pkt */
	ulong_t fe_dh;		/* ddi dma handle */
	uint_t  fe_len;		/* length of mblk component */
	uint64_t fe_pa;		/* physical address */
} freelQ_ce_t;

pesge *t1_sge_create(ch_t *, struct sge_params *);

extern int  t1_sge_destroy(pesge* sge);
extern int  sge_data_out(pesge*, int,  mblk_t *, cmdQ_ce_t *, int, uint32_t);
extern int  sge_data_in(pesge *);
extern int  sge_start(pesge*);
extern int  sge_stop(pesge *);
extern int t1_sge_configure(pesge *sge, struct sge_params *p);

extern int  t1_sge_intr_error_handler(pesge*);
extern int  t1_sge_intr_enable(pesge*);
extern int  t1_sge_intr_disable(pesge*);
extern int  t1_sge_intr_clear(pesge*);
extern u32  t1_sge_get_ptimeout(ch_t *);
extern void t1_sge_set_ptimeout(ch_t *, u32);

extern struct sge_intr_counts *sge_get_stat(pesge *);
extern void sge_add_fake_arp(pesge *, void *);

/*
 * Default SGE settings
 */
#define	SGE_CMDQ0_CNT	(512)
#define	SGE_FLQ0_CNT	(512)
#define	SGE_RESPQ_CNT	(1024)

/*
 * the structures below were taken from cpl5_cmd.h. It turns out that there
 * is a number of   #includes    that causes build problems. For now, we're
 * putting a private copy here. When the sge code is made common, then this
 * problem will need to be resolved.
 */

typedef uint8_t  __u8;
typedef uint32_t __u32;
typedef uint16_t __u16;

union opcode_tid {
    __u32 opcode_tid;
    __u8 opcode;
};

/*
 * We want this header's alignment to be no more stringent than 2-byte aligned.
 * All fields are u8 or u16 except for the length.  However that field is not
 * used so we break it into 2 16-bit parts to easily meet our alignment needs.
 */
struct cpl_tx_pkt {
    __u8 opcode;
#if BYTE_ORDER == BIG_ENDIAN
    __u8 rsvd:1;
    __u8 vlan_valid:1;
    __u8 l4_csum_dis:1;
    __u8 ip_csum_dis:1;
    __u8 iff:4;
#else
    __u8 iff:4;
    __u8 ip_csum_dis:1;
    __u8 l4_csum_dis:1;
    __u8 vlan_valid:1;
    __u8 rsvd:1;
#endif
    __u16 vlan;
    __u16 len_hi;
    __u16 len_lo;
};

#define	CPL_TX_PKT 0xb2
#define	SZ_CPL_TX_PKT CPL_FORMAT_0_SIZE

struct cpl_rx_data {
    union opcode_tid ot;
    __u32 len;
    __u32 seq;
    __u16 urg;
    __u8  rsvd;
    __u8  status;
};

struct cpl_rx_pkt {
    __u8 opcode;
#if BYTE_ORDER == LITTLE_ENDIAN
    __u8 iff:4;
    __u8 csum_valid:1;
    __u8 bad_pkt:1;
    __u8 vlan_valid:1;
    __u8 rsvd:1;
#else
    __u8 rsvd:1;
    __u8 vlan_valid:1;
    __u8 bad_pkt:1;
    __u8 csum_valid:1;
    __u8 iff:4;
#endif
    __u16 csum;
    __u16 vlan;
    __u16 len;
};

#ifdef __cplusplus
}
#endif

#endif /* _CHELSIO_SGE_H */
