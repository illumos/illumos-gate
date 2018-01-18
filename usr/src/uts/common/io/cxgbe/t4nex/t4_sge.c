/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/atomic.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <inet/ip.h>
#include <inet/tcp.h>

#include "version.h"
#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_regs_values.h"

/* TODO: Tune. */
int rx_buf_size = 8192;
int tx_copy_threshold = 256;
uint16_t rx_copy_threshold = 256;

/* Used to track coalesced tx work request */
struct txpkts {
	mblk_t *tail;		/* head is in the software descriptor */
	uint64_t *flitp;	/* ptr to flit where next pkt should start */
	uint8_t npkt;		/* # of packets in this work request */
	uint8_t nflits;		/* # of flits used by this work request */
	uint16_t plen;		/* total payload (sum of all packets) */
};

/* All information needed to tx a frame */
struct txinfo {
	uint32_t len;		/* Total length of frame */
	uint32_t flags;		/* Checksum and LSO flags */
	uint32_t mss;		/* MSS for LSO */
	uint8_t nsegs;		/* # of segments in the SGL, 0 means imm. tx */
	uint8_t nflits;		/* # of flits needed for the SGL */
	uint8_t hdls_used;	/* # of DMA handles used */
	uint32_t txb_used;	/* txb_space used */
	struct ulptx_sgl sgl __attribute__((aligned(8)));
	struct ulptx_sge_pair reserved[TX_SGL_SEGS / 2];
};

static int service_iq(struct sge_iq *iq, int budget);
static inline void init_iq(struct sge_iq *iq, struct adapter *sc, int tmr_idx,
    int8_t pktc_idx, int qsize, uint8_t esize);
static inline void init_fl(struct sge_fl *fl, uint16_t qsize);
static inline void init_eq(struct adapter *sc, struct sge_eq *eq,
    uint16_t eqtype, uint16_t qsize,uint8_t tx_chan, uint16_t iqid);
static int alloc_iq_fl(struct port_info *pi, struct sge_iq *iq,
    struct sge_fl *fl, int intr_idx, int cong);
static int free_iq_fl(struct port_info *pi, struct sge_iq *iq,
    struct sge_fl *fl);
static int alloc_fwq(struct adapter *sc);
static int free_fwq(struct adapter *sc);
#ifdef TCP_OFFLOAD_ENABLE
static int alloc_mgmtq(struct adapter *sc);
#endif
static int alloc_rxq(struct port_info *pi, struct sge_rxq *rxq, int intr_idx,
    int i);
static int free_rxq(struct port_info *pi, struct sge_rxq *rxq);
#ifdef TCP_OFFLOAD_ENABLE
static int alloc_ofld_rxq(struct port_info *pi, struct sge_ofld_rxq *ofld_rxq,
	int intr_idx);
static int free_ofld_rxq(struct port_info *pi, struct sge_ofld_rxq *ofld_rxq);
#endif
static int ctrl_eq_alloc(struct adapter *sc, struct sge_eq *eq);
static int eth_eq_alloc(struct adapter *sc, struct port_info *pi,
    struct sge_eq *eq);
#ifdef TCP_OFFLOAD_ENABLE
static int ofld_eq_alloc(struct adapter *sc, struct port_info *pi,
    struct sge_eq *eq);
#endif
static int alloc_eq(struct adapter *sc, struct port_info *pi,
    struct sge_eq *eq);
static int free_eq(struct adapter *sc, struct sge_eq *eq);
#ifdef TCP_OFFLOAD_ENABLE
static int alloc_wrq(struct adapter *sc, struct port_info *pi,
    struct sge_wrq *wrq, int idx);
static int free_wrq(struct adapter *sc, struct sge_wrq *wrq);
#endif
static int alloc_txq(struct port_info *pi, struct sge_txq *txq, int idx);
static int free_txq(struct port_info *pi, struct sge_txq *txq);
static int alloc_dma_memory(struct adapter *sc, size_t len, int flags,
    ddi_device_acc_attr_t *acc_attr, ddi_dma_attr_t *dma_attr,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl, uint64_t *pba,
    caddr_t *pva);
static int free_dma_memory(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl);
static int alloc_desc_ring(struct adapter *sc, size_t len, int rw,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl, uint64_t *pba,
    caddr_t *pva);
static int free_desc_ring(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl);
static int alloc_tx_copybuffer(struct adapter *sc, size_t len,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl, uint64_t *pba,
    caddr_t *pva);
static inline bool is_new_response(const struct sge_iq *iq,
    struct rsp_ctrl **ctrl);
static inline void iq_next(struct sge_iq *iq);
static int refill_fl(struct adapter *sc, struct sge_fl *fl, int nbufs);
static void refill_sfl(void *arg);
static void add_fl_to_sfl(struct adapter *sc, struct sge_fl *fl);
static void free_fl_bufs(struct sge_fl *fl);
static mblk_t *get_fl_payload(struct adapter *sc, struct sge_fl *fl,
    uint32_t len_newbuf, int *fl_bufs_used);
static int get_frame_txinfo(struct sge_txq *txq, mblk_t **fp,
    struct txinfo *txinfo, int sgl_only);
static inline int fits_in_txb(struct sge_txq *txq, int len, int *waste);
static inline int copy_into_txb(struct sge_txq *txq, mblk_t *m, int len,
    struct txinfo *txinfo);
static inline void add_seg(struct txinfo *txinfo, uint64_t ba, uint32_t len);
static inline int add_mblk(struct sge_txq *txq, struct txinfo *txinfo,
    mblk_t *m, int len);
static void free_txinfo_resources(struct sge_txq *txq, struct txinfo *txinfo);
static int add_to_txpkts(struct sge_txq *txq, struct txpkts *txpkts, mblk_t *m,
    struct txinfo *txinfo);
static void write_txpkts_wr(struct sge_txq *txq, struct txpkts *txpkts);
static int write_txpkt_wr(struct port_info *pi, struct sge_txq *txq, mblk_t *m,
    struct txinfo *txinfo);
static inline void write_ulp_cpl_sgl(struct port_info *pi, struct sge_txq *txq,
    struct txpkts *txpkts, struct txinfo *txinfo);
static inline void copy_to_txd(struct sge_eq *eq, caddr_t from, caddr_t *to,
    int len);
static inline void ring_tx_db(struct adapter *sc, struct sge_eq *eq);
static int reclaim_tx_descs(struct sge_txq *txq, int howmany);
static void write_txqflush_wr(struct sge_txq *txq);
static int t4_eth_rx(struct sge_iq *iq, const struct rss_header *rss,
    mblk_t *m);
static inline void ring_fl_db(struct adapter *sc, struct sge_fl *fl);
static kstat_t *setup_port_config_kstats(struct port_info *pi);
static kstat_t *setup_port_info_kstats(struct port_info *pi);
static kstat_t *setup_rxq_kstats(struct port_info *pi, struct sge_rxq *rxq,
    int idx);
static int update_rxq_kstats(kstat_t *ksp, int rw);
static int update_port_info_kstats(kstat_t *ksp, int rw);
static kstat_t *setup_txq_kstats(struct port_info *pi, struct sge_txq *txq,
    int idx);
static int update_txq_kstats(kstat_t *ksp, int rw);
static int handle_sge_egr_update(struct sge_iq *, const struct rss_header *,
    mblk_t *);
static int handle_fw_rpl(struct sge_iq *iq, const struct rss_header *rss,
    mblk_t *m);

static inline int
reclaimable(struct sge_eq *eq)
{
	unsigned int cidx;

	cidx = eq->spg->cidx;   /* stable snapshot */
	cidx = be16_to_cpu(cidx);

	if (cidx >= eq->cidx)
		return (cidx - eq->cidx);
	else
		return (cidx + eq->cap - eq->cidx);
}

void
t4_sge_init(struct adapter *sc)
{
	struct driver_properties *p = &sc->props;
	ddi_dma_attr_t *dma_attr;
	ddi_device_acc_attr_t *acc_attr;
	uint32_t sge_control, sge_conm_ctrl;
	int egress_threshold;

	/*
	 * Device access and DMA attributes for descriptor rings
	 */
	acc_attr = &sc->sge.acc_attr_desc;
	acc_attr->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc_attr->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	acc_attr->devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	dma_attr = &sc->sge.dma_attr_desc;
	dma_attr->dma_attr_version = DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo = 0;
	dma_attr->dma_attr_addr_hi = UINT64_MAX;
	dma_attr->dma_attr_count_max = UINT64_MAX;
	dma_attr->dma_attr_align = 512;
	dma_attr->dma_attr_burstsizes = 0xfff;
	dma_attr->dma_attr_minxfer = 1;
	dma_attr->dma_attr_maxxfer = UINT64_MAX;
	dma_attr->dma_attr_seg = UINT64_MAX;
	dma_attr->dma_attr_sgllen = 1;
	dma_attr->dma_attr_granular = 1;
	dma_attr->dma_attr_flags = 0;

	/*
	 * Device access and DMA attributes for tx buffers
	 */
	acc_attr = &sc->sge.acc_attr_tx;
	acc_attr->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc_attr->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	dma_attr = &sc->sge.dma_attr_tx;
	dma_attr->dma_attr_version = DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo = 0;
	dma_attr->dma_attr_addr_hi = UINT64_MAX;
	dma_attr->dma_attr_count_max = UINT64_MAX;
	dma_attr->dma_attr_align = 1;
	dma_attr->dma_attr_burstsizes = 0xfff;
	dma_attr->dma_attr_minxfer = 1;
	dma_attr->dma_attr_maxxfer = UINT64_MAX;
	dma_attr->dma_attr_seg = UINT64_MAX;
	dma_attr->dma_attr_sgllen = TX_SGL_SEGS;
	dma_attr->dma_attr_granular = 1;
	dma_attr->dma_attr_flags = 0;

	/*
	 * Ingress Padding Boundary and Egress Status Page Size are set up by
	 * t4_fixup_host_params().
	 */
	sge_control = t4_read_reg(sc, A_SGE_CONTROL);
	sc->sge.pktshift = G_PKTSHIFT(sge_control);
	sc->sge.stat_len = (sge_control & F_EGRSTATUSPAGESIZE) ? 128 : 64;

	/* t4_nex uses FLM packed mode */
	sc->sge.fl_align = t4_fl_pkt_align(sc, true);

	/*
	 * Device access and DMA attributes for rx buffers
	 */
	sc->sge.rxb_params.dip = sc->dip;
	sc->sge.rxb_params.buf_size = rx_buf_size;

	acc_attr = &sc->sge.rxb_params.acc_attr_rx;
	acc_attr->devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc_attr->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	dma_attr = &sc->sge.rxb_params.dma_attr_rx;
	dma_attr->dma_attr_version = DMA_ATTR_V0;
	dma_attr->dma_attr_addr_lo = 0;
	dma_attr->dma_attr_addr_hi = UINT64_MAX;
	dma_attr->dma_attr_count_max = UINT64_MAX;
	/*
	 * Low 4 bits of an rx buffer address have a special meaning to the SGE
	 * and an rx buf cannot have an address with any of these bits set.
	 * FL_ALIGN is >= 32 so we're sure things are ok.
	 */
	dma_attr->dma_attr_align = sc->sge.fl_align;
	dma_attr->dma_attr_burstsizes = 0xfff;
	dma_attr->dma_attr_minxfer = 1;
	dma_attr->dma_attr_maxxfer = UINT64_MAX;
	dma_attr->dma_attr_seg = UINT64_MAX;
	dma_attr->dma_attr_sgllen = 1;
	dma_attr->dma_attr_granular = 1;
	dma_attr->dma_attr_flags = 0;

	sc->sge.rxbuf_cache = rxbuf_cache_create(&sc->sge.rxb_params);

	/*
	 * A FL with <= fl_starve_thres buffers is starving and a periodic
	 * timer will attempt to refill it.  This needs to be larger than the
	 * SGE's Egress Congestion Threshold.  If it isn't, then we can get
	 * stuck waiting for new packets while the SGE is waiting for us to
	 * give it more Free List entries.  (Note that the SGE's Egress
	 * Congestion Threshold is in units of 2 Free List pointers.) For T4,
	 * there was only a single field to control this.  For T5 there's the
	 * original field which now only applies to Unpacked Mode Free List
	 * buffers and a new field which only applies to Packed Mode Free List
	 * buffers.
	 */

	sge_conm_ctrl = t4_read_reg(sc, A_SGE_CONM_CTRL);
	switch (CHELSIO_CHIP_VERSION(sc->params.chip)) {
	case CHELSIO_T4:
		egress_threshold = G_EGRTHRESHOLD(sge_conm_ctrl);
		break;
	case CHELSIO_T5:
		egress_threshold = G_EGRTHRESHOLDPACKING(sge_conm_ctrl);
		break;
	case CHELSIO_T6:
	default:
		egress_threshold = G_T6_EGRTHRESHOLDPACKING(sge_conm_ctrl);
	}
	sc->sge.fl_starve_threshold = 2*egress_threshold + 1;

	t4_write_reg(sc, A_SGE_FL_BUFFER_SIZE0, rx_buf_size);

	t4_write_reg(sc, A_SGE_INGRESS_RX_THRESHOLD,
	    V_THRESHOLD_0(p->counter_val[0]) |
	    V_THRESHOLD_1(p->counter_val[1]) |
	    V_THRESHOLD_2(p->counter_val[2]) |
	    V_THRESHOLD_3(p->counter_val[3]));

	t4_write_reg(sc, A_SGE_TIMER_VALUE_0_AND_1,
	    V_TIMERVALUE0(us_to_core_ticks(sc, p->timer_val[0])) |
	    V_TIMERVALUE1(us_to_core_ticks(sc, p->timer_val[1])));
	t4_write_reg(sc, A_SGE_TIMER_VALUE_2_AND_3,
	    V_TIMERVALUE2(us_to_core_ticks(sc, p->timer_val[2])) |
	    V_TIMERVALUE3(us_to_core_ticks(sc, p->timer_val[3])));
	t4_write_reg(sc, A_SGE_TIMER_VALUE_4_AND_5,
	    V_TIMERVALUE4(us_to_core_ticks(sc, p->timer_val[4])) |
	    V_TIMERVALUE5(us_to_core_ticks(sc, p->timer_val[5])));

	(void) t4_register_cpl_handler(sc, CPL_FW4_MSG, handle_fw_rpl);
	(void) t4_register_cpl_handler(sc, CPL_FW6_MSG, handle_fw_rpl);
	(void) t4_register_cpl_handler(sc, CPL_SGE_EGR_UPDATE, handle_sge_egr_update);
	(void) t4_register_cpl_handler(sc, CPL_RX_PKT, t4_eth_rx);
	(void) t4_register_fw_msg_handler(sc, FW6_TYPE_CMD_RPL,
		    t4_handle_fw_rpl);
}

/*
 * Allocate and initialize the firmware event queue and the forwarded interrupt
 * queues, if any.  The adapter owns all these queues as they are not associated
 * with any particular port.
 *
 * Returns errno on failure.  Resources allocated up to that point may still be
 * allocated.  Caller is responsible for cleanup in case this function fails.
 */
int
t4_setup_adapter_queues(struct adapter *sc)
{
	int rc;

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	/*
	 * Firmware event queue
	 */
	rc = alloc_fwq(sc);
	if (rc != 0)
		return (rc);

#ifdef TCP_OFFLOAD_ENABLE
	/*
	 * Management queue.  This is just a control queue that uses the fwq as
	 * its associated iq.
	 */
	rc = alloc_mgmtq(sc);
#endif

	return (rc);
}

/*
 * Idempotent
 */
int
t4_teardown_adapter_queues(struct adapter *sc)
{

	ADAPTER_LOCK_ASSERT_NOTOWNED(sc);

	(void) free_fwq(sc);

	return (0);
}

static inline int
first_vector(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	int rc = T4_EXTRA_INTR, i;

	if (sc->intr_count == 1)
		return (0);

	for_each_port(sc, i) {
		struct port_info *p = sc->port[i];

		if (i == pi->port_id)
			break;

#ifdef TCP_OFFLOAD_ENABLE
		if (!(sc->flags & INTR_FWD))
			rc += p->nrxq + p->nofldrxq;
		else
			rc += max(p->nrxq, p->nofldrxq);
#else
		/*
		 * Not compiled with offload support and intr_count > 1.  Only
		 * NIC queues exist and they'd better be taking direct
		 * interrupts.
		 */
		ASSERT(!(sc->flags & INTR_FWD));
		rc += p->nrxq;
#endif
	}
	return (rc);
}

/*
 * Given an arbitrary "index," come up with an iq that can be used by other
 * queues (of this port) for interrupt forwarding, SGE egress updates, etc.
 * The iq returned is guaranteed to be something that takes direct interrupts.
 */
static struct sge_iq *
port_intr_iq(struct port_info *pi, int idx)
{
	struct adapter *sc = pi->adapter;
	struct sge *s = &sc->sge;
	struct sge_iq *iq = NULL;

	if (sc->intr_count == 1)
		return (&sc->sge.fwq);

#ifdef TCP_OFFLOAD_ENABLE
	if (!(sc->flags & INTR_FWD)) {
		idx %= pi->nrxq + pi->nofldrxq;

		if (idx >= pi->nrxq) {
			idx -= pi->nrxq;
			iq = &s->ofld_rxq[pi->first_ofld_rxq + idx].iq;
		} else
			iq = &s->rxq[pi->first_rxq + idx].iq;

	} else {
		idx %= max(pi->nrxq, pi->nofldrxq);

		if (pi->nrxq >= pi->nofldrxq)
			iq = &s->rxq[pi->first_rxq + idx].iq;
		else
			iq = &s->ofld_rxq[pi->first_ofld_rxq + idx].iq;
	}
#else
	/*
	 * Not compiled with offload support and intr_count > 1.  Only NIC
	 * queues exist and they'd better be taking direct interrupts.
	 */
	ASSERT(!(sc->flags & INTR_FWD));

	idx %= pi->nrxq;
	iq = &s->rxq[pi->first_rxq + idx].iq;
#endif

	return (iq);
}

int
t4_setup_port_queues(struct port_info *pi)
{
	int rc = 0, i, intr_idx, j;
	struct sge_rxq *rxq;
	struct sge_txq *txq;
#ifdef TCP_OFFLOAD_ENABLE
	int iqid;
	struct sge_wrq *ctrlq;
	struct sge_ofld_rxq *ofld_rxq;
	struct sge_wrq *ofld_txq;
#endif
	struct adapter *sc = pi->adapter;
	struct driver_properties *p = &sc->props;

	pi->ksp_config = setup_port_config_kstats(pi);
	pi->ksp_info   = setup_port_info_kstats(pi);

	/* Interrupt vector to start from (when using multiple vectors) */
	intr_idx = first_vector(pi);

	/*
	 * First pass over all rx queues (NIC and TOE):
	 * a) initialize iq and fl
	 * b) allocate queue iff it will take direct interrupts.
	 */

	for_each_rxq(pi, i, rxq) {

		init_iq(&rxq->iq, sc, pi->tmr_idx, pi->pktc_idx, p->qsize_rxq,
		    RX_IQ_ESIZE);

		init_fl(&rxq->fl, p->qsize_rxq / 8); /* 8 bufs in each entry */

		if ((!(sc->flags & INTR_FWD))
#ifdef TCP_OFFLOAD_ENABLE
		    || (sc->intr_count > 1 && pi->nrxq >= pi->nofldrxq)
#else
		    || (sc->intr_count > 1 && pi->nrxq)
#endif
		   ) {
			rxq->iq.flags |= IQ_INTR;
			rc = alloc_rxq(pi, rxq, intr_idx, i);
			if (rc != 0)
				goto done;
			intr_idx++;
		}

	}

#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_rxq(pi, i, ofld_rxq) {

		init_iq(&ofld_rxq->iq, sc, pi->tmr_idx, pi->pktc_idx,
		    p->qsize_rxq, RX_IQ_ESIZE);

		init_fl(&ofld_rxq->fl, p->qsize_rxq / 8);

		if (!(sc->flags & INTR_FWD) ||
		    (sc->intr_count > 1 && pi->nofldrxq > pi->nrxq)) {
			ofld_rxq->iq.flags = IQ_INTR;
			rc = alloc_ofld_rxq(pi, ofld_rxq, intr_idx);
			if (rc != 0)
				goto done;

			intr_idx++;
		}
	}
#endif

	/*
	 * Second pass over all rx queues (NIC and TOE).  The queues forwarding
	 * their interrupts are allocated now.
	 */
	j = 0;
	for_each_rxq(pi, i, rxq) {
		if (rxq->iq.flags & IQ_INTR)
			continue;

		intr_idx = port_intr_iq(pi, j)->abs_id;

		rc = alloc_rxq(pi, rxq, intr_idx, i);
		if (rc != 0)
			goto done;
		j++;
	}

#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_rxq(pi, i, ofld_rxq) {
		if (ofld_rxq->iq.flags & IQ_INTR)
			continue;

		intr_idx = port_intr_iq(pi, j)->abs_id;
		rc = alloc_ofld_rxq(pi, ofld_rxq, intr_idx);
		if (rc != 0)
			goto done;
		j++;
	}
#endif
	/*
	 * Now the tx queues.  Only one pass needed.
	 */
	j = 0;
	for_each_txq(pi, i, txq) {
		uint16_t iqid;

		iqid = port_intr_iq(pi, j)->cntxt_id;
		init_eq(sc, &txq->eq, EQ_ETH, p->qsize_txq, pi->tx_chan, iqid);
		rc = alloc_txq(pi, txq, i);
		if (rc != 0)
			goto done;
	}

#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_txq(pi, i, ofld_txq) {
		uint16_t iqid;

		iqid = port_intr_iq(pi, j)->cntxt_id;
		init_eq(sc, &ofld_txq->eq, EQ_OFLD, p->qsize_txq, pi->tx_chan,
		    iqid);
		rc = alloc_wrq(sc, pi, ofld_txq, i);
		if (rc != 0)
			goto done;
	}

	/*
	 * Finally, the control queue.
	 */
	ctrlq = &sc->sge.ctrlq[pi->port_id];
	iqid = port_intr_iq(pi, 0)->cntxt_id;
	init_eq(sc, &ctrlq->eq, EQ_CTRL, CTRL_EQ_QSIZE, pi->tx_chan, iqid);
	rc = alloc_wrq(sc, pi, ctrlq, 0);
#endif

done:
	if (rc != 0)
		(void) t4_teardown_port_queues(pi);

	return (rc);
}

/*
 * Idempotent
 */
int
t4_teardown_port_queues(struct port_info *pi)
{
	int i;
	struct sge_rxq *rxq;
	struct sge_txq *txq;
#ifdef TCP_OFFLOAD_ENABLE
	struct adapter *sc = pi->adapter;
	struct sge_ofld_rxq *ofld_rxq;
	struct sge_wrq *ofld_txq;
#endif

	if (pi->ksp_config != NULL) {
		kstat_delete(pi->ksp_config);
		pi->ksp_config = NULL;
	}
	if (pi->ksp_info != NULL) {
		kstat_delete(pi->ksp_info);
		pi->ksp_info = NULL;
	}

#ifdef TCP_OFFLOAD_ENABLE
	(void) free_wrq(sc, &sc->sge.ctrlq[pi->port_id]);
#endif

	for_each_txq(pi, i, txq) {
		(void) free_txq(pi, txq);
	}

#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_txq(pi, i, ofld_txq) {
		(void) free_wrq(sc, ofld_txq);
	}

	for_each_ofld_rxq(pi, i, ofld_rxq) {
		if ((ofld_rxq->iq.flags & IQ_INTR) == 0)
			(void) free_ofld_rxq(pi, ofld_rxq);
	}
#endif

	for_each_rxq(pi, i, rxq) {
		if ((rxq->iq.flags & IQ_INTR) == 0)
			(void) free_rxq(pi, rxq);
	}

	/*
	 * Then take down the rx queues that take direct interrupts.
	 */

	for_each_rxq(pi, i, rxq) {
		if (rxq->iq.flags & IQ_INTR)
			(void) free_rxq(pi, rxq);
	}

#ifdef TCP_OFFLOAD_ENABLE
	for_each_ofld_rxq(pi, i, ofld_rxq) {
		if (ofld_rxq->iq.flags & IQ_INTR)
			(void) free_ofld_rxq(pi, ofld_rxq);
	}
#endif

	return (0);
}

/* Deals with errors and forwarded interrupts */
uint_t
t4_intr_all(caddr_t arg1, caddr_t arg2)
{

	(void) t4_intr_err(arg1, arg2);
	(void) t4_intr(arg1, arg2);

	return (DDI_INTR_CLAIMED);
}

static void
t4_intr_rx_work(struct sge_iq *iq)
{
	mblk_t *mp = NULL;
	struct sge_rxq *rxq = iq_to_rxq(iq);	/* Use iff iq is part of rxq */
	RXQ_LOCK(rxq);
	if (!iq->polling) {
		mp = t4_ring_rx(rxq, iq->qsize/8);
		t4_write_reg(iq->adapter, MYPF_REG(A_SGE_PF_GTS),
		     V_INGRESSQID((u32)iq->cntxt_id) | V_SEINTARM(iq->intr_next));
	}
	RXQ_UNLOCK(rxq);
	if (mp != NULL)
		mac_rx_ring(rxq->port->mh, rxq->ring_handle, mp,
			    rxq->ring_gen_num);
}

/* Deals with interrupts on the given ingress queue */
/* ARGSUSED */
uint_t
t4_intr(caddr_t arg1, caddr_t arg2)
{
	struct sge_iq *iq = (struct sge_iq *)arg2;
	int state;

	/* Right now receive polling is only enabled for MSI-X and
	 * when we have enough msi-x vectors i.e no interrupt forwarding.
	 */
	if (iq->adapter->props.multi_rings) {
		t4_intr_rx_work(iq);
	} else {
		state = atomic_cas_uint(&iq->state, IQS_IDLE, IQS_BUSY);
		if (state == IQS_IDLE) {
			(void) service_iq(iq, 0);
			(void) atomic_cas_uint(&iq->state, IQS_BUSY, IQS_IDLE);
		}
	}
	return (DDI_INTR_CLAIMED);
}

/* Deals with error interrupts */
/* ARGSUSED */
uint_t
t4_intr_err(caddr_t arg1, caddr_t arg2)
{
	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	struct adapter *sc = (struct adapter *)arg1;

	t4_write_reg(sc, MYPF_REG(A_PCIE_PF_CLI), 0);
	(void) t4_slow_intr_handler(sc);

	return (DDI_INTR_CLAIMED);
}

/*
 * t4_ring_rx - Process responses from an SGE response queue.
 *
 * This function processes responses from an SGE response queue up to the supplied budget.
 * Responses include received packets as well as control messages from FW
 * or HW.
 * It returns a chain of mblks containing the received data, to be
 * passed up to mac_ring_rx().
 */
mblk_t *
t4_ring_rx(struct sge_rxq *rxq, int budget)
{
	struct sge_iq *iq = &rxq->iq;
	struct sge_fl *fl = &rxq->fl;           /* Use iff IQ_HAS_FL */
	struct adapter *sc = iq->adapter;
	struct rsp_ctrl *ctrl;
	const struct rss_header *rss;
	int ndescs = 0, fl_bufs_used = 0;
	int rsp_type;
	uint32_t lq;
	mblk_t *mblk_head = NULL, **mblk_tail, *m;
	struct cpl_rx_pkt *cpl;
	uint32_t received_bytes = 0, pkt_len = 0;
	bool csum_ok;
	uint16_t err_vec;

	mblk_tail = &mblk_head;

	while (is_new_response(iq, &ctrl)) {

		membar_consumer();

		m = NULL;
		rsp_type = G_RSPD_TYPE(ctrl->u.type_gen);
		lq = be32_to_cpu(ctrl->pldbuflen_qid);
		rss = (const void *)iq->cdesc;

		switch (rsp_type) {
		case X_RSPD_TYPE_FLBUF:

			ASSERT(iq->flags & IQ_HAS_FL);

			if (CPL_RX_PKT == rss->opcode) {
				cpl = (void *)(rss + 1);
				pkt_len = be16_to_cpu(cpl->len);

				if (iq->polling && ((received_bytes + pkt_len) > budget))
					goto done;

				m = get_fl_payload(sc, fl, lq, &fl_bufs_used);
				if (m == NULL) {
					panic("%s: line %d.", __func__,
					    __LINE__);
				}

				iq->intr_next = iq->intr_params;
				m->b_rptr += sc->sge.pktshift;
				if (sc->params.tp.rx_pkt_encap)
				/* It is enabled only in T6 config file */
					err_vec = G_T6_COMPR_RXERR_VEC(ntohs(cpl->err_vec));
				else
					err_vec = ntohs(cpl->err_vec);

				csum_ok = cpl->csum_calc && !err_vec;

				/* TODO: what about cpl->ip_frag? */
				if (csum_ok && !cpl->ip_frag) {
					mac_hcksum_set(m, 0, 0, 0, 0xffff,
					    HCK_FULLCKSUM_OK | HCK_FULLCKSUM |
					    HCK_IPV4_HDRCKSUM_OK);
					rxq->rxcsum++;
				}
				rxq->rxpkts++;
				rxq->rxbytes += pkt_len;
				received_bytes += pkt_len;

				*mblk_tail = m;
				mblk_tail = &m->b_next;

				break;
			}

			m = get_fl_payload(sc, fl, lq, &fl_bufs_used);
			if (m == NULL) {
				panic("%s: line %d.", __func__,
				    __LINE__);
			}

		case X_RSPD_TYPE_CPL:
			ASSERT(rss->opcode < NUM_CPL_CMDS);
			sc->cpl_handler[rss->opcode](iq, rss, m);
			break;

		default:
			break;
		}
		iq_next(iq);
		++ndescs;
		if (!iq->polling && (ndescs == budget))
			break;
	}

done:

	t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS),
		     V_CIDXINC(ndescs) | V_INGRESSQID(iq->cntxt_id) |
		     V_SEINTARM(V_QINTR_TIMER_IDX(X_TIMERREG_UPDATE_CIDX)));

	if ((fl_bufs_used > 0) || (iq->flags & IQ_HAS_FL)) {
		int starved;
		FL_LOCK(fl);
		fl->needed += fl_bufs_used;
		starved = refill_fl(sc, fl, fl->cap / 8);
		FL_UNLOCK(fl);
		if (starved)
			add_fl_to_sfl(sc, fl);
	}
	return (mblk_head);
}

/*
 * Deals with anything and everything on the given ingress queue.
 */
static int
service_iq(struct sge_iq *iq, int budget)
{
	struct sge_iq *q;
	struct sge_rxq *rxq = iq_to_rxq(iq);	/* Use iff iq is part of rxq */
	struct sge_fl *fl = &rxq->fl;		/* Use iff IQ_HAS_FL */
	struct adapter *sc = iq->adapter;
	struct rsp_ctrl *ctrl;
	const struct rss_header *rss;
	int ndescs = 0, limit, fl_bufs_used = 0;
	int rsp_type;
	uint32_t lq;
	mblk_t *m;
	STAILQ_HEAD(, sge_iq) iql = STAILQ_HEAD_INITIALIZER(iql);

	limit = budget ? budget : iq->qsize / 8;

	/*
	 * We always come back and check the descriptor ring for new indirect
	 * interrupts and other responses after running a single handler.
	 */
	for (;;) {
		while (is_new_response(iq, &ctrl)) {

			membar_consumer();

			m = NULL;
			rsp_type = G_RSPD_TYPE(ctrl->u.type_gen);
			lq = be32_to_cpu(ctrl->pldbuflen_qid);
			rss = (const void *)iq->cdesc;

			switch (rsp_type) {
			case X_RSPD_TYPE_FLBUF:

				ASSERT(iq->flags & IQ_HAS_FL);

				m = get_fl_payload(sc, fl, lq, &fl_bufs_used);
				if (m == NULL) {
					panic("%s: line %d.", __func__,
					    __LINE__);
				}

			/* FALLTHRU */
			case X_RSPD_TYPE_CPL:

				ASSERT(rss->opcode < NUM_CPL_CMDS);
				sc->cpl_handler[rss->opcode](iq, rss, m);
				break;

			case X_RSPD_TYPE_INTR:

				/*
				 * Interrupts should be forwarded only to queues
				 * that are not forwarding their interrupts.
				 * This means service_iq can recurse but only 1
				 * level deep.
				 */
				ASSERT(budget == 0);

				q = sc->sge.iqmap[lq - sc->sge.iq_start];
				if (atomic_cas_uint(&q->state, IQS_IDLE,
				    IQS_BUSY) == IQS_IDLE) {
					if (service_iq(q, q->qsize / 8) == 0) {
						(void) atomic_cas_uint(
						    &q->state, IQS_BUSY,
						    IQS_IDLE);
					} else {
						STAILQ_INSERT_TAIL(&iql, q,
						    link);
					}
				}
				break;

			default:
				break;
			}

			iq_next(iq);
			if (++ndescs == limit) {
				t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS),
				    V_CIDXINC(ndescs) |
				    V_INGRESSQID(iq->cntxt_id) |
				    V_SEINTARM(V_QINTR_TIMER_IDX(
				    X_TIMERREG_UPDATE_CIDX)));
				ndescs = 0;

				if (fl_bufs_used > 0) {
					ASSERT(iq->flags & IQ_HAS_FL);
					FL_LOCK(fl);
					fl->needed += fl_bufs_used;
					(void) refill_fl(sc, fl, fl->cap / 8);
					FL_UNLOCK(fl);
					fl_bufs_used = 0;
				}

				if (budget != 0)
					return (EINPROGRESS);
			}
		}

		if (STAILQ_EMPTY(&iql) != 0)
			break;

		/*
		 * Process the head only, and send it to the back of the list if
		 * it's still not done.
		 */
		q = STAILQ_FIRST(&iql);
		STAILQ_REMOVE_HEAD(&iql, link);
		if (service_iq(q, q->qsize / 8) == 0)
			(void) atomic_cas_uint(&q->state, IQS_BUSY, IQS_IDLE);
		else
			STAILQ_INSERT_TAIL(&iql, q, link);
	}

	t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS), V_CIDXINC(ndescs) |
	    V_INGRESSQID((u32)iq->cntxt_id) | V_SEINTARM(iq->intr_next));

	if (iq->flags & IQ_HAS_FL) {
		int starved;

		FL_LOCK(fl);
		fl->needed += fl_bufs_used;
		starved = refill_fl(sc, fl, fl->cap / 4);
		FL_UNLOCK(fl);
		if (starved != 0)
			add_fl_to_sfl(sc, fl);
	}

	return (0);
}

#ifdef TCP_OFFLOAD_ENABLE
int
t4_mgmt_tx(struct adapter *sc, mblk_t *m)
{
	return (t4_wrq_tx(sc, &sc->sge.mgmtq, m));
}

/*
 * Doesn't fail.  Holds on to work requests it can't send right away.
 */
int
t4_wrq_tx_locked(struct adapter *sc, struct sge_wrq *wrq, mblk_t *m0)
{
	struct sge_eq *eq = &wrq->eq;
	struct mblk_pair *wr_list = &wrq->wr_list;
	int can_reclaim;
	caddr_t dst;
	mblk_t *wr, *next;

	TXQ_LOCK_ASSERT_OWNED(wrq);
#ifdef TCP_OFFLOAD_ENABLE
	ASSERT((eq->flags & EQ_TYPEMASK) == EQ_OFLD ||
	    (eq->flags & EQ_TYPEMASK) == EQ_CTRL);
#else
	ASSERT((eq->flags & EQ_TYPEMASK) == EQ_CTRL);
#endif

	if (m0 != NULL) {
		if (wr_list->head != NULL)
			wr_list->tail->b_next = m0;
		else
			wr_list->head = m0;
		while (m0->b_next)
			m0 = m0->b_next;
		wr_list->tail = m0;
	}

	can_reclaim = reclaimable(eq);
	eq->cidx += can_reclaim;
	eq->avail += can_reclaim;
	if (eq->cidx >= eq->cap)
		eq->cidx -= eq->cap;

	for (wr = wr_list->head; wr; wr = next) {
		int ndesc, len = 0;
		mblk_t *m;

		next = wr->b_next;
		wr->b_next = NULL;

		for (m = wr; m; m = m->b_cont)
			len += MBLKL(m);

		ASSERT(len > 0 && (len & 0x7) == 0);
		ASSERT(len <= SGE_MAX_WR_LEN);

		ndesc = howmany(len, EQ_ESIZE);
		if (eq->avail < ndesc) {
			wr->b_next = next;
			wrq->no_desc++;
			break;
		}

		dst = (void *)&eq->desc[eq->pidx];
		for (m = wr; m; m = m->b_cont)
			copy_to_txd(eq, (void *)m->b_rptr, &dst, MBLKL(m));

		eq->pidx += ndesc;
		eq->avail -= ndesc;
		if (eq->pidx >= eq->cap)
			eq->pidx -= eq->cap;

		eq->pending += ndesc;
		if (eq->pending > 16)
			ring_tx_db(sc, eq);

		wrq->tx_wrs++;
		freemsg(wr);

		if (eq->avail < 8) {
			can_reclaim = reclaimable(eq);
			eq->cidx += can_reclaim;
			eq->avail += can_reclaim;
			if (eq->cidx >= eq->cap)
				eq->cidx -= eq->cap;
		}
	}

	if (eq->pending != 0)
		ring_tx_db(sc, eq);

	if (wr == NULL)
		wr_list->head = wr_list->tail = NULL;
	else {
		wr_list->head = wr;

		ASSERT(wr_list->tail->b_next == NULL);
	}

	return (0);
}
#endif

/* Per-packet header in a coalesced tx WR, before the SGL starts (in flits) */
#define	TXPKTS_PKT_HDR ((\
	sizeof (struct ulp_txpkt) + \
	sizeof (struct ulptx_idata) + \
	sizeof (struct cpl_tx_pkt_core)) / 8)

/* Header of a coalesced tx WR, before SGL of first packet (in flits) */
#define	TXPKTS_WR_HDR (\
	sizeof (struct fw_eth_tx_pkts_wr) / 8 + \
	TXPKTS_PKT_HDR)

/* Header of a tx WR, before SGL of first packet (in flits) */
#define	TXPKT_WR_HDR ((\
	sizeof (struct fw_eth_tx_pkt_wr) + \
	sizeof (struct cpl_tx_pkt_core)) / 8)

/* Header of a tx LSO WR, before SGL of first packet (in flits) */
#define	TXPKT_LSO_WR_HDR ((\
	sizeof (struct fw_eth_tx_pkt_wr) + \
	sizeof(struct cpl_tx_pkt_lso_core) + \
	sizeof (struct cpl_tx_pkt_core)) / 8)

mblk_t *
t4_eth_tx(void *arg, mblk_t *frame)
{
	struct sge_txq *txq = (struct sge_txq *) arg;
	struct port_info *pi = txq->port;
	struct adapter *sc = pi->adapter;
	struct sge_eq *eq = &txq->eq;
	mblk_t *next_frame;
	int rc, coalescing;
	struct txpkts txpkts;
	struct txinfo txinfo;

	txpkts.npkt = 0; /* indicates there's nothing in txpkts */
	coalescing = 0;

	TXQ_LOCK(txq);
	if (eq->avail < 8)
		(void) reclaim_tx_descs(txq, 8);
	for (; frame; frame = next_frame) {

		if (eq->avail < 8)
			break;

		next_frame = frame->b_next;
		frame->b_next = NULL;

		if (next_frame != NULL)
			coalescing = 1;

		rc = get_frame_txinfo(txq, &frame, &txinfo, coalescing);
		if (rc != 0) {
			if (rc == ENOMEM) {

				/* Short of resources, suspend tx */

				frame->b_next = next_frame;
				break;
			}

			/*
			 * Unrecoverable error for this frame, throw it
			 * away and move on to the next.
			 */

			freemsg(frame);
			continue;
		}

		if (coalescing != 0 &&
		    add_to_txpkts(txq, &txpkts, frame, &txinfo) == 0) {

			/* Successfully absorbed into txpkts */

			write_ulp_cpl_sgl(pi, txq, &txpkts, &txinfo);
			goto doorbell;
		}

		/*
		 * We weren't coalescing to begin with, or current frame could
		 * not be coalesced (add_to_txpkts flushes txpkts if a frame
		 * given to it can't be coalesced).  Either way there should be
		 * nothing in txpkts.
		 */
		ASSERT(txpkts.npkt == 0);

		/* We're sending out individual frames now */
		coalescing = 0;

		if (eq->avail < 8)
			(void) reclaim_tx_descs(txq, 8);
		rc = write_txpkt_wr(pi, txq, frame, &txinfo);
		if (rc != 0) {

			/* Short of hardware descriptors, suspend tx */

			/*
			 * This is an unlikely but expensive failure.  We've
			 * done all the hard work (DMA bindings etc.) and now we
			 * can't send out the frame.  What's worse, we have to
			 * spend even more time freeing up everything in txinfo.
			 */
			txq->qfull++;
			free_txinfo_resources(txq, &txinfo);

			frame->b_next = next_frame;
			break;
		}

doorbell:
		/* Fewer and fewer doorbells as the queue fills up */
		if (eq->pending >= (1 << (fls(eq->qsize - eq->avail) / 2))) {
			txq->txbytes += txinfo.len;
			txq->txpkts++;
			ring_tx_db(sc, eq);
		}
		(void) reclaim_tx_descs(txq, 32);
	}

	if (txpkts.npkt > 0)
		write_txpkts_wr(txq, &txpkts);

	/*
	 * frame not NULL means there was an error but we haven't thrown it
	 * away.  This can happen when we're short of tx descriptors (qfull) or
	 * maybe even DMA handles (dma_hdl_failed).  Either way, a credit flush
	 * and reclaim will get things going again.
	 *
	 * If eq->avail is already 0 we know a credit flush was requested in the
	 * WR that reduced it to 0 so we don't need another flush (we don't have
	 * any descriptor for a flush WR anyway, duh).
	 */
	if (frame && eq->avail > 0)
		write_txqflush_wr(txq);

	if (eq->pending != 0)
		ring_tx_db(sc, eq);

	(void) reclaim_tx_descs(txq, eq->qsize);
	TXQ_UNLOCK(txq);

	return (frame);
}

static inline void
init_iq(struct sge_iq *iq, struct adapter *sc, int tmr_idx, int8_t pktc_idx,
	int qsize, uint8_t esize)
{
	ASSERT(tmr_idx >= 0 && tmr_idx < SGE_NTIMERS);
	ASSERT(pktc_idx < SGE_NCOUNTERS);	/* -ve is ok, means don't use */

	iq->flags = 0;
	iq->adapter = sc;
	iq->intr_params = V_QINTR_TIMER_IDX(tmr_idx);
	iq->intr_pktc_idx = SGE_NCOUNTERS - 1;
	if (pktc_idx >= 0) {
		iq->intr_params |= F_QINTR_CNT_EN;
		iq->intr_pktc_idx = pktc_idx;
	}
	iq->qsize = roundup(qsize, 16);		/* See FW_IQ_CMD/iqsize */
	iq->esize = max(esize, 16);		/* See FW_IQ_CMD/iqesize */
}

static inline void
init_fl(struct sge_fl *fl, uint16_t qsize)
{

	fl->qsize = qsize;
}

static inline void
init_eq(struct adapter *sc, struct sge_eq *eq, uint16_t eqtype, uint16_t qsize,
    uint8_t tx_chan, uint16_t iqid)
{
	struct sge *s = &sc->sge;
	uint32_t r;

	ASSERT(tx_chan < NCHAN);
	ASSERT(eqtype <= EQ_TYPEMASK);

	if (is_t5(sc->params.chip)) {
		r = t4_read_reg(sc, A_SGE_EGRESS_QUEUES_PER_PAGE_PF);
		r >>= S_QUEUESPERPAGEPF0 +
		    (S_QUEUESPERPAGEPF1 - S_QUEUESPERPAGEPF0) * sc->pf;
		s->s_qpp = r & M_QUEUESPERPAGEPF0;
	}
 
	eq->flags = eqtype & EQ_TYPEMASK;
	eq->tx_chan = tx_chan;
	eq->iqid = iqid;
	eq->qsize = qsize;
}

/*
 * Allocates the ring for an ingress queue and an optional freelist.  If the
 * freelist is specified it will be allocated and then associated with the
 * ingress queue.
 *
 * Returns errno on failure.  Resources allocated up to that point may still be
 * allocated.  Caller is responsible for cleanup in case this function fails.
 *
 * If the ingress queue will take interrupts directly (iq->flags & IQ_INTR) then
 * the intr_idx specifies the vector, starting from 0.  Otherwise it specifies
 * the index of the queue to which its interrupts will be forwarded.
 */
static int
alloc_iq_fl(struct port_info *pi, struct sge_iq *iq, struct sge_fl *fl,
    int intr_idx, int cong)
{
	int rc, i, cntxt_id;
	size_t len;
	struct fw_iq_cmd c;
	struct adapter *sc = iq->adapter;
	uint32_t v = 0;

	len = iq->qsize * iq->esize;
	rc = alloc_desc_ring(sc, len, DDI_DMA_READ, &iq->dhdl, &iq->ahdl,
	    &iq->ba, (caddr_t *)&iq->desc);
	if (rc != 0)
		return (rc);

	bzero(&c, sizeof (c));
	c.op_to_vfn = cpu_to_be32(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE | F_FW_CMD_EXEC | V_FW_IQ_CMD_PFN(sc->pf) |
	    V_FW_IQ_CMD_VFN(0));

	c.alloc_to_len16 = cpu_to_be32(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
	    FW_LEN16(c));

	/* Special handling for firmware event queue */
	if (iq == &sc->sge.fwq)
		v |= F_FW_IQ_CMD_IQASYNCH;

	if (iq->flags & IQ_INTR)
		ASSERT(intr_idx < sc->intr_count);
	else
		v |= F_FW_IQ_CMD_IQANDST;
	v |= V_FW_IQ_CMD_IQANDSTINDEX(intr_idx);

	c.type_to_iqandstindex = cpu_to_be32(v |
	    V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
	    V_FW_IQ_CMD_VIID(pi->viid) |
	    V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT));
	c.iqdroprss_to_iqesize = cpu_to_be16(V_FW_IQ_CMD_IQPCIECH(pi->tx_chan) |
	    F_FW_IQ_CMD_IQGTSMODE |
	    V_FW_IQ_CMD_IQINTCNTTHRESH(iq->intr_pktc_idx) |
	    V_FW_IQ_CMD_IQESIZE(ilog2(iq->esize) - 4));
	c.iqsize = cpu_to_be16(iq->qsize);
	c.iqaddr = cpu_to_be64(iq->ba);
	if (cong >= 0)
		c.iqns_to_fl0congen = BE_32(F_FW_IQ_CMD_IQFLINTCONGEN);

	if (fl != NULL) {
		unsigned int chip_ver = CHELSIO_CHIP_VERSION(sc->params.chip);

		mutex_init(&fl->lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(sc->intr_pri));
		fl->flags |= FL_MTX;

		len = fl->qsize * RX_FL_ESIZE;
		rc = alloc_desc_ring(sc, len, DDI_DMA_WRITE, &fl->dhdl,
		    &fl->ahdl, &fl->ba, (caddr_t *)&fl->desc);
		if (rc != 0)
			return (rc);

		/* Allocate space for one software descriptor per buffer. */
		fl->cap = (fl->qsize - sc->sge.stat_len / RX_FL_ESIZE) * 8;
		fl->sdesc = kmem_zalloc(sizeof (struct fl_sdesc) * fl->cap,
		    KM_SLEEP);
		fl->needed = fl->cap;
		fl->lowat = roundup(sc->sge.fl_starve_threshold, 8);

		c.iqns_to_fl0congen |=
		    cpu_to_be32(V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
		    F_FW_IQ_CMD_FL0PACKEN | F_FW_IQ_CMD_FL0PADEN);
		if (cong >= 0) {
			c.iqns_to_fl0congen |=
			    BE_32(V_FW_IQ_CMD_FL0CNGCHMAP(cong) |
			    F_FW_IQ_CMD_FL0CONGCIF |
			    F_FW_IQ_CMD_FL0CONGEN);
		}

		/* In T6, for egress queue type FL there is internal overhead
		 * of 16B for header going into FLM module.  Hence the maximum
		 * allowed burst size is 448 bytes.  For T4/T5, the hardware
		 * doesn't coalesce fetch requests if more than 64 bytes of
		 * Free List pointers are provided, so we use a 128-byte Fetch
		 * Burst Minimum there (T6 implements coalescing so we can use
		 * the smaller 64-byte value there).
		 */

		c.fl0dcaen_to_fl0cidxfthresh =
		    cpu_to_be16(V_FW_IQ_CMD_FL0FBMIN(chip_ver <= CHELSIO_T5
						     ? X_FETCHBURSTMIN_128B
						     : X_FETCHBURSTMIN_64B) |
		    V_FW_IQ_CMD_FL0FBMAX(chip_ver <= CHELSIO_T5
					 ? X_FETCHBURSTMAX_512B
					 : X_FETCHBURSTMAX_256B));
		c.fl0size = cpu_to_be16(fl->qsize);
		c.fl0addr = cpu_to_be64(fl->ba);
	}

	rc = -t4_wr_mbox(sc, sc->mbox, &c, sizeof (c), &c);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to create ingress queue: %d", rc);
		return (rc);
	}

	iq->cdesc = iq->desc;
	iq->cidx = 0;
	iq->gen = 1;
	iq->intr_next = iq->intr_params;
	iq->adapter = sc;
	iq->cntxt_id = be16_to_cpu(c.iqid);
	iq->abs_id = be16_to_cpu(c.physiqid);
	iq->flags |= IQ_ALLOCATED;
	mutex_init(&iq->lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(DDI_INTR_PRI(sc->intr_pri)));
	iq->polling = 0;

	cntxt_id = iq->cntxt_id - sc->sge.iq_start;
	if (cntxt_id >= sc->sge.niq) {
		panic("%s: iq->cntxt_id (%d) more than the max (%d)", __func__,
		    cntxt_id, sc->sge.niq - 1);
	}
	sc->sge.iqmap[cntxt_id] = iq;

	if (fl != NULL) {
		fl->cntxt_id = be16_to_cpu(c.fl0id);
		fl->pidx = fl->cidx = 0;
		fl->copy_threshold = rx_copy_threshold;

		cntxt_id = fl->cntxt_id - sc->sge.eq_start;
		if (cntxt_id >= sc->sge.neq) {
			panic("%s: fl->cntxt_id (%d) more than the max (%d)",
			    __func__, cntxt_id, sc->sge.neq - 1);
		}
		sc->sge.eqmap[cntxt_id] = (void *)fl;

		FL_LOCK(fl);
		(void) refill_fl(sc, fl, fl->lowat);
		FL_UNLOCK(fl);

		iq->flags |= IQ_HAS_FL;
	}

	if (is_t5(sc->params.chip) && cong >= 0) {
		uint32_t param, val;

		param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
			V_FW_PARAMS_PARAM_YZ(iq->cntxt_id);
		if (cong == 0)
			val = 1 << 19;
		else {
			val = 2 << 19;
			for (i = 0; i < 4; i++) {
				if (cong & (1 << i))
					val |= 1 << (i << 2);
			}
		}

		rc = -t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
		if (rc != 0) {
			/* report error but carry on */
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to set congestion manager context for "
			    "ingress queue %d: %d", iq->cntxt_id, rc);
		}
	}

	/* Enable IQ interrupts */
	iq->state = IQS_IDLE;
	t4_write_reg(sc, MYPF_REG(A_SGE_PF_GTS), V_SEINTARM(iq->intr_params) |
	    V_INGRESSQID(iq->cntxt_id));

	return (0);
}

static int
free_iq_fl(struct port_info *pi, struct sge_iq *iq, struct sge_fl *fl)
{
	int rc;
	struct adapter *sc = iq->adapter;
	dev_info_t *dip;

	dip = pi ? pi->dip : sc->dip;

	if (iq != NULL) {
		if (iq->flags & IQ_ALLOCATED) {
			rc = -t4_iq_free(sc, sc->mbox, sc->pf, 0,
			    FW_IQ_TYPE_FL_INT_CAP, iq->cntxt_id,
			    fl ? fl->cntxt_id : 0xffff, 0xffff);
			if (rc != 0) {
				cxgb_printf(dip, CE_WARN,
				    "failed to free queue %p: %d", iq, rc);
				return (rc);
			}
			mutex_destroy(&iq->lock);
			iq->flags &= ~IQ_ALLOCATED;
		}

		if (iq->desc != NULL) {
			(void) free_desc_ring(&iq->dhdl, &iq->ahdl);
			iq->desc = NULL;
		}

		bzero(iq, sizeof (*iq));
	}

	if (fl != NULL) {
		if (fl->sdesc != NULL) {
			FL_LOCK(fl);
			free_fl_bufs(fl);
			FL_UNLOCK(fl);

			kmem_free(fl->sdesc, sizeof (struct fl_sdesc) *
			    fl->cap);
			fl->sdesc = NULL;
		}

		if (fl->desc != NULL) {
			(void) free_desc_ring(&fl->dhdl, &fl->ahdl);
			fl->desc = NULL;
		}

		if (fl->flags & FL_MTX) {
			mutex_destroy(&fl->lock);
			fl->flags &= ~FL_MTX;
		}

		bzero(fl, sizeof (struct sge_fl));
	}

	return (0);
}

static int
alloc_fwq(struct adapter *sc)
{
	int rc, intr_idx;
	struct sge_iq *fwq = &sc->sge.fwq;

	init_iq(fwq, sc, 0, 0, FW_IQ_QSIZE, FW_IQ_ESIZE);
	fwq->flags |= IQ_INTR;	/* always */
	intr_idx = sc->intr_count > 1 ? 1 : 0;
	rc = alloc_iq_fl(sc->port[0], fwq, NULL, intr_idx, -1);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to create firmware event queue: %d.", rc);
		return (rc);
	}

	return (0);
}

static int
free_fwq(struct adapter *sc)
{

	return (free_iq_fl(NULL, &sc->sge.fwq, NULL));
}

#ifdef TCP_OFFLOAD_ENABLE
static int
alloc_mgmtq(struct adapter *sc)
{
	int rc;
	struct sge_wrq *mgmtq = &sc->sge.mgmtq;

	init_eq(sc, &mgmtq->eq, EQ_CTRL, CTRL_EQ_QSIZE, sc->port[0]->tx_chan,
	    sc->sge.fwq.cntxt_id);
	rc = alloc_wrq(sc, NULL, mgmtq, 0);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to create management queue: %d\n", rc);
		return (rc);
	}

	return (0);
}
#endif

static int
alloc_rxq(struct port_info *pi, struct sge_rxq *rxq, int intr_idx, int i)
{
	int rc;

	rxq->port = pi;
	rc = alloc_iq_fl(pi, &rxq->iq, &rxq->fl, intr_idx, 1 << pi->tx_chan);
	if (rc != 0)
		return (rc);

	rxq->ksp = setup_rxq_kstats(pi, rxq, i);

	return (rc);
}

static int
free_rxq(struct port_info *pi, struct sge_rxq *rxq)
{
	int rc;

	if (rxq->ksp != NULL) {
		kstat_delete(rxq->ksp);
		rxq->ksp = NULL;
	}

	rc = free_iq_fl(pi, &rxq->iq, &rxq->fl);
	if (rc == 0)
		bzero(&rxq->fl, sizeof (*rxq) - offsetof(struct sge_rxq, fl));

	return (rc);
}

#ifdef TCP_OFFLOAD_ENABLE
static int
alloc_ofld_rxq(struct port_info *pi, struct sge_ofld_rxq *ofld_rxq,
	int intr_idx)
{
	int rc;

	rc = alloc_iq_fl(pi, &ofld_rxq->iq, &ofld_rxq->fl, intr_idx,
	    1 << pi->tx_chan);
	if (rc != 0)
		return (rc);

	return (rc);
}

static int
free_ofld_rxq(struct port_info *pi, struct sge_ofld_rxq *ofld_rxq)
{
	int rc;

	rc = free_iq_fl(pi, &ofld_rxq->iq, &ofld_rxq->fl);
	if (rc == 0)
		bzero(&ofld_rxq->fl, sizeof (*ofld_rxq) -
		    offsetof(struct sge_ofld_rxq, fl));

	return (rc);
}
#endif

static int
ctrl_eq_alloc(struct adapter *sc, struct sge_eq *eq)
{
	int rc, cntxt_id;
	struct fw_eq_ctrl_cmd c;

	bzero(&c, sizeof (c));

	c.op_to_vfn = BE_32(V_FW_CMD_OP(FW_EQ_CTRL_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE | F_FW_CMD_EXEC | V_FW_EQ_CTRL_CMD_PFN(sc->pf) |
	    V_FW_EQ_CTRL_CMD_VFN(0));
	c.alloc_to_len16 = BE_32(F_FW_EQ_CTRL_CMD_ALLOC |
	    F_FW_EQ_CTRL_CMD_EQSTART | FW_LEN16(c));
	c.cmpliqid_eqid = htonl(V_FW_EQ_CTRL_CMD_CMPLIQID(eq->iqid)); /* TODO */
	c.physeqid_pkd = BE_32(0);
	c.fetchszm_to_iqid =
	    BE_32(V_FW_EQ_CTRL_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
	    V_FW_EQ_CTRL_CMD_PCIECHN(eq->tx_chan) |
	    F_FW_EQ_CTRL_CMD_FETCHRO | V_FW_EQ_CTRL_CMD_IQID(eq->iqid));
	c.dcaen_to_eqsize =
	    BE_32(V_FW_EQ_CTRL_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
	    V_FW_EQ_CTRL_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
	    V_FW_EQ_CTRL_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
	    V_FW_EQ_CTRL_CMD_EQSIZE(eq->qsize));
	c.eqaddr = BE_64(eq->ba);

	rc = -t4_wr_mbox(sc, sc->mbox, &c, sizeof (c), &c);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to create control queue %d: %d", eq->tx_chan, rc);
		return (rc);
	}
	eq->flags |= EQ_ALLOCATED;

	eq->cntxt_id = G_FW_EQ_CTRL_CMD_EQID(BE_32(c.cmpliqid_eqid));
	cntxt_id = eq->cntxt_id - sc->sge.eq_start;
	if (cntxt_id >= sc->sge.neq)
		panic("%s: eq->cntxt_id (%d) more than the max (%d)", __func__,
		    cntxt_id, sc->sge.neq - 1);
	sc->sge.eqmap[cntxt_id] = eq;

	return (rc);
}

static int
eth_eq_alloc(struct adapter *sc, struct port_info *pi, struct sge_eq *eq)
{
	int rc, cntxt_id;
	struct fw_eq_eth_cmd c;

	bzero(&c, sizeof (c));

	c.op_to_vfn = BE_32(V_FW_CMD_OP(FW_EQ_ETH_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE | F_FW_CMD_EXEC | V_FW_EQ_ETH_CMD_PFN(sc->pf) |
	    V_FW_EQ_ETH_CMD_VFN(0));
	c.alloc_to_len16 = BE_32(F_FW_EQ_ETH_CMD_ALLOC |
	    F_FW_EQ_ETH_CMD_EQSTART | FW_LEN16(c));
	c.autoequiqe_to_viid = BE_32(F_FW_EQ_ETH_CMD_AUTOEQUIQE |
	    F_FW_EQ_ETH_CMD_AUTOEQUEQE | V_FW_EQ_ETH_CMD_VIID(pi->viid));
	c.fetchszm_to_iqid =
	    BE_32(V_FW_EQ_ETH_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
	    V_FW_EQ_ETH_CMD_PCIECHN(eq->tx_chan) | F_FW_EQ_ETH_CMD_FETCHRO |
	    V_FW_EQ_ETH_CMD_IQID(eq->iqid));
	c.dcaen_to_eqsize = BE_32(V_FW_EQ_ETH_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
	    V_FW_EQ_ETH_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
	    V_FW_EQ_ETH_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
	    V_FW_EQ_ETH_CMD_EQSIZE(eq->qsize));
	c.eqaddr = BE_64(eq->ba);

	rc = -t4_wr_mbox(sc, sc->mbox, &c, sizeof (c), &c);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN,
		    "failed to create Ethernet egress queue: %d", rc);
		return (rc);
	}
	eq->flags |= EQ_ALLOCATED;

	eq->cntxt_id = G_FW_EQ_ETH_CMD_EQID(BE_32(c.eqid_pkd));
	cntxt_id = eq->cntxt_id - sc->sge.eq_start;
	if (cntxt_id >= sc->sge.neq)
		panic("%s: eq->cntxt_id (%d) more than the max (%d)", __func__,
		    cntxt_id, sc->sge.neq - 1);
	sc->sge.eqmap[cntxt_id] = eq;

	return (rc);
}

#ifdef TCP_OFFLOAD_ENABLE
static int
ofld_eq_alloc(struct adapter *sc, struct port_info *pi, struct sge_eq *eq)
{
	int rc, cntxt_id;
	struct fw_eq_ofld_cmd c;

	bzero(&c, sizeof (c));

	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD) | F_FW_CMD_REQUEST |
	    F_FW_CMD_WRITE | F_FW_CMD_EXEC | V_FW_EQ_OFLD_CMD_PFN(sc->pf) |
	    V_FW_EQ_OFLD_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_OFLD_CMD_ALLOC |
	    F_FW_EQ_OFLD_CMD_EQSTART | FW_LEN16(c));
	c.fetchszm_to_iqid =
	    htonl(V_FW_EQ_OFLD_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
	    V_FW_EQ_OFLD_CMD_PCIECHN(eq->tx_chan) |
	    F_FW_EQ_OFLD_CMD_FETCHRO | V_FW_EQ_OFLD_CMD_IQID(eq->iqid));
	c.dcaen_to_eqsize =
	    BE_32(V_FW_EQ_OFLD_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
	    V_FW_EQ_OFLD_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
	    V_FW_EQ_OFLD_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
	    V_FW_EQ_OFLD_CMD_EQSIZE(eq->qsize));
	c.eqaddr = BE_64(eq->ba);

	rc = -t4_wr_mbox(sc, sc->mbox, &c, sizeof (c), &c);
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN,
		    "failed to create egress queue for TCP offload: %d", rc);
		return (rc);
	}
	eq->flags |= EQ_ALLOCATED;

	eq->cntxt_id = G_FW_EQ_OFLD_CMD_EQID(BE_32(c.eqid_pkd));
	cntxt_id = eq->cntxt_id - sc->sge.eq_start;
	if (cntxt_id >= sc->sge.neq)
		panic("%s: eq->cntxt_id (%d) more than the max (%d)", __func__,
		    cntxt_id, sc->sge.neq - 1);
	sc->sge.eqmap[cntxt_id] = eq;

	return (rc);
}
#endif

static int
alloc_eq(struct adapter *sc, struct port_info *pi, struct sge_eq *eq)
{
	int rc;
	size_t len;

	mutex_init(&eq->lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(sc->intr_pri));
	eq->flags |= EQ_MTX;

	len = eq->qsize * EQ_ESIZE;
	rc = alloc_desc_ring(sc, len, DDI_DMA_WRITE, &eq->desc_dhdl,
	    &eq->desc_ahdl, &eq->ba, (caddr_t *)&eq->desc);
	if (rc != 0)
		return (rc);

	eq->cap = eq->qsize - sc->sge.stat_len / EQ_ESIZE;
	eq->spg = (void *)&eq->desc[eq->cap];
	eq->avail = eq->cap - 1;	/* one less to avoid cidx = pidx */
	eq->pidx = eq->cidx = 0;
	eq->doorbells = sc->doorbells;

	switch (eq->flags & EQ_TYPEMASK) {
	case EQ_CTRL:
		rc = ctrl_eq_alloc(sc, eq);
		break;

	case EQ_ETH:
		rc = eth_eq_alloc(sc, pi, eq);
		break;

#ifdef TCP_OFFLOAD_ENABLE
	case EQ_OFLD:
		rc = ofld_eq_alloc(sc, pi, eq);
		break;
#endif

	default:
		panic("%s: invalid eq type %d.", __func__,
		    eq->flags & EQ_TYPEMASK);
	}

	if (eq->doorbells &
		(DOORBELL_UDB | DOORBELL_UDBWC | DOORBELL_WCWR)) {
		uint32_t s_qpp = sc->sge.s_qpp;
		uint32_t mask = (1 << s_qpp) - 1;
		volatile uint8_t *udb;

		udb = (volatile uint8_t *)sc->reg1p + UDBS_DB_OFFSET;
		udb += (eq->cntxt_id >> s_qpp) << PAGE_SHIFT;   /* pg offset */
		eq->udb_qid = eq->cntxt_id & mask;              /* id in page */
		if (eq->udb_qid > PAGE_SIZE / UDBS_SEG_SIZE)
			eq->doorbells &= ~DOORBELL_WCWR;
		else {
			udb += eq->udb_qid << UDBS_SEG_SHIFT;   /* seg offset */
			eq->udb_qid = 0;
		}
		eq->udb = (volatile void *)udb;
	}

	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to allocate egress queue(%d): %d",
		    eq->flags & EQ_TYPEMASK, rc);
	}

	return (rc);
}

static int
free_eq(struct adapter *sc, struct sge_eq *eq)
{
	int rc;

	if (eq->flags & EQ_ALLOCATED) {
		switch (eq->flags & EQ_TYPEMASK) {
		case EQ_CTRL:
			rc = -t4_ctrl_eq_free(sc, sc->mbox, sc->pf, 0,
			    eq->cntxt_id);
			break;

		case EQ_ETH:
			rc = -t4_eth_eq_free(sc, sc->mbox, sc->pf, 0,
			    eq->cntxt_id);
			break;

#ifdef TCP_OFFLOAD_ENABLE
		case EQ_OFLD:
			rc = -t4_ofld_eq_free(sc, sc->mbox, sc->pf, 0,
			    eq->cntxt_id);
			break;
#endif

		default:
			panic("%s: invalid eq type %d.", __func__,
			    eq->flags & EQ_TYPEMASK);
		}
		if (rc != 0) {
			cxgb_printf(sc->dip, CE_WARN,
			    "failed to free egress queue (%d): %d",
			    eq->flags & EQ_TYPEMASK, rc);
			return (rc);
		}
		eq->flags &= ~EQ_ALLOCATED;
	}

	if (eq->desc != NULL) {
		(void) free_desc_ring(&eq->desc_dhdl, &eq->desc_ahdl);
		eq->desc = NULL;
	}

	if (eq->flags & EQ_MTX)
		mutex_destroy(&eq->lock);

	bzero(eq, sizeof (*eq));
	return (0);
}

#ifdef TCP_OFFLOAD_ENABLE
/* ARGSUSED */
static int
alloc_wrq(struct adapter *sc, struct port_info *pi, struct sge_wrq *wrq,
    int idx)
{
	int rc;

	rc = alloc_eq(sc, pi, &wrq->eq);
	if (rc != 0)
		return (rc);

	wrq->adapter = sc;
	wrq->wr_list.head = NULL;
	wrq->wr_list.tail = NULL;

	/*
	 * TODO: use idx to figure out what kind of wrq this is and install
	 * useful kstats for it.
	 */

	return (rc);
}

static int
free_wrq(struct adapter *sc, struct sge_wrq *wrq)
{
	int rc;

	rc = free_eq(sc, &wrq->eq);
	if (rc != 0)
		return (rc);

	bzero(wrq, sizeof (*wrq));
	return (0);
}
#endif

static int
alloc_txq(struct port_info *pi, struct sge_txq *txq, int idx)
{
	int rc, i;
	struct adapter *sc = pi->adapter;
	struct sge_eq *eq = &txq->eq;

	rc = alloc_eq(sc, pi, eq);
	if (rc != 0)
		return (rc);

	txq->port = pi;
	txq->sdesc = kmem_zalloc(sizeof (struct tx_sdesc) * eq->cap, KM_SLEEP);
	txq->txb_size = eq->qsize * tx_copy_threshold;
	rc = alloc_tx_copybuffer(sc, txq->txb_size, &txq->txb_dhdl,
	    &txq->txb_ahdl, &txq->txb_ba, &txq->txb_va);
	if (rc == 0)
		txq->txb_avail = txq->txb_size;
	else
		txq->txb_avail = txq->txb_size = 0;

	/*
	 * TODO: is this too low?  Worst case would need around 4 times qsize
	 * (all tx descriptors filled to the brim with SGLs, with each entry in
	 * the SGL coming from a distinct DMA handle).  Increase tx_dhdl_total
	 * if you see too many dma_hdl_failed.
	 */
	txq->tx_dhdl_total = eq->qsize * 2;
	txq->tx_dhdl = kmem_zalloc(sizeof (ddi_dma_handle_t) *
	    txq->tx_dhdl_total, KM_SLEEP);
	for (i = 0; i < txq->tx_dhdl_total; i++) {
		rc = ddi_dma_alloc_handle(sc->dip, &sc->sge.dma_attr_tx,
		    DDI_DMA_SLEEP, 0, &txq->tx_dhdl[i]);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN,
			    "%s: failed to allocate DMA handle (%d)",
			    __func__, rc);
			return (rc == DDI_DMA_NORESOURCES ? ENOMEM : EINVAL);
		}
		txq->tx_dhdl_avail++;
	}

	txq->ksp = setup_txq_kstats(pi, txq, idx);

	return (rc);
}

static int
free_txq(struct port_info *pi, struct sge_txq *txq)
{
	int i;
	struct adapter *sc = pi->adapter;
	struct sge_eq *eq = &txq->eq;

	if (txq->ksp != NULL) {
		kstat_delete(txq->ksp);
		txq->ksp = NULL;
	}

	if (txq->txb_va != NULL) {
		(void) free_desc_ring(&txq->txb_dhdl, &txq->txb_ahdl);
		txq->txb_va = NULL;
	}

	if (txq->sdesc != NULL) {
		struct tx_sdesc *sd;
		ddi_dma_handle_t hdl;

		TXQ_LOCK(txq);
		while (eq->cidx != eq->pidx) {
			sd = &txq->sdesc[eq->cidx];

			for (i = sd->hdls_used; i; i--) {
				hdl = txq->tx_dhdl[txq->tx_dhdl_cidx];
				(void) ddi_dma_unbind_handle(hdl);
				if (++txq->tx_dhdl_cidx == txq->tx_dhdl_total)
					txq->tx_dhdl_cidx = 0;
			}

			ASSERT(sd->m);
			freemsgchain(sd->m);

			eq->cidx += sd->desc_used;
			if (eq->cidx >= eq->cap)
				eq->cidx -= eq->cap;

			txq->txb_avail += txq->txb_used;
		}
		ASSERT(txq->tx_dhdl_cidx == txq->tx_dhdl_pidx);
		ASSERT(txq->txb_avail == txq->txb_size);
		TXQ_UNLOCK(txq);

		kmem_free(txq->sdesc, sizeof (struct tx_sdesc) * eq->cap);
		txq->sdesc = NULL;
	}

	if (txq->tx_dhdl != NULL) {
		for (i = 0; i < txq->tx_dhdl_total; i++) {
			if (txq->tx_dhdl[i] != NULL)
				ddi_dma_free_handle(&txq->tx_dhdl[i]);
		}
	}

	(void) free_eq(sc, &txq->eq);

	bzero(txq, sizeof (*txq));
	return (0);
}

/*
 * Allocates a block of contiguous memory for DMA.  Can be used to allocate
 * memory for descriptor rings or for tx/rx copy buffers.
 *
 * Caller does not have to clean up anything if this function fails, it cleans
 * up after itself.
 *
 * Caller provides the following:
 * len		length of the block of memory to allocate.
 * flags	DDI_DMA_* flags to use (CONSISTENT/STREAMING, READ/WRITE/RDWR)
 * acc_attr	device access attributes for the allocation.
 * dma_attr	DMA attributes for the allocation
 *
 * If the function is successful it fills up this information:
 * dma_hdl	DMA handle for the allocated memory
 * acc_hdl	access handle for the allocated memory
 * ba		bus address of the allocated memory
 * va		KVA of the allocated memory.
 */
static int
alloc_dma_memory(struct adapter *sc, size_t len, int flags,
    ddi_device_acc_attr_t *acc_attr, ddi_dma_attr_t *dma_attr,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl,
    uint64_t *pba, caddr_t *pva)
{
	int rc;
	ddi_dma_handle_t dhdl;
	ddi_acc_handle_t ahdl;
	ddi_dma_cookie_t cookie;
	uint_t ccount;
	caddr_t va;
	size_t real_len;

	*pva = NULL;

	/*
	 * DMA handle.
	 */
	rc = ddi_dma_alloc_handle(sc->dip, dma_attr, DDI_DMA_SLEEP, 0, &dhdl);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to allocate DMA handle: %d", rc);

		return (rc == DDI_DMA_NORESOURCES ? ENOMEM : EINVAL);
	}

	/*
	 * Memory suitable for DMA.
	 */
	rc = ddi_dma_mem_alloc(dhdl, len, acc_attr,
	    flags & DDI_DMA_CONSISTENT ? DDI_DMA_CONSISTENT : DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, 0, &va, &real_len, &ahdl);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to allocate DMA memory: %d", rc);

		ddi_dma_free_handle(&dhdl);
		return (ENOMEM);
	}

	if (len != real_len) {
		cxgb_printf(sc->dip, CE_WARN,
		    "%s: len (%u) != real_len (%u)\n", len, real_len);
	}

	/*
	 * DMA bindings.
	 */
	rc = ddi_dma_addr_bind_handle(dhdl, NULL, va, real_len, flags, NULL,
	    NULL, &cookie, &ccount);
	if (rc != DDI_DMA_MAPPED) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to map DMA memory: %d", rc);

		ddi_dma_mem_free(&ahdl);
		ddi_dma_free_handle(&dhdl);
		return (ENOMEM);
	}
	if (ccount != 1) {
		cxgb_printf(sc->dip, CE_WARN,
		    "unusable DMA mapping (%d segments)", ccount);
		(void) free_desc_ring(&dhdl, &ahdl);
	}

	bzero(va, real_len);
	*dma_hdl = dhdl;
	*acc_hdl = ahdl;
	*pba = cookie.dmac_laddress;
	*pva = va;

	return (0);
}

static int
free_dma_memory(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl)
{
	(void) ddi_dma_unbind_handle(*dhdl);
	ddi_dma_mem_free(ahdl);
	ddi_dma_free_handle(dhdl);

	return (0);
}

static int
alloc_desc_ring(struct adapter *sc, size_t len, int rw,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl,
    uint64_t *pba, caddr_t *pva)
{
	ddi_device_acc_attr_t *acc_attr = &sc->sge.acc_attr_desc;
	ddi_dma_attr_t *dma_attr = &sc->sge.dma_attr_desc;

	return (alloc_dma_memory(sc, len, DDI_DMA_CONSISTENT | rw, acc_attr,
	    dma_attr, dma_hdl, acc_hdl, pba, pva));
}

static int
free_desc_ring(ddi_dma_handle_t *dhdl, ddi_acc_handle_t *ahdl)
{
	return (free_dma_memory(dhdl, ahdl));
}

static int
alloc_tx_copybuffer(struct adapter *sc, size_t len,
    ddi_dma_handle_t *dma_hdl, ddi_acc_handle_t *acc_hdl,
    uint64_t *pba, caddr_t *pva)
{
	ddi_device_acc_attr_t *acc_attr = &sc->sge.acc_attr_tx;
	ddi_dma_attr_t *dma_attr = &sc->sge.dma_attr_desc; /* NOT dma_attr_tx */

	return (alloc_dma_memory(sc, len, DDI_DMA_STREAMING | DDI_DMA_WRITE,
	    acc_attr, dma_attr, dma_hdl, acc_hdl, pba, pva));
}

static inline bool
is_new_response(const struct sge_iq *iq, struct rsp_ctrl **ctrl)
{
	(void) ddi_dma_sync(iq->dhdl, (uintptr_t)iq->cdesc -
	    (uintptr_t)iq->desc, iq->esize, DDI_DMA_SYNC_FORKERNEL);

	*ctrl = (void *)((uintptr_t)iq->cdesc +
	    (iq->esize - sizeof (struct rsp_ctrl)));

	return ((((*ctrl)->u.type_gen >> S_RSPD_GEN) == iq->gen));
}

static inline void
iq_next(struct sge_iq *iq)
{
	iq->cdesc = (void *) ((uintptr_t)iq->cdesc + iq->esize);
	if (++iq->cidx == iq->qsize - 1) {
		iq->cidx = 0;
		iq->gen ^= 1;
		iq->cdesc = iq->desc;
	}
}

/*
 * Fill up the freelist by upto nbufs and maybe ring its doorbell.
 *
 * Returns non-zero to indicate that it should be added to the list of starving
 * freelists.
 */
static int
refill_fl(struct adapter *sc, struct sge_fl *fl, int nbufs)
{
	uint64_t *d = &fl->desc[fl->pidx];
	struct fl_sdesc *sd = &fl->sdesc[fl->pidx];

	FL_LOCK_ASSERT_OWNED(fl);
	ASSERT(nbufs >= 0);

	if (nbufs > fl->needed)
		nbufs = fl->needed;

	while (nbufs--) {
		if (sd->rxb != NULL) {
			if (sd->rxb->ref_cnt == 1) {
				/*
				 * Buffer is available for recycling.  Two ways
				 * this can happen:
				 *
				 * a) All the packets DMA'd into it last time
				 *    around were within the rx_copy_threshold
				 *    and no part of the buffer was ever passed
				 *    up (ref_cnt never went over 1).
				 *
				 * b) Packets DMA'd into the buffer were passed
				 *    up but have all been freed by the upper
				 *    layers by now (ref_cnt went over 1 but is
				 *    now back to 1).
				 *
				 * Either way the bus address in the descriptor
				 * ring is already valid.
				 */
				ASSERT(*d == cpu_to_be64(sd->rxb->ba));
				d++;
				goto recycled;
			} else {
				/*
				 * Buffer still in use and we need a
				 * replacement. But first release our reference
				 * on the existing buffer.
				 */
				rxbuf_free(sd->rxb);
			}
		}

		sd->rxb = rxbuf_alloc(sc->sge.rxbuf_cache, KM_NOSLEEP, 1);
		if (sd->rxb == NULL)
			break;
		*d++ = cpu_to_be64(sd->rxb->ba);

recycled:	fl->pending++;
		sd++;
		fl->needed--;
		if (++fl->pidx == fl->cap) {
			fl->pidx = 0;
			sd = fl->sdesc;
			d = fl->desc;
		}
	}

	if (fl->pending >= 8)
		ring_fl_db(sc, fl);

	return (FL_RUNNING_LOW(fl) && !(fl->flags & FL_STARVING));
}

#ifndef TAILQ_FOREACH_SAFE
#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

/*
 * Attempt to refill all starving freelists.
 */
static void
refill_sfl(void *arg)
{
	struct adapter *sc = arg;
	struct sge_fl *fl, *fl_temp;

	mutex_enter(&sc->sfl_lock);
	TAILQ_FOREACH_SAFE(fl, &sc->sfl, link, fl_temp) {
		FL_LOCK(fl);
		(void) refill_fl(sc, fl, 64);
		if (FL_NOT_RUNNING_LOW(fl) || fl->flags & FL_DOOMED) {
			TAILQ_REMOVE(&sc->sfl, fl, link);
			fl->flags &= ~FL_STARVING;
		}
		FL_UNLOCK(fl);
	}

	if (!TAILQ_EMPTY(&sc->sfl) != 0)
		sc->sfl_timer =  timeout(refill_sfl, sc, drv_usectohz(100000));
	mutex_exit(&sc->sfl_lock);
}

static void
add_fl_to_sfl(struct adapter *sc, struct sge_fl *fl)
{
	mutex_enter(&sc->sfl_lock);
	FL_LOCK(fl);
	if ((fl->flags & FL_DOOMED) == 0) {
		if (TAILQ_EMPTY(&sc->sfl) != 0) {
			sc->sfl_timer = timeout(refill_sfl, sc,
			    drv_usectohz(100000));
		}
		fl->flags |= FL_STARVING;
		TAILQ_INSERT_TAIL(&sc->sfl, fl, link);
	}
	FL_UNLOCK(fl);
	mutex_exit(&sc->sfl_lock);
}

static void
free_fl_bufs(struct sge_fl *fl)
{
	struct fl_sdesc *sd;
	unsigned int i;

	FL_LOCK_ASSERT_OWNED(fl);

	for (i = 0; i < fl->cap; i++) {
		sd = &fl->sdesc[i];

		if (sd->rxb != NULL) {
			rxbuf_free(sd->rxb);
			sd->rxb = NULL;
		}
	}
}

/*
 * Note that fl->cidx and fl->offset are left unchanged in case of failure.
 */
static mblk_t *
get_fl_payload(struct adapter *sc, struct sge_fl *fl,
	       uint32_t len_newbuf, int *fl_bufs_used)
{
	struct mblk_pair frame = {0};
	struct rxbuf *rxb;
	mblk_t *m = NULL;
	uint_t nbuf = 0, len, copy, n;
	uint32_t cidx, offset;

	/*
	 * The SGE won't pack a new frame into the current buffer if the entire
	 * payload doesn't fit in the remaining space.  Move on to the next buf
	 * in that case.
	 */
	if (fl->offset > 0 && len_newbuf & F_RSPD_NEWBUF) {
		fl->offset = 0;
		if (++fl->cidx == fl->cap)
			fl->cidx = 0;
		nbuf++;
	}
	cidx = fl->cidx;
	offset = fl->offset;

	len = G_RSPD_LEN(len_newbuf);	/* pktshift + payload length */
	copy = (len <= fl->copy_threshold);
	if (copy != 0) {
		frame.head = m = allocb(len, BPRI_HI);
		if (m == NULL)
			return (NULL);
	}

	while (len) {
		rxb = fl->sdesc[cidx].rxb;
		n = min(len, rxb->buf_size - offset);

		(void) ddi_dma_sync(rxb->dhdl, offset, n,
		    DDI_DMA_SYNC_FORKERNEL);

		if (copy != 0)
			bcopy(rxb->va + offset, m->b_wptr, n);
		else {
			m = desballoc((unsigned char *)rxb->va + offset, n,
			    BPRI_HI, &rxb->freefunc);
			if (m == NULL) {
				freemsg(frame.head);
				return (NULL);
			}
			atomic_inc_uint(&rxb->ref_cnt);
			if (frame.head != NULL)
				frame.tail->b_cont = m;
			else
				frame.head = m;
			frame.tail = m;
		}
		m->b_wptr += n;
		len -= n;
		offset += roundup(n, sc->sge.fl_align);
		ASSERT(offset <= rxb->buf_size);
		if (offset == rxb->buf_size) {
			offset = 0;
			if (++cidx == fl->cap)
				cidx = 0;
			nbuf++;
		}
	}

	fl->cidx = cidx;
	fl->offset = offset;
	(*fl_bufs_used) += nbuf;

	ASSERT(frame.head != NULL);
	return (frame.head);
}

/*
 * We'll do immediate data tx for non-LSO, but only when not coalescing.  We're
 * willing to use upto 2 hardware descriptors which means a maximum of 96 bytes
 * of immediate data.
 */
#define	IMM_LEN ( \
	2 * EQ_ESIZE \
	- sizeof (struct fw_eth_tx_pkt_wr) \
	- sizeof (struct cpl_tx_pkt_core))

/*
 * Returns non-zero on failure, no need to cleanup anything in that case.
 *
 * Note 1: We always try to pull up the mblk if required and return E2BIG only
 * if this fails.
 *
 * Note 2: We'll also pullup incoming mblk if HW_LSO is set and the first mblk
 * does not have the TCP header in it.
 */
static int
get_frame_txinfo(struct sge_txq *txq, mblk_t **fp, struct txinfo *txinfo,
    int sgl_only)
{
	uint32_t flags = 0, len, n;
	mblk_t *m = *fp;
	int rc;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* will manipulate txb and dma_hdls */

	mac_hcksum_get(m, NULL, NULL, NULL, NULL, &flags);
	txinfo->flags = flags;

	mac_lso_get(m, &txinfo->mss, &flags);
	txinfo->flags |= flags;

	if (flags & HW_LSO)
		sgl_only = 1;	/* Do not allow immediate data with LSO */

start:	txinfo->nsegs = 0;
	txinfo->hdls_used = 0;
	txinfo->txb_used = 0;
	txinfo->len = 0;

	/* total length and a rough estimate of # of segments */
	n = 0;
	for (; m; m = m->b_cont) {
		len = MBLKL(m);
		n += (len / PAGE_SIZE) + 1;
		txinfo->len += len;
	}
	m = *fp;

	if (n >= TX_SGL_SEGS || (flags & HW_LSO && MBLKL(m) < 50)) {
		txq->pullup_early++;
		m = msgpullup(*fp, -1);
		if (m == NULL) {
			txq->pullup_failed++;
			return (E2BIG);	/* (*fp) left as it was */
		}
		freemsg(*fp);
		*fp = m;
		mac_hcksum_set(m, NULL, NULL, NULL, NULL, txinfo->flags);
	}

	if (txinfo->len <= IMM_LEN && !sgl_only)
		return (0);	/* nsegs = 0 tells caller to use imm. tx */

	if (txinfo->len <= txq->copy_threshold &&
	    copy_into_txb(txq, m, txinfo->len, txinfo) == 0)
		goto done;

	for (; m; m = m->b_cont) {

		len = MBLKL(m);

		/* Use tx copy buffer if this mblk is small enough */
		if (len <= txq->copy_threshold &&
		    copy_into_txb(txq, m, len, txinfo) == 0)
			continue;

		/* Add DMA bindings for this mblk to the SGL */
		rc = add_mblk(txq, txinfo, m, len);

		if (rc == E2BIG ||
		    (txinfo->nsegs == TX_SGL_SEGS && m->b_cont)) {

			txq->pullup_late++;
			m = msgpullup(*fp, -1);
			if (m != NULL) {
				free_txinfo_resources(txq, txinfo);
				freemsg(*fp);
				*fp = m;
				mac_hcksum_set(m, NULL, NULL, NULL, NULL,
				    txinfo->flags);
				goto start;
			}

			txq->pullup_failed++;
			rc = E2BIG;
		}

		if (rc != 0) {
			free_txinfo_resources(txq, txinfo);
			return (rc);
		}
	}

	ASSERT(txinfo->nsegs > 0 && txinfo->nsegs <= TX_SGL_SEGS);

done:

	/*
	 * Store the # of flits required to hold this frame's SGL in nflits.  An
	 * SGL has a (ULPTX header + len0, addr0) tuple optionally followed by
	 * multiple (len0 + len1, addr0, addr1) tuples.  If addr1 is not used
	 * then len1 must be set to 0.
	 */
	n = txinfo->nsegs - 1;
	txinfo->nflits = (3 * n) / 2 + (n & 1) + 2;
	if (n & 1)
		txinfo->sgl.sge[n / 2].len[1] = cpu_to_be32(0);

	txinfo->sgl.cmd_nsge = cpu_to_be32(V_ULPTX_CMD((u32)ULP_TX_SC_DSGL) |
	    V_ULPTX_NSGE(txinfo->nsegs));

	return (0);
}

static inline int
fits_in_txb(struct sge_txq *txq, int len, int *waste)
{
	if (txq->txb_avail < len)
		return (0);

	if (txq->txb_next + len <= txq->txb_size) {
		*waste = 0;
		return (1);
	}

	*waste = txq->txb_size - txq->txb_next;

	return (txq->txb_avail - *waste < len ? 0 : 1);
}

#define	TXB_CHUNK	64

/*
 * Copies the specified # of bytes into txq's tx copy buffer and updates txinfo
 * and txq to indicate resources used.  Caller has to make sure that those many
 * bytes are available in the mblk chain (b_cont linked).
 */
static inline int
copy_into_txb(struct sge_txq *txq, mblk_t *m, int len, struct txinfo *txinfo)
{
	int waste, n;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* will manipulate txb */

	if (!fits_in_txb(txq, len, &waste)) {
		txq->txb_full++;
		return (ENOMEM);
	}

	if (waste != 0) {
		ASSERT((waste & (TXB_CHUNK - 1)) == 0);
		txinfo->txb_used += waste;
		txq->txb_avail -= waste;
		txq->txb_next = 0;
	}

	for (n = 0; n < len; m = m->b_cont) {
		bcopy(m->b_rptr, txq->txb_va + txq->txb_next + n, MBLKL(m));
		n += MBLKL(m);
	}

	add_seg(txinfo, txq->txb_ba + txq->txb_next, len);

	n = roundup(len, TXB_CHUNK);
	txinfo->txb_used += n;
	txq->txb_avail -= n;
	txq->txb_next += n;
	ASSERT(txq->txb_next <= txq->txb_size);
	if (txq->txb_next == txq->txb_size)
		txq->txb_next = 0;

	return (0);
}

static inline void
add_seg(struct txinfo *txinfo, uint64_t ba, uint32_t len)
{
	ASSERT(txinfo->nsegs < TX_SGL_SEGS);	/* must have room */

	if (txinfo->nsegs != 0) {
		int idx = txinfo->nsegs - 1;
		txinfo->sgl.sge[idx / 2].len[idx & 1] = cpu_to_be32(len);
		txinfo->sgl.sge[idx / 2].addr[idx & 1] = cpu_to_be64(ba);
	} else {
		txinfo->sgl.len0 = cpu_to_be32(len);
		txinfo->sgl.addr0 = cpu_to_be64(ba);
	}
	txinfo->nsegs++;
}

/*
 * This function cleans up any partially allocated resources when it fails so
 * there's nothing for the caller to clean up in that case.
 *
 * EIO indicates permanent failure.  Caller should drop the frame containing
 * this mblk and continue.
 *
 * E2BIG indicates that the SGL length for this mblk exceeds the hardware
 * limit.  Caller should pull up the frame before trying to send it out.
 * (This error means our pullup_early heuristic did not work for this frame)
 *
 * ENOMEM indicates a temporary shortage of resources (DMA handles, other DMA
 * resources, etc.).  Caller should suspend the tx queue and wait for reclaim to
 * free up resources.
 */
static inline int
add_mblk(struct sge_txq *txq, struct txinfo *txinfo, mblk_t *m, int len)
{
	ddi_dma_handle_t dhdl;
	ddi_dma_cookie_t cookie;
	uint_t ccount = 0;
	int rc;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* will manipulate dhdls */

	if (txq->tx_dhdl_avail == 0) {
		txq->dma_hdl_failed++;
		return (ENOMEM);
	}

	dhdl = txq->tx_dhdl[txq->tx_dhdl_pidx];
	rc = ddi_dma_addr_bind_handle(dhdl, NULL, (caddr_t)m->b_rptr, len,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL, &cookie,
	    &ccount);
	if (rc != DDI_DMA_MAPPED) {
		txq->dma_map_failed++;

		ASSERT(rc != DDI_DMA_INUSE && rc != DDI_DMA_PARTIAL_MAP);

		return (rc == DDI_DMA_NORESOURCES ? ENOMEM : EIO);
	}

	if (ccount + txinfo->nsegs > TX_SGL_SEGS) {
		(void) ddi_dma_unbind_handle(dhdl);
		return (E2BIG);
	}

	add_seg(txinfo, cookie.dmac_laddress, cookie.dmac_size);
	while (--ccount) {
		ddi_dma_nextcookie(dhdl, &cookie);
		add_seg(txinfo, cookie.dmac_laddress, cookie.dmac_size);
	}

	if (++txq->tx_dhdl_pidx == txq->tx_dhdl_total)
		txq->tx_dhdl_pidx = 0;
	txq->tx_dhdl_avail--;
	txinfo->hdls_used++;

	return (0);
}

/*
 * Releases all the txq resources used up in the specified txinfo.
 */
static void
free_txinfo_resources(struct sge_txq *txq, struct txinfo *txinfo)
{
	int n;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* dhdls, txb */

	n = txinfo->txb_used;
	if (n > 0) {
		txq->txb_avail += n;
		if (n <= txq->txb_next)
			txq->txb_next -= n;
		else {
			n -= txq->txb_next;
			txq->txb_next = txq->txb_size - n;
		}
	}

	for (n = txinfo->hdls_used; n > 0; n--) {
		if (txq->tx_dhdl_pidx > 0)
			txq->tx_dhdl_pidx--;
		else
			txq->tx_dhdl_pidx = txq->tx_dhdl_total - 1;
		txq->tx_dhdl_avail++;
		(void) ddi_dma_unbind_handle(txq->tx_dhdl[txq->tx_dhdl_pidx]);
	}
}

/*
 * Returns 0 to indicate that m has been accepted into a coalesced tx work
 * request.  It has either been folded into txpkts or txpkts was flushed and m
 * has started a new coalesced work request (as the first frame in a fresh
 * txpkts).
 *
 * Returns non-zero to indicate a failure - caller is responsible for
 * transmitting m, if there was anything in txpkts it has been flushed.
 */
static int
add_to_txpkts(struct sge_txq *txq, struct txpkts *txpkts, mblk_t *m,
    struct txinfo *txinfo)
{
	struct sge_eq *eq = &txq->eq;
	int can_coalesce;
	struct tx_sdesc *txsd;
	uint8_t flits;

	TXQ_LOCK_ASSERT_OWNED(txq);

	if (txpkts->npkt > 0) {
		flits = TXPKTS_PKT_HDR + txinfo->nflits;
		can_coalesce = (txinfo->flags & HW_LSO) == 0 &&
		    txpkts->nflits + flits <= TX_WR_FLITS &&
		    txpkts->nflits + flits <= eq->avail * 8 &&
		    txpkts->plen + txinfo->len < 65536;

		if (can_coalesce != 0) {
			txpkts->tail->b_next = m;
			txpkts->tail = m;
			txpkts->npkt++;
			txpkts->nflits += flits;
			txpkts->plen += txinfo->len;

			txsd = &txq->sdesc[eq->pidx];
			txsd->txb_used += txinfo->txb_used;
			txsd->hdls_used += txinfo->hdls_used;

			return (0);
		}

		/*
		 * Couldn't coalesce m into txpkts.  The first order of business
		 * is to send txpkts on its way.  Then we'll revisit m.
		 */
		write_txpkts_wr(txq, txpkts);
	}

	/*
	 * Check if we can start a new coalesced tx work request with m as
	 * the first packet in it.
	 */

	ASSERT(txpkts->npkt == 0);
	ASSERT(txinfo->len < 65536);

	flits = TXPKTS_WR_HDR + txinfo->nflits;
	can_coalesce = (txinfo->flags & HW_LSO) == 0 &&
	    flits <= eq->avail * 8 && flits <= TX_WR_FLITS;

	if (can_coalesce == 0)
		return (EINVAL);

	/*
	 * Start a fresh coalesced tx WR with m as the first frame in it.
	 */
	txpkts->tail = m;
	txpkts->npkt = 1;
	txpkts->nflits = flits;
	txpkts->flitp = &eq->desc[eq->pidx].flit[2];
	txpkts->plen = txinfo->len;

	txsd = &txq->sdesc[eq->pidx];
	txsd->m = m;
	txsd->txb_used = txinfo->txb_used;
	txsd->hdls_used = txinfo->hdls_used;

	return (0);
}

/*
 * Note that write_txpkts_wr can never run out of hardware descriptors (but
 * write_txpkt_wr can).  add_to_txpkts ensures that a frame is accepted for
 * coalescing only if sufficient hardware descriptors are available.
 */
static void
write_txpkts_wr(struct sge_txq *txq, struct txpkts *txpkts)
{
	struct sge_eq *eq = &txq->eq;
	struct fw_eth_tx_pkts_wr *wr;
	struct tx_sdesc *txsd;
	uint32_t ctrl;
	uint16_t ndesc;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* pidx, avail */

	ndesc = howmany(txpkts->nflits, 8);

	wr = (void *)&eq->desc[eq->pidx];
	wr->op_pkd = cpu_to_be32(V_FW_WR_OP(FW_ETH_TX_PKTS_WR) |
	    V_FW_WR_IMMDLEN(0)); /* immdlen does not matter in this WR */
	ctrl = V_FW_WR_LEN16(howmany(txpkts->nflits, 2));
	if (eq->avail == ndesc)
		ctrl |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;
	wr->equiq_to_len16 = cpu_to_be32(ctrl);
	wr->plen = cpu_to_be16(txpkts->plen);
	wr->npkt = txpkts->npkt;
	wr->r3 = wr->type = 0;

	/* Everything else already written */

	txsd = &txq->sdesc[eq->pidx];
	txsd->desc_used = ndesc;

	txq->txb_used += txsd->txb_used / TXB_CHUNK;
	txq->hdl_used += txsd->hdls_used;

	ASSERT(eq->avail >= ndesc);

	eq->pending += ndesc;
	eq->avail -= ndesc;
	eq->pidx += ndesc;
	if (eq->pidx >= eq->cap)
		eq->pidx -= eq->cap;

	txq->txpkts_pkts += txpkts->npkt;
	txq->txpkts_wrs++;
	txpkts->npkt = 0;	/* emptied */
}

static int
write_txpkt_wr(struct port_info *pi, struct sge_txq *txq, mblk_t *m,
    struct txinfo *txinfo)
{
	struct sge_eq *eq = &txq->eq;
	struct fw_eth_tx_pkt_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	uint32_t ctrl;	/* used in many unrelated places */
	uint64_t ctrl1;
	int nflits, ndesc;
	struct tx_sdesc *txsd;
	caddr_t dst;

	TXQ_LOCK_ASSERT_OWNED(txq);	/* pidx, avail */

	/*
	 * Do we have enough flits to send this frame out?
	 */
	ctrl = sizeof (struct cpl_tx_pkt_core);
	if (txinfo->flags & HW_LSO) {
		nflits = TXPKT_LSO_WR_HDR;
		ctrl += sizeof(struct cpl_tx_pkt_lso_core);
	} else
		nflits = TXPKT_WR_HDR;
	if (txinfo->nsegs > 0)
		nflits += txinfo->nflits;
	else {
		nflits += howmany(txinfo->len, 8);
		ctrl += txinfo->len;
	}
	ndesc = howmany(nflits, 8);
	if (ndesc > eq->avail)
		return (ENOMEM);

	/* Firmware work request header */
	wr = (void *)&eq->desc[eq->pidx];
	wr->op_immdlen = cpu_to_be32(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
	    V_FW_WR_IMMDLEN(ctrl));
	ctrl = V_FW_WR_LEN16(howmany(nflits, 2));
	if (eq->avail == ndesc)
		ctrl |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;
	wr->equiq_to_len16 = cpu_to_be32(ctrl);
	wr->r3 = 0;

	if (txinfo->flags & HW_LSO) {
		struct cpl_tx_pkt_lso_core *lso = (void *)(wr + 1);
		char *p = (void *)m->b_rptr;
		ctrl = V_LSO_OPCODE((u32)CPL_TX_PKT_LSO) | F_LSO_FIRST_SLICE |
		    F_LSO_LAST_SLICE;

		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		if (((struct ether_header *)p)->ether_type ==
		    htons(ETHERTYPE_VLAN)) {
			ctrl |= V_LSO_ETHHDR_LEN(1);
			p += sizeof (struct ether_vlan_header);
		} else
			p += sizeof (struct ether_header);

		/* LINTED: E_BAD_PTR_CAST_ALIGN for IPH_HDR_LENGTH() */
		ctrl |= V_LSO_IPHDR_LEN(IPH_HDR_LENGTH(p) / 4);
		/* LINTED: E_BAD_PTR_CAST_ALIGN for IPH_HDR_LENGTH() */
		p += IPH_HDR_LENGTH(p);
		ctrl |= V_LSO_TCPHDR_LEN(TCP_HDR_LENGTH((tcph_t *)p) / 4);

		lso->lso_ctrl = cpu_to_be32(ctrl);
		lso->ipid_ofst = cpu_to_be16(0);
		lso->mss = cpu_to_be16(txinfo->mss);
		lso->seqno_offset = cpu_to_be32(0);
		if (is_t4(pi->adapter->params.chip))
			lso->len = cpu_to_be32(txinfo->len);
		else
			lso->len = cpu_to_be32(V_LSO_T5_XFER_SIZE(txinfo->len));

		cpl = (void *)(lso + 1);

		txq->tso_wrs++;
	} else
		cpl = (void *)(wr + 1);

	/* Checksum offload */
	ctrl1 = 0;
	if (!(txinfo->flags & HCK_IPV4_HDRCKSUM))
		ctrl1 |= F_TXPKT_IPCSUM_DIS;
	if (!(txinfo->flags & HCK_FULLCKSUM))
		ctrl1 |= F_TXPKT_L4CSUM_DIS;
	if (ctrl1 == 0)
		txq->txcsum++;	/* some hardware assistance provided */

	/* CPL header */
	cpl->ctrl0 = cpu_to_be32(V_TXPKT_OPCODE(CPL_TX_PKT) |
	    V_TXPKT_INTF(pi->tx_chan) | V_TXPKT_PF(pi->adapter->pf));
	cpl->pack = 0;
	cpl->len = cpu_to_be16(txinfo->len);
	cpl->ctrl1 = cpu_to_be64(ctrl1);

	/* Software descriptor */
	txsd = &txq->sdesc[eq->pidx];
	txsd->m = m;
	txsd->txb_used = txinfo->txb_used;
	txsd->hdls_used = txinfo->hdls_used;
	/* LINTED: E_ASSIGN_NARROW_CONV */
	txsd->desc_used = ndesc;

	txq->txb_used += txinfo->txb_used / TXB_CHUNK;
	txq->hdl_used += txinfo->hdls_used;

	eq->pending += ndesc;
	eq->avail -= ndesc;
	eq->pidx += ndesc;
	if (eq->pidx >= eq->cap)
		eq->pidx -= eq->cap;

	/* SGL */
	dst = (void *)(cpl + 1);
	if (txinfo->nsegs > 0) {
		txq->sgl_wrs++;
		copy_to_txd(eq, (void *)&txinfo->sgl, &dst, txinfo->nflits * 8);

		/* Need to zero-pad to a 16 byte boundary if not on one */
		if ((uintptr_t)dst & 0xf)
			/* LINTED: E_BAD_PTR_CAST_ALIGN */
			*(uint64_t *)dst = 0;

	} else {
		txq->imm_wrs++;
#ifdef DEBUG
		ctrl = txinfo->len;
#endif
		for (; m; m = m->b_cont) {
			copy_to_txd(eq, (void *)m->b_rptr, &dst, MBLKL(m));
#ifdef DEBUG
			ctrl -= MBLKL(m);
#endif
		}
		ASSERT(ctrl == 0);
	}

	txq->txpkt_wrs++;
	return (0);
}

static inline void
write_ulp_cpl_sgl(struct port_info *pi, struct sge_txq *txq,
    struct txpkts *txpkts, struct txinfo *txinfo)
{
	struct ulp_txpkt *ulpmc;
	struct ulptx_idata *ulpsc;
	struct cpl_tx_pkt_core *cpl;
	uintptr_t flitp, start, end;
	uint64_t ctrl;
	caddr_t dst;

	ASSERT(txpkts->npkt > 0);

	start = (uintptr_t)txq->eq.desc;
	end = (uintptr_t)txq->eq.spg;

	/* Checksum offload */
	ctrl = 0;
	if (!(txinfo->flags & HCK_IPV4_HDRCKSUM))
		ctrl |= F_TXPKT_IPCSUM_DIS;
	if (!(txinfo->flags & HCK_FULLCKSUM))
		ctrl |= F_TXPKT_L4CSUM_DIS;
	if (ctrl == 0)
		txq->txcsum++;	/* some hardware assistance provided */

	/*
	 * The previous packet's SGL must have ended at a 16 byte boundary (this
	 * is required by the firmware/hardware).  It follows that flitp cannot
	 * wrap around between the ULPTX master command and ULPTX subcommand (8
	 * bytes each), and that it can not wrap around in the middle of the
	 * cpl_tx_pkt_core either.
	 */
	flitp = (uintptr_t)txpkts->flitp;
	ASSERT((flitp & 0xf) == 0);

	/* ULP master command */
	ulpmc = (void *)flitp;
	ulpmc->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	ulpmc->len = htonl(howmany(sizeof (*ulpmc) + sizeof (*ulpsc) +
	    sizeof (*cpl) + 8 * txinfo->nflits, 16));

	/* ULP subcommand */
	ulpsc = (void *)(ulpmc + 1);
	ulpsc->cmd_more = cpu_to_be32(V_ULPTX_CMD((u32)ULP_TX_SC_IMM) |
	    F_ULP_TX_SC_MORE);
	ulpsc->len = cpu_to_be32(sizeof (struct cpl_tx_pkt_core));

	flitp += sizeof (*ulpmc) + sizeof (*ulpsc);
	if (flitp == end)
		flitp = start;

	/* CPL_TX_PKT */
	cpl = (void *)flitp;
	cpl->ctrl0 = cpu_to_be32(V_TXPKT_OPCODE(CPL_TX_PKT) |
	    V_TXPKT_INTF(pi->tx_chan) | V_TXPKT_PF(pi->adapter->pf));
	cpl->pack = 0;
	cpl->len = cpu_to_be16(txinfo->len);
	cpl->ctrl1 = cpu_to_be64(ctrl);

	flitp += sizeof (*cpl);
	if (flitp == end)
		flitp = start;

	/* SGL for this frame */
	dst = (caddr_t)flitp;
	copy_to_txd(&txq->eq, (void *)&txinfo->sgl, &dst, txinfo->nflits * 8);
	flitp = (uintptr_t)dst;

	/* Zero pad and advance to a 16 byte boundary if not already at one. */
	if (flitp & 0xf) {

		/* no matter what, flitp should be on an 8 byte boundary */
		ASSERT((flitp & 0x7) == 0);

		*(uint64_t *)flitp = 0;
		flitp += sizeof (uint64_t);
		txpkts->nflits++;
	}

	if (flitp == end)
		flitp = start;

	txpkts->flitp = (void *)flitp;
}

static inline void
copy_to_txd(struct sge_eq *eq, caddr_t from, caddr_t *to, int len)
{
	if ((uintptr_t)(*to) + len <= (uintptr_t)eq->spg) {
		bcopy(from, *to, len);
		(*to) += len;
	} else {
		int portion = (uintptr_t)eq->spg - (uintptr_t)(*to);

		bcopy(from, *to, portion);
		from += portion;
		portion = len - portion;	/* remaining */
		bcopy(from, (void *)eq->desc, portion);
		(*to) = (caddr_t)eq->desc + portion;
	}
}

static inline void
ring_tx_db(struct adapter *sc, struct sge_eq *eq)
{
	int val, db_mode;
	u_int db = eq->doorbells;

	if (eq->pending > 1)
		db &= ~DOORBELL_WCWR;

	if (eq->pending > eq->pidx) {
		int offset = eq->cap - (eq->pending - eq->pidx);

		/* pidx has wrapped around since last doorbell */

		(void) ddi_dma_sync(eq->desc_dhdl,
		    offset * sizeof (struct tx_desc), 0,
		    DDI_DMA_SYNC_FORDEV);
		(void) ddi_dma_sync(eq->desc_dhdl,
		    0, eq->pidx * sizeof (struct tx_desc),
		    DDI_DMA_SYNC_FORDEV);
	} else if (eq->pending > 0) {
		(void) ddi_dma_sync(eq->desc_dhdl,
		    (eq->pidx - eq->pending) * sizeof (struct tx_desc),
		    eq->pending * sizeof (struct tx_desc),
		    DDI_DMA_SYNC_FORDEV);
	}

	membar_producer();

	if (is_t4(sc->params.chip))
		val = V_PIDX(eq->pending);
	else
		val = V_PIDX_T5(eq->pending);

	db_mode = (1 << (ffs(db) - 1));
	switch (db_mode) {
		case DOORBELL_UDB:
			*eq->udb = LE_32(V_QID(eq->udb_qid) | val);
			break;

		case DOORBELL_WCWR: 
			{
				volatile uint64_t *dst, *src;
				int i;
				/*
				 * Queues whose 128B doorbell segment fits in
				 * the page do not use relative qid
				 * (udb_qid is always 0).  Only queues with
				 * doorbell segments can do WCWR.
				 */
				ASSERT(eq->udb_qid == 0 && eq->pending == 1);

				dst = (volatile void *)((uintptr_t)eq->udb +
				    UDBS_WR_OFFSET - UDBS_DB_OFFSET);
				i = eq->pidx ? eq->pidx - 1 : eq->cap - 1;
				src = (void *)&eq->desc[i];
				while (src != (void *)&eq->desc[i + 1])
				        *dst++ = *src++;
				membar_producer();
				break;
			}

		case DOORBELL_UDBWC:
			*eq->udb = LE_32(V_QID(eq->udb_qid) | val);
			membar_producer();
			break;

		case DOORBELL_KDB:
			t4_write_reg(sc, MYPF_REG(A_SGE_PF_KDOORBELL),
			    V_QID(eq->cntxt_id) | val);
			break;
	}
 
	eq->pending = 0;
}

static int
reclaim_tx_descs(struct sge_txq *txq, int howmany)
{
	struct tx_sdesc *txsd;
	uint_t cidx, can_reclaim, reclaimed, txb_freed, hdls_freed;
	struct sge_eq *eq = &txq->eq;

	EQ_LOCK_ASSERT_OWNED(eq);

	cidx = eq->spg->cidx;	/* stable snapshot */
	cidx = be16_to_cpu(cidx);

	if (cidx >= eq->cidx)
		can_reclaim = cidx - eq->cidx;
	else
		can_reclaim = cidx + eq->cap - eq->cidx;

	if (can_reclaim == 0)
		return (0);

	txb_freed = hdls_freed = reclaimed = 0;
	do {
		int ndesc;

		txsd = &txq->sdesc[eq->cidx];
		ndesc = txsd->desc_used;

		/* Firmware doesn't return "partial" credits. */
		ASSERT(can_reclaim >= ndesc);

		/*
		 * We always keep mblk around, even for immediate data.  If mblk
		 * is NULL, this has to be the software descriptor for a credit
		 * flush work request.
		 */
		if (txsd->m != NULL)
			freemsgchain(txsd->m);
#ifdef DEBUG
		else {
			ASSERT(txsd->txb_used == 0);
			ASSERT(txsd->hdls_used == 0);
			ASSERT(ndesc == 1);
		}
#endif

		txb_freed += txsd->txb_used;
		hdls_freed += txsd->hdls_used;
		reclaimed += ndesc;

		eq->cidx += ndesc;
		if (eq->cidx >= eq->cap)
			eq->cidx -= eq->cap;

		can_reclaim -= ndesc;

	} while (can_reclaim && reclaimed < howmany);

	eq->avail += reclaimed;
	ASSERT(eq->avail < eq->cap);	/* avail tops out at (cap - 1) */

	txq->txb_avail += txb_freed;

	txq->tx_dhdl_avail += hdls_freed;
	ASSERT(txq->tx_dhdl_avail <= txq->tx_dhdl_total);
	for (; hdls_freed; hdls_freed--) {
		(void) ddi_dma_unbind_handle(txq->tx_dhdl[txq->tx_dhdl_cidx]);
		if (++txq->tx_dhdl_cidx == txq->tx_dhdl_total)
			txq->tx_dhdl_cidx = 0;
	}

	return (reclaimed);
}

static void
write_txqflush_wr(struct sge_txq *txq)
{
	struct sge_eq *eq = &txq->eq;
	struct fw_eq_flush_wr *wr;
	struct tx_sdesc *txsd;

	EQ_LOCK_ASSERT_OWNED(eq);
	ASSERT(eq->avail > 0);

	wr = (void *)&eq->desc[eq->pidx];
	bzero(wr, sizeof (*wr));
	wr->opcode = FW_EQ_FLUSH_WR;
	wr->equiq_to_len16 = cpu_to_be32(V_FW_WR_LEN16(sizeof (*wr) / 16) |
	    F_FW_WR_EQUEQ | F_FW_WR_EQUIQ);

	txsd = &txq->sdesc[eq->pidx];
	txsd->m = NULL;
	txsd->txb_used = 0;
	txsd->hdls_used = 0;
	txsd->desc_used = 1;

	eq->pending++;
	eq->avail--;
	if (++eq->pidx == eq->cap)
		eq->pidx = 0;
}

static int
t4_eth_rx(struct sge_iq *iq, const struct rss_header *rss, mblk_t *m)
{
	bool csum_ok;
	uint16_t err_vec;
	struct sge_rxq *rxq = (void *)iq;
	struct mblk_pair chain = {0};
	struct adapter *sc = iq->adapter;
	const struct cpl_rx_pkt *cpl = (const void *)(rss + 1);

	iq->intr_next = iq->intr_params;

	m->b_rptr += sc->sge.pktshift;

	/* Compressed error vector is enabled for T6 only */
	if (sc->params.tp.rx_pkt_encap)
		/* It is enabled only in T6 config file */
		err_vec = G_T6_COMPR_RXERR_VEC(ntohs(cpl->err_vec));
	else
		err_vec = ntohs(cpl->err_vec);

	csum_ok = cpl->csum_calc && !err_vec;
	/* TODO: what about cpl->ip_frag? */
	if (csum_ok && !cpl->ip_frag) {
		mac_hcksum_set(m, 0, 0, 0, 0xffff,
		    HCK_FULLCKSUM_OK | HCK_FULLCKSUM |
		    HCK_IPV4_HDRCKSUM_OK);
		rxq->rxcsum++;
	}

	/* Add to the chain that we'll send up */
	if (chain.head != NULL)
		chain.tail->b_next = m;
	else
		chain.head = m;
	chain.tail = m;

	t4_mac_rx(rxq->port, rxq, chain.head);

	rxq->rxpkts++;
	rxq->rxbytes  += be16_to_cpu(cpl->len);
	return (0);
}

#define	FL_HW_IDX(idx)	((idx) >> 3)

static inline void
ring_fl_db(struct adapter *sc, struct sge_fl *fl)
{
	int desc_start, desc_last, ndesc;
	uint32_t v = sc->params.arch.sge_fl_db ;

	ndesc = FL_HW_IDX(fl->pending);

	/* Hold back one credit if pidx = cidx */
	if (FL_HW_IDX(fl->pidx) == FL_HW_IDX(fl->cidx))
		ndesc--;

	/*
	 * There are chances of ndesc modified above (to avoid pidx = cidx).
	 * If there is nothing to post, return.
	 */
	if (ndesc <= 0)
		return;

	desc_last = FL_HW_IDX(fl->pidx);

	if (fl->pidx < fl->pending) {
		/* There was a wrap */
		desc_start = FL_HW_IDX(fl->pidx + fl->cap - fl->pending);

		/* From desc_start to the end of list */
		(void) ddi_dma_sync(fl->dhdl, desc_start * RX_FL_ESIZE, 0,
		    DDI_DMA_SYNC_FORDEV);

		/* From start of list to the desc_last */
		if (desc_last != 0)
			(void) ddi_dma_sync(fl->dhdl, 0, desc_last *
			    RX_FL_ESIZE, DDI_DMA_SYNC_FORDEV);
	} else {
		/* There was no wrap, sync from start_desc to last_desc */
		desc_start = FL_HW_IDX(fl->pidx - fl->pending);
		(void) ddi_dma_sync(fl->dhdl, desc_start * RX_FL_ESIZE,
		    ndesc * RX_FL_ESIZE, DDI_DMA_SYNC_FORDEV);
	}

	if (is_t4(sc->params.chip))
		v |= V_PIDX(ndesc);
	else
		v |= V_PIDX_T5(ndesc);
	v |= V_QID(fl->cntxt_id) | V_PIDX(ndesc);

	membar_producer();

	t4_write_reg(sc, MYPF_REG(A_SGE_PF_KDOORBELL), v);

	/*
	 * Update pending count:
	 * Deduct the number of descriptors posted
	 */
	fl->pending -= ndesc * 8;
}

static void
tx_reclaim_task(void *arg)
{
	struct sge_txq *txq = arg;

	TXQ_LOCK(txq);
	reclaim_tx_descs(txq, txq->eq.qsize);
	TXQ_UNLOCK(txq);
}

/* ARGSUSED */
static int
handle_sge_egr_update(struct sge_iq *iq, const struct rss_header *rss,
                mblk_t *m)
{
	const struct cpl_sge_egr_update *cpl = (const void *)(rss + 1);
	unsigned int qid = G_EGR_QID(ntohl(cpl->opcode_qid));
	struct adapter *sc = iq->adapter;
	struct sge *s = &sc->sge;
	struct sge_eq *eq;
	struct sge_txq *txq;

	txq = (void *)s->eqmap[qid - s->eq_start];
	eq = &txq->eq;
	txq->qflush++;
	t4_mac_tx_update(txq->port, txq);

	ddi_taskq_dispatch(sc->tq[eq->tx_chan], tx_reclaim_task,
		(void *)txq, DDI_NOSLEEP);

	return (0);
}

static int
handle_fw_rpl(struct sge_iq *iq, const struct rss_header *rss, mblk_t *m)
{
	struct adapter *sc = iq->adapter;
	const struct cpl_fw6_msg *cpl = (const void *)(rss + 1);

	ASSERT(m == NULL);

	if (cpl->type == FW_TYPE_RSSCPL || cpl->type == FW6_TYPE_RSSCPL) {
		const struct rss_header *rss2;

		rss2 = (const struct rss_header *)&cpl->data[0];
		return (sc->cpl_handler[rss2->opcode](iq, rss2, m));
	}
	return (sc->fw_msg_handler[cpl->type](sc, &cpl->data[0]));
}

int
t4_alloc_tx_maps(struct adapter *sc, struct tx_maps *txmaps, int count,
    int flags)
{
	int i, rc;

	txmaps->map_total =  count;
	txmaps->map_avail = txmaps->map_cidx = txmaps->map_pidx = 0;

	txmaps->map =  kmem_zalloc(sizeof (ddi_dma_handle_t) *
	    txmaps->map_total, flags);

	for (i = 0; i < count; i++) {
		rc = ddi_dma_alloc_handle(sc->dip, &sc->sge.dma_attr_tx,
		    DDI_DMA_SLEEP, 0, &txmaps->map[i]);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN,
			    "%s: failed to allocate DMA handle (%d)",
			    __func__, rc);
			return (rc == DDI_DMA_NORESOURCES ? ENOMEM : EINVAL);
		}
		txmaps->map_avail++;
	}

	return (0);
}

#define	KS_UINIT(x)	kstat_named_init(&kstatp->x, #x, KSTAT_DATA_ULONG)
#define	KS_CINIT(x)	kstat_named_init(&kstatp->x, #x, KSTAT_DATA_CHAR)
#define	KS_U_SET(x, y)	kstatp->x.value.ul = (y)
#define	KS_U_FROM(x, y)	kstatp->x.value.ul = (y)->x
#define	KS_C_SET(x, ...)	\
			(void) snprintf(kstatp->x.value.c, 16,  __VA_ARGS__)

/*
 * cxgbe:X:config
 */
struct cxgbe_port_config_kstats {
	kstat_named_t idx;
	kstat_named_t nrxq;
	kstat_named_t ntxq;
	kstat_named_t first_rxq;
	kstat_named_t first_txq;
	kstat_named_t controller;
	kstat_named_t factory_mac_address;
};

/*
 * cxgbe:X:info
 */
struct cxgbe_port_info_kstats {
	kstat_named_t transceiver;
	kstat_named_t rx_ovflow0;
	kstat_named_t rx_ovflow1;
	kstat_named_t rx_ovflow2;
	kstat_named_t rx_ovflow3;
	kstat_named_t rx_trunc0;
	kstat_named_t rx_trunc1;
	kstat_named_t rx_trunc2;
	kstat_named_t rx_trunc3;
	kstat_named_t tx_pause;
	kstat_named_t rx_pause;
};

static kstat_t *
setup_port_config_kstats(struct port_info *pi)
{
	kstat_t *ksp;
	struct cxgbe_port_config_kstats *kstatp;
	int ndata;
	dev_info_t *pdip = ddi_get_parent(pi->dip);
	uint8_t *ma = &pi->hw_addr[0];

	ndata = sizeof (struct cxgbe_port_config_kstats) /
	    sizeof (kstat_named_t);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), "config",
	    "net", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	kstatp = (struct cxgbe_port_config_kstats *)ksp->ks_data;

	KS_UINIT(idx);
	KS_UINIT(nrxq);
	KS_UINIT(ntxq);
	KS_UINIT(first_rxq);
	KS_UINIT(first_txq);
	KS_CINIT(controller);
	KS_CINIT(factory_mac_address);

	KS_U_SET(idx, pi->port_id);
	KS_U_SET(nrxq, pi->nrxq);
	KS_U_SET(ntxq, pi->ntxq);
	KS_U_SET(first_rxq, pi->first_rxq);
	KS_U_SET(first_txq, pi->first_txq);
	KS_C_SET(controller, "%s%d", ddi_driver_name(pdip),
	    ddi_get_instance(pdip));
	KS_C_SET(factory_mac_address, "%02X%02X%02X%02X%02X%02X",
	    ma[0], ma[1], ma[2], ma[3], ma[4], ma[5]);

	/* Do NOT set ksp->ks_update.  These kstats do not change. */

	/* Install the kstat */
	ksp->ks_private = (void *)pi;
	kstat_install(ksp);

	return (ksp);
}

static kstat_t *
setup_port_info_kstats(struct port_info *pi)
{
	kstat_t *ksp;
	struct cxgbe_port_info_kstats *kstatp;
	int ndata;

	ndata = sizeof (struct cxgbe_port_info_kstats) / sizeof (kstat_named_t);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), "info",
	    "net", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	kstatp = (struct cxgbe_port_info_kstats *)ksp->ks_data;

	KS_CINIT(transceiver);
	KS_UINIT(rx_ovflow0);
	KS_UINIT(rx_ovflow1);
	KS_UINIT(rx_ovflow2);
	KS_UINIT(rx_ovflow3);
	KS_UINIT(rx_trunc0);
	KS_UINIT(rx_trunc1);
	KS_UINIT(rx_trunc2);
	KS_UINIT(rx_trunc3);
	KS_UINIT(tx_pause);
	KS_UINIT(rx_pause);

	/* Install the kstat */
	ksp->ks_update = update_port_info_kstats;
	ksp->ks_private = (void *)pi;
	kstat_install(ksp);

	return (ksp);
}

static int
update_port_info_kstats(kstat_t *ksp, int rw)
{
	struct cxgbe_port_info_kstats *kstatp =
	    (struct cxgbe_port_info_kstats *)ksp->ks_data;
	struct port_info *pi = ksp->ks_private;
	static const char *mod_str[] = { NULL, "LR", "SR", "ER", "TWINAX",
	    "active TWINAX", "LRM" };
	uint32_t bgmap;

	if (rw == KSTAT_WRITE)
		return (0);

	if (pi->mod_type == FW_PORT_MOD_TYPE_NONE)
		KS_C_SET(transceiver, "unplugged");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		KS_C_SET(transceiver, "unknown");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		KS_C_SET(transceiver, "unsupported");
	else if (pi->mod_type > 0 && pi->mod_type < ARRAY_SIZE(mod_str))
		KS_C_SET(transceiver, "%s", mod_str[pi->mod_type]);
	else
		KS_C_SET(transceiver, "type %d", pi->mod_type);

#define	GET_STAT(name) t4_read_reg64(pi->adapter, \
	    PORT_REG(pi->port_id, A_MPS_PORT_STAT_##name##_L))
#define	GET_STAT_COM(name) t4_read_reg64(pi->adapter, \
	    A_MPS_STAT_##name##_L)

	bgmap = G_NUMPORTS(t4_read_reg(pi->adapter, A_MPS_CMN_CTL));
	if (bgmap == 0)
		bgmap = (pi->port_id == 0) ? 0xf : 0;
	else if (bgmap == 1)
		bgmap = (pi->port_id < 2) ? (3 << (2 * pi->port_id)) : 0;
	else
		bgmap = 1;

	KS_U_SET(rx_ovflow0, (bgmap & 1) ?
	    GET_STAT_COM(RX_BG_0_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_ovflow1, (bgmap & 2) ?
	    GET_STAT_COM(RX_BG_1_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_ovflow2, (bgmap & 4) ?
	    GET_STAT_COM(RX_BG_2_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_ovflow3, (bgmap & 8) ?
	    GET_STAT_COM(RX_BG_3_MAC_DROP_FRAME) : 0);
	KS_U_SET(rx_trunc0,  (bgmap & 1) ?
	    GET_STAT_COM(RX_BG_0_MAC_TRUNC_FRAME) : 0);
	KS_U_SET(rx_trunc1,  (bgmap & 2) ?
	    GET_STAT_COM(RX_BG_1_MAC_TRUNC_FRAME) : 0);
	KS_U_SET(rx_trunc2,  (bgmap & 4) ?
	    GET_STAT_COM(RX_BG_2_MAC_TRUNC_FRAME) : 0);
	KS_U_SET(rx_trunc3,  (bgmap & 8) ?
	    GET_STAT_COM(RX_BG_3_MAC_TRUNC_FRAME) : 0);

	KS_U_SET(tx_pause, GET_STAT(TX_PORT_PAUSE));
	KS_U_SET(rx_pause, GET_STAT(RX_PORT_PAUSE));

	return (0);

}

/*
 * cxgbe:X:rxqY
 */
struct rxq_kstats {
	kstat_named_t rxcsum;
	kstat_named_t rxpkts;
	kstat_named_t rxbytes;
	kstat_named_t nomem;
};

static kstat_t *
setup_rxq_kstats(struct port_info *pi, struct sge_rxq *rxq, int idx)
{
	struct kstat *ksp;
	struct rxq_kstats *kstatp;
	int ndata;
	char str[16];

	ndata = sizeof (struct rxq_kstats) / sizeof (kstat_named_t);
	(void) snprintf(str, sizeof (str), "rxq%u", idx);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), str, "rxq",
	    KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN,
		    "%s: failed to initialize rxq kstats for queue %d.",
		    __func__, idx);
		return (NULL);
	}

	kstatp = (struct rxq_kstats *)ksp->ks_data;

	KS_UINIT(rxcsum);
	KS_UINIT(rxpkts);
	KS_UINIT(rxbytes);
	KS_UINIT(nomem);

	ksp->ks_update = update_rxq_kstats;
	ksp->ks_private = (void *)rxq;
	kstat_install(ksp);

	return (ksp);
}

static int
update_rxq_kstats(kstat_t *ksp, int rw)
{
	struct rxq_kstats *kstatp = (struct rxq_kstats *)ksp->ks_data;
	struct sge_rxq *rxq = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (0);

	KS_U_FROM(rxcsum, rxq);
	KS_U_FROM(rxpkts, rxq);
	KS_U_FROM(rxbytes, rxq);
	KS_U_FROM(nomem, rxq);

	return (0);
}

/*
 * cxgbe:X:txqY
 */
struct txq_kstats {
	kstat_named_t txcsum;
	kstat_named_t tso_wrs;
	kstat_named_t imm_wrs;
	kstat_named_t sgl_wrs;
	kstat_named_t txpkt_wrs;
	kstat_named_t txpkts_wrs;
	kstat_named_t txpkts_pkts;
	kstat_named_t txb_used;
	kstat_named_t hdl_used;
	kstat_named_t txb_full;
	kstat_named_t dma_hdl_failed;
	kstat_named_t dma_map_failed;
	kstat_named_t qfull;
	kstat_named_t qflush;
	kstat_named_t pullup_early;
	kstat_named_t pullup_late;
	kstat_named_t pullup_failed;
};

static kstat_t *
setup_txq_kstats(struct port_info *pi, struct sge_txq *txq, int idx)
{
	struct kstat *ksp;
	struct txq_kstats *kstatp;
	int ndata;
	char str[16];

	ndata = sizeof (struct txq_kstats) / sizeof (kstat_named_t);
	(void) snprintf(str, sizeof (str), "txq%u", idx);

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), str, "txq",
	    KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN,
		    "%s: failed to initialize txq kstats for queue %d.",
		    __func__, idx);
		return (NULL);
	}

	kstatp = (struct txq_kstats *)ksp->ks_data;

	KS_UINIT(txcsum);
	KS_UINIT(tso_wrs);
	KS_UINIT(imm_wrs);
	KS_UINIT(sgl_wrs);
	KS_UINIT(txpkt_wrs);
	KS_UINIT(txpkts_wrs);
	KS_UINIT(txpkts_pkts);
	KS_UINIT(txb_used);
	KS_UINIT(hdl_used);
	KS_UINIT(txb_full);
	KS_UINIT(dma_hdl_failed);
	KS_UINIT(dma_map_failed);
	KS_UINIT(qfull);
	KS_UINIT(qflush);
	KS_UINIT(pullup_early);
	KS_UINIT(pullup_late);
	KS_UINIT(pullup_failed);

	ksp->ks_update = update_txq_kstats;
	ksp->ks_private = (void *)txq;
	kstat_install(ksp);

	return (ksp);
}

static int
update_txq_kstats(kstat_t *ksp, int rw)
{
	struct txq_kstats *kstatp = (struct txq_kstats *)ksp->ks_data;
	struct sge_txq *txq = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (0);

	KS_U_FROM(txcsum, txq);
	KS_U_FROM(tso_wrs, txq);
	KS_U_FROM(imm_wrs, txq);
	KS_U_FROM(sgl_wrs, txq);
	KS_U_FROM(txpkt_wrs, txq);
	KS_U_FROM(txpkts_wrs, txq);
	KS_U_FROM(txpkts_pkts, txq);
	KS_U_FROM(txb_used, txq);
	KS_U_FROM(hdl_used, txq);
	KS_U_FROM(txb_full, txq);
	KS_U_FROM(dma_hdl_failed, txq);
	KS_U_FROM(dma_map_failed, txq);
	KS_U_FROM(qfull, txq);
	KS_U_FROM(qflush, txq);
	KS_U_FROM(pullup_early, txq);
	KS_U_FROM(pullup_late, txq);
	KS_U_FROM(pullup_failed, txq);

	return (0);
}
