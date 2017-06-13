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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <netinet/udp.h>
#include <sys/gld.h>
#include "ostypes.h"
#include "common.h"
#ifdef CONFIG_CHELSIO_T1_1G
#include "fpga_defs.h"
#endif
#include "regs.h"
#include "suni1x10gexp_regs.h"
#include "sge.h"
#include "espi.h"

#include "ch.h"

extern uint32_t buffers_in_use[];

uint32_t sge_cmdq0_cnt = SGE_CMDQ0_E_N;
uint32_t sge_cmdq1_cnt = SGE_CMDQ1_E_N;
uint32_t sge_flq0_cnt = SGE_FREELQ0_E_N;
uint32_t sge_flq1_cnt = SGE_FREELQ1_E_N;
uint32_t sge_respq_cnt = SGE_RESPQ_E_N;

uint32_t sge_cmdq0_cnt_orig = SGE_CMDQ0_E_N;
uint32_t sge_cmdq1_cnt_orig = SGE_CMDQ1_E_N;
uint32_t sge_flq0_cnt_orig = SGE_FREELQ0_E_N;
uint32_t sge_flq1_cnt_orig = SGE_FREELQ1_E_N;
uint32_t sge_respq_cnt_orig = SGE_RESPQ_E_N;

#ifdef HOST_PAUSE
uint32_t do_host_pause = 1;
uint32_t flq_pause_window = 64;
#endif

static uint64_t os_freelist_buffer_alloc(ch_t *sa, int sz, mblk_t **mb,
    ulong_t *dh);
void pe_os_free_contig(ch_t *, size_t, void *, uint64_t, ulong_t, ulong_t);

static inline uint32_t t1_sge_rx(pesge *sge, freelQ_t *Q,
    unsigned int len, unsigned int offload);
#ifdef HOST_PAUSE
static void t1_sge_check_pause(pesge *sge, struct freelQ *Q);
#endif
static void alloc_freelQ_buffers(pesge *sge, struct freelQ *Q);
static void freelQs_empty(pesge *sge);
static void free_cmdQ_buffers(pesge *sge, cmdQ_t *Q, uint32_t credits_pend);
static int alloc_rx_resources(pesge *sge, struct sge_params *p);
static int alloc_tx_resources(pesge *sge, struct sge_params *p);
static inline void setup_ring_params(ch_t *adapter, u64 addr, u32 size,
    int base_reg_lo, int base_reg_hi, int size_reg);
static void configure_sge(pesge *sge, struct sge_params *p);
static void free_freelQ_buffers(pesge *sge, struct freelQ *Q);
static void free_rx_resources(pesge *sge);
static void free_tx_resources(pesge *sge);
static inline unsigned int jumbo_payload_capacity(pesge *sge);
#ifdef SUN_KSTATS
static int sge_kstat_setup(pesge *);
static void sge_kstat_remove(pesge *);
static int sge_kstat_update(p_kstat_t, int);
#endif
static uint16_t calc_ocsum(mblk_t *, int);

/*
 * Local routines.
 */
static inline void sge_ring_doorbell(pesge *sge, u32 control_reg);

static inline void
sge_ring_doorbell(pesge *sge, u32 control_reg)
{
	membar_producer();
	t1_write_reg_4(sge->obj, A_SG_DOORBELL, control_reg);
}

/*
 * DESC:
 *
 * NOTES:   Must have at least 1 command queue and 1 freelist queue.
 *
 */
pesge *
t1_sge_create(ch_t *sa, struct sge_params *p)
{
	pesge *sge;

	sge = t1_os_malloc_wait_zero(sizeof (pesge));

	if (sge == NULL)
		goto error_no_mem;

	memset(sge, 0, sizeof (*sge));

	/*
	 * PR2928 & PR3309
	 * set default timeout value - 20 msec
	 * we set the initial value to 2 which gurantees at least one tick.
	 */
	if (is_T2(sa))
		sge->ptimeout = 1;

	sge->obj = sa;
#ifdef SUN_KSTATS
	if (sge_kstat_setup(sge) != 0)
		goto t1_sge_create_fail1;
#endif
	p->cmdQ_size[0] = sge_cmdq0_cnt;
	p->cmdQ_size[1] = sge_cmdq1_cnt;

	/* note that jumbo frame index is inverted for T2 */
	if (is_T2(sa)) {
		p->freelQ_size[1] = sge_flq0_cnt;
		p->freelQ_size[0] = sge_flq1_cnt;
	} else {
		p->freelQ_size[0] = sge_flq0_cnt;
		p->freelQ_size[1] = sge_flq1_cnt;
	}

#if CH_DEBUG
	/* DEBUG only */
	cmn_err(CE_NOTE, "sge: %p\n", sge);
	cmn_err(CE_NOTE, "&sge->cmdQ[0]: %p\n", &sge->cmdQ[0]);
	cmn_err(CE_NOTE, "&sge->freelQ[0]: %p\n", &sge->freelQ[0]);
	cmn_err(CE_NOTE, "&sge->freelQ[1]: %p\n", &sge->freelQ[1]);
	cmn_err(CE_NOTE, "&sge->respQ: %p\n", &sge->respQ);
	cmn_err(CE_NOTE, "&sge->intr_cnt: %p\n", &sge->intr_cnt);
#endif
#ifdef SUN_KSTATS
	goto error_no_mem;

t1_sge_create_fail1:
	t1_os_free(sge, sizeof (pesge));
	sge = NULL;
#endif
error_no_mem:
	return (sge);
}

int
t1_sge_destroy(pesge* sge)
{
	if (sge != NULL) {
		free_tx_resources(sge);
		free_rx_resources(sge);

		/* PR2928 & PR3309 */
		if ((is_T2(sge->obj)) && (sge->pskb))
			pe_free_fake_arp(sge->pskb);
#ifdef SUN_KSTATS
		sge_kstat_remove(sge);
#endif
		t1_os_free(sge, sizeof (pesge));
	}
	return (0);
}

/*
 * PR2928 & PR3309
 * call out event from timeout
 *
 * there is a potential race between the timeout and the close.
 * unless we protect the timeout, the close could occur at the
 * same time. Then if the timeout service routine was slow or
 * interrupted, the sge_stop() could complete with a timeoutID
 * that has expired, thus letting another timeout occur. If the
 * service routine was delayed still further, a detach could occur.
 * the second time could then end up accessing memory that has been
 * released back to the system. Bad things could then occur. We
 * set a flag in sge_stop() to tell the service routine not to
 * issue further timeouts. sge_stop() will block until a timeout
 * has occured. If the command Q is full then we shouldn't put out
 * an arp.
 */

void
t1_espi_workaround(ch_t *adapter)
{
	pesge *sge = adapter->sge;
	ch_t *chp = (ch_t *)sge->obj;
	int rv = 1;

	if ((chp->ch_state == PERUNNING) &&
	    atomic_read(&sge->cmdQ[0].cq_asleep)) {
		u32 seop;
		seop = t1_espi_get_mon(adapter, 0x930, 0);
		if ((seop & 0xfff0fff) == 0xfff) {
			/* after first arp */
			if (sge->pskb) {
				rv = pe_start(adapter, (mblk_t *)sge->pskb,
				    CH_ARP);
				if (!rv)
					sge->intr_cnt.arp_sent++;
			}
		}
	}
#ifdef HOST_PAUSE
	/*
	 * If we are already in sge_data_in, then we can skip calling
	 * t1_sge_check_pause() this clock cycle. lockstat showed that
	 * we were blocking on the mutex ~ 2% of the time.
	 */
	if (mutex_tryenter(&adapter->ch_intr)) {
		t1_sge_check_pause(sge, &sge->freelQ[0]);
		t1_sge_check_pause(sge, &sge->freelQ[1]);
		mutex_exit(&adapter->ch_intr);
	}
#endif
}

int
sge_start(pesge *sge)
{
	t1_write_reg_4(sge->obj, A_SG_CONTROL, sge->sge_control);
	/* PR2928 & PR3309, also need to avoid Pause deadlock */
	ch_init_cyclic(sge->obj, &sge->espi_wa_cyclic,
	    (void (*)(void *))t1_espi_workaround, sge->obj);
	ch_start_cyclic(&sge->espi_wa_cyclic, sge->ptimeout);
	return (0);
}

/*
 * Disables SGE queues.
 */
int
sge_stop(pesge *sge)
{
	uint32_t status;
	int loops;

	DBGASSERT(sge);

	/* PR2928 & PR3309, also need to avoid Pause deadlock */
	t1_write_reg_4(sge->obj, A_SG_CONTROL, 0x0);

	/* wait until there's no more outstanding interrupts pending */
	loops = 0;
	do {
		status = t1_read_reg_4(sge->obj, A_SG_INT_CAUSE);
		t1_write_reg_4(sge->obj, A_SG_INT_CAUSE, status);
		drv_usecwait(125);
		loops++;
	} while (status && (loops < 1000));

	ch_stop_cyclic(&sge->espi_wa_cyclic);

	return (0);
}

uint32_t sge_cmdq_send_fail;

int
sge_data_out(pesge* sge, int qid, mblk_t *m0,
    cmdQ_ce_t *cmp, int count, uint32_t flg)
{
	struct cmdQ *Q = &sge->cmdQ[qid];
	ddi_dma_handle_t dh = (ddi_dma_handle_t)sge->cmdQ[qid].cq_dh;
	spinlock_t *qlock = &Q->cq_qlock;
	cmdQ_e *e;
	cmdQ_e *q = Q->cq_entries;
	uint32_t credits;
	uint32_t pidx;
	uint32_t genbit;
	uint32_t entries_n = Q->cq_entries_n;
	cmdQ_ce_t *ce;
	cmdQ_ce_t *cq = Q->cq_centries;
	dma_addr_t mapping;
	uint32_t j = 0;
	uint32_t offset;
#if defined(TX_CKSUM_FIX)
	uint16_t csum;
	uint16_t *csum_loc;
#endif
#ifdef TX_THREAD_RECLAIM
	uint32_t reclaim_cnt;
#endif

	/*
	 * We must exit if we don't have enough free command queue entries
	 * available.
	 */

	spin_lock(qlock);

#if defined(TX_CKSUM_FIX)
	/*
	 * This checksum fix will address a fragmented datagram
	 * checksum error. Which will lead to the next packet after
	 * the last packet with the More fragment bit set having its
	 * checksum corrupted. When the packet reaches this point
	 * the 'flg' variable indicates whether a checksum is needed
	 * or not. The algorithm is as follows, if the current packet
	 * is a More fragment set the count of packets to be checksummed
	 * after it to 3. If it't not and the count of is more than 0
	 * then calculate the checksum in software, if a hardware checksum
	 * was requested. Then decrment the count. Same algorithm applies
	 * to TCP.
	 */
	if (flg & CH_UDP_MF) {
		sge->do_udp_csum = 3;
	} else if ((flg & CH_UDP) && (sge->do_udp_csum != 0)) {
		if ((flg & CH_NO_HWCKSUM) == 0) {
			/*
			 *  Calc Checksum here.
			 */
			csum = calc_ocsum(m0,
			    sizeof (struct ether_header) + CPL_FORMAT_0_SIZE);
			csum_loc = (uint16_t *)(m0->b_rptr +
			    sizeof (struct ether_header) + CPL_FORMAT_0_SIZE);
			csum_loc += (((*(char *)csum_loc) & 0x0f) << 1);

			sge->intr_cnt.tx_soft_cksums++;
			((struct udphdr *)(csum_loc))->uh_sum = csum;
			((struct cpl_tx_pkt *)m0->b_rptr)->l4_csum_dis = 1;
		}
		sge->do_udp_csum--;
	} else if (flg & CH_TCP_MF) {
		sge->do_tcp_csum = 3;
	} else if (sge->do_tcp_csum != 0) {
		if ((flg & CH_NO_HWCKSUM) == 0) {
			sge->intr_cnt.tx_soft_cksums++;
			/*
			 *  Calc Checksum here.
			 */
		}
		sge->do_tcp_csum--;
	}
#endif	/* TX_CKSUM_FIX */
#ifdef TX_THREAD_RECLAIM
	reclaim_cnt = Q->cq_complete;
	if (reclaim_cnt > SGE_BATCH_THRESH) {
		sge->intr_cnt.tx_reclaims[qid]++;
		free_cmdQ_buffers(sge, Q, reclaim_cnt);
		Q->cq_complete = 0;
	}
#endif
	genbit = Q->cq_genbit;
	pidx = Q->cq_pidx;
	credits = Q->cq_credits;

	if ((credits - 1) < count) {
		spin_unlock(qlock);
		sge->intr_cnt.cmdQ_full[qid]++;
		return (1);
	}

	atomic_sub(count, &Q->cq_credits);
	Q->cq_pidx += count;
	if (Q->cq_pidx >= entries_n) {
		Q->cq_pidx -= entries_n;
		Q->cq_genbit ^= 1;
	}

	spin_unlock(qlock);

#ifdef SUN_KSTATS
	if (count > MBLK_MAX)
		sge->intr_cnt.tx_descs[MBLK_MAX - 1]++;
	else
		sge->intr_cnt.tx_descs[count]++;
#endif

	ce = &cq[pidx];
	*ce = *cmp;
	mapping = cmp->ce_pa;
	j++;

	e = &q[pidx];

	offset = (caddr_t)e - (caddr_t)q;

	e->Sop =  1;
	e->DataValid = 1;
	e->BufferLength = cmp->ce_len;
	e->AddrHigh = ((u64)mapping >> 32);
	e->AddrLow = ((u64)mapping & 0xffffffff);

	--count;
	if (count > 0) {
		unsigned int i;

		e->Eop = 0;
		wmb();
		e->GenerationBit = e->GenerationBit2 = genbit;

		for (i = 0; i < count; i++) {

			ce++;
			e++;
			cmp++;
			if (++pidx == entries_n) {
				pidx = 0;
				genbit ^= 1;
				/* sync from offset to end of cmdQ */
				(void) ddi_dma_sync(dh, (off_t)(offset),
				    j*sizeof (*e), DDI_DMA_SYNC_FORDEV);
				offset = j = 0;
				ce = cq;
				e = q;
			}

			*ce = *cmp;
			mapping = cmp->ce_pa;
			j++;
			e->Sop = 0;
			e->DataValid = 1;
			e->BufferLength = cmp->ce_len;
			e->AddrHigh = ((u64)mapping >> 32);
			e->AddrLow = ((u64)mapping & 0xffffffff);

			if (i < (count - 1)) {
				e->Eop = 0;
				wmb();
				e->GenerationBit = e->GenerationBit2 = genbit;
			}
		}
	}

	ce->ce_mp = m0;

	e->Eop = 1;
	wmb();
	e->GenerationBit = e->GenerationBit2 = genbit;

	(void) ddi_dma_sync(dh, (off_t)(offset), j*sizeof (*e),
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * We always ring the doorbell for cmdQ1.  For cmdQ0, we only ring
	 * the doorbell if the Q is asleep. There is a natural race, where
	 * the hardware is going to sleep just after we checked, however,
	 * then the interrupt handler will detect the outstanding TX packet
	 * and ring the doorbell for us.
	 */
	if (qid) {
		doorbell_pio(sge, F_CMDQ1_ENABLE);
	} else {
		if (atomic_read(Q->cq_asleep)) {
			atomic_set(&Q->cq_asleep, 0);
/* NOT YET		doorbell_pio(sge, F_CMDQ0_ENABLE); */
			atomic_set(&Q->cq_pio_pidx, Q->cq_pidx);
		}
	}
	doorbell_pio(sge, F_CMDQ0_ENABLE);

	return (0);
}

#define	SGE_PL_INTR_MASK (F_PL_INTR_SGE_ERR | F_PL_INTR_SGE_DATA)

/*
 * Disable SGE error interrupts.
 */
int
t1_sge_intr_disable(pesge* sge)
{
	u32 val = t1_read_reg_4(sge->obj, A_PL_ENABLE);

	t1_write_reg_4(sge->obj, A_PL_ENABLE, val & ~SGE_PL_INTR_MASK);
	t1_write_reg_4(sge->obj, A_SG_INT_ENABLE, 0);
	return (0);
}

#define	SGE_INT_ENABLE (F_RESPQ_EXHAUSTED | F_RESPQ_OVERFLOW | \
	F_FL_EXHAUSTED | F_PACKET_TOO_BIG | F_PACKET_MISMATCH)

/*
 * Enable SGE error interrupts.
 */
int
t1_sge_intr_enable(pesge* sge)
{
	u32 en = SGE_INT_ENABLE;
	u32 val = t1_read_reg_4(sge->obj, A_PL_ENABLE);

	t1_write_reg_4(sge->obj, A_PL_ENABLE, val | SGE_PL_INTR_MASK);

	if (sge->obj->ch_flags & TSO_CAPABLE)
		en &= ~F_PACKET_TOO_BIG;
	t1_write_reg_4(sge->obj, A_SG_INT_ENABLE, en);
	return (0);
}

/*
 * Clear SGE error interrupts.
 */
int
t1_sge_intr_clear(pesge* sge)
{
	t1_write_reg_4(sge->obj, A_PL_CAUSE, SGE_PL_INTR_MASK);
	t1_write_reg_4(sge->obj, A_SG_INT_CAUSE, 0xffffffff);
	return (0);
}

#define	SGE_INT_FATAL (F_RESPQ_OVERFLOW | F_PACKET_TOO_BIG | F_PACKET_MISMATCH)

int
t1_sge_intr_error_handler(pesge *sge)
{
	peobj *obj = sge->obj;
	u32 cause = t1_read_reg_4(obj, A_SG_INT_CAUSE);

	if (cause & F_RESPQ_EXHAUSTED)
		sge->intr_cnt.respQ_empty++;
	if (cause & F_RESPQ_OVERFLOW) {
		sge->intr_cnt.respQ_overflow++;
		cmn_err(CE_WARN, "%s: SGE response queue overflow\n",
		    obj->ch_name);
	}
	if (cause & F_FL_EXHAUSTED) {
		sge->intr_cnt.freelistQ_empty++;
		freelQs_empty(sge);
	}
	if (cause & F_PACKET_TOO_BIG) {
		sge->intr_cnt.pkt_too_big++;
		cmn_err(CE_WARN, "%s: SGE max packet size exceeded\n",
		    obj->ch_name);
	}
	if (cause & F_PACKET_MISMATCH) {
		sge->intr_cnt.pkt_mismatch++;
		cmn_err(CE_WARN, "%s: SGE packet mismatch\n",
		    obj->ch_name);
	}
	if (cause & SGE_INT_FATAL)
		t1_fatal_err(obj);

	t1_write_reg_4(obj, A_SG_INT_CAUSE, cause);
	return (0);
}

/*
 *
 * PARAM:   sge     - SGE instance pointer.
 */
int
sge_data_in(pesge *sge)
{
	peobj *adapter = sge->obj;
	struct respQ *Q = &sge->respQ;
	respQ_e *e;				/* response queue entry */
	respQ_e *q = Q->rq_entries;		/* base response queue */
	uint32_t cidx = Q->rq_cidx;
	uint32_t genbit = Q->rq_genbit;
	uint32_t entries_n = Q->rq_entries_n;
	uint32_t credits = Q->rq_credits;
	uint32_t credits_thresh = Q->rq_credits_thresh;
	uint32_t ret = 0;
#ifndef TX_THREAD_RECLAIM
	uint32_t credits_pend[2] = {0, 0};
#endif
	uint32_t flags = 0;
	uint32_t flagt;
	ddi_dma_handle_t dh = (ddi_dma_handle_t)Q->rq_dh;

	t1_write_reg_4(adapter, A_PL_CAUSE, F_PL_INTR_SGE_DATA);

	/*
	 * Catch the case where an interrupt arrives
	 * early.
	 */
	if ((q == NULL) || (dh == NULL)) {
		goto check_slow_ints;
	}

	/* initial response queue entry */
	e = &q[cidx];

	/* pull physical memory of response queue entry into cache */
	(void) ddi_dma_sync(dh, (off_t)((caddr_t)e - (caddr_t)q),
	    sizeof (*e), DDI_DMA_SYNC_FORKERNEL);

	while (e->GenerationBit == genbit) {
		if (--credits < credits_thresh) {
			uint32_t n = entries_n - credits - 1;
			t1_write_reg_4(adapter, A_SG_RSPQUEUECREDIT, n);
			credits += n;
		}
		if (likely(e->DataValid)) {
			(void) t1_sge_rx(sge, &sge->freelQ[e->FreelistQid],
			    e->BufferLength, e->Offload);
			if ((e->Sop != 1) || (e->Eop != 1)) {
				sge->intr_cnt.rx_badEopSop++;
				cmn_err(CE_WARN, "bad Sop %d or Eop %d: %d",
				    e->Sop, e->Eop, e->BufferLength);
			}
		}
		flagt = e->Qsleeping;
		flags |= flagt;
		if (flagt & F_CMDQ0_ENABLE)
			sge->intr_cnt.rx_cmdq0++;
		if (flagt & F_CMDQ1_ENABLE)
			sge->intr_cnt.rx_cmdq1++;
		if (flagt & F_FL0_ENABLE)
			sge->intr_cnt.rx_flq0++;
		if (flagt & F_FL1_ENABLE)
			sge->intr_cnt.rx_flq1++;
#ifdef TX_THREAD_RECLAIM
		spin_lock(&sge->cmdQ[0].cq_qlock);
		sge->cmdQ[0].cq_complete += e->Cmdq0CreditReturn;
		spin_unlock(&sge->cmdQ[0].cq_qlock);
		spin_lock(&sge->cmdQ[1].cq_qlock);
		sge->cmdQ[1].cq_complete += e->Cmdq1CreditReturn;
		if ((adapter->ch_blked) &&
		    (sge->cmdQ[0].cq_complete +
		    sge->cmdQ[1].cq_complete) > 16) {
			adapter->ch_blked = 0;
			ch_gld_ok(adapter);
		}
		spin_unlock(&sge->cmdQ[1].cq_qlock);
#else
		credits_pend[0] += e->Cmdq0CreditReturn;
		credits_pend[1] += e->Cmdq1CreditReturn;
#ifdef CONFIG_SMP
		if (unlikely(credits_pend[0] > SGE_BATCH_THRESH)) {
			free_cmdQ_buffers(sge, &sge->cmdQ[0], credits_pend[0]);
			credits_pend[0] = 0;
		}
		if (unlikely(credits_pend[1] > SGE_BATCH_THRESH)) {
			free_cmdQ_buffers(sge, &sge->cmdQ[1], credits_pend[1]);
			credits_pend[1] = 0;
		}
#endif
#endif
#ifdef HOST_PAUSE
		t1_sge_check_pause(sge, &sge->freelQ[e->FreelistQid]);
#endif
		e++;
		if (unlikely(++cidx == entries_n)) {
			cidx = 0;
			genbit ^= 1;
			e = q;
		}

		/* pull physical memory of response queue entry into cache */
		(void) ddi_dma_sync(dh, (off_t)((caddr_t)e - (caddr_t)q),
		    sizeof (*e), DDI_DMA_SYNC_FORKERNEL);

		ret = 1;
	}

#ifndef TX_THREAD_RECLAIM
	if (credits_pend[0])
		free_cmdQ_buffers(sge, &sge->cmdQ[0], credits_pend[0]);
	if (credits_pend[1])
		free_cmdQ_buffers(sge, &sge->cmdQ[1], credits_pend[1]);
#endif
	if (flags & F_CMDQ0_ENABLE) {
		struct cmdQ *cmdQ = &sge->cmdQ[0];
		atomic_set(&cmdQ->cq_asleep, 1);
		if (atomic_read(cmdQ->cq_pio_pidx) != cmdQ->cq_pidx) {
			doorbell_pio(sge, F_CMDQ0_ENABLE);
			atomic_set(&cmdQ->cq_pio_pidx, cmdQ->cq_pidx);
		}
	}

	/* the SGE told us one of the free lists is empty */
	if (unlikely(flags & (F_FL0_ENABLE | F_FL1_ENABLE)))
		freelQs_empty(sge);

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (adapter->ch_tx_overflow_mutex)
		mutex_enter(adapter->ch_tx_overflow_mutex);
	if (adapter->ch_blked &&
	    (sge->cmdQ[0].cq_credits > (sge->cmdQ[0].cq_entries_n>>2)) &&
	    (sge->cmdQ[1].cq_credits > (sge->cmdQ[1].cq_entries_n>>2))) {
		adapter->ch_blked = 0;
		if (adapter->ch_tx_overflow_cv)
			cv_broadcast(adapter->ch_tx_overflow_cv);
		ch_gld_ok(adapter);
	}
	if (adapter->ch_tx_overflow_mutex)
		mutex_exit(adapter->ch_tx_overflow_mutex);
#else
#ifndef TX_THREAD_RECLAIM
	if (adapter->ch_blked &&
	    (sge->cmdQ[0].cq_credits > (sge->cmdQ[0].cq_entries_n>>1)) &&
	    (sge->cmdQ[1].cq_credits > (sge->cmdQ[1].cq_entries_n>>1))) {
		adapter->ch_blked = 0;
		ch_gld_ok(adapter);
	}
#endif
#endif	/* CONFIG_CHELSIO_T1_OFFLOAD */

	Q->rq_genbit = genbit;
	Q->rq_cidx = cidx;
	Q->rq_credits = credits;

	t1_write_reg_4(adapter, A_SG_SLEEPING, cidx);

check_slow_ints:
	/* handle non-data interrupts */
	if (unlikely(!ret))
		ret = t1_slow_intr_handler(adapter);

	return (ret);
}

/*
 * allocate a mblk with DMA mapped mblk.
 * When checksum offload is enabled, we start the DMA at a 2 byte offset so
 * the IP header will be aligned. We do this for sparc only.
 */
static uint64_t
os_freelist_buffer_alloc(ch_t *sa, int sz, mblk_t **mb, ulong_t *dh)
{
	ch_esb_t *ch_get_small_rbuf(ch_t *sa);
	ch_esb_t *ch_get_big_rbuf(ch_t *sa);
	ch_esb_t *rbp;
	uint32_t rxoff = sa->sge->rx_offset;

	if (sz == SGE_SM_BUF_SZ(sa)) {
		/* get pre-mapped buffer */
		if ((rbp = ch_get_small_rbuf(sa)) == NULL) {
			sa->norcvbuf++;
			return ((uint64_t)0);
		}

		*mb = desballoc((unsigned char *)rbp->cs_buf + rxoff,
		    SGE_SM_BUF_SZ(sa)-rxoff, BPRI_MED, &rbp->cs_frtn);
		if (*mb == NULL) {
			mutex_enter(&sa->ch_small_esbl);
			rbp->cs_next = sa->ch_small_esb_free;
			sa->ch_small_esb_free = rbp;
			mutex_exit(&sa->ch_small_esbl);
			return ((uint64_t)0);
		}
		*dh = rbp->cs_dh;

		return (rbp->cs_pa + rxoff);
	} else {
		/* get pre-mapped buffer */
		if ((rbp = ch_get_big_rbuf(sa)) == NULL) {
			sa->norcvbuf++;
			return ((uint64_t)0);
		}

		*mb = desballoc((unsigned char *)rbp->cs_buf + rxoff,
		    SGE_BG_BUF_SZ(sa)-rxoff, BPRI_MED, &rbp->cs_frtn);
		if (*mb == NULL) {
			mutex_enter(&sa->ch_big_esbl);
			rbp->cs_next = sa->ch_big_esb_free;
			sa->ch_big_esb_free = rbp;
			mutex_exit(&sa->ch_big_esbl);
			return ((uint64_t)0);
		}
		*dh = rbp->cs_dh;

		return (rbp->cs_pa + rxoff);
	}
}

static inline unsigned int
t1_sge_rx(pesge *sge, struct freelQ *Q, unsigned int len, unsigned int offload)
{
	mblk_t *skb;
	peobj *adapter = sge->obj;
	struct freelQ_ce *cq = Q->fq_centries;
	struct freelQ_ce *ce = &cq[Q->fq_cidx];
	ddi_dma_handle_t dh = (ddi_dma_handle_t)ce->fe_dh;
	uint32_t cidx = Q->fq_cidx;
	uint32_t entries_n = Q->fq_entries_n;
	uint32_t sz = Q->fq_rx_buffer_size;
	uint32_t useit = 1;
	uint32_t rxoff = sge->rx_offset;
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	uint32_t rv;
#endif

	if (Q->fq_id)
		sge->intr_cnt.rx_flq1_cnt++;
	else
		sge->intr_cnt.rx_flq0_cnt++;
	/*
	 * If pkt size falls below threshold, then we'll copy data to
	 * an blk and reuse mblk.
	 *
	 * NOTE that rxoff is 2 for T1 adapters. We align the the start
	 * of the DMA buffer begin at rxoff offset for T1 cards instead of
	 * at the beginning of the buffer, thus the length of the received
	 * data does not include this offset. We therefore always add
	 * SGE_RX_OFFSET to the allocb size so we have space to provide the
	 * offset for the copied data.
	 */
#ifdef HOST_PAUSE
	/*
	 * If we have Host pause compiled in, then we look at the
	 * free list, if the pause is on and we're not in offload
	 * mode then we drop packets, this is designed to avoid
	 * overwhelming the machine. If the machine is powerfull enough
	 * this will not happen. The 'rx_pkt_drops' will show when
	 * packets are being dropped and how much.
	 */
	if ((offload == 0) && adapter->pause_on) {
		freelQ_e *e;
		/* Ditch the packet and reuse original buffer */
		e = &Q->fq_entries[cidx];
		e->GenerationBit  ^= 1;
		e->GenerationBit2 ^= 1;
		sge->intr_cnt.rx_pkt_drops++;
		goto rx_entry_consumed;
	} else if (((adapter->pause_on ||
	    (len <= SGE_RX_COPY_THRESHOLD)) &&
	    (skb = allocb(len + SGE_RX_OFFSET, BPRI_HI))))
#else
	if ((len <= SGE_RX_COPY_THRESHOLD) &&
	    (skb = allocb(len + SGE_RX_OFFSET, BPRI_HI)))
#endif
	{
		freelQ_e *e;
		char *src = (char *)((mblk_t *)ce->fe_mp)->b_rptr;

		/*
		 * pull physical memory of pkt data into cache
		 * Note that len does not include offset for T1.
		 */
		(void) ddi_dma_sync(dh, (off_t)(rxoff), len,
		    DDI_DMA_SYNC_FORKERNEL);

		if (offload == 0) {
			/*
			 * create 2 byte offset so IP header aligned on
			 * 4 byte boundry
			 */
			skb_reserve(skb, SGE_RX_OFFSET);
			/*
			 * if hardware inserted 2 byte offset then need to
			 * start copying with extra offset
			 */
			src += sge->rx_pkt_pad;
		}
		memcpy(skb->b_rptr, src, len);
		useit = 0;	/* mblk copy, don't inc esballoc in use cnt */

		/* so we can reuse original buffer */
		e = &Q->fq_entries[cidx];
		e->GenerationBit  ^= 1;
		e->GenerationBit2 ^= 1;
		sge->intr_cnt.rx_pkt_copied++;
	} else {
		/* consume buffer off the ring */
		skb = ce->fe_mp;
		ce->fe_mp = NULL;

		/*
		 * if not offload (tunneled pkt), & hardward padded, then
		 * adjust start of pkt to point to start of data i.e.
		 * skip pad (2 bytes).
		 */
		if (!offload && sge->rx_pkt_pad)
			__skb_pull(skb, SGE_RX_OFFSET);

		/*
		 * pull physical memory of pkt data into cache
		 * Note that len does not include offset for T1.
		 */
		(void) ddi_dma_sync(dh, (off_t)(rxoff), len,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	/* set length of data in skb */
	skb_put(skb, len);

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (likely(offload)) {
		if (likely(toe_running(adapter))) {
			/* sends pkt upstream to toe layer */
			if (useit) {
				uint_t index;
				if (sz == SGE_SM_BUF_SZ(adapter))
					index = adapter->ch_sm_index;
				else
					index = adapter->ch_big_index;
				atomic_add(1, &buffers_in_use[index]);
			}
			if (adapter->toe_rcv)
				adapter->toe_rcv(adapter->ch_toeinst, skb);
			else
				freemsg(skb);
		} else {
			cmn_err(CE_WARN,
			    "%s: unexpected offloaded packet, cmd %u\n",
			    adapter->ch_name, *skb->b_rptr);

			/* discard packet */
			freemsg(skb);
		}
	}
#else
	if (unlikely(offload)) {
		cmn_err(CE_WARN,
		    "%s: unexpected offloaded packet, cmd %u\n",
		    adapter->ch_name, *skb->b_rptr);

		/* discard paket */
		freemsg(skb);
	}
#endif
	else {
		struct cpl_rx_pkt *p = (struct cpl_rx_pkt *)skb->b_rptr;
		int flg = 0;
		uint32_t cksum;

		/* adjust beginning of data to skip CPL header */
		skb_pull(skb, SZ_CPL_RX_PKT);

		/* extract checksum from CPL header here */

		/*
		 * bump count of mlbks in used by protocol stack(s)
		 */
		if (useit) {
			if (sz == SGE_SM_BUF_SZ(adapter)) {
				atomic_add(1,
				    &buffers_in_use[adapter->ch_sm_index]);
			} else {
				atomic_add(1,
				    &buffers_in_use[adapter->ch_big_index]);
			}
		}

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
		/*
		 * let the TOE layer have a crack at the packet first.
		 */
		if (adapter->toe_tunnel) {
			rv = adapter->toe_tunnel(adapter->ch_toeinst, skb);
			/*
			 * The TOE may have consumed the packet.
			 */
			if (rv)
				goto rx_entry_consumed;
		}
#endif	/* CONFIG_CHELSIO_T1_OFFLOAD */

		cksum = p->csum;

		/*
		 * NOTE: 14+9 = size of MAC + offset to IP protocol field
		 */
		if (adapter->ch_config.cksum_enabled &&
		    (ntohs(((struct ether_header *)skb->b_rptr)->ether_type) ==
		    ETHERTYPE_IP) &&
		    ((skb->b_rptr[14+9] == IPPROTO_TCP) ||
		    (skb->b_rptr[14+9] == IPPROTO_UDP))) {
			flg = 1;
		}

		ch_send_up(adapter, skb, cksum, flg);
	}

rx_entry_consumed:

	if (++cidx == entries_n)
		cidx = 0;

	Q->fq_cidx = cidx;

	if (unlikely(--Q->fq_credits < (entries_n>>2)))
		/* allocate new buffers on the free list */
		alloc_freelQ_buffers(sge, Q);
	return (1);
}

#ifdef HOST_PAUSE
static void
t1_sge_check_pause(pesge *sge, struct freelQ *Q)
{
	peobj *adapter = sge->obj;

	/*
	 * If the number of available credits shrinks below
	 * the Pause on threshold then enable the pause and
	 * try and allocate more buffers.
	 * On the next pass, if there's more credits returned
	 * then check that you've went above the pause
	 * threshold and then disable the pause.
	 */
	if (Q->fq_credits < Q->fq_pause_on_thresh) {
		if (do_host_pause) {
			sge->intr_cnt.rx_pause_on++;
			adapter->txxg_cfg1 |=
			    SUNI1x10GEXP_BITMSK_TXXG_HOSTPAUSE;
			(void) t1_tpi_write(adapter,
			    SUNI1x10GEXP_REG_TXXG_CONFIG_1 << 2,
			    adapter->txxg_cfg1);
			adapter->pause_on = 1;
			adapter->pause_time = gethrtime();
		}
		alloc_freelQ_buffers(sge, Q);
	} else if ((adapter->pause_on) &&
	    (Q->fq_credits > Q->fq_pause_off_thresh)) {
		hrtime_t time;
		sge->intr_cnt.rx_pause_off++;
		adapter->txxg_cfg1 &= ~SUNI1x10GEXP_BITMSK_TXXG_HOSTPAUSE;
		(void) t1_tpi_write(adapter,
		    SUNI1x10GEXP_REG_TXXG_CONFIG_1 << 2,
		    adapter->txxg_cfg1);
		adapter->pause_on = 0;
		time = (gethrtime() - adapter->pause_time)/1000;
		sge->intr_cnt.rx_pause_ms += time;
		if (time > sge->intr_cnt.rx_pause_spike)
			sge->intr_cnt.rx_pause_spike = (uint32_t)time;
	}
	sge->intr_cnt.rx_fl_credits = Q->fq_credits;
}
#endif	/* HOST_PAUSE */

static void
alloc_freelQ_buffers(pesge *sge, struct freelQ *Q)
{
	uint32_t pidx = Q->fq_pidx;
	struct freelQ_ce *ce = &Q->fq_centries[pidx];
	freelQ_e *fq = Q->fq_entries;		/* base of freelist Q */
	freelQ_e *e = &Q->fq_entries[pidx];
	uint32_t sz = Q->fq_rx_buffer_size;
	uint32_t rxoff = sge->rx_offset;
	uint32_t credits = Q->fq_credits;
	uint32_t entries_n = Q->fq_entries_n;
	uint32_t genbit = Q->fq_genbit;
	ddi_dma_handle_t th = (ddi_dma_handle_t)Q->fq_dh;
	ulong_t dh;
	uint64_t mapping;
	off_t offset = (off_t)((caddr_t)e - (caddr_t)fq);
	size_t len = 0;

	while (credits < entries_n) {
		if (e->GenerationBit != genbit) {
			mblk_t *skb;

			mapping = os_freelist_buffer_alloc(sge->obj, sz,
			    &skb, &dh);
			if (mapping == 0) {
				sge->intr_cnt.rx_flbuf_fails++;
				break;
			}
			sge->intr_cnt.rx_flbuf_allocs++;

			ce->fe_mp = skb;
			ce->fe_dh = dh;

			/*
			 * Note that for T1, we've started the beginning of
			 * of the buffer by an offset of 2 bytes. We thus
			 * decrement the length to account for this.
			 */
			e->AddrLow = (u32)mapping;
			e->AddrHigh = (u64)mapping >> 32;
			e->BufferLength = sz - rxoff;
			wmb();
			e->GenerationBit = e->GenerationBit2 = genbit;
		}

		len += sizeof (*e);

		ce++;
		e++;
		credits++;
		if (++pidx == entries_n) {
			/*
			 * sync freelist entries to physical memory up to
			 * end of the table.
			 */
			(void) ddi_dma_sync(th, offset, len,
			    DDI_DMA_SYNC_FORDEV);
			offset = 0;
			len = 0;

			pidx = 0;
			genbit ^= 1;
			ce = Q->fq_centries;
			e = Q->fq_entries;
		}
	}

	/* sync freelist entries that have been modified. */
	if (len)
		(void) ddi_dma_sync(th, offset, len, DDI_DMA_SYNC_FORDEV);

	Q->fq_genbit = genbit;
	Q->fq_pidx = pidx;
	Q->fq_credits = credits;
}

static void
freelQs_empty(pesge *sge)
{
	u32 irq_reg = t1_read_reg_4(sge->obj, A_SG_INT_ENABLE);
	u32 irqholdoff_reg;

	alloc_freelQ_buffers(sge, &sge->freelQ[0]);
	alloc_freelQ_buffers(sge, &sge->freelQ[1]);

	if ((sge->freelQ[0].fq_credits > sge->freelQ[0].fq_entries_n >> 2) &&
	    (sge->freelQ[1].fq_credits > sge->freelQ[1].fq_entries_n >> 2)) {
		irq_reg |= F_FL_EXHAUSTED;
		irqholdoff_reg = sge->intrtimer[sge->currIndex];
	} else {
		/* Clear the F_FL_EXHAUSTED interrupts for now */
		irq_reg &= ~F_FL_EXHAUSTED;
		irqholdoff_reg = sge->intrtimer_nres;
	}
	t1_write_reg_4(sge->obj, A_SG_INTRTIMER, irqholdoff_reg);
	t1_write_reg_4(sge->obj, A_SG_INT_ENABLE, irq_reg);

	/* We reenable the Qs to force an Freelist GTS interrupt later */
	doorbell_pio(sge, F_FL0_ENABLE | F_FL1_ENABLE);
}

/*
 * Frees 'credits_pend' TX buffers and returns the credits to Q->credits.
 * Free xmit buffers
 */
static void
free_cmdQ_buffers(pesge *sge, struct cmdQ *Q, unsigned int credits_pend)
{
	mblk_t *skb;
	struct cmdQ_ce *ce;
	struct cmdQ_ce *cq = Q->cq_centries;
	uint32_t entries_n = Q->cq_entries_n;
	uint32_t cidx = Q->cq_cidx;
	uint32_t i = credits_pend;
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	ch_t *chp = sge->obj;
#endif
	ce = &cq[cidx];

	while (i--) {
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
		/* if flag set, then toe buffer */
		switch (ce->ce_flg & 0x7) {
		case DH_DMA:
			if (ce->ce_dh) {
				ch_unbind_dma_handle(sge->obj, ce->ce_dh);
				ce->ce_dh = NULL;	/* may not be needed */
			}
			skb = ce->ce_mp;
			if (skb && ((ce->ce_flg & CH_ARP) == NULL)) {
				freemsg(skb);
			}
			ce->ce_mp = NULL;
			break;

#if defined(__sparc)
		case DH_DVMA:
			if (ce->ce_dh) {
				ch_unbind_dvma_handle(sge->obj, ce->ce_dh);
				ce->ce_dh = NULL;	/* may not be needed */
			}
			skb = ce->ce_mp;
			if (skb && ((ce->ce_flg & CH_ARP) == NULL)) {
				freemsg(skb);
			}
			ce->ce_mp = NULL;
			break;
#endif	/* __sparc */

		case DH_TOE:
			chp->toe_free(chp->ch_toeinst, (tbuf_t *)(ce->ce_mp));
			ce->ce_mp = NULL;
			break;
		}
#else	/* CONFIG_CHELSIO_T1_OFFLOAD */
		if (ce->ce_dh) {
			if ((ce->ce_flg & 7) == DH_DMA) {
				ch_unbind_dma_handle(sge->obj, ce->ce_dh);
			}
#if defined(__sparc)
			else {
				ch_unbind_dvma_handle(sge->obj, ce->ce_dh);
			}
#endif	/* __sparc */
			ce->ce_dh = NULL; /* may not be needed */
		}

		skb = ce->ce_mp;
		if (skb && ((ce->ce_flg & CH_ARP) == NULL)) {
			freemsg(skb);
		}
		ce->ce_mp = NULL;
#endif	/* !CONFIG_CHELSIO_T1_OFFLOAD */

		ce++;
		if (++cidx == entries_n) {
			cidx = 0;
			ce = cq;
		}
	}

	Q->cq_cidx = cidx;
	atomic_add(credits_pend, &Q->cq_credits);
}

struct sge_intr_counts *
sge_get_stat(pesge *sge)
{
	return (&sge->intr_cnt);
}

/*
 * Allocates both RX and TX resources and configures the SGE. However,
 * the hardware is not enabled yet.
 *
 * rx_pkt_pad is set, if the hardware supports aligning non-offload traffic.
 * jumbo_fl is set to the index of the freelist containing the jumbo buffers.
 */
int
t1_sge_configure(pesge *sge, struct sge_params *p)
{
	sge->rx_pkt_pad = t1_is_T1B(sge->obj) ? 0 : SGE_RX_OFFSET;
	sge->jumbo_fl = t1_is_T1B(sge->obj) ? 1 : 0;
	/* if we're a T2 card, then we have hardware offset support */
	sge->rx_offset = t1_is_T1B(sge->obj) ? SGE_RX_OFFSET: 0;

	if (alloc_rx_resources(sge, p))
		return (-ENOMEM);
	if (alloc_tx_resources(sge, p)) {
		free_rx_resources(sge);
		return (-ENOMEM);
	}
	configure_sge(sge, p);

	/*
	 * Now that we have sized the free lists calculate the payload
	 * capacity of the large buffers.  Other parts of the driver use
	 * this to set the max offload coalescing size so that RX packets
	 * do not overflow our large buffers.
	 */
	p->large_buf_capacity = jumbo_payload_capacity(sge);
	return (0);
}

/*
 * Allocates basic RX resources, consisting of memory mapped freelist Qs and a
 * response Q.
 */
static int
alloc_rx_resources(pesge *sge, struct sge_params *p)
{
	unsigned int size, i;

	for (i = 0; i < SGE_FREELQ_N; i++) {
		struct freelQ *Q = &sge->freelQ[i];

		Q->fq_id = i;
		Q->fq_genbit = 1;
		Q->fq_entries_n = p->freelQ_size[i];
#ifdef HOST_PAUSE
		Q->fq_pause_on_thresh = flq_pause_window;
		Q->fq_pause_off_thresh = Q->fq_entries_n >> 1;
#endif
		size = sizeof (freelQ_e) * Q->fq_entries_n;

		Q->fq_entries = pe_os_malloc_contig_wait_zero(sge->obj,
		    size, &Q->fq_pa, &Q->fq_dh, &Q->fq_ah, DMA_OUT);


		if (!Q->fq_entries)
			goto err_no_mem;
		memset(Q->fq_entries, 0, size);
		size = sizeof (struct freelQ_ce) * Q->fq_entries_n;
		Q->fq_centries = t1_os_malloc_wait_zero(size);
		if (!Q->fq_centries)
			goto err_no_mem;
		memset(Q->fq_centries, 0, size);
	}

	/*
	 * Calculate the buffer sizes for the two free lists.  FL0 accommodates
	 * regular sized Ethernet frames, FL1 is sized not to exceed 16K,
	 * including all the sk_buff overhead.
	 * For T1C FL0 and FL1 are reversed.
	 */
#ifdef NOTYET
	sge->freelQ[1 ^ sge->jumbo_fl].fq_rx_buffer_size = SGE_RX_SM_BUF_SIZE +
	    sizeof (struct cpl_rx_data) +
	    SGE_RX_OFFSET - sge->rx_pkt_pad;
#else
	sge->freelQ[1 ^ sge->jumbo_fl].fq_rx_buffer_size =
	    sge->obj->ch_sm_buf_sz;
	if (is_T2(sge->obj))
		sge->intr_cnt.rx_flq1_sz = sge->obj->ch_sm_buf_sz;
	else
		sge->intr_cnt.rx_flq0_sz = sge->obj->ch_sm_buf_sz;
#endif
#ifdef NOTYET
	sge->freelQ[sge->jumbo_fl].fq_rx_buffer_size = (16 * 1024) -
	    SKB_DATA_ALIGN(sizeof (struct skb_shared_info));
#else
	sge->freelQ[sge->jumbo_fl].fq_rx_buffer_size = sge->obj->ch_bg_buf_sz;
	if (is_T2(sge->obj))
		sge->intr_cnt.rx_flq0_sz = sge->obj->ch_bg_buf_sz;
	else
		sge->intr_cnt.rx_flq1_sz = sge->obj->ch_bg_buf_sz;
#endif

	sge->respQ.rq_genbit = 1;
	sge->respQ.rq_entries_n = sge_respq_cnt;
	sge->respQ.rq_credits = sge_respq_cnt;
	sge->respQ.rq_credits_thresh = sge_respq_cnt - (sge_respq_cnt >> 2);
	size = sizeof (respQ_e) * sge->respQ.rq_entries_n;

	sge->respQ.rq_entries = pe_os_malloc_contig_wait_zero(sge->obj,
	    size, &(sge->respQ.rq_pa), &(sge->respQ.rq_dh),
	    &(sge->respQ.rq_ah), 0);

	if (!sge->respQ.rq_entries)
		goto err_no_mem;
	memset(sge->respQ.rq_entries, 0, size);
	return (0);

err_no_mem:
	free_rx_resources(sge);
	return (1);
}

/*
 * Allocates basic TX resources, consisting of memory mapped command Qs.
 */
static int
alloc_tx_resources(pesge *sge, struct sge_params *p)
{
	unsigned int size, i;

	for (i = 0; i < SGE_CMDQ_N; i++) {
		struct cmdQ *Q = &sge->cmdQ[i];

		Q->cq_genbit = 1;
		Q->cq_entries_n = p->cmdQ_size[i];
		atomic_set(&Q->cq_credits, Q->cq_entries_n);
		atomic_set(&Q->cq_asleep, 1);

		mutex_init(&Q->cq_qlock, NULL, MUTEX_DRIVER,
		    sge->obj->ch_icookp);

		size = sizeof (cmdQ_e) * Q->cq_entries_n;
		Q->cq_entries = pe_os_malloc_contig_wait_zero(sge->obj,
		    size, &Q->cq_pa, &Q->cq_dh, &Q->cq_ah, DMA_OUT);

		if (!Q->cq_entries)
			goto err_no_mem;
		memset(Q->cq_entries, 0, size);
		size = sizeof (struct cmdQ_ce) * Q->cq_entries_n;
		Q->cq_centries = t1_os_malloc_wait_zero(size);
		if (!Q->cq_centries)
			goto err_no_mem;
		memset(Q->cq_centries, 0, size);

		/* allocate pre-mapped dma headers */
		pe_dma_handle_init(sge->obj, Q->cq_entries_n);
	}

	return (0);

err_no_mem:
	free_tx_resources(sge);
	return (1);
}

/*
 * Sets the interrupt latency timer when the adaptive Rx coalescing
 * is turned off. Do nothing when it is turned on again.
 *
 * This routine relies on the fact that the caller has already set
 * the adaptive policy in adapter->sge_params before calling it.
 */
int
t1_sge_set_coalesce_params(pesge *sge, struct sge_params *p)
{
	if (!p->coalesce_enable) {
		u32 newTimer = p->rx_coalesce_usecs *
		    (board_info(sge->obj)->clock_core / 1000000);

		t1_write_reg_4(sge->obj, A_SG_INTRTIMER, newTimer);
	}
	return (0);
}

/*
 * Programs the various SGE registers. However, the engine is not yet enabled,
 * but sge->sge_control is setup and ready to go.
 */
static void
configure_sge(pesge *sge, struct sge_params *p)
{
	ch_t *ap = sge->obj;
	int i;

	t1_write_reg_4(ap, A_SG_CONTROL, 0);

	setup_ring_params(ap, sge->cmdQ[0].cq_pa, sge->cmdQ[0].cq_entries_n,
	    A_SG_CMD0BASELWR, A_SG_CMD0BASEUPR, A_SG_CMD0SIZE);
	setup_ring_params(ap, sge->cmdQ[1].cq_pa, sge->cmdQ[1].cq_entries_n,
	    A_SG_CMD1BASELWR, A_SG_CMD1BASEUPR, A_SG_CMD1SIZE);
	setup_ring_params(ap, sge->freelQ[0].fq_pa,
	    sge->freelQ[0].fq_entries_n, A_SG_FL0BASELWR,
	    A_SG_FL0BASEUPR, A_SG_FL0SIZE);
	setup_ring_params(ap, sge->freelQ[1].fq_pa,
	    sge->freelQ[1].fq_entries_n, A_SG_FL1BASELWR,
	    A_SG_FL1BASEUPR, A_SG_FL1SIZE);

	/* The threshold comparison uses <. */
	t1_write_reg_4(ap, A_SG_FLTHRESHOLD, SGE_RX_SM_BUF_SIZE(ap) -
	    SZ_CPL_RX_PKT - sge->rx_pkt_pad - sge->rx_offset + 1);
	setup_ring_params(ap, sge->respQ.rq_pa, sge->respQ.rq_entries_n,
	    A_SG_RSPBASELWR, A_SG_RSPBASEUPR, A_SG_RSPSIZE);
	t1_write_reg_4(ap, A_SG_RSPQUEUECREDIT, (u32)sge->respQ.rq_entries_n);
	sge->sge_control = F_CMDQ0_ENABLE | F_CMDQ1_ENABLE | F_FL0_ENABLE |
	    F_FL1_ENABLE | F_CPL_ENABLE | F_RESPONSE_QUEUE_ENABLE |
	    V_CMDQ_PRIORITY(2) | F_DISABLE_CMDQ1_GTS | F_ISCSI_COALESCE |
#if 1
		/*
		 * if the the following bit is not set, then we'll get an
		 * interrupt everytime command Q 0 goes empty. Since we're
		 * always ringing the doorbell, we can turn it on.
		 */
	    F_DISABLE_CMDQ0_GTS |
#endif
	    V_RX_PKT_OFFSET(sge->rx_pkt_pad);

#if BYTE_ORDER == BIG_ENDIAN
	sge->sge_control |= F_ENABLE_BIG_ENDIAN;
#endif

	/*
	 * Initialize the SGE Interrupt Timer arrray:
	 * intrtimer[0] = (SGE_INTRTIMER0) usec
	 * intrtimer[0<i<10] = (SGE_INTRTIMER0 + 2*i) usec
	 * intrtimer[10] = (SGE_INTRTIMER1) usec
	 *
	 */
	sge->intrtimer[0] = board_info(sge->obj)->clock_core / 1000000;
	for (i = 1; i < SGE_INTR_MAXBUCKETS - 1; ++i) {
		sge->intrtimer[i] = SGE_INTRTIMER0 + (2 * i);
		sge->intrtimer[i] *= sge->intrtimer[0];
	}
	sge->intrtimer[SGE_INTR_MAXBUCKETS - 1] =
	    sge->intrtimer[0] * SGE_INTRTIMER1;
	/* Initialize resource timer */
	sge->intrtimer_nres = (uint32_t)(sge->intrtimer[0] *
	    SGE_INTRTIMER_NRES);
	/* Finally finish initialization of intrtimer[0] */
	sge->intrtimer[0] = (uint32_t)(sge->intrtimer[0] * SGE_INTRTIMER0);
	/* Initialize for a throughput oriented workload */
	sge->currIndex = SGE_INTR_MAXBUCKETS - 1;

	if (p->coalesce_enable)
		t1_write_reg_4(ap, A_SG_INTRTIMER,
		    sge->intrtimer[sge->currIndex]);
	else
		(void) t1_sge_set_coalesce_params(sge, p);
}

static inline void
setup_ring_params(ch_t *adapter, u64 addr, u32 size, int base_reg_lo,
    int base_reg_hi, int size_reg)
{
	t1_write_reg_4(adapter, base_reg_lo, (u32)addr);
	t1_write_reg_4(adapter, base_reg_hi, addr >> 32);
	t1_write_reg_4(adapter, size_reg, size);
}

/*
 * Frees RX resources.
 */
static void
free_rx_resources(pesge *sge)
{
	unsigned int size, i;

	if (sge->respQ.rq_entries) {
		size = sizeof (respQ_e) * sge->respQ.rq_entries_n;

		pe_os_free_contig(sge->obj, size, sge->respQ.rq_entries,
		    sge->respQ.rq_pa, sge->respQ.rq_dh, sge->respQ.rq_ah);
	}

	for (i = 0; i < SGE_FREELQ_N; i++) {
		struct freelQ *Q = &sge->freelQ[i];

		if (Q->fq_centries) {
			free_freelQ_buffers(sge, Q);

			t1_os_free(Q->fq_centries,
			    Q->fq_entries_n * sizeof (freelQ_ce_t));
		}
		if (Q->fq_entries) {
			size = sizeof (freelQ_e) * Q->fq_entries_n;

			/* free the freelist queue */
			pe_os_free_contig(sge->obj, size, Q->fq_entries,
			    Q->fq_pa, Q->fq_dh, Q->fq_ah);

		}
	}
}

/*
 * Frees all RX buffers on the freelist Q. The caller must make sure that
 * the SGE is turned off before calling this function.
 */
static void
free_freelQ_buffers(pesge *sge, struct freelQ *Q)
{
	struct freelQ_ce *ce;
	struct freelQ_ce *cq = Q->fq_centries;
	uint32_t credits = Q->fq_credits;
	uint32_t entries_n = Q->fq_entries_n;
	uint32_t cidx = Q->fq_cidx;
	uint32_t i = Q->fq_id;

	ce = &cq[cidx];

	credits = entries_n;
	while (credits--) {
		mblk_t *mp;
		if ((mp = ce->fe_mp) != NULL) {
			/* bump in-use count of receive buffers */
			if (i != sge->jumbo_fl) {
				atomic_add(1,
				    &buffers_in_use[sge->obj->ch_sm_index]);
			} else {
				atomic_add(1,
				    &buffers_in_use[sge->obj->ch_big_index]);
			}

			/*
			 * note. freeb() callback of esb-alloced mblk will
			 * cause receive buffer to be put back on sa free list.
			 */
			freeb(mp);
			ce->fe_mp = NULL;
		}

		ce++;
		if (++cidx == entries_n) {
			cidx = 0;
			ce = cq;
		}
	}

	Q->fq_cidx = cidx;
	Q->fq_credits = credits;
}

/*
 * Free TX resources.
 *
 * Assumes that SGE is stopped and all interrupts are disabled.
 */
static void
free_tx_resources(pesge *sge)
{
	unsigned int size;
	uint32_t i;

	for (i = 0; i < SGE_CMDQ_N; i++) {
		struct cmdQ *Q = &sge->cmdQ[i];

		if (Q->cq_centries) {
			unsigned int pending = Q->cq_entries_n -
			    atomic_read(Q->cq_credits);

			mutex_destroy(&Q->cq_qlock);

			if (pending)
				free_cmdQ_buffers(sge, Q, pending);

			size = sizeof (struct cmdQ_ce) * Q->cq_entries_n;
			t1_os_free(Q->cq_centries, size);
		}

		if (Q->cq_entries) {
			size = sizeof (cmdQ_e) * Q->cq_entries_n;
			pe_os_free_contig(sge->obj, size, Q->cq_entries,
			    Q->cq_pa, Q->cq_dh, Q->cq_ah);
		}
	}
}

/*
 * Return the payload capacity of the jumbo free-list buffers.
 */
static inline unsigned int jumbo_payload_capacity(pesge *sge)
{
	return (sge->freelQ[sge->jumbo_fl].fq_rx_buffer_size -
	    sizeof (struct cpl_rx_data) - sge->rx_pkt_pad - sge->rx_offset);
}

/* PR2928 & PR3309 */
void
t1_sge_set_ptimeout(adapter_t *adapter, u32 val)
{
	pesge *sge = adapter->sge;

	if (is_T2(adapter))
		sge->ptimeout = max(val, 1);
}

/* PR2928 & PR3309 */
u32
t1_sge_get_ptimeout(adapter_t *adapter)
{
	pesge *sge = adapter->sge;

	return (is_T2(adapter) ? sge->ptimeout : 0);
}

void
sge_add_fake_arp(pesge *sge, void *bp)
{
	sge->pskb = bp;
}

#ifdef SUN_KSTATS
static int
sge_kstat_setup(pesge *sge)
{
	int status;
	p_kstat_t ksp;
	size_t ch_kstat_sz;
	p_ch_kstat_t chkp;
	char kstat_name[32];
	int instance;
	int i;

	status = -1;
	ch_kstat_sz = sizeof (ch_kstat_t);
	instance = ddi_get_instance(sge->obj->ch_dip);
	if ((ksp = kstat_create(CHNAME "_debug", instance,
	    NULL, "net_debug", KSTAT_TYPE_NAMED,
	    ch_kstat_sz / sizeof (kstat_named_t), 0)) == NULL)
		goto sge_kstat_setup_exit;
	chkp = (p_ch_kstat_t)ksp->ks_data;
	kstat_named_init(&chkp->respQ_empty,		"respQ_empty",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->respQ_overflow,		"respQ_overflow",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->freelistQ_empty,	"freelistQ_empty",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->pkt_too_big,		"pkt_too_big",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->pkt_mismatch,		"pkt_mismatch",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->cmdQ_full[0],		"cmdQ_full[0]",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->cmdQ_full[1],		"cmdQ_full[1]",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_reclaims[0],		"tx_reclaims[0]",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_reclaims[1],		"tx_reclaims[1]",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_msg_pullups,		"tx_msg_pullups",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_hdr_pullups,		"tx_hdr_pullups",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_tcp_ip_frag,		"tx_tcp_ip_frag",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_udp_ip_frag,		"tx_udp_ip_frag",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_soft_cksums,		"tx_soft_cksums",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_need_cpl_space,	"tx_need_cpl_space",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_multi_mblks,		"tx_multi_mblks",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_no_dvma1,	"tx_num_multi_dvma_fails",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_no_dvma2,	"tx_num_single_dvma_fails",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_no_dma1,	"tx_num_multi_dma_fails",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_no_dma2,	"tx_num_single_dma_fails",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_cmdq0,		"rx_cmdq0",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_cmdq1,		"rx_cmdq1",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flq0,		"rx_flq0",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flq1,		"rx_flq1",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flq0_sz,		"rx_flq0_buffer_sz",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flq1_sz,		"rx_flq1_buffer_sz",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_pkt_drops,		"rx_pkt_drops",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_pkt_copied,		"rx_pkt_copied",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_pause_on,		"rx_pause_on",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_pause_off,		"rx_pause_off",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_pause_ms,		"rx_pause_ms",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_pause_spike,		"rx_pause_spike",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_fl_credits,		"rx_fl_credits",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flbuf_fails,		"rx_flbuf_fails",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flbuf_allocs,	"rx_flbuf_allocs",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_badEopSop,		"rx_badEopSop",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flq0_cnt,		"rx_flq0_cnt",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->rx_flq1_cnt,		"rx_flq1_cnt",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->arp_sent,		"arp_sent",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->tx_doorbells,		"tx_doorbells",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->intr_doorbells,		"intr_doorbells",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->intr1_doorbells,	"intr1_doorbells",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->sleep_cnt,		"sleep_cnt",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&chkp->pe_allocb_cnt,		"pe_allocb_cnt",
	    KSTAT_DATA_UINT32);
	for (i = 0; i < MBLK_MAX; i++) {
		(void) sprintf(kstat_name, "tx_descs[%02d]", i);
		kstat_named_init(&chkp->tx_descs[i],
		    kstat_name, KSTAT_DATA_UINT32);
	}
	ksp->ks_update = sge_kstat_update;
	ksp->ks_private = (void *)sge;
	sge->ksp = ksp;
	kstat_install(ksp);
	status = 0;

sge_kstat_setup_exit:
	return (status);
}

static void
sge_kstat_remove(pesge *sge)
{
	if (sge->ksp)
		kstat_delete(sge->ksp);
}

static int
sge_kstat_update(p_kstat_t ksp, int rw)
{
	pesge *sge;
	p_ch_stats_t statsp;
	p_ch_kstat_t chkp;
	int i;

	sge = (pesge *)ksp->ks_private;
	statsp = (p_ch_stats_t)&sge->intr_cnt;
	chkp = (p_ch_kstat_t)ksp->ks_data;
	if (rw == KSTAT_WRITE) {
		statsp->respQ_empty	= chkp->respQ_empty.value.ui32;
		statsp->respQ_overflow	= chkp->respQ_overflow.value.ui32;
		statsp->freelistQ_empty	= chkp->freelistQ_empty.value.ui32;
		statsp->pkt_too_big	= chkp->pkt_too_big.value.ui32;
		statsp->pkt_mismatch	= chkp->pkt_mismatch.value.ui32;
		statsp->cmdQ_full[0]	= chkp->cmdQ_full[0].value.ui32;
		statsp->cmdQ_full[1]	= chkp->cmdQ_full[1].value.ui32;
		statsp->tx_reclaims[0]	= chkp->tx_reclaims[0].value.ui32;
		statsp->tx_reclaims[1]	= chkp->tx_reclaims[1].value.ui32;
		statsp->tx_msg_pullups	= chkp->tx_msg_pullups.value.ui32;
		statsp->tx_hdr_pullups	= chkp->tx_hdr_pullups.value.ui32;
		statsp->tx_tcp_ip_frag	= chkp->tx_tcp_ip_frag.value.ui32;
		statsp->tx_udp_ip_frag	= chkp->tx_udp_ip_frag.value.ui32;
		statsp->tx_soft_cksums	= chkp->tx_soft_cksums.value.ui32;
		statsp->tx_need_cpl_space
		    = chkp->tx_need_cpl_space.value.ui32;
		statsp->tx_multi_mblks	= chkp->tx_multi_mblks.value.ui32;
		statsp->tx_no_dvma1	= chkp->tx_no_dvma1.value.ui32;
		statsp->tx_no_dvma2	= chkp->tx_no_dvma2.value.ui32;
		statsp->tx_no_dma1	= chkp->tx_no_dma1.value.ui32;
		statsp->tx_no_dma2	= chkp->tx_no_dma2.value.ui32;
		statsp->rx_cmdq0	= chkp->rx_cmdq0.value.ui32;
		statsp->rx_cmdq1	= chkp->rx_cmdq1.value.ui32;
		statsp->rx_flq0		= chkp->rx_flq0.value.ui32;
		statsp->rx_flq1		= chkp->rx_flq1.value.ui32;
		statsp->rx_flq0_sz	= chkp->rx_flq0_sz.value.ui32;
		statsp->rx_flq1_sz	= chkp->rx_flq1_sz.value.ui32;
		statsp->rx_pkt_drops	= chkp->rx_pkt_drops.value.ui32;
		statsp->rx_pkt_copied	= chkp->rx_pkt_copied.value.ui32;
		statsp->rx_pause_on	= chkp->rx_pause_on.value.ui32;
		statsp->rx_pause_off	= chkp->rx_pause_off.value.ui32;
		statsp->rx_pause_ms	= chkp->rx_pause_ms.value.ui32;
		statsp->rx_pause_spike	= chkp->rx_pause_spike.value.ui32;
		statsp->rx_fl_credits	= chkp->rx_fl_credits.value.ui32;
		statsp->rx_flbuf_fails	= chkp->rx_flbuf_fails.value.ui32;
		statsp->rx_flbuf_allocs	= chkp->rx_flbuf_allocs.value.ui32;
		statsp->rx_badEopSop	= chkp->rx_badEopSop.value.ui32;
		statsp->rx_flq0_cnt	= chkp->rx_flq0_cnt.value.ui32;
		statsp->rx_flq1_cnt	= chkp->rx_flq1_cnt.value.ui32;
		statsp->arp_sent	= chkp->arp_sent.value.ui32;
		statsp->tx_doorbells	= chkp->tx_doorbells.value.ui32;
		statsp->intr_doorbells	= chkp->intr_doorbells.value.ui32;
		statsp->intr1_doorbells = chkp->intr1_doorbells.value.ui32;
		statsp->sleep_cnt	= chkp->sleep_cnt.value.ui32;
		statsp->pe_allocb_cnt	= chkp->pe_allocb_cnt.value.ui32;
		for (i = 0; i < MBLK_MAX; i++) {
			statsp->tx_descs[i] = chkp->tx_descs[i].value.ui32;
		}
	} else {
		chkp->respQ_empty.value.ui32	= statsp->respQ_empty;
		chkp->respQ_overflow.value.ui32	= statsp->respQ_overflow;
		chkp->freelistQ_empty.value.ui32
		    = statsp->freelistQ_empty;
		chkp->pkt_too_big.value.ui32	= statsp->pkt_too_big;
		chkp->pkt_mismatch.value.ui32	= statsp->pkt_mismatch;
		chkp->cmdQ_full[0].value.ui32	= statsp->cmdQ_full[0];
		chkp->cmdQ_full[1].value.ui32	= statsp->cmdQ_full[1];
		chkp->tx_reclaims[0].value.ui32	= statsp->tx_reclaims[0];
		chkp->tx_reclaims[1].value.ui32	= statsp->tx_reclaims[1];
		chkp->tx_msg_pullups.value.ui32	= statsp->tx_msg_pullups;
		chkp->tx_hdr_pullups.value.ui32	= statsp->tx_hdr_pullups;
		chkp->tx_tcp_ip_frag.value.ui32	= statsp->tx_tcp_ip_frag;
		chkp->tx_udp_ip_frag.value.ui32	= statsp->tx_udp_ip_frag;
		chkp->tx_soft_cksums.value.ui32	= statsp->tx_soft_cksums;
		chkp->tx_need_cpl_space.value.ui32
		    = statsp->tx_need_cpl_space;
		chkp->tx_multi_mblks.value.ui32	= statsp->tx_multi_mblks;
		chkp->tx_no_dvma1.value.ui32	= statsp->tx_no_dvma1;
		chkp->tx_no_dvma2.value.ui32	= statsp->tx_no_dvma2;
		chkp->tx_no_dma1.value.ui32	= statsp->tx_no_dma1;
		chkp->tx_no_dma2.value.ui32	= statsp->tx_no_dma2;
		chkp->rx_cmdq0.value.ui32	= statsp->rx_cmdq0;
		chkp->rx_cmdq1.value.ui32	= statsp->rx_cmdq1;
		chkp->rx_flq0.value.ui32	= statsp->rx_flq0;
		chkp->rx_flq1.value.ui32	= statsp->rx_flq1;
		chkp->rx_flq0_sz.value.ui32	= statsp->rx_flq0_sz;
		chkp->rx_flq1_sz.value.ui32	= statsp->rx_flq1_sz;
		chkp->rx_pkt_drops.value.ui32	= statsp->rx_pkt_drops;
		chkp->rx_pkt_copied.value.ui32	= statsp->rx_pkt_copied;
		chkp->rx_pause_on.value.ui32	= statsp->rx_pause_on;
		chkp->rx_pause_off.value.ui32	= statsp->rx_pause_off;
		chkp->rx_pause_ms.value.ui32	= statsp->rx_pause_ms;
		chkp->rx_pause_spike.value.ui32	= statsp->rx_pause_spike;
		chkp->rx_fl_credits.value.ui32	= statsp->rx_fl_credits;
		chkp->rx_flbuf_fails.value.ui32
		    = statsp->rx_flbuf_fails;
		chkp->rx_flbuf_allocs.value.ui32
		    = statsp->rx_flbuf_allocs;
		chkp->rx_badEopSop.value.ui32	= statsp->rx_badEopSop;
		chkp->rx_flq0_cnt.value.ui32	= statsp->rx_flq0_cnt;
		chkp->rx_flq1_cnt.value.ui32	= statsp->rx_flq1_cnt;
		chkp->arp_sent.value.ui32	= statsp->arp_sent;
		chkp->tx_doorbells.value.ui32	= statsp->tx_doorbells;
		chkp->intr_doorbells.value.ui32	= statsp->intr_doorbells;
		chkp->intr1_doorbells.value.ui32
		    = statsp->intr1_doorbells;
		chkp->sleep_cnt.value.ui32	= statsp->sleep_cnt;
		chkp->pe_allocb_cnt.value.ui32	= statsp->pe_allocb_cnt;
		for (i = 0; i < MBLK_MAX; i++) {
			chkp->tx_descs[i].value.ui32 = statsp->tx_descs[i];
		}
	}
	return (0);
}
#endif

static uint16_t
calc_ocsum(mblk_t *mp, int offset)
{
	uint8_t *addrp;
	uint32_t src;
	uint32_t dst;

	ipha_t *ihdr = (ipha_t *)(mp->b_rptr + offset);
	uint32_t sum;
	int iplen = IPH_HDR_LENGTH(ihdr);
	struct udphdr *udpp = (struct udphdr *)(mp->b_rptr + offset + iplen);
	uchar_t *byte;
	int len;

	addrp = (uint8_t *)&ihdr->ipha_src;
	src =  ((uint32_t)(addrp[0]) << 24) | ((uint32_t)(addrp[1]) << 16) |
	    ((uint32_t)(addrp[2]) << 8) | (uint32_t)(addrp[3]);

	addrp = (uint8_t *)&ihdr->ipha_dst;
	dst =  ((uint32_t)(addrp[0]) << 24) | ((uint32_t)(addrp[1]) << 16) |
	    ((uint32_t)(addrp[2]) << 8) | (uint32_t)(addrp[3]);

	sum = (uint16_t)(src >> 16) +
	    (uint16_t)(src) +
	    (uint16_t)(dst >> 16) +
	    (uint16_t)(dst) + (udpp->uh_ulen + htons(IPPROTO_UDP));

	sum = (uint16_t)(sum >> 16) + (uint16_t)(sum);

	if (sum > 0xffff)
		sum -= 0xffff;

	udpp->uh_sum = 0;
	byte = mp->b_rptr + offset + iplen;
	do {
		len = (mp->b_wptr - byte);
		sum = bcksum(byte, len, sum);
		if (sum > 0xffff)
			sum -= 0xffff;
		mp = mp->b_cont;
		if (mp)
			byte = mp->b_rptr;
	} while (mp);

	sum = ~sum & 0xffff;

	return (sum);
}
