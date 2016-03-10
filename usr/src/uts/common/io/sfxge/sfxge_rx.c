/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/strft.h>
#include <sys/ksynch.h>
#include <sys/ethernet.h>
#include <sys/crc32.h>
#include <sys/pattr.h>
#include <sys/cpu.h>

#include <sys/ethernet.h>
#include <inet/ip.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sfxge.h"

#include "efx.h"

/* RXQ flush response timeout (in microseconds) */
#define	SFXGE_RX_QFLUSH_USEC	(2000000)

/* RXQ flush tries in the case of failure */
#define	SFXGE_RX_QFLUSH_TRIES	(5)

/* RXQ default packet buffer preallocation (number of packet buffers) */
#define	SFXGE_RX_QPREALLOC	(0)

/* Receive packet DMA attributes */
static ddi_device_acc_attr_t sfxge_rx_packet_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_rx_packet_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version	*/
	0,			/* dma_attr_addr_lo	*/
	0xffffffffffffffffull,	/* dma_attr_addr_hi	*/
	0xffffffffffffffffull,	/* dma_attr_count_max	*/
	SFXGE_CPU_CACHE_SIZE,	/* dma_attr_align	*/
	0xffffffff,		/* dma_attr_burstsizes	*/
	1,			/* dma_attr_minxfer	*/
	0xffffffffffffffffull,	/* dma_attr_maxxfer	*/
	0xffffffffffffffffull,	/* dma_attr_seg		*/
	1,			/* dma_attr_sgllen	*/
	1,			/* dma_attr_granular	*/
	0			/* dma_attr_flags	*/
};

/* Receive queue DMA attributes */
static ddi_device_acc_attr_t sfxge_rxq_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_rxq_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version	*/
	0,			/* dma_attr_addr_lo	*/
	0xffffffffffffffffull,	/* dma_attr_addr_hi	*/
	0xffffffffffffffffull,	/* dma_attr_count_max	*/
	EFX_BUF_SIZE,		/* dma_attr_align	*/
	0xffffffff,		/* dma_attr_burstsizes	*/
	1,			/* dma_attr_minxfer	*/
	0xffffffffffffffffull,	/* dma_attr_maxxfer	*/
	0xffffffffffffffffull,	/* dma_attr_seg		*/
	1,			/* dma_attr_sgllen	*/
	1,			/* dma_attr_granular	*/
	0			/* dma_attr_flags	*/
};

/* Forward declaration */
static void sfxge_rx_qpreallocate(sfxge_rxq_t *srp, int nprealloc);

static int
sfxge_rx_packet_ctor(void *buf, void *arg, int kmflags)
{
	sfxge_rx_packet_t *srpp = buf;
	sfxge_t *sp = arg;
	dev_info_t *dip = sp->s_dip;
	int err;

	ASSERT3U(sizeof (srpp->__srp_u1.__srp_s1), <=,
	    sizeof (srpp->__srp_u1.__srp_pad));
	ASSERT3U(sizeof (srpp->__srp_u2.__srp_s2), <=,
	    sizeof (srpp->__srp_u2.__srp_pad));

	bzero(buf, sizeof (sfxge_rx_packet_t));

	/* Allocate a DMA handle */
	err = ddi_dma_alloc_handle(dip, &sfxge_rx_packet_dma_attr,
	    (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL, &(srpp->srp_dma_handle));
	if (err != DDI_SUCCESS)
		goto fail1;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, err);

	SFXGE_OBJ_CHECK(srpp, sfxge_rx_packet_t);

	return (-1);
}

static void
sfxge_rx_packet_dtor(void *buf, void *arg)
{
	sfxge_rx_packet_t *srpp = buf;

	_NOTE(ARGUNUSED(arg))

	/* Free the DMA handle */
	ddi_dma_free_handle(&(srpp->srp_dma_handle));
	srpp->srp_dma_handle = NULL;

	SFXGE_OBJ_CHECK(srpp, sfxge_rx_packet_t);
}

static int
sfxge_rx_qctor(void *buf, void *arg, int kmflags)
{
	sfxge_rxq_t *srp = buf;
	efsys_mem_t *esmp = &(srp->sr_mem);
	sfxge_t *sp = arg;
	sfxge_dma_buffer_attr_t dma_attr;
	sfxge_rx_fpp_t *srfppp;
	int nprealloc;
	unsigned int id;
	int rc;

	/* Compile-time structure layout checks */
	EFX_STATIC_ASSERT(sizeof (srp->__sr_u1.__sr_s1) <=
	    sizeof (srp->__sr_u1.__sr_pad));
	EFX_STATIC_ASSERT(sizeof (srp->__sr_u2.__sr_s2) <=
	    sizeof (srp->__sr_u2.__sr_pad));
	EFX_STATIC_ASSERT(sizeof (srp->__sr_u3.__sr_s3) <=
	    sizeof (srp->__sr_u3.__sr_pad));

	bzero(buf, sizeof (sfxge_rxq_t));

	srp->sr_sp = sp;

	dma_attr.sdba_dip	 = sp->s_dip;
	dma_attr.sdba_dattrp	 = &sfxge_rxq_dma_attr;
	dma_attr.sdba_callback	 = DDI_DMA_SLEEP;
	dma_attr.sdba_length	 = EFX_RXQ_SIZE(sp->s_rxq_size);
	dma_attr.sdba_memflags	 = DDI_DMA_CONSISTENT;
	dma_attr.sdba_devaccp	 = &sfxge_rxq_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_READ | DDI_DMA_CONSISTENT;
	dma_attr.sdba_maxcookies = 1;
	dma_attr.sdba_zeroinit	 = B_FALSE;

	if ((rc = sfxge_dma_buffer_create(esmp, &dma_attr)) != 0)
		goto fail1;

	/* Allocate some buffer table entries */
	if ((rc = sfxge_sram_buf_tbl_alloc(sp, EFX_RXQ_NBUFS(sp->s_rxq_size),
	    &(srp->sr_id))) != 0)
		goto fail2;

	/* Allocate the context array */
	if ((srp->sr_srpp = kmem_zalloc(sizeof (sfxge_rx_packet_t *) *
	    sp->s_rxq_size, kmflags)) == NULL) {
		rc = ENOMEM;
		goto fail3;
	}

	/* Allocate the flow table */
	if ((srp->sr_flow = kmem_zalloc(sizeof (sfxge_rx_flow_t) *
	    SFXGE_MAX_FLOW, kmflags)) == NULL) {
		rc = ENOMEM;
		goto fail4;
	}

	srp->sr_srfpp = &(srp->sr_srfp);
	srp->sr_rto = drv_usectohz(200000);

	srp->sr_mpp = &(srp->sr_mp);

	/* Initialize the free packet pool */
	srfppp = &(srp->sr_fpp);
	if ((srfppp->srfpp_putp = kmem_zalloc(SFXGE_CPU_CACHE_SIZE *
	    SFXGE_RX_FPP_NSLOTS, kmflags)) == NULL) {
		rc = ENOMEM;
		goto fail5;
	}
	for (id = 0; id < SFXGE_RX_FPP_NSLOTS; id++) {
		sfxge_rx_fpp_putlist_t *putp;
		size_t off;

		off = id * SFXGE_CPU_CACHE_SIZE;
		putp = (void *)(srfppp->srfpp_putp + off);

		putp->srfpl_putp = NULL;
		putp->srfpl_putpp = &(putp->srfpl_putp);
		mutex_init(&(putp->srfpl_lock), NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(sp->s_intr.si_intr_pri));
	}

	cv_init(&(srp->sr_flush_kv), NULL, CV_DRIVER, NULL);

	/* Preallocate some packets on the free packet pool */
	nprealloc = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "rx_prealloc_pkt_buffers", SFXGE_RX_QPREALLOC);
	sfxge_rx_qpreallocate(srp, nprealloc);


	return (0);

fail5:
	DTRACE_PROBE(fail5);

	srp->sr_mpp = NULL;

	srp->sr_rto = 0;
	srp->sr_srfpp = NULL;

	/* Free the flow table */
	kmem_free(srp->sr_flow, sizeof (sfxge_rx_flow_t) *
	    SFXGE_MAX_FLOW);
	srp->sr_flow = NULL;

fail4:
	DTRACE_PROBE(fail4);

	/* Free the context array */
	kmem_free(srp->sr_srpp, sizeof (sfxge_rx_packet_t *) *
	    sp->s_rxq_size);
	srp->sr_srpp = NULL;

fail3:
	DTRACE_PROBE(fail3);

	/* Free the buffer table entries */
	sfxge_sram_buf_tbl_free(sp, srp->sr_id,
	    EFX_RXQ_NBUFS(sp->s_rxq_size));
	srp->sr_id = 0;

fail2:
	DTRACE_PROBE(fail2);
	/* Remove dma setup */
	sfxge_dma_buffer_destroy(esmp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	srp->sr_sp = NULL;

	SFXGE_OBJ_CHECK(srp, sfxge_rxq_t);

	return (-1);
}

static void
sfxge_rx_qdtor(void *buf, void *arg)
{
	sfxge_rxq_t *srp = buf;
	efsys_mem_t *esmp = &(srp->sr_mem);
	sfxge_t *sp = srp->sr_sp;
	sfxge_rx_fpp_t *srfppp = &(srp->sr_fpp);
	unsigned int id;

	_NOTE(ARGUNUSED(arg))

	cv_destroy(&(srp->sr_flush_kv));

	/* Tear down the free packet pool */
	for (id = 0; id < SFXGE_RX_FPP_NSLOTS; id++) {
		sfxge_rx_fpp_putlist_t *putp;
		size_t off;

		off = id * SFXGE_CPU_CACHE_SIZE;
		putp = (void *)(srfppp->srfpp_putp + off);

		putp->srfpl_putpp = NULL;
		mutex_destroy(&(putp->srfpl_lock));

		SFXGE_OBJ_CHECK(putp, sfxge_rx_fpp_putlist_t);
	}
	kmem_free(srfppp->srfpp_putp, SFXGE_CPU_CACHE_SIZE *
	    SFXGE_RX_FPP_NSLOTS);
	srfppp->srfpp_putp = NULL;

	srp->sr_mpp = NULL;

	srp->sr_rto = 0;
	srp->sr_srfpp = NULL;

	/* Free the flow table */
	kmem_free(srp->sr_flow, sizeof (sfxge_rx_flow_t) *
	    SFXGE_MAX_FLOW);
	srp->sr_flow = NULL;

	/* Free the context array */
	kmem_free(srp->sr_srpp, sizeof (sfxge_rx_packet_t *) *
	    sp->s_rxq_size);
	srp->sr_srpp = NULL;

	/* Free the buffer table entries */
	sfxge_sram_buf_tbl_free(sp, srp->sr_id,
	    EFX_RXQ_NBUFS(sp->s_rxq_size));
	srp->sr_id = 0;

	/* Tear down dma setup */
	sfxge_dma_buffer_destroy(esmp);

	SFXGE_OBJ_CHECK(srp, sfxge_rxq_t);
}

/* Note: This function takes ownership of *srpp. */
static inline void
sfxge_rx_qfpp_put(sfxge_rxq_t *srp, sfxge_rx_packet_t *srpp)
{
	sfxge_rx_fpp_t *srfppp = &(srp->sr_fpp);
	mblk_t *mp = srpp->srp_mp;
	unsigned int id;
	size_t off;
	sfxge_rx_fpp_putlist_t *putp;

	ASSERT3P(mp->b_next, ==, NULL);
	ASSERT3P(mp->b_prev, ==, NULL);

	id = CPU->cpu_seqid & SFXGE_RX_FPP_MASK;
	off = id * SFXGE_CPU_CACHE_SIZE;

	ASSERT3P(srpp->srp_putp, ==, srfppp->srfpp_putp);
	putp = (void *)(srpp->srp_putp + off);

	mutex_enter(&(putp->srfpl_lock));
	putp->srfpl_count++;
	*putp->srfpl_putpp = mp;
	putp->srfpl_putpp = &(mp->b_next);
	mutex_exit(&(putp->srfpl_lock));
}

static unsigned int
sfxge_rx_qfpp_swizzle(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	sfxge_rx_fpp_t *srfppp = &(srp->sr_fpp);
	unsigned int start;
	unsigned int id;
	mblk_t *p;
	mblk_t **pp;
	unsigned int count;
	unsigned int loaned;

	ASSERT(mutex_owned(&(sep->se_lock)));

	/* We want to access the put list for the current CPU last */
	id = start = (CPU->cpu_seqid + 1) & SFXGE_RX_FPP_MASK;

	do {
		sfxge_rx_fpp_putlist_t *putp;
		size_t off;

		off = id * SFXGE_CPU_CACHE_SIZE;
		id  = (id + 1) & SFXGE_RX_FPP_MASK;

		putp = (void *)(srfppp->srfpp_putp + off);

		/* Acquire the put list */
		mutex_enter(&(putp->srfpl_lock));

		p = putp->srfpl_putp;
		pp = putp->srfpl_putpp;
		count = putp->srfpl_count;

		putp->srfpl_putp = NULL;
		putp->srfpl_putpp = &(putp->srfpl_putp);
		putp->srfpl_count = 0;

		mutex_exit(&(putp->srfpl_lock));

		if (p == NULL)
			continue;

		/* Add the list to the head of the get list */
		*pp = srfppp->srfpp_get;
		srfppp->srfpp_get = p;

		/* Adjust the counters */
		ASSERT3U(srfppp->srfpp_loaned, >=, count);
		srfppp->srfpp_loaned -= count;
		srfppp->srfpp_count += count;

#if 0
		/* NOTE: this probe is disabled because it is expensive!! */
		DTRACE_PROBE2(count,
		    unsigned int, (id - 1) & SFXGE_RX_FPP_MASK,
		    unsigned int, count);
#endif

	} while (id != start);

	/* Return the number of packets yet to appear in the put list */
	loaned = srfppp->srfpp_loaned;


	return (loaned);
}


#define	DB_FRTNP(mp)	((mp)->b_datap->db_frtnp)

static void
sfxge_rx_qfpp_empty(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	sfxge_rx_fpp_t *srfppp;
	mblk_t *mp;

	mutex_enter(&(sep->se_lock));
	srfppp = &(srp->sr_fpp);

	/* Swizzle put list to get list */
	(void) sfxge_rx_qfpp_swizzle(srp);
	ASSERT3U(srfppp->srfpp_loaned, ==, 0);

	mp = srfppp->srfpp_get;
	srfppp->srfpp_get = NULL;

	/* Free the remainder */
	while (mp != NULL) {
		mblk_t *next;
		frtn_t *freep;
		sfxge_rx_packet_t *srpp;

		next = mp->b_next;
		mp->b_next = NULL;

		ASSERT3U(srfppp->srfpp_count, >, 0);
		srfppp->srfpp_count--;

		freep = DB_FRTNP(mp);
		/*
		 * ASSERT3P(freep->free_func, ==, sfxge_rx_qpacket_free);
		 *   is implied by srpp test below
		 */
		/*LINTED*/
		srpp = (sfxge_rx_packet_t *)(freep->free_arg);
		ASSERT3P(srpp->srp_mp, ==, mp);
		ASSERT3P(mp->b_cont, ==, NULL);
		srpp->srp_recycle = B_FALSE;

		freeb(mp);

		mp = next;
	}
	ASSERT3U(srfppp->srfpp_count, ==, 0);

	srfppp->srfpp_min = 0;

	mutex_exit(&(sep->se_lock));
}

/*
 * This is an estimate of all memory consumed per RX packet
 * it can be inaccurate but but sp->s_rx_pkt_mem_alloc mustn't drift
 */
static uint64_t
sfxge_rx_pkt_mem_approx(const sfxge_rx_packet_t *srpp)
{
	return (srpp->srp_mblksize + sizeof (mblk_t) + sizeof (dblk_t) +
	    sizeof (sfxge_rx_packet_t));
}

static void
sfxge_rx_qpacket_destroy(sfxge_rxq_t *srp, sfxge_rx_packet_t *srpp)
{
	sfxge_t *sp = srp->sr_sp;
	int64_t delta = sfxge_rx_pkt_mem_approx(srpp);

	ASSERT(!(srpp->srp_recycle));
	ASSERT3P(srpp->srp_mp, ==, NULL);

	srpp->srp_off = 0;
	srpp->srp_thp = NULL;
	srpp->srp_iphp = NULL;
	srpp->srp_etherhp = NULL;
	srpp->srp_size = 0;
	srpp->srp_flags = 0;

	bzero(&(srpp->srp_free), sizeof (frtn_t));

	srpp->srp_mblksize = 0;
	srpp->srp_base = NULL;

	/* Unbind the DMA memory from the DMA handle */
	srpp->srp_addr = 0;
	(void) ddi_dma_unbind_handle(srpp->srp_dma_handle);

	/* Free the DMA memory */
	srpp->srp_base = NULL;
	ddi_dma_mem_free(&(srpp->srp_acc_handle));
	srpp->srp_acc_handle = NULL;

	srpp->srp_putp = NULL;
	srpp->srp_srp = NULL;

	kmem_cache_free(sp->s_rpc, srpp);
	if (sp->s_rx_pkt_mem_max)
		atomic_add_64(&sp->s_rx_pkt_mem_alloc, -delta);
}

static void
sfxge_rx_qpacket_free(void *arg)
{
	sfxge_rx_packet_t *srpp = arg;
	sfxge_rxq_t *srp = srpp->srp_srp;

	/*
	 * WARNING "man -s 9f esballoc"  states:
	 * => runs sync from the thread calling freeb()
	 * => must not sleep, or access data structures that could be freed
	 */

	/* Check whether we want to recycle the receive packets */
	if (srpp->srp_recycle) {
		frtn_t *freep;
		mblk_t *mp;
		size_t size;

		freep = &(srpp->srp_free);
		ASSERT3P(freep->free_func, ==, sfxge_rx_qpacket_free);
		ASSERT3P(freep->free_arg, ==, (caddr_t)srpp);

		/*
		 * Allocate a matching mblk_t before the current one is
		 * freed.
		 */
		size = srpp->srp_mblksize;

		if ((mp = desballoc(srpp->srp_base, size, BPRI_HI,
		    freep)) != NULL) {
			srpp->srp_mp = mp;

			/* NORMAL recycled case */
			sfxge_rx_qfpp_put(srp, srpp);
			return;
		}
	}

	srpp->srp_mp = NULL;

	sfxge_rx_qpacket_destroy(srp, srpp);
}

static sfxge_rx_packet_t *
sfxge_rx_qpacket_create(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	sfxge_rx_fpp_t *srfppp = &(srp->sr_fpp);
	sfxge_rx_packet_t *srpp;
	size_t size;
	caddr_t base;
	size_t unit;
	ddi_dma_cookie_t dmac;
	unsigned int ncookies;
	frtn_t *freep;
	mblk_t *mp;
	int err;
	int rc;

	size = sp->s_rx_buffer_size;

	if (sp->s_rx_pkt_mem_max &&
	    (sp->s_rx_pkt_mem_alloc + size >= sp->s_rx_pkt_mem_max)) {
		DTRACE_PROBE(rx_pkt_mem_max);
		srp->sr_kstat.srk_rx_pkt_mem_limit++;
		return (NULL);
	}

	/* Allocate a new packet */
	if ((srpp = kmem_cache_alloc(sp->s_rpc, KM_NOSLEEP)) == NULL) {
		srp->sr_kstat.srk_kcache_alloc_nomem++;
		rc = ENOMEM;
		goto fail1;
	}

	srpp->srp_srp = srp;
	srpp->srp_putp = srfppp->srfpp_putp;

	/* Allocate some DMA memory */
	err = ddi_dma_mem_alloc(srpp->srp_dma_handle, size,
	    &sfxge_rx_packet_devacc, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
	    NULL, &base, &unit, &(srpp->srp_acc_handle));
	switch (err) {
	case DDI_SUCCESS:
		break;

	case DDI_FAILURE:
		srp->sr_kstat.srk_dma_alloc_nomem++;
		rc = ENOMEM;
		goto fail2;

	default:
		srp->sr_kstat.srk_dma_alloc_fail++;
		rc = EFAULT;
		goto fail2;
	}

	/* Adjust the buffer to align the start of the DMA area correctly */
	base += sp->s_rx_buffer_align;
	size -= sp->s_rx_buffer_align;

	/* Bind the DMA memory to the DMA handle */
	err = ddi_dma_addr_bind_handle(srpp->srp_dma_handle, NULL,
	    base, size, DDI_DMA_READ | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, &dmac, &ncookies);
	switch (err) {
	case DDI_DMA_MAPPED:
		break;

	case DDI_DMA_INUSE:
		srp->sr_kstat.srk_dma_bind_fail++;
		rc = EEXIST;
		goto fail3;

	case DDI_DMA_NORESOURCES:
		srp->sr_kstat.srk_dma_bind_nomem++;
		rc = ENOMEM;
		goto fail3;

	case DDI_DMA_NOMAPPING:
		srp->sr_kstat.srk_dma_bind_fail++;
		rc = ENOTSUP;
		goto fail3;

	case DDI_DMA_TOOBIG:
		srp->sr_kstat.srk_dma_bind_fail++;
		rc = EFBIG;
		goto fail3;

	default:
		srp->sr_kstat.srk_dma_bind_fail++;
		rc = EFAULT;
		goto fail3;
	}
	ASSERT3U(ncookies, ==, 1);

	srpp->srp_addr = dmac.dmac_laddress;

	srpp->srp_base = (unsigned char *)base;
	srpp->srp_mblksize = size;

	/*
	 * Allocate a STREAMS block: We use size 1 so that the allocator will
	 * use the first (and smallest) dblk cache.
	 */
	freep = &(srpp->srp_free);
	freep->free_func = sfxge_rx_qpacket_free;
	freep->free_arg  = (caddr_t)srpp;

	if ((mp = desballoc(srpp->srp_base, size, BPRI_HI, freep)) == NULL) {
		srp->sr_kstat.srk_desballoc_fail++;
		rc = ENOMEM;
		goto fail4;
	}

	srpp->srp_mp = mp;
	srpp->srp_recycle = B_TRUE;

	if (sp->s_rx_pkt_mem_max) {
		int64_t delta = sfxge_rx_pkt_mem_approx(srpp);
		atomic_add_64(&sp->s_rx_pkt_mem_alloc, delta);
	}

	return (srpp);

fail4:
	DTRACE_PROBE(fail4);

	bzero(&(srpp->srp_free), sizeof (frtn_t));

	srpp->srp_mblksize = 0;
	srpp->srp_base = NULL;

	/* Unbind the DMA memory from the DMA handle */
	srpp->srp_addr = 0;
	(void) ddi_dma_unbind_handle(srpp->srp_dma_handle);

fail3:
	DTRACE_PROBE(fail3);

	/* Free the DMA memory */
	ddi_dma_mem_free(&(srpp->srp_acc_handle));
	srpp->srp_acc_handle = NULL;

fail2:
	DTRACE_PROBE(fail2);

	srpp->srp_putp = NULL;
	srpp->srp_srp = NULL;

	kmem_cache_free(sp->s_rpc, srpp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (NULL);
}

#define	SFXGE_REFILL_BATCH  64

/* Try to refill the RX descriptor ring from the associated free pkt pool */
static void
sfxge_rx_qrefill(sfxge_rxq_t *srp, unsigned int target)
{
	sfxge_t *sp = srp->sr_sp;
	sfxge_rx_fpp_t *srfppp = &(srp->sr_fpp);
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	efsys_dma_addr_t addr[SFXGE_REFILL_BATCH];
	mblk_t *mp;
	int ntodo;
	unsigned int count;
	unsigned int batch;
	unsigned int rxfill;
	unsigned int mblksize;

	prefetch_read_many(sp->s_enp);
	prefetch_read_many(srp->sr_erp);

	ASSERT(mutex_owned(&(sep->se_lock)));

	if (srp->sr_state != SFXGE_RXQ_STARTED)
		return;

	rxfill = srp->sr_added - srp->sr_completed;
	ASSERT3U(rxfill, <=, EFX_RXQ_LIMIT(sp->s_rxq_size));
	ntodo = min(EFX_RXQ_LIMIT(sp->s_rxq_size) - rxfill, target);
	ASSERT3U(ntodo, <=, EFX_RXQ_LIMIT(sp->s_rxq_size));

	if (ntodo == 0)
		goto out;

	(void) sfxge_rx_qfpp_swizzle(srp);

	mp = srfppp->srfpp_get;
	count = srfppp->srfpp_count;
	mblksize = sp->s_rx_buffer_size - sp->s_rx_buffer_align;

	batch = 0;
	while (ntodo-- > 0) {
		mblk_t *next;
		frtn_t *freep;
		sfxge_rx_packet_t *srpp;
		unsigned int id;

		if (mp == NULL)
			break;

		next = mp->b_next;
		mp->b_next = NULL;

		if (next != NULL)
			prefetch_read_many(next);

		freep = DB_FRTNP(mp);
		/*LINTED*/
		srpp = (sfxge_rx_packet_t *)(freep->free_arg);
		ASSERT3P(srpp->srp_mp, ==, mp);

		/* The MTU may have changed since the packet was allocated */
		if (MBLKSIZE(mp) != mblksize) {
			srpp->srp_recycle = B_FALSE;

			freeb(mp);

			--count;
			mp = next;
			continue;
		}

		srpp->srp_off = 0;
		srpp->srp_thp = NULL;
		srpp->srp_iphp = NULL;
		srpp->srp_etherhp = NULL;
		srpp->srp_size = 0;
		srpp->srp_flags = EFX_DISCARD;

		id = (srp->sr_added + batch) & (sp->s_rxq_size - 1);
		ASSERT(srp->sr_srpp[id] == NULL);
		srp->sr_srpp[id] = srpp;

		addr[batch++] = srpp->srp_addr;
		if (batch == SFXGE_REFILL_BATCH) {
			efx_rx_qpost(srp->sr_erp, addr, mblksize, batch,
			    srp->sr_completed, srp->sr_added);
			srp->sr_added += batch;
			batch = 0;
		}

		--count;
		mp = next;
	}

	srfppp->srfpp_get = mp;
	srfppp->srfpp_count = count;

	if (batch != 0) {
		efx_rx_qpost(srp->sr_erp, addr, mblksize, batch,
		    srp->sr_completed, srp->sr_added);
		srp->sr_added += batch;
	}

	efx_rx_qpush(srp->sr_erp, srp->sr_added, &srp->sr_pushed);

out:
	if (srfppp->srfpp_count < srfppp->srfpp_min)
		srfppp->srfpp_min = srfppp->srfpp_count;
}

/* Preallocate packets and put them in the free packet pool */
static void
sfxge_rx_qpreallocate(sfxge_rxq_t *srp, int nprealloc)
{
	sfxge_rx_fpp_t *srfppp = &((srp)->sr_fpp);
	srfppp->srfpp_lowat = nprealloc;
	while (nprealloc-- > 0) {
		sfxge_rx_packet_t *srpp;

		if ((srpp = sfxge_rx_qpacket_create(srp)) == NULL)
			break;
		sfxge_rx_qfpp_put(srp, srpp);
	}
}

/* Try to refill the RX descriptor ring by allocating new packets */
static void
sfxge_rx_qfill(sfxge_rxq_t *srp, unsigned int target)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	unsigned int batch;
	unsigned int rxfill;
	unsigned int mblksize;
	int ntodo;
	efsys_dma_addr_t addr[SFXGE_REFILL_BATCH];
	mblk_t *mp = NULL;

	prefetch_read_many(sp->s_enp);
	prefetch_read_many(srp->sr_erp);

	ASSERT(mutex_owned(&(sep->se_lock)));

	if (srp->sr_state != SFXGE_RXQ_STARTED)
		return;

	rxfill = srp->sr_added - srp->sr_completed;
	ASSERT3U(rxfill, <=, EFX_RXQ_LIMIT(sp->s_rxq_size));
	ntodo = min(EFX_RXQ_LIMIT(sp->s_rxq_size) - rxfill, target);
	ASSERT3U(ntodo, <=, EFX_RXQ_LIMIT(sp->s_rxq_size));

	if (ntodo == 0)
		return;

	mblksize = sp->s_rx_buffer_size - sp->s_rx_buffer_align;

	batch = 0;
	while (ntodo-- > 0) {
		sfxge_rx_packet_t *srpp;
		unsigned int id;

		if ((srpp = sfxge_rx_qpacket_create(srp)) == NULL)
			break;

		mp = srpp->srp_mp;

		ASSERT3U(MBLKSIZE(mp), ==, mblksize);

		ASSERT3U(srpp->srp_off, ==, 0);
		ASSERT3P(srpp->srp_thp, ==, NULL);
		ASSERT3P(srpp->srp_iphp, ==, NULL);
		ASSERT3P(srpp->srp_etherhp, ==, NULL);
		ASSERT3U(srpp->srp_size, ==, 0);

		srpp->srp_flags = EFX_DISCARD;

		id = (srp->sr_added + batch) & (sp->s_rxq_size - 1);
		ASSERT(srp->sr_srpp[id] == NULL);
		srp->sr_srpp[id] = srpp;

		addr[batch++] = srpp->srp_addr;
		if (batch == SFXGE_REFILL_BATCH) {
			efx_rx_qpost(srp->sr_erp, addr, mblksize, batch,
			    srp->sr_completed, srp->sr_added);
			srp->sr_added += batch;
			batch = 0;
		}
	}

	if (batch != 0) {
		efx_rx_qpost(srp->sr_erp, addr, mblksize, batch,
		    srp->sr_completed, srp->sr_added);
		srp->sr_added += batch;
	}

	efx_rx_qpush(srp->sr_erp, srp->sr_added, &srp->sr_pushed);
}

void
sfxge_rx_qfpp_trim(sfxge_rxq_t *srp)
{
	sfxge_rx_fpp_t *srfppp = &(srp->sr_fpp);
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	mblk_t *p;
	mblk_t **pp;
	int count;

	ASSERT(mutex_owned(&(sep->se_lock)));

	if (srp->sr_state != SFXGE_RXQ_STARTED)
		goto done;

	/* Make sure the queue is full */
	sfxge_rx_qrefill(srp, EFX_RXQ_LIMIT(sp->s_rxq_size));

	/* The refill may have emptied the pool */
	if (srfppp->srfpp_min == 0)
		goto done;

	/* Don't trim below the pool's low water mark */
	if (srfppp->srfpp_count <= srfppp->srfpp_lowat)
		goto done;

	ASSERT(srfppp->srfpp_min <= srfppp->srfpp_count);

	/* Trim to the largest of srfppp->srfpp_min and srfpp->srfpp_lowat */
	if (srfppp->srfpp_lowat > srfppp->srfpp_min)
		count = srfppp->srfpp_count - srfppp->srfpp_lowat;
	else
		count = srfppp->srfpp_count - srfppp->srfpp_min;

	/* Walk the get list */
	pp = &(srfppp->srfpp_get);
	while (--count >= 0) {
		ASSERT(pp);
		p = *pp;
		ASSERT(p != NULL);

		pp = &(p->b_next);
	}
	ASSERT(pp);
	p = *pp;

	/* Truncate the get list */
	*pp = NULL;

	/* Free the remainder */
	while (p != NULL) {
		mblk_t *next;
		frtn_t *freep;
		sfxge_rx_packet_t *srpp;

		next = p->b_next;
		p->b_next = NULL;

		ASSERT3U(srfppp->srfpp_min, >, 0);
		srfppp->srfpp_min--;
		srfppp->srfpp_count--;

		freep = DB_FRTNP(p);
		/*LINTED*/
		srpp = (sfxge_rx_packet_t *)(freep->free_arg);
		ASSERT3P(srpp->srp_mp, ==, p);

		srpp->srp_recycle = B_FALSE;

		freeb(p);

		p = next;
	}

done:
	srfppp->srfpp_min = srfppp->srfpp_count;
}

static void
sfxge_rx_qpoll(void *arg)
{
	sfxge_rxq_t *srp = arg;
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	uint16_t magic;

	/*
	 * man timeout(9f) states that this code should adhere to the
	 * same requirements as a softirq handler - DO NOT BLOCK
	 */

	/*
	 * Post an event to the event queue to cause the free packet pool to be
	 * trimmed if it is oversize.
	 */
	magic = SFXGE_MAGIC_RX_QFPP_TRIM | index;

#if defined(DEBUG)
	/* This is guaranteed due to the start/stop order of rx and ev */
	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_STARTED);
	ASSERT3U(srp->sr_state, ==, SFXGE_RXQ_STARTED);
#else
	/*
	 * Bug22691 WORKAROUND:
	 * This handler has been observed in the field to be invoked for a
	 * queue in the INITIALIZED state, which should never happen.
	 * Until the mechanism for this is properly understood, add defensive
	 * checks.
	 */
	if ((sep->se_state != SFXGE_EVQ_STARTED) ||
	    (srp->sr_state != SFXGE_RXQ_STARTED) ||
	    (!sep->se_eep)) {
		dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
		    "RXQ[%d] bad state in sfxge_rx_qpoll %d %d %p",
		    index, sep->se_state, srp->sr_state, sep->se_eep);
		return;
	}
#endif
	efx_ev_qpost(sep->se_eep, magic);

	srp->sr_tid = timeout(sfxge_rx_qpoll, srp,
	    drv_usectohz(sp->s_rxq_poll_usec));
}

static void
sfxge_rx_qpoll_start(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];

	ASSERT(mutex_owned(&(sep->se_lock)));
	ASSERT3U(srp->sr_state, ==, SFXGE_RXQ_STARTED);

	/* Schedule a poll */
	ASSERT3P(srp->sr_tid, ==, 0);
	srp->sr_tid = timeout(sfxge_rx_qpoll, srp, 0);
}

static void
sfxge_rx_qpoll_stop(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	timeout_id_t tid;

	ASSERT(mutex_owned(&(sep->se_lock)));
	ASSERT3U(srp->sr_state, ==, SFXGE_RXQ_STARTED);

	/*
	 * Cancel the qpoll timer. Care is needed as this function
	 * can race with sfxge_rx_qpoll() for timeout id updates.
	 *
	 * Do not hold locks used by any timeout(9f) handlers across
	 * calls to untimeout(9f) as this will deadlock.
	 */
	tid = 0;
	while ((srp->sr_tid != 0) && (srp->sr_tid != tid)) {
		tid = srp->sr_tid;
		(void) untimeout(tid);
	}
	srp->sr_tid = 0;
}

static int
sfxge_rx_kstat_update(kstat_t *ksp, int rw)
{
	sfxge_rxq_t *srp = ksp->ks_private;
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	kstat_named_t *knp;
	int rc;

	if (rw != KSTAT_READ) {
		rc = EACCES;
		goto fail1;
	}

	ASSERT(mutex_owned(&(sep->se_lock)));
	if (srp->sr_state != SFXGE_RXQ_STARTED)
		goto done;

	knp = ksp->ks_data;
	/* NB pointer post-increment below */
	knp++->value.ui32 = srp->sr_kstat.srk_rx_pkt_mem_limit;
	knp++->value.ui32 = srp->sr_kstat.srk_kcache_alloc_nomem;
	knp++->value.ui32 = srp->sr_kstat.srk_dma_alloc_nomem;
	knp++->value.ui32 = srp->sr_kstat.srk_dma_alloc_fail;
	knp++->value.ui32 = srp->sr_kstat.srk_dma_bind_nomem;
	knp++->value.ui32 = srp->sr_kstat.srk_dma_bind_fail;
	knp++->value.ui32 = srp->sr_kstat.srk_desballoc_fail;
	knp++->value.ui32 = srp->sr_kstat.srk_rxq_empty_discard;

done:
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_rx_kstat_init(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	dev_info_t *dip = sp->s_dip;
	char name[MAXNAMELEN];
	kstat_t *ksp;
	kstat_named_t *knp;
	int rc;

	/* Create the set */
	(void) snprintf(name, MAXNAMELEN - 1, "%s_rxq%04d",
	    ddi_driver_name(dip), index);

	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "rxq", KSTAT_TYPE_NAMED,
	    SFXGE_RX_NSTATS, 0)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	srp->sr_ksp = ksp;

	ksp->ks_update = sfxge_rx_kstat_update;
	ksp->ks_private = srp;
	ksp->ks_lock = &(sep->se_lock);

	/* Initialise the named stats */
	knp = ksp->ks_data;
	kstat_named_init(knp, "rx_pkt_mem_limit", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "kcache_alloc_nomem", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "dma_alloc_nomem", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "dma_alloc_fail", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "dma_bind_nomem", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "dma_bind_fail", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "desballoc_fail", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "rxq_empty_discard", KSTAT_DATA_UINT32);

	kstat_install(ksp);
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_rx_qinit(sfxge_t *sp, unsigned int index)
{
	sfxge_rxq_t *srp;
	int rc;

	ASSERT3U(index, <, SFXGE_RX_SCALE_MAX);

	if ((srp = kmem_cache_alloc(sp->s_rqc, KM_SLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}
	ASSERT3U(srp->sr_state, ==, SFXGE_RXQ_UNINITIALIZED);

	srp->sr_index = index;
	sp->s_srp[index] = srp;

	if ((rc = sfxge_rx_kstat_init(srp)) != 0)
		goto fail2;

	srp->sr_state = SFXGE_RXQ_INITIALIZED;

	return (0);

fail2:
	DTRACE_PROBE(fail2);
	kmem_cache_free(sp->s_rqc, srp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_rx_qstart(sfxge_t *sp, unsigned int index)
{
	sfxge_evq_t *sep = sp->s_sep[index];
	sfxge_rxq_t *srp;
	efsys_mem_t *esmp;
	efx_nic_t *enp;
	unsigned int level;
	int rc;

	mutex_enter(&(sep->se_lock));
	srp = sp->s_srp[index];
	enp = sp->s_enp;
	esmp = &(srp->sr_mem);

	ASSERT3U(srp->sr_state, ==, SFXGE_RXQ_INITIALIZED);
	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_STARTED);

	/* Zero the memory */
	bzero(esmp->esm_base, EFX_RXQ_SIZE(sp->s_rxq_size));

	/* Program the buffer table */
	if ((rc = sfxge_sram_buf_tbl_set(sp, srp->sr_id, esmp,
	    EFX_RXQ_NBUFS(sp->s_rxq_size))) != 0)
		goto fail1;

	/* Create the receive queue */
	if ((rc = efx_rx_qcreate(enp, index, index, EFX_RXQ_TYPE_DEFAULT,
	    esmp, sp->s_rxq_size, srp->sr_id, sep->se_eep, &(srp->sr_erp)))
	    != 0)
		goto fail2;

	/* Enable the receive queue */
	efx_rx_qenable(srp->sr_erp);

	/* Set the water marks */
	srp->sr_hiwat = EFX_RXQ_LIMIT(sp->s_rxq_size) * 9 / 10;
	srp->sr_lowat = srp->sr_hiwat / 2;

	srp->sr_state = SFXGE_RXQ_STARTED;
	srp->sr_flush = SFXGE_FLUSH_INACTIVE;

	sfxge_rx_qpoll_start(srp);

	/* Try to fill the queue from the pool */
	sfxge_rx_qrefill(srp, EFX_RXQ_LIMIT(sp->s_rxq_size));

	/*
	 * If there were insufficient buffers in the pool to reach the at
	 * least a batch then allocate some.
	 */
	level = srp->sr_added - srp->sr_completed;
	if (level < SFXGE_RX_BATCH)
		sfxge_rx_qfill(srp, SFXGE_RX_BATCH);

	mutex_exit(&(sep->se_lock));

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	/* Clear entries from the buffer table */
	sfxge_sram_buf_tbl_clear(sp, srp->sr_id,
	    EFX_RXQ_NBUFS(sp->s_rxq_size));

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(sep->se_lock));

	return (rc);
}

static void
sfxge_rx_qflow_complete(sfxge_rxq_t *srp, sfxge_rx_flow_t *srfp)
{
	mblk_t *mp;
	struct ether_header *etherhp;
	struct ip *iphp;
	struct tcphdr *thp;

	if (srfp->srf_mp == NULL)
		return;

	mp = srfp->srf_mp;
	etherhp = srfp->srf_etherhp;
	iphp = srfp->srf_iphp;
	thp = srfp->srf_last_thp;

	ASSERT3U(((etherhp->ether_type == htons(ETHERTYPE_VLAN)) ?
	    sizeof (struct ether_vlan_header) :
	    sizeof (struct ether_header)) +
	    srfp->srf_len, ==, msgdsize(mp));

	ASSERT3U(srfp->srf_len & 0xffff, ==, srfp->srf_len);
	iphp->ip_len = htons(srfp->srf_len);

	srfp->srf_first_thp->th_ack = thp->th_ack;
	srfp->srf_first_thp->th_win = thp->th_win;
	srfp->srf_first_thp->th_flags = thp->th_flags;

	DTRACE_PROBE2(flow_complete, uint32_t, srfp->srf_tag,
	    size_t, srfp->srf_len);

	srfp->srf_mp = NULL;
	srfp->srf_len = 0;

	ASSERT(mp->b_next == NULL);
	*(srp->sr_mpp) = mp;
	srp->sr_mpp = &(mp->b_next);
}

static boolean_t
sfxge_rx_qflow_add(sfxge_rxq_t *srp, sfxge_rx_flow_t *srfp,
    sfxge_rx_packet_t *srpp, clock_t now)
{
	sfxge_t *sp = srp->sr_sp;
	struct ether_header *etherhp = srpp->srp_etherhp;
	struct ip *iphp = srpp->srp_iphp;
	struct tcphdr *thp = srpp->srp_thp;
	size_t off = srpp->srp_off;
	size_t size = (size_t)(srpp->srp_size);
	mblk_t *mp = srpp->srp_mp;
	uint32_t seq;
	unsigned int shift;

	ASSERT3U(MBLKL(mp), ==, off + size);
	ASSERT3U(DB_CKSUMFLAGS(mp), ==,
	    HCK_FULLCKSUM | HCK_FULLCKSUM_OK | HCK_IPV4_HDRCKSUM);

	seq = htonl(thp->th_seq);

	/*
	 * If the time between this segment and the last is greater than RTO
	 * then consider this a new flow.
	 */
	if (now - srfp->srf_lbolt > srp->sr_rto) {
		srfp->srf_count = 1;
		srfp->srf_seq = seq + size;

		goto fail1;
	}

	if (seq != srfp->srf_seq) {
		if (srfp->srf_count > SFXGE_SLOW_START)
			srfp->srf_count = SFXGE_SLOW_START;

		srfp->srf_count >>= 1;

		srfp->srf_count++;
		srfp->srf_seq = seq + size;

		goto fail2;
	}

	/* Update the in-order segment count and sequence number */
	srfp->srf_count++;
	srfp->srf_seq = seq + size;

	/* Don't merge across pure ACK, URG, SYN or RST segments */
	if (size == 0 || thp->th_flags & (TH_URG | TH_SYN | TH_RST) ||
	    thp->th_urp != 0)
		goto fail3;

	/*
	 * If the in-order segment count has not yet reached the slow-start
	 * threshold then we cannot coalesce.
	 */
	if (srfp->srf_count < SFXGE_SLOW_START)
		goto fail4;

	/* Scale up the packet size from 4k (the maximum being 64k) */
	ASSERT3U(srfp->srf_count, >=, SFXGE_SLOW_START);
	shift = MIN(srfp->srf_count - SFXGE_SLOW_START + 12, 16);
	if (srfp->srf_len + size >= (1 << shift))
		sfxge_rx_qflow_complete(srp, srfp);

	ASSERT(mp->b_cont == NULL);

	if (srfp->srf_mp == NULL) {
		/* First packet in this flow */
		srfp->srf_etherhp = etherhp;
		srfp->srf_iphp = iphp;
		srfp->srf_first_thp = srfp->srf_last_thp = thp;

		ASSERT3P(mp->b_cont, ==, NULL);
		srfp->srf_mp = mp;
		srfp->srf_mpp = &(mp->b_cont);

		srfp->srf_len = ntohs(iphp->ip_len);

		/*
		 * If the flow is not already in the list of occupied flows then
		 * add it.
		 */
		if (srfp->srf_next == NULL &&
		    srp->sr_srfpp != &(srfp->srf_next)) {
			*(srp->sr_srfpp) = srfp;
			srp->sr_srfpp = &(srfp->srf_next);
		}
	} else {
		/* Later packet in this flow - skip TCP header */
		srfp->srf_last_thp = thp;

		mp->b_rptr += off;
		ASSERT3U(MBLKL(mp), ==, size);

		ASSERT3P(mp->b_cont, ==, NULL);
		*(srfp->srf_mpp) = mp;
		srfp->srf_mpp = &(mp->b_cont);

		srfp->srf_len += size;

		ASSERT(srfp->srf_next != NULL ||
		    srp->sr_srfpp == &(srfp->srf_next));
	}

	DTRACE_PROBE2(flow_add, uint32_t, srfp->srf_tag, size_t, size);

	/*
	 * Try to align coalesced segments on push boundaries, unless they
	 * are too frequent.
	 */
	if (sp->s_rx_coalesce_mode == SFXGE_RX_COALESCE_ALLOW_PUSH &&
	    thp->th_flags & TH_PUSH)
		sfxge_rx_qflow_complete(srp, srfp);

	srfp->srf_lbolt = now;
	return (B_TRUE);

fail4:
fail3:
fail2:
fail1:
	sfxge_rx_qflow_complete(srp, srfp);

	srfp->srf_lbolt = now;
	return (B_FALSE);
}

void
sfxge_rx_qpacket_coalesce(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	clock_t now;
	mblk_t *mp;
	sfxge_rx_flow_t *srfp;

	ASSERT(sp->s_rx_coalesce_mode != SFXGE_RX_COALESCE_OFF);

	now = ddi_get_lbolt();

	mp = srp->sr_mp;

	srp->sr_mp = NULL;
	srp->sr_mpp = &(srp->sr_mp);

	/* Start with the last flow to be appended to */
	srfp = *(srp->sr_srfpp);

	while (mp != NULL) {
		frtn_t *freep;
		sfxge_rx_packet_t *srpp;
		struct ether_header *etherhp;
		struct ip *iphp;
		struct tcphdr *thp;
		size_t off;
		size_t size;
		uint16_t ether_tci;
		uint32_t hash;
		uint32_t tag;
		mblk_t *next;
		sfxge_packet_type_t pkt_type;
		uint16_t sport, dport;

		next = mp->b_next;
		mp->b_next = NULL;

		if (next != NULL)
			prefetch_read_many(next);

		freep = DB_FRTNP(mp);
		/*LINTED*/
		srpp = (sfxge_rx_packet_t *)(freep->free_arg);
		ASSERT3P(srpp->srp_mp, ==, mp);

		/* If the packet is not TCP then we cannot coalesce it */
		if (~(srpp->srp_flags) & EFX_PKT_TCP)
			goto reject;

		/*
		 * If the packet is not fully checksummed then we cannot
		 * coalesce it.
		 */
		if (~(srpp->srp_flags) & (EFX_CKSUM_TCPUDP | EFX_CKSUM_IPV4))
			goto reject;

		/* Parse the TCP header */
		pkt_type = sfxge_pkthdr_parse(mp, &etherhp, &iphp, &thp, &off,
		    &size, &sport, &dport);
		ASSERT(pkt_type == SFXGE_PACKET_TYPE_IPV4_TCP);
		ASSERT(etherhp != NULL);
		ASSERT(iphp != NULL);
		ASSERT(thp != NULL);
		ASSERT(off != 0);

		if ((iphp->ip_off & ~htons(IP_DF)) != 0)
			goto reject;

		if (etherhp->ether_type == htons(ETHERTYPE_VLAN)) {
			struct ether_vlan_header *ethervhp;

			ethervhp = (struct ether_vlan_header *)etherhp;
			ether_tci = ethervhp->ether_tci;
		} else {
			ether_tci = 0;
		}

		/*
		 * Make sure any minimum length padding is stripped
		 * before we try to add the packet to a flow.
		 */
		ASSERT3U(sp->s_rx_prefix_size + MBLKL(mp), ==,
		    (size_t)(srpp->srp_size));
		ASSERT3U(sp->s_rx_prefix_size + off + size, <=,
		    (size_t)(srpp->srp_size));

		if (sp->s_rx_prefix_size + off + size <
		    (size_t)(srpp->srp_size))
			mp->b_wptr = mp->b_rptr + off + size;

		/*
		 * If there is no current flow, or the segment does not match
		 * the current flow then we must attempt to look up the
		 * correct flow in the table.
		 */
		if (srfp == NULL)
			goto lookup;

		if (srfp->srf_saddr != iphp->ip_src.s_addr ||
		    srfp->srf_daddr != iphp->ip_dst.s_addr)
			goto lookup;

		if (srfp->srf_sport != thp->th_sport ||
		    srfp->srf_dport != thp->th_dport)
			goto lookup;

		if (srfp->srf_tci != ether_tci)
			goto lookup;

add:
		ASSERT(srfp != NULL);

		srpp->srp_etherhp = etherhp;
		srpp->srp_iphp = iphp;
		srpp->srp_thp = thp;
		srpp->srp_off = off;

		ASSERT3U(size, <, (1 << 16));
		srpp->srp_size = (uint16_t)size;

		/* Try to append the packet to the flow */
		if (!sfxge_rx_qflow_add(srp, srfp, srpp, now))
			goto reject;

		mp = next;
		continue;

lookup:
		/*
		 * If there is a prefix area then read the hash from that,
		 * otherwise calculate it.
		 */
		if (sp->s_rx_prefix_size != 0) {
			hash = efx_psuedo_hdr_hash_get(sp->s_enp,
			    EFX_RX_HASHALG_TOEPLITZ,
			    DB_BASE(mp));
		} else {
			SFXGE_TCP_HASH(sp,
			    &iphp->ip_src.s_addr,
			    thp->th_sport,
			    &iphp->ip_dst.s_addr,
			    thp->th_dport,
			    hash);
		}

		srfp = &(srp->sr_flow[(hash >> 6) % SFXGE_MAX_FLOW]);
		tag = hash + 1; /* Make sure it's not zero */

		/*
		 * If the flow we have found does not match the hash then
		 * it may be an unused flow, or it may be stale.
		 */
		if (tag != srfp->srf_tag) {
			if (srfp->srf_count != 0) {
				if (now - srfp->srf_lbolt <= srp->sr_rto)
					goto reject;
			}

			if (srfp->srf_mp != NULL)
				goto reject;

			/* Start a new flow */
			ASSERT(srfp->srf_next == NULL);

			srfp->srf_tag = tag;

			srfp->srf_saddr = iphp->ip_src.s_addr;
			srfp->srf_daddr = iphp->ip_dst.s_addr;
			srfp->srf_sport = thp->th_sport;
			srfp->srf_dport = thp->th_dport;
			srfp->srf_tci = ether_tci;

			srfp->srf_count = 0;
			srfp->srf_seq = ntohl(thp->th_seq);

			srfp->srf_lbolt = now;
			goto add;
		}

		/*
		 * If the flow we have found does match the hash then it could
		 * still be an alias.
		 */
		if (srfp->srf_saddr != iphp->ip_src.s_addr ||
		    srfp->srf_daddr != iphp->ip_dst.s_addr)
			goto reject;

		if (srfp->srf_sport != thp->th_sport ||
		    srfp->srf_dport != thp->th_dport)
			goto reject;

		if (srfp->srf_tci != ether_tci)
			goto reject;

		goto add;

reject:
		*(srp->sr_mpp) = mp;
		srp->sr_mpp = &(mp->b_next);

		mp = next;
	}
}

void
sfxge_rx_qcomplete(sfxge_rxq_t *srp, boolean_t eop)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	unsigned int completed;
	sfxge_rx_fpp_t *srfppp = &(srp->sr_fpp);
	unsigned int level;

	ASSERT(mutex_owned(&(sep->se_lock)));

	ASSERT(srp->sr_mp == NULL);
	ASSERT(srp->sr_mpp == &(srp->sr_mp));

	completed = srp->sr_completed;
	while (completed != srp->sr_pending) {
		unsigned int id;
		sfxge_rx_packet_t *srpp;
		mblk_t *mp;
		size_t size;
		uint16_t flags;
		int rc;

		id = completed++ & (sp->s_rxq_size - 1);

		if (srp->sr_pending - completed >= 4) {
			unsigned int prefetch;

			prefetch = (id + 4) & (sp->s_rxq_size - 1);

			srpp = srp->sr_srpp[prefetch];
			ASSERT(srpp != NULL);

			mp = srpp->srp_mp;
			prefetch_read_many(mp->b_datap);
		} else if (completed == srp->sr_pending) {
			prefetch_read_many(srp->sr_mp);
		}

		srpp = srp->sr_srpp[id];
		ASSERT(srpp != NULL);

		srp->sr_srpp[id] = NULL;

		mp = srpp->srp_mp;
		ASSERT(mp->b_cont == NULL);

		/* when called from sfxge_rx_qstop() */
		if (srp->sr_state != SFXGE_RXQ_STARTED)
			goto discard;

		if (srpp->srp_flags & (EFX_ADDR_MISMATCH | EFX_DISCARD))
			goto discard;

		/* Make the data visible to the kernel */
		rc = ddi_dma_sync(srpp->srp_dma_handle, 0,
		    sp->s_rx_buffer_size, DDI_DMA_SYNC_FORKERNEL);
		ASSERT3P(rc, ==, DDI_SUCCESS);

		/* Read the length from the psuedo header if required */
		if (srpp->srp_flags & EFX_PKT_PREFIX_LEN) {
			rc = efx_psuedo_hdr_pkt_length_get(sp->s_enp,
			    mp->b_rptr,
			    &srpp->srp_size);
			ASSERT3P(rc, ==, 0);
			srpp->srp_size += sp->s_rx_prefix_size;
		}

		/* Set up the packet length */
		ASSERT3P(mp->b_rptr, ==, DB_BASE(mp));
		mp->b_rptr += sp->s_rx_prefix_size;

		prefetch_read_many(mp->b_rptr);

		ASSERT3P(mp->b_wptr, ==, DB_BASE(mp));
		mp->b_wptr += (size_t)(srpp->srp_size);
		ASSERT3P(mp->b_wptr, <=, DB_LIM(mp));

		/* Calculate the maximum packet size */
		size = sp->s_mtu;
		size += (srpp->srp_flags & EFX_PKT_VLAN_TAGGED) ?
		    sizeof (struct ether_vlan_header) :
		    sizeof (struct ether_header);

		if (MBLKL(mp) > size)
			goto discard;

		/* Check for loopback packets */
		if (!(srpp->srp_flags & EFX_PKT_IPV4) &&
		    !(srpp->srp_flags & EFX_PKT_IPV6)) {
			struct ether_header *etherhp;

			/*LINTED*/
			etherhp = (struct ether_header *)(mp->b_rptr);

			if (etherhp->ether_type ==
			    htons(SFXGE_ETHERTYPE_LOOPBACK)) {
				DTRACE_PROBE(loopback);

				srp->sr_loopback++;
				goto discard;
			}
		}

		/* Set up the checksum information */
		flags = 0;

		if (srpp->srp_flags & EFX_CKSUM_IPV4) {
			ASSERT(srpp->srp_flags & EFX_PKT_IPV4);
			flags |= HCK_IPV4_HDRCKSUM;
		}

		if (srpp->srp_flags & EFX_CKSUM_TCPUDP) {
			ASSERT(srpp->srp_flags & EFX_PKT_TCP ||
			    srpp->srp_flags & EFX_PKT_UDP);
			flags |= HCK_FULLCKSUM | HCK_FULLCKSUM_OK;
		}

		DB_CKSUMSTART(mp) = 0;
		DB_CKSUMSTUFF(mp) = 0;
		DB_CKSUMEND(mp) = 0;
		DB_CKSUMFLAGS(mp) = flags;
		DB_CKSUM16(mp) = 0;

		/* Add the packet to the tail of the chain */
		srfppp->srfpp_loaned++;

		ASSERT(mp->b_next == NULL);
		*(srp->sr_mpp) = mp;
		srp->sr_mpp = &(mp->b_next);

		continue;

discard:
		/* Return the packet to the pool */
		srfppp->srfpp_loaned++;
		freeb(mp); /* Equivalent to freemsg() as b_cont==0 */
	}
	srp->sr_completed = completed;

	/* Attempt to coalesce any TCP packets */
	if (sp->s_rx_coalesce_mode != SFXGE_RX_COALESCE_OFF)
		sfxge_rx_qpacket_coalesce(srp);

	/*
	 * If there are any pending flows and this is the end of the
	 * poll then they must be completed.
	 */
	if (srp->sr_srfp != NULL && eop) {
		sfxge_rx_flow_t *srfp;

		srfp = srp->sr_srfp;

		srp->sr_srfp = NULL;
		srp->sr_srfpp = &(srp->sr_srfp);

		do {
			sfxge_rx_flow_t *next;

			next = srfp->srf_next;
			srfp->srf_next = NULL;

			sfxge_rx_qflow_complete(srp, srfp);

			srfp = next;
		} while (srfp != NULL);
	}

	level = srp->sr_pushed - srp->sr_completed;

	/* If there are any packets then pass them up the stack */
	if (srp->sr_mp != NULL) {
		mblk_t *mp;

		mp = srp->sr_mp;

		srp->sr_mp = NULL;
		srp->sr_mpp = &(srp->sr_mp);

		if (level == 0) {
			/* Try to refill ASAP */
			sfxge_rx_qrefill(srp, EFX_RXQ_LIMIT(sp->s_rxq_size));
			level = srp->sr_pushed - srp->sr_completed;
		}

		/*
		 * If the RXQ is still empty, discard and recycle the
		 * current entry to ensure that the ring always
		 * contains at least one descriptor. This ensures that
		 * the next hardware RX will trigger an event
		 * (possibly delayed by interrupt moderation) and
		 * trigger another refill/fill attempt.
		 *
		 * Note this drops a complete LRO fragment from the
		 * start of the batch.
		 *
		 * Note also that copymsgchain() does not help with
		 * resource starvation here, unless we are short of DMA
		 * mappings.
		 */
		if (level == 0) {
			mblk_t *nmp;

			srp->sr_kstat.srk_rxq_empty_discard++;
			DTRACE_PROBE1(rxq_empty_discard, int, index);
			nmp = mp->b_next;
			if (nmp)
				sfxge_gld_rx_post(sp, index, nmp);
			/* as level==0 will swizzle,rxpost below */
			freemsg(mp);
		} else {
			sfxge_gld_rx_post(sp, index, mp);
		}
	}

	/* Top up the queue if necessary */
	if (level < srp->sr_hiwat) {
		sfxge_rx_qrefill(srp, EFX_RXQ_LIMIT(sp->s_rxq_size));

		level = srp->sr_added - srp->sr_completed;
		if (level < srp->sr_lowat)
			sfxge_rx_qfill(srp, EFX_RXQ_LIMIT(sp->s_rxq_size));
	}
}

void
sfxge_rx_qflush_done(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	boolean_t flush_pending;

	ASSERT(mutex_owned(&(sep->se_lock)));

	/*
	 * Flush successful: wakeup sfxge_rx_qstop() if flush is pending.
	 *
	 * A delayed flush event received after RxQ stop has timed out
	 * will be ignored, as then the flush state will not be PENDING
	 * (see SFCbug22989).
	 */
	flush_pending = (srp->sr_flush == SFXGE_FLUSH_PENDING);
	srp->sr_flush = SFXGE_FLUSH_DONE;
	if (flush_pending)
		cv_broadcast(&(srp->sr_flush_kv));
}

void
sfxge_rx_qflush_failed(sfxge_rxq_t *srp)
{
	sfxge_t *sp = srp->sr_sp;
	unsigned int index = srp->sr_index;
	sfxge_evq_t *sep = sp->s_sep[index];
	boolean_t flush_pending;

	ASSERT(mutex_owned(&(sep->se_lock)));

	/*
	 * Flush failed: wakeup sfxge_rx_qstop() if flush is pending.
	 *
	 * A delayed flush event received after RxQ stop has timed out
	 * will be ignored, as then the flush state will not be PENDING
	 * (see SFCbug22989).
	 */
	flush_pending = (srp->sr_flush == SFXGE_FLUSH_PENDING);
	srp->sr_flush = SFXGE_FLUSH_FAILED;
	if (flush_pending)
		cv_broadcast(&(srp->sr_flush_kv));
}

static void
sfxge_rx_qstop(sfxge_t *sp, unsigned int index)
{
	dev_info_t *dip = sp->s_dip;
	sfxge_evq_t *sep = sp->s_sep[index];
	sfxge_rxq_t *srp;
	clock_t timeout;
	unsigned int flush_tries = SFXGE_RX_QFLUSH_TRIES;
	int rc;

	ASSERT(mutex_owned(&(sp->s_state_lock)));

	mutex_enter(&(sep->se_lock));

	srp = sp->s_srp[index];
	ASSERT3U(srp->sr_state, ==, SFXGE_RXQ_STARTED);

	sfxge_rx_qpoll_stop(srp);

	/* Further packets are discarded by sfxge_rx_qcomplete() */
	srp->sr_state = SFXGE_RXQ_INITIALIZED;

	if (sp->s_hw_err != SFXGE_HW_OK) {
		/*
		 * Flag indicates possible hardware failure.
		 * Attempt flush but do not wait for it to complete.
		 */
		srp->sr_flush = SFXGE_FLUSH_DONE;
		(void) efx_rx_qflush(srp->sr_erp);
	}

	/* Wait upto 2sec for queue flushing to complete */
	timeout = ddi_get_lbolt() + drv_usectohz(SFXGE_RX_QFLUSH_USEC);

	while (srp->sr_flush != SFXGE_FLUSH_DONE && flush_tries-- > 0) {
		if ((rc = efx_rx_qflush(srp->sr_erp)) != 0) {
			if (rc == EALREADY)
				srp->sr_flush = SFXGE_FLUSH_DONE;
			else
				srp->sr_flush = SFXGE_FLUSH_FAILED;
			break;
		}
		srp->sr_flush = SFXGE_FLUSH_PENDING;
		if (cv_timedwait(&(srp->sr_flush_kv), &(sep->se_lock),
		    timeout) < 0) {
			/* Timeout waiting for successful or failed flush */
			dev_err(dip, CE_NOTE,
			    SFXGE_CMN_ERR "rxq[%d] flush timeout", index);
			break;
		}
	}

	if (srp->sr_flush == SFXGE_FLUSH_FAILED)
		dev_err(dip, CE_NOTE,
		    SFXGE_CMN_ERR "rxq[%d] flush failed", index);

	DTRACE_PROBE1(flush, sfxge_flush_state_t, srp->sr_flush);
	srp->sr_flush = SFXGE_FLUSH_DONE;

	/* Destroy the receive queue */
	efx_rx_qdestroy(srp->sr_erp);
	srp->sr_erp = NULL;

	/* Clear entries from the buffer table */
	sfxge_sram_buf_tbl_clear(sp, srp->sr_id,
	    EFX_RXQ_NBUFS(sp->s_rxq_size));

	/*
	 * Free any unused RX packets which had descriptors on the RXQ
	 * Packets will be discard as state != STARTED
	 */
	srp->sr_pending = srp->sr_added;
	sfxge_rx_qcomplete(srp, B_TRUE);

	ASSERT3U(srp->sr_completed, ==, srp->sr_pending);

	srp->sr_added = 0;
	srp->sr_pushed = 0;
	srp->sr_pending = 0;
	srp->sr_completed = 0;
	srp->sr_loopback = 0;

	srp->sr_lowat = 0;
	srp->sr_hiwat = 0;

	mutex_exit(&(sep->se_lock));
}

static void
sfxge_rx_kstat_fini(sfxge_rxq_t *srp)
{
	kstat_delete(srp->sr_ksp);
	srp->sr_ksp = NULL;
}

static void
sfxge_rx_qfini(sfxge_t *sp, unsigned int index)
{
	sfxge_rxq_t *srp = sp->s_srp[index];

	ASSERT3U(srp->sr_state, ==, SFXGE_RXQ_INITIALIZED);

	sp->s_srp[index] = NULL;
	srp->sr_state = SFXGE_RXQ_UNINITIALIZED;

	sfxge_rx_kstat_fini(srp);

	/* Empty the pool */
	sfxge_rx_qfpp_empty(srp);

	srp->sr_index = 0;

	kmem_cache_free(sp->s_rqc, srp);
}

static int
sfxge_rx_scale_kstat_update(kstat_t *ksp, int rw)
{
	sfxge_t *sp = ksp->ks_private;
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	sfxge_intr_t *sip = &(sp->s_intr);
	kstat_named_t *knp;
	unsigned int index;
	unsigned int entry;
	unsigned int *freq;
	int rc;

	ASSERT(mutex_owned(&(srsp->srs_lock)));

	if (rw != KSTAT_READ) {
		rc = EACCES;
		goto fail1;
	}

	if ((freq = kmem_zalloc(sizeof (unsigned int) * sip->si_nalloc,
	    KM_NOSLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	for (entry = 0; entry < SFXGE_RX_SCALE_MAX; entry++) {
		index = srsp->srs_tbl[entry];

		freq[index]++;
	}

	knp = ksp->ks_data;
	for (index = 0; index < sip->si_nalloc; index++) {
		knp->value.ui64 = freq[index];
		knp++;
	}

	knp->value.ui64 = srsp->srs_count;

	kmem_free(freq, sizeof (unsigned int) * sip->si_nalloc);

	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	return (rc);
}

static int
sfxge_rx_scale_kstat_init(sfxge_t *sp)
{
	dev_info_t *dip = sp->s_dip;
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	sfxge_intr_t *sip = &(sp->s_intr);
	char name[MAXNAMELEN];
	kstat_t *ksp;
	kstat_named_t *knp;
	unsigned int index;
	int rc;

	/* Create the set */
	(void) snprintf(name, MAXNAMELEN - 1, "%s_rss", ddi_driver_name(dip));

	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "rss", KSTAT_TYPE_NAMED,
	    sip->si_nalloc + 1, 0)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	srsp->srs_ksp = ksp;

	ksp->ks_update = sfxge_rx_scale_kstat_update;
	ksp->ks_private = sp;
	ksp->ks_lock = &(srsp->srs_lock);

	/* Initialise the named stats */
	knp = ksp->ks_data;
	for (index = 0; index < sip->si_nalloc; index++) {
		char name[MAXNAMELEN];

		(void) snprintf(name, MAXNAMELEN - 1, "evq%04d_count", index);
		kstat_named_init(knp, name, KSTAT_DATA_UINT64);
		knp++;
	}

	kstat_named_init(knp, "scale", KSTAT_DATA_UINT64);

	kstat_install(ksp);
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_rx_scale_kstat_fini(sfxge_t *sp)
{
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);

	/* Destroy the set */
	kstat_delete(srsp->srs_ksp);
	srsp->srs_ksp = NULL;
}


unsigned int
sfxge_rx_scale_prop_get(sfxge_t *sp)
{
	int rx_scale;

	rx_scale = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "rx_scale_count", SFXGE_RX_SCALE_MAX);
	/* 0 and all -ve numbers sets to number of logical CPUs */
	if (rx_scale <= 0)
		rx_scale = ncpus;

	return (rx_scale);
}


static int
sfxge_rx_scale_init(sfxge_t *sp)
{
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	sfxge_intr_t *sip = &(sp->s_intr);
	int rc;

	ASSERT3U(srsp->srs_state, ==, SFXGE_RX_SCALE_UNINITIALIZED);

	/* Create tables for CPU, core, cache and chip counts */
	srsp->srs_cpu = kmem_zalloc(sizeof (unsigned int) * NCPU, KM_SLEEP);

	mutex_init(&(srsp->srs_lock), NULL, MUTEX_DRIVER, NULL);

	/* We need at least one event queue */
	srsp->srs_count = sfxge_rx_scale_prop_get(sp);
	if (srsp->srs_count > sip->si_nalloc)
		srsp->srs_count = sip->si_nalloc;
	if (srsp->srs_count < 1)
		srsp->srs_count = 1;

	/* Set up the kstats */
	if ((rc = sfxge_rx_scale_kstat_init(sp)) != 0)
		goto fail1;

	srsp->srs_state = SFXGE_RX_SCALE_INITIALIZED;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);
	mutex_destroy(&(srsp->srs_lock));

	return (rc);
}

void
sfxge_rx_scale_update(void *arg)
{
	sfxge_t *sp = arg;
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	sfxge_intr_t *sip;
	processorid_t id;
	unsigned int count;
	unsigned int *tbl;
	unsigned int *rating;
	unsigned int entry;
	int rc;

	mutex_enter(&(srsp->srs_lock));

	if (srsp->srs_state != SFXGE_RX_SCALE_STARTED) {
		rc = EFAULT;
		goto fail1;
	}

	if ((tbl =  kmem_zalloc(sizeof (unsigned int) * SFXGE_RX_SCALE_MAX,
	    KM_NOSLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	sip = &(sp->s_intr);
	if ((rating = kmem_zalloc(sizeof (unsigned int) * sip->si_nalloc,
	    KM_NOSLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail3;
	}

	mutex_enter(&cpu_lock);

	/*
	 * Substract any current CPU, core, cache and chip usage from the
	 * global contention tables.
	 */
	for (id = 0; id < NCPU; id++) {
		ASSERT3U(sfxge_cpu[id], >=, srsp->srs_cpu[id]);
		sfxge_cpu[id] -= srsp->srs_cpu[id];
		srsp->srs_cpu[id] = 0;
	}

	ASSERT(srsp->srs_count != 0);

	/* Choose as many event queues as we need */
	for (count = 0; count < srsp->srs_count; count++) {
		unsigned int index;
		sfxge_evq_t *sep;
		unsigned int choice;
		unsigned int choice_rating;

		bzero(rating, sizeof (unsigned int) * sip->si_nalloc);

		/*
		 * Rate each event queue on its global level of CPU
		 * contention.
		 */
		for (index = 0; index < sip->si_nalloc; index++) {
			sep = sp->s_sep[index];

			id = sep->se_cpu_id;
			rating[index] += sfxge_cpu[id];
		}

		/* Choose the queue with the lowest CPU contention */
		choice = 0;
		choice_rating = rating[0];

		for (index = 1; index < sip->si_nalloc; index++) {
			if (rating[index] < choice_rating) {
				choice = index;
				choice_rating = rating[index];
			}
		}

		/* Add our choice to the condensed RSS table */
		tbl[count] = choice;

		/* Add information to the global contention tables */
		sep = sp->s_sep[choice];

		id = sep->se_cpu_id;
		srsp->srs_cpu[id]++;
		sfxge_cpu[id]++;
	}

	mutex_exit(&cpu_lock);

	/* Build the expanded RSS table */
	count = 0;
	for (entry = 0; entry < SFXGE_RX_SCALE_MAX; entry++) {
		unsigned int index;

		index = tbl[count];
		count = (count + 1) % srsp->srs_count;

		srsp->srs_tbl[entry] = index;
	}

	/* Program the expanded RSS table into the hardware */
	(void) efx_rx_scale_tbl_set(sp->s_enp, srsp->srs_tbl,
	    SFXGE_RX_SCALE_MAX);

	mutex_exit(&(srsp->srs_lock));
	kmem_free(rating, sizeof (unsigned int) * sip->si_nalloc);
	kmem_free(tbl, sizeof (unsigned int) * SFXGE_RX_SCALE_MAX);
	return;

fail3:
	DTRACE_PROBE(fail3);
	kmem_free(tbl, sizeof (unsigned int) * SFXGE_RX_SCALE_MAX);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(srsp->srs_lock));
}

static int
sfxge_rx_scale_start(sfxge_t *sp)
{
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	int rc;

	mutex_enter(&(srsp->srs_lock));

	ASSERT3U(srsp->srs_state, ==, SFXGE_RX_SCALE_INITIALIZED);

	/* Clear down the RSS table */
	bzero(srsp->srs_tbl, sizeof (unsigned int) * SFXGE_RX_SCALE_MAX);

	(void) efx_rx_scale_tbl_set(sp->s_enp, srsp->srs_tbl,
	    SFXGE_RX_SCALE_MAX);

	if ((rc = sfxge_toeplitz_hash_init(sp)) != 0)
		goto fail1;

	srsp->srs_state = SFXGE_RX_SCALE_STARTED;

	mutex_exit(&(srsp->srs_lock));

	/* sfxge_t->s_state_lock held */
	(void) ddi_taskq_dispatch(sp->s_tqp, sfxge_rx_scale_update, sp,
	    DDI_SLEEP);

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(srsp->srs_lock));

	return (rc);
}

int
sfxge_rx_scale_count_get(sfxge_t *sp, unsigned int *countp)
{
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	int rc;

	mutex_enter(&(srsp->srs_lock));

	if (srsp->srs_state != SFXGE_RX_SCALE_INITIALIZED &&
	    srsp->srs_state != SFXGE_RX_SCALE_STARTED) {
		rc = ENOTSUP;
		goto fail1;
	}

	*countp = srsp->srs_count;

	mutex_exit(&(srsp->srs_lock));

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(srsp->srs_lock));

	return (rc);
}

int
sfxge_rx_scale_count_set(sfxge_t *sp, unsigned int count)
{
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	sfxge_intr_t *sip = &(sp->s_intr);
	int dispatch = 1;
	int rc;

	if (count < 1 || count > sip->si_nalloc) {
		rc = EINVAL;
		goto fail1;
	}

	mutex_enter(&(srsp->srs_lock));

	if (srsp->srs_state != SFXGE_RX_SCALE_INITIALIZED &&
	    srsp->srs_state != SFXGE_RX_SCALE_STARTED) {
		rc = ENOTSUP;
		goto fail2;
	}

	srsp->srs_count = count;

	if (srsp->srs_state != SFXGE_RX_SCALE_STARTED)
		dispatch = 0;

	mutex_exit(&(srsp->srs_lock));

	if (dispatch)
		/* no locks held */
		(void) ddi_taskq_dispatch(sp->s_tqp, sfxge_rx_scale_update, sp,
		    DDI_SLEEP);

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	mutex_exit(&(srsp->srs_lock));

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_rx_scale_stop(sfxge_t *sp)
{
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);
	processorid_t id;

	mutex_enter(&(srsp->srs_lock));

	ASSERT3U(srsp->srs_state, ==, SFXGE_RX_SCALE_STARTED);

	srsp->srs_state = SFXGE_RX_SCALE_INITIALIZED;

	mutex_enter(&cpu_lock);

	/*
	 * Substract any current CPU, core, cache and chip usage from the
	 * global contention tables.
	 */
	for (id = 0; id < NCPU; id++) {
		ASSERT3U(sfxge_cpu[id], >=, srsp->srs_cpu[id]);
		sfxge_cpu[id] -= srsp->srs_cpu[id];
		srsp->srs_cpu[id] = 0;
	}

	mutex_exit(&cpu_lock);

	/* Clear down the RSS table */
	bzero(srsp->srs_tbl, sizeof (unsigned int) * SFXGE_RX_SCALE_MAX);

	(void) efx_rx_scale_tbl_set(sp->s_enp, srsp->srs_tbl,
	    SFXGE_RX_SCALE_MAX);

	mutex_exit(&(srsp->srs_lock));
}

static void
sfxge_rx_scale_fini(sfxge_t *sp)
{
	sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);

	ASSERT3U(srsp->srs_state, ==, SFXGE_RX_SCALE_INITIALIZED);

	srsp->srs_state = SFXGE_RX_SCALE_UNINITIALIZED;

	/* Tear down the kstats */
	sfxge_rx_scale_kstat_fini(sp);

	srsp->srs_count = 0;

	mutex_destroy(&(srsp->srs_lock));

	/* Destroy tables */
	kmem_free(srsp->srs_cpu, sizeof (unsigned int) * NCPU);
	srsp->srs_cpu = NULL;

	sfxge_toeplitz_hash_fini(sp);
}

int
sfxge_rx_init(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	char name[MAXNAMELEN];
	int index;
	int rc;

	if (sip->si_state == SFXGE_INTR_UNINITIALIZED) {
		rc = EINVAL;
		goto fail1;
	}

	if ((rc = sfxge_rx_scale_init(sp)) != 0)
		goto fail2;

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_rx_packet_cache",
	    ddi_driver_name(sp->s_dip), ddi_get_instance(sp->s_dip));

	sp->s_rpc = kmem_cache_create(name, sizeof (sfxge_rx_packet_t),
	    SFXGE_CPU_CACHE_SIZE, sfxge_rx_packet_ctor, sfxge_rx_packet_dtor,
	    NULL, sp, NULL, 0);
	ASSERT(sp->s_rpc != NULL);

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_rxq_cache",
	    ddi_driver_name(sp->s_dip), ddi_get_instance(sp->s_dip));

	sp->s_rqc = kmem_cache_create(name, sizeof (sfxge_rxq_t),
	    SFXGE_CPU_CACHE_SIZE, sfxge_rx_qctor, sfxge_rx_qdtor, NULL, sp,
	    NULL, 0);
	ASSERT(sp->s_rqc != NULL);

	sp->s_rx_pkt_mem_max = ddi_prop_get_int64(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "rx_pkt_mem_max", 0); /* disabled */

	/* Initialize the receive queue(s) */
	for (index = 0; index < sip->si_nalloc; index++) {
		if ((rc = sfxge_rx_qinit(sp, index)) != 0)
			goto fail3;
	}

	sp->s_rx_coalesce_mode = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "rx_coalesce_mode", SFXGE_RX_COALESCE_OFF);

	return (0);

fail3:
	DTRACE_PROBE(fail3);

	/* Tear down the receive queue(s) */
	while (--index >= 0)
		sfxge_rx_qfini(sp, index);

	kmem_cache_destroy(sp->s_rqc);
	sp->s_rqc = NULL;

	kmem_cache_destroy(sp->s_rpc);
	sp->s_rpc = NULL;

	sfxge_rx_scale_fini(sp);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

int
sfxge_rx_start(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	sfxge_intr_t *sip;
	const efx_nic_cfg_t *encp;
	size_t hdrlen, align;
	int index;
	int rc;

	mutex_enter(&(smp->sm_lock));

	/* Calculate the receive packet buffer size and alignment */
	sp->s_rx_buffer_size = EFX_MAC_PDU(sp->s_mtu);

	encp = efx_nic_cfg_get(sp->s_enp);

	/* Packet buffer allocations are cache line aligned */
	EFSYS_ASSERT3U(encp->enc_rx_buf_align_start, <=, SFXGE_CPU_CACHE_SIZE);

	if (sp->s_family == EFX_FAMILY_HUNTINGTON) {
		sp->s_rx_prefix_size = encp->enc_rx_prefix_size;

		hdrlen = sp->s_rx_prefix_size + sizeof (struct ether_header);

		/* Ensure IP headers are 32bit aligned */
		sp->s_rx_buffer_align = P2ROUNDUP(hdrlen, 4) - hdrlen;
		sp->s_rx_buffer_size += sp->s_rx_buffer_align;

	} else if (encp->enc_features & EFX_FEATURE_LFSR_HASH_INSERT) {
		sp->s_rx_prefix_size = encp->enc_rx_prefix_size;

		/*
		 * Place the start of the buffer a prefix length minus 2
		 * before the start of a cache line. This ensures that the
		 * last two bytes of the prefix (which is where the LFSR hash
		 * is located) are in the same cache line as the headers, and
		 * the IP header is 32-bit aligned.
		 */
		sp->s_rx_buffer_align =
		    SFXGE_CPU_CACHE_SIZE - (encp->enc_rx_prefix_size - 2);
		sp->s_rx_buffer_size += sp->s_rx_buffer_align;
	} else {
		sp->s_rx_prefix_size = 0;

		/*
		 * Place the start of the buffer 2 bytes after a cache line
		 * boundary so that the headers fit into the cache line and
		 * the IP header is 32-bit aligned.
		 */
		hdrlen = sp->s_rx_prefix_size + sizeof (struct ether_header);

		sp->s_rx_buffer_align = P2ROUNDUP(hdrlen, 4) - hdrlen;
		sp->s_rx_buffer_size += sp->s_rx_buffer_align;
	}

	/* Align end of packet buffer for RX DMA end padding */
	align = MAX(1, encp->enc_rx_buf_align_end);
	EFSYS_ASSERT(ISP2(align));
	sp->s_rx_buffer_size = P2ROUNDUP(sp->s_rx_buffer_size, align);

	/* Initialize the receive module */
	if ((rc = efx_rx_init(sp->s_enp)) != 0)
		goto fail1;

	mutex_exit(&(smp->sm_lock));

	if ((rc = sfxge_rx_scale_start(sp)) != 0)
		goto fail2;

	/* Start the receive queue(s) */
	sip = &(sp->s_intr);
	for (index = 0; index < sip->si_nalloc; index++) {
		if ((rc = sfxge_rx_qstart(sp, index)) != 0)
			goto fail3;
	}

	ASSERT3U(sp->s_srp[0]->sr_state, ==, SFXGE_RXQ_STARTED);
	/* It is sufficient to have Rx scale initialized */
	ASSERT3U(sp->s_rx_scale.srs_state, ==, SFXGE_RX_SCALE_STARTED);
	rc = efx_mac_filter_default_rxq_set(sp->s_enp, sp->s_srp[0]->sr_erp,
	    sp->s_rx_scale.srs_count > 1);
	if (rc != 0)
		goto fail4;

	return (0);

fail4:
	DTRACE_PROBE(fail4);

fail3:
	DTRACE_PROBE(fail3);

	/* Stop the receive queue(s) */
	while (--index >= 0)
		sfxge_rx_qstop(sp, index);

	sfxge_rx_scale_stop(sp);

fail2:
	DTRACE_PROBE(fail2);

	mutex_enter(&(smp->sm_lock));

	/* Tear down the receive module */
	efx_rx_fini(sp->s_enp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(smp->sm_lock));

	return (rc);
}

void
sfxge_rx_coalesce_mode_get(sfxge_t *sp, sfxge_rx_coalesce_mode_t *modep)
{
	*modep = sp->s_rx_coalesce_mode;
}

int
sfxge_rx_coalesce_mode_set(sfxge_t *sp, sfxge_rx_coalesce_mode_t mode)
{
	int rc;

	switch (mode) {
	case SFXGE_RX_COALESCE_OFF:
	case SFXGE_RX_COALESCE_DISALLOW_PUSH:
	case SFXGE_RX_COALESCE_ALLOW_PUSH:
		break;

	default:
		rc = EINVAL;
		goto fail1;
	}

	sp->s_rx_coalesce_mode = mode;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

void
sfxge_rx_stop(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	sfxge_intr_t *sip = &(sp->s_intr);
	efx_nic_t *enp = sp->s_enp;
	int index;

	ASSERT(mutex_owned(&(sp->s_state_lock)));

	efx_mac_filter_default_rxq_clear(enp);

	/* Stop the receive queue(s) */
	index = sip->si_nalloc;
	while (--index >= 0) {
		/* TBD: Flush RXQs in parallel; HW has limit + may need retry */
		sfxge_rx_qstop(sp, index);
	}

	sfxge_rx_scale_stop(sp);

	mutex_enter(&(smp->sm_lock));

	/* Tear down the receive module */
	efx_rx_fini(enp);

	sp->s_rx_buffer_align = 0;
	sp->s_rx_prefix_size = 0;
	sp->s_rx_buffer_size = 0;

	mutex_exit(&(smp->sm_lock));
}

unsigned int
sfxge_rx_loaned(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	int index;
	unsigned int loaned;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_INITIALIZED);

	loaned = 0;
	for (index = 0; index < sip->si_nalloc; index++) {
		sfxge_rxq_t *srp = sp->s_srp[index];
		sfxge_evq_t *sep = sp->s_sep[srp->sr_index];

		mutex_enter(&(sep->se_lock));

		loaned += sfxge_rx_qfpp_swizzle(srp);

		mutex_exit(&(sep->se_lock));
	}

	return (loaned);
}

void
sfxge_rx_fini(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	int index;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_INITIALIZED);

	sp->s_rx_coalesce_mode = SFXGE_RX_COALESCE_OFF;

	/* Tear down the receive queue(s) */
	index = sip->si_nalloc;
	while (--index >= 0)
		sfxge_rx_qfini(sp, index);

	ASSERT3U(sp->s_rx_pkt_mem_alloc, ==, 0);

	kmem_cache_destroy(sp->s_rqc);
	sp->s_rqc = NULL;

	kmem_cache_destroy(sp->s_rpc);
	sp->s_rpc = NULL;

	sfxge_rx_scale_fini(sp);
}
