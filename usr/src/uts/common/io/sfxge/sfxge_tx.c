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
#include <sys/pattr.h>
#include <sys/cpu.h>

#include <sys/ethernet.h>
#include <inet/ip.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sfxge.h"

#include "efx.h"

/* TXQ flush response timeout (in microseconds) */
#define	SFXGE_TX_QFLUSH_USEC	(2000000)

/* See sfxge.conf.private for descriptions */
#define	SFXGE_TX_DPL_GET_PKT_LIMIT_DEFAULT 4096
#define	SFXGE_TX_DPL_PUT_PKT_LIMIT_DEFAULT 256


/* Transmit buffer DMA attributes */
static ddi_device_acc_attr_t sfxge_tx_buffer_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_tx_buffer_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version	*/
	0,			/* dma_attr_addr_lo	*/
	0xffffffffffffffffull,	/* dma_attr_addr_hi	*/
	0xffffffffffffffffull,	/* dma_attr_count_max	*/
	SFXGE_TX_BUFFER_SIZE,	/* dma_attr_align	*/
	0xffffffff,		/* dma_attr_burstsizes	*/
	1,			/* dma_attr_minxfer	*/
	0xffffffffffffffffull,	/* dma_attr_maxxfer	*/
	0xffffffffffffffffull,	/* dma_attr_seg		*/
	1,			/* dma_attr_sgllen	*/
	1,			/* dma_attr_granular	*/
	0			/* dma_attr_flags	*/
};

/* Transmit mapping DMA attributes */
static ddi_dma_attr_t sfxge_tx_mapping_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version	*/
	0,			/* dma_attr_addr_lo	*/
	0xffffffffffffffffull,	/* dma_attr_addr_hi	*/
	0xffffffffffffffffull,	/* dma_attr_count_max	*/
	1,			/* dma_attr_align	*/
	0xffffffff,		/* dma_attr_burstsizes	*/
	1,			/* dma_attr_minxfer	*/
	0xffffffffffffffffull,	/* dma_attr_maxxfer	*/
	0xffffffffffffffffull,	/* dma_attr_seg		*/
	0x7fffffff,		/* dma_attr_sgllen	*/
	1,			/* dma_attr_granular	*/
	0			/* dma_attr_flags	*/
};

/* Transmit queue DMA attributes */
static ddi_device_acc_attr_t sfxge_txq_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_txq_dma_attr = {
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


/*
 * A sfxge_tx_qdpl_swizzle() can happen when the DPL get list is one packet
 * under the limit, and must move all packets from the DPL put->get list
 * Hence this is the real maximum length of the TX DPL get list.
 */
static int
sfxge_tx_dpl_get_pkt_max(sfxge_txq_t *stp)
{
	sfxge_tx_dpl_t *stdp = &(stp->st_dpl);
	return (stdp->get_pkt_limit + stdp->put_pkt_limit - 1);
}


static int
sfxge_tx_packet_ctor(void *buf, void *arg, int kmflags)
{
	_NOTE(ARGUNUSED(arg, kmflags))

	bzero(buf, sizeof (sfxge_tx_packet_t));

	return (0);
}

static void
sfxge_tx_packet_dtor(void *buf, void *arg)
{
	sfxge_tx_packet_t *stpp = buf;

	_NOTE(ARGUNUSED(arg))

	SFXGE_OBJ_CHECK(stpp, sfxge_tx_packet_t);
}

static int
sfxge_tx_buffer_ctor(void *buf, void *arg, int kmflags)
{
	sfxge_tx_buffer_t *stbp = buf;
	sfxge_t *sp = arg;
	sfxge_dma_buffer_attr_t dma_attr;
	int rc;

	bzero(buf, sizeof (sfxge_tx_buffer_t));

	dma_attr.sdba_dip	 = sp->s_dip;
	dma_attr.sdba_dattrp	 = &sfxge_tx_buffer_dma_attr;
	dma_attr.sdba_callback	 = ((kmflags == KM_SLEEP) ?
	    DDI_DMA_SLEEP : DDI_DMA_DONTWAIT);
	dma_attr.sdba_length	 = SFXGE_TX_BUFFER_SIZE;
	dma_attr.sdba_memflags	 = DDI_DMA_STREAMING;
	dma_attr.sdba_devaccp	 = &sfxge_tx_buffer_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_WRITE | DDI_DMA_STREAMING;
	dma_attr.sdba_maxcookies = 1;
	dma_attr.sdba_zeroinit	 = B_FALSE;

	if ((rc = sfxge_dma_buffer_create(&(stbp->stb_esm), &dma_attr)) != 0)
		goto fail1;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	SFXGE_OBJ_CHECK(stbp, sfxge_tx_buffer_t);

	return (-1);
}

static void
sfxge_tx_buffer_dtor(void *buf, void *arg)
{
	sfxge_tx_buffer_t *stbp = buf;

	_NOTE(ARGUNUSED(arg))

	sfxge_dma_buffer_destroy(&(stbp->stb_esm));

	SFXGE_OBJ_CHECK(stbp, sfxge_tx_buffer_t);
}

static int
sfxge_tx_mapping_ctor(void *buf, void *arg, int kmflags)
{
	sfxge_tx_mapping_t *stmp = buf;
	sfxge_t *sp = arg;
	dev_info_t *dip = sp->s_dip;
	int rc;

	bzero(buf, sizeof (sfxge_tx_mapping_t));

	stmp->stm_sp = sp;

	/* Allocate DMA handle */
	rc = ddi_dma_alloc_handle(dip, &sfxge_tx_mapping_dma_attr,
	    (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT,
	    NULL, &(stmp->stm_dma_handle));
	if (rc != DDI_SUCCESS)
		goto fail1;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	stmp->stm_sp = NULL;

	SFXGE_OBJ_CHECK(stmp, sfxge_tx_mapping_t);

	return (-1);
}

static void
sfxge_tx_mapping_dtor(void *buf, void *arg)
{
	sfxge_tx_mapping_t *stmp = buf;

	ASSERT3P(stmp->stm_sp, ==, arg);

	/* Free the DMA handle */
	ddi_dma_free_handle(&(stmp->stm_dma_handle));
	stmp->stm_dma_handle = NULL;

	stmp->stm_sp = NULL;

	SFXGE_OBJ_CHECK(stmp, sfxge_tx_mapping_t);
}

static int
sfxge_tx_qctor(void *buf, void *arg, int kmflags)
{
	sfxge_txq_t *stp = buf;
	efsys_mem_t *esmp = &(stp->st_mem);
	sfxge_t *sp = arg;
	sfxge_dma_buffer_attr_t dma_attr;
	sfxge_tx_dpl_t *stdp;
	int rc;

	/* Compile-time structure layout checks */
	EFX_STATIC_ASSERT(sizeof (stp->__st_u1.__st_s1) <=
	    sizeof (stp->__st_u1.__st_pad));
	EFX_STATIC_ASSERT(sizeof (stp->__st_u2.__st_s2) <=
	    sizeof (stp->__st_u2.__st_pad));
	EFX_STATIC_ASSERT(sizeof (stp->__st_u3.__st_s3) <=
	    sizeof (stp->__st_u3.__st_pad));
	EFX_STATIC_ASSERT(sizeof (stp->__st_u4.__st_s4) <=
	    sizeof (stp->__st_u4.__st_pad));

	bzero(buf, sizeof (sfxge_txq_t));

	stp->st_sp = sp;

	dma_attr.sdba_dip	 = sp->s_dip;
	dma_attr.sdba_dattrp	 = &sfxge_txq_dma_attr;
	dma_attr.sdba_callback	 = DDI_DMA_SLEEP;
	dma_attr.sdba_length	 = EFX_TXQ_SIZE(SFXGE_TX_NDESCS);
	dma_attr.sdba_memflags	 = DDI_DMA_CONSISTENT;
	dma_attr.sdba_devaccp	 = &sfxge_txq_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_READ | DDI_DMA_CONSISTENT;
	dma_attr.sdba_maxcookies = EFX_TXQ_NBUFS(SFXGE_TX_NDESCS);
	dma_attr.sdba_zeroinit	 = B_FALSE;

	if ((rc = sfxge_dma_buffer_create(esmp, &dma_attr)) != 0)
		goto fail1;

	/* Allocate some buffer table entries */
	if ((rc = sfxge_sram_buf_tbl_alloc(sp, EFX_TXQ_NBUFS(SFXGE_TX_NDESCS),
	    &(stp->st_id))) != 0)
		goto fail2;

	/* Allocate the descriptor array */
	if ((stp->st_eb = kmem_zalloc(sizeof (efx_buffer_t) *
	    EFX_TXQ_LIMIT(SFXGE_TX_NDESCS), kmflags)) == NULL) {
		rc = ENOMEM;
		goto fail3;
	}

	/* Allocate the context arrays */
	if ((stp->st_stmp = kmem_zalloc(sizeof (sfxge_tx_mapping_t *) *
	    SFXGE_TX_NDESCS, kmflags)) == NULL) {
		rc = ENOMEM;
		goto fail4;
	}

	if ((stp->st_stbp = kmem_zalloc(sizeof (sfxge_tx_buffer_t *) *
	    SFXGE_TX_NDESCS, kmflags)) == NULL) {
		rc = ENOMEM;
		goto fail5;
	}

	if ((stp->st_mp = kmem_zalloc(sizeof (mblk_t *) *
	    SFXGE_TX_NDESCS, kmflags)) == NULL) {
		rc = ENOMEM;
		goto fail6;
	}

	/* Initialize the deferred packet list */
	stdp = &(stp->st_dpl);
	stdp->std_getp = &(stdp->std_get);

	stp->st_unblock = SFXGE_TXQ_NOT_BLOCKED;

	return (0);

fail6:
	DTRACE_PROBE(fail6);

	kmem_free(stp->st_stbp, sizeof (sfxge_tx_buffer_t *) * SFXGE_TX_NDESCS);
	stp->st_stbp = NULL;

fail5:
	DTRACE_PROBE(fail5);

	kmem_free(stp->st_stmp,
	    sizeof (sfxge_tx_mapping_t *) * SFXGE_TX_NDESCS);
	stp->st_stmp = NULL;

fail4:
	DTRACE_PROBE(fail4);

	/* Free the descriptor array */
	kmem_free(stp->st_eb, sizeof (efx_buffer_t) *
	    EFX_TXQ_LIMIT(SFXGE_TX_NDESCS));
	stp->st_eb = NULL;

fail3:
	DTRACE_PROBE(fail3);

	/* Free the buffer table entries */
	sfxge_sram_buf_tbl_free(sp, stp->st_id, EFX_TXQ_NBUFS(SFXGE_TX_NDESCS));
	stp->st_id = 0;

fail2:
	DTRACE_PROBE(fail2);

	/* Tear down DMA setup */
	sfxge_dma_buffer_destroy(esmp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	stp->st_sp = NULL;

	SFXGE_OBJ_CHECK(stp, sfxge_txq_t);

	return (-1);
}

static void
sfxge_tx_qdtor(void *buf, void *arg)
{
	sfxge_txq_t *stp = buf;
	efsys_mem_t *esmp = &(stp->st_mem);
	sfxge_t *sp = stp->st_sp;
	sfxge_tx_dpl_t *stdp;

	_NOTE(ARGUNUSED(arg))

	stp->st_unblock = 0;

	/* Tear down the deferred packet list */
	stdp = &(stp->st_dpl);
	ASSERT3P(stdp->std_getp, ==, &(stdp->std_get));
	stdp->std_getp = NULL;

	/* Free the context arrays */
	kmem_free(stp->st_mp, sizeof (mblk_t *) * SFXGE_TX_NDESCS);
	stp->st_mp = NULL;

	kmem_free(stp->st_stbp, sizeof (sfxge_tx_buffer_t *) * SFXGE_TX_NDESCS);
	stp->st_stbp = NULL;

	kmem_free(stp->st_stmp,
	    sizeof (sfxge_tx_mapping_t *) * SFXGE_TX_NDESCS);
	stp->st_stmp = NULL;

	/* Free the descriptor array */
	kmem_free(stp->st_eb, sizeof (efx_buffer_t) *
	    EFX_TXQ_LIMIT(SFXGE_TX_NDESCS));
	stp->st_eb = NULL;

	/* Free the buffer table entries */
	sfxge_sram_buf_tbl_free(sp, stp->st_id, EFX_TXQ_NBUFS(SFXGE_TX_NDESCS));
	stp->st_id = 0;

	/* Tear down dma setup */
	sfxge_dma_buffer_destroy(esmp);

	stp->st_sp = NULL;

	SFXGE_OBJ_CHECK(stp, sfxge_txq_t);
}

static void
sfxge_tx_packet_destroy(sfxge_t *sp, sfxge_tx_packet_t *stpp)
{
	kmem_cache_free(sp->s_tpc, stpp);
}

static sfxge_tx_packet_t *
sfxge_tx_packet_create(sfxge_t *sp)
{
	sfxge_tx_packet_t *stpp;

	stpp = kmem_cache_alloc(sp->s_tpc, KM_NOSLEEP);

	return (stpp);
}

static inline int
sfxge_tx_qfpp_put(sfxge_txq_t *stp, sfxge_tx_packet_t *stpp)
{
	sfxge_tx_fpp_t *stfp = &(stp->st_fpp);

	ASSERT(mutex_owned(&(stp->st_lock)));

	ASSERT3P(stpp->stp_next, ==, NULL);
	ASSERT3P(stpp->stp_mp, ==, NULL);
	ASSERT3P(stpp->stp_etherhp, ==, NULL);
	ASSERT3P(stpp->stp_iphp, ==, NULL);
	ASSERT3P(stpp->stp_thp, ==, NULL);
	ASSERT3U(stpp->stp_off, ==, 0);
	ASSERT3U(stpp->stp_size, ==, 0);
	ASSERT3U(stpp->stp_mss, ==, 0);
	ASSERT3U(stpp->stp_dpl_put_len, ==, 0);

	if (stfp->stf_count < SFXGE_TX_FPP_MAX) {
		/* Add to the start of the list */
		stpp->stp_next = stfp->stf_stpp;
		stfp->stf_stpp = stpp;
		stfp->stf_count++;

		return (0);
	}

	DTRACE_PROBE(fpp_full);
	return (ENOSPC);
}

static inline sfxge_tx_packet_t *
sfxge_tx_qfpp_get(sfxge_txq_t *stp)
{
	sfxge_tx_packet_t *stpp;
	sfxge_tx_fpp_t *stfp = &(stp->st_fpp);

	ASSERT(mutex_owned(&(stp->st_lock)));

	stpp = stfp->stf_stpp;
	if (stpp == NULL) {
		ASSERT3U(stfp->stf_count, ==, 0);
		return (NULL);
	}

	/* Remove item from the head of the list */
	stfp->stf_stpp = stpp->stp_next;
	stpp->stp_next = NULL;

	ASSERT3U(stfp->stf_count, >, 0);
	stfp->stf_count--;

	if (stfp->stf_count != 0) {
		ASSERT(stfp->stf_stpp != NULL);
		prefetch_read_many(stfp->stf_stpp);
	}
	return (stpp);
}

static void
sfxge_tx_qfpp_empty(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	sfxge_tx_fpp_t *stfp = &(stp->st_fpp);
	sfxge_tx_packet_t *stpp;

	mutex_enter(&(stp->st_lock));

	stpp = stfp->stf_stpp;
	stfp->stf_stpp = NULL;

	while (stpp != NULL) {
		sfxge_tx_packet_t *next;

		next = stpp->stp_next;
		stpp->stp_next = NULL;

		ASSERT3U(stfp->stf_count, >, 0);
		stfp->stf_count--;

		sfxge_tx_packet_destroy(sp, stpp);

		stpp = next;
	}
	ASSERT3U(stfp->stf_count, ==, 0);

	mutex_exit(&(stp->st_lock));
}

static inline void
sfxge_tx_qfbp_put(sfxge_txq_t *stp, sfxge_tx_buffer_t *stbp)
{
	sfxge_tx_fbp_t *stfp = &(stp->st_fbp);

	ASSERT3P(stbp->stb_next, ==, NULL);
	ASSERT3U(stbp->stb_off, ==, 0);
	ASSERT3U(stbp->stb_esm.esm_used, ==, 0);

	stbp->stb_next = stfp->stf_stbp;
	stfp->stf_stbp = stbp;
	stfp->stf_count++;
}


static inline sfxge_tx_buffer_t *
sfxge_tx_qfbp_get(sfxge_txq_t *stp)
{
	sfxge_tx_buffer_t *stbp;
	sfxge_tx_fbp_t *stfp = &(stp->st_fbp);

	stbp = stfp->stf_stbp;
	if (stbp == NULL) {
		ASSERT3U(stfp->stf_count, ==, 0);
		return (NULL);
	}

	stfp->stf_stbp = stbp->stb_next;
	stbp->stb_next = NULL;

	ASSERT3U(stfp->stf_count, >, 0);
	stfp->stf_count--;

	if (stfp->stf_count != 0) {
		ASSERT(stfp->stf_stbp != NULL);
		prefetch_read_many(stfp->stf_stbp);
	}

	return (stbp);
}

static void
sfxge_tx_qfbp_empty(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	sfxge_tx_fbp_t *stfp = &(stp->st_fbp);
	sfxge_tx_buffer_t *stbp;

	mutex_enter(&(stp->st_lock));

	stbp = stfp->stf_stbp;
	stfp->stf_stbp = NULL;

	while (stbp != NULL) {
		sfxge_tx_buffer_t *next;

		next = stbp->stb_next;
		stbp->stb_next = NULL;

		ASSERT3U(stfp->stf_count, >, 0);
		stfp->stf_count--;

		kmem_cache_free(sp->s_tbc, stbp);

		stbp = next;
	}
	ASSERT3U(stfp->stf_count, ==, 0);

	mutex_exit(&(stp->st_lock));
}

static inline void
sfxge_tx_qfmp_put(sfxge_txq_t *stp, sfxge_tx_mapping_t *stmp)
{
	sfxge_tx_fmp_t *stfp = &(stp->st_fmp);

	ASSERT3P(stmp->stm_next, ==, NULL);
	ASSERT3P(stmp->stm_mp, ==, NULL);
	ASSERT3P(stmp->stm_base, ==, NULL);
	ASSERT3U(stmp->stm_off, ==, 0);
	ASSERT3U(stmp->stm_size, ==, 0);

	stmp->stm_next = stfp->stf_stmp;
	stfp->stf_stmp = stmp;
	stfp->stf_count++;
}

static inline sfxge_tx_mapping_t *
sfxge_tx_qfmp_get(sfxge_txq_t *stp)
{
	sfxge_tx_mapping_t *stmp;
	sfxge_tx_fmp_t *stfp = &(stp->st_fmp);

	stmp = stfp->stf_stmp;
	if (stmp == NULL) {
		ASSERT3U(stfp->stf_count, ==, 0);
		return (NULL);
	}

	stfp->stf_stmp = stmp->stm_next;
	stmp->stm_next = NULL;

	ASSERT3U(stfp->stf_count, >, 0);
	stfp->stf_count--;

	if (stfp->stf_count != 0) {
		ASSERT(stfp->stf_stmp != NULL);
		prefetch_read_many(stfp->stf_stmp);
	}
	return (stmp);
}

static void
sfxge_tx_qfmp_empty(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	sfxge_tx_fmp_t *stfp = &(stp->st_fmp);
	sfxge_tx_mapping_t *stmp;

	mutex_enter(&(stp->st_lock));

	stmp = stfp->stf_stmp;
	stfp->stf_stmp = NULL;

	while (stmp != NULL) {
		sfxge_tx_mapping_t *next;

		next = stmp->stm_next;
		stmp->stm_next = NULL;

		ASSERT3U(stfp->stf_count, >, 0);
		stfp->stf_count--;

		kmem_cache_free(sp->s_tmc, stmp);

		stmp = next;
	}
	ASSERT3U(stfp->stf_count, ==, 0);

	mutex_exit(&(stp->st_lock));
}

static void
sfxge_tx_msgb_unbind(sfxge_tx_mapping_t *stmp)
{
	bzero(stmp->stm_addr, sizeof (uint64_t) * SFXGE_TX_MAPPING_NADDR);
	stmp->stm_off = 0;

	(void) ddi_dma_unbind_handle(stmp->stm_dma_handle);

	stmp->stm_size = 0;
	stmp->stm_base = NULL;

	stmp->stm_mp = NULL;
}

#define	SFXGE_TX_DESCSHIFT	12
#define	SFXGE_TX_DESCSIZE	(1 << 12)

#define	SFXGE_TX_DESCOFFSET	(SFXGE_TX_DESCSIZE - 1)
#define	SFXGE_TX_DESCMASK	(~SFXGE_TX_DESCOFFSET)

static int
sfxge_tx_msgb_bind(mblk_t *mp, sfxge_tx_mapping_t *stmp)
{
	ddi_dma_cookie_t dmac;
	unsigned int ncookies;
	size_t size;
	unsigned int n;
	int rc;

	ASSERT(mp != NULL);
	ASSERT3U(DB_TYPE(mp), ==, M_DATA);

	ASSERT(stmp->stm_mp == NULL);
	stmp->stm_mp = mp;

	stmp->stm_base = (caddr_t)(mp->b_rptr);
	stmp->stm_size = MBLKL(mp);

	/* Bind the STREAMS block to the mapping */
	rc = ddi_dma_addr_bind_handle(stmp->stm_dma_handle, NULL,
	    stmp->stm_base, stmp->stm_size, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, &dmac, &ncookies);
	if (rc != DDI_DMA_MAPPED)
		goto fail1;

	ASSERT3U(ncookies, <=, SFXGE_TX_MAPPING_NADDR);

	/*
	 * Construct an array of addresses and an initial
	 * offset.
	 */
	n = 0;
	stmp->stm_addr[n++] = dmac.dmac_laddress & SFXGE_TX_DESCMASK;
	DTRACE_PROBE1(addr, uint64_t, dmac.dmac_laddress & SFXGE_TX_DESCMASK);

	stmp->stm_off = dmac.dmac_laddress & SFXGE_TX_DESCOFFSET;

	size = MIN(SFXGE_TX_DESCSIZE - stmp->stm_off, dmac.dmac_size);
	dmac.dmac_laddress += size;
	dmac.dmac_size -= size;

	for (;;) {
		ASSERT3U(n, <, SFXGE_TX_MAPPING_NADDR);

		if (dmac.dmac_size == 0) {
			if (--ncookies == 0)
				break;

			ddi_dma_nextcookie(stmp->stm_dma_handle, &dmac);
		}

		ASSERT((dmac.dmac_laddress & SFXGE_TX_DESCMASK) != 0);
		ASSERT((dmac.dmac_laddress & SFXGE_TX_DESCOFFSET) == 0);
		stmp->stm_addr[n++] = dmac.dmac_laddress;
		DTRACE_PROBE1(addr, uint64_t, dmac.dmac_laddress);

		size = MIN(SFXGE_TX_DESCSIZE, dmac.dmac_size);
		dmac.dmac_laddress += size;
		dmac.dmac_size -= size;
	}
	ASSERT3U(n, <=, SFXGE_TX_MAPPING_NADDR);

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	stmp->stm_size = 0;
	stmp->stm_base = NULL;

	stmp->stm_mp = NULL;

	return (-1);
}

static void
sfxge_tx_qreap(sfxge_txq_t *stp)
{
	unsigned int reaped;

	ASSERT(mutex_owned(&(stp->st_lock)));

	reaped = stp->st_reaped;
	while (reaped != stp->st_completed) {
		unsigned int id;
		sfxge_tx_mapping_t *stmp;
		sfxge_tx_buffer_t *stbp;

		id = reaped++ & (SFXGE_TX_NDESCS - 1);

		ASSERT3P(stp->st_mp[id], ==, NULL);

		if ((stmp = stp->st_stmp[id]) != NULL) {
			stp->st_stmp[id] = NULL;

			/* Free all the mappings */
			do {
				sfxge_tx_mapping_t *next;

				next = stmp->stm_next;
				stmp->stm_next = NULL;

				sfxge_tx_qfmp_put(stp, stmp);

				stmp = next;
			} while (stmp != NULL);
		}

		if ((stbp = stp->st_stbp[id]) != NULL) {
			stp->st_stbp[id] = NULL;

			/* Free all the buffers */
			do {
				sfxge_tx_buffer_t *next;

				next = stbp->stb_next;
				stbp->stb_next = NULL;

				stbp->stb_esm.esm_used = 0;
				stbp->stb_off = 0;

				sfxge_tx_qfbp_put(stp, stbp);

				stbp = next;
			} while (stbp != NULL);
		}
	}
	stp->st_reaped = reaped;
}

static void
sfxge_tx_qlist_abort(sfxge_txq_t *stp)
{
	unsigned int id;
	sfxge_tx_mapping_t *stmp;
	sfxge_tx_buffer_t *stbp;
	mblk_t *mp;

	ASSERT(mutex_owned(&(stp->st_lock)));

	id = stp->st_added & (SFXGE_TX_NDESCS - 1);

	/* Clear the completion information */
	stmp = stp->st_stmp[id];
	stp->st_stmp[id] = NULL;

	/* Free any mappings that were used */
	while (stmp != NULL) {
		sfxge_tx_mapping_t *next;

		next = stmp->stm_next;
		stmp->stm_next = NULL;

		if (stmp->stm_mp != NULL)
			sfxge_tx_msgb_unbind(stmp);

		sfxge_tx_qfmp_put(stp, stmp);

		stmp = next;
	}

	stbp = stp->st_stbp[id];
	stp->st_stbp[id] = NULL;

	/* Free any buffers that were used */
	while (stbp != NULL) {
		sfxge_tx_buffer_t *next;

		next = stbp->stb_next;
		stbp->stb_next = NULL;

		stbp->stb_off = 0;
		stbp->stb_esm.esm_used = 0;

		sfxge_tx_qfbp_put(stp, stbp);

		stbp = next;
	}

	mp = stp->st_mp[id];
	stp->st_mp[id] = NULL;

	if (mp != NULL)
		freemsg(mp);

	/* Clear the fragment list */
	stp->st_n = 0;
}

/* Push descriptors to the TX ring setting blocked if no space */
static void
sfxge_tx_qlist_post(sfxge_txq_t *stp)
{
	unsigned int id;
	unsigned int level;
	unsigned int available;
	int rc;

	ASSERT(mutex_owned(&(stp->st_lock)));

	ASSERT(stp->st_n != 0);

again:
	level = stp->st_added - stp->st_reaped;
	available = EFX_TXQ_LIMIT(SFXGE_TX_NDESCS) - level;

	id = stp->st_added & (SFXGE_TX_NDESCS - 1);

	if (available < stp->st_n) {
		rc = ENOSPC;
		goto fail1;
	}

	ASSERT3U(available, >=, stp->st_n);

	/* Post the fragment list */
	if ((rc = efx_tx_qpost(stp->st_etp, stp->st_eb, stp->st_n,
	    stp->st_reaped, &(stp->st_added))) != 0)
		goto fail2;

	/*
	 * If the list took more than a single descriptor then we need to
	 * to move the completion information so it is referenced by the last
	 * descriptor.
	 */
	if (((stp->st_added - 1) & (SFXGE_TX_NDESCS - 1)) != id) {
		sfxge_tx_mapping_t *stmp;
		sfxge_tx_buffer_t *stbp;
		mblk_t *mp;

		stmp = stp->st_stmp[id];
		stp->st_stmp[id] = NULL;

		stbp = stp->st_stbp[id];
		stp->st_stbp[id] = NULL;

		mp = stp->st_mp[id];
		stp->st_mp[id] = NULL;

		id = (stp->st_added - 1) & (SFXGE_TX_NDESCS - 1);

		ASSERT(stp->st_stmp[id] == NULL);
		stp->st_stmp[id] = stmp;

		ASSERT(stp->st_stbp[id] == NULL);
		stp->st_stbp[id] = stbp;

		ASSERT(stp->st_mp[id] == NULL);
		stp->st_mp[id] = mp;
	}

	/* Clear the list */
	stp->st_n = 0;

	ASSERT3U(stp->st_unblock, ==, SFXGE_TXQ_NOT_BLOCKED);
	return;

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	ASSERT(rc == ENOSPC);

	level = stp->st_added - stp->st_completed;
	available = EFX_TXQ_LIMIT(SFXGE_TX_NDESCS) - level;

	/*
	 * If there would be enough space after we've reaped any completed
	 * mappings and buffers, and we gain sufficient queue space by doing
	 * so, then reap now and try posting again.
	 */
	if (stp->st_n <= available &&
	    stp->st_completed - stp->st_reaped >= SFXGE_TX_BATCH) {
		sfxge_tx_qreap(stp);

		goto again;
	}

	/* Set the unblock level */
	if (stp->st_unblock == SFXGE_TXQ_NOT_BLOCKED) {
		stp->st_unblock = SFXGE_TXQ_UNBLOCK_LEVEL1;
	} else {
		ASSERT(stp->st_unblock == SFXGE_TXQ_UNBLOCK_LEVEL1);

		stp->st_unblock = SFXGE_TXQ_UNBLOCK_LEVEL2;
	}

	/*
	 * Avoid a race with completion interrupt handling that could leave the
	 * queue blocked.
	 *
	 * NOTE: The use of st_pending rather than st_completed is intentional
	 *	 as st_pending is updated per-event rather than per-batch and
	 *	 therefore avoids needless deferring.
	 */
	if (stp->st_pending == stp->st_added) {
		sfxge_tx_qreap(stp);

		stp->st_unblock = SFXGE_TXQ_NOT_BLOCKED;
		goto again;
	}

	ASSERT(stp->st_unblock != SFXGE_TXQ_NOT_BLOCKED);
}

static int
sfxge_tx_kstat_update(kstat_t *ksp, int rw)
{
	sfxge_txq_t *stp = ksp->ks_private;
	sfxge_tx_dpl_t *stdp = &(stp->st_dpl);
	kstat_named_t *knp;
	int rc;

	ASSERT(mutex_owned(&(stp->st_lock)));

	if (rw != KSTAT_READ) {
		rc = EACCES;
		goto fail1;
	}

	if (stp->st_state != SFXGE_TXQ_STARTED)
		goto done;

	efx_tx_qstats_update(stp->st_etp, stp->st_stat);
	knp = (kstat_named_t *)ksp->ks_data + TX_NQSTATS;
	knp->value.ui64 = stdp->get_pkt_limit;
	knp++;
	knp->value.ui64 = stdp->put_pkt_limit;
	knp++;
	knp->value.ui64 = stdp->get_full_count;
	knp++;
	knp->value.ui64 = stdp->put_full_count;

done:
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_tx_kstat_init(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	unsigned int index = stp->st_index;
	dev_info_t *dip = sp->s_dip;
	kstat_t *ksp;
	kstat_named_t *knp;
	char name[MAXNAMELEN];
	unsigned int id;
	int rc;

	/* Create the set */
	(void) snprintf(name, MAXNAMELEN - 1, "%s_txq%04d",
	    ddi_driver_name(dip), index);

	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "queue", KSTAT_TYPE_NAMED,
	    TX_NQSTATS + 4, 0)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	stp->st_ksp = ksp;

	ksp->ks_update = sfxge_tx_kstat_update;
	ksp->ks_private = stp;
	ksp->ks_lock = &(stp->st_lock);

	/* Initialise the named stats */
	stp->st_stat = knp = ksp->ks_data;
	for (id = 0; id < TX_NQSTATS; id++) {
		kstat_named_init(knp, (char *)efx_tx_qstat_name(sp->s_enp, id),
		    KSTAT_DATA_UINT64);
		knp++;
	}
	kstat_named_init(knp, "dpl_get_pkt_limit", KSTAT_DATA_UINT64);
	knp++;
	kstat_named_init(knp, "dpl_put_pkt_limit", KSTAT_DATA_UINT64);
	knp++;
	kstat_named_init(knp, "dpl_get_full_count", KSTAT_DATA_UINT64);
	knp++;
	kstat_named_init(knp, "dpl_put_full_count", KSTAT_DATA_UINT64);

	kstat_install(ksp);
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_tx_kstat_fini(sfxge_txq_t *stp)
{
	/* Destroy the set */
	kstat_delete(stp->st_ksp);
	stp->st_ksp = NULL;
	stp->st_stat = NULL;
}

static int
sfxge_tx_qinit(sfxge_t *sp, unsigned int index, sfxge_txq_type_t type,
    unsigned int evq)
{
	sfxge_txq_t *stp;
	sfxge_tx_dpl_t *stdp;
	int rc;

	ASSERT3U(index, <, EFX_ARRAY_SIZE(sp->s_stp));
	ASSERT3U(type, <, SFXGE_TXQ_NTYPES);
	ASSERT3U(evq, <, EFX_ARRAY_SIZE(sp->s_sep));

	if ((stp = kmem_cache_alloc(sp->s_tqc, KM_SLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}
	ASSERT3U(stp->st_state, ==, SFXGE_TXQ_UNINITIALIZED);

	stdp = &(stp->st_dpl);

	stp->st_index = index;
	stp->st_type = type;
	stp->st_evq = evq;

	mutex_init(&(stp->st_lock), NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sp->s_intr.si_intr_pri));

	/* Initialize the statistics */
	if ((rc = sfxge_tx_kstat_init(stp)) != 0)
		goto fail2;

	stdp->get_pkt_limit = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "tx_dpl_get_pkt_limit",
	    SFXGE_TX_DPL_GET_PKT_LIMIT_DEFAULT);

	stdp->put_pkt_limit = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "tx_dpl_put_pkt_limit",
	    SFXGE_TX_DPL_PUT_PKT_LIMIT_DEFAULT);

	/* Allocate a per-EVQ label for events from this TXQ */
	if ((rc = sfxge_ev_txlabel_alloc(sp, evq, stp, &(stp->st_label))) != 0)
		goto fail2;

	stp->st_state = SFXGE_TXQ_INITIALIZED;

	/* Attach the TXQ to the driver */
	ASSERT3P(sp->s_stp[index], ==, NULL);
	sp->s_stp[index] = stp;
	sp->s_tx_qcount++;

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	sfxge_tx_kstat_fini(stp);


	stp->st_evq = 0;
	stp->st_type = 0;
	stp->st_index = 0;

	mutex_destroy(&(stp->st_lock));

	kmem_cache_free(sp->s_tqc, stp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_tx_qstart(sfxge_t *sp, unsigned int index)
{
	sfxge_txq_t *stp = sp->s_stp[index];
	efx_nic_t *enp = sp->s_enp;
	efsys_mem_t *esmp;
	sfxge_evq_t *sep;
	unsigned int evq;
	unsigned int flags;
	unsigned int desc_index;
	int rc;

	mutex_enter(&(stp->st_lock));

	esmp = &(stp->st_mem);
	evq = stp->st_evq;
	sep = sp->s_sep[evq];

	ASSERT3U(stp->st_state, ==, SFXGE_TXQ_INITIALIZED);
	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_STARTED);

	/* Zero the memory */
	bzero(esmp->esm_base, EFX_TXQ_SIZE(SFXGE_TX_NDESCS));

	/* Program the buffer table */
	if ((rc = sfxge_sram_buf_tbl_set(sp, stp->st_id, esmp,
	    EFX_TXQ_NBUFS(SFXGE_TX_NDESCS))) != 0)
		goto fail1;

	switch (stp->st_type) {
	case SFXGE_TXQ_NON_CKSUM:
		flags = 0;
		break;

	case SFXGE_TXQ_IP_CKSUM:
		flags = EFX_TXQ_CKSUM_IPV4;
		break;

	case SFXGE_TXQ_IP_TCP_UDP_CKSUM:
		flags = EFX_TXQ_CKSUM_IPV4 | EFX_TXQ_CKSUM_TCPUDP;
		break;

	default:
		ASSERT(B_FALSE);

		flags = 0;
		break;
	}

	/* Create the transmit queue */
	if ((rc = efx_tx_qcreate(enp, index, stp->st_label, esmp,
	    SFXGE_TX_NDESCS, stp->st_id, flags, sep->se_eep,
	    &(stp->st_etp), &desc_index)) != 0)
		goto fail2;

	/* Initialise queue descriptor indexes */
	stp->st_added = desc_index;
	stp->st_pending = desc_index;
	stp->st_completed = desc_index;
	stp->st_reaped = desc_index;

	/* Enable the transmit queue */
	efx_tx_qenable(stp->st_etp);

	stp->st_state = SFXGE_TXQ_STARTED;

	mutex_exit(&(stp->st_lock));

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	/* Clear entries from the buffer table */
	sfxge_sram_buf_tbl_clear(sp, stp->st_id,
	    EFX_TXQ_NBUFS(SFXGE_TX_NDESCS));

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(stp->st_lock));

	return (rc);
}

static inline int
sfxge_tx_qmapping_add(sfxge_txq_t *stp, sfxge_tx_mapping_t *stmp,
    size_t *offp, size_t *limitp)
{
	mblk_t *mp;
	size_t mapping_off;
	size_t mapping_size;
	int rc;

	ASSERT3U(*offp, <, stmp->stm_size);
	ASSERT(*limitp != 0);

	mp = stmp->stm_mp;

	ASSERT3P(stmp->stm_base, ==, mp->b_rptr);
	ASSERT3U(stmp->stm_size, ==, MBLKL(mp));

	mapping_off = stmp->stm_off + *offp;
	mapping_size = stmp->stm_size - *offp;

	while (mapping_size != 0 && *limitp != 0) {
		size_t page =
		    mapping_off >> SFXGE_TX_DESCSHIFT;
		size_t page_off =
		    mapping_off & SFXGE_TX_DESCOFFSET;
		size_t page_size =
		    SFXGE_TX_DESCSIZE - page_off;
		efx_buffer_t *ebp;

		ASSERT3U(page, <, SFXGE_TX_MAPPING_NADDR);
		ASSERT((stmp->stm_addr[page] & SFXGE_TX_DESCMASK) != 0);

		page_size = MIN(page_size, mapping_size);
		page_size = MIN(page_size, *limitp);

		ASSERT3U(stp->st_n, <=,
		    EFX_TXQ_LIMIT(SFXGE_TX_NDESCS));
		if (stp->st_n ==
		    EFX_TXQ_LIMIT(SFXGE_TX_NDESCS)) {
			rc = ENOSPC;
			goto fail1;
		}

		ebp = &(stp->st_eb[stp->st_n++]);
		ebp->eb_addr = stmp->stm_addr[page] +
		    page_off;
		ebp->eb_size = page_size;

		*offp += page_size;
		*limitp -= page_size;

		mapping_off += page_size;
		mapping_size -= page_size;

		ebp->eb_eop = (*limitp == 0 ||
		    (mapping_size == 0 && mp->b_cont == NULL));

		DTRACE_PROBE5(tx_mapping_add,
		    unsigned int, stp->st_index,
		    unsigned int, stp->st_n - 1,
		    uint64_t, ebp->eb_addr,
		    size_t, ebp->eb_size,
		    boolean_t, ebp->eb_eop);
	}

	ASSERT3U(*offp, <=, stmp->stm_size);

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static inline int
sfxge_tx_qbuffer_add(sfxge_txq_t *stp, sfxge_tx_buffer_t *stbp, boolean_t eop)
{
	efx_buffer_t *ebp;
	int rc;

	ASSERT3U(stp->st_n, <=,
	    EFX_TXQ_LIMIT(SFXGE_TX_NDESCS));
	if (stp->st_n == EFX_TXQ_LIMIT(SFXGE_TX_NDESCS)) {
		rc = ENOSPC;
		goto fail1;
	}

	ebp = &(stp->st_eb[stp->st_n++]);
	ebp->eb_addr = stbp->stb_esm.esm_addr + stbp->stb_off;
	ebp->eb_size = stbp->stb_esm.esm_used - stbp->stb_off;
	ebp->eb_eop = eop;

	(void) ddi_dma_sync(stbp->stb_esm.esm_dma_handle,
	    stbp->stb_off, ebp->eb_size,
	    DDI_DMA_SYNC_FORDEV);

	stbp->stb_off = stbp->stb_esm.esm_used;

	DTRACE_PROBE5(tx_buffer_add,
	    unsigned int, stp->st_index,
	    unsigned int, stp->st_n - 1,
	    uint64_t, ebp->eb_addr, size_t, ebp->eb_size,
	    boolean_t, ebp->eb_eop);

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static inline boolean_t
sfxge_tx_msgb_copy(mblk_t *mp, sfxge_tx_buffer_t *stbp, size_t *offp,
    size_t *limitp)
{
	size_t data_off;
	size_t data_size;
	size_t copy_off;
	size_t copy_size;
	boolean_t eop;

	ASSERT3U(*offp, <=, MBLKL(mp));
	ASSERT(*limitp != 0);

	data_off = *offp;
	data_size = MBLKL(mp) - *offp;

	copy_off = stbp->stb_esm.esm_used;
	copy_size = SFXGE_TX_BUFFER_SIZE - copy_off;

	copy_size = MIN(copy_size, data_size);
	copy_size = MIN(copy_size, *limitp);

	bcopy(mp->b_rptr + data_off,
	    stbp->stb_esm.esm_base + copy_off, copy_size);

	stbp->stb_esm.esm_used += copy_size;
	ASSERT3U(stbp->stb_esm.esm_used, <=,
	    SFXGE_TX_BUFFER_SIZE);

	*offp += copy_size;
	*limitp -= copy_size;

	data_off += copy_size;
	data_size -= copy_size;

	eop = (*limitp == 0 ||
	    (data_size == 0 && mp->b_cont == NULL));

	ASSERT3U(*offp, <=, MBLKL(mp));

	return (eop);
}

static int
sfxge_tx_qpayload_fragment(sfxge_txq_t *stp, unsigned int id, mblk_t **mpp,
    size_t *offp, size_t size, boolean_t copy)
{
	sfxge_t *sp = stp->st_sp;
	mblk_t *mp = *mpp;
	size_t off = *offp;
	sfxge_tx_buffer_t *stbp;
	sfxge_tx_mapping_t *stmp;
	int rc;

	stbp = stp->st_stbp[id];
	ASSERT(stbp == NULL || (stbp->stb_esm.esm_used == stbp->stb_off));

	stmp = stp->st_stmp[id];

	while (size != 0) {
		boolean_t eop;

		ASSERT(mp != NULL);

		if (mp->b_cont != NULL)
			prefetch_read_many(mp->b_cont);

		ASSERT3U(off, <, MBLKL(mp));

		if (copy)
			goto copy;

		/*
		 * Check whether we have already mapped this data block for
		 * DMA.
		 */
		if (stmp == NULL || stmp->stm_mp != mp) {
			/*
			 * If we are part way through copying a data block then
			 * there's no point in trying to map it for DMA.
			 */
			if (off != 0)
				goto copy;

			/*
			 * If the data block is too short then the cost of
			 * mapping it for DMA would outweigh the cost of
			 * copying it.
			 */
			if (MBLKL(mp) < SFXGE_TX_COPY_THRESHOLD)
				goto copy;

			/* Try to grab a transmit mapping from the pool */
			stmp = sfxge_tx_qfmp_get(stp);
			if (stmp == NULL) {
				/*
				 * The pool was empty so allocate a new
				 * mapping.
				 */
				if ((stmp = kmem_cache_alloc(sp->s_tmc,
				    KM_NOSLEEP)) == NULL)
					goto copy;
			}

			/* Add the DMA mapping to the list */
			stmp->stm_next = stp->st_stmp[id];
			stp->st_stmp[id] = stmp;

			/* Try to bind the data block to the mapping */
			if (sfxge_tx_msgb_bind(mp, stmp) != 0)
				goto copy;
		}
		ASSERT3P(stmp->stm_mp, ==, mp);

		/*
		 * If we have a partially filled buffer then we must add it to
		 * the fragment list before adding the mapping.
		 */
		if (stbp != NULL && (stbp->stb_esm.esm_used > stbp->stb_off)) {
			rc = sfxge_tx_qbuffer_add(stp, stbp, B_FALSE);
			if (rc != 0)
				goto fail1;
		}

		/* Add the mapping to the fragment list */
		rc = sfxge_tx_qmapping_add(stp, stmp, &off, &size);
		if (rc != 0)
			goto fail2;

		ASSERT(off == MBLKL(mp) || size == 0);

		/*
		 * If the data block has been exhausted then Skip over the
		 * control block and advance to the next data block.
		 */
		if (off == MBLKL(mp)) {
			mp = mp->b_cont;
			off = 0;
		}

		continue;

copy:
		if (stbp == NULL ||
		    stbp->stb_esm.esm_used == SFXGE_TX_BUFFER_SIZE) {
			/* Try to grab a buffer from the pool */
			stbp = sfxge_tx_qfbp_get(stp);
			if (stbp == NULL) {
				/*
				 * The pool was empty so allocate a new
				 * buffer.
				 */
				if ((stbp = kmem_cache_alloc(sp->s_tbc,
				    KM_NOSLEEP)) == NULL) {
					rc = ENOMEM;
					goto fail3;
				}
			}

			/* Add it to the list */
			stbp->stb_next = stp->st_stbp[id];
			stp->st_stbp[id] = stbp;
		}

		/* Copy as much of the data block as we can into the buffer */
		eop = sfxge_tx_msgb_copy(mp, stbp, &off, &size);

		ASSERT(off == MBLKL(mp) || size == 0 ||
		    stbp->stb_esm.esm_used == SFXGE_TX_BUFFER_SIZE);

		/*
		 * If we have reached the end of the packet, or the buffer is
		 * full, then add the buffer to the fragment list.
		 */
		if (stbp->stb_esm.esm_used == SFXGE_TX_BUFFER_SIZE || eop) {
			rc = sfxge_tx_qbuffer_add(stp, stbp, eop);
			if (rc != 0)
				goto fail4;
		}

		/*
		 * If the data block has been exhaused then advance to the next
		 * one.
		 */
		if (off == MBLKL(mp)) {
			mp = mp->b_cont;
			off = 0;
		}
	}

	*mpp = mp;
	*offp = off;

	return (0);

fail4:
	DTRACE_PROBE(fail4);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_tx_qlso_fragment(sfxge_txq_t *stp, sfxge_tx_packet_t *stpp,
    boolean_t copy)
{
	sfxge_t *sp = stp->st_sp;
	mblk_t *mp = stpp->stp_mp;
	struct ether_header *etherhp = stpp->stp_etherhp;
	struct ip *iphp = stpp->stp_iphp;
	struct tcphdr *thp = stpp->stp_thp;
	size_t size = stpp->stp_size;
	size_t off = stpp->stp_off;
	size_t mss = stpp->stp_mss;
	unsigned int id;
	caddr_t hp;
	size_t ehs, hs;
	uint16_t start_len;
	uint16_t start_id;
	uint16_t ip_id;
	uint8_t start_flags;
	uint32_t start_seq;
	uint32_t th_seq;
	size_t lss;
	sfxge_tx_buffer_t *stbp;
	int rc;

	ASSERT(mutex_owned(&(stp->st_lock)));

	if ((DB_LSOFLAGS(mp) & HW_LSO) == 0) {
		rc = EINVAL;
		goto fail1;
	}

	id = stp->st_added & (SFXGE_TX_NDESCS - 1);

	ASSERT(stp->st_n == 0);
	ASSERT(stp->st_stbp[id] == NULL);
	ASSERT(stp->st_stmp[id] == NULL);

	ehs = (etherhp->ether_type == htons(ETHERTYPE_VLAN)) ?
	    sizeof (struct ether_vlan_header) :
	    sizeof (struct ether_header);
	if (msgdsize(mp) != ehs + ntohs(iphp->ip_len)) {
		rc = EINVAL;
		goto fail2;
	}

	/* The payload offset is equivalent to the size of the headers */
	hp = (caddr_t)(mp->b_rptr);
	hs = off;

	/*
	 * If the initial data block only contains the headers then advance
	 * to the next one.
	 */
	if (hs > MBLKL(mp)) {
		rc = EINVAL;
		goto fail3;
	}
	mp->b_rptr += hs;

	if (MBLKL(mp) == 0)
		mp = mp->b_cont;

	off = 0;

	/* Check IP and TCP headers are suitable for LSO */
	if (((iphp->ip_off & ~htons(IP_DF)) != 0) ||
	    ((thp->th_flags & (TH_URG | TH_SYN)) != 0) ||
	    (thp->th_urp != 0)) {
		rc = EINVAL;
		goto fail4;
	}

	if (size + (thp->th_off << 2) + (iphp->ip_hl << 2) !=
	    ntohs(iphp->ip_len)) {
		rc = EINVAL;
		goto fail4;
	}

	/*
	 * Get the base IP id, The stack leaves enough of a gap in id space
	 * for us to increment this for each segment we send out.
	 */
	start_len = ntohs(iphp->ip_len);
	start_id = ip_id = ntohs(iphp->ip_id);

	/* Get the base TCP sequence number and flags */
	start_flags = thp->th_flags;
	start_seq = th_seq = ntohl(thp->th_seq);

	/* Adjust the header for interim segments */
	iphp->ip_len = htons((iphp->ip_hl << 2) + (thp->th_off << 2) + mss);
	thp->th_flags = start_flags & ~(TH_PUSH | TH_FIN);

	lss = size;
	if ((lss / mss) >= (EFX_TXQ_LIMIT(SFXGE_TX_NDESCS) / 2)) {
		rc = EINVAL;
		goto fail5;
	}

	stbp = NULL;
	while (lss != 0) {
		size_t ss = MIN(lss, mss);
		boolean_t eol = (ss == lss);

		/* Adjust the header for this segment */
		iphp->ip_id = htons(ip_id);
		ip_id++;

		thp->th_seq = htonl(th_seq);
		th_seq += ss;

		/* If this is the final segment then do some extra adjustment */
		if (eol) {
			iphp->ip_len = htons((iphp->ip_hl << 2) +
			    (thp->th_off << 2) + ss);
			thp->th_flags = start_flags;
		}

		if (stbp == NULL ||
		    stbp->stb_esm.esm_used + hs > SFXGE_TX_BUFFER_SIZE) {
			/* Try to grab a buffer from the pool */
			stbp = sfxge_tx_qfbp_get(stp);
			if (stbp == NULL) {
				/*
				 * The pool was empty so allocate a new
				 * buffer.
				 */
				if ((stbp = kmem_cache_alloc(sp->s_tbc,
				    KM_NOSLEEP)) == NULL) {
					rc = ENOMEM;
					goto fail6;
				}
			}

			/* Add it to the list */
			stbp->stb_next = stp->st_stbp[id];
			stp->st_stbp[id] = stbp;
		}

		/* Copy in the headers */
		ASSERT3U(stbp->stb_off, ==, stbp->stb_esm.esm_used);
		bcopy(hp, stbp->stb_esm.esm_base + stbp->stb_off, hs);
		stbp->stb_esm.esm_used += hs;

		/* Add the buffer to the fragment list */
		rc = sfxge_tx_qbuffer_add(stp, stbp, B_FALSE);
		if (rc != 0)
			goto fail7;

		/* Add the payload to the fragment list */
		if ((rc = sfxge_tx_qpayload_fragment(stp, id, &mp, &off,
		    ss, copy)) != 0)
			goto fail8;

		lss -= ss;
	}
	ASSERT3U(off, ==, 0);
	ASSERT3P(mp, ==, NULL);

	ASSERT3U(th_seq - start_seq, ==, size);

	/*
	 * If no part of the packet has been mapped for DMA then we can free
	 * it now, otherwise it can only be freed on completion.
	 */
	if (stp->st_stmp[id] == NULL)
		freemsg(stpp->stp_mp);
	else
		stp->st_mp[id] = stpp->stp_mp;

	stpp->stp_mp = NULL;

	return (0);

fail8:
	DTRACE_PROBE(fail8);
fail7:
	DTRACE_PROBE(fail7);
fail6:
	DTRACE_PROBE(fail6);
fail5:
	DTRACE_PROBE(fail5);

	/* Restore the header */
	thp->th_seq = htonl(start_seq);
	thp->th_flags = start_flags;

	iphp->ip_len = htons(start_len);
	iphp->ip_id = htons(start_id);

fail4:
	DTRACE_PROBE(fail4);

	mp = stpp->stp_mp;
	mp->b_rptr -= hs;

	ASSERT3U(((etherhp->ether_type == htons(ETHERTYPE_VLAN)) ?
	    sizeof (struct ether_vlan_header) :
	    sizeof (struct ether_header)) +
	    ntohs(iphp->ip_len), ==, msgdsize(mp));

	ASSERT(stp->st_mp[id] == NULL);

fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_tx_qpacket_fragment(sfxge_txq_t *stp, sfxge_tx_packet_t *stpp,
    boolean_t copy)
{
	sfxge_t *sp = stp->st_sp;
	mblk_t *mp = stpp->stp_mp;
	unsigned int id;
	size_t off;
	size_t size;
	sfxge_tx_mapping_t *stmp;
	sfxge_tx_buffer_t *stbp;
	int rc;

	ASSERT(mutex_owned(&(stp->st_lock)));

	ASSERT(stp->st_n == 0);

	id = stp->st_added & (SFXGE_TX_NDESCS - 1);

	ASSERT(stp->st_stbp[id] == NULL);
	ASSERT(stp->st_stmp[id] == NULL);

	off = 0;
	size = LONG_MAX;	/* must be larger than the packet */

	stbp = NULL;
	stmp = NULL;

	while (mp != NULL) {
		boolean_t eop;

		ASSERT(mp != NULL);

		if (mp->b_cont != NULL)
			prefetch_read_many(mp->b_cont);

		ASSERT(stmp == NULL || stmp->stm_mp != mp);

		if (copy)
			goto copy;

		/*
		 * If we are part way through copying a data block then there's
		 * no point in trying to map it for DMA.
		 */
		if (off != 0)
			goto copy;

		/*
		 * If the data block is too short then the cost of mapping it
		 * for DMA would outweigh the cost of copying it.
		 *
		 * TX copy break
		 */
		if (MBLKL(mp) < SFXGE_TX_COPY_THRESHOLD)
			goto copy;

		/* Try to grab a transmit mapping from the pool */
		stmp = sfxge_tx_qfmp_get(stp);
		if (stmp == NULL) {
			/*
			 * The pool was empty so allocate a new
			 * mapping.
			 */
			if ((stmp = kmem_cache_alloc(sp->s_tmc,
			    KM_NOSLEEP)) == NULL)
				goto copy;
		}

		/* Add the DMA mapping to the list */
		stmp->stm_next = stp->st_stmp[id];
		stp->st_stmp[id] = stmp;

		/* Try to bind the data block to the mapping */
		if (sfxge_tx_msgb_bind(mp, stmp) != 0)
			goto copy;

		/*
		 * If we have a partially filled buffer then we must add it to
		 * the fragment list before adding the mapping.
		 */
		if (stbp != NULL && (stbp->stb_esm.esm_used > stbp->stb_off)) {
			rc = sfxge_tx_qbuffer_add(stp, stbp, B_FALSE);
			if (rc != 0)
				goto fail1;
		}

		/* Add the mapping to the fragment list */
		rc = sfxge_tx_qmapping_add(stp, stmp, &off, &size);
		if (rc != 0)
			goto fail2;

		ASSERT3U(off, ==, MBLKL(mp));

		/* Advance to the next data block */
		mp = mp->b_cont;
		off = 0;
		continue;

copy:
		if (stbp == NULL ||
		    stbp->stb_esm.esm_used == SFXGE_TX_BUFFER_SIZE) {
			/* Try to grab a buffer from the pool */
			stbp = sfxge_tx_qfbp_get(stp);
			if (stbp == NULL) {
				/*
				 * The pool was empty so allocate a new
				 * buffer.
				 */
				if ((stbp = kmem_cache_alloc(sp->s_tbc,
				    KM_NOSLEEP)) == NULL) {
					rc = ENOMEM;
					goto fail3;
				}
			}

			/* Add it to the list */
			stbp->stb_next = stp->st_stbp[id];
			stp->st_stbp[id] = stbp;
		}

		/* Copy as much of the data block as we can into the buffer */
		eop = sfxge_tx_msgb_copy(mp, stbp, &off, &size);

		ASSERT(off == MBLKL(mp) ||
		    stbp->stb_esm.esm_used == SFXGE_TX_BUFFER_SIZE);

		/*
		 * If we have reached the end of the packet, or the buffer is
		 * full, then add the buffer to the fragment list.
		 */
		if (stbp->stb_esm.esm_used == SFXGE_TX_BUFFER_SIZE || eop) {
			rc = sfxge_tx_qbuffer_add(stp, stbp, eop);
			if (rc != 0)
				goto fail4;
		}

		/*
		 * If the data block has been exhaused then advance to the next
		 * one.
		 */
		if (off == MBLKL(mp)) {
			mp = mp->b_cont;
			off = 0;
		}
	}
	ASSERT3U(off, ==, 0);
	ASSERT3P(mp, ==, NULL);
	ASSERT3U(size, !=, 0);

	/*
	 * If no part of the packet has been mapped for DMA then we can free
	 * it now, otherwise it can only be freed on completion.
	 */
	if (stp->st_stmp[id] == NULL)
		freemsg(stpp->stp_mp);
	else
		stp->st_mp[id] = stpp->stp_mp;

	stpp->stp_mp = NULL;

	return (0);

fail4:
	DTRACE_PROBE(fail4);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	ASSERT(stp->st_stmp[id] == NULL);

	return (rc);
}


#define	SFXGE_TX_QDPL_PUT_PENDING(_stp)					\
	((_stp)->st_dpl.std_put != 0)

static void
sfxge_tx_qdpl_swizzle(sfxge_txq_t *stp)
{
	sfxge_tx_dpl_t *stdp = &(stp->st_dpl);
	volatile uintptr_t *putp;
	uintptr_t put;
	sfxge_tx_packet_t *stpp;
	sfxge_tx_packet_t *p;
	sfxge_tx_packet_t **pp;
	unsigned int count;

	ASSERT(mutex_owned(&(stp->st_lock)));

	/*
	 * Guaranteed that in flight TX packets will cause more TX completions
	 * hence more swizzles must happen
	 */
	ASSERT3U(stdp->std_count, <=, sfxge_tx_dpl_get_pkt_max(stp));
	if (stdp->std_count >= stdp->get_pkt_limit)
		return;

	/* Acquire the put list - replacing with an empty list */
	putp = &(stdp->std_put);
	put = atomic_swap_ulong(putp, 0);
	stpp = (void *)put;

	if (stpp == NULL)
		return;

	/* Reverse the list */
	pp = &(stpp->stp_next);
	p = NULL;

	count = 0;
	do {
		sfxge_tx_packet_t *next;

		next = stpp->stp_next;

		stpp->stp_next = p;
		p = stpp;

		count++;
		stpp = next;
	} while (stpp != NULL);

	/* Add it to the tail of the get list */
	ASSERT3P(*pp, ==, NULL);

	*(stdp->std_getp) = p;
	stdp->std_getp = pp;
	stdp->std_count += count;
	ASSERT3U(stdp->std_count, <=, sfxge_tx_dpl_get_pkt_max(stp));

	DTRACE_PROBE2(dpl_counts, int, stdp->std_count, int, count);
}


/*
 * If TXQ locked, add the RX DPL put list and this packet to the TX DPL get list
 * If TXQ unlocked, atomically add this packet to TX DPL put list
 *
 * The only possible error is ENOSPC (used for TX backpressure)
 * For the TX DPL put or get list becoming full, in both cases there must be
 * future TX completions (as represented by the packets on the DPL get lists).
 *
 * This ensures that in the future mac_tx_update() will be called from
 * sfxge_tx_qcomplete()
 */
static inline int
sfxge_tx_qdpl_add(sfxge_txq_t *stp, sfxge_tx_packet_t *stpp, int locked)
{
	sfxge_tx_dpl_t *stdp = &stp->st_dpl;

	ASSERT3P(stpp->stp_next, ==, NULL);

	if (locked) {
		ASSERT(mutex_owned(&stp->st_lock));

		if (stdp->std_count >= stdp->get_pkt_limit) {
			stdp->get_full_count++;
			return (ENOSPC);
		}

		/* Reverse the put list onto the get list */
		sfxge_tx_qdpl_swizzle(stp);

		/* Add to the tail of the get list */
		*(stdp->std_getp) = stpp;
		stdp->std_getp = &stpp->stp_next;
		stdp->std_count++;
		ASSERT3U(stdp->std_count, <=, sfxge_tx_dpl_get_pkt_max(stp));

	} else {
		volatile uintptr_t *putp;
		uintptr_t old;
		uintptr_t new;
		sfxge_tx_packet_t *old_pkt;

		putp = &(stdp->std_put);
		new = (uintptr_t)stpp;

		/* Add to the head of the put list, keeping a list length */
		do {
			old = *putp;
			old_pkt =  (sfxge_tx_packet_t *)old;

			stpp->stp_dpl_put_len = old ?
			    old_pkt->stp_dpl_put_len + 1 : 1;

			if (stpp->stp_dpl_put_len >= stdp->put_pkt_limit) {
				stpp->stp_next = 0;
				stpp->stp_dpl_put_len = 0;
				stdp->put_full_count++;
				return (ENOSPC);
			}

			stpp->stp_next = (void *)old;
		} while (atomic_cas_ulong(putp, old, new) != old);
	}
	return (0);
}


/* Take all packets from DPL get list and try to send to HW */
static void
sfxge_tx_qdpl_drain(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	sfxge_tx_dpl_t *stdp = &(stp->st_dpl);
	unsigned int pushed = stp->st_added;
	sfxge_tx_packet_t *stpp;
	unsigned int count;

	ASSERT(mutex_owned(&(stp->st_lock)));

	prefetch_read_many(sp->s_enp);
	prefetch_read_many(stp->st_etp);

	stpp = stdp->std_get;
	count = stdp->std_count;

	while (count != 0) {
		sfxge_tx_packet_t *next;
		boolean_t copy;
		int rc;

		ASSERT(stpp != NULL);

		/* Split stpp off */
		next = stpp->stp_next;
		stpp->stp_next = NULL;

		if (next != NULL)
			prefetch_read_many(next);

		if (stp->st_state != SFXGE_TXQ_STARTED)
			goto reject;

		copy = B_FALSE;

again:
		/* Fragment the packet */
		if (stpp->stp_mss != 0) {
			rc = sfxge_tx_qlso_fragment(stp, stpp, copy);
		} else {
			rc = sfxge_tx_qpacket_fragment(stp, stpp, copy);
		}

		switch (rc) {
		case 0:
			break;

		case ENOSPC:
			if (!copy)
				goto copy;

		/*FALLTHRU*/
		default:
			goto reject;
		}

		/* Free the packet structure */
		stpp->stp_etherhp = NULL;
		stpp->stp_iphp = NULL;
		stpp->stp_thp = NULL;
		stpp->stp_off = 0;
		stpp->stp_size = 0;
		stpp->stp_mss = 0;
		stpp->stp_dpl_put_len = 0;

		ASSERT3P(stpp->stp_mp, ==, NULL);

		if (sfxge_tx_qfpp_put(stp, stpp) != 0) {
			sfxge_tx_packet_destroy(sp, stpp);
			stpp = NULL;
		}

		--count;
		stpp = next;

		/* Post the packet */
		sfxge_tx_qlist_post(stp);

		if (stp->st_unblock != SFXGE_TXQ_NOT_BLOCKED)
			goto defer;

		if (stp->st_added - pushed >= SFXGE_TX_BATCH) {
			efx_tx_qpush(stp->st_etp, stp->st_added, pushed);
			pushed = stp->st_added;
		}

		continue;

copy:
		/* Abort the current fragment list */
		sfxge_tx_qlist_abort(stp);

		/* Try copying the packet to flatten it */
		ASSERT(!copy);
		copy = B_TRUE;

		goto again;

reject:
		/* Abort the current fragment list */
		sfxge_tx_qlist_abort(stp);

		/* Discard the packet */
		freemsg(stpp->stp_mp);
		stpp->stp_mp = NULL;

		/* Free the packet structure */
		stpp->stp_etherhp = NULL;
		stpp->stp_iphp = NULL;
		stpp->stp_thp = NULL;
		stpp->stp_off = 0;
		stpp->stp_size = 0;
		stpp->stp_mss = 0;
		stpp->stp_dpl_put_len = 0;

		if (sfxge_tx_qfpp_put(stp, stpp) != 0) {
			sfxge_tx_packet_destroy(sp, stpp);
			stpp = NULL;
		}

		--count;
		stpp = next;
		continue;
defer:
		DTRACE_PROBE1(defer, unsigned int, stp->st_index);
		break;
	}

	if (count == 0) {
		/* New empty get list */
		ASSERT3P(stpp, ==, NULL);
		stdp->std_get = NULL;
		stdp->std_count = 0;

		stdp->std_getp = &(stdp->std_get);
	} else {
		/* shorten the list by moving the head */
		stdp->std_get = stpp;
		stdp->std_count = count;
		ASSERT3U(stdp->std_count, <=, sfxge_tx_dpl_get_pkt_max(stp));
	}

	if (stp->st_added != pushed)
		efx_tx_qpush(stp->st_etp, stp->st_added, pushed);

	ASSERT(stp->st_unblock != SFXGE_TXQ_NOT_BLOCKED ||
	    stdp->std_count == 0);
}

/* Swizzle deferred packet list, try and push to HW */
static inline void
sfxge_tx_qdpl_service(sfxge_txq_t *stp)
{
	do {
		ASSERT(mutex_owned(&(stp->st_lock)));

		if (SFXGE_TX_QDPL_PUT_PENDING(stp))
			sfxge_tx_qdpl_swizzle(stp);

		if (stp->st_unblock == SFXGE_TXQ_NOT_BLOCKED)
			sfxge_tx_qdpl_drain(stp);

		mutex_exit(&(stp->st_lock));

		if (!SFXGE_TX_QDPL_PUT_PENDING(stp))
			break;
	} while (mutex_tryenter(&(stp->st_lock)));
}

static void
sfxge_tx_qdpl_flush_locked(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	sfxge_tx_dpl_t *stdp = &(stp->st_dpl);
	sfxge_tx_packet_t *stpp;
	unsigned int count;

	ASSERT(mutex_owned(&(stp->st_lock)));

	/* Swizzle put list to the get list */
	sfxge_tx_qdpl_swizzle(stp);

	stpp = stdp->std_get;
	count = stdp->std_count;

	while (count != 0) {
		sfxge_tx_packet_t *next;

		next = stpp->stp_next;
		stpp->stp_next = NULL;

		/* Discard the packet */
		freemsg(stpp->stp_mp);
		stpp->stp_mp = NULL;

		/* Free the packet structure */
		stpp->stp_etherhp = NULL;
		stpp->stp_iphp = NULL;
		stpp->stp_thp = NULL;
		stpp->stp_off = 0;
		stpp->stp_size = 0;
		stpp->stp_mss = 0;
		stpp->stp_dpl_put_len = 0;

		sfxge_tx_packet_destroy(sp, stpp);

		--count;
		stpp = next;
	}

	ASSERT3P(stpp, ==, NULL);

	/* Empty list */
	stdp->std_get = NULL;
	stdp->std_count = 0;
	stdp->std_getp = &(stdp->std_get);
}


void
sfxge_tx_qdpl_flush(sfxge_txq_t *stp)
{
	mutex_enter(&(stp->st_lock));
	sfxge_tx_qdpl_flush_locked(stp);
	mutex_exit(&(stp->st_lock));
}


static void
sfxge_tx_qunblock(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	unsigned int evq = stp->st_evq;
	sfxge_evq_t *sep = sp->s_sep[evq];

	ASSERT(mutex_owned(&(sep->se_lock)));

	mutex_enter(&(stp->st_lock));

	if (stp->st_state != SFXGE_TXQ_STARTED) {
		mutex_exit(&(stp->st_lock));
		return;
	}

	if (stp->st_unblock != SFXGE_TXQ_NOT_BLOCKED) {
		unsigned int level;

		level = stp->st_added - stp->st_completed;
		if (level <= stp->st_unblock) {
			stp->st_unblock = SFXGE_TXQ_NOT_BLOCKED;
			sfxge_tx_qlist_post(stp);
		}
	}

	sfxge_tx_qdpl_service(stp);
	/* lock has been dropped */
}

void
sfxge_tx_qcomplete(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	sfxge_tx_dpl_t *stdp = &(stp->st_dpl);
	unsigned int evq = stp->st_evq;
	sfxge_evq_t *sep = sp->s_sep[evq];
	unsigned int completed;

	ASSERT(mutex_owned(&(sep->se_lock)));

	completed = stp->st_completed;
	while (completed != stp->st_pending) {
		unsigned int id;
		sfxge_tx_mapping_t *stmp;

		id = completed++ & (SFXGE_TX_NDESCS - 1);

		if ((stmp = stp->st_stmp[id]) != NULL) {
			mblk_t *mp;

			/* Unbind all the mappings */
			do {
				ASSERT(stmp->stm_mp != NULL);
				sfxge_tx_msgb_unbind(stmp);

				stmp = stmp->stm_next;
			} while (stmp != NULL);

			/*
			 * Now that the packet is no longer mapped for DMA it
			 * can be freed.
			 */
			mp = stp->st_mp[id];
			stp->st_mp[id] = NULL;

			ASSERT(mp != NULL);
			freemsg(mp);
		}
	}
	stp->st_completed = completed;

	/* Check whether we need to unblock the queue */
	if (stp->st_unblock != SFXGE_TXQ_NOT_BLOCKED) {
		unsigned int level;

		level = stp->st_added - stp->st_completed;
		if (level <= stp->st_unblock)
			sfxge_tx_qunblock(stp);
	}

	/* Release TX backpressure from the TX DPL put/get list being full */
	if (stdp->std_count < stdp->get_pkt_limit)
		mac_tx_update(sp->s_mh);
}

void
sfxge_tx_qflush_done(sfxge_txq_t *stp)
{
	sfxge_t *sp = stp->st_sp;
	boolean_t flush_pending = B_FALSE;

	ASSERT(mutex_owned(&(sp->s_sep[stp->st_evq]->se_lock)));

	mutex_enter(&(stp->st_lock));

	switch (stp->st_state) {
	case SFXGE_TXQ_INITIALIZED:
		/* Ignore flush event after TxQ destroyed */
		break;

	case SFXGE_TXQ_FLUSH_PENDING:
		flush_pending = B_TRUE;
		stp->st_state = SFXGE_TXQ_FLUSH_DONE;
		break;

	case SFXGE_TXQ_FLUSH_FAILED:
		/* MC may have rebooted before handling the flush request */
		stp->st_state = SFXGE_TXQ_FLUSH_DONE;
		break;

	case SFXGE_TXQ_STARTED:
		/*
		 * MC initiated flush on MC reboot or because of bad Tx
		 * descriptor
		 */
		stp->st_state = SFXGE_TXQ_FLUSH_DONE;
		break;

	case SFXGE_TXQ_FLUSH_DONE:
		/* Ignore unexpected extra flush event */
		ASSERT(B_FALSE);
		break;

	default:
		ASSERT(B_FALSE);
	}


	mutex_exit(&(stp->st_lock));

	if (flush_pending == B_FALSE) {
		/* Flush was not pending */
		return;
	}

	mutex_enter(&(sp->s_tx_flush_lock));
	sp->s_tx_flush_pending--;
	if (sp->s_tx_flush_pending <= 0) {
		/* All queues flushed: wakeup sfxge_tx_stop() */
		cv_signal(&(sp->s_tx_flush_kv));
	}
	mutex_exit(&(sp->s_tx_flush_lock));
}

static void
sfxge_tx_qflush(sfxge_t *sp, unsigned int index, boolean_t wait_for_flush)
{
	sfxge_txq_t *stp = sp->s_stp[index];
	int rc;

	ASSERT(mutex_owned(&(sp->s_state_lock)));
	ASSERT(mutex_owned(&(sp->s_tx_flush_lock)));

	mutex_enter(&(stp->st_lock));

	/* Prepare to flush and stop the queue */
	if (stp->st_state == SFXGE_TXQ_STARTED) {
		/* Flush the transmit queue */
		if ((rc = efx_tx_qflush(stp->st_etp)) == EALREADY) {
			/* Already flushed, may be initiated by MC */
			stp->st_state = SFXGE_TXQ_FLUSH_DONE;
		} else if (rc != 0) {
			/* Unexpected error */
			stp->st_state = SFXGE_TXQ_FLUSH_FAILED;
		} else if (wait_for_flush) {
			stp->st_state = SFXGE_TXQ_FLUSH_PENDING;
			sp->s_tx_flush_pending++;
		} else {
			/* Assume the flush is done */
			stp->st_state = SFXGE_TXQ_FLUSH_DONE;
		}
	}

	mutex_exit(&(stp->st_lock));
}

static void
sfxge_tx_qstop(sfxge_t *sp, unsigned int index)
{
	sfxge_txq_t *stp = sp->s_stp[index];
	unsigned int evq = stp->st_evq;
	sfxge_evq_t *sep = sp->s_sep[evq];

	mutex_enter(&(sep->se_lock));
	mutex_enter(&(stp->st_lock));

	if (stp->st_state == SFXGE_TXQ_INITIALIZED)
		goto done;

	ASSERT(stp->st_state == SFXGE_TXQ_FLUSH_PENDING ||
	    stp->st_state == SFXGE_TXQ_FLUSH_DONE ||
	    stp->st_state == SFXGE_TXQ_FLUSH_FAILED);

	/* All queues should have been flushed */
	if (stp->st_sp->s_tx_flush_pending != 0) {
		dev_err(sp->s_dip, CE_NOTE,
		    SFXGE_CMN_ERR "txq[%d] stop with flush_pending=%d",
		    index, stp->st_sp->s_tx_flush_pending);
	}
	if (stp->st_state == SFXGE_TXQ_FLUSH_FAILED) {
		dev_err(sp->s_dip, CE_NOTE,
		    SFXGE_CMN_ERR "txq[%d] flush failed", index);
	}

	/* Destroy the transmit queue */
	efx_tx_qdestroy(stp->st_etp);
	stp->st_etp = NULL;

	/* Clear entries from the buffer table */
	sfxge_sram_buf_tbl_clear(sp, stp->st_id,
	    EFX_TXQ_NBUFS(SFXGE_TX_NDESCS));

	sfxge_tx_qlist_abort(stp);
	ASSERT3U(stp->st_n, ==, 0);

	stp->st_unblock = SFXGE_TXQ_NOT_BLOCKED;

	stp->st_pending = stp->st_added;

	sfxge_tx_qcomplete(stp);
	ASSERT3U(stp->st_completed, ==, stp->st_pending);

	sfxge_tx_qreap(stp);
	ASSERT3U(stp->st_reaped, ==, stp->st_completed);

	/*
	 * Ensure the deferred packet list is cleared
	 * Can race with sfxge_tx_packet_add() adding to the put list
	 */
	sfxge_tx_qdpl_flush_locked(stp);

	stp->st_added = 0;
	stp->st_pending = 0;
	stp->st_completed = 0;
	stp->st_reaped = 0;

	stp->st_state = SFXGE_TXQ_INITIALIZED;

done:
	mutex_exit(&(stp->st_lock));
	mutex_exit(&(sep->se_lock));
}

static void
sfxge_tx_qfini(sfxge_t *sp, unsigned int index)
{
	sfxge_txq_t *stp = sp->s_stp[index];
	sfxge_tx_dpl_t *stdp = &(stp->st_dpl);

	ASSERT3U(stp->st_state, ==, SFXGE_TXQ_INITIALIZED);
	stp->st_state = SFXGE_TXQ_UNINITIALIZED;

	/* Detach the TXQ from the driver */
	sp->s_stp[index] = NULL;
	ASSERT(sp->s_tx_qcount > 0);
	sp->s_tx_qcount--;

	/* Free the EVQ label for events from this TXQ */
	(void) sfxge_ev_txlabel_free(sp, stp->st_evq, stp, stp->st_label);
	stp->st_label = 0;

	/* Tear down the statistics */
	sfxge_tx_kstat_fini(stp);

	/* Ensure the deferred packet list is empty */
	ASSERT3U(stdp->std_count, ==, 0);
	ASSERT3P(stdp->std_get, ==, NULL);
	ASSERT3U(stdp->std_put, ==, 0);

	/* Clear the free buffer pool */
	sfxge_tx_qfbp_empty(stp);

	/* Clear the free mapping pool */
	sfxge_tx_qfmp_empty(stp);

	/* Clear the free packet pool */
	sfxge_tx_qfpp_empty(stp);

	mutex_destroy(&(stp->st_lock));

	stp->st_evq = 0;
	stp->st_type = 0;
	stp->st_index = 0;

	kmem_cache_free(sp->s_tqc, stp);
}

int
sfxge_tx_init(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	char name[MAXNAMELEN];
	sfxge_txq_type_t qtype;
	unsigned int txq, evq;
	int index;
	int rc;

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_tx_packet_cache",
	    ddi_driver_name(sp->s_dip), ddi_get_instance(sp->s_dip));

	sp->s_tpc = kmem_cache_create(name, sizeof (sfxge_tx_packet_t),
	    SFXGE_CPU_CACHE_SIZE, sfxge_tx_packet_ctor, sfxge_tx_packet_dtor,
	    NULL, sp, NULL, 0);
	ASSERT(sp->s_tpc != NULL);

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_tx_buffer_cache",
	    ddi_driver_name(sp->s_dip), ddi_get_instance(sp->s_dip));

	sp->s_tbc = kmem_cache_create(name, sizeof (sfxge_tx_buffer_t),
	    SFXGE_CPU_CACHE_SIZE, sfxge_tx_buffer_ctor, sfxge_tx_buffer_dtor,
	    NULL, sp, NULL, 0);
	ASSERT(sp->s_tbc != NULL);

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_tx_mapping_cache",
	    ddi_driver_name(sp->s_dip), ddi_get_instance(sp->s_dip));

	sp->s_tmc = kmem_cache_create(name, sizeof (sfxge_tx_mapping_t),
	    SFXGE_CPU_CACHE_SIZE, sfxge_tx_mapping_ctor, sfxge_tx_mapping_dtor,
	    NULL, sp, NULL, 0);
	ASSERT(sp->s_tmc != NULL);

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_txq_cache",
	    ddi_driver_name(sp->s_dip), ddi_get_instance(sp->s_dip));

	sp->s_tqc = kmem_cache_create(name, sizeof (sfxge_txq_t),
	    SFXGE_CPU_CACHE_SIZE, sfxge_tx_qctor, sfxge_tx_qdtor, NULL, sp,
	    NULL, 0);
	ASSERT(sp->s_tqc != NULL);

	/* Initialize the transmit queues. */
	sp->s_tx_scale_max[SFXGE_TXQ_NON_CKSUM]		= sip->si_nalloc;
	sp->s_tx_scale_max[SFXGE_TXQ_IP_CKSUM]		= 1;
	sp->s_tx_scale_max[SFXGE_TXQ_IP_TCP_UDP_CKSUM]	= sip->si_nalloc;

	/* Ensure minimum queue counts required by sfxge_tx_packet_add(). */
	if (sp->s_tx_scale_max[SFXGE_TXQ_NON_CKSUM] < 1)
		sp->s_tx_scale_max[SFXGE_TXQ_NON_CKSUM] = 1;

	if (sp->s_tx_scale_max[SFXGE_TXQ_IP_CKSUM] < 1)
		sp->s_tx_scale_max[SFXGE_TXQ_IP_CKSUM] = 1;

	txq = 0;
	for (qtype = 0; qtype < SFXGE_TXQ_NTYPES; qtype++) {
		unsigned int tx_scale = sp->s_tx_scale_max[qtype];

		if (txq + tx_scale > EFX_ARRAY_SIZE(sp->s_stp)) {
			rc = EINVAL;
			goto fail1;
		}

		sp->s_tx_scale_base[qtype] = txq;

		for (evq = 0; evq < tx_scale; evq++) {
			if ((rc = sfxge_tx_qinit(sp, txq, qtype, evq)) != 0) {
				goto fail2;
			}
			txq++;
		}
		ASSERT3U(txq, <=, EFX_ARRAY_SIZE(sp->s_stp));
	}

	return (0);

fail2:
	DTRACE_PROBE(fail2);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	index = EFX_ARRAY_SIZE(sp->s_stp);
	while (--index >= 0) {
		if (sp->s_stp[index] != NULL)
			sfxge_tx_qfini(sp, index);
	}

	kmem_cache_destroy(sp->s_tqc);
	sp->s_tqc = NULL;

	kmem_cache_destroy(sp->s_tmc);
	sp->s_tmc = NULL;

	kmem_cache_destroy(sp->s_tbc);
	sp->s_tbc = NULL;

	kmem_cache_destroy(sp->s_tpc);
	sp->s_tpc = NULL;

	return (rc);
}

int
sfxge_tx_start(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	int index;
	int rc;

	/* Initialize the transmit module */
	if ((rc = efx_tx_init(enp)) != 0)
		goto fail1;

	for (index = 0; index < EFX_ARRAY_SIZE(sp->s_stp); index++) {
		if (sp->s_stp[index] != NULL)
			if ((rc = sfxge_tx_qstart(sp, index)) != 0)
				goto fail2;
	}

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	sfxge_tx_stop(sp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


/*
 * Add a packet to the TX Deferred Packet List and if the TX queue lock
 * can be acquired then call sfxge_tx_qdpl_service() to fragment and push
 * to the H/W transmit descriptor ring
 *
 * If ENOSPC is returned then the DPL is full or the packet create failed, but
 * the mblk isn't freed so that the caller can return this mblk from mc_tx() to
 * back-pressure the OS stack.
 *
 * For all other errors the mblk is freed
 */
int
sfxge_tx_packet_add(sfxge_t *sp, mblk_t *mp)
{
	struct ether_header *etherhp;
	struct ip *iphp;
	struct tcphdr *thp;
	size_t off;
	size_t size;
	size_t mss;
	sfxge_txq_t *stp;
	unsigned int txq;
	int index;
	boolean_t locked;
	sfxge_tx_packet_t *stpp;
	sfxge_packet_type_t pkt_type;
	uint16_t sport, dport;
	int rc = 0;

	ASSERT3P(mp->b_next, ==, NULL);
	ASSERT(!(DB_CKSUMFLAGS(mp) & HCK_PARTIALCKSUM));

	/*
	 * Do not enqueue packets during startup/shutdown;
	 *
	 * NOTE: This access to the state is NOT protected by the state lock. It
	 * is an imperfect test and anything further getting onto the get/put
	 * deferred packet lists is cleaned up in (possibly repeated) calls to
	 * sfxge_can_destroy().
	 */
	if (sp->s_state != SFXGE_STARTED) {
		rc = EINVAL;
		goto fail1;
	}

	etherhp = NULL;
	iphp = NULL;
	thp = NULL;
	off = 0;
	size = 0;
	mss = 0;

	/* Check whether we need the header pointers for LSO segmentation */
	if (DB_LSOFLAGS(mp) & HW_LSO) {
		/* LSO segmentation relies on hardware checksum offload */
		DB_CKSUMFLAGS(mp) |= HCK_FULLCKSUM;

		if ((mss = DB_LSOMSS(mp)) == 0) {
			rc = EINVAL;
			goto fail1;
		}

		pkt_type = sfxge_pkthdr_parse(mp, &etherhp, &iphp, &thp,
		    &off, &size, &sport, &dport);

		if (pkt_type != SFXGE_PACKET_TYPE_IPV4_TCP ||
		    etherhp == NULL ||
		    iphp == NULL ||
		    thp == NULL ||
		    off == 0) {
			rc = EINVAL;
			goto fail2;
		}
	}

	/* Choose the appropriate transit queue */
	if (DB_CKSUMFLAGS(mp) & HCK_FULLCKSUM) {
		sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);

		if (srsp->srs_state == SFXGE_RX_SCALE_STARTED) {
			uint32_t hash;

			if (srsp->srs_count > 1) {
				/*
				 * If we have not already parsed the headers
				 * for LSO segmentation then we need to do it
				 * now so we can calculate the hash.
				 */
				if (thp == NULL) {
					(void) sfxge_pkthdr_parse(mp, &etherhp,
					    &iphp, &thp, &off, &size,
					    &sport, &dport);
				}

				if (thp != NULL) {
					SFXGE_TCP_HASH(sp,
					    &iphp->ip_dst.s_addr,
					    thp->th_dport,
					    &iphp->ip_src.s_addr,
					    thp->th_sport, hash);

					index = srsp->srs_tbl[hash %
					    SFXGE_RX_SCALE_MAX];
				} else if (iphp != NULL) {
					/*
					 * Calculate IPv4 4-tuple hash, with
					 * TCP/UDP/SCTP src/dest ports. Ports
					 * are zero for other IPv4 protocols.
					 */
					SFXGE_IP_HASH(sp,
					    &iphp->ip_dst.s_addr, dport,
					    &iphp->ip_src.s_addr, sport, hash);

					index = srsp->srs_tbl[hash %
					    SFXGE_RX_SCALE_MAX];
				} else {
					/*
					 * Other traffic always goes to the
					 * the queue in the zero-th entry of
					 * the RSS table.
					 */
					index = srsp->srs_tbl[0];
				}
			} else {
				/*
				 * It does not matter what the hash is
				 * because all the RSS table entries will be
				 * the same.
				 */
				index = srsp->srs_tbl[0];
			}

			/*
			 * Find the event queue corresponding to the hash in
			 * the RSS table.
			 */
			txq = sp->s_tx_scale_base[SFXGE_TXQ_IP_TCP_UDP_CKSUM] +
			    index;
			stp = sp->s_stp[txq];
			ASSERT3U(stp->st_evq, ==, index);
		} else {
			index = 0;
			txq = sp->s_tx_scale_base[SFXGE_TXQ_IP_TCP_UDP_CKSUM] +
			    index;
			stp = sp->s_stp[txq];
		}
	} else if (DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM) {
		ASSERT3U(sp->s_tx_scale_max[SFXGE_TXQ_IP_CKSUM], >=, 1);
		index = 0;
		txq = sp->s_tx_scale_base[SFXGE_TXQ_IP_CKSUM] + index;
		stp = sp->s_stp[txq];
	} else {
		/*
		 * No hardware checksum offload requested.
		 */
		sfxge_rx_scale_t *srsp = &(sp->s_rx_scale);

		if (srsp->srs_state == SFXGE_RX_SCALE_STARTED) {
			uint32_t hash = 0;

			if (srsp->srs_count > 1) {
				if (iphp == NULL) {
					(void) sfxge_pkthdr_parse(mp, &etherhp,
					    &iphp, &thp, &off, &size,
					    &sport, &dport);
				}

				if (iphp != NULL) {
					/*
					 * Calculate IPv4 4-tuple hash, with
					 * TCP/UDP/SCTP src/dest ports. Ports
					 * are zero for other IPv4 protocols.
					 */
					SFXGE_IP_HASH(sp,
					    &iphp->ip_dst.s_addr, dport,
					    &iphp->ip_src.s_addr, sport, hash);

					hash = hash % SFXGE_RX_SCALE_MAX;
				}
			}
			index = srsp->srs_tbl[hash];

			/*
			 * The RSS table (indexed by hash) gives the RXQ index,
			 * (mapped 1:1 with EVQs). Find the TXQ that results in
			 * using the same EVQ as for the RX data path.
			 */
			ASSERT3U(sp->s_tx_scale_max[SFXGE_TXQ_NON_CKSUM],
			    >, index);
			txq = sp->s_tx_scale_base[SFXGE_TXQ_NON_CKSUM] + index;
			stp = sp->s_stp[txq];
			ASSERT3U(stp->st_evq, ==, index);
		} else {
			ASSERT3U(sp->s_tx_scale_max[SFXGE_TXQ_NON_CKSUM], >, 0);
			index = 0;
			txq = sp->s_tx_scale_base[SFXGE_TXQ_NON_CKSUM] + index;
			stp = sp->s_stp[txq];
		}


	}
	ASSERT(stp != NULL);

	ASSERT(mss == 0 || (DB_LSOFLAGS(mp) & HW_LSO));

	/* Try to grab the lock */
	locked = mutex_tryenter(&(stp->st_lock));

	if (locked) {
		/* Try to grab a packet from the pool */
		stpp = sfxge_tx_qfpp_get(stp);
	} else {
		stpp = NULL;
	}

	if (stpp == NULL) {
		/*
		 * Either the pool was empty or we don't have the lock so
		 * allocate a new packet.
		 */
		if ((stpp = sfxge_tx_packet_create(sp)) == NULL) {
			rc = ENOSPC;
			goto fail3;
		}
	}

	stpp->stp_mp = mp;
	stpp->stp_etherhp = etherhp;
	stpp->stp_iphp = iphp;
	stpp->stp_thp = thp;
	stpp->stp_off = off;
	stpp->stp_size = size;
	stpp->stp_mss = mss;
	stpp->stp_dpl_put_len = 0;

	rc = sfxge_tx_qdpl_add(stp, stpp, locked);
	if (rc != 0) {
		/* ENOSPC can happen for DPL get or put list is full */
		ASSERT3U(rc, ==, ENOSPC);

		/*
		 * Note; if this is the unlocked DPL put list full case there is
		 * no need to worry about a race with locked
		 * sfxge_tx_qdpl_swizzle() as we know that the TX DPL put list
		 * was full and would have been swizzle'd to the TX DPL get
		 * list; hence guaranteeing future TX completions and calls
		 * to mac_tx_update() via sfxge_tx_qcomplete()
		 */
		goto fail4;
	}

	/* Try to grab the lock again */
	if (!locked)
		locked = mutex_tryenter(&(stp->st_lock));

	if (locked) {
		/* Try to service the list */
		sfxge_tx_qdpl_service(stp);
		/* lock has been dropped */
	}

	return (0);

fail4:
	DTRACE_PROBE(fail4);
	sfxge_tx_packet_destroy(sp, stpp);
fail3:
	DTRACE_PROBE(fail3);
	if (locked)
		mutex_exit(&(stp->st_lock));
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	if (rc != ENOSPC)
		freemsg(mp);
	return (rc);
}

void
sfxge_tx_stop(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	clock_t timeout;
	boolean_t wait_for_flush;
	int index;

	ASSERT(mutex_owned(&(sp->s_state_lock)));

	mutex_enter(&(sp->s_tx_flush_lock));

	/* Flush all the queues */
	if (sp->s_hw_err == SFXGE_HW_OK) {
		wait_for_flush = B_TRUE;
	} else {
		/*
		 * Flag indicates possible hardware failure.
		 * Attempt flush but do not wait for it to complete.
		 */
		wait_for_flush = B_FALSE;
	}

	/* Prepare queues to stop and flush the hardware ring */
	index = EFX_ARRAY_SIZE(sp->s_stp);
	while (--index >= 0) {
		if (sp->s_stp[index] != NULL)
			sfxge_tx_qflush(sp, index, wait_for_flush);
	}

	if (wait_for_flush == B_FALSE)
		goto flush_done;

	/* Wait upto 2sec for queue flushing to complete */
	timeout = ddi_get_lbolt() + drv_usectohz(SFXGE_TX_QFLUSH_USEC);

	while (sp->s_tx_flush_pending > 0) {
		if (cv_timedwait(&(sp->s_tx_flush_kv), &(sp->s_tx_flush_lock),
		    timeout) < 0) {
			/* Timeout waiting for queues to flush */
			dev_info_t *dip = sp->s_dip;

			DTRACE_PROBE(timeout);
			dev_err(dip, CE_NOTE,
			    SFXGE_CMN_ERR "tx qflush timeout");
			break;
		}
	}

flush_done:
	sp->s_tx_flush_pending = 0;
	mutex_exit(&(sp->s_tx_flush_lock));

	/* Stop all the queues */
	index = EFX_ARRAY_SIZE(sp->s_stp);
	while (--index >= 0) {
		if (sp->s_stp[index] != NULL)
			sfxge_tx_qstop(sp, index);
	}

	/* Tear down the transmit module */
	efx_tx_fini(enp);
}

void
sfxge_tx_fini(sfxge_t *sp)
{
	int index;

	index = EFX_ARRAY_SIZE(sp->s_stp);
	while (--index >= 0) {
		if (sp->s_stp[index] != NULL)
			sfxge_tx_qfini(sp, index);
	}

	kmem_cache_destroy(sp->s_tqc);
	sp->s_tqc = NULL;

	kmem_cache_destroy(sp->s_tmc);
	sp->s_tmc = NULL;

	kmem_cache_destroy(sp->s_tbc);
	sp->s_tbc = NULL;

	kmem_cache_destroy(sp->s_tpc);
	sp->s_tpc = NULL;
}
