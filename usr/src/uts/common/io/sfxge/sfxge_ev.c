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
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/cpu.h>
#include <sys/pghw.h>

#include "sfxge.h"

#include "efx.h"


/* Timeout to wait for DRIVER_EV_START event at EVQ startup */
#define	SFXGE_EV_QSTART_TIMEOUT_USEC	(2000000)


/* Event queue DMA attributes */
static ddi_device_acc_attr_t sfxge_evq_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_evq_dma_attr = {
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

static int
_sfxge_ev_qctor(sfxge_t *sp, sfxge_evq_t *sep, int kmflags, uint16_t evq_size)
{
	efsys_mem_t *esmp = &(sep->se_mem);
	sfxge_dma_buffer_attr_t dma_attr;
	int rc;

	/* Compile-time structure layout checks */
	EFX_STATIC_ASSERT(sizeof (sep->__se_u1.__se_s1) <=
	    sizeof (sep->__se_u1.__se_pad));
	EFX_STATIC_ASSERT(sizeof (sep->__se_u2.__se_s2) <=
	    sizeof (sep->__se_u2.__se_pad));
	EFX_STATIC_ASSERT(sizeof (sep->__se_u3.__se_s3) <=
	    sizeof (sep->__se_u3.__se_pad));

	bzero(sep, sizeof (sfxge_evq_t));

	sep->se_sp = sp;

	dma_attr.sdba_dip	 = sp->s_dip;
	dma_attr.sdba_dattrp	 = &sfxge_evq_dma_attr;
	dma_attr.sdba_callback	 = (kmflags == KM_SLEEP) ?
	    DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;
	dma_attr.sdba_length	 = EFX_EVQ_SIZE(evq_size);
	dma_attr.sdba_memflags	 = DDI_DMA_CONSISTENT;
	dma_attr.sdba_devaccp	 = &sfxge_evq_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_READ | DDI_DMA_CONSISTENT;
	dma_attr.sdba_maxcookies = 1;
	dma_attr.sdba_zeroinit	 = B_FALSE;

	if ((rc = sfxge_dma_buffer_create(esmp, &dma_attr)) != 0)
		goto fail1;

	/* Allocate some buffer table entries */
	if ((rc = sfxge_sram_buf_tbl_alloc(sp, EFX_EVQ_NBUFS(evq_size),
	    &(sep->se_id))) != 0)
		goto fail2;

	sep->se_stpp = &(sep->se_stp);

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	/* Tear down DMA setup */
	esmp->esm_addr = 0;
	sfxge_dma_buffer_destroy(esmp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	sep->se_sp = NULL;

	SFXGE_OBJ_CHECK(sep, sfxge_evq_t);

	return (-1);
}

static int
sfxge_ev_q0ctor(void *buf, void *arg, int kmflags)
{
	sfxge_evq_t *sep = buf;
	sfxge_t *sp = arg;
	return (_sfxge_ev_qctor(sp, sep, kmflags, sp->s_evq0_size));
}

static int
sfxge_ev_qXctor(void *buf, void *arg, int kmflags)
{
	sfxge_evq_t *sep = buf;
	sfxge_t *sp = arg;
	return (_sfxge_ev_qctor(sp, sep, kmflags, sp->s_evqX_size));
}
static void
_sfxge_ev_qdtor(sfxge_t *sp, sfxge_evq_t *sep, uint16_t evq_size)
{
	efsys_mem_t *esmp = &(sep->se_mem);
	ASSERT3P(sep->se_sp, ==, sp);
	ASSERT3P(sep->se_stpp, ==, &(sep->se_stp));
	sep->se_stpp = NULL;

	/* Free the buffer table entries */
	sfxge_sram_buf_tbl_free(sp, sep->se_id, EFX_EVQ_NBUFS(evq_size));
	sep->se_id = 0;

	/* Tear down DMA setup */
	sfxge_dma_buffer_destroy(esmp);

	sep->se_sp = NULL;

	SFXGE_OBJ_CHECK(sep, sfxge_evq_t);
}

static void
sfxge_ev_q0dtor(void *buf, void *arg)
{
	sfxge_evq_t *sep = buf;
	sfxge_t *sp = arg;
	_sfxge_ev_qdtor(sp, sep, sp->s_evq0_size);
}

static void
sfxge_ev_qXdtor(void *buf, void *arg)
{
	sfxge_evq_t *sep = buf;
	sfxge_t *sp = arg;
	_sfxge_ev_qdtor(sp, sep, sp->s_evqX_size);
}

static boolean_t
sfxge_ev_initialized(void *arg)
{
	sfxge_evq_t *sep = arg;

	ASSERT(mutex_owned(&(sep->se_lock)));

	/* Init done events may be duplicated on 7xxx (see SFCbug31631) */
	if (sep->se_state == SFXGE_EVQ_STARTED)
		goto done;

	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_STARTING);
	sep->se_state = SFXGE_EVQ_STARTED;

	cv_broadcast(&(sep->se_init_kv));

done:
	return (B_FALSE);
}

static void
sfxge_ev_qcomplete(sfxge_evq_t *sep, boolean_t eop)
{
	sfxge_t *sp = sep->se_sp;
	unsigned int index = sep->se_index;
	sfxge_rxq_t *srp = sp->s_srp[index];
	sfxge_txq_t *stp;

	if ((stp = sep->se_stp) != NULL) {
		sep->se_stp = NULL;
		sep->se_stpp = &(sep->se_stp);

		do {
			sfxge_txq_t *next;

			next = stp->st_next;
			stp->st_next = NULL;

			ASSERT3U(stp->st_evq, ==, index);

			if (stp->st_pending != stp->st_completed)
				sfxge_tx_qcomplete(stp);

			stp = next;
		} while (stp != NULL);
	}

	if (srp != NULL) {
		if (srp->sr_pending != srp->sr_completed)
			sfxge_rx_qcomplete(srp, eop);
	}
}

static boolean_t
sfxge_ev_rx(void *arg, uint32_t label, uint32_t id, uint32_t size,
    uint16_t flags)
{
	sfxge_evq_t *sep = arg;
	sfxge_t *sp = sep->se_sp;
	sfxge_rxq_t *srp;
	sfxge_rx_packet_t *srpp;
	unsigned int prefetch;
	unsigned int stop;
	unsigned int delta;

	ASSERT(mutex_owned(&(sep->se_lock)));

	if (sep->se_exception)
		goto done;

	srp = sp->s_srp[label];
	if (srp == NULL)
		goto done;

	ASSERT3U(sep->se_index, ==, srp->sr_index);
	ASSERT3U(id, <, sp->s_rxq_size);

	/*
	 * Note that in sfxge_stop() EVQ stopped after RXQ, and will be reset
	 * So the return missing srp->sr_pending increase is safe
	 */
	if (srp->sr_state != SFXGE_RXQ_STARTED)
		goto done;

	stop = (id + 1) & (sp->s_rxq_size - 1);
	id = srp->sr_pending & (sp->s_rxq_size - 1);

	delta = (stop >= id) ? (stop - id) : (sp->s_rxq_size - id + stop);
	srp->sr_pending += delta;

	if (delta != 1) {
		if ((!efx_nic_cfg_get(sp->s_enp)->enc_rx_batching_enabled) ||
		    (delta == 0) ||
		    (delta > efx_nic_cfg_get(sp->s_enp)->enc_rx_batch_max)) {
			/*
			 * FIXME: This does not take into account scatter
			 * aborts.  See Bug40811
			 */
			sep->se_exception = B_TRUE;

			DTRACE_PROBE(restart_ev_rx_id);
			/* sfxge_evq_t->se_lock held */
			(void) sfxge_restart_dispatch(sp, DDI_SLEEP,
			    SFXGE_HW_ERR, "Out of order RX event", delta);

			goto done;
		}
	}

	prefetch = (id + 4) & (sp->s_rxq_size - 1);
	if ((srpp = srp->sr_srpp[prefetch]) != NULL)
		prefetch_read_many(srpp);

	srpp = srp->sr_srpp[id];
	ASSERT(srpp != NULL);
	prefetch_read_many(srpp->srp_mp);

	for (; id != stop; id = (id + 1) & (sp->s_rxq_size - 1)) {
		srpp = srp->sr_srpp[id];
		ASSERT(srpp != NULL);

		ASSERT3U(srpp->srp_flags, ==, EFX_DISCARD);
		srpp->srp_flags = flags;

		ASSERT3U(size, <, (1 << 16));
		srpp->srp_size = (uint16_t)size;
	}

	sep->se_rx++;

	DTRACE_PROBE2(qlevel, unsigned int, srp->sr_index,
	    unsigned int, srp->sr_added - srp->sr_pending);

	if (srp->sr_pending - srp->sr_completed >= SFXGE_RX_BATCH)
		sfxge_ev_qcomplete(sep, B_FALSE);

done:
	/* returning B_TRUE makes efx_ev_qpoll() stop processing events */
	return (sep->se_rx >= sep->se_ev_batch);
}

static boolean_t
sfxge_ev_exception(void *arg, uint32_t code, uint32_t data)
{
	sfxge_evq_t *sep = arg;
	sfxge_t *sp = sep->se_sp;

	_NOTE(ARGUNUSED(code))
	_NOTE(ARGUNUSED(data))

	ASSERT(mutex_owned(&(sep->se_lock)));
	sep->se_exception = B_TRUE;

	if (code != EFX_EXCEPTION_UNKNOWN_SENSOREVT) {

		DTRACE_PROBE(restart_ev_exception);

		/* sfxge_evq_t->se_lock held */
		(void) sfxge_restart_dispatch(sp, DDI_SLEEP, SFXGE_HW_ERR,
		    "Unknown EV", code);
	}

	return (B_FALSE);
}

static boolean_t
sfxge_ev_rxq_flush_done(void *arg, uint32_t rxq_index)
{
	sfxge_evq_t *sep_targetq, *sep = arg;
	sfxge_t *sp = sep->se_sp;
	sfxge_rxq_t *srp;
	unsigned int index;
	unsigned int label;
	uint16_t magic;

	ASSERT(mutex_owned(&(sep->se_lock)));

	/* Ensure RXQ exists, as events may arrive after RXQ was destroyed */
	srp = sp->s_srp[rxq_index];
	if (srp == NULL)
		goto done;

	/* Process right now if it is the correct event queue */
	index = srp->sr_index;
	if (index == sep->se_index) {
		sfxge_rx_qflush_done(srp);
		goto done;
	}

	/* Resend a software event on the correct queue */
	sep_targetq = sp->s_sep[index];

	if (sep_targetq->se_state != SFXGE_EVQ_STARTED)
		goto done; /* TBD: state test not under the lock */

	label = rxq_index;
	ASSERT((label & SFXGE_MAGIC_DMAQ_LABEL_MASK) == label);
	magic = SFXGE_MAGIC_RX_QFLUSH_DONE | label;

	efx_ev_qpost(sep_targetq->se_eep, magic);

done:
	return (B_FALSE);
}

static boolean_t
sfxge_ev_rxq_flush_failed(void *arg, uint32_t rxq_index)
{
	sfxge_evq_t *sep_targetq, *sep = arg;
	sfxge_t *sp = sep->se_sp;
	sfxge_rxq_t *srp;
	unsigned int index;
	unsigned int label;
	uint16_t magic;

	ASSERT(mutex_owned(&(sep->se_lock)));

	/* Ensure RXQ exists, as events may arrive after RXQ was destroyed */
	srp = sp->s_srp[rxq_index];
	if (srp == NULL)
		goto done;

	/* Process right now if it is the correct event queue */
	index = srp->sr_index;
	if (index == sep->se_index) {
		sfxge_rx_qflush_failed(srp);
		goto done;
	}

	/* Resend a software event on the correct queue */
	sep_targetq = sp->s_sep[index];

	label = rxq_index;
	ASSERT((label & SFXGE_MAGIC_DMAQ_LABEL_MASK) == label);
	magic = SFXGE_MAGIC_RX_QFLUSH_FAILED | label;

	if (sep_targetq->se_state != SFXGE_EVQ_STARTED)
		goto done; /* TBD: state test not under the lock */

	efx_ev_qpost(sep_targetq->se_eep, magic);

done:
	return (B_FALSE);
}

static boolean_t
sfxge_ev_tx(void *arg, uint32_t label, uint32_t id)
{
	sfxge_evq_t *sep = arg;
	sfxge_txq_t *stp;
	unsigned int stop;
	unsigned int delta;

	ASSERT(mutex_owned(&(sep->se_lock)));

	stp = sep->se_label_stp[label];
	if (stp == NULL)
		goto done;

	if (stp->st_state != SFXGE_TXQ_STARTED)
		goto done;

	ASSERT3U(sep->se_index, ==, stp->st_evq);

	stop = (id + 1) & (SFXGE_TX_NDESCS - 1);
	id = stp->st_pending & (SFXGE_TX_NDESCS - 1);

	delta = (stop >= id) ? (stop - id) : (SFXGE_TX_NDESCS - id + stop);
	stp->st_pending += delta;

	sep->se_tx++;

	if (stp->st_next == NULL &&
	    sep->se_stpp != &(stp->st_next)) {
		*(sep->se_stpp) = stp;
		sep->se_stpp = &(stp->st_next);
	}

	DTRACE_PROBE2(qlevel, unsigned int, stp->st_index,
	    unsigned int, stp->st_added - stp->st_pending);

	if (stp->st_pending - stp->st_completed >= SFXGE_TX_BATCH)
		sfxge_tx_qcomplete(stp);

done:
	/* returning B_TRUE makes efx_ev_qpoll() stop processing events */
	return (sep->se_tx >= sep->se_ev_batch);
}

static boolean_t
sfxge_ev_txq_flush_done(void *arg, uint32_t txq_index)
{
	sfxge_evq_t *sep = arg;
	sfxge_t *sp = sep->se_sp;
	sfxge_txq_t *stp;
	unsigned int evq;
	unsigned int label;
	uint16_t magic;

	ASSERT(mutex_owned(&(sep->se_lock)));

	/* Ensure TXQ exists, as events may arrive after TXQ was destroyed */
	stp = sp->s_stp[txq_index];
	if (stp == NULL)
		goto done;

	/* Process right now if it is the correct event queue */
	evq = stp->st_evq;
	if (evq == sep->se_index) {
		sfxge_tx_qflush_done(stp);
		goto done;
	}

	/* Resend a software event on the correct queue */
	sep = sp->s_sep[evq];

	label = stp->st_label;

	ASSERT((label & SFXGE_MAGIC_DMAQ_LABEL_MASK) == label);
	magic = SFXGE_MAGIC_TX_QFLUSH_DONE | label;

	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_STARTED);
	efx_ev_qpost(sep->se_eep, magic);

done:
	return (B_FALSE);
}

static boolean_t
sfxge_ev_software(void *arg, uint16_t magic)
{
	sfxge_evq_t *sep = arg;
	sfxge_t *sp = sep->se_sp;
	dev_info_t *dip = sp->s_dip;
	unsigned int label;

	ASSERT(mutex_owned(&(sep->se_lock)));

	EFX_STATIC_ASSERT(SFXGE_MAGIC_DMAQ_LABEL_WIDTH ==
	    FSF_AZ_RX_EV_Q_LABEL_WIDTH);
	EFX_STATIC_ASSERT(SFXGE_MAGIC_DMAQ_LABEL_WIDTH ==
	    FSF_AZ_TX_EV_Q_LABEL_WIDTH);

	label = magic & SFXGE_MAGIC_DMAQ_LABEL_MASK;
	magic &= ~SFXGE_MAGIC_DMAQ_LABEL_MASK;

	switch (magic) {
	case SFXGE_MAGIC_RX_QFLUSH_DONE: {
		sfxge_rxq_t *srp = sp->s_srp[label];

		if (srp != NULL) {
			ASSERT3U(sep->se_index, ==, srp->sr_index);

			sfxge_rx_qflush_done(srp);
		}
		break;
	}
	case SFXGE_MAGIC_RX_QFLUSH_FAILED: {
		sfxge_rxq_t *srp = sp->s_srp[label];

		if (srp != NULL) {
			ASSERT3U(sep->se_index, ==, srp->sr_index);

			sfxge_rx_qflush_failed(srp);
		}
		break;
	}
	case SFXGE_MAGIC_RX_QFPP_TRIM: {
		sfxge_rxq_t *srp = sp->s_srp[label];

		if (srp != NULL) {
			ASSERT3U(sep->se_index, ==, srp->sr_index);

			sfxge_rx_qfpp_trim(srp);
		}
		break;
	}
	case SFXGE_MAGIC_TX_QFLUSH_DONE: {
		sfxge_txq_t *stp = sep->se_label_stp[label];

		if (stp != NULL) {
			ASSERT3U(sep->se_index, ==, stp->st_evq);

			sfxge_tx_qflush_done(stp);
		}
		break;
	}
	default:
		dev_err(dip, CE_NOTE,
		    SFXGE_CMN_ERR "unknown software event 0x%x", magic);
		break;
	}

	return (B_FALSE);
}

static boolean_t
sfxge_ev_sram(void *arg, uint32_t code)
{
	_NOTE(ARGUNUSED(arg))

	switch (code) {
	case EFX_SRAM_UPDATE:
		DTRACE_PROBE(sram_update);
		break;

	case EFX_SRAM_CLEAR:
		DTRACE_PROBE(sram_clear);
		break;

	case EFX_SRAM_ILLEGAL_CLEAR:
		DTRACE_PROBE(sram_illegal_clear);
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}

	return (B_FALSE);
}

static boolean_t
sfxge_ev_timer(void *arg, uint32_t index)
{
	_NOTE(ARGUNUSED(arg, index))

	return (B_FALSE);
}

static boolean_t
sfxge_ev_wake_up(void *arg, uint32_t index)
{
	_NOTE(ARGUNUSED(arg, index))

	return (B_FALSE);
}

static boolean_t
sfxge_ev_link_change(void *arg, efx_link_mode_t	link_mode)
{
	sfxge_evq_t *sep = arg;
	sfxge_t *sp = sep->se_sp;

	sfxge_mac_link_update(sp, link_mode);

	return (B_FALSE);
}

static int
sfxge_ev_kstat_update(kstat_t *ksp, int rw)
{
	sfxge_evq_t *sep = ksp->ks_private;
	kstat_named_t *knp;
	int rc;

	if (rw != KSTAT_READ) {
		rc = EACCES;
		goto fail1;
	}

	ASSERT(mutex_owned(&(sep->se_lock)));

	if (sep->se_state != SFXGE_EVQ_STARTED)
		goto done;

	efx_ev_qstats_update(sep->se_eep, sep->se_stat);

	knp = ksp->ks_data;
	knp += EV_NQSTATS;

	knp->value.ui64 = sep->se_cpu_id;

done:
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_ev_kstat_init(sfxge_evq_t *sep)
{
	sfxge_t *sp = sep->se_sp;
	unsigned int index = sep->se_index;
	dev_info_t *dip = sp->s_dip;
	kstat_t *ksp;
	kstat_named_t *knp;
	char name[MAXNAMELEN];
	unsigned int id;
	int rc;

	/* Determine the name */
	(void) snprintf(name, MAXNAMELEN - 1, "%s_evq%04d",
	    ddi_driver_name(dip), index);

	/* Create the set */
	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "queue", KSTAT_TYPE_NAMED,
	    EV_NQSTATS + 1, 0)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	sep->se_ksp = ksp;

	ksp->ks_update = sfxge_ev_kstat_update;
	ksp->ks_private = sep;
	ksp->ks_lock = &(sep->se_lock);

	/* Initialise the named stats */
	sep->se_stat = knp = ksp->ks_data;
	for (id = 0; id < EV_NQSTATS; id++) {
		kstat_named_init(knp, (char *)efx_ev_qstat_name(sp->s_enp, id),
		    KSTAT_DATA_UINT64);
		knp++;
	}

	kstat_named_init(knp, "cpu", KSTAT_DATA_UINT64);

	kstat_install(ksp);
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_ev_kstat_fini(sfxge_evq_t *sep)
{
	/* Destroy the set */
	kstat_delete(sep->se_ksp);
	sep->se_ksp = NULL;
	sep->se_stat = NULL;
}

inline unsigned pow2_ge(unsigned int n) {
	unsigned int order = 0;
	ASSERT3U(n, >, 0);
	while ((1ul << order) < n) ++order;
	return (1ul << (order));
}

static int
sfxge_ev_qinit(sfxge_t *sp, unsigned int index, unsigned int ev_batch)
{
	sfxge_evq_t *sep;
	int rc;

	ASSERT3U(index, <, SFXGE_RX_SCALE_MAX);

	sep = kmem_cache_alloc(index ? sp->s_eqXc : sp->s_eq0c, KM_SLEEP);
	if (sep == NULL) {
		rc = ENOMEM;
		goto fail1;
	}
	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_UNINITIALIZED);

	sep->se_index = index;

	mutex_init(&(sep->se_lock), NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(sp->s_intr.si_intr_pri));

	cv_init(&(sep->se_init_kv), NULL, CV_DRIVER, NULL);

	/* Initialize the statistics */
	if ((rc = sfxge_ev_kstat_init(sep)) != 0)
		goto fail2;

	sep->se_state = SFXGE_EVQ_INITIALIZED;
	sep->se_ev_batch = (uint16_t)ev_batch;
	sp->s_sep[index] = sep;

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	sep->se_index = 0;

	cv_destroy(&(sep->se_init_kv));
	mutex_destroy(&(sep->se_lock));

	kmem_cache_free(index ? sp->s_eqXc : sp->s_eq0c, sep);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_ev_qstart(sfxge_t *sp, unsigned int index)
{
	sfxge_evq_t *sep = sp->s_sep[index];
	sfxge_intr_t *sip = &(sp->s_intr);
	efx_nic_t *enp = sp->s_enp;
	efx_ev_callbacks_t *eecp;
	efsys_mem_t *esmp;
	clock_t timeout;
	int rc;
	uint16_t evq_size = index ? sp->s_evqX_size : sp->s_evq0_size;

	mutex_enter(&(sep->se_lock));
	esmp = &(sep->se_mem);

	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_INITIALIZED);

	/* Set the memory to all ones */
	(void) memset(esmp->esm_base, 0xff, EFX_EVQ_SIZE(evq_size));

	/* Program the buffer table */
	if ((rc = sfxge_sram_buf_tbl_set(sp, sep->se_id, esmp,
	    EFX_EVQ_NBUFS(evq_size))) != 0)
		goto fail1;

	/* Set up the event callbacks */
	eecp = &(sep->se_eec);
	eecp->eec_initialized = sfxge_ev_initialized;
	eecp->eec_rx = sfxge_ev_rx;
	eecp->eec_tx = sfxge_ev_tx;
	eecp->eec_exception = sfxge_ev_exception;
	eecp->eec_rxq_flush_done = sfxge_ev_rxq_flush_done;
	eecp->eec_rxq_flush_failed = sfxge_ev_rxq_flush_failed;
	eecp->eec_txq_flush_done = sfxge_ev_txq_flush_done;
	eecp->eec_software = sfxge_ev_software;
	eecp->eec_sram = sfxge_ev_sram;
	eecp->eec_wake_up = sfxge_ev_wake_up;
	eecp->eec_timer = sfxge_ev_timer;
	eecp->eec_link_change = sfxge_ev_link_change;

	/* Create the event queue */
	if ((rc = efx_ev_qcreate(enp, index, esmp, evq_size, sep->se_id,
	    &(sep->se_eep))) != 0)
		goto fail2;

	/* Set the default moderation */
	if ((rc = efx_ev_qmoderate(sep->se_eep, sp->s_ev_moderation)) != 0)
		goto fail3;

	/* Check that interrupts are enabled at the NIC */
	if (sip->si_state != SFXGE_INTR_STARTED) {
		rc = EINVAL;
		goto fail4;
	}

	sep->se_state = SFXGE_EVQ_STARTING;

	/* Prime the event queue for interrupts */
	if ((rc = efx_ev_qprime(sep->se_eep, sep->se_count)) != 0)
		goto fail5;

	/* Wait for the initialization event */
	timeout = ddi_get_lbolt() + drv_usectohz(SFXGE_EV_QSTART_TIMEOUT_USEC);
	while (sep->se_state != SFXGE_EVQ_STARTED) {
		if (cv_timedwait(&(sep->se_init_kv), &(sep->se_lock),
		    timeout) < 0) {
			/* Timeout waiting for initialization */
			dev_info_t *dip = sp->s_dip;

			DTRACE_PROBE(timeout);
			dev_err(dip, CE_NOTE,
			    SFXGE_CMN_ERR "evq[%d] qstart timeout", index);

			rc = ETIMEDOUT;
			goto fail6;
		}
	}

	mutex_exit(&(sep->se_lock));
	return (0);

fail6:
	DTRACE_PROBE(fail6);

fail5:
	DTRACE_PROBE(fail5);

	sep->se_state = SFXGE_EVQ_INITIALIZED;

fail4:
	DTRACE_PROBE(fail4);

fail3:
	DTRACE_PROBE(fail3);

	/* Destroy the event queue */
	efx_ev_qdestroy(sep->se_eep);
	sep->se_eep = NULL;

fail2:
	DTRACE_PROBE(fail2);

	/* Zero out the event handlers */
	bzero(&(sep->se_eec), sizeof (efx_ev_callbacks_t));

	/* Clear entries from the buffer table */
	sfxge_sram_buf_tbl_clear(sp, sep->se_id, EFX_EVQ_NBUFS(evq_size));

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(sep->se_lock));

	return (rc);
}

int
sfxge_ev_qpoll(sfxge_t *sp, unsigned int index)
{
	sfxge_evq_t *sep = sp->s_sep[index];
	processorid_t cpu_id;
	int rc;
	uint16_t evq_size = index ? sp->s_evqX_size : sp->s_evq0_size;

	mutex_enter(&(sep->se_lock));

	if (sep->se_state != SFXGE_EVQ_STARTING &&
	    sep->se_state != SFXGE_EVQ_STARTED) {
		rc = EINVAL;
		goto fail1;
	}

	/* Make sure the CPU information is up to date */
	cpu_id = CPU->cpu_id;

	if (cpu_id != sep->se_cpu_id) {
		sep->se_cpu_id = cpu_id;

		/* sfxge_evq_t->se_lock held */
		(void) ddi_taskq_dispatch(sp->s_tqp, sfxge_rx_scale_update, sp,
		    DDI_NOSLEEP);
	}

	/* Synchronize the DMA memory for reading */
	(void) ddi_dma_sync(sep->se_mem.esm_dma_handle,
	    0,
	    EFX_EVQ_SIZE(evq_size),
	    DDI_DMA_SYNC_FORKERNEL);

	ASSERT3U(sep->se_rx, ==, 0);
	ASSERT3U(sep->se_tx, ==, 0);
	ASSERT3P(sep->se_stp, ==, NULL);
	ASSERT3P(sep->se_stpp, ==, &(sep->se_stp));

	/* Poll the queue */
	efx_ev_qpoll(sep->se_eep, &(sep->se_count), &(sep->se_eec),
	    sep);

	sep->se_rx = 0;
	sep->se_tx = 0;

	/* Perform any pending completion processing */
	sfxge_ev_qcomplete(sep, B_TRUE);

	/* Re-prime the event queue for interrupts */
	if ((rc = efx_ev_qprime(sep->se_eep, sep->se_count)) != 0)
		goto fail2;

	mutex_exit(&(sep->se_lock));

	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(sep->se_lock));

	return (rc);
}

int
sfxge_ev_qprime(sfxge_t *sp, unsigned int index)
{
	sfxge_evq_t *sep = sp->s_sep[index];
	int rc;

	mutex_enter(&(sep->se_lock));

	if (sep->se_state != SFXGE_EVQ_STARTING &&
	    sep->se_state != SFXGE_EVQ_STARTED) {
		rc = EINVAL;
		goto fail1;
	}

	if ((rc = efx_ev_qprime(sep->se_eep, sep->se_count)) != 0)
		goto fail2;

	mutex_exit(&(sep->se_lock));

	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(sep->se_lock));

	return (rc);
}


int
sfxge_ev_qmoderate(sfxge_t *sp, unsigned int index, unsigned int us)
{
	sfxge_evq_t *sep = sp->s_sep[index];
	efx_evq_t *eep = sep->se_eep;

	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_STARTED);

	return (efx_ev_qmoderate(eep, us));
}

static void
sfxge_ev_qstop(sfxge_t *sp, unsigned int index)
{
	sfxge_evq_t *sep = sp->s_sep[index];
	uint16_t evq_size;

	mutex_enter(&(sep->se_lock));
	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_STARTED);
	sep->se_state = SFXGE_EVQ_INITIALIZED;
	evq_size = index ? sp->s_evqX_size : sp->s_evq0_size;

	/* Clear the CPU information */
	sep->se_cpu_id = 0;

	/* Clear the event count */
	sep->se_count = 0;

	/* Reset the exception flag */
	sep->se_exception = B_FALSE;

	/* Destroy the event queue */
	efx_ev_qdestroy(sep->se_eep);
	sep->se_eep = NULL;

	mutex_exit(&(sep->se_lock));

	/* Zero out the event handlers */
	bzero(&(sep->se_eec), sizeof (efx_ev_callbacks_t));

	/* Clear entries from the buffer table */
	sfxge_sram_buf_tbl_clear(sp, sep->se_id, EFX_EVQ_NBUFS(evq_size));
}

static void
sfxge_ev_qfini(sfxge_t *sp, unsigned int index)
{
	sfxge_evq_t *sep = sp->s_sep[index];

	ASSERT3U(sep->se_state, ==, SFXGE_EVQ_INITIALIZED);

	sp->s_sep[index] = NULL;
	sep->se_state = SFXGE_EVQ_UNINITIALIZED;

	/* Tear down the statistics */
	sfxge_ev_kstat_fini(sep);

	cv_destroy(&(sep->se_init_kv));
	mutex_destroy(&(sep->se_lock));

	sep->se_index = 0;

	kmem_cache_free(index ? sp->s_eqXc : sp->s_eq0c, sep);
}

int
sfxge_ev_txlabel_alloc(sfxge_t *sp, unsigned int evq, sfxge_txq_t *stp,
    unsigned int *labelp)
{
	sfxge_evq_t *sep = sp->s_sep[evq];
	sfxge_txq_t **stpp;
	unsigned int label;
	int rc;

	mutex_enter(&(sep->se_lock));

	if (stp == NULL || labelp == NULL) {
		rc = EINVAL;
		goto fail1;
	}

	stpp = NULL;
	for (label = 0; label < SFXGE_TX_NLABELS; label++) {
		if (sep->se_label_stp[label] == stp) {
			rc = EEXIST;
			goto fail2;
		}
		if ((stpp == NULL) && (sep->se_label_stp[label] == NULL)) {
			stpp = &sep->se_label_stp[label];
		}
	}
	if (stpp == NULL) {
		rc = ENOSPC;
		goto fail3;
	}
	*stpp = stp;
	label = stpp - sep->se_label_stp;

	ASSERT3U(label, <, SFXGE_TX_NLABELS);
	*labelp = label;

	mutex_exit(&(sep->se_lock));
	return (0);

fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(sep->se_lock));

	return (rc);
}


int
sfxge_ev_txlabel_free(sfxge_t *sp, unsigned int evq, sfxge_txq_t *stp,
    unsigned int label)
{
	sfxge_evq_t *sep = sp->s_sep[evq];
	int rc;

	mutex_enter(&(sep->se_lock));

	if (stp == NULL || label > SFXGE_TX_NLABELS) {
		rc = EINVAL;
		goto fail1;
	}

	if (sep->se_label_stp[label] != stp) {
		rc = EINVAL;
		goto fail2;
	}
	sep->se_label_stp[label] = NULL;

	mutex_exit(&(sep->se_lock));

	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(sep->se_lock));

	return (rc);
}


static 	kmem_cache_t *
sfxge_ev_kmem_cache_create(sfxge_t *sp, const char *qname,
    int (*ctor)(void *, void *, int), void (*dtor)(void *, void *))
{
	char name[MAXNAMELEN];
	kmem_cache_t *eqc;

	(void) snprintf(name, MAXNAMELEN - 1, "%s%d_%s_cache",
	    ddi_driver_name(sp->s_dip), ddi_get_instance(sp->s_dip), qname);

	eqc = kmem_cache_create(name, sizeof (sfxge_evq_t),
	    SFXGE_CPU_CACHE_SIZE, ctor, dtor, NULL, sp, NULL, 0);
	ASSERT(eqc != NULL);
	return (eqc);
}

int
sfxge_ev_init(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	unsigned int evq0_size;
	unsigned int evqX_size;
	unsigned int ev_batch;
	int index;
	int rc;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_INITIALIZED);

	/*
	 * Must account for RXQ, TXQ(s); MCDI not event completed at present
	 * Note that common code does not completely fill descriptor queues
	 */
	evqX_size = sp->s_rxq_size + SFXGE_TX_NDESCS;
	evq0_size = evqX_size + SFXGE_TX_NDESCS; /* only IP checksum TXQ */
	evq0_size += SFXGE_TX_NDESCS; /* no checksums */

	ASSERT3U(evqX_size, >=, EFX_EVQ_MINNEVS);
	ASSERT3U(evq0_size, >, evqX_size);

	if (evq0_size > EFX_EVQ_MAXNEVS) {
		rc = EINVAL;
		goto fail1;
	}

	sp->s_evq0_size = pow2_ge(evq0_size);
	sp->s_evqX_size = pow2_ge(evqX_size);

	/* Read driver parameters */
	sp->s_ev_moderation = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "intr_moderation", SFXGE_DEFAULT_MODERATION);

	ev_batch = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "ev_batch", SFXGE_EV_BATCH);

	/*
	 * It is slightly peverse to have a cache for one item. But it allows
	 * for simple alignment control without increasing the allocation size
	 */
	sp->s_eq0c = sfxge_ev_kmem_cache_create(sp, "evq0", sfxge_ev_q0ctor,
	    sfxge_ev_q0dtor);
	sp->s_eqXc = sfxge_ev_kmem_cache_create(sp, "evqX", sfxge_ev_qXctor,
	    sfxge_ev_qXdtor);

	/* Initialize the event queue(s) */
	for (index = 0; index < sip->si_nalloc; index++) {
		if ((rc = sfxge_ev_qinit(sp, index, ev_batch)) != 0)
			goto fail2;
	}

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	while (--index >= 0)
		sfxge_ev_qfini(sp, index);
	sp->s_ev_moderation = 0;

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	kmem_cache_destroy(sp->s_eqXc);
	kmem_cache_destroy(sp->s_eq0c);
	sp->s_eqXc = NULL;
	sp->s_eq0c = NULL;

	return (rc);
}

int
sfxge_ev_start(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	efx_nic_t *enp = sp->s_enp;
	int index;
	int rc;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_STARTED);

	/* Initialize the event module */
	if ((rc = efx_ev_init(enp)) != 0)
		goto fail1;

	/* Start the event queues */
	for (index = 0; index < sip->si_nalloc; index++) {
		if ((rc = sfxge_ev_qstart(sp, index)) != 0)
			goto fail2;
	}

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	/* Stop the event queue(s) */
	while (--index >= 0)
		sfxge_ev_qstop(sp, index);

	/* Tear down the event module */
	efx_ev_fini(enp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

void
sfxge_ev_moderation_get(sfxge_t *sp, unsigned int *usp)
{
	*usp = sp->s_ev_moderation;
}

int
sfxge_ev_moderation_set(sfxge_t *sp, unsigned int us)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	int index;
	int rc;

	if (sip->si_state != SFXGE_INTR_STARTED)
		return (ENODEV);

	for (index = 0; index < sip->si_nalloc; index++) {
		if ((rc = sfxge_ev_qmoderate(sp, index, us)) != 0)
			goto fail1;
	}

	sp->s_ev_moderation = us;
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	/*  The only error path is if the value to set to is invalid. */
	ASSERT3U(index, ==, 0);

	return (rc);
}

void
sfxge_ev_stop(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	efx_nic_t *enp = sp->s_enp;
	int index;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_STARTED);

	/* Stop the event queue(s) */
	index = sip->si_nalloc;
	while (--index >= 0)
		sfxge_ev_qstop(sp, index);

	/* Tear down the event module */
	efx_ev_fini(enp);
}

void
sfxge_ev_fini(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	int index;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_INITIALIZED);

	sp->s_ev_moderation = 0;

	/* Tear down the event queue(s) */
	index = sip->si_nalloc;
	while (--index >= 0)
		sfxge_ev_qfini(sp, index);

	kmem_cache_destroy(sp->s_eqXc);
	kmem_cache_destroy(sp->s_eq0c);
	sp->s_eqXc = NULL;
	sp->s_eq0c = NULL;
}
