/*
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#include <sys/debug.h>
#include <sys/param.h>
#include <sys/bitmap.h>
#include <sys/mutex.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/taskq.h>
#include <sys/cpuvar.h>
#include <sys/reboot.h>

#include <sys/hyperv_busdma.h>
#include <sys/vmbus.h>
#include <sys/vmbus_xact.h>
#include "hyperv_var.h"
#include "vmbus_reg.h"
#include "vmbus_var.h"
#include "vmbus_brvar.h"
#include "vmbus_chanvar.h"

static void			vmbus_chan_update_evtflagcnt(
				    struct vmbus_softc *,
				    const struct vmbus_channel *);
static int			vmbus_chan_close_internal(
				    struct vmbus_channel *);
extern	void membar_sync(void);

static struct vmbus_channel	*vmbus_chan_alloc(struct vmbus_softc *);
static void			vmbus_chan_free(struct vmbus_channel *);
static int			vmbus_chan_add(struct vmbus_channel *);
static void			vmbus_chan_cpu_default(struct vmbus_channel *);
static int			vmbus_chan_release(struct vmbus_channel *);
static void			vmbus_chan_set_chmap(struct vmbus_channel *);
static void			vmbus_chan_clear_chmap(struct vmbus_channel *);
static void			vmbus_chan_detach(struct vmbus_channel *);
static boolean_t		vmbus_chan_wait_revoke(
				    const struct vmbus_channel *);

static void			vmbus_chan_ins_prilist(struct vmbus_softc *,
				    struct vmbus_channel *);
static void			vmbus_chan_rem_prilist(struct vmbus_softc *,
				    struct vmbus_channel *);
static void			vmbus_chan_ins_list(struct vmbus_softc *,
				    struct vmbus_channel *);
static void			vmbus_chan_rem_list(struct vmbus_softc *,
				    struct vmbus_channel *);
static void			vmbus_chan_ins_sublist(struct vmbus_channel *,
				    struct vmbus_channel *);
static void			vmbus_chan_rem_sublist(struct vmbus_channel *,
				    struct vmbus_channel *);

static void			vmbus_chan_task(void *);
static void			vmbus_chan_task_nobatch(void *);
static void			vmbus_chan_clrchmap_task(void *);
static void			vmbus_prichan_attach_task(void *);
static void			vmbus_subchan_attach_task(void *);
static void			vmbus_prichan_detach_task(void *);
static void			vmbus_subchan_detach_task(void *);

static void			vmbus_chan_msgproc_choffer(struct vmbus_softc *,
				    const struct vmbus_message *);
static void			vmbus_chan_msgproc_chrescind(
				    struct vmbus_softc *,
				    const struct vmbus_message *);

#define	vmbus_chan_printf(chan, fmt...) \
	dev_err(chan->ch_dev == NULL ? \
	    chan->ch_vmbus->vmbus_dev : chan->ch_dev, CE_WARN, fmt)

/*
 * Vmbus channel message processing.
 */
static const vmbus_chanmsg_proc_t
vmbus_chan_msgprocs[VMBUS_CHANMSG_TYPE_MAX] = {
	VMBUS_CHANMSG_PROC(CHOFFER,	vmbus_chan_msgproc_choffer),
	VMBUS_CHANMSG_PROC(CHRESCIND,	vmbus_chan_msgproc_chrescind),

	VMBUS_CHANMSG_PROC_WAKEUP(CHOPEN_RESP),
	VMBUS_CHANMSG_PROC_WAKEUP(GPADL_CONNRESP),
	VMBUS_CHANMSG_PROC_WAKEUP(GPADL_DISCONNRESP)
};

/*
 * Check to see if the bit is set or cleared
 * Note: These routines don't return old value.
 * It returns 0 when succeeds, or -1 when fails.
 */
#ifdef _LP64
#define	test_and_set_bit(p, b) \
	atomic_set_long_excl(((ulong_t *)(void *)p) + (b >> 6), (b & 0x3f))
#define	test_and_clear_bit(p, b) \
	atomic_clear_long_excl(((ulong_t *)(void *)(p)) + ((b) >> 6), \
	((b) & 0x3f))
#else
#define	test_and_set_bit(p, b) \
	atomic_set_long_excl(((ulong_t *)(void *)p) + (b >> 5), (b & 0x1f))
#define	test_and_clear_bit(p, b) \
	atomic_clear_long_excl(((ulong_t *)(void *)p) + (b >> 5), (b & 0x1f))
#endif

#define	atomic_cmpset_int(p, c, n) \
	((c == atomic_cas_uint(p, c, n)) ? 1 : 0)



/*
 * Notify host that there are data pending on our TX bufring.
 */
static __inline void
vmbus_chan_signal_tx(const struct vmbus_channel *chan)
{
	atomic_or_ulong(chan->ch_evtflag, chan->ch_evtflag_mask);
	if (chan->ch_txflags & VMBUS_CHAN_TXF_HASMNF) {
		atomic_or_uint(chan->ch_montrig, chan->ch_montrig_mask);
	} else {
		hv_status_t status =
		    hypercall_signal_event(chan->ch_monprm_dma.hv_paddr);
		if (status != HYPERCALL_STATUS_SUCCESS) {
			vmbus_chan_printf(chan,
			    "signal event failed ! status: 0x%x", status);
		}
	}
}

static void
vmbus_chan_ins_prilist(struct vmbus_softc *sc, struct vmbus_channel *chan)
{

	ASSERT(MUTEX_HELD(&sc->vmbus_prichan_lock));
	if (test_and_set_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_ONPRIL_SHIFT) == -1) {
		panic("channel %u is already on the prilist", chan->ch_id);
	}
	TAILQ_INSERT_TAIL(&sc->vmbus_prichans, chan, ch_prilink);
}

static void
vmbus_chan_rem_prilist(struct vmbus_softc *sc, struct vmbus_channel *chan)
{

	ASSERT(MUTEX_HELD(&sc->vmbus_prichan_lock));
	if (test_and_clear_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_ONPRIL_SHIFT) == -1) {
		panic("channel %u is not on the prilist", chan->ch_id);
	}
	TAILQ_REMOVE(&sc->vmbus_prichans, chan, ch_prilink);
}

static void
vmbus_chan_ins_sublist(struct vmbus_channel *prichan,
    struct vmbus_channel *chan)
{

	ASSERT(MUTEX_HELD(&prichan->ch_subchan_lock));

	if (test_and_set_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_ONSUBL_SHIFT) == -1) {
		panic("channel %u is already on the sublist %u",
		    prichan->ch_id, chan->ch_id);
	}
	TAILQ_INSERT_TAIL(&prichan->ch_subchans, chan, ch_sublink);

	/* Bump sub-channel count. */
	prichan->ch_subchan_cnt++;
}

static void
vmbus_chan_rem_sublist(struct vmbus_channel *prichan,
    struct vmbus_channel *chan)
{
	ASSERT(chan->ch_vmbus != NULL);
	ASSERT(MUTEX_HELD(&prichan->ch_subchan_lock));

	ASSERT3U(prichan->ch_subchan_cnt, >, 0);
	prichan->ch_subchan_cnt--;

	if (test_and_clear_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_ONSUBL_SHIFT) == -1) {
		panic("channel: %u is not on the sublist", chan->ch_id);
	}
	TAILQ_REMOVE(&prichan->ch_subchans, chan, ch_sublink);
}

static void
vmbus_chan_ins_list(struct vmbus_softc *sc, struct vmbus_channel *chan)
{

	ASSERT(MUTEX_HELD(&sc->vmbus_chan_lock));
	if (test_and_set_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_ONLIST_SHIFT) == -1) {
		panic("channel %u is already on the list", chan->ch_id);
	}
	TAILQ_INSERT_TAIL(&sc->vmbus_chans, chan, ch_link);
}

static void
vmbus_chan_rem_list(struct vmbus_softc *sc, struct vmbus_channel *chan)
{

	ASSERT(MUTEX_HELD(&sc->vmbus_chan_lock));
	if (test_and_clear_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_ONLIST_SHIFT) == -1) {
		panic("channel %u is not on the list", chan->ch_id);
	}
	TAILQ_REMOVE(&sc->vmbus_chans, chan, ch_link);
}

int
vmbus_chan_open(struct vmbus_channel *chan, int txbr_size, int rxbr_size,
    const void *udata, int udlen, vmbus_chan_callback_t cb, void *cbarg)
{
	struct vmbus_chan_br cbr;
	int error;

	/*
	 * Allocate the TX+RX bufrings.
	 */
	if (chan->ch_bufring != NULL)
		dev_err(chan->ch_dev, CE_WARN, "bufrings are allocated");
	ASSERT(chan->ch_bufring == NULL);
	chan->ch_bufring = hyperv_dmamem_alloc(chan->ch_dev,
	    PAGE_SIZE, 0, txbr_size + rxbr_size, &chan->ch_bufring_dma,
	    DDI_DMA_RDWR);
	if (chan->ch_bufring == NULL) {
		vmbus_chan_printf(chan, "bufring allocation failed");
		return (ENOMEM);
	}

	cbr.cbr = chan->ch_bufring;
	cbr.cbr_paddr = chan->ch_bufring_dma.hv_paddr;
	cbr.cbr_txsz = txbr_size;
	cbr.cbr_rxsz = rxbr_size;

	error = vmbus_chan_open_br(chan, &cbr, udata, udlen, cb, cbarg);
	if (error) {
		if (error == EISCONN) {
			/*
			 * XXX
			 * The bufring GPADL is still connected; abandon
			 * this bufring, instead of having mysterious
			 * crash or trashed data later on.
			 */
			vmbus_chan_printf(chan, "chan%u bufring GPADL "
			    "is still connected upon channel open error; "
			    "leak %d bytes memory", chan->ch_id,
			    txbr_size + rxbr_size);
		} else {
			hyperv_dmamem_free(&chan->ch_bufring_dma);
		}
		chan->ch_bufring = NULL;
	}
	return (error);
}

int
vmbus_chan_open_br(struct vmbus_channel *chan, const struct vmbus_chan_br *cbr,
    const void *udata, int udlen, vmbus_chan_callback_t cb, void *cbarg)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	const struct vmbus_message *msg;
	struct vmbus_chanmsg_chopen *req;
	struct vmbus_msghc *mh;
	uint32_t status;
	int error, txbr_size, rxbr_size;
	uint8_t *br;

	if (udlen > VMBUS_CHANMSG_CHOPEN_UDATA_SIZE) {
		vmbus_chan_printf(chan,
		    "invalid udata len %d for chan%u", udlen, chan->ch_id);
		return (EINVAL);
	}

	br = cbr->cbr;
	txbr_size = cbr->cbr_txsz;
	rxbr_size = cbr->cbr_rxsz;
	ASSERT0((txbr_size & PAGEOFFSET));
	ASSERT0((rxbr_size & PAGEOFFSET));
	ASSERT0((cbr->cbr_paddr & PAGEOFFSET));

	/*
	 * Zero out the TX/RX bufrings, in case that they were used before.
	 */
	(void) memset(br, 0, txbr_size + rxbr_size);

	if (test_and_set_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_OPENED_SHIFT) == -1) {
		panic("double-open chan %u", chan->ch_id);
	}

	chan->ch_cb = cb;
	chan->ch_cbarg = cbarg;

	vmbus_chan_update_evtflagcnt(sc, chan);

	chan->ch_tq = VMBUS_PCPU_GET(chan->ch_vmbus, event_tq, chan->ch_cpuid);
	if (chan->ch_flags & VMBUS_CHAN_FLAG_BATCHREAD)
		chan->ch_tqent_func =  vmbus_chan_task;
	else
		chan->ch_tqent_func =  vmbus_chan_task_nobatch;

	/* TX bufring comes first */
	vmbus_txbr_setup(&chan->ch_txbr, br, txbr_size);
	/* RX bufring immediately follows TX bufring */
	vmbus_rxbr_setup(&chan->ch_rxbr, (void *) (br + txbr_size), rxbr_size);

	/*
	 * Connect the bufrings, both RX and TX, to this channel.
	 */
	ASSERT0(chan->ch_bufring_gpadl);
	error = vmbus_chan_gpadl_connect(chan, cbr->cbr_paddr,
	    txbr_size + rxbr_size, &chan->ch_bufring_gpadl);
	if (error) {
		vmbus_chan_printf(chan,
		    "failed to connect bufring GPADL to chan%u", chan->ch_id);
		goto failed;
	}

	/*
	 * Install this channel, before it is opened, but after everything
	 * else has been setup.
	 */
	vmbus_chan_set_chmap(chan);

	/*
	 * Open channel w/ the bufring GPADL on the target CPU.
	 */
	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL) {
		vmbus_chan_printf(chan,
		    "can not get msg hypercall for chopen(chan%u)",
		    chan->ch_id);
		error = ENXIO;
		goto failed;
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHOPEN;
	req->chm_chanid = chan->ch_id;
	req->chm_openid = chan->ch_id;
	req->chm_gpadl = chan->ch_bufring_gpadl;
	req->chm_vcpuid = chan->ch_vcpuid;
	req->chm_txbr_pgcnt = txbr_size >> PAGESHIFT;
	if (udlen > 0)
		(void) memcpy(req->chm_udata, udata, udlen);

	error = vmbus_msghc_exec(sc, mh);
	if (error) {
		vmbus_chan_printf(chan,
		    "chopen(chan%u) msg hypercall exec failed: %d",
		    chan->ch_id, error);
		vmbus_msghc_put(sc, mh);
		goto failed;
	}

	for (;;) {
		msg = vmbus_msghc_poll_result(sc, mh);
		if (msg != NULL)
			break;
		if (vmbus_chan_is_revoked(chan)) {
			int i;

			/*
			 * NOTE:
			 * Hypervisor does _not_ send response CHOPEN to
			 * a revoked channel.
			 */
			vmbus_chan_printf(chan,
			    "chan%u is revoked, when it is being opened",
			    chan->ch_id);

			/*
			 * XXX
			 * Add extra delay before cancel the hypercall
			 * execution; mainly to close any possible
			 * CHRESCIND and CHOPEN_RESP races on the
			 * hypervisor side.
			 */
#define	REVOKE_LINGER	100
			for (i = 0; i < REVOKE_LINGER; ++i) {
				msg = vmbus_msghc_poll_result(sc, mh);
				if (msg != NULL)
					break;
				drv_usecwait(1000);
			}
#undef REVOKE_LINGER
			if (msg == NULL)
				vmbus_msghc_exec_cancel(sc, mh);
			break;
		}
		drv_usecwait(1000);
	}
	if (msg != NULL) {
		status = ((const struct vmbus_chanmsg_chopen_resp *)
		    msg->msg_data)->chm_status;
	} else {
		/* XXX any non-0 value is ok here. */
		status = 0xff;
	}

	vmbus_msghc_put(sc, mh);

	if (status == 0) {
		if (boothowto & RB_VERBOSE)
			vmbus_chan_printf(chan, "chan%u opened", chan->ch_id);
		return (0);
	}

	dev_err(sc->vmbus_dev, CE_WARN, "failed to open chan%u", chan->ch_id);
	error = ENXIO;

failed:
	vmbus_chan_clear_chmap(chan);
	if (chan->ch_bufring_gpadl != 0) {
		int error1;

		error1 = vmbus_chan_gpadl_disconnect(chan,
		    chan->ch_bufring_gpadl);
		if (error1) {
			/*
			 * Give caller a hint that the bufring GPADL is still
			 * connected.
			 */
			error = EISCONN;
		}
		chan->ch_bufring_gpadl = 0;
	}
	(void) test_and_clear_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_OPENED_SHIFT);
	return (error);
}

int
vmbus_chan_gpadl_connect(struct vmbus_channel *chan, paddr_t paddr,
    int size, uint32_t *gpadl0)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	struct vmbus_msghc *mh;
	struct vmbus_chanmsg_gpadl_conn *req;
	const struct vmbus_message *msg;
	size_t reqsz;
	uint32_t gpadl, status;
	int page_count, range_len, i, cnt, error;
	uint64_t page_id;

	ASSERT0(*gpadl0);

	/*
	 * Preliminary checks.
	 */

	ASSERT0((size & PAGEOFFSET));
	page_count = size >> PAGESHIFT;

	ASSERT0((paddr & PAGEOFFSET));
	page_id = paddr >> PAGESHIFT;

	range_len = offsetof(struct vmbus_gpa_range, gpa_page[page_count]);
	/*
	 * We don't support multiple GPA ranges.
	 */
	if (range_len > UINT16_MAX) {
		vmbus_chan_printf(chan, "GPA too large, %d pages",
		    page_count);
		return (EOPNOTSUPP);
	}

	/*
	 * Allocate GPADL id.
	 */
	gpadl = vmbus_gpadl_alloc(sc);

	/*
	 * Connect this GPADL to the target channel.
	 *
	 * NOTE:
	 * Since each message can only hold small set of page
	 * addresses, several messages may be required to
	 * complete the connection.
	 */
	if (page_count > VMBUS_CHANMSG_GPADL_CONN_PGMAX)
		cnt = VMBUS_CHANMSG_GPADL_CONN_PGMAX;
	else
		cnt = page_count;
	page_count -= cnt;

	reqsz = offsetof(struct vmbus_chanmsg_gpadl_conn,
	    chm_range.gpa_page[cnt]);
	mh = vmbus_msghc_get(sc, reqsz);
	if (mh == NULL) {
		vmbus_chan_printf(chan,
		    "can not get msg hypercall for gpadl_conn(chan%u)",
		    chan->ch_id);
		return (EIO);
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_GPADL_CONN;
	req->chm_chanid = chan->ch_id;
	req->chm_gpadl = gpadl;
	req->chm_range_len = range_len;
	req->chm_range_cnt = 1;
	req->chm_range.gpa_len = size;
	req->chm_range.gpa_ofs = 0;
	for (i = 0; i < cnt; ++i)
		req->chm_range.gpa_page[i] = page_id++;

	error = vmbus_msghc_exec(sc, mh);
	if (error) {
		vmbus_chan_printf(chan,
		    "gpadl_conn(chan%u) msg hypercall exec failed: %d",
		    chan->ch_id, error);
		vmbus_msghc_put(sc, mh);
		return (error);
	}

	while (page_count > 0) {
		struct vmbus_chanmsg_gpadl_subconn *subreq;

		if (page_count > VMBUS_CHANMSG_GPADL_SUBCONN_PGMAX)
			cnt = VMBUS_CHANMSG_GPADL_SUBCONN_PGMAX;
		else
			cnt = page_count;
		page_count -= cnt;

		reqsz = offsetof(struct vmbus_chanmsg_gpadl_subconn,
		    chm_gpa_page[cnt]);
		vmbus_msghc_reset(mh, reqsz);

		subreq = vmbus_msghc_dataptr(mh);
		subreq->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_GPADL_SUBCONN;
		subreq->chm_gpadl = gpadl;
		for (i = 0; i < cnt; ++i)
			subreq->chm_gpa_page[i] = page_id++;

		(void) vmbus_msghc_exec_noresult(mh);
	}

	ASSERT0(page_count);

	msg = vmbus_msghc_wait_result(sc, mh);

	status = ((const struct vmbus_chanmsg_gpadl_connresp *)
	    msg->msg_data)->chm_status;

	vmbus_msghc_put(sc, mh);

	if (status != 0) {
		vmbus_chan_printf(chan, "gpadl_conn(chan%u) failed: %u",
		    chan->ch_id, status);
		return (EIO);
	}

	/* Done; commit the GPADL id. */
	*gpadl0 = gpadl;
	if (boothowto & RB_VERBOSE)
		vmbus_chan_printf(chan, "gpadl_conn(chan%u) succeeded",
		    chan->ch_id);
	return (0);
}

static boolean_t
vmbus_chan_wait_revoke(const struct vmbus_channel *chan)
{
#define	WAIT_COUNT	200	/* 200ms */

	int i;

	for (i = 0; i < WAIT_COUNT; ++i) {
		if (vmbus_chan_is_revoked(chan))
			return (B_TRUE);
		/* Not sure about the context; use busy-wait. */
		drv_usecwait(1000);
	}
	return (B_FALSE);

#undef WAIT_COUNT
}

/*
 * Disconnect the GPA from the target channel
 */
int
vmbus_chan_gpadl_disconnect(struct vmbus_channel *chan, uint32_t gpadl)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	struct vmbus_msghc *mh;
	struct vmbus_chanmsg_gpadl_disconn *req;
	int error;

	ASSERT3U(gpadl, !=, 0);

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL) {
		vmbus_chan_printf(chan,
		    "can not get msg hypercall for gpadl_disconn(chan%u)",
		    chan->ch_id);
		return (EBUSY);
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_GPADL_DISCONN;
	req->chm_chanid = chan->ch_id;
	req->chm_gpadl = gpadl;

	error = vmbus_msghc_exec(sc, mh);
	if (error != 0) {
		vmbus_msghc_put(sc, mh);

		if (vmbus_chan_wait_revoke(chan)) {
			/*
			 * Error is benign; this channel is revoked,
			 * so this GPADL will not be touched anymore.
			 */
			vmbus_chan_printf(chan,
			    "gpadl_disconn(revoked chan%u) msg hypercall "
			    "exec failed: %d", chan->ch_id, error);
			return (0);
		}
		vmbus_chan_printf(chan,
		    "gpadl_disconn(chan%u) msg hypercall exec failed: %d",
		    chan->ch_id, error);
		return (error);
	}

	(void) vmbus_msghc_wait_result(sc, mh);
	/* Discard result; no useful information */
	vmbus_msghc_put(sc, mh);

	return (0);
}

static void
vmbus_chan_detach(struct vmbus_channel *chan)
{
	uint32_t refs;

	ASSERT3U(chan->ch_refs, >, 0);
	refs = atomic_dec_32_nv(&chan->ch_refs);
	if (VMBUS_CHAN_ISPRIMARY(chan)) {
		VERIFY0(refs);
	}
	if (refs == 0) {
		/*
		 * Detach the target channel.
		 */
		if (boothowto & RB_VERBOSE) {
			vmbus_chan_printf(chan, "chan%u detached",
			    chan->ch_id);
		}
		(void) ddi_taskq_dispatch(chan->ch_mgmt_tq,
		    chan->ch_detach_task, chan, DDI_SLEEP);
	}
}

static void
vmbus_chan_clrchmap_task(void *xchan)
{
	struct vmbus_channel *chan = xchan;
	/* Disable preemption */
	kpreempt_disable();
	chan->ch_vmbus->vmbus_chmap[chan->ch_id] = NULL;
	/* Enable preemption */
	kpreempt_enable();
}

static void
vmbus_chan_clear_chmap(struct vmbus_channel *chan)
{
	vmbus_chan_run_task(chan, vmbus_chan_clrchmap_task);
}

static void
vmbus_chan_set_chmap(struct vmbus_channel *chan)
{
	membar_sync();
	chan->ch_vmbus->vmbus_chmap[chan->ch_id] = chan;
}

static int
vmbus_chan_close_internal(struct vmbus_channel *chan)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	struct vmbus_msghc *mh;
	struct vmbus_chanmsg_chclose *req;
	uint32_t old_stflags;
	int error;

	/*
	 * NOTE:
	 * Sub-channels are closed upon their primary channel closing,
	 * so they can be closed even before they are opened.
	 */
	for (;;) {
		old_stflags = chan->ch_stflags;
		if (atomic_cas_32(&chan->ch_stflags, old_stflags,
		    old_stflags & ~VMBUS_CHAN_ST_OPENED) == old_stflags)
			break;
	}
	if ((old_stflags & VMBUS_CHAN_ST_OPENED) == 0) {
		/* Not opened yet; done */
		if (boothowto & RB_VERBOSE) {
			vmbus_chan_printf(chan, "chan%u not opened",
			    chan->ch_id);
		}
		return (0);
	}

	/*
	 * NOTE:
	 * Order is critical.  This channel _must_ be uninstalled first,
	 * else the channel task may be enqueued by the IDT after it has
	 * been drained.
	 */
	vmbus_chan_clear_chmap(chan);
	ddi_taskq_wait(chan->ch_tq); /* drain the queue first */
	chan->ch_tq = NULL;

	/*
	 * Close this channel.
	 */
	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL) {
		vmbus_chan_printf(chan,
		    "can not get msg hypercall for chclose(chan%u)",
		    chan->ch_id);
		error = ENXIO;
		goto disconnect;
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHCLOSE;
	req->chm_chanid = chan->ch_id;

	error = vmbus_msghc_exec_noresult(mh);
	vmbus_msghc_put(sc, mh);

	if (error) {
		vmbus_chan_printf(chan,
		    "chclose(chan%u) msg hypercall exec failed: %d",
		    chan->ch_id, error);
		goto disconnect;
	}

	if (boothowto & RB_VERBOSE)
		vmbus_chan_printf(chan, "chan%u closed", chan->ch_id);

disconnect:
	/*
	 * Disconnect the TX+RX bufrings from this channel.
	 */
	if (chan->ch_bufring_gpadl != 0) {
		int error1;

		error1 = vmbus_chan_gpadl_disconnect(chan,
		    chan->ch_bufring_gpadl);
		if (error1) {
			/*
			 * XXX
			 * The bufring GPADL is still connected; abandon
			 * this bufring, instead of having mysterious
			 * crash or trashed data later on.
			 */
			vmbus_chan_printf(chan, "chan%u bufring GPADL "
			    "is still connected after close", chan->ch_id);
			chan->ch_bufring = NULL;
			/*
			 * Give caller a hint that the bufring GPADL is
			 * still connected.
			 */
			error = EISCONN;
		}
		chan->ch_bufring_gpadl = 0;
	}

	/*
	 * Destroy the TX+RX bufrings.
	 */
	if (chan->ch_bufring != NULL) {
		hyperv_dmamem_free(&chan->ch_bufring_dma);
		chan->ch_bufring = NULL;
	}
	return (error);
}

int
vmbus_chan_close_direct(struct vmbus_channel *chan)
{
	int error;

	if (VMBUS_CHAN_ISPRIMARY(chan)) {
		struct vmbus_channel *subchan;

		/*
		 * All sub-channels _must_ have been closed, or are _not_
		 * opened at all.
		 */
		mutex_enter(&chan->ch_subchan_lock);
		TAILQ_FOREACH(subchan, &chan->ch_subchans, ch_sublink) {
			VERIFY0(subchan->ch_stflags & VMBUS_CHAN_ST_OPENED);
		}
		mutex_exit(&chan->ch_subchan_lock);
	}

	error = vmbus_chan_close_internal(chan);
	if (!VMBUS_CHAN_ISPRIMARY(chan)) {
		/*
		 * This sub-channel is referenced, when it is linked to
		 * the primary channel; drop that reference now.
		 */
		vmbus_chan_detach(chan);
	}
	return (error);
}

/*
 * Caller should make sure that all sub-channels have
 * been added to 'chan' and all to-be-closed channels
 * are not being opened.
 */
void
vmbus_chan_close(struct vmbus_channel *chan)
{
	int subchan_cnt;

	if (!VMBUS_CHAN_ISPRIMARY(chan)) {
		/*
		 * Sub-channel is closed when its primary channel
		 * is closed; done.
		 */
		return;
	}

	/*
	 * Close all sub-channels, if any.
	 */
	subchan_cnt = chan->ch_subchan_cnt;
	if (subchan_cnt > 0) {
		struct vmbus_channel **subchan;
		int i;

		subchan = vmbus_subchan_get(chan, subchan_cnt);
		for (i = 0; i < subchan_cnt; ++i) {
			(void) vmbus_chan_close_internal(subchan[i]);
			/*
			 * This sub-channel is referenced, when it is
			 * linked to the primary channel; drop that
			 * reference now.
			 */
			vmbus_chan_detach(subchan[i]);
		}
		vmbus_subchan_rel(subchan, subchan_cnt);
	}

	/* Then close the primary channel. */
	(void) vmbus_chan_close_internal(chan);
}

void
vmbus_chan_intr_drain(struct vmbus_channel *chan)
{
	ddi_taskq_wait(chan->ch_tq);
}

int
vmbus_chan_send(struct vmbus_channel *chan, uint16_t type, uint16_t flags,
    void *data, int dlen, uint64_t xactid)
{
	struct vmbus_chanpkt pkt;
	int pktlen, pad_pktlen, hlen, error;
	uint64_t pad = 0;
	struct iovec iov[3];
	boolean_t send_evt;

	hlen = sizeof (pkt);
	pktlen = hlen + dlen;
	pad_pktlen = VMBUS_CHANPKT_TOTLEN(pktlen);
	ASSERT3U(pad_pktlen, <=, vmbus_txbr_maxpktsz(&chan->ch_txbr));

	pkt.cp_hdr.cph_type = type;
	pkt.cp_hdr.cph_flags = flags;
	VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_hlen, hlen);
	VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_tlen, pad_pktlen);
	pkt.cp_hdr.cph_xactid = xactid;

	iov[0].iov_base = (void *)&pkt;
	iov[0].iov_len = hlen;
	iov[1].iov_base = data;
	iov[1].iov_len = dlen;
	iov[2].iov_base = (void *)&pad;
	iov[2].iov_len = pad_pktlen - pktlen;

	error = vmbus_txbr_write(&chan->ch_txbr, iov, 3, &send_evt);
	if (!error && send_evt)
		vmbus_chan_signal_tx(chan);
	return (error);
}

int
vmbus_chan_send_sglist(struct vmbus_channel *chan,
    struct vmbus_gpa sg[], int sglen, void *data, int dlen, uint64_t xactid)
{
	struct vmbus_chanpkt_sglist pkt;
	int pktlen, pad_pktlen, hlen, error;
	struct iovec iov[4];
	boolean_t send_evt;
	uint64_t pad = 0;

	hlen = offsetof(struct vmbus_chanpkt_sglist, cp_gpa[sglen]);
	pktlen = hlen + dlen;
	pad_pktlen = VMBUS_CHANPKT_TOTLEN(pktlen);
	ASSERT3U(pad_pktlen, <=, vmbus_txbr_maxpktsz(&chan->ch_txbr));

	pkt.cp_hdr.cph_type = VMBUS_CHANPKT_TYPE_GPA;
	pkt.cp_hdr.cph_flags = VMBUS_CHANPKT_FLAG_RC;
	VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_hlen, hlen);
	VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_tlen, pad_pktlen);
	pkt.cp_hdr.cph_xactid = xactid;
	pkt.cp_rsvd = 0;
	pkt.cp_gpa_cnt = sglen;

	iov[0].iov_base = (void *)&pkt;
	iov[0].iov_len = sizeof (pkt);
	iov[1].iov_base = (void *)sg;
	iov[1].iov_len = sizeof (struct vmbus_gpa) * sglen;
	iov[2].iov_base = data;
	iov[2].iov_len = dlen;
	iov[3].iov_base = (void *)&pad;
	iov[3].iov_len = pad_pktlen - pktlen;

	error = vmbus_txbr_write(&chan->ch_txbr, iov, 4, &send_evt);
	if (!error && send_evt)
		vmbus_chan_signal_tx(chan);
	return (error);
}

int
vmbus_chan_send_prplist(struct vmbus_channel *chan,
    struct vmbus_gpa_range *prp, int prp_cnt, void *data, int dlen,
    uint64_t xactid)
{
	struct vmbus_chanpkt_prplist pkt;
	int pktlen, pad_pktlen, hlen, error;
	struct iovec iov[4];
	boolean_t send_evt;
	uint64_t pad = 0;

	hlen = offsetof(struct vmbus_chanpkt_prplist,
	    cp_range[0].gpa_page[prp_cnt]);
	pktlen = hlen + dlen;
	pad_pktlen = VMBUS_CHANPKT_TOTLEN(pktlen);
	ASSERT3U(pad_pktlen, <=, vmbus_txbr_maxpktsz(&chan->ch_txbr));

	pkt.cp_hdr.cph_type = VMBUS_CHANPKT_TYPE_GPA;
	pkt.cp_hdr.cph_flags = VMBUS_CHANPKT_FLAG_RC;
	VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_hlen, hlen);
	VMBUS_CHANPKT_SETLEN(pkt.cp_hdr.cph_tlen, pad_pktlen);
	pkt.cp_hdr.cph_xactid = xactid;
	pkt.cp_rsvd = 0;
	pkt.cp_range_cnt = 1;

	iov[0].iov_base = (void *)&pkt;
	iov[0].iov_len = sizeof (pkt);
	iov[1].iov_base = (void *)prp;
	iov[1].iov_len = offsetof(struct vmbus_gpa_range, gpa_page[prp_cnt]);
	iov[2].iov_base = data;
	iov[2].iov_len = dlen;
	iov[3].iov_base = (void *)&pad;
	iov[3].iov_len = pad_pktlen - pktlen;

	error = vmbus_txbr_write(&chan->ch_txbr, iov, 4, &send_evt);
	if (!error && send_evt)
		vmbus_chan_signal_tx(chan);
	return (error);
}

int
vmbus_chan_recv(struct vmbus_channel *chan, void *data, int *dlen0,
    uint64_t *xactid)
{
	struct vmbus_chanpkt_hdr pkt;
	int error, dlen, hlen;

	error = vmbus_rxbr_peek(&chan->ch_rxbr, &pkt, sizeof (pkt));
	if (error)
		return (error);

	if (__predict_false(pkt.cph_hlen < VMBUS_CHANPKT_HLEN_MIN)) {
		vmbus_chan_printf(chan, "invalid hlen %u", pkt.cph_hlen);
		/* XXX this channel is dead actually. */
		return (EIO);
	}
	if (__predict_false(pkt.cph_hlen > pkt.cph_tlen)) {
		vmbus_chan_printf(chan, "invalid hlen %u and tlen %u",
		    pkt.cph_hlen, pkt.cph_tlen);
		/* XXX this channel is dead actually. */
		return (EIO);
	}

	hlen = VMBUS_CHANPKT_GETLEN(pkt.cph_hlen);
	dlen = VMBUS_CHANPKT_GETLEN(pkt.cph_tlen) - hlen;

	if (*dlen0 < dlen) {
		/* Return the size of this packet's data. */
		*dlen0 = dlen;
		return (ENOBUFS);
	}

	*xactid = pkt.cph_xactid;
	*dlen0 = dlen;

	/* Skip packet header */
	error = vmbus_rxbr_read(&chan->ch_rxbr, data, dlen, hlen);
	ASSERT0(error);

	return (0);
}

int
vmbus_chan_recv_pkt(struct vmbus_channel *chan,
    struct vmbus_chanpkt_hdr *pkt, int *pktlen0)
{
	int error, pktlen, pkt_hlen;

	pkt_hlen = sizeof (*pkt);
	error = vmbus_rxbr_peek(&chan->ch_rxbr, pkt, pkt_hlen);
	if (error)
		return (error);

	if (__predict_false(pkt->cph_hlen < VMBUS_CHANPKT_HLEN_MIN)) {
		vmbus_chan_printf(chan, "invalid hlen %u", pkt->cph_hlen);
		/* XXX this channel is dead actually. */
		return (EIO);
	}
	if (__predict_false(pkt->cph_hlen > pkt->cph_tlen)) {
		vmbus_chan_printf(chan, "invalid hlen %u and tlen %u",
		    pkt->cph_hlen, pkt->cph_tlen);
		/* XXX this channel is dead actually. */
		return (EIO);
	}

	pktlen = VMBUS_CHANPKT_GETLEN(pkt->cph_tlen);
	if (*pktlen0 < pktlen) {
		/* Return the size of this packet. */
		*pktlen0 = pktlen;
		return (ENOBUFS);
	}
	*pktlen0 = pktlen;

	/*
	 * Skip the fixed-size packet header, which has been filled
	 * by the above vmbus_rxbr_peek().
	 */
	error = vmbus_rxbr_read(&chan->ch_rxbr, pkt + 1,
	    pktlen - pkt_hlen, pkt_hlen);
	ASSERT(!error);

	return (0);
}

static void
vmbus_chan_task(void *xchan)
{
	struct vmbus_channel *chan = xchan;
	vmbus_chan_callback_t cb = chan->ch_cb;
	void *cbarg = chan->ch_cbarg;

	/*
	 * Optimize host to guest signaling by ensuring:
	 * 1. While reading the channel, we disable interrupts from
	 *    host.
	 * 2. Ensure that we process all posted messages from the host
	 *    before returning from this callback.
	 * 3. Once we return, enable signaling from the host. Once this
	 *    state is set we check to see if additional packets are
	 *    available to read. In this case we repeat the process.
	 *
	 * NOTE: Interrupt has been disabled in the ISR.
	 */
	for (;;) {
		uint32_t left;

		cb(chan, cbarg);

		left = vmbus_rxbr_intr_unmask(&chan->ch_rxbr);
		if (left == 0) {
			/* No more data in RX bufring; done */
			break;
		}
		vmbus_rxbr_intr_mask(&chan->ch_rxbr);
	}
}

static void
vmbus_chan_task_nobatch(void *xchan)
{
	struct vmbus_channel *chan = xchan;

	chan->ch_cb(chan, chan->ch_cbarg);
}

static void /* __inline (really ?) */
vmbus_event_flags_proc(struct vmbus_softc *sc, volatile ulong_t *event_flags,
    int flag_cnt)
{
	int f;

	for (f = 0; f < flag_cnt; ++f) {
		uint32_t chid_base;
		uint64_t flags;
		int chid_ofs;

		if (event_flags[f] == 0)
			continue;

		flags = atomic_swap_ulong(&event_flags[f], 0);
		chid_base = f << VMBUS_EVTFLAG_SHIFT;

		while ((chid_ofs = lowbit(flags)) != 0) {
			struct vmbus_channel *chan;

			--chid_ofs; /* NOTE: lowbit is 1-based */
			flags &= ~(1UL << chid_ofs);

			chan = sc->vmbus_chmap[chid_base + chid_ofs];
			if (__predict_false(chan == NULL)) {
				/* Channel is closed. */
				continue;
			}
			__compiler_membar();

			if (chan->ch_flags & VMBUS_CHAN_FLAG_BATCHREAD)
				vmbus_rxbr_intr_mask(&chan->ch_rxbr);
			if (ddi_taskq_dispatch(chan->ch_tq, chan->ch_tqent_func,
			    chan, 0) != DDI_SUCCESS) {
				vmbus_chan_printf(chan,
				    "Failed to dispatch ch_task, flag: %d, "
				    "flag_cnt: %d", f, flag_cnt);
			}
		}
	}
}

void
vmbus_event_proc(struct vmbus_softc *sc, int cpu)
{
	struct vmbus_evtflags *eventf;

	/*
	 * On Host with Win8 or above, the event page can be checked directly
	 * to get the id of the channel that has the pending interrupt.
	 */
	eventf = VMBUS_PCPU_GET(sc, event_flags, cpu) + VMBUS_SINT_MESSAGE;
	vmbus_event_flags_proc(sc, eventf->evt_flags,
	    VMBUS_PCPU_GET(sc, event_flags_cnt, cpu));
}

void
vmbus_event_proc_compat(struct vmbus_softc *sc, int cpu)
{
	struct vmbus_evtflags *eventf;

	eventf = VMBUS_PCPU_GET(sc, event_flags, cpu) + VMBUS_SINT_MESSAGE;
	if (atomic_clear_long_excl(&eventf->evt_flags[0], 0) == 0) {
		vmbus_event_flags_proc(sc, sc->vmbus_rx_evtflags,
		    VMBUS_CHAN_MAX_COMPAT >> VMBUS_EVTFLAG_SHIFT);
	}
}

static void
vmbus_chan_update_evtflagcnt(struct vmbus_softc *sc,
    const struct vmbus_channel *chan)
{
	volatile uint_t *flag_cnt_ptr;
	uint_t flag_cnt;

	flag_cnt = (chan->ch_id / VMBUS_EVTFLAG_LEN) + 1;
	flag_cnt_ptr = (uint_t *)VMBUS_PCPU_PTR(sc, event_flags_cnt,
	    chan->ch_cpuid);

	for (;;) {
		uint_t old_flag_cnt;

		old_flag_cnt = *flag_cnt_ptr;
		if (old_flag_cnt >= flag_cnt)
			break;
		if (atomic_cmpset_int(flag_cnt_ptr, old_flag_cnt, flag_cnt)) {
			if (boothowto & RB_VERBOSE) {
				vmbus_chan_printf(chan,
				    "chan%u update cpu%d flag_cnt to %d",
				    chan->ch_id, chan->ch_cpuid, flag_cnt);
			}
			break;
		}
	}
}

static struct vmbus_channel *
vmbus_chan_alloc(struct vmbus_softc *sc)
{
	struct vmbus_channel *chan;

	chan = (struct vmbus_channel *)kmem_zalloc(sizeof (*chan), KM_SLEEP);

	chan->ch_monprm = (struct hyperv_mon_param *)hyperv_dmamem_alloc(
	    sc->vmbus_dev, (uint64_t)HYPERCALL_PARAM_ALIGN, 0,
	    sizeof (struct hyperv_mon_param), &chan->ch_monprm_dma,
	    DDI_DMA_RDWR);
	if (chan->ch_monprm == NULL) {
		dev_err(sc->vmbus_dev, CE_WARN, "monprm dma alloc failed");
		kmem_free(chan, sizeof (*chan));
		return (NULL);
	}

	chan->ch_refs = 1;
	chan->ch_vmbus = sc;
	mutex_init(&chan->ch_subchan_lock, "vmbus subchan", MUTEX_DRIVER, NULL);
	mutex_init(&chan->ch_orphan_lock, "vmbus chorphan", MUTEX_DRIVER, NULL);
	cv_init(&chan->ch_subchan_cv, NULL, CV_DEFAULT, NULL);
	TAILQ_INIT(&chan->ch_subchans);
	vmbus_rxbr_init(&chan->ch_rxbr);
	vmbus_txbr_init(&chan->ch_txbr);

	return (chan);
}

static void
vmbus_chan_free(struct vmbus_channel *chan)
{

	ASSERT(TAILQ_EMPTY(&chan->ch_subchans) && chan->ch_subchan_cnt == 0);
	    /* ("still owns sub-channels"); */
	ASSERT((chan->ch_stflags &
	    (VMBUS_CHAN_ST_OPENED |
	    VMBUS_CHAN_ST_ONPRIL |
	    VMBUS_CHAN_ST_ONSUBL |
	    VMBUS_CHAN_ST_ONLIST)) == 0);
	ASSERT3P(chan->ch_orphan_xact, ==, NULL);
	ASSERT0(chan->ch_refs);

	hyperv_dmamem_free(&chan->ch_monprm_dma);
	mutex_destroy(&chan->ch_subchan_lock);
	mutex_destroy(&chan->ch_orphan_lock);
	cv_destroy(&chan->ch_subchan_cv);
	vmbus_rxbr_deinit(&chan->ch_rxbr);
	vmbus_txbr_deinit(&chan->ch_txbr);
	kmem_free(chan, sizeof (*chan));
}

static int
vmbus_chan_add(struct vmbus_channel *newchan)
{
	struct vmbus_softc *sc = newchan->ch_vmbus;
	struct vmbus_channel *prichan;

	if (newchan->ch_id == 0) {
		/*
		 * XXX
		 * Chan0 will neither be processed nor should be offered;
		 * skip it.
		 */
		dev_err(sc->vmbus_dev, CE_WARN, "got chan0 offer, discard");
		return (EINVAL);
	} else if (newchan->ch_id >= VMBUS_CHAN_MAX) {
		dev_err(sc->vmbus_dev, CE_WARN, "invalid chan%u offer",
		    newchan->ch_id);
		return (EINVAL);
	}

	mutex_enter(&sc->vmbus_prichan_lock);
	TAILQ_FOREACH(prichan, &sc->vmbus_prichans, ch_prilink) {
		/*
		 * Sub-channel will have the same type GUID and instance
		 * GUID as its primary channel.
		 */
		if (memcmp(&prichan->ch_guid_type, &newchan->ch_guid_type,
		    sizeof (struct hyperv_guid)) == 0 &&
		    memcmp(&prichan->ch_guid_inst, &newchan->ch_guid_inst,
		    sizeof (struct hyperv_guid)) == 0)
			break;
	}
	if (VMBUS_CHAN_ISPRIMARY(newchan)) {
		if (prichan == NULL) {
			/* Install the new primary channel */
			vmbus_chan_ins_prilist(sc, newchan);
			mutex_exit(&sc->vmbus_prichan_lock);
			goto done;
		} else {
			mutex_exit(&sc->vmbus_prichan_lock);
			dev_err(sc->vmbus_dev, CE_WARN,
			    "duplicated primary chan%u", newchan->ch_id);
			return (EINVAL);
		}
	} else { /* Sub-channel */
		if (prichan == NULL) {
			mutex_exit(&sc->vmbus_prichan_lock);
			dev_err(sc->vmbus_dev, CE_WARN,
			    "no primary chan for chan%u", newchan->ch_id);
			return (EINVAL);
		}
		/*
		 * Found the primary channel for this sub-channel and
		 * move on.
		 *
		 * XXX refcnt prichan
		 */
	}
	mutex_exit(&sc->vmbus_prichan_lock);

	/*
	 * This is a sub-channel; link it with the primary channel.
	 */
	if (VMBUS_CHAN_ISPRIMARY(newchan)) {
		dev_err(sc->vmbus_dev, CE_WARN,
		    "new channel is not sub-channel");
	}
	ASSERT(!VMBUS_CHAN_ISPRIMARY(newchan));
	if (prichan == NULL)
		dev_err(sc->vmbus_dev, CE_WARN, "no primary channel");
	ASSERT(prichan != NULL);

	/*
	 * Reference count this sub-channel; it will be dereferenced
	 * when this sub-channel is closed.
	 */
	ASSERT3U(newchan->ch_refs, ==, 1);
	atomic_inc_32(&newchan->ch_refs);

	newchan->ch_prichan = prichan;
	newchan->ch_dev = prichan->ch_dev;

	mutex_enter(&prichan->ch_subchan_lock);
	vmbus_chan_ins_sublist(prichan, newchan);
	mutex_exit(&prichan->ch_subchan_lock);
	/*
	 * Notify anyone that is interested in this sub-channel,
	 * after this sub-channel is setup.
	 */
	cv_broadcast(&prichan->ch_subchan_cv);
done:
	/*
	 * Hook this channel up for later revocation.
	 */
	mutex_enter(&sc->vmbus_chan_lock);
	vmbus_chan_ins_list(sc, newchan);
	mutex_exit(&sc->vmbus_chan_lock);

	if (boothowto & RB_VERBOSE) {
		vmbus_chan_printf(newchan, "chan%u subidx%u offer",
		    newchan->ch_id, newchan->ch_subidx);
	}

	/* Select default cpu for this channel. */
	vmbus_chan_cpu_default(newchan);

	return (0);
}

void
vmbus_chan_cpu_set(struct vmbus_channel *chan, int cpu)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	/* ASSERT(cpu >= 0 && cpu < mp_ncpus);  ("invalid cpu %d", cpu)); */
	ASSERT(cpu >= 0 && cpu < ncpus);

	if (sc->vmbus_version == VMBUS_VERSION_WS2008 ||
	    sc->vmbus_version == VMBUS_VERSION_WIN7) {
		/* Only cpu0 is supported */
		cpu = 0;
	}

	chan->ch_cpuid = cpu;
	chan->ch_vcpuid = VMBUS_PCPU_GET(sc, vcpuid, cpu);

	if (boothowto & RB_VERBOSE) {
		vmbus_chan_printf(chan,
		    "chan%u: assigned to cpu%u [vcpu%u]",
		    chan->ch_id, chan->ch_cpuid, chan->ch_vcpuid);
	}
}

void
vmbus_chan_cpu_rr(struct vmbus_channel *chan)
{
	static uint32_t vmbus_chan_nextcpu;
	int cpu;

	/* cpu = atomic_fetchadd_int(&vmbus_chan_nextcpu, 1) % NCPU; */
	cpu = (atomic_inc_32_nv(
	    (volatile uint32_t *)&vmbus_chan_nextcpu) - 1) % ncpus_online;
	vmbus_chan_cpu_set(chan, cpu);
}

static void
vmbus_chan_cpu_default(struct vmbus_channel *chan)
{
	/*
	 * By default, pin the channel to cpu0.  Devices having
	 * special channel-cpu mapping requirement should call
	 * vmbus_chan_cpu_{set,rr}().
	 */
	vmbus_chan_cpu_set(chan, 0);
}

static void
vmbus_chan_msgproc_choffer(struct vmbus_softc *sc,
    const struct vmbus_message *msg)
{
	const struct vmbus_chanmsg_choffer *offer;
	struct vmbus_channel *chan;
	task_func_t *detach_fn, *attach_fn;
	int error;

	offer = (const struct vmbus_chanmsg_choffer *)msg->msg_data;

	chan = vmbus_chan_alloc(sc);
	if (chan == NULL) {
		dev_err(sc->vmbus_dev, CE_WARN, "allocate chan%u failed",
		    offer->chm_chanid);
		return;
	}

	chan->ch_id = offer->chm_chanid;
	chan->ch_subidx = offer->chm_subidx;
	chan->ch_guid_type = offer->chm_chtype;
	chan->ch_guid_inst = offer->chm_chinst;

	/* Batch reading is on by default */
	chan->ch_flags |= VMBUS_CHAN_FLAG_BATCHREAD;

	chan->ch_monprm->mp_connid = VMBUS_CONNID_EVENT;
	if (sc->vmbus_version != VMBUS_VERSION_WS2008)
		chan->ch_monprm->mp_connid = offer->chm_connid;

	if (offer->chm_flags1 & VMBUS_CHOFFER_FLAG1_HASMNF) {
		int trig_idx;

		/*
		 * Setup MNF stuffs.
		 */
		chan->ch_txflags |= VMBUS_CHAN_TXF_HASMNF;

		trig_idx = offer->chm_montrig / VMBUS_MONTRIG_LEN;
		if (trig_idx >= VMBUS_MONTRIGS_MAX)
			panic("invalid monitor trigger %u", offer->chm_montrig);
		chan->ch_montrig =
		    &sc->vmbus_mnf2->mnf_trigs[trig_idx].mt_pending;

		chan->ch_montrig_mask =
		    1 << (offer->chm_montrig % VMBUS_MONTRIG_LEN);
	}

	/*
	 * Setup event flag.
	 */
	chan->ch_evtflag =
	    &sc->vmbus_tx_evtflags[chan->ch_id >> VMBUS_EVTFLAG_SHIFT];
	chan->ch_evtflag_mask = 1UL << (chan->ch_id & VMBUS_EVTFLAG_MASK);

	/*
	 * Setup attach and detach tasks.
	 */
	if (VMBUS_CHAN_ISPRIMARY(chan)) {
		chan->ch_mgmt_tq = sc->vmbus_devtq;
		attach_fn = vmbus_prichan_attach_task;
		detach_fn = vmbus_prichan_detach_task;
	} else {
		chan->ch_mgmt_tq = sc->vmbus_subchtq;
		attach_fn = vmbus_subchan_attach_task;
		detach_fn = vmbus_subchan_detach_task;
	}
	chan->ch_attach_task = attach_fn;
	chan->ch_detach_task = detach_fn;

	error = vmbus_chan_add(chan);
	if (error) {
		dev_err(sc->vmbus_dev, CE_WARN, "add chan%u failed: %d",
		    chan->ch_id, error);
		atomic_dec_32(&chan->ch_refs);
		vmbus_chan_free(chan);
		return;
	}
	(void) ddi_taskq_dispatch(chan->ch_mgmt_tq, chan->ch_attach_task,
	    chan, 0);
}

static void
vmbus_chan_msgproc_chrescind(struct vmbus_softc *sc,
    const struct vmbus_message *msg)
{
	const struct vmbus_chanmsg_chrescind *note;
	struct vmbus_channel *chan;

	note = (const struct vmbus_chanmsg_chrescind *)msg->msg_data;
	if (note->chm_chanid > VMBUS_CHAN_MAX) {
		dev_err(sc->vmbus_dev, CE_WARN, "invalid revoked chan%u",
		    note->chm_chanid);
		return;
	}

	/*
	 * Find and remove the target channel from the channel list.
	 */
	mutex_enter(&sc->vmbus_chan_lock);
	TAILQ_FOREACH(chan, &sc->vmbus_chans, ch_link) {
		if (chan->ch_id == note->chm_chanid)
			break;
	}
	if (chan == NULL) {
		mutex_exit(&sc->vmbus_chan_lock);
		dev_err(sc->vmbus_dev, CE_WARN, "chan%u is not offered",
		    note->chm_chanid);
		return;
	}
	vmbus_chan_rem_list(sc, chan);
	mutex_exit(&sc->vmbus_chan_lock);

	if (VMBUS_CHAN_ISPRIMARY(chan)) {
		/*
		 * The target channel is a primary channel; remove the
		 * target channel from the primary channel list now,
		 * instead of later, so that it will not be found by
		 * other sub-channel offers, which are processed in
		 * this thread.
		 */
		mutex_enter(&sc->vmbus_prichan_lock);
		vmbus_chan_rem_prilist(sc, chan);
		mutex_exit(&sc->vmbus_prichan_lock);
	}

	/*
	 * NOTE:
	 * The following processing order is critical:
	 * Set the REVOKED state flag before orphaning the installed xact.
	 */

	if (test_and_set_bit(&chan->ch_stflags,
	    VMBUS_CHAN_ST_REVOKED_SHIFT) == -1)
		panic("channel has already been revoked");

	mutex_enter(&chan->ch_orphan_lock);
	if (chan->ch_orphan_xact != NULL)
		(void) vmbus_xact_ctx_orphan(chan->ch_orphan_xact);
	mutex_exit(&chan->ch_orphan_lock);

	if (boothowto & RB_VERBOSE)
		vmbus_chan_printf(chan, "chan%u rescinded", note->chm_chanid);

	vmbus_chan_detach(chan);
}

static int
vmbus_chan_release(struct vmbus_channel *chan)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	struct vmbus_chanmsg_chfree *req;
	struct vmbus_msghc *mh;
	int error;

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL) {
		vmbus_chan_printf(chan,
		    "can not get msg hypercall for chfree(chan%u)",
		    chan->ch_id);
		return (ENXIO);
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHFREE;
	req->chm_chanid = chan->ch_id;

	error = vmbus_msghc_exec_noresult(mh);
	vmbus_msghc_put(sc, mh);

	if (error) {
		vmbus_chan_printf(chan,
		    "chfree(chan%u) msg hypercall exec failed: %d",
		    chan->ch_id, error);
	} else {
		if (boothowto & RB_VERBOSE)
			vmbus_chan_printf(chan, "chan%u freed", chan->ch_id);
	}
	return (error);
}

static void
vmbus_prichan_detach_task(void *xchan)
{
	struct vmbus_channel *chan = xchan;

	ASSERT(VMBUS_CHAN_ISPRIMARY(chan));
	    /* ("chan%u is not primary channel", chan->ch_id); */

	/* Delete and detach the device associated with this channel. */
	(void) vmbus_delete_child(chan);

	/* Release this channel (back to vmbus). */
	(void) vmbus_chan_release(chan);

	/* Free this channel's resource. */
	vmbus_chan_free(chan);
}

static void
vmbus_subchan_detach_task(void *xchan)
{
	struct vmbus_channel *chan = xchan;
	struct vmbus_channel *pri_chan = chan->ch_prichan;

	ASSERT(!VMBUS_CHAN_ISPRIMARY(chan));
	    /* ("chan%u is primary channel", chan->ch_id); */

	/* Release this channel (back to vmbus). */
	(void) vmbus_chan_release(chan);

	/* Unlink from its primary channel's sub-channel list. */
	mutex_enter(&pri_chan->ch_subchan_lock);
	vmbus_chan_rem_sublist(pri_chan, chan);
	mutex_exit(&pri_chan->ch_subchan_lock);
	/* Notify anyone that is waiting for this sub-channel to vanish. */
	cv_broadcast(&pri_chan->ch_subchan_cv);

	/* Free this channel's resource. */
	vmbus_chan_free(chan);
}

static void
vmbus_prichan_attach_task(void *xchan)
{

	/*
	 * Add device for this primary channel.
	 */
	(void) vmbus_add_child(xchan);
}

/* ARGSUSED */
static void
vmbus_subchan_attach_task(void *xchan)
{
}

void
vmbus_chan_destroy_all(struct vmbus_softc *sc)
{

	/*
	 * Detach all devices and destroy the corresponding primary
	 * channels.
	 */
	for (;;) {
		struct vmbus_channel *chan;

		mutex_enter(&sc->vmbus_chan_lock);
		TAILQ_FOREACH(chan, &sc->vmbus_chans, ch_link) {
			if (VMBUS_CHAN_ISPRIMARY(chan))
				break;
		}
		if (chan == NULL) {
			/* No more primary channels; done. */
			mutex_exit(&sc->vmbus_chan_lock);
			break;
		}
		vmbus_chan_rem_list(sc, chan);
		mutex_exit(&sc->vmbus_chan_lock);

		mutex_enter(&sc->vmbus_prichan_lock);
		vmbus_chan_rem_prilist(sc, chan);
		mutex_exit(&sc->vmbus_prichan_lock);

		(void) ddi_taskq_dispatch(chan->ch_mgmt_tq,
		    chan->ch_detach_task, chan, 0);
	}
}

struct vmbus_channel **
vmbus_subchan_get(struct vmbus_channel *pri_chan, int subchan_cnt)
{
	struct vmbus_channel **ret, *chan;
	int i;

	ASSERT(subchan_cnt > 0);
	/* ("invalid sub-channel count %d", subchan_cnt); */

	ret = kmem_alloc(subchan_cnt * sizeof (struct vmbus_channel *),
	    KM_SLEEP);

	mutex_enter(&pri_chan->ch_subchan_lock);

	while (pri_chan->ch_subchan_cnt < subchan_cnt)
		cv_wait(&pri_chan->ch_subchan_cv, &pri_chan->ch_subchan_lock);

	i = 0;
	TAILQ_FOREACH(chan, &pri_chan->ch_subchans, ch_sublink) {
		/* TODO: refcnt chan */
		ret[i] = chan;

		++i;
		if (i == subchan_cnt)
			break;
	}
	ASSERT3U(i, ==, subchan_cnt);

	mutex_exit(&pri_chan->ch_subchan_lock);

	return (ret);
}

void
vmbus_subchan_rel(struct vmbus_channel **subchan, int subchan_cnt)
{
	kmem_free(subchan, (subchan_cnt * sizeof (*subchan)));
}

void
vmbus_subchan_drain(struct vmbus_channel *pri_chan)
{
	mutex_enter(&pri_chan->ch_subchan_lock);
	while (pri_chan->ch_subchan_cnt > 0)
		cv_wait(&pri_chan->ch_subchan_cv, &pri_chan->ch_subchan_lock);
	mutex_exit(&pri_chan->ch_subchan_lock);
}

void
vmbus_chan_msgproc(struct vmbus_softc *sc, const struct vmbus_message *msg)
{
	vmbus_chanmsg_proc_t msg_proc;
	uint32_t msg_type;

	msg_type = ((const struct vmbus_chanmsg_hdr *)msg->msg_data)->chm_type;
	ASSERT(msg_type < VMBUS_CHANMSG_TYPE_MAX);

	msg_proc = vmbus_chan_msgprocs[msg_type];
	if (msg_proc != NULL)
		msg_proc(sc, msg);
}

void
vmbus_chan_set_readbatch(struct vmbus_channel *chan, boolean_t on)
{
	if (!on)
		chan->ch_flags &= ~VMBUS_CHAN_FLAG_BATCHREAD;
	else
		chan->ch_flags |= VMBUS_CHAN_FLAG_BATCHREAD;
}

uint32_t
vmbus_chan_id(const struct vmbus_channel *chan)
{
	return (chan->ch_id);
}

uint32_t
vmbus_chan_subidx(const struct vmbus_channel *chan)
{
	return (chan->ch_subidx);
}

boolean_t
vmbus_chan_is_primary(const struct vmbus_channel *chan)
{
	if (VMBUS_CHAN_ISPRIMARY(chan))
		return (B_TRUE);
	else
		return (B_FALSE);
}

const struct hyperv_guid *
vmbus_chan_guid_inst(const struct vmbus_channel *chan)
{
	return (&chan->ch_guid_inst);
}

int
vmbus_chan_prplist_nelem(int br_size, int prpcnt_max, int dlen_max)
{
	int elem_size;

	elem_size = offsetof(struct vmbus_chanpkt_prplist,
	    cp_range[0].gpa_page[prpcnt_max]);
	elem_size += dlen_max;
	elem_size = VMBUS_CHANPKT_TOTLEN(elem_size);

	return (vmbus_br_nelem(br_size, elem_size));
}

boolean_t
vmbus_chan_tx_empty(const struct vmbus_channel *chan)
{
	return (vmbus_txbr_empty(&chan->ch_txbr));
}

boolean_t
vmbus_chan_rx_empty(const struct vmbus_channel *chan)
{
	return (vmbus_rxbr_empty(&chan->ch_rxbr));
}

void
vmbus_chan_run_task(struct vmbus_channel *chan, task_func_t *task)
{
	if (ddi_taskq_dispatch(chan->ch_tq, task, chan, 0) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_PANIC,
		    "Failed to run task: %p", (void *)task);
	} else {
		ddi_taskq_wait(chan->ch_tq);
	}
}

ddi_taskq_t *
vmbus_chan_mgmt_tq(const struct vmbus_channel *chan)
{

	return (chan->ch_mgmt_tq);
}

boolean_t
vmbus_chan_is_revoked(const struct vmbus_channel *chan)
{

	if (chan->ch_stflags & VMBUS_CHAN_ST_REVOKED)
		return (B_TRUE);
	return (B_FALSE);
}

void
vmbus_chan_set_orphan(struct vmbus_channel *chan, struct vmbus_xact_ctx *xact)
{

	mutex_enter(&chan->ch_orphan_lock);
	chan->ch_orphan_xact = xact;
	mutex_exit(&chan->ch_orphan_lock);
}

void
vmbus_chan_unset_orphan(struct vmbus_channel *chan)
{

	mutex_enter(&chan->ch_orphan_lock);
	chan->ch_orphan_xact = NULL;
	mutex_exit(&chan->ch_orphan_lock);
}

const void *
vmbus_chan_xact_wait(const struct vmbus_channel *chan,
    struct vmbus_xact *xact, size_t *resp_len, boolean_t can_sleep)
{
	const void *ret;

	if (can_sleep)
		ret = vmbus_xact_wait(xact, resp_len);
	else
		ret = vmbus_xact_busywait(xact, resp_len);
	if (vmbus_chan_is_revoked(chan)) {
		/*
		 * This xact probably is interrupted, and the
		 * interruption can race the reply reception,
		 * so we have to make sure that there are nothing
		 * left on the RX bufring, i.e. this xact will
		 * not be touched, once this function returns.
		 *
		 * Since the hypervisor will not put more data
		 * onto the RX bufring once the channel is revoked,
		 * the following loop will be terminated, once all
		 * data are drained by the driver's channel
		 * callback.
		 */
		while (!vmbus_chan_rx_empty(chan)) {
			if (can_sleep)
				delay(1);
			else
				drv_usecwait(1000);
		}
	}
	return (ret);
}
