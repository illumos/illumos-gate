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

/*
 * VM Bus Driver Implementation
 */
#include <sys/hyperv.h>
#include <sys/vmbus_xact.h>
#include <vmbus/hyperv_var.h>
#include <vmbus/vmbus_var.h>
#include <vmbus/vmbus_reg.h>
#include <vmbus/vmbus_chanvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/callo.h>
#include <sys/sysmacros.h>
#include <sys/smp_impldefs.h>
#include <sys/x_call.h>
#include <sys/x86_archext.h>
#include <sys/sunndi.h>

#define	curcpu	CPU->cpu_id

#define	VMBUS_GPADL_START		0xe1e10

struct vmbus_msghc {
	struct vmbus_xact		*mh_xact;
	struct hypercall_postmsg_in	mh_inprm_save;
};

kmutex_t vmbus_lock;


static int			vmbus_attach(dev_info_t *, ddi_attach_cmd_t);
static int			vmbus_detach(dev_info_t *, ddi_detach_cmd_t);
static int			vmbus_init(struct vmbus_softc *);
static int			vmbus_connect(struct vmbus_softc *, uint32_t);
static int			vmbus_req_channels(struct vmbus_softc *sc);
static void			vmbus_disconnect(struct vmbus_softc *);
static int			vmbus_scan(struct vmbus_softc *);
static void			vmbus_scan_teardown(struct vmbus_softc *);
static void			vmbus_scan_done(struct vmbus_softc *,
				    const struct vmbus_message *);
static void			vmbus_chanmsg_handle(struct vmbus_softc *,
				    const struct vmbus_message *);
static void			vmbus_msg_task(void *);
static void			vmbus_synic_setup(void *);
static void			vmbus_synic_teardown(void *);
static int			vmbus_dma_alloc(struct vmbus_softc *);
static void			vmbus_dma_free(struct vmbus_softc *);
static int			vmbus_intr_setup(struct vmbus_softc *);
static void			vmbus_intr_teardown(struct vmbus_softc *);
static int			vmbus_doattach(struct vmbus_softc *);
static void			vmbus_event_proc_dummy(struct vmbus_softc *,
				    int);

typedef void (*vmbus_xcall_func_t)(void *);
static void			vmbus_xcall(vmbus_xcall_func_t, void *);

static void			*vmbus_state = NULL;
static struct vmbus_softc	*vmbus_sc;

static const uint32_t		vmbus_version[] = {
	VMBUS_VERSION_WIN8_1,
	VMBUS_VERSION_WIN8,
	VMBUS_VERSION_WIN7,
	VMBUS_VERSION_WS2008
};

static const vmbus_chanmsg_proc_t
vmbus_chanmsg_handlers[VMBUS_CHANMSG_TYPE_MAX] = {
	VMBUS_CHANMSG_PROC(CHOFFER_DONE, vmbus_scan_done),
	VMBUS_CHANMSG_PROC_WAKEUP(CONNECT_RESP)
};

static __inline struct vmbus_softc *
vmbus_get_softc(void)
{
	return (vmbus_sc);
}

void
vmbus_msghc_reset(struct vmbus_msghc *mh, size_t dsize)
{
	struct hypercall_postmsg_in *inprm;

	if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
		panic("invalid data size %llu", (u_longlong_t)dsize);

	inprm = vmbus_xact_req_data(mh->mh_xact);
	(void) memset(inprm, 0, HYPERCALL_POSTMSGIN_SIZE);
	inprm->hc_connid = VMBUS_CONNID_MESSAGE;
	inprm->hc_msgtype = HYPERV_MSGTYPE_CHANNEL;
	inprm->hc_dsize = (uint32_t)dsize;
}

struct vmbus_msghc *
vmbus_msghc_get(struct vmbus_softc *sc, size_t dsize)
{
	struct vmbus_msghc *mh = NULL;
	struct vmbus_xact *xact;

	if (dsize > HYPERCALL_POSTMSGIN_DSIZE_MAX)
		panic("invalid data size %llu", (u_longlong_t)dsize);

	xact = vmbus_xact_get(sc->vmbus_xc,
	    dsize + offsetof(struct hypercall_postmsg_in, hc_data[0]));
	if (xact == NULL)
		return (NULL);

	mh = vmbus_xact_priv(xact, sizeof (*mh));
	mh->mh_xact = xact;

	vmbus_msghc_reset(mh, dsize);
	return (mh);
}

/* ARGSUSED */
void
vmbus_msghc_put(struct vmbus_softc *sc, struct vmbus_msghc *mh)
{

	vmbus_xact_put(mh->mh_xact);
}

void *
vmbus_msghc_dataptr(struct vmbus_msghc *mh)
{
	struct hypercall_postmsg_in *inprm;

	inprm = vmbus_xact_req_data(mh->mh_xact);
	return (inprm->hc_data);
}

int
vmbus_msghc_exec_noresult(struct vmbus_msghc *mh)
{
	clock_t delay_us = MILLISEC;
	struct hypercall_postmsg_in *inprm;
	paddr_t inprm_paddr;
	int i;

	inprm = vmbus_xact_req_data(mh->mh_xact);
	inprm_paddr = vmbus_xact_req_paddr(mh->mh_xact);

	/*
	 * Save the input parameter so that we could restore the input
	 * parameter if the Hypercall failed.
	 *
	 * XXX
	 * Is this really necessary?!  i.e. Will the Hypercall ever
	 * overwrite the input parameter?
	 */
	(void) memcpy(&mh->mh_inprm_save, inprm, HYPERCALL_POSTMSGIN_SIZE);

	/*
	 * In order to cope with transient failures, e.g. insufficient
	 * resources on host side, we retry the post message Hypercall
	 * several times.  20 retries seem sufficient.
	 */
#define	HC_RETRY_MAX	20

	for (i = 0; i < HC_RETRY_MAX; ++i) {
		uint64_t status;

		status = hypercall_post_message(inprm_paddr);
		if (status == HYPERCALL_STATUS_SUCCESS)
			return (0);

		drv_usecwait(delay_us);
		if (delay_us < MICROSEC * 2)
			delay_us *= 2;

		/* Restore input parameter and try again */
		(void) memcpy(inprm, &mh->mh_inprm_save,
		    HYPERCALL_POSTMSGIN_SIZE);
	}

#undef HC_RETRY_MAX

	return (EIO);
}

/* ARGSUSED */
int
vmbus_msghc_exec(struct vmbus_softc *sc, struct vmbus_msghc *mh)
{
	int error;

	vmbus_xact_activate(mh->mh_xact);
	error = vmbus_msghc_exec_noresult(mh);
	if (error)
		vmbus_xact_deactivate(mh->mh_xact);
	return (error);
}

/* ARGSUSED */
void
vmbus_msghc_exec_cancel(struct vmbus_softc *sc, struct vmbus_msghc *mh)
{

	vmbus_xact_deactivate(mh->mh_xact);
}

/* ARGSUSED */
const struct vmbus_message *
vmbus_msghc_wait_result(struct vmbus_softc *sc, struct vmbus_msghc *mh)
{
	size_t resp_len;

	return (vmbus_xact_wait(mh->mh_xact, &resp_len));
}

/* ARGSUSED */
const struct vmbus_message *
vmbus_msghc_poll_result(struct vmbus_softc *sc, struct vmbus_msghc *mh)
{
	size_t resp_len;

	return (vmbus_xact_poll(mh->mh_xact, &resp_len));
}

void
vmbus_msghc_wakeup(struct vmbus_softc *sc, const struct vmbus_message *msg)
{
	vmbus_xact_ctx_wakeup(sc->vmbus_xc, msg, sizeof (*msg));
}

uint32_t
vmbus_gpadl_alloc(struct vmbus_softc *sc)
{
	uint32_t gpadl;

again:
	gpadl = atomic_inc_32_nv(&sc->vmbus_gpadl) - 1;
	if (gpadl == 0)
		goto again;
	return (gpadl);
}

static int
vmbus_connect(struct vmbus_softc *sc, uint32_t version)
{
	struct vmbus_chanmsg_connect *req;
	const struct vmbus_message *msg;
	struct vmbus_msghc *mh;
	int error, done = 0;

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL)
		return (ENXIO);

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CONNECT;
	req->chm_ver = version;
	req->chm_evtflags = sc->vmbus_evtflags_dma.hv_paddr;
	req->chm_mnf1 = sc->vmbus_mnf1_dma.hv_paddr;
	req->chm_mnf2 = sc->vmbus_mnf2_dma.hv_paddr;

	error = vmbus_msghc_exec(sc, mh);
	if (error) {
		vmbus_msghc_put(sc, mh);
		return (error);
	}

	msg = vmbus_msghc_wait_result(sc, mh);
	done = ((const struct vmbus_chanmsg_connect_resp *)
	    msg->msg_data)->chm_done;

	vmbus_msghc_put(sc, mh);

	return (done ? 0 : EOPNOTSUPP);
}

static int
vmbus_init(struct vmbus_softc *sc)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(vmbus_version); ++i) {
		int error;

		error = vmbus_connect(sc, vmbus_version[i]);
		if (!error) {
			char version[16];

			sc->vmbus_version = vmbus_version[i];
			(void) snprintf(version, sizeof (version),
			    "%u.%u", VMBUS_VERSION_MAJOR(sc->vmbus_version),
			    VMBUS_VERSION_MINOR(sc->vmbus_version));
			dev_err(sc->vmbus_dev, CE_NOTE, "version %s",
			    version);
			(void) ddi_prop_update_string(DDI_DEV_T_NONE,
			    sc->vmbus_dev, VMBUS_VERSION, version);
			return (0);
		}
	}
	return (ENXIO);
}

static void
vmbus_disconnect(struct vmbus_softc *sc)
{
	struct vmbus_chanmsg_disconnect *req;
	struct vmbus_msghc *mh;
	int error;

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL) {
		dev_err(sc->vmbus_dev, CE_WARN,
		    "can not get msg hypercall for disconnect");
		return;
	}

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_DISCONNECT;

	error = vmbus_msghc_exec_noresult(mh);
	vmbus_msghc_put(sc, mh);

	if (error) {
		dev_err(sc->vmbus_dev, CE_WARN,
		    "disconnect msg hypercall failed");
	}
}

static int
vmbus_req_channels(struct vmbus_softc *sc)
{
	struct vmbus_chanmsg_chrequest *req;
	struct vmbus_msghc *mh;
	int error;

	mh = vmbus_msghc_get(sc, sizeof (*req));
	if (mh == NULL)
		return (ENXIO);

	req = vmbus_msghc_dataptr(mh);
	req->chm_hdr.chm_type = VMBUS_CHANMSG_TYPE_CHREQUEST;

	error = vmbus_msghc_exec_noresult(mh);
	vmbus_msghc_put(sc, mh);

	return (error);
}

static void
vmbus_scan_done_task(void *xsc)
{
	struct vmbus_softc *sc = xsc;

	mutex_enter(&vmbus_lock);
	sc->vmbus_scandone = B_TRUE;
	cv_broadcast(&sc->vmbus_scandone_cv);
	mutex_exit(&vmbus_lock);
}

/* ARGSUSED */
static void
vmbus_scan_done(struct vmbus_softc *sc,
    const struct vmbus_message *msg)
{

	if (ddi_taskq_dispatch(sc->vmbus_devtq,
	    vmbus_scan_done_task, sc, DDI_SLEEP) != DDI_SUCCESS) {
		dev_err(sc->vmbus_dev, CE_WARN, "dispatch of "
		    "vmbus_scan_done_task failed");
	}
}

static int
vmbus_scan(struct vmbus_softc *sc)
{
	int error;

	/*
	 * This taskqueue serializes vmbus devices' attach and detach
	 * for channel offer and rescind messages.
	 */
	sc->vmbus_devtq = ddi_taskq_create(sc->vmbus_dev,
	    "vmbus dev", 1, maxclsyspri, TASKQ_PREPOPULATE);

	/*
	 * This taskqueue handles sub-channel detach, so that vmbus
	 * device's detach running in vmbus_devtq can drain its sub-
	 * channels.
	 */
	sc->vmbus_subchtq = ddi_taskq_create(sc->vmbus_dev,
	    "vmbus subch", 1, maxclsyspri, TASKQ_PREPOPULATE);

	/*
	 * Start vmbus scanning.
	 */
	error = vmbus_req_channels(sc);
	if (error) {
		dev_err(sc->vmbus_dev, CE_WARN, "channel request failed: %d",
		    error);
		return (error);
	}

	/*
	 * Wait for all vmbus devices from the initial channel offers to be
	 * attached.
	 */
	ASSERT(MUTEX_HELD(&vmbus_lock));
	while (!sc->vmbus_scandone)
		cv_wait(&sc->vmbus_scandone_cv, &vmbus_lock);

	dev_err(sc->vmbus_dev, CE_CONT, "?device scan, probe and attach "
	    "done\n");
	return (0);
}

static void
vmbus_scan_teardown(struct vmbus_softc *sc)
{

	ASSERT(MUTEX_HELD(&vmbus_lock));
	if (sc->vmbus_devtq != NULL) {
		mutex_exit(&vmbus_lock);
		ddi_taskq_destroy(sc->vmbus_devtq);
		mutex_enter(&vmbus_lock);
		sc->vmbus_devtq = NULL;
	}
	if (sc->vmbus_subchtq != NULL) {
		mutex_exit(&vmbus_lock);
		ddi_taskq_destroy(sc->vmbus_subchtq);
		mutex_enter(&vmbus_lock);
		sc->vmbus_subchtq = NULL;
	}
}

static void
vmbus_chanmsg_handle(struct vmbus_softc *sc, const struct vmbus_message *msg)
{
	vmbus_chanmsg_proc_t msg_proc;
	uint32_t msg_type;

	msg_type = ((const struct vmbus_chanmsg_hdr *)msg->msg_data)->chm_type;
	if (msg_type >= VMBUS_CHANMSG_TYPE_MAX) {
		dev_err(sc->vmbus_dev, CE_WARN, "unknown message type 0x%x",
		    msg_type);
		return;
	}

	msg_proc = vmbus_chanmsg_handlers[msg_type];
	if (msg_proc != NULL)
		msg_proc(sc, msg);

	/* Channel specific processing */
	vmbus_chan_msgproc(sc, msg);
}

static void
vmbus_msg_task(void *arg)
{
	struct vmbus_message *msg_base = (struct vmbus_message *)arg;
	volatile struct vmbus_message *msg;
	struct vmbus_softc *sc = vmbus_get_softc();

	msg = msg_base + VMBUS_SINT_MESSAGE;
	for (;;) {
		if (msg->msg_type == HYPERV_MSGTYPE_NONE) {
			/* No message */
			break;
		} else if (msg->msg_type == HYPERV_MSGTYPE_CHANNEL) {
			/* Channel message */
			vmbus_chanmsg_handle(sc, (struct vmbus_message *)msg);
		}

		msg->msg_type = HYPERV_MSGTYPE_NONE;
		/*
		 * Make sure the write to msg_type (i.e. set to
		 * HYPERV_MSGTYPE_NONE) happens before we read the
		 * msg_flags and EOMing. Otherwise, the EOMing will
		 * not deliver any more messages since there is no
		 * empty slot
		 *
		 * NOTE:
		 * membar_sync() is used here, since
		 * atomic_thread_fence_seq_cst()
		 * will become compiler fence on UP kernel.
		 */
		membar_sync();
		if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
			/*
			 * This will cause message queue rescan to possibly
			 * deliver another msg from the hypervisor
			 */
			wrmsr(MSR_HV_EOM, 0);
		}
	}
}

static int
vmbus_handle_intr1(struct vmbus_softc *sc, int cpu)
{
	volatile struct vmbus_message *msg;
	struct vmbus_message *msg_base;

	msg_base = VMBUS_PCPU_GET(sc, message, cpu);

	/*
	 * Check event timer.
	 *
	 * TODO: move this to independent IDT vector.
	 */
	msg = msg_base + VMBUS_SINT_TIMER;
	if (msg->msg_type == HYPERV_MSGTYPE_TIMER_EXPIRED) {
		msg->msg_type = HYPERV_MSGTYPE_NONE;

		/*
		 * Make sure the write to msg_type (i.e. set to
		 * HYPERV_MSGTYPE_NONE) happens before we read the
		 * msg_flags and EOMing. Otherwise, the EOMing will
		 * not deliver any more messages since there is no
		 * empty slot
		 *
		 * NOTE:
		 * membar_sync() is used here, since
		 * atomic_thread_fence_seq_cst()
		 * will become compiler fence on UP kernel.
		 */
		membar_sync();
		if (msg->msg_flags & VMBUS_MSGFLAG_PENDING) {
			/*
			 * This will cause message queue rescan to possibly
			 * deliver another msg from the hypervisor
			 */
			wrmsr(MSR_HV_EOM, 0);
		}
	}

	/*
	 * Check events.  Hot path for network and storage I/O data; high rate.
	 *
	 * NOTE:
	 * As recommended by the Windows guest fellows, we check events before
	 * checking messages.
	 */
	sc->vmbus_event_proc(sc, cpu);

	/*
	 * Check messages.  Mainly management stuffs; ultra low rate.
	 */
	msg = msg_base + VMBUS_SINT_MESSAGE;
	if (__predict_false(msg->msg_type != HYPERV_MSGTYPE_NONE)) {
		/*
		 * Pass in the msg_base to the vmbus_msg_task so that it knows
		 * which message to process.
		 */
		(void) ddi_taskq_dispatch(VMBUS_PCPU_GET(sc, message_tq, cpu),
		    vmbus_msg_task, msg_base, DDI_SLEEP);
	}

	return (DDI_INTR_CLAIMED);
}

uint_t
vmbus_handle_intr(struct vmbus_softc *sc)
{
	int cpu = curcpu;

	/*
	 * Disable preemption.
	 */
	kpreempt_disable();

	/*
	 * Do a little interrupt counting.
	 */
	VMBUS_PCPU_GET(sc, intr_cnt, cpu)++;

	int rc = vmbus_handle_intr1(sc, cpu);

	/*
	 * Enable preemption.
	 */
	kpreempt_enable();
	return (rc);

}

static void
vmbus_synic_setup(void *xsc)
{
	struct vmbus_softc *sc = xsc;
	int cpu = curcpu;
	uint64_t val, orig;
	uint32_t sint;

	if (hyperv_features & CPUID_HV_MSR_VP_INDEX) {
		/* Save virtual processor id. */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = rdmsr(MSR_HV_VP_INDEX);
	} else {
		/* Set virtual processor id to 0 for compatibility. */
		VMBUS_PCPU_GET(sc, vcpuid, cpu) = 0;
	}

	/*
	 * Setup the SynIC message.
	 */
	orig = rdmsr(MSR_HV_SIMP);
	val = MSR_HV_SIMP_ENABLE | (orig & MSR_HV_SIMP_RSVD_MASK) |
	    ((VMBUS_PCPU_GET(sc, message_dma.hv_paddr, cpu) >> PAGE_SHIFT) <<
	    MSR_HV_SIMP_PGSHIFT);
	wrmsr(MSR_HV_SIMP, val);

	/*
	 * Setup the SynIC event flags.
	 */
	orig = rdmsr(MSR_HV_SIEFP);
	val = MSR_HV_SIEFP_ENABLE | (orig & MSR_HV_SIEFP_RSVD_MASK) |
	    ((VMBUS_PCPU_GET(sc, event_flags_dma.hv_paddr, cpu)
	    >> PAGE_SHIFT) << MSR_HV_SIEFP_PGSHIFT);
	wrmsr(MSR_HV_SIEFP, val);


	/*
	 * Configure and unmask SINT for message and event flags.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_MESSAGE;
	orig = rdmsr(sint);
	val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
	    (orig & MSR_HV_SINT_RSVD_MASK);
	dev_err(sc->vmbus_dev, CE_CONT, "?SINT val %llx\n", (u_longlong_t)val);
	wrmsr(sint, val);

	/*
	 * Configure and unmask SINT for timer.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_TIMER;
	orig = rdmsr(sint);
	val = sc->vmbus_idtvec | MSR_HV_SINT_AUTOEOI |
	    (orig & MSR_HV_SINT_RSVD_MASK);
	wrmsr(sint, val);

	/*
	 * All done; enable SynIC.
	 */
	orig = rdmsr(MSR_HV_SCONTROL);
	val = MSR_HV_SCTRL_ENABLE | (orig & MSR_HV_SCTRL_RSVD_MASK);
	wrmsr(MSR_HV_SCONTROL, val);
}

/* ARGSUSED */
static void
vmbus_synic_teardown(void *arg)
{
	uint64_t orig;
	uint32_t sint;

	/*
	 * Disable SynIC.
	 */
	orig = rdmsr(MSR_HV_SCONTROL);
	wrmsr(MSR_HV_SCONTROL, (orig & MSR_HV_SCTRL_RSVD_MASK));

	/*
	 * Mask message and event flags SINT.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_MESSAGE;
	orig = rdmsr(sint);
	wrmsr(sint, orig | MSR_HV_SINT_MASKED);

	/*
	 * Mask timer SINT.
	 */
	sint = MSR_HV_SINT0 + VMBUS_SINT_TIMER;
	orig = rdmsr(sint);
	wrmsr(sint, orig | MSR_HV_SINT_MASKED);

	/*
	 * Teardown SynIC message.
	 */
	orig = rdmsr(MSR_HV_SIMP);
	wrmsr(MSR_HV_SIMP, (orig & MSR_HV_SIMP_RSVD_MASK));

	/*
	 * Teardown SynIC event flags.
	 */
	orig = rdmsr(MSR_HV_SIEFP);
	wrmsr(MSR_HV_SIEFP, (orig & MSR_HV_SIEFP_RSVD_MASK));
}

static int
vmbus_dma_alloc(struct vmbus_softc *sc)
{
	uint8_t *evtflags;
	int cpu;

	for (cpu = 0; cpu < ncpus; cpu++) {
		void *ptr;

		/*
		 * Per-cpu messages and event flags.
		 */
		ptr = hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
		    PAGE_SIZE, VMBUS_PCPU_PTR(sc, message_dma, cpu),
		    DDI_DMA_RDWR);
		if (ptr == NULL)
			return (ENOMEM);
		VMBUS_PCPU_GET(sc, message, cpu) = ptr;

		ptr = hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
		    PAGE_SIZE, VMBUS_PCPU_PTR(sc, event_flags_dma, cpu),
		    DDI_DMA_RDWR);
		if (ptr == NULL)
			return (ENOMEM);
		VMBUS_PCPU_GET(sc, event_flags, cpu) = ptr;
	}

	evtflags = (uint8_t *)hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
	    PAGE_SIZE, &sc->vmbus_evtflags_dma, DDI_DMA_RDWR);
	if (evtflags == NULL)
		return (ENOMEM);
	sc->vmbus_rx_evtflags = (ulong_t *)evtflags;
	sc->vmbus_tx_evtflags = (ulong_t *)(evtflags + (PAGE_SIZE / 2));
	sc->vmbus_evtflags = evtflags;

	sc->vmbus_mnf1 = hyperv_dmamem_alloc(sc->vmbus_dev, PAGE_SIZE, 0,
	    PAGE_SIZE, &sc->vmbus_mnf1_dma, DDI_DMA_RDWR);
	if (sc->vmbus_mnf1 == NULL)
		return (ENOMEM);

	sc->vmbus_mnf2 = (struct vmbus_mnf *)hyperv_dmamem_alloc(sc->vmbus_dev,
	    PAGE_SIZE, 0, sizeof (struct vmbus_mnf), &sc->vmbus_mnf2_dma,
	    DDI_DMA_RDWR);
	if (sc->vmbus_mnf2 == NULL)
		return (ENOMEM);

	return (0);
}

static void
vmbus_dma_free(struct vmbus_softc *sc)
{
	int cpu;

	if (sc->vmbus_evtflags != NULL) {
		hyperv_dmamem_free(&sc->vmbus_evtflags_dma);
		sc->vmbus_evtflags = NULL;
		sc->vmbus_rx_evtflags = NULL;
		sc->vmbus_tx_evtflags = NULL;
	}
	if (sc->vmbus_mnf1 != NULL) {
		hyperv_dmamem_free(&sc->vmbus_mnf1_dma);
		sc->vmbus_mnf1 = NULL;
	}
	if (sc->vmbus_mnf2 != NULL) {
		hyperv_dmamem_free(&sc->vmbus_mnf2_dma);
		sc->vmbus_mnf2 = NULL;
	}

	for (cpu = 0; cpu < ncpus; cpu++) {
		if (VMBUS_PCPU_GET(sc, message, cpu) != NULL) {
			hyperv_dmamem_free(
			    VMBUS_PCPU_PTR(sc, message_dma, cpu));
			VMBUS_PCPU_GET(sc, message, cpu) = NULL;
		}
		if (VMBUS_PCPU_GET(sc, event_flags, cpu) != NULL) {
			hyperv_dmamem_free(
			    VMBUS_PCPU_PTR(sc, event_flags_dma, cpu));
			VMBUS_PCPU_GET(sc, event_flags, cpu) = NULL;
		}
	}
}

#define	IPL_VMBUS	0x1

static int
vmbus_intr_setup(struct vmbus_softc *sc)
{
	int cpu;

	for (cpu = 0; cpu < ncpus; cpu++) {
		char tq_name[MAXPATHLEN];

		/* Allocate an interrupt counter for Hyper-V interrupt */
		VMBUS_PCPU_GET(sc, intr_cnt, cpu) = 0;

		/*
		 * Setup taskq to handle events.  Task will be per-
		 * channel.
		 */
		(void) snprintf(tq_name, sizeof (tq_name), "hyperv event[%d]",
		    cpu);
		*VMBUS_PCPU_PTR(sc, event_tq, cpu) = ddi_taskq_create(NULL,
		    tq_name, 1, maxclsyspri, TASKQ_PREPOPULATE);

		/*
		 * Setup tasks and taskq to handle messages.
		 */
		(void) snprintf(tq_name, sizeof (tq_name), "hyperv msg[%d]",
		    cpu);
		*VMBUS_PCPU_PTR(sc, message_tq, cpu) = ddi_taskq_create(NULL,
		    tq_name, 1, maxclsyspri, TASKQ_PREPOPULATE);
	}

	sc->vmbus_idtvec = psm_get_ipivect(IPL_VMBUS, -1);
	if (add_avintr(NULL, IPL_VMBUS, (avfunc)vmbus_handle_intr,
	    "Hyper-V vmbus", sc->vmbus_idtvec, (caddr_t)sc, NULL,
	    NULL, NULL) == 0) {
		dev_err(sc->vmbus_dev, CE_WARN,
		    "cannot find free IDT (%d) vector", sc->vmbus_idtvec);
		return (ENXIO);
	}
	dev_err(sc->vmbus_dev, CE_CONT, "?vmbus IDT vector %d\n",
	    sc->vmbus_idtvec);
	return (0);
}

static void
vmbus_intr_teardown(struct vmbus_softc *sc)
{
	int cpu;

	if (sc->vmbus_idtvec >= 0) {
		rem_avintr(NULL, IPL_VMBUS, (avfunc)vmbus_handle_intr,
		    sc->vmbus_idtvec);
		sc->vmbus_idtvec = -1;
	}

	for (cpu = 0; cpu < ncpus; cpu++) {
		if (VMBUS_PCPU_GET(sc, event_tq, cpu) != NULL) {
			ddi_taskq_destroy(VMBUS_PCPU_GET(sc, event_tq, cpu));
			VMBUS_PCPU_GET(sc, event_tq, cpu) = NULL;
		}
		if (VMBUS_PCPU_GET(sc, message_tq, cpu) != NULL) {
			ddi_taskq_destroy(VMBUS_PCPU_GET(sc, message_tq, cpu));
			VMBUS_PCPU_GET(sc, message_tq, cpu) = NULL;
		}
	}
}

typedef struct hv_vmbus_device {
	char	*hv_name;
	char	*hv_devname;
	char	*hv_guid;
} hv_vmbus_device_t;

static hv_vmbus_device_t vmbus_devices[] = {
	{
	"Hyper-V Shutdown", "hv_shutdown",
	"0e0b6031-5213-4934-818b-38d90ced39db"
	},

	{
	"Hyper-V Timesync", "hv_timesync",
	"9527e630-d0ae-497b-adce-e80ab0175caf"
	},

	{
	"Hyper-V Heartbeat", "hv_heartbeat",
	"57164f39-9115-4e78-ab55-382f3bd5422d"
	},

	{
	"Hyper-V KVP", "hv_kvp",
	"a9a0f4e7-5a45-4d96-b827-8a841e8c03e6"
	},

	{
	"Hyper-V Network Interface", "hv_netvsc",
	"f8615163-df3e-46c5-913f-f2d2f965ed0e"
	},

	{
	"Hyper-V IDE Storage Interface", "blksvc",
	"32412632-86cb-44a2-9b5c-50d1417354f5"
	},

	{
	"Hyper-V SCSI Storage Interface", "hv_storvsc",
	"ba6163d9-04a1-4d29-b605-72e2ffb1dc7f"
	},

	{
	NULL,  NULL, NULL
	}
};

void
vmbus_walk_children(int (*walk_cb)(dev_info_t *, void *), void *arg)
{
	struct vmbus_softc *sc = vmbus_get_softc();
	ddi_walk_devs(sc->vmbus_dev, walk_cb, arg);
}

int
vmbus_add_child(struct vmbus_channel *chan)
{
	struct vmbus_softc *sc = chan->ch_vmbus;
	dev_info_t *parent = sc->vmbus_dev;
	hv_vmbus_device_t *dev;
	char *devname = NULL;

	mutex_enter(&vmbus_lock);

	char classid[HYPERV_GUID_STRLEN] = { 0 };
	(void) hyperv_guid2str(&chan->ch_guid_type, classid, sizeof (classid));

	/*
	 * Find a device that matches the classid in the channel.
	 */
	for (dev = vmbus_devices; dev->hv_guid != NULL; dev++) {
		if (strncmp(dev->hv_guid, classid, strlen(dev->hv_guid)) == 0) {
			devname = dev->hv_devname;
			break;
		}
	}

	if (devname == NULL)
		devname = "vmbus_child";

	ndi_devi_alloc_sleep(parent, devname, DEVI_SID_NODEID, &chan->ch_dev);
	if (chan->ch_dev == NULL) {
		mutex_exit(&vmbus_lock);
		dev_err(parent, CE_WARN, "device_add_child for chan%u failed",
		    chan->ch_id);
		return (ENXIO);
	}
	ddi_set_parent_data(chan->ch_dev, chan);
	int err = ndi_devi_online(chan->ch_dev, 0);
	if (err != NDI_SUCCESS) {
		(void) ndi_devi_free(chan->ch_dev);
		chan->ch_dev = NULL;
		mutex_exit(&vmbus_lock);
		dev_err(parent, CE_CONT, "?failed to online: classid %s, "
		    "devname %s for chan%u, err %d\n", classid, devname,
		    chan->ch_id, err);
		return (DDI_FAILURE);
	}

	mutex_exit(&vmbus_lock);
	return (DDI_SUCCESS);
}

int
vmbus_delete_child(struct vmbus_channel *chan)
{
	int error = 0;

	mutex_enter(&vmbus_lock);
	if (chan->ch_dev != NULL) {
		if (ddi_prop_update_string(DDI_DEV_T_NONE, chan->ch_dev,
		    VMBUS_STATE, VMBUS_STATE_OFFLINE) != DDI_SUCCESS) {
			dev_err(chan->ch_dev, CE_WARN, "Unable to set "
			    "\"%s(%s)\" property", VMBUS_STATE,
			    VMBUS_STATE_OFFLINE);
			mutex_exit(&vmbus_lock);
			return (DDI_FAILURE);
		}

		if (ndi_devi_offline(chan->ch_dev, NDI_DEVI_REMOVE) !=
		    DDI_SUCCESS) {
			dev_err(chan->ch_dev, CE_WARN, "Unable to offline "
			    "device");
			mutex_exit(&vmbus_lock);
			return (DDI_FAILURE);
		}
		(void) ndi_devi_free(chan->ch_dev);
		chan->ch_dev = NULL;
	}
	mutex_exit(&vmbus_lock);
	return (error);
}

uint32_t
vmbus_get_version(void)
{
	struct vmbus_softc *sc = vmbus_get_softc();

	return (sc->vmbus_version);
}

int
vmbus_probe_guid(dev_info_t *dev, const struct hyperv_guid *guid)
{
	const struct vmbus_channel *chan = vmbus_get_channel(dev);

	if (memcmp(&chan->ch_guid_type, guid, sizeof (struct hyperv_guid)) == 0)
		return (0);
	return (ENXIO);
}

/*
 * @brief Main vmbus driver initialization routine.
 *
 * Here, we
 * - initialize the vmbus driver context
 * - setup various driver entry points
 * - invoke the vmbus hv main init routine
 * - get the irq resource
 * - invoke the vmbus to add the vmbus root device
 * - setup the vmbus root device
 * - retrieve the channel offers
 */
static int
vmbus_doattach(struct vmbus_softc *sc)
{
	int ret;

	if (sc->vmbus_flags & VMBUS_FLAG_ATTACHED)
		return (DDI_SUCCESS);

	sc->vmbus_gpadl = VMBUS_GPADL_START;
	mutex_init(&sc->vmbus_prichan_lock, NULL, MUTEX_DEFAULT, NULL);
	TAILQ_INIT(&sc->vmbus_prichans);
	mutex_init(&sc->vmbus_chan_lock, NULL, MUTEX_DEFAULT, NULL);
	TAILQ_INIT(&sc->vmbus_chans);
	sc->vmbus_chmap = kmem_zalloc(
	    sizeof (struct vmbus_channel *) * VMBUS_CHAN_MAX, KM_SLEEP);

	/*
	 * Create context for "post message" Hypercalls
	 */
	sc->vmbus_xc = vmbus_xact_ctx_create(sc->vmbus_dev,
	    HYPERCALL_POSTMSGIN_SIZE, VMBUS_MSG_SIZE,
	    sizeof (struct vmbus_msghc));
	if (sc->vmbus_xc == NULL) {
		ret = ENXIO;
		goto cleanup;
	}

	/*
	 * Allocate DMA stuffs.
	 */
	ret = vmbus_dma_alloc(sc);
	if (ret != 0)
		goto cleanup;

	/*
	 * Setup interrupt.
	 */
	ret = vmbus_intr_setup(sc);
	if (ret != 0)
		goto cleanup;

	/*
	 * Setup SynIC.
	 */
	vmbus_xcall(vmbus_synic_setup, sc);
	sc->vmbus_flags |= VMBUS_FLAG_SYNIC;

	/*
	 * Initialize vmbus, e.g. connect to Hypervisor.
	 */
	ret = vmbus_init(sc);
	if (ret != 0)
		goto cleanup;

	if (sc->vmbus_version == VMBUS_VERSION_WS2008 ||
	    sc->vmbus_version == VMBUS_VERSION_WIN7)
		sc->vmbus_event_proc = vmbus_event_proc_compat;
	else
		sc->vmbus_event_proc = vmbus_event_proc;

	ret = vmbus_scan(sc);
	if (ret != 0)
		goto cleanup;

	sc->vmbus_flags |= VMBUS_FLAG_ATTACHED;
	return (DDI_SUCCESS);

cleanup:
	vmbus_scan_teardown(sc);
	vmbus_intr_teardown(sc);
	vmbus_dma_free(sc);
	if (sc->vmbus_xc != NULL) {
		vmbus_xact_ctx_destroy(sc->vmbus_xc);
		sc->vmbus_xc = NULL;
	}
	kmem_free(sc->vmbus_chmap,
	    sizeof (struct vmbus_channel *) * VMBUS_CHAN_MAX);
	mutex_destroy(&sc->vmbus_prichan_lock);
	mutex_destroy(&sc->vmbus_chan_lock);

	return (DDI_FAILURE);
}

/* ARGSUSED */
static void
vmbus_event_proc_dummy(struct vmbus_softc *sc, int cpu)
{
}

static int
vmbus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&vmbus_lock);
	int instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(vmbus_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "ddi_soft_state_zalloc failed");
		mutex_exit(&vmbus_lock);
		return (DDI_FAILURE);
	}
	vmbus_sc = ddi_get_soft_state(vmbus_state, instance);
	vmbus_sc->vmbus_dev = dip;
	vmbus_sc->vmbus_idtvec = -1;

	if (hypercall_create(vmbus_sc->vmbus_dev) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "unable to create hypercall context");
		return (DDI_FAILURE);
	}

	/*
	 * Event processing logic will be configured:
	 * - After the vmbus protocol version negotiation.
	 * - Before we request channel offers.
	 */
	vmbus_sc->vmbus_event_proc = vmbus_event_proc_dummy;

	int ret = vmbus_doattach(vmbus_sc);
	if (vmbus_sc->vmbus_flags & VMBUS_FLAG_ATTACHED) {
		(void) ddi_hold_driver(ddi_name_to_major("hyperv"));
	}

	ddi_report_dev(dip);
	mutex_exit(&vmbus_lock);
	return (ret);
}

static int
vmbus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct vmbus_softc *sc = NULL;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&vmbus_lock);
	int instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(vmbus_state, instance);
	if (sc == NULL) {
		mutex_exit(&vmbus_lock);
		return (DDI_FAILURE);
	}

	vmbus_chan_destroy_all(sc);

	vmbus_scan_teardown(sc);

	vmbus_disconnect(sc);

	if (sc->vmbus_flags & VMBUS_FLAG_SYNIC) {
		sc->vmbus_flags &= ~VMBUS_FLAG_SYNIC;
		vmbus_xcall(vmbus_synic_teardown, NULL);
	}

	vmbus_intr_teardown(sc);
	vmbus_dma_free(sc);

	if (sc->vmbus_xc != NULL) {
		vmbus_xact_ctx_destroy(sc->vmbus_xc);
		sc->vmbus_xc = NULL;
	}

	kmem_free(sc->vmbus_chmap,
	    sizeof (struct vmbus_channel *) * VMBUS_CHAN_MAX);
	mutex_destroy(&sc->vmbus_prichan_lock);
	mutex_destroy(&sc->vmbus_chan_lock);

	hypercall_destroy();

	if (sc->vmbus_flags & VMBUS_FLAG_ATTACHED) {
		(void) ddi_rele_driver(ddi_name_to_major("hyperv"));
		sc->vmbus_flags &= ~VMBUS_FLAG_ATTACHED;
	}
	ddi_soft_state_free(vmbus_state, instance);
	mutex_exit(&vmbus_lock);
	return (DDI_SUCCESS);
}

static int
vmbus_sysinit(void)
{
	if ((get_hwenv() & HW_MICROSOFT) == 0)
		return (-1);

	int error = ddi_soft_state_init(&vmbus_state,
	    sizeof (struct vmbus_softc), 0);
	if (error != 0)
		return (error);

	return (0);
}

static void
vmbus_xcall(vmbus_xcall_func_t func, void *arg)
{
	cpuset_t set;
	CPUSET_ALL(set);
	uint32_t spl = ddi_enter_critical();
	xc_sync((xc_arg_t)arg, NULL, NULL, CPUSET2BV(set), (xc_func_t)func);
	ddi_exit_critical(spl);
}

static int
vmbus_initchild(dev_info_t *child)
{
	struct vmbus_softc *sc = vmbus_get_softc();
	const struct vmbus_channel *chan = vmbus_get_channel(child);
	char addr[80];

	ASSERT3P(chan, !=, NULL);
	ASSERT3P(chan->ch_dev, ==, child);

	char classid[HYPERV_GUID_STRLEN] = { 0 };
	(void) hyperv_guid2str(&chan->ch_guid_type, classid, sizeof (classid));
	if (ddi_prop_update_string(DDI_DEV_T_NONE, child,
	    VMBUS_CLASSID, classid) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN, "Unable to set \"%s(%s)\" "
		    "property", VMBUS_CLASSID, classid);
		return (DDI_FAILURE);
	}

	char deviceid[HYPERV_GUID_STRLEN] = { 0 };
	(void) hyperv_guid2str(&chan->ch_guid_inst, deviceid,
	    sizeof (deviceid));
	if (ddi_prop_update_string(DDI_DEV_T_NONE, child,
	    VMBUS_DEVICEID, deviceid) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN, "Unable to set \"%s(%s)\" "
		    "property", VMBUS_DEVICEID, deviceid);
		return (DDI_FAILURE);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, child,
	    VMBUS_STATE, VMBUS_STATE_ONLINE) != DDI_SUCCESS) {
		dev_err(chan->ch_dev, CE_WARN, "Unable to set "
		    "\"%s(%s)\" property", VMBUS_STATE,
		    VMBUS_STATE_ONLINE);
		return (DDI_FAILURE);
	}

	dev_err(sc->vmbus_dev, CE_CONT,
	    "?vmbus_initchild parent %p child %p (%s : %s)\n",
	    (void *)sc->vmbus_dev, (void *)child, classid, deviceid);

	(void) snprintf(addr, sizeof (addr), "%s", deviceid);
	ddi_set_name_addr(child, addr);

	return (DDI_SUCCESS);
}

static int
vmbus_removechild(dev_info_t *dip)
{
	ddi_set_name_addr(dip, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
vmbus_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?%s@%s, %s%d\n", ddi_node_name(rdip),
		    ddi_get_name_addr(rdip), ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (vmbus_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (vmbus_removechild((dev_info_t *)arg));

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		return (DDI_FAILURE);

	case DDI_CTLOPS_POWER: {
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	/* NOTREACHED */

}

static struct cb_ops vmbus_cb_ops = {
	nulldev,	/* open */
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nodev,		/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* chpoll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* stream */
	D_NEW | D_MP,	/* flag */
	CB_REV,		/* rev */
	nodev,		/* aread */
	nodev		/* awrite */
};

static struct bus_ops vmbus_bus_ops = {
	BUSO_REV,
	i_ddi_bus_map,
	NULL,   /* NO OP */
	NULL,   /* NO OP */
	NULL,   /* NO OP */
	i_ddi_map_fault,
	NULL,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	vmbus_ctlops,
	ddi_bus_prop_op,
	NULL,		/* (*bus_get_eventcookie)();	*/
	NULL,		/* (*bus_add_eventcall)();	*/
	NULL,		/* (*bus_remove_eventcall)();	*/
	NULL,		/* (*bus_post_event)();		*/
	NULL,		/* (*bus_intr_ctl)();		*/
	NULL,		/* (*bus_config)();		*/
	NULL,		/* (*bus_unconfig)();		*/
	NULL,		/* (*bus_fm_init)();		*/
	NULL,		/* (*bus_fm_fini)();		*/
	NULL,		/* (*bus_fm_access_enter)();    */
	NULL,		/* (*bus_fm_access_fini)();	*/
	NULL,		/* (*bus_power)();		*/
	i_ddi_intr_ops	/* (*bus_intr_op)();		*/
};

static struct dev_ops vmbus_ops = {
	DEVO_REV,	/* version */
	0,		/* refcnt */
	NULL,		/* info */
	nulldev,	/* identify */
	nulldev,	/* probe */
	vmbus_attach,	/* attach */
	vmbus_detach,	/* detach */
	nodev,		/* reset */
	&vmbus_cb_ops,	/* driver operations */
	&vmbus_bus_ops,	/* no bus operations */
	NULL,		/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv vmbus_modldrv = {
	&mod_driverops,
	"Hyper-V VMBus driver",
	&vmbus_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&vmbus_modldrv,
	NULL
};

int
_init(void)
{
	mutex_init(&vmbus_lock, NULL, MUTEX_DEFAULT, NULL);

	if (vmbus_sysinit() != 0)
		return (ENOTSUP);

	int error = mod_install(&modlinkage);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int error = mod_remove(&modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(vmbus_state);
		mutex_destroy(&vmbus_lock);
	}
	return (error);
}
