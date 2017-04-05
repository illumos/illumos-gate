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

/*
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/xpv_support.h>
#include <sys/hypervisor.h>
#include <sys/machsystm.h>
#include <sys/mutex.h>
#include <sys/cmn_err.h>
#include <sys/dditypes.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/cpu.h>
#include <sys/psw.h>
#include <sys/psm.h>
#include <sys/sdt.h>

extern dev_info_t *xpv_dip;
static ddi_intr_handle_t *evtchn_ihp = NULL;
static ddi_softint_handle_t evtchn_to_handle[NR_EVENT_CHANNELS];
kmutex_t ec_lock;

static int evtchn_callback_irq = -1;

static volatile ulong_t *pending_events;
static volatile ulong_t *masked_events;

/* log2(NBBY * sizeof (ulong)) */
#ifdef __amd64
#define	EVTCHN_SHIFT	6
#else /* __i386 */
#define	EVTCHN_SHIFT	5
#endif

/* Atomically get and clear a ulong from memory. */
#define	GET_AND_CLEAR(src, targ) {				\
	membar_enter();						\
	do {							\
		targ = *src;					\
	} while (atomic_cas_ulong(src, targ, 0) != targ);	\
}

/* Get the first and last bits set in a bitmap */
#define	GET_BOUNDS(bitmap, low, high)	 {	\
	int _i;						\
	low = high = -1;				\
	for (_i = 0; _i <= sizeof (ulong_t); _i++)			\
		if (bitmap & (1UL << _i)) {	\
			if (low == -1)			\
				low = _i;		\
			high = _i;			\
		}					\
}

void
ec_bind_evtchn_to_handler(int evtchn, pri_t pri, ec_handler_fcn_t handler,
    void *arg1)
{
	ddi_softint_handle_t hdl;

	if (evtchn < 0 || evtchn >= NR_EVENT_CHANNELS) {
		cmn_err(CE_WARN, "Binding invalid event channel: %d", evtchn);
		return;
	}

	(void) ddi_intr_add_softint(xpv_dip, &hdl, pri, handler, (caddr_t)arg1);
	mutex_enter(&ec_lock);
	ASSERT(evtchn_to_handle[evtchn] == NULL);
	evtchn_to_handle[evtchn] = hdl;
	mutex_exit(&ec_lock);

	/* Let the hypervisor know we're prepared to handle this event */
	hypervisor_unmask_event(evtchn);
}

void
ec_unbind_evtchn(int evtchn)
{
	evtchn_close_t close;
	ddi_softint_handle_t hdl;

	if (evtchn < 0 || evtchn >= NR_EVENT_CHANNELS) {
		cmn_err(CE_WARN, "Unbinding invalid event channel: %d", evtchn);
		return;
	}

	/*
	 * Let the hypervisor know we're no longer prepared to handle this
	 * event
	 */
	hypervisor_mask_event(evtchn);

	/* Cleanup the event handler metadata */
	mutex_enter(&ec_lock);
	hdl = evtchn_to_handle[evtchn];
	evtchn_to_handle[evtchn] = NULL;
	mutex_exit(&ec_lock);

	close.port = evtchn;
	(void) HYPERVISOR_event_channel_op(EVTCHNOP_close, &close);
	(void) ddi_intr_remove_softint(hdl);
}

void
ec_notify_via_evtchn(unsigned int port)
{
	evtchn_send_t send;

	if ((int)port == -1)
		return;
	send.port = port;
	(void) HYPERVISOR_event_channel_op(EVTCHNOP_send, &send);
}

void
hypervisor_unmask_event(unsigned int ev)
{
	int index = ev >> EVTCHN_SHIFT;
	ulong_t bit = 1UL << (ev & ((1UL << EVTCHN_SHIFT) - 1));
	volatile ulong_t *maskp;
	evtchn_unmask_t unmask;

	/*
	 * index,bit contain the event number as an index into the
	 * masked-events bitmask. Set it to 0.
	 */
	maskp = &masked_events[index];
	atomic_and_ulong(maskp, ~bit);

	/* Let the hypervisor know the event has been unmasked */
	unmask.port = ev;
	if (HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &unmask) != 0)
		panic("xen_evtchn_unmask() failed");
}

/* Set a bit in an evtchan mask word */
void
hypervisor_mask_event(uint_t ev)
{
	int index = ev >> EVTCHN_SHIFT;
	ulong_t bit = 1UL << (ev & ((1UL << EVTCHN_SHIFT) - 1));
	volatile ulong_t *maskp;

	maskp = &masked_events[index];
	atomic_or_ulong(maskp, bit);
}

void
hypervisor_clear_event(uint_t ev)
{
	int index = ev >> EVTCHN_SHIFT;
	ulong_t bit = 1UL << (ev & ((1UL << EVTCHN_SHIFT) - 1));
	volatile ulong_t *maskp;

	maskp = &pending_events[index];
	atomic_and_ulong(maskp, ~bit);
}

int
xen_alloc_unbound_evtchn(int domid, int *evtchnp)
{
	evtchn_alloc_unbound_t alloc;
	int err;

	alloc.dom = DOMID_SELF;
	alloc.remote_dom = (domid_t)domid;

	if ((err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
	    &alloc)) == 0) {
		*evtchnp = alloc.port;
		/* ensure evtchn is masked till we're ready to use it */
		(void) hypervisor_mask_event(*evtchnp);
	} else {
		err = xen_xlate_errcode(err);
	}

	return (err);
}

int
xen_bind_interdomain(int domid, int remote_port, int *port)
{
	evtchn_bind_interdomain_t bind;
	int err;

	bind.remote_dom = (domid_t)domid;
	bind.remote_port = remote_port;
	if ((err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain,
	    &bind)) == 0)
		*port = bind.local_port;
	else
		err = xen_xlate_errcode(err);
	return (err);
}

/*ARGSUSED*/
uint_t
evtchn_callback_fcn(caddr_t arg0, caddr_t arg1)
{
	ulong_t pending_word;
	int i, j, port;
	volatile struct vcpu_info *vci;
	uint_t rv = DDI_INTR_UNCLAIMED;
	ddi_softint_handle_t hdl;
	int low, high;
	ulong_t sels;

	/*
	 * Xen hard-codes all notifications to VCPU0, so we bind
	 * ourselves via xpv.conf.  Note that this also assumes that all
	 * evtchns are bound to VCPU0, which is true by default.
	 */
	ASSERT(CPU->cpu_id == 0);

	vci = &HYPERVISOR_shared_info->vcpu_info[0];

again:
	DTRACE_PROBE2(evtchn__scan__start, int, vci->evtchn_upcall_pending,
	    ulong_t, vci->evtchn_pending_sel);

	atomic_and_8(&vci->evtchn_upcall_pending, 0);

	/*
	 * Find the upper and lower bounds in which we need to search for
	 * pending events.
	 */
	GET_AND_CLEAR(&vci->evtchn_pending_sel, sels);

	/* sels == 1 is by far the most common case.  Make it fast */
	if (sels == 1)
		low = high = 0;
	else if (sels == 0)
		return (rv);
	else
		GET_BOUNDS(sels, low, high);

	/* Scan the port list, looking for words with bits set */
	for (i = low; i <= high; i++) {
		ulong_t tmp;

		GET_AND_CLEAR(&pending_events[i], tmp);
		pending_word = tmp & ~(masked_events[i]);

		/* Scan the bits in the word, looking for pending events */
		while (pending_word != 0) {
			j = lowbit(pending_word) - 1;
			port = (i << EVTCHN_SHIFT) + j;
			pending_word = pending_word & ~(1UL << j);

			/*
			 * If there is a handler registered for this event,
			 * schedule a softint of the appropriate priority
			 * to execute it.
			 */
			if ((hdl = evtchn_to_handle[port]) != NULL) {
				(void) ddi_intr_trigger_softint(hdl, NULL);
				rv = DDI_INTR_CLAIMED;
			}
		}
	}
	DTRACE_PROBE2(evtchn__scan__end, int, vci->evtchn_upcall_pending,
	    ulong_t, vci->evtchn_pending_sel);

	if ((volatile uint8_t)vci->evtchn_upcall_pending ||
	    ((volatile ulong_t)vci->evtchn_pending_sel))
		goto again;

	return (rv);
}

static int
set_hvm_callback(int irq)
{
	struct xen_hvm_param xhp;

	xhp.domid = DOMID_SELF;
	xhp.index = HVM_PARAM_CALLBACK_IRQ;
	xhp.value = irq;
	return (HYPERVISOR_hvm_op(HVMOP_set_param, &xhp));
}

void
ec_fini()
{
	int i;

	for (i = 0; i < NR_EVENT_CHANNELS; i++)
		ec_unbind_evtchn(i);

	evtchn_callback_irq = -1;
	if (evtchn_ihp != NULL) {
		(void) ddi_intr_disable(*evtchn_ihp);
		(void) ddi_intr_remove_handler(*evtchn_ihp);
		(void) ddi_intr_free(*evtchn_ihp);
		kmem_free(evtchn_ihp, sizeof (ddi_intr_handle_t));
		evtchn_ihp = NULL;
	}
}

int
ec_init(void)
{
	int i;
	int rv, actual;
	ddi_intr_handle_t *ihp;

	/*
	 * Translate the variable-sized pending and masked event bitmasks
	 * into constant-sized arrays of uint32_t's.
	 */
	pending_events = &HYPERVISOR_shared_info->evtchn_pending[0];
	masked_events = &HYPERVISOR_shared_info->evtchn_mask[0];

	/*
	 * Clear our event handler structures and prevent the hypervisor
	 * from triggering any events.
	 */
	mutex_init(&ec_lock, NULL, MUTEX_SPIN, (void *)ipltospl(SPL7));
	for (i = 0; i < NR_EVENT_CHANNELS; i++) {
		evtchn_to_handle[i] = NULL;
		(void) hypervisor_mask_event(i);
	}

	/*
	 * Allocate and initialize an interrupt handler to process the
	 * hypervisor's "hey you have events pending!" interrupt.
	 */
	ihp = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);
	rv = ddi_intr_alloc(xpv_dip, ihp, DDI_INTR_TYPE_FIXED, 0, 1, &actual,
	    DDI_INTR_ALLOC_NORMAL);
	if (rv < 0 || actual != 1) {
		cmn_err(CE_WARN, "Could not allocate evtchn interrupt: %d",
		    rv);
		return (-1);
	}

	rv = ddi_intr_add_handler(*ihp, evtchn_callback_fcn, NULL, NULL);
	if (rv < 0) {
		(void) ddi_intr_free(*ihp);
		cmn_err(CE_WARN, "Could not attach evtchn handler");
		return (-1);
	}
	evtchn_ihp = ihp;

	if (ddi_intr_enable(*ihp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Could not enable evtchn interrupts\n");
		return (-1);
	}

	/* Tell the hypervisor which interrupt we're waiting on. */
	evtchn_callback_irq = ((ddi_intr_handle_impl_t *)*ihp)->ih_vector;

	if (set_hvm_callback(evtchn_callback_irq) != 0) {
		cmn_err(CE_WARN, "Couldn't register evtchn callback");
		return (-1);
	}
	return (0);
}

void
ec_resume(void)
{
	int i;

	/* New event-channel space is not 'live' yet. */
	for (i = 0; i < NR_EVENT_CHANNELS; i++)
		(void) hypervisor_mask_event(i);
	if (set_hvm_callback(evtchn_callback_irq) != 0)
		cmn_err(CE_WARN, "Couldn't register evtchn callback");

}
