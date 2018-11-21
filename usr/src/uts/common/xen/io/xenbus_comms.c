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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * xenbus_comms.c
 *
 * Low level code to talks to Xen Store: ringbuffer and event channel.
 *
 * Copyright (C) 2005 Rusty Russell, IBM Corporation
 *
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <sys/types.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <sys/bootconf.h>
#include <vm/seg_kmem.h>
#ifdef XPV_HVM_DRIVER
#include <sys/pc_mmu.h>
#include <sys/xpv_support.h>
#include <sys/hypervisor.h>
#else
#include <vm/kboot_mmu.h>
#include <sys/bootinfo.h>
#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#endif
#include <sys/condvar.h>
#include <sys/mutex.h>
#include <sys/atomic.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/avintr.h>
#include <xen/sys/xenbus_comms.h>
#include <xen/public/io/xs_wire.h>

#ifndef XPV_HVM_DRIVER
static int xenbus_irq;
#endif
static ddi_umem_cookie_t xb_cookie; /* cookie for xenbus comm page */
extern caddr_t xb_addr;	/* va of xenbus comm page */

static kcondvar_t xb_wait_cv;
static kmutex_t xb_wait_lock;

#define	xs_domain_interface(ra) ((struct xenstore_domain_interface *)(ra))

static uint_t
xenbus_intr(caddr_t arg __unused, caddr_t arg1 __unused)
{
	mutex_enter(&xb_wait_lock);
	cv_broadcast(&xb_wait_cv);
	mutex_exit(&xb_wait_lock);
	return (DDI_INTR_CLAIMED);
}

static int
check_indexes(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod)
{
	return ((prod - cons) <= XENSTORE_RING_SIZE);
}

static void *
get_output_chunk(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod,
    char *buf, uint32_t *len)
{
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);
	if ((XENSTORE_RING_SIZE - (prod - cons)) < *len)
		*len = XENSTORE_RING_SIZE - (prod - cons);
	return ((void *)(buf + MASK_XENSTORE_IDX(prod)));
}

static const void *
get_input_chunk(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod,
    const char *buf, uint32_t *len)
{
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(cons);
	if ((prod - cons) < *len)
		*len = prod - cons;
	return ((void *)(buf + MASK_XENSTORE_IDX(cons)));
}


int
xb_write(const void *data, unsigned len)
{
	volatile struct xenstore_domain_interface *intf =
	    xs_domain_interface(xb_addr);
	XENSTORE_RING_IDX cons, prod;
	extern int do_polled_io;

	while (len != 0) {
		void *dst;
		unsigned int avail;

		mutex_enter(&xb_wait_lock);
		while ((intf->req_prod - intf->req_cons) ==
		    XENSTORE_RING_SIZE) {
			if (interrupts_unleashed && !do_polled_io) {
				if (cv_wait_sig(&xb_wait_cv,
				    &xb_wait_lock) == 0) {
					mutex_exit(&xb_wait_lock);
					return (EINTR);
				}
			} else { /* polled mode needed for early probes */
				(void) HYPERVISOR_yield();
			}
		}
		mutex_exit(&xb_wait_lock);
		/* Read indexes, then verify. */
		cons = intf->req_cons;
		prod = intf->req_prod;
		membar_enter();
		if (!check_indexes(cons, prod))
			return (EIO);

		dst = get_output_chunk(cons, prod, (char *)intf->req, &avail);
		if (avail == 0)
			continue;
		if (avail > len)
			avail = len;

		(void) memcpy(dst, data, avail);
		data = (void *)((uintptr_t)data + avail);
		len -= avail;

		/* Other side must not see new header until data is there. */
		membar_producer();
		intf->req_prod += avail;

		/* This implies mb() before other side sees interrupt. */
		ec_notify_via_evtchn(xen_info->store_evtchn);
	}

	return (0);
}

int
xb_read(void *data, unsigned len)
{
	volatile struct xenstore_domain_interface *intf =
	    xs_domain_interface(xb_addr);
	XENSTORE_RING_IDX cons, prod;
	extern int do_polled_io;

	while (len != 0) {
		unsigned int avail;
		const char *src;

		mutex_enter(&xb_wait_lock);
		while (intf->rsp_cons == intf->rsp_prod) {
			if (interrupts_unleashed && !do_polled_io) {
				if (cv_wait_sig(&xb_wait_cv,
				    &xb_wait_lock) == 0) {
					mutex_exit(&xb_wait_lock);
					return (EINTR);
				}
			} else { /* polled mode needed for early probes */
				(void) HYPERVISOR_yield();
			}
		}
		mutex_exit(&xb_wait_lock);
		/* Read indexes, then verify. */
		cons = intf->rsp_cons;
		prod = intf->rsp_prod;
		membar_enter();
		if (!check_indexes(cons, prod))
			return (EIO);

		src = get_input_chunk(cons, prod, (char *)intf->rsp, &avail);
		if (avail == 0)
			continue;
		if (avail > len)
			avail = len;

		/* We must read header before we read data. */
		membar_consumer();

		(void) memcpy(data, src, avail);
		data = (void *)((uintptr_t)data + avail);
		len -= avail;

		/* Other side must not see free space until we've copied out */
		membar_enter();
		intf->rsp_cons += avail;

		/* Implies mb(): they will see new header. */
		ec_notify_via_evtchn(xen_info->store_evtchn);
	}

	return (0);
}

void
xb_suspend(void)
{
#ifdef XPV_HVM_DRIVER
	ec_unbind_evtchn(xen_info->store_evtchn);
#else
	rem_avintr(NULL, IPL_XENBUS, xenbus_intr, xenbus_irq);
#endif
}

void
xb_setup_intr(void)
{
#ifdef XPV_HVM_DRIVER
	ec_bind_evtchn_to_handler(xen_info->store_evtchn, IPL_XENBUS,
	    xenbus_intr, NULL);
#else
	xenbus_irq = ec_bind_evtchn_to_irq(xen_info->store_evtchn);
	if (xenbus_irq < 0) {
		cmn_err(CE_WARN, "Couldn't bind xenbus event channel");
		return;
	}
	if (!add_avintr(NULL, IPL_XENBUS, xenbus_intr, "xenbus",
	    xenbus_irq, NULL, NULL, NULL, NULL))
		cmn_err(CE_WARN, "XENBUS add intr failed\n");
#endif
}

/*
 * Set up our xenstore page and event channel. Domain 0 needs to allocate a
 * page and event channel; other domains use what we are told.
 */
void
xb_init(void)
{
	int err;

	if (DOMAIN_IS_INITDOMAIN(xen_info)) {

		if (xb_addr != NULL)
			return;

		xb_addr = ddi_umem_alloc(PAGESIZE, DDI_UMEM_SLEEP,
		    &xb_cookie);
		xen_info->store_mfn = pfn_to_mfn(hat_getpfnum(kas.a_hat,
		    xb_addr));

		err = xen_alloc_unbound_evtchn(0,
		    (int *)&xen_info->store_evtchn);
		ASSERT(err == 0);
	} else {
		/*
		 * This is harmless on first boot, but needed for resume and
		 * migrate. We use kbm_map_ma() as a shortcut instead of
		 * directly using HYPERVISOR_update_va_mapping().
		 */
		ASSERT(xb_addr != NULL);
		kbm_map_ma(mfn_to_ma(xen_info->store_mfn),
		    (uintptr_t)xb_addr, 0);
	}

	ASSERT(xen_info->store_evtchn);
}

void *
xb_xenstore_cookie(void)
{
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));
	return (xb_cookie);
}
