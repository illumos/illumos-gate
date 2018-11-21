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
 * evtchn.c
 *
 * Communication via hypervisor event channels.
 *
 * Copyright (c) 2002-2005, K A Fraser
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

/* some parts derived from netbsd's hypervisor_machdep.c 1.2.2.2 */

/*
 *
 * Copyright (c) 2004 Christian Limpach.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. This section intentionally left blank.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 * Section 3 of the above license was updated in response to bug 6379571.
 */

#include <sys/types.h>
#include <sys/hypervisor.h>
#include <sys/machsystm.h>
#include <sys/mutex.h>
#include <sys/evtchn_impl.h>
#include <sys/ddi_impldefs.h>
#include <sys/avintr.h>
#include <sys/cpuvar.h>
#include <sys/smp_impldefs.h>
#include <sys/archsystm.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/promif.h>
#include <sys/debug.h>
#include <sys/psm.h>
#include <sys/privregs.h>
#include <sys/trap.h>
#include <sys/atomic.h>
#include <sys/cpu.h>
#include <sys/psw.h>
#include <sys/traptrace.h>
#include <sys/stack.h>
#include <sys/x_call.h>
#include <xen/public/physdev.h>

/*
 * This file manages our association between hypervisor event channels and
 * Solaris's IRQs.  This is a one-to-one mapping, with the exception of
 * IPI IRQs, for which there is one event channel per CPU participating
 * in the IPI, and the clock VIRQ which also has an event channel per cpu
 * and the IRQ for /dev/xen/evtchn. The IRQ types are:
 *
 * IRQT_VIRQ:
 *	The hypervisor's standard virtual IRQ, used for the clock timer, for
 *	example.  This code allows any cpu to bind to one of these, although
 *	some are treated specially (i.e. VIRQ_DEBUG).
 *	Event channel binding is done via EVTCHNOP_bind_virq.
 *
 * IRQT_PIRQ:
 *	These associate a physical IRQ with an event channel via
 *	EVTCHNOP_bind_pirq.
 *
 * IRQT_IPI:
 *	A cross-call IRQ. Maps to "ncpus" event channels, each of which is
 *	bound to exactly one of the vcpus.  We do not currently support
 *	unbinding of IPIs (since Solaris doesn't need it). Uses
 *	EVTCHNOP_bind_ipi.
 *
 * IRQT_EVTCHN:
 *	A "normal" binding to an event channel, typically used by the frontend
 *      drivers to bind to the their backend event channel.
 *
 * IRQT_DEV_EVTCHN:
 *	This is a one-time IRQ used by /dev/xen/evtchn. Unlike other IRQs, we
 *	have a one-IRQ to many-evtchn mapping. We only track evtchn->irq for
 *	these event channels, which are managed via ec_irq_add/rm_evtchn().
 *	We enforce that IRQT_DEV_EVTCHN's representative evtchn (->ii_evtchn)
 *	is zero, and make any calls to irq_evtchn() an error, to prevent
 *	accidentally attempting to use the illegal evtchn 0.
 *
 * Suspend/resume
 *
 *	During a suspend/resume cycle, we need to tear down the event channels.
 *	All other mapping data is kept. The drivers will remove their own event
 *	channels via xendev on receiving a DDI_SUSPEND.  This leaves us with
 *	the IPIs and VIRQs, which we handle in ec_suspend() and ec_resume()
 *	below.
 *
 * CPU binding
 *
 *	When an event channel is bound to a CPU, we set a bit in a mask present
 *	in the machcpu (evt_affinity) to indicate that this CPU can accept this
 *	event channel.  For both IPIs and VIRQs, this binding is fixed at
 *	allocation time and we never modify it.  All other event channels are
 *	bound via the PSM either as part of add_avintr(), or interrupt
 *	redistribution (xen_psm_dis/enable_intr()) as a result of CPU
 *	offline/online.
 *
 * Locking
 *
 *	Updates are done holding the ec_lock.  The xen_callback_handler()
 *	routine reads the mapping data in a lockless fashion.  Additionally
 *	suspend takes ec_lock to prevent update races during a suspend/resume
 *	cycle.  The IPI info is also examined without the lock; this is OK
 *	since we only ever change IPI info during initial setup and resume.
 */

#define	IRQ_IS_CPUPOKE(irq) (ipi_info[XC_CPUPOKE_PIL].mi_irq == (irq))

#define	EVTCHN_MASKED(ev) \
	(HYPERVISOR_shared_info->evtchn_mask[(ev) >> EVTCHN_SHIFT] & \
	(1ul << ((ev) & ((1ul << EVTCHN_SHIFT) - 1))))

static short evtchn_to_irq[NR_EVENT_CHANNELS];
static cpuset_t evtchn_cpus[NR_EVENT_CHANNELS];
static int	evtchn_owner[NR_EVENT_CHANNELS];
#ifdef DEBUG
static kthread_t *evtchn_owner_thread[NR_EVENT_CHANNELS];
#endif

static irq_info_t irq_info[NR_IRQS];
static mec_info_t ipi_info[MAXIPL];
static mec_info_t virq_info[NR_VIRQS];

/*
 * See the locking description above.
 */
kmutex_t ec_lock;

/*
 * Bitmap indicating which PIRQs require the hypervisor to be notified
 * on unmask.
 */
static unsigned long pirq_needs_eoi[NR_PIRQS / (sizeof (unsigned long) * NBBY)];

static int ec_debug_irq = INVALID_IRQ;
int ec_dev_irq = INVALID_IRQ;

int
xen_bind_virq(unsigned int virq, processorid_t cpu, int *port)
{
	evtchn_bind_virq_t bind;
	int err;

	bind.virq = virq;
	bind.vcpu = cpu;
	if ((err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_virq, &bind)) == 0)
		*port = bind.port;
	else
		err = xen_xlate_errcode(err);
	return (err);
}

int
xen_bind_interdomain(int domid, int remote_port, int *port)
{
	evtchn_bind_interdomain_t bind;
	int err;

	bind.remote_dom  = domid;
	bind.remote_port = remote_port;
	if ((err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain,
	    &bind)) == 0)
		*port = bind.local_port;
	else
		err = xen_xlate_errcode(err);
	return (err);
}

int
xen_alloc_unbound_evtchn(int domid, int *evtchnp)
{
	evtchn_alloc_unbound_t alloc;
	int err;

	alloc.dom = DOMID_SELF;
	alloc.remote_dom = domid;

	if ((err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
	    &alloc)) == 0) {
		*evtchnp = alloc.port;
		/* ensure evtchn is masked till we're ready to use it */
		(void) ec_mask_evtchn(*evtchnp);
	} else {
		err = xen_xlate_errcode(err);
	}

	return (err);
}

static int
xen_close_evtchn(int evtchn)
{
	evtchn_close_t close;
	int err;

	close.port = evtchn;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_close, &close);
	if (err)
		err = xen_xlate_errcode(err);
	return (err);
}

static int
xen_bind_ipi(processorid_t cpu)
{
	evtchn_bind_ipi_t bind;

	ASSERT(MUTEX_HELD(&ec_lock));

	bind.vcpu = cpu;
	if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_ipi, &bind) != 0)
		panic("xen_bind_ipi() failed");
	return (bind.port);
}

/* Send future instances of this interrupt to other vcpu. */
static void
xen_bind_vcpu(int evtchn, int cpu)
{
	evtchn_bind_vcpu_t bind;

	ASSERT(MUTEX_HELD(&ec_lock));

	bind.port = evtchn;
	bind.vcpu = cpu;
	if (HYPERVISOR_event_channel_op(EVTCHNOP_bind_vcpu, &bind) != 0)
		panic("xen_bind_vcpu() failed");
}

static int
xen_bind_pirq(int pirq)
{
	evtchn_bind_pirq_t bind;
	int ret;

	bind.pirq = pirq;
	bind.flags = BIND_PIRQ__WILL_SHARE;
	if ((ret = HYPERVISOR_event_channel_op(EVTCHNOP_bind_pirq, &bind)) != 0)
		panic("xen_bind_pirq() failed (err %d)", ret);
	return (bind.port);
}

/* unmask an evtchn and send upcall to appropriate vcpu if pending bit is set */
static void
xen_evtchn_unmask(int evtchn)
{
	evtchn_unmask_t unmask;

	unmask.port = evtchn;
	if (HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &unmask) != 0)
		panic("xen_evtchn_unmask() failed");
}

static void
update_evtchn_affinity(int evtchn)
{
	cpu_t *cp;
	struct xen_evt_data *cpe;

	ASSERT(evtchn_to_irq[evtchn] != INVALID_IRQ);
	ASSERT(MUTEX_HELD(&ec_lock));

	/*
	 * Use lockless search of cpu_list, similar to mutex_vector_enter().
	 */
	kpreempt_disable();
	cp = cpu_list;
	do {
		cpe = cp->cpu_m.mcpu_evt_pend;
		if (CPU_IN_SET(evtchn_cpus[evtchn], cp->cpu_id))
			SET_EVTCHN_BIT(evtchn, cpe->evt_affinity);
		else
			CLEAR_EVTCHN_BIT(evtchn, cpe->evt_affinity);
	} while ((cp = cp->cpu_next) != cpu_list);
	kpreempt_enable();
}

static void
bind_evtchn_to_cpuset(int evtchn, cpuset_t cpus)
{
	ASSERT(evtchn_to_irq[evtchn] != INVALID_IRQ);

	CPUSET_ZERO(evtchn_cpus[evtchn]);
	CPUSET_OR(evtchn_cpus[evtchn], cpus);
	update_evtchn_affinity(evtchn);
}

static void
clear_evtchn_affinity(int evtchn)
{
	CPUSET_ZERO(evtchn_cpus[evtchn]);
	update_evtchn_affinity(evtchn);
}

static void
alloc_irq_evtchn(int irq, int index, int evtchn, int cpu)
{
	irq_info_t *irqp = &irq_info[irq];

	switch (irqp->ii_type) {
	case IRQT_IPI:
		ipi_info[index].mi_evtchns[cpu] = evtchn;
		irqp->ii_u.index = index;
		break;
	case IRQT_VIRQ:
		virq_info[index].mi_evtchns[cpu] = evtchn;
		irqp->ii_u.index = index;
		break;
	default:
		irqp->ii_u.evtchn = evtchn;
		break;
	}

	evtchn_to_irq[evtchn] = irq;

	/*
	 * If a CPU is not specified, we expect to bind it to a CPU later via
	 * the PSM.
	 */
	if (cpu != -1) {
		cpuset_t tcpus;
		CPUSET_ONLY(tcpus, cpu);
		bind_evtchn_to_cpuset(evtchn, tcpus);
	}
}

static int
alloc_irq(int type, int index, int evtchn, int cpu)
{
	int irq;
	irq_info_t *irqp;

	ASSERT(MUTEX_HELD(&ec_lock));
	ASSERT(type != IRQT_IPI || cpu != -1);

	for (irq = 0; irq < NR_IRQS; irq++) {
		if (irq_info[irq].ii_type == IRQT_UNBOUND)
			break;
	}

	if (irq == NR_IRQS)
		panic("No available IRQ to bind to: increase NR_IRQS!\n");

	irqp = &irq_info[irq];

	irqp->ii_type = type;
	/*
	 * Set irq/has_handler field to zero which means handler not installed
	 */
	irqp->ii_u2.has_handler = 0;

	alloc_irq_evtchn(irq, index, evtchn, cpu);
	return (irq);
}

static int
irq_evtchn(irq_info_t *irqp)
{
	int evtchn;

	ASSERT(irqp->ii_type != IRQT_DEV_EVTCHN);

	switch (irqp->ii_type) {
	case IRQT_IPI:
		ASSERT(irqp->ii_u.index != 0);
		evtchn = ipi_info[irqp->ii_u.index].mi_evtchns[CPU->cpu_id];
		break;
	case IRQT_VIRQ:
		evtchn = virq_info[irqp->ii_u.index].mi_evtchns[CPU->cpu_id];
		break;
	default:
		evtchn = irqp->ii_u.evtchn;
		break;
	}

	return (evtchn);
}

int
ec_is_edge_pirq(int irq)
{
	return (irq_info[irq].ii_type == IRQT_PIRQ &&
	    !TEST_EVTCHN_BIT(irq, &pirq_needs_eoi[0]));
}

static void
unbind_evtchn(ushort_t *evtchnp)
{
	int err;

	ASSERT(MUTEX_HELD(&ec_lock));

	ASSERT(*evtchnp != 0);

	err = xen_close_evtchn(*evtchnp);
	ASSERT(err == 0);
	clear_evtchn_affinity(*evtchnp);
	evtchn_to_irq[*evtchnp] = INVALID_IRQ;
	*evtchnp = 0;
}

static void
pirq_unmask_notify(int pirq)
{
	struct physdev_eoi eoi;

	if (TEST_EVTCHN_BIT(pirq, &pirq_needs_eoi[0])) {
		eoi.irq = pirq;
		(void) HYPERVISOR_physdev_op(PHYSDEVOP_eoi, &eoi);
	}
}

static void
pirq_query_unmask(int pirq)
{
	struct physdev_irq_status_query irq_status;

	irq_status.irq = pirq;
	(void) HYPERVISOR_physdev_op(PHYSDEVOP_irq_status_query, &irq_status);
	CLEAR_EVTCHN_BIT(pirq, &pirq_needs_eoi[0]);
	if (irq_status.flags & XENIRQSTAT_needs_eoi)
		SET_EVTCHN_BIT(pirq, &pirq_needs_eoi[0]);
}

static void
end_pirq(int irq)
{
	int evtchn = irq_evtchn(&irq_info[irq]);

	/*
	 * If it is an edge-triggered interrupt we have already unmasked
	 */
	if (TEST_EVTCHN_BIT(irq, &pirq_needs_eoi[0])) {
		ec_unmask_evtchn(evtchn);
		pirq_unmask_notify(IRQ_TO_PIRQ(irq));
	}
}

/*
 * Bind an event channel to a vcpu
 */
void
ec_bind_vcpu(int evtchn, int cpu)
{
	mutex_enter(&ec_lock);
	xen_bind_vcpu(evtchn, cpu);
	mutex_exit(&ec_lock);
}

/*
 * Set up a physical device irq to be associated with an event channel.
 */
void
ec_setup_pirq(int irq, int ipl, cpuset_t *cpusp)
{
	int evtchn;
	irq_info_t *irqp = &irq_info[irq];

	/*
	 * Test if this PIRQ is already bound to an evtchn,
	 * which means it is a shared IRQ and we don't want to
	 * bind and do some initial setup that has already been
	 * done for this irq on a previous trip through this code.
	 */
	if (irqp->ii_u.evtchn == INVALID_EVTCHN) {
		evtchn = xen_bind_pirq(irq);

		pirq_query_unmask(IRQ_TO_PIRQ(irq));

		irqp->ii_type = IRQT_PIRQ;
		irqp->ii_u.evtchn = evtchn;

		evtchn_to_irq[evtchn] = irq;
		irqp->ii_u2.ipl = ipl;
		ec_set_irq_affinity(irq, *cpusp);
		ec_enable_irq(irq);
		pirq_unmask_notify(IRQ_TO_PIRQ(irq));
	} else {
		ASSERT(irqp->ii_u2.ipl != 0);
		cmn_err(CE_NOTE, "!IRQ%d is shared", irq);
		if (ipl > irqp->ii_u2.ipl)
			irqp->ii_u2.ipl = ipl;
		*cpusp = evtchn_cpus[irqp->ii_u.evtchn];
	}
}

void
ec_unbind_irq(int irq)
{
	irq_info_t *irqp = &irq_info[irq];
	mec_info_t *virqp;
	int drop_lock = 0;
	int type, i;

	/*
	 * Nasty, but we need this during suspend.
	 */
	if (mutex_owner(&ec_lock) != curthread) {
		mutex_enter(&ec_lock);
		drop_lock = 1;
	}

	type = irqp->ii_type;

	ASSERT((type == IRQT_EVTCHN) || (type == IRQT_PIRQ) ||
	    (type == IRQT_VIRQ));

	if ((type == IRQT_EVTCHN) || (type == IRQT_PIRQ)) {
		/* There's only one event channel associated with this irq */
		unbind_evtchn(&irqp->ii_u.evtchn);
	} else if (type == IRQT_VIRQ) {
		/*
		 * Each cpu on the system can have it's own event channel
		 * associated with a virq.  Unbind them all.
		 */
		virqp = &virq_info[irqp->ii_u.index];
		for (i = 0; i < NCPU; i++) {
			if (virqp->mi_evtchns[i] != 0)
				unbind_evtchn(&virqp->mi_evtchns[i]);
		}
		/* Mark the virq structure as invalid. */
		virqp->mi_irq = INVALID_IRQ;
	}

	bzero(irqp, sizeof (*irqp));
	/* Re-reserve PIRQ. */
	if (type == IRQT_PIRQ)
		irqp->ii_type = IRQT_PIRQ;

	if (drop_lock)
		mutex_exit(&ec_lock);
}

/*
 * Rebind an event channel for delivery to a CPU.
 */
void
ec_set_irq_affinity(int irq, cpuset_t dest)
{
	int evtchn, tcpu;
	irq_info_t *irqp = &irq_info[irq];

	mutex_enter(&ec_lock);

	ASSERT(irq < NR_IRQS);
	ASSERT(irqp->ii_type != IRQT_UNBOUND);

	/*
	 * Binding is done at allocation time for these types, so we should
	 * never modify them.
	 */
	if (irqp->ii_type == IRQT_IPI || irqp->ii_type == IRQT_VIRQ ||
	    irqp->ii_type == IRQT_DEV_EVTCHN) {
		mutex_exit(&ec_lock);
		return;
	}

	CPUSET_FIND(dest, tcpu);
	ASSERT(tcpu != CPUSET_NOTINSET);

	evtchn = irq_evtchn(irqp);

	xen_bind_vcpu(evtchn, tcpu);

	bind_evtchn_to_cpuset(evtchn, dest);

	mutex_exit(&ec_lock);

	/*
	 * Now send the new target processor a NOP IPI.
	 * It will check for any pending interrupts, and so service any that
	 * got delivered to the wrong processor by mistake.
	 */
	if (ncpus > 1)
		poke_cpu(tcpu);
}

int
ec_set_irq_priority(int irq, int pri)
{
	irq_info_t *irqp;

	if (irq >= NR_IRQS)
		return (-1);

	irqp = &irq_info[irq];

	if (irqp->ii_type == IRQT_UNBOUND)
		return (-1);

	irqp->ii_u2.ipl = pri;

	return (0);
}

void
ec_clear_irq_priority(int irq)
{
	irq_info_t *irqp = &irq_info[irq];

	ASSERT(irq < NR_IRQS);
	ASSERT(irqp->ii_type != IRQT_UNBOUND);

	irqp->ii_u2.ipl = 0;
}

int
ec_bind_evtchn_to_irq(int evtchn)
{
	mutex_enter(&ec_lock);

	ASSERT(evtchn_to_irq[evtchn] == INVALID_IRQ);

	(void) alloc_irq(IRQT_EVTCHN, 0, evtchn, -1);

	mutex_exit(&ec_lock);
	return (evtchn_to_irq[evtchn]);
}

int
ec_bind_virq_to_irq(int virq, int cpu)
{
	int err;
	int evtchn;
	mec_info_t *virqp;

	virqp = &virq_info[virq];
	mutex_enter(&ec_lock);

	err = xen_bind_virq(virq, cpu, &evtchn);
	ASSERT(err == 0);

	ASSERT(evtchn_to_irq[evtchn] == INVALID_IRQ);

	if (virqp->mi_irq == INVALID_IRQ) {
		virqp->mi_irq = alloc_irq(IRQT_VIRQ, virq, evtchn, cpu);
	} else {
		alloc_irq_evtchn(virqp->mi_irq, virq, evtchn, cpu);
	}

	mutex_exit(&ec_lock);

	return (virqp->mi_irq);
}

int
ec_bind_ipi_to_irq(int ipl, int cpu)
{
	int evtchn;
	ulong_t flags;
	mec_info_t *ipip;

	mutex_enter(&ec_lock);

	ipip = &ipi_info[ipl];

	evtchn = xen_bind_ipi(cpu);

	ASSERT(evtchn_to_irq[evtchn] == INVALID_IRQ);

	if (ipip->mi_irq == INVALID_IRQ) {
		ipip->mi_irq = alloc_irq(IRQT_IPI, ipl, evtchn, cpu);
	} else {
		alloc_irq_evtchn(ipip->mi_irq, ipl, evtchn, cpu);
	}

	/*
	 * Unmask the new evtchn so that it can be seen by the target cpu
	 */
	flags = intr_clear();
	ec_unmask_evtchn(evtchn);
	intr_restore(flags);

	mutex_exit(&ec_lock);
	return (ipip->mi_irq);
}

/*
 * When bringing up a CPU, bind to all the IPIs that CPU0 bound.
 */
void
ec_bind_cpu_ipis(int cpu)
{
	int i;

	for (i = 0; i < MAXIPL; i++) {
		mec_info_t *ipip = &ipi_info[i];
		if (ipip->mi_irq == INVALID_IRQ)
			continue;

		(void) ec_bind_ipi_to_irq(i, cpu);
	}
}

/*
 * Can this IRQ be rebound to another CPU?
 */
int
ec_irq_rebindable(int irq)
{
	irq_info_t *irqp = &irq_info[irq];

	if (irqp->ii_u.evtchn == 0)
		return (0);

	return (irqp->ii_type == IRQT_EVTCHN || irqp->ii_type == IRQT_PIRQ);
}

/*
 * Should this IRQ be unbound from this CPU (which is being offlined) to
 * another?
 */
int
ec_irq_needs_rebind(int irq, int cpu)
{
	irq_info_t *irqp = &irq_info[irq];

	return (ec_irq_rebindable(irq) &&
	    CPU_IN_SET(evtchn_cpus[irqp->ii_u.evtchn], cpu));
}

void
ec_send_ipi(int ipl, int cpu)
{
	mec_info_t *ipip = &ipi_info[ipl];

	ASSERT(ipip->mi_irq != INVALID_IRQ);

	ec_notify_via_evtchn(ipip->mi_evtchns[cpu]);
}

void
ec_try_ipi(int ipl, int cpu)
{
	mec_info_t *ipip = &ipi_info[ipl];

	if (ipip->mi_irq == INVALID_IRQ || ipip->mi_irq == 0)
		return;

	ec_notify_via_evtchn(ipip->mi_evtchns[cpu]);
}

void
ec_irq_add_evtchn(int irq, int evtchn)
{
	mutex_enter(&ec_lock);

	/*
	 * See description of IRQT_DEV_EVTCHN above.
	 */
	ASSERT(irq == ec_dev_irq);

	alloc_irq_evtchn(irq, 0, evtchn, 0);
	/*
	 * We enforce that the representative event channel for IRQT_DEV_EVTCHN
	 * is zero, so PSM operations on it have no effect.
	 */
	irq_info[irq].ii_u.evtchn = 0;
	mutex_exit(&ec_lock);
}

void
ec_irq_rm_evtchn(int irq, int evtchn)
{
	ushort_t ec = evtchn;

	mutex_enter(&ec_lock);
	ASSERT(irq == ec_dev_irq);
	unbind_evtchn(&ec);
	mutex_exit(&ec_lock);
}

/*
 * Allocate an /dev/xen/evtchn IRQ.  See the big comment at the top
 * for an explanation.
 */
int
ec_dev_alloc_irq(void)
{
	int i;
	irq_info_t *irqp;

	for (i = 0; i < NR_IRQS; i++) {
		if (irq_info[i].ii_type == IRQT_UNBOUND)
			break;
	}

	ASSERT(i != NR_IRQS);

	irqp = &irq_info[i];
	irqp->ii_type = IRQT_DEV_EVTCHN;
	irqp->ii_u2.ipl = IPL_EVTCHN;
	/*
	 * Force the evtchn to zero for the special evtchn device irq
	 */
	irqp->ii_u.evtchn = 0;
	return (i);
}

void
ec_enable_irq(unsigned int irq)
{
	ulong_t flag;
	irq_info_t *irqp = &irq_info[irq];

	if (irqp->ii_type == IRQT_DEV_EVTCHN)
		return;

	flag = intr_clear();
	ec_unmask_evtchn(irq_evtchn(irqp));
	intr_restore(flag);
}

void
ec_disable_irq(unsigned int irq)
{
	irq_info_t *irqp = &irq_info[irq];

	if (irqp->ii_type == IRQT_DEV_EVTCHN)
		return;

	/*
	 * Spin till we are the one to mask the evtchn
	 * Ensures no one else can be servicing this evtchn.
	 */
	while (!ec_mask_evtchn(irq_evtchn(irqp)))
		SMT_PAUSE();
}

static int
ec_evtchn_pending(uint_t ev)
{
	uint_t evi;
	shared_info_t *si = HYPERVISOR_shared_info;

	evi = ev >> EVTCHN_SHIFT;
	ev &= (1ul << EVTCHN_SHIFT) - 1;
	return ((si->evtchn_pending[evi] & (1ul << ev)) != 0);
}

int
ec_pending_irq(unsigned int irq)
{
	int evtchn = irq_evtchn(&irq_info[irq]);

	return (ec_evtchn_pending(evtchn));
}

void
ec_clear_irq(int irq)
{
	irq_info_t *irqp = &irq_info[irq];
	int evtchn;

	if (irqp->ii_type == IRQT_DEV_EVTCHN)
		return;

	ASSERT(irqp->ii_type != IRQT_UNBOUND);

	evtchn = irq_evtchn(irqp);

	ASSERT(EVTCHN_MASKED(evtchn));
	ec_clear_evtchn(evtchn);
}

void
ec_unmask_irq(int irq)
{
	ulong_t flags;
	irq_info_t *irqp = &irq_info[irq];

	flags = intr_clear();
	switch (irqp->ii_type) {
	case IRQT_PIRQ:
		end_pirq(irq);
		break;
	case IRQT_DEV_EVTCHN:
		break;
	default:
		ec_unmask_evtchn(irq_evtchn(irqp));
		break;
	}
	intr_restore(flags);
}

void
ec_try_unmask_irq(int irq)
{
	ulong_t flags;
	irq_info_t *irqp = &irq_info[irq];
	int evtchn;

	flags = intr_clear();
	switch (irqp->ii_type) {
	case IRQT_PIRQ:
		end_pirq(irq);
		break;
	case IRQT_DEV_EVTCHN:
		break;
	default:
		if ((evtchn = irq_evtchn(irqp)) != 0)
			ec_unmask_evtchn(evtchn);
		break;
	}
	intr_restore(flags);
}

/*
 * Poll until an event channel is ready or 'check_func' returns true.  This can
 * only be used in a situation where interrupts are masked, otherwise we have a
 * classic time-of-check vs. time-of-use race.
 */
void
ec_wait_on_evtchn(int evtchn, int (*check_func)(void *), void *arg)
{
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		while (!check_func(arg))
			(void) HYPERVISOR_yield();
		return;
	}

	ASSERT(CPU->cpu_m.mcpu_vcpu_info->evtchn_upcall_mask != 0);

	for (;;) {
		evtchn_port_t ports[1];

		ports[0] = evtchn;

		ec_clear_evtchn(evtchn);

		if (check_func(arg))
			return;

		(void) HYPERVISOR_poll(ports, 1, 0);
	}
}

void
ec_wait_on_ipi(int ipl, int (*check_func)(void *), void *arg)
{
	mec_info_t *ipip = &ipi_info[ipl];

	if (ipip->mi_irq == INVALID_IRQ || ipip->mi_irq == 0)
		return;

	ec_wait_on_evtchn(ipip->mi_evtchns[CPU->cpu_id], check_func, arg);
}

void
ec_suspend(void)
{
	irq_info_t *irqp;
	ushort_t *evtchnp;
	int i;
	int c;

	ASSERT(MUTEX_HELD(&ec_lock));

	for (i = 0; i < MAXIPL; i++) {
		if (ipi_info[i].mi_irq == INVALID_IRQ)
			continue;

		for (c = 0; c < NCPU; c++) {
			if (cpu[c] == NULL)
				continue;

			if (CPU_IN_SET(cpu_suspend_lost_set, c))
				continue;

			evtchnp = &ipi_info[i].mi_evtchns[c];
			ASSERT(*evtchnp != 0);
			unbind_evtchn(evtchnp);
		}
	}

	for (i = 0; i < NR_VIRQS; i++) {
		if (virq_info[i].mi_irq == INVALID_IRQ)
			continue;

		/*
		 * If we're sharing a single event channel across all CPUs, we
		 * should only unbind once.
		 */
		if (virq_info[i].mi_shared) {
			evtchnp = &virq_info[i].mi_evtchns[0];
			unbind_evtchn(evtchnp);
			for (c = 1; c < NCPU; c++)
				virq_info[i].mi_evtchns[c] = 0;
		} else {
			for (c = 0; c < NCPU; c++) {
				if (cpu[c] == NULL)
					continue;

				evtchnp = &virq_info[i].mi_evtchns[c];
				if (*evtchnp != 0)
					unbind_evtchn(evtchnp);
			}
		}
	}

	for (i = 0; i < NR_IRQS; i++) {
		irqp = &irq_info[i];

		switch (irqp->ii_type) {
		case IRQT_EVTCHN:
		case IRQT_DEV_EVTCHN:
			(void) HYPERVISOR_shutdown(SHUTDOWN_crash);
			break;
		case IRQT_PIRQ:
			if (irqp->ii_u.evtchn != 0)
				(void) HYPERVISOR_shutdown(SHUTDOWN_crash);
			break;
		default:
			break;
		}
	}
}

/*
 * The debug irq is special, we only have one evtchn and irq but we allow all
 * cpus to service it.  It's marked as shared and we propogate the event
 * channel into all CPUs by hand.
 */
static void
share_virq(mec_info_t *virqp)
{
	int evtchn = virqp->mi_evtchns[0];
	cpuset_t tset;
	int i;

	ASSERT(evtchn != 0);

	virqp->mi_shared = 1;

	for (i = 1; i < NCPU; i++)
		virqp->mi_evtchns[i] = evtchn;
	CPUSET_ALL(tset);
	bind_evtchn_to_cpuset(evtchn, tset);
}

static void
virq_resume(int virq)
{
	mec_info_t *virqp = &virq_info[virq];
	int evtchn;
	int i, err;

	for (i = 0; i < NCPU; i++) {
		cpuset_t tcpus;

		if (cpu[i] == NULL || CPU_IN_SET(cpu_suspend_lost_set, i))
			continue;

		err = xen_bind_virq(virq, i, &evtchn);
		ASSERT(err == 0);

		virqp->mi_evtchns[i] = evtchn;
		evtchn_to_irq[evtchn] = virqp->mi_irq;
		CPUSET_ONLY(tcpus, i);
		bind_evtchn_to_cpuset(evtchn, tcpus);
		ec_unmask_evtchn(evtchn);
		/*
		 * only timer VIRQ is bound to all cpus
		 */
		if (virq != VIRQ_TIMER)
			break;
	}

	if (virqp->mi_shared)
		share_virq(virqp);
}

static void
ipi_resume(int ipl)
{
	mec_info_t *ipip = &ipi_info[ipl];
	int i;

	for (i = 0; i < NCPU; i++) {
		cpuset_t tcpus;
		int evtchn;

		if (cpu[i] == NULL || CPU_IN_SET(cpu_suspend_lost_set, i))
			continue;

		evtchn = xen_bind_ipi(i);
		ipip->mi_evtchns[i] = evtchn;
		evtchn_to_irq[evtchn] = ipip->mi_irq;
		CPUSET_ONLY(tcpus, i);
		bind_evtchn_to_cpuset(evtchn, tcpus);
		ec_unmask_evtchn(evtchn);
	}
}

void
ec_resume(void)
{
	int i;

	/* New event-channel space is not 'live' yet. */
	for (i = 0; i < NR_EVENT_CHANNELS; i++)
		(void) ec_mask_evtchn(i);

	for (i = 0; i < MAXIPL; i++) {
		if (ipi_info[i].mi_irq == INVALID_IRQ)
			continue;
		ipi_resume(i);
	}

	for (i = 0; i < NR_VIRQS; i++) {
		if (virq_info[i].mi_irq == INVALID_IRQ)
			continue;
		virq_resume(i);
	}
}

int
ec_init(void)
{
	int i;
	mutex_init(&ec_lock, NULL, MUTEX_SPIN, (void *)ipltospl(SPL7));

	for (i = 0; i < NR_EVENT_CHANNELS; i++) {
		CPUSET_ZERO(evtchn_cpus[i]);
		evtchn_to_irq[i] = INVALID_IRQ;
		(void) ec_mask_evtchn(i);
	}

	for (i = 0; i < MAXIPL; i++)
		ipi_info[i].mi_irq = INVALID_IRQ;

	for (i = 0; i < NR_VIRQS; i++)
		virq_info[i].mi_irq = INVALID_IRQ;

	/*
	 * Phys IRQ space is statically bound (1:1 mapping), grab the IRQs
	 * now.
	 */
	for (i = PIRQ_BASE; i < NR_PIRQS; i++) {
		irq_info[PIRQ_TO_IRQ(i)].ii_type = IRQT_PIRQ;
	}

	return (0);
}

void
ec_init_debug_irq()
{
	int irq;

	irq = ec_bind_virq_to_irq(VIRQ_DEBUG, 0);
	(void) add_avintr(NULL, IPL_DEBUG, xen_debug_handler,
	    "debug", irq, NULL, NULL, NULL, NULL);

	mutex_enter(&ec_lock);
	share_virq(&virq_info[irq_info[irq].ii_u.index]);
	mutex_exit(&ec_lock);
	ec_debug_irq = irq;
}

#define	UNBLOCKED_EVENTS(si, ix, cpe, cpu_id) \
	((si)->evtchn_pending[ix] & ~(si)->evtchn_mask[ix] & \
		(cpe)->evt_affinity[ix])


/*
 * This is the entry point for processing events from xen
 *
 * (See the commentary associated with the shared_info_st structure
 * in hypervisor-if.h)
 *
 * Since the event channel mechanism doesn't really implement the
 * concept of priority like hardware interrupt controllers, we simulate
 * that in software here using the cpu priority field and the pending
 * interrupts field.  Events/interrupts that are not able to be serviced
 * now because they are at a lower priority than the current cpu priority
 * cause a level bit to be recorded in the pending interrupts word.  When
 * the priority is lowered (either by spl or interrupt exit code) the pending
 * levels are checked and an upcall is scheduled if there are events/interrupts
 * that have become deliverable.
 */
void
xen_callback_handler(struct regs *rp, trap_trace_rec_t *ttp)
{
	ulong_t pending_sels, pe, selbit;
	int i, j, port, pri, curpri, irq, sipri;
	uint16_t pending_ints, sip;
	struct cpu *cpu = CPU;
	volatile shared_info_t *si = HYPERVISOR_shared_info;
	volatile vcpu_info_t *vci = cpu->cpu_m.mcpu_vcpu_info;
	volatile struct xen_evt_data *cpe = cpu->cpu_m.mcpu_evt_pend;
	volatile uint16_t *cpu_ipp = &cpu->cpu_m.mcpu_intr_pending;
	extern void dosoftint(struct regs *);

	ASSERT(rp->r_trapno == T_AST && rp->r_err == 0);
	ASSERT(&si->vcpu_info[cpu->cpu_id] == vci);
	ASSERT_STACK_ALIGNED();

	vci->evtchn_upcall_pending = 0;

	/*
	 * To expedite scanning of pending notifications, any 0->1
	 * pending transition on an unmasked channel causes a
	 * corresponding bit in evtchn_pending_sel to be set.
	 * Each bit in the selector covers a 32-bit word in
	 * the evtchn_pending[] array.
	 */
	membar_enter();
	do {
		pending_sels = vci->evtchn_pending_sel;
	} while (atomic_cas_ulong((volatile ulong_t *)&vci->evtchn_pending_sel,
	    pending_sels, 0) != pending_sels);

	pending_ints = *cpu_ipp;
	while ((i = ffs(pending_sels)) != 0) {
		i--;
		selbit = 1ul << i;
		pending_sels &= ~selbit;

		membar_enter();
		while ((pe = UNBLOCKED_EVENTS(si, i, cpe, cpu->cpu_id)) != 0) {
			j = ffs(pe) - 1;
			pe &= ~(1ul << j);

			port = (i << EVTCHN_SHIFT) + j;

			irq = evtchn_to_irq[port];

			/*
			 * If no irq set, just ignore the event.
			 * On e.g. netbsd they call evtchn_device_upcall(port)
			 * We require the evtchn driver to install a handler
			 * so there will be an irq associated with user mode
			 * evtchns.
			 */
			if (irq == INVALID_IRQ) {
				ec_clear_evtchn(port);
				continue;
			}

			/*
			 * If there's no handler, it could be a poke, so just
			 * accept the event and continue.
			 */
			if (!irq_info[irq].ii_u2.has_handler) {
#ifdef TRAPTRACE
				ttp->ttr_ipl = 0xff;
				if (IRQ_IS_CPUPOKE(irq)) {
					ttp->ttr_ipl = XC_CPUPOKE_PIL;
					ttp->ttr_marker = TT_INTERRUPT;
				}
				ttp->ttr_pri = cpu->cpu_pri;
				ttp->ttr_spl = cpu->cpu_base_spl;
				ttp->ttr_vector = 0xff;
#endif /* TRAPTRACE */
				if (ec_mask_evtchn(port)) {
					ec_clear_evtchn(port);
					ec_unmask_evtchn(port);
					continue;
				}
			}

			pri = irq_info[irq].ii_u2.ipl;

			/*
			 * If we are the cpu that successfully masks
			 * the event, then record it as a pending event
			 * for this cpu to service
			 */
			if (ec_mask_evtchn(port)) {
				if (ec_evtchn_pending(port)) {
					cpe->pending_sel[pri] |= selbit;
					cpe->pending_evts[pri][i] |= (1ul << j);
					pending_ints |= 1 << pri;
					/*
					 * We have recorded a pending interrupt
					 * for this cpu.  If it is an edge
					 * triggered interrupt then we go ahead
					 * and clear the pending and mask bits
					 * from the shared info to avoid having
					 * the hypervisor see the pending event
					 * again and possibly disabling the
					 * interrupt.  This should also help
					 * keep us from missing an interrupt.
					 */
					if (ec_is_edge_pirq(irq)) {
						ec_clear_evtchn(port);
						ec_unmask_evtchn(port);
					}
				} else {
					/*
					 * another cpu serviced this event
					 * before us, clear the mask.
					 */
					ec_unmask_evtchn(port);
				}
			}
		}
	}
	*cpu_ipp = pending_ints;
	if (pending_ints == 0)
		return;
	/*
	 * We have gathered all the pending events/interrupts,
	 * go service all the ones we can from highest priority to lowest.
	 * Note: This loop may not actually complete and service all
	 * pending interrupts since one of the interrupt threads may
	 * block and the pinned thread runs.  In that case, when we
	 * exit the interrupt thread that blocked we will check for
	 * any unserviced interrupts and re-post an upcall to process
	 * any unserviced pending events.
	 */
restart:
	curpri = cpu->cpu_pri;
	pri = bsrw_insn(*cpu_ipp);
	while (pri > curpri) {
		while ((pending_sels = cpe->pending_sel[pri]) != 0) {
			i = ffs(pending_sels) - 1;
			while ((pe = cpe->pending_evts[pri][i]) != 0) {
				j = ffs(pe) - 1;
				port = (i << EVTCHN_SHIFT) + j;
				pe &= ~(1ul << j);
				cpe->pending_evts[pri][i] = pe;
				if (pe == 0) {
					/*
					 * Must reload pending selector bits
					 * here as they could have changed on
					 * a previous trip around the inner loop
					 * while we were interrupt enabled
					 * in a interrupt service routine.
					 */
					pending_sels = cpe->pending_sel[pri];
					pending_sels &= ~(1ul << i);
					cpe->pending_sel[pri] = pending_sels;
					if (pending_sels == 0)
						*cpu_ipp &= ~(1 << pri);
				}
				irq = evtchn_to_irq[port];
				if (irq == INVALID_IRQ) {
					/*
					 * No longer a handler for this event
					 * channel.  Clear the event and
					 * ignore it, unmask the event.
					 */
					ec_clear_evtchn(port);
					ec_unmask_evtchn(port);
					continue;
				}
				if (irq == ec_dev_irq) {
					ASSERT(cpu->cpu_m.mcpu_ec_mbox == 0);
					cpu->cpu_m.mcpu_ec_mbox = port;
				}
				/*
				 * Set up the regs struct to
				 * look like a normal hardware int
				 * and do normal interrupt handling.
				 */
				rp->r_trapno = irq;
				do_interrupt(rp, ttp);
				/*
				 * Check for cpu priority change
				 * Can happen if int thread blocks
				 */
				if (cpu->cpu_pri != curpri)
					goto restart;
			}
		}
		/*
		 * Dispatch any soft interrupts that are
		 * higher priority than any hard ones remaining.
		 */
		pri = bsrw_insn(*cpu_ipp);
		sip = (uint16_t)cpu->cpu_softinfo.st_pending;
		if (sip != 0) {
			sipri = bsrw_insn(sip);
			if (sipri > pri && sipri > cpu->cpu_pri) {
				dosoftint(rp);
				/*
				 * Check for cpu priority change
				 * Can happen if softint thread blocks
				 */
				if (cpu->cpu_pri != curpri)
					goto restart;
			}
		}
	}
	/*
	 * Deliver any pending soft interrupts.
	 */
	if (cpu->cpu_softinfo.st_pending)
		dosoftint(rp);
}


void
ec_unmask_evtchn(unsigned int ev)
{
	uint_t evi, evb;
	volatile shared_info_t *si = HYPERVISOR_shared_info;
	volatile vcpu_info_t *vci = CPU->cpu_m.mcpu_vcpu_info;
	volatile ulong_t *ulp;

	ASSERT(!interrupts_enabled());
	/*
	 * Check if we need to take slow path
	 */
	if (!CPU_IN_SET(evtchn_cpus[ev], CPU->cpu_id)) {
		xen_evtchn_unmask(ev);
		return;
	}
	evi = ev >> EVTCHN_SHIFT;
	evb = ev & ((1ul << EVTCHN_SHIFT) - 1);
	ulp = (volatile ulong_t *)&si->evtchn_mask[evi];
	atomic_and_ulong(ulp, ~(1ul << evb));
	/*
	 * The following is basically the equivalent of
	 * 'hw_resend_irq'. Just like a real IO-APIC we 'lose the
	 * interrupt edge' if the channel is masked.
	 * XXPV - slight race if upcall was about to be set, we may get
	 * an extra upcall.
	 */
	membar_enter();
	if (si->evtchn_pending[evi] & (1ul << evb)) {
		membar_consumer();
		ulp = (volatile ulong_t *)&vci->evtchn_pending_sel;
		if (!(*ulp & (1ul << evi))) {
			atomic_or_ulong(ulp, (1ul << evi));
		}
		vci->evtchn_upcall_pending = 1;
	}
}

/*
 * Set a bit in an evtchan mask word, return true if we are the cpu that
 * set the bit.
 */
int
ec_mask_evtchn(unsigned int ev)
{
	uint_t evi, evb;
	ulong_t new, old, bit;
	volatile shared_info_t *si = HYPERVISOR_shared_info;
	volatile ulong_t *maskp;
	int masked;

	kpreempt_disable();
	evi = ev >> EVTCHN_SHIFT;
	evb = ev & ((1ul << EVTCHN_SHIFT) - 1);
	bit = 1ul << evb;
	maskp = (volatile ulong_t *)&si->evtchn_mask[evi];
	do {
		old = si->evtchn_mask[evi];
		new = old | bit;
	} while (atomic_cas_ulong(maskp, old, new) != old);
	masked = (old & bit) == 0;
	if (masked) {
		evtchn_owner[ev] = CPU->cpu_id;
#ifdef DEBUG
		evtchn_owner_thread[ev] = curthread;
#endif
	}
	kpreempt_enable();
	return (masked);
}

void
ec_clear_evtchn(unsigned int ev)
{
	uint_t evi;
	shared_info_t *si = HYPERVISOR_shared_info;
	volatile ulong_t *pendp;

	evi = ev >> EVTCHN_SHIFT;
	ev &= (1ul << EVTCHN_SHIFT) - 1;
	pendp = (volatile ulong_t *)&si->evtchn_pending[evi];
	atomic_and_ulong(pendp, ~(1ul << ev));
}

void
ec_notify_via_evtchn(unsigned int port)
{
	evtchn_send_t send;

	ASSERT(port != INVALID_EVTCHN);

	send.port = port;
	(void) HYPERVISOR_event_channel_op(EVTCHNOP_send, &send);
}

int
ec_block_irq(int irq)
{
	irq_info_t *irqp = &irq_info[irq];
	int evtchn;


	evtchn = irq_evtchn(irqp);
	(void) ec_mask_evtchn(evtchn);
	return (evtchn_owner[evtchn]);
}

/*
 * Make a event that is pending for delivery on the current cpu  "go away"
 * without servicing the interrupt.
 */
void
ec_unpend_irq(int irq)
{
	irq_info_t *irqp = &irq_info[irq];
	int pri = irqp->ii_u2.ipl;
	ulong_t flags;
	uint_t evtchn, evi, bit;
	unsigned long pe, pending_sels;
	struct xen_evt_data *cpe;

	/*
	 * The evtchn must be masked
	 */
	evtchn = irq_evtchn(irqp);
	ASSERT(EVTCHN_MASKED(evtchn));
	evi = evtchn >> EVTCHN_SHIFT;
	bit = evtchn & (1ul << EVTCHN_SHIFT) - 1;
	flags = intr_clear();
	cpe = CPU->cpu_m.mcpu_evt_pend;
	pe = cpe->pending_evts[pri][evi] & ~(1ul << bit);
	cpe->pending_evts[pri][evi] = pe;
	if (pe == 0) {
		pending_sels = cpe->pending_sel[pri];
		pending_sels &= ~(1ul << evi);
		cpe->pending_sel[pri] = pending_sels;
		if (pending_sels == 0)
			CPU->cpu_m.mcpu_intr_pending &= ~(1 << pri);
	}
	intr_restore(flags);
}
