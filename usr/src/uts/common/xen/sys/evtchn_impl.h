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
 * evtchn.h (renamed to evtchn_impl.h)
 *
 * Communication via Xen event channels.
 * Also definitions for the device that demuxes notifications to userspace.
 *
 * Copyright (c) 2004-2005, K A Fraser
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

#ifndef _SYS_EVTCHN_H
#define	_SYS_EVTCHN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/privregs.h>
#include <sys/systm.h>
#include <sys/traptrace.h>
#include <sys/ddi_intr.h>
#include <sys/ddi_intr_impl.h>
#include <sys/avintr.h>
#include <sys/cpuvar.h>
#include <sys/hypervisor.h>

/* evtchn binding types */
#define	IRQT_UNBOUND	0	/* unassigned irq */
#define	IRQT_PIRQ	1	/* IRQ from phys hdw device */
#define	IRQT_VIRQ	2	/* Virtual IRQ from Xen */
#define	IRQT_IPI	3	/* Inter VCPU interrupt IRQ */
#define	IRQT_EVTCHN	4	/* Virtual device IRQ */
#define	IRQT_DEV_EVTCHN	5	/* Special evtchn device IRQ */

#define	SET_EVTCHN_BIT(bit, arrayp) \
	((arrayp)[bit >> EVTCHN_SHIFT] |= \
	(1ul << ((bit) & ((1ul << EVTCHN_SHIFT) - 1))))
#define	CLEAR_EVTCHN_BIT(bit, arrayp) \
	((arrayp)[bit >> EVTCHN_SHIFT] &= \
		~((1ul << ((bit) & ((1ul << EVTCHN_SHIFT) - 1)))))
#define	TEST_EVTCHN_BIT(bit, arrayp) \
	((arrayp)[bit >> EVTCHN_SHIFT] & \
		(1ul << ((bit) & ((1ul << EVTCHN_SHIFT) - 1))))

/* Xen will never allocate port zero for any purpose. */
#define	INVALID_EVTCHN	0

/* XXPV - should these defines be somewhere else? xenos.h perhaps? */

#define	IPL_DEBUG	15	/* domain debug interrupt */
#define	IPL_CONS	9
#define	IPL_VIF		6
#define	IPL_VBD		5
#define	IPL_EVTCHN	1

#define	PIRQ_BASE	0	/* base of pirq range */
#define	NR_PIRQS	256	/* Number of supported physical irqs */
#define	DYNIRQ_BASE	(PIRQ_BASE + NR_PIRQS) /* base of dynamic irq range */
#define	NR_DYNIRQS	256	/* Number of dynamic irqs */
#define	NR_IRQS		(NR_PIRQS + NR_DYNIRQS) /* total irq count */

#define	PIRQ_TO_IRQ(pirq)	((pirq) + PIRQ_BASE)
#define	IRQ_TO_PIRQ(irq)	((irq) - PIRQ_BASE)

#define	DYNIRQ_TO_IRQ(dirq)	((dirq) + DYNIRQ_BASE)
#define	IRQ_TO_DYNIRQ(irq)	((irq) - DYNIRQ_BASE)

#if defined(_LP64)
#define	EVTCHN_SHIFT	6	/* log2(NBBY * sizeof (ulong_t)) */
#else
#define	EVTCHN_SHIFT	5	/* log2(NBBY * sizeof (ulong_t)) */
#endif

#define	INVALID_IRQ -1

extern int ec_dev_irq;
extern kmutex_t ec_lock;

typedef struct mec_info {
	ushort_t mi_evtchns[NCPU];	/* event channels for this IRQ */
	short mi_irq;			/* the IRQ, or INVALID_IRQ */
	char mi_shared;			/* one evtchn for all CPUs? */
} mec_info_t;

/*
 * Careful: ii_ipl is /only/ set if there's a handler for this IRQ.
 */
typedef struct irq_info {
	union {
		ushort_t evtchn;	/* event channel */
		ushort_t index;		/* index to next table if mec */
	} ii_u;
	uchar_t ii_type;		/* IRQ type as above */
	union {
		uchar_t ipl;		/* IPL of IRQ, != 0 => has handler */
		uchar_t	has_handler;	/* alternate name for ipl */
	} ii_u2;
} irq_info_t;

extern int ec_is_edge_pirq(int);
extern int ec_init(void);
extern void ec_init_debug_irq(void);
extern void ec_suspend(void);
extern void ec_resume(void);
extern void ec_wait_on_evtchn(int, int (*)(void *), void *);
extern void ec_wait_on_ipi(int, int (*)(void *), void *);

extern void ec_setup_pirq(int, int, cpuset_t *);
extern void ec_set_irq_affinity(int, cpuset_t);
extern int ec_set_irq_priority(int, int);

extern int ec_bind_ipi_to_irq(int, int);
extern void ec_bind_cpu_ipis(int);
extern int ec_bind_evtchn_to_irq(int);
extern int ec_bind_virq_to_irq(int, int);
extern void ec_unbind_irq(int irq);

extern void ec_send_ipi(int, int);
extern void ec_try_ipi(int, int);
extern void ec_clear_irq(int);
extern void ec_unmask_irq(int);
extern void ec_try_unmask_irq(int);
extern int ec_block_irq(int);
extern void ec_unpend_irq(int);
extern int ec_irq_needs_rebind(int, int);
extern int ec_irq_rebindable(int);
extern int ec_pending_irq(unsigned int);
extern void ec_enable_irq(unsigned int);
extern void ec_disable_irq(unsigned int);

extern int xen_bind_interdomain(int, int, int *);
extern int xen_bind_virq(unsigned int, processorid_t, int *);
extern int xen_alloc_unbound_evtchn(int, int *);
extern void ec_bind_vcpu(int, int);

extern int ec_mask_evtchn(unsigned int);
extern void ec_unmask_evtchn(unsigned int);
extern void ec_clear_evtchn(unsigned int);

extern void ec_notify_via_evtchn(unsigned int);

/*
 * /dev/xen/evtchn handling.
 */
extern void ec_irq_add_evtchn(int, int);
extern void ec_irq_rm_evtchn(int, int);
extern int ec_dev_alloc_irq(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_EVTCHN_H */
