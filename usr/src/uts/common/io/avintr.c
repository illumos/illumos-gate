/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Autovectored Interrupt Configuration and Deconfiguration
 */

#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/trap.h>
#include <sys/t_lock.h>
#include <sys/avintr.h>
#include <sys/kmem.h>
#include <sys/machlock.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/sunddi.h>
#include <sys/x_call.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/smp_impldefs.h>
#include <sys/sdt.h>
#include <sys/stack.h>
#include <sys/ddi_impldefs.h>

static int insert_av(void *intr_id, struct av_head *vectp, avfunc f,
	caddr_t arg1, caddr_t arg2, int pri_level, dev_info_t *dip);
static void remove_av(void *intr_id, struct av_head *vectp, avfunc f,
	int pri_level, int vect);

/*
 * Arrange for a driver to be called when a particular
 * auto-vectored interrupt occurs.
 * NOTE: if a device can generate interrupts on more than
 * one level, or if a driver services devices that interrupt
 * on more than one level, then the driver should install
 * itself on each of those levels.
 */
static char badsoft[] =
	"add_avintr: bad soft interrupt level %d for driver '%s'\n";
static char multilevel[] =
	"!IRQ%d is being shared by drivers with different interrupt levels.\n"
	"This may result in reduced system performance.";
static char multilevel2[] =
	"Cannot register interrupt for '%s' device at IPL %d because it\n"
	"conflicts with another device using the same vector %d with an IPL\n"
	"of %d. Reconfigure the conflicting devices to use different vectors.";

#define	MAX_VECT	256
struct autovec *nmivect = NULL;
struct av_head autovect[MAX_VECT];
struct av_head softvect[LOCK_LEVEL + 1];
kmutex_t av_lock;
ddi_softint_hdl_impl_t softlevel1_hdl =
	{0, NULL, NULL, 0, 0, NULL, NULL, NULL};

void
set_pending(int pri)
{
	atomic_or_32((uint32_t *)&CPU->cpu_softinfo.st_pending, 1 << pri);
}

/*
 * register nmi interrupt routine. The first arg is used only to order
 * various nmi interrupt service routines in the chain. Higher lvls will
 * be called first
 */
int
add_nmintr(int lvl, avfunc nmintr, char *name, caddr_t arg)
{
	struct autovec  *mem;
	struct autovec *p, *prev = NULL;

	if (nmintr == NULL) {
		printf("Attempt to add null vect for %s on nmi\n", name);
		return (0);

	}

	mem = kmem_zalloc(sizeof (struct autovec), KM_SLEEP);
	mem->av_vector = nmintr;
	mem->av_intarg1 = arg;
	mem->av_intarg2 = NULL;
	mem->av_intr_id = NULL;
	mem->av_prilevel = lvl;
	mem->av_link = NULL;

	mutex_enter(&av_lock);

	if (!nmivect) {
		nmivect = mem;
		mutex_exit(&av_lock);
		return (1);
	}
	/* find where it goes in list */
	for (p = nmivect; p != NULL; p = p->av_link) {
		if (p->av_vector == nmintr && p->av_intarg1 == arg) {
			/*
			 * already in list
			 * So? Somebody added the same interrupt twice.
			 */
			cmn_err(CE_WARN, "Driver already registered '%s'",
			    name);
			kmem_free(mem, sizeof (struct autovec));
			mutex_exit(&av_lock);
			return (0);
		}
		if (p->av_prilevel < lvl) {
			if (p == nmivect) {   /* it's at head of list */
				mem->av_link = p;
				nmivect = mem;
			} else {
				mem->av_link = p;
				prev->av_link = mem;
			}
			mutex_exit(&av_lock);
			return (1);
		}
		prev = p;

	}
	/* didn't find it, add it to the end */
	prev->av_link = mem;
	mutex_exit(&av_lock);
	return (1);

}

/*
 * register a hardware interrupt handler.
 */
int
add_avintr(void *intr_id, int lvl, avfunc xxintr, char *name, int vect,
    caddr_t arg1, caddr_t arg2, dev_info_t *dip)
{
	struct av_head *vecp = (struct av_head *)0;
	avfunc f;
	int s, vectindex;			/* save old spl value */
	ushort_t hi_pri;

	if ((f = xxintr) == NULL) {
		printf("Attempt to add null vect for %s on vector %d\n",
			name, vect);
		return (0);

	}
	vectindex = vect % MAX_VECT;

	vecp = &autovect[vectindex];

	/*
	 * "hi_pri == 0" implies all entries on list are "unused",
	 * which means that it's OK to just insert this one.
	 */
	hi_pri = vecp->avh_hi_pri;
	if (vecp->avh_link && (hi_pri != 0)) {
		if (((hi_pri > LOCK_LEVEL) && (lvl < LOCK_LEVEL)) ||
		    ((hi_pri < LOCK_LEVEL) && (lvl > LOCK_LEVEL))) {
			cmn_err(CE_WARN, multilevel2, name, lvl, vect,
				hi_pri);
			return (0);
		}
		if ((vecp->avh_lo_pri != lvl) || (hi_pri != lvl))
			cmn_err(CE_NOTE, multilevel, vect);
	}

	if (!insert_av(intr_id, vecp, f, arg1, arg2, lvl, dip))
		return (0);
	s = splhi();
	/*
	 * do what ever machine specific things are necessary
	 * to set priority level (e.g. set picmasks)
	 */
	mutex_enter(&av_lock);
	(*addspl)(vect, lvl, vecp->avh_lo_pri, vecp->avh_hi_pri);
	mutex_exit(&av_lock);
	splx(s);
	return (1);

}

void
update_avsoftintr_args(void *intr_id, int lvl, caddr_t arg2)
{
	struct autovec *p;
	struct autovec *target = NULL;
	struct av_head *vectp = (struct av_head *)&softvect[lvl];

	for (p = vectp->avh_link; p && p->av_vector; p = p->av_link) {
		if (p->av_intr_id == intr_id) {
			target = p;
			break;
		}
	}

	if (target == NULL)
		return;
	target->av_intarg2 = arg2;
}

/*
 * Register a software interrupt handler
 */
int
add_avsoftintr(void *intr_id, int lvl, avfunc xxintr, char *name,
    caddr_t arg1, caddr_t arg2)
{
	int slvl;

	if ((slvl = slvltovect(lvl)) != -1)
		return (add_avintr(intr_id, lvl, xxintr,
		    name, slvl, arg1, arg2, NULL));

	if (intr_id == NULL) {
		printf("Attempt to add null intr_id for %s on level %d\n",
		    name, lvl);
		return (0);
	}

	if (xxintr == NULL) {
		printf("Attempt to add null handler for %s on level %d\n",
		    name, lvl);
		return (0);
	}

	if (lvl <= 0 || lvl > LOCK_LEVEL) {
		printf(badsoft, lvl, name);
		return (0);
	}
	if (!insert_av(intr_id, &softvect[lvl], xxintr, arg1, arg2,
	    lvl, NULL)) {
		return (0);
	}
	return (1);
}

/* insert an interrupt vector into chain */
static int
insert_av(void *intr_id, struct av_head *vectp, avfunc f, caddr_t arg1,
    caddr_t arg2, int pri_level, dev_info_t *dip)
{
	/*
	 * Protect rewrites of the list
	 */
	struct autovec *p, *mem;

	mem = kmem_zalloc(sizeof (struct autovec), KM_SLEEP);
	mem->av_vector = f;
	mem->av_intarg1 = arg1;
	mem->av_intarg2 = arg2;
	mem->av_intr_id = intr_id;
	mem->av_prilevel = pri_level;
	mem->av_dip = dip;
	mem->av_link = NULL;

	mutex_enter(&av_lock);

	if (vectp->avh_link == NULL) {	/* Nothing on list - put it at head */
		vectp->avh_link = mem;
		vectp->avh_hi_pri = vectp->avh_lo_pri = (ushort_t)pri_level;

		mutex_exit(&av_lock);
		return (1);
	}

	/* find where it goes in list */
	for (p = vectp->avh_link; p != NULL; p = p->av_link) {
		if (p->av_vector == NULL) {	/* freed struct available */
			kmem_free(mem, sizeof (struct autovec));
			p->av_intarg1 = arg1;
			p->av_intarg2 = arg2;
			p->av_intr_id = intr_id;
			p->av_prilevel = pri_level;
			if (pri_level > (int)vectp->avh_hi_pri) {
				vectp->avh_hi_pri = (ushort_t)pri_level;
			}
			if (pri_level < (int)vectp->avh_lo_pri) {
				vectp->avh_lo_pri = (ushort_t)pri_level;
			}
			p->av_vector = f;
			mutex_exit(&av_lock);
			return (1);
		}
	}
	/* insert new intpt at beginning of chain */
	mem->av_link = vectp->avh_link;
	vectp->avh_link = mem;
	if (pri_level > (int)vectp->avh_hi_pri) {
		vectp->avh_hi_pri = (ushort_t)pri_level;
	}
	if (pri_level < (int)vectp->avh_lo_pri) {
		vectp->avh_lo_pri = (ushort_t)pri_level;
	}
	mutex_exit(&av_lock);

	return (1);
}

/*
 * Remove a driver from the autovector list.
 */
int
rem_avsoftintr(void *intr_id, int lvl, avfunc xxintr)
{
	struct av_head *vecp = (struct av_head *)0;
	int slvl;

	if (xxintr == NULL)
		return (0);

	if ((slvl = slvltovect(lvl)) != -1) {
		rem_avintr(intr_id, lvl, xxintr, slvl);
		return (1);
	}

	if (lvl <= 0 && lvl >= LOCK_LEVEL) {
		return (0);
	}
	vecp = &softvect[lvl];
	remove_av(intr_id, vecp, xxintr, lvl, 0);

	return (1);
}

void
rem_avintr(void *intr_id, int lvl, avfunc xxintr, int vect)
{
	struct av_head *vecp = (struct av_head *)0;
	avfunc f;
	int s, vectindex;			/* save old spl value */

	if ((f = xxintr) == NULL)
		return;

	vectindex = vect % MAX_VECT;
	vecp = &autovect[vectindex];
	remove_av(intr_id, vecp, f, lvl, vect);
	s = splhi();
	mutex_enter(&av_lock);
	(*delspl)(vect, lvl, vecp->avh_lo_pri, vecp->avh_hi_pri);
	mutex_exit(&av_lock);
	splx(s);
}


/*
 * After having made a change to an autovector list, wait until we have
 * seen each cpu not executing an interrupt at that level--so we know our
 * change has taken effect completely (no old state in registers, etc).
 */
void
wait_till_seen(int ipl)
{
	int cpu_in_chain, cix;
	struct cpu *cpup;
	cpuset_t cpus_to_check;

	CPUSET_ALL(cpus_to_check);
	do {
		cpu_in_chain = 0;
		for (cix = 0; cix < NCPU; cix++) {
			cpup = cpu[cix];
			if (cpup != NULL && CPU_IN_SET(cpus_to_check, cix)) {
				if (intr_active(cpup, ipl)) {
					cpu_in_chain = 1;
				} else {
					CPUSET_DEL(cpus_to_check, cix);
				}
			}
		}
	} while (cpu_in_chain);
}

/* remove an interrupt vector from the chain */
static void
remove_av(void *intr_id, struct av_head *vectp, avfunc f, int pri_level,
	int vect)
{
	struct autovec *endp, *p, *target;
	int	lo_pri, hi_pri;
	int	ipl;
	/*
	 * Protect rewrites of the list
	 */
	target = NULL;

	mutex_enter(&av_lock);
	ipl = pri_level;
	lo_pri = MAXIPL;
	hi_pri = 0;
	for (endp = p = vectp->avh_link; p && p->av_vector; p = p->av_link) {
		endp = p;
		if ((p->av_vector == f) && (p->av_intr_id == intr_id)) {
			/* found the handler */
			target = p;
			continue;
		}
		if (p->av_prilevel > hi_pri)
			hi_pri = p->av_prilevel;
		if (p->av_prilevel < lo_pri)
			lo_pri = p->av_prilevel;
	}
	if (ipl < hi_pri)
		ipl = hi_pri;
	if (target == NULL) {	/* not found */
		printf("Couldn't remove function %p at %d, %d\n",
			(void *)f, vect, pri_level);
		mutex_exit(&av_lock);
		return;
	}

	target->av_vector = NULL;
	wait_till_seen(ipl);
	if (endp != target) {	/* vector to be removed is not last in chain */
		target->av_intarg1 = endp->av_intarg1;
		target->av_intarg2 = endp->av_intarg2;
		target->av_prilevel = endp->av_prilevel;
		target->av_intr_id = endp->av_intr_id;
		target->av_vector = endp->av_vector;
		/*
		 * We have a hole here where the routine corresponding to
		 * endp may not get called. Do a wait_till_seen to take care
		 * of this.
		 */
		wait_till_seen(ipl);
		endp->av_vector = NULL;
	}

	if (lo_pri > hi_pri) {	/* the chain is now empty */
		/* Leave the unused entries here for probable future use */
		vectp->avh_lo_pri = MAXIPL;
		vectp->avh_hi_pri = 0;
	} else {
		if ((int)vectp->avh_lo_pri < lo_pri)
			vectp->avh_lo_pri = (ushort_t)lo_pri;
		if ((int)vectp->avh_hi_pri > hi_pri)
			vectp->avh_hi_pri = (ushort_t)hi_pri;
	}
	mutex_exit(&av_lock);
	wait_till_seen(ipl);
}

/*
 * Trigger a soft interrupt.
 */
void
siron(void)
{
	softlevel1_hdl.ih_pending = 1;
	(*setsoftint)(1);
}

/*
 * Walk the autovector table for this vector, invoking each
 * interrupt handler as we go.
 */
void
av_dispatch_autovect(uint_t vec)
{
	struct autovec *av;

	ASSERT_STACK_ALIGNED();

	while ((av = autovect[vec].avh_link) != NULL) {
		uint_t numcalled = 0;
		uint_t claimed = 0;

		for (; av; av = av->av_link) {
			uint_t r;
			uint_t (*intr)() = av->av_vector;
			caddr_t arg1 = av->av_intarg1;
			caddr_t arg2 = av->av_intarg2;
			dev_info_t *dip = av->av_dip;

			numcalled++;
			if (intr == NULL)
				break;

			DTRACE_PROBE4(interrupt__start, dev_info_t *, dip,
			    void *, intr, caddr_t, arg1, caddr_t, arg2);
			r = (*intr)(arg1, arg2);
			DTRACE_PROBE4(interrupt__complete, dev_info_t *, dip,
			    void *, intr, caddr_t, arg1, uint_t, r);
			claimed |= r;
		}

		/*
		 * If there's only one interrupt handler in the chain,
		 * or if no-one claimed the interrupt at all give up now.
		 */
		if (numcalled == 1 || claimed == 0)
			break;
	}
}

/*
 * Call every soft interrupt handler we can find at this level once.
 */
void
av_dispatch_softvect(uint_t pil)
{
	struct autovec *av;
	ddi_softint_hdl_impl_t	*hdlp;
	uint_t (*intr)();
	caddr_t arg1;
	caddr_t arg2;

	ASSERT_STACK_ALIGNED();
	ASSERT(pil >= 0 && pil <= PIL_MAX);

	for (av = softvect[pil].avh_link; av; av = av->av_link) {
		if ((intr = av->av_vector) == NULL)
			break;
		arg1 = av->av_intarg1;
		arg2 = av->av_intarg2;

		hdlp = (ddi_softint_hdl_impl_t *)av->av_intr_id;
		ASSERT(hdlp);

		if (hdlp->ih_pending) {
			hdlp->ih_pending = 0;
			(void) (*intr)(arg1, arg2);
		}
	}
}

struct regs;

/*
 * Call every NMI handler we know of once.
 */
void
av_dispatch_nmivect(struct regs *rp)
{
	struct autovec *av;

	ASSERT_STACK_ALIGNED();

	for (av = nmivect; av; av = av->av_link)
		(void) (av->av_vector)(av->av_intarg1, rp);
}
