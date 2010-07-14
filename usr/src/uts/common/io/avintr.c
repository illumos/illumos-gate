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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#ifdef __xpv
#include <sys/evtchn_impl.h>
#endif

typedef struct av_softinfo {
	cpuset_t	av_pending;	/* pending bitmasks */
} av_softinfo_t;

static void insert_av(void *intr_id, struct av_head *vectp, avfunc f,
	caddr_t arg1, caddr_t arg2, uint64_t *ticksp, int pri_level,
	dev_info_t *dip);
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

#ifdef __xpv
#define	MAX_VECT	NR_IRQS
#else
#define	MAX_VECT	256
#endif

struct autovec *nmivect = NULL;
struct av_head autovect[MAX_VECT];
struct av_head softvect[LOCK_LEVEL + 1];
kmutex_t av_lock;
/*
 * These are software interrupt handlers dedicated to ddi timer.
 * The interrupt levels up to 10 are supported, but high interrupts
 * must not be used there.
 */
ddi_softint_hdl_impl_t softlevel_hdl[DDI_IPL_10] = {
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 1 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 2 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 3 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 4 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 5 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 6 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 7 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 8 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 9 */
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL}, /* level 10 */
};
ddi_softint_hdl_impl_t softlevel1_hdl =
	{0, NULL, NULL, NULL, 0, NULL, NULL, NULL};

/*
 * clear/check softint pending flag corresponding for
 * the current CPU
 */
void
av_clear_softint_pending(av_softinfo_t *infop)
{
	CPUSET_ATOMIC_DEL(infop->av_pending, CPU->cpu_seqid);
}

boolean_t
av_check_softint_pending(av_softinfo_t *infop, boolean_t check_all)
{
	if (check_all)
		return (!CPUSET_ISNULL(infop->av_pending));
	else
		return (CPU_IN_SET(infop->av_pending, CPU->cpu_seqid) != 0);
}

/*
 * This is the wrapper function which is generally used to set a softint
 * pending
 */
void
av_set_softint_pending(int pri, av_softinfo_t *infop)
{
	kdi_av_set_softint_pending(pri, infop);
}

/*
 * This is kmdb's private entry point to setsoftint called from kdi_siron
 * It first sets our av softint pending bit for the current CPU,
 * then it sets the CPU softint pending bit for pri.
 */
void
kdi_av_set_softint_pending(int pri, av_softinfo_t *infop)
{
	CPUSET_ATOMIC_ADD(infop->av_pending, CPU->cpu_seqid);

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
	mem->av_dip = NULL;
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
 *
 * The autovect data structure only supports globally 256 interrupts.
 * In order to support 256 * #LocalAPIC interrupts, a new PSM module
 * apix is introduced. It defines PSM private data structures for the
 * interrupt handlers. The PSM module initializes addintr to a PSM
 * private function so that it could override add_avintr() to operate
 * on its private data structures.
 */
int
add_avintr(void *intr_id, int lvl, avfunc xxintr, char *name, int vect,
    caddr_t arg1, caddr_t arg2, uint64_t *ticksp, dev_info_t *dip)
{
	struct av_head *vecp = (struct av_head *)0;
	avfunc f;
	int s, vectindex;			/* save old spl value */
	ushort_t hi_pri;

	if (addintr) {
		return ((*addintr)(intr_id, lvl, xxintr, name, vect,
		    arg1, arg2, ticksp, dip));
	}

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

	insert_av(intr_id, vecp, f, arg1, arg2, ticksp, lvl, dip);
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
	ddi_softint_hdl_impl_t	*hdlp = (ddi_softint_hdl_impl_t *)intr_id;

	if ((slvl = slvltovect(lvl)) != -1)
		return (add_avintr(intr_id, lvl, xxintr,
		    name, slvl, arg1, arg2, NULL, NULL));

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

	if (hdlp->ih_pending == NULL) {
		hdlp->ih_pending =
		    kmem_zalloc(sizeof (av_softinfo_t), KM_SLEEP);
	}

	insert_av(intr_id, &softvect[lvl], xxintr, arg1, arg2, NULL, lvl, NULL);

	return (1);
}

/*
 * insert an interrupt vector into chain by its priority from high
 * to low
 */
static void
insert_av(void *intr_id, struct av_head *vectp, avfunc f, caddr_t arg1,
    caddr_t arg2, uint64_t *ticksp, int pri_level, dev_info_t *dip)
{
	/*
	 * Protect rewrites of the list
	 */
	struct autovec *p, *prep, *mem;

	mem = kmem_zalloc(sizeof (struct autovec), KM_SLEEP);
	mem->av_vector = f;
	mem->av_intarg1 = arg1;
	mem->av_intarg2 = arg2;
	mem->av_ticksp = ticksp;
	mem->av_intr_id = intr_id;
	mem->av_prilevel = pri_level;
	mem->av_dip = dip;
	mem->av_link = NULL;

	mutex_enter(&av_lock);

	if (vectp->avh_link == NULL) {	/* Nothing on list - put it at head */
		vectp->avh_link = mem;
		vectp->avh_hi_pri = vectp->avh_lo_pri = (ushort_t)pri_level;

		mutex_exit(&av_lock);
		return;
	}

	/* find where it goes in list */
	prep = NULL;
	for (p = vectp->avh_link; p != NULL; p = p->av_link) {
		if (p->av_vector && p->av_prilevel <= pri_level)
			break;
		prep = p;
	}
	if (prep != NULL) {
		if (prep->av_vector == NULL) {	/* freed struct available */
			p = prep;
			p->av_intarg1 = arg1;
			p->av_intarg2 = arg2;
			p->av_ticksp = ticksp;
			p->av_intr_id = intr_id;
			p->av_prilevel = pri_level;
			p->av_dip = dip;
			if (pri_level > (int)vectp->avh_hi_pri) {
				vectp->avh_hi_pri = (ushort_t)pri_level;
			}
			if (pri_level < (int)vectp->avh_lo_pri) {
				vectp->avh_lo_pri = (ushort_t)pri_level;
			}
			/*
			 * To prevent calling service routine before args
			 * and ticksp are ready fill in vector last.
			 */
			p->av_vector = f;
			mutex_exit(&av_lock);
			kmem_free(mem, sizeof (struct autovec));
			return;
		}

		mem->av_link = prep->av_link;
		prep->av_link = mem;
	} else {
		/* insert new intpt at beginning of chain */
		mem->av_link = vectp->avh_link;
		vectp->avh_link = mem;
	}
	if (pri_level > (int)vectp->avh_hi_pri) {
		vectp->avh_hi_pri = (ushort_t)pri_level;
	}
	if (pri_level < (int)vectp->avh_lo_pri) {
		vectp->avh_lo_pri = (ushort_t)pri_level;
	}
	mutex_exit(&av_lock);
}

static int
av_rem_softintr(void *intr_id, int lvl, avfunc xxintr, boolean_t rem_softinfo)
{
	struct av_head *vecp = (struct av_head *)0;
	int slvl;
	ddi_softint_hdl_impl_t	*hdlp = (ddi_softint_hdl_impl_t *)intr_id;
	av_softinfo_t *infop = (av_softinfo_t *)hdlp->ih_pending;

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

	if (rem_softinfo) {
		kmem_free(infop, sizeof (av_softinfo_t));
		hdlp->ih_pending = NULL;
	}

	return (1);
}

int
av_softint_movepri(void *intr_id, int old_lvl)
{
	int ret;
	ddi_softint_hdl_impl_t	*hdlp = (ddi_softint_hdl_impl_t *)intr_id;

	ret = add_avsoftintr(intr_id, hdlp->ih_pri, hdlp->ih_cb_func,
	    DEVI(hdlp->ih_dip)->devi_name, hdlp->ih_cb_arg1, hdlp->ih_cb_arg2);

	if (ret) {
		(void) av_rem_softintr(intr_id, old_lvl, hdlp->ih_cb_func,
		    B_FALSE);
	}

	return (ret);
}

/*
 * Remove a driver from the autovector list.
 */
int
rem_avsoftintr(void *intr_id, int lvl, avfunc xxintr)
{
	return (av_rem_softintr(intr_id, lvl, xxintr, B_TRUE));
}

/*
 * Remove specified interrupt handler.
 *
 * PSM module could initialize remintr to some PSM private function
 * so that it could override rem_avintr() to operate on its private
 * data structures.
 */
void
rem_avintr(void *intr_id, int lvl, avfunc xxintr, int vect)
{
	struct av_head *vecp = (struct av_head *)0;
	avfunc f;
	int s, vectindex;			/* save old spl value */

	if (remintr) {
		(*remintr)(intr_id, lvl, xxintr, vect);
		return;
	}

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
				if (INTR_ACTIVE(cpup, ipl)) {
					cpu_in_chain = 1;
				} else {
					CPUSET_DEL(cpus_to_check, cix);
				}
			}
		}
	} while (cpu_in_chain);
}

static uint64_t dummy_tick;

/* remove an interrupt vector from the chain */
static void
remove_av(void *intr_id, struct av_head *vectp, avfunc f, int pri_level,
	int vect)
{
	struct autovec *p, *target;
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
	for (p = vectp->avh_link; p; p = p->av_link) {
		if ((p->av_vector == f) && (p->av_intr_id == intr_id)) {
			/* found the handler */
			target = p;
			continue;
		}
		if (p->av_vector != NULL) {
			if (p->av_prilevel > hi_pri)
				hi_pri = p->av_prilevel;
			if (p->av_prilevel < lo_pri)
				lo_pri = p->av_prilevel;
		}
	}
	if (ipl < hi_pri)
		ipl = hi_pri;
	if (target == NULL) {	/* not found */
		printf("Couldn't remove function %p at %d, %d\n",
		    (void *)f, vect, pri_level);
		mutex_exit(&av_lock);
		return;
	}

	/*
	 * This drops the handler from the chain, it can no longer be called.
	 * However, there is no guarantee that the handler is not currently
	 * still executing.
	 */
	target->av_vector = NULL;
	/*
	 * There is a race where we could be just about to pick up the ticksp
	 * pointer to increment it after returning from the service routine
	 * in av_dispatch_autovect.  Rather than NULL it out let's just point
	 * it off to something safe so that any final tick update attempt
	 * won't fault.
	 */
	target->av_ticksp = &dummy_tick;
	wait_till_seen(ipl);

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
 * kmdb uses siron (and thus setsoftint) while the world is stopped in order to
 * inform its driver component that there's work to be done.  We need to keep
 * DTrace from instrumenting kmdb's siron and setsoftint.  We duplicate siron,
 * giving kmdb's version a kdi prefix to keep DTrace at bay.   We also
 * provide a version of the various setsoftint functions available for kmdb to
 * use using a kdi_ prefix while the main *setsoftint() functionality is
 * implemented as a wrapper.  This allows tracing, while still providing a
 * way for kmdb to sneak in unmolested.
 */
void
kdi_siron(void)
{
	(*kdisetsoftint)(1, softlevel1_hdl.ih_pending);
}

/*
 * Trigger a soft interrupt.
 */
void
siron(void)
{
	/* Level 1 software interrupt */
	(*setsoftint)(1, softlevel1_hdl.ih_pending);
}

/*
 * Trigger software interrupts dedicated to ddi timer.
 */
void
sir_on(int level)
{
	ASSERT(level >= DDI_IPL_1 && level <= DDI_IPL_10);
	(*setsoftint)(level, softlevel_hdl[level-1].ih_pending);
}

/*
 * The handler which is executed on the target CPU.
 */
/*ARGSUSED*/
static int
siron_poke_intr(xc_arg_t a1, xc_arg_t a2, xc_arg_t a3)
{
	siron();
	return (0);
}

/*
 * May get called from softcall to poke CPUs.
 */
void
siron_poke_cpu(cpuset_t poke)
{
	int cpuid = CPU->cpu_id;

	/*
	 * If we are poking to ourself then we can simply
	 * generate level1 using siron()
	 */
	if (CPU_IN_SET(poke, cpuid)) {
		siron();
		CPUSET_DEL(poke, cpuid);
		if (CPUSET_ISNULL(poke))
			return;
	}

	xc_call(0, 0, 0, CPUSET2BV(poke), (xc_func_t)siron_poke_intr);
}

/*
 * Walk the autovector table for this vector, invoking each
 * interrupt handler as we go.
 */

extern uint64_t intr_get_time(void);

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

			/*
			 * We must walk the entire chain.  Removed handlers
			 * may be anywhere in the chain.
			 */
			if (intr == NULL)
				continue;

			DTRACE_PROBE4(interrupt__start, dev_info_t *, dip,
			    void *, intr, caddr_t, arg1, caddr_t, arg2);
			r = (*intr)(arg1, arg2);
			DTRACE_PROBE4(interrupt__complete, dev_info_t *, dip,
			    void *, intr, caddr_t, arg1, uint_t, r);
			numcalled++;
			claimed |= r;
			if (av->av_ticksp && av->av_prilevel <= LOCK_LEVEL)
				atomic_add_64(av->av_ticksp, intr_get_time());
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
		/*
		 * We must walk the entire chain.  Removed handlers
		 * may be anywhere in the chain.
		 */
		if ((intr = av->av_vector) == NULL)
			continue;
		arg1 = av->av_intarg1;
		arg2 = av->av_intarg2;

		hdlp = (ddi_softint_hdl_impl_t *)av->av_intr_id;
		ASSERT(hdlp);

		/*
		 * Each cpu has its own pending bit in hdlp->ih_pending,
		 * here av_check/clear_softint_pending is just checking
		 * and clearing the pending bit for the current cpu, who
		 * has just triggered a softint.
		 */
		if (av_check_softint_pending(hdlp->ih_pending, B_FALSE)) {
			av_clear_softint_pending(hdlp->ih_pending);
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
