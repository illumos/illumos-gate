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
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <sys/sysmacros.h>
#include <sys/stack.h>
#include <sys/cpuvar.h>
#include <sys/ivintr.h>
#include <sys/intreg.h>
#include <sys/membar.h>
#include <sys/kmem.h>
#include <sys/intr.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/cmn_err.h>
#include <sys/privregs.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <vm/seg_kp.h>
#include <sys/debug.h>
#include <sys/cyclic.h>
#include <sys/kdi_impl.h>
#include <sys/ddi_periodic.h>

#include <sys/cpu_sgnblk_defs.h>

/* Global locks which protect the interrupt distribution lists */
static kmutex_t intr_dist_lock;
static kmutex_t intr_dist_cpu_lock;

/* Head of the interrupt distribution lists */
static struct intr_dist *intr_dist_head = NULL;
static struct intr_dist *intr_dist_whead = NULL;

static uint64_t siron_inum[DDI_IPL_10]; /* software interrupt numbers */
uint64_t *siron_cpu_inum = NULL;
uint64_t siron_poke_cpu_inum;
static int siron_cpu_setup(cpu_setup_t, int, void *);
extern uint_t softlevel1();

static uint64_t siron1_inum; /* backward compatibility */
uint64_t poke_cpu_inum;
uint_t poke_cpu_intr(caddr_t arg1, caddr_t arg2);
uint_t siron_poke_cpu_intr(caddr_t arg1, caddr_t arg2);

/*
 * Variable to enable/disable printing a message when an invalid vecintr
 * is received.
 */
uint_t ignore_invalid_vecintr = 0;

/*
 * Note:-
 * siron_pending was originally created to prevent a resource over consumption
 * bug in setsoftint(exhaustion of interrupt pool free list).
 * It's original intention is obsolete with the use of iv_pending in
 * setsoftint. However, siron_pending stayed around, acting as a second
 * gatekeeper preventing soft interrupts from being queued. In this capacity,
 * it can lead to hangs on MP systems, where due to global visibility issues
 * it can end up set while iv_pending is reset, preventing soft interrupts from
 * ever being processed. In addition to its gatekeeper role, init_intr also
 * uses it to flag the situation where siron() was called before siron_inum has
 * been defined.
 *
 * siron() does not need an extra gatekeeper; any cpu that wishes should be
 * allowed to queue a soft interrupt. It is softint()'s job to ensure
 * correct handling of the queues. Therefore, siron_pending has been
 * stripped of its gatekeeper task, retaining only its intr_init job, where
 * it indicates that there is a pending need to call siron().
 */
static int siron_pending[DDI_IPL_10]; /* software interrupt pending flags */
static int siron1_pending; /* backward compatibility */

int intr_policy = INTR_WEIGHTED_DIST;	/* interrupt distribution policy */
int intr_dist_debug = 0;
int32_t intr_dist_weight_max = 1;
int32_t intr_dist_weight_maxmax = 1000;
int intr_dist_weight_maxfactor = 2;
#define	INTR_DEBUG(args) if (intr_dist_debug) cmn_err args

/*
 * intr_init() - Interrupt initialization
 *	Initialize the system's interrupt vector table.
 */
void
intr_init(cpu_t *cp)
{
	int i;
	extern uint_t softlevel1();

	init_ivintr();
	REGISTER_BBUS_INTR();

	/*
	 * Register these software interrupts for ddi timer.
	 * Software interrupts up to the level 10 are supported.
	 */
	for (i = DDI_IPL_1; i <= DDI_IPL_10; i++) {
		siron_inum[i - 1] = add_softintr(i,
		    (softintrfunc)ddi_periodic_softintr,
		    (caddr_t)(uintptr_t)(i), SOFTINT_ST);
	}

	siron1_inum = add_softintr(PIL_1, softlevel1, 0, SOFTINT_ST);
	poke_cpu_inum = add_softintr(PIL_13, poke_cpu_intr, 0, SOFTINT_MT);
	siron_poke_cpu_inum = add_softintr(PIL_13,
	    siron_poke_cpu_intr, 0, SOFTINT_MT);
	cp->cpu_m.poke_cpu_outstanding = B_FALSE;

	mutex_init(&intr_dist_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&intr_dist_cpu_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * A soft interrupt may have been requested prior to the initialization
	 * of soft interrupts.  Soft interrupts can't be dispatched until after
	 * init_intr(), so we have to wait until now before we can dispatch the
	 * pending soft interrupt (if any).
	 */
	for (i = DDI_IPL_1; i <= DDI_IPL_10; i++) {
		if (siron_pending[i-1]) {
			siron_pending[i-1] = 0;
			sir_on(i);
		}
	}
	if (siron1_pending) {
		siron1_pending = 0;
		siron();
	}
}

/*
 * poke_cpu_intr - fall through when poke_cpu calls
 */
/* ARGSUSED */
uint_t
poke_cpu_intr(caddr_t arg1, caddr_t arg2)
{
	CPU->cpu_m.poke_cpu_outstanding = B_FALSE;
	membar_stld_stst();
	return (1);
}

/*
 * Trigger software interrupts dedicated to ddi timer.
 */
void
sir_on(int level)
{
	ASSERT(level >= DDI_IPL_1 && level <= DDI_IPL_10);
	if (siron_inum[level-1])
		setsoftint(siron_inum[level-1]);
	else
		siron_pending[level-1] = 1;
}

/*
 * kmdb uses siron (and thus setsoftint) while the world is stopped in order to
 * inform its driver component that there's work to be done.  We need to keep
 * DTrace from instrumenting kmdb's siron and setsoftint.  We duplicate siron,
 * giving kmdb's version a kdi_ prefix to keep DTrace at bay.  The
 * implementation of setsoftint is complicated enough that we don't want to
 * duplicate it, but at the same time we don't want to preclude tracing either.
 * The meat of setsoftint() therefore goes into kdi_setsoftint, with
 * setsoftint() implemented as a wrapper.  This allows tracing, while still
 * providing a way for kmdb to sneak in unmolested.
 */
void
kdi_siron(void)
{
	if (siron1_inum != 0)
		kdi_setsoftint(siron1_inum);
	else
		siron1_pending = 1;
}

void
setsoftint(uint64_t inum)
{
	kdi_setsoftint(inum);
}

/*
 * Generates softlevel1 interrupt on current CPU if it
 * is not pending already.
 */
void
siron(void)
{
	uint64_t inum;

	if (siron1_inum != 0) {
		/*
		 * Once siron_cpu_inum has been allocated, we can
		 * use per-CPU siron inum.
		 */
		if (siron_cpu_inum && siron_cpu_inum[CPU->cpu_id] != 0)
			inum = siron_cpu_inum[CPU->cpu_id];
		else
			inum = siron1_inum;

		setsoftint(inum);
	} else
		siron1_pending = 1;
}


static void
siron_init(void)
{
	/*
	 * We just allocate memory for per-cpu siron right now. Rest of
	 * the work is done when CPU is configured.
	 */
	siron_cpu_inum = kmem_zalloc(sizeof (uint64_t) * NCPU, KM_SLEEP);
}

/*
 * This routine creates per-CPU siron inum for CPUs which are
 * configured during boot.
 */
void
siron_mp_init()
{
	cpu_t *c;

	/*
	 * Get the memory for per-CPU siron inums
	 */
	siron_init();

	mutex_enter(&cpu_lock);
	c = cpu_list;
	do {
		(void) siron_cpu_setup(CPU_CONFIG, c->cpu_id, NULL);
	} while ((c = c->cpu_next) != cpu_list);

	register_cpu_setup_func(siron_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
}

/*
 * siron_poke_cpu_intr - cross-call handler.
 */
/* ARGSUSED */
uint_t
siron_poke_cpu_intr(caddr_t arg1, caddr_t arg2)
{
	/* generate level1 softint */
	siron();
	return (1);
}

/*
 * This routine generates a cross-call on target CPU(s).
 */
void
siron_poke_cpu(cpuset_t poke)
{
	int cpuid = CPU->cpu_id;

	if (CPU_IN_SET(poke, cpuid)) {
		siron();
		CPUSET_DEL(poke, cpuid);
		if (CPUSET_ISNULL(poke))
			return;
	}

	xt_some(poke, setsoftint_tl1, siron_poke_cpu_inum, 0);
}

/*
 * This callback function allows us to create per-CPU siron inum.
 */
/* ARGSUSED */
static int
siron_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	cpu_t *cp = cpu[id];

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cp != NULL);

	switch (what) {
	case CPU_CONFIG:
		siron_cpu_inum[cp->cpu_id] = add_softintr(PIL_1,
		    (softintrfunc)softlevel1, 0, SOFTINT_ST);
		break;
	case CPU_UNCONFIG:
		(void) rem_softintr(siron_cpu_inum[cp->cpu_id]);
		siron_cpu_inum[cp->cpu_id] = 0;
		break;
	default:
		break;
	}

	return (0);
}

/*
 * no_ivintr()
 * 	called by setvecint_tl1() through sys_trap()
 *	vector interrupt received but not valid or not
 *	registered in intr_vec_table
 *	considered as a spurious mondo interrupt
 */
/* ARGSUSED */
void
no_ivintr(struct regs *rp, int inum, int pil)
{
	if (!ignore_invalid_vecintr)
		cmn_err(CE_WARN, "invalid vector intr: number 0x%x, pil 0x%x",
		    inum, pil);

#ifdef DEBUG_VEC_INTR
	prom_enter_mon();
#endif /* DEBUG_VEC_INTR */
}

void
intr_dequeue_req(uint_t pil, uint64_t inum)
{
	intr_vec_t	*iv, *next, *prev;
	struct machcpu	*mcpu;
	uint32_t	clr;
	processorid_t	cpu_id;
	extern uint_t	getpstate(void);

	ASSERT((getpstate() & PSTATE_IE) == 0);

	mcpu = &CPU->cpu_m;
	cpu_id = CPU->cpu_id;

	iv = (intr_vec_t *)inum;
	prev = NULL;
	next = mcpu->intr_head[pil];

	/* Find a matching entry in the list */
	while (next != NULL) {
		if (next == iv)
			break;
		prev = next;
		next = IV_GET_PIL_NEXT(next, cpu_id);
	}

	if (next != NULL) {
		intr_vec_t	*next_iv = IV_GET_PIL_NEXT(next, cpu_id);

		/* Remove entry from list */
		if (prev != NULL)
			IV_SET_PIL_NEXT(prev, cpu_id, next_iv); /* non-head */
		else
			mcpu->intr_head[pil] = next_iv; /* head */

		if (next_iv == NULL)
			mcpu->intr_tail[pil] = prev; /* tail */
	}

	/* Clear pending interrupts at this level if the list is empty */
	if (mcpu->intr_head[pil] == NULL) {
		clr = 1 << pil;
		if (pil == PIL_14)
			clr |= (TICK_INT_MASK | STICK_INT_MASK);
		wr_clr_softint(clr);
	}
}


/*
 * Send a directed interrupt of specified interrupt number id to a cpu.
 */
void
send_dirint(
	int cpuix,		/* cpu to be interrupted */
	int intr_id)		/* interrupt number id */
{
	xt_one(cpuix, setsoftint_tl1, intr_id, 0);
}

/*
 * Take the specified CPU out of participation in interrupts.
 *	Called by p_online(2) when a processor is being taken off-line.
 *	This allows interrupt threads being handled on the processor to
 *	complete before the processor is idled.
 */
int
cpu_disable_intr(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Turn off the CPU_ENABLE flag before calling the redistribution
	 * function, since it checks for this in the cpu flags.
	 */
	cp->cpu_flags &= ~CPU_ENABLE;

	intr_redist_all_cpus();

	return (0);
}

/*
 * Allow the specified CPU to participate in interrupts.
 *	Called by p_online(2) if a processor could not be taken off-line
 *	because of bound threads, in order to resume processing interrupts.
 *	Also called after starting a processor.
 */
void
cpu_enable_intr(struct cpu *cp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	cp->cpu_flags |= CPU_ENABLE;

	intr_redist_all_cpus();
}

/*
 * Add function to callback list for intr_redist_all_cpus.  We keep two lists,
 * one for weighted callbacks and one for normal callbacks. Weighted callbacks
 * are issued to redirect interrupts of a specified weight, from heavy to
 * light.  This allows all the interrupts of a given weight to be redistributed
 * for all weighted nexus drivers prior to those of less weight.
 */
static void
intr_dist_add_list(struct intr_dist **phead, void (*func)(void *), void *arg)
{
	struct intr_dist *new = kmem_alloc(sizeof (*new), KM_SLEEP);
	struct intr_dist *iptr;
	struct intr_dist **pptr;

	ASSERT(func);
	new->func = func;
	new->arg = arg;
	new->next = NULL;

	/* Add to tail so that redistribution occurs in original order. */
	mutex_enter(&intr_dist_lock);
	for (iptr = *phead, pptr = phead; iptr != NULL;
	    pptr = &iptr->next, iptr = iptr->next) {
		/* check for problems as we locate the tail */
		if ((iptr->func == func) && (iptr->arg == arg)) {
			cmn_err(CE_PANIC, "intr_dist_add_list(): duplicate");
			/*NOTREACHED*/
		}
	}
	*pptr = new;

	mutex_exit(&intr_dist_lock);
}

void
intr_dist_add(void (*func)(void *), void *arg)
{
	intr_dist_add_list(&intr_dist_head, (void (*)(void *))func, arg);
}

void
intr_dist_add_weighted(void (*func)(void *, int32_t, int32_t), void *arg)
{
	intr_dist_add_list(&intr_dist_whead, (void (*)(void *))func, arg);
}

/*
 * Search for the interrupt distribution structure with the specified
 * mondo vec reg in the interrupt distribution list. If a match is found,
 * then delete the entry from the list. The caller is responsible for
 * modifying the mondo vector registers.
 */
static void
intr_dist_rem_list(struct intr_dist **headp, void (*func)(void *), void *arg)
{
	struct intr_dist *iptr;
	struct intr_dist **vect;

	mutex_enter(&intr_dist_lock);
	for (iptr = *headp, vect = headp;
	    iptr != NULL; vect = &iptr->next, iptr = iptr->next) {
		if ((iptr->func == func) && (iptr->arg == arg)) {
			*vect = iptr->next;
			kmem_free(iptr, sizeof (struct intr_dist));
			mutex_exit(&intr_dist_lock);
			return;
		}
	}

	if (!panicstr)
		cmn_err(CE_PANIC, "intr_dist_rem_list: not found");
	mutex_exit(&intr_dist_lock);
}

void
intr_dist_rem(void (*func)(void *), void *arg)
{
	intr_dist_rem_list(&intr_dist_head, (void (*)(void *))func, arg);
}

void
intr_dist_rem_weighted(void (*func)(void *, int32_t, int32_t), void *arg)
{
	intr_dist_rem_list(&intr_dist_whead, (void (*)(void *))func, arg);
}

/*
 * Initiate interrupt redistribution.  Redistribution improves the isolation
 * associated with interrupt weights by ordering operations from heavy weight
 * to light weight.  When a CPUs orientation changes relative to interrupts,
 * there is *always* a redistribution to accommodate this change (call to
 * intr_redist_all_cpus()).  As devices (not CPUs) attach/detach it is possible
 * that a redistribution could improve the quality of an initialization. For
 * example, if you are not using a NIC it may not be attached with s10 (devfs).
 * If you then configure the NIC (ifconfig), this may cause the NIC to attach
 * and plumb interrupts.  The CPU assignment for the NIC's interrupts is
 * occurring late, so optimal "isolation" relative to weight is not occurring.
 * The same applies to detach, although in this case doing the redistribution
 * might improve "spread" for medium weight devices since the "isolation" of
 * a higher weight device may no longer be present.
 *
 * NB: We should provide a utility to trigger redistribution (ala "intradm -r").
 *
 * NB: There is risk associated with automatically triggering execution of the
 * redistribution code at arbitrary times. The risk comes from the fact that
 * there is a lot of low-level hardware interaction associated with a
 * redistribution.  At some point we may want this code to perform automatic
 * redistribution (redistribution thread; trigger timeout when add/remove
 * weight delta is large enough, and call cv_signal from timeout - causing
 * thead to call i_ddi_intr_redist_all_cpus()) but this is considered too
 * risky at this time.
 */
void
i_ddi_intr_redist_all_cpus()
{
	mutex_enter(&cpu_lock);
	INTR_DEBUG((CE_CONT, "intr_dist: i_ddi_intr_redist_all_cpus\n"));
	intr_redist_all_cpus();
	mutex_exit(&cpu_lock);
}

/*
 * Redistribute all interrupts
 *
 * This function redistributes all interrupting devices, running the
 * parent callback functions for each node.
 */
void
intr_redist_all_cpus(void)
{
	struct cpu *cp;
	struct intr_dist *iptr;
	int32_t weight, max_weight;

	ASSERT(MUTEX_HELD(&cpu_lock));
	mutex_enter(&intr_dist_lock);

	/*
	 * zero cpu_intr_weight on all cpus - it is safe to traverse
	 * cpu_list since we hold cpu_lock.
	 */
	cp = cpu_list;
	do {
		cp->cpu_intr_weight = 0;
	} while ((cp = cp->cpu_next) != cpu_list);

	/*
	 * Assume that this redistribution may encounter a device weight
	 * via driver.conf tuning of "ddi-intr-weight" that is at most
	 * intr_dist_weight_maxfactor times larger.
	 */
	max_weight = intr_dist_weight_max * intr_dist_weight_maxfactor;
	if (max_weight > intr_dist_weight_maxmax)
		max_weight = intr_dist_weight_maxmax;
	intr_dist_weight_max = 1;

	INTR_DEBUG((CE_CONT, "intr_dist: "
	    "intr_redist_all_cpus: %d-0\n", max_weight));

	/*
	 * Redistribute weighted, from heavy to light.  The callback that
	 * specifies a weight equal to weight_max should redirect all
	 * interrupts of weight weight_max or greater [weight_max, inf.).
	 * Interrupts of lesser weight should be processed on the call with
	 * the matching weight. This allows all the heaver weight interrupts
	 * on all weighted busses (multiple pci busses) to be redirected prior
	 * to any lesser weight interrupts.
	 */
	for (weight = max_weight; weight >= 0; weight--)
		for (iptr = intr_dist_whead; iptr != NULL; iptr = iptr->next)
			((void (*)(void *, int32_t, int32_t))iptr->func)
			    (iptr->arg, max_weight, weight);

	/* redistribute normal (non-weighted) interrupts */
	for (iptr = intr_dist_head; iptr != NULL; iptr = iptr->next)
		((void (*)(void *))iptr->func)(iptr->arg);
	mutex_exit(&intr_dist_lock);
}

void
intr_redist_all_cpus_shutdown(void)
{
	intr_policy = INTR_CURRENT_CPU;
	intr_redist_all_cpus();
}

/*
 * Determine what CPU to target, based on interrupt policy.
 *
 * INTR_FLAT_DIST: hold a current CPU pointer in a static variable and
 *	advance through interrupt enabled cpus (round-robin).
 *
 * INTR_WEIGHTED_DIST: search for an enabled CPU with the lowest
 *	cpu_intr_weight, round robin when all equal.
 *
 *	Weighted interrupt distribution provides two things: "spread" of weight
 *	(associated with algorithm itself) and "isolation" (associated with a
 *	particular device weight). A redistribution is what provides optimal
 *	"isolation" of heavy weight interrupts, optimal "spread" of weight
 *	(relative to what came before) is always occurring.
 *
 *	An interrupt weight is a subjective number that represents the
 *	percentage of a CPU required to service a device's interrupts: the
 *	default weight is 0% (however the algorithm still maintains
 *	round-robin), a network interface controller (NIC) may have a large
 *	weight (35%). Interrupt weight only has meaning relative to the
 *	interrupt weight of other devices: a CPU can be weighted more than
 *	100%, and a single device might consume more than 100% of a CPU.
 *
 *	A coarse interrupt weight can be defined by the parent nexus driver
 *	based on bus specific information, like pci class codes. A nexus
 *	driver that supports device interrupt weighting for its children
 *	should call intr_dist_cpuid_add/rem_device_weight(), which adds
 *	and removes the weight of a device from the CPU that an interrupt
 *	is directed at.  The quality of initialization improves when the
 *	device interrupt weights more accuracy reflect actual run-time weights,
 *	and as the assignments are ordered from is heavy to light.
 *
 *	The implementation also supports interrupt weight being specified in
 *	driver.conf files via the property "ddi-intr-weight", which takes
 *	precedence over the nexus supplied weight.  This support is added to
 *	permit possible tweaking in the product in response to customer
 *	problems. This is not a formal or committed interface.
 *
 *	While a weighted approach chooses the CPU providing the best spread
 *	given past weights, less than optimal isolation can result in cases
 *	where heavy weight devices show up last. The nexus driver's interrupt
 *	redistribution logic should use intr_dist_add/rem_weighted so that
 *	interrupts can be redistributed heavy first for optimal isolation.
 */
uint32_t
intr_dist_cpuid(void)
{
	static struct cpu	*curr_cpu;
	struct cpu		*start_cpu;
	struct cpu		*new_cpu;
	struct cpu		*cp;
	int			cpuid = -1;

	/* Establish exclusion for curr_cpu and cpu_intr_weight manipulation */
	mutex_enter(&intr_dist_cpu_lock);

	switch (intr_policy) {
	case INTR_CURRENT_CPU:
		cpuid = CPU->cpu_id;
		break;

	case INTR_BOOT_CPU:
		panic("INTR_BOOT_CPU no longer supported.");
		/*NOTREACHED*/

	case INTR_FLAT_DIST:
	case INTR_WEIGHTED_DIST:
	default:
		/*
		 * Ensure that curr_cpu is valid - cpu_next will be NULL if
		 * the cpu has been deleted (cpu structs are never freed).
		 */
		if (curr_cpu == NULL || curr_cpu->cpu_next == NULL)
			curr_cpu = CPU;

		/*
		 * Advance to online CPU after curr_cpu (round-robin). For
		 * INTR_WEIGHTED_DIST we choose the cpu with the lightest
		 * weight.  For a nexus that does not support weight the
		 * default weight of zero is used. We degrade to round-robin
		 * behavior among equal weightes.  The default weight is zero
		 * and round-robin behavior continues.
		 *
		 * Disable preemption while traversing cpu_next_onln to
		 * ensure the list does not change.  This works because
		 * modifiers of this list and other lists in a struct cpu
		 * call pause_cpus() before making changes.
		 */
		kpreempt_disable();
		cp = start_cpu = curr_cpu->cpu_next_onln;
		new_cpu = NULL;
		do {
			/* Skip CPUs with interrupts disabled */
			if ((cp->cpu_flags & CPU_ENABLE) == 0)
				continue;

			if (intr_policy == INTR_FLAT_DIST) {
				/* select CPU */
				new_cpu = cp;
				break;
			} else if ((new_cpu == NULL) ||
			    (cp->cpu_intr_weight < new_cpu->cpu_intr_weight)) {
				/* Choose if lighter weight */
				new_cpu = cp;
			}
		} while ((cp = cp->cpu_next_onln) != start_cpu);
		ASSERT(new_cpu);
		cpuid = new_cpu->cpu_id;

		INTR_DEBUG((CE_CONT, "intr_dist: cpu %2d weight %3d: "
		    "targeted\n", cpuid, new_cpu->cpu_intr_weight));

		/* update static pointer for next round-robin */
		curr_cpu = new_cpu;
		kpreempt_enable();
		break;
	}
	mutex_exit(&intr_dist_cpu_lock);
	return (cpuid);
}

/*
 * Add or remove the the weight of a device from a CPUs interrupt weight.
 *
 * We expect nexus drivers to call intr_dist_cpuid_add/rem_device_weight for
 * their children to improve the overall quality of interrupt initialization.
 *
 * If a nexues shares the CPU returned by a single intr_dist_cpuid() call
 * among multiple devices (sharing ino) then the nexus should call
 * intr_dist_cpuid_add/rem_device_weight for each device separately. Devices
 * that share must specify the same cpuid.
 *
 * If a nexus driver is unable to determine the cpu at remove_intr time
 * for some of its interrupts, then it should not call add_device_weight -
 * intr_dist_cpuid will still provide round-robin.
 *
 * An established device weight (from dev_info node) takes precedence over
 * the weight passed in.  If a device weight is not already established
 * then the passed in nexus weight is established.
 */
void
intr_dist_cpuid_add_device_weight(uint32_t cpuid,
    dev_info_t *dip, int32_t nweight)
{
	int32_t		eweight;

	/*
	 * For non-weighted policy everything has weight of zero (and we get
	 * round-robin distribution from intr_dist_cpuid).
	 * NB: intr_policy is limited to this file. A weighted nexus driver is
	 * calls this rouitne even if intr_policy has been patched to
	 * INTR_FLAG_DIST.
	 */
	ASSERT(dip);
	if (intr_policy != INTR_WEIGHTED_DIST)
		return;

	eweight = i_ddi_get_intr_weight(dip);
	INTR_DEBUG((CE_CONT, "intr_dist: cpu %2d weight %3d: +%2d/%2d for "
	    "%s#%d/%s#%d\n", cpuid, cpu[cpuid]->cpu_intr_weight,
	    nweight, eweight, ddi_driver_name(ddi_get_parent(dip)),
	    ddi_get_instance(ddi_get_parent(dip)),
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	/* if no establish weight, establish nexus weight */
	if (eweight < 0) {
		if (nweight > 0)
			(void) i_ddi_set_intr_weight(dip, nweight);
		else
			nweight = 0;
	} else
		nweight = eweight;	/* use established weight */

	/* Establish exclusion for cpu_intr_weight manipulation */
	mutex_enter(&intr_dist_cpu_lock);
	cpu[cpuid]->cpu_intr_weight += nweight;

	/* update intr_dist_weight_max */
	if (nweight > intr_dist_weight_max)
		intr_dist_weight_max = nweight;
	mutex_exit(&intr_dist_cpu_lock);
}

void
intr_dist_cpuid_rem_device_weight(uint32_t cpuid, dev_info_t *dip)
{
	struct cpu	*cp;
	int32_t		weight;

	ASSERT(dip);
	if (intr_policy != INTR_WEIGHTED_DIST)
		return;

	/* remove weight of device from cpu */
	weight = i_ddi_get_intr_weight(dip);
	if (weight < 0)
		weight = 0;
	INTR_DEBUG((CE_CONT, "intr_dist: cpu %2d weight %3d: -%2d    for "
	    "%s#%d/%s#%d\n", cpuid, cpu[cpuid]->cpu_intr_weight, weight,
	    ddi_driver_name(ddi_get_parent(dip)),
	    ddi_get_instance(ddi_get_parent(dip)),
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	/* Establish exclusion for cpu_intr_weight manipulation */
	mutex_enter(&intr_dist_cpu_lock);
	cp = cpu[cpuid];
	cp->cpu_intr_weight -= weight;
	if (cp->cpu_intr_weight < 0)
		cp->cpu_intr_weight = 0;	/* sanity */
	mutex_exit(&intr_dist_cpu_lock);
}

ulong_t
create_softint(uint_t pil, uint_t (*func)(caddr_t, caddr_t), caddr_t arg1)
{
	uint64_t inum;

	inum = add_softintr(pil, func, arg1, SOFTINT_MT);
	return ((ulong_t)inum);
}

void
invoke_softint(processorid_t cpuid, ulong_t hdl)
{
	uint64_t inum = hdl;

	if (cpuid == CPU->cpu_id)
		setsoftint(inum);
	else
		xt_one(cpuid, setsoftint_tl1, inum, 0);
}

void
remove_softint(ulong_t hdl)
{
	uint64_t inum = hdl;

	(void) rem_softintr(inum);
}

void
sync_softint(cpuset_t set)
{
	xt_sync(set);
}
