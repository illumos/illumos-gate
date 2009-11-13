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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/spl.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kdi_impl.h>
#include <sys/cpuvar.h>
#include <sys/cpuvar.h>
#include <sys/archsystm.h>

/*
 * Handle software interrupts through 'softcall' mechanism
 *
 * At present softcall mechanism uses a global list headed by softhead.
 * Entries are added to tail and removed from head so as to preserve FIFO
 * nature of entries in the softcall list. softcall() takes care of adding
 * entries to the softtail.
 *
 * softint must take care of executing the entries in the FIFO
 * order. It could be called simultaneously from multiple cpus, however only
 * one instance of softint should process the softcall list with the exception
 * when CPU is stuck due to high interrupt load and can't execute callbacks.
 * State diagram is as follows :-
 *
 *	- Upper half which is same as old state machine
 *	  (IDLE->PEND->DRAIN->IDLE)
 *
 *	- Lower half which steals the entries from softcall queue and execute
 *        in the context of softint interrupt handler. The interrupt handler
 *        is fired on a different CPU by sending a cross-call.
 *
 * Starting state is IDLE.
 *
 * 				softint()
 *
 *
 *				(c)
 * 	____________________________________________________
 * 	|                          ^                         ^
 * 	v            (a)           |           (b)           |
 * 	IDLE--------------------->PEND--------------------->DRAIN
 *	^                         |                         |
 * 	|                         |                         |
 * 	|                         |                         |
 * 	|                         |                         |
 * 	|                         |                         |
 * 	|                         d                         d
 * 	|                         |                         |
 * 	|                         v                         v
 * 	|                         PEND                      DRAIN
 * 	|            (e)           &                          &
 * 	|<-----------------------STEAL                      STEAL
 * 	^                                                    |
 * 	|                                                    |
 * 	|                         (e)                        v
 * 	|_________________________<__________________________|
 *
 *
 *
 * Edge (a)->(b)->(c) are same as old state machine and these
 * are mutually exclusive state.
 *
 * a - When an entry is being enqueued to softcall queue then the state
 *     moves from IDLE to PEND.
 *
 * b - When interrupt handler has started processing softcall queue.
 *
 * c - When interrupt handler finished processing softcall queue, the
 *     state of machines goes back to IDLE.
 *
 * d - softcall() generates another softlevel1 iff interrupt handler
 *     hasn't run recently.
 *
 * e - Either PEND|STEAL or DRAIN|STEAL is set. We let softlevel1
 *     handler exit because we have processed all the entries.
 *
 * When CPU is being pinned by higher level interrupts for more than
 * softcall_delay clock ticks, SOFT_STEAL is OR'ed so that softlevel1
 * handler on the other CPU can drain the queue.
 *
 * These states are needed for softcall mechanism since Solaris has only
 * one interface (ie. siron ) as of now for :
 *
 * - raising a soft interrupt architecture independently (ie not through
 *   setsoftint(..) )
 * - to process the softcall queue.
 */

#define	NSOFTCALLS	200

/*
 * Defined states for softcall processing.
 */
#define	SOFT_IDLE		0x01	/* no processing is needed */
#define	SOFT_PEND		0x02	/* softcall list needs processing */
#define	SOFT_DRAIN		0x04	/* list is being processed */
#define	SOFT_STEAL		0x08	/* list is being stolen for draining */

typedef struct softcall {
	void (*sc_func)(void *);	/* function to call */
	void *sc_arg;			/* arg to pass to func */
	struct softcall *sc_next;	/* next in list */
} softcall_t;

/*
 * softcall list and state variables.
 */
static softcall_t *softcalls;
static softcall_t *softhead, *softtail, *softfree;
static uint_t	softcall_state;
static clock_t softcall_tick;
static clock_t softcall_countstart, softcall_lastpoke;
static uint_t softcall_pokecount;

/*
 * Max number of pokes per second before increasing softcall_delay
 */
uint_t softcall_pokemax = 10;

/*
 * This ensures that softcall entries don't get stuck for long. It's expressed
 * in 10 milliseconds as 1 unit. When hires_tick is set or other clock frequency
 * is used, softcall_init() ensures that it's still expressed as 1 =  10 milli
 * seconds.
 */
unsigned int softcall_delay = 1;

/*
 * The last CPU which will drain softcall queue.
 */
static int softcall_latest_cpuid = -1;

/*
 * CPUSET to hold the CPU which is processing softcall queue
 * currently. There can be more than one CPU having bit set
 * but it will happen only when they are stuck.
 */
static cpuset_t *softcall_cpuset = NULL;

/*
 * protects softcall lists and control variable softcall_state.
 */
static kmutex_t	softcall_lock;

static void (*kdi_softcall_func)(void);
extern void siron_poke_cpu(cpuset_t);

extern void siron(void);
extern void kdi_siron(void);


void
softcall_init(void)
{
	softcall_t *sc;

	softcalls = kmem_zalloc(sizeof (softcall_t) * NSOFTCALLS, KM_SLEEP);
	softcall_cpuset = kmem_zalloc(sizeof (cpuset_t), KM_SLEEP);
	for (sc = softcalls; sc < &softcalls[NSOFTCALLS]; sc++) {
		sc->sc_next = softfree;
		softfree = sc;
	}
	mutex_init(&softcall_lock, NULL, MUTEX_SPIN,
	    (void *)ipltospl(SPL8));
	softcall_state = SOFT_IDLE;
	softcall_tick = ddi_get_lbolt();

	/*
	 * Since softcall_delay is expressed as 1 = 10 milliseconds.
	 */
	softcall_delay = softcall_delay * (hz/100);
	CPUSET_ZERO(*softcall_cpuset);
}

/*
 * Gets called when softcall queue is not moving forward. We choose
 * a CPU and poke except the ones which are already poked.
 */
static int
softcall_choose_cpu()
{
	cpu_t *cplist = CPU;
	cpu_t *cp;
	int intr_load = INT_MAX;
	int cpuid = -1;
	cpuset_t poke;
	int s;

	ASSERT(getpil() >= DISP_LEVEL);
	ASSERT(ncpus > 1);
	ASSERT(MUTEX_HELD(&softcall_lock));

	CPUSET_ZERO(poke);

	/*
	 * The hint is to start from current CPU.
	 */
	cp = cplist;
	do {
		/*
		 * Don't select this CPU if :
		 *   - in cpuset already
		 *   - CPU is not accepting interrupts
		 *   - CPU is being offlined
		 */
		if (CPU_IN_SET(*softcall_cpuset, cp->cpu_id) ||
		    (cp->cpu_flags & CPU_ENABLE) == 0 ||
		    (cp == cpu_inmotion))
			continue;
#if defined(__x86)
		/*
		 * Don't select this CPU if a hypervisor indicates it
		 * isn't currently scheduled onto a physical cpu.  We are
		 * looking for a cpu that can respond quickly and the time
		 * to get the virtual cpu scheduled and switched to running
		 * state is likely to be relatively lengthy.
		 */
		if (vcpu_on_pcpu(cp->cpu_id) == VCPU_NOT_ON_PCPU)
			continue;
#endif	/* __x86 */

		/* if CPU is not busy */
		if (cp->cpu_intrload == 0) {
			cpuid = cp->cpu_id;
			break;
		}

		if (cp->cpu_intrload < intr_load) {
			cpuid = cp->cpu_id;
			intr_load = cp->cpu_intrload;
		} else if (cp->cpu_intrload == intr_load) {
			/*
			 * We want to poke CPUs having similar
			 * load because we don't know which CPU is
			 * can acknowledge level1 interrupt. The
			 * list of such CPUs should not be large.
			 */
			if (cpuid != -1) {
				/*
				 * Put the last CPU chosen because
				 * it also has same interrupt load.
				 */
				CPUSET_ADD(poke, cpuid);
				cpuid = -1;
			}

			CPUSET_ADD(poke, cp->cpu_id);
		}
	} while ((cp = cp->cpu_next_onln) != cplist);

	/* if we found a CPU which suits best to poke */
	if (cpuid != -1) {
		CPUSET_ZERO(poke);
		CPUSET_ADD(poke, cpuid);
	}

	if (CPUSET_ISNULL(poke)) {
		mutex_exit(&softcall_lock);
		return (0);
	}

	/*
	 * We first set the bit in cpuset and then poke.
	 */
	CPUSET_XOR(*softcall_cpuset, poke);
	mutex_exit(&softcall_lock);

	/*
	 * If softcall() was called at low pil then we may
	 * get preempted before we raise PIL. It should be okay
	 * because we are just going to poke CPUs now or at most
	 * another thread may start choosing CPUs in this routine.
	 */
	s = splhigh();
	siron_poke_cpu(poke);
	splx(s);
	return (1);
}


/*
 * Call function func with argument arg
 * at some later time at software interrupt priority
 */
void
softcall(void (*func)(void *), void *arg)
{
	softcall_t *sc;
	clock_t w, now;

	/*
	 * protect against cross-calls
	 */
	mutex_enter(&softcall_lock);
	/* coalesce identical softcalls */
	for (sc = softhead; sc != 0; sc = sc->sc_next) {
		if (sc->sc_func == func && sc->sc_arg == arg) {
			goto intr;
		}
	}

	if ((sc = softfree) == 0)
		panic("too many softcalls");

	softfree = sc->sc_next;
	sc->sc_func = func;
	sc->sc_arg = arg;
	sc->sc_next = 0;

	if (softhead) {
		softtail->sc_next = sc;
		softtail = sc;
	} else
		softhead = softtail = sc;

intr:
	if (softcall_state & SOFT_IDLE) {
		softcall_state = SOFT_PEND;
		softcall_tick = ddi_get_lbolt();
		mutex_exit(&softcall_lock);
		siron();
	} else if (softcall_state & (SOFT_DRAIN|SOFT_PEND)) {
		now = ddi_get_lbolt();
		w = now - softcall_tick;
		if (w <= softcall_delay || ncpus == 1) {
			mutex_exit(&softcall_lock);
			return;
		}
		/*
		 * Did we poke less than a second ago?
		 */
		if (now - softcall_lastpoke < hz) {
			/*
			 * We did, increment the poke count and
			 * see if we are poking too often
			 */
			if (softcall_pokecount++ == 0)
				softcall_countstart = now;
			if (softcall_pokecount > softcall_pokemax) {
				/*
				 * If poking too much increase the delay
				 */
				if (now - softcall_countstart <= hz)
					softcall_delay++;
				softcall_pokecount = 0;
			}
		} else {
			/*
			 * poke rate has dropped off, reset the poke monitor
			 */
			softcall_pokecount = 0;
		}
		softcall_lastpoke = now;
		if (!(softcall_state & SOFT_STEAL)) {
			softcall_state |= SOFT_STEAL;

			/*
			 * We want to give some more chance before
			 * fishing around again.
			 */
			softcall_tick = now;
		}

		/* softcall_lock will be released by this routine */
		(void) softcall_choose_cpu();
	}
}

void
kdi_softcall(void (*func)(void))
{
	kdi_softcall_func = func;

	if (softhead == NULL)
		kdi_siron();
}

/*
 * Called to process software interrupts take one off queue, call it,
 * repeat.
 *
 * Note queue may change during call; softcall_lock, state variables
 * softcall_state and softcall_latest_cpuid ensures that -
 * - we don't have multiple cpus pulling from the list (thus causing
 *   a violation of FIFO order with an exception when we are stuck).
 * - we don't miss a new entry having been added to the head.
 * - we don't miss a wakeup.
 */

void
softint(void)
{
	softcall_t *sc = NULL;
	void (*func)();
	caddr_t arg;
	int cpu_id = CPU->cpu_id;

	/*
	 * Don't process softcall queue if current CPU is quiesced or
	 * offlined. This can happen when a CPU is running pause
	 * thread but softcall already sent a xcall.
	 */
	if (CPU->cpu_flags & (CPU_QUIESCED|CPU_OFFLINE)) {
		if (softcall_cpuset != NULL &&
		    CPU_IN_SET(*softcall_cpuset, cpu_id)) {
			CPUSET_DEL(*softcall_cpuset, cpu_id);
			goto out;
		}
	}

	mutex_enter(&softcall_lock);

	if (softcall_state & (SOFT_STEAL|SOFT_PEND)) {
		softcall_state = SOFT_DRAIN;
	} else  {
		/*
		 * The check for softcall_cpuset being
		 * NULL is required because it may get
		 * called very early during boot.
		 */
		if (softcall_cpuset != NULL &&
		    CPU_IN_SET(*softcall_cpuset, cpu_id))
			CPUSET_DEL(*softcall_cpuset, cpu_id);
		mutex_exit(&softcall_lock);
		goto out;
	}

	/*
	 * Setting softcall_latest_cpuid to current CPU ensures
	 * that there is only one active softlevel1 handler to
	 * process softcall queues.
	 *
	 * Since softcall_lock lock is dropped before calling
	 * func (callback), we need softcall_latest_cpuid
	 * to prevent two softlevel1 hanlders working on the
	 * queue when the first softlevel1 handler gets
	 * stuck due to high interrupt load.
	 */
	softcall_latest_cpuid = cpu_id;

	/* add ourself to the cpuset */
	if (!CPU_IN_SET(*softcall_cpuset, cpu_id))
		CPUSET_ADD(*softcall_cpuset, cpu_id);

	for (;;) {
		softcall_tick = ddi_get_lbolt();
		if ((sc = softhead) != NULL) {
			func = sc->sc_func;
			arg = sc->sc_arg;
			softhead = sc->sc_next;
			sc->sc_next = softfree;
			softfree = sc;
		}

		if (sc == NULL) {
			if (CPU_IN_SET(*softcall_cpuset, cpu_id))
				CPUSET_DEL(*softcall_cpuset, cpu_id);

			softcall_state = SOFT_IDLE;
			ASSERT(softcall_latest_cpuid == cpu_id);
			softcall_latest_cpuid = -1;

			mutex_exit(&softcall_lock);
			break;
		}

		mutex_exit(&softcall_lock);
		func(arg);
		mutex_enter(&softcall_lock);

		/*
		 * No longer need softcall processing from current
		 * interrupt handler because either
		 *  (a) softcall is in SOFT_IDLE state or
		 *  (b) There is a CPU already draining softcall
		 *	queue and the current softlevel1 is no
		 *	longer required.
		 */
		if (softcall_latest_cpuid != cpu_id) {
			if (CPU_IN_SET(*softcall_cpuset, cpu_id))
				CPUSET_DEL(*softcall_cpuset, cpu_id);

			mutex_exit(&softcall_lock);
			break;
		}
	}

out:
	if ((func = kdi_softcall_func) != NULL) {
		kdi_softcall_func = NULL;
		func();
	}
}
