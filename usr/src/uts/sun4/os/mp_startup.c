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

#include <sys/sysmacros.h>
#include <sys/prom_plat.h>
#include <sys/prom_debug.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kp.h>
#include <vm/seg_kmem.h>
#include <sys/machsystm.h>
#include <sys/callb.h>
#include <sys/cpu_module.h>
#include <sys/chip.h>
#include <sys/dtrace.h>
#include <sys/reboot.h>
#include <sys/kdi.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#include <sys/bootconf.h>
#endif /* TRAPTRACE */

#include <sys/cpu_sgnblk_defs.h>

extern void cpu_intrq_setup(struct cpu *);
extern void cpu_intrq_register(struct cpu *);

struct cpu	*cpus;	/* pointer to other cpus; dynamically allocate */
struct cpu	*cpu[NCPU];	/* pointers to all CPUs */
uint64_t	cpu_pa[NCPU];	/* pointers to all CPUs in PA */
cpu_core_t	cpu_core[NCPU];	/* cpu_core structures */

#ifdef TRAPTRACE
caddr_t	ttrace_buf;	/* bop alloced traptrace for all cpus except 0 */
#endif /* TRAPTRACE */

/* bit mask of cpus ready for x-calls, protected by cpu_lock */
cpuset_t cpu_ready_set;

/* bit mask used to communicate with cpus during bringup */
static cpuset_t proxy_ready_set;

static void	slave_startup(void);

/*
 * Defined in $KARCH/os/mach_mp_startup.c
 */
#pragma weak init_cpu_info

/*
 * Amount of time (in milliseconds) we should wait before giving up on CPU
 * initialization and assuming that the CPU we're trying to wake up is dead
 * or out of control.
 */
#define	CPU_WAKEUP_GRACE_MSEC 1000

/*
 * MP configurations may reserve additional interrupt request entries.
 * intr_add_{div,max} can be modified to tune memory usage.
 */

uint_t	intr_add_div = 1;			/* 1=worst case memory usage */
size_t	intr_add_max = 0;

/* intr_add_{pools,head,tail} calculated based on intr_add_{div,max} */

size_t	intr_add_pools = 0;			/* additional pools per cpu */
struct intr_req	*intr_add_head = (struct intr_req *)NULL;
#ifdef	DEBUG
struct intr_req	*intr_add_tail = (struct intr_req *)NULL;
#endif	/* DEBUG */


#ifdef	TRAPTRACE
/*
 * This function bop allocs traptrace buffers for all cpus
 * other than boot cpu.
 */
caddr_t
trap_trace_alloc(caddr_t base)
{
	caddr_t	vaddr;
	extern int max_ncpus;

	if (max_ncpus == 1) {
		return (base);
	}

	if ((vaddr = (caddr_t)BOP_ALLOC(bootops, base, (TRAP_TBUF_SIZE *
		(max_ncpus - 1)), TRAP_TBUF_SIZE)) == NULL) {
		panic("traptrace_alloc: can't bop alloc");
	}
	ttrace_buf = vaddr;
	PRM_DEBUG(ttrace_buf);
	return (vaddr + (TRAP_TBUF_SIZE * (max_ncpus - 1)));
}
#endif	/* TRAPTRACE */

/*
 * common slave cpu initialization code
 */
void
common_startup_init(cpu_t *cp, int cpuid)
{
	kthread_id_t tp;
	sfmmu_t *sfmmup;
	caddr_t	sp;

	/*
	 * Allocate and initialize the startup thread for this CPU.
	 */
	tp = thread_create(NULL, 0, slave_startup, NULL, 0, &p0,
	    TS_STOPPED, maxclsyspri);

	/*
	 * Set state to TS_ONPROC since this thread will start running
	 * as soon as the CPU comes online.
	 *
	 * All the other fields of the thread structure are setup by
	 * thread_create().
	 */
	THREAD_ONPROC(tp, cp);
	tp->t_preempt = 1;
	tp->t_bound_cpu = cp;
	tp->t_affinitycnt = 1;
	tp->t_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;

	sfmmup = astosfmmu(&kas);
	CPUSET_ADD(sfmmup->sfmmu_cpusran, cpuid);

	/*
	 * Setup thread to start in slave_startup.
	 */
	sp = tp->t_stk;
	tp->t_pc = (uintptr_t)slave_startup - 8;
	tp->t_sp = (uintptr_t)((struct rwindow *)sp - 1) - STACK_BIAS;

	cp->cpu_id = cpuid;
	cp->cpu_self = cp;
	cp->cpu_thread = tp;
	cp->cpu_lwp = NULL;
	cp->cpu_dispthread = tp;
	cp->cpu_dispatch_pri = DISP_PRIO(tp);
}

/*
 * parametric flag setting functions.  these routines set the cpu
 * state just prior to releasing the slave cpu.
 */
void
cold_flag_set(int cpuid)
{
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpu[cpuid];
	cp->cpu_flags |= CPU_RUNNING | CPU_ENABLE | CPU_EXISTS;
	cpu_add_active(cp);
	/*
	 * Add CPU_READY after the cpu_add_active() call
	 * to avoid pausing cp.
	 */
	cp->cpu_flags |= CPU_READY;		/* ready */
	cpu_set_state(cp);
}

static void
warm_flag_set(int cpuid)
{
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * warm start activates cpus into the OFFLINE state
	 */
	cp = cpu[cpuid];
	cp->cpu_flags |= CPU_RUNNING | CPU_READY | CPU_EXISTS
		| CPU_OFFLINE | CPU_QUIESCED;
	cpu_set_state(cp);
}

/*
 * Internal cpu startup sequencer
 * The sequence is as follows:
 *
 * MASTER	SLAVE
 * -------	----------
 * assume the kernel data is initialized
 * clear the proxy bit
 * start the slave cpu
 * wait for the slave cpu to set the proxy
 *
 *		the slave runs slave_startup and then sets the proxy
 *		the slave waits for the master to add slave to the ready set
 *
 * the master finishes the initialization and
 * adds the slave to the ready set
 *
 *		the slave exits the startup thread and is running
 */
void
start_cpu(int cpuid, void(*flag_func)(int))
{
	extern caddr_t cpu_startup;
	int timout;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Before we begin the dance, tell DTrace that we're about to start
	 * a CPU.
	 */
	if (dtrace_cpustart_init != NULL)
		(*dtrace_cpustart_init)();

	/* start the slave cpu */
	CPUSET_DEL(proxy_ready_set, cpuid);
	if (prom_test("SUNW,start-cpu-by-cpuid") == 0) {
		(void) prom_startcpu_bycpuid(cpuid, (caddr_t)&cpu_startup,
		    cpuid);
	} else {
		/* "by-cpuid" interface didn't exist.  Do it the old way */
		pnode_t nodeid = cpunodes[cpuid].nodeid;

		ASSERT(nodeid != (pnode_t)0);
		(void) prom_startcpu(nodeid, (caddr_t)&cpu_startup, cpuid);
	}

	/* wait for the slave cpu to check in. */
	for (timout = CPU_WAKEUP_GRACE_MSEC; timout; timout--) {
		if (CPU_IN_SET(proxy_ready_set, cpuid))
			break;
		DELAY(1000);
	}
	if (timout == 0) {
		panic("cpu%d failed to start (2)", cpuid);
	}

	/*
	 * The slave has started; we can tell DTrace that it's safe again.
	 */
	if (dtrace_cpustart_fini != NULL)
		(*dtrace_cpustart_fini)();

	/* run the master side of stick synchronization for the slave cpu */
	sticksync_master();

	/*
	 * deal with the cpu flags in a phase-specific manner
	 * for various reasons, this needs to run after the slave
	 * is checked in but before the slave is released.
	 */
	(*flag_func)(cpuid);

	/* release the slave */
	CPUSET_ADD(cpu_ready_set, cpuid);
}

#ifdef TRAPTRACE
int trap_tr0_inuse = 1;	/* it is always used on the boot cpu */
int trap_trace_inuse[NCPU];
#endif /* TRAPTRACE */

#define	cpu_next_free	cpu_prev

/*
 * Routine to set up a CPU to prepare for starting it up.
 */
void
setup_cpu_common(int cpuid)
{
	struct cpu *cp = NULL;
	kthread_id_t tp;
#ifdef TRAPTRACE
	int tt_index;
	TRAP_TRACE_CTL	*ctlp;
	caddr_t	newbuf;
#endif /* TRAPTRACE */

	extern void idle();
	extern void init_intr_threads(struct cpu *);

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu[cpuid] == NULL);

	ASSERT(ncpus <= max_ncpus);

#ifdef TRAPTRACE
	/*
	 * allocate a traptrace buffer for this CPU.
	 */
	ctlp = &trap_trace_ctl[cpuid];
	if (!trap_tr0_inuse) {
		trap_tr0_inuse = 1;
		newbuf = trap_tr0;
		tt_index = -1;
	} else {
		for (tt_index = 0; tt_index < (max_ncpus-1); tt_index++)
			if (!trap_trace_inuse[tt_index])
			    break;
		ASSERT(tt_index < max_ncpus - 1);
		trap_trace_inuse[tt_index] = 1;
		newbuf = (caddr_t)(ttrace_buf + (tt_index * TRAP_TBUF_SIZE));
	}
	ctlp->d.vaddr_base = newbuf;
	ctlp->d.offset = ctlp->d.last_offset = 0;
	ctlp->d.limit = trap_trace_bufsize;
	ctlp->d.paddr_base = va_to_pa(newbuf);
	ASSERT(ctlp->d.paddr_base != (uint64_t)-1);
	/*
	 * initialize HV trap trace buffer for other cpus
	 */
	htrap_trace_setup((newbuf + TRAP_TSIZE), cpuid);
#endif /* TRAPTRACE */

	/*
	 * Obtain pointer to the appropriate cpu structure.
	 */
	if (cpu0.cpu_flags == 0) {
		cp = &cpu0;
	} else {
		/*
		 *  When dynamically allocating cpu structs,
		 *  cpus is used as a pointer to a list of freed
		 *  cpu structs.
		 */
		if (cpus) {
			/* grab the first cpu struct on the free list */
			cp = cpus;
			if (cp->cpu_next_free)
				cpus = cp->cpu_next_free;
			else
				cpus = NULL;
		}
	}

	if (cp == NULL)
		cp = vmem_xalloc(static_alloc_arena, CPU_ALLOC_SIZE,
		    CPU_ALLOC_SIZE, 0, 0, NULL, NULL, VM_SLEEP);

	bzero(cp, sizeof (*cp));

	cp->cpu_id = cpuid;
	cp->cpu_self = cp;

	/*
	 * Initialize ptl1_panic stack
	 */
	ptl1_init_cpu(cp);

	/*
	 * Initialize the dispatcher for this CPU.
	 */
	disp_cpu_init(cp);

	cpu_vm_data_init(cp);

	/*
	 * Now, initialize per-CPU idle thread for this CPU.
	 */
	tp = thread_create(NULL, 0, idle, NULL, 0, &p0, TS_ONPROC, -1);

	cp->cpu_idle_thread = tp;

	tp->t_preempt = 1;
	tp->t_bound_cpu = cp;
	tp->t_affinitycnt = 1;
	tp->t_cpu = cp;
	tp->t_disp_queue = cp->cpu_disp;

	/*
	 * Registering a thread in the callback table is usually
	 * done in the initialization code of the thread. In this
	 * case, we do it right after thread creation to avoid
	 * blocking idle thread while registering itself. It also
	 * avoids the possibility of reregistration in case a CPU
	 * restarts its idle thread.
	 */
	CALLB_CPR_INIT_SAFE(tp, "idle");

	init_cpu_info(cp);

	/*
	 * Initialize the interrupt threads for this CPU
	 */
	init_intr_pool(cp);
	init_intr_threads(cp);

	/*
	 * Add CPU to list of available CPUs.
	 * It'll be on the active list after it is started.
	 */
	cpu_add_unit(cp);

	/*
	 * Allocate and init cpu module private data structures,
	 * including scrubber.
	 */
	cpu_init_private(cp);

	/*
	 * Associate this CPU with a physical processor
	 */
	chip_cpu_init(cp);

	cpu_intrq_setup(cp);
}

/*
 * Routine to clean up a CPU after shutting it down.
 */
int
cleanup_cpu_common(int cpuid)
{
	struct cpu *cp;
#ifdef TRAPTRACE
	int i;
	TRAP_TRACE_CTL	*ctlp;
	caddr_t	newbuf;
#endif /* TRAPTRACE */

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpu[cpuid] != NULL);

	cp = cpu[cpuid];

	/* Free cpu module private data structures, including scrubber. */
	cpu_uninit_private(cp);

	cpu_vm_data_destroy(cp);

	/*
	 * Remove CPU from list of available CPUs.
	 */
	cpu_del_unit(cpuid);

	/*
	 * Clean up the interrupt pool.
	 */
	cleanup_intr_pool(cp);

	/*
	 * At this point, the only threads bound to this CPU should be
	 * special per-cpu threads: it's idle thread, it's pause thread,
	 * and it's interrupt threads.  Clean these up.
	 */
	cpu_destroy_bound_threads(cp);

	/*
	 * Free the interrupt stack.
	 */
	segkp_release(segkp, cp->cpu_intr_stack);

#ifdef TRAPTRACE
	/*
	 * Free the traptrace buffer for this CPU.
	 */
	ctlp = &trap_trace_ctl[cpuid];
	newbuf = ctlp->d.vaddr_base;
	i = (newbuf - ttrace_buf) / (TRAP_TBUF_SIZE);
	if (((newbuf - ttrace_buf) % (TRAP_TBUF_SIZE) == 0) &&
	    ((i >= 0) && (i < (max_ncpus-1)))) {
		/*
		 * This CPU got it's trap trace buffer from the
		 * boot-alloc'd bunch of them.
		 */
		trap_trace_inuse[i] = 0;
		bzero(newbuf, (TRAP_TBUF_SIZE));
	} else if (newbuf == trap_tr0) {
		trap_tr0_inuse = 0;
		bzero(trap_tr0, (TRAP_TBUF_SIZE));
	} else {
		cmn_err(CE_WARN, "failed to free trap trace buffer from cpu%d",
		    cpuid);
	}
	bzero(ctlp, sizeof (*ctlp));
#endif /* TRAPTRACE */

	/*
	 * There is a race condition with mutex_vector_enter() which
	 * caches a cpu pointer. The race is detected by checking cpu_next.
	 */
	disp_cpu_fini(cp);
	cpu_pa[cpuid] = 0;
	bzero(cp, sizeof (*cp));

	/*
	 * Place the freed cpu structure on the list of freed cpus.
	 */
	if (cp != &cpu0) {
		if (cpus) {
			cp->cpu_next_free = cpus;
			cpus = cp;
		}
		else
			cpus = cp;
	}

	return (0);
}

/*
 * This routine is used to start a previously powered off processor.
 * Note that restarted cpus are initialized into the offline state.
 */
void
restart_other_cpu(int cpuid)
{
	struct cpu *cp;
	kthread_id_t tp;
	caddr_t	sp;
	extern void idle();

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpuid < NCPU && cpu[cpuid] != NULL);

	/*
	 * Obtain pointer to the appropriate cpu structure.
	 */
	cp = cpu[cpuid];

	common_startup_init(cp, cpuid);

	/*
	 * idle thread t_lock is held when the idle thread is suspended.
	 * Manually unlock the t_lock of idle loop so that we can resume
	 * the suspended idle thread.
	 * Also adjust the PC of idle thread for re-retry.
	 */
	cp->cpu_intr_actv = 0;	/* clear the value from previous life */
	cp->cpu_m.mutex_ready = 0; /* we are not ready yet */
	lock_clear(&cp->cpu_idle_thread->t_lock);
	tp = cp->cpu_idle_thread;

	sp = tp->t_stk;
	tp->t_sp = (uintptr_t)((struct rwindow *)sp - 1) - STACK_BIAS;
	tp->t_pc = (uintptr_t)idle - 8;

	/*
	 * restart the cpu now
	 */
	promsafe_pause_cpus();
	start_cpu(cpuid, warm_flag_set);
	start_cpus();

	/* call cmn_err outside pause_cpus/start_cpus to avoid deadlock */
	cmn_err(CE_CONT, "!cpu%d initialization complete - restarted\n",
	    cpuid);
}

/*
 * Startup function executed on 'other' CPUs.  This is the first
 * C function after cpu_start sets up the cpu registers.
 */
static void
slave_startup(void)
{
	struct cpu	*cp = CPU;
	ushort_t	original_flags = cp->cpu_flags;

#ifdef TRAPTRACE
	htrap_trace_register(cp->cpu_id);
#endif
	cpu_intrq_register(CPU);
	cp->cpu_m.mutex_ready = 1;
	cp->cpu_m.poke_cpu_outstanding = B_FALSE;

	/* acknowledge that we are done with initialization */
	CPUSET_ADD(proxy_ready_set, cp->cpu_id);

	/* synchronize STICK */
	sticksync_slave();

	if (boothowto & RB_DEBUG)
		kdi_dvec_cpu_init(cp);

	/*
	 * the slave will wait here forever -- assuming that the master
	 * will get back to us.  if it doesn't we've got bigger problems
	 * than a master not replying to this slave.
	 * the small delay improves the slave's responsiveness to the
	 * master's ack and decreases the time window between master and
	 * slave operations.
	 */
	while (!CPU_IN_SET(cpu_ready_set, cp->cpu_id))
		DELAY(1);

	/* enable interrupts */
	(void) spl0();

	/*
	 * Signature block update to indicate that this CPU is in OS now.
	 * This needs to be done after the PIL is lowered since on
	 * some platforms the update code may block.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_RUN, SIGSUBST_NULL, cp->cpu_id);

	/*
	 * park the slave thread in a safe/quiet state and wait for the master
	 * to finish configuring this CPU before proceeding to thread_exit().
	 */
	while (((volatile ushort_t)cp->cpu_flags) & CPU_QUIESCED)
		DELAY(1);

	/*
	 * Initialize CPC CPU state.
	 */
	kcpc_hw_startup_cpu(original_flags);

	/*
	 * Notify the CMT subsystem that the slave has started
	 */
	chip_cpu_startup(CPU);

	/*
	 * Now we are done with the startup thread, so free it up.
	 */
	thread_exit();
	cmn_err(CE_PANIC, "slave_startup: cannot return");
	/*NOTREACHED*/
}

/*
 * 4163850 changes the allocation method for cpu structs. cpu structs
 * are dynamically allocated. This routine now determines if additional
 * per-cpu intr_req entries need to be allocated.
 */
int
ndata_alloc_cpus(struct memlist *ndata)
{
	size_t real_sz;
	extern int niobus;

	if (niobus > 1) {

		/*
		 * Allocate additional intr_req entries if we have more than
		 * one io bus.  The memory to allocate is calculated from four
		 * variables: niobus, max_ncpus, intr_add_div, and intr_add_max.
		 * Allocate multiple of INTR_POOL_SIZE bytes (512).  Each cpu
		 * already reserves 512 bytes in its machcpu structure, so the
		 * worst case is (512 * (niobus - 1) * max_ncpus) add'l bytes.
		 *
		 * While niobus and max_ncpus reflect the h/w, the following
		 * may be tuned (before boot):
		 *
		 *	intr_add_div -	divisor for scaling the number of
		 *			additional intr_req entries. use '1'
		 *			for worst case memory, '2' for half,
		 *			etc.
		 *
		 *   intr_add_max - upper limit on bytes of memory to reserve
		 */

		real_sz = INTR_POOL_SIZE * (niobus - 1) * max_ncpus;

		/* tune memory usage by applying divisor and maximum */

		if (intr_add_max == 0)
			intr_add_max = max_ncpus * INTR_POOL_SIZE;
		real_sz = MIN(intr_add_max, real_sz / MAX(intr_add_div, 1));

		/* round down to multiple of (max_ncpus * INTR_POOL_SIZE) */

		intr_add_pools = real_sz / (max_ncpus * INTR_POOL_SIZE);
		real_sz = intr_add_pools * (max_ncpus * INTR_POOL_SIZE);

		/* actually reserve the space */

		intr_add_head = ndata_alloc(ndata, real_sz, ecache_alignsize);
		if (intr_add_head == NULL)
			return (-1);

		PRM_DEBUG(intr_add_head);
#ifdef	DEBUG
		intr_add_tail = (struct intr_req *)
		    ((uintptr_t)intr_add_head + real_sz);
#endif	/* DEBUG */
	}

	return (0);
}


extern struct cpu	*cpu[NCPU];	/* pointers to all CPUs */

extern void setup_cpu_common(int);
extern void common_startup_init(cpu_t *, int);
extern void start_cpu(int, void(*func)(int));
extern void cold_flag_set(int cpuid);

/*
 * cpu_bringup_set is a tunable (via /etc/system, debugger, etc.) that
 * can be used during debugging to control which processors are brought
 * online at boot time.  The variable represents a bitmap of the id's
 * of the processors that will be brought online.  The initialization
 * of this variable depends on the type of cpuset_t, which varies
 * depending on the number of processors supported (see cpuvar.h).
 */
cpuset_t cpu_bringup_set;


/*
 * Generic start-all cpus entry.  Typically used during cold initialization.
 * Note that cold start cpus are initialized into the online state.
 */
/*ARGSUSED*/
void
start_other_cpus(int flag)
{
	int cpuid;
	extern void idlestop_init(void);
	int bootcpu;

	/*
	 * Check if cpu_bringup_set has been explicitly set before
	 * initializing it.
	 */
	if (CPUSET_ISNULL(cpu_bringup_set)) {
#ifdef MPSAS
		/* just CPU 0 */
		CPUSET_ADD(cpu_bringup_set, 0);
#else
		CPUSET_ALL(cpu_bringup_set);
#endif
	}

	if (&cpu_feature_init)
		cpu_feature_init();

	/*
	 * Initialize CPC.
	 */
	kcpc_hw_init();

	mutex_enter(&cpu_lock);

	/*
	 * Initialize our own cpu_info.
	 */
	init_cpu_info(CPU);

	/*
	 * Initialize CPU 0 cpu module private data area, including scrubber.
	 */
	cpu_init_private(CPU);

	/*
	 * perform such initialization as is needed
	 * to be able to take CPUs on- and off-line.
	 */
	cpu_pause_init();
	xc_init();		/* initialize processor crosscalls */
	idlestop_init();

	if (!use_mp) {
		mutex_exit(&cpu_lock);
		cmn_err(CE_CONT, "?***** Not in MP mode\n");
		return;
	}
	/*
	 * should we be initializing this cpu?
	 */
	bootcpu = getprocessorid();

	/*
	 * launch all the slave cpus now
	 */
	for (cpuid = 0; cpuid < NCPU; cpuid++) {
		pnode_t nodeid = cpunodes[cpuid].nodeid;

		if (nodeid == (pnode_t)0)
			continue;

		if (cpuid == bootcpu) {
			if (!CPU_IN_SET(cpu_bringup_set, cpuid)) {
				cmn_err(CE_WARN, "boot cpu not a member "
				    "of cpu_bringup_set, adding it");
				CPUSET_ADD(cpu_bringup_set, cpuid);
			}
			continue;
		}
		if (!CPU_IN_SET(cpu_bringup_set, cpuid))
			continue;

		ASSERT(cpu[cpuid] == NULL);

		setup_cpu_common(cpuid);

		common_startup_init(cpu[cpuid], cpuid);

		start_cpu(cpuid, cold_flag_set);
		/*
		 * Because slave_startup() gets fired off after init()
		 * starts, we can't use the '?' trick to do 'boot -v'
		 * printing - so we always direct the 'cpu .. online'
		 * messages to the log.
		 */
		cmn_err(CE_CONT, "!cpu%d initialization complete - online\n",
		    cpuid);

		/*
		 * XXX: register_cpu_setup() callbacks should be called here
		 * with a new setup code, CPU_BOOT (or something).
		 */
		if (dtrace_cpu_init != NULL)
			(*dtrace_cpu_init)(cpuid);
	}

	/*
	 * since all the cpus are online now, redistribute interrupts to them.
	 */
	intr_redist_all_cpus();

	mutex_exit(&cpu_lock);

	/*
	 * Start the Ecache scrubber.  Must be done after all calls to
	 * cpu_init_private for every cpu (including CPU 0).
	 */
	cpu_init_cache_scrub();

	if (&cpu_mp_init)
		cpu_mp_init();
}
