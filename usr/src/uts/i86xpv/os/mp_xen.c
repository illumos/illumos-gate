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
 * Virtual CPU management.
 *
 * VCPUs can be controlled in one of two ways; through the domain itself
 * (psradm, p_online(), etc.), and via changes in xenstore (vcpu_config()).
 * Unfortunately, the terminology is used in different ways; they work out as
 * follows:
 *
 * P_ONLINE: the VCPU is up and running, taking interrupts and running threads
 *
 * P_OFFLINE: the VCPU is up and running, but quiesced (i.e. blocked in the
 * hypervisor on the idle thread).  It must be up since a downed VCPU cannot
 * receive interrupts, and we require this for offline CPUs in Solaris.
 *
 * P_POWEROFF: the VCPU is down (we never called xen_vcpu_up(), or called
 * xen_vcpu_down() for it).  It can't take interrupts or run anything, though
 * if it has run previously, its software state (cpu_t, machcpu structures, IPI
 * event channels, etc.) will still exist.
 *
 * The hypervisor has two notions of CPU states as represented in the store:
 *
 * "offline": the VCPU is down.  Corresponds to P_POWEROFF.
 *
 * "online": the VCPU is running.  Corresponds to a CPU state other than
 * P_POWEROFF.
 *
 * Currently, only a notification via xenstore can bring a CPU into a
 * P_POWEROFF state, and only the domain can change between P_ONLINE, P_NOINTR,
 * P_OFFLINE, etc.  We need to be careful to treat xenstore notifications
 * idempotently, as we'll get 'duplicate' entries when we resume a domain.
 *
 * Note that the xenstore configuration is strictly advisory, in that a domain
 * can choose to ignore it and still power up a VCPU in the offline state. To
 * play nice, we don't allow it. Thus, any attempt to power on/off a CPU is
 * ENOTSUP from within Solaris.
 *
 * Powering off a VCPU and suspending the domain use similar code. The
 * difficulty here is that we must ensure that each VCPU is in a stable
 * state: it must have a saved PCB, and not be responding to interrupts
 * (since we are just about to remove its ability to run on a real CPU,
 * possibly forever).  However, an offline CPU in Solaris can take
 * cross-call interrupts, as mentioned, so we must go through a
 * two-stage process.  First, we use the standard Solaris pause_cpus().
 * This ensures that all CPUs are either in mach_cpu_pause() or
 * mach_cpu_idle(), and nothing will cross-call them.
 *
 * Powered-off-CPUs are already safe, as we own the cpu_lock needed to
 * bring them back up, and in state CPU_PHASE_POWERED_OFF.
 *
 * Running CPUs are spinning in mach_cpu_pause() waiting for either
 * PAUSE_IDLE or CPU_PHASE_WAIT_SAFE.
 *
 * Offline CPUs are either running the idle thread and periodically
 * checking for CPU_PHASE_WAIT_SAFE, or blocked in the hypervisor.
 *
 * Thus, we set CPU_PHASE_WAIT_SAFE for every powered-on CPU, as well as
 * poking them to make sure they're not blocked[1]. When every CPU has
 * responded by reaching a safe state and setting CPU_PHASE_SAFE, we
 * know we can suspend, or power-off a CPU, without problems.
 *
 * [1] note that we have to repeatedly poke offline CPUs: it's the only
 * way to ensure that the CPU doesn't miss the state change before
 * dropping into HYPERVISOR_block().
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/taskq.h>
#include <sys/cmn_err.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/segments.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <sys/hypervisor.h>
#include <sys/xpv_panic.h>
#include <sys/mman.h>
#include <sys/psw.h>
#include <sys/cpu.h>
#include <sys/sunddi.h>
#include <util/sscanf.h>
#include <vm/hat_i86.h>
#include <vm/hat.h>
#include <vm/as.h>

#include <xen/public/io/xs_wire.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/public/vcpu.h>

extern cpuset_t cpu_ready_set;

#define	CPU_PHASE_NONE 0
#define	CPU_PHASE_WAIT_SAFE 1
#define	CPU_PHASE_SAFE 2
#define	CPU_PHASE_POWERED_OFF 3

/*
 * We can only poke CPUs during barrier enter 256 times a second at
 * most.
 */
#define	POKE_TIMEOUT (NANOSEC / 256)

static taskq_t *cpu_config_tq;
static int cpu_phase[NCPU];

static void vcpu_config_event(struct xenbus_watch *, const char **, uint_t);
static int xen_vcpu_initialize(processorid_t, vcpu_guest_context_t *);

/*
 * Return whether or not the vcpu is actually running on a pcpu
 */
int
vcpu_on_pcpu(processorid_t cpu)
{
	struct vcpu_runstate_info runstate;
	int	ret = VCPU_STATE_UNKNOWN;

	ASSERT(cpu < NCPU);
	/*
	 * Don't bother with hypercall if we are asking about ourself
	 */
	if (cpu == CPU->cpu_id)
		return (VCPU_ON_PCPU);
	if (HYPERVISOR_vcpu_op(VCPUOP_get_runstate_info, cpu, &runstate) != 0)
		goto out;

	switch (runstate.state) {
	case RUNSTATE_running:
		ret = VCPU_ON_PCPU;
		break;

	case RUNSTATE_runnable:
	case RUNSTATE_offline:
	case RUNSTATE_blocked:
		ret = VCPU_NOT_ON_PCPU;
		break;

	default:
		break;
	}

out:
	return (ret);
}

/*
 * These routines allocate any global state that might be needed
 * while starting cpus.  For virtual cpus, there is no such state.
 */
int
mach_cpucontext_init(void)
{
	return (0);
}

void
do_cpu_config_watch(int state)
{
	static struct xenbus_watch cpu_config_watch;

	if (state != XENSTORE_UP)
		return;
	cpu_config_watch.node = "cpu";
	cpu_config_watch.callback = vcpu_config_event;
	if (register_xenbus_watch(&cpu_config_watch)) {
		taskq_destroy(cpu_config_tq);
		cmn_err(CE_WARN, "do_cpu_config_watch: "
		    "failed to set vcpu config watch");
	}

}

/*
 * This routine is called after all the "normal" MP startup has
 * been done; a good place to start watching xen store for virtual
 * cpu hot plug events.
 */
void
mach_cpucontext_fini(void)
{

	cpu_config_tq = taskq_create("vcpu config taskq", 1,
	    maxclsyspri - 1, 1, 1, TASKQ_PREPOPULATE);

	(void) xs_register_xenbus_callback(do_cpu_config_watch);
}

/*
 * Fill in the remaining CPU context and initialize it.
 */
static int
mp_set_cpu_context(vcpu_guest_context_t *vgc, cpu_t *cp)
{
	uint_t vec, iopl;

	vgc->flags = VGCF_IN_KERNEL;

	/*
	 * fpu_ctx we leave as zero; on first fault we'll store
	 * sse_initial into it anyway.
	 */

#if defined(__amd64)
	vgc->user_regs.cs = KCS_SEL | SEL_KPL;	/* force to ring 3 */
#else
	vgc->user_regs.cs = KCS_SEL;
#endif
	vgc->user_regs.ds = KDS_SEL;
	vgc->user_regs.es = KDS_SEL;
	vgc->user_regs.ss = KDS_SEL;
	vgc->kernel_ss = KDS_SEL;

	/*
	 * Allow I/O privilege level for Dom0 kernel.
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info))
		iopl = (PS_IOPL & 0x1000); /* ring 1 */
	else
		iopl = 0;

#if defined(__amd64)
	vgc->user_regs.fs = 0;
	vgc->user_regs.gs = 0;
	vgc->user_regs.rflags = F_OFF | iopl;
#elif defined(__i386)
	vgc->user_regs.fs = KFS_SEL;
	vgc->user_regs.gs = KGS_SEL;
	vgc->user_regs.eflags = F_OFF | iopl;
	vgc->event_callback_cs = vgc->user_regs.cs;
	vgc->failsafe_callback_cs = vgc->user_regs.cs;
#endif

	/*
	 * Initialize the trap_info_t from the IDT
	 */
#if !defined(__lint)
	ASSERT(NIDT == sizeof (vgc->trap_ctxt) / sizeof (vgc->trap_ctxt[0]));
#endif
	for (vec = 0; vec < NIDT; vec++) {
		trap_info_t *ti = &vgc->trap_ctxt[vec];

		if (xen_idt_to_trap_info(vec,
		    &cp->cpu_m.mcpu_idt[vec], ti) == 0) {
			ti->cs = KCS_SEL;
			ti->vector = vec;
		}
	}

	/*
	 * No LDT
	 */

	/*
	 * (We assert in various places that the GDT is (a) aligned on a
	 * page boundary and (b) one page long, so this really should fit..)
	 */
#ifdef CRASH_XEN
	vgc->gdt_frames[0] = pa_to_ma(mmu_btop(cp->cpu_m.mcpu_gdtpa));
#else
	vgc->gdt_frames[0] = pfn_to_mfn(mmu_btop(cp->cpu_m.mcpu_gdtpa));
#endif
	vgc->gdt_ents = NGDT;

	vgc->ctrlreg[0] = CR0_ENABLE_FPU_FLAGS(getcr0());

#if defined(__i386)
	if (mmu.pae_hat)
		vgc->ctrlreg[3] =
		    xen_pfn_to_cr3(pfn_to_mfn(kas.a_hat->hat_htable->ht_pfn));
	else
#endif
		vgc->ctrlreg[3] =
		    pa_to_ma(mmu_ptob(kas.a_hat->hat_htable->ht_pfn));

	vgc->ctrlreg[4] = getcr4();

	vgc->event_callback_eip = (uintptr_t)xen_callback;
	vgc->failsafe_callback_eip = (uintptr_t)xen_failsafe_callback;
	vgc->flags |= VGCF_failsafe_disables_events;

#if defined(__amd64)
	/*
	 * XXPV should this be moved to init_cpu_syscall?
	 */
	vgc->syscall_callback_eip = (uintptr_t)sys_syscall;
	vgc->flags |= VGCF_syscall_disables_events;

	ASSERT(vgc->user_regs.gs == 0);
	vgc->gs_base_kernel = (uintptr_t)cp;
#endif

	return (xen_vcpu_initialize(cp->cpu_id, vgc));
}

/*
 * Create a guest virtual cpu context so that the virtual cpu
 * springs into life in the domain just about to call mp_startup()
 *
 * Virtual CPUs must be initialized once in the lifetime of the domain;
 * after that subsequent attempts to start them will fail with X_EEXIST.
 *
 * Thus 'alloc' -really- creates and initializes the virtual
 * CPU context just once. Once the initialisation succeeds, we never
 * free it, nor the regular cpu_t to which it refers.
 */
void *
mach_cpucontext_alloc(struct cpu *cp)
{
	kthread_t *tp = cp->cpu_thread;
	vcpu_guest_context_t vgc;

	int err = 1;

	/*
	 * First, augment the incoming cpu structure
	 * - vcpu pointer reference
	 * - pending event storage area
	 * - physical address of GDT
	 */
	cp->cpu_m.mcpu_vcpu_info =
	    &HYPERVISOR_shared_info->vcpu_info[cp->cpu_id];
	cp->cpu_m.mcpu_evt_pend = kmem_zalloc(
	    sizeof (struct xen_evt_data), KM_SLEEP);
	cp->cpu_m.mcpu_gdtpa =
	    mmu_ptob(hat_getpfnum(kas.a_hat, (caddr_t)cp->cpu_gdt));

	if ((err = xen_gdt_setprot(cp, PROT_READ)) != 0)
		goto done;

	/*
	 * Now set up the vcpu context so that we can start this vcpu
	 * in the kernel at tp->t_pc (mp_startup).  Note that the
	 * thread will thread_exit() shortly after performing the
	 * initialization; in particular, we will *never* take a
	 * privilege transition on this thread.
	 */

	bzero(&vgc, sizeof (vgc));

#ifdef __amd64
	vgc.user_regs.rip = tp->t_pc;
	vgc.user_regs.rsp = tp->t_sp;
	vgc.user_regs.rbp = tp->t_sp - 2 * sizeof (greg_t);
#else
	vgc.user_regs.eip = tp->t_pc;
	vgc.user_regs.esp = tp->t_sp;
	vgc.user_regs.ebp = tp->t_sp - 2 * sizeof (greg_t);
#endif
	/*
	 * XXPV	Fix resume, if Russ didn't already fix it.
	 *
	 * Note that resume unconditionally puts t->t_stk + sizeof (regs)
	 * into kernel_sp via HYPERVISOR_stack_switch. This anticipates
	 * that only lwps take traps that switch to the kernel stack;
	 * part of creating an lwp adjusts the stack by subtracting
	 * sizeof (struct regs) off t_stk.
	 *
	 * The more interesting question is, why do we do all the work
	 * of a fully fledged lwp for a plain thread?  In particular
	 * we don't have to call HYPERVISOR_stack_switch for lwp-less threads
	 * or futz with the LDT.  This should probably all be done with
	 * an lwp context operator to keep pure thread context switch fast.
	 */
	vgc.kernel_sp = (ulong_t)tp->t_stk;

	err = mp_set_cpu_context(&vgc, cp);

done:
	if (err) {
		mach_cpucontext_free(cp, NULL, err);
		return (NULL);
	}
	return (cp);
}

/*
 * By the time we are called either we have successfully started
 * the cpu, or our attempt to start it has failed.
 */

/*ARGSUSED*/
void
mach_cpucontext_free(struct cpu *cp, void *arg, int err)
{
	switch (err) {
	case 0:
		break;
	case ETIMEDOUT:
		/*
		 * The vcpu context is loaded into the hypervisor, and
		 * we've tried to start it, but the vcpu has not been set
		 * running yet, for whatever reason.  We arrange to -not-
		 * free any data structures it may be referencing.  In
		 * particular, we've already told the hypervisor about
		 * the GDT, and so we can't map it read-write again.
		 */
		break;
	default:
		(void) xen_gdt_setprot(cp, PROT_READ | PROT_WRITE);
		kmem_free(cp->cpu_m.mcpu_evt_pend,
		    sizeof (struct xen_evt_data));
		break;
	}
}

/*
 * Reset this CPU's context.  Clear out any pending evtchn data, since event
 * channel numbers will all change when we resume.
 */
void
mach_cpucontext_reset(cpu_t *cp)
{
	bzero(cp->cpu_m.mcpu_evt_pend, sizeof (struct xen_evt_data));
	/* mcpu_intr_pending ? */
}

static void
pcb_to_user_regs(label_t *pcb, vcpu_guest_context_t *vgc)
{
#ifdef __amd64
	vgc->user_regs.rip = pcb->val[REG_LABEL_PC];
	vgc->user_regs.rsp = pcb->val[REG_LABEL_SP];
	vgc->user_regs.rbp = pcb->val[REG_LABEL_BP];
	vgc->user_regs.rbx = pcb->val[REG_LABEL_RBX];
	vgc->user_regs.r12 = pcb->val[REG_LABEL_R12];
	vgc->user_regs.r13 = pcb->val[REG_LABEL_R13];
	vgc->user_regs.r14 = pcb->val[REG_LABEL_R14];
	vgc->user_regs.r15 = pcb->val[REG_LABEL_R15];
#else /* __amd64 */
	vgc->user_regs.eip = pcb->val[REG_LABEL_PC];
	vgc->user_regs.esp = pcb->val[REG_LABEL_SP];
	vgc->user_regs.ebp = pcb->val[REG_LABEL_BP];
	vgc->user_regs.ebx = pcb->val[REG_LABEL_EBX];
	vgc->user_regs.esi = pcb->val[REG_LABEL_ESI];
	vgc->user_regs.edi = pcb->val[REG_LABEL_EDI];
#endif /* __amd64 */
}

/*
 * Restore the context of a CPU during resume.  This context is always
 * inside enter_safe_phase(), below.
 */
void
mach_cpucontext_restore(cpu_t *cp)
{
	vcpu_guest_context_t vgc;
	int err;

	ASSERT(cp->cpu_thread == cp->cpu_pause_thread ||
	    cp->cpu_thread == cp->cpu_idle_thread);

	bzero(&vgc, sizeof (vgc));

	pcb_to_user_regs(&cp->cpu_thread->t_pcb, &vgc);

	/*
	 * We're emulating a longjmp() here: in particular, we need to bump the
	 * stack pointer to account for the pop of xIP that returning from
	 * longjmp() normally would do, and set the return value in xAX to 1.
	 */
#ifdef __amd64
	vgc.user_regs.rax = 1;
	vgc.user_regs.rsp += sizeof (ulong_t);
#else
	vgc.user_regs.eax = 1;
	vgc.user_regs.esp += sizeof (ulong_t);
#endif

	vgc.kernel_sp = cp->cpu_thread->t_sp;

	err = mp_set_cpu_context(&vgc, cp);

	ASSERT(err == 0);
}

/*
 * Reach a point at which the CPU can be safely powered-off or
 * suspended.  Nothing can wake this CPU out of the loop.
 */
static void
enter_safe_phase(void)
{
	ulong_t flags = intr_clear();

	if (setjmp(&curthread->t_pcb) == 0) {
		cpu_phase[CPU->cpu_id] = CPU_PHASE_SAFE;
		while (cpu_phase[CPU->cpu_id] == CPU_PHASE_SAFE)
			SMT_PAUSE();
	}

	ASSERT(!interrupts_enabled());

	intr_restore(flags);
}

/*
 * Offline CPUs run this code even under a pause_cpus(), so we must
 * check if we need to enter the safe phase.
 */
void
mach_cpu_idle(void)
{
	if (IN_XPV_PANIC()) {
		xpv_panic_halt();
	} else  {
		(void) HYPERVISOR_block();
		if (cpu_phase[CPU->cpu_id] == CPU_PHASE_WAIT_SAFE)
			enter_safe_phase();
	}
}

/*
 * Spin until either start_cpus() wakes us up, or we get a request to
 * enter the safe phase (followed by a later start_cpus()).
 */
void
mach_cpu_pause(volatile char *safe)
{
	*safe = PAUSE_WAIT;
	membar_enter();

	while (*safe != PAUSE_IDLE) {
		if (cpu_phase[CPU->cpu_id] == CPU_PHASE_WAIT_SAFE)
			enter_safe_phase();
		SMT_PAUSE();
	}
}

void
mach_cpu_halt(char *msg)
{
	if (msg)
		prom_printf("%s\n", msg);
	(void) xen_vcpu_down(CPU->cpu_id);
}

/*ARGSUSED*/
int
mp_cpu_poweron(struct cpu *cp)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
int
mp_cpu_poweroff(struct cpu *cp)
{
	return (ENOTSUP);
}

void
mp_enter_barrier(void)
{
	hrtime_t last_poke_time = 0;
	int poke_allowed = 0;
	int done = 0;
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	pause_cpus(NULL, NULL);

	while (!done) {
		done = 1;
		poke_allowed = 0;

		if (xpv_gethrtime() - last_poke_time > POKE_TIMEOUT) {
			last_poke_time = xpv_gethrtime();
			poke_allowed = 1;
		}

		for (i = 0; i < NCPU; i++) {
			cpu_t *cp = cpu_get(i);

			if (cp == NULL || cp == CPU)
				continue;

			switch (cpu_phase[i]) {
			case CPU_PHASE_NONE:
				cpu_phase[i] = CPU_PHASE_WAIT_SAFE;
				poke_cpu(i);
				done = 0;
				break;

			case CPU_PHASE_WAIT_SAFE:
				if (poke_allowed)
					poke_cpu(i);
				done = 0;
				break;

			case CPU_PHASE_SAFE:
			case CPU_PHASE_POWERED_OFF:
				break;
			}
		}

		SMT_PAUSE();
	}
}

void
mp_leave_barrier(void)
{
	int i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	for (i = 0; i < NCPU; i++) {
		cpu_t *cp = cpu_get(i);

		if (cp == NULL || cp == CPU)
			continue;

		switch (cpu_phase[i]) {
		/*
		 * If we see a CPU in one of these phases, something has
		 * gone badly wrong with the guarantees
		 * mp_enter_barrier() is supposed to provide.  Rather
		 * than attempt to stumble along (and since we can't
		 * panic properly in this context), we tell the
		 * hypervisor we've crashed.
		 */
		case CPU_PHASE_NONE:
		case CPU_PHASE_WAIT_SAFE:
			(void) HYPERVISOR_shutdown(SHUTDOWN_crash);
			break;

		case CPU_PHASE_POWERED_OFF:
			break;

		case CPU_PHASE_SAFE:
			cpu_phase[i] = CPU_PHASE_NONE;
		}
	}

	start_cpus();
}

static int
poweroff_vcpu(struct cpu *cp)
{
	int error;

	ASSERT(MUTEX_HELD(&cpu_lock));

	ASSERT(CPU->cpu_id != cp->cpu_id);
	ASSERT(cp->cpu_flags & CPU_QUIESCED);

	mp_enter_barrier();

	if ((error = xen_vcpu_down(cp->cpu_id)) == 0) {
		ASSERT(cpu_phase[cp->cpu_id] == CPU_PHASE_SAFE);

		CPUSET_DEL(cpu_ready_set, cp->cpu_id);

		cp->cpu_flags |= CPU_POWEROFF | CPU_OFFLINE;
		cp->cpu_flags &=
		    ~(CPU_RUNNING | CPU_READY | CPU_EXISTS | CPU_ENABLE);

		cpu_phase[cp->cpu_id] = CPU_PHASE_POWERED_OFF;

		cpu_set_state(cp);
	}

	mp_leave_barrier();

	return (error);
}

static int
vcpu_config_poweroff(processorid_t id)
{
	int oldstate;
	int error;
	cpu_t *cp;

	mutex_enter(&cpu_lock);

	if ((cp = cpu_get(id)) == NULL) {
		mutex_exit(&cpu_lock);
		return (ESRCH);
	}

	if (cpu_get_state(cp) == P_POWEROFF) {
		mutex_exit(&cpu_lock);
		return (0);
	}

	mutex_exit(&cpu_lock);

	do {
		error = p_online_internal(id, P_OFFLINE,
		    &oldstate);

		if (error != 0)
			break;

		/*
		 * So we just changed it to P_OFFLINE.  But then we dropped
		 * cpu_lock, so now it is possible for another thread to change
		 * the cpu back to a different, non-quiesced state e.g.
		 * P_ONLINE.
		 */
		mutex_enter(&cpu_lock);
		if ((cp = cpu_get(id)) == NULL)
			error = ESRCH;
		else {
			if (cp->cpu_flags & CPU_QUIESCED)
				error = poweroff_vcpu(cp);
			else
				error = EBUSY;
		}
		mutex_exit(&cpu_lock);
	} while (error == EBUSY);

	return (error);
}

/*
 * Add a new virtual cpu to the domain.
 */
static int
vcpu_config_new(processorid_t id)
{
	extern int start_cpu(processorid_t);
	int error;

	if (ncpus == 1) {
		printf("cannot (yet) add cpus to a single-cpu domain\n");
		return (ENOTSUP);
	}

	affinity_set(CPU_CURRENT);
	error = start_cpu(id);
	affinity_clear();
	return (error);
}

static int
poweron_vcpu(struct cpu *cp)
{
	int error;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (HYPERVISOR_vcpu_op(VCPUOP_is_up, cp->cpu_id, NULL) != 0) {
		printf("poweron_vcpu: vcpu%d is not available!\n",
		    cp->cpu_id);
		return (ENXIO);
	}

	if ((error = xen_vcpu_up(cp->cpu_id)) == 0) {
		CPUSET_ADD(cpu_ready_set, cp->cpu_id);
		cp->cpu_flags |= CPU_EXISTS | CPU_READY | CPU_RUNNING;
		cp->cpu_flags &= ~CPU_POWEROFF;
		/*
		 * There are some nasty races possible here.
		 * Tell the vcpu it's up one more time.
		 * XXPV	Is this enough?  Is this safe?
		 */
		(void) xen_vcpu_up(cp->cpu_id);

		cpu_phase[cp->cpu_id] = CPU_PHASE_NONE;

		cpu_set_state(cp);
	}
	return (error);
}

static int
vcpu_config_poweron(processorid_t id)
{
	cpu_t *cp;
	int oldstate;
	int error;

	if (id >= ncpus)
		return (vcpu_config_new(id));

	mutex_enter(&cpu_lock);

	if ((cp = cpu_get(id)) == NULL) {
		mutex_exit(&cpu_lock);
		return (ESRCH);
	}

	if (cpu_get_state(cp) != P_POWEROFF) {
		mutex_exit(&cpu_lock);
		return (0);
	}

	if ((error = poweron_vcpu(cp)) != 0) {
		mutex_exit(&cpu_lock);
		return (error);
	}

	mutex_exit(&cpu_lock);

	return (p_online_internal(id, P_ONLINE, &oldstate));
}

#define	REPORT_LEN	128

static void
vcpu_config_report(processorid_t id, uint_t newstate, int error)
{
	char *report = kmem_alloc(REPORT_LEN, KM_SLEEP);
	size_t len;
	char *ps;

	switch (newstate) {
	case P_ONLINE:
		ps = PS_ONLINE;
		break;
	case P_POWEROFF:
		ps = PS_POWEROFF;
		break;
	default:
		cmn_err(CE_PANIC, "unknown state %u\n", newstate);
		break;
	}

	len = snprintf(report, REPORT_LEN,
	    "cpu%d: externally initiated %s", id, ps);

	if (!error) {
		cmn_err(CE_CONT, "!%s\n", report);
		kmem_free(report, REPORT_LEN);
		return;
	}

	len += snprintf(report + len, REPORT_LEN - len,
	    " failed, error %d: ", error);
	switch (error) {
	case EEXIST:
		len += snprintf(report + len, REPORT_LEN - len,
		    "cpu already %s", ps ? ps : "?");
		break;
	case ESRCH:
		len += snprintf(report + len, REPORT_LEN - len,
		    "cpu not found");
		break;
	case EINVAL:
	case EALREADY:
		break;
	case EPERM:
		len += snprintf(report + len, REPORT_LEN - len,
		    "insufficient privilege (0x%x)", id);
		break;
	case EBUSY:
		switch (newstate) {
		case P_ONLINE:
			/*
			 * This return comes from mp_cpu_start -
			 * we cannot 'start' the boot CPU.
			 */
			len += snprintf(report + len, REPORT_LEN - len,
			    "already running");
			break;
		case P_POWEROFF:
			len += snprintf(report + len, REPORT_LEN - len,
			    "bound lwps?");
			break;
		default:
			break;
		}
	default:
		break;
	}

	cmn_err(CE_CONT, "%s\n", report);
	kmem_free(report, REPORT_LEN);
}

static void
vcpu_config(void *arg)
{
	int id = (int)(uintptr_t)arg;
	int error;
	char dir[16];
	char *state;

	if ((uint_t)id >= max_ncpus) {
		cmn_err(CE_WARN,
		    "vcpu_config: cpu%d does not fit in this domain", id);
		return;
	}

	(void) snprintf(dir, sizeof (dir), "cpu/%d", id);
	state = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (xenbus_scanf(XBT_NULL, dir, "availability", "%s", state) == 0) {
		if (strcmp(state, "online") == 0) {
			error = vcpu_config_poweron(id);
			vcpu_config_report(id, P_ONLINE, error);
		} else if (strcmp(state, "offline") == 0) {
			error = vcpu_config_poweroff(id);
			vcpu_config_report(id, P_POWEROFF, error);
		} else {
			cmn_err(CE_WARN,
			    "cpu%d: unknown target state '%s'", id, state);
		}
	} else
		cmn_err(CE_WARN,
		    "cpu%d: unable to read target state from xenstore", id);

	kmem_free(state, MAXPATHLEN);
}

/*ARGSUSED*/
static void
vcpu_config_event(struct xenbus_watch *watch, const char **vec, uint_t len)
{
	const char *path = vec[XS_WATCH_PATH];
	processorid_t id;
	char *s;

	if ((s = strstr(path, "cpu/")) != NULL &&
	    sscanf(s, "cpu/%d", &id) == 1) {
		/*
		 * Run the virtual CPU configuration on a separate thread to
		 * avoid blocking on this event for too long (and for now,
		 * to ensure configuration requests are serialized.)
		 */
		(void) taskq_dispatch(cpu_config_tq,
		    vcpu_config, (void *)(uintptr_t)id, 0);
	}
}

static int
xen_vcpu_initialize(processorid_t id, vcpu_guest_context_t *vgc)
{
	int err;

	if ((err = HYPERVISOR_vcpu_op(VCPUOP_initialise, id, vgc)) != 0) {
		char *str;
		int level = CE_WARN;

		switch (err) {
		case -X_EINVAL:
			/*
			 * This interface squashes multiple error sources
			 * to one error code.  In particular, an X_EINVAL
			 * code can mean:
			 *
			 * -	the vcpu id is out of range
			 * -	cs or ss are in ring 0
			 * -	cr3 is wrong
			 * -	an entry in the new gdt is above the
			 *	reserved entry
			 * -	a frame underneath the new gdt is bad
			 */
			str = "something is wrong :(";
			break;
		case -X_ENOENT:
			str = "no such cpu";
			break;
		case -X_ENOMEM:
			str = "no mem to copy ctxt";
			break;
		case -X_EFAULT:
			str = "bad address";
			break;
		case -X_EEXIST:
			/*
			 * Hmm.  This error is returned if the vcpu has already
			 * been initialized once before in the lifetime of this
			 * domain.  This is a logic error in the kernel.
			 */
			level = CE_PANIC;
			str = "already initialized";
			break;
		default:
			level = CE_PANIC;
			str = "<unexpected>";
			break;
		}

		cmn_err(level, "vcpu%d: failed to init: error %d: %s",
		    id, -err, str);
	}
	return (err);
}

long
xen_vcpu_up(processorid_t id)
{
	long err;

	if ((err = HYPERVISOR_vcpu_op(VCPUOP_up, id, NULL)) != 0) {
		char *str;

		switch (err) {
		case -X_ENOENT:
			str = "no such cpu";
			break;
		case -X_EINVAL:
			/*
			 * Perhaps this is diagnostic overkill.
			 */
			if (HYPERVISOR_vcpu_op(VCPUOP_is_up, id, NULL) < 0)
				str = "bad cpuid";
			else
				str = "not initialized";
			break;
		default:
			str = "<unexpected>";
			break;
		}

		printf("vcpu%d: failed to start: error %d: %s\n",
		    id, -(int)err, str);
		return (EBFONT);	/* deliberately silly */
	}
	return (err);
}

long
xen_vcpu_down(processorid_t id)
{
	long err;

	if ((err = HYPERVISOR_vcpu_op(VCPUOP_down, id, NULL)) != 0) {
		/*
		 * X_ENOENT:	no such cpu
		 * X_EINVAL:	bad cpuid
		 */
		panic("vcpu%d: failed to stop: error %d", id, -(int)err);
	}

	return (err);
}
