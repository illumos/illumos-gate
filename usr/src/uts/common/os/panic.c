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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * When the operating system detects that it is in an invalid state, a panic
 * is initiated in order to minimize potential damage to user data and to
 * facilitate debugging.  There are three major tasks to be performed in
 * a system panic: recording information about the panic in memory (and thus
 * making it part of the crash dump), synchronizing the file systems to
 * preserve user file data, and generating the crash dump.  We define the
 * system to be in one of four states with respect to the panic code:
 *
 * CALM    - the state of the system prior to any thread initiating a panic
 *
 * QUIESCE - the state of the system when the first thread to initiate
 *           a system panic records information about the cause of the panic
 *           and renders the system quiescent by stopping other processors
 *
 * SYNC    - the state of the system when we synchronize the file systems
 * DUMP    - the state when we generate the crash dump.
 *
 * The transitions between these states are irreversible: once we begin
 * panicking, we only make one attempt to perform the actions associated with
 * each state.
 *
 * The panic code itself must be re-entrant because actions taken during any
 * state may lead to another system panic.  Additionally, any Solaris
 * thread may initiate a panic at any time, and so we must have synchronization
 * between threads which attempt to initiate a state transition simultaneously.
 * The panic code makes use of a special locking primitive, a trigger, to
 * perform this synchronization.  A trigger is simply a word which is set
 * atomically and can only be set once.  We declare three triggers, one for
 * each transition between the four states.  When a thread enters the panic
 * code it attempts to set each trigger; if it fails it moves on to the
 * next trigger.  A special case is the first trigger: if two threads race
 * to perform the transition to QUIESCE, the losing thread may execute before
 * the winner has a chance to stop its CPU.  To solve this problem, we have
 * the loser look ahead to see if any other triggers are set; if not, it
 * presumes a panic is underway and simply spins.  Unfortunately, since we
 * are panicking, it is not possible to know this with absolute certainty.
 *
 * There are two common reasons for re-entering the panic code once a panic
 * has been initiated: (1) after we debug_enter() at the end of QUIESCE,
 * the operator may type "sync" instead of "go", and the PROM's sync callback
 * routine will invoke panic(); (2) if the clock routine decides that sync
 * or dump is not making progress, it will invoke panic() to force a timeout.
 * The design assumes that a third possibility, another thread causing an
 * unrelated panic while sync or dump is still underway, is extremely unlikely.
 * If this situation occurs, we may end up triggering dump while sync is
 * still in progress.  This third case is considered extremely unlikely because
 * all other CPUs are stopped and low-level interrupts have been blocked.
 *
 * The panic code is entered via a call directly to the vpanic() function,
 * or its varargs wrappers panic() and cmn_err(9F).  The vpanic routine
 * is implemented in assembly language to record the current machine
 * registers, attempt to set the trigger for the QUIESCE state, and
 * if successful, switch stacks on to the panic_stack before calling into
 * the common panicsys() routine.  The first thread to initiate a panic
 * is allowed to make use of the reserved panic_stack so that executing
 * the panic code itself does not overwrite valuable data on that thread's
 * stack *ahead* of the current stack pointer.  This data will be preserved
 * in the crash dump and may prove invaluable in determining what this
 * thread has previously been doing.  The first thread, saved in panic_thread,
 * is also responsible for stopping the other CPUs as quickly as possible,
 * and then setting the various panic_* variables.  Most important among
 * these is panicstr, which allows threads to subsequently bypass held
 * locks so that we can proceed without ever blocking.  We must stop the
 * other CPUs *prior* to setting panicstr in case threads running there are
 * currently spinning to acquire a lock; we want that state to be preserved.
 * Every thread which initiates a panic has its T_PANIC flag set so we can
 * identify all such threads in the crash dump.
 *
 * The panic_thread is also allowed to make use of the special memory buffer
 * panicbuf, which on machines with appropriate hardware is preserved across
 * reboots.  We allow the panic_thread to store its register set and panic
 * message in this buffer, so even if we fail to obtain a crash dump we will
 * be able to examine the machine after reboot and determine some of the
 * state at the time of the panic.  If we do get a dump, the panic buffer
 * data is structured so that a debugger can easily consume the information
 * therein (see <sys/panic.h>).
 *
 * Each platform or architecture is required to implement the functions
 * panic_savetrap() to record trap-specific information to panicbuf,
 * panic_saveregs() to record a register set to panicbuf, panic_stopcpus()
 * to halt all CPUs but the panicking CPU, panic_quiesce_hw() to perform
 * miscellaneous platform-specific tasks *after* panicstr is set,
 * panic_showtrap() to print trap-specific information to the console,
 * and panic_dump_hw() to perform platform tasks prior to calling dumpsys().
 *
 * A Note on Word Formation, courtesy of the Oxford Guide to English Usage:
 *
 * Words ending in -c interpose k before suffixes which otherwise would
 * indicate a soft c, and thus the verb and adjective forms of 'panic' are
 * spelled "panicked", "panicking", and "panicky" respectively.  Use of
 * the ill-conceived "panicing" and "panic'd" is discouraged.
 */

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/t_lock.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/uadmin.h>
#include <sys/callb.h>
#include <sys/vfs.h>
#include <sys/log.h>
#include <sys/disp.h>
#include <sys/param.h>
#include <sys/dumphdr.h>
#include <sys/ftrace.h>
#include <sys/reboot.h>
#include <sys/debug.h>
#include <sys/stack.h>
#include <sys/spl.h>
#include <sys/errorq.h>
#include <sys/panic.h>
#include <sys/fm/util.h>
#include <sys/clock_impl.h>

/*
 * Panic variables which are set once during the QUIESCE state by the
 * first thread to initiate a panic.  These are examined by post-mortem
 * debugging tools; the inconsistent use of 'panic' versus 'panic_' in
 * the variable naming is historical and allows legacy tools to work.
 */
#pragma align STACK_ALIGN(panic_stack)
char panic_stack[PANICSTKSIZE];		/* reserved stack for panic_thread */
kthread_t *panic_thread;		/* first thread to call panicsys() */
cpu_t panic_cpu;			/* cpu from first call to panicsys() */
label_t panic_regs;			/* setjmp label from panic_thread */
label_t panic_pcb;			/* t_pcb at time of panic */
struct regs *panic_reg;			/* regs struct from first panicsys() */
char *volatile panicstr;		/* format string to first panicsys() */
va_list panicargs;			/* arguments to first panicsys() */
clock_t panic_lbolt;			/* lbolt at time of panic */
int64_t panic_lbolt64;			/* lbolt64 at time of panic */
hrtime_t panic_hrtime;			/* hrtime at time of panic */
timespec_t panic_hrestime;		/* hrestime at time of panic */
int panic_ipl;				/* ipl on panic_cpu at time of panic */
ushort_t panic_schedflag;		/* t_schedflag for panic_thread */
cpu_t *panic_bound_cpu;			/* t_bound_cpu for panic_thread */
char panic_preempt;			/* t_preempt for panic_thread */

/*
 * Panic variables which can be set via /etc/system or patched while
 * the system is in operation.  Again, the stupid names are historic.
 */
char *panic_bootstr = NULL;		/* mdboot string to use after panic */
int panic_bootfcn = AD_BOOT;		/* mdboot function to use after panic */
int halt_on_panic = 0;  		/* halt after dump instead of reboot? */
int nopanicdebug = 0;			/* reboot instead of call debugger? */
int in_sync = 0;			/* skip vfs_syncall() and just dump? */

/*
 * The do_polled_io flag is set by the panic code to inform the SCSI subsystem
 * to use polled mode instead of interrupt-driven i/o.
 */
int do_polled_io = 0;

/*
 * The panic_forced flag is set by the uadmin A_DUMP code to inform the
 * panic subsystem that it should not attempt an initial debug_enter.
 */
int panic_forced = 0;

/*
 * Triggers for panic state transitions:
 */
int panic_quiesce;			/* trigger for CALM    -> QUIESCE */
int panic_dump;				/* trigger for QUIESCE    -> DUMP */

/*
 * Variable signifying quiesce(9E) is in progress.
 */
volatile int quiesce_active = 0;

void
panicsys(const char *format, va_list alist, struct regs *rp, int on_panic_stack)
{
	int s = spl8();
	kthread_t *t = curthread;
	cpu_t *cp = CPU;

	caddr_t intr_stack = NULL;
	uint_t intr_actv;

	ushort_t schedflag = t->t_schedflag;
	cpu_t *bound_cpu = t->t_bound_cpu;
	char preempt = t->t_preempt;
	label_t pcb = t->t_pcb;

	(void) setjmp(&t->t_pcb);
	t->t_flag |= T_PANIC;

	t->t_schedflag |= TS_DONT_SWAP;
	t->t_bound_cpu = cp;
	t->t_preempt++;

	panic_enter_hw(s);

	/*
	 * If we're on the interrupt stack and an interrupt thread is available
	 * in this CPU's pool, preserve the interrupt stack by detaching an
	 * interrupt thread and making its stack the intr_stack.
	 */
	if (CPU_ON_INTR(cp) && cp->cpu_intr_thread != NULL) {
		kthread_t *it = cp->cpu_intr_thread;

		intr_stack = cp->cpu_intr_stack;
		intr_actv = cp->cpu_intr_actv;

		cp->cpu_intr_stack = thread_stk_init(it->t_stk);
		cp->cpu_intr_thread = it->t_link;

		/*
		 * Clear only the high level bits of cpu_intr_actv.
		 * We want to indicate that high-level interrupts are
		 * not active without destroying the low-level interrupt
		 * information stored there.
		 */
		cp->cpu_intr_actv &= ((1 << (LOCK_LEVEL + 1)) - 1);
	}

	/*
	 * Record one-time panic information and quiesce the other CPUs.
	 * Then print out the panic message and stack trace.
	 */
	if (on_panic_stack) {
		panic_data_t *pdp = (panic_data_t *)panicbuf;

		pdp->pd_version = PANICBUFVERS;
		pdp->pd_msgoff = sizeof (panic_data_t) - sizeof (panic_nv_t);

		(void) strncpy(pdp->pd_uuid, dump_get_uuid(),
		    sizeof (pdp->pd_uuid));

		if (t->t_panic_trap != NULL)
			panic_savetrap(pdp, t->t_panic_trap);
		else
			panic_saveregs(pdp, rp);

		(void) vsnprintf(&panicbuf[pdp->pd_msgoff],
		    PANICBUFSIZE - pdp->pd_msgoff, format, alist);

		/*
		 * Call into the platform code to stop the other CPUs.
		 * We currently have all interrupts blocked, and expect that
		 * the platform code will lower ipl only as far as needed to
		 * perform cross-calls, and will acquire as *few* locks as is
		 * possible -- panicstr is not set so we can still deadlock.
		 */
		panic_stopcpus(cp, t, s);

		panicstr = (char *)format;
		va_copy(panicargs, alist);
		panic_lbolt = LBOLT_NO_ACCOUNT;
		panic_lbolt64 = LBOLT_NO_ACCOUNT64;
		panic_hrestime = hrestime;
		panic_hrtime = gethrtime_waitfree();
		panic_thread = t;
		panic_regs = t->t_pcb;
		panic_reg = rp;
		panic_cpu = *cp;
		panic_ipl = spltoipl(s);
		panic_schedflag = schedflag;
		panic_bound_cpu = bound_cpu;
		panic_preempt = preempt;
		panic_pcb = pcb;

		if (intr_stack != NULL) {
			panic_cpu.cpu_intr_stack = intr_stack;
			panic_cpu.cpu_intr_actv = intr_actv;
		}

		/*
		 * Lower ipl to 10 to keep clock() from running, but allow
		 * keyboard interrupts to enter the debugger.  These callbacks
		 * are executed with panicstr set so they can bypass locks.
		 */
		splx(ipltospl(CLOCK_LEVEL));
		panic_quiesce_hw(pdp);
		(void) FTRACE_STOP();
		(void) callb_execute_class(CB_CL_PANIC, NULL);

		if (log_intrq != NULL)
			log_flushq(log_intrq);

		/*
		 * If log_consq has been initialized and syslogd has started,
		 * print any messages in log_consq that haven't been consumed.
		 */
		if (log_consq != NULL && log_consq != log_backlogq)
			log_printq(log_consq);

		fm_banner();

#if defined(__x86)
		/*
		 * A hypervisor panic originates outside of Solaris, so we
		 * don't want to prepend the panic message with misleading
		 * pointers from within Solaris.
		 */
		if (!IN_XPV_PANIC())
#endif
			printf("\n\rpanic[cpu%d]/thread=%p: ", cp->cpu_id,
			    (void *)t);
		vprintf(format, alist);
		printf("\n\n");

		if (t->t_panic_trap != NULL) {
			panic_showtrap(t->t_panic_trap);
			printf("\n");
		}

		traceregs(rp);
		printf("\n");

		if (((boothowto & RB_DEBUG) || obpdebug) &&
		    !nopanicdebug && !panic_forced) {
			if (dumpvp != NULL) {
				debug_enter("panic: entering debugger "
				    "(continue to save dump)");
			} else {
				debug_enter("panic: entering debugger "
				    "(no dump device, continue to reboot)");
			}
		}

	} else if (panic_dump != 0 || panicstr != NULL) {
		printf("\n\rpanic[cpu%d]/thread=%p: ", cp->cpu_id, (void *)t);
		vprintf(format, alist);
		printf("\n");
	} else
		goto spin;

	/*
	 * Prior to performing dump, we make sure that do_polled_io is
	 * set, but we'll leave ipl at 10; deadman(), a CY_HIGH_LEVEL cyclic,
	 * will re-enter panic if we are not making progress with dump.
	 */
	/*
	 * Take the crash dump.  If the dump trigger is already set, try to
	 * enter the debugger again before rebooting the system.
	 */
	if (panic_trigger(&panic_dump)) {
		panic_dump_hw(s);
		splx(ipltospl(CLOCK_LEVEL));
		errorq_panic();
		do_polled_io = 1;
		dumpsys();
	} else if (((boothowto & RB_DEBUG) || obpdebug) && !nopanicdebug) {
		debug_enter("panic: entering debugger (continue to reboot)");
	} else
		printf("dump aborted: please record the above information!\n");

	if (halt_on_panic)
		mdboot(A_REBOOT, AD_HALT, NULL, B_FALSE);
	else
		mdboot(A_REBOOT, panic_bootfcn, panic_bootstr, B_FALSE);
spin:
	/*
	 * Restore ipl to at most CLOCK_LEVEL so we don't end up spinning
	 * and unable to jump into the debugger.
	 */
	splx(MIN(s, ipltospl(CLOCK_LEVEL)));
	for (;;)
		;
}

void
panic(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vpanic(format, alist);
	va_end(alist);
}
