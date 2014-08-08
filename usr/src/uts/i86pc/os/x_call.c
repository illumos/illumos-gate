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
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <sys/xc_levels.h>
#include <sys/cpu.h>
#include <sys/psw.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/mutex_impl.h>
#include <sys/stack.h>
#include <sys/promif.h>
#include <sys/x86_archext.h>

/*
 * Implementation for cross-processor calls via interprocessor interrupts
 *
 * This implementation uses a message passing architecture to allow multiple
 * concurrent cross calls to be in flight at any given time. We use the cmpxchg
 * instruction, aka atomic_cas_ptr(), to implement simple efficient work
 * queues for message passing between CPUs with almost no need for regular
 * locking.  See xc_extract() and xc_insert() below.
 *
 * The general idea is that initiating a cross call means putting a message
 * on a target(s) CPU's work queue. Any synchronization is handled by passing
 * the message back and forth between initiator and target(s).
 *
 * Every CPU has xc_work_cnt, which indicates it has messages to process.
 * This value is incremented as message traffic is initiated and decremented
 * with every message that finishes all processing.
 *
 * The code needs no mfence or other membar_*() calls. The uses of
 * atomic_cas_ptr(), atomic_cas_32() and atomic_dec_32() for the message
 * passing are implemented with LOCK prefix instructions which are
 * equivalent to mfence.
 *
 * One interesting aspect of this implmentation is that it allows 2 or more
 * CPUs to initiate cross calls to intersecting sets of CPUs at the same time.
 * The cross call processing by the CPUs will happen in any order with only
 * a guarantee, for xc_call() and xc_sync(), that an initiator won't return
 * from cross calls before all slaves have invoked the function.
 *
 * The reason for this asynchronous approach is to allow for fast global
 * TLB shootdowns. If all CPUs, say N, tried to do a global TLB invalidation
 * on a different Virtual Address at the same time. The old code required
 * N squared IPIs. With this method, depending on timing, it could happen
 * with just N IPIs.
 */

/*
 * The default is to not enable collecting counts of IPI information, since
 * the updating of shared cachelines could cause excess bus traffic.
 */
uint_t xc_collect_enable = 0;
uint64_t xc_total_cnt = 0;	/* total #IPIs sent for cross calls */
uint64_t xc_multi_cnt = 0;	/* # times we piggy backed on another IPI */

/*
 * Values for message states. Here are the normal transitions. A transition
 * of "->" happens in the slave cpu and "=>" happens in the master cpu as
 * the messages are passed back and forth.
 *
 * FREE => ASYNC ->                       DONE => FREE
 * FREE => CALL ->                        DONE => FREE
 * FREE => SYNC -> WAITING => RELEASED -> DONE => FREE
 *
 * The interesing one above is ASYNC. You might ask, why not go directly
 * to FREE, instead of DONE. If it did that, it might be possible to exhaust
 * the master's xc_free list if a master can generate ASYNC messages faster
 * then the slave can process them. That could be handled with more complicated
 * handling. However since nothing important uses ASYNC, I've not bothered.
 */
#define	XC_MSG_FREE	(0)	/* msg in xc_free queue */
#define	XC_MSG_ASYNC	(1)	/* msg in slave xc_msgbox */
#define	XC_MSG_CALL	(2)	/* msg in slave xc_msgbox */
#define	XC_MSG_SYNC	(3)	/* msg in slave xc_msgbox */
#define	XC_MSG_WAITING	(4)	/* msg in master xc_msgbox or xc_waiters */
#define	XC_MSG_RELEASED	(5)	/* msg in slave xc_msgbox */
#define	XC_MSG_DONE	(6)	/* msg in master xc_msgbox */

/*
 * We allow for one high priority message at a time to happen in the system.
 * This is used for panic, kmdb, etc., so no locking is done.
 */
static volatile cpuset_t xc_priority_set_store;
static volatile ulong_t *xc_priority_set = CPUSET2BV(xc_priority_set_store);
static xc_data_t xc_priority_data;

/*
 * Wrappers to avoid C compiler warnings due to volatile. The atomic bit
 * operations don't accept volatile bit vectors - which is a bit silly.
 */
#define	XC_BT_SET(vector, b)	BT_ATOMIC_SET((ulong_t *)(vector), (b))
#define	XC_BT_CLEAR(vector, b)	BT_ATOMIC_CLEAR((ulong_t *)(vector), (b))

/*
 * Decrement a CPU's work count
 */
static void
xc_decrement(struct machcpu *mcpu)
{
	atomic_dec_32(&mcpu->xc_work_cnt);
}

/*
 * Increment a CPU's work count and return the old value
 */
static int
xc_increment(struct machcpu *mcpu)
{
	int old;
	do {
		old = mcpu->xc_work_cnt;
	} while (atomic_cas_32(&mcpu->xc_work_cnt, old, old + 1) != old);
	return (old);
}

/*
 * Put a message into a queue. The insertion is atomic no matter
 * how many different inserts/extracts to the same queue happen.
 */
static void
xc_insert(void *queue, xc_msg_t *msg)
{
	xc_msg_t *old_head;

	/*
	 * FREE messages should only ever be getting inserted into
	 * the xc_master CPUs xc_free queue.
	 */
	ASSERT(msg->xc_command != XC_MSG_FREE ||
	    cpu[msg->xc_master] == NULL || /* possible only during init */
	    queue == &cpu[msg->xc_master]->cpu_m.xc_free);

	do {
		old_head = (xc_msg_t *)*(volatile xc_msg_t **)queue;
		msg->xc_next = old_head;
	} while (atomic_cas_ptr(queue, old_head, msg) != old_head);
}

/*
 * Extract a message from a queue. The extraction is atomic only
 * when just one thread does extractions from the queue.
 * If the queue is empty, NULL is returned.
 */
static xc_msg_t *
xc_extract(xc_msg_t **queue)
{
	xc_msg_t *old_head;

	do {
		old_head = (xc_msg_t *)*(volatile xc_msg_t **)queue;
		if (old_head == NULL)
			return (old_head);
	} while (atomic_cas_ptr(queue, old_head, old_head->xc_next) !=
	    old_head);
	old_head->xc_next = NULL;
	return (old_head);
}

/*
 * Initialize the machcpu fields used for cross calls
 */
static uint_t xc_initialized = 0;

void
xc_init_cpu(struct cpu *cpup)
{
	xc_msg_t *msg;
	int c;

	/*
	 * Allocate message buffers for the new CPU.
	 */
	for (c = 0; c < max_ncpus; ++c) {
		if (plat_dr_support_cpu()) {
			/*
			 * Allocate a message buffer for every CPU possible
			 * in system, including our own, and add them to our xc
			 * message queue.
			 */
			msg = kmem_zalloc(sizeof (*msg), KM_SLEEP);
			msg->xc_command = XC_MSG_FREE;
			msg->xc_master = cpup->cpu_id;
			xc_insert(&cpup->cpu_m.xc_free, msg);
		} else if (cpu[c] != NULL && cpu[c] != cpup) {
			/*
			 * Add a new message buffer to each existing CPU's free
			 * list, as well as one for my list for each of them.
			 * Note: cpu0 is statically inserted into cpu[] array,
			 * so need to check cpu[c] isn't cpup itself to avoid
			 * allocating extra message buffers for cpu0.
			 */
			msg = kmem_zalloc(sizeof (*msg), KM_SLEEP);
			msg->xc_command = XC_MSG_FREE;
			msg->xc_master = c;
			xc_insert(&cpu[c]->cpu_m.xc_free, msg);

			msg = kmem_zalloc(sizeof (*msg), KM_SLEEP);
			msg->xc_command = XC_MSG_FREE;
			msg->xc_master = cpup->cpu_id;
			xc_insert(&cpup->cpu_m.xc_free, msg);
		}
	}

	if (!plat_dr_support_cpu()) {
		/*
		 * Add one for self messages if CPU hotplug is disabled.
		 */
		msg = kmem_zalloc(sizeof (*msg), KM_SLEEP);
		msg->xc_command = XC_MSG_FREE;
		msg->xc_master = cpup->cpu_id;
		xc_insert(&cpup->cpu_m.xc_free, msg);
	}

	if (!xc_initialized)
		xc_initialized = 1;
}

void
xc_fini_cpu(struct cpu *cpup)
{
	xc_msg_t *msg;

	ASSERT((cpup->cpu_flags & CPU_READY) == 0);
	ASSERT(cpup->cpu_m.xc_msgbox == NULL);
	ASSERT(cpup->cpu_m.xc_work_cnt == 0);

	while ((msg = xc_extract(&cpup->cpu_m.xc_free)) != NULL) {
		kmem_free(msg, sizeof (*msg));
	}
}

#define	XC_FLUSH_MAX_WAITS		1000

/* Flush inflight message buffers. */
int
xc_flush_cpu(struct cpu *cpup)
{
	int i;

	ASSERT((cpup->cpu_flags & CPU_READY) == 0);

	/*
	 * Pause all working CPUs, which ensures that there's no CPU in
	 * function xc_common().
	 * This is used to work around a race condition window in xc_common()
	 * between checking CPU_READY flag and increasing working item count.
	 */
	pause_cpus(cpup);
	start_cpus();

	for (i = 0; i < XC_FLUSH_MAX_WAITS; i++) {
		if (cpup->cpu_m.xc_work_cnt == 0) {
			break;
		}
		DELAY(1);
	}
	for (; i < XC_FLUSH_MAX_WAITS; i++) {
		if (!BT_TEST(xc_priority_set, cpup->cpu_id)) {
			break;
		}
		DELAY(1);
	}

	return (i >= XC_FLUSH_MAX_WAITS ? ETIME : 0);
}

/*
 * X-call message processing routine. Note that this is used by both
 * senders and recipients of messages.
 *
 * We're protected against changing CPUs by either being in a high-priority
 * interrupt, having preemption disabled or by having a raised SPL.
 */
/*ARGSUSED*/
uint_t
xc_serv(caddr_t arg1, caddr_t arg2)
{
	struct machcpu *mcpup = &(CPU->cpu_m);
	xc_msg_t *msg;
	xc_data_t *data;
	xc_msg_t *xc_waiters = NULL;
	uint32_t num_waiting = 0;
	xc_func_t func;
	xc_arg_t a1;
	xc_arg_t a2;
	xc_arg_t a3;
	uint_t rc = DDI_INTR_UNCLAIMED;

	while (mcpup->xc_work_cnt != 0) {
		rc = DDI_INTR_CLAIMED;

		/*
		 * We may have to wait for a message to arrive.
		 */
		for (msg = NULL; msg == NULL;
		    msg = xc_extract(&mcpup->xc_msgbox)) {

			/*
			 * Alway check for and handle a priority message.
			 */
			if (BT_TEST(xc_priority_set, CPU->cpu_id)) {
				func = xc_priority_data.xc_func;
				a1 = xc_priority_data.xc_a1;
				a2 = xc_priority_data.xc_a2;
				a3 = xc_priority_data.xc_a3;
				XC_BT_CLEAR(xc_priority_set, CPU->cpu_id);
				xc_decrement(mcpup);
				func(a1, a2, a3);
				if (mcpup->xc_work_cnt == 0)
					return (rc);
			}

			/*
			 * wait for a message to arrive
			 */
			SMT_PAUSE();
		}


		/*
		 * process the message
		 */
		switch (msg->xc_command) {

		/*
		 * ASYNC gives back the message immediately, then we do the
		 * function and return with no more waiting.
		 */
		case XC_MSG_ASYNC:
			data = &cpu[msg->xc_master]->cpu_m.xc_data;
			func = data->xc_func;
			a1 = data->xc_a1;
			a2 = data->xc_a2;
			a3 = data->xc_a3;
			msg->xc_command = XC_MSG_DONE;
			xc_insert(&cpu[msg->xc_master]->cpu_m.xc_msgbox, msg);
			if (func != NULL)
				(void) (*func)(a1, a2, a3);
			xc_decrement(mcpup);
			break;

		/*
		 * SYNC messages do the call, then send it back to the master
		 * in WAITING mode
		 */
		case XC_MSG_SYNC:
			data = &cpu[msg->xc_master]->cpu_m.xc_data;
			if (data->xc_func != NULL)
				(void) (*data->xc_func)(data->xc_a1,
				    data->xc_a2, data->xc_a3);
			msg->xc_command = XC_MSG_WAITING;
			xc_insert(&cpu[msg->xc_master]->cpu_m.xc_msgbox, msg);
			break;

		/*
		 * WAITING messsages are collected by the master until all
		 * have arrived. Once all arrive, we release them back to
		 * the slaves
		 */
		case XC_MSG_WAITING:
			xc_insert(&xc_waiters, msg);
			if (++num_waiting < mcpup->xc_wait_cnt)
				break;
			while ((msg = xc_extract(&xc_waiters)) != NULL) {
				msg->xc_command = XC_MSG_RELEASED;
				xc_insert(&cpu[msg->xc_slave]->cpu_m.xc_msgbox,
				    msg);
				--num_waiting;
			}
			if (num_waiting != 0)
				panic("wrong number waiting");
			mcpup->xc_wait_cnt = 0;
			break;

		/*
		 * CALL messages do the function and then, like RELEASE,
		 * send the message is back to master as DONE.
		 */
		case XC_MSG_CALL:
			data = &cpu[msg->xc_master]->cpu_m.xc_data;
			if (data->xc_func != NULL)
				(void) (*data->xc_func)(data->xc_a1,
				    data->xc_a2, data->xc_a3);
			/*FALLTHROUGH*/
		case XC_MSG_RELEASED:
			msg->xc_command = XC_MSG_DONE;
			xc_insert(&cpu[msg->xc_master]->cpu_m.xc_msgbox, msg);
			xc_decrement(mcpup);
			break;

		/*
		 * DONE means a slave has completely finished up.
		 * Once we collect all the DONE messages, we'll exit
		 * processing too.
		 */
		case XC_MSG_DONE:
			msg->xc_command = XC_MSG_FREE;
			xc_insert(&mcpup->xc_free, msg);
			xc_decrement(mcpup);
			break;

		case XC_MSG_FREE:
			panic("free message 0x%p in msgbox", (void *)msg);
			break;

		default:
			panic("bad message 0x%p in msgbox", (void *)msg);
			break;
		}
	}
	return (rc);
}

/*
 * Initiate cross call processing.
 */
static void
xc_common(
	xc_func_t func,
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	ulong_t *set,
	uint_t command)
{
	int c;
	struct cpu *cpup;
	xc_msg_t *msg;
	xc_data_t *data;
	int cnt;
	int save_spl;

	if (!xc_initialized) {
		if (BT_TEST(set, CPU->cpu_id) && (CPU->cpu_flags & CPU_READY) &&
		    func != NULL)
			(void) (*func)(arg1, arg2, arg3);
		return;
	}

	save_spl = splr(ipltospl(XC_HI_PIL));

	/*
	 * fill in cross call data
	 */
	data = &CPU->cpu_m.xc_data;
	data->xc_func = func;
	data->xc_a1 = arg1;
	data->xc_a2 = arg2;
	data->xc_a3 = arg3;

	/*
	 * Post messages to all CPUs involved that are CPU_READY
	 */
	CPU->cpu_m.xc_wait_cnt = 0;
	for (c = 0; c < max_ncpus; ++c) {
		if (!BT_TEST(set, c))
			continue;
		cpup = cpu[c];
		if (cpup == NULL || !(cpup->cpu_flags & CPU_READY))
			continue;

		/*
		 * Fill out a new message.
		 */
		msg = xc_extract(&CPU->cpu_m.xc_free);
		if (msg == NULL)
			panic("Ran out of free xc_msg_t's");
		msg->xc_command = command;
		if (msg->xc_master != CPU->cpu_id)
			panic("msg %p has wrong xc_master", (void *)msg);
		msg->xc_slave = c;

		/*
		 * Increment my work count for all messages that I'll
		 * transition from DONE to FREE.
		 * Also remember how many XC_MSG_WAITINGs to look for
		 */
		(void) xc_increment(&CPU->cpu_m);
		if (command == XC_MSG_SYNC)
			++CPU->cpu_m.xc_wait_cnt;

		/*
		 * Increment the target CPU work count then insert the message
		 * in the target msgbox. If I post the first bit of work
		 * for the target to do, send an IPI to the target CPU.
		 */
		cnt = xc_increment(&cpup->cpu_m);
		xc_insert(&cpup->cpu_m.xc_msgbox, msg);
		if (cpup != CPU) {
			if (cnt == 0) {
				CPU_STATS_ADDQ(CPU, sys, xcalls, 1);
				send_dirint(c, XC_HI_PIL);
				if (xc_collect_enable)
					++xc_total_cnt;
			} else if (xc_collect_enable) {
				++xc_multi_cnt;
			}
		}
	}

	/*
	 * Now drop into the message handler until all work is done
	 */
	(void) xc_serv(NULL, NULL);
	splx(save_spl);
}

/*
 * Push out a priority cross call.
 */
static void
xc_priority_common(
	xc_func_t func,
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	ulong_t *set)
{
	int i;
	int c;
	struct cpu *cpup;

	/*
	 * Wait briefly for any previous xc_priority to have finished.
	 */
	for (c = 0; c < max_ncpus; ++c) {
		cpup = cpu[c];
		if (cpup == NULL || !(cpup->cpu_flags & CPU_READY))
			continue;

		/*
		 * The value of 40000 here is from old kernel code. It
		 * really should be changed to some time based value, since
		 * under a hypervisor, there's no guarantee a remote CPU
		 * is even scheduled.
		 */
		for (i = 0; BT_TEST(xc_priority_set, c) && i < 40000; ++i)
			SMT_PAUSE();

		/*
		 * Some CPU did not respond to a previous priority request. It's
		 * probably deadlocked with interrupts blocked or some such
		 * problem. We'll just erase the previous request - which was
		 * most likely a kmdb_enter that has already expired - and plow
		 * ahead.
		 */
		if (BT_TEST(xc_priority_set, c)) {
			XC_BT_CLEAR(xc_priority_set, c);
			if (cpup->cpu_m.xc_work_cnt > 0)
				xc_decrement(&cpup->cpu_m);
		}
	}

	/*
	 * fill in cross call data
	 */
	xc_priority_data.xc_func = func;
	xc_priority_data.xc_a1 = arg1;
	xc_priority_data.xc_a2 = arg2;
	xc_priority_data.xc_a3 = arg3;

	/*
	 * Post messages to all CPUs involved that are CPU_READY
	 * We'll always IPI, plus bang on the xc_msgbox for i86_mwait()
	 */
	for (c = 0; c < max_ncpus; ++c) {
		if (!BT_TEST(set, c))
			continue;
		cpup = cpu[c];
		if (cpup == NULL || !(cpup->cpu_flags & CPU_READY) ||
		    cpup == CPU)
			continue;
		(void) xc_increment(&cpup->cpu_m);
		XC_BT_SET(xc_priority_set, c);
		send_dirint(c, XC_HI_PIL);
		for (i = 0; i < 10; ++i) {
			(void) atomic_cas_ptr(&cpup->cpu_m.xc_msgbox,
			    cpup->cpu_m.xc_msgbox, cpup->cpu_m.xc_msgbox);
		}
	}
}

/*
 * Do cross call to all other CPUs with absolutely no waiting or handshaking.
 * This should only be used for extraordinary operations, like panic(), which
 * need to work, in some fashion, in a not completely functional system.
 * All other uses that want minimal waiting should use xc_call_nowait().
 */
void
xc_priority(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	ulong_t *set,
	xc_func_t func)
{
	extern int IGNORE_KERNEL_PREEMPTION;
	int save_spl = splr(ipltospl(XC_HI_PIL));
	int save_kernel_preemption = IGNORE_KERNEL_PREEMPTION;

	IGNORE_KERNEL_PREEMPTION = 1;
	xc_priority_common((xc_func_t)func, arg1, arg2, arg3, set);
	IGNORE_KERNEL_PREEMPTION = save_kernel_preemption;
	splx(save_spl);
}

/*
 * Wrapper for kmdb to capture other CPUs, causing them to enter the debugger.
 */
void
kdi_xc_others(int this_cpu, void (*func)(void))
{
	extern int IGNORE_KERNEL_PREEMPTION;
	int save_kernel_preemption;
	cpuset_t set;

	if (!xc_initialized)
		return;

	save_kernel_preemption = IGNORE_KERNEL_PREEMPTION;
	IGNORE_KERNEL_PREEMPTION = 1;
	CPUSET_ALL_BUT(set, this_cpu);
	xc_priority_common((xc_func_t)func, 0, 0, 0, CPUSET2BV(set));
	IGNORE_KERNEL_PREEMPTION = save_kernel_preemption;
}



/*
 * Invoke function on specified processors. Remotes may continue after
 * service with no waiting. xc_call_nowait() may return immediately too.
 */
void
xc_call_nowait(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	ulong_t *set,
	xc_func_t func)
{
	xc_common(func, arg1, arg2, arg3, set, XC_MSG_ASYNC);
}

/*
 * Invoke function on specified processors. Remotes may continue after
 * service with no waiting. xc_call() returns only after remotes have finished.
 */
void
xc_call(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	ulong_t *set,
	xc_func_t func)
{
	xc_common(func, arg1, arg2, arg3, set, XC_MSG_CALL);
}

/*
 * Invoke function on specified processors. Remotes wait until all have
 * finished. xc_sync() also waits until all remotes have finished.
 */
void
xc_sync(
	xc_arg_t arg1,
	xc_arg_t arg2,
	xc_arg_t arg3,
	ulong_t *set,
	xc_func_t func)
{
	xc_common(func, arg1, arg2, arg3, set, XC_MSG_SYNC);
}
