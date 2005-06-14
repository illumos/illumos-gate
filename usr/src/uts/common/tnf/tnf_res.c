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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * "Resident" part of TNF -- this has to be around even when the
 * driver is not loaded.
 */

#ifndef NPROBE
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/klwp.h>
#include <sys/proc.h>
#include <sys/kmem.h>
#include <sys/msacct.h>
#include <sys/tnf_com.h>
#include <sys/tnf_writer.h>
#include <sys/tnf_probe.h>
#include <sys/tnf.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/kobj.h>

#include "tnf_buf.h"
#include "tnf_types.h"
#include "tnf_trace.h"

/*
 * Defines
 */

#define	TNF_PC_COUNT	8

/*
 * Declarations
 */

/*
 * TNF kernel probe management externs
 */
extern tnf_probe_control_t	*__tnf_probe_list_head;
extern tnf_tag_data_t		*__tnf_tag_list_head;
extern int			tnf_changed_probe_list;

/*
 * This makes the state of the TNFW_B_STOPPED bit externally visible
 * in the kernel.
 */
volatile int tnf_tracing_active = 0;

/*
 * The trace buffer pointer
 */
caddr_t tnf_buf;

/*
 * Stub definitions for tag data pointers
 */

/* tnf_writer module */
tnf_tag_data_t *tnf_inline_tag_data = NULL;
tnf_tag_data_t *tnf_tagged_tag_data = NULL;
tnf_tag_data_t *tnf_scalar_tag_data = NULL;
tnf_tag_data_t *tnf_char_tag_data = NULL;
tnf_tag_data_t *tnf_int8_tag_data = NULL;
tnf_tag_data_t *tnf_uint8_tag_data = NULL;
tnf_tag_data_t *tnf_int16_tag_data = NULL;
tnf_tag_data_t *tnf_uint16_tag_data = NULL;
tnf_tag_data_t *tnf_int32_tag_data = NULL;
tnf_tag_data_t *tnf_uint32_tag_data = NULL;
tnf_tag_data_t *tnf_int64_tag_data = NULL;
tnf_tag_data_t *tnf_uint64_tag_data = NULL;
tnf_tag_data_t *tnf_float32_tag_data = NULL;
tnf_tag_data_t *tnf_float64_tag_data = NULL;
tnf_tag_data_t *tnf_array_tag_data = NULL;
tnf_tag_data_t *tnf_string_tag_data = NULL;
tnf_tag_data_t *tnf_type_array_tag_data = NULL;
tnf_tag_data_t *tnf_name_array_tag_data = NULL;
tnf_tag_data_t *tnf_derived_tag_data = NULL;
tnf_tag_data_t *tnf_align_tag_data = NULL;
tnf_tag_data_t *tnf_derived_base_tag_data = NULL;
tnf_tag_data_t *tnf_element_type_tag_data = NULL;
tnf_tag_data_t *tnf_header_size_tag_data = NULL;
tnf_tag_data_t *tnf_name_tag_data = NULL;
tnf_tag_data_t *tnf_opaque_tag_data = NULL;
tnf_tag_data_t *tnf_properties_tag_data = NULL;
tnf_tag_data_t *tnf_self_size_tag_data = NULL;
tnf_tag_data_t *tnf_size_tag_data = NULL;
tnf_tag_data_t *tnf_slot_names_tag_data = NULL;
tnf_tag_data_t *tnf_slot_types_tag_data = NULL;
tnf_tag_data_t *tnf_tag_tag_data = NULL;
tnf_tag_data_t *tnf_tag_arg_tag_data = NULL;
tnf_tag_data_t *tnf_type_size_tag_data = NULL;
tnf_tag_data_t *tnf_struct_tag_data = NULL;
tnf_tag_data_t *tnf_file_header_tag_data = NULL;
tnf_tag_data_t *tnf_block_header_tag_data = NULL;
tnf_tag_data_t *tnf_type_tag_data = NULL;
tnf_tag_data_t *tnf_array_type_tag_data = NULL;
tnf_tag_data_t *tnf_derived_type_tag_data = NULL;
tnf_tag_data_t *tnf_scalar_type_tag_data = NULL;
tnf_tag_data_t *tnf_struct_type_tag_data = NULL;

/* tnf_trace module */
tnf_tag_data_t *tnf_probe_event_tag_data = NULL;
tnf_tag_data_t *tnf_time_base_tag_data = NULL;
tnf_tag_data_t *tnf_time_delta_tag_data = NULL;
tnf_tag_data_t *tnf_pid_tag_data = NULL;
tnf_tag_data_t *tnf_lwpid_tag_data = NULL;
tnf_tag_data_t *tnf_kthread_id_tag_data = NULL;
tnf_tag_data_t *tnf_cpuid_tag_data = NULL;
tnf_tag_data_t *tnf_device_tag_data = NULL;
tnf_tag_data_t *tnf_symbol_tag_data = NULL;
tnf_tag_data_t *tnf_symbols_tag_data = NULL;
tnf_tag_data_t *tnf_sysnum_tag_data = NULL;
tnf_tag_data_t *tnf_microstate_tag_data = NULL;
tnf_tag_data_t *tnf_offset_tag_data = NULL;
tnf_tag_data_t *tnf_fault_type_tag_data = NULL;
tnf_tag_data_t *tnf_seg_access_tag_data = NULL;
tnf_tag_data_t *tnf_bioflags_tag_data = NULL;
tnf_tag_data_t *tnf_diskaddr_tag_data = NULL;
tnf_tag_data_t *tnf_kernel_schedule_tag_data = NULL;

tnf_tag_data_t *tnf_probe_type_tag_data = NULL;

/* Exported properties */
tnf_tag_data_t	***tnf_user_struct_properties = NULL;

/*
 * tnf_thread_create()
 * Called from thread_create() to initialize thread's tracing state.
 * XXX Do this when tracing is first turned on
 */

void
tnf_thread_create(kthread_t *t)
{
	/* If the allocation fails, this thread doesn't trace */
	t->t_tnf_tpdp = kmem_zalloc(sizeof (tnf_ops_t), KM_NOSLEEP);

	TNF_PROBE_3(thread_create, "thread", /* CSTYLED */,
		tnf_kthread_id,	tid,		t,
		tnf_pid,	pid,		ttoproc(t)->p_pid,
		tnf_symbol,	start_pc,	t->t_startpc);
}

/*
 * tnf_thread_exit()
 * Called from thread_exit() and lwp_exit() if thread has a tpdp.
 * From this point on, we're off the allthreads list
 */

void
tnf_thread_exit(void)
{
	tnf_ops_t *ops;
	tnf_block_header_t *block;

	TNF_PROBE_0(thread_exit, "thread", /* CSTYLED */);
        /* LINTED pointer cast may result in improper alignment */
	ops = (tnf_ops_t *)curthread->t_tnf_tpdp;
	/*
	 * Mark ops as busy from now on, so it will never be used
	 * again.  If we fail on the busy lock, the buffer
	 * deallocation code is cleaning our ops, so we don't need to
	 * do anything.  If we get the lock and the buffer exists,
	 * release all blocks we hold.  Once we're off allthreads,
	 * the deallocator will not examine our ops.
	 */
	if (ops->busy)
		return;
	LOCK_INIT_HELD(&ops->busy);
	if (tnf_buf != NULL) {
		/* Release any A-locks held */
		block = ops->wcb.tnfw_w_pos.tnfw_w_block;
		ops->wcb.tnfw_w_pos.tnfw_w_block = NULL;
		if (block != NULL)
			lock_clear(&block->A_lock);
		block = ops->wcb.tnfw_w_tag_pos.tnfw_w_block;
		ops->wcb.tnfw_w_tag_pos.tnfw_w_block = NULL;
		if (block != NULL)
			lock_clear(&block->A_lock);
	}
}

/*
 * Called from thread_free() if thread has tpdp.
 */

void
tnf_thread_free(kthread_t *t)
{
	tnf_ops_t *ops;
	/* LINTED pointer cast may result in improper alignment */
	ops = (tnf_ops_t *)t->t_tnf_tpdp;
	t->t_tnf_tpdp = NULL;
	kmem_free(ops, sizeof (*ops));
}

/*
 * tnf_thread_queue()
 * Probe wrapper called when tracing is enabled and a thread is
 * placed on some dispatch queue.
 */

void
tnf_thread_queue(kthread_t *t, cpu_t *cp, pri_t tpri)
{
	TNF_PROBE_4(thread_queue, "dispatcher", /* CSTYLED */,
		tnf_kthread_id,		tid,		t,
		tnf_cpuid,		cpuid,		cp->cpu_id,
		tnf_long,		priority,	tpri,
		tnf_ulong,		queue_length,
			/* cp->cpu_disp->disp_q[tpri].dq_sruncnt */
			cp->cpu_disp->disp_nrunnable);

	TNF_PROBE_2(thread_state, "thread", /* CSTYLED */,
		tnf_kthread_id,		tid,		t,
		tnf_microstate,		state,		LMS_WAIT_CPU);
}

/*
 * pcstack(): fill in, NULL-terminate and return pc stack.
 */

static pc_t *
pcstack(pc_t *pcs)
{
	uint_t n;

	n = getpcstack(pcs, TNF_PC_COUNT);
	pcs[n] = 0;
	return (pcs);
}

/*
 * tnf_thread_switch()
 * Probe wrapper called when tracing enabled and curthread is about to
 * switch to the next thread.
 * XXX Simple sleepstate and runstate calculations
 */

#define	SLPSTATE(t, ts)					\
	(((ts) == TS_STOPPED) ? LMS_STOPPED :		\
	    ((t)->t_wchan0 ? LMS_USER_LOCK : LMS_SLEEP))

#define	RUNSTATE(next, lwp)				\
	((((lwp = ttolwp(next)) != NULL) &&		\
		lwp->lwp_state == LWP_USER) ?		\
		LMS_USER : LMS_SYSTEM)

void
tnf_thread_switch(kthread_t *next)
{
	kthread_t	*t;
	klwp_t		*lwp;
	caddr_t		ztpdp;
	int		borrow;
	uint_t		ts;
	pc_t		pcs[TNF_PC_COUNT + 1];

	t = curthread;
	ts = t->t_state;

	/*
	 * If we're a zombie, borrow idle thread's tpdp.  This lets
	 * the driver decide whether the buffer is busy by examining
	 * allthreads (idle threads are always on the list).
	 */
	if ((borrow = (ts == TS_ZOMB)) != 0) {
		ztpdp = t->t_tnf_tpdp;
		t->t_tnf_tpdp = CPU->cpu_idle_thread->t_tnf_tpdp;
		goto do_next;
	}

	/*
	 * If we're blocked, test the blockage probe
	 */
	if (ts == TS_SLEEP && t->t_wchan)
#if defined(__sparc)
		TNF_PROBE_2(thread_block, "synch", /* CSTYLED */,
		    tnf_opaque,	  reason,	t->t_wchan,
		    tnf_symbols,  stack,	(pc_t *)pcstack(pcs));
#else /* defined(__sparc) */
		TNF_PROBE_2(thread_block, "synch", /* CSTYLED */,
		    tnf_opaque,   reason,	t->t_wchan,
		    tnf_symbols,  stack,	(tnf_opaque_t *)pcstack(pcs));
#endif /* defined(__sparc) */

	/*
	 * Record outgoing thread's state
	 * Kernel thread ID is implicit in schedule record
	 * supress lint: cast from 32-bit integer to 8-bit integer
	 * tnf_microstate_t = tnf_uint8_t
	 */
#if defined(_LP64)
	/* LINTED */
	TNF_PROBE_1(thread_state, "thread", /* CSTYLED */,
	    tnf_microstate,	state,		SLPSTATE(t, ts));
#else
	TNF_PROBE_1(thread_state, "thread", /* CSTYLED */,
		tnf_microstate,	state,	SLPSTATE(t, ts));
#endif

do_next:
	/*
	 * Record incoming thread's state
	 *
	 * supress lint: cast from 32-bit integer to 8-bit integer
	 * tnf_microstate_t = tnf_uint8_t
	 */
#if defined(_LP64)
	/* LINTED */
	TNF_PROBE_2(thread_state, "thread", /* CSTYLED */,
	    tnf_kthread_id,	tid,		next,
	    tnf_microstate,	state,		RUNSTATE(next, lwp));
#else
	TNF_PROBE_2(thread_state, "thread", /* CSTYLED */,
		tnf_kthread_id,	tid,	next,
		tnf_microstate,	state,	RUNSTATE(next, lwp));
#endif

	/*
	 * If we borrowed idle thread's tpdp above, restore the zombies
	 * tpdp so that it will be freed from tnf_thread_free().
	 */
	if (borrow)
		t->t_tnf_tpdp = ztpdp;

}

#endif	/* NPROBE */

/*
 * tnf_mod_load (and tnf_mod_unload), when called from a client module's _init
 * (and _fini) entry points are insufficient mechanisms for maintaining the
 * consistency of __tnf_probe_list_head and __tnf_tag_list_head whenever that
 * module is loaded or unloaded.  The problem occurs because loading a module,
 * at which time the modules probes are linked into the two lists, and
 * installing that module are separate operations.  This means that it is
 * possible for a module to be loaded, not installed, and unloaded without
 * calling _init and _fini.  If the module contains TNF probes, the probe and
 * tag lists will contain references to data addresses freed when the module
 * is unloaded.
 *
 * The implemented solution for maintaining the lists is to perform the
 * unsplicing when the module is unloaded. (Splicing into the lists, "probe
 * discovery", is done when krtld processes relocation references when it
 * loads the module; this information is not available for subsequent
 * operations on the module.
 */
int
tnf_mod_load()
{
	return (0);
}

/* ARGSUSED */
int
tnf_mod_unload(struct modlinkage *mlp)
{
	return (0);
}
