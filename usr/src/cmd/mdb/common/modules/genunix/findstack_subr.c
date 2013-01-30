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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/stack.h>
#include <sys/thread.h>
#include <sys/modctl.h>

#include "findstack.h"
#include "thread.h"
#include "sobj.h"

#define	TOO_BIG_FOR_A_STACK (1024 * 1024)

#define	KTOU(p) ((p) - kbase + ubase)
#define	UTOK(p) ((p) - ubase + kbase)

#define	CRAWL_FOUNDALL	(-1)

#if defined(__i386) || defined(__amd64)
struct rwindow {
	uintptr_t rw_fp;
	uintptr_t rw_rtn;
};
#endif

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

/*
 * Given a stack pointer, try to crawl down it to the bottom.
 * "frame" is a VA in MDB's address space.
 *
 * Returns the number of frames successfully crawled down, or
 * CRAWL_FOUNDALL if it got to the bottom of the stack.
 */
static int
crawl(uintptr_t frame, uintptr_t kbase, uintptr_t ktop, uintptr_t ubase,
    int kill_fp, findstack_info_t *fsip)
{
	int levels = 0;

	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;

	fs_dprintf(("<0> frame = %p, kbase = %p, ktop = %p, ubase = %p\n",
	    frame, kbase, ktop, ubase));
	for (;;) {
		uintptr_t fp;
		long *fpp = (long *)&((struct rwindow *)frame)->rw_fp;

		fs_dprintf(("<1> fpp = %p, frame = %p\n", fpp, frame));

		if ((frame & (STACK_ALIGN - 1)) != 0)
			break;

		fp = ((struct rwindow *)frame)->rw_fp + STACK_BIAS;
		if (fsip->fsi_depth < fsip->fsi_max_depth)
			fsip->fsi_stack[fsip->fsi_depth++] =
			    ((struct rwindow *)frame)->rw_rtn;
		else
			fsip->fsi_overflow = 1;

		fs_dprintf(("<2> fp = %p\n", fp));

		if (fp == ktop)
			return (CRAWL_FOUNDALL);
		fs_dprintf(("<3> not at base\n"));

#if defined(__i386) || defined(__amd64)
		if (ktop - fp == sizeof (struct rwindow)) {
			fs_dprintf(("<4> found base\n"));
			return (CRAWL_FOUNDALL);
		}
#endif

		fs_dprintf(("<5> fp = %p, kbase = %p, ktop - size = %p\n",
		    fp, kbase, ktop - sizeof (struct rwindow)));

		if (fp < kbase || fp >= (ktop - sizeof (struct rwindow)))
			break;

		frame = KTOU(fp);
		fs_dprintf(("<6> frame = %p\n", frame));

		/*
		 * NULL out the old %fp so we don't go down this stack
		 * more than once.
		 */
		if (kill_fp) {
			fs_dprintf(("<7> fpp = %p\n", fpp));
			*fpp = NULL;
		}

		fs_dprintf(("<8> levels = %d\n", levels));
		levels++;
	}

	return (levels);
}

typedef struct mdb_findstack_kthread {
	struct _sobj_ops *t_sobj_ops;
	uint_t	t_state;
	ushort_t t_flag;
	ushort_t t_schedflag;
	caddr_t	t_stk;
	caddr_t	t_stkbase;
	label_t	t_pcb;
} mdb_findstack_kthread_t;

/*ARGSUSED*/
int
stacks_findstack(uintptr_t addr, findstack_info_t *fsip, uint_t print_warnings)
{
	mdb_findstack_kthread_t thr;
	size_t stksz;
	uintptr_t ubase, utop;
	uintptr_t kbase, ktop;
	uintptr_t win, sp;

	fsip->fsi_failed = 0;
	fsip->fsi_pc = 0;
	fsip->fsi_sp = 0;
	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;

	if (mdb_ctf_vread(&thr, "kthread_t", "mdb_findstack_kthread_t",
	    addr, print_warnings ? 0 : MDB_CTF_VREAD_QUIET) == -1) {
		fsip->fsi_failed = FSI_FAIL_BADTHREAD;
		return (DCMD_ERR);
	}

	fsip->fsi_sobj_ops = (uintptr_t)thr.t_sobj_ops;
	fsip->fsi_tstate = thr.t_state;
	fsip->fsi_panic = !!(thr.t_flag & T_PANIC);

	if ((thr.t_schedflag & TS_LOAD) == 0) {
		if (print_warnings)
			mdb_warn("thread %p isn't in memory\n", addr);
		fsip->fsi_failed = FSI_FAIL_NOTINMEMORY;
		return (DCMD_ERR);
	}

	if (thr.t_stk < thr.t_stkbase) {
		if (print_warnings)
			mdb_warn(
			    "stack base or stack top corrupt for thread %p\n",
			    addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	kbase = (uintptr_t)thr.t_stkbase;
	ktop = (uintptr_t)thr.t_stk;
	stksz = ktop - kbase;

#ifdef __amd64
	/*
	 * The stack on amd64 is intentionally misaligned, so ignore the top
	 * half-frame.  See thread_stk_init().  When handling traps, the frame
	 * is automatically aligned by the hardware, so we only alter ktop if
	 * needed.
	 */
	if ((ktop & (STACK_ALIGN - 1)) != 0)
		ktop -= STACK_ENTRY_ALIGN;
#endif

	/*
	 * If the stack size is larger than a meg, assume that it's bogus.
	 */
	if (stksz > TOO_BIG_FOR_A_STACK) {
		if (print_warnings)
			mdb_warn("stack size for thread %p is too big to be "
			    "reasonable\n", addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	/*
	 * This could be (and was) a UM_GC allocation.  Unfortunately,
	 * stksz tends to be very large.  As currently implemented, dcmds
	 * invoked as part of pipelines don't have their UM_GC-allocated
	 * memory freed until the pipeline completes.  With stksz in the
	 * neighborhood of 20k, the popular ::walk thread |::findstack
	 * pipeline can easily run memory-constrained debuggers (kmdb) out
	 * of memory.  This can be changed back to a gc-able allocation when
	 * the debugger is changed to free UM_GC memory more promptly.
	 */
	ubase = (uintptr_t)mdb_alloc(stksz, UM_SLEEP);
	utop = ubase + stksz;
	if (mdb_vread((caddr_t)ubase, stksz, kbase) != stksz) {
		mdb_free((void *)ubase, stksz);
		if (print_warnings)
			mdb_warn("couldn't read entire stack for thread %p\n",
			    addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	/*
	 * Try the saved %sp first, if it looks reasonable.
	 */
	sp = KTOU((uintptr_t)thr.t_sp + STACK_BIAS);
	if (sp >= ubase && sp <= utop) {
		if (crawl(sp, kbase, ktop, ubase, 0, fsip) == CRAWL_FOUNDALL) {
			fsip->fsi_sp = (uintptr_t)thr.t_sp;
#if !defined(__i386)
			fsip->fsi_pc = (uintptr_t)thr.t_pc;
#endif
			goto found;
		}
	}

	/*
	 * Now walk through the whole stack, starting at the base,
	 * trying every possible "window".
	 */
	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		if (crawl(win, kbase, ktop, ubase, 1, fsip) == CRAWL_FOUNDALL) {
			fsip->fsi_sp = UTOK(win) - STACK_BIAS;
			goto found;
		}
	}

	/*
	 * We didn't conclusively find the stack.  So we'll take another lap,
	 * and print out anything that looks possible.
	 */
	if (print_warnings)
		mdb_printf("Possible stack pointers for thread %p:\n", addr);
	(void) mdb_vread((caddr_t)ubase, stksz, kbase);

	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		uintptr_t fp = ((struct rwindow *)win)->rw_fp;
		int levels;

		if ((levels = crawl(win, kbase, ktop, ubase, 1, fsip)) > 1) {
			if (print_warnings)
				mdb_printf("  %p (%d)\n", fp, levels);
		} else if (levels == CRAWL_FOUNDALL) {
			/*
			 * If this is a live system, the stack could change
			 * between the two mdb_vread(ubase, utop, kbase)'s,
			 * and we could have a fully valid stack here.
			 */
			fsip->fsi_sp = UTOK(win) - STACK_BIAS;
			goto found;
		}
	}

	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;
	fsip->fsi_failed = FSI_FAIL_STACKNOTFOUND;

	mdb_free((void *)ubase, stksz);
	return (DCMD_ERR);
found:
	mdb_free((void *)ubase, stksz);
	return (DCMD_OK);
}

void
stacks_findstack_cleanup()
{}

/*ARGSUSED*/
int
stacks_module_cb(uintptr_t addr, const modctl_t *mp, stacks_module_t *smp)
{
	char mod_modname[MODMAXNAMELEN + 1];

	if (!mp->mod_modname)
		return (WALK_NEXT);

	if (mdb_readstr(mod_modname, sizeof (mod_modname),
	    (uintptr_t)mp->mod_modname) == -1) {
		mdb_warn("failed to read mod_modname in \"modctl\" walk");
		return (WALK_ERR);
	}

	if (strcmp(smp->sm_name, mod_modname))
		return (WALK_NEXT);

	smp->sm_text = (uintptr_t)mp->mod_text;
	smp->sm_size = mp->mod_text_size;

	return (WALK_DONE);
}

int
stacks_module(stacks_module_t *smp)
{
	if (mdb_walk("modctl", (mdb_walk_cb_t)stacks_module_cb, smp) != 0) {
		mdb_warn("cannot walk \"modctl\"");
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static void
print_sobj_help(int type, const char *name, const char *ops_name, void *ign)
{
	mdb_printf(" %s", name);
}

/*ARGSUSED*/
static void
print_tstate_help(uint_t state, const char *name, void *ignored)
{
	mdb_printf(" %s", name);
}

void
stacks_help(void)
{
	mdb_printf(
"::stacks processes all of the thread stacks on the system, grouping\n"
"together threads which have the same:\n"
"\n"
"  * Thread state,\n"
"  * Sync object type, and\n"
"  * PCs in their stack trace.\n"
"\n"
"The default output (no address or options) is just a dump of the thread\n"
"groups in the system.  For a view of active threads, use \"::stacks -i\",\n"
"which filters out FREE threads (interrupt threads which are currently\n"
"inactive) and threads sleeping on a CV. (Note that those threads may still\n"
"be noteworthy; this is just for a first glance.)  More general filtering\n"
"options are described below, in the \"FILTERS\" section.\n"
"\n"
"::stacks can be used in a pipeline.  The input to ::stacks is one or more\n"
"thread pointers.  For example, to get a summary of threads in a process,\n"
"you can do:\n"
"\n"
"  %<b>procp%</b>::walk thread | ::stacks\n"
"\n"
"When output into a pipe, ::stacks prints all of the threads input,\n"
"filtered by the given filtering options.  This means that multiple\n"
"::stacks invocations can be piped together to achieve more complicated\n"
"filters.  For example, to get threads which have both 'fop_read' and\n"
"'cv_wait_sig_swap' in their stack trace, you could do:\n"
"\n"
"  ::stacks -c fop_read | ::stacks -c cv_wait_sig_swap_core\n"
"\n"
"To get the full list of threads in each group, use the '-a' flag:\n"
"\n"
"  ::stacks -a\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -a    Print all of the grouped threads, instead of just a count.\n"
"  -f    Force a re-run of the thread stack gathering.\n"
"  -v    Be verbose about thread stack gathering.\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>FILTERS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -i    Show active threads; equivalent to '-S CV -T FREE'.\n"
"  -c func[+offset]\n"
"        Only print threads whose stacks contain func/func+offset.\n"
"  -C func[+offset]\n"
"        Only print threads whose stacks do not contain func/func+offset.\n"
"  -m module\n"
"        Only print threads whose stacks contain functions from module.\n"
"  -M module\n"
"        Only print threads whose stacks do not contain functions from\n"
"        module.\n"
"  -s {type | ALL}\n"
"        Only print threads which are on a 'type' synchronization object\n"
"        (SOBJ).\n"
"  -S {type | ALL}\n"
"        Only print threads which are not on a 'type' SOBJ.\n"
"  -t tstate\n"
"        Only print threads which are in thread state 'tstate'.\n"
"  -T tstate\n"
"        Only print threads which are not in thread state 'tstate'.\n"
"\n");
	mdb_printf("   SOBJ types:");
	sobj_type_walk(print_sobj_help, NULL);
	mdb_printf("\n");
	mdb_printf("Thread states:");
	thread_walk_states(print_tstate_help, NULL);
	mdb_printf(" panic\n");
}
