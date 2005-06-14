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

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/stack.h>
#include <sys/thread.h>

#include "findstack.h"

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

#define	fs_dprintf(x)					\
	if (findstack_debug_on) {			\
		mdb_printf("findstack debug: ");	\
		/*CSTYLED*/				\
		mdb_printf x ;				\
	}

static int findstack_debug_on = 0;

#if defined(__i386) || defined(__amd64)
struct rwindow {
	uintptr_t rw_fp;
	uintptr_t rw_pc;
};
#endif

#define	TOO_BIG_FOR_A_STACK (1024 * 1024)

#define	KTOU(p) ((p) - kbase + ubase)
#define	UTOK(p) ((p) - ubase + kbase)

#if defined(__i386) || defined(__amd64)
static GElf_Sym thread_exit_sym;
#endif

#define	CRAWL_FOUNDALL	(-1)

/*
 * Given a stack pointer, try to crawl down it to the bottom.
 * "frame" is a VA in MDB's address space.
 *
 * Returns the number of frames successfully crawled down, or
 * CRAWL_FOUNDALL if it got to the bottom of the stack.
 */
static int
crawl(uintptr_t frame, uintptr_t kbase, uintptr_t ktop, uintptr_t ubase,
    int kill_fp)
{
	int levels = 0;

	fs_dprintf(("<0> frame = %p, kbase = %p, ktop = %p, ubase = %p\n",
	    frame, kbase, ktop, ubase));
	for (;;) {
		uintptr_t fp;
		long *fpp = (long *)&((struct rwindow *)frame)->rw_fp;

		fs_dprintf(("<1> fpp = %p, frame = %p\n", fpp, frame));

		if ((frame & (STACK_ALIGN - 1)) != 0)
			break;

		fp = ((struct rwindow *)frame)->rw_fp + STACK_BIAS;
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

/*
 * "sp" is a kernel VA.
 */
static int
print_stack(uintptr_t sp, uintptr_t pc, uintptr_t addr,
    int argc, const mdb_arg_t *argv, int free_state)
{
	int showargs = 0, count, err;

	count = mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &showargs, NULL);
	argc -= count;
	argv += count;

	if (argc > 1 || (argc == 1 && argv->a_type != MDB_TYPE_STRING))
		return (DCMD_USAGE);

	mdb_printf("stack pointer for thread %p%s: %p\n",
	    addr, (free_state ? " (TS_FREE)" : ""), sp);
	if (pc != 0)
		mdb_printf("[ %0?lr %a() ]\n", sp, pc);

	mdb_inc_indent(2);
	mdb_set_dot(sp);

	if (argc == 1)
		err = mdb_eval(argv->a_un.a_str);
	else if (showargs)
		err = mdb_eval("<.$C");
	else
		err = mdb_eval("<.$C0");

	mdb_dec_indent(2);

	return ((err == -1) ? DCMD_ABORT : DCMD_OK);
}

/*ARGSUSED*/
int
findstack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kthread_t thr;
	size_t stksz;
	uintptr_t ubase, utop;
	uintptr_t kbase, ktop;
	uintptr_t win, sp;
	int free_state;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	bzero(&thr, sizeof (thr));
	if (mdb_ctf_vread(&thr, "kthread_t", addr,
	    MDB_CTF_VREAD_IGNORE_ALL) == -1) {
		mdb_warn("couldn't read thread at %p\n", addr);
		return (DCMD_ERR);
	}

	if ((thr.t_schedflag & TS_LOAD) == 0) {
		mdb_warn("thread %p isn't in memory\n", addr);
		return (DCMD_ERR);
	}

	if (thr.t_stk < thr.t_stkbase) {
		mdb_warn("stack base or stack top corrupt for thread %p\n",
		    addr);
		return (DCMD_ERR);
	}

	free_state = thr.t_state == TS_FREE;

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
		mdb_warn("stack size for thread %p is too big to be "
		    "reasonable\n", addr);
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
		mdb_warn("couldn't read entire stack for thread %p\n", addr);
		return (DCMD_ERR);
	}

	/*
	 * Try the saved %sp first, if it looks reasonable.
	 */
	sp = KTOU((uintptr_t)thr.t_sp + STACK_BIAS);
	if (sp >= ubase && sp <= utop) {
		if (crawl(sp, kbase, ktop, ubase, 0) == CRAWL_FOUNDALL) {
			mdb_free((void *)ubase, stksz);
#if defined(__i386)
			return (print_stack((uintptr_t)thr.t_sp, 0, addr,
			    argc, argv, free_state));
#else
			return (print_stack((uintptr_t)thr.t_sp, thr.t_pc, addr,
			    argc, argv, free_state));
#endif
		}
	}

	/*
	 * Now walk through the whole stack, starting at the base,
	 * trying every possible "window".
	 */
	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		if (crawl(win, kbase, ktop, ubase, 1) == CRAWL_FOUNDALL) {
			mdb_free((void *)ubase, stksz);
			return (print_stack(UTOK(win) - STACK_BIAS, 0, addr,
			    argc, argv, free_state));
		}
	}

	/*
	 * We didn't conclusively find the stack.  So we'll take another lap,
	 * and print out anything that looks possible.
	 */
	mdb_printf("Possible stack pointers for thread %p:\n", addr);
	(void) mdb_vread((caddr_t)ubase, stksz, kbase);

	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		uintptr_t fp = ((struct rwindow *)win)->rw_fp;
		int levels;

		if ((levels = crawl(win, kbase, ktop, ubase, 1)) > 1) {
			mdb_printf("  %p (%d)\n", fp, levels);
		} else if (levels == CRAWL_FOUNDALL) {
			/*
			 * If this is a live system, the stack could change
			 * between the two mdb_vread(ubase, utop, kbase)'s,
			 * and we could have a fully valid stack here.
			 */
			mdb_free((void *)ubase, stksz);
			return (print_stack(UTOK(win) - STACK_BIAS, 0, addr,
			    argc, argv, free_state));
		}
	}

	mdb_free((void *)ubase, stksz);
	return (DCMD_OK);
}

/*ARGSUSED*/
int
findstack_debug(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *av)
{
	findstack_debug_on ^= 1;

	mdb_printf("findstack: debugging is now %s\n",
	    findstack_debug_on ? "on" : "off");

	return (DCMD_OK);
}

int
findstack_init(void)
{
#if defined(__i386) || defined(__amd64)
	if (mdb_lookup_by_name("thread_exit", &thread_exit_sym) == -1) {
		mdb_warn("couldn't find 'thread_exit' symbol");
		return (DCMD_ABORT);
	}
#endif

	return (DCMD_OK);
}
