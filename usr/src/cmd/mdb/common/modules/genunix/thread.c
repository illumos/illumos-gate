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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/disp.h>
#include <sys/taskq_impl.h>

typedef struct thread_walk {
	kthread_t *tw_thread;
	uintptr_t tw_last;
	uint_t tw_inproc;
	uint_t tw_step;
} thread_walk_t;

int
thread_walk_init(mdb_walk_state_t *wsp)
{
	thread_walk_t *twp = mdb_alloc(sizeof (thread_walk_t), UM_SLEEP);

	if (wsp->walk_addr == NULL) {
		if (mdb_readvar(&wsp->walk_addr, "allthreads") == -1) {
			mdb_warn("failed to read 'allthreads'");
			mdb_free(twp, sizeof (thread_walk_t));
			return (WALK_ERR);
		}

		twp->tw_inproc = FALSE;

	} else {
		proc_t pr;

		if (mdb_vread(&pr, sizeof (proc_t), wsp->walk_addr) == -1) {
			mdb_warn("failed to read proc at %p", wsp->walk_addr);
			mdb_free(twp, sizeof (thread_walk_t));
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)pr.p_tlist;
		twp->tw_inproc = TRUE;
	}

	twp->tw_thread = mdb_alloc(sizeof (kthread_t), UM_SLEEP);
	twp->tw_last = wsp->walk_addr;
	twp->tw_step = FALSE;

	wsp->walk_data = twp;
	return (WALK_NEXT);
}

int
thread_walk_step(mdb_walk_state_t *wsp)
{
	thread_walk_t *twp = (thread_walk_t *)wsp->walk_data;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE); /* Proc has 0 threads or allthreads = 0 */

	if (twp->tw_step && wsp->walk_addr == twp->tw_last)
		return (WALK_DONE); /* We've wrapped around */

	if (mdb_vread(twp->tw_thread, sizeof (kthread_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read thread at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, twp->tw_thread,
	    wsp->walk_cbdata);

	if (twp->tw_inproc)
		wsp->walk_addr = (uintptr_t)twp->tw_thread->t_forw;
	else
		wsp->walk_addr = (uintptr_t)twp->tw_thread->t_next;

	twp->tw_step = TRUE;
	return (status);
}

void
thread_walk_fini(mdb_walk_state_t *wsp)
{
	thread_walk_t *twp = (thread_walk_t *)wsp->walk_data;

	mdb_free(twp->tw_thread, sizeof (kthread_t));
	mdb_free(twp, sizeof (thread_walk_t));
}

int
deathrow_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("thread_deathrow", wsp) == -1) {
		mdb_warn("couldn't walk 'thread_deathrow'");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("lwp_deathrow", wsp) == -1) {
		mdb_warn("couldn't walk 'lwp_deathrow'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
deathrow_walk_step(mdb_walk_state_t *wsp)
{
	kthread_t t;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&t, sizeof (t), addr) == -1) {
		mdb_warn("couldn't read deathrow thread at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)t.t_forw;

	return (wsp->walk_callback(addr, &t, wsp->walk_cbdata));
}

int
thread_deathrow_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_readvar(&wsp->walk_addr, "thread_deathrow") == -1) {
		mdb_warn("couldn't read symbol 'thread_deathrow'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
lwp_deathrow_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_readvar(&wsp->walk_addr, "lwp_deathrow") == -1) {
		mdb_warn("couldn't read symbol 'lwp_deathrow'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}


typedef struct dispq_walk {
	int dw_npri;
	uintptr_t dw_dispq;
	uintptr_t dw_last;
} dispq_walk_t;

int
cpu_dispq_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	dispq_walk_t *dw;
	cpu_t cpu;
	dispq_t dispq;
	disp_t disp;

	if (addr == NULL) {
		mdb_warn("cpu_dispq walk needs a cpu_t address\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&cpu, sizeof (cpu_t), addr) == -1) {
		mdb_warn("failed to read cpu_t at %p", addr);
		return (WALK_ERR);
	}

	if (mdb_vread(&disp, sizeof (disp_t), (uintptr_t)cpu.cpu_disp) == -1) {
		mdb_warn("failed to read disp_t at %p", cpu.cpu_disp);
		return (WALK_ERR);
	}

	if (mdb_vread(&dispq, sizeof (dispq_t),
	    (uintptr_t)disp.disp_q) == -1) {
		mdb_warn("failed to read dispq_t at %p", disp.disp_q);
		return (WALK_ERR);
	}

	dw = mdb_alloc(sizeof (dispq_walk_t), UM_SLEEP);

	dw->dw_npri = disp.disp_npri;
	dw->dw_dispq = (uintptr_t)disp.disp_q;
	dw->dw_last = (uintptr_t)dispq.dq_last;

	wsp->walk_addr = (uintptr_t)dispq.dq_first;
	wsp->walk_data = dw;

	return (WALK_NEXT);
}

int
cpupart_dispq_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	dispq_walk_t *dw;
	cpupart_t cpupart;
	dispq_t dispq;

	if (addr == NULL) {
		mdb_warn("cpupart_dispq walk needs a cpupart_t address\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&cpupart, sizeof (cpupart_t), addr) == -1) {
		mdb_warn("failed to read cpupart_t at %p", addr);
		return (WALK_ERR);
	}

	if (mdb_vread(&dispq, sizeof (dispq_t),
	    (uintptr_t)cpupart.cp_kp_queue.disp_q) == -1) {
		mdb_warn("failed to read dispq_t at %p",
		    cpupart.cp_kp_queue.disp_q);
		return (WALK_ERR);
	}

	dw = mdb_alloc(sizeof (dispq_walk_t), UM_SLEEP);

	dw->dw_npri = cpupart.cp_kp_queue.disp_npri;
	dw->dw_dispq = (uintptr_t)cpupart.cp_kp_queue.disp_q;
	dw->dw_last = (uintptr_t)dispq.dq_last;

	wsp->walk_addr = (uintptr_t)dispq.dq_first;
	wsp->walk_data = dw;

	return (WALK_NEXT);
}

int
dispq_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	dispq_walk_t *dw = wsp->walk_data;
	dispq_t dispq;
	kthread_t t;

	while (addr == NULL) {
		if (--dw->dw_npri == 0)
			return (WALK_DONE);

		dw->dw_dispq += sizeof (dispq_t);

		if (mdb_vread(&dispq, sizeof (dispq_t), dw->dw_dispq) == -1) {
			mdb_warn("failed to read dispq_t at %p", dw->dw_dispq);
			return (WALK_ERR);
		}

		dw->dw_last = (uintptr_t)dispq.dq_last;
		addr = (uintptr_t)dispq.dq_first;
	}

	if (mdb_vread(&t, sizeof (kthread_t), addr) == -1) {
		mdb_warn("failed to read kthread_t at %p", addr);
		return (WALK_ERR);
	}

	if (addr == dw->dw_last)
		wsp->walk_addr = NULL;
	else
		wsp->walk_addr = (uintptr_t)t.t_link;

	return (wsp->walk_callback(addr, &t, wsp->walk_cbdata));
}

void
dispq_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (dispq_walk_t));
}


#define	TF_INTR		0x01
#define	TF_PROC		0x02
#define	TF_BLOCK	0x04
#define	TF_SIG		0x08
#define	TF_DISP		0x10
#define	TF_MERGE	0x20

/*
 * Display a kthread_t.
 * This is a little complicated, as there is a lot of information that
 * the user could be interested in.  The flags "ipbsd" are used to
 * indicate which subset of the thread's members are to be displayed
 * ('i' is the default).  If multiple options are specified, multiple
 * sets of data will be displayed in a vaguely readable format.  If the
 * 'm' option is specified, all the selected sets will be merged onto a
 * single line for the benefit of those using wider-than-normal
 * terminals.  Having a generic mechanism for doing this would be
 * really useful, but is a project best left to another day.
 */

int
thread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kthread_t	t;
	uint_t		oflags = 0;
	uint_t		fflag = FALSE;
	int		first;
	char		*state;
	char		stbuf[20];

	/*
	 * "Gracefully" handle printing a boatload of stuff to the
	 * screen.  If we are not printing our first set of data, and
	 * we haven't been instructed to merge sets together, output a
	 * newline and indent such that the thread addresses form a
	 * column of their own.
	 */
#define	SPACER()				\
	if (first) {				\
		first = FALSE;			\
	} else if (!(oflags & TF_MERGE)) {	\
		mdb_printf("\n%?s", "");	\
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("thread", "thread", argc, argv) == -1) {
			mdb_warn("can't walk threads");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'f', MDB_OPT_SETBITS, TRUE, &fflag,
	    'i', MDB_OPT_SETBITS, TF_INTR, &oflags,
	    'p', MDB_OPT_SETBITS, TF_PROC, &oflags,
	    'b', MDB_OPT_SETBITS, TF_BLOCK, &oflags,
	    's', MDB_OPT_SETBITS, TF_SIG, &oflags,
	    'd', MDB_OPT_SETBITS, TF_DISP, &oflags,
	    'm', MDB_OPT_SETBITS, TF_MERGE, &oflags, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no sets were specified, choose the 'i' set.
	 */
	if (!(oflags & ~TF_MERGE))
#ifdef	_LP64
		oflags = TF_INTR;
#else
		oflags = TF_INTR | TF_DISP | TF_MERGE;
#endif

	/*
	 * Print the relevant headers; note use of SPACER().
	 */
	if (DCMD_HDRSPEC(flags)) {
		first = TRUE;
		mdb_printf("%<u>%?s%</u>", "ADDR");
		mdb_flush();

		if (oflags & TF_PROC) {
			SPACER();
			mdb_printf("%<u> %?s %?s %?s%</u>",
			    "PROC", "LWP", "CRED");
		}

		if (oflags & TF_INTR) {
			SPACER();
			mdb_printf("%<u> %8s %4s %4s %4s %5s %5s %3s %?s%</u>",
			    "STATE", "FLG", "PFLG",
			    "SFLG", "PRI", "EPRI", "PIL", "INTR");
		}

		if (oflags & TF_BLOCK) {
			SPACER();
			mdb_printf("%<u> %?s %?s %?s %11s%</u>",
			    "WCHAN", "TS", "PITS", "SOBJ OPS");
		}

		if (oflags & TF_SIG) {
			SPACER();
			mdb_printf("%<u> %?s %16s %16s%</u>",
			    "SIGQUEUE", "SIG PEND", "SIG HELD");
		}

		if (oflags & TF_DISP) {
			SPACER();
			mdb_printf("%<u> %?s %5s %2s%</u>",
			    "DISPTIME", "BOUND", "PR");
		}
		mdb_printf("\n");
	}

	if (mdb_vread(&t, sizeof (kthread_t), addr) == -1) {
		mdb_warn("can't read kthread_t at %#lx", addr);
		return (DCMD_ERR);
	}

	if (fflag && (t.t_state == TS_FREE))
		return (DCMD_OK);

	first = TRUE;
	mdb_printf("%0?lx", addr);

	/* process information */
	if (oflags & TF_PROC) {
		SPACER();
		mdb_printf(" %?p %?p %?p", t.t_procp, t.t_lwp, t.t_cred);
	}

	/* priority/interrupt information */
	if (oflags & TF_INTR) {
		SPACER();
		switch (t.t_state) {
		case TS_FREE:
			state = "free";
			break;
		case TS_SLEEP:
			state = "sleep";
			break;
		case TS_RUN:
			state = "run";
			break;
		case TS_ONPROC:
			state = "onproc";
			break;
		case TS_ZOMB:
			state = "zomb";
			break;
		case TS_STOPPED:
			state = "stopped";
			break;
		case TS_WAIT:
			state = "wait";
			break;
		default:
			(void) mdb_snprintf(stbuf, 11, "inval/%02x", t.t_state);
			state = stbuf;
		}
		if (t.t_intr == NULL) {
			mdb_printf(" %-8s %4x %4x %4x %5d %5d %3d %?s",
			    state, t.t_flag, t.t_proc_flag, t.t_schedflag,
			    t.t_pri, t.t_epri, t.t_pil, "n/a");
		} else {
			mdb_printf(" %-8s %4x %4x %4x %5d %5d %3d %?p",
			    state, t.t_flag, t.t_proc_flag, t.t_schedflag,
			    t.t_pri, t.t_epri, t.t_pil, t.t_intr);
		}
	}

	/* blocking information */
	if (oflags & TF_BLOCK) {
		SPACER();
		(void) mdb_snprintf(stbuf, 20, "%a", t.t_sobj_ops);
		stbuf[11] = '\0';
		mdb_printf(" %?p %?p %?p %11s",
		    t.t_wchan, t.t_ts, t.t_prioinv, stbuf);
	}

	/* signal information */
	if (oflags & TF_SIG) {
		SPACER();
		mdb_printf(" %?p %016llx %016llx",
		    t.t_sigqueue, t.t_sig, t.t_hold);
	}

	/* dispatcher stuff */
	if (oflags & TF_DISP) {
		SPACER();
		mdb_printf(" %?lx %5d %2d",
		    t.t_disp_time, t.t_bind_cpu, t.t_preempt);
	}

	mdb_printf("\n");

#undef SPACER

	return (DCMD_OK);
}

void
thread_help(void)
{
	mdb_printf(
	    "The flags -ipbsd control which information is displayed.  When\n"
	    "combined, the fields are displayed on separate lines unless the\n"
	    "-m option is given.\n"
	    "\n"
	    "\t-b\tprint blocked thread state\n"
	    "\t-d\tprint dispatcher state\n"
	    "\t-f\tignore freed threads\n"
	    "\t-i\tprint basic thread state (default)\n"
	    "\t-m\tdisplay results on a single line\n"
	    "\t-p\tprint process and lwp state\n"
	    "\t-s\tprint signal state\n");
}

/*
 * List a combination of kthread_t and proc_t. Add stack traces in verbose mode.
 */
int
threadlist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i;
	uint_t count =  0;
	uint_t verbose = FALSE;
	uint_t notaskq = FALSE;
	kthread_t t;
	taskq_t tq;
	proc_t p;
	char cmd[80];
	mdb_arg_t cmdarg;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("thread", "threadlist", argc, argv) == -1) {
			mdb_warn("can't walk threads");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	i = mdb_getopts(argc, argv,
	    't', MDB_OPT_SETBITS, TRUE, &notaskq,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL);

	if (i != argc) {
		if (i != argc - 1 || !verbose)
			return (DCMD_USAGE);

		if (argv[i].a_type == MDB_TYPE_IMMEDIATE)
			count = (uint_t)argv[i].a_un.a_val;
		else
			count = (uint_t)mdb_strtoull(argv[i].a_un.a_str);
	}

	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("%<u>%?s %?s %?s %3s %3s %?s%</u>\n",
			    "ADDR", "PROC", "LWP", "CLS", "PRI", "WCHAN");
		else
			mdb_printf("%<u>%?s %?s %?s %s/%s%</u>\n",
			    "ADDR", "PROC", "LWP", "CMD", "LWPID");
	}

	if (mdb_vread(&t, sizeof (kthread_t), addr) == -1) {
		mdb_warn("failed to read kthread_t at %p", addr);
		return (DCMD_ERR);
	}

	if (notaskq && t.t_taskq != NULL)
		return (DCMD_OK);

	if (t.t_state == TS_FREE)
		return (DCMD_OK);

	if (mdb_vread(&p, sizeof (proc_t), (uintptr_t)t.t_procp) == -1) {
		mdb_warn("failed to read proc at %p", t.t_procp);
		return (DCMD_ERR);
	}

	if (mdb_vread(&tq, sizeof (taskq_t), (uintptr_t)t.t_taskq) == -1)
		tq.tq_name[0] = '\0';

	if (verbose) {
		mdb_printf("%0?p %?p %?p %3u %3d %?p\n",
		    addr, t.t_procp, t.t_lwp, t.t_cid, t.t_pri, t.t_wchan);

		mdb_inc_indent(2);

		mdb_printf("PC: %a", t.t_pc);
		if (t.t_tid == 0) {
			if (tq.tq_name[0] != '\0')
				mdb_printf("    TASKQ: %s\n", tq.tq_name);
			else
				mdb_printf("    THREAD: %a()\n", t.t_startpc);
		} else {
			mdb_printf("    CMD: %s\n", p.p_user.u_psargs);
		}

		mdb_snprintf(cmd, sizeof (cmd), "<.$c%d", count);
		cmdarg.a_type = MDB_TYPE_STRING;
		cmdarg.a_un.a_str = cmd;

		(void) mdb_call_dcmd("findstack", addr, flags, 1, &cmdarg);

		mdb_dec_indent(2);

		mdb_printf("\n");
	} else {
		mdb_printf("%0?p %?p %?p", addr, t.t_procp, t.t_lwp);
		if (t.t_tid == 0) {
			if (tq.tq_name[0] != '\0')
				mdb_printf(" tq:%s\n", tq.tq_name);
			else
				mdb_printf(" %a()\n", t.t_startpc);
		} else {
			mdb_printf(" %s/%u\n", p.p_user.u_comm, t.t_tid);
		}
	}

	return (DCMD_OK);
}

void
threadlist_help(void)
{
	mdb_printf(
	    "   -v         print verbose output including C stack trace\n"
	    "   -t         skip threads belonging to a taskq\n"
	    "   count      print no more than count arguments (default 0)\n");
}
