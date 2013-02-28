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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */


#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/disp.h>
#include <sys/taskq_impl.h>
#include <sys/stack.h>

#ifndef	STACK_BIAS
#define	STACK_BIAS	0
#endif

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

struct thread_state {
	uint_t ts_state;
	const char *ts_name;
} thread_states[] = {
	{ TS_FREE,	"free" },
	{ TS_SLEEP,	"sleep" },
	{ TS_RUN,	"run" },
	{ TS_ONPROC,	"onproc" },
	{ TS_ZOMB,	"zomb" },
	{ TS_STOPPED,	"stopped" },
	{ TS_WAIT,	"wait" }
};
#define	NUM_THREAD_STATES (sizeof (thread_states) / sizeof (*thread_states))

void
thread_state_to_text(uint_t state, char *out, size_t out_sz)
{
	int idx;

	for (idx = 0; idx < NUM_THREAD_STATES; idx++) {
		struct thread_state *tsp = &thread_states[idx];
		if (tsp->ts_state == state) {
			mdb_snprintf(out, out_sz, "%s", tsp->ts_name);
			return;
		}
	}
	mdb_snprintf(out, out_sz, "inval/%02x", state);
}

int
thread_text_to_state(const char *state, uint_t *out)
{
	int idx;

	for (idx = 0; idx < NUM_THREAD_STATES; idx++) {
		struct thread_state *tsp = &thread_states[idx];
		if (strcasecmp(tsp->ts_name, state) == 0) {
			*out = tsp->ts_state;
			return (0);
		}
	}
	return (-1);
}

void
thread_walk_states(void (*cbfunc)(uint_t, const char *, void *), void *cbarg)
{
	int idx;

	for (idx = 0; idx < NUM_THREAD_STATES; idx++) {
		struct thread_state *tsp = &thread_states[idx];
		cbfunc(tsp->ts_state, tsp->ts_name, cbarg);
	}
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
			mdb_printf("%<u> %?s %5s %2s %-6s%</u>",
			    "DISPTIME", "BOUND", "PR", "SWITCH");
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
		thread_state_to_text(t.t_state, stbuf, sizeof (stbuf));
		if (t.t_intr == NULL) {
			mdb_printf(" %-8s %4x %4x %4x %5d %5d %3d %?s",
			    stbuf, t.t_flag, t.t_proc_flag, t.t_schedflag,
			    t.t_pri, t.t_epri, t.t_pil, "n/a");
		} else {
			mdb_printf(" %-8s %4x %4x %4x %5d %5d %3d %?p",
			    stbuf, t.t_flag, t.t_proc_flag, t.t_schedflag,
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
		mdb_printf(" %?lx %5d %2d ",
		    t.t_disp_time, t.t_bind_cpu, t.t_preempt);
		if (t.t_disp_time != 0)
			mdb_printf("t-%-4d",
			    (clock_t)mdb_get_lbolt() - t.t_disp_time);
		else
			mdb_printf("%-6s", "-");
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

static size_t
stk_compute_percent(caddr_t t_stk, caddr_t t_stkbase, caddr_t sp)
{
	size_t percent;
	size_t s;

	if (t_stk > t_stkbase) {
		/* stack grows down */
		if (sp > t_stk) {
			return (0);
		}
		if (sp < t_stkbase) {
			return (100);
		}
		percent = t_stk - sp + 1;
		s = t_stk - t_stkbase + 1;
	} else {
		/* stack grows up */
		if (sp < t_stk) {
			return (0);
		}
		if (sp > t_stkbase) {
			return (100);
		}
		percent = sp - t_stk + 1;
		s = t_stkbase - t_stk + 1;
	}
	percent = ((100 * percent) / s) + 1;
	if (percent > 100) {
		percent = 100;
	}
	return (percent);
}

/*
 * Display kthread stack infos.
 */
int
stackinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kthread_t t;
	proc_t p;
	uint64_t *ptr;  /* pattern pointer */
	caddr_t	start;	/* kernel stack start */
	caddr_t end;	/* kernel stack end */
	caddr_t ustack;	/* userland copy of kernel stack */
	size_t usize;	/* userland copy of kernel stack size */
	caddr_t ustart;	/* userland copy of kernel stack, aligned start */
	caddr_t uend;	/* userland copy of kernel stack, aligned end */
	size_t percent = 0;
	uint_t all = FALSE; /* don't show TS_FREE kthread by default */
	uint_t history = FALSE;
	int i = 0;
	unsigned int ukmem_stackinfo;
	uintptr_t allthreads;

	/* handle options */
	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &all,
	    'h', MDB_OPT_SETBITS, TRUE, &history, NULL) != argc) {
		return (DCMD_USAGE);
	}

	/* walk all kthread if needed */
	if ((history == FALSE) && !(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("thread", "stackinfo", argc, argv) == -1) {
			mdb_warn("can't walk threads");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/* read 'kmem_stackinfo' */
	if (mdb_readsym(&ukmem_stackinfo, sizeof (ukmem_stackinfo),
	    "kmem_stackinfo") == -1) {
		mdb_warn("failed to read 'kmem_stackinfo'\n");
		ukmem_stackinfo = 0;
	}

	/* read 'allthreads' */
	if (mdb_readsym(&allthreads, sizeof (kthread_t *),
	    "allthreads") == -1) {
		mdb_warn("failed to read 'allthreads'\n");
		allthreads = NULL;
	}

	if (history == TRUE) {
		kmem_stkinfo_t *log;
		uintptr_t kaddr;

		mdb_printf("Dead kthreads stack usage history:\n");
		if (ukmem_stackinfo == 0) {
			mdb_printf("Tunable kmem_stackinfo is unset, history ");
			mdb_printf("feature is off.\nUse ::help stackinfo ");
			mdb_printf("for more details.\n");
			return (DCMD_OK);
		}

		mdb_printf("%<u>%?s%</u>", "THREAD");
		mdb_printf(" %<u>%?s%</u>", "STACK");
		mdb_printf("%<u>%s%</u>", "   SIZE  MAX CMD/LWPID or STARTPC");
		mdb_printf("\n");
		usize = KMEM_STKINFO_LOG_SIZE * sizeof (kmem_stkinfo_t);
		log = (kmem_stkinfo_t *)mdb_alloc(usize, UM_SLEEP);
		if (mdb_readsym(&kaddr, sizeof (kaddr),
		    "kmem_stkinfo_log") == -1) {
			mdb_free((void *)log, usize);
			mdb_warn("failed to read 'kmem_stkinfo_log'\n");
			return (DCMD_ERR);
		}
		if (kaddr == NULL) {
			mdb_free((void *)log, usize);
			return (DCMD_OK);
		}
		if (mdb_vread(log, usize, kaddr) == -1) {
			mdb_free((void *)log, usize);
			mdb_warn("failed to read %p\n", kaddr);
			return (DCMD_ERR);
		}
		for (i = 0; i < KMEM_STKINFO_LOG_SIZE; i++) {
			if (log[i].kthread == NULL) {
				continue;
			}
			mdb_printf("%0?p %0?p %6x %3d%%",
			    log[i].kthread,
			    log[i].start,
			    (uint_t)log[i].stksz,
			    (int)log[i].percent);
			if (log[i].t_tid != 0) {
				mdb_printf(" %s/%u\n",
				    log[i].cmd, log[i].t_tid);
			} else {
				mdb_printf(" %p (%a)\n", log[i].t_startpc,
				    log[i].t_startpc);
			}
		}
		mdb_free((void *)log, usize);
		return (DCMD_OK);
	}

	/* display header */
	if (DCMD_HDRSPEC(flags)) {
		if (ukmem_stackinfo == 0) {
			mdb_printf("Tunable kmem_stackinfo is unset, ");
			mdb_printf("MAX value is not available.\n");
			mdb_printf("Use ::help stackinfo for more details.\n");
		}
		mdb_printf("%<u>%?s%</u>", "THREAD");
		mdb_printf(" %<u>%?s%</u>", "STACK");
		mdb_printf("%<u>%s%</u>", "   SIZE  CUR  MAX CMD/LWPID");
		mdb_printf("\n");
	}

	/* read kthread */
	if (mdb_vread(&t, sizeof (kthread_t), addr) == -1) {
		mdb_warn("can't read kthread_t at %#lx\n", addr);
		return (DCMD_ERR);
	}

	if (t.t_state == TS_FREE && all == FALSE) {
		return (DCMD_OK);
	}

	/* read proc */
	if (mdb_vread(&p, sizeof (proc_t), (uintptr_t)t.t_procp) == -1) {
		mdb_warn("failed to read proc at %p\n", t.t_procp);
		return (DCMD_ERR);
	}

	/*
	 * Stack grows up or down, see thread_create(),
	 * compute stack memory aera start and end (start < end).
	 */
	if (t.t_stk > t.t_stkbase) {
		/* stack grows down */
		start = t.t_stkbase;
		end = t.t_stk;
	} else {
		/* stack grows up */
		start = t.t_stk;
		end = t.t_stkbase;
	}

	/* display stack info */
	mdb_printf("%0?p %0?p", addr, start);

	/* (end - start), kernel stack size as found in kthread_t */
	if ((end <= start) || ((end - start) > (1024 * 1024))) {
		/* negative or stack size > 1 meg, assume bogus */
		mdb_warn(" t_stk/t_stkbase problem\n");
		return (DCMD_ERR);
	}

	/* display stack size */
	mdb_printf(" %6x", end - start);

	/* display current stack usage */
	percent = stk_compute_percent(t.t_stk, t.t_stkbase,
	    (caddr_t)t.t_sp + STACK_BIAS);

	mdb_printf(" %3d%%", percent);
	percent = 0;

	if (ukmem_stackinfo == 0) {
		mdb_printf("  n/a");
		if (t.t_tid == 0) {
			mdb_printf(" %a()", t.t_startpc);
		} else {
			mdb_printf(" %s/%u", p.p_user.u_comm, t.t_tid);
		}
		mdb_printf("\n");
		return (DCMD_OK);
	}

	if ((((uintptr_t)start) & 0x7) != 0) {
		start = (caddr_t)((((uintptr_t)start) & (~0x7)) + 8);
	}
	end = (caddr_t)(((uintptr_t)end) & (~0x7));
	/* size to scan in userland copy of kernel stack */
	usize = end - start; /* is a multiple of 8 bytes */

	/*
	 * Stackinfo pattern size is 8 bytes. Ensure proper 8 bytes
	 * alignement for ustart and uend, in boundaries.
	 */
	ustart = ustack = (caddr_t)mdb_alloc(usize + 8, UM_SLEEP);
	if ((((uintptr_t)ustart) & 0x7) != 0) {
		ustart = (caddr_t)((((uintptr_t)ustart) & (~0x7)) + 8);
	}
	uend = ustart + usize;

	/* read the kernel stack */
	if (mdb_vread(ustart, usize, (uintptr_t)start) != usize) {
		mdb_free((void *)ustack, usize + 8);
		mdb_printf("\n");
		mdb_warn("couldn't read entire stack\n");
		return (DCMD_ERR);
	}

	/* scan the stack */
	if (t.t_stk > t.t_stkbase) {
		/* stack grows down */
#if defined(__i386) || defined(__amd64)
		/*
		 * 6 longs are pushed on stack, see thread_load(). Skip
		 * them, so if kthread has never run, percent is zero.
		 * 8 bytes alignement is preserved for a 32 bit kernel,
		 * 6 x 4 = 24, 24 is a multiple of 8.
		 */
		uend -= (6 * sizeof (long));
#endif
		ptr = (uint64_t *)((void *)ustart);
		while (ptr < (uint64_t *)((void *)uend)) {
			if (*ptr != KMEM_STKINFO_PATTERN) {
				percent = stk_compute_percent(uend,
				    ustart, (caddr_t)ptr);
				break;
			}
			ptr++;
		}
	} else {
		/* stack grows up */
		ptr = (uint64_t *)((void *)uend);
		ptr--;
		while (ptr >= (uint64_t *)((void *)ustart)) {
			if (*ptr != KMEM_STKINFO_PATTERN) {
				percent = stk_compute_percent(ustart,
				    uend, (caddr_t)ptr);
				break;
			}
			ptr--;
		}
	}

	/* thread 't0' stack is not created by thread_create() */
	if (addr == allthreads) {
		percent = 0;
	}
	if (percent != 0) {
		mdb_printf(" %3d%%", percent);
	} else {
		mdb_printf("  n/a");
	}
	if (t.t_tid == 0) {
		mdb_printf(" %a()", t.t_startpc);
	} else {
		mdb_printf(" %s/%u", p.p_user.u_comm, t.t_tid);
	}
	mdb_printf("\n");
	mdb_free((void *)ustack, usize + 8);
	return (DCMD_OK);
}

void
stackinfo_help(void)
{
	mdb_printf(
	    "Shows kernel stacks real utilization, if /etc/system "
	    "kmem_stackinfo tunable\n");
	mdb_printf(
	    "(an unsigned integer) is non zero at kthread creation time. ");
	mdb_printf("For example:\n");
	mdb_printf(
	    "          THREAD            STACK   SIZE  CUR  MAX CMD/LWPID\n");
	mdb_printf(
	    "ffffff014f5f2c20 ffffff0004153000   4f00   4%%  43%% init/1\n");
	mdb_printf(
	    "The stack size utilization for this kthread is at 4%%"
	    " of its maximum size,\n");
	mdb_printf(
	    "but has already used up to 43%%, stack size is 4f00 bytes.\n");
	mdb_printf(
	    "MAX value can be shown as n/a (not available):\n");
	mdb_printf(
	    "  - for the very first kthread (sched/1)\n");
	mdb_printf(
	    "  - kmem_stackinfo was zero at kthread creation time\n");
	mdb_printf(
	    "  - kthread has not yet run\n");
	mdb_printf("\n");
	mdb_printf("Options:\n");
	mdb_printf(
	    "-a shows also TS_FREE kthreads (interrupt kthreads)\n");
	mdb_printf(
	    "-h shows history, dead kthreads that used their "
	    "kernel stack the most\n");
	mdb_printf(
	    "\nSee Solaris Modular Debugger Guide for detailed usage.\n");
	mdb_flush();
}
