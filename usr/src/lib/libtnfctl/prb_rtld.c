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
 * Interfaces to sync up with run time linker (rtld) at process start up time
 * and at dlopen() and dlclose() time
 * In Solaris 2.6, librtld_db.so should replace this functionality.  Issues
 * to solve before libtnfctl.so can use librtld_db.so:
 * 1. Should libtnfctl.so be usable before Solaris 2.6 - If so, cannot use
 *    librtld_db.so
 * 2. libtnfctl.so will have to provide <proc_service.h> in order to use
 *    librtld_db.so.  If libtnfctl.so is now linked into a debugger that
 *    also provides <proc_service.h>, how will the two co-exist - will the
 *    linker get confused, or not ?
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/procfs.h>
#include <link.h>

#include "tnfctl.h"
#include "prb_proc_int.h"
#include "dbg.h"


static prb_status_t prb_rtld_setup(prb_proc_ctl_t *proc_p, boolean_t *synced);
static prb_status_t prb_rtld_wait(prb_proc_ctl_t *proc_p);
static prb_status_t bpt(prb_proc_ctl_t *proc_p, uintptr_t addr);
static prb_status_t unbpt(prb_proc_ctl_t *proc_p, uintptr_t addr);


/* ---------------------------------------------------------------- */
/* ----------------------- Public Functions ----------------------- */
/* ---------------------------------------------------------------- */


/*
 * prb_rtld_stalk() - setup for a breakpoint when rtld has opened or closed a
 * shared object.
 */
prb_status_t
prb_rtld_stalk(prb_proc_ctl_t *proc_p)
{
	prb_status_t	prbstat = PRB_STATUS_OK;

	DBG_TNF_PROBE_0(prb_rtld_stalk_1, "libtnfctl", "sunw%verbosity 2");

	if (!proc_p->bptaddr) {
		Elf3264_Dyn	   dentry;
		struct r_debug  r_dbg;

		if (proc_p->dbgaddr == 0) {
			DBG((void) fprintf(stderr,
				"prb_rtld_stalk: dbgaddr not set\n"));
			return (PRB_STATUS_BADARG);
		}

		prbstat = prb_proc_read(proc_p, proc_p->dbgaddr,
			&dentry, sizeof (dentry));
		if (prbstat || !dentry.d_un.d_ptr) {
			DBG((void) fprintf(stderr,
				"prb_rtld_stalk: error in d_un.d_ptr\n"));
			return (prbstat);
		}
		/* read in the debug struct that it points to */
		prbstat = prb_proc_read(proc_p, dentry.d_un.d_ptr,
			&r_dbg, sizeof (r_dbg));
		if (prbstat)
			return (prbstat);

		proc_p->bptaddr = r_dbg.r_brk;
	}
	/* plant a breakpoint trap in the pointed to function */
	prbstat = bpt(proc_p, proc_p->bptaddr);
	if (prbstat)
		return (prbstat);

	/* setup process to stop when breakpoint encountered */
	prbstat = prb_proc_tracebpt(proc_p, B_TRUE);

	return (prbstat);

}


/*
 * prb_rtld_unstalk() - remove rtld breakpoint
 */
prb_status_t
prb_rtld_unstalk(prb_proc_ctl_t *proc_p)
{
	prb_status_t	prbstat;

	DBG_TNF_PROBE_0(prb_rtld_unstalk_1, "libtnfctl", "sunw%verbosity 2");

	/* turn off BPT tracing while out of the water ... */
	prbstat = prb_proc_tracebpt(proc_p, B_FALSE);

	prbstat = unbpt(proc_p, proc_p->bptaddr);

	return (prbstat);
}


/*
 * prb_rtld_advance() - we've hit a breakpoint, replace the original
 * instruction, istep, put the breakpoint back ...
 */
prb_status_t
prb_rtld_advance(prb_proc_ctl_t *proc_p)
{
	prb_status_t	prbstat;

	DBG_TNF_PROBE_0(prb_rtld_advance_1, "libtnfctl", "sunw%verbosity 2");

	prbstat = prb_proc_clrbptflt(proc_p);
	if (prbstat)
		return (prbstat);
	prbstat = unbpt(proc_p, proc_p->bptaddr);
	if (prbstat)
		return (prbstat);

	prbstat = prb_proc_istepbpt(proc_p);
	if (prbstat)
		return (prbstat);

	prbstat = bpt(proc_p, proc_p->bptaddr);
	if (prbstat)
		return (prbstat);

	return (PRB_STATUS_OK);
}

/*
 * checks if process has reached rtld_sync point or not i.e. has rltld
 * loaded in libraries or not ?  If not, it lets process run until
 * rtld has mapped in all libraries (no user code would have been
 * executed, including .init sections)
 */
prb_status_t
prb_rtld_sync_if_needed(prb_proc_ctl_t *proc_p)
{
	prb_status_t	prbstat = PRB_STATUS_OK;
	boolean_t	synced = B_FALSE;

	prbstat = prb_rtld_setup(proc_p, &synced);
	if (prbstat)
		return (prbstat);

	if (synced == B_FALSE) {
		/* wait on target to sync up after rtld maps in all .so's */
		prbstat = prb_rtld_wait(proc_p);
		if (prbstat)
			return (prbstat);
	}

	return (prbstat);
}

/* ---------------------------------------------------------------- */
/* ----------------------- Private Functions ---------------------- */
/* ---------------------------------------------------------------- */

/*
 * prb_rtld_setup() - turns on the flag in the rtld structure so that rtld
 * executes a getpid() stystem call after it done mapping all shared objects
 * but before it executes any init code.
 */
static prb_status_t
prb_rtld_setup(prb_proc_ctl_t *proc_p, boolean_t *synced)
{
	prb_status_t	prbstat = PRB_STATUS_OK;
	Elf3264_Dyn	dentry;

	DBG_TNF_PROBE_0(prb_rtld_setup_1, "libtnfctl", "sunw%verbosity 2");

	if (proc_p->dbgaddr == 0) {
		DBG((void) fprintf(stderr,
			"prb_rtld_setup: dbgaddr not set\n"));
		return (PRB_STATUS_BADARG);
	}

	prbstat = prb_proc_read(proc_p, proc_p->dbgaddr, &dentry,
					sizeof (dentry));
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_setup: error in d_un.d_ptr\n"));
		return (prbstat);
	}

	if ((dentry.d_un.d_ptr == 0) || (dentry.d_un.d_ptr == 1)) {
		*synced = B_FALSE;
	} else {
		*synced = B_TRUE;
		return (PRB_STATUS_OK);
	}

	/* modify it  - i.e. request rtld to do getpid() */
	dentry.d_un.d_ptr = 1;
	prbstat = prb_proc_write(proc_p, proc_p->dbgaddr, &dentry,
					sizeof (dentry));

	return (prbstat);
}


/*
 * prb_rtld_wait() - waits on target to execute getpid()
 */
static prb_status_t
prb_rtld_wait(prb_proc_ctl_t *proc_p)
{
	prb_proc_state_t pstate;
	prb_status_t	prbstat;

	DBG_TNF_PROBE_0(prb_rtld_wait_1, "libtnfctl", "sunw%verbosity 2");

	/* stop on exit of getpid() */
	prbstat = prb_proc_exit(proc_p, SYS_getpid, PRB_SYS_ADD);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't set up child to stop on "
			"exit of getpid(): %s\n", prb_status_str(prbstat)));
		return (prbstat);
	}
	/* stop on entry of exit() - i.e. exec failed */
	prbstat = prb_proc_entry(proc_p, SYS_exit, PRB_SYS_ADD);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't set up child to stop on "
			"entry of exit(): %s\n", prb_status_str(prbstat)));
		return (prbstat);
	}
	/* continue target and wait for it to stop */
	prbstat = prb_proc_cont(proc_p);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't continue target process: %s\n",
				prb_status_str(prbstat)));
		return (prbstat);
	}
	/* wait for target to stop */
	prbstat = prb_proc_wait(proc_p, B_FALSE, NULL);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't wait on target process: %s\n",
			prb_status_str(prbstat)));
		return (prbstat);
	}
	/* make sure it did stop on getpid() */
	prbstat = prb_proc_state(proc_p, &pstate);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't get state of target: %s\n",
				prb_status_str(prbstat)));
		return (prbstat);
	}
	if (pstate.ps_issysentry && (pstate.ps_syscallnum == SYS_exit)) {
		DBG((void) fprintf(stderr, "prb_rtld_wait: target exited\n"));
		return (prb_status_map(EACCES));
	}
	/* catch any other errors */
	if (!(pstate.ps_issysexit && (pstate.ps_syscallnum == SYS_getpid))) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: target didn't stop on getpid\n"));
		return (PRB_STATUS_BADSYNC);
	}
	/* clear wait on getpid */
	prbstat = prb_proc_exit(proc_p, SYS_getpid, PRB_SYS_DEL);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't clear child to stop on "
			"exit of getpid(): %s\n", prb_status_str(prbstat)));
		return (prbstat);
	}
	/* clear wait on exit */
	prbstat = prb_proc_entry(proc_p, SYS_exit, PRB_SYS_DEL);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't clear child to stop on "
			"entry of exit(): %s\n", prb_status_str(prbstat)));
		return (prbstat);
	}
	/* start-stop the process to clear it out of the system call */
	prbstat = prb_proc_prstop(proc_p);
	if (prbstat) {
		DBG((void) fprintf(stderr,
			"prb_rtld_wait: couldn't prstop child: %s\n",
			prb_status_str(prbstat)));
		return (prbstat);
	}
	return (PRB_STATUS_OK);
}


#if defined(__sparc)
#define	INS_BPT 0x91d02001
#elif defined(__i386) || defined(__amd64)
#define	INS_BPT 0xcc
#else
#error  What is your breakpoint instruction?
#endif

/*
 * plants a breakpoint at the specified location in
 * the target process, and saves the existing instruction.
 */
static prb_status_t
bpt(prb_proc_ctl_t *proc_p, uintptr_t addr)
{
	prb_status_t	prbstat;
	bptsave_t	instr;

	if (!proc_p->bpt_inserted) {

		DBG_TNF_PROBE_1(bpt_1, "libtnfctl", "sunw%verbosity 2",
			tnf_opaque, bpt_planted_at, addr);

		prbstat = prb_proc_read(proc_p, addr,
			&(proc_p->saveinstr), sizeof (proc_p->saveinstr));
		if (prbstat)
			return (prbstat);

		DBG_TNF_PROBE_1(bpt_2, "libtnfctl", "sunw%verbosity 2",
			tnf_opaque, saved_instr, (unsigned)proc_p->saveinstr);

		instr = INS_BPT;

		prbstat = prb_proc_write(proc_p, addr,
			&instr, sizeof (instr));
		if (prbstat)
			return (prbstat);

		proc_p->bpt_inserted = B_TRUE;
	}
	return (PRB_STATUS_OK);
}

/*
 * removes  a breakpoint at the specified location in
 * the target process, and replaces it with the original instruction.
 */
prb_status_t
unbpt(prb_proc_ctl_t *proc_p, uintptr_t addr)
{
	prb_status_t	prbstat;

	if (proc_p->bpt_inserted) {

		DBG_TNF_PROBE_2(unbpt_1, "libtnfctl", "sunw%verbosity 2",
			tnf_opaque, unplanting_at, addr,
			tnf_opaque, saved_instr, (unsigned)proc_p->saveinstr);

		prbstat = prb_proc_write(proc_p, addr, &(proc_p->saveinstr),
			sizeof (proc_p->saveinstr));
		if (prbstat)
			return (prbstat);

		proc_p->bpt_inserted = B_FALSE;
	}
	return (PRB_STATUS_OK);
}
