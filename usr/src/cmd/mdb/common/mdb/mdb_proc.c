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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2015 Joyent, Inc.
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

/*
 * User Process Target
 *
 * The user process target is invoked when the -u or -p command-line options
 * are used, or when an ELF executable file or ELF core file is specified on
 * the command-line.  This target is also selected by default when no target
 * options are present.  In this case, it defaults the executable name to
 * "a.out".  If no process or core file is currently attached, the target
 * functions as a kind of virtual /dev/zero (in accordance with adb(1)
 * semantics); reads from the virtual address space return zeroes and writes
 * fail silently.  The proc target itself is designed as a wrapper around the
 * services provided by libproc.so: t->t_pshandle is set to the struct
 * ps_prochandle pointer returned as a handle by libproc.  The target also
 * opens the executable file itself using the MDB GElf services, for
 * interpreting the .symtab and .dynsym if no libproc handle has been
 * initialized, and for handling i/o to and from the object file.  Currently,
 * the only ISA-dependent portions of the proc target are the $r and ::fpregs
 * dcmds, the callbacks for t_next() and t_step_out(), and the list of named
 * registers; these are linked in from the proc_isadep.c file for each ISA and
 * called from the common code in this file.
 *
 * The user process target implements complete user process control using the
 * facilities provided by libproc.so.  The MDB execution control model and
 * an overview of software event management is described in mdb_target.c.  The
 * proc target implements breakpoints by replacing the instruction of interest
 * with a trap instruction, and then restoring the original instruction to step
 * over the breakpoint.  The idea of replacing program text with instructions
 * that transfer control to the debugger dates back as far as 1951 [1].  When
 * the target stops, we replace each breakpoint with the original instruction
 * as part of the disarm operation.  This means that no special processing is
 * required for t_vread() because the instrumented instructions will never be
 * seen by the debugger once the target stops.  Some debuggers have improved
 * start/stop performance by leaving breakpoint traps in place and then
 * handling a read from a breakpoint address as a special case.  Although this
 * improves efficiency for a source-level debugger, it runs somewhat contrary
 * to the philosophy of the low-level debugger.  Since we remove the
 * instructions, users can apply other external debugging tools to the process
 * once it has stopped (e.g. the proc(1) tools) and not be misled by MDB
 * instrumentation.  The tracing of faults, signals, system calls, and
 * watchpoints and general process inspection is implemented directly using
 * the mechanisms provided by /proc, as described originally in [2] and [3].
 *
 * References
 *
 * [1] S. Gill, "The Diagnosis Of Mistakes In Programmes on the EDSAC",
 *     Proceedings of the Royal Society Series A Mathematical and Physical
 *     Sciences, Cambridge University Press, 206(1087), May 1951, pp. 538-554.
 *
 * [2] T.J. Killian, "Processes as Files", Proceedings of the USENIX Association
 *     Summer Conference, Salt Lake City, June 1984, pp. 203-207.
 *
 * [3] Roger Faulkner and Ron Gomes, "The Process File System and Process
 *     Model in UNIX System V", Proceedings of the USENIX Association
 *     Winter Conference, Dallas, January 1991, pp. 243-252.
 */

#include <mdb/mdb_proc.h>
#include <mdb/mdb_disasm.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb.h>

#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <termio.h>
#include <signal.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>

#define	PC_FAKE		-1UL			/* illegal pc value unequal 0 */
#define	PANIC_BUFSIZE	1024

static const char PT_EXEC_PATH[] = "a.out";	/* Default executable */
static const char PT_CORE_PATH[] = "core";	/* Default core file */

static const pt_ptl_ops_t proc_lwp_ops;
static const pt_ptl_ops_t proc_tdb_ops;
static const mdb_se_ops_t proc_brkpt_ops;
static const mdb_se_ops_t proc_wapt_ops;

static int pt_setrun(mdb_tgt_t *, mdb_tgt_status_t *, int);
static void pt_activate_common(mdb_tgt_t *);
static mdb_tgt_vespec_f pt_ignore_sig;
static mdb_tgt_se_f pt_fork;
static mdb_tgt_se_f pt_exec;

static int pt_lookup_by_name_thr(mdb_tgt_t *, const char *,
    const char *, GElf_Sym *, mdb_syminfo_t *, mdb_tgt_tid_t);
static int tlsbase(mdb_tgt_t *, mdb_tgt_tid_t, Lmid_t, const char *,
    psaddr_t *);

/*
 * When debugging postmortem, we don't resolve names as we may very well not
 * be on a system on which those names resolve.
 */
#define	PT_LIBPROC_RESOLVE(P) \
	(!(mdb.m_flags & MDB_FL_LMRAW) && Pstate(P) != PS_DEAD)

/*
 * The Perror_printf() function interposes on the default, empty libproc
 * definition.  It will be called to report additional information on complex
 * errors, such as a corrupt core file.  We just pass the args to vwarn.
 */
/*ARGSUSED*/
void
Perror_printf(struct ps_prochandle *P, const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vwarn(format, alist);
	va_end(alist);
}

/*
 * Open the specified i/o backend as the a.out executable file, and attempt to
 * load its standard and dynamic symbol tables.  Note that if mdb_gelf_create
 * succeeds, io is assigned to p_fio and is automatically held by gelf_create.
 */
static mdb_gelf_file_t *
pt_open_aout(mdb_tgt_t *t, mdb_io_t *io)
{
	pt_data_t *pt = t->t_data;
	GElf_Sym s1, s2;

	if ((pt->p_file = mdb_gelf_create(io, ET_NONE, GF_FILE)) == NULL)
		return (NULL);

	pt->p_symtab = mdb_gelf_symtab_create_file(pt->p_file,
	    SHT_SYMTAB, MDB_TGT_SYMTAB);
	pt->p_dynsym = mdb_gelf_symtab_create_file(pt->p_file,
	    SHT_DYNSYM, MDB_TGT_DYNSYM);

	/*
	 * If we've got an _start symbol with a zero size, prime the private
	 * symbol table with a copy of _start with its size set to the distance
	 * between _mcount and _start.  We do this because DevPro has shipped
	 * the Intel crt1.o without proper .size directives for years, which
	 * precludes proper identification of _start in stack traces.
	 */
	if (mdb_gelf_symtab_lookup_by_name(pt->p_dynsym, "_start", &s1,
	    NULL) == 0 && s1.st_size == 0 &&
	    GELF_ST_TYPE(s1.st_info) == STT_FUNC) {
		if (mdb_gelf_symtab_lookup_by_name(pt->p_dynsym, "_mcount",
		    &s2, NULL) == 0 && GELF_ST_TYPE(s2.st_info) == STT_FUNC) {
			s1.st_size = s2.st_value - s1.st_value;
			mdb_gelf_symtab_insert(mdb.m_prsym, "_start", &s1);
		}
	}

	pt->p_fio = io;
	return (pt->p_file);
}

/*
 * Destroy the symbol tables and GElf file object associated with p_fio.  Note
 * that we do not need to explicitly free p_fio: its reference count is
 * automatically decremented by mdb_gelf_destroy, which will free it if needed.
 */
static void
pt_close_aout(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;

	if (pt->p_symtab != NULL) {
		mdb_gelf_symtab_destroy(pt->p_symtab);
		pt->p_symtab = NULL;
	}

	if (pt->p_dynsym != NULL) {
		mdb_gelf_symtab_destroy(pt->p_dynsym);
		pt->p_dynsym = NULL;
	}

	if (pt->p_file != NULL) {
		mdb_gelf_destroy(pt->p_file);
		pt->p_file = NULL;
	}

	mdb_gelf_symtab_delete(mdb.m_prsym, "_start", NULL);
	pt->p_fio = NULL;
}

typedef struct tdb_mapping {
	const char *tm_thr_lib;
	const char *tm_db_dir;
	const char *tm_db_name;
} tdb_mapping_t;

static const tdb_mapping_t tdb_map[] = {
	{ "/lwp/amd64/libthread.so",	"/usr/lib/lwp/", "libthread_db.so" },
	{ "/lwp/sparcv9/libthread.so",	"/usr/lib/lwp/", "libthread_db.so" },
	{ "/lwp/libthread.so",		"/usr/lib/lwp/", "libthread_db.so" },
	{ "/libthread.so",		"/lib/", "libthread_db.so" },
	{ "/libc_hwcap",		"/lib/", "libc_db.so" },
	{ "/libc.so",			"/lib/", "libc_db.so" }
};

/*
 * Pobject_iter callback that we use to search for the presence of libthread in
 * order to load the corresponding libthread_db support.  We derive the
 * libthread_db path dynamically based on the libthread path.  If libthread is
 * found, this function returns 1 (and thus Pobject_iter aborts and returns 1)
 * regardless of whether it was successful in loading the libthread_db support.
 * If we iterate over all objects and no libthread is found, 0 is returned.
 * Since libthread_db support was then merged into libc_db, we load either
 * libc_db or libthread_db, depending on which library we see first.
 */
/*ARGSUSED*/
static int
thr_check(mdb_tgt_t *t, const prmap_t *pmp, const char *name)
{
	pt_data_t *pt = t->t_data;
	const mdb_tdb_ops_t *ops;
	char *p;

	char path[MAXPATHLEN];

	int libn;

	if (name == NULL)
		return (0); /* no rtld_db object name; keep going */

	for (libn = 0; libn < sizeof (tdb_map) / sizeof (tdb_map[0]); libn++) {
		if ((p = strstr(name, tdb_map[libn].tm_thr_lib)) != NULL)
			break;
	}

	if (p == NULL)
		return (0); /* no match; keep going */

	path[0] = '\0';
	(void) strlcat(path, mdb.m_root, sizeof (path));
	(void) strlcat(path, tdb_map[libn].tm_db_dir, sizeof (path));
#if !defined(_ILP32)
	(void) strlcat(path, "64/", sizeof (path));
#endif /* !_ILP32 */
	(void) strlcat(path, tdb_map[libn].tm_db_name, sizeof (path));

	/* Append the trailing library version number. */
	(void) strlcat(path, strrchr(name, '.'), sizeof (path));

	if ((ops = mdb_tdb_load(path)) == NULL) {
		if (libn != 0 || errno != ENOENT)
			warn("failed to load %s", path);
		goto err;
	}

	if (ops == pt->p_tdb_ops)
		return (1); /* no changes needed */

	PTL_DTOR(t);
	pt->p_tdb_ops = ops;
	pt->p_ptl_ops = &proc_tdb_ops;
	pt->p_ptl_hdl = NULL;

	if (PTL_CTOR(t) == -1) {
		warn("failed to initialize %s", path);
		goto err;
	}

	mdb_dprintf(MDB_DBG_TGT, "loaded %s for debugging %s\n", path, name);
	(void) mdb_tgt_status(t, &t->t_status);
	return (1);
err:
	PTL_DTOR(t);
	pt->p_tdb_ops = NULL;
	pt->p_ptl_ops = &proc_lwp_ops;
	pt->p_ptl_hdl = NULL;

	if (libn != 0 || errno != ENOENT) {
		warn("warning: debugger will only be able to "
		    "examine raw LWPs\n");
	}

	(void) mdb_tgt_status(t, &t->t_status);
	return (1);
}

/*
 * Whenever the link map is consistent following an add or delete event, we ask
 * libproc to update its mappings, check to see if we need to load libthread_db,
 * and then update breakpoints which have been mapped or unmapped.
 */
/*ARGSUSED*/
static void
pt_rtld_event(mdb_tgt_t *t, int vid, void *private)
{
	struct ps_prochandle *P = t->t_pshandle;
	pt_data_t *pt = t->t_data;
	rd_event_msg_t rdm;
	int docontinue = 1;

	if (rd_event_getmsg(pt->p_rtld, &rdm) == RD_OK) {

		mdb_dprintf(MDB_DBG_TGT, "rtld event type 0x%x state 0x%x\n",
		    rdm.type, rdm.u.state);

		if (rdm.type == RD_DLACTIVITY && rdm.u.state == RD_CONSISTENT) {
			mdb_sespec_t *sep, *nsep = mdb_list_next(&t->t_active);
			pt_brkpt_t *ptb;

			Pupdate_maps(P);

			if (Pobject_iter(P, (proc_map_f *)thr_check, t) == 0 &&
			    pt->p_ptl_ops != &proc_lwp_ops) {
				mdb_dprintf(MDB_DBG_TGT, "unloading thread_db "
				    "support after dlclose\n");
				PTL_DTOR(t);
				pt->p_tdb_ops = NULL;
				pt->p_ptl_ops = &proc_lwp_ops;
				pt->p_ptl_hdl = NULL;
				(void) mdb_tgt_status(t, &t->t_status);
			}

			for (sep = nsep; sep != NULL; sep = nsep) {
				nsep = mdb_list_next(sep);
				ptb = sep->se_data;

				if (sep->se_ops == &proc_brkpt_ops &&
				    Paddr_to_map(P, ptb->ptb_addr) == NULL)
					mdb_tgt_sespec_idle_one(t, sep,
					    EMDB_NOMAP);
			}

			if (!mdb_tgt_sespec_activate_all(t) &&
			    (mdb.m_flags & MDB_FL_BPTNOSYMSTOP) &&
			    pt->p_rtld_finished) {
				/*
				 * We weren't able to activate the breakpoints.
				 * If so requested, we'll return without
				 * calling continue, thus throwing the user into
				 * the debugger.
				 */
				docontinue = 0;
			}

			if (pt->p_rdstate == PT_RD_ADD)
				pt->p_rdstate = PT_RD_CONSIST;
		}

		if (rdm.type == RD_PREINIT)
			(void) mdb_tgt_sespec_activate_all(t);

		if (rdm.type == RD_POSTINIT) {
			pt->p_rtld_finished = TRUE;
			if (!mdb_tgt_sespec_activate_all(t) &&
			    (mdb.m_flags & MDB_FL_BPTNOSYMSTOP)) {
				/*
				 * Now that rtld has been initialized, we
				 * should be able to initialize all deferred
				 * breakpoints.  If we can't, don't let the
				 * target continue.
				 */
				docontinue = 0;
			}
		}

		if (rdm.type == RD_DLACTIVITY && rdm.u.state == RD_ADD &&
		    pt->p_rtld_finished)
			pt->p_rdstate = MAX(pt->p_rdstate, PT_RD_ADD);
	}

	if (docontinue)
		(void) mdb_tgt_continue(t, NULL);
}

static void
pt_post_attach(mdb_tgt_t *t)
{
	struct ps_prochandle *P = t->t_pshandle;
	const lwpstatus_t *psp = &Pstatus(P)->pr_lwp;
	pt_data_t *pt = t->t_data;
	int hflag = MDB_TGT_SPEC_HIDDEN;

	mdb_dprintf(MDB_DBG_TGT, "attach pr_flags=0x%x pr_why=%d pr_what=%d\n",
	    psp->pr_flags, psp->pr_why, psp->pr_what);

	/*
	 * When we grab a process, the initial setting of p_rtld_finished
	 * should be false if the process was just created by exec; otherwise
	 * we permit unscoped references to resolve because we do not know how
	 * far the process has proceeded through linker initialization.
	 */
	if ((psp->pr_flags & PR_ISTOP) && psp->pr_why == PR_SYSEXIT &&
	    psp->pr_errno == 0 && psp->pr_what == SYS_execve) {
		if (mdb.m_target == NULL) {
			warn("target performed exec of %s\n",
			    IOP_NAME(pt->p_fio));
		}
		pt->p_rtld_finished = FALSE;
	} else
		pt->p_rtld_finished = TRUE;

	/*
	 * When we grab a process, if it is stopped by job control and part of
	 * the same session (i.e. same controlling tty), set MDB_FL_JOBCTL so
	 * we will know to bring it to the foreground when we continue it.
	 */
	if (mdb.m_term != NULL && (psp->pr_flags & PR_STOPPED) &&
	    psp->pr_why == PR_JOBCONTROL && getsid(0) == Pstatus(P)->pr_sid)
		mdb.m_flags |= MDB_FL_JOBCTL;

	/*
	 * When we grab control of a live process, set F_RDWR so that the
	 * target layer permits writes to the target's address space.
	 */
	t->t_flags |= MDB_TGT_F_RDWR;

	(void) Pfault(P, FLTBPT, TRUE);		/* always trace breakpoints */
	(void) Pfault(P, FLTWATCH, TRUE);	/* always trace watchpoints */
	(void) Pfault(P, FLTTRACE, TRUE);	/* always trace single-step */

	(void) Punsetflags(P, PR_ASYNC);	/* require synchronous mode */
	(void) Psetflags(P, PR_BPTADJ);		/* always adjust eip on x86 */
	(void) Psetflags(P, PR_FORK);		/* inherit tracing on fork */

	/*
	 * Install event specifiers to track fork and exec activities:
	 */
	(void) mdb_tgt_add_sysexit(t, SYS_vfork, hflag, pt_fork, NULL);
	(void) mdb_tgt_add_sysexit(t, SYS_forksys, hflag, pt_fork, NULL);
	(void) mdb_tgt_add_sysexit(t, SYS_execve, hflag, pt_exec, NULL);

	/*
	 * Attempt to instantiate the librtld_db agent and set breakpoints
	 * to track rtld activity.  We will legitimately fail to instantiate
	 * the rtld_db agent if the target is statically linked.
	 */
	if (pt->p_rtld == NULL && (pt->p_rtld = Prd_agent(P)) != NULL) {
		rd_notify_t rdn;
		rd_err_e err;

		if ((err = rd_event_enable(pt->p_rtld, TRUE)) != RD_OK) {
			warn("failed to enable rtld_db event tracing: %s\n",
			    rd_errstr(err));
			goto out;
		}

		if ((err = rd_event_addr(pt->p_rtld, RD_PREINIT,
		    &rdn)) == RD_OK && rdn.type == RD_NOTIFY_BPT) {
			(void) mdb_tgt_add_vbrkpt(t, rdn.u.bptaddr,
			    hflag, pt_rtld_event, NULL);
		} else {
			warn("failed to install rtld_db preinit tracing: %s\n",
			    rd_errstr(err));
		}

		if ((err = rd_event_addr(pt->p_rtld, RD_POSTINIT,
		    &rdn)) == RD_OK && rdn.type == RD_NOTIFY_BPT) {
			(void) mdb_tgt_add_vbrkpt(t, rdn.u.bptaddr,
			    hflag, pt_rtld_event, NULL);
		} else {
			warn("failed to install rtld_db postinit tracing: %s\n",
			    rd_errstr(err));
		}

		if ((err = rd_event_addr(pt->p_rtld, RD_DLACTIVITY,
		    &rdn)) == RD_OK && rdn.type == RD_NOTIFY_BPT) {
			(void) mdb_tgt_add_vbrkpt(t, rdn.u.bptaddr,
			    hflag, pt_rtld_event, NULL);
		} else {
			warn("failed to install rtld_db activity tracing: %s\n",
			    rd_errstr(err));
		}
	}
out:
	Pupdate_maps(P);
	Psync(P);

	/*
	 * If librtld_db failed to initialize due to an error or because we are
	 * debugging a statically linked executable, allow unscoped references.
	 */
	if (pt->p_rtld == NULL)
		pt->p_rtld_finished = TRUE;

	(void) mdb_tgt_sespec_activate_all(t);
}

/*ARGSUSED*/
static int
pt_vespec_delete(mdb_tgt_t *t, void *private, int id, void *data)
{
	if (id < 0) {
		ASSERT(data == NULL); /* we don't use any ve_data */
		(void) mdb_tgt_vespec_delete(t, id);
	}
	return (0);
}

static void
pt_pre_detach(mdb_tgt_t *t, int clear_matched)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	pt_data_t *pt = t->t_data;
	long cmd = 0;

	/*
	 * If we are about to release the process and it is stopped on a traced
	 * SIGINT, breakpoint fault, single-step fault, or watchpoint, make
	 * sure to clear this event prior to releasing the process so that it
	 * does not subsequently reissue the fault and die from SIGTRAP.
	 */
	if (psp->pr_flags & PR_ISTOP) {
		if (psp->pr_why == PR_FAULTED && (psp->pr_what == FLTBPT ||
		    psp->pr_what == FLTTRACE || psp->pr_what == FLTWATCH))
			cmd = PCCFAULT;
		else if (psp->pr_why == PR_SIGNALLED && psp->pr_what == SIGINT)
			cmd = PCCSIG;

		if (cmd != 0)
			(void) write(Pctlfd(t->t_pshandle), &cmd, sizeof (cmd));
	}

	if (Pstate(t->t_pshandle) == PS_UNDEAD)
		(void) waitpid(Pstatus(t->t_pshandle)->pr_pid, NULL, WNOHANG);

	(void) mdb_tgt_vespec_iter(t, pt_vespec_delete, NULL);
	mdb_tgt_sespec_idle_all(t, EMDB_NOPROC, clear_matched);

	if (pt->p_fio != pt->p_aout_fio) {
		pt_close_aout(t);
		(void) pt_open_aout(t, pt->p_aout_fio);
	}

	PTL_DTOR(t);
	pt->p_tdb_ops = NULL;
	pt->p_ptl_ops = &proc_lwp_ops;
	pt->p_ptl_hdl = NULL;

	pt->p_rtld = NULL;
	pt->p_signal = 0;
	pt->p_rtld_finished = FALSE;
	pt->p_rdstate = PT_RD_NONE;
}

static void
pt_release_parents(mdb_tgt_t *t)
{
	struct ps_prochandle *P = t->t_pshandle;
	pt_data_t *pt = t->t_data;

	mdb_sespec_t *sep;
	pt_vforkp_t *vfp;

	while ((vfp = mdb_list_next(&pt->p_vforkp)) != NULL) {
		mdb_dprintf(MDB_DBG_TGT, "releasing vfork parent %d\n",
		    (int)Pstatus(vfp->p_pshandle)->pr_pid);

		/*
		 * To release vfork parents, we must also wipe out any armed
		 * events in the parent by switching t_pshandle and calling
		 * se_disarm().  Do not change states or lose the matched list.
		 */
		t->t_pshandle = vfp->p_pshandle;

		for (sep = mdb_list_next(&t->t_active); sep != NULL;
		    sep = mdb_list_next(sep)) {
			if (sep->se_state == MDB_TGT_SPEC_ARMED)
				(void) sep->se_ops->se_disarm(t, sep);
		}

		t->t_pshandle = P;

		Prelease(vfp->p_pshandle, PRELEASE_CLEAR);
		mdb_list_delete(&pt->p_vforkp, vfp);
		mdb_free(vfp, sizeof (pt_vforkp_t));
	}
}

/*ARGSUSED*/
static void
pt_fork(mdb_tgt_t *t, int vid, void *private)
{
	struct ps_prochandle *P = t->t_pshandle;
	const lwpstatus_t *psp = &Pstatus(P)->pr_lwp;
	pt_data_t *pt = t->t_data;
	mdb_sespec_t *sep;

	int follow_parent = mdb.m_forkmode != MDB_FM_CHILD;
	int is_vfork = (psp->pr_what == SYS_vfork ||
	    (psp->pr_what == SYS_forksys && psp->pr_sysarg[0] == 2));

	struct ps_prochandle *C;
	const lwpstatus_t *csp;
	char sysname[32];
	int gcode;
	char c;

	mdb_dprintf(MDB_DBG_TGT, "parent %s: errno=%d rv1=%ld rv2=%ld\n",
	    proc_sysname(psp->pr_what, sysname, sizeof (sysname)),
	    psp->pr_errno, psp->pr_rval1, psp->pr_rval2);

	if (psp->pr_errno != 0) {
		(void) mdb_tgt_continue(t, NULL);
		return; /* fork failed */
	}

	/*
	 * If forkmode is ASK and stdout is a terminal, then ask the user to
	 * explicitly set the fork behavior for this particular fork.
	 */
	if (mdb.m_forkmode == MDB_FM_ASK && mdb.m_term != NULL) {
		mdb_iob_printf(mdb.m_err, "%s: %s detected: follow (p)arent "
		    "or (c)hild? ", mdb.m_pname, sysname);
		mdb_iob_flush(mdb.m_err);

		while (IOP_READ(mdb.m_term, &c, sizeof (c)) == sizeof (c)) {
			if (c == 'P' || c == 'p') {
				mdb_iob_printf(mdb.m_err, "%c\n", c);
				follow_parent = TRUE;
				break;
			} else if (c == 'C' || c == 'c') {
				mdb_iob_printf(mdb.m_err, "%c\n", c);
				follow_parent = FALSE;
				break;
			}
		}
	}

	/*
	 * The parent is now stopped on exit from its fork call.  We must now
	 * grab the child on its return from fork in order to manipulate it.
	 */
	if ((C = Pgrab(psp->pr_rval1, PGRAB_RETAIN, &gcode)) == NULL) {
		warn("failed to grab forked child process %ld: %s\n",
		    psp->pr_rval1, Pgrab_error(gcode));
		return; /* just stop if we failed to grab the child */
	}

	/*
	 * We may have grabbed the child and stopped it prematurely before it
	 * stopped on exit from fork.  If so, wait up to 1 sec for it to settle.
	 */
	if (Pstatus(C)->pr_lwp.pr_why != PR_SYSEXIT)
		(void) Pwait(C, MILLISEC);

	csp = &Pstatus(C)->pr_lwp;

	if (csp->pr_why != PR_SYSEXIT ||
	    (csp->pr_what != SYS_vfork && csp->pr_what != SYS_forksys)) {
		warn("forked child process %ld did not stop on exit from "
		    "fork as expected\n", psp->pr_rval1);
	}

	warn("target forked child process %ld (debugger following %s)\n",
	    psp->pr_rval1, follow_parent ? "parent" : "child");

	(void) Punsetflags(C, PR_ASYNC);	/* require synchronous mode */
	(void) Psetflags(C, PR_BPTADJ);		/* always adjust eip on x86 */
	(void) Prd_agent(C);			/* initialize librtld_db */

	/*
	 * At the time pt_fork() is called, the target event engine has already
	 * disarmed the specifiers on the active list, clearing out events in
	 * the parent process.  However, this means that events that change
	 * the address space (e.g. breakpoints) have not been effectively
	 * disarmed in the child since its address space reflects the state of
	 * the process at the time of fork when events were armed.  We must
	 * therefore handle this as a special case and re-invoke the disarm
	 * callback of each active specifier to clean out the child process.
	 */
	if (!is_vfork) {
		for (t->t_pshandle = C, sep = mdb_list_next(&t->t_active);
		    sep != NULL; sep = mdb_list_next(sep)) {
			if (sep->se_state == MDB_TGT_SPEC_ACTIVE)
				(void) sep->se_ops->se_disarm(t, sep);
		}

		t->t_pshandle = P; /* restore pshandle to parent */
	}

	/*
	 * If we're following the parent process, we need to temporarily change
	 * t_pshandle to refer to the child handle C so that we can clear out
	 * all the events in the child prior to releasing it below.  If we are
	 * tracing a vfork, we also need to explicitly wait for the child to
	 * exec, exit, or die before we can reset and continue the parent.  We
	 * avoid having to deal with the vfork child forking again by clearing
	 * PR_FORK and setting PR_RLC; if it does fork it will effectively be
	 * released from our control and we will continue following the parent.
	 */
	if (follow_parent) {
		if (is_vfork) {
			mdb_tgt_status_t status;

			ASSERT(psp->pr_flags & PR_VFORKP);
			mdb_tgt_sespec_idle_all(t, EBUSY, FALSE);
			t->t_pshandle = C;

			(void) Psysexit(C, SYS_execve, TRUE);

			(void) Punsetflags(C, PR_FORK | PR_KLC);
			(void) Psetflags(C, PR_RLC);

			do {
				if (pt_setrun(t, &status, 0) == -1 ||
				    status.st_state == MDB_TGT_UNDEAD ||
				    status.st_state == MDB_TGT_LOST)
					break; /* failure or process died */

			} while (csp->pr_why != PR_SYSEXIT ||
			    csp->pr_errno != 0 || csp->pr_what != SYS_execve);
		} else
			t->t_pshandle = C;
	}

	/*
	 * If we are following the child, destroy any active libthread_db
	 * handle before we release the parent process.
	 */
	if (!follow_parent) {
		PTL_DTOR(t);
		pt->p_tdb_ops = NULL;
		pt->p_ptl_ops = &proc_lwp_ops;
		pt->p_ptl_hdl = NULL;
	}

	/*
	 * Idle all events to make sure the address space and tracing flags are
	 * restored, and then release the process we are not tracing.  If we
	 * are following the child of a vfork, we push the parent's pshandle
	 * on to a list of vfork parents to be released when we exec or exit.
	 */
	if (is_vfork && !follow_parent) {
		pt_vforkp_t *vfp = mdb_alloc(sizeof (pt_vforkp_t), UM_SLEEP);

		ASSERT(psp->pr_flags & PR_VFORKP);
		vfp->p_pshandle = P;
		mdb_list_append(&pt->p_vforkp, vfp);
		mdb_tgt_sespec_idle_all(t, EBUSY, FALSE);

	} else {
		mdb_tgt_sespec_idle_all(t, EBUSY, FALSE);
		Prelease(t->t_pshandle, PRELEASE_CLEAR);
		if (!follow_parent)
			pt_release_parents(t);
	}

	/*
	 * Now that all the hard stuff is done, switch t_pshandle back to the
	 * process we are following and reset our events to the ACTIVE state.
	 * If we are following the child, reset the libthread_db handle as well
	 * as the rtld agent.
	 */
	if (follow_parent)
		t->t_pshandle = P;
	else {
		t->t_pshandle = C;
		pt->p_rtld = Prd_agent(C);
		(void) Pobject_iter(t->t_pshandle, (proc_map_f *)thr_check, t);
	}

	(void) mdb_tgt_sespec_activate_all(t);
	(void) mdb_tgt_continue(t, NULL);
}

/*ARGSUSED*/
static void
pt_exec(mdb_tgt_t *t, int vid, void *private)
{
	struct ps_prochandle *P = t->t_pshandle;
	const pstatus_t *psp = Pstatus(P);
	pt_data_t *pt = t->t_data;
	int follow_exec = mdb.m_execmode == MDB_EM_FOLLOW;
	pid_t pid = psp->pr_pid;

	char execname[MAXPATHLEN];
	mdb_sespec_t *sep, *nsep;
	mdb_io_t *io;
	char c;

	mdb_dprintf(MDB_DBG_TGT, "exit from %s: errno=%d\n", proc_sysname(
	    psp->pr_lwp.pr_what, execname, sizeof (execname)),
	    psp->pr_lwp.pr_errno);

	if (psp->pr_lwp.pr_errno != 0) {
		(void) mdb_tgt_continue(t, NULL);
		return; /* exec failed */
	}

	/*
	 * If execmode is ASK and stdout is a terminal, then ask the user to
	 * explicitly set the exec behavior for this particular exec.  If
	 * Pstate() still shows PS_LOST, we are being called from pt_setrun()
	 * directly and therefore we must resume the terminal since it is still
	 * in the suspended state as far as tgt_continue() is concerned.
	 */
	if (mdb.m_execmode == MDB_EM_ASK && mdb.m_term != NULL) {
		if (Pstate(P) == PS_LOST)
			IOP_RESUME(mdb.m_term);

		mdb_iob_printf(mdb.m_err, "%s: %s detected: (f)ollow new "
		    "program or (s)top? ", mdb.m_pname, execname);
		mdb_iob_flush(mdb.m_err);

		while (IOP_READ(mdb.m_term, &c, sizeof (c)) == sizeof (c)) {
			if (c == 'F' || c == 'f') {
				mdb_iob_printf(mdb.m_err, "%c\n", c);
				follow_exec = TRUE;
				break;
			} else if (c == 'S' || c == 's') {
				mdb_iob_printf(mdb.m_err, "%c\n", c);
				follow_exec = FALSE;
				break;
			}
		}

		if (Pstate(P) == PS_LOST)
			IOP_SUSPEND(mdb.m_term);
	}

	pt_release_parents(t);	/* release any waiting vfork parents */
	pt_pre_detach(t, FALSE); /* remove our breakpoints and idle events */
	Preset_maps(P);		/* libproc must delete mappings and symtabs */
	pt_close_aout(t);	/* free pt symbol tables and GElf file data */

	/*
	 * If we lost control of the process across the exec and are not able
	 * to reopen it, we have no choice but to clear the matched event list
	 * and wait for the user to quit or otherwise release the process.
	 */
	if (Pstate(P) == PS_LOST && Preopen(P) == -1) {
		int error = errno;

		warn("lost control of PID %d due to exec of %s executable\n",
		    (int)pid, error == EOVERFLOW ? "64-bit" : "set-id");

		for (sep = t->t_matched; sep != T_SE_END; sep = nsep) {
			nsep = sep->se_matched;
			sep->se_matched = NULL;
			mdb_tgt_sespec_rele(t, sep);
		}

		if (error != EOVERFLOW)
			return; /* just stop if we exec'd a set-id executable */
	}

	if (Pstate(P) != PS_LOST) {
		if (Pexecname(P, execname, sizeof (execname)) == NULL) {
			(void) mdb_iob_snprintf(execname, sizeof (execname),
			    "/proc/%d/object/a.out", (int)pid);
		}

		if (follow_exec == FALSE || psp->pr_dmodel == PR_MODEL_NATIVE)
			warn("target performed exec of %s\n", execname);

		io = mdb_fdio_create_path(NULL, execname, pt->p_oflags, 0);
		if (io == NULL) {
			warn("failed to open %s", execname);
			warn("a.out symbol tables will not be available\n");
		} else if (pt_open_aout(t, io) == NULL) {
			(void) mdb_dis_select(pt_disasm(NULL));
			mdb_io_destroy(io);
		} else
			(void) mdb_dis_select(pt_disasm(&pt->p_file->gf_ehdr));
	}

	/*
	 * We reset our libthread_db state here, but deliberately do NOT call
	 * PTL_DTOR because we do not want to call libthread_db's td_ta_delete.
	 * This interface is hopelessly broken in that it writes to the process
	 * address space (which we do not want it to do after an exec) and it
	 * doesn't bother deallocating any of its storage anyway.
	 */
	pt->p_tdb_ops = NULL;
	pt->p_ptl_ops = &proc_lwp_ops;
	pt->p_ptl_hdl = NULL;

	if (follow_exec && psp->pr_dmodel != PR_MODEL_NATIVE) {
		const char *argv[3];
		char *state, *env;
		char pidarg[16];
		size_t envlen;

		if (realpath(getexecname(), execname) == NULL) {
			warn("cannot follow PID %d -- failed to resolve "
			    "debugger pathname for re-exec", (int)pid);
			return;
		}

		warn("restarting debugger to follow PID %d ...\n", (int)pid);
		mdb_dprintf(MDB_DBG_TGT, "re-exec'ing %s\n", execname);

		(void) mdb_snprintf(pidarg, sizeof (pidarg), "-p%d", (int)pid);

		state = mdb_get_config();
		envlen = strlen(MDB_CONFIG_ENV_VAR) + 1 + strlen(state) + 1;
		env = mdb_alloc(envlen, UM_SLEEP);
		(void) snprintf(env, envlen,
		    "%s=%s", MDB_CONFIG_ENV_VAR, state);

		(void) putenv(env);

		argv[0] = mdb.m_pname;
		argv[1] = pidarg;
		argv[2] = NULL;

		if (mdb.m_term != NULL)
			IOP_SUSPEND(mdb.m_term);

		Prelease(P, PRELEASE_CLEAR | PRELEASE_HANG);
		(void) execv(execname, (char *const *)argv);
		warn("failed to re-exec debugger");

		if (mdb.m_term != NULL)
			IOP_RESUME(mdb.m_term);

		t->t_pshandle = pt->p_idlehandle;
		return;
	}

	pt_post_attach(t);	/* install tracing flags and activate events */
	pt_activate_common(t);	/* initialize librtld_db and libthread_db */

	if (psp->pr_dmodel != PR_MODEL_NATIVE && mdb.m_term != NULL) {
		warn("loadable dcmds will not operate on non-native %d-bit "
		    "data model\n", psp->pr_dmodel == PR_MODEL_ILP32 ? 32 : 64);
		warn("use ::release -a and then run mdb -p %d to restart "
		    "debugger\n", (int)pid);
	}

	if (follow_exec)
		(void) mdb_tgt_continue(t, NULL);
}

static int
pt_setflags(mdb_tgt_t *t, int flags)
{
	pt_data_t *pt = t->t_data;

	if ((flags ^ t->t_flags) & MDB_TGT_F_RDWR) {
		int mode = (flags & MDB_TGT_F_RDWR) ? O_RDWR : O_RDONLY;
		mdb_io_t *io;

		if (pt->p_fio == NULL)
			return (set_errno(EMDB_NOEXEC));

		io = mdb_fdio_create_path(NULL, IOP_NAME(pt->p_fio), mode, 0);

		if (io == NULL)
			return (-1); /* errno is set for us */

		t->t_flags = (t->t_flags & ~MDB_TGT_F_RDWR) |
		    (flags & MDB_TGT_F_RDWR);

		pt->p_fio = mdb_io_hold(io);
		mdb_io_rele(pt->p_file->gf_io);
		pt->p_file->gf_io = pt->p_fio;
	}

	if (flags & MDB_TGT_F_FORCE) {
		t->t_flags |= MDB_TGT_F_FORCE;
		pt->p_gflags |= PGRAB_FORCE;
	}

	return (0);
}

/*ARGSUSED*/
static int
pt_frame(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uint_t)(uintptr_t)arglim);
	mdb_printf("%a(", pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}

static int
pt_framev(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uint_t)(uintptr_t)arglim);
#if defined(__i386) || defined(__amd64)
	mdb_printf("%0?lr %a(", gregs->gregs[R_FP], pc);
#else
	mdb_printf("%0?lr %a(", gregs->gregs[R_SP], pc);
#endif
	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}

static int
pt_framer(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	if (pt_frameregs(arglim, pc, argc, argv, gregs, pc == PC_FAKE) == -1) {
		/*
		 * Use verbose format if register format is not supported.
		 */
		return (pt_framev(arglim, pc, argc, argv, gregs));
	}

	return (0);
}

/*ARGSUSED*/
static int
pt_stack_common(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv, mdb_tgt_stack_f *func, prgreg_t saved_pc)
{
	void *arg = (void *)(uintptr_t)mdb.m_nargs;
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_gregset_t gregs;

	if (argc != 0) {
		if (argv->a_type == MDB_TYPE_CHAR || argc > 1)
			return (DCMD_USAGE);

		if (argv->a_type == MDB_TYPE_STRING)
			arg = (void *)(uintptr_t)mdb_strtoull(argv->a_un.a_str);
		else
			arg = (void *)(uintptr_t)argv->a_un.a_val;
	}

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_IDLE) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	/*
	 * In the universe of sparcv7, sparcv9, ia32, and amd64 this code can be
	 * common: <sys/procfs_isa.h> conveniently #defines R_FP to be the
	 * appropriate register we need to set in order to perform a stack
	 * traceback from a given frame address.
	 */
	if (flags & DCMD_ADDRSPEC) {
		bzero(&gregs, sizeof (gregs));
		gregs.gregs[R_FP] = addr;
#ifdef __sparc
		gregs.gregs[R_I7] = saved_pc;
#endif /* __sparc */
	} else if (PTL_GETREGS(t, PTL_TID(t), gregs.gregs) != 0) {
		mdb_warn("failed to get current register set");
		return (DCMD_ERR);
	}

	(void) mdb_tgt_stack_iter(t, &gregs, func, arg);
	return (DCMD_OK);
}

static int
pt_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (pt_stack_common(addr, flags, argc, argv, pt_frame, 0));
}

static int
pt_stackv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (pt_stack_common(addr, flags, argc, argv, pt_framev, 0));
}

static int
pt_stackr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	/*
	 * Force printing of first register window, by setting  the
	 * saved pc (%i7) to PC_FAKE.
	 */
	return (pt_stack_common(addr, flags, argc, argv, pt_framer, PC_FAKE));
}

/*ARGSUSED*/
static int
pt_ignored(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct ps_prochandle *P = mdb.m_target->t_pshandle;
	char buf[PRSIGBUFSZ];

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (P == NULL) {
		mdb_warn("no process is currently active\n");
		return (DCMD_ERR);
	}

	mdb_printf("%s\n", proc_sigset2str(&Pstatus(P)->pr_sigtrace, " ",
	    FALSE, buf, sizeof (buf)));

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_lwpid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct ps_prochandle *P = mdb.m_target->t_pshandle;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (P == NULL) {
		mdb_warn("no process is currently active\n");
		return (DCMD_ERR);
	}

	mdb_printf("%d\n", Pstatus(P)->pr_lwp.pr_lwpid);
	return (DCMD_OK);
}

static int
pt_print_lwpid(int *n, const lwpstatus_t *psp)
{
	struct ps_prochandle *P = mdb.m_target->t_pshandle;
	int nlwp = Pstatus(P)->pr_nlwp;

	if (*n == nlwp - 2)
		mdb_printf("%d and ", (int)psp->pr_lwpid);
	else if (*n == nlwp - 1)
		mdb_printf("%d are", (int)psp->pr_lwpid);
	else
		mdb_printf("%d, ", (int)psp->pr_lwpid);

	(*n)++;
	return (0);
}

/*ARGSUSED*/
static int
pt_lwpids(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct ps_prochandle *P = mdb.m_target->t_pshandle;
	int n = 0;

	if (P == NULL) {
		mdb_warn("no process is currently active\n");
		return (DCMD_ERR);
	}

	switch (Pstatus(P)->pr_nlwp) {
	case 0:
		mdb_printf("no lwps are");
		break;
	case 1:
		mdb_printf("lwpid %d is the only lwp",
		    Pstatus(P)->pr_lwp.pr_lwpid);
		break;
	default:
		mdb_printf("lwpids ");
		(void) Plwp_iter(P, (proc_lwp_f *)pt_print_lwpid, &n);
	}

	switch (Pstate(P)) {
	case PS_DEAD:
		mdb_printf(" in core of process %d.\n", Pstatus(P)->pr_pid);
		break;
	case PS_IDLE:
		mdb_printf(" in idle target.\n");
		break;
	default:
		mdb_printf(" in process %d.\n", (int)Pstatus(P)->pr_pid);
		break;
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_ignore(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pt_data_t *pt = mdb.m_target->t_data;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (addr < 1 || addr > pt->p_maxsig) {
		mdb_warn("invalid signal number -- 0t%lu\n", addr);
		return (DCMD_ERR);
	}

	(void) mdb_tgt_vespec_iter(mdb.m_target, pt_ignore_sig, (void *)addr);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_attach(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	pt_data_t *pt = t->t_data;
	int state, perr;

	if (!(flags & DCMD_ADDRSPEC) && argc == 0)
		return (DCMD_USAGE);

	if (((flags & DCMD_ADDRSPEC) && argc != 0) || argc > 1 ||
	    (argc != 0 && argv->a_type != MDB_TYPE_STRING))
		return (DCMD_USAGE);

	if (t->t_pshandle != NULL && Pstate(t->t_pshandle) != PS_IDLE) {
		mdb_warn("debugger is already attached to a %s\n",
		    (Pstate(t->t_pshandle) == PS_DEAD) ? "core" : "process");
		return (DCMD_ERR);
	}

	if (pt->p_fio == NULL) {
		mdb_warn("attach requires executable to be specified on "
		    "command-line (or use -p)\n");
		return (DCMD_ERR);
	}

	if (flags & DCMD_ADDRSPEC)
		t->t_pshandle = Pgrab((pid_t)addr, pt->p_gflags, &perr);
	else
		t->t_pshandle = proc_arg_grab(argv->a_un.a_str,
		    PR_ARG_ANY, pt->p_gflags, &perr);

	if (t->t_pshandle == NULL) {
		t->t_pshandle = pt->p_idlehandle;
		mdb_warn("cannot attach: %s\n", Pgrab_error(perr));
		return (DCMD_ERR);
	}

	state = Pstate(t->t_pshandle);
	if (state != PS_DEAD && state != PS_IDLE) {
		(void) Punsetflags(t->t_pshandle, PR_KLC);
		(void) Psetflags(t->t_pshandle, PR_RLC);
		pt_post_attach(t);
		pt_activate_common(t);
	}

	(void) mdb_tgt_status(t, &t->t_status);
	mdb_module_load_all(0);
	return (DCMD_OK);
}

static int
pt_regstatus(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;

	if (t->t_pshandle != NULL) {
		const pstatus_t *psp = Pstatus(t->t_pshandle);
		int cursig = psp->pr_lwp.pr_cursig;
		char signame[SIG2STR_MAX];
		int state = Pstate(t->t_pshandle);

		if (state != PS_DEAD && state != PS_IDLE)
			mdb_printf("process id = %d\n", psp->pr_pid);
		else
			mdb_printf("no process\n");

		if (cursig != 0 && sig2str(cursig, signame) == 0)
			mdb_printf("SIG%s: %s\n", signame, strsignal(cursig));
	}

	return (pt_regs(addr, flags, argc, argv));
}

static int
pt_findstack(uintptr_t tid, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_gregset_t gregs;
	int showargs = 0;
	int count;
	uintptr_t pc, sp;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	count = mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &showargs,
	    NULL);
	argc -= count;
	argv += count;

	if (argc > 1 || (argc == 1 && argv->a_type != MDB_TYPE_STRING))
		return (DCMD_USAGE);

	if (PTL_GETREGS(t, tid, gregs.gregs) != 0) {
		mdb_warn("failed to get register set for thread %p", tid);
		return (DCMD_ERR);
	}

	pc = gregs.gregs[R_PC];
#if defined(__i386) || defined(__amd64)
	sp = gregs.gregs[R_FP];
#else
	sp = gregs.gregs[R_SP];
#endif
	mdb_printf("stack pointer for thread %p: %p\n", tid, sp);
	if (pc != 0)
		mdb_printf("[ %0?lr %a() ]\n", sp, pc);

	(void) mdb_inc_indent(2);
	mdb_set_dot(sp);

	if (argc == 1)
		(void) mdb_eval(argv->a_un.a_str);
	else if (showargs)
		(void) mdb_eval("<.$C");
	else
		(void) mdb_eval("<.$C0");

	(void) mdb_dec_indent(2);
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_gcore(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	char *prefix = "core";
	char *content_str = NULL;
	core_content_t content = CC_CONTENT_DEFAULT;
	size_t size;
	char *fname;
	pid_t pid;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'o', MDB_OPT_STR, &prefix,
	    'c', MDB_OPT_STR, &content_str, NULL) != argc)
		return (DCMD_USAGE);

	if (content_str != NULL &&
	    (proc_str2content(content_str, &content) != 0 ||
	    content == CC_CONTENT_INVALID)) {
		mdb_warn("invalid content string '%s'\n", content_str);
		return (DCMD_ERR);
	}

	if (t->t_pshandle == NULL) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	pid = Pstatus(t->t_pshandle)->pr_pid;
	size = 1 + mdb_snprintf(NULL, 0, "%s.%d", prefix, (int)pid);
	fname = mdb_alloc(size, UM_SLEEP | UM_GC);
	(void) mdb_snprintf(fname, size, "%s.%d", prefix, (int)pid);

	if (Pgcore(t->t_pshandle, fname, content) != 0) {
		/*
		 * Short writes during dumping are specifically described by
		 * EBADE, just as ZFS uses this otherwise-unused code for
		 * checksum errors.  Translate to and mdb errno.
		 */
		if (errno == EBADE)
			(void) set_errno(EMDB_SHORTWRITE);
		mdb_warn("couldn't dump core");
		return (DCMD_ERR);
	}

	mdb_warn("%s dumped\n", fname);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_kill(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	pt_data_t *pt = t->t_data;
	int state;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (t->t_pshandle != NULL &&
	    (state = Pstate(t->t_pshandle)) != PS_DEAD && state != PS_IDLE) {
		mdb_warn("victim process PID %d forcibly terminated\n",
		    (int)Pstatus(t->t_pshandle)->pr_pid);
		pt_pre_detach(t, TRUE);
		pt_release_parents(t);
		Prelease(t->t_pshandle, PRELEASE_KILL);
		t->t_pshandle = pt->p_idlehandle;
		(void) mdb_tgt_status(t, &t->t_status);
		mdb.m_flags &= ~(MDB_FL_VCREATE | MDB_FL_JOBCTL);
	} else
		mdb_warn("no victim process is currently under control\n");

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_detach(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	pt_data_t *pt = t->t_data;
	int rflags = pt->p_rflags;

	if (argc != 0 && argv->a_type == MDB_TYPE_STRING &&
	    strcmp(argv->a_un.a_str, "-a") == 0) {
		rflags = PRELEASE_HANG | PRELEASE_CLEAR;
		argv++;
		argc--;
	}

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_IDLE) {
		mdb_warn("debugger is not currently attached to a process "
		    "or core file\n");
		return (DCMD_ERR);
	}

	pt_pre_detach(t, TRUE);
	pt_release_parents(t);
	Prelease(t->t_pshandle, rflags);
	t->t_pshandle = pt->p_idlehandle;
	(void) mdb_tgt_status(t, &t->t_status);
	mdb.m_flags &= ~(MDB_FL_VCREATE | MDB_FL_JOBCTL);

	return (DCMD_OK);
}

static uintmax_t
reg_disc_get(const mdb_var_t *v)
{
	mdb_tgt_t *t = MDB_NV_COOKIE(v);
	mdb_tgt_tid_t tid = PTL_TID(t);
	mdb_tgt_reg_t r = 0;

	if (tid != (mdb_tgt_tid_t)-1L)
		(void) mdb_tgt_getareg(t, tid, mdb_nv_get_name(v), &r);

	return (r);
}

static void
reg_disc_set(mdb_var_t *v, uintmax_t r)
{
	mdb_tgt_t *t = MDB_NV_COOKIE(v);
	mdb_tgt_tid_t tid = PTL_TID(t);

	if (tid != (mdb_tgt_tid_t)-1L && mdb_tgt_putareg(t, tid,
	    mdb_nv_get_name(v), r) == -1)
		mdb_warn("failed to modify %%%s register", mdb_nv_get_name(v));
}

static void
pt_print_reason(const lwpstatus_t *psp)
{
	char name[SIG2STR_MAX + 4]; /* enough for SIG+name+\0, syscall or flt */
	const char *desc;

	switch (psp->pr_why) {
	case PR_REQUESTED:
		mdb_printf("stopped by debugger");
		break;
	case PR_SIGNALLED:
		mdb_printf("stopped on %s (%s)", proc_signame(psp->pr_what,
		    name, sizeof (name)), strsignal(psp->pr_what));
		break;
	case PR_SYSENTRY:
		mdb_printf("stopped on entry to %s system call",
		    proc_sysname(psp->pr_what, name, sizeof (name)));
		break;
	case PR_SYSEXIT:
		mdb_printf("stopped on exit from %s system call",
		    proc_sysname(psp->pr_what, name, sizeof (name)));
		break;
	case PR_JOBCONTROL:
		mdb_printf("stopped by job control");
		break;
	case PR_FAULTED:
		if (psp->pr_what == FLTBPT) {
			mdb_printf("stopped on a breakpoint");
		} else if (psp->pr_what == FLTWATCH) {
			switch (psp->pr_info.si_code) {
			case TRAP_RWATCH:
				desc = "read";
				break;
			case TRAP_WWATCH:
				desc = "write";
				break;
			case TRAP_XWATCH:
				desc = "execute";
				break;
			default:
				desc = "unknown";
			}
			mdb_printf("stopped %s a watchpoint (%s access to %p)",
			    psp->pr_info.si_trapafter ? "after" : "on",
			    desc, psp->pr_info.si_addr);
		} else if (psp->pr_what == FLTTRACE) {
			mdb_printf("stopped after a single-step");
		} else {
			mdb_printf("stopped on a %s fault",
			    proc_fltname(psp->pr_what, name, sizeof (name)));
		}
		break;
	case PR_SUSPENDED:
	case PR_CHECKPOINT:
		mdb_printf("suspended by the kernel");
		break;
	default:
		mdb_printf("stopped for unknown reason (%d/%d)",
		    psp->pr_why, psp->pr_what);
	}
}

/*ARGSUSED*/
static int
pt_status_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	struct ps_prochandle *P = t->t_pshandle;
	pt_data_t *pt = t->t_data;

	if (P != NULL) {
		const psinfo_t *pip = Ppsinfo(P);
		const pstatus_t *psp = Pstatus(P);
		int cursig = 0, bits = 0, coredump = 0;
		int state;
		GElf_Sym sym;
		uintptr_t panicstr;
		char *panicbuf = mdb_alloc(PANIC_BUFSIZE, UM_SLEEP);
		const siginfo_t *sip = &(psp->pr_lwp.pr_info);

		char execname[MAXPATHLEN], buf[BUFSIZ];
		char signame[SIG2STR_MAX + 4]; /* enough for SIG+name+\0 */

		mdb_tgt_spec_desc_t desc;
		mdb_sespec_t *sep;

		struct utsname uts;
		prcred_t cred;
		psinfo_t pi;

		(void) strcpy(uts.nodename, "unknown machine");
		(void) Puname(P, &uts);

		if (pip != NULL) {
			bcopy(pip, &pi, sizeof (psinfo_t));
			proc_unctrl_psinfo(&pi);
		} else
			bzero(&pi, sizeof (psinfo_t));

		bits = pi.pr_dmodel == PR_MODEL_ILP32 ? 32 : 64;

		state = Pstate(P);
		if (psp != NULL && state != PS_UNDEAD && state != PS_IDLE)
			cursig = psp->pr_lwp.pr_cursig;

		if (state == PS_DEAD && pip != NULL) {
			mdb_printf("debugging core file of %s (%d-bit) "
			    "from %s\n", pi.pr_fname, bits, uts.nodename);

		} else if (state == PS_DEAD) {
			mdb_printf("debugging core file\n");

		} else if (state == PS_IDLE) {
			const GElf_Ehdr *ehp = &pt->p_file->gf_ehdr;

			mdb_printf("debugging %s file (%d-bit)\n",
			    ehp->e_type == ET_EXEC ? "executable" : "object",
			    ehp->e_ident[EI_CLASS] == ELFCLASS32 ? 32 : 64);

		} else if (state == PS_UNDEAD && pi.pr_pid == 0) {
			mdb_printf("debugging defunct process\n");

		} else {
			mdb_printf("debugging PID %d (%d-bit)\n",
			    pi.pr_pid, bits);
		}

		if (Pexecname(P, execname, sizeof (execname)) != NULL)
			mdb_printf("file: %s\n", execname);

		if (pip != NULL && state == PS_DEAD)
			mdb_printf("initial argv: %s\n", pi.pr_psargs);

		if (state != PS_UNDEAD && state != PS_IDLE) {
			mdb_printf("threading model: ");
			if (pt->p_ptl_ops == &proc_lwp_ops)
				mdb_printf("raw lwps\n");
			else
				mdb_printf("native threads\n");
		}

		mdb_printf("status: ");
		switch (state) {
		case PS_RUN:
			ASSERT(!(psp->pr_flags & PR_STOPPED));
			mdb_printf("process is running");
			if (psp->pr_flags & PR_DSTOP)
				mdb_printf(", debugger stop directive pending");
			mdb_printf("\n");
			break;

		case PS_STOP:
			ASSERT(psp->pr_flags & PR_STOPPED);
			pt_print_reason(&psp->pr_lwp);

			if (psp->pr_flags & PR_DSTOP)
				mdb_printf(", debugger stop directive pending");
			if (psp->pr_flags & PR_ASLEEP)
				mdb_printf(", sleeping in %s system call",
				    proc_sysname(psp->pr_lwp.pr_syscall,
				    signame, sizeof (signame)));

			mdb_printf("\n");

			for (sep = t->t_matched; sep != T_SE_END;
			    sep = sep->se_matched) {
				mdb_printf("event: %s\n", sep->se_ops->se_info(
				    t, sep, mdb_list_next(&sep->se_velist),
				    &desc, buf, sizeof (buf)));
			}
			break;

		case PS_LOST:
			mdb_printf("debugger lost control of process\n");
			break;

		case PS_UNDEAD:
			coredump = WIFSIGNALED(pi.pr_wstat) &&
			    WCOREDUMP(pi.pr_wstat);
			/*FALLTHRU*/

		case PS_DEAD:
			if (cursig == 0 && WIFSIGNALED(pi.pr_wstat))
				cursig = WTERMSIG(pi.pr_wstat);
			/*
			 * We can only use pr_wstat == 0 as a test for gcore if
			 * an NT_PRCRED note is present; these features were
			 * added at the same time in Solaris 8.
			 */
			if (pi.pr_wstat == 0 && Pstate(P) == PS_DEAD &&
			    Pcred(P, &cred, 1) == 0) {
				mdb_printf("process core file generated "
				    "with gcore(1)\n");
			} else if (cursig != 0) {
				mdb_printf("process terminated by %s (%s)",
				    proc_signame(cursig, signame,
				    sizeof (signame)), strsignal(cursig));

				if (sip->si_signo != 0 && SI_FROMUSER(sip) &&
				    sip->si_pid != 0) {
					mdb_printf(", pid=%d uid=%u",
					    (int)sip->si_pid, sip->si_uid);
					if (sip->si_code != 0) {
						mdb_printf(" code=%d",
						    sip->si_code);
					}
				} else {
					switch (sip->si_signo) {
					case SIGILL:
					case SIGTRAP:
					case SIGFPE:
					case SIGSEGV:
					case SIGBUS:
					case SIGEMT:
						mdb_printf(", addr=%p",
						    sip->si_addr);
					default:
						break;
					}
				}

				if (coredump)
					mdb_printf(" - core file dumped");
				mdb_printf("\n");
			} else {
				mdb_printf("process terminated with exit "
				    "status %d\n", WEXITSTATUS(pi.pr_wstat));
			}

			if (Plookup_by_name(t->t_pshandle, "libc.so",
			    "panicstr", &sym) == 0 &&
			    Pread(t->t_pshandle, &panicstr, sizeof (panicstr),
			    sym.st_value) == sizeof (panicstr) &&
			    Pread_string(t->t_pshandle, panicbuf,
			    PANIC_BUFSIZE, panicstr) > 0) {
				mdb_printf("panic message: %s",
				    panicbuf);
			}


			break;

		case PS_IDLE:
			mdb_printf("idle\n");
			break;

		default:
			mdb_printf("unknown libproc Pstate: %d\n", Pstate(P));
		}
		mdb_free(panicbuf, PANIC_BUFSIZE);

	} else if (pt->p_file != NULL) {
		const GElf_Ehdr *ehp = &pt->p_file->gf_ehdr;

		mdb_printf("debugging %s file (%d-bit)\n",
		    ehp->e_type == ET_EXEC ? "executable" : "object",
		    ehp->e_ident[EI_CLASS] == ELFCLASS32 ? 32 : 64);
		mdb_printf("executable file: %s\n", IOP_NAME(pt->p_fio));
		mdb_printf("status: idle\n");
	}

	return (DCMD_OK);
}

static int
pt_tls(uintptr_t tid, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *name;
	const char *object;
	GElf_Sym sym;
	mdb_syminfo_t si;
	mdb_tgt_t *t = mdb.m_target;

	if (!(flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc == 0) {
		psaddr_t b;

		if (tlsbase(t, tid, PR_LMID_EVERY, MDB_TGT_OBJ_EXEC, &b) != 0) {
			mdb_warn("failed to lookup tlsbase for %r", tid);
			return (DCMD_ERR);
		}

		mdb_printf("%lr\n", b);
		mdb_set_dot(b);

		return (DCMD_OK);
	}

	name = argv[0].a_un.a_str;
	object = MDB_TGT_OBJ_EVERY;

	if (pt_lookup_by_name_thr(t, object, name, &sym, &si, tid) != 0) {
		mdb_warn("failed to lookup %s", name);
		return (DCMD_ABORT); /* avoid repeated failure */
	}

	if (GELF_ST_TYPE(sym.st_info) != STT_TLS && DCMD_HDRSPEC(flags))
		mdb_warn("%s does not refer to thread local storage\n", name);

	mdb_printf("%llr\n", sym.st_value);
	mdb_set_dot(sym.st_value);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_tmodel(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	pt_data_t *pt = t->t_data;
	const pt_ptl_ops_t *ptl_ops;

	if (argc != 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (strcmp(argv->a_un.a_str, "thread") == 0)
		ptl_ops = &proc_tdb_ops;
	else if (strcmp(argv->a_un.a_str, "lwp") == 0)
		ptl_ops = &proc_lwp_ops;
	else
		return (DCMD_USAGE);

	if (t->t_pshandle != NULL && pt->p_ptl_ops != ptl_ops) {
		PTL_DTOR(t);
		pt->p_tdb_ops = NULL;
		pt->p_ptl_ops = &proc_lwp_ops;
		pt->p_ptl_hdl = NULL;

		if (ptl_ops == &proc_tdb_ops) {
			(void) Pobject_iter(t->t_pshandle, (proc_map_f *)
			    thr_check, t);
		}
	}

	(void) mdb_tgt_status(t, &t->t_status);
	return (DCMD_OK);
}

static const char *
env_match(const char *cmp, const char *nameval)
{
	const char *loc;
	size_t cmplen = strlen(cmp);

	loc = strchr(nameval, '=');
	if (loc != NULL && (loc - nameval) == cmplen &&
	    strncmp(nameval, cmp, cmplen) == 0) {
		return (loc + 1);
	}

	return (NULL);
}

/*ARGSUSED*/
static int
print_env(void *data, struct ps_prochandle *P, uintptr_t addr,
    const char *nameval)
{
	const char *value;

	if (nameval == NULL) {
		mdb_printf("<0x%p>\n", addr);
	} else {
		if (data == NULL)
			mdb_printf("%s\n", nameval);
		else if ((value = env_match(data, nameval)) != NULL)
			mdb_printf("%s\n", value);
	}

	return (0);
}

/*ARGSUSED*/
static int
pt_getenv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	pt_data_t *pt = t->t_data;
	int i;
	uint_t opt_t = 0;
	mdb_var_t *v;

	i = mdb_getopts(argc, argv,
	    't', MDB_OPT_SETBITS, TRUE, &opt_t, NULL);

	argc -= i;
	argv += i;

	if ((flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc == 1 && argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (opt_t && t->t_pshandle == NULL) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	if (opt_t && (Pstate(t->t_pshandle) == PS_IDLE ||
	    Pstate(t->t_pshandle) == PS_UNDEAD)) {
		mdb_warn("-t option requires target to be running\n");
		return (DCMD_ERR);
	}

	if (opt_t != 0) {
		if (Penv_iter(t->t_pshandle, print_env,
		    argc == 0 ? NULL : (void *)argv->a_un.a_str) != 0)
			return (DCMD_ERR);
	} else if (argc == 1) {
		if ((v = mdb_nv_lookup(&pt->p_env, argv->a_un.a_str)) == NULL)
			return (DCMD_ERR);

		ASSERT(strchr(mdb_nv_get_cookie(v), '=') != NULL);
		mdb_printf("%s\n", strchr(mdb_nv_get_cookie(v), '=') + 1);
	} else {

		mdb_nv_rewind(&pt->p_env);
		while ((v = mdb_nv_advance(&pt->p_env)) != NULL)
			mdb_printf("%s\n", mdb_nv_get_cookie(v));
	}

	return (DCMD_OK);
}

/*
 * Function to set a variable in the internal environment, which is used when
 * creating new processes.  Note that it is possible that 'nameval' can refer to
 * read-only memory, if mdb calls putenv() on an existing value before calling
 * this function.  While we should avoid this situation, this function is
 * designed to be robust in the face of such changes.
 */
static void
pt_env_set(pt_data_t *pt, const char *nameval)
{
	mdb_var_t *v;
	char *equals, *val;
	const char *name;
	size_t len;

	if ((equals = strchr(nameval, '=')) != NULL) {
		val = strdup(nameval);
		equals = val + (equals - nameval);
	} else {
		/*
		 * nameval doesn't contain an equals character.  Convert this to
		 * be 'nameval='.
		 */
		len = strlen(nameval);
		val = mdb_alloc(len + 2, UM_SLEEP);
		(void) mdb_snprintf(val, len + 2, "%s=", nameval);
		equals = val + len;
	}

	/* temporary truncate the string for lookup/insert */
	*equals = '\0';
	v = mdb_nv_lookup(&pt->p_env, val);

	if (v != NULL) {
		char *old = mdb_nv_get_cookie(v);
		mdb_free(old, strlen(old) + 1);
		name = mdb_nv_get_name(v);
	} else {
		/*
		 * The environment is created using MDB_NV_EXTNAME, so we must
		 * provide external storage for the variable names.
		 */
		name = strdup(val);
	}

	*equals = '=';

	(void) mdb_nv_insert(&pt->p_env, name, NULL, (uintptr_t)val,
	    MDB_NV_EXTNAME);

	if (equals)
		*equals = '=';
}

/*
 * Clears the internal environment.
 */
static void
pt_env_clear(pt_data_t *pt)
{
	mdb_var_t *v;
	char *val, *name;

	mdb_nv_rewind(&pt->p_env);
	while ((v = mdb_nv_advance(&pt->p_env)) != NULL) {

		name = (char *)mdb_nv_get_name(v);
		val = mdb_nv_get_cookie(v);

		mdb_nv_remove(&pt->p_env, v);

		mdb_free(name, strlen(name) + 1);
		mdb_free(val, strlen(val) + 1);
	}
}

/*ARGSUSED*/
static int
pt_setenv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	pt_data_t *pt = t->t_data;
	char *nameval;
	size_t len;
	int alloc;

	if ((flags & DCMD_ADDRSPEC) || argc == 0 || argc > 2)
		return (DCMD_USAGE);

	if ((argc > 0 && argv[0].a_type != MDB_TYPE_STRING) ||
	    (argc > 1 && argv[1].a_type != MDB_TYPE_STRING))
		return (DCMD_USAGE);

	if (t->t_pshandle == NULL) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	/*
	 * If the process is in some sort of running state, warn the user that
	 * changes won't immediately take effect.
	 */
	if (Pstate(t->t_pshandle) == PS_RUN ||
	    Pstate(t->t_pshandle) == PS_STOP) {
		mdb_warn("warning: changes will not take effect until process"
		    " is restarted\n");
	}

	/*
	 * We allow two forms of operation.  The first is the usual "name=value"
	 * parameter.  We also allow the user to specify two arguments, where
	 * the first is the name of the variable, and the second is the value.
	 */
	alloc = 0;
	if (argc == 1) {
		nameval = (char *)argv->a_un.a_str;
	} else {
		len = strlen(argv[0].a_un.a_str) +
		    strlen(argv[1].a_un.a_str) + 2;
		nameval = mdb_alloc(len, UM_SLEEP);
		(void) mdb_snprintf(nameval, len, "%s=%s", argv[0].a_un.a_str,
		    argv[1].a_un.a_str);
		alloc = 1;
	}

	pt_env_set(pt, nameval);

	if (alloc)
		mdb_free(nameval, strlen(nameval) + 1);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
pt_unsetenv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	pt_data_t *pt = t->t_data;
	mdb_var_t *v;
	char *value, *name;

	if ((flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc == 1 && argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (t->t_pshandle == NULL) {
		mdb_warn("no process active\n");
		return (DCMD_ERR);
	}

	/*
	 * If the process is in some sort of running state, warn the user that
	 * changes won't immediately take effect.
	 */
	if (Pstate(t->t_pshandle) == PS_RUN ||
	    Pstate(t->t_pshandle) == PS_STOP) {
		mdb_warn("warning: changes will not take effect until process"
		    " is restarted\n");
	}

	if (argc == 0) {
		pt_env_clear(pt);
	} else {
		if ((v = mdb_nv_lookup(&pt->p_env, argv->a_un.a_str)) != NULL) {
			name = (char *)mdb_nv_get_name(v);
			value = mdb_nv_get_cookie(v);

			mdb_nv_remove(&pt->p_env, v);

			mdb_free(name, strlen(name) + 1);
			mdb_free(value, strlen(value) + 1);
		}
	}

	return (DCMD_OK);
}

void
getenv_help(void)
{
	mdb_printf("-t  show current process environment"
	    " instead of initial environment.\n");
}

static const mdb_dcmd_t pt_dcmds[] = {
	{ "$c", "?[cnt]", "print stack backtrace", pt_stack },
	{ "$C", "?[cnt]", "print stack backtrace", pt_stackv },
	{ "$i", NULL, "print signals that are ignored", pt_ignored },
	{ "$l", NULL, "print the representative thread's lwp id", pt_lwpid },
	{ "$L", NULL, "print list of the active lwp ids", pt_lwpids },
	{ "$r", "?[-u]", "print general-purpose registers", pt_regs },
	{ "$x", "?", "print floating point registers", pt_fpregs },
	{ "$X", "?", "print floating point registers", pt_fpregs },
	{ "$y", "?", "print floating point registers", pt_fpregs },
	{ "$Y", "?", "print floating point registers", pt_fpregs },
	{ "$?", "?", "print status and registers", pt_regstatus },
	{ ":A", "?[core|pid]", "attach to process or core file", pt_attach },
	{ ":i", ":", "ignore signal (delete all matching events)", pt_ignore },
	{ ":k", NULL, "forcibly kill and release target", pt_kill },
	{ ":R", "[-a]", "release the previously attached process", pt_detach },
	{ "attach", "?[core|pid]",
	    "attach to process or core file", pt_attach },
	{ "findstack", ":[-v]", "find user thread stack", pt_findstack },
	{ "gcore", "[-o prefix] [-c content]",
	    "produce a core file for the attached process", pt_gcore },
	{ "getenv", "[-t] [name]", "display an environment variable",
		pt_getenv, getenv_help },
	{ "kill", NULL, "forcibly kill and release target", pt_kill },
	{ "release", "[-a]",
	    "release the previously attached process", pt_detach },
	{ "regs", "?[-u]", "print general-purpose registers", pt_regs },
	{ "fpregs", "?[-dqs]", "print floating point registers", pt_fpregs },
	{ "setenv", "name=value", "set an environment variable", pt_setenv },
	{ "stack", "?[cnt]", "print stack backtrace", pt_stack },
	{ "stackregs", "?", "print stack backtrace and registers", pt_stackr },
	{ "status", NULL, "print summary of current target", pt_status_dcmd },
	{ "tls", ":symbol",
	    "lookup TLS data in the context of a given thread", pt_tls },
	{ "tmodel", "{thread|lwp}", NULL, pt_tmodel },
	{ "unsetenv", "[name]", "clear an environment variable", pt_unsetenv },
	{ NULL }
};

static void
pt_thr_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_addrvec_destroy(wsp->walk_data);
	mdb_free(wsp->walk_data, sizeof (mdb_addrvec_t));
}

static int
pt_thr_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_data = mdb_zalloc(sizeof (mdb_addrvec_t), UM_SLEEP);
	mdb_addrvec_create(wsp->walk_data);

	if (PTL_ITER(mdb.m_target, wsp->walk_data) == -1) {
		mdb_warn("failed to iterate over threads");
		pt_thr_walk_fini(wsp);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
pt_thr_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_addrvec_length(wsp->walk_data) != 0) {
		return (wsp->walk_callback(mdb_addrvec_shift(wsp->walk_data),
		    NULL, wsp->walk_cbdata));
	}
	return (WALK_DONE);
}

static const mdb_walker_t pt_walkers[] = {
	{ "thread", "walk list of valid thread identifiers",
	    pt_thr_walk_init, pt_thr_walk_step, pt_thr_walk_fini },
	{ NULL }
};

static int
pt_agent_check(boolean_t *agent, const lwpstatus_t *psp)
{
	if (psp->pr_flags & PR_AGENT)
		*agent = B_TRUE;

	return (0);
}

static void
pt_activate_common(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;
	boolean_t hasagent = B_FALSE;
	GElf_Sym sym;

	/*
	 * If we have a libproc handle and AT_BASE is set, the process or core
	 * is dynamically linked.  We call Prd_agent() to force libproc to
	 * try to initialize librtld_db, and issue a warning if that fails.
	 */
	if (t->t_pshandle != NULL && Pgetauxval(t->t_pshandle,
	    AT_BASE) != -1L && Prd_agent(t->t_pshandle) == NULL) {
		mdb_warn("warning: librtld_db failed to initialize; shared "
		    "library information will not be available\n");
	}

	if (t->t_pshandle != NULL) {
		(void) Plwp_iter(t->t_pshandle,
		    (proc_lwp_f *)pt_agent_check, &hasagent);
	}

	if (hasagent) {
		mdb_warn("agent lwp detected; forcing "
		    "lwp thread model (use ::tmodel to change)\n");
	} else if (t->t_pshandle != NULL && Pstate(t->t_pshandle) != PS_IDLE) {
		/*
		 * If we have a libproc handle and we do not have an agent LWP,
		 * look for the correct thread debugging library.  (If we have
		 * an agent LWP, we leave the model as the raw LWP model to
		 * allow the agent LWP to be visible to the debugger.)
		 */
		(void) Pobject_iter(t->t_pshandle, (proc_map_f *)thr_check, t);
	}

	/*
	 * If there's a global object named '_mdb_abort_info', assuming we're
	 * debugging mdb itself and load the developer support module.
	 */
	if (mdb_gelf_symtab_lookup_by_name(pt->p_symtab, "_mdb_abort_info",
	    &sym, NULL) == 0 && GELF_ST_TYPE(sym.st_info) == STT_OBJECT) {
		if (mdb_module_load("mdb_ds", MDB_MOD_SILENT) < 0)
			mdb_warn("warning: failed to load developer support\n");
	}

	mdb_tgt_elf_export(pt->p_file);
}

static void
pt_activate(mdb_tgt_t *t)
{
	static const mdb_nv_disc_t reg_disc = { reg_disc_set, reg_disc_get };

	pt_data_t *pt = t->t_data;
	struct utsname u1, u2;
	mdb_var_t *v;
	core_content_t content;

	if (t->t_pshandle) {
		mdb_prop_postmortem = (Pstate(t->t_pshandle) == PS_DEAD);
		mdb_prop_kernel = FALSE;
	} else
		mdb_prop_kernel = mdb_prop_postmortem = FALSE;

	mdb_prop_datamodel = MDB_TGT_MODEL_NATIVE;

	/*
	 * If we're examining a core file that doesn't contain program text,
	 * and uname(2) doesn't match the NT_UTSNAME note recorded in the
	 * core file, issue a warning.
	 */
	if (mdb_prop_postmortem == TRUE &&
	    ((content = Pcontent(t->t_pshandle)) == CC_CONTENT_INVALID ||
	    !(content & CC_CONTENT_TEXT)) &&
	    uname(&u1) >= 0 && Puname(t->t_pshandle, &u2) == 0 &&
	    (strcmp(u1.release, u2.release) != 0 ||
	    strcmp(u1.version, u2.version) != 0)) {
		mdb_warn("warning: core file is from %s %s %s; shared text "
		    "mappings may not match installed libraries\n",
		    u2.sysname, u2.release, u2.version);
	}

	/*
	 * Perform the common initialization tasks -- these are shared with
	 * the pt_exec() and pt_run() subroutines.
	 */
	pt_activate_common(t);

	(void) mdb_tgt_register_dcmds(t, &pt_dcmds[0], MDB_MOD_FORCE);
	(void) mdb_tgt_register_walkers(t, &pt_walkers[0], MDB_MOD_FORCE);

	/*
	 * Iterate through our register description list and export
	 * each register as a named variable.
	 */
	mdb_nv_rewind(&pt->p_regs);
	while ((v = mdb_nv_advance(&pt->p_regs)) != NULL) {
		ushort_t rd_flags = MDB_TGT_R_FLAGS(mdb_nv_get_value(v));

		if (!(rd_flags & MDB_TGT_R_EXPORT))
			continue; /* Don't export register as a variable */

		(void) mdb_nv_insert(&mdb.m_nv, mdb_nv_get_name(v), &reg_disc,
		    (uintptr_t)t, MDB_NV_PERSIST);
	}
}

static void
pt_deactivate(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;
	const mdb_dcmd_t *dcp;
	const mdb_walker_t *wp;
	mdb_var_t *v, *w;

	mdb_nv_rewind(&pt->p_regs);
	while ((v = mdb_nv_advance(&pt->p_regs)) != NULL) {
		ushort_t rd_flags = MDB_TGT_R_FLAGS(mdb_nv_get_value(v));

		if (!(rd_flags & MDB_TGT_R_EXPORT))
			continue; /* Didn't export register as a variable */

		if (w = mdb_nv_lookup(&mdb.m_nv, mdb_nv_get_name(v))) {
			w->v_flags &= ~MDB_NV_PERSIST;
			mdb_nv_remove(&mdb.m_nv, w);
		}
	}

	for (wp = &pt_walkers[0]; wp->walk_name != NULL; wp++) {
		if (mdb_module_remove_walker(t->t_module, wp->walk_name) == -1)
			warn("failed to remove walk %s", wp->walk_name);
	}

	for (dcp = &pt_dcmds[0]; dcp->dc_name != NULL; dcp++) {
		if (mdb_module_remove_dcmd(t->t_module, dcp->dc_name) == -1)
			warn("failed to remove dcmd %s", dcp->dc_name);
	}

	mdb_prop_postmortem = FALSE;
	mdb_prop_kernel = FALSE;
	mdb_prop_datamodel = MDB_TGT_MODEL_UNKNOWN;
}

static void
pt_periodic(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;

	if (pt->p_rdstate == PT_RD_CONSIST) {
		if (t->t_pshandle != NULL && Pstate(t->t_pshandle) < PS_LOST &&
		    !(mdb.m_flags & MDB_FL_NOMODS)) {
			mdb_printf("%s: You've got symbols!\n", mdb.m_pname);
			mdb_module_load_all(0);
		}
		pt->p_rdstate = PT_RD_NONE;
	}
}

static void
pt_destroy(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;

	if (pt->p_idlehandle != NULL && pt->p_idlehandle != t->t_pshandle)
		Prelease(pt->p_idlehandle, 0);

	if (t->t_pshandle != NULL) {
		PTL_DTOR(t);
		pt_release_parents(t);
		pt_pre_detach(t, TRUE);
		Prelease(t->t_pshandle, pt->p_rflags);
	}

	mdb.m_flags &= ~(MDB_FL_VCREATE | MDB_FL_JOBCTL);
	pt_close_aout(t);

	if (pt->p_aout_fio != NULL)
		mdb_io_rele(pt->p_aout_fio);

	pt_env_clear(pt);
	mdb_nv_destroy(&pt->p_env);

	mdb_nv_destroy(&pt->p_regs);
	mdb_free(pt, sizeof (pt_data_t));
}

/*ARGSUSED*/
static const char *
pt_name(mdb_tgt_t *t)
{
	return ("proc");
}

static const char *
pt_platform(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;

	if (t->t_pshandle != NULL &&
	    Pplatform(t->t_pshandle, pt->p_platform, MAXNAMELEN) != NULL)
		return (pt->p_platform);

	return (mdb_conf_platform());
}

static int
pt_uname(mdb_tgt_t *t, struct utsname *utsp)
{
	if (t->t_pshandle != NULL)
		return (Puname(t->t_pshandle, utsp));

	return (uname(utsp) >= 0 ? 0 : -1);
}

static int
pt_dmodel(mdb_tgt_t *t)
{
	if (t->t_pshandle == NULL)
		return (MDB_TGT_MODEL_NATIVE);

	switch (Pstatus(t->t_pshandle)->pr_dmodel) {
	case PR_MODEL_ILP32:
		return (MDB_TGT_MODEL_ILP32);
	case PR_MODEL_LP64:
		return (MDB_TGT_MODEL_LP64);
	}

	return (MDB_TGT_MODEL_UNKNOWN);
}

static ssize_t
pt_vread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	ssize_t n;

	/*
	 * If no handle is open yet, reads from virtual addresses are
	 * allowed to succeed but return zero-filled memory.
	 */
	if (t->t_pshandle == NULL) {
		bzero(buf, nbytes);
		return (nbytes);
	}

	if ((n = Pread(t->t_pshandle, buf, nbytes, addr)) <= 0)
		return (set_errno(EMDB_NOMAP));

	return (n);
}

static ssize_t
pt_vwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	ssize_t n;

	/*
	 * If no handle is open yet, writes to virtual addresses are
	 * allowed to succeed but do not actually modify anything.
	 */
	if (t->t_pshandle == NULL)
		return (nbytes);

	n = Pwrite(t->t_pshandle, buf, nbytes, addr);

	if (n == -1 && errno == EIO)
		return (set_errno(EMDB_NOMAP));

	return (n);
}

static ssize_t
pt_fread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	pt_data_t *pt = t->t_data;

	if (pt->p_file != NULL) {
		return (mdb_gelf_rw(pt->p_file, buf, nbytes, addr,
		    IOPF_READ(pt->p_fio), GIO_READ));
	}

	bzero(buf, nbytes);
	return (nbytes);
}

static ssize_t
pt_fwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	pt_data_t *pt = t->t_data;

	if (pt->p_file != NULL) {
		return (mdb_gelf_rw(pt->p_file, (void *)buf, nbytes, addr,
		    IOPF_WRITE(pt->p_fio), GIO_WRITE));
	}

	return (nbytes);
}

static const char *
pt_resolve_lmid(const char *object, Lmid_t *lmidp)
{
	Lmid_t lmid = PR_LMID_EVERY;
	const char *p;

	if (object == MDB_TGT_OBJ_EVERY || object == MDB_TGT_OBJ_EXEC)
		lmid = LM_ID_BASE; /* restrict scope to a.out's link map */
	else if (object != MDB_TGT_OBJ_RTLD && strncmp(object, "LM", 2) == 0 &&
	    (p = strchr(object, '`')) != NULL) {
		object += 2;	/* skip past initial "LM" prefix */
		lmid = strntoul(object, (size_t)(p - object), mdb.m_radix);
		object = p + 1;	/* skip past link map specifier */
	}

	*lmidp = lmid;
	return (object);
}

static int
tlsbase(mdb_tgt_t *t, mdb_tgt_tid_t tid, Lmid_t lmid, const char *object,
    psaddr_t *basep)
{
	pt_data_t *pt = t->t_data;
	const rd_loadobj_t *loadobjp;
	td_thrhandle_t th;
	td_err_e err;

	if (object == MDB_TGT_OBJ_EVERY)
		return (set_errno(EINVAL));

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) == PS_IDLE)
		return (set_errno(EMDB_NOPROC));

	if (pt->p_tdb_ops == NULL)
		return (set_errno(EMDB_TDB));

	err = pt->p_tdb_ops->td_ta_map_id2thr(pt->p_ptl_hdl, tid, &th);
	if (err != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	/*
	 * If this fails, rtld_db has failed to initialize properly.
	 */
	if ((loadobjp = Plmid_to_loadobj(t->t_pshandle, lmid, object)) == NULL)
		return (set_errno(EMDB_NORTLD));

	/*
	 * This will fail if the TLS block has not been allocated for the
	 * object that contains the TLS symbol in question.
	 */
	err = pt->p_tdb_ops->td_thr_tlsbase(&th, loadobjp->rl_tlsmodid, basep);
	if (err != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

typedef struct {
	mdb_tgt_t	*pl_tgt;
	const char	*pl_name;
	Lmid_t		pl_lmid;
	GElf_Sym	*pl_symp;
	mdb_syminfo_t	*pl_sip;
	mdb_tgt_tid_t	pl_tid;
	mdb_bool_t	pl_found;
} pt_lookup_t;

/*ARGSUSED*/
static int
pt_lookup_cb(void *data, const prmap_t *pmp, const char *object)
{
	pt_lookup_t *plp = data;
	struct ps_prochandle *P = plp->pl_tgt->t_pshandle;
	prsyminfo_t si;
	GElf_Sym sym;

	if (Pxlookup_by_name(P, plp->pl_lmid, object, plp->pl_name, &sym,
	    &si) != 0)
		return (0);

	/*
	 * If we encounter a match with SHN_UNDEF, keep looking for a
	 * better match. Return the first match with SHN_UNDEF set if no
	 * better match is found.
	 */
	if (sym.st_shndx == SHN_UNDEF) {
		if (!plp->pl_found) {
			plp->pl_found = TRUE;
			*plp->pl_symp = sym;
			plp->pl_sip->sym_table = si.prs_table;
			plp->pl_sip->sym_id = si.prs_id;
		}

		return (0);
	}

	/*
	 * Note that if the symbol's st_shndx is SHN_UNDEF we don't have the
	 * TLS offset anyway, so adding in the tlsbase would be worthless.
	 */
	if (GELF_ST_TYPE(sym.st_info) == STT_TLS &&
	    plp->pl_tid != (mdb_tgt_tid_t)-1) {
		psaddr_t base;

		if (tlsbase(plp->pl_tgt, plp->pl_tid, plp->pl_lmid, object,
		    &base) != 0)
			return (-1); /* errno is set for us */

		sym.st_value += base;
	}

	plp->pl_found = TRUE;
	*plp->pl_symp = sym;
	plp->pl_sip->sym_table = si.prs_table;
	plp->pl_sip->sym_id = si.prs_id;

	return (1);
}

/*
 * Lookup the symbol with a thread context so that we can adjust TLS symbols
 * to get the values as they would appear in the context of the given thread.
 */
static int
pt_lookup_by_name_thr(mdb_tgt_t *t, const char *object,
    const char *name, GElf_Sym *symp, mdb_syminfo_t *sip, mdb_tgt_tid_t tid)
{
	struct ps_prochandle *P = t->t_pshandle;
	pt_data_t *pt = t->t_data;
	Lmid_t lmid;
	uint_t i;
	const rd_loadobj_t *aout_lop;

	object = pt_resolve_lmid(object, &lmid);

	if (P != NULL) {
		pt_lookup_t pl;

		pl.pl_tgt = t;
		pl.pl_name = name;
		pl.pl_lmid = lmid;
		pl.pl_symp = symp;
		pl.pl_sip = sip;
		pl.pl_tid = tid;
		pl.pl_found = FALSE;

		if (object == MDB_TGT_OBJ_EVERY) {
			if (Pobject_iter_resolved(P, pt_lookup_cb, &pl) == -1)
				return (-1); /* errno is set for us */
			if ((!pl.pl_found) &&
			    (Pobject_iter(P, pt_lookup_cb, &pl) == -1))
				return (-1); /* errno is set for us */
		} else {
			const prmap_t *pmp;

			/*
			 * This can fail either due to an invalid lmid or
			 * an invalid object. To determine which is
			 * faulty, we test the lmid against known valid
			 * lmids and then see if using a wild-card lmid
			 * improves ths situation.
			 */
			if ((pmp = Plmid_to_map(P, lmid, object)) == NULL) {
				if (lmid != PR_LMID_EVERY &&
				    lmid != LM_ID_BASE &&
				    lmid != LM_ID_LDSO &&
				    Plmid_to_map(P, PR_LMID_EVERY, object)
				    != NULL)
					return (set_errno(EMDB_NOLMID));
				else
					return (set_errno(EMDB_NOOBJ));
			}

			if (pt_lookup_cb(&pl, pmp, object) == -1)
				return (-1); /* errno is set for us */
		}

		if (pl.pl_found)
			return (0);
	}

	/*
	 * If libproc doesn't have the symbols for rtld, we're cooked --
	 * mdb doesn't have those symbols either.
	 */
	if (object == MDB_TGT_OBJ_RTLD)
		return (set_errno(EMDB_NOSYM));

	if (object != MDB_TGT_OBJ_EXEC && object != MDB_TGT_OBJ_EVERY) {
		int status = mdb_gelf_symtab_lookup_by_file(pt->p_symtab,
		    object, name, symp, &sip->sym_id);

		if (status != 0) {
			if (P != NULL &&
			    Plmid_to_map(P, PR_LMID_EVERY, object) != NULL)
				return (set_errno(EMDB_NOSYM));
			else
				return (-1); /* errno set from lookup_by_file */
		}

		goto found;
	}

	if (mdb_gelf_symtab_lookup_by_name(pt->p_symtab, name, symp, &i) == 0) {
		sip->sym_table = MDB_TGT_SYMTAB;
		sip->sym_id = i;
		goto local_found;
	}

	if (mdb_gelf_symtab_lookup_by_name(pt->p_dynsym, name, symp, &i) == 0) {
		sip->sym_table = MDB_TGT_DYNSYM;
		sip->sym_id = i;
		goto local_found;
	}

	return (set_errno(EMDB_NOSYM));

local_found:
	if (pt->p_file != NULL &&
	    pt->p_file->gf_ehdr.e_type == ET_DYN &&
	    P != NULL &&
	    (aout_lop = Pname_to_loadobj(P, PR_OBJ_EXEC)) != NULL)
		symp->st_value += aout_lop->rl_base;

found:
	/*
	 * If the symbol has type TLS, libproc should have found the symbol
	 * if it exists and has been allocated.
	 */
	if (GELF_ST_TYPE(symp->st_info) == STT_TLS)
		return (set_errno(EMDB_TLS));

	return (0);
}

static int
pt_lookup_by_name(mdb_tgt_t *t, const char *object,
    const char *name, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	return (pt_lookup_by_name_thr(t, object, name, symp, sip, PTL_TID(t)));
}

static int
pt_lookup_by_addr(mdb_tgt_t *t, uintptr_t addr, uint_t flags,
    char *buf, size_t nbytes, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	struct ps_prochandle *P = t->t_pshandle;
	pt_data_t *pt = t->t_data;
	rd_plt_info_t rpi = { 0 };

	const char *pltsym;
	int rv, match, i;

	mdb_gelf_symtab_t *gsts[3];	/* mdb.m_prsym, .symtab, .dynsym */
	int gstc = 0;			/* number of valid gsts[] entries */

	mdb_gelf_symtab_t *gst = NULL;	/* set if 'sym' is from a gst */
	const prmap_t *pmp = NULL;	/* set if 'sym' is from libproc */
	GElf_Sym sym;			/* best symbol found so far if !exact */
	prsyminfo_t si;

	/*
	 * Fill in our array of symbol table pointers with the private symbol
	 * table, static symbol table, and dynamic symbol table if applicable.
	 * These are done in order of precedence so that if we match and
	 * MDB_TGT_SYM_EXACT is set, we need not look any further.
	 */
	if (mdb.m_prsym != NULL)
		gsts[gstc++] = mdb.m_prsym;
	if (P == NULL && pt->p_symtab != NULL)
		gsts[gstc++] = pt->p_symtab;
	if (P == NULL && pt->p_dynsym != NULL)
		gsts[gstc++] = pt->p_dynsym;

	/*
	 * Loop through our array attempting to match the address.  If we match
	 * and we're in exact mode, we're done.  Otherwise save the symbol in
	 * the local sym variable if it is closer than our previous match.
	 * We explicitly watch for zero-valued symbols since DevPro insists
	 * on storing __fsr_init_value's value as the symbol value instead
	 * of storing it in a constant integer.
	 */
	for (i = 0; i < gstc; i++) {
		if (mdb_gelf_symtab_lookup_by_addr(gsts[i], addr, flags, buf,
		    nbytes, symp, &sip->sym_id) != 0 || symp->st_value == 0)
			continue;

		if (flags & MDB_TGT_SYM_EXACT) {
			gst = gsts[i];
			goto found;
		}

		if (gst == NULL || mdb_gelf_sym_closer(symp, &sym, addr)) {
			gst = gsts[i];
			sym = *symp;
		}
	}

	/*
	 * If we have no libproc handle active, we're done: fail if gst is
	 * NULL; otherwise copy out our best symbol and skip to the end.
	 * We also skip to found if gst is the private symbol table: we
	 * want this to always take precedence over PLT re-vectoring.
	 */
	if (P == NULL || (gst != NULL && gst == mdb.m_prsym)) {
		if (gst == NULL)
			return (set_errno(EMDB_NOSYMADDR));
		*symp = sym;
		goto found;
	}

	/*
	 * Check to see if the address is in a PLT: if it is, use librtld_db to
	 * attempt to resolve the PLT entry.  If the entry is bound, reset addr
	 * to the bound address, add a special prefix to the caller's buf,
	 * forget our previous guess, and then continue using the new addr.
	 * If the entry is not bound, copy the corresponding symbol name into
	 * buf and return a fake symbol for the given address.
	 */
	if ((pltsym = Ppltdest(P, addr)) != NULL) {
		const rd_loadobj_t *rlp;
		rd_agent_t *rap;

		if ((rap = Prd_agent(P)) != NULL &&
		    (rlp = Paddr_to_loadobj(P, addr)) != NULL &&
		    rd_plt_resolution(rap, addr, Pstatus(P)->pr_lwp.pr_lwpid,
		    rlp->rl_plt_base, &rpi) == RD_OK &&
		    (rpi.pi_flags & RD_FLG_PI_PLTBOUND)) {
			size_t n;
			n = mdb_iob_snprintf(buf, nbytes, "PLT=");
			addr = rpi.pi_baddr;
			if (n > nbytes) {
				buf += nbytes;
				nbytes = 0;
			} else {
				buf += n;
				nbytes -= n;
			}
			gst = NULL;
		} else {
			(void) mdb_iob_snprintf(buf, nbytes, "PLT:%s", pltsym);
			bzero(symp, sizeof (GElf_Sym));
			symp->st_value = addr;
			symp->st_info = GELF_ST_INFO(STB_GLOBAL, STT_FUNC);
			return (0);
		}
	}

	/*
	 * Ask libproc to convert the address to the closest symbol for us.
	 * Once we get the closest symbol, we perform the EXACT match or
	 * smart-mode or absolute distance check ourself:
	 */
	if (PT_LIBPROC_RESOLVE(P)) {
		rv = Pxlookup_by_addr_resolved(P, addr, buf, nbytes,
		    symp, &si);
	} else {
		rv = Pxlookup_by_addr(P, addr, buf, nbytes,
		    symp, &si);
	}
	if ((rv == 0) && (symp->st_value != 0) &&
	    (gst == NULL || mdb_gelf_sym_closer(symp, &sym, addr))) {

		if (flags & MDB_TGT_SYM_EXACT)
			match = (addr == symp->st_value);
		else if (mdb.m_symdist == 0)
			match = (addr >= symp->st_value &&
			    addr < symp->st_value + symp->st_size);
		else
			match = (addr >= symp->st_value &&
			    addr < symp->st_value + mdb.m_symdist);

		if (match) {
			pmp = Paddr_to_map(P, addr);
			gst = NULL;
			sip->sym_table = si.prs_table;
			sip->sym_id = si.prs_id;
			goto found;
		}
	}

	/*
	 * If we get here, Plookup_by_addr has failed us.  If we have no
	 * previous best symbol (gst == NULL), we've failed completely.
	 * Otherwise we copy out that symbol and continue on to 'found'.
	 */
	if (gst == NULL)
		return (set_errno(EMDB_NOSYMADDR));
	*symp = sym;
found:
	/*
	 * Once we've found something, copy the final name into the caller's
	 * buffer and prefix it with the mapping name if appropriate.
	 */
	if (pmp != NULL && pmp != Pname_to_map(P, PR_OBJ_EXEC)) {
		const char *prefix = pmp->pr_mapname;
		Lmid_t lmid;

		if (PT_LIBPROC_RESOLVE(P)) {
			if (Pobjname_resolved(P, addr, pt->p_objname,
			    MDB_TGT_MAPSZ))
				prefix = pt->p_objname;
		} else {
			if (Pobjname(P, addr, pt->p_objname, MDB_TGT_MAPSZ))
				prefix = pt->p_objname;
		}

		if (buf != NULL && nbytes > 1) {
			(void) strncpy(pt->p_symname, buf, MDB_TGT_SYM_NAMLEN);
			pt->p_symname[MDB_TGT_SYM_NAMLEN - 1] = '\0';
		} else {
			pt->p_symname[0] = '\0';
		}

		if (prefix == pt->p_objname && Plmid(P, addr, &lmid) == 0 && (
		    (lmid != LM_ID_BASE && lmid != LM_ID_LDSO) ||
		    (mdb.m_flags & MDB_FL_SHOWLMID))) {
			(void) mdb_iob_snprintf(buf, nbytes, "LM%lr`%s`%s",
			    lmid, strbasename(prefix), pt->p_symname);
		} else {
			(void) mdb_iob_snprintf(buf, nbytes, "%s`%s",
			    strbasename(prefix), pt->p_symname);
		}

	} else if (gst != NULL && buf != NULL && nbytes > 0) {
		(void) strncpy(buf, mdb_gelf_sym_name(gst, symp), nbytes);
		buf[nbytes - 1] = '\0';
	}

	return (0);
}


static int
pt_symbol_iter_cb(void *arg, const GElf_Sym *sym, const char *name,
    const prsyminfo_t *sip)
{
	pt_symarg_t *psp = arg;

	psp->psym_info.sym_id = sip->prs_id;

	return (psp->psym_func(psp->psym_private, sym, name, &psp->psym_info,
	    psp->psym_obj));
}

static int
pt_objsym_iter(void *arg, const prmap_t *pmp, const char *object)
{
	Lmid_t lmid = PR_LMID_EVERY;
	pt_symarg_t *psp = arg;

	psp->psym_obj = object;

	(void) Plmid(psp->psym_targ->t_pshandle, pmp->pr_vaddr, &lmid);
	(void) Pxsymbol_iter(psp->psym_targ->t_pshandle, lmid, object,
	    psp->psym_which, psp->psym_type, pt_symbol_iter_cb, arg);

	return (0);
}

static int
pt_symbol_filt(void *arg, const GElf_Sym *sym, const char *name, uint_t id)
{
	pt_symarg_t *psp = arg;

	if (mdb_tgt_sym_match(sym, psp->psym_type)) {
		psp->psym_info.sym_id = id;
		return (psp->psym_func(psp->psym_private, sym, name,
		    &psp->psym_info, psp->psym_obj));
	}

	return (0);
}

static int
pt_symbol_iter(mdb_tgt_t *t, const char *object, uint_t which,
    uint_t type, mdb_tgt_sym_f *func, void *private)
{
	pt_data_t *pt = t->t_data;
	mdb_gelf_symtab_t *gst;
	pt_symarg_t ps;
	Lmid_t lmid;

	object = pt_resolve_lmid(object, &lmid);

	ps.psym_targ = t;
	ps.psym_which = which;
	ps.psym_type = type;
	ps.psym_func = func;
	ps.psym_private = private;
	ps.psym_obj = object;

	if (t->t_pshandle != NULL) {
		if (object != MDB_TGT_OBJ_EVERY) {
			if (Plmid_to_map(t->t_pshandle, lmid, object) == NULL)
				return (set_errno(EMDB_NOOBJ));
			(void) Pxsymbol_iter(t->t_pshandle, lmid, object,
			    which, type, pt_symbol_iter_cb, &ps);
			return (0);
		} else if (Prd_agent(t->t_pshandle) != NULL) {
			if (PT_LIBPROC_RESOLVE(t->t_pshandle)) {
				(void) Pobject_iter_resolved(t->t_pshandle,
				    pt_objsym_iter, &ps);
			} else {
				(void) Pobject_iter(t->t_pshandle,
				    pt_objsym_iter, &ps);
			}
			return (0);
		}
	}

	if (lmid != LM_ID_BASE && lmid != PR_LMID_EVERY)
		return (set_errno(EMDB_NOLMID));

	if (object != MDB_TGT_OBJ_EXEC && object != MDB_TGT_OBJ_EVERY &&
	    pt->p_fio != NULL &&
	    strcmp(object, IOP_NAME(pt->p_fio)) != 0)
		return (set_errno(EMDB_NOOBJ));

	if (which == MDB_TGT_SYMTAB)
		gst = pt->p_symtab;
	else
		gst = pt->p_dynsym;

	if (gst != NULL) {
		ps.psym_info.sym_table = gst->gst_tabid;
		mdb_gelf_symtab_iter(gst, pt_symbol_filt, &ps);
	}

	return (0);
}

static const mdb_map_t *
pt_prmap_to_mdbmap(mdb_tgt_t *t, const prmap_t *prp, mdb_map_t *mp)
{
	struct ps_prochandle *P = t->t_pshandle;
	char *rv, name[MAXPATHLEN];
	Lmid_t lmid;

	if (PT_LIBPROC_RESOLVE(P)) {
		rv = Pobjname_resolved(P, prp->pr_vaddr, name, sizeof (name));
	} else {
		rv = Pobjname(P, prp->pr_vaddr, name, sizeof (name));
	}

	if (rv != NULL) {
		if (Plmid(P, prp->pr_vaddr, &lmid) == 0 && (
		    (lmid != LM_ID_BASE && lmid != LM_ID_LDSO) ||
		    (mdb.m_flags & MDB_FL_SHOWLMID))) {
			(void) mdb_iob_snprintf(mp->map_name, MDB_TGT_MAPSZ,
			    "LM%lr`%s", lmid, name);
		} else {
			(void) strncpy(mp->map_name, name, MDB_TGT_MAPSZ - 1);
			mp->map_name[MDB_TGT_MAPSZ - 1] = '\0';
		}
	} else {
		(void) strncpy(mp->map_name, prp->pr_mapname,
		    MDB_TGT_MAPSZ - 1);
		mp->map_name[MDB_TGT_MAPSZ - 1] = '\0';
	}

	mp->map_base = prp->pr_vaddr;
	mp->map_size = prp->pr_size;
	mp->map_flags = 0;

	if (prp->pr_mflags & MA_READ)
		mp->map_flags |= MDB_TGT_MAP_R;
	if (prp->pr_mflags & MA_WRITE)
		mp->map_flags |= MDB_TGT_MAP_W;
	if (prp->pr_mflags & MA_EXEC)
		mp->map_flags |= MDB_TGT_MAP_X;

	if (prp->pr_mflags & MA_SHM)
		mp->map_flags |= MDB_TGT_MAP_SHMEM;
	if (prp->pr_mflags & MA_BREAK)
		mp->map_flags |= MDB_TGT_MAP_HEAP;
	if (prp->pr_mflags & MA_STACK)
		mp->map_flags |= MDB_TGT_MAP_STACK;
	if (prp->pr_mflags & MA_ANON)
		mp->map_flags |= MDB_TGT_MAP_ANON;

	return (mp);
}

/*ARGSUSED*/
static int
pt_map_apply(void *arg, const prmap_t *prp, const char *name)
{
	pt_maparg_t *pmp = arg;
	mdb_map_t map;

	return (pmp->pmap_func(pmp->pmap_private,
	    pt_prmap_to_mdbmap(pmp->pmap_targ, prp, &map), map.map_name));
}

static int
pt_mapping_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	if (t->t_pshandle != NULL) {
		pt_maparg_t pm;

		pm.pmap_targ = t;
		pm.pmap_func = func;
		pm.pmap_private = private;

		if (PT_LIBPROC_RESOLVE(t->t_pshandle)) {
			(void) Pmapping_iter_resolved(t->t_pshandle,
			    pt_map_apply, &pm);
		} else {
			(void) Pmapping_iter(t->t_pshandle,
			    pt_map_apply, &pm);
		}
		return (0);
	}

	return (set_errno(EMDB_NOPROC));
}

static int
pt_object_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	pt_data_t *pt = t->t_data;

	/*
	 * If we have a libproc handle, we can just call Pobject_iter to
	 * iterate over its list of load object information.
	 */
	if (t->t_pshandle != NULL) {
		pt_maparg_t pm;

		pm.pmap_targ = t;
		pm.pmap_func = func;
		pm.pmap_private = private;

		if (PT_LIBPROC_RESOLVE(t->t_pshandle)) {
			(void) Pobject_iter_resolved(t->t_pshandle,
			    pt_map_apply, &pm);
		} else {
			(void) Pobject_iter(t->t_pshandle,
			    pt_map_apply, &pm);
		}
		return (0);
	}

	/*
	 * If we're examining an executable or other ELF file but we have no
	 * libproc handle, fake up some information based on DT_NEEDED entries.
	 */
	if (pt->p_dynsym != NULL && pt->p_file->gf_dyns != NULL &&
	    pt->p_fio != NULL) {
		mdb_gelf_sect_t *gsp = pt->p_dynsym->gst_ssect;
		GElf_Dyn *dynp = pt->p_file->gf_dyns;
		mdb_map_t *mp = &pt->p_map;
		const char *s = IOP_NAME(pt->p_fio);
		size_t i;

		(void) strncpy(mp->map_name, s, MDB_TGT_MAPSZ);
		mp->map_name[MDB_TGT_MAPSZ - 1] = '\0';
		mp->map_flags = MDB_TGT_MAP_R | MDB_TGT_MAP_X;
		mp->map_base = NULL;
		mp->map_size = 0;

		if (func(private, mp, s) != 0)
			return (0);

		for (i = 0; i < pt->p_file->gf_ndyns; i++, dynp++) {
			if (dynp->d_tag == DT_NEEDED) {
				s = (char *)gsp->gs_data + dynp->d_un.d_val;
				(void) strncpy(mp->map_name, s, MDB_TGT_MAPSZ);
				mp->map_name[MDB_TGT_MAPSZ - 1] = '\0';
				if (func(private, mp, s) != 0)
					return (0);
			}
		}

		return (0);
	}

	return (set_errno(EMDB_NOPROC));
}

static const mdb_map_t *
pt_addr_to_map(mdb_tgt_t *t, uintptr_t addr)
{
	pt_data_t *pt = t->t_data;
	const prmap_t *pmp;

	if (t->t_pshandle == NULL) {
		(void) set_errno(EMDB_NOPROC);
		return (NULL);
	}

	if ((pmp = Paddr_to_map(t->t_pshandle, addr)) == NULL) {
		(void) set_errno(EMDB_NOMAP);
		return (NULL);
	}

	return (pt_prmap_to_mdbmap(t, pmp, &pt->p_map));
}

static const mdb_map_t *
pt_name_to_map(mdb_tgt_t *t, const char *object)
{
	pt_data_t *pt = t->t_data;
	const prmap_t *pmp;
	Lmid_t lmid;

	if (t->t_pshandle == NULL) {
		(void) set_errno(EMDB_NOPROC);
		return (NULL);
	}

	object = pt_resolve_lmid(object, &lmid);

	if ((pmp = Plmid_to_map(t->t_pshandle, lmid, object)) == NULL) {
		(void) set_errno(EMDB_NOOBJ);
		return (NULL);
	}

	return (pt_prmap_to_mdbmap(t, pmp, &pt->p_map));
}

static ctf_file_t *
pt_addr_to_ctf(mdb_tgt_t *t, uintptr_t addr)
{
	ctf_file_t *ret;

	if (t->t_pshandle == NULL) {
		(void) set_errno(EMDB_NOPROC);
		return (NULL);
	}

	if ((ret = Paddr_to_ctf(t->t_pshandle, addr)) == NULL) {
		(void) set_errno(EMDB_NOOBJ);
		return (NULL);
	}

	return (ret);
}

static ctf_file_t *
pt_name_to_ctf(mdb_tgt_t *t, const char *name)
{
	ctf_file_t *ret;

	if (t->t_pshandle == NULL) {
		(void) set_errno(EMDB_NOPROC);
		return (NULL);
	}

	if ((ret = Pname_to_ctf(t->t_pshandle, name)) == NULL) {
		(void) set_errno(EMDB_NOOBJ);
		return (NULL);
	}

	return (ret);
}

static int
pt_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	const pstatus_t *psp;
	prgregset_t gregs;
	int state;

	bzero(tsp, sizeof (mdb_tgt_status_t));

	if (t->t_pshandle == NULL) {
		tsp->st_state = MDB_TGT_IDLE;
		return (0);
	}

	switch (state = Pstate(t->t_pshandle)) {
	case PS_RUN:
		tsp->st_state = MDB_TGT_RUNNING;
		break;

	case PS_STOP:
		tsp->st_state = MDB_TGT_STOPPED;
		psp = Pstatus(t->t_pshandle);

		tsp->st_tid = PTL_TID(t);
		if (PTL_GETREGS(t, tsp->st_tid, gregs) == 0)
			tsp->st_pc = gregs[R_PC];

		if (psp->pr_flags & PR_ISTOP)
			tsp->st_flags |= MDB_TGT_ISTOP;
		if (psp->pr_flags & PR_DSTOP)
			tsp->st_flags |= MDB_TGT_DSTOP;

		break;

	case PS_LOST:
		tsp->st_state = MDB_TGT_LOST;
		break;
	case PS_UNDEAD:
		tsp->st_state = MDB_TGT_UNDEAD;
		break;
	case PS_DEAD:
		tsp->st_state = MDB_TGT_DEAD;
		break;
	case PS_IDLE:
		tsp->st_state = MDB_TGT_IDLE;
		break;
	default:
		fail("unknown libproc state (%d)\n", state);
	}

	if (t->t_flags & MDB_TGT_F_BUSY)
		tsp->st_flags |= MDB_TGT_BUSY;

	return (0);
}

static void
pt_dupfd(const char *file, int oflags, mode_t mode, int dfd)
{
	int fd;

	if ((fd = open(file, oflags, mode)) >= 0) {
		(void) fcntl(fd, F_DUP2FD, dfd);
		(void) close(fd);
	} else
		warn("failed to open %s as descriptor %d", file, dfd);
}

/*
 * The Pcreate_callback() function interposes on the default, empty libproc
 * definition.  It will be called following a fork of a new child process by
 * Pcreate() below, but before the exec of the new process image.  We use this
 * callback to optionally redirect stdin and stdout and reset the dispositions
 * of SIGPIPE and SIGQUIT from SIG_IGN back to SIG_DFL.
 */
/*ARGSUSED*/
void
Pcreate_callback(struct ps_prochandle *P)
{
	pt_data_t *pt = mdb.m_target->t_data;

	if (pt->p_stdin != NULL)
		pt_dupfd(pt->p_stdin, O_RDWR, 0, STDIN_FILENO);
	if (pt->p_stdout != NULL)
		pt_dupfd(pt->p_stdout, O_CREAT | O_WRONLY, 0666, STDOUT_FILENO);

	(void) mdb_signal_sethandler(SIGPIPE, SIG_DFL, NULL);
	(void) mdb_signal_sethandler(SIGQUIT, SIG_DFL, NULL);
}

static int
pt_run(mdb_tgt_t *t, int argc, const mdb_arg_t *argv)
{
	pt_data_t *pt = t->t_data;
	struct ps_prochandle *P;
	char execname[MAXPATHLEN];
	const char **pargv;
	int pargc = 0;
	int i, perr;
	char **penv;
	mdb_var_t *v;

	if (pt->p_aout_fio == NULL) {
		warn("run requires executable to be specified on "
		    "command-line\n");
		return (set_errno(EMDB_TGT));
	}

	pargv = mdb_alloc(sizeof (char *) * (argc + 2), UM_SLEEP);
	pargv[pargc++] = strbasename(IOP_NAME(pt->p_aout_fio));

	for (i = 0; i < argc; i++) {
		if (argv[i].a_type != MDB_TYPE_STRING) {
			mdb_free(pargv, sizeof (char *) * (argc + 2));
			return (set_errno(EINVAL));
		}
		if (argv[i].a_un.a_str[0] == '<')
			pt->p_stdin = argv[i].a_un.a_str + 1;
		else if (argv[i].a_un.a_str[0] == '>')
			pt->p_stdout = argv[i].a_un.a_str + 1;
		else
			pargv[pargc++] = argv[i].a_un.a_str;
	}
	pargv[pargc] = NULL;

	/*
	 * Since Pcreate() uses execvp() and "." may not be present in $PATH,
	 * we must manually prepend "./" when the executable is a simple name.
	 */
	if (strchr(IOP_NAME(pt->p_aout_fio), '/') == NULL) {
		(void) snprintf(execname, sizeof (execname), "./%s",
		    IOP_NAME(pt->p_aout_fio));
	} else {
		(void) snprintf(execname, sizeof (execname), "%s",
		    IOP_NAME(pt->p_aout_fio));
	}

	penv = mdb_alloc((mdb_nv_size(&pt->p_env)+ 1) * sizeof (char *),
	    UM_SLEEP);
	for (mdb_nv_rewind(&pt->p_env), i = 0;
	    (v = mdb_nv_advance(&pt->p_env)) != NULL; i++)
		penv[i] = mdb_nv_get_cookie(v);
	penv[i] = NULL;

	P = Pxcreate(execname, (char **)pargv, penv, &perr, NULL, 0);
	mdb_free(pargv, sizeof (char *) * (argc + 2));
	pt->p_stdin = pt->p_stdout = NULL;

	mdb_free(penv, i * sizeof (char *));

	if (P == NULL) {
		warn("failed to create process: %s\n", Pcreate_error(perr));
		return (set_errno(EMDB_TGT));
	}

	if (t->t_pshandle != NULL) {
		pt_pre_detach(t, TRUE);
		if (t->t_pshandle != pt->p_idlehandle)
			Prelease(t->t_pshandle, pt->p_rflags);
	}

	(void) Punsetflags(P, PR_RLC);	/* make sure run-on-last-close is off */
	(void) Psetflags(P, PR_KLC);	/* kill on last close by debugger */
	pt->p_rflags = PRELEASE_KILL;	/* kill on debugger Prelease */
	t->t_pshandle = P;

	pt_post_attach(t);
	pt_activate_common(t);
	(void) mdb_tgt_status(t, &t->t_status);
	mdb.m_flags |= MDB_FL_VCREATE;

	return (0);
}

/*
 * Forward a signal to the victim process in order to force it to stop or die.
 * Refer to the comments above pt_setrun(), below, for more info.
 */
/*ARGSUSED*/
static void
pt_sigfwd(int sig, siginfo_t *sip, ucontext_t *ucp, mdb_tgt_t *t)
{
	struct ps_prochandle *P = t->t_pshandle;
	const lwpstatus_t *psp = &Pstatus(P)->pr_lwp;
	pid_t pid = Pstatus(P)->pr_pid;
	long ctl[2];

	if (getpgid(pid) != mdb.m_pgid) {
		mdb_dprintf(MDB_DBG_TGT, "fwd SIG#%d to %d\n", sig, (int)pid);
		(void) kill(pid, sig);
	}

	if (Pwait(P, 1) == 0 && (psp->pr_flags & PR_STOPPED) &&
	    psp->pr_why == PR_JOBCONTROL && Pdstop(P) == 0) {
		/*
		 * If we're job control stopped and our DSTOP is pending, the
		 * victim will never see our signal, so undo the kill() and
		 * then send SIGCONT the victim to kick it out of the job
		 * control stop and force our DSTOP to take effect.
		 */
		if ((psp->pr_flags & PR_DSTOP) &&
		    prismember(&Pstatus(P)->pr_sigpend, sig)) {
			ctl[0] = PCUNKILL;
			ctl[1] = sig;
			(void) write(Pctlfd(P), ctl, sizeof (ctl));
		}

		mdb_dprintf(MDB_DBG_TGT, "fwd SIGCONT to %d\n", (int)pid);
		(void) kill(pid, SIGCONT);
	}
}

/*
 * Common code for step and continue: if no victim process has been created,
 * call pt_run() to create one.  Then set the victim running, clearing any
 * pending fault.  One special case is that if the victim was previously
 * stopped on reception of SIGINT, we know that SIGINT was traced and the user
 * requested the victim to stop, so clear this signal before continuing.
 * For all other traced signals, the signal will be delivered on continue.
 *
 * Once the victim process is running, we wait for it to stop on an event of
 * interest.  Although libproc provides the basic primitive to wait for the
 * victim, we must be careful in our handling of signals.  We want to allow the
 * user to issue a SIGINT or SIGQUIT using the designated terminal control
 * character (typically ^C and ^\), and have these signals stop the target and
 * return control to the debugger if the signals are traced.  There are three
 * cases to be considered in our implementation:
 *
 * (1) If the debugger and victim are in the same process group, both receive
 * the signal from the terminal driver.  The debugger returns from Pwait() with
 * errno = EINTR, so we want to loop back and continue waiting until the victim
 * stops on receipt of its SIGINT or SIGQUIT.
 *
 * (2) If the debugger and victim are in different process groups, and the
 * victim is a member of the foreground process group, it will receive the
 * signal from the terminal driver and the debugger will not.  As such, we
 * will remain blocked in Pwait() until the victim stops on its signal.
 *
 * (3) If the debugger and victim are in different process groups, and the
 * debugger is a member of the foreground process group, it will receive the
 * signal from the terminal driver, and the victim will not.  The debugger
 * returns from Pwait() with errno = EINTR, so we need to forward the signal
 * to the victim process directly and then Pwait() again for it to stop.
 *
 * We can observe that all three cases are handled by simply calling Pwait()
 * repeatedly if it fails with EINTR, and forwarding SIGINT and SIGQUIT to
 * the victim if it is in a different process group, using pt_sigfwd() above.
 *
 * An additional complication is that the process may not be able to field
 * the signal if it is currently stopped by job control.  In this case, we
 * also DSTOP the process, and then send it a SIGCONT to wake it up from
 * job control and force it to re-enter stop() under the control of /proc.
 *
 * Finally, we would like to allow the user to suspend the process using the
 * terminal suspend character (typically ^Z) if both are in the same session.
 * We again employ pt_sigfwd() to forward SIGTSTP to the victim, wait for it to
 * stop from job control, and then capture it using /proc.  Once the process
 * has stopped, normal SIGTSTP processing is restored and the user can issue
 * another ^Z in order to suspend the debugger and return to the parent shell.
 */
static int
pt_setrun(mdb_tgt_t *t, mdb_tgt_status_t *tsp, int flags)
{
	struct ps_prochandle *P = t->t_pshandle;
	pt_data_t *pt = t->t_data;
	pid_t old_pgid = -1;

	mdb_signal_f *intf, *quitf, *tstpf;
	const lwpstatus_t *psp;
	void *intd, *quitd, *tstpd;

	int sig = pt->p_signal;
	int error = 0;
	int pgid = -1;

	pt->p_signal = 0; /* clear pending signal */

	if (P == NULL && pt_run(t, 0, NULL) == -1)
		return (-1); /* errno is set for us */

	P = t->t_pshandle;
	psp = &Pstatus(P)->pr_lwp;

	if (sig == 0 && psp->pr_why == PR_SIGNALLED && psp->pr_what == SIGINT)
		flags |= PRCSIG; /* clear pending SIGINT */
	else
		flags |= PRCFAULT; /* clear any pending fault (e.g. BPT) */

	intf = mdb_signal_gethandler(SIGINT, &intd);
	quitf = mdb_signal_gethandler(SIGQUIT, &quitd);
	tstpf = mdb_signal_gethandler(SIGTSTP, &tstpd);

	(void) mdb_signal_sethandler(SIGINT, (mdb_signal_f *)pt_sigfwd, t);
	(void) mdb_signal_sethandler(SIGQUIT, (mdb_signal_f *)pt_sigfwd, t);
	(void) mdb_signal_sethandler(SIGTSTP, (mdb_signal_f *)pt_sigfwd, t);

	if (sig != 0 && Pstate(P) == PS_RUN &&
	    kill(Pstatus(P)->pr_pid, sig) == -1) {
		error = errno;
		goto out;
	}

	/*
	 * If we attached to a job stopped background process in the same
	 * session, make its pgid the foreground process group before running
	 * it.  Ignore SIGTTOU while doing this to avoid being suspended.
	 */
	if (mdb.m_flags & MDB_FL_JOBCTL) {
		(void) mdb_signal_sethandler(SIGTTOU, SIG_IGN, NULL);
		(void) IOP_CTL(mdb.m_term, TIOCGPGRP, &old_pgid);
		(void) IOP_CTL(mdb.m_term, TIOCSPGRP,
		    (void *)&Pstatus(P)->pr_pgid);
		(void) mdb_signal_sethandler(SIGTTOU, SIG_DFL, NULL);
	}

	if (Pstate(P) != PS_RUN && Psetrun(P, sig, flags) == -1) {
		error = errno;
		goto out;
	}

	/*
	 * If the process is stopped on job control, resume its process group
	 * by sending it a SIGCONT if we are in the same session.  Otherwise
	 * we have no choice but to wait for someone else to foreground it.
	 */
	if (psp->pr_why == PR_JOBCONTROL) {
		if (mdb.m_flags & MDB_FL_JOBCTL)
			(void) kill(-Pstatus(P)->pr_pgid, SIGCONT);
		else if (mdb.m_term != NULL)
			warn("process is still suspended by job control ...\n");
	}

	/*
	 * Wait for the process to stop.  As described above, we loop around if
	 * we are interrupted (EINTR).  If we lose control, attempt to re-open
	 * the process, or call pt_exec() if that fails to handle a re-exec.
	 * If the process dies (ENOENT) or Pwait() fails, break out of the loop.
	 */
	while (Pwait(P, 0) == -1) {
		if (errno != EINTR) {
			if (Pstate(P) == PS_LOST) {
				if (Preopen(P) == 0)
					continue; /* Pwait() again */
				else
					pt_exec(t, 0, NULL);
			} else if (errno != ENOENT)
				warn("failed to wait for event");
			break;
		}
	}

	/*
	 * If we changed the foreground process group, restore the old pgid
	 * while ignoring SIGTTOU so we are not accidentally suspended.
	 */
	if (old_pgid != -1) {
		(void) mdb_signal_sethandler(SIGTTOU, SIG_IGN, NULL);
		(void) IOP_CTL(mdb.m_term, TIOCSPGRP, &pgid);
		(void) mdb_signal_sethandler(SIGTTOU, SIG_DFL, NULL);
	}

	/*
	 * If we're now stopped on exit from a successful exec, release any
	 * vfork parents and clean out their address space before returning
	 * to tgt_continue() and perturbing the list of armed event specs.
	 * If we're stopped for any other reason, just update the mappings.
	 */
	switch (Pstate(P)) {
	case PS_STOP:
		if (psp->pr_why == PR_SYSEXIT && psp->pr_errno == 0 &&
		    psp->pr_what == SYS_execve)
			pt_release_parents(t);
		else
			Pupdate_maps(P);
		break;

	case PS_UNDEAD:
	case PS_LOST:
		pt_release_parents(t);
		break;
	}

out:
	(void) mdb_signal_sethandler(SIGINT, intf, intd);
	(void) mdb_signal_sethandler(SIGQUIT, quitf, quitd);
	(void) mdb_signal_sethandler(SIGTSTP, tstpf, tstpd);
	(void) pt_status(t, tsp);

	return (error ? set_errno(error) : 0);
}

static int
pt_step(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	return (pt_setrun(t, tsp, PRSTEP));
}

static int
pt_continue(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	return (pt_setrun(t, tsp, 0));
}

static int
pt_signal(mdb_tgt_t *t, int sig)
{
	pt_data_t *pt = t->t_data;

	if (sig > 0 && sig <= pt->p_maxsig) {
		pt->p_signal = sig; /* pending until next pt_setrun */
		return (0);
	}

	return (set_errno(EMDB_BADSIGNUM));
}

static int
pt_sysenter_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	struct ps_prochandle *P = t->t_pshandle;

	if (P != NULL && Pstate(P) < PS_LOST) {
		sep->se_data = args; /* data is raw system call number */
		return (Psysentry(P, (intptr_t)args, TRUE) < 0 ? -1 : 0);
	}

	return (set_errno(EMDB_NOPROC));
}

static void
pt_sysenter_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	(void) Psysentry(t->t_pshandle, (intptr_t)sep->se_data, FALSE);
}

/*ARGSUSED*/
static char *
pt_sysenter_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	char name[32];
	int sysnum;

	if (vep != NULL)
		sysnum = (intptr_t)vep->ve_args;
	else
		sysnum = (intptr_t)sep->se_data;

	(void) proc_sysname(sysnum, name, sizeof (name));
	(void) mdb_iob_snprintf(buf, nbytes, "stop on entry to %s", name);

	return (buf);
}

/*ARGSUSED*/
static int
pt_sysenter_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	int sysnum = (intptr_t)sep->se_data;

	return (psp->pr_why == PR_SYSENTRY && psp->pr_what == sysnum);
}

static const mdb_se_ops_t proc_sysenter_ops = {
	pt_sysenter_ctor,	/* se_ctor */
	pt_sysenter_dtor,	/* se_dtor */
	pt_sysenter_info,	/* se_info */
	no_se_secmp,		/* se_secmp */
	no_se_vecmp,		/* se_vecmp */
	no_se_arm,		/* se_arm */
	no_se_disarm,		/* se_disarm */
	no_se_cont,		/* se_cont */
	pt_sysenter_match	/* se_match */
};

static int
pt_sysexit_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	struct ps_prochandle *P = t->t_pshandle;

	if (P != NULL && Pstate(P) < PS_LOST) {
		sep->se_data = args; /* data is raw system call number */
		return (Psysexit(P, (intptr_t)args, TRUE) < 0 ? -1 : 0);
	}

	return (set_errno(EMDB_NOPROC));
}

static void
pt_sysexit_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	(void) Psysexit(t->t_pshandle, (intptr_t)sep->se_data, FALSE);
}

/*ARGSUSED*/
static char *
pt_sysexit_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	char name[32];
	int sysnum;

	if (vep != NULL)
		sysnum = (intptr_t)vep->ve_args;
	else
		sysnum = (intptr_t)sep->se_data;

	(void) proc_sysname(sysnum, name, sizeof (name));
	(void) mdb_iob_snprintf(buf, nbytes, "stop on exit from %s", name);

	return (buf);
}

/*ARGSUSED*/
static int
pt_sysexit_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	int sysnum = (intptr_t)sep->se_data;

	return (psp->pr_why == PR_SYSEXIT && psp->pr_what == sysnum);
}

static const mdb_se_ops_t proc_sysexit_ops = {
	pt_sysexit_ctor,	/* se_ctor */
	pt_sysexit_dtor,	/* se_dtor */
	pt_sysexit_info,	/* se_info */
	no_se_secmp,		/* se_secmp */
	no_se_vecmp,		/* se_vecmp */
	no_se_arm,		/* se_arm */
	no_se_disarm,		/* se_disarm */
	no_se_cont,		/* se_cont */
	pt_sysexit_match	/* se_match */
};

static int
pt_signal_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	struct ps_prochandle *P = t->t_pshandle;

	if (P != NULL && Pstate(P) < PS_LOST) {
		sep->se_data = args; /* data is raw signal number */
		return (Psignal(P, (intptr_t)args, TRUE) < 0 ? -1 : 0);
	}

	return (set_errno(EMDB_NOPROC));
}

static void
pt_signal_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	(void) Psignal(t->t_pshandle, (intptr_t)sep->se_data, FALSE);
}

/*ARGSUSED*/
static char *
pt_signal_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	char name[SIG2STR_MAX];
	int signum;

	if (vep != NULL)
		signum = (intptr_t)vep->ve_args;
	else
		signum = (intptr_t)sep->se_data;

	(void) proc_signame(signum, name, sizeof (name));
	(void) mdb_iob_snprintf(buf, nbytes, "stop on %s", name);

	return (buf);
}

/*ARGSUSED*/
static int
pt_signal_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	int signum = (intptr_t)sep->se_data;

	return (psp->pr_why == PR_SIGNALLED && psp->pr_what == signum);
}

static const mdb_se_ops_t proc_signal_ops = {
	pt_signal_ctor,		/* se_ctor */
	pt_signal_dtor,		/* se_dtor */
	pt_signal_info,		/* se_info */
	no_se_secmp,		/* se_secmp */
	no_se_vecmp,		/* se_vecmp */
	no_se_arm,		/* se_arm */
	no_se_disarm,		/* se_disarm */
	no_se_cont,		/* se_cont */
	pt_signal_match		/* se_match */
};

static int
pt_fault_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	struct ps_prochandle *P = t->t_pshandle;

	if (P != NULL && Pstate(P) < PS_LOST) {
		sep->se_data = args; /* data is raw fault number */
		return (Pfault(P, (intptr_t)args, TRUE) < 0 ? -1 : 0);
	}

	return (set_errno(EMDB_NOPROC));
}

static void
pt_fault_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	int fault = (intptr_t)sep->se_data;

	if (fault != FLTBPT && fault != FLTTRACE && fault != FLTWATCH)
		(void) Pfault(t->t_pshandle, fault, FALSE);
}

/*ARGSUSED*/
static char *
pt_fault_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	char name[32];
	int fltnum;

	if (vep != NULL)
		fltnum = (intptr_t)vep->ve_args;
	else
		fltnum = (intptr_t)sep->se_data;

	(void) proc_fltname(fltnum, name, sizeof (name));
	(void) mdb_iob_snprintf(buf, nbytes, "stop on %s", name);

	return (buf);
}

/*ARGSUSED*/
static int
pt_fault_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	int fltnum = (intptr_t)sep->se_data;

	return (psp->pr_why == PR_FAULTED && psp->pr_what == fltnum);
}

static const mdb_se_ops_t proc_fault_ops = {
	pt_fault_ctor,		/* se_ctor */
	pt_fault_dtor,		/* se_dtor */
	pt_fault_info,		/* se_info */
	no_se_secmp,		/* se_secmp */
	no_se_vecmp,		/* se_vecmp */
	no_se_arm,		/* se_arm */
	no_se_disarm,		/* se_disarm */
	no_se_cont,		/* se_cont */
	pt_fault_match		/* se_match */
};

/*
 * Callback for pt_ignore() dcmd above: for each VID, determine if it
 * corresponds to a vespec that traces the specified signal, and delete it.
 */
/*ARGSUSED*/
static int
pt_ignore_sig(mdb_tgt_t *t, void *sig, int vid, void *data)
{
	mdb_vespec_t *vep = mdb_tgt_vespec_lookup(t, vid);

	if (vep->ve_se->se_ops == &proc_signal_ops && vep->ve_args == sig)
		(void) mdb_tgt_vespec_delete(t, vid);

	return (0);
}

static int
pt_brkpt_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	pt_data_t *pt = t->t_data;
	pt_bparg_t *pta = args;
	pt_brkpt_t *ptb;
	GElf_Sym s;

	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) >= PS_LOST)
		return (set_errno(EMDB_NOPROC));

	if (pta->pta_symbol != NULL) {
		if (!pt->p_rtld_finished &&
		    strchr(pta->pta_symbol, '`') == NULL)
			return (set_errno(EMDB_NOSYM));
		if (mdb_tgt_lookup_by_scope(t, pta->pta_symbol, &s,
		    NULL) == -1) {
			if (errno != EMDB_NOOBJ && !(errno == EMDB_NOSYM &&
			    (!(mdb.m_flags & MDB_FL_BPTNOSYMSTOP) ||
			    !pt->p_rtld_finished))) {
				warn("breakpoint %s activation failed",
				    pta->pta_symbol);
			}
			return (-1); /* errno is set for us */
		}

		pta->pta_addr = (uintptr_t)s.st_value;
	}

#ifdef __sparc
	if (pta->pta_addr & 3)
		return (set_errno(EMDB_BPALIGN));
#endif

	if (Paddr_to_map(t->t_pshandle, pta->pta_addr) == NULL)
		return (set_errno(EMDB_NOMAP));

	ptb = mdb_alloc(sizeof (pt_brkpt_t), UM_SLEEP);
	ptb->ptb_addr = pta->pta_addr;
	ptb->ptb_instr = NULL;
	sep->se_data = ptb;

	return (0);
}

/*ARGSUSED*/
static void
pt_brkpt_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	mdb_free(sep->se_data, sizeof (pt_brkpt_t));
}

/*ARGSUSED*/
static char *
pt_brkpt_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	uintptr_t addr = NULL;

	if (vep != NULL) {
		pt_bparg_t *pta = vep->ve_args;

		if (pta->pta_symbol != NULL) {
			(void) mdb_iob_snprintf(buf, nbytes, "stop at %s",
			    pta->pta_symbol);
		} else {
			(void) mdb_iob_snprintf(buf, nbytes, "stop at %a",
			    pta->pta_addr);
			addr = pta->pta_addr;
		}

	} else {
		addr = ((pt_brkpt_t *)sep->se_data)->ptb_addr;
		(void) mdb_iob_snprintf(buf, nbytes, "stop at %a", addr);
	}

	sp->spec_base = addr;
	sp->spec_size = sizeof (instr_t);

	return (buf);
}

static int
pt_brkpt_secmp(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	pt_brkpt_t *ptb = sep->se_data;
	pt_bparg_t *pta = args;
	GElf_Sym sym;

	if (pta->pta_symbol != NULL) {
		return (mdb_tgt_lookup_by_scope(t, pta->pta_symbol,
		    &sym, NULL) == 0 && sym.st_value == ptb->ptb_addr);
	}

	return (pta->pta_addr == ptb->ptb_addr);
}

/*ARGSUSED*/
static int
pt_brkpt_vecmp(mdb_tgt_t *t, mdb_vespec_t *vep, void *args)
{
	pt_bparg_t *pta1 = vep->ve_args;
	pt_bparg_t *pta2 = args;

	if (pta1->pta_symbol != NULL && pta2->pta_symbol != NULL)
		return (strcmp(pta1->pta_symbol, pta2->pta_symbol) == 0);

	if (pta1->pta_symbol == NULL && pta2->pta_symbol == NULL)
		return (pta1->pta_addr == pta2->pta_addr);

	return (0); /* fail if one is symbolic, other is an explicit address */
}

static int
pt_brkpt_arm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	pt_brkpt_t *ptb = sep->se_data;
	return (Psetbkpt(t->t_pshandle, ptb->ptb_addr, &ptb->ptb_instr));
}

/*
 * In order to disarm a breakpoint, we replace the trap instruction at ptb_addr
 * with the saved instruction.  However, if we have stopped after a successful
 * exec(2), we do not want to restore ptb_instr because the address space has
 * now been replaced with the text of a different executable, and so restoring
 * the saved instruction would be incorrect.  The exec itself has effectively
 * removed all breakpoint trap instructions for us, so we can just return.
 */
static int
pt_brkpt_disarm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	pt_brkpt_t *ptb = sep->se_data;

	if (psp->pr_why == PR_SYSEXIT && psp->pr_errno == 0 &&
	    psp->pr_what == SYS_execve)
		return (0); /* do not restore saved instruction */

	return (Pdelbkpt(t->t_pshandle, ptb->ptb_addr, ptb->ptb_instr));
}

/*
 * Determine whether the specified sespec is an armed watchpoint that overlaps
 * with the given breakpoint and has the given flags set.  We use this to find
 * conflicts with breakpoints, below.
 */
static int
pt_wp_overlap(mdb_sespec_t *sep, pt_brkpt_t *ptb, int flags)
{
	const prwatch_t *wp = sep->se_data;

	return (sep->se_state == MDB_TGT_SPEC_ARMED &&
	    sep->se_ops == &proc_wapt_ops && (wp->pr_wflags & flags) &&
	    ptb->ptb_addr - wp->pr_vaddr < wp->pr_size);
}

/*
 * We step over breakpoints using Pxecbkpt() in libproc.  If a conflicting
 * watchpoint is present, we must temporarily remove it before stepping over
 * the breakpoint so we do not immediately re-trigger the watchpoint.  We know
 * the watchpoint has already triggered on our trap instruction as part of
 * fetching it.  Before we return, we must re-install any disabled watchpoints.
 */
static int
pt_brkpt_cont(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	pt_brkpt_t *ptb = sep->se_data;
	int status = -1;
	int error;
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;

	/*
	 * If the PC no longer matches our original address, then the user has
	 * changed it while we have been stopped. In this case, it no longer
	 * makes any sense to continue over this breakpoint.  We return as if we
	 * continued normally.
	 */
	if ((uintptr_t)psp->pr_info.si_addr != psp->pr_reg[R_PC])
		return (pt_status(t, tsp));

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (pt_wp_overlap(sep, ptb, WA_EXEC))
			(void) Pdelwapt(t->t_pshandle, sep->se_data);
	}

	if (Pxecbkpt(t->t_pshandle, ptb->ptb_instr) == 0 &&
	    Pdelbkpt(t->t_pshandle, ptb->ptb_addr, ptb->ptb_instr) == 0)
		status = pt_status(t, tsp);

	error = errno; /* save errno from Pxecbkpt, Pdelbkpt, or pt_status */

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (pt_wp_overlap(sep, ptb, WA_EXEC) &&
		    Psetwapt(t->t_pshandle, sep->se_data) == -1) {
			sep->se_state = MDB_TGT_SPEC_ERROR;
			sep->se_errno = errno;
		}
	}

	(void) set_errno(error);
	return (status);
}

/*ARGSUSED*/
static int
pt_brkpt_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	pt_brkpt_t *ptb = sep->se_data;

	return (psp->pr_why == PR_FAULTED && psp->pr_what == FLTBPT &&
	    psp->pr_reg[R_PC] == ptb->ptb_addr);
}

static const mdb_se_ops_t proc_brkpt_ops = {
	pt_brkpt_ctor,		/* se_ctor */
	pt_brkpt_dtor,		/* se_dtor */
	pt_brkpt_info,		/* se_info */
	pt_brkpt_secmp,		/* se_secmp */
	pt_brkpt_vecmp,		/* se_vecmp */
	pt_brkpt_arm,		/* se_arm */
	pt_brkpt_disarm,	/* se_disarm */
	pt_brkpt_cont,		/* se_cont */
	pt_brkpt_match		/* se_match */
};

static int
pt_wapt_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	if (t->t_pshandle == NULL || Pstate(t->t_pshandle) >= PS_LOST)
		return (set_errno(EMDB_NOPROC));

	sep->se_data = mdb_alloc(sizeof (prwatch_t), UM_SLEEP);
	bcopy(args, sep->se_data, sizeof (prwatch_t));
	return (0);
}

/*ARGSUSED*/
static void
pt_wapt_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	mdb_free(sep->se_data, sizeof (prwatch_t));
}

/*ARGSUSED*/
static char *
pt_wapt_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	prwatch_t *wp = vep != NULL ? vep->ve_args : sep->se_data;
	char desc[24];

	ASSERT(wp->pr_wflags != 0);
	desc[0] = '\0';

	switch (wp->pr_wflags) {
	case WA_READ:
		(void) strcat(desc, "/read");
		break;
	case WA_WRITE:
		(void) strcat(desc, "/write");
		break;
	case WA_EXEC:
		(void) strcat(desc, "/exec");
		break;
	default:
		if (wp->pr_wflags & WA_READ)
			(void) strcat(desc, "/r");
		if (wp->pr_wflags & WA_WRITE)
			(void) strcat(desc, "/w");
		if (wp->pr_wflags & WA_EXEC)
			(void) strcat(desc, "/x");
	}

	(void) mdb_iob_snprintf(buf, nbytes, "stop on %s of [%la, %la)",
	    desc + 1, wp->pr_vaddr, wp->pr_vaddr + wp->pr_size);

	sp->spec_base = wp->pr_vaddr;
	sp->spec_size = wp->pr_size;

	return (buf);
}

/*ARGSUSED*/
static int
pt_wapt_secmp(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	prwatch_t *wp1 = sep->se_data;
	prwatch_t *wp2 = args;

	return (wp1->pr_vaddr == wp2->pr_vaddr &&
	    wp1->pr_size == wp2->pr_size && wp1->pr_wflags == wp2->pr_wflags);
}

/*ARGSUSED*/
static int
pt_wapt_vecmp(mdb_tgt_t *t, mdb_vespec_t *vep, void *args)
{
	prwatch_t *wp1 = vep->ve_args;
	prwatch_t *wp2 = args;

	return (wp1->pr_vaddr == wp2->pr_vaddr &&
	    wp1->pr_size == wp2->pr_size && wp1->pr_wflags == wp2->pr_wflags);
}

static int
pt_wapt_arm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	return (Psetwapt(t->t_pshandle, sep->se_data));
}

static int
pt_wapt_disarm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	return (Pdelwapt(t->t_pshandle, sep->se_data));
}

/*
 * Determine whether the specified sespec is an armed breakpoint at the
 * given %pc.  We use this to find conflicts with watchpoints below.
 */
static int
pt_bp_overlap(mdb_sespec_t *sep, uintptr_t pc)
{
	pt_brkpt_t *ptb = sep->se_data;

	return (sep->se_state == MDB_TGT_SPEC_ARMED &&
	    sep->se_ops == &proc_brkpt_ops && ptb->ptb_addr == pc);
}

/*
 * We step over watchpoints using Pxecwapt() in libproc.  If a conflicting
 * breakpoint is present, we must temporarily disarm it before stepping
 * over the watchpoint so we do not immediately re-trigger the breakpoint.
 * This is similar to the case handled in pt_brkpt_cont(), above.
 */
static int
pt_wapt_cont(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	mdb_sespec_t *bep = NULL;
	int status = -1;
	int error;

	/*
	 * If the PC no longer matches our original address, then the user has
	 * changed it while we have been stopped. In this case, it no longer
	 * makes any sense to continue over this instruction.  We return as if
	 * we continued normally.
	 */
	if ((uintptr_t)psp->pr_info.si_pc != psp->pr_reg[R_PC])
		return (pt_status(t, tsp));

	if (psp->pr_info.si_code != TRAP_XWATCH) {
		for (bep = mdb_list_next(&t->t_active); bep != NULL;
		    bep = mdb_list_next(bep)) {
			if (pt_bp_overlap(bep, psp->pr_reg[R_PC])) {
				(void) bep->se_ops->se_disarm(t, bep);
				bep->se_state = MDB_TGT_SPEC_ACTIVE;
				break;
			}
		}
	}

	if (Pxecwapt(t->t_pshandle, sep->se_data) == 0)
		status = pt_status(t, tsp);

	error = errno; /* save errno from Pxecwapt or pt_status */

	if (bep != NULL)
		mdb_tgt_sespec_arm_one(t, bep);

	(void) set_errno(error);
	return (status);
}

/*ARGSUSED*/
static int
pt_wapt_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	const lwpstatus_t *psp = &Pstatus(t->t_pshandle)->pr_lwp;
	prwatch_t *wp = sep->se_data;

	return (psp->pr_why == PR_FAULTED && psp->pr_what == FLTWATCH &&
	    (uintptr_t)psp->pr_info.si_addr - wp->pr_vaddr < wp->pr_size);
}

static const mdb_se_ops_t proc_wapt_ops = {
	pt_wapt_ctor,		/* se_ctor */
	pt_wapt_dtor,		/* se_dtor */
	pt_wapt_info,		/* se_info */
	pt_wapt_secmp,		/* se_secmp */
	pt_wapt_vecmp,		/* se_vecmp */
	pt_wapt_arm,		/* se_arm */
	pt_wapt_disarm,		/* se_disarm */
	pt_wapt_cont,		/* se_cont */
	pt_wapt_match		/* se_match */
};

static void
pt_bparg_dtor(mdb_vespec_t *vep)
{
	pt_bparg_t *pta = vep->ve_args;

	if (pta->pta_symbol != NULL)
		strfree(pta->pta_symbol);

	mdb_free(pta, sizeof (pt_bparg_t));
}

static int
pt_add_vbrkpt(mdb_tgt_t *t, uintptr_t addr,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	pt_bparg_t *pta = mdb_alloc(sizeof (pt_bparg_t), UM_SLEEP);

	pta->pta_symbol = NULL;
	pta->pta_addr = addr;

	return (mdb_tgt_vespec_insert(t, &proc_brkpt_ops, spec_flags,
	    func, data, pta, pt_bparg_dtor));
}

static int
pt_add_sbrkpt(mdb_tgt_t *t, const char *sym,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	pt_bparg_t *pta;

	if (sym[0] == '`') {
		(void) set_errno(EMDB_NOOBJ);
		return (0);
	}

	if (sym[strlen(sym) - 1] == '`') {
		(void) set_errno(EMDB_NOSYM);
		return (0);
	}

	pta = mdb_alloc(sizeof (pt_bparg_t), UM_SLEEP);
	pta->pta_symbol = strdup(sym);
	pta->pta_addr = NULL;

	return (mdb_tgt_vespec_insert(t, &proc_brkpt_ops, spec_flags,
	    func, data, pta, pt_bparg_dtor));
}

static int
pt_wparg_overlap(const prwatch_t *wp1, const prwatch_t *wp2)
{
	if (wp2->pr_vaddr + wp2->pr_size <= wp1->pr_vaddr)
		return (0); /* no range overlap */

	if (wp1->pr_vaddr + wp1->pr_size <= wp2->pr_vaddr)
		return (0); /* no range overlap */

	return (wp1->pr_vaddr != wp2->pr_vaddr ||
	    wp1->pr_size != wp2->pr_size || wp1->pr_wflags != wp2->pr_wflags);
}

static void
pt_wparg_dtor(mdb_vespec_t *vep)
{
	mdb_free(vep->ve_args, sizeof (prwatch_t));
}

static int
pt_add_vwapt(mdb_tgt_t *t, uintptr_t addr, size_t len, uint_t wflags,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	prwatch_t *wp = mdb_alloc(sizeof (prwatch_t), UM_SLEEP);
	mdb_sespec_t *sep;

	wp->pr_vaddr = addr;
	wp->pr_size = len;
	wp->pr_wflags = 0;

	if (wflags & MDB_TGT_WA_R)
		wp->pr_wflags |= WA_READ;
	if (wflags & MDB_TGT_WA_W)
		wp->pr_wflags |= WA_WRITE;
	if (wflags & MDB_TGT_WA_X)
		wp->pr_wflags |= WA_EXEC;

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (sep->se_ops == &proc_wapt_ops &&
		    mdb_list_next(&sep->se_velist) != NULL &&
		    pt_wparg_overlap(wp, sep->se_data))
			goto dup;
	}

	for (sep = mdb_list_next(&t->t_idle); sep; sep = mdb_list_next(sep)) {
		if (sep->se_ops == &proc_wapt_ops && pt_wparg_overlap(wp,
		    ((mdb_vespec_t *)mdb_list_next(&sep->se_velist))->ve_args))
			goto dup;
	}

	return (mdb_tgt_vespec_insert(t, &proc_wapt_ops, spec_flags,
	    func, data, wp, pt_wparg_dtor));

dup:
	mdb_free(wp, sizeof (prwatch_t));
	(void) set_errno(EMDB_WPDUP);
	return (0);
}

static int
pt_add_sysenter(mdb_tgt_t *t, int sysnum,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	if (sysnum <= 0 || sysnum > PRMAXSYS) {
		(void) set_errno(EMDB_BADSYSNUM);
		return (0);
	}

	return (mdb_tgt_vespec_insert(t, &proc_sysenter_ops, spec_flags,
	    func, data, (void *)(uintptr_t)sysnum, no_ve_dtor));
}

static int
pt_add_sysexit(mdb_tgt_t *t, int sysnum,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	if (sysnum <= 0 || sysnum > PRMAXSYS) {
		(void) set_errno(EMDB_BADSYSNUM);
		return (0);
	}

	return (mdb_tgt_vespec_insert(t, &proc_sysexit_ops, spec_flags,
	    func, data, (void *)(uintptr_t)sysnum, no_ve_dtor));
}

static int
pt_add_signal(mdb_tgt_t *t, int signum,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	pt_data_t *pt = t->t_data;

	if (signum <= 0 || signum > pt->p_maxsig) {
		(void) set_errno(EMDB_BADSIGNUM);
		return (0);
	}

	return (mdb_tgt_vespec_insert(t, &proc_signal_ops, spec_flags,
	    func, data, (void *)(uintptr_t)signum, no_ve_dtor));
}

static int
pt_add_fault(mdb_tgt_t *t, int fltnum,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	if (fltnum <= 0 || fltnum > PRMAXFAULT) {
		(void) set_errno(EMDB_BADFLTNUM);
		return (0);
	}

	return (mdb_tgt_vespec_insert(t, &proc_fault_ops, spec_flags,
	    func, data, (void *)(uintptr_t)fltnum, no_ve_dtor));
}

static int
pt_getareg(mdb_tgt_t *t, mdb_tgt_tid_t tid,
    const char *rname, mdb_tgt_reg_t *rp)
{
	pt_data_t *pt = t->t_data;
	prgregset_t grs;
	mdb_var_t *v;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((v = mdb_nv_lookup(&pt->p_regs, rname)) != NULL) {
		uintmax_t rd_nval = mdb_nv_get_value(v);
		ushort_t rd_num = MDB_TGT_R_NUM(rd_nval);
		ushort_t rd_flags = MDB_TGT_R_FLAGS(rd_nval);

		if (!MDB_TGT_R_IS_FP(rd_flags)) {
			mdb_tgt_reg_t r = 0;

#if defined(__sparc) && defined(_ILP32)
			/*
			 * If we are debugging on 32-bit SPARC, the globals and
			 * outs can have 32 upper bits hiding in the xregs.
			 */
			/* gcc doesn't like >= R_G0 because R_G0 == 0 */
			int is_g = (rd_num == R_G0 ||
			    rd_num >= R_G1 && rd_num <= R_G7);
			int is_o = (rd_num >= R_O0 && rd_num <= R_O7);
			prxregset_t xrs;

			if (is_g && PTL_GETXREGS(t, tid, &xrs) == 0 &&
			    xrs.pr_type == XR_TYPE_V8P) {
				r |= (uint64_t)xrs.pr_un.pr_v8p.pr_xg[
				    rd_num - R_G0 + XR_G0] << 32;
			}

			if (is_o && PTL_GETXREGS(t, tid, &xrs) == 0 &&
			    xrs.pr_type == XR_TYPE_V8P) {
				r |= (uint64_t)xrs.pr_un.pr_v8p.pr_xo[
				    rd_num - R_O0 + XR_O0] << 32;
			}
#endif	/* __sparc && _ILP32 */

			/*
			 * Avoid sign-extension by casting: recall that procfs
			 * defines prgreg_t as a long or int and our native
			 * register handling uses uint64_t's.
			 */
			if (PTL_GETREGS(t, tid, grs) == 0) {
				*rp = r | (ulong_t)grs[rd_num];
				if (rd_flags & MDB_TGT_R_32)
					*rp &= 0xffffffffULL;
				else if (rd_flags & MDB_TGT_R_16)
					*rp &= 0xffffULL;
				else if (rd_flags & MDB_TGT_R_8H)
					*rp = (*rp & 0xff00ULL) >> 8;
				else if (rd_flags & MDB_TGT_R_8L)
					*rp &= 0xffULL;
				return (0);
			}
			return (-1);
		} else
			return (pt_getfpreg(t, tid, rd_num, rd_flags, rp));
	}

	return (set_errno(EMDB_BADREG));
}

static int
pt_putareg(mdb_tgt_t *t, mdb_tgt_tid_t tid, const char *rname, mdb_tgt_reg_t r)
{
	pt_data_t *pt = t->t_data;
	prgregset_t grs;
	mdb_var_t *v;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((v = mdb_nv_lookup(&pt->p_regs, rname)) != NULL) {
		uintmax_t rd_nval = mdb_nv_get_value(v);
		ushort_t rd_num = MDB_TGT_R_NUM(rd_nval);
		ushort_t rd_flags = MDB_TGT_R_FLAGS(rd_nval);

		if (!MDB_TGT_R_IS_FP(rd_flags)) {

			if (rd_flags & MDB_TGT_R_32)
				r &= 0xffffffffULL;
			else if (rd_flags & MDB_TGT_R_16)
				r &= 0xffffULL;
			else if (rd_flags & MDB_TGT_R_8H)
				r = (r & 0xffULL) << 8;
			else if (rd_flags & MDB_TGT_R_8L)
				r &= 0xffULL;

#if defined(__sparc) && defined(_ILP32)
			/*
			 * If we are debugging on 32-bit SPARC, the globals and
			 * outs can have 32 upper bits stored in the xregs.
			 */
			int is_g = (rd_num == R_G0 ||
			    rd_num >= R_G1 && rd_num <= R_G7);
			int is_o = (rd_num >= R_O0 && rd_num <= R_O7);
			prxregset_t xrs;

			if ((is_g || is_o) && PTL_GETXREGS(t, tid, &xrs) == 0 &&
			    xrs.pr_type == XR_TYPE_V8P) {
				if (is_g) {
					xrs.pr_un.pr_v8p.pr_xg[rd_num -
					    R_G0 + XR_G0] = (uint32_t)(r >> 32);
				} else if (is_o) {
					xrs.pr_un.pr_v8p.pr_xo[rd_num -
					    R_O0 + XR_O0] = (uint32_t)(r >> 32);
				}

				if (PTL_SETXREGS(t, tid, &xrs) == -1)
					return (-1);
			}
#endif	/* __sparc && _ILP32 */

			if (PTL_GETREGS(t, tid, grs) == 0) {
				grs[rd_num] = (prgreg_t)r;
				return (PTL_SETREGS(t, tid, grs));
			}
			return (-1);
		} else
			return (pt_putfpreg(t, tid, rd_num, rd_flags, r));
	}

	return (set_errno(EMDB_BADREG));
}

static int
pt_stack_call(pt_stkarg_t *psp, const prgregset_t grs, uint_t argc, long *argv)
{
	psp->pstk_gotpc |= (grs[R_PC] != 0);

	if (!psp->pstk_gotpc)
		return (0); /* skip initial zeroed frames */

	return (psp->pstk_func(psp->pstk_private, grs[R_PC],
	    argc, argv, (const struct mdb_tgt_gregset *)grs));
}

static int
pt_stack_iter(mdb_tgt_t *t, const mdb_tgt_gregset_t *gsp,
    mdb_tgt_stack_f *func, void *arg)
{
	if (t->t_pshandle != NULL) {
		pt_stkarg_t pstk;

		pstk.pstk_func = func;
		pstk.pstk_private = arg;
		pstk.pstk_gotpc = FALSE;

		(void) Pstack_iter(t->t_pshandle, gsp->gregs,
		    (proc_stack_f *)pt_stack_call, &pstk);

		return (0);
	}

	return (set_errno(EMDB_NOPROC));
}

static int
pt_auxv(mdb_tgt_t *t, const auxv_t **auxvp)
{
	if (t->t_pshandle != NULL) {
		*auxvp = Pgetauxvec(t->t_pshandle);
		return (0);
	}

	return (set_errno(EMDB_NOPROC));
}


static const mdb_tgt_ops_t proc_ops = {
	pt_setflags,				/* t_setflags */
	(int (*)()) mdb_tgt_notsup,		/* t_setcontext */
	pt_activate,				/* t_activate */
	pt_deactivate,				/* t_deactivate */
	pt_periodic,				/* t_periodic */
	pt_destroy,				/* t_destroy */
	pt_name,				/* t_name */
	(const char *(*)()) mdb_conf_isa,	/* t_isa */
	pt_platform,				/* t_platform */
	pt_uname,				/* t_uname */
	pt_dmodel,				/* t_dmodel */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_aread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_awrite */
	pt_vread,				/* t_vread */
	pt_vwrite,				/* t_vwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_pread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_pwrite */
	pt_fread,				/* t_fread */
	pt_fwrite,				/* t_fwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_ioread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_iowrite */
	(int (*)()) mdb_tgt_notsup,		/* t_vtop */
	pt_lookup_by_name,			/* t_lookup_by_name */
	pt_lookup_by_addr,			/* t_lookup_by_addr */
	pt_symbol_iter,				/* t_symbol_iter */
	pt_mapping_iter,			/* t_mapping_iter */
	pt_object_iter,				/* t_object_iter */
	pt_addr_to_map,				/* t_addr_to_map */
	pt_name_to_map,				/* t_name_to_map */
	pt_addr_to_ctf,				/* t_addr_to_ctf */
	pt_name_to_ctf,				/* t_name_to_ctf */
	pt_status,				/* t_status */
	pt_run,					/* t_run */
	pt_step,				/* t_step */
	pt_step_out,				/* t_step_out */
	(int (*)()) mdb_tgt_notsup,		/* t_step_branch */
	pt_next,				/* t_next */
	pt_continue,				/* t_cont */
	pt_signal,				/* t_signal */
	pt_add_vbrkpt,				/* t_add_vbrkpt */
	pt_add_sbrkpt,				/* t_add_sbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_pwapt */
	pt_add_vwapt,				/* t_add_vwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_iowapt */
	pt_add_sysenter,			/* t_add_sysenter */
	pt_add_sysexit,				/* t_add_sysexit */
	pt_add_signal,				/* t_add_signal */
	pt_add_fault,				/* t_add_fault */
	pt_getareg,				/* t_getareg */
	pt_putareg,				/* t_putareg */
	pt_stack_iter,				/* t_stack_iter */
	pt_auxv					/* t_auxv */
};

/*
 * Utility function for converting libproc errno values to mdb error values
 * for the ptl calls below.  Currently, we only need to convert ENOENT to
 * EMDB_NOTHREAD to produce a more useful error message for the user.
 */
static int
ptl_err(int error)
{
	if (error != 0 && errno == ENOENT)
		return (set_errno(EMDB_NOTHREAD));

	return (error);
}

/*ARGSUSED*/
static mdb_tgt_tid_t
pt_lwp_tid(mdb_tgt_t *t, void *tap)
{
	if (t->t_pshandle != NULL)
		return (Pstatus(t->t_pshandle)->pr_lwp.pr_lwpid);

	return (set_errno(EMDB_NOPROC));
}

static int
pt_lwp_add(mdb_addrvec_t *ap, const lwpstatus_t *psp)
{
	mdb_addrvec_unshift(ap, psp->pr_lwpid);
	return (0);
}

/*ARGSUSED*/
static int
pt_lwp_iter(mdb_tgt_t *t, void *tap, mdb_addrvec_t *ap)
{
	if (t->t_pshandle != NULL)
		return (Plwp_iter(t->t_pshandle, (proc_lwp_f *)pt_lwp_add, ap));

	return (set_errno(EMDB_NOPROC));
}

/*ARGSUSED*/
static int
pt_lwp_getregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid, prgregset_t gregs)
{
	if (t->t_pshandle != NULL) {
		return (ptl_err(Plwp_getregs(t->t_pshandle,
		    (lwpid_t)tid, gregs)));
	}
	return (set_errno(EMDB_NOPROC));
}

/*ARGSUSED*/
static int
pt_lwp_setregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid, prgregset_t gregs)
{
	if (t->t_pshandle != NULL) {
		return (ptl_err(Plwp_setregs(t->t_pshandle,
		    (lwpid_t)tid, gregs)));
	}
	return (set_errno(EMDB_NOPROC));
}

#ifdef	__sparc

/*ARGSUSED*/
static int
pt_lwp_getxregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid, prxregset_t *xregs)
{
	if (t->t_pshandle != NULL) {
		return (ptl_err(Plwp_getxregs(t->t_pshandle,
		    (lwpid_t)tid, xregs)));
	}
	return (set_errno(EMDB_NOPROC));
}

/*ARGSUSED*/
static int
pt_lwp_setxregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid,
    const prxregset_t *xregs)
{
	if (t->t_pshandle != NULL) {
		return (ptl_err(Plwp_setxregs(t->t_pshandle,
		    (lwpid_t)tid, xregs)));
	}
	return (set_errno(EMDB_NOPROC));
}

#endif	/* __sparc */

/*ARGSUSED*/
static int
pt_lwp_getfpregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid,
    prfpregset_t *fpregs)
{
	if (t->t_pshandle != NULL) {
		return (ptl_err(Plwp_getfpregs(t->t_pshandle,
		    (lwpid_t)tid, fpregs)));
	}
	return (set_errno(EMDB_NOPROC));
}

/*ARGSUSED*/
static int
pt_lwp_setfpregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid,
    const prfpregset_t *fpregs)
{
	if (t->t_pshandle != NULL) {
		return (ptl_err(Plwp_setfpregs(t->t_pshandle,
		    (lwpid_t)tid, fpregs)));
	}
	return (set_errno(EMDB_NOPROC));
}

static const pt_ptl_ops_t proc_lwp_ops = {
	(int (*)()) mdb_tgt_nop,
	(void (*)()) mdb_tgt_nop,
	pt_lwp_tid,
	pt_lwp_iter,
	pt_lwp_getregs,
	pt_lwp_setregs,
#ifdef __sparc
	pt_lwp_getxregs,
	pt_lwp_setxregs,
#endif
	pt_lwp_getfpregs,
	pt_lwp_setfpregs
};

static int
pt_tdb_ctor(mdb_tgt_t *t)
{
	pt_data_t *pt = t->t_data;
	td_thragent_t *tap;
	td_err_e err;

	if ((err = pt->p_tdb_ops->td_ta_new(t->t_pshandle, &tap)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	pt->p_ptl_hdl = tap;
	return (0);
}

static void
pt_tdb_dtor(mdb_tgt_t *t, void *tap)
{
	pt_data_t *pt = t->t_data;

	ASSERT(tap == pt->p_ptl_hdl);
	(void) pt->p_tdb_ops->td_ta_delete(tap);
	pt->p_ptl_hdl = NULL;
}

static mdb_tgt_tid_t
pt_tdb_tid(mdb_tgt_t *t, void *tap)
{
	pt_data_t *pt = t->t_data;

	td_thrhandle_t th;
	td_thrinfo_t ti;
	td_err_e err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((err = pt->p_tdb_ops->td_ta_map_lwp2thr(tap,
	    Pstatus(t->t_pshandle)->pr_lwp.pr_lwpid, &th)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	if ((err = pt->p_tdb_ops->td_thr_get_info(&th, &ti)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	return (ti.ti_tid);
}

static int
pt_tdb_add(const td_thrhandle_t *thp, pt_addarg_t *pap)
{
	td_thrinfo_t ti;

	if (pap->pa_pt->p_tdb_ops->td_thr_get_info(thp, &ti) == TD_OK &&
	    ti.ti_state != TD_THR_ZOMBIE)
		mdb_addrvec_unshift(pap->pa_ap, ti.ti_tid);

	return (0);
}

static int
pt_tdb_iter(mdb_tgt_t *t, void *tap, mdb_addrvec_t *ap)
{
	pt_data_t *pt = t->t_data;
	pt_addarg_t arg;
	int err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	arg.pa_pt = pt;
	arg.pa_ap = ap;

	if ((err = pt->p_tdb_ops->td_ta_thr_iter(tap, (td_thr_iter_f *)
	    pt_tdb_add, &arg, TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
	    TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

static int
pt_tdb_getregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid, prgregset_t gregs)
{
	pt_data_t *pt = t->t_data;

	td_thrhandle_t th;
	td_err_e err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((err = pt->p_tdb_ops->td_ta_map_id2thr(tap, tid, &th)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	err = pt->p_tdb_ops->td_thr_getgregs(&th, gregs);
	if (err != TD_OK && err != TD_PARTIALREG)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

static int
pt_tdb_setregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid, prgregset_t gregs)
{
	pt_data_t *pt = t->t_data;

	td_thrhandle_t th;
	td_err_e err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((err = pt->p_tdb_ops->td_ta_map_id2thr(tap, tid, &th)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	err = pt->p_tdb_ops->td_thr_setgregs(&th, gregs);
	if (err != TD_OK && err != TD_PARTIALREG)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

#ifdef __sparc

static int
pt_tdb_getxregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid, prxregset_t *xregs)
{
	pt_data_t *pt = t->t_data;

	td_thrhandle_t th;
	td_err_e err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((err = pt->p_tdb_ops->td_ta_map_id2thr(tap, tid, &th)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	err = pt->p_tdb_ops->td_thr_getxregs(&th, xregs);
	if (err != TD_OK && err != TD_PARTIALREG)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

static int
pt_tdb_setxregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid,
    const prxregset_t *xregs)
{
	pt_data_t *pt = t->t_data;

	td_thrhandle_t th;
	td_err_e err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((err = pt->p_tdb_ops->td_ta_map_id2thr(tap, tid, &th)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	err = pt->p_tdb_ops->td_thr_setxregs(&th, xregs);
	if (err != TD_OK && err != TD_PARTIALREG)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

#endif	/* __sparc */

static int
pt_tdb_getfpregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid,
    prfpregset_t *fpregs)
{
	pt_data_t *pt = t->t_data;

	td_thrhandle_t th;
	td_err_e err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((err = pt->p_tdb_ops->td_ta_map_id2thr(tap, tid, &th)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	err = pt->p_tdb_ops->td_thr_getfpregs(&th, fpregs);
	if (err != TD_OK && err != TD_PARTIALREG)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

static int
pt_tdb_setfpregs(mdb_tgt_t *t, void *tap, mdb_tgt_tid_t tid,
    const prfpregset_t *fpregs)
{
	pt_data_t *pt = t->t_data;

	td_thrhandle_t th;
	td_err_e err;

	if (t->t_pshandle == NULL)
		return (set_errno(EMDB_NOPROC));

	if ((err = pt->p_tdb_ops->td_ta_map_id2thr(tap, tid, &th)) != TD_OK)
		return (set_errno(tdb_to_errno(err)));

	err = pt->p_tdb_ops->td_thr_setfpregs(&th, fpregs);
	if (err != TD_OK && err != TD_PARTIALREG)
		return (set_errno(tdb_to_errno(err)));

	return (0);
}

static const pt_ptl_ops_t proc_tdb_ops = {
	pt_tdb_ctor,
	pt_tdb_dtor,
	pt_tdb_tid,
	pt_tdb_iter,
	pt_tdb_getregs,
	pt_tdb_setregs,
#ifdef __sparc
	pt_tdb_getxregs,
	pt_tdb_setxregs,
#endif
	pt_tdb_getfpregs,
	pt_tdb_setfpregs
};

static ssize_t
pt_xd_auxv(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	struct ps_prochandle *P = t->t_pshandle;
	const auxv_t *auxp, *auxv = NULL;
	int auxn = 0;

	if (P != NULL && (auxv = Pgetauxvec(P)) != NULL &&
	    auxv->a_type != AT_NULL) {
		for (auxp = auxv, auxn = 1; auxp->a_type != NULL; auxp++)
			auxn++;
	}

	if (buf == NULL && nbytes == 0)
		return (sizeof (auxv_t) * auxn);

	if (auxn == 0)
		return (set_errno(ENODATA));

	nbytes = MIN(nbytes, sizeof (auxv_t) * auxn);
	bcopy(auxv, buf, nbytes);
	return (nbytes);
}

static ssize_t
pt_xd_cred(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	prcred_t cr, *crp;
	size_t cbytes = 0;

	if (t->t_pshandle != NULL && Pcred(t->t_pshandle, &cr, 1) == 0) {
		cbytes = (cr.pr_ngroups <= 1) ? sizeof (prcred_t) :
		    (sizeof (prcred_t) + (cr.pr_ngroups - 1) * sizeof (gid_t));
	}

	if (buf == NULL && nbytes == 0)
		return (cbytes);

	if (cbytes == 0)
		return (set_errno(ENODATA));

	crp = mdb_alloc(cbytes, UM_SLEEP);

	if (Pcred(t->t_pshandle, crp, cr.pr_ngroups) == -1)
		return (set_errno(ENODATA));

	nbytes = MIN(nbytes, cbytes);
	bcopy(crp, buf, nbytes);
	mdb_free(crp, cbytes);
	return (nbytes);
}

static ssize_t
pt_xd_ehdr(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	pt_data_t *pt = t->t_data;

	if (buf == NULL && nbytes == 0)
		return (sizeof (GElf_Ehdr));

	if (pt->p_file == NULL)
		return (set_errno(ENODATA));

	nbytes = MIN(nbytes, sizeof (GElf_Ehdr));
	bcopy(&pt->p_file->gf_ehdr, buf, nbytes);
	return (nbytes);
}

static int
pt_copy_lwp(lwpstatus_t **lspp, const lwpstatus_t *lsp)
{
	bcopy(lsp, *lspp, sizeof (lwpstatus_t));
	(*lspp)++;
	return (0);
}

static ssize_t
pt_xd_lwpstatus(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	lwpstatus_t *lsp, *lbuf;
	const pstatus_t *psp;
	int nlwp = 0;

	if (t->t_pshandle != NULL && (psp = Pstatus(t->t_pshandle)) != NULL)
		nlwp = psp->pr_nlwp;

	if (buf == NULL && nbytes == 0)
		return (sizeof (lwpstatus_t) * nlwp);

	if (nlwp == 0)
		return (set_errno(ENODATA));

	lsp = lbuf = mdb_alloc(sizeof (lwpstatus_t) * nlwp, UM_SLEEP);
	nbytes = MIN(nbytes, sizeof (lwpstatus_t) * nlwp);

	(void) Plwp_iter(t->t_pshandle, (proc_lwp_f *)pt_copy_lwp, &lsp);
	bcopy(lbuf, buf, nbytes);

	mdb_free(lbuf, sizeof (lwpstatus_t) * nlwp);
	return (nbytes);
}

static ssize_t
pt_xd_pshandle(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	if (buf == NULL && nbytes == 0)
		return (sizeof (struct ps_prochandle *));

	if (t->t_pshandle == NULL || nbytes != sizeof (struct ps_prochandle *))
		return (set_errno(ENODATA));

	bcopy(&t->t_pshandle, buf, nbytes);
	return (nbytes);
}

static ssize_t
pt_xd_psinfo(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	const psinfo_t *psp;

	if (buf == NULL && nbytes == 0)
		return (sizeof (psinfo_t));

	if (t->t_pshandle == NULL || (psp = Ppsinfo(t->t_pshandle)) == NULL)
		return (set_errno(ENODATA));

	nbytes = MIN(nbytes, sizeof (psinfo_t));
	bcopy(psp, buf, nbytes);
	return (nbytes);
}

static ssize_t
pt_xd_pstatus(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	const pstatus_t *psp;

	if (buf == NULL && nbytes == 0)
		return (sizeof (pstatus_t));

	if (t->t_pshandle == NULL || (psp = Pstatus(t->t_pshandle)) == NULL)
		return (set_errno(ENODATA));

	nbytes = MIN(nbytes, sizeof (pstatus_t));
	bcopy(psp, buf, nbytes);
	return (nbytes);
}

static ssize_t
pt_xd_utsname(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	struct utsname uts;

	if (buf == NULL && nbytes == 0)
		return (sizeof (struct utsname));

	if (t->t_pshandle == NULL || Puname(t->t_pshandle, &uts) != 0)
		return (set_errno(ENODATA));

	nbytes = MIN(nbytes, sizeof (struct utsname));
	bcopy(&uts, buf, nbytes);
	return (nbytes);
}

int
mdb_proc_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	pt_data_t *pt = mdb_zalloc(sizeof (pt_data_t), UM_SLEEP);

	const char *aout_path = argc > 0 ? argv[0] : PT_EXEC_PATH;
	const char *core_path = argc > 1 ? argv[1] : NULL;

	const mdb_tgt_regdesc_t *rdp;
	char execname[MAXPATHLEN];
	struct stat64 st;
	int perr;
	int state;
	struct rlimit rlim;
	int i;

	if (argc > 2) {
		mdb_free(pt, sizeof (pt_data_t));
		return (set_errno(EINVAL));
	}

	if (t->t_flags & MDB_TGT_F_RDWR)
		pt->p_oflags = O_RDWR;
	else
		pt->p_oflags = O_RDONLY;

	if (t->t_flags & MDB_TGT_F_FORCE)
		pt->p_gflags |= PGRAB_FORCE;
	if (t->t_flags & MDB_TGT_F_NOSTOP)
		pt->p_gflags |= PGRAB_NOSTOP;

	pt->p_ptl_ops = &proc_lwp_ops;
	pt->p_maxsig = sysconf(_SC_SIGRT_MAX);

	(void) mdb_nv_create(&pt->p_regs, UM_SLEEP);
	(void) mdb_nv_create(&pt->p_env, UM_SLEEP);

	t->t_ops = &proc_ops;
	t->t_data = pt;

	/*
	 * If no core file name was specified, but the file ./core is present,
	 * infer that we want to debug it.  I find this behavior confusing,
	 * so we only do this when precise adb(1) compatibility is required.
	 */
	if (core_path == NULL && (mdb.m_flags & MDB_FL_ADB) &&
	    access(PT_CORE_PATH, F_OK) == 0)
		core_path = PT_CORE_PATH;

	/*
	 * For compatibility with adb(1), the special name "-" may be used
	 * to suppress the loading of the executable or core file.
	 */
	if (aout_path != NULL && strcmp(aout_path, "-") == 0)
		aout_path = NULL;
	if (core_path != NULL && strcmp(core_path, "-") == 0)
		core_path = NULL;

	/*
	 * If a core file or pid was specified, attempt to grab it now using
	 * proc_arg_grab(); otherwise we'll create a fresh process later.
	 */
	if (core_path != NULL && (t->t_pshandle = proc_arg_xgrab(core_path,
	    aout_path == PT_EXEC_PATH ? NULL : aout_path, PR_ARG_ANY,
	    pt->p_gflags, &perr, NULL)) == NULL) {
		mdb_warn("cannot debug %s: %s\n", core_path, Pgrab_error(perr));
		goto err;
	}

	if (aout_path != NULL &&
	    (pt->p_idlehandle = Pgrab_file(aout_path, &perr)) != NULL &&
	    t->t_pshandle == NULL)
		t->t_pshandle = pt->p_idlehandle;

	if (t->t_pshandle != NULL)
		state = Pstate(t->t_pshandle);

	/*
	 * Make sure we'll have enough file descriptors to handle a target
	 * has many many mappings.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	/*
	 * If we don't have an executable path or the executable path is the
	 * /proc/<pid>/object/a.out path, but we now have a libproc handle,
	 * attempt to derive the executable path using Pexecname().  We need
	 * to do this in the /proc case in order to open the executable for
	 * writing because /proc/object/<file> permission are masked with 0555.
	 * If Pexecname() fails us, fall back to /proc/<pid>/object/a.out.
	 */
	if (t->t_pshandle != NULL && (aout_path == NULL || (stat64(aout_path,
	    &st) == 0 && strcmp(st.st_fstype, "proc") == 0))) {
		GElf_Sym s;
		aout_path = Pexecname(t->t_pshandle, execname, MAXPATHLEN);
		if (aout_path == NULL && state != PS_DEAD && state != PS_IDLE) {
			(void) mdb_iob_snprintf(execname, sizeof (execname),
			    "/proc/%d/object/a.out",
			    (int)Pstatus(t->t_pshandle)->pr_pid);
			aout_path = execname;
		}
		if (aout_path == NULL &&
		    Plookup_by_name(t->t_pshandle, "a.out", "_start", &s) != 0)
			mdb_warn("warning: failed to infer pathname to "
			    "executable; symbol table will not be available\n");

		mdb_dprintf(MDB_DBG_TGT, "a.out is %s\n", aout_path);
	}

	/*
	 * Attempt to open the executable file.  We only want this operation
	 * to actually cause the constructor to abort if the executable file
	 * name was given explicitly.  If we defaulted to PT_EXEC_PATH or
	 * derived the executable using Pexecname, then we want to continue
	 * along with p_fio and p_file set to NULL.
	 */
	if (aout_path != NULL && (pt->p_aout_fio = mdb_fdio_create_path(NULL,
	    aout_path, pt->p_oflags, 0)) == NULL && argc > 0) {
		mdb_warn("failed to open %s", aout_path);
		goto err;
	}

	/*
	 * Now create an ELF file from the input file, if we have one.  Again,
	 * only abort the constructor if the name was given explicitly.
	 */
	if (pt->p_aout_fio != NULL && pt_open_aout(t,
	    mdb_io_hold(pt->p_aout_fio)) == NULL && argc > 0)
		goto err;

	/*
	 * If we've successfully opened an ELF file, select the appropriate
	 * disassembler based on the ELF header.
	 */
	if (pt->p_file != NULL)
		(void) mdb_dis_select(pt_disasm(&pt->p_file->gf_ehdr));
	else
		(void) mdb_dis_select(pt_disasm(NULL));

	/*
	 * Add each register described in the target ISA register description
	 * list to our hash table of register descriptions and then add any
	 * appropriate ISA-specific floating-point register descriptions.
	 */
	for (rdp = pt_regdesc; rdp->rd_name != NULL; rdp++) {
		(void) mdb_nv_insert(&pt->p_regs, rdp->rd_name, NULL,
		    MDB_TGT_R_NVAL(rdp->rd_num, rdp->rd_flags), MDB_NV_RDONLY);
	}
	pt_addfpregs(t);

	/*
	 * Certain important /proc structures may be of interest to mdb
	 * modules and their dcmds.  Export these using the xdata interface:
	 */
	(void) mdb_tgt_xdata_insert(t, "auxv",
	    "procfs auxv_t array", pt_xd_auxv);
	(void) mdb_tgt_xdata_insert(t, "cred",
	    "procfs prcred_t structure", pt_xd_cred);
	(void) mdb_tgt_xdata_insert(t, "ehdr",
	    "executable file GElf_Ehdr structure", pt_xd_ehdr);
	(void) mdb_tgt_xdata_insert(t, "lwpstatus",
	    "procfs lwpstatus_t array", pt_xd_lwpstatus);
	(void) mdb_tgt_xdata_insert(t, "pshandle",
	    "libproc proc service API handle", pt_xd_pshandle);
	(void) mdb_tgt_xdata_insert(t, "psinfo",
	    "procfs psinfo_t structure", pt_xd_psinfo);
	(void) mdb_tgt_xdata_insert(t, "pstatus",
	    "procfs pstatus_t structure", pt_xd_pstatus);
	(void) mdb_tgt_xdata_insert(t, "utsname",
	    "utsname structure", pt_xd_utsname);

	/*
	 * Force a status update now so that we fill in t_status with the
	 * latest information based on any successful grab.
	 */
	(void) mdb_tgt_status(t, &t->t_status);

	/*
	 * If we're not examining a core file, trace SIGINT and all signals
	 * that cause the process to dump core as part of our initialization.
	 */
	if ((t->t_pshandle != NULL && state != PS_DEAD && state != PS_IDLE) ||
	    (pt->p_file != NULL && pt->p_file->gf_ehdr.e_type == ET_EXEC)) {

		int tflag = MDB_TGT_SPEC_STICKY; /* default sigs are sticky */

		(void) mdb_tgt_add_signal(t, SIGINT, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGQUIT, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGILL, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGTRAP, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGABRT, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGEMT, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGFPE, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGBUS, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGSEGV, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGSYS, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGXCPU, tflag, no_se_f, NULL);
		(void) mdb_tgt_add_signal(t, SIGXFSZ, tflag, no_se_f, NULL);
	}

	/*
	 * If we've grabbed a live process, establish our initial breakpoints
	 * and librtld_db agent so we can track rtld activity.  If FL_VCREATE
	 * is set, this process was created by a previous instantiation of
	 * the debugger, so reset pr_flags to kill it; otherwise we attached
	 * to an already running process.  Pgrab() has already set the PR_RLC
	 * flag appropriately based on whether the process was stopped when we
	 * attached.
	 */
	if (t->t_pshandle != NULL && state != PS_DEAD && state != PS_IDLE) {
		if (mdb.m_flags & MDB_FL_VCREATE) {
			(void) Punsetflags(t->t_pshandle, PR_RLC);
			(void) Psetflags(t->t_pshandle, PR_KLC);
			pt->p_rflags = PRELEASE_KILL;
		} else {
			(void) Punsetflags(t->t_pshandle, PR_KLC);
		}
		pt_post_attach(t);
	}

	/*
	 * Initialize a local copy of the environment, which can be modified
	 * before running the program.
	 */
	for (i = 0; mdb.m_env[i] != NULL; i++)
		pt_env_set(pt, mdb.m_env[i]);

	/*
	 * If adb(1) compatibility mode is on, then print the appropriate
	 * greeting message if we have grabbed a core file.
	 */
	if ((mdb.m_flags & MDB_FL_ADB) && t->t_pshandle != NULL &&
	    state == PS_DEAD) {
		const pstatus_t *psp = Pstatus(t->t_pshandle);
		int cursig = psp->pr_lwp.pr_cursig;
		char signame[SIG2STR_MAX];

		mdb_printf("core file = %s -- program ``%s'' on platform %s\n",
		    core_path, aout_path ? aout_path : "?", pt_platform(t));

		if (cursig != 0 && sig2str(cursig, signame) == 0)
			mdb_printf("SIG%s: %s\n", signame, strsignal(cursig));
	}

	return (0);

err:
	pt_destroy(t);
	return (-1);
}
