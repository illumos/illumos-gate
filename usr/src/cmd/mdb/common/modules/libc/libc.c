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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */
/*
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_whatis.h>
#include <mdb/mdb_ctf.h>
#include <procfs.h>
#include <ucontext.h>
#include <siginfo.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <thr_uberdata.h>
#include "findstack.h"

static const char *
stack_flags(const stack_t *sp)
{
	static char buf[32];

	if (sp->ss_flags == 0)
		(void) strcpy(buf, " 0");
	else if (sp->ss_flags & ~(SS_ONSTACK | SS_DISABLE))
		(void) mdb_snprintf(buf, sizeof (buf), " 0x%x", sp->ss_flags);
	else {
		buf[0] = '\0';
		if (sp->ss_flags & SS_ONSTACK)
			(void) strcat(buf, "|ONSTACK");
		if (sp->ss_flags & SS_DISABLE)
			(void) strcat(buf, "|DISABLE");
	}

	return (buf + 1);
}

/*ARGSUSED*/
static int
d_jmp_buf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	jmp_buf jb;
	const ulong_t *b = (const ulong_t *)jb;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&jb, sizeof (jb), addr) != sizeof (jb)) {
		mdb_warn("failed to read jmp_buf at %p", addr);
		return (DCMD_ERR);
	}

#if defined(__sparc)
	mdb_printf("  %%sp = 0x%lx\n", b[1]);
	mdb_printf("  %%pc = 0x%lx %lA\n", b[2], b[2]);
	mdb_printf("  %%fp = 0x%lx\n", b[3]);
	mdb_printf("  %%i7 = 0x%lx %lA\n", b[4], b[4]);
#elif defined(__amd64)
	mdb_printf("  %%rbx = 0x%lx\n", b[0]);
	mdb_printf("  %%r12 = 0x%lx\n", b[1]);
	mdb_printf("  %%r13 = 0x%lx\n", b[2]);
	mdb_printf("  %%r14 = 0x%lx\n", b[3]);
	mdb_printf("  %%r15 = 0x%lx\n", b[4]);
	mdb_printf("  %%rbp = 0x%lx\n", b[5]);
	mdb_printf("  %%rsp = 0x%lx\n", b[6]);
	mdb_printf("  %%rip = 0x%lx %lA\n", b[7], b[7]);
#elif defined(__i386)
	mdb_printf("  %%ebx = 0x%lx\n", b[0]);
	mdb_printf("  %%esi = 0x%lx\n", b[1]);
	mdb_printf("  %%edi = 0x%lx\n", b[2]);
	mdb_printf("  %%ebp = 0x%lx\n", b[3]);
	mdb_printf("  %%esp = 0x%lx\n", b[4]);
	mdb_printf("  %%eip = 0x%lx %lA\n", b[5], b[5]);
#endif
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
d_ucontext(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ucontext_t uc;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&uc, sizeof (uc), addr) != sizeof (uc)) {
		mdb_warn("failed to read ucontext at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("  flags    = 0x%lx\n", uc.uc_flags);
	mdb_printf("  link     = 0x%p\n", uc.uc_link);
	mdb_printf("  sigmask  = 0x%08x 0x%08x 0x%08x 0x%08x\n",
	    uc.uc_sigmask.__sigbits[0], uc.uc_sigmask.__sigbits[1],
	    uc.uc_sigmask.__sigbits[2], uc.uc_sigmask.__sigbits[3]);
	mdb_printf("  stack    = sp 0x%p size 0x%lx flags %s\n",
	    uc.uc_stack.ss_sp, uc.uc_stack.ss_size, stack_flags(&uc.uc_stack));
	mdb_printf("  mcontext = 0x%p\n",
	    addr + OFFSETOF(ucontext_t, uc_mcontext));

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
d_sigjmp_buf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
#if defined(__sparc)
	struct {
		int sjs_flags;
		greg_t sjs_sp;
		greg_t sjs_pc;
		greg_t sjs_fp;
		greg_t sjs_i7;
		ucontext_t *sjs_uclink;
		ulong_t sjs_pad[_JBLEN - 6];
		sigset_t sjs_sigmask;
#if defined(_LP64)
		greg_t sjs_asi;
		greg_t sjs_fprs;
#endif
		stack_t sjs_stack;
	} s;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&s, sizeof (s), addr) != sizeof (s)) {
		mdb_warn("failed to read sigjmp_buf at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("  flags  = 0x%x\n", s.sjs_flags);
	mdb_printf("  %%sp    = 0x%lx %lA\n", s.sjs_sp, s.sjs_sp);
	mdb_printf("  %%pc    = 0x%lx %lA\n", s.sjs_pc, s.sjs_pc);
	mdb_printf("  %%fp    = 0x%lx %lA\n", s.sjs_fp, s.sjs_fp);
	mdb_printf("  %%i7    = 0x%lx %lA\n", s.sjs_i7, s.sjs_i7);
	mdb_printf("  uclink = %p\n", s.sjs_uclink);
	mdb_printf("  sigset = 0x%08x 0x%08x 0x%08x 0x%08x\n",
	    s.sjs_sigmask.__sigbits[0], s.sjs_sigmask.__sigbits[1],
	    s.sjs_sigmask.__sigbits[2], s.sjs_sigmask.__sigbits[3]);
#if defined(_LP64)
	mdb_printf("  %%asi   = 0x%lx\n", s.sjs_asi);
	mdb_printf("  %%fprs  = 0x%lx\n", s.sjs_fprs);
#endif
	mdb_printf("  stack  = sp 0x%p size 0x%lx flags %s\n",
	    s.sjs_stack.ss_sp, s.sjs_stack.ss_size, stack_flags(&s.sjs_stack));

	return (DCMD_OK);

#elif defined(__i386) || defined(__amd64)
	return (d_ucontext(addr, flags, argc, argv));
#endif
}

/*ARGSUSED*/
static int
d_siginfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	static const char *const msname[] = {
		"USER", "SYSTEM", "TRAP", "TFAULT", "DFAULT", "KFAULT",
		"USER_LOCK", "SLEEP", "WAIT_CPU", "STOPPED"
	};

	char signame[SIG2STR_MAX];
	siginfo_t si;
	int i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&si, sizeof (si), addr) != sizeof (si)) {
		mdb_warn("failed to read siginfo at %p", addr);
		return (DCMD_ERR);
	}

	if (sig2str(si.si_signo, signame) == -1)
		(void) strcpy(signame, "unknown");

	mdb_printf("  signal %5d (%s)\n", si.si_signo, signame);
	mdb_printf("  code   %5d (", si.si_code);

	switch (si.si_code) {
	case SI_NOINFO:
		mdb_printf("no info");
		break;
	case SI_DTRACE:
		mdb_printf("from DTrace raise() action");
		break;
	case SI_RCTL:
		mdb_printf("from rctl action");
		break;
	case SI_USER:
		mdb_printf("user generated via kill");
		break;
	case SI_LWP:
		mdb_printf("user generated via lwp_kill");
		break;
	case SI_QUEUE:
		mdb_printf("user generated via sigqueue");
		break;
	case SI_TIMER:
		mdb_printf("from timer expiration");
		break;
	case SI_ASYNCIO:
		mdb_printf("from async i/o completion");
		break;
	case SI_MESGQ:
		mdb_printf("from message arrival");
		break;
	default:
		if (SI_FROMUSER(&si))
			mdb_printf("from user process");
		else
			mdb_printf("from kernel");
	}

	mdb_printf(")\n  errno  %5d (%s)\n",
	    si.si_errno, strerror(si.si_errno));

	if (si.si_code == SI_USER || si.si_code == SI_QUEUE) {
		mdb_printf("  signal sent from PID %d (uid %d)\n",
		    si.si_pid, si.si_uid);
	}

	if (si.si_code == SI_QUEUE) {
		mdb_printf("  signal value = 0t%d / %p\n",
		    si.si_value.sival_int, si.si_value.sival_ptr);
	}

	switch (si.si_signo) {
	case SIGCLD:
		mdb_printf("  signal sent from child PID %d (uid %d)\n",
		    si.si_pid, si.si_uid);
		mdb_printf("  usr time = 0t%ld ticks, sys time = 0t%ld ticks\n",
		    si.si_utime, si.si_stime);
		mdb_printf("  wait status = 0x%x\n", si.si_status);
		break;

	case SIGSEGV:
	case SIGBUS:
	case SIGILL:
	case SIGTRAP:
	case SIGFPE:
		mdb_printf("  fault address = 0x%p\n  trapno = %d\n",
		    si.si_addr, si.si_trapno);
		mdb_printf("  instruction address = 0x%p %lA\n",
		    si.si_pc, si.si_pc);
		break;

	case SIGPOLL:
	case SIGXFSZ:
		mdb_printf("  fd = %d  band = 0x%lx\n",
		    si.si_fd, si.si_band);
		break;

	case SIGPROF:
		mdb_printf("  last fault address = 0x%p fault type = %d\n",
		    si.si_faddr, si.si_fault);
		mdb_printf("  timestamp = 0t%ld sec 0t%ld nsec\n",
		    si.si_tstamp.tv_sec, si.si_tstamp.tv_nsec);

		if (si.__data.__prof.__syscall != 0) {
			mdb_printf("  system call %d (", si.si_syscall);
			if (si.si_nsysarg > 0) {
				mdb_printf("%lx", si.si_sysarg[0]);
				for (i = 1; i < si.si_nsysarg; i++)
					mdb_printf(", %lx", si.si_sysarg[i]);
			}
			mdb_printf("  )\n");
		}

		for (i = 0; i < sizeof (msname) / sizeof (msname[0]); i++) {
			mdb_printf("  mstate[\"%s\"] = %d\n",
			    msname[i], si.si_mstate[i]);
		}
		break;
	}

	return (DCMD_OK);
}

static int
uc_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	ucontext_t uc;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&uc, sizeof (uc), addr) != sizeof (uc)) {
		mdb_warn("failed to read ucontext at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)uc.uc_link;
	return (wsp->walk_callback(addr, &uc, wsp->walk_cbdata));
}

static int
oldc_walk_init(mdb_walk_state_t *wsp)
{
	ssize_t nbytes = mdb_get_xdata("lwpstatus", NULL, 0);

	if (nbytes <= 0) {
		mdb_warn("lwpstatus information not available");
		return (WALK_ERR);
	}

	if (wsp->walk_addr != NULL) {
		mdb_warn("walker only supports global walk\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = nbytes; /* Use walk_addr to track size */
	wsp->walk_data = mdb_alloc(nbytes, UM_SLEEP);

	if (mdb_get_xdata("lwpstatus", wsp->walk_data, nbytes) != nbytes) {
		mdb_warn("failed to read lwpstatus information");
		mdb_free(wsp->walk_data, nbytes);
		return (WALK_ERR);
	}

	wsp->walk_arg = wsp->walk_data; /* Use walk_arg to track pointer */
	return (WALK_NEXT);
}

static int
oldc_walk_step(mdb_walk_state_t *wsp)
{
	const lwpstatus_t *lsp, *end;

	end = (const lwpstatus_t *)((uintptr_t)wsp->walk_data + wsp->walk_addr);
	lsp = wsp->walk_arg;

	wsp->walk_arg = (void *)(lsp + 1);

	if (lsp < end) {
		uintptr_t addr = lsp->pr_oldcontext;
		ucontext_t uc;

		if (addr == NULL)
			return (WALK_NEXT);

		if (mdb_vread(&uc, sizeof (uc), addr) != sizeof (uc)) {
			mdb_warn("failed to read ucontext at %p", addr);
			return (WALK_NEXT);
		}

		return (wsp->walk_callback(addr, &uc, wsp->walk_cbdata));
	}

	return (WALK_DONE);
}

static void
oldc_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, wsp->walk_addr); /* walk_addr has size */
}

/*
 * ==================== threads ==========================
 * These are the interfaces that used to require libthread.
 * Now, libthread has been folded into libc.
 * =======================================================
 */

/*
 * prt_addr() is called up to three times to generate arguments for
 * one call to mdb_printf().  We must return at least three different
 * pointers to static storage for consecutive calls to prt_addr().
 */
static const char *
prt_addr(void *addr, int pad)
{
	static char buffer[4][24];
	static int ix = 0;
	char *buf;

	if (ix == 4)	/* use buffers in sequence: 0, 1, 2, 3 */
		ix = 0;
	buf = buffer[ix++];
	if (addr == NULL)
		return (pad? "<NULL>               " : "<NULL>");
	else {
#ifdef _LP64
		(void) mdb_snprintf(buf, sizeof (buffer[0]), "0x%016lx", addr);
		if (pad)
			(void) strcpy(buf + 18, "   ");
#else
		(void) mdb_snprintf(buf, sizeof (buffer[0]), "0x%08lx", addr);
		if (pad)
			(void) strcpy(buf + 10, "           ");
#endif	/* _LP64 */
		return (buf);
	}
}

#define	HD(str)		mdb_printf("           " str "\n")
#define	OFFSTR		"+0x%-7lx "
#define	OFFSET(member)	((size_t)OFFSETOF(ulwp_t, member))

/*ARGSUSED*/
static int
d_ulwp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ulwp_t ulwp;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ulwp, sizeof (ulwp), addr) != sizeof (ulwp) &&
	    (bzero(&ulwp, sizeof (ulwp)),
	    mdb_vread(&ulwp, REPLACEMENT_SIZE, addr)) != REPLACEMENT_SIZE) {
		mdb_warn("failed to read ulwp at 0x%p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%#a\n", addr);

	HD("self                  uberdata");
	mdb_printf(OFFSTR "%s %s\n",
	    OFFSET(ul_self),
	    prt_addr(ulwp.ul_self, 1),
	    prt_addr(ulwp.ul_uberdata, 0));

	HD("tlsent                ntlsent");
	mdb_printf(OFFSTR "%s %ld\n",
	    OFFSET(ul_tlsent),
	    prt_addr(ulwp.ul_tlsent, 1),
	    ulwp.ul_ntlsent);

	HD("forw                  back                  next");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ul_forw),
	    prt_addr(ulwp.ul_forw, 1),
	    prt_addr(ulwp.ul_back, 1),
	    prt_addr(ulwp.ul_next, 0));

	HD("hash                  rval                  stk");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ul_hash),
	    prt_addr(ulwp.ul_hash, 1),
	    prt_addr(ulwp.ul_rval, 1),
	    prt_addr(ulwp.ul_stk, 0));

	HD("mapsiz     guardsize  stktop                stksiz");
	mdb_printf(OFFSTR "%-10ld %-10ld %s %ld\n",
	    OFFSET(ul_mapsiz),
	    ulwp.ul_mapsiz,
	    ulwp.ul_guardsize,
	    prt_addr((void *)ulwp.ul_stktop, 1),
	    ulwp.ul_stksiz);

	HD("ustack.ss_sp          ustack.ss_size        ustack.ss_flags");
	mdb_printf(OFFSTR "%s %-21ld %s\n",
	    OFFSET(ul_ustack.ss_sp),
	    prt_addr(ulwp.ul_ustack.ss_sp, 1),
	    ulwp.ul_ustack.ss_size,
	    stack_flags(&ulwp.ul_ustack));

	HD("ix         lwpid      pri        epri       policy     cid");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d %d\n",
	    OFFSET(ul_ix),
	    ulwp.ul_ix,
	    ulwp.ul_lwpid,
	    ulwp.ul_pri,
	    ulwp.ul_epri,
	    ulwp.ul_policy,
	    ulwp.ul_cid);

	HD("cursig     pleasestop stop       signalled  dead       unwind");
	mdb_printf(OFFSTR "%-10d ",
	    OFFSET(ul_cursig),
	    ulwp.ul_cursig);
	mdb_printf(ulwp.ul_pleasestop? "0x%-8x " : "%-10d ",
	    ulwp.ul_pleasestop);
	mdb_printf(ulwp.ul_stop? "0x%-8x " : "%-10d ",
	    ulwp.ul_stop);
	mdb_printf("%-10d %-10d %d\n",
	    ulwp.ul_signalled,
	    ulwp.ul_dead,
	    ulwp.ul_unwind);

	HD("detached   writer     stopping   can'prolog preempt    savpreempt");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d %d\n",
	    OFFSET(ul_detached),
	    ulwp.ul_detached,
	    ulwp.ul_writer,
	    ulwp.ul_stopping,
	    ulwp.ul_cancel_prologue,
	    ulwp.ul_preempt,
	    ulwp.ul_savpreempt);

	HD("sigsuspend main       fork       primarymap m'spinners d'noreserv");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d %d\n",
	    OFFSET(ul_sigsuspend),
	    ulwp.ul_sigsuspend,
	    ulwp.ul_main,
	    ulwp.ul_fork,
	    ulwp.ul_primarymap,
	    ulwp.ul_max_spinners,
	    ulwp.ul_door_noreserve);

	HD("queue_fifo c'w'defer  e'detect'  async_safe rt         rtqueued");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d %d\n",
	    OFFSET(ul_queue_fifo),
	    ulwp.ul_queue_fifo,
	    ulwp.ul_cond_wait_defer,
	    ulwp.ul_error_detection,
	    ulwp.ul_async_safe,
	    ulwp.ul_rt,
	    ulwp.ul_rtqueued);

	HD("misaligned adapt'spin queue_spin critical   sigdefer   vfork");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d %d\n",
	    OFFSET(ul_misaligned),
	    ulwp.ul_misaligned,
	    ulwp.ul_adaptive_spin,
	    ulwp.ul_queue_spin,
	    ulwp.ul_critical,
	    ulwp.ul_sigdefer,
	    ulwp.ul_vfork);

	HD("cancelable c'pending  c'disabled c'async    save_async mutator");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d %d\n",
	    OFFSET(ul_cancelable),
	    ulwp.ul_cancelable,
	    ulwp.ul_cancel_pending,
	    ulwp.ul_cancel_disabled,
	    ulwp.ul_cancel_async,
	    ulwp.ul_save_async,
	    ulwp.ul_mutator);

	HD("created    replace    nocancel   errno      errnop");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %s\n",
	    OFFSET(ul_created),
	    ulwp.ul_created,
	    ulwp.ul_replace,
	    ulwp.ul_nocancel,
	    ulwp.ul_errno,
	    prt_addr(ulwp.ul_errnop, 0));

	HD("clnup_hdr             schedctl_called       schedctl");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ul_clnup_hdr),
	    prt_addr(ulwp.ul_clnup_hdr, 1),
	    prt_addr(ulwp.ul_schedctl_called, 1),
	    prt_addr((void *)ulwp.ul_schedctl, 0));

	HD("bindflags  libc_locks stsd                  &ftsd");
	mdb_printf(OFFSTR,
	    OFFSET(ul_bindflags));
	mdb_printf(ulwp.ul_bindflags? "0x%-8x " : "%-10d ",
	    ulwp.ul_bindflags);
	mdb_printf("%-10d ", ulwp.ul_libc_locks);
	mdb_printf("%s %s\n",
	    prt_addr(ulwp.ul_stsd, 1),
	    prt_addr((void *)(addr + OFFSET(ul_ftsd[0])), 0));

	HD("eventmask[0..1]       eventnum              eventdata");
	mdb_printf(OFFSTR "0x%08x 0x%08x %-21d %s\n",
	    OFFSET(ul_td_evbuf.eventmask.event_bits[0]),
	    ulwp.ul_td_evbuf.eventmask.event_bits[0],
	    ulwp.ul_td_evbuf.eventmask.event_bits[1],
	    ulwp.ul_td_evbuf.eventnum,
	    prt_addr(ulwp.ul_td_evbuf.eventdata, 0));

	HD("td'enable  sync'reg   qtype      cv_wake    rtld       usropts");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d ",
	    OFFSET(ul_td_events_enable),
	    ulwp.ul_td_events_enable,
	    ulwp.ul_sync_obj_reg,
	    ulwp.ul_qtype,
	    ulwp.ul_cv_wake,
	    ulwp.ul_rtld);
	mdb_printf(ulwp.ul_usropts? "0x%x\n" : "%d\n",
	    ulwp.ul_usropts);

	HD("startpc               startarg              wchan");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ul_startpc),
	    prt_addr((void *)ulwp.ul_startpc, 1),
	    prt_addr(ulwp.ul_startarg, 1),
	    prt_addr(ulwp.ul_wchan, 0));

	HD("link                  sleepq                cvmutex");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ul_link),
	    prt_addr(ulwp.ul_link, 1),
	    prt_addr(ulwp.ul_sleepq, 1),
	    prt_addr(ulwp.ul_cvmutex, 0));

	HD("mxchain               save_state");
	mdb_printf(OFFSTR "%s %d\n",
	    OFFSET(ul_mxchain),
	    prt_addr(ulwp.ul_mxchain, 1),
	    ulwp.ul_save_state);

	HD("rdlockcnt             rd_rwlock             rd_count");
	mdb_printf(OFFSTR "%-21d %s %d\n",
	    OFFSET(ul_rdlockcnt),
	    ulwp.ul_rdlockcnt,
	    prt_addr(ulwp.ul_readlock.single.rd_rwlock, 1),
	    ulwp.ul_readlock.single.rd_count);

	HD("heldlockcnt           heldlocks             tpdp");
	mdb_printf(OFFSTR "%-21d %s %s\n",
	    OFFSET(ul_heldlockcnt),
	    ulwp.ul_heldlockcnt,
	    prt_addr(ulwp.ul_heldlocks.single, 1),
	    prt_addr(ulwp.ul_tpdp, 0));

	HD("siglink               s'l'spin   s'l'spin2  s'l'sleep  s'l'wakeup");
	mdb_printf(OFFSTR "%s %-10d %-10d %-10d %d\n",
	    OFFSET(ul_siglink),
	    prt_addr(ulwp.ul_siglink, 1),
	    ulwp.ul_spin_lock_spin,
	    ulwp.ul_spin_lock_spin2,
	    ulwp.ul_spin_lock_sleep,
	    ulwp.ul_spin_lock_wakeup);

	HD("&queue_root           rtclassid  pilocks");
	mdb_printf(OFFSTR "%s %-10d %d\n",
	    OFFSET(ul_queue_root),
	    prt_addr((void *)(addr + OFFSET(ul_queue_root)), 1),
	    ulwp.ul_rtclassid,
	    ulwp.ul_pilocks);

	/*
	 * The remainder of the ulwp_t structure
	 * is invalid if this is a replacement.
	 */
	if (ulwp.ul_replace)
		return (DCMD_OK);

	HD("sigmask[0..3]");
	mdb_printf(OFFSTR "0x%08x 0x%08x 0x%08x 0x%08x\n",
	    OFFSET(ul_sigmask.__sigbits[0]),
	    ulwp.ul_sigmask.__sigbits[0],
	    ulwp.ul_sigmask.__sigbits[1],
	    ulwp.ul_sigmask.__sigbits[2],
	    ulwp.ul_sigmask.__sigbits[3]);

	HD("tmpmask[0..3]");
	mdb_printf(OFFSTR "0x%08x 0x%08x 0x%08x 0x%08x\n",
	    OFFSET(ul_tmpmask.__sigbits[0]),
	    ulwp.ul_tmpmask.__sigbits[0],
	    ulwp.ul_tmpmask.__sigbits[1],
	    ulwp.ul_tmpmask.__sigbits[2],
	    ulwp.ul_tmpmask.__sigbits[3]);

	HD("&siginfo              &spinlock             &fpuenv");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ul_siginfo),
	    prt_addr((void *)(addr + OFFSET(ul_siginfo)), 1),
	    prt_addr((void *)(addr + OFFSET(ul_spinlock)), 1),
	    prt_addr((void *)(addr + OFFSET(ul_fpuenv)), 0));

	HD("tmem.size             &tmem.roots");
	mdb_printf(OFFSTR "%-21H %s\n",
	    OFFSET(ul_tmem),
	    ulwp.ul_tmem.tm_size,
	    prt_addr((void *)(addr + OFFSET(ul_tmem) + sizeof (size_t)), 0));

	return (DCMD_OK);
}

/*
 * Get the address of the unique uberdata_t structure.
 */
static uintptr_t
uberdata_addr(void)
{
	uintptr_t uaddr;
	uintptr_t addr;
	GElf_Sym sym;

	if (mdb_lookup_by_obj("libc.so.1", "_tdb_bootstrap", &sym) != 0) {
		mdb_warn("cannot find libc.so.1`_tdb_bootstrap");
		return (NULL);
	}
	if (mdb_vread(&addr, sizeof (addr), sym.st_value) == sizeof (addr) &&
	    addr != NULL &&
	    mdb_vread(&uaddr, sizeof (uaddr), addr) == sizeof (uaddr) &&
	    uaddr != NULL) {
		return (uaddr);
	}
	if (mdb_lookup_by_obj("libc.so.1", "_uberdata", &sym) != 0) {
		mdb_warn("cannot find libc.so.1`_uberdata");
		return (NULL);
	}
	return ((uintptr_t)sym.st_value);
}

#undef OFFSET
#define	OFFSET(member)	((size_t)OFFSETOF(uberdata_t, member))

/*ARGSUSED*/
static int
d_uberdata(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uberdata_t uberdata;
	int i;

	if (argc != 0)
		return (DCMD_USAGE);
	if (!(flags & DCMD_ADDRSPEC) && (addr = uberdata_addr()) == NULL)
		return (DCMD_ERR);

	if (mdb_vread(&uberdata, sizeof (uberdata), addr) !=
	    sizeof (uberdata)) {
		mdb_warn("failed to read uberdata at 0x%p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%#a\n", addr);

	HD("&link_lock            &ld_lock              &fork_lock");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(link_lock),
	    prt_addr((void *)(addr + OFFSET(link_lock)), 1),
	    prt_addr((void *)(addr + OFFSET(ld_lock)), 1),
	    prt_addr((void *)(addr + OFFSET(fork_lock)), 0));

	HD("&atfork_lock          &callout_lock         &tdb_hash_lock");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(atfork_lock),
	    prt_addr((void *)(addr + OFFSET(atfork_lock)), 1),
	    prt_addr((void *)(addr + OFFSET(callout_lock)), 1),
	    prt_addr((void *)(addr + OFFSET(tdb_hash_lock)), 0));

	HD("&tdb_hash_lock_stats  &siguaction[0]");
	mdb_printf(OFFSTR "%s %s\n",
	    OFFSET(tdb_hash_lock_stats),
	    prt_addr((void *)(addr + OFFSET(tdb_hash_lock_stats)), 1),
	    prt_addr((void *)(addr + OFFSET(siguaction)), 0));

	HD("&bucket               free_list             chunks");
	for (i = 0; i < NBUCKETS; i++) {
		mdb_printf(OFFSTR "%s %s %ld\n",
		    OFFSET(bucket[i]),
		    prt_addr((void *)(addr + OFFSET(bucket[i])), 1),
		    prt_addr(uberdata.bucket[i].free_list, 1),
		    uberdata.bucket[i].chunks);
	}

	HD("&atexit_root          head                  exit_frame_monitor");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(atexit_root),
	    prt_addr((void *)(addr + OFFSET(atexit_root.exitfns_lock)), 1),
	    prt_addr(uberdata.atexit_root.head, 1),
	    prt_addr(uberdata.atexit_root.exit_frame_monitor, 0));

	HD("&tsd_metadata         tsdm_nkeys tsdm_nused tsdm_destro");
	mdb_printf(OFFSTR "%s %-10d %-10d %s\n",
	    OFFSET(tsd_metadata),
	    prt_addr((void *)(addr + OFFSET(tsd_metadata.tsdm_lock)), 1),
	    uberdata.tsd_metadata.tsdm_nkeys,
	    uberdata.tsd_metadata.tsdm_nused,
	    prt_addr((void *)uberdata.tsd_metadata.tsdm_destro, 0));

	HD("&tls_metadata         tls_modinfo.data      tls_modinfo.size");
	mdb_printf(OFFSTR "%s %s %ld\n",
	    OFFSET(tls_metadata),
	    prt_addr((void *)(addr + OFFSET(tls_metadata.tls_lock)), 1),
	    prt_addr(uberdata.tls_metadata.tls_modinfo.tls_data, 1),
	    uberdata.tls_metadata.tls_modinfo.tls_size);

	HD("                      static_tls.data       static_tls.size");
	mdb_printf(OFFSTR "%s %s %ld\n",
	    OFFSET(tls_metadata.static_tls),
	    "                     ",
	    prt_addr(uberdata.tls_metadata.static_tls.tls_data, 1),
	    uberdata.tls_metadata.static_tls.tls_size);

	HD("primary_ma bucket_ini uflags.mt  uflags.pad uflags.trs uflags.ted");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d %-10d %d\n",
	    OFFSET(primary_map),
	    uberdata.primary_map,
	    uberdata.bucket_init,
	    uberdata.uberflags.uf_x.x_mt,
	    uberdata.uberflags.uf_x.x_pad,
	    uberdata.uberflags.uf_x.x_tdb_register_sync,
	    uberdata.uberflags.uf_x.x_thread_error_detection);

	HD("queue_head            thr_hash_table        hash_size  hash_mask");
	mdb_printf(OFFSTR "%s %s %-10d 0x%x\n",
	    OFFSET(queue_head),
	    prt_addr(uberdata.queue_head, 1),
	    prt_addr(uberdata.thr_hash_table, 1),
	    uberdata.hash_size,
	    uberdata.hash_mask);

	HD("ulwp_one              all_lwps              all_zombies");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ulwp_one),
	    prt_addr(uberdata.ulwp_one, 1),
	    prt_addr(uberdata.all_lwps, 1),
	    prt_addr(uberdata.all_zombies, 0));

	HD("nthreads   nzombies   ndaemons   pid");
	mdb_printf(OFFSTR "%-10d %-10d %-10d %-10d\n",
	    OFFSET(nthreads),
	    uberdata.nthreads,
	    uberdata.nzombies,
	    uberdata.ndaemons,
	    (int)uberdata.pid);

	HD("sigacthandler         setctxt");
	mdb_printf(OFFSTR "%s %s\n",
	    OFFSET(sigacthandler),
	    prt_addr((void *)uberdata.sigacthandler, 1),
	    prt_addr((void *)uberdata.setctxt, 1));

	HD("lwp_stacks            lwp_laststack         nfreestack stk_cache");
	mdb_printf(OFFSTR "%s %s %-10d %d\n",
	    OFFSET(lwp_stacks),
	    prt_addr(uberdata.lwp_stacks, 1),
	    prt_addr(uberdata.lwp_laststack, 1),
	    uberdata.nfreestack,
	    uberdata.thread_stack_cache);

	HD("ulwp_freelist         ulwp_lastfree         ulwp_replace_free");
	mdb_printf(OFFSTR "%s %s %s\n",
	    OFFSET(ulwp_freelist),
	    prt_addr(uberdata.ulwp_freelist, 1),
	    prt_addr(uberdata.ulwp_lastfree, 1),
	    prt_addr(uberdata.ulwp_replace_free, 0));

	HD("ulwp_replace_last     atforklist");
	mdb_printf(OFFSTR "%s %s\n",
	    OFFSET(ulwp_replace_last),
	    prt_addr(uberdata.ulwp_replace_last, 1),
	    prt_addr(uberdata.atforklist, 0));

	HD("robustlocks           robustlist");
	mdb_printf(OFFSTR "%s %s\n",
	    OFFSET(robustlocks),
	    prt_addr(uberdata.robustlocks, 1),
	    prt_addr(uberdata.robustlist, 1));

	HD("progname              ub_broot");
	mdb_printf(OFFSTR "%s %s\n",
	    OFFSET(progname),
	    prt_addr(uberdata.progname, 1),
	    prt_addr(uberdata.ub_broot, 1));

	HD("tdb_bootstrap         tdb_sync_addr_hash    tdb_'count tdb_'fail");
	mdb_printf(OFFSTR "%s %s %-10d %d\n",
	    OFFSET(tdb_bootstrap),
	    prt_addr(uberdata.tdb_bootstrap, 1),
	    prt_addr(uberdata.tdb.tdb_sync_addr_hash, 1),
	    uberdata.tdb.tdb_register_count,
	    uberdata.tdb.tdb_hash_alloc_failed);

	HD("tdb_sync_addr_free    tdb_sync_addr_last    tdb_sync_alloc");
	mdb_printf(OFFSTR "%s %s %ld\n",
	    OFFSET(tdb.tdb_sync_addr_free),
	    prt_addr(uberdata.tdb.tdb_sync_addr_free, 1),
	    prt_addr(uberdata.tdb.tdb_sync_addr_last, 1),
	    uberdata.tdb.tdb_sync_alloc);

	HD("tdb_ev_global_mask    tdb_events");
	mdb_printf(OFFSTR "0x%08x 0x%08x %s\n",
	    OFFSET(tdb.tdb_ev_global_mask),
	    uberdata.tdb.tdb_ev_global_mask.event_bits[0],
	    uberdata.tdb.tdb_ev_global_mask.event_bits[1],
	    prt_addr((void *)uberdata.tdb.tdb_events, 0));

	return (DCMD_OK);
}

static int
ulwp_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	uintptr_t uber_addr;

	if (addr == NULL &&
	    ((uber_addr = uberdata_addr()) == NULL ||
	    mdb_vread(&addr, sizeof (addr),
	    uber_addr + OFFSETOF(uberdata_t, all_lwps))
	    != sizeof (addr))) {
		mdb_warn("cannot find 'uberdata.all_lwps'");
		return (WALK_ERR);
	}
	if (addr == NULL)
		return (WALK_DONE);
	wsp->walk_addr = addr;
	wsp->walk_data = (void *)addr;
	return (WALK_NEXT);
}

static int
ulwp_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	ulwp_t ulwp;

	if (addr == NULL)
		return (WALK_DONE);
	if (mdb_vread(&ulwp, sizeof (ulwp), addr) != sizeof (ulwp) &&
	    (bzero(&ulwp, sizeof (ulwp)),
	    mdb_vread(&ulwp, REPLACEMENT_SIZE, addr)) != REPLACEMENT_SIZE) {
		mdb_warn("failed to read ulwp at 0x%p", addr);
		return (WALK_ERR);
	}
	/*
	 * If we have looped around to the beginning
	 * of the circular linked list, we are done.
	 */
	if ((wsp->walk_addr = (uintptr_t)ulwp.ul_forw)
	    == (uintptr_t)wsp->walk_data)
		wsp->walk_addr = NULL;
	return (wsp->walk_callback(addr, &ulwp, wsp->walk_cbdata));
}

/* Avoid classifying NULL pointers as part of the main stack on x86 */
#define	MIN_STACK_ADDR		(0x10000ul)

static int
whatis_walk_ulwp(uintptr_t addr, const ulwp_t *ulwp, mdb_whatis_t *w)
{
	uintptr_t cur;
	lwpid_t id = ulwp->ul_lwpid;
	uintptr_t top, base, size;

	while (mdb_whatis_match(w, addr, sizeof (ulwp_t), &cur))
		mdb_whatis_report_object(w, cur, addr,
		    "allocated as thread %#r's ulwp_t\n", id);

	top = (uintptr_t)ulwp->ul_stktop;
	size = ulwp->ul_stksiz;

	/*
	 * The main stack ends up being a little weird, especially if
	 * the stack ulimit is unlimited.  This tries to take that into
	 * account.
	 */
	if (size > top)
		size = top;
	if (top > MIN_STACK_ADDR && top - size < MIN_STACK_ADDR)
		size = top - MIN_STACK_ADDR;

	base = top - size;

	while (mdb_whatis_match(w, base, size, &cur))
		mdb_whatis_report_address(w, cur, "in [ stack tid=%#r ]\n", id);

	if (ulwp->ul_ustack.ss_flags & SS_ONSTACK) {
		base = (uintptr_t)ulwp->ul_ustack.ss_sp;
		size = ulwp->ul_ustack.ss_size;

		while (mdb_whatis_match(w, base, size, &cur))
			mdb_whatis_report_address(w, cur,
			    "in [ altstack tid=%#r ]\n", id);
	}

	return (WHATIS_WALKRET(w));
}

/*ARGSUSED*/
static int
whatis_run_ulwps(mdb_whatis_t *w, void *arg)
{
	if (mdb_walk("ulwps", (mdb_walk_cb_t)whatis_walk_ulwp, w) == -1) {
		mdb_warn("couldn't find ulwps walker");
		return (1);
	}
	return (0);
}

/*
 * =======================================================
 * End of thread (previously libthread) interfaces.
 * ==================== threads ==========================
 */

int
stacks_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int rval = stacks(addr, flags, argc, argv);

	/*
	 * For the user-level variant of ::stacks, we don't bother caching
	 * state, as even a very large program is unlikely to compare to the
	 * kernel in terms of number of threads.  (And if you find yourself
	 * here in anger, frustrated about how long ::stacks is running on
	 * your galactically complicated zillion-thread program, hopefully
	 * you will find some solace in the irony.  Okay, probably not...)
	 */
	stacks_cleanup(B_TRUE);
	return (rval);
}

typedef struct tid2ulwp_walk {
	lwpid_t t2u_tid;
	uintptr_t t2u_lwp;
	boolean_t t2u_found;
} tid2ulwp_walk_t;

/*ARGSUSED*/
static int
tid2ulwp_walk(uintptr_t addr, ulwp_t *ulwp, tid2ulwp_walk_t *t2u)
{
	if (ulwp->ul_lwpid == t2u->t2u_tid) {
		t2u->t2u_lwp = addr;
		t2u->t2u_found = B_TRUE;
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

static int
tid2ulwp_impl(uintptr_t tid_addr, uintptr_t *ulwp_addrp)
{
	tid2ulwp_walk_t t2u;

	bzero(&t2u, sizeof (t2u));
	t2u.t2u_tid = (lwpid_t)tid_addr;

	if (mdb_walk("ulwp", (mdb_walk_cb_t)tid2ulwp_walk, &t2u) != 0) {
		mdb_warn("can't walk 'ulwp'");
		return (DCMD_ERR);
	}

	if (!t2u.t2u_found) {
		mdb_warn("thread ID %d not found", t2u.t2u_tid);
		return (DCMD_ERR);
	}
	*ulwp_addrp = t2u.t2u_lwp;
	return (DCMD_OK);
}

/*ARGSUSED*/
static int
tid2ulwp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t ulwp_addr;
	int error;

	if (argc != 0)
		return (DCMD_USAGE);

	error = tid2ulwp_impl(addr, &ulwp_addr);
	if (error == DCMD_OK)
		mdb_printf("%p\n", ulwp_addr);
	return (error);
}

typedef struct mdb_libc_ulwp {
	void *ul_ftsd[TSD_NFAST];
	tsd_t *ul_stsd;
} mdb_libc_ulwp_t;

/*
 * Map from thread pointer to tsd for given key
 */
static int
d_tsd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_libc_ulwp_t u;
	uintptr_t ulwp_addr;
	uintptr_t key = NULL;
	void *element = NULL;

	if (mdb_getopts(argc, argv, 'k', MDB_OPT_UINTPTR, &key, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC) || key == NULL)
		return (DCMD_USAGE);

	if (tid2ulwp_impl(addr, &ulwp_addr) != DCMD_OK)
		return (DCMD_ERR);

	if (mdb_ctf_vread(&u, "ulwp_t", "mdb_libc_ulwp_t", ulwp_addr, 0) == -1)
		return (DCMD_ERR);

	if (key < TSD_NFAST) {
		element = u.ul_ftsd[key];
	} else if (u.ul_stsd != NULL) {
		uint_t nalloc;
		/* tsd_t is a union, so we can't use ctf_vread() on it. */
		if (mdb_vread(&nalloc, sizeof (nalloc),
		    (uintptr_t)&u.ul_stsd->tsd_nalloc) == -1) {
			mdb_warn("failed to read tsd_t at %p", u.ul_stsd);
			return (DCMD_ERR);
		}
		if (key < nalloc) {
			if (mdb_vread(&element, sizeof (element),
			    (uintptr_t)&u.ul_stsd->tsd_data[key]) == -1) {
				mdb_warn("failed to read tsd_t at %p",
				    u.ul_stsd);
				return (DCMD_ERR);
			}
		}
	}

	if (element == NULL && (flags & DCMD_PIPE))
		return (DCMD_OK);

	mdb_printf("%p\n", element);
	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "jmp_buf", ":", "print jmp_buf contents", d_jmp_buf, NULL },
	{ "sigjmp_buf", ":", "print sigjmp_buf contents", d_sigjmp_buf, NULL },
	{ "siginfo", ":", "print siginfo_t structure", d_siginfo, NULL },
	{ "stacks", "?[-afiv] [-c func] [-C func] [-m module] [-M module] ",
		"print unique thread stacks", stacks_dcmd, stacks_help },
	{ "tid2ulwp", "?", "convert TID to ulwp_t address", tid2ulwp },
	{ "ucontext", ":", "print ucontext_t structure", d_ucontext, NULL },
	{ "ulwp", ":", "print ulwp_t structure", d_ulwp, NULL },
	{ "uberdata", ":", "print uberdata_t structure", d_uberdata, NULL },
	{ "tsd", ":-k key", "print tsd for this thread", d_tsd, NULL },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "ucontext", "walk ucontext_t uc_link list",
		NULL, uc_walk_step, NULL, NULL },
	{ "oldcontext", "walk per-lwp oldcontext pointers",
		oldc_walk_init, oldc_walk_step, oldc_walk_fini, NULL },
	{ "ulwps", "walk list of ulwp_t pointers",
		ulwp_walk_init, ulwp_walk_step, NULL, NULL },
	{ "ulwp", "walk list of ulwp_t pointers",
		ulwp_walk_init, ulwp_walk_step, NULL, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	mdb_whatis_register("threads", whatis_run_ulwps, NULL,
	    WHATIS_PRIO_EARLY, WHATIS_REG_NO_ID);

	return (&modinfo);
}
