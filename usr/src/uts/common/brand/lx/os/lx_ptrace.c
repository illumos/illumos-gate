/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Emulation of the Linux ptrace(2) interface.
 *
 * OVERVIEW
 *
 * The Linux process model is somewhat different from the illumos native
 * model.  One critical difference is that each Linux thread has a unique
 * identifier in the pid namespace.  The lx brand assigns a pid to each LWP
 * within the emulated process, giving the pid of the process itself to the
 * first LWP.
 *
 * The Linux ptrace(2) interface allows for any LWP in a branded process to
 * exert control over any other LWP within the same zone.  Control is exerted
 * by the use of the ptrace(2) system call itself, which accepts a number of
 * request codes.  Feedback on traced events is primarily received by the
 * tracer through SIGCLD and the emulated waitpid(2) and waitid(2) system
 * calls.  Many of the possible ptrace(2) requests will only succeed if the
 * target LWP is in a "ptrace-stop" condition.
 *
 * HISTORY
 *
 * The brand support for ptrace(2) was originally built on top of the rich
 * support for debugging and tracing provided through the illumos /proc
 * interfaces, mounted at /native/proc within the zone.  The native legacy
 * ptrace(3C) functionality was used as a starting point, but was generally
 * insufficient for complete and precise emulation.  The extant legacy
 * interface, and indeed our native SIGCLD and waitid(2) facilities, are
 * focused on _process_ level concerns -- the Linux interface has been
 * extended to be aware of LWPs as well.
 *
 * In order to allow us to focus on providing more complete and accurate
 * emulation without extensive and undesirable changes to the native
 * facilities, this second generation ptrace(2) emulation is mostly separate
 * from any other tracing or debugging framework in the system.
 *
 * ATTACHING TRACERS TO TRACEES
 *
 * There are several ways that a child LWP may becomed traced by a tracer.
 * To determine which attach method caused a tracee to become attached, one
 * may inspect the "br_ptrace_attach" member of the LWP-specific brand data
 * with the debugger.
 *
 * The first attach methods to consider are the attaching ptrace(2) requests:
 *
 *   PTRACE_TRACEME
 *
 *   If an LWP makes a PTRACE_TRACEME call, it will be attached as a tracee
 *   to its parent LWP (br_ppid).  Using PTRACE_TRACEME does _not_ cause the
 *   tracee to be held in a stop condition.  It is common practice for
 *   consumers to raise(SIGSTOP) immediately afterward.
 *
 *   PTRACE_ATTACH
 *
 *   An LWP may attempt to trace any other LWP in this, or another, process.
 *   We currently allow any attach where the process containing the tracer
 *   LWP has permission to write to /proc for the process containing the
 *   intended tracer.  This action also sends a SIGSTOP to the newly attached
 *   tracee.
 *
 * The second class of attach methods are the clone(2)/fork(2) inheritance
 * options that may be set on a tracee with PTRACE_SETOPTIONS:
 *
 *   PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK and PTRACE_O_TRACECLONE
 *
 *   If these options have been set on a tracee, then a fork(2), vfork(2) or
 *   clone(2) respectively will cause the newly created LWP to be traced by
 *   the same tracer.  The same set of ptrace(2) options will also be set on
 *   the new child.
 *
 * The third class of attach method is the PTRACE_CLONE flag to clone(2).
 * This flag induces the same inheritance as PTRACE_O_TRACECLONE, but is
 * passed by the tracee as an argument to clone(2).
 *
 * DETACHING TRACEES
 *
 * Tracees can be detached by the tracer with the PTRACE_DETACH request.
 * This request is only valid when the tracee is in a ptrace(2) stop
 * condition, and is itself a restarting action.
 *
 * If the tracer exits without detaching all of its tracees, then all of the
 * tracees are automatically detached and restarted.  If a tracee was in
 * "signal-delivery-stop" at the time the tracer exited, the signal will be
 * released to the child unless it is a SIGSTOP.  We drop this instance of
 * SIGSTOP in order to prevent the child from becoming stopped by job
 * control.
 *
 * ACCORD ALLOCATION AND MANAGEMENT
 *
 * The "lx_ptrace_accord_t" object tracks the agreement between a tracer LWP
 * and zero or more tracee LWPs.  It is explicitly illegal for a tracee to
 * trace its tracer, and we block this in PTRACE_ATTACH/PTRACE_TRACEME.
 *
 * An LWP starts out without an accord.  If a child of that LWP calls
 * ptrace(2) with the PTRACE_TRACEME subcommand, or if the LWP itself uses
 * PTRACE_ATTACH, an accord will be allocated and stored on that LWP.  The
 * accord structure is not released from that LWP until it arrives in
 * lx_exitlwp(), as called by lwp_exit().  A new accord will not be
 * allocated, even if one does not exist, once an LWP arrives in lx_exitlwp()
 * and sets the LX_PTF_EXITING flag.  An LWP will have at most one accord
 * structure throughout its entire lifecycle; once it has one, it has the
 * same one until death.
 *
 * The accord is reference counted (lxpa_refcnt), starting at a count of one
 * at creation to represent the link from the tracer LWP to its accord.  The
 * accord is not freed until the reference count falls to zero.
 *
 * To make mutual exclusion between a detaching tracer and various notifying
 * tracees simpler, the tracer will hold "pidlock" while it clears the
 * accord members that point back to the tracer LWP and CV.
 *
 * SIGNALS AND JOB CONTROL
 *
 * Various actions, either directly ptrace(2) related or commonly associated
 * with tracing, cause process- or thread-directed SIGSTOP signals to be sent
 * to tracees (a "signal-delivery-stop"). These signals, and indeed any signal
 * other than SIGKILL, can be suppressed by the tracer when using a restarting
 * request (including PTRACE_DETACH) on a child.  The signal may also be
 * substituted for a different signal.
 *
 * If a SIGSTOP (or other stopping signal) is not suppressed by the tracer,
 * it will induce the regular illumos native job control stop of the entire
 * traced process.  This is at least passingly similar to the Linux "group
 * stop" ptrace(2) condition.
 *
 * SYSTEM CALL TRACING
 *
 * The ptrace(2) interface enables the tracer to hold the tracee on entry and
 * exit from system calls.  When a stopped tracee is restarted through the
 * PTRACE_SYSCALL request, the LX_PTF_SYSCALL flag is set until the next
 * system call boundary.  Whether this is a "syscall-entry-stop" or
 * "syscall-exit-stop", the tracee is held and the tracer is notified via
 * SIGCLD/waitpid(2) in the usual way.  The flag LX_PTF_SYSCALL flag is
 * cleared after each stop; for ongoing system call tracing the tracee must
 * be continuously restarted with PTRACE_SYSCALL.
 *
 * SPECIAL CASES FOR STOP EVENTS
 *
 * The strace command is one of the primary consumers of ptrace. In order for
 * strace to properly understand what is actually happening when it receives a
 * signal associated with a stop event, these signals must match Linux behavior
 * exactly or the strace consumer will get out of sync and report incorrect
 * state. There are a couple of special cases we have to handle to provide
 * proper interaction of the syscall-entry-stop, syscall-exit-stop, and
 * signal-delivery-stop events:
 * 1) The child process of a clone/fork does not emit a syscall-exit-stop event.
 * 2) A signal that arrives between syscall-enter-stop & syscall-exit-stop must
 *    not immediately emit signal-delivery-stop. This event must be emitted
 *    after the syscall is interrupted and syscall-exit-stop has been emitted.
 *
 * EVENT STOPS
 *
 * Various events (particularly FORK, VFORK, CLONE, EXEC and EXIT) are
 * enabled by the tracer through PTRACE_SETOPTIONS.  Once enabled, the tracee
 * will be stopped at the nominated points of interest and the tracer
 * notified.  The tracer may request additional information about the event,
 * such as the pid of new LWPs and processes, via PTRACE_GETEVENTMSG.
 *
 * LOCK ORDERING RULES
 *
 * It is not safe, in general, to hold p_lock for two different processes at
 * the same time.  This constraint is the primary reason for the existence
 * (and complexity) of the ptrace(2) accord mechanism.
 *
 * In order to facilitate looking up accords by the "pid" of a tracer LWP,
 * p_lock for the tracer process may be held while entering the accord mutex
 * (lxpa_lock).  This mutex protects the accord flags and reference count.
 * The reference count is manipulated through lx_ptrace_accord_hold() and
 * lx_ptrace_accord_rele().
 *
 * DO NOT interact with the accord mutex (lxpa_lock) directly.  The
 * lx_ptrace_accord_enter() and lx_ptrace_accord_exit() functions do various
 * book-keeping and lock ordering enforcement and MUST be used.
 *
 * It is NOT legal to take ANY p_lock while holding the accord mutex
 * (lxpa_lock).  If the lxpa_tracees_lock is to be held concurrently with
 * lxpa_lock, lxpa_lock MUST be taken first and dropped before taking p_lock
 * of any processes from the tracee list.
 *
 * It is NOT legal to take a tracee p_lock and then attempt to enter the
 * accord mutex (or tracee list mutex) of its tracer.  When running as the
 * tracee LWP, the tracee's hold will prevent the accord from being freed.
 * Use of the LX_PTF_STOPPING or LX_PTF_CLONING flag in the LWP-specific brand
 * data prevents an exiting tracer from altering the tracee until the tracee
 * has come to an orderly stop, without requiring the tracee to hold its own
 * p_lock the entire time it is stopping.
 *
 * It is not safe, in general, to enter "pidlock" while holding the p_lock of
 * any process.  It is similarly illegal to hold any accord locks (lxpa_lock
 * or lxpa_sublock) while attempting to enter "pidlock".  As "pidlock" is a
 * global mutex, it should be held for the shortest possible time.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/sysmacros.h>
#include <sys/procfs.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/wait.h>
#include <sys/prsystm.h>
#include <sys/note.h>

#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_impl.h>
#include <sys/lx_misc.h>
#include <lx_syscall.h>
#include <lx_signum.h>


typedef enum lx_ptrace_cont_flags_t {
	LX_PTC_NONE = 0x00,
	LX_PTC_SYSCALL = 0x01,
	LX_PTC_SINGLESTEP = 0x02
} lx_ptrace_cont_flags_t;


extern int lx_user_regs_copyin(lx_lwp_data_t *, void *);
extern int lx_user_regs_copyout(lx_lwp_data_t *, void *);
extern int lx_ptrace_peekuser(lx_lwp_data_t *, uintptr_t, void *);
extern int lx_ptrace_pokeuser(lx_lwp_data_t *, uintptr_t, void *);
extern int lx_user_fpregs_copyin(lx_lwp_data_t *, void *);
extern int lx_user_fpregs_copyout(lx_lwp_data_t *, void *);
extern int lx_user_fpxregs_copyin(lx_lwp_data_t *, void *);
extern int lx_user_fpxregs_copyout(lx_lwp_data_t *, void *);

/*
 * Macros for checking the state of an LWP via "br_ptrace_flags":
 */
#define	LX_PTRACE_BUSY \
	(LX_PTF_EXITING | LX_PTF_STOPPING | LX_PTF_CLONING)

#define	VISIBLE(a)	(((a)->br_ptrace_flags & LX_PTF_EXITING) == 0)
#define	TRACEE_BUSY(a)	(((a)->br_ptrace_flags & LX_PTRACE_BUSY) != 0)

#define	ACCORD_HELD(a)	MUTEX_HELD(&(a)->lxpa_lock)

#define	LX_PID_TO_INIT(x)	((x) == curproc->p_zone->zone_proc_initpid ? \
	1 : (x))
#define	LX_INIT_TO_PID(x)	((x) == 1 ? \
	curproc->p_zone->zone_proc_initpid : (x))

static kcondvar_t lx_ptrace_busy_cv;
static kmem_cache_t *lx_ptrace_accord_cache;

/*
 * Enter the accord mutex.
 */
static void
lx_ptrace_accord_enter(lx_ptrace_accord_t *accord)
{
	VERIFY(MUTEX_NOT_HELD(&accord->lxpa_tracees_lock));

	mutex_enter(&accord->lxpa_lock);
}

/*
 * Exit the accord mutex.  If the reference count has dropped to zero,
 * free the accord.
 */
static void
lx_ptrace_accord_exit(lx_ptrace_accord_t *accord)
{
	VERIFY(ACCORD_HELD(accord));

	if (accord->lxpa_refcnt > 0) {
		mutex_exit(&accord->lxpa_lock);
		return;
	}

	/*
	 * When the reference count drops to zero we must free the accord.
	 */
	VERIFY(accord->lxpa_tracer == NULL);
	VERIFY(MUTEX_NOT_HELD(&accord->lxpa_tracees_lock));
	VERIFY(list_is_empty(&accord->lxpa_tracees));
	VERIFY(accord->lxpa_flags & LX_ACC_TOMBSTONE);

	mutex_destroy(&accord->lxpa_lock);
	mutex_destroy(&accord->lxpa_tracees_lock);

	kmem_cache_free(lx_ptrace_accord_cache, accord);
}

/*
 * Drop our reference to this accord.  If this drops the reference count
 * to zero, the next lx_ptrace_accord_exit() will free the accord.
 */
static void
lx_ptrace_accord_rele(lx_ptrace_accord_t *accord)
{
	VERIFY(ACCORD_HELD(accord));

	VERIFY(accord->lxpa_refcnt > 0);
	accord->lxpa_refcnt--;
}

/*
 * Place an additional hold on an accord.
 */
static void
lx_ptrace_accord_hold(lx_ptrace_accord_t *accord)
{
	VERIFY(ACCORD_HELD(accord));

	accord->lxpa_refcnt++;
}

/*
 * Fetch the accord for this LWP.  If one has not yet been created, and the
 * process is not exiting, allocate it now.  Must be called with p_lock held
 * for the process containing the target LWP.
 *
 * If successful, we return holding the accord lock (lxpa_lock).
 */
static int
lx_ptrace_accord_get_locked(klwp_t *lwp, lx_ptrace_accord_t **accordp,
    boolean_t allocate_one)
{
	lx_ptrace_accord_t *lxpa;
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	proc_t *p = lwptoproc(lwp);

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * If this LWP does not have an accord, we wish to allocate
	 * and install one.
	 */
	if ((lxpa = lwpd->br_ptrace_accord) == NULL) {
		if (!allocate_one || !VISIBLE(lwpd)) {
			/*
			 * Either we do not wish to allocate an accord, or this
			 * LWP has already begun exiting from a ptrace
			 * perspective.
			 */
			*accordp = NULL;
			return (ESRCH);
		}

		lxpa = kmem_cache_alloc(lx_ptrace_accord_cache, KM_SLEEP);
		bzero(lxpa, sizeof (*lxpa));

		/*
		 * The initial reference count is 1 because we are referencing
		 * it in from the soon-to-be tracer LWP.
		 */
		lxpa->lxpa_refcnt = 1;
		mutex_init(&lxpa->lxpa_lock, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&lxpa->lxpa_tracees_lock, NULL, MUTEX_DEFAULT, NULL);
		list_create(&lxpa->lxpa_tracees, sizeof (lx_lwp_data_t),
		    offsetof(lx_lwp_data_t, br_ptrace_linkage));
		lxpa->lxpa_cvp = &p->p_cv;

		lxpa->lxpa_tracer = lwpd;
		lwpd->br_ptrace_accord = lxpa;
	}

	/*
	 * Lock the accord before returning it to the caller.
	 */
	lx_ptrace_accord_enter(lxpa);

	/*
	 * There should be at least one active reference to this accord,
	 * otherwise it should have been freed.
	 */
	VERIFY(lxpa->lxpa_refcnt > 0);

	*accordp = lxpa;
	return (0);
}

/*
 * Accords belong to the tracer LWP.  Get the accord for this tracer or return
 * an error if it was not possible.  To prevent deadlocks, the caller MUST NOT
 * hold p_lock on its own or any other process.
 *
 * If successful, we return holding the accord lock (lxpa_lock).
 */
static int
lx_ptrace_accord_get_by_pid(pid_t lxpid, lx_ptrace_accord_t **accordp)
{
	int ret = ESRCH;
	proc_t *aproc;
	kthread_t *athr;
	klwp_t *alwp;
	lx_lwp_data_t *alwpd;

	VERIFY(MUTEX_NOT_HELD(&curproc->p_lock));

	/*
	 * Locate the process containing the tracer LWP based on its Linux pid
	 * and lock it.
	 */
	if (lx_lpid_lock(lxpid, curzone, PRLOCK, &aproc, &athr) != 0) {
		return (ESRCH);
	}

	/*
	 * Locate the tracer LWP itself and ensure that it is visible to
	 * ptrace(2).
	 */
	if ((alwp = ttolwp(athr)) == NULL ||
	    (alwpd = lwptolxlwp(alwp)) == NULL ||
	    !VISIBLE(alwpd)) {
		sprunlock(aproc);
		return (ESRCH);
	}

	/*
	 * We should not fetch our own accord this way.
	 */
	if (athr == curthread) {
		sprunlock(aproc);
		return (EPERM);
	}

	/*
	 * Fetch (or allocate) the accord owned by this tracer LWP:
	 */
	ret = lx_ptrace_accord_get_locked(alwp, accordp, B_TRUE);

	/*
	 * Unlock the process and return.
	 */
	sprunlock(aproc);
	return (ret);
}

/*
 * Get (or allocate) the ptrace(2) accord for the current LWP, acting as a
 * tracer.  The caller MUST NOT currently hold p_lock on the process containing
 * this LWP.
 *
 * If successful, we return holding the accord lock (lxpa_lock).
 */
static int
lx_ptrace_accord_get(lx_ptrace_accord_t **accordp, boolean_t allocate_one)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	int ret;

	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * Lock the tracer (this LWP).
	 */
	mutex_enter(&p->p_lock);

	/*
	 * Fetch (or allocate) the accord for this LWP:
	 */
	ret = lx_ptrace_accord_get_locked(lwp, accordp, allocate_one);

	mutex_exit(&p->p_lock);

	return (ret);
}

/*
 * Restart an LWP if it is in "ptrace-stop".  This function may induce sleep,
 * so the caller MUST NOT hold any mutexes other than p_lock for the process
 * containing the LWP.
 */
static void
lx_ptrace_restart_lwp(klwp_t *lwp)
{
	kthread_t *rt = lwptot(lwp);
	proc_t *rproc = lwptoproc(lwp);
	lx_lwp_data_t *rlwpd = lwptolxlwp(lwp);

	VERIFY(rt != curthread);
	VERIFY(MUTEX_HELD(&rproc->p_lock));

	/*
	 * Exclude potential meddling from procfs.
	 */
	prbarrier(rproc);

	/*
	 * Check that the LWP is still in "ptrace-stop" and, if so, restart it.
	 */
	thread_lock(rt);
	if (BSTOPPED(rt) && rt->t_whystop == PR_BRAND) {
		rt->t_schedflag |= TS_BSTART;
		setrun_locked(rt);

		/*
		 * Clear stop reason.
		 */
		rlwpd->br_ptrace_whystop = 0;
		rlwpd->br_ptrace_whatstop = 0;
		rlwpd->br_ptrace_flags &= ~(LX_PTF_CLDPEND | LX_PTF_WAITPEND);
	}
	thread_unlock(rt);
}

static void
lx_ptrace_winfo(lx_lwp_data_t *remote, k_siginfo_t *ip, boolean_t waitflag,
    pid_t *event_ppid, pid_t *event_pid)
{
	int signo;

	/*
	 * Populate our k_siginfo_t with data about this "ptrace-stop"
	 * condition:
	 */
	bzero(ip, sizeof (*ip));
	ip->si_signo = SIGCLD;
	ip->si_pid = LX_PID_TO_INIT(remote->br_pid);
	ip->si_code = CLD_TRAPPED;

	switch (remote->br_ptrace_whatstop) {
	case LX_PR_SYSENTRY:
	case LX_PR_SYSEXIT:
		ip->si_status = SIGTRAP;
		if (remote->br_ptrace_options & LX_PTRACE_O_TRACESYSGOOD) {
			ip->si_status |= 0x80;
		}
		break;

	case LX_PR_SIGNALLED:
		signo = remote->br_ptrace_stopsig;
		if (signo < 1 || signo >= LX_NSIG) {
			/*
			 * If this signal number is not valid, pretend it
			 * was a SIGTRAP.
			 */
			ip->si_status = SIGTRAP;
		} else {
			ip->si_status = ltos_signo[signo];
		}
		break;

	case LX_PR_EVENT:
		ip->si_status = SIGTRAP | remote->br_ptrace_event;
		/*
		 * Record the Linux pid of both this LWP and the create
		 * event we are dispatching.  We will use this information
		 * to unblock any subsequent ptrace(2) events that depend
		 * on this one.
		 */
		if (event_ppid != NULL)
			*event_ppid = remote->br_pid;
		if (event_pid != NULL)
			*event_pid = (pid_t)remote->br_ptrace_eventmsg;
		break;

	default:
		cmn_err(CE_PANIC, "unxpected stop subreason: %d",
		    remote->br_ptrace_whatstop);
	}

	/*
	 * If WNOWAIT was specified, do not mark the event as posted
	 * so that it may be re-fetched on another call to waitid().
	 */
	if (waitflag)
		remote->br_ptrace_flags &= ~(LX_PTF_CLDPEND | LX_PTF_WAITPEND);
}

/*
 * Receive notification from stop() of a PR_BRAND stop.
 */
void
lx_stop_notify(proc_t *p, klwp_t *lwp, ushort_t why, ushort_t what)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;
	klwp_t *plwp = NULL;
	proc_t *pp = NULL;
	lx_lwp_data_t *parent;
	boolean_t cldpend = B_TRUE;
	boolean_t cldpost = B_FALSE;
	sigqueue_t *sqp = NULL;

	/*
	 * We currently only care about LX-specific stop reasons.
	 */
	if (why != PR_BRAND)
		return;

	switch (what) {
	case LX_PR_SYSENTRY:
	case LX_PR_SYSEXIT:
	case LX_PR_SIGNALLED:
	case LX_PR_EVENT:
		break;
	default:
		cmn_err(CE_PANIC, "unexpected subreason for PR_BRAND"
		    " stop: %d", (int)what);
	}

	/*
	 * We should be holding the lock on our containing process.  The
	 * STOPPING flag should have been set by lx_ptrace_stop() for all
	 * PR_BRAND stops.
	 */
	VERIFY(MUTEX_HELD(&p->p_lock));
	VERIFY(lwpd->br_ptrace_flags & LX_PTF_STOPPING);
	VERIFY((accord = lwpd->br_ptrace_tracer) != NULL);

	/*
	 * We must drop our process lock to take "pidlock".  The
	 * LX_PTF_STOPPING flag protects us from an exiting tracer.
	 */
	mutex_exit(&p->p_lock);

	/*
	 * Allocate before we enter any mutexes.
	 */
	sqp = kmem_zalloc(sizeof (*sqp), KM_SLEEP);

	/*
	 * We take pidlock now, which excludes all callers of waitid() and
	 * prevents a detaching tracer from clearing critical accord members.
	 */
	mutex_enter(&pidlock);
	mutex_enter(&p->p_lock);

	/*
	 * Get the ptrace(2) "parent" process, to which we may send
	 * a SIGCLD signal later.
	 */
	if ((parent = accord->lxpa_tracer) != NULL &&
	    (plwp = parent->br_lwp) != NULL) {
		pp = lwptoproc(plwp);
	}

	/*
	 * Our tracer should not have been modified in our absence; the
	 * LX_PTF_STOPPING flag prevents it.
	 */
	VERIFY(lwpd->br_ptrace_tracer == accord);

	/*
	 * Stash data for this stop condition in the LWP data while we hold
	 * both pidlock and our p_lock.
	 */
	lwpd->br_ptrace_whystop = why;
	lwpd->br_ptrace_whatstop = what;
	lwpd->br_ptrace_flags |= LX_PTF_WAITPEND;

	/*
	 * If this event does not depend on an event from the parent LWP,
	 * populate the siginfo_t for the event pending on this tracee LWP.
	 */
	if (!(lwpd->br_ptrace_flags & LX_PTF_PARENT_WAIT) && pp != NULL) {
		cldpost = B_TRUE;
		lx_ptrace_winfo(lwpd, &sqp->sq_info, B_FALSE, NULL, NULL);
	}

	/*
	 * Drop our p_lock so that we may lock the tracer.
	 */
	mutex_exit(&p->p_lock);
	if (cldpost && pp != NULL) {
		/*
		 * Post the SIGCLD to the tracer.
		 */
		mutex_enter(&pp->p_lock);
		if (!sigismember(&pp->p_sig, SIGCLD)) {
			sigaddqa(pp, plwp->lwp_thread, sqp);
			cldpend = B_FALSE;
			sqp = NULL;
		}
		mutex_exit(&pp->p_lock);
	}

	/*
	 * We re-take our process lock now.  The lock will be held until
	 * the thread is actually marked stopped, so we will not race with
	 * lx_ptrace_lock_if_stopped() or lx_waitid_helper().
	 */
	mutex_enter(&p->p_lock);

	/*
	 * We clear the STOPPING flag; stop() continues to hold our p_lock
	 * until our thread stop state is visible.
	 */
	lwpd->br_ptrace_flags &= ~LX_PTF_STOPPING;
	lwpd->br_ptrace_flags |= LX_PTF_STOPPED;
	if (cldpend) {
		/*
		 * We sent the SIGCLD for this new wait condition already.
		 */
		lwpd->br_ptrace_flags |= LX_PTF_CLDPEND;
	}

	/*
	 * If lx_ptrace_exit_tracer() is trying to detach our tracer, it will
	 * be sleeping on this CV until LX_PTF_STOPPING is clear.  Wake it
	 * now.
	 */
	cv_broadcast(&lx_ptrace_busy_cv);

	/*
	 * While still holding pidlock, we attempt to wake our tracer from a
	 * potential waitid() slumber.
	 */
	if (accord->lxpa_cvp != NULL) {
		cv_broadcast(accord->lxpa_cvp);
	}

	/*
	 * We release pidlock and return as we were called: with our p_lock
	 * held.
	 */
	mutex_exit(&pidlock);

	if (sqp != NULL) {
		kmem_free(sqp, sizeof (*sqp));
	}
}

/*
 * For any restarting action (e.g. PTRACE_CONT, PTRACE_SYSCALL or
 * PTRACE_DETACH) to be allowed, the tracee LWP must be in "ptrace-stop".  This
 * check must ONLY be run on tracees of the current LWP.  If the check is
 * successful, we return with the tracee p_lock held.
 *
 * In the case of PTRACE_DETACH, we can return with the tracee locked even if
 * it is not in "ptrace-stop". This can happen for various reasons, such as if
 * the remote process is already job-stopped in the kernel. We must still be
 * able to detach from this process. We return ENOENT in this case.
 */
static int
lx_ptrace_lock_if_stopped(lx_ptrace_accord_t *accord, lx_lwp_data_t *remote,
    boolean_t detaching)
{
	klwp_t *rlwp = remote->br_lwp;
	proc_t *rproc = lwptoproc(rlwp);
	kthread_t *rt = lwptot(rlwp);

	/*
	 * We must never check that we, ourselves, are stopped.  We must also
	 * have the accord tracee list locked while we lock our tracees.
	 */
	VERIFY(curthread != rt);
	VERIFY(MUTEX_HELD(&accord->lxpa_tracees_lock));
	VERIFY(accord->lxpa_tracer == ttolxlwp(curthread));

	/*
	 * Lock the process containing the tracee LWP.
	 */
	mutex_enter(&rproc->p_lock);
	if (!VISIBLE(remote)) {
		/*
		 * The tracee LWP is currently detaching itself as it exits.
		 * It is no longer visible to ptrace(2).
		 */
		mutex_exit(&rproc->p_lock);
		return (ESRCH);
	}

	/*
	 * We must only check whether tracees of the current LWP are stopped.
	 * We check this condition after confirming visibility as an exiting
	 * tracee may no longer be completely consistent.
	 */
	VERIFY(remote->br_ptrace_tracer == accord);

	if (!(remote->br_ptrace_flags & LX_PTF_STOPPED)) {
		if (detaching) {
			/*
			 * The tracee is not in "ptrace-stop", but we still
			 * return with the locked process. This is indicated
			 * by ENOENT.
			 */
			return (ENOENT);
		}

		/*
		 * The tracee is not in "ptrace-stop", so we release the
		 * process.
		 */
		mutex_exit(&rproc->p_lock);
		return (ESRCH);
	}

	/*
	 * The tracee is stopped.  We return holding its process lock so that
	 * the caller may manipulate it.
	 */
	return (0);
}

static int
lx_ptrace_setoptions(lx_lwp_data_t *remote, uintptr_t options)
{
	/*
	 * Check for valid options.
	 */
	if ((options & ~LX_PTRACE_O_ALL) != 0) {
		return (EINVAL);
	}

	/*
	 * Set ptrace options on the target LWP.
	 */
	remote->br_ptrace_options = (lx_ptrace_options_t)options;

	return (0);
}

static int
lx_ptrace_geteventmsg(lx_lwp_data_t *remote, void *umsgp)
{
	int error;

#if defined(_SYSCALL32_IMPL)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		uint32_t tmp = remote->br_ptrace_eventmsg;

		error = copyout(&tmp, umsgp, sizeof (uint32_t));
	} else
#endif
	{
		error = copyout(&remote->br_ptrace_eventmsg, umsgp,
		    sizeof (ulong_t));
	}

	return (error);
}

static int
lx_ptrace_getsiginfo(lx_lwp_data_t *remote, void *usiginfo)
{
	klwp_t *lwp = remote->br_lwp;
	int lx_sig;

	lx_sig = lx_stol_signo(lwp->lwp_cursig, 0);
	if (lx_sig < 1 || lwp->lwp_curinfo == NULL) {
		return (EINVAL);
	}

#if defined(_SYSCALL32_IMPL)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		if (stol_ksiginfo32_copyout(&lwp->lwp_curinfo->sq_info,
		    usiginfo) != 0) {
			return (EFAULT);
		}
	} else
#endif
	{
		if (stol_ksiginfo_copyout(&lwp->lwp_curinfo->sq_info,
		    usiginfo) != 0) {
			return (EFAULT);
		}
	}

	return (0);
}


/*
 * Implements the PTRACE_CONT subcommand of the Linux ptrace(2) interface.
 */
static int
lx_ptrace_cont(lx_lwp_data_t *remote, lx_ptrace_cont_flags_t flags, int signo)
{
	klwp_t *lwp = remote->br_lwp;

	if (flags & LX_PTC_SINGLESTEP) {
		/*
		 * We do not currently support single-stepping.
		 */
		lx_unsupported("PTRACE_SINGLESTEP not currently implemented");
		return (EINVAL);
	}

	/*
	 * The tracer may choose to suppress the delivery of a signal, or
	 * select an alternative signal for delivery.  If this is an
	 * appropriate ptrace(2) "signal-delivery-stop", br_ptrace_stopsig
	 * will be used as the new signal number.
	 *
	 * As with so many other aspects of the Linux ptrace(2) interface, this
	 * may fail silently if the state machine is not aligned correctly.
	 */
	remote->br_ptrace_stopsig = signo;
	remote->br_ptrace_donesig = 0;

	/*
	 * Handle the syscall-stop flag if this is a PTRACE_SYSCALL restart:
	 */
	if (flags & LX_PTC_SYSCALL) {
		remote->br_ptrace_flags |= LX_PTF_SYSCALL;
	} else {
		remote->br_ptrace_flags &= ~LX_PTF_SYSCALL;
	}

	lx_ptrace_restart_lwp(lwp);

	return (0);
}

/*
 * Implements the PTRACE_DETACH subcommand of the Linux ptrace(2) interface.
 *
 * The LWP identified by the Linux pid "lx_pid" will, if it as a tracee of the
 * current LWP, be detached and (optionally) set runnable.
 */
static void
lx_ptrace_detach(lx_ptrace_accord_t *accord, lx_lwp_data_t *remote, int signo,
    boolean_t restart)
{
	klwp_t *rlwp = remote->br_lwp;

	/*
	 * The tracee LWP was in "ptrace-stop" and we now hold its p_lock.
	 * Detach the LWP from the accord and set it running.
	 */
	VERIFY(!TRACEE_BUSY(remote));
	VERIFY(MUTEX_HELD(&accord->lxpa_tracees_lock));
	remote->br_ptrace_flags &= ~(LX_PTF_SYSCALL | LX_PTF_INHERIT);
	VERIFY(list_link_active(&remote->br_ptrace_linkage));
	list_remove(&accord->lxpa_tracees, remote);

	remote->br_ptrace_attach = LX_PTA_NONE;
	remote->br_ptrace_tracer = NULL;
	remote->br_ptrace_flags = 0;

	/*
	 * Decrement traced-lwp count for the process.
	 */
	ASSERT(MUTEX_HELD(&rlwp->lwp_procp->p_lock));
	VERIFY(ptolxproc(rlwp->lwp_procp)->l_ptrace-- >= 1);

	/*
	 * The tracer may, as described in lx_ptrace_cont(), choose to suppress
	 * or modify the delivered signal.
	 */
	remote->br_ptrace_stopsig = signo;
	remote->br_ptrace_donesig = 0;

	if (restart) {
		lx_ptrace_restart_lwp(rlwp);
	}
}

/*
 * This routine implements the PTRACE_ATTACH operation of the Linux ptrace(2)
 * interface.
 *
 * This LWP is requesting to be attached as a tracer to another LWP -- the
 * tracee.  If a ptrace accord to track the list of tracees has not yet been
 * allocated, one will be allocated and attached to this LWP now.
 *
 * The "br_ptrace_tracer" on the tracee LWP is set to this accord, and the
 * tracee LWP is then added to the "lxpa_tracees" list in the accord.  We drop
 * locks between these two phases; the only consumer of trace events from this
 * accord is this LWP, which obviously cannot be running waitpid(2) at the same
 * time as this call to ptrace(2).
 */
static int
lx_ptrace_attach(pid_t lx_pid)
{
	int error = ESRCH;
	/*
	 * Our (Tracer) LWP:
	 */
	lx_ptrace_accord_t *accord;
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	/*
	 * Remote (Tracee) LWP:
	 */
	proc_t *rproc;
	kthread_t *rthr;
	klwp_t *rlwp;
	lx_lwp_data_t *rlwpd;

	if (lwpd->br_pid == lx_pid) {
		/*
		 * We cannot trace ourselves.
		 */
		return (EPERM);
	}

	/*
	 * Ensure that we have an accord and obtain a lock on it.  This
	 * routine should not fail because the LWP cannot make ptrace(2) system
	 * calls after it has begun exiting.
	 */
	VERIFY0(lwpd->br_ptrace_flags & LX_PTF_EXITING);
	VERIFY(lx_ptrace_accord_get(&accord, B_TRUE) == 0);

	/*
	 * Place speculative hold in case the attach is successful.
	 */
	lx_ptrace_accord_hold(accord);
	lx_ptrace_accord_exit(accord);

	/*
	 * Locate the process containing the tracee LWP based on its Linux pid
	 * and lock it.
	 */
	if (lx_lpid_lock(lx_pid, curzone, PRLOCK, &rproc, &rthr) != 0) {
		/*
		 * We could not find the target process.
		 */
		goto errout;
	}

	/*
	 * Locate the tracee LWP.
	 */
	if ((rlwp = ttolwp(rthr)) == NULL ||
	    (rlwpd = lwptolxlwp(rlwp)) == NULL ||
	    !VISIBLE(rlwpd)) {
		/*
		 * The LWP could not be found, was not branded, or is not
		 * visible to ptrace(2) at this time.
		 */
		goto unlock_errout;
	}

	/*
	 * We now hold the lock on the tracee.  Attempt to install ourselves
	 * as the tracer.
	 */
	if (curproc != rproc && priv_proc_cred_perm(curproc->p_cred, rproc,
	    NULL, VWRITE) != 0) {
		/*
		 * This process does not have permission to trace the remote
		 * process.
		 */
		error = EPERM;
	} else if (rlwpd->br_ptrace_tracer != NULL) {
		/*
		 * This LWP is already being traced.
		 */
		VERIFY(list_link_active(&rlwpd->br_ptrace_linkage));
		VERIFY(rlwpd->br_ptrace_attach != LX_PTA_NONE);
		error = EPERM;
	} else {
		lx_proc_data_t *rprocd = ptolxproc(rproc);

		/*
		 * Bond the tracee to the accord.
		 */
		VERIFY0(rlwpd->br_ptrace_flags & LX_PTF_EXITING);
		VERIFY(rlwpd->br_ptrace_attach == LX_PTA_NONE);
		rlwpd->br_ptrace_attach = LX_PTA_ATTACH;
		rlwpd->br_ptrace_tracer = accord;

		/* Don't emit ptrace syscall-stop-exit event on kernel exit. */
		rlwpd->br_ptrace_flags |= LX_PTF_NOSTOP;

		/*
		 * We had no tracer, and are thus not in the tracees list.
		 * It is safe to take the tracee list lock while we insert
		 * ourselves.
		 */
		mutex_enter(&accord->lxpa_tracees_lock);
		VERIFY(!list_link_active(&rlwpd->br_ptrace_linkage));
		list_insert_tail(&accord->lxpa_tracees, rlwpd);
		/*
		 * Bump traced-lwp count for the remote process.
		 */
		rprocd->l_ptrace++;
		mutex_exit(&accord->lxpa_tracees_lock);

		/*
		 * Send a thread-directed SIGSTOP.
		 */
		sigtoproc(rproc, rthr, SIGSTOP);


		error = 0;
	}

unlock_errout:
	/*
	 * Unlock the process containing the tracee LWP and the accord.
	 */
	sprunlock(rproc);

errout:
	if (error != 0) {
		/*
		 * The attach was not successful.  Remove our speculative
		 * hold.
		 */
		lx_ptrace_accord_enter(accord);
		lx_ptrace_accord_rele(accord);
		lx_ptrace_accord_exit(accord);
	}

	return (error);
}

int
lx_ptrace_set_clone_inherit(int option, boolean_t inherit_flag)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

	switch (option) {
	case LX_PTRACE_O_TRACEFORK:
	case LX_PTRACE_O_TRACEVFORK:
	case LX_PTRACE_O_TRACECLONE:
		break;

	default:
		return (EINVAL);
	}

	mutex_enter(&p->p_lock);

	lwpd->br_ptrace_clone_option = option;

	if (inherit_flag) {
		lwpd->br_ptrace_flags |= LX_PTF_INHERIT;
	} else {
		lwpd->br_ptrace_flags &= ~LX_PTF_INHERIT;
	}

	mutex_exit(&p->p_lock);
	return (0);
}

/*
 * If the parent LWP is being traced, we want to attach ourselves to the
 * same accord.
 */
void
lx_ptrace_inherit_tracer(lx_lwp_data_t *src, lx_lwp_data_t *dst)
{
	proc_t *srcp = lwptoproc(src->br_lwp);
	proc_t *dstp = lwptoproc(dst->br_lwp);
	lx_ptrace_accord_t *accord;
	boolean_t is_fork = B_FALSE;

	VERIFY(MUTEX_HELD(&dstp->p_lock));
	if (srcp != dstp) {
		/*
		 * In the case of being called via forklwp, some lock shuffling
		 * is required.  The destination p_lock must be dropped to
		 * avoid deadlocks when locking the source and manipulating
		 * ptrace accord resources.
		 */
		is_fork = B_TRUE;
		sprlock_proc(dstp);
		mutex_exit(&dstp->p_lock);
		mutex_enter(&srcp->p_lock);
	}

	if ((accord = src->br_ptrace_tracer) == NULL) {
		/*
		 * The source LWP does not have a tracer to inherit.
		 */
		goto out;
	}

	/*
	 * There are two conditions to check when determining if the new
	 * child should inherit the same tracer (and tracing options) as its
	 * parent.  Either condition is sufficient to trigger inheritance.
	 */
	dst->br_ptrace_attach = LX_PTA_NONE;
	if ((src->br_ptrace_options & src->br_ptrace_clone_option) != 0) {
		/*
		 * Condition 1:
		 * The clone(2), fork(2) and vfork(2) emulated system calls
		 * populate "br_ptrace_clone_option" with the specific
		 * ptrace(2) SETOPTIONS option that applies to this
		 * operation.  If the relevant option has been enabled by the
		 * tracer then we inherit.
		 */
		dst->br_ptrace_attach |= LX_PTA_INHERIT_OPTIONS;

	} else if ((src->br_ptrace_flags & LX_PTF_INHERIT) != 0) {
		/*
		 * Condition 2:
		 * If the caller opted in to inheritance with the
		 * PTRACE_CLONE flag to clone(2), the LX_PTF_INHERIT flag
		 * will be set and we inherit.
		 */
		dst->br_ptrace_attach |= LX_PTA_INHERIT_CLONE;
	}

	/*
	 * These values only apply for the duration of a single clone(2), et
	 * al, system call.
	 */
	src->br_ptrace_flags &= ~LX_PTF_INHERIT;
	src->br_ptrace_clone_option = 0;

	if (dst->br_ptrace_attach == LX_PTA_NONE) {
		/*
		 * No condition triggered inheritance.
		 */
		goto out;
	}

	/*
	 * Set the LX_PTF_CLONING flag to prevent us from being detached
	 * while our p_lock is dropped.
	 */
	src->br_ptrace_flags |= LX_PTF_CLONING;
	mutex_exit(&srcp->p_lock);

	/*
	 * Hold the accord for the new LWP.
	 */
	lx_ptrace_accord_enter(accord);
	lx_ptrace_accord_hold(accord);
	lx_ptrace_accord_exit(accord);

	/*
	 * Install the tracer and copy the current PTRACE_SETOPTIONS options.
	 */
	dst->br_ptrace_tracer = accord;
	dst->br_ptrace_options = src->br_ptrace_options;

	/*
	 * This flag prevents waitid() from seeing events for the new child
	 * until the parent is able to post the relevant ptrace event to
	 * the tracer.
	 */
	dst->br_ptrace_flags |= LX_PTF_PARENT_WAIT;

	mutex_enter(&accord->lxpa_tracees_lock);
	VERIFY(list_link_active(&src->br_ptrace_linkage));
	VERIFY(!list_link_active(&dst->br_ptrace_linkage));
	list_insert_tail(&accord->lxpa_tracees, dst);
	mutex_exit(&accord->lxpa_tracees_lock);

	/*
	 * Relock our process and clear our busy flag.
	 */
	mutex_enter(&srcp->p_lock);
	src->br_ptrace_flags &= ~LX_PTF_CLONING;

	/*
	 * Bump traced-lwp count for the process.
	 */
	ptolxproc(dstp)->l_ptrace++;

	/*
	 * If lx_ptrace_exit_tracer() is trying to detach our tracer, it will
	 * be sleeping on this CV until LX_PTF_CLONING is clear.  Wake it
	 * now.
	 */
	cv_broadcast(&lx_ptrace_busy_cv);

out:
	if (is_fork) {
		mutex_exit(&srcp->p_lock);
		mutex_enter(&dstp->p_lock);
		sprunprlock(dstp);
	}
}

static int
lx_ptrace_traceme(void)
{
	int error;
	boolean_t did_attach = B_FALSE;
	/*
	 * Our (Tracee) LWP:
	 */
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	/*
	 * Remote (Tracer) LWP:
	 */
	lx_ptrace_accord_t *accord;

	/*
	 * We are intending to be the tracee.  Fetch (or allocate) the accord
	 * for our parent LWP.
	 */
	if ((error = lx_ptrace_accord_get_by_pid(lx_lwp_ppid(lwp, NULL,
	    NULL), &accord)) != 0) {
		/*
		 * Could not determine the Linux pid of the parent LWP, or
		 * could not get the accord for that LWP.
		 */
		return (error);
	}

	/*
	 * We now hold the accord lock.
	 */
	if (accord->lxpa_flags & LX_ACC_TOMBSTONE) {
		/*
		 * The accord is marked for death; give up now.
		 */
		lx_ptrace_accord_exit(accord);
		return (ESRCH);
	}

	/*
	 * Bump the reference count so that the accord is not freed.  We need
	 * to drop the accord lock before we take our own p_lock.
	 */
	lx_ptrace_accord_hold(accord);
	lx_ptrace_accord_exit(accord);

	/*
	 * We now lock _our_ process and determine if we can install our parent
	 * as our tracer.
	 */
	mutex_enter(&p->p_lock);
	if (lwpd->br_ptrace_tracer != NULL) {
		/*
		 * This LWP is already being traced.
		 */
		VERIFY(lwpd->br_ptrace_attach != LX_PTA_NONE);
		error = EPERM;
	} else {
		/*
		 * Bond ourselves to the accord.  We already bumped the accord
		 * reference count.
		 */
		VERIFY(lwpd->br_ptrace_attach == LX_PTA_NONE);
		lwpd->br_ptrace_attach = LX_PTA_TRACEME;
		lwpd->br_ptrace_tracer = accord;
		did_attach = B_TRUE;
		error = 0;

		/*
		 * Speculatively bump l_ptrace now before dropping p_lock.
		 * It will be reverted if the tracee attachment fails.
		 */
		ptolxproc(p)->l_ptrace++;
	}
	mutex_exit(&p->p_lock);

	/*
	 * Lock the accord tracee list and add this LWP.  Once we are in the
	 * tracee list, it is the responsibility of the tracer to detach us.
	 */
	if (error == 0) {
		lx_ptrace_accord_enter(accord);
		mutex_enter(&accord->lxpa_tracees_lock);

		if (!(accord->lxpa_flags & LX_ACC_TOMBSTONE)) {
			/*
			 * Put ourselves in the tracee list for this accord.
			 */
			VERIFY(!list_link_active(&lwpd->br_ptrace_linkage));
			list_insert_tail(&accord->lxpa_tracees, lwpd);
			mutex_exit(&accord->lxpa_tracees_lock);
			lx_ptrace_accord_exit(accord);

			return (0);
		}
		mutex_exit(&accord->lxpa_tracees_lock);

		/*
		 * The accord has been marked for death.  We must
		 * untrace ourselves.
		 */
		error = ESRCH;
		lx_ptrace_accord_exit(accord);

		/*
		 * Undo speculative increment of ptracer count.
		 */
		mutex_enter(&p->p_lock);
		ptolxproc(p)->l_ptrace--;
		mutex_exit(&p->p_lock);
	}

	/*
	 * Our optimism was unjustified: We were unable to attach.  We need to
	 * lock the process containing this LWP again in order to remove the
	 * tracer.
	 */
	VERIFY(error != 0);
	mutex_enter(&p->p_lock);
	if (did_attach) {
		/*
		 * Verify that things were as we left them:
		 */
		VERIFY(!list_link_active(&lwpd->br_ptrace_linkage));
		VERIFY(lwpd->br_ptrace_tracer == accord);

		lwpd->br_ptrace_attach = LX_PTA_NONE;
		lwpd->br_ptrace_tracer = NULL;
	}
	mutex_exit(&p->p_lock);

	/*
	 * Remove our speculative hold on the accord, possibly causing it to be
	 * freed in the process.
	 */
	lx_ptrace_accord_enter(accord);
	lx_ptrace_accord_rele(accord);
	lx_ptrace_accord_exit(accord);

	return (error);
}

static boolean_t
lx_ptrace_stop_common(proc_t *p, lx_lwp_data_t *lwpd, ushort_t what)
{
	boolean_t reset_nostop = B_FALSE;

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * Mark this LWP as stopping and call stop() to enter "ptrace-stop".
	 */
	VERIFY0(lwpd->br_ptrace_flags & LX_PTF_STOPPING);
	lwpd->br_ptrace_flags |= LX_PTF_STOPPING;

	if (lwpd->br_lwp->lwp_nostop == 1 &&
	    lwpd->br_ptrace_event == LX_PTRACE_EVENT_EXEC) {
		/* We need to clear this to get the signal delivered. */
		lwpd->br_lwp->lwp_nostop = 0;
		reset_nostop = B_TRUE;
	}

	stop(PR_BRAND, what);

	if (reset_nostop) {
		VERIFY(lwpd->br_lwp->lwp_nostop == 0);
		lwpd->br_lwp->lwp_nostop = 1;
	}

	/*
	 * We are back from "ptrace-stop" with our process lock held.
	 */
	lwpd->br_ptrace_flags &= ~(LX_PTF_STOPPING | LX_PTF_STOPPED |
	    LX_PTF_CLDPEND);
	lwpd->br_ptrace_stopucp = NULL;
	cv_broadcast(&lx_ptrace_busy_cv);
	mutex_exit(&p->p_lock);

	return (B_TRUE);
}

int
lx_ptrace_stop_for_option(int option, boolean_t child, ulong_t msg,
    uintptr_t ucp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

	mutex_enter(&p->p_lock);
	if (lwpd->br_ptrace_tracer == NULL) {
		mutex_exit(&p->p_lock);
		return (ESRCH);
	}

	if (!child) {
		/*
		 * Only the first event posted by a new process is to be held
		 * until the matching parent event is dispatched, and only if
		 * it is a "child" event.  This is not a child event, so we
		 * clear the wait flag.
		 */
		lwpd->br_ptrace_flags &= ~LX_PTF_PARENT_WAIT;

	} else if (option == LX_PTRACE_O_TRACEVFORK) {
		/*
		 * For a child, we have to handle vfork as a special case. In
		 * lx_ptrace_inherit_tracer() we set LX_PTF_PARENT_WAIT to
		 * force events to be delayed until the parent posts its event.
		 * This flag is cleared in lx_waitid_helper() to enforce a
		 * "happens after" relationship. However, this obviously cannot
		 * work for the vfork case. Thus, we clear our flag now so that
		 * we can deliver the signal in lx_stop_notify(), if necessary.
		 */
		lwpd->br_ptrace_flags &= ~LX_PTF_PARENT_WAIT;
	}

	if (!(lwpd->br_ptrace_options & option)) {
		if (option == LX_PTRACE_O_TRACEEXEC) {
			/*
			 * Without PTRACE_O_TRACEEXEC, the Linux kernel will
			 * send SIGTRAP to the process.
			 */
			sigtoproc(p, t, SIGTRAP);
			mutex_exit(&p->p_lock);
			return (0);
		}

		/*
		 * The flag for this trace event is not enabled, so we will not
		 * stop.
		 */
		mutex_exit(&p->p_lock);
		return (ESRCH);
	}

	if (child) {
		switch (option) {
		case LX_PTRACE_O_TRACECLONE:
		case LX_PTRACE_O_TRACEFORK:
		case LX_PTRACE_O_TRACEVFORK:
			/*
			 * Send the child LWP a directed SIGSTOP.
			 */
			sigtoproc(p, t, SIGSTOP);
			mutex_exit(&p->p_lock);
			return (0);
		default:
			goto nostop;
		}
	}

	lwpd->br_ptrace_eventmsg = msg;

	switch (option) {
	case LX_PTRACE_O_TRACECLONE:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_CLONE;
		break;
	case LX_PTRACE_O_TRACEEXEC:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_EXEC;
		lwpd->br_ptrace_eventmsg = 0;
		break;
	case LX_PTRACE_O_TRACEEXIT:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_EXIT;
		break;
	case LX_PTRACE_O_TRACEFORK:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_FORK;
		break;
	case LX_PTRACE_O_TRACEVFORK:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_VFORK;
		break;
	case LX_PTRACE_O_TRACEVFORKDONE:
		lwpd->br_ptrace_event = LX_PTRACE_EVENT_VFORK_DONE;
		lwpd->br_ptrace_eventmsg = 0;
		break;
	default:
		goto nostop;
	}

	/*
	 * Userland may have passed in a ucontext_t pointer for
	 * PTRACE_GETREGS/PTRACE_SETREGS usage while stopped.
	 */
	lwpd->br_ptrace_stopucp = ucp;

	/*
	 * p_lock for the process containing the tracee will be dropped by
	 * lx_ptrace_stop_common().
	 */
	return (lx_ptrace_stop_common(p, lwpd, LX_PR_EVENT) ? 0 : ESRCH);

nostop:
	lwpd->br_ptrace_event = 0;
	lwpd->br_ptrace_eventmsg = 0;
	mutex_exit(&p->p_lock);
	return (ESRCH);
}

boolean_t
lx_ptrace_stop(ushort_t what)
{
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);

	VERIFY(what == LX_PR_SYSENTRY || what == LX_PR_SYSEXIT ||
	    what == LX_PR_SIGNALLED);

	/*
	 * If we do not have an accord, bail out early.
	 */
	if (lwpd->br_ptrace_tracer == NULL)
		return (B_FALSE);

	/*
	 * Lock this process and re-check the condition.
	 */
	mutex_enter(&p->p_lock);

	/*
	 * The child after a fork/clone doesn't emit syscall-exit-stop event.
	 */
	if (what == LX_PR_SYSEXIT && (lwpd->br_ptrace_flags & LX_PTF_NOSTOP)) {
		lwpd->br_ptrace_flags &= ~LX_PTF_NOSTOP;
		mutex_exit(&p->p_lock);
		return (B_FALSE);
	}

	if (lwpd->br_ptrace_tracer == NULL) {
		VERIFY0(lwpd->br_ptrace_flags & LX_PTF_SYSCALL);
		mutex_exit(&p->p_lock);
		return (B_FALSE);
	}

	if (what == LX_PR_SYSENTRY || what == LX_PR_SYSEXIT) {
		if (what == LX_PR_SYSENTRY) {
			lwpd->br_ptrace_flags |= LX_PTF_INSYSCALL;
		} else {
			lwpd->br_ptrace_flags &= ~LX_PTF_INSYSCALL;
		}

		/*
		 * This is a syscall-entry-stop or syscall-exit-stop point.
		 */
		if (!(lwpd->br_ptrace_flags & LX_PTF_SYSCALL)) {
			/*
			 * A system call stop has not been requested.
			 */
			mutex_exit(&p->p_lock);
			return (B_FALSE);
		}

		/*
		 * The PTRACE_SYSCALL restart command applies only to the next
		 * system call entry or exit.  The tracer must restart us with
		 * PTRACE_SYSCALL while we are in ptrace-stop for us to fire
		 * again at the next system call boundary.
		 */
		lwpd->br_ptrace_flags &= ~LX_PTF_SYSCALL;
	}

	/*
	 * p_lock for the process containing the tracee will be dropped by
	 * lx_ptrace_stop_common().
	 */
	return (lx_ptrace_stop_common(p, lwpd, what));
}

int
lx_ptrace_issig_stop(proc_t *p, klwp_t *lwp)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	int lx_sig;

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * In very rare circumstances, a process which is almost completely
	 * through proc_exit() may incur issig checks in the current thread via
	 * clean-up actions.  The process will still be branded, but the thread
	 * will have already been stripped of any LX-specific data on its way
	 * to the grave.  Bail early if the brand data is missing.
	 */
	if (lwpd == NULL) {
		return (0);
	}

	/*
	 * If we do not have an accord, bail out now.  Additionally, if there
	 * is no valid signal then we have no reason to stop.
	 */
	if (lwpd->br_ptrace_tracer == NULL || lwp->lwp_cursig == SIGKILL ||
	    (lwp->lwp_cursig == 0 || lwp->lwp_cursig > NSIG) ||
	    (lx_sig = stol_signo[lwp->lwp_cursig]) < 1) {
		if (lwp->lwp_cursig == 0) {
			/*
			 * If this lwp has no current signal, it means that any
			 * signal ignorance enabled by br_ptrace_donesig has
			 * already taken place (the signal was consumed).
			 * By clearing donesig, we declare desire to ignore no
			 * signals for accurate ptracing.
			 */
			lwpd->br_ptrace_donesig = 0;
		}
		return (0);
	}

	/*
	 * We can't deliver the signal-delivery-stop condition while we're
	 * between the syscall-enter-stop and syscall-exit-stop conditions.
	 * We must first let the signal interrupt the in-progress syscall, let
	 * it emit syscall-exit-stop with the interrupted result, then we'll
	 * come back here to emit signal-delivery-stop.
	 */
	if (lwpd->br_ptrace_flags & LX_PTF_INSYSCALL) {
		return (0);
	}

	/*
	 * We stash the signal on the LWP where our waitid_helper will find it
	 * and enter the ptrace "signal-delivery-stop" condition.
	 */
	lwpd->br_ptrace_stopsig = lx_sig;
	lwpd->br_ptrace_donesig = 0;
	(void) lx_ptrace_stop_common(p, lwpd, LX_PR_SIGNALLED);
	mutex_enter(&p->p_lock);

	/*
	 * When we return, the signal may have been altered or suppressed.
	 */
	if (lwpd->br_ptrace_stopsig != lx_sig) {
		int native_sig;
		lx_sig = lwpd->br_ptrace_stopsig;

		if (lx_sig >= LX_NSIG) {
			lx_sig = 0;
		}

		/*
		 * Translate signal from Linux signal number back to
		 * an illumos native signal.
		 */
		if (lx_sig >= LX_NSIG || lx_sig < 0 || (native_sig =
		    ltos_signo[lx_sig]) < 1) {
			/*
			 * The signal is not deliverable.
			 */
			lwp->lwp_cursig = 0;
			lwp->lwp_extsig = 0;
			if (lwp->lwp_curinfo) {
				siginfofree(lwp->lwp_curinfo);
				lwp->lwp_curinfo = NULL;
			}
		} else {
			/*
			 * Alter the currently dispatching signal.
			 */
			if (native_sig == SIGKILL) {
				/*
				 * We mark ourselves the victim and request
				 * a restart of signal processing.
				 */
				p->p_flag |= SKILLED;
				p->p_flag &= ~SEXTKILLED;
				return (-1);
			}
			lwp->lwp_cursig = native_sig;
			lwp->lwp_extsig = 0;
			if (lwp->lwp_curinfo != NULL) {
				lwp->lwp_curinfo->sq_info.si_signo = native_sig;
			}
		}
	}

	lwpd->br_ptrace_donesig = lwp->lwp_cursig;
	lwpd->br_ptrace_stopsig = 0;
	return (0);
}

boolean_t
lx_ptrace_sig_ignorable(proc_t *p, klwp_t *lwp, int sig)
{
	lx_proc_data_t *lxpd = ptolxproc(p);

	/*
	 * Ignored signals and ptrace:
	 *
	 * When a process is being ptraced by another, special care is needed
	 * while handling signals.  Since the tracer is interested in all
	 * signals sent to the tracee, an effort must be made to initially
	 * bypass signal ignorance logic.  This allows the signal to be placed
	 * in the tracee's sigqueue to be inspected and potentially altered by
	 * the tracer.
	 *
	 * A critical detail in this procedure is how a signal is handled after
	 * tracer has completed processing for the event.  If the signal would
	 * have been ignored, were it not for the initial ptrace override, then
	 * lx_ptrace_sig_ignorable must report B_TRUE when the tracee is
	 * restarted and resumes signal processing.  This is done by recording
	 * the most recent tracee signal consumed by ptrace.
	 */

	if (lxpd->l_ptrace != 0 && lx_stol_signo(sig, 0) != 0) {
		/*
		 * This process is being ptraced.  Bypass signal ignorance for
		 * anything that maps to a valid Linux signal...
		 */
		if (lwp != NULL && lwptolxlwp(lwp)->br_ptrace_donesig == sig) {
			/*
			 * ...Unless it is a signal which has already been
			 * processed by the tracer.
			 */
			return (B_TRUE);
		}
		return (B_FALSE);
	}
	return (B_TRUE);
}

static void
lx_ptrace_exit_tracer(proc_t *p, lx_lwp_data_t *lwpd,
    lx_ptrace_accord_t *accord)
{
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	lx_ptrace_accord_enter(accord);
	/*
	 * Mark this accord for death.  This means no new tracees can be
	 * attached to this accord.
	 */
	VERIFY0(accord->lxpa_flags & LX_ACC_TOMBSTONE);
	accord->lxpa_flags |= LX_ACC_TOMBSTONE;
	lx_ptrace_accord_exit(accord);

	/*
	 * Walk the list of tracees, detaching them and setting them runnable
	 * if they are stopped.
	 */
	for (;;) {
		klwp_t *rlwp;
		proc_t *rproc;
		lx_lwp_data_t *remote;
		kmutex_t *rmp;

		mutex_enter(&accord->lxpa_tracees_lock);
		if (list_is_empty(&accord->lxpa_tracees)) {
			mutex_exit(&accord->lxpa_tracees_lock);
			break;
		}

		/*
		 * Fetch the first tracee LWP in the list and lock the process
		 * which contains it.
		 */
		remote = list_head(&accord->lxpa_tracees);
		rlwp = remote->br_lwp;
		rproc = lwptoproc(rlwp);
		/*
		 * The p_lock mutex persists beyond the life of the process
		 * itself.  We save the address, here, to prevent the need to
		 * dereference the proc_t after awaking from sleep.
		 */
		rmp = &rproc->p_lock;
		mutex_enter(rmp);

		if (TRACEE_BUSY(remote)) {
			/*
			 * This LWP is currently detaching itself on exit, or
			 * mid-way through stop().  We must wait for this
			 * action to be completed.  While we wait on the CV, we
			 * must drop the accord tracee list lock.
			 */
			mutex_exit(&accord->lxpa_tracees_lock);
			cv_wait(&lx_ptrace_busy_cv, rmp);

			/*
			 * While we were waiting, some state may have changed.
			 * Restart the walk to be sure we don't miss anything.
			 */
			mutex_exit(rmp);
			continue;
		}

		/*
		 * We now hold p_lock on the process.  Remove the tracee from
		 * the list.
		 */
		VERIFY(list_link_active(&remote->br_ptrace_linkage));
		list_remove(&accord->lxpa_tracees, remote);

		/*
		 * Unlink the accord and clear our trace flags.
		 */
		remote->br_ptrace_attach = LX_PTA_NONE;
		remote->br_ptrace_tracer = NULL;
		remote->br_ptrace_flags = 0;

		/*
		 * Let go of the list lock before we restart the LWP.  We must
		 * not hold any locks other than the process p_lock when
		 * we call lx_ptrace_restart_lwp() as it will thread_lock
		 * the tracee.
		 */
		mutex_exit(&accord->lxpa_tracees_lock);

		/*
		 * Decrement traced-lwp count for the remote process.
		 */
		VERIFY(ptolxproc(rproc)->l_ptrace-- >= 1);

		/*
		 * Ensure that the LWP is not stopped on our account.
		 */
		lx_ptrace_restart_lwp(rlwp);

		/*
		 * Unlock the former tracee.
		 */
		mutex_exit(rmp);

		/*
		 * Drop the hold this tracee had on the accord.
		 */
		lx_ptrace_accord_enter(accord);
		lx_ptrace_accord_rele(accord);
		lx_ptrace_accord_exit(accord);
	}

	mutex_enter(&p->p_lock);
	lwpd->br_ptrace_accord = NULL;
	mutex_exit(&p->p_lock);

	/*
	 * Clean up and release our hold on the accord If we completely
	 * detached all tracee LWPs, this will free the accord.  Otherwise, it
	 * will be freed when they complete their cleanup.
	 *
	 * We hold "pidlock" while clearing these members for easy exclusion of
	 * waitid(), etc.
	 */
	mutex_enter(&pidlock);
	lx_ptrace_accord_enter(accord);
	accord->lxpa_cvp = NULL;
	accord->lxpa_tracer = NULL;
	mutex_exit(&pidlock);
	lx_ptrace_accord_rele(accord);
	lx_ptrace_accord_exit(accord);
}

static void
lx_ptrace_exit_tracee(proc_t *p, lx_lwp_data_t *lwpd,
    lx_ptrace_accord_t *accord)
{
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * We are the tracee LWP.  Lock the accord tracee list and then our
	 * containing process.
	 */
	mutex_enter(&accord->lxpa_tracees_lock);
	mutex_enter(&p->p_lock);

	/*
	 * Remove our reference to the accord.  We will release our hold
	 * later.
	 */
	VERIFY(lwpd->br_ptrace_tracer == accord);
	lwpd->br_ptrace_attach = LX_PTA_NONE;
	lwpd->br_ptrace_tracer = NULL;

	/*
	 * Remove this LWP from the accord tracee list:
	 */
	VERIFY(list_link_active(&lwpd->br_ptrace_linkage));
	list_remove(&accord->lxpa_tracees, lwpd);

	/*
	 * Wake up any tracers waiting for us to detach from the accord.
	 */
	cv_broadcast(&lx_ptrace_busy_cv);

	/*
	 * Decrement traced-lwp count for the process.
	 */
	VERIFY(ptolxproc(p)->l_ptrace-- >= 1);

	mutex_exit(&p->p_lock);
	mutex_exit(&accord->lxpa_tracees_lock);

	/*
	 * Grab "pidlock" and wake the tracer if it is blocked in waitid().
	 */
	mutex_enter(&pidlock);
	if (accord->lxpa_cvp != NULL) {
		cv_broadcast(accord->lxpa_cvp);
	}
	mutex_exit(&pidlock);

	/*
	 * Release our hold on the accord.
	 */
	lx_ptrace_accord_enter(accord);
	lx_ptrace_accord_rele(accord);
	lx_ptrace_accord_exit(accord);
}

/*
 * This routine is called from lx_exitlwp() when an LWP is ready to exit.  If
 * this LWP is being traced, it will be detached from the tracer's accord.  The
 * routine will also detach any LWPs being traced by this LWP.
 */
void
lx_ptrace_exit(proc_t *p, klwp_t *lwp)
{
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;

	VERIFY(MUTEX_HELD(&p->p_lock));

	/*
	 * Mark our LWP as exiting from a ptrace perspective.  This will
	 * prevent a new accord from being allocated if one does not exist
	 * already, and will make us invisible to PTRACE_ATTACH/PTRACE_TRACEME.
	 */
	VERIFY0(lwpd->br_ptrace_flags & LX_PTF_EXITING);
	lwpd->br_ptrace_flags |= LX_PTF_EXITING;

	if ((accord = lwpd->br_ptrace_tracer) != NULL) {
		/*
		 * We are traced by another LWP and must detach ourselves.
		 */
		mutex_exit(&p->p_lock);
		lx_ptrace_exit_tracee(p, lwpd, accord);
		mutex_enter(&p->p_lock);
	}

	if ((accord = lwpd->br_ptrace_accord) != NULL) {
		/*
		 * We have been tracing other LWPs, and must detach from
		 * them and clean up our accord.
		 */
		mutex_exit(&p->p_lock);
		lx_ptrace_exit_tracer(p, lwpd, accord);
		mutex_enter(&p->p_lock);
	}
}

/*
 * Called when a SIGCLD signal is dispatched so that we may enqueue another.
 * Return 0 if we enqueued a signal, or -1 if not.
 */
int
lx_sigcld_repost(proc_t *pp, sigqueue_t *sqp)
{
	klwp_t *lwp = ttolwp(curthread);
	lx_lwp_data_t *lwpd = lwptolxlwp(lwp);
	lx_ptrace_accord_t *accord;
	lx_lwp_data_t *remote;
	klwp_t *rlwp;
	proc_t *rproc;
	boolean_t found = B_FALSE;

	VERIFY(MUTEX_HELD(&pidlock));
	VERIFY(MUTEX_NOT_HELD(&pp->p_lock));
	VERIFY(lwptoproc(lwp) == pp);

	mutex_enter(&pp->p_lock);
	if ((accord = lwpd->br_ptrace_accord) == NULL) {
		/*
		 * This LWP is not a tracer LWP, so there will be no
		 * SIGCLD.
		 */
		mutex_exit(&pp->p_lock);
		return (-1);
	}
	mutex_exit(&pp->p_lock);

	mutex_enter(&accord->lxpa_tracees_lock);
	for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
	    remote = list_next(&accord->lxpa_tracees, remote)) {
		rlwp = remote->br_lwp;
		rproc = lwptoproc(rlwp);

		/*
		 * Check if this LWP is in "ptrace-stop".  If in the correct
		 * stop condition, lock the process containing the tracee LWP.
		 */
		if (lx_ptrace_lock_if_stopped(accord, remote, B_FALSE) != 0) {
			continue;
		}

		if (remote->br_ptrace_flags & LX_PTF_PARENT_WAIT) {
			/*
			 * This event depends on waitid() clearing out the
			 * event of another LWP.  Skip it for now.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		if (!(remote->br_ptrace_flags & LX_PTF_CLDPEND)) {
			/*
			 * No SIGCLD is required for this LWP.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		if (!(remote->br_ptrace_flags & LX_PTF_WAITPEND) ||
		    remote->br_ptrace_whystop == 0 ||
		    remote->br_ptrace_whatstop == 0) {
			/*
			 * No (new) stop reason to post for this LWP.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		/*
		 * We found a process of interest.  Leave the process
		 * containing the tracee LWP locked and break out of the loop.
		 */
		found = B_TRUE;
		break;
	}
	mutex_exit(&accord->lxpa_tracees_lock);

	if (!found) {
		return (-1);
	}

	/*
	 * Generate siginfo for this tracee LWP.
	 */
	lx_ptrace_winfo(remote, &sqp->sq_info, B_FALSE, NULL, NULL);
	remote->br_ptrace_flags &= ~LX_PTF_CLDPEND;
	mutex_exit(&rproc->p_lock);

	mutex_enter(&pp->p_lock);
	if (sigismember(&pp->p_sig, SIGCLD)) {
		mutex_exit(&pp->p_lock);

		mutex_enter(&rproc->p_lock);
		remote->br_ptrace_flags |= LX_PTF_CLDPEND;
		mutex_exit(&rproc->p_lock);

		return (-1);
	}
	sigaddqa(pp, curthread, sqp);
	mutex_exit(&pp->p_lock);

	return (0);
}

/*
 * Consume the next available ptrace(2) event queued against the accord for
 * this LWP.  The event will be emitted as if through waitid(), and converted
 * by lx_waitpid() and friends before the return to usermode.
 */
int
lx_waitid_helper(idtype_t idtype, id_t id, k_siginfo_t *ip, int options,
    boolean_t *brand_wants_wait, int *rval)
{
	lx_ptrace_accord_t *accord;
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = lwptoproc(lwp);
	lx_lwp_data_t *local = lwptolxlwp(lwp);
	lx_lwp_data_t *remote;
	boolean_t found = B_FALSE;
	klwp_t *rlwp = NULL;
	proc_t *rproc = NULL;
	pid_t event_pid = 0, event_ppid = 0;
	boolean_t waitflag = !(options & WNOWAIT);
	boolean_t target_found = B_FALSE;

	VERIFY(MUTEX_HELD(&pidlock));
	VERIFY(MUTEX_NOT_HELD(&p->p_lock));

	/*
	 * By default, we do not expect waitid() to block on our account.
	 */
	*brand_wants_wait = B_FALSE;

	if (!local->br_waitid_emulate) {
		/*
		 * This waitid() call is not expecting emulated results.
		 */
		return (-1);
	}

	switch (idtype) {
	case P_ALL:
	case P_PID:
	case P_PGID:
		break;
	default:
		/*
		 * This idtype has no power here.
		 */
		return (-1);
	}

	if (lx_ptrace_accord_get(&accord, B_FALSE) != 0) {
		/*
		 * This LWP does not have an accord; it cannot be tracing.
		 */
		return (-1);
	}

	/*
	 * We do not need an additional hold on the accord as it belongs to
	 * the running, tracer, LWP.
	 */
	lx_ptrace_accord_exit(accord);

	mutex_enter(&accord->lxpa_tracees_lock);
	if (list_is_empty(&accord->lxpa_tracees)) {
		/*
		 * Though it has an accord, there are currently no tracees in
		 * the list for this LWP.
		 */
		mutex_exit(&accord->lxpa_tracees_lock);
		return (-1);
	}

	/*
	 * Walk the list of tracees and determine if any of them have events to
	 * report.
	 */
	for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
	    remote = list_next(&accord->lxpa_tracees, remote)) {
		rlwp = remote->br_lwp;
		rproc = lwptoproc(rlwp);

		/*
		 * We check to see if this LWP matches an id we are waiting for.
		 */
		switch (idtype) {
		case P_ALL:
			break;
		case P_PID:
			if (remote->br_pid != id)
				continue;
			break;
		case P_PGID:
			if (rproc->p_pgrp != id)
				continue;
			break;
		default:
			cmn_err(CE_PANIC, "unexpected idtype: %d", idtype);
		}

		/* This tracee matches provided idtype and id */
		target_found = B_TRUE;

		/*
		 * Check if this LWP is in "ptrace-stop".  If in the correct
		 * stop condition, lock the process containing the tracee LWP.
		 */
		if (lx_ptrace_lock_if_stopped(accord, remote, B_FALSE) != 0) {
			continue;
		}

		if (remote->br_ptrace_flags & LX_PTF_PARENT_WAIT) {
			/*
			 * This event depends on waitid() clearing out the
			 * event of another LWP.  Skip it for now.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		if (!(remote->br_ptrace_flags & LX_PTF_WAITPEND) ||
		    remote->br_ptrace_whystop == 0 ||
		    remote->br_ptrace_whatstop == 0) {
			/*
			 * No (new) stop reason to post for this LWP.
			 */
			mutex_exit(&rproc->p_lock);
			continue;
		}

		/*
		 * We found a process of interest.  Leave the process
		 * containing the tracee LWP locked and break out of the loop.
		 */
		found = B_TRUE;
		break;
	}
	mutex_exit(&accord->lxpa_tracees_lock);

	if (!found) {
		/*
		 * There were no events of interest, but we have tracees.
		 * If any of the tracees matched the spcified criteria, signal
		 * to waitid() that it should block if the provided flags allow
		 * for it.
		 */
		if (target_found) {
			*brand_wants_wait = B_TRUE;
		}

		return (-1);
	}

	/*
	 * Populate the signal information.
	 */
	lx_ptrace_winfo(remote, ip, waitflag, &event_ppid, &event_pid);

	/*
	 * Unlock the tracee.
	 */
	mutex_exit(&rproc->p_lock);

	if (event_pid != 0 && event_ppid != 0) {
		/*
		 * We need to do another pass around the tracee list and
		 * unblock any events that have a "happens after" relationship
		 * with this event.
		 */
		mutex_enter(&accord->lxpa_tracees_lock);
		for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
		    remote = list_next(&accord->lxpa_tracees, remote)) {
			rlwp = remote->br_lwp;
			rproc = lwptoproc(rlwp);

			mutex_enter(&rproc->p_lock);

			if (remote->br_pid != event_pid ||
			    remote->br_ppid != event_ppid) {
				mutex_exit(&rproc->p_lock);
				continue;
			}

			remote->br_ptrace_flags &= ~LX_PTF_PARENT_WAIT;

			mutex_exit(&rproc->p_lock);
		}
		mutex_exit(&accord->lxpa_tracees_lock);
	}

	/*
	 * If we are consuming this wait state, we remove the SIGCLD from
	 * the queue and post another.
	 */
	if (waitflag) {
		mutex_exit(&pidlock);
		sigcld_delete(ip);
		sigcld_repost();
		mutex_enter(&pidlock);
	}

	*rval = 0;
	return (0);
}

static int
lx_ptrace_peek(lx_lwp_data_t *lwpd, uintptr_t addr, void *data)
{
	proc_t *p = lwptoproc(lwpd->br_lwp);
	long buf;
	int error = 0, size = sizeof (buf);

#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		size = sizeof (uint32_t);
	}
#endif
	if ((addr & (size - 1)) != 0) {
		/* unaligned access */
		return (EINVAL);
	}

	mutex_exit(&p->p_lock);
	error = uread(p, &buf, size, addr);
	mutex_enter(&p->p_lock);

	if (error != 0) {
		return (EIO);
	}
	if (copyout(&buf, data, size) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
lx_ptrace_poke(lx_lwp_data_t *lwpd, uintptr_t addr, uintptr_t data)
{
	proc_t *p = lwptoproc(lwpd->br_lwp);
	int error = 0, size = sizeof (data);

#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		size = sizeof (uint32_t);
	}
#endif
	if ((addr & (size - 1)) != 0) {
		/* unaligned access */
		return (EINVAL);
	}

	mutex_exit(&p->p_lock);
	error = uwrite(p, &data, size, addr);
	mutex_enter(&p->p_lock);

	if (error != 0) {
		return (EIO);
	}
	return (0);
}

static int
lx_ptrace_kill(lx_lwp_data_t *lwpd)
{
	sigtoproc(lwptoproc(lwpd->br_lwp), NULL, SIGKILL);

	return (0);
}

static int
lx_ptrace_kernel(int ptrace_op, pid_t lxpid, uintptr_t addr, uintptr_t data)
{
	lx_lwp_data_t *local = ttolxlwp(curthread);
	lx_ptrace_accord_t *accord;
	lx_lwp_data_t *remote;
	klwp_t *rlwp;
	proc_t *rproc;
	int error;
	boolean_t found = B_FALSE, restart = B_TRUE;

	/*
	 * PTRACE_TRACEME and PTRACE_ATTACH operations induce the tracing of
	 * one LWP by another.  The target LWP must not be traced already.
	 */
	switch (ptrace_op) {
	case LX_PTRACE_TRACEME:
		return (lx_ptrace_traceme());

	case LX_PTRACE_ATTACH:
		return (lx_ptrace_attach(lxpid));
	}

	/*
	 * Ensure that we have an accord and obtain a lock on it.  This routine
	 * should not fail because the LWP cannot make ptrace(2) system calls
	 * after it has begun exiting.
	 */
	VERIFY0(local->br_ptrace_flags & LX_PTF_EXITING);
	VERIFY(lx_ptrace_accord_get(&accord, B_TRUE) == 0);

	/*
	 * The accord belongs to this (the tracer) LWP, and we have a hold on
	 * it.  We drop the lock so that we can take other locks.
	 */
	lx_ptrace_accord_exit(accord);

	/*
	 * Does the tracee list contain the pid in question?
	 */
	mutex_enter(&accord->lxpa_tracees_lock);
	for (remote = list_head(&accord->lxpa_tracees); remote != NULL;
	    remote = list_next(&accord->lxpa_tracees, remote)) {
		if (remote->br_pid == lxpid) {
			found = B_TRUE;
			break;
		}
	}
	if (!found) {
		/*
		 * The requested pid does not appear in the tracee list.
		 */
		mutex_exit(&accord->lxpa_tracees_lock);
		return (ESRCH);
	}

	if (ptrace_op == LX_PTRACE_DETACH) {
		/*
		 * We're detaching, make sure in-syscall flag is off so that
		 * signal will stop the process directly.
		 */
		remote->br_ptrace_flags &= ~LX_PTF_INSYSCALL;
	}

	/*
	 * Attempt to lock the target LWP.
	 */
	if ((error = lx_ptrace_lock_if_stopped(accord, remote,
	    (ptrace_op == LX_PTRACE_DETACH))) != 0) {
		/*
		 * The LWP was not in "ptrace-stop". For detach, ENOENT
		 * indicates that the LWP was not in "ptrace-stop", but is
		 * still locked.
		 */
		if (ptrace_op == LX_PTRACE_DETACH && error == ENOENT) {
			/*
			 * We're detaching, but the process was not in
			 * ptrace_stop, so we don't want to try to restart it.
			 */
			restart = B_FALSE;
		} else {
			mutex_exit(&accord->lxpa_tracees_lock);
			return (error);
		}
	}

	/*
	 * The target LWP is in "ptrace-stop".  We have the containing process
	 * locked.
	 */
	rlwp = remote->br_lwp;
	rproc = lwptoproc(rlwp);


	if (ptrace_op == LX_PTRACE_DETACH) {
		lx_ptrace_detach(accord, remote, (int)data, restart);
		/*
		 * Drop the lock on both the tracee process and the tracee list.
		 */
		mutex_exit(&rproc->p_lock);
		mutex_exit(&accord->lxpa_tracees_lock);

		/*
		 * Release a hold from the accord.
		 */
		lx_ptrace_accord_enter(accord);
		lx_ptrace_accord_rele(accord);
		lx_ptrace_accord_exit(accord);

		return (0);
	}

	/*
	 * The tracees lock is not needed for any of the other operations.
	 * Drop it so further actions can avoid deadlock.
	 */
	mutex_exit(&accord->lxpa_tracees_lock);

	/*
	 * Process the ptrace(2) request:
	 */
	switch (ptrace_op) {
	case LX_PTRACE_CONT:
		error = lx_ptrace_cont(remote, LX_PTC_NONE, (int)data);
		break;

	case LX_PTRACE_SYSCALL:
		error = lx_ptrace_cont(remote, LX_PTC_SYSCALL, (int)data);
		break;

	case LX_PTRACE_SINGLESTEP:
		error = lx_ptrace_cont(remote, LX_PTC_SINGLESTEP, (int)data);
		break;

	case LX_PTRACE_SETOPTIONS:
		error = lx_ptrace_setoptions(remote, data);
		break;

	case LX_PTRACE_GETEVENTMSG:
		error = lx_ptrace_geteventmsg(remote, (void *)data);
		break;

	case LX_PTRACE_GETREGS:
		error = lx_user_regs_copyout(remote, (void *)data);
		break;

	case LX_PTRACE_SETREGS:
		error = lx_user_regs_copyin(remote, (void *)data);
		break;

	case LX_PTRACE_GETSIGINFO:
		error = lx_ptrace_getsiginfo(remote, (void *)data);
		break;

	case LX_PTRACE_PEEKTEXT:
	case LX_PTRACE_PEEKDATA:
		error = lx_ptrace_peek(remote, addr, (void *)data);
		break;

	case LX_PTRACE_POKETEXT:
	case LX_PTRACE_POKEDATA:
		error = lx_ptrace_poke(remote, addr, data);
		break;

	case LX_PTRACE_PEEKUSER:
		error = lx_ptrace_peekuser(remote, addr, (void *)data);
		break;

	case LX_PTRACE_POKEUSER:
		error = lx_ptrace_pokeuser(remote, addr, (void *)data);
		break;

	case LX_PTRACE_GETFPREGS:
		error = lx_user_fpregs_copyout(remote, (void *)data);
		break;

	case LX_PTRACE_SETFPREGS:
		error = lx_user_fpregs_copyin(remote, (void *)data);
		break;

	case LX_PTRACE_GETFPXREGS:
		error = lx_user_fpxregs_copyout(remote, (void *)data);
		break;

	case LX_PTRACE_SETFPXREGS:
		error = lx_user_fpxregs_copyin(remote, (void *)data);
		break;

	case LX_PTRACE_KILL:
		error = lx_ptrace_kill(remote);
		break;

	default:
		error = EINVAL;
	}

	/*
	 * Drop the lock on both the tracee process and the tracee list.
	 */
	mutex_exit(&rproc->p_lock);

	return (error);
}

int
lx_ptrace(int ptrace_op, pid_t lxpid, uintptr_t addr, uintptr_t data)
{
	int error;

	error = lx_ptrace_kernel(ptrace_op, LX_INIT_TO_PID(lxpid), addr, data);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

void
lx_ptrace_init(void)
{
	cv_init(&lx_ptrace_busy_cv, NULL, CV_DEFAULT, NULL);

	lx_ptrace_accord_cache = kmem_cache_create("lx_ptrace_accord",
	    sizeof (lx_ptrace_accord_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
lx_ptrace_fini(void)
{
	cv_destroy(&lx_ptrace_busy_cv);

	kmem_cache_destroy(lx_ptrace_accord_cache);
}
