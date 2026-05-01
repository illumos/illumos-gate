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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * spawn(2): in-kernel process creation for posix_spawn(3C)
 * --------------------------------------------------------
 *
 * posix_spawn(3C) and posix_spawnp(3C) create a new process running a
 * named program. They were historically implemented in libc on top of
 * vforkx() where the library borrowed the parent's address space,
 * stopped every other thread in the process, ran the file actions and
 * attribute changes in the borrowed image, and exec'd. This was
 * rather expensive in the face of a highly-threaded parent. Stopping
 * the other threads serialises a multi-threaded program around each
 * spawn, and a child that blocks (for example opening a FIFO as a
 * file action) blocks the whole process with it.
 *
 * spawn(2) moves the work into the kernel. It is a private system call,
 * used only by libc to implement the posix_spawn() family, and is not a
 * committed interface. The parent describes the whole operation up
 * front, the kernel creates a child with a single kernel-resident LWP,
 * and that LWP applies the requested changes to itself and execs the
 * target. No address space is copied and no threads are stopped. A
 * process can spawn(2) in all its threads and concurrency is limited
 * only by locks that need to be held shortly when processes are
 * created.
 *
 * The libc/kernel boundary
 * ------------------------
 *
 * Everything the child needs is marshalled by libc into two flat,
 * position-independent blobs and copied in as the spawn(2) arguments:
 *
 *    o spawn_param_t -- the attributes and the ordered file actions.
 *    o spawn_args_t  -- the argv and envp string vectors.
 *
 * Both have fixed headers that carry byte offsets and counts into a
 * trailing data[] region. Since the blobs come from userland they are
 * untrusted; spawn_param_verify() and spawn_args_verify() check every
 * offset, length and count for consistency and overflow before
 * anything is dereferenced. Anything malformed results in an EINVAL.
 *
 * Creating the child
 * ------------------
 *
 * Process creation reuses cfork(), which recognises a spawn by its
 * non-NULL kspawn_param_t. Unlike fork() it does not hold the other
 * LWPs and unlike both fork() and vfork() it neither duplicates nor
 * borrows the parent's address space. The child is born with a single
 * LWP, running in the kernel, with kas for its p_as. /proc and
 * relvm() already treat a process in this state as having no address
 * space, the same as the window during an ordinary exec. That single
 * LWP runs spawn_main().
 *
 * The child: spawn_main()
 * -----------------------
 *
 * spawn_main() first arranges for the LWP to appear as though it is
 * returning from an execve(2) call - that is in effect what it is
 * about to do. It then, in the order the old libc implementation used:
 *
 *    o applies the attributes - signal mask and dispositions, RESETIDS,
 *      SETSID, SETPGROUP, and last the scheduling class and priority.
 *      These are last so the credential checks see the post-RESETIDS
 *      ids;
 *    o applies the file actions in the caller's order - open, close,
 *      dup2, closefrom, chdir, fchdir;
 *    o execs the target. For posix_spawnp() the PATH search and the
 *      ENOEXEC "run it as a shell script" fallback happen here, in the
 *      child and after the file actions, so a relative PATH entry
 *      resolves against whatever directory the file actions chose.
 *
 * On success the LWP enters userland through lwp_rtt_initial() and
 * the new program runs.
 *
 * The handshake
 * -------------
 *
 * The parent's spawn(2) call must not return until the child has
 * either started its new program or failed, and in the failing case
 * it must learn the error. The two LWPs synchronise through the
 * kspawn_param_t (ksp). The parent owns ksp for the whole operation
 * in that it allocates it, and frees it once the child has signalled.
 * The child only sets the result and signals, and must not touch it
 * once it has signalled.
 *
 *   parent thread -- spawn()          child LWP -- spawn_main()
 *   ------------------------          ------------------------
 *   copyin + verify the blob
 *   mutex_enter(ksp_lock)
 *   cfork() ----------------------->  p_spawn_ksp = ksp; new LWP runs:
 *   while (!ksp_complete)               apply attributes, file actions
 *       cv_wait_sig / cv_wait            exec the target
 *                                      spawn_complete(ksp, err):
 *                                        ksp_error = err
 *                                        ksp_complete = true
 *   woken  <---------------------------- cv_signal(ksp_cv)
 *   ksp_complete now set, loop ends    then one of:
 *                                        ok        -> lwp_rtt_initial()
 *                                        NOEXECERR -> exit(127)
 *                                        failed    -> CLDEVAPORATE; exit
 *   return pid, or set_errno(ksp_error)
 *
 * If we didn't do anything else, a child killed before it reaches
 * spawn_complete() would leave the parent waiting forever.
 * proc_exit() deals with this by completing the handshake on the
 * child's behalf should it exit with p_spawn_ksp still set. Such a
 * child does not set CLDEVAPORATE, so it becomes an ordinary zombie,
 * matching a fork(2) child that is killed before it can exec.
 *
 * The parent waits with cv_wait_sig() so that job control and /proc
 * keep their usual effect on it. Once a signal is actually delivered
 * it switches to an uninterruptible cv_wait(), because it cannot
 * return and free ksp while the child may still reference it. A fatal
 * signal aimed only at the parent therefore does not unwedge it until
 * the child reports back. This is consistent with what happens with a
 * vfork() parent in vfwait().
 *
 * Running without holdlwps
 * ------------------------
 *
 * Skipping holdlwps() is what makes spawn(2) cheap, but it means the
 * parent's other threads keep running while the child is built. Each
 * thing the child copies out of the parent must therefore be taken
 * atomically with respect to those threads:
 *
 *    o the fd table is copied by flist_spawn(), which locks each
 *      entry as it copies it (see "Copying the file descriptor table"
 *      below);
 *    o the uarea, cwd/root vnodes and signal state are copied in
 *      under p_lock, so a concurrent chdir() or sigaction() cannot
 *      change them.
 *
 * That the parent is still running is the main thing to bear in mind
 * when reading the rest of this file.
 *
 * Copying the file descriptor table
 * ---------------------------------
 *
 * The child's descriptor table is built by flist_spawn() rather than
 * the flist_fork() that fork() and vfork() use. It differs for two
 * reasons.
 *
 * The first is locking, as above. flist_fork() copies the table
 * without per-entry locks, which is safe only because the other LWPs
 * are held. flist_spawn() takes each entry's lock as it reads and
 * copies it, and takes the hold on the underlying file while that
 * lock is still held, so a sibling thread cannot close the descriptor
 * and drop its last reference midway through.
 *
 * The second is that a spawn is logically equivalent to a fork
 * immediately followed by an exec, so a descriptor that cannot play
 * any part in the exec'd image need not be copied at all. Descriptors
 * are kept only if they would still be present in the new program, or
 * if a file action needs it first:
 *
 *    o an FD_CLOFORK descriptor is dropped, as it is by fork();
 *    o a descriptor that is not FD_CLOEXEC and lies below any
 *      closefrom() file action's bound is kept;
 *    o a descriptor named as the source of a dup2 or fchdir file action
 *      is kept even when it is FD_CLOEXEC or above the closefrom bound,
 *      because the action must still read it;
 *    o anything else is dropped.
 *
 * A descriptor kept only because an action references it, but which
 * is FD_CLOEXEC, is still closed by close_exec() at the exec. The set
 * of descriptors the new program sees is therefore unchanged, the
 * selective copy being purely an optimisation.
 *
 * Skipping descriptors also lets the child's table be sized to the
 * highest descriptor actually kept, rather than to the parent's
 * highest. A process that has at some point opened a high-numbered
 * descriptor (say fd 60000), with FD_CLOEXEC would otherwise force
 * every child it spawns to allocate a 60000-entry table only to close
 * it again at exec. Two passes of the table are made. The first finds
 * the highest kept descriptor and sizes the child's table to it. The
 * second walks that range and, under each entry's lock, re-evaluates the
 * keep decision and copies the descriptor. These two passes are not one
 * atomic snapshot of the whole table. A change a sibling makes within the
 * sized range is picked up by the second pass, but a descriptor opened
 * above that range between the passes is not copied by this spawn, the
 * same way an fd change made concurrently with fork(2) may or may not be
 * seen by the child. Either way no descriptor is ever torn, since each is
 * copied while its entry is locked.
 *
 * Exec'ing from kernel memory
 * ---------------------------
 *
 * A normal execve(2) reads its argv and envp from the calling
 * process's user address space. The spawn child has no user address
 * space yet, and its arguments sit in the marshalled blob in kernel
 * memory. exec_common() therefore takes a uio_seg_t saying where the
 * vectors live, and spawn_main() builds native char * arrays that
 * point into the blob. The standard exec code then copies the strings
 * onto the new user stack from kernel rather than user memory, but is
 * otherwise unchanged. Every other caller passes UIO_USERSPACE and
 * follows the original path.
 *
 * Privileges
 * ----------
 *
 * spawn(2) grants nothing that a fork(2) and exec(2) pair could not.
 * Entry is gated by the same secpolicy_basic_fork() check fork() uses,
 * and the child runs with the credentials it inherits from the parent.
 * POSIX_SPAWN_RESETIDS is the only attribute that touches credentials,
 * and it only ever drops privilege, resetting the effective uid and
 * gid to the real uid and gid. The exec itself performs the usual
 * checks on the target, including the handling of set-id binaries,
 * just as a direct execve(2) would.
 *
 * Observability
 * -------------
 *
 * To the proc DTrace provider and to /proc, a spawn looks like a fork
 * followed by an exec and fires the same probes. While it is being
 * built the child carries SSPAWNING, which makes /proc control
 * operations on it fail with EBUSY, as for a system process. A child
 * whose setup fails evaporates without ever being seen by its parent,
 * so the new sdt:::spawn-error probe records the failing stage and
 * errno, and the ::spawn mdb dcmd lists the spawns currently in
 * flight.
 *
 * Before it execs, a spawn child is in the same state as any process
 * caught partway through an ordinary exec(). In particular it has no
 * address space of its own (p_as == kas). /proc already knows how to
 * treat such a process, and the entry points divide into three groups by
 * how much of that existing handling already covers a spawn child:
 *
 *    o The observation paths and pr_set() already test p_as == kas and
 *      report a process with no address space as a system process. A
 *      half-built spawn child falls into that same part-exec'd category.
 *
 *    o The control entry points pr_control[32]() gate only on SSYS,
 *      never on kas. A spawn child is not SSYS, so we also need to
 *      test the SSPAWNING flag here so that an operation such as PCSTOP
 *      does not try to stop a process executing in the kernel.
 *
 *    o The legacy stop ioctls (PIOCSTOP, PIOCWSTOP) must test both kas
 *      and SSPAWNING, because the kas test has a gap at the tail of
 *      exec. The new address space is installed before SSPAWNING is
 *      cleared and SEXECED set in exec_common(). In that window the
 *      child has its own address space but has not finished exec'ing.
 *
 * We deliberately do not expose a dedicated "this is a spawning child"
 * flag through /proc. This is consistent with what is in place for
 * a vfork child that has not yet exec'd. If required in the future,
 * a PR_SPAWNING bit could be added to extend the committed procfs
 * interface.
 *
 * Auditing
 * --------
 *
 * A real fork() followed by an exec() produces two audit records in
 * two processes - the fork in the parent and the exec in the child. A
 * spawn is a single system call in the parent, and it audits as one
 * event, AUE_SPAWN.
 *
 * The record is assembled entirely in the parent's spawn(2) context.
 * The process-creation part is added by audit_newproc() during
 * getproc(), as it is for fork(). Once the child has reported back,
 * audit_spawn() adds the exec detail. The path is recorded as a text
 * token, the attributes of the exec'd file as an attribute token, and,
 * subject to the audit_argv and audit_arge policies, the argument and
 * environment vectors are included. The path is ksp_path, which for
 * posix_spawnp() is the name the child exec'd after the path search,
 * not necessarily the name the caller passed. In the ENOEXEC shell
 * fallback case the audited argv is the one the child built - "sh"
 * followed by the resolved script path and the caller's remaining
 * arguments - so the record reflects that the shell, not the script,
 * was the program loaded.
 */

#include <sys/class.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/exec.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/fork.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/pgrpsys.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/signal.h>
#include <sys/spawn.h>
#include <sys/spawn_impl.h>
#include <sys/sunddi.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>

#include <c2/audit.h>

extern int64_t cfork(int, int, kspawn_param_t *, int);

extern int setpgrp(int, int, int);
extern int setuid(uid_t);
extern int setgid(gid_t);
extern int fchdir(int);
extern int kchdir(const char *);
extern int64_t lwp_sigmask(int, uint_t, uint_t, uint_t, uint_t);
extern int setthreadprio(pcprio_t *, kthread_t *);

static const spawn_attr_t *
spawn_param_attr(const spawn_param_t *sp)
{
	if (sp == NULL || sp->sp_attr_len == 0)
		return (NULL);
	return ((const spawn_attr_t *)&sp->sp_data[sp->sp_attr_off]);
}

/*
 * Signal completion to the parent which is waiting in spawn(2).
 */
void
spawn_complete(kspawn_param_t *ksp, int err)
{
	curproc->p_spawn_ksp = NULL;

	mutex_enter(&ksp->ksp_lock);
	ksp->ksp_error = err;
	ksp->ksp_complete = true;
	cv_signal(&ksp->ksp_cv);
	mutex_exit(&ksp->ksp_lock);
}

/*
 * Apply the spawn attributes in the child.
 */
static int
spawn_attrs_apply(const spawn_param_t *sp)
{
	const spawn_attr_t *spa = spawn_param_attr(sp);
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = curproc;
	int sig;

	if (spa == NULL)
		return (0);

	if (spa->sa_psflags & POSIX_SPAWN_SETSIGMASK) {
		(void) lwp_sigmask(SIG_SETMASK,
		    spa->sa_sigmask.__sigbits[0],
		    spa->sa_sigmask.__sigbits[1],
		    spa->sa_sigmask.__sigbits[2],
		    spa->sa_sigmask.__sigbits[3]);
	}

	if (spa->sa_psflags & POSIX_SPAWN_SETSIGIGN_NP) {
		k_sigset_t kset;

		sigutok(&spa->sa_sigignore, &kset);
		for (sig = 1; sig < NSIG; sig++) {
			if (sigismember(&kset, sig) &&
			    !sigismember(&cantmask, sig)) {
				mutex_enter(&p->p_lock);
				setsigact(sig, SIG_IGN, &nullsmask, 0);
				mutex_exit(&p->p_lock);
			}
		}
	}

	if (spa->sa_psflags & POSIX_SPAWN_SETSIGDEF) {
		k_sigset_t kset;

		sigutok(&spa->sa_sigdefault, &kset);
		for (sig = 1; sig < NSIG; sig++) {
			if (sigismember(&kset, sig) &&
			    !sigismember(&cantmask, sig)) {
				mutex_enter(&p->p_lock);
				setsigact(sig, SIG_DFL, &nullsmask, 0);
				mutex_exit(&p->p_lock);
			}
		}
	}

	if (spa->sa_psflags & POSIX_SPAWN_RESETIDS) {
		lwp->lwp_errno = 0;
		if (setgid(crgetrgid(CRED())) != 0 ||
		    setuid(crgetruid(CRED())) != 0) {
			return (lwp->lwp_errno);
		}
	}

	if (spa->sa_psflags & POSIX_SPAWN_SETSID) {
		/*
		 * setpgrp() reports failure through lwp_errno. Its return
		 * value with the SETSID subcommand is a session ID.
		 */
		lwp->lwp_errno = 0;
		(void) setpgrp(PGRPSYS_SETSID, 0, 0);
		if (lwp->lwp_errno != 0)
			return (lwp->lwp_errno);
	}

	if (spa->sa_psflags & POSIX_SPAWN_SETPGROUP) {
		lwp->lwp_errno = 0;
		if (setpgrp(PGRPSYS_SETPGID, 0, spa->sa_pgroup) != 0)
			return (lwp->lwp_errno);
	}

	/*
	 * The scheduling attributes are applied last, once any RESETIDS,
	 * SETSID and SETPGROUP changes are in place. RESETIDS in particular
	 * must come first so that the privilege checks made while setting the
	 * scheduling parameters see the child's final credentials.
	 */
	if ((spa->sa_psflags &
	    (POSIX_SPAWN_SETSCHEDULER | POSIX_SPAWN_SETSCHEDPARAM)) != 0) {
		kspawn_sched_t ks;
		int err = 0;

		bcopy(&sp->sp_data[sp->sp_sched_off], &ks, sizeof (ks));

		switch (ks.ksched_op) {
		case KSCHED_PARMS:
			err = parmsin(&ks.ksched_parms, NULL);
			break;
		case KSCHED_PRIO:
			/* The same check that doprio() applies */
			if (ks.ksched_prio.pc_cid >= loaded_classes ||
			    ks.ksched_prio.pc_cid < 1) {
				err = EINVAL;
			}
			break;
		}

		if (err != 0)
			return (err);

		mutex_enter(&pidlock);
		mutex_enter(&p->p_lock);
		if (ks.ksched_op == KSCHED_PARMS)
			err = parmsset(&ks.ksched_parms, curthread);
		else
			err = setthreadprio(&ks.ksched_prio, curthread);
		mutex_exit(&p->p_lock);
		mutex_exit(&pidlock);

		if (err != 0)
			return (err);
	}

	return (0);
}

static int
spawn_factions_apply(const kspawn_param_t *ksp)
{
	const spawn_param_t *sp = ksp->ksp_param;
	klwp_t *lwp = ttolwp(curthread);
	uint32_t off;

	if (sp == NULL || sp->sp_fattr_cnt == 0)
		return (0);

	off = sp->sp_fattr_off;
	for (uint32_t i = 0; i < sp->sp_fattr_cnt; i++) {
		const kfile_attr_t *kfa =
		    (const kfile_attr_t *)&sp->sp_data[off];
		int err = 0;
		int fd;

		switch (kfa->kfa_type) {
		case FA_OPEN:
			fd = kopenat(AT_FDCWD, (char *)kfa->kfa_path,
			    kfa->kfa_oflag, kfa->kfa_mode,
			    ksp->ksp_parent_model);
			if (fd < 0) {
				err = lwp->lwp_errno;
			} else if (fd != kfa->kfa_filedes) {
				err = fdup2(fd, kfa->kfa_filedes);
				(void) closeandsetf(fd, NULL);
			}
			break;
		case FA_CLOSE:
			err = closeandsetf(kfa->kfa_filedes, NULL);
			/* An already-closed descriptor is not an error */
			if (err == EBADF)
				err = 0;
			break;
		case FA_DUP2:
			err = fdup2(kfa->kfa_filedes, kfa->kfa_newfiledes);
			break;
		case FA_CLOSEFROM:
			closefrom_all(kfa->kfa_filedes);
			break;
		case FA_CHDIR:
			err = kchdir((const char *)kfa->kfa_path);
			break;
		case FA_FCHDIR:
			lwp->lwp_errno = 0;
			if (fchdir(kfa->kfa_filedes) != 0)
				err = lwp->lwp_errno;
			break;
		}

		if (err != 0)
			return (err);

		off += kfa->kfa_len;
	}

	return (0);
}

/*
 * Build a NULL-terminated vector of pointers to the packed, NUL-terminated
 * strings in the spawn args data area.
 */
static char **
spawn_vector(const spawn_args_t *sa, uint32_t off, uint32_t cnt)
{
	char **vec = kmem_alloc(((size_t)cnt + 1) * sizeof (char *), KM_SLEEP);

	for (uint32_t i = 0; i < cnt; i++) {
		vec[i] = (char *)&sa->sa_data[off];
		off += strlen(vec[i]) + 1;
	}
	vec[cnt] = NULL;

	return (vec);
}

/*
 * Build the path name for the next attempt in a PATH search by joining the
 * leading component of the search path with the program name. Returns the
 * remainder of the search path or NULL if we're done. Sets *fits to false
 * if the joined name would not fit in buf, in which case buf is not filled
 * and the caller must skip this candidate rather than exec a truncated path.
 */
static const char *
spawn_execat(const char *path, const char *name, char *buf, size_t bufl,
    bool *fits)
{
	const char *sep = strchr(path, ':');
	size_t dirlen = (sep == NULL) ? strlen(path) : (size_t)(sep - path);
	size_t namelen = strlen(name);
	size_t need = dirlen + namelen + 1;
	char *s = buf;

	if (dirlen > 0)
		need++;		/* for the '/' separator */

	*fits = (need <= bufl);
	if (*fits) {
		bcopy(path, s, dirlen);
		s += dirlen;
		if (dirlen > 0)
			*s++ = '/';
		bcopy(name, s, namelen);
		s[namelen] = '\0';
	}

	return (sep != NULL ? sep + 1 : NULL);
}

/*
 * Record the attributes of the file we have just exec'd so that the parent can
 * include them in the spawn(2) audit record, the same attribute token an
 * ordinary exec(2) produces. The exec'd file is now the process's p_exec. This
 * runs in the child after a successful exec_common() and before it reports back
 * to the parent, so the parent sees the result. It is only worth the
 * vop_getattr() when auditing is active.
 */
static void
spawn_capture_vattr(kspawn_param_t *ksp)
{
	if (!ksp->ksp_audit)
		return;

	ksp->ksp_vattr.va_mask = AT_ALL;
	if (VOP_GETATTR(curproc->p_exec, &ksp->ksp_vattr, 0, CRED(), NULL) == 0)
		ksp->ksp_have_vattr = true;
}

/*
 * Marshal the argument vector the child actually exec'd into ksp_argv, as a run
 * of nul-terminated strings, so the parent audits it in place of the caller's
 * argv. This is only needed for the ENOEXEC shell fallback and only when
 * auditing is active.
 */
static void
spawn_capture_argv(kspawn_param_t *ksp, char *const *argv)
{
	size_t sz = 0;
	uint_t argc = 0;
	char *p;

	if (!ksp->ksp_audit)
		return;

	for (uint_t i = 0; argv[i] != NULL; i++) {
		sz += strlen(argv[i]) + 1;
		argc++;
	}
	if (sz == 0)
		return;

	p = kmem_alloc(sz, KM_SLEEP);
	ksp->ksp_argv = p;
	ksp->ksp_argvsz = sz;
	ksp->ksp_argc = argc;
	for (uint_t i = 0; argv[i] != NULL; i++) {
		size_t len = strlen(argv[i]) + 1;

		bcopy(argv[i], p, len);
		p += len;
	}
}

/*
 * Exec the target program. For posix_spawn() this is a single attempt at the
 * given path. For posix_spawnp(), libc supplies the search path and shell in
 * the spawn parameters, and we need to walk the path.
 *
 * On success the process is running the new image and this returns 0.
 */
static int
spawn_exec(kspawn_param_t *ksp)
{
	const spawn_args_t *sa = ksp->ksp_args;
	const spawn_param_t *sp = ksp->ksp_param;
	const char *pathstr = NULL, *shell = NULL, *cp;
	/*
	 * Allow for prepending "./" below, should the resulting filename begin
	 * with a '-'.
	 */
	const size_t pathl = MAXPATHLEN + sizeof ("./");
	char **argv, **envp;
	char *path = NULL;
	int err = ENOENT;
	int saved_err = 0;

	argv = spawn_vector(sa, sa->sa_arg_off, sa->sa_arg_cnt);
	envp = spawn_vector(sa, sa->sa_env_off, sa->sa_env_cnt);

	if (sp != NULL && sp->sp_path_len != 0) {
		pathstr = (const char *)&sp->sp_data[sp->sp_path_off];
		if (sp->sp_shell_len != 0)
			shell = (const char *)&sp->sp_data[sp->sp_shell_off];
	}

	if (pathstr == NULL) {
		/* posix_spawn() - the simple case with the given path */
		err = exec_common(ksp->ksp_path, (const char **)argv,
		    (const char **)envp, NULL, EBA_NONE, UIO_SYSSPACE);
		if (err == 0)
			spawn_capture_vattr(ksp);
		goto out;
	}

	path = kmem_alloc(pathl, KM_SLEEP);

	cp = pathstr;
	do {
		bool fits;

		cp = spawn_execat(cp, ksp->ksp_path, path, MAXPATHLEN + 1,
		    &fits);
		if (!fits) {
			/*
			 * This candidate does not fit in the buffer. Skip it
			 * rather than exec a truncated path, remembering the
			 * error in case the search finds nothing better.
			 */
			err = ENAMETOOLONG;
			if (saved_err == 0)
				saved_err = ENAMETOOLONG;
			continue;
		}

		/*
		 * If the resulting filename begins with a '-', prepend "./"
		 * so that the shell cannot interpret it as an option.
		 */
		if (*path == '-') {
			memmove(path + 2, path, strlen(path) + 1);
			path[0] = '.';
			path[1] = '/';
		}

		err = exec_common(path, (const char **)argv,
		    (const char **)envp, NULL, EBA_NONE, UIO_SYSSPACE);
		if (err == 0) {
			/*
			 * Record the path the search resolved to so
			 * the parent can audit it. The copy will fit
			 * in ksp_path since our call to exec_common()
			 * succeeded with this path.
			 */
			(void) strlcpy(ksp->ksp_path, path,
			    sizeof (ksp->ksp_path));
			spawn_capture_vattr(ksp);
			goto out;
		}

		/*
		 * Remember the most meaningful error seen during the search
		 * (matching execvp). A candidate that existed but could not be
		 * executed (EACCES) outranks both a later "not found" and an
		 * over-long candidate that we had to skip.
		 */
		if (err == EACCES)
			saved_err = EACCES;

		/*
		 * The candidate has execute permission but is not in a
		 * format the kernel recognises. That is, it is neither a
		 * binary nor a "#!" script, both of which the kernel's exec
		 * would run directly. We treat it as a bare shell script
		 * and re-exec it through the shell interpreter passed in
		 * from userland ("sh"), reproducing the historical
		 * execvp()-based posix_spawnp(). The PATH search stops
		 * here.
		 *
		 * Note that POSIX.1-2024 (Issue 8) now requires
		 * posix_spawnp() to fail with ENOEXEC here rather than fall
		 * back to sh (see Austin Group defect 1674). However, we
		 * keep the fallback for now to preserve the execvp()
		 * behaviour that callers may rely on.
		 */
		if (err == ENOEXEC) {
			size_t nargs = (size_t)sa->sa_arg_cnt + 3;
			char **newargs;
			uint32_t i;

			if (shell == NULL)
				goto out;

			newargs = kmem_alloc(nargs * sizeof (char *),
			    KM_SLEEP);
			/*
			 * argv[0] is always the literal "sh", regardless of
			 * the shell path supplied by libc, matching the
			 * behaviour of execvp().
			 */
			newargs[0] = "sh";
			newargs[1] = path;
			for (i = 1; i < sa->sa_arg_cnt; i++)
				newargs[i + 1] = argv[i];
			newargs[i + 1] = NULL;

			err = exec_common(shell, (const char **)newargs,
			    (const char **)envp, NULL, EBA_NONE,
			    UIO_SYSSPACE);
			if (err == 0) {
				(void) strlcpy(ksp->ksp_path, shell,
				    sizeof (ksp->ksp_path));
				spawn_capture_vattr(ksp);
				spawn_capture_argv(ksp, newargs);
			}

			kmem_free(newargs, nargs * sizeof (char *));
			goto out;
		}
	} while (cp != NULL);

	/*
	 * The search is exhausted without an exec. Prefer the most
	 * meaningful error we saw over whichever happened to be last.
	 */
	if (saved_err != 0)
		err = saved_err;

out:
	if (path != NULL)
		kmem_free(path, pathl);
	kmem_free(argv, ((size_t)sa->sa_arg_cnt + 1) * sizeof (char *));
	kmem_free(envp, ((size_t)sa->sa_env_cnt + 1) * sizeof (char *));

	return (err);
}

/*
 * The entry point for the single LWP of a spawned child, which begins life
 * here in the kernel. Apply the spawn attributes and file actions, exec the
 * target program, report the outcome to the waiting parent and, if
 * everything's ok, enter userland via lwp_rtt_initial().
 */
void
spawn_main(void *arg)
{
	kspawn_param_t *ksp = arg;
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = curproc;
	const spawn_attr_t *spa = spawn_param_attr(ksp->ksp_param);
	bool execfail = false;
	int err;

	ASSERT(p->p_spawn_ksp == ksp);

	/*
	 * Make this LWP look as if it is completing an execve() system
	 * call. /proc and post_syscall() rely on this.
	 */
	bzero(lwp->lwp_arg, sizeof (lwp->lwp_arg));
	lwp->lwp_ap = lwp->lwp_arg;
	curthread->t_sysnum = SYS_execve;
	curthread->t_post_sys = 1;

	/*
	 * The spawn-error probes identify the spawn parameters, the stage
	 * at which the spawn failed and the error. A failed spawn child
	 * usually evaporates without ever running in userland, and its
	 * image is still the parent's, so these probes are the observable
	 * record of what went wrong inside it.
	 */
	if ((err = spawn_attrs_apply(ksp->ksp_param)) != 0) {
		DTRACE_PROBE3(spawn__error, kspawn_param_t *, ksp,
		    char *, "attributes", int, err);
	} else if ((err = spawn_factions_apply(ksp)) != 0) {
		DTRACE_PROBE3(spawn__error, kspawn_param_t *, ksp,
		    char *, "file-actions", int, err);
	} else if ((err = spawn_exec(ksp)) != 0) {
		DTRACE_PROBE3(spawn__error, kspawn_param_t *, ksp,
		    char *, "exec", int, err);
		execfail = true;
	}

	if (err == 0) {
		/*
		 * The exec succeeded. Release the parent and enter userland
		 * in the new program.
		 */
		spawn_complete(ksp, 0);
		lwp_rtt_initial();
		/* NOTREACHED */
	}

	if (execfail && spa != NULL &&
	    (spa->sa_psflags & POSIX_SPAWN_NOEXECERR_NP) != 0) {
		/*
		 * POSIX_SPAWN_NOEXECERR_NP: an exec failure is not reported
		 * to the parent. It is told that the spawn succeeded, and
		 * the child exits with status 127 for the parent to observe
		 * via wait().
		 */
		spawn_complete(ksp, 0);
		exit(CLD_EXITED, SPAWN_NOEXECERR_STATUS);
		/* NOTREACHED */
	}

	/*
	 * The error is reported to the parent and the parent never learns
	 * this child's pid - it disappears without a trace and without
	 * raising SIGCHLD.
	 */
	mutex_enter(&pidlock);
	p->p_pidflag |= CLDEVAPORATE;
	mutex_exit(&pidlock);

	spawn_complete(ksp, err);
	exit(CLD_EXITED, 0);
	/* NOTREACHED */
}

static bool
spawn_region_ok(const spawn_param_t *sp, uint32_t off, uint32_t len)
{
	return (off <= sp->sp_datalen && len <= sp->sp_datalen - off);
}

/*
 * As spawn_region_ok(), additionally requiring that the region holds a
 * NUL-terminated string.
 */
static bool
spawn_str_ok(const spawn_param_t *sp, uint32_t off, uint32_t len)
{
	return (len != 0 && spawn_region_ok(sp, off, len) &&
	    sp->sp_data[off + len - 1] == '\0');
}

static int
spawn_param_verify(const spawn_param_t *sp, uint32_t spsize)
{
	int schedflags = 0;

	if (sp->sp_size != spsize ||
	    sp->sp_datalen != spsize - offsetof(spawn_param_t, sp_data)) {
		return (EINVAL);
	}

	if (sp->sp_attr_len != 0) {
		const spawn_attr_t *spa;

		if (sp->sp_attr_len != sizeof (spawn_attr_t) ||
		    !IS_P2ALIGNED(sp->sp_attr_off, sizeof (uint32_t)) ||
		    !spawn_region_ok(sp, sp->sp_attr_off, sp->sp_attr_len)) {
			return (EINVAL);
		}

		spa = spawn_param_attr(sp);

		if ((spa->sa_psflags & ~ALL_POSIX_SPAWN_FLAGS) != 0)
			return (EINVAL);
		if (spa->sa_pgroup < 0)
			return (EINVAL);

		schedflags = spa->sa_psflags &
		    (POSIX_SPAWN_SETSCHEDULER | POSIX_SPAWN_SETSCHEDPARAM);
	} else if (sp->sp_attr_off != 0) {
		return (EINVAL);
	}

	/*
	 * The resolved scheduling attributes are required when one of the
	 * scheduling flags is set, and must not be present otherwise.
	 */
	if (schedflags != 0) {
		const kspawn_sched_t *ks;

		if (sp->sp_sched_len != sizeof (kspawn_sched_t) ||
		    !IS_P2ALIGNED(sp->sp_sched_off, sizeof (uint32_t)) ||
		    !spawn_region_ok(sp, sp->sp_sched_off, sp->sp_sched_len)) {
			return (EINVAL);
		}

		ks = (const kspawn_sched_t *)&sp->sp_data[sp->sp_sched_off];

		switch (ks->ksched_op) {
		case KSCHED_PARMS:
			break;
		case KSCHED_PRIO:
			if (ks->ksched_prio.pc_op != PC_SETPRIO)
				return (EINVAL);
			break;
		default:
			return (EINVAL);
		}
	} else if (sp->sp_sched_len != 0 || sp->sp_sched_off != 0) {
		return (EINVAL);
	}

	if (sp->sp_fattr_cnt != 0) {
		uint32_t off = sp->sp_fattr_off;

		if (!IS_P2ALIGNED(off, sizeof (uint32_t)))
			return (EINVAL);

		for (uint32_t i = 0; i < sp->sp_fattr_cnt; i++) {
			const kfile_attr_t *kfa;
			uint64_t reclen;

			if (!spawn_region_ok(sp, off, sizeof (kfile_attr_t)))
				return (EINVAL);

			kfa = (const kfile_attr_t *)&sp->sp_data[off];

			/*
			 * Each record is padded so that the next one remains
			 * 32-bit aligned.
			 */
			reclen = P2ROUNDUP((uint64_t)sizeof (kfile_attr_t) +
			    kfa->kfa_pathsize, sizeof (uint32_t));
			if (kfa->kfa_len != reclen ||
			    !spawn_region_ok(sp, off, kfa->kfa_len)) {
				return (EINVAL);
			}

			/*
			 * Each action uses only some of these fields. The
			 * rest may hold arbitrary values, so an action's
			 * consumer must read only the fields for its type.
			 */
			switch (kfa->kfa_type) {
			case FA_OPEN:
				/*
				 * kfa_oflag and kfa_mode are not checked
				 * here. kopenat() interprets them when the
				 * action runs, as open(2) would.
				 */
				if (kfa->kfa_filedes < 0)
					return (EINVAL);
				/* FALLTHROUGH */
			case FA_CHDIR:
				if (kfa->kfa_pathsize == 0 ||
				    kfa->kfa_path[kfa->kfa_pathsize - 1] !=
				    '\0') {
					return (EINVAL);
				}
				break;
			case FA_CLOSE:
			case FA_CLOSEFROM:
			case FA_FCHDIR:
				if (kfa->kfa_pathsize != 0 ||
				    kfa->kfa_filedes < 0) {
					return (EINVAL);
				}
				break;
			case FA_DUP2:
				if (kfa->kfa_pathsize != 0 ||
				    kfa->kfa_filedes < 0 ||
				    kfa->kfa_newfiledes < 0) {
					return (EINVAL);
				}
				break;
			default:
				return (EINVAL);
			}

			off += kfa->kfa_len;
		}
	} else if (sp->sp_fattr_off != 0) {
		return (EINVAL);
	}

	if (sp->sp_shell_len != 0) {
		if (!spawn_str_ok(sp, sp->sp_shell_off, sp->sp_shell_len))
			return (EINVAL);
	} else if (sp->sp_shell_off != 0) {
		return (EINVAL);
	}

	if (sp->sp_path_len != 0) {
		if (!spawn_str_ok(sp, sp->sp_path_off, sp->sp_path_len))
			return (EINVAL);
	} else if (sp->sp_path_off != 0) {
		return (EINVAL);
	}

	return (0);
}

static int
spawn_args_verify(const spawn_args_t *sa, uint32_t sasize)
{
	uint32_t off;

	if (sa->sa_size != sasize ||
	    sa->sa_datalen != sasize - offsetof(spawn_args_t, sa_data)) {
		return (EINVAL);
	}

	if (sa->sa_env_off > sa->sa_datalen ||
	    sa->sa_arg_off > sa->sa_env_off) {
		return (EINVAL);
	}

	off = sa->sa_arg_off;
	for (uint32_t i = 0; i < sa->sa_arg_cnt; i++) {
		const char *s = (const char *)&sa->sa_data[off];
		const char *e = memchr(s, '\0', sa->sa_env_off - off);

		if (e == NULL)
			return (EINVAL);
		off += (uint32_t)(e - s) + 1;
	}
	if (off != sa->sa_env_off)
		return (EINVAL);

	for (uint32_t i = 0; i < sa->sa_env_cnt; i++) {
		const char *s = (const char *)&sa->sa_data[off];
		const char *e = memchr(s, '\0', sa->sa_datalen - off);

		if (e == NULL)
			return (EINVAL);
		off += (uint32_t)(e - s) + 1;
	}
	if (off != sa->sa_datalen)
		return (EINVAL);

	return (0);
}

/*
 * Pre-scan the file actions to determine which of the parent's file
 * descriptors the child actually needs, so that flist_spawn() can limit its
 * copy of the descriptor table:
 *
 *  - ksp_closefrom is the lowest closefrom() bound. Descriptors at or above
 *    it would be closed by the closefrom action anyway, so they need not be
 *    copied unless an action consumes them as a source.
 *  - ksp_reffds lists the descriptors that actions consume as sources -
 *    dup2() and fchdir() - which must be copied even if they carry
 *    FD_CLOEXEC or sit above the closefrom bound.
 *
 * This is purely an optimisation. Copying too much is harmless since
 * the file actions and close_exec() still run in the child.
 */
static void
spawn_prescan(const spawn_param_t *sp, kspawn_param_t *ksp)
{
	const kfile_attr_t *kfa;
	uint32_t off, i, n;

	ksp->ksp_closefrom = INT_MAX;

	if (sp == NULL || sp->sp_fattr_cnt == 0)
		return;

	n = 0;
	off = sp->sp_fattr_off;
	for (i = 0; i < sp->sp_fattr_cnt; i++) {
		kfa = (const kfile_attr_t *)&sp->sp_data[off];
		switch (kfa->kfa_type) {
		case FA_CLOSEFROM:
			ksp->ksp_closefrom =
			    MIN(ksp->ksp_closefrom, kfa->kfa_filedes);
			break;
		case FA_DUP2:
		case FA_FCHDIR:
			n++;
			break;
		default:
			break;
		}
		off += kfa->kfa_len;
	}

	if (n == 0)
		return;

	/* We saw at least one dup2 or chdir. Build a list of source fds */

	ksp->ksp_reffds = kmem_alloc(n * sizeof (int), KM_SLEEP);
	ksp->ksp_nreffds = n;

	n = 0;
	off = sp->sp_fattr_off;
	for (i = 0; i < sp->sp_fattr_cnt; i++) {
		kfa = (const kfile_attr_t *)&sp->sp_data[off];
		if (kfa->kfa_type == FA_DUP2 || kfa->kfa_type == FA_FCHDIR) {
			VERIFY3U(n, <, ksp->ksp_nreffds);
			ksp->ksp_reffds[n++] = kfa->kfa_filedes;
		}
		off += kfa->kfa_len;
	}
}

static int
spawn_forkflags(const spawn_param_t *sp)
{
	const spawn_attr_t *spa = spawn_param_attr(sp);
	int flags = 0;

	if (spa != NULL) {
		if ((spa->sa_psflags & POSIX_SPAWN_NOSIGCHLD_NP) != 0)
			flags |= FORK_NOSIGCHLD;
		if ((spa->sa_psflags & POSIX_SPAWN_WAITPID_NP) != 0)
			flags |= FORK_WAITPID;
	}

	return (flags);
}

int64_t
spawn(void *path, void *sparam, uint32_t spsize, void *sargs, uint32_t sasize)
{
	kspawn_param_t *ksp = NULL;
	spawn_param_t *sp = NULL;
	spawn_args_t *sa = NULL;
	int64_t ret = -1;
	int err = 0;

	if (path == NULL || sargs == NULL || sasize < sizeof (*sa))
		return ((int64_t)set_errno(EINVAL));

	if (spsize > NCARGS64 || sasize > NCARGS64)
		return ((int64_t)set_errno(E2BIG));

	if (spsize > 0) {
		if (spsize < sizeof (*sp))
			return ((int64_t)set_errno(EINVAL));

		sp = kmem_alloc(spsize, KM_SLEEP);
		if (copyin(sparam, sp, spsize) != 0) {
			err = EFAULT;
			goto out;
		}
		if ((err = spawn_param_verify(sp, spsize)) != 0)
			goto out;
	}

	sa = kmem_alloc(sasize, KM_SLEEP);
	if (copyin(sargs, sa, sasize) != 0) {
		err = EFAULT;
		goto out;
	}
	if ((err = spawn_args_verify(sa, sasize)) != 0)
		goto out;

	ksp = kmem_zalloc(sizeof (*ksp), KM_SLEEP);

	err = copyinstr(path, ksp->ksp_path, sizeof (ksp->ksp_path), NULL);
	if (err != 0)
		goto out;

	ksp->ksp_param = sp;
	ksp->ksp_args = sa;
	ksp->ksp_parent_model = get_udatamodel();
	ksp->ksp_audit = AU_AUDITING();
	spawn_prescan(sp, ksp);

	mutex_init(&ksp->ksp_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ksp->ksp_cv, NULL, CV_DEFAULT, NULL);

	/*
	 * If cfork() succeeds, wait for the child to apply the various spawn
	 * attributes and attempt the exec. Every child exit path signals
	 * completion, including abnormal termination, so the wait is bounded
	 * by the child's lifetime.
	 *
	 * This logic is taken from vfwait(). We wait interruptibly with
	 * cv_wait_sig() for its jobcontrol and /proc side effects. The
	 * spawning thread can then be stopped or examined and does not block a
	 * concurrent holdlwps() from another of the parent's threads while it
	 * waits. Once a signal is pending we must switch to an uninterruptible
	 * cv_wait(), since we cannot return and free ksp while the child may
	 * still reference it, and cv_wait_sig() would otherwise spin returning
	 * immediately.
	 */
	mutex_enter(&ksp->ksp_lock);
	ret = cfork(0, 0, ksp, spawn_forkflags(sp));
	if (ttolwp(curthread)->lwp_errno == 0) {
		bool signalled = false;

		while (!ksp->ksp_complete) {
			if (signalled) {
				cv_wait(&ksp->ksp_cv, &ksp->ksp_lock);
			} else {
				signalled = !cv_wait_sig(&ksp->ksp_cv,
				    &ksp->ksp_lock);
			}
		}
		if (ksp->ksp_error != 0) {
			err = ksp->ksp_error;
			ret = -1;
		}
	}
	mutex_exit(&ksp->ksp_lock);

	mutex_destroy(&ksp->ksp_lock);
	cv_destroy(&ksp->ksp_cv);

	/*
	 * Record the details of the spawn while the marshalled data is still
	 * to hand. On success ksp_path holds the path that the child actually
	 * exec'd, which for posix_spawnp() may differ from the caller-supplied
	 * name. The target's attributes are in ksp_vattr and ksp_argv holds
	 * the vector it exec'd when that differs from the caller's argv.
	 */
	if (ksp->ksp_audit) {
		const char *argstr;
		ssize_t argc;

		if (ksp->ksp_argv != NULL) {
			argstr = ksp->ksp_argv;
			argc = (ssize_t)ksp->ksp_argc;
		} else {
			argstr = (const char *)&sa->sa_data[sa->sa_arg_off];
			argc = (ssize_t)sa->sa_arg_cnt;
		}

		audit_spawn(ksp->ksp_path,
		    ksp->ksp_have_vattr ? &ksp->ksp_vattr : NULL,
		    argstr, (const char *)&sa->sa_data[sa->sa_env_off],
		    argc, (ssize_t)sa->sa_env_cnt);
	}

out:
	if (sp != NULL)
		kmem_free(sp, spsize);
	if (sa != NULL)
		kmem_free(sa, sasize);
	if (ksp != NULL) {
		if (ksp->ksp_reffds != NULL) {
			kmem_free(ksp->ksp_reffds,
			    ksp->ksp_nreffds * sizeof (int));
		}
		kmem_free(ksp, sizeof (*ksp));
	}

	if (err != 0)
		return ((int64_t)set_errno(err));
	return (ret);
}
