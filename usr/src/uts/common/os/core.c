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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <sys/prsystm.h>
#include <sys/vnode.h>
#include <sys/var.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/exec.h>
#include <sys/debug.h>
#include <sys/stack.h>
#include <sys/kmem.h>
#include <sys/schedctl.h>
#include <sys/core.h>
#include <sys/corectl.h>
#include <sys/cmn_err.h>
#include <vm/as.h>
#include <sys/rctl.h>
#include <sys/nbmlock.h>
#include <sys/stat.h>
#include <sys/zone.h>
#include <sys/contract/process_impl.h>
#include <sys/ddi.h>

/*
 * Processes running within a zone potentially dump core in 3 locations,
 * based on the per-process, per-zone, and the global zone's core settings.
 *
 * Per-zone and global zone settings are often referred to as "global"
 * settings since they apply to the system (or zone) as a whole, as
 * opposed to a particular process.
 */
enum core_types {
	CORE_PROC,	/* Use per-process settings */
	CORE_ZONE,	/* Use per-zone settings */
	CORE_GLOBAL	/* Use global zone settings */
};

/*
 * Log information about "global" core dumps to syslog.
 */
static void
core_log(struct core_globals *cg, int error, const char *why, const char *path,
    zoneid_t zoneid)
{
	proc_t *p = curproc;
	pid_t pid = p->p_pid;
	char *fn = PTOU(p)->u_comm;

	if (!(cg->core_options & CC_GLOBAL_LOG))
		return;

	if (path == NULL)
		zcmn_err(zoneid, CE_NOTE, "core_log: %s[%d] %s", fn, pid, why);
	else if (error == 0)
		zcmn_err(zoneid, CE_NOTE, "core_log: %s[%d] %s: %s", fn, pid,
		    why, path);
	else
		zcmn_err(zoneid, CE_NOTE, "core_log: %s[%d] %s, errno=%d: %s",
		    fn, pid, why, error, path);
}

/*
 * Private version of vn_remove().
 * Refuse to unlink a directory or an unwritable file.
 * Also allow the process to access files normally inaccessible due to
 * chroot(2) or Zone limitations.
 */
static int
remove_core_file(char *fp, enum core_types core_type)
{
	vnode_t *vp = NULL;		/* entry vnode */
	vnode_t *dvp;			/* ptr to parent dir vnode */
	vfs_t *dvfsp;
	int error;
	int in_crit = 0;
	pathname_t pn;			/* name of entry */
	vnode_t *startvp, *rootvp;

	if ((error = pn_get(fp, UIO_SYSSPACE, &pn)) != 0)
		return (error);
	/*
	 * Determine what rootvp to use.
	 */
	if (core_type == CORE_PROC) {
		rootvp = (PTOU(curproc)->u_rdir == NULL ?
		    curproc->p_zone->zone_rootvp : PTOU(curproc)->u_rdir);
		startvp = (fp[0] == '/' ? rootvp : PTOU(curproc)->u_cdir);
	} else if (core_type == CORE_ZONE) {
		startvp = curproc->p_zone->zone_rootvp;
		rootvp = curproc->p_zone->zone_rootvp;
	} else {
		ASSERT(core_type == CORE_GLOBAL);
		startvp = rootdir;
		rootvp = rootdir;
	}
	VN_HOLD(startvp);
	if (rootvp != rootdir)
		VN_HOLD(rootvp);
	if ((error = lookuppnvp(&pn, NULL, NO_FOLLOW, &dvp, &vp, rootvp,
	    startvp, CRED())) != 0) {
		pn_free(&pn);
		return (error);
	}
	/*
	 * Succeed if there is no file.
	 * Fail if the file is not a regular file.
	 * Fail if the filesystem is mounted read-only.
	 * Fail if the file is not writeable.
	 * Fail if the file has NBMAND share reservations.
	 */
	if (vp == NULL)
		error = 0;
	else if (vp->v_type != VREG)
		error = EACCES;
	else if ((dvfsp = dvp->v_vfsp) != NULL &&
	    (dvfsp->vfs_flag & VFS_RDONLY))
		error = EROFS;
	else if ((error = VOP_ACCESS(vp, VWRITE, 0, CRED(), NULL)) == 0) {
		if (nbl_need_check(vp)) {
			nbl_start_crit(vp, RW_READER);
			in_crit = 1;
			if (nbl_share_conflict(vp, NBL_REMOVE, NULL)) {
				error = EACCES;
			}
		}
		if (!error) {
			error = VOP_REMOVE(dvp, pn.pn_path, CRED(), NULL, 0);
		}
	}

	pn_free(&pn);
	if (vp != NULL) {
		if (in_crit)
			nbl_end_crit(vp);
		VN_RELE(vp);
	}
	VN_RELE(dvp);
	return (error);
}

/*
 * Create the core file in a location that may be normally inaccessible due
 * to chroot(2) or Zone limitations.
 */
static int
create_core_file(char *fp, enum core_types core_type, vnode_t **vpp)
{
	int error;
	mode_t perms = (S_IRUSR | S_IWUSR);
	pathname_t pn;
	char *file;
	vnode_t *vp;
	vnode_t *dvp;
	vattr_t vattr;
	cred_t *credp = CRED();

	if (core_type == CORE_PROC) {
		file = fp;
		dvp = NULL;	/* regular lookup */
	} else {
		vnode_t *startvp, *rootvp;

		ASSERT(core_type == CORE_ZONE || core_type == CORE_GLOBAL);
		/*
		 * This is tricky because we want to dump the core in
		 * a location which may normally be inaccessible
		 * to us (due to chroot(2) limitations, or zone
		 * membership), and hence need to overcome u_rdir
		 * restrictions.  The basic idea is to separate
		 * the path from the filename, lookup the
		 * pathname separately (starting from the global
		 * zone's root directory), and then open the
		 * file starting at the directory vnode.
		 */
		if (error = pn_get(fp, UIO_SYSSPACE, &pn))
			return (error);

		if (core_type == CORE_ZONE) {
			startvp = rootvp = curproc->p_zone->zone_rootvp;
		} else {
			startvp = rootvp = rootdir;
		}
		/*
		 * rootvp and startvp will be VN_RELE()'d by lookuppnvp() if
		 * necessary.
		 */
		VN_HOLD(startvp);
		if (rootvp != rootdir)
			VN_HOLD(rootvp);
		/*
		 * Do a lookup on the full path, ignoring the actual file, but
		 * finding the vnode for the directory.  It's OK if the file
		 * doesn't exist -- it most likely won't since we just removed
		 * it.
		 */
		error = lookuppnvp(&pn, NULL, FOLLOW, &dvp, NULLVPP,
		    rootvp, startvp, credp);
		pn_free(&pn);
		if (error != 0)
			return (error);
		ASSERT(dvp != NULL);
		/*
		 * Now find the final component in the path (ie, the name of
		 * the core file).
		 */
		if (error = pn_get(fp, UIO_SYSSPACE, &pn)) {
			VN_RELE(dvp);
			return (error);
		}
		pn_setlast(&pn);
		file = pn.pn_path;
	}
	error =  vn_openat(file, UIO_SYSSPACE,
	    FWRITE | FTRUNC | FEXCL | FCREAT | FOFFMAX,
	    perms, &vp, CRCREAT, PTOU(curproc)->u_cmask, dvp, -1);
	if (core_type != CORE_PROC) {
		VN_RELE(dvp);
		pn_free(&pn);
	}
	/*
	 * Don't dump a core file owned by "nobody".
	 */
	vattr.va_mask = AT_UID;
	if (error == 0 &&
	    (VOP_GETATTR(vp, &vattr, 0, credp, NULL) != 0 ||
	    vattr.va_uid != crgetuid(credp))) {
		(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0,
		    credp, NULL);
		VN_RELE(vp);
		(void) remove_core_file(fp, core_type);
		error = EACCES;
	}
	*vpp = vp;
	return (error);
}

/*
 * Install the specified held cred into the process, and return a pointer to
 * the held cred which was previously the value of p->p_cred.
 */
static cred_t *
set_cred(proc_t *p, cred_t *newcr)
{
	cred_t *oldcr;
	uid_t olduid, newuid;

	/*
	 * Place a hold on the existing cred, and then install the new
	 * cred into the proc structure.
	 */
	mutex_enter(&p->p_crlock);
	oldcr = p->p_cred;
	crhold(oldcr);
	p->p_cred = newcr;
	mutex_exit(&p->p_crlock);

	ASSERT(crgetzoneid(oldcr) == crgetzoneid(newcr));

	/*
	 * If the real uid is changing, keep the per-user process
	 * counts accurate.
	 */
	olduid = crgetruid(oldcr);
	newuid = crgetruid(newcr);
	if (olduid != newuid) {
		zoneid_t zoneid = crgetzoneid(newcr);

		mutex_enter(&pidlock);
		upcount_dec(olduid, zoneid);
		upcount_inc(newuid, zoneid);
		mutex_exit(&pidlock);
	}

	/*
	 * Broadcast the new cred to all the other threads.  The old
	 * cred can be safely returned because we have a hold on it.
	 */
	crset(p, newcr);
	return (oldcr);
}

static int
do_core(char *fp, int sig, enum core_types core_type, struct core_globals *cg)
{
	proc_t *p = curproc;
	cred_t *credp = CRED();
	rlim64_t rlimit;
	vnode_t *vp;
	int error = 0;
	struct execsw *eswp;
	cred_t *ocredp = NULL;
	int is_setid = 0;
	core_content_t content;
	uid_t uid;
	gid_t gid;

	if (core_type == CORE_GLOBAL || core_type == CORE_ZONE) {
		mutex_enter(&cg->core_lock);
		content = cg->core_content;
		mutex_exit(&cg->core_lock);
		rlimit = cg->core_rlimit;
	} else {
		mutex_enter(&p->p_lock);
		rlimit = rctl_enforced_value(rctlproc_legacy[RLIMIT_CORE],
		    p->p_rctls, p);
		content = corectl_content_value(p->p_content);
		mutex_exit(&p->p_lock);
	}

	if (rlimit == 0)
		return (EFBIG);

	/*
	 * If SNOCD is set, or if the effective, real, and saved ids do
	 * not match up, no one but a privileged user is allowed to view
	 * this core file.  Set the credentials and the owner to root.
	 */
	if ((p->p_flag & SNOCD) ||
	    (uid = crgetuid(credp)) != crgetruid(credp) ||
	    uid != crgetsuid(credp) ||
	    (gid = crgetgid(credp)) != crgetrgid(credp) ||
	    gid != crgetsgid(credp)) {
		/*
		 * Because this is insecure against certain forms of file
		 * system attack, do it only if set-id core files have been
		 * enabled via corectl(CC_GLOBAL_SETID | CC_PROCESS_SETID).
		 */
		if (((core_type == CORE_GLOBAL || core_type == CORE_ZONE) &&
		    !(cg->core_options & CC_GLOBAL_SETID)) ||
		    (core_type == CORE_PROC &&
		    !(cg->core_options & CC_PROCESS_SETID)))
			return (ENOTSUP);

		is_setid = 1;
	}

	/*
	 * If we are doing a "global" core dump or a set-id core dump,
	 * use kcred to do the dumping.
	 */
	if (core_type == CORE_GLOBAL || core_type == CORE_ZONE || is_setid) {
		/*
		 * Use the zone's "kcred" to prevent privilege
		 * escalation.
		 */
		credp = zone_get_kcred(getzoneid());
		ASSERT(credp != NULL);
		ocredp = set_cred(p, credp);
	}

	/*
	 * First remove any existing core file, then
	 * open the new core file with (O_EXCL|O_CREAT).
	 *
	 * The reasons for doing this are manifold:
	 *
	 * For security reasons, we don't want root processes
	 * to dump core through a symlink because that would
	 * allow a malicious user to clobber any file on
	 * the system if s/he could convince a root process,
	 * perhaps a set-uid root process that s/he started,
	 * to dump core in a directory writable by that user.
	 * Similar security reasons apply to hard links.
	 * For symmetry we do this unconditionally, not
	 * just for root processes.
	 *
	 * If the process has the core file mmap()d into the
	 * address space, we would be modifying the address
	 * space that we are trying to dump if we did not first
	 * remove the core file.  (The command "file core"
	 * is the canonical example of this possibility.)
	 *
	 * Opening the core file with O_EXCL|O_CREAT ensures than
	 * two concurrent core dumps don't clobber each other.
	 * One is bound to lose; we don't want to make both lose.
	 */
	if ((error = remove_core_file(fp, core_type)) == 0) {
		error = create_core_file(fp, core_type, &vp);
	}

	/*
	 * Now that vn_open is complete, reset the process's credentials if
	 * we changed them, and make 'credp' point to kcred used
	 * above.  We use 'credp' to do i/o on the core file below, but leave
	 * p->p_cred set to the original credential to allow the core file
	 * to record this information.
	 */
	if (ocredp != NULL)
		credp = set_cred(p, ocredp);

	if (error == 0) {
		int closerr;
#if defined(__sparc)
		(void) flush_user_windows_to_stack(NULL);
#endif
		if ((eswp = PTOU(curproc)->u_execsw) == NULL ||
		    (eswp = findexec_by_magic(eswp->exec_magic)) == NULL) {
			error = ENOSYS;
		} else {
			error = eswp->exec_core(vp, p, credp, rlimit, sig,
			    content);
			rw_exit(eswp->exec_lock);
		}

		closerr = VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, credp, NULL);
		VN_RELE(vp);
		if (error == 0)
			error = closerr;
	}

	if (ocredp != NULL)
		crfree(credp);

	return (error);
}

/*
 * Convert a core name pattern to a pathname.
 */
static int
expand_string(const char *pat, char *fp, int size, cred_t *cr)
{
	proc_t *p = curproc;
	char buf[24];
	int len, i;
	char *s;
	char c;

	while ((c = *pat++) != '\0') {
		if (size < 2)
			return (ENAMETOOLONG);
		if (c != '%') {
			size--;
			*fp++ = c;
			continue;
		}
		if ((c = *pat++) == '\0') {
			size--;
			*fp++ = '%';
			break;
		}
		switch (c) {
		case 'p':	/* pid */
			(void) sprintf((s = buf), "%d", p->p_pid);
			break;
		case 'u':	/* effective uid */
			(void) sprintf((s = buf), "%u", crgetuid(p->p_cred));
			break;
		case 'g':	/* effective gid */
			(void) sprintf((s = buf), "%u", crgetgid(p->p_cred));
			break;
		case 'f':	/* exec'd filename */
			s = PTOU(p)->u_comm;
			break;
		case 'd':	/* exec'd dirname */
			/*
			 * Even if pathname caching is disabled, we should
			 * be able to lookup the pathname for a directory.
			 */
			if (p->p_execdir != NULL && vnodetopath(NULL,
			    p->p_execdir, fp, size, cr) == 0) {
				len = (int)strlen(fp);
				ASSERT(len < size);
				ASSERT(len >= 1);
				ASSERT(fp[0] == '/');

				/*
				 * Strip off the leading slash.
				 */
				for (i = 0; i < len; i++) {
					fp[i] = fp[i + 1];
				}

				len--;

				size -= len;
				fp += len;
			} else {
				*fp = '\0';
			}

			continue;
		case 'n':	/* system nodename */
			s = uts_nodename();
			break;
		case 'm':	/* machine (sun4u, etc) */
			s = utsname.machine;
			break;
		case 't':	/* decimal value of time(2) */
			(void) sprintf((s = buf), "%ld", gethrestime_sec());
			break;
		case 'z':
			s = p->p_zone->zone_name;
			break;
		case '%':
			(void) strcpy((s = buf), "%");
			break;
		default:
			s = buf;
			buf[0] = '%';
			buf[1] = c;
			buf[2] = '\0';
			break;
		}
		len = (int)strlen(s);
		if ((size -= len) <= 0)
			return (ENAMETOOLONG);
		(void) strcpy(fp, s);
		fp += len;
	}

	*fp = '\0';
	return (0);
}

static int
dump_one_core(int sig, rlim64_t rlimit, enum core_types core_type,
    struct core_globals *cg, char **name)
{
	refstr_t *rp;
	proc_t *p = curproc;
	zoneid_t zoneid;
	int error;
	char *fp;
	cred_t *cr;

	ASSERT(core_type == CORE_ZONE || core_type == CORE_GLOBAL);
	zoneid = (core_type == CORE_ZONE ? getzoneid() : GLOBAL_ZONEID);

	mutex_enter(&cg->core_lock);
	if ((rp = cg->core_file) != NULL)
		refstr_hold(rp);
	mutex_exit(&cg->core_lock);
	if (rp == NULL) {
		core_log(cg, 0, "no global core file pattern exists", NULL,
		    zoneid);
		return (1);	/* core file not generated */
	}
	fp = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	cr = zone_get_kcred(getzoneid());
	error = expand_string(refstr_value(rp), fp, MAXPATHLEN, cr);
	crfree(cr);
	if (error != 0) {
		core_log(cg, 0, "global core file pattern too long",
		    refstr_value(rp), zoneid);
	} else if ((error = do_core(fp, sig, core_type, cg)) == 0) {
		core_log(cg, 0, "core dumped", fp, zoneid);
	} else if (error == ENOTSUP) {
		core_log(cg, 0, "setid process, core not dumped", fp, zoneid);
	} else if (error == ENOSPC) {
		core_log(cg, 0, "no space left on device, core truncated",
		    fp, zoneid);
	} else if (error == EFBIG) {
		if (rlimit == 0)
			core_log(cg, 0, "core rlimit is zero, core not dumped",
			    fp, zoneid);
		else
			core_log(cg, 0, "core rlimit exceeded, core truncated",
			    fp, zoneid);
		/*
		 * In addition to the core result logging, we
		 * may also have explicit actions defined on
		 * core file size violations via the resource
		 * control framework.
		 */
		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_CORE],
		    p->p_rctls, p, RCA_SAFE);
		mutex_exit(&p->p_lock);
	} else {
		core_log(cg, error, "core dump failed", fp, zoneid);
	}
	refstr_rele(rp);
	if (name != NULL)
		*name = fp;
	else
		kmem_free(fp, MAXPATHLEN);
	return (error);
}

int
core(int sig, int ext)
{
	proc_t *p = curproc;
	klwp_t *lwp = ttolwp(curthread);
	refstr_t *rp;
	char *fp_process = NULL, *fp_global = NULL, *fp_zone = NULL;
	int error1 = 1;
	int error2 = 1;
	int error3 = 1;
	k_sigset_t sigmask;
	k_sigset_t sighold;
	rlim64_t rlimit;
	struct core_globals *my_cg, *global_cg;

	global_cg = zone_getspecific(core_zone_key, global_zone);
	ASSERT(global_cg != NULL);

	my_cg = zone_getspecific(core_zone_key, curproc->p_zone);
	ASSERT(my_cg != NULL);

	/* core files suppressed? */
	if (!(my_cg->core_options & (CC_PROCESS_PATH|CC_GLOBAL_PATH)) &&
	    !(global_cg->core_options & CC_GLOBAL_PATH)) {
		if (!ext && p->p_ct_process != NULL)
			contract_process_core(p->p_ct_process, p, sig,
			    NULL, NULL, NULL);
		return (1);
	}

	/*
	 * Block all signals except SIGHUP, SIGINT, SIGKILL, and SIGTERM; no
	 * other signal may interrupt a core dump.  For each signal, we
	 * explicitly unblock it and set it in p_siginfo to allow for some
	 * minimal error reporting.  Additionally, we get the current limit on
	 * core file size for handling later error reporting.
	 */
	mutex_enter(&p->p_lock);

	p->p_flag |= SDOCORE;
	schedctl_finish_sigblock(curthread);
	sigmask = curthread->t_hold;	/* remember for later */
	sigfillset(&sighold);
	if (!sigismember(&sigmask, SIGHUP))
		sigdelset(&sighold, SIGHUP);
	if (!sigismember(&sigmask, SIGINT))
		sigdelset(&sighold, SIGINT);
	if (!sigismember(&sigmask, SIGKILL))
		sigdelset(&sighold, SIGKILL);
	if (!sigismember(&sigmask, SIGTERM))
		sigdelset(&sighold, SIGTERM);

	sigaddset(&p->p_siginfo, SIGHUP);
	sigaddset(&p->p_siginfo, SIGINT);
	sigaddset(&p->p_siginfo, SIGKILL);
	sigaddset(&p->p_siginfo, SIGTERM);

	curthread->t_hold = sighold;

	rlimit = rctl_enforced_value(rctlproc_legacy[RLIMIT_CORE], p->p_rctls,
	    p);

	mutex_exit(&p->p_lock);

	/*
	 * Undo any watchpoints.
	 */
	pr_free_watched_pages(p);

	/*
	 * The presence of a current signal prevents file i/o
	 * from succeeding over a network.  We copy the current
	 * signal information to the side and cancel the current
	 * signal so that the core dump will succeed.
	 */
	ASSERT(lwp->lwp_cursig == sig);
	lwp->lwp_cursig = 0;
	lwp->lwp_extsig = 0;
	if (lwp->lwp_curinfo == NULL) {
		bzero(&lwp->lwp_siginfo, sizeof (k_siginfo_t));
		lwp->lwp_siginfo.si_signo = sig;
		lwp->lwp_siginfo.si_code = SI_NOINFO;
	} else {
		bcopy(&lwp->lwp_curinfo->sq_info,
		    &lwp->lwp_siginfo, sizeof (k_siginfo_t));
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}

	/*
	 * Convert the core file name patterns into path names
	 * and call do_core() to write the core files.
	 */

	if (my_cg->core_options & CC_PROCESS_PATH) {
		mutex_enter(&p->p_lock);
		if (p->p_corefile != NULL)
			rp = corectl_path_value(p->p_corefile);
		else
			rp = NULL;
		mutex_exit(&p->p_lock);
		if (rp != NULL) {
			fp_process = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			error1 = expand_string(refstr_value(rp),
			    fp_process, MAXPATHLEN, p->p_cred);
			if (error1 == 0)
				error1 = do_core(fp_process, sig, CORE_PROC,
				    my_cg);
			refstr_rele(rp);
		}
	}

	if (my_cg->core_options & CC_GLOBAL_PATH)
		error2 = dump_one_core(sig, rlimit, CORE_ZONE, my_cg,
		    &fp_global);
	if (global_cg != my_cg && (global_cg->core_options & CC_GLOBAL_PATH))
		error3 = dump_one_core(sig, rlimit, CORE_GLOBAL, global_cg,
		    &fp_zone);

	/*
	 * Restore the signal hold mask.
	 */
	mutex_enter(&p->p_lock);
	curthread->t_hold = sigmask;
	mutex_exit(&p->p_lock);

	if (!ext && p->p_ct_process != NULL)
		contract_process_core(p->p_ct_process, p, sig,
		    error1 == 0 ? fp_process : NULL,
		    error2 == 0 ? fp_global : NULL,
		    error3 == 0 ? fp_zone : NULL);

	if (fp_process != NULL)
		kmem_free(fp_process, MAXPATHLEN);
	if (fp_global != NULL)
		kmem_free(fp_global, MAXPATHLEN);
	if (fp_zone != NULL)
		kmem_free(fp_zone, MAXPATHLEN);

	/*
	 * Return non-zero if no core file was created.
	 */
	return (error1 != 0 && error2 != 0 && error3 != 0);
}

/*
 * Maximum chunk size for dumping core files,
 * size in pages, patchable in /etc/system
 */
uint_t	core_chunk = 32;

/*
 * The delay between core_write() calls, in microseconds.  The default
 * matches one "normal" clock tick, or 10 milliseconds.
 */
clock_t	core_delay_usec = 10000;

/*
 * Common code to core dump process memory.  The core_seg routine does i/o
 * using core_write() below, and so it has the same failure semantics.
 */
int
core_seg(proc_t *p, vnode_t *vp, offset_t offset, caddr_t addr, size_t size,
    rlim64_t rlimit, cred_t *credp)
{
	caddr_t eaddr;
	caddr_t base;
	size_t len;
	int err = 0;

	eaddr = addr + size;
	for (base = addr; base < eaddr; base += len) {
		len = eaddr - base;
		if (as_memory(p->p_as, &base, &len) != 0)
			return (0);

		/*
		 * Reduce len to a reasonable value so that we don't
		 * overwhelm the VM system with a monstrously large
		 * single write and cause pageout to stop running.
		 */
		if (len > (size_t)core_chunk * PAGESIZE)
			len = (size_t)core_chunk * PAGESIZE;

		err = core_write(vp, UIO_USERSPACE,
		    offset + (size_t)(base - addr), base, len, rlimit, credp);

		if (err)
			return (err);

		/*
		 * If we have taken a signal, return EINTR to allow the dump
		 * to be aborted.
		 */
		if (issig(JUSTLOOKING) && issig(FORREAL))
			return (EINTR);
	}

	return (0);
}

/*
 * Wrapper around vn_rdwr to perform writes to a core file.  For core files,
 * we always want to write as much as we possibly can, and then make sure to
 * return either 0 to the caller (for success), or the actual errno value.
 * By using this function, the caller can omit additional code for handling
 * retries and errors for partial writes returned by vn_rdwr.  If vn_rdwr
 * unexpectedly returns zero but no progress has been made, we return ENOSPC.
 */
int
core_write(vnode_t *vp, enum uio_seg segflg, offset_t offset,
    const void *buf, size_t len, rlim64_t rlimit, cred_t *credp)
{
	ssize_t resid = len;
	int error = 0;

	while (len != 0) {
		error = vn_rdwr(UIO_WRITE, vp, (caddr_t)buf, len, offset,
		    segflg, 0, rlimit, credp, &resid);

		if (error != 0)
			break;

		if (resid >= len)
			return (ENOSPC);

		buf = (const char *)buf + len - resid;
		offset += len - resid;
		len = resid;
	}

	return (error);
}
