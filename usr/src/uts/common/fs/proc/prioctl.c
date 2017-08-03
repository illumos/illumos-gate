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
 * Copyright 2017 Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All rights reserved.  	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/vmparam.h>
#include <sys/var.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cpuvar.h>
#include <sys/session.h>
#include <sys/signal.h>
#include <sys/auxv.h>
#include <sys/user.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/ts.h>
#include <sys/mman.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/schedctl.h>
#include <sys/pset.h>
#include <sys/old_procfs.h>
#include <sys/zone.h>
#include <sys/time.h>
#include <sys/msacct.h>
#include <vm/rm.h>
#include <vm/as.h>
#include <vm/rm.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <sys/contract_impl.h>
#include <sys/ctfs_impl.h>
#include <sys/ctfs.h>

#if defined(__i386) || defined(__i386_COMPAT)
#include <sys/sysi86.h>
#endif

#include <fs/proc/prdata.h>

static	int	isprwrioctl(int);
static	ulong_t	prmaprunflags(long);
static	long	prmapsetflags(long);
static	void	prsetrun(kthread_t *, prrun_t *);
static	int	propenm(prnode_t *, caddr_t, caddr_t, int *, cred_t *);
extern	void	oprgetstatus(kthread_t *, prstatus_t *, zone_t *);
extern	void	oprgetpsinfo(proc_t *, prpsinfo_t *, kthread_t *);
static	int	oprgetmap(proc_t *, list_t *);

static int
prctioctl(prnode_t *pnp, int cmd, intptr_t arg, int flag, cred_t *cr)
{
	int error = 0;
	ct_kparam_t kparam;
	ct_param_t *param = &kparam.param;
	ct_template_t *tmpl;

	if (cmd != CT_TSET && cmd != CT_TGET)
		return (EINVAL);

	error = ctparam_copyin((void *)arg, &kparam, flag, cmd);
	if (error != 0)
		return (error);

	if ((error = prlock(pnp, ZNO)) != 0) {
		kmem_free(kparam.ctpm_kbuf, param->ctpm_size);
		return (error);
	}

	tmpl = pnp->pr_common->prc_thread->t_lwp->lwp_ct_active[pnp->pr_cttype];
	if (tmpl == NULL) {
		prunlock(pnp);
		kmem_free(kparam.ctpm_kbuf, param->ctpm_size);
		return (ESTALE);
	}

	if (cmd == CT_TSET)
		error = ctmpl_set(tmpl, &kparam, cr);
	else
		error = ctmpl_get(tmpl, &kparam);

	prunlock(pnp);

	if (cmd == CT_TGET && error == 0) {
		error = ctparam_copyout(&kparam, (void *)arg, flag);
	} else {
		kmem_free(kparam.ctpm_kbuf, param->ctpm_size);
	}

	return (error);
}


/*
 * Control operations (lots).
 */
/*ARGSUSED*/
#ifdef _SYSCALL32_IMPL
static int
prioctl64(
	struct vnode *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
#else
int
prioctl(
	struct vnode *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
#endif	/* _SYSCALL32_IMPL */
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
	caddr_t cmaddr = (caddr_t)arg;
	proc_t *p;
	user_t *up;
	kthread_t *t;
	klwp_t *lwp;
	prnode_t *pnp = VTOP(vp);
	prcommon_t *pcp;
	prnode_t *xpnp = NULL;
	int error;
	int zdisp;
	void *thing = NULL;
	size_t thingsize = 0;

	/*
	 * For copyin()/copyout().
	 */
	union {
		caddr_t		va;
		int		signo;
		int		nice;
		uint_t		lwpid;
		long		flags;
		prstatus_t	prstat;
		prrun_t		prrun;
		sigset_t	smask;
		siginfo_t	info;
		sysset_t	prmask;
		prgregset_t	regs;
		prfpregset_t	fpregs;
		prpsinfo_t	prps;
		sigset_t	holdmask;
		fltset_t	fltmask;
		prcred_t	prcred;
		prhusage_t	prhusage;
		prmap_t		prmap;
		auxv_t		auxv[__KERN_NAUXV_IMPL];
	} un;

	if (pnp->pr_type == PR_TMPL)
		return (prctioctl(pnp, cmd, arg, flag, cr));

	/*
	 * Support for old /proc interface.
	 */
	if (pnp->pr_pidfile != NULL) {
		ASSERT(pnp->pr_type == PR_PIDDIR);
		vp = pnp->pr_pidfile;
		pnp = VTOP(vp);
		ASSERT(pnp->pr_type == PR_PIDFILE);
	}

	if (pnp->pr_type != PR_PIDFILE && pnp->pr_type != PR_LWPIDFILE)
		return (ENOTTY);

	/*
	 * Fail ioctls which are logically "write" requests unless
	 * the user has write permission.
	 */
	if ((flag & FWRITE) == 0 && isprwrioctl(cmd))
		return (EBADF);

	/*
	 * Perform any necessary copyin() operations before
	 * locking the process.  Helps avoid deadlocks and
	 * improves performance.
	 *
	 * Also, detect invalid ioctl codes here to avoid
	 * locking a process unnnecessarily.
	 *
	 * Also, prepare to allocate space that will be needed below,
	 * case by case.
	 */
	error = 0;
	switch (cmd) {
	case PIOCGETPR:
		thingsize = sizeof (proc_t);
		break;
	case PIOCGETU:
		thingsize = sizeof (user_t);
		break;
	case PIOCSTOP:
	case PIOCWSTOP:
	case PIOCLWPIDS:
	case PIOCGTRACE:
	case PIOCGENTRY:
	case PIOCGEXIT:
	case PIOCSRLC:
	case PIOCRRLC:
	case PIOCSFORK:
	case PIOCRFORK:
	case PIOCGREG:
	case PIOCGFPREG:
	case PIOCSTATUS:
	case PIOCLSTATUS:
	case PIOCPSINFO:
	case PIOCMAXSIG:
	case PIOCGXREGSIZE:
		break;
	case PIOCSXREG:		/* set extra registers */
	case PIOCGXREG:		/* get extra registers */
#if defined(__sparc)
		thingsize = sizeof (prxregset_t);
#else
		thingsize = 0;
#endif
		break;
	case PIOCACTION:
		thingsize = (nsig-1) * sizeof (struct sigaction);
		break;
	case PIOCGHOLD:
	case PIOCNMAP:
	case PIOCMAP:
	case PIOCGFAULT:
	case PIOCCFAULT:
	case PIOCCRED:
	case PIOCGROUPS:
	case PIOCUSAGE:
	case PIOCLUSAGE:
		break;
	case PIOCOPENPD:
		/*
		 * We will need this below.
		 * Allocate it now, before locking the process.
		 */
		xpnp = prgetnode(vp, PR_OPAGEDATA);
		break;
	case PIOCNAUXV:
	case PIOCAUXV:
		break;

#if defined(__i386) || defined(__amd64)
	case PIOCNLDT:
	case PIOCLDT:
		break;
#endif	/* __i386 || __amd64 */

#if defined(__sparc)
	case PIOCGWIN:
		thingsize = sizeof (gwindows_t);
		break;
#endif	/* __sparc */

	case PIOCOPENM:		/* open mapped object for reading */
		if (cmaddr == NULL)
			un.va = NULL;
		else if (copyin(cmaddr, &un.va, sizeof (un.va)))
			error = EFAULT;
		break;

	case PIOCRUN:		/* make lwp or process runnable */
		if (cmaddr == NULL)
			un.prrun.pr_flags = 0;
		else if (copyin(cmaddr, &un.prrun, sizeof (un.prrun)))
			error = EFAULT;
		break;

	case PIOCOPENLWP:	/* return /proc lwp file descriptor */
		if (copyin(cmaddr, &un.lwpid, sizeof (un.lwpid)))
			error = EFAULT;
		break;

	case PIOCSTRACE:	/* set signal trace mask */
		if (copyin(cmaddr, &un.smask, sizeof (un.smask)))
			error = EFAULT;
		break;

	case PIOCSSIG:		/* set current signal */
		if (cmaddr == NULL)
			un.info.si_signo = 0;
		else if (copyin(cmaddr, &un.info, sizeof (un.info)))
			error = EFAULT;
		break;

	case PIOCKILL:		/* send signal */
	case PIOCUNKILL:	/* delete a signal */
		if (copyin(cmaddr, &un.signo, sizeof (un.signo)))
			error = EFAULT;
		break;

	case PIOCNICE:		/* set nice priority */
		if (copyin(cmaddr, &un.nice, sizeof (un.nice)))
			error = EFAULT;
		break;

	case PIOCSENTRY:	/* set syscall entry bit mask */
	case PIOCSEXIT:		/* set syscall exit bit mask */
		if (copyin(cmaddr, &un.prmask, sizeof (un.prmask)))
			error = EFAULT;
		break;

	case PIOCSET:		/* set process flags */
	case PIOCRESET:		/* reset process flags */
		if (copyin(cmaddr, &un.flags, sizeof (un.flags)))
			error = EFAULT;
		break;

	case PIOCSREG:		/* set general registers */
		if (copyin(cmaddr, un.regs, sizeof (un.regs)))
			error = EFAULT;
		break;

	case PIOCSFPREG:	/* set floating-point registers */
		if (copyin(cmaddr, &un.fpregs, sizeof (un.fpregs)))
			error = EFAULT;
		break;

	case PIOCSHOLD:		/* set signal-hold mask */
		if (copyin(cmaddr, &un.holdmask, sizeof (un.holdmask)))
			error = EFAULT;
		break;

	case PIOCSFAULT:	/* set mask of traced faults */
		if (copyin(cmaddr, &un.fltmask, sizeof (un.fltmask)))
			error = EFAULT;
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error)
		return (error);

startover:
	/*
	 * If we need kmem_alloc()d space then we allocate it now, before
	 * grabbing the process lock.  Using kmem_alloc(KM_SLEEP) while
	 * holding the process lock leads to deadlock with the clock thread.
	 * (The clock thread wakes up the pageout daemon to free up space.
	 * If the clock thread blocks behind us and we are sleeping waiting
	 * for space, then space may never become available.)
	 */
	if (thingsize) {
		ASSERT(thing == NULL);
		thing = kmem_alloc(thingsize, KM_SLEEP);
	}

	switch (cmd) {
	case PIOCPSINFO:
	case PIOCGETPR:
	case PIOCUSAGE:
	case PIOCLUSAGE:
		zdisp = ZYES;
		break;
	case PIOCSXREG:		/* set extra registers */
		/*
		 * perform copyin before grabbing the process lock
		 */
		if (thing) {
			if (copyin(cmaddr, thing, thingsize)) {
				kmem_free(thing, thingsize);
				return (EFAULT);
			}
		}
		/* fall through... */
	default:
		zdisp = ZNO;
		break;
	}

	if ((error = prlock(pnp, zdisp)) != 0) {
		if (thing != NULL)
			kmem_free(thing, thingsize);
		if (xpnp)
			prfreenode(xpnp);
		return (error);
	}

	pcp = pnp->pr_common;
	p = pcp->prc_proc;
	ASSERT(p != NULL);

	/*
	 * Choose a thread/lwp for the operation.
	 */
	if (zdisp == ZNO && cmd != PIOCSTOP && cmd != PIOCWSTOP) {
		if (pnp->pr_type == PR_LWPIDFILE && cmd != PIOCLSTATUS) {
			t = pcp->prc_thread;
			ASSERT(t != NULL);
		} else {
			t = prchoose(p);	/* returns locked thread */
			ASSERT(t != NULL);
			thread_unlock(t);
		}
		lwp = ttolwp(t);
	}

	error = 0;
	switch (cmd) {

	case PIOCGETPR:		/* read struct proc */
	{
		proc_t *prp = thing;

		*prp = *p;
		prunlock(pnp);
		if (copyout(prp, cmaddr, sizeof (proc_t)))
			error = EFAULT;
		kmem_free(prp, sizeof (proc_t));
		thing = NULL;
		break;
	}

	case PIOCGETU:		/* read u-area */
	{
		user_t *userp = thing;

		up = PTOU(p);
		*userp = *up;
		prunlock(pnp);
		if (copyout(userp, cmaddr, sizeof (user_t)))
			error = EFAULT;
		kmem_free(userp, sizeof (user_t));
		thing = NULL;
		break;
	}

	case PIOCOPENM:		/* open mapped object for reading */
		error = propenm(pnp, cmaddr, un.va, rvalp, cr);
		/* propenm() called prunlock(pnp) */
		break;

	case PIOCSTOP:		/* stop process or lwp from running */
	case PIOCWSTOP:		/* wait for process or lwp to stop */
		/*
		 * Can't apply to a system process.
		 */
		if ((p->p_flag & SSYS) || p->p_as == &kas) {
			prunlock(pnp);
			error = EBUSY;
			break;
		}

		if (cmd == PIOCSTOP)
			pr_stop(pnp);

		/*
		 * If an lwp is waiting for itself or its process, don't wait.
		 * The stopped lwp would never see the fact that it is stopped.
		 */
		if ((pnp->pr_type == PR_LWPIDFILE)?
		    (pcp->prc_thread == curthread) : (p == curproc)) {
			if (cmd == PIOCWSTOP)
				error = EBUSY;
			prunlock(pnp);
			break;
		}

		if ((error = pr_wait_stop(pnp, (time_t)0)) != 0)
			break;	/* pr_wait_stop() unlocked the process */

		if (cmaddr == NULL)
			prunlock(pnp);
		else {
			/*
			 * Return process/lwp status information.
			 */
			t = pr_thread(pnp);	/* returns locked thread */
			thread_unlock(t);
			oprgetstatus(t, &un.prstat, VTOZONE(vp));
			prunlock(pnp);
			if (copyout(&un.prstat, cmaddr, sizeof (un.prstat)))
				error = EFAULT;
		}
		break;

	case PIOCRUN:		/* make lwp or process runnable */
	{
		long flags = un.prrun.pr_flags;

		/*
		 * Cannot set an lwp running is it is not stopped.
		 * Also, no lwp other than the /proc agent lwp can
		 * be set running so long as the /proc agent lwp exists.
		 */
		if ((!ISTOPPED(t) && !VSTOPPED(t) &&
		    !(t->t_proc_flag & TP_PRSTOP)) ||
		    (p->p_agenttp != NULL &&
		    (t != p->p_agenttp || pnp->pr_type != PR_LWPIDFILE))) {
			prunlock(pnp);
			error = EBUSY;
			break;
		}

		if (flags & (PRSHOLD|PRSTRACE|PRSFAULT|PRSVADDR))
			prsetrun(t, &un.prrun);

		error = pr_setrun(pnp, prmaprunflags(flags));

		prunlock(pnp);
		break;
	}

	case PIOCLWPIDS:	/* get array of lwp identifiers */
	{
		int nlwp;
		int Nlwp;
		id_t *idp;
		id_t *Bidp;

		Nlwp = nlwp = p->p_lwpcnt;

		if (thing && thingsize != (Nlwp+1) * sizeof (id_t)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = (Nlwp+1) * sizeof (id_t);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			prunlock(pnp);
			goto startover;
		}

		idp = thing;
		thing = NULL;
		Bidp = idp;
		if ((t = p->p_tlist) != NULL) {
			do {
				ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
				ASSERT(nlwp > 0);
				--nlwp;
				*idp++ = t->t_tid;
			} while ((t = t->t_forw) != p->p_tlist);
		}
		*idp = 0;
		ASSERT(nlwp == 0);
		prunlock(pnp);
		if (copyout(Bidp, cmaddr, (Nlwp+1) * sizeof (id_t)))
			error = EFAULT;
		kmem_free(Bidp, (Nlwp+1) * sizeof (id_t));
		break;
	}

	case PIOCOPENLWP:	/* return /proc lwp file descriptor */
	{
		vnode_t *xvp;
		int n;

		prunlock(pnp);
		if ((xvp = prlwpnode(pnp, un.lwpid)) == NULL)
			error = ENOENT;
		else if (error = fassign(&xvp, flag & (FREAD|FWRITE), &n)) {
			VN_RELE(xvp);
		} else
			*rvalp = n;
		break;
	}

	case PIOCOPENPD:	/* return /proc page data file descriptor */
	{
		vnode_t *xvp = PTOV(xpnp);
		vnode_t *dp = pnp->pr_parent;
		int n;

		if (pnp->pr_type == PR_LWPIDFILE) {
			dp = VTOP(dp)->pr_parent;
			dp = VTOP(dp)->pr_parent;
		}
		ASSERT(VTOP(dp)->pr_type == PR_PIDDIR);

		VN_HOLD(dp);
		pcp = pnp->pr_pcommon;
		xpnp->pr_ino = ptoi(pcp->prc_pid);
		xpnp->pr_common = pcp;
		xpnp->pr_pcommon = pcp;
		xpnp->pr_parent = dp;

		xpnp->pr_next = p->p_plist;
		p->p_plist = xvp;

		prunlock(pnp);
		if (error = fassign(&xvp, FREAD, &n)) {
			VN_RELE(xvp);
		} else
			*rvalp = n;

		xpnp = NULL;
		break;
	}

	case PIOCGTRACE:	/* get signal trace mask */
		prassignset(&un.smask, &p->p_sigmask);
		prunlock(pnp);
		if (copyout(&un.smask, cmaddr, sizeof (un.smask)))
			error = EFAULT;
		break;

	case PIOCSTRACE:	/* set signal trace mask */
		prdelset(&un.smask, SIGKILL);
		prassignset(&p->p_sigmask, &un.smask);
		if (!sigisempty(&p->p_sigmask))
			p->p_proc_flag |= P_PR_TRACE;
		else if (prisempty(&p->p_fltmask)) {
			up = PTOU(p);
			if (up->u_systrap == 0)
				p->p_proc_flag &= ~P_PR_TRACE;
		}
		prunlock(pnp);
		break;

	case PIOCSSIG:		/* set current signal */
		error = pr_setsig(pnp, &un.info);
		prunlock(pnp);
		if (un.info.si_signo == SIGKILL && error == 0)
			pr_wait_die(pnp);
		break;

	case PIOCKILL:		/* send signal */
	{
		int sig = (int)un.signo;

		error = pr_kill(pnp, sig, cr);
		prunlock(pnp);
		if (sig == SIGKILL && error == 0)
			pr_wait_die(pnp);
		break;
	}

	case PIOCUNKILL:	/* delete a signal */
		error = pr_unkill(pnp, (int)un.signo);
		prunlock(pnp);
		break;

	case PIOCNICE:		/* set nice priority */
		error = pr_nice(p, (int)un.nice, cr);
		prunlock(pnp);
		break;

	case PIOCGENTRY:	/* get syscall entry bit mask */
	case PIOCGEXIT:		/* get syscall exit bit mask */
		up = PTOU(p);
		if (cmd == PIOCGENTRY) {
			prassignset(&un.prmask, &up->u_entrymask);
		} else {
			prassignset(&un.prmask, &up->u_exitmask);
		}
		prunlock(pnp);
		if (copyout(&un.prmask, cmaddr, sizeof (un.prmask)))
			error = EFAULT;
		break;

	case PIOCSENTRY:	/* set syscall entry bit mask */
	case PIOCSEXIT:		/* set syscall exit bit mask */
		pr_setentryexit(p, &un.prmask, cmd == PIOCSENTRY);
		prunlock(pnp);
		break;

	case PIOCSRLC:		/* obsolete: set running on last /proc close */
		error = pr_set(p, prmapsetflags(PR_RLC));
		prunlock(pnp);
		break;

	case PIOCRRLC:		/* obsolete: reset run-on-last-close flag */
		error = pr_unset(p, prmapsetflags(PR_RLC));
		prunlock(pnp);
		break;

	case PIOCSFORK:		/* obsolete: set inherit-on-fork flag */
		error = pr_set(p, prmapsetflags(PR_FORK));
		prunlock(pnp);
		break;

	case PIOCRFORK:		/* obsolete: reset inherit-on-fork flag */
		error = pr_unset(p, prmapsetflags(PR_FORK));
		prunlock(pnp);
		break;

	case PIOCSET:		/* set process flags */
		error = pr_set(p, prmapsetflags(un.flags));
		prunlock(pnp);
		break;

	case PIOCRESET:		/* reset process flags */
		error = pr_unset(p, prmapsetflags(un.flags));
		prunlock(pnp);
		break;

	case PIOCGREG:		/* get general registers */
		if (t->t_state != TS_STOPPED && !VSTOPPED(t))
			bzero(un.regs, sizeof (un.regs));
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prgetprregs(lwp, un.regs);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (copyout(un.regs, cmaddr, sizeof (un.regs)))
			error = EFAULT;
		break;

	case PIOCSREG:		/* set general registers */
		if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t))
			error = EBUSY;
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prsetprregs(lwp, un.regs, 0);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		break;

	case PIOCGFPREG:	/* get floating-point registers */
		if (!prhasfp()) {
			prunlock(pnp);
			error = EINVAL;	/* No FP support */
			break;
		}

		if (t->t_state != TS_STOPPED && !VSTOPPED(t))
			bzero(&un.fpregs, sizeof (un.fpregs));
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prgetprfpregs(lwp, &un.fpregs);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (copyout(&un.fpregs, cmaddr, sizeof (un.fpregs)))
			error = EFAULT;
		break;

	case PIOCSFPREG:	/* set floating-point registers */
		if (!prhasfp())
			error = EINVAL;	/* No FP support */
		else if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t))
			error = EBUSY;
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prsetprfpregs(lwp, &un.fpregs);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		break;

	case PIOCGXREGSIZE:	/* get the size of the extra registers */
	{
		int xregsize;

		if (prhasx(p)) {
			xregsize = prgetprxregsize(p);
			prunlock(pnp);
			if (copyout(&xregsize, cmaddr, sizeof (xregsize)))
				error = EFAULT;
		} else {
			prunlock(pnp);
			error = EINVAL;	/* No extra register support */
		}
		break;
	}

	case PIOCGXREG:		/* get extra registers */
		if (prhasx(p)) {
			bzero(thing, thingsize);
			if (t->t_state == TS_STOPPED || VSTOPPED(t)) {
				/* drop p_lock to touch the stack */
				mutex_exit(&p->p_lock);
				prgetprxregs(lwp, thing);
				mutex_enter(&p->p_lock);
			}
			prunlock(pnp);
			if (copyout(thing, cmaddr, thingsize))
				error = EFAULT;
		} else {
			prunlock(pnp);
			error = EINVAL;	/* No extra register support */
		}
		if (thing) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		break;

	case PIOCSXREG:		/* set extra registers */
		if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t))
			error = EBUSY;
		else if (!prhasx(p))
			error = EINVAL;	/* No extra register support */
		else if (thing) {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prsetprxregs(lwp, thing);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (thing) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		break;

	case PIOCSTATUS:	/* get process/lwp status */
		oprgetstatus(t, &un.prstat, VTOZONE(vp));
		prunlock(pnp);
		if (copyout(&un.prstat, cmaddr, sizeof (un.prstat)))
			error = EFAULT;
		break;

	case PIOCLSTATUS:	/* get status for process & all lwps */
	{
		int Nlwp;
		int nlwp;
		prstatus_t *Bprsp;
		prstatus_t *prsp;

		nlwp = Nlwp = p->p_lwpcnt;

		if (thing && thingsize != (Nlwp+1) * sizeof (prstatus_t)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = (Nlwp+1) * sizeof (prstatus_t);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			prunlock(pnp);
			goto startover;
		}

		Bprsp = thing;
		thing = NULL;
		prsp = Bprsp;
		oprgetstatus(t, prsp, VTOZONE(vp));
		t = p->p_tlist;
		do {
			ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
			ASSERT(nlwp > 0);
			--nlwp;
			oprgetstatus(t, ++prsp, VTOZONE(vp));
		} while ((t = t->t_forw) != p->p_tlist);
		ASSERT(nlwp == 0);
		prunlock(pnp);
		if (copyout(Bprsp, cmaddr, (Nlwp+1) * sizeof (prstatus_t)))
			error = EFAULT;

		kmem_free(Bprsp, (Nlwp+1) * sizeof (prstatus_t));
		break;
	}

	case PIOCPSINFO:	/* get ps(1) information */
	{
		prpsinfo_t *psp = &un.prps;

		oprgetpsinfo(p, psp,
		    (pnp->pr_type == PR_LWPIDFILE)? pcp->prc_thread : NULL);

		prunlock(pnp);
		if (copyout(&un.prps, cmaddr, sizeof (un.prps)))
			error = EFAULT;
		break;
	}

	case PIOCMAXSIG:	/* get maximum signal number */
	{
		int n = nsig-1;

		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (n)))
			error = EFAULT;
		break;
	}

	case PIOCACTION:	/* get signal action structures */
	{
		uint_t sig;
		struct sigaction *sap = thing;

		up = PTOU(p);
		for (sig = 1; sig < nsig; sig++)
			prgetaction(p, up, sig, &sap[sig-1]);
		prunlock(pnp);
		if (copyout(sap, cmaddr, (nsig-1) * sizeof (struct sigaction)))
			error = EFAULT;
		kmem_free(sap, (nsig-1) * sizeof (struct sigaction));
		thing = NULL;
		break;
	}

	case PIOCGHOLD:		/* get signal-hold mask */
		schedctl_finish_sigblock(t);
		sigktou(&t->t_hold, &un.holdmask);
		prunlock(pnp);
		if (copyout(&un.holdmask, cmaddr, sizeof (un.holdmask)))
			error = EFAULT;
		break;

	case PIOCSHOLD:		/* set signal-hold mask */
		pr_sethold(pnp, &un.holdmask);
		prunlock(pnp);
		break;

	case PIOCNMAP:		/* get number of memory mappings */
	{
		int n;
		struct as *as = p->p_as;

		if ((p->p_flag & SSYS) || as == &kas)
			n = 0;
		else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_WRITER);
			n = prnsegs(as, 0);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (int)))
			error = EFAULT;
		break;
	}

	case PIOCMAP:		/* get memory map information */
	{
		list_t iolhead;
		struct as *as = p->p_as;

		if ((p->p_flag & SSYS) || as == &kas) {
			error = 0;
			prunlock(pnp);
		} else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_WRITER);
			error = oprgetmap(p, &iolhead);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
			prunlock(pnp);

			error = pr_iol_copyout_and_free(&iolhead,
			    &cmaddr, error);
		}
		/*
		 * The procfs PIOCMAP ioctl returns an all-zero buffer
		 * to indicate the end of the prmap[] array.
		 * Append it to whatever has already been copied out.
		 */
		bzero(&un.prmap, sizeof (un.prmap));
		if (!error && copyout(&un.prmap, cmaddr, sizeof (un.prmap)))
			error = EFAULT;

		break;
	}

	case PIOCGFAULT:	/* get mask of traced faults */
		prassignset(&un.fltmask, &p->p_fltmask);
		prunlock(pnp);
		if (copyout(&un.fltmask, cmaddr, sizeof (un.fltmask)))
			error = EFAULT;
		break;

	case PIOCSFAULT:	/* set mask of traced faults */
		pr_setfault(p, &un.fltmask);
		prunlock(pnp);
		break;

	case PIOCCFAULT:	/* clear current fault */
		lwp->lwp_curflt = 0;
		prunlock(pnp);
		break;

	case PIOCCRED:		/* get process credentials */
	{
		cred_t *cp;

		mutex_enter(&p->p_crlock);
		cp = p->p_cred;
		un.prcred.pr_euid = crgetuid(cp);
		un.prcred.pr_ruid = crgetruid(cp);
		un.prcred.pr_suid = crgetsuid(cp);
		un.prcred.pr_egid = crgetgid(cp);
		un.prcred.pr_rgid = crgetrgid(cp);
		un.prcred.pr_sgid = crgetsgid(cp);
		un.prcred.pr_ngroups = crgetngroups(cp);
		mutex_exit(&p->p_crlock);

		prunlock(pnp);
		if (copyout(&un.prcred, cmaddr, sizeof (un.prcred)))
			error = EFAULT;
		break;
	}

	case PIOCGROUPS:	/* get supplementary groups */
	{
		cred_t *cp;

		mutex_enter(&p->p_crlock);
		cp = p->p_cred;
		crhold(cp);
		mutex_exit(&p->p_crlock);

		prunlock(pnp);
		if (copyout(crgetgroups(cp), cmaddr,
		    MAX(crgetngroups(cp), 1) * sizeof (gid_t)))
			error = EFAULT;
		crfree(cp);
		break;
	}

	case PIOCUSAGE:		/* get usage info */
	{
		/*
		 * For an lwp file descriptor, return just the lwp usage.
		 * For a process file descriptor, return total usage,
		 * all current lwps plus all defunct lwps.
		 */
		prhusage_t *pup = &un.prhusage;
		prusage_t *upup;

		bzero(pup, sizeof (*pup));
		pup->pr_tstamp = gethrtime();

		if (pnp->pr_type == PR_LWPIDFILE) {
			t = pcp->prc_thread;
			if (t != NULL)
				prgetusage(t, pup);
			else
				error = ENOENT;
		} else {
			pup->pr_count  = p->p_defunct;
			pup->pr_create = p->p_mstart;
			pup->pr_term   = p->p_mterm;

			pup->pr_rtime    = p->p_mlreal;
			pup->pr_utime    = p->p_acct[LMS_USER];
			pup->pr_stime    = p->p_acct[LMS_SYSTEM];
			pup->pr_ttime    = p->p_acct[LMS_TRAP];
			pup->pr_tftime   = p->p_acct[LMS_TFAULT];
			pup->pr_dftime   = p->p_acct[LMS_DFAULT];
			pup->pr_kftime   = p->p_acct[LMS_KFAULT];
			pup->pr_ltime    = p->p_acct[LMS_USER_LOCK];
			pup->pr_slptime  = p->p_acct[LMS_SLEEP];
			pup->pr_wtime    = p->p_acct[LMS_WAIT_CPU];
			pup->pr_stoptime = p->p_acct[LMS_STOPPED];

			pup->pr_minf  = p->p_ru.minflt;
			pup->pr_majf  = p->p_ru.majflt;
			pup->pr_nswap = p->p_ru.nswap;
			pup->pr_inblk = p->p_ru.inblock;
			pup->pr_oublk = p->p_ru.oublock;
			pup->pr_msnd  = p->p_ru.msgsnd;
			pup->pr_mrcv  = p->p_ru.msgrcv;
			pup->pr_sigs  = p->p_ru.nsignals;
			pup->pr_vctx  = p->p_ru.nvcsw;
			pup->pr_ictx  = p->p_ru.nivcsw;
			pup->pr_sysc  = p->p_ru.sysc;
			pup->pr_ioch  = p->p_ru.ioch;

			/*
			 * Add the usage information for each active lwp.
			 */
			if ((t = p->p_tlist) != NULL &&
			    !(pcp->prc_flags & PRC_DESTROY)) {
				do {
					ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
					pup->pr_count++;
					praddusage(t, pup);
				} while ((t = t->t_forw) != p->p_tlist);
			}
		}

		prunlock(pnp);

		upup = kmem_zalloc(sizeof (*upup), KM_SLEEP);
		prcvtusage(&un.prhusage, upup);
		if (copyout(upup, cmaddr, sizeof (*upup)))
			error = EFAULT;
		kmem_free(upup, sizeof (*upup));

		break;
	}

	case PIOCLUSAGE:	/* get detailed usage info */
	{
		int Nlwp;
		int nlwp;
		prusage_t *upup;
		prusage_t *Bupup;
		prhusage_t *pup;
		hrtime_t curtime;

		nlwp = Nlwp = (pcp->prc_flags & PRC_DESTROY)? 0 : p->p_lwpcnt;

		if (thing && thingsize !=
		    sizeof (prhusage_t) + (Nlwp+1) * sizeof (prusage_t)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = sizeof (prhusage_t) +
			    (Nlwp+1) * sizeof (prusage_t);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			prunlock(pnp);
			goto startover;
		}

		pup = thing;
		upup = Bupup = (prusage_t *)(pup + 1);

		ASSERT(p == pcp->prc_proc);

		curtime = gethrtime();

		/*
		 * First the summation over defunct lwps.
		 */
		bzero(pup, sizeof (*pup));
		pup->pr_count  = p->p_defunct;
		pup->pr_tstamp = curtime;
		pup->pr_create = p->p_mstart;
		pup->pr_term   = p->p_mterm;

		pup->pr_rtime    = p->p_mlreal;
		pup->pr_utime    = p->p_acct[LMS_USER];
		pup->pr_stime    = p->p_acct[LMS_SYSTEM];
		pup->pr_ttime    = p->p_acct[LMS_TRAP];
		pup->pr_tftime   = p->p_acct[LMS_TFAULT];
		pup->pr_dftime   = p->p_acct[LMS_DFAULT];
		pup->pr_kftime   = p->p_acct[LMS_KFAULT];
		pup->pr_ltime    = p->p_acct[LMS_USER_LOCK];
		pup->pr_slptime  = p->p_acct[LMS_SLEEP];
		pup->pr_wtime    = p->p_acct[LMS_WAIT_CPU];
		pup->pr_stoptime = p->p_acct[LMS_STOPPED];

		pup->pr_minf  = p->p_ru.minflt;
		pup->pr_majf  = p->p_ru.majflt;
		pup->pr_nswap = p->p_ru.nswap;
		pup->pr_inblk = p->p_ru.inblock;
		pup->pr_oublk = p->p_ru.oublock;
		pup->pr_msnd  = p->p_ru.msgsnd;
		pup->pr_mrcv  = p->p_ru.msgrcv;
		pup->pr_sigs  = p->p_ru.nsignals;
		pup->pr_vctx  = p->p_ru.nvcsw;
		pup->pr_ictx  = p->p_ru.nivcsw;
		pup->pr_sysc  = p->p_ru.sysc;
		pup->pr_ioch  = p->p_ru.ioch;

		prcvtusage(pup, upup);

		/*
		 * Fill one prusage struct for each active lwp.
		 */
		if ((t = p->p_tlist) != NULL &&
		    !(pcp->prc_flags & PRC_DESTROY)) {
			do {
				ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
				ASSERT(nlwp > 0);
				--nlwp;
				upup++;
				prgetusage(t, pup);
				prcvtusage(pup, upup);
			} while ((t = t->t_forw) != p->p_tlist);
		}
		ASSERT(nlwp == 0);

		prunlock(pnp);
		if (copyout(Bupup, cmaddr, (Nlwp+1) * sizeof (prusage_t)))
			error = EFAULT;
		kmem_free(thing, thingsize);
		thing = NULL;
		break;
	}

	case PIOCNAUXV:		/* get number of aux vector entries */
	{
		int n = __KERN_NAUXV_IMPL;

		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (int)))
			error = EFAULT;
		break;
	}

	case PIOCAUXV:		/* get aux vector (see sys/auxv.h) */
	{
		up = PTOU(p);
		bcopy(up->u_auxv, un.auxv,
		    __KERN_NAUXV_IMPL * sizeof (auxv_t));
		prunlock(pnp);
		if (copyout(un.auxv, cmaddr,
		    __KERN_NAUXV_IMPL * sizeof (auxv_t)))
			error = EFAULT;
		break;
	}

#if defined(__i386) || defined(__amd64)
	case PIOCNLDT:		/* get number of LDT entries */
	{
		int n;

		mutex_exit(&p->p_lock);
		mutex_enter(&p->p_ldtlock);
		n = prnldt(p);
		mutex_exit(&p->p_ldtlock);
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (n)))
			error = EFAULT;
		break;
	}

	case PIOCLDT:		/* get LDT entries */
	{
		struct ssd *ssd;
		int n;

		mutex_exit(&p->p_lock);
		mutex_enter(&p->p_ldtlock);
		n = prnldt(p);

		if (thing && thingsize != (n+1) * sizeof (*ssd)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = (n+1) * sizeof (*ssd);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			mutex_exit(&p->p_ldtlock);
			mutex_enter(&p->p_lock);
			prunlock(pnp);
			goto startover;
		}

		ssd = thing;
		thing = NULL;
		if (n != 0)
			prgetldt(p, ssd);
		mutex_exit(&p->p_ldtlock);
		mutex_enter(&p->p_lock);
		prunlock(pnp);

		/* mark the end of the list with a null entry */
		bzero(&ssd[n], sizeof (*ssd));
		if (copyout(ssd, cmaddr, (n+1) * sizeof (*ssd)))
			error = EFAULT;
		kmem_free(ssd, (n+1) * sizeof (*ssd));
		break;
	}
#endif	/* __i386 || __amd64 */

#if defined(__sparc)
	case PIOCGWIN:		/* get gwindows_t (see sys/reg.h) */
	{
		gwindows_t *gwp = thing;

		/* drop p->p_lock while touching the stack */
		mutex_exit(&p->p_lock);
		bzero(gwp, sizeof (*gwp));
		prgetwindows(lwp, gwp);
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		if (copyout(gwp, cmaddr, sizeof (*gwp)))
			error = EFAULT;
		kmem_free(gwp, sizeof (gwindows_t));
		thing = NULL;
		break;
	}
#endif	/* __sparc */

	default:
		prunlock(pnp);
		error = EINVAL;
		break;

	}

	ASSERT(thing == NULL);
	ASSERT(xpnp == NULL);
	return (error);
}

#ifdef _SYSCALL32_IMPL

static int oprgetmap32(proc_t *, list_t *);

void
oprgetstatus32(kthread_t *t, prstatus32_t *sp, zone_t *zp)
{
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	int32_t flags;
	user_t *up;
	ulong_t instr;

	ASSERT(MUTEX_HELD(&p->p_lock));

	up = PTOU(p);
	bzero(sp, sizeof (*sp));
	flags = 0L;
	if (t->t_state == TS_STOPPED) {
		flags |= PR_STOPPED;
		if ((t->t_schedflag & TS_PSTART) == 0)
			flags |= PR_ISTOP;
	} else if (VSTOPPED(t)) {
		flags |= PR_STOPPED|PR_ISTOP;
	}
	if (!(flags & PR_ISTOP) && (t->t_proc_flag & TP_PRSTOP))
		flags |= PR_DSTOP;
	if (lwp->lwp_asleep)
		flags |= PR_ASLEEP;
	if (p->p_proc_flag & P_PR_FORK)
		flags |= PR_FORK;
	if (p->p_proc_flag & P_PR_RUNLCL)
		flags |= PR_RLC;
	if (p->p_proc_flag & P_PR_KILLCL)
		flags |= PR_KLC;
	if (p->p_proc_flag & P_PR_ASYNC)
		flags |= PR_ASYNC;
	if (p->p_proc_flag & P_PR_BPTADJ)
		flags |= PR_BPTADJ;
	if (p->p_proc_flag & P_PR_PTRACE)
		flags |= PR_PCOMPAT;
	if (t->t_proc_flag & TP_MSACCT)
		flags |= PR_MSACCT;
	sp->pr_flags = flags;
	if (VSTOPPED(t)) {
		sp->pr_why   = PR_REQUESTED;
		sp->pr_what  = 0;
	} else {
		sp->pr_why   = t->t_whystop;
		sp->pr_what  = t->t_whatstop;
	}

	if (t->t_whystop == PR_FAULTED) {
		siginfo_kto32(&lwp->lwp_siginfo, &sp->pr_info);
		if (t->t_whatstop == FLTPAGE)
			sp->pr_info.si_addr =
			    (caddr32_t)(uintptr_t)lwp->lwp_siginfo.si_addr;
	} else if (lwp->lwp_curinfo)
		siginfo_kto32(&lwp->lwp_curinfo->sq_info, &sp->pr_info);

	if (SI_FROMUSER(&lwp->lwp_siginfo) && zp->zone_id != GLOBAL_ZONEID &&
	    sp->pr_info.si_zoneid != zp->zone_id) {
		sp->pr_info.si_pid = zp->zone_zsched->p_pid;
		sp->pr_info.si_uid = 0;
		sp->pr_info.si_ctid = -1;
		sp->pr_info.si_zoneid = zp->zone_id;
	}

	sp->pr_cursig  = lwp->lwp_cursig;
	prassignset(&sp->pr_sigpend, &p->p_sig);
	prassignset(&sp->pr_lwppend, &t->t_sig);
	schedctl_finish_sigblock(t);
	prassignset(&sp->pr_sighold, &t->t_hold);
	sp->pr_altstack.ss_sp =
	    (caddr32_t)(uintptr_t)lwp->lwp_sigaltstack.ss_sp;
	sp->pr_altstack.ss_size = (size32_t)lwp->lwp_sigaltstack.ss_size;
	sp->pr_altstack.ss_flags = (int32_t)lwp->lwp_sigaltstack.ss_flags;
	prgetaction32(p, up, lwp->lwp_cursig, &sp->pr_action);
	sp->pr_pid   = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		sp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		sp->pr_ppid = p->p_ppid;
	}
	sp->pr_pgrp  = p->p_pgrp;
	sp->pr_sid   = p->p_sessp->s_sid;
	hrt2ts32(mstate_aggr_state(p, LMS_USER), &sp->pr_utime);
	hrt2ts32(mstate_aggr_state(p, LMS_SYSTEM), &sp->pr_stime);
	TICK_TO_TIMESTRUC32(p->p_cutime, &sp->pr_cutime);
	TICK_TO_TIMESTRUC32(p->p_cstime, &sp->pr_cstime);
	(void) strncpy(sp->pr_clname, sclass[t->t_cid].cl_name,
	    sizeof (sp->pr_clname) - 1);
	sp->pr_who = t->t_tid;
	sp->pr_nlwp = p->p_lwpcnt;
	sp->pr_brkbase = (caddr32_t)(uintptr_t)p->p_brkbase;
	sp->pr_brksize = (size32_t)p->p_brksize;
	sp->pr_stkbase = (caddr32_t)(uintptr_t)prgetstackbase(p);
	sp->pr_stksize = (size32_t)p->p_stksize;
	sp->pr_oldcontext = (caddr32_t)lwp->lwp_oldcontext;
	sp->pr_processor = t->t_cpu->cpu_id;
	sp->pr_bind = t->t_bind_cpu;

	/*
	 * Fetch the current instruction, if not a system process.
	 * We don't attempt this unless the lwp is stopped.
	 */
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		sp->pr_flags |= (PR_ISSYS|PR_PCINVAL);
	else if (!(flags & PR_STOPPED))
		sp->pr_flags |= PR_PCINVAL;
	else if (!prfetchinstr(lwp, &instr))
		sp->pr_flags |= PR_PCINVAL;
	else
		sp->pr_instr = (uint32_t)instr;

	/*
	 * Drop p_lock while touching the lwp's stack.
	 */
	mutex_exit(&p->p_lock);
	if (prisstep(lwp))
		sp->pr_flags |= PR_STEP;
	if ((flags & (PR_STOPPED|PR_ASLEEP)) && t->t_sysnum) {
		int i;
		auxv_t *auxp;

		sp->pr_syscall = get_syscall32_args(lwp,
		    (int *)sp->pr_sysarg, &i);
		sp->pr_nsysarg = (short)i;
		if (t->t_whystop == PR_SYSEXIT && t->t_sysnum == SYS_execve) {
			sp->pr_sysarg[0] = 0;
			sp->pr_sysarg[1] = (caddr32_t)up->u_argv;
			sp->pr_sysarg[2] = (caddr32_t)up->u_envp;
			for (i = 0, auxp = up->u_auxv;
			    i < sizeof (up->u_auxv) / sizeof (up->u_auxv[0]);
			    i++, auxp++) {
				if (auxp->a_type == AT_SUN_EXECNAME) {
					sp->pr_sysarg[0] =
					    (caddr32_t)
					    (uintptr_t)auxp->a_un.a_ptr;
					break;
				}
			}
		}
	}
	if ((flags & PR_STOPPED) || t == curthread)
		prgetprregs32(lwp, sp->pr_reg);
	mutex_enter(&p->p_lock);
}

void
oprgetpsinfo32(proc_t *p, prpsinfo32_t *psp, kthread_t *tp)
{
	kthread_t *t;
	char c, state;
	user_t *up;
	dev_t d;
	uint64_t pct;
	int retval, niceval;
	cred_t *cred;
	struct as *as;
	hrtime_t hrutime, hrstime, cur_time;

	ASSERT(MUTEX_HELD(&p->p_lock));

	bzero(psp, sizeof (*psp));

	if ((t = tp) == NULL)
		t = prchoose(p);	/* returns locked thread */
	else
		thread_lock(t);

	/* kludge: map thread state enum into process state enum */

	if (t == NULL) {
		state = TS_ZOMB;
	} else {
		state = VSTOPPED(t) ? TS_STOPPED : t->t_state;
		thread_unlock(t);
	}

	switch (state) {
	case TS_SLEEP:		state = SSLEEP;		break;
	case TS_RUN:		state = SRUN;		break;
	case TS_ONPROC:		state = SONPROC;	break;
	case TS_ZOMB:		state = SZOMB;		break;
	case TS_STOPPED:	state = SSTOP;		break;
	default:		state = 0;		break;
	}
	switch (state) {
	case SSLEEP:	c = 'S';	break;
	case SRUN:	c = 'R';	break;
	case SZOMB:	c = 'Z';	break;
	case SSTOP:	c = 'T';	break;
	case SIDL:	c = 'I';	break;
	case SONPROC:	c = 'O';	break;
#ifdef SXBRK
	case SXBRK:	c = 'X';	break;
#endif
	default:	c = '?';	break;
	}
	psp->pr_state = state;
	psp->pr_sname = c;
	psp->pr_zomb = (state == SZOMB);
	/*
	 * only export SSYS and SMSACCT; everything else is off-limits to
	 * userland apps.
	 */
	psp->pr_flag = p->p_flag & (SSYS | SMSACCT);

	mutex_enter(&p->p_crlock);
	cred = p->p_cred;
	psp->pr_uid = crgetruid(cred);
	psp->pr_gid = crgetrgid(cred);
	psp->pr_euid = crgetuid(cred);
	psp->pr_egid = crgetgid(cred);
	mutex_exit(&p->p_crlock);

	psp->pr_pid = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		psp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		psp->pr_ppid = p->p_ppid;
	}
	psp->pr_pgrp = p->p_pgrp;
	psp->pr_sid = p->p_sessp->s_sid;
	psp->pr_addr = 0;	/* cannot represent 64-bit addr in 32 bits */
	hrutime = mstate_aggr_state(p, LMS_USER);
	hrstime = mstate_aggr_state(p, LMS_SYSTEM);
	hrt2ts32(hrutime + hrstime, &psp->pr_time);
	TICK_TO_TIMESTRUC32(p->p_cutime + p->p_cstime, &psp->pr_ctime);
	switch (p->p_model) {
	case DATAMODEL_ILP32:
		psp->pr_dmodel = PR_MODEL_ILP32;
		break;
	case DATAMODEL_LP64:
		psp->pr_dmodel = PR_MODEL_LP64;
		break;
	}
	if (state == SZOMB || t == NULL) {
		int wcode = p->p_wcode;		/* must be atomic read */

		if (wcode)
			psp->pr_wstat = wstat(wcode, p->p_wdata);
		psp->pr_lttydev = PRNODEV32;
		psp->pr_ottydev = (o_dev_t)PRNODEV32;
		psp->pr_size = 0;
		psp->pr_rssize = 0;
		psp->pr_pctmem = 0;
	} else {
		up = PTOU(p);
		psp->pr_wchan = 0;	/* cannot represent in 32 bits */
		psp->pr_pri = t->t_pri;
		(void) strncpy(psp->pr_clname, sclass[t->t_cid].cl_name,
		    sizeof (psp->pr_clname) - 1);
		retval = CL_DONICE(t, NULL, 0, &niceval);
		if (retval == 0) {
			psp->pr_oldpri = v.v_maxsyspri - psp->pr_pri;
			psp->pr_nice = niceval + NZERO;
		} else {
			psp->pr_oldpri = 0;
			psp->pr_nice = 0;
		}
		d = cttydev(p);
#ifdef sun
		{
			extern dev_t rwsconsdev, rconsdev, uconsdev;
			/*
			 * If the controlling terminal is the real
			 * or workstation console device, map to what the
			 * user thinks is the console device. Handle case when
			 * rwsconsdev or rconsdev is set to NODEV for Starfire.
			 */
			if ((d == rwsconsdev || d == rconsdev) && d != NODEV)
				d = uconsdev;
		}
#endif
		(void) cmpldev(&psp->pr_lttydev, d);
		psp->pr_ottydev = cmpdev(d);
		TIMESPEC_TO_TIMESPEC32(&psp->pr_start, &up->u_start);
		bcopy(up->u_comm, psp->pr_fname,
		    MIN(sizeof (up->u_comm), sizeof (psp->pr_fname)-1));
		bcopy(up->u_psargs, psp->pr_psargs,
		    MIN(PRARGSZ-1, PSARGSZ));
		psp->pr_syscall = t->t_sysnum;
		psp->pr_argc = up->u_argc;
		psp->pr_argv = (caddr32_t)up->u_argv;
		psp->pr_envp = (caddr32_t)up->u_envp;

		/* compute %cpu for the lwp or process */
		pct = 0;
		if ((t = tp) == NULL)
			t = p->p_tlist;
		cur_time = gethrtime_unscaled();
		do {
			pct += cpu_update_pct(t, cur_time);
			if (tp != NULL)		/* just do the one lwp */
				break;
		} while ((t = t->t_forw) != p->p_tlist);

		psp->pr_pctcpu = prgetpctcpu(pct);
		psp->pr_cpu = (psp->pr_pctcpu*100 + 0x6000) >> 15; /* [0..99] */
		if (psp->pr_cpu > 99)
			psp->pr_cpu = 99;

		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
			psp->pr_size = 0;
			psp->pr_rssize = 0;
			psp->pr_pctmem = 0;
		} else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_READER);
			psp->pr_size = (size32_t)btopr(as->a_resvsize);
			psp->pr_rssize = (size32_t)rm_asrss(as);
			psp->pr_pctmem = rm_pctmemory(as);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
		}
	}
	psp->pr_bysize = (size32_t)ptob(psp->pr_size);
	psp->pr_byrssize = (size32_t)ptob(psp->pr_rssize);

	/*
	 * If we are looking at an LP64 process, zero out
	 * the fields that cannot be represented in ILP32.
	 */
	if (p->p_model != DATAMODEL_ILP32) {
		psp->pr_size = 0;
		psp->pr_rssize = 0;
		psp->pr_bysize = 0;
		psp->pr_byrssize = 0;
		psp->pr_argv = 0;
		psp->pr_envp = 0;
	}
}

/*ARGSUSED*/
static int
prioctl32(
	struct vnode *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
	caddr_t cmaddr = (caddr_t)arg;
	proc_t *p;
	user_t *up;
	kthread_t *t;
	klwp_t *lwp;
	prnode_t *pnp = VTOP(vp);
	prcommon_t *pcp;
	prnode_t *xpnp = NULL;
	int error;
	int zdisp;
	void *thing = NULL;
	size_t thingsize = 0;

	/*
	 * For copyin()/copyout().
	 */
	union {
		caddr32_t	va;
		int		signo;
		int		nice;
		uint_t		lwpid;
		int32_t		flags;
		prstatus32_t	prstat;
		prrun32_t	prrun;
		sigset_t	smask;
		siginfo32_t	info;
		sysset_t	prmask;
		prgregset32_t	regs;
		prfpregset32_t	fpregs;
		prpsinfo32_t	prps;
		sigset_t	holdmask;
		fltset_t	fltmask;
		prcred_t	prcred;
		prusage32_t	prusage;
		prhusage_t	prhusage;
		ioc_prmap32_t	prmap;
		auxv32_t	auxv[__KERN_NAUXV_IMPL];
	} un32;

	/*
	 * Native objects for internal use.
	 */
	union {
		caddr_t		va;
		int		signo;
		int		nice;
		uint_t		lwpid;
		long		flags;
		prstatus_t	prstat;
		prrun_t		prrun;
		sigset_t	smask;
		siginfo_t	info;
		sysset_t	prmask;
		prgregset_t	regs;
		prpsinfo_t	prps;
		sigset_t	holdmask;
		fltset_t	fltmask;
		prcred_t	prcred;
		prusage_t	prusage;
		prhusage_t	prhusage;
		auxv_t		auxv[__KERN_NAUXV_IMPL];
	} un;

	if (pnp->pr_type == PR_TMPL)
		return (prctioctl(pnp, cmd, arg, flag, cr));

	/*
	 * Support for old /proc interface.
	 */
	if (pnp->pr_pidfile != NULL) {
		ASSERT(pnp->pr_type == PR_PIDDIR);
		vp = pnp->pr_pidfile;
		pnp = VTOP(vp);
		ASSERT(pnp->pr_type == PR_PIDFILE);
	}

	if (pnp->pr_type != PR_PIDFILE && pnp->pr_type != PR_LWPIDFILE)
		return (ENOTTY);

	/*
	 * Fail ioctls which are logically "write" requests unless
	 * the user has write permission.
	 */
	if ((flag & FWRITE) == 0 && isprwrioctl(cmd))
		return (EBADF);

	/*
	 * Perform any necessary copyin() operations before
	 * locking the process.  Helps avoid deadlocks and
	 * improves performance.
	 *
	 * Also, detect invalid ioctl codes here to avoid
	 * locking a process unnnecessarily.
	 *
	 * Also, prepare to allocate space that will be needed below,
	 * case by case.
	 */
	error = 0;
	switch (cmd) {
	case PIOCGETPR:
		thingsize = sizeof (proc_t);
		break;
	case PIOCGETU:
		thingsize = sizeof (user_t);
		break;
	case PIOCSTOP:
	case PIOCWSTOP:
	case PIOCLWPIDS:
	case PIOCGTRACE:
	case PIOCGENTRY:
	case PIOCGEXIT:
	case PIOCSRLC:
	case PIOCRRLC:
	case PIOCSFORK:
	case PIOCRFORK:
	case PIOCGREG:
	case PIOCGFPREG:
	case PIOCSTATUS:
	case PIOCLSTATUS:
	case PIOCPSINFO:
	case PIOCMAXSIG:
	case PIOCGXREGSIZE:
		break;
	case PIOCSXREG:		/* set extra registers */
	case PIOCGXREG:		/* get extra registers */
#if defined(__sparc)
		thingsize = sizeof (prxregset_t);
#else
		thingsize = 0;
#endif
		break;
	case PIOCACTION:
		thingsize = (nsig-1) * sizeof (struct sigaction32);
		break;
	case PIOCGHOLD:
	case PIOCNMAP:
	case PIOCMAP:
	case PIOCGFAULT:
	case PIOCCFAULT:
	case PIOCCRED:
	case PIOCGROUPS:
	case PIOCUSAGE:
	case PIOCLUSAGE:
		break;
	case PIOCOPENPD:
		/*
		 * We will need this below.
		 * Allocate it now, before locking the process.
		 */
		xpnp = prgetnode(vp, PR_OPAGEDATA);
		break;
	case PIOCNAUXV:
	case PIOCAUXV:
		break;

#if defined(__i386) || defined(__i386_COMPAT)
	case PIOCNLDT:
	case PIOCLDT:
		break;
#endif	/* __i386 || __i386_COMPAT */

#if defined(__sparc)
	case PIOCGWIN:
		thingsize = sizeof (gwindows32_t);
		break;
#endif	/* __sparc */

	case PIOCOPENM:		/* open mapped object for reading */
		if (cmaddr == NULL)
			un32.va = NULL;
		else if (copyin(cmaddr, &un32.va, sizeof (un32.va)))
			error = EFAULT;
		break;

	case PIOCRUN:		/* make lwp or process runnable */
		if (cmaddr == NULL)
			un32.prrun.pr_flags = 0;
		else if (copyin(cmaddr, &un32.prrun, sizeof (un32.prrun)))
			error = EFAULT;
		break;

	case PIOCOPENLWP:	/* return /proc lwp file descriptor */
		if (copyin(cmaddr, &un32.lwpid, sizeof (un32.lwpid)))
			error = EFAULT;
		break;

	case PIOCSTRACE:	/* set signal trace mask */
		if (copyin(cmaddr, &un32.smask, sizeof (un32.smask)))
			error = EFAULT;
		break;

	case PIOCSSIG:		/* set current signal */
		if (cmaddr == NULL)
			un32.info.si_signo = 0;
		else if (copyin(cmaddr, &un32.info, sizeof (un32.info)))
			error = EFAULT;
		break;

	case PIOCKILL:		/* send signal */
	case PIOCUNKILL:	/* delete a signal */
		if (copyin(cmaddr, &un32.signo, sizeof (un32.signo)))
			error = EFAULT;
		break;

	case PIOCNICE:		/* set nice priority */
		if (copyin(cmaddr, &un32.nice, sizeof (un32.nice)))
			error = EFAULT;
		break;

	case PIOCSENTRY:	/* set syscall entry bit mask */
	case PIOCSEXIT:		/* set syscall exit bit mask */
		if (copyin(cmaddr, &un32.prmask, sizeof (un32.prmask)))
			error = EFAULT;
		break;

	case PIOCSET:		/* set process flags */
	case PIOCRESET:		/* reset process flags */
		if (copyin(cmaddr, &un32.flags, sizeof (un32.flags)))
			error = EFAULT;
		break;

	case PIOCSREG:		/* set general registers */
		if (copyin(cmaddr, un32.regs, sizeof (un32.regs)))
			error = EFAULT;
		break;

	case PIOCSFPREG:	/* set floating-point registers */
		if (copyin(cmaddr, &un32.fpregs, sizeof (un32.fpregs)))
			error = EFAULT;
		break;

	case PIOCSHOLD:		/* set signal-hold mask */
		if (copyin(cmaddr, &un32.holdmask, sizeof (un32.holdmask)))
			error = EFAULT;
		break;

	case PIOCSFAULT:	/* set mask of traced faults */
		if (copyin(cmaddr, &un32.fltmask, sizeof (un32.fltmask)))
			error = EFAULT;
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error)
		return (error);

startover:
	/*
	 * If we need kmem_alloc()d space then we allocate it now, before
	 * grabbing the process lock.  Using kmem_alloc(KM_SLEEP) while
	 * holding the process lock leads to deadlock with the clock thread.
	 * (The clock thread wakes up the pageout daemon to free up space.
	 * If the clock thread blocks behind us and we are sleeping waiting
	 * for space, then space may never become available.)
	 */
	if (thingsize) {
		ASSERT(thing == NULL);
		thing = kmem_alloc(thingsize, KM_SLEEP);
	}

	switch (cmd) {
	case PIOCPSINFO:
	case PIOCGETPR:
	case PIOCUSAGE:
	case PIOCLUSAGE:
		zdisp = ZYES;
		break;
	case PIOCSXREG:		/* set extra registers */
		/*
		 * perform copyin before grabbing the process lock
		 */
		if (thing) {
			if (copyin(cmaddr, thing, thingsize)) {
				kmem_free(thing, thingsize);
				return (EFAULT);
			}
		}
		/* fall through... */
	default:
		zdisp = ZNO;
		break;
	}

	if ((error = prlock(pnp, zdisp)) != 0) {
		if (thing != NULL)
			kmem_free(thing, thingsize);
		if (xpnp)
			prfreenode(xpnp);
		return (error);
	}

	pcp = pnp->pr_common;
	p = pcp->prc_proc;
	ASSERT(p != NULL);

	/*
	 * Choose a thread/lwp for the operation.
	 */
	if (zdisp == ZNO && cmd != PIOCSTOP && cmd != PIOCWSTOP) {
		if (pnp->pr_type == PR_LWPIDFILE && cmd != PIOCLSTATUS) {
			t = pcp->prc_thread;
			ASSERT(t != NULL);
		} else {
			t = prchoose(p);	/* returns locked thread */
			ASSERT(t != NULL);
			thread_unlock(t);
		}
		lwp = ttolwp(t);
	}

	error = 0;
	switch (cmd) {

	case PIOCGETPR:		/* read struct proc */
	{
		proc_t *prp = thing;

		*prp = *p;
		prunlock(pnp);
		if (copyout(prp, cmaddr, sizeof (proc_t)))
			error = EFAULT;
		kmem_free(prp, sizeof (proc_t));
		thing = NULL;
		break;
	}

	case PIOCGETU:		/* read u-area */
	{
		user_t *userp = thing;

		up = PTOU(p);
		*userp = *up;
		prunlock(pnp);
		if (copyout(userp, cmaddr, sizeof (user_t)))
			error = EFAULT;
		kmem_free(userp, sizeof (user_t));
		thing = NULL;
		break;
	}

	case PIOCOPENM:		/* open mapped object for reading */
		if (PROCESS_NOT_32BIT(p) && cmaddr != NULL) {
			prunlock(pnp);
			error = EOVERFLOW;
			break;
		}
		error = propenm(pnp, cmaddr,
		    (caddr_t)(uintptr_t)un32.va, rvalp, cr);
		/* propenm() called prunlock(pnp) */
		break;

	case PIOCSTOP:		/* stop process or lwp from running */
	case PIOCWSTOP:		/* wait for process or lwp to stop */
		/*
		 * Can't apply to a system process.
		 */
		if ((p->p_flag & SSYS) || p->p_as == &kas) {
			prunlock(pnp);
			error = EBUSY;
			break;
		}

		if (cmd == PIOCSTOP)
			pr_stop(pnp);

		/*
		 * If an lwp is waiting for itself or its process, don't wait.
		 * The lwp will never see the fact that itself is stopped.
		 */
		if ((pnp->pr_type == PR_LWPIDFILE)?
		    (pcp->prc_thread == curthread) : (p == curproc)) {
			if (cmd == PIOCWSTOP)
				error = EBUSY;
			prunlock(pnp);
			break;
		}

		if ((error = pr_wait_stop(pnp, (time_t)0)) != 0)
			break;	/* pr_wait_stop() unlocked the process */

		if (cmaddr == NULL)
			prunlock(pnp);
		else if (PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			error = EOVERFLOW;
		} else {
			/*
			 * Return process/lwp status information.
			 */
			t = pr_thread(pnp);	/* returns locked thread */
			thread_unlock(t);
			oprgetstatus32(t, &un32.prstat, VTOZONE(vp));
			prunlock(pnp);
			if (copyout(&un32.prstat, cmaddr, sizeof (un32.prstat)))
				error = EFAULT;
		}
		break;

	case PIOCRUN:		/* make lwp or process runnable */
	{
		long flags = un32.prrun.pr_flags;

		/*
		 * Cannot set an lwp running is it is not stopped.
		 * Also, no lwp other than the /proc agent lwp can
		 * be set running so long as the /proc agent lwp exists.
		 */
		if ((!ISTOPPED(t) && !VSTOPPED(t) &&
		    !(t->t_proc_flag & TP_PRSTOP)) ||
		    (p->p_agenttp != NULL &&
		    (t != p->p_agenttp || pnp->pr_type != PR_LWPIDFILE))) {
			prunlock(pnp);
			error = EBUSY;
			break;
		}

		if ((flags & PRSVADDR) && PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			error = EOVERFLOW;
			break;
		}

		if (flags & (PRSHOLD|PRSTRACE|PRSFAULT|PRSVADDR)) {
			un.prrun.pr_flags = (int)flags;
			un.prrun.pr_trace = un32.prrun.pr_trace;
			un.prrun.pr_sighold = un32.prrun.pr_sighold;
			un.prrun.pr_fault = un32.prrun.pr_fault;
			un.prrun.pr_vaddr =
			    (caddr_t)(uintptr_t)un32.prrun.pr_vaddr;
			prsetrun(t, &un.prrun);
		}

		error = pr_setrun(pnp, prmaprunflags(flags));

		prunlock(pnp);
		break;
	}

	case PIOCLWPIDS:	/* get array of lwp identifiers */
	{
		int nlwp;
		int Nlwp;
		id_t *idp;
		id_t *Bidp;

		Nlwp = nlwp = p->p_lwpcnt;

		if (thing && thingsize != (Nlwp+1) * sizeof (id_t)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = (Nlwp+1) * sizeof (id_t);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			prunlock(pnp);
			goto startover;
		}

		idp = thing;
		thing = NULL;
		Bidp = idp;
		if ((t = p->p_tlist) != NULL) {
			do {
				ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
				ASSERT(nlwp > 0);
				--nlwp;
				*idp++ = t->t_tid;
			} while ((t = t->t_forw) != p->p_tlist);
		}
		*idp = 0;
		ASSERT(nlwp == 0);
		prunlock(pnp);
		if (copyout(Bidp, cmaddr, (Nlwp+1) * sizeof (id_t)))
			error = EFAULT;
		kmem_free(Bidp, (Nlwp+1) * sizeof (id_t));
		break;
	}

	case PIOCOPENLWP:	/* return /proc lwp file descriptor */
	{
		vnode_t *xvp;
		int n;

		prunlock(pnp);
		if ((xvp = prlwpnode(pnp, un32.lwpid)) == NULL)
			error = ENOENT;
		else if (error = fassign(&xvp, flag & (FREAD|FWRITE), &n)) {
			VN_RELE(xvp);
		} else
			*rvalp = n;
		break;
	}

	case PIOCOPENPD:	/* return /proc page data file descriptor */
	{
		vnode_t *xvp = PTOV(xpnp);
		vnode_t *dp = pnp->pr_parent;
		int n;

		if (PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			prfreenode(xpnp);
			xpnp = NULL;
			error = EOVERFLOW;
			break;
		}

		if (pnp->pr_type == PR_LWPIDFILE) {
			dp = VTOP(dp)->pr_parent;
			dp = VTOP(dp)->pr_parent;
		}
		ASSERT(VTOP(dp)->pr_type == PR_PIDDIR);

		VN_HOLD(dp);
		pcp = pnp->pr_pcommon;
		xpnp->pr_ino = ptoi(pcp->prc_pid);
		xpnp->pr_common = pcp;
		xpnp->pr_pcommon = pcp;
		xpnp->pr_parent = dp;

		xpnp->pr_next = p->p_plist;
		p->p_plist = xvp;

		prunlock(pnp);
		if (error = fassign(&xvp, FREAD, &n)) {
			VN_RELE(xvp);
		} else
			*rvalp = n;

		xpnp = NULL;
		break;
	}

	case PIOCGTRACE:	/* get signal trace mask */
		prassignset(&un32.smask, &p->p_sigmask);
		prunlock(pnp);
		if (copyout(&un32.smask, cmaddr, sizeof (un32.smask)))
			error = EFAULT;
		break;

	case PIOCSTRACE:	/* set signal trace mask */
		prdelset(&un32.smask, SIGKILL);
		prassignset(&p->p_sigmask, &un32.smask);
		if (!sigisempty(&p->p_sigmask))
			p->p_proc_flag |= P_PR_TRACE;
		else if (prisempty(&p->p_fltmask)) {
			up = PTOU(p);
			if (up->u_systrap == 0)
				p->p_proc_flag &= ~P_PR_TRACE;
		}
		prunlock(pnp);
		break;

	case PIOCSSIG:		/* set current signal */
		if (un32.info.si_signo != 0 && PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			error = EOVERFLOW;
		} else {
			bzero(&un.info, sizeof (un.info));
			siginfo_32tok(&un32.info, (k_siginfo_t *)&un.info);
			error = pr_setsig(pnp, &un.info);
			prunlock(pnp);
			if (un32.info.si_signo == SIGKILL && error == 0)
				pr_wait_die(pnp);
		}
		break;

	case PIOCKILL:		/* send signal */
		error = pr_kill(pnp, un32.signo, cr);
		prunlock(pnp);
		if (un32.signo == SIGKILL && error == 0)
			pr_wait_die(pnp);
		break;

	case PIOCUNKILL:	/* delete a signal */
		error = pr_unkill(pnp, un32.signo);
		prunlock(pnp);
		break;

	case PIOCNICE:		/* set nice priority */
		error = pr_nice(p, un32.nice, cr);
		prunlock(pnp);
		break;

	case PIOCGENTRY:	/* get syscall entry bit mask */
	case PIOCGEXIT:		/* get syscall exit bit mask */
		up = PTOU(p);
		if (cmd == PIOCGENTRY) {
			prassignset(&un32.prmask, &up->u_entrymask);
		} else {
			prassignset(&un32.prmask, &up->u_exitmask);
		}
		prunlock(pnp);
		if (copyout(&un32.prmask, cmaddr, sizeof (un32.prmask)))
			error = EFAULT;
		break;

	case PIOCSENTRY:	/* set syscall entry bit mask */
	case PIOCSEXIT:		/* set syscall exit bit mask */
		pr_setentryexit(p, &un32.prmask, cmd == PIOCSENTRY);
		prunlock(pnp);
		break;

	case PIOCSRLC:		/* obsolete: set running on last /proc close */
		error = pr_set(p, prmapsetflags(PR_RLC));
		prunlock(pnp);
		break;

	case PIOCRRLC:		/* obsolete: reset run-on-last-close flag */
		error = pr_unset(p, prmapsetflags(PR_RLC));
		prunlock(pnp);
		break;

	case PIOCSFORK:		/* obsolete: set inherit-on-fork flag */
		error = pr_set(p, prmapsetflags(PR_FORK));
		prunlock(pnp);
		break;

	case PIOCRFORK:		/* obsolete: reset inherit-on-fork flag */
		error = pr_unset(p, prmapsetflags(PR_FORK));
		prunlock(pnp);
		break;

	case PIOCSET:		/* set process flags */
		error = pr_set(p, prmapsetflags((long)un32.flags));
		prunlock(pnp);
		break;

	case PIOCRESET:		/* reset process flags */
		error = pr_unset(p, prmapsetflags((long)un32.flags));
		prunlock(pnp);
		break;

	case PIOCGREG:		/* get general registers */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else if (t->t_state != TS_STOPPED && !VSTOPPED(t))
			bzero(un32.regs, sizeof (un32.regs));
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prgetprregs32(lwp, un32.regs);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (error == 0 &&
		    copyout(un32.regs, cmaddr, sizeof (un32.regs)))
			error = EFAULT;
		break;

	case PIOCSREG:		/* set general registers */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t))
			error = EBUSY;
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prgregset_32ton(lwp, un32.regs, un.regs);
			prsetprregs(lwp, un.regs, 0);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		break;

	case PIOCGFPREG:	/* get floating-point registers */
		if (!prhasfp())
			error = EINVAL;	/* No FP support */
		else if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else if (t->t_state != TS_STOPPED && !VSTOPPED(t))
			bzero(&un32.fpregs, sizeof (un32.fpregs));
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prgetprfpregs32(lwp, &un32.fpregs);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (error == 0 &&
		    copyout(&un32.fpregs, cmaddr, sizeof (un32.fpregs)))
			error = EFAULT;
		break;

	case PIOCSFPREG:	/* set floating-point registers */
		if (!prhasfp())
			error = EINVAL;	/* No FP support */
		else if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t))
			error = EBUSY;
		else {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prsetprfpregs32(lwp, &un32.fpregs);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		break;

	case PIOCGXREGSIZE:	/* get the size of the extra registers */
	{
		int xregsize;

		if (prhasx(p)) {
			xregsize = prgetprxregsize(p);
			prunlock(pnp);
			if (copyout(&xregsize, cmaddr, sizeof (xregsize)))
				error = EFAULT;
		} else {
			prunlock(pnp);
			error = EINVAL;	/* No extra register support */
		}
		break;
	}

	case PIOCGXREG:		/* get extra registers */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else if (!prhasx(p))
			error = EINVAL;	/* No extra register support */
		else {
			bzero(thing, thingsize);
			if (t->t_state == TS_STOPPED || VSTOPPED(t)) {
				/* drop p_lock to touch the stack */
				mutex_exit(&p->p_lock);
				prgetprxregs(lwp, thing);
				mutex_enter(&p->p_lock);
			}
		}
		prunlock(pnp);
		if (error == 0 &&
		    copyout(thing, cmaddr, thingsize))
			error = EFAULT;
		if (thing) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		break;

	case PIOCSXREG:		/* set extra registers */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t))
			error = EBUSY;
		else if (!prhasx(p))
			error = EINVAL;	/* No extra register support */
		else if (thing) {
			/* drop p_lock while touching the lwp's stack */
			mutex_exit(&p->p_lock);
			prsetprxregs(lwp, thing);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (thing) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		break;

	case PIOCSTATUS:	/* get process/lwp status */
		if (PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			error = EOVERFLOW;
			break;
		}
		oprgetstatus32(t, &un32.prstat, VTOZONE(vp));
		prunlock(pnp);
		if (copyout(&un32.prstat, cmaddr, sizeof (un32.prstat)))
			error = EFAULT;
		break;

	case PIOCLSTATUS:	/* get status for process & all lwps */
	{
		int Nlwp;
		int nlwp;
		prstatus32_t *Bprsp;
		prstatus32_t *prsp;

		if (PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			if (thing) {
				kmem_free(thing, thingsize);
				thing = NULL;
			}
			error = EOVERFLOW;
			break;
		}

		nlwp = Nlwp = p->p_lwpcnt;

		if (thing && thingsize != (Nlwp+1) * sizeof (prstatus32_t)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = (Nlwp+1) * sizeof (prstatus32_t);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			prunlock(pnp);
			goto startover;
		}

		Bprsp = (prstatus32_t *)thing;
		thing = NULL;
		prsp = Bprsp;
		oprgetstatus32(t, prsp, VTOZONE(vp));
		t = p->p_tlist;
		do {
			ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
			ASSERT(nlwp > 0);
			--nlwp;
			oprgetstatus32(t, ++prsp, VTOZONE(vp));
		} while ((t = t->t_forw) != p->p_tlist);
		ASSERT(nlwp == 0);
		prunlock(pnp);
		if (copyout(Bprsp, cmaddr, (Nlwp+1) * sizeof (prstatus32_t)))
			error = EFAULT;

		kmem_free(Bprsp, (Nlwp + 1) * sizeof (prstatus32_t));
		break;
	}

	case PIOCPSINFO:	/* get ps(1) information */
	{
		prpsinfo32_t *psp = &un32.prps;

		oprgetpsinfo32(p, psp,
		    (pnp->pr_type == PR_LWPIDFILE)? pcp->prc_thread : NULL);

		prunlock(pnp);
		if (copyout(&un32.prps, cmaddr, sizeof (un32.prps)))
			error = EFAULT;
		break;
	}

	case PIOCMAXSIG:	/* get maximum signal number */
	{
		int n = nsig-1;

		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (int)))
			error = EFAULT;
		break;
	}

	case PIOCACTION:	/* get signal action structures */
	{
		uint_t sig;
		struct sigaction32 *sap = thing;

		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else {
			up = PTOU(p);
			for (sig = 1; sig < nsig; sig++)
				prgetaction32(p, up, sig, &sap[sig-1]);
		}
		prunlock(pnp);
		if (error == 0 &&
		    copyout(sap, cmaddr, (nsig-1)*sizeof (struct sigaction32)))
			error = EFAULT;
		kmem_free(sap, (nsig-1)*sizeof (struct sigaction32));
		thing = NULL;
		break;
	}

	case PIOCGHOLD:		/* get signal-hold mask */
		schedctl_finish_sigblock(t);
		sigktou(&t->t_hold, &un32.holdmask);
		prunlock(pnp);
		if (copyout(&un32.holdmask, cmaddr, sizeof (un32.holdmask)))
			error = EFAULT;
		break;

	case PIOCSHOLD:		/* set signal-hold mask */
		pr_sethold(pnp, &un32.holdmask);
		prunlock(pnp);
		break;

	case PIOCNMAP:		/* get number of memory mappings */
	{
		int n;
		struct as *as = p->p_as;

		if ((p->p_flag & SSYS) || as == &kas)
			n = 0;
		else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_WRITER);
			n = prnsegs(as, 0);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (int)))
			error = EFAULT;
		break;
	}

	case PIOCMAP:		/* get memory map information */
	{
		list_t iolhead;
		struct as *as = p->p_as;

		if ((p->p_flag & SSYS) || as == &kas) {
			error = 0;
			prunlock(pnp);
		} else if (PROCESS_NOT_32BIT(p)) {
			error = EOVERFLOW;
			prunlock(pnp);
		} else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_WRITER);
			error = oprgetmap32(p, &iolhead);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
			prunlock(pnp);

			error = pr_iol_copyout_and_free(&iolhead,
			    &cmaddr, error);
		}
		/*
		 * The procfs PIOCMAP ioctl returns an all-zero buffer
		 * to indicate the end of the prmap[] array.
		 * Append it to whatever has already been copied out.
		 */
		bzero(&un32.prmap, sizeof (un32.prmap));
		if (!error &&
		    copyout(&un32.prmap, cmaddr, sizeof (un32.prmap)))
				error = EFAULT;
		break;
	}

	case PIOCGFAULT:	/* get mask of traced faults */
		prassignset(&un32.fltmask, &p->p_fltmask);
		prunlock(pnp);
		if (copyout(&un32.fltmask, cmaddr, sizeof (un32.fltmask)))
			error = EFAULT;
		break;

	case PIOCSFAULT:	/* set mask of traced faults */
		pr_setfault(p, &un32.fltmask);
		prunlock(pnp);
		break;

	case PIOCCFAULT:	/* clear current fault */
		lwp->lwp_curflt = 0;
		prunlock(pnp);
		break;

	case PIOCCRED:		/* get process credentials */
	{
		cred_t *cp;

		mutex_enter(&p->p_crlock);
		cp = p->p_cred;
		un32.prcred.pr_euid = crgetuid(cp);
		un32.prcred.pr_ruid = crgetruid(cp);
		un32.prcred.pr_suid = crgetsuid(cp);
		un32.prcred.pr_egid = crgetgid(cp);
		un32.prcred.pr_rgid = crgetrgid(cp);
		un32.prcred.pr_sgid = crgetsgid(cp);
		un32.prcred.pr_ngroups = crgetngroups(cp);
		mutex_exit(&p->p_crlock);

		prunlock(pnp);
		if (copyout(&un32.prcred, cmaddr, sizeof (un32.prcred)))
			error = EFAULT;
		break;
	}

	case PIOCGROUPS:	/* get supplementary groups */
	{
		cred_t *cp;

		mutex_enter(&p->p_crlock);
		cp = p->p_cred;
		crhold(cp);
		mutex_exit(&p->p_crlock);

		prunlock(pnp);
		if (copyout(crgetgroups(cp), cmaddr,
		    MAX(crgetngroups(cp), 1) * sizeof (gid_t)))
			error = EFAULT;
		crfree(cp);
		break;
	}

	case PIOCUSAGE:		/* get usage info */
	{
		/*
		 * For an lwp file descriptor, return just the lwp usage.
		 * For a process file descriptor, return total usage,
		 * all current lwps plus all defunct lwps.
		 */
		prhusage_t *pup = &un32.prhusage;
		prusage32_t *upup;

		bzero(pup, sizeof (*pup));
		pup->pr_tstamp = gethrtime();

		if (pnp->pr_type == PR_LWPIDFILE) {
			t = pcp->prc_thread;
			if (t != NULL)
				prgetusage(t, pup);
			else
				error = ENOENT;
		} else {
			pup->pr_count  = p->p_defunct;
			pup->pr_create = p->p_mstart;
			pup->pr_term   = p->p_mterm;

			pup->pr_rtime    = p->p_mlreal;
			pup->pr_utime    = p->p_acct[LMS_USER];
			pup->pr_stime    = p->p_acct[LMS_SYSTEM];
			pup->pr_ttime    = p->p_acct[LMS_TRAP];
			pup->pr_tftime   = p->p_acct[LMS_TFAULT];
			pup->pr_dftime   = p->p_acct[LMS_DFAULT];
			pup->pr_kftime   = p->p_acct[LMS_KFAULT];
			pup->pr_ltime    = p->p_acct[LMS_USER_LOCK];
			pup->pr_slptime  = p->p_acct[LMS_SLEEP];
			pup->pr_wtime    = p->p_acct[LMS_WAIT_CPU];
			pup->pr_stoptime = p->p_acct[LMS_STOPPED];

			pup->pr_minf  = p->p_ru.minflt;
			pup->pr_majf  = p->p_ru.majflt;
			pup->pr_nswap = p->p_ru.nswap;
			pup->pr_inblk = p->p_ru.inblock;
			pup->pr_oublk = p->p_ru.oublock;
			pup->pr_msnd  = p->p_ru.msgsnd;
			pup->pr_mrcv  = p->p_ru.msgrcv;
			pup->pr_sigs  = p->p_ru.nsignals;
			pup->pr_vctx  = p->p_ru.nvcsw;
			pup->pr_ictx  = p->p_ru.nivcsw;
			pup->pr_sysc  = p->p_ru.sysc;
			pup->pr_ioch  = p->p_ru.ioch;

			/*
			 * Add the usage information for each active lwp.
			 */
			if ((t = p->p_tlist) != NULL &&
			    !(pcp->prc_flags & PRC_DESTROY)) {
				do {
					ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
					pup->pr_count++;
					praddusage(t, pup);
				} while ((t = t->t_forw) != p->p_tlist);
			}
		}

		prunlock(pnp);

		upup = kmem_alloc(sizeof (*upup), KM_SLEEP);
		prcvtusage32(pup, upup);
		if (copyout(upup, cmaddr, sizeof (*upup)))
			error = EFAULT;
		kmem_free(upup, sizeof (*upup));

		break;
	}

	case PIOCLUSAGE:	/* get detailed usage info */
	{
		int Nlwp;
		int nlwp;
		prusage32_t *upup;
		prusage32_t *Bupup;
		prhusage_t *pup;
		hrtime_t curtime;

		nlwp = Nlwp = (pcp->prc_flags & PRC_DESTROY)? 0 : p->p_lwpcnt;

		if (thing && thingsize !=
		    sizeof (prhusage_t) + (Nlwp+1) * sizeof (prusage32_t)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = sizeof (prhusage_t) +
			    (Nlwp+1) * sizeof (prusage32_t);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			prunlock(pnp);
			goto startover;
		}

		pup = (prhusage_t *)thing;
		upup = Bupup = (prusage32_t *)(pup + 1);

		ASSERT(p == pcp->prc_proc);

		curtime = gethrtime();

		/*
		 * First the summation over defunct lwps.
		 */
		bzero(pup, sizeof (*pup));
		pup->pr_count  = p->p_defunct;
		pup->pr_tstamp = curtime;
		pup->pr_create = p->p_mstart;
		pup->pr_term   = p->p_mterm;

		pup->pr_rtime    = p->p_mlreal;
		pup->pr_utime    = p->p_acct[LMS_USER];
		pup->pr_stime    = p->p_acct[LMS_SYSTEM];
		pup->pr_ttime    = p->p_acct[LMS_TRAP];
		pup->pr_tftime   = p->p_acct[LMS_TFAULT];
		pup->pr_dftime   = p->p_acct[LMS_DFAULT];
		pup->pr_kftime   = p->p_acct[LMS_KFAULT];
		pup->pr_ltime    = p->p_acct[LMS_USER_LOCK];
		pup->pr_slptime  = p->p_acct[LMS_SLEEP];
		pup->pr_wtime    = p->p_acct[LMS_WAIT_CPU];
		pup->pr_stoptime = p->p_acct[LMS_STOPPED];

		pup->pr_minf  = p->p_ru.minflt;
		pup->pr_majf  = p->p_ru.majflt;
		pup->pr_nswap = p->p_ru.nswap;
		pup->pr_inblk = p->p_ru.inblock;
		pup->pr_oublk = p->p_ru.oublock;
		pup->pr_msnd  = p->p_ru.msgsnd;
		pup->pr_mrcv  = p->p_ru.msgrcv;
		pup->pr_sigs  = p->p_ru.nsignals;
		pup->pr_vctx  = p->p_ru.nvcsw;
		pup->pr_ictx  = p->p_ru.nivcsw;
		pup->pr_sysc  = p->p_ru.sysc;
		pup->pr_ioch  = p->p_ru.ioch;

		prcvtusage32(pup, upup);

		/*
		 * Fill one prusage struct for each active lwp.
		 */
		if ((t = p->p_tlist) != NULL &&
		    !(pcp->prc_flags & PRC_DESTROY)) {
			do {
				ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
				ASSERT(nlwp > 0);
				--nlwp;
				upup++;
				prgetusage(t, pup);
				prcvtusage32(pup, upup);
			} while ((t = t->t_forw) != p->p_tlist);
		}
		ASSERT(nlwp == 0);

		prunlock(pnp);
		if (copyout(Bupup, cmaddr, (Nlwp+1) * sizeof (prusage32_t)))
			error = EFAULT;
		kmem_free(thing, thingsize);
		thing = NULL;
		break;
	}

	case PIOCNAUXV:		/* get number of aux vector entries */
	{
		int n = __KERN_NAUXV_IMPL;

		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (int)))
			error = EFAULT;
		break;
	}

	case PIOCAUXV:		/* get aux vector (see sys/auxv.h) */
	{
		int i;

		if (PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			error = EOVERFLOW;
		} else {
			up = PTOU(p);
			for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
				un32.auxv[i].a_type = up->u_auxv[i].a_type;
				un32.auxv[i].a_un.a_val =
				    (int32_t)up->u_auxv[i].a_un.a_val;
			}
			prunlock(pnp);
			if (copyout(un32.auxv, cmaddr,
			    __KERN_NAUXV_IMPL * sizeof (auxv32_t)))
				error = EFAULT;
		}
		break;
	}

#if defined(__i386) || defined(__i386_COMPAT)
	case PIOCNLDT:		/* get number of LDT entries */
	{
		int n;

		mutex_exit(&p->p_lock);
		mutex_enter(&p->p_ldtlock);
		n = prnldt(p);
		mutex_exit(&p->p_ldtlock);
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		if (copyout(&n, cmaddr, sizeof (n)))
			error = EFAULT;
		break;
	}

	case PIOCLDT:		/* get LDT entries */
	{
		struct ssd *ssd;
		int n;

		mutex_exit(&p->p_lock);
		mutex_enter(&p->p_ldtlock);
		n = prnldt(p);

		if (thing && thingsize != (n+1) * sizeof (*ssd)) {
			kmem_free(thing, thingsize);
			thing = NULL;
		}
		if (thing == NULL) {
			thingsize = (n+1) * sizeof (*ssd);
			thing = kmem_alloc(thingsize, KM_NOSLEEP);
		}
		if (thing == NULL) {
			mutex_exit(&p->p_ldtlock);
			mutex_enter(&p->p_lock);
			prunlock(pnp);
			goto startover;
		}

		ssd = thing;
		thing = NULL;
		if (n != 0)
			prgetldt(p, ssd);
		mutex_exit(&p->p_ldtlock);
		mutex_enter(&p->p_lock);
		prunlock(pnp);

		/* mark the end of the list with a null entry */
		bzero(&ssd[n], sizeof (*ssd));
		if (copyout(ssd, cmaddr, (n+1) * sizeof (*ssd)))
			error = EFAULT;
		kmem_free(ssd, (n+1) * sizeof (*ssd));
		break;
	}
#endif	/* __i386 || __i386_COMPAT */

#if defined(__sparc)
	case PIOCGWIN:		/* get gwindows_t (see sys/reg.h) */
	{
		gwindows32_t *gwp = thing;

		if (PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			error = EOVERFLOW;
		} else {
			/* drop p->p_lock while touching the stack */
			mutex_exit(&p->p_lock);
			bzero(gwp, sizeof (*gwp));
			prgetwindows32(lwp, gwp);
			mutex_enter(&p->p_lock);
			prunlock(pnp);
			if (copyout(gwp, cmaddr, sizeof (*gwp)))
				error = EFAULT;
		}
		kmem_free(gwp, sizeof (*gwp));
		thing = NULL;
		break;
	}
#endif	/* __sparc */

	default:
		prunlock(pnp);
		error = EINVAL;
		break;

	}

	ASSERT(thing == NULL);
	ASSERT(xpnp == NULL);
	return (error);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Distinguish "writeable" ioctl requests from others.
 */
static int
isprwrioctl(int cmd)
{
	switch (cmd) {
	case PIOCSTOP:
	case PIOCRUN:
	case PIOCSTRACE:
	case PIOCSSIG:
	case PIOCKILL:
	case PIOCUNKILL:
	case PIOCNICE:
	case PIOCSENTRY:
	case PIOCSEXIT:
	case PIOCSRLC:
	case PIOCRRLC:
	case PIOCSREG:
	case PIOCSFPREG:
	case PIOCSXREG:
	case PIOCSHOLD:
	case PIOCSFAULT:
	case PIOCCFAULT:
	case PIOCSFORK:
	case PIOCRFORK:
	case PIOCSET:
	case PIOCRESET:
		return (1);
	}
	return (0);
}

/*
 * Map the ioctl() interface run flags to the new interface run flags.
 */
static ulong_t
prmaprunflags(long flags)
{
	ulong_t newflags = 0;

	if (flags & PRCSIG)
		newflags |= 0x01;
	if (flags & PRCFAULT)
		newflags |= 0x02;
	if (flags & PRSTEP)
		newflags |= 0x04;
	if (flags & PRSABORT)
		newflags |= 0x08;
	if (flags & PRSTOP)
		newflags |= 0x10;
	return (newflags);
}

/*
 * Map the ioctl() interface settable mode flags to the new interface flags.
 */
static long
prmapsetflags(long flags)
{
	long newflags = 0;

#define	ALLFLAGS	\
	(PR_FORK|PR_RLC|PR_KLC|PR_ASYNC|PR_BPTADJ|PR_MSACCT|PR_PCOMPAT)

	if (flags & ~ALLFLAGS)
		newflags = 0xffff;	/* forces EINVAL */
	if (flags & PR_FORK)
		newflags |= (0x00100000 | 0x08000000);
	if (flags & PR_RLC)
		newflags |= 0x00200000;
	if (flags & PR_KLC)
		newflags |= 0x00400000;
	if (flags & PR_ASYNC)
		newflags |= 0x00800000;
	if (flags & PR_MSACCT)
		newflags |= 0x01000000;
	if (flags & PR_BPTADJ)
		newflags |= 0x02000000;
	if (flags & PR_PCOMPAT)
		newflags |= 0x04000000;
	return (newflags);
}

/*
 * Apply PIOCRUN options specific to the ioctl() interface.
 */
static void
prsetrun(kthread_t *t, prrun_t *prp)
{
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	long flags = prp->pr_flags;
	user_t *up = PTOU(p);

	ASSERT(MUTEX_HELD(&p->p_lock));

	if (flags & PRSHOLD) {
		schedctl_finish_sigblock(t);
		sigutok(&prp->pr_sighold, &t->t_hold);
		t->t_sig_check = 1;	/* so ISSIG will be done */
	}
	if (flags & PRSTRACE) {
		prdelset(&prp->pr_trace, SIGKILL);
		prassignset(&p->p_sigmask, &prp->pr_trace);
		if (!sigisempty(&p->p_sigmask))
			p->p_proc_flag |= P_PR_TRACE;
		else if (prisempty(&p->p_fltmask)) {
			if (up->u_systrap == 0)
				p->p_proc_flag &= ~P_PR_TRACE;
		}
	}
	if (flags & PRSFAULT) {
		prassignset(&p->p_fltmask, &prp->pr_fault);
		if (!prisempty(&p->p_fltmask))
			p->p_proc_flag |= P_PR_TRACE;
		else if (sigisempty(&p->p_sigmask)) {
			if (up->u_systrap == 0)
				p->p_proc_flag &= ~P_PR_TRACE;
		}
	}
	/*
	 * prsvaddr() must be called before prstep() because
	 * stepping can depend on the current value of the PC.
	 * We drop p_lock while touching the lwp's registers (on stack).
	 */
	if (flags & PRSVADDR) {
		mutex_exit(&p->p_lock);
		prsvaddr(lwp, prp->pr_vaddr);
		mutex_enter(&p->p_lock);
	}
}

/*
 * Common code for PIOCOPENM
 * Returns with the process unlocked.
 */
static int
propenm(prnode_t *pnp, caddr_t cmaddr, caddr_t va, int *rvalp, cred_t *cr)
{
	proc_t *p = pnp->pr_common->prc_proc;
	struct as *as = p->p_as;
	int error = 0;
	struct seg *seg;
	struct vnode *xvp;
	int n;

	/*
	 * By fiat, a system process has no address space.
	 */
	if ((p->p_flag & SSYS) || as == &kas) {
		error = EINVAL;
	} else if (cmaddr) {
		/*
		 * We drop p_lock before grabbing the address
		 * space lock in order to avoid a deadlock with
		 * the clock thread.  The process will not
		 * disappear and its address space will not
		 * change because it is marked P_PR_LOCK.
		 */
		mutex_exit(&p->p_lock);
		AS_LOCK_ENTER(as, RW_READER);
		seg = as_segat(as, va);
		if (seg != NULL &&
		    seg->s_ops == &segvn_ops &&
		    SEGOP_GETVP(seg, va, &xvp) == 0 &&
		    xvp != NULL &&
		    xvp->v_type == VREG) {
			VN_HOLD(xvp);
		} else {
			error = EINVAL;
		}
		AS_LOCK_EXIT(as);
		mutex_enter(&p->p_lock);
	} else if ((xvp = p->p_exec) == NULL) {
		error = EINVAL;
	} else {
		VN_HOLD(xvp);
	}

	prunlock(pnp);

	if (error == 0) {
		if ((error = VOP_ACCESS(xvp, VREAD, 0, cr, NULL)) == 0)
			error = fassign(&xvp, FREAD, &n);
		if (error) {
			VN_RELE(xvp);
		} else {
			*rvalp = n;
		}
	}

	return (error);
}

/*
 * Return old version of process/lwp status.
 * The u-block is mapped in by this routine and unmapped at the end.
 */
void
oprgetstatus(kthread_t *t, prstatus_t *sp, zone_t *zp)
{
	proc_t *p = ttoproc(t);
	klwp_t *lwp = ttolwp(t);
	int flags;
	user_t *up;
	ulong_t instr;

	ASSERT(MUTEX_HELD(&p->p_lock));

	up = PTOU(p);
	bzero(sp, sizeof (*sp));
	flags = 0;
	if (t->t_state == TS_STOPPED) {
		flags |= PR_STOPPED;
		if ((t->t_schedflag & TS_PSTART) == 0)
			flags |= PR_ISTOP;
	} else if (VSTOPPED(t)) {
		flags |= PR_STOPPED|PR_ISTOP;
	}
	if (!(flags & PR_ISTOP) && (t->t_proc_flag & TP_PRSTOP))
		flags |= PR_DSTOP;
	if (lwp->lwp_asleep)
		flags |= PR_ASLEEP;
	if (p->p_proc_flag & P_PR_FORK)
		flags |= PR_FORK;
	if (p->p_proc_flag & P_PR_RUNLCL)
		flags |= PR_RLC;
	if (p->p_proc_flag & P_PR_KILLCL)
		flags |= PR_KLC;
	if (p->p_proc_flag & P_PR_ASYNC)
		flags |= PR_ASYNC;
	if (p->p_proc_flag & P_PR_BPTADJ)
		flags |= PR_BPTADJ;
	if (p->p_proc_flag & P_PR_PTRACE)
		flags |= PR_PCOMPAT;
	if (t->t_proc_flag & TP_MSACCT)
		flags |= PR_MSACCT;
	sp->pr_flags = flags;
	if (VSTOPPED(t)) {
		sp->pr_why   = PR_REQUESTED;
		sp->pr_what  = 0;
	} else {
		sp->pr_why   = t->t_whystop;
		sp->pr_what  = t->t_whatstop;
	}

	if (t->t_whystop == PR_FAULTED)
		bcopy(&lwp->lwp_siginfo,
		    &sp->pr_info, sizeof (k_siginfo_t));
	else if (lwp->lwp_curinfo)
		bcopy(&lwp->lwp_curinfo->sq_info,
		    &sp->pr_info, sizeof (k_siginfo_t));

	if (SI_FROMUSER(&lwp->lwp_siginfo) && zp->zone_id != GLOBAL_ZONEID &&
	    sp->pr_info.si_zoneid != zp->zone_id) {
		sp->pr_info.si_pid = zp->zone_zsched->p_pid;
		sp->pr_info.si_uid = 0;
		sp->pr_info.si_ctid = -1;
		sp->pr_info.si_zoneid = zp->zone_id;
	}

	sp->pr_cursig  = lwp->lwp_cursig;
	prassignset(&sp->pr_sigpend, &p->p_sig);
	prassignset(&sp->pr_lwppend, &t->t_sig);
	schedctl_finish_sigblock(t);
	prassignset(&sp->pr_sighold, &t->t_hold);
	sp->pr_altstack = lwp->lwp_sigaltstack;
	prgetaction(p, up, lwp->lwp_cursig, &sp->pr_action);
	sp->pr_pid   = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		sp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		sp->pr_ppid = p->p_ppid;
	}
	sp->pr_pgrp  = p->p_pgrp;
	sp->pr_sid   = p->p_sessp->s_sid;
	hrt2ts(mstate_aggr_state(p, LMS_USER), &sp->pr_utime);
	hrt2ts(mstate_aggr_state(p, LMS_SYSTEM), &sp->pr_stime);
	TICK_TO_TIMESTRUC(p->p_cutime, &sp->pr_cutime);
	TICK_TO_TIMESTRUC(p->p_cstime, &sp->pr_cstime);
	(void) strncpy(sp->pr_clname, sclass[t->t_cid].cl_name,
	    sizeof (sp->pr_clname) - 1);
	sp->pr_who = t->t_tid;
	sp->pr_nlwp = p->p_lwpcnt;
	sp->pr_brkbase = p->p_brkbase;
	sp->pr_brksize = p->p_brksize;
	sp->pr_stkbase = prgetstackbase(p);
	sp->pr_stksize = p->p_stksize;
	sp->pr_oldcontext = (struct ucontext *)lwp->lwp_oldcontext;
	sp->pr_processor = t->t_cpu->cpu_id;
	sp->pr_bind = t->t_bind_cpu;

	/*
	 * Fetch the current instruction, if not a system process.
	 * We don't attempt this unless the lwp is stopped.
	 */
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		sp->pr_flags |= (PR_ISSYS|PR_PCINVAL);
	else if (!(flags & PR_STOPPED))
		sp->pr_flags |= PR_PCINVAL;
	else if (!prfetchinstr(lwp, &instr))
		sp->pr_flags |= PR_PCINVAL;
	else
		sp->pr_instr = instr;

	/*
	 * Drop p_lock while touching the lwp's stack.
	 */
	mutex_exit(&p->p_lock);
	if (prisstep(lwp))
		sp->pr_flags |= PR_STEP;
	if ((flags & (PR_STOPPED|PR_ASLEEP)) && t->t_sysnum) {
		int i;
		auxv_t *auxp;

		sp->pr_syscall = get_syscall_args(lwp,
		    (long *)sp->pr_sysarg, &i);
		sp->pr_nsysarg = (short)i;
		if (t->t_whystop == PR_SYSEXIT && t->t_sysnum == SYS_execve) {
			sp->pr_sysarg[0] = 0;
			sp->pr_sysarg[1] = (uintptr_t)up->u_argv;
			sp->pr_sysarg[2] = (uintptr_t)up->u_envp;
			for (i = 0, auxp = up->u_auxv;
			    i < sizeof (up->u_auxv) / sizeof (up->u_auxv[0]);
			    i++, auxp++) {
				if (auxp->a_type == AT_SUN_EXECNAME) {
					sp->pr_sysarg[0] =
					    (uintptr_t)auxp->a_un.a_ptr;
					break;
				}
			}
		}
	}
	if ((flags & PR_STOPPED) || t == curthread)
		prgetprregs(lwp, sp->pr_reg);
	mutex_enter(&p->p_lock);
}

/*
 * Return old version of information used by ps(1).
 */
void
oprgetpsinfo(proc_t *p, prpsinfo_t *psp, kthread_t *tp)
{
	kthread_t *t;
	char c, state;
	user_t *up;
	dev_t d;
	uint64_t pct;
	int retval, niceval;
	cred_t *cred;
	struct as *as;
	hrtime_t hrutime, hrstime, cur_time;

	ASSERT(MUTEX_HELD(&p->p_lock));

	bzero(psp, sizeof (*psp));

	if ((t = tp) == NULL)
		t = prchoose(p);	/* returns locked thread */
	else
		thread_lock(t);

	/* kludge: map thread state enum into process state enum */

	if (t == NULL) {
		state = TS_ZOMB;
	} else {
		state = VSTOPPED(t) ? TS_STOPPED : t->t_state;
		thread_unlock(t);
	}

	switch (state) {
	case TS_SLEEP:		state = SSLEEP;		break;
	case TS_RUN:		state = SRUN;		break;
	case TS_ONPROC:		state = SONPROC;	break;
	case TS_ZOMB:		state = SZOMB;		break;
	case TS_STOPPED:	state = SSTOP;		break;
	default:		state = 0;		break;
	}
	switch (state) {
	case SSLEEP:	c = 'S';	break;
	case SRUN:	c = 'R';	break;
	case SZOMB:	c = 'Z';	break;
	case SSTOP:	c = 'T';	break;
	case SIDL:	c = 'I';	break;
	case SONPROC:	c = 'O';	break;
#ifdef SXBRK
	case SXBRK:	c = 'X';	break;
#endif
	default:	c = '?';	break;
	}
	psp->pr_state = state;
	psp->pr_sname = c;
	psp->pr_zomb = (state == SZOMB);
	/*
	 * only export SSYS and SMSACCT; everything else is off-limits to
	 * userland apps.
	 */
	psp->pr_flag = p->p_flag & (SSYS | SMSACCT);

	mutex_enter(&p->p_crlock);
	cred = p->p_cred;
	psp->pr_uid = crgetruid(cred);
	psp->pr_gid = crgetrgid(cred);
	psp->pr_euid = crgetuid(cred);
	psp->pr_egid = crgetgid(cred);
	mutex_exit(&p->p_crlock);

	psp->pr_pid = p->p_pid;
	if (curproc->p_zone->zone_id != GLOBAL_ZONEID &&
	    (p->p_flag & SZONETOP)) {
		ASSERT(p->p_zone->zone_id != GLOBAL_ZONEID);
		/*
		 * Inside local zones, fake zsched's pid as parent pids for
		 * processes which reference processes outside of the zone.
		 */
		psp->pr_ppid = curproc->p_zone->zone_zsched->p_pid;
	} else {
		psp->pr_ppid = p->p_ppid;
	}
	psp->pr_pgrp = p->p_pgrp;
	psp->pr_sid = p->p_sessp->s_sid;
	psp->pr_addr = prgetpsaddr(p);
	hrutime = mstate_aggr_state(p, LMS_USER);
	hrstime = mstate_aggr_state(p, LMS_SYSTEM);
	hrt2ts(hrutime + hrstime, &psp->pr_time);
	TICK_TO_TIMESTRUC(p->p_cutime + p->p_cstime, &psp->pr_ctime);
	switch (p->p_model) {
	case DATAMODEL_ILP32:
		psp->pr_dmodel = PR_MODEL_ILP32;
		break;
	case DATAMODEL_LP64:
		psp->pr_dmodel = PR_MODEL_LP64;
		break;
	}
	if (state == SZOMB || t == NULL) {
		int wcode = p->p_wcode;		/* must be atomic read */

		if (wcode)
			psp->pr_wstat = wstat(wcode, p->p_wdata);
		psp->pr_lttydev = PRNODEV;
		psp->pr_ottydev = (o_dev_t)PRNODEV;
		psp->pr_size = 0;
		psp->pr_rssize = 0;
		psp->pr_pctmem = 0;
	} else {
		up = PTOU(p);
		psp->pr_wchan = t->t_wchan;
		psp->pr_pri = t->t_pri;
		(void) strncpy(psp->pr_clname, sclass[t->t_cid].cl_name,
		    sizeof (psp->pr_clname) - 1);
		retval = CL_DONICE(t, NULL, 0, &niceval);
		if (retval == 0) {
			psp->pr_oldpri = v.v_maxsyspri - psp->pr_pri;
			psp->pr_nice = niceval + NZERO;
		} else {
			psp->pr_oldpri = 0;
			psp->pr_nice = 0;
		}
		d = cttydev(p);
#ifdef sun
		{
			extern dev_t rwsconsdev, rconsdev, uconsdev;
			/*
			 * If the controlling terminal is the real
			 * or workstation console device, map to what the
			 * user thinks is the console device. Handle case when
			 * rwsconsdev or rconsdev is set to NODEV for Starfire.
			 */
			if ((d == rwsconsdev || d == rconsdev) && d != NODEV)
				d = uconsdev;
		}
#endif
		psp->pr_lttydev = (d == NODEV) ? PRNODEV : d;
		psp->pr_ottydev = cmpdev(d);
		psp->pr_start = up->u_start;
		bcopy(up->u_comm, psp->pr_fname,
		    MIN(sizeof (up->u_comm), sizeof (psp->pr_fname)-1));
		bcopy(up->u_psargs, psp->pr_psargs,
		    MIN(PRARGSZ-1, PSARGSZ));
		psp->pr_syscall = t->t_sysnum;
		psp->pr_argc = up->u_argc;
		psp->pr_argv = (char **)up->u_argv;
		psp->pr_envp = (char **)up->u_envp;

		/* compute %cpu for the lwp or process */
		pct = 0;
		if ((t = tp) == NULL)
			t = p->p_tlist;
		cur_time = gethrtime_unscaled();
		do {
			pct += cpu_update_pct(t, cur_time);
			if (tp != NULL)		/* just do the one lwp */
				break;
		} while ((t = t->t_forw) != p->p_tlist);

		psp->pr_pctcpu = prgetpctcpu(pct);
		psp->pr_cpu = (psp->pr_pctcpu*100 + 0x6000) >> 15; /* [0..99] */
		if (psp->pr_cpu > 99)
			psp->pr_cpu = 99;

		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
			psp->pr_size = 0;
			psp->pr_rssize = 0;
			psp->pr_pctmem = 0;
		} else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_READER);
			psp->pr_size = btopr(as->a_resvsize);
			psp->pr_rssize = rm_asrss(as);
			psp->pr_pctmem = rm_pctmemory(as);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
		}
	}
	psp->pr_bysize = ptob(psp->pr_size);
	psp->pr_byrssize = ptob(psp->pr_rssize);
}

/*
 * Return an array of structures with memory map information.
 * We allocate here; the caller must deallocate.
 * The caller is also responsible to append the zero-filled entry
 * that terminates the PIOCMAP output buffer.
 */
static int
oprgetmap(proc_t *p, list_t *iolhead)
{
	struct as *as = p->p_as;
	prmap_t *mp;
	struct seg *seg;
	struct seg *brkseg, *stkseg;
	uint_t prot;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	/*
	 * Request an initial buffer size that doesn't waste memory
	 * if the address space has only a small number of segments.
	 */
	pr_iol_initlist(iolhead, sizeof (*mp), avl_numnodes(&as->a_segtree));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	brkseg = break_seg(p);
	stkseg = as_segat(as, prgetstackbase(p));

	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		if ((seg->s_flags & S_HOLE) != 0) {
			continue;
		}

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if (saddr == naddr)
				continue;

			mp = pr_iol_newbuf(iolhead, sizeof (*mp));

			mp->pr_vaddr = saddr;
			mp->pr_size = naddr - saddr;
			mp->pr_off = SEGOP_GETOFFSET(seg, saddr);
			mp->pr_mflags = 0;
			if (prot & PROT_READ)
				mp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				mp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				mp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				mp->pr_mflags |= MA_SHARED;
			if (seg == brkseg)
				mp->pr_mflags |= MA_BREAK;
			else if (seg == stkseg)
				mp->pr_mflags |= MA_STACK;
			mp->pr_pagesize = PAGESIZE;
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (0);
}

#ifdef _SYSCALL32_IMPL
static int
oprgetmap32(proc_t *p, list_t *iolhead)
{
	struct as *as = p->p_as;
	ioc_prmap32_t *mp;
	struct seg *seg;
	struct seg *brkseg, *stkseg;
	uint_t prot;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	/*
	 * Request an initial buffer size that doesn't waste memory
	 * if the address space has only a small number of segments.
	 */
	pr_iol_initlist(iolhead, sizeof (*mp), avl_numnodes(&as->a_segtree));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	brkseg = break_seg(p);
	stkseg = as_segat(as, prgetstackbase(p));

	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		if ((seg->s_flags & S_HOLE) != 0) {
			continue;
		}

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if (saddr == naddr)
				continue;

			mp = pr_iol_newbuf(iolhead, sizeof (*mp));

			mp->pr_vaddr = (caddr32_t)(uintptr_t)saddr;
			mp->pr_size = (size32_t)(naddr - saddr);
			mp->pr_off = (off32_t)SEGOP_GETOFFSET(seg, saddr);
			mp->pr_mflags = 0;
			if (prot & PROT_READ)
				mp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				mp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				mp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				mp->pr_mflags |= MA_SHARED;
			if (seg == brkseg)
				mp->pr_mflags |= MA_BREAK;
			else if (seg == stkseg)
				mp->pr_mflags |= MA_STACK;
			mp->pr_pagesize = PAGESIZE;
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (0);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Return the size of the old /proc page data file.
 */
size_t
oprpdsize(struct as *as)
{
	struct seg *seg;
	size_t size;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	size = sizeof (prpageheader_t);
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;
		size_t npage;

		if ((seg->s_flags & S_HOLE) != 0) {
			continue;
		}

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			(void) pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((npage = (naddr - saddr) / PAGESIZE) != 0)
				size += sizeof (prasmap_t) + roundlong(npage);
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (size);
}

#ifdef _SYSCALL32_IMPL
size_t
oprpdsize32(struct as *as)
{
	struct seg *seg;
	size_t size;

	ASSERT(as != &kas && AS_WRITE_HELD(as));

	if ((seg = AS_SEGFIRST(as)) == NULL)
		return (0);

	size = sizeof (ioc_prpageheader32_t);
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;
		size_t npage;

		if ((seg->s_flags & S_HOLE) != 0) {
			continue;
		}

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			(void) pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((npage = (naddr - saddr) / PAGESIZE) != 0)
				size += sizeof (ioc_prmap32_t) + round4(npage);
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	return (size);
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Read old /proc page data information.
 */
int
oprpdread(struct as *as, uint_t hatid, struct uio *uiop)
{
	caddr_t buf;
	size_t size;
	prpageheader_t *php;
	prasmap_t *pmp;
	struct seg *seg;
	int error;

again:
	AS_LOCK_ENTER(as, RW_WRITER);

	if ((seg = AS_SEGFIRST(as)) == NULL) {
		AS_LOCK_EXIT(as);
		return (0);
	}
	size = oprpdsize(as);
	if (uiop->uio_resid < size) {
		AS_LOCK_EXIT(as);
		return (E2BIG);
	}

	buf = kmem_zalloc(size, KM_SLEEP);
	php = (prpageheader_t *)buf;
	pmp = (prasmap_t *)(buf + sizeof (prpageheader_t));

	hrt2ts(gethrtime(), &php->pr_tstamp);
	php->pr_nmap = 0;
	php->pr_npage = 0;
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		if ((seg->s_flags & S_HOLE) != 0) {
			continue;
		}

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			size_t len;
			size_t npage;
			uint_t prot;
			uintptr_t next;

			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((len = naddr - saddr) == 0)
				continue;
			npage = len / PAGESIZE;
			next = (uintptr_t)(pmp + 1) + roundlong(npage);
			/*
			 * It's possible that the address space can change
			 * subtlely even though we're holding as->a_lock
			 * due to the nondeterminism of page_exists() in
			 * the presence of asychronously flushed pages or
			 * mapped files whose sizes are changing.
			 * page_exists() may be called indirectly from
			 * pr_getprot() by a SEGOP_INCORE() routine.
			 * If this happens we need to make sure we don't
			 * overrun the buffer whose size we computed based
			 * on the initial iteration through the segments.
			 * Once we've detected an overflow, we need to clean
			 * up the temporary memory allocated in pr_getprot()
			 * and retry. If there's a pending signal, we return
			 * EINTR so that this thread can be dislodged if
			 * a latent bug causes us to spin indefinitely.
			 */
			if (next > (uintptr_t)buf + size) {
				pr_getprot_done(&tmp);
				AS_LOCK_EXIT(as);

				kmem_free(buf, size);

				if (ISSIG(curthread, JUSTLOOKING))
					return (EINTR);

				goto again;
			}

			php->pr_nmap++;
			php->pr_npage += npage;
			pmp->pr_vaddr = saddr;
			pmp->pr_npage = npage;
			pmp->pr_off = SEGOP_GETOFFSET(seg, saddr);
			pmp->pr_mflags = 0;
			if (prot & PROT_READ)
				pmp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				pmp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				pmp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				pmp->pr_mflags |= MA_SHARED;
			pmp->pr_pagesize = PAGESIZE;
			hat_getstat(as, saddr, len, hatid,
			    (char *)(pmp + 1), HAT_SYNC_ZERORM);
			pmp = (prasmap_t *)next;
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	AS_LOCK_EXIT(as);

	ASSERT((uintptr_t)pmp <= (uintptr_t)buf + size);
	error = uiomove(buf, (caddr_t)pmp - buf, UIO_READ, uiop);
	kmem_free(buf, size);

	return (error);
}

#ifdef _SYSCALL32_IMPL
int
oprpdread32(struct as *as, uint_t hatid, struct uio *uiop)
{
	caddr_t buf;
	size_t size;
	ioc_prpageheader32_t *php;
	ioc_prasmap32_t *pmp;
	struct seg *seg;
	int error;

again:
	AS_LOCK_ENTER(as, RW_WRITER);

	if ((seg = AS_SEGFIRST(as)) == NULL) {
		AS_LOCK_EXIT(as);
		return (0);
	}
	size = oprpdsize32(as);
	if (uiop->uio_resid < size) {
		AS_LOCK_EXIT(as);
		return (E2BIG);
	}

	buf = kmem_zalloc(size, KM_SLEEP);
	php = (ioc_prpageheader32_t *)buf;
	pmp = (ioc_prasmap32_t *)(buf + sizeof (ioc_prpageheader32_t));

	hrt2ts32(gethrtime(), &php->pr_tstamp);
	php->pr_nmap = 0;
	php->pr_npage = 0;
	do {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;

		if ((seg->s_flags & S_HOLE) != 0) {
			continue;
		}

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			size_t len;
			size_t npage;
			uint_t prot;
			uintptr_t next;

			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			if ((len = naddr - saddr) == 0)
				continue;
			npage = len / PAGESIZE;
			next = (uintptr_t)(pmp + 1) + round4(npage);
			/*
			 * It's possible that the address space can change
			 * subtlely even though we're holding as->a_lock
			 * due to the nondeterminism of page_exists() in
			 * the presence of asychronously flushed pages or
			 * mapped files whose sizes are changing.
			 * page_exists() may be called indirectly from
			 * pr_getprot() by a SEGOP_INCORE() routine.
			 * If this happens we need to make sure we don't
			 * overrun the buffer whose size we computed based
			 * on the initial iteration through the segments.
			 * Once we've detected an overflow, we need to clean
			 * up the temporary memory allocated in pr_getprot()
			 * and retry. If there's a pending signal, we return
			 * EINTR so that this thread can be dislodged if
			 * a latent bug causes us to spin indefinitely.
			 */
			if (next > (uintptr_t)buf + size) {
				pr_getprot_done(&tmp);
				AS_LOCK_EXIT(as);

				kmem_free(buf, size);

				if (ISSIG(curthread, JUSTLOOKING))
					return (EINTR);

				goto again;
			}

			php->pr_nmap++;
			php->pr_npage += npage;
			pmp->pr_vaddr = (uint32_t)(uintptr_t)saddr;
			pmp->pr_npage = (uint32_t)npage;
			pmp->pr_off = (int32_t)SEGOP_GETOFFSET(seg, saddr);
			pmp->pr_mflags = 0;
			if (prot & PROT_READ)
				pmp->pr_mflags |= MA_READ;
			if (prot & PROT_WRITE)
				pmp->pr_mflags |= MA_WRITE;
			if (prot & PROT_EXEC)
				pmp->pr_mflags |= MA_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				pmp->pr_mflags |= MA_SHARED;
			pmp->pr_pagesize = PAGESIZE;
			hat_getstat(as, saddr, len, hatid,
			    (char *)(pmp + 1), HAT_SYNC_ZERORM);
			pmp = (ioc_prasmap32_t *)next;
		}
		ASSERT(tmp == NULL);
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	AS_LOCK_EXIT(as);

	ASSERT((uintptr_t)pmp == (uintptr_t)buf + size);
	error = uiomove(buf, (caddr_t)pmp - buf, UIO_READ, uiop);
	kmem_free(buf, size);

	return (error);
}
#endif	/* _SYSCALL32_IMPL */

/*ARGSUSED*/
#ifdef _SYSCALL32_IMPL
int
prioctl(
	struct vnode *vp,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cr,
	int *rvalp,
	caller_context_t *ct)
{
	switch (curproc->p_model) {
	case DATAMODEL_ILP32:
		return (prioctl32(vp, cmd, arg, flag, cr, rvalp, ct));
	case DATAMODEL_LP64:
		return (prioctl64(vp, cmd, arg, flag, cr, rvalp, ct));
	default:
		return (ENOSYS);
	}
}
#endif	/* _SYSCALL32_IMPL */
