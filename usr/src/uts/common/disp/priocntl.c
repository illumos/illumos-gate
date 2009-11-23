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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/pcb.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/sysinfo.h>
#include <sys/var.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/procset.h>
#include <sys/debug.h>
#include <sys/inline.h>
#include <sys/priocntl.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/modctl.h>
#include <sys/t_lock.h>
#include <sys/uadmin.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>
#include <sys/schedctl.h>

/*
 * Structure used to pass arguments to the proccmp() function.
 * The arguments must be passed in a structure because proccmp()
 * is called indirectly through the dotoprocs() function which
 * will only pass through a single one word argument.
 */
struct pcmpargs {
	id_t	*pcmp_cidp;
	int	*pcmp_cntp;
	kthread_t **pcmp_retthreadp;
};

/*
 * Structure used to pass arguments to the setparms() function
 * which is called indirectly through dotoprocs().
 */
struct stprmargs {
	struct pcparms	*stp_parmsp;	/* pointer to parameters */
	int		stp_error;	/* some errors returned here */
};

#if defined(_SYSCALL32_IMPL) && _LONG_LONG_ALIGNMENT_32 == 4
/*
 * A vaparm_t is an int followed by a long long -- this packs differently
 * between the 64-bit kernel ABI and the 32-bit user ABI.
 */
static int
copyin_vaparms32(caddr_t arg, pc_vaparms_t *vap, uio_seg_t seg)
{
	pc_vaparms32_t vaparms32;
	pc_vaparm32_t *src;
	pc_vaparm_t *dst;
	uint_t cnt;

	ASSERT(get_udatamodel() == DATAMODEL_ILP32);

	if ((seg == UIO_USERSPACE ? copyin : kcopy)(arg, &vaparms32,
	    sizeof (vaparms32)))
		return (EFAULT);

	vap->pc_vaparmscnt = vaparms32.pc_vaparmscnt;
	if ((cnt = vaparms32.pc_vaparmscnt) > PC_VAPARMCNT)
		cnt = PC_VAPARMCNT;
	for (src = vaparms32.pc_parms, dst = vap->pc_parms;
	    cnt--; src++, dst++) {
		dst->pc_key = src->pc_key;
		dst->pc_parm = src->pc_parm;
	}
	return (0);
}

#define	COPYIN_VAPARMS(arg, vap, size, seg)	\
	(get_udatamodel() == DATAMODEL_NATIVE ?	\
	(*copyinfn)(arg, vap, size) : copyin_vaparms32(arg, vap, seg))

#else

#define	COPYIN_VAPARMS(arg, vap, size, seg)	(*copyinfn)(arg, vap, size)

#endif

static int donice(procset_t *, pcnice_t *);
static int doprio(procset_t *, pcprio_t *);
static int proccmp(proc_t *, struct pcmpargs *);
static int setparms(proc_t *, struct stprmargs *);
extern int threadcmp(struct pcmpargs *, kthread_t *);

/*
 * The priocntl system call.
 */
long
priocntl_common(int pc_version, procset_t *psp, int cmd, caddr_t arg,
    caddr_t arg2, uio_seg_t seg)
{
	pcinfo_t		pcinfo;
	pcparms_t		pcparms;
	pcnice_t		pcnice;
	pcprio_t		pcprio;
	pcadmin_t		pcadmin;
	pcpri_t			pcpri;
	procset_t		procset;
	struct stprmargs	stprmargs;
	struct pcmpargs		pcmpargs;
	pc_vaparms_t		vaparms;
	char			clname[PC_CLNMSZ];
	char			*outstr;
	int			count;
	kthread_t		*retthreadp;
	proc_t			*initpp;
	int			clnullflag;
	int			error = 0;
	int			error1 = 0;
	int			rv = 0;
	pid_t			saved_pid;
	id_t			classid;
	int			size;
	int (*copyinfn)(const void *, void *, size_t);
	int (*copyoutfn)(const void *, void *, size_t);

	/*
	 * First just check the version number. Right now there is only
	 * one version we know about and support.  If we get some other
	 * version number from the application it may be that the
	 * application was built with some future version and is trying
	 * to run on an old release of the system (that's us).  In any
	 * case if we don't recognize the version number all we can do is
	 * return error.
	 */
	if (pc_version != PC_VERSION)
		return (set_errno(EINVAL));

	if (seg == UIO_USERSPACE) {
		copyinfn = copyin;
		copyoutfn = copyout;
	} else {
		copyinfn = kcopy;
		copyoutfn = kcopy;
	}

	switch (cmd) {
	case PC_GETCID:
		/*
		 * If the arg pointer is NULL, the user just wants to
		 * know the number of classes. If non-NULL, the pointer
		 * should point to a valid user pcinfo buffer.  In the
		 * dynamic world we need to return the number of loaded
		 * classes, not the max number of available classes that
		 * can be loaded.
		 */
		if (arg == NULL) {
			rv = loaded_classes;
			break;
		} else {
			if ((*copyinfn)(arg, &pcinfo, sizeof (pcinfo)))
				return (set_errno(EFAULT));
		}

		pcinfo.pc_clname[PC_CLNMSZ-1] = '\0';

		/*
		 * Get the class ID corresponding to user supplied name.
		 */
		error = getcid(pcinfo.pc_clname, &pcinfo.pc_cid);
		if (error)
			return (set_errno(error));

		/*
		 * Can't get info about the sys class.
		 */
		if (pcinfo.pc_cid == 0)
			return (set_errno(EINVAL));

		/*
		 * Get the class specific information.
		 * we MUST make sure that the class has not already
		 * been unloaded before we try the CL_GETCLINFO.
		 * If it has then we need to load it.
		 */
		error =
		    scheduler_load(pcinfo.pc_clname, &sclass[pcinfo.pc_cid]);
		if (error)
			return (set_errno(error));
		error = CL_GETCLINFO(&sclass[pcinfo.pc_cid], pcinfo.pc_clinfo);
		if (error)
			return (set_errno(error));

		if ((*copyoutfn)(&pcinfo, arg, sizeof (pcinfo)))
			return (set_errno(EFAULT));

		rv = loaded_classes;

		break;

	case PC_GETCLINFO:
		/*
		 * If the arg pointer is NULL, the user just wants to know
		 * the number of classes. If non-NULL, the pointer should
		 * point to a valid user pcinfo buffer.
		 */
		if (arg == NULL) {
			rv = loaded_classes;
			break;
		} else {
			if ((*copyinfn)(arg, &pcinfo, sizeof (pcinfo)))
				return (set_errno(EFAULT));
		}

		if (pcinfo.pc_cid >= loaded_classes || pcinfo.pc_cid < 1)
			return (set_errno(EINVAL));

		(void) strncpy(pcinfo.pc_clname, sclass[pcinfo.pc_cid].cl_name,
		    PC_CLNMSZ);

		/*
		 * Get the class specific information.  we MUST make sure
		 * that the class has not already been unloaded before we
		 * try the CL_GETCLINFO.  If it has then we need to load
		 * it.
		 */
		error =
		    scheduler_load(pcinfo.pc_clname, &sclass[pcinfo.pc_cid]);
		if (error)
			return (set_errno(error));
		error = CL_GETCLINFO(&sclass[pcinfo.pc_cid], pcinfo.pc_clinfo);
		if (error)
			return (set_errno(error));

		if ((*copyoutfn)(&pcinfo, arg, sizeof (pcinfo)))
			return (set_errno(EFAULT));

		rv = loaded_classes;
		break;

	case PC_SETPARMS:
	case PC_SETXPARMS:
		/*
		 * First check the validity of the parameters we got from
		 * the user.  We don't do any permissions checking here
		 * because it's done on a per thread basis by parmsset().
		 */
		if (cmd == PC_SETPARMS) {
			if ((*copyinfn)(arg, &pcparms, sizeof (pcparms)))
				return (set_errno(EFAULT));

			error = parmsin(&pcparms, NULL);
		} else {
			if ((*copyinfn)(arg, clname, PC_CLNMSZ) ||
			    COPYIN_VAPARMS(arg2, &vaparms, sizeof (vaparms),
			    seg))
				return (set_errno(EFAULT));
			clname[PC_CLNMSZ-1] = '\0';

			if (getcid(clname, &pcparms.pc_cid))
				return (set_errno(EINVAL));

			error = parmsin(&pcparms, &vaparms);
		}

		if (error)
			return (set_errno(error));

		/*
		 * Get the procset from the user.
		 */
		if ((*copyinfn)(psp, &procset, sizeof (procset)))
			return (set_errno(EFAULT));

		/*
		 * For performance we do a quick check here to catch
		 * common cases where the current thread is the only one
		 * in the set.  In such cases we can call parmsset()
		 * directly, avoiding the relatively lengthy path through
		 * dotoprocs().  The underlying classes expect pidlock to
		 * be held.
		 */
		if (cur_inset_only(&procset) == B_TRUE) {
			/* do a single LWP */
			if ((procset.p_lidtype == P_LWPID) ||
			    (procset.p_ridtype == P_LWPID)) {
				mutex_enter(&pidlock);
				mutex_enter(&curproc->p_lock);
				error = parmsset(&pcparms, curthread);
				mutex_exit(&curproc->p_lock);
				mutex_exit(&pidlock);
			} else {
				/* do the entire process otherwise */
				stprmargs.stp_parmsp = &pcparms;
				stprmargs.stp_error = 0;
				mutex_enter(&pidlock);
				error = setparms(curproc, &stprmargs);
				mutex_exit(&pidlock);
				if (error == 0 && stprmargs.stp_error != 0)
					error = stprmargs.stp_error;
			}
			if (error)
				return (set_errno(error));
		} else {
			stprmargs.stp_parmsp = &pcparms;
			stprmargs.stp_error = 0;

			error1 = error = ESRCH;

			/*
			 * The dotoprocs() call below will cause
			 * setparms() to be called for each thread in the
			 * specified procset. setparms() will in turn
			 * call parmsset() (which does the real work).
			 */
			if ((procset.p_lidtype != P_LWPID) ||
			    (procset.p_ridtype != P_LWPID)) {
				error1 = dotoprocs(&procset, setparms,
				    (char *)&stprmargs);
			}

			/*
			 * take care of the case when any of the
			 * operands happen to be LWP's
			 */

			if ((procset.p_lidtype == P_LWPID) ||
			    (procset.p_ridtype == P_LWPID)) {
				error = dotolwp(&procset, parmsset,
				    (char *)&pcparms);
				/*
				 * Dotolwp() returns with p_lock held.
				 * This is required for the GETPARMS case
				 * below. So, here we just release the
				 * p_lock.
				 */
				if (MUTEX_HELD(&curproc->p_lock))
					mutex_exit(&curproc->p_lock);
			}

			/*
			 * If setparms() encounters a permissions error
			 * for one or more of the threads it returns
			 * EPERM in stp_error so dotoprocs() will
			 * continue through the thread set.  If
			 * dotoprocs() returned an error above, it was
			 * more serious than permissions and dotoprocs
			 * quit when the error was encountered.  We
			 * return the more serious error if there was
			 * one, otherwise we return EPERM if we got that
			 * back.
			 */
			if (error1 != ESRCH)
				error = error1;
			if (error == 0 && stprmargs.stp_error != 0)
				error = stprmargs.stp_error;
		}
		break;

	case PC_GETPARMS:
	case PC_GETXPARMS:
		if (cmd == PC_GETPARMS) {
			if ((*copyinfn)(arg, &pcparms, sizeof (pcparms)))
				return (set_errno(EFAULT));
		} else {
			if (arg != NULL) {
				if ((*copyinfn)(arg, clname, PC_CLNMSZ))
					return (set_errno(EFAULT));

				clname[PC_CLNMSZ-1] = '\0';

				if (getcid(clname, &pcparms.pc_cid))
					return (set_errno(EINVAL));
			} else
				pcparms.pc_cid = PC_CLNULL;

			if (COPYIN_VAPARMS(arg2, &vaparms, sizeof (vaparms),
			    seg))
				return (set_errno(EFAULT));
		}

		if (pcparms.pc_cid >= loaded_classes ||
		    (pcparms.pc_cid < 1 && pcparms.pc_cid != PC_CLNULL))
			return (set_errno(EINVAL));

		if ((*copyinfn)(psp, &procset, sizeof (procset)))
			return (set_errno(EFAULT));

		/*
		 * Check to see if the current thread is the only one
		 * in the set. If not we must go through the whole set
		 * to select a thread.
		 */
		if (cur_inset_only(&procset) == B_TRUE) {
			/* do a single LWP */
			if ((procset.p_lidtype == P_LWPID) ||
			    (procset.p_ridtype == P_LWPID)) {
				if (pcparms.pc_cid != PC_CLNULL &&
				    pcparms.pc_cid != curthread->t_cid) {
					/*
					 * Specified thread not in
					 * specified class.
					 */
					return (set_errno(ESRCH));
				} else {
					mutex_enter(&curproc->p_lock);
					retthreadp = curthread;
				}
			} else {
				count = 0;
				retthreadp = NULL;
				pcmpargs.pcmp_cidp = &pcparms.pc_cid;
				pcmpargs.pcmp_cntp = &count;
				pcmpargs.pcmp_retthreadp = &retthreadp;
				/*
				 * Specified thread not in specified class.
				 */
				if (pcparms.pc_cid != PC_CLNULL &&
				    pcparms.pc_cid != curthread->t_cid)
					return (set_errno(ESRCH));
				error = proccmp(curproc, &pcmpargs);
				if (error) {
					if (retthreadp != NULL)
						mutex_exit(&(curproc->p_lock));
					return (set_errno(error));
				}
			}
		} else {
			/*
			 * get initpp early to avoid lock ordering problems
			 * (we cannot get pidlock while holding any p_lock).
			 */
			mutex_enter(&pidlock);
			initpp = prfind(P_INITPID);
			mutex_exit(&pidlock);

			/*
			 * Select the thread (from the set) whose
			 * parameters we are going to return.  First we
			 * set up some locations for return values, then
			 * we call proccmp() indirectly through
			 * dotoprocs().  proccmp() will call a class
			 * specific routine which actually does the
			 * selection.  To understand how this works take
			 * a careful look at the code below, the
			 * dotoprocs() function, the proccmp() function,
			 * and the class specific cl_proccmp() functions.
			 */
			if (pcparms.pc_cid == PC_CLNULL)
				clnullflag = 1;
			else
				clnullflag = 0;
			count = 0;
			retthreadp = NULL;
			pcmpargs.pcmp_cidp = &pcparms.pc_cid;
			pcmpargs.pcmp_cntp = &count;
			pcmpargs.pcmp_retthreadp = &retthreadp;
			error1 = error = ESRCH;

			if ((procset.p_lidtype != P_LWPID) ||
			    (procset.p_ridtype != P_LWPID)) {
				error1 = dotoprocs(&procset, proccmp,
				    (char *)&pcmpargs);
			}

			/*
			 * take care of combination of LWP and process
			 * set case in a procset
			 */
			if ((procset.p_lidtype == P_LWPID) ||
			    (procset.p_ridtype == P_LWPID)) {
				error = dotolwp(&procset, threadcmp,
				    (char *)&pcmpargs);
			}

			/*
			 * Both proccmp() and threadcmp() return with the
			 * p_lock held for the ttoproc(retthreadp). This
			 * is required to make sure that the process we
			 * chose as the winner doesn't go away
			 * i.e. retthreadp has to be a valid pointer.
			 *
			 * The case below can only happen if the thread
			 * with the highest priority was not in your
			 * process.  In that case, dotolwp will return
			 * holding p_lock for both your process as well
			 * as the process in which retthreadp is a
			 * thread.
			 */
			if ((retthreadp != NULL) &&
			    (ttoproc(retthreadp) != curproc) &&
			    MUTEX_HELD(&(curproc)->p_lock))
				mutex_exit(&(curproc)->p_lock);

			ASSERT(retthreadp == NULL ||
			    MUTEX_HELD(&(ttoproc(retthreadp)->p_lock)));
			if (error1 != ESRCH)
				error = error1;
			if (error) {
				if (retthreadp != NULL)
				    /* CSTYLED */
				    mutex_exit(&(ttoproc(retthreadp)->p_lock));
				ASSERT(MUTEX_NOT_HELD(&(curproc)->p_lock));
				return (set_errno(error));
			}
			/*
			 * dotoprocs() ignores the init process if it is
			 * in the set, unless it was the only process found.
			 * Since we are getting parameters here rather than
			 * setting them, we want to make sure init is not
			 * excluded if it is in the set.
			 */
			if (initpp != NULL && retthreadp != NULL &&
			    ttoproc(retthreadp) != initpp) {
				mutex_enter(&initpp->p_lock);
				if (procinset(initpp, &procset)) {
					mutex_exit(&initpp->p_lock);
					(void) proccmp(initpp, &pcmpargs);
				} else {
					mutex_exit(&initpp->p_lock);
				}
			}

			/*
			 * If dotoprocs returned success it found at least
			 * one thread in the set.  If proccmp() failed to
			 * select a thread it is because the user specified
			 * a class and none of the threads in the set
			 * belonged to that class, or because the process
			 * specified was in the middle of exiting and had
			 * cleared its thread list.
			 */
			if (retthreadp == NULL) {
				/*
				 * Might be here and still holding p_lock
				 * if we did a dotolwp on an lwp that
				 * existed but was in the wrong class.
				 */
				if (MUTEX_HELD(&(curproc)->p_lock))
					mutex_exit(&(curproc)->p_lock);
				return (set_errno(ESRCH));
			}

			/*
			 * User can only use PC_CLNULL with one thread in set.
			 */
			if (clnullflag && count > 1) {
				if (retthreadp != NULL)
					mutex_exit(
					    &(ttoproc(retthreadp)->p_lock));
				ASSERT(MUTEX_NOT_HELD(&(curproc)->p_lock));
				return (set_errno(EINVAL));
			}
		}

		ASSERT(retthreadp == NULL ||
		    MUTEX_HELD(&(ttoproc(retthreadp)->p_lock)));
		/*
		 * It is possible to have retthreadp == NULL. Proccmp()
		 * in the rare case (p_tlist == NULL) could return without
		 * setting a value for retthreadp.
		 */
		if (retthreadp == NULL) {
			ASSERT(MUTEX_NOT_HELD(&(curproc)->p_lock));
			return (set_errno(ESRCH));
		}
		/*
		 * We've selected a thread so now get the parameters.
		 */
		parmsget(retthreadp, &pcparms);

		/*
		 * Prepare to return parameters to the user
		 */
		error = parmsout(&pcparms,
		    (cmd == PC_GETPARMS ? NULL : &vaparms));

		/*
		 * Save pid of selected thread before dropping p_lock.
		 */
		saved_pid = ttoproc(retthreadp)->p_pid;
		mutex_exit(&(ttoproc(retthreadp)->p_lock));
		ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

		if (error)
			return (set_errno(error));

		if (cmd == PC_GETPARMS) {
			if ((*copyoutfn)(&pcparms, arg, sizeof (pcparms)))
				return (set_errno(EFAULT));
		} else if ((error = vaparmsout(arg, &pcparms, &vaparms,
		    seg)) != 0)
			return (set_errno(error));

		/*
		 * And finally, return the pid of the selected thread.
		 */
		rv = saved_pid;
		break;

	case PC_ADMIN:
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if ((*copyinfn)(arg, &pcadmin, sizeof (pcadmin_t)))
				return (set_errno(EFAULT));
#ifdef _SYSCALL32_IMPL
		} else {
			/* pcadmin struct from ILP32 callers */
			pcadmin32_t pcadmin32;

			if ((*copyinfn)(arg, &pcadmin32, sizeof (pcadmin32_t)))
				return (set_errno(EFAULT));
			pcadmin.pc_cid = pcadmin32.pc_cid;
			pcadmin.pc_cladmin = (caddr_t)(uintptr_t)
			    pcadmin32.pc_cladmin;
#endif /* _SYSCALL32_IMPL */
		}

		if (pcadmin.pc_cid >= loaded_classes ||
		    pcadmin.pc_cid < 1)
			return (set_errno(EINVAL));

		/*
		 * Have the class do whatever the user is requesting.
		 */
		mutex_enter(&ualock);
		error = CL_ADMIN(&sclass[pcadmin.pc_cid], pcadmin.pc_cladmin,
		    CRED());
		mutex_exit(&ualock);
		break;

	case PC_GETPRIRANGE:
		if ((*copyinfn)(arg, &pcpri, sizeof (pcpri_t)))
			return (set_errno(EFAULT));

		if (pcpri.pc_cid >= loaded_classes || pcpri.pc_cid < 0)
			return (set_errno(EINVAL));

		error = CL_GETCLPRI(&sclass[pcpri.pc_cid], &pcpri);
		if (!error) {
			if ((*copyoutfn)(&pcpri, arg, sizeof (pcpri)))
				return (set_errno(EFAULT));
		}
		break;

	case PC_DONICE:
		/*
		 * Get pcnice and procset structures from the user.
		 */
		if ((*copyinfn)(arg, &pcnice, sizeof (pcnice)) ||
		    (*copyinfn)(psp, &procset, sizeof (procset)))
			return (set_errno(EFAULT));

		error = donice(&procset, &pcnice);

		if (!error && (pcnice.pc_op == PC_GETNICE)) {
			if ((*copyoutfn)(&pcnice, arg, sizeof (pcnice)))
				return (set_errno(EFAULT));
		}
		break;

	case PC_DOPRIO:
		/*
		 * Get pcprio and procset structures from the user.
		 */
		if ((*copyinfn)(arg, &pcprio, sizeof (pcprio)) ||
		    (*copyinfn)(psp, &procset, sizeof (procset)))
			return (set_errno(EFAULT));

		error = doprio(&procset, &pcprio);

		if (!error && (pcprio.pc_op == PC_GETPRIO)) {
			if ((*copyoutfn)(&pcprio, arg, sizeof (pcprio)))
				return (set_errno(EFAULT));
		}
		break;

	case PC_SETDFLCL:
		if (secpolicy_dispadm(CRED()) != 0)
			return (set_errno(EPERM));

		if (copyin(arg, (caddr_t)clname, PC_CLNMSZ) != 0)
			return (set_errno(EFAULT));
		clname[PC_CLNMSZ-1] = '\0';

		if (getcid(clname, &classid) != 0)
			return (set_errno(EINVAL));
		if (CLASS_KERNEL(classid))
			return (set_errno(EINVAL));
		defaultcid = classid;
		ASSERT(defaultcid > 0 && defaultcid < loaded_classes);
		break;

	case PC_GETDFLCL:
		mutex_enter(&class_lock);

		if (defaultcid >= loaded_classes)
			outstr = "";
		else
			outstr = sclass[defaultcid].cl_name;
		size = strlen(outstr) + 1;
		if (arg != NULL)
			if ((*copyoutfn)(outstr, arg, size) != 0)
				error = EFAULT;

		mutex_exit(&class_lock);
		break;

	default:
		error = EINVAL;
		break;
	}
	return (error ? (set_errno(error)) : rv);
}

long
priocntlsys(int pc_version, procset_t *psp, int cmd, caddr_t arg, caddr_t arg2)
{
	return (priocntl_common(pc_version, psp, cmd, arg, arg2,
	    UIO_USERSPACE));
}

/*
 * The proccmp() function is part of the implementation of the
 * PC_GETPARMS command of the priocntl system call.  This function works
 * with the system call code and with the class specific cl_globpri()
 * function to select one thread from a specified procset based on class
 * specific criteria. proccmp() is called indirectly from the priocntl
 * code through the dotoprocs function.  Basic strategy is dotoprocs()
 * calls us once for each thread in the set.  We in turn call the class
 * specific function to compare the current thread from dotoprocs to the
 * "best" (according to the class criteria) found so far.  We keep the
 * "best" thread in *pcmp_retthreadp.
 */
static int
proccmp(proc_t *pp, struct pcmpargs *argp)
{
	kthread_t	*tx;
	kthread_t	*ty;
	int		last_pri = -1;
	int		tx_pri;
	int		found = 0;

	mutex_enter(&pp->p_lock);

	if (pp->p_tlist == NULL) {
		mutex_exit(&pp->p_lock);
		return (0);
	}
	(*argp->pcmp_cntp)++;	/* Increment count of procs in the set */

	if (*argp->pcmp_cidp == PC_CLNULL) {
		/*
		 * If no cid is specified, then lets just pick the first one.
		 * It doesn't matter because if the number of processes in the
		 * set are more than 1, then we return EINVAL in priocntlsys.
		 */
		*argp->pcmp_cidp = pp->p_tlist->t_cid;
	}
	ty = tx = pp->p_tlist;
	do {
		if (tx->t_cid == *argp->pcmp_cidp) {
			/*
			 * We found one which matches the required cid.
			 */
			found = 1;
			if ((tx_pri = CL_GLOBPRI(tx)) > last_pri) {
				last_pri = tx_pri;
				ty = tx;
			}
		}
	} while ((tx = tx->t_forw) != pp->p_tlist);
	if (found) {
		if (*argp->pcmp_retthreadp == NULL) {
			/*
			 * First time through for this set.
			 * keep the mutex held. He might be the one!
			 */
			*argp->pcmp_retthreadp = ty;
		} else {
			tx = *argp->pcmp_retthreadp;
			if (CL_GLOBPRI(ty) <= CL_GLOBPRI(tx)) {
				mutex_exit(&pp->p_lock);
			} else {
				mutex_exit(&(ttoproc(tx)->p_lock));
				*argp->pcmp_retthreadp = ty;
			}
		}
	} else {
		/*
		 * We actually didn't find anything of the same cid in
		 * this process.
		 */
		mutex_exit(&pp->p_lock);
	}
	return (0);
}


int
threadcmp(struct pcmpargs *argp, kthread_t *tp)
{
	kthread_t	*tx;
	proc_t		*pp;

	ASSERT(MUTEX_HELD(&(ttoproc(tp))->p_lock));

	(*argp->pcmp_cntp)++;   /* Increment count of procs in the set */
	if (*argp->pcmp_cidp == PC_CLNULL) {
		/*
		 * If no cid is specified, then lets just pick the first one.
		 * It doesn't matter because if the number of threads in the
		 * set are more than 1, then we return EINVAL in priocntlsys.
		 */
		*argp->pcmp_cidp = tp->t_cid;
	}
	if (tp->t_cid == *argp->pcmp_cidp) {
		if (*argp->pcmp_retthreadp == NULL) {
			/*
			 * First time through for this set.
			 */
			*argp->pcmp_retthreadp = tp;
		} else {
			tx = *argp->pcmp_retthreadp;
			if (CL_GLOBPRI(tp) > CL_GLOBPRI(tx)) {
				/*
				 * Unlike proccmp(), we don't release the
				 * p_lock of the ttoproc(tp) if tp's global
				 * priority is less than tx's. We need to go
				 * through the entire list before we can do
				 * that. The p_lock is released by the caller
				 * of dotolwp().
				 */
				pp = ttoproc(tx);
				ASSERT(MUTEX_HELD(&pp->p_lock));
				if (pp != curproc) {
					mutex_exit(&pp->p_lock);
				}
				*argp->pcmp_retthreadp = tp;
			}
		}
	}
	return (0);
}


/*
 * The setparms() function is called indirectly by priocntlsys()
 * through the dotoprocs() function.  setparms() acts as an
 * intermediary between dotoprocs() and the parmsset() function,
 * calling parmsset() for each thread in the set and handling
 * the error returns on their way back up to dotoprocs().
 */
static int
setparms(proc_t *targpp, struct stprmargs *stprmp)
{
	int error = 0;
	kthread_t *t;
	int err;

	mutex_enter(&targpp->p_lock);
	if ((t = targpp->p_tlist) == NULL) {
		mutex_exit(&targpp->p_lock);
		return (0);
	}
	do {
		err = parmsset(stprmp->stp_parmsp, t);
		if (error == 0)
			error = err;
	} while ((t = t->t_forw) != targpp->p_tlist);
	mutex_exit(&targpp->p_lock);
	if (error) {
		if (error == EPERM) {
			stprmp->stp_error = EPERM;
			return (0);
		} else {
			return (error);
		}
	} else
		return (0);
}

int
setthreadnice(pcnice_t *pcnice, kthread_t *tp)
{
	int error;
	int nice;
	int inc;
	id_t rtcid;

	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&(ttoproc(tp)->p_lock)));

	/*
	 * The XPG5 standard requires that any realtime process or thread
	 * must be unaffected by a call to setpriority().
	 */
	error = getcidbyname("RT", &rtcid);
	if (error == 0 && tp->t_cid == rtcid) {
		if (pcnice->pc_op == PC_SETNICE)
			return (0);
	}

	if ((error = CL_DONICE(tp, CRED(), 0, &nice)) != 0)
		return (error);

	if (pcnice->pc_op == PC_GETNICE) {
		/*
		 * If there is no change to priority, we should return the
		 * highest priority (lowest numerical value) pertaining to
		 * any of the specified threads.
		 */
		if (nice < pcnice->pc_val)
			pcnice->pc_val = nice;
	} else {
		ASSERT(pcnice->pc_op == PC_SETNICE);
		/*
		 * Try to change the nice value of the thread.
		 */
		inc = pcnice->pc_val - nice;

		error = CL_DONICE(tp, CRED(), inc, &inc);
		schedctl_set_cidpri(tp);
	}

	return (error);
}

int
setprocnice(proc_t *pp, pcnice_t *pcnice)
{
	kthread_t *tp;
	int retval = 0;
	int error;

	ASSERT(MUTEX_HELD(&pidlock));
	mutex_enter(&pp->p_lock);

	if ((tp = pp->p_tlist) == NULL) {
		mutex_exit(&pp->p_lock);
		return (ESRCH);
	}

	/*
	 * Check permissions before changing the nice value.
	 */
	if (pcnice->pc_op == PC_SETNICE) {
		if (!prochasprocperm(pp, curproc, CRED())) {
			mutex_exit(&pp->p_lock);
			return (EPERM);
		}
	}

	do {
		error = setthreadnice(pcnice, tp);
		if (error)
			retval = error;
	} while ((tp = tp->t_forw) != pp->p_tlist);

	mutex_exit(&pp->p_lock);
	return (retval);
}

/*
 * Update the nice value of the specified LWP or set of processes.
 */
static int
donice(procset_t *procset, pcnice_t *pcnice)
{
	int err_proc = 0;
	int err_thread = 0;
	int err = 0;

	/*
	 * Sanity check.
	 */
	if (pcnice->pc_op != PC_GETNICE && pcnice->pc_op != PC_SETNICE)
		return (EINVAL);

	/*
	 * If it is PC_GETNICE operation then set pc_val to the largest
	 * possible nice value to help us find the lowest nice value
	 * pertaining to any of the specified processes.
	 */
	if (pcnice->pc_op == PC_GETNICE)
		pcnice->pc_val = NZERO;

	if (procset->p_lidtype != P_LWPID ||
	    procset->p_ridtype != P_LWPID)
		err_proc = dotoprocs(procset, setprocnice, (char *)pcnice);

	if (procset->p_lidtype == P_LWPID || procset->p_ridtype == P_LWPID) {
		err_thread = dotolwp(procset, setthreadnice, (char *)pcnice);
		/*
		 * dotolwp() can return with p_lock held.  This is required
		 * for the priocntl GETPARMS case.  So, here we just release
		 * the p_lock.
		 */
		if (MUTEX_HELD(&curproc->p_lock))
			mutex_exit(&curproc->p_lock);

		/*
		 * If we were called for a single LWP, then ignore ESRCH
		 * returned by the previous dotoprocs() call.
		 */
		if (err_proc == ESRCH)
			err_proc = 0;
	}

	/*
	 * dotoprocs() ignores the init process if it is in the set, unless
	 * it was the only process found. We want to make sure init is not
	 * excluded if we're going PC_GETNICE operation.
	 */
	if (pcnice->pc_op == PC_GETNICE) {
		proc_t *initpp;

		mutex_enter(&pidlock);
		if ((initpp = prfind(P_INITPID)) != NULL) {
			mutex_enter(&initpp->p_lock);
			if (procinset(initpp, procset)) {
				mutex_exit(&initpp->p_lock);
				err = setprocnice(initpp, pcnice);
			} else {
				mutex_exit(&initpp->p_lock);
			}
		}
		mutex_exit(&pidlock);
	}

	/*
	 * We're returning the latest error here that we've got back from
	 * the setthreadnice() or setprocnice(). That is, err_thread and/or
	 * err_proc can be replaced by err.
	 */
	if (!err)
		err = err_thread ? err_thread : err_proc;

	return (err);
}

int
setthreadprio(pcprio_t *pcprio, kthread_t *tp)
{
	int prio = 0;
	int incr;
	int error;

	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&(ttoproc(tp)->p_lock)));

	if (pcprio->pc_op == PC_SETPRIO && pcprio->pc_cid != tp->t_cid) {
		/*
		 * Target thread must change to new class.
		 * See comments in parmsset(), from where this code was copied.
		 */
		void *bufp = NULL;
		caddr_t clprocp = (caddr_t)tp->t_cldata;
		id_t oldcid = tp->t_cid;

		error = CL_CANEXIT(tp, NULL);
		if (error)
			return (error);
		if (CL_ALLOC(&bufp, pcprio->pc_cid, KM_NOSLEEP) != 0)
			return (ENOMEM);
		error = CL_ENTERCLASS(tp, pcprio->pc_cid, NULL, CRED(), bufp);
		if (error) {
			CL_FREE(pcprio->pc_cid, bufp);
			return (error);
		}
		CL_EXITCLASS(oldcid, clprocp);
		schedctl_set_cidpri(tp);
	}

	if ((error = CL_DOPRIO(tp, CRED(), 0, &prio)) != 0)
		return (error);

	if (pcprio->pc_op == PC_GETPRIO) {
		/*
		 * If we are not setting the priority, we should return the
		 * highest priority pertaining to any of the specified threads.
		 */
		if (prio > pcprio->pc_val) {
			pcprio->pc_cid = tp->t_cid;
			pcprio->pc_val = prio;
		}
	} else if (prio != pcprio->pc_val) {
		/*
		 * Try to change the priority of the thread.
		 */
		incr = pcprio->pc_val - prio;
		error = CL_DOPRIO(tp, CRED(), incr, &prio);
		schedctl_set_cidpri(tp);
	}

	return (error);
}

int
setprocprio(proc_t *pp, pcprio_t *pcprio)
{
	kthread_t *tp;
	int retval = 0;
	int error;

	ASSERT(MUTEX_HELD(&pidlock));
	mutex_enter(&pp->p_lock);

	if ((tp = pp->p_tlist) == NULL) {
		mutex_exit(&pp->p_lock);
		return (ESRCH);
	}

	/*
	 * Check permissions before changing the prio value.
	 */
	if (pcprio->pc_op == PC_SETPRIO) {
		if (!prochasprocperm(pp, curproc, CRED())) {
			mutex_exit(&pp->p_lock);
			return (EPERM);
		}
	}

	do {
		error = setthreadprio(pcprio, tp);
		if (error)
			retval = error;
	} while ((tp = tp->t_forw) != pp->p_tlist);

	mutex_exit(&pp->p_lock);
	return (retval);
}

/*
 * Set the class and priority of the specified LWP or set of processes.
 */
static int
doprio(procset_t *procset, pcprio_t *pcprio)
{
	int err_proc = 0;
	int err_thread = 0;
	int err = 0;

	/*
	 * Sanity check.
	 */
	if (pcprio->pc_op != PC_GETPRIO && pcprio->pc_op != PC_SETPRIO)
		return (EINVAL);
	if (pcprio->pc_op == PC_SETPRIO &&
	    (pcprio->pc_cid >= loaded_classes || pcprio->pc_cid < 1))
		return (EINVAL);

	/*
	 * If it is a PC_GETPRIO operation then set pc_val to the smallest
	 * possible prio value to help us find the highest priority
	 * pertaining to any of the specified processes.
	 */
	if (pcprio->pc_op == PC_GETPRIO)
		pcprio->pc_val = SHRT_MIN;

	if (procset->p_lidtype != P_LWPID ||
	    procset->p_ridtype != P_LWPID)
		err_proc = dotoprocs(procset, setprocprio, (char *)pcprio);

	if (procset->p_lidtype == P_LWPID || procset->p_ridtype == P_LWPID) {
		err_thread = dotolwp(procset, setthreadprio, (char *)pcprio);
		/*
		 * dotolwp() can return with p_lock held.  This is required
		 * for the priocntl GETPARMS case.  So, here we just release
		 * the p_lock.
		 */
		if (MUTEX_HELD(&curproc->p_lock))
			mutex_exit(&curproc->p_lock);

		/*
		 * If we were called for a single LWP, then ignore ESRCH
		 * returned by the previous dotoprocs() call.
		 */
		if (err_proc == ESRCH)
			err_proc = 0;
	}

	/*
	 * dotoprocs() ignores the init process if it is in the set, unless
	 * it was the only process found. We want to make sure init is not
	 * excluded if we're going PC_GETPRIO operation.
	 */
	if (pcprio->pc_op == PC_GETPRIO) {
		proc_t *initpp;

		mutex_enter(&pidlock);
		if ((initpp = prfind(P_INITPID)) != NULL) {
			mutex_enter(&initpp->p_lock);
			if (procinset(initpp, procset)) {
				mutex_exit(&initpp->p_lock);
				err = setprocprio(initpp, pcprio);
			} else {
				mutex_exit(&initpp->p_lock);
			}
		}
		mutex_exit(&pidlock);
	}

	/*
	 * We're returning the latest error here that we've got back from
	 * the setthreadprio() or setprocprio(). That is, err_thread and/or
	 * err_proc can be replaced by err.
	 */
	if (!err)
		err = err_thread ? err_thread : err_proc;

	return (err);
}
