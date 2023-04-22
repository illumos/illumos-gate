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
 * Copyright 2015, Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/regset.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/signal.h>
#include <sys/auxv.h>
#include <sys/user.h>
#include <sys/class.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/zone.h>
#include <sys/copyops.h>
#include <sys/schedctl.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <fs/proc/prdata.h>
#include <sys/contract/process_impl.h>
#include <sys/stdalign.h>

static	void	pr_settrace(proc_t *, sigset_t *);
static	int	pr_setfpregs(prnode_t *, prfpregset_t *);
static	int	pr_setxregs(prnode_t *, prxregset_t *);
static	int	pr_setvaddr(prnode_t *, caddr_t);
static	int	pr_clearsig(prnode_t *);
static	int	pr_clearflt(prnode_t *);
static	int	pr_watch(prnode_t *, prwatch_t *, int *);
static	int	pr_agent(prnode_t *, prgregset_t, int *);
static	int	pr_rdwr(proc_t *, enum uio_rw, priovec_t *);
static	int	pr_scred(proc_t *, prcred_t *, cred_t *, boolean_t);
static	int	pr_spriv(proc_t *, prpriv_t *, cred_t *);
static	int	pr_szoneid(proc_t *, zoneid_t, cred_t *);
static	void	pauselwps(proc_t *);
static	void	unpauselwps(proc_t *);

/*
 * This union represents the size of commands that are generally fixed size in
 * /proc. There are some commands that are variable size because the actual data
 * is structured. Of things in the latter category, some of these are the same
 * across all architectures (e.g. prcred_t, prpriv_t) and some vary and are
 * opaque (e.g. the prxregset_t).
 */
typedef union {
	long		sig;		/* PCKILL, PCUNKILL */
	long		nice;		/* PCNICE */
	long		timeo;		/* PCTWSTOP */
	ulong_t		flags;		/* PCRUN, PCSET, PCUNSET */
	caddr_t		vaddr;		/* PCSVADDR */
	siginfo_t	siginfo;	/* PCSSIG */
	sigset_t	sigset;		/* PCSTRACE, PCSHOLD */
	fltset_t	fltset;		/* PCSFAULT */
	sysset_t	sysset;		/* PCSENTRY, PCSEXIT */
	prgregset_t	prgregset;	/* PCSREG, PCAGENT */
	prfpregset_t	prfpregset;	/* PCSFPREG */
	prwatch_t	prwatch;	/* PCWATCH */
	priovec_t	priovec;	/* PCREAD, PCWRITE */
	prcred_t	prcred;		/* PCSCRED */
	prpriv_t	prpriv;		/* PCSPRIV */
	long		przoneid;	/* PCSZONE */
} arg_t;

static boolean_t
prwritectl_pcscredx_sizef(const void *datap, size_t *sizep)
{
	const prcred_t *cred = datap;

	if (cred->pr_ngroups < 0 || cred->pr_ngroups > ngroups_max) {
		return (B_FALSE);
	}

	if (cred->pr_ngroups == 0) {
		*sizep = 0;
	} else {
		*sizep = (cred->pr_ngroups - 1) * sizeof (gid_t);
	}
	return (B_TRUE);
}

static boolean_t
prwritectl_pcspriv_sizef(const void *datap, size_t *sizep)
{
	const prpriv_t *priv = datap;
	*sizep = priv_prgetprivsize(priv) - sizeof (prpriv_t);
	return (B_TRUE);
}

/*
 * This structure represents a single /proc write command that we support and
 * metadata about how to ensure we have sufficient data for it. To determine the
 * data that we need to read, this combines information from three different
 * sources for a given named command in 'pcs_cmd'. The main goal is to first
 * make sure we have the right minimum amount of information so we can read and
 * validate the data around variable length structures.
 *
 *   o Most commands have a fixed static size. This is represented in the
 *     pcs_size member. This also is used to represent the base structure size
 *     in the case of entries like PCSCREDX.
 *
 *   o Other commands have an unknown minimum size to determine how much data
 *     there is and they use the pcs_minf() function to determine the right
 *     value. This is often unknown at compile time because it is say a
 *     machdep or ISA based feature (ala PCSXREGS) and we'd rather not #ifdef
 *     this code to death. This may be skipped and is for most things. The value
 *     it returns is added to the static value.
 *
 *   o The final piece is the pcs_sizef() function pointer which determines the
 *     total required size for this. It is given a pointer that has at least
 *     pcs_size and pcs_minf() bytes. This is used to determine the total
 *     expected size of the structure. Callers must not dereference data beyond
 *     what they've indicated previously. This should only return extra bytes
 *     that are required beyond what was already indicated between the two
 *     functions.
 *
 * In all cases, the core prwritectl() logic will determine if there is
 * sufficient step along the way for each of these to proceed.
 */
typedef struct proc_control_info {
	long	pcs_cmd;
	size_t	pcs_size;
	boolean_t (*pcs_minf)(size_t *);
	boolean_t (*pcs_sizef)(const void *, size_t *);
} proc_control_info_t;

static const proc_control_info_t proc_ctl_info[] = {
	{ PCNULL,	0,			NULL,		NULL },
	{ PCSTOP,	0,			NULL,		NULL },
	{ PCDSTOP,	0,			NULL,		NULL },
	{ PCWSTOP,	0,			NULL,		NULL },
	{ PCCSIG,	0,			NULL,		NULL },
	{ PCCFAULT,	0,			NULL,		NULL },
	{ PCSSIG,	sizeof (siginfo_t),	NULL,		NULL },
	{ PCTWSTOP,	sizeof (long),		NULL,		NULL },
	{ PCKILL,	sizeof (long),		NULL,		NULL },
	{ PCUNKILL,	sizeof (long),		NULL,		NULL },
	{ PCNICE,	sizeof (long),		NULL,		NULL },
	{ PCRUN,	sizeof (ulong_t),	NULL,		NULL },
	{ PCSET,	sizeof (ulong_t),	NULL,		NULL },
	{ PCUNSET,	sizeof (ulong_t),	NULL,		NULL },
	{ PCSTRACE,	sizeof (sigset_t),	NULL,		NULL },
	{ PCSHOLD,	sizeof (sigset_t),	NULL,		NULL },
	{ PCSFAULT,	sizeof (fltset_t),	NULL,		NULL },
	{ PCSENTRY,	sizeof (sysset_t),	NULL,		NULL },
	{ PCSEXIT,	sizeof (sysset_t),	NULL,		NULL },
	{ PCSREG,	sizeof (prgregset_t),	NULL,		NULL },
	{ PCAGENT,	sizeof (prgregset_t),	NULL,		NULL },
	{ PCSFPREG,	sizeof (prfpregset_t),	NULL,		NULL },
	{ PCSXREG,	0,			prwriteminxreg,
	    prwritesizexreg },
	{ PCWATCH,	sizeof (prwatch_t),	NULL,		NULL },
	{ PCREAD,	sizeof (priovec_t),	NULL,		NULL },
	{ PCWRITE,	sizeof (priovec_t),	NULL,		NULL },
	{ PCSCRED,	sizeof (prcred_t),	NULL,		NULL },
	{ PCSCREDX,	sizeof (prcred_t),	NULL,
	    prwritectl_pcscredx_sizef },
	{ PCSPRIV,	sizeof (prpriv_t),	NULL,
	    prwritectl_pcspriv_sizef },
	{ PCSZONE,	sizeof (long),		NULL,		NULL },
};

/*
 * We need a default buffer that we're going to allocate when we need memory to
 * read control operations. This is on average large enough to hold multiple
 * control operations. We leave this as a smaller value on debug builds just
 * to exercise our reallocation logic.
 */
#ifdef	DEBUG
#define	PROC_CTL_DEFSIZE	32
#else
#define	PROC_CTL_DEFSIZE	1024
#endif

/*
 * This structure is used to track all of the information that we have around a
 * prwritectl call. This is used to reduce function parameters and make state
 * clear.
 */
typedef struct {
	void	*prwc_buf;
	size_t	prwc_buflen;
	size_t	prwc_curvalid;
	uio_t	*prwc_uiop;
	prnode_t *prwc_pnp;
	boolean_t prwc_locked;
	boolean_t prwc_need32;
	void	*prwc_buf32;
} prwritectl_t;

/*
 * Ensure that we have at least "needed" data marked as valid and present. If we
 * require additional data, then we will read that in from uio_t. When we read
 * data, we try to buffer as much data as will fit in our internal buffers in
 * one go.
 */
static int
prwritectl_readin(prwritectl_t *prwc, size_t needed)
{
	int ret;
	size_t toread;
	void *start;

	/*
	 * If we have as much data as we need then we're good to go.
	 */
	if (prwc->prwc_curvalid > needed) {
		ASSERT3U(prwc->prwc_buflen, >=, prwc->prwc_curvalid);
		ASSERT3U(prwc->prwc_buflen, >=, needed);
		return (0);
	}

	/*
	 * We don't have all of our data. We must make sure of several things:
	 *
	 *   1. That there actually is enough data in the uio_t for what we
	 *	need, considering what we've already read.
	 *   2. If the process is locked, at this point, we want to unlock it
	 *	before we deal with any I/O or memory allocation. Otherwise we
	 *	can wreak havoc with p_lock / paging.
	 *   3. We need to make sure that our buffer is large enough to actually
	 *	fit it all.
	 *   4. Only at that point can we actually perform the read.
	 */
	if (needed - prwc->prwc_curvalid > prwc->prwc_uiop->uio_resid) {
		return (EINVAL);
	}

	if (prwc->prwc_locked) {
		prunlock(prwc->prwc_pnp);
		prwc->prwc_locked = B_FALSE;
	}

	if (needed > prwc->prwc_buflen) {
		size_t new_len = P2ROUNDUP(needed, PROC_CTL_DEFSIZE);
		prwc->prwc_buf = kmem_rezalloc(prwc->prwc_buf,
		    prwc->prwc_buflen, new_len, KM_SLEEP);
		if (prwc->prwc_need32) {
			prwc->prwc_buf32 = kmem_rezalloc(prwc->prwc_buf32,
			    prwc->prwc_buflen, new_len, KM_SLEEP);
		}
		prwc->prwc_buflen = new_len;
	}

	toread = MIN(prwc->prwc_buflen - prwc->prwc_curvalid,
	    prwc->prwc_uiop->uio_resid);
	ASSERT3U(toread, >=, needed - prwc->prwc_curvalid);
	start = (void *)((uintptr_t)prwc->prwc_buf + prwc->prwc_curvalid);
	if ((ret = uiomove(start, toread, UIO_WRITE, prwc->prwc_uiop)) != 0) {
		return (ret);
	}

	prwc->prwc_curvalid += toread;
	return (0);
}

static const proc_control_info_t *
prwritectl_cmd_identify(const prwritectl_t *prwc,
    const proc_control_info_t *info, size_t ninfo, size_t cmdsize)
{
	long cmd;

	ASSERT(cmdsize == sizeof (int32_t) || cmdsize == sizeof (long));
	if (cmdsize == 4) {
		cmd = (long)*(int32_t *)prwc->prwc_buf;
	} else {
		cmd = *(long *)prwc->prwc_buf;
	}


	for (size_t i = 0; i < ninfo; i++) {
		if (info[i].pcs_cmd == cmd) {
			return (&info[i]);
		}
	}

	return (NULL);
}

/*
 * Control operations (lots).
 *
 * Users can submit one or more commands to us in the uio_t. They are required
 * to always be complete messages. The first one that fails will cause all
 * subsequent things to fail. Processing this can be a little tricky as the
 * actual data size that may be required is variable, not all structures are
 * fixed sizes and some vary based on the instructing set (e.g. x86 vs.
 * something else).
 *
 * The way that we handle process locking deserves some consideration. Prior to
 * the colonization of prwritectl and the support for dynamic sizing of data,
 * the logic would try to read in a large chunk of data and keep a process
 * locked throughout that period and then unlock it before reading more data. As
 * such, we mimic that logically and basically lock it before executing the
 * first (or any subsequent) command and then only unlock it either when we're
 * done entirely or we need to allocate memory or read from the process.
 *
 * This function is a common implementation for both the ILP32 and LP64 entry
 * points as they are mostly the same except for the sizing and control function
 * we call.
 */
int
prwritectl_common(vnode_t *vp, uio_t *uiop, cred_t *cr,
    const proc_control_info_t *proc_info, size_t ninfo, size_t cmdsize,
    int (*pr_controlf)(long, void *, prnode_t *, cred_t *))
{
	int ret;
	prwritectl_t prwc;

	VERIFY(cmdsize == sizeof (int32_t) || cmdsize == sizeof (long));

	bzero(&prwc, sizeof (prwc));
	prwc.prwc_pnp = VTOP(vp);
	prwc.prwc_uiop = uiop;
	prwc.prwc_need32 = (cmdsize == sizeof (int32_t));

	/*
	 * We may have multiple commands to read and want to try to minimize the
	 * amount of reading that we do. Our callers expect us to have a
	 * contiguous buffer for a command's actual implementation. However, we
	 * must have at least a single long worth of data, otherwise it's not
	 * worth continuing.
	 */
	while (uiop->uio_resid > 0 || prwc.prwc_curvalid > 0) {
		const proc_control_info_t *proc_cmd;
		void *data;

		/*
		 * Check if we have enough data to identify a command. If not,
		 * we read as much as we can in one gulp.
		 */
		if ((ret = prwritectl_readin(&prwc, cmdsize)) != 0) {
			goto out;
		}

		/*
		 * Identify the command and figure out how how much data we
		 * should have read in the kernel. Some commands have a variable
		 * length and we need to make sure the minimum is met before
		 * asking how much there is in general. Most things know what
		 * the minimum length is and this pcs_minf() is not implemented.
		 * However things that are ISA-specific require us to ask that
		 * first.
		 *
		 * We also must be aware that there may not actually be enough
		 * data present in the uio_t.
		 */
		if ((proc_cmd = prwritectl_cmd_identify(&prwc, proc_info,
		    ninfo, cmdsize)) == NULL) {
			ret = EINVAL;
			goto out;
		}

		size_t needed_data = cmdsize + proc_cmd->pcs_size;
		if (proc_cmd->pcs_minf != NULL) {
			size_t min;

			if (!proc_cmd->pcs_minf(&min)) {
				ret = EINVAL;
				goto out;
			}

			needed_data += min;
		}

		if (proc_cmd->pcs_sizef != NULL) {
			size_t extra;

			/*
			 * Make sure we have the minimum amount of data that
			 * they asked us to between the static and minf
			 * function.
			 */
			if ((ret = prwritectl_readin(&prwc, needed_data)) !=
			    0) {
				goto out;
			}

			VERIFY3U(prwc.prwc_curvalid, >, cmdsize);
			data = (void *)((uintptr_t)prwc.prwc_buf + cmdsize);
			if (!proc_cmd->pcs_sizef(data, &extra)) {
				ret = EINVAL;
				goto out;
			}

			needed_data += extra;
		}

		/*
		 * Now that we know how much data we're supposed to have,
		 * finally ensure we have the total amount we need.
		 */
		if ((ret = prwritectl_readin(&prwc, needed_data)) != 0) {
			goto out;
		}

		/*
		 * /proc has traditionally assumed control writes come in
		 * multiples of a long. This is 4 bytes for ILP32 and 8 bytes
		 * for LP64. When calculating the required size for a structure,
		 * it would always round that up to the next long. However, the
		 * exact combination of circumstances changes with the
		 * introduction of the 64-bit kernel. For 64-bit processes we
		 * round up when the current command we're processing isn't the
		 * last one.
		 *
		 * Because of our tracking structures and caching we need to
		 * look beyond the uio_t to make this determination. In
		 * particular, the uio_t can have a zero resid, but we may still
		 * have additional data to read as indicated by prwc_curvalid
		 * exceeding the current command size. In the end, we must check
		 * both of these cases.
		 */
		if ((needed_data % cmdsize) != 0) {
			if (cmdsize == sizeof (int32_t) ||
			    prwc.prwc_curvalid > needed_data ||
			    prwc.prwc_uiop->uio_resid > 0) {
				needed_data = P2ROUNDUP(needed_data,
				    cmdsize);
				if ((ret = prwritectl_readin(&prwc,
				    needed_data)) != 0) {
					goto out;
				}
			}
		}

		if (!prwc.prwc_locked) {
			ret = prlock(prwc.prwc_pnp, ZNO);
			if (ret != 0) {
				goto out;
			}
			prwc.prwc_locked = B_TRUE;
		}

		/*
		 * Run our actual command. When there is an error, then the
		 * underlying pr_control call will have unlocked the prnode_t
		 * on our behalf. pr_control can return -1, which is a special
		 * error indicating a timeout occurred. In such a case the node
		 * is unlocked; however, that we are supposed to continue
		 * processing commands regardless.
		 *
		 * Finally, we must deal with with one actual wrinkle. The LP64
		 * based logic always guarantees that we have data that is
		 * 8-byte aligned. However, the ILP32 logic is 4-byte aligned
		 * and the rest of the /proc code assumes it can always
		 * dereference it. If we're not aligned, we have to bcopy it to
		 * a temporary buffer.
		 */
		data = (void *)((uintptr_t)prwc.prwc_buf + cmdsize);
#ifdef	DEBUG
		if (cmdsize == sizeof (long)) {
			ASSERT0((uintptr_t)data % alignof (long));
		}
#endif
		if (prwc.prwc_need32 && ((uintptr_t)data % alignof (long)) !=
		    0 && needed_data > cmdsize) {
			bcopy(data, prwc.prwc_buf32, needed_data - cmdsize);
			data = prwc.prwc_buf32;
		}
		ret = pr_controlf(proc_cmd->pcs_cmd, data, prwc.prwc_pnp, cr);
		if (ret != 0) {
			prwc.prwc_locked = B_FALSE;
			if (ret > 0) {
				goto out;
			}
		}

		/*
		 * Finally, now that we have processed this command, we need to
		 * move on. To make our life simple, we basically shift all the
		 * data in our buffer over to indicate it's been consumed. While
		 * a little wasteful, this simplifies buffer management and
		 * guarantees that command processing uses a semi-sanitized
		 * state. Visually, this is the following transformation:
		 *
		 *  0			20		prwc.prwc_curvalid
		 *   +------------------+----------------+
		 *   |   needed_data    | remaining_data |
		 *   +------------------+----------------+
		 *
		 * In the above example we are shifting all the data over by 20,
		 * so remaining data starts at 0. This leaves us needed_data
		 * bytes to clean up from what was valid.
		 */
		if (prwc.prwc_buf32 != NULL) {
			bzero(prwc.prwc_buf32, needed_data - cmdsize);
		}

		if (prwc.prwc_curvalid > needed_data) {
			size_t save_size = prwc.prwc_curvalid - needed_data;
			void *first_save = (void *)((uintptr_t)prwc.prwc_buf +
			    needed_data);
			memmove(prwc.prwc_buf, first_save, save_size);
			void *first_zero = (void *)((uintptr_t)prwc.prwc_buf +
			    save_size);
			bzero(first_zero, needed_data);
		} else {
			bzero(prwc.prwc_buf, prwc.prwc_curvalid);
		}
		prwc.prwc_curvalid -= needed_data;
	}

	/*
	 * We've managed to successfully process everything. We can actually say
	 * this was successful now.
	 */
	ret = 0;

out:
	if (prwc.prwc_locked) {
		prunlock(prwc.prwc_pnp);
		prwc.prwc_locked = B_FALSE;
	}

	if (prwc.prwc_buf != NULL) {
		kmem_free(prwc.prwc_buf, prwc.prwc_buflen);
	}

	if (prwc.prwc_buf32 != NULL) {
		VERIFY(prwc.prwc_need32);
		kmem_free(prwc.prwc_buf32, prwc.prwc_buflen);
	}

	return (ret);
}

static int
pr_control(long cmd, void *generic, prnode_t *pnp, cred_t *cr)
{
	prcommon_t *pcp;
	proc_t *p;
	int unlocked;
	int error = 0;
	arg_t *argp = generic;

	if (cmd == PCNULL)
		return (0);

	pcp = pnp->pr_common;
	p = pcp->prc_proc;
	ASSERT(p != NULL);

	/* System processes defy control. */
	if (p->p_flag & SSYS) {
		prunlock(pnp);
		return (EBUSY);
	}

	switch (cmd) {

	default:
		error = EINVAL;
		break;

	case PCSTOP:	/* direct process or lwp to stop and wait for stop */
	case PCDSTOP:	/* direct process or lwp to stop, don't wait */
	case PCWSTOP:	/* wait for process or lwp to stop */
	case PCTWSTOP:	/* wait for process or lwp to stop, with timeout */
		{
			time_t timeo;

			/*
			 * Can't apply to a system process.
			 */
			if (p->p_as == &kas) {
				error = EBUSY;
				break;
			}

			if (cmd == PCSTOP || cmd == PCDSTOP)
				pr_stop(pnp);

			if (cmd == PCDSTOP)
				break;

			/*
			 * If an lwp is waiting for itself or its process,
			 * don't wait. The stopped lwp would never see the
			 * fact that it is stopped.
			 */
			if ((pcp->prc_flags & PRC_LWP)?
			    (pcp->prc_thread == curthread) : (p == curproc)) {
				if (cmd == PCWSTOP || cmd == PCTWSTOP)
					error = EBUSY;
				break;
			}

			timeo = (cmd == PCTWSTOP)? (time_t)argp->timeo : 0;
			if ((error = pr_wait_stop(pnp, timeo)) != 0)
				return (error);

			break;
		}

	case PCRUN:	/* make lwp or process runnable */
		error = pr_setrun(pnp, argp->flags);
		break;

	case PCSTRACE:	/* set signal trace mask */
		pr_settrace(p,  &argp->sigset);
		break;

	case PCSSIG:	/* set current signal */
		error = pr_setsig(pnp, &argp->siginfo);
		if (argp->siginfo.si_signo == SIGKILL && error == 0) {
			prunlock(pnp);
			pr_wait_die(pnp);
			return (-1);
		}
		break;

	case PCKILL:	/* send signal */
		error = pr_kill(pnp, (int)argp->sig, cr);
		if (error == 0 && argp->sig == SIGKILL) {
			prunlock(pnp);
			pr_wait_die(pnp);
			return (-1);
		}
		break;

	case PCUNKILL:	/* delete a pending signal */
		error = pr_unkill(pnp, (int)argp->sig);
		break;

	case PCNICE:	/* set nice priority */
		error = pr_nice(p, (int)argp->nice, cr);
		break;

	case PCSENTRY:	/* set syscall entry bit mask */
	case PCSEXIT:	/* set syscall exit bit mask */
		pr_setentryexit(p, &argp->sysset, cmd == PCSENTRY);
		break;

	case PCSET:	/* set process flags */
		error = pr_set(p, argp->flags);
		break;

	case PCUNSET:	/* unset process flags */
		error = pr_unset(p, argp->flags);
		break;

	case PCSREG:	/* set general registers */
		{
			kthread_t *t = pr_thread(pnp);

			if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t)) {
				thread_unlock(t);
				error = EBUSY;
			} else {
				thread_unlock(t);
				mutex_exit(&p->p_lock);
				prsetprregs(ttolwp(t), argp->prgregset, 0);
				mutex_enter(&p->p_lock);
			}
			break;
		}

	case PCSFPREG:	/* set floating-point registers */
		error = pr_setfpregs(pnp, &argp->prfpregset);
		break;

	case PCSXREG:	/* set extra registers */
		error = pr_setxregs(pnp, (prxregset_t *)argp);
		break;

	case PCSVADDR:	/* set virtual address at which to resume */
		error = pr_setvaddr(pnp, argp->vaddr);
		break;

	case PCSHOLD:	/* set signal-hold mask */
		pr_sethold(pnp, &argp->sigset);
		break;

	case PCSFAULT:	/* set mask of traced faults */
		pr_setfault(p, &argp->fltset);
		break;

	case PCCSIG:	/* clear current signal */
		error = pr_clearsig(pnp);
		break;

	case PCCFAULT:	/* clear current fault */
		error = pr_clearflt(pnp);
		break;

	case PCWATCH:	/* set or clear watched areas */
		error = pr_watch(pnp, &argp->prwatch, &unlocked);
		if (error && unlocked)
			return (error);
		break;

	case PCAGENT:	/* create the /proc agent lwp in the target process */
		error = pr_agent(pnp, argp->prgregset, &unlocked);
		if (error && unlocked)
			return (error);
		break;

	case PCREAD:	/* read from the address space */
		error = pr_rdwr(p, UIO_READ, &argp->priovec);
		break;

	case PCWRITE:	/* write to the address space */
		error = pr_rdwr(p, UIO_WRITE, &argp->priovec);
		break;

	case PCSCRED:	/* set the process credentials */
	case PCSCREDX:
		error = pr_scred(p, &argp->prcred, cr, cmd == PCSCREDX);
		break;

	case PCSPRIV:	/* set the process privileges */
		error = pr_spriv(p, &argp->prpriv, cr);
		break;
	case PCSZONE:	/* set the process's zoneid credentials */
		error = pr_szoneid(p, (zoneid_t)argp->przoneid, cr);
		break;
	}

	if (error)
		prunlock(pnp);
	return (error);
}

int
prwritectl(vnode_t *vp, uio_t *uiop, cred_t *cr)
{
	return (prwritectl_common(vp, uiop, cr, proc_ctl_info,
	    ARRAY_SIZE(proc_ctl_info), sizeof (long), pr_control));
}

#ifdef _SYSCALL32_IMPL

typedef union {
	int32_t		sig;		/* PCKILL, PCUNKILL */
	int32_t		nice;		/* PCNICE */
	int32_t		timeo;		/* PCTWSTOP */
	uint32_t	flags;		/* PCRUN, PCSET, PCUNSET */
	caddr32_t	vaddr;		/* PCSVADDR */
	siginfo32_t	siginfo;	/* PCSSIG */
	sigset_t	sigset;		/* PCSTRACE, PCSHOLD */
	fltset_t	fltset;		/* PCSFAULT */
	sysset_t	sysset;		/* PCSENTRY, PCSEXIT */
	prgregset32_t	prgregset;	/* PCSREG, PCAGENT */
	prfpregset32_t	prfpregset;	/* PCSFPREG */
	prwatch32_t	prwatch;	/* PCWATCH */
	priovec32_t	priovec;	/* PCREAD, PCWRITE */
	prcred32_t	prcred;		/* PCSCRED */
	prpriv_t	prpriv;		/* PCSPRIV */
	int32_t		przoneid;	/* PCSZONE */
} arg32_t;

static	int	pr_setfpregs32(prnode_t *, prfpregset32_t *);

static boolean_t
prwritectl_pcscredx32_sizef(const void *datap, size_t *sizep)
{
	const prcred32_t *cred = datap;

	if (cred->pr_ngroups < 0 || cred->pr_ngroups > ngroups_max) {
		return (B_FALSE);
	}

	if (cred->pr_ngroups == 0) {
		*sizep = 0;
	} else {
		*sizep = (cred->pr_ngroups - 1) * sizeof (gid32_t);
	}
	return (B_TRUE);
}

/*
 * When dealing with ILP32 code, we are not at a point where we can assume
 * 64-bit aligned data. Any functions that are operating here must be aware of
 * that.
 */
static const proc_control_info_t proc_ctl_info32[] = {
	{ PCNULL,	0,			NULL,		NULL },
	{ PCSTOP,	0,			NULL,		NULL },
	{ PCDSTOP,	0,			NULL,		NULL },
	{ PCWSTOP,	0,			NULL,		NULL },
	{ PCCSIG,	0,			NULL,		NULL },
	{ PCCFAULT,	0,			NULL,		NULL },
	{ PCSSIG,	sizeof (siginfo32_t),	NULL,		NULL },
	{ PCTWSTOP,	sizeof (int32_t),	NULL,		NULL },
	{ PCKILL,	sizeof (int32_t),	NULL,		NULL },
	{ PCUNKILL,	sizeof (int32_t),	NULL,		NULL },
	{ PCNICE,	sizeof (int32_t),	NULL,		NULL },
	{ PCRUN,	sizeof (uint32_t),	NULL,		NULL },
	{ PCSET,	sizeof (uint32_t),	NULL,		NULL },
	{ PCUNSET,	sizeof (uint32_t),	NULL,		NULL },
	{ PCSVADDR,	sizeof (caddr32_t),	NULL,		NULL },
	{ PCSTRACE,	sizeof (sigset_t),	NULL,		NULL },
	{ PCSHOLD,	sizeof (sigset_t),	NULL,		NULL },
	{ PCSFAULT,	sizeof (fltset_t),	NULL,		NULL },
	{ PCSENTRY,	sizeof (sysset_t),	NULL,		NULL },
	{ PCSEXIT,	sizeof (sysset_t),	NULL,		NULL },
	{ PCSREG,	sizeof (prgregset32_t),	NULL,		NULL },
	{ PCAGENT,	sizeof (prgregset32_t),	NULL,		NULL },
	{ PCSFPREG,	sizeof (prfpregset32_t), NULL,		NULL },
	{ PCSXREG,	0,			prwriteminxreg,
	    prwritesizexreg },
	{ PCWATCH,	sizeof (prwatch32_t),	NULL,		NULL },
	{ PCREAD,	sizeof (priovec32_t),	NULL,		NULL },
	{ PCWRITE,	sizeof (priovec32_t),	NULL,		NULL },
	{ PCSCRED,	sizeof (prcred32_t),	NULL,		NULL },
	{ PCSCREDX,	sizeof (prcred32_t),	NULL,
	    prwritectl_pcscredx32_sizef },
	{ PCSPRIV,	sizeof (prpriv_t),	NULL,
	    prwritectl_pcspriv_sizef },
	{ PCSZONE,	sizeof (long),		NULL,		NULL },
};

static int
pr_control32(long cmd, void *generic, prnode_t *pnp, cred_t *cr)
{
	prcommon_t *pcp;
	proc_t *p;
	int unlocked;
	int error = 0;
	arg32_t *argp = generic;

	if (cmd == PCNULL)
		return (0);

	pcp = pnp->pr_common;
	p = pcp->prc_proc;
	ASSERT(p != NULL);

	if (p->p_flag & SSYS) {
		prunlock(pnp);
		return (EBUSY);
	}

	switch (cmd) {

	default:
		error = EINVAL;
		break;

	case PCSTOP:	/* direct process or lwp to stop and wait for stop */
	case PCDSTOP:	/* direct process or lwp to stop, don't wait */
	case PCWSTOP:	/* wait for process or lwp to stop */
	case PCTWSTOP:	/* wait for process or lwp to stop, with timeout */
		{
			time_t timeo;

			/*
			 * Can't apply to a system process.
			 */
			if (p->p_as == &kas) {
				error = EBUSY;
				break;
			}

			if (cmd == PCSTOP || cmd == PCDSTOP)
				pr_stop(pnp);

			if (cmd == PCDSTOP)
				break;

			/*
			 * If an lwp is waiting for itself or its process,
			 * don't wait. The lwp will never see the fact that
			 * itself is stopped.
			 */
			if ((pcp->prc_flags & PRC_LWP)?
			    (pcp->prc_thread == curthread) : (p == curproc)) {
				if (cmd == PCWSTOP || cmd == PCTWSTOP)
					error = EBUSY;
				break;
			}

			timeo = (cmd == PCTWSTOP)? (time_t)argp->timeo : 0;
			if ((error = pr_wait_stop(pnp, timeo)) != 0)
				return (error);

			break;
		}

	case PCRUN:	/* make lwp or process runnable */
		error = pr_setrun(pnp, (ulong_t)argp->flags);
		break;

	case PCSTRACE:	/* set signal trace mask */
		pr_settrace(p,  &argp->sigset);
		break;

	case PCSSIG:	/* set current signal */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else {
			int sig = (int)argp->siginfo.si_signo;
			siginfo_t siginfo;

			bzero(&siginfo, sizeof (siginfo));
			siginfo_32tok(&argp->siginfo, (k_siginfo_t *)&siginfo);
			error = pr_setsig(pnp, &siginfo);
			if (sig == SIGKILL && error == 0) {
				prunlock(pnp);
				pr_wait_die(pnp);
				return (-1);
			}
		}
		break;

	case PCKILL:	/* send signal */
		error = pr_kill(pnp, (int)argp->sig, cr);
		if (error == 0 && argp->sig == SIGKILL) {
			prunlock(pnp);
			pr_wait_die(pnp);
			return (-1);
		}
		break;

	case PCUNKILL:	/* delete a pending signal */
		error = pr_unkill(pnp, (int)argp->sig);
		break;

	case PCNICE:	/* set nice priority */
		error = pr_nice(p, (int)argp->nice, cr);
		break;

	case PCSENTRY:	/* set syscall entry bit mask */
	case PCSEXIT:	/* set syscall exit bit mask */
		pr_setentryexit(p, &argp->sysset, cmd == PCSENTRY);
		break;

	case PCSET:	/* set process flags */
		error = pr_set(p, (long)argp->flags);
		break;

	case PCUNSET:	/* unset process flags */
		error = pr_unset(p, (long)argp->flags);
		break;

	case PCSREG:	/* set general registers */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else {
			kthread_t *t = pr_thread(pnp);

			if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t)) {
				thread_unlock(t);
				error = EBUSY;
			} else {
				prgregset_t prgregset;
				klwp_t *lwp = ttolwp(t);

				thread_unlock(t);
				mutex_exit(&p->p_lock);
				prgregset_32ton(lwp, argp->prgregset,
				    prgregset);
				prsetprregs(lwp, prgregset, 0);
				mutex_enter(&p->p_lock);
			}
		}
		break;

	case PCSFPREG:	/* set floating-point registers */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else
			error = pr_setfpregs32(pnp, &argp->prfpregset);
		break;

	case PCSXREG:	/* set extra registers */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else
			error = pr_setxregs(pnp, (prxregset_t *)argp);
		break;

	case PCSVADDR:	/* set virtual address at which to resume */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else
			error = pr_setvaddr(pnp,
			    (caddr_t)(uintptr_t)argp->vaddr);
		break;

	case PCSHOLD:	/* set signal-hold mask */
		pr_sethold(pnp, &argp->sigset);
		break;

	case PCSFAULT:	/* set mask of traced faults */
		pr_setfault(p, &argp->fltset);
		break;

	case PCCSIG:	/* clear current signal */
		error = pr_clearsig(pnp);
		break;

	case PCCFAULT:	/* clear current fault */
		error = pr_clearflt(pnp);
		break;

	case PCWATCH:	/* set or clear watched areas */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else {
			prwatch_t prwatch;

			prwatch.pr_vaddr = argp->prwatch.pr_vaddr;
			prwatch.pr_size = argp->prwatch.pr_size;
			prwatch.pr_wflags = argp->prwatch.pr_wflags;
			prwatch.pr_pad = argp->prwatch.pr_pad;
			error = pr_watch(pnp, &prwatch, &unlocked);
			if (error && unlocked)
				return (error);
		}
		break;

	case PCAGENT:	/* create the /proc agent lwp in the target process */
		if (PROCESS_NOT_32BIT(p))
			error = EOVERFLOW;
		else {
			prgregset_t prgregset;
			kthread_t *t = pr_thread(pnp);
			klwp_t *lwp = ttolwp(t);
			thread_unlock(t);
			mutex_exit(&p->p_lock);
			prgregset_32ton(lwp, argp->prgregset, prgregset);
			mutex_enter(&p->p_lock);
			error = pr_agent(pnp, prgregset, &unlocked);
			if (error && unlocked)
				return (error);
		}
		break;

	case PCREAD:	/* read from the address space */
	case PCWRITE:	/* write to the address space */
		if (PROCESS_NOT_32BIT(p) || (pnp->pr_flags & PR_OFFMAX))
			error = EOVERFLOW;
		else {
			enum uio_rw rw = (cmd == PCREAD)? UIO_READ : UIO_WRITE;
			priovec_t priovec;

			priovec.pio_base =
			    (void *)(uintptr_t)argp->priovec.pio_base;
			priovec.pio_len = (size_t)argp->priovec.pio_len;
			priovec.pio_offset = (off_t)
			    (uint32_t)argp->priovec.pio_offset;
			error = pr_rdwr(p, rw, &priovec);
		}
		break;

	case PCSCRED:	/* set the process credentials */
	case PCSCREDX:
		{
			/*
			 * All the fields in these structures are exactly the
			 * same and so the structures are compatible.  In case
			 * this ever changes, we catch this with the ASSERT
			 * below.
			 */
			prcred_t *prcred = (prcred_t *)&argp->prcred;

#ifndef __lint
			ASSERT(sizeof (prcred_t) == sizeof (prcred32_t));
#endif

			error = pr_scred(p, prcred, cr, cmd == PCSCREDX);
			break;
		}

	case PCSPRIV:	/* set the process privileges */
		error = pr_spriv(p, &argp->prpriv, cr);
		break;

	case PCSZONE:	/* set the process's zoneid */
		error = pr_szoneid(p, (zoneid_t)argp->przoneid, cr);
		break;
	}

	if (error)
		prunlock(pnp);
	return (error);
}

int
prwritectl32(struct vnode *vp, struct uio *uiop, cred_t *cr)
{
	return (prwritectl_common(vp, uiop, cr, proc_ctl_info32,
	    ARRAY_SIZE(proc_ctl_info32), sizeof (int32_t), pr_control32));
}
#endif	/* _SYSCALL32_IMPL */

/*
 * Return the specific or chosen thread/lwp for a control operation.
 * Returns with the thread locked via thread_lock(t).
 */
kthread_t *
pr_thread(prnode_t *pnp)
{
	prcommon_t *pcp = pnp->pr_common;
	kthread_t *t;

	if (pcp->prc_flags & PRC_LWP) {
		t = pcp->prc_thread;
		ASSERT(t != NULL);
		thread_lock(t);
	} else {
		proc_t *p = pcp->prc_proc;
		t = prchoose(p);	/* returns locked thread */
		ASSERT(t != NULL);
	}

	return (t);
}

/*
 * Direct the process or lwp to stop.
 */
void
pr_stop(prnode_t *pnp)
{
	prcommon_t *pcp = pnp->pr_common;
	proc_t *p = pcp->prc_proc;
	kthread_t *t;
	vnode_t *vp;

	/*
	 * If already stopped, do nothing; otherwise flag
	 * it to be stopped the next time it tries to run.
	 * If sleeping at interruptible priority, set it
	 * running so it will stop within cv_wait_sig().
	 *
	 * Take care to cooperate with jobcontrol: if an lwp
	 * is stopped due to the default action of a jobcontrol
	 * stop signal, flag it to be stopped the next time it
	 * starts due to a SIGCONT signal.
	 */
	if (pcp->prc_flags & PRC_LWP)
		t = pcp->prc_thread;
	else
		t = p->p_tlist;
	ASSERT(t != NULL);

	do {
		int notify;

		notify = 0;
		thread_lock(t);
		if (!ISTOPPED(t)) {
			t->t_proc_flag |= TP_PRSTOP;
			t->t_sig_check = 1;	/* do ISSIG */
		}

		/* Move the thread from wait queue to run queue */
		if (ISWAITING(t))
			setrun_locked(t);

		if (ISWAKEABLE(t)) {
			if (t->t_wchan0 == NULL)
				setrun_locked(t);
			else if (!VSTOPPED(t)) {
				/*
				 * Mark it virtually stopped.
				 */
				t->t_proc_flag |= TP_PRVSTOP;
				notify = 1;
			}
		}
		/*
		 * force the thread into the kernel
		 * if it is not already there.
		 */
		prpokethread(t);
		thread_unlock(t);
		if (notify &&
		    (vp = p->p_lwpdir[t->t_dslot].ld_entry->le_trace) != NULL)
			prnotify(vp);
		if (pcp->prc_flags & PRC_LWP)
			break;
	} while ((t = t->t_forw) != p->p_tlist);

	/*
	 * We do this just in case the thread we asked
	 * to stop is in holdlwps() (called from cfork()).
	 */
	cv_broadcast(&p->p_holdlwps);
}

/*
 * Sleep until the lwp stops, but cooperate with
 * jobcontrol:  Don't wake up if the lwp is stopped
 * due to the default action of a jobcontrol stop signal.
 * If this is the process file descriptor, sleep
 * until all of the process's lwps stop.
 */
int
pr_wait_stop(prnode_t *pnp, time_t timeo)
{
	prcommon_t *pcp = pnp->pr_common;
	proc_t *p = pcp->prc_proc;
	timestruc_t rqtime;
	timestruc_t *rqtp = NULL;
	int timecheck = 0;
	kthread_t *t;
	int error;

	if (timeo > 0) {	/* millisecond timeout */
		/*
		 * Determine the precise future time of the requested timeout.
		 */
		timestruc_t now;

		timecheck = timechanged;
		gethrestime(&now);
		rqtp = &rqtime;
		rqtp->tv_sec = timeo / MILLISEC;
		rqtp->tv_nsec = (timeo % MILLISEC) * MICROSEC;
		timespecadd(rqtp, &now);
	}

	if (pcp->prc_flags & PRC_LWP) {	/* lwp file descriptor */
		t = pcp->prc_thread;
		ASSERT(t != NULL);
		thread_lock(t);
		while (!ISTOPPED(t) && !VSTOPPED(t)) {
			thread_unlock(t);
			mutex_enter(&pcp->prc_mutex);
			prunlock(pnp);
			error = pr_wait(pcp, rqtp, timecheck);
			if (error)	/* -1 is timeout */
				return (error);
			if ((error = prlock(pnp, ZNO)) != 0)
				return (error);
			ASSERT(p == pcp->prc_proc);
			ASSERT(t == pcp->prc_thread);
			thread_lock(t);
		}
		thread_unlock(t);
	} else {			/* process file descriptor */
		t = prchoose(p);	/* returns locked thread */
		ASSERT(t != NULL);
		ASSERT(MUTEX_HELD(&p->p_lock));
		while ((!ISTOPPED(t) && !VSTOPPED(t) && !SUSPENDED(t)) ||
		    (p->p_flag & SEXITLWPS)) {
			thread_unlock(t);
			mutex_enter(&pcp->prc_mutex);
			prunlock(pnp);
			error = pr_wait(pcp, rqtp, timecheck);
			if (error)	/* -1 is timeout */
				return (error);
			if ((error = prlock(pnp, ZNO)) != 0)
				return (error);
			ASSERT(p == pcp->prc_proc);
			t = prchoose(p);	/* returns locked t */
			ASSERT(t != NULL);
		}
		thread_unlock(t);
	}

	ASSERT(!(pcp->prc_flags & PRC_DESTROY) && p->p_stat != SZOMB &&
	    t != NULL && t->t_state != TS_ZOMB);

	return (0);
}

int
pr_setrun(prnode_t *pnp, ulong_t flags)
{
	prcommon_t *pcp = pnp->pr_common;
	proc_t *p = pcp->prc_proc;
	kthread_t *t;
	klwp_t *lwp;

	/*
	 * Cannot set an lwp running if it is not stopped.
	 * Also, no lwp other than the /proc agent lwp can
	 * be set running so long as the /proc agent lwp exists.
	 */
	t = pr_thread(pnp);	/* returns locked thread */
	if ((!ISTOPPED(t) && !VSTOPPED(t) &&
	    !(t->t_proc_flag & TP_PRSTOP)) ||
	    (p->p_agenttp != NULL &&
	    (t != p->p_agenttp || !(pcp->prc_flags & PRC_LWP)))) {
		thread_unlock(t);
		return (EBUSY);
	}
	thread_unlock(t);
	if (flags & ~(PRCSIG|PRCFAULT|PRSTEP|PRSTOP|PRSABORT))
		return (EINVAL);
	lwp = ttolwp(t);
	if ((flags & PRCSIG) && lwp->lwp_cursig != SIGKILL) {
		/*
		 * Discard current siginfo_t, if any.
		 */
		lwp->lwp_cursig = 0;
		lwp->lwp_extsig = 0;
		if (lwp->lwp_curinfo) {
			siginfofree(lwp->lwp_curinfo);
			lwp->lwp_curinfo = NULL;
		}
	}
	if (flags & PRCFAULT)
		lwp->lwp_curflt = 0;
	/*
	 * We can't hold p->p_lock when we touch the lwp's registers.
	 * It may be swapped out and we will get a page fault.
	 */
	if (flags & PRSTEP) {
		mutex_exit(&p->p_lock);
		prstep(lwp, 0);
		mutex_enter(&p->p_lock);
	}
	if (flags & PRSTOP) {
		t->t_proc_flag |= TP_PRSTOP;
		t->t_sig_check = 1;	/* do ISSIG */
	}
	if (flags & PRSABORT)
		lwp->lwp_sysabort = 1;
	thread_lock(t);
	if ((pcp->prc_flags & PRC_LWP) || (flags & (PRSTEP|PRSTOP))) {
		/*
		 * Here, we are dealing with a single lwp.
		 */
		if (ISTOPPED(t)) {
			t->t_schedflag |= TS_PSTART;
			t->t_dtrace_stop = 0;
			setrun_locked(t);
		} else if (flags & PRSABORT) {
			t->t_proc_flag &=
			    ~(TP_PRSTOP|TP_PRVSTOP|TP_STOPPING);
			setrun_locked(t);
		} else if (!(flags & PRSTOP)) {
			t->t_proc_flag &=
			    ~(TP_PRSTOP|TP_PRVSTOP|TP_STOPPING);
		}
		thread_unlock(t);
	} else {
		/*
		 * Here, we are dealing with the whole process.
		 */
		if (ISTOPPED(t)) {
			/*
			 * The representative lwp is stopped on an event
			 * of interest.  We demote it to PR_REQUESTED and
			 * choose another representative lwp.  If the new
			 * representative lwp is not stopped on an event of
			 * interest (other than PR_REQUESTED), we set the
			 * whole process running, else we leave the process
			 * stopped showing the next event of interest.
			 */
			kthread_t *tx = NULL;

			if (!(flags & PRSABORT) &&
			    t->t_whystop == PR_SYSENTRY &&
			    t->t_whatstop == SYS_lwp_exit)
				tx = t;		/* remember the exiting lwp */
			t->t_whystop = PR_REQUESTED;
			t->t_whatstop = 0;
			thread_unlock(t);
			t = prchoose(p);	/* returns locked t */
			ASSERT(ISTOPPED(t) || VSTOPPED(t));
			if (VSTOPPED(t) ||
			    t->t_whystop == PR_REQUESTED) {
				thread_unlock(t);
				allsetrun(p);
			} else {
				thread_unlock(t);
				/*
				 * As a special case, if the old representative
				 * lwp was stopped on entry to _lwp_exit()
				 * (and we are not aborting the system call),
				 * we set the old representative lwp running.
				 * We do this so that the next process stop
				 * will find the exiting lwp gone.
				 */
				if (tx != NULL) {
					thread_lock(tx);
					tx->t_schedflag |= TS_PSTART;
					t->t_dtrace_stop = 0;
					setrun_locked(tx);
					thread_unlock(tx);
				}
			}
		} else {
			/*
			 * No event of interest; set all of the lwps running.
			 */
			if (flags & PRSABORT) {
				t->t_proc_flag &=
				    ~(TP_PRSTOP|TP_PRVSTOP|TP_STOPPING);
				setrun_locked(t);
			}
			thread_unlock(t);
			allsetrun(p);
		}
	}
	return (0);
}

/*
 * Wait until process/lwp stops or until timer expires.
 * Return EINTR for an interruption, -1 for timeout, else 0.
 */
int
pr_wait(prcommon_t *pcp,	/* prcommon referring to process/lwp */
    timestruc_t *ts,		/* absolute time of timeout, if any */
    int timecheck)
{
	int rval;

	ASSERT(MUTEX_HELD(&pcp->prc_mutex));
	rval = cv_waituntil_sig(&pcp->prc_wait, &pcp->prc_mutex, ts, timecheck);
	mutex_exit(&pcp->prc_mutex);
	switch (rval) {
	case 0:
		return (EINTR);
	case -1:
		return (-1);
	default:
		return (0);
	}
}

/*
 * Make all threads in the process runnable.
 */
void
allsetrun(proc_t *p)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((t = p->p_tlist) != NULL) {
		do {
			thread_lock(t);
			ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
			t->t_proc_flag &= ~(TP_PRSTOP|TP_PRVSTOP|TP_STOPPING);
			if (ISTOPPED(t)) {
				t->t_schedflag |= TS_PSTART;
				t->t_dtrace_stop = 0;
				setrun_locked(t);
			}
			thread_unlock(t);
		} while ((t = t->t_forw) != p->p_tlist);
	}
}

/*
 * Wait for the process to die.
 * We do this after sending SIGKILL because we know it will
 * die soon and we want subsequent operations to return ENOENT.
 */
void
pr_wait_die(prnode_t *pnp)
{
	proc_t *p;

	mutex_enter(&pidlock);
	while ((p = pnp->pr_common->prc_proc) != NULL && p->p_stat != SZOMB) {
		if (!cv_wait_sig(&p->p_srwchan_cv, &pidlock))
			break;
	}
	mutex_exit(&pidlock);
}

static void
pr_settrace(proc_t *p, sigset_t *sp)
{
	prdelset(sp, SIGKILL);
	prassignset(&p->p_sigmask, sp);
	if (!sigisempty(&p->p_sigmask))
		p->p_proc_flag |= P_PR_TRACE;
	else if (prisempty(&p->p_fltmask)) {
		user_t *up = PTOU(p);
		if (up->u_systrap == 0)
			p->p_proc_flag &= ~P_PR_TRACE;
	}
}

int
pr_setsig(prnode_t *pnp, siginfo_t *sip)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
	int sig = sip->si_signo;
	prcommon_t *pcp = pnp->pr_common;
	proc_t *p = pcp->prc_proc;
	kthread_t *t;
	klwp_t *lwp;
	int error = 0;

	t = pr_thread(pnp);	/* returns locked thread */
	thread_unlock(t);
	lwp = ttolwp(t);
	if (sig < 0 || sig >= nsig)
		/* Zero allowed here */
		error = EINVAL;
	else if (lwp->lwp_cursig == SIGKILL)
		/* "can't happen", but just in case */
		error = EBUSY;
	else if ((lwp->lwp_cursig = (uchar_t)sig) == 0) {
		lwp->lwp_extsig = 0;
		/*
		 * Discard current siginfo_t, if any.
		 */
		if (lwp->lwp_curinfo) {
			siginfofree(lwp->lwp_curinfo);
			lwp->lwp_curinfo = NULL;
		}
	} else {
		kthread_t *tx;
		sigqueue_t *sqp;

		/* drop p_lock to do kmem_alloc(KM_SLEEP) */
		mutex_exit(&p->p_lock);
		sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
		mutex_enter(&p->p_lock);

		if (lwp->lwp_curinfo == NULL)
			lwp->lwp_curinfo = sqp;
		else
			kmem_free(sqp, sizeof (sigqueue_t));
		/*
		 * Copy contents of info to current siginfo_t.
		 */
		bcopy(sip, &lwp->lwp_curinfo->sq_info,
		    sizeof (lwp->lwp_curinfo->sq_info));
		/*
		 * Prevent contents published by si_zoneid-unaware /proc
		 * consumers from being incorrectly filtered.  Because
		 * an uninitialized si_zoneid is the same as
		 * GLOBAL_ZONEID, this means that you can't pr_setsig a
		 * process in a non-global zone with a siginfo which
		 * appears to come from the global zone.
		 */
		if (SI_FROMUSER(sip) && sip->si_zoneid == 0)
			lwp->lwp_curinfo->sq_info.si_zoneid =
			    p->p_zone->zone_id;
		/*
		 * Side-effects for SIGKILL and jobcontrol signals.
		 */
		if (sig == SIGKILL) {
			p->p_flag |= SKILLED;
			p->p_flag &= ~SEXTKILLED;
		} else if (sig == SIGCONT) {
			p->p_flag |= SSCONT;
			sigdelq(p, NULL, SIGSTOP);
			sigdelq(p, NULL, SIGTSTP);
			sigdelq(p, NULL, SIGTTOU);
			sigdelq(p, NULL, SIGTTIN);
			sigdiffset(&p->p_sig, &stopdefault);
			sigdiffset(&p->p_extsig, &stopdefault);
			if ((tx = p->p_tlist) != NULL) {
				do {
					sigdelq(p, tx, SIGSTOP);
					sigdelq(p, tx, SIGTSTP);
					sigdelq(p, tx, SIGTTOU);
					sigdelq(p, tx, SIGTTIN);
					sigdiffset(&tx->t_sig, &stopdefault);
					sigdiffset(&tx->t_extsig, &stopdefault);
				} while ((tx = tx->t_forw) != p->p_tlist);
			}
		} else if (sigismember(&stopdefault, sig)) {
			if (PTOU(p)->u_signal[sig-1] == SIG_DFL &&
			    (sig == SIGSTOP || !p->p_pgidp->pid_pgorphaned))
				p->p_flag &= ~SSCONT;
			sigdelq(p, NULL, SIGCONT);
			sigdelset(&p->p_sig, SIGCONT);
			sigdelset(&p->p_extsig, SIGCONT);
			if ((tx = p->p_tlist) != NULL) {
				do {
					sigdelq(p, tx, SIGCONT);
					sigdelset(&tx->t_sig, SIGCONT);
					sigdelset(&tx->t_extsig, SIGCONT);
				} while ((tx = tx->t_forw) != p->p_tlist);
			}
		}
		thread_lock(t);
		if (ISWAKEABLE(t) || ISWAITING(t)) {
			/* Set signaled sleeping/waiting lwp running */
			setrun_locked(t);
		} else if (t->t_state == TS_STOPPED && sig == SIGKILL) {
			/* If SIGKILL, set stopped lwp running */
			p->p_stopsig = 0;
			t->t_schedflag |= TS_XSTART | TS_PSTART | TS_BSTART;
			t->t_dtrace_stop = 0;
			setrun_locked(t);
		}
		t->t_sig_check = 1;	/* so ISSIG will be done */
		thread_unlock(t);
		/*
		 * More jobcontrol side-effects.
		 */
		if (sig == SIGCONT && (tx = p->p_tlist) != NULL) {
			p->p_stopsig = 0;
			do {
				thread_lock(tx);
				if (tx->t_state == TS_STOPPED &&
				    tx->t_whystop == PR_JOBCONTROL) {
					tx->t_schedflag |= TS_XSTART;
					setrun_locked(tx);
				}
				thread_unlock(tx);
			} while ((tx = tx->t_forw) != p->p_tlist);
		}
	}
	return (error);
}

int
pr_kill(prnode_t *pnp, int sig, cred_t *cr)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
	prcommon_t *pcp = pnp->pr_common;
	proc_t *p = pcp->prc_proc;
	k_siginfo_t info;

	if (sig <= 0 || sig >= nsig)
		return (EINVAL);

	bzero(&info, sizeof (info));
	info.si_signo = sig;
	info.si_code = SI_USER;
	info.si_pid = curproc->p_pid;
	info.si_ctid = PRCTID(curproc);
	info.si_zoneid = getzoneid();
	info.si_uid = crgetruid(cr);
	sigaddq(p, (pcp->prc_flags & PRC_LWP)?
	    pcp->prc_thread : NULL, &info, KM_NOSLEEP);

	return (0);
}

int
pr_unkill(prnode_t *pnp, int sig)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
	prcommon_t *pcp = pnp->pr_common;
	proc_t *p = pcp->prc_proc;
	sigqueue_t *infop = NULL;

	if (sig <= 0 || sig >= nsig || sig == SIGKILL)
		return (EINVAL);

	if (pcp->prc_flags & PRC_LWP)
		sigdeq(p, pcp->prc_thread, sig, &infop);
	else
		sigdeq(p, NULL, sig, &infop);

	if (infop)
		siginfofree(infop);

	return (0);
}

int
pr_nice(proc_t *p, int nice, cred_t *cr)
{
	kthread_t *t;
	int err;
	int error = 0;

	t = p->p_tlist;
	do {
		ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
		err = CL_DONICE(t, cr, nice, (int *)NULL);
		schedctl_set_cidpri(t);
		if (error == 0)
			error = err;
	} while ((t = t->t_forw) != p->p_tlist);

	return (error);
}

void
pr_setentryexit(proc_t *p, sysset_t *sysset, int entry)
{
	user_t *up = PTOU(p);

	if (entry) {
		prassignset(&up->u_entrymask, sysset);
	} else {
		prassignset(&up->u_exitmask, sysset);
	}
	if (!prisempty(&up->u_entrymask) ||
	    !prisempty(&up->u_exitmask)) {
		up->u_systrap = 1;
		p->p_proc_flag |= P_PR_TRACE;
		set_proc_sys(p);	/* set pre and post-sys flags */
	} else {
		up->u_systrap = 0;
		if (sigisempty(&p->p_sigmask) &&
		    prisempty(&p->p_fltmask))
			p->p_proc_flag &= ~P_PR_TRACE;
	}
}

#define	ALLFLAGS	\
	(PR_FORK|PR_RLC|PR_KLC|PR_ASYNC|PR_BPTADJ|PR_MSACCT|PR_MSFORK|PR_PTRACE)

int
pr_set(proc_t *p, long flags)
{
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		return (EBUSY);

	if (flags & ~ALLFLAGS)
		return (EINVAL);

	if (flags & PR_FORK)
		p->p_proc_flag |= P_PR_FORK;
	if (flags & PR_RLC)
		p->p_proc_flag |= P_PR_RUNLCL;
	if (flags & PR_KLC)
		p->p_proc_flag |= P_PR_KILLCL;
	if (flags & PR_ASYNC)
		p->p_proc_flag |= P_PR_ASYNC;
	if (flags & PR_BPTADJ)
		p->p_proc_flag |= P_PR_BPTADJ;
	if (flags & PR_MSACCT)
		if ((p->p_flag & SMSACCT) == 0)
			estimate_msacct(p->p_tlist, gethrtime());
	if (flags & PR_MSFORK)
		p->p_flag |= SMSFORK;
	if (flags & PR_PTRACE) {
		p->p_proc_flag |= P_PR_PTRACE;
		/* ptraced process must die if parent dead */
		if (p->p_ppid == 1)
			sigtoproc(p, NULL, SIGKILL);
	}

	return (0);
}

int
pr_unset(proc_t *p, long flags)
{
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		return (EBUSY);

	if (flags & ~ALLFLAGS)
		return (EINVAL);

	if (flags & PR_FORK)
		p->p_proc_flag &= ~P_PR_FORK;
	if (flags & PR_RLC)
		p->p_proc_flag &= ~P_PR_RUNLCL;
	if (flags & PR_KLC)
		p->p_proc_flag &= ~P_PR_KILLCL;
	if (flags & PR_ASYNC)
		p->p_proc_flag &= ~P_PR_ASYNC;
	if (flags & PR_BPTADJ)
		p->p_proc_flag &= ~P_PR_BPTADJ;
	if (flags & PR_MSACCT)
		disable_msacct(p);
	if (flags & PR_MSFORK)
		p->p_flag &= ~SMSFORK;
	if (flags & PR_PTRACE)
		p->p_proc_flag &= ~P_PR_PTRACE;

	return (0);
}

static int
pr_setfpregs(prnode_t *pnp, prfpregset_t *prfpregset)
{
	proc_t *p = pnp->pr_common->prc_proc;
	kthread_t *t = pr_thread(pnp);	/* returns locked thread */

	if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t)) {
		thread_unlock(t);
		return (EBUSY);
	}
	if (!prhasfp()) {
		thread_unlock(t);
		return (EINVAL);	/* No FP support */
	}

	/* drop p_lock while touching the lwp's stack */
	thread_unlock(t);
	mutex_exit(&p->p_lock);
	prsetprfpregs(ttolwp(t), prfpregset);
	mutex_enter(&p->p_lock);

	return (0);
}

#ifdef	_SYSCALL32_IMPL
static int
pr_setfpregs32(prnode_t *pnp, prfpregset32_t *prfpregset)
{
	proc_t *p = pnp->pr_common->prc_proc;
	kthread_t *t = pr_thread(pnp);	/* returns locked thread */

	if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t)) {
		thread_unlock(t);
		return (EBUSY);
	}
	if (!prhasfp()) {
		thread_unlock(t);
		return (EINVAL);	/* No FP support */
	}

	/* drop p_lock while touching the lwp's stack */
	thread_unlock(t);
	mutex_exit(&p->p_lock);
	prsetprfpregs32(ttolwp(t), prfpregset);
	mutex_enter(&p->p_lock);

	return (0);
}
#endif	/* _SYSCALL32_IMPL */

/* ARGSUSED */
static int
pr_setxregs(prnode_t *pnp, prxregset_t *prxregset)
{
	int error;
	proc_t *p = pnp->pr_common->prc_proc;
	kthread_t *t = pr_thread(pnp);	/* returns locked thread */

	if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t)) {
		thread_unlock(t);
		return (EBUSY);
	}
	thread_unlock(t);

	if (!prhasx(p))
		return (EINVAL);	/* No extra register support */

	/* drop p_lock while touching the lwp's stack */
	mutex_exit(&p->p_lock);
	error = prsetprxregs(ttolwp(t), prxregset);
	mutex_enter(&p->p_lock);

	return (error);
}

static int
pr_setvaddr(prnode_t *pnp, caddr_t vaddr)
{
	proc_t *p = pnp->pr_common->prc_proc;
	kthread_t *t = pr_thread(pnp);	/* returns locked thread */

	if (!ISTOPPED(t) && !VSTOPPED(t) && !DSTOPPED(t)) {
		thread_unlock(t);
		return (EBUSY);
	}

	/* drop p_lock while touching the lwp's stack */
	thread_unlock(t);
	mutex_exit(&p->p_lock);
	prsvaddr(ttolwp(t), vaddr);
	mutex_enter(&p->p_lock);

	return (0);
}

void
pr_sethold(prnode_t *pnp, sigset_t *sp)
{
	proc_t *p = pnp->pr_common->prc_proc;
	kthread_t *t = pr_thread(pnp);	/* returns locked thread */

	schedctl_finish_sigblock(t);
	sigutok(sp, &t->t_hold);
	if (ISWAKEABLE(t) &&
	    (fsig(&p->p_sig, t) || fsig(&t->t_sig, t)))
		setrun_locked(t);
	t->t_sig_check = 1;	/* so thread will see new holdmask */
	thread_unlock(t);
}

void
pr_setfault(proc_t *p, fltset_t *fltp)
{
	prassignset(&p->p_fltmask, fltp);
	if (!prisempty(&p->p_fltmask))
		p->p_proc_flag |= P_PR_TRACE;
	else if (sigisempty(&p->p_sigmask)) {
		user_t *up = PTOU(p);
		if (up->u_systrap == 0)
			p->p_proc_flag &= ~P_PR_TRACE;
	}
}

static int
pr_clearsig(prnode_t *pnp)
{
	kthread_t *t = pr_thread(pnp);	/* returns locked thread */
	klwp_t *lwp = ttolwp(t);

	thread_unlock(t);
	if (lwp->lwp_cursig == SIGKILL)
		return (EBUSY);

	/*
	 * Discard current siginfo_t, if any.
	 */
	lwp->lwp_cursig = 0;
	lwp->lwp_extsig = 0;
	if (lwp->lwp_curinfo) {
		siginfofree(lwp->lwp_curinfo);
		lwp->lwp_curinfo = NULL;
	}

	return (0);
}

static int
pr_clearflt(prnode_t *pnp)
{
	kthread_t *t = pr_thread(pnp);	/* returns locked thread */

	thread_unlock(t);
	ttolwp(t)->lwp_curflt = 0;

	return (0);
}

static int
pr_watch(prnode_t *pnp, prwatch_t *pwp, int *unlocked)
{
	proc_t *p = pnp->pr_common->prc_proc;
	struct as *as = p->p_as;
	uintptr_t vaddr = pwp->pr_vaddr;
	size_t size = pwp->pr_size;
	int wflags = pwp->pr_wflags;
	ulong_t newpage = 0;
	struct watched_area *pwa;
	int error;

	*unlocked = 0;

	/*
	 * Can't apply to a system process.
	 */
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		return (EBUSY);

	/*
	 * Verify that the address range does not wrap
	 * and that only the proper flags were specified.
	 */
	if ((wflags & ~WA_TRAPAFTER) == 0)
		size = 0;
	if (vaddr + size < vaddr ||
	    (wflags & ~(WA_READ|WA_WRITE|WA_EXEC|WA_TRAPAFTER)) != 0 ||
	    ((wflags & ~WA_TRAPAFTER) != 0 && size == 0))
		return (EINVAL);

	/*
	 * Don't let the address range go above as->a_userlimit.
	 * There is no error here, just a limitation.
	 */
	if (vaddr >= (uintptr_t)as->a_userlimit)
		return (0);
	if (vaddr + size > (uintptr_t)as->a_userlimit)
		size = (uintptr_t)as->a_userlimit - vaddr;

	/*
	 * Compute maximum number of pages this will add.
	 */
	if ((wflags & ~WA_TRAPAFTER) != 0) {
		ulong_t pagespan = (vaddr + size) - (vaddr & PAGEMASK);
		newpage = btopr(pagespan);
		if (newpage > 2 * prnwatch)
			return (E2BIG);
	}

	/*
	 * Force the process to be fully stopped.
	 */
	if (p == curproc) {
		prunlock(pnp);
		while (holdwatch() != 0)
			continue;
		if ((error = prlock(pnp, ZNO)) != 0) {
			continuelwps(p);
			*unlocked = 1;
			return (error);
		}
	} else {
		pauselwps(p);
		while (pr_allstopped(p, 0) > 0) {
			/*
			 * This cv/mutex pair is persistent even
			 * if the process disappears after we
			 * unmark it and drop p->p_lock.
			 */
			kcondvar_t *cv = &pr_pid_cv[p->p_slot];
			kmutex_t *mp = &p->p_lock;

			prunmark(p);
			(void) cv_wait(cv, mp);
			mutex_exit(mp);
			if ((error = prlock(pnp, ZNO)) != 0) {
				/*
				 * Unpause the process if it exists.
				 */
				p = pr_p_lock(pnp);
				mutex_exit(&pr_pidlock);
				if (p != NULL) {
					unpauselwps(p);
					prunlock(pnp);
				}
				*unlocked = 1;
				return (error);
			}
		}
	}

	/*
	 * Drop p->p_lock in order to perform the rest of this.
	 * The process is still locked with the P_PR_LOCK flag.
	 */
	mutex_exit(&p->p_lock);

	pwa = kmem_alloc(sizeof (struct watched_area), KM_SLEEP);
	pwa->wa_vaddr = (caddr_t)vaddr;
	pwa->wa_eaddr = (caddr_t)vaddr + size;
	pwa->wa_flags = (ulong_t)wflags;

	error = ((pwa->wa_flags & ~WA_TRAPAFTER) == 0)?
	    clear_watched_area(p, pwa) : set_watched_area(p, pwa);

	if (p == curproc) {
		setallwatch();
		mutex_enter(&p->p_lock);
		continuelwps(p);
	} else {
		mutex_enter(&p->p_lock);
		unpauselwps(p);
	}

	return (error);
}

/* jobcontrol stopped, but with a /proc directed stop in effect */
#define	JDSTOPPED(t)	\
	((t)->t_state == TS_STOPPED && \
	(t)->t_whystop == PR_JOBCONTROL && \
	((t)->t_proc_flag & TP_PRSTOP))

/*
 * pr_agent() creates the agent lwp. If the process is exiting while
 * we are creating an agent lwp, then exitlwps() waits until the
 * agent has been created using prbarrier().
 */
static int
pr_agent(prnode_t *pnp, prgregset_t prgregset, int *unlocked)
{
	proc_t *p = pnp->pr_common->prc_proc;
	prcommon_t *pcp;
	kthread_t *t;
	kthread_t *ct;
	klwp_t *clwp;
	k_sigset_t smask;
	int cid;
	void *bufp = NULL;
	int error;

	*unlocked = 0;

	/*
	 * Cannot create the /proc agent lwp if :-
	 * - the process is not fully stopped or directed to stop.
	 * - there is an agent lwp already.
	 * - the process has been killed.
	 * - the process is exiting.
	 * - it's a vfork(2) parent.
	 */
	t = prchoose(p);	/* returns locked thread */
	ASSERT(t != NULL);

	if ((!ISTOPPED(t) && !VSTOPPED(t) && !SUSPENDED(t) && !JDSTOPPED(t)) ||
	    p->p_agenttp != NULL ||
	    (p->p_flag & (SKILLED | SEXITING | SVFWAIT))) {
		thread_unlock(t);
		return (EBUSY);
	}

	thread_unlock(t);
	mutex_exit(&p->p_lock);

	sigfillset(&smask);
	sigdiffset(&smask, &cantmask);
	clwp = lwp_create(lwp_rtt, NULL, 0, p, TS_STOPPED,
	    t->t_pri, &smask, NOCLASS, 0);
	if (clwp == NULL) {
		mutex_enter(&p->p_lock);
		return (ENOMEM);
	}
	prsetprregs(clwp, prgregset, 1);

	/*
	 * Because abandoning the agent inside the target process leads to
	 * a state that is essentially undebuggable, we record the psinfo of
	 * the process creating the agent and hang that off of the lwp.
	 */
	clwp->lwp_spymaster = kmem_zalloc(sizeof (psinfo_t), KM_SLEEP);
	mutex_enter(&curproc->p_lock);
	prgetpsinfo(curproc, clwp->lwp_spymaster);
	mutex_exit(&curproc->p_lock);

	/*
	 * We overload pr_time in the spymaster to denote the time at which the
	 * agent was created.
	 */
	gethrestime(&clwp->lwp_spymaster->pr_time);

retry:
	cid = t->t_cid;
	(void) CL_ALLOC(&bufp, cid, KM_SLEEP);
	mutex_enter(&p->p_lock);
	if (cid != t->t_cid) {
		/*
		 * Someone just changed this thread's scheduling class,
		 * so try pre-allocating the buffer again.  Hopefully we
		 * don't hit this often.
		 */
		mutex_exit(&p->p_lock);
		CL_FREE(cid, bufp);
		goto retry;
	}

	clwp->lwp_ap = clwp->lwp_arg;
	clwp->lwp_eosys = NORMALRETURN;
	ct = lwptot(clwp);
	ct->t_clfuncs = t->t_clfuncs;
	CL_FORK(t, ct, bufp);
	ct->t_cid = t->t_cid;
	ct->t_proc_flag |= TP_PRSTOP;
	/*
	 * Setting t_sysnum to zero causes post_syscall()
	 * to bypass all syscall checks and go directly to
	 *	if (issig()) psig();
	 * so that the agent lwp will stop in issig_forreal()
	 * showing PR_REQUESTED.
	 */
	ct->t_sysnum = 0;
	ct->t_post_sys = 1;
	ct->t_sig_check = 1;
	p->p_agenttp = ct;
	ct->t_proc_flag &= ~TP_HOLDLWP;

	pcp = pnp->pr_pcommon;
	mutex_enter(&pcp->prc_mutex);

	lwp_create_done(ct);

	/*
	 * Don't return until the agent is stopped on PR_REQUESTED.
	 */

	for (;;) {
		prunlock(pnp);
		*unlocked = 1;

		/*
		 * Wait for the agent to stop and notify us.
		 * If we've been interrupted, return that information.
		 */
		error = pr_wait(pcp, NULL, 0);
		if (error == EINTR) {
			error = 0;
			break;
		}

		/*
		 * Confirm that the agent LWP has stopped.
		 */

		if ((error = prlock(pnp, ZNO)) != 0)
			break;
		*unlocked = 0;

		/*
		 * Since we dropped the lock on the process, the agent
		 * may have disappeared or changed. Grab the current
		 * agent and check fail if it has disappeared.
		 */
		if ((ct = p->p_agenttp) == NULL) {
			error = ENOENT;
			break;
		}

		mutex_enter(&pcp->prc_mutex);
		thread_lock(ct);

		if (ISTOPPED(ct)) {
			thread_unlock(ct);
			mutex_exit(&pcp->prc_mutex);
			break;
		}

		thread_unlock(ct);
	}

	return (error ? error : -1);
}

static int
pr_rdwr(proc_t *p, enum uio_rw rw, priovec_t *pio)
{
	caddr_t base = (caddr_t)pio->pio_base;
	size_t cnt = pio->pio_len;
	uintptr_t offset = (uintptr_t)pio->pio_offset;
	struct uio auio;
	struct iovec aiov;
	int error = 0;

	if ((p->p_flag & SSYS) || p->p_as == &kas)
		error = EIO;
	else if ((base + cnt) < base || (offset + cnt) < offset)
		error = EINVAL;
	else if (cnt != 0) {
		aiov.iov_base = base;
		aiov.iov_len = cnt;

		auio.uio_loffset = offset;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_resid = cnt;
		auio.uio_segflg = UIO_USERSPACE;
		auio.uio_llimit = (longlong_t)MAXOFFSET_T;
		auio.uio_fmode = FREAD|FWRITE;
		auio.uio_extflg = UIO_COPY_DEFAULT;

		mutex_exit(&p->p_lock);
		error = prusrio(p, rw, &auio, 0);
		mutex_enter(&p->p_lock);

		/*
		 * We have no way to return the i/o count,
		 * like read() or write() would do, so we
		 * return an error if the i/o was truncated.
		 */
		if (auio.uio_resid != 0 && error == 0)
			error = EIO;
	}

	return (error);
}

static int
pr_scred(proc_t *p, prcred_t *prcred, cred_t *cr, boolean_t dogrps)
{
	kthread_t *t;
	cred_t *oldcred;
	cred_t *newcred;
	uid_t oldruid;
	int error;
	zone_t *zone = crgetzone(cr);

	if (!VALID_UID(prcred->pr_euid, zone) ||
	    !VALID_UID(prcred->pr_ruid, zone) ||
	    !VALID_UID(prcred->pr_suid, zone) ||
	    !VALID_GID(prcred->pr_egid, zone) ||
	    !VALID_GID(prcred->pr_rgid, zone) ||
	    !VALID_GID(prcred->pr_sgid, zone))
		return (EINVAL);

	if (dogrps) {
		int ngrp = prcred->pr_ngroups;
		int i;

		if (ngrp < 0 || ngrp > ngroups_max)
			return (EINVAL);

		for (i = 0; i < ngrp; i++) {
			if (!VALID_GID(prcred->pr_groups[i], zone))
				return (EINVAL);
		}
	}

	error = secpolicy_allow_setid(cr, prcred->pr_euid, B_FALSE);

	if (error == 0 && prcred->pr_ruid != prcred->pr_euid)
		error = secpolicy_allow_setid(cr, prcred->pr_ruid, B_FALSE);

	if (error == 0 && prcred->pr_suid != prcred->pr_euid &&
	    prcred->pr_suid != prcred->pr_ruid)
		error = secpolicy_allow_setid(cr, prcred->pr_suid, B_FALSE);

	if (error)
		return (error);

	mutex_exit(&p->p_lock);

	/* hold old cred so it doesn't disappear while we dup it */
	mutex_enter(&p->p_crlock);
	crhold(oldcred = p->p_cred);
	mutex_exit(&p->p_crlock);
	newcred = crdup(oldcred);
	oldruid = crgetruid(oldcred);
	crfree(oldcred);

	/* Error checking done above */
	(void) crsetresuid(newcred, prcred->pr_ruid, prcred->pr_euid,
	    prcred->pr_suid);
	(void) crsetresgid(newcred, prcred->pr_rgid, prcred->pr_egid,
	    prcred->pr_sgid);

	if (dogrps) {
		(void) crsetgroups(newcred, prcred->pr_ngroups,
		    prcred->pr_groups);

	}

	mutex_enter(&p->p_crlock);
	oldcred = p->p_cred;
	p->p_cred = newcred;
	mutex_exit(&p->p_crlock);
	crfree(oldcred);

	/*
	 * Keep count of processes per uid consistent.
	 */
	if (oldruid != prcred->pr_ruid) {
		zoneid_t zoneid = crgetzoneid(newcred);

		mutex_enter(&pidlock);
		upcount_dec(oldruid, zoneid);
		upcount_inc(prcred->pr_ruid, zoneid);
		mutex_exit(&pidlock);
	}

	/*
	 * Broadcast the cred change to the threads.
	 */
	mutex_enter(&p->p_lock);
	t = p->p_tlist;
	do {
		t->t_pre_sys = 1; /* so syscall will get new cred */
	} while ((t = t->t_forw) != p->p_tlist);

	return (0);
}

/*
 * Change process credentials to specified zone.  Used to temporarily
 * set a process to run in the global zone; only transitions between
 * the process's actual zone and the global zone are allowed.
 */
static int
pr_szoneid(proc_t *p, zoneid_t zoneid, cred_t *cr)
{
	kthread_t *t;
	cred_t *oldcred;
	cred_t *newcred;
	zone_t *zptr;
	zoneid_t oldzoneid;

	if (secpolicy_zone_config(cr) != 0)
		return (EPERM);
	if (zoneid != GLOBAL_ZONEID && zoneid != p->p_zone->zone_id)
		return (EINVAL);
	/*
	 * We cannot hold p_lock when we call zone_find_by_id since that can
	 * lead to a deadlock. zone_find_by_id() takes zonehash_lock.
	 * zone_enter() can hold the zonehash_lock and needs p_lock when it
	 * calls task_join.
	 */
	mutex_exit(&p->p_lock);
	if ((zptr = zone_find_by_id(zoneid)) == NULL) {
		mutex_enter(&p->p_lock);
		return (EINVAL);
	}
	mutex_enter(&p->p_crlock);
	oldcred = p->p_cred;
	crhold(oldcred);
	mutex_exit(&p->p_crlock);
	newcred = crdup(oldcred);
	oldzoneid = crgetzoneid(oldcred);
	crfree(oldcred);

	crsetzone(newcred, zptr);
	zone_rele(zptr);

	mutex_enter(&p->p_crlock);
	oldcred = p->p_cred;
	p->p_cred = newcred;
	mutex_exit(&p->p_crlock);
	crfree(oldcred);

	/*
	 * The target process is changing zones (according to its cred), so
	 * update the per-zone upcounts, which are based on process creds.
	 */
	if (oldzoneid != zoneid) {
		uid_t ruid = crgetruid(newcred);

		mutex_enter(&pidlock);
		upcount_dec(ruid, oldzoneid);
		upcount_inc(ruid, zoneid);
		mutex_exit(&pidlock);
	}
	/*
	 * Broadcast the cred change to the threads.
	 */
	mutex_enter(&p->p_lock);
	t = p->p_tlist;
	do {
		t->t_pre_sys = 1;	/* so syscall will get new cred */
	} while ((t = t->t_forw) != p->p_tlist);

	return (0);
}

static int
pr_spriv(proc_t *p, prpriv_t *prpriv, cred_t *cr)
{
	kthread_t *t;
	int err;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((err = priv_pr_spriv(p, prpriv, cr)) == 0) {
		/*
		 * Broadcast the cred change to the threads.
		 */
		t = p->p_tlist;
		do {
			t->t_pre_sys = 1; /* so syscall will get new cred */
		} while ((t = t->t_forw) != p->p_tlist);
	}

	return (err);
}

/*
 * Return -1 if the process is the parent of a vfork(1) whose child has yet to
 * terminate or perform an exec(2).
 *
 * Returns 0 if the process is fully stopped except for the current thread (if
 * we are operating on our own process), 1 otherwise.
 *
 * If the watchstop flag is set, then we ignore threads with TP_WATCHSTOP set.
 * See holdwatch() for details.
 */
int
pr_allstopped(proc_t *p, int watchstop)
{
	kthread_t *t;
	int rv = 0;

	ASSERT(MUTEX_HELD(&p->p_lock));

	if (p->p_flag & SVFWAIT)	/* waiting for vfork'd child to exec */
		return (-1);

	if ((t = p->p_tlist) != NULL) {
		do {
			if (t == curthread || VSTOPPED(t) ||
			    (watchstop && (t->t_proc_flag & TP_WATCHSTOP)))
				continue;
			thread_lock(t);
			switch (t->t_state) {
			case TS_ZOMB:
			case TS_STOPPED:
				break;
			case TS_SLEEP:
				if (!(t->t_flag & T_WAKEABLE) ||
				    t->t_wchan0 == NULL)
					rv = 1;
				break;
			default:
				rv = 1;
				break;
			}
			thread_unlock(t);
		} while (rv == 0 && (t = t->t_forw) != p->p_tlist);
	}

	return (rv);
}

/*
 * Cause all lwps in the process to pause (for watchpoint operations).
 */
static void
pauselwps(proc_t *p)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(p != curproc);

	if ((t = p->p_tlist) != NULL) {
		do {
			thread_lock(t);
			t->t_proc_flag |= TP_PAUSE;
			aston(t);
			if ((ISWAKEABLE(t) && (t->t_wchan0 == NULL)) ||
			    ISWAITING(t)) {
				setrun_locked(t);
			}
			prpokethread(t);
			thread_unlock(t);
		} while ((t = t->t_forw) != p->p_tlist);
	}
}

/*
 * undo the effects of pauselwps()
 */
static void
unpauselwps(proc_t *p)
{
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(p != curproc);

	if ((t = p->p_tlist) != NULL) {
		do {
			thread_lock(t);
			t->t_proc_flag &= ~TP_PAUSE;
			if (t->t_state == TS_STOPPED) {
				t->t_schedflag |= TS_UNPAUSE;
				t->t_dtrace_stop = 0;
				setrun_locked(t);
			}
			thread_unlock(t);
		} while ((t = t->t_forw) != p->p_tlist);
	}
}

/*
 * Cancel all watched areas.  Called from prclose().
 */
proc_t *
pr_cancel_watch(prnode_t *pnp)
{
	proc_t *p = pnp->pr_pcommon->prc_proc;
	struct as *as;
	kthread_t *t;

	ASSERT(MUTEX_HELD(&p->p_lock) && (p->p_proc_flag & P_PR_LOCK));

	if (!pr_watch_active(p))
		return (p);

	/*
	 * Pause the process before dealing with the watchpoints.
	 */
	if (p == curproc) {
		prunlock(pnp);
		while (holdwatch() != 0)
			continue;
		p = pr_p_lock(pnp);
		mutex_exit(&pr_pidlock);
		ASSERT(p == curproc);
	} else {
		pauselwps(p);
		while (p != NULL && pr_allstopped(p, 0) > 0) {
			/*
			 * This cv/mutex pair is persistent even
			 * if the process disappears after we
			 * unmark it and drop p->p_lock.
			 */
			kcondvar_t *cv = &pr_pid_cv[p->p_slot];
			kmutex_t *mp = &p->p_lock;

			prunmark(p);
			(void) cv_wait(cv, mp);
			mutex_exit(mp);
			p = pr_p_lock(pnp);  /* NULL if process disappeared */
			mutex_exit(&pr_pidlock);
		}
	}

	if (p == NULL)		/* the process disappeared */
		return (NULL);

	ASSERT(p == pnp->pr_pcommon->prc_proc);
	ASSERT(MUTEX_HELD(&p->p_lock) && (p->p_proc_flag & P_PR_LOCK));

	if (pr_watch_active(p)) {
		pr_free_watchpoints(p);
		if ((t = p->p_tlist) != NULL) {
			do {
				watch_disable(t);

			} while ((t = t->t_forw) != p->p_tlist);
		}
	}

	if ((as = p->p_as) != NULL) {
		avl_tree_t *tree;
		struct watched_page *pwp;

		/*
		 * If this is the parent of a vfork, the watched page
		 * list has been moved temporarily to p->p_wpage.
		 */
		if (avl_numnodes(&p->p_wpage) != 0)
			tree = &p->p_wpage;
		else
			tree = &as->a_wpage;

		mutex_exit(&p->p_lock);
		AS_LOCK_ENTER(as, RW_WRITER);

		for (pwp = avl_first(tree); pwp != NULL;
		    pwp = AVL_NEXT(tree, pwp)) {
			pwp->wp_read = 0;
			pwp->wp_write = 0;
			pwp->wp_exec = 0;
			if ((pwp->wp_flags & WP_SETPROT) == 0) {
				pwp->wp_flags |= WP_SETPROT;
				pwp->wp_prot = pwp->wp_oprot;
				pwp->wp_list = p->p_wprot;
				p->p_wprot = pwp;
			}
		}

		AS_LOCK_EXIT(as);
		mutex_enter(&p->p_lock);
	}

	/*
	 * Unpause the process now.
	 */
	if (p == curproc)
		continuelwps(p);
	else
		unpauselwps(p);

	return (p);
}
