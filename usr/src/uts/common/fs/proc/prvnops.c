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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

/*	Copyright (c) 1984,	 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/debug.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/proc.h>
#include <sys/brand.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/zone.h>
#include <sys/uio.h>
#include <sys/var.h>
#include <sys/mode.h>
#include <sys/poll.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/gfs.h>
#include <sys/vnode.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/contract_impl.h>
#include <sys/ctfs.h>
#include <sys/avl.h>
#include <fs/fs_subr.h>
#include <vm/rm.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <vm/hat.h>
#include <fs/proc/prdata.h>
#if defined(__sparc)
#include <sys/regset.h>
#endif
#if defined(__x86)
#include <sys/sysi86.h>
#endif

/*
 * Created by prinit.
 */
vnodeops_t *prvnodeops;

/*
 * Directory characteristics (patterned after the s5 file system).
 */
#define	PRROOTINO	2

#define	PRDIRSIZE	14
struct prdirect {
	ushort_t	d_ino;
	char		d_name[PRDIRSIZE];
};

#define	PRSDSIZE	(sizeof (struct prdirect))

/*
 * Directory characteristics.
 */
typedef struct prdirent {
	ino64_t		d_ino;		/* "inode number" of entry */
	off64_t		d_off;		/* offset of disk directory entry */
	unsigned short	d_reclen;	/* length of this record */
	char		d_name[14];	/* name of file */
} prdirent_t;

/*
 * Contents of a /proc/<pid> directory.
 * Reuse d_ino field for the /proc file type.
 */
static prdirent_t piddir[] = {
	{ PR_PIDDIR,	 1 * sizeof (prdirent_t), sizeof (prdirent_t),
		"." },
	{ PR_PROCDIR,	 2 * sizeof (prdirent_t), sizeof (prdirent_t),
		".." },
	{ PR_AS,	 3 * sizeof (prdirent_t), sizeof (prdirent_t),
		"as" },
	{ PR_CTL,	 4 * sizeof (prdirent_t), sizeof (prdirent_t),
		"ctl" },
	{ PR_STATUS,	 5 * sizeof (prdirent_t), sizeof (prdirent_t),
		"status" },
	{ PR_LSTATUS,	 6 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lstatus" },
	{ PR_PSINFO,	 7 * sizeof (prdirent_t), sizeof (prdirent_t),
		"psinfo" },
	{ PR_LPSINFO,	 8 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lpsinfo" },
	{ PR_MAP,	 9 * sizeof (prdirent_t), sizeof (prdirent_t),
		"map" },
	{ PR_RMAP,	10 * sizeof (prdirent_t), sizeof (prdirent_t),
		"rmap" },
	{ PR_XMAP,	11 * sizeof (prdirent_t), sizeof (prdirent_t),
		"xmap" },
	{ PR_CRED,	12 * sizeof (prdirent_t), sizeof (prdirent_t),
		"cred" },
	{ PR_SIGACT,	13 * sizeof (prdirent_t), sizeof (prdirent_t),
		"sigact" },
	{ PR_AUXV,	14 * sizeof (prdirent_t), sizeof (prdirent_t),
		"auxv" },
	{ PR_USAGE,	15 * sizeof (prdirent_t), sizeof (prdirent_t),
		"usage" },
	{ PR_LUSAGE,	16 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lusage" },
	{ PR_PAGEDATA,	17 * sizeof (prdirent_t), sizeof (prdirent_t),
		"pagedata" },
	{ PR_WATCH,	18 * sizeof (prdirent_t), sizeof (prdirent_t),
		"watch" },
	{ PR_CURDIR,	19 * sizeof (prdirent_t), sizeof (prdirent_t),
		"cwd" },
	{ PR_ROOTDIR,	20 * sizeof (prdirent_t), sizeof (prdirent_t),
		"root" },
	{ PR_FDDIR,	21 * sizeof (prdirent_t), sizeof (prdirent_t),
		"fd" },
	{ PR_OBJECTDIR,	22 * sizeof (prdirent_t), sizeof (prdirent_t),
		"object" },
	{ PR_LWPDIR,	23 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lwp" },
	{ PR_PRIV,	24 * sizeof (prdirent_t), sizeof (prdirent_t),
		"priv" },
	{ PR_PATHDIR,	25 * sizeof (prdirent_t), sizeof (prdirent_t),
		"path" },
	{ PR_CTDIR,	26 * sizeof (prdirent_t), sizeof (prdirent_t),
		"contracts" },
#if defined(__x86)
	{ PR_LDT,	27 * sizeof (prdirent_t), sizeof (prdirent_t),
		"ldt" },
#endif
};

#define	NPIDDIRFILES	(sizeof (piddir) / sizeof (piddir[0]) - 2)

/*
 * Contents of a /proc/<pid>/lwp/<lwpid> directory.
 */
static prdirent_t lwpiddir[] = {
	{ PR_LWPIDDIR,	 1 * sizeof (prdirent_t), sizeof (prdirent_t),
		"." },
	{ PR_LWPDIR,	 2 * sizeof (prdirent_t), sizeof (prdirent_t),
		".." },
	{ PR_LWPCTL,	 3 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lwpctl" },
	{ PR_LWPSTATUS,	 4 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lwpstatus" },
	{ PR_LWPSINFO,	 5 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lwpsinfo" },
	{ PR_LWPUSAGE,	 6 * sizeof (prdirent_t), sizeof (prdirent_t),
		"lwpusage" },
	{ PR_XREGS,	 7 * sizeof (prdirent_t), sizeof (prdirent_t),
		"xregs" },
	{ PR_TMPLDIR,	 8 * sizeof (prdirent_t), sizeof (prdirent_t),
		"templates" },
	{ PR_SPYMASTER,	 9 * sizeof (prdirent_t), sizeof (prdirent_t),
		"spymaster" },
#if defined(__sparc)
	{ PR_GWINDOWS,	10 * sizeof (prdirent_t), sizeof (prdirent_t),
		"gwindows" },
	{ PR_ASRS,	11 * sizeof (prdirent_t), sizeof (prdirent_t),
		"asrs" },
#endif
};

#define	NLWPIDDIRFILES	(sizeof (lwpiddir) / sizeof (lwpiddir[0]) - 2)

/*
 * Span of entries in the array files (lstatus, lpsinfo, lusage).
 * We make the span larger than the size of the structure on purpose,
 * to make sure that programs cannot use the structure size by mistake.
 * Align _ILP32 structures at 8 bytes, _LP64 structures at 16 bytes.
 */
#ifdef _LP64
#define	LSPAN(type)	(round16(sizeof (type)) + 16)
#define	LSPAN32(type)	(round8(sizeof (type)) + 8)
#else
#define	LSPAN(type)	(round8(sizeof (type)) + 8)
#endif

static void rebuild_objdir(struct as *);
static void prfreecommon(prcommon_t *);
static int praccess(vnode_t *, int, int, cred_t *, caller_context_t *);

static int
propen(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	vnode_t *vp = *vpp;
	prnode_t *pnp = VTOP(vp);
	prcommon_t *pcp = pnp->pr_pcommon;
	prnodetype_t type = pnp->pr_type;
	vnode_t *rvp;
	vtype_t vtype;
	proc_t *p;
	int error = 0;
	prnode_t *npnp = NULL;

	/*
	 * Nothing to do for the /proc directory itself.
	 */
	if (type == PR_PROCDIR)
		return (0);

	/*
	 * If we are opening an underlying mapped object, reject opens
	 * for writing regardless of the objects's access modes.
	 * If we are opening a file in the /proc/pid/fd directory,
	 * reject the open for any but a regular file or directory.
	 * Just do it if we are opening the current or root directory.
	 */
	switch (type) {
	case PR_OBJECT:
	case PR_FD:
	case PR_CURDIR:
	case PR_ROOTDIR:
		rvp = pnp->pr_realvp;
		vtype = rvp->v_type;
		if ((type == PR_OBJECT && (flag & FWRITE)) ||
		    (type == PR_FD && vtype != VREG && vtype != VDIR))
			error = EACCES;
		else {
			/*
			 * Need to hold rvp since VOP_OPEN() may release it.
			 */
			VN_HOLD(rvp);
			error = VOP_OPEN(&rvp, flag, cr, ct);
			if (error) {
				VN_RELE(rvp);
			} else {
				*vpp = rvp;
				VN_RELE(vp);
			}
		}
		return (error);
	default:
		break;
	}

	/*
	 * If we are opening the pagedata file, allocate a prnode now
	 * to avoid calling kmem_alloc() while holding p->p_lock.
	 */
	if (type == PR_PAGEDATA || type == PR_OPAGEDATA)
		npnp = prgetnode(vp, type);

	/*
	 * If the process exists, lock it now.
	 * Otherwise we have a race condition with prclose().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		if (npnp != NULL)
			prfreenode(npnp);
		return (ENOENT);
	}
	ASSERT(p == pcp->prc_proc);
	ASSERT(p->p_proc_flag & P_PR_LOCK);

	/*
	 * Maintain a count of opens for write.  Allow exactly one
	 * O_WRITE|O_EXCL request and fail subsequent ones.
	 * Don't fail opens of old (bletch!) /proc lwp files.
	 * Special case for open by the process itself:
	 * Always allow the open by self and discount this
	 * open for other opens for writing.
	 */
	if (flag & FWRITE) {
		if (p == curproc) {
			pcp->prc_selfopens++;
			pnp->pr_flags |= PR_ISSELF;
		} else if (type == PR_LWPIDFILE) {
			/* EMPTY */;
		} else if (flag & FEXCL) {
			if (pcp->prc_writers > pcp->prc_selfopens) {
				error = EBUSY;
				goto out;
			}
			/* semantic for old /proc interface */
			if (type == PR_PIDDIR)
				pcp->prc_flags |= PRC_EXCL;
		} else if (pcp->prc_flags & PRC_EXCL) {
			ASSERT(pcp->prc_writers > pcp->prc_selfopens);
			error = secpolicy_proc_excl_open(cr);
			if (error)
				goto out;
		}
		pcp->prc_writers++;
		/*
		 * The vnode may have become invalid between the
		 * VOP_LOOKUP() of the /proc vnode and the VOP_OPEN().
		 * If so, do now what prinvalidate() should have done.
		 */
		if ((pnp->pr_flags & PR_INVAL) ||
		    (type == PR_PIDDIR &&
		    (VTOP(pnp->pr_pidfile)->pr_flags & PR_INVAL))) {
			if (p != curproc)
				pcp->prc_selfopens++;
			ASSERT(pcp->prc_selfopens <= pcp->prc_writers);
			if (pcp->prc_selfopens == pcp->prc_writers)
				pcp->prc_flags &= ~PRC_EXCL;
		}
	}

	/*
	 * If this is a large file open, indicate that in our flags -- some
	 * procfs structures are not off_t-neutral (e.g., priovec_t), and
	 * the open will need to be differentiated where 32-bit processes
	 * pass these structures across the user/kernel boundary.
	 */
	if (flag & FOFFMAX)
		pnp->pr_flags |= PR_OFFMAX;

	/*
	 * Do file-specific things.
	 */
	switch (type) {
	default:
		break;
	case PR_PAGEDATA:
	case PR_OPAGEDATA:
		/*
		 * Enable data collection for page data file;
		 * get unique id from the hat layer.
		 */
		{
			int id;

			/*
			 * Drop p->p_lock to call hat_startstat()
			 */
			mutex_exit(&p->p_lock);
			if ((p->p_flag & SSYS) || p->p_as == &kas ||
			    (id = hat_startstat(p->p_as)) == -1) {
				mutex_enter(&p->p_lock);
				error = ENOMEM;
			} else if (pnp->pr_hatid == 0) {
				mutex_enter(&p->p_lock);
				pnp->pr_hatid = (uint_t)id;
			} else {
				mutex_enter(&p->p_lock);
				/*
				 * Use our newly allocated prnode.
				 */
				npnp->pr_hatid = (uint_t)id;
				/*
				 * prgetnode() initialized most of the prnode.
				 * Duplicate the remainder.
				 */
				npnp->pr_ino = pnp->pr_ino;
				npnp->pr_common = pnp->pr_common;
				npnp->pr_pcommon = pnp->pr_pcommon;
				npnp->pr_parent = pnp->pr_parent;
				VN_HOLD(npnp->pr_parent);
				npnp->pr_index = pnp->pr_index;

				npnp->pr_next = p->p_plist;
				p->p_plist = PTOV(npnp);

				VN_RELE(PTOV(pnp));
				pnp = npnp;
				npnp = NULL;
				*vpp = PTOV(pnp);
			}
		}
		break;
	}

out:
	prunlock(pnp);

	if (npnp != NULL)
		prfreenode(npnp);
	return (error);
}

/* ARGSUSED */
static int
prclose(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr,
	caller_context_t *ct)
{
	prnode_t *pnp = VTOP(vp);
	prcommon_t *pcp = pnp->pr_pcommon;
	prnodetype_t type = pnp->pr_type;
	proc_t *p;
	kthread_t *t;
	user_t *up;

	/*
	 * Nothing to do for the /proc directory itself.
	 */
	if (type == PR_PROCDIR)
		return (0);

	ASSERT(type != PR_OBJECT && type != PR_FD &&
	    type != PR_CURDIR && type != PR_ROOTDIR);

	/*
	 * If the process exists, lock it now.
	 * Otherwise we have a race condition with propen().
	 * Hold pr_pidlock across the reference to prc_selfopens,
	 * and prc_writers in case there is no process anymore,
	 * to cover the case of concurrent calls to prclose()
	 * after the process has been reaped by freeproc().
	 */
	p = pr_p_lock(pnp);

	/*
	 * There is nothing more to do until the last close of
	 * the file table entry except to clear the pr_owner
	 * field of the prnode and notify any waiters
	 * (their file descriptor may have just been closed).
	 */
	if (count > 1) {
		mutex_exit(&pr_pidlock);
		if (pnp->pr_owner == curproc && !fisopen(vp))
			pnp->pr_owner = NULL;
		if (p != NULL) {
			prnotify(vp);
			prunlock(pnp);
		}
		return (0);
	}

	/*
	 * Decrement the count of self-opens for writing.
	 * Decrement the total count of opens for writing.
	 * Cancel exclusive opens when only self-opens remain.
	 */
	if (flag & FWRITE) {
		/*
		 * prc_selfopens also contains the count of
		 * invalid writers.  See prinvalidate().
		 */
		if ((pnp->pr_flags & (PR_ISSELF|PR_INVAL)) ||
		    (type == PR_PIDDIR &&
		    (VTOP(pnp->pr_pidfile)->pr_flags & PR_INVAL))) {
			ASSERT(pcp->prc_selfopens != 0);
			--pcp->prc_selfopens;
		}
		ASSERT(pcp->prc_writers != 0);
		if (--pcp->prc_writers == pcp->prc_selfopens)
			pcp->prc_flags &= ~PRC_EXCL;
	}
	ASSERT(pcp->prc_writers >= pcp->prc_selfopens);
	mutex_exit(&pr_pidlock);
	if (pnp->pr_owner == curproc && !fisopen(vp))
		pnp->pr_owner = NULL;

	/*
	 * If there is no process, there is nothing more to do.
	 */
	if (p == NULL)
		return (0);

	ASSERT(p == pcp->prc_proc);
	prnotify(vp);	/* notify waiters */

	/*
	 * Do file-specific things.
	 */
	switch (type) {
	default:
		break;
	case PR_PAGEDATA:
	case PR_OPAGEDATA:
		/*
		 * This is a page data file.
		 * Free the hat level statistics.
		 * Drop p->p_lock before calling hat_freestat().
		 */
		mutex_exit(&p->p_lock);
		if (p->p_as != &kas && pnp->pr_hatid != 0)
			hat_freestat(p->p_as, pnp->pr_hatid);
		mutex_enter(&p->p_lock);
		pnp->pr_hatid = 0;
		break;
	}

	/*
	 * On last close of all writable file descriptors,
	 * perform run-on-last-close and/or kill-on-last-close logic.
	 * Can't do this is the /proc agent lwp still exists.
	 */
	if (pcp->prc_writers == 0 &&
	    p->p_agenttp == NULL &&
	    !(pcp->prc_flags & PRC_DESTROY) &&
	    p->p_stat != SZOMB &&
	    (p->p_proc_flag & (P_PR_RUNLCL|P_PR_KILLCL))) {
		int killproc;

		/*
		 * Cancel any watchpoints currently in effect.
		 * The process might disappear during this operation.
		 */
		if (pr_cancel_watch(pnp) == NULL)
			return (0);
		/*
		 * If any tracing flags are set, clear them.
		 */
		if (p->p_proc_flag & P_PR_TRACE) {
			up = PTOU(p);
			premptyset(&up->u_entrymask);
			premptyset(&up->u_exitmask);
			up->u_systrap = 0;
		}
		premptyset(&p->p_sigmask);
		premptyset(&p->p_fltmask);
		killproc = (p->p_proc_flag & P_PR_KILLCL);
		p->p_proc_flag &= ~(P_PR_RUNLCL|P_PR_KILLCL|P_PR_TRACE);
		/*
		 * Cancel any outstanding single-step requests.
		 */
		if ((t = p->p_tlist) != NULL) {
			/*
			 * Drop p_lock because prnostep() touches the stack.
			 * The loop is safe because the process is P_PR_LOCK'd.
			 */
			mutex_exit(&p->p_lock);
			do {
				prnostep(ttolwp(t));
			} while ((t = t->t_forw) != p->p_tlist);
			mutex_enter(&p->p_lock);
		}
		/*
		 * Set runnable all lwps stopped by /proc.
		 */
		if (killproc)
			sigtoproc(p, NULL, SIGKILL);
		else
			allsetrun(p);
	}

	prunlock(pnp);
	return (0);
}

/*
 * Array of read functions, indexed by /proc file type.
 */
static int pr_read_inval(), pr_read_as(), pr_read_status(),
	pr_read_lstatus(), pr_read_psinfo(), pr_read_lpsinfo(),
	pr_read_map(), pr_read_rmap(), pr_read_xmap(),
	pr_read_cred(), pr_read_sigact(), pr_read_auxv(),
#if defined(__x86)
	pr_read_ldt(),
#endif
	pr_read_usage(), pr_read_lusage(), pr_read_pagedata(),
	pr_read_watch(), pr_read_lwpstatus(), pr_read_lwpsinfo(),
	pr_read_lwpusage(), pr_read_xregs(), pr_read_priv(),
	pr_read_spymaster(),
#if defined(__sparc)
	pr_read_gwindows(), pr_read_asrs(),
#endif
	pr_read_piddir(), pr_read_pidfile(), pr_read_opagedata();

static int (*pr_read_function[PR_NFILES])() = {
	pr_read_inval,		/* /proc				*/
	pr_read_inval,		/* /proc/self				*/
	pr_read_piddir,		/* /proc/<pid> (old /proc read())	*/
	pr_read_as,		/* /proc/<pid>/as			*/
	pr_read_inval,		/* /proc/<pid>/ctl			*/
	pr_read_status,		/* /proc/<pid>/status			*/
	pr_read_lstatus,	/* /proc/<pid>/lstatus			*/
	pr_read_psinfo,		/* /proc/<pid>/psinfo			*/
	pr_read_lpsinfo,	/* /proc/<pid>/lpsinfo			*/
	pr_read_map,		/* /proc/<pid>/map			*/
	pr_read_rmap,		/* /proc/<pid>/rmap			*/
	pr_read_xmap,		/* /proc/<pid>/xmap			*/
	pr_read_cred,		/* /proc/<pid>/cred			*/
	pr_read_sigact,		/* /proc/<pid>/sigact			*/
	pr_read_auxv,		/* /proc/<pid>/auxv			*/
#if defined(__x86)
	pr_read_ldt,		/* /proc/<pid>/ldt			*/
#endif
	pr_read_usage,		/* /proc/<pid>/usage			*/
	pr_read_lusage,		/* /proc/<pid>/lusage			*/
	pr_read_pagedata,	/* /proc/<pid>/pagedata			*/
	pr_read_watch,		/* /proc/<pid>/watch			*/
	pr_read_inval,		/* /proc/<pid>/cwd			*/
	pr_read_inval,		/* /proc/<pid>/root			*/
	pr_read_inval,		/* /proc/<pid>/fd			*/
	pr_read_inval,		/* /proc/<pid>/fd/nn			*/
	pr_read_inval,		/* /proc/<pid>/object			*/
	pr_read_inval,		/* /proc/<pid>/object/xxx		*/
	pr_read_inval,		/* /proc/<pid>/lwp			*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>		*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>/lwpctl	*/
	pr_read_lwpstatus,	/* /proc/<pid>/lwp/<lwpid>/lwpstatus	*/
	pr_read_lwpsinfo,	/* /proc/<pid>/lwp/<lwpid>/lwpsinfo	*/
	pr_read_lwpusage,	/* /proc/<pid>/lwp/<lwpid>/lwpusage	*/
	pr_read_xregs,		/* /proc/<pid>/lwp/<lwpid>/xregs	*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>/templates	*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>/templates/<id> */
	pr_read_spymaster,	/* /proc/<pid>/lwp/<lwpid>/spymaster	*/
#if defined(__sparc)
	pr_read_gwindows,	/* /proc/<pid>/lwp/<lwpid>/gwindows	*/
	pr_read_asrs,		/* /proc/<pid>/lwp/<lwpid>/asrs		*/
#endif
	pr_read_priv,		/* /proc/<pid>/priv			*/
	pr_read_inval,		/* /proc/<pid>/path			*/
	pr_read_inval,		/* /proc/<pid>/path/xxx			*/
	pr_read_inval,		/* /proc/<pid>/contracts		*/
	pr_read_inval,		/* /proc/<pid>/contracts/<ctid>		*/
	pr_read_pidfile,	/* old process file			*/
	pr_read_pidfile,	/* old lwp file				*/
	pr_read_opagedata,	/* old pagedata file			*/
};

/* ARGSUSED */
static int
pr_read_inval(prnode_t *pnp, uio_t *uiop)
{
	/*
	 * No read() on any /proc directory, use getdents(2) instead.
	 * Cannot read a control file either.
	 * An underlying mapped object file cannot get here.
	 */
	return (EINVAL);
}

static int
pr_uioread(void *base, long count, uio_t *uiop)
{
	int error = 0;

	ASSERT(count >= 0);
	count -= uiop->uio_offset;
	if (count > 0 && uiop->uio_offset >= 0) {
		error = uiomove((char *)base + uiop->uio_offset,
		    count, UIO_READ, uiop);
	}

	return (error);
}

static int
pr_read_as(prnode_t *pnp, uio_t *uiop)
{
	int error;

	ASSERT(pnp->pr_type == PR_AS);

	if ((error = prlock(pnp, ZNO)) == 0) {
		proc_t *p = pnp->pr_common->prc_proc;
		struct as *as = p->p_as;

		/*
		 * /proc I/O cannot be done to a system process.
		 * A 32-bit process cannot read a 64-bit process.
		 */
		if ((p->p_flag & SSYS) || as == &kas) {
			error = 0;
#ifdef _SYSCALL32_IMPL
		} else if (curproc->p_model == DATAMODEL_ILP32 &&
		    PROCESS_NOT_32BIT(p)) {
			error = EOVERFLOW;
#endif
		} else {
			/*
			 * We don't hold p_lock over an i/o operation because
			 * that could lead to deadlock with the clock thread.
			 */
			mutex_exit(&p->p_lock);
			error = prusrio(p, UIO_READ, uiop, 0);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
	}

	return (error);
}

static int
pr_read_status(prnode_t *pnp, uio_t *uiop)
{
	pstatus_t *sp;
	int error;

	ASSERT(pnp->pr_type == PR_STATUS);

	/*
	 * We kmem_alloc() the pstatus structure because
	 * it is so big it might blow the kernel stack.
	 */
	sp = kmem_alloc(sizeof (*sp), KM_SLEEP);
	if ((error = prlock(pnp, ZNO)) == 0) {
		prgetstatus(pnp->pr_common->prc_proc, sp, VTOZONE(PTOV(pnp)));
		prunlock(pnp);
		error = pr_uioread(sp, sizeof (*sp), uiop);
	}
	kmem_free(sp, sizeof (*sp));
	return (error);
}

static int
pr_read_lstatus(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	kthread_t *t;
	lwpdir_t *ldp;
	size_t size;
	prheader_t *php;
	lwpstatus_t *sp;
	int error;
	int nlwp;
	int i;

	ASSERT(pnp->pr_type == PR_LSTATUS);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;
	nlwp = p->p_lwpcnt;
	size = sizeof (prheader_t) + nlwp * LSPAN(lwpstatus_t);

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	php = kmem_zalloc(size, KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_lwpcnt can't change while process is locked */
	ASSERT(nlwp == p->p_lwpcnt);

	php->pr_nent = nlwp;
	php->pr_entsize = LSPAN(lwpstatus_t);

	sp = (lwpstatus_t *)(php + 1);
	for (ldp = p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++, ldp++) {
		if (ldp->ld_entry == NULL ||
		    (t = ldp->ld_entry->le_thread) == NULL)
			continue;
		prgetlwpstatus(t, sp, VTOZONE(PTOV(pnp)));
		sp = (lwpstatus_t *)((caddr_t)sp + LSPAN(lwpstatus_t));
	}
	prunlock(pnp);

	error = pr_uioread(php, size, uiop);
	kmem_free(php, size);
	return (error);
}

static int
pr_read_psinfo(prnode_t *pnp, uio_t *uiop)
{
	psinfo_t psinfo;
	proc_t *p;
	int error = 0;

	ASSERT(pnp->pr_type == PR_PSINFO);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		error = ENOENT;
	else {
		ASSERT(p == pnp->pr_common->prc_proc);
		prgetpsinfo(p, &psinfo);
		prunlock(pnp);
		error = pr_uioread(&psinfo, sizeof (psinfo), uiop);
	}
	return (error);
}

static int
pr_read_lpsinfo(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	kthread_t *t;
	lwpdir_t *ldp;
	lwpent_t *lep;
	size_t size;
	prheader_t *php;
	lwpsinfo_t *sp;
	int error;
	int nlwp;
	int i;

	ASSERT(pnp->pr_type == PR_LPSINFO);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	ASSERT(p == pnp->pr_common->prc_proc);
	if ((nlwp = p->p_lwpcnt + p->p_zombcnt) == 0) {
		prunlock(pnp);
		return (ENOENT);
	}
	size = sizeof (prheader_t) + nlwp * LSPAN(lwpsinfo_t);

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	php = kmem_zalloc(size, KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_lwpcnt can't change while process is locked */
	ASSERT(nlwp == p->p_lwpcnt + p->p_zombcnt);

	php->pr_nent = nlwp;
	php->pr_entsize = LSPAN(lwpsinfo_t);

	sp = (lwpsinfo_t *)(php + 1);
	for (ldp = p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++, ldp++) {
		if ((lep = ldp->ld_entry) == NULL)
			continue;
		if ((t = lep->le_thread) != NULL)
			prgetlwpsinfo(t, sp);
		else {
			bzero(sp, sizeof (*sp));
			sp->pr_lwpid = lep->le_lwpid;
			sp->pr_state = SZOMB;
			sp->pr_sname = 'Z';
			sp->pr_start.tv_sec = lep->le_start;
			sp->pr_bindpro = PBIND_NONE;
			sp->pr_bindpset = PS_NONE;
		}
		sp = (lwpsinfo_t *)((caddr_t)sp + LSPAN(lwpsinfo_t));
	}
	prunlock(pnp);

	error = pr_uioread(php, size, uiop);
	kmem_free(php, size);
	return (error);
}

static int
pr_read_map_common(prnode_t *pnp, uio_t *uiop, prnodetype_t type)
{
	proc_t *p;
	struct as *as;
	list_t iolhead;
	int error;

readmap_common:
	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	as = p->p_as;

	if ((p->p_flag & SSYS) || as == &kas) {
		prunlock(pnp);
		return (0);
	}

	if (!AS_LOCK_TRYENTER(as, &as->a_lock, RW_WRITER)) {
		prunlock(pnp);
		delay(1);
		goto readmap_common;
	}
	mutex_exit(&p->p_lock);

	switch (type) {
	case PR_XMAP:
		error = prgetxmap(p, &iolhead);
		break;
	case PR_RMAP:
		error = prgetmap(p, 1, &iolhead);
		break;
	case PR_MAP:
		error = prgetmap(p, 0, &iolhead);
		break;
	}

	AS_LOCK_EXIT(as, &as->a_lock);
	mutex_enter(&p->p_lock);
	prunlock(pnp);

	error = pr_iol_uiomove_and_free(&iolhead, uiop, error);

	return (error);
}

static int
pr_read_map(prnode_t *pnp, uio_t *uiop)
{
	ASSERT(pnp->pr_type == PR_MAP);
	return (pr_read_map_common(pnp, uiop, pnp->pr_type));
}

static int
pr_read_rmap(prnode_t *pnp, uio_t *uiop)
{
	ASSERT(pnp->pr_type == PR_RMAP);
	return (pr_read_map_common(pnp, uiop, pnp->pr_type));
}

static int
pr_read_xmap(prnode_t *pnp, uio_t *uiop)
{
	ASSERT(pnp->pr_type == PR_XMAP);
	return (pr_read_map_common(pnp, uiop, pnp->pr_type));
}

static int
pr_read_cred(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	prcred_t *pcrp;
	int error;
	size_t count;

	ASSERT(pnp->pr_type == PR_CRED);

	/*
	 * We kmem_alloc() the prcred_t structure because
	 * the number of supplementary groups is variable.
	 */
	pcrp =
	    kmem_alloc(sizeof (prcred_t) + sizeof (gid_t) * (ngroups_max - 1),
	    KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;
	p = pnp->pr_common->prc_proc;
	ASSERT(p != NULL);

	prgetcred(p, pcrp);
	prunlock(pnp);

	count = sizeof (prcred_t);
	if (pcrp->pr_ngroups > 1)
		count += sizeof (gid_t) * (pcrp->pr_ngroups - 1);
	error = pr_uioread(pcrp, count, uiop);
out:
	kmem_free(pcrp, sizeof (prcred_t) + sizeof (gid_t) * (ngroups_max - 1));
	return (error);
}

static int
pr_read_priv(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	size_t psize = prgetprivsize();
	prpriv_t *ppriv = kmem_alloc(psize, KM_SLEEP);
	int error;

	ASSERT(pnp->pr_type == PR_PRIV);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;
	p = pnp->pr_common->prc_proc;
	ASSERT(p != NULL);

	prgetpriv(p, ppriv);
	prunlock(pnp);

	error = pr_uioread(ppriv, psize, uiop);
out:
	kmem_free(ppriv, psize);
	return (error);
}

static int
pr_read_sigact(prnode_t *pnp, uio_t *uiop)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
	proc_t *p;
	struct sigaction *sap;
	int sig;
	int error;
	user_t *up;

	ASSERT(pnp->pr_type == PR_SIGACT);

	/*
	 * We kmem_alloc() the sigaction array because
	 * it is so big it might blow the kernel stack.
	 */
	sap = kmem_alloc((nsig-1) * sizeof (struct sigaction), KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;
	p = pnp->pr_common->prc_proc;
	ASSERT(p != NULL);

	if (uiop->uio_offset >= (nsig-1)*sizeof (struct sigaction)) {
		prunlock(pnp);
		goto out;
	}

	up = PTOU(p);
	for (sig = 1; sig < nsig; sig++)
		prgetaction(p, up, sig, &sap[sig-1]);
	prunlock(pnp);

	error = pr_uioread(sap, (nsig - 1) * sizeof (struct sigaction), uiop);
out:
	kmem_free(sap, (nsig-1) * sizeof (struct sigaction));
	return (error);
}

static int
pr_read_auxv(prnode_t *pnp, uio_t *uiop)
{
	auxv_t auxv[__KERN_NAUXV_IMPL];
	proc_t *p;
	user_t *up;
	int error;

	ASSERT(pnp->pr_type == PR_AUXV);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	if (uiop->uio_offset >= sizeof (auxv)) {
		prunlock(pnp);
		return (0);
	}

	p = pnp->pr_common->prc_proc;
	up = PTOU(p);
	bcopy(up->u_auxv, auxv, sizeof (auxv));
	prunlock(pnp);

	return (pr_uioread(auxv, sizeof (auxv), uiop));
}

#if defined(__x86)
/*
 * XX64
 *	This is almost certainly broken for the amd64 kernel, because
 *	we have two kinds of LDT structures to export -- one for compatibility
 *	mode, and one for long mode, sigh.
 *
 * 	For now lets just have a ldt of size 0 for 64-bit processes.
 */
static int
pr_read_ldt(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	struct ssd *ssd;
	size_t size;
	int error;

	ASSERT(pnp->pr_type == PR_LDT);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;

	mutex_exit(&p->p_lock);
	mutex_enter(&p->p_ldtlock);
	size = prnldt(p) * sizeof (struct ssd);
	if (uiop->uio_offset >= size) {
		mutex_exit(&p->p_ldtlock);
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		return (0);
	}

	ssd = kmem_alloc(size, KM_SLEEP);
	prgetldt(p, ssd);
	mutex_exit(&p->p_ldtlock);
	mutex_enter(&p->p_lock);
	prunlock(pnp);

	error = pr_uioread(ssd, size, uiop);
	kmem_free(ssd, size);
	return (error);
}
#endif	/* __x86 */

static int
pr_read_usage(prnode_t *pnp, uio_t *uiop)
{
	prhusage_t *pup;
	prusage_t *upup;
	proc_t *p;
	kthread_t *t;
	int error;

	ASSERT(pnp->pr_type == PR_USAGE);

	/* allocate now, before locking the process */
	pup = kmem_zalloc(sizeof (*pup), KM_SLEEP);
	upup = kmem_alloc(sizeof (*upup), KM_SLEEP);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		error = ENOENT;
		goto out;
	}
	ASSERT(p == pnp->pr_common->prc_proc);

	if (uiop->uio_offset >= sizeof (prusage_t)) {
		prunlock(pnp);
		error = 0;
		goto out;
	}

	pup->pr_tstamp = gethrtime();

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
	    !(pnp->pr_pcommon->prc_flags & PRC_DESTROY)) {
		do {
			if (t->t_proc_flag & TP_LWPEXIT)
				continue;
			pup->pr_count++;
			praddusage(t, pup);
		} while ((t = t->t_forw) != p->p_tlist);
	}

	prunlock(pnp);

	prcvtusage(pup, upup);

	error = pr_uioread(upup, sizeof (prusage_t), uiop);
out:
	kmem_free(pup, sizeof (*pup));
	kmem_free(upup, sizeof (*upup));
	return (error);
}

static int
pr_read_lusage(prnode_t *pnp, uio_t *uiop)
{
	int nlwp;
	prhusage_t *pup;
	prheader_t *php;
	prusage_t *upup;
	size_t size;
	hrtime_t curtime;
	proc_t *p;
	kthread_t *t;
	lwpdir_t *ldp;
	int error;
	int i;

	ASSERT(pnp->pr_type == PR_LUSAGE);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	ASSERT(p == pnp->pr_common->prc_proc);
	if ((nlwp = p->p_lwpcnt) == 0) {
		prunlock(pnp);
		return (ENOENT);
	}

	size = sizeof (prheader_t) + (nlwp + 1) * LSPAN(prusage_t);
	if (uiop->uio_offset >= size) {
		prunlock(pnp);
		return (0);
	}

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	pup = kmem_zalloc(size + sizeof (prhusage_t), KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_lwpcnt can't change while process is locked */
	ASSERT(nlwp == p->p_lwpcnt);

	php = (prheader_t *)(pup + 1);
	upup = (prusage_t *)(php + 1);

	php->pr_nent = nlwp + 1;
	php->pr_entsize = LSPAN(prusage_t);

	curtime = gethrtime();

	/*
	 * First the summation over defunct lwps.
	 */
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
	for (ldp = p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++, ldp++) {
		if (ldp->ld_entry == NULL ||
		    (t = ldp->ld_entry->le_thread) == NULL)
			continue;
		ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
		ASSERT(nlwp > 0);
		--nlwp;
		upup = (prusage_t *)((caddr_t)upup + LSPAN(prusage_t));
		prgetusage(t, pup);
		prcvtusage(pup, upup);
	}
	ASSERT(nlwp == 0);

	prunlock(pnp);

	error = pr_uioread(php, size, uiop);
	kmem_free(pup, size + sizeof (prhusage_t));
	return (error);
}

static int
pr_read_pagedata(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	int error;

	ASSERT(pnp->pr_type == PR_PAGEDATA);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	if ((p->p_flag & SSYS) || p->p_as == &kas) {
		prunlock(pnp);
		return (0);
	}

	mutex_exit(&p->p_lock);
	error = prpdread(p, pnp->pr_hatid, uiop);
	mutex_enter(&p->p_lock);

	prunlock(pnp);
	return (error);
}

static int
pr_read_opagedata(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	struct as *as;
	int error;

	ASSERT(pnp->pr_type == PR_OPAGEDATA);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	as = p->p_as;
	if ((p->p_flag & SSYS) || as == &kas) {
		prunlock(pnp);
		return (0);
	}

	mutex_exit(&p->p_lock);
	error = oprpdread(as, pnp->pr_hatid, uiop);
	mutex_enter(&p->p_lock);

	prunlock(pnp);
	return (error);
}

static int
pr_read_watch(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	int error;
	prwatch_t *Bpwp;
	size_t size;
	prwatch_t *pwp;
	int nwarea;
	struct watched_area *pwarea;

	ASSERT(pnp->pr_type == PR_WATCH);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	nwarea = avl_numnodes(&p->p_warea);
	size = nwarea * sizeof (prwatch_t);
	if (uiop->uio_offset >= size) {
		prunlock(pnp);
		return (0);
	}

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	Bpwp = pwp = kmem_zalloc(size, KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_nwarea can't change while process is locked */
	ASSERT(nwarea == avl_numnodes(&p->p_warea));

	/* gather the watched areas */
	for (pwarea = avl_first(&p->p_warea); pwarea != NULL;
	    pwarea = AVL_NEXT(&p->p_warea, pwarea), pwp++) {
		pwp->pr_vaddr = (uintptr_t)pwarea->wa_vaddr;
		pwp->pr_size = pwarea->wa_eaddr - pwarea->wa_vaddr;
		pwp->pr_wflags = (int)pwarea->wa_flags;
	}

	prunlock(pnp);

	error = pr_uioread(Bpwp, size, uiop);
	kmem_free(Bpwp, size);
	return (error);
}

static int
pr_read_lwpstatus(prnode_t *pnp, uio_t *uiop)
{
	lwpstatus_t *sp;
	int error;

	ASSERT(pnp->pr_type == PR_LWPSTATUS);

	/*
	 * We kmem_alloc() the lwpstatus structure because
	 * it is so big it might blow the kernel stack.
	 */
	sp = kmem_alloc(sizeof (*sp), KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;

	if (uiop->uio_offset >= sizeof (*sp)) {
		prunlock(pnp);
		goto out;
	}

	prgetlwpstatus(pnp->pr_common->prc_thread, sp, VTOZONE(PTOV(pnp)));
	prunlock(pnp);

	error = pr_uioread(sp, sizeof (*sp), uiop);
out:
	kmem_free(sp, sizeof (*sp));
	return (error);
}

static int
pr_read_lwpsinfo(prnode_t *pnp, uio_t *uiop)
{
	lwpsinfo_t lwpsinfo;
	proc_t *p;
	kthread_t *t;
	lwpent_t *lep;

	ASSERT(pnp->pr_type == PR_LWPSINFO);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	ASSERT(p == pnp->pr_common->prc_proc);
	if (pnp->pr_common->prc_tslot == -1) {
		prunlock(pnp);
		return (ENOENT);
	}

	if (uiop->uio_offset >= sizeof (lwpsinfo)) {
		prunlock(pnp);
		return (0);
	}

	if ((t = pnp->pr_common->prc_thread) != NULL)
		prgetlwpsinfo(t, &lwpsinfo);
	else {
		lep = p->p_lwpdir[pnp->pr_common->prc_tslot].ld_entry;
		bzero(&lwpsinfo, sizeof (lwpsinfo));
		lwpsinfo.pr_lwpid = lep->le_lwpid;
		lwpsinfo.pr_state = SZOMB;
		lwpsinfo.pr_sname = 'Z';
		lwpsinfo.pr_start.tv_sec = lep->le_start;
		lwpsinfo.pr_bindpro = PBIND_NONE;
		lwpsinfo.pr_bindpset = PS_NONE;
	}
	prunlock(pnp);

	return (pr_uioread(&lwpsinfo, sizeof (lwpsinfo), uiop));
}

static int
pr_read_lwpusage(prnode_t *pnp, uio_t *uiop)
{
	prhusage_t *pup;
	prusage_t *upup;
	proc_t *p;
	int error;

	ASSERT(pnp->pr_type == PR_LWPUSAGE);

	/* allocate now, before locking the process */
	pup = kmem_zalloc(sizeof (*pup), KM_SLEEP);
	upup = kmem_alloc(sizeof (*upup), KM_SLEEP);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		error = ENOENT;
		goto out;
	}
	ASSERT(p == pnp->pr_common->prc_proc);
	if (pnp->pr_common->prc_thread == NULL) {
		prunlock(pnp);
		error = ENOENT;
		goto out;
	}
	if (uiop->uio_offset >= sizeof (prusage_t)) {
		prunlock(pnp);
		error = 0;
		goto out;
	}

	pup->pr_tstamp = gethrtime();
	prgetusage(pnp->pr_common->prc_thread, pup);

	prunlock(pnp);

	prcvtusage(pup, upup);

	error = pr_uioread(upup, sizeof (prusage_t), uiop);
out:
	kmem_free(pup, sizeof (*pup));
	kmem_free(upup, sizeof (*upup));
	return (error);
}

/* ARGSUSED */
static int
pr_read_xregs(prnode_t *pnp, uio_t *uiop)
{
#if defined(__sparc)
	proc_t *p;
	kthread_t *t;
	int error;
	char *xreg;
	size_t size;

	ASSERT(pnp->pr_type == PR_XREGS);

	xreg = kmem_zalloc(sizeof (prxregset_t), KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;

	p = pnp->pr_common->prc_proc;
	t = pnp->pr_common->prc_thread;

	size = prhasx(p)? prgetprxregsize(p) : 0;
	if (uiop->uio_offset >= size) {
		prunlock(pnp);
		goto out;
	}

	/* drop p->p_lock while (possibly) touching the stack */
	mutex_exit(&p->p_lock);
	prgetprxregs(ttolwp(t), xreg);
	mutex_enter(&p->p_lock);
	prunlock(pnp);

	error = pr_uioread(xreg, size, uiop);
out:
	kmem_free(xreg, sizeof (prxregset_t));
	return (error);
#else
	return (0);
#endif
}

static int
pr_read_spymaster(prnode_t *pnp, uio_t *uiop)
{
	psinfo_t psinfo;
	int error;
	klwp_t *lwp;

	ASSERT(pnp->pr_type == PR_SPYMASTER);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	lwp = pnp->pr_common->prc_thread->t_lwp;

	if (lwp->lwp_spymaster == NULL) {
		prunlock(pnp);
		return (0);
	}

	bcopy(lwp->lwp_spymaster, &psinfo, sizeof (psinfo_t));
	prunlock(pnp);

	return (pr_uioread(&psinfo, sizeof (psinfo), uiop));
}

#if defined(__sparc)

static int
pr_read_gwindows(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	kthread_t *t;
	gwindows_t *gwp;
	int error;
	size_t size;

	ASSERT(pnp->pr_type == PR_GWINDOWS);

	gwp = kmem_zalloc(sizeof (gwindows_t), KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;

	p = pnp->pr_common->prc_proc;
	t = pnp->pr_common->prc_thread;

	/*
	 * Drop p->p_lock while touching the stack.
	 * The P_PR_LOCK flag prevents the lwp from
	 * disappearing while we do this.
	 */
	mutex_exit(&p->p_lock);
	if ((size = prnwindows(ttolwp(t))) != 0)
		size = sizeof (gwindows_t) -
		    (SPARC_MAXREGWINDOW - size) * sizeof (struct rwindow);
	if (uiop->uio_offset >= size) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		goto out;
	}
	prgetwindows(ttolwp(t), gwp);
	mutex_enter(&p->p_lock);
	prunlock(pnp);

	error = pr_uioread(gwp, size, uiop);
out:
	kmem_free(gwp, sizeof (gwindows_t));
	return (error);
}

/* ARGSUSED */
static int
pr_read_asrs(prnode_t *pnp, uio_t *uiop)
{
	int error;

	ASSERT(pnp->pr_type == PR_ASRS);

	/* the asrs file exists only for sparc v9 _LP64 processes */
	if ((error = prlock(pnp, ZNO)) == 0) {
		proc_t *p = pnp->pr_common->prc_proc;
		kthread_t *t = pnp->pr_common->prc_thread;
		asrset_t asrset;

		if (p->p_model != DATAMODEL_LP64 ||
		    uiop->uio_offset >= sizeof (asrset_t)) {
			prunlock(pnp);
			return (0);
		}

		/*
		 * Drop p->p_lock while touching the stack.
		 * The P_PR_LOCK flag prevents the lwp from
		 * disappearing while we do this.
		 */
		mutex_exit(&p->p_lock);
		prgetasregs(ttolwp(t), asrset);
		mutex_enter(&p->p_lock);
		prunlock(pnp);

		error = pr_uioread(&asrset[0], sizeof (asrset_t), uiop);
	}

	return (error);
}

#endif	/* __sparc */

static int
pr_read_piddir(prnode_t *pnp, uio_t *uiop)
{
	ASSERT(pnp->pr_type == PR_PIDDIR);
	ASSERT(pnp->pr_pidfile != NULL);

	/* use the underlying PR_PIDFILE to read the process */
	pnp = VTOP(pnp->pr_pidfile);
	ASSERT(pnp->pr_type == PR_PIDFILE);

	return (pr_read_pidfile(pnp, uiop));
}

static int
pr_read_pidfile(prnode_t *pnp, uio_t *uiop)
{
	int error;

	ASSERT(pnp->pr_type == PR_PIDFILE || pnp->pr_type == PR_LWPIDFILE);

	if ((error = prlock(pnp, ZNO)) == 0) {
		proc_t *p = pnp->pr_common->prc_proc;
		struct as *as = p->p_as;

		if ((p->p_flag & SSYS) || as == &kas) {
			/*
			 * /proc I/O cannot be done to a system process.
			 */
			error = EIO;	/* old /proc semantics */
		} else {
			/*
			 * We drop p_lock because we don't want to hold
			 * it over an I/O operation because that could
			 * lead to deadlock with the clock thread.
			 * The process will not disappear and its address
			 * space will not change because it is marked P_PR_LOCK.
			 */
			mutex_exit(&p->p_lock);
			error = prusrio(p, UIO_READ, uiop, 1);
			mutex_enter(&p->p_lock);
		}
		prunlock(pnp);
	}

	return (error);
}

#ifdef _SYSCALL32_IMPL

/*
 * Array of ILP32 read functions, indexed by /proc file type.
 */
static int pr_read_status_32(),
	pr_read_lstatus_32(), pr_read_psinfo_32(), pr_read_lpsinfo_32(),
	pr_read_map_32(), pr_read_rmap_32(), pr_read_xmap_32(),
	pr_read_sigact_32(), pr_read_auxv_32(),
	pr_read_usage_32(), pr_read_lusage_32(), pr_read_pagedata_32(),
	pr_read_watch_32(), pr_read_lwpstatus_32(), pr_read_lwpsinfo_32(),
	pr_read_lwpusage_32(), pr_read_spymaster_32(),
#if defined(__sparc)
	pr_read_gwindows_32(),
#endif
	pr_read_opagedata_32();

static int (*pr_read_function_32[PR_NFILES])() = {
	pr_read_inval,		/* /proc				*/
	pr_read_inval,		/* /proc/self				*/
	pr_read_piddir,		/* /proc/<pid> (old /proc read())	*/
	pr_read_as,		/* /proc/<pid>/as			*/
	pr_read_inval,		/* /proc/<pid>/ctl			*/
	pr_read_status_32,	/* /proc/<pid>/status			*/
	pr_read_lstatus_32,	/* /proc/<pid>/lstatus			*/
	pr_read_psinfo_32,	/* /proc/<pid>/psinfo			*/
	pr_read_lpsinfo_32,	/* /proc/<pid>/lpsinfo			*/
	pr_read_map_32,		/* /proc/<pid>/map			*/
	pr_read_rmap_32,	/* /proc/<pid>/rmap			*/
	pr_read_xmap_32,	/* /proc/<pid>/xmap			*/
	pr_read_cred,		/* /proc/<pid>/cred			*/
	pr_read_sigact_32,	/* /proc/<pid>/sigact			*/
	pr_read_auxv_32,	/* /proc/<pid>/auxv			*/
#if defined(__x86)
	pr_read_ldt,		/* /proc/<pid>/ldt			*/
#endif
	pr_read_usage_32,	/* /proc/<pid>/usage			*/
	pr_read_lusage_32,	/* /proc/<pid>/lusage			*/
	pr_read_pagedata_32,	/* /proc/<pid>/pagedata			*/
	pr_read_watch_32,	/* /proc/<pid>/watch			*/
	pr_read_inval,		/* /proc/<pid>/cwd			*/
	pr_read_inval,		/* /proc/<pid>/root			*/
	pr_read_inval,		/* /proc/<pid>/fd			*/
	pr_read_inval,		/* /proc/<pid>/fd/nn			*/
	pr_read_inval,		/* /proc/<pid>/object			*/
	pr_read_inval,		/* /proc/<pid>/object/xxx		*/
	pr_read_inval,		/* /proc/<pid>/lwp			*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>		*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>/lwpctl	*/
	pr_read_lwpstatus_32,	/* /proc/<pid>/lwp/<lwpid>/lwpstatus	*/
	pr_read_lwpsinfo_32,	/* /proc/<pid>/lwp/<lwpid>/lwpsinfo	*/
	pr_read_lwpusage_32,	/* /proc/<pid>/lwp/<lwpid>/lwpusage	*/
	pr_read_xregs,		/* /proc/<pid>/lwp/<lwpid>/xregs	*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>/templates	*/
	pr_read_inval,		/* /proc/<pid>/lwp/<lwpid>/templates/<id> */
	pr_read_spymaster_32,	/* /proc/<pid>/lwp/<lwpid>/spymaster	*/
#if defined(__sparc)
	pr_read_gwindows_32,	/* /proc/<pid>/lwp/<lwpid>/gwindows	*/
	pr_read_asrs,		/* /proc/<pid>/lwp/<lwpid>/asrs		*/
#endif
	pr_read_priv,		/* /proc/<pid>/priv			*/
	pr_read_inval,		/* /proc/<pid>/path			*/
	pr_read_inval,		/* /proc/<pid>/path/xxx			*/
	pr_read_inval,		/* /proc/<pid>/contracts		*/
	pr_read_inval,		/* /proc/<pid>/contracts/<ctid>		*/
	pr_read_pidfile,	/* old process file			*/
	pr_read_pidfile,	/* old lwp file				*/
	pr_read_opagedata_32,	/* old pagedata file			*/
};

static int
pr_read_status_32(prnode_t *pnp, uio_t *uiop)
{
	pstatus32_t *sp;
	proc_t *p;
	int error;

	ASSERT(pnp->pr_type == PR_STATUS);

	/*
	 * We kmem_alloc() the pstatus structure because
	 * it is so big it might blow the kernel stack.
	 */
	sp = kmem_alloc(sizeof (*sp), KM_SLEEP);
	if ((error = prlock(pnp, ZNO)) == 0) {
		/*
		 * A 32-bit process cannot get the status of a 64-bit process.
		 * The fields for the 64-bit quantities are not large enough.
		 */
		p = pnp->pr_common->prc_proc;
		if (PROCESS_NOT_32BIT(p)) {
			prunlock(pnp);
			error = EOVERFLOW;
		} else {
			prgetstatus32(pnp->pr_common->prc_proc, sp,
			    VTOZONE(PTOV(pnp)));
			prunlock(pnp);
			error = pr_uioread(sp, sizeof (*sp), uiop);
		}
	}
	kmem_free((caddr_t)sp, sizeof (*sp));
	return (error);
}

static int
pr_read_lstatus_32(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	kthread_t *t;
	lwpdir_t *ldp;
	size_t size;
	prheader32_t *php;
	lwpstatus32_t *sp;
	int error;
	int nlwp;
	int i;

	ASSERT(pnp->pr_type == PR_LSTATUS);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;
	/*
	 * A 32-bit process cannot get the status of a 64-bit process.
	 * The fields for the 64-bit quantities are not large enough.
	 */
	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		return (EOVERFLOW);
	}
	nlwp = p->p_lwpcnt;
	size = sizeof (prheader32_t) + nlwp * LSPAN32(lwpstatus32_t);

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	php = kmem_zalloc(size, KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_lwpcnt can't change while process is locked */
	ASSERT(nlwp == p->p_lwpcnt);

	php->pr_nent = nlwp;
	php->pr_entsize = LSPAN32(lwpstatus32_t);

	sp = (lwpstatus32_t *)(php + 1);
	for (ldp = p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++, ldp++) {
		if (ldp->ld_entry == NULL ||
		    (t = ldp->ld_entry->le_thread) == NULL)
			continue;
		prgetlwpstatus32(t, sp, VTOZONE(PTOV(pnp)));
		sp = (lwpstatus32_t *)((caddr_t)sp + LSPAN32(lwpstatus32_t));
	}
	prunlock(pnp);

	error = pr_uioread(php, size, uiop);
	kmem_free(php, size);
	return (error);
}

static int
pr_read_psinfo_32(prnode_t *pnp, uio_t *uiop)
{
	psinfo32_t psinfo;
	proc_t *p;
	int error = 0;

	ASSERT(pnp->pr_type == PR_PSINFO);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		error = ENOENT;
	else {
		ASSERT(p == pnp->pr_common->prc_proc);
		prgetpsinfo32(p, &psinfo);
		prunlock(pnp);
		error = pr_uioread(&psinfo, sizeof (psinfo), uiop);
	}
	return (error);
}

static int
pr_read_lpsinfo_32(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	kthread_t *t;
	lwpdir_t *ldp;
	lwpent_t *lep;
	size_t size;
	prheader32_t *php;
	lwpsinfo32_t *sp;
	int error;
	int nlwp;
	int i;

	ASSERT(pnp->pr_type == PR_LPSINFO);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	ASSERT(p == pnp->pr_common->prc_proc);
	if ((nlwp = p->p_lwpcnt + p->p_zombcnt) == 0) {
		prunlock(pnp);
		return (ENOENT);
	}
	size = sizeof (prheader32_t) + nlwp * LSPAN32(lwpsinfo32_t);

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	php = kmem_zalloc(size, KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_lwpcnt can't change while process is locked */
	ASSERT(nlwp == p->p_lwpcnt + p->p_zombcnt);

	php->pr_nent = nlwp;
	php->pr_entsize = LSPAN32(lwpsinfo32_t);

	sp = (lwpsinfo32_t *)(php + 1);
	for (ldp = p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++, ldp++) {
		if ((lep = ldp->ld_entry) == NULL)
			continue;
		if ((t = lep->le_thread) != NULL)
			prgetlwpsinfo32(t, sp);
		else {
			bzero(sp, sizeof (*sp));
			sp->pr_lwpid = lep->le_lwpid;
			sp->pr_state = SZOMB;
			sp->pr_sname = 'Z';
			sp->pr_start.tv_sec = (time32_t)lep->le_start;
		}
		sp = (lwpsinfo32_t *)((caddr_t)sp + LSPAN32(lwpsinfo32_t));
	}
	prunlock(pnp);

	error = pr_uioread(php, size, uiop);
	kmem_free(php, size);
	return (error);
}

static int
pr_read_map_common_32(prnode_t *pnp, uio_t *uiop, prnodetype_t type)
{
	proc_t *p;
	struct as *as;
	list_t	iolhead;
	int error;

readmap32_common:
	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	as = p->p_as;

	if ((p->p_flag & SSYS) || as == &kas) {
		prunlock(pnp);
		return (0);
	}

	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		return (EOVERFLOW);
	}

	if (!AS_LOCK_TRYENTER(as, &as->a_lock, RW_WRITER)) {
		prunlock(pnp);
		delay(1);
		goto readmap32_common;
	}
	mutex_exit(&p->p_lock);

	switch (type) {
	case PR_XMAP:
		error = prgetxmap32(p, &iolhead);
		break;
	case PR_RMAP:
		error = prgetmap32(p, 1, &iolhead);
		break;
	case PR_MAP:
		error = prgetmap32(p, 0, &iolhead);
		break;
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	mutex_enter(&p->p_lock);
	prunlock(pnp);

	error = pr_iol_uiomove_and_free(&iolhead, uiop, error);

	return (error);
}

static int
pr_read_map_32(prnode_t *pnp, uio_t *uiop)
{
	ASSERT(pnp->pr_type == PR_MAP);
	return (pr_read_map_common_32(pnp, uiop, pnp->pr_type));
}

static int
pr_read_rmap_32(prnode_t *pnp, uio_t *uiop)
{
	ASSERT(pnp->pr_type == PR_RMAP);
	return (pr_read_map_common_32(pnp, uiop, pnp->pr_type));
}

static int
pr_read_xmap_32(prnode_t *pnp, uio_t *uiop)
{
	ASSERT(pnp->pr_type == PR_XMAP);
	return (pr_read_map_common_32(pnp, uiop, pnp->pr_type));
}

static int
pr_read_sigact_32(prnode_t *pnp, uio_t *uiop)
{
	int nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
	proc_t *p;
	struct sigaction32 *sap;
	int sig;
	int error;
	user_t *up;

	ASSERT(pnp->pr_type == PR_SIGACT);

	/*
	 * We kmem_alloc() the sigaction32 array because
	 * it is so big it might blow the kernel stack.
	 */
	sap = kmem_alloc((nsig-1) * sizeof (struct sigaction32), KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;
	p = pnp->pr_common->prc_proc;

	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		error = EOVERFLOW;
		goto out;
	}

	if (uiop->uio_offset >= (nsig-1) * sizeof (struct sigaction32)) {
		prunlock(pnp);
		goto out;
	}

	up = PTOU(p);
	for (sig = 1; sig < nsig; sig++)
		prgetaction32(p, up, sig, &sap[sig-1]);
	prunlock(pnp);

	error = pr_uioread(sap, (nsig - 1) * sizeof (struct sigaction32), uiop);
out:
	kmem_free(sap, (nsig-1) * sizeof (struct sigaction32));
	return (error);
}

static int
pr_read_auxv_32(prnode_t *pnp, uio_t *uiop)
{
	auxv32_t auxv[__KERN_NAUXV_IMPL];
	proc_t *p;
	user_t *up;
	int error;
	int i;

	ASSERT(pnp->pr_type == PR_AUXV);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;

	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		return (EOVERFLOW);
	}

	if (uiop->uio_offset >= sizeof (auxv)) {
		prunlock(pnp);
		return (0);
	}

	up = PTOU(p);
	for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
		auxv[i].a_type = (int32_t)up->u_auxv[i].a_type;
		auxv[i].a_un.a_val = (int32_t)up->u_auxv[i].a_un.a_val;
	}
	prunlock(pnp);

	return (pr_uioread(auxv, sizeof (auxv), uiop));
}

static int
pr_read_usage_32(prnode_t *pnp, uio_t *uiop)
{
	prhusage_t *pup;
	prusage32_t *upup;
	proc_t *p;
	kthread_t *t;
	int error;

	ASSERT(pnp->pr_type == PR_USAGE);

	/* allocate now, before locking the process */
	pup = kmem_zalloc(sizeof (*pup), KM_SLEEP);
	upup = kmem_alloc(sizeof (*upup), KM_SLEEP);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		error = ENOENT;
		goto out;
	}
	ASSERT(p == pnp->pr_common->prc_proc);

	if (uiop->uio_offset >= sizeof (prusage32_t)) {
		prunlock(pnp);
		error = 0;
		goto out;
	}

	pup->pr_tstamp = gethrtime();

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
	    !(pnp->pr_pcommon->prc_flags & PRC_DESTROY)) {
		do {
			if (t->t_proc_flag & TP_LWPEXIT)
				continue;
			pup->pr_count++;
			praddusage(t, pup);
		} while ((t = t->t_forw) != p->p_tlist);
	}

	prunlock(pnp);

	prcvtusage32(pup, upup);

	error = pr_uioread(upup, sizeof (prusage32_t), uiop);
out:
	kmem_free(pup, sizeof (*pup));
	kmem_free(upup, sizeof (*upup));
	return (error);
}

static int
pr_read_lusage_32(prnode_t *pnp, uio_t *uiop)
{
	int nlwp;
	prhusage_t *pup;
	prheader32_t *php;
	prusage32_t *upup;
	size_t size;
	hrtime_t curtime;
	proc_t *p;
	kthread_t *t;
	lwpdir_t *ldp;
	int error;
	int i;

	ASSERT(pnp->pr_type == PR_LUSAGE);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	ASSERT(p == pnp->pr_common->prc_proc);
	if ((nlwp = p->p_lwpcnt) == 0) {
		prunlock(pnp);
		return (ENOENT);
	}

	size = sizeof (prheader32_t) + (nlwp + 1) * LSPAN32(prusage32_t);
	if (uiop->uio_offset >= size) {
		prunlock(pnp);
		return (0);
	}

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	pup = kmem_zalloc(size + sizeof (prhusage_t), KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_lwpcnt can't change while process is locked */
	ASSERT(nlwp == p->p_lwpcnt);

	php = (prheader32_t *)(pup + 1);
	upup = (prusage32_t *)(php + 1);

	php->pr_nent = nlwp + 1;
	php->pr_entsize = LSPAN32(prusage32_t);

	curtime = gethrtime();

	/*
	 * First the summation over defunct lwps.
	 */
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
	for (ldp = p->p_lwpdir, i = 0; i < p->p_lwpdir_sz; i++, ldp++) {
		if (ldp->ld_entry == NULL ||
		    (t = ldp->ld_entry->le_thread) == NULL)
			continue;
		ASSERT(!(t->t_proc_flag & TP_LWPEXIT));
		ASSERT(nlwp > 0);
		--nlwp;
		upup = (prusage32_t *)
		    ((caddr_t)upup + LSPAN32(prusage32_t));
		prgetusage(t, pup);
		prcvtusage32(pup, upup);
	}
	ASSERT(nlwp == 0);

	prunlock(pnp);

	error = pr_uioread(php, size, uiop);
	kmem_free(pup, size + sizeof (prhusage_t));
	return (error);
}

static int
pr_read_pagedata_32(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	int error;

	ASSERT(pnp->pr_type == PR_PAGEDATA);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	if ((p->p_flag & SSYS) || p->p_as == &kas) {
		prunlock(pnp);
		return (0);
	}

	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		return (EOVERFLOW);
	}

	mutex_exit(&p->p_lock);
	error = prpdread32(p, pnp->pr_hatid, uiop);
	mutex_enter(&p->p_lock);

	prunlock(pnp);
	return (error);
}

static int
pr_read_opagedata_32(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	struct as *as;
	int error;

	ASSERT(pnp->pr_type == PR_OPAGEDATA);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	as = p->p_as;

	if ((p->p_flag & SSYS) || as == &kas) {
		prunlock(pnp);
		return (0);
	}

	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		return (EOVERFLOW);
	}

	mutex_exit(&p->p_lock);
	error = oprpdread32(as, pnp->pr_hatid, uiop);
	mutex_enter(&p->p_lock);

	prunlock(pnp);
	return (error);
}

static int
pr_read_watch_32(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	int error;
	prwatch32_t *Bpwp;
	size_t size;
	prwatch32_t *pwp;
	int nwarea;
	struct watched_area *pwarea;

	ASSERT(pnp->pr_type == PR_WATCH);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	p = pnp->pr_common->prc_proc;
	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		return (EOVERFLOW);
	}
	nwarea = avl_numnodes(&p->p_warea);
	size = nwarea * sizeof (prwatch32_t);
	if (uiop->uio_offset >= size) {
		prunlock(pnp);
		return (0);
	}

	/* drop p->p_lock to do kmem_alloc(KM_SLEEP) */
	mutex_exit(&p->p_lock);
	Bpwp = pwp = kmem_zalloc(size, KM_SLEEP);
	mutex_enter(&p->p_lock);
	/* p->p_nwarea can't change while process is locked */
	ASSERT(nwarea == avl_numnodes(&p->p_warea));

	/* gather the watched areas */
	for (pwarea = avl_first(&p->p_warea); pwarea != NULL;
	    pwarea = AVL_NEXT(&p->p_warea, pwarea), pwp++) {
		pwp->pr_vaddr = (caddr32_t)(uintptr_t)pwarea->wa_vaddr;
		pwp->pr_size = (size32_t)(pwarea->wa_eaddr - pwarea->wa_vaddr);
		pwp->pr_wflags = (int)pwarea->wa_flags;
	}

	prunlock(pnp);

	error = pr_uioread(Bpwp, size, uiop);
	kmem_free(Bpwp, size);
	return (error);
}

static int
pr_read_lwpstatus_32(prnode_t *pnp, uio_t *uiop)
{
	lwpstatus32_t *sp;
	proc_t *p;
	int error;

	ASSERT(pnp->pr_type == PR_LWPSTATUS);

	/*
	 * We kmem_alloc() the lwpstatus structure because
	 * it is so big it might blow the kernel stack.
	 */
	sp = kmem_alloc(sizeof (*sp), KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;

	/*
	 * A 32-bit process cannot get the status of a 64-bit process.
	 * The fields for the 64-bit quantities are not large enough.
	 */
	p = pnp->pr_common->prc_proc;
	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		error = EOVERFLOW;
		goto out;
	}

	if (uiop->uio_offset >= sizeof (*sp)) {
		prunlock(pnp);
		goto out;
	}

	prgetlwpstatus32(pnp->pr_common->prc_thread, sp, VTOZONE(PTOV(pnp)));
	prunlock(pnp);

	error = pr_uioread(sp, sizeof (*sp), uiop);
out:
	kmem_free(sp, sizeof (*sp));
	return (error);
}

static int
pr_read_lwpsinfo_32(prnode_t *pnp, uio_t *uiop)
{
	lwpsinfo32_t lwpsinfo;
	proc_t *p;
	kthread_t *t;
	lwpent_t *lep;

	ASSERT(pnp->pr_type == PR_LWPSINFO);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	ASSERT(p == pnp->pr_common->prc_proc);
	if (pnp->pr_common->prc_tslot == -1) {
		prunlock(pnp);
		return (ENOENT);
	}

	if (uiop->uio_offset >= sizeof (lwpsinfo)) {
		prunlock(pnp);
		return (0);
	}

	if ((t = pnp->pr_common->prc_thread) != NULL)
		prgetlwpsinfo32(t, &lwpsinfo);
	else {
		lep = p->p_lwpdir[pnp->pr_common->prc_tslot].ld_entry;
		bzero(&lwpsinfo, sizeof (lwpsinfo));
		lwpsinfo.pr_lwpid = lep->le_lwpid;
		lwpsinfo.pr_state = SZOMB;
		lwpsinfo.pr_sname = 'Z';
		lwpsinfo.pr_start.tv_sec = (time32_t)lep->le_start;
	}
	prunlock(pnp);

	return (pr_uioread(&lwpsinfo, sizeof (lwpsinfo), uiop));
}

static int
pr_read_lwpusage_32(prnode_t *pnp, uio_t *uiop)
{
	prhusage_t *pup;
	prusage32_t *upup;
	proc_t *p;
	int error;

	ASSERT(pnp->pr_type == PR_LWPUSAGE);

	/* allocate now, before locking the process */
	pup = kmem_zalloc(sizeof (*pup), KM_SLEEP);
	upup = kmem_alloc(sizeof (*upup), KM_SLEEP);

	/*
	 * We don't want the full treatment of prlock(pnp) here.
	 * This file is world-readable and never goes invalid.
	 * It doesn't matter if we are in the middle of an exec().
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		error = ENOENT;
		goto out;
	}
	ASSERT(p == pnp->pr_common->prc_proc);
	if (pnp->pr_common->prc_thread == NULL) {
		prunlock(pnp);
		error = ENOENT;
		goto out;
	}
	if (uiop->uio_offset >= sizeof (prusage32_t)) {
		prunlock(pnp);
		error = 0;
		goto out;
	}

	pup->pr_tstamp = gethrtime();
	prgetusage(pnp->pr_common->prc_thread, pup);

	prunlock(pnp);

	prcvtusage32(pup, upup);

	error = pr_uioread(upup, sizeof (prusage32_t), uiop);
out:
	kmem_free(pup, sizeof (*pup));
	kmem_free(upup, sizeof (*upup));
	return (error);
}

static int
pr_read_spymaster_32(prnode_t *pnp, uio_t *uiop)
{
	psinfo32_t psinfo;
	int error;
	klwp_t *lwp;

	ASSERT(pnp->pr_type == PR_SPYMASTER);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	lwp = pnp->pr_common->prc_thread->t_lwp;

	if (lwp->lwp_spymaster == NULL) {
		prunlock(pnp);
		return (0);
	}

	psinfo_kto32(lwp->lwp_spymaster, &psinfo);
	prunlock(pnp);

	return (pr_uioread(&psinfo, sizeof (psinfo), uiop));
}

#if defined(__sparc)
static int
pr_read_gwindows_32(prnode_t *pnp, uio_t *uiop)
{
	proc_t *p;
	kthread_t *t;
	gwindows32_t *gwp;
	int error;
	size_t size;

	ASSERT(pnp->pr_type == PR_GWINDOWS);

	gwp = kmem_zalloc(sizeof (gwindows32_t), KM_SLEEP);

	if ((error = prlock(pnp, ZNO)) != 0)
		goto out;

	p = pnp->pr_common->prc_proc;
	t = pnp->pr_common->prc_thread;

	if (PROCESS_NOT_32BIT(p)) {
		prunlock(pnp);
		error = EOVERFLOW;
		goto out;
	}

	/*
	 * Drop p->p_lock while touching the stack.
	 * The P_PR_LOCK flag prevents the lwp from
	 * disappearing while we do this.
	 */
	mutex_exit(&p->p_lock);
	if ((size = prnwindows(ttolwp(t))) != 0)
		size = sizeof (gwindows32_t) -
		    (SPARC_MAXREGWINDOW - size) * sizeof (struct rwindow32);
	if (uiop->uio_offset >= size) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		goto out;
	}
	prgetwindows32(ttolwp(t), gwp);
	mutex_enter(&p->p_lock);
	prunlock(pnp);

	error = pr_uioread(gwp, size, uiop);
out:
	kmem_free(gwp, sizeof (gwindows32_t));
	return (error);
}
#endif	/* __sparc */

#endif	/* _SYSCALL32_IMPL */

/* ARGSUSED */
static int
prread(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr, caller_context_t *ct)
{
	prnode_t *pnp = VTOP(vp);

	ASSERT(pnp->pr_type < PR_NFILES);

#ifdef _SYSCALL32_IMPL
	/*
	 * What is read from the /proc files depends on the data
	 * model of the caller.  An LP64 process will see LP64
	 * data.  An ILP32 process will see ILP32 data.
	 */
	if (curproc->p_model == DATAMODEL_LP64)
		return (pr_read_function[pnp->pr_type](pnp, uiop));
	else
		return (pr_read_function_32[pnp->pr_type](pnp, uiop));
#else
	return (pr_read_function[pnp->pr_type](pnp, uiop));
#endif
}

/*
 * We make pr_write_psinfo_fname() somewhat simpler by asserting at compile
 * time that PRFNSZ has the same definition as MAXCOMLEN.
 */
#if PRFNSZ != MAXCOMLEN
#error PRFNSZ/MAXCOMLEN mismatch
#endif

static int
pr_write_psinfo_fname(prnode_t *pnp, uio_t *uiop)
{
	char fname[PRFNSZ];
	int offset = offsetof(psinfo_t, pr_fname), error;

#ifdef _SYSCALL32_IMPL
	if (curproc->p_model != DATAMODEL_LP64)
		offset = offsetof(psinfo32_t, pr_fname);
#endif

	/*
	 * If this isn't a write to pr_fname (or if the size doesn't match
	 * PRFNSZ) return.
	 */
	if (uiop->uio_offset != offset || uiop->uio_resid != PRFNSZ)
		return (0);

	if ((error = uiomove(fname, PRFNSZ, UIO_WRITE, uiop)) != 0)
		return (error);

	fname[PRFNSZ - 1] = '\0';

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	bcopy(fname, pnp->pr_common->prc_proc->p_user.u_comm, PRFNSZ);

	prunlock(pnp);

	return (0);
}

/*
 * We make pr_write_psinfo_psargs() somewhat simpler by asserting at compile
 * time that PRARGSZ has the same definition as PSARGSZ.
 */
#if PRARGSZ != PSARGSZ
#error PRARGSZ/PSARGSZ mismatch
#endif

static int
pr_write_psinfo_psargs(prnode_t *pnp, uio_t *uiop)
{
	char psargs[PRARGSZ];
	int offset = offsetof(psinfo_t, pr_psargs), error;

#ifdef _SYSCALL32_IMPL
	if (curproc->p_model != DATAMODEL_LP64)
		offset = offsetof(psinfo32_t, pr_psargs);
#endif

	/*
	 * If this isn't a write to pr_psargs (or if the size doesn't match
	 * PRARGSZ) return.
	 */
	if (uiop->uio_offset != offset || uiop->uio_resid != PRARGSZ)
		return (0);

	if ((error = uiomove(psargs, PRARGSZ, UIO_WRITE, uiop)) != 0)
		return (error);

	psargs[PRARGSZ - 1] = '\0';

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);

	bcopy(psargs, pnp->pr_common->prc_proc->p_user.u_psargs, PRARGSZ);

	prunlock(pnp);

	return (0);
}

int
pr_write_psinfo(prnode_t *pnp, uio_t *uiop)
{
	int error;

	if ((error = pr_write_psinfo_fname(pnp, uiop)) != 0)
		return (error);

	if ((error = pr_write_psinfo_psargs(pnp, uiop)) != 0)
		return (error);

	return (0);
}


/* ARGSUSED */
static int
prwrite(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr, caller_context_t *ct)
{
	prnode_t *pnp = VTOP(vp);
	int old = 0;
	int error;
	ssize_t resid;

	ASSERT(pnp->pr_type < PR_NFILES);

	/*
	 * Only a handful of /proc files are writable, enumerate them here.
	 */
	switch (pnp->pr_type) {
	case PR_PIDDIR:		/* directory write()s: visceral revulsion. */
		ASSERT(pnp->pr_pidfile != NULL);
		/* use the underlying PR_PIDFILE to write the process */
		vp = pnp->pr_pidfile;
		pnp = VTOP(vp);
		ASSERT(pnp->pr_type == PR_PIDFILE);
		/* FALLTHROUGH */
	case PR_PIDFILE:
	case PR_LWPIDFILE:
		old = 1;
		/* FALLTHROUGH */
	case PR_AS:
		if ((error = prlock(pnp, ZNO)) == 0) {
			proc_t *p = pnp->pr_common->prc_proc;
			struct as *as = p->p_as;

			if ((p->p_flag & SSYS) || as == &kas) {
				/*
				 * /proc I/O cannot be done to a system process.
				 */
				error = EIO;
#ifdef _SYSCALL32_IMPL
			} else if (curproc->p_model == DATAMODEL_ILP32 &&
			    PROCESS_NOT_32BIT(p)) {
				error = EOVERFLOW;
#endif
			} else {
				/*
				 * See comments above (pr_read_pidfile)
				 * about this locking dance.
				 */
				mutex_exit(&p->p_lock);
				error = prusrio(p, UIO_WRITE, uiop, old);
				mutex_enter(&p->p_lock);
			}
			prunlock(pnp);
		}
		return (error);

	case PR_CTL:
	case PR_LWPCTL:
		resid = uiop->uio_resid;
		/*
		 * Perform the action on the control file
		 * by passing curthreads credentials
		 * and not target process's credentials.
		 */
#ifdef _SYSCALL32_IMPL
		if (curproc->p_model == DATAMODEL_ILP32)
			error = prwritectl32(vp, uiop, CRED());
		else
			error = prwritectl(vp, uiop, CRED());
#else
		error = prwritectl(vp, uiop, CRED());
#endif
		/*
		 * This hack makes sure that the EINTR is passed
		 * all the way back to the caller's write() call.
		 */
		if (error == EINTR)
			uiop->uio_resid = resid;
		return (error);

	case PR_PSINFO:
		return (pr_write_psinfo(pnp, uiop));

	default:
		return ((vp->v_type == VDIR)? EISDIR : EBADF);
	}
	/* NOTREACHED */
}

static int
prgetattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	prnode_t *pnp = VTOP(vp);
	prnodetype_t type = pnp->pr_type;
	prcommon_t *pcp;
	proc_t *p;
	struct as *as;
	int error;
	vnode_t *rvp;
	timestruc_t now;
	extern uint_t nproc;
	int ngroups;
	int nsig;

	/*
	 * This ugly bit of code allows us to keep both versions of this
	 * function from the same source.
	 */
#ifdef _LP64
	int iam32bit = (curproc->p_model == DATAMODEL_ILP32);
#define	PR_OBJSIZE(obj32, obj64)	\
	(iam32bit ? sizeof (obj32) : sizeof (obj64))
#define	PR_OBJSPAN(obj32, obj64)	\
	(iam32bit ? LSPAN32(obj32) : LSPAN(obj64))
#else
#define	PR_OBJSIZE(obj32, obj64)	\
	(sizeof (obj64))
#define	PR_OBJSPAN(obj32, obj64)	\
	(LSPAN(obj64))
#endif

	/*
	 * Return all the attributes.  Should be refined
	 * so that it returns only those asked for.
	 * Most of this is complete fakery anyway.
	 */

	/*
	 * For files in the /proc/<pid>/object directory,
	 * return the attributes of the underlying object.
	 * For files in the /proc/<pid>/fd directory,
	 * return the attributes of the underlying file, but
	 * make it look inaccessible if it is not a regular file.
	 * Make directories look like symlinks.
	 */
	switch (type) {
	case PR_CURDIR:
	case PR_ROOTDIR:
		if (!(flags & ATTR_REAL))
			break;
		/* restrict full knowledge of the attributes to owner or root */
		if ((error = praccess(vp, 0, 0, cr, ct)) != 0)
			return (error);
		/* FALLTHROUGH */
	case PR_OBJECT:
	case PR_FD:
		rvp = pnp->pr_realvp;
		error = VOP_GETATTR(rvp, vap, flags, cr, ct);
		if (error)
			return (error);
		if (type == PR_FD) {
			if (rvp->v_type != VREG && rvp->v_type != VDIR)
				vap->va_mode = 0;
			else
				vap->va_mode &= pnp->pr_mode;
		}
		if (type == PR_OBJECT)
			vap->va_mode &= 07555;
		if (rvp->v_type == VDIR && !(flags & ATTR_REAL)) {
			vap->va_type = VLNK;
			vap->va_size = 0;
			vap->va_nlink = 1;
		}
		return (0);
	default:
		break;
	}

	bzero(vap, sizeof (*vap));
	/*
	 * Large Files: Internally proc now uses VPROC to indicate
	 * a proc file. Since we have been returning VREG through
	 * VOP_GETATTR() until now, we continue to do this so as
	 * not to break apps depending on this return value.
	 */
	vap->va_type = (vp->v_type == VPROC) ? VREG : vp->v_type;
	vap->va_mode = pnp->pr_mode;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
	vap->va_blksize = DEV_BSIZE;
	vap->va_rdev = 0;
	vap->va_seq = 0;

	if (type == PR_PROCDIR) {
		vap->va_uid = 0;
		vap->va_gid = 0;
		vap->va_nlink = nproc + 2;
		vap->va_nodeid = (ino64_t)PRROOTINO;
		gethrestime(&now);
		vap->va_atime = vap->va_mtime = vap->va_ctime = now;
		vap->va_size = (v.v_proc + 2) * PRSDSIZE;
		vap->va_nblocks = btod(vap->va_size);
		return (0);
	}

	/*
	 * /proc/<pid>/self is a symbolic link, and has no prcommon member
	 */
	if (type == PR_SELF) {
		vap->va_uid = crgetruid(CRED());
		vap->va_gid = crgetrgid(CRED());
		vap->va_nodeid = (ino64_t)PR_SELF;
		gethrestime(&now);
		vap->va_atime = vap->va_mtime = vap->va_ctime = now;
		vap->va_nlink = 1;
		vap->va_type = VLNK;
		vap->va_size = 0;
		return (0);
	}

	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	pcp = pnp->pr_common;

	mutex_enter(&p->p_crlock);
	vap->va_uid = crgetruid(p->p_cred);
	vap->va_gid = crgetrgid(p->p_cred);
	mutex_exit(&p->p_crlock);

	vap->va_nlink = 1;
	vap->va_nodeid = pnp->pr_ino? pnp->pr_ino :
	    pmkino(pcp->prc_tslot, pcp->prc_slot, pnp->pr_type);
	if ((pcp->prc_flags & PRC_LWP) && pcp->prc_tslot != -1) {
		vap->va_atime.tv_sec = vap->va_mtime.tv_sec =
		    vap->va_ctime.tv_sec =
		    p->p_lwpdir[pcp->prc_tslot].ld_entry->le_start;
		vap->va_atime.tv_nsec = vap->va_mtime.tv_nsec =
		    vap->va_ctime.tv_nsec = 0;
	} else {
		user_t *up = PTOU(p);
		vap->va_atime.tv_sec = vap->va_mtime.tv_sec =
		    vap->va_ctime.tv_sec = up->u_start.tv_sec;
		vap->va_atime.tv_nsec = vap->va_mtime.tv_nsec =
		    vap->va_ctime.tv_nsec = up->u_start.tv_nsec;
	}

	switch (type) {
	case PR_PIDDIR:
		/* va_nlink: count 'lwp', 'object' and 'fd' directory links */
		vap->va_nlink = 5;
		vap->va_size = sizeof (piddir);
		break;
	case PR_OBJECTDIR:
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas)
			vap->va_size = 2 * PRSDSIZE;
		else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
			if (as->a_updatedir)
				rebuild_objdir(as);
			vap->va_size = (as->a_sizedir + 2) * PRSDSIZE;
			AS_LOCK_EXIT(as, &as->a_lock);
			mutex_enter(&p->p_lock);
		}
		vap->va_nlink = 2;
		break;
	case PR_PATHDIR:
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas)
			vap->va_size = (P_FINFO(p)->fi_nfiles + 4) * PRSDSIZE;
		else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
			if (as->a_updatedir)
				rebuild_objdir(as);
			vap->va_size = (as->a_sizedir + 4 +
			    P_FINFO(p)->fi_nfiles) * PRSDSIZE;
			AS_LOCK_EXIT(as, &as->a_lock);
			mutex_enter(&p->p_lock);
		}
		vap->va_nlink = 2;
		break;
	case PR_PATH:
	case PR_CURDIR:
	case PR_ROOTDIR:
	case PR_CT:
		vap->va_type = VLNK;
		vap->va_size = 0;
		break;
	case PR_FDDIR:
		vap->va_nlink = 2;
		vap->va_size = (P_FINFO(p)->fi_nfiles + 2) * PRSDSIZE;
		break;
	case PR_LWPDIR:
		/*
		 * va_nlink: count each lwp as a directory link.
		 * va_size: size of p_lwpdir + 2
		 */
		vap->va_nlink = p->p_lwpcnt + p->p_zombcnt + 2;
		vap->va_size = (p->p_lwpdir_sz + 2) * PRSDSIZE;
		break;
	case PR_LWPIDDIR:
		vap->va_nlink = 2;
		vap->va_size = sizeof (lwpiddir);
		break;
	case PR_CTDIR:
		vap->va_nlink = 2;
		vap->va_size = (avl_numnodes(&p->p_ct_held) + 2) * PRSDSIZE;
		break;
	case PR_TMPLDIR:
		vap->va_nlink = 2;
		vap->va_size = (ct_ntypes + 2) * PRSDSIZE;
		break;
	case PR_AS:
	case PR_PIDFILE:
	case PR_LWPIDFILE:
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas)
			vap->va_size = 0;
		else
			vap->va_size = as->a_resvsize;
		break;
	case PR_STATUS:
		vap->va_size = PR_OBJSIZE(pstatus32_t, pstatus_t);
		break;
	case PR_LSTATUS:
		vap->va_size = PR_OBJSIZE(prheader32_t, prheader_t) +
		    p->p_lwpcnt * PR_OBJSPAN(lwpstatus32_t, lwpstatus_t);
		break;
	case PR_PSINFO:
		vap->va_size = PR_OBJSIZE(psinfo32_t, psinfo_t);
		break;
	case PR_LPSINFO:
		vap->va_size = PR_OBJSIZE(prheader32_t, prheader_t) +
		    (p->p_lwpcnt + p->p_zombcnt) *
		    PR_OBJSPAN(lwpsinfo32_t, lwpsinfo_t);
		break;
	case PR_MAP:
	case PR_RMAP:
	case PR_XMAP:
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas)
			vap->va_size = 0;
		else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
			if (type == PR_MAP)
				vap->va_mtime = as->a_updatetime;
			if (type == PR_XMAP)
				vap->va_size = prnsegs(as, 0) *
				    PR_OBJSIZE(prxmap32_t, prxmap_t);
			else
				vap->va_size = prnsegs(as, type == PR_RMAP) *
				    PR_OBJSIZE(prmap32_t, prmap_t);
			AS_LOCK_EXIT(as, &as->a_lock);
			mutex_enter(&p->p_lock);
		}
		break;
	case PR_CRED:
		mutex_enter(&p->p_crlock);
		vap->va_size = sizeof (prcred_t);
		ngroups = crgetngroups(p->p_cred);
		if (ngroups > 1)
			vap->va_size += (ngroups - 1) * sizeof (gid_t);
		mutex_exit(&p->p_crlock);
		break;
	case PR_PRIV:
		vap->va_size = prgetprivsize();
		break;
	case PR_SIGACT:
		nsig = PROC_IS_BRANDED(curproc)? BROP(curproc)->b_nsig : NSIG;
		vap->va_size = (nsig-1) *
		    PR_OBJSIZE(struct sigaction32, struct sigaction);
		break;
	case PR_AUXV:
		vap->va_size = __KERN_NAUXV_IMPL * PR_OBJSIZE(auxv32_t, auxv_t);
		break;
#if defined(__x86)
	case PR_LDT:
		mutex_exit(&p->p_lock);
		mutex_enter(&p->p_ldtlock);
		vap->va_size = prnldt(p) * sizeof (struct ssd);
		mutex_exit(&p->p_ldtlock);
		mutex_enter(&p->p_lock);
		break;
#endif
	case PR_USAGE:
		vap->va_size = PR_OBJSIZE(prusage32_t, prusage_t);
		break;
	case PR_LUSAGE:
		vap->va_size = PR_OBJSIZE(prheader32_t, prheader_t) +
		    (p->p_lwpcnt + 1) * PR_OBJSPAN(prusage32_t, prusage_t);
		break;
	case PR_PAGEDATA:
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas)
			vap->va_size = 0;
		else {
			/*
			 * We can drop p->p_lock before grabbing the
			 * address space lock because p->p_as will not
			 * change while the process is marked P_PR_LOCK.
			 */
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
#ifdef _LP64
			vap->va_size = iam32bit?
			    prpdsize32(as) : prpdsize(as);
#else
			vap->va_size = prpdsize(as);
#endif
			AS_LOCK_EXIT(as, &as->a_lock);
			mutex_enter(&p->p_lock);
		}
		break;
	case PR_OPAGEDATA:
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas)
			vap->va_size = 0;
		else {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
#ifdef _LP64
			vap->va_size = iam32bit?
			    oprpdsize32(as) : oprpdsize(as);
#else
			vap->va_size = oprpdsize(as);
#endif
			AS_LOCK_EXIT(as, &as->a_lock);
			mutex_enter(&p->p_lock);
		}
		break;
	case PR_WATCH:
		vap->va_size = avl_numnodes(&p->p_warea) *
		    PR_OBJSIZE(prwatch32_t, prwatch_t);
		break;
	case PR_LWPSTATUS:
		vap->va_size = PR_OBJSIZE(lwpstatus32_t, lwpstatus_t);
		break;
	case PR_LWPSINFO:
		vap->va_size = PR_OBJSIZE(lwpsinfo32_t, lwpsinfo_t);
		break;
	case PR_LWPUSAGE:
		vap->va_size = PR_OBJSIZE(prusage32_t, prusage_t);
		break;
	case PR_XREGS:
		if (prhasx(p))
			vap->va_size = prgetprxregsize(p);
		else
			vap->va_size = 0;
		break;
	case PR_SPYMASTER:
		if (pnp->pr_common->prc_thread->t_lwp->lwp_spymaster != NULL) {
			vap->va_size = PR_OBJSIZE(psinfo32_t, psinfo_t);
		} else {
			vap->va_size = 0;
		}
		break;
#if defined(__sparc)
	case PR_GWINDOWS:
	{
		kthread_t *t;
		int n;

		/*
		 * If there is no lwp then just make the size zero.
		 * This can happen if the lwp exits between the VOP_LOOKUP()
		 * of the /proc/<pid>/lwp/<lwpid>/gwindows file and the
		 * VOP_GETATTR() of the resulting vnode.
		 */
		if ((t = pcp->prc_thread) == NULL) {
			vap->va_size = 0;
			break;
		}
		/*
		 * Drop p->p_lock while touching the stack.
		 * The P_PR_LOCK flag prevents the lwp from
		 * disappearing while we do this.
		 */
		mutex_exit(&p->p_lock);
		if ((n = prnwindows(ttolwp(t))) == 0)
			vap->va_size = 0;
		else
			vap->va_size = PR_OBJSIZE(gwindows32_t, gwindows_t) -
			    (SPARC_MAXREGWINDOW - n) *
			    PR_OBJSIZE(struct rwindow32, struct rwindow);
		mutex_enter(&p->p_lock);
		break;
	}
	case PR_ASRS:
#ifdef _LP64
		if (p->p_model == DATAMODEL_LP64)
			vap->va_size = sizeof (asrset_t);
		else
#endif
			vap->va_size = 0;
		break;
#endif
	case PR_CTL:
	case PR_LWPCTL:
	default:
		vap->va_size = 0;
		break;
	}

	prunlock(pnp);
	vap->va_nblocks = (fsblkcnt64_t)btod(vap->va_size);
	return (0);
}

static int
praccess(vnode_t *vp, int mode, int flags, cred_t *cr, caller_context_t *ct)
{
	prnode_t *pnp = VTOP(vp);
	prnodetype_t type = pnp->pr_type;
	int vmode;
	vtype_t vtype;
	proc_t *p;
	int error = 0;
	vnode_t *rvp;
	vnode_t *xvp;

	if ((mode & VWRITE) && vn_is_readonly(vp))
		return (EROFS);

	switch (type) {
	case PR_PROCDIR:
		break;

	case PR_OBJECT:
	case PR_FD:
		/*
		 * Disallow write access to the underlying objects.
		 * Disallow access to underlying non-regular-file fds.
		 * Disallow access to fds with other than existing open modes.
		 */
		rvp = pnp->pr_realvp;
		vtype = rvp->v_type;
		vmode = pnp->pr_mode;
		if ((type == PR_OBJECT && (mode & VWRITE)) ||
		    (type == PR_FD && vtype != VREG && vtype != VDIR) ||
		    (type == PR_FD && (vmode & mode) != mode &&
		    secpolicy_proc_access(cr) != 0))
			return (EACCES);
		return (VOP_ACCESS(rvp, mode, flags, cr, ct));

	case PR_PSINFO:		/* these files can be read by anyone */
	case PR_LPSINFO:
	case PR_LWPSINFO:
	case PR_LWPDIR:
	case PR_LWPIDDIR:
	case PR_USAGE:
	case PR_LUSAGE:
	case PR_LWPUSAGE:
		p = pr_p_lock(pnp);
		mutex_exit(&pr_pidlock);
		if (p == NULL)
			return (ENOENT);
		prunlock(pnp);
		break;

	default:
		/*
		 * Except for the world-readable files above,
		 * only /proc/pid exists if the process is a zombie.
		 */
		if ((error = prlock(pnp,
		    (type == PR_PIDDIR)? ZYES : ZNO)) != 0)
			return (error);
		p = pnp->pr_common->prc_proc;
		if (p != curproc)
			error = priv_proc_cred_perm(cr, p, NULL, mode);

		if (error != 0 || p == curproc || (p->p_flag & SSYS) ||
		    p->p_as == &kas || (xvp = p->p_exec) == NULL) {
			prunlock(pnp);
		} else {
			/*
			 * Determine if the process's executable is readable.
			 * We have to drop p->p_lock before the secpolicy
			 * and VOP operation.
			 */
			VN_HOLD(xvp);
			prunlock(pnp);
			if (secpolicy_proc_access(cr) != 0)
				error = VOP_ACCESS(xvp, VREAD, 0, cr, ct);
			VN_RELE(xvp);
		}
		if (error)
			return (error);
		break;
	}

	if (type == PR_CURDIR || type == PR_ROOTDIR) {
		/*
		 * Final access check on the underlying directory vnode.
		 */
		return (VOP_ACCESS(pnp->pr_realvp, mode, flags, cr, ct));
	}

	/*
	 * Visceral revulsion:  For compatibility with old /proc,
	 * allow the /proc/<pid> directory to be opened for writing.
	 */
	vmode = pnp->pr_mode;
	if (type == PR_PIDDIR)
		vmode |= VWRITE;
	if ((vmode & mode) != mode)
		error = secpolicy_proc_access(cr);
	return (error);
}

/*
 * Array of lookup functions, indexed by /proc file type.
 */
static vnode_t *pr_lookup_notdir(), *pr_lookup_procdir(), *pr_lookup_piddir(),
	*pr_lookup_objectdir(), *pr_lookup_lwpdir(), *pr_lookup_lwpiddir(),
	*pr_lookup_fddir(), *pr_lookup_pathdir(), *pr_lookup_tmpldir(),
	*pr_lookup_ctdir();

static vnode_t *(*pr_lookup_function[PR_NFILES])() = {
	pr_lookup_procdir,	/* /proc				*/
	pr_lookup_notdir,	/* /proc/self				*/
	pr_lookup_piddir,	/* /proc/<pid>				*/
	pr_lookup_notdir,	/* /proc/<pid>/as			*/
	pr_lookup_notdir,	/* /proc/<pid>/ctl			*/
	pr_lookup_notdir,	/* /proc/<pid>/status			*/
	pr_lookup_notdir,	/* /proc/<pid>/lstatus			*/
	pr_lookup_notdir,	/* /proc/<pid>/psinfo			*/
	pr_lookup_notdir,	/* /proc/<pid>/lpsinfo			*/
	pr_lookup_notdir,	/* /proc/<pid>/map			*/
	pr_lookup_notdir,	/* /proc/<pid>/rmap			*/
	pr_lookup_notdir,	/* /proc/<pid>/xmap			*/
	pr_lookup_notdir,	/* /proc/<pid>/cred			*/
	pr_lookup_notdir,	/* /proc/<pid>/sigact			*/
	pr_lookup_notdir,	/* /proc/<pid>/auxv			*/
#if defined(__x86)
	pr_lookup_notdir,	/* /proc/<pid>/ldt			*/
#endif
	pr_lookup_notdir,	/* /proc/<pid>/usage			*/
	pr_lookup_notdir,	/* /proc/<pid>/lusage			*/
	pr_lookup_notdir,	/* /proc/<pid>/pagedata			*/
	pr_lookup_notdir,	/* /proc/<pid>/watch			*/
	pr_lookup_notdir,	/* /proc/<pid>/cwd			*/
	pr_lookup_notdir,	/* /proc/<pid>/root			*/
	pr_lookup_fddir,	/* /proc/<pid>/fd			*/
	pr_lookup_notdir,	/* /proc/<pid>/fd/nn			*/
	pr_lookup_objectdir,	/* /proc/<pid>/object			*/
	pr_lookup_notdir,	/* /proc/<pid>/object/xxx		*/
	pr_lookup_lwpdir,	/* /proc/<pid>/lwp			*/
	pr_lookup_lwpiddir,	/* /proc/<pid>/lwp/<lwpid>		*/
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpctl	*/
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpstatus	*/
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpsinfo	*/
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpusage	*/
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/xregs	*/
	pr_lookup_tmpldir,	/* /proc/<pid>/lwp/<lwpid>/templates	*/
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/templates/<id> */
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/spymaster	*/
#if defined(__sparc)
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/gwindows	*/
	pr_lookup_notdir,	/* /proc/<pid>/lwp/<lwpid>/asrs		*/
#endif
	pr_lookup_notdir,	/* /proc/<pid>/priv			*/
	pr_lookup_pathdir,	/* /proc/<pid>/path			*/
	pr_lookup_notdir,	/* /proc/<pid>/path/xxx			*/
	pr_lookup_ctdir,	/* /proc/<pid>/contracts		*/
	pr_lookup_notdir,	/* /proc/<pid>/contracts/<ctid>		*/
	pr_lookup_notdir,	/* old process file			*/
	pr_lookup_notdir,	/* old lwp file				*/
	pr_lookup_notdir,	/* old pagedata file			*/
};

static int
prlookup(vnode_t *dp, char *comp, vnode_t **vpp, pathname_t *pathp,
	int flags, vnode_t *rdir, cred_t *cr, caller_context_t *ct,
	int *direntflags, pathname_t *realpnp)
{
	prnode_t *pnp = VTOP(dp);
	prnodetype_t type = pnp->pr_type;
	int error;

	ASSERT(dp->v_type == VDIR);
	ASSERT(type < PR_NFILES);

	if (type != PR_PROCDIR && strcmp(comp, "..") == 0) {
		VN_HOLD(pnp->pr_parent);
		*vpp = pnp->pr_parent;
		return (0);
	}

	if (*comp == '\0' ||
	    strcmp(comp, ".") == 0 || strcmp(comp, "..") == 0) {
		VN_HOLD(dp);
		*vpp = dp;
		return (0);
	}

	switch (type) {
	case PR_CURDIR:
	case PR_ROOTDIR:
		/* restrict lookup permission to owner or root */
		if ((error = praccess(dp, VEXEC, 0, cr, ct)) != 0)
			return (error);
		/* FALLTHROUGH */
	case PR_FD:
		dp = pnp->pr_realvp;
		return (VOP_LOOKUP(dp, comp, vpp, pathp, flags, rdir, cr, ct,
		    direntflags, realpnp));
	default:
		break;
	}

	if ((type == PR_OBJECTDIR || type == PR_FDDIR || type == PR_PATHDIR) &&
	    (error = praccess(dp, VEXEC, 0, cr, ct)) != 0)
		return (error);

	/* XXX - Do we need to pass ct, direntflags, or realpnp? */
	*vpp = (pr_lookup_function[type](dp, comp));

	return ((*vpp == NULL) ? ENOENT : 0);
}

/* ARGSUSED */
static int
prcreate(vnode_t *dp, char *comp, vattr_t *vap, vcexcl_t excl,
	int mode, vnode_t **vpp, cred_t *cr, int flag, caller_context_t *ct,
	vsecattr_t *vsecp)
{
	int error;

	if ((error = prlookup(dp, comp, vpp, NULL, 0, NULL, cr,
	    ct, NULL, NULL)) != 0) {
		if (error == ENOENT)	/* can't O_CREAT nonexistent files */
			error = EACCES;		/* unwriteable directories */
	} else {
		if (excl == EXCL)			/* O_EXCL */
			error = EEXIST;
		else if (vap->va_mask & AT_SIZE) {	/* O_TRUNC */
			vnode_t *vp = *vpp;
			uint_t mask;

			if (vp->v_type == VDIR)
				error = EISDIR;
			else if (vp->v_type != VPROC ||
			    VTOP(vp)->pr_type != PR_FD)
				error = EACCES;
			else {		/* /proc/<pid>/fd/<n> */
				vp = VTOP(vp)->pr_realvp;
				mask = vap->va_mask;
				vap->va_mask = AT_SIZE;
				error = VOP_SETATTR(vp, vap, 0, cr, ct);
				vap->va_mask = mask;
			}
		}
		if (error) {
			VN_RELE(*vpp);
			*vpp = NULL;
		}
	}
	return (error);
}

/* ARGSUSED */
static vnode_t *
pr_lookup_notdir(vnode_t *dp, char *comp)
{
	return (NULL);
}

/*
 * Find or construct a process vnode for the given pid.
 */
static vnode_t *
pr_lookup_procdir(vnode_t *dp, char *comp)
{
	pid_t pid;
	prnode_t *pnp;
	prcommon_t *pcp;
	vnode_t *vp;
	proc_t *p;
	int c;

	ASSERT(VTOP(dp)->pr_type == PR_PROCDIR);

	if (strcmp(comp, "self") == 0) {
		pnp = prgetnode(dp, PR_SELF);
		return (PTOV(pnp));
	} else {
		pid = 0;
		while ((c = *comp++) != '\0') {
			if (c < '0' || c > '9')
				return (NULL);
			pid = 10*pid + c - '0';
			if (pid > maxpid)
				return (NULL);
		}
	}

	pnp = prgetnode(dp, PR_PIDDIR);

	mutex_enter(&pidlock);
	if ((p = prfind(pid)) == NULL || p->p_stat == SIDL) {
		mutex_exit(&pidlock);
		prfreenode(pnp);
		return (NULL);
	}
	ASSERT(p->p_stat != 0);

	/* NOTE: we're holding pidlock across the policy call. */
	if (secpolicy_basic_procinfo(CRED(), p, curproc) != 0) {
		mutex_exit(&pidlock);
		prfreenode(pnp);
		return (NULL);
	}

	mutex_enter(&p->p_lock);
	mutex_exit(&pidlock);

	/*
	 * If a process vnode already exists and it is not invalid
	 * and it was created by the current process and it belongs
	 * to the same /proc mount point as our parent vnode, then
	 * just use it and discard the newly-allocated prnode.
	 */
	for (vp = p->p_trace; vp != NULL; vp = VTOP(vp)->pr_next) {
		if (!(VTOP(VTOP(vp)->pr_pidfile)->pr_flags & PR_INVAL) &&
		    VTOP(vp)->pr_owner == curproc &&
		    vp->v_vfsp == dp->v_vfsp) {
			ASSERT(!(VTOP(vp)->pr_flags & PR_INVAL));
			VN_HOLD(vp);
			prfreenode(pnp);
			mutex_exit(&p->p_lock);
			return (vp);
		}
	}
	pnp->pr_owner = curproc;

	/*
	 * prgetnode() initialized most of the prnode.
	 * Finish the job.
	 */
	pcp = pnp->pr_common;	/* the newly-allocated prcommon struct */
	if ((vp = p->p_trace) != NULL) {
		/* discard the new prcommon and use the existing prcommon */
		prfreecommon(pcp);
		pcp = VTOP(vp)->pr_common;
		mutex_enter(&pcp->prc_mutex);
		ASSERT(pcp->prc_refcnt > 0);
		pcp->prc_refcnt++;
		mutex_exit(&pcp->prc_mutex);
		pnp->pr_common = pcp;
	} else {
		/* initialize the new prcommon struct */
		if ((p->p_flag & SSYS) || p->p_as == &kas)
			pcp->prc_flags |= PRC_SYS;
		if (p->p_stat == SZOMB)
			pcp->prc_flags |= PRC_DESTROY;
		pcp->prc_proc = p;
		pcp->prc_datamodel = p->p_model;
		pcp->prc_pid = p->p_pid;
		pcp->prc_slot = p->p_slot;
	}
	pnp->pr_pcommon = pcp;
	pnp->pr_parent = dp;
	VN_HOLD(dp);
	/*
	 * Link in the old, invalid directory vnode so we
	 * can later determine the last close of the file.
	 */
	pnp->pr_next = p->p_trace;
	p->p_trace = dp = PTOV(pnp);

	/*
	 * Kludge for old /proc: initialize the PR_PIDFILE as well.
	 */
	vp = pnp->pr_pidfile;
	pnp = VTOP(vp);
	pnp->pr_ino = ptoi(pcp->prc_pid);
	pnp->pr_common = pcp;
	pnp->pr_pcommon = pcp;
	pnp->pr_parent = dp;
	pnp->pr_next = p->p_plist;
	p->p_plist = vp;

	mutex_exit(&p->p_lock);
	return (dp);
}

static vnode_t *
pr_lookup_piddir(vnode_t *dp, char *comp)
{
	prnode_t *dpnp = VTOP(dp);
	vnode_t *vp;
	prnode_t *pnp;
	proc_t *p;
	user_t *up;
	prdirent_t *dirp;
	int i;
	enum prnodetype type;

	ASSERT(dpnp->pr_type == PR_PIDDIR);

	for (i = 0; i < NPIDDIRFILES; i++) {
		/* Skip "." and ".." */
		dirp = &piddir[i+2];
		if (strcmp(comp, dirp->d_name) == 0)
			break;
	}

	if (i >= NPIDDIRFILES)
		return (NULL);

	type = (int)dirp->d_ino;
	pnp = prgetnode(dp, type);

	p = pr_p_lock(dpnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		prfreenode(pnp);
		return (NULL);
	}
	if (dpnp->pr_pcommon->prc_flags & PRC_DESTROY) {
		switch (type) {
		case PR_PSINFO:
		case PR_USAGE:
			break;
		default:
			prunlock(dpnp);
			prfreenode(pnp);
			return (NULL);
		}
	}

	switch (type) {
	case PR_CURDIR:
	case PR_ROOTDIR:
		up = PTOU(p);
		vp = (type == PR_CURDIR)? up->u_cdir :
		    (up->u_rdir? up->u_rdir : rootdir);

		if (vp == NULL) {	/* can't happen? */
			prunlock(dpnp);
			prfreenode(pnp);
			return (NULL);
		}
		/*
		 * Fill in the prnode so future references will
		 * be able to find the underlying object's vnode.
		 */
		VN_HOLD(vp);
		pnp->pr_realvp = vp;
		break;
	default:
		break;
	}

	mutex_enter(&dpnp->pr_mutex);

	if ((vp = dpnp->pr_files[i]) != NULL &&
	    !(VTOP(vp)->pr_flags & PR_INVAL)) {
		VN_HOLD(vp);
		mutex_exit(&dpnp->pr_mutex);
		prunlock(dpnp);
		prfreenode(pnp);
		return (vp);
	}

	/*
	 * prgetnode() initialized most of the prnode.
	 * Finish the job.
	 */
	pnp->pr_common = dpnp->pr_common;
	pnp->pr_pcommon = dpnp->pr_pcommon;
	pnp->pr_parent = dp;
	VN_HOLD(dp);
	pnp->pr_index = i;

	dpnp->pr_files[i] = vp = PTOV(pnp);

	/*
	 * Link new vnode into list of all /proc vnodes for the process.
	 */
	if (vp->v_type == VPROC) {
		pnp->pr_next = p->p_plist;
		p->p_plist = vp;
	}
	mutex_exit(&dpnp->pr_mutex);
	prunlock(dpnp);
	return (vp);
}

static vnode_t *
pr_lookup_objectdir(vnode_t *dp, char *comp)
{
	prnode_t *dpnp = VTOP(dp);
	prnode_t *pnp;
	proc_t *p;
	struct seg *seg;
	struct as *as;
	vnode_t *vp;
	vattr_t vattr;

	ASSERT(dpnp->pr_type == PR_OBJECTDIR);

	pnp = prgetnode(dp, PR_OBJECT);

	if (prlock(dpnp, ZNO) != 0) {
		prfreenode(pnp);
		return (NULL);
	}
	p = dpnp->pr_common->prc_proc;
	if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
		prunlock(dpnp);
		prfreenode(pnp);
		return (NULL);
	}

	/*
	 * We drop p_lock before grabbing the address space lock
	 * in order to avoid a deadlock with the clock thread.
	 * The process will not disappear and its address space
	 * will not change because it is marked P_PR_LOCK.
	 */
	mutex_exit(&p->p_lock);
	AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
	if ((seg = AS_SEGFIRST(as)) == NULL) {
		vp = NULL;
		goto out;
	}
	if (strcmp(comp, "a.out") == 0) {
		vp = p->p_exec;
		goto out;
	}
	do {
		/*
		 * Manufacture a filename for the "object" directory.
		 */
		vattr.va_mask = AT_FSID|AT_NODEID;
		if (seg->s_ops == &segvn_ops &&
		    SEGOP_GETVP(seg, seg->s_base, &vp) == 0 &&
		    vp != NULL && vp->v_type == VREG &&
		    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {
			char name[64];

			if (vp == p->p_exec)	/* "a.out" */
				continue;
			pr_object_name(name, vp, &vattr);
			if (strcmp(name, comp) == 0)
				goto out;
		}
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	vp = NULL;
out:
	if (vp != NULL) {
		VN_HOLD(vp);
	}
	AS_LOCK_EXIT(as, &as->a_lock);
	mutex_enter(&p->p_lock);
	prunlock(dpnp);

	if (vp == NULL)
		prfreenode(pnp);
	else {
		/*
		 * Fill in the prnode so future references will
		 * be able to find the underlying object's vnode.
		 * Don't link this prnode into the list of all
		 * prnodes for the process; this is a one-use node.
		 * Its use is entirely to catch and fail opens for writing.
		 */
		pnp->pr_realvp = vp;
		vp = PTOV(pnp);
	}

	return (vp);
}

/*
 * Find or construct an lwp vnode for the given lwpid.
 */
static vnode_t *
pr_lookup_lwpdir(vnode_t *dp, char *comp)
{
	id_t tid;	/* same type as t->t_tid */
	int want_agent;
	prnode_t *dpnp = VTOP(dp);
	prnode_t *pnp;
	prcommon_t *pcp;
	vnode_t *vp;
	proc_t *p;
	kthread_t *t;
	lwpdir_t *ldp;
	lwpent_t *lep;
	int tslot;
	int c;

	ASSERT(dpnp->pr_type == PR_LWPDIR);

	tid = 0;
	if (strcmp(comp, "agent") == 0)
		want_agent = 1;
	else {
		want_agent = 0;
		while ((c = *comp++) != '\0') {
			id_t otid;

			if (c < '0' || c > '9')
				return (NULL);
			otid = tid;
			tid = 10*tid + c - '0';
			if (tid/10 != otid)	/* integer overflow */
				return (NULL);
		}
	}

	pnp = prgetnode(dp, PR_LWPIDDIR);

	p = pr_p_lock(dpnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		prfreenode(pnp);
		return (NULL);
	}

	if (want_agent) {
		if ((t = p->p_agenttp) == NULL)
			lep = NULL;
		else {
			tid = t->t_tid;
			tslot = t->t_dslot;
			lep = p->p_lwpdir[tslot].ld_entry;
		}
	} else {
		if ((ldp = lwp_hash_lookup(p, tid)) == NULL)
			lep = NULL;
		else {
			tslot = (int)(ldp - p->p_lwpdir);
			lep = ldp->ld_entry;
		}
	}

	if (lep == NULL) {
		prunlock(dpnp);
		prfreenode(pnp);
		return (NULL);
	}

	/*
	 * If an lwp vnode already exists and it is not invalid
	 * and it was created by the current process and it belongs
	 * to the same /proc mount point as our parent vnode, then
	 * just use it and discard the newly-allocated prnode.
	 */
	for (vp = lep->le_trace; vp != NULL; vp = VTOP(vp)->pr_next) {
		if (!(VTOP(vp)->pr_flags & PR_INVAL) &&
		    VTOP(vp)->pr_owner == curproc &&
		    vp->v_vfsp == dp->v_vfsp) {
			VN_HOLD(vp);
			prunlock(dpnp);
			prfreenode(pnp);
			return (vp);
		}
	}
	pnp->pr_owner = curproc;

	/*
	 * prgetnode() initialized most of the prnode.
	 * Finish the job.
	 */
	pcp = pnp->pr_common;	/* the newly-allocated prcommon struct */
	if ((vp = lep->le_trace) != NULL) {
		/* discard the new prcommon and use the existing prcommon */
		prfreecommon(pcp);
		pcp = VTOP(vp)->pr_common;
		mutex_enter(&pcp->prc_mutex);
		ASSERT(pcp->prc_refcnt > 0);
		pcp->prc_refcnt++;
		mutex_exit(&pcp->prc_mutex);
		pnp->pr_common = pcp;
	} else {
		/* initialize the new prcommon struct */
		pcp->prc_flags |= PRC_LWP;
		if ((p->p_flag & SSYS) || p->p_as == &kas)
			pcp->prc_flags |= PRC_SYS;
		if ((t = lep->le_thread) == NULL)
			pcp->prc_flags |= PRC_DESTROY;
		pcp->prc_proc = p;
		pcp->prc_datamodel = dpnp->pr_pcommon->prc_datamodel;
		pcp->prc_pid = p->p_pid;
		pcp->prc_slot = p->p_slot;
		pcp->prc_thread = t;
		pcp->prc_tid = tid;
		pcp->prc_tslot = tslot;
	}
	pnp->pr_pcommon = dpnp->pr_pcommon;
	pnp->pr_parent = dp;
	VN_HOLD(dp);
	/*
	 * Link in the old, invalid directory vnode so we
	 * can later determine the last close of the file.
	 */
	pnp->pr_next = lep->le_trace;
	lep->le_trace = vp = PTOV(pnp);
	prunlock(dpnp);
	return (vp);
}

static vnode_t *
pr_lookup_lwpiddir(vnode_t *dp, char *comp)
{
	prnode_t *dpnp = VTOP(dp);
	vnode_t *vp;
	prnode_t *pnp;
	proc_t *p;
	prdirent_t *dirp;
	int i;
	enum prnodetype type;

	ASSERT(dpnp->pr_type == PR_LWPIDDIR);

	for (i = 0; i < NLWPIDDIRFILES; i++) {
		/* Skip "." and ".." */
		dirp = &lwpiddir[i+2];
		if (strcmp(comp, dirp->d_name) == 0)
			break;
	}

	if (i >= NLWPIDDIRFILES)
		return (NULL);

	type = (int)dirp->d_ino;
	pnp = prgetnode(dp, type);

	p = pr_p_lock(dpnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		prfreenode(pnp);
		return (NULL);
	}
	if (dpnp->pr_common->prc_flags & PRC_DESTROY) {
		/*
		 * Only the lwpsinfo file is present for zombie lwps.
		 * Nothing is present if the lwp has been reaped.
		 */
		if (dpnp->pr_common->prc_tslot == -1 ||
		    type != PR_LWPSINFO) {
			prunlock(dpnp);
			prfreenode(pnp);
			return (NULL);
		}
	}

#if defined(__sparc)
	/* the asrs file exists only for sparc v9 _LP64 processes */
	if (type == PR_ASRS && p->p_model != DATAMODEL_LP64) {
		prunlock(dpnp);
		prfreenode(pnp);
		return (NULL);
	}
#endif

	mutex_enter(&dpnp->pr_mutex);

	if ((vp = dpnp->pr_files[i]) != NULL &&
	    !(VTOP(vp)->pr_flags & PR_INVAL)) {
		VN_HOLD(vp);
		mutex_exit(&dpnp->pr_mutex);
		prunlock(dpnp);
		prfreenode(pnp);
		return (vp);
	}

	/*
	 * prgetnode() initialized most of the prnode.
	 * Finish the job.
	 */
	pnp->pr_common = dpnp->pr_common;
	pnp->pr_pcommon = dpnp->pr_pcommon;
	pnp->pr_parent = dp;
	VN_HOLD(dp);
	pnp->pr_index = i;

	dpnp->pr_files[i] = vp = PTOV(pnp);

	/*
	 * Link new vnode into list of all /proc vnodes for the process.
	 */
	if (vp->v_type == VPROC) {
		pnp->pr_next = p->p_plist;
		p->p_plist = vp;
	}
	mutex_exit(&dpnp->pr_mutex);
	prunlock(dpnp);
	return (vp);
}

/*
 * Lookup one of the process's open files.
 */
static vnode_t *
pr_lookup_fddir(vnode_t *dp, char *comp)
{
	prnode_t *dpnp = VTOP(dp);
	prnode_t *pnp;
	vnode_t *vp = NULL;
	proc_t *p;
	file_t *fp;
	uint_t fd;
	int c;
	uf_entry_t *ufp;
	uf_info_t *fip;

	ASSERT(dpnp->pr_type == PR_FDDIR);

	fd = 0;
	while ((c = *comp++) != '\0') {
		int ofd;
		if (c < '0' || c > '9')
			return (NULL);
		ofd = fd;
		fd = 10*fd + c - '0';
		if (fd/10 != ofd)	/* integer overflow */
			return (NULL);
	}

	pnp = prgetnode(dp, PR_FD);

	if (prlock(dpnp, ZNO) != 0) {
		prfreenode(pnp);
		return (NULL);
	}
	p = dpnp->pr_common->prc_proc;
	if ((p->p_flag & SSYS) || p->p_as == &kas) {
		prunlock(dpnp);
		prfreenode(pnp);
		return (NULL);
	}

	fip = P_FINFO(p);
	mutex_exit(&p->p_lock);
	mutex_enter(&fip->fi_lock);
	if (fd < fip->fi_nfiles) {
		UF_ENTER(ufp, fip, fd);
		if ((fp = ufp->uf_file) != NULL) {
			pnp->pr_mode = 07111;
			if (fp->f_flag & FREAD)
				pnp->pr_mode |= 0444;
			if (fp->f_flag & FWRITE)
				pnp->pr_mode |= 0222;
			vp = fp->f_vnode;
			VN_HOLD(vp);
		}
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);
	mutex_enter(&p->p_lock);
	prunlock(dpnp);

	if (vp == NULL)
		prfreenode(pnp);
	else {
		/*
		 * Fill in the prnode so future references will
		 * be able to find the underlying object's vnode.
		 * Don't link this prnode into the list of all
		 * prnodes for the process; this is a one-use node.
		 */
		pnp->pr_realvp = vp;
		pnp->pr_parent = dp;		/* needed for prlookup */
		VN_HOLD(dp);
		vp = PTOV(pnp);
		if (pnp->pr_realvp->v_type == VDIR)
			vp->v_type = VDIR;
	}

	return (vp);
}

static vnode_t *
pr_lookup_pathdir(vnode_t *dp, char *comp)
{
	prnode_t *dpnp = VTOP(dp);
	prnode_t *pnp;
	vnode_t *vp = NULL;
	proc_t *p;
	uint_t fd, flags = 0;
	int c;
	uf_entry_t *ufp;
	uf_info_t *fip;
	enum { NAME_FD, NAME_OBJECT, NAME_ROOT, NAME_CWD, NAME_UNKNOWN } type;
	char *tmp;
	int idx;
	struct seg *seg;
	struct as *as = NULL;
	vattr_t vattr;

	ASSERT(dpnp->pr_type == PR_PATHDIR);

	/*
	 * First, check if this is a numeric entry, in which case we have a
	 * file descriptor.
	 */
	fd = 0;
	type = NAME_FD;
	tmp = comp;
	while ((c = *tmp++) != '\0') {
		int ofd;
		if (c < '0' || c > '9') {
			type = NAME_UNKNOWN;
			break;
		}
		ofd = fd;
		fd = 10*fd + c - '0';
		if (fd/10 != ofd) {	/* integer overflow */
			type = NAME_UNKNOWN;
			break;
		}
	}

	/*
	 * Next, see if it is one of the special values {root, cwd}.
	 */
	if (type == NAME_UNKNOWN) {
		if (strcmp(comp, "root") == 0)
			type = NAME_ROOT;
		else if (strcmp(comp, "cwd") == 0)
			type = NAME_CWD;
	}

	/*
	 * Grab the necessary data from the process
	 */
	if (prlock(dpnp, ZNO) != 0)
		return (NULL);
	p = dpnp->pr_common->prc_proc;

	fip = P_FINFO(p);

	switch (type) {
	case NAME_ROOT:
		if ((vp = PTOU(p)->u_rdir) == NULL)
			vp = p->p_zone->zone_rootvp;
		VN_HOLD(vp);
		break;
	case NAME_CWD:
		vp = PTOU(p)->u_cdir;
		VN_HOLD(vp);
		break;
	default:
		if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
			prunlock(dpnp);
			return (NULL);
		}
	}
	mutex_exit(&p->p_lock);

	/*
	 * Determine if this is an object entry
	 */
	if (type == NAME_UNKNOWN) {
		/*
		 * Start with the inode index immediately after the number of
		 * files.
		 */
		mutex_enter(&fip->fi_lock);
		idx = fip->fi_nfiles + 4;
		mutex_exit(&fip->fi_lock);

		if (strcmp(comp, "a.out") == 0) {
			if (p->p_execdir != NULL) {
				vp = p->p_execdir;
				VN_HOLD(vp);
				type = NAME_OBJECT;
				flags |= PR_AOUT;
			} else {
				vp = p->p_exec;
				VN_HOLD(vp);
				type = NAME_OBJECT;
			}
		} else {
			AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
			if ((seg = AS_SEGFIRST(as)) != NULL) {
				do {
					/*
					 * Manufacture a filename for the
					 * "object" directory.
					 */
					vattr.va_mask = AT_FSID|AT_NODEID;
					if (seg->s_ops == &segvn_ops &&
					    SEGOP_GETVP(seg, seg->s_base, &vp)
					    == 0 &&
					    vp != NULL && vp->v_type == VREG &&
					    VOP_GETATTR(vp, &vattr, 0, CRED(),
					    NULL) == 0) {
						char name[64];

						if (vp == p->p_exec)
							continue;
						idx++;
						pr_object_name(name, vp,
						    &vattr);
						if (strcmp(name, comp) == 0)
							break;
					}
				} while ((seg = AS_SEGNEXT(as, seg)) != NULL);
			}

			if (seg == NULL) {
				vp = NULL;
			} else {
				VN_HOLD(vp);
				type = NAME_OBJECT;
			}

			AS_LOCK_EXIT(as, &as->a_lock);
		}
	}


	switch (type) {
	case NAME_FD:
		mutex_enter(&fip->fi_lock);
		if (fd < fip->fi_nfiles) {
			UF_ENTER(ufp, fip, fd);
			if (ufp->uf_file != NULL) {
				vp = ufp->uf_file->f_vnode;
				VN_HOLD(vp);
			}
			UF_EXIT(ufp);
		}
		mutex_exit(&fip->fi_lock);
		idx = fd + 4;
		break;
	case NAME_ROOT:
		idx = 2;
		break;
	case NAME_CWD:
		idx = 3;
		break;
	case NAME_OBJECT:
	case NAME_UNKNOWN:
		/* Nothing to do */
		break;
	}

	mutex_enter(&p->p_lock);
	prunlock(dpnp);

	if (vp != NULL) {
		pnp = prgetnode(dp, PR_PATH);

		pnp->pr_flags |= flags;
		pnp->pr_common = dpnp->pr_common;
		pnp->pr_pcommon = dpnp->pr_pcommon;
		pnp->pr_realvp = vp;
		pnp->pr_parent = dp;		/* needed for prlookup */
		pnp->pr_ino = pmkino(idx, dpnp->pr_common->prc_slot, PR_PATH);
		VN_HOLD(dp);
		vp = PTOV(pnp);
		vp->v_type = VLNK;
	}

	return (vp);
}

/*
 * Look up one of the process's active templates.
 */
static vnode_t *
pr_lookup_tmpldir(vnode_t *dp, char *comp)
{
	prnode_t *dpnp = VTOP(dp);
	prnode_t *pnp;
	vnode_t *vp = NULL;
	proc_t *p;
	int i;

	ASSERT(dpnp->pr_type == PR_TMPLDIR);

	for (i = 0; i < ct_ntypes; i++)
		if (strcmp(comp, ct_types[i]->ct_type_name) == 0)
			break;
	if (i == ct_ntypes)
		return (NULL);

	pnp = prgetnode(dp, PR_TMPL);

	if (prlock(dpnp, ZNO) != 0) {
		prfreenode(pnp);
		return (NULL);
	}
	p = dpnp->pr_common->prc_proc;
	if ((p->p_flag & SSYS) || p->p_as == &kas ||
	    (dpnp->pr_common->prc_flags & (PRC_DESTROY | PRC_LWP)) != PRC_LWP) {
		prunlock(dpnp);
		prfreenode(pnp);
		return (NULL);
	}
	if (ttolwp(dpnp->pr_common->prc_thread)->lwp_ct_active[i] != NULL) {
		pnp->pr_common = dpnp->pr_common;
		pnp->pr_pcommon = dpnp->pr_pcommon;
		pnp->pr_parent = dp;
		pnp->pr_cttype = i;
		VN_HOLD(dp);
		vp = PTOV(pnp);
	} else {
		prfreenode(pnp);
	}
	prunlock(dpnp);

	return (vp);
}

/*
 * Look up one of the contracts owned by the process.
 */
static vnode_t *
pr_lookup_ctdir(vnode_t *dp, char *comp)
{
	prnode_t *dpnp = VTOP(dp);
	prnode_t *pnp;
	vnode_t *vp = NULL;
	proc_t *p;
	id_t id = 0;
	contract_t *ct;
	int c;

	ASSERT(dpnp->pr_type == PR_CTDIR);

	while ((c = *comp++) != '\0') {
		id_t oid;
		if (c < '0' || c > '9')
			return (NULL);
		oid = id;
		id = 10 * id + c - '0';
		if (id / 10 != oid)	/* integer overflow */
			return (NULL);
	}

	/*
	 * Search all contracts; we'll filter below.
	 */
	ct = contract_ptr(id, GLOBAL_ZONEUNIQID);
	if (ct == NULL)
		return (NULL);

	pnp = prgetnode(dp, PR_CT);

	if (prlock(dpnp, ZNO) != 0) {
		prfreenode(pnp);
		contract_rele(ct);
		return (NULL);
	}
	p = dpnp->pr_common->prc_proc;
	/*
	 * We only allow lookups of contracts owned by this process, or,
	 * if we are zsched and this is a zone's procfs, contracts on
	 * stuff in the zone which are held by processes or contracts
	 * outside the zone.  (see logic in contract_status_common)
	 */
	if ((ct->ct_owner != p) &&
	    !(p == VTOZONE(dp)->zone_zsched && ct->ct_state < CTS_ORPHAN &&
	    VTOZONE(dp)->zone_uniqid == contract_getzuniqid(ct) &&
	    VTOZONE(dp)->zone_uniqid != GLOBAL_ZONEUNIQID &&
	    ct->ct_czuniqid == GLOBAL_ZONEUNIQID)) {
		prunlock(dpnp);
		prfreenode(pnp);
		contract_rele(ct);
		return (NULL);
	}
	pnp->pr_common = dpnp->pr_common;
	pnp->pr_pcommon = dpnp->pr_pcommon;
	pnp->pr_contract = ct;
	pnp->pr_parent = dp;
	pnp->pr_ino = pmkino(id, pnp->pr_common->prc_slot, PR_CT);
	VN_HOLD(dp);
	prunlock(dpnp);
	vp = PTOV(pnp);

	return (vp);
}

/*
 * Construct an lwp vnode for the old /proc interface.
 * We stand on our head to make the /proc plumbing correct.
 */
vnode_t *
prlwpnode(prnode_t *pnp, uint_t tid)
{
	char comp[12];
	vnode_t *dp;
	vnode_t *vp;
	prcommon_t *pcp;
	proc_t *p;

	/*
	 * Lookup the /proc/<pid>/lwp/<lwpid> directory vnode.
	 */
	if (pnp->pr_type == PR_PIDFILE) {
		dp = pnp->pr_parent;		/* /proc/<pid> */
		VN_HOLD(dp);
		vp = pr_lookup_piddir(dp, "lwp");
		VN_RELE(dp);
		if ((dp = vp) == NULL)		/* /proc/<pid>/lwp */
			return (NULL);
	} else if (pnp->pr_type == PR_LWPIDFILE) {
		dp = pnp->pr_parent;		/* /proc/<pid>/lwp/<lwpid> */
		dp = VTOP(dp)->pr_parent;	/* /proc/<pid>/lwp */
		VN_HOLD(dp);
	} else {
		return (NULL);
	}

	(void) pr_u32tos(tid, comp, sizeof (comp));
	vp = pr_lookup_lwpdir(dp, comp);
	VN_RELE(dp);
	if ((dp = vp) == NULL)
		return (NULL);

	pnp = prgetnode(dp, PR_LWPIDFILE);
	vp = PTOV(pnp);

	/*
	 * prgetnode() initialized most of the prnode.
	 * Finish the job.
	 */
	pcp = VTOP(dp)->pr_common;
	pnp->pr_ino = ptoi(pcp->prc_pid);
	pnp->pr_common = pcp;
	pnp->pr_pcommon = VTOP(dp)->pr_pcommon;
	pnp->pr_parent = dp;
	/*
	 * Link new vnode into list of all /proc vnodes for the process.
	 */
	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL) {
		VN_RELE(dp);
		prfreenode(pnp);
		vp = NULL;
	} else if (pcp->prc_thread == NULL) {
		prunlock(pnp);
		VN_RELE(dp);
		prfreenode(pnp);
		vp = NULL;
	} else {
		pnp->pr_next = p->p_plist;
		p->p_plist = vp;
		prunlock(pnp);
	}

	return (vp);
}

#if defined(DEBUG)

static	uint32_t nprnode;
static	uint32_t nprcommon;

#define	INCREMENT(x)	atomic_inc_32(&x);
#define	DECREMENT(x)	atomic_dec_32(&x);

#else

#define	INCREMENT(x)
#define	DECREMENT(x)

#endif	/* DEBUG */

/*
 * New /proc vnode required; allocate it and fill in most of the fields.
 */
prnode_t *
prgetnode(vnode_t *dp, prnodetype_t type)
{
	prnode_t *pnp;
	prcommon_t *pcp;
	vnode_t *vp;
	ulong_t nfiles;

	INCREMENT(nprnode);
	pnp = kmem_zalloc(sizeof (prnode_t), KM_SLEEP);

	mutex_init(&pnp->pr_mutex, NULL, MUTEX_DEFAULT, NULL);
	pnp->pr_type = type;

	pnp->pr_vnode = vn_alloc(KM_SLEEP);

	vp = PTOV(pnp);
	vp->v_flag = VNOCACHE|VNOMAP|VNOSWAP|VNOMOUNT;
	vn_setops(vp, prvnodeops);
	vp->v_vfsp = dp->v_vfsp;
	vp->v_type = VPROC;
	vp->v_data = (caddr_t)pnp;

	switch (type) {
	case PR_PIDDIR:
	case PR_LWPIDDIR:
		/*
		 * We need a prcommon and a files array for each of these.
		 */
		INCREMENT(nprcommon);

		pcp = kmem_zalloc(sizeof (prcommon_t), KM_SLEEP);
		pcp->prc_refcnt = 1;
		pnp->pr_common = pcp;
		mutex_init(&pcp->prc_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&pcp->prc_wait, NULL, CV_DEFAULT, NULL);

		nfiles = (type == PR_PIDDIR)? NPIDDIRFILES : NLWPIDDIRFILES;
		pnp->pr_files =
		    kmem_zalloc(nfiles * sizeof (vnode_t *), KM_SLEEP);

		vp->v_type = VDIR;
		/*
		 * Mode should be read-search by all, but we cannot so long
		 * as we must support compatibility mode with old /proc.
		 * Make /proc/<pid> be read by owner only, search by all.
		 * Make /proc/<pid>/lwp/<lwpid> read-search by all.  Also,
		 * set VDIROPEN on /proc/<pid> so it can be opened for writing.
		 */
		if (type == PR_PIDDIR) {
			/* kludge for old /proc interface */
			prnode_t *xpnp = prgetnode(dp, PR_PIDFILE);
			pnp->pr_pidfile = PTOV(xpnp);
			pnp->pr_mode = 0511;
			vp->v_flag |= VDIROPEN;
		} else {
			pnp->pr_mode = 0555;
		}

		break;

	case PR_CURDIR:
	case PR_ROOTDIR:
	case PR_FDDIR:
	case PR_OBJECTDIR:
	case PR_PATHDIR:
	case PR_CTDIR:
	case PR_TMPLDIR:
		vp->v_type = VDIR;
		pnp->pr_mode = 0500;	/* read-search by owner only */
		break;

	case PR_CT:
		vp->v_type = VLNK;
		pnp->pr_mode = 0500;	/* read-search by owner only */
		break;

	case PR_PATH:
	case PR_SELF:
		vp->v_type = VLNK;
		pnp->pr_mode = 0777;
		break;

	case PR_LWPDIR:
		vp->v_type = VDIR;
		pnp->pr_mode = 0555;	/* read-search by all */
		break;

	case PR_AS:
	case PR_TMPL:
		pnp->pr_mode = 0600;	/* read-write by owner only */
		break;

	case PR_CTL:
	case PR_LWPCTL:
		pnp->pr_mode = 0200;	/* write-only by owner only */
		break;

	case PR_PIDFILE:
	case PR_LWPIDFILE:
		pnp->pr_mode = 0600;	/* read-write by owner only */
		break;

	case PR_PSINFO:
		pnp->pr_mode = 0644;	/* readable by all + owner can write */
		break;

	case PR_LPSINFO:
	case PR_LWPSINFO:
	case PR_USAGE:
	case PR_LUSAGE:
	case PR_LWPUSAGE:
		pnp->pr_mode = 0444;	/* read-only by all */
		break;

	default:
		pnp->pr_mode = 0400;	/* read-only by owner only */
		break;
	}
	vn_exists(vp);
	return (pnp);
}

/*
 * Free the storage obtained from prgetnode().
 */
void
prfreenode(prnode_t *pnp)
{
	vnode_t *vp;
	ulong_t nfiles;

	vn_invalid(PTOV(pnp));
	vn_free(PTOV(pnp));
	mutex_destroy(&pnp->pr_mutex);

	switch (pnp->pr_type) {
	case PR_PIDDIR:
		/* kludge for old /proc interface */
		if (pnp->pr_pidfile != NULL) {
			prfreenode(VTOP(pnp->pr_pidfile));
			pnp->pr_pidfile = NULL;
		}
		/* FALLTHROUGH */
	case PR_LWPIDDIR:
		/*
		 * We allocated a prcommon and a files array for each of these.
		 */
		prfreecommon(pnp->pr_common);
		nfiles = (pnp->pr_type == PR_PIDDIR)?
		    NPIDDIRFILES : NLWPIDDIRFILES;
		kmem_free(pnp->pr_files, nfiles * sizeof (vnode_t *));
		break;
	default:
		break;
	}
	/*
	 * If there is an underlying vnode, be sure
	 * to release it after freeing the prnode.
	 */
	vp = pnp->pr_realvp;
	kmem_free(pnp, sizeof (*pnp));
	DECREMENT(nprnode);
	if (vp != NULL) {
		VN_RELE(vp);
	}
}

/*
 * Free a prcommon structure, if the reference count reaches zero.
 */
static void
prfreecommon(prcommon_t *pcp)
{
	mutex_enter(&pcp->prc_mutex);
	ASSERT(pcp->prc_refcnt > 0);
	if (--pcp->prc_refcnt != 0)
		mutex_exit(&pcp->prc_mutex);
	else {
		mutex_exit(&pcp->prc_mutex);
		ASSERT(pcp->prc_pollhead.ph_list == NULL);
		ASSERT(pcp->prc_refcnt == 0);
		ASSERT(pcp->prc_selfopens == 0 && pcp->prc_writers == 0);
		mutex_destroy(&pcp->prc_mutex);
		cv_destroy(&pcp->prc_wait);
		kmem_free(pcp, sizeof (prcommon_t));
		DECREMENT(nprcommon);
	}
}

/*
 * Array of readdir functions, indexed by /proc file type.
 */
static int pr_readdir_notdir(), pr_readdir_procdir(), pr_readdir_piddir(),
	pr_readdir_objectdir(), pr_readdir_lwpdir(), pr_readdir_lwpiddir(),
	pr_readdir_fddir(), pr_readdir_pathdir(), pr_readdir_tmpldir(),
	pr_readdir_ctdir();

static int (*pr_readdir_function[PR_NFILES])() = {
	pr_readdir_procdir,	/* /proc				*/
	pr_readdir_notdir,	/* /proc/self				*/
	pr_readdir_piddir,	/* /proc/<pid>				*/
	pr_readdir_notdir,	/* /proc/<pid>/as			*/
	pr_readdir_notdir,	/* /proc/<pid>/ctl			*/
	pr_readdir_notdir,	/* /proc/<pid>/status			*/
	pr_readdir_notdir,	/* /proc/<pid>/lstatus			*/
	pr_readdir_notdir,	/* /proc/<pid>/psinfo			*/
	pr_readdir_notdir,	/* /proc/<pid>/lpsinfo			*/
	pr_readdir_notdir,	/* /proc/<pid>/map			*/
	pr_readdir_notdir,	/* /proc/<pid>/rmap			*/
	pr_readdir_notdir,	/* /proc/<pid>/xmap			*/
	pr_readdir_notdir,	/* /proc/<pid>/cred			*/
	pr_readdir_notdir,	/* /proc/<pid>/sigact			*/
	pr_readdir_notdir,	/* /proc/<pid>/auxv			*/
#if defined(__x86)
	pr_readdir_notdir,	/* /proc/<pid>/ldt			*/
#endif
	pr_readdir_notdir,	/* /proc/<pid>/usage			*/
	pr_readdir_notdir,	/* /proc/<pid>/lusage			*/
	pr_readdir_notdir,	/* /proc/<pid>/pagedata			*/
	pr_readdir_notdir,	/* /proc/<pid>/watch			*/
	pr_readdir_notdir,	/* /proc/<pid>/cwd			*/
	pr_readdir_notdir,	/* /proc/<pid>/root			*/
	pr_readdir_fddir,	/* /proc/<pid>/fd			*/
	pr_readdir_notdir,	/* /proc/<pid>/fd/nn			*/
	pr_readdir_objectdir,	/* /proc/<pid>/object			*/
	pr_readdir_notdir,	/* /proc/<pid>/object/xxx		*/
	pr_readdir_lwpdir,	/* /proc/<pid>/lwp			*/
	pr_readdir_lwpiddir,	/* /proc/<pid>/lwp/<lwpid>		*/
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpctl	*/
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpstatus	*/
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpsinfo	*/
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/lwpusage	*/
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/xregs	*/
	pr_readdir_tmpldir,	/* /proc/<pid>/lwp/<lwpid>/templates	*/
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/templates/<id> */
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/spymaster	*/
#if defined(__sparc)
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/gwindows	*/
	pr_readdir_notdir,	/* /proc/<pid>/lwp/<lwpid>/asrs		*/
#endif
	pr_readdir_notdir,	/* /proc/<pid>/priv			*/
	pr_readdir_pathdir,	/* /proc/<pid>/path			*/
	pr_readdir_notdir,	/* /proc/<pid>/path/xxx			*/
	pr_readdir_ctdir,	/* /proc/<pid>/contracts		*/
	pr_readdir_notdir,	/* /proc/<pid>/contracts/<ctid>		*/
	pr_readdir_notdir,	/* old process file			*/
	pr_readdir_notdir,	/* old lwp file				*/
	pr_readdir_notdir,	/* old pagedata file			*/
};

/* ARGSUSED */
static int
prreaddir(vnode_t *vp, uio_t *uiop, cred_t *cr, int *eofp,
	caller_context_t *ct, int flags)
{
	prnode_t *pnp = VTOP(vp);

	ASSERT(pnp->pr_type < PR_NFILES);

	/* XXX - Do we need to pass ct and flags? */
	return (pr_readdir_function[pnp->pr_type](pnp, uiop, eofp));
}

/* ARGSUSED */
static int
pr_readdir_notdir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	return (ENOTDIR);
}

/* ARGSUSED */
static int
pr_readdir_procdir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	zoneid_t zoneid;
	gfs_readdir_state_t gstate;
	int error, eof = 0;
	offset_t n;

	ASSERT(pnp->pr_type == PR_PROCDIR);

	zoneid = VTOZONE(PTOV(pnp))->zone_id;

	if ((error = gfs_readdir_init(&gstate, PNSIZ, PRSDSIZE, uiop,
	    PRROOTINO, PRROOTINO, 0)) != 0)
		return (error);

	/*
	 * Loop until user's request is satisfied or until all processes
	 * have been examined.
	 */
	while ((error = gfs_readdir_pred(&gstate, uiop, &n)) == 0) {
		uint_t pid;
		int pslot;
		proc_t *p;

		/*
		 * Find next entry.  Skip processes not visible where
		 * this /proc was mounted.
		 */
		mutex_enter(&pidlock);
		while (n < v.v_proc &&
		    ((p = pid_entry(n)) == NULL || p->p_stat == SIDL ||
		    (zoneid != GLOBAL_ZONEID && p->p_zone->zone_id != zoneid) ||
		    secpolicy_basic_procinfo(CRED(), p, curproc) != 0))
			n++;

		/*
		 * Stop when entire proc table has been examined.
		 */
		if (n >= v.v_proc) {
			mutex_exit(&pidlock);
			eof = 1;
			break;
		}

		ASSERT(p->p_stat != 0);
		pid = p->p_pid;
		pslot = p->p_slot;
		mutex_exit(&pidlock);
		error = gfs_readdir_emitn(&gstate, uiop, n,
		    pmkino(0, pslot, PR_PIDDIR), pid);
		if (error)
			break;
	}

	return (gfs_readdir_fini(&gstate, error, eofp, eof));
}

/* ARGSUSED */
static int
pr_readdir_piddir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	int zombie = ((pnp->pr_pcommon->prc_flags & PRC_DESTROY) != 0);
	prdirent_t dirent;
	prdirent_t *dirp;
	offset_t off;
	int error;

	ASSERT(pnp->pr_type == PR_PIDDIR);

	if (uiop->uio_offset < 0 ||
	    uiop->uio_offset % sizeof (prdirent_t) != 0 ||
	    uiop->uio_resid < sizeof (prdirent_t))
		return (EINVAL);
	if (pnp->pr_pcommon->prc_proc == NULL)
		return (ENOENT);
	if (uiop->uio_offset >= sizeof (piddir))
		goto out;

	/*
	 * Loop until user's request is satisfied, omitting some
	 * files along the way if the process is a zombie.
	 */
	for (dirp = &piddir[uiop->uio_offset / sizeof (prdirent_t)];
	    uiop->uio_resid >= sizeof (prdirent_t) &&
	    dirp < &piddir[NPIDDIRFILES+2];
	    uiop->uio_offset = off + sizeof (prdirent_t), dirp++) {
		off = uiop->uio_offset;
		if (zombie) {
			switch (dirp->d_ino) {
			case PR_PIDDIR:
			case PR_PROCDIR:
			case PR_PSINFO:
			case PR_USAGE:
				break;
			default:
				continue;
			}
		}
		bcopy(dirp, &dirent, sizeof (prdirent_t));
		if (dirent.d_ino == PR_PROCDIR)
			dirent.d_ino = PRROOTINO;
		else
			dirent.d_ino = pmkino(0, pnp->pr_pcommon->prc_slot,
			    dirent.d_ino);
		if ((error = uiomove((caddr_t)&dirent, sizeof (prdirent_t),
		    UIO_READ, uiop)) != 0)
			return (error);
	}
out:
	if (eofp)
		*eofp = (uiop->uio_offset >= sizeof (piddir));
	return (0);
}

static void
rebuild_objdir(struct as *as)
{
	struct seg *seg;
	vnode_t *vp;
	vattr_t vattr;
	vnode_t **dir;
	ulong_t nalloc;
	ulong_t nentries;
	int i, j;
	ulong_t nold, nnew;

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));

	if (as->a_updatedir == 0 && as->a_objectdir != NULL)
		return;
	as->a_updatedir = 0;

	if ((nalloc = avl_numnodes(&as->a_segtree)) == 0 ||
	    (seg = AS_SEGFIRST(as)) == NULL)	/* can't happen? */
		return;

	/*
	 * Allocate space for the new object directory.
	 * (This is usually about two times too many entries.)
	 */
	nalloc = (nalloc + 0xf) & ~0xf;		/* multiple of 16 */
	dir = kmem_zalloc(nalloc * sizeof (vnode_t *), KM_SLEEP);

	/* fill in the new directory with desired entries */
	nentries = 0;
	do {
		vattr.va_mask = AT_FSID|AT_NODEID;
		if (seg->s_ops == &segvn_ops &&
		    SEGOP_GETVP(seg, seg->s_base, &vp) == 0 &&
		    vp != NULL && vp->v_type == VREG &&
		    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {
			for (i = 0; i < nentries; i++)
				if (vp == dir[i])
					break;
			if (i == nentries) {
				ASSERT(nentries < nalloc);
				dir[nentries++] = vp;
			}
		}
	} while ((seg = AS_SEGNEXT(as, seg)) != NULL);

	if (as->a_objectdir == NULL) {	/* first time */
		as->a_objectdir = dir;
		as->a_sizedir = nalloc;
		return;
	}

	/*
	 * Null out all of the defunct entries in the old directory.
	 */
	nold = 0;
	nnew = nentries;
	for (i = 0; i < as->a_sizedir; i++) {
		if ((vp = as->a_objectdir[i]) != NULL) {
			for (j = 0; j < nentries; j++) {
				if (vp == dir[j]) {
					dir[j] = NULL;
					nnew--;
					break;
				}
			}
			if (j == nentries)
				as->a_objectdir[i] = NULL;
			else
				nold++;
		}
	}

	if (nold + nnew > as->a_sizedir) {
		/*
		 * Reallocate the old directory to have enough
		 * space for the old and new entries combined.
		 * Round up to the next multiple of 16.
		 */
		ulong_t newsize = (nold + nnew + 0xf) & ~0xf;
		vnode_t **newdir = kmem_zalloc(newsize * sizeof (vnode_t *),
		    KM_SLEEP);
		bcopy(as->a_objectdir, newdir,
		    as->a_sizedir * sizeof (vnode_t *));
		kmem_free(as->a_objectdir, as->a_sizedir * sizeof (vnode_t *));
		as->a_objectdir = newdir;
		as->a_sizedir = newsize;
	}

	/*
	 * Move all new entries to the old directory and
	 * deallocate the space used by the new directory.
	 */
	if (nnew) {
		for (i = 0, j = 0; i < nentries; i++) {
			if ((vp = dir[i]) == NULL)
				continue;
			for (; j < as->a_sizedir; j++) {
				if (as->a_objectdir[j] != NULL)
					continue;
				as->a_objectdir[j++] = vp;
				break;
			}
		}
	}
	kmem_free(dir, nalloc * sizeof (vnode_t *));
}

/*
 * Return the vnode from a slot in the process's object directory.
 * The caller must have locked the process's address space.
 * The only caller is below, in pr_readdir_objectdir().
 */
static vnode_t *
obj_entry(struct as *as, int slot)
{
	ASSERT(AS_LOCK_HELD(as, &as->a_lock));
	if (as->a_objectdir == NULL)
		return (NULL);
	ASSERT(slot < as->a_sizedir);
	return (as->a_objectdir[slot]);
}

/* ARGSUSED */
static int
pr_readdir_objectdir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	gfs_readdir_state_t gstate;
	int error, eof = 0;
	offset_t n;
	int pslot;
	size_t objdirsize;
	proc_t *p;
	struct as *as;
	vnode_t *vp;

	ASSERT(pnp->pr_type == PR_OBJECTDIR);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;
	pslot = p->p_slot;

	/*
	 * We drop p_lock before grabbing the address space lock
	 * in order to avoid a deadlock with the clock thread.
	 * The process will not disappear and its address space
	 * will not change because it is marked P_PR_LOCK.
	 */
	mutex_exit(&p->p_lock);

	if ((error = gfs_readdir_init(&gstate, 64, PRSDSIZE, uiop,
	    pmkino(0, pslot, PR_PIDDIR),
	    pmkino(0, pslot, PR_OBJECTDIR), 0)) != 0) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		return (error);
	}

	if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
		as = NULL;
		objdirsize = 0;
	}

	/*
	 * Loop until user's request is satisfied or until
	 * all mapped objects have been examined. Cannot hold
	 * the address space lock for the following call as
	 * gfs_readdir_pred() utimately causes a call to uiomove().
	 */
	while ((error = gfs_readdir_pred(&gstate, uiop, &n)) == 0) {
		vattr_t vattr;
		char str[64];

		/*
		 * Set the correct size of the directory just
		 * in case the process has changed it's address
		 * space via mmap/munmap calls.
		 */
		if (as != NULL) {
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
			if (as->a_updatedir)
				rebuild_objdir(as);
			objdirsize = as->a_sizedir;
		}

		/*
		 * Find next object.
		 */
		vattr.va_mask = AT_FSID | AT_NODEID;
		while (n < objdirsize && (((vp = obj_entry(as, n)) == NULL) ||
		    (VOP_GETATTR(vp, &vattr, 0, CRED(), NULL)
		    != 0))) {
			vattr.va_mask = AT_FSID | AT_NODEID;
			n++;
		}

		if (as != NULL)
			AS_LOCK_EXIT(as, &as->a_lock);

		/*
		 * Stop when all objects have been reported.
		 */
		if (n >= objdirsize) {
			eof = 1;
			break;
		}

		if (vp == p->p_exec)
			(void) strcpy(str, "a.out");
		else
			pr_object_name(str, vp, &vattr);

		error = gfs_readdir_emit(&gstate, uiop, n, vattr.va_nodeid,
		    str, 0);

		if (error)
			break;
	}

	mutex_enter(&p->p_lock);
	prunlock(pnp);

	return (gfs_readdir_fini(&gstate, error, eofp, eof));
}

/* ARGSUSED */
static int
pr_readdir_lwpdir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	gfs_readdir_state_t gstate;
	int error, eof = 0;
	offset_t tslot;
	proc_t *p;
	int pslot;
	lwpdir_t *lwpdir;
	int lwpdirsize;

	ASSERT(pnp->pr_type == PR_LWPDIR);

	p = pr_p_lock(pnp);
	mutex_exit(&pr_pidlock);
	if (p == NULL)
		return (ENOENT);
	ASSERT(p == pnp->pr_common->prc_proc);
	pslot = p->p_slot;
	lwpdir = p->p_lwpdir;
	lwpdirsize = p->p_lwpdir_sz;

	/*
	 * Drop p->p_lock so we can safely do uiomove().
	 * The lwp directory will not change because
	 * we have the process locked with P_PR_LOCK.
	 */
	mutex_exit(&p->p_lock);


	if ((error = gfs_readdir_init(&gstate, PLNSIZ, PRSDSIZE, uiop,
	    pmkino(0, pslot, PR_PIDDIR),
	    pmkino(0, pslot, PR_LWPDIR), 0)) != 0) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		return (error);
	}

	/*
	 * Loop until user's request is satisfied or until all lwps
	 * have been examined.
	 */
	while ((error = gfs_readdir_pred(&gstate, uiop, &tslot)) == 0) {
		lwpent_t *lep;
		uint_t tid;

		/*
		 * Find next LWP.
		 */
		while (tslot < lwpdirsize &&
		    ((lep = lwpdir[tslot].ld_entry) == NULL))
			tslot++;
		/*
		 * Stop when all lwps have been reported.
		 */
		if (tslot >= lwpdirsize) {
			eof = 1;
			break;
		}

		tid = lep->le_lwpid;
		error = gfs_readdir_emitn(&gstate, uiop, tslot,
		    pmkino(tslot, pslot, PR_LWPIDDIR), tid);
		if (error)
			break;
	}

	mutex_enter(&p->p_lock);
	prunlock(pnp);

	return (gfs_readdir_fini(&gstate, error, eofp, eof));
}

/* ARGSUSED */
static int
pr_readdir_lwpiddir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	prcommon_t *pcp = pnp->pr_common;
	int zombie = ((pcp->prc_flags & PRC_DESTROY) != 0);
	prdirent_t dirent;
	prdirent_t *dirp;
	offset_t off;
	int error;
	int pslot;
	int tslot;

	ASSERT(pnp->pr_type == PR_LWPIDDIR);

	if (uiop->uio_offset < 0 ||
	    uiop->uio_offset % sizeof (prdirent_t) != 0 ||
	    uiop->uio_resid < sizeof (prdirent_t))
		return (EINVAL);
	if (pcp->prc_proc == NULL || pcp->prc_tslot == -1)
		return (ENOENT);
	if (uiop->uio_offset >= sizeof (lwpiddir))
		goto out;

	/*
	 * Loop until user's request is satisfied, omitting some files
	 * along the way if the lwp is a zombie and also depending
	 * on the data model of the process.
	 */
	pslot = pcp->prc_slot;
	tslot = pcp->prc_tslot;
	for (dirp = &lwpiddir[uiop->uio_offset / sizeof (prdirent_t)];
	    uiop->uio_resid >= sizeof (prdirent_t) &&
	    dirp < &lwpiddir[NLWPIDDIRFILES+2];
	    uiop->uio_offset = off + sizeof (prdirent_t), dirp++) {
		off = uiop->uio_offset;
		if (zombie) {
			switch (dirp->d_ino) {
			case PR_LWPIDDIR:
			case PR_LWPDIR:
			case PR_LWPSINFO:
				break;
			default:
				continue;
			}
		}
#if defined(__sparc)
		/* the asrs file exists only for sparc v9 _LP64 processes */
		if (dirp->d_ino == PR_ASRS &&
		    pcp->prc_datamodel != DATAMODEL_LP64)
			continue;
#endif
		bcopy(dirp, &dirent, sizeof (prdirent_t));
		if (dirent.d_ino == PR_LWPDIR)
			dirent.d_ino = pmkino(0, pslot, dirp->d_ino);
		else
			dirent.d_ino = pmkino(tslot, pslot, dirp->d_ino);
		if ((error = uiomove((caddr_t)&dirent, sizeof (prdirent_t),
		    UIO_READ, uiop)) != 0)
			return (error);
	}
out:
	if (eofp)
		*eofp = (uiop->uio_offset >= sizeof (lwpiddir));
	return (0);
}

/* ARGSUSED */
static int
pr_readdir_fddir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	gfs_readdir_state_t gstate;
	int error, eof = 0;
	offset_t n;
	proc_t *p;
	int pslot;
	int fddirsize;
	uf_info_t *fip;

	ASSERT(pnp->pr_type == PR_FDDIR);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;
	pslot = p->p_slot;
	fip = P_FINFO(p);
	mutex_exit(&p->p_lock);

	if ((error = gfs_readdir_init(&gstate, PLNSIZ, PRSDSIZE, uiop,
	    pmkino(0, pslot, PR_PIDDIR), pmkino(0, pslot, PR_FDDIR), 0)) != 0) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		return (error);
	}

	mutex_enter(&fip->fi_lock);
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		fddirsize = 0;
	else
		fddirsize = fip->fi_nfiles;

	/*
	 * Loop until user's request is satisfied or until
	 * all file descriptors have been examined.
	 */
	while ((error = gfs_readdir_pred(&gstate, uiop, &n)) == 0) {
		/*
		 * Find next fd.
		 */
		while (n < fddirsize && fip->fi_list[n].uf_file == NULL)
			n++;
		/*
		 * Stop when all fds have been reported.
		 */
		if (n >= fddirsize) {
			eof = 1;
			break;
		}

		error = gfs_readdir_emitn(&gstate, uiop, n,
		    pmkino(n, pslot, PR_FD), n);
		if (error)
			break;
	}

	mutex_exit(&fip->fi_lock);
	mutex_enter(&p->p_lock);
	prunlock(pnp);

	return (gfs_readdir_fini(&gstate, error, eofp, eof));
}

/* ARGSUSED */
static int
pr_readdir_pathdir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	longlong_t bp[DIRENT64_RECLEN(64) / sizeof (longlong_t)];
	dirent64_t *dirent = (dirent64_t *)bp;
	int reclen;
	ssize_t oresid;
	offset_t off, idx;
	int error = 0;
	proc_t *p;
	int fd, obj;
	int pslot;
	int fddirsize;
	uf_info_t *fip;
	struct as *as = NULL;
	size_t objdirsize;
	vattr_t vattr;
	vnode_t *vp;

	ASSERT(pnp->pr_type == PR_PATHDIR);

	if (uiop->uio_offset < 0 ||
	    uiop->uio_resid <= 0 ||
	    (uiop->uio_offset % PRSDSIZE) != 0)
		return (EINVAL);
	oresid = uiop->uio_resid;
	bzero(bp, sizeof (bp));

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;
	fip = P_FINFO(p);
	pslot = p->p_slot;
	mutex_exit(&p->p_lock);

	if ((p->p_flag & SSYS) || (as = p->p_as) == &kas) {
		as = NULL;
		objdirsize = 0;
	} else {
		AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
		if (as->a_updatedir)
			rebuild_objdir(as);
		objdirsize = as->a_sizedir;
		AS_LOCK_EXIT(as, &as->a_lock);
		as = NULL;
	}

	mutex_enter(&fip->fi_lock);
	if ((p->p_flag & SSYS) || p->p_as == &kas)
		fddirsize = 0;
	else
		fddirsize = fip->fi_nfiles;

	for (; uiop->uio_resid > 0; uiop->uio_offset = off + PRSDSIZE) {
		/*
		 * There are 4 special files in the path directory: ".", "..",
		 * "root", and "cwd".  We handle those specially here.
		 */
		off = uiop->uio_offset;
		idx = off / PRSDSIZE;
		if (off == 0) {				/* "." */
			dirent->d_ino = pmkino(0, pslot, PR_PATHDIR);
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '\0';
			reclen = DIRENT64_RECLEN(1);
		} else if (idx == 1) {			/* ".." */
			dirent->d_ino = pmkino(0, pslot, PR_PIDDIR);
			dirent->d_name[0] = '.';
			dirent->d_name[1] = '.';
			dirent->d_name[2] = '\0';
			reclen = DIRENT64_RECLEN(2);
		} else if (idx == 2) {			/* "root" */
			dirent->d_ino = pmkino(idx, pslot, PR_PATH);
			(void) strcpy(dirent->d_name, "root");
			reclen = DIRENT64_RECLEN(4);
		} else if (idx == 3) {			/* "cwd" */
			dirent->d_ino = pmkino(idx, pslot, PR_PATH);
			(void) strcpy(dirent->d_name, "cwd");
			reclen = DIRENT64_RECLEN(3);
		} else if (idx < 4 + fddirsize) {
			/*
			 * In this case, we have one of the file descriptors.
			 */
			fd = idx - 4;
			if (fip->fi_list[fd].uf_file == NULL)
				continue;
			dirent->d_ino = pmkino(idx, pslot, PR_PATH);
			(void) pr_u32tos(fd, dirent->d_name, PLNSIZ+1);
			reclen = DIRENT64_RECLEN(PLNSIZ);
		} else if (idx < 4 + fddirsize + objdirsize) {
			if (fip != NULL) {
				mutex_exit(&fip->fi_lock);
				fip = NULL;
			}

			/*
			 * We drop p_lock before grabbing the address space lock
			 * in order to avoid a deadlock with the clock thread.
			 * The process will not disappear and its address space
			 * will not change because it is marked P_PR_LOCK.
			 */
			if (as == NULL) {
				as = p->p_as;
				AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
			}

			if (as->a_updatedir) {
				rebuild_objdir(as);
				objdirsize = as->a_sizedir;
			}

			obj = idx - 4 - fddirsize;
			if ((vp = obj_entry(as, obj)) == NULL)
				continue;
			vattr.va_mask = AT_FSID|AT_NODEID;
			if (VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) != 0)
				continue;
			if (vp == p->p_exec)
				(void) strcpy(dirent->d_name, "a.out");
			else
				pr_object_name(dirent->d_name, vp, &vattr);
			dirent->d_ino = pmkino(idx, pslot, PR_PATH);
			reclen = DIRENT64_RECLEN(strlen(dirent->d_name));
		} else {
			break;
		}

		dirent->d_off = uiop->uio_offset + PRSDSIZE;
		dirent->d_reclen = (ushort_t)reclen;
		if (reclen > uiop->uio_resid) {
			/*
			 * Error if no entries have been returned yet.
			 */
			if (uiop->uio_resid == oresid)
				error = EINVAL;
			break;
		}
		/*
		 * Drop the address space lock to do the uiomove().
		 */
		if (as != NULL)
			AS_LOCK_EXIT(as, &as->a_lock);

		error = uiomove((caddr_t)dirent, reclen, UIO_READ, uiop);
		if (as != NULL)
			AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);

		if (error)
			break;
	}

	if (error == 0 && eofp)
		*eofp = (uiop->uio_offset >= (fddirsize + 2) * PRSDSIZE);

	if (fip != NULL)
		mutex_exit(&fip->fi_lock);
	if (as != NULL)
		AS_LOCK_EXIT(as, &as->a_lock);
	mutex_enter(&p->p_lock);
	prunlock(pnp);
	return (error);
}

static int
pr_readdir_tmpldir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	proc_t *p;
	int pslot, tslot;
	gfs_readdir_state_t gstate;
	int error, eof = 0;
	offset_t n;

	ASSERT(pnp->pr_type == PR_TMPLDIR);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;
	pslot = pnp->pr_common->prc_slot;
	tslot = pnp->pr_common->prc_tslot;
	mutex_exit(&p->p_lock);

	if ((error = gfs_readdir_init(&gstate, PRDIRSIZE, PRSDSIZE, uiop,
	    pmkino(tslot, pslot, PR_LWPDIR),
	    pmkino(tslot, pslot, PR_TMPLDIR), 0)) != 0) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		return (error);
	}

	while ((error = gfs_readdir_pred(&gstate, uiop, &n)) == 0) {
		/*
		 * Check for an active template.  Reading a directory's
		 * contents is already racy, so we don't bother taking
		 * any locks.
		 */
		while (n < ct_ntypes &&
		    pnp->pr_common->prc_thread->t_lwp->lwp_ct_active[n] == NULL)
			n++;
		/*
		 * Stop when all types have been reported.
		 */
		if (n >= ct_ntypes) {
			eof = 1;
			break;
		}
		/*
		 * The pmkino invocation below will need to be updated
		 * when we create our fifth contract type.
		 */
		ASSERT(ct_ntypes <= 4);
		error = gfs_readdir_emit(&gstate, uiop, n,
		    pmkino((tslot << 2) | n, pslot, PR_TMPL),
		    ct_types[n]->ct_type_name, 0);
		if (error)
			break;
	}

	mutex_enter(&p->p_lock);
	prunlock(pnp);

	return (gfs_readdir_fini(&gstate, error, eofp, eof));
}

static int
pr_readdir_ctdir(prnode_t *pnp, uio_t *uiop, int *eofp)
{
	proc_t *p;
	int pslot;
	gfs_readdir_state_t gstate;
	int error, eof = 0;
	offset_t n;
	uint64_t zid;

	ASSERT(pnp->pr_type == PR_CTDIR);

	if ((error = prlock(pnp, ZNO)) != 0)
		return (error);
	p = pnp->pr_common->prc_proc;
	pslot = p->p_slot;
	mutex_exit(&p->p_lock);

	if ((error = gfs_readdir_init(&gstate, PRDIRSIZE, PRSDSIZE, uiop,
	    pmkino(0, pslot, PR_PIDDIR), pmkino(0, pslot, PR_CTDIR), 0)) != 0) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		return (error);
	}

	zid = VTOZONE(pnp->pr_vnode)->zone_uniqid;
	while ((error = gfs_readdir_pred(&gstate, uiop, &n)) == 0) {
		id_t next = contract_plookup(p, n, zid);
		if (next == -1) {
			eof = 1;
			break;
		}
		error = gfs_readdir_emitn(&gstate, uiop, next,
		    pmkino(next, pslot, PR_CT), next);
		if (error)
			break;
	}

	mutex_enter(&p->p_lock);
	prunlock(pnp);

	return (gfs_readdir_fini(&gstate, error, eofp, eof));
}

/* ARGSUSED */
static int
prfsync(vnode_t *vp, int syncflag, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/*
 * Utility: remove a /proc vnode from a linked list, threaded through pr_next.
 */
static void
pr_list_unlink(vnode_t *pvp, vnode_t **listp)
{
	vnode_t *vp;
	prnode_t *pnp;

	while ((vp = *listp) != NULL) {
		pnp = VTOP(vp);
		if (vp == pvp) {
			*listp = pnp->pr_next;
			pnp->pr_next = NULL;
			break;
		}
		listp = &pnp->pr_next;
	}
}

/* ARGSUSED */
static void
prinactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	prnode_t *pnp = VTOP(vp);
	prnodetype_t type = pnp->pr_type;
	proc_t *p;
	vnode_t *dp;
	vnode_t *ovp = NULL;
	prnode_t *opnp = NULL;

	switch (type) {
	case PR_OBJECT:
	case PR_FD:
	case PR_SELF:
	case PR_PATH:
		/* These are not linked into the usual lists */
		ASSERT(vp->v_count == 1);
		if ((dp = pnp->pr_parent) != NULL)
			VN_RELE(dp);
		prfreenode(pnp);
		return;
	default:
		break;
	}

	mutex_enter(&pr_pidlock);
	if (pnp->pr_pcommon == NULL)
		p = NULL;
	else if ((p = pnp->pr_pcommon->prc_proc) != NULL)
		mutex_enter(&p->p_lock);
	mutex_enter(&vp->v_lock);

	if (type == PR_PROCDIR || vp->v_count > 1) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		if (p != NULL)
			mutex_exit(&p->p_lock);
		mutex_exit(&pr_pidlock);
		return;
	}

	if ((dp = pnp->pr_parent) != NULL) {
		prnode_t *dpnp;

		switch (type) {
		case PR_PIDFILE:
		case PR_LWPIDFILE:
		case PR_OPAGEDATA:
			break;
		default:
			dpnp = VTOP(dp);
			mutex_enter(&dpnp->pr_mutex);
			if (dpnp->pr_files != NULL &&
			    dpnp->pr_files[pnp->pr_index] == vp)
				dpnp->pr_files[pnp->pr_index] = NULL;
			mutex_exit(&dpnp->pr_mutex);
			break;
		}
		pnp->pr_parent = NULL;
	}

	ASSERT(vp->v_count == 1);

	/*
	 * If we allocated an old /proc/pid node, free it too.
	 */
	if (pnp->pr_pidfile != NULL) {
		ASSERT(type == PR_PIDDIR);
		ovp = pnp->pr_pidfile;
		opnp = VTOP(ovp);
		ASSERT(opnp->pr_type == PR_PIDFILE);
		pnp->pr_pidfile = NULL;
	}

	mutex_exit(&pr_pidlock);

	if (p != NULL) {
		/*
		 * Remove the vnodes from the lists of
		 * /proc vnodes for the process.
		 */
		int slot;

		switch (type) {
		case PR_PIDDIR:
			pr_list_unlink(vp, &p->p_trace);
			break;
		case PR_LWPIDDIR:
			if ((slot = pnp->pr_common->prc_tslot) != -1) {
				lwpent_t *lep = p->p_lwpdir[slot].ld_entry;
				pr_list_unlink(vp, &lep->le_trace);
			}
			break;
		default:
			pr_list_unlink(vp, &p->p_plist);
			break;
		}
		if (ovp != NULL)
			pr_list_unlink(ovp, &p->p_plist);
		mutex_exit(&p->p_lock);
	}

	mutex_exit(&vp->v_lock);

	if (type == PR_CT && pnp->pr_contract != NULL) {
		contract_rele(pnp->pr_contract);
		pnp->pr_contract = NULL;
	}

	if (opnp != NULL)
		prfreenode(opnp);
	prfreenode(pnp);
	if (dp != NULL) {
		VN_RELE(dp);
	}
}

/* ARGSUSED */
static int
prseek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	return (0);
}

/*
 * We use the p_execdir member of proc_t to expand the %d token in core file
 * paths (the directory path for the executable that dumped core; see
 * coreadm(1M) for details). We'd like gcore(1) to be able to expand %d in
 * the same way as core dumping from the kernel, but there's no convenient
 * and comprehensible way to export the path name for p_execdir. To solve
 * this, we try to find the actual path to the executable that was used. In
 * pr_lookup_pathdir(), we mark the a.out path name vnode with the PR_AOUT
 * flag, and use that here to indicate that more work is needed beyond the
 * call to vnodetopath().
 */
static int
prreadlink_lookup(prnode_t *pnp, char *buf, size_t size, cred_t *cr)
{
	proc_t *p;
	vnode_t *vp, *execvp, *vrootp;
	int ret;
	size_t len;
	dirent64_t *dp;
	size_t dlen = DIRENT64_RECLEN(MAXPATHLEN);
	char *dbuf;

	p = curproc;
	mutex_enter(&p->p_lock);
	if ((vrootp = PTOU(p)->u_rdir) == NULL)
		vrootp = rootdir;
	VN_HOLD(vrootp);
	mutex_exit(&p->p_lock);

	ret = vnodetopath(vrootp, pnp->pr_realvp, buf, size, cr);

	/*
	 * If PR_AOUT isn't set, then we looked up the path for the vnode;
	 * otherwise, we looked up the path for (what we believe to be) the
	 * containing directory.
	 */
	if ((pnp->pr_flags & PR_AOUT) == 0) {
		VN_RELE(vrootp);
		return (ret);
	}

	/*
	 * Fail if there's a problem locking the process. This will only
	 * occur if the process is changing so the information we would
	 * report would already be invalid.
	 */
	if (prlock(pnp, ZNO) != 0) {
		VN_RELE(vrootp);
		return (EIO);
	}

	p = pnp->pr_common->prc_proc;
	mutex_exit(&p->p_lock);

	execvp = p->p_exec;
	VN_HOLD(execvp);

	/*
	 * If our initial lookup of the directory failed, fall back to
	 * the path name information for p_exec.
	 */
	if (ret != 0) {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
		ret = vnodetopath(vrootp, execvp, buf, size, cr);
		VN_RELE(execvp);
		VN_RELE(vrootp);
		return (ret);
	}

	len = strlen(buf);

	/*
	 * We use u_comm as a guess for the last component of the full
	 * executable path name. If there isn't going to be enough space
	 * we fall back to using the p_exec so that we can have _an_
	 * answer even if it's not perfect.
	 */
	if (strlen(PTOU(p)->u_comm) + len + 1 < size) {
		buf[len] = '/';
		(void) strcpy(buf + len + 1, PTOU(p)->u_comm);
		mutex_enter(&p->p_lock);
		prunlock(pnp);

		/*
		 * Do a forward lookup of our u_comm guess.
		 */
		if (lookupnameat(buf + len + 1, UIO_SYSSPACE, FOLLOW, NULLVPP,
		    &vp, pnp->pr_realvp) == 0) {
			if (vn_compare(vp, execvp)) {
				VN_RELE(vp);
				VN_RELE(execvp);
				VN_RELE(vrootp);
				return (0);
			}

			VN_RELE(vp);
		}
	} else {
		mutex_enter(&p->p_lock);
		prunlock(pnp);
	}

	dbuf = kmem_alloc(dlen, KM_SLEEP);

	/*
	 * Try to find a matching vnode by iterating through the directory's
	 * entries. If that fails, fall back to the path information for
	 * p_exec.
	 */
	if ((ret = dirfindvp(vrootp, pnp->pr_realvp, execvp, cr, dbuf,
	    dlen, &dp)) == 0 && strlen(dp->d_name) + len + 1 < size) {
		buf[len] = '/';
		(void) strcpy(buf + len + 1, dp->d_name);
	} else {
		ret = vnodetopath(vrootp, execvp, buf, size, cr);
	}

	kmem_free(dbuf, dlen);
	VN_RELE(execvp);
	VN_RELE(vrootp);

	return (ret);
}

/* ARGSUSED */
static int
prreadlink(vnode_t *vp, uio_t *uiop, cred_t *cr, caller_context_t *ctp)
{
	prnode_t *pnp = VTOP(vp);
	char *buf;
	int ret = EINVAL;
	char idbuf[16];
	int length, rlength;
	contract_t *ct;

	switch (pnp->pr_type) {
	case PR_SELF:
		(void) snprintf(idbuf, sizeof (idbuf), "%d", curproc->p_pid);
		ret = uiomove(idbuf, strlen(idbuf), UIO_READ, uiop);
		break;
	case PR_OBJECT:
	case PR_FD:
	case PR_CURDIR:
	case PR_ROOTDIR:
		if (pnp->pr_realvp->v_type == VDIR)
			ret = 0;
		break;
	case PR_PATH:
		buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if ((ret = prreadlink_lookup(pnp, buf, MAXPATHLEN, cr)) == 0)
			ret = uiomove(buf, strlen(buf), UIO_READ, uiop);

		kmem_free(buf, MAXPATHLEN);
		break;
	case PR_CT:
		ASSERT(pnp->pr_contract != NULL);
		ct = pnp->pr_contract;
		length = sizeof (CTFS_ROOT "//") + sizeof (idbuf) +
		    strlen(ct->ct_type->ct_type_name);
		buf = kmem_alloc(length, KM_SLEEP);
		rlength = snprintf(buf, length, CTFS_ROOT "/%s/%d",
		    ct->ct_type->ct_type_name, ct->ct_id);
		ASSERT(rlength < length);
		ret = uiomove(buf, rlength, UIO_READ, uiop);
		kmem_free(buf, length);
		break;
	default:
		break;
	}

	return (ret);
}

/*ARGSUSED2*/
static int
prcmp(vnode_t *vp1, vnode_t *vp2, caller_context_t *ct)
{
	prnode_t *pp1, *pp2;

	if (vp1 == vp2)
		return (1);

	if (!vn_matchops(vp1, prvnodeops) || !vn_matchops(vp2, prvnodeops))
		return (0);

	pp1 = VTOP(vp1);
	pp2 = VTOP(vp2);

	if (pp1->pr_type != pp2->pr_type)
		return (0);
	if (pp1->pr_type == PR_PROCDIR)
		return (1);
	if (pp1->pr_ino || pp2->pr_ino)
		return (pp2->pr_ino == pp1->pr_ino);

	if (pp1->pr_common == NULL || pp2->pr_common == NULL)
		return (0);

	return (pp1->pr_common->prc_slot == pp2->pr_common->prc_slot &&
	    pp1->pr_common->prc_tslot == pp2->pr_common->prc_tslot);
}

static int
prrealvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	vnode_t *rvp;

	if ((rvp = VTOP(vp)->pr_realvp) != NULL) {
		vp = rvp;
		if (VOP_REALVP(vp, &rvp, ct) == 0)
			vp = rvp;
	}

	*vpp = vp;
	return (0);
}

/*
 * Return the answer requested to poll().
 * POLLIN, POLLRDNORM, and POLLOUT are recognized as in fs_poll().
 * In addition, these have special meaning for /proc files:
 *	POLLPRI		process or lwp stopped on an event of interest
 *	POLLERR		/proc file descriptor is invalid
 *	POLLHUP		process or lwp has terminated
 */
/*ARGSUSED5*/
static int
prpoll(vnode_t *vp, short events, int anyyet, short *reventsp,
	pollhead_t **phpp, caller_context_t *ct)
{
	prnode_t *pnp = VTOP(vp);
	prcommon_t *pcp = pnp->pr_common;
	pollhead_t *php = &pcp->prc_pollhead;
	proc_t *p;
	short revents;
	int error;
	int lockstate;

	ASSERT(pnp->pr_type < PR_NFILES);

	/*
	 * Support for old /proc interface.
	 */
	if (pnp->pr_pidfile != NULL) {
		vp = pnp->pr_pidfile;
		pnp = VTOP(vp);
		ASSERT(pnp->pr_type == PR_PIDFILE);
		ASSERT(pnp->pr_common == pcp);
	}

	*reventsp = revents = 0;
	*phpp = (pollhead_t *)NULL;

	if (vp->v_type == VDIR) {
		*reventsp |= POLLNVAL;
		return (0);
	}

	lockstate = pollunlock();	/* avoid deadlock with prnotify() */

	if ((error = prlock(pnp, ZNO)) != 0) {
		pollrelock(lockstate);
		switch (error) {
		case ENOENT:		/* process or lwp died */
			*reventsp = POLLHUP;
			error = 0;
			break;
		case EAGAIN:		/* invalidated */
			*reventsp = POLLERR;
			error = 0;
			break;
		}
		return (error);
	}

	/*
	 * We have the process marked locked (P_PR_LOCK) and we are holding
	 * its p->p_lock.  We want to unmark the process but retain
	 * exclusive control w.r.t. other /proc controlling processes
	 * before reacquiring the polling locks.
	 *
	 * prunmark() does this for us.  It unmarks the process
	 * but retains p->p_lock so we still have exclusive control.
	 * We will drop p->p_lock at the end to relinquish control.
	 *
	 * We cannot call prunlock() at the end to relinquish control
	 * because prunlock(), like prunmark(), may drop and reacquire
	 * p->p_lock and that would lead to a lock order violation
	 * w.r.t. the polling locks we are about to reacquire.
	 */
	p = pcp->prc_proc;
	ASSERT(p != NULL);
	prunmark(p);

	pollrelock(lockstate);		/* reacquire dropped poll locks */

	if ((p->p_flag & SSYS) || p->p_as == &kas)
		revents = POLLNVAL;
	else {
		short ev;

		if ((ev = (events & (POLLIN|POLLRDNORM))) != 0)
			revents |= ev;
		/*
		 * POLLWRNORM (same as POLLOUT) really should not be
		 * used to indicate that the process or lwp stopped.
		 * However, USL chose to use POLLWRNORM rather than
		 * POLLPRI to indicate this, so we just accept either
		 * requested event to indicate stopped.  (grr...)
		 */
		if ((ev = (events & (POLLPRI|POLLOUT|POLLWRNORM))) != 0) {
			kthread_t *t;

			if (pcp->prc_flags & PRC_LWP) {
				t = pcp->prc_thread;
				ASSERT(t != NULL);
				thread_lock(t);
			} else {
				t = prchoose(p);	/* returns locked t */
				ASSERT(t != NULL);
			}

			if (ISTOPPED(t) || VSTOPPED(t))
				revents |= ev;
			thread_unlock(t);
		}
	}

	*reventsp = revents;
	if ((!anyyet && revents == 0) || (events & POLLET)) {
		/*
		 * Arrange to wake up the polling lwp when
		 * the target process/lwp stops or terminates
		 * or when the file descriptor becomes invalid.
		 */
		pcp->prc_flags |= PRC_POLL;
		*phpp = php;
	}
	mutex_exit(&p->p_lock);
	return (0);
}

/* in prioctl.c */
extern int prioctl(vnode_t *, int, intptr_t, int, cred_t *, int *,
	caller_context_t *);

/*
 * /proc vnode operations vector
 */
const fs_operation_def_t pr_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = propen },
	VOPNAME_CLOSE,		{ .vop_close = prclose },
	VOPNAME_READ,		{ .vop_read = prread },
	VOPNAME_WRITE,		{ .vop_write = prwrite },
	VOPNAME_IOCTL,		{ .vop_ioctl = prioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = prgetattr },
	VOPNAME_ACCESS,		{ .vop_access = praccess },
	VOPNAME_LOOKUP,		{ .vop_lookup = prlookup },
	VOPNAME_CREATE,		{ .vop_create = prcreate },
	VOPNAME_READDIR,	{ .vop_readdir = prreaddir },
	VOPNAME_READLINK,	{ .vop_readlink = prreadlink },
	VOPNAME_FSYNC,		{ .vop_fsync = prfsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = prinactive },
	VOPNAME_SEEK,		{ .vop_seek = prseek },
	VOPNAME_CMP,		{ .vop_cmp = prcmp },
	VOPNAME_FRLOCK,		{ .error = fs_error },
	VOPNAME_REALVP,		{ .vop_realvp = prrealvp },
	VOPNAME_POLL,		{ .vop_poll = prpoll },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	NULL,			NULL
};
