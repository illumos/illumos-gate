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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains the audit hook support code for auditing.
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/stropts.h>
#include <sys/systm.h>
#include <sys/pathname.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>
#include <sys/ipc_impl.h>
#include <sys/msg_impl.h>
#include <sys/sem_impl.h>
#include <sys/shm_impl.h>
#include <sys/kmem.h>		/* for KM_SLEEP */
#include <sys/socket.h>
#include <sys/cmn_err.h>	/* snprintf... */
#include <sys/debug.h>
#include <sys/thread.h>
#include <netinet/in.h>
#include <c2/audit.h>		/* needs to be included before user.h */
#include <c2/audit_kernel.h>	/* for M_DONTWAIT */
#include <c2/audit_kevents.h>
#include <c2/audit_record.h>
#include <sys/strsubr.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include <sys/timod.h>
#include <sys/model.h>		/* for model_t */
#include <sys/disp.h>		/* for servicing_interrupt() */
#include <sys/devpolicy.h>
#include <sys/crypto/ioctladmin.h>
#include <sys/cred_impl.h>
#include <inet/kssl/kssl.h>
#include <net/pfpolicy.h>

static void add_return_token(caddr_t *, unsigned int scid, int err, int rval);

static void audit_pathbuild(struct pathname *pnp);

/*
 * ROUTINE:	AUDIT_NEWPROC
 * PURPOSE:	initialize the child p_audit_data structure
 * CALLBY:	GETPROC
 * NOTE:	All threads for the parent process are locked at this point.
 *		We are essentially running singled threaded for this reason.
 *		GETPROC is called when system creates a new process.
 *		By the time AUDIT_NEWPROC is called, the child proc
 *		structure has already been initialized. What we need
 *		to do is to allocate the child p_audit_data and
 *		initialize it with the content of current parent process.
 */

void
audit_newproc(struct proc *cp)	/* initialized child proc structure */
{
	p_audit_data_t *pad;	/* child process audit data */
	p_audit_data_t *opad;	/* parent process audit data */

	pad = kmem_cache_alloc(au_pad_cache, KM_SLEEP);

	P2A(cp) = pad;

	opad = P2A(curproc);

	/*
	 * copy the audit data. Note that all threads of current
	 *   process have been "held". Thus there is no race condition
	 *   here with mutiple threads trying to alter the cwrd
	 *   structure (such as releasing it).
	 *
	 *   The audit context in the cred is "duplicated" for the new
	 *   proc by elsewhere crhold'ing the parent's cred which it shares.
	 *
	 *   We still want to hold things since auditon() [A_SETUMASK,
	 *   A_SETSMASK] could be walking through the processes to
	 *   update things.
	 */
	mutex_enter(&opad->pad_lock);	/* lock opad structure during copy */
	pad->pad_data = opad->pad_data;	/* copy parent's process audit data */
	au_pathhold(pad->pad_root);
	au_pathhold(pad->pad_cwd);
	mutex_exit(&opad->pad_lock);	/* current proc will keep cwrd open */

	/*
	 * finish auditing of parent here so that it will be done
	 * before child has a chance to run. We include the child
	 * pid since the return value in the return token is a dummy
	 * one and contains no useful information (it is included to
	 * make the audit record structure consistant).
	 *
	 * tad_flag is set if auditing is on
	 */
	if (((t_audit_data_t *)T2A(curthread))->tad_flag)
		au_uwrite(au_to_arg32(0, "child PID", (uint32_t)cp->p_pid));

	/*
	 * finish up audit record generation here because child process
	 * is set to run before parent process. We distinguish here
	 * between FORK, FORK1, or VFORK by the saved system call ID.
	 */
	audit_finish(0, ((t_audit_data_t *)T2A(curthread))->tad_scid, 0, 0);
}

/*
 * ROUTINE:	AUDIT_PFREE
 * PURPOSE:	deallocate the per-process udit data structure
 * CALLBY:	EXIT
 *		FORK_FAIL
 * NOTE:	all lwp except current one have stopped in SEXITLWPS
 * 		why we are single threaded?
 *		. all lwp except current one have stopped in SEXITLWPS.
 */
void
audit_pfree(struct proc *p)		/* proc structure to be freed */

{	/* AUDIT_PFREE */

	p_audit_data_t *pad;

	pad = P2A(p);

	/* better be a per process audit data structure */
	ASSERT(pad != (p_audit_data_t *)0);

	if (pad == pad0) {
		return;
	}

	/* deallocate all auditing resources for this process */
	au_pathrele(pad->pad_root);
	au_pathrele(pad->pad_cwd);

	/*
	 * Since the pad structure is completely overwritten after alloc,
	 * we don't bother to clear it.
	 */

	kmem_cache_free(au_pad_cache, pad);
}

/*
 * ROUTINE:	AUDIT_THREAD_CREATE
 * PURPOSE:	allocate per-process thread audit data structure
 * CALLBY:	THREAD_CREATE
 * NOTE:	This is called just after *t was bzero'd.
 *		We are single threaded in this routine.
 * TODO:
 * QUESTION:
 */

void
audit_thread_create(kthread_id_t t)
{
	t_audit_data_t *tad;	/* per-thread audit data */

	tad = kmem_zalloc(sizeof (struct t_audit_data), KM_SLEEP);

	T2A(t) = tad;		/* set up thread audit data ptr */
	tad->tad_thread = t;	/* back ptr to thread: DEBUG */
}

/*
 * ROUTINE:	AUDIT_THREAD_FREE
 * PURPOSE:	free the per-thread audit data structure
 * CALLBY:	THREAD_FREE
 * NOTE:	most thread data is clear after return
 */
void
audit_thread_free(kthread_t *t)
{
	t_audit_data_t *tad;
	au_defer_info_t	*attr;

	tad = T2A(t);

	/* thread audit data must still be set */

	if (tad == tad0) {
		return;
	}

	if (tad == NULL) {
		return;
	}

	t->t_audit_data = 0;

	/* must not have any audit record residual */
	ASSERT(tad->tad_ad == NULL);

	/* saved path must be empty */
	ASSERT(tad->tad_aupath == NULL);

	if (tad->tad_atpath)
		au_pathrele(tad->tad_atpath);

	attr = tad->tad_defer_head;
	while (attr != NULL) {
		au_defer_info_t	*tmp_attr = attr;

		au_free_rec(attr->audi_ad);

		attr = attr->audi_next;
		kmem_free(tmp_attr, sizeof (au_defer_info_t));
	}

	kmem_free(tad, sizeof (*tad));
}

/*
 * ROUTINE:	AUDIT_SAVEPATH
 * PURPOSE:
 * CALLBY:	LOOKUPPN
 *
 * NOTE:	We have reached the end of a path in fs/lookup.c.
 *		We get two pieces of information here:
 *		the vnode of the last component (vp) and
 *		the status of the last access (flag).
 * TODO:
 * QUESTION:
 */

/*ARGSUSED*/
int
audit_savepath(
	struct pathname *pnp,		/* pathname to lookup */
	struct vnode *vp,		/* vnode of the last component */
	int    flag,			/* status of the last access */
	cred_t *cr)			/* cred of requestor */
{

	t_audit_data_t *tad;	/* current thread */
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	tad = U2A(u);

	/*
	 * this event being audited or do we need path information
	 * later? This might be for a chdir/chroot or open (add path
	 * to file pointer. If the path has already been found for an
	 * open/creat then we don't need to process the path.
	 *
	 * S2E_SP (PAD_SAVPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	chroot, chdir, open, creat system call processing. It determines
	 *	if audit_savepath() will discard the path or we need it later.
	 * PAD_PATHFND means path already included in this audit record. It
	 *	is used in cases where multiple path lookups are done per
	 *	system call. The policy flag, AUDIT_PATH, controls if multiple
	 *	paths are allowed.
	 * S2E_NPT (PAD_NOPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	exit processing to inhibit any paths that may be added due to
	 *	closes.
	 */
	if ((tad->tad_flag == 0 && !(tad->tad_ctrl & PAD_SAVPATH)) ||
		((tad->tad_ctrl & PAD_PATHFND) &&
		!(kctx->auk_policy & AUDIT_PATH)) ||
		(tad->tad_ctrl & PAD_NOPATH)) {
			return (0);
	}

	tad->tad_ctrl |= PAD_NOPATH;		/* prevent possible reentry */

	audit_pathbuild(pnp);
	tad->tad_vn = vp;

	/*
	 * are we auditing only if error, or if it is not open or create
	 * otherwise audit_setf will do it
	 */

	if (tad->tad_flag) {
		if (flag && (tad->tad_scid == SYS_open ||
		    tad->tad_scid == SYS_open64 ||
		    tad->tad_scid == SYS_creat ||
		    tad->tad_scid == SYS_creat64 ||
		    tad->tad_scid == SYS_fsat)) {
			tad->tad_ctrl |= PAD_TRUE_CREATE;
		}

		/* add token to audit record for this name */
		au_uwrite(au_to_path(tad->tad_aupath));

		/* add the attributes of the object */
		if (vp) {
			/*
			 * only capture attributes when there is no error
			 * lookup will not return the vnode of the failing
			 * component.
			 *
			 * if there was a lookup error, then don't add
			 * attribute. if lookup in vn_create(),
			 * then don't add attribute,
			 * it will be added at end of vn_create().
			 */
			if (!flag && !(tad->tad_ctrl & PAD_NOATTRB))
				audit_attributes(vp);
		}
	}

	/* free up space if we're not going to save path (open, crate) */
	if ((tad->tad_ctrl & PAD_SAVPATH) == 0) {
		if (tad->tad_aupath != NULL) {
			au_pathrele(tad->tad_aupath);
			tad->tad_aupath = NULL;
			tad->tad_vn = NULL;
		}
	}
	if (tad->tad_ctrl & PAD_MLD)
		tad->tad_ctrl |= PAD_PATHFND;

	tad->tad_ctrl &= ~PAD_NOPATH;		/* restore */
	return (0);
}

static void
audit_pathbuild(struct pathname *pnp)
{
	char *pp;	/* pointer to path */
	int len;	/* length of incoming segment */
	int newsect;	/* path requires a new section */
	struct audit_path	*pfxapp;	/* prefix for path */
	struct audit_path	*newapp;	/* new audit_path */
	t_audit_data_t *tad;	/* current thread */
	p_audit_data_t *pad;	/* current process */

	tad = U2A(u);
	ASSERT(tad != NULL);
	pad = P2A(curproc);
	ASSERT(pad != NULL);

	len = (pnp->pn_path - pnp->pn_buf) + 1;		/* +1 for terminator */
	ASSERT(len > 0);

	/* adjust for path prefix: tad_aupath, ATPATH, CRD, or CWD */
	mutex_enter(&pad->pad_lock);
	if (tad->tad_aupath != NULL) {
		pfxapp = tad->tad_aupath;
	} else if (tad->tad_scid == SYS_fsat && pnp->pn_buf[0] != '/') {
		ASSERT(tad->tad_atpath != NULL);
		pfxapp = tad->tad_atpath;
	} else if (tad->tad_ctrl & PAD_ABSPATH) {
		pfxapp = pad->pad_root;
	} else {
		pfxapp = pad->pad_cwd;
	}
	au_pathhold(pfxapp);
	mutex_exit(&pad->pad_lock);

	/* get an expanded buffer to hold the anchored path */
	newsect = tad->tad_ctrl & PAD_ATPATH;
	newapp = au_pathdup(pfxapp, newsect, len);
	au_pathrele(pfxapp);

	pp = newapp->audp_sect[newapp->audp_cnt] - len;
	if (!newsect) {
		/* overlay previous NUL terminator */
		*(pp - 1) = '/';
	}

	/* now add string of processed path */
	bcopy(pnp->pn_buf, pp, len);
	pp[len - 1] = '\0';

	/* perform path simplification as necessary */
	audit_fixpath(newapp, len);

	if (tad->tad_aupath)
		au_pathrele(tad->tad_aupath);
	tad->tad_aupath = newapp;

	/* for case where multiple lookups in one syscall (rename) */
	tad->tad_ctrl &= ~(PAD_ABSPATH | PAD_ATPATH);
}



/*ARGSUSED*/

/*
 * ROUTINE:	AUDIT_ADDCOMPONENT
 * PURPOSE:	extend the path by the component accepted
 * CALLBY:	LOOKUPPN
 * NOTE:	This function is called only when there is an error in
 *		parsing a path component
 * TODO:	Add the error component to audit record
 * QUESTION:	what is this for
 */

void
audit_addcomponent(struct pathname *pnp)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;
	t_audit_data_t *tad;

	tad = U2A(u);
	/*
	 * S2E_SP (PAD_SAVPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	chroot, chdir, open, creat system call processing. It determines
	 *	if audit_savepath() will discard the path or we need it later.
	 * PAD_PATHFND means path already included in this audit record. It
	 *	is used in cases where multiple path lookups are done per
	 *	system call. The policy flag, AUDIT_PATH, controls if multiple
	 *	paths are allowed.
	 * S2E_NPT (PAD_NOPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	exit processing to inhibit any paths that may be added due to
	 *	closes.
	 */
	if ((tad->tad_flag == 0 && !(tad->tad_ctrl & PAD_SAVPATH)) ||
		((tad->tad_ctrl & PAD_PATHFND) &&
		!(kctx->auk_policy & AUDIT_PATH)) ||
		(tad->tad_ctrl & PAD_NOPATH)) {
			return;
	}

	return;

}	/* AUDIT_ADDCOMPONENT */








/*
 * ROUTINE:	AUDIT_ANCHORPATH
 * PURPOSE:
 * CALLBY:	LOOKUPPN
 * NOTE:
 * anchor path at "/". We have seen a symbolic link or entering for the
 * first time we will throw away any saved path if path is anchored.
 *
 * flag = 0, path is relative.
 * flag = 1, path is absolute. Free any saved path and set flag to PAD_ABSPATH.
 *
 * If the (new) path is absolute, then we have to throw away whatever we have
 * already accumulated since it is being superseded by new path which is
 * anchored at the root.
 *		Note that if the path is relative, this function does nothing
 * TODO:
 * QUESTION:
 */
/*ARGSUSED*/
void
audit_anchorpath(struct pathname *pnp, int flag)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;
	t_audit_data_t *tad;

	tad = U2A(u);

	/*
	 * this event being audited or do we need path information
	 * later? This might be for a chdir/chroot or open (add path
	 * to file pointer. If the path has already been found for an
	 * open/creat then we don't need to process the path.
	 *
	 * S2E_SP (PAD_SAVPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	chroot, chdir, open, creat system call processing. It determines
	 *	if audit_savepath() will discard the path or we need it later.
	 * PAD_PATHFND means path already included in this audit record. It
	 *	is used in cases where multiple path lookups are done per
	 *	system call. The policy flag, AUDIT_PATH, controls if multiple
	 *	paths are allowed.
	 * S2E_NPT (PAD_NOPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	exit processing to inhibit any paths that may be added due to
	 *	closes.
	 */
	if ((tad->tad_flag == 0 && !(tad->tad_ctrl & PAD_SAVPATH)) ||
		((tad->tad_ctrl & PAD_PATHFND) &&
		!(kctx->auk_policy & AUDIT_PATH)) ||
		(tad->tad_ctrl & PAD_NOPATH)) {
			return;
	}

	if (flag) {
		tad->tad_ctrl |= PAD_ABSPATH;
		if (tad->tad_aupath != NULL) {
			au_pathrele(tad->tad_aupath);
			tad->tad_aupath = NULL;
			tad->tad_vn = NULL;
		}
	}
}


/*
 * symbolic link. Save previous components.
 *
 * the path seen so far looks like this
 *
 *  +-----------------------+----------------+
 *  | path processed so far | remaining path |
 *  +-----------------------+----------------+
 *  \-----------------------/
 *	save this string if
 *	symbolic link relative
 *	(but don't include  symlink component)
 */

/*ARGSUSED*/


/*
 * ROUTINE:	AUDIT_SYMLINK
 * PURPOSE:
 * CALLBY:	LOOKUPPN
 * NOTE:
 * TODO:
 * QUESTION:
 */
void
audit_symlink(struct pathname *pnp, struct pathname *sympath)
{
	char *sp;	/* saved initial pp */
	char *cp;	/* start of symlink path */
	uint_t len_path;	/* processed path before symlink */
	t_audit_data_t *tad;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	tad = U2A(u);

	/*
	 * this event being audited or do we need path information
	 * later? This might be for a chdir/chroot or open (add path
	 * to file pointer. If the path has already been found for an
	 * open/creat then we don't need to process the path.
	 *
	 * S2E_SP (PAD_SAVPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	chroot, chdir, open, creat system call processing. It determines
	 *	if audit_savepath() will discard the path or we need it later.
	 * PAD_PATHFND means path already included in this audit record. It
	 *	is used in cases where multiple path lookups are done per
	 *	system call. The policy flag, AUDIT_PATH, controls if multiple
	 *	paths are allowed.
	 * S2E_NPT (PAD_NOPATH) flag comes from audit_s2e[].au_ctrl. Used with
	 *	exit processing to inhibit any paths that may be added due to
	 *	closes.
	 */
	if ((tad->tad_flag == 0 &&
		!(tad->tad_ctrl & PAD_SAVPATH)) ||
		((tad->tad_ctrl & PAD_PATHFND) &&
		!(kctx->auk_policy & AUDIT_PATH)) ||
		(tad->tad_ctrl & PAD_NOPATH)) {
			return;
	}

	/*
	 * if symbolic link is anchored at / then do nothing.
	 * When we cycle back to begin: in lookuppn() we will
	 * call audit_anchorpath() with a flag indicating if the
	 * path is anchored at / or is relative. We will release
	 * any saved path at that point.
	 *
	 * Note In the event that an error occurs in pn_combine then
	 * we want to remain pointing at the component that caused the
	 * path to overflow the pnp structure.
	 */
	if (sympath->pn_buf[0] == '/')
		return;

	/* backup over last component */
	sp = cp = pnp->pn_path;
	while (*--cp != '/' && cp > pnp->pn_buf)
		;

	len_path = cp - pnp->pn_buf;

	/* is there anything to save? */
	if (len_path) {
		pnp->pn_path = pnp->pn_buf;
		audit_pathbuild(pnp);
		pnp->pn_path = sp;
	}
}

/*
 * file_is_public : determine whether events for the file (corresponding to
 * 			the specified file attr) should be audited or ignored.
 *
 * returns: 	1 - if audit policy and file attributes indicate that
 *			file is effectively public. read events for
 *			the file should not be audited.
 *		0 - otherwise
 *
 * The required attributes to be considered a public object are:
 * - owned by root, AND
 * - world-readable (permissions for other include read), AND
 * - NOT world-writeable (permissions for other don't
 *	include write)
 *   (mode doesn't need to be checked for symlinks)
 */
int
file_is_public(struct vattr *attr)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	if (!(kctx->auk_policy & AUDIT_PUBLIC) && (attr->va_uid == 0) &&
	    ((attr->va_type == VLNK) ||
	    ((attr->va_mode & (VREAD>>6)) != 0) &&
	    ((attr->va_mode & (VWRITE>>6)) == 0))) {
		return (1);
	}
	return (0);
}


/*
 * ROUTINE:	AUDIT_ATTRIBUTES
 * PURPOSE:	Audit the attributes so we can tell why the error occurred
 * CALLBY:	AUDIT_SAVEPATH
 *		AUDIT_VNCREATE_FINISH
 *		AUS_FCHOWN...audit_event.c...audit_path.c
 * NOTE:
 * TODO:
 * QUESTION:
 */
void
audit_attributes(struct vnode *vp)
{
	struct vattr attr;
	struct t_audit_data *tad;

	tad = U2A(u);

	if (vp) {
		attr.va_mask = AT_ALL;
		if (VOP_GETATTR(vp, &attr, 0, CRED(), NULL) != 0)
			return;

		if (file_is_public(&attr) && (tad->tad_ctrl & PAD_PUBLIC_EV)) {
			/*
			 * This is a public object and a "public" event
			 * (i.e., read only) -- either by definition
			 * (e.g., stat, access...) or by virtue of write access
			 * not being requested (e.g. mmap).
			 * Flag it in the tad to prevent this audit at the end.
			 */
			tad->tad_ctrl |= PAD_NOAUDIT;
		} else {
			au_uwrite(au_to_attr(&attr));
			audit_sec_attributes(&(u_ad), vp);
		}
	}
}


/*
 * ROUTINE:	AUDIT_FALLOC
 * PURPOSE:	allocating a new file structure
 * CALLBY:	FALLOC
 * NOTE:	file structure already initialized
 * TODO:
 * QUESTION:
 */

void
audit_falloc(struct file *fp)
{	/* AUDIT_FALLOC */

	f_audit_data_t *fad;

	/* allocate per file audit structure if there a'int any */
	ASSERT(F2A(fp) == NULL);

	fad = kmem_zalloc(sizeof (struct f_audit_data), KM_SLEEP);

	F2A(fp) = fad;

	fad->fad_thread = curthread; 	/* file audit data back ptr; DEBUG */
}

/*
 * ROUTINE:	AUDIT_UNFALLOC
 * PURPOSE:	deallocate file audit data structure
 * CALLBY:	CLOSEF
 *		UNFALLOC
 * NOTE:
 * TODO:
 * QUESTION:
 */

void
audit_unfalloc(struct file *fp)
{
	f_audit_data_t *fad;

	fad = F2A(fp);

	if (!fad) {
		return;
	}
	if (fad->fad_aupath != NULL) {
		au_pathrele(fad->fad_aupath);
	}
	fp->f_audit_data = 0;
	kmem_free(fad, sizeof (struct f_audit_data));
}

/*
 * ROUTINE:	AUDIT_EXIT
 * PURPOSE:
 * CALLBY:	EXIT
 * NOTE:
 * TODO:
 * QUESTION:	why cmw code as offset by 2 but not here
 */
/* ARGSUSED */
void
audit_exit(int code, int what)
{
	struct t_audit_data *tad;
	tad = U2A(u);

	/*
	 * tad_scid will be set by audit_start even if we are not auditing
	 * the event.
	 */
	if (tad->tad_scid == SYS_exit) {
		/*
		 * if we are auditing the exit system call, then complete
		 * audit record generation (no return from system call).
		 */
		if (tad->tad_flag && tad->tad_event == AUE_EXIT)
			audit_finish(0, SYS_exit, 0, 0);
		return;
	}

	/*
	 * Anyone auditing the system call that was aborted?
	 */
	if (tad->tad_flag) {
		au_uwrite(au_to_text("event aborted"));
		audit_finish(0, tad->tad_scid, 0, 0);
	}

	/*
	 * Generate an audit record for process exit if preselected.
	 */
	(void) audit_start(0, SYS_exit, 0, 0);
	audit_finish(0, SYS_exit, 0, 0);
}

/*
 * ROUTINE:	AUDIT_CORE_START
 * PURPOSE:
 * CALLBY: 	PSIG
 * NOTE:
 * TODO:
 */
void
audit_core_start(int sig)
{
	au_event_t event;
	au_state_t estate;
	t_audit_data_t *tad;
	au_kcontext_t	*kctx;

	tad = U2A(u);

	ASSERT(tad != (t_audit_data_t *)0);

	ASSERT(tad->tad_scid == 0);
	ASSERT(tad->tad_event == 0);
	ASSERT(tad->tad_evmod == 0);
	ASSERT(tad->tad_ctrl == 0);
	ASSERT(tad->tad_flag == 0);
	ASSERT(tad->tad_aupath == NULL);

	kctx = GET_KCTX_PZ;

	/* get basic event for system call */
	event = AUE_CORE;
	estate = kctx->auk_ets[event];

	if ((tad->tad_flag = auditme(kctx, tad, estate)) == 0)
		return;

	/* reset the flags for non-user attributable events */
	tad->tad_ctrl   = PAD_CORE;
	tad->tad_scid   = 0;

	/* if auditing not enabled, then don't generate an audit record */

	if (!((kctx->auk_auditstate == AUC_AUDITING ||
	    kctx->auk_auditstate == AUC_INIT_AUDIT) ||
	    kctx->auk_auditstate == AUC_NOSPACE)) {
		tad->tad_flag = 0;
		tad->tad_ctrl = 0;
		return;
	}

	tad->tad_event  = event;
	tad->tad_evmod  = 0;

	ASSERT(tad->tad_ad == NULL);

	au_write(&(u_ad), au_to_arg32(1, "signal", (uint32_t)sig));
}

/*
 * ROUTINE:	AUDIT_CORE_FINISH
 * PURPOSE:
 * CALLBY:	PSIG
 * NOTE:
 * TODO:
 * QUESTION:
 */

/*ARGSUSED*/
void
audit_core_finish(int code)
{
	int flag;
	t_audit_data_t *tad;
	au_kcontext_t	*kctx;

	tad = U2A(u);

	ASSERT(tad != (t_audit_data_t *)0);

	if ((flag = tad->tad_flag) == 0) {
		tad->tad_event = 0;
		tad->tad_evmod = 0;
		tad->tad_ctrl  = 0;
		ASSERT(tad->tad_aupath == NULL);
		return;
	}
	tad->tad_flag = 0;

	kctx = GET_KCTX_PZ;

	/* kludge for error 0, should use `code==CLD_DUMPED' instead */
	if (flag = audit_success(kctx, tad, 0, NULL)) {
		cred_t *cr = CRED();
		const auditinfo_addr_t *ainfo = crgetauinfo(cr);

		ASSERT(ainfo != NULL);

		/*
		 * Add subject information (no locks since our private copy of
		 * credential
		 */
		AUDIT_SETSUBJ(&(u_ad), cr, ainfo, kctx);

		/* Add a return token (should use f argument) */
		add_return_token((caddr_t *)&(u_ad), tad->tad_scid, 0, 0);

		AS_INC(as_generated, 1, kctx);
		AS_INC(as_kernel, 1, kctx);
	}

	/* Close up everything */
	au_close(kctx, &(u_ad), flag, tad->tad_event, tad->tad_evmod);

	/* free up any space remaining with the path's */
	if (tad->tad_aupath != NULL) {
		au_pathrele(tad->tad_aupath);
		tad->tad_aupath = NULL;
		tad->tad_vn = NULL;
	}
	tad->tad_event = 0;
	tad->tad_evmod = 0;
	tad->tad_ctrl  = 0;
}

/*ARGSUSED*/
void
audit_stropen(struct vnode *vp, dev_t *devp, int flag, cred_t *crp)
{
}

/*ARGSUSED*/
void
audit_strclose(struct vnode *vp, int flag, cred_t *crp)
{
}

/*ARGSUSED*/
void
audit_strioctl(struct vnode *vp, int cmd, intptr_t arg, int flag,
    int copyflag, cred_t *crp, int *rvalp)
{
}


/*ARGSUSED*/
void
audit_strgetmsg(struct vnode *vp, struct strbuf *mctl, struct strbuf *mdata,
    unsigned char *pri, int *flag, int fmode)
{
	struct stdata *stp;
	t_audit_data_t *tad = U2A(u);

	ASSERT(tad != (t_audit_data_t *)0);

	stp = vp->v_stream;

	/* lock stdata from audit_sock */
	mutex_enter(&stp->sd_lock);

	/* proceed ONLY if user is being audited */
	if (!tad->tad_flag) {
		/*
		 * this is so we will not add audit data onto
		 * a thread that is not being audited.
		 */
		stp->sd_t_audit_data = NULL;
		mutex_exit(&stp->sd_lock);
		return;
	}

	stp->sd_t_audit_data = (caddr_t)curthread;
	mutex_exit(&stp->sd_lock);
}

/*ARGSUSED*/
void
audit_strputmsg(struct vnode *vp, struct strbuf *mctl, struct strbuf *mdata,
    unsigned char pri, int flag, int fmode)
{
	struct stdata *stp;
	t_audit_data_t *tad = U2A(u);

	ASSERT(tad != (t_audit_data_t *)0);

	stp = vp->v_stream;

	/* lock stdata from audit_sock */
	mutex_enter(&stp->sd_lock);

	/* proceed ONLY if user is being audited */
	if (!tad->tad_flag) {
		/*
		 * this is so we will not add audit data onto
		 * a thread that is not being audited.
		 */
		stp->sd_t_audit_data = NULL;
		mutex_exit(&stp->sd_lock);
		return;
	}

	stp->sd_t_audit_data = (caddr_t)curthread;
	mutex_exit(&stp->sd_lock);
}

/*
 * ROUTINE:	AUDIT_CLOSEF
 * PURPOSE:
 * CALLBY:	CLOSEF
 * NOTE:
 * release per file audit resources when file structure is being released.
 *
 * IMPORTANT NOTE: Since we generate an audit record here, we may sleep
 *	on the audit queue if it becomes full. This means
 *	audit_closef can not be called when f_count == 0. Since
 *	f_count == 0 indicates the file structure is free, another
 *	process could attempt to use the file while we were still
 *	asleep waiting on the audit queue. This would cause the
 *	per file audit data to be corrupted when we finally do
 *	wakeup.
 * TODO:
 * QUESTION:
 */

void
audit_closef(struct file *fp)
{	/* AUDIT_CLOSEF */
	f_audit_data_t *fad;
	t_audit_data_t *tad;
	int success;
	au_state_t estate;
	struct vnode *vp;
	token_t *ad = NULL;
	struct vattr attr;
	au_emod_t evmod = 0;
	const auditinfo_addr_t *ainfo;
	int getattr_ret;
	cred_t *cr;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	fad = F2A(fp);
	estate = kctx->auk_ets[AUE_CLOSE];
	tad = U2A(u);
	cr = CRED();

	/* audit record already generated by system call envelope */
	if (tad->tad_event == AUE_CLOSE) {
		/* so close audit event will have bits set */
		tad->tad_evmod |= (au_emod_t)fad->fad_flags;
		return;
	}

	/* if auditing not enabled, then don't generate an audit record */
	if (!((kctx->auk_auditstate == AUC_AUDITING ||
	    kctx->auk_auditstate == AUC_INIT_AUDIT) ||
	    kctx->auk_auditstate == AUC_NOSPACE))
		return;

	ainfo = crgetauinfo(cr);
	if (ainfo == NULL)
		return;

	success = ainfo->ai_mask.as_success & estate;

	/* not selected for this event */
	if (success == 0)
		return;

	/*
	 * can't use audit_attributes here since we use a private audit area
	 * to build the audit record instead of the one off the thread.
	 */
	if ((vp = fp->f_vnode) != NULL) {
		attr.va_mask = AT_ALL;
		getattr_ret = VOP_GETATTR(vp, &attr, 0, CRED(), NULL);
	}

	/*
	 * When write was not used and the file can be considered public,
	 * then skip the audit.
	 */
	if ((getattr_ret == 0) && ((fp->f_flag & FWRITE) == 0)) {
		if (file_is_public(&attr)) {
			return;
		}
	}

	evmod = (au_emod_t)fad->fad_flags;
	if (fad->fad_aupath != NULL) {
		au_write((caddr_t *)&(ad), au_to_path(fad->fad_aupath));
	} else {
#ifdef _LP64
		au_write((caddr_t *)&(ad), au_to_arg64(
			1, "no path: fp", (uint64_t)fp));
#else
		au_write((caddr_t *)&(ad), au_to_arg32(
			1, "no path: fp", (uint32_t)fp));
#endif
	}

	if (getattr_ret == 0) {
		au_write((caddr_t *)&(ad), au_to_attr(&attr));
		audit_sec_attributes((caddr_t *)&(ad), vp);
	}

	/* Add subject information */
	AUDIT_SETSUBJ((caddr_t *)&(ad), cr, ainfo, kctx);

	/* add a return token */
	add_return_token((caddr_t *)&(ad), tad->tad_scid, 0, 0);

	AS_INC(as_generated, 1, kctx);
	AS_INC(as_kernel, 1, kctx);

	/*
	 * Close up everything
	 * Note: path space recovery handled by normal system
	 * call envelope if not at last close.
	 * Note there is no failure at this point since
	 *   this represents closes due to exit of process,
	 *   thus we always indicate successful closes.
	 */
	au_close(kctx, (caddr_t *)&(ad), AU_OK | AU_DEFER,
	    AUE_CLOSE, evmod);
}

/*
 * ROUTINE:	AUDIT_SET
 * PURPOSE:	Audit the file path and file attributes.
 * CALLBY:	SETF
 * NOTE:	SETF associate a file pointer with user area's open files.
 * TODO:
 * call audit_finish directly ???
 * QUESTION:
 */

/*ARGSUSED*/
void
audit_setf(file_t *fp, int fd)
{
	f_audit_data_t *fad;
	t_audit_data_t *tad;

	if (fp == NULL)
		return;

	tad = T2A(curthread);
	fad = F2A(fp);

	if (!(tad->tad_scid == SYS_open || tad->tad_scid == SYS_creat ||
	    tad->tad_scid == SYS_open64 || tad->tad_scid == SYS_creat64 ||
	    tad->tad_scid == SYS_fsat))
		return;

	/* no path */
	if (tad->tad_aupath == 0)
		return;

	/*
	 * assign path information associated with file audit data
	 * use tad hold
	 */
	fad->fad_aupath = tad->tad_aupath;
	tad->tad_aupath = NULL;
	tad->tad_vn = NULL;

	if (!(tad->tad_ctrl & PAD_TRUE_CREATE)) {
	/* adjust event type */
		switch (tad->tad_event) {
		case AUE_OPEN_RC:
			tad->tad_event = AUE_OPEN_R;
			tad->tad_ctrl |= PAD_PUBLIC_EV;
			break;
		case AUE_OPEN_RTC:
			tad->tad_event = AUE_OPEN_RT;
			break;
		case AUE_OPEN_WC:
			tad->tad_event = AUE_OPEN_W;
			break;
		case AUE_OPEN_WTC:
			tad->tad_event = AUE_OPEN_WT;
			break;
		case AUE_OPEN_RWC:
			tad->tad_event = AUE_OPEN_RW;
			break;
		case AUE_OPEN_RWTC:
			tad->tad_event = AUE_OPEN_RWT;
			break;
		default:
			break;
		}
	}
}


/*
 * ROUTINE:	AUDIT_COPEN
 * PURPOSE:
 * CALLBY:	COPEN
 * NOTE:
 * TODO:
 * QUESTION:
 */
/*ARGSUSED*/
void
audit_copen(int fd, file_t *fp, vnode_t *vp)
{
}

void
audit_ipc(int type, int id, void *vp)
{
	/* if not auditing this event, then do nothing */
	if (ad_flag == 0)
		return;

	switch (type) {
	case AT_IPC_MSG:
		au_uwrite(au_to_ipc(AT_IPC_MSG, id));
		au_uwrite(au_to_ipc_perm(&(((kmsqid_t *)vp)->msg_perm)));
		break;
	case AT_IPC_SEM:
		au_uwrite(au_to_ipc(AT_IPC_SEM, id));
		au_uwrite(au_to_ipc_perm(&(((ksemid_t *)vp)->sem_perm)));
		break;
	case AT_IPC_SHM:
		au_uwrite(au_to_ipc(AT_IPC_SHM, id));
		au_uwrite(au_to_ipc_perm(&(((kshmid_t *)vp)->shm_perm)));
		break;
	}
}

void
audit_ipcget(int type, void *vp)
{
	/* if not auditing this event, then do nothing */
	if (ad_flag == 0)
		return;

	switch (type) {
	case NULL:
		au_uwrite(au_to_ipc_perm((struct kipc_perm *)vp));
		break;
	case AT_IPC_MSG:
		au_uwrite(au_to_ipc_perm(&(((kmsqid_t *)vp)->msg_perm)));
		break;
	case AT_IPC_SEM:
		au_uwrite(au_to_ipc_perm(&(((ksemid_t *)vp)->sem_perm)));
		break;
	case AT_IPC_SHM:
		au_uwrite(au_to_ipc_perm(&(((kshmid_t *)vp)->shm_perm)));
		break;
	}
}

/*
 * ROUTINE:	AUDIT_REBOOT
 * PURPOSE:
 * CALLBY:
 * NOTE:
 * At this point we know that the system call reboot will not return. We thus
 * have to complete the audit record generation and put it onto the queue.
 * This might be fairly useless if the auditing daemon is already dead....
 * TODO:
 * QUESTION:	who calls audit_reboot
 */

void
audit_reboot(void)
{
	int flag;
	t_audit_data_t *tad;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	tad = U2A(u);

	/* if not auditing this event, then do nothing */
	if (tad->tad_flag == 0)
		return;

	/* do preselection on success/failure */
	if (flag = audit_success(kctx, tad, 0, NULL)) {
		/* add a process token */

		cred_t *cr = CRED();
		const auditinfo_addr_t *ainfo = crgetauinfo(cr);

		if (ainfo == NULL)
			return;

		/* Add subject information */
		AUDIT_SETSUBJ(&(u_ad), cr, ainfo, kctx);

		/* add a return token */
		add_return_token((caddr_t *)&(u_ad), tad->tad_scid, 0, 0);

		AS_INC(as_generated, 1, kctx);
		AS_INC(as_kernel, 1, kctx);
	}

	/*
	 * Flow control useless here since we're going
	 * to drop everything in the queue anyway. Why
	 * block and wait. There aint anyone left alive to
	 * read the records remaining anyway.
	 */

	/* Close up everything */
	au_close(kctx, &(u_ad), flag | AU_DONTBLOCK,
	    tad->tad_event, tad->tad_evmod);
}

void
audit_setfsat_path(int argnum)
{
	klwp_id_t clwp = ttolwp(curthread);
	struct file  *fp;
	uint32_t fd;
	t_audit_data_t *tad;
	struct f_audit_data *fad;
	p_audit_data_t *pad;	/* current process */
	struct a {
		long id;
		long arg1;
		long arg2;
		long arg3;
		long arg4;
		long arg5;
	} *uap;
	struct b {
		long arg1;
		long arg2;
		long arg3;
		long arg4;
		long arg5;
	} *uap1;

	if (clwp == NULL)
		return;
	uap1 = (struct b *)&clwp->lwp_ap[1];
	uap = (struct a *)clwp->lwp_ap;

	tad = U2A(u);

	ASSERT(tad != NULL);

	if (tad->tad_scid != SYS_fsat)
		return;

	switch (argnum) {
	case 1:
		fd = (uint32_t)uap1->arg1;
		break;
	case 2:
		fd = (uint32_t)uap1->arg2;
		break;
	case 3:
		fd = (uint32_t)uap1->arg3;
		break;
	case 4:
		fd = (uint32_t)uap1->arg4;
		break;
	case 5:
		fd = (uint32_t)uap1->arg5;
		break;
	default:
		return;
	}

	if (uap->id == 9 && tad->tad_atpath != NULL) { /* openattrdir */
		tad->tad_ctrl |= PAD_ATPATH;
		return;
	}
	if (tad->tad_atpath != NULL) {
		au_pathrele(tad->tad_atpath);
		tad->tad_atpath = NULL;
	}
	if (fd != AT_FDCWD) {
		if ((fp = getf(fd)) == NULL)
			return;

		fad = F2A(fp);
		ASSERT(fad);
		au_pathhold(fad->fad_aupath);
		tad->tad_atpath = fad->fad_aupath;
		releasef(fd);
	} else {
		pad = P2A(curproc);
		mutex_enter(&pad->pad_lock);
		au_pathhold(pad->pad_cwd);
		tad->tad_atpath = pad->pad_cwd;
		mutex_exit(&pad->pad_lock);
	}
}

void
audit_symlink_create(vnode_t *dvp, char *sname, char *target, int error)
{
	t_audit_data_t *tad;
	vnode_t	*vp;

	tad = U2A(u);

	/* if not auditing this event, then do nothing */
	if (tad->tad_flag == 0)
		return;

	au_uwrite(au_to_text(target));

	if (error)
		return;

	error = VOP_LOOKUP(dvp, sname, &vp, NULL, 0, NULL, CRED(),
			NULL, NULL, NULL);
	if (error == 0) {
		audit_attributes(vp);
		VN_RELE(vp);
	}
}

/*
 * ROUTINE:	AUDIT_VNCREATE_START
 * PURPOSE:	set flag so path name lookup in create will not add attribute
 * CALLBY:	VN_CREATE
 * NOTE:
 * TODO:
 * QUESTION:
 */

void
audit_vncreate_start()
{
	t_audit_data_t *tad;

	tad = U2A(u);
	tad->tad_ctrl |= PAD_NOATTRB;
}

/*
 * ROUTINE:	AUDIT_VNCREATE_FINISH
 * PURPOSE:
 * CALLBY:	VN_CREATE
 * NOTE:
 * TODO:
 * QUESTION:
 */
void
audit_vncreate_finish(struct vnode *vp, int error)
{
	t_audit_data_t *tad;

	if (error)
		return;

	tad = U2A(u);

	/* if not auditing this event, then do nothing */
	if (tad->tad_flag == 0)
		return;

	if (tad->tad_ctrl & PAD_TRUE_CREATE) {
		audit_attributes(vp);
	}

	if (tad->tad_ctrl & PAD_CORE) {
		audit_attributes(vp);
		tad->tad_ctrl &= ~PAD_CORE;
	}

	if (!error && ((tad->tad_event == AUE_MKNOD) ||
			(tad->tad_event == AUE_MKDIR))) {
		audit_attributes(vp);
	}

	/* for case where multiple lookups in one syscall (rename) */
	tad->tad_ctrl &= ~PAD_NOATTRB;
}








/*
 * ROUTINE:	AUDIT_EXEC
 * PURPOSE:	Records the function arguments and environment variables
 * CALLBY:	EXEC_ARGS
 * NOTE:
 * TODO:
 * QUESTION:
 */

/*ARGSUSED*/
void
audit_exec(
	const char *argstr,	/* argument strings */
	const char *envstr,	/* environment strings */
	ssize_t argc,		/* total # arguments */
	ssize_t envc)		/* total # environment variables */
{
	t_audit_data_t *tad;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	tad = U2A(u);

	/* if not auditing this event, then do nothing */
	if (!tad->tad_flag)
		return;

	/* return if not interested in argv or environment variables */
	if (!(kctx->auk_policy & (AUDIT_ARGV|AUDIT_ARGE)))
		return;

	if (kctx->auk_policy & AUDIT_ARGV) {
		au_uwrite(au_to_exec_args(argstr, argc));
	}

	if (kctx->auk_policy & AUDIT_ARGE) {
		au_uwrite(au_to_exec_env(envstr, envc));
	}
}

/*
 * ROUTINE:	AUDIT_ENTERPROM
 * PURPOSE:
 * CALLBY:	KBDINPUT
 *		ZSA_XSINT
 * NOTE:
 * TODO:
 * QUESTION:
 */
void
audit_enterprom(int flg)
{
	token_t *rp = NULL;
	int sorf;

	if (flg)
		sorf = AUM_SUCC;
	else
		sorf = AUM_FAIL;

	AUDIT_ASYNC_START(rp, AUE_ENTERPROM, sorf);

	au_write((caddr_t *)&(rp), au_to_text("kmdb"));

	if (flg)
		au_write((caddr_t *)&(rp), au_to_return32(0, 0));
	else
		au_write((caddr_t *)&(rp), au_to_return32(ECANCELED, 0));

	AUDIT_ASYNC_FINISH(rp, AUE_ENTERPROM, NULL);
}


/*
 * ROUTINE:	AUDIT_EXITPROM
 * PURPOSE:
 * CALLBY:	KBDINPUT
 *		ZSA_XSINT
 * NOTE:
 * TODO:
 * QUESTION:
 */
void
audit_exitprom(int flg)
{
	int sorf;
	token_t *rp = NULL;

	if (flg)
		sorf = AUM_SUCC;
	else
		sorf = AUM_FAIL;

	AUDIT_ASYNC_START(rp, AUE_EXITPROM, sorf);

	au_write((caddr_t *)&(rp), au_to_text("kmdb"));

	if (flg)
		au_write((caddr_t *)&(rp), au_to_return32(0, 0));
	else
		au_write((caddr_t *)&(rp), au_to_return32(ECANCELED, 0));

	AUDIT_ASYNC_FINISH(rp, AUE_EXITPROM, NULL);
}

struct fcntla {
	int fdes;
	int cmd;
	intptr_t arg;
};

/*
 * ROUTINE:	AUDIT_C2_REVOKE
 * PURPOSE:
 * CALLBY:	FCNTL
 * NOTE:
 * TODO:
 * QUESTION:	are we keeping this func
 */

/*ARGSUSED*/
int
audit_c2_revoke(struct fcntla *uap, rval_t *rvp)
{
	return (0);
}


/*
 * ROUTINE:	AUDIT_CHDIREC
 * PURPOSE:
 * CALLBY:	CHDIREC
 * NOTE:	The main function of CHDIREC
 * TODO:	Move the audit_chdirec hook above the VN_RELE in vncalls.c
 * QUESTION:
 */

/*ARGSUSED*/
void
audit_chdirec(vnode_t *vp, vnode_t **vpp)
{
	int		chdir;
	int		fchdir;
	struct audit_path	**appp;
	struct file	*fp;
	f_audit_data_t *fad;
	p_audit_data_t *pad = P2A(curproc);
	t_audit_data_t *tad = T2A(curthread);

	struct a {
		long fd;
	} *uap = (struct a *)ttolwp(curthread)->lwp_ap;

	if ((tad->tad_scid == SYS_chdir) || (tad->tad_scid == SYS_chroot)) {
		chdir = tad->tad_scid == SYS_chdir;
		if (tad->tad_aupath) {
			mutex_enter(&pad->pad_lock);
			if (chdir)
				appp = &(pad->pad_cwd);
			else
				appp = &(pad->pad_root);
			au_pathrele(*appp);
			/* use tad hold */
			*appp = tad->tad_aupath;
			tad->tad_aupath = NULL;
			mutex_exit(&pad->pad_lock);
		}
	} else if ((tad->tad_scid == SYS_fchdir) ||
	    (tad->tad_scid == SYS_fchroot)) {
		fchdir = tad->tad_scid == SYS_fchdir;
		if ((fp = getf(uap->fd)) == NULL)
			return;
		fad = F2A(fp);
		if (fad->fad_aupath) {
			au_pathhold(fad->fad_aupath);
			mutex_enter(&pad->pad_lock);
			if (fchdir)
				appp = &(pad->pad_cwd);
			else
				appp = &(pad->pad_root);
			au_pathrele(*appp);
			*appp = fad->fad_aupath;
			mutex_exit(&pad->pad_lock);
			if (tad->tad_flag) {
				au_uwrite(au_to_path(fad->fad_aupath));
				audit_attributes(fp->f_vnode);
			}
		}
		releasef(uap->fd);
	}
}

/*
 * ROUTINE:	AUDIT_GETF
 * PURPOSE:
 * CALLBY:	GETF_INTERNAL
 * NOTE:	The main function of GETF_INTERNAL is to associate a given
 *		file descriptor with a file structure and increment the
 *		file pointer reference count.
 * TODO:	remove pass in of fpp.
 * increment a reference count so that even if a thread with same process delete
 * the same object, it will not panic our system
 * QUESTION:
 * where to decrement the f_count?????????????????
 * seems like I need to set a flag if f_count incremented through audit_getf
 */

/*ARGSUSED*/
int
audit_getf(int fd)
{
#ifdef NOTYET
	t_audit_data_t *tad;

	tad = T2A(curthread);

	if (!(tad->tad_scid == SYS_open || tad->tad_scid == SYS_creat))
		return;
#endif
	return (0);
}

/*
 *	Audit hook for stream based socket and tli request.
 *	Note that we do not have user context while executing
 *	this code so we had to record them earlier during the
 *	putmsg/getmsg to figure out which user we are dealing with.
 */

/*ARGSUSED*/
void
audit_sock(
	int type,	/* type of tihdr.h header requests */
	queue_t *q,	/* contains the process and thread audit data */
	mblk_t *mp,	/* contains the tihdr.h header structures */
	int from)	/* timod or sockmod request */
{
	int32_t    len;
	int32_t    offset;
	struct sockaddr_in *sock_data;
	struct T_conn_req *conn_req;
	struct T_conn_ind *conn_ind;
	struct T_unitdata_req *unitdata_req;
	struct T_unitdata_ind *unitdata_ind;
	au_state_t estate;
	t_audit_data_t *tad;
	caddr_t saved_thread_ptr;
	au_mask_t amask;
	const auditinfo_addr_t *ainfo;
	au_kcontext_t	*kctx;

	if (q->q_stream == NULL)
		return;
	mutex_enter(&q->q_stream->sd_lock);
	/* are we being audited */
	saved_thread_ptr = q->q_stream->sd_t_audit_data;
	/* no pointer to thread, nothing to do */
	if (saved_thread_ptr == NULL) {
		mutex_exit(&q->q_stream->sd_lock);
		return;
	}
	/* only allow one addition of a record token */
	q->q_stream->sd_t_audit_data = NULL;
	/*
	 * thread is not the one being audited, then nothing to do
	 * This could be the stream thread handling the module
	 * service routine. In this case, the context for the audit
	 * record can no longer be assumed. Simplest to just drop
	 * the operation.
	 */
	if (curthread != (kthread_id_t)saved_thread_ptr) {
		mutex_exit(&q->q_stream->sd_lock);
		return;
	}
	if (curthread->t_sysnum >= SYS_so_socket &&
	    curthread->t_sysnum <= SYS_sockconfig) {
		mutex_exit(&q->q_stream->sd_lock);
		return;
	}
	mutex_exit(&q->q_stream->sd_lock);
	/*
	 * we know that the thread that did the put/getmsg is the
	 * one running. Now we can get the TAD and see if we should
	 * add an audit token.
	 */
	tad = U2A(u);

	kctx = GET_KCTX_PZ;

	/* proceed ONLY if user is being audited */
	if (!tad->tad_flag)
		return;

	ainfo = crgetauinfo(CRED());
	if (ainfo == NULL)
		return;
	amask = ainfo->ai_mask;

	/*
	 * Figure out the type of stream networking request here.
	 * Note that getmsg and putmsg are always preselected
	 * because during the beginning of the system call we have
	 * not yet figure out which of the socket or tli request
	 * we are looking at until we are here. So we need to check
	 * against that specific request and reset the type of event.
	 */
	switch (type) {
	case T_CONN_REQ:	/* connection request */
		conn_req = (struct T_conn_req *)mp->b_rptr;
		if (conn_req->DEST_offset < sizeof (struct T_conn_req))
			return;
		offset = conn_req->DEST_offset;
		len = conn_req->DEST_length;
		estate = kctx->auk_ets[AUE_SOCKCONNECT];
		if (amask.as_success & estate || amask.as_failure & estate) {
			tad->tad_event = AUE_SOCKCONNECT;
			break;
		} else {
			return;
		}
	case T_CONN_IND:	 /* connectionless receive request */
		conn_ind = (struct T_conn_ind *)mp->b_rptr;
		if (conn_ind->SRC_offset < sizeof (struct T_conn_ind))
			return;
		offset = conn_ind->SRC_offset;
		len = conn_ind->SRC_length;
		estate = kctx->auk_ets[AUE_SOCKACCEPT];
		if (amask.as_success & estate || amask.as_failure & estate) {
			tad->tad_event = AUE_SOCKACCEPT;
			break;
		} else {
			return;
		}
	case T_UNITDATA_REQ:	 /* connectionless send request */
		unitdata_req = (struct T_unitdata_req *)mp->b_rptr;
		if (unitdata_req->DEST_offset < sizeof (struct T_unitdata_req))
			return;
		offset = unitdata_req->DEST_offset;
		len = unitdata_req->DEST_length;
		estate = kctx->auk_ets[AUE_SOCKSEND];
		if (amask.as_success & estate || amask.as_failure & estate) {
			tad->tad_event = AUE_SOCKSEND;
			break;
		} else {
			return;
		}
	case T_UNITDATA_IND:	 /* connectionless receive request */
		unitdata_ind = (struct T_unitdata_ind *)mp->b_rptr;
		if (unitdata_ind->SRC_offset < sizeof (struct T_unitdata_ind))
			return;
		offset = unitdata_ind->SRC_offset;
		len = unitdata_ind->SRC_length;
		estate = kctx->auk_ets[AUE_SOCKRECEIVE];
		if (amask.as_success & estate || amask.as_failure & estate) {
			tad->tad_event = AUE_SOCKRECEIVE;
			break;
		} else {
			return;
		}
	default:
		return;
	}

	/*
	 * we are only interested in tcp stream connections,
	 * not unix domain stuff
	 */
	if ((len < 0) || (len > sizeof (struct sockaddr_in))) {
		tad->tad_event = AUE_GETMSG;
		return;
	}
	/* skip over TPI header and point to the ip address */
	sock_data = (struct sockaddr_in *)((char *)mp->b_rptr + offset);

	switch (sock_data->sin_family) {
	case AF_INET:
		au_write(&(tad->tad_ad), au_to_sock_inet(sock_data));
		break;
	default:	/* reset to AUE_PUTMSG if not a inet request */
		tad->tad_event = AUE_GETMSG;
		break;
	}
}

void
audit_lookupname()
{
}

/*ARGSUSED*/
int
audit_pathcomp(struct pathname *pnp, vnode_t *cvp, cred_t *cr)
{
	return (0);
}

static void
add_return_token(caddr_t *ad, unsigned int scid, int err, int rval)
{
	unsigned int sy_flags;

#ifdef _SYSCALL32_IMPL
	/*
	 * Guard against t_lwp being NULL when this function is called
	 * from a kernel queue instead of from a direct system call.
	 * In that case, assume the running kernel data model.
	 */
	if ((curthread->t_lwp == NULL) || (lwp_getdatamodel(
	    ttolwp(curthread)) == DATAMODEL_NATIVE))
		sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
	else
		sy_flags = sysent32[scid].sy_flags & SE_RVAL_MASK;
#else
		sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
#endif

	if (sy_flags == SE_64RVAL)
		au_write(ad, au_to_return64(err, rval));
	else
		au_write(ad, au_to_return32(err, rval));

}

/*ARGSUSED*/
void
audit_fdsend(fd, fp, error)
	int fd;
	struct file *fp;
	int error;		/* ignore for now */
{
	t_audit_data_t *tad;	/* current thread */
	f_audit_data_t *fad;	/* per file audit structure */
	struct vnode *vp;	/* for file attributes */

	/* is this system call being audited */
	tad = U2A(u);
	ASSERT(tad != (t_audit_data_t *)0);
	if (!tad->tad_flag)
		return;

	fad = F2A(fp);

	/* add path and file attributes */
	if (fad != NULL && fad->fad_aupath != NULL) {
		au_uwrite(au_to_arg32(0, "send fd", (uint32_t)fd));
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(0, "send fd", (uint32_t)fd));
#ifdef _LP64
		au_uwrite(au_to_arg64(0, "no path", (uint64_t)fp));
#else
		au_uwrite(au_to_arg32(0, "no path", (uint32_t)fp));
#endif
	}
	vp = fp->f_vnode;	/* include vnode attributes */
	audit_attributes(vp);
}

/*
 * Record privileges successfully used and we attempted to use but
 * didn't have.
 */
void
audit_priv(int priv, const priv_set_t *set, int flag)
{
	t_audit_data_t *tad;
	int sbit;
	priv_set_t *target;

	/* Make sure this isn't being called in an interrupt context */
	ASSERT(servicing_interrupt() == 0);

	tad = U2A(u);

	if (tad->tad_flag == 0)
		return;

	target = flag ? &tad->tad_sprivs : &tad->tad_fprivs;
	sbit = flag ? PAD_SPRIVUSE : PAD_FPRIVUSE;

	/* Tell audit_success() and audit_finish() that we saw this case */
	if (!(tad->tad_evmod & sbit)) {
		/* Clear set first time around */
		priv_emptyset(target);
		tad->tad_evmod |= sbit;
	}

	/* Save the privileges in the tad */
	if (priv == PRIV_ALL) {
		priv_fillset(target);
	} else {
		ASSERT(set != NULL || priv != PRIV_NONE);
		if (set != NULL)
			priv_union(set, target);
		if (priv != PRIV_NONE)
			priv_addset(target, priv);
	}
}

/*
 * Audit the setpriv() system call; the operation, the set name and
 * the current value as well as the set argument are put in the
 * audit trail.
 */
void
audit_setppriv(int op, int set, const priv_set_t *newpriv, const cred_t *ocr)
{
	t_audit_data_t *tad;
	const priv_set_t *oldpriv;
	priv_set_t report;
	const char *setname;

	tad = U2A(u);

	if (tad->tad_flag == 0)
		return;

	oldpriv = priv_getset(ocr, set);

	/* Generate the actual record, include the before and after */
	au_uwrite(au_to_arg32(2, "op", op));
	setname = priv_getsetbynum(set);

	switch (op) {
	case PRIV_OFF:
		/* Report privileges actually switched off */
		report = *oldpriv;
		priv_intersect(newpriv, &report);
		au_uwrite(au_to_privset(setname, &report, AUT_PRIV, 0));
		break;
	case PRIV_ON:
		/* Report privileges actually switched on */
		report = *oldpriv;
		priv_inverse(&report);
		priv_intersect(newpriv, &report);
		au_uwrite(au_to_privset(setname, &report, AUT_PRIV, 0));
		break;
	case PRIV_SET:
		/* Report before and after */
		au_uwrite(au_to_privset(setname, oldpriv, AUT_PRIV, 0));
		au_uwrite(au_to_privset(setname, newpriv, AUT_PRIV, 0));
		break;
	}
}

/*
 * Dump the full device policy setting in the audit trail.
 */
void
audit_devpolicy(int nitems, const devplcysys_t *items)
{
	t_audit_data_t *tad;
	int i;

	tad = U2A(u);

	if (tad->tad_flag == 0)
		return;

	for (i = 0; i < nitems; i++) {
		au_uwrite(au_to_arg32(2, "major", items[i].dps_maj));
		if (items[i].dps_minornm[0] == '\0') {
			au_uwrite(au_to_arg32(2, "lomin", items[i].dps_lomin));
			au_uwrite(au_to_arg32(2, "himin", items[i].dps_himin));
		} else
			au_uwrite(au_to_text(items[i].dps_minornm));

		au_uwrite(au_to_privset("read", &items[i].dps_rdp,
		    AUT_PRIV, 0));
		au_uwrite(au_to_privset("write", &items[i].dps_wrp,
		    AUT_PRIV, 0));
	}
}

/*ARGSUSED*/
void
audit_fdrecv(fd, fp)
	int fd;
	struct file *fp;
{
	t_audit_data_t *tad;	/* current thread */
	f_audit_data_t *fad;	/* per file audit structure */
	struct vnode *vp;	/* for file attributes */

	/* is this system call being audited */
	tad = U2A(u);
	ASSERT(tad != (t_audit_data_t *)0);
	if (!tad->tad_flag)
		return;

	fad = F2A(fp);

	/* add path and file attributes */
	if (fad != NULL && fad->fad_aupath != NULL) {
		au_uwrite(au_to_arg32(0, "recv fd", (uint32_t)fd));
		au_uwrite(au_to_path(fad->fad_aupath));
	} else {
		au_uwrite(au_to_arg32(0, "recv fd", (uint32_t)fd));
#ifdef _LP64
		au_uwrite(au_to_arg64(0, "no path", (uint64_t)fp));
#else
		au_uwrite(au_to_arg32(0, "no path", (uint32_t)fp));
#endif
	}
	vp = fp->f_vnode;	/* include vnode attributes */
	audit_attributes(vp);
}

/*
 * ROUTINE:	AUDIT_CRYPTOADM
 * PURPOSE:	Records arguments to administrative ioctls on /dev/cryptoadm
 * CALLBY:	CRYPTO_LOAD_DEV_DISABLED, CRYPTO_LOAD_SOFT_DISABLED,
 *		CRYPTO_UNLOAD_SOFT_MODULE, CRYPTO_LOAD_SOFT_CONFIG,
 *		CRYPTO_POOL_CREATE, CRYPTO_POOL_WAIT, CRYPTO_POOL_RUN,
 *		CRYPTO_LOAD_DOOR
 * NOTE:
 * TODO:
 * QUESTION:
 */

void
audit_cryptoadm(int cmd, char *module_name, crypto_mech_name_t *mech_names,
    uint_t mech_count, uint_t device_instance, uint32_t rv, int error)
{
	boolean_t		mech_list_required = B_FALSE;
	cred_t			*cr = CRED();
	t_audit_data_t		*tad;
	token_t			*ad = NULL;
	const auditinfo_addr_t	*ainfo = crgetauinfo(cr);
	char			buffer[MAXNAMELEN * 2];
	au_kcontext_t		*kctx = GET_KCTX_PZ;

	tad = U2A(u);
	if (tad == NULL)
		return;

	if (ainfo == NULL)
		return;

	tad->tad_event = AUE_CRYPTOADM;

	if (audit_success(kctx, tad, error, NULL) != AU_OK)
		return;

	/* Add subject information */
	AUDIT_SETSUBJ((caddr_t *)&(ad), cr, ainfo, kctx);

	switch (cmd) {
	case CRYPTO_LOAD_DEV_DISABLED:
		if (error == 0 && rv == CRYPTO_SUCCESS) {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_DEV_DISABLED, module=%s,"
			    " dev_instance=%d",
			    module_name, device_instance);
			mech_list_required = B_TRUE;
		} else {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_DEV_DISABLED, return_val=%d", rv);
		}
		break;

	case CRYPTO_LOAD_SOFT_DISABLED:
		if (error == 0 && rv == CRYPTO_SUCCESS) {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_SOFT_DISABLED, module=%s",
			    module_name);
			mech_list_required = B_TRUE;
		} else {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_SOFT_DISABLED, return_val=%d", rv);
		}
		break;

	case CRYPTO_UNLOAD_SOFT_MODULE:
		if (error == 0 && rv == CRYPTO_SUCCESS) {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_UNLOAD_SOFT_MODULE, module=%s",
			    module_name);
		} else {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_UNLOAD_SOFT_MODULE, return_val=%d", rv);
		}
		break;

	case CRYPTO_LOAD_SOFT_CONFIG:
		if (error == 0 && rv == CRYPTO_SUCCESS) {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_SOFT_CONFIG, module=%s",
			    module_name);
			mech_list_required = B_TRUE;
		} else {
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_SOFT_CONFIG, return_val=%d", rv);
		}
		break;

	case CRYPTO_POOL_CREATE:
		(void) snprintf(buffer, sizeof (buffer),
		    "op=CRYPTO_POOL_CREATE");
		break;

	case CRYPTO_POOL_WAIT:
		(void) snprintf(buffer, sizeof (buffer), "op=CRYPTO_POOL_WAIT");
		break;

	case CRYPTO_POOL_RUN:
		(void) snprintf(buffer, sizeof (buffer), "op=CRYPTO_POOL_RUN");
		break;

	case CRYPTO_LOAD_DOOR:
		if (error == 0 && rv == CRYPTO_SUCCESS)
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_DOOR");
		else
			(void) snprintf(buffer, sizeof (buffer),
			    "op=CRYPTO_LOAD_DOOR, return_val=%d", rv);
		break;

	default:
		return;
	}

	au_write((caddr_t *)&ad, au_to_text(buffer));

	if (mech_list_required) {
		int i;

		if (mech_count == 0) {
			au_write((caddr_t *)&ad, au_to_text("mech=list empty"));
		} else {
			char	*pb = buffer;
			size_t	l = sizeof (buffer);
			size_t	n;
			char	space[2] = ":";

			n = snprintf(pb, l, "mech=");

			for (i = 0; i < mech_count; i++) {
				pb += n;
				l -= n;
				if (l < 0)
					l = 0;

				if (i == mech_count - 1)
					(void) strcpy(space, "");

				n = snprintf(pb, l, "%s%s", mech_names[i],
				    space);
			}
			au_write((caddr_t *)&ad, au_to_text(buffer));
		}
	}

	/* add a return token */
	if (error || (rv != CRYPTO_SUCCESS))
		add_return_token((caddr_t *)&ad, tad->tad_scid, -1, error);
	else
		add_return_token((caddr_t *)&ad, tad->tad_scid, 0, rv);

	AS_INC(as_generated, 1, kctx);
	AS_INC(as_kernel, 1, kctx);

	au_close(kctx, (caddr_t *)&ad, AU_OK, AUE_CRYPTOADM, 0);
}

/*
 * Audit the kernel SSL administration command. The address and the
 * port number for the SSL instance, and the proxy port are put in the
 * audit trail.
 */
void
audit_kssl(int cmd, void *params, int error)
{
	cred_t			*cr = CRED();
	t_audit_data_t		*tad;
	token_t			*ad = NULL;
	const auditinfo_addr_t	*ainfo = crgetauinfo(cr);
	au_kcontext_t		*kctx = GET_KCTX_PZ;

	tad = U2A(u);

	if (ainfo == NULL)
		return;

	tad->tad_event = AUE_CONFIGKSSL;

	if (audit_success(kctx, tad, error, NULL) != AU_OK)
		return;

	/* Add subject information */
	AUDIT_SETSUBJ((caddr_t *)&ad, cr, ainfo, kctx);

	switch (cmd) {
	case KSSL_ADD_ENTRY: {
		char buf[32];
		kssl_params_t *kp = (kssl_params_t *)params;
		struct sockaddr_in *saddr = &(kp->kssl_addr);

		au_write((caddr_t *)&ad, au_to_text("op=KSSL_ADD_ENTRY"));
		au_write((caddr_t *)&ad, au_to_in_addr(&(saddr->sin_addr)));
		(void) snprintf(buf, sizeof (buf), "SSL port=%d",
		    saddr->sin_port);
		au_write((caddr_t *)&ad, au_to_text(buf));

		(void) snprintf(buf, sizeof (buf), "proxy port=%d",
		    kp->kssl_proxy_port);
		au_write((caddr_t *)&ad, au_to_text(buf));
		break;
	}

	case KSSL_DELETE_ENTRY: {
		char buf[32];
		struct sockaddr_in *saddr = (struct sockaddr_in *)params;

		au_write((caddr_t *)&ad, au_to_text("op=KSSL_DELETE_ENTRY"));
		au_write((caddr_t *)&ad, au_to_in_addr(&(saddr->sin_addr)));
		(void) snprintf(buf, sizeof (buf), "SSL port=%d",
		    saddr->sin_port);
		au_write((caddr_t *)&ad, au_to_text(buf));
		break;
	}

	default:
		return;
	}

	/* add a return token */
	add_return_token((caddr_t *)&ad, tad->tad_scid, error, 0);

	AS_INC(as_generated, 1, kctx);
	AS_INC(as_kernel, 1, kctx);

	au_close(kctx, (caddr_t *)&ad, AU_OK, AUE_CONFIGKSSL, 0);
}

/*
 * Audit the kernel PF_POLICY administration commands.  Record command,
 * zone, policy type (global or tunnel, active or inactive)
 */
/*
 * ROUTINE:	AUDIT_PF_POLICY
 * PURPOSE:	Records arguments to administrative ioctls on PF_POLICY socket
 * CALLBY:	SPD_ADDRULE, SPD_DELETERULE, SPD_FLUSH, SPD_UPDATEALGS,
 *		SPD_CLONE, SPD_FLIP
 * NOTE:
 * TODO:
 * QUESTION:
 */

void
audit_pf_policy(int cmd, cred_t *cred, netstack_t *ns, char *tun,
    boolean_t active, int error, pid_t pid)
{
	const auditinfo_addr_t	*ainfo;
	t_audit_data_t		*tad;
	token_t			*ad = NULL;
	au_kcontext_t		*kctx = GET_KCTX_PZ;
	char			buf[80];
	int			flag;

	tad = U2A(u);
	if (tad == NULL)
		return;

	ainfo = crgetauinfo((cred != NULL) ? cred : CRED());
	if (ainfo == NULL)
		return;

	/*
	 * Initialize some variables since these are only set
	 * with system calls.
	 */

	switch (cmd) {
	case SPD_ADDRULE: {
		tad->tad_event = AUE_PF_POLICY_ADDRULE;
		break;
	}

	case SPD_DELETERULE: {
		tad->tad_event = AUE_PF_POLICY_DELRULE;
		break;
	}

	case SPD_FLUSH: {
		tad->tad_event = AUE_PF_POLICY_FLUSH;
		break;
	}

	case SPD_UPDATEALGS: {
		tad->tad_event = AUE_PF_POLICY_ALGS;
		break;
	}

	case SPD_CLONE: {
		tad->tad_event = AUE_PF_POLICY_CLONE;
		break;
	}

	case SPD_FLIP: {
		tad->tad_event = AUE_PF_POLICY_FLIP;
		break;
	}

	default:
		tad->tad_event = AUE_NULL;
	}

	tad->tad_evmod = 0;

	if (flag = audit_success(kctx, tad, error, cred)) {
		zone_t *nszone;

		/*
		 * For now, just audit that an event happened,
		 * along with the error code.
		 */
		au_write((caddr_t *)&ad,
		    au_to_arg32(1, "Policy Active?", (uint32_t)active));
		au_write((caddr_t *)&ad,
		    au_to_arg32(2, "Policy Global?", (uint32_t)(tun == NULL)));

		/* Supplemental data */

		/*
		 * Generate this zone token if the target zone differs
		 * from the administrative zone.  If netstacks are expanded
		 * to something other than a 1-1 relationship with zones,
		 * the auditing framework should create a new token type
		 * and audit it as a netstack instead.
		 * Turn on general zone auditing to get the administrative zone.
		 */

		nszone = zone_find_by_id(netstackid_to_zoneid(
		    ns->netstack_stackid));
		if (nszone != NULL) {
			if (strncmp(cred->cr_zone->zone_name, nszone->zone_name,
			    ZONENAME_MAX) != 0) {
				token_t *ztoken;

				ztoken = au_to_zonename(0, nszone);
				au_write((caddr_t *)&ad, ztoken);
			}
			zone_rele(nszone);
		}

		if (tun != NULL) {
			/* write tunnel name - tun is bounded */
			(void) snprintf(buf, sizeof (buf), "tunnel_name:%s",
			    tun);
			au_write((caddr_t *)&ad, au_to_text(buf));
		}

		/* Add subject information */
		AUDIT_SETSUBJ_GENERIC((caddr_t *)&ad,
		    ((cred != NULL) ? cred : CRED()), ainfo, kctx, pid);

		/* add a return token */
		add_return_token((caddr_t *)&ad, 0, error, 0);

		AS_INC(as_generated, 1, kctx);
		AS_INC(as_kernel, 1, kctx);

	}
	au_close(kctx, (caddr_t *)&ad, flag, tad->tad_event, 0);

	/*
	 * clear the ctrl flag so that we don't have spurious collection of
	 * audit information.
	 */
	tad->tad_scid  = 0;
	tad->tad_event = 0;
	tad->tad_evmod = 0;
	tad->tad_ctrl  = 0;
}

/*
 * ROUTINE:	AUDIT_SEC_ATTRIBUTES
 * PURPOSE:	Add security attributes
 * CALLBY:	AUDIT_ATTRIBUTES
 *		AUDIT_CLOSEF
 *		AUS_CLOSE
 * NOTE:
 * TODO:
 * QUESTION:
 */

void
audit_sec_attributes(caddr_t *ad, struct vnode *vp)
{
	/* Dump the SL */
	if (is_system_labeled()) {
		ts_label_t	*tsl;
		bslabel_t	*bsl;

		tsl = getflabel(vp);
		if (tsl == NULL)
			return;			/* nothing else to do */

		bsl = label2bslabel(tsl);
		if (bsl == NULL)
			return;			/* nothing else to do */
		au_write(ad, au_to_label(bsl));
		label_rele(tsl);
	}

}	/* AUDIT_SEC_ATTRIBUTES */
