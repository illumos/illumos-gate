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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/stropts.h>
#include <sys/systm.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/cred_impl.h>
#include <sys/zone.h>
#include <sys/modctl.h>
#include <sys/sysconf.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_kevents.h>
#include <c2/audit_record.h>


struct p_audit_data *pad0;
struct t_audit_data *tad0;

extern uint_t num_syscall;		/* size of audit_s2e table */
extern kmutex_t pidlock;		/* proc table lock */


void
audit_init()
{
	kthread_t	    *au_thread;
	auditinfo_addr_t    *ainfo;
	struct audit_path   apempty;

	/*
	 * If the c2audit module is explicitely excluded in /etc/system,
	 * it cannot be loaded later (e.g. using modload). Make a notice
	 * that the module won't be present and do nothing.
	 */

	if (mod_sysctl(SYS_CHECK_EXCLUDE, "c2audit") != 0) {
		audit_active = C2AUDIT_DISABLED;
		return;
	}

	/* c2audit module can be loaded anytime */
	audit_active = C2AUDIT_UNLOADED;

	/* initialize the process audit data (pad) memory allocator */
	au_pad_init();

	/* initialize the zone audit context */
	au_zone_setup();

	/* inital thread structure */
	tad0 = kmem_zalloc(sizeof (struct t_audit_data), KM_SLEEP);

	/* initial process structure */
	pad0 = kmem_cache_alloc(au_pad_cache, KM_SLEEP);
	bzero(&pad0->pad_data, sizeof (pad0->pad_data));

	curthread->t_audit_data = tad0;
	curproc->p_audit_data = pad0;

	/*
	 * The kernel allocates a bunch of threads make sure they have
	 * a valid tad
	 */

	mutex_enter(&pidlock);

	au_thread = curthread;
	do {
		if (T2A(au_thread) == NULL) {
			T2A(au_thread) = tad0;
		}
		au_thread = au_thread->t_next;
	} while (au_thread != curthread);

	tad0->tad_ad = NULL;
	mutex_exit(&pidlock);

	/*
	 * Initialize audit context in our cred (kcred).
	 * No copy-on-write needed here because it's so early in init.
	 */

	ainfo = crgetauinfo_modifiable(kcred);
	ASSERT(ainfo != NULL);
	bzero(ainfo, sizeof (auditinfo_addr_t));
	ainfo->ai_auid = AU_NOAUDITID;

	/* fabricate an empty audit_path to extend */
	apempty.audp_cnt = 0;
	apempty.audp_sect[0] = (char *)(&apempty.audp_sect[1]);
	pad0->pad_root = au_pathdup(&apempty, 1, 2);
	bcopy("/", pad0->pad_root->audp_sect[0], 2);
	au_pathhold(pad0->pad_root);
	pad0->pad_cwd = pad0->pad_root;
}

/*
 * Check for any pending changes to the audit context for the given proc.
 * p_crlock and pad_lock for the process are acquired here. Caller is
 * responsible for assuring the process doesn't go away. If context is
 * updated, the specified cralloc'ed cred will be used, otherwise it's freed.
 * If no cred is given, it will be cralloc'ed here and caller assures that
 * it is safe to allocate memory.
 */

void
audit_update_context(proc_t *p, cred_t *ncr)
{
	struct p_audit_data *pad;
	cred_t *newcred = ncr;

	pad = P2A(p);
	if (pad == NULL) {
		if (newcred != NULL)
			crfree(newcred);
		return;
	}

	/* If a mask update is pending, take care of it. */
	if (pad->pad_flags & PAD_SETMASK) {
		auditinfo_addr_t *ainfo;

		if (newcred == NULL)
			newcred = cralloc();

		mutex_enter(&pad->pad_lock);
		/* the condition may have been handled by the time we lock */
		if (pad->pad_flags & PAD_SETMASK) {
			ainfo = crgetauinfo_modifiable(newcred);
			if (ainfo == NULL) {
				mutex_exit(&pad->pad_lock);
				crfree(newcred);
				return;
			}

			mutex_enter(&p->p_crlock);
			crcopy_to(p->p_cred, newcred);
			p->p_cred = newcred;

			ainfo->ai_mask = pad->pad_newmask;

			/* Unlock and cleanup. */
			mutex_exit(&p->p_crlock);
			pad->pad_flags &= ~PAD_SETMASK;

			/*
			 * For curproc, assure that our thread points to right
			 * cred, so CRED() will be correct. Otherwise, no need
			 * to broadcast changes (via set_proc_pre_sys), since
			 * t_pre_sys is ALWAYS on when audit is enabled... due
			 * to syscall auditing.
			 */
			if (p == curproc)
				crset(p, newcred);
			else
				crfree(newcred);
		} else {
			crfree(newcred);
		}
		mutex_exit(&pad->pad_lock);
	} else {
		if (newcred != NULL)
			crfree(newcred);
	}
}

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
	 * If we are in the limited mode, there is nothing to audit and
	 * there could not have been anything to audit, since it is not
	 * possible to switch from the full mode into the limited mode
	 * once the full mode is set.
	 */
	if (audit_active != C2AUDIT_LOADED)
		return;

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

	if (audit_active == C2AUDIT_LOADED) {
		attr = tad->tad_defer_head;
		while (attr != NULL) {
			au_defer_info_t	*tmp_attr = attr;

			au_free_rec(attr->audi_ad);

			attr = attr->audi_next;
			kmem_free(tmp_attr, sizeof (au_defer_info_t));
		}
	}

	kmem_free(tad, sizeof (*tad));
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

uint32_t
audit_getstate()
{
	return (audit_active == C2AUDIT_LOADED &&
	    ((AU_AUDIT_MASK) & U2A(u)->tad_audit));
}
