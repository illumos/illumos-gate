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
 * This file contains the envelope code for system call auditing.
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
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_kevents.h>
#include <c2/audit_record.h>
#include "audit_door_infc.h"

extern uint_t num_syscall;		/* size of audit_s2e table */
extern kmutex_t pidlock;		/* proc table lock */

int audit_load = 0;	/* set from /etc/system */

struct p_audit_data *pad0;
struct t_audit_data *tad0;

/*
 * Das Boot. Initialize first process. Also generate an audit record indicating
 * that the system has been booted.
 */
void
audit_init()
{
	kthread_t *au_thread;
	token_t *rp = NULL;
	label_t jb;
	struct audit_path apempty;
	auditinfo_addr_t *ainfo;

	if (audit_load == 0) {
		audit_active = 0;
		au_auditstate = AUC_DISABLED;
		return;
#ifdef DEBUG
	} else if (audit_load == 2) {
		debug_enter((char *)NULL);
#endif
	}

	audit_active = 1;
	set_all_proc_sys();		/* set pre- and post-syscall flags */

	/* initialize memory allocators */
	au_mem_init();

	au_zone_setup();

	/* inital thread structure */
	tad0 = kmem_zalloc(sizeof (struct t_audit_data), KM_SLEEP);

	/* initial process structure */
	pad0 = kmem_cache_alloc(au_pad_cache, KM_SLEEP);
	bzero(&pad0->pad_data, sizeof (pad0->pad_data));

	T2A(curthread) = tad0;
	P2A(curproc) = pad0;

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

	tad0->tad_ad   = NULL;
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

	/*
	 * setup environment for asynchronous auditing. We can't use
	 * audit_async_start() here since it assumes the audit system
	 * has been started via auditd(1m). auditd sets the variable,
	 * auk_auditstate, to indicate audit record generation should
	 * commence. Here we want to always generate an audit record.
	 */
	if (setjmp(&jb)) {
		/* process audit policy (AUDIT_AHLT) for asynchronous events */
		audit_async_drop((caddr_t *)(&rp), 0);
		return;
	}

	ASSERT(tad0->tad_errjmp == NULL);
	tad0->tad_errjmp = (void *)&jb;
	tad0->tad_ctrl |= PAD_ERRJMP;

	/* generate a system-booted audit record */
	au_write((caddr_t *)&rp, au_to_text("booting kernel"));

	audit_async_finish((caddr_t *)&rp, AUE_SYSTEMBOOT, NULL);
}

void
audit_free()
{
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
	cred_t	*newcred = ncr;

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
				mutex_enter(&pad->pad_lock);
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
 * Enter system call. Do any necessary setup here. allocate resouces, etc.
 */

#include <sys/syscall.h>


/*ARGSUSED*/
int
audit_start(
	unsigned type,
	unsigned scid,
	int error,
	klwp_t *lwp)
{
	struct t_audit_data	*tad;
	au_kcontext_t		*kctx;

	tad = U2A(u);
	ASSERT(tad != NULL);

	if (error) {
		tad->tad_ctrl = 0;
		tad->tad_flag = 0;
		return (0);
	}

	audit_update_context(curproc, NULL);

	/*
	 * if this is an indirect system call then don't do anything.
	 * audit_start will be called again from indir() in trap.c
	 */
	if (scid == 0) {
		tad->tad_ctrl = 0;
		tad->tad_flag = 0;
		return (0);
	}
	if (scid >= num_syscall)
		scid = 0;

	/*
	 * we can no longer depend on a valid lwp_ap, so we need to
	 * copy the syscall args as future audit stuff may need them.
	 */
	(void) save_syscall_args();

	/*
	 * We need to gather paths for certain system calls even if they are
	 * not audited so that we can audit the various f* calls and be
	 * sure to have a CWD and CAR. Thus we thus set tad_ctrl over the
	 * system call regardless if the call is audited or not.
	 * We allow the event specific initial processing routines (au_init)
	 * to adjust the tad_ctrl as necessary.
	 */
	tad->tad_ctrl   = audit_s2e[scid].au_ctrl;
	tad->tad_scid   = scid;

	/* get basic event for system call */
	tad->tad_event = audit_s2e[scid].au_event;
	if (audit_s2e[scid].au_init != (au_event_t)AUE_NULL) {
		/* get specific event */
		tad->tad_event = (*audit_s2e[scid].au_init)(tad->tad_event);
	}

	kctx = GET_KCTX_PZ;

	/* now do preselection. Audit or not to Audit, that is the question */
	if ((tad->tad_flag = auditme(kctx, tad,
	    kctx->auk_ets[tad->tad_event])) == 0) {
		/*
		 * we assume that audit_finish will always be called.
		 */
		return (0);
	}

	/*
	 * if auditing not enabled, then don't generate an audit record
	 * and don't count it.
	 */
	if ((kctx->auk_auditstate != AUC_AUDITING &&
	    kctx->auk_auditstate != AUC_INIT_AUDIT)) {
		/*
		 * we assume that audit_finish will always be called.
		 */
		tad->tad_flag = 0;
		return (0);
	}

	/*
	 * audit daemon has informed us that there is no longer any
	 * space left to hold audit records. We decide here if records
	 * should be dropped (but counted).
	 */
	if (kctx->auk_auditstate == AUC_NOSPACE) {
		if ((kctx->auk_policy & AUDIT_CNT) ||
		    (kctx->auk_policy & AUDIT_SCNT)) {
			/* assume that audit_finish will always be called. */
			tad->tad_flag = 0;

			/* just count # of dropped audit records */
			AS_INC(as_dropped, 1, kctx);

			return (0);
		}
	}

	tad->tad_evmod  = 0;

	if (audit_s2e[scid].au_start != NULL) {
		/* do start of system call processing */
		(*audit_s2e[scid].au_start)(tad);
	}

	return (0);
}

/*
 * system call has completed. Now determine if we genearate an audit record
 * or not.
 */
/*ARGSUSED*/
void
audit_finish(
	unsigned type,
	unsigned scid,
	int error,
	rval_t *rval)
{
	struct t_audit_data *tad;
	int	flag;
	au_defer_info_t	*attr;
	au_kcontext_t *kctx = GET_KCTX_PZ;

	tad = U2A(u);

	/*
	 * Process all deferred events first.
	 */
	attr = tad->tad_defer_head;
	while (attr != NULL) {
		au_defer_info_t	*tmp_attr = attr;

		au_close_time(kctx, (token_t *)attr->audi_ad, attr->audi_flag,
		    attr->audi_e_type, attr->audi_e_mod, &(attr->audi_atime));

		attr = attr->audi_next;
		kmem_free(tmp_attr, sizeof (au_defer_info_t));
	}
	tad->tad_defer_head = tad->tad_defer_tail = NULL;

	if (tad->tad_flag == 0 && !(tad->tad_ctrl & PAD_SAVPATH)) {
		/*
		 * clear the ctrl flag so that we don't have spurious
		 * collection of audit information.
		 */
		tad->tad_scid  = 0;
		tad->tad_event = 0;
		tad->tad_evmod = 0;
		tad->tad_ctrl  = 0;
		ASSERT(tad->tad_aupath == NULL);
		return;
	}

	scid = tad->tad_scid;

	/*
	 * Perform any extra processing and determine if we are
	 * really going to generate any audit record.
	 */
	if (audit_s2e[scid].au_finish != NULL) {
		/* do any post system call processing */
		(*audit_s2e[scid].au_finish)(tad, error, rval);
	}
	if (tad->tad_flag) {
		tad->tad_flag = 0;

		if (flag = audit_success(kctx, tad, error, NULL)) {
			unsigned int sy_flags;
			cred_t *cr = CRED();
			const auditinfo_addr_t *ainfo = crgetauinfo(cr);

			ASSERT(ainfo != NULL);

			/* Add subject information */
			AUDIT_SETSUBJ(&(u_ad), cr, ainfo, kctx);

			if (tad->tad_evmod & PAD_SPRIVUSE) {
				au_write(&(u_ad),
				    au_to_privset("", &tad->tad_sprivs,
				    AUT_UPRIV, 1));
			}

			if (tad->tad_evmod & PAD_FPRIVUSE) {
				au_write(&(u_ad),
				    au_to_privset("", &tad->tad_fprivs,
				    AUT_UPRIV, 0));
			}

			/* Add a return token */
#ifdef	_SYSCALL32_IMPL
			if (lwp_getdatamodel(ttolwp(curthread)) ==
			    DATAMODEL_NATIVE) {
				sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
			} else {
				sy_flags =
				    sysent32[scid].sy_flags & SE_RVAL_MASK;
			}
#else	/* _SYSCALL64_IMPL */
			sy_flags = sysent[scid].sy_flags & SE_RVAL_MASK;
#endif   /* _SYSCALL32_IMPL */

			if (sy_flags == SE_32RVAL1) {
				if (type == 0) {
					au_write(&(u_ad),
					    au_to_return32(error, 0));
				} else {
					au_write(&(u_ad), au_to_return32(error,
					    rval->r_val1));
				}
			}
			if (sy_flags == (SE_32RVAL2|SE_32RVAL1)) {
				if (type == 0) {
					au_write(&(u_ad),
					    au_to_return32(error, 0));
				} else {
					au_write(&(u_ad),
					    au_to_return32(error,
					    rval->r_val1));
#ifdef NOTYET	/* for possible future support */
					au_write(&(u_ad), au_to_return32(error,
					    rval->r_val2));
#endif
				}
			}
			if (sy_flags == SE_64RVAL) {
				if (type == 0) {
					au_write(&(u_ad),
					    au_to_return64(error, 0));
				} else {
					au_write(&(u_ad), au_to_return64(error,
					    rval->r_vals));
				}
			}

			AS_INC(as_generated, 1, kctx);
			AS_INC(as_kernel, 1, kctx);
		}

		/* Close up everything */
		au_close(kctx, &(u_ad), flag, tad->tad_event, tad->tad_evmod);
	}

	ASSERT(u_ad == NULL);

	/* free up any space remaining with the path's */
	if (tad->tad_aupath != NULL) {
		au_pathrele(tad->tad_aupath);
		tad->tad_aupath = NULL;
		tad->tad_vn = NULL;
	}

	/* free up any space remaining with openat path's */
	if (tad->tad_atpath) {
		au_pathrele(tad->tad_atpath);
		tad->tad_atpath = NULL;
	}

	/*
	 * clear the ctrl flag so that we don't have spurious collection of
	 * audit information.
	 */
	tad->tad_scid  = 0;
	tad->tad_event = 0;
	tad->tad_evmod = 0;
	tad->tad_ctrl  = 0;
}

int
audit_success(au_kcontext_t *kctx, struct t_audit_data *tad, int error,
    cred_t *cr)
{
	au_state_t ess;
	au_state_t esf;
	au_mask_t amask;
	const auditinfo_addr_t *ainfo;

	ess = esf = kctx->auk_ets[tad->tad_event];

	if (error)
		tad->tad_evmod |= PAD_FAILURE;

	/* see if we really want to generate an audit record */
	if (tad->tad_ctrl & PAD_NOAUDIT)
		return (0);

	/*
	 * nfs operation and we're auditing privilege or MAC. This
	 * is so we have a client audit record to match a nfs server
	 * audit record.
	 */
	if (tad->tad_ctrl & PAD_AUDITME)
		return (AU_OK);

	/*
	 * Used passed cred if available, otherwise use cred from kernel thread
	 */
	if (cr == NULL)
		cr = CRED();
	ainfo = crgetauinfo(cr);
	if (ainfo == NULL)
		return (0);
	amask = ainfo->ai_mask;

	if (error == 0)
		return ((ess & amask.as_success) ? AU_OK : 0);
	else
		return ((esf & amask.as_failure) ? AU_OK : 0);
}

/*
 * determine if we've preselected this event (system call).
 */
int
auditme(au_kcontext_t *kctx, struct t_audit_data *tad, au_state_t estate)
{
	int flag = 0;
	au_mask_t amask;
	const auditinfo_addr_t *ainfo;

	ainfo = crgetauinfo(CRED());
	if (ainfo == NULL)
		return (0);
	amask = ainfo->ai_mask;

		/* preselected system call */

	if (amask.as_success & estate || amask.as_failure & estate) {
		flag = 1;
	} else if ((tad->tad_scid == SYS_putmsg) ||
	    (tad->tad_scid == SYS_getmsg)) {
		estate = kctx->auk_ets[AUE_SOCKCONNECT]	|
		    kctx->auk_ets[AUE_SOCKACCEPT]	|
		    kctx->auk_ets[AUE_SOCKSEND]		|
		    kctx->auk_ets[AUE_SOCKRECEIVE];
		if (amask.as_success & estate || amask.as_failure & estate)
			flag = 1;
	}

	return (flag);
}
