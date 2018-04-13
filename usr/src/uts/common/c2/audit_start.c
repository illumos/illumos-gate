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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/cred.h>
#include <sys/zone.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_kevents.h>
#include <c2/audit_record.h>
#include "audit_door_infc.h"

extern uint_t num_syscall;		/* size of audit_s2e table */
extern kmutex_t pidlock;		/* proc table lock */

/*
 * Obsolete and ignored - Historically, the 'set c2audit:audit_load=1' entry
 * in /etc/system enabled auditing. The No Reboot Audit project does not
 * use this entry. However, to prevent the system from printing warning
 * messages, the audit_load entry is being left in /etc/system. It will be
 * removed when there is a small chance that the entry is used on currently
 * running systems.
 */
int audit_load = 0;

kmutex_t module_lock;			/* audit_module_state lock */

/*
 * Das Boot. Initialize first process. Also generate an audit record indicating
 * that the system has been booted.
 */
void
audit_init_module()
{
	token_t *rp = NULL;
	label_t jb;
	t_audit_data_t *tad = U2A(u);

	/*
	 * Solaris Auditing module is being loaded -> change the state. The lock
	 * is here to prevent memory leaks caused by multiple initializations.
	 */
	mutex_enter(&module_lock);
	if (audit_active != C2AUDIT_UNLOADED) {
		mutex_exit(&module_lock);
		return;
	}
	audit_active = C2AUDIT_LOADED;
	mutex_exit(&module_lock);

	/* initialize memory allocators */
	au_mem_init();

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

	ASSERT(tad->tad_errjmp == NULL);
	tad->tad_errjmp = (void *)&jb;
	tad->tad_ctrl |= TAD_ERRJMP;

	/* generate a system-booted audit record */
	au_write((caddr_t *)&rp, au_to_text("booting kernel"));
	audit_async_finish((caddr_t *)&rp, AUE_SYSTEMBOOT, NULL,
	    &(p0.p_user.u_start));
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
	uint32_t audit_state,
	int error,
	klwp_t *lwp)
{
	struct t_audit_data	*tad;
	au_kcontext_t		*kctx;

	tad = U2A(u);
	ASSERT(tad != NULL);

	/* Remember the audit state in the cache */
	tad->tad_audit = audit_state;

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
	if (audit_s2e[scid].au_init != (au_event_t (*)(au_event_t))NULL) {
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
	if (audit_state & ~(AUC_AUDITING | AUC_INIT_AUDIT)) {
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
	if (audit_state == AUC_NOSPACE) {
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

	if (tad->tad_flag == 0 && !(tad->tad_ctrl & TAD_SAVPATH)) {
		/*
		 * clear the ctrl flag so that we don't have spurious
		 * collection of audit information.
		 */
		tad->tad_scid  = 0;
		tad->tad_event = 0;
		tad->tad_evmod = 0;
		tad->tad_ctrl  = 0;
		tad->tad_audit = AUC_UNSET;
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
		au_close(kctx, &(u_ad), flag, tad->tad_event, tad->tad_evmod,
		    NULL);
	}

	ASSERT(u_ad == NULL);

	/* free up any space remaining with the path's */
	if (tad->tad_aupath != NULL) {
		au_pathrele(tad->tad_aupath);
		tad->tad_aupath = NULL;
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
	tad->tad_audit = AUC_UNSET;
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
	if (tad->tad_ctrl & TAD_NOAUDIT)
		return (0);

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
	} else if (tad->tad_scid == SYS_execve &&
	    getpflags(PRIV_PFEXEC, CRED()) != 0) {
		estate = kctx->auk_ets[AUE_PFEXEC];
		if (amask.as_success & estate || amask.as_failure & estate)
			flag = 1;
	}

	return (flag);
}
