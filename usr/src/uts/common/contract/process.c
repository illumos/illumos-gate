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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/mutex.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/id_space.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/contract.h>
#include <sys/contract_impl.h>
#include <sys/contract/process.h>
#include <sys/contract/process_impl.h>
#include <sys/cmn_err.h>
#include <sys/nvpair.h>
#include <sys/policy.h>
#include <sys/refstr.h>
#include <sys/sunddi.h>

/*
 * Process Contracts
 * -----------------
 *
 * Generally speaking, a process contract is a contract between a
 * process and a set of its descendent processes.  In some cases, when
 * the child processes outlive the author of the contract, the contract
 * may be held by (and therefore be between the child processes and) a
 * successor process which adopts the contract after the death of the
 * original author.
 *
 * The process contract adds two new concepts to the Solaris process
 * model.  The first is that a process contract forms a rigid fault
 * boundary around a set of processes.  Hardware, software, and even
 * administrator errors impacting a process in a process contract
 * generate specific events and can be requested to atomically shutdown
 * all processes in the contract.  The second is that a process
 * contract is a process collective whose leader is not a member of the
 * collective.  This means that the leader can reliably react to events
 * in the collective, and may also act upon the collective without
 * special casing itself.
 *
 * A composite outcome of these two concepts is that we can now create
 * a tree of process contracts, rooted at init(1M), which represent
 * services and subservices that are reliably observed and can be
 * restarted when fatal errors occur.  The service management framework
 * (SMF) realizes this structure.
 *
 * For more details, see the "restart agreements" case, PSARC 2003/193.
 *
 * There are four sets of routines in this file: the process contract
 * standard template operations, the process contract standard contract
 * operations, a couple routines used only by the contract subsystem to
 * handle process contracts' unique role as a temporary holder of
 * abandoned contracts, and the interfaces which allow the system to
 * create and act upon process contracts.  The first two are defined by
 * the contracts framework and won't be discussed further.  As for the
 * remaining two:
 *
 * Special framework interfaces
 * ----------------------------
 *
 * contract_process_accept - determines if a process contract is a
 *   regent, i.e. if it can inherit other contracts.
 *
 * contract_process_take - tells a regent process contract to inherit
 *   an abandoned contract
 *
 * contract_process_adopt - tells a regent process contract that a
 *   contract it has inherited is being adopted by a process.
 *
 * Process contract interfaces
 * ---------------------------
 *
 * contract_process_fork - called when a process is created; adds the
 *   new process to an existing contract or to a newly created one.
 *
 * contract_process_exit - called when a process exits
 *
 * contract_process_core - called when a process would have dumped core
 *   (even if a core file wasn't generated)
 *
 * contract_process_hwerr - called when a process was killed because of
 *   an uncorrectable hardware error
 *
 * contract_process_sig - called when a process was killed by a fatal
 *   signal sent by a process in another process contract
 *
 */

ct_type_t *process_type;
ctmpl_process_t *sys_process_tmpl;
refstr_t *conp_svc_aux_default;

/*
 * Macro predicates for determining when events should be sent and how.
 */
#define	EVSENDP(ctp, flag) \
	((ctp->conp_contract.ct_ev_info | ctp->conp_contract.ct_ev_crit) & flag)

#define	EVINFOP(ctp, flag) \
	((ctp->conp_contract.ct_ev_crit & flag) == 0)

#define	EVFATALP(ctp, flag) \
	(ctp->conp_ev_fatal & flag)


/*
 * Process contract template implementation
 */

/*
 * ctmpl_process_dup
 *
 * The process contract template dup entry point.  Other than the
 * to-be-subsumed contract, which must be held, this simply copies all
 * the fields of the original.
 */
static struct ct_template *
ctmpl_process_dup(struct ct_template *template)
{
	ctmpl_process_t *new;
	ctmpl_process_t *old = template->ctmpl_data;

	new = kmem_alloc(sizeof (ctmpl_process_t), KM_SLEEP);

	ctmpl_copy(&new->ctp_ctmpl, template);
	new->ctp_ctmpl.ctmpl_data = new;

	new->ctp_subsume = old->ctp_subsume;
	if (new->ctp_subsume)
		contract_hold(new->ctp_subsume);
	new->ctp_params = old->ctp_params;
	new->ctp_ev_fatal = old->ctp_ev_fatal;
	new->ctp_svc_fmri = old->ctp_svc_fmri;
	if (new->ctp_svc_fmri != NULL) {
		refstr_hold(new->ctp_svc_fmri);
	}
	new->ctp_svc_aux = old->ctp_svc_aux;
	if (new->ctp_svc_aux != NULL) {
		refstr_hold(new->ctp_svc_aux);
	}

	return (&new->ctp_ctmpl);
}

/*
 * ctmpl_process_free
 *
 * The process contract template free entry point.  Just releases a
 * to-be-subsumed contract and frees the template.
 */
static void
ctmpl_process_free(struct ct_template *template)
{
	ctmpl_process_t *ctp = template->ctmpl_data;

	if (ctp->ctp_subsume)
		contract_rele(ctp->ctp_subsume);
	if (ctp->ctp_svc_fmri != NULL) {
		refstr_rele(ctp->ctp_svc_fmri);
	}
	if (ctp->ctp_svc_aux != NULL) {
		refstr_rele(ctp->ctp_svc_aux);
	}
	kmem_free(template, sizeof (ctmpl_process_t));
}

/*
 * SAFE_EV is the set of events which a non-privileged process is
 * allowed to make critical but not fatal or if the PGRPONLY parameter
 * is set.  EXCESS tells us if "value", a critical event set, requires
 * additional privilege given the template "ctp".
 */
#define	SAFE_EV			(CT_PR_EV_EMPTY)
#define	EXCESS(ctp, value)	\
	(((value) & ~((ctp)->ctp_ev_fatal | SAFE_EV)) || \
	(((value) & ~SAFE_EV) && (ctp->ctp_params & CT_PR_PGRPONLY)))

/*
 * ctmpl_process_set
 *
 * The process contract template set entry point.  None of the terms
 * may be unconditionally set, and setting the parameters or fatal
 * event set may result in events being implicitly removed from to the
 * critical event set and added to the informative event set.  The
 * (admittedly subtle) reason we implicitly change the critical event
 * set when the parameter or fatal event set is modified but not the
 * other way around is because a change to the critical event set only
 * affects the contract's owner, whereas a change to the parameter set
 * and fatal set can affect the execution of the application running in
 * the contract (and should therefore be only made explicitly).  We
 * allow implicit changes at all so that setting contract terms doesn't
 * become a complex dance dependent on the template's initial state and
 * the desired terms.
 */
static int
ctmpl_process_set(struct ct_template *tmpl, ct_kparam_t *kparam,
    const cred_t *cr)
{
	ctmpl_process_t *ctp = tmpl->ctmpl_data;
	ct_param_t *param = &kparam->param;
	contract_t *ct;
	int error;
	uint64_t param_value = 0;
	char *str_value;

	if ((param->ctpm_id == CTPP_SVC_FMRI) ||
	    (param->ctpm_id == CTPP_CREATOR_AUX)) {
		str_value = (char *)kparam->ctpm_kbuf;
		str_value[param->ctpm_size - 1] = '\0';
	} else {
		if (param->ctpm_size < sizeof (uint64_t))
			return (EINVAL);
		param_value = *(uint64_t *)kparam->ctpm_kbuf;
		/*
		 * No process contract parameters are > 32 bits.
		 * Unless it is a string.
		 */
		if (param_value & ~UINT32_MAX)
			return (EINVAL);
	}

	switch (param->ctpm_id) {
	case CTPP_SUBSUME:
		if (param_value != 0) {
			/*
			 * Ensure that the contract exists, that we
			 * hold the contract, and that the contract is
			 * empty.
			 */
			ct = contract_type_ptr(process_type, param_value,
			    curproc->p_zone->zone_uniqid);
			if (ct == NULL)
				return (ESRCH);
			if (ct->ct_owner != curproc) {
				contract_rele(ct);
				return (EACCES);
			}
			if (((cont_process_t *)ct->ct_data)->conp_nmembers) {
				contract_rele(ct);
				return (ENOTEMPTY);
			}
		} else {
			ct = NULL;
		}
		if (ctp->ctp_subsume)
			contract_rele(ctp->ctp_subsume);
		ctp->ctp_subsume = ct;
		break;
	case CTPP_PARAMS:
		if (param_value & ~CT_PR_ALLPARAM)
			return (EINVAL);
		ctp->ctp_params = param_value;
		/*
		 * If an unprivileged process requests that
		 * CT_PR_PGRPONLY be set, remove any unsafe events from
		 * the critical event set and add them to the
		 * informative event set.
		 */
		if ((ctp->ctp_params & CT_PR_PGRPONLY) &&
		    EXCESS(ctp, tmpl->ctmpl_ev_crit) &&
		    !secpolicy_contract_event_choice(cr)) {
			tmpl->ctmpl_ev_info |= (tmpl->ctmpl_ev_crit & ~SAFE_EV);
			tmpl->ctmpl_ev_crit &= SAFE_EV;
		}

		break;
	case CTPP_SVC_FMRI:
		if (error = secpolicy_contract_identity(cr))
			return (error);
		if (ctp->ctp_svc_fmri != NULL)
			refstr_rele(ctp->ctp_svc_fmri);
		if (strcmp(CT_PR_SVC_DEFAULT, str_value) == 0)
			ctp->ctp_svc_fmri = NULL;
		else
			ctp->ctp_svc_fmri =
			    refstr_alloc(str_value);
		break;
	case CTPP_CREATOR_AUX:
		if (ctp->ctp_svc_aux != NULL)
			refstr_rele(ctp->ctp_svc_aux);
		if (param->ctpm_size == 1) /* empty string */
			ctp->ctp_svc_aux = NULL;
		else
			ctp->ctp_svc_aux =
			    refstr_alloc(str_value);
		break;
	case CTP_EV_CRITICAL:
		/*
		 * We simply don't allow adding events to the critical
		 * event set which aren't permitted by our policy or by
		 * privilege.
		 */
		if (EXCESS(ctp, param_value) &&
		    (error = secpolicy_contract_event(cr)) != 0)
			return (error);
		tmpl->ctmpl_ev_crit = param_value;
		break;
	case CTPP_EV_FATAL:
		if (param_value & ~CT_PR_ALLFATAL)
			return (EINVAL);
		ctp->ctp_ev_fatal = param_value;
		/*
		 * Check to see if an unprivileged process is
		 * requesting that events be removed from the fatal
		 * event set which are still in the critical event set.
		 */
		if (EXCESS(ctp, tmpl->ctmpl_ev_crit) &&
		    !secpolicy_contract_event_choice(cr)) {
			int allowed =
			    SAFE_EV | (ctp->ctp_params & CT_PR_PGRPONLY) ?
			    0 : ctp->ctp_ev_fatal;
			tmpl->ctmpl_ev_info |= (tmpl->ctmpl_ev_crit & ~allowed);
			tmpl->ctmpl_ev_crit &= allowed;
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * ctmpl_process_get
 *
 * The process contract template get entry point.  Simply fetches and
 * returns the requested term.
 */
static int
ctmpl_process_get(struct ct_template *template, ct_kparam_t *kparam)
{
	ctmpl_process_t *ctp = template->ctmpl_data;
	ct_param_t *param = &kparam->param;
	uint64_t *param_value = kparam->ctpm_kbuf;

	if (param->ctpm_id == CTPP_SUBSUME ||
	    param->ctpm_id == CTPP_PARAMS ||
	    param->ctpm_id == CTPP_EV_FATAL) {
		if (param->ctpm_size < sizeof (uint64_t))
			return (EINVAL);
		kparam->ret_size = sizeof (uint64_t);
	}

	switch (param->ctpm_id) {
	case CTPP_SUBSUME:
		*param_value = ctp->ctp_subsume ?
		    ctp->ctp_subsume->ct_id : 0;
		break;
	case CTPP_PARAMS:
		*param_value = ctp->ctp_params;
		break;
	case CTPP_SVC_FMRI:
		if (ctp->ctp_svc_fmri == NULL) {
			kparam->ret_size =
			    strlcpy((char *)kparam->ctpm_kbuf,
			    CT_PR_SVC_DEFAULT, param->ctpm_size);
		} else {
			kparam->ret_size =
			    strlcpy((char *)kparam->ctpm_kbuf,
			    refstr_value(ctp->ctp_svc_fmri), param->ctpm_size);
		}
		kparam->ret_size++;
		break;
	case CTPP_CREATOR_AUX:
		if (ctp->ctp_svc_aux == NULL) {
			kparam->ret_size =
			    strlcpy((char *)kparam->ctpm_kbuf,
			    refstr_value(conp_svc_aux_default),
			    param->ctpm_size);
		} else {
			kparam->ret_size =
			    strlcpy((char *)kparam->ctpm_kbuf,
			    refstr_value(ctp->ctp_svc_aux), param->ctpm_size);
		}
		kparam->ret_size++;
		break;
	case CTPP_EV_FATAL:
		*param_value = ctp->ctp_ev_fatal;
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static ctmplops_t ctmpl_process_ops = {
	ctmpl_process_dup,		/* ctop_dup */
	ctmpl_process_free,		/* ctop_free */
	ctmpl_process_set,		/* ctop_set */
	ctmpl_process_get,		/* ctop_get */
	ctmpl_create_inval,		/* ctop_create */
	CT_PR_ALLEVENT
};


/*
 * Process contract implementation
 */

/*
 * ctmpl_process_default
 *
 * The process contract default template entry point.  Creates a
 * process contract template with no parameters set, with informative
 * core and signal events, critical empty and hwerr events, and fatal
 * hwerr events.
 */
static ct_template_t *
contract_process_default(void)
{
	ctmpl_process_t *new;

	new = kmem_alloc(sizeof (ctmpl_process_t), KM_SLEEP);
	ctmpl_init(&new->ctp_ctmpl, &ctmpl_process_ops, process_type, new);

	new->ctp_subsume = NULL;
	new->ctp_params = 0;
	new->ctp_ctmpl.ctmpl_ev_info = CT_PR_EV_CORE | CT_PR_EV_SIGNAL;
	new->ctp_ctmpl.ctmpl_ev_crit = CT_PR_EV_EMPTY | CT_PR_EV_HWERR;
	new->ctp_ev_fatal = CT_PR_EV_HWERR;
	new->ctp_svc_fmri = NULL;
	new->ctp_svc_aux = NULL;

	return (&new->ctp_ctmpl);
}

/*
 * contract_process_free
 *
 * The process contract free entry point.
 */
static void
contract_process_free(contract_t *ct)
{
	cont_process_t *ctp = ct->ct_data;
	crfree(ctp->conp_cred);
	list_destroy(&ctp->conp_members);
	list_destroy(&ctp->conp_inherited);
	if (ctp->conp_svc_fmri != NULL) {
		refstr_rele(ctp->conp_svc_fmri);
	}
	if (ctp->conp_svc_aux != NULL) {
		refstr_rele(ctp->conp_svc_aux);
	}
	if (ctp->conp_svc_creator != NULL) {
		refstr_rele(ctp->conp_svc_creator);
	}
	kmem_free(ctp, sizeof (cont_process_t));
}

/*
 * contract_process_cankill
 *
 * Determine if the contract author had or if the process generating
 * the event, sp, has adequate privileges to kill process tp.
 */
static int
contract_process_cankill(proc_t *tp, proc_t *sp, cont_process_t *ctp)
{
	int cankill;

	mutex_enter(&tp->p_crlock);
	cankill = hasprocperm(tp->p_cred, ctp->conp_cred);
	mutex_exit(&tp->p_crlock);
	if (cankill || (sp && prochasprocperm(tp, sp, CRED())))
		return (1);

	return (0);
}

/*
 * contract_process_kill
 *
 * Kills all processes in a contract, or all processes in the
 * intersection of a contract and ex's process group (if ex is non-NULL
 * and the contract's PGRPONLY parameter is set).  If checkpriv is
 * true, only those processes which may be signaled by the contract
 * author or ex are killed.
 */
static void
contract_process_kill(contract_t *ct, proc_t *ex, int checkpriv)
{
	cont_process_t *ctp = ct->ct_data;
	proc_t *p;
	pid_t pgrp = -1;

	ASSERT(MUTEX_HELD(&ct->ct_lock));

	if (ex && (ctp->conp_params & CT_PR_PGRPONLY)) {
		pgrp = ex->p_pgrp;
		mutex_enter(&pidlock);
	}

	for (p = list_head(&ctp->conp_members); p != NULL;
	    p = list_next(&ctp->conp_members, p)) {
		if ((p == ex) ||
		    (pgrp != -1 && (p->p_stat == SIDL || p->p_pgrp != pgrp)) ||
		    (checkpriv && !contract_process_cankill(p, ex, ctp)))
			continue;

		psignal(p, SIGKILL);
	}

	if (pgrp != -1)
		mutex_exit(&pidlock);
}


/*
 * contract_process_accept
 *
 * Tests if the process contract is willing to act as a regent for
 * inherited contracts.  Though brief and only called from one place,
 * this functionality is kept here to avoid including knowledge of
 * process contract implementation in the generic contract code.
 */
int
contract_process_accept(contract_t *parent)
{
	cont_process_t *ctp = parent->ct_data;

	ASSERT(parent->ct_type == process_type);

	return (ctp->conp_params & CT_PR_REGENT);
}

/*
 * contract_process_take
 *
 * Executes the process contract side of inheriting a contract.
 */
void
contract_process_take(contract_t *parent, contract_t *child)
{
	cont_process_t *ctp = parent->ct_data;

	ASSERT(MUTEX_HELD(&parent->ct_lock));
	ASSERT(MUTEX_HELD(&child->ct_lock));
	ASSERT(parent->ct_type == process_type);
	ASSERT(ctp->conp_params & CT_PR_REGENT);

	list_insert_head(&ctp->conp_inherited, child);
	ctp->conp_ninherited++;
}

/*
 * contract_process_adopt
 *
 * Executes the process contract side of adopting a contract.
 */
void
contract_process_adopt(contract_t *ct, proc_t *p)
{
	cont_process_t *parent = p->p_ct_process;

	ASSERT(MUTEX_HELD(&parent->conp_contract.ct_lock));
	ASSERT(MUTEX_HELD(&ct->ct_lock));

	list_remove(&parent->conp_inherited, ct);
	parent->conp_ninherited--;

	/*
	 * We drop the parent lock first because a) we are passing the
	 * contract reference to the child, and b) contract_adopt
	 * expects us to return with the contract lock held.
	 */
	mutex_exit(&parent->conp_contract.ct_lock);
}

/*
 * contract_process_abandon
 *
 * The process contract abandon entry point.
 */
static void
contract_process_abandon(contract_t *ct)
{
	cont_process_t *ctp = ct->ct_data;

	ASSERT(MUTEX_HELD(&ct->ct_lock));

	/*
	 * Shall we stay or shall we go?
	 */
	if (list_head(&ctp->conp_members) == NULL) {
		contract_destroy(ct);
	} else {
		/*
		 * Strictly speaking, we actually do orphan the contract.
		 * Assuming our credentials allow us to kill all
		 * processes in the contract, this is only temporary.
		 */
		if (ctp->conp_params & CT_PR_NOORPHAN)
			contract_process_kill(ct, NULL, B_TRUE);
		contract_orphan(ct);
		mutex_exit(&ct->ct_lock);
		contract_rele(ct);
	}
}

/*
 * contract_process_destroy
 *
 * The process contract destroy entry point.
 */
static void
contract_process_destroy(contract_t *ct)
{
	cont_process_t *ctp = ct->ct_data;
	contract_t *cct;

	ASSERT(MUTEX_HELD(&ct->ct_lock));

	/*
	 * contract_destroy all empty children, kill or orphan the rest
	 */
	while (cct = list_head(&ctp->conp_inherited)) {
		mutex_enter(&cct->ct_lock);

		ASSERT(cct->ct_state == CTS_INHERITED);

		list_remove(&ctp->conp_inherited, cct);
		ctp->conp_ninherited--;
		cct->ct_regent = NULL;
		cct->ct_type->ct_type_ops->contop_abandon(cct);
	}
}

/*
 * contract_process_status
 *
 * The process contract status entry point.
 */
static void
contract_process_status(contract_t *ct, zone_t *zone, int detail, nvlist_t *nvl,
    void *status, model_t model)
{
	cont_process_t *ctp = ct->ct_data;
	uint32_t *pids, *ctids;
	uint_t npids, nctids;
	uint_t spids, sctids;
	ctid_t local_svc_zone_enter;

	if (detail == CTD_FIXED) {
		mutex_enter(&ct->ct_lock);
		contract_status_common(ct, zone, status, model);
		local_svc_zone_enter = ctp->conp_svc_zone_enter;
		mutex_exit(&ct->ct_lock);
	} else {
		contract_t *cnext;
		proc_t *pnext;
		uint_t loc;

		ASSERT(detail == CTD_ALL);
		mutex_enter(&ct->ct_lock);
		for (;;) {
			spids = ctp->conp_nmembers + 5;
			sctids = ctp->conp_ninherited + 5;
			mutex_exit(&ct->ct_lock);

			pids = kmem_alloc(spids * sizeof (uint32_t), KM_SLEEP);
			ctids = kmem_alloc(sctids * sizeof (uint32_t),
			    KM_SLEEP);

			mutex_enter(&ct->ct_lock);
			npids = ctp->conp_nmembers;
			nctids = ctp->conp_ninherited;
			if (spids >= npids && sctids >= nctids)
				break;

			kmem_free(pids, spids * sizeof (uint32_t));
			kmem_free(ctids, sctids * sizeof (uint32_t));
		}
		contract_status_common(ct, zone, status, model);
		for (loc = 0, cnext = list_head(&ctp->conp_inherited); cnext;
		    cnext = list_next(&ctp->conp_inherited, cnext))
			ctids[loc++] = cnext->ct_id;
		ASSERT(loc == nctids);
		for (loc = 0, pnext = list_head(&ctp->conp_members); pnext;
		    pnext = list_next(&ctp->conp_members, pnext))
			pids[loc++] = pnext->p_pid;
		ASSERT(loc == npids);
		local_svc_zone_enter = ctp->conp_svc_zone_enter;
		mutex_exit(&ct->ct_lock);
	}

	/*
	 * Contract terms are static; there's no need to hold the
	 * contract lock while accessing them.
	 */
	VERIFY(nvlist_add_uint32(nvl, CTPS_PARAMS, ctp->conp_params) == 0);
	VERIFY(nvlist_add_uint32(nvl, CTPS_EV_FATAL, ctp->conp_ev_fatal) == 0);
	if (detail == CTD_ALL) {
		VERIFY(nvlist_add_uint32_array(nvl, CTPS_MEMBERS, pids,
		    npids) == 0);
		VERIFY(nvlist_add_uint32_array(nvl, CTPS_CONTRACTS, ctids,
		    nctids) == 0);
		VERIFY(nvlist_add_string(nvl, CTPS_CREATOR_AUX,
		    refstr_value(ctp->conp_svc_aux)) == 0);
		VERIFY(nvlist_add_string(nvl, CTPS_SVC_CREATOR,
		    refstr_value(ctp->conp_svc_creator)) == 0);
		kmem_free(pids, spids * sizeof (uint32_t));
		kmem_free(ctids, sctids * sizeof (uint32_t));
	}

	/*
	 * if we are in a local zone and svc_fmri was inherited from
	 * the global zone, we provide fake svc_fmri and svc_ctid
	 */
	if (local_svc_zone_enter == 0 ||
	    zone->zone_uniqid == GLOBAL_ZONEUNIQID) {
		if (detail > CTD_COMMON) {
			VERIFY(nvlist_add_int32(nvl, CTPS_SVC_CTID,
			    ctp->conp_svc_ctid) == 0);
			VERIFY(nvlist_add_string(nvl, CTPS_SVC_FMRI,
			    refstr_value(ctp->conp_svc_fmri)) == 0);
		}
	} else {
		if (detail > CTD_COMMON) {
			VERIFY(nvlist_add_int32(nvl, CTPS_SVC_CTID,
			    local_svc_zone_enter) == 0);
			VERIFY(nvlist_add_string(nvl, CTPS_SVC_FMRI,
			    CT_PR_SVC_FMRI_ZONE_ENTER) == 0);
		}
	}
}

/*ARGSUSED*/
static int
contract_process_newct(contract_t *ct)
{
	return (0);
}

/* process contracts don't negotiate */
static contops_t contract_process_ops = {
	contract_process_free,		/* contop_free */
	contract_process_abandon,	/* contop_abandon */
	contract_process_destroy,	/* contop_destroy */
	contract_process_status,	/* contop_status */
	contract_ack_inval,		/* contop_ack */
	contract_ack_inval,		/* contop_nack */
	contract_qack_inval,		/* contop_qack */
	contract_process_newct		/* contop_newct */
};

/*
 * contract_process_init
 *
 * Initializes the process contract type.  Also creates a template for
 * use by newproc() when it creates user processes.
 */
void
contract_process_init(void)
{
	process_type = contract_type_init(CTT_PROCESS, "process",
	    &contract_process_ops, contract_process_default);

	/*
	 * Create a template for use with init(1M) and other
	 * kernel-started processes.
	 */
	sys_process_tmpl = kmem_alloc(sizeof (ctmpl_process_t), KM_SLEEP);
	ctmpl_init(&sys_process_tmpl->ctp_ctmpl, &ctmpl_process_ops,
	    process_type, sys_process_tmpl);
	sys_process_tmpl->ctp_subsume = NULL;
	sys_process_tmpl->ctp_params = CT_PR_NOORPHAN;
	sys_process_tmpl->ctp_ev_fatal = CT_PR_EV_HWERR;
	sys_process_tmpl->ctp_svc_fmri =
	    refstr_alloc("svc:/system/init:default");
	sys_process_tmpl->ctp_svc_aux = refstr_alloc("");
	conp_svc_aux_default = sys_process_tmpl->ctp_svc_aux;
	refstr_hold(conp_svc_aux_default);
}

/*
 * contract_process_create
 *
 * create a process contract given template "tmpl" and parent process
 * "parent".  May fail and return NULL if project.max-contracts would
 * have been exceeded.
 */
static cont_process_t *
contract_process_create(ctmpl_process_t *tmpl, proc_t *parent, int canfail)
{
	cont_process_t *ctp;

	ASSERT(tmpl != NULL);

	(void) contract_type_pbundle(process_type, parent);

	ctp = kmem_zalloc(sizeof (cont_process_t), KM_SLEEP);

	list_create(&ctp->conp_members, sizeof (proc_t),
	    offsetof(proc_t, p_ct_member));
	list_create(&ctp->conp_inherited, sizeof (contract_t),
	    offsetof(contract_t, ct_ctlist));
	mutex_enter(&tmpl->ctp_ctmpl.ctmpl_lock);
	ctp->conp_params = tmpl->ctp_params;
	ctp->conp_ev_fatal = tmpl->ctp_ev_fatal;
	crhold(ctp->conp_cred = CRED());

	if (contract_ctor(&ctp->conp_contract, process_type, &tmpl->ctp_ctmpl,
	    ctp, (ctp->conp_params & CT_PR_INHERIT) ? CTF_INHERIT : 0,
	    parent, canfail)) {
		mutex_exit(&tmpl->ctp_ctmpl.ctmpl_lock);
		contract_process_free(&ctp->conp_contract);
		return (NULL);
	}

	/*
	 * inherit svc_fmri if not defined by consumer. In this case, inherit
	 * also svc_ctid to keep track of the contract id where
	 * svc_fmri was set
	 */
	if (tmpl->ctp_svc_fmri == NULL) {
		ctp->conp_svc_fmri = parent->p_ct_process->conp_svc_fmri;
		ctp->conp_svc_ctid = parent->p_ct_process->conp_svc_ctid;
		ctp->conp_svc_zone_enter =
		    parent->p_ct_process->conp_svc_zone_enter;
	} else {
		ctp->conp_svc_fmri = tmpl->ctp_svc_fmri;
		ctp->conp_svc_ctid = ctp->conp_contract.ct_id;
		/* make svc_zone_enter flag false when svc_fmri is set */
		ctp->conp_svc_zone_enter = 0;
	}
	refstr_hold(ctp->conp_svc_fmri);
	/* set svc_aux to default value if not defined in template */
	if (tmpl->ctp_svc_aux == NULL) {
		ctp->conp_svc_aux = conp_svc_aux_default;
	} else {
		ctp->conp_svc_aux = tmpl->ctp_svc_aux;
	}
	refstr_hold(ctp->conp_svc_aux);
	/*
	 * set svc_creator to execname
	 * We special case pid0 because when newproc() creates
	 * the init process, the p_user.u_comm field of sched's proc_t
	 * has not been populated yet.
	 */
	if (parent->p_pidp == &pid0) /* if the kernel is the creator */
		ctp->conp_svc_creator = refstr_alloc("sched");
	else
		ctp->conp_svc_creator = refstr_alloc(parent->p_user.u_comm);

	/*
	 * Transfer subcontracts only after new contract is visible.
	 * Also, only transfer contracts if the parent matches -- we
	 * don't want to create a cycle in the tree of contracts.
	 */
	if (tmpl->ctp_subsume && tmpl->ctp_subsume->ct_owner == parent) {
		cont_process_t *sct = tmpl->ctp_subsume->ct_data;
		contract_t *ct;

		mutex_enter(&tmpl->ctp_subsume->ct_lock);
		mutex_enter(&ctp->conp_contract.ct_lock);
		while (ct = list_head(&sct->conp_inherited)) {
			mutex_enter(&ct->ct_lock);
			list_remove(&sct->conp_inherited, ct);
			list_insert_tail(&ctp->conp_inherited, ct);
			ct->ct_regent = &ctp->conp_contract;
			mutex_exit(&ct->ct_lock);
		}
		ctp->conp_ninherited += sct->conp_ninherited;
		sct->conp_ninherited = 0;
		mutex_exit(&ctp->conp_contract.ct_lock);
		mutex_exit(&tmpl->ctp_subsume->ct_lock);

		/*
		 * Automatically abandon the contract.
		 */
		(void) contract_abandon(tmpl->ctp_subsume, parent, 1);
	}

	mutex_exit(&tmpl->ctp_ctmpl.ctmpl_lock);

	return (ctp);
}

/*
 * contract_process_exit
 *
 * Called on process exit.  Removes process p from process contract
 * ctp.  Generates an exit event, if requested.  Generates an empty
 * event, if p is the last member of the the process contract and empty
 * events were requested.
 */
void
contract_process_exit(cont_process_t *ctp, proc_t *p, int exitstatus)
{
	contract_t *ct = &ctp->conp_contract;
	ct_kevent_t *event;
	int empty;

	/*
	 * Remove self from process contract.
	 */
	mutex_enter(&ct->ct_lock);
	list_remove(&ctp->conp_members, p);
	ctp->conp_nmembers--;
	mutex_enter(&p->p_lock);	/* in case /proc is watching */
	p->p_ct_process = NULL;
	mutex_exit(&p->p_lock);

	/*
	 * We check for emptiness before dropping the contract lock to
	 * send the exit event, otherwise we could end up with two
	 * empty events.
	 */
	empty = (list_head(&ctp->conp_members) == NULL);
	if (EVSENDP(ctp, CT_PR_EV_EXIT)) {
		nvlist_t *nvl;

		mutex_exit(&ct->ct_lock);
		VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_PID, p->p_pid) == 0);
		VERIFY(nvlist_add_int32(nvl, CTPE_EXITSTATUS, exitstatus) == 0);

		event = kmem_zalloc(sizeof (ct_kevent_t), KM_SLEEP);
		event->cte_flags = EVINFOP(ctp, CT_PR_EV_EXIT) ? CTE_INFO : 0;
		event->cte_type = CT_PR_EV_EXIT;
		(void) cte_publish_all(ct, event, nvl, NULL);
		mutex_enter(&ct->ct_lock);
	}

	/*
	 * CT_PR_EV_EXIT is not part of the CT_PR_ALLFATAL definition since
	 * we never allow including this in the fatal set via a user-land
	 * application, but we do allow CT_PR_EV_EXIT in the contract's fatal
	 * set for a process setup for zone init. See zone_start_init().
	 */
	if (EVFATALP(ctp, CT_PR_EV_EXIT)) {
		ASSERT(MUTEX_HELD(&ct->ct_lock));
		contract_process_kill(ct, p, B_TRUE);
	}

	if (empty) {
		/*
		 * Send EMPTY message.
		 */
		if (EVSENDP(ctp, CT_PR_EV_EMPTY)) {
			nvlist_t *nvl;

			mutex_exit(&ct->ct_lock);
			VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME,
			    KM_SLEEP) == 0);
			VERIFY(nvlist_add_uint32(nvl, CTPE_PID, p->p_pid) == 0);

			event = kmem_zalloc(sizeof (ct_kevent_t), KM_SLEEP);
			event->cte_flags = EVINFOP(ctp, CT_PR_EV_EMPTY) ?
			    CTE_INFO : 0;
			event->cte_type = CT_PR_EV_EMPTY;
			(void) cte_publish_all(ct, event, nvl, NULL);
			mutex_enter(&ct->ct_lock);
		}

		/*
		 * The last one to leave an orphaned contract turns out
		 * the lights.
		 */
		if (ct->ct_state == CTS_ORPHAN) {
			contract_destroy(ct);
			return;
		}
	}
	mutex_exit(&ct->ct_lock);
	contract_rele(ct);
}

/*
 * contract_process_fork
 *
 * Called on process fork.  If the current lwp has a active process
 * contract template, we attempt to create a new process contract.
 * Failure to create a process contract when required is a failure in
 * fork so, in such an event, we return NULL.
 *
 * Assuming we succeeded or skipped the previous step, we add the child
 * process to the new contract (success) or to the parent's process
 * contract (skip).  If requested, we also send a fork event to that
 * contract.
 *
 * Because contract_process_fork() may fail, and because we would
 * prefer that process contracts not be created for processes which
 * don't complete forking, this should be the last function called
 * before the "all clear" point in cfork.
 */
cont_process_t *
contract_process_fork(ctmpl_process_t *rtmpl, proc_t *cp, proc_t *pp,
    int canfail)
{
	contract_t *ct;
	cont_process_t *ctp;
	ct_kevent_t *event;
	ct_template_t *tmpl;

	if (rtmpl == NULL && (tmpl = ttolwp(curthread)->lwp_ct_active[
	    process_type->ct_type_index]) != NULL)
		rtmpl = tmpl->ctmpl_data;

	if (rtmpl == NULL)
		ctp = curproc->p_ct_process;
	else if ((ctp = contract_process_create(rtmpl, pp, canfail)) == NULL)
		return (NULL);

	ct = &ctp->conp_contract;
	/*
	 * Prevent contract_process_kill() from missing forked children
	 * by failing forks by parents that have just been killed.
	 * It's not worth hoisting the ctp test since contract creation
	 * is by no means the common case.
	 */
	mutex_enter(&ct->ct_lock);
	mutex_enter(&pp->p_lock);
	if (ctp == curproc->p_ct_process && (pp->p_flag & SKILLED) != 0 &&
	    canfail) {
		mutex_exit(&pp->p_lock);
		mutex_exit(&ct->ct_lock);
		return (NULL);
	}
	cp->p_ct_process = ctp;
	mutex_exit(&pp->p_lock);
	contract_hold(ct);
	list_insert_head(&ctp->conp_members, cp);
	ctp->conp_nmembers++;
	mutex_exit(&ct->ct_lock);
	if (EVSENDP(ctp, CT_PR_EV_FORK)) {
		nvlist_t *nvl;

		VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_PID, cp->p_pid) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_PPID, pp->p_pid) == 0);

		event = kmem_zalloc(sizeof (ct_kevent_t), KM_SLEEP);
		event->cte_flags = EVINFOP(ctp, CT_PR_EV_FORK) ? CTE_INFO : 0;
		event->cte_type = CT_PR_EV_FORK;
		(void) cte_publish_all(ct, event, nvl, NULL);
	}

	/*
	 * Because the CT_PR_KEEP_EXEC flag is meant to be used by applications
	 * which are not contract aware, we can assume that these applications
	 * will never explicitly abandon the child's new contract. Thus, we
	 * abandon it now.
	 */
	if (ctp->conp_params & CT_PR_KEEP_EXEC) {
		(void) contract_abandon(ct, pp, 1);
	}

	return (ctp);
}

/*
 * contract_process_core
 *
 * Called on core file generation attempts.  Generates a core event, if
 * requested, containing the names of the process, global, and
 * system-global ("zone") core files.  If dumping core is in the fatal
 * event set, calls contract_process_kill().
 */
void
contract_process_core(cont_process_t *ctp, proc_t *p, int sig,
    const char *process, const char *global, const char *zone)
{
	contract_t *ct = &ctp->conp_contract;

	if (EVSENDP(ctp, CT_PR_EV_CORE)) {
		ct_kevent_t *event;
		nvlist_t *nvl, *gnvl = NULL;

		VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_PID, p->p_pid) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_SIGNAL, sig) == 0);
		if (process)
			VERIFY(nvlist_add_string(nvl, CTPE_PCOREFILE,
			    (char *)process) == 0);
		if (global)
			VERIFY(nvlist_add_string(nvl, CTPE_GCOREFILE,
			    (char *)global) == 0);

		if (zone) {
			/*
			 * Only the global zone is informed of the
			 * local-zone generated global-zone core.
			 */
			VERIFY(nvlist_alloc(&gnvl, NV_UNIQUE_NAME,
			    KM_SLEEP) == 0);
			VERIFY(nvlist_add_string(gnvl, CTPE_ZCOREFILE,
			    (char *)zone) == 0);
		}

		event = kmem_zalloc(sizeof (ct_kevent_t), KM_SLEEP);
		event->cte_flags = EVINFOP(ctp, CT_PR_EV_CORE) ? CTE_INFO : 0;
		event->cte_type = CT_PR_EV_CORE;
		(void) cte_publish_all(ct, event, nvl, gnvl);
	}

	if (EVFATALP(ctp, CT_PR_EV_CORE)) {
		mutex_enter(&ct->ct_lock);
		contract_process_kill(ct, p, B_TRUE);
		mutex_exit(&ct->ct_lock);
	}
}

/*
 * contract_process_hwerr
 *
 * Called when a process is killed by an unrecoverable hardware error.
 * Generates an hwerr event, if requested.  If hardware errors are in
 * the fatal event set, calls contract_process_kill().
 */
void
contract_process_hwerr(cont_process_t *ctp, proc_t *p)
{
	contract_t *ct = &ctp->conp_contract;

	if (EVSENDP(ctp, CT_PR_EV_HWERR)) {
		ct_kevent_t *event;
		nvlist_t *nvl;

		VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_PID, p->p_pid) == 0);

		event = kmem_zalloc(sizeof (ct_kevent_t), KM_SLEEP);
		event->cte_flags = EVINFOP(ctp, CT_PR_EV_HWERR) ? CTE_INFO : 0;
		event->cte_type = CT_PR_EV_HWERR;
		(void) cte_publish_all(ct, event, nvl, NULL);
	}

	if (EVFATALP(ctp, CT_PR_EV_HWERR)) {
		mutex_enter(&ct->ct_lock);
		contract_process_kill(ct, p, B_FALSE);
		mutex_exit(&ct->ct_lock);
	}
}

/*
 * contract_process_sig
 *
 * Called when a process is killed by a signal originating from a
 * process outside of its process contract or its process contract's
 * holder.  Generates an signal event, if requested, containing the
 * signal number, and the sender's pid and contract id (if available).
 * If signals are in the fatal event set, calls
 * contract_process_kill().
 */
void
contract_process_sig(cont_process_t *ctp, proc_t *p, int sig, pid_t pid,
    ctid_t ctid, zoneid_t zoneid)
{
	contract_t *ct = &ctp->conp_contract;

	if (EVSENDP(ctp, CT_PR_EV_SIGNAL)) {
		ct_kevent_t *event;
		nvlist_t *dest, *nvl, *gnvl = NULL;

		VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_PID, p->p_pid) == 0);
		VERIFY(nvlist_add_uint32(nvl, CTPE_SIGNAL, sig) == 0);

		if (zoneid >= 0 && p->p_zone->zone_id != zoneid) {
			VERIFY(nvlist_alloc(&gnvl, NV_UNIQUE_NAME,
			    KM_SLEEP) == 0);
			dest = gnvl;
		} else {
			dest = nvl;
		}

		if (pid != -1)
			VERIFY(nvlist_add_uint32(dest, CTPE_SENDER, pid) == 0);
		if (ctid != 0)
			VERIFY(nvlist_add_uint32(dest, CTPE_SENDCT, ctid) == 0);

		event = kmem_zalloc(sizeof (ct_kevent_t), KM_SLEEP);
		event->cte_flags = EVINFOP(ctp, CT_PR_EV_SIGNAL) ? CTE_INFO : 0;
		event->cte_type = CT_PR_EV_SIGNAL;
		(void) cte_publish_all(ct, event, nvl, gnvl);
	}

	if (EVFATALP(ctp, CT_PR_EV_SIGNAL)) {
		mutex_enter(&ct->ct_lock);
		contract_process_kill(ct, p, B_TRUE);
		mutex_exit(&ct->ct_lock);
	}
}
