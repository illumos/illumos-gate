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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/policy.h>

#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_record.h>

#define	CLEAR_VAL -1

extern kmutex_t pidlock;

uint32_t audit_policy; /* global audit policies in force */


/*ARGSUSED1*/
int
auditsys(struct auditcalls *uap, rval_t *rvp)
{
	int err;
	int result = 0;

	if (audit_active == C2AUDIT_DISABLED)
		return (ENOTSUP);

	switch (uap->code) {
	case BSM_GETAUID:
		result = getauid((caddr_t)uap->a1);
		break;
	case BSM_SETAUID:
		result = setauid((caddr_t)uap->a1);
		break;
	case BSM_GETAUDIT:
		result = getaudit((caddr_t)uap->a1);
		break;
	case BSM_GETAUDIT_ADDR:
		result = getaudit_addr((caddr_t)uap->a1, (int)uap->a2);
		break;
	case BSM_SETAUDIT:
		result = setaudit((caddr_t)uap->a1);
		break;
	case BSM_SETAUDIT_ADDR:
		result = setaudit_addr((caddr_t)uap->a1, (int)uap->a2);
		break;
	case BSM_AUDITCTL:
		result = auditctl((int)uap->a1, (caddr_t)uap->a2, (int)uap->a3);
		break;
	case BSM_AUDIT:
		if (audit_active == C2AUDIT_UNLOADED)
			return (0);
		result = audit((caddr_t)uap->a1, (int)uap->a2);
		break;
	case BSM_AUDITDOOR:
		if (audit_active == C2AUDIT_LOADED) {
			result = auditdoor((int)uap->a1);
			break;
		}
	default:
		if (audit_active == C2AUDIT_LOADED) {
			result = EINVAL;
			break;
		}
		/* Return a different error when not privileged */
		err = secpolicy_audit_config(CRED());
		if (err == 0)
			return (EINVAL);
		else
			return (err);
	}
	rvp->r_vals = result;
	return (result);
}

/*
 * Return the audit user ID for the current process.  Currently only
 * the privileged processes may see the audit id.  That may change.
 * If copyout is unsucessful return EFAULT.
 */
int
getauid(caddr_t auid_p)
{
	const auditinfo_addr_t	*ainfo;

	if (secpolicy_audit_getattr(CRED(), B_FALSE) != 0)
		return (EPERM);

	ainfo = crgetauinfo(CRED());
	if (ainfo == NULL)
		return (EINVAL);

	if (copyout(&ainfo->ai_auid, auid_p, sizeof (au_id_t)))
		return (EFAULT);

	return (0);
}

/*
 * Set the audit userid, for a process.  This can only be changed by
 * privileged processes.  The audit userid is inherited across forks & execs.
 * Passed in is a pointer to the au_id_t; if copyin unsuccessful return EFAULT.
 */
int
setauid(caddr_t auid_p)
{
	proc_t *p;
	au_id_t	auid;
	cred_t *newcred;
	auditinfo_addr_t *auinfo;

	if (secpolicy_audit_config(CRED()) != 0)
		return (EPERM);

	if (copyin(auid_p, &auid, sizeof (au_id_t))) {
		return (EFAULT);
	}

	newcred = cralloc();
	if ((auinfo = crgetauinfo_modifiable(newcred)) == NULL) {
		crfree(newcred);
		return (EINVAL);
	}

	/* grab p_crlock and switch to new cred */
	p = curproc;
	mutex_enter(&p->p_crlock);
	crcopy_to(p->p_cred, newcred);
	p->p_cred = newcred;

	auinfo->ai_auid = auid;			/* update the auid */

	/* unlock and broadcast the cred changes */
	mutex_exit(&p->p_crlock);
	crset(p, newcred);

	return (0);
}

/*
 * Get the audit state information from the current process.
 * Return EFAULT if copyout fails.
 */
int
getaudit(caddr_t info_p)
{
	STRUCT_DECL(auditinfo, info);
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	if (secpolicy_audit_getattr(CRED(), B_FALSE) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	ainfo = crgetauinfo(CRED());
	if (ainfo == NULL)
		return (EINVAL);

	/* trying to read a process with an IPv6 address? */
	if (ainfo->ai_termid.at_type == AU_IPv6)
		return (EOVERFLOW);

	STRUCT_FSET(info, ai_auid, ainfo->ai_auid);
	STRUCT_FSET(info, ai_mask, ainfo->ai_mask);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			return (EOVERFLOW);
		}
		STRUCT_FSET(info, ai_termid.port, dev);
	} else
		STRUCT_FSET(info, ai_termid.port, ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(info, ai_termid.port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(info, ai_termid.machine, ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(info, ai_asid, ainfo->ai_asid);

	if (copyout(STRUCT_BUF(info), info_p, STRUCT_SIZE(info)))
		return (EFAULT);

	return (0);
}

/*
 * Get the audit state information from the current process.
 * Return EFAULT if copyout fails.
 */
int
getaudit_addr(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	if (secpolicy_audit_getattr(CRED(), B_FALSE) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	ainfo = crgetauinfo(CRED());

	if (ainfo == NULL)
		return (EINVAL);

	STRUCT_FSET(info, ai_auid, ainfo->ai_auid);
	STRUCT_FSET(info, ai_mask, ainfo->ai_mask);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			return (EOVERFLOW);
		}
		STRUCT_FSET(info, ai_termid.at_port, dev);
	} else
		STRUCT_FSET(info, ai_termid.at_port, ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(info, ai_termid.at_port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(info, ai_termid.at_type, ainfo->ai_termid.at_type);
	STRUCT_FSET(info, ai_termid.at_addr[0], ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(info, ai_termid.at_addr[1], ainfo->ai_termid.at_addr[1]);
	STRUCT_FSET(info, ai_termid.at_addr[2], ainfo->ai_termid.at_addr[2]);
	STRUCT_FSET(info, ai_termid.at_addr[3], ainfo->ai_termid.at_addr[3]);
	STRUCT_FSET(info, ai_asid, ainfo->ai_asid);

	if (copyout(STRUCT_BUF(info), info_p, STRUCT_SIZE(info)))
		return (EFAULT);

	return (0);
}

/*
 * Set the audit state information for the current process.
 * Return EFAULT if copyout fails.
 */
int
setaudit(caddr_t info_p)
{
	STRUCT_DECL(auditinfo, info);
	proc_t *p;
	cred_t	*newcred;
	model_t	model;
	auditinfo_addr_t *ainfo;

	if (secpolicy_audit_config(CRED()) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (copyin(info_p, STRUCT_BUF(info), STRUCT_SIZE(info)))
		return (EFAULT);

	newcred = cralloc();
	if ((ainfo = crgetauinfo_modifiable(newcred)) == NULL) {
		crfree(newcred);
		return (EINVAL);
	}

	/* grab p_crlock and switch to new cred */
	p = curproc;
	mutex_enter(&p->p_crlock);
	crcopy_to(p->p_cred, newcred);
	p->p_cred = newcred;

	/* Set audit mask, id, termid and session id as specified */
	ainfo->ai_auid = STRUCT_FGET(info, ai_auid);
#ifdef _LP64
	/* only convert to 64 bit if coming from a 32 bit binary */
	if (model == DATAMODEL_ILP32)
		ainfo->ai_termid.at_port =
		    DEVEXPL(STRUCT_FGET(info, ai_termid.port));
	else
		ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.port);
#else
	ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.port);
#endif
	ainfo->ai_termid.at_type = AU_IPv4;
	ainfo->ai_termid.at_addr[0] = STRUCT_FGET(info, ai_termid.machine);
	ainfo->ai_asid = STRUCT_FGET(info, ai_asid);
	ainfo->ai_mask = STRUCT_FGET(info, ai_mask);

	/* unlock and broadcast the cred changes */
	mutex_exit(&p->p_crlock);
	crset(p, newcred);

	return (0);
}

/*
 * Set the audit state information for the current process.
 * Return EFAULT if copyin fails.
 */
int
setaudit_addr(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	proc_t *p;
	cred_t	*newcred;
	model_t	model;
	int i;
	int type;
	auditinfo_addr_t *ainfo;

	if (secpolicy_audit_config(CRED()) != 0)
		return (EPERM);

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	if (copyin(info_p, STRUCT_BUF(info), STRUCT_SIZE(info)))
		return (EFAULT);

	type = STRUCT_FGET(info, ai_termid.at_type);
	if ((type != AU_IPv4) && (type != AU_IPv6))
		return (EINVAL);

	newcred = cralloc();
	if ((ainfo = crgetauinfo_modifiable(newcred)) == NULL) {
		crfree(newcred);
		return (EINVAL);
	}

	/* grab p_crlock and switch to new cred */
	p = curproc;
	mutex_enter(&p->p_crlock);
	crcopy_to(p->p_cred, newcred);
	p->p_cred = newcred;

	/* Set audit mask, id, termid and session id as specified */
	ainfo->ai_auid = STRUCT_FGET(info, ai_auid);
	ainfo->ai_mask = STRUCT_FGET(info, ai_mask);
#ifdef _LP64
	/* only convert to 64 bit if coming from a 32 bit binary */
	if (model == DATAMODEL_ILP32)
		ainfo->ai_termid.at_port =
		    DEVEXPL(STRUCT_FGET(info, ai_termid.at_port));
	else
		ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.at_port);
#else
	ainfo->ai_termid.at_port = STRUCT_FGET(info, ai_termid.at_port);
#endif
	ainfo->ai_termid.at_type = type;
	bzero(&ainfo->ai_termid.at_addr[0], sizeof (ainfo->ai_termid.at_addr));
	for (i = 0; i < (type/sizeof (int)); i++)
		ainfo->ai_termid.at_addr[i] =
		    STRUCT_FGET(info, ai_termid.at_addr[i]);

	if (ainfo->ai_termid.at_type == AU_IPv6 &&
	    IN6_IS_ADDR_V4MAPPED(((in6_addr_t *)ainfo->ai_termid.at_addr))) {
		ainfo->ai_termid.at_type = AU_IPv4;
		ainfo->ai_termid.at_addr[0] = ainfo->ai_termid.at_addr[3];
		ainfo->ai_termid.at_addr[1] = 0;
		ainfo->ai_termid.at_addr[2] = 0;
		ainfo->ai_termid.at_addr[3] = 0;
	}

	ainfo->ai_asid = STRUCT_FGET(info, ai_asid);

	/* unlock and broadcast the cred changes */
	mutex_exit(&p->p_crlock);
	crset(p, newcred);

	return (0);
}

/*
 * Get the global policy flag
 */
static int
getpolicy(caddr_t data)
{
	uint32_t	policy;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	policy = audit_policy | kctx->auk_policy;

	if (copyout(&policy, data, sizeof (policy)))
		return (EFAULT);
	return (0);
}

/*
 * Set the global and local policy flags
 *
 * The global flags only make sense from the global zone;
 * the local flags depend on the AUDIT_PERZONE policy:
 * if the perzone policy is set, then policy is set separately
 * per zone, else held only in the global zone.
 *
 * The initial value of a local zone's policy flag is determined
 * by the value of the global zone's flags at the time the
 * local zone is created.
 *
 * While auditconfig(1M) allows setting and unsetting policies one bit
 * at a time, the mask passed in from auditconfig() is created by a
 * syscall to getpolicy and then modified based on the auditconfig()
 * cmd line, so the input policy value is used to replace the existing
 * policy.
 */
static int
setpolicy(caddr_t data)
{
	uint32_t	policy;
	au_kcontext_t	*kctx;

	if (copyin(data, &policy, sizeof (policy)))
		return (EFAULT);

	kctx = GET_KCTX_NGZ;

	if (INGLOBALZONE(curproc)) {
		if (policy & ~(AUDIT_GLOBAL | AUDIT_LOCAL))
			return (EINVAL);

		audit_policy = policy & AUDIT_GLOBAL;
	} else {
		if (!(audit_policy & AUDIT_PERZONE))
			return (EINVAL);

		if (policy & ~AUDIT_LOCAL)	/* global bits are a no-no */
			return (EINVAL);
	}
	kctx->auk_policy = policy & AUDIT_LOCAL;

	/*
	 * auk_current_vp is NULL before auditd starts (or during early
	 * auditd starup) or if auditd is halted; in either case,
	 * notification of a policy change is not needed, since auditd
	 * reads policy as it comes up.  The error return from au_doormsg()
	 * is ignored to avoid a race condition -- for example if auditd
	 * segv's, the audit state may be "auditing" but the door may
	 * be closed.  Returning an error if the door is open makes it
	 * impossible for Greenline to restart auditd.
	 */
	if (kctx->auk_current_vp != NULL)
		(void) au_doormsg(kctx, AU_DBUF_POLICY, &policy);

	/*
	 * Wake up anyone who might have blocked on full audit
	 * partitions. audit daemons need to set AUDIT_FULL when no
	 * space so we can tell if we should start dropping records.
	 */
	mutex_enter(&(kctx->auk_queue.lock));

	if ((policy & (AUDIT_CNT | AUDIT_SCNT) &&
	    (kctx->auk_queue.cnt >= kctx->auk_queue.hiwater)))
		cv_broadcast(&(kctx->auk_queue.write_cv));

	mutex_exit(&(kctx->auk_queue.lock));

	return (0);
}

static int
getamask(caddr_t data)
{
	au_kcontext_t	*kctx;

	kctx = GET_KCTX_PZ;

	if (copyout(&kctx->auk_info.ai_amask, data, sizeof (au_mask_t)))
		return (EFAULT);

	return (0);
}

static int
setamask(caddr_t data)
{
	au_mask_t	mask;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &mask, sizeof (au_mask_t)))
		return (EFAULT);

	kctx->auk_info.ai_amask = mask;
	return (0);
}

static int
getkmask(caddr_t data)
{
	au_kcontext_t	*kctx;

	kctx = GET_KCTX_PZ;

	if (copyout(&kctx->auk_info.ai_namask, data, sizeof (au_mask_t)))
		return (EFAULT);
	return (0);
}

static int
setkmask(caddr_t data)
{
	au_mask_t	mask;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &mask, sizeof (au_mask_t)))
		return (EFAULT);

	kctx->auk_info.ai_namask = mask;
	return (0);
}

static int
getkaudit(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	model_t model;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	STRUCT_FSET(info, ai_auid, kctx->auk_info.ai_auid);
	STRUCT_FSET(info, ai_mask, kctx->auk_info.ai_namask);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, kctx->auk_info.ai_termid.at_port) == 0) {
			return (EOVERFLOW);
		}
		STRUCT_FSET(info, ai_termid.at_port, dev);
	} else {
		STRUCT_FSET(info, ai_termid.at_port,
		    kctx->auk_info.ai_termid.at_port);
	}
#else
	STRUCT_FSET(info, ai_termid.at_port,
	    kctx->auk_info.ai_termid.at_port);
#endif
	STRUCT_FSET(info, ai_termid.at_type,
	    kctx->auk_info.ai_termid.at_type);
	STRUCT_FSET(info, ai_termid.at_addr[0],
	    kctx->auk_info.ai_termid.at_addr[0]);
	STRUCT_FSET(info, ai_termid.at_addr[1],
	    kctx->auk_info.ai_termid.at_addr[1]);
	STRUCT_FSET(info, ai_termid.at_addr[2],
	    kctx->auk_info.ai_termid.at_addr[2]);
	STRUCT_FSET(info, ai_termid.at_addr[3],
	    kctx->auk_info.ai_termid.at_addr[3]);
	STRUCT_FSET(info, ai_asid, kctx->auk_info.ai_asid);

	if (copyout(STRUCT_BUF(info), info_p, STRUCT_SIZE(info)))
		return (EFAULT);

	return (0);
}

/*
 * the host address for AUDIT_PERZONE == 0 is that of the global
 * zone and for local zones it is of the current zone.
 */
static int
setkaudit(caddr_t info_p, int len)
{
	STRUCT_DECL(auditinfo_addr, info);
	model_t model;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	model = get_udatamodel();
	STRUCT_INIT(info, model);

	if (len < STRUCT_SIZE(info))
		return (EOVERFLOW);

	if (copyin(info_p, STRUCT_BUF(info), STRUCT_SIZE(info)))
		return (EFAULT);

	if ((STRUCT_FGET(info, ai_termid.at_type) != AU_IPv4) &&
	    (STRUCT_FGET(info, ai_termid.at_type) != AU_IPv6))
		return (EINVAL);

	/* Set audit mask, termid and session id as specified */
	kctx->auk_info.ai_auid = STRUCT_FGET(info, ai_auid);
	kctx->auk_info.ai_namask = STRUCT_FGET(info, ai_mask);
#ifdef _LP64
	/* only convert to 64 bit if coming from a 32 bit binary */
	if (model == DATAMODEL_ILP32)
		kctx->auk_info.ai_termid.at_port =
		    DEVEXPL(STRUCT_FGET(info, ai_termid.at_port));
	else
		kctx->auk_info.ai_termid.at_port =
		    STRUCT_FGET(info, ai_termid.at_port);
#else
	kctx->auk_info.ai_termid.at_port = STRUCT_FGET(info, ai_termid.at_port);
#endif
	kctx->auk_info.ai_termid.at_type = STRUCT_FGET(info, ai_termid.at_type);
	bzero(&kctx->auk_info.ai_termid.at_addr[0],
	    sizeof (kctx->auk_info.ai_termid.at_addr));
	kctx->auk_info.ai_termid.at_addr[0] =
	    STRUCT_FGET(info, ai_termid.at_addr[0]);
	kctx->auk_info.ai_termid.at_addr[1] =
	    STRUCT_FGET(info, ai_termid.at_addr[1]);
	kctx->auk_info.ai_termid.at_addr[2] =
	    STRUCT_FGET(info, ai_termid.at_addr[2]);
	kctx->auk_info.ai_termid.at_addr[3] =
	    STRUCT_FGET(info, ai_termid.at_addr[3]);
	kctx->auk_info.ai_asid = STRUCT_FGET(info, ai_asid);

	if (kctx->auk_info.ai_termid.at_type == AU_IPv6 &&
	    IN6_IS_ADDR_V4MAPPED(
	    ((in6_addr_t *)kctx->auk_info.ai_termid.at_addr))) {
		kctx->auk_info.ai_termid.at_type = AU_IPv4;
		kctx->auk_info.ai_termid.at_addr[0] =
		    kctx->auk_info.ai_termid.at_addr[3];
		kctx->auk_info.ai_termid.at_addr[1] = 0;
		kctx->auk_info.ai_termid.at_addr[2] = 0;
		kctx->auk_info.ai_termid.at_addr[3] = 0;
	}
	if (kctx->auk_info.ai_termid.at_type == AU_IPv6)
		kctx->auk_hostaddr_valid = IN6_IS_ADDR_UNSPECIFIED(
		    (in6_addr_t *)kctx->auk_info.ai_termid.at_addr) ? 0 : 1;
	else
		kctx->auk_hostaddr_valid =
		    (kctx->auk_info.ai_termid.at_addr[0] ==
		    htonl(INADDR_ANY)) ? 0 : 1;

	return (0);
}

static int
getqctrl(caddr_t data)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;
	STRUCT_DECL(au_qctrl, qctrl);
	STRUCT_INIT(qctrl, get_udatamodel());

	mutex_enter(&(kctx->auk_queue.lock));
	STRUCT_FSET(qctrl, aq_hiwater, kctx->auk_queue.hiwater);
	STRUCT_FSET(qctrl, aq_lowater, kctx->auk_queue.lowater);
	STRUCT_FSET(qctrl, aq_bufsz, kctx->auk_queue.bufsz);
	STRUCT_FSET(qctrl, aq_delay, kctx->auk_queue.delay);
	mutex_exit(&(kctx->auk_queue.lock));

	if (copyout(STRUCT_BUF(qctrl), data, STRUCT_SIZE(qctrl)))
		return (EFAULT);

	return (0);
}

static int
setqctrl(caddr_t data)
{
	au_kcontext_t	*kctx;
	struct au_qctrl qctrl_tmp;
	STRUCT_DECL(au_qctrl, qctrl);
	STRUCT_INIT(qctrl, get_udatamodel());

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);
	kctx = GET_KCTX_NGZ;

	if (copyin(data, STRUCT_BUF(qctrl), STRUCT_SIZE(qctrl)))
		return (EFAULT);

	qctrl_tmp.aq_hiwater = (size_t)STRUCT_FGET(qctrl, aq_hiwater);
	qctrl_tmp.aq_lowater = (size_t)STRUCT_FGET(qctrl, aq_lowater);
	qctrl_tmp.aq_bufsz = (size_t)STRUCT_FGET(qctrl, aq_bufsz);
	qctrl_tmp.aq_delay = (clock_t)STRUCT_FGET(qctrl, aq_delay);

	/* enforce sane values */

	if (qctrl_tmp.aq_hiwater <= qctrl_tmp.aq_lowater)
		return (EINVAL);

	if (qctrl_tmp.aq_hiwater < AQ_LOWATER)
		return (EINVAL);

	if (qctrl_tmp.aq_hiwater > AQ_MAXHIGH)
		return (EINVAL);

	if (qctrl_tmp.aq_bufsz < AQ_BUFSZ)
		return (EINVAL);

	if (qctrl_tmp.aq_bufsz > AQ_MAXBUFSZ)
		return (EINVAL);

	if (qctrl_tmp.aq_delay == 0)
		return (EINVAL);

	if (qctrl_tmp.aq_delay > AQ_MAXDELAY)
		return (EINVAL);

	/* update everything at once so things are consistant */
	mutex_enter(&(kctx->auk_queue.lock));
	kctx->auk_queue.hiwater = qctrl_tmp.aq_hiwater;
	kctx->auk_queue.lowater = qctrl_tmp.aq_lowater;
	kctx->auk_queue.bufsz = qctrl_tmp.aq_bufsz;
	kctx->auk_queue.delay = qctrl_tmp.aq_delay;

	if (kctx->auk_queue.rd_block &&
	    kctx->auk_queue.cnt > kctx->auk_queue.lowater)
		cv_broadcast(&(kctx->auk_queue.read_cv));

	if (kctx->auk_queue.wt_block &&
	    kctx->auk_queue.cnt < kctx->auk_queue.hiwater)
		cv_broadcast(&(kctx->auk_queue.write_cv));

	mutex_exit(&(kctx->auk_queue.lock));

	return (0);
}

static int
getcwd(caddr_t data, int length)
{
	struct p_audit_data	*pad;
	struct audit_path	*app;
	int	pathlen;

	pad = P2A(curproc);
	ASSERT(pad != NULL);

	mutex_enter(&(pad->pad_lock));
	app = pad->pad_cwd;
	au_pathhold(app);
	mutex_exit(&(pad->pad_lock));

	pathlen = app->audp_sect[1] - app->audp_sect[0];
	if (pathlen > length) {
		au_pathrele(app);
		return (E2BIG);
	}

	if (copyout(app->audp_sect[0], data, pathlen)) {
		au_pathrele(app);
		return (EFAULT);
	}

	au_pathrele(app);
	return (0);
}

static int
getcar(caddr_t data, int length)
{
	struct p_audit_data	*pad;
	struct audit_path	*app;
	int	pathlen;

	pad = P2A(curproc);
	ASSERT(pad != NULL);

	mutex_enter(&(pad->pad_lock));
	app = pad->pad_root;
	au_pathhold(app);
	mutex_exit(&(pad->pad_lock));

	pathlen = app->audp_sect[1] - app->audp_sect[0];
	if (pathlen > length) {
		au_pathrele(app);
		return (E2BIG);
	}

	if (copyout(app->audp_sect[0], data, pathlen)) {
		au_pathrele(app);
		return (EFAULT);
	}

	au_pathrele(app);
	return (0);
}

static int
getstat(caddr_t data)
{
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	membar_consumer();

	if (copyout((caddr_t)&(kctx->auk_statistics), data, sizeof (au_stat_t)))
		return (EFAULT);
	return (0);
}

static int
setstat(caddr_t data)
{
	au_kcontext_t *kctx = GET_KCTX_PZ;
	au_stat_t au_stat;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	if (copyin(data, &au_stat, sizeof (au_stat_t)))
		return (EFAULT);

	if (au_stat.as_generated == CLEAR_VAL)
		kctx->auk_statistics.as_generated = 0;
	if (au_stat.as_nonattrib == CLEAR_VAL)
		kctx->auk_statistics.as_nonattrib = 0;
	if (au_stat.as_kernel == CLEAR_VAL)
		kctx->auk_statistics.as_kernel = 0;
	if (au_stat.as_audit == CLEAR_VAL)
		kctx->auk_statistics.as_audit = 0;
	if (au_stat.as_auditctl == CLEAR_VAL)
		kctx->auk_statistics.as_auditctl = 0;
	if (au_stat.as_enqueue == CLEAR_VAL)
		kctx->auk_statistics.as_enqueue = 0;
	if (au_stat.as_written == CLEAR_VAL)
		kctx->auk_statistics.as_written = 0;
	if (au_stat.as_wblocked == CLEAR_VAL)
		kctx->auk_statistics.as_wblocked = 0;
	if (au_stat.as_rblocked == CLEAR_VAL)
		kctx->auk_statistics.as_rblocked = 0;
	if (au_stat.as_dropped == CLEAR_VAL)
		kctx->auk_statistics.as_dropped = 0;
	if (au_stat.as_totalsize == CLEAR_VAL)
		kctx->auk_statistics.as_totalsize = 0;

	membar_producer();

	return (0);

}

static int
setumask(caddr_t data)
{
	STRUCT_DECL(auditinfo, user_info);
	struct proc *p;
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	/* setumask not applicable in non-global zones without perzone policy */
	if (!(audit_policy & AUDIT_PERZONE) && (!INGLOBALZONE(curproc)))
		return (EINVAL);

	model = get_udatamodel();
	STRUCT_INIT(user_info, model);

	if (copyin(data, STRUCT_BUF(user_info), STRUCT_SIZE(user_info)))
		return (EFAULT);

	mutex_enter(&pidlock);	/* lock the process queue against updates */
	for (p = practive; p != NULL; p = p->p_next) {
		cred_t	*cr;

		/* if in non-global zone only modify processes in same zone */
		if (!HASZONEACCESS(curproc, p->p_zone->zone_id))
			continue;

		mutex_enter(&p->p_lock);	/* so process doesn't go away */

		/* skip system processes and ones being created or going away */
		if (p->p_stat == SIDL || p->p_stat == SZOMB ||
		    (p->p_flag & (SSYS | SEXITING | SEXITLWPS))) {
			mutex_exit(&p->p_lock);
			continue;
		}

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			mutex_exit(&p->p_lock);
			crfree(cr);
			continue;
		}

		if (ainfo->ai_auid == STRUCT_FGET(user_info, ai_auid)) {
			au_mask_t	mask;
			int		err;

			/*
			 * Here's a process which matches the specified auid.
			 * If its mask doesn't already match the new mask,
			 * save the new mask in the pad, to be picked up
			 * next syscall.
			 */
			mask = STRUCT_FGET(user_info, ai_mask);
			err = bcmp(&mask, &ainfo->ai_mask, sizeof (au_mask_t));
			crfree(cr);
			if (err != 0) {
				struct p_audit_data *pad = P2A(p);
				ASSERT(pad != NULL);

				mutex_enter(&(pad->pad_lock));
				pad->pad_flags |= PAD_SETMASK;
				pad->pad_newmask = mask;
				mutex_exit(&(pad->pad_lock));

				/*
				 * No need to call set_proc_pre_sys(), since
				 * t_pre_sys is ALWAYS on when audit is
				 * enabled...due to syscall auditing.
				 */
			}
		} else {
			crfree(cr);
		}
		mutex_exit(&p->p_lock);
	}
	mutex_exit(&pidlock);

	return (0);
}

static int
setsmask(caddr_t data)
{
	STRUCT_DECL(auditinfo, user_info);
	struct proc *p;
	const auditinfo_addr_t	*ainfo;
	model_t	model;

	/* setsmask not applicable in non-global zones without perzone policy */
	if (!(audit_policy & AUDIT_PERZONE) && (!INGLOBALZONE(curproc)))
		return (EINVAL);

	model = get_udatamodel();
	STRUCT_INIT(user_info, model);

	if (copyin(data, STRUCT_BUF(user_info), STRUCT_SIZE(user_info)))
		return (EFAULT);

	mutex_enter(&pidlock);	/* lock the process queue against updates */
	for (p = practive; p != NULL; p = p->p_next) {
		cred_t	*cr;

		/* if in non-global zone only modify processes in same zone */
		if (!HASZONEACCESS(curproc, p->p_zone->zone_id))
			continue;

		mutex_enter(&p->p_lock);	/* so process doesn't go away */

		/* skip system processes and ones being created or going away */
		if (p->p_stat == SIDL || p->p_stat == SZOMB ||
		    (p->p_flag & (SSYS | SEXITING | SEXITLWPS))) {
			mutex_exit(&p->p_lock);
			continue;
		}

		mutex_enter(&p->p_crlock);
		crhold(cr = p->p_cred);
		mutex_exit(&p->p_crlock);
		ainfo = crgetauinfo(cr);
		if (ainfo == NULL) {
			mutex_exit(&p->p_lock);
			crfree(cr);
			continue;
		}

		if (ainfo->ai_asid == STRUCT_FGET(user_info, ai_asid)) {
			au_mask_t	mask;
			int		err;

			/*
			 * Here's a process which matches the specified asid.
			 * If its mask doesn't already match the new mask,
			 * save the new mask in the pad, to be picked up
			 * next syscall.
			 */
			mask = STRUCT_FGET(user_info, ai_mask);
			err = bcmp(&mask, &ainfo->ai_mask, sizeof (au_mask_t));
			crfree(cr);
			if (err != 0) {
				struct p_audit_data *pad = P2A(p);
				ASSERT(pad != NULL);

				mutex_enter(&(pad->pad_lock));
				pad->pad_flags |= PAD_SETMASK;
				pad->pad_newmask = mask;
				mutex_exit(&(pad->pad_lock));

				/*
				 * No need to call set_proc_pre_sys(), since
				 * t_pre_sys is ALWAYS on when audit is
				 * enabled...due to syscall auditing.
				 */
			}
		} else {
			crfree(cr);
		}
		mutex_exit(&p->p_lock);
	}
	mutex_exit(&pidlock);

	return (0);
}

/*
 * Get the current audit state of the system
 */
static int
getcond(caddr_t data)
{
	au_kcontext_t *kctx = GET_KCTX_PZ;

	if (copyout(&(kctx->auk_auditstate), data, sizeof (int)))
		return (EFAULT);

	return (0);
}

/*
 * Set the current audit state of the system to on (AUC_AUDITING) or
 * off (AUC_NOAUDIT).
 */
/* ARGSUSED */
static int
setcond(caddr_t data)
{
	int auditstate;
	au_kcontext_t *kctx;

	if (!(audit_policy & AUDIT_PERZONE) && (!INGLOBALZONE(curproc)))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &auditstate, sizeof (int)))
		return (EFAULT);

	switch (auditstate) {
	case AUC_AUDITING:		/* Turn auditing on */
		if (audit_active == C2AUDIT_UNLOADED)
			audit_init_module();
		kctx->auk_auditstate = AUC_AUDITING;
		if (!(audit_policy & AUDIT_PERZONE) && INGLOBALZONE(curproc))
			set_all_zone_usr_proc_sys(ALL_ZONES);
		else
			set_all_zone_usr_proc_sys(curproc->p_zone->zone_id);
		break;

	case AUC_NOAUDIT:		/* Turn auditing off */
		if (kctx->auk_auditstate == AUC_NOAUDIT)
			break;
		kctx->auk_auditstate = AUC_NOAUDIT;

		/* clear out the audit queue */

		mutex_enter(&(kctx->auk_queue.lock));
		if (kctx->auk_queue.wt_block)
			cv_broadcast(&(kctx->auk_queue.write_cv));

		/* unblock au_output_thread */
		cv_broadcast(&(kctx->auk_queue.read_cv));

		mutex_exit(&(kctx->auk_queue.lock));
		break;

	default:
		return (EINVAL);
	}

	return (0);
}

static int
getclass(caddr_t data)
{
	au_evclass_map_t event;
	au_kcontext_t	*kctx = GET_KCTX_PZ;

	if (copyin(data, &event, sizeof (au_evclass_map_t)))
		return (EFAULT);

	if (event.ec_number > MAX_KEVENTS)
		return (EINVAL);

	event.ec_class = kctx->auk_ets[event.ec_number];

	if (copyout(&event, data, sizeof (au_evclass_map_t)))
		return (EFAULT);

	return (0);
}

static int
setclass(caddr_t data)
{
	au_evclass_map_t event;
	au_kcontext_t	*kctx;

	if (!(audit_policy & AUDIT_PERZONE) && !INGLOBALZONE(curproc))
		return (EINVAL);

	kctx = GET_KCTX_NGZ;

	if (copyin(data, &event, sizeof (au_evclass_map_t)))
		return (EFAULT);

	if (event.ec_number > MAX_KEVENTS)
		return (EINVAL);

	kctx->auk_ets[event.ec_number] = event.ec_class;

	return (0);
}

static int
getpinfo(caddr_t data)
{
	STRUCT_DECL(auditpinfo, apinfo);
	proc_t *proc;
	const auditinfo_addr_t	*ainfo;
	model_t	model;
	cred_t	*cr, *newcred;

	model = get_udatamodel();
	STRUCT_INIT(apinfo, model);

	if (copyin(data, STRUCT_BUF(apinfo), STRUCT_SIZE(apinfo)))
		return (EFAULT);

	newcred = cralloc();

	mutex_enter(&pidlock);
	if ((proc = prfind(STRUCT_FGET(apinfo, ap_pid))) == NULL) {
		mutex_exit(&pidlock);
		crfree(newcred);
		return (ESRCH);		/* no such process */
	}
	mutex_enter(&proc->p_lock);	/* so process doesn't go away */
	mutex_exit(&pidlock);

	audit_update_context(proc, newcred);	/* make sure it's up-to-date */

	mutex_enter(&proc->p_crlock);
	crhold(cr = proc->p_cred);
	mutex_exit(&proc->p_crlock);
	mutex_exit(&proc->p_lock);

	ainfo = crgetauinfo(cr);
	if (ainfo == NULL) {
		crfree(cr);
		return (EINVAL);
	}

	/* designated process has an ipv6 address? */
	if (ainfo->ai_termid.at_type == AU_IPv6) {
		crfree(cr);
		return (EOVERFLOW);
	}

	STRUCT_FSET(apinfo, ap_auid, ainfo->ai_auid);
	STRUCT_FSET(apinfo, ap_asid, ainfo->ai_asid);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			crfree(cr);
			return (EOVERFLOW);
		}
		STRUCT_FSET(apinfo, ap_termid.port, dev);
	} else
		STRUCT_FSET(apinfo, ap_termid.port, ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(apinfo, ap_termid.port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(apinfo, ap_termid.machine, ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(apinfo, ap_mask, ainfo->ai_mask);

	crfree(cr);

	if (copyout(STRUCT_BUF(apinfo), data, STRUCT_SIZE(apinfo)))
		return (EFAULT);

	return (0);
}

static int
getpinfo_addr(caddr_t data, int len)
{
	STRUCT_DECL(auditpinfo_addr, apinfo);
	proc_t *proc;
	const auditinfo_addr_t	*ainfo;
	model_t	model;
	cred_t	*cr, *newcred;

	model = get_udatamodel();
	STRUCT_INIT(apinfo, model);

	if (len < STRUCT_SIZE(apinfo))
		return (EOVERFLOW);

	if (copyin(data, STRUCT_BUF(apinfo), STRUCT_SIZE(apinfo)))
		return (EFAULT);

	newcred = cralloc();

	mutex_enter(&pidlock);
	if ((proc = prfind(STRUCT_FGET(apinfo, ap_pid))) == NULL) {
		mutex_exit(&pidlock);
		crfree(newcred);
		return (ESRCH);
	}
	mutex_enter(&proc->p_lock);	/* so process doesn't go away */
	mutex_exit(&pidlock);

	audit_update_context(proc, newcred);	/* make sure it's up-to-date */

	mutex_enter(&proc->p_crlock);
	crhold(cr = proc->p_cred);
	mutex_exit(&proc->p_crlock);
	mutex_exit(&proc->p_lock);

	ainfo = crgetauinfo(cr);
	if (ainfo == NULL) {
		crfree(cr);
		return (EINVAL);
	}

	STRUCT_FSET(apinfo, ap_auid, ainfo->ai_auid);
	STRUCT_FSET(apinfo, ap_asid, ainfo->ai_asid);
#ifdef _LP64
	if (model == DATAMODEL_ILP32) {
		dev32_t dev;
		/* convert internal 64 bit form to 32 bit version */
		if (cmpldev(&dev, ainfo->ai_termid.at_port) == 0) {
			crfree(cr);
			return (EOVERFLOW);
		}
		STRUCT_FSET(apinfo, ap_termid.at_port, dev);
	} else
		STRUCT_FSET(apinfo, ap_termid.at_port,
		    ainfo->ai_termid.at_port);
#else
	STRUCT_FSET(apinfo, ap_termid.at_port, ainfo->ai_termid.at_port);
#endif
	STRUCT_FSET(apinfo, ap_termid.at_type, ainfo->ai_termid.at_type);
	STRUCT_FSET(apinfo, ap_termid.at_addr[0], ainfo->ai_termid.at_addr[0]);
	STRUCT_FSET(apinfo, ap_termid.at_addr[1], ainfo->ai_termid.at_addr[1]);
	STRUCT_FSET(apinfo, ap_termid.at_addr[2], ainfo->ai_termid.at_addr[2]);
	STRUCT_FSET(apinfo, ap_termid.at_addr[3], ainfo->ai_termid.at_addr[3]);
	STRUCT_FSET(apinfo, ap_mask, ainfo->ai_mask);

	crfree(cr);

	if (copyout(STRUCT_BUF(apinfo), data, STRUCT_SIZE(apinfo)))
		return (EFAULT);

	return (0);
}

static int
setpmask(caddr_t data)
{
	STRUCT_DECL(auditpinfo, apinfo);
	proc_t *proc;
	cred_t	*newcred;
	auditinfo_addr_t	*ainfo;
	struct p_audit_data	*pad;

	model_t	model;

	model = get_udatamodel();
	STRUCT_INIT(apinfo, model);

	if (copyin(data, STRUCT_BUF(apinfo), STRUCT_SIZE(apinfo)))
		return (EFAULT);

	mutex_enter(&pidlock);
	if ((proc = prfind(STRUCT_FGET(apinfo, ap_pid))) == NULL) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}
	mutex_enter(&proc->p_lock);	/* so process doesn't go away */
	mutex_exit(&pidlock);

	newcred = cralloc();
	if ((ainfo = crgetauinfo_modifiable(newcred)) == NULL) {
		mutex_exit(&proc->p_lock);
		crfree(newcred);
		return (EINVAL);
	}

	mutex_enter(&proc->p_crlock);
	crcopy_to(proc->p_cred, newcred);
	proc->p_cred = newcred;

	ainfo->ai_mask = STRUCT_FGET(apinfo, ap_mask);

	/*
	 * Unlock. No need to broadcast changes via set_proc_pre_sys(),
	 * since t_pre_sys is ALWAYS on when audit is enabled... due to
	 * syscall auditing.
	 */
	crfree(newcred);
	mutex_exit(&proc->p_crlock);

	/* Reset flag for any previous pending mask change; this supercedes */
	pad = P2A(proc);
	ASSERT(pad != NULL);
	mutex_enter(&(pad->pad_lock));
	pad->pad_flags &= ~PAD_SETMASK;
	mutex_exit(&(pad->pad_lock));

	mutex_exit(&proc->p_lock);

	return (0);
}

/*
 * The out of control system call
 * This is audit kitchen sink aka auditadm, aka auditon
 */
int
auditctl(
	int	cmd,
	caddr_t data,
	int	length)
{
	int result;

	switch (cmd) {
	case A_GETAMASK:
	case A_GETCOND:
	case A_GETCAR:
	case A_GETCLASS:
	case A_GETCWD:
	case A_GETKAUDIT:
	case A_GETKMASK:
	case A_GETPINFO:
	case A_GETPINFO_ADDR:
	case A_GETPOLICY:
	case A_GETQCTRL:
	case A_GETSTAT:
		if (secpolicy_audit_getattr(CRED(), B_FALSE) != 0)
			return (EPERM);
		break;
	default:
		if (secpolicy_audit_config(CRED()) != 0)
			return (EPERM);
		break;
	}

	switch (cmd) {
	case A_GETPOLICY:
		result = getpolicy(data);
		break;
	case A_SETPOLICY:
		result = setpolicy(data);
		break;
	case A_GETAMASK:
		result = getamask(data);
		break;
	case A_SETAMASK:
		result = setamask(data);
		break;
	case A_GETKMASK:
		result = getkmask(data);
		break;
	case A_SETKMASK:
		result = setkmask(data);
		break;
	case A_GETKAUDIT:
		result = getkaudit(data, length);
		break;
	case A_SETKAUDIT:
		result = setkaudit(data, length);
		break;
	case A_GETQCTRL:
		result = getqctrl(data);
		break;
	case A_SETQCTRL:
		result = setqctrl(data);
		break;
	case A_GETCWD:
		result = getcwd(data, length);
		break;
	case A_GETCAR:
		result = getcar(data, length);
		break;
	case A_GETSTAT:
		result = getstat(data);
		break;
	case A_SETSTAT:
		result = setstat(data);
		break;
	case A_SETUMASK:
		result = setumask(data);
		break;
	case A_SETSMASK:
		result = setsmask(data);
		break;
	case A_GETCOND:
		result = getcond(data);
		break;
	case A_SETCOND:
		result = setcond(data);
		break;
	case A_GETCLASS:
		result = getclass(data);
		break;
	case A_SETCLASS:
		result = setclass(data);
		break;
	case A_GETPINFO:
		result = getpinfo(data);
		break;
	case A_GETPINFO_ADDR:
		result = getpinfo_addr(data, length);
		break;
	case A_SETPMASK:
		result = setpmask(data);
		break;
	default:
		result = EINVAL;
		break;
	}
	return (result);
}
