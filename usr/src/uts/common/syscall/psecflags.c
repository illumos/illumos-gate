/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/* Copyright 2015, Richard Lowe. */

#include <sys/ddi.h>
#include <sys/errno.h>
#include <sys/policy.h>
#include <sys/proc.h>
#include <sys/procset.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <c2/audit.h>

struct psdargs {
	psecflagwhich_t which;
	const secflagdelta_t *delta;
};

void
secflags_apply_delta(secflagset_t *set, const secflagdelta_t *delta)
{
	if (delta->psd_ass_active) {
		secflags_copy(set, &delta->psd_assign);
	} else {
		if (!secflags_isempty(delta->psd_add)) {
			secflags_union(set, &delta->psd_add);
		}
		if (!secflags_isempty(delta->psd_rem)) {
			secflags_difference(set, &delta->psd_rem);
		}
	}
}


static int
psecdo(proc_t *p, struct psdargs *args)
{
	secflagset_t *set;
	int ret = 0;

	mutex_enter(&p->p_lock);

	if (secpolicy_psecflags(CRED(), p, curproc) != 0) {
		ret = EPERM;
		goto out;
	}

	ASSERT(args->which != PSF_EFFECTIVE);

	if (!psecflags_validate_delta(&p->p_secflags, args->delta)) {
		ret = EINVAL;
		goto out;
	}

	if (AU_AUDITING())
		audit_psecflags(p, args->which, args->delta);

	switch (args->which) {
	case PSF_INHERIT:
		set = &p->p_secflags.psf_inherit;
		break;
	case PSF_LOWER:
		set = &p->p_secflags.psf_lower;
		break;
	case PSF_UPPER:
		set = &p->p_secflags.psf_upper;
		break;
	}

	secflags_apply_delta(set, args->delta);

	/*
	 * Add any flag now in the lower that is not in the inheritable.
	 */
	secflags_union(&p->p_secflags.psf_inherit, &p->p_secflags.psf_lower);

out:
	mutex_exit(&p->p_lock);
	return (ret);
}

int
psecflags(procset_t *psp, psecflagwhich_t which, secflagdelta_t *ap)
{
	procset_t procset;
	secflagdelta_t args;
	int rv = 0;
	struct psdargs psd = {
		.which = which,
	};

	/* Can never change the effective flags */
	if (psd.which == PSF_EFFECTIVE)
		return (EINVAL);

	if (copyin(psp, &procset, sizeof (procset)) != 0)
		return (set_errno(EFAULT));

	if (copyin(ap, &args, sizeof (secflagdelta_t)) != 0)
		return (set_errno(EFAULT));

	psd.delta = &args;

	/* secflags are per-process, procset must be in terms of processes */
	if ((procset.p_lidtype == P_LWPID) ||
	    (procset.p_ridtype == P_LWPID))
		return (set_errno(EINVAL));

	rv = dotoprocs(&procset, psecdo, (caddr_t)&psd);

	return (rv ? set_errno(rv) : 0);
}
