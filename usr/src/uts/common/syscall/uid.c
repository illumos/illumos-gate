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

/*
 * 	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <sys/cred_impl.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/sid.h>

int
setuid(uid_t uid)
{
	proc_t *p;
	int error;
	int do_nocd = 0;
	int uidchge = 0;
	cred_t	*cr, *newcr;
	uid_t oldruid = uid;
	zoneid_t zoneid = getzoneid();
	ksid_t ksid, *ksp;
	zone_t	*zone = crgetzone(CRED());

	if (!VALID_UID(uid, zone))
		return (set_errno(EINVAL));

	if (uid > MAXUID) {
		if (ksid_lookupbyuid(zone, uid, &ksid) != 0)
			return (set_errno(EINVAL));
		ksp = &ksid;
	} else {
		ksp = NULL;
	}
	/*
	 * Need to pre-allocate the new cred structure before grabbing
	 * the p_crlock mutex.  We can't hold on to the p_crlock for most
	 * if this though, now that we allow kernel upcalls from the
	 * policy routines.
	 */
	newcr = cralloc_ksid();

	p = ttoproc(curthread);

retry:
	mutex_enter(&p->p_crlock);
retry_locked:
	cr = p->p_cred;
	crhold(cr);
	mutex_exit(&p->p_crlock);

	if ((uid == cr->cr_ruid || uid == cr->cr_suid) &&
	    secpolicy_allow_setid(cr, uid, B_TRUE) != 0) {
		mutex_enter(&p->p_crlock);
		crfree(cr);
		if (cr != p->p_cred)
			goto retry_locked;
		error = 0;
		crcopy_to(cr, newcr);
		p->p_cred = newcr;
		newcr->cr_uid = uid;
		crsetsid(newcr, ksp, KSID_USER);
		mutex_exit(&p->p_crlock);
	} else if ((error = secpolicy_allow_setid(cr, uid, B_FALSE)) == 0) {
		mutex_enter(&p->p_crlock);
		crfree(cr);
		if (cr != p->p_cred)
			goto retry_locked;
		if (!uidchge && uid != cr->cr_ruid) {
			/*
			 * The ruid of the process is going to change. In order
			 * to avoid a race condition involving the
			 * process-count associated with the newly given ruid,
			 * we increment the count before assigning the
			 * credential to the process.
			 * To do that, we'll have to take pidlock, so we first
			 * release p_crlock.
			 */
			mutex_exit(&p->p_crlock);
			uidchge = 1;
			mutex_enter(&pidlock);
			upcount_inc(uid, zoneid);
			mutex_exit(&pidlock);
			/*
			 * As we released p_crlock we can't rely on the cr
			 * we read. So retry the whole thing.
			 */
			goto retry;
		}
		/*
		 * A privileged process that gives up its privilege
		 * must be marked to produce no core dump.
		 */
		if (cr->cr_uid != uid ||
		    cr->cr_ruid != uid ||
		    cr->cr_suid != uid)
			do_nocd = 1;
		oldruid = cr->cr_ruid;
		crcopy_to(cr, newcr);
		p->p_cred = newcr;
		newcr->cr_ruid = uid;
		newcr->cr_suid = uid;
		newcr->cr_uid = uid;

		/* Remove the PRIV_PFEXEC, we changed the real uid. */
		if (uidchge)
			CR_FLAGS(newcr) &= ~PRIV_PFEXEC;

		crsetsid(newcr, ksp, KSID_USER);

		priv_reset_PA(newcr, B_TRUE);

		ASSERT(uid != oldruid ? uidchge : 1);
		mutex_exit(&p->p_crlock);
	} else {
		crfree(newcr);
		crfree(cr);
		if (ksp != NULL)
			ksid_rele(ksp);
	}

	/*
	 * We decrement the number of processes associated with the oldruid
	 * to match the increment above, even if the ruid of the process
	 * did not change or an error occurred (oldruid == uid).
	 */
	if (uidchge) {
		mutex_enter(&pidlock);
		upcount_dec(oldruid, zoneid);
		mutex_exit(&pidlock);
	}

	if (error == 0) {
		if (do_nocd) {
			mutex_enter(&p->p_lock);
			p->p_flag |= SNOCD;
			mutex_exit(&p->p_lock);
		}
		crset(p, newcr);	/* broadcast to process threads */
		return (0);
	}
	return (set_errno(error));
}

int64_t
getuid(void)
{
	rval_t	r;
	cred_t *cr;

	cr = curthread->t_cred;
	r.r_val1 = cr->cr_ruid;
	r.r_val2 = cr->cr_uid;
	return (r.r_vals);
}

int
seteuid(uid_t uid)
{
	proc_t *p;
	int error = EPERM;
	int do_nocd = 0;
	cred_t	*cr, *newcr;
	ksid_t ksid, *ksp;
	zone_t	*zone = crgetzone(CRED());

	if (!VALID_UID(uid, zone))
		return (set_errno(EINVAL));

	if (uid > MAXUID) {
		if (ksid_lookupbyuid(zone, uid, &ksid) != 0)
			return (set_errno(EINVAL));
		ksp = &ksid;
	} else {
		ksp = NULL;
	}

	/*
	 * Need to pre-allocate the new cred structure before grabbing
	 * the p_crlock mutex.
	 */
	newcr = cralloc_ksid();
	p = ttoproc(curthread);
	mutex_enter(&p->p_crlock);
retry:
	crhold(cr = p->p_cred);
	mutex_exit(&p->p_crlock);

	if (uid == cr->cr_ruid || uid == cr->cr_uid || uid == cr->cr_suid ||
	    (error = secpolicy_allow_setid(cr, uid, B_FALSE)) == 0) {
		/*
		 * A privileged process that makes itself look like a
		 * set-uid process must be marked to produce no core dump,
		 * if the effective uid did changed.
		 */
		mutex_enter(&p->p_crlock);
		crfree(cr);
		if (cr != p->p_cred)
			goto retry;
		if (cr->cr_uid != uid && error == 0)
			do_nocd = 1;
		error = 0;
		crcopy_to(cr, newcr);
		p->p_cred = newcr;
		newcr->cr_uid = uid;
		crsetsid(newcr, ksp, KSID_USER);
		priv_reset_PA(newcr, B_FALSE);
		mutex_exit(&p->p_crlock);
		if (do_nocd) {
			mutex_enter(&p->p_lock);
			p->p_flag |= SNOCD;
			mutex_exit(&p->p_lock);
		}
		crset(p, newcr);	/* broadcast to process threads */
		return (0);
	}

	crfree(newcr);
	crfree(cr);
	if (ksp != NULL)
		ksid_rele(ksp);
	return (set_errno(error));
}

/*
 * Buy-back from SunOS 4.x
 *
 * Like setuid() and seteuid() combined -except- that non-root users
 * can change cr_ruid to cr_uid, and the semantics of cr_suid are
 * subtly different.
 */
int
setreuid(uid_t ruid, uid_t euid)
{
	proc_t *p;
	int error = 0;
	int do_nocd = 0;
	int uidchge = 0;
	uid_t oldruid = ruid;
	cred_t *cr, *newcr;
	zoneid_t zoneid = getzoneid();
	ksid_t ksid, *ksp;
	zone_t	*zone = crgetzone(CRED());

	if ((ruid != -1 && !VALID_UID(ruid, zone)) ||
	    (euid != -1 && !VALID_UID(euid, zone)))
		return (set_errno(EINVAL));

	if (euid != -1 && euid > MAXUID) {
		if (ksid_lookupbyuid(zone, euid, &ksid) != 0)
			return (set_errno(EINVAL));
		ksp = &ksid;
	} else {
		ksp = NULL;
	}

	/*
	 * Need to pre-allocate the new cred structure before grabbing
	 * the p_crlock mutex.
	 */
	newcr = cralloc_ksid();

	p = ttoproc(curthread);

retry:
	mutex_enter(&p->p_crlock);
retry_locked:
	crhold(cr = p->p_cred);
	mutex_exit(&p->p_crlock);

	if (ruid != -1 && ruid != cr->cr_ruid && ruid != cr->cr_uid &&
	    secpolicy_allow_setid(cr, ruid, B_FALSE) != 0) {
		mutex_enter(&p->p_crlock);
		crfree(cr);
		if (cr != p->p_cred)
			goto retry_locked;
		error = EPERM;
	} else if (euid != -1 &&
	    euid != cr->cr_ruid && euid != cr->cr_uid &&
	    euid != cr->cr_suid && secpolicy_allow_setid(cr, euid, B_FALSE)) {
		mutex_enter(&p->p_crlock);
		crfree(cr);
		if (cr != p->p_cred)
			goto retry_locked;
		error = EPERM;
	} else {
		mutex_enter(&p->p_crlock);
		crfree(cr);
		if (cr != p->p_cred)
			goto retry_locked;
		if (!uidchge && ruid != -1 && cr->cr_ruid != ruid) {
			/*
			 * The ruid of the process is going to change. In order
			 * to avoid a race condition involving the
			 * process-count associated with the newly given ruid,
			 * we increment the count before assigning the
			 * credential to the process.
			 * To do that, we'll have to take pidlock, so we first
			 * release p_crlock.
			 */
			mutex_exit(&p->p_crlock);
			uidchge = 1;
			mutex_enter(&pidlock);
			upcount_inc(ruid, zoneid);
			mutex_exit(&pidlock);
			/*
			 * As we released p_crlock we can't rely on the cr
			 * we read. So retry the whole thing.
			 */
			goto retry;
		}
		crhold(cr);
		crcopy_to(cr, newcr);
		p->p_cred = newcr;

		if (euid != -1) {
			newcr->cr_uid = euid;
			crsetsid(newcr, ksp, KSID_USER);
		}
		if (ruid != -1) {
			/* Remove the PRIV_PFEXEC, we changed the real uid. */
			if (uidchge)
				CR_FLAGS(newcr) &= ~PRIV_PFEXEC;

			oldruid = newcr->cr_ruid;
			newcr->cr_ruid = ruid;
			ASSERT(ruid != oldruid ? uidchge : 1);
		}
		/*
		 * "If the real uid is being changed, or the effective uid is
		 * being changed to a value not equal to the real uid, the
		 * saved uid is set to the new effective uid."
		 */
		if (ruid != -1 ||
		    (euid != -1 && newcr->cr_uid != newcr->cr_ruid))
			newcr->cr_suid = newcr->cr_uid;
		/*
		 * A process that gives up its privilege
		 * must be marked to produce no core dump.
		 */
		if ((cr->cr_uid != newcr->cr_uid ||
		    cr->cr_ruid != newcr->cr_ruid ||
		    cr->cr_suid != newcr->cr_suid))
			do_nocd = 1;

		priv_reset_PA(newcr, ruid != -1 && euid != -1 && ruid == euid);
		crfree(cr);
	}
	mutex_exit(&p->p_crlock);

	/*
	 * We decrement the number of processes associated with the oldruid
	 * to match the increment above, even if the ruid of the process
	 * did not change or an error occurred (oldruid == uid).
	 */
	if (uidchge) {
		ASSERT(oldruid != -1 && ruid != -1);
		mutex_enter(&pidlock);
		upcount_dec(oldruid, zoneid);
		mutex_exit(&pidlock);
	}

	if (error == 0) {
		if (do_nocd) {
			mutex_enter(&p->p_lock);
			p->p_flag |= SNOCD;
			mutex_exit(&p->p_lock);
		}
		crset(p, newcr);	/* broadcast to process threads */
		return (0);
	}
	crfree(newcr);
	if (ksp != NULL)
		ksid_rele(ksp);
	return (set_errno(error));
}
