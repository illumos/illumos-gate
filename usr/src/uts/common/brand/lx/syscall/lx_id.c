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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/zone.h>
#include <sys/cred_impl.h>
#include <sys/policy.h>

typedef ushort_t	l_uid16_t;
typedef ushort_t	l_gid16_t;
typedef uint_t		l_uid_t;
typedef uint_t		l_gid_t;

#define	LINUX_UID16_TO_UID32(uid16)	\
	(((uid16) == (l_uid16_t)-1) ? ((l_uid_t)-1) : (l_uid_t)(uid16))

#define	LINUX_GID16_TO_GID32(gid16)     \
	(((gid16) == (l_gid16_t)-1) ? ((l_gid_t)-1) : (l_gid_t)(gid16))

#define	LX_NGROUPS_MAX	32
extern int setgroups(int, gid_t *);

/*
 * This function is based on setreuid in common/syscall/uid.c and exists
 * because illumos does not have a way to explicitly set the saved uid (suid)
 * from any other system call.
 */
long
lx_setresuid(l_uid_t ruid, l_uid_t euid, l_uid_t suid)
{
	proc_t	*p;
	int	error = 0;
	int	do_nocd = 0;
	int	uidchge = 0;
	uid_t	oldruid = ruid;
	cred_t	*cr, *newcr;
	zoneid_t zoneid = getzoneid();

	if ((ruid != -1 && (ruid > MAXUID)) ||
	    (euid != -1 && (euid > MAXUID)) ||
	    (suid != -1 && (suid > MAXUID))) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Need to pre-allocate the new cred structure before grabbing
	 * the p_crlock mutex.
	 */
	newcr = cralloc();

	p = ttoproc(curthread);

retry:
	mutex_enter(&p->p_crlock);
	cr = p->p_cred;

	if (ruid != -1 &&
	    ruid != cr->cr_ruid && ruid != cr->cr_uid &&
	    ruid != cr->cr_suid && secpolicy_allow_setid(cr, ruid, B_FALSE)) {
		error = EPERM;
	} else if (euid != -1 &&
	    euid != cr->cr_ruid && euid != cr->cr_uid &&
	    euid != cr->cr_suid && secpolicy_allow_setid(cr, euid, B_FALSE)) {
		error = EPERM;
	} else if (suid != -1 &&
	    suid != cr->cr_ruid && suid != cr->cr_uid &&
	    suid != cr->cr_suid && secpolicy_allow_setid(cr, suid, B_FALSE)) {
		error = EPERM;
	} else {
		if (!uidchge && ruid != -1 && cr->cr_ruid != ruid) {
			/*
			 * The ruid of the process is going to change. In order
			 * to avoid a race condition involving the
			 * process count associated with the newly given ruid,
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

		if (euid != -1)
			newcr->cr_uid = euid;
		if (suid != -1)
			newcr->cr_suid = suid;
		if (ruid != -1) {
			oldruid = newcr->cr_ruid;
			newcr->cr_ruid = ruid;
			ASSERT(ruid != oldruid ? uidchge : 1);
		}

		/*
		 * A process that gives up its privilege
		 * must be marked to produce no core dump.
		 */
		if ((cr->cr_uid != newcr->cr_uid ||
		    cr->cr_ruid != newcr->cr_ruid ||
		    cr->cr_suid != newcr->cr_suid))
			do_nocd = 1;

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
		goto done;
	}
	crfree(newcr);
done:
	if (error)
		return (set_errno(error));
	else
		return (0);
}

long
lx_setresuid16(l_uid16_t ruid16, l_uid16_t euid16, l_uid16_t suid16)
{
	long	rval;

	rval = lx_setresuid(
	    LINUX_UID16_TO_UID32(ruid16),
	    LINUX_UID16_TO_UID32(euid16),
	    LINUX_UID16_TO_UID32(suid16));

	return (rval);
}

/*
 * This function is based on setregid in common/syscall/gid.c
 */
long
lx_setresgid(l_gid_t rgid, l_gid_t egid, l_gid_t sgid)
{
	proc_t	*p;
	int	error = 0;
	int	do_nocd = 0;
	cred_t	*cr, *newcr;

	if ((rgid != -1 && (rgid > MAXUID)) ||
	    (egid != -1 && (egid > MAXUID)) ||
	    (sgid != -1 && (sgid > MAXUID))) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Need to pre-allocate the new cred structure before grabbing
	 * the p_crlock mutex.
	 */
	newcr = cralloc();

	p = ttoproc(curthread);
	mutex_enter(&p->p_crlock);
	cr = p->p_cred;

	if (rgid != -1 &&
	    rgid != cr->cr_rgid && rgid != cr->cr_gid &&
	    rgid != cr->cr_sgid && secpolicy_allow_setid(cr, -1, B_FALSE)) {
		error = EPERM;
	} else if (egid != -1 &&
	    egid != cr->cr_rgid && egid != cr->cr_gid &&
	    egid != cr->cr_sgid && secpolicy_allow_setid(cr, -1, B_FALSE)) {
		error = EPERM;
	} else if (sgid != -1 &&
	    sgid != cr->cr_rgid && sgid != cr->cr_gid &&
	    sgid != cr->cr_sgid && secpolicy_allow_setid(cr, -1, B_FALSE)) {
		error = EPERM;
	} else {
		crhold(cr);
		crcopy_to(cr, newcr);
		p->p_cred = newcr;

		if (egid != -1)
			newcr->cr_gid = egid;
		if (sgid != -1)
			newcr->cr_sgid = sgid;
		if (rgid != -1)
			newcr->cr_rgid = rgid;

		/*
		 * A process that gives up its privilege
		 * must be marked to produce no core dump.
		 */
		if ((cr->cr_gid != newcr->cr_gid ||
		    cr->cr_rgid != newcr->cr_rgid ||
		    cr->cr_sgid != newcr->cr_sgid))
			do_nocd = 1;

		crfree(cr);
	}
	mutex_exit(&p->p_crlock);

	if (error == 0) {
		if (do_nocd) {
			mutex_enter(&p->p_lock);
			p->p_flag |= SNOCD;
			mutex_exit(&p->p_lock);
		}
		crset(p, newcr);	/* broadcast to process threads */
		goto done;
	}
	crfree(newcr);
done:
	if (error)
		return (set_errno(error));
	else
		return (0);
}

long
lx_setresgid16(l_gid16_t rgid16, l_gid16_t egid16, l_gid16_t sgid16)
{
	long	rval;

	rval = lx_setresgid(
	    LINUX_GID16_TO_GID32(rgid16),
	    LINUX_GID16_TO_GID32(egid16),
	    LINUX_GID16_TO_GID32(sgid16));

	return (rval);
}

/*
 * Linux defines NGROUPS_MAX to be 32, but on illumos it is only 16. We employ
 * the terrible hack below so that tests may proceed, if only on DEBUG kernels.
 */
int
lx_helper_setgroups(int ngroups, gid_t *grouplist)
{
#ifdef DEBUG
	if (ngroups > ngroups_max && ngroups <= LX_NGROUPS_MAX)
		ngroups = ngroups_max;
#endif /* DEBUG */

	return (setgroups(ngroups, grouplist));
}
