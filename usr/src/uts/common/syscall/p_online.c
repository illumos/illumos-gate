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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/kstat.h>
#include <sys/uadmin.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/smt.h>

/*
 * CPU state diagram
 *
 *                  P_SPARE
 * P_POWEROFF <---> P_OFFLINE <---> P_ONLINE <---> P_NOINTR
 *                  P_FAULTED
 *                  P_DISABLED
 */
int
p_online_internal_locked(processorid_t cpun, int new_status, int *old_status)
{
	cpu_t	*cp;
	int	status;
	int	error = 0;
	int	flags = 0;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cpun == P_ALL_SIBLINGS) {
		if (new_status != P_DISABLED) {
			error = EINVAL;
			goto out;
		}

		return (smt_disable());
	}

	if ((cp = cpu_get(cpun)) == NULL) {
		error = EINVAL;
		goto out;
	}

	if (new_status & P_FORCED)
		flags = CPU_FORCED;
	*old_status = status = cpu_get_state(cp); /* get processor status */
	new_status &= ~P_FORCED;

	/*
	 * Perform credentials check.
	 */
	switch (new_status) {
	case P_STATUS:
		goto out;
	case P_ONLINE:
	case P_OFFLINE:
	case P_NOINTR:
	case P_FAULTED:
	case P_SPARE:
		if (secpolicy_ponline(CRED()) != 0)
			error = EPERM;
		break;
	case P_DISABLED:
	default:
		error = EINVAL;
		break;
	}

	if (error)
		goto out;

	/*
	 * return 0 if the CPU is already in the desired new state.
	 */
	if (status == new_status)
		goto out;

	switch (new_status) {
	case P_ONLINE:
		switch (status) {
		case P_POWEROFF:
			/*
			 * If CPU is powered off, power it on.
			 */
			if (error = cpu_poweron(cp))
				break;
			ASSERT(cpu_get_state(cp) == P_OFFLINE);
			/* FALLTHROUGH */
		case P_DISABLED:
		case P_OFFLINE:
		case P_FAULTED:
		case P_SPARE:
			/*
			 * If CPU is in one of the offline states,
			 * bring it online.
			 */
			error = cpu_online(cp, flags);
			break;
		case P_NOINTR:
			cpu_intr_enable(cp);
			break;
		}
		break;

	case P_OFFLINE:
		switch (status) {
		case P_NOINTR:
			/*
			 * Before we take the CPU offline, we first enable I/O
			 * interrupts.
			 */
			cpu_intr_enable(cp);
			/* FALLTHROUGH */
		case P_ONLINE:
		case P_DISABLED:
		case P_FAULTED:
		case P_SPARE:
			/*
			 * CPU is online, or in a special offline state.
			 * Take it offline.
			 */
			error = cpu_offline(cp, flags);
			break;
		case P_POWEROFF:
			/*
			 * If CPU is powered off, power it on.
			 */
			error = cpu_poweron(cp);
			break;
		}
		break;

	case P_NOINTR:
		switch (status) {
		case P_POWEROFF:
			/*
			 * if CPU is powered off, power it on.
			 */
			if (error = cpu_poweron(cp))
				break;
			ASSERT(cpu_get_state(cp) == P_OFFLINE);
			/* FALLTHROUGH */
		case P_DISABLED:
		case P_OFFLINE:
		case P_FAULTED:
		case P_SPARE:
			/*
			 * First, bring the CPU online.
			 */
			if (error = cpu_online(cp, flags))
				break;
			/* FALLTHROUGH */
		case P_ONLINE:
			/*
			 * CPU is now online.  Try to disable interrupts.
			 */
			error = cpu_intr_disable(cp);
			break;
		}
		break;

	case P_FAULTED:
		switch (status) {
		case P_POWEROFF:
			/*
			 * If CPU is powered off, power it on.
			 */
			if (error = cpu_poweron(cp))
				break;
			ASSERT(cpu_get_state(cp) == P_OFFLINE);
			/*FALLTHROUGH*/
		case P_DISABLED:
		case P_OFFLINE:
		case P_ONLINE:
		case P_NOINTR:
		case P_SPARE:
			/*
			 * Mark this CPU as faulted.
			 */
			error = cpu_faulted(cp, flags);
			break;
		}
		break;

	case P_SPARE:
		switch (status) {
		case P_POWEROFF:
			/*
			 * If CPU is powered off, power it on.
			 */
			if (error = cpu_poweron(cp))
				break;
			ASSERT(cpu_get_state(cp) == P_OFFLINE);
			/*FALLTHROUGH*/
		case P_DISABLED:
		case P_OFFLINE:
		case P_FAULTED:
		case P_ONLINE:
		case P_NOINTR:
			/*
			 * Mark this CPU as a spare.
			 */
			error = cpu_spare(cp, flags);
			break;
		}
		break;
	}
out:
	return (error);
}

int
p_online_internal(processorid_t cpun, int new_status, int *old_status)
{
	int rc;

	mutex_enter(&cpu_lock);		/* protects CPU states */
	rc = p_online_internal_locked(cpun, new_status, old_status);
	mutex_exit(&cpu_lock);

	return (rc);
}

/*
 * p_online(2) - get/change processor operational status.
 *
 *   As noted in os/cpu.c, the P_ONLINE and other state constants are for use
 *   only in this system call path and other paths conveying CPU state to
 *   userland.  In general, other kernel consumers should be using the accessor
 *   functions in uts/common/os/cpu.c.
 */
int
p_online(processorid_t cpun, int new_status)
{
	int ret;
	int old_status;

	ret = p_online_internal(cpun, new_status, &old_status);
	if (ret != 0)
		return (set_errno(ret));
	return (old_status);
}
