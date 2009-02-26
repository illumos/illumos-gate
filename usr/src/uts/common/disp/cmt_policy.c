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
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/cmn_err.h>
#include <sys/disp.h>
#include <sys/group.h>
#include <sys/bitset.h>
#include <sys/lgrp.h>
#include <sys/cmt.h>

/*
 * CMT dispatcher policies
 *
 * This file implements CMT dispatching policies using Processor Groups.
 *
 * The scheduler/dispatcher leverages knowledge of the performance
 * relevant CMT sharing relationships existing between CPUs to implement
 * load balancing, and coalescence thread placement policies.
 *
 * Load balancing policy seeks to improve performance by minimizing
 * contention over shared processor resources / facilities. Coalescence
 * policies improve resource utilization and ultimately power efficiency.
 *
 * On NUMA systems, the dispatcher will generally perform load balancing and
 * coalescence within (and not across) lgroups. This is because there isn't
 * much sense in trying to correct an imbalance by sending a thread outside
 * of its home, if it would attempt to return home a short while later.
 * The dispatcher will implement CMT policy across lgroups however, if
 * it can do so with a thread homed to the root lgroup, since root homed
 * threads have no lgroup affinity.
 */

/*
 * Return non-zero if, given the policy, we should migrate from running
 * somewhere "here" to somewhere "there".
 */
static int
cmt_should_migrate(pg_cmt_t *here, pg_cmt_t *there, pg_cmt_policy_t policy,
    int self)
{
	uint32_t here_util, there_util;

	here_util = here->cmt_utilization;
	there_util = there->cmt_utilization;

	/*
	 * This assumes that curthread's utilization is "1"
	 */
	if (self && bitset_in_set(&here->cmt_cpus_actv_set, CPU->cpu_seqid))
		here_util--;	/* Ignore curthread's effect */

	/*
	 * Load balancing and coalescence are conflicting policies
	 */
	ASSERT((policy & (CMT_BALANCE|CMT_COALESCE)) !=
	    (CMT_BALANCE|CMT_COALESCE));

	if (policy & CMT_BALANCE) {
		/*
		 * Balance utilization
		 *
		 * If the target is comparatively underutilized
		 * (either in an absolute sense, or scaled by capacity),
		 * then choose to balance.
		 */
		if ((here_util > there_util) ||
		    (here_util == there_util &&
		    (CMT_CAPACITY(there) > CMT_CAPACITY(here)))) {
			return (1);
		}
	} else if (policy & CMT_COALESCE) {
		/*
		 * Attempt to drive group utilization up to capacity
		 */
		if (there_util > here_util &&
		    there_util < CMT_CAPACITY(there))
			return (1);
	}
	return (0);
}

/*
 * Perform multi-level CMT load balancing of running threads.
 *
 * tp is the thread being enqueued.
 * cp is a hint CPU, against which CMT load balancing will be performed.
 *
 * Returns cp, or a CPU better than cp with respect to balancing
 * running thread load.
 */
cpu_t *
cmt_balance(kthread_t *tp, cpu_t *cp)
{
	int		hint, i, cpu, nsiblings;
	int		self = 0;
	group_t		*cmt_pgs, *siblings;
	pg_cmt_t	*pg, *pg_tmp, *tpg = NULL;
	int		level = 0;
	cpu_t		*newcp;
	extern cmt_lgrp_t *cmt_root;

	ASSERT(THREAD_LOCK_HELD(tp));

	cmt_pgs = &cp->cpu_pg->cmt_pgs;

	if (GROUP_SIZE(cmt_pgs) == 0)
		return (cp);	/* nothing to do */

	if (tp == curthread)
		self = 1;

	/*
	 * Balance across siblings in the CPUs CMT lineage
	 * If the thread is homed to the root lgroup, perform
	 * top level balancing against other top level PGs
	 * in the system. Otherwise, start with the default
	 * top level siblings group, which is within the leaf lgroup
	 */
	pg = GROUP_ACCESS(cmt_pgs, level);
	if (tp->t_lpl->lpl_lgrpid == LGRP_ROOTID)
		siblings = &cmt_root->cl_pgs;
	else
		siblings = pg->cmt_siblings;

	/*
	 * Traverse down the lineage until we find a level that needs
	 * balancing, or we get to the end.
	 */
	for (;;) {
		nsiblings = GROUP_SIZE(siblings);	/* self inclusive */
		if (nsiblings == 1)
			goto next_level;

		hint = CPU_PSEUDO_RANDOM() % nsiblings;

		/*
		 * Find a balancing candidate from among our siblings
		 * "hint" is a hint for where to start looking
		 */
		i = hint;
		do {
			ASSERT(i < nsiblings);
			pg_tmp = GROUP_ACCESS(siblings, i);

			/*
			 * The candidate must not be us, and must
			 * have some CPU resources in the thread's
			 * partition
			 */
			if (pg_tmp != pg &&
			    bitset_in_set(&tp->t_cpupart->cp_cmt_pgs,
			    ((pg_t *)pg_tmp)->pg_id)) {
				tpg = pg_tmp;
				break;
			}

			if (++i >= nsiblings)
				i = 0;
		} while (i != hint);

		if (!tpg)
			goto next_level; /* no candidates at this level */

		/*
		 * Decide if we should migrate from the current PG to a
		 * target PG given a policy
		 */
		if (cmt_should_migrate(pg, tpg, pg->cmt_policy, self))
			break;
		tpg = NULL;

next_level:
		if (++level == GROUP_SIZE(cmt_pgs))
			break;

		pg = GROUP_ACCESS(cmt_pgs, level);
		siblings = pg->cmt_siblings;
	}

	if (tpg) {
		uint_t	tgt_size = GROUP_SIZE(&tpg->cmt_cpus_actv);

		/*
		 * Select an idle CPU from the target
		 */
		hint = CPU_PSEUDO_RANDOM() % tgt_size;
		cpu = hint;
		do {
			newcp = GROUP_ACCESS(&tpg->cmt_cpus_actv, cpu);
			if (newcp->cpu_part == tp->t_cpupart &&
			    newcp->cpu_dispatch_pri == -1) {
				cp = newcp;
				break;
			}
			if (++cpu == tgt_size)
				cpu = 0;
		} while (cpu != hint);
	}

	return (cp);
}
