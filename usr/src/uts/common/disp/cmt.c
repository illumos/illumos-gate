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

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/processor.h>
#include <sys/disp.h>
#include <sys/group.h>
#include <sys/pghw.h>
#include <sys/bitset.h>
#include <sys/lgrp.h>
#include <sys/cmt.h>
#include <sys/cpu_pm.h>

/*
 * CMT scheduler / dispatcher support
 *
 * This file implements CMT scheduler support using Processor Groups.
 * The CMT processor group class creates and maintains the CMT class
 * specific processor group pg_cmt_t.
 *
 * ---------------------------- <-- pg_cmt_t *
 * | pghw_t                   |
 * ----------------------------
 * | CMT class specific data  |
 * | - hierarchy linkage      |
 * | - CMT load balancing data|
 * | - active CPU group/bitset|
 * ----------------------------
 *
 * The scheduler/dispatcher leverages knowledge of the performance
 * relevant CMT sharing relationships existing between cpus to implement
 * optimized affinity, load balancing, and coalescence policies.
 *
 * Load balancing policy seeks to improve performance by minimizing
 * contention over shared processor resources / facilities, Affinity
 * policies seek to improve cache and TLB utilization. Coalescence
 * policies improve resource utilization and ultimately power efficiency.
 *
 * The CMT PGs created by this class are already arranged into a
 * hierarchy (which is done in the pghw layer). To implement the top-down
 * CMT load balancing algorithm, the CMT PGs additionally maintain
 * parent, child and sibling hierarchy relationships.
 * Parent PGs always contain a superset of their children(s) resources,
 * each PG can have at most one parent, and siblings are the group of PGs
 * sharing the same parent.
 *
 * On UMA based systems, the CMT load balancing algorithm begins by balancing
 * load across the group of top level PGs in the system hierarchy.
 * On NUMA systems, the CMT load balancing algorithm balances load across the
 * group of top level PGs in each leaf lgroup...but for root homed threads,
 * is willing to balance against all the top level PGs in the system.
 *
 * Groups of top level PGs are maintained to implement the above, one for each
 * leaf lgroup (containing the top level PGs in that lgroup), and one (for the
 * root lgroup) that contains all the top level PGs in the system.
 */
static cmt_lgrp_t	*cmt_lgrps = NULL;	/* cmt_lgrps list head */
static cmt_lgrp_t	*cpu0_lgrp = NULL;	/* boot CPU's initial lgrp */
						/* used for null_proc_lpa */
cmt_lgrp_t		*cmt_root = NULL;	/* Reference to root cmt pg */

static int		is_cpu0 = 1; /* true if this is boot CPU context */

/*
 * Array of hardware sharing relationships that are blacklisted.
 * CMT scheduling optimizations won't be performed for blacklisted sharing
 * relationships.
 */
static int		cmt_hw_blacklisted[PGHW_NUM_COMPONENTS];

/*
 * Set this to non-zero to disable CMT scheduling
 * This must be done via kmdb -d, as /etc/system will be too late
 */
int			cmt_sched_disabled = 0;

/*
 * Status codes for CMT lineage validation
 * See pg_cmt_lineage_validate() below
 */
typedef enum cmt_lineage_validation {
	CMT_LINEAGE_VALID,
	CMT_LINEAGE_NON_CONCENTRIC,
	CMT_LINEAGE_PG_SPANS_LGRPS,
	CMT_LINEAGE_NON_PROMOTABLE,
	CMT_LINEAGE_REPAIRED,
	CMT_LINEAGE_UNRECOVERABLE
} cmt_lineage_validation_t;

/*
 * Status of the current lineage under construction.
 * One must be holding cpu_lock to change this.
 */
cmt_lineage_validation_t	cmt_lineage_status = CMT_LINEAGE_VALID;

/*
 * Power domain definitions (on x86) are defined by ACPI, and
 * therefore may be subject to BIOS bugs.
 */
#define	PG_CMT_HW_SUSPECT(hw)	PGHW_IS_PM_DOMAIN(hw)

/*
 * Macro to test if PG is managed by the CMT PG class
 */
#define	IS_CMT_PG(pg)	(((pg_t *)(pg))->pg_class->pgc_id == pg_cmt_class_id)

static pg_cid_t		pg_cmt_class_id;		/* PG class id */

static pg_t		*pg_cmt_alloc();
static void		pg_cmt_free(pg_t *);
static void		pg_cmt_cpu_init(cpu_t *, cpu_pg_t *);
static void		pg_cmt_cpu_fini(cpu_t *, cpu_pg_t *);
static void		pg_cmt_cpu_active(cpu_t *);
static void		pg_cmt_cpu_inactive(cpu_t *);
static void		pg_cmt_cpupart_in(cpu_t *, cpupart_t *);
static void		pg_cmt_cpupart_move(cpu_t *, cpupart_t *, cpupart_t *);
static char		*pg_cmt_policy_name(pg_t *);
static void		pg_cmt_hier_sort(pg_cmt_t **, int);
static pg_cmt_t		*pg_cmt_hier_rank(pg_cmt_t *, pg_cmt_t *);
static int		pg_cmt_cpu_belongs(pg_t *, cpu_t *);
static int		pg_cmt_hw(pghw_type_t);
static cmt_lgrp_t	*pg_cmt_find_lgrp(lgrp_handle_t);
static cmt_lgrp_t	*pg_cmt_lgrp_create(lgrp_handle_t);
static void		cmt_ev_thread_swtch(pg_t *, cpu_t *, hrtime_t,
			    kthread_t *, kthread_t *);
static void		cmt_ev_thread_swtch_pwr(pg_t *, cpu_t *, hrtime_t,
			    kthread_t *, kthread_t *);
static void		cmt_ev_thread_remain_pwr(pg_t *, cpu_t *, kthread_t *);
static cmt_lineage_validation_t	pg_cmt_lineage_validate(pg_cmt_t **, int *,
			    cpu_pg_t *);

/*
 * CMT PG ops
 */
struct pg_ops pg_ops_cmt = {
	pg_cmt_alloc,
	pg_cmt_free,
	pg_cmt_cpu_init,
	pg_cmt_cpu_fini,
	pg_cmt_cpu_active,
	pg_cmt_cpu_inactive,
	pg_cmt_cpupart_in,
	NULL,			/* cpupart_out */
	pg_cmt_cpupart_move,
	pg_cmt_cpu_belongs,
	pg_cmt_policy_name,
};

/*
 * Initialize the CMT PG class
 */
void
pg_cmt_class_init(void)
{
	if (cmt_sched_disabled)
		return;

	pg_cmt_class_id = pg_class_register("cmt", &pg_ops_cmt, PGR_PHYSICAL);
}

/*
 * Called to indicate a new CPU has started up so
 * that either t0 or the slave startup thread can
 * be accounted for.
 */
void
pg_cmt_cpu_startup(cpu_t *cp)
{
	pg_ev_thread_swtch(cp, gethrtime_unscaled(), cp->cpu_idle_thread,
	    cp->cpu_thread);
}

/*
 * Return non-zero if thread can migrate between "from" and "to"
 * without a performance penalty
 */
int
pg_cmt_can_migrate(cpu_t *from, cpu_t *to)
{
	if (from->cpu_physid->cpu_cacheid ==
	    to->cpu_physid->cpu_cacheid)
		return (1);
	return (0);
}

/*
 * CMT class specific PG allocation
 */
static pg_t *
pg_cmt_alloc(void)
{
	return (kmem_zalloc(sizeof (pg_cmt_t), KM_NOSLEEP));
}

/*
 * Class specific PG de-allocation
 */
static void
pg_cmt_free(pg_t *pg)
{
	ASSERT(pg != NULL);
	ASSERT(IS_CMT_PG(pg));

	kmem_free((pg_cmt_t *)pg, sizeof (pg_cmt_t));
}

/*
 * Given a hardware sharing relationship, return which dispatcher
 * policies should be implemented to optimize performance and efficiency
 */
static pg_cmt_policy_t
pg_cmt_policy(pghw_type_t hw)
{
	pg_cmt_policy_t p;

	/*
	 * Give the platform a chance to override the default
	 */
	if ((p = pg_plat_cmt_policy(hw)) != CMT_NO_POLICY)
		return (p);

	switch (hw) {
	case PGHW_IPIPE:
	case PGHW_FPU:
	case PGHW_PROCNODE:
	case PGHW_CHIP:
		return (CMT_BALANCE);
	case PGHW_CACHE:
		return (CMT_AFFINITY | CMT_BALANCE);
	case PGHW_POW_ACTIVE:
	case PGHW_POW_IDLE:
		return (CMT_BALANCE);
	default:
		return (CMT_NO_POLICY);
	}
}

/*
 * Rank the importance of optimizing for the pg1 relationship vs.
 * the pg2 relationship.
 */
static pg_cmt_t *
pg_cmt_hier_rank(pg_cmt_t *pg1, pg_cmt_t *pg2)
{
	pghw_type_t hw1 = ((pghw_t *)pg1)->pghw_hw;
	pghw_type_t hw2 = ((pghw_t *)pg2)->pghw_hw;

	/*
	 * A power domain is only important if CPUPM is enabled.
	 */
	if (cpupm_get_policy() == CPUPM_POLICY_DISABLED) {
		if (PGHW_IS_PM_DOMAIN(hw1) && !PGHW_IS_PM_DOMAIN(hw2))
			return (pg2);
		if (PGHW_IS_PM_DOMAIN(hw2) && !PGHW_IS_PM_DOMAIN(hw1))
			return (pg1);
	}

	/*
	 * Otherwise, ask the platform
	 */
	if (pg_plat_hw_rank(hw1, hw2) == hw1)
		return (pg1);
	else
		return (pg2);
}

/*
 * Initialize CMT callbacks for the given PG
 */
static void
cmt_callback_init(pg_t *pg)
{
	/*
	 * Stick with the default callbacks if there isn't going to be
	 * any CMT thread placement optimizations implemented.
	 */
	if (((pg_cmt_t *)pg)->cmt_policy == CMT_NO_POLICY)
		return;

	switch (((pghw_t *)pg)->pghw_hw) {
	case PGHW_POW_ACTIVE:
		pg->pg_cb.thread_swtch = cmt_ev_thread_swtch_pwr;
		pg->pg_cb.thread_remain = cmt_ev_thread_remain_pwr;
		break;
	default:
		pg->pg_cb.thread_swtch = cmt_ev_thread_swtch;

	}
}

/*
 * Promote PG above it's current parent.
 * This is only legal if PG has an equal or greater number of CPUs than its
 * parent.
 *
 * This routine operates on the CPU specific processor group data (for the CPUs
 * in the PG being promoted), and may be invoked from a context where one CPU's
 * PG data is under construction. In this case the argument "pgdata", if not
 * NULL, is a reference to the CPU's under-construction PG data.
 */
static void
cmt_hier_promote(pg_cmt_t *pg, cpu_pg_t *pgdata)
{
	pg_cmt_t	*parent;
	group_t		*children;
	cpu_t		*cpu;
	group_iter_t	iter;
	pg_cpu_itr_t	cpu_iter;
	int		r;
	int		err;
	int		nchildren;

	ASSERT(MUTEX_HELD(&cpu_lock));

	parent = pg->cmt_parent;
	if (parent == NULL) {
		/*
		 * Nothing to do
		 */
		return;
	}

	ASSERT(PG_NUM_CPUS((pg_t *)pg) >= PG_NUM_CPUS((pg_t *)parent));

	/*
	 * We're changing around the hierarchy, which is actively traversed
	 * by the dispatcher. Pause CPUS to ensure exclusivity.
	 */
	pause_cpus(NULL, NULL);

	/*
	 * If necessary, update the parent's sibling set, replacing parent
	 * with PG.
	 */
	if (parent->cmt_siblings) {
		if (group_remove(parent->cmt_siblings, parent, GRP_NORESIZE)
		    != -1) {
			r = group_add(parent->cmt_siblings, pg, GRP_NORESIZE);
			ASSERT(r != -1);
		}
	}

	/*
	 * If the parent is at the top of the hierarchy, replace it's entry
	 * in the root lgroup's group of top level PGs.
	 */
	if (parent->cmt_parent == NULL &&
	    parent->cmt_siblings != &cmt_root->cl_pgs) {
		if (group_remove(&cmt_root->cl_pgs, parent, GRP_NORESIZE)
		    != -1) {
			r = group_add(&cmt_root->cl_pgs, pg, GRP_NORESIZE);
			ASSERT(r != -1);
		}
	}

	/*
	 * We assume (and therefore assert) that the PG being promoted is an
	 * only child of it's parent. Update the parent's children set
	 * replacing PG's entry with the parent (since the parent is becoming
	 * the child). Then have PG and the parent swap children sets and
	 * children counts.
	 */
	ASSERT(GROUP_SIZE(parent->cmt_children) <= 1);
	if (group_remove(parent->cmt_children, pg, GRP_NORESIZE) != -1) {
		r = group_add(parent->cmt_children, parent, GRP_NORESIZE);
		ASSERT(r != -1);
	}

	children = pg->cmt_children;
	pg->cmt_children = parent->cmt_children;
	parent->cmt_children = children;

	nchildren = pg->cmt_nchildren;
	pg->cmt_nchildren = parent->cmt_nchildren;
	parent->cmt_nchildren = nchildren;

	/*
	 * Update the sibling references for PG and it's parent
	 */
	pg->cmt_siblings = parent->cmt_siblings;
	parent->cmt_siblings = pg->cmt_children;

	/*
	 * Update any cached lineages in the per CPU pg data.
	 */
	PG_CPU_ITR_INIT(pg, cpu_iter);
	while ((cpu = pg_cpu_next(&cpu_iter)) != NULL) {
		int		idx;
		int		sz;
		pg_cmt_t	*cpu_pg;
		cpu_pg_t	*pgd;	/* CPU's PG data */

		/*
		 * The CPU's whose lineage is under construction still
		 * references the bootstrap CPU PG data structure.
		 */
		if (pg_cpu_is_bootstrapped(cpu))
			pgd = pgdata;
		else
			pgd = cpu->cpu_pg;

		/*
		 * Iterate over the CPU's PGs updating the children
		 * of the PG being promoted, since they have a new parent.
		 */
		group_iter_init(&iter);
		while ((cpu_pg = group_iterate(&pgd->cmt_pgs, &iter)) != NULL) {
			if (cpu_pg->cmt_parent == pg) {
				cpu_pg->cmt_parent = parent;
			}
		}

		/*
		 * Update the CMT load balancing lineage
		 */
		if ((idx = group_find(&pgd->cmt_pgs, (void *)pg)) == -1) {
			/*
			 * Unless this is the CPU who's lineage is being
			 * constructed, the PG being promoted should be
			 * in the lineage.
			 */
			ASSERT(pg_cpu_is_bootstrapped(cpu));
			continue;
		}

		ASSERT(idx > 0);
		ASSERT(GROUP_ACCESS(&pgd->cmt_pgs, idx - 1) == parent);

		/*
		 * Have the child and the parent swap places in the CPU's
		 * lineage
		 */
		group_remove_at(&pgd->cmt_pgs, idx);
		group_remove_at(&pgd->cmt_pgs, idx - 1);
		err = group_add_at(&pgd->cmt_pgs, parent, idx);
		ASSERT(err == 0);
		err = group_add_at(&pgd->cmt_pgs, pg, idx - 1);
		ASSERT(err == 0);

		/*
		 * Ensure cmt_lineage references CPU's leaf PG.
		 * Since cmt_pgs is top-down ordered, the bottom is the last
		 * element.
		 */
		if ((sz = GROUP_SIZE(&pgd->cmt_pgs)) > 0)
			pgd->cmt_lineage = GROUP_ACCESS(&pgd->cmt_pgs, sz - 1);
	}

	/*
	 * Update the parent references for PG and it's parent
	 */
	pg->cmt_parent = parent->cmt_parent;
	parent->cmt_parent = pg;

	start_cpus();
}

/*
 * CMT class callback for a new CPU entering the system
 *
 * This routine operates on the CPU specific processor group data (for the CPU
 * being initialized). The argument "pgdata" is a reference to the CPU's PG
 * data to be constructed.
 *
 * cp->cpu_pg is used by the dispatcher to access the CPU's PG data
 * references a "bootstrap" structure. pg_cmt_cpu_init() and the routines it
 * calls must be careful to operate only on the "pgdata" argument, and not
 * cp->cpu_pg.
 */
static void
pg_cmt_cpu_init(cpu_t *cp, cpu_pg_t *pgdata)
{
	pg_cmt_t	*pg;
	group_t		*cmt_pgs;
	int		levels, level;
	pghw_type_t	hw;
	pg_t		*pg_cache = NULL;
	pg_cmt_t	*cpu_cmt_hier[PGHW_NUM_COMPONENTS];
	lgrp_handle_t	lgrp_handle;
	cmt_lgrp_t	*lgrp;
	cmt_lineage_validation_t	lineage_status;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(pg_cpu_is_bootstrapped(cp));

	if (cmt_sched_disabled)
		return;

	/*
	 * A new CPU is coming into the system.
	 * Interrogate the platform to see if the CPU
	 * has any performance or efficiency relevant
	 * sharing relationships
	 */
	cmt_pgs = &pgdata->cmt_pgs;
	pgdata->cmt_lineage = NULL;

	bzero(cpu_cmt_hier, sizeof (cpu_cmt_hier));
	levels = 0;
	for (hw = PGHW_START; hw < PGHW_NUM_COMPONENTS; hw++) {

		pg_cmt_policy_t	policy;

		/*
		 * We're only interested in the hw sharing relationships
		 * for which we know how to optimize.
		 */
		policy = pg_cmt_policy(hw);
		if (policy == CMT_NO_POLICY ||
		    pg_plat_hw_shared(cp, hw) == 0)
			continue;

		/*
		 * We will still create the PGs for hardware sharing
		 * relationships that have been blacklisted, but won't
		 * implement CMT thread placement optimizations against them.
		 */
		if (cmt_hw_blacklisted[hw] == 1)
			policy = CMT_NO_POLICY;

		/*
		 * Find (or create) the PG associated with
		 * the hw sharing relationship in which cp
		 * belongs.
		 *
		 * Determine if a suitable PG already
		 * exists, or if one needs to be created.
		 */
		pg = (pg_cmt_t *)pghw_place_cpu(cp, hw);
		if (pg == NULL) {
			/*
			 * Create a new one.
			 * Initialize the common...
			 */
			pg = (pg_cmt_t *)pg_create(pg_cmt_class_id);

			/* ... physical ... */
			pghw_init((pghw_t *)pg, cp, hw);

			/*
			 * ... and CMT specific portions of the
			 * structure.
			 */
			pg->cmt_policy = policy;

			/* CMT event callbacks */
			cmt_callback_init((pg_t *)pg);

			bitset_init(&pg->cmt_cpus_actv_set);
			group_create(&pg->cmt_cpus_actv);
		} else {
			ASSERT(IS_CMT_PG(pg));
		}

		((pghw_t *)pg)->pghw_generation++;

		/* Add the CPU to the PG */
		pg_cpu_add((pg_t *)pg, cp, pgdata);

		/*
		 * Ensure capacity of the active CPU group/bitset
		 */
		group_expand(&pg->cmt_cpus_actv,
		    GROUP_SIZE(&((pg_t *)pg)->pg_cpus));

		if (cp->cpu_seqid >=
		    bitset_capacity(&pg->cmt_cpus_actv_set)) {
			bitset_resize(&pg->cmt_cpus_actv_set,
			    cp->cpu_seqid + 1);
		}

		/*
		 * Build a lineage of CMT PGs for load balancing / coalescence
		 */
		if (policy & (CMT_BALANCE | CMT_COALESCE)) {
			cpu_cmt_hier[levels++] = pg;
		}

		/* Cache this for later */
		if (hw == PGHW_CACHE)
			pg_cache = (pg_t *)pg;
	}

	group_expand(cmt_pgs, levels);

	if (cmt_root == NULL)
		cmt_root = pg_cmt_lgrp_create(lgrp_plat_root_hand());

	/*
	 * Find the lgrp that encapsulates this CPU's CMT hierarchy
	 */
	lgrp_handle = lgrp_plat_cpu_to_hand(cp->cpu_id);
	if ((lgrp = pg_cmt_find_lgrp(lgrp_handle)) == NULL)
		lgrp = pg_cmt_lgrp_create(lgrp_handle);

	/*
	 * Ascendingly sort the PGs in the lineage by number of CPUs
	 */
	pg_cmt_hier_sort(cpu_cmt_hier, levels);

	/*
	 * Examine the lineage and validate it.
	 * This routine will also try to fix the lineage along with the
	 * rest of the PG hierarchy should it detect an issue.
	 *
	 * If it returns anything other than VALID or REPAIRED, an
	 * unrecoverable error has occurred, and we cannot proceed.
	 */
	lineage_status = pg_cmt_lineage_validate(cpu_cmt_hier, &levels, pgdata);
	if ((lineage_status != CMT_LINEAGE_VALID) &&
	    (lineage_status != CMT_LINEAGE_REPAIRED)) {
		/*
		 * In the case of an unrecoverable error where CMT scheduling
		 * has been disabled, assert that the under construction CPU's
		 * PG data has an empty CMT load balancing lineage.
		 */
		ASSERT((cmt_sched_disabled == 0) ||
		    (GROUP_SIZE(&(pgdata->cmt_pgs)) == 0));
		return;
	}

	/*
	 * For existing PGs in the lineage, verify that the parent is
	 * correct, as the generation in the lineage may have changed
	 * as a result of the sorting. Start the traversal at the top
	 * of the lineage, moving down.
	 */
	for (level = levels - 1; level >= 0; ) {
		int reorg;

		reorg = 0;
		pg = cpu_cmt_hier[level];

		/*
		 * Promote PGs at an incorrect generation into place.
		 */
		while (pg->cmt_parent &&
		    pg->cmt_parent != cpu_cmt_hier[level + 1]) {
			cmt_hier_promote(pg, pgdata);
			reorg++;
		}
		if (reorg > 0)
			level = levels - 1;
		else
			level--;
	}

	/*
	 * For each of the PGs in the CPU's lineage:
	 *	- Add an entry in the CPU sorted CMT PG group
	 *	  which is used for top down CMT load balancing
	 *	- Tie the PG into the CMT hierarchy by connecting
	 *	  it to it's parent and siblings.
	 */
	for (level = 0; level < levels; level++) {
		uint_t		children;
		int		err;

		pg = cpu_cmt_hier[level];
		err = group_add_at(cmt_pgs, pg, levels - level - 1);
		ASSERT(err == 0);

		if (level == 0)
			pgdata->cmt_lineage = (pg_t *)pg;

		if (pg->cmt_siblings != NULL) {
			/* Already initialized */
			ASSERT(pg->cmt_parent == NULL ||
			    pg->cmt_parent == cpu_cmt_hier[level + 1]);
			ASSERT(pg->cmt_siblings == &lgrp->cl_pgs ||
			    ((pg->cmt_parent != NULL) &&
			    pg->cmt_siblings == pg->cmt_parent->cmt_children));
			continue;
		}

		if ((level + 1) == levels) {
			pg->cmt_parent = NULL;

			pg->cmt_siblings = &lgrp->cl_pgs;
			children = ++lgrp->cl_npgs;
			if (cmt_root != lgrp)
				cmt_root->cl_npgs++;
		} else {
			pg->cmt_parent = cpu_cmt_hier[level + 1];

			/*
			 * A good parent keeps track of their children.
			 * The parent's children group is also the PG's
			 * siblings.
			 */
			if (pg->cmt_parent->cmt_children == NULL) {
				pg->cmt_parent->cmt_children =
				    kmem_zalloc(sizeof (group_t), KM_SLEEP);
				group_create(pg->cmt_parent->cmt_children);
			}
			pg->cmt_siblings = pg->cmt_parent->cmt_children;
			children = ++pg->cmt_parent->cmt_nchildren;
		}

		group_expand(pg->cmt_siblings, children);
		group_expand(&cmt_root->cl_pgs, cmt_root->cl_npgs);
	}

	/*
	 * Cache the chip and core IDs in the cpu_t->cpu_physid structure
	 * for fast lookups later.
	 */
	if (cp->cpu_physid) {
		cp->cpu_physid->cpu_chipid =
		    pg_plat_hw_instance_id(cp, PGHW_CHIP);
		cp->cpu_physid->cpu_coreid = pg_plat_get_core_id(cp);

		/*
		 * If this cpu has a PG representing shared cache, then set
		 * cpu_cacheid to that PG's logical id
		 */
		if (pg_cache)
			cp->cpu_physid->cpu_cacheid = pg_cache->pg_id;
	}

	/* CPU0 only initialization */
	if (is_cpu0) {
		is_cpu0 = 0;
		cpu0_lgrp = lgrp;
	}

}

/*
 * Class callback when a CPU is leaving the system (deletion)
 *
 * "pgdata" is a reference to the CPU's PG data to be deconstructed.
 *
 * cp->cpu_pg is used by the dispatcher to access the CPU's PG data
 * references a "bootstrap" structure across this function's invocation.
 * pg_cmt_cpu_fini() and the routines it calls must be careful to operate only
 * on the "pgdata" argument, and not cp->cpu_pg.
 */
static void
pg_cmt_cpu_fini(cpu_t *cp, cpu_pg_t *pgdata)
{
	group_iter_t	i;
	pg_cmt_t	*pg;
	group_t		*pgs, *cmt_pgs;
	lgrp_handle_t	lgrp_handle;
	cmt_lgrp_t	*lgrp;

	if (cmt_sched_disabled)
		return;

	ASSERT(pg_cpu_is_bootstrapped(cp));

	pgs = &pgdata->pgs;
	cmt_pgs = &pgdata->cmt_pgs;

	/*
	 * Find the lgroup that encapsulates this CPU's CMT hierarchy
	 */
	lgrp_handle = lgrp_plat_cpu_to_hand(cp->cpu_id);

	lgrp = pg_cmt_find_lgrp(lgrp_handle);
	if (ncpus == 1 && lgrp != cpu0_lgrp) {
		/*
		 * One might wonder how we could be deconfiguring the
		 * only CPU in the system.
		 *
		 * On Starcat systems when null_proc_lpa is detected,
		 * the boot CPU (which is already configured into a leaf
		 * lgroup), is moved into the root lgroup. This is done by
		 * deconfiguring it from both lgroups and processor
		 * groups), and then later reconfiguring it back in.  This
		 * call to pg_cmt_cpu_fini() is part of that deconfiguration.
		 *
		 * This special case is detected by noting that the platform
		 * has changed the CPU's lgrp affiliation (since it now
		 * belongs in the root). In this case, use the cmt_lgrp_t
		 * cached for the boot CPU, since this is what needs to be
		 * torn down.
		 */
		lgrp = cpu0_lgrp;
	}

	ASSERT(lgrp != NULL);

	/*
	 * First, clean up anything load balancing specific for each of
	 * the CPU's PGs that participated in CMT load balancing
	 */
	pg = (pg_cmt_t *)pgdata->cmt_lineage;
	while (pg != NULL) {

		((pghw_t *)pg)->pghw_generation++;

		/*
		 * Remove the PG from the CPU's load balancing lineage
		 */
		(void) group_remove(cmt_pgs, pg, GRP_RESIZE);

		/*
		 * If it's about to become empty, destroy it's children
		 * group, and remove it's reference from it's siblings.
		 * This is done here (rather than below) to avoid removing
		 * our reference from a PG that we just eliminated.
		 */
		if (GROUP_SIZE(&((pg_t *)pg)->pg_cpus) == 1) {
			if (pg->cmt_children != NULL)
				group_destroy(pg->cmt_children);
			if (pg->cmt_siblings != NULL) {
				if (pg->cmt_siblings == &lgrp->cl_pgs)
					lgrp->cl_npgs--;
				else
					pg->cmt_parent->cmt_nchildren--;
			}
		}
		pg = pg->cmt_parent;
	}
	ASSERT(GROUP_SIZE(cmt_pgs) == 0);

	/*
	 * Now that the load balancing lineage updates have happened,
	 * remove the CPU from all it's PGs (destroying any that become
	 * empty).
	 */
	group_iter_init(&i);
	while ((pg = group_iterate(pgs, &i)) != NULL) {
		if (IS_CMT_PG(pg) == 0)
			continue;

		pg_cpu_delete((pg_t *)pg, cp, pgdata);
		/*
		 * Deleting the CPU from the PG changes the CPU's
		 * PG group over which we are actively iterating
		 * Re-initialize the iteration
		 */
		group_iter_init(&i);

		if (GROUP_SIZE(&((pg_t *)pg)->pg_cpus) == 0) {

			/*
			 * The PG has become zero sized, so destroy it.
			 */
			group_destroy(&pg->cmt_cpus_actv);
			bitset_fini(&pg->cmt_cpus_actv_set);
			pghw_fini((pghw_t *)pg);

			pg_destroy((pg_t *)pg);
		}
	}
}

/*
 * Class callback when a CPU is entering a cpu partition
 */
static void
pg_cmt_cpupart_in(cpu_t *cp, cpupart_t *pp)
{
	group_t		*pgs;
	pg_t		*pg;
	group_iter_t	i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cmt_sched_disabled)
		return;

	pgs = &cp->cpu_pg->pgs;

	/*
	 * Ensure that the new partition's PG bitset
	 * is large enough for all CMT PG's to which cp
	 * belongs
	 */
	group_iter_init(&i);
	while ((pg = group_iterate(pgs, &i)) != NULL) {
		if (IS_CMT_PG(pg) == 0)
			continue;

		if (bitset_capacity(&pp->cp_cmt_pgs) <= pg->pg_id)
			bitset_resize(&pp->cp_cmt_pgs, pg->pg_id + 1);
	}
}

/*
 * Class callback when a CPU is actually moving partitions
 */
static void
pg_cmt_cpupart_move(cpu_t *cp, cpupart_t *oldpp, cpupart_t *newpp)
{
	cpu_t		*cpp;
	group_t		*pgs;
	pg_t		*pg;
	group_iter_t	pg_iter;
	pg_cpu_itr_t	cpu_iter;
	boolean_t	found;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cmt_sched_disabled)
		return;

	pgs = &cp->cpu_pg->pgs;
	group_iter_init(&pg_iter);

	/*
	 * Iterate over the CPUs CMT PGs
	 */
	while ((pg = group_iterate(pgs, &pg_iter)) != NULL) {

		if (IS_CMT_PG(pg) == 0)
			continue;

		/*
		 * Add the PG to the bitset in the new partition.
		 */
		bitset_add(&newpp->cp_cmt_pgs, pg->pg_id);

		/*
		 * Remove the PG from the bitset in the old partition
		 * if the last of the PG's CPUs have left.
		 */
		found = B_FALSE;
		PG_CPU_ITR_INIT(pg, cpu_iter);
		while ((cpp = pg_cpu_next(&cpu_iter)) != NULL) {
			if (cpp == cp)
				continue;
			if (CPU_ACTIVE(cpp) &&
			    cpp->cpu_part->cp_id == oldpp->cp_id) {
				found = B_TRUE;
				break;
			}
		}
		if (!found)
			bitset_del(&cp->cpu_part->cp_cmt_pgs, pg->pg_id);
	}
}

/*
 * Class callback when a CPU becomes active (online)
 *
 * This is called in a context where CPUs are paused
 */
static void
pg_cmt_cpu_active(cpu_t *cp)
{
	int		err;
	group_iter_t	i;
	pg_cmt_t	*pg;
	group_t		*pgs;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cmt_sched_disabled)
		return;

	pgs = &cp->cpu_pg->pgs;
	group_iter_init(&i);

	/*
	 * Iterate over the CPU's PGs
	 */
	while ((pg = group_iterate(pgs, &i)) != NULL) {

		if (IS_CMT_PG(pg) == 0)
			continue;

		/*
		 * Move to the next generation since topology is changing
		 */
		((pghw_t *)pg)->pghw_generation++;

		err = group_add(&pg->cmt_cpus_actv, cp, GRP_NORESIZE);
		ASSERT(err == 0);

		/*
		 * If this is the first active CPU in the PG, and it
		 * represents a hardware sharing relationship over which
		 * CMT load balancing is performed, add it as a candidate
		 * for balancing with it's siblings.
		 */
		if (GROUP_SIZE(&pg->cmt_cpus_actv) == 1 &&
		    (pg->cmt_policy & (CMT_BALANCE | CMT_COALESCE))) {
			err = group_add(pg->cmt_siblings, pg, GRP_NORESIZE);
			ASSERT(err == 0);

			/*
			 * If this is a top level PG, add it as a balancing
			 * candidate when balancing within the root lgroup.
			 */
			if (pg->cmt_parent == NULL &&
			    pg->cmt_siblings != &cmt_root->cl_pgs) {
				err = group_add(&cmt_root->cl_pgs, pg,
				    GRP_NORESIZE);
				ASSERT(err == 0);
			}
		}

		/*
		 * Notate the CPU in the PGs active CPU bitset.
		 * Also notate the PG as being active in it's associated
		 * partition
		 */
		bitset_add(&pg->cmt_cpus_actv_set, cp->cpu_seqid);
		bitset_add(&cp->cpu_part->cp_cmt_pgs, ((pg_t *)pg)->pg_id);
	}
}

/*
 * Class callback when a CPU goes inactive (offline)
 *
 * This is called in a context where CPUs are paused
 */
static void
pg_cmt_cpu_inactive(cpu_t *cp)
{
	int		err;
	group_t		*pgs;
	pg_cmt_t	*pg;
	cpu_t		*cpp;
	group_iter_t	i;
	pg_cpu_itr_t	cpu_itr;
	boolean_t	found;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cmt_sched_disabled)
		return;

	pgs = &cp->cpu_pg->pgs;
	group_iter_init(&i);

	while ((pg = group_iterate(pgs, &i)) != NULL) {

		if (IS_CMT_PG(pg) == 0)
			continue;

		/*
		 * Move to the next generation since topology is changing
		 */
		((pghw_t *)pg)->pghw_generation++;

		/*
		 * Remove the CPU from the CMT PGs active CPU group
		 * bitmap
		 */
		err = group_remove(&pg->cmt_cpus_actv, cp, GRP_NORESIZE);
		ASSERT(err == 0);

		bitset_del(&pg->cmt_cpus_actv_set, cp->cpu_seqid);

		/*
		 * If there are no more active CPUs in this PG over which
		 * load was balanced, remove it as a balancing candidate.
		 */
		if (GROUP_SIZE(&pg->cmt_cpus_actv) == 0 &&
		    (pg->cmt_policy & (CMT_BALANCE | CMT_COALESCE))) {
			err = group_remove(pg->cmt_siblings, pg, GRP_NORESIZE);
			ASSERT(err == 0);

			if (pg->cmt_parent == NULL &&
			    pg->cmt_siblings != &cmt_root->cl_pgs) {
				err = group_remove(&cmt_root->cl_pgs, pg,
				    GRP_NORESIZE);
				ASSERT(err == 0);
			}
		}

		/*
		 * Assert the number of active CPUs does not exceed
		 * the total number of CPUs in the PG
		 */
		ASSERT(GROUP_SIZE(&pg->cmt_cpus_actv) <=
		    GROUP_SIZE(&((pg_t *)pg)->pg_cpus));

		/*
		 * Update the PG bitset in the CPU's old partition
		 */
		found = B_FALSE;
		PG_CPU_ITR_INIT(pg, cpu_itr);
		while ((cpp = pg_cpu_next(&cpu_itr)) != NULL) {
			if (cpp == cp)
				continue;
			if (CPU_ACTIVE(cpp) &&
			    cpp->cpu_part->cp_id == cp->cpu_part->cp_id) {
				found = B_TRUE;
				break;
			}
		}
		if (!found) {
			bitset_del(&cp->cpu_part->cp_cmt_pgs,
			    ((pg_t *)pg)->pg_id);
		}
	}
}

/*
 * Return non-zero if the CPU belongs in the given PG
 */
static int
pg_cmt_cpu_belongs(pg_t *pg, cpu_t *cp)
{
	cpu_t	*pg_cpu;

	pg_cpu = GROUP_ACCESS(&pg->pg_cpus, 0);

	ASSERT(pg_cpu != NULL);

	/*
	 * The CPU belongs if, given the nature of the hardware sharing
	 * relationship represented by the PG, the CPU has that
	 * relationship with some other CPU already in the PG
	 */
	if (pg_plat_cpus_share(cp, pg_cpu, ((pghw_t *)pg)->pghw_hw))
		return (1);

	return (0);
}

/*
 * Sort the CPUs CMT hierarchy, where "size" is the number of levels.
 */
static void
pg_cmt_hier_sort(pg_cmt_t **hier, int size)
{
	int		i, j, inc, sz;
	int		start, end;
	pg_t		*tmp;
	pg_t		**h = (pg_t **)hier;

	/*
	 * First sort by number of CPUs
	 */
	inc = size / 2;
	while (inc > 0) {
		for (i = inc; i < size; i++) {
			j = i;
			tmp = h[i];
			while ((j >= inc) &&
			    (PG_NUM_CPUS(h[j - inc]) > PG_NUM_CPUS(tmp))) {
				h[j] = h[j - inc];
				j = j - inc;
			}
			h[j] = tmp;
		}
		if (inc == 2)
			inc = 1;
		else
			inc = (inc * 5) / 11;
	}

	/*
	 * Break ties by asking the platform.
	 * Determine if h[i] outranks h[i + 1] and if so, swap them.
	 */
	for (start = 0; start < size; start++) {

		/*
		 * Find various contiguous sets of elements,
		 * in the array, with the same number of cpus
		 */
		end = start;
		sz = PG_NUM_CPUS(h[start]);
		while ((end < size) && (sz == PG_NUM_CPUS(h[end])))
			end++;
		/*
		 * Sort each such set of the array by rank
		 */
		for (i = start + 1; i < end; i++) {
			j = i - 1;
			tmp = h[i];
			while (j >= start &&
			    pg_cmt_hier_rank(hier[j],
			    (pg_cmt_t *)tmp) == hier[j]) {
				h[j + 1] = h[j];
				j--;
			}
			h[j + 1] = tmp;
		}
	}
}

/*
 * Return a cmt_lgrp_t * given an lgroup handle.
 */
static cmt_lgrp_t *
pg_cmt_find_lgrp(lgrp_handle_t hand)
{
	cmt_lgrp_t	*lgrp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	lgrp = cmt_lgrps;
	while (lgrp != NULL) {
		if (lgrp->cl_hand == hand)
			break;
		lgrp = lgrp->cl_next;
	}
	return (lgrp);
}

/*
 * Create a cmt_lgrp_t with the specified handle.
 */
static cmt_lgrp_t *
pg_cmt_lgrp_create(lgrp_handle_t hand)
{
	cmt_lgrp_t	*lgrp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	lgrp = kmem_zalloc(sizeof (cmt_lgrp_t), KM_SLEEP);

	lgrp->cl_hand = hand;
	lgrp->cl_npgs = 0;
	lgrp->cl_next = cmt_lgrps;
	cmt_lgrps = lgrp;
	group_create(&lgrp->cl_pgs);

	return (lgrp);
}

/*
 * Interfaces to enable and disable power aware dispatching
 * The caller must be holding cpu_lock.
 *
 * Return 0 on success and -1 on failure.
 */
int
cmt_pad_enable(pghw_type_t type)
{
	group_t		*hwset;
	group_iter_t	iter;
	pg_cmt_t	*pg;

	ASSERT(PGHW_IS_PM_DOMAIN(type));
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cmt_sched_disabled == 1)
		return (-1);

	if ((hwset = pghw_set_lookup(type)) == NULL ||
	    cmt_hw_blacklisted[type]) {
		/*
		 * Unable to find any instances of the specified type
		 * of power domain, or the power domains have been blacklisted.
		 */
		return (-1);
	}

	/*
	 * Iterate over the power domains, setting the default dispatcher
	 * policy for power/performance optimization.
	 *
	 * Simply setting the policy isn't enough in the case where the power
	 * domain is an only child of another PG. Because the dispatcher walks
	 * the PG hierarchy in a top down fashion, the higher up PG's policy
	 * will dominate. So promote the power domain above it's parent if both
	 * PG and it's parent have the same CPUs to ensure it's policy
	 * dominates.
	 */
	group_iter_init(&iter);
	while ((pg = group_iterate(hwset, &iter)) != NULL) {
		/*
		 * If the power domain is an only child to a parent
		 * not implementing the same policy, promote the child
		 * above the parent to activate the policy.
		 */
		pg->cmt_policy = pg_cmt_policy(((pghw_t *)pg)->pghw_hw);
		while ((pg->cmt_parent != NULL) &&
		    (pg->cmt_parent->cmt_policy != pg->cmt_policy) &&
		    (PG_NUM_CPUS((pg_t *)pg) ==
		    PG_NUM_CPUS((pg_t *)pg->cmt_parent))) {
			cmt_hier_promote(pg, NULL);
		}
	}

	return (0);
}

int
cmt_pad_disable(pghw_type_t type)
{
	group_t		*hwset;
	group_iter_t	iter;
	pg_cmt_t	*pg;
	pg_cmt_t	*child;

	ASSERT(PGHW_IS_PM_DOMAIN(type));
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cmt_sched_disabled == 1)
		return (-1);

	if ((hwset = pghw_set_lookup(type)) == NULL) {
		/*
		 * Unable to find any instances of the specified type of
		 * power domain.
		 */
		return (-1);
	}
	/*
	 * Iterate over the power domains, setting the default dispatcher
	 * policy for performance optimization (load balancing).
	 */
	group_iter_init(&iter);
	while ((pg = group_iterate(hwset, &iter)) != NULL) {

		/*
		 * If the power domain has an only child that implements
		 * policy other than load balancing, promote the child
		 * above the power domain to ensure it's policy dominates.
		 */
		if (pg->cmt_children != NULL &&
		    GROUP_SIZE(pg->cmt_children) == 1) {
			child = GROUP_ACCESS(pg->cmt_children, 0);
			if ((child->cmt_policy & CMT_BALANCE) == 0) {
				cmt_hier_promote(child, NULL);
			}
		}
		pg->cmt_policy = CMT_BALANCE;
	}
	return (0);
}

/* ARGSUSED */
static void
cmt_ev_thread_swtch(pg_t *pg, cpu_t *cp, hrtime_t now, kthread_t *old,
		    kthread_t *new)
{
	pg_cmt_t	*cmt_pg = (pg_cmt_t *)pg;

	if (old == cp->cpu_idle_thread) {
		atomic_inc_32(&cmt_pg->cmt_utilization);
	} else if (new == cp->cpu_idle_thread) {
		atomic_dec_32(&cmt_pg->cmt_utilization);
	}
}

/*
 * Macro to test whether a thread is currently runnable on a CPU in a PG.
 */
#define	THREAD_RUNNABLE_IN_PG(t, pg)					\
	((t)->t_state == TS_RUN &&					\
	    (t)->t_disp_queue->disp_cpu &&				\
	    bitset_in_set(&(pg)->cmt_cpus_actv_set,			\
	    (t)->t_disp_queue->disp_cpu->cpu_seqid))

static void
cmt_ev_thread_swtch_pwr(pg_t *pg, cpu_t *cp, hrtime_t now, kthread_t *old,
    kthread_t *new)
{
	pg_cmt_t	*cmt = (pg_cmt_t *)pg;
	cpupm_domain_t	*dom;
	uint32_t	u;

	if (old == cp->cpu_idle_thread) {
		ASSERT(new != cp->cpu_idle_thread);
		u = atomic_inc_32_nv(&cmt->cmt_utilization);
		if (u == 1) {
			/*
			 * Notify the CPU power manager that the domain
			 * is non-idle.
			 */
			dom = (cpupm_domain_t *)cmt->cmt_pg.pghw_handle;
			cpupm_utilization_event(cp, now, dom,
			    CPUPM_DOM_BUSY_FROM_IDLE);
		}
	} else if (new == cp->cpu_idle_thread) {
		ASSERT(old != cp->cpu_idle_thread);
		u = atomic_dec_32_nv(&cmt->cmt_utilization);
		if (u == 0) {
			/*
			 * The domain is idle, notify the CPU power
			 * manager.
			 *
			 * Avoid notifying if the thread is simply migrating
			 * between CPUs in the domain.
			 */
			if (!THREAD_RUNNABLE_IN_PG(old, cmt)) {
				dom = (cpupm_domain_t *)cmt->cmt_pg.pghw_handle;
				cpupm_utilization_event(cp, now, dom,
				    CPUPM_DOM_IDLE_FROM_BUSY);
			}
		}
	}
}

/* ARGSUSED */
static void
cmt_ev_thread_remain_pwr(pg_t *pg, cpu_t *cp, kthread_t *t)
{
	pg_cmt_t	*cmt = (pg_cmt_t *)pg;
	cpupm_domain_t	*dom;

	dom = (cpupm_domain_t *)cmt->cmt_pg.pghw_handle;
	cpupm_utilization_event(cp, (hrtime_t)0, dom, CPUPM_DOM_REMAIN_BUSY);
}

/*
 * Return the name of the CMT scheduling policy
 * being implemented across this PG
 */
static char *
pg_cmt_policy_name(pg_t *pg)
{
	pg_cmt_policy_t policy;

	policy = ((pg_cmt_t *)pg)->cmt_policy;

	if (policy & CMT_AFFINITY) {
		if (policy & CMT_BALANCE)
			return ("Load Balancing & Affinity");
		else if (policy & CMT_COALESCE)
			return ("Load Coalescence & Affinity");
		else
			return ("Affinity");
	} else {
		if (policy & CMT_BALANCE)
			return ("Load Balancing");
		else if (policy & CMT_COALESCE)
			return ("Load Coalescence");
		else
			return ("None");
	}
}

/*
 * Prune PG, and all other instances of PG's hardware sharing relationship
 * from the CMT PG hierarchy.
 *
 * This routine operates on the CPU specific processor group data (for the CPUs
 * in the PG being pruned), and may be invoked from a context where one CPU's
 * PG data is under construction. In this case the argument "pgdata", if not
 * NULL, is a reference to the CPU's under-construction PG data.
 */
static int
pg_cmt_prune(pg_cmt_t *pg_bad, pg_cmt_t **lineage, int *sz, cpu_pg_t *pgdata)
{
	group_t		*hwset, *children;
	int		i, j, r, size = *sz;
	group_iter_t	hw_iter, child_iter;
	pg_cpu_itr_t	cpu_iter;
	pg_cmt_t	*pg, *child;
	cpu_t		*cpu;
	int		cap_needed;
	pghw_type_t	hw;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Inform pghw layer that this PG is pruned.
	 */
	pghw_cmt_fini((pghw_t *)pg_bad);

	hw = ((pghw_t *)pg_bad)->pghw_hw;

	if (hw == PGHW_POW_ACTIVE) {
		cmn_err(CE_NOTE, "!Active CPUPM domain groups look suspect. "
		    "Event Based CPUPM Unavailable");
	} else if (hw == PGHW_POW_IDLE) {
		cmn_err(CE_NOTE, "!Idle CPUPM domain groups look suspect. "
		    "Dispatcher assisted CPUPM disabled.");
	}

	/*
	 * Find and eliminate the PG from the lineage.
	 */
	for (i = 0; i < size; i++) {
		if (lineage[i] == pg_bad) {
			for (j = i; j < size - 1; j++)
				lineage[j] = lineage[j + 1];
			*sz = size - 1;
			break;
		}
	}

	/*
	 * We'll prune all instances of the hardware sharing relationship
	 * represented by pg. But before we do that (and pause CPUs) we need
	 * to ensure the hierarchy's groups are properly sized.
	 */
	hwset = pghw_set_lookup(hw);

	/*
	 * Blacklist the hardware so future processor groups of this type won't
	 * participate in CMT thread placement.
	 *
	 * XXX
	 * For heterogeneous system configurations, this might be overkill.
	 * We may only need to blacklist the illegal PGs, and other instances
	 * of this hardware sharing relationship may be ok.
	 */
	cmt_hw_blacklisted[hw] = 1;

	/*
	 * For each of the PGs being pruned, ensure sufficient capacity in
	 * the siblings set for the PG's children
	 */
	group_iter_init(&hw_iter);
	while ((pg = group_iterate(hwset, &hw_iter)) != NULL) {
		/*
		 * PG is being pruned, but if it is bringing up more than
		 * one child, ask for more capacity in the siblings group.
		 */
		cap_needed = 0;
		if (pg->cmt_children &&
		    GROUP_SIZE(pg->cmt_children) > 1) {
			cap_needed = GROUP_SIZE(pg->cmt_children) - 1;

			group_expand(pg->cmt_siblings,
			    GROUP_SIZE(pg->cmt_siblings) + cap_needed);

			/*
			 * If this is a top level group, also ensure the
			 * capacity in the root lgrp level CMT grouping.
			 */
			if (pg->cmt_parent == NULL &&
			    pg->cmt_siblings != &cmt_root->cl_pgs) {
				group_expand(&cmt_root->cl_pgs,
				    GROUP_SIZE(&cmt_root->cl_pgs) + cap_needed);
				cmt_root->cl_npgs += cap_needed;
			}
		}
	}

	/*
	 * We're operating on the PG hierarchy. Pause CPUs to ensure
	 * exclusivity with respect to the dispatcher.
	 */
	pause_cpus(NULL, NULL);

	/*
	 * Prune all PG instances of the hardware sharing relationship
	 * represented by pg.
	 */
	group_iter_init(&hw_iter);
	while ((pg = group_iterate(hwset, &hw_iter)) != NULL) {

		/*
		 * Remove PG from it's group of siblings, if it's there.
		 */
		if (pg->cmt_siblings) {
			(void) group_remove(pg->cmt_siblings, pg, GRP_NORESIZE);
		}
		if (pg->cmt_parent == NULL &&
		    pg->cmt_siblings != &cmt_root->cl_pgs) {
			(void) group_remove(&cmt_root->cl_pgs, pg,
			    GRP_NORESIZE);
		}

		/*
		 * Indicate that no CMT policy will be implemented across
		 * this PG.
		 */
		pg->cmt_policy = CMT_NO_POLICY;

		/*
		 * Move PG's children from it's children set to it's parent's
		 * children set. Note that the parent's children set, and PG's
		 * siblings set are the same thing.
		 *
		 * Because we are iterating over the same group that we are
		 * operating on (removing the children), first add all of PG's
		 * children to the parent's children set, and once we are done
		 * iterating, empty PG's children set.
		 */
		if (pg->cmt_children != NULL) {
			children = pg->cmt_children;

			group_iter_init(&child_iter);
			while ((child = group_iterate(children, &child_iter))
			    != NULL) {
				if (pg->cmt_siblings != NULL) {
					r = group_add(pg->cmt_siblings, child,
					    GRP_NORESIZE);
					ASSERT(r == 0);

					if (pg->cmt_parent == NULL &&
					    pg->cmt_siblings !=
					    &cmt_root->cl_pgs) {
						r = group_add(&cmt_root->cl_pgs,
						    child, GRP_NORESIZE);
						ASSERT(r == 0);
					}
				}
			}
			group_empty(pg->cmt_children);
		}

		/*
		 * Reset the callbacks to the defaults
		 */
		pg_callback_set_defaults((pg_t *)pg);

		/*
		 * Update all the CPU lineages in each of PG's CPUs
		 */
		PG_CPU_ITR_INIT(pg, cpu_iter);
		while ((cpu = pg_cpu_next(&cpu_iter)) != NULL) {
			pg_cmt_t	*cpu_pg;
			group_iter_t	liter;	/* Iterator for the lineage */
			cpu_pg_t	*cpd;	/* CPU's PG data */

			/*
			 * The CPU's lineage is under construction still
			 * references the bootstrap CPU PG data structure.
			 */
			if (pg_cpu_is_bootstrapped(cpu))
				cpd = pgdata;
			else
				cpd = cpu->cpu_pg;

			/*
			 * Iterate over the CPU's PGs updating the children
			 * of the PG being promoted, since they have a new
			 * parent and siblings set.
			 */
			group_iter_init(&liter);
			while ((cpu_pg = group_iterate(&cpd->pgs,
			    &liter)) != NULL) {
				if (cpu_pg->cmt_parent == pg) {
					cpu_pg->cmt_parent = pg->cmt_parent;
					cpu_pg->cmt_siblings = pg->cmt_siblings;
				}
			}

			/*
			 * Update the CPU's lineages
			 *
			 * Remove the PG from the CPU's group used for CMT
			 * scheduling.
			 */
			(void) group_remove(&cpd->cmt_pgs, pg, GRP_NORESIZE);
		}
	}
	start_cpus();
	return (0);
}

/*
 * Disable CMT scheduling
 */
static void
pg_cmt_disable(void)
{
	cpu_t		*cpu;

	ASSERT(MUTEX_HELD(&cpu_lock));

	pause_cpus(NULL, NULL);
	cpu = cpu_list;

	do {
		if (cpu->cpu_pg)
			group_empty(&cpu->cpu_pg->cmt_pgs);
	} while ((cpu = cpu->cpu_next) != cpu_list);

	cmt_sched_disabled = 1;
	start_cpus();
	cmn_err(CE_NOTE, "!CMT thread placement optimizations unavailable");
}

/*
 * CMT lineage validation
 *
 * This routine is invoked by pg_cmt_cpu_init() to validate the integrity
 * of the PGs in a CPU's lineage. This is necessary because it's possible that
 * some groupings (power domain groupings in particular) may be defined by
 * sources that are buggy (e.g. BIOS bugs). In such cases, it may not be
 * possible to integrate those groupings into the CMT PG hierarchy, if doing
 * so would violate the subset invariant of the hierarchy, which says that
 * a PG must be subset of its parent (if it has one).
 *
 * pg_cmt_lineage_validate()'s purpose is to detect grouping definitions that
 * would result in a violation of this invariant. If a violation is found,
 * and the PG is of a grouping type who's definition is known to originate from
 * suspect sources (BIOS), then pg_cmt_prune() will be invoked to prune the
 * PG (and all other instances PG's sharing relationship type) from the CMT
 * hierarchy. Further, future instances of that sharing relationship type won't
 * be added. If the grouping definition doesn't originate from suspect
 * sources, then pg_cmt_disable() will be invoked to log an error, and disable
 * CMT scheduling altogether.
 *
 * This routine is invoked after the CPU has been added to the PGs in which
 * it belongs, but before those PGs have been added to (or had their place
 * adjusted in) the CMT PG hierarchy.
 *
 * The first argument is the CPUs PG lineage (essentially an array of PGs in
 * which the CPU belongs) that has already been sorted in ascending order
 * by CPU count. Some of the PGs in the CPUs lineage may already have other
 * CPUs in them, and have already been integrated into the CMT hierarchy.
 *
 * The addition of this new CPU to these pre-existing PGs means that those
 * PGs may need to be promoted up in the hierarchy to satisfy the subset
 * invariant. In additon to testing the subset invariant for the lineage,
 * this routine also verifies that the addition of the new CPU to the
 * existing PGs wouldn't cause the subset invariant to be violated in
 * the exiting lineages.
 *
 * This routine will normally return one of the following:
 * CMT_LINEAGE_VALID - There were no problems detected with the lineage.
 * CMT_LINEAGE_REPAIRED - Problems were detected, but repaired via pruning.
 *
 * Otherwise, this routine will return a value indicating which error it
 * was unable to recover from (and set cmt_lineage_status along the way).
 *
 * This routine operates on the CPU specific processor group data (for the CPU
 * whose lineage is being validated), which is under-construction.
 * "pgdata" is a reference to the CPU's under-construction PG data.
 * This routine must be careful to operate only on "pgdata", and not cp->cpu_pg.
 */
static cmt_lineage_validation_t
pg_cmt_lineage_validate(pg_cmt_t **lineage, int *sz, cpu_pg_t *pgdata)
{
	int		i, j, size;
	pg_cmt_t	*pg, *pg_next, *pg_bad, *pg_tmp, *parent;
	cpu_t		*cp;
	pg_cpu_itr_t	cpu_iter;
	lgrp_handle_t	lgrp;

	ASSERT(MUTEX_HELD(&cpu_lock));

revalidate:
	size = *sz;
	pg_bad = NULL;
	lgrp = LGRP_NULL_HANDLE;
	for (i = 0; i < size; i++) {

		pg = lineage[i];
		if (i < size - 1)
			pg_next = lineage[i + 1];
		else
			pg_next = NULL;

		/*
		 * We assume that the lineage has already been sorted
		 * by the number of CPUs. In fact, we depend on it.
		 */
		ASSERT(pg_next == NULL ||
		    (PG_NUM_CPUS((pg_t *)pg) <= PG_NUM_CPUS((pg_t *)pg_next)));

		/*
		 * The CPUs PG lineage was passed as the first argument to
		 * this routine and contains the sorted list of the CPU's
		 * PGs. Ultimately, the ordering of the PGs in that list, and
		 * the ordering as traversed by the cmt_parent list must be
		 * the same. PG promotion will be used as the mechanism to
		 * achieve this, but first we need to look for cases where
		 * promotion will be necessary, and validate that will be
		 * possible without violating the subset invarient described
		 * above.
		 *
		 * Since the PG topology is in the middle of being changed, we
		 * need to check whether the PG's existing parent (if any) is
		 * part of this CPU's lineage (and therefore should contain
		 * the new CPU). If not, it means that the addition of the
		 * new CPU should have made this PG have more CPUs than its
		 * parent (and other ancestors not in the same lineage) and
		 * will need to be promoted into place.
		 *
		 * We need to verify all of this to defend against a buggy
		 * BIOS giving bad power domain CPU groupings. Sigh.
		 */
		parent = pg->cmt_parent;
		while (parent != NULL) {
			/*
			 * Determine if the parent/ancestor is in this lineage
			 */
			pg_tmp = NULL;
			for (j = 0; (j < size) && (pg_tmp != parent); j++) {
				pg_tmp = lineage[j];
			}
			if (pg_tmp == parent) {
				/*
				 * It's in the lineage. The concentricity
				 * checks will handle the rest.
				 */
				break;
			}
			/*
			 * If it is not in the lineage, PG will eventually
			 * need to be promoted above it. Verify the ancestor
			 * is a proper subset. There is still an error if
			 * the ancestor has the same number of CPUs as PG,
			 * since that would imply it should be in the lineage,
			 * and we already know it isn't.
			 */
			if (PG_NUM_CPUS((pg_t *)parent) >=
			    PG_NUM_CPUS((pg_t *)pg)) {
				/*
				 * Not a proper subset if the parent/ancestor
				 * has the same or more CPUs than PG.
				 */
				cmt_lineage_status = CMT_LINEAGE_NON_PROMOTABLE;
				goto handle_error;
			}
			parent = parent->cmt_parent;
		}

		/*
		 * Walk each of the CPUs in the PGs group and perform
		 * consistency checks along the way.
		 */
		PG_CPU_ITR_INIT((pg_t *)pg, cpu_iter);
		while ((cp = pg_cpu_next(&cpu_iter)) != NULL) {
			/*
			 * Verify that there aren't any CPUs contained in PG
			 * that the next PG in the lineage (which is larger
			 * or same size) doesn't also contain.
			 */
			if (pg_next != NULL &&
			    pg_cpu_find((pg_t *)pg_next, cp) == B_FALSE) {
				cmt_lineage_status = CMT_LINEAGE_NON_CONCENTRIC;
				goto handle_error;
			}

			/*
			 * Verify that all the CPUs in the PG are in the same
			 * lgroup.
			 */
			if (lgrp == LGRP_NULL_HANDLE) {
				lgrp = lgrp_plat_cpu_to_hand(cp->cpu_id);
			} else if (lgrp_plat_cpu_to_hand(cp->cpu_id) != lgrp) {
				cmt_lineage_status = CMT_LINEAGE_PG_SPANS_LGRPS;
				goto handle_error;
			}
		}
	}

handle_error:
	/*
	 * Some of these validation errors can result when the CPU grouping
	 * information is derived from buggy sources (for example, incorrect
	 * ACPI tables on x86 systems).
	 *
	 * We'll try to recover in such cases by pruning out the illegal
	 * groupings from the PG hierarchy, which means that we won't optimize
	 * for those levels, but we will for the remaining ones.
	 */
	switch (cmt_lineage_status) {
	case CMT_LINEAGE_VALID:
	case CMT_LINEAGE_REPAIRED:
		break;
	case CMT_LINEAGE_PG_SPANS_LGRPS:
		/*
		 * We've detected a PG whose CPUs span lgroups.
		 *
		 * This isn't supported, as the dispatcher isn't allowed to
		 * to do CMT thread placement across lgroups, as this would
		 * conflict with policies implementing MPO thread affinity.
		 *
		 * If the PG is of a sharing relationship type known to
		 * legitimately span lgroups, specify that no CMT thread
		 * placement policy should be implemented, and prune the PG
		 * from the existing CMT PG hierarchy.
		 *
		 * Otherwise, fall though to the case below for handling.
		 */
		if (((pghw_t *)pg)->pghw_hw == PGHW_CHIP) {
			if (pg_cmt_prune(pg, lineage, sz, pgdata) == 0) {
				cmt_lineage_status = CMT_LINEAGE_REPAIRED;
				goto revalidate;
			}
		}
		/*LINTED*/
	case CMT_LINEAGE_NON_PROMOTABLE:
		/*
		 * We've detected a PG that already exists in another CPU's
		 * lineage that cannot cannot legally be promoted into place
		 * without breaking the invariants of the hierarchy.
		 */
		if (PG_CMT_HW_SUSPECT(((pghw_t *)pg)->pghw_hw)) {
			if (pg_cmt_prune(pg, lineage, sz, pgdata) == 0) {
				cmt_lineage_status = CMT_LINEAGE_REPAIRED;
				goto revalidate;
			}
		}
		/*
		 * Something went wrong trying to prune out the bad level.
		 * Disable CMT scheduling altogether.
		 */
		pg_cmt_disable();
		break;
	case CMT_LINEAGE_NON_CONCENTRIC:
		/*
		 * We've detected a non-concentric PG lineage, which means that
		 * there's a PG in the lineage that has CPUs that the next PG
		 * over in the lineage (which is the same size or larger)
		 * doesn't have.
		 *
		 * In this case, we examine the two PGs to see if either
		 * grouping is defined by potentially buggy sources.
		 *
		 * If one has less CPUs than the other, and contains CPUs
		 * not found in the parent, and it is an untrusted enumeration,
		 * then prune it. If both have the same number of CPUs, then
		 * prune the one that is untrusted.
		 *
		 * This process repeats until we have a concentric lineage,
		 * or we would have to prune out level derived from what we
		 * thought was a reliable source, in which case CMT scheduling
		 * is disabled altogether.
		 */
		if ((PG_NUM_CPUS((pg_t *)pg) < PG_NUM_CPUS((pg_t *)pg_next)) &&
		    (PG_CMT_HW_SUSPECT(((pghw_t *)pg)->pghw_hw))) {
			pg_bad = pg;
		} else if (PG_NUM_CPUS((pg_t *)pg) ==
		    PG_NUM_CPUS((pg_t *)pg_next)) {
			if (PG_CMT_HW_SUSPECT(((pghw_t *)pg_next)->pghw_hw)) {
				pg_bad = pg_next;
			} else if (PG_CMT_HW_SUSPECT(((pghw_t *)pg)->pghw_hw)) {
				pg_bad = pg;
			}
		}
		if (pg_bad) {
			if (pg_cmt_prune(pg_bad, lineage, sz, pgdata) == 0) {
				cmt_lineage_status = CMT_LINEAGE_REPAIRED;
				goto revalidate;
			}
		}
		/*
		 * Something went wrong trying to identify and/or prune out
		 * the bad level. Disable CMT scheduling altogether.
		 */
		pg_cmt_disable();
		break;
	default:
		/*
		 * If we're here, we've encountered a validation error for
		 * which we don't know how to recover. In this case, disable
		 * CMT scheduling altogether.
		 */
		cmt_lineage_status = CMT_LINEAGE_UNRECOVERABLE;
		pg_cmt_disable();
	}
	return (cmt_lineage_status);
}
