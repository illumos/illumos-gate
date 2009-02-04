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
 * optimized affinity and load balancing policies.
 *
 * Load balancing policy seeks to improve performance by minimizing
 * contention over shared processor resources / facilities, while the
 * affinity policies seek to improve cache and TLB utilization.
 *
 * The CMT PGs created by this class are already arranged into a
 * hierarchy (which is done in the pghw layer). To implement the top-down
 * CMT load balancing algorithm, the CMT PGs additionally maintain
 * parent, child and sibling hierarchy relationships.
 * Parent PGs always contain a superset of their children(s) resources,
 * each PG can have at most one parent, and siblings are the group of PGs
 * sharing the same parent.
 *
 * On NUMA systems, the CMT load balancing algorithm balances across the
 * CMT PGs within their respective lgroups. On UMA based system, there
 * exists a top level group of PGs to balance across. On NUMA systems multiple
 * top level groups are instantiated, where the top level balancing begins by
 * balancng across the CMT PGs within their respective (per lgroup) top level
 * groups.
 */
typedef struct cmt_lgrp {
	group_t		cl_pgs;		/* Top level group of active CMT PGs */
	int		cl_npgs;	/* # of top level PGs in the lgroup */
	lgrp_handle_t	cl_hand;	/* lgroup's platform handle */
	struct cmt_lgrp *cl_next;	/* next cmt_lgrp */
} cmt_lgrp_t;

static cmt_lgrp_t	*cmt_lgrps = NULL;	/* cmt_lgrps list head */
static cmt_lgrp_t	*cpu0_lgrp = NULL;	/* boot CPU's initial lgrp */
						/* used for null_proc_lpa */
static cmt_lgrp_t	*cmt_root = NULL;	/* Reference to root cmt pg */

static int		is_cpu0 = 1; /* true if this is boot CPU context */

/*
 * Set this to non-zero to disable CMT scheduling
 * This must be done via kmdb -d, as /etc/system will be too late
 */
static int		cmt_sched_disabled = 0;

static pg_cid_t		pg_cmt_class_id;		/* PG class id */

static pg_t		*pg_cmt_alloc();
static void		pg_cmt_free(pg_t *);
static void		pg_cmt_cpu_init(cpu_t *);
static void		pg_cmt_cpu_fini(cpu_t *);
static void		pg_cmt_cpu_active(cpu_t *);
static void		pg_cmt_cpu_inactive(cpu_t *);
static void		pg_cmt_cpupart_in(cpu_t *, cpupart_t *);
static void		pg_cmt_cpupart_move(cpu_t *, cpupart_t *, cpupart_t *);
static void		pg_cmt_hier_pack(void **, int);
static int		pg_cmt_cpu_belongs(pg_t *, cpu_t *);
static int		pg_cmt_hw(pghw_type_t);
static cmt_lgrp_t	*pg_cmt_find_lgrp(lgrp_handle_t);
static cmt_lgrp_t	*pg_cmt_lgrp_create(lgrp_handle_t);

/*
 * Macro to test if PG is managed by the CMT PG class
 */
#define	IS_CMT_PG(pg)	(((pg_t *)(pg))->pg_class->pgc_id == pg_cmt_class_id)

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
	PG_NRUN_UPDATE(cp, 1);
}

/*
 * Adjust the CMT load in the CMT PGs in which the CPU belongs
 * Note that "n" can be positive in the case of increasing
 * load, or negative in the case of decreasing load.
 */
void
pg_cmt_load(cpu_t *cp, int n)
{
	pg_cmt_t	*pg;

	pg = (pg_cmt_t *)cp->cpu_pg->cmt_lineage;
	while (pg != NULL) {
		ASSERT(IS_CMT_PG(pg));
		atomic_add_32(&pg->cmt_nrunning, n);
		pg = pg->cmt_parent;
	}
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
 * Return 1 if CMT scheduling policies should be impelmented
 * for the specified hardware sharing relationship.
 */
static int
pg_cmt_hw(pghw_type_t hw)
{
	return (pg_plat_cmt_load_bal_hw(hw) ||
	    pg_plat_cmt_affinity_hw(hw));
}

/*
 * CMT class callback for a new CPU entering the system
 */
static void
pg_cmt_cpu_init(cpu_t *cp)
{
	pg_cmt_t	*pg;
	group_t		*cmt_pgs;
	int		level, max_level, nlevels;
	pghw_type_t	hw;
	pg_t		*pg_cache = NULL;
	pg_cmt_t	*cpu_cmt_hier[PGHW_NUM_COMPONENTS];
	lgrp_handle_t	lgrp_handle;
	cmt_lgrp_t	*lgrp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * A new CPU is coming into the system.
	 * Interrogate the platform to see if the CPU
	 * has any performance relevant CMT sharing
	 * relationships
	 */
	cmt_pgs = &cp->cpu_pg->cmt_pgs;
	cp->cpu_pg->cmt_lineage = NULL;

	bzero(cpu_cmt_hier, sizeof (cpu_cmt_hier));
	max_level = nlevels = 0;
	for (hw = PGHW_START; hw < PGHW_NUM_COMPONENTS; hw++) {

		/*
		 * We're only interested in CMT hw sharing relationships
		 */
		if (pg_cmt_hw(hw) == 0 || pg_plat_hw_shared(cp, hw) == 0)
			continue;

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
			bitset_init(&pg->cmt_cpus_actv_set);
			group_create(&pg->cmt_cpus_actv);
		} else {
			ASSERT(IS_CMT_PG(pg));
		}

		/* Add the CPU to the PG */
		pg_cpu_add((pg_t *)pg, cp);

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
		 * Build a lineage of CMT PGs for load balancing
		 */
		if (pg_plat_cmt_load_bal_hw(hw)) {
			level = pghw_level(hw);
			cpu_cmt_hier[level] = pg;
			if (level > max_level)
				max_level = level;
			nlevels++;
		}

		/* Cache this for later */
		if (hw == PGHW_CACHE)
			pg_cache = (pg_t *)pg;
	}

	/*
	 * Pack out any gaps in the constructed lineage,
	 * then size it out.
	 *
	 * Gaps may exist where the architecture knows
	 * about a hardware sharing relationship, but such a
	 * relationship either isn't relevant for load
	 * balancing or doesn't exist between CPUs on the system.
	 */
	pg_cmt_hier_pack((void **)cpu_cmt_hier, max_level + 1);
	group_expand(cmt_pgs, nlevels);


	if (cmt_root == NULL)
		cmt_root = pg_cmt_lgrp_create(lgrp_plat_root_hand());

	/*
	 * Find the lgrp that encapsulates this CPU's CMT hierarchy.
	 * and locate/create a suitable cmt_lgrp_t.
	 */
	lgrp_handle = lgrp_plat_cpu_to_hand(cp->cpu_id);
	if ((lgrp = pg_cmt_find_lgrp(lgrp_handle)) == NULL)
		lgrp = pg_cmt_lgrp_create(lgrp_handle);

	/*
	 * For each of the PGs in the CPU's lineage:
	 *	- Add an entry in the CPU's CMT PG group
	 *	  which is used by the dispatcher to implement load balancing
	 *	  policy.
	 *	- Tie the PG into the CMT hierarchy by connecting
	 *	  it to it's parent and siblings.
	 */
	for (level = 0; level < nlevels; level++) {
		uint_t		children;
		int		err;

		pg = cpu_cmt_hier[level];
		err = group_add_at(cmt_pgs, pg, nlevels - level - 1);
		ASSERT(err == 0);

		if (level == 0)
			cp->cpu_pg->cmt_lineage = (pg_t *)pg;

		if (pg->cmt_siblings != NULL) {
			/* Already initialized */
			ASSERT(pg->cmt_parent == NULL ||
			    pg->cmt_parent == cpu_cmt_hier[level + 1]);
			ASSERT(pg->cmt_siblings == &lgrp->cl_pgs ||
			    ((pg->cmt_parent != NULL) &&
			    pg->cmt_siblings == pg->cmt_parent->cmt_children));
			continue;
		}

		if ((level + 1) == nlevels) {
			pg->cmt_parent = NULL;

			pg->cmt_siblings = &lgrp->cl_pgs;
			children = ++lgrp->cl_npgs;
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
		pg_cmt_cpu_startup(cp);
		is_cpu0 = 0;
		cpu0_lgrp = lgrp;
	}

}

/*
 * Class callback when a CPU is leaving the system (deletion)
 */
static void
pg_cmt_cpu_fini(cpu_t *cp)
{
	group_iter_t	i;
	pg_cmt_t	*pg;
	group_t		*pgs, *cmt_pgs;
	lgrp_handle_t	lgrp_handle;
	cmt_lgrp_t	*lgrp;

	pgs = &cp->cpu_pg->pgs;
	cmt_pgs = &cp->cpu_pg->cmt_pgs;

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
	pg = (pg_cmt_t *)cp->cpu_pg->cmt_lineage;
	while (pg != NULL) {

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

		pg_cpu_delete((pg_t *)pg, cp);
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

	pgs = &cp->cpu_pg->pgs;
	group_iter_init(&i);

	/*
	 * Iterate over the CPU's PGs
	 */
	while ((pg = group_iterate(pgs, &i)) != NULL) {

		if (IS_CMT_PG(pg) == 0)
			continue;

		err = group_add(&pg->cmt_cpus_actv, cp, GRP_NORESIZE);
		ASSERT(err == 0);

		/*
		 * If this is the first active CPU in the PG, and it
		 * represents a hardware sharing relationship over which
		 * CMT load balancing is performed, add it as a candidate
		 * for balancing with it's siblings.
		 */
		if (GROUP_SIZE(&pg->cmt_cpus_actv) == 1 &&
		    pg_plat_cmt_load_bal_hw(((pghw_t *)pg)->pghw_hw)) {
			err = group_add(pg->cmt_siblings, pg, GRP_NORESIZE);
			ASSERT(err == 0);

			/*
			 * If this is a top level PG, add it as a balancing
			 * candidate when balancing within the root lgroup
			 */
			if (pg->cmt_parent == NULL) {
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

	pgs = &cp->cpu_pg->pgs;
	group_iter_init(&i);

	while ((pg = group_iterate(pgs, &i)) != NULL) {

		if (IS_CMT_PG(pg) == 0)
			continue;

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
		    pg_plat_cmt_load_bal_hw(((pghw_t *)pg)->pghw_hw)) {
			err = group_remove(pg->cmt_siblings, pg, GRP_NORESIZE);
			ASSERT(err == 0);

			if (pg->cmt_parent == NULL) {
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
 * Hierarchy packing utility routine. The hierarchy order is preserved.
 */
static void
pg_cmt_hier_pack(void *hier[], int sz)
{
	int	i, j;

	for (i = 0; i < sz; i++) {
		if (hier[i] != NULL)
			continue;

		for (j = i; j < sz; j++) {
			if (hier[j] != NULL) {
				hier[i] = hier[j];
				hier[j] = NULL;
				break;
			}
		}
		if (j == sz)
			break;
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
	int		pg_nrun, tpg_nrun;
	int		level = 0;
	cpu_t		*newcp;

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

		pg_nrun = pg->cmt_nrunning;
		if (self &&
		    bitset_in_set(&pg->cmt_cpus_actv_set, CPU->cpu_seqid))
			pg_nrun--;	/* Ignore curthread's effect */

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
		 * Check if the balancing target is underloaded
		 * Decide to balance if the target is running fewer
		 * threads, or if it's running the same number of threads
		 * with more online CPUs
		 */
		tpg_nrun = tpg->cmt_nrunning;
		if (pg_nrun > tpg_nrun ||
		    (pg_nrun == tpg_nrun &&
		    (GROUP_SIZE(&tpg->cmt_cpus_actv) >
		    GROUP_SIZE(&pg->cmt_cpus_actv)))) {
			break;
		}
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
