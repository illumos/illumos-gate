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
#include <sys/pg.h>

/*
 * Processor groups
 *
 * With the introduction of Chip Multi-Threaded (CMT) processor architectures,
 * it is no longer necessarily true that a given physical processor module
 * will present itself as a single schedulable entity (cpu_t). Rather, each
 * chip and/or processor core may present itself as one or more "logical" CPUs.
 *
 * The logical CPUs presented may share physical components such as caches,
 * data pipes, execution pipelines, FPUs, etc. It is advantageous to have the
 * kernel be aware of the relationships existing between logical CPUs so that
 * the appropriate optmizations may be employed.
 *
 * The processor group abstraction represents a set of logical CPUs that
 * generally share some sort of physical or characteristic relationship.
 *
 * In the case of a physical sharing relationship, the CPUs in the group may
 * share a pipeline, cache or floating point unit. In the case of a logical
 * relationship, a PG may represent the set of CPUs in a processor set, or the
 * set of CPUs running at a particular clock speed.
 *
 * The generic processor group structure, pg_t, contains the elements generic
 * to a group of CPUs. Depending on the nature of the CPU relationship
 * (LOGICAL or PHYSICAL), a pointer to a pg may be recast to a "view" of that
 * PG where more specific data is represented.
 *
 * As an example, a PG representing a PHYSICAL relationship, may be recast to
 * a pghw_t, where data further describing the hardware sharing relationship
 * is maintained. See pghw.c and pghw.h for details on physical PGs.
 *
 * At this time a more specialized casting of a PG representing a LOGICAL
 * relationship has not been implemented, but the architecture allows for this
 * in the future.
 *
 * Processor Group Classes
 *
 * Processor group consumers may wish to maintain and associate specific
 * data with the PGs they create. For this reason, a mechanism for creating
 * class specific PGs exists. Classes may overload the default functions for
 * creating, destroying, and associating CPUs with PGs, and may also register
 * class specific callbacks to be invoked when the CPU related system
 * configuration changes. Class specific data is stored/associated with
 * PGs by incorporating the pg_t (or pghw_t, as appropriate), as the first
 * element of a class specific PG object. In memory, such a structure may look
 * like:
 *
 * ----------------------- - - -
 * | common              | | | |  <--(pg_t *)
 * ----------------------- | | -
 * | HW specific         | | | <-----(pghw_t *)
 * ----------------------- | -
 * | class specific      | | <-------(pg_cmt_t *)
 * ----------------------- -
 *
 * Access to the PG class specific data can be had by casting a pointer to
 * it's class specific view.
 */

static pg_t		*pg_alloc_default(pg_class_t);
static void		pg_free_default(pg_t *);
static void		pg_null_op();

/*
 * Bootstrap CPU specific PG data
 * See pg_cpu_bootstrap()
 */
static cpu_pg_t		bootstrap_pg_data;

/*
 * Bitset of allocated PG ids (they are sequential)
 * and the next free id in the set.
 */
static bitset_t		pg_id_set;

/*
 * ID space starts from 1 to assume that root has ID 0;
 */
static pgid_t		pg_id_next = 1;

/*
 * Default and externed PG ops vectors
 */
static struct pg_ops pg_ops_default = {
	pg_alloc_default,	/* alloc */
	pg_free_default,	/* free */
	NULL,			/* cpu_init */
	NULL,			/* cpu_fini */
	NULL,			/* cpu_active */
	NULL,			/* cpu_inactive */
	NULL,			/* cpupart_in */
	NULL,			/* cpupart_out */
	NULL,			/* cpupart_move */
	NULL,			/* cpu_belongs */
	NULL,			/* policy_name */
};

static struct pg_cb_ops pg_cb_ops_default = {
	pg_null_op,		/* thread_swtch */
	pg_null_op,		/* thread_remain */
};

/*
 * Class specific PG allocation callbacks
 */
#define	PG_ALLOC(class)							\
	(pg_classes[class].pgc_ops->alloc ?				\
	    pg_classes[class].pgc_ops->alloc() :			\
	    pg_classes[pg_default_cid].pgc_ops->alloc())

#define	PG_FREE(pg)							\
	((pg)->pg_class->pgc_ops->free ?				\
	    (pg)->pg_class->pgc_ops->free(pg) :				\
	    pg_classes[pg_default_cid].pgc_ops->free(pg))		\


/*
 * Class specific PG policy name
 */
#define	PG_POLICY_NAME(pg)						\
	((pg)->pg_class->pgc_ops->policy_name ?				\
	    (pg)->pg_class->pgc_ops->policy_name(pg) : NULL)		\

/*
 * Class specific membership test callback
 */
#define	PG_CPU_BELONGS(pg, cp)						\
	((pg)->pg_class->pgc_ops->cpu_belongs ?				\
	    (pg)->pg_class->pgc_ops->cpu_belongs(pg, cp) : 0)		\

/*
 * CPU configuration callbacks
 */
#define	PG_CPU_INIT(class, cp, cpu_pg)					\
{									\
	if (pg_classes[class].pgc_ops->cpu_init)			\
		pg_classes[class].pgc_ops->cpu_init(cp, cpu_pg);	\
}

#define	PG_CPU_FINI(class, cp, cpu_pg)					\
{									\
	if (pg_classes[class].pgc_ops->cpu_fini)			\
		pg_classes[class].pgc_ops->cpu_fini(cp, cpu_pg);	\
}

#define	PG_CPU_ACTIVE(class, cp)					\
{									\
	if (pg_classes[class].pgc_ops->cpu_active)			\
		pg_classes[class].pgc_ops->cpu_active(cp);		\
}

#define	PG_CPU_INACTIVE(class, cp)					\
{									\
	if (pg_classes[class].pgc_ops->cpu_inactive)			\
		pg_classes[class].pgc_ops->cpu_inactive(cp);		\
}

/*
 * CPU / cpupart configuration callbacks
 */
#define	PG_CPUPART_IN(class, cp, pp)					\
{									\
	if (pg_classes[class].pgc_ops->cpupart_in)			\
		pg_classes[class].pgc_ops->cpupart_in(cp, pp);		\
}

#define	PG_CPUPART_OUT(class, cp, pp)					\
{									\
	if (pg_classes[class].pgc_ops->cpupart_out)			\
		pg_classes[class].pgc_ops->cpupart_out(cp, pp);		\
}

#define	PG_CPUPART_MOVE(class, cp, old, new)				\
{									\
	if (pg_classes[class].pgc_ops->cpupart_move)			\
		pg_classes[class].pgc_ops->cpupart_move(cp, old, new);	\
}



static pg_class_t	*pg_classes;
static int		pg_nclasses;

static pg_cid_t		pg_default_cid;

/*
 * Initialze common PG subsystem.
 */
void
pg_init(void)
{
	extern void pg_cmt_class_init();
	extern void pg_cmt_cpu_startup();

	pg_default_cid =
	    pg_class_register("default", &pg_ops_default, PGR_LOGICAL);

	/*
	 * Initialize classes to allow them to register with the framework
	 */
	pg_cmt_class_init();

	pg_cpu0_init();
	pg_cmt_cpu_startup(CPU);
}

/*
 * Perform CPU 0 initialization
 */
void
pg_cpu0_init(void)
{
	extern void pghw_physid_create();

	/*
	 * Create the physical ID cache for the boot CPU
	 */
	pghw_physid_create(CPU);

	/*
	 * pg_cpu_* require that cpu_lock be held
	 */
	mutex_enter(&cpu_lock);

	(void) pg_cpu_init(CPU, B_FALSE);
	pg_cpupart_in(CPU, &cp_default);
	pg_cpu_active(CPU);

	mutex_exit(&cpu_lock);
}

/*
 * Invoked when topology for CPU0 changes
 * post pg_cpu0_init().
 *
 * Currently happens as a result of null_proc_lpa
 * on Starcat.
 */
void
pg_cpu0_reinit(void)
{
	mutex_enter(&cpu_lock);
	pg_cpu_inactive(CPU);
	pg_cpupart_out(CPU, &cp_default);
	pg_cpu_fini(CPU, NULL);

	(void) pg_cpu_init(CPU, B_FALSE);
	pg_cpupart_in(CPU, &cp_default);
	pg_cpu_active(CPU);
	mutex_exit(&cpu_lock);
}

/*
 * Register a new PG class
 */
pg_cid_t
pg_class_register(char *name, struct pg_ops *ops, pg_relation_t relation)
{
	pg_class_t	*newclass;
	pg_class_t	*classes_old;
	id_t		cid;

	mutex_enter(&cpu_lock);

	/*
	 * Allocate a new pg_class_t in the pg_classes array
	 */
	if (pg_nclasses == 0) {
		pg_classes = kmem_zalloc(sizeof (pg_class_t), KM_SLEEP);
	} else {
		classes_old = pg_classes;
		pg_classes =
		    kmem_zalloc(sizeof (pg_class_t) * (pg_nclasses + 1),
		    KM_SLEEP);
		(void) kcopy(classes_old, pg_classes,
		    sizeof (pg_class_t) * pg_nclasses);
		kmem_free(classes_old, sizeof (pg_class_t) * pg_nclasses);
	}

	cid = pg_nclasses++;
	newclass = &pg_classes[cid];

	(void) strncpy(newclass->pgc_name, name, PG_CLASS_NAME_MAX);
	newclass->pgc_id = cid;
	newclass->pgc_ops = ops;
	newclass->pgc_relation = relation;

	mutex_exit(&cpu_lock);

	return (cid);
}

/*
 * Try to find an existing pg in set in which to place cp.
 * Returns the pg if found, and NULL otherwise.
 * In the event that the CPU could belong to multiple
 * PGs in the set, the first matching PG will be returned.
 */
pg_t *
pg_cpu_find_pg(cpu_t *cp, group_t *set)
{
	pg_t		*pg;
	group_iter_t	i;

	group_iter_init(&i);
	while ((pg = group_iterate(set, &i)) != NULL) {
		/*
		 * Ask the class if the CPU belongs here
		 */
		if (PG_CPU_BELONGS(pg, cp))
			return (pg);
	}
	return (NULL);
}

/*
 * Iterate over the CPUs in a PG after initializing
 * the iterator with PG_CPU_ITR_INIT()
 */
cpu_t *
pg_cpu_next(pg_cpu_itr_t *itr)
{
	cpu_t		*cpu;
	pg_t		*pg = itr->pg;

	cpu = group_iterate(&pg->pg_cpus, &itr->position);
	return (cpu);
}

/*
 * Test if a given PG contains a given CPU
 */
boolean_t
pg_cpu_find(pg_t *pg, cpu_t *cp)
{
	if (group_find(&pg->pg_cpus, cp) == (uint_t)-1)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Set the PGs callbacks to the default
 */
void
pg_callback_set_defaults(pg_t *pg)
{
	bcopy(&pg_cb_ops_default, &pg->pg_cb, sizeof (struct pg_cb_ops));
}

/*
 * Create a PG of a given class.
 * This routine may block.
 */
pg_t *
pg_create(pg_cid_t cid)
{
	pg_t	*pg;
	pgid_t	id;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Call the class specific PG allocation routine
	 */
	pg = PG_ALLOC(cid);
	pg->pg_class = &pg_classes[cid];
	pg->pg_relation = pg->pg_class->pgc_relation;

	/*
	 * Find the next free sequential pg id
	 */
	do {
		if (pg_id_next >= bitset_capacity(&pg_id_set))
			bitset_resize(&pg_id_set, pg_id_next + 1);
		id = pg_id_next++;
	} while (bitset_in_set(&pg_id_set, id));

	pg->pg_id = id;
	bitset_add(&pg_id_set, pg->pg_id);

	/*
	 * Create the PG's CPU group
	 */
	group_create(&pg->pg_cpus);

	/*
	 * Initialize the events ops vector
	 */
	pg_callback_set_defaults(pg);

	return (pg);
}

/*
 * Destroy a PG.
 * This routine may block.
 */
void
pg_destroy(pg_t *pg)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	group_destroy(&pg->pg_cpus);

	/*
	 * Unassign the pg_id
	 */
	if (pg_id_next > pg->pg_id)
		pg_id_next = pg->pg_id;
	bitset_del(&pg_id_set, pg->pg_id);

	/*
	 * Invoke the class specific de-allocation routine
	 */
	PG_FREE(pg);
}

/*
 * Add the CPU "cp" to processor group "pg"
 * This routine may block.
 */
void
pg_cpu_add(pg_t *pg, cpu_t *cp, cpu_pg_t *cpu_pg)
{
	int	err;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/* This adds the CPU to the PG's CPU group */
	err = group_add(&pg->pg_cpus, cp, GRP_RESIZE);
	ASSERT(err == 0);

	/*
	 * The CPU should be referencing the bootstrap PG data still
	 * at this point, since this routine may block causing us to
	 * enter the dispatcher.
	 */
	ASSERT(pg_cpu_is_bootstrapped(cp));

	/* This adds the PG to the CPUs PG group */
	err = group_add(&cpu_pg->pgs, pg, GRP_RESIZE);
	ASSERT(err == 0);
}

/*
 * Remove "cp" from "pg".
 * This routine may block.
 */
void
pg_cpu_delete(pg_t *pg, cpu_t *cp, cpu_pg_t *cpu_pg)
{
	int	err;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/* Remove the CPU from the PG */
	err = group_remove(&pg->pg_cpus, cp, GRP_RESIZE);
	ASSERT(err == 0);

	/*
	 * The CPU should be referencing the bootstrap PG data still
	 * at this point, since this routine may block causing us to
	 * enter the dispatcher.
	 */
	ASSERT(pg_cpu_is_bootstrapped(cp));

	/* Remove the PG from the CPU's PG group */
	err = group_remove(&cpu_pg->pgs, pg, GRP_RESIZE);
	ASSERT(err == 0);
}

/*
 * Allocate a CPU's PG data. This hangs off struct cpu at cpu_pg
 */
static cpu_pg_t *
pg_cpu_data_alloc(void)
{
	cpu_pg_t	*pgd;

	pgd = kmem_zalloc(sizeof (cpu_pg_t), KM_SLEEP);
	group_create(&pgd->pgs);
	group_create(&pgd->cmt_pgs);

	return (pgd);
}

/*
 * Free the CPU's PG data.
 */
static void
pg_cpu_data_free(cpu_pg_t *pgd)
{
	group_destroy(&pgd->pgs);
	group_destroy(&pgd->cmt_pgs);
	kmem_free(pgd, sizeof (cpu_pg_t));
}

/*
 * Called when either a new CPU is coming into the system (either
 * via booting or DR) or when the CPU's PG data is being recalculated.
 * Allocate its PG data, and notify all registered classes about
 * the new CPU.
 *
 * If "deferred_init" is B_TRUE, the CPU's PG data will be allocated
 * and returned, but the "bootstrap" structure will be left in place.
 * The deferred_init option is used when all CPUs in the system are
 * using the bootstrap structure as part of the process of recalculating
 * all PG data. The caller must replace the bootstrap structure with the
 * allocated PG data before pg_cpu_active is called.
 *
 * This routine may block.
 */
cpu_pg_t *
pg_cpu_init(cpu_t *cp, boolean_t deferred_init)
{
	pg_cid_t	i;
	cpu_pg_t	*cpu_pg;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Allocate and size the per CPU pg data
	 *
	 * The CPU's PG data will be populated by the various
	 * PG classes during the invocation of the PG_CPU_INIT()
	 * callback below.
	 *
	 * Since the we could block and enter the dispatcher during
	 * this process, the CPU will continue to reference the bootstrap
	 * PG data until all the initialization completes.
	 */
	ASSERT(pg_cpu_is_bootstrapped(cp));

	cpu_pg = pg_cpu_data_alloc();

	/*
	 * Notify all registered classes about the new CPU
	 */
	for (i = 0; i < pg_nclasses; i++)
		PG_CPU_INIT(i, cp, cpu_pg);

	/*
	 * The CPU's PG data is now ready to use.
	 */
	if (deferred_init == B_FALSE)
		cp->cpu_pg = cpu_pg;

	return (cpu_pg);
}

/*
 * Either this CPU is being deleted from the system or its PG data is
 * being recalculated. Notify the classes and free up the CPU's PG data.
 *
 * If "cpu_pg_deferred" is non-NULL, it points to the CPU's PG data and
 * serves to indicate that this CPU is already using the bootstrap
 * stucture. Used as part of the process to recalculate the PG data for
 * all CPUs in the system.
 */
void
pg_cpu_fini(cpu_t *cp, cpu_pg_t *cpu_pg_deferred)
{
	pg_cid_t	i;
	cpu_pg_t	*cpu_pg;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (cpu_pg_deferred == NULL) {
		cpu_pg = cp->cpu_pg;

		/*
		 * This can happen if the CPU coming into the system
		 * failed to power on.
		 */
		if (cpu_pg == NULL || pg_cpu_is_bootstrapped(cp))
			return;

		/*
		 * Have the CPU reference the bootstrap PG data to survive
		 * the dispatcher should it block from here on out.
		 */
		pg_cpu_bootstrap(cp);
	} else {
		ASSERT(pg_cpu_is_bootstrapped(cp));
		cpu_pg = cpu_pg_deferred;
	}

	for (i = 0; i < pg_nclasses; i++)
		PG_CPU_FINI(i, cp, cpu_pg);

	pg_cpu_data_free(cpu_pg);
}

/*
 * This CPU is becoming active (online)
 * This routine may not block as it is called from paused CPUs
 * context.
 */
void
pg_cpu_active(cpu_t *cp)
{
	pg_cid_t	i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Notify all registered classes about the new CPU
	 */
	for (i = 0; i < pg_nclasses; i++)
		PG_CPU_ACTIVE(i, cp);
}

/*
 * This CPU is going inactive (offline)
 * This routine may not block, as it is called from paused
 * CPUs context.
 */
void
pg_cpu_inactive(cpu_t *cp)
{
	pg_cid_t	i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Notify all registered classes about the new CPU
	 */
	for (i = 0; i < pg_nclasses; i++)
		PG_CPU_INACTIVE(i, cp);
}

/*
 * Invoked when the CPU is about to move into the partition
 * This routine may block.
 */
void
pg_cpupart_in(cpu_t *cp, cpupart_t *pp)
{
	int	i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Notify all registered classes that the
	 * CPU is about to enter the CPU partition
	 */
	for (i = 0; i < pg_nclasses; i++)
		PG_CPUPART_IN(i, cp, pp);
}

/*
 * Invoked when the CPU is about to move out of the partition
 * This routine may block.
 */
/*ARGSUSED*/
void
pg_cpupart_out(cpu_t *cp, cpupart_t *pp)
{
	int	i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Notify all registered classes that the
	 * CPU is about to leave the CPU partition
	 */
	for (i = 0; i < pg_nclasses; i++)
		PG_CPUPART_OUT(i, cp, pp);
}

/*
 * Invoked when the CPU is *moving* partitions.
 *
 * This routine may not block, as it is called from paused CPUs
 * context.
 */
void
pg_cpupart_move(cpu_t *cp, cpupart_t *oldpp, cpupart_t *newpp)
{
	int	i;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Notify all registered classes that the
	 * CPU is about to leave the CPU partition
	 */
	for (i = 0; i < pg_nclasses; i++)
		PG_CPUPART_MOVE(i, cp, oldpp, newpp);
}

/*
 * Return a class specific string describing a policy implemented
 * across this PG
 */
char *
pg_policy_name(pg_t *pg)
{
	char *str;
	if ((str = PG_POLICY_NAME(pg)) != NULL)
		return (str);

	return ("N/A");
}

/*
 * Provide the specified CPU a bootstrap pg
 * This is needed to allow sane behaviour if any PG consuming
 * code needs to deal with a partially initialized CPU
 */
void
pg_cpu_bootstrap(cpu_t *cp)
{
	cp->cpu_pg = &bootstrap_pg_data;
}

/*
 * Return non-zero if the specified CPU is bootstrapped,
 * which means it's CPU specific PG data has not yet been
 * fully constructed.
 */
int
pg_cpu_is_bootstrapped(cpu_t *cp)
{
	return (cp->cpu_pg == &bootstrap_pg_data);
}

/*ARGSUSED*/
static pg_t *
pg_alloc_default(pg_class_t class)
{
	return (kmem_zalloc(sizeof (pg_t), KM_SLEEP));
}

/*ARGSUSED*/
static void
pg_free_default(struct pg *pg)
{
	kmem_free(pg, sizeof (pg_t));
}

static void
pg_null_op()
{
}

/*
 * Invoke the "thread switch" callback for each of the CPU's PGs
 * This is invoked from the dispatcher swtch() routine, which is called
 * when a thread running an a CPU should switch to another thread.
 * "cp" is the CPU on which the thread switch is happening
 * "now" is an unscaled hrtime_t timestamp taken in swtch()
 * "old" and "new" are the outgoing and incoming threads, respectively.
 */
void
pg_ev_thread_swtch(struct cpu *cp, hrtime_t now, kthread_t *old, kthread_t *new)
{
	int	i, sz;
	group_t	*grp;
	pg_t	*pg;

	grp = &cp->cpu_pg->pgs;
	sz = GROUP_SIZE(grp);
	for (i = 0; i < sz; i++) {
		pg = GROUP_ACCESS(grp, i);
		pg->pg_cb.thread_swtch(pg, cp, now, old, new);
	}
}

/*
 * Invoke the "thread remain" callback for each of the CPU's PGs.
 * This is called from the dispatcher's swtch() routine when a thread
 * running on the CPU "cp" is switching to itself, which can happen as an
 * artifact of the thread's timeslice expiring.
 */
void
pg_ev_thread_remain(struct cpu *cp, kthread_t *t)
{
	int	i, sz;
	group_t	*grp;
	pg_t	*pg;

	grp = &cp->cpu_pg->pgs;
	sz = GROUP_SIZE(grp);
	for (i = 0; i < sz; i++) {
		pg = GROUP_ACCESS(grp, i);
		pg->pg_cb.thread_remain(pg, cp, t);
	}
}
