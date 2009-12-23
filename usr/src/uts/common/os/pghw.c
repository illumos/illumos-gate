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
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/group.h>
#include <sys/pg.h>
#include <sys/pghw.h>
#include <sys/cpu_pm.h>
#include <sys/cap_util.h>

/*
 * Processor Groups: Hardware sharing relationship layer
 *
 * This file implements an extension to Processor Groups to capture
 * hardware sharing relationships existing between logical CPUs. Examples of
 * hardware sharing relationships include shared caches on some CMT
 * procesoor architectures, or shared local memory controllers on NUMA
 * based system architectures.
 *
 * The pghw_t structure represents the extended PG. The first member
 * of the structure is the generic pg_t with the pghw specific members
 * following. The generic pg_t *must* remain the first member of the
 * structure as the code uses casting of structure references to access
 * the generic pg_t structure elements.
 *
 * In addition to the generic CPU grouping, physical PGs have a hardware
 * sharing relationship enumerated "type", and an instance id. The enumerated
 * type is defined by the pghw_type_t enumeration, while the instance id
 * uniquely identifies the sharing instance from among others of the same
 * hardware sharing type.
 *
 * The physical PGs are organized into an overall hierarchy, and are tracked
 * in a number of different per CPU, and per pghw_type_t type groups.
 * As an example:
 *
 * -------------
 * | pg_hw     |
 * | (group_t) |
 * -------------
 *  ||                          ============================
 *  ||\\-----------------------//       \\                 \\
 *  ||  | hwset (PGC_HW_CHIP) |        -------------      -------------
 *  ||  | (group_t)           |        | pghw_t    |      | pghw_t    |
 *  ||  -----------------------        | chip 0    |      | chip 1    |
 *  ||                                 -------------      -------------
 *  ||                                 \\  \\  \\  \\     \\  \\  \\  \\
 *  ||                                  cpu cpu cpu cpu    cpu cpu cpu cpu
 *  ||
 *  ||                          ============================
 *  ||\\-----------------------//       \\                 \\
 *  ||  | hwset (PGC_HW_IPIPE)|        -------------      -------------
 *  ||  | (group_t)           |        | pghw_t    |      | pghw_t    |
 *  ||  -----------------------        | ipipe 0   |      | ipipe 1   |
 *  ||                                 -------------      -------------
 *  ||                                 \\  \\             \\  \\
 *  ||                                  cpu cpu            cpu cpu
 *  ...
 *
 *
 * The top level pg_hw is a group of "hwset" groups. Each hwset holds of group
 * of physical PGs of the same hardware sharing type. Within each hwset, the
 * PG's instance id uniquely identifies the grouping relationshsip among other
 * groupings of the same sharing type. The instance id for a grouping is
 * platform defined, and in some cases may be used by platform code as a handle
 * to search for a particular relationship instance.
 *
 * Each physical PG (by virtue of the embedded pg_t) contains a group of CPUs
 * that participate in the sharing relationship. Each CPU also has associated
 * with it a grouping tracking the PGs in which the CPU belongs. This can be
 * used to iterate over the various relationships in which the CPU participates
 * (the CPU's chip, cache, lgroup, etc.).
 *
 * The hwsets are created dynamically as new hardware sharing relationship types
 * are instantiated. They are never destroyed, as once a given relationship
 * type appears in the system, it is quite likely that at least one instance of
 * that relationship will always persist as long as the system is running.
 */

static group_t		*pg_hw;		/* top level pg hw group */

/*
 * Physical PG kstats
 */
struct pghw_kstat {
	kstat_named_t	pg_id;
	kstat_named_t	pg_class;
	kstat_named_t	pg_ncpus;
	kstat_named_t	pg_instance_id;
	kstat_named_t	pg_hw;
	kstat_named_t	pg_policy;
} pghw_kstat = {
	{ "id",			KSTAT_DATA_UINT32 },
	{ "pg_class",		KSTAT_DATA_STRING },
	{ "ncpus",		KSTAT_DATA_UINT32 },
	{ "instance_id",	KSTAT_DATA_UINT32 },
	{ "hardware",		KSTAT_DATA_STRING },
	{ "policy",		KSTAT_DATA_STRING },
};

kmutex_t		pghw_kstat_lock;

/*
 * Capacity and Utilization PG kstats
 *
 * These kstats are updated one at a time, so we can have a single scratch space
 * to fill the data.
 *
 * kstat fields:
 *
 *   pgid		PG ID for PG described by this kstat
 *
 *   pg_ncpus		Number of CPUs within this PG
 *
 *   pg_cpus		String describing CPUs within this PG
 *
 *   pg_sharing		Name of sharing relationship for this PG
 *
 *   pg_generation	Generation value that increases whenever any CPU leaves
 *			  or joins PG. Two kstat snapshots for the same
 *			  CPU may only be compared if they have the same
 *			  generation
 *
 *   pg_hw_util		Running value of PG utilization for the sharing
 *			  relationship
 *
 *   pg_hw_util_time_running
 *			Total time spent collecting CU data. The time may be
 *			less than wall time if CU counters were stopped for
 *			some time.
 *
 *   pg_hw_util_time_stopped Total time the CU counters were stopped.
 *
 *   pg_hw_util_rate	Utilization rate, expressed in operations per second.
 *
 *   pg_hw_util_rate_max Maximum observed value of utilization rate.
 */
struct pghw_cu_kstat {
	kstat_named_t	pg_id;
	kstat_named_t	pg_ncpus;
	kstat_named_t	pg_generation;
	kstat_named_t	pg_hw_util;
	kstat_named_t	pg_hw_util_time_running;
	kstat_named_t	pg_hw_util_time_stopped;
	kstat_named_t	pg_hw_util_rate;
	kstat_named_t	pg_hw_util_rate_max;
	kstat_named_t	pg_cpus;
	kstat_named_t	pg_sharing;
} pghw_cu_kstat = {
	{ "id",			KSTAT_DATA_UINT32 },
	{ "ncpus",		KSTAT_DATA_UINT32 },
	{ "generation",		KSTAT_DATA_UINT32   },
	{ "hw_util",		KSTAT_DATA_UINT64   },
	{ "hw_util_time_running",	KSTAT_DATA_UINT64   },
	{ "hw_util_time_stopped",	KSTAT_DATA_UINT64   },
	{ "hw_util_rate",	KSTAT_DATA_UINT64   },
	{ "hw_util_rate_max",	KSTAT_DATA_UINT64   },
	{ "cpus",		KSTAT_DATA_STRING   },
	{ "sharing_relation",	KSTAT_DATA_STRING   },
};

/*
 * Calculate the string size to represent NCPUS. Allow 5 digits for each CPU ID
 * plus one space per CPU plus NUL byte in the end. This is only an estimate,
 * since we try to compress CPU ranges as x-y. In the worst case the string
 * representation of CPUs may be truncated.
 */
#define	CPUSTR_LEN(ncpus) ((ncpus) * 6)

/*
 * Maximum length of the string that represents list of CPUs
 */
static int pg_cpulist_maxlen = 0;

static void		pghw_kstat_create(pghw_t *);
static int		pghw_kstat_update(kstat_t *, int);
static int		pghw_cu_kstat_update(kstat_t *, int);
static int		cpu2id(void *);

/*
 * hwset operations
 */
static group_t		*pghw_set_create(pghw_type_t);
static void		pghw_set_add(group_t *, pghw_t *);
static void		pghw_set_remove(group_t *, pghw_t *);

static void		pghw_cpulist_alloc(pghw_t *);
static int		cpu2id(void *);

/*
 * Initialize the physical portion of a hardware PG
 */
void
pghw_init(pghw_t *pg, cpu_t *cp, pghw_type_t hw)
{
	group_t		*hwset;

	if ((hwset = pghw_set_lookup(hw)) == NULL) {
		/*
		 * Haven't seen this hardware type yet
		 */
		hwset = pghw_set_create(hw);
	}

	pghw_set_add(hwset, pg);
	pg->pghw_hw = hw;
	pg->pghw_generation = 0;
	pg->pghw_instance =
	    pg_plat_hw_instance_id(cp, hw);
	pghw_kstat_create(pg);

	/*
	 * Hardware sharing relationship specific initialization
	 */
	switch (pg->pghw_hw) {
	case PGHW_POW_ACTIVE:
		pg->pghw_handle =
		    (pghw_handle_t)cpupm_domain_init(cp, CPUPM_DTYPE_ACTIVE);
		break;
	case PGHW_POW_IDLE:
		pg->pghw_handle =
		    (pghw_handle_t)cpupm_domain_init(cp, CPUPM_DTYPE_IDLE);
		break;
	default:
		pg->pghw_handle = (pghw_handle_t)NULL;
	}
}

/*
 * Teardown the physical portion of a physical PG
 */
void
pghw_fini(pghw_t *pg)
{
	group_t		*hwset;

	hwset = pghw_set_lookup(pg->pghw_hw);
	ASSERT(hwset != NULL);

	pghw_set_remove(hwset, pg);
	pg->pghw_instance = (id_t)PGHW_INSTANCE_ANON;
	pg->pghw_hw = (pghw_type_t)-1;

	if (pg->pghw_kstat != NULL)
		kstat_delete(pg->pghw_kstat);

	/*
	 * Destroy string representation of CPUs
	 */
	if (pg->pghw_cpulist != NULL) {
		kmem_free(pg->pghw_cpulist,
		    pg->pghw_cpulist_len);
		pg->pghw_cpulist = NULL;
	}

	if (pg->pghw_cu_kstat != NULL)
		kstat_delete(pg->pghw_cu_kstat);
}

/*
 * Find an existing physical PG in which to place
 * the given CPU for the specified hardware sharing
 * relationship
 */
pghw_t *
pghw_place_cpu(cpu_t *cp, pghw_type_t hw)
{
	group_t		*hwset;

	if ((hwset = pghw_set_lookup(hw)) == NULL) {
		return (NULL);
	}

	return ((pghw_t *)pg_cpu_find_pg(cp, hwset));
}

/*
 * Find the pg representing the hw sharing relationship in which
 * cp belongs
 */
pghw_t *
pghw_find_pg(cpu_t *cp, pghw_type_t hw)
{
	group_iter_t	i;
	pghw_t	*pg;

	group_iter_init(&i);
	while ((pg = group_iterate(&cp->cpu_pg->pgs, &i)) != NULL) {
		if (pg->pghw_hw == hw)
			return (pg);
	}
	return (NULL);
}

/*
 * Find the PG of the given hardware sharing relationship
 * type with the given instance id
 */
pghw_t *
pghw_find_by_instance(id_t id, pghw_type_t hw)
{
	group_iter_t	i;
	group_t		*set;
	pghw_t		*pg;

	set = pghw_set_lookup(hw);
	if (!set)
		return (NULL);

	group_iter_init(&i);
	while ((pg = group_iterate(set, &i)) != NULL) {
		if (pg->pghw_instance == id)
			return (pg);
	}
	return (NULL);
}

/*
 * CPUs physical ID cache creation / destruction
 * The cache's elements are initialized to the CPU's id
 */
void
pghw_physid_create(cpu_t *cp)
{
	int	i;

	cp->cpu_physid = kmem_alloc(sizeof (cpu_physid_t), KM_SLEEP);

	for (i = 0; i < (sizeof (cpu_physid_t) / sizeof (id_t)); i++) {
		((id_t *)cp->cpu_physid)[i] = cp->cpu_id;
	}
}

void
pghw_physid_destroy(cpu_t *cp)
{
	if (cp->cpu_physid) {
		kmem_free(cp->cpu_physid, sizeof (cpu_physid_t));
		cp->cpu_physid = NULL;
	}
}

/*
 * Create a new, empty hwset.
 * This routine may block, and must not be called from any
 * paused CPU context.
 */
static group_t	*
pghw_set_create(pghw_type_t hw)
{
	group_t	*g;
	int	ret;

	/*
	 * Create the top level PG hw group if it doesn't already exist
	 * This is a "set" of hardware sets, that is ordered (and indexed)
	 * by the pghw_type_t enum.
	 */
	if (pg_hw == NULL) {
		pg_hw = kmem_alloc(sizeof (group_t), KM_SLEEP);
		group_create(pg_hw);
		group_expand(pg_hw, (uint_t)PGHW_NUM_COMPONENTS);
	}

	/*
	 * Create the new hwset
	 * Add it to the top level pg_hw group.
	 */
	g = kmem_alloc(sizeof (group_t), KM_SLEEP);
	group_create(g);

	ret = group_add_at(pg_hw, g, (uint_t)hw);
	ASSERT(ret == 0);

	return (g);
}

/*
 * Find the hwset associated with the given hardware sharing type
 */
group_t *
pghw_set_lookup(pghw_type_t hw)
{
	group_t	*hwset;

	if (pg_hw == NULL)
		return (NULL);

	hwset = GROUP_ACCESS(pg_hw, (uint_t)hw);
	return (hwset);
}

/*
 * Add a PG to a hwset
 */
static void
pghw_set_add(group_t *hwset, pghw_t *pg)
{
	(void) group_add(hwset, pg, GRP_RESIZE);
}

/*
 * Remove a PG from a hwset
 */
static void
pghw_set_remove(group_t *hwset, pghw_t *pg)
{
	int result;

	result = group_remove(hwset, pg, GRP_RESIZE);
	ASSERT(result == 0);
}

/*
 * Return a string name given a pg_hw sharing type
 */
char *
pghw_type_string(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		return ("Integer Pipeline");
	case PGHW_CACHE:
		return ("Cache");
	case PGHW_FPU:
		return ("Floating Point Unit");
	case PGHW_MPIPE:
		return ("Data Pipe to memory");
	case PGHW_CHIP:
		return ("Socket");
	case PGHW_MEMORY:
		return ("Memory");
	case PGHW_POW_ACTIVE:
		return ("CPU PM Active Power Domain");
	case PGHW_POW_IDLE:
		return ("CPU PM Idle Power Domain");
	default:
		return ("unknown");
	}
}

/*
 * Return a short string name given a pg_hw sharing type
 */
char *
pghw_type_shortstring(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		return ("instr_pipeline");
	case PGHW_CACHE:
		return ("Cache");
	case PGHW_FPU:
		return ("FPU");
	case PGHW_MPIPE:
		return ("memory_pipeline");
	case PGHW_CHIP:
		return ("Socket");
	case PGHW_MEMORY:
		return ("Memory");
	case PGHW_POW_ACTIVE:
		return ("CPU_PM_Active");
	case PGHW_POW_IDLE:
		return ("CPU_PM_Idle");
	default:
		return ("unknown");
	}
}

/*
 * Create / Update routines for PG hw kstats
 *
 * It is the intention of these kstats to provide some level
 * of informational / debugging observability into the types
 * and nature of the system's detected hardware sharing relationships
 */
void
pghw_kstat_create(pghw_t *pg)
{
	char *class = pghw_type_string(pg->pghw_hw);

	/*
	 * Create a physical pg kstat
	 */
	if ((pg->pghw_kstat = kstat_create("pg", ((pg_t *)pg)->pg_id,
	    "pg", "pg",
	    KSTAT_TYPE_NAMED,
	    sizeof (pghw_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) != NULL) {
		/* Class string, hw string, and policy string */
		pg->pghw_kstat->ks_data_size += PG_CLASS_NAME_MAX;
		pg->pghw_kstat->ks_data_size += PGHW_KSTAT_STR_LEN_MAX;
		pg->pghw_kstat->ks_data_size += PGHW_KSTAT_STR_LEN_MAX;
		pg->pghw_kstat->ks_lock = &pghw_kstat_lock;
		pg->pghw_kstat->ks_data = &pghw_kstat;
		pg->pghw_kstat->ks_update = pghw_kstat_update;
		pg->pghw_kstat->ks_private = pg;
		kstat_install(pg->pghw_kstat);
	}

	if (pg_cpulist_maxlen == 0)
		pg_cpulist_maxlen = CPUSTR_LEN(max_ncpus);

	/*
	 * Create a physical pg kstat
	 */
	if ((pg->pghw_cu_kstat = kstat_create("pg", ((pg_t *)pg)->pg_id,
	    "hardware", class,
	    KSTAT_TYPE_NAMED,
	    sizeof (pghw_cu_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) != NULL) {
		pg->pghw_cu_kstat->ks_lock = &pghw_kstat_lock;
		pg->pghw_cu_kstat->ks_data = &pghw_cu_kstat;
		pg->pghw_cu_kstat->ks_update = pghw_cu_kstat_update;
		pg->pghw_cu_kstat->ks_private = pg;
		pg->pghw_cu_kstat->ks_data_size += strlen(class) + 1;
		/* Allow space for CPU strings */
		pg->pghw_cu_kstat->ks_data_size += PGHW_KSTAT_STR_LEN_MAX;
		pg->pghw_cu_kstat->ks_data_size += pg_cpulist_maxlen;
		kstat_install(pg->pghw_cu_kstat);
	}
}

int
pghw_kstat_update(kstat_t *ksp, int rw)
{
	struct pghw_kstat	*pgsp = &pghw_kstat;
	pghw_t			*pg = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	pgsp->pg_id.value.ui32 = ((pg_t *)pg)->pg_id;
	pgsp->pg_ncpus.value.ui32 = GROUP_SIZE(&((pg_t *)pg)->pg_cpus);
	pgsp->pg_instance_id.value.ui32 = pg->pghw_instance;
	kstat_named_setstr(&pgsp->pg_class, ((pg_t *)pg)->pg_class->pgc_name);
	kstat_named_setstr(&pgsp->pg_hw, pghw_type_string(pg->pghw_hw));
	kstat_named_setstr(&pgsp->pg_policy, pg_policy_name((pg_t *)pg));
	return (0);
}

int
pghw_cu_kstat_update(kstat_t *ksp, int rw)
{
	struct pghw_cu_kstat	*pgsp = &pghw_cu_kstat;
	pghw_t			*pg = ksp->ks_private;
	pghw_util_t		*hw_util = &pg->pghw_stats;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	pgsp->pg_id.value.ui32 = ((pg_t *)pg)->pg_id;
	pgsp->pg_ncpus.value.ui32 = GROUP_SIZE(&((pg_t *)pg)->pg_cpus);

	/*
	 * Allocate memory for the string representing the list of CPUs in PG.
	 * This memory should persist past the call to pghw_cu_kstat_update()
	 * since the kstat snapshot routine will reference this memory.
	 */
	pghw_cpulist_alloc(pg);

	if (pg->pghw_kstat_gen != pg->pghw_generation) {
		/*
		 * PG kstat generation number is out of sync with PG's
		 * generation mumber. It means that some CPUs could have joined
		 * or left PG and it is not possible to compare the numbers
		 * obtained before and after the generation change.
		 *
		 * Reset the maximum utilization rate and start computing it
		 * from scratch.
		 */
		hw_util->pghw_util = 0;
		hw_util->pghw_rate_max = 0;
		pg->pghw_kstat_gen = pg->pghw_generation;
	}

	/*
	 * We can't block on CPU lock because when PG is destroyed (under
	 * cpu_lock) it tries to delete this kstat and it will wait for us to
	 * complete which will never happen since we are waiting for cpu_lock to
	 * drop. Deadlocks are fun!
	 */
	if (mutex_tryenter(&cpu_lock)) {
		if (pg->pghw_cpulist != NULL &&
		    *(pg->pghw_cpulist) == '\0') {
			(void) group2intlist(&(((pg_t *)pg)->pg_cpus),
			    pg->pghw_cpulist, pg->pghw_cpulist_len, cpu2id);
		}
		cu_pg_update(pg);
		mutex_exit(&cpu_lock);
	}

	pgsp->pg_generation.value.ui32 = pg->pghw_kstat_gen;
	pgsp->pg_hw_util.value.ui64 = hw_util->pghw_util;
	pgsp->pg_hw_util_time_running.value.ui64 = hw_util->pghw_time_running;
	pgsp->pg_hw_util_time_stopped.value.ui64 = hw_util->pghw_time_stopped;
	pgsp->pg_hw_util_rate.value.ui64 = hw_util->pghw_rate;
	pgsp->pg_hw_util_rate_max.value.ui64 = hw_util->pghw_rate_max;
	if (pg->pghw_cpulist != NULL)
		kstat_named_setstr(&pgsp->pg_cpus, pg->pghw_cpulist);
	else
		kstat_named_setstr(&pgsp->pg_cpus, "");

	kstat_named_setstr(&pgsp->pg_sharing, pghw_type_string(pg->pghw_hw));

	return (0);
}

/*
 * Update the string representation of CPUs in PG (pg->pghw_cpulist).
 * The string representation is used for kstats.
 *
 * The string is allocated if it has not already been or if it is already
 * allocated and PG has more CPUs now. If PG has smaller or equal number of
 * CPUs, but the actual CPUs may have changed, the string is reset to the empty
 * string causes the string representation to be recreated. The pghw_generation
 * field is used to detect whether CPUs within the pg may have changed.
 */
static void
pghw_cpulist_alloc(pghw_t *pg)
{
	uint_t	ncpus = GROUP_SIZE(&((pg_t *)pg)->pg_cpus);
	size_t	len = CPUSTR_LEN(ncpus);

	/*
	 * If the pghw_cpulist string is already allocated we need to make sure
	 * that it has sufficient length. Also if the set of CPUs may have
	 * changed, we need to re-generate the string.
	 */
	if (pg->pghw_cpulist != NULL &&
	    pg->pghw_kstat_gen != pg->pghw_generation) {
		if (len <= pg->pghw_cpulist_len) {
			/*
			 * There is sufficient space in the pghw_cpulist for
			 * the new set of CPUs. Just clear the string to trigger
			 * re-generation of list of CPUs
			 */
			*(pg->pghw_cpulist) = '\0';
		} else {
			/*
			 * There is, potentially, insufficient space in
			 * pghw_cpulist, so reallocate the string.
			 */
			ASSERT(strlen(pg->pghw_cpulist) < pg->pghw_cpulist_len);
			kmem_free(pg->pghw_cpulist, pg->pghw_cpulist_len);
			pg->pghw_cpulist = NULL;
			pg->pghw_cpulist_len = 0;
		}
	}

	if (pg->pghw_cpulist == NULL) {
		/*
		 * Allocate space to hold cpulist.
		 *
		 * Length can not be bigger that the maximum space we have
		 * allowed for the kstat buffer
		 */
		if (len > pg_cpulist_maxlen)
			len = pg_cpulist_maxlen;
		if (len > 0) {
			pg->pghw_cpulist = kmem_zalloc(len, KM_NOSLEEP);
			if (pg->pghw_cpulist != NULL)
				pg->pghw_cpulist_len = len;
		}
	}
}

static int
cpu2id(void *v)
{
	cpu_t *cp = (cpu_t *)v;

	ASSERT(v != NULL);

	return (cp->cpu_id);
}
