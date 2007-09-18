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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * are instantiated. They are never destroyed, as once a given relathionship
 * type appears in the system, it is quite likely that at least one instance of
 * that relationship will always persist as long as the system is running.
 */

static group_t		*pg_hw;		/* top level pg hw group */

/*
 * Lookup table mapping hardware sharing relationships with hierarchy levels
 */
static int		pghw_level_table[PGHW_NUM_COMPONENTS];

/*
 * Physical PG kstats
 */
struct pghw_kstat {
	kstat_named_t	pg_id;
	kstat_named_t	pg_class;
	kstat_named_t	pg_ncpus;
	kstat_named_t	pg_instance_id;
	kstat_named_t	pg_hw;
} pghw_kstat = {
	{ "id",			KSTAT_DATA_UINT64 },
	{ "pg_class",		KSTAT_DATA_STRING },
	{ "ncpus",		KSTAT_DATA_UINT64 },
	{ "instance_id",	KSTAT_DATA_UINT64 },
	{ "hardware",		KSTAT_DATA_STRING },
};

kmutex_t		pghw_kstat_lock;

/*
 * hwset operations
 */
static group_t		*pghw_set_create(pghw_type_t);
static void		pghw_set_add(group_t *, pghw_t *);
static void		pghw_set_remove(group_t *, pghw_t *);

/*
 * Initialize the physical portion of a physical PG
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
	pg->pghw_instance =
	    pg_plat_hw_instance_id(cp, hw);
	pghw_kstat_create(pg);
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

	if (pg->pghw_kstat)
		kstat_delete(pg->pghw_kstat);
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
 * Return a sequential level identifier for the specified
 * hardware sharing relationship
 */
int
pghw_level(pghw_type_t hw)
{
	return (pg_plat_hw_level(hw));
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

	/*
	 * Update the table that maps hardware sharing relationships
	 * to hierarchy levels
	 */
	ASSERT(pghw_level_table[hw] == NULL);
	pghw_level_table[hw] = pg_plat_hw_level(hw);

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
#define	PGHW_TYPE_NAME_MAX	8

static char *
pghw_type_string(pghw_type_t hw)
{
	switch (hw) {
	case PGHW_IPIPE:
		return ("ipipe");
	case PGHW_CACHE:
		return ("cache");
	case PGHW_FPU:
		return ("fpu");
	case PGHW_MPIPE:
		return ("mpipe");
	case PGHW_CHIP:
		return ("chip");
	case PGHW_MEMORY:
		return ("memory");
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
	/*
	 * Create a physical pg kstat
	 */
	if ((pg->pghw_kstat = kstat_create("pg", ((pg_t *)pg)->pg_id,
	    "pg", "pg", KSTAT_TYPE_NAMED,
	    sizeof (pghw_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) != NULL) {
		pg->pghw_kstat->ks_data_size += PG_CLASS_NAME_MAX;
		pg->pghw_kstat->ks_data_size += PGHW_TYPE_NAME_MAX;
		pg->pghw_kstat->ks_lock = &pghw_kstat_lock;
		pg->pghw_kstat->ks_data = &pghw_kstat;
		pg->pghw_kstat->ks_update = pghw_kstat_update;
		pg->pghw_kstat->ks_private = pg;
		kstat_install(pg->pghw_kstat);
	}
}

int
pghw_kstat_update(kstat_t *ksp, int rw)
{
	struct pghw_kstat	*pgsp = &pghw_kstat;
	pghw_t			*pg = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	pgsp->pg_id.value.ui64 = ((pg_t *)pg)->pg_id;
	pgsp->pg_ncpus.value.ui64 = GROUP_SIZE(&((pg_t *)pg)->pg_cpus);
	pgsp->pg_instance_id.value.ui64 = (uint64_t)pg->pghw_instance;
	kstat_named_setstr(&pgsp->pg_class, ((pg_t *)pg)->pg_class->pgc_name);
	kstat_named_setstr(&pgsp->pg_hw, pghw_type_string(pg->pghw_hw));

	return (0);
}
