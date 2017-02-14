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

/*
 * vm_usage
 *
 * This file implements the getvmusage() private system call.
 * getvmusage() counts the amount of resident memory pages and swap
 * reserved by the specified process collective. A "process collective" is
 * the set of processes owned by a particular, zone, project, task, or user.
 *
 * rss and swap are counted so that for a given process collective, a page is
 * only counted once.  For example, this means that if multiple processes in
 * the same project map the same page, then the project will only be charged
 * once for that page.  On the other hand, if two processes in different
 * projects map the same page, then both projects will be charged
 * for the page.
 *
 * The vm_getusage() calculation is implemented so that the first thread
 * performs the rss/swap counting. Other callers will wait for that thread to
 * finish, copying the results.  This enables multiple rcapds and prstats to
 * consume data from the same calculation.  The results are also cached so that
 * a caller interested in recent results can just copy them instead of starting
 * a new calculation. The caller passes the maximium age (in seconds) of the
 * data.  If the cached data is young enough, the cache is copied, otherwise,
 * a new calculation is executed and the cache is replaced with the new
 * data.
 *
 * The rss calculation for each process collective is as follows:
 *
 *   - Inspect flags, determine if counting rss for zones, projects, tasks,
 *     and/or users.
 *   - For each proc:
 *	- Figure out proc's collectives (zone, project, task, and/or user).
 *	- For each seg in proc's address space:
 *		- If seg is private:
 *			- Lookup anons in the amp.
 *			- For incore pages not previously visited each of the
 *			  proc's collectives, add incore pagesize to each.
 *			  collective.
 *			  Anon's with a refcnt of 1 can be assummed to be not
 *			  previously visited.
 *			- For address ranges without anons in the amp:
 *				- Lookup pages in underlying vnode.
 *				- For incore pages not previously visiting for
 *				  each of the proc's collectives, add incore
 *				  pagesize to each collective.
 *		- If seg is shared:
 *			- Lookup pages in the shared amp or vnode.
 *			- For incore pages not previously visited for each of
 *			  the proc's collectives, add incore pagesize to each
 *			  collective.
 *
 * Swap is reserved by private segments, and shared anonymous segments.
 * The only shared anon segments which do not reserve swap are ISM segments
 * and schedctl segments, both of which can be identified by having
 * amp->swresv == 0.
 *
 * The swap calculation for each collective is as follows:
 *
 *   - Inspect flags, determine if counting rss for zones, projects, tasks,
 *     and/or users.
 *   - For each proc:
 *	- Figure out proc's collectives (zone, project, task, and/or user).
 *	- For each seg in proc's address space:
 *		- If seg is private:
 *			- Add svd->swresv pages to swap count for each of the
 *			  proc's collectives.
 *		- If seg is anon, shared, and amp->swresv != 0
 *			- For address ranges in amp not previously visited for
 *			  each of the proc's collectives, add size of address
 *			  range to the swap count for each collective.
 *
 * These two calculations are done simultaneously, with most of the work
 * being done in vmu_calculate_seg().  The results of the calculation are
 * copied into "vmu_data.vmu_cache_results".
 *
 * To perform the calculation, various things are tracked and cached:
 *
 *    - incore/not-incore page ranges for all vnodes.
 *	(vmu_data.vmu_all_vnodes_hash)
 *	This eliminates looking up the same page more than once.
 *
 *    - incore/not-incore page ranges for all shared amps.
 *	(vmu_data.vmu_all_amps_hash)
 *	This eliminates looking up the same page more than once.
 *
 *    - visited page ranges for each collective.
 *	   - per vnode (entity->vme_vnode_hash)
 *	   - per shared amp (entity->vme_amp_hash)
 *	For accurate counting of map-shared and COW-shared pages.
 *
 *    - visited private anons (refcnt > 1) for each collective.
 *	(entity->vme_anon_hash)
 *	For accurate counting of COW-shared pages.
 *
 * The common accounting structure is the vmu_entity_t, which represents
 * collectives:
 *
 *    - A zone.
 *    - A project, task, or user within a zone.
 *    - The entire system (vmu_data.vmu_system).
 *    - Each collapsed (col) project and user.  This means a given projid or
 *	uid, regardless of which zone the process is in.  For instance,
 *      project 0 in the global zone and project 0 in a non global zone are
 *	the same collapsed project.
 *
 *  Each entity structure tracks which pages have been already visited for
 *  that entity (via previously inspected processes) so that these pages are
 *  not double counted.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/zone.h>
#include <sys/proc.h>
#include <sys/project.h>
#include <sys/task.h>
#include <sys/thread.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/modhash.h>
#include <sys/modhash_impl.h>
#include <sys/shm.h>
#include <sys/swap.h>
#include <sys/synch.h>
#include <sys/systm.h>
#include <sys/var.h>
#include <sys/vm_usage.h>
#include <sys/zone.h>
#include <sys/sunddi.h>
#include <sys/avl.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/seg_vn.h>
#include <vm/seg_spt.h>

#define	VMUSAGE_HASH_SIZE		512

#define	VMUSAGE_TYPE_VNODE		1
#define	VMUSAGE_TYPE_AMP		2
#define	VMUSAGE_TYPE_ANON		3

#define	VMUSAGE_BOUND_UNKNOWN		0
#define	VMUSAGE_BOUND_INCORE		1
#define	VMUSAGE_BOUND_NOT_INCORE	2

#define	ISWITHIN(node, addr)	((node)->vmb_start <= addr && \
				    (node)->vmb_end >= addr ? 1 : 0)

/*
 * bounds for vnodes and shared amps
 * Each bound is either entirely incore, entirely not in core, or
 * entirely unknown.  bounds are stored in an avl tree sorted by start member
 * when in use, otherwise (free or temporary lists) they're strung
 * together off of vmb_next.
 */
typedef struct vmu_bound {
	avl_node_t vmb_node;
	struct vmu_bound *vmb_next; /* NULL in tree else on free or temp list */
	pgcnt_t vmb_start;  /* page offset in vnode/amp on which bound starts */
	pgcnt_t	vmb_end;    /* page offset in vnode/amp on which bound ends */
	char	vmb_type;   /* One of VMUSAGE_BOUND_* */
} vmu_bound_t;

/*
 * hash of visited objects (vnodes or shared amps)
 * key is address of vnode or amp.  Bounds lists known incore/non-incore
 * bounds for vnode/amp.
 */
typedef struct vmu_object {
	struct vmu_object	*vmo_next;	/* free list */
	caddr_t		vmo_key;
	short		vmo_type;
	avl_tree_t	vmo_bounds;
} vmu_object_t;

/*
 * Entity by which to count results.
 *
 * The entity structure keeps the current rss/swap counts for each entity
 * (zone, project, etc), and hashes of vm structures that have already
 * been visited for the entity.
 *
 * vme_next:	links the list of all entities currently being counted by
 *		vmu_calculate().
 *
 * vme_next_calc: links the list of entities related to the current process
 *		 being counted by vmu_calculate_proc().
 *
 * vmu_calculate_proc() walks all processes.  For each process, it makes a
 * list of the entities related to that process using vme_next_calc.  This
 * list changes each time vmu_calculate_proc() is called.
 *
 */
typedef struct vmu_entity {
	struct vmu_entity *vme_next;
	struct vmu_entity *vme_next_calc;
	mod_hash_t	*vme_vnode_hash; /* vnodes visited for entity */
	mod_hash_t	*vme_amp_hash;	 /* shared amps visited for entity */
	mod_hash_t	*vme_anon_hash;	 /* COW anons visited for entity */
	vmusage_t	vme_result;	 /* identifies entity and results */
} vmu_entity_t;

/*
 * Hash of entities visited within a zone, and an entity for the zone
 * itself.
 */
typedef struct vmu_zone {
	struct vmu_zone	*vmz_next;	/* free list */
	id_t		vmz_id;
	vmu_entity_t	*vmz_zone;
	mod_hash_t	*vmz_projects_hash;
	mod_hash_t	*vmz_tasks_hash;
	mod_hash_t	*vmz_rusers_hash;
	mod_hash_t	*vmz_eusers_hash;
} vmu_zone_t;

/*
 * Cache of results from last calculation
 */
typedef struct vmu_cache {
	vmusage_t	*vmc_results;	/* Results from last call to */
					/* vm_getusage(). */
	uint64_t	vmc_nresults;	/* Count of cached results */
	uint64_t	vmc_refcnt;	/* refcnt for free */
	uint_t		vmc_flags;	/* Flags for vm_getusage() */
	hrtime_t	vmc_timestamp;	/* when cache was created */
} vmu_cache_t;

/*
 * top level rss info for the system
 */
typedef struct vmu_data {
	kmutex_t	vmu_lock;		/* Protects vmu_data */
	kcondvar_t	vmu_cv;			/* Used to signal threads */
						/* Waiting for */
						/* Rss_calc_thread to finish */
	vmu_entity_t	*vmu_system;		/* Entity for tracking */
						/* rss/swap for all processes */
						/* in all zones */
	mod_hash_t	*vmu_zones_hash;	/* Zones visited */
	mod_hash_t	*vmu_projects_col_hash; /* These *_col_hash hashes */
	mod_hash_t	*vmu_rusers_col_hash;	/* keep track of entities, */
	mod_hash_t	*vmu_eusers_col_hash;	/* ignoring zoneid, in order */
						/* to implement VMUSAGE_COL_* */
						/* flags, which aggregate by */
						/* project or user regardless */
						/* of zoneid. */
	mod_hash_t	*vmu_all_vnodes_hash;	/* System wide visited vnodes */
						/* to track incore/not-incore */
	mod_hash_t	*vmu_all_amps_hash;	/* System wide visited shared */
						/* amps to track incore/not- */
						/* incore */
	vmu_entity_t	*vmu_entities;		/* Linked list of entities */
	size_t		vmu_nentities;		/* Count of entities in list */
	vmu_cache_t	*vmu_cache;		/* Cached results */
	kthread_t	*vmu_calc_thread;	/* NULL, or thread running */
						/* vmu_calculate() */
	uint_t		vmu_calc_flags;		/* Flags being using by */
						/* currently running calc */
						/* thread */
	uint_t		vmu_pending_flags;	/* Flags of vm_getusage() */
						/* threads waiting for */
						/* calc thread to finish */
	uint_t		vmu_pending_waiters;	/* Number of threads waiting */
						/* for calc thread */
	vmu_bound_t	*vmu_free_bounds;
	vmu_object_t	*vmu_free_objects;
	vmu_entity_t	*vmu_free_entities;
	vmu_zone_t	*vmu_free_zones;
} vmu_data_t;

extern struct as kas;
extern proc_t *practive;
extern zone_t *global_zone;
extern struct seg_ops segvn_ops;
extern struct seg_ops segspt_shmops;

static vmu_data_t vmu_data;
static kmem_cache_t *vmu_bound_cache;
static kmem_cache_t *vmu_object_cache;

/*
 * Comparison routine for AVL tree. We base our comparison on vmb_start.
 */
static int
bounds_cmp(const void *bnd1, const void *bnd2)
{
	const vmu_bound_t *bound1 = bnd1;
	const vmu_bound_t *bound2 = bnd2;

	if (bound1->vmb_start == bound2->vmb_start) {
		return (0);
	}
	if (bound1->vmb_start < bound2->vmb_start) {
		return (-1);
	}

	return (1);
}

/*
 * Save a bound on the free list.
 */
static void
vmu_free_bound(vmu_bound_t *bound)
{
	bound->vmb_next = vmu_data.vmu_free_bounds;
	bound->vmb_start = 0;
	bound->vmb_end = 0;
	bound->vmb_type = 0;
	vmu_data.vmu_free_bounds = bound;
}

/*
 * Free an object, and all visited bound info.
 */
static void
vmu_free_object(mod_hash_val_t val)
{
	vmu_object_t *obj = (vmu_object_t *)val;
	avl_tree_t *tree = &(obj->vmo_bounds);
	vmu_bound_t *bound;
	void *cookie = NULL;

	while ((bound = avl_destroy_nodes(tree, &cookie)) != NULL)
		vmu_free_bound(bound);
	avl_destroy(tree);

	obj->vmo_type = 0;
	obj->vmo_next = vmu_data.vmu_free_objects;
	vmu_data.vmu_free_objects = obj;
}

/*
 * Free an entity, and hashes of visited objects for that entity.
 */
static void
vmu_free_entity(mod_hash_val_t val)
{
	vmu_entity_t *entity = (vmu_entity_t *)val;

	if (entity->vme_vnode_hash != NULL)
		i_mod_hash_clear_nosync(entity->vme_vnode_hash);
	if (entity->vme_amp_hash != NULL)
		i_mod_hash_clear_nosync(entity->vme_amp_hash);
	if (entity->vme_anon_hash != NULL)
		i_mod_hash_clear_nosync(entity->vme_anon_hash);

	entity->vme_next = vmu_data.vmu_free_entities;
	vmu_data.vmu_free_entities = entity;
}

/*
 * Free zone entity, and all hashes of entities inside that zone,
 * which are projects, tasks, and users.
 */
static void
vmu_free_zone(mod_hash_val_t val)
{
	vmu_zone_t *zone = (vmu_zone_t *)val;

	if (zone->vmz_zone != NULL) {
		vmu_free_entity((mod_hash_val_t)zone->vmz_zone);
		zone->vmz_zone = NULL;
	}
	if (zone->vmz_projects_hash != NULL)
		i_mod_hash_clear_nosync(zone->vmz_projects_hash);
	if (zone->vmz_tasks_hash != NULL)
		i_mod_hash_clear_nosync(zone->vmz_tasks_hash);
	if (zone->vmz_rusers_hash != NULL)
		i_mod_hash_clear_nosync(zone->vmz_rusers_hash);
	if (zone->vmz_eusers_hash != NULL)
		i_mod_hash_clear_nosync(zone->vmz_eusers_hash);
	zone->vmz_next = vmu_data.vmu_free_zones;
	vmu_data.vmu_free_zones = zone;
}

/*
 * Initialize synchronization primitives and hashes for system-wide tracking
 * of visited vnodes and shared amps.  Initialize results cache.
 */
void
vm_usage_init()
{
	mutex_init(&vmu_data.vmu_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&vmu_data.vmu_cv, NULL, CV_DEFAULT, NULL);

	vmu_data.vmu_system = NULL;
	vmu_data.vmu_zones_hash = NULL;
	vmu_data.vmu_projects_col_hash = NULL;
	vmu_data.vmu_rusers_col_hash = NULL;
	vmu_data.vmu_eusers_col_hash = NULL;

	vmu_data.vmu_free_bounds = NULL;
	vmu_data.vmu_free_objects = NULL;
	vmu_data.vmu_free_entities = NULL;
	vmu_data.vmu_free_zones = NULL;

	vmu_data.vmu_all_vnodes_hash = mod_hash_create_ptrhash(
	    "vmusage vnode hash", VMUSAGE_HASH_SIZE, vmu_free_object,
	    sizeof (vnode_t));
	vmu_data.vmu_all_amps_hash = mod_hash_create_ptrhash(
	    "vmusage amp hash", VMUSAGE_HASH_SIZE, vmu_free_object,
	    sizeof (struct anon_map));
	vmu_data.vmu_projects_col_hash = mod_hash_create_idhash(
	    "vmusage collapsed project hash", VMUSAGE_HASH_SIZE,
	    vmu_free_entity);
	vmu_data.vmu_rusers_col_hash = mod_hash_create_idhash(
	    "vmusage collapsed ruser hash", VMUSAGE_HASH_SIZE,
	    vmu_free_entity);
	vmu_data.vmu_eusers_col_hash = mod_hash_create_idhash(
	    "vmusage collpased euser hash", VMUSAGE_HASH_SIZE,
	    vmu_free_entity);
	vmu_data.vmu_zones_hash = mod_hash_create_idhash(
	    "vmusage zone hash", VMUSAGE_HASH_SIZE, vmu_free_zone);

	vmu_bound_cache = kmem_cache_create("vmu_bound_cache",
	    sizeof (vmu_bound_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	vmu_object_cache = kmem_cache_create("vmu_object_cache",
	    sizeof (vmu_object_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	vmu_data.vmu_entities = NULL;
	vmu_data.vmu_nentities = 0;

	vmu_data.vmu_cache = NULL;
	vmu_data.vmu_calc_thread = NULL;
	vmu_data.vmu_calc_flags = 0;
	vmu_data.vmu_pending_flags = 0;
	vmu_data.vmu_pending_waiters = 0;
}

/*
 * Allocate hashes for tracking vm objects visited for an entity.
 * Update list of entities.
 */
static vmu_entity_t *
vmu_alloc_entity(id_t id, int type, id_t zoneid)
{
	vmu_entity_t *entity;

	if (vmu_data.vmu_free_entities != NULL) {
		entity = vmu_data.vmu_free_entities;
		vmu_data.vmu_free_entities =
		    vmu_data.vmu_free_entities->vme_next;
		bzero(&entity->vme_result, sizeof (vmusage_t));
	} else {
		entity = kmem_zalloc(sizeof (vmu_entity_t), KM_SLEEP);
	}
	entity->vme_result.vmu_id = id;
	entity->vme_result.vmu_zoneid = zoneid;
	entity->vme_result.vmu_type = type;

	if (entity->vme_vnode_hash == NULL)
		entity->vme_vnode_hash = mod_hash_create_ptrhash(
		    "vmusage vnode hash", VMUSAGE_HASH_SIZE, vmu_free_object,
		    sizeof (vnode_t));

	if (entity->vme_amp_hash == NULL)
		entity->vme_amp_hash = mod_hash_create_ptrhash(
		    "vmusage amp hash", VMUSAGE_HASH_SIZE, vmu_free_object,
		    sizeof (struct anon_map));

	if (entity->vme_anon_hash == NULL)
		entity->vme_anon_hash = mod_hash_create_ptrhash(
		    "vmusage anon hash", VMUSAGE_HASH_SIZE,
		    mod_hash_null_valdtor, sizeof (struct anon));

	entity->vme_next = vmu_data.vmu_entities;
	vmu_data.vmu_entities = entity;
	vmu_data.vmu_nentities++;

	return (entity);
}

/*
 * Allocate a zone entity, and hashes for tracking visited vm objects
 * for projects, tasks, and users within that zone.
 */
static vmu_zone_t *
vmu_alloc_zone(id_t id)
{
	vmu_zone_t *zone;

	if (vmu_data.vmu_free_zones != NULL) {
		zone = vmu_data.vmu_free_zones;
		vmu_data.vmu_free_zones =
		    vmu_data.vmu_free_zones->vmz_next;
		zone->vmz_next = NULL;
		zone->vmz_zone = NULL;
	} else {
		zone = kmem_zalloc(sizeof (vmu_zone_t), KM_SLEEP);
	}

	zone->vmz_id = id;

	if ((vmu_data.vmu_calc_flags & (VMUSAGE_ZONE | VMUSAGE_ALL_ZONES)) != 0)
		zone->vmz_zone = vmu_alloc_entity(id, VMUSAGE_ZONE, id);

	if ((vmu_data.vmu_calc_flags & (VMUSAGE_PROJECTS |
	    VMUSAGE_ALL_PROJECTS)) != 0 && zone->vmz_projects_hash == NULL)
		zone->vmz_projects_hash = mod_hash_create_idhash(
		    "vmusage project hash", VMUSAGE_HASH_SIZE, vmu_free_entity);

	if ((vmu_data.vmu_calc_flags & (VMUSAGE_TASKS | VMUSAGE_ALL_TASKS))
	    != 0 && zone->vmz_tasks_hash == NULL)
		zone->vmz_tasks_hash = mod_hash_create_idhash(
		    "vmusage task hash", VMUSAGE_HASH_SIZE, vmu_free_entity);

	if ((vmu_data.vmu_calc_flags & (VMUSAGE_RUSERS | VMUSAGE_ALL_RUSERS))
	    != 0 && zone->vmz_rusers_hash == NULL)
		zone->vmz_rusers_hash = mod_hash_create_idhash(
		    "vmusage ruser hash", VMUSAGE_HASH_SIZE, vmu_free_entity);

	if ((vmu_data.vmu_calc_flags & (VMUSAGE_EUSERS | VMUSAGE_ALL_EUSERS))
	    != 0 && zone->vmz_eusers_hash == NULL)
		zone->vmz_eusers_hash = mod_hash_create_idhash(
		    "vmusage euser hash", VMUSAGE_HASH_SIZE, vmu_free_entity);

	return (zone);
}

/*
 * Allocate a structure for tracking visited bounds for a vm object.
 */
static vmu_object_t *
vmu_alloc_object(caddr_t key, int type)
{
	vmu_object_t *object;

	if (vmu_data.vmu_free_objects != NULL) {
		object = vmu_data.vmu_free_objects;
		vmu_data.vmu_free_objects =
		    vmu_data.vmu_free_objects->vmo_next;
	} else {
		object = kmem_cache_alloc(vmu_object_cache, KM_SLEEP);
	}

	object->vmo_next = NULL;
	object->vmo_key = key;
	object->vmo_type = type;
	avl_create(&(object->vmo_bounds), bounds_cmp, sizeof (vmu_bound_t), 0);

	return (object);
}

/*
 * Allocate and return a bound structure.
 */
static vmu_bound_t *
vmu_alloc_bound()
{
	vmu_bound_t *bound;

	if (vmu_data.vmu_free_bounds != NULL) {
		bound = vmu_data.vmu_free_bounds;
		vmu_data.vmu_free_bounds =
		    vmu_data.vmu_free_bounds->vmb_next;
	} else {
		bound = kmem_cache_alloc(vmu_bound_cache, KM_SLEEP);
	}

	bound->vmb_next = NULL;
	bound->vmb_start = 0;
	bound->vmb_end = 0;
	bound->vmb_type = 0;
	return (bound);
}

/*
 * vmu_find_insert_* functions implement hash lookup or allocate and
 * insert operations.
 */
static vmu_object_t *
vmu_find_insert_object(mod_hash_t *hash, caddr_t key, uint_t type)
{
	int ret;
	vmu_object_t *object;

	ret = i_mod_hash_find_nosync(hash, (mod_hash_key_t)key,
	    (mod_hash_val_t *)&object);
	if (ret != 0) {
		object = vmu_alloc_object(key, type);
		ret = i_mod_hash_insert_nosync(hash, (mod_hash_key_t)key,
		    (mod_hash_val_t)object, (mod_hash_hndl_t)0);
		ASSERT(ret == 0);
	}
	return (object);
}

static int
vmu_find_insert_anon(mod_hash_t *hash, caddr_t key)
{
	int ret;
	caddr_t val;

	ret = i_mod_hash_find_nosync(hash, (mod_hash_key_t)key,
	    (mod_hash_val_t *)&val);

	if (ret == 0)
		return (0);

	ret = i_mod_hash_insert_nosync(hash, (mod_hash_key_t)key,
	    (mod_hash_val_t)key, (mod_hash_hndl_t)0);

	ASSERT(ret == 0);

	return (1);
}

static vmu_entity_t *
vmu_find_insert_entity(mod_hash_t *hash, id_t id, uint_t type, id_t zoneid)
{
	int ret;
	vmu_entity_t *entity;

	ret = i_mod_hash_find_nosync(hash, (mod_hash_key_t)(uintptr_t)id,
	    (mod_hash_val_t *)&entity);
	if (ret != 0) {
		entity = vmu_alloc_entity(id, type, zoneid);
		ret = i_mod_hash_insert_nosync(hash,
		    (mod_hash_key_t)(uintptr_t)id, (mod_hash_val_t)entity,
		    (mod_hash_hndl_t)0);
		ASSERT(ret == 0);
	}
	return (entity);
}




/*
 * Returns list of object bounds between start and end.  New bounds inserted
 * by this call are given type.
 *
 * Returns the number of pages covered if new bounds are created.  Returns 0
 * if region between start/end consists of all existing bounds.
 */
static pgcnt_t
vmu_insert_lookup_object_bounds(vmu_object_t *ro, pgcnt_t start, pgcnt_t
    end, char type, vmu_bound_t **first, vmu_bound_t **last)
{
	avl_tree_t	*tree = &(ro->vmo_bounds);
	avl_index_t	where;
	vmu_bound_t	*walker, *tmp;
	pgcnt_t		ret = 0;

	ASSERT(start <= end);

	*first = *last = NULL;

	tmp = vmu_alloc_bound();
	tmp->vmb_start = start;
	tmp->vmb_type = type;

	/* Hopelessly optimistic case. */
	if (walker = avl_find(tree, tmp, &where)) {
		/* We got lucky. */
		vmu_free_bound(tmp);
		*first = walker;
	}

	if (walker == NULL) {
		/* Is start in the previous node? */
		walker = avl_nearest(tree, where, AVL_BEFORE);
		if (walker != NULL) {
			if (ISWITHIN(walker, start)) {
				/* We found start. */
				vmu_free_bound(tmp);
				*first = walker;
			}
		}
	}

	/*
	 * At this point, if *first is still NULL, then we
	 * didn't get a direct hit and start isn't covered
	 * by the previous node. We know that the next node
	 * must have a greater start value than we require
	 * because avl_find tells us where the AVL routines would
	 * insert our new node. We have some gap between the
	 * start we want and the next node.
	 */
	if (*first == NULL) {
		walker = avl_nearest(tree, where, AVL_AFTER);
		if (walker != NULL && walker->vmb_start <= end) {
			/* Fill the gap. */
			tmp->vmb_end = walker->vmb_start - 1;
			*first = tmp;
		} else {
			/* We have a gap over [start, end]. */
			tmp->vmb_end = end;
			*first = *last = tmp;
		}
		ret += tmp->vmb_end - tmp->vmb_start + 1;
		avl_insert(tree, tmp, where);
	}

	ASSERT(*first != NULL);

	if (*last != NULL) {
		/* We're done. */
		return (ret);
	}

	/*
	 * If we are here we still need to set *last and
	 * that may involve filling in some gaps.
	 */
	*last = *first;
	for (;;) {
		if (ISWITHIN(*last, end)) {
			/* We're done. */
			break;
		}
		walker = AVL_NEXT(tree, *last);
		if (walker == NULL || walker->vmb_start > end) {
			/* Bottom or mid tree with gap. */
			tmp = vmu_alloc_bound();
			tmp->vmb_start = (*last)->vmb_end + 1;
			tmp->vmb_end = end;
			tmp->vmb_type = type;
			ret += tmp->vmb_end - tmp->vmb_start + 1;
			avl_insert_here(tree, tmp, *last, AVL_AFTER);
			*last = tmp;
			break;
		} else {
			if ((*last)->vmb_end + 1 != walker->vmb_start) {
				/* Non-contiguous. */
				tmp = vmu_alloc_bound();
				tmp->vmb_start = (*last)->vmb_end + 1;
				tmp->vmb_end = walker->vmb_start - 1;
				tmp->vmb_type = type;
				ret += tmp->vmb_end - tmp->vmb_start + 1;
				avl_insert_here(tree, tmp, *last, AVL_AFTER);
				*last = tmp;
			} else {
				*last = walker;
			}
		}
	}

	return (ret);
}

/*
 * vmu_update_bounds()
 *
 * tree: avl_tree in which first and last hang.
 *
 * first, last:	list of continuous bounds, of which zero or more are of
 * 		type VMUSAGE_BOUND_UNKNOWN.
 *
 * new_tree: avl_tree in which new_first and new_last hang.
 *
 * new_first, new_last:	list of continuous bounds, of which none are of
 *			type VMUSAGE_BOUND_UNKNOWN.  These bounds are used to
 *			update the types of bounds in (first,last) with
 *			type VMUSAGE_BOUND_UNKNOWN.
 *
 * For the list of bounds (first,last), this function updates any bounds
 * with type VMUSAGE_BOUND_UNKNOWN using the type of the corresponding bound in
 * the list (new_first, new_last).
 *
 * If a bound of type VMUSAGE_BOUND_UNKNOWN spans multiple bounds in the list
 * (new_first, new_last), it will be split into multiple bounds.
 *
 * Return value:
 * 	The number of pages in the list of bounds (first,last) that were of
 *	type VMUSAGE_BOUND_UNKNOWN, which have been updated to be of type
 *	VMUSAGE_BOUND_INCORE.
 *
 */
static pgcnt_t
vmu_update_bounds(avl_tree_t *tree, vmu_bound_t **first, vmu_bound_t **last,
    avl_tree_t *new_tree, vmu_bound_t *new_first, vmu_bound_t *new_last)
{
	vmu_bound_t *next, *new_next, *tmp;
	pgcnt_t rss = 0;

	next = *first;
	new_next = new_first;

	/*
	 * Verify first and last bound are covered by new bounds if they
	 * have unknown type.
	 */
	ASSERT((*first)->vmb_type != VMUSAGE_BOUND_UNKNOWN ||
	    (*first)->vmb_start >= new_first->vmb_start);
	ASSERT((*last)->vmb_type != VMUSAGE_BOUND_UNKNOWN ||
	    (*last)->vmb_end <= new_last->vmb_end);
	for (;;) {
		/* If bound already has type, proceed to next bound. */
		if (next->vmb_type != VMUSAGE_BOUND_UNKNOWN) {
			if (next == *last)
				break;
			next = AVL_NEXT(tree, next);
			continue;
		}
		while (new_next->vmb_end < next->vmb_start)
			new_next = AVL_NEXT(new_tree, new_next);
		ASSERT(new_next->vmb_type != VMUSAGE_BOUND_UNKNOWN);
		next->vmb_type = new_next->vmb_type;
		if (new_next->vmb_end < next->vmb_end) {
			/* need to split bound */
			tmp = vmu_alloc_bound();
			tmp->vmb_type = VMUSAGE_BOUND_UNKNOWN;
			tmp->vmb_start = new_next->vmb_end + 1;
			tmp->vmb_end = next->vmb_end;
			avl_insert_here(tree, tmp, next, AVL_AFTER);
			next->vmb_end = new_next->vmb_end;
			if (*last == next)
				*last = tmp;
			if (next->vmb_type == VMUSAGE_BOUND_INCORE)
				rss += next->vmb_end - next->vmb_start + 1;
			next = tmp;
		} else {
			if (next->vmb_type == VMUSAGE_BOUND_INCORE)
				rss += next->vmb_end - next->vmb_start + 1;
			if (next == *last)
				break;
			next = AVL_NEXT(tree, next);
		}
	}
	return (rss);
}

/*
 * Merges adjacent bounds with same type between first and last bound.
 * After merge, last pointer may point to a different bound, as (incoming)
 * last bound may have been merged away.
 */
static void
vmu_merge_bounds(avl_tree_t *tree, vmu_bound_t **first, vmu_bound_t **last)
{
	vmu_bound_t *current;
	vmu_bound_t *next;

	ASSERT(tree != NULL);
	ASSERT(*first != NULL);
	ASSERT(*last != NULL);

	current = *first;
	while (current != *last) {
		next = AVL_NEXT(tree, current);
		if ((current->vmb_end + 1) == next->vmb_start &&
		    current->vmb_type == next->vmb_type) {
			current->vmb_end = next->vmb_end;
			avl_remove(tree, next);
			vmu_free_bound(next);
			if (next == *last) {
				*last = current;
			}
		} else {
			current = AVL_NEXT(tree, current);
		}
	}
}

/*
 * Given an amp and a list of bounds, updates each bound's type with
 * VMUSAGE_BOUND_INCORE or VMUSAGE_BOUND_NOT_INCORE.
 *
 * If a bound is partially incore, it will be split into two bounds.
 * first and last may be modified, as bounds may be split into multiple
 * bounds if they are partially incore/not-incore.
 *
 * Set incore to non-zero if bounds are already known to be incore.
 *
 */
static void
vmu_amp_update_incore_bounds(avl_tree_t *tree, struct anon_map *amp,
    vmu_bound_t **first, vmu_bound_t **last, boolean_t incore)
{
	vmu_bound_t *next;
	vmu_bound_t *tmp;
	pgcnt_t index;
	short bound_type;
	short page_type;
	vnode_t *vn;
	anoff_t off;
	struct anon *ap;

	next = *first;
	/* Shared anon slots don't change once set. */
	ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
	for (;;) {
		if (incore == B_TRUE)
			next->vmb_type = VMUSAGE_BOUND_INCORE;

		if (next->vmb_type != VMUSAGE_BOUND_UNKNOWN) {
			if (next == *last)
				break;
			next = AVL_NEXT(tree, next);
			continue;
		}
		bound_type = next->vmb_type;
		index = next->vmb_start;
		while (index <= next->vmb_end) {

			/*
			 * These are used to determine how much to increment
			 * index when a large page is found.
			 */
			page_t *page;
			pgcnt_t pgcnt = 1;
			uint_t pgshft;
			pgcnt_t pgmsk;

			ap = anon_get_ptr(amp->ahp, index);
			if (ap != NULL)
				swap_xlate(ap, &vn, &off);

			if (ap != NULL && vn != NULL && vn->v_pages != NULL &&
			    (page = page_exists(vn, off)) != NULL) {
				page_type = VMUSAGE_BOUND_INCORE;
				if (page->p_szc > 0) {
					pgcnt = page_get_pagecnt(page->p_szc);
					pgshft = page_get_shift(page->p_szc);
					pgmsk = (0x1 << (pgshft - PAGESHIFT))
					    - 1;
				}
			} else {
				page_type = VMUSAGE_BOUND_NOT_INCORE;
			}
			if (bound_type == VMUSAGE_BOUND_UNKNOWN) {
				next->vmb_type = page_type;
			} else if (next->vmb_type != page_type) {
				/*
				 * If current bound type does not match page
				 * type, need to split off new bound.
				 */
				tmp = vmu_alloc_bound();
				tmp->vmb_type = page_type;
				tmp->vmb_start = index;
				tmp->vmb_end = next->vmb_end;
				avl_insert_here(tree, tmp, next, AVL_AFTER);
				next->vmb_end = index - 1;
				if (*last == next)
					*last = tmp;
				next = tmp;
			}
			if (pgcnt > 1) {
				/*
				 * If inside large page, jump to next large
				 * page
				 */
				index = (index & ~pgmsk) + pgcnt;
			} else {
				index++;
			}
		}
		if (next == *last) {
			ASSERT(next->vmb_type != VMUSAGE_BOUND_UNKNOWN);
			break;
		} else
			next = AVL_NEXT(tree, next);
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);
}

/*
 * Same as vmu_amp_update_incore_bounds(), except for tracking
 * incore-/not-incore for vnodes.
 */
static void
vmu_vnode_update_incore_bounds(avl_tree_t *tree, vnode_t *vnode,
    vmu_bound_t **first, vmu_bound_t **last)
{
	vmu_bound_t *next;
	vmu_bound_t *tmp;
	pgcnt_t index;
	short bound_type;
	short page_type;

	next = *first;
	for (;;) {
		if (vnode->v_pages == NULL)
			next->vmb_type = VMUSAGE_BOUND_NOT_INCORE;

		if (next->vmb_type != VMUSAGE_BOUND_UNKNOWN) {
			if (next == *last)
				break;
			next = AVL_NEXT(tree, next);
			continue;
		}

		bound_type = next->vmb_type;
		index = next->vmb_start;
		while (index <= next->vmb_end) {

			/*
			 * These are used to determine how much to increment
			 * index when a large page is found.
			 */
			page_t *page;
			pgcnt_t pgcnt = 1;
			uint_t pgshft;
			pgcnt_t pgmsk;

			if (vnode->v_pages != NULL &&
			    (page = page_exists(vnode, ptob(index))) != NULL) {
				page_type = VMUSAGE_BOUND_INCORE;
				if (page->p_szc > 0) {
					pgcnt = page_get_pagecnt(page->p_szc);
					pgshft = page_get_shift(page->p_szc);
					pgmsk = (0x1 << (pgshft - PAGESHIFT))
					    - 1;
				}
			} else {
				page_type = VMUSAGE_BOUND_NOT_INCORE;
			}
			if (bound_type == VMUSAGE_BOUND_UNKNOWN) {
				next->vmb_type = page_type;
			} else if (next->vmb_type != page_type) {
				/*
				 * If current bound type does not match page
				 * type, need to split off new bound.
				 */
				tmp = vmu_alloc_bound();
				tmp->vmb_type = page_type;
				tmp->vmb_start = index;
				tmp->vmb_end = next->vmb_end;
				avl_insert_here(tree, tmp, next, AVL_AFTER);
				next->vmb_end = index - 1;
				if (*last == next)
					*last = tmp;
				next = tmp;
			}
			if (pgcnt > 1) {
				/*
				 * If inside large page, jump to next large
				 * page
				 */
				index = (index & ~pgmsk) + pgcnt;
			} else {
				index++;
			}
		}
		if (next == *last) {
			ASSERT(next->vmb_type != VMUSAGE_BOUND_UNKNOWN);
			break;
		} else
			next = AVL_NEXT(tree, next);
	}
}

/*
 * Calculate the rss and swap consumed by a segment.  vmu_entities is the
 * list of entities to visit.  For shared segments, the vnode or amp
 * is looked up in each entity to see if it has been already counted.  Private
 * anon pages are checked per entity to ensure that COW pages are not
 * double counted.
 *
 * For private mapped files, first the amp is checked for private pages.
 * Bounds not backed by the amp are looked up in the vnode for each entity
 * to avoid double counting of private COW vnode pages.
 */
static void
vmu_calculate_seg(vmu_entity_t *vmu_entities, struct seg *seg)
{
	struct segvn_data *svd;
	struct shm_data *shmd;
	struct spt_data *sptd;
	vmu_object_t *shared_object = NULL;
	vmu_object_t *entity_object = NULL;
	vmu_entity_t *entity;
	vmusage_t *result;
	vmu_bound_t *first = NULL;
	vmu_bound_t *last = NULL;
	vmu_bound_t *cur = NULL;
	vmu_bound_t *e_first = NULL;
	vmu_bound_t *e_last = NULL;
	vmu_bound_t *tmp;
	pgcnt_t p_index, s_index, p_start, p_end, s_start, s_end, rss, virt;
	struct anon_map *private_amp = NULL;
	boolean_t incore = B_FALSE;
	boolean_t shared = B_FALSE;
	int file = 0;
	pgcnt_t swresv = 0;
	pgcnt_t panon = 0;

	/* Can zero-length segments exist?  Not sure, so paranoia. */
	if (seg->s_size <= 0)
		return;

	/*
	 * Figure out if there is a shared object (such as a named vnode or
	 * a shared amp, then figure out if there is a private amp, which
	 * identifies private pages.
	 */
	if (seg->s_ops == &segvn_ops) {
		svd = (struct segvn_data *)seg->s_data;
		if (svd->type == MAP_SHARED) {
			shared = B_TRUE;
		} else {
			swresv = svd->swresv;

			if (SEGVN_LOCK_TRYENTER(seg->s_as, &svd->lock,
			    RW_READER) != 0) {
				/*
				 * Text replication anon maps can be shared
				 * across all zones. Space used for text
				 * replication is typically capped as a small %
				 * of memory.  To keep it simple for now we
				 * don't account for swap and memory space used
				 * for text replication.
				 */
				if (svd->tr_state == SEGVN_TR_OFF &&
				    svd->amp != NULL) {
					private_amp = svd->amp;
					p_start = svd->anon_index;
					p_end = svd->anon_index +
					    btop(seg->s_size) - 1;
				}
				SEGVN_LOCK_EXIT(seg->s_as, &svd->lock);
			}
		}
		if (svd->vp != NULL) {
			file = 1;
			shared_object = vmu_find_insert_object(
			    vmu_data.vmu_all_vnodes_hash, (caddr_t)svd->vp,
			    VMUSAGE_TYPE_VNODE);
			s_start = btop(svd->offset);
			s_end = btop(svd->offset + seg->s_size) - 1;
		}
		if (svd->amp != NULL && svd->type == MAP_SHARED) {
			ASSERT(shared_object == NULL);
			shared_object = vmu_find_insert_object(
			    vmu_data.vmu_all_amps_hash, (caddr_t)svd->amp,
			    VMUSAGE_TYPE_AMP);
			s_start = svd->anon_index;
			s_end = svd->anon_index + btop(seg->s_size) - 1;
			/* schedctl mappings are always in core */
			if (svd->amp->swresv == 0)
				incore = B_TRUE;
		}
	} else if (seg->s_ops == &segspt_shmops) {
		shared = B_TRUE;
		shmd = (struct shm_data *)seg->s_data;
		shared_object = vmu_find_insert_object(
		    vmu_data.vmu_all_amps_hash, (caddr_t)shmd->shm_amp,
		    VMUSAGE_TYPE_AMP);
		s_start = 0;
		s_end = btop(seg->s_size) - 1;
		sptd = shmd->shm_sptseg->s_data;

		/* ism segments are always incore and do not reserve swap */
		if (sptd->spt_flags & SHM_SHARE_MMU)
			incore = B_TRUE;

	} else {
		return;
	}

	/*
	 * If there is a private amp, count anon pages that exist.  If an
	 * anon has a refcnt > 1 (COW sharing), then save the anon in a
	 * hash so that it is not double counted.
	 *
	 * If there is also a shared object, then figure out the bounds
	 * which are not mapped by the private amp.
	 */
	if (private_amp != NULL) {

		/* Enter as writer to prevent COW anons from being freed */
		ANON_LOCK_ENTER(&private_amp->a_rwlock, RW_WRITER);

		p_index = p_start;
		s_index = s_start;

		while (p_index <= p_end) {

			pgcnt_t p_index_next;
			pgcnt_t p_bound_size;
			int cnt;
			anoff_t off;
			struct vnode *vn;
			struct anon *ap;
			page_t *page;		/* For handling of large */
			pgcnt_t pgcnt = 1;	/* pages */
			pgcnt_t pgstart;
			pgcnt_t pgend;
			uint_t pgshft;
			pgcnt_t pgmsk;

			p_index_next = p_index;
			ap = anon_get_next_ptr(private_amp->ahp,
			    &p_index_next);

			/*
			 * If next anon is past end of mapping, simulate
			 * end of anon so loop terminates.
			 */
			if (p_index_next > p_end) {
				p_index_next = p_end + 1;
				ap = NULL;
			}
			/*
			 * For COW segments, keep track of bounds not
			 * backed by private amp so they can be looked
			 * up in the backing vnode
			 */
			if (p_index_next != p_index) {

				/*
				 * Compute index difference between anon and
				 * previous anon.
				 */
				p_bound_size = p_index_next - p_index - 1;

				if (shared_object != NULL) {
					cur = vmu_alloc_bound();
					cur->vmb_start = s_index;
					cur->vmb_end = s_index + p_bound_size;
					cur->vmb_type = VMUSAGE_BOUND_UNKNOWN;
					if (first == NULL) {
						first = cur;
						last = cur;
					} else {
						last->vmb_next = cur;
						last = cur;
					}
				}
				p_index = p_index + p_bound_size + 1;
				s_index = s_index + p_bound_size + 1;
			}

			/* Detect end of anons in amp */
			if (ap == NULL)
				break;

			cnt = ap->an_refcnt;
			swap_xlate(ap, &vn, &off);

			if (vn == NULL || vn->v_pages == NULL ||
			    (page = page_exists(vn, off)) == NULL) {
				p_index++;
				s_index++;
				continue;
			}

			/*
			 * If large page is found, compute portion of large
			 * page in mapping, and increment indicies to the next
			 * large page.
			 */
			if (page->p_szc > 0) {

				pgcnt = page_get_pagecnt(page->p_szc);
				pgshft = page_get_shift(page->p_szc);
				pgmsk = (0x1 << (pgshft - PAGESHIFT)) - 1;

				/* First page in large page */
				pgstart = p_index & ~pgmsk;
				/* Last page in large page */
				pgend = pgstart + pgcnt - 1;
				/*
				 * Artifically end page if page extends past
				 * end of mapping.
				 */
				if (pgend > p_end)
					pgend = p_end;

				/*
				 * Compute number of pages from large page
				 * which are mapped.
				 */
				pgcnt = pgend - p_index + 1;

				/*
				 * Point indicies at page after large page,
				 * or at page after end of mapping.
				 */
				p_index += pgcnt;
				s_index += pgcnt;
			} else {
				p_index++;
				s_index++;
			}

			/*
			 * Assume anon structs with a refcnt
			 * of 1 are not COW shared, so there
			 * is no reason to track them per entity.
			 */
			if (cnt == 1) {
				panon += pgcnt;
				continue;
			}
			for (entity = vmu_entities; entity != NULL;
			    entity = entity->vme_next_calc) {

				result = &entity->vme_result;
				/*
				 * Track COW anons per entity so
				 * they are not double counted.
				 */
				if (vmu_find_insert_anon(entity->vme_anon_hash,
				    (caddr_t)ap) == 0)
					continue;

				result->vmu_rss_all += (pgcnt << PAGESHIFT);
				result->vmu_rss_private +=
				    (pgcnt << PAGESHIFT);
			}
		}
		ANON_LOCK_EXIT(&private_amp->a_rwlock);
	}

	/* Add up resident anon and swap reserved for private mappings */
	if (swresv > 0 || panon > 0) {
		for (entity = vmu_entities; entity != NULL;
		    entity = entity->vme_next_calc) {
			result = &entity->vme_result;
			result->vmu_swap_all += swresv;
			result->vmu_swap_private += swresv;
			result->vmu_rss_all += (panon << PAGESHIFT);
			result->vmu_rss_private += (panon << PAGESHIFT);
		}
	}

	/* Compute resident pages backing shared amp or named vnode */
	if (shared_object != NULL) {
		avl_tree_t *tree = &(shared_object->vmo_bounds);

		if (first == NULL) {
			/*
			 * No private amp, or private amp has no anon
			 * structs.  This means entire segment is backed by
			 * the shared object.
			 */
			first = vmu_alloc_bound();
			first->vmb_start = s_start;
			first->vmb_end = s_end;
			first->vmb_type = VMUSAGE_BOUND_UNKNOWN;
		}
		/*
		 * Iterate bounds not backed by private amp, and compute
		 * resident pages.
		 */
		cur = first;
		while (cur != NULL) {

			if (vmu_insert_lookup_object_bounds(shared_object,
			    cur->vmb_start, cur->vmb_end, VMUSAGE_BOUND_UNKNOWN,
			    &first, &last) > 0) {
				/* new bounds, find incore/not-incore */
				if (shared_object->vmo_type ==
				    VMUSAGE_TYPE_VNODE) {
					vmu_vnode_update_incore_bounds(
					    tree,
					    (vnode_t *)
					    shared_object->vmo_key, &first,
					    &last);
				} else {
					vmu_amp_update_incore_bounds(
					    tree,
					    (struct anon_map *)
					    shared_object->vmo_key, &first,
					    &last, incore);
				}
				vmu_merge_bounds(tree, &first, &last);
			}
			for (entity = vmu_entities; entity != NULL;
			    entity = entity->vme_next_calc) {
				avl_tree_t *e_tree;

				result = &entity->vme_result;

				entity_object = vmu_find_insert_object(
				    shared_object->vmo_type ==
				    VMUSAGE_TYPE_VNODE ? entity->vme_vnode_hash:
				    entity->vme_amp_hash,
				    shared_object->vmo_key,
				    shared_object->vmo_type);

				virt = vmu_insert_lookup_object_bounds(
				    entity_object, cur->vmb_start, cur->vmb_end,
				    VMUSAGE_BOUND_UNKNOWN, &e_first, &e_last);

				if (virt == 0)
					continue;
				/*
				 * Range visited for this entity
				 */
				e_tree = &(entity_object->vmo_bounds);
				rss = vmu_update_bounds(e_tree, &e_first,
				    &e_last, tree, first, last);
				result->vmu_rss_all += (rss << PAGESHIFT);
				if (shared == B_TRUE && file == B_FALSE) {
					/* shared anon mapping */
					result->vmu_swap_all +=
					    (virt << PAGESHIFT);
					result->vmu_swap_shared +=
					    (virt << PAGESHIFT);
					result->vmu_rss_shared +=
					    (rss << PAGESHIFT);
				} else if (shared == B_TRUE && file == B_TRUE) {
					/* shared file mapping */
					result->vmu_rss_shared +=
					    (rss << PAGESHIFT);
				} else if (shared == B_FALSE &&
				    file == B_TRUE) {
					/* private file mapping */
					result->vmu_rss_private +=
					    (rss << PAGESHIFT);
				}
				vmu_merge_bounds(e_tree, &e_first, &e_last);
			}
			tmp = cur;
			cur = cur->vmb_next;
			vmu_free_bound(tmp);
		}
	}
}

/*
 * Based on the current calculation flags, find the relevant entities
 * which are relative to the process.  Then calculate each segment
 * in the process'es address space for each relevant entity.
 */
static void
vmu_calculate_proc(proc_t *p)
{
	vmu_entity_t *entities = NULL;
	vmu_zone_t *zone;
	vmu_entity_t *tmp;
	struct as *as;
	struct seg *seg;
	int ret;

	/* Figure out which entities are being computed */
	if ((vmu_data.vmu_system) != NULL) {
		tmp = vmu_data.vmu_system;
		tmp->vme_next_calc = entities;
		entities = tmp;
	}
	if (vmu_data.vmu_calc_flags &
	    (VMUSAGE_ZONE | VMUSAGE_ALL_ZONES | VMUSAGE_PROJECTS |
	    VMUSAGE_ALL_PROJECTS | VMUSAGE_TASKS | VMUSAGE_ALL_TASKS |
	    VMUSAGE_RUSERS | VMUSAGE_ALL_RUSERS | VMUSAGE_EUSERS |
	    VMUSAGE_ALL_EUSERS)) {
		ret = i_mod_hash_find_nosync(vmu_data.vmu_zones_hash,
		    (mod_hash_key_t)(uintptr_t)p->p_zone->zone_id,
		    (mod_hash_val_t *)&zone);
		if (ret != 0) {
			zone = vmu_alloc_zone(p->p_zone->zone_id);
			ret = i_mod_hash_insert_nosync(vmu_data.vmu_zones_hash,
			    (mod_hash_key_t)(uintptr_t)p->p_zone->zone_id,
			    (mod_hash_val_t)zone, (mod_hash_hndl_t)0);
			ASSERT(ret == 0);
		}
		if (zone->vmz_zone != NULL) {
			tmp = zone->vmz_zone;
			tmp->vme_next_calc = entities;
			entities = tmp;
		}
		if (vmu_data.vmu_calc_flags &
		    (VMUSAGE_PROJECTS | VMUSAGE_ALL_PROJECTS)) {
			tmp = vmu_find_insert_entity(zone->vmz_projects_hash,
			    p->p_task->tk_proj->kpj_id, VMUSAGE_PROJECTS,
			    zone->vmz_id);
			tmp->vme_next_calc = entities;
			entities = tmp;
		}
		if (vmu_data.vmu_calc_flags &
		    (VMUSAGE_TASKS | VMUSAGE_ALL_TASKS)) {
			tmp = vmu_find_insert_entity(zone->vmz_tasks_hash,
			    p->p_task->tk_tkid, VMUSAGE_TASKS, zone->vmz_id);
			tmp->vme_next_calc = entities;
			entities = tmp;
		}
		if (vmu_data.vmu_calc_flags &
		    (VMUSAGE_RUSERS | VMUSAGE_ALL_RUSERS)) {
			tmp = vmu_find_insert_entity(zone->vmz_rusers_hash,
			    crgetruid(p->p_cred), VMUSAGE_RUSERS, zone->vmz_id);
			tmp->vme_next_calc = entities;
			entities = tmp;
		}
		if (vmu_data.vmu_calc_flags &
		    (VMUSAGE_EUSERS | VMUSAGE_ALL_EUSERS)) {
			tmp = vmu_find_insert_entity(zone->vmz_eusers_hash,
			    crgetuid(p->p_cred), VMUSAGE_EUSERS, zone->vmz_id);
			tmp->vme_next_calc = entities;
			entities = tmp;
		}
	}
	/* Entities which collapse projects and users for all zones */
	if (vmu_data.vmu_calc_flags & VMUSAGE_COL_PROJECTS) {
		tmp = vmu_find_insert_entity(vmu_data.vmu_projects_col_hash,
		    p->p_task->tk_proj->kpj_id, VMUSAGE_PROJECTS, ALL_ZONES);
		tmp->vme_next_calc = entities;
		entities = tmp;
	}
	if (vmu_data.vmu_calc_flags & VMUSAGE_COL_RUSERS) {
		tmp = vmu_find_insert_entity(vmu_data.vmu_rusers_col_hash,
		    crgetruid(p->p_cred), VMUSAGE_RUSERS, ALL_ZONES);
		tmp->vme_next_calc = entities;
		entities = tmp;
	}
	if (vmu_data.vmu_calc_flags & VMUSAGE_COL_EUSERS) {
		tmp = vmu_find_insert_entity(vmu_data.vmu_eusers_col_hash,
		    crgetuid(p->p_cred), VMUSAGE_EUSERS, ALL_ZONES);
		tmp->vme_next_calc = entities;
		entities = tmp;
	}

	ASSERT(entities != NULL);
	/* process all segs in process's address space */
	as = p->p_as;
	AS_LOCK_ENTER(as, RW_READER);
	for (seg = AS_SEGFIRST(as); seg != NULL;
	    seg = AS_SEGNEXT(as, seg)) {
		vmu_calculate_seg(entities, seg);
	}
	AS_LOCK_EXIT(as);
}

/*
 * Free data created by previous call to vmu_calculate().
 */
static void
vmu_clear_calc()
{
	if (vmu_data.vmu_system != NULL) {
		vmu_free_entity(vmu_data.vmu_system);
		vmu_data.vmu_system = NULL;
	}
	if (vmu_data.vmu_zones_hash != NULL)
		i_mod_hash_clear_nosync(vmu_data.vmu_zones_hash);
	if (vmu_data.vmu_projects_col_hash != NULL)
		i_mod_hash_clear_nosync(vmu_data.vmu_projects_col_hash);
	if (vmu_data.vmu_rusers_col_hash != NULL)
		i_mod_hash_clear_nosync(vmu_data.vmu_rusers_col_hash);
	if (vmu_data.vmu_eusers_col_hash != NULL)
		i_mod_hash_clear_nosync(vmu_data.vmu_eusers_col_hash);

	i_mod_hash_clear_nosync(vmu_data.vmu_all_vnodes_hash);
	i_mod_hash_clear_nosync(vmu_data.vmu_all_amps_hash);
}

/*
 * Free unused data structures.  These can result if the system workload
 * decreases between calculations.
 */
static void
vmu_free_extra()
{
	vmu_bound_t *tb;
	vmu_object_t *to;
	vmu_entity_t *te;
	vmu_zone_t *tz;

	while (vmu_data.vmu_free_bounds != NULL) {
		tb = vmu_data.vmu_free_bounds;
		vmu_data.vmu_free_bounds = vmu_data.vmu_free_bounds->vmb_next;
		kmem_cache_free(vmu_bound_cache, tb);
	}
	while (vmu_data.vmu_free_objects != NULL) {
		to = vmu_data.vmu_free_objects;
		vmu_data.vmu_free_objects =
		    vmu_data.vmu_free_objects->vmo_next;
		kmem_cache_free(vmu_object_cache, to);
	}
	while (vmu_data.vmu_free_entities != NULL) {
		te = vmu_data.vmu_free_entities;
		vmu_data.vmu_free_entities =
		    vmu_data.vmu_free_entities->vme_next;
		if (te->vme_vnode_hash != NULL)
			mod_hash_destroy_hash(te->vme_vnode_hash);
		if (te->vme_amp_hash != NULL)
			mod_hash_destroy_hash(te->vme_amp_hash);
		if (te->vme_anon_hash != NULL)
			mod_hash_destroy_hash(te->vme_anon_hash);
		kmem_free(te, sizeof (vmu_entity_t));
	}
	while (vmu_data.vmu_free_zones != NULL) {
		tz = vmu_data.vmu_free_zones;
		vmu_data.vmu_free_zones =
		    vmu_data.vmu_free_zones->vmz_next;
		if (tz->vmz_projects_hash != NULL)
			mod_hash_destroy_hash(tz->vmz_projects_hash);
		if (tz->vmz_tasks_hash != NULL)
			mod_hash_destroy_hash(tz->vmz_tasks_hash);
		if (tz->vmz_rusers_hash != NULL)
			mod_hash_destroy_hash(tz->vmz_rusers_hash);
		if (tz->vmz_eusers_hash != NULL)
			mod_hash_destroy_hash(tz->vmz_eusers_hash);
		kmem_free(tz, sizeof (vmu_zone_t));
	}
}

extern kcondvar_t *pr_pid_cv;

/*
 * Determine which entity types are relevant and allocate the hashes to
 * track them.  Then walk the process table and count rss and swap
 * for each process'es address space.  Address space object such as
 * vnodes, amps and anons are tracked per entity, so that they are
 * not double counted in the results.
 *
 */
static void
vmu_calculate()
{
	int i = 0;
	int ret;
	proc_t *p;

	vmu_clear_calc();

	if (vmu_data.vmu_calc_flags & VMUSAGE_SYSTEM)
		vmu_data.vmu_system = vmu_alloc_entity(0, VMUSAGE_SYSTEM,
		    ALL_ZONES);

	/*
	 * Walk process table and calculate rss of each proc.
	 *
	 * Pidlock and p_lock cannot be held while doing the rss calculation.
	 * This is because:
	 *	1.  The calculation allocates using KM_SLEEP.
	 *	2.  The calculation grabs a_lock, which cannot be grabbed
	 *	    after p_lock.
	 *
	 * Since pidlock must be dropped, we cannot simply just walk the
	 * practive list.  Instead, we walk the process table, and sprlock
	 * each process to ensure that it does not exit during the
	 * calculation.
	 */

	mutex_enter(&pidlock);
	for (i = 0; i < v.v_proc; i++) {
again:
		p = pid_entry(i);
		if (p == NULL)
			continue;

		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);

		if (panicstr) {
			mutex_exit(&p->p_lock);
			return;
		}

		/* Try to set P_PR_LOCK */
		ret = sprtrylock_proc(p);
		if (ret == -1) {
			/* Process in invalid state */
			mutex_exit(&p->p_lock);
			mutex_enter(&pidlock);
			continue;
		} else if (ret == 1) {
			/*
			 * P_PR_LOCK is already set.  Wait and try again.
			 * This also drops p_lock.
			 */
			sprwaitlock_proc(p);
			mutex_enter(&pidlock);
			goto again;
		}
		mutex_exit(&p->p_lock);

		vmu_calculate_proc(p);

		mutex_enter(&p->p_lock);
		sprunlock(p);
		mutex_enter(&pidlock);
	}
	mutex_exit(&pidlock);

	vmu_free_extra();
}

/*
 * allocate a new cache for N results satisfying flags
 */
vmu_cache_t *
vmu_cache_alloc(size_t nres, uint_t flags)
{
	vmu_cache_t *cache;

	cache = kmem_zalloc(sizeof (vmu_cache_t), KM_SLEEP);
	cache->vmc_results = kmem_zalloc(sizeof (vmusage_t) * nres, KM_SLEEP);
	cache->vmc_nresults = nres;
	cache->vmc_flags = flags;
	cache->vmc_refcnt = 1;
	return (cache);
}

/*
 * Make sure cached results are not freed
 */
static void
vmu_cache_hold(vmu_cache_t *cache)
{
	ASSERT(MUTEX_HELD(&vmu_data.vmu_lock));
	cache->vmc_refcnt++;
}

/*
 * free cache data
 */
static void
vmu_cache_rele(vmu_cache_t *cache)
{
	ASSERT(MUTEX_HELD(&vmu_data.vmu_lock));
	ASSERT(cache->vmc_refcnt > 0);
	cache->vmc_refcnt--;
	if (cache->vmc_refcnt == 0) {
		kmem_free(cache->vmc_results, sizeof (vmusage_t) *
		    cache->vmc_nresults);
		kmem_free(cache, sizeof (vmu_cache_t));
	}
}

/*
 * Copy out the cached results to a caller.  Inspect the callers flags
 * and zone to determine which cached results should be copied.
 */
static int
vmu_copyout_results(vmu_cache_t *cache, vmusage_t *buf, size_t *nres,
    uint_t flags, int cpflg)
{
	vmusage_t *result, *out_result;
	vmusage_t dummy;
	size_t i, count = 0;
	size_t bufsize;
	int ret = 0;
	uint_t types = 0;

	if (nres != NULL) {
		if (ddi_copyin((caddr_t)nres, &bufsize, sizeof (size_t), cpflg))
			return (set_errno(EFAULT));
	} else {
		bufsize = 0;
	}

	/* figure out what results the caller is interested in. */
	if ((flags & VMUSAGE_SYSTEM) && curproc->p_zone == global_zone)
		types |= VMUSAGE_SYSTEM;
	if (flags & (VMUSAGE_ZONE | VMUSAGE_ALL_ZONES))
		types |= VMUSAGE_ZONE;
	if (flags & (VMUSAGE_PROJECTS | VMUSAGE_ALL_PROJECTS |
	    VMUSAGE_COL_PROJECTS))
		types |= VMUSAGE_PROJECTS;
	if (flags & (VMUSAGE_TASKS | VMUSAGE_ALL_TASKS))
		types |= VMUSAGE_TASKS;
	if (flags & (VMUSAGE_RUSERS | VMUSAGE_ALL_RUSERS | VMUSAGE_COL_RUSERS))
		types |= VMUSAGE_RUSERS;
	if (flags & (VMUSAGE_EUSERS | VMUSAGE_ALL_EUSERS | VMUSAGE_COL_EUSERS))
		types |= VMUSAGE_EUSERS;

	/* count results for current zone */
	out_result = buf;
	for (result = cache->vmc_results, i = 0;
	    i < cache->vmc_nresults; result++, i++) {

		/* Do not return "other-zone" results to non-global zones */
		if (curproc->p_zone != global_zone &&
		    curproc->p_zone->zone_id != result->vmu_zoneid)
			continue;

		/*
		 * If non-global zone requests VMUSAGE_SYSTEM, fake
		 * up VMUSAGE_ZONE result as VMUSAGE_SYSTEM result.
		 */
		if (curproc->p_zone != global_zone &&
		    (flags & VMUSAGE_SYSTEM) != 0 &&
		    result->vmu_type == VMUSAGE_ZONE) {
			count++;
			if (out_result != NULL) {
				if (bufsize < count) {
					ret = set_errno(EOVERFLOW);
				} else {
					dummy = *result;
					dummy.vmu_zoneid = ALL_ZONES;
					dummy.vmu_id = 0;
					dummy.vmu_type = VMUSAGE_SYSTEM;
					if (ddi_copyout(&dummy, out_result,
					    sizeof (vmusage_t), cpflg))
						return (set_errno(EFAULT));
					out_result++;
				}
			}
		}

		/* Skip results that do not match requested type */
		if ((result->vmu_type & types) == 0)
			continue;

		/* Skip collated results if not requested */
		if (result->vmu_zoneid == ALL_ZONES) {
			if (result->vmu_type == VMUSAGE_PROJECTS &&
			    (flags & VMUSAGE_COL_PROJECTS) == 0)
				continue;
			if (result->vmu_type == VMUSAGE_EUSERS &&
			    (flags & VMUSAGE_COL_EUSERS) == 0)
				continue;
			if (result->vmu_type == VMUSAGE_RUSERS &&
			    (flags & VMUSAGE_COL_RUSERS) == 0)
				continue;
		}

		/* Skip "other zone" results if not requested */
		if (result->vmu_zoneid != curproc->p_zone->zone_id) {
			if (result->vmu_type == VMUSAGE_ZONE &&
			    (flags & VMUSAGE_ALL_ZONES) == 0)
				continue;
			if (result->vmu_type == VMUSAGE_PROJECTS &&
			    (flags & (VMUSAGE_ALL_PROJECTS |
			    VMUSAGE_COL_PROJECTS)) == 0)
				continue;
			if (result->vmu_type == VMUSAGE_TASKS &&
			    (flags & VMUSAGE_ALL_TASKS) == 0)
				continue;
			if (result->vmu_type == VMUSAGE_RUSERS &&
			    (flags & (VMUSAGE_ALL_RUSERS |
			    VMUSAGE_COL_RUSERS)) == 0)
				continue;
			if (result->vmu_type == VMUSAGE_EUSERS &&
			    (flags & (VMUSAGE_ALL_EUSERS |
			    VMUSAGE_COL_EUSERS)) == 0)
				continue;
		}
		count++;
		if (out_result != NULL) {
			if (bufsize < count) {
				ret = set_errno(EOVERFLOW);
			} else {
				if (ddi_copyout(result, out_result,
				    sizeof (vmusage_t), cpflg))
					return (set_errno(EFAULT));
				out_result++;
			}
		}
	}
	if (nres != NULL)
		if (ddi_copyout(&count, (void *)nres, sizeof (size_t), cpflg))
			return (set_errno(EFAULT));

	return (ret);
}

/*
 * vm_getusage()
 *
 * Counts rss and swap by zone, project, task, and/or user.  The flags argument
 * determines the type of results structures returned.  Flags requesting
 * results from more than one zone are "flattened" to the local zone if the
 * caller is not the global zone.
 *
 * args:
 *	flags:	bitmap consisting of one or more of VMUSAGE_*.
 *	age:	maximum allowable age (time since counting was done) in
 *		seconds of the results.  Results from previous callers are
 *		cached in kernel.
 *	buf:	pointer to buffer array of vmusage_t.  If NULL, then only nres
 *		set on success.
 *	nres:	Set to number of vmusage_t structures pointed to by buf
 *		before calling vm_getusage().
 *		On return 0 (success) or ENOSPC, is set to the number of result
 *		structures returned or attempted to return.
 *
 * returns 0 on success, -1 on failure:
 *	EINTR (interrupted)
 *	ENOSPC (nres to small for results, nres set to needed value for success)
 *	EINVAL (flags invalid)
 *	EFAULT (bad address for buf or nres)
 */
int
vm_getusage(uint_t flags, time_t age, vmusage_t *buf, size_t *nres, int cpflg)
{
	vmu_entity_t *entity;
	vmusage_t *result;
	int ret = 0;
	int cacherecent = 0;
	hrtime_t now;
	uint_t flags_orig;

	/*
	 * Non-global zones cannot request system wide and/or collated
	 * results, or the system result, so munge the flags accordingly.
	 */
	flags_orig = flags;
	if (curproc->p_zone != global_zone) {
		if (flags & (VMUSAGE_ALL_PROJECTS | VMUSAGE_COL_PROJECTS)) {
			flags &= ~(VMUSAGE_ALL_PROJECTS | VMUSAGE_COL_PROJECTS);
			flags |= VMUSAGE_PROJECTS;
		}
		if (flags & (VMUSAGE_ALL_RUSERS | VMUSAGE_COL_RUSERS)) {
			flags &= ~(VMUSAGE_ALL_RUSERS | VMUSAGE_COL_RUSERS);
			flags |= VMUSAGE_RUSERS;
		}
		if (flags & (VMUSAGE_ALL_EUSERS | VMUSAGE_COL_EUSERS)) {
			flags &= ~(VMUSAGE_ALL_EUSERS | VMUSAGE_COL_EUSERS);
			flags |= VMUSAGE_EUSERS;
		}
		if (flags & VMUSAGE_SYSTEM) {
			flags &= ~VMUSAGE_SYSTEM;
			flags |= VMUSAGE_ZONE;
		}
	}

	/* Check for unknown flags */
	if ((flags & (~VMUSAGE_MASK)) != 0)
		return (set_errno(EINVAL));

	/* Check for no flags */
	if ((flags & VMUSAGE_MASK) == 0)
		return (set_errno(EINVAL));

	mutex_enter(&vmu_data.vmu_lock);
	now = gethrtime();

start:
	if (vmu_data.vmu_cache != NULL) {

		vmu_cache_t *cache;

		if ((vmu_data.vmu_cache->vmc_timestamp +
		    ((hrtime_t)age * NANOSEC)) > now)
			cacherecent = 1;

		if ((vmu_data.vmu_cache->vmc_flags & flags) == flags &&
		    cacherecent == 1) {
			cache = vmu_data.vmu_cache;
			vmu_cache_hold(cache);
			mutex_exit(&vmu_data.vmu_lock);

			ret = vmu_copyout_results(cache, buf, nres, flags_orig,
			    cpflg);
			mutex_enter(&vmu_data.vmu_lock);
			vmu_cache_rele(cache);
			if (vmu_data.vmu_pending_waiters > 0)
				cv_broadcast(&vmu_data.vmu_cv);
			mutex_exit(&vmu_data.vmu_lock);
			return (ret);
		}
		/*
		 * If the cache is recent, it is likely that there are other
		 * consumers of vm_getusage running, so add their flags to the
		 * desired flags for the calculation.
		 */
		if (cacherecent == 1)
			flags = vmu_data.vmu_cache->vmc_flags | flags;
	}
	if (vmu_data.vmu_calc_thread == NULL) {

		vmu_cache_t *cache;

		vmu_data.vmu_calc_thread = curthread;
		vmu_data.vmu_calc_flags = flags;
		vmu_data.vmu_entities = NULL;
		vmu_data.vmu_nentities = 0;
		if (vmu_data.vmu_pending_waiters > 0)
			vmu_data.vmu_calc_flags |=
			    vmu_data.vmu_pending_flags;

		vmu_data.vmu_pending_flags = 0;
		mutex_exit(&vmu_data.vmu_lock);
		vmu_calculate();
		mutex_enter(&vmu_data.vmu_lock);
		/* copy results to cache */
		if (vmu_data.vmu_cache != NULL)
			vmu_cache_rele(vmu_data.vmu_cache);
		cache = vmu_data.vmu_cache =
		    vmu_cache_alloc(vmu_data.vmu_nentities,
		    vmu_data.vmu_calc_flags);

		result = cache->vmc_results;
		for (entity = vmu_data.vmu_entities; entity != NULL;
		    entity = entity->vme_next) {
			*result = entity->vme_result;
			result++;
		}
		cache->vmc_timestamp = gethrtime();
		vmu_cache_hold(cache);

		vmu_data.vmu_calc_flags = 0;
		vmu_data.vmu_calc_thread = NULL;

		if (vmu_data.vmu_pending_waiters > 0)
			cv_broadcast(&vmu_data.vmu_cv);

		mutex_exit(&vmu_data.vmu_lock);

		/* copy cache */
		ret = vmu_copyout_results(cache, buf, nres, flags_orig, cpflg);
		mutex_enter(&vmu_data.vmu_lock);
		vmu_cache_rele(cache);
		mutex_exit(&vmu_data.vmu_lock);

		return (ret);
	}
	vmu_data.vmu_pending_flags |= flags;
	vmu_data.vmu_pending_waiters++;
	while (vmu_data.vmu_calc_thread != NULL) {
		if (cv_wait_sig(&vmu_data.vmu_cv,
		    &vmu_data.vmu_lock) == 0) {
			vmu_data.vmu_pending_waiters--;
			mutex_exit(&vmu_data.vmu_lock);
			return (set_errno(EINTR));
		}
	}
	vmu_data.vmu_pending_waiters--;
	goto start;
}
