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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/id_space.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/log.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/procset.h>
#include <sys/project.h>
#include <sys/resource.h>
#include <sys/rctl.h>
#include <sys/siginfo.h>
#include <sys/strlog.h>
#include <sys/systm.h>
#include <sys/task.h>
#include <sys/types.h>
#include <sys/policy.h>
#include <sys/zone.h>

/*
 * Resource controls (rctls)
 *
 *   The rctl subsystem provides a mechanism for kernel components to
 *   register their individual resource controls with the system as a whole,
 *   such that those controls can subscribe to specific actions while being
 *   associated with the various process-model entities provided by the kernel:
 *   the process, the task, the project, and the zone.  (In principle, only
 *   minor modifications would be required to connect the resource control
 *   functionality to non-process-model entities associated with the system.)
 *
 *   Subsystems register their rctls via rctl_register().  Subsystems
 *   also wishing to provide additional limits on a given rctl can modify
 *   them once they have the rctl handle.  Each subsystem should store the
 *   handle to their rctl for direct access.
 *
 *   A primary dictionary, rctl_dict, contains a hash of id to the default
 *   control definition for each controlled resource-entity pair on the system.
 *   A secondary dictionary, rctl_dict_by_name, contains a hash of name to
 *   resource control handles.  The resource control handles are distributed by
 *   the rctl_ids ID space.  The handles are private and not to be
 *   advertised to userland; all userland interactions are via the rctl
 *   names.
 *
 *   Entities inherit their rctls from their predecessor.  Since projects have
 *   no ancestor, they inherit their rctls from the rctl dict for project
 *   rctls.  It is expected that project controls will be set to their
 *   appropriate values shortly after project creation, presumably from a
 *   policy source such as the project database.
 *
 * Data structures
 *   The rctl_set_t attached to each of the process model entities is a simple
 *   hash table keyed on the rctl handle assigned at registration.  The entries
 *   in the hash table are rctl_t's, whose relationship with the active control
 *   values on that resource and with the global state of the resource we
 *   illustrate below:
 *
 *   rctl_dict[key] --> rctl_dict_entry
 *			   ^
 *			   |
 *			+--+---+
 *   rctl_set[key] ---> | rctl | --> value <-> value <-> system value --> NULL
 *			+--+---+		 ^
 *			   |			 |
 *			   +------- cursor ------+
 *
 *   That is, the rctl contains a back pointer to the global resource control
 *   state for this resource, which is also available in the rctl_dict hash
 *   table mentioned earlier.  The rctl contains two pointers to resource
 *   control values:  one, values, indicates the entire sequence of control
 *   values; the other, cursor, indicates the currently active control
 *   value--the next value to be enforced.  The value list itself is an open,
 *   doubly-linked list, the last non-NULL member of which is the system value
 *   for that resource (being the theoretical/conventional maximum allowable
 *   value for the resource on this OS instance).
 *
 * Ops Vector
 *   Subsystems publishing rctls need not provide instances of all of the
 *   functions specified by the ops vector.  In particular, if general
 *   rctl_*() entry points are not being called, certain functions can be
 *   omitted.  These align as follows:
 *
 *   rctl_set()
 *     You may wish to provide a set callback if locking circumstances prevent
 *     it or if the performance cost of requesting the enforced value from the
 *     resource control is prohibitively expensive.  For instance, the currently
 *     enforced file size limit is stored on the process in the p_fsz_ctl to
 *     maintain read()/write() performance.
 *
 *   rctl_test()
 *     You must provide a test callback if you are using the rctl_test()
 *     interface.  An action callback is optional.
 *
 *   rctl_action()
 *     You may wish to provide an action callback.
 *
 * Registration
 *   New resource controls can be added to a running instance by loaded modules
 *   via registration.  (The current implementation does not support unloadable
 *   modules; this functionality can be added if needed, via an
 *   activation/deactivation interface involving the manipulation of the
 *   ops vector for the resource control(s) needing to support unloading.)
 *
 * Control value ordering
 *   Because the rctl_val chain on each rctl must be navigable in a
 *   deterministic way, we have to define an ordering on the rctl_val_t's.  The
 *   defined order is (flags & [maximal], value, flags & [deny-action],
 *   privilege).
 *
 * Locking
 *   rctl_dict_lock must be acquired prior to rctl_lists_lock.  Since
 *   rctl_dict_lock or rctl_lists_lock can be called at the enforcement point
 *   of any subsystem, holding subsystem locks, it is at all times inappropriate
 *   to call kmem_alloc(., KM_SLEEP) while holding either of these locks.
 *   Traversing any of the various resource control entity lists requires
 *   holding rctl_lists_lock.
 *
 *   Each individual resource control set associated with an entity must have
 *   its rcs_lock held for the duration of any operations that would add
 *   resource controls or control values to the set.
 *
 *   The locking subsequence of interest is: p_lock, rctl_dict_lock,
 *   rctl_lists_lock, entity->rcs_lock.
 *
 * The projects(4) database and project entity resource controls
 *   A special case is made for RCENTITY_PROJECT values set through the
 *   setproject(3PROJECT) interface.  setproject() makes use of a private
 *   interface, setprojrctl(), which passes through an array of resource control
 *   blocks that need to be set while holding the entity->rcs_lock.  This
 *   ensures that the act of modifying a project's resource controls is
 *   "atomic" within the kernel.
 *
 *   Within the rctl sub-system, we provide two interfaces that are only used by
 *   the setprojrctl() code path - rctl_local_insert_all() and
 *   rctl_local_replace_all().  rctl_local_insert_all() will ensure that the
 *   resource values specified in *new_values are applied.
 *   rctl_local_replace_all() will purge the current rctl->rc_projdb and
 *   rctl->rc_values entries, and apply the *new_values.
 *
 *   These functions modify not only the linked list of active resource controls
 *   (rctl->rc_values), but also a "cached" linked list (rctl->rc_projdb) of
 *   values set through these interfaces.  To clarify:
 *
 *      rctl->rc_values - a linked list of rctl_val_t.  These are the active
 *      resource values associated with this rctl, and may have been set by
 *      setrctl() - via prctl(1M), or by setprojrctl() - via
 *      setproject(3PROJECT).
 *
 *      rctl->rc_projdb - a linked list of rctl_val_t.  These reflect the
 *      resource values set by the setprojrctl() code path.  rc_projdb is not
 *      referenced by any other component of the rctl sub-system.
 *
 *   As various locks are held when calling these functions, we ensure that all
 *   the possible memory allocations are performed prior to calling the
 *   function.  *alloc_values is a linked list of uninitialized rctl_val_t,
 *   which may be used to duplicate a new resource control value (passed in as
 *   one of the members of the *new_values linked list), in order to populate
 *   rctl->rc_values.
 */

id_t max_rctl_hndl = 32768;
int rctl_dict_size = 64;
int rctl_set_size = 8;
kmutex_t rctl_dict_lock;
mod_hash_t *rctl_dict;
mod_hash_t *rctl_dict_by_name;
id_space_t *rctl_ids;
kmem_cache_t *rctl_cache;	/* kmem cache for rctl structures */
kmem_cache_t *rctl_val_cache;	/* kmem cache for rctl values */

kmutex_t rctl_lists_lock;
rctl_dict_entry_t *rctl_lists[RC_MAX_ENTITY + 1];

/*
 * Default resource control operations and ops vector
 *   To be used if the particular rcontrol has no specific actions defined, or
 *   if the subsystem providing the control is quiescing (in preparation for
 *   unloading, presumably.)
 *
 *   Resource controls with callbacks should fill the unused operations with the
 *   appropriate default impotent callback.
 */
/*ARGSUSED*/
void
rcop_no_action(struct rctl *r, struct proc *p, rctl_entity_p_t *e)
{
}

/*ARGSUSED*/
rctl_qty_t
rcop_no_usage(struct rctl *r, struct proc *p)
{
	return (0);
}

/*ARGSUSED*/
int
rcop_no_set(struct rctl *r, struct proc *p, rctl_entity_p_t *e, rctl_qty_t l)
{
	return (0);
}

/*ARGSUSED*/
int
rcop_no_test(struct rctl *r, struct proc *p, rctl_entity_p_t *e,
    struct rctl_val *rv, rctl_qty_t i, uint_t f)
{
	return (0);
}

rctl_ops_t rctl_default_ops = {
	rcop_no_action,
	rcop_no_usage,
	rcop_no_set,
	rcop_no_test
};

/*
 * Default "absolute" resource control operation and ops vector
 *   Useful if there is no usage associated with the
 *   resource control.
 */
/*ARGSUSED*/
int
rcop_absolute_test(struct rctl *r, struct proc *p, rctl_entity_p_t *e,
    struct rctl_val *rv, rctl_qty_t i, uint_t f)
{
	return (i > rv->rcv_value);
}

rctl_ops_t rctl_absolute_ops = {
	rcop_no_action,
	rcop_no_usage,
	rcop_no_set,
	rcop_absolute_test
};

/*ARGSUSED*/
static uint_t
rctl_dict_hash_by_id(void *hash_data, mod_hash_key_t key)
{
	return ((uint_t)(uintptr_t)key % rctl_dict_size);
}

static int
rctl_dict_id_cmp(mod_hash_key_t key1, mod_hash_key_t key2)
{
	uint_t u1 = (uint_t)(uintptr_t)key1;
	uint_t u2 = (uint_t)(uintptr_t)key2;

	if (u1 > u2)
		return (1);

	if (u1 == u2)
		return (0);

	return (-1);
}

static void
rctl_dict_val_dtor(mod_hash_val_t val)
{
	rctl_dict_entry_t *kr = (rctl_dict_entry_t *)val;

	kmem_free(kr, sizeof (rctl_dict_entry_t));
}

/*
 * size_t rctl_build_name_buf()
 *
 * Overview
 *   rctl_build_name_buf() walks all active resource controls in the dictionary,
 *   building a buffer of continguous NUL-terminated strings.
 *
 * Return values
 *   The size of the buffer is returned, the passed pointer's contents are
 *   modified to that of the location of the buffer.
 *
 * Caller's context
 *   Caller must be in a context suitable for KM_SLEEP allocations.
 */
size_t
rctl_build_name_buf(char **rbufp)
{
	size_t req_size, cpy_size;
	char *rbufloc;
	int i;

rctl_rebuild_name_buf:
	req_size = cpy_size = 0;

	/*
	 * Calculate needed buffer length.
	 */
	mutex_enter(&rctl_lists_lock);
	for (i = 0; i < RC_MAX_ENTITY + 1; i++) {
		rctl_dict_entry_t *rde;

		for (rde = rctl_lists[i];
		    rde != NULL;
		    rde = rde->rcd_next)
			req_size += strlen(rde->rcd_name) + 1;
	}
	mutex_exit(&rctl_lists_lock);

	rbufloc = *rbufp = kmem_alloc(req_size, KM_SLEEP);

	/*
	 * Copy rctl names into our buffer.  If the copy length exceeds the
	 * allocate length (due to registration changes), stop copying, free the
	 * buffer, and start again.
	 */
	mutex_enter(&rctl_lists_lock);
	for (i = 0; i < RC_MAX_ENTITY + 1; i++) {
		rctl_dict_entry_t *rde;

		for (rde = rctl_lists[i];
		    rde != NULL;
		    rde = rde->rcd_next) {
			size_t length = strlen(rde->rcd_name) + 1;

			cpy_size += length;

			if (cpy_size > req_size) {
				kmem_free(*rbufp, req_size);
				mutex_exit(&rctl_lists_lock);
				goto rctl_rebuild_name_buf;
			}

			bcopy(rde->rcd_name, rbufloc, length);
			rbufloc += length;
		}
	}
	mutex_exit(&rctl_lists_lock);

	return (req_size);
}

/*
 * rctl_dict_entry_t *rctl_dict_lookup(const char *)
 *
 * Overview
 *   rctl_dict_lookup() returns the resource control dictionary entry for the
 *   named resource control.
 *
 * Return values
 *   A pointer to the appropriate resource control dictionary entry, or NULL if
 *   no such named entry exists.
 *
 * Caller's context
 *   Caller must not be holding rctl_dict_lock.
 */
rctl_dict_entry_t *
rctl_dict_lookup(const char *name)
{
	rctl_dict_entry_t *rde;

	mutex_enter(&rctl_dict_lock);

	if (mod_hash_find(rctl_dict_by_name, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&rde) == MH_ERR_NOTFOUND) {
		mutex_exit(&rctl_dict_lock);
		return (NULL);
	}

	mutex_exit(&rctl_dict_lock);

	return (rde);
}

/*
 * rctl_hndl_t rctl_hndl_lookup(const char *)
 *
 * Overview
 *   rctl_hndl_lookup() returns the resource control id (the "handle") for the
 *   named resource control.
 *
 * Return values
 *   The appropriate id, or -1 if no such named entry exists.
 *
 * Caller's context
 *   Caller must not be holding rctl_dict_lock.
 */
rctl_hndl_t
rctl_hndl_lookup(const char *name)
{
	rctl_dict_entry_t *rde;

	if ((rde = rctl_dict_lookup(name)) == NULL)
		return (-1);

	return (rde->rcd_id);
}

/*
 * rctl_dict_entry_t * rctl_dict_lookup_hndl(rctl_hndl_t)
 *
 * Overview
 *   rctl_dict_lookup_hndl() completes the public lookup functions, by returning
 *   the resource control dictionary entry matching a given resource control id.
 *
 * Return values
 *   A pointer to the matching resource control dictionary entry, or NULL if the
 *   id does not match any existing entries.
 *
 * Caller's context
 *   Caller must not be holding rctl_lists_lock.
 */
rctl_dict_entry_t *
rctl_dict_lookup_hndl(rctl_hndl_t hndl)
{
	uint_t i;

	mutex_enter(&rctl_lists_lock);
	for (i = 0; i < RC_MAX_ENTITY + 1; i++) {
		rctl_dict_entry_t *rde;

		for (rde = rctl_lists[i];
		    rde != NULL;
		    rde = rde->rcd_next)
			if (rde->rcd_id == hndl) {
				mutex_exit(&rctl_lists_lock);
				return (rde);
			}
	}
	mutex_exit(&rctl_lists_lock);

	return (NULL);
}

/*
 * void rctl_add_default_limit(const char *name, rctl_qty_t value,
 *     rctl_priv_t privilege, uint_t action)
 *
 * Overview
 *   Create a default limit with specified value, privilege, and action.
 *
 * Return value
 *   No value returned.
 */
void
rctl_add_default_limit(const char *name, rctl_qty_t value,
    rctl_priv_t privilege, uint_t action)
{
	rctl_val_t *dval;
	rctl_dict_entry_t *rde;

	dval = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);
	bzero(dval, sizeof (rctl_val_t));
	dval->rcv_value = value;
	dval->rcv_privilege = privilege;
	dval->rcv_flagaction = action;
	dval->rcv_action_recip_pid = -1;

	rde = rctl_dict_lookup(name);
	(void) rctl_val_list_insert(&rde->rcd_default_value, dval);
}

/*
 * void rctl_add_legacy_limit(const char *name, const char *mname,
 *     const char *lname, rctl_qty_t dflt)
 *
 * Overview
 *   Create a default privileged limit, using the value obtained from
 *   /etc/system if it exists and is greater than the specified default
 *   value.  Exists primarily for System V IPC.
 *
 * Return value
 *   No value returned.
 */
void
rctl_add_legacy_limit(const char *name, const char *mname, const char *lname,
    rctl_qty_t dflt, rctl_qty_t max)
{
	rctl_qty_t qty;

	if (!mod_sysvar(mname, lname, &qty) || (qty < dflt))
		qty = dflt;

	if (qty > max)
		qty = max;

	rctl_add_default_limit(name, qty, RCPRIV_PRIVILEGED, RCTL_LOCAL_DENY);
}

rctl_set_t *
rctl_entity_obtain_rset(rctl_dict_entry_t *rcd, struct proc *p)
{
	rctl_set_t *rset = NULL;

	if (rcd == NULL)
		return (NULL);

	switch (rcd->rcd_entity) {
	case RCENTITY_PROCESS:
		rset = p->p_rctls;
		break;
	case RCENTITY_TASK:
		ASSERT(MUTEX_HELD(&p->p_lock));
		if (p->p_task != NULL)
			rset = p->p_task->tk_rctls;
		break;
	case RCENTITY_PROJECT:
		ASSERT(MUTEX_HELD(&p->p_lock));
		if (p->p_task != NULL &&
		    p->p_task->tk_proj != NULL)
			rset = p->p_task->tk_proj->kpj_rctls;
		break;
	case RCENTITY_ZONE:
		ASSERT(MUTEX_HELD(&p->p_lock));
		if (p->p_zone != NULL)
			rset = p->p_zone->zone_rctls;
		break;
	default:
		panic("unknown rctl entity type %d seen", rcd->rcd_entity);
		break;
	}

	return (rset);
}

static void
rctl_entity_obtain_entity_p(rctl_entity_t entity, struct proc *p,
    rctl_entity_p_t *e)
{
	e->rcep_p.proc = NULL;
	e->rcep_t = entity;

	switch (entity) {
	case RCENTITY_PROCESS:
		e->rcep_p.proc = p;
		break;
	case RCENTITY_TASK:
		ASSERT(MUTEX_HELD(&p->p_lock));
		if (p->p_task != NULL)
			e->rcep_p.task = p->p_task;
		break;
	case RCENTITY_PROJECT:
		ASSERT(MUTEX_HELD(&p->p_lock));
		if (p->p_task != NULL &&
		    p->p_task->tk_proj != NULL)
			e->rcep_p.proj = p->p_task->tk_proj;
		break;
	case RCENTITY_ZONE:
		ASSERT(MUTEX_HELD(&p->p_lock));
		if (p->p_zone != NULL)
			e->rcep_p.zone = p->p_zone;
		break;
	default:
		panic("unknown rctl entity type %d seen", entity);
		break;
	}
}

static void
rctl_gp_alloc(rctl_alloc_gp_t *rcgp)
{
	uint_t i;

	if (rcgp->rcag_nctls > 0) {
		rctl_t *prev = kmem_cache_alloc(rctl_cache, KM_SLEEP);
		rctl_t *rctl = prev;

		rcgp->rcag_ctls = prev;

		for (i = 1; i < rcgp->rcag_nctls; i++) {
			rctl = kmem_cache_alloc(rctl_cache, KM_SLEEP);
			prev->rc_next = rctl;
			prev = rctl;
		}

		rctl->rc_next = NULL;
	}

	if (rcgp->rcag_nvals > 0) {
		rctl_val_t *prev = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);
		rctl_val_t *rval = prev;

		rcgp->rcag_vals = prev;

		for (i = 1; i < rcgp->rcag_nvals; i++) {
			rval = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);
			prev->rcv_next = rval;
			prev = rval;
		}

		rval->rcv_next = NULL;
	}

}

static rctl_val_t *
rctl_gp_detach_val(rctl_alloc_gp_t *rcgp)
{
	rctl_val_t *rval = rcgp->rcag_vals;

	ASSERT(rcgp->rcag_nvals > 0);
	rcgp->rcag_nvals--;
	rcgp->rcag_vals = rval->rcv_next;

	rval->rcv_next = NULL;

	return (rval);
}

static rctl_t *
rctl_gp_detach_ctl(rctl_alloc_gp_t *rcgp)
{
	rctl_t *rctl = rcgp->rcag_ctls;

	ASSERT(rcgp->rcag_nctls > 0);
	rcgp->rcag_nctls--;
	rcgp->rcag_ctls = rctl->rc_next;

	rctl->rc_next = NULL;

	return (rctl);

}

static void
rctl_gp_free(rctl_alloc_gp_t *rcgp)
{
	rctl_val_t *rval = rcgp->rcag_vals;
	rctl_t *rctl = rcgp->rcag_ctls;

	while (rval != NULL) {
		rctl_val_t *next = rval->rcv_next;

		kmem_cache_free(rctl_val_cache, rval);
		rval = next;
	}

	while (rctl != NULL) {
		rctl_t *next = rctl->rc_next;

		kmem_cache_free(rctl_cache, rctl);
		rctl = next;
	}
}

/*
 * void rctl_prealloc_destroy(rctl_alloc_gp_t *)
 *
 * Overview
 *   Release all unused memory allocated via one of the "prealloc" functions:
 *   rctl_set_init_prealloc, rctl_set_dup_prealloc, or rctl_rlimit_set_prealloc.
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   No restrictions on context.
 */
void
rctl_prealloc_destroy(rctl_alloc_gp_t *gp)
{
	rctl_gp_free(gp);
	kmem_free(gp, sizeof (rctl_alloc_gp_t));
}

/*
 * int rctl_val_cmp(rctl_val_t *, rctl_val_t *, int)
 *
 * Overview
 *   This function defines an ordering to rctl_val_t's in order to allow
 *   for correct placement in value lists. When the imprecise flag is set,
 *   the action recipient is ignored. This is to facilitate insert,
 *   delete, and replace operations by rctlsys.
 *
 * Return values
 *   0 if the val_t's are are considered identical
 *   -1 if a is ordered lower than b
 *   1 if a is lowered higher than b
 *
 * Caller's context
 *   No restrictions on context.
 */
int
rctl_val_cmp(rctl_val_t *a, rctl_val_t *b, int imprecise)
{
	if ((a->rcv_flagaction & RCTL_LOCAL_MAXIMAL) <
	    (b->rcv_flagaction & RCTL_LOCAL_MAXIMAL))
		return (-1);

	if ((a->rcv_flagaction & RCTL_LOCAL_MAXIMAL) >
	    (b->rcv_flagaction & RCTL_LOCAL_MAXIMAL))
		return (1);

	if (a->rcv_value < b->rcv_value)
		return (-1);

	if (a->rcv_value > b->rcv_value)
		return (1);

	if ((a->rcv_flagaction & RCTL_LOCAL_DENY) <
	    (b->rcv_flagaction & RCTL_LOCAL_DENY))
		return (-1);

	if ((a->rcv_flagaction & RCTL_LOCAL_DENY) >
	    (b->rcv_flagaction & RCTL_LOCAL_DENY))
		return (1);

	if (a->rcv_privilege < b->rcv_privilege)
		return (-1);

	if (a->rcv_privilege > b->rcv_privilege)
		return (1);

	if (imprecise)
		return (0);

	if (a->rcv_action_recip_pid < b->rcv_action_recip_pid)
		return (-1);

	if (a->rcv_action_recip_pid > b->rcv_action_recip_pid)
		return (1);

	return (0);
}

static rctl_val_t *
rctl_val_list_find(rctl_val_t **head, rctl_val_t *cval)
{
	rctl_val_t *rval = *head;

	while (rval != NULL) {
		if (rctl_val_cmp(cval, rval, 0) == 0)
			return (rval);

		rval = rval->rcv_next;
	}

	return (NULL);

}

/*
 * int rctl_val_list_insert(rctl_val_t **, rctl_val_t *)
 *
 * Overview
 *   This function inserts the rctl_val_t into the value list provided.
 *   The insert is always successful unless if the value is a duplicate
 *   of one already in the list.
 *
 * Return values
 *    1 if the value was a duplicate of an existing value in the list.
 *    0 if the insert was successful.
 */
int
rctl_val_list_insert(rctl_val_t **root, rctl_val_t *rval)
{
	rctl_val_t *prev;
	int equiv;

	rval->rcv_next = NULL;
	rval->rcv_prev = NULL;

	if (*root == NULL) {
		*root = rval;
		return (0);
	}

	equiv = rctl_val_cmp(rval, *root, 0);

	if (equiv == 0)
		return (1);

	if (equiv < 0) {
		rval->rcv_next = *root;
		rval->rcv_next->rcv_prev = rval;
		*root = rval;

		return (0);
	}

	prev = *root;
	while (prev->rcv_next != NULL &&
	    (equiv = rctl_val_cmp(rval, prev->rcv_next, 0)) > 0) {
		prev = prev->rcv_next;
	}

	if (equiv == 0)
		return (1);

	rval->rcv_next = prev->rcv_next;
	if (rval->rcv_next != NULL)
		rval->rcv_next->rcv_prev = rval;
	prev->rcv_next = rval;
	rval->rcv_prev = prev;

	return (0);
}

static int
rctl_val_list_delete(rctl_val_t **root, rctl_val_t *rval)
{
	rctl_val_t *prev;

	if (*root == NULL)
		return (-1);

	prev = *root;
	if (rctl_val_cmp(rval, prev, 0) == 0) {
		*root = prev->rcv_next;
		if (*root != NULL)
			(*root)->rcv_prev = NULL;

		kmem_cache_free(rctl_val_cache, prev);

		return (0);
	}

	while (prev->rcv_next != NULL &&
	    rctl_val_cmp(rval, prev->rcv_next, 0) != 0) {
		prev = prev->rcv_next;
	}

	if (prev->rcv_next == NULL) {
		/*
		 * If we navigate the entire list and cannot find a match, then
		 * return failure.
		 */
		return (-1);
	}

	prev = prev->rcv_next;
	prev->rcv_prev->rcv_next = prev->rcv_next;
	if (prev->rcv_next != NULL)
		prev->rcv_next->rcv_prev = prev->rcv_prev;

	kmem_cache_free(rctl_val_cache, prev);

	return (0);
}

static rctl_val_t *
rctl_val_list_dup(rctl_val_t *rval, rctl_alloc_gp_t *ragp, struct proc *oldp,
    struct proc *newp)
{
	rctl_val_t *head = NULL;

	for (; rval != NULL; rval = rval->rcv_next) {
		rctl_val_t *dval = rctl_gp_detach_val(ragp);

		bcopy(rval, dval, sizeof (rctl_val_t));
		dval->rcv_prev = dval->rcv_next = NULL;

		if (oldp == NULL ||
		    rval->rcv_action_recipient == NULL ||
		    rval->rcv_action_recipient == oldp) {
			if (rval->rcv_privilege == RCPRIV_BASIC) {
				dval->rcv_action_recipient = newp;
				dval->rcv_action_recip_pid = newp->p_pid;
			} else {
				dval->rcv_action_recipient = NULL;
				dval->rcv_action_recip_pid = -1;
			}

			(void) rctl_val_list_insert(&head, dval);
		} else {
			kmem_cache_free(rctl_val_cache, dval);
		}
	}

	return (head);
}

static void
rctl_val_list_reset(rctl_val_t *rval)
{
	for (; rval != NULL; rval = rval->rcv_next)
		rval->rcv_firing_time = 0;
}

static uint_t
rctl_val_list_count(rctl_val_t *rval)
{
	uint_t n = 0;

	for (; rval != NULL; rval = rval->rcv_next)
		n++;

	return (n);
}


static void
rctl_val_list_free(rctl_val_t *rval)
{
	while (rval != NULL) {
		rctl_val_t *next = rval->rcv_next;

		kmem_cache_free(rctl_val_cache, rval);

		rval = next;
	}
}

/*
 * rctl_qty_t rctl_model_maximum(rctl_dict_entry_t *, struct proc *)
 *
 * Overview
 *   In cases where the operating system supports more than one process
 *   addressing model, the operating system capabilities will exceed those of
 *   one or more of these models.  Processes in a less capable model must have
 *   their resources accurately controlled, without diluting those of their
 *   descendants reached via exec().  rctl_model_maximum() returns the governing
 *   value for the specified process with respect to a resource control, such
 *   that the value can used for the RCTLOP_SET callback or compatability
 *   support.
 *
 * Return values
 *   The maximum value for the given process for the specified resource control.
 *
 * Caller's context
 *   No restrictions on context.
 */
rctl_qty_t
rctl_model_maximum(rctl_dict_entry_t *rde, struct proc *p)
{
	if (p->p_model == DATAMODEL_NATIVE)
		return (rde->rcd_max_native);

	return (rde->rcd_max_ilp32);
}

/*
 * rctl_qty_t rctl_model_value(rctl_dict_entry_t *, struct proc *, rctl_qty_t)
 *
 * Overview
 *   Convenience function wrapping the rctl_model_maximum() functionality.
 *
 * Return values
 *   The lesser of the process's maximum value and the given value for the
 *   specified resource control.
 *
 * Caller's context
 *   No restrictions on context.
 */
rctl_qty_t
rctl_model_value(rctl_dict_entry_t *rde, struct proc *p, rctl_qty_t value)
{
	rctl_qty_t max = rctl_model_maximum(rde, p);

	return (value < max ? value : max);
}

static void
rctl_set_insert(rctl_set_t *set, rctl_hndl_t hndl, rctl_t *rctl)
{
	uint_t index = hndl % rctl_set_size;
	rctl_t *next_ctl, *prev_ctl;

	ASSERT(MUTEX_HELD(&set->rcs_lock));

	rctl->rc_next = NULL;

	if (set->rcs_ctls[index] == NULL) {
		set->rcs_ctls[index] = rctl;
		return;
	}

	if (hndl < set->rcs_ctls[index]->rc_id) {
		rctl->rc_next = set->rcs_ctls[index];
		set->rcs_ctls[index] = rctl;

		return;
	}

	for (next_ctl = set->rcs_ctls[index]->rc_next,
	    prev_ctl = set->rcs_ctls[index];
	    next_ctl != NULL;
	    prev_ctl = next_ctl,
	    next_ctl = next_ctl->rc_next) {
		if (next_ctl->rc_id > hndl) {
			rctl->rc_next = next_ctl;
			prev_ctl->rc_next = rctl;

			return;
		}
	}

	rctl->rc_next = next_ctl;
	prev_ctl->rc_next = rctl;
}

/*
 * rctl_set_t *rctl_set_create()
 *
 * Overview
 *   Create an empty resource control set, suitable for attaching to a
 *   controlled entity.
 *
 * Return values
 *   A pointer to the newly created set.
 *
 * Caller's context
 *   Safe for KM_SLEEP allocations.
 */
rctl_set_t *
rctl_set_create()
{
	rctl_set_t *rset = kmem_zalloc(sizeof (rctl_set_t), KM_SLEEP);

	mutex_init(&rset->rcs_lock, NULL, MUTEX_DEFAULT, NULL);
	rset->rcs_ctls = kmem_zalloc(rctl_set_size * sizeof (rctl_t *),
	    KM_SLEEP);
	rset->rcs_entity = -1;

	return (rset);
}

/*
 * rctl_gp_alloc_t *rctl_set_init_prealloc(rctl_entity_t)
 *
 * Overview
 *    rctl_set_init_prealloc() examines the globally defined resource controls
 *    and their default values and returns a resource control allocation group
 *    populated with sufficient controls and values to form a representative
 *    resource control set for the specified entity.
 *
 * Return values
 *    A pointer to the newly created allocation group.
 *
 * Caller's context
 *    Caller must be in a context suitable for KM_SLEEP allocations.
 */
rctl_alloc_gp_t *
rctl_set_init_prealloc(rctl_entity_t entity)
{
	rctl_dict_entry_t *rde;
	rctl_alloc_gp_t *ragp = kmem_zalloc(sizeof (rctl_alloc_gp_t), KM_SLEEP);

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	if (rctl_lists[entity] == NULL)
		return (ragp);

	mutex_enter(&rctl_lists_lock);

	for (rde = rctl_lists[entity]; rde != NULL; rde = rde->rcd_next) {
		ragp->rcag_nctls++;
		ragp->rcag_nvals += rctl_val_list_count(rde->rcd_default_value);
	}

	mutex_exit(&rctl_lists_lock);

	rctl_gp_alloc(ragp);

	return (ragp);
}

/*
 * rctl_set_t *rctl_set_init(rctl_entity_t)
 *
 * Overview
 *   rctl_set_create() creates a resource control set, initialized with the
 *   system infinite values on all registered controls, for attachment to a
 *   system entity requiring resource controls, such as a process or a task.
 *
 * Return values
 *   A pointer to the newly filled set.
 *
 * Caller's context
 *   Caller must be holding p_lock on entry so that RCTLOP_SET() functions
 *   may modify task and project members based on the proc structure
 *   they are passed.
 */
rctl_set_t *
rctl_set_init(rctl_entity_t entity, struct proc *p, rctl_entity_p_t *e,
    rctl_set_t *rset, rctl_alloc_gp_t *ragp)
{
	rctl_dict_entry_t *rde;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e);
	rset->rcs_entity = entity;

	if (rctl_lists[entity] == NULL)
		return (rset);

	mutex_enter(&rctl_lists_lock);
	mutex_enter(&rset->rcs_lock);

	for (rde = rctl_lists[entity]; rde != NULL; rde = rde->rcd_next) {
		rctl_t *rctl = rctl_gp_detach_ctl(ragp);

		rctl->rc_dict_entry = rde;
		rctl->rc_id = rde->rcd_id;
		rctl->rc_projdb = NULL;

		rctl->rc_values = rctl_val_list_dup(rde->rcd_default_value,
		    ragp, NULL, p);
		rctl->rc_cursor = rctl->rc_values;

		ASSERT(rctl->rc_cursor != NULL);

		rctl_set_insert(rset, rde->rcd_id, rctl);

		RCTLOP_SET(rctl, p, e, rctl_model_value(rctl->rc_dict_entry, p,
		    rctl->rc_cursor->rcv_value));
	}

	mutex_exit(&rset->rcs_lock);
	mutex_exit(&rctl_lists_lock);

	return (rset);
}

static rctl_t *
rctl_dup(rctl_t *rctl, rctl_alloc_gp_t *ragp, struct proc *oldp,
    struct proc *newp)
{
	rctl_t *dup = rctl_gp_detach_ctl(ragp);
	rctl_val_t *dval;

	dup->rc_id = rctl->rc_id;
	dup->rc_dict_entry = rctl->rc_dict_entry;
	dup->rc_next = NULL;
	dup->rc_cursor = NULL;
	dup->rc_values = rctl_val_list_dup(rctl->rc_values, ragp, oldp, newp);

	for (dval = dup->rc_values;
	    dval != NULL; dval = dval->rcv_next) {
		if (rctl_val_cmp(rctl->rc_cursor, dval, 0) >= 0) {
			dup->rc_cursor = dval;
			break;
		}
	}

	if (dup->rc_cursor == NULL)
		dup->rc_cursor = dup->rc_values;

	return (dup);
}

static void
rctl_set_fill_alloc_gp(rctl_set_t *set, rctl_alloc_gp_t *ragp)
{
	uint_t i;

	bzero(ragp, sizeof (rctl_alloc_gp_t));

	for (i = 0; i < rctl_set_size; i++) {
		rctl_t *r = set->rcs_ctls[i];

		while (r != NULL) {
			ragp->rcag_nctls++;

			ragp->rcag_nvals += rctl_val_list_count(r->rc_values);

			r = r->rc_next;
		}
	}
}

/*
 * rctl_alloc_gp_t *rctl_set_dup_prealloc(rctl_set_t *)
 *
 * Overview
 *   Given a resource control set, allocate a sufficiently large allocation
 *   group to contain a duplicate of the set.
 *
 * Return value
 *   A pointer to the newly created allocation group.
 *
 * Caller's context
 *   Safe for KM_SLEEP allocations.
 */
rctl_alloc_gp_t *
rctl_set_dup_prealloc(rctl_set_t *set)
{
	rctl_alloc_gp_t *ragp = kmem_zalloc(sizeof (rctl_alloc_gp_t), KM_SLEEP);

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	mutex_enter(&set->rcs_lock);
	rctl_set_fill_alloc_gp(set, ragp);
	mutex_exit(&set->rcs_lock);

	rctl_gp_alloc(ragp);

	return (ragp);
}

/*
 * int rctl_set_dup_ready(rctl_set_t *, rctl_alloc_gp_t *)
 *
 * Overview
 *   Verify that the allocation group provided is large enough to allow a
 *   duplicate of the given resource control set to be constructed from its
 *   contents.
 *
 * Return values
 *   1 if the allocation group is sufficiently large, 0 otherwise.
 *
 * Caller's context
 *   rcs_lock must be held prior to entry.
 */
int
rctl_set_dup_ready(rctl_set_t *set, rctl_alloc_gp_t *ragp)
{
	rctl_alloc_gp_t curr_gp;

	ASSERT(MUTEX_HELD(&set->rcs_lock));

	rctl_set_fill_alloc_gp(set, &curr_gp);

	if (curr_gp.rcag_nctls <= ragp->rcag_nctls &&
	    curr_gp.rcag_nvals <= ragp->rcag_nvals)
		return (1);

	return (0);
}

/*
 * rctl_set_t *rctl_set_dup(rctl_set_t *, struct proc *, struct proc *,
 *   rctl_set_t *, rctl_alloc_gp_t *, int)
 *
 * Overview
 *   Make a duplicate of the resource control set.  The proc pointers are those
 *   of the owning process and of the process associated with the entity
 *   receiving the duplicate.
 *
 *   Duplication is a 3 stage process. Stage 1 is memory allocation for
 *   the duplicate set, which is taken care of by rctl_set_dup_prealloc().
 *   Stage 2 consists of copying all rctls and values from the old set into
 *   the new. Stage 3 completes the duplication by performing the appropriate
 *   callbacks for each rctl in the new set.
 *
 *   Stages 2 and 3 are handled by calling rctl_set_dup with the RCD_DUP and
 *   RCD_CALLBACK functions, respectively. The RCD_CALLBACK flag may only
 *   be supplied if the newp proc structure reflects the new task and
 *   project linkage.
 *
 * Return value
 *   A pointer to the duplicate set.
 *
 * Caller's context
 *   The rcs_lock of the set to be duplicated must be held prior to entry.
 */
rctl_set_t *
rctl_set_dup(rctl_set_t *set, struct proc *oldp, struct proc *newp,
    rctl_entity_p_t *e, rctl_set_t *dup, rctl_alloc_gp_t *ragp, int flag)
{
	uint_t i;
	rctl_set_t	*iter;

	ASSERT((flag & RCD_DUP) || (flag & RCD_CALLBACK));
	ASSERT(e);
	/*
	 * When copying the old set, iterate over that. Otherwise, when
	 * only callbacks have been requested, iterate over the dup set.
	 */
	if (flag & RCD_DUP) {
		ASSERT(MUTEX_HELD(&set->rcs_lock));
		iter = set;
		dup->rcs_entity = set->rcs_entity;
	} else {
		iter = dup;
	}

	mutex_enter(&dup->rcs_lock);

	for (i = 0; i < rctl_set_size; i++) {
		rctl_t *r = iter->rcs_ctls[i];
		rctl_t *d;

		while (r != NULL) {
			if (flag & RCD_DUP) {
				d = rctl_dup(r, ragp, oldp, newp);
				rctl_set_insert(dup, r->rc_id, d);
			} else {
				d = r;
			}

			if (flag & RCD_CALLBACK)
				RCTLOP_SET(d, newp, e,
				    rctl_model_value(d->rc_dict_entry, newp,
				    d->rc_cursor->rcv_value));

			r = r->rc_next;
		}
	}

	mutex_exit(&dup->rcs_lock);

	return (dup);
}

/*
 * void rctl_set_free(rctl_set_t *)
 *
 * Overview
 *   Delete resource control set and all attached values.
 *
 * Return values
 *   No value returned.
 *
 * Caller's context
 *   No restrictions on context.
 */
void
rctl_set_free(rctl_set_t *set)
{
	uint_t i;

	mutex_enter(&set->rcs_lock);
	for (i = 0; i < rctl_set_size; i++) {
		rctl_t *r = set->rcs_ctls[i];

		while (r != NULL) {
			rctl_val_t *v = r->rc_values;
			rctl_t *n = r->rc_next;

			kmem_cache_free(rctl_cache, r);

			rctl_val_list_free(v);

			r = n;
		}
	}
	mutex_exit(&set->rcs_lock);

	kmem_free(set->rcs_ctls, sizeof (rctl_t *) * rctl_set_size);
	kmem_free(set, sizeof (rctl_set_t));
}

/*
 * void rctl_set_reset(rctl_set_t *)
 *
 * Overview
 *   Resets all rctls within the set such that the lowest value becomes active.
 *
 * Return values
 *   No value returned.
 *
 * Caller's context
 *   No restrictions on context.
 */
void
rctl_set_reset(rctl_set_t *set, struct proc *p, rctl_entity_p_t *e)
{
	uint_t i;

	ASSERT(e);

	mutex_enter(&set->rcs_lock);
	for (i = 0; i < rctl_set_size; i++) {
		rctl_t *r = set->rcs_ctls[i];

		while (r != NULL) {
			r->rc_cursor = r->rc_values;
			rctl_val_list_reset(r->rc_cursor);
			RCTLOP_SET(r, p, e, rctl_model_value(r->rc_dict_entry,
			    p, r->rc_cursor->rcv_value));

			ASSERT(r->rc_cursor != NULL);

			r = r->rc_next;
		}
	}

	mutex_exit(&set->rcs_lock);
}

/*
 * void rctl_set_tearoff(rctl_set *, struct proc *)
 *
 * Overview
 *   Tear off any resource control values on this set with an action recipient
 *   equal to the specified process (as they are becoming invalid with the
 *   process's departure from this set as an observer).
 *
 * Return values
 *   No value returned.
 *
 * Caller's context
 *   No restrictions on context
 */
void
rctl_set_tearoff(rctl_set_t *set, struct proc *p)
{
	uint_t i;

	mutex_enter(&set->rcs_lock);
	for (i = 0; i < rctl_set_size; i++) {
		rctl_t *r = set->rcs_ctls[i];

		while (r != NULL) {
			rctl_val_t *rval;

tearoff_rewalk_list:
			rval = r->rc_values;

			while (rval != NULL) {
				if (rval->rcv_privilege == RCPRIV_BASIC &&
				    rval->rcv_action_recipient == p) {
					if (r->rc_cursor == rval)
						r->rc_cursor = rval->rcv_next;

					(void) rctl_val_list_delete(
					    &r->rc_values, rval);

					goto tearoff_rewalk_list;
				}

				rval = rval->rcv_next;
			}

			ASSERT(r->rc_cursor != NULL);

			r = r->rc_next;
		}
	}

	mutex_exit(&set->rcs_lock);
}

int
rctl_set_find(rctl_set_t *set, rctl_hndl_t hndl, rctl_t **rctl)
{
	uint_t index = hndl % rctl_set_size;
	rctl_t *curr_ctl;

	ASSERT(MUTEX_HELD(&set->rcs_lock));

	for (curr_ctl = set->rcs_ctls[index]; curr_ctl != NULL;
	    curr_ctl = curr_ctl->rc_next) {
		if (curr_ctl->rc_id == hndl) {
			*rctl = curr_ctl;

			return (0);
		}
	}

	return (-1);
}

/*
 * rlim64_t rctl_enforced_value(rctl_hndl_t, rctl_set_t *, struct proc *)
 *
 * Overview
 *   Given a process, get the next enforced value on the rctl of the specified
 *   handle.
 *
 * Return value
 *   The enforced value.
 *
 * Caller's context
 *   For controls on process collectives, p->p_lock must be held across the
 *   operation.
 */
/*ARGSUSED*/
rctl_qty_t
rctl_enforced_value(rctl_hndl_t hndl, rctl_set_t *rset, struct proc *p)
{
	rctl_t *rctl;
	rlim64_t ret;

	mutex_enter(&rset->rcs_lock);

	if (rctl_set_find(rset, hndl, &rctl) == -1)
		panic("unknown resource control handle %d requested", hndl);
	else
		ret = rctl_model_value(rctl->rc_dict_entry, p,
		    rctl->rc_cursor->rcv_value);

	mutex_exit(&rset->rcs_lock);

	return (ret);
}

/*
 * int rctl_global_get(const char *, rctl_dict_entry_t *)
 *
 * Overview
 *   Copy a sanitized version of the global rctl for a given resource control
 *   name.  (By sanitization, we mean that the unsafe data pointers have been
 *   zeroed.)
 *
 * Return value
 *   -1 if name not defined, 0 otherwise.
 *
 * Caller's context
 *   No restrictions on context.  rctl_dict_lock must not be held.
 */
int
rctl_global_get(const char *name, rctl_dict_entry_t *drde)
{
	rctl_dict_entry_t *rde = rctl_dict_lookup(name);

	if (rde == NULL)
		return (-1);

	bcopy(rde, drde, sizeof (rctl_dict_entry_t));

	drde->rcd_next = NULL;
	drde->rcd_ops = NULL;

	return (0);
}

/*
 * int rctl_global_set(const char *, rctl_dict_entry_t *)
 *
 * Overview
 *   Transfer the settable fields of the named rctl to the global rctl matching
 *   the given resource control name.
 *
 * Return value
 *   -1 if name not defined, 0 otherwise.
 *
 * Caller's context
 *   No restrictions on context.  rctl_dict_lock must not be held.
 */
int
rctl_global_set(const char *name, rctl_dict_entry_t *drde)
{
	rctl_dict_entry_t *rde = rctl_dict_lookup(name);

	if (rde == NULL)
		return (-1);

	rde->rcd_flagaction = drde->rcd_flagaction;
	rde->rcd_syslog_level = drde->rcd_syslog_level;
	rde->rcd_strlog_flags = drde->rcd_strlog_flags;

	return (0);
}

static int
rctl_local_op(rctl_hndl_t hndl, rctl_val_t *oval, rctl_val_t *nval,
    int (*cbop)(rctl_hndl_t, struct proc *p, rctl_entity_p_t *e, rctl_t *,
    rctl_val_t *, rctl_val_t *), struct proc *p)
{
	rctl_t *rctl;
	rctl_set_t *rset;
	rctl_entity_p_t e;
	int ret = 0;
	rctl_dict_entry_t *rde = rctl_dict_lookup_hndl(hndl);

local_op_retry:

	ASSERT(MUTEX_HELD(&p->p_lock));

	rset = rctl_entity_obtain_rset(rde, p);

	if (rset == NULL) {
		return (-1);
	}
	rctl_entity_obtain_entity_p(rset->rcs_entity, p, &e);

	mutex_enter(&rset->rcs_lock);

	/* using rctl's hndl, get rctl from local set */
	if (rctl_set_find(rset, hndl, &rctl) == -1) {
		mutex_exit(&rset->rcs_lock);
		return (-1);
	}

	ret = cbop(hndl, p, &e, rctl, oval, nval);

	mutex_exit(&rset->rcs_lock);
	return (ret);
}

/*ARGSUSED*/
static int
rctl_local_get_cb(rctl_hndl_t hndl, struct proc *p, rctl_entity_p_t *e,
    rctl_t *rctl, rctl_val_t *oval, rctl_val_t *nval)
{
	if (oval == NULL) {
		/*
		 * RCTL_FIRST
		 */
		bcopy(rctl->rc_values, nval, sizeof (rctl_val_t));
	} else {
		/*
		 * RCTL_NEXT
		 */
		rctl_val_t *tval = rctl_val_list_find(&rctl->rc_values, oval);

		if (tval == NULL)
			return (ESRCH);
		else if (tval->rcv_next == NULL)
			return (ENOENT);
		else
			bcopy(tval->rcv_next, nval, sizeof (rctl_val_t));
	}

	return (0);
}

/*
 * int rctl_local_get(rctl_hndl_t, rctl_val_t *)
 *
 * Overview
 *   Get the rctl value for the given flags.
 *
 * Return values
 *   0 for successful get, errno otherwise.
 */
int
rctl_local_get(rctl_hndl_t hndl, rctl_val_t *oval, rctl_val_t *nval,
    struct proc *p)
{
	return (rctl_local_op(hndl, oval, nval, rctl_local_get_cb, p));
}

/*ARGSUSED*/
static int
rctl_local_delete_cb(rctl_hndl_t hndl, struct proc *p, rctl_entity_p_t *e,
    rctl_t *rctl, rctl_val_t *oval, rctl_val_t *nval)
{
	if ((oval = rctl_val_list_find(&rctl->rc_values, nval)) == NULL)
		return (ESRCH);

	if (rctl->rc_cursor == oval) {
		rctl->rc_cursor = oval->rcv_next;
		rctl_val_list_reset(rctl->rc_cursor);
		RCTLOP_SET(rctl, p, e, rctl_model_value(rctl->rc_dict_entry, p,
		    rctl->rc_cursor->rcv_value));

		ASSERT(rctl->rc_cursor != NULL);
	}

	(void) rctl_val_list_delete(&rctl->rc_values, oval);

	return (0);
}

/*
 * int rctl_local_delete(rctl_hndl_t, rctl_val_t *)
 *
 * Overview
 *   Delete the rctl value for the given flags.
 *
 * Return values
 *   0 for successful delete, errno otherwise.
 */
int
rctl_local_delete(rctl_hndl_t hndl, rctl_val_t *val, struct proc *p)
{
	return (rctl_local_op(hndl, NULL, val, rctl_local_delete_cb, p));
}

/*
 * rctl_local_insert_cb()
 *
 * Overview
 *   Insert a new value into the rctl's val list. If an error occurs,
 *   the val list must be left in the same state as when the function
 *   was entered.
 *
 * Return Values
 *   0 for successful insert, EINVAL if the value is duplicated in the
 *   existing list.
 */
/*ARGSUSED*/
static int
rctl_local_insert_cb(rctl_hndl_t hndl, struct proc *p, rctl_entity_p_t *e,
    rctl_t *rctl, rctl_val_t *oval, rctl_val_t *nval)
{
	/*
	 * Before inserting, confirm there are no duplicates of this value
	 * and flag level. If there is a duplicate, flag an error and do
	 * nothing.
	 */
	if (rctl_val_list_insert(&rctl->rc_values, nval) != 0)
		return (EINVAL);

	if (rctl_val_cmp(nval, rctl->rc_cursor, 0) < 0) {
		rctl->rc_cursor = nval;
		rctl_val_list_reset(rctl->rc_cursor);
		RCTLOP_SET(rctl, p, e, rctl_model_value(rctl->rc_dict_entry, p,
		    rctl->rc_cursor->rcv_value));

		ASSERT(rctl->rc_cursor != NULL);
	}

	return (0);
}

/*
 * int rctl_local_insert(rctl_hndl_t, rctl_val_t *)
 *
 * Overview
 *   Insert the rctl value into the appropriate rctl set for the calling
 *   process, given the handle.
 */
int
rctl_local_insert(rctl_hndl_t hndl, rctl_val_t *val, struct proc *p)
{
	return (rctl_local_op(hndl, NULL, val, rctl_local_insert_cb, p));
}

/*
 * rctl_local_insert_all_cb()
 *
 * Overview
 *   Called for RCENTITY_PROJECT rctls only, via rctlsys_projset().
 *
 *   Inserts new values from the project database (new_values).  alloc_values
 *   should be a linked list of pre-allocated rctl_val_t, which are used to
 *   populate (rc_projdb).
 *
 *   Should the *new_values linked list match the contents of the rctl's
 *   rp_projdb then we do nothing.
 *
 * Return Values
 *   0 is always returned.
 */
/*ARGSUSED*/
static int
rctl_local_insert_all_cb(rctl_hndl_t hndl, struct proc *p, rctl_entity_p_t *e,
    rctl_t *rctl, rctl_val_t *new_values, rctl_val_t *alloc_values)
{
	rctl_val_t *val;
	rctl_val_t *tmp_val;
	rctl_val_t *next;
	int modified = 0;

	/*
	 * If this the first time we've set this project rctl, then we delete
	 * all the privilege values.  These privilege values have been set by
	 * rctl_add_default_limit().
	 *
	 * We save some cycles here by not calling rctl_val_list_delete().
	 */
	if (rctl->rc_projdb == NULL) {
		val = rctl->rc_values;

		while (val != NULL) {
			if (val->rcv_privilege == RCPRIV_PRIVILEGED) {
				if (val->rcv_prev != NULL)
					val->rcv_prev->rcv_next = val->rcv_next;
				else
					rctl->rc_values = val->rcv_next;

				if (val->rcv_next != NULL)
					val->rcv_next->rcv_prev = val->rcv_prev;

				tmp_val = val;
				val = val->rcv_next;
				kmem_cache_free(rctl_val_cache, tmp_val);
			} else {
				val = val->rcv_next;
			}
		}
		modified = 1;
	}

	/*
	 * Delete active values previously set through the project database.
	 */
	val = rctl->rc_projdb;

	while (val != NULL) {

		/* Is the old value found in the new values? */
		if (rctl_val_list_find(&new_values, val) == NULL) {

			/*
			 * Delete from the active values if it originated from
			 * the project database.
			 */
			if (((tmp_val = rctl_val_list_find(&rctl->rc_values,
			    val)) != NULL) &&
			    (tmp_val->rcv_flagaction & RCTL_LOCAL_PROJDB)) {
				(void) rctl_val_list_delete(&rctl->rc_values,
				    tmp_val);
			}

			tmp_val = val->rcv_next;
			(void) rctl_val_list_delete(&rctl->rc_projdb, val);
			val = tmp_val;
			modified = 1;

		} else
			val = val->rcv_next;
	}

	/*
	 * Insert new values from the project database.
	 */
	while (new_values != NULL) {
		next = new_values->rcv_next;

		/*
		 * Insert this new value into the rc_projdb, and duplicate this
		 * entry to the active list.
		 */
		if (rctl_val_list_insert(&rctl->rc_projdb, new_values) == 0) {

			tmp_val = alloc_values->rcv_next;
			bcopy(new_values, alloc_values, sizeof (rctl_val_t));
			alloc_values->rcv_next = tmp_val;

			if (rctl_val_list_insert(&rctl->rc_values,
			    alloc_values) == 0) {
				/* inserted move alloc_values on */
				alloc_values = tmp_val;
				modified = 1;
			}
		} else {
			/*
			 * Unlike setrctl() we don't want to return an error on
			 * a duplicate entry; we are concerned solely with
			 * ensuring that all the values specified are set.
			 */
			kmem_cache_free(rctl_val_cache, new_values);
		}
		new_values = next;
	}

	/* Teardown any unused rctl_val_t */
	while (alloc_values != NULL) {
		tmp_val = alloc_values;
		alloc_values = alloc_values->rcv_next;
		kmem_cache_free(rctl_val_cache, tmp_val);
	}

	/* Reset the cursor if rctl values have been modified */
	if (modified) {
		rctl->rc_cursor = rctl->rc_values;
		rctl_val_list_reset(rctl->rc_cursor);
		RCTLOP_SET(rctl, p, e, rctl_model_value(rctl->rc_dict_entry, p,
		    rctl->rc_cursor->rcv_value));
	}

	return (0);
}

int
rctl_local_insert_all(rctl_hndl_t hndl, rctl_val_t *new_values,
    rctl_val_t *alloc_values, struct proc *p)
{
	return (rctl_local_op(hndl, new_values, alloc_values,
	    rctl_local_insert_all_cb, p));
}

/*
 * rctl_local_replace_all_cb()
 *
 * Overview
 *   Called for RCENTITY_PROJECT rctls only, via rctlsys_projset().
 *
 *   Clears the active rctl values (rc_values), and stored values from the
 *   previous insertions from the project database (rc_projdb).
 *
 *   Inserts new values from the project database (new_values).  alloc_values
 *   should be a linked list of pre-allocated rctl_val_t, which are used to
 *   populate (rc_projdb).
 *
 * Return Values
 *   0 is always returned.
 */
/*ARGSUSED*/
static int
rctl_local_replace_all_cb(rctl_hndl_t hndl, struct proc *p, rctl_entity_p_t *e,
    rctl_t *rctl, rctl_val_t *new_values, rctl_val_t *alloc_values)
{
	rctl_val_t *val;
	rctl_val_t *next;
	rctl_val_t *tmp_val;

	/* Delete all the privilege vaules */
	val = rctl->rc_values;

	while (val != NULL) {
		if (val->rcv_privilege == RCPRIV_PRIVILEGED) {
			if (val->rcv_prev != NULL)
				val->rcv_prev->rcv_next = val->rcv_next;
			else
				rctl->rc_values = val->rcv_next;

			if (val->rcv_next != NULL)
				val->rcv_next->rcv_prev = val->rcv_prev;

			tmp_val = val;
			val = val->rcv_next;
			kmem_cache_free(rctl_val_cache, tmp_val);
		} else {
			val = val->rcv_next;
		}
	}

	/* Delete the contents of rc_projdb */
	val = rctl->rc_projdb;
	while (val != NULL) {

		tmp_val = val;
		val = val->rcv_next;
		kmem_cache_free(rctl_val_cache, tmp_val);
	}
	rctl->rc_projdb = NULL;

	/*
	 * Insert new values from the project database.
	 */
	while (new_values != NULL) {
		next = new_values->rcv_next;

		if (rctl_val_list_insert(&rctl->rc_projdb, new_values) == 0) {
			tmp_val = alloc_values->rcv_next;
			bcopy(new_values, alloc_values, sizeof (rctl_val_t));
			alloc_values->rcv_next = tmp_val;

			if (rctl_val_list_insert(&rctl->rc_values,
			    alloc_values) == 0) {
				/* inserted, so move alloc_values on */
				alloc_values = tmp_val;
			}
		} else {
			/*
			 * Unlike setrctl() we don't want to return an error on
			 * a duplicate entry; we are concerned solely with
			 * ensuring that all the values specified are set.
			 */
			kmem_cache_free(rctl_val_cache, new_values);
		}

		new_values = next;
	}

	/* Teardown any unused rctl_val_t */
	while (alloc_values != NULL) {
		tmp_val = alloc_values;
		alloc_values = alloc_values->rcv_next;
		kmem_cache_free(rctl_val_cache, tmp_val);
	}

	/* Always reset the cursor */
	rctl->rc_cursor = rctl->rc_values;
	rctl_val_list_reset(rctl->rc_cursor);
	RCTLOP_SET(rctl, p, e, rctl_model_value(rctl->rc_dict_entry, p,
	    rctl->rc_cursor->rcv_value));

	return (0);
}

int
rctl_local_replace_all(rctl_hndl_t hndl, rctl_val_t *new_values,
    rctl_val_t *alloc_values, struct proc *p)
{
	return (rctl_local_op(hndl, new_values, alloc_values,
	    rctl_local_replace_all_cb, p));
}

static int
rctl_local_replace_cb(rctl_hndl_t hndl, struct proc *p, rctl_entity_p_t *e,
    rctl_t *rctl, rctl_val_t *oval, rctl_val_t *nval)
{
	int ret;
	rctl_val_t *tmp;

	/* Verify that old will be delete-able */
	tmp = rctl_val_list_find(&rctl->rc_values, oval);
	if (tmp == NULL)
		return (ESRCH);
	/*
	 * Caller should verify that value being deleted is not the
	 * system value.
	 */
	ASSERT(tmp->rcv_privilege != RCPRIV_SYSTEM);

	/*
	 * rctl_local_insert_cb() does the job of flagging an error
	 * for any duplicate values. So, call rctl_local_insert_cb()
	 * for the new value first, then do deletion of the old value.
	 * Since this is a callback function to rctl_local_op, we can
	 * count on rcs_lock being held at this point. This guarantees
	 * that there is at no point a visible list which contains both
	 * new and old values.
	 */
	if (ret = rctl_local_insert_cb(hndl, p, e, rctl, NULL, nval))
		return (ret);

	ret = rctl_local_delete_cb(hndl, p, e, rctl, NULL, oval);
	ASSERT(ret == 0);
	return (0);
}

/*
 * int rctl_local_replace(rctl_hndl_t, void *, int, uint64_t *)
 *
 * Overview
 *   Replace the rctl value with a new one.
 *
 * Return values
 *   0 for successful replace, errno otherwise.
 */
int
rctl_local_replace(rctl_hndl_t hndl, rctl_val_t *oval, rctl_val_t *nval,
    struct proc *p)
{
	return (rctl_local_op(hndl, oval, nval, rctl_local_replace_cb, p));
}

/*
 * int rctl_rlimit_get(rctl_hndl_t, struct proc *, struct rlimit64 *)
 *
 * Overview
 *   To support rlimit compatibility, we need a function which takes a 64-bit
 *   rlimit and encodes it as appropriate rcontrol values on the given rcontrol.
 *   This operation is only intended for legacy rlimits.
 */
int
rctl_rlimit_get(rctl_hndl_t rc, struct proc *p, struct rlimit64 *rlp64)
{
	rctl_t *rctl;
	rctl_val_t *rval;
	rctl_set_t *rset = p->p_rctls;
	int soft_limit_seen = 0;
	int test_for_deny = 1;

	mutex_enter(&rset->rcs_lock);
	if (rctl_set_find(rset, rc, &rctl) == -1) {
		mutex_exit(&rset->rcs_lock);
		return (-1);
	}

	rval = rctl->rc_values;

	if (rctl->rc_dict_entry->rcd_flagaction & (RCTL_GLOBAL_DENY_NEVER |
	    RCTL_GLOBAL_DENY_ALWAYS))
		test_for_deny = 0;

	/*
	 * 1.  Find the first control value with the RCTL_LOCAL_DENY bit set.
	 */
	while (rval != NULL && rval->rcv_privilege != RCPRIV_SYSTEM) {
		if (test_for_deny &&
		    (rval->rcv_flagaction & RCTL_LOCAL_DENY) == 0) {
			rval = rval->rcv_next;
			continue;
		}

		/*
		 * 2.  If this is an RCPRIV_BASIC value, then we've found the
		 * effective soft limit and should set rlim_cur.  We should then
		 * continue looking for another control value with the DENY bit
		 * set.
		 */
		if (rval->rcv_privilege == RCPRIV_BASIC) {
			if (soft_limit_seen) {
				rval = rval->rcv_next;
				continue;
			}

			if ((rval->rcv_flagaction & RCTL_LOCAL_MAXIMAL) == 0 &&
			    rval->rcv_value < rctl_model_maximum(
			    rctl->rc_dict_entry, p))
				rlp64->rlim_cur = rval->rcv_value;
			else
				rlp64->rlim_cur = RLIM64_INFINITY;
			soft_limit_seen = 1;

			rval = rval->rcv_next;
			continue;
		}

		/*
		 * 3.  This is an RCPRIV_PRIVILEGED value.  If we haven't found
		 * a soft limit candidate, then we've found the effective hard
		 * and soft limits and should set both  If we had found a soft
		 * limit, then this is only the hard limit and we need only set
		 * rlim_max.
		 */
		if ((rval->rcv_flagaction & RCTL_LOCAL_MAXIMAL) == 0 &&
		    rval->rcv_value < rctl_model_maximum(rctl->rc_dict_entry,
		    p))
			rlp64->rlim_max = rval->rcv_value;
		else
			rlp64->rlim_max = RLIM64_INFINITY;
		if (!soft_limit_seen)
			rlp64->rlim_cur = rlp64->rlim_max;

		mutex_exit(&rset->rcs_lock);
		return (0);
	}

	if (rval == NULL) {
		/*
		 * This control sequence is corrupt, as it is not terminated by
		 * a system privileged control value.
		 */
		mutex_exit(&rset->rcs_lock);
		return (-1);
	}

	/*
	 * 4.  If we run into a RCPRIV_SYSTEM value, then the hard limit (and
	 * the soft, if we haven't a soft candidate) should be the value of the
	 * system control value.
	 */
	if ((rval->rcv_flagaction & RCTL_LOCAL_MAXIMAL) == 0 &&
	    rval->rcv_value < rctl_model_maximum(rctl->rc_dict_entry, p))
		rlp64->rlim_max = rval->rcv_value;
	else
		rlp64->rlim_max = RLIM64_INFINITY;

	if (!soft_limit_seen)
		rlp64->rlim_cur = rlp64->rlim_max;

	mutex_exit(&rset->rcs_lock);
	return (0);
}

/*
 * rctl_alloc_gp_t *rctl_rlimit_set_prealloc(uint_t)
 *
 * Overview
 *   Before making a series of calls to rctl_rlimit_set(), we must have a
 *   preallocated batch of resource control values, as rctl_rlimit_set() can
 *   potentially consume two resource control values per call.
 *
 * Return values
 *   A populated resource control allocation group with 2n resource control
 *   values.
 *
 * Caller's context
 *   Must be safe for KM_SLEEP allocations.
 */
rctl_alloc_gp_t *
rctl_rlimit_set_prealloc(uint_t n)
{
	rctl_alloc_gp_t *gp = kmem_zalloc(sizeof (rctl_alloc_gp_t), KM_SLEEP);

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	gp->rcag_nvals = 2 * n;

	rctl_gp_alloc(gp);

	return (gp);
}

/*
 * int rctl_rlimit_set(rctl_hndl_t, struct proc *, struct rlimit64 *, int,
 *   int)
 *
 * Overview
 *   To support rlimit compatibility, we need a function which takes a 64-bit
 *   rlimit and encodes it as appropriate rcontrol values on the given rcontrol.
 *   This operation is only intended for legacy rlimits.
 *
 *   The implementation of rctl_rlimit_set() is a bit clever, as it tries to
 *   minimize the number of values placed on the value sequence in various
 *   cases.  Furthermore, we don't allow multiple identical privilege-action
 *   values on the same sequence.  (That is, we don't want a sequence like
 *   "while (1) { rlim.rlim_cur++; setrlimit(..., rlim); }" to exhaust kernel
 *   memory.)  So we want to delete any values with the same privilege value and
 *   action.
 *
 * Return values
 *   0 for successful set, errno otherwise. Errno will be either EINVAL
 *   or EPERM, in keeping with defined errnos for ulimit() and setrlimit()
 *   system calls.
 */
/*ARGSUSED*/
int
rctl_rlimit_set(rctl_hndl_t rc, struct proc *p, struct rlimit64 *rlp64,
    rctl_alloc_gp_t *ragp, int flagaction, int signal, const cred_t *cr)
{
	rctl_t *rctl;
	rctl_val_t *rval, *rval_priv, *rval_basic;
	rctl_set_t *rset = p->p_rctls;
	rctl_qty_t max;
	rctl_entity_p_t e;
	struct rlimit64 cur_rl;

	e.rcep_t = RCENTITY_PROCESS;
	e.rcep_p.proc = p;

	if (rlp64->rlim_cur > rlp64->rlim_max)
		return (EINVAL);

	if (rctl_rlimit_get(rc, p, &cur_rl) == -1)
		return (EINVAL);

	/*
	 * If we are not privileged, we can only lower the hard limit.
	 */
	if ((rlp64->rlim_max > cur_rl.rlim_max) &&
	    cur_rl.rlim_max != RLIM64_INFINITY &&
	    secpolicy_resource(cr) != 0)
		return (EPERM);

	mutex_enter(&rset->rcs_lock);

	if (rctl_set_find(rset, rc, &rctl) == -1) {
		mutex_exit(&rset->rcs_lock);
		return (EINVAL);
	}

	rval_priv = rctl_gp_detach_val(ragp);

	rval = rctl->rc_values;

	while (rval != NULL) {
		rctl_val_t *next = rval->rcv_next;

		if (rval->rcv_privilege == RCPRIV_SYSTEM)
			break;

		if ((rval->rcv_privilege == RCPRIV_BASIC) ||
		    (rval->rcv_flagaction & ~RCTL_LOCAL_ACTION_MASK) ==
		    (flagaction & ~RCTL_LOCAL_ACTION_MASK)) {
			if (rctl->rc_cursor == rval) {
				rctl->rc_cursor = rval->rcv_next;
				rctl_val_list_reset(rctl->rc_cursor);
				RCTLOP_SET(rctl, p, &e, rctl_model_value(
				    rctl->rc_dict_entry, p,
				    rctl->rc_cursor->rcv_value));
			}
			(void) rctl_val_list_delete(&rctl->rc_values, rval);
		}

		rval = next;
	}

	rval_priv->rcv_privilege = RCPRIV_PRIVILEGED;
	rval_priv->rcv_flagaction = flagaction;
	if (rlp64->rlim_max == RLIM64_INFINITY) {
		rval_priv->rcv_flagaction |= RCTL_LOCAL_MAXIMAL;
		max = rctl->rc_dict_entry->rcd_max_native;
	} else {
		max = rlp64->rlim_max;
	}
	rval_priv->rcv_value = max;
	rval_priv->rcv_action_signal = signal;
	rval_priv->rcv_action_recipient = NULL;
	rval_priv->rcv_action_recip_pid = -1;
	rval_priv->rcv_firing_time = 0;
	rval_priv->rcv_prev = rval_priv->rcv_next = NULL;

	(void) rctl_val_list_insert(&rctl->rc_values, rval_priv);
	rctl->rc_cursor = rval_priv;
	rctl_val_list_reset(rctl->rc_cursor);
	RCTLOP_SET(rctl, p, &e, rctl_model_value(rctl->rc_dict_entry, p,
	    rctl->rc_cursor->rcv_value));

	if (rlp64->rlim_cur != RLIM64_INFINITY && rlp64->rlim_cur < max) {
		rval_basic = rctl_gp_detach_val(ragp);

		rval_basic->rcv_privilege = RCPRIV_BASIC;
		rval_basic->rcv_value = rlp64->rlim_cur;
		rval_basic->rcv_flagaction = flagaction;
		rval_basic->rcv_action_signal = signal;
		rval_basic->rcv_action_recipient = p;
		rval_basic->rcv_action_recip_pid = p->p_pid;
		rval_basic->rcv_firing_time = 0;
		rval_basic->rcv_prev = rval_basic->rcv_next = NULL;

		(void) rctl_val_list_insert(&rctl->rc_values, rval_basic);
		rctl->rc_cursor = rval_basic;
		rctl_val_list_reset(rctl->rc_cursor);
		RCTLOP_SET(rctl, p, &e, rctl_model_value(rctl->rc_dict_entry, p,
		    rctl->rc_cursor->rcv_value));
	}

	ASSERT(rctl->rc_cursor != NULL);

	mutex_exit(&rset->rcs_lock);
	return (0);
}


/*
 * rctl_hndl_t rctl_register(const char *, rctl_entity_t, int, rlim64_t,
 *   rlim64_t, rctl_ops_t *)
 *
 * Overview
 *   rctl_register() performs a look-up in the dictionary of rctls
 *   active on the system; if a rctl of that name is absent, an entry is
 *   made into the dictionary.  The rctl is returned with its reference
 *   count incremented by one.  If the rctl name already exists, we panic.
 *   (Were the resource control system to support dynamic loading and unloading,
 *   which it is structured for, duplicate registration should lead to load
 *   failure instead of panicking.)
 *
 *   Each registered rctl has a requirement that a RCPRIV_SYSTEM limit be
 *   defined.  This limit contains the highest possible value for this quantity
 *   on the system.  Furthermore, the registered control must provide infinite
 *   values for all applicable address space models supported by the operating
 *   system.  Attempts to set resource control values beyond the system limit
 *   will fail.
 *
 * Return values
 *   The rctl's ID.
 *
 * Caller's context
 *   Caller must be in a context suitable for KM_SLEEP allocations.
 */
rctl_hndl_t
rctl_register(
    const char *name,
    rctl_entity_t entity,
    int global_flags,
    rlim64_t max_native,
    rlim64_t max_ilp32,
    rctl_ops_t *ops)
{
	rctl_t *rctl = kmem_cache_alloc(rctl_cache, KM_SLEEP);
	rctl_val_t *rctl_val = kmem_cache_alloc(rctl_val_cache, KM_SLEEP);
	rctl_dict_entry_t *rctl_de = kmem_zalloc(sizeof (rctl_dict_entry_t),
	    KM_SLEEP);
	rctl_t *old_rctl;
	rctl_hndl_t rhndl;
	int localflags;

	ASSERT(ops != NULL);

	bzero(rctl, sizeof (rctl_t));
	bzero(rctl_val, sizeof (rctl_val_t));

	if (global_flags & RCTL_GLOBAL_DENY_NEVER)
		localflags = RCTL_LOCAL_MAXIMAL;
	else
		localflags = RCTL_LOCAL_MAXIMAL | RCTL_LOCAL_DENY;

	rctl_val->rcv_privilege = RCPRIV_SYSTEM;
	rctl_val->rcv_value = max_native;
	rctl_val->rcv_flagaction = localflags;
	rctl_val->rcv_action_signal = 0;
	rctl_val->rcv_action_recipient = NULL;
	rctl_val->rcv_action_recip_pid = -1;
	rctl_val->rcv_firing_time = 0;
	rctl_val->rcv_next = NULL;
	rctl_val->rcv_prev = NULL;

	rctl_de->rcd_name = (char *)name;
	rctl_de->rcd_default_value = rctl_val;
	rctl_de->rcd_max_native = max_native;
	rctl_de->rcd_max_ilp32 = max_ilp32;
	rctl_de->rcd_entity = entity;
	rctl_de->rcd_ops = ops;
	rctl_de->rcd_flagaction = global_flags;

	rctl->rc_dict_entry = rctl_de;
	rctl->rc_values = rctl_val;

	/*
	 * 1.  Take global lock, validate nonexistence of name, get ID.
	 */
	mutex_enter(&rctl_dict_lock);

	if (mod_hash_find(rctl_dict_by_name, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&rhndl) != MH_ERR_NOTFOUND)
		panic("duplicate registration of rctl %s", name);

	rhndl = rctl_de->rcd_id = rctl->rc_id =
	    (rctl_hndl_t)id_alloc(rctl_ids);

	/*
	 * 2.  Insert name-entry pair in rctl_dict_by_name.
	 */
	if (mod_hash_insert(rctl_dict_by_name, (mod_hash_key_t)name,
	    (mod_hash_val_t)rctl_de))
		panic("unable to insert rctl dict entry for %s (%u)", name,
		    (uint_t)rctl->rc_id);

	/*
	 * 3.  Insert ID-rctl_t * pair in rctl_dict.
	 */
	if (mod_hash_find(rctl_dict, (mod_hash_key_t)(uintptr_t)rctl->rc_id,
	    (mod_hash_val_t *)&old_rctl) != MH_ERR_NOTFOUND)
		panic("duplicate rctl ID %u registered", rctl->rc_id);

	if (mod_hash_insert(rctl_dict, (mod_hash_key_t)(uintptr_t)rctl->rc_id,
	    (mod_hash_val_t)rctl))
		panic("unable to insert rctl %s/%u (%p)", name,
		    (uint_t)rctl->rc_id, (void *)rctl);

	/*
	 * 3a. Insert rctl_dict_entry_t * in appropriate entity list.
	 */

	mutex_enter(&rctl_lists_lock);

	switch (entity) {
	case RCENTITY_ZONE:
	case RCENTITY_PROJECT:
	case RCENTITY_TASK:
	case RCENTITY_PROCESS:
		rctl_de->rcd_next = rctl_lists[entity];
		rctl_lists[entity] = rctl_de;
		break;
	default:
		panic("registering unknown rctl entity %d (%s)", entity,
		    name);
		break;
	}

	mutex_exit(&rctl_lists_lock);

	/*
	 * 4.  Drop lock.
	 */
	mutex_exit(&rctl_dict_lock);

	return (rhndl);
}

/*
 * static int rctl_global_action(rctl_t *r, rctl_set_t *rset, struct proc *p,
 *    rctl_val_t *v)
 *
 * Overview
 *   rctl_global_action() takes, in according with the flags on the rctl_dict
 *   entry for the given control, the appropriate actions on the exceeded
 *   control value.  Additionally, rctl_global_action() updates the firing time
 *   on the exceeded value.
 *
 * Return values
 *   A bitmask reflecting the actions actually taken.
 *
 * Caller's context
 *   No restrictions on context.
 */
/*ARGSUSED*/
static int
rctl_global_action(rctl_t *r, rctl_set_t *rset, struct proc *p, rctl_val_t *v)
{
	rctl_dict_entry_t *rde = r->rc_dict_entry;
	const char *pr, *en, *idstr;
	id_t id;
	enum {
		SUFFIX_NONE,	/* id consumed directly */
		SUFFIX_NUMERIC,	/* id consumed in suffix */
		SUFFIX_STRING	/* idstr consumed in suffix */
	} suffix = SUFFIX_NONE;
	int ret = 0;

	v->rcv_firing_time = gethrtime();

	switch (v->rcv_privilege) {
	case RCPRIV_BASIC:
		pr = "basic";
		break;
	case RCPRIV_PRIVILEGED:
		pr = "privileged";
		break;
	case RCPRIV_SYSTEM:
		pr = "system";
		break;
	default:
		pr = "unknown";
		break;
	}

	switch (rde->rcd_entity) {
	case RCENTITY_PROCESS:
		en = "process";
		id = p->p_pid;
		suffix = SUFFIX_NONE;
		break;
	case RCENTITY_TASK:
		en = "task";
		id = p->p_task->tk_tkid;
		suffix = SUFFIX_NUMERIC;
		break;
	case RCENTITY_PROJECT:
		en = "project";
		id = p->p_task->tk_proj->kpj_id;
		suffix = SUFFIX_NUMERIC;
		break;
	case RCENTITY_ZONE:
		en = "zone";
		idstr = p->p_zone->zone_name;
		suffix = SUFFIX_STRING;
		break;
	default:
		en = "unknown entity associated with process";
		id = p->p_pid;
		suffix = SUFFIX_NONE;
		break;
	}

	if (rde->rcd_flagaction & RCTL_GLOBAL_SYSLOG) {
		switch (suffix) {
		default:
		case SUFFIX_NONE:
			(void) strlog(0, 0, 0,
			    rde->rcd_strlog_flags | log_global.lz_active,
			    "%s rctl %s (value %llu) exceeded by %s %d.",
			    pr, rde->rcd_name, v->rcv_value, en, id);
			break;
		case SUFFIX_NUMERIC:
			(void) strlog(0, 0, 0,
			    rde->rcd_strlog_flags | log_global.lz_active,
			    "%s rctl %s (value %llu) exceeded by process %d"
			    " in %s %d.",
			    pr, rde->rcd_name, v->rcv_value, p->p_pid,
			    en, id);
			break;
		case SUFFIX_STRING:
			(void) strlog(0, 0, 0,
			    rde->rcd_strlog_flags | log_global.lz_active,
			    "%s rctl %s (value %llu) exceeded by process %d"
			    " in %s %s.",
			    pr, rde->rcd_name, v->rcv_value, p->p_pid,
			    en, idstr);
			break;
		}
	}

	if (rde->rcd_flagaction & RCTL_GLOBAL_DENY_ALWAYS)
		ret |= RCT_DENY;

	return (ret);
}

static int
rctl_local_action(rctl_t *r, rctl_set_t *rset, struct proc *p, rctl_val_t *v,
    uint_t safety)
{
	int ret = 0;
	sigqueue_t *sqp = NULL;
	rctl_dict_entry_t *rde = r->rc_dict_entry;
	int unobservable = (rde->rcd_flagaction & RCTL_GLOBAL_UNOBSERVABLE);

	proc_t *recipient = v->rcv_action_recipient;
	id_t recip_pid = v->rcv_action_recip_pid;
	int recip_signal = v->rcv_action_signal;
	uint_t flagaction = v->rcv_flagaction;

	if (safety == RCA_UNSAFE_ALL) {
		if (flagaction & RCTL_LOCAL_DENY) {
			ret |= RCT_DENY;
		}
		return (ret);
	}

	if (flagaction & RCTL_LOCAL_SIGNAL) {
		/*
		 * We can build a siginfo only in the case that it is
		 * safe for us to drop p_lock.  (For asynchronous
		 * checks this is currently not true.)
		 */
		if (safety == RCA_SAFE) {
			mutex_exit(&rset->rcs_lock);
			mutex_exit(&p->p_lock);
			sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
			mutex_enter(&p->p_lock);
			mutex_enter(&rset->rcs_lock);

			sqp->sq_info.si_signo = recip_signal;
			sqp->sq_info.si_code = SI_RCTL;
			sqp->sq_info.si_errno = 0;
			sqp->sq_info.si_entity = (int)rde->rcd_entity;
		}

		if (recipient == NULL || recipient == p) {
			ret |= RCT_SIGNAL;

			if (sqp == NULL) {
				sigtoproc(p, NULL, recip_signal);
			} else if (p == curproc) {
				/*
				 * Then this is a synchronous test and we can
				 * direct the signal at the violating thread.
				 */
				sigaddqa(curproc, curthread, sqp);
			} else {
				sigaddqa(p, NULL, sqp);
			}
		} else if (!unobservable) {
			proc_t *rp;

			mutex_exit(&rset->rcs_lock);
			mutex_exit(&p->p_lock);

			mutex_enter(&pidlock);
			if ((rp = prfind(recip_pid)) == recipient) {
				/*
				 * Recipient process is still alive, but may not
				 * be in this task or project any longer.  In
				 * this case, the recipient's resource control
				 * set pertinent to this control will have
				 * changed--and we will not deliver the signal,
				 * as the recipient process is trying to tear
				 * itself off of its former set.
				 */
				mutex_enter(&rp->p_lock);
				mutex_exit(&pidlock);

				if (rctl_entity_obtain_rset(rde, rp) == rset) {
					ret |= RCT_SIGNAL;

					if (sqp == NULL)
						sigtoproc(rp, NULL,
						    recip_signal);
					else
						sigaddqa(rp, NULL, sqp);
				} else if (sqp) {
					kmem_free(sqp, sizeof (sigqueue_t));
				}
				mutex_exit(&rp->p_lock);
			} else {
				mutex_exit(&pidlock);
				if (sqp)
					kmem_free(sqp, sizeof (sigqueue_t));
			}

			mutex_enter(&p->p_lock);
			/*
			 * Since we dropped p_lock, we may no longer be in the
			 * same task or project as we were at entry.  It is thus
			 * unsafe for us to reacquire the set lock at this
			 * point; callers of rctl_local_action() must handle
			 * this possibility.
			 */
			ret |= RCT_LK_ABANDONED;
		} else if (sqp) {
			kmem_free(sqp, sizeof (sigqueue_t));
		}
	}

	if ((flagaction & RCTL_LOCAL_DENY) &&
	    (recipient == NULL || recipient == p)) {
		ret |= RCT_DENY;
	}

	return (ret);
}

/*
 * int rctl_action(rctl_hndl_t, rctl_set_t *, struct proc *, uint_t)
 *
 * Overview
 *   Take the action associated with the enforced value (as defined by
 *   rctl_get_enforced_value()) being exceeded or encountered.  Possibly perform
 *   a restricted subset of the available actions, if circumstances dictate that
 *   we cannot safely allocate memory (for a sigqueue_t) or guarantee process
 *   persistence across the duration of the function (an asynchronous action).
 *
 * Return values
 *   Actions taken, according to the rctl_test bitmask.
 *
 * Caller's context
 *   Safe to acquire rcs_lock.
 */
int
rctl_action(rctl_hndl_t hndl, rctl_set_t *rset, struct proc *p, uint_t safety)
{
	return (rctl_action_entity(hndl, rset, p, NULL, safety));
}

int
rctl_action_entity(rctl_hndl_t hndl, rctl_set_t *rset, struct proc *p,
    rctl_entity_p_t *e, uint_t safety)
{
	int ret = RCT_NONE;
	rctl_t *lrctl;
	rctl_entity_p_t e_tmp;

rctl_action_acquire:
	mutex_enter(&rset->rcs_lock);
	if (rctl_set_find(rset, hndl, &lrctl) == -1) {
		mutex_exit(&rset->rcs_lock);
		return (ret);
	}

	if (e == NULL) {
		rctl_entity_obtain_entity_p(lrctl->rc_dict_entry->rcd_entity,
		    p, &e_tmp);
		e = &e_tmp;
	}

	if ((ret & RCT_LK_ABANDONED) == 0) {
		ret |= rctl_global_action(lrctl, rset, p, lrctl->rc_cursor);

		RCTLOP_ACTION(lrctl, p, e);

		ret |= rctl_local_action(lrctl, rset, p,
		    lrctl->rc_cursor, safety);

		if (ret & RCT_LK_ABANDONED)
			goto rctl_action_acquire;
	}

	ret &= ~RCT_LK_ABANDONED;

	if (!(ret & RCT_DENY) &&
	    lrctl->rc_cursor->rcv_next != NULL) {
		lrctl->rc_cursor = lrctl->rc_cursor->rcv_next;

		RCTLOP_SET(lrctl, p, e, rctl_model_value(lrctl->rc_dict_entry,
		    p, lrctl->rc_cursor->rcv_value));

	}
	mutex_exit(&rset->rcs_lock);

	return (ret);
}

/*
 * int rctl_test(rctl_hndl_t, rctl_set_t *, struct proc *, rctl_qty_t, uint_t)
 *
 * Overview
 *   Increment the resource associated with the given handle, returning zero if
 *   the incremented value does not exceed the threshold for the current limit
 *   on the resource.
 *
 * Return values
 *   Actions taken, according to the rctl_test bitmask.
 *
 * Caller's context
 *   p_lock held by caller.
 */
/*ARGSUSED*/
int
rctl_test(rctl_hndl_t rhndl, rctl_set_t *rset, struct proc *p,
    rctl_qty_t incr, uint_t flags)
{
	return (rctl_test_entity(rhndl, rset, p, NULL, incr, flags));
}

int
rctl_test_entity(rctl_hndl_t rhndl, rctl_set_t *rset, struct proc *p,
    rctl_entity_p_t *e, rctl_qty_t incr, uint_t flags)
{
	rctl_t *lrctl;
	int ret = RCT_NONE;
	rctl_entity_p_t e_tmp;
	if (p == &p0) {
		/*
		 * We don't enforce rctls on the kernel itself.
		 */
		return (ret);
	}

rctl_test_acquire:
	ASSERT(MUTEX_HELD(&p->p_lock));

	mutex_enter(&rset->rcs_lock);

	/*
	 * Dereference from rctl_set.  We don't enforce newly loaded controls
	 * that haven't been set on this entity (since the only valid value is
	 * the infinite system value).
	 */
	if (rctl_set_find(rset, rhndl, &lrctl) == -1) {
		mutex_exit(&rset->rcs_lock);
		return (ret);
	}

	/*
	 * This control is currently unenforced:  maximal value on control
	 * supporting infinitely available resource.
	 */
	if ((lrctl->rc_dict_entry->rcd_flagaction & RCTL_GLOBAL_INFINITE) &&
	    (lrctl->rc_cursor->rcv_flagaction & RCTL_LOCAL_MAXIMAL)) {

		mutex_exit(&rset->rcs_lock);
		return (ret);
	}

	/*
	 * If we have been called by rctl_test, look up the entity pointer
	 * from the proc pointer.
	 */
	if (e == NULL) {
		rctl_entity_obtain_entity_p(lrctl->rc_dict_entry->rcd_entity,
		    p, &e_tmp);
		e = &e_tmp;
	}

	/*
	 * Get enforced rctl value and current usage.  Test the increment
	 * with the current usage against the enforced value--take action as
	 * necessary.
	 */
	while (RCTLOP_TEST(lrctl, p, e, lrctl->rc_cursor, incr, flags)) {
		if ((ret & RCT_LK_ABANDONED) == 0) {
			ret |= rctl_global_action(lrctl, rset, p,
			    lrctl->rc_cursor);

			RCTLOP_ACTION(lrctl, p, e);

			ret |= rctl_local_action(lrctl, rset, p,
			    lrctl->rc_cursor, flags);

			if (ret & RCT_LK_ABANDONED)
				goto rctl_test_acquire;
		}

		ret &= ~RCT_LK_ABANDONED;

		if ((ret & RCT_DENY) == RCT_DENY ||
		    lrctl->rc_cursor->rcv_next == NULL) {
			ret |= RCT_DENY;
			break;
		}

		lrctl->rc_cursor = lrctl->rc_cursor->rcv_next;
		RCTLOP_SET(lrctl, p, e, rctl_model_value(lrctl->rc_dict_entry,
		    p, lrctl->rc_cursor->rcv_value));
	}

	mutex_exit(&rset->rcs_lock);

	return (ret);
}

/*
 * void rctl_init(void)
 *
 * Overview
 *   Initialize the rctl subsystem, including the primoridal rctls
 *   provided by the system.  New subsystem-specific rctls should _not_ be
 *   initialized here.  (Do it in your own file.)
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   Safe for KM_SLEEP allocations.  Must be called prior to any process model
 *   initialization.
 */
void
rctl_init(void)
{
	rctl_cache = kmem_cache_create("rctl_cache", sizeof (rctl_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
	rctl_val_cache = kmem_cache_create("rctl_val_cache",
	    sizeof (rctl_val_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	rctl_dict = mod_hash_create_extended("rctl_dict",
	    rctl_dict_size, mod_hash_null_keydtor, rctl_dict_val_dtor,
	    rctl_dict_hash_by_id, NULL, rctl_dict_id_cmp, KM_SLEEP);
	rctl_dict_by_name = mod_hash_create_strhash(
	    "rctl_handles_by_name", rctl_dict_size,
	    mod_hash_null_valdtor);
	rctl_ids = id_space_create("rctl_ids", 1, max_rctl_hndl);
	bzero(rctl_lists, (RC_MAX_ENTITY + 1) * sizeof (rctl_dict_entry_t *));

	rctlproc_init();
}

/*
 * rctl_incr_locked_mem(proc_t *p, kproject_t *proj, rctl_qty_t inc,
 *     int chargeproc)
 *
 * Increments the amount of locked memory on a project, and
 * zone. If proj is non-NULL the project must be held by the
 * caller; if it is NULL the proj and zone of proc_t p are used.
 * If chargeproc is non-zero, then the charged amount is cached
 * on p->p_locked_mem so that the charge can be migrated when a
 * process changes projects.
 *
 * Return values
 *    0 - success
 *    EAGAIN - attempting to increment locked memory is denied by one
 *      or more resource entities.
 */
int
rctl_incr_locked_mem(proc_t *p, kproject_t *proj, rctl_qty_t inc,
    int chargeproc)
{
	kproject_t *projp;
	zone_t *zonep;
	rctl_entity_p_t e;
	int ret = 0;

	ASSERT(p != NULL);
	ASSERT(MUTEX_HELD(&p->p_lock));
	if (proj != NULL) {
		projp = proj;
		zonep = proj->kpj_zone;
	} else {
		projp = p->p_task->tk_proj;
		zonep = p->p_zone;
	}

	mutex_enter(&zonep->zone_mem_lock);

	e.rcep_p.proj = projp;
	e.rcep_t = RCENTITY_PROJECT;

	/* check for overflow */
	if ((projp->kpj_data.kpd_locked_mem + inc) <
	    projp->kpj_data.kpd_locked_mem) {
		ret = EAGAIN;
		goto out;
	}
	if (projp->kpj_data.kpd_locked_mem + inc >
	    projp->kpj_data.kpd_locked_mem_ctl) {
		if (rctl_test_entity(rc_project_locked_mem, projp->kpj_rctls,
		    p, &e, inc, 0) & RCT_DENY) {
			ret = EAGAIN;
			goto out;
		}
	}
	e.rcep_p.zone = zonep;
	e.rcep_t = RCENTITY_ZONE;

	/* Check for overflow */
	if ((zonep->zone_locked_mem + inc) < zonep->zone_locked_mem) {
		ret = EAGAIN;
		goto out;
	}
	if (zonep->zone_locked_mem + inc > zonep->zone_locked_mem_ctl) {
		if (rctl_test_entity(rc_zone_locked_mem, zonep->zone_rctls,
		    p, &e, inc, 0) & RCT_DENY) {
			ret = EAGAIN;
			goto out;
		}
	}

	zonep->zone_locked_mem += inc;
	projp->kpj_data.kpd_locked_mem += inc;
	if (chargeproc != 0) {
		p->p_locked_mem += inc;
	}
out:
	mutex_exit(&zonep->zone_mem_lock);
	return (ret);
}

/*
 * rctl_decr_locked_mem(proc_t *p, kproject_t *proj, rctl_qty_t inc,
 *     int creditproc)
 *
 * Decrements the amount of locked memory on a project and
 * zone.  If proj is non-NULL the project must be held by the
 * caller; if it is NULL the proj and zone of proc_t p are used.
 * If creditproc is non-zero, then the quantity of locked memory
 * is subtracted from p->p_locked_mem.
 *
 * Return values
 *   none
 */
void
rctl_decr_locked_mem(proc_t *p, kproject_t *proj, rctl_qty_t inc,
    int creditproc)
{
	kproject_t *projp;
	zone_t *zonep;

	if (proj != NULL) {
		projp = proj;
		zonep = proj->kpj_zone;
	} else {
		ASSERT(p != NULL);
		ASSERT(MUTEX_HELD(&p->p_lock));
		projp = p->p_task->tk_proj;
		zonep = p->p_zone;
	}

	mutex_enter(&zonep->zone_mem_lock);
	zonep->zone_locked_mem -= inc;
	projp->kpj_data.kpd_locked_mem -= inc;
	if (creditproc != 0) {
		ASSERT(p != NULL);
		ASSERT(MUTEX_HELD(&p->p_lock));
		p->p_locked_mem -= inc;
	}
	mutex_exit(&zonep->zone_mem_lock);
}

/*
 * rctl_incr_swap(proc_t *, zone_t *, size_t)
 *
 * Overview
 *   Increments the swap charge on the specified zone.
 *
 * Return values
 *   0 on success.  EAGAIN if swap increment fails due an rctl value
 *   on the zone.
 *
 * Callers context
 *   p_lock held on specified proc.
 *   swap must be even multiple of PAGESIZE
 */
int
rctl_incr_swap(proc_t *proc, zone_t *zone, size_t swap)
{
	rctl_entity_p_t e;

	ASSERT(MUTEX_HELD(&proc->p_lock));
	ASSERT((swap & PAGEOFFSET) == 0);
	e.rcep_p.zone = zone;
	e.rcep_t = RCENTITY_ZONE;

	mutex_enter(&zone->zone_mem_lock);

	/* Check for overflow */
	if ((zone->zone_max_swap + swap) < zone->zone_max_swap) {
		mutex_exit(&zone->zone_mem_lock);
		return (EAGAIN);
	}
	if ((zone->zone_max_swap + swap) >
	    zone->zone_max_swap_ctl) {

		if (rctl_test_entity(rc_zone_max_swap, zone->zone_rctls,
		    proc, &e, swap, 0) & RCT_DENY) {
			mutex_exit(&zone->zone_mem_lock);
			return (EAGAIN);
		}
	}
	zone->zone_max_swap += swap;
	mutex_exit(&zone->zone_mem_lock);
	return (0);
}

/*
 * rctl_decr_swap(zone_t *, size_t)
 *
 * Overview
 *   Decrements the swap charge on the specified zone.
 *
 * Return values
 *   None
 *
 * Callers context
 *   swap must be even multiple of PAGESIZE
 */
void
rctl_decr_swap(zone_t *zone, size_t swap)
{
	ASSERT((swap & PAGEOFFSET) == 0);
	mutex_enter(&zone->zone_mem_lock);
	ASSERT(zone->zone_max_swap >= swap);
	zone->zone_max_swap -= swap;
	mutex_exit(&zone->zone_mem_lock);
}

/*
 * rctl_incr_lofi(proc_t *, zone_t *, size_t)
 *
 * Overview
 *   Increments the number of lofi devices for the zone.
 *
 * Return values
 *   0 on success.  EAGAIN if increment fails due an rctl value
 *   on the zone.
 *
 * Callers context
 *   p_lock held on specified proc.
 */
int
rctl_incr_lofi(proc_t *proc, zone_t *zone, size_t incr)
{
	rctl_entity_p_t e;

	ASSERT(MUTEX_HELD(&proc->p_lock));
	ASSERT(incr > 0);

	e.rcep_p.zone = zone;
	e.rcep_t = RCENTITY_ZONE;

	mutex_enter(&zone->zone_rctl_lock);

	/* Check for overflow */
	if ((zone->zone_max_lofi + incr) < zone->zone_max_lofi) {
		mutex_exit(&zone->zone_rctl_lock);
		return (EAGAIN);
	}
	if ((zone->zone_max_lofi + incr) > zone->zone_max_lofi_ctl) {
		if (rctl_test_entity(rc_zone_max_lofi, zone->zone_rctls,
		    proc, &e, incr, 0) & RCT_DENY) {
			mutex_exit(&zone->zone_rctl_lock);
			return (EAGAIN);
		}
	}
	zone->zone_max_lofi += incr;
	mutex_exit(&zone->zone_rctl_lock);
	return (0);
}

/*
 * rctl_decr_lofi(zone_t *, size_t)
 *
 * Overview
 *   Decrements the number of lofi devices for the zone.
 */
void
rctl_decr_lofi(zone_t *zone, size_t decr)
{
	mutex_enter(&zone->zone_rctl_lock);
	ASSERT(zone->zone_max_lofi >= decr);
	zone->zone_max_lofi -= decr;
	mutex_exit(&zone->zone_rctl_lock);
}

/*
 * Create resource kstat
 */
static kstat_t *
rctl_kstat_create_common(char *ks_name, int ks_instance, char *ks_class,
    uchar_t ks_type, uint_t ks_ndata, uchar_t ks_flags, int ks_zoneid)
{
	kstat_t *ksp = NULL;
	char name[KSTAT_STRLEN];

	(void) snprintf(name, KSTAT_STRLEN, "%s_%d", ks_name, ks_instance);

	if ((ksp = kstat_create_zone("caps", ks_zoneid,
	    name, ks_class, ks_type,
	    ks_ndata, ks_flags, ks_zoneid)) != NULL) {
		if (ks_zoneid != GLOBAL_ZONEID)
			kstat_zone_add(ksp, GLOBAL_ZONEID);
	}
	return (ksp);
}

/*
 * Create zone-specific resource kstat
 */
kstat_t *
rctl_kstat_create_zone(zone_t *zone, char *ks_name, uchar_t ks_type,
    uint_t ks_ndata, uchar_t ks_flags)
{
	char name[KSTAT_STRLEN];

	(void) snprintf(name, KSTAT_STRLEN, "%s_zone", ks_name);

	return (rctl_kstat_create_common(name, zone->zone_id, "zone_caps",
	    ks_type, ks_ndata, ks_flags, zone->zone_id));
}

/*
 * Create project-specific resource kstat
 */
kstat_t *
rctl_kstat_create_project(kproject_t *kpj, char *ks_name, uchar_t ks_type,
    uint_t ks_ndata, uchar_t ks_flags)
{
	char name[KSTAT_STRLEN];

	(void) snprintf(name, KSTAT_STRLEN, "%s_project", ks_name);

	return (rctl_kstat_create_common(name, kpj->kpj_id, "project_caps",
	    ks_type, ks_ndata, ks_flags, kpj->kpj_zoneid));
}

/*
 * Create task-specific resource kstat
 */
kstat_t *
rctl_kstat_create_task(task_t *tk, char *ks_name, uchar_t ks_type,
    uint_t ks_ndata, uchar_t ks_flags)
{
	char name[KSTAT_STRLEN];

	(void) snprintf(name, KSTAT_STRLEN, "%s_task", ks_name);

	return (rctl_kstat_create_common(name, tk->tk_tkid, "task_caps",
	    ks_type, ks_ndata, ks_flags, tk->tk_proj->kpj_zoneid));
}
