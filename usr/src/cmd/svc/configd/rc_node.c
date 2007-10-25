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

/*
 * rc_node.c - object management primitives
 *
 * This layer manages entities, their data structure, its locking, iterators,
 * transactions, and change notification requests.  Entities (scopes,
 * services, instances, snapshots, snaplevels, property groups, "composed"
 * property groups (see composition below), and properties) are represented by
 * rc_node_t's and are kept in the cache_hash hash table.  (Property values
 * are kept in the rn_values member of the respective property -- not as
 * separate objects.)  Iterators are represented by rc_node_iter_t's.
 * Transactions are represented by rc_node_tx_t's and are only allocated as
 * part of repcache_tx_t's in the client layer (client.c).  Change
 * notification requests are represented by rc_notify_t structures and are
 * described below.
 *
 * The entity tree is rooted at rc_scope, which rc_node_init() initializes to
 * the "localhost" scope.  The tree is filled in from the database on-demand
 * by rc_node_fill_children(), usually from rc_iter_create() since iterators
 * are the only way to find the children of an entity.
 *
 * Each rc_node_t is protected by its rn_lock member.  Operations which can
 * take too long, however, should serialize on an RC_NODE_WAITING_FLAGS bit in
 * rn_flags with the rc_node_{hold,rele}_flag() functions.  And since pointers
 * to rc_node_t's are allowed, rn_refs is a reference count maintained by
 * rc_node_{hold,rele}().  See configd.h for locking order information.
 *
 * When a node (property group or snapshot) is updated, a new node takes the
 * place of the old node in the global hash, and the old node is hung off of
 * the rn_former list of the new node.  At the same time, all of its children
 * have their rn_parent_ref pointer set, and any holds they have are reflected
 * in the old node's rn_other_refs count.  This is automatically kept up
 * to date, until the final reference to the subgraph is dropped, at which
 * point the node is unrefed and destroyed, along with all of its children.
 *
 * Locking rules: To dereference an rc_node_t * (usually to lock it), you must
 * have a hold (rc_node_hold()) on it or otherwise be sure that it hasn't been
 * rc_node_destroy()ed (hold a lock on its parent or child, hold a flag,
 * etc.).  Once you have locked an rc_node_t you must check its rn_flags for
 * RC_NODE_DEAD before you can use it.  This is usually done with the
 * rc_node_{wait,hold}_flag() functions (often via the rc_node_check_*()
 * functions & RC_NODE_*() macros), which fail if the object has died.
 *
 * Because name service lookups may take a long time and, more importantly
 * may trigger additional accesses to the repository, perm_granted() must be
 * called without holding any locks.
 *
 * An ITER_START for a non-ENTITY_VALUE induces an rc_node_fill_children()
 * call via rc_node_setup_iter() to populate the rn_children uu_list of the
 * rc_node_t * in question and a call to uu_list_walk_start() on that list.  For
 * ITER_READ, rc_iter_next() uses uu_list_walk_next() to find the next
 * apropriate child.
 *
 * An ITER_START for an ENTITY_VALUE makes sure the node has its values
 * filled, and sets up the iterator.  An ITER_READ_VALUE just copies out
 * the proper values and updates the offset information.
 *
 * When a property group gets changed by a transaction, it sticks around as
 * a child of its replacement property group, but is removed from the parent.
 *
 * To allow aliases, snapshots are implemented with a level of indirection.
 * A snapshot rc_node_t has a snapid which refers to an rc_snapshot_t in
 * snapshot.c which contains the authoritative snaplevel information.  The
 * snapid is "assigned" by rc_attach_snapshot().
 *
 * We provide the client layer with rc_node_ptr_t's to reference objects.
 * Objects referred to by them are automatically held & released by
 * rc_node_assign() & rc_node_clear().  The RC_NODE_PTR_*() macros are used at
 * client.c entry points to read the pointers.  They fetch the pointer to the
 * object, return (from the function) if it is dead, and lock, hold, or hold
 * a flag of the object.
 */

/*
 * Permission checking is authorization-based: some operations may only
 * proceed if the user has been assigned at least one of a set of
 * authorization strings.  The set of enabling authorizations depends on the
 * operation and the target object.  The set of authorizations assigned to
 * a user is determined by reading /etc/security/policy.conf, querying the
 * user_attr database, and possibly querying the prof_attr database, as per
 * chkauthattr() in libsecdb.
 *
 * The fastest way to decide whether the two sets intersect is by entering the
 * strings into a hash table and detecting collisions, which takes linear time
 * in the total size of the sets.  Except for the authorization patterns which
 * may be assigned to users, which without advanced pattern-matching
 * algorithms will take O(n) in the number of enabling authorizations, per
 * pattern.
 *
 * We can achieve some practical speed-ups by noting that if we enter all of
 * the authorizations from one of the sets into the hash table we can merely
 * check the elements of the second set for existence without adding them.
 * This reduces memory requirements and hash table clutter.  The enabling set
 * is well suited for this because it is internal to configd (for now, at
 * least).  Combine this with short-circuiting and we can even minimize the
 * number of queries to the security databases (user_attr & prof_attr).
 *
 * To force this usage onto clients we provide functions for adding
 * authorizations to the enabling set of a permission context structure
 * (perm_add_*()) and one to decide whether the the user associated with the
 * current door call client possesses any of them (perm_granted()).
 *
 * At some point, a generic version of this should move to libsecdb.
 */

/*
 * Composition is the combination of sets of properties.  The sets are ordered
 * and properties in higher sets obscure properties of the same name in lower
 * sets.  Here we present a composed view of an instance's properties as the
 * union of its properties and its service's properties.  Similarly the
 * properties of snaplevels are combined to form a composed view of the
 * properties of a snapshot (which should match the composed view of the
 * properties of the instance when the snapshot was taken).
 *
 * In terms of the client interface, the client may request that a property
 * group iterator for an instance or snapshot be composed.  Property groups
 * traversed by such an iterator may not have the target entity as a parent.
 * Similarly, the properties traversed by a property iterator for those
 * property groups may not have the property groups iterated as parents.
 *
 * Implementation requires that iterators for instances and snapshots be
 * composition-savvy, and that we have a "composed property group" entity
 * which represents the composition of a number of property groups.  Iteration
 * over "composed property groups" yields properties which may have different
 * parents, but for all other operations a composed property group behaves
 * like the top-most property group it represents.
 *
 * The implementation is based on the rn_cchain[] array of rc_node_t pointers
 * in rc_node_t.  For instances, the pointers point to the instance and its
 * parent service.  For snapshots they point to the child snaplevels, and for
 * composed property groups they point to property groups.  A composed
 * iterator carries an index into rn_cchain[].  Thus most of the magic ends up
 * int the rc_iter_*() code.
 */

#include <assert.h>
#include <atomic.h>
#include <errno.h>
#include <libuutil.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <prof_attr.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <user_attr.h>

#include "configd.h"

#define	AUTH_PREFIX		"solaris.smf."
#define	AUTH_MANAGE		AUTH_PREFIX "manage"
#define	AUTH_MODIFY		AUTH_PREFIX "modify"
#define	AUTH_MODIFY_PREFIX	AUTH_MODIFY "."
#define	AUTH_PG_ACTIONS		SCF_PG_RESTARTER_ACTIONS
#define	AUTH_PG_ACTIONS_TYPE	SCF_PG_RESTARTER_ACTIONS_TYPE
#define	AUTH_PG_GENERAL		SCF_PG_GENERAL
#define	AUTH_PG_GENERAL_TYPE	SCF_PG_GENERAL_TYPE
#define	AUTH_PG_GENERAL_OVR	SCF_PG_GENERAL_OVR
#define	AUTH_PG_GENERAL_OVR_TYPE  SCF_PG_GENERAL_OVR_TYPE
#define	AUTH_PROP_ACTION	"action_authorization"
#define	AUTH_PROP_ENABLED	"enabled"
#define	AUTH_PROP_MODIFY	"modify_authorization"
#define	AUTH_PROP_VALUE		"value_authorization"
#define	AUTH_PROP_READ		"read_authorization"
/* libsecdb should take care of this. */
#define	RBAC_AUTH_SEP		","

#define	MAX_VALID_CHILDREN 3

typedef struct rc_type_info {
	uint32_t	rt_type;		/* matches array index */
	uint32_t	rt_num_ids;
	uint32_t	rt_name_flags;
	uint32_t	rt_valid_children[MAX_VALID_CHILDREN];
} rc_type_info_t;

#define	RT_NO_NAME	-1U

static rc_type_info_t rc_types[] = {
	{REP_PROTOCOL_ENTITY_NONE, 0, RT_NO_NAME},
	{REP_PROTOCOL_ENTITY_SCOPE, 0, 0,
	    {REP_PROTOCOL_ENTITY_SERVICE, REP_PROTOCOL_ENTITY_SCOPE}},
	{REP_PROTOCOL_ENTITY_SERVICE, 0, UU_NAME_DOMAIN | UU_NAME_PATH,
	    {REP_PROTOCOL_ENTITY_INSTANCE, REP_PROTOCOL_ENTITY_PROPERTYGRP}},
	{REP_PROTOCOL_ENTITY_INSTANCE, 1, UU_NAME_DOMAIN,
	    {REP_PROTOCOL_ENTITY_SNAPSHOT, REP_PROTOCOL_ENTITY_PROPERTYGRP}},
	{REP_PROTOCOL_ENTITY_SNAPSHOT, 2, UU_NAME_DOMAIN,
	    {REP_PROTOCOL_ENTITY_SNAPLEVEL, REP_PROTOCOL_ENTITY_PROPERTYGRP}},
	{REP_PROTOCOL_ENTITY_SNAPLEVEL, 4, RT_NO_NAME,
	    {REP_PROTOCOL_ENTITY_PROPERTYGRP}},
	{REP_PROTOCOL_ENTITY_PROPERTYGRP, 5, UU_NAME_DOMAIN,
	    {REP_PROTOCOL_ENTITY_PROPERTY}},
	{REP_PROTOCOL_ENTITY_CPROPERTYGRP, 0, UU_NAME_DOMAIN,
	    {REP_PROTOCOL_ENTITY_PROPERTY}},
	{REP_PROTOCOL_ENTITY_PROPERTY, 7, UU_NAME_DOMAIN},
	{-1UL}
};
#define	NUM_TYPES	((sizeof (rc_types) / sizeof (*rc_types)))

/* Element of a permcheck_t hash table. */
struct pc_elt {
	struct pc_elt	*pce_next;
	char		pce_auth[1];
};

/* An authorization set hash table. */
typedef struct {
	struct pc_elt	**pc_buckets;
	uint_t		pc_bnum;		/* number of buckets */
	uint_t		pc_enum;		/* number of elements */
} permcheck_t;

static uu_list_pool_t *rc_children_pool;
static uu_list_pool_t *rc_pg_notify_pool;
static uu_list_pool_t *rc_notify_pool;
static uu_list_pool_t *rc_notify_info_pool;

static rc_node_t *rc_scope;

static pthread_mutex_t	rc_pg_notify_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	rc_pg_notify_cv = PTHREAD_COND_INITIALIZER;
static uint_t		rc_notify_in_use;	/* blocks removals */

static pthread_mutex_t	perm_lock = PTHREAD_MUTEX_INITIALIZER;

static void rc_node_unrefed(rc_node_t *np);

/*
 * We support an arbitrary number of clients interested in events for certain
 * types of changes.  Each client is represented by an rc_notify_info_t, and
 * all clients are chained onto the rc_notify_info_list.
 *
 * The rc_notify_list is the global notification list.  Each entry is of
 * type rc_notify_t, which is embedded in one of three other structures:
 *
 *	rc_node_t		property group update notification
 *	rc_notify_delete_t	object deletion notification
 *	rc_notify_info_t	notification clients
 *
 * Which type of object is determined by which pointer in the rc_notify_t is
 * non-NULL.
 *
 * New notifications and clients are added to the end of the list.
 * Notifications no-one is interested in are never added to the list.
 *
 * Clients use their position in the list to track which notifications they
 * have not yet reported.  As they process notifications, they move forward
 * in the list past them.  There is always a client at the beginning of the
 * list -- as he moves past notifications, he removes them from the list and
 * cleans them up.
 *
 * The rc_pg_notify_lock protects all notification state.  The rc_pg_notify_cv
 * is used for global signalling, and each client has a cv which he waits for
 * events of interest on.
 */
static uu_list_t	*rc_notify_info_list;
static uu_list_t	*rc_notify_list;

#define	HASH_SIZE	512
#define	HASH_MASK	(HASH_SIZE - 1)

#pragma align 64(cache_hash)
static cache_bucket_t cache_hash[HASH_SIZE];

#define	CACHE_BUCKET(h)		(&cache_hash[(h) & HASH_MASK])

static uint32_t
rc_node_hash(rc_node_lookup_t *lp)
{
	uint32_t type = lp->rl_type;
	uint32_t backend = lp->rl_backend;
	uint32_t mainid = lp->rl_main_id;
	uint32_t *ids = lp->rl_ids;

	rc_type_info_t *tp = &rc_types[type];
	uint32_t num_ids;
	uint32_t left;
	uint32_t hash;

	assert(backend == BACKEND_TYPE_NORMAL ||
	    backend == BACKEND_TYPE_NONPERSIST);

	assert(type > 0 && type < NUM_TYPES);
	num_ids = tp->rt_num_ids;

	left = MAX_IDS - num_ids;
	assert(num_ids <= MAX_IDS);

	hash = type * 7 + mainid * 5 + backend;

	while (num_ids-- > 0)
		hash = hash * 11 + *ids++ * 7;

	/*
	 * the rest should be zeroed
	 */
	while (left-- > 0)
		assert(*ids++ == 0);

	return (hash);
}

static int
rc_node_match(rc_node_t *np, rc_node_lookup_t *l)
{
	rc_node_lookup_t *r = &np->rn_id;
	rc_type_info_t *tp;
	uint32_t type;
	uint32_t num_ids;

	if (r->rl_main_id != l->rl_main_id)
		return (0);

	type = r->rl_type;
	if (type != l->rl_type)
		return (0);

	assert(type > 0 && type < NUM_TYPES);

	tp = &rc_types[r->rl_type];
	num_ids = tp->rt_num_ids;

	assert(num_ids <= MAX_IDS);
	while (num_ids-- > 0)
		if (r->rl_ids[num_ids] != l->rl_ids[num_ids])
			return (0);

	return (1);
}

/*
 * the "other" references on a node are maintained in an atomically
 * updated refcount, rn_other_refs.  This can be bumped from arbitrary
 * context, and tracks references to a possibly out-of-date node's children.
 *
 * To prevent the node from disappearing between the final drop of
 * rn_other_refs and the unref handling, rn_other_refs_held is bumped on
 * 0->1 transitions and decremented (with the node lock held) on 1->0
 * transitions.
 */
static void
rc_node_hold_other(rc_node_t *np)
{
	if (atomic_add_32_nv(&np->rn_other_refs, 1) == 1) {
		atomic_add_32(&np->rn_other_refs_held, 1);
		assert(np->rn_other_refs_held > 0);
	}
	assert(np->rn_other_refs > 0);
}

/*
 * No node locks may be held
 */
static void
rc_node_rele_other(rc_node_t *np)
{
	assert(np->rn_other_refs > 0);
	if (atomic_add_32_nv(&np->rn_other_refs, -1) == 0) {
		(void) pthread_mutex_lock(&np->rn_lock);
		assert(np->rn_other_refs_held > 0);
		if (atomic_add_32_nv(&np->rn_other_refs_held, -1) == 0 &&
		    np->rn_refs == 0 && (np->rn_flags & RC_NODE_OLD))
			rc_node_unrefed(np);
		else
			(void) pthread_mutex_unlock(&np->rn_lock);
	}
}

static void
rc_node_hold_locked(rc_node_t *np)
{
	assert(MUTEX_HELD(&np->rn_lock));

	if (np->rn_refs == 0 && (np->rn_flags & RC_NODE_PARENT_REF))
		rc_node_hold_other(np->rn_parent_ref);
	np->rn_refs++;
	assert(np->rn_refs > 0);
}

static void
rc_node_hold(rc_node_t *np)
{
	(void) pthread_mutex_lock(&np->rn_lock);
	rc_node_hold_locked(np);
	(void) pthread_mutex_unlock(&np->rn_lock);
}

static void
rc_node_rele_locked(rc_node_t *np)
{
	int unref = 0;
	rc_node_t *par_ref = NULL;

	assert(MUTEX_HELD(&np->rn_lock));
	assert(np->rn_refs > 0);

	if (--np->rn_refs == 0) {
		if (np->rn_flags & RC_NODE_PARENT_REF)
			par_ref = np->rn_parent_ref;

		/*
		 * Composed property groups are only as good as their
		 * references.
		 */
		if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_CPROPERTYGRP)
			np->rn_flags |= RC_NODE_DEAD;

		if ((np->rn_flags & (RC_NODE_DEAD|RC_NODE_OLD)) &&
		    np->rn_other_refs == 0 && np->rn_other_refs_held == 0)
			unref = 1;
	}

	if (unref)
		rc_node_unrefed(np);
	else
		(void) pthread_mutex_unlock(&np->rn_lock);

	if (par_ref != NULL)
		rc_node_rele_other(par_ref);
}

void
rc_node_rele(rc_node_t *np)
{
	(void) pthread_mutex_lock(&np->rn_lock);
	rc_node_rele_locked(np);
}

static cache_bucket_t *
cache_hold(uint32_t h)
{
	cache_bucket_t *bp = CACHE_BUCKET(h);
	(void) pthread_mutex_lock(&bp->cb_lock);
	return (bp);
}

static void
cache_release(cache_bucket_t *bp)
{
	(void) pthread_mutex_unlock(&bp->cb_lock);
}

static rc_node_t *
cache_lookup_unlocked(cache_bucket_t *bp, rc_node_lookup_t *lp)
{
	uint32_t h = rc_node_hash(lp);
	rc_node_t *np;

	assert(MUTEX_HELD(&bp->cb_lock));
	assert(bp == CACHE_BUCKET(h));

	for (np = bp->cb_head; np != NULL; np = np->rn_hash_next) {
		if (np->rn_hash == h && rc_node_match(np, lp)) {
			rc_node_hold(np);
			return (np);
		}
	}

	return (NULL);
}

static rc_node_t *
cache_lookup(rc_node_lookup_t *lp)
{
	uint32_t h;
	cache_bucket_t *bp;
	rc_node_t *np;

	h = rc_node_hash(lp);
	bp = cache_hold(h);

	np = cache_lookup_unlocked(bp, lp);

	cache_release(bp);

	return (np);
}

static void
cache_insert_unlocked(cache_bucket_t *bp, rc_node_t *np)
{
	assert(MUTEX_HELD(&bp->cb_lock));
	assert(np->rn_hash == rc_node_hash(&np->rn_id));
	assert(bp == CACHE_BUCKET(np->rn_hash));

	assert(np->rn_hash_next == NULL);

	np->rn_hash_next = bp->cb_head;
	bp->cb_head = np;
}

static void
cache_remove_unlocked(cache_bucket_t *bp, rc_node_t *np)
{
	rc_node_t **npp;

	assert(MUTEX_HELD(&bp->cb_lock));
	assert(np->rn_hash == rc_node_hash(&np->rn_id));
	assert(bp == CACHE_BUCKET(np->rn_hash));

	for (npp = &bp->cb_head; *npp != NULL; npp = &(*npp)->rn_hash_next)
		if (*npp == np)
			break;

	assert(*npp == np);
	*npp = np->rn_hash_next;
	np->rn_hash_next = NULL;
}

/*
 * verify that the 'parent' type can have a child typed 'child'
 * Fails with
 *   _INVALID_TYPE - argument is invalid
 *   _TYPE_MISMATCH - parent type cannot have children of type child
 */
static int
rc_check_parent_child(uint32_t parent, uint32_t child)
{
	int idx;
	uint32_t type;

	if (parent == 0 || parent >= NUM_TYPES ||
	    child == 0 || child >= NUM_TYPES)
		return (REP_PROTOCOL_FAIL_INVALID_TYPE); /* invalid types */

	for (idx = 0; idx < MAX_VALID_CHILDREN; idx++) {
		type = rc_types[parent].rt_valid_children[idx];
		if (type == child)
			return (REP_PROTOCOL_SUCCESS);
	}

	return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
}

/*
 * Fails with
 *   _INVALID_TYPE - type is invalid
 *   _BAD_REQUEST - name is an invalid name for a node of type type
 */
int
rc_check_type_name(uint32_t type, const char *name)
{
	if (type == 0 || type >= NUM_TYPES)
		return (REP_PROTOCOL_FAIL_INVALID_TYPE); /* invalid types */

	if (uu_check_name(name, rc_types[type].rt_name_flags) == -1)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	return (REP_PROTOCOL_SUCCESS);
}

static int
rc_check_pgtype_name(const char *name)
{
	if (uu_check_name(name, UU_NAME_DOMAIN) == -1)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	return (REP_PROTOCOL_SUCCESS);
}

static int
rc_notify_info_interested(rc_notify_info_t *rnip, rc_notify_t *np)
{
	rc_node_t *nnp = np->rcn_node;
	int i;

	assert(MUTEX_HELD(&rc_pg_notify_lock));

	if (np->rcn_delete != NULL) {
		assert(np->rcn_info == NULL && np->rcn_node == NULL);
		return (1);		/* everyone likes deletes */
	}
	if (np->rcn_node == NULL) {
		assert(np->rcn_info != NULL || np->rcn_delete != NULL);
		return (0);
	}
	assert(np->rcn_info == NULL);

	for (i = 0; i < RC_NOTIFY_MAX_NAMES; i++) {
		if (rnip->rni_namelist[i] != NULL) {
			if (strcmp(nnp->rn_name, rnip->rni_namelist[i]) == 0)
				return (1);
		}
		if (rnip->rni_typelist[i] != NULL) {
			if (strcmp(nnp->rn_type, rnip->rni_typelist[i]) == 0)
				return (1);
		}
	}
	return (0);
}

static void
rc_notify_insert_node(rc_node_t *nnp)
{
	rc_notify_t *np = &nnp->rn_notify;
	rc_notify_info_t *nip;
	int found = 0;

	assert(np->rcn_info == NULL);

	if (nnp->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP)
		return;

	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	np->rcn_node = nnp;
	for (nip = uu_list_first(rc_notify_info_list); nip != NULL;
	    nip = uu_list_next(rc_notify_info_list, nip)) {
		if (rc_notify_info_interested(nip, np)) {
			(void) pthread_cond_broadcast(&nip->rni_cv);
			found++;
		}
	}
	if (found)
		(void) uu_list_insert_before(rc_notify_list, NULL, np);
	else
		np->rcn_node = NULL;

	(void) pthread_mutex_unlock(&rc_pg_notify_lock);
}

static void
rc_notify_deletion(rc_notify_delete_t *ndp, const char *service,
    const char *instance, const char *pg)
{
	rc_notify_info_t *nip;

	uu_list_node_init(&ndp->rnd_notify, &ndp->rnd_notify.rcn_list_node,
	    rc_notify_pool);
	ndp->rnd_notify.rcn_delete = ndp;

	(void) snprintf(ndp->rnd_fmri, sizeof (ndp->rnd_fmri),
	    "svc:/%s%s%s%s%s", service,
	    (instance != NULL)? ":" : "", (instance != NULL)? instance : "",
	    (pg != NULL)? "/:properties/" : "", (pg != NULL)? pg : "");

	/*
	 * add to notification list, notify watchers
	 */
	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	for (nip = uu_list_first(rc_notify_info_list); nip != NULL;
	    nip = uu_list_next(rc_notify_info_list, nip))
		(void) pthread_cond_broadcast(&nip->rni_cv);
	(void) uu_list_insert_before(rc_notify_list, NULL, ndp);
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);
}

static void
rc_notify_remove_node(rc_node_t *nnp)
{
	rc_notify_t *np = &nnp->rn_notify;

	assert(np->rcn_info == NULL);
	assert(!MUTEX_HELD(&nnp->rn_lock));

	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	while (np->rcn_node != NULL) {
		if (rc_notify_in_use) {
			(void) pthread_cond_wait(&rc_pg_notify_cv,
			    &rc_pg_notify_lock);
			continue;
		}
		(void) uu_list_remove(rc_notify_list, np);
		np->rcn_node = NULL;
		break;
	}
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);
}

static void
rc_notify_remove_locked(rc_notify_t *np)
{
	assert(MUTEX_HELD(&rc_pg_notify_lock));
	assert(rc_notify_in_use == 0);

	(void) uu_list_remove(rc_notify_list, np);
	if (np->rcn_node) {
		np->rcn_node = NULL;
	} else if (np->rcn_delete) {
		uu_free(np->rcn_delete);
	} else {
		assert(0);	/* CAN'T HAPPEN */
	}
}

/*
 * Permission checking functions.  See comment atop this file.
 */
#ifndef NATIVE_BUILD
static permcheck_t *
pc_create()
{
	permcheck_t *p;

	p = uu_zalloc(sizeof (*p));
	if (p == NULL)
		return (NULL);
	p->pc_bnum = 8;			/* Normal case will only have 2 elts. */
	p->pc_buckets = uu_zalloc(sizeof (*p->pc_buckets) * p->pc_bnum);
	if (p->pc_buckets == NULL) {
		uu_free(p);
		return (NULL);
	}

	p->pc_enum = 0;
	return (p);
}

static void
pc_free(permcheck_t *pcp)
{
	uint_t i;
	struct pc_elt *ep, *next;

	for (i = 0; i < pcp->pc_bnum; ++i) {
		for (ep = pcp->pc_buckets[i]; ep != NULL; ep = next) {
			next = ep->pce_next;
			free(ep);
		}
	}

	free(pcp->pc_buckets);
	free(pcp);
}

static uint32_t
pc_hash(const char *auth)
{
	uint32_t h = 0, g;
	const char *p;

	/*
	 * Generic hash function from uts/common/os/modhash.c.
	 */
	for (p = auth; *p != '\0'; ++p) {
		h = (h << 4) + *p;
		g = (h & 0xf0000000);
		if (g != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

static int
pc_exists(const permcheck_t *pcp, const char *auth)
{
	uint32_t h;
	struct pc_elt *ep;

	h = pc_hash(auth);
	for (ep = pcp->pc_buckets[h & (pcp->pc_bnum - 1)];
	    ep != NULL;
	    ep = ep->pce_next) {
		if (strcmp(auth, ep->pce_auth) == 0)
			return (1);
	}

	return (0);
}

static int
pc_match(const permcheck_t *pcp, const char *pattern)
{
	uint_t i;
	struct pc_elt *ep;

	for (i = 0; i < pcp->pc_bnum; ++i) {
		for (ep = pcp->pc_buckets[i]; ep != NULL; ep = ep->pce_next) {
			if (_auth_match(pattern, ep->pce_auth))
				return (1);
		}
	}

	return (0);
}

static int
pc_grow(permcheck_t *pcp)
{
	uint_t new_bnum, i, j;
	struct pc_elt **new_buckets;
	struct pc_elt *ep, *next;

	new_bnum = pcp->pc_bnum * 2;
	if (new_bnum < pcp->pc_bnum)
		/* Homey don't play that. */
		return (-1);

	new_buckets = uu_zalloc(sizeof (*new_buckets) * new_bnum);
	if (new_buckets == NULL)
		return (-1);

	for (i = 0; i < pcp->pc_bnum; ++i) {
		for (ep = pcp->pc_buckets[i]; ep != NULL; ep = next) {
			next = ep->pce_next;
			j = pc_hash(ep->pce_auth) & (new_bnum - 1);
			ep->pce_next = new_buckets[j];
			new_buckets[j] = ep;
		}
	}

	uu_free(pcp->pc_buckets);
	pcp->pc_buckets = new_buckets;
	pcp->pc_bnum = new_bnum;

	return (0);
}

static int
pc_add(permcheck_t *pcp, const char *auth)
{
	struct pc_elt *ep;
	uint_t i;

	ep = uu_zalloc(offsetof(struct pc_elt, pce_auth) + strlen(auth) + 1);
	if (ep == NULL)
		return (-1);

	/* Grow if pc_enum / pc_bnum > 3/4. */
	if (pcp->pc_enum * 4 > 3 * pcp->pc_bnum)
		/* Failure is not a stopper; we'll try again next time. */
		(void) pc_grow(pcp);

	(void) strcpy(ep->pce_auth, auth);

	i = pc_hash(auth) & (pcp->pc_bnum - 1);
	ep->pce_next = pcp->pc_buckets[i];
	pcp->pc_buckets[i] = ep;

	++pcp->pc_enum;

	return (0);
}

/*
 * For the type of a property group, return the authorization which may be
 * used to modify it.
 */
static const char *
perm_auth_for_pgtype(const char *pgtype)
{
	if (strcmp(pgtype, SCF_GROUP_METHOD) == 0)
		return (AUTH_MODIFY_PREFIX "method");
	else if (strcmp(pgtype, SCF_GROUP_DEPENDENCY) == 0)
		return (AUTH_MODIFY_PREFIX "dependency");
	else if (strcmp(pgtype, SCF_GROUP_APPLICATION) == 0)
		return (AUTH_MODIFY_PREFIX "application");
	else if (strcmp(pgtype, SCF_GROUP_FRAMEWORK) == 0)
		return (AUTH_MODIFY_PREFIX "framework");
	else
		return (NULL);
}

/*
 * Fails with
 *   _NO_RESOURCES - out of memory
 */
static int
perm_add_enabling(permcheck_t *pcp, const char *auth)
{
	return (pc_add(pcp, auth) == 0 ? REP_PROTOCOL_SUCCESS :
	    REP_PROTOCOL_FAIL_NO_RESOURCES);
}

/* Note that perm_add_enabling_values() is defined below. */

/*
 * perm_granted() returns 1 if the current door caller has one of the enabling
 * authorizations in pcp, 0 if it doesn't, and -1 if an error (usually lack of
 * memory) occurs.  check_auth_list() checks an RBAC_AUTH_SEP-separated list
 * of authorizations for existence in pcp, and check_prof_list() checks the
 * authorizations granted to an RBAC_AUTH_SEP-separated list of profiles.
 */
static int
check_auth_list(const permcheck_t *pcp, char *authlist)
{
	char *auth, *lasts;
	int ret;

	for (auth = (char *)strtok_r(authlist, RBAC_AUTH_SEP, &lasts);
	    auth != NULL;
	    auth = (char *)strtok_r(NULL, RBAC_AUTH_SEP, &lasts)) {
		if (strchr(auth, KV_WILDCHAR) == NULL)
			ret = pc_exists(pcp, auth);
		else
			ret = pc_match(pcp, auth);

		if (ret)
			return (ret);
	}

	return (0);
}

static int
check_prof_list(const permcheck_t *pcp, char *proflist)
{
	char *prof, *lasts, *authlist, *subproflist;
	profattr_t *pap;
	int ret = 0;

	for (prof = strtok_r(proflist, RBAC_AUTH_SEP, &lasts);
	    prof != NULL;
	    prof = strtok_r(NULL, RBAC_AUTH_SEP, &lasts)) {
		pap = getprofnam(prof);
		if (pap == NULL)
			continue;

		authlist = kva_match(pap->attr, PROFATTR_AUTHS_KW);
		if (authlist != NULL)
			ret = check_auth_list(pcp, authlist);

		if (!ret) {
			subproflist = kva_match(pap->attr, PROFATTR_PROFS_KW);
			if (subproflist != NULL)
				/* depth check to avoid invinite recursion? */
				ret = check_prof_list(pcp, subproflist);
		}

		free_profattr(pap);
		if (ret)
			return (ret);
	}

	return (ret);
}

static int
perm_granted(const permcheck_t *pcp)
{
	ucred_t *uc;

	int ret = 0;
	uid_t uid;
	userattr_t *uap;
	char *authlist, *userattr_authlist, *proflist, *def_prof = NULL;

	/*
	 * Get generic authorizations from policy.conf
	 *
	 * Note that _get_auth_policy is not threadsafe, so we single-thread
	 * access to it.
	 */
	(void) pthread_mutex_lock(&perm_lock);
	ret = _get_auth_policy(&authlist, &def_prof);
	(void) pthread_mutex_unlock(&perm_lock);

	if (ret != 0)
		return (-1);

	if (authlist != NULL) {
		ret = check_auth_list(pcp, authlist);

		if (ret) {
			_free_auth_policy(authlist, def_prof);
			return (ret);
		}
	}

	/*
	 * Put off checking def_prof for later in an attempt to consolidate
	 * prof_attr accesses.
	 */

	/* Get the uid */
	if ((uc = get_ucred()) == NULL) {
		_free_auth_policy(authlist, def_prof);

		if (errno == EINVAL) {
			/*
			 * Client is no longer waiting for our response (e.g.,
			 * it received a signal & resumed with EINTR).
			 * Punting with door_return() would be nice but we
			 * need to release all of the locks & references we
			 * hold.  And we must report failure to the client
			 * layer to keep it from ignoring retries as
			 * already-done (idempotency & all that).  None of the
			 * error codes fit very well, so we might as well
			 * force the return of _PERMISSION_DENIED since we
			 * couldn't determine the user.
			 */
			return (0);
		}
		assert(0);
		abort();
	}

	uid = ucred_geteuid(uc);
	assert(uid != (uid_t)-1);

	uap = getuseruid(uid);
	if (uap != NULL) {
		/* Get the authorizations from user_attr. */
		userattr_authlist = kva_match(uap->attr, USERATTR_AUTHS_KW);
		if (userattr_authlist != NULL)
			ret = check_auth_list(pcp, userattr_authlist);
	}

	if (!ret && def_prof != NULL) {
		/* Check generic profiles. */
		ret = check_prof_list(pcp, def_prof);
	}

	if (!ret && uap != NULL) {
		proflist = kva_match(uap->attr, USERATTR_PROFILES_KW);
		if (proflist != NULL)
			ret = check_prof_list(pcp, proflist);
	}

	_free_auth_policy(authlist, def_prof);
	if (uap != NULL)
		free_userattr(uap);

	return (ret);
}
#endif /* NATIVE_BUILD */

/*
 * flags in RC_NODE_WAITING_FLAGS are broadcast when unset, and are used to
 * serialize certain actions, and to wait for certain operations to complete
 *
 * The waiting flags are:
 *	RC_NODE_CHILDREN_CHANGING
 *		The child list is being built or changed (due to creation
 *		or deletion).  All iterators pause.
 *
 *	RC_NODE_USING_PARENT
 *		Someone is actively using the parent pointer, so we can't
 *		be removed from the parent list.
 *
 *	RC_NODE_CREATING_CHILD
 *		A child is being created -- locks out other creations, to
 *		prevent insert-insert races.
 *
 *	RC_NODE_IN_TX
 *		This object is running a transaction.
 *
 *	RC_NODE_DYING
 *		This node might be dying.  Always set as a set, using
 *		RC_NODE_DYING_FLAGS (which is everything but
 *		RC_NODE_USING_PARENT)
 */
static int
rc_node_hold_flag(rc_node_t *np, uint32_t flag)
{
	assert(MUTEX_HELD(&np->rn_lock));
	assert((flag & ~RC_NODE_WAITING_FLAGS) == 0);

	while (!(np->rn_flags & RC_NODE_DEAD) && (np->rn_flags & flag)) {
		(void) pthread_cond_wait(&np->rn_cv, &np->rn_lock);
	}
	if (np->rn_flags & RC_NODE_DEAD)
		return (0);

	np->rn_flags |= flag;
	return (1);
}

static void
rc_node_rele_flag(rc_node_t *np, uint32_t flag)
{
	assert((flag & ~RC_NODE_WAITING_FLAGS) == 0);
	assert(MUTEX_HELD(&np->rn_lock));
	assert((np->rn_flags & flag) == flag);
	np->rn_flags &= ~flag;
	(void) pthread_cond_broadcast(&np->rn_cv);
}

/*
 * wait until a particular flag has cleared.  Fails if the object dies.
 */
static int
rc_node_wait_flag(rc_node_t *np, uint32_t flag)
{
	assert(MUTEX_HELD(&np->rn_lock));
	while (!(np->rn_flags & RC_NODE_DEAD) && (np->rn_flags & flag))
		(void) pthread_cond_wait(&np->rn_cv, &np->rn_lock);

	return (!(np->rn_flags & RC_NODE_DEAD));
}

/*
 * On entry, np's lock must be held, and this thread must be holding
 * RC_NODE_USING_PARENT.  On return, both of them are released.
 *
 * If the return value is NULL, np either does not have a parent, or
 * the parent has been marked DEAD.
 *
 * If the return value is non-NULL, it is the parent of np, and both
 * its lock and the requested flags are held.
 */
static rc_node_t *
rc_node_hold_parent_flag(rc_node_t *np, uint32_t flag)
{
	rc_node_t *pp;

	assert(MUTEX_HELD(&np->rn_lock));
	assert(np->rn_flags & RC_NODE_USING_PARENT);

	if ((pp = np->rn_parent) == NULL) {
		rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (NULL);
	}
	(void) pthread_mutex_unlock(&np->rn_lock);

	(void) pthread_mutex_lock(&pp->rn_lock);
	(void) pthread_mutex_lock(&np->rn_lock);
	rc_node_rele_flag(np, RC_NODE_USING_PARENT);
	(void) pthread_mutex_unlock(&np->rn_lock);

	if (!rc_node_hold_flag(pp, flag)) {
		(void) pthread_mutex_unlock(&pp->rn_lock);
		return (NULL);
	}
	return (pp);
}

rc_node_t *
rc_node_alloc(void)
{
	rc_node_t *np = uu_zalloc(sizeof (*np));

	if (np == NULL)
		return (NULL);

	(void) pthread_mutex_init(&np->rn_lock, NULL);
	(void) pthread_cond_init(&np->rn_cv, NULL);

	np->rn_children = uu_list_create(rc_children_pool, np, 0);
	np->rn_pg_notify_list = uu_list_create(rc_pg_notify_pool, np, 0);

	uu_list_node_init(np, &np->rn_sibling_node, rc_children_pool);

	uu_list_node_init(&np->rn_notify, &np->rn_notify.rcn_list_node,
	    rc_notify_pool);

	return (np);
}

void
rc_node_destroy(rc_node_t *np)
{
	int i;

	if (np->rn_flags & RC_NODE_UNREFED)
		return;				/* being handled elsewhere */

	assert(np->rn_refs == 0 && np->rn_other_refs == 0);
	assert(np->rn_former == NULL);

	if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_CPROPERTYGRP) {
		/* Release the holds from rc_iter_next(). */
		for (i = 0; i < COMPOSITION_DEPTH; ++i) {
			/* rn_cchain[i] may be NULL for empty snapshots. */
			if (np->rn_cchain[i] != NULL)
				rc_node_rele(np->rn_cchain[i]);
		}
	}

	if (np->rn_name != NULL)
		free((void *)np->rn_name);
	np->rn_name = NULL;
	if (np->rn_type != NULL)
		free((void *)np->rn_type);
	np->rn_type = NULL;
	if (np->rn_values != NULL)
		object_free_values(np->rn_values, np->rn_valtype,
		    np->rn_values_count, np->rn_values_size);
	np->rn_values = NULL;

	if (np->rn_snaplevel != NULL)
		rc_snaplevel_rele(np->rn_snaplevel);
	np->rn_snaplevel = NULL;

	uu_list_node_fini(np, &np->rn_sibling_node, rc_children_pool);

	uu_list_node_fini(&np->rn_notify, &np->rn_notify.rcn_list_node,
	    rc_notify_pool);

	assert(uu_list_first(np->rn_children) == NULL);
	uu_list_destroy(np->rn_children);
	uu_list_destroy(np->rn_pg_notify_list);

	(void) pthread_mutex_destroy(&np->rn_lock);
	(void) pthread_cond_destroy(&np->rn_cv);

	uu_free(np);
}

/*
 * Link in a child node.
 *
 * Because of the lock ordering, cp has to already be in the hash table with
 * its lock dropped before we get it.  To prevent anyone from noticing that
 * it is parentless, the creation code sets the RC_NODE_USING_PARENT.  Once
 * we've linked it in, we release the flag.
 */
static void
rc_node_link_child(rc_node_t *np, rc_node_t *cp)
{
	assert(!MUTEX_HELD(&np->rn_lock));
	assert(!MUTEX_HELD(&cp->rn_lock));

	(void) pthread_mutex_lock(&np->rn_lock);
	(void) pthread_mutex_lock(&cp->rn_lock);
	assert(!(cp->rn_flags & RC_NODE_IN_PARENT) &&
	    (cp->rn_flags & RC_NODE_USING_PARENT));

	assert(rc_check_parent_child(np->rn_id.rl_type, cp->rn_id.rl_type) ==
	    REP_PROTOCOL_SUCCESS);

	cp->rn_parent = np;
	cp->rn_flags |= RC_NODE_IN_PARENT;
	(void) uu_list_insert_before(np->rn_children, NULL, cp);

	(void) pthread_mutex_unlock(&np->rn_lock);

	rc_node_rele_flag(cp, RC_NODE_USING_PARENT);
	(void) pthread_mutex_unlock(&cp->rn_lock);
}

/*
 * Sets the rn_parent_ref field of all the children of np to pp -- always
 * initially invoked as rc_node_setup_parent_ref(np, np), we then recurse.
 *
 * This is used when we mark a node RC_NODE_OLD, so that when the object and
 * its children are no longer referenced, they will all be deleted as a unit.
 */
static void
rc_node_setup_parent_ref(rc_node_t *np, rc_node_t *pp)
{
	rc_node_t *cp;

	assert(MUTEX_HELD(&np->rn_lock));

	for (cp = uu_list_first(np->rn_children); cp != NULL;
	    cp = uu_list_next(np->rn_children, cp)) {
		(void) pthread_mutex_lock(&cp->rn_lock);
		if (cp->rn_flags & RC_NODE_PARENT_REF) {
			assert(cp->rn_parent_ref == pp);
		} else {
			assert(cp->rn_parent_ref == NULL);

			cp->rn_flags |= RC_NODE_PARENT_REF;
			cp->rn_parent_ref = pp;
			if (cp->rn_refs != 0)
				rc_node_hold_other(pp);
		}
		rc_node_setup_parent_ref(cp, pp);		/* recurse */
		(void) pthread_mutex_unlock(&cp->rn_lock);
	}
}

/*
 * Atomically replace 'np' with 'newp', with a parent of 'pp'.
 *
 * Requirements:
 *	*no* node locks may be held.
 *	pp must be held with RC_NODE_CHILDREN_CHANGING
 *	newp and np must be held with RC_NODE_IN_TX
 *	np must be marked RC_NODE_IN_PARENT, newp must not be
 *	np must be marked RC_NODE_OLD
 *
 * Afterwards:
 *	pp's RC_NODE_CHILDREN_CHANGING is dropped
 *	newp and np's RC_NODE_IN_TX is dropped
 *	newp->rn_former = np;
 *	newp is RC_NODE_IN_PARENT, np is not.
 *	interested notify subscribers have been notified of newp's new status.
 */
static void
rc_node_relink_child(rc_node_t *pp, rc_node_t *np, rc_node_t *newp)
{
	cache_bucket_t *bp;
	/*
	 * First, swap np and nnp in the cache.  newp's RC_NODE_IN_TX flag
	 * keeps rc_node_update() from seeing it until we are done.
	 */
	bp = cache_hold(newp->rn_hash);
	cache_remove_unlocked(bp, np);
	cache_insert_unlocked(bp, newp);
	cache_release(bp);

	/*
	 * replace np with newp in pp's list, and attach it to newp's rn_former
	 * link.
	 */
	(void) pthread_mutex_lock(&pp->rn_lock);
	assert(pp->rn_flags & RC_NODE_CHILDREN_CHANGING);

	(void) pthread_mutex_lock(&newp->rn_lock);
	assert(!(newp->rn_flags & RC_NODE_IN_PARENT));
	assert(newp->rn_flags & RC_NODE_IN_TX);

	(void) pthread_mutex_lock(&np->rn_lock);
	assert(np->rn_flags & RC_NODE_IN_PARENT);
	assert(np->rn_flags & RC_NODE_OLD);
	assert(np->rn_flags & RC_NODE_IN_TX);

	newp->rn_parent = pp;
	newp->rn_flags |= RC_NODE_IN_PARENT;

	/*
	 * Note that we carefully add newp before removing np -- this
	 * keeps iterators on the list from missing us.
	 */
	(void) uu_list_insert_after(pp->rn_children, np, newp);
	(void) uu_list_remove(pp->rn_children, np);

	/*
	 * re-set np
	 */
	newp->rn_former = np;
	np->rn_parent = NULL;
	np->rn_flags &= ~RC_NODE_IN_PARENT;
	np->rn_flags |= RC_NODE_ON_FORMER;

	rc_notify_insert_node(newp);

	rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
	(void) pthread_mutex_unlock(&pp->rn_lock);
	rc_node_rele_flag(newp, RC_NODE_USING_PARENT | RC_NODE_IN_TX);
	(void) pthread_mutex_unlock(&newp->rn_lock);
	rc_node_setup_parent_ref(np, np);
	rc_node_rele_flag(np, RC_NODE_IN_TX);
	(void) pthread_mutex_unlock(&np->rn_lock);
}

/*
 * makes sure a node with lookup 'nip', name 'name', and parent 'pp' exists.
 * 'cp' is used (and returned) if the node does not yet exist.  If it does
 * exist, 'cp' is freed, and the existent node is returned instead.
 */
rc_node_t *
rc_node_setup(rc_node_t *cp, rc_node_lookup_t *nip, const char *name,
    rc_node_t *pp)
{
	rc_node_t *np;
	cache_bucket_t *bp;
	uint32_t h = rc_node_hash(nip);

	assert(cp->rn_refs == 0);

	bp = cache_hold(h);
	if ((np = cache_lookup_unlocked(bp, nip)) != NULL) {
		cache_release(bp);

		/*
		 * make sure it matches our expectations
		 */
		(void) pthread_mutex_lock(&np->rn_lock);
		if (rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
			assert(np->rn_parent == pp);
			assert(memcmp(&np->rn_id, nip, sizeof (*nip)) == 0);
			assert(strcmp(np->rn_name, name) == 0);
			assert(np->rn_type == NULL);
			assert(np->rn_flags & RC_NODE_IN_PARENT);
			rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		}
		(void) pthread_mutex_unlock(&np->rn_lock);

		rc_node_destroy(cp);
		return (np);
	}

	/*
	 * No one is there -- create a new node.
	 */
	np = cp;
	rc_node_hold(np);
	np->rn_id = *nip;
	np->rn_hash = h;
	np->rn_name = strdup(name);

	np->rn_flags |= RC_NODE_USING_PARENT;

	if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_INSTANCE) {
#if COMPOSITION_DEPTH == 2
		np->rn_cchain[0] = np;
		np->rn_cchain[1] = pp;
#else
#error This code must be updated.
#endif
	}

	cache_insert_unlocked(bp, np);
	cache_release(bp);		/* we are now visible */

	rc_node_link_child(pp, np);

	return (np);
}

/*
 * makes sure a snapshot with lookup 'nip', name 'name', and parent 'pp' exists.
 * 'cp' is used (and returned) if the node does not yet exist.  If it does
 * exist, 'cp' is freed, and the existent node is returned instead.
 */
rc_node_t *
rc_node_setup_snapshot(rc_node_t *cp, rc_node_lookup_t *nip, const char *name,
    uint32_t snap_id, rc_node_t *pp)
{
	rc_node_t *np;
	cache_bucket_t *bp;
	uint32_t h = rc_node_hash(nip);

	assert(cp->rn_refs == 0);

	bp = cache_hold(h);
	if ((np = cache_lookup_unlocked(bp, nip)) != NULL) {
		cache_release(bp);

		/*
		 * make sure it matches our expectations
		 */
		(void) pthread_mutex_lock(&np->rn_lock);
		if (rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
			assert(np->rn_parent == pp);
			assert(memcmp(&np->rn_id, nip, sizeof (*nip)) == 0);
			assert(strcmp(np->rn_name, name) == 0);
			assert(np->rn_type == NULL);
			assert(np->rn_flags & RC_NODE_IN_PARENT);
			rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		}
		(void) pthread_mutex_unlock(&np->rn_lock);

		rc_node_destroy(cp);
		return (np);
	}

	/*
	 * No one is there -- create a new node.
	 */
	np = cp;
	rc_node_hold(np);
	np->rn_id = *nip;
	np->rn_hash = h;
	np->rn_name = strdup(name);
	np->rn_snapshot_id = snap_id;

	np->rn_flags |= RC_NODE_USING_PARENT;

	cache_insert_unlocked(bp, np);
	cache_release(bp);		/* we are now visible */

	rc_node_link_child(pp, np);

	return (np);
}

/*
 * makes sure a snaplevel with lookup 'nip' and parent 'pp' exists.  'cp' is
 * used (and returned) if the node does not yet exist.  If it does exist, 'cp'
 * is freed, and the existent node is returned instead.
 */
rc_node_t *
rc_node_setup_snaplevel(rc_node_t *cp, rc_node_lookup_t *nip,
    rc_snaplevel_t *lvl, rc_node_t *pp)
{
	rc_node_t *np;
	cache_bucket_t *bp;
	uint32_t h = rc_node_hash(nip);

	assert(cp->rn_refs == 0);

	bp = cache_hold(h);
	if ((np = cache_lookup_unlocked(bp, nip)) != NULL) {
		cache_release(bp);

		/*
		 * make sure it matches our expectations
		 */
		(void) pthread_mutex_lock(&np->rn_lock);
		if (rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
			assert(np->rn_parent == pp);
			assert(memcmp(&np->rn_id, nip, sizeof (*nip)) == 0);
			assert(np->rn_name == NULL);
			assert(np->rn_type == NULL);
			assert(np->rn_flags & RC_NODE_IN_PARENT);
			rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		}
		(void) pthread_mutex_unlock(&np->rn_lock);

		rc_node_destroy(cp);
		return (np);
	}

	/*
	 * No one is there -- create a new node.
	 */
	np = cp;
	rc_node_hold(np);	/* released in snapshot_fill_children() */
	np->rn_id = *nip;
	np->rn_hash = h;

	rc_snaplevel_hold(lvl);
	np->rn_snaplevel = lvl;

	np->rn_flags |= RC_NODE_USING_PARENT;

	cache_insert_unlocked(bp, np);
	cache_release(bp);		/* we are now visible */

	/* Add this snaplevel to the snapshot's composition chain. */
	assert(pp->rn_cchain[lvl->rsl_level_num - 1] == NULL);
	pp->rn_cchain[lvl->rsl_level_num - 1] = np;

	rc_node_link_child(pp, np);

	return (np);
}

/*
 * Returns NULL if strdup() fails.
 */
rc_node_t *
rc_node_setup_pg(rc_node_t *cp, rc_node_lookup_t *nip, const char *name,
    const char *type, uint32_t flags, uint32_t gen_id, rc_node_t *pp)
{
	rc_node_t *np;
	cache_bucket_t *bp;

	uint32_t h = rc_node_hash(nip);
	bp = cache_hold(h);
	if ((np = cache_lookup_unlocked(bp, nip)) != NULL) {
		cache_release(bp);

		/*
		 * make sure it matches our expectations (don't check
		 * the generation number or parent, since someone could
		 * have gotten a transaction through while we weren't
		 * looking)
		 */
		(void) pthread_mutex_lock(&np->rn_lock);
		if (rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
			assert(memcmp(&np->rn_id, nip, sizeof (*nip)) == 0);
			assert(strcmp(np->rn_name, name) == 0);
			assert(strcmp(np->rn_type, type) == 0);
			assert(np->rn_pgflags == flags);
			assert(np->rn_flags & RC_NODE_IN_PARENT);
			rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		}
		(void) pthread_mutex_unlock(&np->rn_lock);

		rc_node_destroy(cp);
		return (np);
	}

	np = cp;
	rc_node_hold(np);		/* released in fill_pg_callback() */
	np->rn_id = *nip;
	np->rn_hash = h;
	np->rn_name = strdup(name);
	if (np->rn_name == NULL) {
		rc_node_rele(np);
		return (NULL);
	}
	np->rn_type = strdup(type);
	if (np->rn_type == NULL) {
		free((void *)np->rn_name);
		rc_node_rele(np);
		return (NULL);
	}
	np->rn_pgflags = flags;
	np->rn_gen_id = gen_id;

	np->rn_flags |= RC_NODE_USING_PARENT;

	cache_insert_unlocked(bp, np);
	cache_release(bp);		/* we are now visible */

	rc_node_link_child(pp, np);

	return (np);
}

#if COMPOSITION_DEPTH == 2
/*
 * Initialize a "composed property group" which represents the composition of
 * property groups pg1 & pg2.  It is ephemeral: once created & returned for an
 * ITER_READ request, keeping it out of cache_hash and any child lists
 * prevents it from being looked up.  Operations besides iteration are passed
 * through to pg1.
 *
 * pg1 & pg2 should be held before entering this function.  They will be
 * released in rc_node_destroy().
 */
static int
rc_node_setup_cpg(rc_node_t *cpg, rc_node_t *pg1, rc_node_t *pg2)
{
	if (strcmp(pg1->rn_type, pg2->rn_type) != 0)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	cpg->rn_id.rl_type = REP_PROTOCOL_ENTITY_CPROPERTYGRP;
	cpg->rn_name = strdup(pg1->rn_name);
	if (cpg->rn_name == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	cpg->rn_cchain[0] = pg1;
	cpg->rn_cchain[1] = pg2;

	return (REP_PROTOCOL_SUCCESS);
}
#else
#error This code must be updated.
#endif

/*
 * Fails with _NO_RESOURCES.
 */
int
rc_node_create_property(rc_node_t *pp, rc_node_lookup_t *nip,
    const char *name, rep_protocol_value_type_t type,
    const char *vals, size_t count, size_t size)
{
	rc_node_t *np;
	cache_bucket_t *bp;

	uint32_t h = rc_node_hash(nip);
	bp = cache_hold(h);
	if ((np = cache_lookup_unlocked(bp, nip)) != NULL) {
		cache_release(bp);
		/*
		 * make sure it matches our expectations
		 */
		(void) pthread_mutex_lock(&np->rn_lock);
		if (rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
			assert(np->rn_parent == pp);
			assert(memcmp(&np->rn_id, nip, sizeof (*nip)) == 0);
			assert(strcmp(np->rn_name, name) == 0);
			assert(np->rn_valtype == type);
			assert(np->rn_values_count == count);
			assert(np->rn_values_size == size);
			assert(vals == NULL ||
			    memcmp(np->rn_values, vals, size) == 0);
			assert(np->rn_flags & RC_NODE_IN_PARENT);
			rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		}
		rc_node_rele_locked(np);
		object_free_values(vals, type, count, size);
		return (REP_PROTOCOL_SUCCESS);
	}

	/*
	 * No one is there -- create a new node.
	 */
	np = rc_node_alloc();
	if (np == NULL) {
		cache_release(bp);
		object_free_values(vals, type, count, size);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}
	np->rn_id = *nip;
	np->rn_hash = h;
	np->rn_name = strdup(name);
	if (np->rn_name == NULL) {
		cache_release(bp);
		object_free_values(vals, type, count, size);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	np->rn_valtype = type;
	np->rn_values = vals;
	np->rn_values_count = count;
	np->rn_values_size = size;

	np->rn_flags |= RC_NODE_USING_PARENT;

	cache_insert_unlocked(bp, np);
	cache_release(bp);		/* we are now visible */

	rc_node_link_child(pp, np);

	return (REP_PROTOCOL_SUCCESS);
}

int
rc_node_init(void)
{
	rc_node_t *np;
	cache_bucket_t *bp;

	rc_children_pool = uu_list_pool_create("rc_children_pool",
	    sizeof (rc_node_t), offsetof(rc_node_t, rn_sibling_node),
	    NULL, UU_LIST_POOL_DEBUG);

	rc_pg_notify_pool = uu_list_pool_create("rc_pg_notify_pool",
	    sizeof (rc_node_pg_notify_t),
	    offsetof(rc_node_pg_notify_t, rnpn_node),
	    NULL, UU_LIST_POOL_DEBUG);

	rc_notify_pool = uu_list_pool_create("rc_notify_pool",
	    sizeof (rc_notify_t), offsetof(rc_notify_t, rcn_list_node),
	    NULL, UU_LIST_POOL_DEBUG);

	rc_notify_info_pool = uu_list_pool_create("rc_notify_info_pool",
	    sizeof (rc_notify_info_t),
	    offsetof(rc_notify_info_t, rni_list_node),
	    NULL, UU_LIST_POOL_DEBUG);

	if (rc_children_pool == NULL || rc_pg_notify_pool == NULL ||
	    rc_notify_pool == NULL || rc_notify_info_pool == NULL)
		uu_die("out of memory");

	rc_notify_list = uu_list_create(rc_notify_pool,
	    &rc_notify_list, 0);

	rc_notify_info_list = uu_list_create(rc_notify_info_pool,
	    &rc_notify_info_list, 0);

	if (rc_notify_list == NULL || rc_notify_info_list == NULL)
		uu_die("out of memory");

	if ((np = rc_node_alloc()) == NULL)
		uu_die("out of memory");

	rc_node_hold(np);
	np->rn_id.rl_type = REP_PROTOCOL_ENTITY_SCOPE;
	np->rn_id.rl_backend = BACKEND_TYPE_NORMAL;
	np->rn_hash = rc_node_hash(&np->rn_id);
	np->rn_name = "localhost";

	bp = cache_hold(np->rn_hash);
	cache_insert_unlocked(bp, np);
	cache_release(bp);

	rc_scope = np;
	return (1);
}

/*
 * Fails with
 *   _INVALID_TYPE - type is invalid
 *   _TYPE_MISMATCH - np doesn't carry children of type type
 *   _DELETED - np has been deleted
 *   _NO_RESOURCES
 */
static int
rc_node_fill_children(rc_node_t *np, uint32_t type)
{
	int rc;

	assert(MUTEX_HELD(&np->rn_lock));

	if ((rc = rc_check_parent_child(np->rn_id.rl_type, type)) !=
	    REP_PROTOCOL_SUCCESS)
		return (rc);

	if (!rc_node_hold_flag(np, RC_NODE_CHILDREN_CHANGING))
		return (REP_PROTOCOL_FAIL_DELETED);

	if (np->rn_flags & RC_NODE_HAS_CHILDREN) {
		rc_node_rele_flag(np, RC_NODE_CHILDREN_CHANGING);
		return (REP_PROTOCOL_SUCCESS);
	}

	(void) pthread_mutex_unlock(&np->rn_lock);
	rc = object_fill_children(np);
	(void) pthread_mutex_lock(&np->rn_lock);

	if (rc == REP_PROTOCOL_SUCCESS) {
		np->rn_flags |= RC_NODE_HAS_CHILDREN;
	}
	rc_node_rele_flag(np, RC_NODE_CHILDREN_CHANGING);

	return (rc);
}

/*
 * Returns
 *   _INVALID_TYPE - type is invalid
 *   _TYPE_MISMATCH - np doesn't carry children of type type
 *   _DELETED - np has been deleted
 *   _NO_RESOURCES
 *   _SUCCESS - if *cpp is not NULL, it is held
 */
static int
rc_node_find_named_child(rc_node_t *np, const char *name, uint32_t type,
    rc_node_t **cpp)
{
	int ret;
	rc_node_t *cp;

	assert(MUTEX_HELD(&np->rn_lock));
	assert(np->rn_id.rl_type != REP_PROTOCOL_ENTITY_CPROPERTYGRP);

	ret = rc_node_fill_children(np, type);
	if (ret != REP_PROTOCOL_SUCCESS)
		return (ret);

	for (cp = uu_list_first(np->rn_children);
	    cp != NULL;
	    cp = uu_list_next(np->rn_children, cp)) {
		if (cp->rn_id.rl_type == type && strcmp(cp->rn_name, name) == 0)
			break;
	}

	if (cp != NULL)
		rc_node_hold(cp);
	*cpp = cp;

	return (REP_PROTOCOL_SUCCESS);
}

static int rc_node_parent(rc_node_t *, rc_node_t **);

/*
 * Returns
 *   _INVALID_TYPE - type is invalid
 *   _DELETED - np or an ancestor has been deleted
 *   _NOT_FOUND - no ancestor of specified type exists
 *   _SUCCESS - *app is held
 */
static int
rc_node_find_ancestor(rc_node_t *np, uint32_t type, rc_node_t **app)
{
	int ret;
	rc_node_t *parent, *np_orig;

	if (type >= REP_PROTOCOL_ENTITY_MAX)
		return (REP_PROTOCOL_FAIL_INVALID_TYPE);

	np_orig = np;

	while (np->rn_id.rl_type > type) {
		ret = rc_node_parent(np, &parent);
		if (np != np_orig)
			rc_node_rele(np);
		if (ret != REP_PROTOCOL_SUCCESS)
			return (ret);
		np = parent;
	}

	if (np->rn_id.rl_type == type) {
		*app = parent;
		return (REP_PROTOCOL_SUCCESS);
	}

	return (REP_PROTOCOL_FAIL_NOT_FOUND);
}

#ifndef NATIVE_BUILD
/*
 * If the propname property exists in pg, and it is of type string, add its
 * values as authorizations to pcp.  pg must not be locked on entry, and it is
 * returned unlocked.  Returns
 *   _DELETED - pg was deleted
 *   _NO_RESOURCES
 *   _NOT_FOUND - pg has no property named propname
 *   _SUCCESS
 */
static int
perm_add_pg_prop_values(permcheck_t *pcp, rc_node_t *pg, const char *propname)
{
	rc_node_t *prop;
	int result;

	uint_t count;
	const char *cp;

	assert(!MUTEX_HELD(&pg->rn_lock));
	assert(pg->rn_id.rl_type == REP_PROTOCOL_ENTITY_PROPERTYGRP);

	(void) pthread_mutex_lock(&pg->rn_lock);
	result = rc_node_find_named_child(pg, propname,
	    REP_PROTOCOL_ENTITY_PROPERTY, &prop);
	(void) pthread_mutex_unlock(&pg->rn_lock);
	if (result != REP_PROTOCOL_SUCCESS) {
		switch (result) {
		case REP_PROTOCOL_FAIL_DELETED:
		case REP_PROTOCOL_FAIL_NO_RESOURCES:
			return (result);

		case REP_PROTOCOL_FAIL_INVALID_TYPE:
		case REP_PROTOCOL_FAIL_TYPE_MISMATCH:
		default:
			bad_error("rc_node_find_named_child", result);
		}
	}

	if (prop == NULL)
		return (REP_PROTOCOL_FAIL_NOT_FOUND);

	/* rn_valtype is immutable, so no locking. */
	if (prop->rn_valtype != REP_PROTOCOL_TYPE_STRING) {
		rc_node_rele(prop);
		return (REP_PROTOCOL_SUCCESS);
	}

	(void) pthread_mutex_lock(&prop->rn_lock);
	for (count = prop->rn_values_count, cp = prop->rn_values;
	    count > 0;
	    --count) {
		result = perm_add_enabling(pcp, cp);
		if (result != REP_PROTOCOL_SUCCESS)
			break;

		cp = strchr(cp, '\0') + 1;
	}

	rc_node_rele_locked(prop);

	return (result);
}

/*
 * Assuming that ent is a service or instance node, if the pgname property
 * group has type pgtype, and it has a propname property with string type, add
 * its values as authorizations to pcp.  If pgtype is NULL, it is not checked.
 * Returns
 *   _SUCCESS
 *   _DELETED - ent was deleted
 *   _NO_RESOURCES - no resources
 *   _NOT_FOUND - ent does not have pgname pg or propname property
 */
static int
perm_add_ent_prop_values(permcheck_t *pcp, rc_node_t *ent, const char *pgname,
    const char *pgtype, const char *propname)
{
	int r;
	rc_node_t *pg;

	assert(!MUTEX_HELD(&ent->rn_lock));

	(void) pthread_mutex_lock(&ent->rn_lock);
	r = rc_node_find_named_child(ent, pgname,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, &pg);
	(void) pthread_mutex_unlock(&ent->rn_lock);

	switch (r) {
	case REP_PROTOCOL_SUCCESS:
		break;

	case REP_PROTOCOL_FAIL_DELETED:
	case REP_PROTOCOL_FAIL_NO_RESOURCES:
		return (r);

	default:
		bad_error("rc_node_find_named_child", r);
	}

	if (pg == NULL)
		return (REP_PROTOCOL_FAIL_NOT_FOUND);

	if (pgtype == NULL || strcmp(pg->rn_type, pgtype) == 0) {
		r = perm_add_pg_prop_values(pcp, pg, propname);
		switch (r) {
		case REP_PROTOCOL_FAIL_DELETED:
			r = REP_PROTOCOL_FAIL_NOT_FOUND;
			break;

		case REP_PROTOCOL_FAIL_NO_RESOURCES:
		case REP_PROTOCOL_SUCCESS:
		case REP_PROTOCOL_FAIL_NOT_FOUND:
			break;

		default:
			bad_error("perm_add_pg_prop_values", r);
		}
	}

	rc_node_rele(pg);

	return (r);
}

/*
 * If pg has a property named propname, and is string typed, add its values as
 * authorizations to pcp.  If pg has no such property, and its parent is an
 * instance, walk up to the service and try doing the same with the property
 * of the same name from the property group of the same name.  Returns
 *   _SUCCESS
 *   _NO_RESOURCES
 *   _DELETED - pg (or an ancestor) was deleted
 */
static int
perm_add_enabling_values(permcheck_t *pcp, rc_node_t *pg, const char *propname)
{
	int r;
	char pgname[REP_PROTOCOL_NAME_LEN + 1];
	rc_node_t *svc;
	size_t sz;

	r = perm_add_pg_prop_values(pcp, pg, propname);

	if (r != REP_PROTOCOL_FAIL_NOT_FOUND)
		return (r);

	assert(!MUTEX_HELD(&pg->rn_lock));

	if (pg->rn_id.rl_ids[ID_INSTANCE] == 0)
		return (REP_PROTOCOL_SUCCESS);

	sz = strlcpy(pgname, pg->rn_name, sizeof (pgname));
	assert(sz < sizeof (pgname));

	/*
	 * If pg is a child of an instance or snapshot, we want to compose the
	 * authorization property with the service's (if it exists).  The
	 * snapshot case applies only to read_authorization.  In all other
	 * cases, the pg's parent will be the instance.
	 */
	r = rc_node_find_ancestor(pg, REP_PROTOCOL_ENTITY_SERVICE, &svc);
	if (r != REP_PROTOCOL_SUCCESS) {
		assert(r == REP_PROTOCOL_FAIL_DELETED);
		return (r);
	}
	assert(svc->rn_id.rl_type == REP_PROTOCOL_ENTITY_SERVICE);

	r = perm_add_ent_prop_values(pcp, svc, pgname, NULL, propname);

	rc_node_rele(svc);

	if (r == REP_PROTOCOL_FAIL_NOT_FOUND)
		r = REP_PROTOCOL_SUCCESS;

	return (r);
}

/*
 * Call perm_add_enabling_values() for the "action_authorization" property of
 * the "general" property group of inst.  Returns
 *   _DELETED - inst (or an ancestor) was deleted
 *   _NO_RESOURCES
 *   _SUCCESS
 */
static int
perm_add_inst_action_auth(permcheck_t *pcp, rc_node_t *inst)
{
	int r;
	rc_node_t *svc;

	assert(inst->rn_id.rl_type == REP_PROTOCOL_ENTITY_INSTANCE);

	r = perm_add_ent_prop_values(pcp, inst, AUTH_PG_GENERAL,
	    AUTH_PG_GENERAL_TYPE, AUTH_PROP_ACTION);

	if (r != REP_PROTOCOL_FAIL_NOT_FOUND)
		return (r);

	r = rc_node_parent(inst, &svc);
	if (r != REP_PROTOCOL_SUCCESS) {
		assert(r == REP_PROTOCOL_FAIL_DELETED);
		return (r);
	}

	r = perm_add_ent_prop_values(pcp, svc, AUTH_PG_GENERAL,
	    AUTH_PG_GENERAL_TYPE, AUTH_PROP_ACTION);

	return (r == REP_PROTOCOL_FAIL_NOT_FOUND ? REP_PROTOCOL_SUCCESS : r);
}
#endif /* NATIVE_BUILD */

void
rc_node_ptr_init(rc_node_ptr_t *out)
{
	out->rnp_node = NULL;
	out->rnp_authorized = 0;
	out->rnp_deleted = 0;
}

static void
rc_node_assign(rc_node_ptr_t *out, rc_node_t *val)
{
	rc_node_t *cur = out->rnp_node;
	if (val != NULL)
		rc_node_hold(val);
	out->rnp_node = val;
	if (cur != NULL)
		rc_node_rele(cur);
	out->rnp_authorized = 0;
	out->rnp_deleted = 0;
}

void
rc_node_clear(rc_node_ptr_t *out, int deleted)
{
	rc_node_assign(out, NULL);
	out->rnp_deleted = deleted;
}

void
rc_node_ptr_assign(rc_node_ptr_t *out, const rc_node_ptr_t *val)
{
	rc_node_assign(out, val->rnp_node);
}

/*
 * rc_node_check()/RC_NODE_CHECK()
 *	generic "entry" checks, run before the use of an rc_node pointer.
 *
 * Fails with
 *   _NOT_SET
 *   _DELETED
 */
static int
rc_node_check_and_lock(rc_node_t *np)
{
	int result = REP_PROTOCOL_SUCCESS;
	if (np == NULL)
		return (REP_PROTOCOL_FAIL_NOT_SET);

	(void) pthread_mutex_lock(&np->rn_lock);
	if (!rc_node_wait_flag(np, RC_NODE_DYING)) {
		result = REP_PROTOCOL_FAIL_DELETED;
		(void) pthread_mutex_unlock(&np->rn_lock);
	}

	return (result);
}

/*
 * Fails with
 *   _NOT_SET - ptr is reset
 *   _DELETED - node has been deleted
 */
static rc_node_t *
rc_node_ptr_check_and_lock(rc_node_ptr_t *npp, int *res)
{
	rc_node_t *np = npp->rnp_node;
	if (np == NULL) {
		if (npp->rnp_deleted)
			*res = REP_PROTOCOL_FAIL_DELETED;
		else
			*res = REP_PROTOCOL_FAIL_NOT_SET;
		return (NULL);
	}

	(void) pthread_mutex_lock(&np->rn_lock);
	if (!rc_node_wait_flag(np, RC_NODE_DYING)) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_clear(npp, 1);
		*res = REP_PROTOCOL_FAIL_DELETED;
		return (NULL);
	}
	return (np);
}

#define	RC_NODE_CHECK_AND_LOCK(n) {					\
	int rc__res;							\
	if ((rc__res = rc_node_check_and_lock(n)) != REP_PROTOCOL_SUCCESS) \
		return (rc__res);					\
}

#define	RC_NODE_CHECK(n) {						\
	RC_NODE_CHECK_AND_LOCK(n);					\
	(void) pthread_mutex_unlock(&(n)->rn_lock);			\
}

#define	RC_NODE_CHECK_AND_HOLD(n) {					\
	RC_NODE_CHECK_AND_LOCK(n);					\
	rc_node_hold_locked(n);						\
	(void) pthread_mutex_unlock(&(n)->rn_lock);			\
}

#define	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp) {			\
	int rc__res;							\
	if (((np) = rc_node_ptr_check_and_lock(npp, &rc__res)) == NULL)	\
		return (rc__res);					\
}

#define	RC_NODE_PTR_GET_CHECK(np, npp) {				\
	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);			\
	(void) pthread_mutex_unlock(&(np)->rn_lock);			\
}

#define	RC_NODE_PTR_GET_CHECK_AND_HOLD(np, npp) {			\
	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);			\
	rc_node_hold_locked(np);					\
	(void) pthread_mutex_unlock(&(np)->rn_lock);			\
}

#define	HOLD_FLAG_OR_RETURN(np, flag) {					\
	assert(MUTEX_HELD(&(np)->rn_lock));				\
	assert(!((np)->rn_flags & RC_NODE_DEAD));			\
	if (!rc_node_hold_flag((np), flag)) {				\
		(void) pthread_mutex_unlock(&(np)->rn_lock);		\
		return (REP_PROTOCOL_FAIL_DELETED);			\
	}								\
}

#define	HOLD_PTR_FLAG_OR_RETURN(np, npp, flag) {			\
	assert(MUTEX_HELD(&(np)->rn_lock));				\
	assert(!((np)->rn_flags & RC_NODE_DEAD));			\
	if (!rc_node_hold_flag((np), flag)) {				\
		(void) pthread_mutex_unlock(&(np)->rn_lock);		\
		assert((np) == (npp)->rnp_node);			\
		rc_node_clear(npp, 1);					\
		return (REP_PROTOCOL_FAIL_DELETED);			\
	}								\
}

int
rc_local_scope(uint32_t type, rc_node_ptr_t *out)
{
	if (type != REP_PROTOCOL_ENTITY_SCOPE) {
		rc_node_clear(out, 0);
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	/*
	 * the main scope never gets destroyed
	 */
	rc_node_assign(out, rc_scope);

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _NOT_SET - npp is not set
 *   _DELETED - the node npp pointed at has been deleted
 *   _TYPE_MISMATCH - type is not _SCOPE
 *   _NOT_FOUND - scope has no parent
 */
static int
rc_scope_parent_scope(rc_node_ptr_t *npp, uint32_t type, rc_node_ptr_t *out)
{
	rc_node_t *np;

	rc_node_clear(out, 0);

	RC_NODE_PTR_GET_CHECK(np, npp);

	if (type != REP_PROTOCOL_ENTITY_SCOPE)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	return (REP_PROTOCOL_FAIL_NOT_FOUND);
}

static int rc_node_pg_check_read_protect(rc_node_t *);

/*
 * Fails with
 *   _NOT_SET
 *   _DELETED
 *   _NOT_APPLICABLE
 *   _NOT_FOUND
 *   _BAD_REQUEST
 *   _TRUNCATED
 *   _NO_RESOURCES
 */
int
rc_node_name(rc_node_ptr_t *npp, char *buf, size_t sz, uint32_t answertype,
    size_t *sz_out)
{
	size_t actual;
	rc_node_t *np;

	assert(sz == *sz_out);

	RC_NODE_PTR_GET_CHECK(np, npp);

	if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_CPROPERTYGRP) {
		np = np->rn_cchain[0];
		RC_NODE_CHECK(np);
	}

	switch (answertype) {
	case RP_ENTITY_NAME_NAME:
		if (np->rn_name == NULL)
			return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		actual = strlcpy(buf, np->rn_name, sz);
		break;
	case RP_ENTITY_NAME_PGTYPE:
		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP)
			return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		actual = strlcpy(buf, np->rn_type, sz);
		break;
	case RP_ENTITY_NAME_PGFLAGS:
		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP)
			return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		actual = snprintf(buf, sz, "%d", np->rn_pgflags);
		break;
	case RP_ENTITY_NAME_SNAPLEVEL_SCOPE:
		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPLEVEL)
			return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		actual = strlcpy(buf, np->rn_snaplevel->rsl_scope, sz);
		break;
	case RP_ENTITY_NAME_SNAPLEVEL_SERVICE:
		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPLEVEL)
			return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		actual = strlcpy(buf, np->rn_snaplevel->rsl_service, sz);
		break;
	case RP_ENTITY_NAME_SNAPLEVEL_INSTANCE:
		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPLEVEL)
			return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		if (np->rn_snaplevel->rsl_instance == NULL)
			return (REP_PROTOCOL_FAIL_NOT_FOUND);
		actual = strlcpy(buf, np->rn_snaplevel->rsl_instance, sz);
		break;
	case RP_ENTITY_NAME_PGREADPROT:
	{
		int ret;

		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP)
			return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		ret = rc_node_pg_check_read_protect(np);
		assert(ret != REP_PROTOCOL_FAIL_TYPE_MISMATCH);
		switch (ret) {
		case REP_PROTOCOL_FAIL_PERMISSION_DENIED:
			actual = snprintf(buf, sz, "1");
			break;
		case REP_PROTOCOL_SUCCESS:
			actual = snprintf(buf, sz, "0");
			break;
		default:
			return (ret);
		}
		break;
	}
	default:
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}
	if (actual >= sz)
		return (REP_PROTOCOL_FAIL_TRUNCATED);

	*sz_out = actual;
	return (REP_PROTOCOL_SUCCESS);
}

int
rc_node_get_property_type(rc_node_ptr_t *npp, rep_protocol_value_type_t *out)
{
	rc_node_t *np;

	RC_NODE_PTR_GET_CHECK(np, npp);

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTY)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	*out = np->rn_valtype;

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Get np's parent.  If np is deleted, returns _DELETED.  Otherwise puts a hold
 * on the parent, returns a pointer to it in *out, and returns _SUCCESS.
 */
static int
rc_node_parent(rc_node_t *np, rc_node_t **out)
{
	rc_node_t *pnp;
	rc_node_t *np_orig;

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_CPROPERTYGRP) {
		RC_NODE_CHECK_AND_LOCK(np);
	} else {
		np = np->rn_cchain[0];
		RC_NODE_CHECK_AND_LOCK(np);
	}

	np_orig = np;
	rc_node_hold_locked(np);		/* simplifies the remainder */

	for (;;) {
		if (!rc_node_wait_flag(np,
		    RC_NODE_IN_TX | RC_NODE_USING_PARENT)) {
			rc_node_rele_locked(np);
			return (REP_PROTOCOL_FAIL_DELETED);
		}

		if (!(np->rn_flags & RC_NODE_OLD))
			break;

		rc_node_rele_locked(np);
		np = cache_lookup(&np_orig->rn_id);
		assert(np != np_orig);

		if (np == NULL)
			goto deleted;
		(void) pthread_mutex_lock(&np->rn_lock);
	}

	/* guaranteed to succeed without dropping the lock */
	if (!rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		*out = NULL;
		rc_node_rele(np);
		return (REP_PROTOCOL_FAIL_DELETED);
	}

	assert(np->rn_parent != NULL);
	pnp = np->rn_parent;
	(void) pthread_mutex_unlock(&np->rn_lock);

	(void) pthread_mutex_lock(&pnp->rn_lock);
	(void) pthread_mutex_lock(&np->rn_lock);
	rc_node_rele_flag(np, RC_NODE_USING_PARENT);
	(void) pthread_mutex_unlock(&np->rn_lock);

	rc_node_hold_locked(pnp);

	(void) pthread_mutex_unlock(&pnp->rn_lock);

	rc_node_rele(np);
	*out = pnp;
	return (REP_PROTOCOL_SUCCESS);

deleted:
	rc_node_rele(np);
	return (REP_PROTOCOL_FAIL_DELETED);
}

/*
 * Fails with
 *   _NOT_SET
 *   _DELETED
 */
static int
rc_node_ptr_parent(rc_node_ptr_t *npp, rc_node_t **out)
{
	rc_node_t *np;

	RC_NODE_PTR_GET_CHECK(np, npp);

	return (rc_node_parent(np, out));
}

/*
 * Fails with
 *   _NOT_SET - npp is not set
 *   _DELETED - the node npp pointed at has been deleted
 *   _TYPE_MISMATCH - npp's node's parent is not of type type
 *
 * If npp points to a scope, can also fail with
 *   _NOT_FOUND - scope has no parent
 */
int
rc_node_get_parent(rc_node_ptr_t *npp, uint32_t type, rc_node_ptr_t *out)
{
	rc_node_t *pnp;
	int rc;

	if (npp->rnp_node != NULL &&
	    npp->rnp_node->rn_id.rl_type == REP_PROTOCOL_ENTITY_SCOPE)
		return (rc_scope_parent_scope(npp, type, out));

	if ((rc = rc_node_ptr_parent(npp, &pnp)) != REP_PROTOCOL_SUCCESS) {
		rc_node_clear(out, 0);
		return (rc);
	}

	if (type != pnp->rn_id.rl_type) {
		rc_node_rele(pnp);
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	rc_node_assign(out, pnp);
	rc_node_rele(pnp);

	return (REP_PROTOCOL_SUCCESS);
}

int
rc_node_parent_type(rc_node_ptr_t *npp, uint32_t *type_out)
{
	rc_node_t *pnp;
	int rc;

	if (npp->rnp_node != NULL &&
	    npp->rnp_node->rn_id.rl_type == REP_PROTOCOL_ENTITY_SCOPE) {
		*type_out = REP_PROTOCOL_ENTITY_SCOPE;
		return (REP_PROTOCOL_SUCCESS);
	}

	if ((rc = rc_node_ptr_parent(npp, &pnp)) != REP_PROTOCOL_SUCCESS)
		return (rc);

	*type_out = pnp->rn_id.rl_type;

	rc_node_rele(pnp);

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _INVALID_TYPE - type is invalid
 *   _TYPE_MISMATCH - np doesn't carry children of type type
 *   _DELETED - np has been deleted
 *   _NOT_FOUND - no child with that name/type combo found
 *   _NO_RESOURCES
 *   _BACKEND_ACCESS
 */
int
rc_node_get_child(rc_node_ptr_t *npp, const char *name, uint32_t type,
    rc_node_ptr_t *outp)
{
	rc_node_t *np, *cp;
	rc_node_t *child = NULL;
	int ret, idx;

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);
	if ((ret = rc_check_type_name(type, name)) == REP_PROTOCOL_SUCCESS) {
		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_CPROPERTYGRP) {
			ret = rc_node_find_named_child(np, name, type, &child);
		} else {
			(void) pthread_mutex_unlock(&np->rn_lock);
			ret = REP_PROTOCOL_SUCCESS;
			for (idx = 0; idx < COMPOSITION_DEPTH; idx++) {
				cp = np->rn_cchain[idx];
				if (cp == NULL)
					break;
				RC_NODE_CHECK_AND_LOCK(cp);
				ret = rc_node_find_named_child(cp, name, type,
				    &child);
				(void) pthread_mutex_unlock(&cp->rn_lock);
				/*
				 * loop only if we succeeded, but no child of
				 * the correct name was found.
				 */
				if (ret != REP_PROTOCOL_SUCCESS ||
				    child != NULL)
					break;
			}
			(void) pthread_mutex_lock(&np->rn_lock);
		}
	}
	(void) pthread_mutex_unlock(&np->rn_lock);

	if (ret == REP_PROTOCOL_SUCCESS) {
		rc_node_assign(outp, child);
		if (child != NULL)
			rc_node_rele(child);
		else
			ret = REP_PROTOCOL_FAIL_NOT_FOUND;
	} else {
		rc_node_assign(outp, NULL);
	}
	return (ret);
}

int
rc_node_update(rc_node_ptr_t *npp)
{
	cache_bucket_t *bp;
	rc_node_t *np = npp->rnp_node;
	rc_node_t *nnp;
	rc_node_t *cpg = NULL;

	if (np != NULL &&
	    np->rn_id.rl_type == REP_PROTOCOL_ENTITY_CPROPERTYGRP) {
		/*
		 * If we're updating a composed property group, actually
		 * update the top-level property group & return the
		 * appropriate value.  But leave *nnp pointing at us.
		 */
		cpg = np;
		np = np->rn_cchain[0];
	}

	RC_NODE_CHECK(np);

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP &&
	    np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPSHOT)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	for (;;) {
		bp = cache_hold(np->rn_hash);
		nnp = cache_lookup_unlocked(bp, &np->rn_id);
		if (nnp == NULL) {
			cache_release(bp);
			rc_node_clear(npp, 1);
			return (REP_PROTOCOL_FAIL_DELETED);
		}
		/*
		 * grab the lock before dropping the cache bucket, so
		 * that no one else can sneak in
		 */
		(void) pthread_mutex_lock(&nnp->rn_lock);
		cache_release(bp);

		if (!(nnp->rn_flags & RC_NODE_IN_TX) ||
		    !rc_node_wait_flag(nnp, RC_NODE_IN_TX))
			break;

		rc_node_rele_locked(nnp);
	}

	/*
	 * If it is dead, we want to update it so that it will continue to
	 * report being dead.
	 */
	if (nnp->rn_flags & RC_NODE_DEAD) {
		(void) pthread_mutex_unlock(&nnp->rn_lock);
		if (nnp != np && cpg == NULL)
			rc_node_assign(npp, nnp);	/* updated */
		rc_node_rele(nnp);
		return (REP_PROTOCOL_FAIL_DELETED);
	}

	assert(!(nnp->rn_flags & RC_NODE_OLD));
	(void) pthread_mutex_unlock(&nnp->rn_lock);

	if (nnp != np && cpg == NULL)
		rc_node_assign(npp, nnp);		/* updated */

	rc_node_rele(nnp);

	return ((nnp == np)? REP_PROTOCOL_SUCCESS : REP_PROTOCOL_DONE);
}

/*
 * does a generic modification check, for creation, deletion, and snapshot
 * management only.  Property group transactions have different checks.
 */
int
rc_node_modify_permission_check(void)
{
	int rc = REP_PROTOCOL_SUCCESS;
	permcheck_t *pcp;
	int granted;

	if (!client_is_privileged()) {
#ifdef NATIVE_BUILD
		rc = REP_PROTOCOL_FAIL_PERMISSION_DENIED;
#else
		pcp = pc_create();
		if (pcp != NULL) {
			rc = perm_add_enabling(pcp, AUTH_MODIFY);

			if (rc == REP_PROTOCOL_SUCCESS) {
				granted = perm_granted(pcp);

				if (granted < 0)
					rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
			}

			pc_free(pcp);
		} else {
			rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
		}

		if (rc == REP_PROTOCOL_SUCCESS && !granted)
			rc = REP_PROTOCOL_FAIL_PERMISSION_DENIED;
#endif /* NATIVE_BUILD */
	}
	return (rc);
}

/*
 * Fails with
 *   _DELETED - node has been deleted
 *   _NOT_SET - npp is reset
 *   _NOT_APPLICABLE - type is _PROPERTYGRP
 *   _INVALID_TYPE - node is corrupt or type is invalid
 *   _TYPE_MISMATCH - node cannot have children of type type
 *   _BAD_REQUEST - name is invalid
 *		    cannot create children for this type of node
 *   _NO_RESOURCES - out of memory, or could not allocate new id
 *   _PERMISSION_DENIED
 *   _BACKEND_ACCESS
 *   _BACKEND_READONLY
 *   _EXISTS - child already exists
 */
int
rc_node_create_child(rc_node_ptr_t *npp, uint32_t type, const char *name,
    rc_node_ptr_t *cpp)
{
	rc_node_t *np;
	rc_node_t *cp = NULL;
	int rc, perm_rc;

	rc_node_clear(cpp, 0);

	perm_rc = rc_node_modify_permission_check();

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);

	/*
	 * there is a separate interface for creating property groups
	 */
	if (type == REP_PROTOCOL_ENTITY_PROPERTYGRP) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
	}

	if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_CPROPERTYGRP) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		np = np->rn_cchain[0];
		RC_NODE_CHECK_AND_LOCK(np);
	}

	if ((rc = rc_check_parent_child(np->rn_id.rl_type, type)) !=
	    REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (rc);
	}
	if ((rc = rc_check_type_name(type, name)) != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (rc);
	}

	if (perm_rc != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (perm_rc);
	}

	HOLD_PTR_FLAG_OR_RETURN(np, npp, RC_NODE_CREATING_CHILD);
	(void) pthread_mutex_unlock(&np->rn_lock);

	rc = object_create(np, type, name, &cp);
	assert(rc != REP_PROTOCOL_FAIL_NOT_APPLICABLE);

	if (rc == REP_PROTOCOL_SUCCESS) {
		rc_node_assign(cpp, cp);
		rc_node_rele(cp);
	}

	(void) pthread_mutex_lock(&np->rn_lock);
	rc_node_rele_flag(np, RC_NODE_CREATING_CHILD);
	(void) pthread_mutex_unlock(&np->rn_lock);

	return (rc);
}

int
rc_node_create_child_pg(rc_node_ptr_t *npp, uint32_t type, const char *name,
    const char *pgtype, uint32_t flags, rc_node_ptr_t *cpp)
{
	rc_node_t *np;
	rc_node_t *cp;
	int rc;
	permcheck_t *pcp;
	int granted;

	rc_node_clear(cpp, 0);

	/* verify flags is valid */
	if (flags & ~SCF_PG_FLAG_NONPERSISTENT)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	RC_NODE_PTR_GET_CHECK_AND_HOLD(np, npp);

	if (type != REP_PROTOCOL_ENTITY_PROPERTYGRP) {
		rc_node_rele(np);
		return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
	}

	if ((rc = rc_check_parent_child(np->rn_id.rl_type, type)) !=
	    REP_PROTOCOL_SUCCESS) {
		rc_node_rele(np);
		return (rc);
	}
	if ((rc = rc_check_type_name(type, name)) != REP_PROTOCOL_SUCCESS ||
	    (rc = rc_check_pgtype_name(pgtype)) != REP_PROTOCOL_SUCCESS) {
		rc_node_rele(np);
		return (rc);
	}

	if (!client_is_privileged()) {
#ifdef NATIVE_BUILD
		rc = REP_PROTOCOL_FAIL_PERMISSION_DENIED;
#else
		/* Must have .smf.modify or smf.modify.<type> authorization */
		pcp = pc_create();
		if (pcp != NULL) {
			rc = perm_add_enabling(pcp, AUTH_MODIFY);

			if (rc == REP_PROTOCOL_SUCCESS) {
				const char * const auth =
				    perm_auth_for_pgtype(pgtype);

				if (auth != NULL)
					rc = perm_add_enabling(pcp, auth);
			}

			/*
			 * .manage or $action_authorization can be used to
			 * create the actions pg and the general_ovr pg.
			 */
			if (rc == REP_PROTOCOL_SUCCESS &&
			    (flags & SCF_PG_FLAG_NONPERSISTENT) != 0 &&
			    np->rn_id.rl_type == REP_PROTOCOL_ENTITY_INSTANCE &&
			    ((strcmp(name, AUTH_PG_ACTIONS) == 0 &&
			    strcmp(pgtype, AUTH_PG_ACTIONS_TYPE) == 0) ||
			    (strcmp(name, AUTH_PG_GENERAL_OVR) == 0 &&
			    strcmp(pgtype, AUTH_PG_GENERAL_OVR_TYPE) == 0))) {
				rc = perm_add_enabling(pcp, AUTH_MANAGE);

				if (rc == REP_PROTOCOL_SUCCESS)
					rc = perm_add_inst_action_auth(pcp, np);
			}

			if (rc == REP_PROTOCOL_SUCCESS) {
				granted = perm_granted(pcp);

				if (granted < 0)
					rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
			}

			pc_free(pcp);
		} else {
			rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
		}

		if (rc == REP_PROTOCOL_SUCCESS && !granted)
			rc = REP_PROTOCOL_FAIL_PERMISSION_DENIED;
#endif /* NATIVE_BUILD */

		if (rc != REP_PROTOCOL_SUCCESS) {
			rc_node_rele(np);
			return (rc);
		}
	}

	(void) pthread_mutex_lock(&np->rn_lock);
	HOLD_PTR_FLAG_OR_RETURN(np, npp, RC_NODE_CREATING_CHILD);
	(void) pthread_mutex_unlock(&np->rn_lock);

	rc = object_create_pg(np, type, name, pgtype, flags, &cp);

	if (rc == REP_PROTOCOL_SUCCESS) {
		rc_node_assign(cpp, cp);
		rc_node_rele(cp);
	}

	(void) pthread_mutex_lock(&np->rn_lock);
	rc_node_rele_flag(np, RC_NODE_CREATING_CHILD);
	(void) pthread_mutex_unlock(&np->rn_lock);

	return (rc);
}

static void
rc_pg_notify_fire(rc_node_pg_notify_t *pnp)
{
	assert(MUTEX_HELD(&rc_pg_notify_lock));

	if (pnp->rnpn_pg != NULL) {
		uu_list_remove(pnp->rnpn_pg->rn_pg_notify_list, pnp);
		(void) close(pnp->rnpn_fd);

		pnp->rnpn_pg = NULL;
		pnp->rnpn_fd = -1;
	} else {
		assert(pnp->rnpn_fd == -1);
	}
}

static void
rc_notify_node_delete(rc_notify_delete_t *ndp, rc_node_t *np_arg)
{
	rc_node_t *svc = NULL;
	rc_node_t *inst = NULL;
	rc_node_t *pg = NULL;
	rc_node_t *np = np_arg;
	rc_node_t *nnp;

	while (svc == NULL) {
		(void) pthread_mutex_lock(&np->rn_lock);
		if (!rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
			(void) pthread_mutex_unlock(&np->rn_lock);
			goto cleanup;
		}
		nnp = np->rn_parent;
		rc_node_hold_locked(np);	/* hold it in place */

		switch (np->rn_id.rl_type) {
		case REP_PROTOCOL_ENTITY_PROPERTYGRP:
			assert(pg == NULL);
			pg = np;
			break;
		case REP_PROTOCOL_ENTITY_INSTANCE:
			assert(inst == NULL);
			inst = np;
			break;
		case REP_PROTOCOL_ENTITY_SERVICE:
			assert(svc == NULL);
			svc = np;
			break;
		default:
			rc_node_rele_flag(np, RC_NODE_USING_PARENT);
			rc_node_rele_locked(np);
			goto cleanup;
		}

		(void) pthread_mutex_unlock(&np->rn_lock);

		np = nnp;
		if (np == NULL)
			goto cleanup;
	}

	rc_notify_deletion(ndp,
	    svc->rn_name,
	    inst != NULL ? inst->rn_name : NULL,
	    pg != NULL ? pg->rn_name : NULL);

	ndp = NULL;

cleanup:
	if (ndp != NULL)
		uu_free(ndp);

	for (;;) {
		if (svc != NULL) {
			np = svc;
			svc = NULL;
		} else if (inst != NULL) {
			np = inst;
			inst = NULL;
		} else if (pg != NULL) {
			np = pg;
			pg = NULL;
		} else
			break;

		(void) pthread_mutex_lock(&np->rn_lock);
		rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		rc_node_rele_locked(np);
	}
}

/*
 * N.B.:  this function drops np->rn_lock on the way out.
 */
static void
rc_node_delete_hold(rc_node_t *np, int andformer)
{
	rc_node_t *cp;

again:
	assert(MUTEX_HELD(&np->rn_lock));
	assert((np->rn_flags & RC_NODE_DYING_FLAGS) == RC_NODE_DYING_FLAGS);

	for (cp = uu_list_first(np->rn_children); cp != NULL;
	    cp = uu_list_next(np->rn_children, cp)) {
		(void) pthread_mutex_lock(&cp->rn_lock);
		(void) pthread_mutex_unlock(&np->rn_lock);
		if (!rc_node_hold_flag(cp, RC_NODE_DYING_FLAGS)) {
			/*
			 * already marked as dead -- can't happen, since that
			 * would require setting RC_NODE_CHILDREN_CHANGING
			 * in np, and we're holding that...
			 */
			abort();
		}
		rc_node_delete_hold(cp, andformer);	/* recurse, drop lock */

		(void) pthread_mutex_lock(&np->rn_lock);
	}
	if (andformer && (cp = np->rn_former) != NULL) {
		(void) pthread_mutex_lock(&cp->rn_lock);
		(void) pthread_mutex_unlock(&np->rn_lock);
		if (!rc_node_hold_flag(cp, RC_NODE_DYING_FLAGS))
			abort();		/* can't happen, see above */
		np = cp;
		goto again;		/* tail-recurse down rn_former */
	}
	(void) pthread_mutex_unlock(&np->rn_lock);
}

/*
 * N.B.:  this function drops np->rn_lock on the way out.
 */
static void
rc_node_delete_rele(rc_node_t *np, int andformer)
{
	rc_node_t *cp;

again:
	assert(MUTEX_HELD(&np->rn_lock));
	assert((np->rn_flags & RC_NODE_DYING_FLAGS) == RC_NODE_DYING_FLAGS);

	for (cp = uu_list_first(np->rn_children); cp != NULL;
	    cp = uu_list_next(np->rn_children, cp)) {
		(void) pthread_mutex_lock(&cp->rn_lock);
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_delete_rele(cp, andformer);	/* recurse, drop lock */
		(void) pthread_mutex_lock(&np->rn_lock);
	}
	if (andformer && (cp = np->rn_former) != NULL) {
		(void) pthread_mutex_lock(&cp->rn_lock);
		rc_node_rele_flag(np, RC_NODE_DYING_FLAGS);
		(void) pthread_mutex_unlock(&np->rn_lock);

		np = cp;
		goto again;		/* tail-recurse down rn_former */
	}
	rc_node_rele_flag(np, RC_NODE_DYING_FLAGS);
	(void) pthread_mutex_unlock(&np->rn_lock);
}

static void
rc_node_finish_delete(rc_node_t *cp)
{
	cache_bucket_t *bp;
	rc_node_pg_notify_t *pnp;

	assert(MUTEX_HELD(&cp->rn_lock));

	if (!(cp->rn_flags & RC_NODE_OLD)) {
		assert(cp->rn_flags & RC_NODE_IN_PARENT);
		if (!rc_node_wait_flag(cp, RC_NODE_USING_PARENT)) {
			abort();		/* can't happen, see above */
		}
		cp->rn_flags &= ~RC_NODE_IN_PARENT;
		cp->rn_parent = NULL;
	}

	cp->rn_flags |= RC_NODE_DEAD;

	/*
	 * If this node is not out-dated, we need to remove it from
	 * the notify list and cache hash table.
	 */
	if (!(cp->rn_flags & RC_NODE_OLD)) {
		assert(cp->rn_refs > 0);	/* can't go away yet */
		(void) pthread_mutex_unlock(&cp->rn_lock);

		(void) pthread_mutex_lock(&rc_pg_notify_lock);
		while ((pnp = uu_list_first(cp->rn_pg_notify_list)) != NULL)
			rc_pg_notify_fire(pnp);
		(void) pthread_mutex_unlock(&rc_pg_notify_lock);
		rc_notify_remove_node(cp);

		bp = cache_hold(cp->rn_hash);
		(void) pthread_mutex_lock(&cp->rn_lock);
		cache_remove_unlocked(bp, cp);
		cache_release(bp);
	}
}

/*
 * N.B.:  this function drops np->rn_lock and a reference on the way out.
 */
static void
rc_node_delete_children(rc_node_t *np, int andformer)
{
	rc_node_t *cp;

again:
	assert(np->rn_refs > 0);
	assert(MUTEX_HELD(&np->rn_lock));
	assert(np->rn_flags & RC_NODE_DEAD);

	while ((cp = uu_list_first(np->rn_children)) != NULL) {
		uu_list_remove(np->rn_children, cp);
		(void) pthread_mutex_lock(&cp->rn_lock);
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_hold_locked(cp);	/* hold while we recurse */
		rc_node_finish_delete(cp);
		rc_node_delete_children(cp, andformer);	/* drops lock + ref */
		(void) pthread_mutex_lock(&np->rn_lock);
	}

	/*
	 * when we drop cp's lock, all the children will be gone, so we
	 * can release DYING_FLAGS.
	 */
	rc_node_rele_flag(np, RC_NODE_DYING_FLAGS);
	if (andformer && (cp = np->rn_former) != NULL) {
		np->rn_former = NULL;		/* unlink */
		(void) pthread_mutex_lock(&cp->rn_lock);
		(void) pthread_mutex_unlock(&np->rn_lock);
		np->rn_flags &= ~RC_NODE_ON_FORMER;

		rc_node_hold_locked(cp);	/* hold while we loop */

		rc_node_finish_delete(cp);

		rc_node_rele(np);		/* drop the old reference */

		np = cp;
		goto again;		/* tail-recurse down rn_former */
	}
	rc_node_rele_locked(np);
}

static void
rc_node_unrefed(rc_node_t *np)
{
	int unrefed;
	rc_node_t *pp, *cur;

	assert(MUTEX_HELD(&np->rn_lock));
	assert(np->rn_refs == 0);
	assert(np->rn_other_refs == 0);
	assert(np->rn_other_refs_held == 0);

	if (np->rn_flags & RC_NODE_DEAD) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_destroy(np);
		return;
	}

	assert(np->rn_flags & RC_NODE_OLD);
	if (np->rn_flags & RC_NODE_UNREFED) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return;
	}
	np->rn_flags |= RC_NODE_UNREFED;

	(void) pthread_mutex_unlock(&np->rn_lock);

	/*
	 * find the current in-hash object, and grab it's RC_NODE_IN_TX
	 * flag.  That protects the entire rn_former chain.
	 */
	for (;;) {
		pp = cache_lookup(&np->rn_id);
		if (pp == NULL) {
			(void) pthread_mutex_lock(&np->rn_lock);
			if (np->rn_flags & RC_NODE_DEAD)
				goto died;
			/*
			 * We are trying to unreference this node, but the
			 * owner of the former list does not exist.  It must
			 * be the case that another thread is deleting this
			 * entire sub-branch, but has not yet reached us.
			 * We will in short order be deleted.
			 */
			np->rn_flags &= ~RC_NODE_UNREFED;
			(void) pthread_mutex_unlock(&np->rn_lock);
			return;
		}
		if (pp == np) {
			/*
			 * no longer unreferenced
			 */
			(void) pthread_mutex_lock(&np->rn_lock);
			np->rn_flags &= ~RC_NODE_UNREFED;
			rc_node_rele_locked(np);
			return;
		}
		(void) pthread_mutex_lock(&pp->rn_lock);
		if ((pp->rn_flags & RC_NODE_OLD) ||
		    !rc_node_hold_flag(pp, RC_NODE_IN_TX)) {
			rc_node_rele_locked(pp);
			continue;
		}
		if (!(pp->rn_flags & RC_NODE_OLD)) {
			(void) pthread_mutex_unlock(&pp->rn_lock);
			break;
		}
		rc_node_rele_flag(pp, RC_NODE_IN_TX);
		rc_node_rele_locked(pp);
	}

	(void) pthread_mutex_lock(&np->rn_lock);
	if (!(np->rn_flags & (RC_NODE_OLD | RC_NODE_DEAD)) ||
	    np->rn_refs != 0 || np->rn_other_refs != 0 ||
	    np->rn_other_refs_held != 0) {
		np->rn_flags &= ~RC_NODE_UNREFED;
		(void) pthread_mutex_lock(&pp->rn_lock);

		rc_node_rele_flag(pp, RC_NODE_IN_TX);
		rc_node_rele_locked(pp);
		return;
	}

	if (!rc_node_hold_flag(np, RC_NODE_DYING_FLAGS)) {
		(void) pthread_mutex_unlock(&np->rn_lock);

		rc_node_rele_flag(pp, RC_NODE_IN_TX);
		rc_node_rele_locked(pp);

		(void) pthread_mutex_lock(&np->rn_lock);
		goto died;
	}

	rc_node_delete_hold(np, 0);

	(void) pthread_mutex_lock(&np->rn_lock);
	if (!(np->rn_flags & RC_NODE_OLD) ||
	    np->rn_refs != 0 || np->rn_other_refs != 0 ||
	    np->rn_other_refs_held != 0) {
		np->rn_flags &= ~RC_NODE_UNREFED;
		rc_node_delete_rele(np, 0);

		(void) pthread_mutex_lock(&pp->rn_lock);
		rc_node_rele_flag(pp, RC_NODE_IN_TX);
		rc_node_rele_locked(pp);
		return;
	}

	np->rn_flags |= RC_NODE_DEAD;
	rc_node_hold_locked(np);
	rc_node_delete_children(np, 0);

	/*
	 * It's gone -- remove it from the former chain and destroy it.
	 */
	(void) pthread_mutex_lock(&pp->rn_lock);
	for (cur = pp; cur != NULL && cur->rn_former != np;
	    cur = cur->rn_former)
		;
	assert(cur != NULL && cur != np);

	cur->rn_former = np->rn_former;
	np->rn_former = NULL;

	rc_node_rele_flag(pp, RC_NODE_IN_TX);
	rc_node_rele_locked(pp);

	(void) pthread_mutex_lock(&np->rn_lock);
	assert(np->rn_flags & RC_NODE_ON_FORMER);
	np->rn_flags &= ~(RC_NODE_UNREFED | RC_NODE_ON_FORMER);
	(void) pthread_mutex_unlock(&np->rn_lock);
	rc_node_destroy(np);
	return;

died:
	np->rn_flags &= ~RC_NODE_UNREFED;
	unrefed = (np->rn_refs == 0 && np->rn_other_refs == 0 &&
	    np->rn_other_refs_held == 0);
	(void) pthread_mutex_unlock(&np->rn_lock);
	if (unrefed)
		rc_node_destroy(np);
}

/*
 * Fails with
 *   _NOT_SET
 *   _DELETED
 *   _BAD_REQUEST
 *   _PERMISSION_DENIED
 *   _NO_RESOURCES
 * and whatever object_delete() fails with.
 */
int
rc_node_delete(rc_node_ptr_t *npp)
{
	rc_node_t *np, *np_orig;
	rc_node_t *pp = NULL;
	int rc;
	rc_node_pg_notify_t *pnp;
	cache_bucket_t *bp;
	rc_notify_delete_t *ndp;
	permcheck_t *pcp;
	int granted;

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);

	switch (np->rn_id.rl_type) {
	case REP_PROTOCOL_ENTITY_SERVICE:
	case REP_PROTOCOL_ENTITY_INSTANCE:
	case REP_PROTOCOL_ENTITY_SNAPSHOT:
		break;			/* deletable */

	case REP_PROTOCOL_ENTITY_SCOPE:
	case REP_PROTOCOL_ENTITY_SNAPLEVEL:
		/* Scopes and snaplevels are indelible. */
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	case REP_PROTOCOL_ENTITY_CPROPERTYGRP:
		(void) pthread_mutex_unlock(&np->rn_lock);
		np = np->rn_cchain[0];
		RC_NODE_CHECK_AND_LOCK(np);
		break;

	case REP_PROTOCOL_ENTITY_PROPERTYGRP:
		if (np->rn_id.rl_ids[ID_SNAPSHOT] == 0)
			break;

		/* Snapshot property groups are indelible. */
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);

	case REP_PROTOCOL_ENTITY_PROPERTY:
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	default:
		assert(0);
		abort();
		break;
	}

	np_orig = np;
	rc_node_hold_locked(np);	/* simplifies rest of the code */

again:
	/*
	 * The following loop is to deal with the fact that snapshots and
	 * property groups are moving targets -- changes to them result
	 * in a new "child" node.  Since we can only delete from the top node,
	 * we have to loop until we have a non-RC_NODE_OLD version.
	 */
	for (;;) {
		if (!rc_node_wait_flag(np,
		    RC_NODE_IN_TX | RC_NODE_USING_PARENT)) {
			rc_node_rele_locked(np);
			return (REP_PROTOCOL_FAIL_DELETED);
		}

		if (np->rn_flags & RC_NODE_OLD) {
			rc_node_rele_locked(np);
			np = cache_lookup(&np_orig->rn_id);
			assert(np != np_orig);

			if (np == NULL) {
				rc = REP_PROTOCOL_FAIL_DELETED;
				goto fail;
			}
			(void) pthread_mutex_lock(&np->rn_lock);
			continue;
		}

		if (!rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
			rc_node_rele_locked(np);
			rc_node_clear(npp, 1);
			return (REP_PROTOCOL_FAIL_DELETED);
		}

		/*
		 * Mark our parent as children changing.  this call drops our
		 * lock and the RC_NODE_USING_PARENT flag, and returns with
		 * pp's lock held
		 */
		pp = rc_node_hold_parent_flag(np, RC_NODE_CHILDREN_CHANGING);
		if (pp == NULL) {
			/* our parent is gone, we're going next... */
			rc_node_rele(np);

			rc_node_clear(npp, 1);
			return (REP_PROTOCOL_FAIL_DELETED);
		}

		rc_node_hold_locked(pp);		/* hold for later */
		(void) pthread_mutex_unlock(&pp->rn_lock);

		(void) pthread_mutex_lock(&np->rn_lock);
		if (!(np->rn_flags & RC_NODE_OLD))
			break;			/* not old -- we're done */

		(void) pthread_mutex_unlock(&np->rn_lock);
		(void) pthread_mutex_lock(&pp->rn_lock);
		rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
		rc_node_rele_locked(pp);
		(void) pthread_mutex_lock(&np->rn_lock);
		continue;			/* loop around and try again */
	}
	/*
	 * Everyone out of the pool -- we grab everything but
	 * RC_NODE_USING_PARENT (including RC_NODE_DYING) to keep
	 * any changes from occurring while we are attempting to
	 * delete the node.
	 */
	if (!rc_node_hold_flag(np, RC_NODE_DYING_FLAGS)) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc = REP_PROTOCOL_FAIL_DELETED;
		goto fail;
	}

	assert(!(np->rn_flags & RC_NODE_OLD));

	if (!client_is_privileged()) {
		/* permission check */
		(void) pthread_mutex_unlock(&np->rn_lock);

#ifdef NATIVE_BUILD
		rc = REP_PROTOCOL_FAIL_PERMISSION_DENIED;
#else
		pcp = pc_create();
		if (pcp != NULL) {
			rc = perm_add_enabling(pcp, AUTH_MODIFY);

			/* add .smf.modify.<type> for pgs. */
			if (rc == REP_PROTOCOL_SUCCESS && np->rn_id.rl_type ==
			    REP_PROTOCOL_ENTITY_PROPERTYGRP) {
				const char * const auth =
				    perm_auth_for_pgtype(np->rn_type);

				if (auth != NULL)
					rc = perm_add_enabling(pcp, auth);
			}

			if (rc == REP_PROTOCOL_SUCCESS) {
				granted = perm_granted(pcp);

				if (granted < 0)
					rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
			}

			pc_free(pcp);
		} else {
			rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
		}

		if (rc == REP_PROTOCOL_SUCCESS && !granted)
			rc = REP_PROTOCOL_FAIL_PERMISSION_DENIED;
#endif /* NATIVE_BUILD */

		if (rc != REP_PROTOCOL_SUCCESS) {
			(void) pthread_mutex_lock(&np->rn_lock);
			rc_node_rele_flag(np, RC_NODE_DYING_FLAGS);
			(void) pthread_mutex_unlock(&np->rn_lock);
			goto fail;
		}

		(void) pthread_mutex_lock(&np->rn_lock);
	}

	ndp = uu_zalloc(sizeof (*ndp));
	if (ndp == NULL) {
		rc_node_rele_flag(np, RC_NODE_DYING_FLAGS);
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
		goto fail;
	}

	rc_node_delete_hold(np, 1);	/* hold entire subgraph, drop lock */

	rc = object_delete(np);

	if (rc != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_lock(&np->rn_lock);
		rc_node_delete_rele(np, 1);		/* drops lock */
		uu_free(ndp);
		goto fail;
	}

	/*
	 * Now, delicately unlink and delete the object.
	 *
	 * Create the delete notification, atomically remove
	 * from the hash table and set the NODE_DEAD flag, and
	 * remove from the parent's children list.
	 */
	rc_notify_node_delete(ndp, np); /* frees or uses ndp */

	bp = cache_hold(np->rn_hash);

	(void) pthread_mutex_lock(&np->rn_lock);
	cache_remove_unlocked(bp, np);
	cache_release(bp);

	np->rn_flags |= RC_NODE_DEAD;
	if (pp != NULL) {
		(void) pthread_mutex_unlock(&np->rn_lock);

		(void) pthread_mutex_lock(&pp->rn_lock);
		(void) pthread_mutex_lock(&np->rn_lock);
		uu_list_remove(pp->rn_children, np);
		rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
		(void) pthread_mutex_unlock(&pp->rn_lock);
		np->rn_flags &= ~RC_NODE_IN_PARENT;
	}
	/*
	 * finally, propagate death to our children, handle notifications,
	 * and release our hold.
	 */
	rc_node_hold_locked(np);	/* hold for delete */
	rc_node_delete_children(np, 1);	/* drops DYING_FLAGS, lock, ref */

	rc_node_clear(npp, 1);

	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	while ((pnp = uu_list_first(np->rn_pg_notify_list)) != NULL)
		rc_pg_notify_fire(pnp);
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);
	rc_notify_remove_node(np);

	rc_node_rele(np);

	return (rc);

fail:
	rc_node_rele(np);
	if (rc == REP_PROTOCOL_FAIL_DELETED)
		rc_node_clear(npp, 1);
	if (pp != NULL) {
		(void) pthread_mutex_lock(&pp->rn_lock);
		rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
		rc_node_rele_locked(pp);	/* drop ref and lock */
	}
	return (rc);
}

int
rc_node_next_snaplevel(rc_node_ptr_t *npp, rc_node_ptr_t *cpp)
{
	rc_node_t *np;
	rc_node_t *cp, *pp;
	int res;

	rc_node_clear(cpp, 0);

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPSHOT &&
	    np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPLEVEL) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
	}

	if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_SNAPSHOT) {
		if ((res = rc_node_fill_children(np,
		    REP_PROTOCOL_ENTITY_SNAPLEVEL)) != REP_PROTOCOL_SUCCESS) {
			(void) pthread_mutex_unlock(&np->rn_lock);
			return (res);
		}

		for (cp = uu_list_first(np->rn_children);
		    cp != NULL;
		    cp = uu_list_next(np->rn_children, cp)) {
			if (cp->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPLEVEL)
				continue;
			rc_node_hold(cp);
			break;
		}

		(void) pthread_mutex_unlock(&np->rn_lock);
	} else {
		HOLD_PTR_FLAG_OR_RETURN(np, npp, RC_NODE_USING_PARENT);
		/*
		 * mark our parent as children changing.  This call drops our
		 * lock and the RC_NODE_USING_PARENT flag, and returns with
		 * pp's lock held
		 */
		pp = rc_node_hold_parent_flag(np, RC_NODE_CHILDREN_CHANGING);
		if (pp == NULL) {
			/* our parent is gone, we're going next... */

			rc_node_clear(npp, 1);
			return (REP_PROTOCOL_FAIL_DELETED);
		}

		/*
		 * find the next snaplevel
		 */
		cp = np;
		while ((cp = uu_list_next(pp->rn_children, cp)) != NULL &&
		    cp->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPLEVEL)
			;

		/* it must match the snaplevel list */
		assert((cp == NULL && np->rn_snaplevel->rsl_next == NULL) ||
		    (cp != NULL && np->rn_snaplevel->rsl_next ==
		    cp->rn_snaplevel));

		if (cp != NULL)
			rc_node_hold(cp);

		rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);

		(void) pthread_mutex_unlock(&pp->rn_lock);
	}

	rc_node_assign(cpp, cp);
	if (cp != NULL) {
		rc_node_rele(cp);

		return (REP_PROTOCOL_SUCCESS);
	}
	return (REP_PROTOCOL_FAIL_NOT_FOUND);
}

/*
 * This call takes a snapshot (np) and either:
 *	an existing snapid (to be associated with np), or
 *	a non-NULL parentp (from which a new snapshot is taken, and associated
 *	    with np)
 *
 * To do the association, np is duplicated, the duplicate is made to
 * represent the new snapid, and np is replaced with the new rc_node_t on
 * np's parent's child list. np is placed on the new node's rn_former list,
 * and replaces np in cache_hash (so rc_node_update() will find the new one).
 */
static int
rc_attach_snapshot(rc_node_t *np, uint32_t snapid, rc_node_t *parentp)
{
	rc_node_t *np_orig;
	rc_node_t *nnp, *prev;
	rc_node_t *pp;
	int rc;

	if (parentp != NULL)
		assert(snapid == 0);

	assert(MUTEX_HELD(&np->rn_lock));

	np_orig = np;
	rc_node_hold_locked(np);		/* simplifies the remainder */

	(void) pthread_mutex_unlock(&np->rn_lock);
	if ((rc = rc_node_modify_permission_check()) != REP_PROTOCOL_SUCCESS)
		return (rc);
	(void) pthread_mutex_lock(&np->rn_lock);

	/*
	 * get the latest node, holding RC_NODE_IN_TX to keep the rn_former
	 * list from changing.
	 */
	for (;;) {
		if (!(np->rn_flags & RC_NODE_OLD)) {
			if (!rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
				goto again;
			}
			pp = rc_node_hold_parent_flag(np,
			    RC_NODE_CHILDREN_CHANGING);

			(void) pthread_mutex_lock(&np->rn_lock);
			if (pp == NULL) {
				goto again;
			}
			if (np->rn_flags & RC_NODE_OLD) {
				rc_node_rele_flag(pp,
				    RC_NODE_CHILDREN_CHANGING);
				(void) pthread_mutex_unlock(&pp->rn_lock);
				goto again;
			}
			(void) pthread_mutex_unlock(&pp->rn_lock);

			if (!rc_node_hold_flag(np, RC_NODE_IN_TX)) {
				/*
				 * Can't happen, since we're holding our
				 * parent's CHILDREN_CHANGING flag...
				 */
				abort();
			}
			break;			/* everything's ready */
		}
again:
		rc_node_rele_locked(np);
		np = cache_lookup(&np_orig->rn_id);

		if (np == NULL)
			return (REP_PROTOCOL_FAIL_DELETED);

		(void) pthread_mutex_lock(&np->rn_lock);
	}

	if (parentp != NULL) {
		if (pp != parentp) {
			rc = REP_PROTOCOL_FAIL_BAD_REQUEST;
			goto fail;
		}
		nnp = NULL;
	} else {
		/*
		 * look for a former node with the snapid we need.
		 */
		if (np->rn_snapshot_id == snapid) {
			rc_node_rele_flag(np, RC_NODE_IN_TX);
			rc_node_rele_locked(np);

			(void) pthread_mutex_lock(&pp->rn_lock);
			rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
			(void) pthread_mutex_unlock(&pp->rn_lock);
			return (REP_PROTOCOL_SUCCESS);	/* nothing to do */
		}

		prev = np;
		while ((nnp = prev->rn_former) != NULL) {
			if (nnp->rn_snapshot_id == snapid) {
				rc_node_hold(nnp);
				break;		/* existing node with that id */
			}
			prev = nnp;
		}
	}

	if (nnp == NULL) {
		prev = NULL;
		nnp = rc_node_alloc();
		if (nnp == NULL) {
			rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
			goto fail;
		}

		nnp->rn_id = np->rn_id;		/* structure assignment */
		nnp->rn_hash = np->rn_hash;
		nnp->rn_name = strdup(np->rn_name);
		nnp->rn_snapshot_id = snapid;
		nnp->rn_flags = RC_NODE_IN_TX | RC_NODE_USING_PARENT;

		if (nnp->rn_name == NULL) {
			rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
			goto fail;
		}
	}

	(void) pthread_mutex_unlock(&np->rn_lock);

	rc = object_snapshot_attach(&np->rn_id, &snapid, (parentp != NULL));

	if (parentp != NULL)
		nnp->rn_snapshot_id = snapid;	/* fill in new snapid */
	else
		assert(nnp->rn_snapshot_id == snapid);

	(void) pthread_mutex_lock(&np->rn_lock);
	if (rc != REP_PROTOCOL_SUCCESS)
		goto fail;

	/*
	 * fix up the former chain
	 */
	if (prev != NULL) {
		prev->rn_former = nnp->rn_former;
		(void) pthread_mutex_lock(&nnp->rn_lock);
		nnp->rn_flags &= ~RC_NODE_ON_FORMER;
		nnp->rn_former = NULL;
		(void) pthread_mutex_unlock(&nnp->rn_lock);
	}
	np->rn_flags |= RC_NODE_OLD;
	(void) pthread_mutex_unlock(&np->rn_lock);

	/*
	 * replace np with nnp
	 */
	rc_node_relink_child(pp, np, nnp);

	rc_node_rele(np);

	return (REP_PROTOCOL_SUCCESS);

fail:
	rc_node_rele_flag(np, RC_NODE_IN_TX);
	rc_node_rele_locked(np);
	(void) pthread_mutex_lock(&pp->rn_lock);
	rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
	(void) pthread_mutex_unlock(&pp->rn_lock);

	if (nnp != NULL) {
		if (prev == NULL)
			rc_node_destroy(nnp);
		else
			rc_node_rele(nnp);
	}

	return (rc);
}

int
rc_snapshot_take_new(rc_node_ptr_t *npp, const char *svcname,
    const char *instname, const char *name, rc_node_ptr_t *outpp)
{
	rc_node_t *np;
	rc_node_t *outp = NULL;
	int rc, perm_rc;

	rc_node_clear(outpp, 0);

	perm_rc = rc_node_modify_permission_check();

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);
	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_INSTANCE) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	rc = rc_check_type_name(REP_PROTOCOL_ENTITY_SNAPSHOT, name);
	if (rc != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (rc);
	}

	if (svcname != NULL && (rc =
	    rc_check_type_name(REP_PROTOCOL_ENTITY_SERVICE, svcname)) !=
	    REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (rc);
	}

	if (instname != NULL && (rc =
	    rc_check_type_name(REP_PROTOCOL_ENTITY_INSTANCE, instname)) !=
	    REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (rc);
	}

	if (perm_rc != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (perm_rc);
	}

	HOLD_PTR_FLAG_OR_RETURN(np, npp, RC_NODE_CREATING_CHILD);
	(void) pthread_mutex_unlock(&np->rn_lock);

	rc = object_snapshot_take_new(np, svcname, instname, name, &outp);

	if (rc == REP_PROTOCOL_SUCCESS) {
		rc_node_assign(outpp, outp);
		rc_node_rele(outp);
	}

	(void) pthread_mutex_lock(&np->rn_lock);
	rc_node_rele_flag(np, RC_NODE_CREATING_CHILD);
	(void) pthread_mutex_unlock(&np->rn_lock);

	return (rc);
}

int
rc_snapshot_take_attach(rc_node_ptr_t *npp, rc_node_ptr_t *outpp)
{
	rc_node_t *np, *outp;

	RC_NODE_PTR_GET_CHECK(np, npp);
	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_INSTANCE) {
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	RC_NODE_PTR_GET_CHECK_AND_LOCK(outp, outpp);
	if (outp->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPSHOT) {
		(void) pthread_mutex_unlock(&outp->rn_lock);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}

	return (rc_attach_snapshot(outp, 0, np));	/* drops outp's lock */
}

int
rc_snapshot_attach(rc_node_ptr_t *npp, rc_node_ptr_t *cpp)
{
	rc_node_t *np;
	rc_node_t *cp;
	uint32_t snapid;

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);
	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPSHOT) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}
	snapid = np->rn_snapshot_id;
	(void) pthread_mutex_unlock(&np->rn_lock);

	RC_NODE_PTR_GET_CHECK_AND_LOCK(cp, cpp);
	if (cp->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPSHOT) {
		(void) pthread_mutex_unlock(&cp->rn_lock);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}

	return (rc_attach_snapshot(cp, snapid, NULL));	/* drops cp's lock */
}

/*
 * If the pgname property group under ent has type pgtype, and it has a
 * propname property with type ptype, return _SUCCESS.  If pgtype is NULL,
 * it is not checked.  If ent is not a service node, we will return _SUCCESS if
 * a property meeting the requirements exists in either the instance or its
 * parent.
 *
 * Returns
 *   _SUCCESS - see above
 *   _DELETED - ent or one of its ancestors was deleted
 *   _NO_RESOURCES - no resources
 *   _NOT_FOUND - no matching property was found
 */
static int
rc_svc_prop_exists(rc_node_t *ent, const char *pgname, const char *pgtype,
    const char *propname, rep_protocol_value_type_t ptype)
{
	int ret;
	rc_node_t *pg = NULL, *spg = NULL, *svc, *prop;

	assert(!MUTEX_HELD(&ent->rn_lock));

	(void) pthread_mutex_lock(&ent->rn_lock);
	ret = rc_node_find_named_child(ent, pgname,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, &pg);
	(void) pthread_mutex_unlock(&ent->rn_lock);

	switch (ret) {
	case REP_PROTOCOL_SUCCESS:
		break;

	case REP_PROTOCOL_FAIL_DELETED:
	case REP_PROTOCOL_FAIL_NO_RESOURCES:
		return (ret);

	default:
		bad_error("rc_node_find_named_child", ret);
	}

	if (ent->rn_id.rl_type != REP_PROTOCOL_ENTITY_SERVICE) {
		ret = rc_node_find_ancestor(ent, REP_PROTOCOL_ENTITY_SERVICE,
		    &svc);
		if (ret != REP_PROTOCOL_SUCCESS) {
			assert(ret == REP_PROTOCOL_FAIL_DELETED);
			if (pg != NULL)
				rc_node_rele(pg);
			return (ret);
		}
		assert(svc->rn_id.rl_type == REP_PROTOCOL_ENTITY_SERVICE);

		(void) pthread_mutex_lock(&svc->rn_lock);
		ret = rc_node_find_named_child(svc, pgname,
		    REP_PROTOCOL_ENTITY_PROPERTYGRP, &spg);
		(void) pthread_mutex_unlock(&svc->rn_lock);

		rc_node_rele(svc);

		switch (ret) {
		case REP_PROTOCOL_SUCCESS:
			break;

		case REP_PROTOCOL_FAIL_DELETED:
		case REP_PROTOCOL_FAIL_NO_RESOURCES:
			if (pg != NULL)
				rc_node_rele(pg);
			return (ret);

		default:
			bad_error("rc_node_find_named_child", ret);
		}
	}

	if (pg != NULL &&
	    pgtype != NULL && strcmp(pg->rn_type, pgtype) != 0) {
		rc_node_rele(pg);
		pg = NULL;
	}

	if (spg != NULL &&
	    pgtype != NULL && strcmp(spg->rn_type, pgtype) != 0) {
		rc_node_rele(spg);
		spg = NULL;
	}

	if (pg == NULL) {
		if (spg == NULL)
			return (REP_PROTOCOL_FAIL_NOT_FOUND);
		pg = spg;
		spg = NULL;
	}

	/*
	 * At this point, pg is non-NULL, and is a property group node of the
	 * correct type.  spg, if non-NULL, is also a property group node of
	 * the correct type.  Check for the property in pg first, then spg
	 * (if applicable).
	 */
	(void) pthread_mutex_lock(&pg->rn_lock);
	ret = rc_node_find_named_child(pg, propname,
	    REP_PROTOCOL_ENTITY_PROPERTY, &prop);
	(void) pthread_mutex_unlock(&pg->rn_lock);
	rc_node_rele(pg);
	switch (ret) {
	case REP_PROTOCOL_SUCCESS:
		if (prop != NULL) {
			if (prop->rn_valtype == ptype) {
				rc_node_rele(prop);
				if (spg != NULL)
					rc_node_rele(spg);
				return (REP_PROTOCOL_SUCCESS);
			}
			rc_node_rele(prop);
		}
		break;

	case REP_PROTOCOL_FAIL_NO_RESOURCES:
		if (spg != NULL)
			rc_node_rele(spg);
		return (ret);

	case REP_PROTOCOL_FAIL_DELETED:
		break;

	default:
		bad_error("rc_node_find_named_child", ret);
	}

	if (spg == NULL)
		return (REP_PROTOCOL_FAIL_NOT_FOUND);

	pg = spg;

	(void) pthread_mutex_lock(&pg->rn_lock);
	ret = rc_node_find_named_child(pg, propname,
	    REP_PROTOCOL_ENTITY_PROPERTY, &prop);
	(void) pthread_mutex_unlock(&pg->rn_lock);
	rc_node_rele(pg);
	switch (ret) {
	case REP_PROTOCOL_SUCCESS:
		if (prop != NULL) {
			if (prop->rn_valtype == ptype) {
				rc_node_rele(prop);
				return (REP_PROTOCOL_SUCCESS);
			}
			rc_node_rele(prop);
		}
		return (REP_PROTOCOL_FAIL_NOT_FOUND);

	case REP_PROTOCOL_FAIL_NO_RESOURCES:
		return (ret);

	case REP_PROTOCOL_FAIL_DELETED:
		return (REP_PROTOCOL_FAIL_NOT_FOUND);

	default:
		bad_error("rc_node_find_named_child", ret);
	}

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Given a property group node, returns _SUCCESS if the property group may
 * be read without any special authorization.
 *
 * Fails with:
 *   _DELETED - np or an ancestor node was deleted
 *   _TYPE_MISMATCH - np does not refer to a property group
 *   _NO_RESOURCES - no resources
 *   _PERMISSION_DENIED - authorization is required
 */
static int
rc_node_pg_check_read_protect(rc_node_t *np)
{
	int ret;
	rc_node_t *ent;

	assert(!MUTEX_HELD(&np->rn_lock));

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	if (strcmp(np->rn_type, SCF_GROUP_FRAMEWORK) == 0 ||
	    strcmp(np->rn_type, SCF_GROUP_DEPENDENCY) == 0 ||
	    strcmp(np->rn_type, SCF_GROUP_METHOD) == 0)
		return (REP_PROTOCOL_SUCCESS);

	ret = rc_node_parent(np, &ent);

	if (ret != REP_PROTOCOL_SUCCESS)
		return (ret);

	ret = rc_svc_prop_exists(ent, np->rn_name, np->rn_type,
	    AUTH_PROP_READ, REP_PROTOCOL_TYPE_STRING);

	rc_node_rele(ent);

	switch (ret) {
	case REP_PROTOCOL_FAIL_NOT_FOUND:
		return (REP_PROTOCOL_SUCCESS);
	case REP_PROTOCOL_SUCCESS:
		return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);
	case REP_PROTOCOL_FAIL_DELETED:
	case REP_PROTOCOL_FAIL_NO_RESOURCES:
		return (ret);
	default:
		bad_error("rc_svc_prop_exists", ret);
	}

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _DELETED - np's node or parent has been deleted
 *   _TYPE_MISMATCH - np's node is not a property
 *   _NO_RESOURCES - out of memory
 *   _PERMISSION_DENIED - no authorization to read this property's value(s)
 *   _BAD_REQUEST - np's parent is not a property group
 */
static int
rc_node_property_may_read(rc_node_t *np)
{
	int ret, granted = 0;
	rc_node_t *pgp;
	permcheck_t *pcp;

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTY)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	if (client_is_privileged())
		return (REP_PROTOCOL_SUCCESS);

#ifdef NATIVE_BUILD
	return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);
#else
	ret = rc_node_parent(np, &pgp);

	if (ret != REP_PROTOCOL_SUCCESS)
		return (ret);

	if (pgp->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP) {
		rc_node_rele(pgp);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}

	ret = rc_node_pg_check_read_protect(pgp);

	if (ret != REP_PROTOCOL_FAIL_PERMISSION_DENIED) {
		rc_node_rele(pgp);
		return (ret);
	}

	pcp = pc_create();

	if (pcp == NULL) {
		rc_node_rele(pgp);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	ret = perm_add_enabling(pcp, AUTH_MODIFY);

	if (ret == REP_PROTOCOL_SUCCESS) {
		const char * const auth =
		    perm_auth_for_pgtype(pgp->rn_type);

		if (auth != NULL)
			ret = perm_add_enabling(pcp, auth);
	}

	/*
	 * If you are permitted to modify the value, you may also
	 * read it.  This means that both the MODIFY and VALUE
	 * authorizations are acceptable.  We don't allow requests
	 * for AUTH_PROP_MODIFY if all you have is $AUTH_PROP_VALUE,
	 * however, to avoid leaking possibly valuable information
	 * since such a user can't change the property anyway.
	 */
	if (ret == REP_PROTOCOL_SUCCESS)
		ret = perm_add_enabling_values(pcp, pgp,
		    AUTH_PROP_MODIFY);

	if (ret == REP_PROTOCOL_SUCCESS &&
	    strcmp(np->rn_name, AUTH_PROP_MODIFY) != 0)
		ret = perm_add_enabling_values(pcp, pgp,
		    AUTH_PROP_VALUE);

	if (ret == REP_PROTOCOL_SUCCESS)
		ret = perm_add_enabling_values(pcp, pgp,
		    AUTH_PROP_READ);

	rc_node_rele(pgp);

	if (ret == REP_PROTOCOL_SUCCESS) {
		granted = perm_granted(pcp);
		if (granted < 0)
			ret = REP_PROTOCOL_FAIL_NO_RESOURCES;
	}

	pc_free(pcp);

	if (ret == REP_PROTOCOL_SUCCESS && !granted)
		ret = REP_PROTOCOL_FAIL_PERMISSION_DENIED;

	return (ret);
#endif	/* NATIVE_BUILD */
}

/*
 * Iteration
 */
static int
rc_iter_filter_name(rc_node_t *np, void *s)
{
	const char *name = s;

	return (strcmp(np->rn_name, name) == 0);
}

static int
rc_iter_filter_type(rc_node_t *np, void *s)
{
	const char *type = s;

	return (np->rn_type != NULL && strcmp(np->rn_type, type) == 0);
}

/*ARGSUSED*/
static int
rc_iter_null_filter(rc_node_t *np, void *s)
{
	return (1);
}

/*
 * Allocate & initialize an rc_node_iter_t structure.  Essentially, ensure
 * np->rn_children is populated and call uu_list_walk_start(np->rn_children).
 * If successful, leaves a hold on np & increments np->rn_other_refs
 *
 * If composed is true, then set up for iteration across the top level of np's
 * composition chain.  If successful, leaves a hold on np and increments
 * rn_other_refs for the top level of np's composition chain.
 *
 * Fails with
 *   _NO_RESOURCES
 *   _INVALID_TYPE
 *   _TYPE_MISMATCH - np cannot carry type children
 *   _DELETED
 */
static int
rc_iter_create(rc_node_iter_t **resp, rc_node_t *np, uint32_t type,
    rc_iter_filter_func *filter, void *arg, boolean_t composed)
{
	rc_node_iter_t *nip;
	int res;

	assert(*resp == NULL);

	nip = uu_zalloc(sizeof (*nip));
	if (nip == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	/* np is held by the client's rc_node_ptr_t */
	if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_CPROPERTYGRP)
		composed = 1;

	if (!composed) {
		(void) pthread_mutex_lock(&np->rn_lock);

		if ((res = rc_node_fill_children(np, type)) !=
		    REP_PROTOCOL_SUCCESS) {
			(void) pthread_mutex_unlock(&np->rn_lock);
			uu_free(nip);
			return (res);
		}

		nip->rni_clevel = -1;

		nip->rni_iter = uu_list_walk_start(np->rn_children,
		    UU_WALK_ROBUST);
		if (nip->rni_iter != NULL) {
			nip->rni_iter_node = np;
			rc_node_hold_other(np);
		} else {
			(void) pthread_mutex_unlock(&np->rn_lock);
			uu_free(nip);
			return (REP_PROTOCOL_FAIL_NO_RESOURCES);
		}
		(void) pthread_mutex_unlock(&np->rn_lock);
	} else {
		rc_node_t *ent;

		if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_SNAPSHOT) {
			/* rn_cchain isn't valid until children are loaded. */
			(void) pthread_mutex_lock(&np->rn_lock);
			res = rc_node_fill_children(np,
			    REP_PROTOCOL_ENTITY_SNAPLEVEL);
			(void) pthread_mutex_unlock(&np->rn_lock);
			if (res != REP_PROTOCOL_SUCCESS) {
				uu_free(nip);
				return (res);
			}

			/* Check for an empty snapshot. */
			if (np->rn_cchain[0] == NULL)
				goto empty;
		}

		/* Start at the top of the composition chain. */
		for (nip->rni_clevel = 0; ; ++nip->rni_clevel) {
			if (nip->rni_clevel >= COMPOSITION_DEPTH) {
				/* Empty composition chain. */
empty:
				nip->rni_clevel = -1;
				nip->rni_iter = NULL;
				/* It's ok, iter_next() will return _DONE. */
				goto out;
			}

			ent = np->rn_cchain[nip->rni_clevel];
			assert(ent != NULL);

			if (rc_node_check_and_lock(ent) == REP_PROTOCOL_SUCCESS)
				break;

			/* Someone deleted it, so try the next one. */
		}

		res = rc_node_fill_children(ent, type);

		if (res == REP_PROTOCOL_SUCCESS) {
			nip->rni_iter = uu_list_walk_start(ent->rn_children,
			    UU_WALK_ROBUST);

			if (nip->rni_iter == NULL)
				res = REP_PROTOCOL_FAIL_NO_RESOURCES;
			else {
				nip->rni_iter_node = ent;
				rc_node_hold_other(ent);
			}
		}

		if (res != REP_PROTOCOL_SUCCESS) {
			(void) pthread_mutex_unlock(&ent->rn_lock);
			uu_free(nip);
			return (res);
		}

		(void) pthread_mutex_unlock(&ent->rn_lock);
	}

out:
	rc_node_hold(np);		/* released by rc_iter_end() */
	nip->rni_parent = np;
	nip->rni_type = type;
	nip->rni_filter = (filter != NULL)? filter : rc_iter_null_filter;
	nip->rni_filter_arg = arg;
	*resp = nip;
	return (REP_PROTOCOL_SUCCESS);
}

static void
rc_iter_end(rc_node_iter_t *iter)
{
	rc_node_t *np = iter->rni_parent;

	if (iter->rni_clevel >= 0)
		np = np->rn_cchain[iter->rni_clevel];

	assert(MUTEX_HELD(&np->rn_lock));
	if (iter->rni_iter != NULL)
		uu_list_walk_end(iter->rni_iter);
	iter->rni_iter = NULL;

	(void) pthread_mutex_unlock(&np->rn_lock);
	rc_node_rele(iter->rni_parent);
	if (iter->rni_iter_node != NULL)
		rc_node_rele_other(iter->rni_iter_node);
}

/*
 * Fails with
 *   _NOT_SET - npp is reset
 *   _DELETED - npp's node has been deleted
 *   _NOT_APPLICABLE - npp's node is not a property
 *   _NO_RESOURCES - out of memory
 */
static int
rc_node_setup_value_iter(rc_node_ptr_t *npp, rc_node_iter_t **iterp)
{
	rc_node_t *np;

	rc_node_iter_t *nip;

	assert(*iterp == NULL);

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTY) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);
	}

	nip = uu_zalloc(sizeof (*nip));
	if (nip == NULL) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	nip->rni_parent = np;
	nip->rni_iter = NULL;
	nip->rni_clevel = -1;
	nip->rni_type = REP_PROTOCOL_ENTITY_VALUE;
	nip->rni_offset = 0;
	nip->rni_last_offset = 0;

	rc_node_hold_locked(np);

	*iterp = nip;
	(void) pthread_mutex_unlock(&np->rn_lock);

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Returns:
 *   _NO_RESOURCES - out of memory
 *   _NOT_SET - npp is reset
 *   _DELETED - npp's node has been deleted
 *   _TYPE_MISMATCH - npp's node is not a property
 *   _NOT_FOUND - property has no values
 *   _TRUNCATED - property has >1 values (first is written into out)
 *   _SUCCESS - property has 1 value (which is written into out)
 *   _PERMISSION_DENIED - no authorization to read property value(s)
 *
 * We shorten *sz_out to not include anything after the final '\0'.
 */
int
rc_node_get_property_value(rc_node_ptr_t *npp,
    struct rep_protocol_value_response *out, size_t *sz_out)
{
	rc_node_t *np;
	size_t w;
	int ret;

	assert(*sz_out == sizeof (*out));

	RC_NODE_PTR_GET_CHECK_AND_HOLD(np, npp);
	ret = rc_node_property_may_read(np);
	rc_node_rele(np);

	if (ret != REP_PROTOCOL_SUCCESS)
		return (ret);

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTY) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	if (np->rn_values_size == 0) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_NOT_FOUND);
	}
	out->rpr_type = np->rn_valtype;
	w = strlcpy(out->rpr_value, &np->rn_values[0],
	    sizeof (out->rpr_value));

	if (w >= sizeof (out->rpr_value))
		backend_panic("value too large");

	*sz_out = offsetof(struct rep_protocol_value_response,
	    rpr_value[w + 1]);

	ret = (np->rn_values_count != 1)? REP_PROTOCOL_FAIL_TRUNCATED :
	    REP_PROTOCOL_SUCCESS;
	(void) pthread_mutex_unlock(&np->rn_lock);
	return (ret);
}

int
rc_iter_next_value(rc_node_iter_t *iter,
    struct rep_protocol_value_response *out, size_t *sz_out, int repeat)
{
	rc_node_t *np = iter->rni_parent;
	const char *vals;
	size_t len;

	size_t start;
	size_t w;
	int ret;

	rep_protocol_responseid_t result;

	assert(*sz_out == sizeof (*out));

	(void) memset(out, '\0', *sz_out);

	if (iter->rni_type != REP_PROTOCOL_ENTITY_VALUE)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	RC_NODE_CHECK(np);
	ret = rc_node_property_may_read(np);

	if (ret != REP_PROTOCOL_SUCCESS)
		return (ret);

	RC_NODE_CHECK_AND_LOCK(np);

	vals = np->rn_values;
	len = np->rn_values_size;

	out->rpr_type = np->rn_valtype;

	start = (repeat)? iter->rni_last_offset : iter->rni_offset;

	if (len == 0 || start >= len) {
		result = REP_PROTOCOL_DONE;
		*sz_out -= sizeof (out->rpr_value);
	} else {
		w = strlcpy(out->rpr_value, &vals[start],
		    sizeof (out->rpr_value));

		if (w >= sizeof (out->rpr_value))
			backend_panic("value too large");

		*sz_out = offsetof(struct rep_protocol_value_response,
		    rpr_value[w + 1]);

		/*
		 * update the offsets if we're not repeating
		 */
		if (!repeat) {
			iter->rni_last_offset = iter->rni_offset;
			iter->rni_offset += (w + 1);
		}

		result = REP_PROTOCOL_SUCCESS;
	}

	(void) pthread_mutex_unlock(&np->rn_lock);
	return (result);
}

/*
 * Entry point for ITER_START from client.c.  Validate the arguments & call
 * rc_iter_create().
 *
 * Fails with
 *   _NOT_SET
 *   _DELETED
 *   _TYPE_MISMATCH - np cannot carry type children
 *   _BAD_REQUEST - flags is invalid
 *		    pattern is invalid
 *   _NO_RESOURCES
 *   _INVALID_TYPE
 *   _TYPE_MISMATCH - *npp cannot have children of type
 *   _BACKEND_ACCESS
 */
int
rc_node_setup_iter(rc_node_ptr_t *npp, rc_node_iter_t **iterp,
    uint32_t type, uint32_t flags, const char *pattern)
{
	rc_node_t *np;
	rc_iter_filter_func *f = NULL;
	int rc;

	RC_NODE_PTR_GET_CHECK(np, npp);

	if (pattern != NULL && pattern[0] == '\0')
		pattern = NULL;

	if (type == REP_PROTOCOL_ENTITY_VALUE) {
		if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTY)
			return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
		if (flags != RP_ITER_START_ALL || pattern != NULL)
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);

		rc = rc_node_setup_value_iter(npp, iterp);
		assert(rc != REP_PROTOCOL_FAIL_NOT_APPLICABLE);
		return (rc);
	}

	if ((rc = rc_check_parent_child(np->rn_id.rl_type, type)) !=
	    REP_PROTOCOL_SUCCESS)
		return (rc);

	if (((flags & RP_ITER_START_FILT_MASK) == RP_ITER_START_ALL) ^
	    (pattern == NULL))
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	/* Composition only works for instances & snapshots. */
	if ((flags & RP_ITER_START_COMPOSED) &&
	    (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_INSTANCE &&
	    np->rn_id.rl_type != REP_PROTOCOL_ENTITY_SNAPSHOT))
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	if (pattern != NULL) {
		if ((rc = rc_check_type_name(type, pattern)) !=
		    REP_PROTOCOL_SUCCESS)
			return (rc);
		pattern = strdup(pattern);
		if (pattern == NULL)
			return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	switch (flags & RP_ITER_START_FILT_MASK) {
	case RP_ITER_START_ALL:
		f = NULL;
		break;
	case RP_ITER_START_EXACT:
		f = rc_iter_filter_name;
		break;
	case RP_ITER_START_PGTYPE:
		if (type != REP_PROTOCOL_ENTITY_PROPERTYGRP) {
			free((void *)pattern);
			return (REP_PROTOCOL_FAIL_BAD_REQUEST);
		}
		f = rc_iter_filter_type;
		break;
	default:
		free((void *)pattern);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}

	rc = rc_iter_create(iterp, np, type, f, (void *)pattern,
	    flags & RP_ITER_START_COMPOSED);
	if (rc != REP_PROTOCOL_SUCCESS && pattern != NULL)
		free((void *)pattern);

	return (rc);
}

/*
 * Do uu_list_walk_next(iter->rni_iter) until we find a child which matches
 * the filter.
 * For composed iterators, then check to see if there's an overlapping entity
 * (see embedded comments).  If we reach the end of the list, start over at
 * the next level.
 *
 * Returns
 *   _BAD_REQUEST - iter walks values
 *   _TYPE_MISMATCH - iter does not walk type entities
 *   _DELETED - parent was deleted
 *   _NO_RESOURCES
 *   _INVALID_TYPE - type is invalid
 *   _DONE
 *   _SUCCESS
 *
 * For composed property group iterators, can also return
 *   _TYPE_MISMATCH - parent cannot have type children
 */
int
rc_iter_next(rc_node_iter_t *iter, rc_node_ptr_t *out, uint32_t type)
{
	rc_node_t *np = iter->rni_parent;
	rc_node_t *res;
	int rc;

	if (iter->rni_type == REP_PROTOCOL_ENTITY_VALUE)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	if (iter->rni_iter == NULL) {
		rc_node_clear(out, 0);
		return (REP_PROTOCOL_DONE);
	}

	if (iter->rni_type != type) {
		rc_node_clear(out, 0);
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	(void) pthread_mutex_lock(&np->rn_lock);  /* held by _iter_create() */

	if (!rc_node_wait_flag(np, RC_NODE_CHILDREN_CHANGING)) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_clear(out, 1);
		return (REP_PROTOCOL_FAIL_DELETED);
	}

	if (iter->rni_clevel >= 0) {
		/* Composed iterator.  Iterate over appropriate level. */
		(void) pthread_mutex_unlock(&np->rn_lock);
		np = np->rn_cchain[iter->rni_clevel];
		/*
		 * If iter->rni_parent is an instance or a snapshot, np must
		 * be valid since iter holds iter->rni_parent & possible
		 * levels (service, instance, snaplevel) cannot be destroyed
		 * while rni_parent is held.  If iter->rni_parent is
		 * a composed property group then rc_node_setup_cpg() put
		 * a hold on np.
		 */

		(void) pthread_mutex_lock(&np->rn_lock);

		if (!rc_node_wait_flag(np, RC_NODE_CHILDREN_CHANGING)) {
			(void) pthread_mutex_unlock(&np->rn_lock);
			rc_node_clear(out, 1);
			return (REP_PROTOCOL_FAIL_DELETED);
		}
	}

	assert(np->rn_flags & RC_NODE_HAS_CHILDREN);

	for (;;) {
		res = uu_list_walk_next(iter->rni_iter);
		if (res == NULL) {
			rc_node_t *parent = iter->rni_parent;

#if COMPOSITION_DEPTH == 2
			if (iter->rni_clevel < 0 || iter->rni_clevel == 1) {
				/* release walker and lock */
				rc_iter_end(iter);
				break;
			}

			/* Stop walking current level. */
			uu_list_walk_end(iter->rni_iter);
			iter->rni_iter = NULL;
			(void) pthread_mutex_unlock(&np->rn_lock);
			rc_node_rele_other(iter->rni_iter_node);
			iter->rni_iter_node = NULL;

			/* Start walking next level. */
			++iter->rni_clevel;
			np = parent->rn_cchain[iter->rni_clevel];
			assert(np != NULL);
#else
#error This code must be updated.
#endif

			(void) pthread_mutex_lock(&np->rn_lock);

			rc = rc_node_fill_children(np, iter->rni_type);

			if (rc == REP_PROTOCOL_SUCCESS) {
				iter->rni_iter =
				    uu_list_walk_start(np->rn_children,
				    UU_WALK_ROBUST);

				if (iter->rni_iter == NULL)
					rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
				else {
					iter->rni_iter_node = np;
					rc_node_hold_other(np);
				}
			}

			if (rc != REP_PROTOCOL_SUCCESS) {
				(void) pthread_mutex_unlock(&np->rn_lock);
				rc_node_clear(out, 0);
				return (rc);
			}

			continue;
		}

		if (res->rn_id.rl_type != type ||
		    !iter->rni_filter(res, iter->rni_filter_arg))
			continue;

		/*
		 * If we're composed and not at the top level, check to see if
		 * there's an entity at a higher level with the same name.  If
		 * so, skip this one.
		 */
		if (iter->rni_clevel > 0) {
			rc_node_t *ent = iter->rni_parent->rn_cchain[0];
			rc_node_t *pg;

#if COMPOSITION_DEPTH == 2
			assert(iter->rni_clevel == 1);

			(void) pthread_mutex_unlock(&np->rn_lock);
			(void) pthread_mutex_lock(&ent->rn_lock);
			rc = rc_node_find_named_child(ent, res->rn_name, type,
			    &pg);
			if (rc == REP_PROTOCOL_SUCCESS && pg != NULL)
				rc_node_rele(pg);
			(void) pthread_mutex_unlock(&ent->rn_lock);
			if (rc != REP_PROTOCOL_SUCCESS) {
				rc_node_clear(out, 0);
				return (rc);
			}
			(void) pthread_mutex_lock(&np->rn_lock);

			/* Make sure np isn't being deleted all of a sudden. */
			if (!rc_node_wait_flag(np, RC_NODE_DYING)) {
				(void) pthread_mutex_unlock(&np->rn_lock);
				rc_node_clear(out, 1);
				return (REP_PROTOCOL_FAIL_DELETED);
			}

			if (pg != NULL)
				/* Keep going. */
				continue;
#else
#error This code must be updated.
#endif
		}

		/*
		 * If we're composed, iterating over property groups, and not
		 * at the bottom level, check to see if there's a pg at lower
		 * level with the same name.  If so, return a cpg.
		 */
		if (iter->rni_clevel >= 0 &&
		    type == REP_PROTOCOL_ENTITY_PROPERTYGRP &&
		    iter->rni_clevel < COMPOSITION_DEPTH - 1) {
#if COMPOSITION_DEPTH == 2
			rc_node_t *pg;
			rc_node_t *ent = iter->rni_parent->rn_cchain[1];

			rc_node_hold(res);	/* While we drop np->rn_lock */

			(void) pthread_mutex_unlock(&np->rn_lock);
			(void) pthread_mutex_lock(&ent->rn_lock);
			rc = rc_node_find_named_child(ent, res->rn_name, type,
			    &pg);
			/* holds pg if not NULL */
			(void) pthread_mutex_unlock(&ent->rn_lock);
			if (rc != REP_PROTOCOL_SUCCESS) {
				rc_node_rele(res);
				rc_node_clear(out, 0);
				return (rc);
			}

			(void) pthread_mutex_lock(&np->rn_lock);
			if (!rc_node_wait_flag(np, RC_NODE_DYING)) {
				(void) pthread_mutex_unlock(&np->rn_lock);
				rc_node_rele(res);
				if (pg != NULL)
					rc_node_rele(pg);
				rc_node_clear(out, 1);
				return (REP_PROTOCOL_FAIL_DELETED);
			}

			if (pg == NULL) {
				rc_node_rele(res);
			} else {
				rc_node_t *cpg;

				/* Keep res held for rc_node_setup_cpg(). */

				cpg = rc_node_alloc();
				if (cpg == NULL) {
					(void) pthread_mutex_unlock(
					    &np->rn_lock);
					rc_node_rele(res);
					rc_node_rele(pg);
					rc_node_clear(out, 0);
					return (REP_PROTOCOL_FAIL_NO_RESOURCES);
				}

				switch (rc_node_setup_cpg(cpg, res, pg)) {
				case REP_PROTOCOL_SUCCESS:
					res = cpg;
					break;

				case REP_PROTOCOL_FAIL_TYPE_MISMATCH:
					/* Nevermind. */
					rc_node_destroy(cpg);
					rc_node_rele(pg);
					rc_node_rele(res);
					break;

				case REP_PROTOCOL_FAIL_NO_RESOURCES:
					rc_node_destroy(cpg);
					(void) pthread_mutex_unlock(
					    &np->rn_lock);
					rc_node_rele(res);
					rc_node_rele(pg);
					rc_node_clear(out, 0);
					return (REP_PROTOCOL_FAIL_NO_RESOURCES);

				default:
					assert(0);
					abort();
				}
			}
#else
#error This code must be updated.
#endif
		}

		rc_node_hold(res);
		(void) pthread_mutex_unlock(&np->rn_lock);
		break;
	}
	rc_node_assign(out, res);

	if (res == NULL)
		return (REP_PROTOCOL_DONE);
	rc_node_rele(res);
	return (REP_PROTOCOL_SUCCESS);
}

void
rc_iter_destroy(rc_node_iter_t **nipp)
{
	rc_node_iter_t *nip = *nipp;
	rc_node_t *np;

	if (nip == NULL)
		return;				/* already freed */

	np = nip->rni_parent;

	if (nip->rni_filter_arg != NULL)
		free(nip->rni_filter_arg);
	nip->rni_filter_arg = NULL;

	if (nip->rni_type == REP_PROTOCOL_ENTITY_VALUE ||
	    nip->rni_iter != NULL) {
		if (nip->rni_clevel < 0)
			(void) pthread_mutex_lock(&np->rn_lock);
		else
			(void) pthread_mutex_lock(
			    &np->rn_cchain[nip->rni_clevel]->rn_lock);
		rc_iter_end(nip);		/* release walker and lock */
	}
	nip->rni_parent = NULL;

	uu_free(nip);
	*nipp = NULL;
}

int
rc_node_setup_tx(rc_node_ptr_t *npp, rc_node_ptr_t *txp)
{
	rc_node_t *np;
	permcheck_t *pcp;
	int ret;
	int authorized = 0;

	RC_NODE_PTR_GET_CHECK_AND_HOLD(np, npp);

	if (np->rn_id.rl_type == REP_PROTOCOL_ENTITY_CPROPERTYGRP) {
		rc_node_rele(np);
		np = np->rn_cchain[0];
		RC_NODE_CHECK_AND_HOLD(np);
	}

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP) {
		rc_node_rele(np);
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	if (np->rn_id.rl_ids[ID_SNAPSHOT] != 0) {
		rc_node_rele(np);
		return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);
	}

	if (client_is_privileged())
		goto skip_checks;

#ifdef NATIVE_BUILD
	rc_node_rele(np);
	return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);
#else
	/* permission check */
	pcp = pc_create();
	if (pcp == NULL) {
		rc_node_rele(np);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	if (np->rn_id.rl_ids[ID_INSTANCE] != 0 &&	/* instance pg */
	    ((strcmp(np->rn_name, AUTH_PG_ACTIONS) == 0 &&
	    strcmp(np->rn_type, AUTH_PG_ACTIONS_TYPE) == 0) ||
	    (strcmp(np->rn_name, AUTH_PG_GENERAL_OVR) == 0 &&
	    strcmp(np->rn_type, AUTH_PG_GENERAL_OVR_TYPE) == 0))) {
		rc_node_t *instn;

		/* solaris.smf.manage can be used. */
		ret = perm_add_enabling(pcp, AUTH_MANAGE);

		if (ret != REP_PROTOCOL_SUCCESS) {
			pc_free(pcp);
			rc_node_rele(np);
			return (ret);
		}

		/* general/action_authorization values can be used. */
		ret = rc_node_parent(np, &instn);
		if (ret != REP_PROTOCOL_SUCCESS) {
			assert(ret == REP_PROTOCOL_FAIL_DELETED);
			rc_node_rele(np);
			pc_free(pcp);
			return (REP_PROTOCOL_FAIL_DELETED);
		}

		assert(instn->rn_id.rl_type == REP_PROTOCOL_ENTITY_INSTANCE);

		ret = perm_add_inst_action_auth(pcp, instn);
		rc_node_rele(instn);
		switch (ret) {
		case REP_PROTOCOL_SUCCESS:
			break;

		case REP_PROTOCOL_FAIL_DELETED:
		case REP_PROTOCOL_FAIL_NO_RESOURCES:
			rc_node_rele(np);
			pc_free(pcp);
			return (ret);

		default:
			bad_error("perm_add_inst_action_auth", ret);
		}

		if (strcmp(np->rn_name, AUTH_PG_ACTIONS) == 0)
			authorized = 1;		/* Don't check on commit. */
	} else {
		ret = perm_add_enabling(pcp, AUTH_MODIFY);

		if (ret == REP_PROTOCOL_SUCCESS) {
			/* propertygroup-type-specific authorization */
			/* no locking because rn_type won't change anyway */
			const char * const auth =
			    perm_auth_for_pgtype(np->rn_type);

			if (auth != NULL)
				ret = perm_add_enabling(pcp, auth);
		}

		if (ret == REP_PROTOCOL_SUCCESS)
			/* propertygroup/transaction-type-specific auths */
			ret =
			    perm_add_enabling_values(pcp, np, AUTH_PROP_VALUE);

		if (ret == REP_PROTOCOL_SUCCESS)
			ret =
			    perm_add_enabling_values(pcp, np, AUTH_PROP_MODIFY);

		/* AUTH_MANAGE can manipulate general/AUTH_PROP_ACTION */
		if (ret == REP_PROTOCOL_SUCCESS &&
		    strcmp(np->rn_name, AUTH_PG_GENERAL) == 0 &&
		    strcmp(np->rn_type, AUTH_PG_GENERAL_TYPE) == 0)
			ret = perm_add_enabling(pcp, AUTH_MANAGE);

		if (ret != REP_PROTOCOL_SUCCESS) {
			pc_free(pcp);
			rc_node_rele(np);
			return (ret);
		}
	}

	ret = perm_granted(pcp);
	if (ret != 1) {
		pc_free(pcp);
		rc_node_rele(np);
		return (ret == 0 ? REP_PROTOCOL_FAIL_PERMISSION_DENIED :
		    REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	pc_free(pcp);
#endif /* NATIVE_BUILD */

skip_checks:
	rc_node_assign(txp, np);
	txp->rnp_authorized = authorized;

	rc_node_rele(np);
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Return 1 if the given transaction commands only modify the values of
 * properties other than "modify_authorization".  Return -1 if any of the
 * commands are invalid, and 0 otherwise.
 */
static int
tx_allow_value(const void *cmds_arg, size_t cmds_sz, rc_node_t *pg)
{
	const struct rep_protocol_transaction_cmd *cmds;
	uintptr_t loc;
	uint32_t sz;
	rc_node_t *prop;
	boolean_t ok;

	assert(!MUTEX_HELD(&pg->rn_lock));

	loc = (uintptr_t)cmds_arg;

	while (cmds_sz > 0) {
		cmds = (struct rep_protocol_transaction_cmd *)loc;

		if (cmds_sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (-1);

		sz = cmds->rptc_size;
		if (sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (-1);

		sz = TX_SIZE(sz);
		if (sz > cmds_sz)
			return (-1);

		switch (cmds[0].rptc_action) {
		case REP_PROTOCOL_TX_ENTRY_CLEAR:
			break;

		case REP_PROTOCOL_TX_ENTRY_REPLACE:
			/* Check type */
			(void) pthread_mutex_lock(&pg->rn_lock);
			if (rc_node_find_named_child(pg,
			    (const char *)cmds[0].rptc_data,
			    REP_PROTOCOL_ENTITY_PROPERTY, &prop) ==
			    REP_PROTOCOL_SUCCESS) {
				ok = (prop != NULL &&
				    prop->rn_valtype == cmds[0].rptc_type);
			} else {
				/* Return more particular error? */
				ok = B_FALSE;
			}
			(void) pthread_mutex_unlock(&pg->rn_lock);
			if (ok)
				break;
			return (0);

		default:
			return (0);
		}

		if (strcmp((const char *)cmds[0].rptc_data, AUTH_PROP_MODIFY)
		    == 0)
			return (0);

		loc += sz;
		cmds_sz -= sz;
	}

	return (1);
}

/*
 * Return 1 if any of the given transaction commands affect
 * "action_authorization".  Return -1 if any of the commands are invalid and
 * 0 in all other cases.
 */
static int
tx_modifies_action(const void *cmds_arg, size_t cmds_sz)
{
	const struct rep_protocol_transaction_cmd *cmds;
	uintptr_t loc;
	uint32_t sz;

	loc = (uintptr_t)cmds_arg;

	while (cmds_sz > 0) {
		cmds = (struct rep_protocol_transaction_cmd *)loc;

		if (cmds_sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (-1);

		sz = cmds->rptc_size;
		if (sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (-1);

		sz = TX_SIZE(sz);
		if (sz > cmds_sz)
			return (-1);

		if (strcmp((const char *)cmds[0].rptc_data, AUTH_PROP_ACTION)
		    == 0)
			return (1);

		loc += sz;
		cmds_sz -= sz;
	}

	return (0);
}

/*
 * Returns 1 if the transaction commands only modify properties named
 * 'enabled'.
 */
static int
tx_only_enabled(const void *cmds_arg, size_t cmds_sz)
{
	const struct rep_protocol_transaction_cmd *cmd;
	uintptr_t loc;
	uint32_t sz;

	loc = (uintptr_t)cmds_arg;

	while (cmds_sz > 0) {
		cmd = (struct rep_protocol_transaction_cmd *)loc;

		if (cmds_sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (-1);

		sz = cmd->rptc_size;
		if (sz <= REP_PROTOCOL_TRANSACTION_CMD_MIN_SIZE)
			return (-1);

		sz = TX_SIZE(sz);
		if (sz > cmds_sz)
			return (-1);

		if (strcmp((const char *)cmd->rptc_data, AUTH_PROP_ENABLED)
		    != 0)
			return (0);

		loc += sz;
		cmds_sz -= sz;
	}

	return (1);
}

int
rc_tx_commit(rc_node_ptr_t *txp, const void *cmds, size_t cmds_sz)
{
	rc_node_t *np = txp->rnp_node;
	rc_node_t *pp;
	rc_node_t *nnp;
	rc_node_pg_notify_t *pnp;
	int rc;
	permcheck_t *pcp;
	int granted, normal;

	RC_NODE_CHECK(np);

	if (!client_is_privileged() && !txp->rnp_authorized) {
#ifdef NATIVE_BUILD
		return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);
#else
		/* permission check: depends on contents of transaction */
		pcp = pc_create();
		if (pcp == NULL)
			return (REP_PROTOCOL_FAIL_NO_RESOURCES);

		/* If normal is cleared, we won't do the normal checks. */
		normal = 1;
		rc = REP_PROTOCOL_SUCCESS;

		if (strcmp(np->rn_name, AUTH_PG_GENERAL) == 0 &&
		    strcmp(np->rn_type, AUTH_PG_GENERAL_TYPE) == 0) {
			/* Touching general[framework]/action_authorization? */
			rc = tx_modifies_action(cmds, cmds_sz);
			if (rc == -1) {
				pc_free(pcp);
				return (REP_PROTOCOL_FAIL_BAD_REQUEST);
			}

			if (rc) {
				/* Yes: only AUTH_MANAGE can be used. */
				rc = perm_add_enabling(pcp, AUTH_MANAGE);
				normal = 0;
			} else {
				rc = REP_PROTOCOL_SUCCESS;
			}
		} else if (np->rn_id.rl_ids[ID_INSTANCE] != 0 &&
		    strcmp(np->rn_name, AUTH_PG_GENERAL_OVR) == 0 &&
		    strcmp(np->rn_type, AUTH_PG_GENERAL_OVR_TYPE) == 0) {
			rc_node_t *instn;

			rc = tx_only_enabled(cmds, cmds_sz);
			if (rc == -1) {
				pc_free(pcp);
				return (REP_PROTOCOL_FAIL_BAD_REQUEST);
			}

			if (rc) {
				rc = rc_node_parent(np, &instn);
				if (rc != REP_PROTOCOL_SUCCESS) {
					assert(rc == REP_PROTOCOL_FAIL_DELETED);
					pc_free(pcp);
					return (rc);
				}

				assert(instn->rn_id.rl_type ==
				    REP_PROTOCOL_ENTITY_INSTANCE);

				rc = perm_add_inst_action_auth(pcp, instn);
				rc_node_rele(instn);
				switch (rc) {
				case REP_PROTOCOL_SUCCESS:
					break;

				case REP_PROTOCOL_FAIL_DELETED:
				case REP_PROTOCOL_FAIL_NO_RESOURCES:
					pc_free(pcp);
					return (rc);

				default:
					bad_error("perm_add_inst_action_auth",
					    rc);
				}
			} else {
				rc = REP_PROTOCOL_SUCCESS;
			}
		}

		if (rc == REP_PROTOCOL_SUCCESS && normal) {
			rc = perm_add_enabling(pcp, AUTH_MODIFY);

			if (rc == REP_PROTOCOL_SUCCESS) {
				/* Add pgtype-specific authorization. */
				const char * const auth =
				    perm_auth_for_pgtype(np->rn_type);

				if (auth != NULL)
					rc = perm_add_enabling(pcp, auth);
			}

			/* Add pg-specific modify_authorization auths. */
			if (rc == REP_PROTOCOL_SUCCESS)
				rc = perm_add_enabling_values(pcp, np,
				    AUTH_PROP_MODIFY);

			/* If value_authorization values are ok, add them. */
			if (rc == REP_PROTOCOL_SUCCESS) {
				rc = tx_allow_value(cmds, cmds_sz, np);
				if (rc == -1)
					rc = REP_PROTOCOL_FAIL_BAD_REQUEST;
				else if (rc)
					rc = perm_add_enabling_values(pcp, np,
					    AUTH_PROP_VALUE);
			}
		}

		if (rc == REP_PROTOCOL_SUCCESS) {
			granted = perm_granted(pcp);
			if (granted < 0)
				rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
		}

		pc_free(pcp);

		if (rc != REP_PROTOCOL_SUCCESS)
			return (rc);

		if (!granted)
			return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);
#endif /* NATIVE_BUILD */
	}

	nnp = rc_node_alloc();
	if (nnp == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	nnp->rn_id = np->rn_id;			/* structure assignment */
	nnp->rn_hash = np->rn_hash;
	nnp->rn_name = strdup(np->rn_name);
	nnp->rn_type = strdup(np->rn_type);
	nnp->rn_pgflags = np->rn_pgflags;

	nnp->rn_flags = RC_NODE_IN_TX | RC_NODE_USING_PARENT;

	if (nnp->rn_name == NULL || nnp->rn_type == NULL) {
		rc_node_destroy(nnp);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	(void) pthread_mutex_lock(&np->rn_lock);
	/*
	 * We must have all of the old properties in the cache, or the
	 * database deletions could cause inconsistencies.
	 */
	if ((rc = rc_node_fill_children(np, REP_PROTOCOL_ENTITY_PROPERTY)) !=
	    REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_destroy(nnp);
		return (rc);
	}

	if (!rc_node_hold_flag(np, RC_NODE_USING_PARENT)) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_destroy(nnp);
		return (REP_PROTOCOL_FAIL_DELETED);
	}

	if (np->rn_flags & RC_NODE_OLD) {
		rc_node_rele_flag(np, RC_NODE_USING_PARENT);
		(void) pthread_mutex_unlock(&np->rn_lock);
		rc_node_destroy(nnp);
		return (REP_PROTOCOL_FAIL_NOT_LATEST);
	}

	pp = rc_node_hold_parent_flag(np, RC_NODE_CHILDREN_CHANGING);
	if (pp == NULL) {
		/* our parent is gone, we're going next... */
		rc_node_destroy(nnp);
		(void) pthread_mutex_lock(&np->rn_lock);
		if (np->rn_flags & RC_NODE_OLD) {
			(void) pthread_mutex_unlock(&np->rn_lock);
			return (REP_PROTOCOL_FAIL_NOT_LATEST);
		}
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_DELETED);
	}
	(void) pthread_mutex_unlock(&pp->rn_lock);

	/*
	 * prepare for the transaction
	 */
	(void) pthread_mutex_lock(&np->rn_lock);
	if (!rc_node_hold_flag(np, RC_NODE_IN_TX)) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		(void) pthread_mutex_lock(&pp->rn_lock);
		rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
		(void) pthread_mutex_unlock(&pp->rn_lock);
		rc_node_destroy(nnp);
		return (REP_PROTOCOL_FAIL_DELETED);
	}
	nnp->rn_gen_id = np->rn_gen_id;
	(void) pthread_mutex_unlock(&np->rn_lock);

	/* Sets nnp->rn_gen_id on success. */
	rc = object_tx_commit(&np->rn_id, cmds, cmds_sz, &nnp->rn_gen_id);

	(void) pthread_mutex_lock(&np->rn_lock);
	if (rc != REP_PROTOCOL_SUCCESS) {
		rc_node_rele_flag(np, RC_NODE_IN_TX);
		(void) pthread_mutex_unlock(&np->rn_lock);
		(void) pthread_mutex_lock(&pp->rn_lock);
		rc_node_rele_flag(pp, RC_NODE_CHILDREN_CHANGING);
		(void) pthread_mutex_unlock(&pp->rn_lock);
		rc_node_destroy(nnp);
		rc_node_clear(txp, 0);
		if (rc == REP_PROTOCOL_DONE)
			rc = REP_PROTOCOL_SUCCESS; /* successful empty tx */
		return (rc);
	}

	/*
	 * Notify waiters
	 */
	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	while ((pnp = uu_list_first(np->rn_pg_notify_list)) != NULL)
		rc_pg_notify_fire(pnp);
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);

	np->rn_flags |= RC_NODE_OLD;
	(void) pthread_mutex_unlock(&np->rn_lock);

	rc_notify_remove_node(np);

	/*
	 * replace np with nnp
	 */
	rc_node_relink_child(pp, np, nnp);

	/*
	 * all done -- clear the transaction.
	 */
	rc_node_clear(txp, 0);

	return (REP_PROTOCOL_SUCCESS);
}

void
rc_pg_notify_init(rc_node_pg_notify_t *pnp)
{
	uu_list_node_init(pnp, &pnp->rnpn_node, rc_pg_notify_pool);
	pnp->rnpn_pg = NULL;
	pnp->rnpn_fd = -1;
}

int
rc_pg_notify_setup(rc_node_pg_notify_t *pnp, rc_node_ptr_t *npp, int fd)
{
	rc_node_t *np;

	RC_NODE_PTR_GET_CHECK_AND_LOCK(np, npp);

	if (np->rn_id.rl_type != REP_PROTOCOL_ENTITY_PROPERTYGRP) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}

	/*
	 * wait for any transaction in progress to complete
	 */
	if (!rc_node_wait_flag(np, RC_NODE_IN_TX)) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_DELETED);
	}

	if (np->rn_flags & RC_NODE_OLD) {
		(void) pthread_mutex_unlock(&np->rn_lock);
		return (REP_PROTOCOL_FAIL_NOT_LATEST);
	}

	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	rc_pg_notify_fire(pnp);
	pnp->rnpn_pg = np;
	pnp->rnpn_fd = fd;
	(void) uu_list_insert_after(np->rn_pg_notify_list, NULL, pnp);
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);

	(void) pthread_mutex_unlock(&np->rn_lock);
	return (REP_PROTOCOL_SUCCESS);
}

void
rc_pg_notify_fini(rc_node_pg_notify_t *pnp)
{
	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	rc_pg_notify_fire(pnp);
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);

	uu_list_node_fini(pnp, &pnp->rnpn_node, rc_pg_notify_pool);
}

void
rc_notify_info_init(rc_notify_info_t *rnip)
{
	int i;

	uu_list_node_init(rnip, &rnip->rni_list_node, rc_notify_info_pool);
	uu_list_node_init(&rnip->rni_notify, &rnip->rni_notify.rcn_list_node,
	    rc_notify_pool);

	rnip->rni_notify.rcn_node = NULL;
	rnip->rni_notify.rcn_info = rnip;

	bzero(rnip->rni_namelist, sizeof (rnip->rni_namelist));
	bzero(rnip->rni_typelist, sizeof (rnip->rni_typelist));

	(void) pthread_cond_init(&rnip->rni_cv, NULL);

	for (i = 0; i < RC_NOTIFY_MAX_NAMES; i++) {
		rnip->rni_namelist[i] = NULL;
		rnip->rni_typelist[i] = NULL;
	}
}

static void
rc_notify_info_insert_locked(rc_notify_info_t *rnip)
{
	assert(MUTEX_HELD(&rc_pg_notify_lock));

	assert(!(rnip->rni_flags & RC_NOTIFY_ACTIVE));

	rnip->rni_flags |= RC_NOTIFY_ACTIVE;
	(void) uu_list_insert_after(rc_notify_info_list, NULL, rnip);
	(void) uu_list_insert_before(rc_notify_list, NULL, &rnip->rni_notify);
}

static void
rc_notify_info_remove_locked(rc_notify_info_t *rnip)
{
	rc_notify_t *me = &rnip->rni_notify;
	rc_notify_t *np;

	assert(MUTEX_HELD(&rc_pg_notify_lock));

	assert(rnip->rni_flags & RC_NOTIFY_ACTIVE);

	assert(!(rnip->rni_flags & RC_NOTIFY_DRAIN));
	rnip->rni_flags |= RC_NOTIFY_DRAIN;
	(void) pthread_cond_broadcast(&rnip->rni_cv);

	(void) uu_list_remove(rc_notify_info_list, rnip);

	/*
	 * clean up any notifications at the beginning of the list
	 */
	if (uu_list_first(rc_notify_list) == me) {
		while ((np = uu_list_next(rc_notify_list, me)) != NULL &&
		    np->rcn_info == NULL)
			rc_notify_remove_locked(np);
	}
	(void) uu_list_remove(rc_notify_list, me);

	while (rnip->rni_waiters) {
		(void) pthread_cond_broadcast(&rc_pg_notify_cv);
		(void) pthread_cond_broadcast(&rnip->rni_cv);
		(void) pthread_cond_wait(&rnip->rni_cv, &rc_pg_notify_lock);
	}

	rnip->rni_flags &= ~(RC_NOTIFY_DRAIN | RC_NOTIFY_ACTIVE);
}

static int
rc_notify_info_add_watch(rc_notify_info_t *rnip, const char **arr,
    const char *name)
{
	int i;
	int rc;
	char *f;

	rc = rc_check_type_name(REP_PROTOCOL_ENTITY_PROPERTYGRP, name);
	if (rc != REP_PROTOCOL_SUCCESS)
		return (rc);

	f = strdup(name);
	if (f == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	(void) pthread_mutex_lock(&rc_pg_notify_lock);

	while (rnip->rni_flags & RC_NOTIFY_EMPTYING)
		(void) pthread_cond_wait(&rnip->rni_cv, &rc_pg_notify_lock);

	for (i = 0; i < RC_NOTIFY_MAX_NAMES; i++)
		if (arr[i] == NULL)
			break;

	if (i == RC_NOTIFY_MAX_NAMES) {
		(void) pthread_mutex_unlock(&rc_pg_notify_lock);
		free(f);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	arr[i] = f;
	if (!(rnip->rni_flags & RC_NOTIFY_ACTIVE))
		rc_notify_info_insert_locked(rnip);

	(void) pthread_mutex_unlock(&rc_pg_notify_lock);
	return (REP_PROTOCOL_SUCCESS);
}

int
rc_notify_info_add_name(rc_notify_info_t *rnip, const char *name)
{
	return (rc_notify_info_add_watch(rnip, rnip->rni_namelist, name));
}

int
rc_notify_info_add_type(rc_notify_info_t *rnip, const char *type)
{
	return (rc_notify_info_add_watch(rnip, rnip->rni_typelist, type));
}

/*
 * Wait for and report an event of interest to rnip, a notification client
 */
int
rc_notify_info_wait(rc_notify_info_t *rnip, rc_node_ptr_t *out,
    char *outp, size_t sz)
{
	rc_notify_t *np;
	rc_notify_t *me = &rnip->rni_notify;
	rc_node_t *nnp;
	rc_notify_delete_t *ndp;

	int am_first_info;

	if (sz > 0)
		outp[0] = 0;

	(void) pthread_mutex_lock(&rc_pg_notify_lock);

	while ((rnip->rni_flags & (RC_NOTIFY_ACTIVE | RC_NOTIFY_DRAIN)) ==
	    RC_NOTIFY_ACTIVE) {
		/*
		 * If I'm first on the notify list, it is my job to
		 * clean up any notifications I pass by.  I can't do that
		 * if someone is blocking the list from removals, so I
		 * have to wait until they have all drained.
		 */
		am_first_info = (uu_list_first(rc_notify_list) == me);
		if (am_first_info && rc_notify_in_use) {
			rnip->rni_waiters++;
			(void) pthread_cond_wait(&rc_pg_notify_cv,
			    &rc_pg_notify_lock);
			rnip->rni_waiters--;
			continue;
		}

		/*
		 * Search the list for a node of interest.
		 */
		np = uu_list_next(rc_notify_list, me);
		while (np != NULL && !rc_notify_info_interested(rnip, np)) {
			rc_notify_t *next = uu_list_next(rc_notify_list, np);

			if (am_first_info) {
				if (np->rcn_info) {
					/*
					 * Passing another client -- stop
					 * cleaning up notifications
					 */
					am_first_info = 0;
				} else {
					rc_notify_remove_locked(np);
				}
			}
			np = next;
		}

		/*
		 * Nothing of interest -- wait for notification
		 */
		if (np == NULL) {
			rnip->rni_waiters++;
			(void) pthread_cond_wait(&rnip->rni_cv,
			    &rc_pg_notify_lock);
			rnip->rni_waiters--;
			continue;
		}

		/*
		 * found something to report -- move myself after the
		 * notification and process it.
		 */
		(void) uu_list_remove(rc_notify_list, me);
		(void) uu_list_insert_after(rc_notify_list, np, me);

		if ((ndp = np->rcn_delete) != NULL) {
			(void) strlcpy(outp, ndp->rnd_fmri, sz);
			if (am_first_info)
				rc_notify_remove_locked(np);
			(void) pthread_mutex_unlock(&rc_pg_notify_lock);
			rc_node_clear(out, 0);
			return (REP_PROTOCOL_SUCCESS);
		}

		nnp = np->rcn_node;
		assert(nnp != NULL);

		/*
		 * We can't bump nnp's reference count without grabbing its
		 * lock, and rc_pg_notify_lock is a leaf lock.  So we
		 * temporarily block all removals to keep nnp from
		 * disappearing.
		 */
		rc_notify_in_use++;
		assert(rc_notify_in_use > 0);
		(void) pthread_mutex_unlock(&rc_pg_notify_lock);

		rc_node_assign(out, nnp);

		(void) pthread_mutex_lock(&rc_pg_notify_lock);
		assert(rc_notify_in_use > 0);
		rc_notify_in_use--;
		if (am_first_info)
			rc_notify_remove_locked(np);
		if (rc_notify_in_use == 0)
			(void) pthread_cond_broadcast(&rc_pg_notify_cv);
		(void) pthread_mutex_unlock(&rc_pg_notify_lock);

		return (REP_PROTOCOL_SUCCESS);
	}
	/*
	 * If we're the last one out, let people know it's clear.
	 */
	if (rnip->rni_waiters == 0)
		(void) pthread_cond_broadcast(&rnip->rni_cv);
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);
	return (REP_PROTOCOL_DONE);
}

static void
rc_notify_info_reset(rc_notify_info_t *rnip)
{
	int i;

	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	if (rnip->rni_flags & RC_NOTIFY_ACTIVE)
		rc_notify_info_remove_locked(rnip);
	assert(!(rnip->rni_flags & (RC_NOTIFY_DRAIN | RC_NOTIFY_EMPTYING)));
	rnip->rni_flags |= RC_NOTIFY_EMPTYING;
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);

	for (i = 0; i < RC_NOTIFY_MAX_NAMES; i++) {
		if (rnip->rni_namelist[i] != NULL) {
			free((void *)rnip->rni_namelist[i]);
			rnip->rni_namelist[i] = NULL;
		}
		if (rnip->rni_typelist[i] != NULL) {
			free((void *)rnip->rni_typelist[i]);
			rnip->rni_typelist[i] = NULL;
		}
	}

	(void) pthread_mutex_lock(&rc_pg_notify_lock);
	rnip->rni_flags &= ~RC_NOTIFY_EMPTYING;
	(void) pthread_mutex_unlock(&rc_pg_notify_lock);
}

void
rc_notify_info_fini(rc_notify_info_t *rnip)
{
	rc_notify_info_reset(rnip);

	uu_list_node_fini(rnip, &rnip->rni_list_node, rc_notify_info_pool);
	uu_list_node_fini(&rnip->rni_notify, &rnip->rni_notify.rcn_list_node,
	    rc_notify_pool);
}
