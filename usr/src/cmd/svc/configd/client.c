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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 RackTop Systems.
 */

/*
 * This is the client layer for svc.configd.  All direct protocol interactions
 * are handled here.
 *
 * Essentially, the job of this layer is to turn the idempotent protocol
 * into a series of non-idempotent calls into the object layer, while
 * also handling the necessary locking.
 */

#include <alloca.h>
#include <assert.h>
#include <bsm/adt_event.h>
#include <door.h>
#include <errno.h>
#include <libintl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ucred.h>
#include <unistd.h>

#include <libuutil.h>

#include "configd.h"
#include "repcache_protocol.h"

#define	INVALID_CHANGEID	(0)
#define	INVALID_DOORID		((door_id_t)-1)
#define	INVALID_RESULT		((rep_protocol_responseid_t)INT_MIN)

/*
 * lint doesn't like constant assertions
 */
#ifdef lint
#define	assert_nolint(x) (void)0
#else
#define	assert_nolint(x) assert(x)
#endif

/*
 * Protects client linkage and the freelist
 */
#define	CLIENT_HASH_SIZE	64

#pragma align 64(client_hash)
static client_bucket_t client_hash[CLIENT_HASH_SIZE];

static uu_avl_pool_t *entity_pool;
static uu_avl_pool_t *iter_pool;
static uu_list_pool_t *client_pool;

#define	CLIENT_HASH(id)		(&client_hash[((id) & (CLIENT_HASH_SIZE - 1))])

uint_t request_log_size = 1024;		/* tunable, before we start */

static pthread_mutex_t request_log_lock = PTHREAD_MUTEX_INITIALIZER;
static uint_t request_log_cur;
request_log_entry_t	*request_log;

static uint32_t		client_maxid;
static pthread_mutex_t	client_lock;	/* protects client_maxid */

static request_log_entry_t *
get_log(void)
{
	thread_info_t *ti = thread_self();
	return (&ti->ti_log);
}

void
log_enter(request_log_entry_t *rlp)
{
	if (rlp->rl_start != 0 && request_log != NULL) {
		request_log_entry_t *logrlp;

		(void) pthread_mutex_lock(&request_log_lock);
		assert(request_log_cur < request_log_size);
		logrlp = &request_log[request_log_cur++];
		if (request_log_cur == request_log_size)
			request_log_cur = 0;
		(void) memcpy(logrlp, rlp, sizeof (*rlp));
		(void) pthread_mutex_unlock(&request_log_lock);
	}
}

/*
 * Note that the svc.configd dmod will join all of the per-thread log entries
 * with the main log, so that even if the log is disabled, there is some
 * information available.
 */
static request_log_entry_t *
start_log(uint32_t clientid)
{
	request_log_entry_t *rlp = get_log();

	log_enter(rlp);

	(void) memset(rlp, 0, sizeof (*rlp));
	rlp->rl_start = gethrtime();
	rlp->rl_tid = pthread_self();
	rlp->rl_clientid = clientid;

	return (rlp);
}

void
end_log(void)
{
	request_log_entry_t *rlp = get_log();

	rlp->rl_end = gethrtime();
}

static void
add_log_ptr(request_log_entry_t *rlp, enum rc_ptr_type type, uint32_t id,
    void *ptr)
{
	request_log_ptr_t *rpp;

	if (rlp == NULL)
		return;

	if (rlp->rl_num_ptrs >= MAX_PTRS)
		return;

	rpp = &rlp->rl_ptrs[rlp->rl_num_ptrs++];
	rpp->rlp_type = type;
	rpp->rlp_id = id;
	rpp->rlp_ptr = ptr;

	/*
	 * For entities, it's useful to have the node pointer at the start
	 * of the request.
	 */
	if (type == RC_PTR_TYPE_ENTITY && ptr != NULL)
		rpp->rlp_data = ((repcache_entity_t *)ptr)->re_node.rnp_node;
}

int
client_is_privileged(void)
{
	thread_info_t *ti = thread_self();

	ucred_t *uc;

	if (ti->ti_active_client != NULL &&
	    ti->ti_active_client->rc_all_auths)
		return (1);

	if ((uc = get_ucred()) == NULL)
		return (0);

	return (ucred_is_privileged(uc));
}

/*ARGSUSED*/
static int
client_compare(const void *lc_arg, const void *rc_arg, void *private)
{
	uint32_t l_id = ((const repcache_client_t *)lc_arg)->rc_id;
	uint32_t r_id = ((const repcache_client_t *)rc_arg)->rc_id;

	if (l_id > r_id)
		return (1);
	if (l_id < r_id)
		return (-1);
	return (0);
}

/*ARGSUSED*/
static int
entity_compare(const void *lc_arg, const void *rc_arg, void *private)
{
	uint32_t l_id = ((const repcache_entity_t *)lc_arg)->re_id;
	uint32_t r_id = ((const repcache_entity_t *)rc_arg)->re_id;

	if (l_id > r_id)
		return (1);
	if (l_id < r_id)
		return (-1);
	return (0);
}

/*ARGSUSED*/
static int
iter_compare(const void *lc_arg, const void *rc_arg, void *private)
{
	uint32_t l_id = ((const repcache_iter_t *)lc_arg)->ri_id;
	uint32_t r_id = ((const repcache_iter_t *)rc_arg)->ri_id;

	if (l_id > r_id)
		return (1);
	if (l_id < r_id)
		return (-1);
	return (0);
}

static int
client_hash_init(void)
{
	int x;

	assert_nolint(offsetof(repcache_entity_t, re_id) == 0);
	entity_pool = uu_avl_pool_create("repcache_entitys",
	    sizeof (repcache_entity_t), offsetof(repcache_entity_t, re_link),
	    entity_compare, UU_AVL_POOL_DEBUG);

	assert_nolint(offsetof(repcache_iter_t, ri_id) == 0);
	iter_pool = uu_avl_pool_create("repcache_iters",
	    sizeof (repcache_iter_t), offsetof(repcache_iter_t, ri_link),
	    iter_compare, UU_AVL_POOL_DEBUG);

	assert_nolint(offsetof(repcache_client_t, rc_id) == 0);
	client_pool = uu_list_pool_create("repcache_clients",
	    sizeof (repcache_client_t), offsetof(repcache_client_t, rc_link),
	    client_compare, UU_LIST_POOL_DEBUG);

	if (entity_pool == NULL || iter_pool == NULL || client_pool == NULL)
		return (0);

	for (x = 0; x < CLIENT_HASH_SIZE; x++) {
		uu_list_t *lp = uu_list_create(client_pool, &client_hash[x],
		    UU_LIST_SORTED);
		if (lp == NULL)
			return (0);

		(void) pthread_mutex_init(&client_hash[x].cb_lock, NULL);
		client_hash[x].cb_list = lp;
	}

	return (1);
}

static repcache_client_t *
client_alloc(void)
{
	repcache_client_t *cp;
	cp = uu_zalloc(sizeof (*cp));
	if (cp == NULL)
		return (NULL);

	cp->rc_entities = uu_avl_create(entity_pool, cp, 0);
	if (cp->rc_entities == NULL)
		goto fail;

	cp->rc_iters = uu_avl_create(iter_pool, cp, 0);
	if (cp->rc_iters == NULL)
		goto fail;

	uu_list_node_init(cp, &cp->rc_link, client_pool);

	cp->rc_doorfd = -1;
	cp->rc_doorid = INVALID_DOORID;

	(void) pthread_mutex_init(&cp->rc_lock, NULL);
	(void) pthread_mutex_init(&cp->rc_annotate_lock, NULL);

	rc_node_ptr_init(&cp->rc_notify_ptr);

	return (cp);

fail:
	if (cp->rc_iters != NULL)
		uu_avl_destroy(cp->rc_iters);
	if (cp->rc_entities != NULL)
		uu_avl_destroy(cp->rc_entities);
	uu_free(cp);
	return (NULL);
}

static void
client_free(repcache_client_t *cp)
{
	assert(cp->rc_insert_thr == 0);
	assert(cp->rc_refcnt == 0);
	assert(cp->rc_doorfd == -1);
	assert(cp->rc_doorid == INVALID_DOORID);
	assert(uu_avl_first(cp->rc_entities) == NULL);
	assert(uu_avl_first(cp->rc_iters) == NULL);
	uu_avl_destroy(cp->rc_entities);
	uu_avl_destroy(cp->rc_iters);
	uu_list_node_fini(cp, &cp->rc_link, client_pool);
	(void) pthread_mutex_destroy(&cp->rc_lock);
	(void) pthread_mutex_destroy(&cp->rc_annotate_lock);
	rc_node_ptr_free_mem(&cp->rc_notify_ptr);
	uu_free(cp);
}

static void
client_insert(repcache_client_t *cp)
{
	client_bucket_t *bp = CLIENT_HASH(cp->rc_id);
	uu_list_index_t idx;

	assert(cp->rc_id > 0);

	(void) pthread_mutex_lock(&bp->cb_lock);
	/*
	 * We assume it does not already exist
	 */
	(void) uu_list_find(bp->cb_list, cp, NULL, &idx);
	uu_list_insert(bp->cb_list, cp, idx);

	(void) pthread_mutex_unlock(&bp->cb_lock);
}

static repcache_client_t *
client_lookup(uint32_t id)
{
	client_bucket_t *bp = CLIENT_HASH(id);
	repcache_client_t *cp;

	(void) pthread_mutex_lock(&bp->cb_lock);

	cp = uu_list_find(bp->cb_list, &id, NULL, NULL);

	/*
	 * Bump the reference count
	 */
	if (cp != NULL) {
		(void) pthread_mutex_lock(&cp->rc_lock);
		assert(!(cp->rc_flags & RC_CLIENT_DEAD));
		cp->rc_refcnt++;
		(void) pthread_mutex_unlock(&cp->rc_lock);
	}
	(void) pthread_mutex_unlock(&bp->cb_lock);

	return (cp);
}

static void
client_release(repcache_client_t *cp)
{
	(void) pthread_mutex_lock(&cp->rc_lock);
	assert(cp->rc_refcnt > 0);
	assert(cp->rc_insert_thr != pthread_self());

	--cp->rc_refcnt;
	(void) pthread_cond_broadcast(&cp->rc_cv);
	(void) pthread_mutex_unlock(&cp->rc_lock);
}

/*
 * We only allow one thread to be inserting at a time, to prevent
 * insert/insert races.
 */
static void
client_start_insert(repcache_client_t *cp)
{
	(void) pthread_mutex_lock(&cp->rc_lock);
	assert(cp->rc_refcnt > 0);

	while (cp->rc_insert_thr != 0) {
		assert(cp->rc_insert_thr != pthread_self());
		(void) pthread_cond_wait(&cp->rc_cv, &cp->rc_lock);
	}
	cp->rc_insert_thr = pthread_self();
	(void) pthread_mutex_unlock(&cp->rc_lock);
}

static void
client_end_insert(repcache_client_t *cp)
{
	(void) pthread_mutex_lock(&cp->rc_lock);
	assert(cp->rc_insert_thr == pthread_self());
	cp->rc_insert_thr = 0;
	(void) pthread_cond_broadcast(&cp->rc_cv);
	(void) pthread_mutex_unlock(&cp->rc_lock);
}

/*ARGSUSED*/
static repcache_entity_t *
entity_alloc(repcache_client_t *cp)
{
	repcache_entity_t *ep = uu_zalloc(sizeof (repcache_entity_t));
	if (ep != NULL) {
		uu_avl_node_init(ep, &ep->re_link, entity_pool);
	}
	return (ep);
}

static void
entity_add(repcache_client_t *cp, repcache_entity_t *ep)
{
	uu_avl_index_t idx;

	(void) pthread_mutex_lock(&cp->rc_lock);
	assert(cp->rc_insert_thr == pthread_self());

	(void) uu_avl_find(cp->rc_entities, ep, NULL, &idx);
	uu_avl_insert(cp->rc_entities, ep, idx);

	(void) pthread_mutex_unlock(&cp->rc_lock);
}

static repcache_entity_t *
entity_find(repcache_client_t *cp, uint32_t id)
{
	repcache_entity_t *ep;

	(void) pthread_mutex_lock(&cp->rc_lock);
	ep = uu_avl_find(cp->rc_entities, &id, NULL, NULL);
	if (ep != NULL) {
		add_log_ptr(get_log(), RC_PTR_TYPE_ENTITY, id, ep);
		(void) pthread_mutex_lock(&ep->re_lock);
	}
	(void) pthread_mutex_unlock(&cp->rc_lock);

	return (ep);
}

/*
 * Fails with
 *   _DUPLICATE_ID - the ids are equal
 *   _UNKNOWN_ID - an id does not designate an active register
 */
static int
entity_find2(repcache_client_t *cp, uint32_t id1, repcache_entity_t **out1,
    uint32_t id2, repcache_entity_t **out2)
{
	repcache_entity_t *e1, *e2;
	request_log_entry_t *rlp;

	if (id1 == id2)
		return (REP_PROTOCOL_FAIL_DUPLICATE_ID);

	(void) pthread_mutex_lock(&cp->rc_lock);
	e1 = uu_avl_find(cp->rc_entities, &id1, NULL, NULL);
	e2 = uu_avl_find(cp->rc_entities, &id2, NULL, NULL);
	if (e1 == NULL || e2 == NULL) {
		(void) pthread_mutex_unlock(&cp->rc_lock);
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);
	}

	assert(e1 != e2);

	/*
	 * locks are ordered by id number
	 */
	if (id1 < id2) {
		(void) pthread_mutex_lock(&e1->re_lock);
		(void) pthread_mutex_lock(&e2->re_lock);
	} else {
		(void) pthread_mutex_lock(&e2->re_lock);
		(void) pthread_mutex_lock(&e1->re_lock);
	}
	*out1 = e1;
	*out2 = e2;

	(void) pthread_mutex_unlock(&cp->rc_lock);

	if ((rlp = get_log()) != NULL) {
		add_log_ptr(rlp, RC_PTR_TYPE_ENTITY, id1, e1);
		add_log_ptr(rlp, RC_PTR_TYPE_ENTITY, id2, e2);
	}

	return (REP_PROTOCOL_SUCCESS);
}

static void
entity_release(repcache_entity_t *ep)
{
	assert(ep->re_node.rnp_node == NULL ||
	    !MUTEX_HELD(&ep->re_node.rnp_node->rn_lock));
	(void) pthread_mutex_unlock(&ep->re_lock);
}

static void
entity_destroy(repcache_entity_t *entity)
{
	(void) pthread_mutex_lock(&entity->re_lock);
	rc_node_clear(&entity->re_node, 0);
	(void) pthread_mutex_unlock(&entity->re_lock);

	uu_avl_node_fini(entity, &entity->re_link, entity_pool);
	(void) pthread_mutex_destroy(&entity->re_lock);
	rc_node_ptr_free_mem(&entity->re_node);
	uu_free(entity);
}

static void
entity_remove(repcache_client_t *cp, uint32_t id)
{
	repcache_entity_t *entity;

	(void) pthread_mutex_lock(&cp->rc_lock);
	entity = uu_avl_find(cp->rc_entities, &id, NULL, NULL);
	if (entity != NULL) {
		add_log_ptr(get_log(), RC_PTR_TYPE_ENTITY, id, entity);

		uu_avl_remove(cp->rc_entities, entity);
	}
	(void) pthread_mutex_unlock(&cp->rc_lock);

	if (entity != NULL)
		entity_destroy(entity);
}

static void
entity_cleanup(repcache_client_t *cp)
{
	repcache_entity_t *ep;
	void *cookie = NULL;

	(void) pthread_mutex_lock(&cp->rc_lock);
	while ((ep = uu_avl_teardown(cp->rc_entities, &cookie)) != NULL) {
		(void) pthread_mutex_unlock(&cp->rc_lock);
		entity_destroy(ep);
		(void) pthread_mutex_lock(&cp->rc_lock);
	}
	(void) pthread_mutex_unlock(&cp->rc_lock);
}

/*ARGSUSED*/
static repcache_iter_t *
iter_alloc(repcache_client_t *cp)
{
	repcache_iter_t *iter;
	iter = uu_zalloc(sizeof (repcache_iter_t));
	if (iter != NULL)
		uu_avl_node_init(iter, &iter->ri_link, iter_pool);
	return (iter);
}

static void
iter_add(repcache_client_t *cp, repcache_iter_t *iter)
{
	uu_list_index_t idx;

	(void) pthread_mutex_lock(&cp->rc_lock);
	assert(cp->rc_insert_thr == pthread_self());

	(void) uu_avl_find(cp->rc_iters, iter, NULL, &idx);
	uu_avl_insert(cp->rc_iters, iter, idx);

	(void) pthread_mutex_unlock(&cp->rc_lock);
}

static repcache_iter_t *
iter_find(repcache_client_t *cp, uint32_t id)
{
	repcache_iter_t *iter;

	(void) pthread_mutex_lock(&cp->rc_lock);

	iter = uu_avl_find(cp->rc_iters, &id, NULL, NULL);
	if (iter != NULL) {
		add_log_ptr(get_log(), RC_PTR_TYPE_ITER, id, iter);
		(void) pthread_mutex_lock(&iter->ri_lock);
	}
	(void) pthread_mutex_unlock(&cp->rc_lock);

	return (iter);
}

/*
 * Fails with
 *   _UNKNOWN_ID - iter_id or entity_id does not designate an active register
 */
static int
iter_find_w_entity(repcache_client_t *cp, uint32_t iter_id,
    repcache_iter_t **iterp, uint32_t entity_id, repcache_entity_t **epp)
{
	repcache_iter_t *iter;
	repcache_entity_t *ep;
	request_log_entry_t *rlp;

	(void) pthread_mutex_lock(&cp->rc_lock);
	iter = uu_avl_find(cp->rc_iters, &iter_id, NULL, NULL);
	ep = uu_avl_find(cp->rc_entities, &entity_id, NULL, NULL);

	assert(iter == NULL || !MUTEX_HELD(&iter->ri_lock));
	assert(ep == NULL || !MUTEX_HELD(&ep->re_lock));

	if (iter == NULL || ep == NULL) {
		(void) pthread_mutex_unlock(&cp->rc_lock);
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);
	}

	(void) pthread_mutex_lock(&iter->ri_lock);
	(void) pthread_mutex_lock(&ep->re_lock);

	(void) pthread_mutex_unlock(&cp->rc_lock);

	*iterp = iter;
	*epp = ep;

	if ((rlp = get_log()) != NULL) {
		add_log_ptr(rlp, RC_PTR_TYPE_ENTITY, entity_id, ep);
		add_log_ptr(rlp, RC_PTR_TYPE_ITER, iter_id, iter);
	}

	return (REP_PROTOCOL_SUCCESS);
}

static void
iter_release(repcache_iter_t *iter)
{
	(void) pthread_mutex_unlock(&iter->ri_lock);
}

static void
iter_destroy(repcache_iter_t *iter)
{
	(void) pthread_mutex_lock(&iter->ri_lock);
	rc_iter_destroy(&iter->ri_iter);
	(void) pthread_mutex_unlock(&iter->ri_lock);

	uu_avl_node_fini(iter, &iter->ri_link, iter_pool);
	(void) pthread_mutex_destroy(&iter->ri_lock);
	uu_free(iter);
}

static void
iter_remove(repcache_client_t *cp, uint32_t id)
{
	repcache_iter_t *iter;

	(void) pthread_mutex_lock(&cp->rc_lock);
	iter = uu_avl_find(cp->rc_iters, &id, NULL, NULL);
	if (iter != NULL)
		uu_avl_remove(cp->rc_iters, iter);
	(void) pthread_mutex_unlock(&cp->rc_lock);

	if (iter != NULL)
		iter_destroy(iter);
}

static void
iter_cleanup(repcache_client_t *cp)
{
	repcache_iter_t *iter;
	void *cookie = NULL;

	(void) pthread_mutex_lock(&cp->rc_lock);
	while ((iter = uu_avl_teardown(cp->rc_iters, &cookie)) != NULL) {
		(void) pthread_mutex_unlock(&cp->rc_lock);
		iter_destroy(iter);
		(void) pthread_mutex_lock(&cp->rc_lock);
	}
	(void) pthread_mutex_unlock(&cp->rc_lock);
}

/*
 * Ensure that the passed client id is no longer usable, wait for any
 * outstanding invocations to complete, then destroy the client
 * structure.
 */
static void
client_destroy(uint32_t id)
{
	client_bucket_t *bp = CLIENT_HASH(id);
	repcache_client_t *cp;

	(void) pthread_mutex_lock(&bp->cb_lock);

	cp = uu_list_find(bp->cb_list, &id, NULL, NULL);

	if (cp == NULL) {
		(void) pthread_mutex_unlock(&bp->cb_lock);
		return;
	}

	uu_list_remove(bp->cb_list, cp);

	(void) pthread_mutex_unlock(&bp->cb_lock);

	/* kick the waiters out */
	rc_notify_info_fini(&cp->rc_notify_info);

	(void) pthread_mutex_lock(&cp->rc_lock);
	assert(!(cp->rc_flags & RC_CLIENT_DEAD));
	cp->rc_flags |= RC_CLIENT_DEAD;

	if (cp->rc_doorfd != -1) {
		if (door_revoke(cp->rc_doorfd) < 0)
			perror("door_revoke");
		cp->rc_doorfd = -1;
		cp->rc_doorid = INVALID_DOORID;
	}

	while (cp->rc_refcnt > 0)
		(void) pthread_cond_wait(&cp->rc_cv, &cp->rc_lock);

	assert(cp->rc_insert_thr == 0 && cp->rc_notify_thr == 0);
	(void) pthread_mutex_unlock(&cp->rc_lock);

	/*
	 * destroy outstanding objects
	 */
	entity_cleanup(cp);
	iter_cleanup(cp);

	/*
	 * clean up notifications
	 */
	rc_pg_notify_fini(&cp->rc_pg_notify);

	/*
	 * clean up annotations
	 */
	if (cp->rc_operation != NULL)
		free((void *)cp->rc_operation);
	if (cp->rc_file != NULL)
		free((void *)cp->rc_file);

	/*
	 * End audit session.
	 */
#ifndef	NATIVE_BUILD
	(void) adt_end_session(cp->rc_adt_session);
#endif

	client_free(cp);
}

/*
 * Fails with
 *   _TYPE_MISMATCH - the entity is already set up with a different type
 *   _NO_RESOURCES - out of memory
 */
static int
entity_setup(repcache_client_t *cp, struct rep_protocol_entity_setup *rpr)
{
	repcache_entity_t *ep;
	uint32_t type;

	client_start_insert(cp);

	if ((ep = entity_find(cp, rpr->rpr_entityid)) != NULL) {
		type = ep->re_type;
		entity_release(ep);

		client_end_insert(cp);

		if (type != rpr->rpr_entitytype)
			return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
		return (REP_PROTOCOL_SUCCESS);
	}

	switch (type = rpr->rpr_entitytype) {
	case REP_PROTOCOL_ENTITY_SCOPE:
	case REP_PROTOCOL_ENTITY_SERVICE:
	case REP_PROTOCOL_ENTITY_INSTANCE:
	case REP_PROTOCOL_ENTITY_SNAPSHOT:
	case REP_PROTOCOL_ENTITY_SNAPLEVEL:
	case REP_PROTOCOL_ENTITY_PROPERTYGRP:
	case REP_PROTOCOL_ENTITY_PROPERTY:
		break;
	default:
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}

	ep = entity_alloc(cp);
	if (ep == NULL) {
		client_end_insert(cp);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	ep->re_id = rpr->rpr_entityid;
	ep->re_changeid = INVALID_CHANGEID;

	ep->re_type = type;
	rc_node_ptr_init(&ep->re_node);

	entity_add(cp, ep);
	client_end_insert(cp);
	return (REP_PROTOCOL_SUCCESS);
}

/*ARGSUSED*/
static void
entity_name(repcache_client_t *cp, const void *in, size_t insz, void *out_arg,
    size_t *outsz, void *arg)
{
	const struct rep_protocol_entity_name *rpr = in;
	struct rep_protocol_name_response *out = out_arg;
	repcache_entity_t *ep;
	size_t sz = sizeof (out->rpr_name);

	assert(*outsz == sizeof (*out));

	ep = entity_find(cp, rpr->rpr_entityid);

	if (ep == NULL) {
		out->rpr_response = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		*outsz = sizeof (out->rpr_response);
		return;
	}
	out->rpr_response = rc_node_name(&ep->re_node, out->rpr_name,
	    sz, rpr->rpr_answertype, &sz);
	entity_release(ep);

	/*
	 * If we fail, we only return the response code.
	 * If we succeed, we don't return anything after the '\0' in rpr_name.
	 */
	if (out->rpr_response != REP_PROTOCOL_SUCCESS)
		*outsz = sizeof (out->rpr_response);
	else
		*outsz = offsetof(struct rep_protocol_name_response,
		    rpr_name[sz + 1]);
}

/*ARGSUSED*/
static void
entity_parent_type(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg)
{
	const struct rep_protocol_entity_name *rpr = in;
	struct rep_protocol_integer_response *out = out_arg;
	repcache_entity_t *ep;

	assert(*outsz == sizeof (*out));

	ep = entity_find(cp, rpr->rpr_entityid);

	if (ep == NULL) {
		out->rpr_response = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		*outsz = sizeof (out->rpr_response);
		return;
	}

	out->rpr_response = rc_node_parent_type(&ep->re_node, &out->rpr_value);
	entity_release(ep);

	if (out->rpr_response != REP_PROTOCOL_SUCCESS)
		*outsz = sizeof (out->rpr_response);
}

/*
 * Fails with
 *   _DUPLICATE_ID - the ids are equal
 *   _UNKNOWN_ID - an id does not designate an active register
 *   _INVALID_TYPE - type is invalid
 *   _TYPE_MISMATCH - np doesn't carry children of type type
 *   _DELETED - np has been deleted
 *   _NOT_FOUND - no child with that name/type combo found
 *   _NO_RESOURCES
 *   _BACKEND_ACCESS
 */
static int
entity_get_child(repcache_client_t *cp,
    struct rep_protocol_entity_get_child *rpr)
{
	repcache_entity_t *parent, *child;
	int result;

	uint32_t parentid = rpr->rpr_entityid;
	uint32_t childid = rpr->rpr_childid;

	result = entity_find2(cp, childid, &child, parentid, &parent);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	rpr->rpr_name[sizeof (rpr->rpr_name) - 1] = 0;

	result = rc_node_get_child(&parent->re_node, rpr->rpr_name,
	    child->re_type, &child->re_node);

	entity_release(child);
	entity_release(parent);

	return (result);
}

/*
 * Returns _FAIL_DUPLICATE_ID, _FAIL_UNKNOWN_ID, _FAIL_NOT_SET, _FAIL_DELETED,
 * _FAIL_TYPE_MISMATCH, _FAIL_NOT_FOUND (scope has no parent), or _SUCCESS.
 * Fails with
 *   _DUPLICATE_ID - the ids are equal
 *   _UNKNOWN_ID - an id does not designate an active register
 *   _NOT_SET - child is not set
 *   _DELETED - child has been deleted
 *   _TYPE_MISMATCH - child's parent does not match that of the parent register
 *   _NOT_FOUND - child has no parent (and is a scope)
 */
static int
entity_get_parent(repcache_client_t *cp, struct rep_protocol_entity_parent *rpr)
{
	repcache_entity_t *child, *parent;
	int result;

	uint32_t childid = rpr->rpr_entityid;
	uint32_t outid = rpr->rpr_outid;

	result = entity_find2(cp, childid, &child, outid, &parent);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	result = rc_node_get_parent(&child->re_node, parent->re_type,
	    &parent->re_node);

	entity_release(child);
	entity_release(parent);

	return (result);
}

static int
entity_get(repcache_client_t *cp, struct rep_protocol_entity_get *rpr)
{
	repcache_entity_t *ep;
	int result;

	ep = entity_find(cp, rpr->rpr_entityid);

	if (ep == NULL)
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);

	switch (rpr->rpr_object) {
	case RP_ENTITY_GET_INVALIDATE:
		rc_node_clear(&ep->re_node, 0);
		result = REP_PROTOCOL_SUCCESS;
		break;
	case RP_ENTITY_GET_MOST_LOCAL_SCOPE:
		result = rc_local_scope(ep->re_type, &ep->re_node);
		break;
	default:
		result = REP_PROTOCOL_FAIL_BAD_REQUEST;
		break;
	}

	entity_release(ep);

	return (result);
}

static int
entity_update(repcache_client_t *cp, struct rep_protocol_entity_update *rpr)
{
	repcache_entity_t *ep;
	int result;

	if (rpr->rpr_changeid == INVALID_CHANGEID)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	ep = entity_find(cp, rpr->rpr_entityid);

	if (ep == NULL)
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);

	if (ep->re_changeid == rpr->rpr_changeid) {
		result = REP_PROTOCOL_DONE;
	} else {
		result = rc_node_update(&ep->re_node);
		if (result == REP_PROTOCOL_DONE)
			ep->re_changeid = rpr->rpr_changeid;
	}

	entity_release(ep);

	return (result);
}

static int
entity_reset(repcache_client_t *cp, struct rep_protocol_entity_reset *rpr)
{
	repcache_entity_t *ep;

	ep = entity_find(cp, rpr->rpr_entityid);
	if (ep == NULL)
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);

	rc_node_clear(&ep->re_node, 0);
	ep->re_txstate = REPCACHE_TX_INIT;

	entity_release(ep);
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _BAD_REQUEST - request has invalid changeid
 *		    rpr_name is invalid
 *		    cannot create children for parent's type of node
 *   _DUPLICATE_ID - request has duplicate ids
 *   _UNKNOWN_ID - request has unknown id
 *   _DELETED - parent has been deleted
 *   _NOT_SET - parent is reset
 *   _NOT_APPLICABLE - rpr_childtype is _PROPERTYGRP
 *   _INVALID_TYPE - parent is corrupt or rpr_childtype is invalid
 *   _TYPE_MISMATCH - parent cannot have children of type rpr_childtype
 *   _NO_RESOURCES
 *   _PERMISSION_DENIED
 *   _BACKEND_ACCESS
 *   _BACKEND_READONLY
 *   _EXISTS - child already exists
 */
static int
entity_create_child(repcache_client_t *cp,
    struct rep_protocol_entity_create_child *rpr)
{
	repcache_entity_t *parent;
	repcache_entity_t *child;

	uint32_t parentid = rpr->rpr_entityid;
	uint32_t childid = rpr->rpr_childid;

	int result;

	if (rpr->rpr_changeid == INVALID_CHANGEID)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	result = entity_find2(cp, parentid, &parent, childid, &child);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	rpr->rpr_name[sizeof (rpr->rpr_name) - 1] = 0;

	if (child->re_changeid == rpr->rpr_changeid) {
		result = REP_PROTOCOL_SUCCESS;
	} else {
		result = rc_node_create_child(&parent->re_node,
		    rpr->rpr_childtype, rpr->rpr_name, &child->re_node);
		if (result == REP_PROTOCOL_SUCCESS)
			child->re_changeid = rpr->rpr_changeid;
	}

	entity_release(parent);
	entity_release(child);

	return (result);
}

static int
entity_create_pg(repcache_client_t *cp,
    struct rep_protocol_entity_create_pg *rpr)
{
	repcache_entity_t *parent;
	repcache_entity_t *child;

	uint32_t parentid = rpr->rpr_entityid;
	uint32_t childid = rpr->rpr_childid;

	int result;

	if (rpr->rpr_changeid == INVALID_CHANGEID)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	result = entity_find2(cp, parentid, &parent, childid, &child);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	rpr->rpr_name[sizeof (rpr->rpr_name) - 1] = 0;
	rpr->rpr_type[sizeof (rpr->rpr_type) - 1] = 0;

	if (child->re_changeid == rpr->rpr_changeid) {
		result = REP_PROTOCOL_SUCCESS;
	} else {
		result = rc_node_create_child_pg(&parent->re_node,
		    child->re_type, rpr->rpr_name, rpr->rpr_type,
		    rpr->rpr_flags, &child->re_node);
		if (result == REP_PROTOCOL_SUCCESS)
			child->re_changeid = rpr->rpr_changeid;
	}

	entity_release(parent);
	entity_release(child);

	return (result);
}

static int
entity_delete(repcache_client_t *cp,
    struct rep_protocol_entity_delete *rpr)
{
	repcache_entity_t *entity;

	uint32_t entityid = rpr->rpr_entityid;

	int result;

	if (rpr->rpr_changeid == INVALID_CHANGEID)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	entity = entity_find(cp, entityid);

	if (entity == NULL)
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);

	if (entity->re_changeid == rpr->rpr_changeid) {
		result = REP_PROTOCOL_SUCCESS;
	} else {
		result = rc_node_delete(&entity->re_node);
		if (result == REP_PROTOCOL_SUCCESS)
			entity->re_changeid = rpr->rpr_changeid;
	}

	entity_release(entity);

	return (result);
}

static rep_protocol_responseid_t
entity_teardown(repcache_client_t *cp, struct rep_protocol_entity_teardown *rpr)
{
	entity_remove(cp, rpr->rpr_entityid);

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _MISORDERED - the iterator exists and is not reset
 *   _NO_RESOURCES - out of memory
 */
static int
iter_setup(repcache_client_t *cp, struct rep_protocol_iter_request *rpr)
{
	repcache_iter_t *iter;
	uint32_t sequence;

	client_start_insert(cp);
	/*
	 * If the iter already exists, and hasn't been read from,
	 * we assume the previous call succeeded.
	 */
	if ((iter = iter_find(cp, rpr->rpr_iterid)) != NULL) {
		sequence = iter->ri_sequence;
		iter_release(iter);

		client_end_insert(cp);

		if (sequence != 0)
			return (REP_PROTOCOL_FAIL_MISORDERED);
		return (REP_PROTOCOL_SUCCESS);
	}

	iter = iter_alloc(cp);
	if (iter == NULL) {
		client_end_insert(cp);
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	iter->ri_id = rpr->rpr_iterid;
	iter->ri_type = REP_PROTOCOL_TYPE_INVALID;
	iter->ri_sequence = 0;
	iter_add(cp, iter);

	client_end_insert(cp);
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _UNKNOWN_ID
 *   _MISORDERED - iterator has already been started
 *   _NOT_SET
 *   _DELETED
 *   _TYPE_MISMATCH - entity cannot have type children
 *   _BAD_REQUEST - rpr_flags is invalid
 *		    rpr_pattern is invalid
 *   _NO_RESOURCES
 *   _INVALID_TYPE
 *   _BACKEND_ACCESS
 */
static int
iter_start(repcache_client_t *cp, struct rep_protocol_iter_start *rpr)
{
	int result;
	repcache_iter_t *iter;
	repcache_entity_t *ep;

	result = iter_find_w_entity(cp, rpr->rpr_iterid, &iter,
	    rpr->rpr_entity, &ep);

	if (result != REP_PROTOCOL_SUCCESS)
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);

	if (iter->ri_sequence > 1) {
		result = REP_PROTOCOL_FAIL_MISORDERED;
		goto end;
	}

	if (iter->ri_sequence == 1) {
		result = REP_PROTOCOL_SUCCESS;
		goto end;
	}

	rpr->rpr_pattern[sizeof (rpr->rpr_pattern) - 1] = 0;

	result = rc_node_setup_iter(&ep->re_node, &iter->ri_iter,
	    rpr->rpr_itertype, rpr->rpr_flags, rpr->rpr_pattern);

	if (result == REP_PROTOCOL_SUCCESS)
		iter->ri_sequence++;

end:
	iter_release(iter);
	entity_release(ep);
	return (result);
}

/*
 * Returns
 *   _UNKNOWN_ID
 *   _NOT_SET - iter has not been started
 *   _MISORDERED
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
 *   _BACKEND_ACCESS
 */
static rep_protocol_responseid_t
iter_read(repcache_client_t *cp, struct rep_protocol_iter_read *rpr)
{
	rep_protocol_responseid_t result;
	repcache_iter_t *iter;
	repcache_entity_t *ep;
	uint32_t sequence;

	result = iter_find_w_entity(cp, rpr->rpr_iterid, &iter,
	    rpr->rpr_entityid, &ep);

	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	sequence = rpr->rpr_sequence;

	if (iter->ri_sequence == 0) {
		iter_release(iter);
		entity_release(ep);
		return (REP_PROTOCOL_FAIL_NOT_SET);
	}

	if (sequence == 1) {
		iter_release(iter);
		entity_release(ep);
		return (REP_PROTOCOL_FAIL_MISORDERED);
	}

	if (sequence == iter->ri_sequence) {
		iter_release(iter);
		entity_release(ep);
		return (REP_PROTOCOL_SUCCESS);
	}

	if (sequence == iter->ri_sequence + 1) {
		result = rc_iter_next(iter->ri_iter, &ep->re_node,
		    ep->re_type);

		if (result == REP_PROTOCOL_SUCCESS)
			iter->ri_sequence++;

		iter_release(iter);
		entity_release(ep);

		return (result);
	}

	iter_release(iter);
	entity_release(ep);
	return (REP_PROTOCOL_FAIL_MISORDERED);
}

/*ARGSUSED*/
static void
iter_read_value(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg)
{
	const struct rep_protocol_iter_read_value *rpr = in;
	struct rep_protocol_value_response *out = out_arg;
	rep_protocol_responseid_t result;

	repcache_iter_t *iter;
	uint32_t sequence;
	int repeat;

	assert(*outsz == sizeof (*out));

	iter = iter_find(cp, rpr->rpr_iterid);

	if (iter == NULL) {
		result = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		goto out;
	}

	sequence = rpr->rpr_sequence;

	if (iter->ri_sequence == 0) {
		iter_release(iter);
		result = REP_PROTOCOL_FAIL_NOT_SET;
		goto out;
	}

	repeat = (sequence == iter->ri_sequence);

	if (sequence == 1 || (!repeat && sequence != iter->ri_sequence + 1)) {
		iter_release(iter);
		result = REP_PROTOCOL_FAIL_MISORDERED;
		goto out;
	}

	result = rc_iter_next_value(iter->ri_iter, out, outsz, repeat);

	if (!repeat && result == REP_PROTOCOL_SUCCESS)
		iter->ri_sequence++;

	iter_release(iter);

out:
	/*
	 * If we fail, we only return the response code.
	 * If we succeed, rc_iter_next_value has shortened *outsz
	 * to only include the value bytes needed.
	 */
	if (result != REP_PROTOCOL_SUCCESS && result != REP_PROTOCOL_DONE)
		*outsz = sizeof (out->rpr_response);

	out->rpr_response = result;
}

static int
iter_reset(repcache_client_t *cp, struct rep_protocol_iter_request *rpr)
{
	repcache_iter_t *iter = iter_find(cp, rpr->rpr_iterid);

	if (iter == NULL)
		return (REP_PROTOCOL_FAIL_UNKNOWN_ID);

	if (iter->ri_sequence != 0) {
		iter->ri_sequence = 0;
		rc_iter_destroy(&iter->ri_iter);
	}
	iter_release(iter);
	return (REP_PROTOCOL_SUCCESS);
}

static rep_protocol_responseid_t
iter_teardown(repcache_client_t *cp, struct rep_protocol_iter_request *rpr)
{
	iter_remove(cp, rpr->rpr_iterid);

	return (REP_PROTOCOL_SUCCESS);
}

static rep_protocol_responseid_t
tx_start(repcache_client_t *cp, struct rep_protocol_transaction_start *rpr)
{
	repcache_entity_t *tx;
	repcache_entity_t *ep;
	rep_protocol_responseid_t result;

	uint32_t txid = rpr->rpr_entityid_tx;
	uint32_t epid = rpr->rpr_entityid;

	result = entity_find2(cp, txid, &tx, epid, &ep);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	if (tx->re_txstate == REPCACHE_TX_SETUP) {
		result = REP_PROTOCOL_SUCCESS;
		goto end;
	}
	if (tx->re_txstate != REPCACHE_TX_INIT) {
		result = REP_PROTOCOL_FAIL_MISORDERED;
		goto end;
	}

	result = rc_node_setup_tx(&ep->re_node, &tx->re_node);

end:
	if (result == REP_PROTOCOL_SUCCESS)
		tx->re_txstate = REPCACHE_TX_SETUP;
	else
		rc_node_clear(&tx->re_node, 0);

	entity_release(ep);
	entity_release(tx);
	return (result);
}

/*ARGSUSED*/
static void
tx_commit(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg)
{
	struct rep_protocol_response *out = out_arg;
	const struct rep_protocol_transaction_commit *rpr = in;
	repcache_entity_t *tx;

	assert(*outsz == sizeof (*out));
	assert(insz >= REP_PROTOCOL_TRANSACTION_COMMIT_MIN_SIZE);

	if (rpr->rpr_size != insz) {
		out->rpr_response = REP_PROTOCOL_FAIL_BAD_REQUEST;
		return;
	}

	tx = entity_find(cp, rpr->rpr_entityid);

	if (tx == NULL) {
		out->rpr_response = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		return;
	}

	switch (tx->re_txstate) {
	case REPCACHE_TX_INIT:
		out->rpr_response = REP_PROTOCOL_FAIL_MISORDERED;
		break;

	case REPCACHE_TX_SETUP:
		out->rpr_response = rc_tx_commit(&tx->re_node, rpr->rpr_cmd,
		    insz - REP_PROTOCOL_TRANSACTION_COMMIT_MIN_SIZE);

		if (out->rpr_response == REP_PROTOCOL_SUCCESS) {
			tx->re_txstate = REPCACHE_TX_COMMITTED;
			rc_node_clear(&tx->re_node, 0);
		}

		break;
	case REPCACHE_TX_COMMITTED:
		out->rpr_response = REP_PROTOCOL_SUCCESS;
		break;
	default:
		assert(0);	/* CAN'T HAPPEN */
		break;
	}

	entity_release(tx);
}

static rep_protocol_responseid_t
next_snaplevel(repcache_client_t *cp, struct rep_protocol_entity_pair *rpr)
{
	repcache_entity_t *src;
	repcache_entity_t *dest;

	uint32_t srcid = rpr->rpr_entity_src;
	uint32_t destid = rpr->rpr_entity_dst;

	int result;

	result = entity_find2(cp, srcid, &src, destid, &dest);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	result = rc_node_next_snaplevel(&src->re_node, &dest->re_node);

	entity_release(src);
	entity_release(dest);

	return (result);
}

static rep_protocol_responseid_t
snapshot_take(repcache_client_t *cp, struct rep_protocol_snapshot_take *rpr)
{
	repcache_entity_t *src;
	uint32_t srcid = rpr->rpr_entityid_src;
	repcache_entity_t *dest;
	uint32_t destid = rpr->rpr_entityid_dest;

	int result;

	result = entity_find2(cp, srcid, &src, destid, &dest);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	if (dest->re_type != REP_PROTOCOL_ENTITY_SNAPSHOT) {
		result = REP_PROTOCOL_FAIL_TYPE_MISMATCH;
	} else {
		rpr->rpr_name[sizeof (rpr->rpr_name) - 1] = 0;

		if (rpr->rpr_flags == REP_SNAPSHOT_NEW)
			result = rc_snapshot_take_new(&src->re_node, NULL,
			    NULL, rpr->rpr_name, &dest->re_node);
		else if (rpr->rpr_flags == REP_SNAPSHOT_ATTACH &&
		    rpr->rpr_name[0] == 0)
			result = rc_snapshot_take_attach(&src->re_node,
			    &dest->re_node);
		else
			result = REP_PROTOCOL_FAIL_BAD_REQUEST;
	}
	entity_release(src);
	entity_release(dest);

	return (result);
}

static rep_protocol_responseid_t
snapshot_take_named(repcache_client_t *cp,
    struct rep_protocol_snapshot_take_named *rpr)
{
	repcache_entity_t *src;
	uint32_t srcid = rpr->rpr_entityid_src;
	repcache_entity_t *dest;
	uint32_t destid = rpr->rpr_entityid_dest;

	int result;

	result = entity_find2(cp, srcid, &src, destid, &dest);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	if (dest->re_type != REP_PROTOCOL_ENTITY_SNAPSHOT) {
		result = REP_PROTOCOL_FAIL_TYPE_MISMATCH;
	} else {
		rpr->rpr_svcname[sizeof (rpr->rpr_svcname) - 1] = 0;
		rpr->rpr_instname[sizeof (rpr->rpr_instname) - 1] = 0;
		rpr->rpr_name[sizeof (rpr->rpr_name) - 1] = 0;

		result = rc_snapshot_take_new(&src->re_node, rpr->rpr_svcname,
		    rpr->rpr_instname, rpr->rpr_name, &dest->re_node);
	}
	entity_release(src);
	entity_release(dest);

	return (result);
}

static rep_protocol_responseid_t
snapshot_attach(repcache_client_t *cp, struct rep_protocol_snapshot_attach *rpr)
{
	repcache_entity_t *src;
	uint32_t srcid = rpr->rpr_entityid_src;
	repcache_entity_t *dest;
	uint32_t destid = rpr->rpr_entityid_dest;

	int result;

	result = entity_find2(cp, srcid, &src, destid, &dest);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	result = rc_snapshot_attach(&src->re_node, &dest->re_node);

	entity_release(src);
	entity_release(dest);

	return (result);
}

/*ARGSUSED*/
static void
property_get_type(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg)
{
	const struct rep_protocol_property_request *rpr = in;
	struct rep_protocol_integer_response *out = out_arg;
	repcache_entity_t *ep;
	rep_protocol_value_type_t t = 0;

	assert(*outsz == sizeof (*out));

	ep = entity_find(cp, rpr->rpr_entityid);

	if (ep == NULL) {
		out->rpr_response = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		*outsz = sizeof (out->rpr_response);
		return;
	}

	out->rpr_response = rc_node_get_property_type(&ep->re_node, &t);

	entity_release(ep);

	if (out->rpr_response != REP_PROTOCOL_SUCCESS)
		*outsz = sizeof (out->rpr_response);
	else
		out->rpr_value = t;
}

/*
 * Fails with:
 *	_UNKNOWN_ID - an id does not designate an active register
 *	_NOT_SET - The property is not set
 *	_DELETED - The property has been deleted
 *	_TYPE_MISMATCH - The object is not a property
 *	_NOT_FOUND - The property has no values.
 *
 * Succeeds with:
 *	_SUCCESS - The property has 1 value.
 *	_TRUNCATED - The property has >1 value.
 */
/*ARGSUSED*/
static void
property_get_value(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg)
{
	const struct rep_protocol_property_request *rpr = in;
	struct rep_protocol_value_response *out = out_arg;
	repcache_entity_t *ep;

	assert(*outsz == sizeof (*out));

	ep = entity_find(cp, rpr->rpr_entityid);
	if (ep == NULL) {
		out->rpr_response = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		*outsz = sizeof (out->rpr_response);
		return;
	}

	out->rpr_response = rc_node_get_property_value(&ep->re_node, out,
	    outsz);

	entity_release(ep);

	/*
	 * If we fail, we only return the response code.
	 * If we succeed, rc_node_get_property_value has shortened *outsz
	 * to only include the value bytes needed.
	 */
	if (out->rpr_response != REP_PROTOCOL_SUCCESS &&
	    out->rpr_response != REP_PROTOCOL_FAIL_TRUNCATED)
		*outsz = sizeof (out->rpr_response);
}

static rep_protocol_responseid_t
propertygrp_notify(repcache_client_t *cp,
    struct rep_protocol_propertygrp_request *rpr, int *out_fd)
{
	int fds[2];
	int ours, theirs;

	rep_protocol_responseid_t result;
	repcache_entity_t *ep;

	if (pipe(fds) < 0)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	ours = fds[0];
	theirs = fds[1];

	if ((ep = entity_find(cp, rpr->rpr_entityid)) == NULL) {
		result = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		goto fail;
	}

	/*
	 * While the following can race with other threads setting up a
	 * notification, the worst that can happen is that our fd has
	 * already been closed before we return.
	 */
	result = rc_pg_notify_setup(&cp->rc_pg_notify, &ep->re_node,
	    ours);

	entity_release(ep);

	if (result != REP_PROTOCOL_SUCCESS)
		goto fail;

	*out_fd = theirs;
	return (REP_PROTOCOL_SUCCESS);

fail:
	(void) close(ours);
	(void) close(theirs);

	return (result);
}

static rep_protocol_responseid_t
client_add_notify(repcache_client_t *cp,
    struct rep_protocol_notify_request *rpr)
{
	rpr->rpr_pattern[sizeof (rpr->rpr_pattern) - 1] = 0;

	switch (rpr->rpr_type) {
	case REP_PROTOCOL_NOTIFY_PGNAME:
		return (rc_notify_info_add_name(&cp->rc_notify_info,
		    rpr->rpr_pattern));

	case REP_PROTOCOL_NOTIFY_PGTYPE:
		return (rc_notify_info_add_type(&cp->rc_notify_info,
		    rpr->rpr_pattern));

	default:
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);
	}
}

/*ARGSUSED*/
static void
client_wait(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg)
{
	int result;
	repcache_entity_t *ep;
	const struct rep_protocol_wait_request *rpr = in;
	struct rep_protocol_fmri_response *out = out_arg;

	assert(*outsz == sizeof (*out));

	(void) pthread_mutex_lock(&cp->rc_lock);
	if (cp->rc_notify_thr != 0) {
		(void) pthread_mutex_unlock(&cp->rc_lock);
		out->rpr_response = REP_PROTOCOL_FAIL_EXISTS;
		*outsz = sizeof (out->rpr_response);
		return;
	}
	cp->rc_notify_thr = pthread_self();
	(void) pthread_mutex_unlock(&cp->rc_lock);

	result = rc_notify_info_wait(&cp->rc_notify_info, &cp->rc_notify_ptr,
	    out->rpr_fmri, sizeof (out->rpr_fmri));

	if (result == REP_PROTOCOL_SUCCESS) {
		if ((ep = entity_find(cp, rpr->rpr_entityid)) != NULL) {
			if (ep->re_type == REP_PROTOCOL_ENTITY_PROPERTYGRP) {
				rc_node_ptr_assign(&ep->re_node,
				    &cp->rc_notify_ptr);
			} else {
				result = REP_PROTOCOL_FAIL_TYPE_MISMATCH;
			}
			entity_release(ep);
		} else {
			result = REP_PROTOCOL_FAIL_UNKNOWN_ID;
		}
		rc_node_clear(&cp->rc_notify_ptr, 0);
	}

	(void) pthread_mutex_lock(&cp->rc_lock);
	assert(cp->rc_notify_thr == pthread_self());
	cp->rc_notify_thr = 0;
	(void) pthread_mutex_unlock(&cp->rc_lock);

	out->rpr_response = result;
	if (result != REP_PROTOCOL_SUCCESS)
		*outsz = sizeof (out->rpr_response);
}

/*
 * Can return:
 *	_PERMISSION_DENIED	not enough privileges to do request.
 *	_BAD_REQUEST		name is not valid or reserved
 *	_TRUNCATED		name is too long for current repository path
 *	_UNKNOWN		failed for unknown reason (details written to
 *				console)
 *	_BACKEND_READONLY	backend is not writable
 *	_NO_RESOURCES		out of memory
 *	_SUCCESS		Backup completed successfully.
 */
static rep_protocol_responseid_t
backup_repository(repcache_client_t *cp,
    struct rep_protocol_backup_request *rpr)
{
	rep_protocol_responseid_t result;
	ucred_t *uc = get_ucred();

	if (!client_is_privileged() && (uc == NULL || ucred_geteuid(uc) != 0))
		return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);

	rpr->rpr_name[REP_PROTOCOL_NAME_LEN - 1] = 0;
	if (strcmp(rpr->rpr_name, REPOSITORY_BOOT_BACKUP) == 0)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	(void) pthread_mutex_lock(&cp->rc_lock);
	if (rpr->rpr_changeid != cp->rc_changeid) {
		result = backend_create_backup(rpr->rpr_name);
		if (result == REP_PROTOCOL_SUCCESS)
			cp->rc_changeid = rpr->rpr_changeid;
	} else {
		result = REP_PROTOCOL_SUCCESS;
	}
	(void) pthread_mutex_unlock(&cp->rc_lock);

	return (result);
}

/*
 * This function captures the information that will be used for an
 * annotation audit event.  Specifically, it captures the operation to be
 * performed and the name of the file that is being used.  These values are
 * copied from the rep_protocol_annotation request at rpr to the client
 * structure.  If both these values are null, the client is turning
 * annotation off.
 *
 * Fails with
 *	_NO_RESOURCES - unable to allocate memory
 */
static rep_protocol_responseid_t
set_annotation(repcache_client_t *cp, struct rep_protocol_annotation *rpr)
{
	au_id_t audit_uid;
	const char *file = NULL;
	const char *old_ptrs[2];
	const char *operation = NULL;
	rep_protocol_responseid_t rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
	au_asid_t sessionid;

	(void) memset((void *)old_ptrs, 0, sizeof (old_ptrs));

	/* Copy rpr_operation and rpr_file if they are not empty strings. */
	if (rpr->rpr_operation[0] != 0) {
		/*
		 * Make sure that client did not send us an unterminated buffer.
		 */
		rpr->rpr_operation[sizeof (rpr->rpr_operation) - 1] = 0;
		if ((operation = strdup(rpr->rpr_operation)) == NULL)
			goto out;
	}
	if (rpr->rpr_file[0] != 0) {
		/*
		 * Make sure that client did not send us an unterminated buffer.
		 */
		rpr->rpr_file[sizeof (rpr->rpr_file) - 1] = 0;
		if ((file = strdup(rpr->rpr_file)) == NULL)
			goto out;
	}

	(void) pthread_mutex_lock(&cp->rc_annotate_lock);
	/* Save addresses of memory to free when not locked */
	old_ptrs[0] = cp->rc_operation;
	old_ptrs[1] = cp->rc_file;

	/* Save pointers to annotation strings. */
	cp->rc_operation = operation;
	cp->rc_file = file;

	/*
	 * Set annotation flag.  Annotations should be turned on if either
	 * operation or file are not NULL.
	 */
	cp->rc_annotate = (operation != NULL) || (file != NULL);
	(void) pthread_mutex_unlock(&cp->rc_annotate_lock);

	/*
	 * operation and file pointers are saved in cp, so don't free them
	 * during cleanup.
	 */
	operation = NULL;
	file = NULL;
	rc = REP_PROTOCOL_SUCCESS;

	/*
	 * Native builds are done to create svc.configd-native.  This
	 * program runs only on the Open Solaris build machines to create
	 * the seed repository.  Until the SMF auditing code is distributed
	 * to the Open Solaris build machines, adt_get_unique_id() in the
	 * following code is not a global function in libbsm.  Hence the
	 * following conditional compilation.
	 */
#ifndef	NATIVE_BUILD
	/*
	 * Set the appropriate audit session id.
	 */
	if (cp->rc_annotate) {
		/*
		 * We're starting a group of annotated audit events, so
		 * create and set an audit session ID for this annotation.
		 */
		adt_get_auid(cp->rc_adt_session, &audit_uid);
		sessionid = adt_get_unique_id(audit_uid);
	} else {
		/*
		 * Annotation is done so restore our client audit session
		 * id.
		 */
		sessionid = cp->rc_adt_sessionid;
	}
	adt_set_asid(cp->rc_adt_session, sessionid);
#endif	/* NATIVE_BUILD */

out:
	if (operation != NULL)
		free((void *)operation);
	if (file != NULL)
		free((void *)file);
	free((void *)old_ptrs[0]);
	free((void *)old_ptrs[1]);
	return (rc);
}

/*
 * Determine if an annotation event needs to be generated.  If it does
 * provide the operation and file name that should be used in the event.
 *
 * Can return:
 *	0		No annotation event needed or buffers are not large
 *			enough.  Either way an event should not be
 *			generated.
 *	1		Generate annotation event.
 */
int
client_annotation_needed(char *operation, size_t oper_sz,
    char *file, size_t file_sz)
{
	thread_info_t *ti = thread_self();
	repcache_client_t *cp = ti->ti_active_client;
	int rc = 0;

	(void) pthread_mutex_lock(&cp->rc_annotate_lock);
	if (cp->rc_annotate) {
		rc = 1;
		if (cp->rc_operation == NULL) {
			if (oper_sz > 0)
				operation[0] = 0;
		} else {
			if (strlcpy(operation, cp->rc_operation, oper_sz) >=
			    oper_sz) {
				/* Buffer overflow, so do not generate event */
				rc = 0;
			}
		}
		if (cp->rc_file == NULL) {
			if (file_sz > 0)
				file[0] = 0;
		} else if (rc == 1) {
			if (strlcpy(file, cp->rc_file, file_sz) >= file_sz) {
				/* Buffer overflow, so do not generate event */
				rc = 0;
			}
		}
	}
	(void) pthread_mutex_unlock(&cp->rc_annotate_lock);
	return (rc);
}

void
client_annotation_finished()
{
	thread_info_t *ti = thread_self();
	repcache_client_t *cp = ti->ti_active_client;

	(void) pthread_mutex_lock(&cp->rc_annotate_lock);
	cp->rc_annotate = 0;
	(void) pthread_mutex_unlock(&cp->rc_annotate_lock);
}

#ifndef	NATIVE_BUILD
static void
start_audit_session(repcache_client_t *cp)
{
	ucred_t *cred = NULL;
	adt_session_data_t *session;

	/*
	 * A NULL session pointer value can legally be used in all
	 * subsequent calls to adt_* functions.
	 */
	cp->rc_adt_session = NULL;

	if (!adt_audit_state(AUC_AUDITING))
		return;

	if (door_ucred(&cred) != 0) {
		switch (errno) {
		case EAGAIN:
		case ENOMEM:
			syslog(LOG_ERR, gettext("start_audit_session(): cannot "
			    "get ucred.  %m\n"));
			return;
		case EINVAL:
			/*
			 * Door client went away.  This is a normal,
			 * although infrequent event, so there is no need
			 * to create a syslog message.
			 */
			return;
		case EFAULT:
		default:
			bad_error("door_ucred", errno);
			return;
		}
	}
	if (adt_start_session(&session, NULL, 0) != 0) {
		syslog(LOG_ERR, gettext("start_audit_session(): could not "
		    "start audit session.\n"));
		ucred_free(cred);
		return;
	}
	if (adt_set_from_ucred(session, cred, ADT_NEW) != 0) {
		syslog(LOG_ERR, gettext("start_audit_session(): cannot set "
		    "audit session data from ucred\n"));
		/* Something went wrong.  End the session. */
		(void) adt_end_session(session);
		ucred_free(cred);
		return;
	}

	/* All went well.  Save the session data and session ID */
	cp->rc_adt_session = session;
	adt_get_asid(session, &cp->rc_adt_sessionid);

	ucred_free(cred);
}
#endif

/*
 * Handle switch client request
 *
 * This routine can return:
 *
 *	_PERMISSION_DENIED	not enough privileges to do request.
 *	_UNKNOWN		file operation error (details written to
 *				the console).
 *	_SUCCESS		switch operation is completed.
 *	_BACKEND_ACCESS		backend access fails.
 *	_NO_RESOURCES		out of memory.
 *	_BACKEND_READONLY	backend is not writable.
 */
static rep_protocol_responseid_t
repository_switch(repcache_client_t *cp,
    struct rep_protocol_switch_request *rpr)
{
	rep_protocol_responseid_t result;
	ucred_t *uc = get_ucred();

	if (!client_is_privileged() && (uc == NULL ||
	    ucred_geteuid(uc) != 0)) {
		return (REP_PROTOCOL_FAIL_PERMISSION_DENIED);
	}

	(void) pthread_mutex_lock(&cp->rc_lock);
	if (rpr->rpr_changeid != cp->rc_changeid) {
		if ((result = backend_switch(rpr->rpr_flag)) ==
		    REP_PROTOCOL_SUCCESS)
			cp->rc_changeid = rpr->rpr_changeid;
	} else {
		result = REP_PROTOCOL_SUCCESS;
	}
	(void) pthread_mutex_unlock(&cp->rc_lock);

	return (result);
}

typedef rep_protocol_responseid_t protocol_simple_f(repcache_client_t *cp,
    const void *rpr);

/*ARGSUSED*/
static void
simple_handler(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg)
{
	protocol_simple_f *f = (protocol_simple_f *)arg;
	rep_protocol_response_t *out = out_arg;

	assert(*outsz == sizeof (*out));
	assert(f != NULL);

	out->rpr_response = (*f)(cp, in);
}

typedef rep_protocol_responseid_t protocol_simple_fd_f(repcache_client_t *cp,
    const void *rpr, int *out_fd);

/*ARGSUSED*/
static void
simple_fd_handler(repcache_client_t *cp, const void *in, size_t insz,
    void *out_arg, size_t *outsz, void *arg, int *out_fd)
{
	protocol_simple_fd_f *f = (protocol_simple_fd_f *)arg;
	rep_protocol_response_t *out = out_arg;

	assert(*outsz == sizeof (*out));
	assert(f != NULL);

	out->rpr_response = (*f)(cp, in, out_fd);
}

typedef void protocol_handler_f(repcache_client_t *, const void *in,
    size_t insz, void *out, size_t *outsz, void *arg);

typedef void protocol_handler_fdret_f(repcache_client_t *, const void *in,
    size_t insz, void *out, size_t *outsz, void *arg, int *fd_out);

#define	PROTO(p, f, in) {						\
		p, #p, simple_handler, (void *)(&f), NULL,		\
		    sizeof (in), sizeof (rep_protocol_response_t), 0	\
	}

#define	PROTO_FD_OUT(p, f, in) {					\
		p, #p, NULL, (void *)(&f), simple_fd_handler,		\
		    sizeof (in),					\
		    sizeof (rep_protocol_response_t),			\
		    PROTO_FLAG_RETFD					\
	}

#define	PROTO_VARIN(p, f, insz) {					\
		p, #p, &(f), NULL, NULL,				\
		    insz, sizeof (rep_protocol_response_t),		\
		    PROTO_FLAG_VARINPUT					\
	}

#define	PROTO_UINT_OUT(p, f, in) {					\
		p, #p, &(f), NULL, NULL,				\
		    sizeof (in),					\
		    sizeof (struct rep_protocol_integer_response), 0	\
	}

#define	PROTO_NAME_OUT(p, f, in) {					\
		p, #p, &(f), NULL, NULL,				\
		    sizeof (in),					\
		    sizeof (struct rep_protocol_name_response), 0	\
	}

#define	PROTO_FMRI_OUT(p, f, in) {					\
		p, #p, &(f), NULL, NULL,				\
		    sizeof (in),					\
		    sizeof (struct rep_protocol_fmri_response), 0	\
	}

#define	PROTO_VALUE_OUT(p, f, in) {					\
		p, #p, &(f), NULL, NULL,				\
		    sizeof (in),					\
		    sizeof (struct rep_protocol_value_response), 0	\
	}

#define	PROTO_PANIC(p)	{ p, #p, NULL, NULL, NULL, 0, 0, PROTO_FLAG_PANIC }
#define	PROTO_END()	{ 0, NULL, NULL, NULL, NULL, 0, 0, PROTO_FLAG_PANIC }

#define	PROTO_FLAG_PANIC	0x00000001	/* should never be called */
#define	PROTO_FLAG_VARINPUT	0x00000004	/* in_size is minimum size */
#define	PROTO_FLAG_RETFD	0x00000008	/* can also return an FD */

#define	PROTO_ALL_FLAGS		0x0000000f	/* all flags */

static struct protocol_entry {
	enum rep_protocol_requestid	pt_request;
	const char			*pt_name;
	protocol_handler_f		*pt_handler;
	void				*pt_arg;
	protocol_handler_fdret_f	*pt_fd_handler;
	size_t				pt_in_size;
	size_t				pt_out_max;
	uint32_t			pt_flags;
} protocol_table[] = {
	PROTO_PANIC(REP_PROTOCOL_CLOSE),		/* special case */

	PROTO(REP_PROTOCOL_ENTITY_SETUP,		entity_setup,
	    struct rep_protocol_entity_setup),
	PROTO_NAME_OUT(REP_PROTOCOL_ENTITY_NAME,	entity_name,
	    struct rep_protocol_entity_name),
	PROTO_UINT_OUT(REP_PROTOCOL_ENTITY_PARENT_TYPE,	entity_parent_type,
	    struct rep_protocol_entity_parent_type),
	PROTO(REP_PROTOCOL_ENTITY_GET_CHILD,		entity_get_child,
	    struct rep_protocol_entity_get_child),
	PROTO(REP_PROTOCOL_ENTITY_GET_PARENT,		entity_get_parent,
	    struct rep_protocol_entity_parent),
	PROTO(REP_PROTOCOL_ENTITY_GET,			entity_get,
	    struct rep_protocol_entity_get),
	PROTO(REP_PROTOCOL_ENTITY_UPDATE,		entity_update,
	    struct rep_protocol_entity_update),
	PROTO(REP_PROTOCOL_ENTITY_CREATE_CHILD,		entity_create_child,
	    struct rep_protocol_entity_create_child),
	PROTO(REP_PROTOCOL_ENTITY_CREATE_PG,		entity_create_pg,
	    struct rep_protocol_entity_create_pg),
	PROTO(REP_PROTOCOL_ENTITY_DELETE,		entity_delete,
	    struct rep_protocol_entity_delete),
	PROTO(REP_PROTOCOL_ENTITY_RESET,		entity_reset,
	    struct rep_protocol_entity_reset),
	PROTO(REP_PROTOCOL_ENTITY_TEARDOWN,		entity_teardown,
	    struct rep_protocol_entity_teardown),

	PROTO(REP_PROTOCOL_ITER_SETUP,			iter_setup,
	    struct rep_protocol_iter_request),
	PROTO(REP_PROTOCOL_ITER_START,			iter_start,
	    struct rep_protocol_iter_start),
	PROTO(REP_PROTOCOL_ITER_READ,			iter_read,
	    struct rep_protocol_iter_read),
	PROTO_VALUE_OUT(REP_PROTOCOL_ITER_READ_VALUE,	iter_read_value,
	    struct rep_protocol_iter_read_value),
	PROTO(REP_PROTOCOL_ITER_RESET,			iter_reset,
	    struct rep_protocol_iter_request),
	PROTO(REP_PROTOCOL_ITER_TEARDOWN,		iter_teardown,
	    struct rep_protocol_iter_request),

	PROTO(REP_PROTOCOL_NEXT_SNAPLEVEL,		next_snaplevel,
	    struct rep_protocol_entity_pair),

	PROTO(REP_PROTOCOL_SNAPSHOT_TAKE,		snapshot_take,
	    struct rep_protocol_snapshot_take),
	PROTO(REP_PROTOCOL_SNAPSHOT_TAKE_NAMED,		snapshot_take_named,
	    struct rep_protocol_snapshot_take_named),
	PROTO(REP_PROTOCOL_SNAPSHOT_ATTACH,		snapshot_attach,
	    struct rep_protocol_snapshot_attach),

	PROTO_UINT_OUT(REP_PROTOCOL_PROPERTY_GET_TYPE,	property_get_type,
	    struct rep_protocol_property_request),
	PROTO_VALUE_OUT(REP_PROTOCOL_PROPERTY_GET_VALUE, property_get_value,
	    struct rep_protocol_property_request),

	PROTO_FD_OUT(REP_PROTOCOL_PROPERTYGRP_SETUP_WAIT, propertygrp_notify,
	    struct rep_protocol_propertygrp_request),
	PROTO(REP_PROTOCOL_PROPERTYGRP_TX_START,	tx_start,
	    struct rep_protocol_transaction_start),
	PROTO_VARIN(REP_PROTOCOL_PROPERTYGRP_TX_COMMIT,	tx_commit,
	    REP_PROTOCOL_TRANSACTION_COMMIT_MIN_SIZE),

	PROTO(REP_PROTOCOL_CLIENT_ADD_NOTIFY,		client_add_notify,
	    struct rep_protocol_notify_request),
	PROTO_FMRI_OUT(REP_PROTOCOL_CLIENT_WAIT,	client_wait,
	    struct rep_protocol_wait_request),

	PROTO(REP_PROTOCOL_BACKUP,			backup_repository,
	    struct rep_protocol_backup_request),

	PROTO(REP_PROTOCOL_SET_AUDIT_ANNOTATION,	set_annotation,
	    struct rep_protocol_annotation),

	PROTO(REP_PROTOCOL_SWITCH,			repository_switch,
	    struct rep_protocol_switch_request),

	PROTO_END()
};
#undef PROTO
#undef PROTO_FMRI_OUT
#undef PROTO_NAME_OUT
#undef PROTO_UINT_OUT
#undef PROTO_PANIC
#undef PROTO_END

/*
 * The number of entries, sans PROTO_END()
 */
#define	PROTOCOL_ENTRIES \
	    (sizeof (protocol_table) / sizeof (*protocol_table) - 1)

#define	PROTOCOL_PREFIX "REP_PROTOCOL_"

int
client_init(void)
{
	int i;
	struct protocol_entry *e;

	if (!client_hash_init())
		return (0);

	if (request_log_size > 0) {
		request_log = uu_zalloc(request_log_size *
		    sizeof (request_log_entry_t));
	}

	/*
	 * update the names to not include REP_PROTOCOL_
	 */
	for (i = 0; i < PROTOCOL_ENTRIES; i++) {
		e = &protocol_table[i];
		assert(strncmp(e->pt_name, PROTOCOL_PREFIX,
		    strlen(PROTOCOL_PREFIX)) == 0);
		e->pt_name += strlen(PROTOCOL_PREFIX);
	}
	/*
	 * verify the protocol table is consistent
	 */
	for (i = 0; i < PROTOCOL_ENTRIES; i++) {
		e = &protocol_table[i];
		assert(e->pt_request == (REP_PROTOCOL_BASE + i));

		assert((e->pt_flags & ~PROTO_ALL_FLAGS) == 0);

		if (e->pt_flags & PROTO_FLAG_PANIC)
			assert(e->pt_in_size == 0 && e->pt_out_max == 0 &&
			    e->pt_handler == NULL);
		else
			assert(e->pt_in_size != 0 && e->pt_out_max != 0 &&
			    (e->pt_handler != NULL ||
			    e->pt_fd_handler != NULL));
	}
	assert((REP_PROTOCOL_BASE + i) == REP_PROTOCOL_MAX_REQUEST);

	assert(protocol_table[i].pt_request == 0);

	return (1);
}

static void
client_switcher(void *cookie, char *argp, size_t arg_size, door_desc_t *desc_in,
    uint_t n_desc)
{
	thread_info_t *ti = thread_self();

	repcache_client_t *cp;
	uint32_t id = (uint32_t)cookie;
	enum rep_protocol_requestid request_code;

	rep_protocol_responseid_t result = INVALID_RESULT;

	struct protocol_entry *e;

	char *retval = NULL;
	size_t retsize = 0;

	int retfd = -1;
	door_desc_t desc;
	request_log_entry_t *rlp;

	rlp = start_log(id);

	if (n_desc != 0)
		uu_die("can't happen: %d descriptors @%p (cookie %p)",
		    n_desc, desc_in, cookie);

	if (argp == DOOR_UNREF_DATA) {
		client_destroy(id);
		goto bad_end;
	}

	thread_newstate(ti, TI_CLIENT_CALL);

	/*
	 * To simplify returning just a result code, we set up for
	 * that case here.
	 */
	retval = (char *)&result;
	retsize = sizeof (result);

	if (arg_size < sizeof (request_code)) {
		result = REP_PROTOCOL_FAIL_BAD_REQUEST;
		goto end_unheld;
	}

	ti->ti_client_request = (void *)argp;

	/* LINTED alignment */
	request_code = *(uint32_t *)argp;

	if (rlp != NULL) {
		rlp->rl_request = request_code;
	}
	/*
	 * In order to avoid locking problems on removal, we handle the
	 * "close" case before doing a lookup.
	 */
	if (request_code == REP_PROTOCOL_CLOSE) {
		client_destroy(id);
		result = REP_PROTOCOL_SUCCESS;
		goto end_unheld;
	}

	cp = client_lookup(id);
	/*
	 * cp is held
	 */

	if (cp == NULL)
		goto bad_end;

	if (rlp != NULL)
		rlp->rl_client = cp;

	ti->ti_active_client = cp;

	if (request_code < REP_PROTOCOL_BASE ||
	    request_code >= REP_PROTOCOL_BASE + PROTOCOL_ENTRIES) {
		result = REP_PROTOCOL_FAIL_BAD_REQUEST;
		goto end;
	}

	e = &protocol_table[request_code - REP_PROTOCOL_BASE];

	assert(!(e->pt_flags & PROTO_FLAG_PANIC));

	if (e->pt_flags & PROTO_FLAG_VARINPUT) {
		if (arg_size < e->pt_in_size) {
			result = REP_PROTOCOL_FAIL_BAD_REQUEST;
			goto end;
		}
	} else if (arg_size != e->pt_in_size) {
		result = REP_PROTOCOL_FAIL_BAD_REQUEST;
		goto end;
	}

	if (retsize != e->pt_out_max) {
		retsize = e->pt_out_max;
		retval = alloca(retsize);
	}

	if (e->pt_flags & PROTO_FLAG_RETFD)
		e->pt_fd_handler(cp, argp, arg_size, retval, &retsize,
		    e->pt_arg, &retfd);
	else
		e->pt_handler(cp, argp, arg_size, retval, &retsize, e->pt_arg);

end:
	ti->ti_active_client = NULL;
	client_release(cp);

end_unheld:
	if (rlp != NULL) {
		/* LINTED alignment */
		rlp->rl_response = *(uint32_t *)retval;
		end_log();
		rlp = NULL;
	}
	ti->ti_client_request = NULL;
	thread_newstate(ti, TI_DOOR_RETURN);

	if (retval == (char *)&result) {
		assert(result != INVALID_RESULT && retsize == sizeof (result));
	} else {
		/* LINTED alignment */
		result = *(uint32_t *)retval;
	}
	if (retfd != -1) {
		desc.d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
		desc.d_data.d_desc.d_descriptor = retfd;
		(void) door_return(retval, retsize, &desc, 1);
	} else {
		(void) door_return(retval, retsize, NULL, 0);
	}
bad_end:
	if (rlp != NULL) {
		rlp->rl_response = -1;
		end_log();
		rlp = NULL;
	}
	(void) door_return(NULL, 0, NULL, 0);
}

int
create_client(pid_t pid, uint32_t debugflags, int privileged, int *out_fd)
{
	int fd;

	repcache_client_t *cp;

	struct door_info info;

	int door_flags = DOOR_UNREF | DOOR_REFUSE_DESC;
#ifdef DOOR_NO_CANCEL
	door_flags |= DOOR_NO_CANCEL;
#endif

	cp = client_alloc();
	if (cp == NULL)
		return (REPOSITORY_DOOR_FAIL_NO_RESOURCES);

	(void) pthread_mutex_lock(&client_lock);
	cp->rc_id = ++client_maxid;
	(void) pthread_mutex_unlock(&client_lock);

	cp->rc_all_auths = privileged;
	cp->rc_pid = pid;
	cp->rc_debug = debugflags;

#ifndef	NATIVE_BUILD
	start_audit_session(cp);
#endif

	cp->rc_doorfd = door_create(client_switcher, (void *)cp->rc_id,
	    door_flags);

	if (cp->rc_doorfd < 0) {
		client_free(cp);
		return (REPOSITORY_DOOR_FAIL_NO_RESOURCES);
	}
#ifdef DOOR_PARAM_DATA_MIN
	(void) door_setparam(cp->rc_doorfd, DOOR_PARAM_DATA_MIN,
	    sizeof (enum rep_protocol_requestid));
#endif

	if ((fd = dup(cp->rc_doorfd)) < 0 ||
	    door_info(cp->rc_doorfd, &info) < 0) {
		if (fd >= 0)
			(void) close(fd);
		(void) door_revoke(cp->rc_doorfd);
		cp->rc_doorfd = -1;
		client_free(cp);
		return (REPOSITORY_DOOR_FAIL_NO_RESOURCES);
	}

	rc_pg_notify_init(&cp->rc_pg_notify);
	rc_notify_info_init(&cp->rc_notify_info);

	client_insert(cp);

	cp->rc_doorid = info.di_uniquifier;
	*out_fd = fd;

	return (REPOSITORY_DOOR_SUCCESS);
}
