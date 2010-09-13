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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <libuutil.h>
#include <errno.h>

#include "events.h"
#include "objects.h"
#include "util.h"

/*
 * objects.c - contains routines which manipulate object lists of NCUs,
 * locations, ENMs and known WLANs.
 */

typedef struct nwamd_object_list {
	nwam_object_type_t object_type;
	uu_list_t *object_list;
	nwamd_event_method_t *object_event_methods;
	pthread_rwlock_t object_list_lock;
} nwamd_object_list_t;

nwamd_event_method_t enm_event_methods[] =
{
	{ NWAM_EVENT_TYPE_OBJECT_INIT, nwamd_enm_handle_init_event },
	{ NWAM_EVENT_TYPE_OBJECT_FINI, nwamd_enm_handle_fini_event },
	{ NWAM_EVENT_TYPE_OBJECT_ACTION, nwamd_enm_handle_action_event },
	{ NWAM_EVENT_TYPE_OBJECT_STATE, nwamd_enm_handle_state_event },
	{ NWAM_EVENT_TYPE_NOOP, NULL }
};

nwamd_event_method_t loc_event_methods[] =
{
	{ NWAM_EVENT_TYPE_OBJECT_INIT, nwamd_loc_handle_init_event },
	{ NWAM_EVENT_TYPE_OBJECT_FINI, nwamd_loc_handle_fini_event },
	{ NWAM_EVENT_TYPE_OBJECT_ACTION, nwamd_loc_handle_action_event },
	{ NWAM_EVENT_TYPE_OBJECT_STATE, nwamd_loc_handle_state_event },
	{ NWAM_EVENT_TYPE_NOOP, NULL }
};

nwamd_event_method_t ncu_event_methods[] =
{
	{ NWAM_EVENT_TYPE_IF_STATE, nwamd_ncu_handle_if_state_event },
	{ NWAM_EVENT_TYPE_IF_ACTION, nwamd_ncu_handle_if_action_event },
	{ NWAM_EVENT_TYPE_LINK_STATE, nwamd_ncu_handle_link_state_event },
	{ NWAM_EVENT_TYPE_LINK_ACTION, nwamd_ncu_handle_link_action_event },
	{ NWAM_EVENT_TYPE_OBJECT_INIT, nwamd_ncu_handle_init_event },
	{ NWAM_EVENT_TYPE_OBJECT_FINI, nwamd_ncu_handle_fini_event },
	{ NWAM_EVENT_TYPE_OBJECT_ACTION, nwamd_ncu_handle_action_event },
	{ NWAM_EVENT_TYPE_OBJECT_STATE, nwamd_ncu_handle_state_event },
	{ NWAM_EVENT_TYPE_PERIODIC_SCAN, nwamd_ncu_handle_periodic_scan_event },
	{ NWAM_EVENT_TYPE_NOOP, NULL }
};

nwamd_event_method_t ncp_event_methods[] =
{
	{ NWAM_EVENT_TYPE_OBJECT_ACTION, nwamd_ncp_handle_action_event },
	{ NWAM_EVENT_TYPE_OBJECT_STATE, nwamd_ncp_handle_state_event },
	{ NWAM_EVENT_TYPE_UPGRADE, nwamd_handle_upgrade },
	{ NWAM_EVENT_TYPE_NOOP, NULL }
};

nwamd_event_method_t known_wlan_event_methods[] =
{
	{ NWAM_EVENT_TYPE_OBJECT_INIT, nwamd_known_wlan_handle_init_event },
	{ NWAM_EVENT_TYPE_OBJECT_FINI, NULL },
	{ NWAM_EVENT_TYPE_OBJECT_ACTION, nwamd_known_wlan_handle_action_event },
	{ NWAM_EVENT_TYPE_NOOP, NULL }
};

/* Should be kept in same order as object types */
nwamd_object_list_t object_lists[] = {
	{ NWAM_OBJECT_TYPE_NCP, NULL, ncp_event_methods,
	PTHREAD_RWLOCK_INITIALIZER },
	{ NWAM_OBJECT_TYPE_NCU, NULL, ncu_event_methods,
	PTHREAD_RWLOCK_INITIALIZER },
	{ NWAM_OBJECT_TYPE_LOC, NULL, loc_event_methods,
	PTHREAD_RWLOCK_INITIALIZER },
	{ NWAM_OBJECT_TYPE_ENM, NULL, enm_event_methods,
	PTHREAD_RWLOCK_INITIALIZER },
	{ NWAM_OBJECT_TYPE_KNOWN_WLAN, NULL, known_wlan_event_methods,
	PTHREAD_RWLOCK_INITIALIZER }
};

uu_list_pool_t *object_list_pool = NULL;

/*
 * Comparison function for objects, passed in as callback to
 * uu_list_pool_create().
 */
/* ARGSUSED */
static int
nwamd_object_compare(const void *l_arg, const void *r_arg, void *private)
{
	nwamd_object_t l = (nwamd_object_t)l_arg;
	nwamd_object_t r = (nwamd_object_t)r_arg;
	int rv;

	(void) pthread_mutex_lock(&l->nwamd_object_mutex);
	if (l != r)
		(void) pthread_mutex_lock(&r->nwamd_object_mutex);

	rv = strcmp(l->nwamd_object_name, r->nwamd_object_name);
	if (l != r)
		(void) pthread_mutex_unlock(&r->nwamd_object_mutex);
	(void) pthread_mutex_unlock(&l->nwamd_object_mutex);

	return (rv);
}

void
nwamd_object_lists_init(void)
{
	int i;

	object_list_pool = uu_list_pool_create("object_list_pool",
	    sizeof (struct nwamd_object),
	    offsetof(struct nwamd_object, nwamd_object_node),
	    nwamd_object_compare, UU_LIST_POOL_DEBUG);
	if (object_list_pool == NULL)
		pfail("uu_list_pool_create failed with error %d", uu_error());

	for (i = 0;
	    i < sizeof (object_lists) / sizeof (struct nwamd_object_list);
	    i++) {
		object_lists[i].object_list = uu_list_create(object_list_pool,
		    NULL, 0);
		if (object_lists[i].object_list == NULL)
			pfail("uu_list_create failed with error %d",
			    uu_error());
	}
}

void
nwamd_object_lists_fini(void)
{
	int i;
	nwamd_object_t object;
	void *cookie = NULL;

	for (i = 0;
	    i < sizeof (object_lists) / sizeof (struct nwamd_object_list);
	    i++) {
		while ((object = uu_list_teardown(object_lists[i].object_list,
		    &cookie)) != NULL) {
			free(object);
		}
		uu_list_destroy(object_lists[i].object_list);
	}
	if (object_list_pool != NULL)
		uu_list_pool_destroy(object_list_pool);
}

static nwamd_object_list_t *
nwamd_get_object_list(nwam_object_type_t type)
{
	assert(type < sizeof (object_lists) / sizeof (object_lists[0]));
	return (&object_lists[type]);
}

static int
nwamd_object_list_lock(nwam_object_type_t type)
{
	nwamd_object_list_t *object_list = nwamd_get_object_list(type);

	(void) pthread_rwlock_wrlock(&object_list->object_list_lock);
	return (0);
}

static int
nwamd_object_list_rlock(nwam_object_type_t type)
{
	nwamd_object_list_t *object_list = nwamd_get_object_list(type);

	if (pthread_rwlock_rdlock(&object_list->object_list_lock) == -1) {
		nlog(LOG_ERR, "cannot get lock for object list: %s",
		    strerror(errno));
		return (-1);
	}
	return (0);
}

static void
nwamd_object_list_unlock(nwam_object_type_t type)
{
	nwamd_object_list_t *object_list = nwamd_get_object_list(type);

	(void) pthread_rwlock_unlock(&object_list->object_list_lock);
}

/*
 * Initialize object and return it in locked state.
 */
nwamd_object_t
nwamd_object_init(nwam_object_type_t type, const char *name, void *handle,
    void *data)
{
	nwamd_object_t object;
	struct nwamd_object_list *object_list = nwamd_get_object_list(type);

	object = calloc(1, sizeof (struct nwamd_object));
	if (object == NULL)
		return (NULL);

	(void) strlcpy(object->nwamd_object_name, name, NWAM_MAX_NAME_LEN);

	/* 1 for the list and 1 for the returned object */
	object->nwamd_object_refcount = 2;
	object->nwamd_object_handle = handle;
	object->nwamd_object_data = data;
	object->nwamd_object_type = type;
	object->nwamd_object_state = NWAM_STATE_INITIALIZED;
	object->nwamd_object_aux_state = NWAM_AUX_STATE_INITIALIZED;

	/* Add object to appropriate object list */
	if (nwamd_object_list_lock(type) != 0) {
		nlog(LOG_ERR, "nwamd_object_init: could not lock list to init "
		    "object %s", name);
		free(object);
		return (NULL);
	}

	if (pthread_mutex_init(&object->nwamd_object_mutex, NULL) == -1) {
		nlog(LOG_ERR, "pthread_mutex_init failed: %s",
		    strerror(errno));
		free(object);
		nwamd_object_list_unlock(type);
		return (NULL);
	}
	(void) pthread_mutex_lock(&object->nwamd_object_mutex);

	uu_list_node_init(object, &object->nwamd_object_node, object_list_pool);
	(void) uu_list_insert_after(object_list->object_list,
	    uu_list_last(object_list->object_list), object);

	nwamd_object_list_unlock(type);

	return (object);
}

/*
 * Find object in object list, returning it holding a lock and with the
 * reference count incremented.  The opposite function to this is
 * nwamd_object_release().
 */
nwamd_object_t
nwamd_object_find(nwam_object_type_t type, const char *name)
{
	nwamd_object_t object;
	struct nwamd_object_list *object_list = nwamd_get_object_list(type);

	assert(name != NULL);

	if (nwamd_object_list_rlock(type) != 0)
		return (NULL);

	for (object = uu_list_first(object_list->object_list);
	    object != NULL;
	    object = uu_list_next(object_list->object_list, object)) {
		if (strcmp(object->nwamd_object_name, name) == 0)
			break;
	}
	if (object != NULL) {
		(void) pthread_mutex_lock(&object->nwamd_object_mutex);
		object->nwamd_object_refcount++;
	}
	nwamd_object_list_unlock(type);

	return (object);
}

/* Removes object from list, destroy mutex, and free storage. */
static void
nwamd_object_fini(nwamd_object_t object, nwam_object_type_t objtype)
{
	nwamd_object_t o;
	struct nwamd_object_list *object_list;

	assert(object != NULL);

	object_list = nwamd_get_object_list(objtype);

	for (o = uu_list_first(object_list->object_list);
	    o != NULL;
	    o = uu_list_next(object_list->object_list, o)) {
		if (o == object) {
			uu_list_remove(object_list->object_list, object);
			(void) pthread_mutex_unlock(
			    &object->nwamd_object_mutex);
			(void) pthread_mutex_destroy(
			    &object->nwamd_object_mutex);
			uu_list_node_fini(object, &object->nwamd_object_node,
			    object_list_pool);
			switch (objtype) {
			case NWAM_OBJECT_TYPE_NCU:
				nwamd_ncu_free(object->nwamd_object_data);
				nwam_ncu_free(object->nwamd_object_handle);
				break;
			case NWAM_OBJECT_TYPE_LOC:
				nwam_loc_free(object->nwamd_object_handle);
				break;
			case NWAM_OBJECT_TYPE_ENM:
				nwam_enm_free(object->nwamd_object_handle);
				break;
			default:
				nlog(LOG_ERR, "nwamd_object_fini: "
				    "got unexpected object type %d", objtype);
				break;
			}
			free(object);
			break;
		}
	}
}

static void
nwamd_object_decref(nwamd_object_t object, int num)
{
	nwam_object_type_t objtype;

	assert(object->nwamd_object_refcount >= num);
	object->nwamd_object_refcount -= num;
	if (object->nwamd_object_refcount == 0) {
		/*
		 * We need to maintain the locking hierarchy of owning the
		 * list lock before we get the object lock when we are
		 * destroying the object.  If we merely release and then
		 * reacquire in the right order we might not find the right
		 * object.  Instead we bump the ref count so that it can't
		 * be destroyed, we drop the object lock, we acquire the
		 * list lock, we acquire the object lock, decrement the ref
		 * count, check to make sure we are really destroying it and
		 * somebody else hasn't gotten it, and then, if its unref'd,
		 * destroying it.
		 */
		object->nwamd_object_refcount++;
		objtype = object->nwamd_object_type;
		(void) pthread_mutex_unlock(&object->nwamd_object_mutex);
		(void) nwamd_object_list_lock(objtype);
		(void) pthread_mutex_lock(&object->nwamd_object_mutex);
		if (--object->nwamd_object_refcount != 0)
			(void) pthread_mutex_unlock(
			    &object->nwamd_object_mutex);
		else
			nwamd_object_fini(object, objtype);
		nwamd_object_list_unlock(objtype);
	} else {
		(void) pthread_mutex_unlock(&object->nwamd_object_mutex);
	}
}

/*
 * Drop mutex without decreasing reference count.  Used where we wish to
 * let go of an object but ensure it will not go away.
 */
void
nwamd_object_release_and_preserve(nwamd_object_t object)
{
	(void) pthread_mutex_unlock(&object->nwamd_object_mutex);
}

void
nwamd_object_release(nwamd_object_t object)
{
	nwamd_object_decref(object, 1);
}

void
nwamd_object_release_and_destroy(nwamd_object_t object)
{
	nwamd_object_decref(object, 2);
}

void
nwamd_object_release_and_destroy_after_preserve(nwamd_object_t object)
{
	nwamd_object_decref(object, 3);
}

void
nwamd_object_release_after_preserve(nwamd_object_t object)
{
	nwamd_object_decref(object, 2);
}

void
nwamd_object_set_state_timed(nwam_object_type_t type, const char *name,
    nwam_state_t state, nwam_aux_state_t aux_state, uint32_t when)
{
	nwamd_event_t event = nwamd_event_init_object_state(type, name,
	    state, aux_state);

	nlog(LOG_INFO, "nwamd_object_set_state: state event (%s, %s) for %s",
	    nwam_state_to_string(state),
	    nwam_aux_state_to_string(aux_state), name);
	if (event != NULL)
		nwamd_event_enqueue_timed(event, when);
}

void
nwamd_object_set_state(nwam_object_type_t type, const char *name,
    nwam_state_t state, nwam_aux_state_t aux_state)
{
	nwamd_object_set_state_timed(type, name, state, aux_state, 0);
}

nwamd_event_method_t *
nwamd_object_event_methods(nwam_object_type_t type)
{
	struct nwamd_object_list *object_list = nwamd_get_object_list(type);

	return (object_list->object_event_methods);
}

/*
 * Walk all objects of specified type calling callback function cb.
 * Object is locked for duration of callback.
 */
int
nwamd_walk_objects(nwam_object_type_t type, int (*cb)(nwamd_object_t, void *),
    void *data)
{
	nwamd_object_t object;
	struct nwamd_object_list *object_list = nwamd_get_object_list(type);
	int ret = 0;

	if (nwamd_object_list_rlock(type) != 0)
		return (-1);

	for (object = uu_list_first(object_list->object_list);
	    object != NULL;
	    object = uu_list_next(object_list->object_list, object)) {
		(void) pthread_mutex_lock(&object->nwamd_object_mutex);
		ret = cb(object, data);
		(void) pthread_mutex_unlock(&object->nwamd_object_mutex);
		if (ret != 0) {
			nwamd_object_list_unlock(type);
			return (ret);
		}
	}
	nwamd_object_list_unlock(type);

	return (0);
}
