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
 * Copyright 2019 Joyent, Inc.
 */

#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "zerror.h"
#include "ztree.h"


/*
 * ztree is just a helpful wrapper over a tsearch binary tree that deals with
 * all of the libzdoor types.
 *
 * So what this ztree actually is is a tree of trees.  The outer tree is a tree
 * of zones, and each node holds a tree of doors.
 */

/*
 * _ztree_compare(p1, p2) is the tsearch callback for comparing the "outer"
 * tree (e.g., the one of zones).
 */
static int
_ztree_compare(const void *p1, const void *p2)
{
	ztree_entry_t *z1 = (ztree_entry_t *)p1;
	ztree_entry_t *z2 = (ztree_entry_t *)p2;

	if (z1 == NULL && z2 == NULL)
		return (0);
	if (z1 == NULL && z2 != NULL)
		return (-1);
	if (z1 != NULL && z2 == NULL)
		return (1);

	return (strcmp(z1->zte_zonename, z2->zte_zonename));
}

/*
 * _dtree_compare(p1, p2) is the tsearch callback for comparing the "inner"
 * tree (e.g., the one of doors).
 */
static int
_dtree_compare(const void *p1, const void *p2)
{
	dtree_entry_t *d1 = (dtree_entry_t *)p1;
	dtree_entry_t *d2 = (dtree_entry_t *)p2;

	if (d1 == NULL && d2 == NULL)
		return (0);
	if (d1 == NULL && d2 != NULL)
		return (-1);
	if (d1 != NULL && d2 == NULL)
		return (1);

	return (strcmp(d1->dte_service, d2->dte_service));
}

static void
ztree_entry_free(ztree_entry_t *entry)
{
	if (entry == NULL)
		return;

	if (entry->zte_zonename != NULL)
		free(entry->zte_zonename);

	free(entry);
}

static void
dtree_entry_free(dtree_entry_t *entry)
{
	if (entry == NULL)
		return;

	if (entry->dte_service)
		free(entry->dte_service);

	free(entry);
}


/*
 * ztree_zone_add inserts a new zone into the tree iff
 * there is not already an entry for that zone.  This method returns one of
 * four possible return codes, ZTREE_SUCCESS on :), ZTREE_ARGUMENT_ERROR if
 * zone is NULL, ZTREE_ERROR if there is internal failure (e.g., OOM), and
 * ZTREE_ALREADY_EXISTS if the zone is already in the tree.
 */
int
ztree_zone_add(struct zdoor_handle *handle, const char *zonename,
    ztree_door_visitor visitor)
{
	ztree_entry_t *entry = NULL;
	void *ret = NULL;
	int status = ZTREE_SUCCESS;

	if (handle == NULL || zonename == NULL)
		return (ZTREE_ARGUMENT_ERROR);

	entry = (ztree_entry_t *)calloc(1, sizeof (ztree_entry_t));
	if (entry == NULL) {
		OUT_OF_MEMORY();
		return (ZTREE_ERROR);
	}
	entry->zte_zonename = strdup(zonename);
	if (entry->zte_zonename == NULL) {
		ztree_entry_free(entry);
		OUT_OF_MEMORY();
		return (ZTREE_ERROR);
	}
	entry->zte_action = ZDOOR_ACTION_NOOP;
	entry->zte_parent = handle;
	entry->zte_visitor = visitor;

	ret = tsearch(entry, &(handle->zdh_ztree), _ztree_compare);
	if (ret == NULL) {
		ztree_entry_free(entry);
		status = ZTREE_ERROR;
		OUT_OF_MEMORY();
	} else if ((*(ztree_entry_t **)ret) != entry) {
		ztree_entry_free(entry);
		status = ZTREE_ALREADY_EXISTS;
	}

	return (status);
}


/*
 * ztree_zone_find returns the entry in the "outer" tree representing
 * this zone, if it exists, NULL otherwise.
 */
ztree_entry_t *
ztree_zone_find(struct zdoor_handle *handle, const char *zonename)
{
	ztree_entry_t key = {0};
	void *ret = NULL;

	if (handle == NULL || zonename == NULL)
		return (NULL);

	key.zte_zonename = (char *)zonename;
	ret = tfind(&key, &(handle->zdh_ztree), _ztree_compare);

	return (ret != NULL ? *(ztree_entry_t **)ret : NULL);
}


/*
 * ztree_zone_remove removes an entry from the "outer" zone iff the
 * zone exists.  The cookie set by the creator is returned.
 */
void
ztree_zone_remove(struct zdoor_handle *handle, ztree_entry_t *entry)
{
	if (handle == NULL || entry == NULL)
		return;

	(void) tdelete(entry, &(handle->zdh_ztree), _ztree_compare);
	ztree_entry_free(entry);
}


/*
 * ztree_door_add inserts a new door into the inner tree iff
 * there is not already an entry for that door.  This method returns one of
 * four possible return codes, ZTREE_SUCCESS on :), ZTREE_ARGUMENT_ERROR if
 * zone is NULL, ZTREE_ERROR if there is internal failure (e.g., OOM), and
 * ZTREE_ALREADY_EXISTS if the door is already in the tree.
 */
int
ztree_door_add(struct zdoor_handle *handle, const char *zonename,
    const char *service, zdoor_callback callback, zdoor_cookie_t *cookie)
{
	dtree_entry_t *entry = NULL;
	ztree_entry_t *znode = NULL;
	void *ret = NULL;
	int status = ZTREE_SUCCESS;

	if (handle == NULL || zonename == NULL || service == NULL)
		return (ZTREE_ARGUMENT_ERROR);

	znode = ztree_zone_find(handle, zonename);
	if (znode == NULL)
		return (ZTREE_NOT_FOUND);

	entry = (dtree_entry_t *)calloc(1, sizeof (dtree_entry_t));
	if (entry == NULL) {
		OUT_OF_MEMORY();
		return (ZTREE_ERROR);
	}
	entry->dte_parent = znode;
	entry->dte_callback = callback;
	entry->dte_cookie = cookie;
	entry->dte_service = strdup(service);
	if (entry->dte_service == NULL) {
		free(entry);
		OUT_OF_MEMORY();
		return (ZTREE_ERROR);
	}

	ret = tsearch(entry, &(znode->zte_door_tree), _dtree_compare);
	if (ret == NULL) {
		dtree_entry_free(entry);
		OUT_OF_MEMORY();
		status = ZTREE_ERROR;
	} else if ((*(dtree_entry_t **)ret) != entry) {
		dtree_entry_free(entry);
		status = ZTREE_ALREADY_EXISTS;
	} else {
		znode->zte_num_doors++;
	}

	return (status);
}


/*
 * ztree_door_find returns the entry in the "inner" tree
 * representing this zone, if it exists, NULL otherwise.
 */
dtree_entry_t *
ztree_door_find(struct zdoor_handle *handle, const char *zonename,
    const char *service)
{
	dtree_entry_t key = {0};
	ztree_entry_t *znode = NULL;
	void *ret = NULL;

	if (handle == NULL || zonename == NULL || service == NULL)
		return (NULL);

	znode = ztree_zone_find(handle, zonename);
	if (znode == NULL)
		return (NULL);

	key.dte_service = (char *)service;
	ret = tfind(&key, &(znode->zte_door_tree), _dtree_compare);

	return (ret != NULL ? *(dtree_entry_t **)ret : NULL);
}


/*
 * ztree_door_remove(zone, door) removes a node from the inner tree iff
 * both the door and zone exist.  Note this frees the node as well. The
 * cookie set by the creator is returned.
 */
zdoor_cookie_t *
ztree_door_remove(struct zdoor_handle *handle, dtree_entry_t *entry)
{
	zdoor_cookie_t *cookie = NULL;
	ztree_entry_t *znode = NULL;

	if (handle == NULL || entry == NULL)
		return (NULL);

	znode = entry->dte_parent;
	cookie = entry->dte_cookie;

	(void) tdelete(entry, &(znode->zte_door_tree), _dtree_compare);
	dtree_entry_free(entry);

	znode->zte_num_doors--;
	if (znode->zte_num_doors == 0) {
		zdoor_debug("ztree: zone %s has no doors left, removing",
		    znode->zte_zonename);
		ztree_zone_remove(handle, znode);
	}

	return (cookie);
}


/*
 * _ztree_door_visitor(nodep, which, depth) is the private function we use
 * to wrap up tsearch's goofy API.  We're really just using this to ensure
 * zdoor doesn't get called > 1 times for a given entity in the ztree.
 */
static void
_ztree_door_visitor(const void *nodep, const VISIT which, const int depth)
{
	dtree_entry_t *entry = *(dtree_entry_t **)nodep;

	if (entry == NULL)
		return;

	switch (which) {
	case preorder:
	case endorder:
		break;
	case postorder:
	case leaf:
		if (entry->dte_parent->zte_visitor != NULL)
			entry->dte_parent->zte_visitor(entry);
		break;
	}
}


/*
 * ztree_walk_doors(zone) will proceed to visit every node in the "inner" tree
 * for this zone, and callback the visitor that was registered on tree creation.
 */
void
ztree_walk_doors(struct zdoor_handle *handle, const char *zonename)
{
	ztree_entry_t *znode = NULL;

	if (handle == NULL || zonename == NULL)
		return;

	znode = ztree_zone_find(handle, zonename);
	if (znode == NULL)
		return;

	twalk(znode->zte_door_tree, _ztree_door_visitor);
}
