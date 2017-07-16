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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>

#include "isns_server.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_dsapi.h"
#include "isns_dseng.h"
#include "isns_msgq.h"
#include "isns_log.h"
#include "isns_scn.h"
#include "isns_esi.h"

/*
 * extern variables
 */
extern const int NUM_OF_CHILD[MAX_OBJ_TYPE];
extern const int TYPE_OF_PARENT[MAX_OBJ_TYPE_FOR_SIZE];

int
init_data(
)
{
	return (target_init_data());
}

int
load_data(
)
{
	int ec = 0;
	void *prev = NULL;
	isns_obj_t *obj;
	uint32_t uid = 0, type = 0;
	uint32_t puid = 0;
	isns_type_t ptype = 0;
	void const **child[MAX_CHILD_TYPE] = { NULL };
	uchar_t phase;

	isns_attr_t *scn_bitmap;
	isns_attr_t *scn_name;

	isns_attr_t *eid_attr;

	/* lock the cache */
	(void) cache_lock_write();

	ec = target_load_obj(&prev, &obj, &phase);
	while (ec == 0 && obj != NULL) {
		scn_bitmap = NULL;
		switch (obj->type) {
		case OBJ_DD:
		case OBJ_DDS:
			ptype = obj->type;
			ec = register_object(obj, &puid, NULL);
			break;
		case OBJ_ENTITY:
			ptype = OBJ_ENTITY;
			ec = register_object(obj, &puid, NULL);
			if (ec == 0) {
				eid_attr = &obj->attrs[
				    ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID)];
				ec = esi_load(puid,
				    eid_attr->value.ptr,
				    eid_attr->len);
			}
			break;
		case OBJ_ISCSI:
			scn_bitmap = &obj->attrs[ATTR_INDEX_ISCSI(
			    ISNS_ISCSI_SCN_BITMAP_ATTR_ID)];
			scn_name = &obj->attrs[ATTR_INDEX_ISCSI(
			    ISNS_ISCSI_NAME_ATTR_ID)];
			/* FALLTHROUGH */
		case OBJ_PORTAL:
			if (puid != 0 &&
			    TYPE_OF_PARENT[obj->type] == ptype) {
				(void) set_parent_obj(obj, puid);
				type = obj->type;
				ec = register_object(obj, &uid, NULL);
			} else {
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			if (ec == 0) {
				ec = buff_child_obj(ptype, type,
				    (void *)uid, child);
			}
			if (ec == 0 && scn_bitmap != NULL) {
				/* register scn */
				ec = scn_list_load(
				    uid,
				    scn_name->value.ptr,
				    scn_name->len,
				    scn_bitmap->value.ui);
			}
			break;
		case OBJ_PG:
			if (puid != 0 &&
			    TYPE_OF_PARENT[OBJ_PG] == ptype) {
				(void) set_parent_obj(obj, puid);
				ec = register_object(obj, NULL, NULL);
			} else {
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		case OBJ_ASSOC_ISCSI:
			if (puid != 0 &&
			    TYPE_OF_PARENT[OBJ_ASSOC_ISCSI] == ptype) {
				/* ignore adding member to default dd */
				/* during loading objects from data store */
				if (puid != ISNS_DEFAULT_DD_ID) {
					(void) set_parent_obj(obj, puid);
					ec = add_dd_member(obj);
				}
			} else {
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			free_object(obj);
			break;
		case OBJ_ASSOC_DD:
			if (puid != 0 &&
			    TYPE_OF_PARENT[OBJ_ASSOC_DD] == ptype) {
				/* ignore adding member to default dd-set */
				/* and adding default dd to any dd-set */
				/* during loading objects from data store */
				if (puid != ISNS_DEFAULT_DD_SET_ID &&
				    get_obj_uid(obj) != ISNS_DEFAULT_DD_ID) {
					(void) set_parent_obj(obj, puid);
					ec = add_dds_member(obj);
				}
			} else {
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			free_object(obj);
			break;
		default:
			ASSERT(0);
			ec = ISNS_RSP_INTERNAL_ERROR;
			break;
		}
		if (ec == 0) {
			ec = target_load_obj(&prev, &obj, &phase);
		}
		if (ec == 0 &&
		    puid != 0 &&
		    NUM_OF_CHILD[ptype] > 0 &&
		    (obj == NULL ||
		    TYPE_OF_PARENT[obj->type] != ptype)) {
			ec = update_child_obj(ptype, puid, child, 0);
		}
	}

	/* unlock the cache */
	(void) cache_unlock_sync(0);

	/* free the child buffer */
	uid = 0;
	while (uid < MAX_CHILD_TYPE) {
		if (child[uid] != NULL) {
			free(child[uid]);
		}
		uid ++;
	}

	return (ec);
}

int
write_data(
	int op,
	const isns_obj_t *obj
)
{
	int ec = 0;

	switch (op) {
		case DATA_ADD:
			ec = target_add_obj(obj);
			break;
		case DATA_UPDATE:
			ec = target_modify_obj(obj);
			break;
		case DATA_DELETE:
			ec = target_delete_obj(obj);
			break;
		case DATA_DELETE_ASSOC:
			ec = target_delete_assoc(obj);
			break;
		case DATA_COMMIT:
			ec = target_update_commit();
			break;
		case DATA_RETREAT:
			ec = target_update_retreat();
			break;
		default:
			break;
	}

	return (ec);
}
