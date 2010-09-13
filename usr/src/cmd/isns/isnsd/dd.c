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
#include <string.h>

#include "isns_server.h"
#include "isns_msgq.h"
#include "isns_htab.h"
#include "isns_dd.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_pdu.h"
#include "isns_dseng.h"
#include "isns_scn.h"
#include "isns_utils.h"

/*
 * extern global variables
 */
extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];

extern msg_queue_t *sys_q;
extern msg_queue_t *scn_q;

extern int cache_flag;

/*
 * extern functions.
 */

/*
 * global variables
 */

/*
 * local variables
 */

/*
 * local functions.
 */
static matrix_t *new_matrix(uint32_t, uint32_t);

static int
cb_update_ds_attr(
	void *p1,
	void *p2
)
{
	int ec = 0;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	uint32_t tag = lcp->id[1];
	uint32_t which;
	isns_attr_t *attr;

	uint32_t len;
	uchar_t *name;
	lookup_ctrl_t lc;
	uint32_t uid;

	switch (tag) {
	case ISNS_DD_NAME_ATTR_ID:
		which = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
		break;
	case ISNS_DD_FEATURES_ATTR_ID:
		which = ATTR_INDEX_DD(ISNS_DD_FEATURES_ATTR_ID);
		break;
	case ISNS_DD_SET_NAME_ATTR_ID:
		which = ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID);
		break;
	case ISNS_DD_SET_STATUS_ATTR_ID:
		which = ATTR_INDEX_DDS(ISNS_DD_SET_STATUS_ATTR_ID);
		break;
	default:
		ASSERT(0);
		break;
	}

	attr = &obj->attrs[which];

	switch (tag) {
	case ISNS_DD_NAME_ATTR_ID:
	case ISNS_DD_SET_NAME_ATTR_ID:
		len = lcp->data[1].ui;
		name = lcp->data[2].ptr;
		lc.type = lcp->type;
		lc.curr_uid = 0;
		lc.id[0] = which;
		lc.op[0] = OP_STRING;
		lc.data[0].ptr = name;
		lc.op[1] = 0;
		/* check if the name is in use */
		uid = is_obj_there(&lc);
		if (uid != 0) {
			if (uid != get_obj_uid(obj)) {
				ec = ERR_NAME_IN_USE;
			}
			return (ec);
		}
		if (len > attr->len) {
			uchar_t *tmp = (uchar_t *)malloc(len);
			if (tmp != NULL) {
				free(attr->value.ptr);
				attr->value.ptr = tmp;
			} else {
				/* memory exhausted */
				return (ISNS_RSP_INTERNAL_ERROR);
			}
		}
		(void) strcpy((char *)attr->value.ptr, (char *)name);
		attr->len = len;
		break;
	case ISNS_DD_FEATURES_ATTR_ID:
	case ISNS_DD_SET_STATUS_ATTR_ID:
		if (attr->tag != tag ||
		    attr->value.ui != lcp->data[1].ui) {
			attr->tag = tag;
			attr->len = 4;
			attr->value.ui = lcp->data[1].ui;
		} else {
			return (ec);
		}
		break;
	}

	/* cache has been updated, set the flag */
	SET_CACHE_UPDATED();

	/* update data store */
	if (sys_q != NULL) {
		ec = write_data(DATA_UPDATE, obj);
	}

	return (ec);
}

static isns_obj_t *
make_member_node(
	const uint32_t uid,
	isns_attr_t *attr1
)
{
	isns_obj_t *obj = NULL;
	isns_attr_t *attr;
	isns_attr_t tmp;

	switch (attr1->tag) {
	case ISNS_DD_ISCSI_NAME_ATTR_ID:
		obj = obj_calloc(OBJ_ISCSI);
		attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)];
		tmp.tag = ISNS_ISCSI_NAME_ATTR_ID;
		tmp.len = attr1->len;
		tmp.value.ptr = attr1->value.ptr;
		if (assign_attr(attr, &tmp) != 0) {
			free_object(obj);
			obj = NULL;
		} else if (uid != 0) {
			(void) set_obj_uid(obj, uid);
		}
		break;
	default:
		ASSERT(0);
		break;
	}

	return (obj);
}

static isns_obj_t *
make_member_dd(
	const uint32_t uid
)
{
	isns_obj_t *obj = NULL;
	isns_attr_t name = { 0 };

	obj = obj_calloc(OBJ_DD);
	if (obj != NULL) {
		(void) set_obj_uid(obj, uid);
		name.tag = ISNS_DD_NAME_ATTR_ID;
		if (assign_attr(
		    &obj->attrs[ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID)],
		    &name) != 0) {
			free_object(obj);
			obj = NULL;
		}
	}

	return (obj);
}

static int
get_member_info(
	isns_obj_t *assoc,
	uint32_t *m_type,
	uint32_t *m_id,
	int flag
)
{
	int ec = 0;
	lookup_ctrl_t lc = { 0 };

	isns_obj_t *obj;
	isns_attr_t *attr1, *attr2;
	uint32_t tmp_id = 0;
	int i = 0;

	*m_type = 0;
	*m_id = 0;

	attr1 = &assoc->attrs[ATTR_INDEX_ASSOC_ISCSI(
	    ISNS_DD_ISCSI_INDEX_ATTR_ID)];
	attr2 = &assoc->attrs[ATTR_INDEX_ASSOC_ISCSI(
	    ISNS_DD_ISCSI_NAME_ATTR_ID)];

	lc.type = OBJ_ISCSI;
	if (attr1->tag != 0 && attr1->value.ui != 0) {
		*m_id = attr1->value.ui;
		lc.id[i] = UID_ATTR_INDEX[OBJ_ISCSI];
		lc.op[i] = OP_INTEGER;
		lc.data[i].ui = *m_id;
		i ++;
	}
	if (attr2->tag != 0) {
		lc.id[i] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
		lc.op[i] = OP_STRING;
		lc.data[i].ptr = attr2->value.ptr;
		i ++;
	} else if (scn_q != NULL || sys_q != NULL) {
		lc.id[i] = ISNS_ISCSI_NAME_ATTR_ID;
	}

	/* a member id or member name is required */
	if (i == 0) {
		if (flag != 0) {
			/* add member */
			return (ISNS_RSP_INVALID_REGIS);
		} else {
			/* remove member (isnsp msg request only) */
			return (0);
		}
	}

	ec = cache_lookup(&lc, &tmp_id, cb_clone_attrs);

	if (ec == 0 && tmp_id == 0) {
		if (flag != 0) {
			/* add member */
			if (attr1->tag == 0 || sys_q == NULL) {
				/* object does not exist, create one */
				obj = make_member_node(*m_id, attr2);
				if (obj == NULL) {
					ec = ISNS_RSP_INTERNAL_ERROR;
				} else {
					ec = register_assoc(obj, &tmp_id);
					if (ec != 0) {
						free_object(obj);
					}
				}
			} else {
				/* don't create it if uid is specified */
				ec = ISNS_RSP_NO_SUCH_ENTRY;
			}
		} else {
			/* remove member */
			ec = ERR_NO_SUCH_ASSOCIATION;
		}
	}

	if (attr1->tag == 0) {
		attr1->tag = ISNS_DD_ISCSI_INDEX_ATTR_ID;
		attr1->len = 4;
		attr1->value.ui = tmp_id;
	} else if (attr2->tag == 0) {
		attr2->tag = ISNS_DD_ISCSI_NAME_ATTR_ID;
		attr2->len = strlen((char *)lc.data[1].ptr);
		attr2->len += 4 - (attr2->len % 4);
		attr2->value.ptr = lc.data[1].ptr;
	}

	*m_type = OBJ_ISCSI;
	*m_id = tmp_id;

	return (ec);
}

static int
get_dds_member_info(
	uint32_t m_id
)
{
	int ec = 0;
	lookup_ctrl_t lc;

	isns_obj_t *obj;
	uint32_t tmp_id;

	if (m_id != 0) {
		SET_UID_LCP(&lc, OBJ_DD, m_id);
	} else {
		return (ISNS_RSP_INVALID_REGIS);
	}

	tmp_id = is_obj_there(&lc);

	if (tmp_id == 0) {
		/* object does not exist, create one */
		obj = make_member_dd(m_id);
		if (obj != NULL) {
			ec = register_object(obj, NULL, NULL);
		} else {
			/* no memory */
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	}

	return (ec);
}

static int
update_matrix(
	matrix_t *matrix,
	const uchar_t op,
	const uint32_t puid,
	const uint32_t m_id,
	int ddd_flag
)
{
	int ec = 0;

	uint32_t new_x = 0, new_y = 0;
	matrix_t *tmp_matrix;

	uint32_t i, j, k = 0;
	uint32_t x_info;
	bmp_t *bmp, *tmp_bmp;

	uint32_t primary = GET_PRIMARY(m_id);
	uint32_t second = GET_SECOND(m_id);

	if (primary >= matrix->x) {
		if (op == '-') {
			ec = ERR_NO_SUCH_ASSOCIATION;
			goto update_matrix_done;
		}
		/* enlarge the matrix on x axis */
		if (primary >= matrix->x * 2) {
			new_x = primary + 1;
		} else {
			new_x = matrix->x * 2;
		}
	}

	i = 0;
	while (i < matrix->y) {
		bmp = MATRIX_X_UNIT(matrix, i);
		x_info = MATRIX_X_INFO(bmp);
		if (x_info == puid) {
			break;
		} else if (x_info == 0 && k == 0) {
			/* the first available slot */
			k = i;
		}
		i ++;
	}
	if (i == matrix->y) {
		if (op == '-') {
			ec = ERR_NO_SUCH_ASSOCIATION;
			goto update_matrix_done;
		} else if (k == 0) {
			new_y = matrix->y * 2;
		} else {
			i = k;
		}
	}

	/*
	 * enlarge the matrix.
	 */
	if (new_x != 0 || new_y != 0) {
		if (new_x == 0) {
			new_x = matrix->x;
		}
		if (new_y == 0) {
			new_y = matrix->y;
		}
		tmp_matrix = new_matrix(new_x, new_y);
		if (tmp_matrix != NULL) {
			j = 0;
			while (j < matrix->y) {
				bmp = MATRIX_X_UNIT(matrix, j);
				x_info = MATRIX_X_INFO(bmp);
				if (x_info != 0) {
					tmp_bmp = MATRIX_X_UNIT(tmp_matrix, j);
					(void) memcpy((void *)tmp_bmp,
					    (void *)bmp, SIZEOF_X_UNIT(matrix));
				}
				j ++;
			}
			free(matrix->m);
			matrix->x = tmp_matrix->x;
			matrix->y = tmp_matrix->y;
			matrix->m = tmp_matrix->m;
			free(tmp_matrix);
		} else {
			ec = ISNS_RSP_INTERNAL_ERROR;
			goto update_matrix_done;
		}
	}

	bmp = MATRIX_X_UNIT(matrix, i);

	MATRIX_X_INFO(bmp) = puid;
	if (op == '+') {
		if (TEST_MEMBERSHIP(bmp, primary, second) == 0) {
			SET_MEMBERSHIP(bmp, primary, second);
			SET_CACHE_UPDATED();
			if (ddd_flag != 0) {
				bmp = MATRIX_X_UNIT(matrix, 0);
				ASSERT(MATRIX_X_INFO(bmp) ==
				    ISNS_DEFAULT_DD_ID);
				CLEAR_MEMBERSHIP(bmp, primary, second);
			}
		} else {
			ec = ERR_ALREADY_ASSOCIATED;
		}
	} else if (op == '-') {
		if (TEST_MEMBERSHIP(bmp, primary, second) != 0) {
			CLEAR_MEMBERSHIP(bmp, primary, second);
			SET_CACHE_UPDATED();
			if (ddd_flag != 0) {
				i = 1;
				while (i < matrix->y) {
					bmp = MATRIX_X_UNIT(matrix, i);
					x_info = MATRIX_X_INFO(bmp);
					if (x_info != 0 &&
					    TEST_MEMBERSHIP(bmp,
					    primary, second) != 0) {
						break;
					}
					i ++;
				}
				if (i == matrix->y) {
					bmp = MATRIX_X_UNIT(matrix, 0);
					ASSERT(MATRIX_X_INFO(bmp) ==
					    ISNS_DEFAULT_DD_ID);
					SET_MEMBERSHIP(bmp, primary, second);
				}
			}
		} else {
			ec = ERR_NO_SUCH_ASSOCIATION;
		}
	}

update_matrix_done:
	return (ec);
}

/*ARGSUSED*/
static int
update_dd_matrix(
	const uchar_t op,
	const uint32_t dd_id,
	const uint32_t m_type,
	const uint32_t m_id
)
{
	matrix_t *matrix;

	ASSERT(m_type == OBJ_ISCSI);

	matrix = cache_get_matrix(OBJ_DD);

	return (update_matrix(matrix, op, dd_id, m_id, 1));
}

static int
update_dds_matrix(
	const uchar_t op,
	const uint32_t dds_id,
	const uint32_t m_id
)
{
	matrix_t *dds_matrix = cache_get_matrix(OBJ_DDS);

	return (update_matrix(dds_matrix, op, dds_id, m_id, 0));
}

static int
clear_matrix(
	matrix_t *matrix,
	const uint32_t uid,
	bmp_t **p,
	uint32_t *n,
	int ddd_flag
)
{
	int ec = 0;
	bmp_t *bmp;
	uint32_t x_info;
	int i, j;

	uint32_t primary;
	uint32_t second;

	if (p != NULL) {
		*p = NULL;
		*n = 0;
	}

	i = 0;
	while (i < matrix->y) {
		bmp = MATRIX_X_UNIT(matrix, i);
		x_info = MATRIX_X_INFO(bmp);
		if (x_info == uid) {
			if (p != NULL) {
				/* dup it for caller */
				*n = matrix->x;
				*p = (bmp_t *)malloc(*n * sizeof (bmp_t));
				if (*p != NULL) {
					(void) memcpy(*p, &bmp[MATRIX_X_HEADER],
					    *n * sizeof (bmp_t));
				} else {
					ec = ISNS_RSP_INTERNAL_ERROR;
				}
			}
			/* clean it */
			(void) memset(bmp, 0, SIZEOF_X_UNIT(matrix));
			break;
		}
		i ++;
	}

	if (ddd_flag != 0 && p != NULL) {
		bmp = MATRIX_X_UNIT(matrix, 0);
		ASSERT(MATRIX_X_INFO(bmp) == ISNS_DEFAULT_DD_ID);
		/* Test the membership for each node which is a */
		/* member in the dd that is being deleted. */
		FOR_EACH_MEMBER(*p, *n, i, {
			j = get_dd_id(i, 0);
			if (j == 0) {
				/* put it to the default dd */
				primary = GET_PRIMARY(i);
				second = GET_SECOND(i);
				SET_MEMBERSHIP(bmp, primary, second);
			}
		});
	}

	return (ec);
}

static int
get_matrix(
	matrix_t *matrix,
	const uint32_t uid,
	bmp_t **p,
	uint32_t *n
)
{
	int ec = 0;
	bmp_t *bmp;
	uint32_t x_info;
	int i;

	*n = 0;
	*p = NULL;

	i = 0;
	while (i < matrix->y) {
		bmp = MATRIX_X_UNIT(matrix, i);
		x_info = MATRIX_X_INFO(bmp);
		if (x_info == uid) {
			/* dup it for caller */
			*n = matrix->x;
			*p = (bmp_t *)malloc(*n * sizeof (bmp_t));
			if (*p != NULL) {
				(void) memcpy(*p, &bmp[MATRIX_X_HEADER],
				    *n * sizeof (bmp_t));
			} else {
				*n = 0;
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		}
		i ++;
	}

	return (ec);
}

static int
clear_dd_matrix(
	const uint32_t dd_id,
	bmp_t **p,
	uint32_t *n
)
{
	matrix_t *matrix = cache_get_matrix(OBJ_DD);

	return (clear_matrix(matrix, dd_id, p, n, 1));
}

static int
clear_dds_matrix(
	const uint32_t dds_id
)
{
	matrix_t *matrix = cache_get_matrix(OBJ_DDS);

	return (clear_matrix(matrix, dds_id, NULL, NULL, 0));
}

int
get_dd_matrix(
	const uint32_t dd_id,
	bmp_t **p,
	uint32_t *n
)
{
	matrix_t *matrix = cache_get_matrix(OBJ_DD);

	return (get_matrix(matrix, dd_id, p, n));
}

int
get_dds_matrix(
	const uint32_t dds_id,
	bmp_t **p,
	uint32_t *n
)
{
	matrix_t *matrix = cache_get_matrix(OBJ_DDS);

	return (get_matrix(matrix, dds_id, p, n));
}

/*ARGSUSED*/
static int
cb_get_dds_status(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;

	isns_attr_t *attr = &obj->attrs[
	    ATTR_INDEX_DDS(ISNS_DD_SET_STATUS_ATTR_ID)];

	return (DDS_ENABLED(attr->value.ui) ? 1 : 0);
}

static int
get_dds_status(
	uint32_t dds_id
)
{
	lookup_ctrl_t lc;

	if (dds_id == 0) {
		return (0);
	}

	SET_UID_LCP(&lc, OBJ_DDS, dds_id);

	return (cache_lookup(&lc, NULL, cb_get_dds_status));
}

int
is_dd_active(
	uint32_t dd_id
)
{
	int active = 0;

	matrix_t *dds_matrix;
	uint32_t primary;
	uint32_t second;
	uint32_t x_info;
	bmp_t *bmp;
	int i;

	if (dd_id == 0) {
		return (active);
	}

	dds_matrix = cache_get_matrix(OBJ_DDS);
	primary = GET_PRIMARY(dd_id);
	second = GET_SECOND(dd_id);

	if (primary < dds_matrix->x) {
		i = 0;
		while (i < dds_matrix->y) {
			bmp = MATRIX_X_UNIT(dds_matrix, i);
			x_info = MATRIX_X_INFO(bmp);
			if (x_info != 0 &&
			    TEST_MEMBERSHIP(bmp, primary, second) != 0) {
				if (get_dds_status(x_info) != 0) {
					active = 1;
					break;
				}
			}
			i ++;
		}
	}

	return (active);
}

int
get_scope(
	uchar_t *node_name,
	bmp_t **p,
	uint32_t *n
)
{
	int ec = 0;

	lookup_ctrl_t lc;
	uint32_t uid;

	matrix_t *dd_matrix;
	uint32_t primary;
	uint32_t second;
	uint32_t x_info;
	bmp_t *bmp;
	int i, j;

	bmp_t *tmp_p;
	uint32_t tmp_n;

	bmp_t *short_p;
	uint32_t short_n;

	/* clear it */
	*p = NULL;
	*n = 0;

	/* get the source object uid */
	lc.curr_uid = 0;
	lc.type = OBJ_ISCSI;
	lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.data[0].ptr = node_name;
	lc.op[1] = 0;

	uid = is_obj_there(&lc);

	/* no such object */
	if (uid == 0) {
		return (ec);
	}

	dd_matrix = cache_get_matrix(OBJ_DD);
	primary = GET_PRIMARY(uid);
	second = GET_SECOND(uid);

	if (primary < dd_matrix->x) {
		i = 0;
		while (i < dd_matrix->y) {
			bmp = MATRIX_X_UNIT(dd_matrix, i);
			x_info = MATRIX_X_INFO(bmp);
			if (ec == 0 && x_info != 0 &&
			    TEST_MEMBERSHIP(bmp, primary, second) != 0) {
				if (is_dd_active(x_info) != 0 &&
				    (ec = get_dd_matrix(x_info,
				    &tmp_p, &tmp_n)) == 0) {
					if (*p == NULL) {
						*p = tmp_p;
						*n = tmp_n;
					} else {
						if (*n >= tmp_n) {
							short_p = tmp_p;
							short_n = tmp_n;
						} else {
							short_p = *p;
							short_n = *n;
							*p = tmp_p;
							*n = tmp_n;
						}
						j = 0;
						while (j < short_n) {
							(*p)[j] |= short_p[j];
							j ++;
						}
						free(short_p);
					}
				}
			}
			i ++;
		}
	}

	primary ++;
	if (ec == 0 && *p == NULL) {
		*p = (bmp_t *)calloc(primary, sizeof (bmp_t));
		if (*p != NULL) {
			*n = primary;
		} else {
			*n = 0;
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	}

	if (*p != NULL) {
		(*p)[primary - 1] |= (1 << second);
	}

	return (ec);
}

int
cb_clone_attrs(
	void *p1,
	void *p2
)
{
	int ec = 0;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	isns_attr_t *attr;

	int i = 1;

	while (i < MAX_LOOKUP_CTRL &&
	    lcp->op[i] != 0) {
		i ++;
	}

	while (ec == 0 &&
	    i < MAX_LOOKUP_CTRL &&
	    lcp->id[i] != 0) {
		switch (lcp->id[i]) {
		case ISNS_ISCSI_NAME_ATTR_ID:
			attr = &obj->attrs[ATTR_INDEX_ISCSI(
			    ISNS_ISCSI_NAME_ATTR_ID)];
			lcp->data[i].ptr = (uchar_t *)malloc(attr->len);
			if (lcp->data[i].ptr != NULL) {
				(void) strcpy((char *)lcp->data[i].ptr,
				    (char *)attr->value.ptr);
			} else {
				/* memory exhausted */
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		case ISNS_ISCSI_NODE_TYPE_ATTR_ID:
			attr = &obj->attrs[ATTR_INDEX_ISCSI(
			    ISNS_ISCSI_NODE_TYPE_ATTR_ID)];
			lcp->data[i].ui = attr->value.ui;
			break;
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			attr = &obj->attrs[ATTR_INDEX_PG(
			    ISNS_PG_ISCSI_NAME_ATTR_ID)];
			lcp->data[i].ptr = (uchar_t *)malloc(attr->len);
			if (lcp->data[i].ptr != NULL) {
				(void) strcpy((char *)lcp->data[i].ptr,
				    (char *)attr->value.ptr);
			} else {
				/* memory exhausted */
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			attr = &obj->attrs[ATTR_INDEX_PG(
			    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID)];
			lcp->data[i].ip = (in6_addr_t *)malloc(attr->len);
			if (lcp->data[i].ip != NULL) {
				(void) memcpy(lcp->data[i].ip,
				    attr->value.ip, attr->len);
			} else {
				/* memory exhausted */
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		case ISNS_PG_PORTAL_PORT_ATTR_ID:
			attr = &obj->attrs[ATTR_INDEX_PG(
			    ISNS_PG_PORTAL_PORT_ATTR_ID)];
			lcp->data[i].ui = attr->value.ui;
			break;
		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
			attr = &obj->attrs[ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_IP_ADDR_ATTR_ID)];
			lcp->data[i].ip = (in6_addr_t *)malloc(attr->len);
			if (lcp->data[i].ip != NULL) {
				(void) memcpy(lcp->data[i].ip,
				    attr->value.ip, attr->len);
			} else {
				/* memory exhausted */
				ec = ISNS_RSP_INTERNAL_ERROR;
			}
			break;
		case ISNS_PORTAL_PORT_ATTR_ID:
		case ISNS_ESI_PORT_ATTR_ID:
			attr = &obj->attrs[ATTR_INDEX_PORTAL(lcp->id[i])];
			if (attr->tag != 0 && attr->value.ui != 0) {
				lcp->data[i].ui = attr->value.ui;
			} else {
				lcp->data[i].ui = 0;
			}
			break;
		default:
			ASSERT(0);
			lcp->data[i].ui = 0;
			break;
		}
		i ++;
	}

	return (ec);
}

static matrix_t *
new_matrix(
	uint32_t x,
	uint32_t y
)
{
	matrix_t *matrix;

	matrix = (matrix_t *)malloc(sizeof (matrix_t));
	if (matrix != NULL) {
		matrix->x = x;
		matrix->y = y;
		matrix->m = (bmp_t *)calloc(y, SIZEOF_X_UNIT(matrix));
		if (matrix->m == NULL) {
			free(matrix);
			matrix = NULL;
		}
	}

	return (matrix);
}

int
dd_matrix_init(
	struct cache *c
)
{
	matrix_t *x;
	bmp_t *bmp;
	uint32_t primary;
	uint32_t second;

	/*
	 * allocate an array of pointer for dd and dd-set matrix.
	 */
	c->x = (matrix_t **)calloc(2, sizeof (matrix_t *));
	if (c->x == NULL) {
		return (1);
	}

	/*
	 * create dd matrix.
	 */
	x = new_matrix(8, 64);
	if (x != NULL) {
		x->c = c;
		c->x[0] = x;
	} else {
		return (1);
	}

	/*
	 * Mark the first array on the y axis for Default DD.
	 */
	bmp = MATRIX_X_UNIT(x, 0);
	MATRIX_X_INFO(bmp) = ISNS_DEFAULT_DD_ID;

	/*
	 * create dd set matrix.
	 */
	x = new_matrix(2, 16);
	if (x != NULL) {
		x->c = c;
		c->x[1] = x;
	} else {
		return (1);
	}

	/*
	 * Mark the first array on the y axis for Default DD-set.
	 */
	bmp = MATRIX_X_UNIT(x, 0);
	MATRIX_X_INFO(bmp) = ISNS_DEFAULT_DD_SET_ID;

	/*
	 * Add Default DD as a member of Default DD-set.
	 */
	primary = GET_PRIMARY(ISNS_DEFAULT_DD_ID);
	second = GET_SECOND(ISNS_DEFAULT_DD_ID);
	SET_MEMBERSHIP(bmp, primary, second);

	return (0);
}

static uint32_t
get_ds_id(
	matrix_t *matrix,
	uint32_t m_id,
	uint32_t curr_id
)
{
	bmp_t *bmp;
	uint32_t primary = GET_PRIMARY(m_id);
	uint32_t second = GET_SECOND(m_id);
	uint32_t dd_id = 0;
	uint32_t uid;
	int i = 0;

	if (matrix->x > primary) {
		while (i < matrix->y) {
			bmp = MATRIX_X_UNIT(matrix, i);
			uid = MATRIX_X_INFO(bmp);
			if (uid > curr_id &&
			    TEST_MEMBERSHIP(bmp, primary, second) != 0) {
				if (dd_id == 0 || uid < dd_id) {
					dd_id = uid;
				}
			}
			i ++;
		}
	}

	return (dd_id);
}

uint32_t
get_common_dd(
	uint32_t m_id1,
	uint32_t m_id2,
	uint32_t curr_id
)
{
	matrix_t *matrix;

	bmp_t *bmp;
	uint32_t primary1 = GET_PRIMARY(m_id1);
	uint32_t second1 = GET_SECOND(m_id1);
	uint32_t primary2 = GET_PRIMARY(m_id2);
	uint32_t second2 = GET_SECOND(m_id2);
	uint32_t dd_id = 0;
	int i = 0;

	matrix = cache_get_matrix(OBJ_DD);

	if (matrix->x > primary1 && matrix->x > primary2) {
		while (i < matrix->y) {
			bmp = MATRIX_X_UNIT(matrix, i);
			if (MATRIX_X_INFO(bmp) > curr_id &&
			    TEST_MEMBERSHIP(bmp, primary1, second1) != 0 &&
			    TEST_MEMBERSHIP(bmp, primary2, second2) != 0) {
				dd_id = MATRIX_X_INFO(bmp);
				break;
			}
			i ++;
		}
	}

	return (dd_id);
}

uint32_t
get_dd_id(
	uint32_t m_id,
	uint32_t curr_id
)
{
	matrix_t *matrix = cache_get_matrix(OBJ_DD);

	return (get_ds_id(matrix, m_id, curr_id));
}

uint32_t
get_dds_id(
	uint32_t m_id,
	uint32_t curr_id
)
{
	matrix_t *matrix = cache_get_matrix(OBJ_DDS);

	return (get_ds_id(matrix, m_id, curr_id));
}

static int
create_ds_object(
	isns_type_t type,
	isns_obj_t **ds_p,
	isns_attr_t *name_attr,
	isns_attr_t *uid_attr,
	isns_attr_t *status_attr
)
{
	int ec = 0;

	isns_obj_t *obj;
	int id1, id2, id3;

	if (type == OBJ_DD) {
		id1 = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
		id2 = ATTR_INDEX_DD(ISNS_DD_ID_ATTR_ID);
		id3 = ATTR_INDEX_DD(ISNS_DD_FEATURES_ATTR_ID);
	} else {
		ASSERT(type == OBJ_DDS);
		id1 = ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID);
		id2 = ATTR_INDEX_DDS(ISNS_DD_SET_ID_ATTR_ID);
		id3 = ATTR_INDEX_DDS(ISNS_DD_SET_STATUS_ATTR_ID);
	}

	obj = obj_calloc(type);
	if (obj != NULL &&
	    (name_attr != NULL && name_attr->tag != 0 &&
	    assign_attr(&obj->attrs[id1], name_attr) == 0) &&
	    (uid_attr == NULL || uid_attr->value.ui == 0 ||
	    assign_attr(&obj->attrs[id2], uid_attr) == 0) &&
	    (status_attr == NULL || status_attr->value.ui == 0 ||
	    assign_attr(&obj->attrs[id3], status_attr) == 0)) {
		*ds_p = obj;
	} else {
		/* no memory */
		free_object(obj);
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	return (ec);
}

int
create_dd_object(
	isns_tlv_t *op,
	uint16_t op_len,
	isns_obj_t **dd_p
)
{
	int ec = 0;
	uint8_t *value;
	isns_attr_t name = { 0 };
	isns_attr_t dd_id = { 0 }, features = { 0 };

	name.tag = ISNS_DD_NAME_ATTR_ID;

	while (op_len > 8 && ec == 0) {
		value = &op->attr_value[0];
		switch (op->attr_id) {
		case ISNS_DD_ID_ATTR_ID:
			if (op->attr_len == 4) {
				dd_id.tag = ISNS_DD_ID_ATTR_ID;
				dd_id.len = 4;
				dd_id.value.ui = ntohl(*(uint32_t *)value);
			} else if (op->attr_len != 0) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
			break;
		case ISNS_DD_NAME_ATTR_ID:
			if (op->attr_len > 0 &&
			    op->attr_len <= 256) {
				name.len = op->attr_len;
				name.value.ptr = (uchar_t *)value;
			} else if (op->attr_len != 0) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
			break;
		case ISNS_DD_ISCSI_INDEX_ATTR_ID:
		case ISNS_DD_ISCSI_NAME_ATTR_ID:
			break;
		case ISNS_DD_FC_PORT_NAME_ATTR_ID:
		case ISNS_DD_PORTAL_INDEX_ATTR_ID:
		case ISNS_DD_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_DD_PORTAL_PORT_ATTR_ID:
			ec = ISNS_RSP_REGIS_NOT_SUPPORTED;
			break;
		case ISNS_DD_FEATURES_ATTR_ID:
			if (op->attr_len == 4) {
				features.tag = ISNS_DD_FEATURES_ATTR_ID;
				features.len = op->attr_len;
				features.value.ui = ntohl(*(uint32_t *)value);
			} else if (op->attr_len != 0) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
			break;
		default:
			ec = ISNS_RSP_INVALID_REGIS;
			break;
		}
		NEXT_TLV(op, op_len);
	}

	if (ec == 0) {
		ec = create_ds_object(OBJ_DD, dd_p,
		    &name, &dd_id, &features);
	}

	return (ec);
}

int
create_dds_object(
	isns_tlv_t *op,
	uint16_t op_len,
	isns_obj_t **dds_p
)
{
	int ec = 0;
	uint8_t *value;
	isns_attr_t name = { 0 };
	isns_attr_t dds_id = { 0 }, code = { 0 };

	name.tag = ISNS_DD_SET_NAME_ATTR_ID;

	while (op_len > 8 && ec == 0) {
		value = &op->attr_value[0];
		switch (op->attr_id) {
		case ISNS_DD_SET_ID_ATTR_ID:
			if (op->attr_len == 4) {
				dds_id.tag = ISNS_DD_ID_ATTR_ID;
				dds_id.len = 4;
				dds_id.value.ui = ntohl(*(uint32_t *)value);
			} else if (op->attr_len != 0) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
			break;
		case ISNS_DD_SET_NAME_ATTR_ID:
			if (op->attr_len > 0 &&
			    op->attr_len <= 256) {
				name.len = op->attr_len;
				name.value.ptr = (uchar_t *)value;
			} else if (op->attr_len != 0) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
			break;
		case ISNS_DD_SET_STATUS_ATTR_ID:
			if (op->attr_len == 4) {
				code.tag = ISNS_DD_SET_STATUS_ATTR_ID;
				code.len = op->attr_len;
				code.value.ui = ntohl(*(uint32_t *)value);
			} else if (op->attr_len != 0) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
			break;
		case ISNS_DD_ID_ATTR_ID:
			break;
		default:
			ec = ISNS_RSP_INVALID_REGIS;
			break;
		}
		NEXT_TLV(op, op_len);
	}

	if (ec == 0) {
		ec = create_ds_object(OBJ_DDS, dds_p,
		    &name, &dds_id, &code);
	}

	return (ec);
}

int
adm_create_dd(
	isns_obj_t **dd_p,
	uchar_t *name,
	uint32_t uid,
	uint32_t features
)
{
	uint32_t len;
	isns_attr_t name_attr = { 0 };
	isns_attr_t uid_attr = { 0 };
	isns_attr_t features_attr = { 0 };

	name_attr.tag = ISNS_DD_NAME_ATTR_ID;
	if (name != NULL) {
		/* need to include the null terminator */
		/* and be on 4 bytes aligned */
		len = strlen((char *)name) + 1;
		len += 4 - (len % 4);
		name_attr.len = len;
		name_attr.value.ptr = name;
	}

	uid_attr.tag = ISNS_DD_ID_ATTR_ID;
	uid_attr.len = 4;
	uid_attr.value.ui = uid;

	features_attr.tag = ISNS_DD_FEATURES_ATTR_ID;
	features_attr.len = 4;
	features_attr.value.ui = features;

	return (create_ds_object(OBJ_DD, dd_p,
	    &name_attr, &uid_attr, &features_attr));
}

int
adm_create_dds(
	isns_obj_t **dds_p,
	uchar_t *name,
	uint32_t uid,
	uint32_t code
)
{
	uint32_t len;
	isns_attr_t name_attr = { 0 };
	isns_attr_t uid_attr = { 0 };
	isns_attr_t code_attr = { 0 };

	name_attr.tag = ISNS_DD_SET_NAME_ATTR_ID;
	if (name != NULL) {
		/* need to include the null terminator */
		/* and be on 4 bytes aligned */
		len = strlen((char *)name) + 1;
		len += 4 - (len % 4);
		name_attr.len = len;
		name_attr.value.ptr = name;
	}

	uid_attr.tag = ISNS_DD_SET_ID_ATTR_ID;
	uid_attr.len = 4;
	uid_attr.value.ui = uid;

	code_attr.tag = ISNS_DD_SET_STATUS_ATTR_ID;
	code_attr.len = 4;
	code_attr.value.ui = code;

	return (create_ds_object(OBJ_DDS, dds_p,
	    &name_attr, &uid_attr, &code_attr));
}

static int
update_ds_name(
	isns_type_t type,
	uint32_t uid,
	uint32_t tag,
	uint32_t len,
	uchar_t *name
)
{
	int ec = 0;

	lookup_ctrl_t lc;

	SET_UID_LCP(&lc, type, uid);

	lc.id[1] = tag;
	lc.data[1].ui = len;
	lc.data[2].ptr = name;

	ec = cache_rekey(&lc, &uid, cb_update_ds_attr);
	if (uid == 0) {
		ec = ISNS_RSP_INVALID_REGIS;
	}

	return (ec);
}

int
update_dd_name(
	uint32_t uid,
	uint32_t len,
	uchar_t *name
)
{
	/*
	 * We do now allow changing the default DD and DD-set name.
	 */
	if (uid == ISNS_DEFAULT_DD_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	return (update_ds_name(OBJ_DD, uid, ISNS_DD_NAME_ATTR_ID, len, name));
}

int
update_dds_name(
	uint32_t uid,
	uint32_t len,
	uchar_t *name
)
{
	/*
	 * We do now allow changing the default DD and DD-set name.
	 */
	if (uid == ISNS_DEFAULT_DD_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	return (update_ds_name(OBJ_DDS, uid,
	    ISNS_DD_SET_NAME_ATTR_ID, len, name));
}

static int
update_ds_uint32(
	isns_type_t type,
	uint32_t uid,
	uint32_t tag,
	uint32_t value
)
{
	int ec = 0;

	lookup_ctrl_t lc;

	SET_UID_LCP(&lc, type, uid);

	lc.id[1] = tag;
	lc.data[1].ui = value;

	ec = cache_lookup(&lc, &uid, cb_update_ds_attr);
	if (uid == 0) {
		ec = ISNS_RSP_INVALID_REGIS;
	}

	return (ec);
}

int
update_dd_features(
	uint32_t uid,
	uint32_t features
)
{
	return (update_ds_uint32(OBJ_DD, uid,
	    ISNS_DD_FEATURES_ATTR_ID, features));
}

int
update_dds_status(
	uint32_t uid,
	uint32_t enabled
)
{
	return (update_ds_uint32(OBJ_DDS, uid,
	    ISNS_DD_SET_STATUS_ATTR_ID, enabled));
}

int
add_dd_member(
	isns_obj_t *assoc
)
{
	int ec = 0;

	uint32_t dd_id;
	uint32_t m_id, m_type;

	dd_id = get_parent_uid(assoc);
	/*
	 * We do now allow placing any node to the default DD explicitly.
	 */
	if (dd_id == ISNS_DEFAULT_DD_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	ec = get_member_info(assoc, &m_type, &m_id, 1);
	if (ec == 0) {
		ec = update_dd_matrix(
		    '+', /* add member */
		    dd_id,
		    m_type,
		    m_id);
	}

	if (ec == 0) {
		if (sys_q != NULL) {
			/* add the membership to data store */
			ec = write_data(DATA_ADD, assoc);
		}

		/* trigger a management scn */
		if (ec == 0 && scn_q != NULL) {
			(void) make_scn(ISNS_MEMBER_ADDED, assoc);
		}
	}

	return (ec);
}

int
add_dds_member(
	isns_obj_t *assoc
)
{
	int ec = 0;

	uint32_t m_id = assoc->attrs[ATTR_INDEX_ASSOC_DD(
	    ISNS_DD_ID_ATTR_ID)].value.ui;
	uint32_t dds_id;

	dds_id = get_parent_uid(assoc);
	/*
	 * We do now allow changing the membership of the default DD
	 * and DD-set.
	 */
	if (dds_id == ISNS_DEFAULT_DD_SET_ID ||
	    m_id == ISNS_DEFAULT_DD_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	ec = get_dds_member_info(m_id);
	if (ec == 0) {
		ec = update_dds_matrix(
		    '+', /* add member */
		    dds_id,
		    m_id);
	}

	if (ec == 0) {
		if (sys_q != NULL) {
			/* add the membership to data store */
			ec = write_data(DATA_ADD, assoc);
		}

		/* trigger a management scn */
		if (ec == 0 && scn_q != NULL) {
			(void) make_scn(ISNS_MEMBER_ADDED, assoc);
		}
	}

	return (ec);
}

int
remove_dd_member(
	isns_obj_t *assoc
)
{
	int ec = 0;

	uint32_t dd_id;
	uint32_t m_type;
	uint32_t m_id;

	lookup_ctrl_t lc;

	dd_id = get_parent_uid(assoc);
	/*
	 * We do now allow removing the member from default DD explicitly.
	 */
	if (dd_id == ISNS_DEFAULT_DD_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	ec = get_member_info(assoc, &m_type, &m_id, 0);
	if (ec == 0) {
		ec = update_dd_matrix(
		    '-', /* remove member */
		    dd_id,
		    m_type,
		    m_id);
		if (ec == 0) {
			/* update data store */
			if (sys_q != NULL) {
				/* remove it from data store */
				ec = write_data(
				    DATA_DELETE_ASSOC, assoc);
			}

			/* trigger a management scn */
			if (ec == 0 && scn_q != NULL) {
				(void) make_scn(ISNS_MEMBER_REMOVED, assoc);
			}

			/* remove it from object container if */
			/* it is not a registered object */
			if (ec == 0) {
				SET_UID_LCP(&lc, m_type, m_id);
				ec = dereg_assoc(&lc);
			}
		}
	}

	return (ec);
}

int
remove_dds_member(
	uint32_t dds_id,
	uint32_t m_id
)
{
	int ec = 0;

	isns_obj_t *clone;

	/*
	 * We do now allow removing the member from default DD-set.
	 */
	if (dds_id == ISNS_DEFAULT_DD_SET_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	if (m_id != 0) {
		ec = update_dds_matrix(
		    '-', /* remove member */
		    dds_id,
		    m_id);
		if (ec == 0) {
			clone = obj_calloc(OBJ_ASSOC_DD);
			if (clone != NULL) {
				(void) set_obj_uid((void *)clone, m_id);
				(void) set_parent_obj(clone, dds_id);
			}
			/* update data store */
			if (sys_q != NULL) {
				if (clone != NULL) {
					/* remove it from data store */
					ec = write_data(
					    DATA_DELETE_ASSOC, clone);
				} else {
					ec = ISNS_RSP_INTERNAL_ERROR;
				}
			}

			/* trigger a management scn */
			if (ec == 0 &&
			    scn_q != NULL &&
			    clone != NULL) {
				(void) make_scn(ISNS_MEMBER_REMOVED, clone);
			}
			free_object(clone);
		}
	}

	return (ec);
}

static int
remove_member_wildchar(
	matrix_t *matrix,
	uint32_t m_id
)
{
	int ec = 0;

	bmp_t *bmp;
	uint32_t x_info;
	int i;

	uint32_t primary = GET_PRIMARY(m_id);
	uint32_t second = GET_SECOND(m_id);

	isns_obj_t *clone;

	if (primary >= matrix->x) {
		return (ec);
	}

	i = 0;
	while (ec == 0 && i < matrix->y) {
		bmp = MATRIX_X_UNIT(matrix, i);
		x_info = MATRIX_X_INFO(bmp);
		if (x_info != 0 &&
		    TEST_MEMBERSHIP(bmp, primary, second) != 0) {
			/* clean the membership */
			CLEAR_MEMBERSHIP(bmp, primary, second);
			/* update data store */
			if (sys_q != NULL) {
				clone = obj_calloc(OBJ_ASSOC_DD);
				if (clone != NULL) {
					(void) set_obj_uid((void *)clone, m_id);
					(void) set_parent_obj(clone, x_info);
					/* remove it from data store */
					ec = write_data(
					    DATA_DELETE_ASSOC, clone);
					free_object(clone);
				} else {
					ec = ISNS_RSP_INTERNAL_ERROR;
				}
			}
		}
		i ++;
	}

	return (ec);
}

int
remove_dd_object(
	uint32_t dd_id
)
{
	matrix_t *dds_matrix;

	bmp_t *p;
	uint32_t n;
	int ec;

	lookup_ctrl_t lc;
	uint32_t uid;

	/*
	 * We do now allow removing the default DD.
	 */
	if (dd_id == ISNS_DEFAULT_DD_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	SET_UID_LCP(&lc, OBJ_DD, dd_id);

	/* de-register the object at first */
	ec = dereg_object(&lc, 0);

	/* clear it from all of dd-set */
	dds_matrix = cache_get_matrix(OBJ_DDS);
	(void) remove_member_wildchar(dds_matrix, dd_id);

	/* clear its member bitmap */
	(void) clear_dd_matrix(dd_id, &p, &n);

	/* deregister the member nodes which are not-registered node */
	/* and have no longer membership in other DD(s). */
	if (p != NULL) {
		SET_UID_LCP(&lc, OBJ_ISCSI, 0);
		FOR_EACH_MEMBER(p, n, uid, {
			lc.data[0].ui = uid;
			(void) dereg_assoc(&lc);
		});
		free(p);
	}

	return (ec);
}

int
remove_dds_object(
	uint32_t dds_id
)
{
	int ec;

	lookup_ctrl_t lc;

	/*
	 * We do now allow removing the default DD-set.
	 */
	if (dds_id == ISNS_DEFAULT_DD_SET_ID) {
		return (ISNS_RSP_OPTION_NOT_UNDERSTOOD);
	}

	(void) clear_dds_matrix(dds_id);

	SET_UID_LCP(&lc, OBJ_DDS, dds_id);

	ec = dereg_object(&lc, 0);

	return (ec);
}

int
update_ddd(
	void *p,
	const uchar_t op
)
{
	isns_obj_t *obj;
	uint32_t uid;

	matrix_t *matrix;

	obj = (isns_obj_t *)p;
	if (obj->type != OBJ_ISCSI) {
		return (0);
	}

	matrix = cache_get_matrix(OBJ_DD);
	uid = get_obj_uid(obj);

	return (update_matrix(matrix, op, ISNS_DEFAULT_DD_ID, uid, 0));
}

int
verify_ddd(
)
{
	int ec = 0;

	lookup_ctrl_t lc;
	isns_obj_t *obj;

	uchar_t *name;
	uint32_t uid;
	uint32_t features;
	uint32_t code;

	/* Ensure the Default DD is registered. */
	uid = ISNS_DEFAULT_DD_ID;

	SET_UID_LCP(&lc, OBJ_DD, uid);

	(void) cache_lock_write();

	if (is_obj_there(&lc) == 0) {
		name = (uchar_t *)DEFAULT_DD_NAME;
		features = DEFAULT_DD_FEATURES;
		ec = adm_create_dd(&obj, name, uid, features);
		if (ec == 0) {
			ec = register_object(obj, NULL, NULL);
			if (ec != 0) {
				free_object(obj);
				goto verify_done;
			}
		} else {
			goto verify_done;
		}
	}

	/* Ensure the Default DD-set is registered. */
	uid = ISNS_DEFAULT_DD_SET_ID;

	SET_UID_LCP(&lc, OBJ_DDS, uid);

	if (is_obj_there(&lc) == 0) {
		name = (uchar_t *)DEFAULT_DD_SET_NAME;
		code = DEFAULT_DD_SET_STATUS;
		ec = adm_create_dds(&obj, name, uid, code);
		if (ec == 0) {
			ec = register_object(obj, NULL, NULL);
			if (ec != 0) {
				free_object(obj);
			}
		}
	}

verify_done:

	ec = cache_unlock_sync(ec);

	return (ec);
}
