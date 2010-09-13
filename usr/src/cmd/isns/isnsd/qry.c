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
#include "isns_func.h"
#include "isns_msgq.h"
#include "isns_htab.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_dd.h"
#include "isns_pdu.h"
#include "isns_qry.h"

/*
 * external variables
 */
extern const int NUM_OF_ATTRS[MAX_OBJ_TYPE_FOR_SIZE];
extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];
extern const int NUM_OF_CHILD[MAX_OBJ_TYPE];
extern const int TYPE_OF_CHILD[MAX_OBJ_TYPE][MAX_CHILD_TYPE];

/*
 * global variables
 */
const int TAG_RANGE[MAX_OBJ_TYPE][3] = {
	{ 0, 0 },
	{ ENTITY_KEY, LAST_TAG_ENTITY, ENTITY_END },
	{ ISCSI_KEY, LAST_TAG_ISCSI, ISCSI_END },
	{ PORTAL_KEY1, LAST_TAG_PORTAL, PORTAL_END },
	{ PG_KEY1, LAST_TAG_PG, PG_END },
	{ DD_KEY, LAST_TAG_DD, DD_END },
	{ DDS_KEY, LAST_TAG_DDS, DDS_END }
};

/*
 * local variables
 */
typedef int (*qry_func_t)(lookup_ctrl_t *);

/* Edge functions of each adjacent object */
static int qry_c2e(lookup_ctrl_t *);
static int qry_ds2m(lookup_ctrl_t *);
static int qry_slf(lookup_ctrl_t *);
static int qry_e2i(lookup_ctrl_t *);
static int qry_e2p(lookup_ctrl_t *);
static int qry_e2g(lookup_ctrl_t *);
static int qry_i2g(lookup_ctrl_t *);
static int qry_i2d(lookup_ctrl_t *);
static int qry_p2g(lookup_ctrl_t *);
static int qry_g2i(lookup_ctrl_t *);
static int qry_g2p(lookup_ctrl_t *);
static int qry_d2s(lookup_ctrl_t *);

/* The directed cyclic graph of query procedure. */
/* __|____e_________i_________p_________g_________d_________s____ */
/* e | qry_slf...qry_e2i...qry_e2p...qry_e2g...NULL......NULL.... */
/* i | qry_c2e...qry_slf...NULL......qry_i2g...qry_i2d...NULL.... */
/* p | qry_c2e...NULL......qry_slf...qry_p2g...NULL......NULL.... */
/* g | qry_c2e...qry_g2i...qry_g2p...qry_slf...NULL......NULL.... */
/* d | NULL......qry_ds2m..NULL......NULL......qry_slf...qry_d2s. */
/* s | NULL......NULL......NULL......NULL......qry_ds2m..qry_slf. */

/* The type of spanning tree of query graph. */
typedef struct adjvex {
	qry_func_t f;
	isns_type_t t;
	struct adjvex const *v;
} adjvex_t;

/* The solid edges in the spanning tree. */
static const adjvex_t v_slf = { &qry_slf,  0,		NULL };
static const adjvex_t v_c2e = { &qry_c2e,  OBJ_ENTITY,	NULL };
static const adjvex_t v_e2i = { &qry_e2i,  OBJ_ISCSI,	NULL };
static const adjvex_t v_e2p = { &qry_e2p,  OBJ_PORTAL,	NULL };
static const adjvex_t v_e2g = { &qry_e2g,  OBJ_PG,	NULL };
static const adjvex_t v_i2g = { &qry_i2g,  OBJ_PG,	NULL };
static const adjvex_t v_i2d = { &qry_i2d,  OBJ_DD,	NULL };
static const adjvex_t v_p2g = { &qry_p2g,  OBJ_PG,	NULL };
static const adjvex_t v_g2i = { &qry_g2i,  OBJ_ISCSI,	NULL };
static const adjvex_t v_g2p = { &qry_g2p,  OBJ_PORTAL,	NULL };
static const adjvex_t v_d2s = { &qry_d2s,  OBJ_DDS,	NULL };
static const adjvex_t v_d2i = { &qry_ds2m, OBJ_ISCSI,	NULL };
static const adjvex_t v_s2d = { &qry_ds2m, OBJ_DD,	NULL };

/* The virtual edges in the spanning tree. */
static const adjvex_t v_i2p = { &qry_i2g,  OBJ_PG,    &v_g2p };
static const adjvex_t v_i2s = { &qry_i2d,  OBJ_DD,    &v_d2s };

static const adjvex_t v_g2d = { &qry_g2i,  OBJ_ISCSI, &v_i2d };
static const adjvex_t v_g2s = { &qry_g2i,  OBJ_ISCSI, &v_i2s };

static const adjvex_t v_p2i = { &qry_p2g,  OBJ_PG,    &v_g2i };
static const adjvex_t v_p2d = { &qry_p2g,  OBJ_PG,    &v_g2d };
static const adjvex_t v_p2s = { &qry_p2g,  OBJ_PG,    &v_g2s };

static const adjvex_t v_e2d = { &qry_e2i,  OBJ_ISCSI, &v_i2d };
static const adjvex_t v_e2s = { &qry_e2i,  OBJ_ISCSI, &v_i2s };

static const adjvex_t v_d2e = { &qry_ds2m, OBJ_ISCSI, &v_c2e };
static const adjvex_t v_d2p = { &qry_ds2m, OBJ_ISCSI, &v_i2p };
static const adjvex_t v_d2g = { &qry_ds2m, OBJ_ISCSI, &v_i2g };

static const adjvex_t v_s2e = { &qry_ds2m, OBJ_DD,    &v_d2e };
static const adjvex_t v_s2i = { &qry_ds2m, OBJ_DD,    &v_d2i };
static const adjvex_t v_s2p = { &qry_ds2m, OBJ_DD,    &v_d2p };
static const adjvex_t v_s2g = { &qry_ds2m, OBJ_DD,    &v_d2g };

/* the vector of query graph */
static const adjvex_t *qry_puzzle[MAX_OBJ_TYPE][MAX_OBJ_TYPE] = {
{ NULL },
{ NULL, &v_slf, &v_e2i, &v_e2p, &v_e2g, &v_e2d, &v_e2s },
{ NULL, &v_c2e, &v_slf, &v_i2p, &v_i2g, &v_i2d, &v_i2s },
{ NULL, &v_c2e, &v_p2i, &v_slf, &v_p2g, &v_p2d, &v_p2s },
{ NULL, &v_c2e, &v_g2i, &v_g2p, &v_slf, &v_g2d, &v_g2s },
{ NULL, &v_d2e, &v_d2i, &v_d2p, &v_d2g, &v_slf, &v_d2s },
{ NULL, &v_s2e, &v_s2i, &v_s2p, &v_s2g, &v_s2d, &v_slf }
};

static int
cb_qry_parent_uid(
	void *p1,
	/* LINTED E_FUNC_ARG_UNUSED */
	void *p2
)
{
	uint32_t puid = get_parent_uid((isns_obj_t *)p1);
	return ((int)puid);
}

static int
cb_qry_child_uids(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	isns_type_t type = lcp->data[1].ui;
	uint32_t *uidp = get_child_t(obj, type);
	uint32_t num = 0;
	uint32_t *p;

	if (uidp != NULL && *uidp > 0) {
		num = *uidp;
		p = malloc(num * sizeof (*p));
		if (p != NULL) {
			uidp ++;
			(void) memcpy(p, uidp, num * sizeof (*p));
			lcp->id[2] = num;
			lcp->data[2].ptr = (uchar_t *)p;
		} else {
			return (ISNS_RSP_INTERNAL_ERROR);
		}
	}

	return (0);
}

static int
e2c(
	lookup_ctrl_t *lcp,
	isns_type_t type
)
{
	int ec = 0;

	uint32_t uid = lcp->curr_uid; /* last child */
	uint32_t num_of_child;
	uint32_t *uids;

	uint32_t tmp_uid = 0;

	/* the first times of query */
	if (uid == 0) {
		lcp->data[1].ui = type;
		ec = cache_lookup(lcp, NULL, cb_qry_child_uids);
	}

	num_of_child = lcp->id[2];
	uids = (uint32_t *)lcp->data[2].ptr;

	while (num_of_child > 0) {
		if (*uids > uid) {
			tmp_uid = *uids;
			break;
		}
		uids ++;
		num_of_child --;
	}

	uid = tmp_uid;

	/* no more child, clean up memory */
	if (uid == 0) {
		lcp->data[1].ui = 0;
		lcp->id[2] = 0;
		lcp->data[2].ptr = NULL;

		/* free up the memory */
		free(uids);
	}

	/* save it for returning and querying next uid */
	lcp->curr_uid = uid;

	return (ec);
}

static int
qry_c2e(
	lookup_ctrl_t *lcp
)
{
	uint32_t uid;

	/* child object has only one parent */
	if (lcp->curr_uid == 0) {
		uid = (uint32_t)cache_lookup(lcp, NULL,
		    cb_qry_parent_uid);
	} else {
		uid = 0;
	}

	/* save the result for returnning */
	lcp->curr_uid = uid;

	return (0);
}

static int
qry_ds2m(
	lookup_ctrl_t *lcp
)
{
	int ec = 0;

	uint32_t uid = lcp->curr_uid; /* last member */
	isns_type_t type = lcp->type;
	uint32_t ds_id = lcp->data[0].ui;

	uint32_t tmp_uid;

	uint32_t n;
	bmp_t *p;

	/* the first times of query */
	if (uid == 0) {
		ec = (type == OBJ_DD) ?
		    get_dd_matrix(ds_id, &p, &n) :
		    get_dds_matrix(ds_id, &p, &n);
		lcp->id[1] = n;
		lcp->data[1].ptr = (uchar_t *)p;
	} else {
		n = lcp->id[1];
		p = (bmp_t *)lcp->data[1].ptr;
	}

	FOR_EACH_MEMBER(p, n, tmp_uid, {
		if (tmp_uid > uid) {
			lcp->curr_uid = tmp_uid;
			return (ec);
		}
	});

	/* no more member, clean up memory */
	lcp->id[1] = 0;
	lcp->data[1].ptr = NULL;

	/* free up the matrix */
	free(p);

	lcp->curr_uid = 0;

	return (ec);
}

static int
qry_slf(
	lookup_ctrl_t *lcp
)
{
	uint32_t uid;

	if (lcp->curr_uid == 0) {
		uid = lcp->data[0].ui;
	} else {
		uid = 0;
	}

	lcp->curr_uid = uid;

	return (0);
}

static int
qry_e2i(
	lookup_ctrl_t *lcp
)
{
	return (e2c(lcp, OBJ_ISCSI));
}

static int
qry_e2p(
	lookup_ctrl_t *lcp
)
{
	return (e2c(lcp, OBJ_PORTAL));
}

static int
qry_e2g(
	lookup_ctrl_t *lcp
)
{
	uint32_t uid = lcp->curr_uid; /* last pg */

	htab_t *htab = cache_get_htab(OBJ_PG);

	lookup_ctrl_t lc;
	uint32_t puid;

	SET_UID_LCP(&lc, OBJ_PG, 0);

	/* this is a shortcut */
	FOR_EACH_ITEM(htab, uid, {
		lc.data[0].ui = uid;
		puid = (uint32_t)cache_lookup(&lc, NULL,
		    cb_qry_parent_uid);
		if (puid == lcp->data[0].ui) {
			/* keep the current uid */
			lcp->curr_uid = uid;
			return (0);
		}
	});

	lcp->curr_uid = 0;

	return (0);
}

static int
qry_i2g(
	lookup_ctrl_t *lcp
)
{
	int ec = 0;

	uint32_t uid = lcp->curr_uid; /* last pg */
	lookup_ctrl_t lc;

	/* the first times of query */
	if (uid == 0) {
		lcp->id[1] = ISNS_ISCSI_NAME_ATTR_ID;
		ec = cache_lookup(lcp, NULL, cb_clone_attrs);
	}

	if (lcp->data[1].ptr != NULL) {
		/* pg lookup */
		lc.curr_uid = uid;
		lc.type = OBJ_PG;
		lc.id[0] = ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID);
		lc.op[0] = OP_STRING;
		lc.data[0].ptr = lcp->data[1].ptr;
		lc.op[1] = 0;

		uid = is_obj_there(&lc);
	} else {
		uid = 0;
	}

	/* no more pg, update lcp with pg object */
	if (uid == 0) {
		lcp->id[1] = 0;

		/* clean up the memory */
		if (lcp->data[1].ptr != NULL) {
			free(lcp->data[1].ptr);
			/* reset it */
			lcp->data[1].ptr = NULL;
		}
	}

	/* save it for returning and querying next pg */
	lcp->curr_uid = uid;

	return (ec);
}

static int
qry_i2d(
	lookup_ctrl_t *lcp
)
{
	uint32_t dd_id = lcp->curr_uid; /* last dd_id */
	uint32_t uid = lcp->data[0].ui;

	dd_id = get_dd_id(uid, dd_id);

	/* save it for returning and getting next dd */
	lcp->curr_uid = dd_id;

	return (0);
}

static int
qry_p2g(
	lookup_ctrl_t *lcp
)
{
	int ec = 0;

	uint32_t uid = lcp->curr_uid; /* last pg */
	lookup_ctrl_t lc;

	/* the first time of query */
	if (uid == 0) {
		/* use 1&2 for the portal ip address & port */
		lcp->id[1] = ISNS_PORTAL_IP_ADDR_ATTR_ID;
		lcp->id[2] = ISNS_PORTAL_PORT_ATTR_ID;
		ec = cache_lookup(lcp, NULL, cb_clone_attrs);
	}

	if (lcp->data[1].ip != NULL) {
		/* pg lookup */
		lc.curr_uid = uid;
		lc.type = OBJ_PG;
		lc.id[0] = ATTR_INDEX_PG(ISNS_PG_PORTAL_IP_ADDR_ATTR_ID);
		lc.op[0] = OP_MEMORY_IP6;
		lc.data[0].ip = lcp->data[1].ip;
		lc.id[1] = ATTR_INDEX_PG(ISNS_PG_PORTAL_PORT_ATTR_ID);
		lc.op[1] = OP_INTEGER;
		lc.data[1].ui = lcp->data[2].ui;
		lc.op[2] = 0;

		uid = is_obj_there(&lc);
	} else {
		uid = 0;
	}

	/* no more pg, clean up memory */
	if (uid == 0) {
		lcp->id[1] = 0;
		lcp->id[2] = 0;

		/* clean up the memory */
		if (lcp->data[1].ip != NULL) {
			free(lcp->data[1].ip);
			/* reset it */
			lcp->data[1].ip = NULL;
		}
		lcp->data[2].ui = 0;
	}

	/* save it for returning and next query */
	lcp->curr_uid = uid;

	return (ec);
}

static int
qry_g2i(
	lookup_ctrl_t *lcp
)
{
	int ec = 0;

	uint32_t uid = lcp->curr_uid; /* last node */
	lookup_ctrl_t lc;

	/* the first time of query */
	if (uid == 0) {
		/* use slot 1 for the storage node name */
		lcp->id[1] = ISNS_PG_ISCSI_NAME_ATTR_ID;
		ec = cache_lookup(lcp, NULL, cb_clone_attrs);

		if (lcp->data[1].ptr != NULL) {
			/* iscsi node lookup */
			lc.curr_uid = uid;
			lc.type = OBJ_ISCSI;
			lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
			lc.op[0] = OP_STRING;
			lc.data[0].ptr = lcp->data[1].ptr;
			lc.op[1] = 0;

			uid = is_obj_there(&lc);

			/* no longer need it, clean it up */
			free(lcp->data[1].ptr);
			lcp->data[1].ptr = NULL;
		}
		/* no longer need it, reset it */
		lcp->id[1] = 0;
	} else {
		/* one pg has maximum number of one storage node */
		uid = 0;
	}

	/* save it for returning and next query */
	lcp->curr_uid = uid;

	return (ec);
}

static int
qry_g2p(
	lookup_ctrl_t *lcp
)
{
	int ec = 0;

	uint32_t uid = lcp->curr_uid; /* last portal */
	lookup_ctrl_t lc;

	/* the first times of query */
	if (uid == 0) {
		/* use 1&2 for the portal ip addr and port */
		lcp->id[1] = ISNS_PG_PORTAL_IP_ADDR_ATTR_ID;
		lcp->id[2] = ISNS_PG_PORTAL_PORT_ATTR_ID;
		ec = cache_lookup(lcp, NULL, cb_clone_attrs);

		if (lcp->data[1].ip != NULL) {
			/* portal lookup */
			lc.curr_uid = uid;
			lc.type = OBJ_PORTAL;
			lc.id[0] = ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_IP_ADDR_ATTR_ID);
			lc.op[0] = OP_MEMORY_IP6;
			lc.data[0].ip = lcp->data[1].ip;
			lc.id[1] = ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_PORT_ATTR_ID);
			lc.op[1] = OP_INTEGER;
			lc.data[1].ui = lcp->data[2].ui;
			lc.op[2] = 0;

			uid = is_obj_there(&lc);

			/* no longer need it, reset it */
			free(lcp->data[1].ip);
			lcp->data[1].ip = NULL;
		}
		/* no longer need it, reset it */
		lcp->id[1] = 0;
		lcp->id[2] = 0;
		lcp->data[2].ui = 0;
	} else {
		/* one pg has maximum number of one portal */
		uid = 0;
	}

	/* save it for returning and next query */
	lcp->curr_uid = uid;

	return (ec);
}

static int
qry_d2s(
	lookup_ctrl_t *lcp
)
{
	uint32_t dds_id = lcp->curr_uid; /* last dds */
	uint32_t dd_id = lcp->data[0].ui;

	dds_id = get_dds_id(dd_id, dds_id);

	/* save it for returning and for getting next dds */
	lcp->curr_uid = dds_id;

	return (0);
}

int
validate_qry_key(
	isns_type_t type,
	isns_tlv_t *key,
	uint16_t key_len,
	isns_attr_t *attrs
)
{
	int ec = 0;

	uint32_t tag;
	uint32_t min_tag, max_tag;

	isns_attr_t *attr;

	min_tag = TAG_RANGE[type][0];
	max_tag = TAG_RANGE[type][2];

	while (key_len != 0 && ec == 0) {
		tag = key->attr_id;
		if (tag < min_tag || tag > max_tag) {
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
		} else if (key->attr_len > 0 && attrs != NULL) {
			attr = &attrs[tag - min_tag]; /* ATTR_INDEX_xxx */
			ec = extract_attr(attr, key, 0);
			if (ec == ISNS_RSP_INVALID_REGIS) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
		}
		NEXT_TLV(key, key_len);
	}

	return (ec);
}

static lookup_method_t
get_op_method(
	uint32_t tag
)
{
	lookup_method_t method = 0;

	switch (tag) {
	/* OP_STRING */
	case ISNS_EID_ATTR_ID:
	case ISNS_PORTAL_NAME_ATTR_ID:
	case ISNS_ISCSI_ALIAS_ATTR_ID:
	case ISNS_DD_SET_NAME_ATTR_ID:
	case ISNS_DD_NAME_ATTR_ID:
	case ISNS_ISCSI_NAME_ATTR_ID:
	case ISNS_PG_ISCSI_NAME_ATTR_ID:
	case ISNS_ISCSI_AUTH_METHOD_ATTR_ID:
		method = OP_STRING;
		break;
	/* OP_MEMORY_IP6 */
	case ISNS_MGMT_IP_ADDR_ATTR_ID:
	case ISNS_PORTAL_IP_ADDR_ATTR_ID:
	case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
		method = OP_MEMORY_IP6;
		break;
	/* OP_INTEGER */
	case ISNS_ENTITY_PROTOCOL_ATTR_ID:
	case ISNS_VERSION_RANGE_ATTR_ID:
	case ISNS_ENTITY_REG_PERIOD_ATTR_ID:
	case ISNS_ENTITY_INDEX_ATTR_ID:
	case ISNS_PORTAL_PORT_ATTR_ID:
	case ISNS_ESI_INTERVAL_ATTR_ID:
	case ISNS_ESI_PORT_ATTR_ID:
	case ISNS_PORTAL_INDEX_ATTR_ID:
	case ISNS_SCN_PORT_ATTR_ID:
	case ISNS_ISCSI_NODE_TYPE_ATTR_ID:
	case ISNS_ISCSI_SCN_BITMAP_ATTR_ID:
	case ISNS_ISCSI_NODE_INDEX_ATTR_ID:
	case ISNS_PG_PORTAL_PORT_ATTR_ID:
	case ISNS_PG_TAG_ATTR_ID:
	case ISNS_PG_INDEX_ATTR_ID:
	case ISNS_DD_SET_ID_ATTR_ID:
	case ISNS_DD_SET_STATUS_ATTR_ID:
	case ISNS_DD_ID_ATTR_ID:
	/* all other attrs */
	default:
		method = OP_INTEGER;
		break;
	}

	return (method);
}

static int
cb_attrs_match(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	isns_attr_t *attrs = (isns_attr_t *)
	    ((lookup_ctrl_t *)p2)->data[1].ptr;

	lookup_ctrl_t lc;
	int match = 1; /* 0: not match, otherwise: match */

	int i;

	lc.op[1] = 0;

	for (i = 0; match != 0 && i < NUM_OF_ATTRS[obj->type]; i++) {
		if (attrs->tag != 0 && attrs->len > 0) {
			lc.id[0] = i;
			lc.op[0] = get_op_method(attrs->tag);
			lc.data[0].ptr = attrs->value.ptr;
			match = key_cmp(&lc, obj) == 0 ? 1 : 0;
		}
		attrs ++;
	}

	return (match);
}

static int
attrs_match(
	isns_type_t type,
	uint32_t uid,
	isns_attr_t *attrs
)
{
	int match; /* 0: not match, otherwise: match */
	lookup_ctrl_t lc;

	SET_UID_LCP(&lc, type, uid);

	lc.data[1].ptr = (uchar_t *)attrs;

	match = cache_lookup(&lc, NULL, cb_attrs_match);

	return (match);
}

static int
insert_uid(
	uint32_t **pp,
	uint32_t *np,
	uint32_t *sp,
	uint32_t uid
)
{
	int ec = 0;

	uint32_t *p = *pp;
	uint32_t n = *np;
	uint32_t s = *sp;

	uint32_t u;
	uint32_t *t;

	/* check for duplication */
	if (n > 0 && uid <= p[n - 1]) {
		while (n-- > 0) {
			if (p[n] == uid) {
				return (0);
			}
		}
		n = *np;
		u = p[n - 1];
		p[n - 1] = uid;
		uid = u;
	}


	if (s == n) {
		s = (s == 0) ? 8 : s * 2;
		t = (uint32_t *)realloc(p, s * sizeof (uint32_t));
		if (t != NULL) {
			p = t;
			*pp = p;
			*sp = s;
		} else {
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	}

	if (ec == 0) {
		p[n ++] = uid;
		*np = n;
	}

	return (ec);
}

static int
qry_and_match(
	uint32_t **obj_uids,
	uint32_t *num_of_objs,
	uint32_t *size,
	isns_type_t type,
	uint32_t src_uid,
	isns_type_t src_type,
	isns_attr_t *attrs
)
{
	int ec = 0;

	lookup_ctrl_t lc = { 0 }; /* !!! need to be empty */
	uint32_t uid;

	const adjvex_t *vex;

	/* circular list */
	uint32_t *p[2], n[2], s[2];
	int i, j;

	uint32_t *p1, n1;
	uint32_t *p2, n2, s2;
	isns_type_t t;

	/* initialize the circular list */
	i = 0;
	j = 1;

	p[i] = *obj_uids;
	n[i] = *num_of_objs;
	s[i] = *size;

	p[j] = malloc(8 * sizeof (uint32_t));
	p[j][0] = src_uid;
	n[j] = 1;
	s[j] = 8;

	/* initial object type of being queried */
	t = src_type;

	vex = qry_puzzle[src_type][type];

	do {
		/* shift one on the circular list */
		i = (i + 1) & 1;
		j = (j + 1) & 1;

		p1 = p[i]; n1 = n[i];
		p2 = p[j]; n2 = n[j]; s2 = s[j];

		/* prepare lookup control */
		lc.type = t;
		lc.id[0] = UID_ATTR_INDEX[t];
		lc.op[0] = OP_INTEGER;

		/* result object type */
		t = vex->t;

		FOR_EACH_OBJS(p1, n1, uid, {
			/* start query */
			lc.data[0].ui = uid;
			ec = vex->f(&lc);
			uid = lc.curr_uid;
			while (ec == 0 && uid != 0) {
				if (attrs == NULL ||
				    attrs_match(type, uid, attrs) != 0) {
					ec = insert_uid(&p2, &n2, &s2, uid);
				}
				if (ec == 0) {
					ec = vex->f(&lc);
					uid = lc.curr_uid;
				} else {
					n1 = n2 = 0; /* force break */
				}
			}
		});
		if (ec == 0) {
			vex = vex->v;
		} else {
			vex = NULL; /* force break */
		}
		/* push back */
		p[j] = p2; n[j] = n2; s[j] = s2;
		/* reset the number of objects */
		n[i] = 0;
	} while (vex != NULL);

	/* clean up the memory */
	free(p1);
	if (ec != 0) {
		free(p2);
		p2 = NULL;
		n2 = 0;
		s2 = 0;
	}

	*obj_uids = p2;
	*num_of_objs = n2;
	*size = s2;

	return (ec);
}

int
get_qry_keys(
	bmp_t *nodes_bmp,
	uint32_t num_of_nodes,
	isns_type_t *type,
	isns_tlv_t *key,
	uint16_t key_len,
	uint32_t **obj_uids,
	uint32_t *num_of_objs
)
{
	int ec = 0;
	union {
		isns_obj_t o;
		isns_entity_t e;
		isns_iscsi_t i;
		isns_portal_t p;
		isns_pg_t g;
		isns_dd_t d;
		isns_dds_t s;
	} an_obj = { 0 };
	isns_attr_t *attrs;

	htab_t *htab;
	uint32_t node_uid;

	uint32_t size;

	*obj_uids = NULL;
	*num_of_objs = 0;
	size = 0;

	/* get the object type identified by the key */
	*type = TLV2TYPE(key);
	if (*type == 0) {
		return (ISNS_RSP_INVALID_QRY);
	}

	attrs = &an_obj.o.attrs[0];
	/* validate the Message Key */
	ec = validate_qry_key(*type, key, key_len, attrs);
	if (ec != 0) {
		return (ec);
	}

	if (nodes_bmp != NULL) {
		FOR_EACH_MEMBER(nodes_bmp, num_of_nodes, node_uid, {
			ec = qry_and_match(
			    obj_uids, num_of_objs, &size, *type,
			    node_uid, OBJ_ISCSI, attrs);
			if (ec != 0) {
				return (ec);
			}
		});
	} else {
		node_uid = 0;
		htab = cache_get_htab(OBJ_ISCSI);
		FOR_EACH_ITEM(htab, node_uid, {
			ec = qry_and_match(
			    obj_uids, num_of_objs, &size, *type,
			    node_uid, OBJ_ISCSI, attrs);
			if (ec != 0) {
				return (ec);
			}
		});
	}

	return (ec);
}

int
get_qry_ops(
	uint32_t uid,
	isns_type_t src_type,
	isns_type_t op_type,
	uint32_t **op_uids,
	uint32_t *num_of_ops,
	uint32_t *size
)
{
	int ec = 0;

	*num_of_ops = 0;

	ec = qry_and_match(
	    op_uids, num_of_ops, size, op_type,
	    uid, src_type, NULL);

	return (ec);
}

int
get_qry_ops2(
	uint32_t *nodes_bmp,
	uint32_t num_of_nodes,
	isns_type_t op_type,
	uint32_t **op_uids,
	uint32_t *num_of_ops,
	uint32_t *size
)
{
	int ec = 0;

	uint32_t node_uid;

	htab_t *htab;

	*num_of_ops = 0;

	if (nodes_bmp != NULL) {
		FOR_EACH_MEMBER(nodes_bmp, num_of_nodes, node_uid, {
			ec = qry_and_match(
			    op_uids, num_of_ops, size, op_type,
			    node_uid, OBJ_ISCSI, NULL);
			if (ec != 0) {
				return (ec);
			}
		});
	} else {
		node_uid = 0;
		htab = cache_get_htab(OBJ_ISCSI);
		FOR_EACH_ITEM(htab, node_uid, {
			ec = qry_and_match(
			    op_uids, num_of_ops, size, op_type,
			    node_uid, OBJ_ISCSI, NULL);
			if (ec != 0) {
				return (ec);
			}
		});
	}

	return (ec);
}

uint32_t
get_next_obj(
	isns_tlv_t *tlv,
	uint32_t tlv_len,
	isns_type_t type,
	uint32_t *uids,
	uint32_t num
)
{
	lookup_ctrl_t lc;

	uint32_t tag;
	uint8_t *value;

	uint32_t old = 0;
	uint32_t min = 0;
	uint32_t uid, diff;
	uint32_t pre_diff = 0xFFFFFFFF;

	lc.curr_uid = 0;
	lc.type = type;
	lc.op[1] = 0;
	lc.op[2] = 0;

	if (tlv_len > 8) {
		tag = tlv->attr_id;
		value = tlv->attr_value;
		switch (tag) {
		case ISNS_EID_ATTR_ID:
			lc.id[0] = ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID);
			lc.op[0] = OP_STRING;
			lc.data[0].ptr = (uchar_t *)value;
			break;
		case ISNS_ISCSI_NAME_ATTR_ID:
			lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
			lc.op[0] = OP_STRING;
			lc.data[0].ptr = (uchar_t *)value;
			break;
		case ISNS_ISCSI_NODE_INDEX_ATTR_ID:
			lc.id[0] = ATTR_INDEX_ISCSI(
			    ISNS_ISCSI_NODE_INDEX_ATTR_ID);
			lc.op[0] = OP_INTEGER;
			lc.data[0].ui = ntohl(*(uint32_t *)value);
			break;
		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
			lc.id[0] = ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_IP_ADDR_ATTR_ID);
			lc.op[0] = OP_MEMORY_IP6;
			lc.data[0].ip = (in6_addr_t *)value;
			NEXT_TLV(tlv, tlv_len);
			if (tlv_len > 8 &&
			    ((tag = tlv->attr_id) ==
			    ISNS_PORTAL_PORT_ATTR_ID)) {
				value = tlv->attr_value;
				lc.id[1] = ATTR_INDEX_PORTAL(
				    ISNS_PORTAL_PORT_ATTR_ID);
				lc.op[1] = OP_INTEGER;
				lc.data[1].ui = ntohl(*(uint32_t *)value);
			} else {
				return (0);
			}
			break;
		case ISNS_PORTAL_INDEX_ATTR_ID:
			lc.id[0] = ATTR_INDEX_PORTAL(ISNS_PORTAL_INDEX_ATTR_ID);
			lc.op[0] = OP_INTEGER;
			lc.data[0].ui = ntohl(*(uint32_t *)value);
			break;
		case ISNS_PG_INDEX_ATTR_ID:
			lc.id[0] = ATTR_INDEX_PG(ISNS_PG_INDEX_ATTR_ID);
			lc.op[0] = OP_INTEGER;
			lc.data[0].ui = ntohl(*(uint32_t *)value);
			break;
		default:
			return (0);
		}

		old = is_obj_there(&lc);
		if (old == 0) {
			return (0);
		}
	}

	while (num > 0) {
		uid = uids[-- num];
		if (uid > old) {
			diff = uid - old;
			if (diff < pre_diff) {
				min = uid;
				pre_diff = diff;
			}
		}
	}

	return (min);
}

static int
cb_qry_rsp(
	void *p1,
	void *p2
)
{
	int ec = 0;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	uint16_t tlv_len = lcp->id[1];
	isns_tlv_t *tlv = (isns_tlv_t *)lcp->data[1].ptr;
	conn_arg_t *conn = (conn_arg_t *)lcp->data[2].ptr;

	isns_type_t type = obj->type;
	uint32_t min_tag = TAG_RANGE[type][0];
	uint32_t mid_tag = TAG_RANGE[type][1];
	uint32_t max_tag = TAG_RANGE[type][2];

	isns_attr_t *attr;
	uint32_t tag;
	uint32_t id;
	uint32_t len;
	void *value;

	isns_pdu_t *rsp = conn->out_packet.pdu;
	size_t pl = conn->out_packet.pl;
	size_t sz = conn->out_packet.sz;

	do {
		if (tlv->attr_len == 0) {
			tag = tlv->attr_id;
			if (tag <= mid_tag) {
				id = ATTR_INDEX(tag, type);
				attr = &obj->attrs[id];
				len = attr->len;
				value = (void *)attr->value.ptr;
				ec = pdu_add_tlv(&rsp, &pl, &sz,
				    tag, len, value, 0);
			}
		}
		NEXT_TLV(tlv, tlv_len);
	} while (ec == 0 &&
	    tlv_len >= 8 &&
	    tlv->attr_id >= min_tag &&
	    tlv->attr_id <= max_tag);

	conn->out_packet.pdu = rsp;
	conn->out_packet.pl = pl;
	conn->out_packet.sz = sz;

	return (ec);
}

int
get_qry_attrs(
	uint32_t uid,
	isns_type_t type,
	isns_tlv_t *tlv,
	uint16_t tlv_len,
	conn_arg_t *conn
)
{
	int ec = 0;

	lookup_ctrl_t lc;

	SET_UID_LCP(&lc, type, uid);

	lc.id[1] = tlv_len;
	lc.data[1].ptr = (uchar_t *)tlv;
	lc.data[2].ptr = (uchar_t *)conn;

	ec = cache_lookup(&lc, NULL, cb_qry_rsp);

	return (ec);
}

int
get_qry_attrs1(
	uint32_t uid,
	isns_type_t type,
	isns_tlv_t *tlv,
	uint16_t tlv_len,
	conn_arg_t *conn
)
{
	isns_tlv_t *tmp = tlv;
	uint32_t tmp_len = tlv_len;

	/* clear the length of all of tlv */
	while (tmp_len > 8) {
		tmp->attr_len = 0;
		NEXT_TLV(tmp, tmp_len);
	}

	return (get_qry_attrs(uid, type, tlv, tlv_len, conn));
}
