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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "isns_server.h"
#include "isns_msgq.h"
#include "isns_htab.h"
#include "isns_cache.h"
#include "isns_pdu.h"
#include "isns_obj.h"
#include "isns_dd.h"
#include "isns_func.h"
#include "isns_dseng.h"
#include "isns_log.h"
#include "isns_scn.h"
#include "isns_utils.h"
#include "isns_esi.h"

/*
 * external variables
 */
#ifdef DEBUG
extern int verbose_mc;
extern void print_object(char *, isns_obj_t *);
#endif

extern msg_queue_t *sys_q;
extern msg_queue_t *scn_q;

extern pthread_mutex_t el_mtx;

extern int cache_flag;

/*
 * global data
 */

/*
 * local variables
 */
/* type of parent object */
const int TYPE_OF_PARENT[MAX_OBJ_TYPE_FOR_SIZE] = {
	0,
	0,
	ISCSI_PARENT_TYPE,
	PORTAL_PARENT_TYPE,
	PG_PARENT_TYPE,
	0,	/* OBJ_DD */
	0,	/* OBJ_DDS */
	0,	/* MAX_OBJ_TYPE */
	0,	/* OBJ_DUMMY1 */
	0,	/* OBJ_DUMMY2 */
	0,	/* OBJ_DUMMY3 */
	0,	/* OBJ_DUMMY4 */
	ASSOC_ISCSI_PARENT_TYPE,
	ASSOC_DD_PARENT_TYPE
};

/* number of children object type */
const int NUM_OF_CHILD[MAX_OBJ_TYPE] = {
	0,
	MAX_ENTITY_CHILD,
	MAX_ISCSI_CHILD,
	MAX_PORTAL_CHILD,
	MAX_PG_CHILD,
	0,
	0
};

/* type of a child object */
const int TYPE_OF_CHILD[MAX_OBJ_TYPE][MAX_CHILD_TYPE] = {
	{ 0, 0 },
	{ OBJ_ISCSI, OBJ_PORTAL },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 }
};

/* number of attributes of certain type of object */
const int NUM_OF_ATTRS[MAX_OBJ_TYPE_FOR_SIZE] = {
	0,
	NUM_OF_ENTITY_ATTRS,
	NUM_OF_ISCSI_ATTRS,
	NUM_OF_PORTAL_ATTRS,
	NUM_OF_PG_ATTRS,
	NUM_OF_DD_ATTRS,
	NUM_OF_DDS_ATTRS,
	0,			/* MAX_OBJ_TYPE */
	0,			/* OBJ_DUMMY1 */
	0,			/* OBJ_DUMMY2 */
	0,			/* OBJ_DUMMY3 */
	0,			/* OBJ_DUMMY4 */
	NUM_OF_ASSOC_ISCSI_ATTRS,
	NUM_OF_ASSOC_DD_ATTRS
};

/* the tag of UID of each type of object */
static const int UID_TAG[MAX_OBJ_TYPE_FOR_SIZE] = {
	0,
	ISNS_ENTITY_INDEX_ATTR_ID,
	ISNS_ISCSI_NODE_INDEX_ATTR_ID,
	ISNS_PORTAL_INDEX_ATTR_ID,
	ISNS_PG_INDEX_ATTR_ID,
	ISNS_DD_ID_ATTR_ID,
	ISNS_DD_SET_ID_ATTR_ID,
	0,			/* MAX_OBJ_TYPE */
	0,			/* OBJ_DUMMY1 */
	0,			/* OBJ_DUMMY2 */
	0,			/* OBJ_DUMMY3 */
	0,			/* OBJ_DUMMY4 */
	ISNS_DD_ISCSI_INDEX_ATTR_ID,
	ISNS_DD_ID_ATTR_ID
};

/* the index of UID of each type of object */
const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE] = {
	0,
	ATTR_INDEX_ENTITY(ISNS_ENTITY_INDEX_ATTR_ID),
	ATTR_INDEX_ISCSI(ISNS_ISCSI_NODE_INDEX_ATTR_ID),
	ATTR_INDEX_PORTAL(ISNS_PORTAL_INDEX_ATTR_ID),
	ATTR_INDEX_PG(ISNS_PG_INDEX_ATTR_ID),
	ATTR_INDEX_DD(ISNS_DD_ID_ATTR_ID),
	ATTR_INDEX_DDS(ISNS_DD_SET_ID_ATTR_ID),
	0,			/* MAX_OBJ_TYPE */
	0,			/* OBJ_DUMMY1 */
	0,			/* OBJ_DUMMY2 */
	0,			/* OBJ_DUMMY3 */
	0,			/* OBJ_DUMMY4 */
	ATTR_INDEX_ASSOC_ISCSI(ISNS_DD_ISCSI_INDEX_ATTR_ID),
	ATTR_INDEX_ASSOC_DD(ISNS_DD_ID_ATTR_ID)
};

/* the index of the key attributes of each type of object */
static const int KEY_ATTR_INDEX[MAX_OBJ_TYPE][MAX_KEY_ATTRS] = {
	{ 0 },
	{ ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID), 0 },
	{ ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID),
		0 },
	{ ATTR_INDEX_PORTAL(ISNS_PORTAL_IP_ADDR_ATTR_ID),
		ATTR_INDEX_PORTAL(ISNS_PORTAL_PORT_ATTR_ID),
		0 },
	{ ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID),
		ATTR_INDEX_PG(ISNS_PG_PORTAL_IP_ADDR_ATTR_ID),
		ATTR_INDEX_PG(ISNS_PG_PORTAL_PORT_ATTR_ID) },
	{ ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID), 0 },
	{ ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID), 0 }
};

/* the operating methods for key attributes of each type of object */
static const int KEY_ATTR_OP[MAX_OBJ_TYPE][MAX_KEY_ATTRS] = {
	{ 0 },
	{ OP_STRING, 0 },
	{ OP_STRING, 0 },
	{ OP_MEMORY_IP6, OP_INTEGER, 0 },
	{ OP_STRING, OP_MEMORY_IP6, OP_INTEGER },
	{ OP_STRING, 0 },
	{ OP_STRING, 0 }
};

/* the size of each type of object */
static const int SIZEOF_OBJ[MAX_OBJ_TYPE_FOR_SIZE] = {
	0,
	sizeof (isns_entity_t),
	sizeof (isns_iscsi_t),
	sizeof (isns_portal_t),
	sizeof (isns_pg_t),
	sizeof (isns_dd_t),
	sizeof (isns_dds_t),
	0,
	0,
	0,
	0,
	0,
	sizeof (isns_assoc_iscsi_t),
	sizeof (isns_assoc_dd_t)
};

#ifdef DEBUG
const int NUM_OF_REF[MAX_OBJ_TYPE_FOR_SIZE] = {
#else
static const int NUM_OF_REF[MAX_OBJ_TYPE_FOR_SIZE] = {
#endif
	0,
	0,
	0,
	0,
	PG_REF_COUNT,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0
};

/* the type of the reference object */
static const int TYPE_OF_REF[MAX_OBJ_TYPE][MAX_REF_COUNT + 1] = {
	{ 0 },
	{ 0 },
	{ OBJ_PG, OBJ_PORTAL, 0 },
	{ OBJ_PG, OBJ_ISCSI, 0 },
	{ 0, OBJ_ISCSI, OBJ_PORTAL },
	{ 0 },
	{ 0 }
};

/* the operating method for match operation of the reference object */
#define	MAX_REF_MATCH	(2)
static const int REF_MATCH_OPS[MAX_OBJ_TYPE][MAX_REF_MATCH] = {
	{ 0, 0 },
	{ 0, 0 },
	{ OP_STRING, 0 },
	{ OP_MEMORY_IP6, OP_INTEGER },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 }
};

/* the index of the attribute of being matched object */
static const int REF_MATCH_ID1[MAX_OBJ_TYPE][MAX_REF_MATCH] = {
	{ 0, 0 },
	{ 0, 0 },
	{ ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID), 0 },
	{ ATTR_INDEX_PORTAL(ISNS_PORTAL_IP_ADDR_ATTR_ID),
		ATTR_INDEX_PORTAL(ISNS_PORTAL_PORT_ATTR_ID) },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 }
};

/* the index of the attribute of matching object */
static const int REF_MATCH_ID2[MAX_OBJ_TYPE][MAX_REF_MATCH] = {
	{ 0, 0 },
	{ 0, 0 },
	{ ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID), 0 },
	{ ATTR_INDEX_PG(ISNS_PG_PORTAL_IP_ADDR_ATTR_ID),
		ATTR_INDEX_PG(ISNS_PG_PORTAL_PORT_ATTR_ID) },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 }
};

/*
 * local functions.
 */
static uint32_t get_reg_period();
static char *make_unique_name(int *, uint32_t);
static lookup_ctrl_t *set_lookup_ctrl(lookup_ctrl_t *, isns_obj_t *);
static int setup_ref_lcp(lookup_ctrl_t *,
	const isns_obj_t *, const isns_obj_t *);
static int setup_deref_lcp(lookup_ctrl_t *,
	const isns_obj_t *, isns_type_t);
static int cb_get_parent(void *, void *);
static int cb_node_child(void *, void *);
static int cb_set_ref(void *, void *);
static int cb_clear_ref(void *, void *);
static int cb_add_child(void *, void *);
static int cb_remove_child(void *, void *);
static int cb_verify_ref(void *, void *);
static int cb_ref_new2old(void *, void *);
static int cb_new_ref(void *, void *);
static int ref_new2old(
	lookup_ctrl_t *, isns_type_t, uint32_t, const isns_obj_t *);
static int ref_new2new(
	lookup_ctrl_t *, const isns_obj_t *, const isns_obj_t *);
static int new_ref(const isns_obj_t *, const isns_obj_t *);
static uint32_t setup_parent_lcp(lookup_ctrl_t *, isns_obj_t *);
static int set_obj_offline(isns_obj_t *);
static int copy_attrs(isns_obj_t *, const isns_obj_t *);

static isns_obj_t *make_default_pg(const isns_obj_t *, const isns_obj_t *);
static isns_obj_t *(*const make_ref[MAX_OBJ_TYPE])
	(const isns_obj_t *, const isns_obj_t *) = {
		NULL,
		NULL,
		&make_default_pg,
		&make_default_pg,
		NULL,
		NULL,
		NULL
};

static uint32_t entity_hval(void *, uint16_t, uint32_t *);
static uint32_t iscsi_hval(void *, uint16_t, uint32_t *);
static uint32_t portal_hval(void *, uint16_t, uint32_t *);
static uint32_t pg_hval(void *, uint16_t, uint32_t *);
static uint32_t dd_hval(void *, uint16_t, uint32_t *);
static uint32_t dds_hval(void *, uint16_t, uint32_t *);
static uint32_t (*const hval_func[MAX_OBJ_TYPE])
	(void *, uint16_t, uint32_t *) = {
		NULL,
		&entity_hval,
		&iscsi_hval,
		&portal_hval,
		&pg_hval,
		&dd_hval,
		&dds_hval
};

/*
 * ****************************************************************************
 *
 * entity_hval:
 *	caculate the hash value of a network entity object.
 *
 * p	- the pointer pointers to network entity object or
 *	  the lookup control data, both have the key attribute
 *	  of a network entity object.
 * chunk- which chunk of the hash table.
 * flags- pointer to flags.
 * return - the hash value.
 *
 * ****************************************************************************
 */
static uint32_t
entity_hval(
	void *p,
	/* LINTED E_FUNC_ARG_UNUSED */
	uint16_t chunk,
	uint32_t *flags
)
{
	uchar_t *key;
	isns_obj_t *obj;
	lookup_ctrl_t *lcp;

	if ((*flags & FLAGS_CTRL_MASK) == 0) {
		/* p pointers to a network entity object */
		obj = (isns_obj_t *)p;
		key = obj->attrs[ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID)].
		    value.ptr;
	} else {
		/* p is lookup control data */
		lcp = (lookup_ctrl_t *)p;
		key = lcp->data[0].ptr;
	}

	return (htab_compute_hval(key));
}

/*
 * ****************************************************************************
 *
 * iscsi_hval:
 *	caculate the hash value of an iscsi storage node object.
 *
 * p	- the pointer pointers to iscsi storage node object or
 *	  the lookup control data, both have the key attribute
 *	  of an iscsi storage node object.
 * chunk- which chunk of the hash table.
 * flags- pointer to flags.
 * return - the hash value.
 *
 * ****************************************************************************
 */
static uint32_t
iscsi_hval(
	void *p,
	/* LINTED E_FUNC_ARG_UNUSED */
	uint16_t chunk,
	uint32_t *flags
)
{
	uchar_t *key;
	isns_obj_t *obj;
	lookup_ctrl_t *lcp;

	if ((*flags & FLAGS_CTRL_MASK) == 0) {
		/* p pointers to an iscsi storage node object */
		obj = (isns_obj_t *)p;
		key = obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)].
		    value.ptr;
	} else {
		/* p is lookup control data */
		lcp = (lookup_ctrl_t *)p;
		key = lcp->data[0].ptr;
	}

	return (htab_compute_hval(key));
}

/*
 * ****************************************************************************
 *
 * portal_hval:
 *	caculate the hash value of a portal object.
 *
 * p	- the pointer pointers to a portal object or the lookup control
 *	  data, both have the key attributes of a portal object.
 * chunk- which chunk of the hash table.
 * flags- pointer to flags.
 * return - the hash value.
 *
 * ****************************************************************************
 */
static uint32_t
portal_hval(
	void *p,
	/* LINTED E_FUNC_ARG_UNUSED */
	uint16_t chunk,
	uint32_t *flags
)
{
	char buff[INET6_ADDRSTRLEN + 8] = { 0 };
	char buff2[8] = { 0 };
	uchar_t *key;
	isns_obj_t *obj;
	lookup_ctrl_t *lcp;

	in6_addr_t *ip;
	uint32_t port;

	if ((*flags & FLAGS_CTRL_MASK) == 0) {
		/* p pointers to a portal object */
		obj = (isns_obj_t *)p;
		ip = obj->attrs[ATTR_INDEX_PORTAL
		    (ISNS_PORTAL_IP_ADDR_ATTR_ID)].value.ip;
		port = obj->attrs[ATTR_INDEX_PORTAL
		    (ISNS_PORTAL_PORT_ATTR_ID)].value.ui;
	} else {
		/* p is lookup control data */
		lcp = (lookup_ctrl_t *)p;
		ip = lcp->data[0].ip;
		port = lcp->data[1].ui;
	}

	key = (uchar_t *)inet_ntop(AF_INET6, (void *)ip,
	    buff, sizeof (buff));
	(void) snprintf(buff2, sizeof (buff2), "%d", port);
	(void) strcat((char *)key, buff2);

	return (htab_compute_hval(key));
}

/*
 * ****************************************************************************
 *
 * pg_hval:
 *	caculate the hash value of a portal group object.
 *
 * p	- the pointer pointers to a portal group object or the lookup
 *	  control data, both have the key attributes of a portal object.
 * chunk- which chunk of the hash table.
 * flags- pointer to flags.
 * return - the hash value.
 *
 * ****************************************************************************
 */
static uint32_t
pg_hval(
	void *p,
	uint16_t chunk,
	uint32_t *flags
)
{
	char buff[INET6_ADDRSTRLEN + 8] = { 0 };
	char buff2[8] = { 0 };
	uchar_t *key = NULL;
	isns_obj_t *obj;
	lookup_ctrl_t *lcp;

	in6_addr_t *ip = NULL;
	uint32_t port;

	if ((*flags & FLAGS_CTRL_MASK) == 0) {
		/* p is a portal group object */
		obj = (isns_obj_t *)p;
		if (chunk == 0) {
			/* the first chunk */
			key = obj->attrs[ATTR_INDEX_PG
			    (ISNS_PG_ISCSI_NAME_ATTR_ID)].value.ptr;
		} else {
			/* another chunk */
			ip = obj->attrs[ATTR_INDEX_PG
			    (ISNS_PG_PORTAL_IP_ADDR_ATTR_ID)].value.ip;
			port = obj->attrs[ATTR_INDEX_PG
			    (ISNS_PG_PORTAL_PORT_ATTR_ID)].value.ui;
		}
	} else {
		/* p is a lookup control data */
		lcp = (lookup_ctrl_t *)p;
		/* clear the chunk flags */
		*flags &= ~FLAGS_CHUNK_MASK;
		if (lcp->op[0] == OP_STRING) {
			/* the first chunk */
			key = lcp->data[0].ptr;
		} else {
			/* another chunk */
			ip = lcp->data[0].ip;
			port = lcp->data[1].ui;
			*flags |= 1;
		}
	}

	if (key == NULL) {
		key = (uchar_t *)inet_ntop(AF_INET6, (void *)ip,
		    buff, sizeof (buff));
		(void) snprintf(buff2, sizeof (buff2), "%d", port);
		(void) strcat((char *)key, buff2);
	}

	return (htab_compute_hval(key));
}

/*
 * ****************************************************************************
 *
 * dd_hval:
 *	caculate the hash value of a DD object.
 *
 * p	- the pointer pointers to a DD object or the lookup control data,
 *	  both have the key attributes of a DD object.
 * chunk- which chunk of the hash table.
 * flags- pointer to flags.
 * return - the hash value.
 *
 * ****************************************************************************
 */
static uint32_t
dd_hval(
	void *p,
	/* LINTED E_FUNC_ARG_UNUSED */
	uint16_t chunk,
	uint32_t *flags
)
{
	uchar_t *key;
	isns_obj_t *obj;
	lookup_ctrl_t *lcp;

	if ((*flags & FLAGS_CTRL_MASK) == 0) {
		/* p is a DD object */
		obj = (isns_obj_t *)p;
		key = obj->attrs[ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID)].
		    value.ptr;
	} else {
		/* p is a lookup control data */
		lcp = (lookup_ctrl_t *)p;
		key = lcp->data[0].ptr;
	}

	return (htab_compute_hval(key));
}

/*
 * ****************************************************************************
 *
 * dds_hval:
 *	caculate the hash value of a DD-set object.
 *
 * p	- the pointer pointers to a DD-set object or the lookup control data,
 *	  both have the key attributes of a DD-set object.
 * chunk- which chunk of the hash table.
 * flags- pointer to flags.
 * return - the hash value.
 *
 * ****************************************************************************
 */
static uint32_t
dds_hval(
	void *p,
	/* LINTED E_FUNC_ARG_UNUSED */
	uint16_t chunk,
	uint32_t *flags
)
{
	uchar_t *key;
	isns_obj_t *obj;
	lookup_ctrl_t *lcp;

	if ((*flags & FLAGS_CTRL_MASK) == 0) {
		/* p is a DD-set object */
		obj = (isns_obj_t *)p;
		key = obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID)].
		    value.ptr;
	} else {
		/* p is lookup control data */
		lcp = (lookup_ctrl_t *)p;
		key = lcp->data[0].ptr;
	}

	return (htab_compute_hval(key));
}

/*
 * ****************************************************************************
 *
 * obj_hval:
 *	caculate the hash value of an object.
 *
 * p	- the pointer pointers to an object or lookup control data,
 *	  both has the object type and the key attributes of an object.
 * chunk- which chunk of the hash table.
 * flags- pointer to flags.
 * return - the hash value.
 *
 * ****************************************************************************
 */
uint32_t
obj_hval(
	void *p,
	uint16_t chunk,
	uint32_t *flags
)
{
	isns_type_t type = ((isns_obj_t *)p)->type;

	return (hval_func[type](p, chunk, flags));
}

/*
 * ****************************************************************************
 *
 * get_obj_uid:
 *	get the UID of an object.
 *
 * p	- the pointer pointers to an object.
 * return - the UID.
 *
 * ****************************************************************************
 */
uint32_t
get_obj_uid(
	const void *p
)
{
	isns_obj_t *obj = (isns_obj_t *)p;
	isns_attr_t *attr = &obj->attrs[UID_ATTR_INDEX[obj->type]];
	uint32_t uid = attr->value.ui;
	return (uid);
}

/*
 * ****************************************************************************
 *
 * set_obj_uid:
 *	set the UID of an object.
 *
 * p	- the pointer pointers to an object.
 * uid	- the UID.
 * return - the UID.
 *
 * ****************************************************************************
 */
uint32_t
set_obj_uid(
	void *p,
	uint32_t uid
)
{
	isns_obj_t *obj = (isns_obj_t *)p;
	isns_attr_t *attr = &obj->attrs[UID_ATTR_INDEX[obj->type]];

	/* set the tag, len and value */
	attr->tag = UID_TAG[obj->type];
	attr->len = 4;
	attr->value.ui = uid;

	return (uid);
}

/*
 * ****************************************************************************
 *
 * obj_cmp:
 *	compare between two objects or an object with a lookup control data.
 *
 * p1	- the pointer points to an object.
 * p2	- the pointer points to an object or a lookup control data.
 * flags- 0: p2 is an object; otherwise p2 is a lookup control data.
 * return - the comparsion result.
 *
 * ****************************************************************************
 */
int
obj_cmp(
	void *p1,
	void *p2,
	int flags
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t buff = { 0 };
	lookup_ctrl_t *lcp;
	uint32_t uid;

	if (flags == 0) {
		lcp = set_lookup_ctrl(&buff, (isns_obj_t *)p2);
	} else {
		lcp = (lookup_ctrl_t *)p2;
		uid = get_obj_uid(obj);
		/* the object are linked with decending order by */
		/* the object UID, if the object UID is greater than */
		/* or equal to the current UID, it needs to compare */
		/* for the next one. */
		if (lcp->curr_uid != 0 && uid >= lcp->curr_uid) {
			return (-1);
		}
	}

	return (key_cmp(lcp, obj));
}

/*
 * ****************************************************************************
 *
 * replace_object:
 *	replace an existing object with the new one.
 *
 * p1	- the pointer points to an object being replaced.
 * p2	- the pointer points to a new object.
 * uid_p- points to uid for returning.
 * flag	- 0: do not free the source object, otherwise free it.
 * return - error code.
 *
 * ****************************************************************************
 */
int
replace_object(
	void *p1,
	void *p2,
	uint32_t *uid_p,
	int flag
)
{
	int ec = 0;

#ifndef SKIP_SRC_AUTH
	uint32_t *pp_dst, *pp_src, swap;
#endif
	int online;

	isns_obj_t *dst = (isns_obj_t *)p1;
	isns_obj_t *src = (isns_obj_t *)p2;

	if (src->type == OBJ_DD || src->type == OBJ_DDS) {
		/* replace not allowed */
		return (ERR_NAME_IN_USE);
	}

	online = is_obj_online(dst);

	/* set cache update flag */
	SET_CACHE_UPDATED();

	/* update parent uid */
#ifndef SKIP_SRC_AUTH
	pp_dst = get_parent_p(dst);
	if (pp_dst != NULL) {
		pp_src = get_parent_p(src);
		swap = *pp_dst;
		*pp_dst = *pp_src;
		if (swap != 0) {
			*pp_src = swap;
		}
	}
#endif

	/* update all of attributes */
	if (copy_attrs(dst, src) != 0) {
		return (ISNS_RSP_INTERNAL_ERROR);
	}

	/* free up the src object */
	if (flag != 0) {
		(void) free_object(src);
	} else if (online == 0) {
		(void) set_obj_uid(src, get_obj_uid(dst));
		(void) set_obj_offline(src);
	}

	/* update data store */
	if (sys_q != NULL) {
		ec = write_data(DATA_UPDATE, dst);
	} else {
		/* we should never have duplicated entry in data store */
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	/* trigger a scn */
	if (ec == 0) {
		if (scn_q != NULL) {
			(void) make_scn((online == 0) ?
			    ISNS_OBJECT_ADDED :
			    ISNS_OBJECT_UPDATED,
			    dst);
		}
		if (uid_p != NULL) {
			*uid_p = get_obj_uid(dst);
		}
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * add_object:
 *	post function after adding a new object.
 *
 * p	- object which has been added.
 * return - error code.
 *
 * ****************************************************************************
 */
int
add_object(
	void *p
)
{
	int ec = 0;

	isns_obj_t *obj = (isns_obj_t *)p;

	/* add the new object to data store */
	if (sys_q != NULL) {
		ec = write_data(DATA_ADD, obj);
	}

	/* trigger a scn */
	if (ec == 0 && scn_q != NULL) {
		(void) make_scn(ISNS_OBJECT_ADDED, obj);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * obj_tab_init:
 *	initialize the object hash tables.
 *
 * c	- points to the cache.
 * return - error code.
 *
 * ****************************************************************************
 */
int
obj_tab_init(
	struct cache *c
)
{
	htab_t *t;

	htab_init();

	/*
	 * allocate an array of pointer for the object hash tables.
	 */
	c->t = (struct htab **)calloc(sizeof (struct htab *), MAX_OBJ_TYPE);
	if (c->t == NULL) {
		return (1);
	}

	/*
	 * hash table for network entity objects.
	 */
	t = htab_create(UID_FLAGS_SEQ, 8, 1);
	if (t != NULL) {
		t->c = c;
		c->t[OBJ_ENTITY] = t;
	} else {
		return (1);
	}

	/*
	 * hash table for iscsi storage node objects.
	 */
	t = htab_create(UID_FLAGS_SEQ, 8, 1);
	if (t != NULL) {
		t->c = c;
		c->t[OBJ_ISCSI] = t;
	} else {
		return (1);
	}

	/*
	 * hash table for portal objects.
	 */
	t = htab_create(UID_FLAGS_SEQ, 8, 1);
	if (t != NULL) {
		t->c = c;
		c->t[OBJ_PORTAL] = t;
	} else {
		return (1);
	}

	/*
	 * hash table for portal group objects.
	 */
	t = htab_create(UID_FLAGS_SEQ, 8, 2);
	if (t != NULL) {
		t->c = c;
		c->t[OBJ_PG] = t;
	} else {
		return (1);
	}

	/*
	 * hash table for discovery domain objects.
	 */
	t = htab_create(0, 6, 1);
	if (t != NULL) {
		t->c = c;
		c->t[OBJ_DD] = t;
	} else {
		return (1);
	}

	/*
	 * hash table for discovery domain set objects.
	 */
	t = htab_create(0, 4, 1);
	if (t != NULL) {
		t->c = c;
		c->t[OBJ_DDS] = t;
	} else {
		return (1);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * get_ref_np:
 *	get the ref pointer of the portal group object.
 *
 * obj	- portal group object.
 * return - ref pointer.
 *
 * ****************************************************************************
 */
static uint32_t *
get_ref_np(
	isns_obj_t *obj,
	int n
)
{
	uint32_t *refp =
	    obj->type == OBJ_PG ? &((isns_pg_t *)obj)->ref[n] : NULL;

	return (refp);
}

#ifdef DEBUG
uint32_t
#else
static uint32_t
#endif
get_ref_n(
	isns_obj_t *obj,
	int n
)
{
	return (*get_ref_np(obj, n));
}

static uint32_t *
get_ref_p(
	isns_obj_t *obj,
	isns_type_t rt
)
{
	isns_type_t t = obj->type;

	int i = 0;
	while (i < NUM_OF_REF[t]) {
		if (rt == TYPE_OF_REF[t][i + 1]) {
			return (get_ref_np(obj, i));
		}
		i ++;
	}

	return (NULL);
}

uint32_t
get_ref_t(
	isns_obj_t *obj,
	isns_type_t type
)
{
	uint32_t *refp = get_ref_p(obj, type);

	if (refp != NULL) {
		return (*refp);
	/* LINTED E_NOP_ELSE_STMT */
	} else {
		ASSERT(0);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * get_parent_p:
 *	get the pointer of the parent object.
 *
 * obj	- an object.
 * return - parent object pointer.
 *
 * ****************************************************************************
 */
uint32_t *const
get_parent_p(
	const isns_obj_t *obj
)
{
	uint32_t *pp;
	switch (obj->type) {
	case OBJ_ISCSI:
		pp = &((isns_iscsi_t *)obj)->puid;
		break;
	case OBJ_PORTAL:
		pp = &((isns_portal_t *)obj)->puid;
		break;
	case OBJ_PG:
		pp = &((isns_pg_t *)obj)->puid;
		break;
	case OBJ_ASSOC_ISCSI:
		pp = &((isns_assoc_iscsi_t *)obj)->puid;
		break;
	case OBJ_ASSOC_DD:
		pp = &((isns_assoc_dd_t *)obj)->puid;
		break;
	default:
		pp = NULL;
		break;
	}

	return (pp);
}

uint32_t
get_parent_uid(
	const isns_obj_t *obj
)
{
	uint32_t *pp = get_parent_p(obj);
	if (pp != NULL) {
		return (*pp);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * get_child_np:
 *	get the pointer of the UID array of the n'th child of an object.
 *
 * obj	- an object.
 * n	- the child index.
 * return - the pointer of the UID array.
 *
 * ****************************************************************************
 */
static uint32_t **
get_child_np(
	isns_obj_t *obj,
	int n
)
{
	uint32_t **pp =
	    obj->type == OBJ_ENTITY ? &((isns_entity_t *)obj)->cuid[n] : NULL;

	return (pp);
}

/*
 * ****************************************************************************
 *
 * get_child_n:
 *	get the UID array of the n'th child of an object.
 *
 * obj	- an object.
 * n	- the child index.
 * return - the UID array.
 *
 * ****************************************************************************
 */
#ifdef DEBUG
uint32_t *
#else
static uint32_t *
#endif
get_child_n(
	isns_obj_t *obj,
	int n
)
{
	uint32_t **pp = get_child_np(obj, n);

	if (pp != NULL) {
		return (*pp);
	}

	ASSERT(0);
	return (NULL);
}

/*
 * ****************************************************************************
 *
 * get_child_p:
 *	get the pointer of the UID array of the child matching the type.
 *
 * base	- an object.
 * child_type	- the child object type.
 * return - the pointer of the UID array.
 *
 * ****************************************************************************
 */
static uint32_t **
get_child_p(
	isns_obj_t *base,
	int child_type
)
{
	uint32_t **pp = NULL;
	int i = 0;
	while (i < NUM_OF_CHILD[base->type]) {
		if (child_type == TYPE_OF_CHILD[base->type][i]) {
			pp = get_child_np(base, i);
			break;
		}
		i ++;
	}

	return (pp);
}

/*
 * ****************************************************************************
 *
 * get_child_t:
 *	get the UID array of the child object matching the type.
 *
 * base	- an object.
 * child_type	- the child object type.
 * return - the UID array.
 *
 * ****************************************************************************
 */
uint32_t *
get_child_t(
	isns_obj_t *base,
	int child_type
)
{
	uint32_t **pp = get_child_p(base, child_type);

	if (pp != NULL) {
		return (*pp);
	} else {
		return (NULL);
	}
}

/*
 * ****************************************************************************
 *
 * key_cmp:
 *	compare the object against the lookup control data.
 *
 * lcp	- the lookup control data.
 * obj	- an object.
 * return - comparison result.
 *
 * ****************************************************************************
 */
int
key_cmp(
	lookup_ctrl_t *lcp,
	isns_obj_t *obj
)
{
	int i = 0;
	int match = 1;
	while (i < MAX_LOOKUP_CTRL && lcp->op[i] > 0 && match) {
		isns_attr_t *attr = &obj->attrs[lcp->id[i]];
		switch (lcp->op[i]) {
			case OP_STRING:
				match = (strcmp((const char *)lcp->data[i].ptr,
				    (const char *)attr->value.ptr) == 0);
				break;
			case OP_INTEGER:
				match = (lcp->data[i].ui == attr->value.ui);
				break;
			case OP_MEMORY_IP6:
				match = !memcmp((void *)lcp->data[i].ip,
				    (void *)attr->value.ip,
				    sizeof (in6_addr_t));
				break;
			default:
				ASSERT(0);
				match = 0;
				break;
		}
		i ++;
	}

	if (i && match) {
		return (0);
	} else {
		return (1);
	}
}

/*
 * ****************************************************************************
 *
 * set_lookup_ctrl:
 *	fill in the lookup control data for an object.
 *
 * lcp	- the lookup control data.
 * obj	- an object.
 * return - the lookup control data.
 *
 * ****************************************************************************
 */
static lookup_ctrl_t *
set_lookup_ctrl(
	lookup_ctrl_t *lcp,
	isns_obj_t *obj
)
{
	isns_type_t type = obj->type;
	uint32_t id, op;
	int i = 0;

	lcp->type = type;
	while (i < MAX_KEY_ATTRS) {
		op = KEY_ATTR_OP[type][i];
		if (op != 0) {
			id = KEY_ATTR_INDEX[type][i];
			lcp->id[i] = id;
			lcp->op[i] = op;
			lcp->data[i].ui = obj->attrs[id].value.ui;
		} else {
			break;
		}
		i ++;
	}

	return (lcp);
}

/*
 * ****************************************************************************
 *
 * assign_attr:
 *	assign an attribute.
 *
 * attr	- the attribute being assigned.
 * tmp	- the attribute.
 * return - error code.
 *
 * ****************************************************************************
 */
int
assign_attr(
	isns_attr_t *attr,
	const isns_attr_t *tmp
)
{
	uint32_t t;

	switch (tmp->tag) {
	case ISNS_EID_ATTR_ID:
	case ISNS_DD_SET_NAME_ATTR_ID:
	case ISNS_DD_NAME_ATTR_ID:
		if (tmp->len == 0 && attr->len == 0) {
			int len;
			char *name = make_unique_name(&len, tmp->tag);
			if (name != NULL) {
				attr->value.ptr = (uchar_t *)name;
				attr->tag = tmp->tag;
				attr->len = len;
			} else {
				/* memory exhausted */
				return (1);
			}
		}
		/* FALLTHROUGH */
	case ISNS_PORTAL_NAME_ATTR_ID:
	case ISNS_ISCSI_NAME_ATTR_ID:
	case ISNS_ISCSI_ALIAS_ATTR_ID:
	case ISNS_ISCSI_AUTH_METHOD_ATTR_ID:
	case ISNS_PG_ISCSI_NAME_ATTR_ID:
	case ISNS_DD_ISCSI_NAME_ATTR_ID:
		if (tmp->len == 0) {
			return (0);
		} else if (tmp->len >= attr->len) {
			attr->value.ptr = realloc(
			    attr->value.ptr, tmp->len + 1);
		}
		if (attr->value.ptr != NULL) {
			(void) strncpy((char *)attr->value.ptr,
			    (char *)tmp->value.ptr, tmp->len);
			attr->value.ptr[tmp->len] = 0;
			attr->tag = tmp->tag;
			attr->len = tmp->len;
		} else {
			/* memory exhausted */
			return (1);
		}
		break;
	case ISNS_MGMT_IP_ADDR_ATTR_ID:
	case ISNS_PORTAL_IP_ADDR_ATTR_ID:
	case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
		if (attr->value.ip == NULL) {
			attr->value.ip = (in6_addr_t *)calloc(1, tmp->len);
		}
		if (attr->value.ip != NULL) {
			(void) memcpy((void *)attr->value.ip,
			    (void *)tmp->value.ip, tmp->len);
			attr->tag = tmp->tag;
			attr->len = tmp->len;
		} else {
			/* memory exhausted */
			return (1);
		}
		break;
	case ISNS_ENTITY_INDEX_ATTR_ID:
	case ISNS_PORTAL_INDEX_ATTR_ID:
	case ISNS_ISCSI_NODE_INDEX_ATTR_ID:
	case ISNS_PG_INDEX_ATTR_ID:
	case ISNS_DD_SET_ID_ATTR_ID:
	case ISNS_DD_ID_ATTR_ID:
		if (attr->value.ui != 0) {
			break;
		}
		/* FALLTHROUGH */
	case ISNS_ENTITY_PROTOCOL_ATTR_ID:
	case ISNS_VERSION_RANGE_ATTR_ID:

	case ISNS_PORTAL_PORT_ATTR_ID:
	case ISNS_ESI_PORT_ATTR_ID:
	case ISNS_SCN_PORT_ATTR_ID:

	case ISNS_ISCSI_NODE_TYPE_ATTR_ID:
	case ISNS_ISCSI_SCN_BITMAP_ATTR_ID:

	case ISNS_PG_PORTAL_PORT_ATTR_ID:
	case ISNS_PG_TAG_ATTR_ID:

	case ISNS_DD_SET_STATUS_ATTR_ID:
	case ISNS_DD_ISCSI_INDEX_ATTR_ID:
		attr->tag = tmp->tag;
		attr->len = tmp->len;
		attr->value.ui = tmp->value.ui;
		break;
	case ISNS_ENTITY_REG_PERIOD_ATTR_ID:
		attr->tag = tmp->tag;
		attr->len = tmp->len;
		attr->value.ui = tmp->value.ui;
		t = get_reg_period();
		if (attr->value.ui > t) {
			attr->value.ui = t;
		} else if (attr->value.ui < ONE_DAY) {
			attr->value.ui = ONE_DAY;
		}
		break;
	case ISNS_ESI_INTERVAL_ATTR_ID:
		attr->tag = tmp->tag;
		attr->len = tmp->len;
		attr->value.ui = tmp->value.ui;
		if (attr->value.ui > ONE_DAY) {
			attr->value.ui = ONE_DAY;
		} else if (attr->value.ui < MIN_ESI_INTVAL) {
			attr->value.ui = MIN_ESI_INTVAL; /* 20 seconds */
		}
		break;
	default:
		ASSERT(0);
		/* don't assign the attribute */
		break;
	}
	return (0);
}

/*
 * ****************************************************************************
 *
 * copy_attrs:
 *	copy all of attributes from one object to another.
 *
 * dst	- the destination object.
 * tmp	- the source object.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
copy_attrs(
	isns_obj_t *dst,
	const isns_obj_t *src
)
{
	int i = 0;
	int n = NUM_OF_ATTRS[dst->type];

	isns_attr_t *dst_attr;
	const isns_attr_t *src_attr;

	while (i < n) {
		src_attr = &(src->attrs[i]);
		if (src_attr->tag != 0) {
			dst_attr = &(dst->attrs[i]);
			if (assign_attr(dst_attr, src_attr) != 0) {
				return (1);
			}
		}
		i ++;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * extract_attr:
 *	extract an attribute from a TLV format data.
 *
 * attr	- the attribute.
 * tlv	- the TLV format data.
 * return - error code.
 *
 * ****************************************************************************
 */
int
extract_attr(
	isns_attr_t *attr,
	const isns_tlv_t *tlv,
	int flag
)
{
	int ec = 0;

	uint32_t min_len = 4, max_len = 224;

	switch (tlv->attr_id) {
	case ISNS_EID_ATTR_ID:
		min_len = 0;
		/* FALLTHROUGH */
	case ISNS_PORTAL_NAME_ATTR_ID:
	case ISNS_ISCSI_ALIAS_ATTR_ID:
	case ISNS_DD_SET_NAME_ATTR_ID:
	case ISNS_DD_NAME_ATTR_ID:
		max_len = 256;
		/* FALLTHROUGH */
	case ISNS_ISCSI_NAME_ATTR_ID:
	case ISNS_PG_ISCSI_NAME_ATTR_ID:
		if (tlv->attr_len < min_len || tlv->attr_len > max_len) {
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
		} else {
			attr->tag = tlv->attr_id;
			attr->len = tlv->attr_len;
			attr->value.ptr = (uchar_t *)&(tlv->attr_value[0]);
		}
		break;
	case ISNS_ISCSI_AUTH_METHOD_ATTR_ID:
		attr->tag = tlv->attr_id;
		attr->len = tlv->attr_len;
		attr->value.ptr = (uchar_t *)&(tlv->attr_value[0]);
		break;
	case ISNS_MGMT_IP_ADDR_ATTR_ID:
	case ISNS_PORTAL_IP_ADDR_ATTR_ID:
	case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
		if (tlv->attr_len != 16) {
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
		} else {
			attr->tag = tlv->attr_id;
			attr->len = tlv->attr_len;
			attr->value.ip = (void *)&(tlv->attr_value[0]);
		}
		break;
	case ISNS_ENTITY_PROTOCOL_ATTR_ID:
	case ISNS_VERSION_RANGE_ATTR_ID:
	case ISNS_ENTITY_REG_PERIOD_ATTR_ID:
		/* fall throught */
	case ISNS_PORTAL_PORT_ATTR_ID:
	case ISNS_ESI_INTERVAL_ATTR_ID:
	case ISNS_ESI_PORT_ATTR_ID:
	case ISNS_SCN_PORT_ATTR_ID:
		/* fall throught */
	case ISNS_ISCSI_NODE_TYPE_ATTR_ID:
		/* fall throught */
	case ISNS_PG_PORTAL_PORT_ATTR_ID:
		/* fall throught */
	case ISNS_DD_SET_ID_ATTR_ID:
	case ISNS_DD_SET_STATUS_ATTR_ID:
		/* fall throught */
	case ISNS_DD_ID_ATTR_ID:
		if (tlv->attr_len != 4) {
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
			break;
		}
		/* FALLTHROUGH */
	case ISNS_PG_TAG_ATTR_ID:
		attr->tag = tlv->attr_id;
		attr->len = tlv->attr_len;
		if (tlv->attr_len == 4) {
			attr->value.ui = ntohl(*(uint32_t *)
			    &(tlv->attr_value[0]));
		} else {
			attr->value.ui = 0;
		}
		break;
	case ISNS_ISCSI_SCN_BITMAP_ATTR_ID:
		/* ignore scn bitmap attribute during object registration, */
		/* it is registered by scn_reg message. */
	case ISNS_ENTITY_ISAKMP_P1_ATTR_ID:
	case ISNS_ENTITY_CERT_ATTR_ID:
	case ISNS_PORTAL_SEC_BMP_ATTR_ID:
	case ISNS_PORTAL_ISAKMP_P1_ATTR_ID:
	case ISNS_PORTAL_ISAKMP_P2_ATTR_ID:
	case ISNS_PORTAL_CERT_ATTR_ID:
		break;
	case ISNS_PORTAL_INDEX_ATTR_ID:
	case ISNS_ISCSI_NODE_INDEX_ATTR_ID:
	case ISNS_PG_INDEX_ATTR_ID:
		if (flag == 0) {
			if (tlv->attr_len != 4) {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			} else {
				attr->tag = tlv->attr_id;
				attr->len = tlv->attr_len;
				attr->value.ui = ntohl(*(uint32_t *)
				    &(tlv->attr_value[0]));
			}
			break;
		}
		/* FALLTHROUGH */
	case ISNS_ENTITY_INDEX_ATTR_ID:
	case ISNS_TIMESTAMP_ATTR_ID:
	default:
		if (flag == 0) {
			ec = ISNS_RSP_INVALID_QRY;
		} else {
			ec = ISNS_RSP_INVALID_REGIS;
		}
		break;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * copy_attr:
 *	copy an attribute from a TLV format data.
 *
 * attr	- the attribute.
 * tlv	- the TLV format data.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
copy_attr(
	isns_attr_t *attr,
	const isns_tlv_t *tlv
)
{
	int ec = 0;

	isns_attr_t tmp = { 0 };

	/* extract the attribute first */
	ec = extract_attr(&tmp, tlv, 1);

	/* assign the attribute */
	if (ec == 0 && tmp.tag != 0) {
		if (assign_attr(attr, &tmp) != 0) {
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * get_timestamp:
 *	get current timestamp.
 *
 * return - current timestamp.
 *
 * ****************************************************************************
 */
uint32_t
get_timestamp(
)
{
	uint32_t t;
	int flag;

	/* block the scheduler */
	(void) pthread_mutex_lock(&el_mtx);

	/* get most current time */
	if (sys_q != NULL) {
		/* need to wakeup idle */
		flag = 1;
	} else {
		flag = 0;
	}
	t = get_stopwatch(flag);

	/* unblock it */
	(void) pthread_mutex_unlock(&el_mtx);

	return (t);
}

/*
 * ****************************************************************************
 *
 * get_reg_period:
 *	get the longest registration period.
 *
 * return - the longest registration period.
 *
 * ****************************************************************************
 */
static uint32_t
get_reg_period(
)
{
	uint32_t t;
	uint32_t period;

	/* get most current time */
	t = get_timestamp();

	/* just one second before the end of the world */
	period = INFINITY - t - 1;

	return (period);
}

/*
 * ****************************************************************************
 *
 * obj_calloc:
 *	allocate memory space for an object.
 *
 * type	- the object type.
 * return - pointer of the object being allocated.
 *
 * ****************************************************************************
 */
isns_obj_t *
obj_calloc(
	int type
)
{
	isns_obj_t *obj = NULL;

	obj = (isns_obj_t *)calloc(1, SIZEOF_OBJ[type]);
	if (obj != NULL) {
		obj->type = type;
#ifdef DEBUG
	if (verbose_mc) {
		printf("object(%d) allocated\n", type);
	}
#endif
	}

	return (obj);
}

/*
 * ****************************************************************************
 *
 * make_default_entity:
 *	generate a default network entity object.
 *
 * return - pointer of the default network entity object.
 *
 * ****************************************************************************
 */
isns_obj_t *
make_default_entity(
)
{
	uint32_t t;

	isns_obj_t *obj = obj_calloc(OBJ_ENTITY);
	isns_attr_t *attr;
	if (obj != NULL) {
		int len;
		char *eid = make_unique_name(&len, ISNS_EID_ATTR_ID);
		if (!eid) {
			free(obj);
			return (NULL);
		}
		attr = &obj->attrs[ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID)];

		/* set default entity name */
		attr->tag = ISNS_EID_ATTR_ID;
		attr->len = len;
		attr->value.ptr = (uchar_t *)eid;

		/* set default registration period */
		attr = &obj->attrs[
		    ATTR_INDEX_ENTITY(ISNS_ENTITY_REG_PERIOD_ATTR_ID)];
		if (attr->tag == 0) {
			attr->tag = ISNS_ENTITY_REG_PERIOD_ATTR_ID;
			attr->len = 4;
			t = get_reg_period();
			attr->value.ui = t;
		}
	}

	return (obj);
}

/*
 * ****************************************************************************
 *
 * make_default_pg:
 *	generate a default portal group object.
 *
 * iscsi  - the iscsi storage node object.
 * portal - the portal object.
 * return - pointer of the default portal group object.
 *
 * ****************************************************************************
 */
static isns_obj_t *
make_default_pg(
	const isns_obj_t *p1,
	const isns_obj_t *p2
)
{
	const isns_obj_t *iscsi, *portal;
	const isns_attr_t *name, *addr, *port;
	isns_obj_t *pg;

	uchar_t *pg_name;
	in6_addr_t *pg_addr;

	isns_attr_t *attr;

	uint32_t *refp;

	if (p1->type == OBJ_ISCSI) {
		iscsi = p1;
		portal = p2;
	} else {
		iscsi = p2;
		portal = p1;
	}
	name = &iscsi->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)];
	addr = &portal->attrs[ATTR_INDEX_PORTAL(ISNS_PORTAL_IP_ADDR_ATTR_ID)];
	port = &portal->attrs[ATTR_INDEX_PORTAL(ISNS_PORTAL_PORT_ATTR_ID)];

	pg = obj_calloc(OBJ_PG);
	pg_name = (uchar_t *)malloc(name->len);
	pg_addr = (in6_addr_t *)malloc(addr->len);
	if (pg != NULL && pg_name != NULL && pg_addr != NULL) {
		(void) strcpy((char *)pg_name, (char *)name->value.ptr);
		attr = &pg->attrs[ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID)];
		attr->tag = ISNS_PG_ISCSI_NAME_ATTR_ID;
		attr->len = name->len;
		attr->value.ptr = pg_name;

		(void) memcpy((void *)pg_addr,
		    (void *)addr->value.ip, addr->len);
		attr = &pg->attrs[ATTR_INDEX_PG(
		    ISNS_PG_PORTAL_IP_ADDR_ATTR_ID)];
		attr->tag = ISNS_PG_PORTAL_IP_ADDR_ATTR_ID;
		attr->len = addr->len;
		attr->value.ip = pg_addr;

		attr = &pg->attrs[ATTR_INDEX_PG(
		    ISNS_PG_PORTAL_PORT_ATTR_ID)];
		attr->tag = ISNS_PG_PORTAL_PORT_ATTR_ID;
		attr->len = port->len;
		attr->value.ui = port->value.ui;

		attr = &pg->attrs[ATTR_INDEX_PG(
		    ISNS_PG_TAG_ATTR_ID)];
		attr->tag = ISNS_PG_TAG_ATTR_ID;
		attr->len = 4;
		attr->value.ui = ISNS_DEFAULT_PGT;

		refp = get_ref_p(pg, OBJ_ISCSI);
		*refp = get_obj_uid(iscsi);

		refp = get_ref_p(pg, OBJ_PORTAL);
		*refp = get_obj_uid(portal);

		(void) set_parent_obj(pg, get_parent_uid(iscsi));
	} else {
		free(pg);
		free(pg_name);
		free(pg_addr);
		pg = NULL;
	}

	return (pg);
}

/*
 * ****************************************************************************
 *
 * reg_get_entity:
 *	parse the Operating Attributes of the DevAttrReg message and
 *	create the Network Entity object if it has one.
 *
 * p	- the pointer of the object for returning.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
int
reg_get_entity(
	isns_obj_t **p,
	isns_tlv_t **op,
	uint16_t *op_len
)
{
	int ec = 0;

	isns_tlv_t *tmp;
	uint16_t tmp_len;
	isns_attr_t *attr;

	isns_obj_t *entity = NULL;

	tmp = *op;
	tmp_len = *op_len;

	/* parse the entity object */
	if (tmp_len >= 8 && IS_ENTITY_KEY(tmp->attr_id)) {
		entity = obj_calloc(OBJ_ENTITY);
		if (entity != NULL) {
			do {
				attr = &entity->attrs[
				    ATTR_INDEX_ENTITY(tmp->attr_id)];
				ec = copy_attr(attr, tmp);
				NEXT_TLV(tmp, tmp_len);
			} while (ec == 0 &&
			    tmp_len >= 8 &&
			    IS_ENTITY_ATTR(tmp->attr_id));
		} else {
			ec = ISNS_RSP_INTERNAL_ERROR;
		}

		if (ec == 0) {
			/* set default registration period */
			attr = &entity->attrs[
			    ATTR_INDEX_ENTITY(ISNS_ENTITY_REG_PERIOD_ATTR_ID)];
			if (attr->tag == 0) {
				attr->tag = ISNS_ENTITY_REG_PERIOD_ATTR_ID;
				attr->len = 4;
				attr->value.ui = get_reg_period();
			}
		} else if (entity != NULL) {
			free(entity);
			entity = NULL;
		}
	}

	*p = entity;
	*op = tmp;
	*op_len = tmp_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * reg_get_iscsi:
 *	parse the Operating Attributes of the DevAttrReg message and
 *	create an iSCSI Storage Node object.
 *
 * p	- the pointer of the object for returning.
 * pg_key1 - the pointer of iscsi storage node name for returning.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
reg_get_iscsi(
	isns_obj_t **p,
	isns_attr_t *pg_key1,
	isns_tlv_t **op,
	uint16_t *op_len
)
{
	int ec = 0;

	isns_tlv_t *tmp;
	uint16_t tmp_len;
	isns_attr_t *attr;

	isns_obj_t *obj = NULL;

	tmp = *op;
	tmp_len = *op_len;

	/* keep the iscsi storage node name for */
	/* parsing a pg object which is immediately */
	/* followed with a PGT by the iscsi storage node */
	pg_key1->tag = PG_KEY1;
	pg_key1->len = tmp->attr_len;
	pg_key1->value.ptr = (uchar_t *)&tmp->attr_value[0];

	/* parse one iscsi storage node object */
	obj = obj_calloc(OBJ_ISCSI);
	if (obj != NULL) {
		/* parse key & non-key attributes */
		do {
			attr = &obj->attrs[
			    ATTR_INDEX_ISCSI(tmp->attr_id)];
			ec = copy_attr(attr, tmp);
			NEXT_TLV(tmp, tmp_len);
		} while (ec == 0 &&
		    tmp_len >= 8 &&
		    IS_ISCSI_ATTR(tmp->attr_id));
	} else {
		/* no memory */
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	*p = obj;
	*op = tmp;
	*op_len = tmp_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * reg_get_portal:
 *	parse the Operating Attributes of the DevAttrReg message and
 *	create a Portal object.
 *
 * p	- the pointer of the object for returning.
 * pg_key1 - the pointer of portal ip addr for returning.
 * pg_key2 - the pointer of portal port for returning.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
reg_get_portal(
	isns_obj_t **p,
	isns_attr_t *pg_key1,
	isns_attr_t *pg_key2,
	isns_tlv_t **op,
	uint16_t *op_len
)
{
	int ec = 0;

	isns_tlv_t *tmp;
	uint16_t tmp_len;
	isns_attr_t *attr;

	isns_obj_t *obj = NULL;

	isns_tlv_t *ip;

	tmp = *op;
	tmp_len = *op_len;

	/* keep the portal ip addr */
	pg_key1->tag = PG_KEY2;
	pg_key1->len = tmp->attr_len;
	pg_key1->value.ip = (void *)&tmp->attr_value[0];
	ip = tmp;

	NEXT_TLV(tmp, tmp_len);
	if (tmp_len > 8 &&
	    tmp->attr_id == PORTAL_KEY2 &&
	    tmp->attr_len == 4) {
		/* keep the portal port */
		pg_key2->tag = PG_KEY3;
		pg_key2->len = tmp->attr_len;
		pg_key2->value.ui = ntohl(*(uint32_t *)&tmp->attr_value[0]);

		/* parse one portal object */
		obj = obj_calloc(OBJ_PORTAL);
		if (obj != NULL) {
			/* copy ip addr attribute */
			attr = &obj->attrs[
			    ATTR_INDEX_PORTAL(ip->attr_id)];
			ec = copy_attr(attr, ip);
			/* copy port attribute */
			if (ec == 0) {
				attr = &obj->attrs[
				    ATTR_INDEX_PORTAL(tmp->attr_id)];
				ec = copy_attr(attr, tmp);
			}
			/* parse non-key attributes */
			NEXT_TLV(tmp, tmp_len);
			while (ec == 0 &&
			    tmp_len >= 8 &&
			    IS_PORTAL_ATTR(tmp->attr_id)) {
				attr = &obj->attrs[
				    ATTR_INDEX_PORTAL(
				    tmp->attr_id)];
				ec = copy_attr(attr, tmp);
				NEXT_TLV(tmp, tmp_len);
			}
		} else {
			/* no memory */
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	} else {
		/* ip address is not followed by port */
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
	}

	*p = obj;
	*op = tmp;
	*op_len = tmp_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * reg_get_pg:
 *	parse the Operating Attributes of the DevAttrReg message and
 *	create a Portal Group object.
 *
 * p	- the pointer of the object for returning.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
reg_get_pg(
	isns_obj_t **p,
	isns_tlv_t **op,
	uint16_t *op_len
)
{
	int ec = 0;

	isns_tlv_t *tmp;
	uint16_t tmp_len;
	isns_attr_t *attr;

	isns_obj_t *obj = NULL;

	tmp = *op;
	tmp_len = *op_len;

	/* parse a complete pg object */
	obj = obj_calloc(OBJ_PG);
	if (obj != NULL) {
		/* parse attributes */
		do {
			attr = &obj->attrs[
			    ATTR_INDEX_PG(tmp->attr_id)];
			ec = copy_attr(attr, tmp);
			NEXT_TLV(tmp, tmp_len);
		} while (ec == 0 &&
		    tmp_len >= 8 &&
		    IS_PG_ATTR(tmp->attr_id));
	} else {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	*p = obj;
	*op = tmp;
	*op_len = tmp_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * reg_get_pg1:
 *	parse the Operating Attributes of the DevAttrReg message and
 *	create a Portal Group object which is followed to a Portal object.
 *
 * p	- the pointer of the object for returning.
 * pgt	- the size-3 array of pointers which have the pg portal ip addr, port
 *	  and the pg tag attributes.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
reg_get_pg1(
	isns_obj_t **p,
	isns_attr_t const *pgt,
	isns_tlv_t **op,
	uint16_t *op_len
)
{
	int ec = 0;

	isns_tlv_t *tmp;
	uint16_t tmp_len;
	isns_attr_t *attr;

	isns_obj_t *obj = NULL;
	int i = 0;

	tmp = *op;
	tmp_len = *op_len;

	if (pgt[0].tag == PG_KEY2 &&
	    pgt[1].tag == PG_KEY3) {
		/* the pg iscsi storage node name is */
		/* followed to a portal group tag */
		obj = obj_calloc(OBJ_PG);
		if (obj != NULL) {
			/* copy pg iscsi storage node name */
			attr = &obj->attrs[
			    ATTR_INDEX_PG(tmp->attr_id)];
			ec = copy_attr(attr, tmp);
			/* copy pg ip addr, pg port & pgt */
			while (ec == 0 && i < 3) {
				attr = &obj->attrs[
				    ATTR_INDEX_PG(pgt[i].tag)];
				ec = assign_attr(attr, &pgt[i]);
				i ++;
			}
			NEXT_TLV(tmp, tmp_len);
		} else {
			/* no memory */
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	} else {
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
	}

	*p = obj;
	*op = tmp;
	*op_len = tmp_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * reg_get_pg2:
 *	parse the Operating Attributes of the DevAttrReg message and
 *	create a Portal Group object which is followed to a iSCSI
 *	Storage Node object.
 *
 * p	- the pointer of the object for returning.
 * pgt	- the size-3 array of pointers which have the pg iscsi storage
 *	  node name and the pg tag attributes.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
reg_get_pg2(
	isns_obj_t **p,
	isns_attr_t const *pgt,
	isns_tlv_t **op,
	uint16_t *op_len
)
{
	int ec = 0;

	isns_tlv_t *tmp;
	uint16_t tmp_len;
	isns_attr_t *attr;

	isns_obj_t *obj = NULL;
	int i = 0;

	isns_tlv_t *ip;

	tmp = *op;
	tmp_len = *op_len;

	/* keep ip address */
	ip = tmp;
	NEXT_TLV(tmp, tmp_len);

	if (tmp_len > 8 &&
	    /* expect pg portal port */
	    tmp->attr_id == PG_KEY3 &&
	    tmp->attr_len == 4 &&
	    /* expect pg tag */
	    pgt[2].tag == PG_PGT &&
	    /* expect pg iscsi storage node name only */
	    pgt[1].tag == 0 &&
	    pgt[0].tag == PG_KEY1) {
		/* the pg portal ip addr & port is followed */
		/* to a pg tag and we have the iscsi storage */
		/* node parsed previously */
		obj = obj_calloc(OBJ_PG);
		if (obj != NULL) {
			/* copy the pg ip addr */
			attr = &obj->attrs[
			    ATTR_INDEX_PG(ip->attr_id)];
			ec = copy_attr(attr, ip);
			/* copy the pg port */
			if (ec == 0) {
				attr = &obj->attrs[
				    ATTR_INDEX_PG(tmp->attr_id)];
				ec = copy_attr(attr, tmp);
			}
			/* copy pg iscsi storage node name & pgt */
			while (ec == 0 && i < 3) {
				attr = &obj->attrs[
				    ATTR_INDEX_PG(pgt[i].tag)];
				ec = assign_attr(attr, &pgt[i]);
				i += 2;
			}
			NEXT_TLV(tmp, tmp_len);
		} else {
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	} else {
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
	}

	*p = obj;
	*op = tmp;
	*op_len = tmp_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * reg_get_obj:
 *	parse and create one object from the rest of Operating Attributes
 *	of the DevAttrReg message, the object can be iSCSI Storage Node,
 *	Portal or Portal Group.
 *
 * p	- the pointer of the object for returning.
 * pgt	- an attribute array with size 3, the elements are:
 *	  0: the first pg key attribute, it is either the name of an
 *	     iscsi storage node object or the ip addr of a portal object.
 *	  1: the second pg key attribute, i.e. the portal port.
 *	  2: the portal group tag attribute.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
int
reg_get_obj(
	isns_obj_t **p,
	isns_attr_t *pgt,
	isns_tlv_t **op,
	uint16_t *op_len
)
{
	int ec = 0;

	int derefd = 0;

	uint32_t pg_tag;

	if (*op_len == 0) {
		*p = NULL;
		return (0);
	}

	switch ((*op)->attr_id) {
	case ISCSI_KEY:
		ec = reg_get_iscsi(p, &pgt[0], op, op_len);
		pgt[1].tag = 0;
		pgt[2].tag = 0;
		break;
	case PORTAL_KEY1:
		ec = reg_get_portal(p, &pgt[0], &pgt[1], op, op_len);
		pgt[2].tag = 0;
		break;
	case PG_KEY1:
		if (pgt[2].tag == PG_PGT) {
			/* pg iscsi storage node name is */
			/* followed to a pgt */
			ec = reg_get_pg1(p, pgt, op, op_len);
		} else {
			/* a complete pg object */
			ec = reg_get_pg(p, op, op_len);
			pgt[0].tag = 0;
			pgt[1].tag = 0;
			pgt[2].tag = 0;
		}
		break;
	case PG_KEY2:
		/* pg portal ip addr is followed to a pgt */
		ec = reg_get_pg2(p, pgt, op, op_len);
		break;
	case PG_PGT:
		switch (pgt[0].tag) {
		case 0:
			/* portal group tag does not follow */
			/* iscsi storage node or portal object */
			*p = NULL;
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
			break;
		case PG_KEY1:
		case PG_KEY2:
			pgt[2].tag = PG_PGT;
			pgt[2].len = (*op)->attr_len;
			pg_tag = 0;
			switch ((*op)->attr_len) {
			case 4:
				pg_tag = ntohl(*(uint32_t *)
				    &(*op)->attr_value[0]);
				/* FALLTHROUGH */
			case 0:
				pgt[2].value.ui = pg_tag;
				break;
			default:
				*p = NULL;
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
				break;
			}
			if (ec == 0) {
				derefd = 1;
				NEXT_TLV(*op, *op_len);
				ec = reg_get_obj(p, pgt, op, op_len);
			}
			break;
		default:
			/* should never happen */
			ASSERT(0);
			*p = NULL;
			ec = ISNS_RSP_INTERNAL_ERROR;
			break;
		}
		break;
	default:
		*p = NULL;
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
		break;
	}

	if (ec == 0 && derefd == 0) {
		ec = update_deref_obj(*p);
	}

	if (ec != 0 && *p != NULL) {
		free_one_object(*p);
		*p = NULL;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * reg_auth_src:
 *	Authorize the source attribute the DevAttrReg message.
 *	The update can only performed by the node who has the owenership.
 *
 * p	- the pointer of the object for returning.
 * pgt	- an attribute array with size 3, the elements are:
 *	  0: the first pg key attribute, it is either the name of an
 *	     iscsi storage node object or the ip addr of a portal object.
 *	  1: the second pg key attribute, i.e. the portal port.
 *	  2: the portal group tag attribute.
 * op	- the operating attributes.
 * op_len - the length of the operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
int
reg_auth_src(
	isns_type_t type,
	uint32_t uid,
	uchar_t *src
)
{
	lookup_ctrl_t lc;
	uint32_t puid;

	puid = is_parent_there(src);

	if (TYPE_OF_PARENT[type] != 0) {
		SET_UID_LCP(&lc, type, uid);
		uid = cache_lookup(&lc, NULL, cb_get_parent);
		type = TYPE_OF_PARENT[type];
	}

	if (uid != 0 && puid == 0) {
		SET_UID_LCP(&lc, type, uid);
		uid = cache_lookup(&lc, NULL, cb_node_child);
	}

	if (puid != uid) {
		return (0);
	}

	return (1);
}

/*
 * ****************************************************************************
 *
 * is_obj_online:
 *	determine if the object is currently registered with the server.
 *
 * obj - the object being checked.
 * return - 0: not registered, otherwise registered.
 *
 * ****************************************************************************
 */
int
is_obj_online(
	const isns_obj_t *obj
)
{
	int online = 1;

	switch (obj->type) {
	case OBJ_ISCSI:
		online = obj->attrs[ATTR_INDEX_ISCSI(
		    ISNS_ISCSI_NODE_TYPE_ATTR_ID)].value.ui == 0 ? 0 : 1;
		break;
	default:
		break;
	}

	return (online);
}

static int
set_obj_offline(
	isns_obj_t *obj
)
{
	switch (obj->type) {
	case OBJ_ISCSI:
		obj->attrs[ATTR_INDEX_ISCSI(
		    ISNS_ISCSI_NODE_TYPE_ATTR_ID)].value.ui = 0;
		break;
	default:
		break;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * assoc_clone:
 *	clone the association object.
 *
 * p - the object being cloned.
 * clone_flag - 0: the object is being removed;
 *		1: only the association is being removed.
 * return - the clone object.
 *
 * ****************************************************************************
 */
void *
assoc_clone(
	void *p,
	int clone_flag
)
{
	isns_type_t type;
	isns_obj_t *clone;
	const isns_attr_t *src_attr;
	isns_attr_t *dst_attr;
	uint32_t id, op;
	int i = 0;

	const isns_obj_t *obj;
	uint32_t dd_flag;
	int online;

	int state;

	obj = (isns_obj_t *)p;

	if (obj->type != OBJ_ISCSI) {
		return (NULL);
	}

	dd_flag = (get_dd_id(get_obj_uid(obj), ISNS_DEFAULT_DD_ID) == 0) ?
	    0 : 1;
	online = is_obj_online(obj);

	state = (clone_flag << 2) | (dd_flag  << 1) | online;

	/* clone_flag	dd_flag	online	action		*/
	/* 0		0	0	ASSERT(0)	*/
	/* 0		0	1	NULL		*/
	/* 0		1	0	itself		*/
	/* 0		1	1	clone it	*/
	/* 1		0	0	NULL		*/
	/* 1		0	1	itself		*/
	/* 1		1	0	itself		*/
	/* 1		1	1	itself		*/

	switch (state) {
	case 0:
		ASSERT(0);
	case 1:
	case 4:
		return (NULL);
	case 2:
	case 5:
	case 6:
	case 7:
		return (p);
	case 3:
	default:
		break;
	}

	type = obj->type;
	clone = obj_calloc(type);

	if (clone != NULL) {
		id = UID_ATTR_INDEX[type];
		src_attr = &(obj->attrs[id]);
		dst_attr = &(clone->attrs[id]);
		if (assign_attr(dst_attr, src_attr) != 0) {
			free_one_object(clone);
			return (NULL);
		}

		while (i < MAX_KEY_ATTRS) {
			op = KEY_ATTR_OP[type][i];
			if (op != 0) {
				id = KEY_ATTR_INDEX[type][i];
				src_attr = &(obj->attrs[id]);
				dst_attr = &(clone->attrs[id]);
				if (assign_attr(dst_attr, src_attr) != 0) {
					free_one_object(clone);
					return (NULL);
				}
			} else {
				break;
			}
			i ++;
		}
	}

	return ((void *)clone);
}

/*
 * ****************************************************************************
 *
 * free_one_object:
 *	free up one object.
 *
 * obj - the object being freed.
 *
 * ****************************************************************************
 */
void
free_one_object(
	isns_obj_t *obj
)
{
	int i;
	uint32_t *cuid;
	if (obj == NULL) {
		return;
	}
	for (i = 0; i < NUM_OF_ATTRS[obj->type]; i++) {
		isns_attr_t *attr = &obj->attrs[i];
		switch (attr->tag) {
			case ISNS_EID_ATTR_ID:
			case ISNS_ISCSI_NAME_ATTR_ID:
			case ISNS_ISCSI_ALIAS_ATTR_ID:
			case ISNS_ISCSI_AUTH_METHOD_ATTR_ID:
			case ISNS_PG_ISCSI_NAME_ATTR_ID:
			case ISNS_PORTAL_IP_ADDR_ATTR_ID:
			case ISNS_PORTAL_NAME_ATTR_ID:
			case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			case ISNS_DD_SET_NAME_ATTR_ID:
			case ISNS_DD_NAME_ATTR_ID:
			case ISNS_DD_ISCSI_NAME_ATTR_ID:
			case ISNS_DD_FC_PORT_NAME_ATTR_ID:
			case ISNS_DD_PORTAL_IP_ADDR_ATTR_ID:
#ifdef DEBUG
				if (verbose_mc) {
					printf("memory(%d) deallocated\n",
					    attr->len);
				}
#endif
				free(attr->value.ptr);
				attr->value.ptr = NULL;
				break;
			default:
				break;
		}
	}

	/* free child uids */
	i = 0;
	while (i < NUM_OF_CHILD[obj->type]) {
		cuid = get_child_n(obj, i);
		free(cuid);
		i ++;
	}

	/* at last, free the object itself */
#ifdef DEBUG
	if (verbose_mc) {
		printf("object(%d) deallocated\n", obj->type);
	}
#endif
	free(obj);
}

/*
 * ****************************************************************************
 *
 * free_object:
 *	free up one object.
 *
 * obj - the object being freed.
 *
 * ****************************************************************************
 */
void
free_object(
	isns_obj_t *obj
)
{
	free_one_object(obj);
}

/*
 * ****************************************************************************
 *
 * set_parent_obj:
 *	set the parent object UID.
 *
 * obj - the child object.
 * puid- the parent object UID.
 * return - error code.
 *
 * ****************************************************************************
 */
int
set_parent_obj(
	isns_obj_t *obj,
	uint32_t puid
)
{
	uint32_t *const p = get_parent_p(obj);
	if (p != NULL) {
		*p = puid;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * buff_child_obj:
 *	add a child object UID to the child object array.
 *
 * obj - the parent object.
 * child_type - the type of the child object.
 * number  - the number of the child object.
 * return - the length of the child object UID array.
 *
 * ****************************************************************************
 */
int
buff_child_obj(
	const isns_type_t ptype,
	const isns_type_t ctype,
	const void *c,
	void const ***child
)
{
	int ec = 0;

	int i = 0;
	void const ***pp, **p;
	uint32_t num, new_num;

	pp = NULL;
	/* get the pointer of the array which the child belongs to */
	while (i < NUM_OF_CHILD[ptype]) {
		if (TYPE_OF_CHILD[ptype][i] == ctype) {
			pp = &child[i];
			break;
		}
		i ++;
	}

	/* the child type is not applicable */
	if (pp == NULL) {
		return (ec);
	}

	p = *pp;
	/* get an empty slot from the uid array for this child */
	if (p != NULL) {
		num = (uint32_t)*p;
		i = 0;
		while (i < num) {
			if (p[++i] == NULL) {
				/* found it */
				p[i] = c;
				return (ec);
			}
		}
		p = *pp;
		new_num = num + 1;
	} else {
		num = 0;
		new_num = 1;
	}

	/* the array is full, enlarge the child uid array */
	p = (void const **)realloc(p, (new_num + 1) * sizeof (void *));
	if (p != NULL) {
		*pp = p;
		*p = (void *)new_num;
		p[new_num] = c;
	} else {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * update_child_object:
 *	update the child object of a network entity object.
 *
 * puid - the UID of the parent object, i.e. the network entity object.
 * child_type - the type of the child object.
 * child_uid  - the uid of the child object.
 * return - error code.
 *
 * ****************************************************************************
 */
int
update_child_obj(
	const isns_type_t ptype,
	const uint32_t puid,
	void const ***child,
	int child_flag
)
{
	int ec = 0;

	lookup_ctrl_t lc;

	SET_UID_LCP(&lc, ptype, puid);

	lc.data[1].ptr = (uchar_t *)child;
	lc.data[2].ui = child_flag;

	ec = cache_lookup(&lc, NULL, cb_add_child);

	return (ec);
}

int
update_ref_obj(
	const isns_obj_t *obj
)
{
	uint32_t uid;
	lookup_ctrl_t lc;
	isns_type_t t;

	t = obj->type;

	if (TYPE_OF_REF[t][0] != 0) {
		(void) setup_ref_lcp(&lc, obj, NULL);

		lc.id[2] = t;
		lc.data[2].ui = get_obj_uid(obj);

		uid = 0;
		do {
			lc.curr_uid = uid;
			(void) cache_lookup(&lc, &uid, cb_set_ref);
		} while (uid != 0);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * verify_ref_obj:
 *	update the reference bit of a portal group object.
 *
 * obj - the object being ref'ed.
 * return - error code.
 *
 * ****************************************************************************
 */
int
verify_ref_obj(
	const isns_type_t ptype,
	const uint32_t puid,
	void const ***child
)
{
	int ec = 0;

	lookup_ctrl_t lc;

	SET_UID_LCP(&lc, ptype, puid);

	lc.data[1].ptr = (uchar_t *)child;

	ec = cache_lookup(&lc, NULL, cb_verify_ref);

	return (ec);
}

int
update_deref_obj(
	isns_obj_t *obj
)
{
	int ec = 0;

	isns_type_t t, rt;
	lookup_ctrl_t lc;
	int i, ref_count;

	uint32_t uid, *refp;

	t = obj->type;
	i = ref_count = 0;
	while (i < NUM_OF_REF[t]) {
		rt = TYPE_OF_REF[t][i + 1];
		(void) setup_deref_lcp(&lc, obj, rt);
		uid = is_obj_there(&lc);
		if (uid != 0) {
			refp = get_ref_p(obj, lc.type);
			*refp = uid;
			ref_count ++;
		}
		i ++;
	}

	if (i > 0 && ref_count == 0) {
		ec = ISNS_RSP_INVALID_REGIS;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * register_object:
 *	add one object to the object container.
 *
 * obj	- the object being added.
 * uid_p- the pointer for returning object UID.
 * update_p- the pointer for returning flag which indicates if the object
 *		is newly registered or updated with an existing one.
 * return - error code.
 *
 * ****************************************************************************
 */
int
register_object(
	isns_obj_t *obj,
	uint32_t *uid_p,
	int *update_p
)
{
	return (cache_add(obj, 0, uid_p, update_p));
}

/*
 * ****************************************************************************
 *
 * register_assoc:
 *	add one association object to the object container, the association
 *	object has only the information for discovery domain membership, i.e.
 *	a name and UID only.
 *
 * obj	- the association object being added.
 * uid_p- the pointer for returning object UID.
 * return - error code.
 *
 * ****************************************************************************
 */
int
register_assoc(
	isns_obj_t *obj,
	uint32_t *uid_p
)
{
	return (cache_add(obj, 1, uid_p, NULL));
}

/*
 * ****************************************************************************
 *
 * is_obj_there:
 *	check if the object is registered or not.
 *
 * lcp	- the lookup control data.
 * return - the object UID.
 *
 * ****************************************************************************
 */
uint32_t
is_obj_there(
	lookup_ctrl_t *lcp
)
{
	uint32_t uid;

	(void) cache_lookup(lcp, &uid, NULL);

	return (uid);
}

uint32_t
is_parent_there(
	uchar_t *src
)
{
	lookup_ctrl_t lc;

	lc.curr_uid = 0;
	lc.type = OBJ_ISCSI;
	lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.data[0].ptr = src;
	lc.op[1] = 0;

	return (cache_lookup(&lc, NULL, cb_get_parent));
}

/*
 * ****************************************************************************
 *
 * setup_ref_lcp:
 *	prepare the lookup control data for looking up a portal group
 *	object which references to a iscsi stroage node and/or a portal
 *	object.
 *
 * lcp	- the lookup control data.
 * iscsi- the ref'ed iscsi storage node object.
 * portal- the ref'ed portal object.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
setup_ref_lcp(
	lookup_ctrl_t *lcp,
	const isns_obj_t *iscsi,
	const isns_obj_t *portal
)
{
	int i = 0, j = 0;

	lcp->curr_uid = 0;
	lcp->type = TYPE_OF_REF[iscsi->type][0];

	/* extrace the matching attributes from iscsi storage node object */
	while (iscsi != NULL &&
	    i < MAX_REF_MATCH &&
	    REF_MATCH_OPS[iscsi->type][i] > 0) {
		lcp->id[i] = REF_MATCH_ID2[iscsi->type][i];
		lcp->op[i] = REF_MATCH_OPS[iscsi->type][i];
		lcp->data[i].ptr = iscsi->attrs[
		    REF_MATCH_ID1[iscsi->type][i]].value.ptr;
		i ++;
	}

	/* extrace the matching attributes from portal object */
	while (portal != NULL &&
	    i < MAX_LOOKUP_CTRL &&
	    j < MAX_REF_MATCH &&
	    REF_MATCH_OPS[portal->type][j] > 0) {
		lcp->id[i] = REF_MATCH_ID2[portal->type][j];
		lcp->op[i] = REF_MATCH_OPS[portal->type][j];
		lcp->data[i].ptr = portal->attrs[
		    REF_MATCH_ID1[portal->type][j]].value.ptr;
		j ++;
		i ++;
	}

	if (i < MAX_LOOKUP_CTRL) {
		lcp->op[i] = 0;
	}

	return (0);
}

static int
setup_deref_lcp(
	lookup_ctrl_t *lcp,
	const isns_obj_t *pg,
	isns_type_t t
)
{
	int i = 0;

	lcp->curr_uid = 0;
	lcp->type = t;

	/* extrace the matching attributes from iscsi storage node object */
	while (i < MAX_REF_MATCH &&
	    REF_MATCH_OPS[t][i] > 0) {
		lcp->id[i] = REF_MATCH_ID1[t][i];
		lcp->op[i] = REF_MATCH_OPS[t][i];
		lcp->data[i].ptr = pg->attrs[
		    REF_MATCH_ID2[t][i]].value.ptr;
		i ++;
	}

	if (i < MAX_LOOKUP_CTRL) {
		lcp->op[i] = 0;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * setup_parent_lcp:
 *	prepare the lookup control data for looking up parent object
 *	with a child object.
 *
 * lcp	- the lookup control data.
 * obj	- the child object.
 * return - parent object UID.
 *
 * ****************************************************************************
 */
static uint32_t
setup_parent_lcp(
	lookup_ctrl_t *lcp,
	isns_obj_t *obj
)
{
	isns_type_t ptype;
	uint32_t puid;

	puid = get_parent_uid(obj);
	if (puid != 0) {
		ptype = TYPE_OF_PARENT[obj->type];
		SET_UID_LCP(lcp, ptype, puid);
		lcp->data[1].ui = obj->type;
		lcp->data[2].ui = get_obj_uid(obj);
	}

	return (puid);
}

static int
cb_get_parent(
	void *p1,
	/* LINTED E_FUNC_ARG_UNUSED */
	void *p2
)
{
	return (get_parent_uid(p1));
}

static int
cb_node_child(
	void *p1,
	/* LINTED E_FUNC_ARG_UNUSED */
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;

	uint32_t num, uid;

	uint32_t *cuid = get_child_t(obj, OBJ_ISCSI);

	if (cuid != NULL) {
		num = *cuid;
	} else {
		num = 0;
	}

	while (num > 0) {
		uid = *++cuid;
		if (uid != 0) {
			return (uid);
		}
		num --;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_set_ref:
 *	callback function which sets the reference bit to 1 according to
 *	the type of object.
 *
 * p1	- the object.
 * p2	- the lcp.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
cb_set_ref(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	isns_type_t t;
	uint32_t u;

	uint32_t *refp;

	t = lcp->id[2];
	u = lcp->data[2].ui;
	refp = get_ref_p(obj, t);
	*refp = u;

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_clear_ref:
 *	callback function which clears the reference bit according to
 *	the type of object.
 *
 * p1	- the object.
 * p2	- the lcp.
 * return - 1: the object is no longer ref'ed, 0: otherwise.
 *
 * ****************************************************************************
 */
static int
cb_clear_ref(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	isns_type_t t;
	uint32_t *refp;

	int i = 0;
	uint32_t ref;

	t = lcp->data[2].ui;
	refp = get_ref_p(obj, t);
	*refp = 0;

	while (i < NUM_OF_REF[obj->type]) {
		ref = get_ref_n(obj, i);
		if (ref != 0) {
			return (0);
		}
		i ++;
	}

	return (1);
}

static int
cb_add_child(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	const void ***child;
	const void **vpp;
	uint32_t vnum;
	int child_flag;

	uint32_t **upp, *up;
	uint32_t num;

	isns_obj_t *o;

	int i = 0;

	child = (const void ***)lcp->data[1].ptr;
	child_flag = lcp->data[2].ui;

	while (i < NUM_OF_CHILD[obj->type]) {
		vpp = child[i];
		if (vpp != NULL &&
		    (vnum = (uint32_t)*vpp) > 0 &&
		    *(vpp + 1) != NULL) {
			upp = get_child_np(obj, i);
			if (*upp == NULL) {
				if (child_flag == 0 &&
				    sizeof (typeof (**upp)) ==
				    sizeof (typeof (**child))) {
					*upp = (uint32_t *)vpp;
					vpp = NULL;
					child[i] = NULL;
				}
				num = vnum;
			} else {
				num = **upp + vnum;
			}
			if (vpp != NULL) {
				/* copy required */
				up = (uint32_t *)realloc(*upp,
				    (num + 1) * sizeof (uint32_t));
				if (up == NULL) {
					return (ISNS_RSP_INTERNAL_ERROR);
				}
				*upp = up;
				*up = num;
				up += num;
				vpp += vnum;
				while (vnum > 0) {
					if (*vpp == NULL) {
						*up = 0;
					} else if (child_flag == 0) {
						*up = (uint32_t)*vpp;
						*vpp = NULL;
					} else {
						o = (isns_obj_t *)*vpp;
						*up = get_obj_uid(o);
						if (is_obj_online(o) == 0) {
							free_object(o);
						}
						*vpp = NULL;
					}
					up --;
					vpp --;
					vnum --;
				}
			}
		}
		i ++;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_remove_child:
 *	callback function which removes a child object UID from the
 *	children objet UID array of the parent object.
 *
 * p1	- the object.
 * p2	- the lcp.
 * return - 1: no more such type of child object, 0: otherwise.
 *
 * ****************************************************************************
 */
static int
cb_remove_child(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	uint32_t child_type = lcp->data[1].ui;
	uint32_t child_uid = lcp->data[2].ui;
	uint32_t *cuidp, cuid, num_of_child = 0;
	int i;

	/* get the children object UID array */
	cuidp = get_child_t(obj, child_type);
	if (cuidp != NULL) {
		num_of_child = *cuidp;
	}

	/* remove it */
	while (num_of_child > 0) {
		cuid = *++cuidp;
		if (cuid == child_uid) {
			*cuidp = 0;
			break;
		}
		num_of_child --;
	}

	/* check if all of child object UIDs are removed */
	i = 0;
	while (i < NUM_OF_CHILD[obj->type]) {
		cuidp = get_child_n(obj, i);
		if (cuidp != NULL) {
			num_of_child = *cuidp;
			while (num_of_child > 0) {
				cuid = *++cuidp;
				if (cuid != 0) {
					return (0);
				}
				num_of_child --;
			}
		}
		i ++;
	}

	return (1);
}

static int
cb_verify_ref(
	void *p1,
	void *p2
)
{
	int ec = 0;

	isns_obj_t *parent = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	const void ***child;

	const void **vpp;
	const void *vp;
	uint32_t vnum;

	const void **evpp;
	const void *evp;
	uint32_t evnum;

	isns_type_t pt; /* parent object type */
	isns_type_t ct; /* child object type */
	isns_type_t rt; /* ref object type */
	isns_type_t et; /* peer object type */

	uint32_t *up;
	uint32_t u;
	uint32_t unum;

	lookup_ctrl_t lc;
	uint8_t flag[MAX_OBJ_TYPE + 1] = { 0 };

	int i, j, k;

	pt = parent->type;

	child = (const void ***)lcp->data[1].ptr;

	for (i = 0; i < NUM_OF_CHILD[pt]; i++) {
		ct = TYPE_OF_CHILD[pt][i];
		rt = TYPE_OF_REF[ct][0];
		if (rt == 0) {
			continue;
		}

		et = TYPE_OF_REF[ct][1];
		vpp = child[i];
		if (vpp != NULL) {
			vnum = (uint32_t)*vpp;
			up = get_child_t(parent, et);
			if (up != NULL) {
				unum = *up;
			} else {
				unum = 0;
			}
		} else {
			vnum = 0;
		}

		j = vnum;
		while (j > 0) {
			vp = vpp[j];
			if (vp != NULL) {
				(void) setup_ref_lcp(&lc, vp, NULL);
				k = unum;
				while (k > 0) {
					u = up[k];
					if (u != 0) {
						ec = ref_new2old(
						    &lc, et, u, vp);
						if (ec != 0) {
							return (ec);
						}
					}
					k --;
				} /* End of while each unum */
			}
			j --;
		} /* End of while each vnum */

		if (flag[ct] != 0) {
			continue;
		}

		evnum = 0;
		j = 0;
		while (j < NUM_OF_CHILD[pt]) {
			if (TYPE_OF_CHILD[pt][j] == et) {
				evpp = child[j];
				if (evpp != NULL) {
					evnum = (uint32_t)*evpp;
				}
				break;
			}
			j ++;
		}

		j = vnum;
		while (j > 0) {
			vp = vpp[j];
			k = evnum;
			while (k > 0) {
				evp = evpp[k];
				if (vp != NULL && evp != NULL) {
					(void) setup_ref_lcp(&lc, vp, evp);
					ec = ref_new2new(&lc, vp, evp);
					if (ec != 0) {
						return (ec);
					}
				}
				k --;
			}
			j --;
		} /* End of while each vnum */

		flag[et] = 1;
	} /* End of for each type of child */

	return (ec);
}

static int
cb_ref_new2old(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	isns_type_t et;
	uint32_t uu;

	uint32_t ref;

	int match;

	et = lcp->id[2];
	uu = lcp->data[2].ui;

	ref = get_ref_t(obj, et);

	if (ref == uu) {
		match = 1;
	} else {
		match = 0;
	}

	return (match);
}

static int
cb_new_ref(
	void *p1,
	void *p2
)
{
	int ec = 0;

	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	isns_obj_t *a = (isns_obj_t *)p1;
	isns_obj_t *b = (isns_obj_t *)lcp->data[2].ptr;

	ec = new_ref(a, b);

	return (ec);
}

static int
ref_new2old(
	lookup_ctrl_t *lcp,
	isns_type_t et,
	uint32_t uu,
	const isns_obj_t *vp
)
{
	int ec = 0;

	int match;
	uint32_t uid;

	lookup_ctrl_t lc;

	lcp->id[2] = et;
	lcp->data[2].ui = uu;

	uid = 0;
	do {
		lcp->curr_uid = uid;
		match = cache_lookup(lcp, &uid, cb_ref_new2old);
	} while (match == 0 && uid != 0);

	if (match == 0) {
		/* no such ref, create a default one */
		SET_UID_LCP(&lc, et, uu);

		lc.data[2].ptr = (uchar_t *)vp;

		ec = cache_lookup(&lc, NULL, cb_new_ref);
	}

	return (ec);
}

static int
ref_new2new(
	lookup_ctrl_t *lcp,
	const isns_obj_t *p1,
	const isns_obj_t *p2
)
{
	int ec = 0;

	if (is_obj_there(lcp) != 0) {
		return (0);
	}

	ec = new_ref(p1, p2);

	return (ec);
}

static int
new_ref(
	const isns_obj_t *p1,
	const isns_obj_t *p2
)
{
	int ec = 0;

	isns_obj_t *obj;

	obj = make_ref[p1->type](p1, p2);
	if (obj != NULL) {
		ec = register_object(obj, NULL, NULL);
	} else {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * do_dereg:
 *	Physically remove an object along with the children objects,
 *	the reference object and the parent object recursively.
 *	Apporiate SCN is triggered.
 *
 * lcp	- the lookup control for the object being removed.
 * parent_flag	- 1: the object being removed is the parent object;
 *		  0: otherwise.
 * child_flag	- 1: the object being removed is a child object;
 *		  0: otherwise.
 * pending	- 1: do not remove the ESI entry immediately;
 *		  0: remove the ESI entry without any delay.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
do_dereg(
	lookup_ctrl_t *lcp,
	int parent_flag,
	int child_flag,
	int pending
)
{
	int ec = 0;

	isns_obj_t *obj;
	uint32_t *cuidp, num;
	isns_type_t type;
	uint32_t uid;
	int i;

	/* remove the object from object container */
	obj = cache_remove(lcp, 0);

	if (obj == NULL) {
		return (0);
	}

	/* trigger a scn */
	if (scn_q != NULL) {
		(void) make_scn(ISNS_OBJECT_REMOVED, obj);
	}

	/* dereg children */
	i = 0;
	while (ec == 0 && !parent_flag &&
	    i < NUM_OF_CHILD[obj->type]) {
		type = TYPE_OF_CHILD[obj->type][i];
		cuidp = get_child_n(obj, i);
		if (cuidp != NULL) {
			num = *cuidp;
		} else {
			num = 0;
		}
		while (ec == 0 && num > 0) {
			uid = cuidp[num];
			if (uid != 0) {
				SET_UID_LCP(lcp, type, uid);
				ec = do_dereg(lcp,
				    parent_flag,
				    1,
				    pending);
			}
			num --;
		}
		i ++;
	}

	/* clear the ref bit on the ref'd object */
	if (ec == 0 && TYPE_OF_REF[obj->type][0] > 0) {
		uid = 0;
		do {
			(void) setup_ref_lcp(lcp, obj, NULL);
			lcp->curr_uid = uid;
			lcp->data[2].ui = obj->type;
			if (cache_lookup(lcp, &uid, cb_clear_ref) != 0) {
				UPDATE_LCP_UID(lcp, uid);
				ec = do_dereg(lcp,
				    parent_flag,
				    child_flag,
				    pending);
			}
		} while (uid != 0);
	}

	/* remove it from the parent */
	if (ec == 0 && !child_flag &&
	    TYPE_OF_PARENT[obj->type] > 0 &&
	    (uid = setup_parent_lcp(lcp, obj)) != 0) {
		if (cache_lookup(lcp, NULL, cb_remove_child) != 0) {
			UPDATE_LCP_UID(lcp, uid);
			ec = do_dereg(lcp,
			    1,
			    child_flag,
			    0);
		}
	}

	if (ec == 0 && !child_flag) {
		/* remove it from persistent data store */
		if (sys_q) {
			ec = write_data(DATA_DELETE, obj);
		}
		/* remove esi event entry */
		if (ec == 0) {
			(void) esi_remove_obj(obj, pending);
		}

		/* save the parent uid for caller */
		if (TYPE_OF_PARENT[obj->type] != 0) {
			lcp->curr_uid = get_parent_uid(obj);
		} else {
			/* it's the parent itself */
			lcp->curr_uid = get_obj_uid(obj);
		}
	}

	/* remove this portal from scn registry */
	if (ec == 0 &&
	    obj->type == OBJ_PORTAL) {
		(void) remove_scn_portal(get_obj_uid(obj));
	}

	/* free the object */
	(void) free_object(obj);

	return (ec);
}

/*
 * ****************************************************************************
 *
 * dereg_assoc:
 *	Remove one association object from object container.
 *
 * lcp	- the lookup control for the object being removed.
 * return - error code.
 *
 * ****************************************************************************
 */
int
dereg_assoc(
	lookup_ctrl_t *lcp
)
{
	isns_obj_t *obj;

	obj = cache_remove(lcp, 1);

	/* free the object */
	if (obj != NULL) {
		free_object(obj);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * dereg_object:
 *	Remove one object from object container.
 *
 * lcp	- the lookup control for the object being removed.
 * return - error code.
 *
 * ****************************************************************************
 */
int
dereg_object(
	lookup_ctrl_t *lcp,
	int pending
)
{
	return (do_dereg(lcp, 0, 0, pending));
}

/*
 * ****************************************************************************
 *
 * data_sync:
 *	Synchronize the cache with persistent data store.
 *	Flush the cache data to data store if the input ec is zero,
 *	retreat the changes in cache and ignore data store update
 *	if there is an error.
 *
 * ec	- error code.
 * return - error code.
 *
 * ****************************************************************************
 */
int
data_sync(
	int ec
)
{
	/* cache is updated successfully, commit the data to data store */
	if (IS_CACHE_UPDATED()) {
		if (ec == 0) {
			ec = write_data(DATA_COMMIT, NULL);
		}
		if (ec == 0) {
			/* successful, trigger the SCN */
			(void) queue_msg_set(scn_q, SCN_TRIGGER, (void *)NULL);
		} else {
			shutdown_server();
		}
	} else {
		/* ignore all SCNs which have been generated */
		(void) queue_msg_set(scn_q, SCN_IGNORE, (void *)NULL);

		(void) write_data(DATA_RETREAT, NULL);
	}

	return (ec);
}

static pthread_mutex_t name_mtx[3] = {
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_MUTEX_INITIALIZER
};
static const char *name_pattern[3] = {
	"ENTITY_ID_%d",
	"DD_%d",
	"DD-Set_%d"
};
static uint32_t name_count[3] = {
	0,
	0,
	0
};

/*
 * ****************************************************************************
 *
 * make_unique_name:
 *	make a default unique name for a newly registered network entity,
 *	discovery domain or discovery domain set object.
 *
 * len	- pointer of the length of the new name for returning.
 * tag	- which attribute of the new name is for.
 * return - the name being made.
 *
 * ****************************************************************************
 */
static char *
make_unique_name(
	int *len,
	uint32_t tag
)
{
	int i;
	int count;
	char name[32] = { 0 };

	char *p;

	lookup_ctrl_t lc;

	lc.curr_uid = 0;

	switch (tag) {
	case ISNS_EID_ATTR_ID:
		i = 0;
		lc.type = OBJ_ENTITY;
		lc.id[0] = ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID);
		break;
	case ISNS_DD_NAME_ATTR_ID:
		i = 1;
		lc.type = OBJ_DD;
		lc.id[0] = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
		break;
	case ISNS_DD_SET_NAME_ATTR_ID:
		i = 2;
		lc.type = OBJ_DDS;
		lc.id[0] = ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID);
		break;
	default:
		ASSERT(0);
		break;
	}

	lc.op[0] = OP_STRING;
	lc.op[1] = 0;
	do {
		(void) pthread_mutex_lock(&name_mtx[i]);
		count = ++ name_count[i];
		(void) pthread_mutex_unlock(&name_mtx[i]);
		/* no more space, failure */
		if (count == 0) {
			return (NULL);
		}
		(void) sprintf(name, name_pattern[i], count);
		lc.data[0].ptr = (uchar_t *)name;
	} while (is_obj_there(&lc) != 0);

	/* 4-bytes aligned length */
	*len = strlen(name);
	*len = *len + (4 - *len % 4);
	p = (char *)malloc(*len);
	if (p != NULL) {
		(void) strcpy(p, name);
	}
	return (p);
}

#ifdef DEBUG
void
obj_dump(
	void *p
)
{
	print_object(NULL, (isns_obj_t *)p);
}
#endif
