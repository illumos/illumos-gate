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
#include <unistd.h>

#include "isns_server.h"
#include "isns_msgq.h"
#include "isns_cache.h"
#include "isns_cfg.h"
#include "isns_obj.h"
#include "isns_dseng.h"
#include "isns_log.h"
#include "isns_scn.h"
#include "isns_pdu.h"

/*
 * global variables.
 */

/*
 * local variables.
 */
static scn_registry_t *scn_registry = NULL;
static int scn_dispatched = 0;

/*
 * external variables.
 */
extern uint8_t mgmt_scn;
extern msg_queue_t *sys_q;
extern msg_queue_t *scn_q;
extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];

#ifdef DEBUG
extern void dump_pdu1(isns_pdu_t *);
#endif

static int sf_gen(scn_raw_t *);
static int sf_error(scn_raw_t *);

static scn_raw_t *make_raw_entity(isns_obj_t *);
static scn_raw_t *make_raw_iscsi(isns_obj_t *);
static scn_raw_t *make_raw_portal(isns_obj_t *);
static scn_raw_t *make_raw_assoc_iscsi(isns_obj_t *);
static scn_raw_t *make_raw_assoc_dd(isns_obj_t *);
static scn_raw_t *(*const make_raw[MAX_OBJ_TYPE_FOR_SIZE])(isns_obj_t *) = {
	NULL,
	&make_raw_entity,
	&make_raw_iscsi,
	&make_raw_portal,
	NULL,			/* OBJ_PG */
	NULL,			/* OBJ_DD */
	NULL,			/* OBJ_DDS */
	NULL,			/* MAX_OBJ_TYPE */
	NULL,			/* OBJ_DUMMY1 */
	NULL,			/* OBJ_DUMMY2 */
	NULL,			/* OBJ_DUMMY3 */
	NULL,			/* OBJ_DUMMY4 */
	&make_raw_assoc_iscsi,
	&make_raw_assoc_dd
};

static scn_text_t *scn_gen_entity(scn_raw_t *);
static scn_text_t *scn_gen_iscsi(scn_raw_t *);
static scn_text_t *scn_gen_portal(scn_raw_t *);
static scn_text_t *scn_gen_assoc_dd(scn_raw_t *);
static scn_text_t *(*const scn_gen[MAX_OBJ_TYPE_FOR_SIZE])(scn_raw_t *) = {
	NULL,
	&scn_gen_entity,
	&scn_gen_iscsi,
	&scn_gen_portal,
	NULL,			/* OBJ_PG */
	NULL,			/* OBJ_DD */
	NULL,			/* OBJ_DDS */
	NULL,			/* MAX_OBJ_TYPE */
	NULL,			/* OBJ_DUMMY1 */
	NULL,			/* OBJ_DUMMY2 */
	NULL,			/* OBJ_DUMMY3 */
	NULL,			/* OBJ_DUMMY4 */
	&scn_gen_iscsi,
	&scn_gen_assoc_dd
};

#define	SCN_TEST(E, BITMAP, UID1, UID2, NT) \
	(((E) & (BITMAP)) && \
	(!((BITMAP) & (ISNS_INIT_SELF_INFO_ONLY | \
			ISNS_TARGET_SELF_INFO_ONLY)) || \
		((UID1) == (UID2)) || \
		(((BITMAP) & ISNS_INIT_SELF_INFO_ONLY) && \
			((NT) & ISNS_INITIATOR_NODE_TYPE)) || \
		(((BITMAP) & ISNS_TARGET_SELF_INFO_ONLY) && \
			((NT) & ISNS_TARGET_NODE_TYPE))))

/*
 * local functions.
 */

/*
 * ****************************************************************************
 *
 * free_portal_1:
 *	Free one SCN portal or decrease the reference count if the portal
 *	is referenced by other SCN entry(s).
 *
 * p	- the portal.
 *
 * ****************************************************************************
 */
static void
free_portal_1(
	scn_portal_t *p
)
{
	if (p->ref <= 1) {
		if (p->sz == sizeof (in6_addr_t)) {
			free(p->ip.in6);
		}
		free(p);
	} else {
		p->ref --;
	}
}

/*
 * ****************************************************************************
 *
 * free_portal:
 *	Free the unused portals, which are extracted for new SCN entry,
 *	after the new SCN entry is added.
 *
 * p	- the portal.
 *
 * ****************************************************************************
 */
static void
free_portal(
	scn_portal_t *p
)
{
	scn_portal_t *n;

	while (p != NULL) {
		n = p->next;
		free_portal_1(p);
		p = n;
	}
}

/*
 * ****************************************************************************
 *
 * free_portal_list:
 *	Free the list of portals while a SCN entry is being destroyed.
 *
 * l	- the portal list.
 *
 * ****************************************************************************
 */
static void
free_portal_list(
	scn_list_t *l
)
{
	scn_list_t *n;
	scn_portal_t *p;

	while (l != NULL) {
		n = l->next;
		p = l->data.portal;
		free_portal_1(p);
		free(l);
		l = n;
	}
}

/*
 * ****************************************************************************
 *
 * free_scn_text:
 *	Free one SCN or decrease the ref count after the SCN is emitted.
 *
 * text	- the SCN.
 *
 * ****************************************************************************
 */
static void
free_scn_text(
	scn_text_t *text
)
{
	if (text->ref <= 1) {
		free(text->iscsi);
		free(text);
	} else {
		text->ref --;
	}
}

/*
 * ****************************************************************************
 *
 * free_scn_list:
 *	Free the the list of SCN.
 *
 * scn	- the list.
 *
 * ****************************************************************************
 */
static void
free_scn_list(
	scn_t *scn
)
{
	scn_t *next_scn;
	scn_list_t *list;
	scn_list_t *next_list;

	while (scn != NULL) {
		next_scn = scn->next;
		list = scn->data.list;
		while (list != NULL) {
			next_list = list->next;
			free_scn_text(list->data.text);
			free(list);
			list = next_list;
		}
		free(scn);
		scn = next_scn;
	}
}

/*
 * ****************************************************************************
 *
 * free_scn:
 *	Free all of SCNs which are dispatched to every entry.
 *
 * ****************************************************************************
 */
static void
free_scn(
)
{
	scn_registry_t *p;

	p = scn_registry;

	while (p != NULL) {
		free_scn_list(p->scn);
		p->scn = NULL;
		p = p->next;
	}
}

/*
 * ****************************************************************************
 *
 * free_entry:
 *	Free one SCN entry.
 *
 * e	- the SCN entry.
 *
 * ****************************************************************************
 */
static void
free_entry(
	scn_registry_t *e
)
{
	free_scn_list(e->scn);
	free_portal_list(e->portal.l);
	free(e->name);
	free(e);
}

/*
 * ****************************************************************************
 *
 * free_raw:
 *	Free the raw data after the SCN is generated from it.
 *
 * raw	- the raw SCN data.
 *
 * ****************************************************************************
 */
static void
free_raw(
	scn_raw_t *raw
)
{
	if (raw->ref == 0) {
		free(raw->iscsi);
	}
	if (raw->ip != NULL) {
		free(raw->ip);
	}
	free(raw);
}

/*
 * ****************************************************************************
 *
 * scn_add_portal:
 *	Add portals to the portal list of a SCN entry.
 *
 * e	- the SCN entry.
 * p	- the portals.
 * return - 0: successful, otherwise failed.
 *
 * ****************************************************************************
 */
static int
scn_add_portal(
	scn_registry_t *e,
	scn_portal_t *p
)
{
	scn_portal_t *x;
	scn_list_t *l, *m;

	scn_list_t **lp;

	int found_it;

	lp = &e->portal.l;
	while (p != NULL) {
		m = (scn_list_t *)malloc(sizeof (scn_list_t));
		if (m == NULL) {
			return (1);
		}
		found_it = 0;
		e = scn_registry;
		while (e && !found_it) {
			l = e->portal.l;
			while (l && !found_it) {
				x = l->data.portal;
				if (x->uid == p->uid) {
					found_it = 1;
				}
				l = l->next;
			}
			e = e->next;
		}

		if (!found_it) {
			x = p;
		}
		m->data.portal = x;
		x->ref ++;
		m->next = *lp;
		*lp = m;

		p = p->next;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_remove_portal:
 *	Remove a portal from the portal list of every SCN entry.
 *
 * uid	- the portal object uid.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
scn_remove_portal(
	uint32_t uid
)
{
	scn_registry_t **ep, *e;

	scn_portal_t *x;
	scn_list_t **lp, *l;

	ep = &scn_registry;
	e = *ep;

	while (e != NULL) {
		lp = &e->portal.l;
		l = *lp;
		while (l != NULL) {
			x = l->data.portal;
			if (x->uid == uid) {
				/* remove it */
				*lp = l->next;
				free_portal_1(x);
				free(l);
			} else {
				lp = &l->next;
			}
			l = *lp;
		}

		if (e->portal.l == NULL) {
			/* no portal for this entry, destroy it */
			*ep = e->next;
			free_entry(e);
		} else {
			ep = &e->next;
		}
		e = *ep;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_list_add:
 *	Add one SCN entry to the SCN entry list.
 *
 * e	- the SCN entry.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
scn_list_add(
	scn_registry_t *e
)
{
	scn_registry_t **pp;
	scn_portal_t *p;

	p = e->portal.p;
	e->portal.l = NULL;

	pp = &scn_registry;
	while (*pp) {
		if ((*pp)->uid == e->uid) {
			/* replace the bitmap */
			(*pp)->bitmap = e->bitmap;
			free_portal(p);
			free_entry(e);
			return (0);
		} else if ((*pp)->uid < e->uid) {
			break;
		}
		pp = &(*pp)->next;
	}

	(void) scn_add_portal(e, p);

	if (e->portal.l != NULL || sys_q == NULL) {
		/* insert it to the list */
		e->next = *pp;
		*pp = e;
	} else {
		/* no portal, ignore it */
		free_entry(e);
	}

	/* free the unused portal(s) */
	free_portal(p);

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_list_remove:
 *	Remove one SCN entry from the SCN entry list.
 *
 * uid	- the SCN entry unique ID.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
scn_list_remove(
	uint32_t uid
)
{
	scn_registry_t **ep, *e;

	ep = &scn_registry;
	e = *ep;
	while (e) {
		if (e->uid == uid) {
			/* destroy it */
			*ep = e->next;
			free_entry(e);
			break;
		} else if (e->uid < uid) {
			break;
		}
		ep = &e->next;
		e = *ep;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_get_scn_port:
 *	The callback function which returns the SCN port of a portal object.
 *
 * p1	- the portal object.
 * p2	- the lookup control data.
 * return - the SCN port number.
 *
 * ****************************************************************************
 */
static int
cb_get_scn_port(
	void *p1,
	/*ARGSUSED*/
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;

	isns_attr_t *attr = &obj->attrs[
	    ATTR_INDEX_PORTAL(ISNS_SCN_PORT_ATTR_ID)];

	int port = 0;

	if (attr->tag != 0 && attr->value.ui != 0) {
		port = (int)attr->value.ui;
	}

	return (port);
}

/*
 * ****************************************************************************
 *
 * new_scn_portal:
 *	Make a new SCN portal.
 *
 * ref	- the ref count.
 * uid	- the portal object UID.
 * ip	- the ip address.
 * port	- the port number.
 * return - the SCN portal.
 *
 * ****************************************************************************
 */
static scn_portal_t *
new_scn_portal(
	uint32_t ref,
	uint32_t uid,
	in6_addr_t *ip,
	uint32_t port
)
{
	scn_portal_t *p;

	p = (scn_portal_t *)malloc(sizeof (scn_portal_t));
	if (p != NULL) {
		p->uid = uid;
		/* convert the ipv6 to ipv4 */
		if (((int *)ip)[0] == 0x00 &&
		    ((int *)ip)[1] == 0x00 &&
		    ((uchar_t *)ip)[8] == 0x00 &&
		    ((uchar_t *)ip)[9] == 0x00 &&
		    ((uchar_t *)ip)[10] == 0xFF &&
		    ((uchar_t *)ip)[11] == 0xFF) {
			p->sz = sizeof (in_addr_t);
			p->ip.in = ((uint32_t *)ip)[3];
			free(ip);
		} else {
			p->sz = sizeof (in6_addr_t);
			p->ip.in6 = ip;
		}
		p->port = port;
		p->ref = ref;
		p->so = 0;
		p->next = NULL;
	}

	return (p);
}

/*
 * ****************************************************************************
 *
 * extract scn_portal:
 *	Extract the SCN portal(s) for a storage node.
 *
 * name	- the storage node name.
 * return - the SCN portal list.
 *
 * ****************************************************************************
 */
static scn_portal_t *
extract_scn_portal(
	uchar_t *name
)
{
	scn_portal_t *list = NULL;
	scn_portal_t *p;

	lookup_ctrl_t lc_pg, lc_p;
	uint32_t pg_uid, uid;

	in6_addr_t *ip;
	uint32_t port;

	lc_pg.type = OBJ_PG;
	lc_pg.curr_uid = 0;
	lc_pg.id[0] = ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID);
	lc_pg.op[0] = OP_STRING;
	lc_pg.data[0].ptr = name;
	lc_pg.op[1] = 0;

	lc_pg.id[1] = ISNS_PG_PORTAL_IP_ADDR_ATTR_ID;
	lc_pg.id[2] = ISNS_PG_PORTAL_PORT_ATTR_ID;

	lc_p.type = OBJ_PORTAL;
	lc_p.curr_uid = 0;
	lc_p.id[0] = ATTR_INDEX_PORTAL(ISNS_PORTAL_IP_ADDR_ATTR_ID);
	lc_p.op[0] = OP_MEMORY_IP6;
	lc_p.id[1] = ATTR_INDEX_PORTAL(ISNS_PORTAL_PORT_ATTR_ID);
	lc_p.op[1] = OP_INTEGER;
	lc_p.op[2] = 0;

	while (cache_lookup(&lc_pg, &pg_uid, cb_clone_attrs) == 0 &&
	    pg_uid != 0) {
		ip = lc_pg.data[1].ip;
		port = lc_pg.data[2].ui;
		if (ip != NULL) {
			lc_p.data[0].ip = ip;
			lc_p.data[1].ui = port;
			port = cache_lookup(&lc_p, &uid, cb_get_scn_port);
			if (port != 0 && uid != 0) {
				/* ref starts from 1 */
				p = new_scn_portal(1, uid, ip, port);
				if (p != NULL) {
					p->next = list;
					list = p;
				} else {
					free(ip);
					free(p);
				}
			} else {
				/* portal not registered or no scn port */
				free(ip);
			}
		}
		lc_pg.curr_uid = pg_uid;
	}

	return (list);
}

/*
 * ****************************************************************************
 *
 * cb_update_scn_bitmap:
 *	The callback function which updates the SCN Bitmap attribute of
 *	a storage node object.
 *
 * p1	- the storage node object.
 * p2	- the lookup control data.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
cb_update_scn_bitmap(
	void *p1,
	void *p2
)
{
	int ec = 0;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	int id = ATTR_INDEX_ISCSI(ISNS_ISCSI_SCN_BITMAP_ATTR_ID);
	isns_attr_t *attr = &obj->attrs[id];

	uint32_t bitmap = lcp->data[2].ui;

	if (bitmap != 0) {
		attr->tag = ISNS_ISCSI_SCN_BITMAP_ATTR_ID;
		attr->len = 4;
	} else if (attr->tag == 0) {
		return (ec);
	} else {
		attr->tag = 0;
		attr->len = 0;
	}
	attr->value.ui = bitmap;

	if (sys_q != NULL) {
		ec = write_data(DATA_UPDATE, obj);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * cb_get_node_type:
 *	The callback function which returns the node type attribute of
 *	a storage node object.
 *
 * p1	- the storage node object.
 * p2	- the lookup control data.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
cb_get_node_type(
	void *p1,
	/* LINTED E_FUNC_ARG_UNUSED */
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	isns_attr_t *attr = &obj->attrs[
	    ATTR_INDEX_ISCSI(ISNS_ISCSI_NODE_TYPE_ATTR_ID)];
	int nt = (int)attr->value.ui;

	return (nt);
}

/*
 * ****************************************************************************
 *
 * cb_get_node_type:
 *	The callback function which returns the storage node object UID
 *	from a portal group object.
 *
 * p1	- the pg object.
 * p2	- the lookup control data.
 * return - the storage node object UID.
 *
 * ****************************************************************************
 */
static int
cb_pg_node(
	void *p1,
	/* LINTED E_FUNC_ARG_UNUSED */
	void *p2
)
{
	uint32_t ref;

	ref = get_ref_t(p1, OBJ_ISCSI);

	return ((int)ref);
}

/*
 * ****************************************************************************
 *
 * make_raw_entity:
 *	Make raw SCN data with a Network Entity object.
 *
 * obj	- the network entity object.
 * return - the raw SCN data.
 *
 * ****************************************************************************
 */
static scn_raw_t *
make_raw_entity(
	/*ARGSUSED*/
	isns_obj_t *obj
)
{
	scn_raw_t *raw;

	raw = (scn_raw_t *)malloc(sizeof (scn_raw_t));
	if (raw != NULL) {
		raw->type = obj->type;
		raw->uid = get_obj_uid(obj);
		raw->iscsi = NULL;
		raw->ref = 0;
		raw->ilen = 0;
		raw->nt = 0;
		raw->ip = NULL;
		raw->dd_id = 0;
		raw->dds_id = 0;
	} else {
		isnslog(LOG_DEBUG, "make_raw_entity", "malloc failed.");
	}

	return (raw);
}

/*
 * ****************************************************************************
 *
 * make_raw_iscsi:
 *	Make raw SCN data with a Storage Node object.
 *
 * obj	- the storage node object.
 * return - the raw SCN data.
 *
 * ****************************************************************************
 */
static scn_raw_t *
make_raw_iscsi(
	isns_obj_t *obj
)
{
	uint32_t uid;
	uint32_t nt;
	uchar_t *iscsi;
	uint32_t ilen;

	isns_attr_t *attr;

	scn_raw_t *raw;

	uid = get_obj_uid(obj);
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NODE_TYPE_ATTR_ID)];
	nt = attr->value.ui;
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)];

	raw = (scn_raw_t *)malloc(sizeof (scn_raw_t));
	ilen = attr->len;
	iscsi = (uchar_t *)malloc(ilen);
	if (raw != NULL && iscsi != NULL) {
		/* copy the iscsi storage node name */
		(void) strcpy((char *)iscsi, (char *)attr->value.ptr);

		raw->type = obj->type;
		raw->uid = uid;
		raw->iscsi = iscsi;
		raw->ref = 0;
		raw->ilen = ilen;
		raw->nt = nt;
		raw->ip = NULL;
		raw->dd_id = 0;
		raw->dds_id = 0;
	} else {
		free(raw);
		free(iscsi);
		raw = NULL;
		isnslog(LOG_DEBUG, "make_raw_iscsi", "malloc failed.");
	}

	return (raw);
}

/*
 * ****************************************************************************
 *
 * make_raw_portal:
 *	Make raw SCN data with a Portal object.
 *
 * obj	- the portal object.
 * return - the raw SCN data.
 *
 * ****************************************************************************
 */
static scn_raw_t *
make_raw_portal(
	isns_obj_t *obj
)
{
	isns_attr_t *attr;
	in6_addr_t *ip;
	uint32_t port;

	scn_raw_t *raw;

	raw = (scn_raw_t *)malloc(sizeof (scn_raw_t));
	ip = (in6_addr_t *)malloc(sizeof (in6_addr_t));
	if (raw != NULL && ip != NULL) {
		attr = &obj->attrs[
		    ATTR_INDEX_PORTAL(ISNS_PORTAL_IP_ADDR_ATTR_ID)];
		(void) memcpy(ip, attr->value.ip, sizeof (in6_addr_t));
		attr = &obj->attrs[
		    ATTR_INDEX_PORTAL(ISNS_PORTAL_PORT_ATTR_ID)];
		port = attr->value.ui;

		raw->type = obj->type;
		raw->uid = 0;
		raw->iscsi = NULL;
		raw->ref = 0;
		raw->ilen = 0;
		raw->nt = 0;
		raw->ip = ip;
		raw->port = port;
		raw->dd_id = 0;
		raw->dds_id = 0;
	} else {
		free(ip);
		free(raw);
		raw = NULL;
		isnslog(LOG_DEBUG, "make_raw_portal", "malloc failed.");
	}

	return (raw);
}

/*
 * ****************************************************************************
 *
 * make_raw_assoc_iscsi:
 *	Make raw SCN data with a Discovery Domain member association.
 *
 * obj	- the member association object.
 * return - the raw SCN data.
 *
 * ****************************************************************************
 */
static scn_raw_t *
make_raw_assoc_iscsi(
	isns_obj_t *obj
)
{
	uint32_t uid;
	uint32_t dd_id;
	uint32_t nt;

	lookup_ctrl_t lc;
	isns_attr_t *attr;

	scn_raw_t *raw;
	uchar_t *iscsi;
	uint32_t ilen;

	uid = get_obj_uid(obj);
	dd_id = get_parent_uid(obj);

	SET_UID_LCP(&lc, OBJ_ISCSI, uid);

	nt = cache_lookup(&lc, NULL, cb_get_node_type);

	attr = &obj->attrs[ATTR_INDEX_ASSOC_ISCSI(ISNS_DD_ISCSI_NAME_ATTR_ID)];

	raw = (scn_raw_t *)malloc(sizeof (scn_raw_t));
	ilen = attr->len;
	iscsi = (uchar_t *)malloc(ilen);
	if (raw != NULL && iscsi != NULL) {
		/* copy the iscsi storage node name */
		(void) strcpy((char *)iscsi, (char *)attr->value.ptr);

		raw->type = obj->type;
		raw->uid = uid;
		raw->iscsi = iscsi;
		raw->ref = 0;
		raw->ilen = ilen;
		raw->nt = nt;
		raw->ip = NULL;
		raw->dd_id = dd_id;
		raw->dds_id = 0;
	} else {
		free(raw);
		free(iscsi);
		raw = NULL;
		isnslog(LOG_DEBUG, "make_raw_assoc_iscsi", "malloc failed.");
	}

	return (raw);
}

/*
 * ****************************************************************************
 *
 * make_raw_assoc_dd:
 *	Make raw SCN data with a Discovery Domain Set member association.
 *
 * obj	- the member association object.
 * return - the raw SCN data.
 *
 * ****************************************************************************
 */
static scn_raw_t *
make_raw_assoc_dd(
	isns_obj_t *obj
)
{
	scn_raw_t *raw;

	raw = (scn_raw_t *)malloc(sizeof (scn_raw_t));
	if (raw != NULL) {
		raw->type = obj->type;
		raw->uid = 0;
		raw->iscsi = NULL;
		raw->ref = 0;
		raw->ilen = 0;
		raw->nt = 0;
		raw->ip = NULL;
		raw->dd_id = get_obj_uid(obj);
		raw->dds_id = get_parent_uid(obj);
	} else {
		isnslog(LOG_DEBUG, "make_raw_assoc_dd", "malloc failed.");
	}

	return (raw);
}

/*
 * ****************************************************************************
 *
 * scn_gen_entity:
 *	Generate SCN with the raw SCN data from a Network Entity object.
 *
 * raw	- the raw SCN data.
 * return - the SCN.
 *
 * ****************************************************************************
 */
static scn_text_t *
scn_gen_entity(
	/* LINTED E_FUNC_ARG_UNUSED */
	scn_raw_t *raw
)
{
	return (NULL);
}

/*
 * ****************************************************************************
 *
 * scn_gen_iscsi:
 *	Generate SCN with the raw SCN data from a Storage Node object.
 *
 * raw	- the raw SCN data.
 * return - the SCN.
 *
 * ****************************************************************************
 */
static scn_text_t *
scn_gen_iscsi(
	scn_raw_t *raw
)
{
	scn_text_t *text;

	text = (scn_text_t *)malloc(sizeof (scn_text_t));
	if (text != NULL) {
		text->flag = 0;
		text->ref = 1; /* start with 1 */
		text->uid = raw->uid;
		text->iscsi = raw->iscsi;
		raw->ref ++;
		text->ilen = raw->ilen;
		text->nt = raw->nt;
		text->dd_id = raw->dd_id;
		text->dds_id = raw->dds_id;
		text->next = NULL;
	} else {
		isnslog(LOG_DEBUG, "scn_gen_iscsi", "malloc failed.");
	}
	return (text);
}

/*
 * ****************************************************************************
 *
 * scn_gen_portal:
 *	Generate SCN with the raw SCN data from a Portal object.
 *
 * raw	- the raw SCN data.
 * return - the SCN.
 *
 * ****************************************************************************
 */
static scn_text_t *
scn_gen_portal(
	scn_raw_t *raw
)
{
	in6_addr_t *ip;
	uint32_t port;

	uint32_t pg_uid, uid;
	lookup_ctrl_t pg_lc, lc;

	uint32_t nt;
	uchar_t *name;
	int ilen;

	scn_text_t *text, *l = NULL;

	ip = raw->ip;
	port = raw->port;

	pg_lc.curr_uid = 0;
	pg_lc.type = OBJ_PG;
	pg_lc.id[0] = ATTR_INDEX_PG(ISNS_PG_PORTAL_IP_ADDR_ATTR_ID);
	pg_lc.op[0] = OP_MEMORY_IP6;
	pg_lc.data[0].ip = ip;
	pg_lc.id[1] = ATTR_INDEX_PG(ISNS_PG_PORTAL_PORT_ATTR_ID);
	pg_lc.op[1] = OP_INTEGER;
	pg_lc.data[1].ui = port;
	pg_lc.op[2] = 0;

	SET_UID_LCP(&lc, OBJ_ISCSI, 0);

	lc.id[1] = ISNS_ISCSI_NAME_ATTR_ID;
	lc.id[2] = ISNS_ISCSI_NODE_TYPE_ATTR_ID;
	lc.data[1].ptr = NULL;

	/* get a pg which is associated to the portal */
	uid = cache_lookup(&pg_lc, &pg_uid, cb_pg_node);
	while (pg_uid != 0) {
		if (uid != 0) {
			lc.data[0].ui = uid;
			(void) cache_lookup(&lc, NULL, cb_clone_attrs);
			name = lc.data[1].ptr;
			if (name != NULL) {
				nt = lc.data[2].ui;
				text = (scn_text_t *)malloc(
				    sizeof (scn_text_t));
				if (text != NULL) {
					text->flag = 0;
					text->ref = 1; /* start with 1 */
					text->uid = uid;
					text->iscsi = name;
					ilen = strlen((char *)name);
					ilen += 4 - (ilen % 4);
					text->ilen = ilen;
					text->nt = nt;
					text->dd_id = 0;
					text->dds_id = 0;
					text->next = l;
					l = text;
				} else {
					free(name);
					isnslog(LOG_DEBUG, "scn_gen_portal",
					    "malloc failed.");
				}
				lc.data[1].ptr = NULL;
			} else {
				isnslog(LOG_WARNING, "scn_gen_portal",
				    "cannot get node name.");
			}
		}

		/* get the next pg */
		pg_lc.curr_uid = pg_uid;
		uid = cache_lookup(&pg_lc, &pg_uid, cb_pg_node);
	}

	/* update the iscsi storage node object */
	raw->event = ISNS_OBJECT_UPDATED;

	return (l);
}

/*
 * ****************************************************************************
 *
 * scn_gen_assoc_dd:
 *	Generate SCN with the raw SCN data from a DD membership object.
 *
 * raw	- the raw SCN data.
 * return - the SCN.
 *
 * ****************************************************************************
 */
static scn_text_t *
scn_gen_assoc_dd(
	/* LINTED E_FUNC_ARG_UNUSED */
	scn_raw_t *raw
)
{
	return (NULL);
}

/*
 * ****************************************************************************
 *
 * make_scn:
 *	Make a SCN with an event and an object.
 *
 * event - the event.
 * obj	 - the object.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
int
make_scn(
	uint32_t event,
	isns_obj_t *obj
)
{
	scn_raw_t *raw = NULL;

	scn_raw_t *(*f)(isns_obj_t *) = make_raw[obj->type];

	if (f != NULL) {
		/* make raw scn data */
		raw = f(obj);
	}
	if (raw != NULL) {
		/* trigger an scn event */
		raw->event = event;
		(void) queue_msg_set(scn_q, SCN_SET, (void *)raw);
	}

	return (0);
}

/*
 * data structure of the SCN state transition table.
 */
typedef struct scn_tbl {
	int state;
	uint32_t event;
	isns_type_t type;
	int (*sf)(scn_raw_t *);
	int next_state;
} scn_tbl_t;

/*
 * the SCN state transition table.
 */
static const scn_tbl_t stbl[] = {
	{ -1, 0, OBJ_PG, NULL, 0 },
	{ -1, 0, OBJ_DD, NULL, 0 },
	{ -1, 0, OBJ_DDS, NULL, 0 },

	{ 0, ISNS_OBJECT_ADDED, OBJ_ENTITY, NULL, 1 },
	{ 1, ISNS_OBJECT_ADDED, OBJ_ISCSI, sf_gen, 1 },
	{ 1, ISNS_OBJECT_ADDED, 0, NULL, 1 },

	{ 0, ISNS_OBJECT_UPDATED, OBJ_ENTITY, sf_gen, 2 },
	{ 2, ISNS_OBJECT_UPDATED, 0, NULL, 2 },
	{ 2, ISNS_OBJECT_ADDED, OBJ_ISCSI, sf_gen, 2 },
	{ 2, ISNS_OBJECT_ADDED, 0, NULL, 2 },

	{ 0, ISNS_OBJECT_REMOVED, OBJ_ENTITY, NULL, 3 },
	{ 0, ISNS_OBJECT_REMOVED, 0, sf_gen, 4 },
	{ 3, ISNS_OBJECT_REMOVED, OBJ_ISCSI, sf_gen, 3 },
	{ 3, ISNS_OBJECT_REMOVED, 0, NULL, 3 },
	{ 4, ISNS_OBJECT_REMOVED, 0, sf_gen, 4 },

	{ 0, ISNS_MEMBER_ADDED, OBJ_ASSOC_ISCSI, sf_gen, 5 },
	{ 5, ISNS_MEMBER_ADDED, OBJ_ASSOC_ISCSI, sf_gen, 5 },

	{ 0, ISNS_MEMBER_ADDED, OBJ_ASSOC_DD, sf_gen, 6 },
	{ 6, ISNS_MEMBER_ADDED, OBJ_ASSOC_DD, sf_gen, 6 },

	{ 0, ISNS_MEMBER_REMOVED, OBJ_ASSOC_ISCSI, sf_gen, 7 },
	{ 7, ISNS_MEMBER_REMOVED, OBJ_ASSOC_ISCSI, sf_gen, 7 },

	{ 0, ISNS_MEMBER_REMOVED, OBJ_ASSOC_DD, sf_gen, 8 },
	{ 8, ISNS_MEMBER_REMOVED, OBJ_ASSOC_DD, sf_gen, 8 },

	{ -1, 0, 0, sf_error, -1 }
};

/*
 * ****************************************************************************
 *
 * scn_disp1:
 *	Dispatch one SCN to one SCN entry.
 *
 * event - the event.
 * p	 - the SCN entry.
 * t	 - the SCN.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
scn_disp1(
	uint32_t event,
	scn_registry_t *p,
	scn_text_t *t
)
{
	scn_t *s, *r = NULL;
	scn_list_t *l, **lp;

	s = p->scn;

	while (s != NULL) {
		if (s->event == event) {
			l = s->data.list;
			do {
				if (l->data.text->uid == t->uid) {
					/* duplicated */
					return (0);
				}
				lp = &l->next;
				l = *lp;
			} while (l != NULL);
			break;
		}
		r = s;
		s = s->next;
	}

	l = (scn_list_t *)malloc(sizeof (scn_list_t));
	if (l != NULL) {
		if (s == NULL) {
			s = (scn_t *)malloc(sizeof (scn_t));
			if (s != NULL) {
				s->event = event;
				s->next = NULL;
				if (r != NULL) {
					r->next = s;
				} else {
					p->scn = s;
				}
				lp = &s->data.list;
			} else {
				free(l);
				isnslog(LOG_DEBUG, "scn_disp1",
				    "malloc scn failed.\n");
				return (0);
			}
		}

		t->ref ++;
		l->data.text = t;
		l->next = NULL;
		*lp = l;
	} else {
		isnslog(LOG_DEBUG, "scn_disp1",
		    "malloc list failed.\n");
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_disp1:
 *	Dispatch one SCN to every SCN entry and update the dispatch status.
 *
 * event - the event.
 * text	 - the SCN.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
scn_disp(
	uint32_t event,
	scn_text_t *text
)
{
	scn_registry_t *registry, *p;
	uint32_t dd_id = 0;

	scn_text_t *t;

	uint32_t e;

	registry = scn_registry;

	t = text;
	while (t != NULL) {
		e = event;
		if (t->flag == 0) {
			if (e & ISNS_MEMBER_ADDED) {
				e |= ISNS_OBJECT_ADDED;
			} else if (e & ISNS_MEMBER_REMOVED) {
				e |= ISNS_OBJECT_REMOVED;
			}
		}
		p = registry;
		while (p != NULL) {
			if (SCN_TEST(e, p->bitmap, p->uid, t->uid, t->nt)) {
				if (p->bitmap & ISNS_MGMT_REG) {
					/* management scn are not bound */
					/* by discovery domain service. */
					dd_id = 1;
				} else {
					dd_id = 0;
					/* lock the cache for reading */
					(void) cache_lock_read();
					/* verify common dd */
					do {
						dd_id = get_common_dd(
						    p->uid,
						    t->uid,
						    dd_id);
					} while (dd_id > 0 &&
					    is_dd_active(dd_id) == 0);
					/* unlock the cache */
					(void) cache_unlock_nosync();
				}
				if (dd_id != 0) {
					(void) scn_disp1(e, p, t);
				}
			}
			p = p->next;
		}
		t = t->next;
	}

	while (text != NULL) {
		t = text->next;
		/* clean up the scn text(s) which nobody cares about. */
		free_scn_text(text);
		text = t;
	}

	if (dd_id != 0) {
		/* scn(s) are dispatched. */
		scn_dispatched = 1;
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * sf_gen:
 *	State transition function which generates and dispatches SCN(s).
 *
 * raw	- the raw SCN data.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
sf_gen(
	scn_raw_t *raw
)
{
	uint32_t event;

	scn_text_t *(*gen)(scn_raw_t *);
	scn_text_t *text = NULL;

	gen = scn_gen[raw->type];
	if (gen != NULL) {
		text = gen(raw);
	}

	event = raw->event;
	if (text != NULL) {
		(void) scn_disp(event, text);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * sf_error:
 *	State transition function for an error state. It free any SCN(s)
 *	which have been generated and dispatched previously.
 *
 * raw	- the raw SCN data.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
sf_error(
	/* LINTED E_FUNC_ARG_UNUSED */
	scn_raw_t *raw
)
{
	free_scn();

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_transition:
 *	Performs the state transition when a SCN event occurs.
 *
 * state - the previous state.
 * raw	 - the raw SCN data.
 * return - the next state.
 *
 * ****************************************************************************
 */
static int
scn_transition(
	int state,
	scn_raw_t *raw
)
{
	uint32_t event = raw->event;
	isns_type_t type = raw->type;

	int new_state = state;

	const scn_tbl_t *tbl;

	tbl = &stbl[0];
	for (;;) {
		if ((tbl->state == -1 || tbl->state == state) &&
		    (tbl->event == 0 || tbl->event == event) &&
		    (tbl->type == 0 || tbl->type == type)) {
			if (tbl->next_state != 0) {
				new_state = tbl->next_state;
			}
			if (tbl->sf != NULL) {
				tbl->sf(raw);
			}
			break;
		}
		tbl ++;
	}

	if (new_state == -1) {
		isnslog(LOG_DEBUG, "scn_transition",
		    "prev state: %d new event: 0x%x new object: %d.\n",
		    state, event, type);
		new_state = 0;
	}

	state = new_state;

	return (state);
}

/*
 * ****************************************************************************
 *
 * connect_to:
 *	Create socket connection with peer network portal.
 *
 * sz	- the size of the ip addr.
 * in	- the ipv4 address.
 * in6	- the ipv6 address.
 * port2- the port info.
 * return - the socket descriptor.
 *
 * ****************************************************************************
 */
int
connect_to(
	int sz,
	in_addr_t in,
	/* LINTED E_FUNC_ARG_UNUSED */
	in6_addr_t *in6,
	uint32_t port2
)
{
	int so = -1;

	union {
		struct sockaddr sin;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} ca = { 0 };

	int tcp;
	uint16_t port;

	tcp = (port2 & 0x10000) == 0 ? 1 : 0;
	port = (uint16_t)(port2 & 0xFFFF);
	if (sz == sizeof (in_addr_t)) {
		if (tcp != 0) {
			so = socket(AF_INET, SOCK_STREAM, 0);
			if (so != -1) {
				ca.in.sin_family = AF_INET;
				ca.in.sin_port = htons(port);
				ca.in.sin_addr.s_addr = in;
				if (connect(so, &ca.sin, sizeof (ca.in)) !=
				    0) {
					isnslog(LOG_DEBUG, "connect_to",
					    "connect() failed %%m.");
					(void) close(so);
					so = -1;
				}
			} else {
				isnslog(LOG_DEBUG, "connect_to",
				    "socket() failed %%m.");
			}
		} else {
			/* FIXME: UDP support */
			isnslog(LOG_DEBUG, "connect_to", "No UDP support.");
		}
	} else {
		/* FIXME: IPv6 support */
		isnslog(LOG_DEBUG, "connect_to", "No IPv6 support.");
	}

	return (so);
}

/*
 * ****************************************************************************
 *
 * emit_scn:
 *	Emit the SCN to any portal of the peer storage node.
 *
 * list	- the list of portal.
 * pdu	- the SCN packet.
 * pl	- the SCN packet payload length.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
emit_scn(
	scn_list_t *list,
	isns_pdu_t *pdu,
	size_t pl
)
{
	int so = 0;
	scn_list_t *l;
	scn_portal_t *p;

	isns_pdu_t *rsp = NULL;
	size_t rsp_sz;

	pdu->version = htons((uint16_t)ISNSP_VERSION);
	pdu->func_id = htons((uint16_t)ISNS_SCN);
	pdu->xid = htons(get_server_xid());

	l = list;
	while (l != NULL) {
		p = l->data.portal;
		so = connect_to(p->sz, p->ip.in, p->ip.in6, p->port);
		if (so != -1) {
			if (isns_send_pdu(so, pdu, pl) == 0) {
				/* This may help Solaris iSCSI Initiator */
				/* not to panic frequently. */
				(void) isns_rcv_pdu(so, &rsp, &rsp_sz,
				    ISNS_RCV_SHORT_TIMEOUT);
			} else {
				isnslog(LOG_DEBUG, "emit_scn",
				    "sending packet failed.");
			}
			(void) close(so);
			/* p->so = so; */
			break;
		}
		l = l->next;
	}

	if (rsp != NULL) {
#ifdef DEBUG
		dump_pdu1(rsp);
#endif
		free(rsp);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_trigger1:
 *	Trigger one SCN for one SCN entry.
 *
 * t	- the time that SCN is being triggered.
 * p	- the SCN entry.
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
scn_trigger1(
	time_t t,
	scn_registry_t *p
)
{
	int ec;

	isns_pdu_t *pdu = NULL;
	size_t sz;
	size_t pl;

	scn_t *s;
	scn_list_t *l;
	scn_text_t *x;

	union {
		uint32_t i32;
		uint64_t i64;
	} u;

#ifdef DEBUG
	char buff[1024] = { 0 };
	char *logbuff = buff;
#endif

	ec = pdu_reset_scn(&pdu, &pl, &sz);
	if (pdu == NULL) {
		goto scn_done;
	}

	/* add destination attribute */
	ec = pdu_add_tlv(&pdu, &pl, &sz,
	    ISNS_ISCSI_NAME_ATTR_ID,
	    p->nlen,
	    (void *)p->name, 0);
	if (ec != 0) {
		goto scn_done;
	}

#ifdef DEBUG
	sprintf(logbuff, "==>%s ", p->name);
	logbuff += strlen(logbuff);
#endif

	/* add timestamp */
	u.i64 = BE_64((uint64_t)t);
	ec = pdu_add_tlv(&pdu, &pl, &sz,
	    ISNS_TIMESTAMP_ATTR_ID,
	    8,
	    (void *)&u.i64, 1);

	s = p->scn;
	while (s != NULL && ec == 0) {
		u.i32 = htonl(s->event);
		ec = pdu_add_tlv(&pdu, &pl, &sz,
		    ISNS_ISCSI_SCN_BITMAP_ATTR_ID,
		    4,
		    (void *)&u.i32, 1);
#ifdef DEBUG
		sprintf(logbuff, "EVENT [%d] ", s->event);
		logbuff += strlen(logbuff);
#endif
		l = s->data.list;
		while (l != NULL && ec == 0) {
			x = l->data.text;
			if (x->flag == 0) {
				ec = pdu_add_tlv(&pdu, &pl, &sz,
				    ISNS_ISCSI_NAME_ATTR_ID,
				    x->ilen, (void *)x->iscsi, 0);
#ifdef DEBUG
				sprintf(logbuff, "FROM [%s] ", x->iscsi);
				logbuff += strlen(logbuff);
#endif
				if (ec == 0 &&
				    (p->bitmap &
				    (ISNS_MEMBER_ADDED |
				    ISNS_MEMBER_REMOVED))) {
					/* management SCN */
					u.i32 = htonl(x->dd_id);
					ec = pdu_add_tlv(&pdu, &pl, &sz,
					    ISNS_DD_ID_ATTR_ID,
					    4, (void *)&u.i32, 1);
#ifdef DEBUG
					sprintf(logbuff, "IN DD [%d] ",
					    x->dd_id);
					logbuff += strlen(logbuff);
#endif
				}
			} else {
				/* add(remove) dd to(from) dd-set */
				u.i32 = htonl(x->dd_id);
				ec = pdu_add_tlv(&pdu, &pl, &sz,
				    ISNS_DD_ID_ATTR_ID,
				    4, (void *)&u.i32, 1);
				u.i32 = htonl(x->dds_id);
				if (ec == 0) {
					ec = pdu_add_tlv(&pdu, &pl, &sz,
					    ISNS_DD_ID_ATTR_ID,
					    4, (void *)&u.i32, 1);
				}
#ifdef DEBUG
				sprintf(logbuff, "FROM [%d] ", x->dd_id);
				logbuff += strlen(logbuff);
				sprintf(logbuff, "IN [%d] ", x->dds_id);
				logbuff += strlen(logbuff);
#endif
			}
			l = l->next;
		}
		s = s->next;
	}

scn_done:
	if (ec == 0) {
#ifdef DEBUG
		isnslog(LOG_DEBUG, "scn_trigger1", buff);
#endif
		ec = emit_scn(p->portal.l, pdu, pl);
	} else {
		isnslog(LOG_DEBUG, "scn_trigger1", " failed.\n");
	}

	free(pdu);

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_trigger:
 *	Trigger one SCN for every SCN entry.
 *
 * return - always successful (0).
 *
 * ****************************************************************************
 */
static int
scn_trigger(
)
{
	time_t t;
	scn_registry_t *p;

	t = time(NULL);

	p = scn_registry;
	while (p != NULL) {
		if (p->scn != NULL) {
			(void) scn_trigger1(t, p);
		}
		p = p->next;
	}

	return (0);
}

/*
 * global functions.
 */

/*
 * ****************************************************************************
 *
 * scn_list_load:
 *	Load one SCN entry and add it to the SCN entry list.
 *
 * uid	- the Storage Node object UID.
 * node	- the Storage Node name.
 * nlen	- the length of the name.
 * bitmap - the SCN bitmap.
 * return - error code.
 *
 * ****************************************************************************
 */
int
scn_list_load(
	uint32_t uid,
	uchar_t *node,
	uint32_t nlen,
	uint32_t bitmap
)
{
	int ec = 0;

	scn_registry_t *list;
	uchar_t *name;

	list = (scn_registry_t *)malloc(sizeof (scn_registry_t));
	name = (uchar_t *)malloc(nlen);

	if (list != NULL && name != NULL) {
		list->uid = uid;
		(void) strcpy((char *)name, (char *)node);
		list->name = name;
		list->nlen = nlen;
		list->bitmap = bitmap;
		list->portal.l = NULL;
		list->scn = NULL;
		list->next = NULL;
		ASSERT(scn_q == NULL);
		(void) scn_list_add(list);
	} else {
		free(list);
		free(name);
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * verify_scn_portal:
 *	Extract and verify portals for every SCN entry(s) after they are
 *	loaded from data store, for those which do not have a SCN portal,
 *	remove it from the SCN entry list.
 *
 * return - 1: error occurs, otherwise 0.
 *
 * ****************************************************************************
 */
int
verify_scn_portal(
)
{
	scn_registry_t **pp, *e;
	scn_portal_t *p;

	pp = &scn_registry;
	while (*pp != NULL) {
		e = *pp;
		p = extract_scn_portal(e->name);
		if (p != NULL) {
			if (scn_add_portal(e, p) != 0) {
				return (1);
			}
		}
		if (e->portal.l != NULL) {
			pp = &e->next;
		} else {
			/* remove this entry */
			*pp = e->next;
			free_entry(e);
		}
		/* free the unused portal(s) */
		free_portal(p);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * add_scn_entry:
 *	Add a SCN entry.
 *
 * node	- the Storage Node name.
 * nlen	- the length of the name.
 * bitmap - the SCN bitmap.
 * return - error code.
 *
 * ****************************************************************************
 */
int
add_scn_entry(
	uchar_t *node,
	uint32_t nlen,
	uint32_t bitmap
)
{
	int ec = 0;

	uint32_t mgmt;
	scn_portal_t *p;

	lookup_ctrl_t lc;
	uint32_t uid;
	scn_registry_t *e;
	uchar_t *name;

	mgmt = bitmap & (
	    ISNS_MGMT_REG |
	    ISNS_MEMBER_REMOVED |
	    ISNS_MEMBER_ADDED);

	if ((mgmt > 0 &&
	    (mgmt_scn == 0 ||
	    mgmt < ISNS_MGMT_REG ||
	    is_control_node(node) == 0)) ||
	    (p = extract_scn_portal(node)) == NULL) {
		return (ISNS_RSP_SCN_REGIS_REJECTED);
	}

	e = (scn_registry_t *)malloc(sizeof (scn_registry_t));
	name = (uchar_t *)malloc(nlen);
	if (e != NULL && name != NULL) {
		lc.type = OBJ_ISCSI;
		lc.curr_uid = 0;
		lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
		lc.data[0].ptr = node;
		lc.op[0] = OP_STRING;
		lc.op[1] = 0;
		lc.data[2].ui = bitmap;
		ec = cache_lookup(&lc, &uid, cb_update_scn_bitmap);
		if (uid == 0) {
			ec = ISNS_RSP_SCN_REGIS_REJECTED;
		}
		if (ec == 0) {
			e->uid = uid;
			(void) strcpy((char *)name, (char *)node);
			e->name = name;
			e->nlen = nlen;
			e->bitmap = bitmap;
			e->portal.p = p;
			e->scn = NULL;
			e->next = NULL;
			(void) queue_msg_set(scn_q, SCN_ADD, (void *)e);
		}
	} else {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	if (ec != 0) {
		free(e);
		free(name);
		free_portal(p);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * remove_scn_entry:
 *	Remove a SCN entry.
 *
 * node	- the Storage Node name.
 * return - error code.
 *
 * ****************************************************************************
 */
int
remove_scn_entry(
	uchar_t *node
)
{
	int ec = 0;

	lookup_ctrl_t lc;
	uint32_t uid;

	lc.type = OBJ_ISCSI;
	lc.curr_uid = 0;
	lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
	lc.data[0].ptr = node;
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;
	lc.data[2].ui = 0;
	ec = cache_lookup(&lc, &uid, cb_update_scn_bitmap);
	if (ec == 0 && uid != 0) {
		(void) queue_msg_set(scn_q, SCN_REMOVE, (void *)uid);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * remove_scn_portal:
 *	Remove a portal from every SCN entry.
 *
 * uid	- the Portal object UID.
 * return - alrays successful (0).
 *
 * ****************************************************************************
 */
int
remove_scn_portal(
	uint32_t uid
)
{
	(void) queue_msg_set(scn_q, SCN_REMOVE_P, (void *)uid);

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_proc:
 *	The entry point of the SCN thread. It listens on the SCN message
 *	queue and process every SCN related stuff.
 *
 * arg	- nothing.
 * return - NULL.
 *
 * ****************************************************************************
 */
void *
scn_proc(
	/* LINTED E_FUNC_ARG_UNUSED */
	void *arg
)
{
	int state = 0;

	scn_raw_t *raw;
	msg_text_t *msg;

	for (;;) {
		msg = queue_msg_get(scn_q);
		switch (msg->id) {
		case SCN_ADD:
			(void) scn_list_add((scn_registry_t *)msg->data);
			break;
		case SCN_REMOVE:
			(void) scn_list_remove((uint32_t)msg->data);
			break;
		case SCN_REMOVE_P:
			(void) scn_remove_portal((uint32_t)msg->data);
			break;
		case SCN_SET:
			raw = (scn_raw_t *)msg->data;
			state = scn_transition(state, raw);
			/* free the raw data */
			free_raw(raw);
			break;
		case SCN_TRIGGER:
			if (scn_dispatched != 0) {
				(void) scn_trigger();
			}
			/* FALLTHROUGH */
		case SCN_IGNORE:
			/* clean the scn(s) */
			free_scn();
			/* reset the state */
			state = 0;
			/* reset the scn_dispatched flag */
			scn_dispatched = 0;
			break;
		case SCN_STOP:
			queue_msg_free(msg);
			return (NULL);
		default:
			break;
		}
		queue_msg_free(msg);
	}
}
