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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "isns_server.h"
#include "isns_msgq.h"
#include "isns_func.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_dd.h"
#include "isns_pdu.h"
#include "isns_qry.h"
#include "isns_scn.h"
#include "isns_utils.h"
#include "isns_cfg.h"
#include "isns_esi.h"
#include "isns_provider.h"
#include "isns_log.h"

/*
 * extern global variables
 */
#ifdef DEBUG
extern int verbose_mc;
extern int verbose_tc;
#endif
extern const int NUM_OF_ATTRS[MAX_OBJ_TYPE_FOR_SIZE];
extern const int NUM_OF_CHILD[MAX_OBJ_TYPE];
extern const int TYPE_OF_PARENT[MAX_OBJ_TYPE_FOR_SIZE];
extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];
extern const int TAG_RANGE[MAX_OBJ_TYPE][3];

/* scn message queue */
extern msg_queue_t *scn_q;

/*
 * extern functions.
 */

/*
 * local variables
 */

/*
 * local functions.
 */
static int dev_attr_reg(conn_arg_t *);
static int dev_attr_qry(conn_arg_t *);
static int dev_get_next(conn_arg_t *);
static int dev_dereg(conn_arg_t *);
static int scn_reg(conn_arg_t *);
static int scn_dereg(conn_arg_t *);
static int dd_reg(conn_arg_t *);
static int dd_dereg(conn_arg_t *);
static int dds_reg(conn_arg_t *);
static int dds_dereg(conn_arg_t *);
static int msg_error(conn_arg_t *);

/*
 * ****************************************************************************
 *
 * packet_get_source:
 *	get the source attributes of the packet.
 *
 * conn	- the argument of the connection.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
packet_get_source(conn_arg_t *conn)
{
	int ec = 0;

	isns_pdu_t *pdu = conn->in_packet.pdu;
	isns_tlv_t *source = pdu_get_source(pdu);

	if (source == NULL) {
		ec = ISNS_RSP_SRC_ABSENT;
	} else if (source->attr_id != ISNS_ISCSI_NAME_ATTR_ID ||
	    source->attr_len == 0) {
		ec = ISNS_RSP_SRC_UNKNOWN;
	}

	if (ec == 0) {
		conn->in_packet.source = source;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * packet_get_key:
 *	get the key attributes of the packet.
 *
 * conn	- the argument of the connection.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
packet_get_key(conn_arg_t *conn)
{
	int ec = 0;

	isns_pdu_t *pdu = conn->in_packet.pdu;
	isns_tlv_t *key;
	size_t key_len;

	key = pdu_get_key(pdu, &key_len);

	conn->in_packet.key = key;
	conn->in_packet.key_len = key_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * packet_get_operand:
 *	get the operating attributes of the packet.
 *
 * conn	- the argument of the connection.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
packet_get_operand(conn_arg_t *conn)
{
	int ec = 0;

	isns_pdu_t *pdu = conn->in_packet.pdu;
	isns_tlv_t *op;
	size_t op_len;

	op = pdu_get_operand(pdu, &op_len);

	conn->in_packet.op = op;
	conn->in_packet.op_len = op_len;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * packet_split_verify:
 *	split and verify the packet, get the apporiate locking type and
 *	function handler for the packet.
 *
 * conn	- the argument of the connection.
 * return - error code.
 *
 * ****************************************************************************
 */
int
packet_split_verify(conn_arg_t *conn)
{
	int ec = 0;

	isns_pdu_t *pdu = conn->in_packet.pdu;

	int (*handler)(conn_arg_t *) = msg_error;
	int lock = CACHE_NO_ACTION;

	if (pdu->version != ISNSP_VERSION) {
		ec = ISNS_RSP_VER_NOT_SUPPORTED;
	} else {
		switch (pdu->func_id) {
		case ISNS_DEV_ATTR_REG:
			lock = CACHE_WRITE;
			handler = dev_attr_reg;
			break;
		case ISNS_DEV_ATTR_QRY:
			lock = CACHE_READ;
			handler = dev_attr_qry;
			break;
		case ISNS_DEV_GET_NEXT:
			lock = CACHE_READ;
			handler = dev_get_next;
			break;
		case ISNS_DEV_DEREG:
			lock = CACHE_WRITE;
			handler = dev_dereg;
			break;
		case ISNS_SCN_REG:
			if (scn_q != NULL) {
				lock = CACHE_WRITE;
				handler = scn_reg;
			} else {
				ec = ISNS_RSP_SCN_REGIS_REJECTED;
			}
			break;
		case ISNS_SCN_DEREG:
			if (scn_q != NULL) {
				lock = CACHE_WRITE;
				handler = scn_dereg;
			} else {
				ec = ISNS_RSP_SCN_REGIS_REJECTED;
			}
			break;
		case ISNS_SCN_EVENT:
			ec = ISNS_RSP_MSG_NOT_SUPPORTED;
			break;
		case ISNS_DD_REG:
			lock = CACHE_WRITE;
			handler = dd_reg;
			break;
		case ISNS_DD_DEREG:
			lock = CACHE_WRITE;
			handler = dd_dereg;
			break;
		case ISNS_DDS_REG:
			lock = CACHE_WRITE;
			handler = dds_reg;
			break;
		case ISNS_DDS_DEREG:
			lock = CACHE_WRITE;
			handler = dds_dereg;
			break;
		default:
			ec = ISNS_RSP_MSG_NOT_SUPPORTED;
			break;
		}
	}

	if (ISNS_OPERATION_TYPE_ENABLED()) {
		char buf[INET6_ADDRSTRLEN];
		struct sockaddr_storage *ssp = &conn->ss;
		struct sockaddr_in *sinp = (struct sockaddr_in *)ssp;
		if (ssp->ss_family == AF_INET) {
			(void) inet_ntop(AF_INET, (void *)&(sinp->sin_addr),
			    buf, sizeof (buf));
		} else {
			(void) inet_ntop(AF_INET6, (void *)&(sinp->sin_addr),
			    buf, sizeof (buf));
		}
		ISNS_OPERATION_TYPE((uintptr_t)buf, pdu->func_id);
	}

	conn->lock = lock;
	conn->handler = handler;

	/* packet split & verify */
	if (ec == 0) {
		ec = packet_get_source(conn);
		if (ec == 0) {
			ec = packet_get_key(conn);
			if (ec == 0) {
				ec = packet_get_operand(conn);
			}
		}
	}

	conn->ec = ec;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * setup_key_lcp:
 *	setup the lookup control data for looking up the object
 *	which the key attributes identify.
 *
 * lcp	- the pointer of the lookup control data.
 * key	- the key attributes.
 * key_len	- the length of the key attributes.
 * return	- the pointer of the lookup control data or
 *		  NULL if there is an error.
 *
 * ****************************************************************************
 */
static int
setup_key_lcp(lookup_ctrl_t *lcp, isns_tlv_t *key, uint16_t key_len)
{
	int ec = 0;

	uint8_t *value = &key->attr_value[0];

	lcp->curr_uid = 0;
	lcp->op[0] = 0;

	switch (key->attr_id) {
	case ISNS_EID_ATTR_ID:
		if (key->attr_len >= 4) {
			lcp->type = OBJ_ENTITY;
			lcp->id[0] = ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID);
			lcp->op[0] = OP_STRING;
			lcp->data[0].ptr = (uchar_t *)value;
			lcp->op[1] = 0;
		}
		break;
	case ISNS_ISCSI_NAME_ATTR_ID:
		if (key->attr_len >= 4) {
			lcp->type = OBJ_ISCSI;
			lcp->id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
			lcp->op[0] = OP_STRING;
			lcp->data[0].ptr = (uchar_t *)value;
			lcp->op[1] = 0;
		} else {
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
		}
		break;
	case ISNS_PORTAL_IP_ADDR_ATTR_ID:
		if (key->attr_len == sizeof (in6_addr_t)) {
			lcp->id[0] = ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_IP_ADDR_ATTR_ID);
			lcp->op[0] = OP_MEMORY_IP6;
			lcp->data[0].ip = (in6_addr_t *)value;
			NEXT_TLV(key, key_len);
			if (key_len <= 8 ||
			    key->attr_len != 4 ||
			    key->attr_id != ISNS_PORTAL_PORT_ATTR_ID) {
				return (ISNS_RSP_MSG_FORMAT_ERROR);
			}
			lcp->type = OBJ_PORTAL;
			value = &key->attr_value[0];
			lcp->id[1] = ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_PORT_ATTR_ID);
			lcp->op[1] = OP_INTEGER;
			lcp->data[1].ui = ntohl(*(uint32_t *)value);
			lcp->op[2] = 0;
		} else {
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
		}
		break;
	case ISNS_PG_ISCSI_NAME_ATTR_ID:
		if (key->attr_len < 4) {
			return (ISNS_RSP_MSG_FORMAT_ERROR);
		}
		lcp->id[0] = ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID);
		lcp->op[0] = OP_STRING;
		lcp->data[0].ptr = (uchar_t *)value;
		NEXT_TLV(key, key_len);
		if (key_len <= 8 ||
		    key->attr_len != sizeof (in6_addr_t) ||
		    key->attr_id != ISNS_PG_PORTAL_IP_ADDR_ATTR_ID) {
			return (ISNS_RSP_MSG_FORMAT_ERROR);
		}
		value = &key->attr_value[0];
		lcp->id[1] = ATTR_INDEX_PG(ISNS_PG_PORTAL_IP_ADDR_ATTR_ID);
		lcp->op[1] = OP_MEMORY_IP6;
		lcp->data[1].ip = (in6_addr_t *)value;
		NEXT_TLV(key, key_len);
		if (key_len <= 8 ||
		    key->attr_len != 4 ||
		    key->attr_id != ISNS_PG_PORTAL_PORT_ATTR_ID) {
			return (ISNS_RSP_MSG_FORMAT_ERROR);
		}
		value = &key->attr_value[0];
		lcp->id[2] = ATTR_INDEX_PG(ISNS_PG_PORTAL_PORT_ATTR_ID);
		lcp->op[2] = OP_INTEGER;
		lcp->data[2].ui = ntohl(*(uint32_t *)value);
		lcp->type = OBJ_PG;
		break;
	default:
		lcp->type = 0; /* invalid */
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * rsp_add_op:
 *	add the operating attributes to the response packet.
 *
 * conn	- the argument of the connection.
 * obj	- the object which is being added as operating attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
rsp_add_op(conn_arg_t *conn, isns_obj_t *obj)
{
	int ec = 0;

	isns_attr_t *attr;
	int i;

	isns_pdu_t *rsp = conn->out_packet.pdu;
	size_t pl = conn->out_packet.pl;
	size_t sz = conn->out_packet.sz;

	i = 0;
	while (i < NUM_OF_ATTRS[obj->type] &&
	    ec == 0) {
		attr = &obj->attrs[i];
		/* there is an attribute, send it back */
		if (attr->tag != 0) {
			ec = pdu_add_tlv(&rsp, &pl, &sz,
			    attr->tag, attr->len,
			    (void *)attr->value.ptr, 0);
		}
		i ++;
	}

	conn->out_packet.pdu = rsp;
	conn->out_packet.pl = pl;
	conn->out_packet.sz = sz;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * rsp_add_key:
 *	add the key attributes to the response packet.
 *
 * conn	- the argument of the connection.
 * entity - the object which is being added as key attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
rsp_add_key(conn_arg_t *conn, isns_obj_t *entity)
{
	int ec = 0;

	isns_tlv_t *key = conn->in_packet.key;
	size_t key_len = conn->in_packet.key_len;
	uint32_t tag = ISNS_EID_ATTR_ID;
	isns_attr_t *attr = &entity->attrs[ATTR_INDEX_ENTITY(tag)];
	uint32_t len = attr->len;

	isns_pdu_t *rsp = conn->out_packet.pdu;
	size_t pl = conn->out_packet.pl;
	size_t sz = conn->out_packet.sz;

	if (key_len == 0) {
		ec = pdu_add_tlv(&rsp, &pl, &sz,
		    tag, len, (void *)attr->value.ptr, 0);
	} else {
		while (key_len >= 8 &&
		    ec == 0) {
			if (key->attr_id == ISNS_EID_ATTR_ID) {
				ec = pdu_add_tlv(&rsp, &pl, &sz,
				    tag, len,
				    (void *)attr->value.ptr, 0);
			} else {
				ec = pdu_add_tlv(&rsp, &pl, &sz,
				    key->attr_id, key->attr_len,
				    (void *)key->attr_value, 1);
			}
			NEXT_TLV(key, key_len);
		}
	}

	if (ec == 0) {
		ec = pdu_add_tlv(&rsp, &pl, &sz,
		    ISNS_DELIMITER_ATTR_ID, 0, NULL, 0);
	}

	conn->out_packet.pdu = rsp;
	conn->out_packet.pl = pl;
	conn->out_packet.sz = sz;

	if (ec == 0) {
		ec = rsp_add_op(conn, entity);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * rsp_add_tlv:
 *	add one attribute with TLV format to the response packet.
 *
 * conn	- the argument of the connection.
 * tag	- the tag of the attribute.
 * len	- the length of the attribute.
 * value- the value of the attribute.
 * pflag- the flag of the value, 0: value; 1: pointer to value
 * return - error code.
 *
 * ****************************************************************************
 */
static int
rsp_add_tlv(conn_arg_t *conn, uint32_t tag, uint32_t len, void *value,
    int pflag)
{
	int ec = 0;

	isns_pdu_t *rsp = conn->out_packet.pdu;
	size_t pl = conn->out_packet.pl;
	size_t sz = conn->out_packet.sz;

	ec = pdu_add_tlv(&rsp, &pl, &sz, tag, len, value, pflag);

	conn->out_packet.pdu = rsp;
	conn->out_packet.pl = pl;
	conn->out_packet.sz = sz;

	return (ec);
}

/*
 * ****************************************************************************
 *
 * rsp_add_tlvs:
 *	add attributes with TLV format to the response packet.
 *
 * conn	- the argument of the connection.
 * tlv	- the attributes with TLV format being added.
 * tlv_len - the length of the attributes.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
rsp_add_tlvs(conn_arg_t *conn, isns_tlv_t *tlv, uint32_t tlv_len)
{
	int ec = 0;

	uint32_t tag;
	uint32_t len;
	void *value;

	while (tlv_len >= 8 &&
	    ec == 0) {
		tag = tlv->attr_id;
		len = tlv->attr_len;
		value = (void *)tlv->attr_value;

		ec = rsp_add_tlv(conn, tag, len, value, 1);

		NEXT_TLV(tlv, tlv_len);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * dev_attr_reg:
 *	function which handles the isnsp DEV_ATTR_REG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dev_attr_reg(conn_arg_t *conn)
{
	int ec = 0;

	isns_pdu_t *pdu = conn->in_packet.pdu;
	isns_tlv_t *source = conn->in_packet.source;
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	boolean_t replace =
	    ((pdu->flags & ISNS_FLAG_REPLACE_REG) == ISNS_FLAG_REPLACE_REG);

	lookup_ctrl_t lc, lc_key;
	uchar_t *iscsi_name;
	int ctrl;

	isns_obj_t *ety = NULL;	/* network entity object */
	isns_type_t ptype;	/* parent object type */
	uint32_t puid;		/* parent object UID */
	void const **child[MAX_CHILD_TYPE] = { NULL };   /* children */
	int ety_update, obj_update;
	isns_attr_t *eid_attr;

	isns_obj_t *obj;	/* child object */
	isns_type_t ctype;	/* child object type */
	uint32_t uid;		/* child object uid */
	isns_attr_t pgt[3] = { 0 };

	void const **vpp = NULL;
	int i = 0;

	isnslog(LOG_DEBUG, "dev_attr_reg", "entered (replace: %d)", replace);

	ec = pdu_reset_rsp(&conn->out_packet.pdu,
	    &conn->out_packet.pl,
	    &conn->out_packet.sz);
	if (ec != 0) {
		goto reg_done;
	}

	iscsi_name = (uchar_t *)&source->attr_value[0];
	ctrl = is_control_node(iscsi_name);
	lc_key.type = 0;
	if (key != NULL) {
		/* validate key attributes and make lcp for */
		/* the object identified by key attributes. */
		ec = setup_key_lcp(&lc, key, key_len);
		if (ec == 0 && lc.type != 0) {
			lc_key = lc;
			/* object is not found */
			if ((uid = is_obj_there(&lc)) == 0) {
				/* error if it is a network entity */
				if (lc.type != OBJ_ENTITY) {
					ec = ISNS_RSP_INVALID_REGIS;
				}
			/* validate for the source attribute before */
			/* update or replace the network entity object */
			} else if (ctrl == 0 &&
#ifndef SKIP_SRC_AUTH
			    reg_auth_src(lc.type, uid, iscsi_name) == 0) {
#else
			    0) {
#endif
				ec = ISNS_RSP_SRC_UNAUTHORIZED;
			/* de-register the network entity if replace is true */
			} else if (replace != 0) {
				UPDATE_LCP_UID(&lc, uid);
				ec = dereg_object(&lc, 0);
				/* generate a SCN */
				if (ec == 0) {
					(void) queue_msg_set(scn_q,
					    SCN_TRIGGER, NULL);
				}
			}
		}
	}
	if (ec != 0) {
		goto reg_done;
	}

	/* register the network entity object */
	ec = reg_get_entity(&ety, &op, &op_len);
	if (ec != 0) {
		goto reg_done;
	}
	if (ety == NULL && lc_key.type != OBJ_ENTITY) {
		ety = make_default_entity();
	} else if (ety == NULL ||
	    (lc_key.type == OBJ_ENTITY &&
	    key_cmp(&lc_key, ety) != 0)) {
		/* the eid in key attribute and */
		/* op attribute must be the same */
		ec = ISNS_RSP_INVALID_REGIS;
		goto reg_done;
	}
	if (ety == NULL || rsp_add_key(conn, ety) != 0) {
		ec = ISNS_RSP_INTERNAL_ERROR;
	} else {
		eid_attr = &ety->attrs[ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID)];
		ec = register_object(ety, &puid, &ety_update);
		ptype = OBJ_ENTITY;
	}
	if (ec == 0 && ety_update == 0) {
		/* newly registered, reset the pointer */
		ety = NULL;
	}

	/* register the reset of objects which are specified in */
	/* operating attributes */
	while (ec == 0 &&
	    (ec = reg_get_obj(&obj, &pgt[0], &op, &op_len)) == 0 &&
	    obj != NULL &&
	    (ec = rsp_add_op(conn, obj)) == 0) {
		ctype = obj->type;
		/* set the parent object UID */
		(void) set_parent_obj(obj, puid);
		/* register it */
		ec = register_object(obj, &uid, &obj_update);
		if (ec == 0) {
			if (obj_update == 0 ||
			    is_obj_online(obj) == 0) {
				/* update the ref'd object */
				(void) update_ref_obj(obj);
				/* add the newly registered object info */
				/* to child info array of the parent object */
				ec = buff_child_obj(ptype, ctype, obj, child);
			} else {
				if (ctrl == 0 &&
#ifndef SKIP_SRC_AUTH
				    puid != get_parent_uid(obj)) {
#else
				    0) {
#endif
					ec = ISNS_RSP_SRC_UNAUTHORIZED;
				}
				/* it was for updating an existing object */
				free_one_object(obj);
			}
		} else {
			/* failed registering it */
			free_one_object(obj);
		}
	}

	/* update the portal group object for the associations between */
	/* the newly registered objects and previously registered objects */
	if (ec == 0) {
		ec = verify_ref_obj(ptype, puid, child);
	}
	if (ec != 0) {
		goto reg_done;
	}

	/* update the children list of the parent object */
	while (i < MAX_CHILD_TYPE) {
		vpp = child[i];
		if (vpp != NULL) {
			break;
		}
		i ++;
	}
	if (vpp != NULL) {
		ec = update_child_obj(ptype, puid, child, 1);
	} else {
#ifndef SKIP_SRC_AUTH
		ec = ISNS_RSP_INVALID_REGIS;
#else
		/* for interop-ability, we cannot treat this as */
		/* an error, instead, remove the network entity */
		SET_UID_LCP(&lc, OBJ_ENTITY, puid);
		ec = dereg_object(&lc, 0);
		goto reg_done;
#endif
	}
	if (ec != 0) {
		goto reg_done;
	}
	/* add esi entry */
	if (ety_update != 0) {
		(void) esi_remove(puid);
	}
	ec = esi_add(puid, eid_attr->value.ptr, eid_attr->len);

reg_done:
	conn->ec = ec;
	free_one_object(ety);
	uid = 0;
	while (uid < MAX_CHILD_TYPE) {
		if (child[uid] != NULL) {
			free(child[uid]);
		}
		uid ++;
	}

	if (ec != 0) {
		isnslog(LOG_DEBUG, "dev_attr_reg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * dev_attr_qry:
 *	function which handles the isnsp DEV_ATTR_QRY message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dev_attr_qry(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	isns_tlv_t *source = conn->in_packet.source;
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	uchar_t *iscsi_name;

	bmp_t *nodes_bmp = NULL;
	uint32_t num_of_nodes;
	uint32_t *key_uids = NULL;
	uint32_t num_of_keys;
	isns_type_t key_type;

	uint32_t key_uid;
	uint32_t op_uid;

	uint32_t size_of_ops;
	uint32_t num_of_ops;
	uint32_t *op_uids = NULL;
	isns_type_t op_type;

	isns_tlv_t *tlv;
	uint16_t tlv_len;

	isnslog(LOG_DEBUG, "dev_attr_qry", "entered");

	ec = pdu_reset_rsp(&conn->out_packet.pdu,
	    &conn->out_packet.pl,
	    &conn->out_packet.sz);
	if (ec != 0) {
		goto qry_done;
	}

	/*
	 * RFC 4171 section 5.7.5.2:
	 * If no Operating Attributes are included in the original query, then
	 * all Operating Attributes SHALL be returned in the response. ???
	 */
	if (op_len == 0) {
		goto qry_done;
	}

	iscsi_name = (uchar_t *)&source->attr_value[0];
	if (is_control_node(iscsi_name) == 0) {
		ec = get_scope(iscsi_name, &nodes_bmp, &num_of_nodes);
		if (ec != 0 || nodes_bmp == NULL) {
			goto qry_done;
		}
	}

	size_of_ops = 0;
	if (key != NULL) {
		/*
		 * Return the original message key.
		 */
		ec = rsp_add_tlvs(conn, key, key_len);
		if (ec != 0) {
			goto qry_done;
		}

		/*
		 * Delimiter
		 */
		ec = rsp_add_tlv(conn, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0);
		if (ec != 0) {
			goto qry_done;
		}

		/*
		 * Query objects which match the Key Attributes.
		 */
		ec = get_qry_keys(nodes_bmp, num_of_nodes, &key_type,
		    key, key_len, &key_uids, &num_of_keys);
		if (ec != 0 || key_uids == NULL) {
			goto qry_done;
		}

		/*
		 * Iterate thru each object identified by the message key.
		 */
		tlv = op;
		tlv_len = op_len;
		FOR_EACH_OBJS(key_uids, num_of_keys, key_uid, {
			/*
			 * Iterate thru each Operating Attributes.
			 */
			op = tlv;
			op_len = tlv_len;
			FOR_EACH_OP(op, op_len, op_type, {
				if (op_type == 0) {
					ec = ISNS_RSP_INVALID_QRY;
					goto qry_done;
				}
				ec = get_qry_ops(key_uid, key_type,
				    op_type, &op_uids,
				    &num_of_ops, &size_of_ops);
				if (ec != 0) {
					goto qry_done;
				}
				/*
				 * Iterate thru each object for the Operating
				 * Attributes again.
				 */
				FOR_EACH_OBJS(op_uids, num_of_ops, op_uid, {
					ec = get_qry_attrs(op_uid, op_type,
					    op, op_len, conn);
					if (ec != 0) {
						goto qry_done;
					}
				});
			});
		});
	} else {
		/*
		 * Iterate thru each Operating Attributes.
		 */
		FOR_EACH_OP(op, op_len, op_type, {
			ec = get_qry_ops2(nodes_bmp, num_of_nodes,
			    op_type, &op_uids,
			    &num_of_ops, &size_of_ops);
			if (ec != 0) {
				goto qry_done;
			}
			/*
			 * Iterate thru each object for the Operating
			 * Attributes again.
			 */
			FOR_EACH_OBJS(op_uids, num_of_ops, op_uid, {
				ec = get_qry_attrs(op_uid, op_type,
				    op, op_len, conn);
				if (ec != 0) {
					goto qry_done;
				}
			});
		});
	}

qry_done:
	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "dev_attr_qry", "error code: %d", ec);
	}

	free(nodes_bmp);
	free(key_uids);
	free(op_uids);

	return (0);
}

/*
 * ****************************************************************************
 *
 * dev_get_next:
 *	function which handles the isnsp DEV_GET_NEXT message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dev_get_next(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	isns_tlv_t *source = conn->in_packet.source;
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	uchar_t *iscsi_name;

	bmp_t *nodes_bmp = NULL;
	uint32_t num_of_nodes;

	isns_type_t key_type;
	isns_type_t op_type;
	uint32_t size_of_obj;
	uint32_t num_of_obj;
	uint32_t *obj_uids = NULL;

	uint32_t uid;

	isnslog(LOG_DEBUG, "dev_get_next", "entered");

	ec = pdu_reset_rsp(&conn->out_packet.pdu,
	    &conn->out_packet.pl,
	    &conn->out_packet.sz);
	if (ec != 0) {
		goto get_next_done;
	}

	iscsi_name = (uchar_t *)&source->attr_value[0];
	if (is_control_node(iscsi_name) == 0) {
		ec = get_scope(iscsi_name, &nodes_bmp, &num_of_nodes);
		if (nodes_bmp == NULL) {
			ec = ISNS_RSP_NO_SUCH_ENTRY;
		}
		if (ec != 0) {
			goto get_next_done;
		}
	}

	/*
	 * Get Message Key type and validate the Message Key.
	 */
	key_type = TLV2TYPE(key);
	if (key_type == 0) {
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
		goto get_next_done;
	}
	ec = validate_qry_key(key_type, key, key_len, NULL);
	if (ec != 0) {
		goto get_next_done;
	}

	size_of_obj = 0;
	if (op != NULL) {
		/*
		 * Query the objects which match the Operating Attributes.
		 */
		ec = get_qry_keys(nodes_bmp, num_of_nodes, &op_type,
		    op, op_len, &obj_uids, &num_of_obj);
		if (op_type != key_type) {
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
		}
	} else {
		/*
		 * Query the objects which match the Message Key type.
		 */
		ec = get_qry_ops2(nodes_bmp, num_of_nodes,
		    key_type, &obj_uids, &num_of_obj, &size_of_obj);
	}
	if (ec != 0) {
		goto get_next_done;
	}

	/*
	 * Get the object which is next to the one indicated by the
	 * Message Key.
	 */
	uid = get_next_obj(key, key_len, key_type, obj_uids, num_of_obj);
	if (uid == 0) {
		ec = ISNS_RSP_NO_SUCH_ENTRY;
		goto get_next_done;
	}

	/*
	 * Message Key
	 */
	if ((ec = get_qry_attrs1(uid, key_type, key, key_len, conn)) != 0) {
		goto get_next_done;
	}

	/*
	 * Delimiter
	 */
	if ((ec = rsp_add_tlv(conn, ISNS_DELIMITER_ATTR_ID, 0, NULL, 0)) != 0) {
		goto get_next_done;
	}

	/*
	 * Operating Attributes
	 */
	if (op != NULL) {
		ec = get_qry_attrs(uid, op_type, op, op_len, conn);
	}

get_next_done:
	conn->ec = ec;

	if (ec != 0 && ec != ISNS_RSP_NO_SUCH_ENTRY) {
		isnslog(LOG_DEBUG, "dev_get_next", "error code: %d", ec);
	}

	free(nodes_bmp);
	free(obj_uids);

	return (0);
}

/*
 * ****************************************************************************
 *
 * dev_dereg:
 *	function which handles the isnsp DEV_DEREG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dev_dereg(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	isns_tlv_t *source = conn->in_packet.source;
	/* isns_tlv_t *key = conn->in_packet.key; */
	/* uint16_t key_len = conn->in_packet.key_len; */
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	uchar_t *iscsi_name;
	int ctrl;
	uint32_t puid;

	lookup_ctrl_t lc;
	uint8_t *value;

	isnslog(LOG_DEBUG, "dev_dereg", "entered");

	iscsi_name = (uchar_t *)&source->attr_value[0];
	ctrl = is_control_node(iscsi_name);
	if (ctrl == 0) {
		puid = is_parent_there(iscsi_name);
	}

	while (op_len > 8 && ec == 0) {
		lc.curr_uid = 0;
		value = &op->attr_value[0];
		switch (op->attr_id) {
		case ISNS_EID_ATTR_ID:
			lc.id[0] = ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID);
			lc.op[0] = OP_STRING;
			lc.data[0].ptr = (uchar_t *)value;
			lc.op[1] = 0;
			lc.type = OBJ_ENTITY;
			break;
		case ISNS_ISCSI_NAME_ATTR_ID:
			lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
			lc.op[0] = OP_STRING;
			lc.data[0].ptr = (uchar_t *)value;
			lc.op[1] = 0;
			lc.type = OBJ_ISCSI;
			break;
		case ISNS_ISCSI_NODE_INDEX_ATTR_ID:
			lc.id[0] = ATTR_INDEX_ISCSI(
			    ISNS_ISCSI_NODE_INDEX_ATTR_ID);
			lc.op[0] = OP_INTEGER;
			lc.data[0].ui = ntohl(*(uint32_t *)value);
			lc.op[1] = 0;
			lc.type = OBJ_ISCSI;
			break;
		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
			lc.id[0] = ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_IP_ADDR_ATTR_ID);
			lc.op[0] = OP_MEMORY_IP6;
			lc.data[0].ip = (in6_addr_t *)value;
			NEXT_TLV(op, op_len);
			if (op_len > 8 &&
			    op->attr_id == ISNS_PORTAL_PORT_ATTR_ID) {
				value = &op->attr_value[0];
				lc.id[1] = ATTR_INDEX_PORTAL(
				    ISNS_PORTAL_PORT_ATTR_ID);
				lc.op[1] = OP_INTEGER;
				lc.data[1].ui = ntohl(*(uint32_t *)value);
				lc.op[2] = 0;
				lc.type = OBJ_PORTAL;
			} else {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}
			break;
		case ISNS_PORTAL_INDEX_ATTR_ID:
			lc.id[0] = ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_INDEX_ATTR_ID);
			lc.op[0] = OP_INTEGER;
			lc.data[0].ui = ntohl(*(uint32_t *)value);
			lc.op[1] = 0;
			lc.type = OBJ_PORTAL;
			break;
		default:
			ec = ISNS_RSP_MSG_FORMAT_ERROR;
			break;
		}
		if (ec == 0 &&
		    (ec = dereg_object(&lc, 0)) == 0) {
			if (ctrl == 0 &&
#ifndef SKIP_SRC_AUTH
			    lc.curr_uid != 0 &&
			    puid != lc.curr_uid) {
#else
			    0) {
#endif
				ec = ISNS_RSP_SRC_UNAUTHORIZED;
			} else {
				NEXT_TLV(op, op_len);
			}
		}
	}

	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "dev_dereg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_reg:
 *	function which handles the isnsp SCN_REG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
scn_reg(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	/* isns_tlv_t *source = conn->in_packet.source; */
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	/* uchar_t *src; */
	uchar_t *node_name;
	uint32_t nlen;
	uint32_t scn;

	isnslog(LOG_DEBUG, "scn_reg", "entered");

	/* src = (uchar_t *)&source->attr_value[0]; */

	if (op == NULL ||
	    op->attr_id != ISNS_ISCSI_SCN_BITMAP_ATTR_ID ||
	    op_len != 12 ||
	    key == NULL ||
	    key->attr_id != ISNS_ISCSI_NAME_ATTR_ID ||
	    key_len != 8 + key->attr_len) {
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
		goto scn_reg_done;
	}

	node_name = (uchar_t *)&key->attr_value[0];
	nlen = key->attr_len;
	scn = ntohl(*(uint32_t *)&op->attr_value[0]);

	ec = add_scn_entry(node_name, nlen, scn);

scn_reg_done:
	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "scn_reg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * scn_dereg:
 *	function which handles the isnsp SCN_DEREG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
scn_dereg(conn_arg_t *conn)
{
	int ec = 0;

	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;

	uchar_t *node_name;

	isnslog(LOG_DEBUG, "scn_dereg", "entered");

	if (key != NULL &&
	    key->attr_len != 0 &&
	    key_len == 8 + key->attr_len &&
	    key->attr_id == ISNS_ISCSI_NAME_ATTR_ID) {
		node_name = (uchar_t *)&key->attr_value[0];
		ec = remove_scn_entry(node_name);
	} else {
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
	}

	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "scn_dereg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * setup_ddid_lcp:
 *	setup the lookup control data for looking up the DD object
 *	by using the dd_id attribute.
 *
 * lcp	- pointer to the lookup control data.
 * dd_id- the unique ID of the DD object.
 * return - the pointer to the lcp.
 *
 * ****************************************************************************
 */
#ifndef DEBUG
static
#endif
lookup_ctrl_t *
setup_ddid_lcp(lookup_ctrl_t *lcp, uint32_t dd_id)
{
	lcp->curr_uid = 0;
	lcp->type = OBJ_DD;
	lcp->id[0] = ATTR_INDEX_DD(ISNS_DD_ID_ATTR_ID);
	lcp->op[0] = OP_INTEGER;
	lcp->data[0].ui = dd_id;
	lcp->op[1] = 0;

	return (lcp);
}

/*
 * ****************************************************************************
 *
 * setup_ddsid_lcp:
 *	setup the lookup control data for looking up the DD-set object
 *	by using the dds_id attribute.
 *
 * lcp	- pointer to the lookup control data.
 * dds_id - the unique ID of the DD-set object.
 * return - the pointer to the lcp.
 *
 * ****************************************************************************
 */
#ifndef DEBUG
static
#endif
lookup_ctrl_t *
setup_ddsid_lcp(lookup_ctrl_t *lcp, uint32_t dds_id)
{
	lcp->curr_uid = 0;
	lcp->type = OBJ_DDS;
	lcp->id[0] = ATTR_INDEX_DDS(ISNS_DD_SET_ID_ATTR_ID);
	lcp->op[0] = OP_INTEGER;
	lcp->data[0].ui = dds_id;
	lcp->op[1] = 0;

	return (lcp);
}

/*
 * ****************************************************************************
 *
 * dd_reg:
 *	function which handles the isnsp DD_REG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dd_reg(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	isns_tlv_t *source = conn->in_packet.source;
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	uint32_t dd_id = 0;
	uint8_t *value;

	isns_obj_t *dd = NULL;

	uchar_t *iscsi_name;

	lookup_ctrl_t lc;
	isns_assoc_iscsi_t aiscsi;
	isns_obj_t *assoc;
	isns_attr_t *attr;

	uint32_t features;

	isnslog(LOG_DEBUG, "dd_reg", "entered");

	iscsi_name = (uchar_t *)&source->attr_value[0];
	if (is_control_node(iscsi_name) == 0) {
		ec = ISNS_RSP_SRC_UNAUTHORIZED;
		goto dd_reg_done;
	}

	ec = pdu_reset_rsp(&conn->out_packet.pdu,
	    &conn->out_packet.pl,
	    &conn->out_packet.sz);
	if (ec != 0) {
		goto dd_reg_done;
	}

	if (op == NULL ||
	    (key != NULL &&
	    (key_len != 12 ||
	    key->attr_id != ISNS_DD_ID_ATTR_ID ||
	    key->attr_len != 4 ||
	    (dd_id = ntohl(*(uint32_t *)&key->attr_value[0])) == 0 ||
	    is_obj_there(setup_ddid_lcp(&lc, dd_id)) == 0))) {
		ec = ISNS_RSP_INVALID_REGIS;
		goto dd_reg_done;
	}

	/* message key */
	if (key != NULL &&
	    (ec = rsp_add_tlv(conn, ISNS_DD_ID_ATTR_ID, 4,
	    (void *)dd_id, 0)) != 0) {
		goto dd_reg_done;
	}

	/* delimiter */
	if ((ec = rsp_add_tlv(conn, ISNS_DELIMITER_ATTR_ID, 0,
	    NULL, 0)) != 0) {
		goto dd_reg_done;
	}

	/* A DDReg message with no Message Key SHALL result in the */
	/* attempted creation of a new Discovery Domain (DD). */
	if (dd_id == 0) {
		ec = create_dd_object(op, op_len, &dd);
		if (ec == 0) {
			ec = register_object(dd, &dd_id, NULL);
			if (ec == ERR_NAME_IN_USE) {
				ec = ISNS_RSP_INVALID_REGIS;
			}
			if (ec != 0) {
				free_object(dd);
				goto dd_reg_done;
			}
		} else {
			goto dd_reg_done;
		}
	}

	/* add the newly created dd to the response */
	if (dd != NULL) {
		ec = rsp_add_op(conn, dd);
	}

	aiscsi.type = OBJ_ASSOC_ISCSI;
	aiscsi.puid = dd_id;

	while (op_len > 8 && ec == 0) {
		value = &op->attr_value[0];
		switch (op->attr_id) {
		case ISNS_DD_ID_ATTR_ID:
			/* if the DD_ID is included in both the Message Key */
			/* and Operating Attributes, then the DD_ID value */
			/* in the Message Key MUST be the same as the DD_ID */
			/* value in the Operating Attributes. */
			if (dd == NULL) {
				if (op->attr_len != 4 ||
				    dd_id != ntohl(*(uint32_t *)value)) {
					ec = ISNS_RSP_INVALID_REGIS;
				} else {
					ec = rsp_add_tlv(conn,
					    ISNS_DD_ID_ATTR_ID, 4,
					    (void *)dd_id, 0);
				}
			}
			break;
		case ISNS_DD_NAME_ATTR_ID:
			/* It is going to modify the DD Symbolic Name. */
			if (dd == NULL) {
				if (op->attr_len > 0 && op->attr_len <= 256) {
					ec = update_dd_name(
					    dd_id,
					    op->attr_len,
					    (uchar_t *)value);
					if (ec == ERR_NAME_IN_USE) {
						ec = ISNS_RSP_INVALID_REGIS;
					}
				} else {
					ec = ISNS_RSP_INVALID_REGIS;
				}
				if (ec == 0) {
					ec = rsp_add_tlv(conn,
					    ISNS_DD_NAME_ATTR_ID,
					    op->attr_len, (void *)value, 1);
				}
			}
			break;
		case ISNS_DD_ISCSI_INDEX_ATTR_ID:
			if (op->attr_len == 4) {
				/* zero the association object */
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_INDEX_ATTR_ID)];
				attr->tag = ISNS_DD_ISCSI_INDEX_ATTR_ID;
				attr->len = 4;
				attr->value.ui = ntohl(*(uint32_t *)value);
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_NAME_ATTR_ID)];
				attr->tag = 0; /* clear it */
				attr->value.ptr = NULL; /* clear it */
				assoc = (isns_obj_t *)&aiscsi;
				if ((ec = add_dd_member(assoc)) ==
				    ERR_ALREADY_ASSOCIATED) {
					ec = 0;
				}
				if (attr->value.ptr != NULL) {
					free(attr->value.ptr);
				}
			} else {
				ec = ISNS_RSP_INVALID_REGIS;
			}
			if (ec == 0) {
				ec = rsp_add_tlv(conn,
				    ISNS_DD_ISCSI_INDEX_ATTR_ID,
				    4, (void *)attr->value.ui, 0);
			}
			break;
		case ISNS_DD_ISCSI_NAME_ATTR_ID:
			if (op->attr_len > 0 && op->attr_len <= 224) {
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_NAME_ATTR_ID)];
				attr->tag = ISNS_DD_ISCSI_NAME_ATTR_ID;
				attr->len = op->attr_len;
				attr->value.ptr = (uchar_t *)value;
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_INDEX_ATTR_ID)];
				attr->tag = 0; /* clear it */
				assoc = (isns_obj_t *)&aiscsi;
				if ((ec = add_dd_member(assoc)) ==
				    ERR_ALREADY_ASSOCIATED) {
					ec = 0;
				}
			} else {
				ec = ISNS_RSP_INVALID_REGIS;
			}
			if (ec == 0) {
				ec = rsp_add_tlv(conn,
				    ISNS_DD_ISCSI_NAME_ATTR_ID,
				    op->attr_len, (void *)value, 1);
			}
			break;
		case ISNS_DD_FC_PORT_NAME_ATTR_ID:
		case ISNS_DD_PORTAL_INDEX_ATTR_ID:
		case ISNS_DD_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_DD_PORTAL_PORT_ATTR_ID:
			ec = ISNS_RSP_REGIS_NOT_SUPPORTED;
			break;
		case ISNS_DD_FEATURES_ATTR_ID:
			/* It is going to modify the DD Symbolic Name. */
			if (dd == NULL) {
				if (op->attr_len == 4) {
					features = ntohl(*(uint32_t *)value);
					ec = update_dd_features(
					    dd_id, features);
				} else {
					ec = ISNS_RSP_INVALID_REGIS;
				}
				if (ec == 0) {
					ec = rsp_add_tlv(conn,
					    ISNS_DD_FEATURES_ATTR_ID,
					    4, (void *)features, 0);
				}
			}
			break;
		default:
			ec = ISNS_RSP_INVALID_REGIS;
			break;
		}

		NEXT_TLV(op, op_len);
	}

dd_reg_done:
	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "dd_reg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * dds_reg:
 *	function which handles the isnsp DDS_REG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dds_reg(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	isns_tlv_t *source = conn->in_packet.source;
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	uint32_t dds_id = 0;
	uint8_t *value;

	isns_obj_t *dds = NULL;

	uchar_t *iscsi_name;

	lookup_ctrl_t lc;
	isns_assoc_dd_t add;
	isns_obj_t *assoc;
	isns_attr_t *attr;

	uint32_t code;

	isnslog(LOG_DEBUG, "dds_reg", "entered");

	iscsi_name = (uchar_t *)&source->attr_value[0];
	if (is_control_node(iscsi_name) == 0) {
		ec = ISNS_RSP_SRC_UNAUTHORIZED;
		goto dds_reg_done;
	}

	ec = pdu_reset_rsp(&conn->out_packet.pdu,
	    &conn->out_packet.pl,
	    &conn->out_packet.sz);
	if (ec != 0) {
		goto dds_reg_done;
	}

	if (op == NULL ||
	    (key != NULL &&
	    (key_len != 12 ||
	    key->attr_id != ISNS_DD_SET_ID_ATTR_ID ||
	    key->attr_len != 4 ||
	    (dds_id = ntohl(*(uint32_t *)&key->attr_value[0])) == 0 ||
	    is_obj_there(setup_ddsid_lcp(&lc, dds_id)) == 0))) {
		ec = ISNS_RSP_INVALID_REGIS;
		goto dds_reg_done;
	}

	/* message key */
	if (key != NULL &&
	    (ec = rsp_add_tlv(conn, ISNS_DD_SET_ID_ATTR_ID, 4,
	    (void *)dds_id, 0)) != 0) {
		goto dds_reg_done;
	}

	/* delimiter */
	if ((ec = rsp_add_tlv(conn, ISNS_DELIMITER_ATTR_ID, 0,
	    NULL, 0)) != 0) {
		goto dds_reg_done;
	}

	/* A DDSReg message with no Message Key SHALL result in the */
	/* attempted creation of a new Discovery Domain (DD). */
	if (dds_id == 0) {
		ec = create_dds_object(op, op_len, &dds);
		if (ec == 0) {
			ec = register_object(dds, &dds_id, NULL);
			if (ec == ERR_NAME_IN_USE) {
				ec = ISNS_RSP_INVALID_REGIS;
			}
			if (ec != 0) {
				free_object(dds);
				goto dds_reg_done;
			}
		} else {
			goto dds_reg_done;
		}
	}

	/* add the newly created dd to the response */
	if (dds != NULL) {
		ec = rsp_add_op(conn, dds);
	}

	add.type = OBJ_ASSOC_DD;
	add.puid = dds_id;

	while (op_len > 8 && ec == 0) {
		value = &op->attr_value[0];
		switch (op->attr_id) {
		case ISNS_DD_SET_ID_ATTR_ID:
			/* if the DDS_ID is included in both the Message Key */
			/* and Operating Attributes, then the DDS_ID value */
			/* in the Message Key MUST be the same as the DDS_ID */
			/* value in the Operating Attributes. */
			if (dds == NULL) {
				if (op->attr_len != 4 ||
				    dds_id != ntohl(*(uint32_t *)value)) {
					ec = ISNS_RSP_INVALID_REGIS;
				} else {
					ec = rsp_add_tlv(conn,
					    ISNS_DD_SET_ID_ATTR_ID,
					    4, (void *)dds_id, 0);
				}
			}
			break;
		case ISNS_DD_SET_NAME_ATTR_ID:
			/* It is going to modify the DD Symbolic Name. */
			if (dds == NULL) {
				if (op->attr_len > 0 && op->attr_len <= 256) {
					ec = update_dds_name(
					    dds_id,
					    op->attr_len,
					    (uchar_t *)value);
					if (ec == ERR_NAME_IN_USE) {
						ec = ISNS_RSP_INVALID_REGIS;
					}
				} else {
					ec = ISNS_RSP_INVALID_REGIS;
				}
				if (ec == 0) {
					ec = rsp_add_tlv(conn,
					    ISNS_DD_SET_NAME_ATTR_ID,
					    op->attr_len, (void *)value, 1);
				}
			}
			break;
		case ISNS_DD_SET_STATUS_ATTR_ID:
			/* It is going to modify the DD Symbolic Name. */
			if (dds == NULL) {
				if (op->attr_len == 4) {
					code = ntohl(*(uint32_t *)value);
					ec = update_dds_status(
					    dds_id, code);
				} else {
					ec = ISNS_RSP_INVALID_REGIS;
				}
				if (ec == 0) {
					ec = rsp_add_tlv(conn,
					    ISNS_DD_SET_STATUS_ATTR_ID,
					    4, (void *)code, 0);
				}
			}
			break;
		case ISNS_DD_ID_ATTR_ID:
			if (op->attr_len == 4) {
				/* zero the association object */
				attr = &add.attrs[ATTR_INDEX_ASSOC_DD(
				    ISNS_DD_ID_ATTR_ID)];
				attr->tag = ISNS_DD_ID_ATTR_ID;
				attr->len = 4;
				attr->value.ui = ntohl(*(uint32_t *)value);
				assoc = (isns_obj_t *)&add;
				if ((ec = add_dds_member(assoc)) ==
				    ERR_ALREADY_ASSOCIATED) {
					ec = 0;
				}
			} else {
				ec = ISNS_RSP_INVALID_REGIS;
			}
			if (ec == 0) {
				ec = rsp_add_tlv(conn,
				    ISNS_DD_ID_ATTR_ID, 4,
				    (void *)attr->value.ui, 0);
			}
			break;
		default:
			ec = ISNS_RSP_INVALID_REGIS;
			break;
		}

		NEXT_TLV(op, op_len);
	}

dds_reg_done:
	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "dds_reg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * dd_dereg:
 *	function which handles the isnsp DD_DEREG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dd_dereg(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	isns_tlv_t *source = conn->in_packet.source;
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	uint32_t dd_id;
	uint8_t *value;

	uchar_t *iscsi_name;

	isns_assoc_iscsi_t aiscsi;
	isns_obj_t *assoc;
	isns_attr_t *attr;

	isnslog(LOG_DEBUG, "dd_dereg", "entered");

	iscsi_name = (uchar_t *)&source->attr_value[0];
	if (is_control_node(iscsi_name) == 0) {
		ec = ISNS_RSP_SRC_UNAUTHORIZED;
		goto dd_dereg_done;
	}

	if (key == NULL ||
	    key_len != 12 ||
	    key->attr_id != ISNS_DD_ID_ATTR_ID ||
	    (dd_id = ntohl(*(uint32_t *)&key->attr_value[0])) == 0) {
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
		goto dd_dereg_done;
	}

	if (op == NULL) {
		ec = remove_dd_object(dd_id);
	} else {
		aiscsi.type = OBJ_ASSOC_ISCSI;
		aiscsi.puid = dd_id;

		while (op_len > 8 && ec == 0) {
			value = &op->attr_value[0];
			switch (op->attr_id) {
			case ISNS_DD_ISCSI_INDEX_ATTR_ID:
				/* zero the association object */
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_INDEX_ATTR_ID)];
				attr->tag = ISNS_DD_ISCSI_INDEX_ATTR_ID;
				attr->len = 4;
				attr->value.ui = ntohl(*(uint32_t *)value);
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_NAME_ATTR_ID)];
				attr->tag = 0; /* clear it */
				attr->value.ptr = NULL; /* clear it */
				assoc = (isns_obj_t *)&aiscsi;
				if ((ec = remove_dd_member(assoc)) ==
				    ERR_NO_SUCH_ASSOCIATION) {
					ec = 0;
				}
				if (attr->value.ptr != NULL) {
					free(attr->value.ptr);
				}
				break;
			case ISNS_DD_ISCSI_NAME_ATTR_ID:
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_NAME_ATTR_ID)];
				attr->tag = ISNS_DD_ISCSI_NAME_ATTR_ID;
				attr->len = op->attr_len;
				attr->value.ptr = (uchar_t *)value;
				attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
				    ISNS_DD_ISCSI_INDEX_ATTR_ID)];
				attr->tag = 0; /* clear it */
				assoc = (isns_obj_t *)&aiscsi;
				if ((ec = remove_dd_member(assoc)) ==
				    ERR_NO_SUCH_ASSOCIATION) {
					ec = 0;
				}
				break;
			case ISNS_DD_FC_PORT_NAME_ATTR_ID:
			case ISNS_DD_PORTAL_INDEX_ATTR_ID:
			case ISNS_DD_PORTAL_IP_ADDR_ATTR_ID:
			case ISNS_DD_PORTAL_PORT_ATTR_ID:
				ec = ISNS_RSP_REGIS_NOT_SUPPORTED;
				break;
			default:
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
				break;
			}

			NEXT_TLV(op, op_len);
		}
	}

dd_dereg_done:
	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "dd_dereg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * dds_dereg:
 *	function which handles the isnsp DDS_DEREG message.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
dds_dereg(conn_arg_t *conn)
{
	int ec = 0;

	/* isns_pdu_t *pdu = conn->in_packet.pdu; */
	isns_tlv_t *source = conn->in_packet.source;
	isns_tlv_t *key = conn->in_packet.key;
	uint16_t key_len = conn->in_packet.key_len;
	isns_tlv_t *op = conn->in_packet.op;
	uint16_t op_len = conn->in_packet.op_len;

	uint32_t dds_id;
	uint32_t uid;
	uint8_t *value;

	uchar_t *iscsi_name;

	isnslog(LOG_DEBUG, "dds_dereg", "entered");

	iscsi_name = (uchar_t *)&source->attr_value[0];
	if (is_control_node(iscsi_name) == 0) {
		ec = ISNS_RSP_SRC_UNAUTHORIZED;
		goto dds_dereg_done;
	}

	if (key == NULL ||
	    key_len != 12 ||
	    key->attr_id != ISNS_DD_SET_ID_ATTR_ID ||
	    (dds_id = ntohl(*(uint32_t *)&key->attr_value[0])) == 0) {
		ec = ISNS_RSP_MSG_FORMAT_ERROR;
		goto dds_dereg_done;
	}

	if (op == NULL) {
		ec = remove_dds_object(dds_id);
	} else {
		while (op_len > 8 && ec == 0) {
			value = &op->attr_value[0];
			if (op->attr_id == ISNS_DD_ID_ATTR_ID) {
				uid = ntohl(*(uint32_t *)value);
				if ((ec = remove_dds_member(dds_id, uid)) ==
				    ERR_NO_SUCH_ASSOCIATION) {
					ec = 0;
				}
			} else {
				ec = ISNS_RSP_MSG_FORMAT_ERROR;
			}

			NEXT_TLV(op, op_len);
		}
	}

dds_dereg_done:
	conn->ec = ec;

	if (ec != 0) {
		isnslog(LOG_DEBUG, "dds_dereg", "error code: %d", ec);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * msg_error:
 *	function which handles any unknown isnsp messages or the
 *	messages which are not supported.
 *
 * conn	- the argument of the connection.
 * return - 0: the message requires response.
 *
 * ****************************************************************************
 */
static int
msg_error(conn_arg_t *conn __unused)
{
	return (0);
}

/*
 * ****************************************************************************
 *
 * isns_response_ec:
 *	send the response message to the client with error code.
 *
 * so	- the socket descriptor.
 * pdu	- the received pdu.
 * ec	- the error code which is being responsed.
 * return - status of the sending operation.
 *
 * ****************************************************************************
 */
static int
isns_response_ec(int so, isns_pdu_t *pdu, int ec)
{
	int status;

	uint8_t buff[sizeof (isns_pdu_t) + 8];

	isns_pdu_t *rsp = (isns_pdu_t *)&buff;
	isns_resp_t *resp = (isns_resp_t *)rsp->payload;
	size_t pl = 4;

	rsp->version = htons((uint16_t)ISNSP_VERSION);
	rsp->func_id = htons(pdu->func_id | ISNS_RSP_MASK);
	rsp->xid = htons(pdu->xid);
	resp->status = htonl(ec);

	status = isns_send_pdu(so, rsp, pl);

	return (status);
}

/*
 * ****************************************************************************
 *
 * isns_response:
 *	send the response message to the client.
 *
 * conn	- the argument of the connection.
 * return - status of the sending operation.
 *
 * ****************************************************************************
 */
int
isns_response(conn_arg_t *conn)
{
	int status;

	int so = conn->so;
	int ec = conn->ec;
	isns_pdu_t *pdu = conn->in_packet.pdu;
	isns_pdu_t *rsp = conn->out_packet.pdu;
	size_t pl = conn->out_packet.pl;

	if (rsp != NULL) {
		rsp->version = htons((uint16_t)ISNSP_VERSION);
		rsp->func_id = htons(pdu->func_id | ISNS_RSP_MASK);
		rsp->xid = htons(pdu->xid);
		(void) pdu_update_code(rsp, &pl, ec);
		status = isns_send_pdu(so, rsp, pl);
	} else {
		status = isns_response_ec(so, pdu, ec);
	}

	return (status);
}
