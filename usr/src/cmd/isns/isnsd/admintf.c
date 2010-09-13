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
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>
#include <libxml/tree.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "isns_server.h"
#include "isns_cfg.h"
#include "isns_htab.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_dd.h"
#include "isns_utils.h"
#include "isns_mgmt.h"
#include "isns_protocol.h"
#include "admintf.h"

extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];

static isns_type_t
get_lc_type(
	object_type obj
)
{
	isns_type_t type;

	switch (obj) {
	case Node:
		type = OBJ_ISCSI;
		break;
	case DiscoveryDomain:
	case DiscoveryDomainMember:
		type = OBJ_DD;
		break;
	case DiscoveryDomainSet:
	case DiscoveryDomainSetMember:
		type = OBJ_DDS;
		break;
	default:
		ASSERT(0);
		break;
	}

	return (type);
}

static uint32_t
get_lc_id(
	object_type obj
)
{
	uint32_t id;

	switch (obj) {
	case Node:
		id = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
		break;
	case DiscoveryDomain:
	case DiscoveryDomainMember:
		id = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
		break;
	case DiscoveryDomainSet:
	case DiscoveryDomainSetMember:
		id = ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID);
		break;
	default:
		ASSERT(0);
		break;
	}

	return (id);
}

/*
 * ****************************************************************************
 *
 * cb_get_node_info: callback for get_node_op
 *	The routine process matching node and add a Node object elements
 *	to the response doc.
 *
 * p1	- matching node object
 * p2	- lookup control data that was used for node look up
 *	    returns parent index(newtork entity) in look up control.
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_get_node_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, sub_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_XML_ADDCHILD_FAILED);
	}

	n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_ADDCHILD_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)NODEOBJECT);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_ADDCHILD_FAILED);
	}

	/* get node name, alias, type and generate xml info */
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)NAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NODE_TYPE_ATTR_ID)];
	switch (attr->value.ui) {
	    case ISNS_CONTROL_NODE_TYPE | ISNS_INITIATOR_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)CONTROLNODEINITIATORTYPE);
		break;
	    case ISNS_CONTROL_NODE_TYPE | ISNS_TARGET_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)CONTROLNODETARGETTYPE);
		break;
	    case ISNS_TARGET_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)TARGETTYPE);
		break;
	    case ISNS_INITIATOR_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)INITIATORTYPE);
		break;
	    case ISNS_CONTROL_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)CONTROLNODETYPE);
		break;
	    default:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)UNKNOWNTYPE);
	}
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_ALIAS_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)ALIASATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	/*
	 * A node can have all or no SCN subsribtion.
	 * May avoid redundant code with scsusrciption table.
	 */
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_SCN_BITMAP_ATTR_ID)];
	if (IS_SCN_INIT_SELF_INFO_ONLY(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNINITSELFONLY);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}
	if (IS_SCN_TARGET_SELF_INFO_ONLY(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNTARGETSELFONLY);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}
	if (IS_SCN_MGMT_REG(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNTARGETSELFONLY);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}
	if (IS_SCN_OBJ_REMOVED(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNOBJECTREMOVED);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}
	if (IS_SCN_OBJ_ADDED(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNOBJECTADDED);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}
	if (IS_SCN_OBJ_UPDATED(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNOBJECTUPDATED);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}
	if (IS_SCN_MEMBER_REMOVED(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNMEMBERREMOVED);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}
	if (IS_SCN_MEMBER_ADDED(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)SCNSUBSCRIPTION,
		(xmlChar *)SCNMEMBERADDED);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}

	/* set the parent object id, i.e. the network entity object id */
	lcp->id[2] = get_parent_uid(obj);
	/* pass back the node object element to add entity, portal info to it */
	lcp->data[2].ptr =  (uchar_t *)n_node;

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_get_entity_info: callback for get_node_op
 *	The routine process matching network entity and add children elements
 *	to a Node object for given entity.
 *
 * p1	- matching entity object
 * p2	- lookup control data that was used for node look up
 *	    returns parent index(newtork entity) in look up control.
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_get_entity_info(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlNodePtr n_node = (xmlNodePtr)lcp->data[2].ptr;
	xmlNodePtr sub_node, subchild_node, subgrandchild_node;
	char numbuf[32];
	char buff[INET6_ADDRSTRLEN + 1] = { 0 };
	isns_attr_t *attr;

	sub_node = xmlNewChild(n_node, NULL, (xmlChar *)NETWORKENTITY, NULL);

	if (sub_node) {
	    attr = &obj->attrs[ATTR_INDEX_ENTITY(ISNS_EID_ATTR_ID)];
	    subchild_node = xmlNewChild(sub_node, NULL,
		(xmlChar *)ENTITYID, (xmlChar *)attr->value.ptr);
	    if (subchild_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	    attr = &obj->attrs[ATTR_INDEX_ENTITY(ISNS_ENTITY_PROTOCOL_ATTR_ID)];
	    (void) sprintf(numbuf, "%u", attr->value.ui);
	    subchild_node = xmlNewChild(sub_node, NULL,
		(xmlChar *)ENTITYPROTOCOL, (xmlChar *)numbuf);
	    if (subchild_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	    attr = &obj->attrs[ATTR_INDEX_ENTITY(ISNS_MGMT_IP_ADDR_ATTR_ID)];
	    if (attr->value.ip) {
		/* convert the ipv6 to ipv4 */
		if (((int *)attr->value.ip)[0] == 0x00 &&
		    ((int *)attr->value.ip)[1] == 0x00 &&
		    ((uchar_t *)attr->value.ip)[8] == 0x00 &&
		    ((uchar_t *)attr->value.ip)[9] == 0x00 &&
		    ((uchar_t *)attr->value.ip)[10] == 0xFF &&
		    ((uchar_t *)attr->value.ip)[11] == 0xFF) {
		    subchild_node = xmlNewChild(sub_node, NULL,
			(xmlChar *)MANAGEMENTIPADDR,
			(xmlChar *)inet_ntop(AF_INET,
			(void *)&(((uint32_t *)attr->value.ip)[3]),
			buff, sizeof (buff)));
		} else {
		    subchild_node = xmlNewChild(sub_node, NULL,
			(xmlChar *)MANAGEMENTIPADDR,
			(xmlChar *)inet_ntop(AF_INET6,
			(void *)attr->value.ip, buff, sizeof (buff)));
		}
		if (subchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	    attr = &obj->attrs[ATTR_INDEX_ENTITY(ISNS_TIMESTAMP_ATTR_ID)];
	    if (attr->value.ui) {
		(void) sprintf(numbuf, "%u", attr->value.ui);
		subchild_node = xmlNewChild(sub_node, NULL,
		(xmlChar *)ENTITYREGTIMESTAMP, (xmlChar *)numbuf);
		if (subchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	    attr = &obj->attrs[ATTR_INDEX_ENTITY(ISNS_VERSION_RANGE_ATTR_ID)];
	    if (attr->value.ui) {
		subchild_node = xmlNewNode(NULL,
		    (xmlChar *)PROTOCOLVERSIONRANGE);
		subchild_node = xmlAddChild(sub_node, subchild_node);
		if (subchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}

		(void) sprintf(numbuf, "%u",
		    (attr->value.ui >> ISNS_VER_SHIFT) & ISNS_VERSION);
		subgrandchild_node = xmlNewChild(subchild_node, NULL,
		    (xmlChar *)PROTOCOLMAXVERSION, (xmlChar *)numbuf);
		if (subgrandchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
		(void) sprintf(numbuf, "%u", attr->value.ui & ISNS_VERSION);
		subgrandchild_node = xmlNewChild(subchild_node, NULL,
		    (xmlChar *)PROTOCOLMINVERSION, (xmlChar *)numbuf);
		if (subgrandchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	    attr =
		&obj->attrs[ATTR_INDEX_ENTITY(ISNS_ENTITY_REG_PERIOD_ATTR_ID)];
	    if (attr->value.ui) {
		(void) sprintf(numbuf, "%u", attr->value.ui);
		subchild_node = xmlNewChild(sub_node, NULL,
		(xmlChar *)REGISTRATIONPERIOD, (xmlChar *)numbuf);
		if (subchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	} else {
	    return (ERR_XML_NEWCHILD_FAILED);
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_get_pg_info: callback for get_node_op
 *	The routine process matching portal group and returns ip address
 *	and port number for further portal processing.
 *
 * p1	- matching portal group object
 * p2	- lookup control data that was used for portal group look up
 *	    returns portal ip address, port and group tag in look up control.
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_get_pg_info(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	isns_attr_t *attr;

	/* get pg portal ip address and port attributes */
	attr = &obj->attrs[ATTR_INDEX_PG(ISNS_PG_PORTAL_IP_ADDR_ATTR_ID)];
	(void) memcpy(lcp->data[1].ip, attr->value.ip, sizeof (in6_addr_t));
	attr = &obj->attrs[ATTR_INDEX_PG(ISNS_PG_PORTAL_PORT_ATTR_ID)];
	lcp->data[2].ui = attr->value.ui;
	attr = &obj->attrs[ATTR_INDEX_PG(ISNS_PG_TAG_ATTR_ID)];
	lcp->id[2] = attr->value.ui;

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_get_portal_info: callback for get_node_op
 *	The routine process matching portal and add portal object info to
 *	the node object.
 *
 * p1	- matching portal object
 * p2	- lookup control data that was used for portal look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_get_portal_info(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlNodePtr n_node = (xmlNodePtr)lcp->data[2].ptr;
	uint32_t    tag = lcp->id[2];
	xmlNodePtr sub_node, subchild_node, subgrandchild_node;
	char numbuf[32];
	char buff[INET6_ADDRSTRLEN + 1] = { 0 };
	isns_attr_t *attr;

	sub_node = xmlNewChild(n_node, NULL, (xmlChar *)PORTAL, NULL);

	/* get portal object attributes. */
	if (sub_node) {
	    attr = &obj->attrs[ATTR_INDEX_PORTAL(ISNS_PORTAL_IP_ADDR_ATTR_ID)];
	    if (attr->value.ip) {
		/* convert the ipv6 to ipv4 */
		if (((int *)attr->value.ip)[0] == 0x00 &&
		    ((int *)attr->value.ip)[1] == 0x00 &&
		    ((uchar_t *)attr->value.ip)[8] == 0x00 &&
		    ((uchar_t *)attr->value.ip)[9] == 0x00 &&
		    ((uchar_t *)attr->value.ip)[10] == 0xFF &&
		    ((uchar_t *)attr->value.ip)[11] == 0xFF) {
		    subchild_node = xmlNewChild(sub_node, NULL,
			(xmlChar *)IPADDR,
			(xmlChar *)inet_ntop(AF_INET,
			(void *)&(((uint32_t *)attr->value.ip)[3]),
			buff, sizeof (buff)));
		} else {
		    subchild_node = xmlNewChild(sub_node, NULL,
			(xmlChar *)IPADDR,
			(xmlChar *)inet_ntop(AF_INET6,
			(void *)attr->value.ip, buff, sizeof (buff)));
		}
		if (subchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	    subchild_node = xmlNewChild(sub_node, NULL, (xmlChar *)UDPTCPPORT,
		NULL);
	    if (subchild_node) {
		attr = &obj->attrs[ATTR_INDEX_PORTAL(ISNS_PORTAL_PORT_ATTR_ID)];
		subgrandchild_node = xmlNewChild(subchild_node, NULL,
		    (xmlChar *)PORTTYPE, IS_PORT_UDP(attr->value.ui) ?
		    (xmlChar *)UDPPORT : (xmlChar *)TCPPORT);
		if (subgrandchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
		(void) sprintf(numbuf, "%u", PORT_NUMBER(attr->value.ui));
		subgrandchild_node = xmlNewChild(subchild_node, NULL,
		    (xmlChar *)PORTNUMBER, (xmlChar *)numbuf);
		if (subgrandchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    } else {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	    (void) sprintf(numbuf, "%u", tag);
	    subchild_node = xmlNewChild(sub_node, NULL, (xmlChar *)GROUPTAG,
		(xmlChar *)numbuf);
	    if (subchild_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	    attr = &obj->attrs[ATTR_INDEX_PORTAL(ISNS_PORTAL_NAME_ATTR_ID)];
	    if (attr->value.ptr) {
		subchild_node = xmlNewChild(sub_node, NULL,
		(xmlChar *)SYMBOLICNAME, (xmlChar *)attr->value.ptr);
		if (subchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	    attr = &obj->attrs[ATTR_INDEX_PORTAL(ISNS_ESI_INTERVAL_ATTR_ID)];
	    if (attr->value.ui) {
		(void) sprintf(numbuf, "%u", attr->value.ui);
		subchild_node = xmlNewChild(sub_node, NULL,
		(xmlChar *)ESIINTERVAL, (xmlChar *)numbuf);
		if (subchild_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	    attr = &obj->attrs[ATTR_INDEX_PORTAL(ISNS_ESI_PORT_ATTR_ID)];
	    if (attr->value.ui) {
		subchild_node = xmlNewChild(sub_node, NULL,
		    (xmlChar *)ESIPORT, NULL);
		if (subchild_node) {
		    subgrandchild_node = xmlNewChild(subchild_node, NULL,
			(xmlChar *)PORTTYPE, IS_PORT_UDP(attr->value.ui) ?
			(xmlChar *)UDPPORT : (xmlChar *)TCPPORT);
		    if (subgrandchild_node == NULL) {
			return (ERR_XML_NEWCHILD_FAILED);
		    }
		    (void) sprintf(numbuf, "%u", PORT_NUMBER(attr->value.ui));
		    subgrandchild_node = xmlNewChild(subchild_node, NULL,
			(xmlChar *)PORTNUMBER, (xmlChar *)numbuf);
		    if (subgrandchild_node == NULL) {
			return (ERR_XML_NEWCHILD_FAILED);
		    }
		} else {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	    attr = &obj->attrs[ATTR_INDEX_PORTAL(ISNS_SCN_PORT_ATTR_ID)];
	    if (attr->value.ui) {
		subchild_node = xmlNewChild(sub_node, NULL,
		    (xmlChar *)SCNPORT, NULL);
		if (subchild_node) {
		    subgrandchild_node = xmlNewChild(subchild_node, NULL,
			(xmlChar *)PORTTYPE, IS_PORT_UDP(attr->value.ui) ?
			(xmlChar *)UDPPORT : (xmlChar *)TCPPORT);
		    (void) sprintf(numbuf, "%u", PORT_NUMBER(attr->value.ui));
		    if (subgrandchild_node == NULL) {
			return (ERR_XML_NEWCHILD_FAILED);
		    }
		    subgrandchild_node = xmlNewChild(subchild_node, NULL,
			(xmlChar *)PORTNUMBER, (xmlChar *)numbuf);
		    if (subgrandchild_node == NULL) {
			return (ERR_XML_NEWCHILD_FAILED);
		    }
		} else {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	} else if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_get_dd_info: callback for get_dd_op
 *	The routine process matching dd object
 *
 * p1	- matching dd object
 * p2	- lookup control data that was used for dd look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_get_dd_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, sub_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;
	char numbuf[32];

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_ADDCHILD_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)DDOBJECT);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_ADDCHILD_FAILED);
	}

	attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)NAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_ID_ATTR_ID)];
	(void) sprintf(numbuf, "%u", attr->value.ui);
	n_attr = xmlSetProp(n_node, (xmlChar *)IDATTR,
		(xmlChar *)numbuf);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_FEATURES_ATTR_ID)];
	if (DD_BOOTLIST_ENABLED(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)BOOTLISTENABLEDELEM,
		(xmlChar *)XMLTRUE);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	} else {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)BOOTLISTENABLEDELEM,
		(xmlChar *)XMLFALSE);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_get_ddset_info: callback for get_ddset_op
 *	The routine process matching dd object
 *
 * p1	- matching dds object
 * p2	- lookup control data that was used for dd set look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_get_ddset_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, sub_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;
	char numbuf[32];

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}

	n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)DDSETOBJECT);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	/* get node name, alias, type and generate xml info */
	attr = &obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)NAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_ID_ATTR_ID)];
	(void) sprintf(numbuf, "%u", attr->value.ui);
	n_attr = xmlSetProp(n_node, (xmlChar *)IDATTR,
		(xmlChar *)numbuf);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_STATUS_ATTR_ID)];
	if (DDS_ENABLED(attr->value.ui)) {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)ENABLEDELEM,
		(xmlChar *)XMLTRUE);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	} else {
	    sub_node = xmlNewChild(n_node, NULL, (xmlChar *)ENABLEDELEM,
		(xmlChar *)XMLFALSE);
	    if (sub_node == NULL) {
		return (ERR_XML_NEWCHILD_FAILED);
	    }
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_enumerate_node_info: callback for enumerate_node_op
 *	The routine is invoked for each node object.
 *
 * p1	- node object
 * p2	- lookup control data that was used for node look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_enumerate_node_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}

	n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)NODEOBJECT);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	/* get node name, alias, type and generate xml info */
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)NAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NODE_TYPE_ATTR_ID)];
	switch (attr->value.ui) {
	    case ISNS_CONTROL_NODE_TYPE | ISNS_INITIATOR_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)CONTROLNODEINITIATORTYPE);
		break;
	    case ISNS_CONTROL_NODE_TYPE | ISNS_TARGET_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)CONTROLNODETARGETTYPE);
		break;
	    case ISNS_TARGET_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)TARGETTYPE);
		break;
	    case ISNS_INITIATOR_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)INITIATORTYPE);
		break;
	    case ISNS_CONTROL_NODE_TYPE:
		n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)CONTROLNODETYPE);
		break;
	    default:
	    n_attr = xmlSetProp(n_node, (xmlChar *)TYPEATTR,
		    (xmlChar *)UNKNOWNTYPE);
	}
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_ALIAS_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)ALIASATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * i_enumerate_dd_dds_info:
 *	The routine is implemnetation for enumerate dd and enumerate dds.
 *
 * p1	- dd or dd set object
 * p2	- lookup control data that was used for dd and dd set look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
i_enumerate_dd_dds_info(
	void *p1,
	void *p2,
	isns_type_t obj_type
)
{
	xmlNodePtr	n_obj, n_node, sub_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;
	char numbuf[32];

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}

	n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	if (obj_type == OBJ_DD) {
	    n_node = xmlNewNode(NULL, (xmlChar *)DDOBJECT);
	} else {
	    n_node = xmlNewNode(NULL, (xmlChar *)DDSETOBJECT);
	}

	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	if (obj_type == OBJ_DD) {
	    /* get name, id, feaure and generate xml info */
	    attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID)];
	    n_attr = xmlSetProp(n_node, (xmlChar *)NAMEATTR,
		(xmlChar *)attr->value.ptr);
	    if (n_attr == NULL) {
		return (ERR_XML_SETPROP_FAILED);
	    }
	    attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_ID_ATTR_ID)];
	    (void) sprintf(numbuf, "%u", attr->value.ui);
	    n_attr = xmlSetProp(n_node, (xmlChar *)IDATTR,
		(xmlChar *)numbuf);
	    if (n_attr == NULL) {
		return (ERR_XML_SETPROP_FAILED);
	    }
	    attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_FEATURES_ATTR_ID)];
	    if (DD_BOOTLIST_ENABLED(attr->value.ui)) {
		sub_node = xmlNewChild(n_node, NULL,
		    (xmlChar *)BOOTLISTENABLEDELEM, (xmlChar *)XMLTRUE);
		if (sub_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    } else {
		sub_node = xmlNewChild(n_node, NULL,
		    (xmlChar *)BOOTLISTENABLEDELEM, (xmlChar *)XMLFALSE);
		if (sub_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	} else {
	    /* get name, id, status and generate xml info */
	    attr = &obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID)];
	    n_attr = xmlSetProp(n_node, (xmlChar *)NAMEATTR,
		(xmlChar *)attr->value.ptr);
	    if (n_attr == NULL) {
		return (ERR_XML_SETPROP_FAILED);
	    }
	    attr = &obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_ID_ATTR_ID)];
	    (void) sprintf(numbuf, "%u", attr->value.ui);
	    n_attr = xmlSetProp(n_node, (xmlChar *)IDATTR,
		(xmlChar *)numbuf);
	    if (n_attr == NULL) {
		return (ERR_XML_SETPROP_FAILED);
	    }
	    attr = &obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_STATUS_ATTR_ID)];
	    if (DDS_ENABLED(attr->value.ui)) {
		sub_node = xmlNewChild(n_node, NULL,
		    (xmlChar *)ENABLEDELEM, (xmlChar *)XMLTRUE);
		if (sub_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    } else {
		sub_node = xmlNewChild(n_node, NULL,
		    (xmlChar *)ENABLEDELEM, (xmlChar *)XMLFALSE);
		if (sub_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_enumerate_dd_info: callback for enumerate_dd_op
 *	The routine is invoked for each dd object.
 *
 * p1	- dd object
 * p2	- lookup control data that was used for dd look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_enumerate_dd_info(
	void *p1,
	void *p2
)
{
	return (i_enumerate_dd_dds_info(p1, p2, OBJ_DD));
}

/*
 * ****************************************************************************
 *
 * cb_enumerate_ddset_info: callback for enumerate_dd_op
 *	The routine is invoked for each dd object.
 *
 * p1	- dd object
 * p2	- lookup control data that was used for dd set look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_enumerate_ddset_info(
	void *p1,
	void *p2
)
{
	return (i_enumerate_dd_dds_info(p1, p2, OBJ_DDS));
}

/*
 * ****************************************************************************
 *
 * cb_getAssociated_node_info:
 *	The routine is implemnetation for enumerate dd and enumerate dds.
 *
 * p1	- dd or dd set object
 * p2	- lookup control data that was used for dd and dd set look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_getAssociated_node_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;
	uchar_t *ddname = lcp->data[2].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)ASSOCIATION);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)DDOBJECTMEMBER);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	/* get node name, alias, type and generate xml info */
	attr = &obj->attrs[ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)NODENAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	n_attr = xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
		(xmlChar *)ddname);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_getAssociated_node_to_dd_info:
 *	The routine is implemnetation for enumerate dd and enumerate dds.
 *
 * p1	- dd or dd set object
 * p2	- lookup control data that was used for dd and dd set look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_getAssociated_node_to_dd_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;
	uchar_t *nodename = lcp->data[2].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)ASSOCIATION);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)DDOBJECTMEMBER);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	/* get node name, alias, type and generate xml info */
	n_attr = xmlSetProp(n_node, (xmlChar *)NODENAMEATTR,
		(xmlChar *)nodename);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_getAssociated_dd_info:
 *	The routine is implemnetation for getting dds membership.
 *
 * p1	- dd or dd set object
 * p2	- lookup control data that was used for dd and dd set look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_getAssociated_dd_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;
	uchar_t *ddsetname = lcp->data[2].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)ASSOCIATION);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)DDSETOBJECTMEMBER);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	/* get node name, alias, type and generate xml info */
	attr = &obj->attrs[ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	n_attr = xmlSetProp(n_node, (xmlChar *)DDSETNAMEATTR,
		(xmlChar *)ddsetname);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * cb_getAssociated_dd_to_ddset_info:
 *	The routine is implemnetation for enumerate dd and enumerate dds.
 *
 * p1	- dd or dd set object
 * p2	- lookup control data that was used for dd and dd set look up
 * return - error code
 *
 * ****************************************************************************
 */
static int
cb_getAssociated_dd_to_ddset_info(
	void *p1,
	void *p2
)
{
	xmlNodePtr	n_obj, n_node, root;
	xmlAttrPtr	n_attr;
	isns_attr_t *attr;

	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;
	xmlDocPtr doc = (xmlDocPtr)lcp->data[1].ptr;
	uchar_t *ddname = lcp->data[2].ptr;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)ASSOCIATION);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	n_node = xmlNewNode(NULL, (xmlChar *)DDSETOBJECTMEMBER);
	if (n_node) {
	    n_node = xmlAddChild(n_obj, n_node);
	    if (n_node == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	/* get node name, alias, type and generate xml info */
	n_attr = xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
		(xmlChar *)ddname);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}
	attr = &obj->attrs[ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID)];
	n_attr = xmlSetProp(n_node, (xmlChar *)DDSETNAMEATTR,
		(xmlChar *)attr->value.ptr);
	if (n_attr == NULL) {
	    return (ERR_XML_SETPROP_FAILED);
	}

	/* successful */
	return (0);
}

/*
 * ****************************************************************************
 *
 * handle_partial_success:
 *
 * doc	- response doc to fill up
 * ret	- return code from the caller.
 *
 * ****************************************************************************
 */
static int
handle_partial_success(
	xmlDocPtr doc,
	int ret
)
{
	xmlNodePtr	n_obj, n_node, root;
	char numbuf[32];

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)RESULTELEMENT);
	if (n_obj) {
	    if (root->children) {
		n_obj = xmlAddPrevSibling(root->children, n_obj);
		(void) sprintf(numbuf, "%d", (ret != 0) ? PARTIAL_SUCCESS : 0);
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)STATUSELEMENT,
		    (xmlChar *)numbuf);
		if (n_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)MESSAGEELEMENT,
		    (xmlChar *)result_code_to_str((ret != 0) ?
			PARTIAL_SUCCESS : 0));
		if (n_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    } else {
		n_obj = xmlAddChild(root, n_obj);
		if (n_obj == NULL) {
		    return (ERR_XML_ADDCHILD_FAILED);
		}
		(void) sprintf(numbuf, "%d", ret);
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)STATUSELEMENT,
		    (xmlChar *)numbuf);
		if (n_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)MESSAGEELEMENT,
		    (xmlChar *)result_code_to_str(ret));
		if (n_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * handle_partial_failure:
 *
 * doc	- response doc to fill up
 * ret	- return code from the caller.
 *
 * ****************************************************************************
 */
static int
handle_partial_failure(
	xmlDocPtr doc,
	int ret,
	boolean_t all_failed
)
{
	xmlNodePtr	n_obj, n_node, root;
	char numbuf[32];

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)RESULTELEMENT);
	if (n_obj) {
	    if (root->children) {
		/* some or all associations failed to create */
		n_obj = xmlAddPrevSibling(root->children, n_obj);
		/* capture last error. should come up with all failed?? */
		(void) sprintf(numbuf, "%d",
		    all_failed ? ret : PARTIAL_FAILURE);
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)STATUSELEMENT,
		    (xmlChar *)numbuf);
		if (n_node == NULL) {
			return (ERR_XML_NEWCHILD_FAILED);
		}
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)MESSAGEELEMENT,
		    (xmlChar *)result_code_to_str(all_failed ? ret :
			PARTIAL_FAILURE));
		if (n_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    } else {
		n_obj = xmlAddChild(root, n_obj);
		if (n_obj == NULL) {
		    return (ERR_XML_ADDCHILD_FAILED);
		}
		(void) sprintf(numbuf, "%d", (ret != 0) ? ret : 0);
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)STATUSELEMENT,
		    (xmlChar *)numbuf);
		if (n_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
		n_node = xmlNewChild(n_obj, NULL, (xmlChar *)MESSAGEELEMENT,
		    (xmlChar *)result_code_to_str((ret != 0) ? ret : 0));
		if (n_node == NULL) {
		    return (ERR_XML_NEWCHILD_FAILED);
		}
	    }
	} else {
	    return (ERR_XML_NEWNODE_FAILED);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * get_serverconfig_op:
 *	The routine process server administrative setting.
 *
 * doc	- response doc to fill up.
 *
 * ****************************************************************************
 */
int
get_serverconfig_op(
	xmlDocPtr doc
)
{
	extern uint64_t esi_threshold;
	extern uint8_t mgmt_scn;
	extern ctrl_node_t *control_nodes;
	extern pthread_mutex_t ctrl_node_mtx;
	extern char data_store[MAXPATHLEN];

	xmlNodePtr	n_obj, root;
	char numbuf[32];
	ctrl_node_t *ctrl_node_p;
	int ret = 0;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	n_obj = xmlNewNode(NULL, (xmlChar *)ISNSSERVER);
	if (n_obj) {
	    n_obj = xmlAddChild(root, n_obj);
	    if (n_obj == NULL) {
		return (ERR_XML_ADDCHILD_FAILED);
	    }
	} else {
	    return (ERR_XML_ADDCHILD_FAILED);
	}

	if (xmlNewChild(n_obj, NULL, (xmlChar *)DATASTORELOCATION,
	    (xmlChar *)data_store) == NULL) {
	    return (ERR_XML_NEWCHILD_FAILED);
	}

	(void) sprintf(numbuf, "%llu", esi_threshold);
	if (xmlNewChild(n_obj, NULL, (xmlChar *)ESIRETRYTHRESHOLD,
	    (xmlChar *)numbuf) == NULL) {
	    return (ERR_XML_NEWCHILD_FAILED);
	}
	if (xmlNewChild(n_obj, NULL, (xmlChar *)MANAGEMENTSCNENABLED,
	    (mgmt_scn) ? (uchar_t *)XMLTRUE : (uchar_t *)XMLFALSE) == NULL) {
	    return (ERR_XML_NEWCHILD_FAILED);
	}

	(void) pthread_mutex_lock(&ctrl_node_mtx);
	if (control_nodes == NULL) {
	    if (xmlNewChild(n_obj, NULL, (xmlChar *)CONTROLNODENAME,
		    (xmlChar *)NULL) == NULL) {
		    (void) pthread_mutex_unlock(&ctrl_node_mtx);
		    return (ERR_XML_NEWCHILD_FAILED);
	    }
	} else {
	    ctrl_node_p = control_nodes;
	    while (ctrl_node_p != NULL) {
		if (xmlNewChild(n_obj, NULL, (xmlChar *)CONTROLNODENAME,
		    (xmlChar *)ctrl_node_p->name) == NULL) {
		    (void) pthread_mutex_unlock(&ctrl_node_mtx);
		    return (ERR_XML_NEWCHILD_FAILED);
		}
		ctrl_node_p = ctrl_node_p->next;
	    }
	}
	(void) pthread_mutex_unlock(&ctrl_node_mtx);

	return (handle_partial_success(doc, ret));
}

/*
 * ****************************************************************************
 *
 * get_node_op:
 *	service get operation on a given node.
 *
 * req	- contains all info for a request.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
get_node_op(
	request_t *req,
	xmlDocPtr doc
	/* any additional arguments go here */
)
{
	int ret = 0, ret_save = 0;
	int i = 0;
	lookup_ctrl_t lc, lc2, lc3;
	uint32_t uid;
	char buff2[INET6_ADDRSTRLEN];

	/* prepare lookup ctrl data for looking for the node object */
	lc.curr_uid = 0;
	lc.type = get_lc_type(req->op_info.obj);
	lc.id[0] = get_lc_id(req->op_info.obj);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;
	lc.data[1].ptr = (uchar_t *)doc; /* xml writer descriptor */
	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.data[i];
		ret = cache_lookup(&lc, &uid, cb_get_node_info);
		if (uid == 0) {
		    ret = ERR_MATCHING_ISCSI_NODE_NOT_FOUND;
		}

		/* generate network entity object information */
		if (ret == 0 && lc.id[2] != 0) {
			/*
			 * !!! there might be no entity and portal info for
			 * !!! the node if it is not a registered node
			 */
			/* prepare lookup ctrl data for looking for entity */
			SET_UID_LCP(&lc2, OBJ_ENTITY, lc.id[2]);

			lc2.data[1].ptr = (uchar_t *)doc;
			/* cb_get_node_info callback returned Node object. */
			lc2.data[2].ptr = lc.data[2].ptr;
			ret = cache_lookup(&lc2, &uid, cb_get_entity_info);
			if (uid == 0) {
			    ret = ERR_MATCHING_NETWORK_ENTITY_NOT_FOUND;
			}
		}

		/* generate portal information */
		if (ret == 0 && lc.id[2] != 0) {
			/* prepare lookup ctrl data for looking for pg */
			lc2.curr_uid = 0;
			lc2.type = OBJ_PG;
			lc2.id[0] = ATTR_INDEX_PG(ISNS_PG_ISCSI_NAME_ATTR_ID);
			lc2.op[0] = OP_STRING;
			/* lc.data[0].ptr contains node name */
			lc2.data[0].ptr = lc.data[0].ptr;
			lc2.op[1] = 0;
			lc2.data[1].ip = (in6_addr_t *)buff2;

			/* prepare lookup ctrl data for looking for portal */
			lc3.curr_uid = 0;
			lc3.type = OBJ_PORTAL;
			lc3.id[0] = ATTR_INDEX_PORTAL(
				ISNS_PORTAL_IP_ADDR_ATTR_ID);
			lc3.op[0] = OP_MEMORY_IP6;
			lc3.id[1] = ATTR_INDEX_PORTAL(
				ISNS_PORTAL_PORT_ATTR_ID);
			lc3.op[1] = OP_INTEGER;
			lc3.op[2] = 0;
			/* cb_get_node_info callback returned Node object. */
			lc3.data[2].ptr = lc.data[2].ptr;
			for (;;) {
				ret = cache_lookup(&lc2, &uid, cb_get_pg_info);
				if (uid != 0) {
					/* we found a portal group */
					lc2.curr_uid = uid;
					/* it is a null pg if pgt is zero. */
					if (lc2.id[2] != 0) {
						/* pass ip addr */
						lc3.data[0].ip = lc2.data[1].ip;
						/* pass port num */
						lc3.data[1].ui = lc2.data[2].ui;
						/* pass pgt */
						lc3.id[2] = lc2.id[2];
						ret = cache_lookup(&lc3, &uid,
						    cb_get_portal_info);
					}
				} else {
					/*
					 * no more portal group which is
					 * tied to this stroage node object.
					 */
					break;
				}
			}
		}
		/* save error for this iteration */
		if (ret != 0) {
		    ret_save = ret;
		}
		ret = 0;
		i++;
	}

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * i_get_dd_dds_op:
 *	serves get operatrion on dd or dds.
 *
 * req	- contains all info for a request.
 * doc	- response doc to fill up
 * obj_type	- object type(either dd or dd set)
 *
 * ****************************************************************************
 */
static int
i_get_dd_dds_op(
	request_t *req,
	xmlDocPtr doc,
	isns_type_t obj_type
	/* any additional arguments go here */
)
{
	result_code_t ret = 0, ret_save = 0;
	int i = 0;
	lookup_ctrl_t lc;
	uint32_t uid;

	if ((obj_type != OBJ_DD) && (obj_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	/* prepare lookup ctrl data for looking for the node object */
	lc.curr_uid = 0;
	lc.type = obj_type;
	lc.id[0] = get_lc_id(req->op_info.obj);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;
	lc.data[1].ptr = (uchar_t *)doc; /* xml writer descriptor */
	while (i < req->count) {
		if (obj_type == OBJ_DD) {
		    lc.data[0].ptr = (uchar_t *)req->req_data.data[i];
		    ret = cache_lookup(&lc, &uid, cb_get_dd_info);
		    if (uid == 0) {
			/* set an error and continue. */
			ret = ERR_MATCHING_DD_NOT_FOUND;
		    }
		} else {
		    lc.data[0].ptr = (uchar_t *)req->req_data.data[i];
		    ret = cache_lookup(&lc, &uid, cb_get_ddset_info);
		    if (uid == 0) {
			/* set an error and continue. */
			ret = ERR_MATCHING_DDSET_NOT_FOUND;
		    }
		}
		/* save error for this iteration */
		if (ret != 0) {
		    ret_save = ret;
		}
		ret = 0;
		i++;
	}

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * i_delete_ddmember_op:
 *	serves delete member operatrion on dd.
 *
 * container	- dd name
 * member	- node name
 *
 * ****************************************************************************
 */
static int
i_delete_ddmember_op(
	uchar_t *container,
	uchar_t *member
)
{
	int ret = 0;

	isns_assoc_iscsi_t aiscsi;
	isns_obj_t *assoc;
	isns_attr_t *attr;
	int len;

	lookup_ctrl_t lc;
	uint32_t dd_id;

	/* prepare lookup ctrl data for looking for the dd object */
	lc.curr_uid = 0;
	lc.type = OBJ_DD;
	lc.id[0] = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.data[0].ptr = container;
	lc.op[1] = 0;

	if ((dd_id = is_obj_there(&lc)) != 0) {
	    aiscsi.type = OBJ_ASSOC_ISCSI;
	    aiscsi.puid = dd_id;

	    len = strlen((char *)member) + 1;
	    len += 4 - (len % 4);

	    attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
		ISNS_DD_ISCSI_NAME_ATTR_ID)];
	    attr->tag = ISNS_DD_ISCSI_NAME_ATTR_ID;
	    attr->len = len;
	    attr->value.ptr = (uchar_t *)member;
	    attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
		ISNS_DD_ISCSI_INDEX_ATTR_ID)];
	    attr->tag = 0; /* clear it */
	    assoc = (isns_obj_t *)&aiscsi;
	    ret = remove_dd_member(assoc);
	} else {
	    ret = ERR_MATCHING_DD_NOT_FOUND;
	}

	return (ret);
}

/*
 * ****************************************************************************
 *
 * i_delete_ddsetmember_op:
 *	serves delete member operatrion on dd set.
 *
 * container	- dd set name
 * member	- dd name
 *
 * ****************************************************************************
 */
static int
i_delete_ddsetmember_op(
	uchar_t *container,
	uchar_t *member
)
{
	int ret = 0;

	lookup_ctrl_t lc, lc2;
	uint32_t container_id, member_id;

	/* prepare lookup ctrl data for looking for the dd-set object */
	lc.curr_uid = 0;
	lc.type = OBJ_DDS;
	lc.id[0] = ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.data[0].ptr = container;
	lc.op[1] = 0;

	/* prepare lookup ctrl data for looking for the dd object */
	lc2.curr_uid = 0;
	lc2.type = OBJ_DD;
	lc2.id[0] = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
	lc2.op[0] = OP_STRING;
	lc2.data[0].ptr = member;
	lc2.op[1] = 0;

	if ((container_id = is_obj_there(&lc)) != 0) {
	    if ((member_id = is_obj_there(&lc2)) != 0) {
		ret = remove_dds_member(container_id, member_id);
	    } else {
		ret = ERR_MATCHING_DD_NOT_FOUND;
	    }
	} else {
	    ret = ERR_MATCHING_DDSET_NOT_FOUND;
	}

	return (ret);
}

/*
 * ****************************************************************************
 *
 * get_dd_op:
 *	service get operation on given dd(s).
 *
 * req	- contains all info for a request.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
get_dd_op(
	request_t *req,
	xmlDocPtr doc
	/* any additional arguments go here */
)
{
	return (i_get_dd_dds_op(req, doc, OBJ_DD));
}

/*
 * ****************************************************************************
 *
 * get_ddset_op:
 *	service get operation on given dd set(s).
 *
 * req	- contains all info for a request.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
get_ddset_op(
	request_t *req,
	xmlDocPtr doc
	/* any additional arguments go here */
)
{
	return (i_get_dd_dds_op(req, doc, OBJ_DDS));
}

/*
 * ****************************************************************************
 *
 * enumerate_node_op:
 *	services enumerate node op.
 *
 * req	- contains enumerate request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
enumerate_node_op(
	xmlDocPtr   doc
	/* any additional arguments go here */
)
{
	htab_t *htab = cache_get_htab(OBJ_ISCSI);
	uint32_t uid = 0;
	lookup_ctrl_t lc;
	int	    ret = 0, ret_save = 0;

	SET_UID_LCP(&lc, OBJ_ISCSI, 0);

	lc.data[1].ptr = (uchar_t *)doc;
	lc.data[2].ui = 0;

	FOR_EACH_ITEM(htab, uid, {
		lc.data[0].ui = uid;
		ret = cache_lookup(&lc, NULL, cb_enumerate_node_info);
		if (ret != 0) {
		    ret_save = ret;
		}
	});

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * enumerate_dd_op:
 *	services enumerate discovery domain op.
 *
 * req	- contains enumerate request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
enumerate_dd_op(
	xmlDocPtr   doc
	/* any additional arguments go here */
)
{

	htab_t *htab = cache_get_htab(OBJ_DD);
	uint32_t uid = 0;
	lookup_ctrl_t lc;
	int	    ret = 0, ret_save = 0;

	SET_UID_LCP(&lc, OBJ_DD, 0);

	lc.data[1].ptr = (uchar_t *)doc;
	lc.data[2].ui = 0;

	FOR_EACH_ITEM(htab, uid, {
		lc.data[0].ui = uid;
		ret = cache_lookup(&lc, NULL, cb_enumerate_dd_info);
		if (ret != 0) {
		    ret_save = ret;
		}
	});

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * enumerate_ddset_op:
 *	services enumerate discovery domain set op.
 *
 * req	- contains enumerate request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
enumerate_ddset_op(
	xmlDocPtr   doc
	/* any additional arguments go here */
)
{
	htab_t *htab = cache_get_htab(OBJ_DDS);
	uint32_t uid = 0;
	lookup_ctrl_t lc;
	int	    ret = 0, ret_save = 0;

	SET_UID_LCP(&lc, OBJ_DDS, 0);

	lc.data[1].ptr = (uchar_t *)doc;
	lc.data[2].ui = 0;

	FOR_EACH_ITEM(htab, uid, {
		lc.data[0].ui = uid;
		ret = cache_lookup(&lc, NULL, cb_enumerate_ddset_info);
		if (ret != 0) {
		    ret_save = ret;
		}
	});

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * getassociated_dd_to_node_op:
 *	construct a list of node that is associated with a given Discovery
 *	Domain.
 *
 * req	- contains getAssociated request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
getAssociated_dd_to_node_op(
	request_t *req,
	xmlDocPtr   doc
	/* any additional arguments go here */
)
{
	uint32_t uid = 0, n;
	lookup_ctrl_t lc, lc2;
	int	i = 0, ret = 0, ret_save = 0;
	bmp_t	*p;

	lc.curr_uid = 0;
	lc.type = OBJ_DD;
	lc.id[0] = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;

	SET_UID_LCP(&lc2, OBJ_ISCSI, 0);

	lc2.data[1].ptr = (uchar_t *)doc;

	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.data[i];
		if ((uid = is_obj_there(&lc)) != 0) {
		    ret = get_dd_matrix(uid, &p, &n);
		    FOR_EACH_MEMBER(p, n, uid, {
			lc2.data[0].ui = uid;
			lc2.data[2].ptr = (uchar_t *)req->req_data.data[i];
			ret = cache_lookup(&lc2, NULL,
			    cb_getAssociated_node_info);
		    });
		    free(p);
		} else {
		    ret = ERR_MATCHING_DD_NOT_FOUND;
		}
		/* save error for this iteration */
		if (ret != 0) {
		    ret_save = ret;
		}
		ret = 0;
		i++;
	}

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * getassociated_node_to_dd_op:
 *	construct a list of Discovery Doamins that is associated with a given
 *	node.
 *
 * req	- contains getAssociated request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
getAssociated_node_to_dd_op(
	request_t *req,
	xmlDocPtr   doc
	/* any additional arguments go here */
)
{
	uint32_t uid = 0, dd_id;
	lookup_ctrl_t lc, lc2;
	int	i = 0, ret = 0, ret_save = 0;

	lc.curr_uid = 0;
	lc.type = OBJ_ISCSI;
	lc.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;

	SET_UID_LCP(&lc2, OBJ_DD, 0);

	lc2.data[1].ptr = (uchar_t *)doc;

	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.data[i];
		if ((uid = is_obj_there(&lc)) != 0) {
		    if ((dd_id = get_dd_id(uid, 0)) == 0) {
			ret = ERR_NO_ASSOCIATED_DD_FOUND;
			i++;
			continue;
		    } else {
			do {
			    lc2.data[0].ui = dd_id;
			    lc2.data[2].ptr = (uchar_t *)req->req_data.data[i];
			    ret = cache_lookup(&lc2, NULL,
				cb_getAssociated_node_to_dd_info);
			    dd_id = get_dd_id(uid, dd_id);
			} while (dd_id != 0);
		    };
		} else {
		    ret = ERR_MATCHING_NODE_NOT_FOUND;
		}
		/* save error for this iteration */
		if (ret != 0) {
		    ret_save = ret;
		}
		ret = 0;
		i++;
	}

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * getassociated_ddset_to_dd_op:
 *	construct a list of Discovery Doamins that is associated with a given
 *	Discover Domain set.
 *
 * req	- contains getAssociated request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
getAssociated_ddset_to_dd_op(
	request_t *req,
	xmlDocPtr   doc
	/* any additional arguments go here */
)
{
	uint32_t uid = 0, n;
	lookup_ctrl_t lc, lc2;
	int	i = 0, ret = 0, ret_save = 0;
	bmp_t	*p;

	lc.curr_uid = 0;
	lc.type = OBJ_DDS;
	lc.id[0] = ATTR_INDEX_DDS(ISNS_DD_SET_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;

	SET_UID_LCP(&lc2, OBJ_DD, 0);

	lc2.data[1].ptr = (uchar_t *)doc;

	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.data[i];
		if ((uid = is_obj_there(&lc)) != 0) {
		    ret = get_dds_matrix(uid, &p, &n);
		    FOR_EACH_MEMBER(p, n, uid, {
			lc2.data[0].ui = uid;
			lc2.data[2].ptr = (uchar_t *)req->req_data.data[i];
			ret = cache_lookup(&lc2, NULL,
			    cb_getAssociated_dd_info);
		    });
		    free(p);
		} else {
		    ret = ERR_MATCHING_DDSET_NOT_FOUND;
		}
		/* save error for this iteration */
		if (ret != 0) {
		    ret_save = ret;
		}
		ret = 0;
		i++;
	}

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * getassociated_dd_to_ddset_op:
 *	construct a list of Discovery Doamin sets that is associated with a
 *	given Discovery Domain.
 *
 * req	- contains getAssociated request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
getAssociated_dd_to_ddset_op(
	request_t *req,
	xmlDocPtr   doc
	/* any additional arguments go here */
)
{
	uint32_t uid = 0, ddset_id;
	lookup_ctrl_t lc, lc2;
	int	i = 0, ret = 0, ret_save = 0;

	lc.curr_uid = 0;
	lc.type = OBJ_DD;
	lc.id[0] = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;

	SET_UID_LCP(&lc2, OBJ_DDS, 0);

	lc2.data[1].ptr = (uchar_t *)doc;

	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.data[i];
		if ((uid = is_obj_there(&lc)) != 0) {
		    lc2.data[2].ui = 0;
		    if ((ddset_id = get_dds_id(uid, 0)) == 0) {
			ret = ERR_NO_ASSOCIATED_DDSET_FOUND;
			i++;
			continue;
		    } else {
			do {
			    lc2.data[0].ui = ddset_id;
			    lc2.data[2].ptr = (uchar_t *)req->req_data.data[i];
			    ret = cache_lookup(&lc2, NULL,
				cb_getAssociated_dd_to_ddset_info);
			    ddset_id = get_dds_id(uid, ddset_id);
			} while (ddset_id != 0);
		    };
		} else {
		    ret = ERR_MATCHING_DD_NOT_FOUND;
		}
		if (ret != 0) {
		    ret_save = ret;
		}
		i++;
	}

	return (handle_partial_success(doc, ret_save));
}

/*
 * ****************************************************************************
 *
 * delete_dd_ddset_op:
 *	removes a list of dd or dd set.
 *
 * req	- contains delete request info.
 * doc	- response doc to fill up
 * obj_type	- object type(either dd or dd set)
 *
 * ****************************************************************************
 */
int
delete_dd_ddset_op(
	request_t *req,
	xmlDocPtr doc,
	object_type type
	/* any additional arguments go here */
)
{
	result_code_t ret = 0, ret_save = 0;
	isns_type_t lc_type;
	int i = 0, err_count = 0;
	lookup_ctrl_t lc;
	uint32_t uid;
	xmlNodePtr	n_obj, n_node, root;
	xmlAttrPtr	n_attr;
	int different_err = 0;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	lc_type = get_lc_type(type);
	if ((lc_type != OBJ_DD) && (lc_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	/* prepare lookup ctrl data for looking for the node object */
	lc.curr_uid = 0;
	lc.type = lc_type;
	lc.id[0] = get_lc_id(req->op_info.obj);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;
	lc.data[1].ptr = (uchar_t *)doc; /* xml writer descriptor */
	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.data[i];

		/* lock the cache for writing */
		(void) cache_lock_write();

		if ((uid = is_obj_there(&lc)) != 0) {
		    /* remove the dd/ddset */
		    ret = (lc_type == OBJ_DD) ?
			remove_dd_object(uid) :
			remove_dds_object(uid);
		    /* unlock the cache and sync the data */
		    ret = cache_unlock_sync(ret);
		} else {
		    /* unlock the cache and no need to sync data */
		    (void) cache_unlock_nosync();
		    /* set an error and continue. */
		    ret = (lc_type == OBJ_DD) ?  ERR_MATCHING_DD_NOT_FOUND :
			ERR_MATCHING_DDSET_NOT_FOUND;
		}

		if (ret != 0) {
		/* keep track if there are different errors encountered. */
		    if (ret_save != 0 && ret != ret_save) {
			different_err++;
		    }
		    err_count++;
		    n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
		    if (n_obj) {
			if ((n_obj = xmlAddChild(root, n_obj)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }

		    n_node = (lc_type == OBJ_DD) ?
			xmlNewNode(NULL, (xmlChar *)DDOBJECT) :
			xmlNewNode(NULL, (xmlChar *)DDSETOBJECT);
		    if (n_node) {
			if ((n_node = xmlAddChild(n_obj, n_node)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			}
			n_attr = xmlSetProp(n_node, (xmlChar *)NAMEATTR,
				(xmlChar *)req->req_data.data[i]);
			if (n_attr == NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }
		    ret_save = ret;
		}
		i ++;
	}

	return (handle_partial_failure(doc, ret_save,
	    (req->count == err_count && !different_err) ? B_TRUE : B_FALSE));
}

/*
 * ****************************************************************************
 *
 * delete_ddmember_ddsetmember_op:
 *	removes a list of dd memeber or dd seti member.
 *
 * req	- contains delete request info.
 * doc	- response doc to fill up
 * type	- object type(either dd or dd set)
 *
 * ****************************************************************************
 */
int
delete_ddmember_ddsetmember_op(
	request_t *req,
	xmlDocPtr doc,
	object_type type
	/* any additional arguments go here */
)
{
	result_code_t ret = 0, ret_save = 0;
	isns_type_t lc_type;
	int i = 0, err_count = 0;
	lookup_ctrl_t lc, lc2;
	uint32_t container_id, member_id;
	xmlNodePtr	n_node, n_obj, root;
	xmlAttrPtr	n_attr;
	int different_err = 0;
	int is_a_member;

	lc_type = get_lc_type(type);
	if ((lc_type != OBJ_DD) && (lc_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	/* prepare lookup ctrl data for looking for the node object */
	lc.curr_uid = 0;
	lc.type = lc_type;
	lc.id[0] = get_lc_id(req->op_info.obj);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;

	lc2.curr_uid = 0;
	if (lc_type == OBJ_DD) {
	    lc2.type = OBJ_ISCSI;
	    lc2.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
	} else {
	    lc2.type = OBJ_DD;
	    lc2.id[0] = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
	}
	lc2.op[0] = OP_STRING;
	lc2.op[1] = 0;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}

	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.pair[i]->container;

		/* get the dd_id/dds_id */
		(void) cache_lock_write();
		container_id = is_obj_there(&lc);

		if (container_id != 0) {
		    lc2.data[0].ptr = (uchar_t *)req->req_data.pair[i]->member;

		    member_id = is_obj_there(&lc2);
		    if (member_id != 0) {
			is_a_member =
			    (container_id ==
			    ((lc_type == OBJ_DD) ?
			    get_dd_id(member_id, container_id - 1) :
			    get_dds_id(member_id, container_id - 1)));
		    }
		    if (member_id != 0 && is_a_member != 0) {
			/* delete the dd member */
			ret = (lc_type == OBJ_DD) ?
			    i_delete_ddmember_op(
				(uchar_t *)req->req_data.pair[i]->container,
				(uchar_t *)req->req_data.pair[i]->member) :
			    i_delete_ddsetmember_op(
				(uchar_t *)req->req_data.pair[i]->container,
				(uchar_t *)req->req_data.pair[i]->member);
			/* unlock the cache and sync the data */
			ret = cache_unlock_sync(ret);
		    } else {
			/* unlock the cache and no need to sync */
			(void) cache_unlock_nosync();
			ret = ERR_NO_SUCH_ASSOCIATION;
		    }
		} else {
		    /* unlock the cache and no need to sync */
		    (void) cache_unlock_nosync();
		    ret = (lc_type == OBJ_DD) ?  ERR_MATCHING_DD_NOT_FOUND :
			ERR_MATCHING_DDSET_NOT_FOUND;
		}

		if (ret != 0) {
		/* keep track if there are different errors encountered. */
		    if (ret_save != 0 && ret != ret_save) {
			different_err++;
		    }
		    ret_save = ret;
		    err_count++;
		    n_obj = xmlNewNode(NULL, (xmlChar *)ASSOCIATION);
		    if (n_obj) {
			n_obj = xmlAddChild(root, n_obj);
			if (n_obj == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }
		    if (lc_type == OBJ_DD) {
			n_node =
			    xmlNewNode(NULL, (xmlChar *)DDOBJECTMEMBER);
			n_attr = xmlSetProp(n_node, (xmlChar *)NODENAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->member);
			if (n_attr == NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
			n_attr = xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->container);
			if (n_attr == NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
		    } else {
			n_node =
			    xmlNewNode(NULL, (xmlChar *)DDSETOBJECTMEMBER);
			n_attr = xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->member);
			if (n_attr == NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
			n_attr = xmlSetProp(n_node, (xmlChar *)DDSETNAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->container);
			if (n_attr == NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
		    }
		    if (xmlAddChild(n_obj, n_node) == NULL) {
			return (ERR_XML_ADDCHILD_FAILED);
		    }
		}
		i++;
	}

	return (handle_partial_failure(doc, ret_save,
	    (req->count == err_count && !different_err) ? B_TRUE : B_FALSE));
}

/*
 * ****************************************************************************
 *
 * create_ddmember_ddsetmember_op:
 *	removes a list of dd memeber or dd seti member.
 *
 * req	- contains delete request info.
 * doc	- response doc to fill up
 * type	- object type(either dd or dd set)
 *
 * ****************************************************************************
 */
int
create_ddmember_ddsetmember_op(
	request_t *req,
	xmlDocPtr doc,
	object_type type
	/* any additional arguments go here */
)
{
	result_code_t ret = 0, ret_save = 0;
	isns_type_t lc_type;
	int i = 0, err_count = 0;
	lookup_ctrl_t lc, lc2;
	uint32_t container_id, member_id;
	xmlNodePtr	n_node, n_obj, root;
	isns_assoc_iscsi_t aiscsi = { 0 };
	isns_assoc_dd_t add = { 0 };
	isns_obj_t *assoc;
	isns_attr_t *attr;
	uint32_t len;
	int different_err = 0;

	lc_type = get_lc_type(type);
	if ((lc_type != OBJ_DD) && (lc_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	/* prepare lookup ctrl data for looking for the node object */
	lc.curr_uid = 0;
	lc.type = lc_type;
	lc.id[0] = get_lc_id(req->op_info.obj);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;

	lc2.curr_uid = 0;
	if (lc_type == OBJ_DD) {
	    lc2.type = OBJ_ISCSI;
	    lc2.id[0] = ATTR_INDEX_ISCSI(ISNS_ISCSI_NAME_ATTR_ID);
	} else {
	    lc2.type = OBJ_DD;
	    lc2.id[0] = ATTR_INDEX_DD(ISNS_DD_NAME_ATTR_ID);
	}
	lc2.op[0] = OP_STRING;
	lc2.op[1] = 0;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}

	while (i < req->count) {
		lc.data[0].ptr = (uchar_t *)req->req_data.pair[i]->container;

		/* get the dd_id/dds_id */
		(void) cache_lock_write();
		container_id = is_obj_there(&lc);

		if (container_id != 0) {
		    (void) memset(&aiscsi, 0, sizeof (aiscsi));
		    if (lc_type == OBJ_DD) {
			aiscsi.puid = container_id;
			aiscsi.type = OBJ_ASSOC_ISCSI;
			attr = &aiscsi.attrs[ATTR_INDEX_ASSOC_ISCSI(
			    ISNS_DD_ISCSI_NAME_ATTR_ID)];
			attr->tag = ISNS_DD_ISCSI_NAME_ATTR_ID;
			len = xmlStrlen(
			    (xmlChar *)req->req_data.pair[i]->member) + 1;
			len += 4 - (len % 4); /* on 4 bytes aligned */
			attr->len = len;
			attr->value.ptr =
			    (uchar_t *)req->req_data.pair[i]->member;
			assoc = (isns_obj_t *)&aiscsi;

			/* add the dd member */
			ret = add_dd_member(assoc);

			/* unlock the cache and sync the data */
			ret = cache_unlock_sync(ret);
		    } else {
			lc2.data[0].ptr =
			    (uchar_t *)req->req_data.pair[i]->member;

			if ((member_id = is_obj_there(&lc2)) != 0) {
			    add.puid = container_id;
			    add.type = OBJ_ASSOC_DD;
			    attr = &add.attrs[ATTR_INDEX_ASSOC_DD(
				ISNS_DD_ID_ATTR_ID)];
			    attr->tag = ISNS_DD_ID_ATTR_ID;
			    attr->len = 4;
			    attr->value.ui = member_id;
			    assoc = (isns_obj_t *)&add;

			    /* add the dd-set member */
			    ret = add_dds_member(assoc);

			    /* unlock the cache and sync the data */
			    ret = cache_unlock_sync(ret);
			} else {
			    /* unlock the cache and no need to sync */
			    (void) cache_unlock_nosync();
			    ret = ERR_MATCHING_DD_NOT_FOUND;
			}
		    }
		} else {
		    /* unlock the cache and no need to sync */
		    (void) cache_unlock_nosync();
		    ret = (lc_type == OBJ_DD) ?  ERR_MATCHING_DD_NOT_FOUND :
			ERR_MATCHING_DDSET_NOT_FOUND;
		}
		if (ret != 0) {
		/* keep track if there are different errors encountered. */
		    if (ret_save != 0 && ret != ret_save) {
			different_err++;
		    }
		    err_count++;
		    n_obj = xmlNewNode(NULL, (xmlChar *)ASSOCIATION);
		    if (n_obj) {
			n_obj = xmlAddChild(root, n_obj);
			if (n_obj == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }
		    if (lc_type == OBJ_DD) {
			n_node =
			    xmlNewNode(NULL, (xmlChar *)DDOBJECTMEMBER);
			if (xmlSetProp(n_node, (xmlChar *)NODENAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->member) == NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
			if (xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->container) ==
			    NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
		    } else {
			n_node =
			    xmlNewNode(NULL, (xmlChar *)DDSETOBJECTMEMBER);
			if (xmlSetProp(n_node, (xmlChar *)DDNAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->member) == NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
			if (xmlSetProp(n_node, (xmlChar *)DDSETNAMEATTR,
			    (xmlChar *)req->req_data.pair[i]->container) ==
			    NULL) {
			    return (ERR_XML_SETPROP_FAILED);
			}
		    }
		    if (xmlAddChild(n_obj, n_node) == NULL) {
			return (ERR_XML_ADDCHILD_FAILED);
		    }
		    ret_save = ret;
		}
		i++;
	}

	return (handle_partial_failure(doc, ret_save,
	    (req->count == err_count && !different_err) ? B_TRUE : B_FALSE));
}

/*
 * ****************************************************************************
 *
 * rename_dd_ddset_op:
 *	removes a list of dd memeber or dd seti member.
 *
 * req	- contains delete request info.
 * doc	- response doc to fill up
 * type	- object type(either dd or dd set)
 *
 * ****************************************************************************
 */
static int
rename_dd_ddset_op(
	request_t *req,
	xmlDocPtr doc,
	object_type type
	/* any additional arguments go here */
)
{
	result_code_t ret = 0, ret_save = 0;
	isns_type_t lc_type;
	int i = 0, err_count = 0;
	lookup_ctrl_t lc;
	uint32_t container_id;
	xmlNodePtr	n_node, n_obj, root;
	uchar_t *name;
	uint32_t len;
	int different_err = 0;

	lc_type = get_lc_type(type);
	if ((lc_type != OBJ_DD) && (lc_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	/* prepare lookup ctrl data for looking for the node object */
	SET_UID_LCP(&lc, lc_type, 0);

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}

	while (i < req->count) {
		/* id is checked to be not NULL before calling this routine. */
		lc.data[0].ui = *(req->req_data.attrlist[i]->id);

		/* get the dd_id/dds_id */
		(void) cache_lock_write();

		if ((container_id = is_obj_there(&lc)) != 0) {
		    name = (uchar_t *)req->req_data.attrlist[i]->name;
		    /* the length of the name need to include the */
		    /* null terminator and be on 4 bytes aligned */
		    len = xmlStrlen(name) + 1;
		    len += 4 - (len % 4);

		    /* rename the dd/dds */
		    ret = (lc_type == OBJ_DD) ?
			update_dd_name(container_id, len, name) :
			update_dds_name(container_id, len, name);

		    /* release the lock and sync the data */
		    ret = cache_unlock_sync(ret);
		} else {
		    /* release the lock and no need to sync */
		    (void) cache_unlock_nosync();
		    ret = (lc_type == OBJ_DD) ?  ERR_MATCHING_DD_NOT_FOUND :
			ERR_MATCHING_DDSET_NOT_FOUND;
		}
		if (ret != 0) {
		/* keep track if there are different errors encountered. */
		    if (ret_save != 0 && ret != ret_save) {
			different_err++;
		    }
		    ret_save = ret;
		    err_count++;
		    n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
		    if (n_obj) {
			if ((n_obj = xmlAddChild(root, n_obj)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }

		    n_node = (lc_type == OBJ_DD) ?
			xmlNewNode(NULL, (xmlChar *)DDOBJECT) :
			xmlNewNode(NULL, (xmlChar *)DDSETOBJECT);
		    if (n_node) {
			if ((n_node = xmlAddChild(n_obj, n_node)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			} else {
			    if (xmlSetProp(n_node, (xmlChar *)NAMEATTR,
				(xmlChar *)req->req_data.attrlist[i]->name) ==
				NULL) {
				return (ERR_XML_SETPROP_FAILED);
			    }
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }

		}
		i++;
	}

	return (handle_partial_failure(doc, ret_save,
	    (req->count == err_count && !different_err) ? B_TRUE : B_FALSE));
}

/*
 * ****************************************************************************
 *
 * update_dd_ddset_op:
 *	removes a list of dd memeber or dd seti member.
 *
 * req	- contains delete request info.
 * doc	- response doc to fill up
 * type	- object type(either dd or dd set)
 *
 * ****************************************************************************
 */
static int
update_dd_ddset_op(
	request_t *req,
	xmlDocPtr doc,
	object_type type
	/* any additional arguments go here */
)
{
	result_code_t ret = 0, ret_save = 0;
	isns_type_t lc_type;
	int i = 0, err_count = 0;
	lookup_ctrl_t lc;
	uint32_t container_id;
	xmlNodePtr	n_node, n_obj, root;
	int different_err = 0;

	lc_type = get_lc_type(type);
	if ((lc_type != OBJ_DD) && (lc_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	/* prepare lookup ctrl data for looking for the node object */
	lc.curr_uid = 0;
	lc.type = lc_type;
	lc.id[0] = get_lc_id(req->op_info.obj);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}

	while (i < req->count) {
		lc.data[0].ptr = req->req_data.attrlist[i]->name;

		/* lock the cache for writing */
		(void) cache_lock_write();

		if ((container_id = is_obj_there(&lc)) != 0) {
		    ret = (lc_type == OBJ_DD) ?
			/* enabled is checked to be not NULL before calling. */
			update_dd_features(container_id,
			*(req->req_data.attrlist[i]->enabled) ? 1 : 0):
			update_dds_status(container_id,
			*(req->req_data.attrlist[i]->enabled) ? 1 : 0);
		    /* unlock the cache and sync the data */
		    ret = cache_unlock_sync(ret);
		} else {
		    (void) cache_unlock_nosync();
		    ret = (lc_type == OBJ_DD) ?  ERR_MATCHING_DD_NOT_FOUND :
			ERR_MATCHING_DDSET_NOT_FOUND;
		}
		if (ret != 0) {
		/* keep track if there are different errors encountered. */
		    if (ret_save != 0 && ret != ret_save) {
			different_err++;
		    }
		    ret_save = ret;
		    err_count++;
		    n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
		    if (n_obj) {
			if ((n_obj = xmlAddChild(root, n_obj)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }

		    n_node = (lc_type == OBJ_DD) ?
			xmlNewNode(NULL, (xmlChar *)DDOBJECT) :
			xmlNewNode(NULL, (xmlChar *)DDSETOBJECT);
		    if (n_node) {
			if ((n_node = xmlAddChild(n_obj, n_node)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			} else {
			    if (xmlSetProp(n_node, (xmlChar *)NAMEATTR,
				(xmlChar *)req->req_data.attrlist[i]->name) ==
				NULL) {
				return (ERR_XML_SETPROP_FAILED);
			    }
			}
		    } else {
			    return (ERR_XML_NEWNODE_FAILED);
		    }
		}
		i++;
	}

	return (handle_partial_failure(doc, ret_save,
	    (req->count == err_count && !different_err) ? B_TRUE : B_FALSE));
}

/*
 * ****************************************************************************
 *
 * createModify_dd_ddset_op:
 *	removes a list of dd memeber or dd seti member.
 *
 * req	- contains delete request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
static int
create_dd_ddset_op(
	request_t *req,
	xmlDocPtr doc,
	object_type type
	/* any additional arguments go here */
)
{
	isns_obj_t  *obj;
	result_code_t ret = 0, ret_save = 0;
	isns_type_t lc_type;
	lookup_ctrl_t lc;
	uint32_t uid;
	int i = 0, err_count = 0;
	xmlNodePtr	n_obj, n_node, root;
	int different_err = 0;

	lc_type = get_lc_type(type);
	if ((lc_type != OBJ_DD) && (lc_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
	    return (ERR_SYNTAX_MISSING_ROOT);
	}
	lc_type = get_lc_type(type);
	if ((lc_type != OBJ_DD) && (lc_type != OBJ_DDS)) {
	    return (ERR_INVALID_MGMT_REQUEST);
	}

	/* prepare lookup ctrl data for looking for the node object */
	lc.curr_uid = 0;
	lc.type = lc_type;
	lc.id[0] = get_lc_id(req->op_info.obj);
	lc.op[0] = OP_STRING;
	lc.op[1] = 0;
	lc.data[1].ptr = (uchar_t *)doc; /* xml writer descriptor */
	while (i < req->count) {
		lc.data[0].ptr = req->req_data.attrlist[i]->name,
		/* grab the write lock */
		(void) cache_lock_write();

		uid = is_obj_there(&lc);
		if (uid == 0) {
		    ret = (lc_type == OBJ_DD) ?
			adm_create_dd(&obj, req->req_data.attrlist[i]->name,
			0, 0) :
			adm_create_dds(&obj, req->req_data.attrlist[i]->name,
			0, 0);
		    if (ret == 0) {
			ret = register_object(obj, NULL, NULL);
			if (ret != 0) {
			    free_object(obj);
			}
			/* release the lock and sync the cache and data store */
			ret = cache_unlock_sync(ret);
		    }
		} else {
			/* release the lock and no need to sync the data */
			(void) cache_unlock_nosync();
			ret = ERR_NAME_IN_USE;
		}

		if (ret != 0) {
		/* keep track if there are different errors encountered. */
		    if (ret_save != 0 && ret != ret_save) {
			different_err++;
		    }
		    ret_save = ret;
		    err_count++;
		    n_obj = xmlNewNode(NULL, (xmlChar *)ISNSOBJECT);
		    if (n_obj) {
			if ((n_obj = xmlAddChild(root, n_obj)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			}
		    } else {
			return (ERR_XML_ADDCHILD_FAILED);
		    }

		    n_node = (lc_type == OBJ_DD) ?
			xmlNewNode(NULL, (xmlChar *)DDOBJECT) :
			xmlNewNode(NULL, (xmlChar *)DDSETOBJECT);
		    if (n_node) {
			if ((n_node = xmlAddChild(n_obj, n_node)) == NULL) {
			    return (ERR_XML_ADDCHILD_FAILED);
			} else {
			    if (xmlSetProp(n_node, (xmlChar *)NAMEATTR,
				(xmlChar *)req->req_data.attrlist[i]->name) ==
				NULL) {
				return (ERR_XML_SETPROP_FAILED);
			    }
			}
		    } else {
			return (ERR_XML_NEWNODE_FAILED);
		    }
		}
		i++;
	}

	return (handle_partial_failure(doc, ret_save,
	    (req->count == err_count && !different_err) ? B_TRUE : B_FALSE));
}

/*
 * ****************************************************************************
 *
 * createModify_dd_ddset_op:
 *	removes a list of dd memeber or dd seti member.
 *
 * req	- contains delete request info.
 * doc	- response doc to fill up
 *
 * ****************************************************************************
 */
int
createModify_dd_ddset_op(
	request_t *req,
	xmlDocPtr doc
	/* any additional arguments go here */
)
{
	result_code_t ret = 0;

	if (req->req_data.attrlist[0]->id != NULL) {
	    ret = rename_dd_ddset_op(req, doc, req->op_info.obj);
	} else if (req->req_data.attrlist[0]->enabled != NULL) {
	    ret = update_dd_ddset_op(req, doc, req->op_info.obj);
	} else {
	    ret = create_dd_ddset_op(req, doc, req->op_info.obj);
	}

	return (ret);
}
