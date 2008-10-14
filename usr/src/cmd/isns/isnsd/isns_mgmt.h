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

#ifndef _ISNS_MGMT_H
#define	_ISNS_MGMT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <libxml/xmlstring.h>

#define	ISNS_DOOR_NAME	"/var/run/isns_server_door"
#define	ISNS_ADMIN_WRITE_AUTH	"solaris.isnsmgr.write"
#define	ISNS_MAX_LABEL_LEN	50
#define	ISNS_MAX_NAME_LEN	256
#define	DOOR_DEFAULT_BUF_SIZE	4096
#define	MAX_DATA_COUNT	100


/* macro */
#define	XMLNCMP(x, y) (xmlStrncasecmp(xmlTextReaderConstName(x), \
	(const xmlChar *)y, xmlStrlen(xmlTextReaderConstName(x))))
#define	XMLNCMPVAL(x, y) (xmlStrncasecmp(xmlTextReaderConstValue(x), \
	(const xmlChar *)y, xmlStrlen(xmlTextReaderConstName(x))))

/* operation element names */
#define	ISNSREQUEST	"isnsRequest"
#define	ISNSRESPONSE	"isnsResponse"
#define	RESULT		"result"
#define	GET		"get"
#define	ENUMERATE	"enumerate"
#define	GETASSOCIATED	"getAssociated"
#define	CREATEMODIFY	"createModify"
#define	DELETE		"delete"

/* object element names */
#define	ISNSOBJECT	"isnsObject"
#define	ASSOCIATION	"Association"
#define	ISNSSERVER	"isnsServer"
#define	NODEOBJECT	"Node"
#define	DDOBJECT	"DiscoveryDomain"
#define	DDSETOBJECT	"DiscoveryDomainSet"
#define	DDOBJECTMEMBER	"DiscoveryDomainMember"
#define	DDSETOBJECTMEMBER	"DiscoveryDomainSetMember"

/* iSNS NODE attribute element names - Network Entity */
#define	XMLNSATTR	"xmlns"
#define	XMLNSATTRVAL	"http://www.sun.com/schema/isnsmanagement"

/* iSNS NODE attribute element names - Network Entity */
#define	NETWORKENTITY	"Network_Entity"
#define	ENTITYID	"Entity_ID"
#define	ENTITYPROTOCOL	"Entity_Protocol"
#define	MANAGEMENTIPADDR	"Management_IP_Addr"
#define	ENTITYREGTIMESTAMP	"Entity_Reg_Timestamp"
#define	PROTOCOLVERSIONRANGE	"Protocol_Version_Range"
#define	PROTOCOLMINVERSION	"minVersion"
#define	PROTOCOLMAXVERSION	"maxVersion"
#define	REGISTRATIONPERIOD	"Registration_Period"

/* iSNS NODE attribute element names - Portal element names */
#define	SCNSUBSCRIPTION		"SCN_Subscription"
#define	SCNINITSELFONLY		"Initiator and Self information only"
#define	SCNTARGETSELFONLY	"Target and Self information only"
#define	SCNMGMTREG		"Management Registration/SCN"
#define	SCNOBJECTREMOVED	"Object Removed"
#define	SCNOBJECTADDED		"Object Added"
#define	SCNOBJECTUPDATED	"Object Updated"
#define	SCNMEMBERREMOVED	"DD/DD-Set Member Removed"
#define	SCNMEMBERADDED		"DD/DD-Set Member Added"

#define	PORTAL		"Portal"
#define	REGISTRATIONPERIOD	"Registration_Period"
#define	IPADDR			"IP_Addr"
#define	UDPTCPPORT		"UDP_TCP_port"
#define	PORTTYPE		"Port_Type"
#define	UDPPORT			"UDP"
#define	TCPPORT			"TCP"
#define	PORTNUMBER		"Port_Number"
#define	GROUPTAG		"Group_Tag"
#define	SYMBOLICNAME		"Symbolic_Name"
#define	ESIINTERVAL		"ESI_Interval"
#define	ESIPORT			"ESI_Port"
#define	SCNPORT			"SCN_Port"

/* iSNS DD set state element */
#define	ENABLEDELEM		"Enabled"

/* iSNS DD Boot List element */
#define	BOOTLISTENABLEDELEM	"BootList_Enabled"

/* iSNS server config elements */
#define	DATASTORELOCATION	"datastoreLocation"
#define	ESIRETRYTHRESHOLD	"esiRetryThreshold"
#define	DEFAULTDDDDSETENABLED	"defaultDD_DDsetEnabled"
#define	MANAGEMENTSCNENABLED	"managementSCNEnabled"
#define	CANCONTROLNODEMODIFYDDDDSET "canControlNodeModifyDD_DDset"
#define	CANINTIATORNODEMODIFYDDDDSET	"canIntiatorNodeModifyDD_DDset"
#define	CANTARGETNODEMODIFYDDDDSET  "canTargetNodeModifyDD_DDset"
#define	CONTROLNODENAME		"controlNodeName"

/* object element type names */
#define	ISNSOBJECTTYPE	"isnsObjectType"
#define	ASSOCIATIONTYPE	"AssociationType"

/* attribute  names */
#define	NAMEATTR	"name"
#define	IDATTR		"id"
#define	TYPEATTR	"type"
#define	ALIASATTR	"alias"
#define	NODENAMEATTR	"NodeName"
#define	DDNAMEATTR	"DDName"
#define	DDSETNAMEATTR	"DDsetName"
#define	EMPTYSTR	""

/* Node type value names */
#define	INITIATORTYPE	"Initiator"
#define	TARGETTYPE	"Target"
#define	CONTROLNODETYPE	"Control"
#define	CONTROLNODETARGETTYPE	"Control/Target"
#define	CONTROLNODEINITIATORTYPE	"Control/Initiator"
#define	UNKNOWNTYPE	"Unknown"

/* response related element names. */
#define	RESULTELEMENT	"result"
#define	STATUSELEMENT	"status"
#define	MESSAGEELEMENT	"message"

/* response related element names. */
#define	XMLTRUE		"true"
#define	XMLFALSE	"false"

typedef enum {
    get_op = 100,
    enumerate_op,
    getAssociated_op,
    createModify_op,
    delete_op
} request_op;

typedef enum {
    member_to_container,
    container_to_member
} association_req_t;

typedef struct {
    char *op_str;
    request_op op_id;
} op_table_entry_t;

typedef enum {
    Node = 100,
    DiscoveryDomain,
    DiscoveryDomainSet,
    DiscoveryDomainMember,
    DiscoveryDomainSetMember,
    ServerConfig
} object_type;

typedef struct {
    char *obj_str;
    object_type obj_id;
} obj_table_entry_t;

typedef struct thr_elem {
    pthread_t   thr_id;
    xmlChar	*doc;
    struct thr_elem	*next;
} thr_elem_t;

/*
 * request entry with interger and string value
 */
typedef struct {
	request_op  op;
	object_type obj;
} operation_t;

typedef struct {
	xmlChar	*container;
	xmlChar	*member;
} assoc_pair_t;

typedef struct {
	xmlChar	*name;
	uint32_t    *id;
	boolean_t   *enabled;
} object_attrlist_t;

typedef union {
	xmlChar **data;
	assoc_pair_t    **pair;
	object_attrlist_t   **attrlist;
} req_data_ut;

typedef struct {
	operation_t	op_info;
	association_req_t	assoc_req;
	uint_t		count;
	req_data_ut	req_data;
} request_t;

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_MGMT_H */
