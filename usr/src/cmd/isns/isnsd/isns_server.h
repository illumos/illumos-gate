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


#ifndef _ISNS_SERVER_H
#define	_ISNS_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <sys/param.h>
#include <isns_protocol.h>

#ifdef DEBUG
#define	ASSERT(EXP)	assert(EXP)
#else
#define	ASSERT(EXP)
#endif

#define	ISNS_RSP_MASK	(0x8000)

/*
 * definitions for SMF.
 */
#define	ISNS_SERVER_SVC_NAME	"network/isns_server"
#define	ISNS_SERVER_CONFIG	"config"
#define	CONFIG_DATA_STORE	"data_store_location"
#define	CONFIG_ESI_THRESHOLD	"ESI_retry_threshold_count"
#define	CONFIG_MGMT_SCN		"Management_SCN_Enabled"
#define	CONFIG_CONTROL_NODES	"Authorized_Control_Nodes"
#ifdef DEBUG
#define	OPT_DAEMONLIZE		"daemonlize"
#endif

#define	ISNS_DAEMON_SYSLOG_PP "isns"

#define	FIRST_TAG_ENTITY	ISNS_EID_ATTR_ID
#define	FIRST_TAG_ISCSI		ISNS_ISCSI_NAME_ATTR_ID
#define	FIRST_TAG_PORTAL	ISNS_PORTAL_IP_ADDR_ATTR_ID
#define	FIRST_TAG_PG		ISNS_PG_ISCSI_NAME_ATTR_ID
#define	FIRST_TAG_DD		ISNS_DD_ID_ATTR_ID
#define	FIRST_TAG_DDS		ISNS_DD_SET_ID_ATTR_ID
#define	FIRST_TAG_ASSOC_ISCSI	ISNS_DD_ISCSI_INDEX_ATTR_ID
#define	FIRST_TAG_ASSOC_DD	ISNS_DD_ID_ATTR_ID

#define	LAST_TAG_ENTITY		ISNS_ENTITY_INDEX_ATTR_ID
#define	LAST_TAG_ISCSI		ISNS_ISCSI_AUTH_METHOD_ATTR_ID
#define	LAST_TAG_PORTAL		ISNS_SCN_PORT_ATTR_ID
#define	LAST_TAG_PG		ISNS_PG_INDEX_ATTR_ID
#define	LAST_TAG_DD		ISNS_DD_FEATURES_ATTR_ID
#define	LAST_TAG_DDS		ISNS_DD_SET_STATUS_ATTR_ID
#define	LAST_TAG_ASSOC_ISCSI	ISNS_DD_ISCSI_NAME_ATTR_ID
#define	LAST_TAG_ASSOC_DD	ISNS_DD_ID_ATTR_ID

#define	NUM_OF_ENTITY_ATTRS \
	(LAST_TAG_ENTITY - FIRST_TAG_ENTITY + 1)
#define	NUM_OF_ISCSI_ATTRS \
	(LAST_TAG_ISCSI - FIRST_TAG_ISCSI + 1)
#define	NUM_OF_PORTAL_ATTRS \
	(LAST_TAG_PORTAL - FIRST_TAG_PORTAL + 1)
#define	NUM_OF_PG_ATTRS \
	(LAST_TAG_PG - FIRST_TAG_PG + 1)
#define	NUM_OF_DD_ATTRS \
	(LAST_TAG_DD - FIRST_TAG_DD + 1)
#define	NUM_OF_DDS_ATTRS \
	(LAST_TAG_DDS - FIRST_TAG_DDS + 1)
#define	NUM_OF_ASSOC_ISCSI_ATTRS \
	(LAST_TAG_ASSOC_ISCSI - FIRST_TAG_ASSOC_ISCSI + 1)
#define	NUM_OF_ASSOC_DD_ATTRS \
	(LAST_TAG_ASSOC_DD - FIRST_TAG_ASSOC_DD + 1)

#define	ATTR_INDEX_ENTITY(TAG)	((TAG) - FIRST_TAG_ENTITY)
#define	ATTR_INDEX_ISCSI(TAG)	((TAG) - FIRST_TAG_ISCSI)
#define	ATTR_INDEX_PORTAL(TAG)	((TAG) - FIRST_TAG_PORTAL)
#define	ATTR_INDEX_PG(TAG)	((TAG) - FIRST_TAG_PG)
#define	ATTR_INDEX_DD(TAG)	((TAG) - FIRST_TAG_DD)
#define	ATTR_INDEX_DDS(TAG)	((TAG) - FIRST_TAG_DDS)
#define	ATTR_INDEX_ASSOC_ISCSI(TAG)	((TAG) - FIRST_TAG_ASSOC_ISCSI)
#define	ATTR_INDEX_ASSOC_DD(TAG)	((TAG) - FIRST_TAG_ASSOC_DD)
#define	ATTR_INDEX(TAG, TYPE)	((TAG) - TAG_RANGE[TYPE][0])

#define	ISCSI_ATTR(ISCSI, TAG)	((ISCSI)->attrs[ATTR_INDEX_ISCSI(TAG)].value)

/*
 * isns object type.
 */
typedef enum isns_otype {
	/*
	 * iSNS objects as they are defined in RFC 4171.
	 */
	OBJ_ENTITY = 0x1,
	OBJ_ISCSI,
	OBJ_PORTAL,
	OBJ_PG,
	OBJ_DD,
	OBJ_DDS,
	MAX_OBJ_TYPE,
	/*
	 * dummy object types for future extension.
	 */
	OBJ_DUMMY1,
	OBJ_DUMMY2,
	OBJ_DUMMY3,
	OBJ_DUMMY4,
	/*
	 * madeup object for internal implementation.
	 */
	OBJ_ASSOC_ISCSI,
	OBJ_ASSOC_DD,
	MAX_OBJ_TYPE_FOR_SIZE
} isns_type_t;

#define	MAX_LOOKUP_CTRL	(3)
/*
 * lookup operation.
 */
typedef enum {
	OP_STRING = 1,
	OP_INTEGER,
	OP_MEMORY_IP6
} lookup_method_t;

/*
 * lookup control data.
 */
typedef struct lookup_ctrl {
	isns_type_t type;
	uint32_t curr_uid;
	uint16_t id[MAX_LOOKUP_CTRL];
	uint8_t op[MAX_LOOKUP_CTRL];
	union {
		uchar_t *ptr;
		uint32_t ui;
		in6_addr_t *ip;
	} data[MAX_LOOKUP_CTRL];
} lookup_ctrl_t;

#define	SET_UID_LCP(LCP, TYPE, UID)	{\
	(LCP)->type = TYPE;\
	(LCP)->curr_uid = 0;\
	(LCP)->id[0] = UID_ATTR_INDEX[TYPE];\
	(LCP)->op[0] = OP_INTEGER;\
	(LCP)->data[0].ui = UID;\
	(LCP)->op[1] = 0;\
}

#define	UPDATE_LCP_UID(LCP, UID)	{\
	(LCP)->curr_uid = 0;\
	(LCP)->id[0] = UID_ATTR_INDEX[(LCP)->type];\
	(LCP)->op[0] = OP_INTEGER;\
	(LCP)->data[0].ui = UID;\
	(LCP)->op[1] = 0;\
}

/*
 * isns object attribute
 */
typedef struct isns_attr {
	uint32_t tag;
	uint32_t len;
	union {
		int32_t i;
		uint32_t ui;
		in6_addr_t *ip;
		uchar_t *ptr;
		time_t timestamp;
	} value;
} isns_attr_t;

#define	MAX_KEY_ATTRS	(3)

/*
 * isns generic object.
 */
typedef struct isns_obj {
	isns_type_t type;
	isns_attr_t attrs[1];
} isns_obj_t;

#define	ISCSI_PARENT_TYPE	(OBJ_ENTITY)
#define	PORTAL_PARENT_TYPE	(OBJ_ENTITY)
#define	PG_PARENT_TYPE		(OBJ_ENTITY)
#define	ASSOC_ISCSI_PARENT_TYPE	(OBJ_DD)
#define	ASSOC_DD_PARENT_TYPE	(OBJ_DDS)

/*
 * iSNS objects.
 */
typedef struct isns_dds {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_DDS_ATTRS];
} isns_dds_t;

typedef struct isns_assoc_dd {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_ASSOC_DD_ATTRS];

	/* parent object uid */
#ifdef ASSOC_DD_PARENT_TYPE
	uint32_t puid;
#endif
} isns_assoc_dd_t;

#define	DDS_ENABLED(UI) ((UI) & (ISNS_DDS_STATUS))
#define	ENABLE_DDS(DDS)  (((DDS)->status) |= (ISNS_DDS_STATUS))
#define	DISABLE_DDS(DDS) (((DDS)->status) &= ~(ISNS_DDS_STATUS))

#define	DD_BOOTLIST_ENABLED(UI) ((UI) & (ISNS_DD_BOOTLIST))

typedef struct isns_dd {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_DD_ATTRS];
} isns_dd_t;

typedef struct isns_assoc_iscsi {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_ASSOC_ISCSI_ATTRS];

	/* parent object uid */
#ifdef ASSOC_ISCSI_PARENT_TYPE
	uint32_t puid;
#endif
} isns_assoc_iscsi_t;

#define	MAX_ISCSI_CHILD		(0)
#define	MAX_PORTAL_CHILD	(0)
#define	MAX_PG_CHILD		(0)
#define	MAX_ENTITY_CHILD	(2)
#define	MAX_CHILD_TYPE		(2)

#define	PG_REF_COUNT		(2)

#define	MAX_REF_COUNT		(2)

typedef struct isns_iscsi {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_ISCSI_ATTRS];

	/* parent object uid */
#ifdef ISCSI_PARENT_TYPE
	uint32_t puid;
#endif
	/* subordinate object uid(s) */
#if defined(MAX_ISCSI_CHILD) && (MAX_ISCSI_CHILD > 0)
	uint32_t *cuid[MAX_ISCSI_CHILD];
#endif
} isns_iscsi_t;

#define	IS_ISCSI_TARGET(NODE)    (((NODE)->type) & ISNS_TARGET_NODE_TYPE)
#define	IS_ISCSI_INITIATOR(NODE) (((NODE)->type) & ISNS_INITIATOR_NODE_TYPE)
#define	IS_ISCSI_CONTROL(NODE)   (((NODE)->type) & ISNS_CONTROL_NODE_TYPE)

#define	IS_TYPE_TARGET(TYPE)	((TYPE) & ISNS_TARGET_NODE_TYPE)
#define	IS_TYPE_INITIATOR(TYPE)	((TYPE) & ISNS_INITIATOR_NODE_TYPE)
#define	IS_TYPE_CONTROL(TYPE)	((TYPE) & ISNS_CONTROL_NODE_TYPE)
#define	IS_TYPE_UNKNOWN(TYPE)	(!IS_TYPE_TARGET(TYPE) && \
				!IS_TYPE_INITIATOR(TYPE) && \
				!IS_TYPE_CONTROL(TYPE))

#define	IS_SCN_INIT_SELF_INFO_ONLY(UI) ((UI) & ISNS_INIT_SELF_INFO_ONLY)
#define	IS_SCN_TARGET_SELF_INFO_ONLY(UI) ((UI) & ISNS_TARGET_SELF_INFO_ONLY)
#define	IS_SCN_MGMT_REG(UI)		((UI) & ISNS_MGMT_REG)
#define	IS_SCN_OBJ_REMOVED(UI)	((UI) & ISNS_OBJECT_REMOVED)
#define	IS_SCN_OBJ_ADDED(UI)	((UI) & ISNS_OBJECT_ADDED)
#define	IS_SCN_OBJ_UPDATED(UI)	((UI) & ISNS_OBJECT_UPDATED)
#define	IS_SCN_MEMBER_REMOVED(UI)   ((UI) & ISNS_MEMBER_REMOVED)
#define	IS_SCN_MEMBER_ADDED(UI)	((UI) & ISNS_MEMBER_ADDED)

typedef struct isns_portal {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_PORTAL_ATTRS];

	/* parent object uid */
#ifdef PORTAL_PARENT_TYPE
	uint32_t puid;
#endif
	/* subordinate object uid(s) */
#if defined(MAX_PORTAL_CHILD) && (MAX_PORTAL_CHILD > 0)
	uint32_t *cuid[MAX_PORTAL_CHILD];
#endif
} isns_portal_t;

#define	PORTAL_PORT(UI) ((UI) & ISNS_PORT_BITS)
#define	ESI_PORT(UI)    ((UI) & ISNS_PORT_BITS)
#define	IS_ESI_UDP(UI)  ((UI) & ISNS_PORT_TYPE)
#define	SCN_PORT(UI)    ((UI) & ISNS_PORT_BITS)
#define	IS_SCN_UDP(UI)  ((UI) & ISNS_PORT_TYPE)

#define	PORT_NUMBER(UI)	((UI) & ISNS_PORT_BITS)
#define	IS_PORT_UDP(UI)	((UI) & ISNS_PORT_TYPE)

typedef struct isns_pg {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_PG_ATTRS];

	/* parent object uid */
#ifdef PG_PARENT_TYPE
	uint32_t puid;
#endif
	/* subordinate object uid(s) */
#if defined(MAX_PG_CHILD) && (MAX_PG_CHILD > 0)
	uint32_t *cuid[MAX_PG_CHILD];
#endif
	/* ref count */
#if defined(PG_REF_COUNT) && (PG_REF_COUNT > 0)
	uint32_t ref[PG_REF_COUNT];
#endif
} isns_pg_t;

#define	PG_TAG(PGT)	(((PGT)->tag) & ISNS_PG_TAG)

typedef struct isns_entity {
	isns_type_t type;
	isns_attr_t attrs[NUM_OF_ENTITY_ATTRS];

	/* parent object uid */
#ifdef ENTITY_PARENT_TYPE
	uint32_t puid;
#endif
	/* subordinate object uid(s) */
#if defined(MAX_ENTITY_CHILD) && (MAX_ENTITY_CHILD > 0)
	uint32_t *cuid[MAX_ENTITY_CHILD];
#endif
} isns_entity_t;

#define	PROTOCOL_MAX_VER(ENTITY)	((((ENTITY)->versions) >> \
							ISNS_VER_SHIFT) && \
						ISNS_VERSION)
#define	PROTOCOL_MIN_VER(ENTITY)	(((ENTITY)->versions) & ISNS_VERSION)

#define	DEFAULT_EID_LEN	20
#define	DEFAULT_EID_PATTERN	"isns: %.6d"

#define	DEFAULT_DD_NAME		"Default"
#define	DEFAULT_DD_SET_NAME	"Default"

#define	DEFAULT_DD_FEATURES	0
#define	DEFAULT_DD_SET_STATUS	0

#define	MIN_ESI_INTVAL		(20)		/* 20 seconds */
#define	DEFAULT_ESI_INTVAL	(3 * 60)	/* 3 mintues */

#define	ONE_DAY		(86400)
#define	INFINITY	(4294967295UL)	/* >136 years, max # of uint32_t */

/*
 * function prototype.
 */
void *
isns_port_watcher(
	void *
);

uint16_t get_server_xid(void);

void inc_thr_count(void);
void dec_thr_count(void);
void shutdown_server(void);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_SERVER_H */
