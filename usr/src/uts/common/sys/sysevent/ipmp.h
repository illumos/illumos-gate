/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SYSEVENT_IPMP_H
#define	_SYS_SYSEVENT_IPMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * IPMP sysevent definitions.  Note that all of these definitions are
 * Sun-private and are subject to change at any time.
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Event type EC_IPMP/ESC_IPMP_GROUP_STATE event schema
 *
 *	Event Class     - EC_IPMP
 *	Event Sub-Class - ESC_IPMP_GROUP_STATE
 *	Event Publisher - SUNW:usr:in.mpathd
 *
 * 	Attribute Name  - IPMP_EVENT_VERSION
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <version>
 *
 *	Attribute Name  - IPMP_GROUP_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <group-name>
 *
 *	Attribute Name  - IPMP_GROUP_SIGNATURE
 *	Attribute Type  - SE_DATA_TYPE_UINT64
 * 	Attribute Value - <group-signature>
 *
 *	Attribute Name  - IPMP_GROUP_STATE
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <group-state>
 */

#define	IPMP_EVENT_VERSION	"ipmp_event_version"
#define	IPMP_GROUP_NAME		"ipmp_group_name"
#define	IPMP_GROUP_SIGNATURE	"ipmp_group_signature"
#define	IPMP_GROUP_STATE	"ipmp_group_state"

typedef enum {
	IPMP_GROUP_OK,		/* at least one interface in group is ok */
	IPMP_GROUP_FAILED	/* all interfaces in the group have failed */
} ipmp_group_state_t;

#define	IPMP_EVENT_CUR_VERSION	1

/*
 * Event type EC_IPMP/ESC_IPMP_GROUP_CHANGE event schema
 *
 *	Event Class     - EC_IPMP
 *	Event Sub-Class - ESC_IPMP_GROUP_CHANGE
 *	Event Publisher - SUNW:usr:in.mpathd
 *
 *	Attribute Name  - IPMP_GROUP_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <group-name>
 *
 *	Attribute Name  - IPMP_EVENT_VERSION
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <version>
 *
 *	Attribute Name  - IPMP_GROUPLIST_SIGNATURE
 *	Attribute Type  - SE_DATA_TYPE_UINT64
 *	Attribute Value - <grouplist-signature>
 *
 *	Attribute Name  - IPMP_GROUP_OPERATION
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <group-change-op>
 */

#define	IPMP_GROUPLIST_SIGNATURE	"ipmp_grouplist_signature"
#define	IPMP_GROUP_OPERATION		"ipmp_group_operation"

typedef enum {
	IPMP_GROUP_ADD,		/* a new IPMP group has been created */
	IPMP_GROUP_REMOVE	/* an existing IPMP group has been removed */
} ipmp_group_op_t;

/*
 * Event type EC_IPMP/ESC_IPMP_GROUP_MEMBER event schema
 *
 *	Event Class     - EC_IPMP
 *	Event Sub-Class - ESC_IPMP_GROUP_MEMBER_CHANGE
 *	Event Publisher - SUNW:usr:in.mpathd
 *
 *	Attribute Name  - IPMP_GROUP_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <group-name>
 *
 *	Attribute Name  - IPMP_EVENT_VERSION
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <version>
 *
 *	Attribute Name  - IPMP_GROUP_SIGNATURE
 *	Attribute Type  - SE_DATA_TYPE_UINT64
 *	Attribute Value - <group-signature>
 *
 *	Attribute Name  - IPMP_IF_OPERATION
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <interface-op>
 *
 *	Attribute Name  - IPMP_IF_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <if-name>
 *
 *	Attribute Name  - IPMP_IF_TYPE
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <if-type>
 *
 *	Attribute Name  - IPMP_IF_STATE
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <if-state>
 */

#define	IPMP_IF_OPERATION	"ipmp_if_operation"
#define	IPMP_IF_NAME		"ipmp_if_name"
#define	IPMP_IF_TYPE		"ipmp_if_type"
#define	IPMP_IF_STATE		"ipmp_if_state"

typedef enum {
	IPMP_IF_ADD,		/* a new interface has joined the group */
	IPMP_IF_REMOVE 		/* an existing interface has left the group */
} ipmp_if_op_t;

typedef enum {
	IPMP_IF_STANDBY,	/* the interface is a standby */
	IPMP_IF_NORMAL 		/* the interface is not a standby */
} ipmp_if_type_t;

typedef enum {
	IPMP_IF_OK,		/* the interface is functional */
	IPMP_IF_FAILED,		/* the interface is in a failed state */
	IPMP_IF_OFFLINE,	/* the interface is offline */
	IPMP_IF_UNKNOWN		/* the interface may or may not be ok */
} ipmp_if_state_t;		/* (not enough probes have been sent) */

/*
 * Event type EC_IPMP/ESC_IPMP_IF_CHANGE event schema
 *
 *	Event Class     - EC_IPMP
 *	Event Sub-Class - ESC_IPMP_IF_CHANGE
 *	Event Publisher - SUNW:usr:in.mpathd
 *
 *	Attribute Name  - IPMP_GROUP_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <group-name>
 *
 *	Attribute Name  - IPMP_EVENT_VERSION
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <version>
 *
 *	Attribute Name  - IPMP_GROUP_SIGNATURE
 *	Attribute Type  - SE_DATA_TYPE_UINT64
 *	Attribute Value - <group-signature>
 *
 *	Attribute Name  - IPMP_IF_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <if-name>
 *
 *	Attribute Name  - IPMP_IF_STATE
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <if-state>
 *
 *	Attribute Name  - IPMP_IF_TYPE
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <if-type>
 */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_IPMP_H */
