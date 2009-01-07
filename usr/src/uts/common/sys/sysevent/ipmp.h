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

#ifndef _SYS_SYSEVENT_IPMP_H
#define	_SYS_SYSEVENT_IPMP_H

/*
 * IPMP sysevent definitions.  Note that all of these definitions are
 * Sun-private and are subject to change at any time.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Event channel associated with these events
 */
#define	IPMP_EVENT_CHAN "com.sun:ipmp:events"

/*
 * Event type EC_IPMP/ESC_IPMP_GROUP_STATE event schema
 *
 *	Event Class     - EC_IPMP
 *	Event Sub-Class - ESC_IPMP_GROUP_STATE
 *	Event Vendor	- com.sun
 *	Event Publisher - in.mpathd
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
	IPMP_GROUP_OK,		/* all interfaces in the group are ok */
	IPMP_GROUP_FAILED,	/* all interfaces in the group are unusable */
	IPMP_GROUP_DEGRADED	/* some interfaces in the group are unusable */
} ipmp_group_state_t;

#define	IPMP_EVENT_CUR_VERSION	2

/*
 * Event type EC_IPMP/ESC_IPMP_GROUP_CHANGE event schema
 *
 *	Event Class     - EC_IPMP
 *	Event Sub-Class - ESC_IPMP_GROUP_CHANGE
 *	Event Vendor	- com.sun
 *	Event Publisher - in.mpathd
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
 *	Event Vendor	- com.sun
 *	Event Publisher - in.mpathd
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
 *	Event Vendor	- com.sun
 *	Event Publisher - in.mpathd
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

#define	IPMP_PROBE_ID			"ipmp_probe_id"
#define	IPMP_PROBE_STATE		"ipmp_probe_state"
#define	IPMP_PROBE_START_TIME		"ipmp_probe_start_time"
#define	IPMP_PROBE_SENT_TIME		"ipmp_probe_sent_time"
#define	IPMP_PROBE_ACKRECV_TIME		"ipmp_probe_ackrecv_time"
#define	IPMP_PROBE_ACKPROC_TIME		"ipmp_probe_ackproc_time"
#define	IPMP_PROBE_TARGET		"ipmp_probe_target"
#define	IPMP_PROBE_TARGET_RTTAVG	"ipmp_probe_target_rttavg"
#define	IPMP_PROBE_TARGET_RTTDEV	"ipmp_probe_target_rttdev"

typedef enum {
	IPMP_PROBE_SENT,	/* the probe has been sent */
	IPMP_PROBE_ACKED,	/* the probe has been acked */
	IPMP_PROBE_LOST		/* the probe has been lost */
} ipmp_probe_state_t;

/*
 * Event type EC_IPMP/ESC_IPMP_PROBE_STATE event schema
 *
 *	Event Class     - EC_IPMP
 *	Event Sub-Class - ESC_IPMP_PROBE_STATE
 *	Event Vendor	- com.sun
 *	Event Publisher - in.mpathd
 *
 *	Attribute Name  - IPMP_PROBE_ID
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <probe-id>
 *
 *	Attribute Name  - IPMP_EVENT_VERSION
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <version>
 *
 *	Attribute Name  - IPMP_IF_NAME
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - <if-name>
 *
 *	Attribute Name  - IPMP_PROBE_STATE
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <probe-state>
 *
 *	Attribute Name  - IPMP_PROBE_START_TIME
 *	Attribute Type  - SE_DATA_TYPE_TIME
 *	Attribute Value - <probe-start-time>
 *
 *	Attribute Name  - IPMP_PROBE_SENT_TIME
 *	Attribute Type  - SE_DATA_TYPE_TIME
 *	Attribute Value - <probe-sent-time>
 *
 *	Attribute Name  - IPMP_PROBE_ACKRECV_TIME
 *	Attribute Type  - SE_DATA_TYPE_TIME
 *	Attribute Value - <probe-ackrecv-time>
 *
 *	Attribute Name  - IPMP_PROBE_ACKPROC_TIME
 *	Attribute Type  - SE_DATA_TYPE_TIME
 *	Attribute Value - <probe-ackproc-time>
 *
 *	Attribute Name  - IPMP_PROBE_TARGET
 *	Attribute Type  - SE_DATA_TYPE_BYTES
 *	Attribute Value - <probe-target-ip>
 *
 *	Attribute Name  - IPMP_PROBE_TARGET_RTTAVG
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <probe-target-rttavg>
 *
 *	Attribute Name  - IPMP_PROBE_TARGET_RTTDEV
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value - <probe-target-rttdev>
 */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_IPMP_H */
