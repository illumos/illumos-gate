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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _V2_STRUCTS_
#define	_V2_STRUCTS_
#ifndef _STRUCTS_
#include "structs.h"
#endif


#define	V2_ANY_ACS		127
#define	V2_ANY_LSM		16
#define	V2_ANY_CAP		3
#define	V2_ALL_CAP		4
#define	V2_SAME_POOL		65535
#define	V2_SAME_PRIORITY		17


#define	V2_QU_MAX_DRV_STATUS		175


typedef struct {
	IPC_HEADER		ipc_header;
	MESSAGE_HEADER		message_header;
} V2_REQUEST_HEADER;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		message_id;
} V2_ACKNOWLEDGE_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		PANELID		panel_id[MAX_ID];
		SUBPANELID		subpanel_id[MAX_ID];
	} identifier;
} V2_AUDIT_REQUEST;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		AU_ACS_STATUS		acs_status[MAX_ID];
		AU_LSM_STATUS		lsm_status[MAX_ID];
		AU_PNL_STATUS		panel_status[MAX_ID];
		AU_SUB_STATUS		subpanel_status[MAX_ID];
	} identifier_status;
} V2_AUDIT_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	MESSAGE_ID		request;
} V2_CANCEL_REQUEST;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		request;
} V2_CANCEL_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	CAPID		cap_id;
	unsigned short		count;
	VOLUME_STATUS		volume_status[MAX_ID];
} V2_EJECT_ENTER;

typedef V2_EJECT_ENTER		V2_EJECT_RESPONSE;
typedef V2_EJECT_ENTER		V2_ENTER_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	CAPID		cap_id;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
} V2_EJECT_REQUEST;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	CAPID		cap_id;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} V2_EXT_EJECT_REQUEST;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	CAPID		cap_id;
} V2_ENTER_REQUEST;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	VOLID		vol_id;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} V2_MOUNT_REQUEST;

typedef struct  {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V2_MOUNT_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	POOLID		pool_id;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} V2_MOUNT_SCRATCH_REQUEST;

typedef struct  {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	POOLID		pool_id;
	DRIVEID		drive_id;
	VOLID		vol_id;
} V2_MOUNT_SCRATCH_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V2_DISMOUNT_REQUEST;

typedef struct  {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V2_DISMOUNT_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	TYPE		type;
	unsigned short		count;
	union {
		VOLID		vol_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
	} identifier;
} V2_LOCK_REQUEST;

typedef V2_LOCK_REQUEST		V2_CLEAR_LOCK_REQUEST;
typedef V2_LOCK_REQUEST		V2_QUERY_LOCK_REQUEST;
typedef V2_LOCK_REQUEST		V2_UNLOCK_REQUEST;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		LO_VOL_STATUS		volume_status[MAX_ID];
		LO_DRV_STATUS		drive_status[MAX_ID];
	} identifier_status;
} V2_LOCK_RESPONSE;

typedef V2_LOCK_RESPONSE		V2_CLEAR_LOCK_RESPONSE;
typedef V2_LOCK_RESPONSE		V2_UNLOCK_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		CAPID		cap_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
		VOLID		vol_id[MAX_ID];
		MESSAGE_ID		request[MAX_ID];
		PORTID		port_id[MAX_ID];
		POOLID		pool_id[MAX_ID];
	} identifier;
} V2_QUERY_REQUEST;

typedef struct {
	VOLID		vol_id;
	CELLID		home_location;
	unsigned short		max_use;
	unsigned short		current_use;
	STATUS		status;
} V2_QU_CLN_STATUS;

typedef struct {
	DRIVEID		drive_id;
	STATE		state;
	VOLID		vol_id;
	STATUS		status;
} V2_QU_DRV_STATUS;

typedef struct {
	VOLID		vol_id;
	STATUS		status;
	unsigned short		drive_count;
	V2_QU_DRV_STATUS drive_status[V2_QU_MAX_DRV_STATUS];

} V2_QU_MNT_STATUS;

typedef struct {
	VOLID		vol_id;
	LOCATION		location_type;
	union {
		CELLID		cell_id;
		DRIVEID		drive_id;
	} location;
	STATUS		status;
} V2_QU_VOL_STATUS;

typedef struct {
	VOLID		vol_id;
	CELLID		home_location;
	POOLID		pool_id;
	STATUS		status;
} V2_QU_SCR_STATUS;

typedef struct {
	POOLID		pool_id;
	STATUS		status;
	unsigned short		drive_count;
	V2_QU_DRV_STATUS drive_list[V2_QU_MAX_DRV_STATUS];
} V2_QU_MSC_STATUS;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		QU_SRV_STATUS		server_status[MAX_ID];
		QU_ACS_STATUS		acs_status[MAX_ID];
		QU_LSM_STATUS		lsm_status[MAX_ID];
		QU_CAP_STATUS		cap_status[MAX_ID];
		V2_QU_CLN_STATUS		clean_volume_status[MAX_ID];
		V2_QU_DRV_STATUS		drive_status[MAX_ID];
		V2_QU_MNT_STATUS		mount_status[MAX_ID];
		V2_QU_VOL_STATUS		volume_status[MAX_ID];
		QU_PRT_STATUS		port_status[MAX_ID];
		QU_REQ_STATUS		request_status[MAX_ID];
		V2_QU_SCR_STATUS		scratch_status[MAX_ID];
		QU_POL_STATUS		pool_status[MAX_ID];
		V2_QU_MSC_STATUS		mount_scratch_status[MAX_ID];
	} status_response;
} V2_QUERY_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		QL_VOL_STATUS		volume_status[MAX_ID];
		QL_DRV_STATUS		drive_status[MAX_ID];
	} identifier_status;
} V2_QUERY_LOCK_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
		PORTID		port_id[MAX_ID];
		CAPID		cap_id[MAX_ID];
	} identifier;
} V2_VARY_REQUEST;

typedef struct {
	V2_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {		/* list of IDs varied w/status */
		VA_ACS_STATUS		acs_status[MAX_ID];
		VA_LSM_STATUS		lsm_status[MAX_ID];
		VA_DRV_STATUS		drive_status[MAX_ID];
		VA_PRT_STATUS		port_status[MAX_ID];
		VA_CAP_STATUS		cap_status[MAX_ID];
	} device_status;
} V2_VARY_RESPONSE;

typedef struct {			/* venter request */
	V2_REQUEST_HEADER	request_header;
	CAPID			cap_id;	/* CAP used for ejection */
	unsigned short		count;	/* Number of cartridges */
	VOLID		vol_id[MAX_ID]; /* Virtual tape cartridge label */
} V2_VENTER_REQUEST;

typedef struct {			/* define pool request */
	V2_REQUEST_HEADER	_header;
	unsigned long		low_water_mark;
	unsigned long		high_water_mark;
	unsigned long		pool_attributes;
	unsigned short		count;
	POOLID		pool_id[MAX_ID];
} V2_DEFINE_POOL_REQUEST;

typedef struct {			/* define pool response */
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		message_status;
	unsigned long		low_water_mark;
	unsigned long		high_water_mark;
	unsigned long		pool_attributes;
	unsigned short		count;
	struct {
		POOLID		pool_id;
		RESPONSE_STATUS status;
	} pool_status[MAX_ID];
} V2_DEFINE_POOL_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	unsigned short		count;
	POOLID		pool_id[MAX_ID];
} V2_DELETE_POOL_REQUEST;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		message_status;
	unsigned short		count;
	struct {
		POOLID		pool_id;
		RESPONSE_STATUS status;
	} pool_status[MAX_ID];
} V2_DELETE_POOL_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	CAP_PRIORITY		cap_priority;
	CAP_MODE		cap_mode;
	unsigned short		count;
	CAPID		cap_id[MAX_ID];
} V2_SET_CAP_REQUEST;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		message_status;
	CAP_PRIORITY		cap_priority;
	CAP_MODE		cap_mode;
	unsigned short		count;
	struct {
		CAPID		cap_id;
		RESPONSE_STATUS status;
	} set_cap_status[MAX_ID];
} V2_SET_CAP_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	unsigned short		max_use;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} V2_SET_CLEAN_REQUEST;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		message_status;
	unsigned short		max_use;
	unsigned short		count;
	struct {
		VOLID		vol_id;
		RESPONSE_STATUS status;
	} volume_status[MAX_ID];
} V2_SET_CLEAN_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	POOLID		pool_id;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} V2_SET_SCRATCH_REQUEST;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		message_status;
	POOLID			pool_id;
	unsigned short		count;
	struct {
		VOLID		vol_id;
		RESPONSE_STATUS status;
	} scratch_status[MAX_ID];
} V2_SET_SCRATCH_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
} V2_START_REQUEST;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		message_status;
} V2_START_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
} V2_IDLE_REQUEST;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		message_status;
} V2_IDLE_RESPONSE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
} V2_INIT_REQUEST;


typedef union {
	V2_REQUEST_HEADER		generic_request;
	V2_AUDIT_REQUEST		audit_request;
	V2_ENTER_REQUEST		enter_request;
	V2_VENTER_REQUEST		venter_request;
	V2_EJECT_REQUEST		eject_request;
	V2_EXT_EJECT_REQUEST		ext_eject_request;
	V2_VARY_REQUEST			vary_request;
	V2_MOUNT_REQUEST		mount_request;
	V2_MOUNT_SCRATCH_REQUEST	 mount_scratch_request;
	V2_DISMOUNT_REQUEST		dismount_request;
	V2_QUERY_REQUEST		query_request;
	V2_CANCEL_REQUEST		cancel_request;
	V2_START_REQUEST		start_request;
	V2_IDLE_REQUEST			idle_request;
	V2_SET_SCRATCH_REQUEST		set_scratch_request;
	V2_DEFINE_POOL_REQUEST		define_pool_request;
	V2_DELETE_POOL_REQUEST		delete_pool_request;
	V2_SET_CLEAN_REQUEST		set_clean_request;
	V2_LOCK_REQUEST			lock_request;
	V2_UNLOCK_REQUEST		unlock_request;
	V2_CLEAR_LOCK_REQUEST		clear_lock_request;
	V2_QUERY_LOCK_REQUEST		query_lock_request;
	V2_SET_CAP_REQUEST		set_cap_request;
} V2_REQUEST_TYPE;

typedef struct {
	V2_REQUEST_HEADER	request_header;
	RESPONSE_STATUS		response_status;
} V2_RESPONSE_HEADER;

typedef union {
	V2_RESPONSE_HEADER		generic_response;
	V2_ACKNOWLEDGE_RESPONSE		acknowledge_response;
	V2_AUDIT_RESPONSE		audit_response;
	V2_ENTER_RESPONSE		enter_response;
	V2_EJECT_ENTER			eject_enter;
	V2_EJECT_RESPONSE		eject_response;
	V2_VARY_RESPONSE		vary_response;
	V2_MOUNT_RESPONSE		mount_response;
	V2_MOUNT_SCRATCH_RESPONSE	 mount_scratch_response;
	V2_DISMOUNT_RESPONSE		dismount_response;
	V2_QUERY_RESPONSE		query_response;
	V2_CANCEL_RESPONSE		cancel_response;
	V2_START_RESPONSE		start_response;
	V2_IDLE_RESPONSE		idle_response;
	V2_SET_SCRATCH_RESPONSE		set_scratch_response;
	V2_DEFINE_POOL_RESPONSE		define_pool_response;
	V2_DELETE_POOL_RESPONSE		delete_pool_response;
	V2_SET_CLEAN_RESPONSE		set_clean_response;
	V2_LOCK_RESPONSE		lock_response;
	V2_UNLOCK_RESPONSE		unlock_response;
	V2_CLEAR_LOCK_RESPONSE		clear_lock_response;
	V2_QUERY_LOCK_RESPONSE		query_lock_response;
	V2_SET_CAP_RESPONSE		set_cap_response;
} V2_RESPONSE_TYPE;

#endif /* _V2_STRUCTS_ */
