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


#ifndef _V1_STRUCTS_
#define	_V1_STRUCTS_
#ifndef _STRUCTS_
#include "structs.h"
#endif

#define	V1_MAX_ACS_DRIVES		128

typedef struct {
	IPC_HEADER		ipc_header;
	MESSAGE_HEADER		message_header;
} V1_REQUEST_HEADER;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		message_id;
} V1_ACKNOWLEDGE_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	V1_CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		PANELID		panel_id[MAX_ID];
		SUBPANELID		subpanel_id[MAX_ID];
	} identifier;
} V1_AUDIT_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	V1_CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		AU_ACS_STATUS		acs_status[MAX_ID];
		AU_LSM_STATUS		lsm_status[MAX_ID];
		AU_PNL_STATUS		panel_status[MAX_ID];
		AU_SUB_STATUS		subpanel_status[MAX_ID];
	} identifier_status;
} V1_AUDIT_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	V1_CAPID		cap_id;
	unsigned short		count;
	VOLUME_STATUS		volume_status[MAX_ID];
} V1_EJECT_ENTER;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	V1_CAPID		cap_id;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
} V1_EJECT_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	V1_CAPID		cap_id;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} V1_EXT_EJECT_REQUEST;

typedef V1_EJECT_ENTER V1_EJECT_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	V1_CAPID		cap_id;
} V1_ENTER_REQUEST;

typedef V1_EJECT_ENTER V1_ENTER_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	VOLID		vol_id;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} V1_MOUNT_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V1_MOUNT_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	POOLID		pool_id;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} V1_MOUNT_SCRATCH_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	POOLID		pool_id;
	DRIVEID		drive_id;
	VOLID		vol_id;
} V1_MOUNT_SCRATCH_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V1_DISMOUNT_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V1_DISMOUNT_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	TYPE		type;
	unsigned short		count;
	union {
		VOLID		vol_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
	} identifier;
} V1_LOCK_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		LO_VOL_STATUS		volume_status[MAX_ID];
		LO_DRV_STATUS		drive_status[MAX_ID];
	} identifier_status;
} V1_LOCK_RESPONSE;

typedef V1_LOCK_REQUEST V1_CLEAR_LOCK_REQUEST;

typedef V1_LOCK_RESPONSE V1_CLEAR_LOCK_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		V1_CAPID		cap_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
		VOLID		vol_id[MAX_ID];
		MESSAGE_ID		request[MAX_ID];
		PORTID		port_id[MAX_ID];
		POOLID		pool_id[MAX_ID];
	} identifier;
} V1_QUERY_REQUEST;

typedef struct {
	V1_CAPID		cap_id;
	STATUS		status;
	CAP_PRIORITY		cap_priority;
	unsigned short		cap_size;
} V1_QU_CAP_STATUS;

typedef struct {
	VOLID		vol_id;
	CELLID		home_location;
	unsigned short		max_use;
	unsigned short		current_use;
	STATUS		status;
} V1_QU_CLN_STATUS;

typedef struct {
	DRIVEID		drive_id;
	STATE		state;
	VOLID		vol_id;
	STATUS		status;
} V1_QU_DRV_STATUS;

typedef struct {
	VOLID		vol_id;
	STATUS		status;
	unsigned short		drive_count;
	V1_QU_DRV_STATUS		drive_status[V1_MAX_ACS_DRIVES];

} V1_QU_MNT_STATUS;

typedef struct {
	VOLID		vol_id;
	LOCATION		location_type;
	union {
		CELLID		cell_id;
		DRIVEID		drive_id;
	} location;
	STATUS		status;
} V1_QU_VOL_STATUS;

typedef struct {
	VOLID		vol_id;
	CELLID		home_location;
	POOLID		pool_id;
	STATUS		status;
} V1_QU_SCR_STATUS;

typedef struct {
	POOLID		pool_id;
	STATUS		status;
	unsigned short		drive_count;
	V1_QU_DRV_STATUS		drive_list[V1_MAX_ACS_DRIVES];
} V1_QU_MSC_STATUS;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		QU_SRV_STATUS		server_status[MAX_ID];
		QU_ACS_STATUS		acs_status[MAX_ID];
		QU_LSM_STATUS		lsm_status[MAX_ID];
		V1_QU_CAP_STATUS cap_status[MAX_ID];
		V1_QU_CLN_STATUS		clean_volume_status[MAX_ID];
		V1_QU_DRV_STATUS		drive_status[MAX_ID];
		V1_QU_MNT_STATUS		mount_status[MAX_ID];
		V1_QU_VOL_STATUS		volume_status[MAX_ID];
		QU_PRT_STATUS		port_status[MAX_ID];
		QU_REQ_STATUS		request_status[MAX_ID];
		V1_QU_SCR_STATUS		scratch_status[MAX_ID];
		QU_POL_STATUS		pool_status[MAX_ID];
		V1_QU_MSC_STATUS		mount_scratch_status[MAX_ID];
	} status_response;
} V1_QUERY_RESPONSE;

typedef V1_LOCK_REQUEST V1_QUERY_LOCK_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		QL_VOL_STATUS		volume_status[MAX_ID];
		QL_DRV_STATUS		drive_status[MAX_ID];
	} identifier_status;
} V1_QUERY_LOCK_RESPONSE;

typedef V1_LOCK_REQUEST V1_UNLOCK_REQUEST;

typedef V1_LOCK_RESPONSE V1_UNLOCK_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
		PORTID		port_id[MAX_ID];
	} identifier;
} V1_VARY_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {
		VA_ACS_STATUS		acs_status[MAX_ID];
		VA_LSM_STATUS		lsm_status[MAX_ID];
		VA_DRV_STATUS		drive_status[MAX_ID];
		VA_PRT_STATUS		port_status[MAX_ID];
	} device_status;
} V1_VARY_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	V1_CAPID		cap_id;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
} V1_VENTER_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	unsigned long		low_water_mark;
	unsigned long		high_water_mark;
	unsigned long		pool_attributes;
	unsigned short		count;
	POOLID		pool_id[MAX_ID];
} V1_DEFINE_POOL_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	unsigned long		low_water_mark;
	unsigned long		high_water_mark;
	unsigned long		pool_attributes;
	unsigned short		count;
	struct {
		POOLID		pool_id;
		RESPONSE_STATUS status;
	} pool_status[MAX_ID];
} V1_DEFINE_POOL_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	unsigned short		count;
	POOLID		pool_id[MAX_ID];
} V1_DELETE_POOL_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	unsigned short		count;
	struct {
		POOLID		pool_id;
		RESPONSE_STATUS status;
	} pool_status[MAX_ID];
} V1_DELETE_POOL_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	CAP_PRIORITY		cap_priority;
	unsigned short		count;
	V1_CAPID		cap_id[MAX_ID];
} V1_SET_CAP_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	CAP_PRIORITY		cap_priority;
	unsigned short		count;
	struct {
		V1_CAPID		cap_id;
		RESPONSE_STATUS status;
	} set_cap_status[MAX_ID];
} V1_SET_CAP_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	unsigned short		max_use;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} V1_SET_CLEAN_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	unsigned short		max_use;
	unsigned short		count;
	struct {
		VOLID		vol_id;
		RESPONSE_STATUS status;
	} volume_status[MAX_ID];
} V1_SET_CLEAN_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	POOLID		pool_id;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} V1_SET_SCRATCH_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	POOLID		pool_id;
	unsigned short		count;
	struct {
		VOLID		vol_id;
		RESPONSE_STATUS status;
	} scratch_status[MAX_ID];
} V1_SET_SCRATCH_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	MESSAGE_ID		request;
} V1_CANCEL_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		request;
} V1_CANCEL_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
} V1_START_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
} V1_START_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
} V1_IDLE_REQUEST;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
} V1_IDLE_RESPONSE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
} V1_INIT_REQUEST;

typedef union {
	V1_REQUEST_HEADER		generic_request;
	V1_AUDIT_REQUEST		audit_request;
	V1_ENTER_REQUEST		enter_request;
	V1_VENTER_REQUEST		venter_request;
	V1_EJECT_REQUEST		eject_request;
	V1_EXT_EJECT_REQUEST		ext_eject_request;
	V1_VARY_REQUEST		vary_request;
	V1_MOUNT_REQUEST		mount_request;
	V1_MOUNT_SCRATCH_REQUEST		mount_scratch_request;
	V1_DISMOUNT_REQUEST		dismount_request;
	V1_QUERY_REQUEST		query_request;
	V1_CANCEL_REQUEST		cancel_request;
	V1_START_REQUEST		start_request;
	V1_IDLE_REQUEST		idle_request;
	V1_SET_SCRATCH_REQUEST		set_scratch_request;
	V1_DEFINE_POOL_REQUEST		define_pool_request;
	V1_DELETE_POOL_REQUEST		delete_pool_request;
	V1_SET_CLEAN_REQUEST		set_clean_request;
	V1_LOCK_REQUEST		lock_request;
	V1_UNLOCK_REQUEST		unlock_request;
	V1_CLEAR_LOCK_REQUEST		clear_lock_request;
	V1_QUERY_LOCK_REQUEST		query_lock_request;
	V1_SET_CAP_REQUEST		set_cap_request;
} V1_REQUEST_TYPE;

typedef struct {
	V1_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		response_status;
} V1_RESPONSE_HEADER;

typedef union {
	V1_RESPONSE_HEADER		generic_response;
	V1_ACKNOWLEDGE_RESPONSE		acknowledge_response;
	V1_AUDIT_RESPONSE		audit_response;
	V1_ENTER_RESPONSE		enter_response;
	V1_EJECT_ENTER		eject_enter;
	V1_EJECT_RESPONSE		eject_response;
	V1_VARY_RESPONSE		vary_response;
	V1_MOUNT_RESPONSE		mount_response;
	V1_MOUNT_SCRATCH_RESPONSE		mount_scratch_response;
	V1_DISMOUNT_RESPONSE		dismount_response;
	V1_QUERY_RESPONSE		query_response;
	V1_CANCEL_RESPONSE		cancel_response;
	V1_START_RESPONSE		start_response;
	V1_IDLE_RESPONSE		idle_response;
	V1_SET_SCRATCH_RESPONSE		set_scratch_response;
	V1_DEFINE_POOL_RESPONSE		define_pool_response;
	V1_DELETE_POOL_RESPONSE		delete_pool_response;
	V1_SET_CLEAN_RESPONSE		set_clean_response;
	V1_LOCK_RESPONSE		lock_response;
	V1_UNLOCK_RESPONSE		unlock_response;
	V1_CLEAR_LOCK_RESPONSE		clear_lock_response;
	V1_QUERY_LOCK_RESPONSE		query_lock_response;
	V1_SET_CAP_RESPONSE		set_cap_response;
} V1_RESPONSE_TYPE;

#endif /* _V1_STRUCTS_ */
