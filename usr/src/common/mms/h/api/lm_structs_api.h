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



#ifndef _LM_STRUCTS_API_
#define	_LM_STRUCTS_API_
typedef struct {
	IPC_HEADER		ipc_header;
	MESSAGE_HEADER		message_header;
} REQUEST_HEADER;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS message_status;
	MESSAGE_ID		message_id;
} ACKNOWLEDGE_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		PANELID		panel_id[MAX_ID];
		SUBPANELID		subpanel_id[MAX_ID];
	} identifier;
} AUDIT_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
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
} AUDIT_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	CAPID		cap_id;
	unsigned short		count;
	VOLUME_STATUS		volume_status[MAX_ID];
} EJECT_ENTER;

typedef EJECT_ENTER		EJECT_RESPONSE;
typedef EJECT_ENTER		ENTER_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	CAPID		cap_id;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
} EJECT_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	CAPID		cap_id;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} EXT_EJECT_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	CAPID		cap_id;
} ENTER_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	VOLID		vol_id;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} MOUNT_REQUEST;

typedef struct  {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} MOUNT_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	VOLID		vol_id[MAX_ID];
	unsigned short		count;
	LSMID		lsm;

} MOVE_REQUEST;

typedef struct  {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	unsigned short		count;
	VOLUME_STATUS		volume_status[MAX_ID];
} MOVE_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	POOLID		pool_id;
	MEDIA_TYPE		media_type;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} MOUNT_SCRATCH_REQUEST;

typedef struct  {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	POOLID		pool_id;
	DRIVEID		drive_id;
	VOLID		vol_id;
} MOUNT_SCRATCH_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	VOLID		vol_id;
	DRIVEID		drive_id;
} DISMOUNT_REQUEST;

typedef struct  {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} DISMOUNT_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	TYPE		type;
	unsigned short		count;
	union {
		VOLID		vol_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
	} identifier;
} LOCK_REQUEST;

typedef LOCK_REQUEST		CLEAR_LOCK_REQUEST;
typedef LOCK_REQUEST		QUERY_LOCK_REQUEST;
typedef LOCK_REQUEST		UNLOCK_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		LO_VOL_STATUS		volume_status[MAX_ID];
		LO_DRV_STATUS		drive_status[MAX_ID];
	} identifier_status;
} LOCK_RESPONSE;

typedef LOCK_RESPONSE		CLEAR_LOCK_RESPONSE;
typedef LOCK_RESPONSE		UNLOCK_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	TYPE		type;
	union {
		QU_ACS_CRITERIA		acs_criteria;
		QU_LSM_CRITERIA		lsm_criteria;
		QU_CAP_CRITERIA		cap_criteria;
		QU_DRV_CRITERIA		drive_criteria;
		QU_VOL_CRITERIA		vol_criteria;
		QU_REQ_CRITERIA		request_criteria;
		QU_PRT_CRITERIA		port_criteria;
		QU_POL_CRITERIA		pool_criteria;
		QU_MSC_CRITERIA 	mount_scratch_criteria;
		QU_LMU_CRITERIA		lmu_criteria;
		QU_DRG_CRITERIA		drive_group_criteria;
		QU_SPN_CRITERIA		subpl_name_criteria;
		QU_MSC_PINFO_CRITERIA		mount_scratch_pinfo_criteria;
	} select_criteria;
} QUERY_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	union {
		QU_SRV_RESPONSE		server_response;
		QU_ACS_RESPONSE		acs_response;
		QU_LSM_RESPONSE		lsm_response;
		QU_CAP_RESPONSE		cap_response;
		QU_CLN_RESPONSE		clean_volume_response;
		QU_DRV_RESPONSE		drive_response;
		QU_MNT_RESPONSE		mount_response;
		QU_VOL_RESPONSE		volume_response;
		QU_PRT_RESPONSE		port_response;
		QU_REQ_RESPONSE		request_response;
		QU_SCR_RESPONSE		scratch_response;
		QU_POL_RESPONSE		pool_response;
		QU_MSC_RESPONSE		mount_scratch_response;
		QU_MMI_RESPONSE		mm_info_response;
		QU_LMU_RESPONSE		lmu_response;
		QU_DRG_RESPONSE		drive_group_response;
		QU_SPN_RESPONSE		subpl_name_response;
	} status_response;
} QUERY_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		QL_VOL_STATUS		volume_status[MAX_ID];
		QL_DRV_STATUS		drive_status[MAX_ID];
	} identifier_status;
} QUERY_LOCK_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
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
} VARY_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {
		VA_ACS_STATUS		acs_status[MAX_ID];
		VA_LSM_STATUS		lsm_status[MAX_ID];
		VA_DRV_STATUS		drive_status[MAX_ID];
		VA_PRT_STATUS		port_status[MAX_ID];
		VA_CAP_STATUS		cap_status[MAX_ID];
	} device_status;
} VARY_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	CAPID		cap_id;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
} VENTER_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	unsigned long		low_water_mark;
	unsigned long		high_water_mark;
	unsigned long		pool_attributes;
	unsigned short		count;
	POOLID		pool_id[MAX_ID];
} DEFINE_POOL_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS message_status;
	unsigned long		low_water_mark;
	unsigned long		high_water_mark;
	unsigned long		pool_attributes;
	unsigned short		count;
	struct {
		POOLID		pool_id;
		RESPONSE_STATUS status;
	} pool_status[MAX_ID];
} DEFINE_POOL_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	unsigned short		count;
	POOLID		pool_id[MAX_ID];
} DELETE_POOL_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS message_status;
	unsigned short		count;
	struct {
		POOLID		pool_id;
		RESPONSE_STATUS status;
	} pool_status[MAX_ID];
} DELETE_POOL_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	CAP_PRIORITY		cap_priority;
	CAP_MODE		cap_mode;
	unsigned short		count;
	CAPID		cap_id[MAX_ID];
} SET_CAP_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS message_status;
	CAP_PRIORITY		cap_priority;
	CAP_MODE		cap_mode;
	unsigned short		count;
	struct {
		CAPID		cap_id;
		RESPONSE_STATUS status;
	} set_cap_status[MAX_ID];
} SET_CAP_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	unsigned short		max_use;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} SET_CLEAN_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS message_status;
	unsigned short		max_use;
	unsigned short		count;
	struct {
		VOLID		vol_id;
		RESPONSE_STATUS status;
	} volume_status[MAX_ID];
} SET_CLEAN_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	USERID		owner_id;
	TYPE		type;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} SET_OWNER_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS message_status;
	USERID		owner_id;
	TYPE		type;
	unsigned short		count;
	struct {
		VOLID		vol_id;
		RESPONSE_STATUS status;
	} volume_status[MAX_ID];
} SET_OWNER_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	POOLID		pool_id;
	unsigned short		count;
	VOLRANGE		vol_range[MAX_ID];
} SET_SCRATCH_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS message_status;
	POOLID		pool_id;
	unsigned short		count;
	struct {
		VOLID		vol_id;
		RESPONSE_STATUS status;
	} scratch_status[MAX_ID];
} SET_SCRATCH_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	MESSAGE_ID		request;
} CANCEL_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		request;
} CANCEL_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
} START_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
} START_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
} IDLE_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
} IDLE_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
} INIT_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		lmu_id[MAX_ID];
	} identifier;
} SWITCH_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		SW_LMU_STATUS		lmu_status[MAX_ID];
	} device_status;
} SWITCH_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	TYPE		request_type;

	VOLID		vol_id;
	TYPE		location_type;
	union {
		CELLID		cell_id;
		DRIVEID		drive_id;
	} location;
	char		file_name[25];
	char		routine_name[25];
} RCVY_REQUEST;

typedef struct  {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLUME_STATUS		volume_status;
} RCVY_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	REGISTRATION_ID		registration_id;
	unsigned short		count;
	EVENT_CLASS_TYPE		eventClass[MAX_ID];
} REGISTER_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	EVENT_REPLY_TYPE		event_reply_type;
	EVENT_SEQUENCE		event_sequence;
	union {
		EVENT_RESOURCE_STATUS		event_resource_status;
		EVENT_REGISTER_STATUS		event_register_status;
		EVENT_VOLUME_STATUS		event_volume_status;
		EVENT_DRIVE_STATUS		event_drive_status;
	} event;
} REGISTER_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	REGISTRATION_ID		registration_id;
	unsigned short		count;
	EVENT_CLASS_TYPE		eventClass[MAX_ID];
} UNREGISTER_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	EVENT_REGISTER_STATUS		event_register_status;
} UNREGISTER_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	REGISTRATION_ID		registration_id;
} CHECK_REGISTRATION_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	EVENT_REGISTER_STATUS		event_register_status;
} CHECK_REGISTRATION_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	TYPE		display_type;
	DISPLAY_XML_DATA		display_xml_data;
} DISPLAY_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		display_type;
	DISPLAY_XML_DATA		display_xml_data;
} DISPLAY_RESPONSE;

typedef struct {
	REQUEST_HEADER		request_header;
	VOLID		vol_id;
	POOLID		pool_id;
	MGMT_CLAS	mgmt_clas;
	MEDIA_TYPE	media_type;
	JOB_NAME	job_name;
	DATASET_NAME	dataset_name;
	STEP_NAME	step_name;
	DRIVEID		drive_id;
} MOUNT_PINFO_REQUEST;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	POOLID		pool_id;
	DRIVEID		drive_id;
	VOLID		vol_id;
} MOUNT_PINFO_RESPONSE;
#endif /* _LM_STRUCTS_API_ */
