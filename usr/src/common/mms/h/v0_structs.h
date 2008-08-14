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



#ifndef _V0_STRUCTS_
#define	_V0_STRUCTS_
#ifndef _STRUCTS_
#include "structs.h"
#endif

#define	V0_MAX_ACS_DRIVES		128

typedef struct {
	unsigned short		packet_id;
	COMMAND		command;
	unsigned char		message_options;
} V0_MESSAGE_HEADER;

typedef struct {
	IPC_HEADER		ipc_header;
	V0_MESSAGE_HEADER		message_header;
} V0_REQUEST_HEADER;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		message_id;
} V0_ACKNOWLEDGE_RESPONSE;


typedef struct {
	V0_REQUEST_HEADER		request_header;
	V0_CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		PANELID		panel_id[MAX_ID];
		SUBPANELID		subpanel_id[MAX_ID];
	} identifier;
} V0_AUDIT_REQUEST;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	V0_CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		AU_ACS_STATUS		acs_status[MAX_ID];
		AU_LSM_STATUS		lsm_status[MAX_ID];
		AU_PNL_STATUS		panel_status[MAX_ID];
		AU_SUB_STATUS		subpanel_status[MAX_ID];
	} identifier_status;
} V0_AUDIT_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	V0_CAPID		cap_id;
	unsigned short		count;
	VOLUME_STATUS		volume_status[MAX_ID];
} V0_EJECT_ENTER;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	V0_CAPID		cap_id;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
} V0_EJECT_REQUEST;

typedef V0_EJECT_ENTER V0_EJECT_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	V0_CAPID		cap_id;
} V0_ENTER_REQUEST;

typedef V0_EJECT_ENTER V0_ENTER_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	VOLID		vol_id;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} V0_MOUNT_REQUEST;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V0_MOUNT_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V0_DISMOUNT_REQUEST;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} V0_DISMOUNT_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		V0_CAPID		cap_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
		VOLID		vol_id[MAX_ID];
		MESSAGE_ID		request[MAX_ID];
		PORTID		port_id[MAX_ID];
	} identifier;
} V0_QUERY_REQUEST;

typedef struct {
	V0_CAPID		cap_id;
	STATUS		status;
} V0_QU_CAP_STATUS;

typedef struct {
	DRIVEID		drive_id;
	STATE		state;
	VOLID		vol_id;
	STATUS		status;
} V0_QU_DRV_STATUS;

typedef struct {
	VOLID		vol_id;
	STATUS		status;
	unsigned short		drive_count;
	V0_QU_DRV_STATUS drive_status[V0_MAX_ACS_DRIVES];

} V0_QU_MNT_STATUS;

typedef struct {
	VOLID		vol_id;
	LOCATION		location_type;
	union {
		CELLID		cell_id;
		DRIVEID		drive_id;
	} location;
	STATUS		status;
} V0_QU_VOL_STATUS;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		QU_SRV_STATUS		server_status[MAX_ID];
		QU_ACS_STATUS		acs_status[MAX_ID];
		QU_LSM_STATUS		lsm_status[MAX_ID];
		V0_QU_CAP_STATUS cap_status[MAX_ID];
		V0_QU_DRV_STATUS drive_status[MAX_ID];
		V0_QU_MNT_STATUS mount_status[MAX_ID];
		V0_QU_VOL_STATUS volume_status[MAX_ID];
		QU_PRT_STATUS		port_status[MAX_ID];
		QU_REQ_STATUS		request_status[MAX_ID];
	} status_response;
} V0_QUERY_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
		PORTID		port_id[MAX_ID];
	} identifier;
} V0_VARY_REQUEST;

typedef struct {
	V0_REQUEST_HEADER		request_header;
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
} V0_VARY_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	MESSAGE_ID		request;
} V0_CANCEL_REQUEST;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		request;
} V0_CANCEL_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
} V0_START_REQUEST;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
} V0_START_RESPONSE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
} V0_IDLE_REQUEST;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		message_status;
} V0_IDLE_RESPONSE;

typedef union {
	V0_REQUEST_HEADER		generic_request;
	V0_AUDIT_REQUEST		audit_request;
	V0_ENTER_REQUEST		enter_request;
	V0_EJECT_REQUEST		eject_request;
	V0_VARY_REQUEST		vary_request;
	V0_MOUNT_REQUEST		mount_request;
	V0_DISMOUNT_REQUEST dismount_request;
	V0_QUERY_REQUEST		query_request;
	V0_CANCEL_REQUEST		cancel_request;
	V0_START_REQUEST		start_request;
	V0_IDLE_REQUEST		idle_request;
} V0_REQUEST_TYPE;

typedef struct {
	V0_REQUEST_HEADER		request_header;
	RESPONSE_STATUS		response_status;
} V0_RESPONSE_HEADER;

typedef union {
	V0_RESPONSE_HEADER		generic_response;
	V0_ACKNOWLEDGE_RESPONSE acknowledge_response;
	V0_AUDIT_RESPONSE		audit_response;
	V0_ENTER_RESPONSE		enter_response;
	V0_EJECT_RESPONSE		eject_response;
	V0_VARY_RESPONSE		vary_response;
	V0_MOUNT_RESPONSE		mount_response;
	V0_DISMOUNT_RESPONSE		dismount_response;
	V0_QUERY_RESPONSE		query_response;
	V0_CANCEL_RESPONSE		cancel_response;
	V0_START_RESPONSE		start_response;
	V0_IDLE_RESPONSE		idle_response;
} V0_RESPONSE_TYPE;

#endif /* _V0_STRUCTS_ */
