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


#ifndef _CSI_V0_STRUCTS_
#define	_CSI_V0_STRUCTS_

#ifndef _CSI_HEADER_
#include "csi_header.h"
#endif

#ifndef _V0_STRUCTS_
#include "v0_structs.h"
#endif


typedef struct {
	CSI_HEADER		csi_header;
	V0_MESSAGE_HEADER		message_header;
} CSI_V0_REQUEST_HEADER;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		message_id;
} CSI_V0_ACKNOWLEDGE_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	V0_CAPID		cap_id;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		PANELID		panel_id[MAX_ID];
		SUBPANELID		subpanel_id[MAX_ID];
	} identifier;
} CSI_V0_AUDIT_REQUEST;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
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
} CSI_V0_AUDIT_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
	V0_CAPID		cap_id;
	unsigned short		count;
	VOLUME_STATUS		volume_status[MAX_ID];
} CSI_V0_EJECT_ENTER;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	V0_CAPID		cap_id;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
} CSI_V0_EJECT_REQUEST;

typedef CSI_V0_EJECT_ENTER		CSI_V0_EJECT_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	V0_CAPID		cap_id;
} CSI_V0_ENTER_REQUEST;

typedef CSI_V0_EJECT_ENTER		CSI_V0_ENTER_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	VOLID		vol_id;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
} CSI_V0_MOUNT_REQUEST;

typedef struct  {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} CSI_V0_MOUNT_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	VOLID		vol_id;
	DRIVEID		drive_id;
} CSI_V0_DISMOUNT_REQUEST;

typedef struct  {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} CSI_V0_DISMOUNT_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
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
} CSI_V0_QUERY_REQUEST;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
	TYPE		type;
	unsigned short		count;
	union {
		QU_SRV_STATUS		server_status[MAX_ID];
		QU_ACS_STATUS		acs_status[MAX_ID];
		QU_LSM_STATUS		lsm_status[MAX_ID];
		V0_QU_CAP_STATUS		cap_status[MAX_ID];
		V0_QU_DRV_STATUS		drive_status[MAX_ID];
		V0_QU_MNT_STATUS		mount_status[MAX_ID];
		V0_QU_VOL_STATUS		volume_status[MAX_ID];
		QU_PRT_STATUS		port_status[MAX_ID];
		QU_REQ_STATUS		request_status[MAX_ID];
	} status_response;
} CSI_V0_QUERY_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	STATE		state;
	TYPE		type;
	unsigned short		count;
	union {
		ACS		acs_id[MAX_ID];
		LSMID		lsm_id[MAX_ID];
		DRIVEID		drive_id[MAX_ID];
		PORTID		port_id[MAX_ID];
	} identifier;
} CSI_V0_VARY_REQUEST;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
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
} CSI_V0_VARY_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	MESSAGE_ID		request;
} CSI_V0_CANCEL_REQUEST;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
	MESSAGE_ID		request;
} CSI_V0_CANCEL_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
} CSI_V0_START_REQUEST;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
} CSI_V0_START_RESPONSE;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
} CSI_V0_IDLE_REQUEST;

typedef struct {
	CSI_V0_REQUEST_HEADER		csi_request_header;
	RESPONSE_STATUS		message_status;
} CSI_V0_IDLE_RESPONSE;


#endif /* _CSI_V0_STRUCTS_ */
