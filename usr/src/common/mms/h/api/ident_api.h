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


#ifndef _IDENT_API_H_
#define	_IDENT_API_H_
#define	IDENTIFIER_SIZE		64
#define	REGISTRATION_ID_SIZE		32

typedef struct {
	ACS		acs;
	LSM		lsm;
} LSMID;

typedef LSMID		V0_CAPID;
typedef LSMID		V1_CAPID;

typedef struct {
	LSMID		lsm_id;
	CAP		cap;
} CAPID;

typedef struct {
	ACS		acs;
	PORT		port;
} PORTID;

typedef struct {
	LSMID		lsm_id;
	PANEL		panel;
} PANELID;

typedef struct {
	ACS		acs;
	LSM		master_lsm;
	PANEL		master_panel;
	LSM		slave_lsm;
	PANEL		slave_panel;
} PTPID;

typedef struct {
	PANELID		panel_id;
	ROW		begin_row;
	COL		begin_col;
	ROW		end_row;
	COL		end_col;
} SUBPANELID;

typedef struct {
	PANELID		panel_id;
	DRIVE		drive;
} DRIVEID;

typedef struct {
	PANELID		panel_id;
	ROW		row;
	COL		col;
} CELLID;

typedef struct {
	char		external_label[EXTERNAL_LABEL_SIZE + 1];
} VOLID;

typedef struct {
	POOL		pool;
} POOLID;

typedef struct {
	VOLID		startvol;
	VOLID		endvol;
} VOLRANGE;

typedef struct {
	PANEL		panel;
	DRIVE		drive;
} VIRTUAL_TAPE_DRIVE;


typedef struct {
	ACS		acs;
	LSM		lsm;
	VIRTUAL_TAPE_DRIVE vtd;
} VTDID;

typedef struct {
	char		mgmt_clas[MGMT_CLAS_SIZE + 1];
} MGMT_CLAS;

typedef struct {
	char		subpool_name[SUBPOOL_NAME_SIZE + 1];
} SUBPOOL_NAME;

typedef struct {
	char		job_name[JOB_NAME_SIZE + 1];
} JOB_NAME;

typedef struct {
	char		step_name[STEP_NAME_SIZE + 1];
} STEP_NAME;

typedef struct {
	char		dataset_name[DATASET_NAME_SIZE + 1];
} DATASET_NAME;

typedef struct {
	char		groupid[GROUPID_SIZE + 1];
} GROUPID;


typedef struct {
	char		registration[REGISTRATION_ID_SIZE + 1];
} REGISTRATION_ID;

typedef enum {
	EVENT_REGISTER_FIRST = 0,
	EVENT_REGISTER_REGISTERED,
	EVENT_REGISTER_UNREGISTERED,
	EVENT_REGISTER_INVALID_CLASS,
	EVENT_REGISTER_LAST
} EVENT_CLASS_REGISTER_RETURN;

typedef struct {
	EVENT_CLASS_TYPE		event_class;
	EVENT_CLASS_REGISTER_RETURN		register_return;
} REGISTER_STATUS;

typedef enum {
	VOL_FIRST = 0,
	VOL_ENTERED,
	VOL_ADDED,
	VOL_REACTIVATED,
	VOL_EJECTED,
	VOL_DELETED,
	VOL_MARKED_ABSENT,
	VOL_OVER_MAX_CLEAN,
	VOL_CLEAN_CART_SPENT,
	VOL_HOME_LSM_CHG,
	VOL_OWNER_CHG,
	VOL_LAST
} VOL_EVENT_TYPE;

typedef struct {
	VOL_EVENT_TYPE		event_type;
	VOLID		vol_id;
} EVENT_VOLUME_STATUS;

typedef struct {
	PANELID		panel_id;
	HAND		hand;
} HANDID;

#define	ALIGNMENT_PAD_SIZE		32

typedef union {
	ACS		acs_id;
	V0_CAPID		v0_cap_id;
	V1_CAPID		v1_cap_id;
	CAPID		cap_id;
	CELLID		cell_id;
	DRIVEID		drive_id;
	LSMID		lsm_id;
	PANELID		panel_id;
	PORTID		port_id;
	SUBPANELID		subpanel_id;
	VOLID		vol_id;
	POOLID		pool_id;
	LOCKID		lock_id;
	char		socket_name[SOCKET_NAME_SIZE];
	long		request;
	short		lh_error;
	MEDIA_TYPE		media_type;
	DRIVE_TYPE		drive_type;
	HANDID		hand_id;
	PTPID		ptp_id;
	VTDID		vtd_id;
	SUBPOOL_NAME		subpool_name;
	MGMT_CLAS		mgmt_clas;
	JOB_NAME		job_name;
	STEP_NAME		step_name;
	GROUPID		groupid;
	char		alignment_size[ALIGNMENT_PAD_SIZE];
} IDENTIFIER;

typedef enum {
	SENSE_TYPE_FIRST = 0,
	SENSE_TYPE_NONE,
	SENSE_TYPE_HLI,
	SENSE_TYPE_SCSI,
	SENSE_TYPE_FSC,
	RESOURCE_CHANGE_SERIAL_NUM,
	RESOURCE_CHANGE_LSM_TYPE,
	RESOURCE_CHANGE_DRIVE_TYPE,
	DRIVE_ACTIVITY_DATA_TYPE,
	SENSE_TYPE_LAST
} RESOURCE_DATA_TYPE;

typedef struct {
	long		start_time;
	long		completion_time;
	VOLID		vol_id;
	VOLUME_TYPE		volume_type;
	DRIVEID		drive_id;
	POOLID		pool_id;
	CELLID		home_location;
} DRIVE_ACTIVITY_DATA;

typedef union {
	SENSE_HLI		sense_hli;
	SENSE_SCSI		sense_scsi;
	SENSE_FSC		sense_fsc;
	SERIAL_NUM		serial_num;
	LSM_TYPE		lsm_type;
	DRIVE_TYPE		drive_type;
	DRIVE_ACTIVITY_DATA		drive_activity_data;
	char		resource_align_pad[RESOURCE_ALIGN_PAD_SIZE];
} RESOURCE_DATA;

typedef struct {
	TYPE		resource_type;
	IDENTIFIER		resource_identifier;
	RESOURCE_EVENT		resource_event;
	RESOURCE_DATA_TYPE		resource_data_type;
	RESOURCE_DATA		resource_data;
} EVENT_RESOURCE_STATUS;

typedef struct {
	TYPE		event_type;
	RESOURCE_DATA_TYPE		resource_data_type;
	RESOURCE_DATA		resource_data;
} EVENT_DRIVE_STATUS;

#define	MAX_EVENT_CLASS_TYPE 3

typedef struct {
	REGISTRATION_ID		registration_id;
	unsigned short		count;
	REGISTER_STATUS		register_status[MAX_EVENT_CLASS_TYPE];
} EVENT_REGISTER_STATUS;

#define	EVENT_ALIGN_PAD_SIZE		128

typedef union {
	EVENT_REGISTER_STATUS		event_register_status;
	EVENT_VOLUME_STATUS		event_volume_status;
	EVENT_RESOURCE_STATUS		event_resource_status;
	EVENT_DRIVE_STATUS		event_drive_status;
	char		event_align_pad[EVENT_ALIGN_PAD_SIZE];
} EVENT;

#endif /* _IDENT_API_H_ */
