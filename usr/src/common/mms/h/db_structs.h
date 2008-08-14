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


#ifndef _DB_STRUCTS_
#define	_DB_STRUCTS_

#ifndef _IDENTIFIER_
#include "identifier.h"
#endif

typedef struct {
	ACS		acs;
	STATE		acs_state;
} ACS_RECORD;

typedef struct {
	LSMID		lsm_id;
	STATE		lsm_state;
	STATUS		lsm_status;
	int		lsm_activity;
	PANEL		last_panel;
	ROW		last_row;
	COL		last_col;
	LSM		lsm_ptp_1;
	LSM		lsm_ptp_2;
	LSM		lsm_ptp_3;
	LSM		lsm_ptp_4;
} LSM_RECORD;

typedef struct {
	CAPID		cap_id;
	STATUS		cap_status;
	CAP_PRIORITY		cap_priority;
	STATE		cap_state;
	CAP_MODE		cap_mode;
	short		cap_size;
} CAP_RECORD;

typedef struct {
	CELLID		cell_id;
	STATUS		cell_status;
} CELL_RECORD;

typedef struct {
	DRIVEID		drive_id;
	STATUS		drive_status;
	STATE		drive_state;
	VOLID		vol_id;
	LOCKID		lock_id;
	long		lock_time;
	DRIVE_TYPE	    drive_type;
} DRIVE_RECORD;

typedef struct {
	PORTID		port_id;
	STATE		port_state;
	char		port_name[PORT_NAME_SIZE + 1];
} PORT_RECORD;

typedef struct {
	VOLID		vol_id;
	CELLID		cell_id;
	DRIVEID		drive_id;
	VOLUME_TYPE		vol_type;
	LABEL_ATTR		label_attr;
	POOLID		pool_id;
	STATUS		vol_status;
	long		entry_date;
	long		access_date;
	long		access_count;
	long		max_use;
	LOCKID		lock_id;
	long		lock_time;
	MEDIA_TYPE	    media_type;
} VOLUME_RECORD;

typedef struct {
	VOLID		vol_id;
	USERID		owner_id;
} VAC_RECORD;

typedef struct {
	POOLID		pool_id;
	long		low_water_mark;
	long		high_water_mark;
	int		pool_attributes;
} POOL_RECORD;


typedef struct {
	char		csi_name[CSI_NAME_LENGTH+1];
} CSI_RECORD;

typedef enum {
	AVT_FIRST = 0,
	AVT_FOUND,
	AVT_NORMAL,
	AVT_LAST
} AVT_STATUS;

typedef struct {
	short		audit_pid;
	VOLID		vol_id;
	AVT_STATUS		avt_status;
} AVT_RECORD;

typedef struct {
	LOCKID		lock_id;
	USERID		user_id;
} LOCKID_RECORD;

#endif /* _DB_STRUCTS_ */
