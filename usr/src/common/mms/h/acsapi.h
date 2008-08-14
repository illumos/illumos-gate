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


#ifndef _ACSAPI_H_
#define	_ACSAPI_H_

#ifndef _ACSSYS_H_

#endif

#include "inclds.h"

#include "apidef.h"
#include "apipro.h"


typedef struct {
	DRIVEID		drive_id;
	STATUS		status;
	DRIVEID		dlocked_drive_id;
} ACS_LO_DRV_STATUS;

typedef struct {
	VOLID		vol_id;
	STATUS		status;
	VOLID		dlocked_vol_id;
} ACS_LO_VOL_STATUS;

typedef struct {
	STATUS		audit_int_status;
	CAPID		cap_id;
	unsigned short	count;
	VOLID		vol_id[MAX_ID];
	STATUS		vol_status[MAX_ID];
} ACS_AUDIT_INT_RESPONSE;


typedef struct {
	STATUS		audit_acs_status;
	unsigned short	count;
	ACS		acs[MAX_ID];
	STATUS		acs_status[MAX_ID];
} ACS_AUDIT_ACS_RESPONSE;

typedef struct {
	STATUS		audit_lsm_status;
	unsigned short	count;
	LSMID		lsm_id[MAX_ID];
	STATUS		lsm_status[MAX_ID];
} ACS_AUDIT_LSM_RESPONSE;

typedef struct {
	STATUS		audit_pnl_status;
	unsigned short	count;
	PANELID		panel_id[MAX_ID];
	STATUS		panel_status[MAX_ID];
} ACS_AUDIT_PNL_RESPONSE;

typedef struct {
	STATUS		audit_sub_status;
	unsigned short	count;
	SUBPANELID	subpanel_id[MAX_ID];
	STATUS		subpanel_status[MAX_ID];
} ACS_AUDIT_SUB_RESPONSE;

typedef struct {
	STATUS		audit_srv_status;
} ACS_AUDIT_SRV_RESPONSE;

typedef struct {
	STATUS		cancel_status;
	REQ_ID		req_id;
} ACS_CANCEL_RESPONSE;

typedef struct {
	STATUS		idle_status;
} ACS_IDLE_RESPONSE;

typedef struct {
	STATUS		start_status;
} ACS_START_RESPONSE;

typedef struct {
	STATUS		enter_status;
	CAPID		cap_id;
	unsigned short	count;
	VOLID		vol_id[MAX_ID];
	STATUS		vol_status[MAX_ID];
} ACS_ENTER_RESPONSE;

typedef struct {
	STATUS		eject_status;
	CAPID		cap_id;
	unsigned short	count;
	CAPID		cap_used[MAX_ID];
	VOLID		vol_id[MAX_ID];
	STATUS		vol_status[MAX_ID];
} ACS_EJECT_RESPONSE;

typedef struct {
	STATUS		clear_lock_drv_status;
	unsigned short	count;
	ACS_LO_DRV_STATUS	drv_status[MAX_ID];
} ACS_CLEAR_LOCK_DRV_RESPONSE;

typedef struct {
	STATUS		clear_lock_vol_status;
	unsigned short	count;
	ACS_LO_VOL_STATUS	vol_status[MAX_ID];
} ACS_CLEAR_LOCK_VOL_RESPONSE;

typedef struct {
	STATUS		lock_drv_status;
	LOCKID		lock_id;
	unsigned short	count;
	ACS_LO_DRV_STATUS	drv_status[MAX_ID];
} ACS_LOCK_DRV_RESPONSE;

typedef struct {
	STATUS		lock_vol_status;
	LOCKID		lock_id;
	unsigned short	count;
	ACS_LO_VOL_STATUS	vol_status[MAX_ID];
} ACS_LOCK_VOL_RESPONSE;

typedef struct {
	STATUS		unlock_drv_status;
	unsigned short	count;
	ACS_LO_DRV_STATUS	drv_status[MAX_ID];
} ACS_UNLOCK_DRV_RESPONSE;

typedef struct {
	STATUS		unlock_vol_status;
	unsigned short	count;
	ACS_LO_VOL_STATUS	vol_status[MAX_ID];
} ACS_UNLOCK_VOL_RESPONSE;

typedef struct {
	STATUS		dismount_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} ACS_DISMOUNT_RESPONSE;

typedef struct {
	STATUS		mount_status;
	VOLID		vol_id;
	DRIVEID		drive_id;
} ACS_MOUNT_RESPONSE;

typedef struct {
	STATUS		mount_scratch_status;
	VOLID		vol_id;
	POOL		pool;
	DRIVEID		drive_id;
} ACS_MOUNT_SCRATCH_RESPONSE;

typedef struct {
	STATUS		query_acs_status;
	unsigned short	count;
	QU_ACS_STATUS	acs_status[MAX_ID];
} ACS_QUERY_ACS_RESPONSE;

typedef struct {
	STATUS		query_cap_status;
	unsigned short	count;
	QU_CAP_STATUS	cap_status[MAX_ID];
} ACS_QUERY_CAP_RESPONSE;

typedef struct {
	STATUS		query_cln_status;
	unsigned short		count;
	QU_CLN_STATUS		cln_status[MAX_ID];
} ACS_QUERY_CLN_RESPONSE;

typedef struct {
	STATUS		query_drv_status;
	unsigned short		count;
	QU_DRV_STATUS		drv_status[MAX_ID];
} ACS_QUERY_DRV_RESPONSE;

typedef struct {
	STATUS		query_drv_group_status;
	GROUPID		group_id;
	GROUP_TYPE		group_type;
	unsigned short		count;
	QU_VIRT_DRV_MAP virt_drv_map[MAX_VTD_MAP];
} ACS_QU_DRV_GROUP_RESPONSE;

typedef struct {
	STATUS		query_lock_drv_status;
	unsigned short		count;
	QL_DRV_STATUS		drv_status[MAX_ID];
} ACS_QUERY_LOCK_DRV_RESPONSE;

typedef struct {
	STATUS		query_lock_vol_status;
	unsigned short		count;
	QL_VOL_STATUS		vol_status[MAX_ID];
} ACS_QUERY_LOCK_VOL_RESPONSE;

typedef struct {
	STATUS		query_lsm_status;
	unsigned short		count;
	QU_LSM_STATUS		lsm_status[MAX_ID];
} ACS_QUERY_LSM_RESPONSE;

typedef struct {
	STATUS		query_mmi_status;
	QU_MMI_RESPONSE mixed_media_info_status;
} ACS_QUERY_MMI_RESPONSE;

typedef struct {
	STATUS		query_mnt_status;
	unsigned short		count;
	QU_MNT_STATUS		mnt_status[MAX_ID];
} ACS_QUERY_MNT_RESPONSE;

typedef struct {
	STATUS		query_msc_status;
	unsigned short		count;
	QU_MSC_STATUS		msc_status[MAX_ID];
} ACS_QUERY_MSC_RESPONSE;

typedef struct {
	STATUS		query_pol_status;
	unsigned short		count;
	QU_POL_STATUS		pool_status[MAX_ID];
} ACS_QUERY_POL_RESPONSE;

typedef struct {
	STATUS		query_prt_status;
	unsigned short		count;
	QU_PRT_STATUS		prt_status[MAX_ID];
} ACS_QUERY_PRT_RESPONSE;

typedef struct {
	STATUS		query_req_status;
	unsigned short		count;
	QU_REQ_STATUS		req_status[MAX_ID];
} ACS_QUERY_REQ_RESPONSE;

typedef struct {
	STATUS		query_scr_status;
	unsigned short		count;
	QU_SCR_STATUS		scr_status[MAX_ID];
} ACS_QUERY_SCR_RESPONSE;

typedef struct {
	STATUS		query_srv_status;
	unsigned short		count;
	QU_SRV_STATUS		srv_status[MAX_ID];
} ACS_QUERY_SRV_RESPONSE;

typedef struct {
	STATUS		query_subpool_name_status;
	unsigned short		count;
	QU_SUBPOOL_NAME_STATUS subpool_name_status[MAX_ID];
} ACS_QU_SUBPOOL_NAME_RESPONSE;

typedef struct {
	STATUS		query_vol_status;
	unsigned short		count;
	QU_VOL_STATUS		vol_status[MAX_ID];
} ACS_QUERY_VOL_RESPONSE;

typedef struct {
	STATUS		set_cap_status;
	CAP_PRIORITY		cap_priority;
	CAP_MODE		cap_mode;
	unsigned short		count;
	CAPID		cap_id[MAX_ID];
	STATUS		cap_status[MAX_ID];
} ACS_SET_CAP_RESPONSE;

typedef struct {
	STATUS		set_clean_status;
	unsigned short		max_use;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
	STATUS		vol_status[MAX_ID];
} ACS_SET_CLEAN_RESPONSE;

typedef struct {
	STATUS		set_scratch_status;
	POOL		pool;
	unsigned short		count;
	VOLID		vol_id[MAX_ID];
	STATUS		vol_status[MAX_ID];
} ACS_SET_SCRATCH_RESPONSE;

typedef struct {
	STATUS		define_pool_status;
	unsigned long		lwm;
	unsigned long		hwm;
	unsigned long		attributes;
	unsigned short		count;
	POOL		pool[MAX_ID];
	STATUS		pool_status[MAX_ID];
} ACS_DEFINE_POOL_RESPONSE;

typedef struct {
	STATUS		delete_pool_status;
	unsigned short		count;
	POOL		pool[MAX_ID];
	STATUS		pool_status[MAX_ID];
} ACS_DELETE_POOL_RESPONSE;

typedef struct {
	STATUS		vary_acs_status;
	STATE		acs_state;
	unsigned short		count;
	ACS		acs[MAX_ID];
	STATUS		acs_status[MAX_ID];
} ACS_VARY_ACS_RESPONSE;

typedef struct {
	STATUS		vary_cap_status;
	STATE		cap_state;
	unsigned short		count;
	CAPID		cap_id[MAX_ID];
	STATUS		cap_status[MAX_ID];
} ACS_VARY_CAP_RESPONSE;

typedef struct {
	STATUS		vary_drv_status;
	STATE		drive_state;
	unsigned short		count;
	DRIVEID		drive_id[MAX_ID];
	STATUS		drive_status[MAX_ID];
} ACS_VARY_DRV_RESPONSE;

typedef struct {
	STATUS		vary_lsm_status;
	STATE		lsm_state;
	unsigned short		count;
	LSMID		lsm_id[MAX_ID];
	STATUS		lsm_status[MAX_ID];
} ACS_VARY_LSM_RESPONSE;

typedef struct {
	STATUS		vary_prt_status;
	STATE		port_state;
	unsigned short		count;
	PORTID		port_id[MAX_ID];
	STATUS		port_status[MAX_ID];
} ACS_VARY_PRT_RESPONSE;

typedef struct {
	STATUS		register_status;
	EVENT_REPLY_TYPE event_reply_type;
	EVENT_SEQUENCE		event_sequence;
	EVENT		event;
} ACS_REGISTER_RESPONSE;

typedef struct {
	STATUS		unregister_status;
	EVENT_REGISTER_STATUS		event_register_status;
} ACS_UNREGISTER_RESPONSE;

typedef struct {
	STATUS		check_registration_status;
	EVENT_REGISTER_STATUS		event_register_status;
} ACS_CHECK_REGISTRATION_RESPONSE;

typedef struct {
	STATUS			display_status;
	TYPE		display_type;
	DISPLAY_XML_DATA		display_xml_data;
} ACS_DISPLAY_RESPONSE;

typedef struct {
	STATUS		mount_pinfo_status;
	POOLID		pool_id;
	DRIVEID		drive_id;
	VOLID		vol_id;
} ACS_MOUNT_PINFO_RESPONSE;

#endif /* _ACSAPI_H_ */
