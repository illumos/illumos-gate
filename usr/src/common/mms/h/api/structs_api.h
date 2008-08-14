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




#ifndef _STRUCTS_API_
#define	_STRUCTS_API_

#include "db_structs.h"
#include "defs.h"
#define	QU_MAX_DRV_STATUS		165

#define	MAX_VTD_MAP		490

typedef struct {
	unsigned short		packet_id;
	COMMAND		command;
	unsigned char		message_options;
	VERSION		version;
	unsigned long		extended_options;
	LOCKID		lock_id;
	ACCESSID		access_id;
	unsigned char		reserved[16];
} MESSAGE_HEADER;

typedef struct {
	STATUS		status;
	TYPE		type;
	IDENTIFIER		identifier;
} RESPONSE_STATUS;

typedef struct {
	VOLID		vol_id;
	RESPONSE_STATUS status;
} VOLUME_STATUS;

typedef struct {
	ACS		acs_id;
	RESPONSE_STATUS status;
} AU_ACS_STATUS;

typedef struct {
	LSMID		lsm_id;
	RESPONSE_STATUS status;
} AU_LSM_STATUS;

typedef struct {
	PANELID		panel_id;
	RESPONSE_STATUS status;
} AU_PNL_STATUS;

typedef struct {
	SUBPANELID		subpanel_id;
	RESPONSE_STATUS status;
} AU_SUB_STATUS;

typedef struct {
	VOLID		vol_id;
	RESPONSE_STATUS status;
} LO_VOL_STATUS;

typedef struct {
	DRIVEID		drive_id;
	RESPONSE_STATUS status;
} LO_DRV_STATUS;

typedef enum {
	AUDIT = 0,
	MOUNT,
	DISMOUNT,
	ENTER,
	EJECT,
	MAX_COMMANDS
} QU_COMMANDS;

typedef enum {
	CURRENT = 0,
	PENDING,
	MAX_DISPOSITIONS
} QU_DISPOSITIONS;

typedef struct {
	MESSAGE_ID		requests[MAX_COMMANDS][MAX_DISPOSITIONS];
} REQ_SUMMARY;

typedef struct {
	unsigned short		acs_count;
	ACS		acs_id[MAX_ID];
} QU_ACS_CRITERIA;

typedef struct {
	unsigned short		lsm_count;
	LSMID		lsm_id[MAX_ID];
} QU_LSM_CRITERIA;

typedef struct {
	unsigned short		cap_count;
	CAPID		cap_id[MAX_ID];
} QU_CAP_CRITERIA;

typedef struct {
	unsigned short		drive_count;
	DRIVEID		drive_id[MAX_ID];
} QU_DRV_CRITERIA;

typedef struct {
	GROUP_TYPE		group_type;
	unsigned short		drg_count;
	GROUPID		group_id[MAX_DRG];
} QU_DRG_CRITERIA;

typedef struct {
	unsigned short		volume_count;
	VOLID		volume_id[MAX_ID];
} QU_VOL_CRITERIA;

typedef struct {
	unsigned short		request_count;
	MESSAGE_ID		request_id[MAX_ID];
} QU_REQ_CRITERIA;

typedef struct {
	unsigned short		port_count;
	PORTID		port_id[MAX_ID];
} QU_PRT_CRITERIA;

typedef struct {
	unsigned short		pool_count;
	POOLID		pool_id[MAX_ID];
} QU_POL_CRITERIA;

typedef struct {
	MEDIA_TYPE		media_type;
	unsigned short		pool_count;
	POOLID		pool_id[MAX_ID];
} QU_MSC_CRITERIA;

typedef struct {
	MEDIA_TYPE		media_type;
	unsigned short		pool_count;
	POOLID		pool_id[MAX_ID];
	MGMT_CLAS		mgmt_clas;
} QU_MSC_PINFO_CRITERIA;

typedef struct {
	unsigned short		lmu_count;
	ACS		lmu_id[MAX_ID];
} QU_LMU_CRITERIA;

typedef struct {
	unsigned short	spn_count;
	SUBPOOL_NAME	subpl_name[MAX_SPN];
} QU_SPN_CRITERIA;

typedef struct {
	ACS		acs_id;
	STATE		state;
	FREECELLS		freecells;
	REQ_SUMMARY		requests;
	STATUS		status;
} QU_ACS_STATUS;

typedef struct {
	VOLID		vol_id;
	MEDIA_TYPE	    media_type;
	CELLID		home_location;
	unsigned short		max_use;
	unsigned short		current_use;
	STATUS		status;
} QU_CLN_STATUS;

typedef struct {
	CAPID		cap_id;
	STATUS		status;
	CAP_PRIORITY		cap_priority;
	unsigned short		cap_size;
	STATE		cap_state;
	CAP_MODE		cap_mode;
} QU_CAP_STATUS;

typedef struct {
	DRIVEID		drive_id;
	VOLID		vol_id;
	DRIVE_TYPE	    drive_type;
	STATE		state;
	STATUS		status;
} QU_DRV_STATUS;

typedef struct {
	VOLID		vol_id;
	STATE		state;
	STATUS		status;
	DRIVEID		drive_id;
} QU_VIRT_DRV_STATUS;

typedef struct {
	DRIVEID		drive_id;
	unsigned short		drive_addr;
} QU_VIRT_DRV_MAP;

typedef struct {
	LSMID		lsm_id;
	STATE		state;
	FREECELLS		freecells;
	REQ_SUMMARY		requests;
	STATUS		status;
} QU_LSM_STATUS;

typedef struct {
	VOLID		vol_id;
	STATUS		status;
	unsigned short		drive_count;
	QU_DRV_STATUS		drive_status[QU_MAX_DRV_STATUS];
} QU_MNT_STATUS;

typedef struct {
	PORTID		port_id;
	STATE		state;
	STATUS		status;
} QU_PRT_STATUS;

typedef struct {
	MESSAGE_ID		request;
	COMMAND		command;
	STATUS		status;
} QU_REQ_STATUS;

typedef struct {
	STATE		state;
	FREECELLS		freecells;
	REQ_SUMMARY		requests;
} QU_SRV_STATUS;

typedef struct {
	VOLID		vol_id;
	MEDIA_TYPE	    media_type;
	LOCATION		location_type;
	union {
		CELLID		cell_id;
		DRIVEID		drive_id;
	} location;
	STATUS		status;
} QU_VOL_STATUS;

typedef struct {
	VOLID		vol_id;
	MEDIA_TYPE	    media_type;
	CELLID		home_location;
	POOLID		pool_id;
	STATUS		status;
} QU_SCR_STATUS;

typedef struct {
	POOLID		pool_id;
	unsigned long		volume_count;
	unsigned long		low_water_mark;
	unsigned long		high_water_mark;
	unsigned long		pool_attributes;
	STATUS		status;
} QU_POL_STATUS;

typedef struct {
	SUBPOOL_NAME		subpool_name;
	POOLID		pool_id;
	STATUS		status;
} QU_SUBPOOL_NAME_STATUS;

typedef struct {
	POOLID		pool_id;
	STATUS		status;
	unsigned short		drive_count;
	QU_DRV_STATUS		drive_list[QU_MAX_DRV_STATUS];
} QU_MSC_STATUS;

typedef struct {
	MEDIA_TYPE		media_type;
	char		media_type_name[MEDIA_TYPE_NAME_LEN + 1];
	CLN_CART_CAPABILITY		cleaning_cartridge;
	int		max_cleaning_usage;
	unsigned short		compat_count;
	DRIVE_TYPE		compat_drive_types[MM_MAX_COMPAT_TYPES];
} QU_MEDIA_TYPE_STATUS;

typedef struct {
	DRIVE_TYPE		drive_type;
	char		drive_type_name[DRIVE_TYPE_NAME_LEN + 1];
	unsigned short		compat_count;
	MEDIA_TYPE		compat_media_types[MM_MAX_COMPAT_TYPES];
} QU_DRIVE_TYPE_STATUS;

typedef struct {
	QU_SRV_STATUS		server_status;
} QU_SRV_RESPONSE;

typedef struct {
	unsigned short		acs_count;
	QU_ACS_STATUS		acs_status[MAX_ID];
} QU_ACS_RESPONSE;

typedef struct {
	unsigned short		lsm_count;
	QU_LSM_STATUS		lsm_status[MAX_ID];
} QU_LSM_RESPONSE;

typedef struct {
	unsigned short		cap_count;
	QU_CAP_STATUS		cap_status[MAX_ID];
} QU_CAP_RESPONSE;

typedef struct {
	unsigned short		volume_count;
	QU_CLN_STATUS		clean_volume_status[MAX_ID];
} QU_CLN_RESPONSE;

typedef struct {
	unsigned short		drive_count;
	QU_DRV_STATUS		drive_status[MAX_ID];
} QU_DRV_RESPONSE;

typedef struct {
	GROUPID		group_id;
	GROUP_TYPE		group_type;
	unsigned short		vir_drv_map_count;
	QU_VIRT_DRV_MAP virt_drv_map[MAX_VTD_MAP];
} QU_DRG_RESPONSE;

typedef struct {
	unsigned short		mount_status_count;
	QU_MNT_STATUS		mount_status[MAX_ID];
} QU_MNT_RESPONSE;

typedef struct {
	unsigned short		volume_count;
	QU_VOL_STATUS		volume_status[MAX_ID];
} QU_VOL_RESPONSE;

typedef struct {
	unsigned short		port_count;
	QU_PRT_STATUS		port_status[MAX_ID];
} QU_PRT_RESPONSE;

typedef struct {
	unsigned short		request_count;
	QU_REQ_STATUS		request_status[MAX_ID];
} QU_REQ_RESPONSE;

typedef struct {
	unsigned short		volume_count;
	QU_SCR_STATUS		scratch_status[MAX_ID];
} QU_SCR_RESPONSE;

typedef struct {
	unsigned short		pool_count;
	QU_POL_STATUS		pool_status[MAX_ID];
} QU_POL_RESPONSE;

typedef struct {
	unsigned short		spn_status_count;
	QU_SUBPOOL_NAME_STATUS subpl_name_status[MAX_ID];
} QU_SPN_RESPONSE;

typedef struct {
	unsigned short		msc_status_count;
	QU_MSC_STATUS		mount_scratch_status[MAX_ID];
} QU_MSC_RESPONSE;

typedef struct {
	unsigned short		media_type_count;
	QU_MEDIA_TYPE_STATUS		media_type_status[MAX_ID];
	unsigned short		drive_type_count;
	QU_DRIVE_TYPE_STATUS		drive_type_status[MAX_ID];
} QU_MMI_RESPONSE;

typedef struct {
	VOLID		vol_id;
	LOCKID		lock_id;
	unsigned long		lock_duration;
	unsigned int		locks_pending;
	USERID		user_id;
	STATUS		status;
} QL_VOL_STATUS;

typedef struct {
	DRIVEID		drive_id;
	LOCKID		lock_id;
	unsigned long		lock_duration;
	unsigned int		locks_pending;
	USERID		user_id;
	STATUS		status;
} QL_DRV_STATUS;

typedef struct {
	ACS		acs_id;
	RESPONSE_STATUS status;
} VA_ACS_STATUS;

typedef struct {
	DRIVEID		drive_id;
	RESPONSE_STATUS status;
} VA_DRV_STATUS;

typedef struct {
	LSMID		lsm_id;
	RESPONSE_STATUS status;
} VA_LSM_STATUS;

typedef struct {
	CAPID		cap_id;
	RESPONSE_STATUS status;
} VA_CAP_STATUS;

typedef struct {
	PORTID		port_id;
	RESPONSE_STATUS status;
} VA_PRT_STATUS;

typedef struct {
	PORT_RECORD		prt_record;
	ROLE		role;
	int		compat_level;
	STATE		lmu_port_diag;
} LMU_PORT_RECORD;

typedef struct {
	STATUS		status;
	ACS		acs_id;
	STATE		state;
	int		prt_count;
	STATUS		standby_status;
	STATUS		master_status;
	MODE		mode;
	LMU_PORT_RECORD lmu_record[MAX_PORTS];
} QU_LMU_STATUS;

typedef struct {
	unsigned short		lmu_count;
	QU_LMU_STATUS		lmu_status[MAX_ID];
} QU_LMU_RESPONSE;

typedef struct {
	STATUS		status;
	ACS		lmu_id;
} SW_LMU_STATUS;


#define	MAX_XML_DATA_SIZE (MAX_MESSAGE_SIZE-                   \
	(                          \
	(sizeof (IPC_HEADER) +4) \
	+ sizeof (MESSAGE_HEADER) \
	+ (sizeof (STATUS)        \
	+ sizeof (TYPE)           \
	+ sizeof (IDENTIFIER))    \
	+ sizeof (TYPE)           \
	+ sizeof (unsigned short)))

typedef struct {
	unsigned short		length;
	char		xml_data[MAX_XML_DATA_SIZE];
} DISPLAY_XML_DATA;

#endif /* _STRUCTS_API_ */
