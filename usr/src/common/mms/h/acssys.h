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


#ifndef _ACSSYS_H_
#define	_ACSSYS_H_


#include <limits.h>
#ifdef AS400
#define	acs_audit_acs		ACS000
#define	acs_audit_lsm		ACS001
#define	acs_audit_panel		ACS002
#define	acs_audit_subpanel		ACS003
#define	acs_cancel		ACS004
#define	acs_clear_lock_drive		ACS005
#define	acs_clear_lock_volume		ACS006
#define	acs_command		ACS111
#define	acs_define_pool		ACS007
#define	acs_delete_pool		ACS008
#define	acs_dismount		ACS009
#define	acs_eject		ACS010
#define	acs_enter		ACS011
#define	acs_idle		ACS012
#define	acs_lock_drive		ACS013
#define	acs_lock_volume		ACS014
#define	acs_mount		ACS015
#define	acs_mount_scratch		ACS016
#define	acs_query_acs		ACS017
#define	acs_query_lsm		ACS018
#define	acs_query_clean		ACS019
#define	acs_query_drive		ACS020
#define	acs_query_lock_drive		ACS021
#define	acs_query_lock_volume		ACS022
#define	acs_query_cap		ACS023
#define	acs_query_mount		ACS024
#define	acs_query_mount_scratch		ACS025
#define	acs_query_pool		ACS026
#define	acs_query_port		ACS027
#define	acs_query_request		ACS028
#define	acs_query_scratch		ACS029
#define	acs_query_server		ACS030
#define	acs_query_volume		ACS031
#define	acs_response		ACS032
#define	acs_set_access		ACS055
#define	acs_set_cap		ACS033
#define	acs_set_clean		ACS034
#define	acs_set_scratch		ACS035
#define	acs_start		ACS036
#define	acs_state		ACS112
#define	acs_status		ACS110
#define	acs_unlock_drive		ACS037
#define	acs_unlock_volume		ACS038
#define	acs_vary_acs		ACS039
#define	acs_vary_drive		ACS040
#define	acs_vary_lsm		ACS041
#define	acs_vary_port		ACS042
#define	acs_venter		ACS043
#define	acs_xeject		ACS044
#define	acs_query_mm_info		ACS045
#define	acs_vary_cap		ACS046
#define	acs_audit_server		ACS047
#define	acs_register		ACS048
#define	acs_unregister		ACS049
#define	acs_check_registration		ACS050
#define	acs_display		ACS051
#define	acs_mount_pinfo		ACS052
#define	acs_query_mount_scratch_pinfo		ACS053
#define	acs_query_drive_group		ACS056
#define	acs_query_subpool_name		ACS057
#define	acs_get_packet_version		ACS107
#define	acs_type		ACS109
#define	acs_type_response		ACS108
#endif


#define	_DB_DEFS_API_HEADER_		"api/db_defs_api.h"
#define	_DEFS_API_HEADER_		"api/defs_api.h"
#define	_IDENT_API_HEADER_		"api/ident_api.h"
#define	_IPC_HDR_API_HEADER_		"api/ipc_hdr_api.h"
#define	_STRUCTS_API_HEADER_		"api/structs_api.h"
#define	_LMSTRUCTS_API_HEADER_		"api/lm_structs_api.h"



typedef enum
{
	ACSMSG_BAD_INPUT_SELECT = 1,
	ACSMSG_IPC_READ_FAILED,
	ACSMSG_IPC_WRITE_FAILED,
	ACSMSG_IPC_CREATE_FAILED,
	ACSMSG_NOT_EXTENDED,
	ACSMSG_BAD_VERSION,
	ACSMSG_INVALID_VERSION,
	ACSMSG_BAD_COUNT,
	ACSMSG_BAD_SOCKET,
	ACSMSG_BAD_FINAL_RESPONSE,
	ACSMSG_BAD_INT_RESPONSE,
	ACSMSG_BAD_QUERY_RESPONSE,
	ACSMSG_BAD_RESPONSE,
	ACSMSG_AUD_RES_COUNT,
	ACSMSG_BAD_AUDIT_RESP_TYPE,
	ACSMSG_BAD_QUERY_RESP_TYPE,
	ACSMSG_VARY_RESP_COUNT,
	ACSMSG_BAD_VARY_RESP_TYPE,
	ACSMSG_SSI_NOT_RUNNING,
	ACSMSG_VARY_RESP_FAILED,
	ACSMSG_BAD_RESPONSE_TYPE,
	ACSMSG_INVALID_TYPE,
	ACSMSG_LAST,
	ACSMSG_FOR_SIZE_ONLY = INT_MAX
} ACSMESSAGES;
#endif /* _ACSSYS_H_ */
