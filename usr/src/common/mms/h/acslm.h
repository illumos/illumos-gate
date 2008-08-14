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


#ifndef _ACSLM_
#define	_ACSLM_

#ifndef _CL_QM_DEFS_
#include "cl_qm_defs.h"
#endif

#ifndef _LH_DEFS_
#include "lh_defs.h"
#endif

#ifndef _LM_STRUCTS_
#include "lm_structs.h"
#endif

#ifndef _V2_STRUCTS_
#include "v2_structs.h"
#endif

#ifndef _V3_STRUCTS_
#include "v3_structs.h"
#endif

#if defined(sun) && !defined(SOLARIS)
typedef unsigned long ulong_t;
#endif

typedef struct {
	LSMID		lsm_id;
	BOOLEAN		vary_in_progress;
	STATE		current_state;
	STATE		base_state;
} LM_OFFLINE_VARY;

typedef struct {
	DRIVEID		drive_id;
	BOOLEAN		flag;
} LM_DRVTBL;

typedef struct {
	CAPID		cap_id;
	BOOLEAN		auto_ent;
	unsigned long		msg_id;
} LM_CAPTBL;

typedef union {
	REQUEST_HEADER		generic_request;
	AUDIT_REQUEST		audit_request;
	ENTER_REQUEST		enter_request;
	VENTER_REQUEST		venter_request;
	EJECT_REQUEST		eject_request;
	EXT_EJECT_REQUEST		ext_eject_request;
	VARY_REQUEST		vary_request;
	MOUNT_REQUEST		mount_request;
	MOUNT_SCRATCH_REQUEST mount_scratch_request;
	DISMOUNT_REQUEST		dismount_request;
	QUERY_REQUEST		query_request;
	CANCEL_REQUEST		cancel_request;
	START_REQUEST		start_request;
	IDLE_REQUEST		idle_request;
	SET_SCRATCH_REQUEST		set_scratch_request;
	DEFINE_POOL_REQUEST		define_pool_request;
	DELETE_POOL_REQUEST		delete_pool_request;
	LH_MESSAGE		lh_request;
	SET_CLEAN_REQUEST		set_clean_request;
	LOCK_REQUEST		lock_request;
	UNLOCK_REQUEST		unlock_request;
	CLEAR_LOCK_REQUEST		clear_lock_request;
	QUERY_LOCK_REQUEST		query_lock_request;
	SET_CAP_REQUEST		set_cap_request;
	SET_OWNER_REQUEST		set_owner_request;
	SWITCH_REQUEST		switch_request;
	MOVE_REQUEST		move_request;
	RCVY_REQUEST		rcvy_request;
	REGISTER_REQUEST		register_request;
	UNREGISTER_REQUEST		unregister_request;
	CHECK_REGISTRATION_REQUEST		check_registration_request;
	DISPLAY_REQUEST		display_request;
	MOUNT_PINFO_REQUEST		mount_pinfo_request;
} REQUEST_TYPE;

typedef struct {
	REQUEST_HEADER		request_header;
	RESPONSE_STATUS		response_status;
} RESPONSE_HEADER;

typedef union {
	RESPONSE_HEADER		generic_response;
	ACKNOWLEDGE_RESPONSE acknowledge_response;
	AUDIT_RESPONSE		audit_response;
	ENTER_RESPONSE		enter_response;
	EJECT_RESPONSE		eject_response;
	VARY_RESPONSE		vary_response;
	MOUNT_RESPONSE		mount_response;
	MOUNT_SCRATCH_RESPONSE mount_scratch_response;
	DISMOUNT_RESPONSE		dismount_response;
	QUERY_RESPONSE		query_response;
	CANCEL_RESPONSE		cancel_response;
	START_RESPONSE		start_response;
	IDLE_RESPONSE		idle_response;
	SET_SCRATCH_RESPONSE set_scratch_response;
	DEFINE_POOL_RESPONSE define_pool_response;
	DELETE_POOL_RESPONSE delete_pool_response;
	SET_CLEAN_RESPONSE		set_clean_response;
	LOCK_RESPONSE		lock_response;
	UNLOCK_RESPONSE		unlock_response;
	CLEAR_LOCK_RESPONSE		clear_lock_response;
	QUERY_LOCK_RESPONSE		query_lock_response;
	SET_CAP_RESPONSE		set_cap_response;
	SET_OWNER_RESPONSE		set_owner_response;
	SWITCH_RESPONSE		switch_response;
	MOVE_RESPONSE		move_response;
	RCVY_RESPONSE		rcvy_response;
	REGISTER_RESPONSE		register_response;
	UNREGISTER_RESPONSE		unregister_response;
	CHECK_REGISTRATION_RESPONSE check_registration_response;
	DISPLAY_RESPONSE		display_response;
	MOUNT_PINFO_RESPONSE mount_pinfo_response;
} RESPONSE_TYPE;

typedef struct request_table {
	long		request_pid;
	REQUEST_TYPE	*request_ptr;
	unsigned long		byte_count;
	STATUS		status;
	STATUS		exit_status;
	COMMAND		command;
	TYPE		requestor_type;
	char		return_socket_name[SOCKET_NAME_SIZE];
	unsigned int		resource_count;
	time_t		ts_que;
	time_t		ts_write;
	time_t		ts_fmt;
	VERSION		version;
	int		pktCnt;
} LM_REQUEST_TABLE;

#define	LM_ERROR_MSG_SIZE		256
#define	LM_FILE_NAME_SIZE		14

typedef struct rp_tbl {
	COMMAND		command_value;
	char		process_filename[LM_FILE_NAME_SIZE];
	BOOLEAN		spawned;
	BOOLEAN		idle_prc;
	BOOLEAN		recov_prc;
	BOOLEAN		cancellable;
	int		resource_count;
	unsigned char		req_msg_mask;
	unsigned long		req_ext_mask;
	VERSION		version;
} LM_RP_TBL;

extern ALIGNED_BYTES acslm_input_buffer[MAX_MESSAGE_BLOCK];
extern ALIGNED_BYTES acslm_output_buffer[MAX_MESSAGE_BLOCK];

extern		int		maxuprc;
#define	MAX_REQUEST_PROCESS_SLOTS		maxuprc - 10

#define	MAX_ACS_PROCESSES	"MAX_ACS_PROCESSES"

#define	LM_SELECT_TIMEOUT		1
#define	LM_SLEEP_TIMEOUT		15

#define	LM_QAUDIT_INTERVAL		300

#define	LM_MAX_QUEUES		1

#define	LM_NO_OPTIONS		0
#define	LM_FINAL_MSG		0x00

#define	LM_TRAVERSE_FWD		0
#define	LM_TRAVERSE_REV		1
#define	LM_TRAVERSE_FIRST		0
#define	LM_TRAVERSE_NEXT		1
#define	LM_TRAVERSE_LAST		2

#define	LM_NO_RESOURCES		0
#define	LM_MIN_RESOURCES		1

#define	LM_IDLE_FLAG		0
#define	LM_IDLE_FORCE_FLAG		1
#define	LM_TERMINATE_FLAG		2
#define	LM_CANCEL_FLAG		3
#define	LM_RECOVERY_FLAG		4

#define	LM_VARY_OFFLINE_INTERVAL   (long)(2*60)

#define	AUTO_CLEAN	"AUTO_CLEAN"

#define	LM_RP_TRAIL	"LM_RP_TRAIL"


#define	LMP_NONE		0
#define	LMP_EMPTY	-1
#define	LMP_PERSISTANT  -2

typedef enum {
	LMM_FIRST = 0,
	LMM_BAD_ACSID,
	LMM_BAD_STAT,
	LMM_BAD_EXECL,
	LMM_BAD_FORK,
	LMM_BAD_LSMID,
	LMM_BAD_NDX,
	LMM_BAD_PACKET,
	LMM_BAD_PORTID,
	LMM_BAD_REQ_TBL,
	LMM_BAD_VARY,
	LMM_CAP_CLOSED,
	LMM_CAP_OPENED,
	LMM_LMU_READY,
	LMM_LSM_NOT_READY,
	LMM_LSM_READY,
	LMM_PORT_MSG,
	LMM_DOOR_CLOSED,
	LMM_DOOR_OPENED,
	LMM_CAP_NOT_FOUND,
	LMM_FAIL_IPC_OPEN,
	LMM_INVAL_ADDRESS,
	LMM_INVAL_SDIR,
	LMM_INVALID_EXIT,
	LMM_INVALID_MSG,
	LMM_INVALID_MSGID,
	LMM_INVALID_TERM,
	LMM_NO_ACCESS,
	LMM_NO_DELETE,
	LMM_NO_MATCH,
	LMM_NO_QUEUE,
	LMM_NULL_PTR,
	LMM_BLANK_SOCKET,
	LMM_CLEAN_DRIVE,
	LMM_DUPLICATE,
	LMM_FATAL,
	LMM_FATAL_STATE,
	LMM_FINAL_DET,
	LMM_FINAL_NOTIF,
	LMM_FREE_ERROR,
	LMM_LSM_ONLINE,
	LMM_NOT_FATAL,
	LMM_OFFLINE_FORCE,
	LMM_PORT_OFFLINE,
	LMM_RETRANS,
	LMM_RESID_REQ,
	LMM_REQ_ERROR,
	LMM_REQ_INCON,
	LMM_UNEXP_MEMBER,
	LMM_UNKN_STATE,
	LMM_TRACE_TRANS,
	LMM_LAST
} LMM_MESSAGE;

extern STATE		lm_state;
extern STATE		lm_previous_state;
extern QM_QID		acslm_req_tbl_ptr;
extern QM_MID		lm_next_member;
extern STATUS		lm_process_creation;
extern int		lm_resources_available;
extern int		lm_lsm_count;
extern int		lm_process_id;
extern LM_OFFLINE_VARY  *lm_offline_ptr;
extern int		lm_suspend_fork;
extern int		lm_mount_count;
extern int		lm_query_count;
extern int		lm_acssurr_count;


STATUS lm_authentic(char *request_ptr);
STATUS lm_cancel_rp(char *request_ptr);
STATUS lm_chk_drvtbl(DRIVEID drive_id, BOOLEAN *value);
STATUS lm_clean_que(void);
void lm_completion(void);
STATUS lm_cvt_req(REQUEST_TYPE *reqp, int *byte_count);
STATUS lm_cvt_resp(RESPONSE_TYPE *rssp, int *byte_count);
STATUS lm_cvt_v0_v1(char *request_ptr, int *byte_count);
STATUS lm_cvt_v1_v0(char *response_ptr, int *byte_count);
STATUS lm_cvt_v1_v2(char *request_ptr, int *byte_count);
STATUS lm_cvt_v2_v1(char *response_ptr, int *byte_count);
STATUS lm_cvt_v2_v3(V2_REQUEST_TYPE *req_ptr, int *byte_count);
STATUS lm_cvt_v3_v2(V2_RESPONSE_TYPE *resp_ptr, int *byte_count);
STATUS lm_cvt_v3_v4(V3_REQUEST_TYPE *request_ptr, int *byte_count);
STATUS lm_cvt_v4_v3(RESPONSE_TYPE *response_ptr, int *byte_count);
STATUS lm_fmt_resp(char *request_ptr, STATUS fmt_status,
    QM_MID request_member);
STATUS lm_fre_resrc(QM_MID member);
STATUS lm_get_resrc(void);
STATUS lm_idle_proc(int idle_options_flag);
STATUS lm_init(int argc, char *argv[]);
STATUS lm_input(char *request_ptr, int *byte_count);
STATUS lm_mk_captbl(void);
STATUS lm_mk_drvtbl(void);
STATUS lm_msg_hdlr(char *request_ptr, char *response_ptr);
STATUS lm_msg_size(char *request_ptr, int byte_count, int *calc_byte_count);
STATUS lm_output(char *response_ptr, int byte_count);
STATUS lm_req_proc(char *request_ptr, int byte_count);
STATUS lm_req_valid(char *request_ptr, int byte_count);
int lm_resource(char *request_ptr);
STATUS lm_resp_proc(char *response_ptr, int byte_count);
STATUS lm_rp_create(void);
STATUS lm_rp_table(void);
int lm_rp_table_loc(COMMAND cmd);
void lm_rp_trail(LM_REQUEST_TABLE *req_tbl_entry, QM_QID request_ID,
		MESSAGE_HEADER *msgHdr);
STATUS lm_set_drvtbl(DRIVEID drive_id);
void lm_sig_hdlr(int signal_received);
STATUS lm_split_resp(char dsoc[], RESPONSE_TYPE *rssp, int *byte_count);
int lm_tbl_loc(int search_direction, int select_type,
    STATUS search_criteria_1, STATUS search_criteria_2);
void lm_terminate(int terminate_flag);
STATUS lm_validator(char *request_ptr, int *byte_count);
STATUS lm_wait_proc(char *request_ptr);

#endif /* _ACSLM_ */
