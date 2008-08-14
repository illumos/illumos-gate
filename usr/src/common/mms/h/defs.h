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


#ifndef _DEFS_
#define	_DEFS_

#if ! defined(__sys_types_h) && ! defined(_H_TYPES)
#include <sys/types.h>
#endif

#ifndef sun
#ifndef _H_SELECT
#include <sys/select.h>
#endif
#endif

#ifndef _DB_DEFS_
#include "db_defs.h"
#endif

#ifndef _DEFS_API_
#include "api/defs_api.h"
#endif


#ifndef SA_RESTART
#define	SA_RESTART	0
#endif

#ifndef		MAX
#define	 MAX(a, b)  (((a) > (b)) ? (a) : (b))
#endif

#ifndef		MIN
#define	 MIN(a, b)  (((a) < (b)) ? (a) : (b))
#endif

#define	DEFAULT_TIME_FORMAT   "%m-%d-%y %H:%M:%S"


typedef		enum  {
	LH_ERR_FIRST = 0,
	LH_ERR_ADDR_INACCESSIBLE,
	LH_ERR_ADDR_TYPE_INVALID,
	LH_ERR_ADDR_UNDEFINED,
	LH_ERR_CANCEL_PENDING,

	LH_ERR_CANCEL_TOO_LATE,
	LH_ERR_CAP_BUSY,
	LH_ERR_CAP_FAILURE,
	LH_ERR_DESTINATION_FULL,
	LH_ERR_FIRST_EXCEEDS_LAST,

	LH_ERR_LH_BUSY,
	LH_ERR_LH_FAILURE,
	LH_ERR_LMU_FAILURE,
	LH_ERR_LSM_FAILURE,
	LH_ERR_LSM_OFFLINE,

	LH_ERR_LSM_OFFLINE_MTCE,
	LH_ERR_MULTI_ACS,
	LH_ERR_MULTI_LSM,
	LH_ERR_MULTI_PANEL,
	LH_ERR_MULTI_TYPE,

	LH_ERR_PATH_UNAVAILABLE,
	LH_ERR_PORT_CONNECT,
	LH_ERR_PORT_DISCONNECT,
	LH_ERR_REQUEST_CANCELLED,
	LH_ERR_REQUEST_INVALID,

	LH_ERR_REQUEST_NOT_ACTIVE,
	LH_ERR_SOURCE_EMPTY,
	LH_ERR_TRANSPORT_BUSY,
	LH_ERR_TRANSPORT_FAILURE,
	LH_ERR_UNABLE_TO_CANCEL,

	LH_ERR_VARY_OVERRIDDEN,
	LH_ERR_VARY_PENDING,
	LH_ERR_VSN_INVALID,
	LH_ERR_VSN_VERIF_FAILED,
	LH_ERR_ALREADY_RESERVED,

	LH_ERR_CAP_OPEN,
	LH_ERR_LMU_LEVEL_INVALID,
	LH_ERR_NO_ERROR,
	LH_ERR_NOT_RESERVED,
	LH_ERR_NO_MAGAZINE,

	LH_ERR_MEDIA_VERIF_FAIL,
	LH_ERR_MEDIA_VSN_VERIF_FAIL,
	LH_ERR_INCOMPATIBLE_MEDIA_DRIVE,
	LH_ERR_MEDIA_TYPE_INVALID,
	LH_ERR_LAST
} LH_ERR_TYPE;

#define	CAP_MSG_INTERVAL		120
#define	DATAGRAM_PATH		"/tmp/"
#define	MAX_ACSMT_PROCS		2
#define	MAX_CSI		20
#define	MAX_LSM_PTP		5
#define	MAX_PORTS		16
#define	MAX_RETRY		10
#define	RETRY_TIMEOUT		2


#define	RETRY		0x01

#define	ACSEL	"50001"
#define	ACSLH	"50002"
#define	ACSLM	"50003"
#define	ACSSA	"50004"
#define	ACSSS	"50005"
#define	ACSPD	"50006"
#define	ACSLOCK	"50007"
#define	ACSSV	"50008"
#define	ACSCM	"50009"
#define	ACES	"50010"
#define	ACSMT	"50100"
#define	ANY_PORT	"0"

#define	TRACE_ACSSS_DAEMON		0x00000100L
#define	TRACE_CSI		0x00000200L
#define	TRACE_ACSLM		0x00000400L
#define	TRACE_MOUNT		0x00000800L
#define	TRACE_DISMOUNT		0x00001000L
#define	TRACE_ENTER		0x00002000L
#define	TRACE_EJECT		0x00004000L
#define	TRACE_AUDIT		0x00008000L
#define	TRACE_QUERY		0x00010000L
#define	TRACE_VARY		0x00020000L
#define	TRACE_RECOVERY		0x00040000L
#define	TRACE_ACSSA		0x00080000L
#define	TRACE_CP		0x00100000L
#define	TRACE_LIBRARY_HANDLER		0x00200000L
#define	TRACE_EVENT_LOGGER		0x00400000L
#define	TRACE_CSI_PACKETS		0x00800000L
#define	TRACE_LOCK_SERVER		0x01000000L
#define	TRACE_SET_CAP		0x02000000L
#define	TRACE_SET_CLEAN		0x04000000L
#define	TRACE_ACSCM		0x08000000L


#define	TRACE(lev)           \
/ (trace_value != 0 && (trace_value & 0xff) >= lev)

typedef void (*SIGFUNCP)();


typedef enum {
	CLM_FIRST = 0,
	CLM_ABORT_TRANSITION,
	CLM_ALLOC_ERROR,
	CLM_ASSERTION,
	CLM_CAT_TARGET_ERROR,

	CLM_DB_DEADLOCK,
	CLM_DB_TIMEOUT,
	CLM_DUP_TYPE_NUM,
	CLM_DUP_TYPE_STR,
	CLM_DESTINATION_FULL,

	CLM_FILE_PROBLEM,
	CLM_FIXED_MEDIA_TYPE,
	CLM_FIXED_VOLUME_TYPE,
	CLM_FUNC_FAILED,
	CLM_INC_TYPES,

	CLM_INV_ARG_NUM,
	CLM_INV_ARG_STR,
	CLM_INV_NUM_ARGS,
	CLM_IPC_ATTACH,
	CLM_IPC_OPEN,

	CLM_IPC_SEND,
	CLM_KILL_ERROR,
	CLM_LOCKED_VOL_DELETED,
	CLM_MSG_TIMEOUT,
	CLM_MSG_TOO_SMALL,

	CLM_NO_TYPES,
	CLM_NOT_BOOLEAN,
	CLM_NOT_DEFINED,
	CLM_SIGNAL_ERROR,
	CLM_SOURCE_EMPTY,

	CLM_TABLE_INCORRECT,
	CLM_TOO_MANY_COMPAT,
	CLM_TRACE_TRANSITION,
	CLM_UNDEF_TRANSITION,
	CLM_UNEXP_CAT_STATUS,

	CLM_UNEXP_COMMAND,
	CLM_UNEXP_EVENT,
	CLM_UNEXP_LD_STATUS,
	CLM_UNEXP_LH_REQUEST,
	CLM_UNEXP_LH_RESPONSE,

	CLM_UNEXP_MESSAGE,
	CLM_UNEXP_ORIGINATOR,
	CLM_UNEXP_REQUESTOR,
	CLM_UNEXP_SIGNAL,
	CLM_UNEXP_STATE,

	CLM_UNEXP_STATUS,
	CLM_UNEXP_TYPE,
	CLM_UNKNOWN_MEDIA_TYPE,
	CLM_UNLINK_ERROR,
	CLM_UNSUP_LH_ERROR,

	CLM_UNSUP_LH_REQUEST,
	CLM_UNSUP_VERSION,
	CLM_VOL_FOUND,
	CLM_VOL_MISPLACED,
	CLM_VOL_MOVED,

	CLM_VOL_NOT_FOUND,
	CLM_LAST
} CL_MESSAGE;

typedef enum {
	FIELD_FIRST = 0,
	FIELD_ACTIVITY,
	FIELD_CAP_MODE,
	FIELD_LOCKID,
	FIELD_MAX_USE,

	FIELD_POOLID,
	FIELD_PRIORITY,
	FIELD_STATE,
	FIELD_STATUS,
	FIELD_VOLUME_TYPE,

	FIELD_LAST
} FIELD;


typedef enum {
	LOG_OPTION_FIRST = 0,
	LOG_OPTION_EVENT,
	LOG_OPTION_TRACE,
	LOG_OPTION_LAST
} LOG_OPTION;

typedef enum {
	QUERY_TYPE_FIRST = 0,
	QUERY_TYPE_ALL,
	QUERY_TYPE_ALL_ACS,
	QUERY_TYPE_ALL_CELL,
	QUERY_TYPE_ALL_DRIVE,

	QUERY_TYPE_ALL_LSM,
	QUERY_TYPE_LSM_RESERVED,
	QUERY_TYPE_NEXT,
	QUERY_TYPE_ONE,
	QUERY_TYPE_ONE_CELL,

	QUERY_TYPE_ONE_DRIVE,
	QUERY_TYPE_LAST
} QUERY_TYPE;

typedef enum {
	SELECT_OPTION_FIRST = 0,
	SELECT_OPTION_ACS,
	SELECT_OPTION_LSM,
	SELECT_OPTION_LAST
} SELECT_OPTION;

typedef enum {
	WRITE_MODE_FIRST = 0,
	WRITE_MODE_CREATE,
	WRITE_MODE_UPDATE,
	WRITE_MODE_LAST
} WRITE_MODE;

#define	MEDIA_TYPE_LEN		3
#define	DRIVE_TYPE_LEN		3

#define	MM_MAX_MEDIA_TYPES	36
#define	MM_MAX_DRIVE_TYPES	40

#define	MM_MEDIA_DB_STR_LEN	(MM_MAX_MEDIA_TYPES*(MEDIA_TYPE_LEN + 1))+1
#define	MM_DRIVE_DB_STR_LEN	(MM_MAX_DRIVE_TYPES*(DRIVE_TYPE_LEN + 1))+1

#ifndef LINUX
extern		char		*sys_errlist[];
extern		char		*sys_siglist[];
#endif


extern		char		acsss_version[];
extern int		sd_in;
extern int		n_fds;
extern int		fd_list[FD_SETSIZE];

extern char		my_sock_name[SOCKET_NAME_SIZE];

extern TYPE		my_module_type;
extern TYPE		requestor_type;
extern int		restart_count;
extern MESSAGE_ID		request_id;

extern STATE		process_state;
extern unsigned long		trace_module;
extern unsigned long		trace_value;


#endif /* _DEFS_ */
