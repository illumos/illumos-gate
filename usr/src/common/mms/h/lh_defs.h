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


#ifndef _LH_DEFS_
#define	_LH_DEFS_


#ifndef _STRUCTS_
#include "structs.h"
#endif


typedef		ROW		CAP_ROW;
typedef		COL		CAP_COL;
typedef		DRIVE		TRANSPORT;

#define	 MIN_IPM		MIN_PORT
#define	 MAX_IPM		MAX_PORT
#define	 MAX_TRANSPORT		4
#define	 MAX_LSM_TRANSPORT		80
#define	 PTP_SLOTS		4
#define	 MAX_PTP		5
#define	 HANDS		2
#define	 VERSION_SIZE		16
#define	 LH_MAX_REQUESTS		32
#define	 MAX_RECOV_CELLS		10
#define	 NULL_IPC_IDENT		0L
#define	 LH_MAX_PRIORITY		99
#define	 NUM_4400_INNER_PNLS 8


typedef		enum  {
	LH_ADDR_TYPE_FIRST = 0,
	LH_ADDR_TYPE_ACS,
	LH_ADDR_TYPE_CAP,
	LH_ADDR_TYPE_CAP_CELL,
	LH_ADDR_TYPE_CELL,

	LH_ADDR_TYPE_DIAG_CELL,
	LH_ADDR_TYPE_LH,
	LH_ADDR_TYPE_LIBRARY,
	LH_ADDR_TYPE_LMU,
	LH_ADDR_TYPE_LSM,

	LH_ADDR_TYPE_NONE,
	LH_ADDR_TYPE_PANEL,
	LH_ADDR_TYPE_PORT,
	LH_ADDR_TYPE_PTP,
	LH_ADDR_TYPE_RECOV_CELL,

	LH_ADDR_TYPE_TRANSPORT,
	LH_ADDR_TYPE_LAST
} LH_ADDR_TYPE;

typedef		struct lh_addr_acs  {
	ACS		acs;
} LH_ADDR_ACS;

typedef		struct lh_addr_cap  {
	ACS		acs;
	LSM		lsm;
	CAP		cap;
} LH_ADDR_CAP;

typedef		struct lh_addr_cap_cell  {
	ACS		acs;
	LSM		lsm;
	CAP		cap;
	CAP_ROW		row;
	CAP_COL		column;
} LH_ADDR_CAP_CELL;

typedef		struct lh_addr_cell  {
	ACS		acs;
	LSM		lsm;
	PANEL		panel;
	ROW		row;
	COL		column;
} LH_ADDR_CELL;

typedef		struct lh_addr_diag_cell  {
	ACS		acs;
	LSM		lsm;
	PANEL		panel;
	ROW		row;
	COL		column;
} LH_ADDR_DIAG_CELL;

typedef		struct lh_addr_lh  {
	unsigned char		unused;
} LH_ADDR_LH;

typedef		struct lh_addr_library  {
	unsigned char		unused;
} LH_ADDR_LIBRARY;

typedef		struct lh_addr_lmu  {
	ACS		acs;
} LH_ADDR_LMU;

typedef		struct lh_addr_lsm  {
	ACS		acs;
	LSM		lsm;
} LH_ADDR_LSM;

typedef		struct lh_addr_none  {
	unsigned char		unused;
} LH_ADDR_NONE;

typedef		struct lh_addr_panel  {
	ACS		acs;
	LSM		lsm;
	PANEL		panel;
} LH_ADDR_PANEL;

typedef		struct lh_addr_port  {
	ACS		acs;
	PORT		port;
	char		name [PORT_NAME_SIZE];
} LH_ADDR_PORT;

typedef		struct lh_addr_ptp  {
	ACS		acs;
	unsigned char		ptp;
} LH_ADDR_PTP;

typedef		struct lh_addr_recov_cell  {
	ACS		acs;
	LSM		lsm;
	ROW		row;
} LH_ADDR_RECOV_CELL;

typedef		struct lh_addr_transport  {
	ACS		acs;
	LSM		lsm;
	PANEL		panel;
	TRANSPORT		transport;
	BOOLEAN		force_unload;
	BOOLEAN		write_protect;
} LH_ADDR_TRANSPORT;

typedef		struct lh_addr  {
	LH_ADDR_TYPE		type;
	union  {
		LH_ADDR_ACS		acs;
		LH_ADDR_CAP		cap;
		LH_ADDR_CAP_CELL		cap_cell;
		LH_ADDR_CELL		cell;
		LH_ADDR_DIAG_CELL		diag_cell;
		LH_ADDR_LH		lh;
		LH_ADDR_LIBRARY		library;
		LH_ADDR_LMU		lmu;
		LH_ADDR_LSM		lsm;
		LH_ADDR_NONE		none;
		LH_ADDR_PANEL		panel;
		LH_ADDR_PORT		port;
		LH_ADDR_PTP		ptp;
		LH_ADDR_RECOV_CELL		recov_cell;
		LH_ADDR_TRANSPORT		transport;
	} address;
} LH_ADDR;



typedef		enum  {
	LH_VSN_TYPE_FIRST = 0,
	LH_VSN_TYPE_BLANK,
	LH_VSN_TYPE_LABELED,
	LH_VSN_TYPE_NONE,
	LH_VSN_TYPE_LAST
} LH_VSN_TYPE;

typedef		struct lh_vsn  {
	LH_VSN_TYPE		type;
	MEDIA_TYPE		media_type;
	char		vsn [EXTERNAL_LABEL_SIZE];
} LH_VSN;



typedef		enum  {
	LH_REQ_TYPE_FIRST = 0,
	LH_REQ_TYPE_CANCEL,
	LH_REQ_TYPE_CATALOG,
	LH_REQ_TYPE_CONNECT,
	LH_REQ_TYPE_DISCONNECT,

	LH_REQ_TYPE_EJECT,
	LH_REQ_TYPE_ENTER,
	LH_REQ_TYPE_MOVE,
	LH_REQ_TYPE_RELEASE,
	LH_REQ_TYPE_RESERVE,

	LH_REQ_TYPE_STATUS,
	LH_REQ_TYPE_VARY,
	LH_REQ_TYPE_LAST
} LH_REQ_TYPE;

typedef		struct lh_cancel_request  {
	unsigned long		ipc_identifier;
} LH_REQ_CANCEL;

typedef		enum  {
	LH_CAT_OPTION_FIRST = 0,
	LH_CAT_OPTION_ALL,
	LH_CAT_OPTION_FIRST_EMPTY,
	LH_CAT_OPTION_LAST
} LH_CAT_OPTION;

typedef		struct lh_catalog_request  {
	LH_ADDR		first;
	LH_ADDR		last;
	LH_CAT_OPTION		option;
} LH_REQ_CATALOG;

typedef		struct lh_connect_request  {
	LH_ADDR_PORT		port;
} LH_REQ_CONNECT;

typedef		struct lh_disconnect_request  {
	LH_ADDR_PORT		port;
} LH_REQ_DISCONNECT;

typedef		enum  {
	LH_OPMSG_FIRST = 0,
	LH_OPMSG_LIBRARY_UNAVAILABLE,
	LH_OPMSG_LOAD_CARTRIDGES,
	LH_OPMSG_NO_MESSAGE,
	LH_OPMSG_REMOVE_CARTRIDGES,
	LH_OPMSG_LAST
} LH_OPMSG;

typedef		struct lh_eject_request  {
	LH_ADDR_CAP		cap;
	LH_OPMSG		opmsg;
} LH_REQ_EJECT;

typedef		struct lh_enter_request  {
	LH_ADDR_CAP		cap;
	LH_OPMSG		opmsg;
} LH_REQ_ENTER;

typedef		struct lh_move_request  {
	LH_ADDR		source;
	LH_ADDR		destination;
	LH_VSN		vsn;
} LH_REQ_MOVE;

typedef		enum  {
	LH_LOCK_TYPE_FIRST = 0,
	LH_LOCK_TYPE_IDLE,
	LH_LOCK_TYPE_LOCK,
	LH_LOCK_TYPE_NOLOCK,
	LH_LOCK_TYPE_RECOVERY,
	LH_LOCK_TYPE_UNLOCK,
	LH_LOCK_TYPE_LAST
} LH_LOCK_TYPE;

typedef		struct lh_release_request  {
	LH_ADDR_CAP		cap;
	LH_LOCK_TYPE		mode;
	LH_OPMSG		opmsg;
} LH_REQ_RELEASE;

typedef		struct lh_reserve_request  {
	LH_ADDR_CAP		cap;
	LH_LOCK_TYPE		mode;
	LH_OPMSG		opmsg;
} LH_REQ_RESERVE;

typedef		struct lh_status_request  {
	LH_ADDR		resource;
} LH_REQ_STATUS;

typedef		enum  {
	LH_VARY_ACTION_FIRST = 0,
	LH_VARY_ACTION_ONLINE,
	LH_VARY_ACTION_OFFLINE,
	LH_VARY_ACTION_OFFLINE_FORCE,
	LH_VARY_ACTION_LAST
} LH_VARY_ACTION;

typedef		struct lh_vary_request  {
	LH_ADDR		resource;
	LH_VARY_ACTION		action;
} LH_REQ_VARY;


typedef		struct lh_request  {
	IPC_HEADER		ipc_header;
	LH_REQ_TYPE		request_type;
	REQUEST_PRIORITY request_priority;
	union {
		LH_REQ_CANCEL		cancel;
		LH_REQ_CATALOG		catalog;
		LH_REQ_CONNECT		connect;
		LH_REQ_DISCONNECT		disconnect;
		LH_REQ_EJECT		eject;
		LH_REQ_ENTER		enter;
		LH_REQ_MOVE		move;
		LH_REQ_RELEASE		release;
		LH_REQ_RESERVE		reserve;
		LH_REQ_STATUS		status;
		LH_REQ_VARY		vary;
	} request;
} LH_REQUEST;

typedef		struct lh_cancel_response  {
	unsigned long		ipc_identifier;
	LH_REQUEST		request;
} LH_RESP_CANCEL;

typedef		enum  {
	LH_CAT_STATUS_FIRST = 0,
	LH_CAT_STATUS_BAD_MOVE,
	LH_CAT_STATUS_EMPTY,
	LH_CAT_STATUS_INACCESSIBLE,
	LH_CAT_STATUS_LOADED,
	LH_CAT_STATUS_MISSING,
	LH_CAT_STATUS_NO_TRANSPORT_COMM,
	LH_CAT_STATUS_READABLE,
	LH_CAT_STATUS_UNREADABLE,
	LH_CAT_STATUS_LAST
} LH_CAT_STATUS;

typedef		struct lh_location  {
	short		status;
	MEDIA_TYPE media_type;
	char		vsn [EXTERNAL_LABEL_SIZE];
} LH_LOCATION;

typedef		struct lh_catalog_response  {
	LH_ADDR		first;
	LH_ADDR		last;
	unsigned short		locations;
	LH_LOCATION		location [1];
} LH_RESP_CATALOG;

typedef		struct lh_connect_response  {
	LH_ADDR_PORT		port;
} LH_RESP_CONNECT;

typedef		struct lh_disconnect_response  {
	LH_ADDR_PORT		port;
} LH_RESP_DISCONNECT;

typedef		enum  {
	LH_DOOR_STATUS_FIRST = 0,
	LH_DOOR_STATUS_CLOSED,
	LH_DOOR_STATUS_OPENED,
	LH_DOOR_STATUS_UNDEFINED,
	LH_DOOR_STATUS_UNLOCKED,
	LH_DOOR_STATUS_LAST
} LH_DOOR_STATUS;

typedef		struct lh_eject_response  {
	LH_ADDR_CAP		cap;
	LH_DOOR_STATUS		status;
} LH_RESP_EJECT;

typedef		struct lh_enter_response  {
	LH_ADDR_CAP		cap;
	LH_DOOR_STATUS		status;
} LH_RESP_ENTER;

typedef		struct lh_error_response  {
	LH_ERR_TYPE		error;
	LH_ADDR		resource;
	BOOLEAN		recovery;
	LH_ADDR		address;
	LH_REQUEST		request;
	char		message[sizeof (int)];
} LH_RESP_ERROR;

typedef		struct lh_move_response  {
	LH_ADDR		source;
	LH_ADDR		destination;
	LH_VSN		vsn;
} LH_RESP_MOVE;

typedef		struct lh_release_response  {
	LH_ADDR_CAP		cap;
	LH_DOOR_STATUS		status;
} LH_RESP_RELEASE;

typedef		struct lh_reserve_response  {
	LH_ADDR_CAP		cap;
	LH_DOOR_STATUS		status;
} LH_RESP_RESERVE;

typedef		enum  {
	LH_CONDITION_FIRST = 0,
	LH_CONDITION_INOPERATIVE,
	LH_CONDITION_MTCE_REQD,
	LH_CONDITION_OPERATIVE,
	LH_CONDITION_LAST
} LH_CONDITION;

typedef		struct lh_acs_status  {
	int		lsms;
	BOOLEAN		lsm_accessible [MAX_LSM+1];
	unsigned char		num_ptp;
	unsigned short		ports;
	LH_ADDR_PORT		port [1];
} LH_STATUS_ACS;

typedef		enum  {
	LH_CAP_STATUS_FIRST = 0,
	LH_CAP_STATUS_EJECT,
	LH_CAP_STATUS_ENTER,
	LH_CAP_STATUS_IDLE,
	LH_CAP_STATUS_LAST
} LH_CAP_STATUS;

typedef		struct lh_cap_status  {
	BOOLEAN		operational;
	BOOLEAN		reserved;
	BOOLEAN		cap_scan;
	LH_CAP_STATUS		cap_status;
	LH_DOOR_STATUS		door_status;
	unsigned char		owner;
	unsigned char		available_cells;
	LH_ADDR_CAP_CELL		first;
	LH_ADDR_CAP_CELL		last;
	CAP_ROW		magazine_rows;
	CAP_COL		magazine_cols;
} LH_STATUS_CAP;

typedef		struct lh_lh_status  {
	char		version [VERSION_SIZE];
	unsigned char		host_id;
	unsigned int		ports;
	unsigned int		ports_online;
	LH_ADDR_PORT		port [1];
} LH_STATUS_LH;

typedef		struct lh_library_status  {
	BOOLEAN		acs_accessible [MAX_ACS+1];
} LH_STATUS_LIBRARY;

typedef		struct lh_lmu_status  {
	LH_CONDITION		ipm_status [MAX_IPM+1];
} LH_STATUS_LMU;

typedef		enum  {
	LH_STATE_LSM_FIRST = 0,
	LH_STATE_LSM_ONLINE,
	LH_STATE_LSM_OFFLINE,
	LH_STATE_LSM_PENDING,
	LH_STATE_LSM_MAINT,
	LH_STATE_LSM_LAST
} LH_STATE_LSM;


#define	LH_INNER_PANEL		-1
#define	LH_INNER_ADJ_PANEL	-2
#define	LH_INNER_DOOR_PANEL	-3

typedef		struct lh_lsm_status  {
	BOOLEAN		ready;
	LH_STATE_LSM		state;
	unsigned char	hands;
	LH_CONDITION		hand_status [HANDS];
	BOOLEAN		hand_empty [HANDS];
	BOOLEAN		door_closed;
	unsigned char		caps;
	unsigned short		panels;
	PANEL_TYPE		panel [MAX_PANEL+1];
	unsigned short		transports;
	LH_ADDR_TRANSPORT		transport [MAX_LSM_TRANSPORT];
	unsigned char		num_ptp;
	LH_ADDR_PTP		ptp [MAX_PTP];
} LH_STATUS_LSM;

typedef		struct lh_panel_status  {
	char		type;
	unsigned short		transports;
	LH_ADDR_TRANSPORT		transport [MAX_TRANSPORT];
} LH_STATUS_PANEL;

typedef		struct lh_port_status  {
	LH_ADDR_PORT		port;
	BOOLEAN		online;
} LH_STATUS_PORT;

typedef		struct lh_ptp_status  {
	unsigned char		ptp;
	LH_ADDR_PANEL		master;
	LH_ADDR_PANEL		slave;
} LH_STATUS_PTP;

typedef		enum  {
	LH_TAPE_STATUS_FIRST = 0,
	LH_TAPE_STATUS_EMPTY,
	LH_TAPE_STATUS_LOADED,
	LH_TAPE_STATUS_NO_COMM,
	LH_TAPE_STATUS_UNLOADED,
	LH_TAPE_STATUS_LAST
} LH_TAPE_STATUS;

typedef		struct lh_transport_status  {
	DRIVE_TYPE		drive_type;
	LH_TAPE_STATUS		status;
	BOOLEAN		ready;
	BOOLEAN		clean;
} LH_STATUS_TRANSPORT;

typedef		enum  {
	LH_STATUS_TYPE_FIRST = 0,
	LH_STATUS_TYPE_ACS,
	LH_STATUS_TYPE_CAP,
	LH_STATUS_TYPE_LH,
	LH_STATUS_TYPE_LIBRARY,

	LH_STATUS_TYPE_LMU,
	LH_STATUS_TYPE_LSM,
	LH_STATUS_TYPE_PANEL,
	LH_STATUS_TYPE_PORT,
	LH_STATUS_TYPE_PTP,

	LH_STATUS_TYPE_TRANSPORT,
	LH_STATUS_TYPE_LAST
} LH_STATUS_TYPE;

typedef		struct lh_status_response  {
	LH_ADDR		resource;
	LH_STATUS_TYPE		status_type;
	union {
		LH_STATUS_ACS		acs;
		LH_STATUS_CAP		cap;
		LH_STATUS_LH		lh;
		LH_STATUS_LIBRARY		library;
		LH_STATUS_LMU		lmu;
		LH_STATUS_LSM		lsm;
		LH_STATUS_PANEL		panel;
		LH_STATUS_PORT		port;
		LH_STATUS_PTP		ptp;
		LH_STATUS_TRANSPORT		transport;
	} status;
} LH_RESP_STATUS;

typedef		struct lh_vary_response  {
	LH_ADDR		resource;
	LH_VARY_ACTION		action;
	BOOLEAN		online;
} LH_RESP_VARY;

typedef		enum  {
	LH_RESP_TYPE_FIRST = 0,
	LH_RESP_TYPE_INTERMED,
	LH_RESP_TYPE_ERROR,
	LH_RESP_TYPE_FINAL,
	LH_RESP_TYPE_LAST
} LH_RESP_TYPE;

typedef		struct lh_response  {
	IPC_HEADER		ipc_header;
	LH_REQ_TYPE		request_type;
	LH_RESP_TYPE		response_type;
	union {
		LH_RESP_CANCEL		cancel;
		LH_RESP_CATALOG		catalog;
		LH_RESP_CONNECT		connect;
		LH_RESP_DISCONNECT		disconnect;
		LH_RESP_EJECT		eject;
		LH_RESP_ENTER		enter;
		LH_RESP_ERROR		error;
		LH_RESP_MOVE		move;
		LH_RESP_RELEASE		release;
		LH_RESP_RESERVE		reserve;
		LH_RESP_STATUS		status;
		LH_RESP_VARY		vary;
	} response;
} LH_RESPONSE;

typedef		enum  {
	LH_MSG_TYPE_FIRST = 0,
	LH_MSG_TYPE_AVAILABLE,
	LH_MSG_TYPE_CAP_CLOSED,
	LH_MSG_TYPE_CAP_OPENED,
	LH_MSG_TYPE_CLEAN_TRANSPORT,

	LH_MSG_TYPE_DEGRADED_MODE,
	LH_MSG_TYPE_DOOR_CLOSED,
	LH_MSG_TYPE_DOOR_OPENED,
	LH_MSG_TYPE_LMU_READY,
	LH_MSG_TYPE_LSM_NOT_READY,

	LH_MSG_TYPE_LSM_READY,
	LH_MSG_TYPE_PORT_OFFLINE,
	LH_MSG_TYPE_LAST
} LH_MSG_TYPE;

typedef		struct lh_available_message  {
	unsigned short		unused;
} LH_MSG_AVAILABLE;

typedef		struct lh_cap_closed_message  {
	LH_ADDR_CAP		cap;
} LH_MSG_CAP_CLOSED;

typedef		struct lh_cap_opened_message  {
	LH_ADDR_CAP		cap;
} LH_MSG_CAP_OPENED;

typedef		struct lh_clean_transport_message  {
	LH_ADDR_TRANSPORT		transport;
} LH_MSG_CLEAN_TRANSPORT;

typedef		enum  {
	LH_DM_CONDITION_FIRST = 0,
	LH_DM_CONDITION_DEGRADED,
	LH_DM_CONDITION_INOPERATIVE,
	LH_DM_CONDITION_LAST
} LH_DM_CONDITION;

typedef		struct lh_degraded_mode_message  {
	LH_ADDR		device;
	LH_DM_CONDITION		condition;
	unsigned short		fsc;
} LH_MSG_DEGRADED_MODE;

typedef		struct lh_door_closed_message  {
	LH_ADDR_LSM		lsm;
} LH_MSG_DOOR_CLOSED;

typedef		struct lh_door_opened_message  {
	LH_ADDR_LSM		lsm;
} LH_MSG_DOOR_OPENED;

typedef		struct lh_lmu_ready_message  {
	LH_ADDR_LMU		lmu;
} LH_MSG_LMU_READY;

typedef		enum  {
	LH_NR_REASON_FIRST = 0,
	LH_NR_REASON_CONFIG_MISMATCH,
	LH_NR_REASON_INIT_FAILED,
	LH_NR_REASON_LOST_COMM,
	LH_NR_REASON_MECHANISM_FAILED,

	LH_NR_REASON_PLAYGROUND_FULL,
	LH_NR_REASON_CAPACITY_MISMATCH,
	LH_NR_REASON_KEY_DOOR_OPEN,
	LH_NR_REASON_LAST
} LH_NR_REASON;

typedef		struct lh_lsm_not_ready_message  {
	LH_ADDR_LSM		lsm;
	LH_NR_REASON		reason;
} LH_MSG_LSM_NOT_READY;

typedef		struct lh_lsm_ready_message  {
	LH_ADDR_LSM		lsm;
} LH_MSG_LSM_READY;

typedef		struct lh_port_offline_message  {
	LH_ADDR_PORT		port;
} LH_MSG_PORT_OFFLINE;

typedef		struct lh_message  {
	IPC_HEADER		ipc_header;
	LH_MSG_TYPE		message_type;
	union  {
		LH_MSG_AVAILABLE		available;
		LH_MSG_CAP_CLOSED		cap_closed;
		LH_MSG_CAP_OPENED		cap_opened;
		LH_MSG_CLEAN_TRANSPORT		clean_transport;
		LH_MSG_DEGRADED_MODE		degraded_mode;
		LH_MSG_DOOR_CLOSED		door_closed;
		LH_MSG_DOOR_OPENED		door_opened;
		LH_MSG_LMU_READY		lmu_ready;
		LH_MSG_LSM_NOT_READY		lsm_not_ready;
		LH_MSG_LSM_READY		lsm_ready;
		LH_MSG_PORT_OFFLINE		port_offline;
	} message;
} LH_MESSAGE;


#endif /* _LH_DEFS_ */
