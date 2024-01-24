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
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains private data structures and APIs of libnwam.  Currently
 * these are used by nwamd (nwam_event_*() and nwam_record_audit_event()) and
 * netcfgd (nwam_backend_*()) only, supporting the event messaging, audit
 * and backend configuration access that nwamd and netcfgd supply.
 *
 * Implementation is MT safe.
 */
#ifndef _LIBNWAM_PRIV_H
#define	_LIBNWAM_PRIV_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libnwam.h>

/* Name of directory containing the doors */
#define	NWAM_DOOR_DIR		"/etc/svc/volatile/nwam"

/* Name of door used to communicate with libnwam backend (in netcfgd) */
#define	NWAM_BACKEND_DOOR_FILE	NWAM_DOOR_DIR "/nwam_backend_door"

/* Name of door used to communicate with nwamd */
#define	NWAM_DOOR		NWAM_DOOR_DIR "/nwam_door"

/* Requests to nwamd door */
typedef enum {
	NWAM_REQUEST_TYPE_NOOP,
	NWAM_REQUEST_TYPE_EVENT_REGISTER,
	NWAM_REQUEST_TYPE_EVENT_UNREGISTER,
	NWAM_REQUEST_TYPE_ACTION,
	NWAM_REQUEST_TYPE_STATE,
	NWAM_REQUEST_TYPE_PRIORITY_GROUP,
	NWAM_REQUEST_TYPE_WLAN_SCAN,
	NWAM_REQUEST_TYPE_WLAN_SCAN_RESULTS,
	NWAM_REQUEST_TYPE_WLAN_SELECT,
	NWAM_REQUEST_TYPE_WLAN_SET_KEY
} nwam_request_type_t;

/* Status returned by nwamd door */
typedef enum {
	NWAM_REQUEST_STATUS_OK,
	NWAM_REQUEST_STATUS_FAILED,
	NWAM_REQUEST_STATUS_UNKNOWN,
	NWAM_REQUEST_STATUS_ALREADY
} nwam_request_status_t;

#define	NWAMD_MAX_NUM_WLANS	64

typedef union {
	/* Used for EVENT_[UN]REGISTER requests */
	struct nwdad_register_info {
		char nwdad_name[MAXPATHLEN];
	} nwdad_register_info;

	/* Used for ACTION requests */
	struct nwdad_object_action {
		nwam_object_type_t nwdad_object_type;
		char nwdad_name[NWAM_MAX_NAME_LEN];
		char nwdad_parent[NWAM_MAX_NAME_LEN];
		nwam_action_t nwdad_action;
	} nwdad_object_action;

	/* Used for STATE requests */
	struct nwdad_object_state {
		nwam_object_type_t nwdad_object_type;
		char nwdad_name[NWAM_MAX_NAME_LEN];
		char nwdad_parent[NWAM_MAX_NAME_LEN];
		nwam_state_t nwdad_state;
		nwam_aux_state_t nwdad_aux_state;
	} nwdad_object_state;

	/* Used for PRIORITY_GROUP requests */
	struct nwdad_priority_group_info {
		int64_t nwdad_priority;
	} nwdad_priority_group_info;

	/* Used for WLAN request/responses */
	struct nwdad_wlan_info {
		char nwdad_name[NWAM_MAX_NAME_LEN];
		char nwdad_essid[NWAM_MAX_NAME_LEN];
		char nwdad_bssid[NWAM_MAX_NAME_LEN];
		uint32_t nwdad_security_mode;
		char nwdad_key[NWAM_MAX_NAME_LEN];
		uint_t nwdad_keyslot;
		boolean_t nwdad_add_to_known_wlans;
		uint_t nwdad_num_wlans;
		nwam_wlan_t nwdad_wlans[NWAMD_MAX_NUM_WLANS];
	} nwdad_wlan_info;

} nwamd_door_arg_data_t;

typedef struct {
	nwam_request_type_t nwda_type;
	nwam_request_status_t nwda_status;
	nwam_error_t nwda_error;
	uint32_t nwda_align;				/* for next member */
	nwamd_door_arg_data_t nwda_data;
} nwamd_door_arg_t;

typedef enum {
	NWAM_BACKEND_DOOR_CMD_READ_REQ,
	NWAM_BACKEND_DOOR_CMD_UPDATE_REQ,
	NWAM_BACKEND_DOOR_CMD_REMOVE_REQ
} nwam_backend_door_cmd_t;

typedef struct nwam_backend_door_arg {
	nwam_backend_door_cmd_t nwbda_cmd;
	char nwbda_dbname[MAXPATHLEN];			/* config filename */
	char nwbda_object[NWAM_MAX_NAME_LEN];		/* config object */
	uint32_t nwbda_datalen;				/* data follows arg */
	nwam_error_t nwbda_result;			/* return code */
	uint32_t nwbda_align;				/* for next member */
	uint64_t nwbda_flags;
} nwam_backend_door_arg_t;

/*
 * Functions needed to initialize/stop processing of libnwam backend data
 * (used in netcfgd).
 */
extern nwam_error_t nwam_backend_init(void);
extern void nwam_backend_fini(void);

/*
 * create audit session, report event, end session.  Used by nwamd.
 */
extern void nwam_record_audit_event(const ucred_t *, au_event_t, char *, char *,
    int, int);

/*
 * NWAM daemon functions, used to send, stop sending, initialize or finish
 * event IPC.  Used by nwamd.
 */
extern nwam_error_t nwam_event_send(nwam_event_t);
extern void nwam_event_send_fini(void);
extern nwam_error_t nwam_event_queue_init(const char *);
extern void nwam_event_queue_fini(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBNWAM_PRIV_H */
