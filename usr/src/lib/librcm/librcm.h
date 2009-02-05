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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBRCM_H
#define	_LIBRCM_H

#include <libnvpair.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <sys/time_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Flags for rcm requests
 */
#define	RCM_INCLUDE_SUBTREE	0x0001
#define	RCM_INCLUDE_DEPENDENT	0x0002
#define	RCM_QUERY		0x0004
#define	RCM_FORCE		0x0008
#define	RCM_FILESYS		0x0010	/* private to filesys module */
#define	RCM_NOPID		0x0020
#define	RCM_DR_OPERATION	0x0040
#define	RCM_MOD_INFO		0x0080	/* private */
#define	RCM_CAPACITY_ADD	0x0100
#define	RCM_CAPACITY_DELETE	0x0200
#define	RCM_QUERY_CANCEL	0x0400	/* private */
#define	RCM_SCOPE		0x0800
#define	RCM_REGISTER_DR		0x1000	/* private */
#define	RCM_REGISTER_EVENT	0x2000	/* private */
#define	RCM_REGISTER_CAPACITY	0x4000	/* private */
#define	RCM_SUSPENDED		0x8000	/* private */
#define	RCM_RETIRE_REQUEST	0x10000
#define	RCM_RETIRE_NOTIFY	0x20000

/*
 * RCM return values
 */
#define	RCM_SUCCESS		0
#define	RCM_FAILURE		-1
#define	RCM_CONFLICT		-2
#define	RCM_NO_CONSTRAINT	-3

/*
 * RCM resource states
 */
#define	RCM_STATE_UNKNOWN		0
#define	RCM_STATE_ONLINE		1
#define	RCM_STATE_ONLINING		2
#define	RCM_STATE_OFFLINE_FAIL		3
#define	RCM_STATE_OFFLINING		4
#define	RCM_STATE_OFFLINE		5
#define	RCM_STATE_REMOVING		6
#define	RCM_STATE_RESUMING		10
#define	RCM_STATE_SUSPEND_FAIL		11
#define	RCM_STATE_SUSPENDING		12
#define	RCM_STATE_SUSPEND		13
#define	RCM_STATE_REMOVE		14	/* private to rcm_daemon */
#define	RCM_STATE_OFFLINE_QUERYING	15
#define	RCM_STATE_OFFLINE_QUERY_FAIL	16
#define	RCM_STATE_OFFLINE_QUERY		17
#define	RCM_STATE_SUSPEND_QUERYING	18
#define	RCM_STATE_SUSPEND_QUERY_FAIL	19
#define	RCM_STATE_SUSPEND_QUERY		20

/*
 * RCM event attr and properties
 */
#define	RCM_RSRCNAME		"rcm.rsrcname"
#define	RCM_CLIENT_NAME		"rcm.client_name"
#define	RCM_CLIENT_EXPORTS	"rcm.client_exports"

/* Resource name to register for new links reconfigured */
#define	RCM_RESOURCE_LINK_NEW		"SUNW_event/resource/new/link"

/* Resource name to register for new physical data-links */
#define	RCM_RESOURCE_PHYSLINK_NEW	"SUNW_event/resource/new/physlink"

/* name-value pair definitions for rcm_notify_event() */
#define	RCM_NV_LINKID		"linkid"
#define	RCM_NV_RECONFIGURED	"reconfigured"

/*
 * rcm handles
 */
typedef struct rcm_handle rcm_handle_t;
typedef struct rcm_info rcm_info_t;
typedef rcm_info_t rcm_info_tuple_t;

/*
 * Interface definitions
 */
int rcm_alloc_handle(char *, uint_t, void *, rcm_handle_t **);
int rcm_free_handle(rcm_handle_t *);
int rcm_get_info(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_get_info_list(rcm_handle_t *, char **, uint_t, rcm_info_t **);
void rcm_free_info(rcm_info_t *);
int rcm_append_info(rcm_info_t **, rcm_info_t *);
rcm_info_tuple_t *rcm_info_next(rcm_info_t *, rcm_info_tuple_t *);
const char *rcm_info_rsrc(rcm_info_tuple_t *);
const char *rcm_info_info(rcm_info_tuple_t *);
const char *rcm_info_error(rcm_info_tuple_t *);
const char *rcm_info_modname(rcm_info_tuple_t *);
pid_t rcm_info_pid(rcm_info_tuple_t *);
int rcm_info_state(rcm_info_tuple_t *);
int rcm_info_seqnum(rcm_info_tuple_t *);
nvlist_t *rcm_info_properties(rcm_info_tuple_t *);

int rcm_request_offline(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_request_offline_list(rcm_handle_t *, char **, uint_t, rcm_info_t **);
int rcm_notify_online(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_notify_online_list(rcm_handle_t *, char **, uint_t, rcm_info_t **);
int rcm_notify_remove(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_notify_remove_list(rcm_handle_t *, char **, uint_t, rcm_info_t **);
int rcm_request_suspend(rcm_handle_t *, char *, uint_t, timespec_t *,
	rcm_info_t **);
int rcm_request_suspend_list(rcm_handle_t *, char **, uint_t, timespec_t *,
	rcm_info_t **);
int rcm_notify_resume(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_notify_resume_list(rcm_handle_t *, char **, uint_t, rcm_info_t **);
int rcm_notify_capacity_change(rcm_handle_t *, char *, uint_t, nvlist_t *,
	rcm_info_t **);
int rcm_request_capacity_change(rcm_handle_t *, char *, uint_t, nvlist_t *,
	rcm_info_t **);
int rcm_notify_event(rcm_handle_t *, char *, uint_t, nvlist_t *, rcm_info_t **);

int rcm_register_event(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_register_capacity(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_register_interest(rcm_handle_t *, char *, uint_t, rcm_info_t **);
int rcm_unregister_event(rcm_handle_t *, char *, uint_t);
int rcm_unregister_capacity(rcm_handle_t *, char *, uint_t);
int rcm_unregister_interest(rcm_handle_t *, char *, uint_t);

int rcm_get_rsrcstate(rcm_handle_t *, char *, int *);
int rcm_exec_cmd(char *);
const char *rcm_get_client_name(rcm_handle_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBRCM_H */
