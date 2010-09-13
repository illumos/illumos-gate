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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef _ISNS_CLIENT_H_
#define	_ISNS_CLIENT_H_

#include "iscsit.h"

/*
 * List of iSNS servers with which we register.
 */

typedef struct {
	int			svr_retry_count;
	struct sockaddr_storage	svr_sa;
	clock_t			svr_last_msg;
	list_node_t		svr_ln;
	uint32_t		svr_registered:1,
				svr_reset_needed:1,
				svr_delete_needed:1,
				svr_targets_changed:1,
				svr_monitor_hold:1;
	uint32_t		svr_last_target_index;
	uint32_t		svr_esi_interval;
	avl_tree_t		svr_target_list;
} iscsit_isns_svr_t;

/*
 * Type of registration to perform (deregister, register, update)
 */
typedef enum {
	ISNS_DEREGISTER_TARGET = 0,
	ISNS_DEREGISTER_ALL,
	ISNS_REGISTER_TARGET,
	ISNS_REGISTER_ALL,
	ISNS_MODIFY_TARGET
} isns_reg_type_t;

/*
 * This structure is used to keep state with regard to the RX threads used
 * for ESI.
 */


typedef struct {
	kthread_t			*esi_thread;
	kt_did_t			esi_thread_did;
	ksocket_t			esi_so;
	kmutex_t			esi_mutex;
	kcondvar_t			esi_cv;
	uint16_t			esi_port;
	boolean_t			esi_enabled;
	boolean_t			esi_valid;
	boolean_t			esi_thread_running;
} isns_esi_tinfo_t;


/*
 * Portal list - both default portals from idm_get_ipaddr and portals
 * defined in target port groups.
 */

typedef struct isns_portal_s {
	struct sockaddr_storage		portal_addr;
	avl_node_t			portal_node;
	timespec_t			portal_esi_timestamp;
	iscsit_portal_t			*portal_iscsit;	/* if in TPG */
	boolean_t			portal_default; /* if in default */
} isns_portal_t;


typedef struct isns_tpgt_addr_s {
	list_node_t		portal_ln;
	struct sockaddr_storage	portal_addr;
} isns_tpgt_addr_t;

typedef struct isns_tpgt_s {
	list_node_t		ti_tpgt_ln;
	uint16_t		ti_tpgt_tag;
	list_t			ti_portal_list;
} isns_tpgt_t;

typedef struct isns_target_info_s {
	idm_refcnt_t		ti_refcnt;
	char			ti_tgt_name[MAX_ISCSI_NODENAMELEN];
	char			ti_tgt_alias[MAX_ISCSI_NODENAMELEN];
	list_t			ti_tpgt_list;
} isns_target_info_t;

/* Contents of isns_target_list and svr->svr_target_list */
typedef struct isns_target_s {
	iscsit_tgt_t		*target;
	avl_node_t		target_node;
	boolean_t		target_registered;
	boolean_t		target_update_needed;
	boolean_t		target_delete_needed;
	isns_target_info_t	*target_info;
} isns_target_t;

/*
 * If no ESI request is received within this number of intervals, we'll
 * try to re-register with the server.
 */
#define	MAX_ESI_INTERVALS			3

/*
 * Interval to ask the server to send us ESI probes, in seconds.
 */
#define	ISNS_DEFAULT_ESI_INTERVAL		20

/*
 * Registration Period (when not using ESI), in seconds. (15 min)
 */
#define	ISNS_DEFAULT_REGISTRATION_PERIOD	900

/*
 * Initial delay before sending first DevAttrReg message.
 */
#define	ISNS_INITIAL_DELAY			5

it_cfg_status_t
isnst_config_merge(it_config_t *cfg);

int iscsit_isns_init(iscsit_hostinfo_t *hostinfo);
void iscsit_isns_fini();
int iscsit_isns_register(iscsit_tgt_t *target);
int iscsit_isns_deregister(iscsit_tgt_t *target);
void iscsit_isns_target_update(iscsit_tgt_t *target);
void iscsit_isns_portal_online(iscsit_portal_t *portal);
void iscsit_isns_portal_offline(iscsit_portal_t *portal);

#endif /* _ISNS_CLIENT_H_ */
