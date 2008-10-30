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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _ISNS_CLIENT_H_
#define	_ISNS_CLIENT_H_

#include <iscsit.h>

/*
 * List of iSNS servers with which we register.
 */

typedef struct {
	int			svr_retry_count;
	struct sockaddr_storage	svr_sa;
	clock_t			svr_last_msg;
	list_node_t		svr_ln;
	boolean_t		svr_registered;
} iscsit_isns_svr_t;

/*
 * Type of registration to perform (deregister, register, update)
 */
typedef enum {
	ISNS_DEREGISTER_TARGET = 0,
	ISNS_DEREGISTER_ALL,
	ISNS_REGISTER_TARGET,
	ISNS_REGISTER_ALL,
	ISNS_UPDATE_TARGET
} isns_reg_type_t;

/*
 * This structure is used to keep state with regard to the RX threads used
 * for ESI.  There must always be a 1:1 correspondence between the entries
 * in this list and the entries in the portal_list.
 */

struct isns_portal_list_s;

typedef struct {
	struct isns_portal_list_s	*esi_portal;
	kthread_t			*esi_thread;
	kt_did_t			esi_thread_did;
	struct sonode			*esi_so;
	uint16_t			esi_port;
	boolean_t			esi_thread_running;
	boolean_t			esi_thread_failed;
	boolean_t			esi_registered;
	boolean_t			esi_not_available;
	list_node_t			esi_ln;
} isns_esi_tinfo_t;

/*
 * Portal list - comprised of "default" portals (i.e. idm_get_ipaddr) and
 * portals that are part of target portal groups.
 */

typedef struct isns_portal_list_s {
	struct sockaddr_storage		portal_addr;
	isns_esi_tinfo_t		*portal_esi;
	iscsit_portal_t			*portal_iscsit;
	list_node_t			portal_ln;
} isns_portal_list_t;

typedef struct isns_target_s {
	iscsit_tgt_t		*target;
	avl_node_t		target_node;
	boolean_t		target_registered;
} isns_target_t;

/*
 * If no ESI request is received within this number of intervals, we'll
 * try to re-register with the server.
 */
#define	MAX_ESI_INTERVALS	3

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
