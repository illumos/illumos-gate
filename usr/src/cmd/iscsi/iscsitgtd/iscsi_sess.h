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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SESSION_H
#define	_SESSION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/iscsi_authclient.h>
#include "iscsi_cmd.h"
#include "t10.h"

/*
 * iSCSI Auth Information
 */
typedef struct iscsi_auth {
	IscsiAuthStringBlock    auth_recv_string_block;
	IscsiAuthStringBlock    auth_send_string_block;
	IscsiAuthLargeBinary    auth_recv_binary_block;
	IscsiAuthLargeBinary    auth_send_binary_block;
	IscsiAuthClient		auth_client_block;
	int			num_auth_buffers;
	IscsiAuthBufferDesc	auth_buffers[5];

	/*
	 * To indicate if authentication is enabled.
	 * 0 means authentication disabled.
	 * 1 means authentication enabled.
	 */
	int			auth_enabled;

	/* Initiator's authentication information. */
	char			username[iscsiAuthStringMaxLength];
	uint8_t			password[iscsiAuthStringMaxLength];
	int			password_length;

	/* Target's authentication information. */
	char			username_in[iscsiAuthStringMaxLength];
	uint8_t			password_in[iscsiAuthStringMaxLength];
	int			password_length_in;
} iscsi_auth_t;

typedef enum iscsi_session_type {
	SessionDiscovery, SessionNormal
} iscsi_session_type_t;

typedef enum iscsi_session_state {
	SS_FREE, SS_STARTED, SS_RUNNING, SS_SHUTDOWN_START, SS_SHUTDOWN_CMPLT
} iscsi_sess_state_t;

typedef struct iscsi_sess {
	struct iscsi_sess	*s_next;

	iscsi_sess_state_t	s_state;

	/*
	 * Set during login
	 * mutex isn't held.
	 */
	char			*s_i_name,
				*s_i_alias,
				*s_t_name;
	uint8_t			s_isid[6];
	/*
	 * This is the highest packet number we've seen and is
	 * used during replies.
	 */
	int			s_seencmdsn;

	/*
	 * To keep the correct order of PDU's submitted to the SCSI
	 * layer we check that the incoming cmdsn matches this value.
	 * Otherwise, we're missing a packet and need to wait. This
	 * is particularly important with multiple connections per
	 * session.
	 */
	int			s_cmdsn;

	iscsi_session_type_t	s_type;

	/*
	 * Set during allocation of this struct and only referenced
	 */
	int			s_tsid;

	target_queue_t		*s_sessq,
				*s_t10q,
				*s_mgmtq;

	t10_targ_handle_t	s_t10;

	struct iscsi_conn	*s_conn_head;

	int			s_num;

	pthread_mutex_t 	s_mutex;
	iscsi_auth_t		sess_auth;
	pthread_t		s_thr_id_conn,
				s_thr_id_t10;
} iscsi_sess_t;

void session_init();
Boolean_t session_alloc(struct iscsi_conn *c, uint8_t *isid);
Boolean_t session_validate(struct iscsi_sess *s);

#ifdef __cplusplus
}
#endif

#endif /* _SESSION_H */
