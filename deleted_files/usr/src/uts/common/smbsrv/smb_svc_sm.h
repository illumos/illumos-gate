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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Structures and type definitions for the SMB module.
 */

#ifndef _SMBSRV_SMB_SVC_SM_H
#define	_SMBSRV_SMB_SVC_SM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * CIFS Service State Machine Definitions
 */

/*
 * Events
 *
 * SMB_SVCEVT_UNDEFINED		Invalid Event
 * SMB_SVCEVT_OPEN		Pseudo-device opened
 * SMB_SVCEVT_CLOSE		Pseudo-device closed
 * SMB_SVCEVT_OPEN_SUCCESS	Open actions completed successfully
 * SMB_SVCEVT_OPEN_FAILED	Open actions failed
 * SMB_SVCEVT_CLOSE_SUCCESS	Close actions completed successfully
 * SMB_SVCEVT_CONNECT		Connected and listening on SMB session port
 * SMB_SVCEVT_DISCONNECT	SMB connection dropped or failed to connect
 * SMB_SVCEVT_CONFIG		New config from smbd
 * SMB_SVCEVT_CONFIG_SUCCESS	Configuration updated successfully
 * SMB_SVCEVT_CONFIG_FAILED	Configuration update failed
 * SMB_SVCEVT_SESSION_CREATE	SMB port listener accepted a connection
 * SMB_SVCEVT_SESSION_DELETE	Session ended
 * SMB_SVCEVT_MAX_EVENT		Invalid Event
 */

typedef enum {
	SMB_SVCEVT_UNDEFINED = 0,
	SMB_SVCEVT_OPEN,
	SMB_SVCEVT_CLOSE,
	SMB_SVCEVT_OPEN_SUCCESS,
	SMB_SVCEVT_OPEN_FAILED,
	SMB_SVCEVT_CLOSE_SUCCESS,
	SMB_SVCEVT_CONNECT,
	SMB_SVCEVT_DISCONNECT,
	SMB_SVCEVT_CONFIG,
	SMB_SVCEVT_CONFIG_SUCCESS,
	SMB_SVCEVT_CONFIG_FAILED,
	SMB_SVCEVT_SESSION_CREATE,
	SMB_SVCEVT_SESSION_DELETE,
	SMB_SVCEVT_MAX_EVENT
} smb_svcevt_t;

/*
 * States
 *
 * SMB_SVCSTATE_UNDEFINED		Invalid state
 * SMB_SVCSTATE_INIT			Pseudo-driver loaded/idle
 * SMB_SVCSTATE_OPENING			Pseudo-driver opened, starting
 * SMB_SVCSTATE_CONFIG_WAIT		Waiting for configuration
 * SMB_SVCSTATE_CONNECTING		Waiting for socket bind to SMB
 * SMB_SVCSTATE_ONLINE			Online, accepting connections
 * SMB_SVCSTATE_RECONFIGURING		Updating config, no new connections
 * SMB_SVCSTATE_DISCONNECTING		Smbd requested shutdown, closing socket
 * SMB_SVCSTATE_SESSION_CLOSE		Shutting down, closing active sessions
 * SMB_SVCSTATE_CLOSING			Shutting down, releasing resources
 * SMB_SVCSTATE_ERROR_SESSION_CLOSE	Unexpected SMB socket error,
 *					closing active sessions
 * SMB_SVCSTATE_ERROR_CLOSING		Error, releasing resources
 * SMB_SVCSTATE_MAX_STATE		Invalid state
 */
typedef enum {
	SMB_SVCSTATE_UNDEFINED = 0,
	SMB_SVCSTATE_INIT,
	SMB_SVCSTATE_OPENING,
	SMB_SVCSTATE_CONFIG_WAIT,
	SMB_SVCSTATE_CONNECTING,
	SMB_SVCSTATE_ONLINE,
	SMB_SVCSTATE_RECONFIGURING,
	SMB_SVCSTATE_DISCONNECTING,
	SMB_SVCSTATE_SESSION_CLOSE,
	SMB_SVCSTATE_ERROR_SESSION_CLOSE,
	SMB_SVCSTATE_CLOSING,
	SMB_SVCSTATE_ERROR_CLOSING,
	SMB_SVCSTATE_ERROR,
	SMB_SVCSTATE_MAX_STATE
} smb_svcstate_t;

#ifdef _KERNEL
/* Event context */
typedef struct {
	smb_svcevt_t	sec_event;
	uintptr_t	sec_info;
} smb_event_ctx_t;

/* Service state machine context */
typedef struct {
	taskq_t			*ssc_taskq;
	krwlock_t		ssc_state_rwlock;
	kmutex_t		ssc_state_cv_mutex;
	kcondvar_t		ssc_state_cv;
	int			ssc_started;
	int			ssc_start_error;
	int			ssc_disconnect_error;
	smb_svcstate_t		ssc_state;
	smb_svcstate_t		ssc_last_state; /* Debug only */
	int			ssc_session_creates_waiting;
	int			ssc_deferred_session_count;
	list_t			ssc_deferred_sessions;
	int			ssc_active_session_count;
	list_t			ssc_active_sessions;
	uint32_t		ssc_error_no_resources;
} smb_svc_sm_ctx_t;

/*
 * SMB service state machine API
 */

extern int smb_svcstate_sm_init(smb_svc_sm_ctx_t *svc_sm);
extern void smb_svcstate_sm_fini(smb_svc_sm_ctx_t *svc_sm);
extern int smb_svcstate_sm_start(smb_svc_sm_ctx_t *svc_sm);
extern void smb_svcstate_sm_stop(smb_svc_sm_ctx_t *svc_sm);
extern boolean_t smb_svcstate_sm_busy(void);
extern void smb_svcstate_event(smb_svcevt_t event, uintptr_t event_info);
extern void smb_svcstate_lock_read(smb_svc_sm_ctx_t *svc_sm);
extern void smb_svcstate_unlock(smb_svc_sm_ctx_t *svc_sm);
extern smb_session_t *smb_svcstate_session_getnext(smb_svc_sm_ctx_t *svc_sm,
    smb_session_t *prev);
extern int smb_svcstate_session_count(smb_svc_sm_ctx_t *svc_sm);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SMBSRV_SMB_SVC_SM_H */
