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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */
#ifndef	_IDM_CONN_SM_H_
#define	_IDM_CONN_SM_H_

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * IDM connection state machine events.  Most events get generated internally
 * either by the state machine or by the IDM TX/RX code.  For example when IDM
 * receives a login request for a target connectionit will generate a
 * CE_LOGIN_RCV event.  Similarly when the target sends a successful login
 * response IDM generate a "CE_LOGIN_SUCCESS_SND" event.  The following
 * events are not detected on the TX/RX path and must be generated explicitly
 * by the client when appropriate:
 *
 * CE_LOGOUT_OTHER_CONN_RCV
 * CE_ASYNC_DROP_CONN_RCV   (Only because the message may be received on
 * a different connection from the connection being dropped)
 * CE_ASYNC_DROP_ALL_CONN_RCV
 * CE_LOGOUT_OTHER_CONN_SND
 * CE_ASYNC_DROP_ALL_CONN_SND
 *
 * The following events might occur in any state since they are driven
 * by the PDU's that IDM receives:
 *
 * CE_LOGIN_RCV
 * CE_LOGIN_SUCCESS_RCV
 * CE_LOGIN_FAIL_RCV
 * CE_LOGOUT_SUCCESS_RCV
 * CE_LOGOUT_FAIL_RCV
 * CE_ASYNC_LOGOUT_RCV
 * CE_MISC_RCV
 * CE_RX_PROTOCOL_ERROR
 */

#define	IDM_LOGIN_SECONDS	20
#define	IDM_LOGOUT_SECONDS	20
#define	IDM_CLEANUP_SECONDS	0

/* Update idm_ce_name table whenever connection events are modified */
typedef enum {
	CE_UNDEFINED = 0,

	/* Initiator events */
	CE_CONNECT_REQ,
	CE_CONNECT_FAIL,
	CE_CONNECT_SUCCESS,
	CE_LOGIN_SND,
	CE_LOGIN_SUCCESS_RCV,
	CE_LOGIN_FAIL_RCV,
	CE_LOGOUT_THIS_CONN_SND,
	CE_LOGOUT_OTHER_CONN_SND,
	CE_LOGOUT_SESSION_SND,
	CE_LOGOUT_SUCCESS_RCV,
	CE_LOGOUT_FAIL_RCV,
	CE_ASYNC_LOGOUT_RCV,
	CE_ASYNC_DROP_CONN_RCV,
	CE_ASYNC_DROP_ALL_CONN_RCV,

	/* Target events */
	CE_CONNECT_ACCEPT,
	CE_CONNECT_REJECT,
	CE_LOGIN_RCV,
	CE_LOGIN_TIMEOUT,
	CE_LOGIN_SUCCESS_SND,
	CE_LOGIN_FAIL_SND,
	CE_LOGIN_FAIL_SND_DONE,
	CE_LOGOUT_THIS_CONN_RCV,
	CE_LOGOUT_OTHER_CONN_RCV,
	CE_LOGOUT_SESSION_RCV,
	CE_LOGOUT_SUCCESS_SND,
	CE_LOGOUT_SUCCESS_SND_DONE,
	CE_LOGOUT_FAIL_SND,
	CE_LOGOUT_FAIL_SND_DONE,
	CE_CLEANUP_TIMEOUT,
	CE_ASYNC_LOGOUT_SND,
	CE_ASYNC_DROP_CONN_SND,
	CE_ASYNC_DROP_ALL_CONN_SND,
	CE_LOGOUT_TIMEOUT,

	/* Common events */
	CE_TRANSPORT_FAIL,
	CE_MISC_TX,
	CE_TX_PROTOCOL_ERROR,
	CE_MISC_RX,
	CE_RX_PROTOCOL_ERROR,
	CE_LOGOUT_SESSION_SUCCESS,
	CE_CONN_REINSTATE,
	CE_CONN_REINSTATE_SUCCESS,
	CE_CONN_REINSTATE_FAIL,
	CE_ENABLE_DM_SUCCESS,
	CE_ENABLE_DM_FAIL,

	/* Add new events above CE_MAX_EVENT */
	CE_MAX_EVENT
} idm_conn_event_t;

#ifdef IDM_CONN_SM_STRINGS
/* An array of event text values, for use in logging events */
static const char *idm_ce_name[CE_MAX_EVENT+1] = {
	"CE_UNDEFINED",
	"CE_CONNECT_REQ",
	"CE_CONNECT_FAIL",
	"CE_CONNECT_SUCCESS",
	"CE_LOGIN_SND",
	"CE_LOGIN_SUCCESS_RCV",
	"CE_LOGIN_FAIL_RCV",
	"CE_LOGOUT_THIS_CONN_SND",
	"CE_LOGOUT_OTHER_CONN_SND",
	"CE_LOGOUT_SESSION_SND",
	"CE_LOGOUT_SUCCESS_RCV",
	"CE_LOGOUT_FAIL_RCV",
	"CE_ASYNC_LOGOUT_RCV",
	"CE_ASYNC_DROP_CONN_RCV",
	"CE_ASYNC_DROP_ALL_CONN_RCV",
	"CE_CONNECT_ACCEPT",
	"CE_CONNECT_REJECT",
	"CE_LOGIN_RCV",
	"CE_LOGIN_TIMEOUT",
	"CE_LOGIN_SUCCESS_SND",
	"CE_LOGIN_FAIL_SND",
	"CE_LOGIN_FAIL_SND_DONE",
	"CE_LOGOUT_THIS_CONN_RCV",
	"CE_LOGOUT_OTHER_CONN_RCV",
	"CE_LOGOUT_SESSION_RCV",
	"CE_LOGOUT_SUCCESS_SND",
	"CE_LOGOUT_SUCCESS_SND_DONE",
	"CE_LOGOUT_FAIL_SND",
	"CE_LOGOUT_FAIL_SND_DONE",
	"CE_CLEANUP_TIMEOUT",
	"CE_ASYNC_LOGOUT_SND",
	"CE_ASYNC_DROP_CONN_SND",
	"CE_ASYNC_DROP_ALL_CONN_SND",
	"CE_LOGOUT_TIMEOUT",
	"CE_TRANSPORT_FAIL",
	"CE_MISC_TX",
	"CE_TX_PROTOCOL_ERROR",
	"CE_MISC_RX",
	"CE_RX_PROTOCOL_ERROR",
	"CE_LOGOUT_SESSION_SUCCESS",
	"CE_CONN_REINSTATE",
	"CE_CONN_REINSTATE_SUCCESS",
	"CE_CONN_REINSTATE_FAIL",
	"CE_ENABLE_DM_SUCCESS",
	"CE_ENABLE_DM_FAIL",
	"CE_MAX_EVENT"
};
#endif

/* Update idm_cs_name table whenever connection states are modified */
typedef enum {
	CS_S0_UNDEFINED = 0,

	CS_S1_FREE,
	CS_S2_XPT_WAIT,
	CS_S3_XPT_UP,
	CS_S4_IN_LOGIN,
	CS_S5_LOGGED_IN,
	CS_S6_IN_LOGOUT,
	CS_S7_LOGOUT_REQ,
	CS_S8_CLEANUP,
	CS_S9_INIT_ERROR,
	CS_S10_IN_CLEANUP,
	CS_S11_COMPLETE,
	CS_S12_ENABLE_DM,
	CS_S9A_REJECTED,
	CS_S9B_WAIT_SND_DONE,

	/* Add new connection states above CS_MAX_STATE */
	CS_MAX_STATE
} idm_conn_state_t;

#ifdef IDM_CONN_SM_STRINGS
/* An array of state text values, for use in logging state transitions */
static const char *idm_cs_name[CS_MAX_STATE+1] = {
	"CS_S0_UNDEFINED",
	"CS_S1_FREE",
	"CS_S2_XPT_WAIT",
	"CS_S3_XPT_UP",
	"CS_S4_IN_LOGIN",
	"CS_S5_LOGGED_IN",
	"CS_S6_IN_LOGOUT",
	"CS_S7_LOGOUT_REQ",
	"CS_S8_CLEANUP",
	"CS_S9_INIT_ERROR",
	"CS_S10_IN_CLEANUP",
	"CS_S11_COMPLETE",
	"CS_S12_ENABLE_DM",
	"CS_S9A_REJECTED",
	"CS_S9B_WAIT_SND_DONE",
	"CS_MAX_STATE"
};
#endif

/*
 * Currently the state machine has a condition where idm_login_timeout() is
 * left active after the connection has been closed. This causes the system
 * to panic when idm_login_timeout() modifies the freed memory. In an attempt
 * to isolate and find this issue special attention is being placed on
 * the ic_state_timeout value. After each untimeout call the value will now
 * be cleared. Just before the value is set the code will check for 0 and
 * display an error. One final change is being done in idm_conn_sm_fini() which
 * if ic_state_machine is not 0, an error message will be displayed and
 * untimeout() called. That should prevent customer sites from seeing the
 * panic. The code also calls ASSERT(0) which should cause a panic during
 * system test.
 */
#define	IDM_SM_TIMER_CHECK(ic) \
	if (ic->ic_state_timeout) { \
		cmn_err(CE_WARN, "%s: existing timeout still set. " \
		    "state: %s, last: %s\n", __func__, \
		    idm_cs_name[ic->ic_state], \
		    idm_cs_name[ic->ic_last_state]); \
		ASSERT(0); \
	}

#define	IDM_SM_TIMER_CLEAR(ic) \
	(void) untimeout(ic->ic_state_timeout); \
	ic->ic_state_timeout = 0;

typedef enum {
	CT_NONE = 0,
	CT_RX_PDU,
	CT_TX_PDU
} idm_pdu_event_type_t;

typedef enum {
	CA_TX_PROTOCOL_ERROR,	/* Send "protocol error" to state machine */
	CA_RX_PROTOCOL_ERROR,	/* Send "protocol error" to state machine */
	CA_FORWARD,		/* State machine event and forward to client */
	CA_DROP			/* Drop PDU */
} idm_pdu_event_action_t;

typedef struct {
	struct idm_conn_s	*iec_ic;
	idm_conn_event_t	iec_event;
	uintptr_t		iec_info;
	idm_pdu_event_type_t	iec_pdu_event_type;
	boolean_t		iec_pdu_forwarded;
} idm_conn_event_ctx_t;

idm_status_t
idm_conn_sm_init(struct idm_conn_s *ic);

void
idm_conn_sm_fini(struct idm_conn_s *ic);

idm_status_t
idm_notify_client(struct idm_conn_s *ic, idm_client_notify_t cn,
    uintptr_t data);

void
idm_conn_event(struct idm_conn_s *ic, idm_conn_event_t event, uintptr_t data);

void
idm_conn_event(struct idm_conn_s *ic, idm_conn_event_t event, uintptr_t data);

void
idm_conn_event_locked(struct idm_conn_s *ic, idm_conn_event_t event,
    uintptr_t event_info, idm_pdu_event_type_t pdu_event_type);

idm_status_t
idm_conn_reinstate_event(struct idm_conn_s *old_ic, struct idm_conn_s *new_ic);

void
idm_conn_tx_pdu_event(struct idm_conn_s *ic, idm_conn_event_t event,
    uintptr_t data);

void
idm_conn_rx_pdu_event(struct idm_conn_s *ic, idm_conn_event_t event,
    uintptr_t data);

char *
idm_conn_state_str(struct idm_conn_s *ic);

#ifdef	__cplusplus
}
#endif

#endif /* _IDM_CONN_SM_H_ */
