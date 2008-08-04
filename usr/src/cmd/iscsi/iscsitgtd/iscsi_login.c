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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/iscsi_protocol.h>
#include <arpa/inet.h>
#include <iscsitgt_impl.h>
#include "queue.h"
#include "iscsi_conn.h"
#include "iscsi_sess.h"
#include "iscsi_login.h"
#include "iscsi_provider_impl.h"
#include "utility.h"
#include "target.h"
#include "isns_client.h"

typedef enum auth_action {
	LOGIN_NO_AUTH,
	LOGIN_AUTH,
	LOGIN_DROP
} auth_action_t;

/*
 * Forward declarations
 */
static iscsi_login_rsp_hdr_t *make_login_response(iscsi_conn_t *c,
    iscsi_login_hdr_t *lhp);
static void send_login_reject(iscsi_conn_t *c, iscsi_login_hdr_t *lhp,
    int err_code);
static Boolean_t check_for_valid_I_T(iscsi_conn_t *c);
static auth_action_t login_set_auth(iscsi_sess_t *s);

/*
 * iscsi_null_callback - This callback may be used under certain
 * conditions when authenticating a target, but I'm not sure what
 * we need to do here.
 */
/* ARGSUSED */
static void
iscsi_null_callback(void *user_handle, void *message_handle, int auth_status)
{
}

/*
 * iscsi_find_key_value -
 */
static int
iscsi_find_key_value(char *param, char *ihp, char *pdu_end,
    char **value_start, char **value_end)
{
	char *str = param;
	char *text = ihp;
	char *value = NULL;

	if (value_start)
		*value_start = NULL;
	if (value_end)
		*value_end = NULL;

	/*
	 * make sure they contain the same bytes
	 */
	while (*str) {
		if (text >= pdu_end) {
			return (0);
		}
		if (*text == '\0') {
			return (0);
		}
		if (*str != *text) {
			return (0);
		}
		str++;
		text++;
	}

	if ((text >= pdu_end) ||
	    (*text == '\0') ||
	    (*text != ISCSI_TEXT_SEPARATOR)) {
		return (0);
	}

	/*
	 * find the value
	 */
	value = text + 1;

	/*
	 * find the end of the value
	 */
	while ((text < pdu_end) && (*text))
		text++;

	if (value_start)
		*value_start = value;
	if (value_end)
		*value_end = text;

	return (1);
}

Boolean_t
iscsi_handle_login_pkt(iscsi_conn_t *c)
{
	iscsi_login_hdr_t	lh;
	iscsi_login_rsp_hdr_t	*rsp		= NULL;
	Boolean_t		rval		= False;
	IscsiAuthClient		*auth_client	= NULL;
	char			*text		= NULL;
	char			*end		= NULL;
	char			*text_rsp	= NULL;
	char			debug[128];
	int			debug_status	= 0;
	int			errcode		= 0;
	int			text_length	= 0;
	int			keytype		= 0;
	int			transit		= 0;
	int			rc		= 0;
	auth_action_t		auth_action	= LOGIN_DROP;
	tgt_node_t		*tnode		= NULL;

	if (read(c->c_fd, &lh, sizeof (lh)) != sizeof (lh)) {
		queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log,
		    "Header to small");
		return (False);
	}

	if ((lh.opcode & ISCSI_OPCODE_MASK) != ISCSI_OP_LOGIN_CMD) {
		(void) snprintf(debug, sizeof (debug),
		    "CON%x  Wrong OP code for state (Got 0x%x, Expected 0x%x)",
		    c->c_num, lh.opcode, ISCSI_OP_LOGIN_CMD);
		queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
		send_login_reject(c, &lh,
		    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
		    ISCSI_LOGIN_STATUS_INVALID_REQUEST);
		conn_state(c, T7);
		return (True);
	}

	if (ISCSI_LOGIN_COMMAND_ENABLED()) {
		uiscsiproto_t info;
		char nil = '\0';

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = &nil;
		info.uip_initiator = &nil;
		info.uip_lun = 0;

		info.uip_itt = lh.itt;
		info.uip_ttt = ISCSI_RSVD_TASK_TAG;

		info.uip_cmdsn = ntohl(lh.cmdsn);
		info.uip_statsn = ntohl(lh.expstatsn);
		info.uip_datasn = 0;

		info.uip_datalen = ntoh24(lh.dlength);
		info.uip_flags = lh.flags;

		ISCSI_LOGIN_COMMAND(&info);
	}

	if ((rval = session_alloc(c, lh.isid)) == False) {
		conn_state(c, T7);
		return (True);
	}

	connection_parameters_default(c);

	c->c_cid	= ntohl(lh.cid);
	c->c_statsn	= ntohl(lh.expstatsn);

	(void) pthread_mutex_lock(&c->c_sess->s_mutex);
	c->c_sess->s_cmdsn	= ntohl(lh.cmdsn);
	c->c_sess->s_seencmdsn	= ntohl(lh.cmdsn);
	(void) pthread_mutex_unlock(&c->c_sess->s_mutex);

	/*
	 * Is this a new session or an attempt to add a connection to
	 * an existing session.
	 */
	if (ntohs(lh.tsid) != 0) {

		/* Multiple connections per session not handled right now */
		conn_state(c, T7);
		return (True);
	}

	if ((rsp = make_login_response(c, &lh)) == NULL) {
		(void) snprintf(debug, sizeof (debug),
		    "CON%x  Failed make_login_response", c->c_num);
		queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
		return (False);
	}
	/* default is ISCSI_FLAG_LOGIN_TRANSIT, not good for login */
	rsp->flags = 0;

	if ((rsp->active_version < lh.min_version) ||
	    (rsp->active_version > lh.max_version)) {
		(void) snprintf(debug, sizeof (debug),
		    "CON%x  Version: Active %d, min %d, max %d", c->c_num,
		    rsp->active_version, lh.min_version, lh.max_version);
		send_login_reject(c, &lh,
		    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
		    ISCSI_LOGIN_STATUS_NO_VERSION);
		queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
		conn_state(c, T7);
		free(rsp);
		return (True);
	}

	if (lh.flags & ISCSI_FLAG_LOGIN_CONTINUE) {
		(void) snprintf(debug, sizeof (debug),
		    "CON%x  Continuation pkt", c->c_num);
		queue_str(c->c_mgmtq, Q_CONN_LOGIN, msg_log, debug);
	}

	auth_client =
	    (c->c_sess->sess_auth.auth_buffers &&
	    c->c_sess->sess_auth.num_auth_buffers) ?
	    (IscsiAuthClient *) c->c_sess->sess_auth.auth_buffers[0].address :
	    NULL;

	if (c->auth_text != NULL)
		free(c->auth_text);
	c->auth_text_length = 0;

	transit = lh.flags & ISCSI_FLAG_LOGIN_TRANSIT;

	switch (ISCSI_LOGIN_CURRENT_STAGE(lh.flags)) {
	case ISCSI_SECURITY_NEGOTIATION_STAGE:

		/*
		 * Grab the parameters and create the response
		 * text.
		 */
		rval = parse_text(c, ntoh24(lh.dlength),
		    &text_rsp, &text_length, &errcode);
		if (rval == False) {
			send_login_reject(c, &lh, errcode);
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  SecurityNegotiation: parse_text"
			    " failed", c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			conn_state(c, T7);
			break;
		}

		if ((rval = check_for_valid_I_T(c)) == False) {
			send_login_reject(c, &lh,
			    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
			    ISCSI_LOGIN_STATUS_INIT_ERR);
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  SecurityNegotiation: invalid I "
			    "or T", c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			conn_state(c, T7);
			break;
		}

		auth_action = login_set_auth(c->c_sess);

		if (auth_action == LOGIN_NO_AUTH) {
			rsp->flags |= ISCSI_FLAG_LOGIN_TRANSIT;
			rsp->flags |= ISCSI_OP_PARMS_NEGOTIATION_STAGE;
			rval = add_text(&text_rsp, &text_length, "AuthMethod",
			    "None");
			if (rval == False) {
				send_login_reject(c, &lh,
				    (ISCSI_STATUS_CLASS_TARGET_ERR << 8) |
				    ISCSI_LOGIN_STATUS_TARGET_ERROR);
				(void) snprintf(debug, sizeof (debug),
				    "CON%x Norm: Failed to add AuthMethod=None",
				    c->c_num);
				queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log,
				    debug);
				conn_state(c, T7);
			}
			break;
		}

		if (auth_action == LOGIN_DROP) {
			send_login_reject(c, &lh,
			    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
			    ISCSI_LOGIN_STATUS_TGT_FORBIDDEN);
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  SecurityNegotiation: access denied",
			    c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			conn_state(c, T7);
			rval = False;
			break;
		}

		if (iscsiAuthClientRecvBegin(auth_client) !=
		    iscsiAuthStatusNoError) {
			(void) snprintf(debug, sizeof (debug), "CON%x  "
			    "login failed - authentication receive failed",
			    c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			break;
		}

		if (iscsiAuthClientRecvTransitBit(auth_client,
		    transit) != iscsiAuthStatusNoError) {
			(void) snprintf(debug, sizeof (debug),
			    "iscsi connection(%u) login failed - "
			    "authentication transmit failed", c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			break;
		}

		/*
		 * scan the text data
		 */
		text = c->auth_text;
		end = text + c->auth_text_length;
more_text:
		while (text && (text < end)) {
			char *value = NULL;
			char *value_end = NULL;
			keytype = iscsiAuthKeyTypeNone;

			/*
			 * skip any NULs separating each text key=value pair
			 */
			while ((text < end) && (*text == '\0')) {
				text++;
			}
			if (text >= end) {
				break;
			}

			while (iscsiAuthClientGetNextKeyType(&keytype) ==
			    iscsiAuthStatusNoError) {
				char *key =
				    (char *)iscsiAuthClientGetKeyName(keytype);
				if ((key) &&
				    (iscsi_find_key_value(key, text, end,
				    &value, &value_end))) {
					(void) snprintf(debug, sizeof (debug),
					    "%s=%s", key, value);
					queue_str(c->c_mgmtq, Q_CONN_ERRS,
					    msg_log, debug);
					if (iscsiAuthClientRecvKeyValue(
					    auth_client, keytype, value)
					    != iscsiAuthStatusNoError) {
						(void) snprintf(debug,
						    sizeof (debug),
						    "iscsi connection(%u) login"
						    "failed - can't accept "
						    "%s in security stage",
						    c->c_num, text);
						queue_str(c->c_mgmtq,
						    Q_CONN_ERRS,
						    msg_log, debug);
					}
					text = value_end;
					goto more_text;
				}
			}
		}

		switch (iscsiAuthClientRecvEnd(auth_client, iscsi_null_callback,
		    (void *)c->c_sess, NULL)) {
		case iscsiAuthStatusContinue:
			/*
			 * continue sending PDUs
			 */
			break;

		case iscsiAuthStatusPass:
			c->c_auth_pass = 1;
			break;

		case iscsiAuthStatusInProgress:
			/*
			 * this should only occur if we were authenticating the
			 * target, which we don't do yet, so treat this as an
			 * error.
			 */
		case iscsiAuthStatusNoError:
			/*
			 * treat this as an error, since we should get a
			 * different code
			 */
		case iscsiAuthStatusError:
		case iscsiAuthStatusFail:
		default:
			debug_status = 0;

			(void) iscsiAuthClientGetDebugStatus(auth_client,
			    &debug_status);
			(void) snprintf(debug, sizeof (debug),
			    "iscsi connection(%u) authentication failed (%s)",
			    c->c_num, iscsiAuthClientDebugStatusToText(
			    debug_status));
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);

			send_login_reject(c, &lh,
			    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
			    ISCSI_LOGIN_STATUS_AUTH_FAILED);
			conn_state(c, T7);
			rval = False;
			break;
		}

		if (rval == False)
			break;

		keytype = iscsiAuthKeyTypeNone;
		rc = iscsiAuthClientSendTransitBit(auth_client, &transit);

		/*
		 * see if we're ready for a stage change
		 */
		if (rc == iscsiAuthStatusNoError) {
			if (transit) {
				rsp->flags = lh.flags;
			}

		} else {
			send_login_reject(c, &lh,
			    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
			    ISCSI_LOGIN_STATUS_AUTH_FAILED);
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  SecurityNegotiation: wants", c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			conn_state(c, T7);
			rval = False;
		}

		/*
		 * enumerate all the keys the auth code might want to send
		 */
		while (iscsiAuthClientGetNextKeyType(&keytype) ==
		    iscsiAuthStatusNoError) {
			int present = 0;
			char *key = (char *)iscsiAuthClientGetKeyName(keytype);
			int key_length = key ? strlen(key) : 0;
			int pdu_length = ntoh24(rsp->dlength);
			char *auth_value = NULL;
			unsigned int max_length = ISCSI_DEFAULT_MAX_XMIT_SEG_LEN
			    - (pdu_length + key_length + 1); /* FIXME: check */

			/*
			 * add the key/value pairs the auth code wants to
			 * send directly to the PDU, since they could in
			 * theory be large.
			 */
			if ((auth_value = (char *)malloc(max_length)) ==
			    NULL) {
				send_login_reject(c, &lh,
				    (ISCSI_STATUS_CLASS_TARGET_ERR << 8) |
				    ISCSI_LOGIN_STATUS_TARGET_ERROR);

				(void) snprintf(debug, sizeof (debug),
				    "CON%x Norm: Failed alloc auth_key %S=%s",
				    c->c_num, key, auth_value);
				queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log,
				    debug);
				conn_state(c, T7);
				rval = False;
				break;
			}
			rc = iscsiAuthClientSendKeyValue(auth_client, keytype,
			    &present, auth_value, max_length);
			if ((rc == iscsiAuthStatusNoError) && present) {
				(void) snprintf(debug, sizeof (debug),
				    "key:%s, auth_value:%s\n", key, auth_value);
				queue_str(c->c_mgmtq, Q_CONN_LOGIN, msg_log,
				    debug);

				rval = add_text(&text_rsp, &text_length,
				    key, auth_value);
				if (rval == False) {
					send_login_reject(c, &lh,
					    (ISCSI_STATUS_CLASS_TARGET_ERR <<
					    8) |
					    ISCSI_LOGIN_STATUS_TARGET_ERROR);
					(void) snprintf(debug, sizeof (debug),
					    "CON%x Norm: Failed to add %S=%s",
					    c->c_num, key, auth_value);
					queue_str(c->c_mgmtq, Q_CONN_ERRS,
					    msg_log, debug);
					conn_state(c, T7);
				}
			}
			if (auth_value != NULL)
				free(auth_value);
		}

		break;

	case ISCSI_OP_PARMS_NEGOTIATION_STAGE:

		/*
		 * Gather up the parameters sent across and build a response
		 * based on any selection required.
		 */
		if ((rval = parse_text(c, ntoh24(lh.dlength), &text_rsp,
		    &text_length, &errcode)) == False) {

			send_login_reject(c, &lh, errcode);
			(void) snprintf(debug, sizeof (debug),
			    "CON%x  Norm: parse_text failed", c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			conn_state(c, T7);
			break;
		}

		/*
		 * If the connection hasn't passed authentication and
		 * it's a normal session see if this connection MUST
		 * have gone through authentication first. If the
		 * initiator has a CHAP secret stored that means we
		 * want to validate.
		 */
		if ((c->c_auth_pass == 0) &&
		    (c->c_sess->s_type == SessionNormal)) {
			if ((tnode = find_target_node(c->c_sess->s_t_name)) ==
			    NULL) {
				send_login_reject(c, &lh,
				    (ISCSI_STATUS_CLASS_TARGET_ERR << 8) |
				    ISCSI_LOGIN_STATUS_TARGET_ERROR);
				(void) snprintf(debug, sizeof (debug),
				    "CON%x  No target node in login",
				    c->c_num);
				queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log,
				    debug);
				conn_state(c, T7);
			}

			/*
			 * check_access will return True if the initiator
			 * is required to use CHAP authentication. So if
			 * true and we're here it means that the initiator
			 * is trying to skip the authentication step.
			 */
			if (check_access(tnode, c->c_sess->s_i_name, True) ==
			    False) {
				send_login_reject(c, &lh,
				    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
				    ISCSI_LOGIN_STATUS_AUTH_FAILED);
				(void) snprintf(debug, sizeof (debug),
				    "CON%x  Authentication required for %s",
				    c->c_num, c->c_sess->s_i_name);
				queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log,
				    debug);
				conn_state(c, T7);
			}
		}

		if ((rval = check_for_valid_I_T(c)) == False) {
			send_login_reject(c, &lh,
			    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
			    ISCSI_LOGIN_STATUS_INIT_ERR);

			(void) snprintf(debug, sizeof (debug),
			    "CON%x  Norm: bad I or T", c->c_num);
			queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
			conn_state(c, T7);
			break;
		}

		/*
		 * We accept transition and stage information as is
		 * and echo it back because at this point there's no need
		 * to send a parameter to the Initiator and expect a
		 * reply.
		 */
		rsp->flags = lh.flags;

		break;

	case ISCSI_FULL_FEATURE_PHASE:
		/* can't jump directly to full feature phase */
		(void) snprintf(debug, sizeof (debug),
		    "CON%x  Protocol error: wrong stage", c->c_num);
		queue_str(c->c_mgmtq, Q_CONN_ERRS, msg_log, debug);
		send_login_reject(c, &lh,
		    (ISCSI_STATUS_CLASS_INITIATOR_ERR << 8) |
		    ISCSI_LOGIN_STATUS_INIT_ERR);
		conn_state(c, T7);
		rval = False;
		break;

	default:
		/* just drop the connection since we don't know what's up */
		rval = False;
		break;
	}

	hton24(rsp->dlength, text_length);
	if ((rval == True) && (session_validate(c->c_sess) == True)) {

		if (ISCSI_LOGIN_RESPONSE_ENABLED()) {
			uiscsiproto_t info;
			char nil = '\0';

			info.uip_target_addr = &c->c_target_sockaddr;
			info.uip_initiator_addr = &c->c_initiator_sockaddr;

			info.uip_target = &nil;
			info.uip_initiator = c->c_sess->s_i_name;
			info.uip_lun = 0;

			info.uip_itt = rsp->itt;
			info.uip_ttt = ISCSI_RSVD_TASK_TAG;

			info.uip_cmdsn = ntohl(rsp->expcmdsn);
			info.uip_statsn = ntohl(rsp->statsn);
			info.uip_datasn = 0;

			info.uip_datalen = text_length;
			info.uip_flags = rsp->flags;

			ISCSI_LOGIN_RESPONSE(&info);
		}

		send_iscsi_pkt(c, (iscsi_hdr_t *)rsp, text_rsp);

		if ((lh.flags & ISCSI_FLAG_LOGIN_TRANSIT) &&
		    (ISCSI_LOGIN_NEXT_STAGE(lh.flags) ==
		    ISCSI_FULL_FEATURE_PHASE)) {

			conn_state(c, T5);

			/*
			 * At this point we've completed the negotiation
			 * of all login parameters. Now we need to perform
			 * some quick boundary checks and then send a couple
			 * pieces of information to STE for it's use.
			 */
			c->c_max_burst_len = MIN(c->c_max_burst_len,
			    c->c_max_recv_data);
		}
	}

	if (text_rsp != NULL)
		free(text_rsp);
	if (rsp != NULL)
		free(rsp);

	return (rval);
}

/*
 * check_for_valid_I_T -- check to see if we have valid names
 *
 * This routine checks to see if we have received a valid InitiatorName
 * and TargetName which is the bare minimum which an Initiator must send
 * across during the login phase.
 */
static Boolean_t
check_for_valid_I_T(iscsi_conn_t *c)
{
	iscsi_sess_t	*s = c->c_sess;
	if (s->s_type == SessionDiscovery)
		return (s->s_i_name == NULL || strlen(s->s_i_name) == 0) ?
		    False : True;
	else
		return (s->s_t_name == NULL || strlen(s->s_t_name) == 0) ||
		    (s->s_i_name == NULL || strlen(s->s_i_name) == 0) ?
		    False : True;
}

static iscsi_login_rsp_hdr_t *
make_login_response(iscsi_conn_t *c, iscsi_login_hdr_t *lhp)
{
	iscsi_login_rsp_hdr_t	*r;

	if (lhp->tsid != 0)
		/* don't except existing sessions for now */
		return (NULL);

	r = (iscsi_login_rsp_hdr_t *)calloc(sizeof (*r), sizeof (char));
	if (r == NULL)
		return (NULL);

	bcopy(lhp->isid, r->isid, 6); /* 6 is defined by protocol */
	r->opcode		= ISCSI_OP_LOGIN_RSP;
	r->flags		= ISCSI_FLAG_LOGIN_TRANSIT;
	r->max_version		= ISCSI_MAX_VERSION;
	r->active_version	= ISCSI_MIN_VERSION;
	r->itt			= lhp->itt;

	/*
	 * As per section 10.13.3 of iSCSI RFC (3720), For a new session,
	 * the target MUST generate a non-zero TSIH and ONLY return it
	 * in the Login Final-Response
	 */
	if ((lhp->flags & ISCSI_FLAG_LOGIN_TRANSIT) &&
	    (ISCSI_LOGIN_NEXT_STAGE(lhp->flags) ==
	    ISCSI_FULL_FEATURE_PHASE))
		/*
		 * If this is the final Login Response, send the target
		 * calculated TSIH
		 */
		r->tsid		= htons(c->c_sess->s_tsid);
	else
		/*
		 * If this is not the final Login Response, send the TSIH value
		 * provided by the initiator.
		 */
		r->tsid		= lhp->tsid;

	(void) pthread_mutex_lock(&c->c_mutex);
	r->statsn		= htonl(c->c_statsn++);
	(void) pthread_mutex_unlock(&c->c_mutex);
	if (c->c_sess != NULL) {
		(void) pthread_mutex_lock(&c->c_sess->s_mutex);
		/* ---- cmdsn is not advanced during login ---- */
		r->expcmdsn	= htonl(c->c_sess->s_seencmdsn);
		r->maxcmdsn	= htonl(CMD_MAXOUTSTANDING +
		    c->c_sess->s_seencmdsn);
		(void) pthread_mutex_unlock(&c->c_sess->s_mutex);
	}

	return (r);
}

static void
send_login_reject(iscsi_conn_t *c, iscsi_login_hdr_t *lhp, int err_code)
{
	iscsi_login_rsp_hdr_t	*r;

	if ((r = make_login_response(c, lhp)) == NULL)
		return;

	r->status_class = (err_code >> 8) & 0xff;
	r->status_detail = err_code & 0xff;

	if (ISCSI_LOGIN_RESPONSE_ENABLED()) {
		uiscsiproto_t info;
		char nil = '\0';

		info.uip_target_addr = &c->c_target_sockaddr;
		info.uip_initiator_addr = &c->c_initiator_sockaddr;

		info.uip_target = &nil;
		info.uip_initiator = &nil;
		info.uip_lun = 0;

		info.uip_itt = r->itt;
		info.uip_ttt = ISCSI_RSVD_TASK_TAG;

		info.uip_cmdsn = ntohl(r->expcmdsn);
		info.uip_statsn = ntohl(r->statsn);
		info.uip_datasn = 0;

		info.uip_datalen = ntoh24(r->dlength);
		info.uip_flags = r->flags;

		ISCSI_LOGIN_RESPONSE(&info);
	}

	(void) write(c->c_fd, r, sizeof (*r));
	free(r);
}

static auth_action_t
login_set_auth(iscsi_sess_t *s)
{
	tgt_node_t *xnInitiator = NULL;
	tgt_node_t *xnTarget = NULL;
	tgt_node_t *xnAcl = NULL;
	char *szIniAlias = NULL;
	char *szIscsiName = NULL;
	char *szChapName = NULL;
	char *szChapSecret = NULL;
	char *possible = NULL;
	iscsi_auth_t *sess_auth = &(s->sess_auth);
	int comp = 0;
	int username_len = 0;

	bzero(sess_auth->username_in, sizeof (sess_auth->username_in));
	bzero(sess_auth->password_in, sizeof (sess_auth->password_in));
	sess_auth->password_length_in = 0;

	/* Load alias, iscsi-name, chap-name, chap-secret from config file */
	while ((xnInitiator = tgt_node_next_child(main_config, XML_ELEMENT_INIT,
	    xnInitiator)) != NULL) {

		(void) tgt_find_value_str(xnInitiator, XML_ELEMENT_INIT,
		    &szIniAlias);

		if (tgt_find_value_str(xnInitiator, XML_ELEMENT_INAME,
		    &szIscsiName) == True) {

			comp = strcmp(s->s_i_name, szIscsiName);
			free(szIscsiName);
			szIscsiName = NULL;

			if (comp == 0) {

				if (tgt_find_value_str(xnInitiator,
				    XML_ELEMENT_CHAPNAME,
				    &szChapName) == True) {
					/*CSTYLED*/
					(void) strcpy(
					    (char *)sess_auth->username_in,
					    szChapName);
					username_len = strlen(szChapName);
					free(szChapName);
				}

				if (tgt_find_value_str(xnInitiator,
				    XML_ELEMENT_CHAPSECRET,
				    &szChapSecret) == True) {
					/*CSTYLED*/
					(void) strcpy(
					    (char *)sess_auth->password_in,
					    szChapSecret);
					sess_auth->password_length_in =
					    strlen(szChapSecret);
					free(szChapSecret);
				}
				break;
			}
		}
	}

	if (s->s_type == SessionDiscovery) {
		return (LOGIN_NO_AUTH);
	}

	if (s->s_t_name == NULL) {
		/*
		 * Should not happen for non-discovery session
		 */
		return (LOGIN_DROP);
	}

	/*
	 * If iSNS enabled set LOGIN_AUTH
	 */
	if (isns_enabled() == True) {
		if (username_len == 0)
			return (LOGIN_NO_AUTH);
		return (LOGIN_AUTH);
	}

	/*
	 * If no acc_list for current target
	 *    If no CHAP secret for the initiator, transit.
	 *    If CHAP secret exists for the initiator, it must be authed.
	 * If acc_list exists for the target, and
	 * If the initiator not in the list, drop it.
	 * If the initiator in the list, and
	 * If no CHAP name for the initiator, transit.
	 * If a CHAP name exists for the initiator, it must be authed.
	 */

	while ((xnTarget = tgt_node_next_child(targets_config, XML_ELEMENT_TARG,
	    xnTarget)) != NULL) {

		if ((tgt_find_value_str(xnTarget, XML_ELEMENT_INAME,
		    &szIscsiName) == False) || (szIscsiName == NULL)) {
			return (LOGIN_DROP);
		}

		comp = strcmp(szIscsiName, s->s_t_name);
		free(szIscsiName);
		szIscsiName = NULL;

		if (comp == 0) {

			if ((xnAcl = tgt_node_next(xnTarget,
			    XML_ELEMENT_ACLLIST, 0)) == NULL) {
				/*
				 * No acl_list found, return auth or no auth
				 */
				if (username_len == 0)
					return (LOGIN_NO_AUTH);
				return (LOGIN_AUTH);
			}

			/*
			 * This target has an access_list. Now compare
			 * those entries against the initiator who started
			 * this session.
			 */
			xnInitiator = NULL;
			while ((xnInitiator = tgt_node_next(xnAcl,
			    XML_ELEMENT_INIT, xnInitiator)) != NULL) {

				if ((tgt_find_value_str(xnInitiator,
				    XML_ELEMENT_INIT, &possible) == False) ||
				    (possible == NULL))
					continue;

				if (strcmp(szIniAlias, possible) == 0) {
					/*
					 * Found the initiator in acl-list,
					 * authentication needed
					 */
					free(possible);
					if (username_len == 0)
						return (LOGIN_NO_AUTH);
					else
						return (LOGIN_AUTH);
				}

				free(possible);
				possible = NULL;
			}
			/*
			 * Acl-list exists, while the initiator is not found in
			 * the list, we should drop the connection
			 */
			return (LOGIN_DROP);
		}
	}

	/* False means Need authentication */
	return (LOGIN_AUTH);
}
