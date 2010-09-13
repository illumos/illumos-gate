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

/*
 * SIP Client/Server Invite/Non-Invite Transaction State machine.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sip.h>

#include "sip_miscdefs.h"
#include "sip_msg.h"
#include "sip_xaction.h"

/*
 * Some Timer related info from RFC 3261, page 265.
 *
 * ----------------------------------------------------------------------
 * Timer    Value            Section               Meaning
 * ----------------------------------------------------------------------
 * T1       500ms default    Section 17.1.1.1     RTT Estimate
 * T2       4s               Section 17.1.2.2     The maximum retransmit
 *                                                interval for non-INVITE
 *                                                requests and INVITE
 *                                                responses
 * T4       5s               Section 17.1.2.2     Maximum duration a
 *                                                message will
 *                                                remain in the network
 * ----------------------------------------------------------------------
 * Timer A  initially T1     Section 17.1.1.2     INVITE request retransmit
 *                                                interval, for UDP only
 * Timer B  64*T1            Section 17.1.1.2     INVITE transaction
 *                                                timeout timer
 * Timer C  > 3min           Section 16.6         proxy INVITE transaction
 *                            bullet 11            timeout
 * Timer D  > 32s for UDP    Section 17.1.1.2     Wait time for response
 *          0s for TCP/SCTP                       retransmits
 * Timer E  initially T1     Section 17.1.2.2     non-INVITE request
 *                                                retransmit interval,
 *                                                UDP only
 * Timer F  64*T1            Section 17.1.2.2     non-INVITE transaction
 *                                                timeout timer
 * Timer G  initially T1     Section 17.2.1       INVITE response
 *                                                retransmit interval
 * Timer H  64*T1            Section 17.2.1       Wait time for
 *                                                ACK receipt
 * Timer I  T4 for UDP       Section 17.2.1       Wait time for
 *          0s for TCP/SCTP                       ACK retransmits
 * Timer J  64*T1 for UDP    Section 17.2.2       Wait time for
 *          0s for TCP/SCTP                       non-INVITE request
 *                                                retransmits
 * Timer K  T4 for UDP       Section 17.1.2.2     Wait time for
 *          0s for TCP/SCTP                       response retransmits
 * ----------------------------------------------------------------------
 */

#ifndef MIN
#define	MIN(a, b)	(((a) < (b)) ? (a):(b))
#endif

/*
 * Arg to the timer fire routine
 */
typedef	struct sip_xaction_timer_obj_s {
	sip_xaction_timer_type_t	sip_xaction_timer_type;
	sip_xaction_t			*sip_trans;
	int				sip_xaction_timer_xport;
} sip_xaction_time_obj_t;

int		sip_xaction_output(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t *);
int		sip_xaction_input(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t **);
void		sip_xaction_terminate(sip_xaction_t *, _sip_msg_t *, int);

static int 	sip_clnt_xaction_output(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t *);
static int	sip_clnt_xaction_input(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t **);
static int	sip_clnt_xaction_inv_res(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t **);
static int	sip_clnt_xaction_noninv_res(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t **);
static int 	sip_srv_xaction_output(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t *);
static int	sip_srv_xaction_input(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t **);
static int	sip_srv_xaction_inv_res(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t *);
static int	sip_srv_xaction_noninv_res(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t *);
static int	sip_create_send_nonOKack(sip_conn_object_t, sip_xaction_t *,
		    _sip_msg_t *, boolean_t);
void		sip_xaction_state_timer_fire(void *);

static sip_xaction_time_obj_t	*sip_setup_timer(sip_conn_object_t,
				    sip_xaction_t *, _sip_msg_t *,
				    sip_timer_t, int);

/*
 * Return a timer object
 */
static sip_xaction_time_obj_t *
sip_setup_timer(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t *sip_msg, sip_timer_t timer, int type)
{
	sip_xaction_time_obj_t	*sip_timer_obj = NULL;

	sip_timer_obj = (sip_xaction_time_obj_t *)
	    malloc(sizeof (sip_xaction_time_obj_t));
	if (sip_timer_obj == NULL)
		return (NULL);
	if (SIP_IS_TIMER_RUNNING(timer))
		SIP_CANCEL_TIMER(timer);
	sip_timer_obj->sip_xaction_timer_type = type;
	sip_timer_obj->sip_xaction_timer_xport = sip_conn_transport(conn_obj);
	sip_timer_obj->sip_trans = sip_trans;
	/*
	 * Save the message
	 */
	if (sip_msg != NULL) {
		(void) sip_add_conn_obj_cache(conn_obj, (void *)sip_trans);
		if (sip_trans->sip_xaction_last_msg != NULL) {
			SIP_MSG_REFCNT_DECR(sip_trans->sip_xaction_last_msg);
			sip_trans->sip_xaction_last_msg = NULL;
		}
		SIP_MSG_REFCNT_INCR(sip_msg);
		sip_trans->sip_xaction_last_msg = sip_msg;
	}
	return (sip_timer_obj);
}

/*
 * --------------------------- Output Routines ---------------------------
 */

/*
 * Send a SIP message, request or response, out
 */
int
sip_xaction_output(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t *msg)
{
	sip_message_type_t	*sip_msg_info;
	int			ret;

	if (conn_obj == NULL) {
		(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
		sip_write_to_log((void *)sip_trans, SIP_TRANSACTION_LOG |
		    SIP_ASSERT_ERROR, __FILE__, __LINE__);
		(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	}
	assert(conn_obj != NULL);
	sip_msg_info = msg->sip_msg_req_res;

	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	sip_trans->sip_xaction_msgcnt++;
	sip_add_log(&sip_trans->sip_xaction_log[sip_trans->sip_xaction_state],
	    (sip_msg_t)msg, sip_trans->sip_xaction_msgcnt, SIP_TRANSACTION_LOG);
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);

	if (sip_msg_info->is_request)
		return (sip_clnt_xaction_output(conn_obj, sip_trans, msg));

	ret = sip_srv_xaction_output(conn_obj, sip_trans, msg);

	return (ret);
}

/*
 * Send a Request out
 */
static int
sip_clnt_xaction_output(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t *msg)
{
	sip_xaction_time_obj_t	*timer_obj_A = NULL;
	sip_xaction_time_obj_t	*timer_obj_B = NULL;
	sip_xaction_time_obj_t	*timer_obj_E = NULL;
	sip_xaction_time_obj_t	*timer_obj_F = NULL;
	sip_message_type_t	*sip_msg_info;
	int			prev_state;
	int			error = 0;
	boolean_t		isreliable;

	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	prev_state = sip_trans->sip_xaction_state;
	if (msg->sip_msg_req_res == NULL) {
		sip_write_to_log((void *)sip_trans, SIP_TRANSACTION_LOG |
		    SIP_ASSERT_ERROR, __FILE__, __LINE__);
	}
	assert(msg->sip_msg_req_res != NULL);
	sip_msg_info = msg->sip_msg_req_res;
	isreliable = sip_is_conn_reliable(conn_obj);

	if (sip_msg_info->sip_req_method == INVITE) {
		/*
		 * if transport is not reliable, start TIMER A.
		 */
		if (!isreliable) {
			timer_obj_A = sip_setup_timer(conn_obj, sip_trans,
			    msg, sip_trans->sip_xaction_TA,
			    SIP_XACTION_TIMER_A);
			if (timer_obj_A == NULL) {
				error = ENOMEM;
				goto error_ret;
			}
		}

		timer_obj_B = sip_setup_timer(conn_obj, sip_trans, NULL,
		    sip_trans->sip_xaction_TB, SIP_XACTION_TIMER_B);
		if (timer_obj_B == NULL) {
			error = ENOMEM;
			goto error_ret;
		}
		if (timer_obj_A != NULL) {
			SIP_SCHED_TIMER(sip_trans->sip_xaction_TA, timer_obj_A,
			    sip_xaction_state_timer_fire);
			if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TA)) {
				error = ENOMEM;
				goto error_ret;
			}
		}
		SIP_SCHED_TIMER(sip_trans->sip_xaction_TB, timer_obj_B,
		    sip_xaction_state_timer_fire);
		if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TB)) {
			if (timer_obj_A != NULL)
				SIP_CANCEL_TIMER(sip_trans->sip_xaction_TA)
			error = ENOMEM;
			goto error_ret;
		}
		sip_trans->sip_xaction_state = SIP_CLNT_CALLING;
	} else {
		/*
		 * if transport is not reliable, start rexmit Timer E.
		 */
		if (!isreliable) {
			timer_obj_E = sip_setup_timer(conn_obj, sip_trans, msg,
			    sip_trans->sip_xaction_TE, SIP_XACTION_TIMER_E);
			if (timer_obj_E == NULL) {
				error = ENOMEM;
				goto error_ret;
			}
		}
		/*
		 * Start transaction Timer F
		 */
		timer_obj_F = sip_setup_timer(conn_obj, sip_trans, NULL,
		    sip_trans->sip_xaction_TF, SIP_XACTION_TIMER_F);
		if (timer_obj_F == NULL) {
			error = ENOMEM;
			goto error_ret;
		}
		if (timer_obj_E != NULL) {
			SIP_SCHED_TIMER(sip_trans->sip_xaction_TE, timer_obj_E,
			    sip_xaction_state_timer_fire);
			if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TE)) {
				error = ENOMEM;
				goto error_ret;
			}
		}
		SIP_SCHED_TIMER(sip_trans->sip_xaction_TF, timer_obj_F,
		    sip_xaction_state_timer_fire);
		if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TF)) {
			if (timer_obj_E != NULL)
				SIP_CANCEL_TIMER(sip_trans->sip_xaction_TE)
			error = ENOMEM;
			goto error_ret;
		}
		sip_trans->sip_xaction_state = SIP_CLNT_TRYING;
	}
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (sip_xaction_ulp_state_cb != NULL) {
		sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
		    (sip_msg_t)msg, prev_state, sip_trans->sip_xaction_state);
	}
	return (0);

error_ret:
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (timer_obj_A != NULL)
		free(timer_obj_A);
	if (timer_obj_B != NULL)
		free(timer_obj_B);
	if (timer_obj_E != NULL)
		free(timer_obj_E);
	if (timer_obj_F != NULL)
		free(timer_obj_F);
	return (error);
}

/*
 * Send a response out
 */
static int
sip_srv_xaction_output(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t *msg)
{
	int		ret;

	if (sip_trans->sip_xaction_method == INVITE)
		ret = sip_srv_xaction_inv_res(conn_obj, sip_trans, msg);
	else
		ret = sip_srv_xaction_noninv_res(conn_obj, sip_trans, msg);
	return (ret);
}

/*
 * Send a INVITE response out
 */
static int
sip_srv_xaction_inv_res(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t *msg)
{
	int			resp_code;
	sip_xaction_time_obj_t	*timer_obj_G = NULL;
	sip_xaction_time_obj_t	*timer_obj_H = NULL;
	sip_message_type_t	*sip_msg_info = msg->sip_msg_req_res;
	int			prev_state;
	boolean_t		isreliable;

	isreliable = sip_is_conn_reliable(conn_obj);

	resp_code = sip_msg_info->sip_resp_code;
	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	prev_state = sip_trans->sip_xaction_state;
	switch (sip_trans->sip_xaction_state) {
		case SIP_SRV_INV_PROCEEDING:
			if (SIP_PROVISIONAL_RESP(resp_code)) {
				if (sip_trans->sip_xaction_last_msg != NULL) {
					SIP_MSG_REFCNT_DECR(
					    sip_trans->sip_xaction_last_msg);
					sip_trans->sip_xaction_last_msg = NULL;
				}
				SIP_MSG_REFCNT_INCR(msg);
				sip_trans->sip_xaction_last_msg = msg;
				(void) sip_add_conn_obj_cache(conn_obj,
				    (void *)sip_trans);
			} else if (SIP_OK_RESP(resp_code)) {
				sip_trans->sip_xaction_state =
				    SIP_SRV_INV_TERMINATED;
			} else  if (SIP_NONOK_FINAL_RESP(resp_code)) {
				if (sip_trans->sip_xaction_last_msg != NULL) {
					SIP_MSG_REFCNT_DECR(
					    sip_trans->sip_xaction_last_msg);
					sip_trans->sip_xaction_last_msg = NULL;
				}
				SIP_MSG_REFCNT_INCR(msg);
				sip_trans->sip_xaction_last_msg = msg;
				(void) sip_add_conn_obj_cache(conn_obj,
				    (void *)sip_trans);
				/*
				 * For unreliable transport start timer G
				 */
				if (!isreliable) {
					timer_obj_G = sip_setup_timer(
					    conn_obj, sip_trans,
					    NULL, sip_trans->sip_xaction_TG,
					    SIP_XACTION_TIMER_G);
					if (timer_obj_G == NULL) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						return (ENOMEM);
					}
				}
				/*
				 * Start Timer H
				 */
				timer_obj_H = sip_setup_timer(
				    conn_obj, sip_trans,
				    NULL, sip_trans->sip_xaction_TH,
				    SIP_XACTION_TIMER_H);
				if (timer_obj_H == NULL) {
					if (timer_obj_G != NULL)
						free(timer_obj_G);
					(void) pthread_mutex_unlock(
					    &sip_trans->sip_xaction_mutex);
					return (ENOMEM);
				}
				if (timer_obj_G != NULL) {
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TG,
					    timer_obj_G,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TG)) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_G);
						return (ENOMEM);
					}
				}
				if (timer_obj_H != NULL) {
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TH,
					    timer_obj_H,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TH)) {
						if (timer_obj_G != NULL) {
							SIP_CANCEL_TIMER(
							    sip_trans->
							    sip_xaction_TG);
							free(timer_obj_G);
						}
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_H);
						return (ENOMEM);
					}
				}
				sip_trans->sip_xaction_state =
				    SIP_SRV_INV_COMPLETED;
			}
			break;
		default:
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (EPROTO);
	}
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (prev_state != sip_trans->sip_xaction_state &&
	    sip_xaction_ulp_state_cb != NULL) {
		sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
		    (sip_msg_t)msg, prev_state, sip_trans->sip_xaction_state);
	}
	return (0);
}

/*
 *  Send a NON-INVITE response out
 */
static int
sip_srv_xaction_noninv_res(sip_conn_object_t conn_obj,
    sip_xaction_t *sip_trans, _sip_msg_t *msg)
{
	int			resp_code;
	sip_xaction_time_obj_t	*timer_obj_J = NULL;
	sip_message_type_t	*sip_msg_info = msg->sip_msg_req_res;
	int			prev_state;
	boolean_t		isreliable;

	resp_code = sip_msg_info->sip_resp_code;
	isreliable = sip_is_conn_reliable(conn_obj);

	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	prev_state = sip_trans->sip_xaction_state;
	switch (sip_trans->sip_xaction_state) {
		case SIP_SRV_TRYING:
			if (sip_trans->sip_xaction_last_msg != NULL) {
				SIP_MSG_REFCNT_DECR(
				    sip_trans->sip_xaction_last_msg);
				sip_trans->sip_xaction_last_msg = NULL;
			}
			SIP_MSG_REFCNT_INCR(msg);
			sip_trans->sip_xaction_last_msg = msg;
			(void) sip_add_conn_obj_cache(conn_obj,
			    (void *)sip_trans);
			if (SIP_PROVISIONAL_RESP(resp_code)) {
				sip_trans->sip_xaction_state =
				    SIP_SRV_NONINV_PROCEEDING;
			} else if (SIP_FINAL_RESP(resp_code)) {
				/*
				 * For unreliable transports, start Timer J
				 */
				if (!isreliable) {
					timer_obj_J = sip_setup_timer(
					    conn_obj, sip_trans,
					    NULL, sip_trans->sip_xaction_TJ,
					    SIP_XACTION_TIMER_J);
					if (timer_obj_J == NULL) {
						(void) pthread_mutex_unlock(&
						    sip_trans->
						    sip_xaction_mutex);
						return (ENOMEM);
					}
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TJ,
					    timer_obj_J,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TJ)) {
						(void) pthread_mutex_unlock(&
						    sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_J);
						return (ENOMEM);
					}
					sip_trans->sip_xaction_state =
					    SIP_SRV_NONINV_COMPLETED;
				} else {
					sip_trans->sip_xaction_state =
					    SIP_SRV_NONINV_TERMINATED;
				}
			}
			break;
		case SIP_SRV_NONINV_PROCEEDING:
			if (sip_trans->sip_xaction_last_msg != NULL) {
				SIP_MSG_REFCNT_DECR(
				    sip_trans->sip_xaction_last_msg);
				sip_trans->sip_xaction_last_msg = NULL;
			}
			SIP_MSG_REFCNT_INCR(msg);
			sip_trans->sip_xaction_last_msg = msg;
			(void) sip_add_conn_obj_cache(conn_obj,
			    (void *)sip_trans);
			if (SIP_PROVISIONAL_RESP(resp_code)) {
				break;
			} else if (SIP_FINAL_RESP(resp_code)) {
				/*
				 * For unreliable transports, start Timer J
				 */
				if (!isreliable) {
					timer_obj_J = sip_setup_timer(
					    conn_obj, sip_trans,
					    NULL, sip_trans->sip_xaction_TJ,
					    SIP_XACTION_TIMER_J);
					if (timer_obj_J == NULL) {
						(void) pthread_mutex_unlock(&
						    sip_trans->
						    sip_xaction_mutex);
						return (ENOMEM);
					}
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TJ,
					    timer_obj_J,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TJ)) {
						(void) pthread_mutex_unlock(&
						    sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_J);
						return (ENOMEM);
					}
					sip_trans->sip_xaction_state =
					    SIP_SRV_NONINV_COMPLETED;
				} else {
					sip_trans->sip_xaction_state =
					    SIP_SRV_NONINV_TERMINATED;
				}
			}
			break;
		default:
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (EPROTO);
	}
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (prev_state != sip_trans->sip_xaction_state &&
	    sip_xaction_ulp_state_cb != NULL) {
		sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
		    (sip_msg_t)msg, prev_state, sip_trans->sip_xaction_state);
	}
	return (0);
}


/*
 * -------------------------- Input Routines ---------------------------
 */

/*
 * Process an incoming SIP message Request or Response
 */
int
sip_xaction_input(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t **sip_msg)
{
	sip_message_type_t	*sip_msg_info;
	int			ret;

	sip_msg_info = (*sip_msg)->sip_msg_req_res;

	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	sip_trans->sip_xaction_msgcnt++;
	sip_add_log(&sip_trans->sip_xaction_log[sip_trans->sip_xaction_state],
	    (sip_msg_t)*sip_msg, sip_trans->sip_xaction_msgcnt,
	    SIP_TRANSACTION_LOG);
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);

	if (sip_msg_info->is_request)
		ret = sip_srv_xaction_input(conn_obj, sip_trans, sip_msg);
	else
		ret = sip_clnt_xaction_input(conn_obj, sip_trans, sip_msg);
	return (ret);
}

/*
 * Process a Request from the transport
 */
static int
sip_srv_xaction_input(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t **sip_msg)
{
	sip_message_type_t	*sip_msg_info;
	_sip_msg_t		*msg = *sip_msg;
	int			prev_state;
	boolean_t		isreliable;

	sip_msg_info = msg->sip_msg_req_res;
	isreliable = sip_is_conn_reliable(conn_obj);

	/*
	 * Cancel if the original transaction has not yet got a final
	 * response and send a 487 response.
	 */
	if (sip_msg_info->sip_req_method == ACK) {
		_sip_msg_t		*sip_last_resp;
		const sip_str_t		*resp_to_tag;
		const sip_str_t		*req_to_tag;
		int			error;
		sip_message_type_t	*last_msg_info;

		(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);

		if (sip_trans->sip_xaction_last_msg != NULL)
			sip_last_resp = sip_trans->sip_xaction_last_msg;
		else
			sip_last_resp = sip_trans->sip_xaction_orig_msg;
		last_msg_info = sip_last_resp->sip_msg_req_res;
		if (last_msg_info->is_request) {
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (0);
		}
		req_to_tag = sip_get_to_tag((sip_msg_t)msg, &error);
		if (req_to_tag == NULL || error != 0) {
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (0);
		}
		resp_to_tag = sip_get_to_tag((sip_msg_t)sip_last_resp,
		    &error);
		if (req_to_tag == NULL || error != 0) {
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (0);
		}
		if (resp_to_tag->sip_str_len != req_to_tag->sip_str_len ||
		    strncmp(resp_to_tag->sip_str_ptr, req_to_tag->sip_str_ptr,
		    req_to_tag->sip_str_len) != 0) {
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (0);
		}
		prev_state = sip_trans->sip_xaction_state;
		if (sip_trans->sip_xaction_state == SIP_SRV_INV_COMPLETED) {
			sip_xaction_time_obj_t	*timer_obj_I = NULL;

			SIP_CANCEL_TIMER(sip_trans->sip_xaction_TG);
			/*
			 * Cancel Timer H and goto TERMINATED state for
			 * reliable transports.
			 */
			if (isreliable) {
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TH);
				sip_trans->sip_xaction_state =
				    SIP_SRV_INV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans,
					    (sip_msg_t)msg, prev_state,
					    sip_trans->sip_xaction_state);
				}
				return (0);
			}
			/*
			 * For unreliable transports, start TIMER I and
			 * transition to CONFIRMED state.
			 */
			timer_obj_I = sip_setup_timer(conn_obj, sip_trans,
			    NULL,
			    sip_trans->sip_xaction_TI, SIP_XACTION_TIMER_I);
			if (timer_obj_I == NULL) {
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				return (ENOMEM);
			}
			SIP_SCHED_TIMER(sip_trans->sip_xaction_TI,
			    timer_obj_I, sip_xaction_state_timer_fire);
			if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TI)) {
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				free(timer_obj_I);
				return (ENOMEM);
			}
			sip_trans->sip_xaction_state = SIP_SRV_CONFIRMED;
		}
		(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
		if (prev_state != sip_trans->sip_xaction_state &&
		    sip_xaction_ulp_state_cb != NULL) {
			sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
			    (sip_msg_t)msg, prev_state,
			    sip_trans->sip_xaction_state);
		}
		return (0);
	} else if (sip_msg_info->sip_req_method == CANCEL) {
		if (sip_trans->sip_xaction_method == INVITE) {
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (0);
		}
	}
	if (sip_msg_info->sip_req_method == INVITE) {
		(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
		if (sip_trans->sip_xaction_method != INVITE) {
			sip_write_to_log((void *)sip_trans,
			    SIP_TRANSACTION_LOG | SIP_ASSERT_ERROR, __FILE__,
			    __LINE__);
		}
		assert(sip_trans->sip_xaction_method == INVITE);
		/*
		 * Retransmitted invite
		 */
		switch (sip_trans->sip_xaction_state) {
			case SIP_SRV_INV_PROCEEDING:
			case SIP_SRV_INV_COMPLETED:
				if (sip_trans->sip_xaction_last_msg != NULL) {
					_sip_msg_t		*new_msg;
					sip_message_type_t	*msg_info;
					int			resp;

					new_msg =
					    sip_trans->sip_xaction_last_msg;
					msg_info = new_msg->sip_msg_req_res;
					if (msg_info == NULL || msg_info->
					    is_request) {
						sip_write_to_log((void *)
						    sip_trans,
						    SIP_TRANSACTION_LOG |
						    SIP_ASSERT_ERROR, __FILE__,
						    __LINE__);
					}
					assert(msg_info != NULL && !msg_info->
					    is_request);
					resp = msg_info->sip_resp_code;
					SIP_UPDATE_COUNTERS(B_FALSE, 0, resp,
					    B_TRUE, new_msg->sip_msg_len);
					++sip_trans->sip_xaction_msgcnt;
					sip_add_log(&sip_trans->sip_xaction_log[
					    sip_trans->sip_xaction_state],
					    new_msg, sip_trans->
					    sip_xaction_msgcnt,
					    SIP_TRANSACTION_LOG);
					(void) sip_stack_send(conn_obj,
					    new_msg->sip_msg_buf,
					    new_msg->sip_msg_len);
				}
				break;
			default:
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				return (EPROTO);
		}
		(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
		/*
		 * We need to account for this invite received by the stack
		 * before we free that message.
		 */
		SIP_UPDATE_COUNTERS(B_TRUE, INVITE, 0, B_FALSE,
		    msg->sip_msg_len);
		sip_free_msg((sip_msg_t)msg);
		*sip_msg = NULL;
		return (0);
	}
	/*
	 * Retransmitted request
	 */
	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	if (sip_trans->sip_xaction_method == INVITE) {
		sip_write_to_log((void *)sip_trans, SIP_TRANSACTION_LOG |
		    SIP_ASSERT_ERROR, __FILE__, __LINE__);
	}
	assert(sip_trans->sip_xaction_method != INVITE);
	switch (sip_trans->sip_xaction_state) {
		case SIP_SRV_NONINV_PROCEEDING:
		case SIP_SRV_NONINV_COMPLETED:
			if (sip_trans->sip_xaction_last_msg != NULL) {
				_sip_msg_t		*new_msg;
				sip_message_type_t	*msg_info;
				int			resp;

				new_msg = sip_trans->sip_xaction_last_msg;
				msg_info = new_msg->sip_msg_req_res;
				if (msg_info == NULL || msg_info->is_request) {
					sip_write_to_log((void *)sip_trans,
					    SIP_TRANSACTION_LOG |
					    SIP_ASSERT_ERROR, __FILE__,
					    __LINE__);
					}
				assert(msg_info != NULL && !msg_info->
				    is_request);
				resp = msg_info->sip_resp_code;
				SIP_UPDATE_COUNTERS(B_FALSE, 0, resp, B_TRUE,
				    new_msg->sip_msg_len);
				++sip_trans->sip_xaction_msgcnt;
				sip_add_log(&sip_trans->sip_xaction_log[
				    sip_trans->sip_xaction_state], new_msg,
				    sip_trans->sip_xaction_msgcnt,
				    SIP_TRANSACTION_LOG);
				(void) sip_stack_send(conn_obj,
				    new_msg->sip_msg_buf, new_msg->sip_msg_len);
			}
			break;
		default:
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (EPROTO);
	}
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	/*
	 * We need to account for the retransmitted non-INVITE request here.
	 * When we return from here the msg will be freed and we will not
	 * be able to capture the details at sip_process_new_packet()
	 */
	SIP_UPDATE_COUNTERS(B_TRUE, sip_msg_info->sip_req_method, 0, B_FALSE,
	    msg->sip_msg_len);
	sip_free_msg((sip_msg_t)msg);
	*sip_msg = NULL;
	return (0);
}

/*
 * Process a Response
 */
static int
sip_clnt_xaction_input(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t **msg)
{
	int		ret;

	if (sip_trans->sip_xaction_method == INVITE)
		ret = sip_clnt_xaction_inv_res(conn_obj, sip_trans, msg);
	else
		ret = sip_clnt_xaction_noninv_res(conn_obj, sip_trans, msg);

	return (ret);
}

static int
sip_create_send_nonOKack(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t *msg, boolean_t copy)
{
	_sip_msg_t	*ack_msg;
	int		ret = 0;

	ack_msg = (_sip_msg_t *)sip_new_msg();
	if (ack_msg == NULL)
		return (ENOMEM);
	if ((ret = sip_create_nonOKack(
	    (sip_msg_t)sip_trans->sip_xaction_orig_msg, (sip_msg_t)msg,
	    (sip_msg_t)ack_msg)) != 0) {
		sip_free_msg((sip_msg_t)ack_msg);
		return (ret);
	}
	SIP_UPDATE_COUNTERS(B_TRUE, ACK, 0, B_TRUE, ack_msg->sip_msg_len);
	++sip_trans->sip_xaction_msgcnt;
	sip_add_log(&sip_trans->sip_xaction_log[sip_trans->sip_xaction_state],
	    ack_msg, sip_trans->sip_xaction_msgcnt, SIP_TRANSACTION_LOG);
	if ((ret = sip_stack_send(conn_obj, ack_msg->sip_msg_buf,
	    ack_msg->sip_msg_len)) != 0) {
		sip_free_msg((sip_msg_t)ack_msg);
		return (ret);
	}
	if (copy) {
		SIP_MSG_REFCNT_INCR(ack_msg);
		if (sip_trans->sip_xaction_last_msg != NULL) {
			SIP_MSG_REFCNT_DECR(sip_trans->sip_xaction_last_msg);
			sip_trans->sip_xaction_last_msg = NULL;
		}
		sip_trans->sip_xaction_last_msg = ack_msg;
	}
	sip_free_msg((sip_msg_t)ack_msg);
	return (0);
}

/*
 * Process a INVITE Response
 */
static int
sip_clnt_xaction_inv_res(sip_conn_object_t conn_obj, sip_xaction_t *sip_trans,
    _sip_msg_t **sip_msg)
{
	int			resp_code;
	_sip_msg_t		*msg = *sip_msg;
	sip_xaction_time_obj_t	*timer_obj_D = NULL;
	sip_message_type_t	*sip_msg_info;
	int			prev_state;
	boolean_t		isreliable;

	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	if (msg->sip_msg_req_res == NULL) {
		sip_write_to_log((void *)sip_trans, SIP_TRANSACTION_LOG |
		    SIP_ASSERT_ERROR, __FILE__, __LINE__);
	}
	assert(msg->sip_msg_req_res != NULL);

	sip_msg_info = msg->sip_msg_req_res;
	resp_code = sip_msg_info->sip_resp_code;
	isreliable = sip_is_conn_reliable(conn_obj);

	prev_state = sip_trans->sip_xaction_state;
	switch (sip_trans->sip_xaction_state) {
		case SIP_CLNT_CALLING:
			if (SIP_PROVISIONAL_RESP(resp_code)) {
				/*
				 * sip_trans->sip_xaction_last_msg ?
				 */
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TA);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_INV_PROCEEDING;
			} else if (SIP_OK_RESP(resp_code)) {
				/*
				 * sip_trans->sip_xaction_last_msg ?
				 */
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TA);
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TB);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_INV_TERMINATED;
			} else if (SIP_NONOK_FINAL_RESP(resp_code)) {
				int	ret;

				/*
				 * sip_trans->sip_xaction_last_msg ?
				 */
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TA);
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TB);
				if ((ret = sip_create_send_nonOKack(conn_obj,
				    sip_trans, msg, B_FALSE)) != 0) {
					(void) pthread_mutex_unlock(
					    &sip_trans->sip_xaction_mutex);
					return (ret);
				}
				/*
				 * start timer D for unreliable transports
				 */
				if (!isreliable) {
					timer_obj_D = sip_setup_timer(
					    conn_obj, sip_trans,
					    NULL, sip_trans->sip_xaction_TD,
					    SIP_XACTION_TIMER_D);
					if (timer_obj_D == NULL) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						return (ENOMEM);
					}
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TD,
					    timer_obj_D,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TD)) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_D);
						return (ENOMEM);
					}
					sip_trans->sip_xaction_state =
					    SIP_CLNT_INV_COMPLETED;
				} else {
					sip_trans->sip_xaction_state =
					    SIP_CLNT_INV_TERMINATED;
				}
			} else {
				/*
				 * Invalid resp_code
				 */
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				return (EPROTO);
			}
			break;
		case SIP_CLNT_INV_PROCEEDING:
			if (SIP_PROVISIONAL_RESP(resp_code)) {
				break;
			} else if (SIP_OK_RESP(resp_code)) {
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TB);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_INV_TERMINATED;
			} else if (SIP_NONOK_FINAL_RESP(resp_code)) {
				int	ret;

				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TB);
				if ((ret = sip_create_send_nonOKack(conn_obj,
				    sip_trans, msg, B_FALSE)) != 0) {
					(void) pthread_mutex_unlock(
					    &sip_trans->sip_xaction_mutex);
					return (ret);
				}
				/*
				 * start timer D for unreliable transports
				 */
				if (!isreliable) {
					timer_obj_D = sip_setup_timer(
					    conn_obj, sip_trans,
					    NULL, sip_trans->sip_xaction_TD,
					    SIP_XACTION_TIMER_D);
					if (timer_obj_D == NULL) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						return (ENOMEM);
					}
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TD,
					    timer_obj_D,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TD)) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_D);
						return (ENOMEM);
					}
					sip_trans->sip_xaction_state =
					    SIP_CLNT_INV_COMPLETED;
				} else {
					sip_trans->sip_xaction_state =
					    SIP_CLNT_INV_TERMINATED;
				}
			} else {
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				return (EPROTO);
			}
			break;
		case SIP_CLNT_INV_COMPLETED:
			/*
			 * Transport error takes it to
			 * SIP_CLNT_INV_TERMINATED
			 */
			if (SIP_NONOK_FINAL_RESP(resp_code)) {
				int	ret;

				if ((ret = sip_create_send_nonOKack(conn_obj,
				    sip_trans, msg, B_FALSE)) != 0) {
					(void) pthread_mutex_unlock(
					    &sip_trans->sip_xaction_mutex);
					return (ret);
				}
			} else {
				/*
				 * Invalid resp_code
				 */
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				return (EPROTO);
			}
			break;
		default:
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (EPROTO);
	}
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (prev_state != sip_trans->sip_xaction_state &&
	    sip_xaction_ulp_state_cb != NULL) {
		sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
		    (sip_msg_t)msg, prev_state, sip_trans->sip_xaction_state);
	}
	return (0);
}

/*
 * Process a NON-INVITE Response
 */
static int
sip_clnt_xaction_noninv_res(sip_conn_object_t conn_obj,
    sip_xaction_t *sip_trans, _sip_msg_t **sip_msg)
{
	int			resp_code;
	sip_xaction_time_obj_t	*timer_obj_K = NULL;
	sip_message_type_t	*sip_msg_info;
	int			prev_state;
	_sip_msg_t		*msg = *sip_msg;
	boolean_t		isreliable;

	if (msg->sip_msg_req_res == NULL || sip_trans == NULL) {
		sip_write_to_log((void *)sip_trans, SIP_TRANSACTION_LOG |
		    SIP_ASSERT_ERROR, __FILE__, __LINE__);
	}
	assert(msg->sip_msg_req_res != NULL);
	assert(sip_trans != NULL);

	sip_msg_info = msg->sip_msg_req_res;
	isreliable = sip_is_conn_reliable(conn_obj);
	resp_code = sip_msg_info->sip_resp_code;
	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	prev_state = sip_trans->sip_xaction_state;
	switch (sip_trans->sip_xaction_state) {
		case SIP_CLNT_TRYING:
			if (SIP_PROVISIONAL_RESP(resp_code)) {
				sip_trans->sip_xaction_state =
				    SIP_CLNT_NONINV_PROCEEDING;
			} else if (SIP_FINAL_RESP(resp_code)) {
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TE);
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TF);
				/*
				 * Start timer K for unreliable transports
				 */
				if (!isreliable) {
					timer_obj_K = sip_setup_timer(
					    conn_obj, sip_trans,
					    NULL, sip_trans->sip_xaction_TK,
					    SIP_XACTION_TIMER_K);
					if (timer_obj_K == NULL) {
						(void) pthread_mutex_unlock(&
						    sip_trans->
						    sip_xaction_mutex);
						return (ENOMEM);
					}
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TK,
					    timer_obj_K,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TK)) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_K);
						return (ENOMEM);
					}
					sip_trans->sip_xaction_state =
					    SIP_CLNT_NONINV_COMPLETED;
				} else {
					sip_trans->sip_xaction_state =
					    SIP_CLNT_NONINV_TERMINATED;
				}
			}
			break;
		case SIP_CLNT_NONINV_PROCEEDING:
			if (SIP_PROVISIONAL_RESP(resp_code)) {
				break;
			} else if (SIP_FINAL_RESP(resp_code)) {
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TE);
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TF);
				/*
				 * Start timer K for unreliable transports
				 */
				if (!isreliable) {
					timer_obj_K = sip_setup_timer(
					    conn_obj, sip_trans,
					    NULL, sip_trans->sip_xaction_TK,
					    SIP_XACTION_TIMER_K);
					if (timer_obj_K == NULL) {
						(void) pthread_mutex_unlock(&
						    sip_trans->
						    sip_xaction_mutex);
						return (ENOMEM);
					}
					SIP_SCHED_TIMER(
					    sip_trans->sip_xaction_TK,
					    timer_obj_K,
					    sip_xaction_state_timer_fire);
					if (!SIP_IS_TIMER_RUNNING(
					    sip_trans->sip_xaction_TK)) {
						(void) pthread_mutex_unlock(
						    &sip_trans->
						    sip_xaction_mutex);
						free(timer_obj_K);
						return (ENOMEM);
					}
					sip_trans->sip_xaction_state =
					    SIP_CLNT_NONINV_COMPLETED;
				} else {
					sip_trans->sip_xaction_state =
					    SIP_CLNT_NONINV_TERMINATED;
				}
			}
			break;
		default:
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return (EPROTO);
	}
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (prev_state != sip_trans->sip_xaction_state &&
	    sip_xaction_ulp_state_cb != NULL) {
		sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
		    (sip_msg_t)msg, prev_state, sip_trans->sip_xaction_state);
	}
	return (0);
}

/*
 * If there is a transport error, sending the message out, terminate the
 * transaction.
 */
/* ARGSUSED */
void
sip_xaction_terminate(sip_xaction_t *sip_trans, _sip_msg_t *msg, int transport)
{
	sip_message_type_t	*sip_msg_info;
	int			state;
	int			prev_state;

	sip_msg_info = msg->sip_msg_req_res;
	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	if (sip_msg_info->is_request) {
		if (sip_trans->sip_xaction_method == INVITE)
			state = SIP_CLNT_INV_TERMINATED;
		else
			state = SIP_CLNT_NONINV_TERMINATED;
	} else {
		if (sip_trans->sip_xaction_method == INVITE)
			state = SIP_SRV_INV_TERMINATED;
		else
			state = SIP_SRV_NONINV_TERMINATED;
	}
	prev_state = sip_trans->sip_xaction_state;
	sip_trans->sip_xaction_state = state;
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (sip_xaction_ulp_state_cb != NULL) {
		sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
		    (sip_msg_t)msg, prev_state, sip_trans->sip_xaction_state);
	}
	sip_xaction_delete(sip_trans);
}

/*
 * --------------------------- Timer Routine ---------------------------
 */

void
sip_xaction_state_timer_fire(void *args)
{
	sip_xaction_time_obj_t	*time_obj = (sip_xaction_time_obj_t *)args;
	sip_xaction_t		*sip_trans = time_obj->sip_trans;
	_sip_msg_t		*new_msg;
	boolean_t		destroy_trans = B_FALSE;
	sip_conn_object_t	conn_obj;
	int			prev_state;
	sip_message_type_t	*msg_info;
	int			resp;
	sip_method_t		method;

	assert(time_obj != NULL);

	(void) pthread_mutex_lock(&sip_trans->sip_xaction_mutex);
	prev_state = sip_trans->sip_xaction_state;
	switch (time_obj->sip_xaction_timer_type) {
		case SIP_XACTION_TIMER_A:
			if (sip_trans->sip_xaction_state != SIP_CLNT_CALLING)
				break;
			/*
			 * Assert candidate
			 */
			if (sip_trans->sip_xaction_last_msg == NULL)
				break;
			if (sip_trans->sip_xaction_conn_obj == NULL)
				break;
			new_msg = sip_trans->sip_xaction_last_msg;
			conn_obj = sip_trans->sip_xaction_conn_obj;
			/* timer A is for INVITE-RETRANSMIT only */
			SIP_UPDATE_COUNTERS(B_TRUE, INVITE, 0, B_TRUE, new_msg->
			    sip_msg_len);
			++sip_trans->sip_xaction_msgcnt;
			sip_add_log(&sip_trans->sip_xaction_log[sip_trans->
			    sip_xaction_state], new_msg, sip_trans->
			    sip_xaction_msgcnt, SIP_TRANSACTION_LOG);
			if (sip_stack_send(conn_obj, new_msg->sip_msg_buf,
			    new_msg->sip_msg_len) != 0) {
				sip_del_conn_obj_cache(
				    sip_trans->sip_xaction_conn_obj,
				    (void *)sip_trans);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_INV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			SIP_SET_TIMEOUT(sip_trans->sip_xaction_TA,
			    2 * SIP_GET_TIMEOUT(sip_trans->sip_xaction_TA));
			/*
			 * Reschedule the timer
			 */
			SIP_SCHED_TIMER(sip_trans->sip_xaction_TA,
			    time_obj, sip_xaction_state_timer_fire);
			if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TA)) {
				sip_del_conn_obj_cache(
				    sip_trans->sip_xaction_conn_obj,
				    (void *)sip_trans);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_INV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return;
		case SIP_XACTION_TIMER_B:
			SIP_CANCEL_TIMER(sip_trans->sip_xaction_TA);
			if (sip_trans->sip_xaction_state == SIP_CLNT_CALLING) {
				sip_trans->sip_xaction_state =
				    SIP_CLNT_INV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			break;
		case SIP_XACTION_TIMER_D:
			if (sip_trans->sip_xaction_state ==
			    SIP_CLNT_INV_COMPLETED) {
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TB);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_INV_TERMINATED;
				destroy_trans = B_TRUE;
			}
			break;
		case SIP_XACTION_TIMER_E:
			/*
			 * Assert candidate
			 */
			if (sip_trans->sip_xaction_state != SIP_CLNT_TRYING &&
			    sip_trans->sip_xaction_state !=
			    SIP_CLNT_NONINV_PROCEEDING) {
				break;
			}
			/*
			 * Assert candidate
			 */
			if (sip_trans->sip_xaction_last_msg == NULL)
				break;
			if (sip_trans->sip_xaction_conn_obj == NULL)
				break;
			conn_obj = sip_trans->sip_xaction_conn_obj;
			new_msg = sip_trans->sip_xaction_last_msg;
			/* Timer E is for non-INVITE request */

			msg_info = new_msg->sip_msg_req_res;
			if (msg_info == NULL || !msg_info->is_request) {
				(void) sip_write_to_log((void *) sip_trans,
				    SIP_TRANSACTION_LOG | SIP_ASSERT_ERROR,
				    __FILE__, __LINE__);
			}
			assert(msg_info != NULL && msg_info->is_request);
			method = msg_info->sip_req_method;
			SIP_UPDATE_COUNTERS(B_TRUE, method, 0, B_TRUE, new_msg->
			    sip_msg_len);
			++sip_trans->sip_xaction_msgcnt;
			sip_add_log(&sip_trans->sip_xaction_log[sip_trans->
			    sip_xaction_state], new_msg, sip_trans->
			    sip_xaction_msgcnt, SIP_TRANSACTION_LOG);
			if (sip_stack_send(conn_obj, new_msg->sip_msg_buf,
			    new_msg->sip_msg_len) != 0) {
				sip_del_conn_obj_cache(
				    sip_trans->sip_xaction_conn_obj,
				    (void *)sip_trans);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_NONINV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			SIP_SET_TIMEOUT(sip_trans->sip_xaction_TE,
			    MIN(SIP_TIMER_T2,
			    2 * SIP_GET_TIMEOUT(sip_trans->sip_xaction_TE)));
			/*
			 * Reschedule the timer
			 */
			SIP_SCHED_TIMER(sip_trans->sip_xaction_TE,
			    time_obj, sip_xaction_state_timer_fire);
			if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TE)) {
				sip_del_conn_obj_cache(
				    sip_trans->sip_xaction_conn_obj,
				    (void *)sip_trans);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_NONINV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return;
		case SIP_XACTION_TIMER_F:
			SIP_CANCEL_TIMER(sip_trans->sip_xaction_TE);
			if (sip_trans->sip_xaction_state == SIP_CLNT_TRYING ||
			    sip_trans->sip_xaction_state ==
			    SIP_CLNT_NONINV_PROCEEDING) {
				sip_trans->sip_xaction_state =
				    SIP_CLNT_NONINV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			break;
		case SIP_XACTION_TIMER_G:
			/*
			 * Assert candidate
			 */
			if (sip_trans->sip_xaction_last_msg == NULL)
				break;
			if (sip_trans->sip_xaction_conn_obj == NULL)
				break;
			if (sip_trans->sip_xaction_state !=
			    SIP_SRV_INV_COMPLETED) {
				break;
			}
			new_msg = sip_trans->sip_xaction_last_msg;
			conn_obj = sip_trans->sip_xaction_conn_obj;
			msg_info = new_msg->sip_msg_req_res;
			if (msg_info == NULL || msg_info->is_request) {
				(void) sip_write_to_log((void *) sip_trans,
				    SIP_TRANSACTION_LOG | SIP_ASSERT_ERROR,
				    __FILE__, __LINE__);
			}
			assert(msg_info != NULL && !msg_info->is_request);
			resp = msg_info->sip_resp_code;
			SIP_UPDATE_COUNTERS(B_FALSE, 0, resp, B_TRUE, new_msg->
			    sip_msg_len);
			++sip_trans->sip_xaction_msgcnt;
			sip_add_log(&sip_trans->sip_xaction_log[sip_trans->
			    sip_xaction_state], new_msg, sip_trans->
			    sip_xaction_msgcnt, SIP_TRANSACTION_LOG);
			if (sip_stack_send(conn_obj, new_msg->sip_msg_buf,
			    new_msg->sip_msg_len) != 0) {
				sip_del_conn_obj_cache(
				    sip_trans->sip_xaction_conn_obj,
				    (void *)sip_trans);
				sip_trans->sip_xaction_state =
				    SIP_SRV_INV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			SIP_SET_TIMEOUT(sip_trans->sip_xaction_TG,
			    MIN(SIP_TIMER_T2,
			    2 * SIP_GET_TIMEOUT(sip_trans->sip_xaction_TG)));
			SIP_SCHED_TIMER(sip_trans->sip_xaction_TG,
			    time_obj, sip_xaction_state_timer_fire);
			if (!SIP_IS_TIMER_RUNNING(sip_trans->sip_xaction_TG)) {
				sip_del_conn_obj_cache(
				    sip_trans->sip_xaction_conn_obj,
				    (void *)sip_trans);
				sip_trans->sip_xaction_state =
				    SIP_SRV_INV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			(void) pthread_mutex_unlock(
			    &sip_trans->sip_xaction_mutex);
			return;
		case SIP_XACTION_TIMER_H:
			SIP_CANCEL_TIMER(sip_trans->sip_xaction_TG);
			if (sip_trans->sip_xaction_state ==
			    SIP_SRV_INV_COMPLETED) {
				sip_trans->sip_xaction_state =
				    SIP_SRV_INV_TERMINATED;
				(void) pthread_mutex_unlock(
				    &sip_trans->sip_xaction_mutex);
				if (sip_xaction_ulp_state_cb != NULL) {
					sip_xaction_ulp_state_cb(
					    (sip_transaction_t)sip_trans, NULL,
					    prev_state, sip_trans->
					    sip_xaction_state);
				}
				if (sip_xaction_ulp_trans_err != NULL) {
					sip_xaction_ulp_trans_err(sip_trans, 0,
					    NULL);
				}
				sip_xaction_delete(sip_trans);
				free(time_obj);
				return;
			}
			break;
		case SIP_XACTION_TIMER_I:
			if (sip_trans->sip_xaction_state ==
			    SIP_SRV_CONFIRMED) {
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TH);
				sip_trans->sip_xaction_state =
				    SIP_SRV_INV_TERMINATED;
				destroy_trans = B_TRUE;
			}
			break;
		case SIP_XACTION_TIMER_J:
			if (sip_trans->sip_xaction_state ==
			    SIP_SRV_NONINV_COMPLETED) {
				sip_trans->sip_xaction_state =
				    SIP_SRV_NONINV_TERMINATED;
				destroy_trans = B_TRUE;

			}
			break;
		case SIP_XACTION_TIMER_K:
			if (sip_trans->sip_xaction_state ==
			    SIP_CLNT_NONINV_COMPLETED) {
				SIP_CANCEL_TIMER(
				    sip_trans->sip_xaction_TF);
				sip_trans->sip_xaction_state =
				    SIP_CLNT_NONINV_TERMINATED;
				destroy_trans = B_TRUE;
			}
			break;
		default:
			break;
	}
	if (destroy_trans) {
		(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
		if (sip_xaction_ulp_state_cb != NULL &&
		    prev_state != sip_trans->sip_xaction_state) {
			sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans,
			    NULL, prev_state, sip_trans->sip_xaction_state);
		}
		sip_xaction_delete(sip_trans);
		free(time_obj);
		return;
	}
	(void) pthread_mutex_unlock(&sip_trans->sip_xaction_mutex);
	if (sip_xaction_ulp_state_cb != NULL &&
	    prev_state != sip_trans->sip_xaction_state) {
		sip_xaction_ulp_state_cb((sip_transaction_t)sip_trans, NULL,
		    prev_state, sip_trans->sip_xaction_state);
	}
	free(time_obj);
}
