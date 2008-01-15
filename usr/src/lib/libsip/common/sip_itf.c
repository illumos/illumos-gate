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

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_xaction.h"
#include "sip_dialog.h"
#include "sip_parse_generic.h"

void		(*sip_ulp_recv)(const sip_conn_object_t, sip_msg_t,
		    const sip_dialog_t) = NULL;
uint_t		(*sip_stack_timeout)(void *, void (*func)(void *),
		    struct timeval *) = NULL;
boolean_t	(*sip_stack_untimeout)(uint_t) = NULL;
int		(*sip_stack_send)(sip_conn_object_t xonn_object, char *, int) =
		    NULL;
void		(*sip_refhold_conn)(sip_conn_object_t) = NULL;
void		(*sip_refrele_conn)(sip_conn_object_t) = NULL;
boolean_t	(*sip_is_conn_stream)(sip_conn_object_t) = NULL;
boolean_t	(*sip_is_conn_reliable)(sip_conn_object_t) = NULL;
int 		(*sip_conn_rem_addr)(sip_conn_object_t, struct sockaddr *,
		    socklen_t *) = NULL;
int		(*sip_conn_local_addr)(sip_conn_object_t, struct sockaddr *,
		    socklen_t *) = NULL;
int		(*sip_conn_transport)(sip_conn_object_t) = NULL;
int		(*sip_conn_timer1)(sip_conn_object_t) = NULL;
int		(*sip_conn_timer2)(sip_conn_object_t) = NULL;
int		(*sip_conn_timer4)(sip_conn_object_t) = NULL;
int		(*sip_conn_timerd)(sip_conn_object_t) = NULL;

boolean_t	sip_manage_dialog = B_FALSE;

uint64_t	sip_hash_salt = 0;

/*
 * Defaults, overridden by configured values, if any
 */
int		sip_timer_T1 = SIP_TIMER_T1;
int		sip_timer_T2 = SIP_TIMER_T2;
int		sip_timer_T4 = SIP_TIMER_T4;
int		sip_timer_TD = 32 * SIP_SECONDS;

/*
 * list of sent-by values registered by the UA
 */
sent_by_list_t	*sip_sent_by = NULL;
int		sip_sent_by_count = 0;
pthread_mutex_t	sip_sent_by_lock;

/*
 * Create and send an error response
 */
static void
sip_send_resp(sip_conn_object_t conn_obj, _sip_msg_t *sip_msg, int resp)
{
	_sip_msg_t		*sip_msg_resp;

	sip_msg_resp = (_sip_msg_t *)sip_create_response((sip_msg_t)sip_msg,
	    resp, sip_get_resp_desc(resp), NULL, NULL);
	if (sip_msg_resp == NULL) {
		/*
		 * Message was too bad to even create a
		 * response. Just drop the messge.
		 */
		return;
	}
	/*
	 * We directly send it to the transport here.
	 */
	if (sip_adjust_msgbuf(sip_msg_resp) != 0) {
		sip_free_msg((sip_msg_t)sip_msg_resp);
		return;
	}

	SIP_UPDATE_COUNTERS(B_FALSE, 0, resp, B_TRUE, sip_msg_resp->
	    sip_msg_len);
	(void) sip_stack_send(conn_obj, sip_msg_resp->sip_msg_buf,
	    sip_msg_resp->sip_msg_len);
	sip_free_msg((sip_msg_t)sip_msg_resp);
}

/*
 * Validate some of the common headers
 */
boolean_t
sip_check_common_headers(sip_conn_object_t conn_obj, _sip_msg_t *sip_msg)
{
	int	err;

	if (sip_get_to_uri_str((sip_msg_t)sip_msg, &err) == NULL)
		goto error;
	if (sip_get_from_uri_str((sip_msg_t)sip_msg, &err) == NULL)
		goto error;
	if (sip_get_callseq_num((sip_msg_t)sip_msg, &err) < 0)
		goto error;
	if (sip_get_callid((sip_msg_t)sip_msg, &err) == NULL)
		goto error;
	return (B_FALSE);
error:
	sip_send_resp(conn_obj, sip_msg, SIP_BAD_REQUEST);
	return (B_TRUE);
}

/*
 * setup pointers to where the headers are.
 */
static int
sip_setup_header_pointers(_sip_msg_t *sip_msg)
{
	char		*msg;
	_sip_header_t	*sip_msg_header;
	char		*end;

	msg = sip_msg->sip_msg_buf;
	end = sip_msg->sip_msg_buf + sip_msg->sip_msg_len;
	/*
	 * Skip while space.
	 */
	while (isspace(*msg)) {
		if (msg < end)
			msg++;
		else
			return (EINVAL);
	}

	/*
	 * We consider Request and Response line as a header
	 */
	for (;;) {
		/*
		 * Skip CRLF
		 */
		if (strncmp(SIP_CRLF, msg, strlen(SIP_CRLF)) == 0) {
			if (sip_msg->sip_msg_headers_end != NULL) {
				SKIP_CRLF(msg);
				sip_msg->sip_msg_headers_end->sip_hdr_end = msg;
			}
			/*
			 * Start of a header.
			 * Check for empty line.
			 */
			if (strncmp(SIP_CRLF, msg, strlen(SIP_CRLF)) == 0) {
				/*
				 * empty line, start of content.
				 */
				SKIP_CRLF(msg);
				sip_msg->sip_msg_headers_end->sip_hdr_end = msg;
				break;
			}
			/*
			 * store start of header.
			 */
			sip_msg_header = calloc(1, sizeof (_sip_header_t));
			if (sip_msg_header == NULL)
				return (EINVAL);
			sip_msg_header->sip_hdr_start = msg;
			sip_msg_header->sip_hdr_current = msg;
			sip_msg_header->sip_hdr_allocated = B_FALSE;
			sip_msg_header->sip_hdr_prev =
			    sip_msg->sip_msg_headers_end;
			sip_msg_header->sip_hdr_next = NULL;
			sip_msg_header->sip_hdr_sipmsg = sip_msg;
			sip_msg->sip_msg_headers_end->sip_hdr_next =
			    sip_msg_header;
			sip_msg->sip_msg_headers_end = sip_msg_header;
		} else {
			if (sip_msg->sip_msg_headers_start == NULL) {
				/*
				 * Allocate first header structure.
				 */
				sip_msg_header = calloc(1,
				    sizeof (_sip_header_t));
				if (sip_msg_header == NULL)
					return (EINVAL);
				sip_msg_header->sip_hdr_allocated = B_FALSE;
				sip_msg_header->sip_hdr_start = msg;
				sip_msg_header->sip_hdr_current = msg;
				sip_msg_header->sip_hdr_sipmsg = sip_msg;
				sip_msg->sip_msg_headers_start = sip_msg_header;
				sip_msg->sip_msg_headers_end = sip_msg_header;
			}
			msg++;
		}
		/*
		 * We have reached the end without hitting the empty line.
		 */
		if (msg - sip_msg->sip_msg_buf >= sip_msg->sip_msg_len)
			return (EINVAL);
	}

	if (sip_msg->sip_msg_headers_start == NULL)
		return (EPROTO);

	/*
	 * Move start line to be a separate line.
	 */
	sip_msg->sip_msg_start_line = sip_msg->sip_msg_headers_start;
	sip_msg->sip_msg_headers_start =
	    sip_msg->sip_msg_headers_start->sip_hdr_next;
	sip_msg->sip_msg_start_line->sip_hdr_prev = NULL;
	sip_msg->sip_msg_start_line->sip_hdr_next = NULL;

	if (sip_msg->sip_msg_headers_start == NULL)
		return (EINVAL);
	sip_msg->sip_msg_headers_start->sip_hdr_prev = NULL;


	/*
	 * Deal with content.
	 */
	sip_msg->sip_msg_content = calloc(1, sizeof (sip_content_t));
	sip_msg->sip_msg_content->sip_content_start = msg;
	sip_msg->sip_msg_content->sip_content_end = sip_msg->sip_msg_buf +
	    sip_msg->sip_msg_len;
	sip_msg->sip_msg_content->sip_content_allocated = B_FALSE;
	sip_msg->sip_msg_content_len =
	    sip_msg->sip_msg_content->sip_content_end -
	    sip_msg->sip_msg_content->sip_content_start;
	return (0);
}

/*
 * The send interface to the sip stack. Used by upper layers.
 */
int
sip_sendmsg(sip_conn_object_t obj, sip_msg_t sip_msg, sip_dialog_t dialog,
    uint32_t flags)
{
	sip_xaction_t		*sip_trans = NULL;
	int			ret = 0;
	sip_message_type_t	*sip_msg_info;
	_sip_msg_t 		*_sip_msg;
	boolean_t		stateful = flags & SIP_SEND_STATEFUL;
	boolean_t		dlg_on_fork = flags & SIP_DIALOG_ON_FORK;

	sip_refhold_conn(obj);

	_sip_msg = (_sip_msg_t *)sip_msg;
	if ((ret = sip_adjust_msgbuf(_sip_msg)) != 0) {
		sip_refrele_conn(obj);
		return (ret);
	}

	assert(_sip_msg->sip_msg_req_res != NULL);
	sip_msg_info = _sip_msg->sip_msg_req_res;
	/*
	 * Send it statefully if:
	 * if stateful is set in 'flags' AND
	 * this is not an ACK request, if it is a request (should the upper
	 * layer set stateful in the latter case?, i.e is the check
	 * necessary here?)
	 */
	if (stateful && (!sip_msg_info->is_request ||
	    sip_msg_info->sip_req_method != ACK)) {
		sip_trans = (sip_xaction_t *)sip_xaction_get(obj, sip_msg,
		    B_TRUE, sip_msg_info->is_request ? SIP_CLIENT_TRANSACTION :
		    SIP_SERVER_TRANSACTION, &ret);
		if (sip_trans == NULL) {
			sip_refrele_conn(obj);
			return (ret);
		}
		ret = sip_xaction_output(obj, sip_trans, _sip_msg);
		SIP_XACTION_REFCNT_DECR(sip_trans);
		if (ret != 0) {
			sip_refrele_conn(obj);
			return (ret);
		}
	}
	/*
	 * If the appln wants us to create the dialog, create a partial
	 * dialog at this stage, when we get the response, we will
	 * complete it.
	 */
	if (sip_manage_dialog) {
		if (sip_msg_info->is_request && dialog == NULL) {
			dialog = (sip_dialog_t)sip_seed_dialog(obj, sip_msg,
			    dlg_on_fork, SIP_UAC_DIALOG);
		} else if (dialog != NULL && (!sip_msg_info->is_request ||
		    sip_msg_info->sip_req_method == NOTIFY)) {
			(void) sip_update_dialog(dialog, _sip_msg);
		} else if (dialog != NULL) {
			/*
			 * Dialog is in CONFIRMED state. If logging is enabled
			 * track the SIP message sent within a dialog.
			 */
			(void) pthread_mutex_lock(&dialog->sip_dlg_mutex);
			dialog->sip_dlg_msgcnt++;
			sip_add_log(&dialog->sip_dlg_log[dialog->sip_dlg_state],
			    (sip_msg_t)sip_msg, dialog->sip_dlg_msgcnt,
			    SIP_DIALOG_LOG);
			(void) pthread_mutex_unlock(&dialog->sip_dlg_mutex);

			if (sip_msg_info->is_request && sip_msg_info->
			    sip_req_method == INVITE) {
				(void) sip_dialog_add_new_contact(dialog,
				    _sip_msg);
			}
		}
	}
	/*
	 * if measure sip traffic is enabled, capture the measurements
	 * Is this the right place to measure or should I put this after
	 * the call to sip_stack_send()
	 */
	if (sip_msg_info->is_request) {
		SIP_UPDATE_COUNTERS(B_TRUE, sip_msg_info->sip_req_method, 0,
		    B_TRUE, _sip_msg->sip_msg_len);
	} else {
		SIP_UPDATE_COUNTERS(B_FALSE, 0, sip_msg_info->sip_resp_code,
		    B_TRUE, _sip_msg->sip_msg_len);
	}
	if ((ret = sip_stack_send(obj, _sip_msg->sip_msg_buf,
	    _sip_msg->sip_msg_len)) != 0) {
		if (sip_trans != NULL) {
			sip_xaction_terminate(sip_trans, _sip_msg,
			    sip_conn_transport(obj));
		}
		sip_refrele_conn(obj);
		return (ret);
	}
	sip_refrele_conn(obj);
	return (ret);
}

/*
 * Given a sent-by value check if it is in the registered list. If no values
 * have been registered, the check passes.
 */
static boolean_t
sip_sent_by_registered(const sip_str_t *sb_val)
{
	sent_by_list_t	*sb;
	int		count = 0;

	(void) pthread_mutex_lock(&sip_sent_by_lock);
	if (sip_sent_by == NULL) {
		(void) pthread_mutex_unlock(&sip_sent_by_lock);
		return (B_TRUE);
	}
	sb = sip_sent_by;
	for (count = 0; count < sip_sent_by_count; count++) {
		if (strncasecmp(sb->sb_val, sb_val->sip_str_ptr,
		    sb_val->sip_str_len) == 0) {
			(void) pthread_mutex_unlock(&sip_sent_by_lock);
			return (B_TRUE);
		}
		sb = sb->sb_next;
	}
	(void) pthread_mutex_unlock(&sip_sent_by_lock);
	return (B_FALSE);
}

/*
 * Given a response, check if the sent-by in the VIA header is valid.
 */
boolean_t
sip_valid_sent_by(sip_msg_t sip_msg)
{
	sip_header_t		via;
	sip_header_value_t	value = NULL;
	int			error;
	const sip_str_t		*sent_by = NULL;

	via = (sip_header_t)sip_get_header(sip_msg, SIP_VIA,  NULL, &error);
	if (via == NULL || error != 0)
		return (B_TRUE);
	value = (sip_header_value_t)sip_get_header_value(via, &error);
	if (value == NULL || error != 0)
		return (B_TRUE);
	sent_by = sip_get_via_sent_by_host(value, &error);
	if (sent_by == NULL || error != 0)
		return (B_TRUE);
	if (sip_sent_by_registered(sent_by))
		return (B_TRUE);
	return (B_FALSE);
}


/*
 * The receive interface to the transport layer.
 */
void
sip_process_new_packet(sip_conn_object_t conn_object, void *msgstr,
    size_t msglen)
{
	_sip_msg_t		*sip_msg;
	sip_message_type_t	*sip_msg_info;
	sip_xaction_t		*sip_trans;
	sip_dialog_t		dialog = NULL;
	boolean_t		dialog_created = B_FALSE;
	int			transport;
	char			*msgbuf = NULL;

	sip_refhold_conn(conn_object);
	transport = sip_conn_transport(conn_object);
	if (transport == IPPROTO_TCP) {
next_msg:
		msgstr = (char *)sip_get_tcp_msg(conn_object, (char *)msgstr,
		    &msglen);
		if (msgstr == NULL) {
			sip_refrele_conn(conn_object);
			return;
		}
	} else {
		msgbuf = (char *)malloc(msglen + 1);
		if (msgbuf == NULL) {
			sip_refrele_conn(conn_object);
			return;
		}
		(void) strncpy(msgbuf, msgstr, msglen);
		msgbuf[msglen] = '\0';
		msgstr = msgbuf;
	}
	sip_msg = (_sip_msg_t *)sip_new_msg();
	if (sip_msg == NULL) {
		if (msgbuf != NULL)
			free(msgbuf);
		sip_refrele_conn(conn_object);
		return;
	}
	sip_msg->sip_msg_buf = (char *)msgstr;
	sip_msg->sip_msg_len = msglen;
	(void) pthread_mutex_lock(&sip_msg->sip_msg_mutex);
	if (sip_setup_header_pointers(sip_msg) != 0) {
		(void) pthread_mutex_unlock(&sip_msg->sip_msg_mutex);
		sip_refrele_conn(conn_object);
		sip_free_msg((sip_msg_t)sip_msg);
		return;
	}
	if (sip_parse_first_line(sip_msg->sip_msg_start_line,
	    &sip_msg->sip_msg_req_res)) {
		(void) pthread_mutex_unlock(&sip_msg->sip_msg_mutex);
		sip_refrele_conn(conn_object);
		sip_free_msg((sip_msg_t)sip_msg);
		return;
	}
	sip_msg_info = sip_msg->sip_msg_req_res;
	(void) pthread_mutex_unlock(&sip_msg->sip_msg_mutex);

	if (sip_check_common_headers(conn_object, sip_msg)) {
		sip_refrele_conn(conn_object);
		sip_free_msg((sip_msg_t)sip_msg);
		return;
	}

	/*
	 * Silently discard the response if the top VIA has a sent-by value AND
	 * the UA has registered sent-by values AND the one in the VIA is
	 * not part of the registerd sent-by values.
	 */
	if (!sip_msg_info->is_request && !sip_valid_sent_by(sip_msg)) {
		sip_refrele_conn(conn_object);
		sip_free_msg((sip_msg_t)sip_msg);
		return;

	}
	sip_trans = (sip_xaction_t *)sip_xaction_get(conn_object,
	    (sip_msg_t)sip_msg,
	    B_FALSE, sip_msg_info->is_request ? SIP_SERVER_TRANSACTION :
	    SIP_CLIENT_TRANSACTION, NULL);
	if (sip_trans != NULL) {
		if (sip_xaction_input(conn_object, sip_trans, &sip_msg) != 0) {
			SIP_XACTION_REFCNT_DECR(sip_trans);
			sip_refrele_conn(conn_object);
			sip_free_msg((sip_msg_t)sip_msg);
			return;
		}
		SIP_XACTION_REFCNT_DECR(sip_trans);

		/*
		 * msg was retransmission - handled by the transaction
		 */
		if (sip_msg == NULL)
			goto check_next;
	} else {
		/*
		 * If we are getting an INVITE request, let us send a
		 * 100 TRYING response here, as in 17.2.1:
		 * "The server transaction MUST generate a 100 (Trying)
		 * response unless it knows that the TU will generate a
		 * provisional or final response within 200 ms".
		 */
		if (sip_msg_info->is_request &&
		    sip_msg_info->sip_req_method == INVITE) {
			sip_send_resp(conn_object, sip_msg, SIP_TRYING);
		}
	}
	if (sip_manage_dialog) {
		dialog = sip_dialog_find(sip_msg);
		if (dialog == NULL) {
			if (sip_msg_info->is_request) {
				/*
				 * sip_seed_dialog will check for the
				 * method in the request
				 */
				dialog = (sip_dialog_t)sip_seed_dialog(
				    conn_object, sip_msg,
				    B_FALSE, SIP_UAS_DIALOG);
				dialog_created = B_TRUE;
			}
		} else if (sip_incomplete_dialog(dialog)) {
			if (!sip_msg_info->is_request ||
			    sip_msg_info->sip_req_method == NOTIFY) {
				dialog = sip_update_dialog(dialog, sip_msg);
			}
		} else if (sip_dialog_process(sip_msg, &dialog) != 0) {
			if (dialog != NULL)
				sip_release_dialog(dialog);
			/*
			 * cseq number in error, send a
			 * SIP_SERVER_INTERNAL_ERROR response.
			 */
			if (sip_msg_info->is_request) {
				sip_send_resp(conn_object, sip_msg,
				    SIP_SERVER_INTERNAL_ERROR);
			}
			sip_refrele_conn(conn_object);
			sip_free_msg((sip_msg_t)sip_msg);
			return;
		}
	}
	if (sip_msg_info->is_request) {
		SIP_UPDATE_COUNTERS(B_TRUE, sip_msg_info->sip_req_method, 0,
		    B_FALSE, sip_msg->sip_msg_len);
	} else {
		SIP_UPDATE_COUNTERS(B_FALSE, 0, sip_msg_info->sip_resp_code,
		    B_FALSE, sip_msg->sip_msg_len);
	}
	sip_ulp_recv(conn_object, (sip_msg_t)sip_msg, dialog);
	sip_free_msg((sip_msg_t)sip_msg);
	if (dialog != NULL && !dialog_created)
		sip_release_dialog(dialog);
check_next:
	/*
	 * Check if there are more complete messages in the TCP fragment list
	 * to be consumed
	 */
	if (transport == IPPROTO_TCP) {
		msgstr = NULL;
		msglen = 0;
		goto next_msg;
	}
	sip_refrele_conn(conn_object);
}

/*
 * Initialize the stack. The connection manager functions, upper layer
 * receive functions are mandatory.
 */
int
sip_stack_init(sip_stack_init_t *stack_val)
{
#ifdef	__linux__
	struct timespec	tspec;
#endif

	/*
	 * If the stack has already been configured, return error
	 */
	if (sip_stack_send != NULL ||
	    stack_val->sip_version != SIP_STACK_VERSION) {
		return (EINVAL);
	}
	if (stack_val->sip_io_pointers == NULL ||
	    stack_val->sip_ulp_pointers == NULL) {
		return (EINVAL);
	}
	sip_ulp_recv = stack_val->sip_ulp_pointers->sip_ulp_recv;
	sip_manage_dialog = stack_val->sip_stack_flags & SIP_STACK_DIALOGS;

	sip_stack_send = stack_val->sip_io_pointers->sip_conn_send;
	sip_refhold_conn = stack_val->sip_io_pointers->sip_hold_conn_object;
	sip_refrele_conn = stack_val->sip_io_pointers->sip_rel_conn_object;
	sip_is_conn_stream = stack_val->sip_io_pointers->sip_conn_is_stream;
	sip_is_conn_reliable = stack_val->sip_io_pointers->sip_conn_is_reliable;
	sip_conn_rem_addr = stack_val->sip_io_pointers->sip_conn_remote_address;
	sip_conn_local_addr =
	    stack_val->sip_io_pointers->sip_conn_local_address;
	sip_conn_transport = stack_val->sip_io_pointers->sip_conn_transport;
	sip_header_function_table_external = stack_val->sip_function_table;

	if (sip_ulp_recv == NULL || sip_stack_send == NULL ||
	    sip_refhold_conn == NULL || sip_refrele_conn == NULL ||
	    sip_is_conn_stream == NULL || sip_is_conn_reliable == NULL ||
	    sip_conn_rem_addr == NULL || sip_conn_local_addr == NULL ||
	    sip_conn_transport == NULL) {
	err_ret:
		sip_ulp_recv = NULL;
		sip_stack_send = NULL;
		sip_refhold_conn = NULL;
		sip_refrele_conn = NULL;
		sip_is_conn_stream = NULL;
		sip_is_conn_reliable = NULL;
		sip_conn_rem_addr = NULL;
		sip_conn_local_addr = NULL;
		sip_conn_transport = NULL;
		sip_header_function_table_external = NULL;
		sip_stack_timeout = NULL;
		sip_stack_untimeout = NULL;
		return (EINVAL);
	}

	sip_conn_timer1 = stack_val->sip_io_pointers->sip_conn_timer1;
	sip_conn_timer2 = stack_val->sip_io_pointers->sip_conn_timer2;
	sip_conn_timer4 = stack_val->sip_io_pointers->sip_conn_timer4;
	sip_conn_timerd = stack_val->sip_io_pointers->sip_conn_timerd;

	/*
	 * Use Appln timeout routines, if provided
	 */
	if (stack_val->sip_ulp_pointers->sip_ulp_timeout != NULL) {
		if (stack_val->sip_ulp_pointers->sip_ulp_untimeout == NULL)
			goto err_ret;
		sip_stack_timeout =
		    stack_val->sip_ulp_pointers->sip_ulp_timeout;
		sip_stack_untimeout =
		    stack_val->sip_ulp_pointers->sip_ulp_untimeout;
	} else {
		if (stack_val->sip_ulp_pointers->sip_ulp_untimeout != NULL)
			goto err_ret;
		sip_timeout_init();
		sip_stack_timeout = sip_timeout;
		sip_stack_untimeout = sip_untimeout;
	}

	/*
	 * Manage Dialogs?
	 */
	if (sip_manage_dialog) {
		sip_dialog_init(stack_val->sip_ulp_pointers->sip_ulp_dlg_del,
		    stack_val->sip_ulp_pointers->sip_ulp_dlg_state_cb);
	}
	sip_xaction_init(stack_val->sip_ulp_pointers->sip_ulp_trans_error,
	    stack_val->sip_ulp_pointers->sip_ulp_trans_state_cb);

	/*
	 * Initialize SIP traffic counter mutex
	 */
	(void) pthread_mutex_init(&sip_counters.sip_counter_mutex, NULL);

	/*
	 * Initialize SIP logfile structures mutex
	 */
	(void) pthread_mutex_init(&trans_log.sip_logfile_mutex, NULL);
	(void) pthread_mutex_init(&dialog_log.sip_logfile_mutex, NULL);

#ifdef	__linux__
	if (clock_gettime(CLOCK_REALTIME, &tspec) != 0)
		goto err_ret;
	sip_hash_salt = tspec.tv_nsec;
#else
	sip_hash_salt = gethrtime();
#endif
	(void) pthread_mutex_init(&sip_sent_by_lock, NULL);
	return (0);
}
