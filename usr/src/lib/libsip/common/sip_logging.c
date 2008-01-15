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
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_xaction.h"
#include "sip_dialog.h"

#define	TIME_BUF_SIZE	50

/*
 * Contains API's which enable/disable transaction or dialog logging,
 * API's which records/measures SIP Traffic.
 */
/*
 * Needed for measuring SIP traffic counters.
 */
sip_traffic_counters_t	sip_counters;

/*
 * Needed for dialog/transaction logging.
 */
sip_logfile_t trans_log;
sip_logfile_t dialog_log;

/*
 * This function increments the appropriate inbound/outbound counters for
 * SIP requests/responses.
 */
void
sip_measure_traffic(boolean_t is_request, sip_method_t method, int resp_code,
    boolean_t outbound, int msg_size)
{
#ifdef	__solaris__
	assert(mutex_held(&sip_counters.sip_counter_mutex));
#endif
	if (outbound)
		sip_counters.sip_total_bytes_sent += msg_size;
	else
		sip_counters.sip_total_bytes_rcvd += msg_size;

	if (is_request) {
		if (outbound)
			++sip_counters.sip_total_req_sent;
		else
			++sip_counters.sip_total_req_rcvd;
		switch (method) {
			case INVITE:
				if (outbound)
					++sip_counters.sip_invite_req_sent;
				else
					++sip_counters.sip_invite_req_rcvd;
				break;
			case ACK:
				if (outbound)
					++sip_counters.sip_ack_req_sent;
				else
					++sip_counters.sip_ack_req_rcvd;
				break;
			case OPTIONS:
				if (outbound)
					++sip_counters.sip_options_req_sent;
				else
					++sip_counters.sip_options_req_rcvd;
				break;
			case BYE:
				if (outbound)
					++sip_counters.sip_bye_req_sent;
				else
					++sip_counters.sip_bye_req_rcvd;
				break;
			case CANCEL:
				if (outbound)
					++sip_counters.sip_cancel_req_sent;
				else
					++sip_counters.sip_cancel_req_rcvd;
				break;
			case REGISTER:
				if (outbound)
					++sip_counters.sip_register_req_sent;
				else
					++sip_counters.sip_register_req_rcvd;
				break;
			case REFER:
				if (outbound)
					++sip_counters.sip_refer_req_sent;
				else
					++sip_counters.sip_refer_req_rcvd;
				break;
			case INFO:
				if (outbound)
					++sip_counters.sip_info_req_sent;
				else
					++sip_counters.sip_info_req_rcvd;
				break;
			case SUBSCRIBE:
				if (outbound)
					++sip_counters.sip_subscribe_req_sent;
				else
					++sip_counters.sip_subscribe_req_rcvd;
				break;
			case NOTIFY:
				if (outbound)
					++sip_counters.sip_notify_req_sent;
				else
					++sip_counters.sip_notify_req_rcvd;
				break;
			case PRACK:
				if (outbound)
					++sip_counters.sip_prack_req_sent;
				else
					++sip_counters.sip_prack_req_rcvd;
				break;
			default:
				break;
		}
	} else {
		if (outbound)
			++sip_counters.sip_total_resp_sent;
		else
			++sip_counters.sip_total_resp_rcvd;
		if (SIP_PROVISIONAL_RESP(resp_code)) {
			if (outbound)
				++sip_counters.sip_1xx_resp_sent;
			else
				++sip_counters.sip_1xx_resp_rcvd;
		} else if (SIP_OK_RESP(resp_code)) {
			if (outbound)
				++sip_counters.sip_2xx_resp_sent;
			else
				++sip_counters.sip_2xx_resp_rcvd;
		} else if (SIP_REDIRECT_RESP(resp_code)) {
			if (outbound)
				++sip_counters.sip_3xx_resp_sent;
			else
				++sip_counters.sip_3xx_resp_rcvd;
		} else if (SIP_REQFAIL_RESP(resp_code)) {
			if (outbound)
				++sip_counters.sip_4xx_resp_sent;
			else
				++sip_counters.sip_4xx_resp_rcvd;
		} else if (SIP_SRVFAIL_RESP(resp_code)) {
			if (outbound)
				++sip_counters.sip_5xx_resp_sent;
			else
				++sip_counters.sip_5xx_resp_rcvd;
		} else if (SIP_GLOBFAIL_RESP(resp_code)) {
			if (outbound)
				++sip_counters.sip_6xx_resp_sent;
			else
				++sip_counters.sip_6xx_resp_rcvd;
		}
	}
}

/*
 * Enables Transaction logging. The flags argument controls the detail
 * of logging.
 */
int
sip_enable_trans_logging(FILE *logfile, int flags)
{
	if (logfile == NULL || flags != SIP_DETAIL_LOGGING)
		return (EINVAL);

	(void) pthread_mutex_lock(&trans_log.sip_logfile_mutex);
	if (!trans_log.sip_logging_enabled) {
		trans_log.sip_logfile = logfile;
		trans_log.sip_logging_enabled = B_TRUE;
	}
	(void) pthread_mutex_unlock(&trans_log.sip_logfile_mutex);
	return (0);
}


/*
 * Enables dialog logging. The flags argument controls the detail
 * of logging.
 */
int
sip_enable_dialog_logging(FILE *logfile, int flags)
{
	if (logfile == NULL || flags != SIP_DETAIL_LOGGING)
		return (EINVAL);

	(void) pthread_mutex_lock(&dialog_log.sip_logfile_mutex);
	if (!dialog_log.sip_logging_enabled) {
		dialog_log.sip_logfile = logfile;
		dialog_log.sip_logging_enabled = B_TRUE;
	}
	(void) pthread_mutex_unlock(&dialog_log.sip_logfile_mutex);
	return (0);
}

void
sip_disable_trans_logging()
{
	(void) pthread_mutex_lock(&trans_log.sip_logfile_mutex);
	if (trans_log.sip_logging_enabled)
		trans_log.sip_logging_enabled = B_FALSE;
	(void) pthread_mutex_unlock(&trans_log.sip_logfile_mutex);
}

void
sip_disable_dialog_logging()
{
	(void) pthread_mutex_lock(&dialog_log.sip_logfile_mutex);
	if (dialog_log.sip_logging_enabled)
		dialog_log.sip_logging_enabled = B_FALSE;
	(void) pthread_mutex_unlock(&dialog_log.sip_logfile_mutex);
}

static void
sip_print_digest(uint16_t *digest, int len, FILE *fp)
{
	int	cnt;

	for (cnt = 0; cnt < len; cnt++)
		(void) fprintf(fp, "%u ", digest[cnt]);
	(void) fprintf(fp, "\n\n");
}

/*
 * Logs all the messages exchanged within a transaction to the transaction
 * log file. Logged messages are then freed.
 */
static void
sip_write_xaction_to_log(void *obj)
{
	sip_xaction_t	*trans = (sip_xaction_t *)obj;
	sip_log_t	*sip_log;
	int		count;
	sip_msg_chain_t	*msg_chain;
	sip_msg_chain_t	*nmsg_chain;
	char		timebuf[TIME_BUF_SIZE];
	struct tm	tms;
	FILE		*sip_trans_logfile = trans_log.sip_logfile;

	assert(trans != NULL && sip_trans_logfile != NULL);
	(void) fprintf(sip_trans_logfile, "************* Begin Transaction"
	    " *************\n");
	(void) fprintf(sip_trans_logfile, "Branchid\t\t: %s\n",
	    trans->sip_xaction_branch_id);
	(void) fprintf(sip_trans_logfile, "Digest\t\t\t: ");
	sip_print_digest(trans->sip_xaction_hash_digest, 8, sip_trans_logfile);
	(void) fprintf(sip_trans_logfile, "-----------------------------\n");
	for (count = 0; count <= SIP_SRV_NONINV_TERMINATED; count++) {
		sip_log = &trans->sip_xaction_log[count];
		if (sip_log->sip_msgcnt == 0)
			continue;
		(void) fprintf(sip_trans_logfile, "Transaction State\t: %s\n\n",
		    sip_get_xaction_state(count));
		msg_chain = sip_log->sip_msgs;
		while (msg_chain != NULL) {
			nmsg_chain = msg_chain->next;
			(void) strftime(timebuf, sizeof (timebuf), NULL,
			    localtime_r(&msg_chain->msg_timestamp, &tms));
			(void) fprintf(sip_trans_logfile, "%s| Message -"
			    " %d\n%s", timebuf, msg_chain->msg_seq, msg_chain->
			    sip_msg);
			free(msg_chain->sip_msg);
			free(msg_chain);
			--sip_log->sip_msgcnt;
			msg_chain = nmsg_chain;
		}
		(void) fprintf(sip_trans_logfile,
		    "-----------------------------\n");
		(trans->sip_xaction_log[count]).sip_msgs = NULL;
	}
	(void) fprintf(sip_trans_logfile, "************* End Transaction "
	    "*************\n");
	(void) fflush(sip_trans_logfile);
}

/*
 * Logs all the messages exchanged within a dialog to the dialog
 * log file. Logged messages are then freed.
 */
static void
sip_write_dlg_to_log(void *obj)
{
	_sip_dialog_t	*dialog = (_sip_dialog_t *)obj;
	sip_log_t	*sip_log;
	int		count;
	sip_msg_chain_t	*msg_chain;
	sip_msg_chain_t	*nmsg_chain;
	char		timebuf[TIME_BUF_SIZE];
	struct tm	tms;
	FILE		*sip_dialog_logfile = dialog_log.sip_logfile;

	assert(dialog != NULL && sip_dialog_logfile != NULL);

	(void) fprintf(sip_dialog_logfile, "************* Begin Dialog "
	    "*************\n");
	(void) fprintf(sip_dialog_logfile, "Digest\t\t\t: ");
	sip_print_digest(dialog->sip_dlg_id, 8, sip_dialog_logfile);
	(void) fprintf(sip_dialog_logfile, "-----------------------------\n");
	for (count = 0; count <= SIP_DLG_DESTROYED; count++) {
		sip_log = &dialog->sip_dlg_log[count];
		if (sip_log->sip_msgcnt == 0)
			continue;
		(void) fprintf(sip_dialog_logfile, "Dialog State\t\t: %s\n\n",
		    sip_get_dialog_state_str(count));
		msg_chain = sip_log->sip_msgs;
		while (msg_chain != NULL) {
			nmsg_chain = msg_chain->next;
			(void) strftime(timebuf, sizeof (timebuf), NULL,
			    localtime_r(&msg_chain->msg_timestamp, &tms));
			(void) fprintf(sip_dialog_logfile, "%s| Message -"
			    " %d\n%s", timebuf, msg_chain->msg_seq, msg_chain->
			    sip_msg);
			free(msg_chain->sip_msg);
			free(msg_chain);
			--sip_log->sip_msgcnt;
			msg_chain = nmsg_chain;
		}
		(void) fprintf(sip_dialog_logfile,
		    "-----------------------------\n");
		(dialog->sip_dlg_log[count]).sip_msgs = NULL;
	}
	(void) fprintf(sip_dialog_logfile, "************* End Dialog "
	    "*************\n");
	(void) fflush(sip_dialog_logfile);
}

/*
 * Calls the appropriate function to log transaction or dialog messages.
 * If this function is called because of assertion failure, then the file and
 * line where the assertion failed is logged to the log file.
 */
void
sip_write_to_log(void *obj, int type, char *file, int line)
{
	if (type & SIP_TRANSACTION_LOG) {
		(void) pthread_mutex_lock(&trans_log.sip_logfile_mutex);
		if (trans_log.sip_logging_enabled) {
			if (type & SIP_ASSERT_ERROR) {
				(void) fprintf(trans_log.sip_logfile,
				    "Assertion Failure at %s:%d\n", file, line);
			}
			sip_write_xaction_to_log(obj);
		}
		(void) pthread_mutex_unlock(&trans_log.sip_logfile_mutex);
	} else {
		(void) pthread_mutex_lock(&dialog_log.sip_logfile_mutex);
		if (dialog_log.sip_logging_enabled) {
			if (type & SIP_ASSERT_ERROR) {
				(void) fprintf(dialog_log.sip_logfile,
				    "Assertion Failure at %s:%d\n", file, line);
			}
			sip_write_dlg_to_log(obj);
		}
		(void) pthread_mutex_unlock(&dialog_log.sip_logfile_mutex);
	}
}

/*
 * This function records the messages that are exchanged within a dialog or
 * transaction. If logging is enabled the recorded messages are then dumped
 * to the log file just before deleting the transaction or dialog.
 */
void
sip_add_log(sip_log_t *sip_log, sip_msg_t sip_msg, int seq, int type)
{
	char			*msgstr;
	sip_msg_chain_t		*new_msg;
	sip_msg_chain_t		*msg_chain = sip_log->sip_msgs;

	/*
	 * No need to take any locks here. Caller of this function MUST
	 * have already taken the transaction or dialog lock.
	 */
	if (((type == SIP_DIALOG_LOG) && !dialog_log.sip_logging_enabled) ||
	    ((type == SIP_TRANSACTION_LOG) && !trans_log.sip_logging_enabled)) {
		return;
	}

	new_msg = calloc(1, sizeof (sip_msg_chain_t));
	if (new_msg == NULL)
		return;

	msgstr = sip_msg_to_str(sip_msg, NULL);
	if (msgstr == NULL) {
		free(new_msg);
		return;
	}

	new_msg->sip_msg =  msgstr;
	new_msg->msg_seq = seq;
	new_msg->msg_timestamp = time(NULL);
	new_msg->next = NULL;
	if (sip_log->sip_msgcnt == 0) {
		sip_log->sip_msgs = new_msg;
	} else {
		while (msg_chain->next != NULL)
			msg_chain = msg_chain->next;
		msg_chain->next = new_msg;
	}
	sip_log->sip_msgcnt++;
}

/*
 * Given a counter group and counter name within the group, returns the value
 * associated with the counter in 'cntval'.
 */
int
sip_get_counter_value(int group, int counter, void *cntval, size_t cntlen)
{
	if (group != SIP_TRAFFIC_COUNTERS || cntval == NULL)
		return (EINVAL);
	if ((counter == SIP_COUNTER_START_TIME || counter ==
	    SIP_COUNTER_STOP_TIME) && (cntlen != sizeof (time_t))) {
		return (EINVAL);
	} else if (cntlen != sizeof (uint64_t)) {
		return (EINVAL);
	}

	(void) pthread_mutex_lock(&sip_counters.sip_counter_mutex);
	switch (counter) {
		case SIP_TOTAL_BYTES_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_total_bytes_rcvd;
			break;
		case SIP_TOTAL_BYTES_SENT:
			*(uint64_t *)cntval = sip_counters.sip_total_bytes_sent;
			break;
		case SIP_TOTAL_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_total_req_rcvd;
			break;
		case SIP_TOTAL_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_total_req_sent;
			break;
		case SIP_TOTAL_RESP_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_total_resp_rcvd;
			break;
		case SIP_TOTAL_RESP_SENT:
			*(uint64_t *)cntval = sip_counters.sip_total_resp_sent;
			break;
		case SIP_ACK_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_ack_req_rcvd;
			break;
		case SIP_ACK_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_ack_req_sent;
			break;
		case SIP_BYE_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_bye_req_rcvd;
			break;
		case SIP_BYE_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_bye_req_sent;
			break;
		case SIP_CANCEL_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_cancel_req_rcvd;
			break;
		case SIP_CANCEL_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_cancel_req_sent;
			break;
		case SIP_INFO_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_info_req_rcvd;
			break;
		case SIP_INFO_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_info_req_sent;
			break;
		case SIP_INVITE_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_invite_req_rcvd;
			break;
		case SIP_INVITE_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_invite_req_sent;
			break;
		case SIP_NOTIFY_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_notify_req_rcvd;
			break;
		case SIP_NOTIFY_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_notify_req_sent;
			break;
		case SIP_OPTIONS_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_options_req_rcvd;
			break;
		case SIP_OPTIONS_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_options_req_sent;
			break;
		case SIP_PRACK_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_prack_req_rcvd;
			break;
		case SIP_PRACK_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_prack_req_sent;
			break;
		case SIP_REFER_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_refer_req_rcvd;
			break;
		case SIP_REFER_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_refer_req_sent;
			break;
		case SIP_REGISTER_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.
			    sip_register_req_rcvd;
			break;
		case SIP_REGISTER_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.
			    sip_register_req_sent;
			break;
		case SIP_SUBSCRIBE_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.
			    sip_subscribe_req_rcvd;
			break;
		case SIP_SUBSCRIBE_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.
			    sip_subscribe_req_sent;
			break;
		case SIP_UPDATE_REQ_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_update_req_rcvd;
			break;
		case SIP_UPDATE_REQ_SENT:
			*(uint64_t *)cntval = sip_counters.sip_update_req_sent;
			break;
		case SIP_1XX_RESP_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_1xx_resp_rcvd;
			break;
		case SIP_1XX_RESP_SENT:
			*(uint64_t *)cntval = sip_counters.sip_1xx_resp_sent;
			break;
		case SIP_2XX_RESP_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_2xx_resp_rcvd;
			break;
		case SIP_2XX_RESP_SENT:
			*(uint64_t *)cntval = sip_counters.sip_2xx_resp_sent;
			break;
		case SIP_3XX_RESP_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_3xx_resp_rcvd;
			break;
		case SIP_3XX_RESP_SENT:
			*(uint64_t *)cntval = sip_counters.sip_3xx_resp_sent;
			break;
		case SIP_4XX_RESP_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_4xx_resp_rcvd;
			break;
		case SIP_4XX_RESP_SENT:
			*(uint64_t *)cntval = sip_counters.sip_4xx_resp_sent;
			break;
		case SIP_5XX_RESP_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_5xx_resp_rcvd;
			break;
		case SIP_5XX_RESP_SENT:
			*(uint64_t *)cntval = sip_counters.sip_5xx_resp_sent;
			break;
		case SIP_6XX_RESP_RCVD:
			*(uint64_t *)cntval = sip_counters.sip_6xx_resp_rcvd;
			break;
		case SIP_6xx_RESP_SENT:
			*(uint64_t *)cntval = sip_counters.sip_6xx_resp_sent;
			break;
		case SIP_COUNTER_START_TIME:
			*(time_t *)cntval = sip_counters.starttime;
			break;
		case SIP_COUNTER_STOP_TIME:
			*(time_t *)cntval = sip_counters.stoptime;
			break;
		default:
			(void) pthread_mutex_unlock(&sip_counters.
			    sip_counter_mutex);
			return (EINVAL);
	}
	(void) pthread_mutex_unlock(&sip_counters.sip_counter_mutex);
	return (0);
}

/*
 * Enables the SIP performance/traffic counting. Also reset's the previous
 * counter values and starts counting afresh.
 */
int
sip_enable_counters(int group)
{
	if (group != SIP_TRAFFIC_COUNTERS)
		return (EINVAL);
	(void) pthread_mutex_lock(&sip_counters.sip_counter_mutex);
	/* If it's not enabled, enable it and capture the start time */
	if (!sip_counters.enabled) {
		/* zero all the counters except for the mutex at the end */
		(void) bzero(&sip_counters, sizeof (sip_traffic_counters_t) -
		    sizeof (pthread_mutex_t));
		sip_counters.enabled = B_TRUE;
		sip_counters.starttime = time(NULL);
		sip_counters.stoptime = 0;
	}
	(void) pthread_mutex_unlock(&sip_counters.sip_counter_mutex);
	return (0);
}

/*
 * Disables the SIP performance/traffic counting. If already disabled it just
 * exits without doing anyting. It records the stop time.
 */
int
sip_disable_counters(int group)
{
	if (group != SIP_TRAFFIC_COUNTERS)
		return (EINVAL);
	(void) pthread_mutex_lock(&sip_counters.sip_counter_mutex);
	if (sip_counters.enabled) {
		sip_counters.enabled = B_FALSE;
		sip_counters.stoptime = time(NULL);
	}
	(void) pthread_mutex_unlock(&sip_counters.sip_counter_mutex);
	return (0);
}
