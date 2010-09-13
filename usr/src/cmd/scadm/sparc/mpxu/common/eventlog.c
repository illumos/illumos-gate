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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * eventlog.c: support for the scadm loghistory option (to display the
 * service processor log history)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by librsc.h */

#include "librsc.h"
#include "adm.h"

#include "event_mess.h"
#define	TAB '\t'
#define	BACKSLASH_ESCAPE '\\'

/* #define DEBUG */

static char *
getEventLogMessage(int eventId)
{
	int	category;
	int	event;
	char	**alertCategory;
	char	*alertMessage;

	category = eventId >> 16;
	event = eventId &0x0000ffff;

	alertCategory = rsc_alerts[category];
	if (alertCategory) {
		alertMessage = alertCategory[event];
	} else {
		return (NULL);
	}

	if (alertMessage) {
		return (alertMessage);
	} else {
		return (NULL);
	}
}

/*
 * getNextEventLogParam
 *
 *	Return the next message from a TAB delimited message parameter list.
 *  Given a string message "mess1\tmess2\tmess3\t\t", this function will
 *  return a ponter to "mess2" the first time it is called.
 */
static char *
getNextEventLogParam(char *mess)
{
	char *p = mess;

	do {
		/* ESCAPE means interpret the next character literally */
		if ((p != mess) && (*(p-1) == BACKSLASH_ESCAPE)) {
			p++;
			continue;
		}

		if ((*p == TAB) && (*(p+1) == TAB)) {
			/* Double tab means end of list */
			return (NULL);
		}
		p++;

	} while (*p != TAB);

	/* return pointer to char after TAB */
	p++;
	return (p);

}

/*
 * expandEventLogMessage
 *
 *	This function will expand the base message for the category/event
 *  passed in with the TAB delimited parameters passed in via messParams.
 * 	The expanded message will be returned in the buf character buffer.
 */

static int
expandEventLogMessage(int eventId, char *messParams, size_t messParamsLen,
    char *buf)
{

	char	*alertMessage;
	char	*s;
	char	*d;
	char	*param;

	/* Get Alert message from internal tables */
	alertMessage = getEventLogMessage(eventId);
	if (alertMessage == NULL) {
		(void) strcpy(buf, "Unknown alert");
		return (strlen("Unknown alert"));
	}

	/* No message parameters to copy */
	if (messParamsLen == 0) {
		(void) strcpy(buf, alertMessage);
		return (strlen(buf));
	}

	/* A %s in the base message means we expand with a parameter */
	if (strstr(alertMessage, "%s")) {
		s = alertMessage;
		d = buf;
		param = messParams;

		do {
			if ((*s == '%') && (*(s+1) == 's')) {
				if (param) {
					char *p = param;

					while ((*p) && (*p != TAB)) {
						*d++ = *p++;
					}
				}
				/* Get next parameter on list for next %s */
				param = getNextEventLogParam(param);
				s += 2;
			}
		} while ((*d++ = *s++));

	} else {
		/* If no %s tokens to expand, just copy message */
		(void) strcpy(buf, alertMessage);
	}

	return (strlen(buf));

}

static void
ADM_Process_old_event_log()
{
	char			timebuf[32];
	char			messBuff[256];
	char			eventMsgBuf[256];
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_get_event_log_r_t	*rscReply;
	char			*datap;
	dp_event_log_entry_t	entry;
	int			i, len, entryhdrsize;

	ADM_Start();

	Message.type = DP_GET_EVENT_LOG;
	Message.len = 0;
	Message.data = NULL;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_GET_EVENT_LOG_R, sizeof (*rscReply));

	/* Print the event log messages */
	rscReply = (dp_get_event_log_r_t *)Message.data;
	datap = (char *)rscReply->data;
	for (i = 0; i < rscReply->entry_count; i++) {
		entryhdrsize = sizeof (entry) - sizeof (entry.param);
		(void) memcpy(&entry, datap, entryhdrsize);
		datap += entryhdrsize;
		(void) memcpy(&entry.param, datap, entry.paramLen);
		(void) strftime(timebuf, sizeof (timebuf), "%b %d %H:%M:%S",
		    gmtime((time_t *)&entry.eventTime));
		(void) sprintf(messBuff, "%s : %08lx: \"", timebuf,
		    entry.eventId);
		len = expandEventLogMessage(entry.eventId, entry.param,
		    entry.paramLen, eventMsgBuf);
		(void) strncat(messBuff, eventMsgBuf, len);
		(void) strcat(messBuff, "\"\r\n");
		(void) printf(messBuff);
		datap += entry.paramLen;
	}

	ADM_Free(&Message);
}

static int
ADM_Process_new_event_log(int all)
{
	char			timebuf[32];
	char			messBuff[256];
	char			eventMsgBuf[256];
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_get_event_log2_r_t	*rscReply;
	char			*datap;
	dp_event_log_entry_t	entry;
	int			i, len, entryhdrsize, sent_ok;
	rsci64			events_remaining, seqno;
	rsci16			request_size, returned_events;
	dp_get_event_log2_t	rscCmd;

	ADM_Start();

	/*
	 * Start by sending a zero-length request to ALOM, so that
	 * we can learn the length of the console log.  We expect
	 * ALOM to return the length of the entire log.  We get
	 * a snapshot of the length of the log here - it may however
	 * continue to grow as we're reading it.  We read only as
	 * much of the log as we get in this snapshot.
	 *
	 * If the command fails, we quietly return failure here so
	 * that the caller can re-try with the old/legacy command.
	 */
	rscCmd.start_seq = 0;
	rscCmd.length = 0;
	Message.type = DP_GET_EVENT_LOG2;
	Message.len = sizeof (rscCmd);
	Message.data = (char *)&rscCmd;
	if (ADM_Send_ret(&Message) != 0) {
		return (1);
	}

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_GET_EVENT_LOG2_R, sizeof (*rscReply));

	rscReply = (dp_get_event_log2_r_t *)Message.data;

	/*
	 * Fetch an fixed number of events from the end of
	 * the log if at least that many exist, and we were not
	 * asked to fetch all the events.
	 */
	if ((all == 0) &&
	    (rscReply->remaining_log_events > DEFAULT_NUM_EVENTS)) {
		events_remaining = DEFAULT_NUM_EVENTS;
		seqno = (rscReply->remaining_log_events +
		    rscReply->next_seq) - events_remaining;
	} else {
		events_remaining = rscReply->remaining_log_events;
		seqno = rscReply->next_seq;
	}
	request_size = sizeof (rscReply->buffer);
	ADM_Free(&Message);

	/*
	 * This loop runs as long as there is data in the log, or until
	 * we hit the default limit (above).  It's possible that ALOM may
	 * shrink the log - we need to account for this.  If ALOM returns
	 * no data, we bail out.
	 */
	while (events_remaining) {
		rscCmd.start_seq = seqno;
		rscCmd.length = request_size;
		Message.type = DP_GET_EVENT_LOG2;
		Message.len = sizeof (rscCmd);
		Message.data = (char *)&rscCmd;
		ADM_Send(&Message);

		Timeout.tv_nsec = 0;
		Timeout.tv_sec  = ADM_TIMEOUT;
		ADM_Recv(&Message, &Timeout,
		    DP_GET_EVENT_LOG2_R, sizeof (*rscReply));

		rscReply = (dp_get_event_log2_r_t *)Message.data;

		/* If ALOM returns zero events, we're done. */
		returned_events = rscReply->num_events;
		if (returned_events == 0) {
			ADM_Free(&Message);
			break;
		}

		/*
		 * if the event at the original sequence number is no
		 * longer in the log, print a message
		 */
		if (seqno + returned_events < rscReply->next_seq) {
			printf(gettext("\nscadm: lost %d events\n"),
			    rscReply->next_seq - (seqno + returned_events));
		}

		/*
		 * get ready for next main loop iteration
		 */
		seqno = rscReply->next_seq;
		events_remaining -= returned_events;

		/* Print the event log messages */
		datap = rscReply->buffer;

		for (i = 0; i < returned_events; i++) {
			entryhdrsize = sizeof (entry) - sizeof (entry.param);
			(void) memcpy(&entry, datap, entryhdrsize);
			datap += entryhdrsize;
			(void) memcpy(&entry.param, datap, entry.paramLen);
			(void) strftime(timebuf, sizeof (timebuf),
			    "%b %d %H:%M:%S",
			    gmtime((time_t *)&entry.eventTime));
			(void) sprintf(messBuff, "%s : %08lx: \"", timebuf,
			    entry.eventId);
			len = expandEventLogMessage(entry.eventId, entry.param,
			    entry.paramLen, eventMsgBuf);
			(void) strncat(messBuff, eventMsgBuf, len);
			(void) strcat(messBuff, "\"\r\n");
			(void) printf(messBuff);
			datap += entry.paramLen;
		}

		ADM_Free(&Message);
	}
	return (0);
}

void
ADM_Process_event_log(int all)
{
	if (ADM_Process_new_event_log(all) != 0) {
		ADM_Process_old_event_log();
	}
}
