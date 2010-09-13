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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * config.c: support for the scadm configlog option (to display the
 * service processor configuration log)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by librsc.h */
#include <limits.h>

#include "librsc.h"
#include "adm.h"

/* #define DEBUG */

void
ADM_Process_fru_log(int all)
{
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_get_config_log_r_t	*rscReply;
	rsci64			bytes_remaining, seqno;
	rsci16			request_size, response_size;
	dp_get_config_log_t	rscCmd;

	ADM_Start();

	/*
	 * Start by sending a zero-length request to ALOM, so that
	 * we can learn the length of the console log.  We expect
	 * ALOM to return the length of the entire log.  We get
	 * a snapshot of the length of the log here - it may however
	 * continue to grow as we're reading it.  We read only as
	 * much of the log as we get in this snapshot.
	 */
	rscCmd.start_seq = 0;
	rscCmd.length = 0;
	Message.type = DP_GET_CONFIG_LOG;
	Message.len = sizeof (rscCmd);
	Message.data = (char *)&rscCmd;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_GET_CONFIG_LOG_R, sizeof (*rscReply));

	rscReply = (dp_get_config_log_r_t *)Message.data;

	/*
	 * If we do not want the whole log, and the log is bigger than
	 * the length limit, then fetch just the last ADM_DEFAULT_LOG_LENGTH
	 * bytes from the log.  Else just get the whole thing.
	 */
	if ((all == 0) && (rscReply->remaining_log_bytes >
	    ADM_DEFAULT_LOG_LENGTH)) {
		bytes_remaining = ADM_DEFAULT_LOG_LENGTH;
		seqno = (rscReply->remaining_log_bytes +
		    rscReply->next_seq) - bytes_remaining;
	} else {
		bytes_remaining = rscReply->remaining_log_bytes;
		seqno = rscReply->next_seq;
	}
	request_size = sizeof (rscReply->buffer);
	ADM_Free(&Message);

	/*
	 * Timeout for RSC response.
	 */
	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;

	/*
	 * This loop runs as long as there is data in the log, or until
	 * we hit the default limit (above).  It's possible that ALOM may
	 * shrink the log - we need to account for this.  If ALOM returns
	 * no data, we bail out.
	 */
	while (bytes_remaining) {
		rscCmd.start_seq = seqno;
		rscCmd.length = (bytes_remaining < request_size) ?
		    bytes_remaining : request_size;
		Message.type = DP_GET_CONFIG_LOG;
		Message.len = sizeof (rscCmd);
		Message.data = (char *)&rscCmd;
		ADM_Send(&Message);

		ADM_Recv(&Message, &Timeout,
		    DP_GET_CONFIG_LOG_R, sizeof (*rscReply));

		rscReply = (dp_get_config_log_r_t *)Message.data;

		/* If ALOM returns zero bytes, we're done. */
		response_size = rscReply->length;
		if (response_size == 0) {
			ADM_Free(&Message);
			break;
		}
		bytes_remaining -= response_size;
		if (rscReply->remaining_log_bytes < bytes_remaining) {
			bytes_remaining = rscReply->remaining_log_bytes;
		}

		/*
		 * If the byte at the original sequence number is no
		 * longer in the log, print a message.
		 */
		if (rscReply->next_seq > seqno + response_size) {
			printf(gettext("\nscadm: lost %d bytes of log data\n"),
			    rscReply->next_seq - (seqno + response_size));
		}
		seqno = rscReply->next_seq;

		/* Print the config log */
		if (fwrite(rscReply->buffer, sizeof (char), response_size,
		    stdout) != response_size) {
			perror(gettext("\ncouldn't write config log buffer"
			    " to stdout"));
			ADM_Free(&Message);
			break;
		}
		ADM_Free(&Message);
	}
	putchar('\n');
}
