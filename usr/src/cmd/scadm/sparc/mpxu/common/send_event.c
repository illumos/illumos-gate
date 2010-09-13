/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * send_event.c: support for the scadm send_event option (send an event message
 * to the service processor)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by librsc.h */

#include "librsc.h"
#include "adm.h"


static void usage();

typedef union data_buffer {
	char	DataBuffer[DP_MAX_MSGLEN];
	void	*DataBuffer_p;
} data_buffer_t;

void
ADM_Process_send_event(int argc, char *argv[])
{
	rscp_msg_t		Message;
	struct timespec		Timeout;
	static data_buffer_t	DataBuffer;
	dp_send_alert_t		*Parms;
	char			*Alert;


	if ((argc != 3) && (argc != 4)) {
		usage();
		exit(-1);
	}
	if (argc == 4) {
		if (strcasecmp(argv[2],  "-c") != 0) {
			usage();
			exit(-1);
		}
	}

	ADM_Start();

	Parms = (dp_send_alert_t *)&DataBuffer;
	Alert = (char *)(&((char *)Parms)[sizeof (dp_send_alert_t)]);
	if (argc == 3) {
		Parms->critical = 0;
		(void) strcpy(Alert, argv[2]);
	} else {
		Parms->critical = 1;
		(void) strcpy(Alert, argv[3]);
	}
	if (strlen(Alert) > 80) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: event message can't exceed 80 characters"));
		exit(-1);
	}

	Message.type = DP_SEND_ALERT;
	Message.len  = sizeof (dp_send_alert_t) + strlen(Alert) + 1;
	Message.data = Parms;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout, DP_SEND_ALERT_R,
	    sizeof (dp_send_alert_r_t));

	if (*(int *)Message.data != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: could not send alert"));
		exit(-1);
	}

	ADM_Free(&Message);
}


static void
usage()
{
	(void) fprintf(stderr, "\n%s\n\n",
	    gettext("USAGE: scadm send_event [-c] \"message\""));
}
