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
 * set.c: support for the scadm set option (set NV variables in the service
 * processor)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by librsc.h */

#include "librsc.h"
#include "adm.h"


void
ADM_Process_set(int argc, char *argv[])
{
	rscp_msg_t	Message;
	struct timespec	Timeout;
	static char	DataBuffer[DP_MAX_MSGLEN];


	if (argc != 4) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("USAGE: scadm set <variable> <value>"));
		exit(-1);
	}

	ADM_Start();

	Message.type = DP_SET_CFGVAR;
	Message.len  = strlen(argv[2]) + strlen(argv[3]) + 2;
	if (Message.len > DP_MAX_MSGLEN - 4) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: command line too long"));
		exit(-1);
	}

	/*
	 * Concatenate the two strings into DataBuffer.  Make sure you
	 * leave space for the string termination char.
	 */
	(void) strcpy(DataBuffer, argv[2]);
	(void) strcpy(&DataBuffer[strlen(argv[2])+1], argv[3]);
	Message.data = DataBuffer;

	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_SET_CFGVAR_R, sizeof (dp_set_cfgvar_r_t));

	if (*(int *)Message.data != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: invalid variable or value"));
		exit(-1);
	}

	ADM_Free(&Message);
}
