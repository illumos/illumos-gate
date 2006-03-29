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
 * to support the scadm rscreset option (reset the service processor)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by rsc.h */

#include "librsc.h"
#include "adm.h"


static void usage();


void
ADM_Process_reset(int argc, char *argv[])
{
	rscp_msg_t	Message;

	if ((argc != 2) && (argc != 3)) {
		usage();
		exit(-1);
	}
	if (argc == 3) {
		if (strcasecmp(argv[2], "-s") != 0) {
			usage();
			exit(-1);
		}
	}

	/* If hard reset, reset rsc */
	if (argc == 2) {
		if (rsc_nmi() != 0) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("scadm: Unable to reset SC hardware"));
			exit(-1);
		}
	} else {
		/* Soft Reset */
		ADM_Start();
		Message.type = DP_RESET_RSC;
		Message.len  = 0;
		Message.data = 0x0;
		ADM_Send(&Message);
	}
}


static void
usage()
{
	(void) fprintf(stderr,
	    "\n%s\n\n", gettext("USAGE: scadm resetrsc [-s]"));
}
