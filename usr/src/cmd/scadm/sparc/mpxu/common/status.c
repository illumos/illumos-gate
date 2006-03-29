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
 * status.c: support for scadm version option (to display the service processor
 * status, fw version)
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>  /* required by librsc.h */

#include "librsc.h"
#include "adm.h"


void
ADM_Process_status(int verbose)
{
	rscp_msg_t		Message;
	struct timespec		Timeout;
	dp_rsc_status_r_t	*rscStatus;


	ADM_Start();

	Message.type = DP_RSC_STATUS;
	Message.len  = 0;
	Message.data = NULL;
	ADM_Send(&Message);

	Timeout.tv_nsec = 0;
	Timeout.tv_sec  = ADM_TIMEOUT;
	ADM_Recv(&Message, &Timeout,
	    DP_RSC_STATUS_R, sizeof (dp_rsc_status_r_t));

	/* Print the status */
	rscStatus = (dp_rsc_status_r_t *)Message.data;
	(void) printf("\n");
	(void) printf("%s v%d.%d\n",
	    gettext("SC Version"),
	    rscStatus->release_rev_major, rscStatus->release_rev_minor);
	(void) printf("%s v%d.%d.%d\n",
	    gettext("SC Bootmon Version: "),
	    rscStatus->bootmon_rev_major, rscStatus->bootmon_rev_minor,
	    rscStatus->bootmon_rev_micro);
	if (verbose) {
		(void) printf("%s %08lX\r\n\n", gettext("SC Bootmon checksum:"),
		    rscStatus->bm_cksum);
	}

	(void) printf("%s v%d.%d.%d\n",
	    gettext("SC Firmware Version: "),
	    rscStatus->main_rev_major, rscStatus->main_rev_minor,
	    rscStatus->main_rev_micro);
	if (verbose) {
		(void) printf("%s %02d\r\n", gettext("SC Build Release:"),
		    rscStatus->rsc_build);
	}

	(void) printf("\n");


	if (verbose) {
		(void) printf("%s %08lX\r\n\n",
		    gettext("SC firmware checksum:"), rscStatus->fw_cksum);
		(void) printf("%s %s\r\n\n",
		    gettext("SC firmware built:"), rscStatus->creationDate);
		(void) printf("%s %ld%s\r\n\r\n",
		    gettext("SC System Memory Size:"), rscStatus->sys_mem,
		    gettext("MB"));
		(void) printf("%s %lx\r\n\r\n",
		    gettext("SC NVRAM Version ="), rscStatus->nvram_version);
	}
	/*
	 * Not currently implemented in firmware
	 * (void) printf("%s = %d\n",
	 *  gettext("Users currently logged in"), rscStatus->nusers);
	 */

	if (verbose) {
		/* 4388953 Display SC board type */
		(void) printf("%s %d\r\n\r\n",
		    gettext("SC hardware type:"), rscStatus->hardware_rev);
	}

	ADM_Free(&Message);
}
