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
 * init.c: initialization of scadm (access to the device driver for the
 * communication with the service processor - rscp_init)
 */

#include <libintl.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>  /* required by rsc.h */

#include "librsc.h"
#include "adm.h"


void
ADM_Init()
{
	int	status;

	status = rscp_init();
	if (status == 0) {
		return;
	}

	if (status == ENODEV) {

		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: The SC hardware was not detected.\n"));
		exit(-1);
	} else if (status == EAGAIN) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: The SC lock file was found. Only one\n"
		    "        instance of scadm can run at a given time"));
		exit(-1);
	} else {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("scadm: The SC hardware could not be "
		    "initialized.\n"));

		exit(-1);
	}
}
