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
 * scadm.c: main function
 */

#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "adm.h"


int
main(int argc,  char *argv[])
{
	(void) textdomain(TEXT_DOMAIN);
	(void) setlocale(LC_MESSAGES, "");

	if (getuid() != 0) {
		(void) fprintf(stderr, "\n%s\n\n",
		    gettext("This program MUST be run as root"));
		exit(-1);
	}

	if (argc < 2) {
		ADM_Usage();
		exit(-1);
	}

	ADM_Init();
	ADM_Process_command(argc, argv);

	return (0);
}
