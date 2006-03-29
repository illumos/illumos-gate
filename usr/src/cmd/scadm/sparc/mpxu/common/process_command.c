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
 * process_command.c: parse the command line and call the proper function
 * to process the command
 */

#include <libintl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "adm.h"


void
ADM_Process_command(int argc, char *argv[])
{
	if (strcasecmp(argv[1], "help") == 0)
		ADM_Process_help();

	else if (strcasecmp(argv[1], "send_event") == 0)
		ADM_Process_send_event(argc, argv);

	else if (strcasecmp(argv[1], "modem_setup") == 0)
		ADM_Process_modem_setup();

	else if (strcasecmp(argv[1], "date") == 0)
		ADM_Process_date(argc, argv);

	else if (strcasecmp(argv[1], "set") == 0)
		ADM_Process_set(argc, argv);

	else if (strcasecmp(argv[1], "show") == 0)
		ADM_Process_show(argc, argv);

	else if (strcasecmp(argv[1], "resetrsc") == 0)
		ADM_Process_reset(argc, argv);

	else if (strcasecmp(argv[1], "download") == 0)
		ADM_Process_download(argc, argv);

	else if (strcasecmp(argv[1], "useradd") == 0)
		ADM_Process_useradd(argc, argv);

	else if (strcasecmp(argv[1], "userdel") == 0)
		ADM_Process_userdel(argc, argv);

	else if (strcasecmp(argv[1], "usershow") == 0)
		ADM_Process_usershow(argc, argv);

	else if (strcasecmp(argv[1], "userpassword") == 0)
		ADM_Process_userpassword(argc, argv);

	else if (strcasecmp(argv[1], "userperm") == 0)
		ADM_Process_userperm(argc, argv);

	else if (strcasecmp(argv[1], "status") == 0)
		ADM_Process_status(0);

	else if (strcasecmp(argv[1], "version") == 0) {
		if (argc == 3) {
			if (strcasecmp(argv[2], "-v") == 0) {
				ADM_Process_status(1);
			} else {
				(void) fprintf(stderr, "\n%s\n\n",
				    gettext("USAGE: scadm version [-v]"));
			}
		} else
			ADM_Process_status(0);

	} else if (strcasecmp(argv[1], "loghistory") == 0 ||
	    strcasecmp(argv[1], "lhist") == 0) {

		if (argc == 2) {
			ADM_Process_event_log(0);
		} else if (argc == 3 && strcmp(argv[2], "-a") == 0) {
			ADM_Process_event_log(1);
		} else {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("USAGE: scadm loghistory [-a]"));
			exit(-1);
		}

	} else if (strcasecmp(argv[1], "shownetwork") == 0) {

		if (argc != 2) {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("USAGE: scadm shownetwork"));
			exit(-1);
		}
		ADM_Process_show_network();

	} else if (strcasecmp(argv[1], "consolehistory") == 0) {

		if (argc == 2) {
			ADM_Process_console_log(0);
		} else if (argc == 3 && strcmp(argv[2], "-a") == 0) {
			ADM_Process_console_log(1);
		} else {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("USAGE: scadm consolehistory [-a]"));
			exit(-1);
		}

	} else if (strcasecmp(argv[1], "fruhistory") == 0) {

		if (argc == 2) {
			ADM_Process_fru_log(0);
		} else if (argc == 3 && strcmp(argv[2], "-a") == 0) {
			ADM_Process_fru_log(1);
		} else {
			(void) fprintf(stderr, "\n%s\n\n",
			    gettext("USAGE: scadm fruhistory [-a]"));
			exit(-1);
		}

	} else {
		(void) fprintf(stderr, "\n%s - \"%s\"\n",
		    gettext("scadm: command unknown"), argv[1]);
		ADM_Usage();
		exit(-1);
	}
}
