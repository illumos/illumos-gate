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
 * help.c: support for the scadm help option (display list of scadm commands)
 */

#include <libintl.h>
#include <stdio.h>

#include "adm.h"


void
ADM_Process_help()
{
	(void) printf("\n\n%s\n\n", gettext(
	    "USAGE: scadm <command> [options]\n"
	    "  For a list of commands, type \"scadm help\"\n"
	    "\n"
	    "scadm - COMMANDS SUPPORTED\n"
	    "  help, date, set, show, resetrsc, download, send_event, "
	    "modem_setup,\n"
	    "  useradd, userdel, usershow, userpassword, userperm, "
	    "shownetwork,\n"
	    "  consolehistory, fruhistory, loghistory, version\n"
	    "\n"
	    "scadm - COMMAND DETAILS\n"
	    "  scadm help => this message\n"
	    "  scadm date [-s] | [[mmdd]HHMM | mmddHHMM[cc]yy][.SS] => print "
	    "or set date\n"
	    "  scadm set <variable> <value> => set variable to value\n"
	    "  scadm show [variable] => show variable(s)\n"
	    "  scadm resetrsc [-s] => reset SC (-s soft reset)\n"
	    "  scadm download [boot] <file> => program firmware or [boot] "
	    "monitor\n"
	    "  scadm send_event [-c] \"message\" => send message as event "
	    "(-c CRITICAL)\n"
	    "  scadm modem_setup => connect to modem port\n"
	    "  scadm useradd <username> => add SC user account\n"
	    "  scadm userdel <username> => delete SC user account\n"
	    "  scadm usershow [username] => show user details\n"
	    "  scadm userpassword <username> => set user password\n"
	    "  scadm userperm <username> [cuar] => set user permissions\n"
	    "  scadm shownetwork => show network configuration\n"
	    "  scadm consolehistory [-a] => show SC console log\n"
	    "  scadm fruhistory [-a] => show SC FRU log\n"
	    "  scadm loghistory [-a] => show SC event log\n"
	    "  scadm version [-v] => show SC version (-v verbose)"));
}
