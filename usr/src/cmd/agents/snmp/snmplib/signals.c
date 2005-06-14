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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <signal.h>
#include <stdio.h>

#include "snmp_msg.h"
#include "signals.h"
#include "error.h"

/*
 *	SIGQUIT: do not trap it to be able to generate a core
 */

int
signals_init(void signals_sighup(), void signals_exit(), char *error_label)
{

	struct sigaction act;
	act.sa_flags = 0;
	error_label[0] = '\0';

	act.sa_handler = signals_sighup;
	if (sigaction(SIGHUP, &act, NULL) == -1) {
		(void) sprintf(error_label, ERR_MSG_SIGACT, SIGHUP,
		"signals_sighup()", errno_string());
		return (-1);
	} else {
		act.sa_handler = signals_exit;
		if (sigaction(SIGINT, &act, NULL) == -1) {
			(void) sprintf(error_label, ERR_MSG_SIGACT, SIGINT,
			"signals_exit()", errno_string());
			return (-1);
		} else if (sigaction(SIGTERM, &act, NULL)  == -1) {
			(void) sprintf(error_label, ERR_MSG_SIGACT, SIGTERM,
			"signals_exit()", errno_string());
			return (-1);
		} else if (sigaction(SIGUSR1, &act, NULL) == -1) {
			(void) sprintf(error_label, ERR_MSG_SIGACT, SIGUSR1,
			"signals_exit()", errno_string());
			return (-1);
		} else if (sigaction(SIGUSR2, &act, NULL) == -1) {
			(void) sprintf(error_label, ERR_MSG_SIGACT, SIGUSR2,
			"signals_exit()", errno_string());
			return (-1);

		} else {
			act.sa_handler = SIG_IGN;
			if (sigaction(SIGCHLD, &act, NULL) == -1) {
				(void) sprintf(error_label, ERR_MSG_SIGACT,
				SIGCHLD, "SIG_IGN", errno_string());
				return (-1);
			} else {
				return (0);
			}
		}
	}
}
