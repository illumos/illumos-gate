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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/uadmin.h>
#include <bsm/libbsm.h>

#define	SMF_RST "/etc/svc/volatile/resetting"

static const char *Usage = "Usage: %s cmd fcn [mdep]\n";

extern int audit_uadmin_setup(int, char **);
extern int audit_uadmin_success();

int
main(int argc, char *argv[])
{
	int cmd, fcn;
	uintptr_t mdep = NULL;
	sigset_t set;

	if (argc < 3 || argc > 4) {
		(void) fprintf(stderr, Usage, argv[0]);
		return (1);
	}

	(void) audit_uadmin_setup(argc, argv);

	(void) sigfillset(&set);
	(void) sigprocmask(SIG_BLOCK, &set, NULL);

	cmd = atoi(argv[1]);
	fcn = atoi(argv[2]);
	if (argc == 4) {	/* mdep argument given */
		if (cmd != A_REBOOT && cmd != A_SHUTDOWN && cmd != A_DUMP &&
		    cmd != A_FREEZE) {
			(void) fprintf(stderr, "%s: mdep argument not "
			    "allowed for this cmd value\n", argv[0]);
			(void) fprintf(stderr, Usage, argv[0]);
			return (1);
		} else {
			mdep = (uintptr_t)argv[3];
		}
	}

	if (geteuid() == 0) {
		if (audit_uadmin_success() == -1)
			(void) fprintf(stderr, "%s: can't turn off auditd\n",
			    argv[0]);

		if (cmd == A_SHUTDOWN || cmd == A_REBOOT)
			(void) creat(SMF_RST, 0777);
	}

	if (uadmin(cmd, fcn, mdep) < 0) {
		perror("uadmin");

		(void) unlink(SMF_RST);

		return (1);
	}

	return (0);
}
