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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <door.h>
#include <libintl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <libscf.h>

#include <cryptoutil.h>
#include <sys/crypto/elfsign.h>
#include "cryptoadm.h"

int
start_daemon(void)
{
	closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();

	return (execl(_PATH_KCFD, _PATH_KCFD, (char *)0));
}

int
stop_daemon(void)
{
	int fd = -1;
	int err = 0;
	struct door_info dinfo;

	/* read PID of kcfd process from kcfd lock file */
	if ((fd = open(_PATH_KCFD_DOOR, O_RDONLY)) == -1) {
		err = errno;
		cryptodebug("Can not open %s: %s", _PATH_KCFD_DOOR,
		    strerror(err));
		goto stop_fail;
	}

	if (door_info(fd, &dinfo) == -1 || dinfo.di_target == -1) {
		err = ENOENT;	/* no errno if di_target == -1 */
		cryptodebug("no door server listening on %s", _PATH_KCFD_DOOR);
		goto stop_fail;
	}

	cryptodebug("Sending SIGINT to %d", dinfo.di_target);
	/* send a signal to kcfd process */
	if ((kill(dinfo.di_target, SIGINT)) != 0) {
		err = errno;
		cryptodebug("failed to send a signal to kcfd: %s",
		    strerror(errno));
		goto stop_fail;
	}

stop_fail:
	if (fd != -1)
		(void) close(fd);

	if (err != 0)  {
		cryptoerror(LOG_STDERR, gettext(
		    "no kcfd available to stop - %s."),
		    strerror(err));
		/*
		 * We return with SMF_EXIT_OK because this was a request
		 * to stop something that wasn't running.
		 */
		return (SMF_EXIT_OK);
	}

	return (SMF_EXIT_OK);
}
