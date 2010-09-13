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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <locale.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <libscf.h>	/* for SMF error exit codes */

#include <srpt_ioctl.h>


/* Globals */
char	cmdName[] = "svc-srpt";

int
main(int argc, char *argv[])
{
	int		ret;
	boolean_t	do_enable = B_FALSE;
	int		srpt_ioctl;
	int		fd = -1;
	int		saverr;
	char		*txt;
	struct stat	statbuf;

	(void) setlocale(LC_ALL, "");

	if (argc < 2 || argc > 2) {
		goto usage;
	}

	if (strcasecmp(argv[1], "start") == 0) {
		do_enable = B_TRUE;
		srpt_ioctl = SRPT_IOC_ENABLE_SVC;
	} else if (strcasecmp(argv[1], "stop") == 0)  {
		srpt_ioctl = SRPT_IOC_DISABLE_SVC;
	} else {
		goto usage;
	}

	fd = open(SRPT_NODE, O_RDONLY);
	if (fd < 0) {
		saverr = errno;

		(void) fprintf(stderr, "%s: %s (%s): %s\n", cmdName,
		    gettext("Could not open SRP Target pseudodevice"),
		    SRPT_NODE, strerror(saverr));

		if (saverr == ENOENT) {
			/* avoid having the service go into maintenance */
			if ((stat("/devices/ib", &statbuf)) != 0) {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext(
				    "No InfiniBand devices on this system."));
			}
			ret = 0;

		} else {
			ret = SMF_EXIT_ERR_FATAL; /* avoid retries */
		}

		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("SRPT Driver may not be loaded."));

		return (ret);
	}

	ret = ioctl(fd, srpt_ioctl, NULL);
	if (ret != 0) {
		if (do_enable) {
			txt = gettext("Could not enable SRP Target");
		} else {
			txt = gettext("Could not disable SRP Target");
		}

		(void) fprintf(stderr, "%s: %d", txt, ret);
		ret = SMF_EXIT_ERR_FATAL;
	}

	(void) close(fd);

	return (ret);

usage:
	(void) fprintf(stderr, gettext("Usage: %s start|stop"), cmdName);
	(void) fprintf(stderr, "\n");

	return (1);
}
