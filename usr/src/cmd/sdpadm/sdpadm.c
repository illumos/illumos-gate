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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <libintl.h>
#include <stdlib.h>
#include <errno.h>
#include <locale.h>
#include <unistd.h>
#include <strings.h>
#include <fcntl.h>
#include <stropts.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#define	E_SUCCESS	0		/* Exit status for success */
#define	E_ERROR		1		/* Exit status for error */
#define	E_USAGE		2		/* Exit status for usage error */

static const char USAGE[] = "Usage:\tsdpadm\tstatus\n\t\tenable\n\t\tdisable\n";
static const char OPTS[] = "?";

static const char FILEENTRY[] = "sysenable=%d\n";
static const char FILENAME[] = "/etc/sdp.conf";
static const char dcname[] = "/dev/sdp";

static char conf_header[] =
"#\n"
"# CDDL HEADER START\n"
"#\n"
"# The contents of this file are subject to the terms of the\n"
"# Common Development and Distribution License (the \"License\").\n"
"# You may not use this file except in compliance with the License.\n"
"#\n"
"# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE\n"
"# or http://www.opensolaris.org/os/licensing.\n"
"# See the License for the specific language governing permissions\n"
"# and limitations under the License.\n"
"#\n"
"# When distributing Covered Code, include this CDDL HEADER in each\n"
"# file and include the License file at usr/src/OPENSOLARIS.LICENSE.\n"
"# If applicable, add the following below this CDDL HEADER, with the\n"
"# fields enclosed by brackets \"[]\" replaced with your own identifying\n"
"# information: Portions Copyright [yyyy] [name of copyright owner]\n"
"#\n"
"# CDDL HEADER END\n"
"#\n"
"#\n"
"# ident \"@(#)sdp.conf   1.1     07/01/03 SMI\"\n"
"#\n"
"# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.\n"
"# Use is subject to license terms.\n"
"#\n\n";

static void
usage()
{
	(void) fprintf(stderr, gettext(USAGE));
	exit(E_USAGE);
}

int
main(int argc, char *argv[])
{
	int c, enable, ret = E_SUCCESS;
	int fd;
	FILE *fConf;
	struct strioctl stri;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, OPTS)) != EOF) {
		switch (c) {
			case '?':
				usage();
		}
	}

	if (argc != 2) {
		usage();
	}

	fd = open(dcname, O_RDONLY);
	if (fd  < 0) {
		(void) fprintf(stderr, gettext("opening %s failed errno %d\n"),
		    dcname, errno);
		exit(0);
	}

	if (argc == 2) {
		/* Parse the on|off from the user */
		if (strcasecmp(argv[1], "enable") == 0) {
			enable = 1;
		} else if (strcasecmp(argv[1], "disable") == 0) {
			enable = 0;
		} else if (strcasecmp(argv[1], "status") == 0)
			enable = -1;
		else {
			usage();
		}
	}

	stri.ic_cmd = SIOCSENABLESDP;
	stri.ic_timout = 0;
	stri.ic_len = sizeof (int);
	stri.ic_dp = (char *)&enable;

	if (ioctl(fd, I_STR, &stri) >= 0) {
		(void) fprintf(stdout, gettext("SDP is %s\n"),
		    enable ? "Enabled" : "Disabled");
		fConf = fopen(FILENAME, "w");
		if (NULL != fConf) {
			(void) fprintf(fConf, conf_header);
			if (enable == 0) {
				(void) fprintf(fConf, FILEENTRY, 0);
			} else {
				(void) fprintf(fConf, FILEENTRY, 1);
			}
			(void) fclose(fConf);
		}
	} else {
		perror("ioctl failed");
		ret = E_ERROR;
	}
	return (ret);
}
