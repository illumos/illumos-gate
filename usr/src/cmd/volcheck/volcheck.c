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
 * Copyright 2017 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include <libintl.h>
#include <sys/types.h>

#include "vold.h"
#include "rmm_common.h"

char *progname = "volcheck";

static void
usage()
{
	fprintf(stderr,
	    gettext("usage: %s [-t #secs -i #secs] [-v] [path | nickname]\n"),
	    progname);
	fprintf(stderr,
	    gettext("If path is not supplied all media is checked\n"));
}

int
main(int argc, char **argv)
{
	const char	*opts = "itv";
	int		c;
	LibHalContext	*hal_ctx;
	DBusError	error;
	rmm_error_t	rmm_error;
	int		ret = 0;

	vold_init(argc, argv);

	while ((c = getopt(argc, argv, opts)) != EOF) {
		switch (c) {
		case 'i':
			break;
		case 't':
			break;
		case 'v':
			break;
		default:
			usage();
			return (1);
		}
	}

	if ((hal_ctx = rmm_hal_init(0, 0, 0, 0, &error, &rmm_error)) == NULL) {
		(void) fprintf(stderr,
		    gettext("HAL initialization failed: %s\n"),
		    rmm_strerror(&error, rmm_error));
		rmm_dbus_error_free(&error);
		return (1);
	}

	if (optind == argc) {
		/* no name provided, check all */
		ret = rmm_rescan(hal_ctx, NULL, B_FALSE);
	} else {
		for (; optind < argc; optind++) {
			if (rmm_rescan(hal_ctx, argv[optind], B_FALSE) != 0) {
				ret = 1;
			}
		}
	}

	rmm_hal_fini(hal_ctx);

	return (ret);
}
