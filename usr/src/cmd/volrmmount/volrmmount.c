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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <libintl.h>
#include <sys/types.h>

#include "vold.h"
#include "rmm_common.h"

char *progname = "volrmmount";

static void
usage()
{
	(void) fprintf(stderr,
	    gettext(
	    "\nusage: %s [-i | -e] [DEVICE | NICKNAME]\n"),
	    progname);
	(void) fprintf(stderr,
	    gettext("or:    %s -d\n"), progname);
	(void) fprintf(stderr,
	    gettext(
	    "options:\t-i        simulate volume being put in/inserted\n"));
	(void) fprintf(stderr,
	    gettext(
	    "options:\t-e        simulate volume being taken out/ejected\n"));
	(void) fprintf(stderr,
	    gettext("options:\t-d        show default device\n"));
	(void) fprintf(stderr,
	    gettext(
	    "\nThis command is deprecated. Use rmmount(1) instead.\n"));
}

int
main(int argc, char **argv)
{
	const char	*opts = "ied";
	int		c;
	boolean_t	opt_insert = B_FALSE;
	boolean_t	opt_eject = B_FALSE;
	boolean_t	opt_default = B_FALSE;
	action_t	action;
	LibHalContext	*hal_ctx;
	DBusError	error;
	rmm_error_t	rmm_error;
	LibHalDrive	*d;
	GSList		*volumes;
	const char	*default_name;
	int		ret = 0;

	while ((c = getopt(argc, argv, opts)) != EOF) {
		switch (c) {
		case 'i':
			opt_insert = B_TRUE;
			action = REMOUNT;
			break;
		case 'e':
			opt_eject = B_TRUE;
			action = UNMOUNT;
			break;
		case 'd':
			opt_default = B_TRUE;
			break;
		default:
			usage();
			return (1);
		}
	}
	if ((opt_insert && opt_eject) ||
	    (!opt_insert && !opt_eject && !opt_default)) {
		usage();
		return (1);
	}

	if ((hal_ctx = rmm_hal_init(0, 0, 0, 0, &error, &rmm_error)) == NULL) {
		(void) fprintf(stderr,
		    gettext("HAL initialization failed: %s\n"),
		    rmm_strerror(&error, rmm_error));
		rmm_dbus_error_free(&error);
		return (1);
	}

	if (opt_default) {
		/* -d: print default name and exit */
		if ((d = rmm_hal_volume_find_default(hal_ctx, &error,
		    &default_name, &volumes)) == NULL) {
			default_name = "nothing inserted";
		} else {
			rmm_volumes_free(volumes);
			libhal_drive_free(d);
		}
		(void) printf(gettext("Default device is: %s\n"), default_name);
	} else if (optind == argc) {
		/* no name provided, use default */
		if ((d = rmm_hal_volume_find_default(hal_ctx, &error,
		    &default_name, &volumes)) == NULL) {
			(void) fprintf(stderr,
			    gettext("No default media available\n"));
			ret = 1;
		} else {
			rmm_volumes_free(volumes);
			libhal_drive_free(d);
			if (!rmm_action(hal_ctx, default_name, action,
			    0, 0, 0, 0)) {
				ret = 1;
			}
		}
	} else {
		for (; optind < argc; optind++) {
			if (rmm_action(hal_ctx, argv[optind], action,
			    0, 0, 0, 0) != 0) {
				ret = 1;
			}
		}
	}

	rmm_hal_fini(hal_ctx);

	return (ret);
}
