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
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <libgen.h>
#include <libintl.h>
#include <errno.h>
#include <sys/syscall.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <libhal.h>

#include <rmm_common.h>

char	*progname;

static boolean_t d_opt, l_opt, o_opt, u_opt, eject_opt,
    closetray_opt, query_opt;

static void usage();
static void nomem();

static void
usage()
{
	if (!u_opt) {
		(void) fprintf(stderr,
		    "%s: [-dlu] [-o options] [nickname | device] "
		    "[mount_point]\n", progname);
	} else {
		(void) fprintf(stderr,
		    "%s: [-dl] [nickname | device]\n", progname);
	}
}

static int
rmmount(int argc, char **argv)
{
	int		c;
	action_t	action;
	LibHalContext	*hal_ctx;
	DBusError	error;
	rmm_error_t	rmm_error;
	LibHalDrive	*d;
	GSList		*volumes;
	const char	*default_name;
	char		**opts = NULL;
	int		num_opts = 0;
	char		*mountpoint = NULL;
	char		**p;
	int		print_mask;
	int		ret = 0;

	progname = basename(argv[0]);

	if (strcmp(progname, "rmumount") == 0) {
		u_opt = B_TRUE;
	}

	if (getenv("RMMOUNT_DEBUG") != NULL) {
		rmm_debug = 1;
	}

	while ((c = getopt(argc, argv, "?dlo:u")) != -1) {
		switch (c) {
		case 'd':
			d_opt = B_TRUE;
			break;
		case 'l':
			l_opt = B_TRUE;
			break;
		case 'o':
			o_opt = B_TRUE;
			if ((opts = g_strsplit(optarg, ",", 10)) == NULL) {
				nomem();
			}
			for (num_opts = 0, p = &opts[0]; *p != NULL; p++) {
				num_opts++;
			}
			break;
		case 'u':
			u_opt = B_TRUE;
			break;
		case '?':
			usage();
			return (0);
		default:
			usage();
			return (1);
		}
	}

	if (u_opt) {
		action = UNMOUNT;
	} else if (closetray_opt) {
		action = CLOSETRAY;
	} else if (eject_opt) {
		action = EJECT;
	} else {
		action = INSERT;
	}

	if ((hal_ctx = rmm_hal_init(0, 0, 0, 0, &error, &rmm_error)) == NULL) {
		(void) fprintf(stderr, gettext("warning: %s\n"),
		    rmm_strerror(&error, rmm_error));
		rmm_dbus_error_free(&error);
		if ((rmm_error == RMM_EDBUS_CONNECT) ||
		    (rmm_error == RMM_EHAL_CONNECT)) {
			return (99);
		} else {
			return (1);
		}
	}

	if (d_opt) {
		/* -d: print default name and exit */
		if ((d = rmm_hal_volume_find_default(hal_ctx, &error,
		    &default_name, &volumes)) == NULL) {
			default_name = "nothing inserted";
		} else {
			rmm_volumes_free(volumes);
			libhal_drive_free(d);
		}
		(void) printf(gettext("Default device is: %s\n"), default_name);
	} else if (l_opt) {
		/* -l: list volumes and exit */
		print_mask = RMM_PRINT_MOUNTABLE;
		if (eject_opt) {
			print_mask |= RMM_PRINT_EJECTABLE;
		}
		rmm_print_volume_nicknames(hal_ctx, &error, print_mask);
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

			if (query_opt) {
				ret = rmm_rescan(hal_ctx, default_name,
				    B_TRUE) ? 0 : 1;
			} else {
				ret = rmm_action(hal_ctx, default_name, action,
				    0, 0, 0, 0) ? 0 : 1;
			}
		}
	} else {
		if (argc - optind > 1) {
			mountpoint = argv[optind + 1];
		}
		if (query_opt) {
			ret = rmm_rescan(hal_ctx, argv[optind],
			    B_TRUE) ? 0 : 1;
		} else {
			ret = rmm_action(hal_ctx, argv[optind], action,
			    0, opts, num_opts, mountpoint) ? 0 : 1;
		}
	}

	rmm_dbus_error_free(&error);
	rmm_hal_fini(hal_ctx);

	return (ret);
}

static int
rmumount(int argc, char **argv)
{
	return (rmmount(argc, argv));
}

static int
eject(int argc, char **argv)
{
	if (getenv("EJECT_CLOSETRAY") != NULL) {
		closetray_opt = B_TRUE;
	} else if (getenv("EJECT_QUERY") != NULL) {
		query_opt = B_TRUE;
	} else {
		eject_opt = B_TRUE;
	}
	return (rmmount(argc, argv));
}

static void
nomem(void)
{
	(void) fprintf(stderr, gettext("%s: Out of memory\n"), progname);
	exit(1);
}


/*
 * get the name by which this program was called
 */
static char *
get_progname(char *path)
{
	char    *s;
	char    *p;

	if ((s = strdup(path)) == NULL) {
		perror(path);
		exit(1);
	}

	p = strrchr(s, '/');
	if (p != NULL) {
		strcpy(s, p + 1);
	}

	return (s);
}

int
main(int argc, char **argv)
{
	int ret = 1;

	vold_init(argc, argv);

	progname = get_progname(argv[0]);

	if (strcmp(progname, "rmmount") == 0) {
		if ((getenv("VOLUME_ACTION") != NULL) &&
		    (getenv("VOLUME_PATH") != NULL)) {
			ret = vold_rmmount(argc, argv);
		} else {
			ret = rmmount(argc, argv);
		}
	} else if (strcmp(progname, "rmumount") == 0) {
		ret = rmumount(argc, argv);
	} else if (strcmp(progname, "eject") == 0) {
		ret = eject(argc, argv);
	} else {
		(void) fprintf(stderr, "rmmount: invalid program name\n");
		ret = 1;
	}

	return (ret);
}
