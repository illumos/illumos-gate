/***************************************************************************
 * CVSID: $Id$
 *
 * hal-is-caller-privileged.c : Determine if a caller is privileged
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <glib.h>
#include <stdlib.h>

#include <libhal.h>
#ifdef HAVE_POLKIT
#include <libpolkit.h>
#endif

/**
 *  usage:
 *  @argc:                Number of arguments given to program
 *  @argv:                Arguments given to program
 *
 *  Print out program usage.
 */
static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
                 "\n"
                 "usage : hal-is-caller-privileged --udi <udi> --action <action>\n"
                 "                                 --caller <caller-name>\n"
                 "                                 [--help] [--version]\n");
	fprintf (stderr,
                 "\n"
                 "        --udi            Unique Device Id\n"
                 "        --action         PolicyKit action to check for\n"
                 "        --caller         The name of the caller\n"
                 "        --version        Show version and exit\n"
                 "        --help           Show this information and exit\n"
                 "\n"
                 "This program determines if a given process on the system bus is\n"
                 "privileged for a given PolicyKit action for a given device. If an error\n"
                 "occurs this program exits with a non-zero exit code. Otherwise\n"
                 "the textual reply will be printed on stdout and this program will\n"
                 "exit with exit code 0. Note that only the super user (root)\n"
                 "or other privileged users can use this tool.\n"
                 "\n");
}

#ifdef HAVE_POLKIT
static void
permission_denied_privilege (const char *privilege, const char *uid)
{
        fprintf (stderr, "org.freedesktop.Hal.Device.PermissionDeniedByPolicy\n"
);
        fprintf (stderr, "%s refused uid %s\n", privilege, uid);
        exit (1);
}
#endif

/**
 *  main:
 *  @argc:                Number of arguments given to program
 *  @argv:                Arguments given to program
 *
 *  Returns:              Return code
 *
 *  Main entry point
 */
int
main (int argc, char *argv[])
{
	char *udi = NULL;
	char *action = NULL;
	char *caller = NULL;
        dbus_bool_t is_version = FALSE;
	DBusError error;
#ifdef HAVE_POLKIT
	LibPolKitContext *pol_ctx = NULL;
#endif
	DBusConnection *system_bus = NULL;
	uid_t calling_uid;
	char *privilege = NULL;
	const char *invoked_by_uid;
	gboolean allowed_by_privilege = FALSE;
        gboolean is_temporary_privilege;

	if (argc <= 1) {
		usage (argc, argv);
		return 1;
	}

	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
			{"udi", 1, NULL, 0},
			{"action", 1, NULL, 0},
			{"caller", 1, NULL, 0},
			{"version", 0, NULL, 0},
			{"help", 0, NULL, 0},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc, argv, "",
				 long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			opt = long_options[option_index].name;

			if (strcmp (opt, "help") == 0) {
				usage (argc, argv);
				return 0;
			} else if (strcmp (opt, "version") == 0) {
				is_version = TRUE;
			} else if (strcmp (opt, "udi") == 0) {
				udi = strdup (optarg);
			} else if (strcmp (opt, "caller") == 0) {
				caller = strdup (optarg);
			} else if (strcmp (opt, "action") == 0) {
				privilege = strdup (optarg);
			}
			break;

		default:
			usage (argc, argv);
			return 1;
			break;
		}
	}

	if (is_version) {
		printf ("hal-is-caller-privileged " PACKAGE_VERSION "\n");
		return 0;
	}

	if (udi == NULL || caller == NULL || privilege == NULL) {
		usage (argc, argv);
		return 1;
	}

	dbus_error_init (&error);
        system_bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (system_bus == NULL) {
                printf ("Cannot connect to the system bus\n");
                LIBHAL_FREE_DBUS_ERROR (&error);
		fprintf (stderr, "This program should only be started by hald.\n");
		exit (1);
        }

#ifdef HAVE_POLKIT
	pol_ctx = libpolkit_new_context (system_bus);
        if (pol_ctx == NULL) {
                printf ("Cannot get libpolkit context\n");
        }
	invoked_by_uid = getenv("HAL_METHOD_INVOKED_BY_UID");

        if (libpolkit_is_uid_allowed_for_privilege (pol_ctx,
						    caller,
                                                    invoked_by_uid,
                                                    privilege,
                                                    udi,
                                                    &allowed_by_privilege,
                                                    &is_temporary_privilege,
                                                    NULL) != LIBPOLKIT_RESULT_OK
) {
                printf ("cannot lookup privilege\n");
                fprintf (stderr, "Cannot lookup privilege from PolicyKit");
		exit (1);
        }

        if (!allowed_by_privilege) {
                printf ("caller don't possess privilege\n");
                permission_denied_privilege (privilege, invoked_by_uid);
        }
#endif

	printf("yes\n");
        return 0;
}
