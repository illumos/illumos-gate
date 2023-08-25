/***************************************************************************
 * CVSID: $Id$
 *
 * hal_find_by_capability.c : Find hal devices
 *
 * Copyright (C) 2005 David Zeuthen, <david@fubar.dk>
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

#include <libhal.h>


/** Print out program usage.
 *
 *  @param  argc                Number of arguments given to program
 *  @param  argv                Arguments given to program
 */
static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
 "\n"
 "usage : hal-find-by-capability --capability <capability>\n"
 "                              [--help] [--verbose] [--version]\n");
	fprintf (stderr,
 "\n"
 "        --capability     HAL Device Capability to search for\n"
 "        --verbose        Be verbose\n"
 "        --version        Show version and exit\n"
 "        --help           Show this information and exit\n"
 "\n"
 "This program prints the Unique Device Identifiers for HAL device\n"
 "objects of a given capability on stdout and exits with exit code 0\n"
 "If there is an error, the program exits with an exit code different\n"
 "from 0.\n"
 "\n");
}

/** Entry point
 *
 *  @param  argc                Number of arguments given to program
 *  @param  argv                Arguments given to program
 *  @return                     Return code
 */
int
main (int argc, char *argv[])
{
	int i;
	int num_udis;
	char **udis;
	char *capability = NULL;
	dbus_bool_t is_verbose = FALSE;
	dbus_bool_t is_version = FALSE;
	DBusError error;
	LibHalContext *hal_ctx;

	if (argc <= 1) {
		usage (argc, argv);
		return 1;
	}

	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
			{"capability", 1, NULL, 0},
			{"verbose", 0, NULL, 0},
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
			} else if (strcmp (opt, "verbose") == 0) {
				is_verbose = TRUE;
			} else if (strcmp (opt, "version") == 0) {
				is_version = TRUE;
			} else if (strcmp (opt, "capability") == 0) {
				capability = strdup (optarg);
			}
			break;

		default:
			usage (argc, argv);
			return 1;
			break;
		}
	}

	if (is_version) {
		printf ("hal-find-by-capability " PACKAGE_VERSION "\n");
		return 0;
	}

	if (capability == NULL) {
		usage (argc, argv);
		return 1;
	}

	dbus_error_init (&error);
	if ((hal_ctx = libhal_ctx_new ()) == NULL) {
		fprintf (stderr, "error: libhal_ctx_new\n");
		LIBHAL_FREE_DBUS_ERROR (&error);
		return 1;
	}
	if (!libhal_ctx_set_dbus_connection (hal_ctx, dbus_bus_get (DBUS_BUS_SYSTEM, &error))) {
		fprintf (stderr, "error: libhal_ctx_set_dbus_connection: %s: %s\n", error.name, error.message);
		LIBHAL_FREE_DBUS_ERROR (&error);
		return 1;
	}
	if (!libhal_ctx_init (hal_ctx, &error)) {
		if (dbus_error_is_set(&error)) {
			fprintf (stderr, "error: libhal_ctx_init: %s: %s\n", error.name, error.message);
			LIBHAL_FREE_DBUS_ERROR (&error);
		}
		fprintf (stderr, "Could not initialise connection to hald.\n"
				 "Normally this means the HAL daemon (hald) is not running or not ready.\n");
		return 1;
	}


	udis = libhal_find_device_by_capability (hal_ctx, capability, &num_udis, &error);

	if (dbus_error_is_set (&error)) {
		fprintf (stderr, "error: %s: %s\n", error.name, error.message);
		LIBHAL_FREE_DBUS_ERROR (&error);
		return 1;
	}

	if (is_verbose)
		printf ("Found %d device objects of capability '%s'\n", num_udis, capability);

	if (num_udis == 0) {
		return 1;
	}

	for (i = 0; i < num_udis; i++) {
		printf ("%s\n", udis[i]);
	}

	libhal_free_string_array (udis);

	return 0;
}

/**
 * @}
 */
