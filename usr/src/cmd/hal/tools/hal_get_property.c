/***************************************************************************
 * CVSID: $Id$
 *
 * hal_get_property.c : Get property for a device
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
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

/**
 * @defgroup HalGetProperty  Get HAL device property
 * @ingroup HalMisc
 *
 * @brief A commandline tool getting a property of a device. Uses libhal
 *
 * @{
 */

static LibHalContext *hal_ctx;

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
 "usage : hal-get-property --udi <udi> --key <key> \n"
 "                        [--hex] [--help] [--verbose] [--version]\n");
	fprintf (stderr,
 "\n"
 "        --udi            Unique Device Id\n"
 "        --key            Key of the property to get\n"
 "        --hex            Show integer values in hex (without leading 0x)\n"
 "        --verbose        Be verbose\n"
 "        --version        Show version and exit\n"
 "        --help           Show this information and exit\n"
 "\n"
 "This program retrieves a property from a device. If the property exist\n"
 "then it is printed on stdout and this program exits with exit code 0.\n"
 "On error, the program exits with an exit code different from 0\n"
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
	char *udi = NULL;
	char *key = NULL;
	int type;
	dbus_bool_t is_hex = FALSE;
	dbus_bool_t is_verbose = FALSE;
	dbus_bool_t is_version = FALSE;
	dbus_bool_t udi_exists = FALSE;
	char *str;
	DBusError error;

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
			{"key", 1, NULL, 0},
			{"hex", 0, NULL, 0},
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
			} else if (strcmp (opt, "hex") == 0) {
				is_hex = TRUE;
			} else if (strcmp (opt, "verbose") == 0) {
				is_verbose = TRUE;
			} else if (strcmp (opt, "version") == 0) {
				is_version = TRUE;
			} else if (strcmp (opt, "key") == 0) {
				key = strdup (optarg);
			} else if (strcmp (opt, "udi") == 0) {
				udi = strdup (optarg);
			}
			break;

		default:
			usage (argc, argv);
			return 1;
			break;
		}
	}

	if (is_version) {
		printf ("hal-get-property " PACKAGE_VERSION "\n");
		return 0;
	}

	if (udi == NULL || key == NULL) {
		usage (argc, argv);
		return 1;
	}

	dbus_error_init (&error);
	if ((hal_ctx = libhal_ctx_new ()) == NULL) {
		fprintf (stderr, "error: libhal_ctx_new\n");
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
			dbus_error_free (&error);
		}
		fprintf (stderr, "Could not initialise connection to hald.\n"
				 "Normally this means the HAL daemon (hald) is not running or not ready.\n");
		return 1;
	}

        /* check UDI exists */
	udi_exists = libhal_device_exists (hal_ctx, udi, &error);
	if (!udi_exists) {
		fprintf (stderr, "error: UDI %s does not exist\n", udi);
		return 1;
	}
        if (dbus_error_is_set(&error)) {
		fprintf (stderr, "error: libhal_device_exists: %s: %s\n", error.name, error.message);
		dbus_error_free (&error);
		return 1;
	}


	type = libhal_device_get_property_type (hal_ctx, udi, key, &error);
	if (type == LIBHAL_PROPERTY_TYPE_INVALID) {
		if (dbus_error_is_set(&error)) {
		        fprintf (stderr, "error: libhal_device_get_property_type: %s: %s\n", error.name, error.message);
			dbus_error_free (&error);
		} else {
		        fprintf (stderr, "error: libhal_device_get_property_type: invalid params.\n");
		}
		return 1;
	}
	/* emit the value to stdout */
	switch (type) {
	case LIBHAL_PROPERTY_TYPE_STRING:
		str = libhal_device_get_property_string (hal_ctx, udi, key, &error);
		if (is_verbose)
			printf ("Type is string\n");
		printf ("%s\n", str);
		libhal_free_string (str);
		break;
	case LIBHAL_PROPERTY_TYPE_INT32:
		if (is_verbose)
			printf ("Type is integer (shown in %s)\n",
				(is_hex ? "hexadecimal" : "decimal"));
		printf ((is_hex ? "%x\n" : "%d\n"),
			libhal_device_get_property_int (hal_ctx, udi, key, &error));
		break;
	case LIBHAL_PROPERTY_TYPE_UINT64:
		if (is_verbose)
			printf ("Type is uint64 (shown in %s)\n",
				(is_hex ? "hexadecimal" : "decimal"));
		printf ((is_hex ? "%llx\n" : "%llu\n"),
			(long long unsigned int) libhal_device_get_property_uint64 (hal_ctx, udi, key, &error));
		break;
	case LIBHAL_PROPERTY_TYPE_DOUBLE:
		if (is_verbose)
			printf ("Type is double\n");
		printf ("%f\n",
			libhal_device_get_property_double (hal_ctx, udi, key, &error));
		break;
	case LIBHAL_PROPERTY_TYPE_BOOLEAN:
		if (is_verbose)
			printf ("Type is boolean\n");
		printf ("%s\n",
			libhal_device_get_property_bool (hal_ctx, udi, key, &error) ? "true" : "false");
		break;

	case LIBHAL_PROPERTY_TYPE_STRLIST:
	{
		unsigned int i;
		char **strlist;

		if ((strlist = libhal_device_get_property_strlist (hal_ctx, udi, key, &error)) != NULL) {

			for (i = 0; strlist[i] != 0; i++) {
				printf ("%s", strlist[i]);
				if (strlist[i+1] != NULL)
					printf (" ");
			}
		}
		break;
	}
	default:
		printf ("Unknown type %d='%c'\n", type, type);
		return 1;
		break;
	}

	if (dbus_error_is_set (&error)) {
		fprintf (stderr, "error: %s: %s\n", error.name, error.message);
		dbus_error_free (&error);
		return 1;
	}


	return 0;
}

/**
 * @}
 */
