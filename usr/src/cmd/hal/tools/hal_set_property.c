/***************************************************************************
 * CVSID: $Id$
 *
 * hal_set_property.c : Set property for a device
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <libhal.h>

static LibHalContext *hal_ctx;

enum property_op {
	PROP_INT,
	PROP_UINT64,
	PROP_STRING,
	PROP_DOUBLE,
	PROP_BOOL,
	PROP_STRLIST_PRE,
	PROP_STRLIST_POST,
	PROP_STRLIST_REM,
	PROP_INVALID
};

/**
 * @defgroup HalSetProperty  Set HAL device property
 * @ingroup HalMisc
 *
 * @brief A commandline tool setting a property of a device. Uses libhal
 *
 * @{
 */

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
 "usage : hal-set-property --udi <udi> --key <key>\n"
 "           (--int <value> | --string <value> | --bool <value> |\n"
 "            --strlist-pre <value> | --strlist-post <value> |\n"
 "            --strlist-rem <value> | --double <value> | --remove)\n"
 "           [--direct] [--help] [--version]\n");
	fprintf (stderr,
 "\n" "        --udi            Unique Device Id\n"
 "        --key            Key of the property to set\n"
 "        --int            Set value to an integer. Accepts decimal and "
 "                         hexadecimal prefixed with 0x or x\n"
 "        --uint64         Set value to an integer. Accepts decimal and "
 "                         hexadecimal prefixed with 0x or x\n"
 "        --string         Set value to a string\n"
 "        --double         Set value to a floating point number\n"
 "        --bool           Set value to a boolean, ie. true or false\n"
 "        --strlist-pre    Prepend a string to a list\n"
 "        --strlist-post   Append a string to a list\n"
 "        --strlist-rem    Remove a string from a list\n"
 "        --remove         Indicates that the property should be removed\n"
 "        --direct         Use direct HAL connection\n"
 "        --version        Show version and exit\n"
 "        --help           Show this information and exit\n"
 "\n"
 "This program attempts to set property for a device. Note that, due to\n"
 "security considerations, it may not be possible to set a property; on\n"
 "success this program exits with exit code 0. On error, the program exits\n"
 "with an exit code different from 0\n" "\n");
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
	dbus_bool_t rc = 0;
	char *udi = NULL;
	char *key = NULL;
	char *str_value = NULL;
	dbus_int32_t int_value = 0;
	dbus_uint64_t uint64_value = 0;
	double double_value = 0.0f;
	dbus_bool_t bool_value = TRUE;
	dbus_bool_t remove = FALSE;
	dbus_bool_t is_version = FALSE;
	dbus_bool_t udi_exists = FALSE;
	int type = PROP_INVALID;
	DBusError error;
	dbus_bool_t direct = FALSE;

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
			{"int", 1, NULL, 0},
			{"uint64", 1, NULL, 0},
			{"string", 1, NULL, 0},
			{"double", 1, NULL, 0},
			{"bool", 1, NULL, 0},
			{"strlist-pre", 1, NULL, 0},
			{"strlist-post", 1, NULL, 0},
			{"strlist-rem", 1, NULL, 0},
			{"direct", 0, NULL, 0},
			{"remove", 0, NULL, 0},
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
			} else if (strcmp (opt, "key") == 0) {
				key = strdup (optarg);
			} else if (strcmp (opt, "string") == 0) {
				str_value = strdup (optarg);
				type = PROP_STRING;
			} else if (strcmp (opt, "int") == 0) {
				int_value = strtol (optarg, NULL, 0);
				type = PROP_INT;
			} else if (strcmp (opt, "uint64") == 0) {
				uint64_value = strtoull (optarg, NULL, 0);
				type = PROP_UINT64;
			} else if (strcmp (opt, "double") == 0) {
				double_value = (double) atof (optarg);
				type = PROP_DOUBLE;
			} else if (strcmp (opt, "bool") == 0) {
				if (strcmp (optarg, "true") == 0)
					bool_value = TRUE;
				else if (strcmp (optarg, "false") == 0)
					bool_value = FALSE;
				else {
					usage (argc, argv);
					return 1;
				}
				type = PROP_BOOL;
			} else if (strcmp (opt, "strlist-pre") == 0) {
				str_value = strdup (optarg);
				type = PROP_STRLIST_PRE;
			} else if (strcmp (opt, "strlist-post") == 0) {
				str_value = strdup (optarg);
				type = PROP_STRLIST_POST;
			} else if (strcmp (opt, "strlist-rem") == 0) {
				str_value = strdup (optarg);
				type = PROP_STRLIST_REM;
			} else if (strcmp (opt, "remove") == 0) {
				remove = TRUE;
			} else if (strcmp (opt, "direct") == 0) {
				direct = TRUE;
			} else if (strcmp (opt, "udi") == 0) {
				udi = strdup (optarg);
			} else if (strcmp (opt, "version") == 0) {
				is_version = TRUE;
			}
			break;

		default:
			usage (argc, argv);
			return 1;
			break;
		}
	}

	if (is_version) {
		printf ("hal-set-property " PACKAGE_VERSION "\n");
		return 0;
	}

	/* must have at least one, but not neither or both */
	if ((remove && type != PROP_INVALID) || ((!remove) && type == PROP_INVALID)) {
		usage (argc, argv);
		return 1;
	}

	fprintf (stderr, "\n");

	dbus_error_init (&error);
	if (direct) {
		if ((hal_ctx = libhal_ctx_init_direct (&error)) == NULL) {
			fprintf (stderr, "error: libhal_ctx_init_direct\n");
			LIBHAL_FREE_DBUS_ERROR (&error);
			return 1;
		}
	} else {
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
				LIBHAL_FREE_DBUS_ERROR (&error);
			}
			fprintf (stderr, "Could not initialise connection to hald.\n"
					 "Normally this means the HAL daemon (hald) is not running or not ready.\n");
			return 1;
		}
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

	if (remove) {
		rc = libhal_device_remove_property (hal_ctx, udi, key, &error);
		if (!rc) {
			if (dbus_error_is_set(&error)) {
			        fprintf (stderr, "error: libhal_device_remove_property: %s: %s\n", error.name, error.message);
				dbus_error_free (&error);
			} else {
				fprintf (stderr, "error: libhal_device_remove_property: invalid params.\n");
			}
			return 1;
		}
	} else {
		switch (type) {
		case PROP_STRING:
			rc = libhal_device_set_property_string (hal_ctx, udi, key, str_value, &error);
			break;
		case PROP_INT:
			rc = libhal_device_set_property_int (hal_ctx, udi, key, int_value, &error);
			break;
		case PROP_UINT64:
			rc = libhal_device_set_property_uint64 (hal_ctx, udi, key, uint64_value, &error);
			break;
		case PROP_DOUBLE:
			rc = libhal_device_set_property_double (hal_ctx, udi, key, double_value, &error);
			break;
		case PROP_BOOL:
			rc = libhal_device_set_property_bool (hal_ctx, udi, key, bool_value, &error);
			break;
		case PROP_STRLIST_PRE:
			rc = libhal_device_property_strlist_prepend (hal_ctx, udi, key, str_value, &error);
			break;
		case PROP_STRLIST_POST:
			rc = libhal_device_property_strlist_append (hal_ctx, udi, key, str_value, &error);
			break;
		case PROP_STRLIST_REM:
			rc = libhal_device_property_strlist_remove (hal_ctx, udi, key, str_value, &error);
			break;
		}
		if (!rc) {
			if (dbus_error_is_set(&error)) {
			        fprintf (stderr, "error: libhal_device_set_property: %s: %s\n", error.name, error.message);
				dbus_error_free (&error);
			} else {
				fprintf (stderr, "error: libhal_device_set_property: invalid params.\n");
			}
			return 1;
		}
	}

	return rc ? 0 : 1;
}

/**
 * @}
 */
