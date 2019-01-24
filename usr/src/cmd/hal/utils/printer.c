/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include <libhal.h>
#include <logger.h>

#include "printer.h"

static char *
strip_ws(char *s)
{
	if (s != NULL) {
		char *p;

		/* skip the leading whitespace */
		for (; ((*s != '\0') && (isspace(*s) != 0)); s++);

		/* drop the trailing whitespace */
		for (p = s + strlen(s) - 1; ((p > s) && (isspace(*p) != 0));
		     p--);
		*(++p) = '\0';
	}

	return (s);
}

int
ieee1284_devid_to_printer_info(char *devid_string, char **manufacturer,
		char **model, char **description, char **class,
		char **serial_no, char ***command_set)
{
	char *iter = NULL;
	char *s;

	if (devid_string == NULL)
		return (-1);

	/* parse the 1284 device id string */
	for (s = (char *)strtok_r(devid_string, ";\n", &iter); s != NULL;
			s = (char *)strtok_r(NULL, ";\n", &iter)) {
		char *t, *u, *iter2 = NULL;

		if ((t = (char *)strtok_r(s, ":\n", &iter2)) == NULL)
			continue;

		if ((u = (char *)strtok_r(NULL, ":\n", &iter2)) == NULL)
			continue;

		if (((strcasecmp(t, "MFG") == 0) ||
		     (strcasecmp(t, "MANUFACTURER") == 0)) &&
		    (manufacturer != NULL))
				*manufacturer = strdup(strip_ws(u));
		else if (((strcasecmp(t, "MDL") == 0) ||
			  (strcasecmp(t, "MODEL") == 0)) &&
			 (model != NULL))
				*model = strdup(strip_ws(u));
		else if (((strcasecmp(t, "DES") == 0) ||
			  (strcasecmp(t, "DESCRIPTION") == 0)) &&
			 (description != NULL))
				*description = strdup(strip_ws(u));
		else if (((strcasecmp(t, "CLS") == 0) ||
			  (strcasecmp(t, "CLASS") == 0)) &&
			 (class != NULL))
				*class = strdup(strip_ws(u));
		else if (((strcasecmp(t, "SER") == 0) ||
			  (strcasecmp(t, "SERNO") == 0)) &&
			 (serial_no != NULL))
				*serial_no = strdup(strip_ws(u));
		else if (((strcasecmp(t, "CMD") == 0) ||
			  (strcasecmp(t, "COMMAND SET") == 0)) &&
			 (command_set != NULL)) {
			/* this should be more dynamic, I got lazy */
			char *v, *iter3 = NULL;
			char *cmds[32];
			int i = 0;

			memset(&cmds, 0, sizeof (cmds));
#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))
			for (v = strtok_r(u, ",\n", &iter3);
			     ((v != NULL) && (i < NELEM(cmds)));
			     v = strtok_r(NULL, ",\n", &iter3)) {
				cmds[i++] = strdup(strip_ws(v));
			}
#undef NELEM
			*command_set = calloc(++i, sizeof (char *));
			for (i = 0; (cmds)[i] != NULL; i++)
				(*command_set)[i] = cmds[i];
		}
	}

	return (0);
}


int
add_printer_info(LibHalChangeSet *cs, char *udi, char *manufacturer,
		char *model, char *description, char *serial_number,
		char **command_set, char *device)
{
#define	NP(x)   (x?x:"")
	HAL_DEBUG(("udi: %s, snmp data: vendor=%s, product=%s, "
		    "description=%s, serial=%s, device=%s\n",
		    NP(udi), NP(manufacturer), NP(model), NP(description),
		    NP(serial_number), NP(device)));
#undef NP

	if (model != NULL)
		libhal_changeset_set_property_string(cs,
					"info.product", model);
	if (manufacturer != NULL)
		libhal_changeset_set_property_string(cs,
					"printer.vendor", manufacturer);
	if (model != NULL)
		libhal_changeset_set_property_string(cs,
					"printer.product", model);
	if (serial_number != NULL)
		libhal_changeset_set_property_string(cs,
					"printer.serial", serial_number);
	if (description != NULL)
		libhal_changeset_set_property_string(cs,
					"printer.description", description);
	if (command_set != NULL)
		libhal_changeset_set_property_strlist(cs, "printer.commandset",
					(const char **)command_set);
	if (device != NULL)
		libhal_changeset_set_property_string(cs,
					"printer.device", device);

	return (0);
}
