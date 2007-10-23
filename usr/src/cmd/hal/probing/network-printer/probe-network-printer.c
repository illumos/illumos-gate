/***************************************************************************
 *
 * probe-network-printer.c : Probe for snmp printer device information
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/prnio.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <libhal.h>
#include <logger.h>

#include "printer.h"

int 
main(int argc, char *argv[])
{
	int ret = 1;
	char *udi;
	char *printer_address,
	     *community;
	DBusError error;
	LibHalContext *ctx = NULL;
	LibHalChangeSet *cs = NULL;
	char *manufacturer = NULL,
	     *model = NULL,
	     *serial_number = NULL,
	     *description = NULL,
	     **command_set = NULL,
	     *device_uri = NULL;
	extern int snmp_printer_info(char *hostname, char *community,
			char **manufacturer, char **model, char **description,
			char **serial_number, char ***command_set,
			char **device_uri);

	dbus_error_init(&error);

	if ((udi = getenv("UDI")) == NULL)
		goto out;

	printer_address = getenv("HAL_PROP_NETWORK_DEVICE_ADDRESS");
	if (printer_address == NULL)
		goto out;

	community = getenv("HAL_PROP_NETWORK_DEVICE_SNMP_COMMUNITY");
	if (community == NULL)
		community = "public";

	setup_logger();

	dbus_error_init(&error);

	if ((ctx = libhal_ctx_init_direct(&error)) == NULL)
		goto out;

	if ((cs = libhal_device_new_changeset(udi)) == NULL) {
		HAL_DEBUG(("Cannot allocate changeset"));
		goto out;
	}

	/* Probe the printer for characteristics via SNMP */
	ret = snmp_printer_info(printer_address, community, &manufacturer,
			&model, &description, &serial_number, &command_set,
			&device_uri);
	if (ret < 0) {
		HAL_DEBUG(("Cannot get snmp data for %s: %s",
				printer_address, strerror(errno)));
		goto out;
	}

	/* Add printer characteristics to the HAL device tree */
	ret = add_printer_info(cs, udi, manufacturer, model, description,
			serial_number, command_set, device_uri);
	if (ret < 0) {
		HAL_DEBUG(("Cannot add printer data for %s to %s: %s",
				printer_address, udi, strerror(errno)));
		goto out;
	}

	libhal_device_commit_changeset(ctx, cs, &error);

	ret = 0;

out:
	if (cs != NULL) {
		libhal_device_free_changeset(cs);
	}

	if (ctx != NULL) {
		if (dbus_error_is_set(&error)) {
			dbus_error_free(&error);
		}
		libhal_ctx_shutdown(ctx, &error);
		libhal_ctx_free(ctx);
	}

	return (ret);
}
