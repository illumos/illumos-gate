/***************************************************************************
 *
 * probe-acpi.c : Probe for ACPI device information
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib.h>

#include <libhal.h>
#include <logger.h>
#include "../utils/acpi.h"

int
main(int argc, char *argv[])
{
	int ret = 1;
	int fd = -1;
	char *udi;
	char device_file[HAL_PATH_MAX] = "/devices";
	char *devfs_path;
	LibHalContext *ctx = NULL;
	DBusError error;

	if ((udi = getenv("UDI")) == NULL)
		goto out;
	if ((devfs_path = getenv("HAL_PROP_SOLARIS_DEVFS_PATH")) == NULL)
		goto out;
	strlcat(device_file, devfs_path, HAL_PATH_MAX);

	setup_logger();

	dbus_error_init(&error);
	if ((ctx = libhal_ctx_init_direct(&error)) == NULL)
		goto out;

	HAL_DEBUG(("Doing probe-acpi for %s (udi=%s)",
	    device_file, udi));

	if ((fd = open(device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		HAL_DEBUG(("Cannot open %s: %s", device_file, strerror(errno)));
		goto out;
	}
	if (strstr(udi, "_ac")) {
		ac_adapter_update(ctx, udi, fd);
	} else if (strstr(udi, "_battery")) {
		battery_update(ctx, udi, fd);
	} else if (strstr(udi, "_lid")) {
		lid_update(ctx, udi, fd);
	} else if (strstr(udi, "_output")) {
		laptop_panel_update(ctx, udi, fd);
	}

	ret = 0;

out:
	if (fd >= 0) {
		close(fd);
	}

	if (ctx != NULL) {
		libhal_ctx_shutdown(ctx, &error);
		libhal_ctx_free(ctx);
		if (dbus_error_is_set(&error)) {
			dbus_error_free(&error);
		}
	}

	return (ret);
}
