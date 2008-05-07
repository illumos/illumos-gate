/***************************************************************************
 *
 * addon-acpi.c : Poll battery and AC adapter devices and update
 *                   properties
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <sys/stat.h>
#include <glib.h>

#include <libhal.h>
#include "../../hald/logger.h"
#include "../../hald/util_helper.h"
#include "../../utils/acpi.h"

int
main(int argc, char **argv)
{
	LibHalContext *ctx = NULL;
	DBusError error;

	GMainLoop *loop = g_main_loop_new(NULL, FALSE);

	drop_privileges(0);
	setup_logger();

	dbus_error_init(&error);
	if ((ctx = libhal_ctx_init_direct(&error)) == NULL) {
		printf("main(): init_direct failed\n");
		return (0);
	}
	dbus_error_init(&error);
	if (!libhal_device_addon_is_ready(ctx, getenv("UDI"), &error)) {
		return (0);
	}

	g_timeout_add(BATTERY_POLL_TIMER, update_devices, ctx);

	g_main_loop_run(loop);
}
