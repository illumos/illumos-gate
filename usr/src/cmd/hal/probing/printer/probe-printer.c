/***************************************************************************
 *
 * probe-printer.c : Probe for prnio(4I) printer device information
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/prnio.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <libhal.h>
#include <logger.h>

#include "printer.h"

static int
prnio_printer_info(char *device_file, char **manufacturer, char **model,
		char **description, char **serial_number, char ***command_set)
{
	struct prn_1284_device_id id;
	char buf[BUFSIZ];
	int fd = -1, rc = -1;

	memset(&id, 0, sizeof (id));
	memset(&buf, 0, sizeof (buf));
	id.id_data = buf;
	id.id_len = sizeof (buf);

	if ((fd = open (device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		goto prnio_out;
	}

	if (ioctl(fd, PRNIOC_GET_1284_DEVID, &id) < 0) {
		goto prnio_out;
	}

	HAL_DEBUG(("IEEE-1284 DeviceId = %s", buf));

	rc = ieee1284_devid_to_printer_info(buf, manufacturer, model,
			description, NULL, serial_number, command_set);

prnio_out:
	if (fd != -1)
		close(fd);

	return (rc);
}

/*
 * It is assumed that all devices that support prnio(4I), also have a link
 * in /dev/printers.
 */
static char *
prnio_device_name(void)
{
	char *result = NULL;
	char *devfs_path;
	DIR *dp;

	if (((devfs_path = getenv("HAL_PROP_SOLARIS_DEVFS_PATH")) != NULL) &&
	    ((dp = opendir("/dev/printers")) != NULL)) {
		struct dirent *ep;

		while ((ep = readdir(dp)) != NULL) {
			char path[MAXPATHLEN], lpath[MAXPATHLEN];

			snprintf(path, sizeof (path), "/dev/printers/%s",
					ep->d_name);
			memset(lpath, 0, sizeof (lpath));
			if ((readlink(path, lpath, sizeof (lpath)) > 0) &&
			    (strstr(lpath, devfs_path) != NULL)) {
				result = strdup(path);
				break;
			}
		}
		closedir(dp);
	}

	return (result);
}

int
main(int argc, char *argv[])
{
	int ret = 1;
	char *udi;
	char *device_file;
	char *manufacturer = NULL,
	     *model = NULL,
	     *serial_number = NULL,
	     *description = NULL,
	     **command_set = NULL;
	DBusError error;
	LibHalContext *ctx = NULL;
	LibHalChangeSet *cs = NULL;

	if ((udi = getenv("UDI")) == NULL)
		goto out;
	if ((device_file = getenv("HAL_PROP_PRINTER_DEVICE")) == NULL)
		device_file = prnio_device_name();

	if (device_file == NULL)
		goto out;

	setup_logger();

	dbus_error_init(&error);
	if ((ctx = libhal_ctx_init_direct(&error)) == NULL)
		goto out;

	if ((cs = libhal_device_new_changeset(udi)) == NULL) {
		HAL_DEBUG(("Cannot allocate changeset"));
		goto out;
	}

	/* Probe the printer for characteristics via prnio(4I) */
	ret = prnio_printer_info(device_file, &manufacturer, &model,
			&description, &serial_number, &command_set);
	if (ret < 0) {
		HAL_DEBUG(("Cannot get prnio data for %s: %s",
				device_file, strerror(errno)));
		goto out;
	}

	/* Add printer characteristics to the HAL device tree */
	ret = add_printer_info(cs, udi, manufacturer, model, description,
			serial_number, command_set, device_file);
	if (ret < 0) {
		HAL_DEBUG(("Cannot add printer data for %s to %s: %s",
				device_file, udi, strerror(errno)));
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
