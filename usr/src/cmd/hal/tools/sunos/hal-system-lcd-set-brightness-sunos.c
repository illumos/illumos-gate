/***************************************************************************
 *
 * hal-system-lcd-set-brightness-sunos.c : Set LCD brightness
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
#include <sys/acpi_drv.h>
#include "../../hald/util.h"

int
main(int argc, char *argv[])
{
	char arg[10];
	int level;
	int fd = -1;
	char *udi;
	char device_file[HAL_PATH_MAX] = "/devices";
	char *devfs_path;

	if ((udi = getenv("UDI")) == NULL) {
		return (1);
	}
	if ((devfs_path = getenv("HAL_PROP_SOLARIS_DEVFS_PATH")) == NULL) {
		return (1);
	}
	strlcat(device_file, devfs_path, HAL_PATH_MAX);
	fprintf(stderr, "Setting brightness on %s (udi=%s)",
	    device_file, udi);

	if ((fd = open(device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		fprintf(stderr, "Cannot open %s: %s", device_file,
		    strerror(errno));
		return (1);
	}
	if (fgets(arg, sizeof (arg), stdin)) {
		level = atoi(arg);
	}
	if (ioctl(fd, ACPI_DRV_IOC_SET_BRIGHTNESS, &level) < 0) {
		close(fd);
		return (1);
	} else {
		close(fd);
		return (0);
	}
}
