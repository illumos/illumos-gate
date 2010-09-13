/***************************************************************************
 *
 * hal-system-lcd-get-brightness-sunos.c : Get LCD brightness
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
#include "../../hald/util.h"
#include <sys/acpi_drv.h>

int
main(int argc, char *argv[])
{
	struct acpi_drv_output_status status;
	int fd = -1;
	char *udi;
	char device_file[HAL_PATH_MAX] = "/devices";
	char *devfs_path;

	if ((udi = getenv("UDI")) == NULL) {
		return (-1);
	}
	if ((devfs_path = getenv("HAL_PROP_SOLARIS_DEVFS_PATH")) == NULL) {
		return (-1);
	}

	strlcat(device_file, devfs_path, HAL_PATH_MAX);
	fprintf(stderr, "Getting brightness on %s (udi=%s)",
	    device_file, udi);
	if ((fd = open(device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		fprintf(stderr, "Cannot open %s: %s", device_file,
		    strerror(errno));
		return (-1);
	}

	bzero(&status, sizeof (status));
	if (ioctl(fd, ACPI_DRV_IOC_STATUS, &status) < 0) {
		close(fd);
		return (-1);
	} else {
		close(fd);
		return (status.cur_level_index);
	}
}
