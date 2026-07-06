/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Utility functions common to amdzen commands.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libdevinfo.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "amdzen_common.h"

/*
 * Traditionally we expected to be given the path to a character device file
 * somewhere under /devices, where the device minor referred to a specific
 * data fabric (DF) instance. It is often more convenient to be able to give
 * a higher-level identifier instead, such as a DF number, optionally
 * prefixed with the driver name. This function distinguishes between the
 * two cases by attempting to parse the argument as a DF identifier. If that
 * succeeds, we map it to the corresponding minor of the named driver and
 * open that, otherwise the argument is treated as a device path and opened
 * directly. Either way the caller receives an open file descriptor, or -1
 * after a warning has been issued.
 */
int
amdzen_open_device(const char *driver, const char *arg, int oflag)
{
	struct stat st;
	di_node_t root, node;
	di_minor_t minor;
	const char *errstr, *id;
	char mname[64];
	char *bpath, *path;
	size_t drvlen;
	int df, fd;

	/* If there is a driver prefix provided, accept and remove it */
	id = arg;
	drvlen = strlen(driver);
	if (strncmp(id, driver, drvlen) == 0)
		id += drvlen;

	df = (int)strtonumx(id, 0, INT_MAX, &errstr, 0);
	if (errstr != NULL) {
		/* Not a DF identifier, so treat it as a device path */
		if ((fd = open(arg, oflag)) < 0) {
			warn("failed to open %s", arg);
			return (-1);
		}
		if (fstat(fd, &st) != 0) {
			warn("failed to stat %s", arg);
			(void) close(fd);
			return (-1);
		}
		if (!S_ISCHR(st.st_mode)) {
			warnx("%s is not a character device", arg);
			(void) close(fd);
			return (-1);
		}
		return (fd);
	}

	root = di_init_driver(driver, DINFOSUBTREE | DINFOMINOR);
	if (root == DI_NODE_NIL) {
		warn("failed to take a devinfo snapshot with %s attached",
		    driver);
		return (-1);
	}

	/* These are all single-instance drivers with one minor per DF */
	node = di_drv_first_node(driver, root);
	if (node == DI_NODE_NIL) {
		warnx("failed to find a devinfo node for %s", driver);
		di_fini(root);
		return (-1);
	}

	(void) snprintf(mname, sizeof (mname), "%s.%d", driver, df);
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		if (strcmp(di_minor_name(minor), mname) == 0)
			break;
	}
	if (minor == DI_MINOR_NIL) {
		warnx("failed to find minor %s on %s%d -- no such DF?",
		    mname, di_driver_name(node), di_instance(node));
		di_fini(root);
		return (-1);
	}

	bpath = di_devfs_minor_path(minor);
	if (bpath == NULL) {
		warn("failed to get minor path for %s%d:%s",
		    di_driver_name(node), di_instance(node),
		    di_minor_name(minor));
		di_fini(root);
		return (-1);
	}
	if (asprintf(&path, "/devices%s", bpath) < 0) {
		warn("failed to construct full path for %s", bpath);
		di_devfs_path_free(bpath);
		di_fini(root);
		return (-1);
	}
	di_devfs_path_free(bpath);
	di_fini(root);

	if ((fd = open(path, oflag)) < 0)
		warn("failed to open %s", path);
	free(path);

	return (fd);
}
