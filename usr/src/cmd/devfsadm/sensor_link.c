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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Create /devices links for various sensors. The sensor series of node types
 * all begin with ddi_sensor. After which, there is a series of : delineated
 * paths in the node type. Those represent the directory under /dev/sensors that
 * the nodes should ultimately be created.
 *
 * For example, ddi_sensor:temperature:cpu would cause us to place the named
 * minor under /dev/sensors/temperature/cpu/. Currently it is up to drivers to
 * not conflict in names or if there is a fear of conflicting, make sure their
 * minor is unique.
 */

#include <devfsadm.h>
#include <string.h>

#define	SENSORS_BASE	"sensors"

static int
sensor_link(di_minor_t minor, di_node_t node)
{
	const char *t, *minor_name, *dir_path = NULL;
	char *type, *c;
	char buf[PATH_MAX];
	size_t len;

	if ((t = di_minor_nodetype(minor)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	if ((minor_name = di_minor_name(minor)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}

	if ((type = strdup(t)) == NULL) {
		return (DEVFSADM_TERMINATE);
	}

	while ((c = strchr(type, ':')) != NULL) {
		if (dir_path == NULL) {
			dir_path = c + 1;
		}
		*c = '/';
	}

	if (dir_path == NULL || *dir_path == '\0') {
		len = snprintf(buf, sizeof (buf), "%s/%s", SENSORS_BASE,
		    minor_name);
	} else {
		len = snprintf(buf, sizeof (buf), "%s/%s/%s", SENSORS_BASE,
		    dir_path, minor_name);
	}

	if (len < sizeof (buf)) {
		(void) devfsadm_mklink(buf, node, minor, 0);
	}

	free(type);
	return (DEVFSADM_CONTINUE);
}

static devfsadm_create_t sensor_create_cbt[] = {
	{ NULL, "ddi_sensor", NULL, TYPE_PARTIAL, ILEVEL_0, sensor_link }
};
DEVFSADM_CREATE_INIT_V0(sensor_create_cbt);
