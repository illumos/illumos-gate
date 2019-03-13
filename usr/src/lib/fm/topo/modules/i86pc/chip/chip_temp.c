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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libnvpair.h>
#include <sys/sensors.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <topo_sensor.h>

#include "chip.h"

static const char *chip_sensor_base = "/dev/sensors/temperature/cpu";

int
chip_create_core_temp_sensor(topo_mod_t *mod, tnode_t *pnode)
{
	int err;
	int32_t chip, core;
	char buf[PATH_MAX];
	struct stat st;

	core = topo_node_instance(pnode);
	if (topo_prop_get_int32(pnode, PGNAME(CORE), CORE_CHIP_ID, &chip,
	    &err) != 0) {
		return (topo_mod_seterrno(mod, err));
	}

	if (snprintf(buf, sizeof (buf), "%s/chip%d.core%d", chip_sensor_base,
	    chip, core) >= sizeof (buf)) {
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	/*
	 * Some systems have per-core sensors. Others have it on a per-die aka
	 * procnode basis. Check to see if the file exists before we attempt to
	 * do something.
	 */
	if (stat(buf, &st) != 0) {
		int32_t procnode;

		if (errno != ENOENT) {
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}

		if (topo_prop_get_int32(pnode, PGNAME(CORE), CORE_PROCNODE_ID,
		    &procnode, &err) != 0) {
			return (topo_mod_seterrno(mod, err));
		}

		if (snprintf(buf, sizeof (buf), "%s/procnode.%d",
		    chip_sensor_base, procnode) >= sizeof (buf)) {
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}
	}

	return (topo_sensor_create_temp_sensor(mod, pnode, buf, "temp"));
}

int
chip_create_chip_temp_sensor(topo_mod_t *mod, tnode_t *pnode)
{
	int32_t chip;
	char buf[PATH_MAX];

	chip = topo_node_instance(pnode);

	if (snprintf(buf, sizeof (buf), "%s/chip%d", chip_sensor_base,
	    chip) >= sizeof (buf)) {
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	return (topo_sensor_create_temp_sensor(mod, pnode, buf, "temp"));
}
