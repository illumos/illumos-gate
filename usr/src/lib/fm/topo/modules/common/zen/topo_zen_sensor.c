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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Create and manage the various CPU Tctl and Tdie sensors.
 */

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <topo_sensor.h>

#include "topo_zen_impl.h"

static const char *sensor_base = "/dev/sensors/temperature/cpu";

int
topo_zen_create_tdie(topo_mod_t *mod, tnode_t *tn, const amdzen_topo_ccd_t *ccd)
{
	char buf[PATH_MAX];

	if (snprintf(buf, sizeof (buf), "%s/procnode.%u.die.%u", sensor_base,
	    ccd->atccd_dfno, ccd->atccd_phys_no) >= sizeof (buf)) {
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	return (topo_sensor_create_scalar_sensor(mod, tn, buf, "Tdie"));
}

int
topo_zen_create_tctl(topo_mod_t *mod, tnode_t *tn, const amdzen_topo_df_t *df)
{
	char buf[PATH_MAX];

	if (snprintf(buf, sizeof (buf), "%s/procnode.%u", sensor_base,
	    df->atd_dfno) >= sizeof (buf)) {
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	return (topo_sensor_create_scalar_sensor(mod, tn, buf, "Tctl"));
}
