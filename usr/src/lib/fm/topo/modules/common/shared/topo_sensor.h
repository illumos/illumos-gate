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

#ifndef _TOPO_SENSOR_H
#define	_TOPO_SENSOR_H

/*
 * Routines to interact with the common kernel sensor framework.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int topo_sensor_create_temp_sensor(topo_mod_t *, tnode_t *, const char *,
    const char *);

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_SENSOR_H */
