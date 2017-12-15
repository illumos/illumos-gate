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
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _TOPO_TRANSCEIVER_H
#define	_TOPO_TRANSCEIVER_H

/*
 * Routines to manage and create ports.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int transceiver_range_create(topo_mod_t *, tnode_t *, topo_instance_t,
    topo_instance_t);
extern int transceiver_create_sff(topo_mod_t *, tnode_t *, topo_instance_t,
    boolean_t, const char *, const char *, const char *, const char *,
    tnode_t **);

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_TRANSCEIVER_H */
