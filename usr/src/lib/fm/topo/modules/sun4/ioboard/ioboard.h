/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IOBOARD_H
#define	_IOBOARD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libdevinfo.h>
#include <did.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	IOB_ENUMR_VERS	1

/*
 * For all machines that currently use this enumerator, buses have one
 * of the following addresses.
 */
#define	IOB_BUSADDR1	0x600000
#define	IOB_BUSADDR2	0x700000

extern tnode_t *ioboard_declare(topo_mod_t *, tnode_t *, topo_instance_t,
    void *);

extern int platform_iob_enum(topo_mod_t *, tnode_t *, topo_instance_t,
    topo_instance_t);
extern int platform_iob_label(topo_mod_t *, tnode_t *, nvlist_t *, nvlist_t **);

/*
 * This routine works for splitting up the string we get from
 * di_bus_addr() for all machines that currently use this enumerator.
 */
extern did_t *split_bus_address(topo_mod_t *, di_node_t, uint_t, uint_t,
    int, int, int *, int *, int *);

#ifdef __cplusplus
}
#endif

#endif /* _IOBOARD_H */
