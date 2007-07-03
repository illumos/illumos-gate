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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TOPO_GATHER_H
#define	_TOPO_GATHER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * bay/disk libtopo plugin property consumer
 * (creates diskmon configuration objects)
 */

#ifdef __cplusplus
extern "C" {
#endif

/* NOTE: some aspects of this code are still x4500 specific */
#define	DISK_MONITOR_PROPERTIES	"sfx4500-properties"

/* Properties added to the machine-specific properties pgroup */
#define	BAY_IND_NAME		"indicator-name"
#define	BAY_IND_ACTION		"indicator-action"
#define	BAY_INDRULE_STATES	"indicator-rule-states"
#define	BAY_INDRULE_ACTIONS	"indicator-rule-actions"

#define	TOPO_SUCCESS		0
#define	TOPO_WALK_ERROR		1
#define	TOPO_WALK_INIT_ERROR	2
#define	TOPO_SNAP_ERROR		3
#define	TOPO_OPEN_ERROR		4

int		update_configuration_from_topo(fmd_hdl_t *, diskmon_t *diskp);
int		init_configuration_from_topo(void);
void		fini_configuration_from_topo(void);
diskmon_t	*dm_fmri_to_diskmon(fmd_hdl_t *hdl, nvlist_t *fmri);

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_GATHER_H */
