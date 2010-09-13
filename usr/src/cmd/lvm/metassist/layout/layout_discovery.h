/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LAYOUT_DISCOVERY_H
#define	_LAYOUT_DISCOVERY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "libdiskmgt.h"

/*
 * scan physical devices and build lists of known devices.
 */
extern int	discover_known_devices();

/*
 * release lists of known devices.
 */
extern int	release_known_devices();

/*
 * scan known devices and build lists of usable devices.
 */
extern int	discover_usable_devices(char *diskset);

/*
 * release lists of usable devices.
 */
extern int	release_usable_devices();

/*
 * functions to access lists of known devices for the system,
 * constructed by load_physical_devices
 */
extern int	get_known_slices(dlist_t **list);
extern int	get_known_disks(dlist_t **list);
extern int	get_known_hbas(dlist_t **list);

/*
 * functions to access lists of devices for the named diskset
 * constructed by load_physical_devices
 */
extern int	get_usable_slices(dlist_t **list);
extern int	get_usable_disks(dlist_t **list);
extern int	get_usable_hbas(dlist_t **list);

/*
 * predicate indicating whether MPXIO appears enabled for the system
 */
extern boolean_t	is_mpxio_enabled();

/*
 * functions that set/get a descriptor's multipath alias name(s).
 */
extern int	get_aliases(dm_descriptor_t desc, dlist_t **aliases);
extern int	set_alias(dm_descriptor_t desc, char	*alias);

#ifdef __cplusplus
}
#endif

#endif /* _LAYOUT_DISCOVERY_H */
