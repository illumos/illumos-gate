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

#ifndef _LAYOUT_DEVICE_CACHE_H
#define	_LAYOUT_DEVICE_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This module manages cached copies of a dm_descriptor_t's nvpair
 * list of attributes and its device name.  The caches are used to
 * make sure that the memory allocated to these objects is correctly
 * released after the layout process has finished.  The cached attrs
 * also allow the layout code to store and retrieve transient,
 * layout-private data in the same data structure as the other
 * relevant device information.
 *
 * There are two primary caches of information:
 *
 *    descriptor->name - which maps a dm_descriptor_t handle to
 *			the associated device's name
 *
 *    name->attributes - which maps a device name to an nvlist_t
 *			attribute collection.
 *
 * These two data structures thus allow the following lookup chain:
 *    descriptor->name->attributes.
 *
 * The attributes are accessed by device name because the it is the
 * unique identifier for the device.  The descriptor returned by
 * libdiskmgt is just an arbitrary handle, multiple calls into the
 * library may return different descriptors for the same device.
 *
 * Descriptors are also get re-cycled by the library which could
 * result in the same descriptor being used to represent different
 * devices (although not concurrently). To prevent such recycling
 * all of the descriptors are held until the layout process has
 * completed.
 *
 * Performance testing indicated that searching the lists of known
 * devices by display (CTD or DID) name or alias was a significant
 * bottleneck. A mapping from display name to descriptor was added
 * to address this.
 *
 * The module should be initialized once by calling create_device_caches()
 * prior to any call which accesses data maintained by the cache.
 *
 * The caches should be flushed after all accesses have completed by
 * calling release_device_caches.
 */

#include "libdiskmgt.h"
#include "layout_device_util.h"

extern int	create_device_caches();
extern int	release_device_caches();

extern int	add_cached_descriptor(char *name, dm_descriptor_t desc);
extern dm_descriptor_t find_cached_descriptor(char *name);

extern int	add_cached_name(dm_descriptor_t desc, char *name);
extern int	get_name(dm_descriptor_t desc, char **name);

extern int	add_cached_attributes(char *name, nvlist_t *attrs);
extern int	get_cached_attributes(dm_descriptor_t desc, nvlist_t **list);

extern int	new_descriptor(dm_descriptor_t *desc);
extern int	add_descriptors_to_free(dm_descriptor_t *desc_list);

#ifdef __cplusplus
}
#endif

#endif /* _LAYOUT_DEVICE_CACHE_H */
