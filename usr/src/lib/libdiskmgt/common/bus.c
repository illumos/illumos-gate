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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdlib.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/scsi/conf/autoconf.h>

#include "libdiskmgt.h"
#include "disks_private.h"

static descriptor_t	**get_assoc_buses(descriptor_t *desc, int *errp);
static descriptor_t	**get_assoc_controllers(descriptor_t *desc, int *errp);

descriptor_t **
bus_get_assoc_descriptors(descriptor_t *desc, dm_desc_type_t type, int *errp)
{
	switch (type) {
	case DM_BUS:
	    return (get_assoc_buses(desc, errp));
	case DM_CONTROLLER:
	    return (get_assoc_controllers(desc, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

nvlist_t *
bus_get_attributes(descriptor_t *dp, int *errp)
{
	bus_t		*bp;
	nvlist_t	*attrs;

	if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	bp = dp->p.bus;

	if (nvlist_add_string(attrs, DM_BTYPE, bp->btype) != 0) {
	    nvlist_free(attrs);
	    *errp = ENOMEM;
	    return (NULL);
	}

	if (bp->freq != 0) {
	    if (nvlist_add_uint32(attrs, DM_CLOCK, bp->freq) != 0) {
		nvlist_free(attrs);
		*errp = ENOMEM;
		return (NULL);
	    }
	}

	if (bp->pname != NULL) {
	    if (nvlist_add_string(attrs, DM_PNAME, bp->pname) != 0) {
		nvlist_free(attrs);
		*errp = ENOMEM;
		return (NULL);
	    }
	}

	*errp = 0;
	return (attrs);
}

descriptor_t *
bus_get_descriptor_by_name(char *name, int *errp)
{
	descriptor_t	**buses;
	int		i;
	descriptor_t	*bus = NULL;

	buses = cache_get_descriptors(DM_BUS, errp);
	if (*errp != 0) {
	    return (NULL);
	}

	for (i = 0; buses[i]; i++) {
	    if (libdiskmgt_str_eq(name, buses[i]->p.bus->name)) {
		bus = buses[i];
	    } else {
		/* clean up the unused descriptors */
		cache_free_descriptor(buses[i]);
	    }
	}
	free(buses);

	if (bus == NULL) {
	    *errp = ENODEV;
	}

	return (bus);
}

/* ARGSUSED */
descriptor_t **
bus_get_descriptors(int filter[], int *errp)
{
	return (cache_get_descriptors(DM_BUS, errp));
}

char *
bus_get_name(descriptor_t *desc)
{
	return (desc->p.bus->name);
}

/* ARGSUSED */
nvlist_t *
bus_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	/* There are no stat types defined for controllers */
	*errp = EINVAL;
	return (NULL);
}

int
bus_make_descriptors()
{
	int	error;
	bus_t	*bp;

	bp = cache_get_buslist();
	while (bp != NULL) {
	    cache_load_desc(DM_BUS, bp, NULL, NULL, &error);
	    if (error != 0) {
		return (error);
	    }
	    bp = bp->next;
	}

	return (0);
}

static descriptor_t **
get_assoc_buses(descriptor_t *desc, int *errp)
{
	bus_t		*bp;
	char		*name;
	descriptor_t	**allbuses;
	descriptor_t	**buses;
	int		cnt;
	int		i;
	int		pos;

	bp = desc->p.bus;
	name = bp->name;

	allbuses = cache_get_descriptors(DM_BUS, errp);
	if (*errp != 0) {
	    return (NULL);
	}

	/* Count how many we have (we overcount, but thats ok). */
	for (cnt = 0; allbuses[cnt]; cnt++);

	/* make the snapshot */
	buses = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (buses == NULL) {
	    *errp = ENOMEM;
	    cache_free_descriptors(allbuses);
	    return (NULL);
	}

	/*
	 * Get this buses parent bus and get the buses that I am the parent of.
	 */
	pos = 0;
	for (i = 0; allbuses[i]; i++) {
	    if (libdiskmgt_str_eq(name, allbuses[i]->p.bus->pname)) {
		buses[pos++] = allbuses[i];
	    } else if (bp->pname != NULL &&
		libdiskmgt_str_eq(bp->pname, allbuses[i]->p.bus->name)) {

		buses[pos++] = allbuses[i];
	    } else {
		/* clean up the unused descriptor */
		cache_free_descriptor(allbuses[i]);
	    }
	}
	buses[pos] = NULL;

	free(allbuses);

	*errp = 0;
	return (buses);
}

static descriptor_t **
get_assoc_controllers(descriptor_t *desc, int *errp)
{
	bus_t		*bp;
	descriptor_t	**controllers;
	int		cnt;
	int		i;

	bp = desc->p.bus;

	/* Count how many we have. */
	for (cnt = 0; bp->controllers[cnt]; cnt++);

	/* make the snapshot */
	controllers = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (controllers == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	for (i = 0; bp->controllers[i]; i++) {
	    controllers[i] = cache_get_desc(DM_CONTROLLER, bp->controllers[i],
		NULL, NULL, errp);
	    if (*errp != 0) {
		cache_free_descriptors(controllers);
		return (NULL);
	    }
	}
	controllers[i] = NULL;

	*errp = 0;
	return (controllers);
}
