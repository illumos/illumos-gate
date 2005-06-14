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
static descriptor_t	**get_assoc_drives(descriptor_t *desc, int *errp);
static descriptor_t	**get_assoc_paths(descriptor_t *desc, int *errp);

descriptor_t **
controller_get_assoc_descriptors(descriptor_t *desc, dm_desc_type_t type,
    int *errp)
{
	switch (type) {
	case DM_DRIVE:
	    return (get_assoc_drives(desc, errp));
	case DM_PATH:
	    return (get_assoc_paths(desc, errp));
	case DM_BUS:
	    return (get_assoc_buses(desc, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

nvlist_t *
controller_get_attributes(descriptor_t *dp, int *errp)
{
	controller_t	*cp;
	nvlist_t	*attrs;

	if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	cp = dp->p.controller;

	if (nvlist_add_string(attrs, DM_CTYPE, cp->ctype) != 0) {
	    nvlist_free(attrs);
	    *errp = ENOMEM;
	    return (NULL);
	}

	if (cp->multiplex) {
	    if (nvlist_add_boolean(attrs, DM_MULTIPLEX) != 0) {
		nvlist_free(attrs);
		*errp = ENOMEM;
		return (NULL);
	    }
	}

	if (cp->scsi_options != -1) {
	    if (cp->scsi_options & SCSI_OPTIONS_FAST) {
		if (nvlist_add_boolean(attrs, DM_FAST) != 0) {
		    nvlist_free(attrs);
		    *errp = ENOMEM;
		    return (NULL);
		}
	    }
	    if (cp->scsi_options & SCSI_OPTIONS_WIDE) {
		if (nvlist_add_boolean(attrs, DM_WIDE) != 0) {
		    nvlist_free(attrs);
		    *errp = ENOMEM;
		    return (NULL);
		}
	    }
	    if (cp->scsi_options & SCSI_OPTIONS_FAST20) {
		if (nvlist_add_boolean(attrs, DM_FAST20) != 0) {
		    nvlist_free(attrs);
		    *errp = ENOMEM;
		    return (NULL);
		}
	    }
	    if (cp->scsi_options & SCSI_OPTIONS_FAST40) {
		if (nvlist_add_boolean(attrs, DM_FAST40) != 0) {
		    nvlist_free(attrs);
		    *errp = ENOMEM;
		    return (NULL);
		}
	    }
	    if (cp->scsi_options & SCSI_OPTIONS_FAST80) {
		if (nvlist_add_boolean(attrs, DM_FAST80) != 0) {
		    nvlist_free(attrs);
		    *errp = ENOMEM;
		    return (NULL);
		}
	    }
	}

	if (cp->freq != 0) {
	    if (nvlist_add_uint32(attrs, DM_CLOCK, cp->freq) != 0) {
		nvlist_free(attrs);
		*errp = ENOMEM;
		return (NULL);
	    }
	}

	*errp = 0;
	return (attrs);
}

descriptor_t *
controller_get_descriptor_by_name(char *name, int *errp)
{
	descriptor_t	**controllers;
	int		i;
	descriptor_t	*controller = NULL;

	controllers = cache_get_descriptors(DM_CONTROLLER, errp);
	if (*errp != 0) {
	    return (NULL);
	}

	for (i = 0; controllers[i]; i++) {
	    if (libdiskmgt_str_eq(name, controllers[i]->p.controller->name)) {
		controller = controllers[i];
	    } else {
		/* clean up the unused descriptors */
		cache_free_descriptor(controllers[i]);
	    }
	}
	free(controllers);

	if (controller == NULL) {
	    *errp = ENODEV;
	}

	return (controller);
}

/* ARGSUSED */
descriptor_t **
controller_get_descriptors(int filter[], int *errp)
{
	return (cache_get_descriptors(DM_CONTROLLER, errp));
}

char *
controller_get_name(descriptor_t *desc)
{
	return (desc->p.controller->name);
}

/* ARGSUSED */
nvlist_t *
controller_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	/* There are no stat types defined for controllers */
	*errp = EINVAL;
	return (NULL);
}

int
controller_make_descriptors()
{
	int		error;
	controller_t	*cp;

	cp = cache_get_controllerlist();
	while (cp != NULL) {
	    cache_load_desc(DM_CONTROLLER, cp, NULL, NULL, &error);
	    if (error != 0) {
		return (error);
	    }
	    cp = cp->next;
	}

	return (0);
}

static descriptor_t **
get_assoc_buses(descriptor_t *desc, int *errp)
{
	controller_t	*cp;
	descriptor_t	**buses;
	int		pos = 0;

	cp = desc->p.controller;

	/* make the snapshot */
	buses = (descriptor_t **)calloc(2, sizeof (descriptor_t *));
	if (buses == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	if (cp->bus != NULL) {
	    buses[pos++] = cache_get_desc(DM_BUS, cp->bus, NULL, NULL, errp);
	    if (*errp != 0) {
		cache_free_descriptors(buses);
		return (NULL);
	    }
	}
	buses[pos] = NULL;

	*errp = 0;
	return (buses);
}

static descriptor_t **
get_assoc_drives(descriptor_t *desc, int *errp)
{
	controller_t	*cp;
	descriptor_t	**drives;
	int		cnt;
	int		i;

	cp = desc->p.controller;

	/* Count how many we have. */
	for (cnt = 0; cp->disks[cnt]; cnt++);

	/* make the snapshot */
	drives = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (drives == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	for (i = 0; cp->disks[i]; i++) {
	    drives[i] = cache_get_desc(DM_DRIVE, cp->disks[i], NULL, NULL,
		errp);
	    if (*errp != 0) {
		cache_free_descriptors(drives);
		return (NULL);
	    }
	}
	drives[i] = NULL;

	*errp = 0;
	return (drives);
}

static descriptor_t **
get_assoc_paths(descriptor_t *desc, int *errp)
{
	path_t		**pp;
	int		cnt;
	descriptor_t	**paths;
	int		i;

	pp = desc->p.controller->paths;

	/* Count how many we have. */
	cnt = 0;
	if (pp != NULL) {
	    for (; pp[cnt]; cnt++);
	}

	/* make the snapshot */
	paths = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (paths == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	/*
	 * The name field of the descriptor is not filled in.  Thus, we
	 * know not to try to lookup drive-path state information within
	 * the path code if we try to get attributes for this descriptor.
	 */
	for (i = 0; i < cnt; i++) {
	    paths[i] = cache_get_desc(DM_PATH, pp[i], NULL, NULL, errp);
	    if (*errp != 0) {
		cache_free_descriptors(paths);
		return (NULL);
	    }
	}

	paths[i] = NULL;

	*errp = 0;
	return (paths);
}
