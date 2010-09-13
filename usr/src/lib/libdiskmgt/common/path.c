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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdlib.h>
#include <sys/sunddi.h>
#include <sys/types.h>

#include "libdiskmgt.h"
#include "disks_private.h"

static int		add_path_state(descriptor_t *dp, nvlist_t *attrs);
static int		add_wwn(descriptor_t *dp, nvlist_t *attrs);
static descriptor_t	**get_assoc_drives(descriptor_t *desc, int *errp);
static descriptor_t	**get_assoc_controllers(descriptor_t *desc, int *errp);
static char		*path_state_name(di_path_state_t st);

descriptor_t **
path_get_assoc_descriptors(descriptor_t *desc, dm_desc_type_t type, int *errp)
{
	switch (type) {
	case DM_DRIVE:
	    return (get_assoc_drives(desc, errp));
	case DM_CONTROLLER:
	    return (get_assoc_controllers(desc, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

nvlist_t *
path_get_attributes(descriptor_t *dp, int *errp)
{
	path_t		*pp;
	nvlist_t	*attrs = NULL;

	pp = dp->p.path;

	if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	if (nvlist_add_string(attrs, DM_CTYPE, pp->ctype) != 0) {
	    nvlist_free(attrs);
	    *errp = ENOMEM;
	    return (NULL);
	}

	/*
	 * We add the path state and wwn attributes only for descriptors that
	 * we got via their association to a specific drive (since these
	 * attributes are drive specific).
	 */
	if (dp->name != NULL) {
	    if (add_path_state(dp, attrs) != 0) {
		nvlist_free(attrs);
		*errp = ENOMEM;
		return (NULL);
	    }
	    if (add_wwn(dp, attrs) != 0) {
		nvlist_free(attrs);
		*errp = ENOMEM;
		return (NULL);
	    }
	}

	*errp = 0;
	return (attrs);
}

descriptor_t *
path_get_descriptor_by_name(char *name, int *errp)
{
	descriptor_t	**paths;
	int		i;
	descriptor_t	*path = NULL;

	paths = cache_get_descriptors(DM_PATH, errp);
	if (*errp != 0) {
	    return (NULL);
	}

	for (i = 0; paths[i]; i++) {
	    if (libdiskmgt_str_eq(name, paths[i]->p.path->name)) {
		path = paths[i];
	    } else {
		/* clean up the unused descriptors */
		cache_free_descriptor(paths[i]);
	    }
	}
	free(paths);

	if (path == NULL) {
	    *errp = ENODEV;
	}

	return (path);
}

/* ARGSUSED */
descriptor_t **
path_get_descriptors(int filter[], int *errp)
{
	return (cache_get_descriptors(DM_PATH, errp));
}

char *
path_get_name(descriptor_t *desc)
{
	return (desc->p.path->name);
}

/* ARGSUSED */
nvlist_t *
path_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	/* There are no stat types defined for paths */
	*errp = EINVAL;
	return (NULL);
}

int
path_make_descriptors()
{
	int		error;
	controller_t	*cp;

	cp = cache_get_controllerlist();
	while (cp != NULL) {
	    if (cp->paths != NULL) {
		int i;

		for (i = 0; cp->paths[i]; i++) {
		    cache_load_desc(DM_PATH, cp->paths[i], NULL, NULL, &error);
		    if (error != 0) {
			return (error);
		    }
		}
	    }
	    cp = cp->next;
	}

	return (0);
}

/*
 * This is called when we have a name in the descriptor name field.  That
 * only will be the case when the descriptor was created by getting the
 * association from a drive to the path.  Since we filled in the name with
 * the drive device id in that case, we can use the device id to look up the
 * drive-path state.
 */
static int
add_path_state(descriptor_t *dp, nvlist_t *attrs)
{
	ddi_devid_t	devid;
	path_t		*pp;
	int		i;
	int		status = 0;

	if (devid_str_decode(dp->name, &devid, NULL) != 0) {
	    return (0);
	}

	/* find the index of the correct drive assoc. */
	pp = dp->p.path;
	for (i = 0; pp->disks[i] && pp->states[i] != -1; i++) {
	    if (pp->disks[i]->devid != NULL &&
		devid_compare(pp->disks[i]->devid, devid) == 0) {

		/* add the corresponding state */
		if (nvlist_add_string(attrs, DM_PATH_STATE,
		    path_state_name(pp->states[i])) != 0) {
		    status = ENOMEM;
		}
		break;
	    }
	}
	devid_free(devid);

	return (status);
}

/*
 * This is called when we have a name in the descriptor name field.  That
 * only will be the case when the descriptor was created by getting the
 * association from a drive to the path.  Since we filled in the name with
 * the drive device id in that case, we can use the device id to look up the
 * drive wwn.
 */
static int
add_wwn(descriptor_t *dp, nvlist_t *attrs)
{
	ddi_devid_t	devid;
	path_t		*pp;
	int		i;
	int		status = 0;

	if (devid_str_decode(dp->name, &devid, NULL) != 0) {
	    return (0);
	}

	/* find the index of the correct drive assoc. */
	pp = dp->p.path;
	for (i = 0; pp->disks[i] && pp->states[i] != -1; i++) {
	    if (pp->disks[i]->devid != NULL &&
		devid_compare(pp->disks[i]->devid, devid) == 0) {

		/* add the corresponding state */
		if (nvlist_add_string(attrs, DM_WWN, pp->wwns[i]) != 0) {
		    status = ENOMEM;
		}
		break;
	    }
	}
	devid_free(devid);

	return (status);
}

static descriptor_t **
get_assoc_controllers(descriptor_t *desc, int *errp)
{
	path_t		*pp;
	descriptor_t	**controllers;
	int		i;

	pp = desc->p.path;

	/* a path can have just one controller */

	controllers = (descriptor_t **)calloc(2, sizeof (descriptor_t *));
	if (controllers == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	i = 0;
	if (pp->controller != NULL) {
	    controllers[i++] = cache_get_desc(DM_CONTROLLER,
		pp->controller, NULL, NULL, errp);
	    if (*errp != 0) {
		cache_free_descriptors(controllers);
		return (NULL);
	    }
	}

	controllers[i] = NULL;

	*errp = 0;
	return (controllers);
}

static descriptor_t **
get_assoc_drives(descriptor_t *desc, int *errp)
{
	path_t		*pp;
	descriptor_t	**drives;
	int		cnt;
	int		i;

	pp = desc->p.path;

	/* Count how many we have. */
	for (cnt = 0; pp->disks[cnt]; cnt++);

	/* make the snapshot */
	drives = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (drives == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	for (i = 0; pp->disks[i]; i++) {
	    drives[i] = cache_get_desc(DM_DRIVE, pp->disks[i], NULL, NULL,
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

static char *
path_state_name(di_path_state_t st)
{
	switch (st) {
	    case DI_PATH_STATE_ONLINE:
		return ("online");
	    case DI_PATH_STATE_STANDBY:
		return ("standby");
	    case DI_PATH_STATE_OFFLINE:
		return ("offline");
	    case DI_PATH_STATE_FAULT:
		return ("faulted");
	}
	return ("unknown");
}
