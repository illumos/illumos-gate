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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "libdiskmgt.h"
#include "disks_private.h"
#include "partition.h"


extern dm_desc_type_t drive_assoc_types[];
extern dm_desc_type_t bus_assoc_types[];
extern dm_desc_type_t controller_assoc_types[];
extern dm_desc_type_t media_assoc_types[];
extern dm_desc_type_t slice_assoc_types[];
extern dm_desc_type_t partition_assoc_types[];
extern dm_desc_type_t path_assoc_types[];
extern dm_desc_type_t alias_assoc_types[];

static dm_descriptor_t *ptr_array_to_desc_array(descriptor_t **ptrs, int *errp);
static descriptor_t **desc_array_to_ptr_array(dm_descriptor_t *da, int *errp);

void
dm_free_descriptor(dm_descriptor_t desc)
{
	descriptor_t	*dp;

	if (desc == NULL) {
	    return;
	}
	dp = (descriptor_t *)(uintptr_t)desc;

	cache_wlock();
	cache_free_descriptor(dp);
	cache_unlock();
}

void
dm_free_descriptors(dm_descriptor_t *desc_list)
{
	descriptor_t	**dp;
	int		error;

	if (desc_list == NULL) {
	    return;
	}
	dp = desc_array_to_ptr_array(desc_list, &error);
	if (error != 0) {
	    free(desc_list);
	    return;
	}

	cache_wlock();
	cache_free_descriptors(dp);
	cache_unlock();
}

/*ARGSUSED*/
void
dm_free_name(char *name)
{
	free(name);
}

dm_descriptor_t *
dm_get_associated_descriptors(dm_descriptor_t desc, dm_desc_type_t type,
    int *errp)
{
	descriptor_t **descs = NULL;
	descriptor_t  *dp;


	dp = (descriptor_t *)(uintptr_t)desc;

	cache_wlock();

	if (!cache_is_valid_desc(dp)) {
	    cache_unlock();
	    *errp = EBADF;
	    return (NULL);
	}

	/* verify that the descriptor is still valid */
	if (dp->p.generic == NULL) {
	    cache_unlock();
	    *errp = ENODEV;
	    return (NULL);
	}

	switch (dp->type) {
	case DM_DRIVE:
	    descs = drive_get_assoc_descriptors(dp, type, errp);
	    break;
	case DM_BUS:
	    descs = bus_get_assoc_descriptors(dp, type, errp);
	    break;
	case DM_CONTROLLER:
	    descs = controller_get_assoc_descriptors(dp, type, errp);
	    break;
	case DM_MEDIA:
	    descs = media_get_assoc_descriptors(dp, type, errp);
	    break;
	case DM_SLICE:
	    descs = slice_get_assoc_descriptors(dp, type, errp);
	    break;
	case DM_PARTITION:
	    descs = partition_get_assoc_descriptors(dp, type, errp);
	    break;
	case DM_PATH:
	    descs = path_get_assoc_descriptors(dp, type, errp);
	    break;
	case DM_ALIAS:
	    descs = alias_get_assoc_descriptors(dp, type, errp);
	    break;
	default:
	    *errp = EINVAL;
	    break;
	}

	cache_unlock();

	return (ptr_array_to_desc_array(descs, errp));
}

dm_desc_type_t *
dm_get_associated_types(dm_desc_type_t type)
{
	switch (type) {
	case DM_DRIVE:
	    return (drive_assoc_types);
	case DM_BUS:
	    return (bus_assoc_types);
	case DM_CONTROLLER:
	    return (controller_assoc_types);
	case DM_MEDIA:
	    return (media_assoc_types);
	case DM_SLICE:
	    return (slice_assoc_types);
	case DM_PARTITION:
	    return (partition_assoc_types);
	case DM_PATH:
	    return (path_assoc_types);
	case DM_ALIAS:
	    return (alias_assoc_types);
	}

	return (NULL);
}

nvlist_t *
dm_get_attributes(dm_descriptor_t desc, int *errp)
{
	descriptor_t	*dp;
	nvlist_t	*attrs = NULL;


	dp = (descriptor_t *)(uintptr_t)desc;

	cache_rlock();

	if (!cache_is_valid_desc(dp)) {
	    cache_unlock();
	    *errp = EBADF;
	    return (NULL);
	}

	/* verify that the descriptor is still valid */
	if (dp->p.generic == NULL) {
	    cache_unlock();
	    *errp = ENODEV;
	    return (NULL);
	}

	switch (dp->type) {
	case DM_DRIVE:
	    attrs = drive_get_attributes(dp, errp);
	    break;
	case DM_BUS:
	    attrs = bus_get_attributes(dp, errp);
	    break;
	case DM_CONTROLLER:
	    attrs = controller_get_attributes(dp, errp);
	    break;
	case DM_MEDIA:
	    attrs = media_get_attributes(dp, errp);
	    break;
	case DM_SLICE:
	    attrs = slice_get_attributes(dp, errp);
	    break;
	case DM_PARTITION:
	    attrs = partition_get_attributes(dp, errp);
	    break;
	case DM_PATH:
	    attrs = path_get_attributes(dp, errp);
	    break;
	case DM_ALIAS:
	    attrs = alias_get_attributes(dp, errp);
	    break;
	default:
	    *errp = EINVAL;
	    break;
	}

	cache_unlock();

	return (attrs);
}

dm_descriptor_t
dm_get_descriptor_by_name(dm_desc_type_t desc_type, char *name, int *errp)
{
	dm_descriptor_t desc = NULL;


	cache_wlock();

	switch (desc_type) {
	case DM_DRIVE:
	    desc = (uintptr_t)drive_get_descriptor_by_name(name, errp);
	    break;
	case DM_BUS:
	    desc = (uintptr_t)bus_get_descriptor_by_name(name, errp);
	    break;
	case DM_CONTROLLER:
	    desc = (uintptr_t)controller_get_descriptor_by_name(name,
		errp);
	    break;
	case DM_MEDIA:
	    desc = (uintptr_t)media_get_descriptor_by_name(name, errp);
	    break;
	case DM_SLICE:
	    desc = (uintptr_t)slice_get_descriptor_by_name(name, errp);
	    break;
	case DM_PARTITION:
	    desc = (uintptr_t)partition_get_descriptor_by_name(name,
		errp);
	    break;
	case DM_PATH:
	    desc = (uintptr_t)path_get_descriptor_by_name(name, errp);
	    break;
	case DM_ALIAS:
	    desc = (uintptr_t)alias_get_descriptor_by_name(name, errp);
	    break;
	default:
	    *errp = EINVAL;
	    break;
	}

	cache_unlock();

	return (desc);
}

dm_descriptor_t *
dm_get_descriptors(dm_desc_type_t type, int filter[], int *errp)
{
	descriptor_t **descs = NULL;


	cache_wlock();

	switch (type) {
	case DM_DRIVE:
	    descs = drive_get_descriptors(filter, errp);
	    break;
	case DM_BUS:
	    descs = bus_get_descriptors(filter, errp);
	    break;
	case DM_CONTROLLER:
	    descs = controller_get_descriptors(filter, errp);
	    break;
	case DM_MEDIA:
	    descs = media_get_descriptors(filter, errp);
	    break;
	case DM_SLICE:
	    descs = slice_get_descriptors(filter, errp);
	    break;
	case DM_PARTITION:
	    descs = partition_get_descriptors(filter, errp);
	    break;
	case DM_PATH:
	    descs = path_get_descriptors(filter, errp);
	    break;
	case DM_ALIAS:
	    descs = alias_get_descriptors(filter, errp);
	    break;
	default:
	    *errp = EINVAL;
	    break;
	}

	cache_unlock();

	return (ptr_array_to_desc_array(descs, errp));
}

char *
dm_get_name(dm_descriptor_t desc, int *errp)
{
	descriptor_t	*dp;
	char		*nm = NULL;
	char		*name = NULL;

	dp = (descriptor_t *)(uintptr_t)desc;

	cache_rlock();

	if (!cache_is_valid_desc(dp)) {
	    cache_unlock();
	    *errp = EBADF;
	    return (NULL);
	}

	/* verify that the descriptor is still valid */
	if (dp->p.generic == NULL) {
	    cache_unlock();
	    *errp = ENODEV;
	    return (NULL);
	}

	switch (dp->type) {
	case DM_DRIVE:
	    nm = (drive_get_name(dp));
	    break;
	case DM_BUS:
	    nm = (bus_get_name(dp));
	    break;
	case DM_CONTROLLER:
	    nm = (controller_get_name(dp));
	    break;
	case DM_MEDIA:
	    nm = (media_get_name(dp));
	    break;
	case DM_SLICE:
	    nm = (slice_get_name(dp));
	    break;
	case DM_PARTITION:
	    nm = (partition_get_name(dp));
	    break;
	case DM_PATH:
	    nm = (path_get_name(dp));
	    break;
	case DM_ALIAS:
	    nm = (alias_get_name(dp));
	    break;
	}

	cache_unlock();

	*errp = 0;
	if (nm != NULL) {
	    name = strdup(nm);
	    if (name == NULL) {
		*errp = ENOMEM;
		return (NULL);
	    }
	    return (name);
	}
	return (NULL);
}

nvlist_t *
dm_get_stats(dm_descriptor_t desc, int stat_type, int *errp)
{
	descriptor_t  *dp;
	nvlist_t	*stats = NULL;


	dp = (descriptor_t *)(uintptr_t)desc;

	cache_rlock();

	if (!cache_is_valid_desc(dp)) {
	    cache_unlock();
	    *errp = EBADF;
	    return (NULL);
	}

	/* verify that the descriptor is still valid */
	if (dp->p.generic == NULL) {
	    cache_unlock();
	    *errp = ENODEV;
	    return (NULL);
	}

	switch (dp->type) {
	case DM_DRIVE:
	    stats = drive_get_stats(dp, stat_type, errp);
	    break;
	case DM_BUS:
	    stats = bus_get_stats(dp, stat_type, errp);
	    break;
	case DM_CONTROLLER:
	    stats = controller_get_stats(dp, stat_type, errp);
	    break;
	case DM_MEDIA:
	    stats = media_get_stats(dp, stat_type, errp);
	    break;
	case DM_SLICE:
	    stats = slice_get_stats(dp, stat_type, errp);
	    break;
	case DM_PARTITION:
	    stats = partition_get_stats(dp, stat_type, errp);
	    break;
	case DM_PATH:
	    stats = path_get_stats(dp, stat_type, errp);
	    break;
	case DM_ALIAS:
	    stats = alias_get_stats(dp, stat_type, errp);
	    break;
	default:
	    *errp = EINVAL;
	    break;
	}

	cache_unlock();

	return (stats);
}

dm_desc_type_t
dm_get_type(dm_descriptor_t desc)
{
	descriptor_t  *dp;

	dp = (descriptor_t *)(uintptr_t)desc;

	cache_rlock();

	if (!cache_is_valid_desc(dp)) {
	    cache_unlock();
	    return (-1);
	}

	cache_unlock();

	return (dp->type);
}

void
libdiskmgt_add_str(nvlist_t *attrs, char *name, char *val, int *errp)
{
	if (*errp == 0) {
		*errp = nvlist_add_string(attrs, name, val);
	}
}

descriptor_t **
libdiskmgt_empty_desc_array(int *errp)
{
	descriptor_t	**empty;

	empty = (descriptor_t **)calloc(1, sizeof (descriptor_t *));
	if (empty == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}
	empty[0] = NULL;

	*errp = 0;
	return (empty);
}

void
libdiskmgt_init_debug()
{
	char	*valp;

	if ((valp = getenv(DM_DEBUG)) != NULL) {
	    dm_debug = atoi(valp);
	}
}

int
libdiskmgt_str_eq(char *nm1, char *nm2)
{
	if (nm1 == NULL) {
	    if (dm_debug) {
		(void) fprintf(stderr, "WARNING: str_eq nm1 NULL\n");
	    }

	    if (nm2 == NULL) {
		return (1);
	    } else {
		return (0);
	    }
	}

	/* nm1 != NULL */

	if (nm2 == NULL) {
	    if (dm_debug) {
		(void) fprintf(stderr, "WARNING: str_eq nm2 NULL\n");
	    }
	    return (0);
	}

	if (strcmp(nm1, nm2) == 0) {
	    return (1);
	}

	return (0);
}

/*ARGSUSED*/
static descriptor_t **
desc_array_to_ptr_array(dm_descriptor_t *descs, int *errp)
{
#ifdef _LP64
	return ((descriptor_t **)descs);
#else
	/* convert the 64 bit descriptors to 32 bit ptrs */
	int	cnt;
	int	i;
	descriptor_t **da;

	for (cnt = 0; descs[cnt]; cnt++);

	da = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (da == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	for (i = 0; descs[i]; i++) {
	    da[i] = (descriptor_t *)(uintptr_t)descs[i];
	}
	*errp = 0;
	free(descs);

	return (da);
#endif
}

/*ARGSUSED*/
static dm_descriptor_t *
ptr_array_to_desc_array(descriptor_t **ptrs, int *errp)
{
#ifdef _LP64
	return ((dm_descriptor_t *)ptrs);
#else
	/* convert the 32 bit ptrs to the 64 bit descriptors */
	int	cnt;
	int	i;
	dm_descriptor_t *da;

	if (*errp != 0 || ptrs == NULL) {
	    return (NULL);
	}

	for (cnt = 0; ptrs[cnt]; cnt++);

	da = (dm_descriptor_t *)calloc(cnt + 1, sizeof (dm_descriptor_t));
	if (da == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	for (i = 0; ptrs[i]; i++) {
	    da[i] = (uintptr_t)ptrs[i];
	}
	*errp = 0;
	free(ptrs);

	return (da);
#endif
}
