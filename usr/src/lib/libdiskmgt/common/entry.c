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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <sys/debug.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/swap.h>

#include "libdiskmgt.h"
#include "disks_private.h"
#include "partition.h"

#define	ANY_ZPOOL_USE(who) \
	(((who) == DM_WHO_ZPOOL_FORCE) || \
	((who) == DM_WHO_ZPOOL) || \
	((who) == DM_WHO_ZPOOL_SPARE))

extern	char	*getfullblkname();

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
static int build_usage_string(char *dname, char *by, char *data, char **use,
	int *found, int *errp);

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
		if (stat_type == DM_SLICE_STAT_USE) {
			/*
			 * If NOINUSE_CHECK is set, we do not perform
			 * the in use checking if the user has set stat_type
			 * DM_SLICE_STAT_USE
			 */
			if (NOINUSE_SET) {
				stats = NULL;
				break;
			}
		}
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
/*
 * Returns, via slices paramater, a dm_descriptor_t list of
 * slices for the named disk drive.
 */
void
dm_get_slices(char *drive, dm_descriptor_t **slices, int *errp)
{
	dm_descriptor_t alias;
	dm_descriptor_t	*media;
	dm_descriptor_t *disk;

	*slices = NULL;
	*errp = 0;

	if (drive == NULL) {
		return;
	}

	alias = dm_get_descriptor_by_name(DM_ALIAS, drive, errp);

	/*
	 * Errors must be handled by the caller. The dm_descriptor_t *
	 * values will be NULL if an error occured in these calls.
	 */

	if (alias != NULL) {
		disk = dm_get_associated_descriptors(alias, DM_DRIVE, errp);
		dm_free_descriptor(alias);
		if (disk != NULL) {
			media = dm_get_associated_descriptors(*disk,
			    DM_MEDIA, errp);
			dm_free_descriptors(disk);
			if (media != NULL) {
				*slices = dm_get_associated_descriptors(*media,
				    DM_SLICE, errp);
				dm_free_descriptors(media);
			}
		}
	}
}
/*
 * Convenience function to get slice stats
 */
void
dm_get_slice_stats(char *slice, nvlist_t **dev_stats, int *errp)
{
	dm_descriptor_t	devp;

	*dev_stats = NULL;
	*errp = 0;

	if (slice == NULL) {
		return;
	}

	/*
	 * Errors must be handled by the caller. The dm_descriptor_t *
	 * values will be NULL if an error occured in these calls.
	 */
	devp = dm_get_descriptor_by_name(DM_SLICE, slice, errp);
	if (devp != NULL) {
		*dev_stats = dm_get_stats(devp, DM_SLICE_STAT_USE,
		    errp);
		dm_free_descriptor(devp);
	}
}

/*
 * Checks for overlapping slices.   If the given device is a slice, and it
 * overlaps with any non-backup slice on the disk, return true with a detailed
 * description similar to dm_inuse().
 */
int
dm_isoverlapping(char *slicename, char **overlaps_with, int *errp)
{
	dm_descriptor_t slice = NULL;
	dm_descriptor_t *media = NULL;
	dm_descriptor_t *slices = NULL;
	int 		i = 0;
	uint32_t	in_snum;
	uint64_t 	start_block = 0;
	uint64_t 	end_block = 0;
	uint64_t 	media_size = 0;
	uint64_t 	size = 0;
	nvlist_t 	*media_attrs = NULL;
	nvlist_t 	*slice_attrs = NULL;
	int		ret = 0;

	slice = dm_get_descriptor_by_name(DM_SLICE, slicename, errp);
	if (slice == NULL)
		goto out;

	/*
	 * Get the list of slices be fetching the associated media, and then all
	 * associated slices.
	 */
	media = dm_get_associated_descriptors(slice, DM_MEDIA, errp);
	if (media == NULL || *media == NULL || *errp != 0)
		goto out;

	slices = dm_get_associated_descriptors(*media, DM_SLICE, errp);
	if (slices == NULL || *slices == NULL || *errp != 0)
		goto out;

	media_attrs = dm_get_attributes(*media, errp);
	if (media_attrs == NULL || *errp)
		goto out;

	*errp = nvlist_lookup_uint64(media_attrs, DM_NACCESSIBLE, &media_size);
	if (*errp != 0)
		goto out;

	slice_attrs = dm_get_attributes(slice, errp);
	if (slice_attrs == NULL || *errp != 0)
		goto out;

	*errp = nvlist_lookup_uint64(slice_attrs, DM_START, &start_block);
	if (*errp != 0)
		goto out;

	*errp = nvlist_lookup_uint64(slice_attrs, DM_SIZE, &size);
	if (*errp != 0)
		goto out;

	*errp = nvlist_lookup_uint32(slice_attrs, DM_INDEX, &in_snum);
	if (*errp != 0)
		goto out;

	end_block = (start_block + size) - 1;

	for (i = 0; slices[i]; i ++) {
		uint64_t other_start;
		uint64_t other_end;
		uint64_t other_size;
		uint32_t snum;

		nvlist_t *other_attrs = dm_get_attributes(slices[i], errp);

		if (other_attrs == NULL)
			continue;

		if (*errp != 0)
			goto out;

		*errp = nvlist_lookup_uint64(other_attrs, DM_START,
		    &other_start);
		if (*errp) {
			nvlist_free(other_attrs);
			goto out;
		}

		*errp = nvlist_lookup_uint64(other_attrs, DM_SIZE,
		    &other_size);

		if (*errp) {
			nvlist_free(other_attrs);
			ret = -1;
			goto out;
		}

		other_end = (other_size + other_start) - 1;

		*errp = nvlist_lookup_uint32(other_attrs, DM_INDEX,
		    &snum);

		if (*errp) {
			nvlist_free(other_attrs);
			ret = -1;
			goto out;
		}

		/*
		 * Check to see if there are > 2 overlapping regions
		 * on this media in the same region as this slice.
		 * This is done by assuming the following:
		 *   	Slice 2 is the backup slice if it is the size
		 *	of the whole disk
		 * If slice 2 is the overlap and slice 2 is the size of
		 * the whole disk, continue. If another slice is found
		 * that overlaps with our slice, return it.
		 * There is the potential that there is more than one slice
		 * that our slice overlaps with, however, we only return
		 * the first overlapping slice we find.
		 *
		 */
		if (start_block >= other_start && start_block <= other_end) {
			if ((snum == 2 && (other_size == media_size)) ||
			    snum == in_snum) {
				continue;
			} else {
				char *str = dm_get_name(slices[i], errp);
				if (*errp != 0) {
					nvlist_free(other_attrs);
					ret = -1;
					goto out;
				}
				*overlaps_with = strdup(str);
				dm_free_name(str);
				nvlist_free(other_attrs);
				ret = 1;
				goto out;
			}
		} else if (other_start >= start_block &&
		    other_start <= end_block) {
			if ((snum == 2 && (other_size == media_size)) ||
			    snum == in_snum) {
				continue;
			} else {
				char *str = dm_get_name(slices[i], errp);
				if (*errp != 0) {
					nvlist_free(other_attrs);
					ret = -1;
					goto out;
				}
				*overlaps_with = strdup(str);
				dm_free_name(str);
				nvlist_free(other_attrs);
				ret = 1;
				goto out;
			}
		}
		nvlist_free(other_attrs);
	}

out:
	nvlist_free(media_attrs);
	nvlist_free(slice_attrs);

	if (slices)
		dm_free_descriptors(slices);
	if (media)
		dm_free_descriptors(media);
	if (slice)
		dm_free_descriptor(slice);

	return (ret);
}

/*
 * Get the full list of swap entries.  Returns -1 on error, or >= 0 to
 * indicate the number of entries in the list.  Callers are responsible
 * for calling dm_free_swapentries() to deallocate memory.  If this
 * returns 0, the swaptbl_t still needs to be freed.
 */
int
dm_get_swapentries(swaptbl_t **stp, int *errp)
{
	int count, i;
	swaptbl_t *tbl;
	char *ptr;

	*stp = NULL;

	/* get number of swap entries */
	if ((count = swapctl(SC_GETNSWP, NULL)) < 0) {
		*errp = errno;
		return (-1);
	}

	if (count == 0) {
		return (0);
	}

	/* allocate space */
	tbl = calloc(1, sizeof (int) + count * sizeof (swapent_t));
	if (tbl == NULL) {
		*errp = ENOMEM;
		return (-1);
	}

	ptr = calloc(1, count * MAXPATHLEN);
	if (ptr == NULL) {
		*errp = ENOMEM;
		free(tbl);
		return (-1);
	}

	/* set up pointers to the pathnames */
	tbl->swt_n = count;
	for (i = 0; i < count; i++) {
		tbl->swt_ent[i].ste_path = ptr;
		ptr += MAXPATHLEN;
	}

	/* get list of swap paths */
	count = swapctl(SC_LIST, tbl);
	if (count < 0) {
		*errp = errno;
		free(ptr);
		free(tbl);
		return (-1);
	}

	*stp = tbl;
	return (count);
}

/* ARGSUSED */
void
dm_free_swapentries(swaptbl_t *stp)
{
	ASSERT(stp != NULL);

	free(stp->swt_ent[0].ste_path);
	free(stp);
}

/*
 * Check a slice to see if it's being used by swap.
 */
int
dm_inuse_swap(const char *dev_name, int *errp)
{
	int count;
	int found;
	swaptbl_t *tbl = NULL;

	*errp = 0;

	count = dm_get_swapentries(&tbl, errp);
	if (count < 0 || *errp) {
		if (tbl)
			dm_free_swapentries(tbl);
		return (-1);
	}

	/* if there are no swap entries, we're done */
	if (!count) {
		return (0);
	}

	ASSERT(tbl != NULL);

	found = 0;
	while (count--) {
		if (strcmp(dev_name, tbl->swt_ent[count].ste_path) == 0) {
			found = 1;
			break;
		}
	}

	dm_free_swapentries(tbl);
	return (found);
}

/*
 * Returns 'in use' details, if found, about a specific dev_name,
 * based on the caller(who). It is important to note that it is possible
 * for there to be more than one 'in use' statistic regarding a dev_name.
 * The **msg parameter returns a list of 'in use' details. This message
 * is formatted via gettext().
 */
int
dm_inuse(char *dev_name, char **msg, dm_who_type_t who, int *errp)
{
	nvlist_t *dev_stats = NULL;
	char *by, *data;
	nvpair_t *nvwhat = NULL;
	nvpair_t *nvdesc = NULL;
	int	found = 0;
	int	err;
	char	*dname = NULL;

	*errp = 0;
	*msg = NULL;

	/*
	 * If the user doesn't want to do in use checking, return.
	 */

	if (NOINUSE_SET)
		return (0);

	dname = getfullblkname(dev_name);
	/*
	 * If we cannot find the block name, we cannot check the device
	 * for in use statistics. So, return found, which is == 0.
	 */
	if (dname == NULL || *dname == '\0') {
		return (found);
	}

	/*
	 * Slice stats for swap devices are only returned if mounted
	 * (e.g. /tmp).  Other devices or files being used for swap
	 * are ignored, so we add a special check here to use swapctl(2)
	 * to perform in-use checking.
	 */
	if (ANY_ZPOOL_USE(who) && (err = dm_inuse_swap(dname, errp))) {

		/* on error, dm_inuse_swap sets errp */
		if (err < 0) {
			free(dname);
			return (err);
		}

		/* simulate a mounted swap device */
		(void) build_usage_string(dname, DM_USE_MOUNT, "swap", msg,
		    &found, errp);

		/* if this fails, dm_get_usage_string changed */
		ASSERT(found == 1);

		free(dname);
		return (found);
	}

	dm_get_slice_stats(dname, &dev_stats, errp);
	if (dev_stats == NULL) {
		/*
		 * If there is an error, but it isn't a no device found error
		 * return the error as recorded. Otherwise, with a full
		 * block name, we might not be able to get the slice
		 * associated, and will get an ENODEV error. For example,
		 * an SVM metadevice will return a value from getfullblkname()
		 * but libdiskmgt won't be able to find this device for
		 * statistics gathering. This is expected and we should not
		 * report errnoneous errors.
		 */
		if (*errp) {
			if (*errp == ENODEV) {
				*errp = 0;
			}
		}
		free(dname);
		return (found);
	}

	for (;;) {

		nvwhat = nvlist_next_nvpair(dev_stats, nvdesc);
		nvdesc = nvlist_next_nvpair(dev_stats, nvwhat);

		/*
		 * End of the list found.
		 */
		if (nvwhat == NULL || nvdesc == NULL) {
			break;
		}
		/*
		 * Otherwise, we check to see if this client(who) cares
		 * about this in use scenario
		 */

		ASSERT(strcmp(nvpair_name(nvwhat), DM_USED_BY) == 0);
		ASSERT(strcmp(nvpair_name(nvdesc), DM_USED_NAME) == 0);
		/*
		 * If we error getting the string value continue on
		 * to the next pair(if there is one)
		 */
		if (nvpair_value_string(nvwhat, &by)) {
			continue;
		}
		if (nvpair_value_string(nvdesc, &data)) {
			continue;
		}

		switch (who) {
			case DM_WHO_MKFS:
				/*
				 * mkfs is not in use for these cases.
				 * All others are in use.
				 */
				if (strcmp(by, DM_USE_LU) == 0 ||
				    strcmp(by, DM_USE_FS) == 0 ||
				    strcmp(by, DM_USE_EXPORTED_ZPOOL) == 0) {
					break;
				}
				if (build_usage_string(dname,
				    by, data, msg, &found, errp) != 0) {
					if (*errp) {
						goto out;
					}
				}
				break;
			case DM_WHO_SWAP:
				/*
				 * Not in use for this.
				 */
				if (strcmp(by, DM_USE_DUMP) == 0 ||
				    strcmp(by, DM_USE_FS) == 0 ||
				    strcmp(by, DM_USE_EXPORTED_ZPOOL) == 0) {
					break;
				}
				if (strcmp(by, DM_USE_LU) == 0 &&
				    strcmp(data, "-") == 0) {
					break;
				}
				if (strcmp(by, DM_USE_VFSTAB) == 0 &&
				    strcmp(data, "") == 0) {
					break;
				}
				if (build_usage_string(dname,
				    by, data, msg, &found, errp) != 0) {
					if (*errp) {
						goto out;
					}
				}
				break;
			case DM_WHO_DUMP:
				/*
				 * Not in use for this.
				 */
				if ((strcmp(by, DM_USE_MOUNT) == 0 &&
				    strcmp(data, "swap") == 0) ||
				    strcmp(by, DM_USE_DUMP) == 0 ||
				    strcmp(by, DM_USE_FS) == 0 ||
				    strcmp(by, DM_USE_EXPORTED_ZPOOL) == 0) {
					break;
				}
				if (build_usage_string(dname,
				    by, data, msg, &found, errp)) {
					if (*errp) {
						goto out;
					}
				}
				break;

			case DM_WHO_FORMAT:
				if (strcmp(by, DM_USE_FS) == 0 ||
				    strcmp(by, DM_USE_EXPORTED_ZPOOL) == 0)
					break;
				if (build_usage_string(dname,
				    by, data, msg, &found, errp) != 0) {
					if (*errp) {
						goto out;
					}
				}
				break;

			case DM_WHO_ZPOOL_FORCE:
				if (strcmp(by, DM_USE_FS) == 0 ||
				    strcmp(by, DM_USE_EXPORTED_ZPOOL) == 0)
					break;
				/* FALLTHROUGH */
			case DM_WHO_ZPOOL:
				if (build_usage_string(dname,
				    by, data, msg, &found, errp) != 0) {
					if (*errp)
						goto out;
				}
				break;

			case DM_WHO_ZPOOL_SPARE:
				if (strcmp(by, DM_USE_SPARE_ZPOOL) != 0) {
					if (build_usage_string(dname, by,
					    data, msg, &found, errp) != 0) {
						if (*errp)
							goto out;
					}
				}
				break;

			default:
				/*
				 * nothing found in use for this client
				 * of libdiskmgt. Default is 'not in use'.
				 */
				break;
		}
	}
out:
	if (dname != NULL)
		free(dname);
	nvlist_free(dev_stats);

	return (found);
}

void
dm_get_usage_string(char *what, char *how, char **usage_string)
{


	if (usage_string == NULL || what == NULL) {
		return;
	}
	*usage_string = NULL;

	if (strcmp(what, DM_USE_MOUNT) == 0) {
		if (strcmp(how, "swap") == 0) {
			*usage_string = dgettext(TEXT_DOMAIN,
			    "%s is currently used by swap. Please see swap(1M)."
			    "\n");
		} else {
			*usage_string = dgettext(TEXT_DOMAIN,
			    "%s is currently mounted on %s."
			    " Please see umount(1M).\n");
		}
	} else if (strcmp(what, DM_USE_VFSTAB) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is normally mounted on %s according to /etc/vfstab. "
		    "Please remove this entry to use this device.\n");
	} else if (strcmp(what, DM_USE_FS) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s contains a %s filesystem.\n");
	} else if (strcmp(what, DM_USE_SVM) == 0) {
		if (strcmp(how, "mdb") == 0) {
			*usage_string = dgettext(TEXT_DOMAIN,
			    "%s contains an SVM %s. Please see "
			    "metadb(1M).\n");
		} else {
			*usage_string = dgettext(TEXT_DOMAIN,
			    "%s is part of SVM volume %s. "
			    "Please see metaclear(1M).\n");
		}
	} else if (strcmp(what, DM_USE_VXVM) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is part of VxVM volume %s.\n");
	} else if (strcmp(what, DM_USE_LU) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is in use for live upgrade %s. Please see ludelete(1M)."
		    "\n");
	} else if (strcmp(what, DM_USE_DUMP) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is in use by %s. Please see dumpadm(1M)."
		    "\n");
	} else if (strcmp(what, DM_USE_EXPORTED_ZPOOL) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is part of exported or potentially active ZFS pool %s. "
		    "Please see zpool(1M).\n");
	} else if (strcmp(what, DM_USE_ACTIVE_ZPOOL) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is part of active ZFS pool %s. Please see zpool(1M)."
		    "\n");
	} else if (strcmp(what, DM_USE_SPARE_ZPOOL) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is reserved as a hot spare for ZFS pool %s.  Please "
		    "see zpool(1M).\n");
	} else if (strcmp(what, DM_USE_L2CACHE_ZPOOL) == 0) {
		*usage_string = dgettext(TEXT_DOMAIN,
		    "%s is in use as a cache device for ZFS pool %s.  "
		    "Please see zpool(1M).\n");
	}
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

	for (cnt = 0; descs[cnt]; cnt++)
		;

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

	for (cnt = 0; ptrs[cnt]; cnt++)
		;

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
/*
 * Build the usage string for the in use data. Return the build string in
 * the msg parameter. This function takes care of reallocing all the memory
 * for this usage string. Usage string is returned already formatted for
 * localization.
 */
static int
build_usage_string(char *dname, char *by, char *data, char **msg,
    int *found, int *errp)
{
	int	len0;
	int	len1;
	char	*use;
	char	*p;

	*errp = 0;

	dm_get_usage_string(by, data, &use);
	if (!use) {
		return (-1);
	}

	if (*msg)
		len0 = strlen(*msg);
	else
		len0 = 0;
	/* LINTED */
	len1 = snprintf(NULL, 0, use, dname, data);

	/*
	 * If multiple in use details they
	 * are listed 1 per line for ease of
	 * reading. dm_find_usage_string
	 * formats these appropriately.
	 */
	if ((p = realloc(*msg, len0 + len1 + 1)) == NULL) {
		*errp = errno;
		free(*msg);
		return (-1);
	}
	*msg = p;

	/* LINTED */
	(void) snprintf(*msg + len0, len1 + 1, use, dname, data);
	(*found)++;
	return (0);
}
