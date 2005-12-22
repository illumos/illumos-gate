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

/*
 * Functions to convert between a list of vdevs and an nvlist representing the
 * configuration.  Each entry in the list can be one of:
 *
 * 	Device vdevs
 * 		disk=(path=..., devid=...)
 * 		file=(path=...)
 *
 * 	Group vdevs
 * 		raidz=(...)
 * 		mirror=(...)
 *
 * While the underlying implementation supports it, group vdevs cannot contain
 * other group vdevs.  All userland verification of devices is contained within
 * this file.  If successful, the nvlist returned can be passed directly to the
 * kernel; we've done as much verification as possible in userland.
 *
 * The only function exported by this file is 'get_vdev_spec'.  The function
 * performs several passes:
 *
 * 	1. Construct the vdev specification.  Performs syntax validation and
 *         makes sure each device is valid.
 * 	2. Check for devices in use.  Using libdiskmgt, makes sure that no
 *         devices are also in use.  Some can be overridden using the 'force'
 *         flag, others cannot.
 * 	3. Check for replication errors if the 'force' flag is not specified.
 *         validates that the replication level is consistent across the
 *         entire pool.
 * 	4. Label any whole disks with an EFI label.
 */

#include <assert.h>
#include <devid.h>
#include <errno.h>
#include <fcntl.h>
#include <libdiskmgt.h>
#include <libintl.h>
#include <libnvpair.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/efi_partition.h>
#include <sys/stat.h>
#include <sys/vtoc.h>
#include <sys/mntent.h>

#include <libzfs.h>

#include "zpool_util.h"

#define	DISK_ROOT	"/dev/dsk"
#define	RDISK_ROOT	"/dev/rdsk"
#define	BACKUP_SLICE	"s2"

/*
 * For any given vdev specification, we can have multiple errors.  The
 * vdev_error() function keeps track of whether we have seen an error yet, and
 * prints out a header if its the first error we've seen.
 */
int error_seen;
int is_force;

void
vdev_error(const char *fmt, ...)
{
	va_list ap;

	if (!error_seen) {
		(void) fprintf(stderr, gettext("invalid vdev specification\n"));
		if (!is_force)
			(void) fprintf(stderr, gettext("use '-f' to override "
			    "the following errors:\n"));
		else
			(void) fprintf(stderr, gettext("the following errors "
			    "must be manually repaired:\n"));
		error_seen = TRUE;
	}

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void
_libdskmgt_error(int err, const char *file, int line)
{
	if (err == 0)
		no_memory();

	/*
	 * Some of the libdiskmgt stuff requires root privileges in order to
	 * examine devices.  Bail out gracefully in this case.
	 */
	if (err == EACCES) {
		(void) fprintf(stderr, gettext("cannot determine disk "
		    "configuration: permission denied\n"));
		exit(1);
	}

	(void) fprintf(stderr, gettext("internal error: disk configuration "
	    "error %d at line %d of file %s\n"), err, line, file);
	abort();
}

#define	libdskmgt_error(err)	(_libdskmgt_error((err), __FILE__, __LINE__))

/*
 * Checks whether a single slice overlaps with any of the slices in the provided
 * list.  Called by check_overlapping().
 */
int
is_overlapping(dm_descriptor_t slice, dm_descriptor_t media,
	dm_descriptor_t *slice_list, int *error, char **overlaps_with)
{
	int 		i = 0;
	uint32_t	in_snum;
	uint64_t 	start_block = 0;
	uint64_t 	end_block = 0;
	uint64_t 	media_size = 0;
	uint64_t 	size = 0;
	nvlist_t 	*media_attrs;
	nvlist_t 	*slice_attrs;

	media_attrs = dm_get_attributes(media, error);
	if (*error != 0) {
		return (-1);
	}

	if (media_attrs == NULL) {
		return (0);
	}

	*error = nvlist_lookup_uint64(media_attrs, DM_NACCESSIBLE, &media_size);
	if (*error != 0) {
		nvlist_free(media_attrs);
		return (-1);
	}

	slice_attrs = dm_get_attributes(slice, error);
	if (*error != 0) {
		nvlist_free(media_attrs);
		return (-1);
	}
	/*
	 * Not really possible, but the error above would catch any system
	 * errors.
	 */
	if (slice_attrs == NULL) {
		nvlist_free(media_attrs);
		return (0);
	}

	*error = nvlist_lookup_uint64(slice_attrs, DM_START, &start_block);
	if (*error != 0) {
		nvlist_free(media_attrs);
		nvlist_free(slice_attrs);
		return (-1);
	}

	*error = nvlist_lookup_uint64(slice_attrs, DM_SIZE, &size);
	if (*error != 0) {
		nvlist_free(media_attrs);
		nvlist_free(slice_attrs);
		return (-1);
	}
	*error = nvlist_lookup_uint32(slice_attrs, DM_INDEX, &in_snum);
	if (*error != 0) {
		nvlist_free(media_attrs);
		nvlist_free(slice_attrs);
		return (-1);
	}

	end_block = (start_block + size) - 1;

	for (i = 0; slice_list[i]; i ++) {
		uint64_t other_start;
		uint64_t other_end;
		uint64_t other_size;
		uint32_t snum;

		nvlist_t *other_attrs = dm_get_attributes(slice_list[i], error);
		if (*error != 0) {
			return (-1);
		}

		if (other_attrs == NULL)
			continue;

		*error = nvlist_lookup_uint64(other_attrs, DM_START,
			&other_start);
		if (*error) {
		    nvlist_free(media_attrs);
		    nvlist_free(slice_attrs);
		    nvlist_free(other_attrs);
		    return (-1);
		}

		*error = nvlist_lookup_uint64(other_attrs, DM_SIZE,
			&other_size);

		if (*error) {
		    nvlist_free(media_attrs);
		    nvlist_free(slice_attrs);
		    nvlist_free(other_attrs);
		    return (-1);
		}

		other_end = (other_size + other_start) - 1;

		*error = nvlist_lookup_uint32(other_attrs, DM_INDEX,
			&snum);

		if (*error) {
		    nvlist_free(media_attrs);
		    nvlist_free(slice_attrs);
		    nvlist_free(other_attrs);
		    return (-1);
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
				char *str = dm_get_name(slice_list[i], error);
				if (*error != 0) {
					nvlist_free(media_attrs);
					nvlist_free(slice_attrs);
					nvlist_free(other_attrs);
					return (-1);
				}
				*overlaps_with = strdup(str);
				dm_free_name(str);
				nvlist_free(media_attrs);
				nvlist_free(slice_attrs);
				nvlist_free(other_attrs);
				return (1);
			}
		} else if (other_start >= start_block &&
			other_start <= end_block) {
			if ((snum == 2 && (other_size == media_size)) ||
				snum == in_snum) {
				continue;
			} else {
				char *str = dm_get_name(slice_list[i], error);
				if (*error != 0) {
					nvlist_free(media_attrs);
					nvlist_free(slice_attrs);
					nvlist_free(other_attrs);
					return (-1);
				}
				*overlaps_with = strdup(str);
				dm_free_name(str);
				nvlist_free(media_attrs);
				nvlist_free(slice_attrs);
				nvlist_free(other_attrs);
				return (1);
			}
		}
		nvlist_free(other_attrs);
	}
	nvlist_free(media_attrs);
	nvlist_free(slice_attrs);
	return (0);
}

/*
 * Check to see whether the given slice overlaps with any other slices.  Get the
 * associated slice information and pass on to is_overlapping().
 */
int
check_overlapping(const char *slicename, dm_descriptor_t slice)
{
	dm_descriptor_t *media;
	dm_descriptor_t *slices;
	int error;
	char *overlaps;
	int ret = 0;

	/*
	 * Get the list of slices be fetching the associated media, and then all
	 * associated slices.
	 */
	media = dm_get_associated_descriptors(slice, DM_MEDIA, &error);
	if (media == NULL || *media == NULL || error != 0)
		libdskmgt_error(error);

	slices = dm_get_associated_descriptors(*media, DM_SLICE, &error);
	if (slices == NULL || *slices == NULL || error != 0)
		libdskmgt_error(error);


	overlaps = NULL;
	if (is_overlapping(slice, *media, slices, &error, &overlaps)) {
		vdev_error(gettext("device '%s' overlaps with '%s'\n"),
		    slicename, overlaps);
		ret = -1;
	}

	if (overlaps != NULL)
		free(overlaps);
	dm_free_descriptors(slices);
	dm_free_descriptors(media);

	return (ret);
}

/*
 * Validate the given slice.  If 'diskname' is non-NULL, then this is a single
 * slice on a complete disk.  If 'force' is set, then the user specified '-f'
 * and we only want to report error for completely forbidden uses.
 */
int
check_slice(const char *slicename, dm_descriptor_t slice, int force,
    int overlap)
{
	nvlist_t *stats;
	int err;
	nvpair_t *nvwhat, *nvdesc;
	char *what, *desc, *name;
	int found = FALSE;
	int found_zfs = FALSE;
	int fd;

	if ((stats = dm_get_stats(slice, DM_SLICE_STAT_USE, &err)) == NULL)
		libdskmgt_error(err);

	/*
	 * Always check to see if this is used by an active ZFS pool.
	 */
	if ((fd = open(slicename, O_RDONLY)) > 0) {
		if (zpool_in_use(fd, &desc, &name)) {

			if (!force) {
				vdev_error(gettext("%s is part of %s pool "
				    "'%s'\n"), slicename, desc, name);
				found = found_zfs = TRUE;
			}

			free(desc);
			free(name);
		}

		(void) close(fd);
	}

	/*
	 * This slice is in use.  Print out a descriptive message describing who
	 * is using it.  The 'used_by' nvlist is formatted as:
	 *
	 * 	(used_by=what, used_name=desc, ...)
	 *
	 * Each 'used_by' must be accompanied by a 'used_name'.
	 */
	nvdesc = NULL;
	for (;;) {
		nvwhat = nvlist_next_nvpair(stats, nvdesc);
		nvdesc = nvlist_next_nvpair(stats, nvwhat);

		if (nvwhat == NULL || nvdesc == NULL)
			break;

		assert(strcmp(nvpair_name(nvwhat), DM_USED_BY) == 0);
		assert(strcmp(nvpair_name(nvdesc), DM_USED_NAME) == 0);

		verify(nvpair_value_string(nvwhat, &what) == 0);
		verify(nvpair_value_string(nvdesc, &desc) == 0);

		/*
		 * For currently mounted filesystems, filesystems in
		 * /etc/vfstab, or dedicated dump devices, we can never use
		 * them, even if '-f' is specified.  The rest of the errors
		 * indicate that a filesystem was detected on disk, which can be
		 * overridden with '-f'.
		 */
		if (strcmp(what, DM_USE_MOUNT) == 0 ||
		    strcmp(what, DM_USE_VFSTAB) == 0 ||
		    strcmp(what, DM_USE_DUMP) == 0) {
			found = TRUE;
			if (strcmp(what, DM_USE_MOUNT) == 0) {
				vdev_error(gettext("%s is "
				    "currently mounted on %s\n"),
				    slicename, desc);
			} else if (strcmp(what, DM_USE_VFSTAB) == 0) {
				vdev_error(gettext("%s is usually "
				    "mounted at %s in /etc/vfstab\n"),
				    slicename, desc);
			} else if (strcmp(what, DM_USE_DUMP) == 0) {
				vdev_error(gettext("%s is the "
				    "dedicated dump device\n"), slicename);
			}
		} else if (!force) {
			found = TRUE;
			if (strcmp(what, DM_USE_SVM) == 0) {
				vdev_error(gettext("%s is part of "
				    "SVM volume %s\n"), slicename, desc);
			} else if (strcmp(what, DM_USE_LU) == 0) {
				vdev_error(gettext("%s is in use "
				    "for live upgrade %s\n"), slicename, desc);
			} else if (strcmp(what, DM_USE_VXVM) == 0) {
				vdev_error(gettext("%s is part of "
				    "VxVM volume %s\n"), slicename, desc);
			} else if (strcmp(what, DM_USE_FS) == 0) {
				/*
				 * We should have already caught ZFS in-use
				 * filesystems above.  If the ZFS version is
				 * different, or there was some other critical
				 * failure, it's possible for fstyp to report it
				 * as in-use, but zpool_open_by_dev() to fail.
				 */
				if (strcmp(desc, MNTTYPE_ZFS) != 0)
					vdev_error(gettext("%s contains a %s "
					    "filesystem\n"), slicename, desc);
				else if (!found_zfs)
					vdev_error(gettext("%s is part of an "
					    "outdated or damaged ZFS "
					    "pool\n"), slicename);
			} else {
				vdev_error(gettext("is used by %s as %s\n"),
				    slicename, what, desc);
			}
		} else {
			found = FALSE;
		}
	}

	/*
	 * Perform any overlap checking if requested to do so.
	 */
	if (overlap && !force)
		found |= (check_overlapping(slicename, slice) != 0);

	return (found ? -1 : 0);
}

/*
 * Validate a whole disk.  Iterate over all slices on the disk and make sure
 * that none is in use by calling check_slice().
 */
/* ARGSUSED */
int
check_disk(const char *name, dm_descriptor_t disk, int force)
{
	dm_descriptor_t *drive, *media, *slice;
	int err = 0;
	int i;
	int ret;

	/*
	 * Get the drive associated with this disk.  This should never fail,
	 * because we already have an alias handle open for the device.
	 */
	if ((drive = dm_get_associated_descriptors(disk, DM_DRIVE,
	    &err)) == NULL || *drive == NULL)
		libdskmgt_error(err);

	if ((media = dm_get_associated_descriptors(*drive, DM_MEDIA,
	    &err)) == NULL)
		libdskmgt_error(err);

	dm_free_descriptors(drive);

	/*
	 * It is possible that the user has specified a removable media drive,
	 * and the media is not present.
	 */
	if (*media == NULL) {
		vdev_error(gettext("'%s' has no media in drive\n"), name);
		dm_free_descriptors(media);
		return (-1);
	}

	if ((slice = dm_get_associated_descriptors(*media, DM_SLICE,
	    &err)) == NULL)
		libdskmgt_error(err);

	dm_free_descriptors(media);

	ret = 0;

	/*
	 * Iterate over all slices and report any errors.  We don't care about
	 * overlapping slices because we are using the whole disk.
	 */
	for (i = 0; slice[i] != NULL; i++) {
		if (check_slice(dm_get_name(slice[i], &err), slice[i],
		    force, FALSE) != 0)
			ret = -1;
	}

	dm_free_descriptors(slice);
	return (ret);
}


/*
 * Validate a device.  Determines whether the device is a disk, slice, or
 * partition, and passes it off to an appropriate function.
 */
int
check_device(const char *path, int force)
{
	dm_descriptor_t desc;
	int err;
	char *dev, rpath[MAXPATHLEN];

	/*
	 * For whole disks, libdiskmgt does not include the leading dev path.
	 */
	dev = strrchr(path, '/');
	assert(dev != NULL);
	dev++;
	if ((desc = dm_get_descriptor_by_name(DM_ALIAS, dev, &err)) != NULL)
		return (check_disk(path, desc, force));

	/*
	 * If 'err' is not ENODEV, then we've had an unexpected error from
	 * libdiskmgt.  The only explanation is that we ran out of memory.
	 */
	if (err != ENODEV)
		libdskmgt_error(err);

	/*
	 * Determine if this is a slice.
	 */
	if ((desc = dm_get_descriptor_by_name(DM_SLICE, (char *)path, &err))
	    != NULL)
		return (check_slice(path, desc, force, TRUE));

	if (err != ENODEV)
		libdskmgt_error(err);

	/*
	 * Check for a partition.  libdiskmgt expects path of /dev/rdsk when
	 * dealing with partitions, so convert it.
	 */
	(void) snprintf(rpath, sizeof (rpath), "/dev/rdsk/%s", dev);
	if ((desc = dm_get_descriptor_by_name(DM_PARTITION, rpath, &err))
	    != NULL) {
		/* XXZFS perform checking on partitions */
		return (0);
	}

	if (err != ENODEV)
		libdskmgt_error(err);

	/*
	 * At this point, libdiskmgt failed to find the device as either a whole
	 * disk or a slice.  Ignore these errors, as we know that it at least a
	 * block device.  The user may have provided us with some unknown device
	 * that libdiskmgt doesn't know about.
	 */
	return (0);
}

/*
 * Check that a file is valid.  All we can do in this case is check that it's
 * not in use by another pool.
 */
int
check_file(const char *file, int force)
{
	char *desc, *name;
	int fd;
	int ret = 0;

	if ((fd = open(file, O_RDONLY)) < 0)
		return (0);

	if (zpool_in_use(fd, &desc, &name)) {
		if (strcmp(desc, gettext("active")) == 0 ||
		    !force) {
			vdev_error(gettext("%s is part of %s pool '%s'\n"),
			    file, desc, name);
			ret = -1;
		}

		free(desc);
		free(name);
	}

	(void) close(fd);
	return (ret);
}

static int
is_whole_disk(const char *arg, struct stat64 *statbuf)
{
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "%s%s", arg, BACKUP_SLICE);
	if (stat64(path, statbuf) == 0)
		return (TRUE);

	return (FALSE);
}

/*
 * Create a leaf vdev.  Determine if this is a file or a device.  If it's a
 * device, fill in the device id to make a complete nvlist.  Valid forms for a
 * leaf vdev are:
 *
 * 	/dev/dsk/xxx	Complete disk path
 * 	/xxx		Full path to file
 * 	xxx		Shorthand for /dev/dsk/xxx
 */
nvlist_t *
make_leaf_vdev(const char *arg)
{
	char path[MAXPATHLEN];
	struct stat64 statbuf;
	nvlist_t *vdev = NULL;
	char *type = NULL;
	int wholedisk = FALSE;

	/*
	 * Determine what type of vdev this is, and put the full path into
	 * 'path'.  We detect whether this is a device of file afterwards by
	 * checking the st_mode of the file.
	 */
	if (arg[0] == '/') {
		/*
		 * Complete device or file path.  Exact type is determined by
		 * examining the file descriptor afterwards.
		 */
		if (is_whole_disk(arg, &statbuf)) {
			wholedisk = TRUE;
		} else if (stat64(arg, &statbuf) != 0) {
			(void) fprintf(stderr,
			    gettext("cannot open '%s': %s\n"),
			    arg, strerror(errno));
			return (NULL);
		}

		(void) strlcpy(path, arg, sizeof (path));
	} else {
		/*
		 * This may be a short path for a device, or it could be total
		 * gibberish.  Check to see if it's a known device in
		 * /dev/dsk/.  As part of this check, see if we've been given a
		 * an entire disk (minus the slice number).
		 */
		(void) snprintf(path, sizeof (path), "%s/%s", DISK_ROOT,
		    arg);
		if (is_whole_disk(path, &statbuf)) {
			wholedisk = TRUE;
		} else if (stat64(path, &statbuf) != 0) {
			/*
			 * If we got ENOENT, then the user gave us
			 * gibberish, so try to direct them with a
			 * reasonable error message.  Otherwise,
			 * regurgitate strerror() since it's the best we
			 * can do.
			 */
			if (errno == ENOENT) {
				(void) fprintf(stderr,
				    gettext("cannot open '%s': no such "
				    "device in %s\n"), arg, DISK_ROOT);
				(void) fprintf(stderr,
				    gettext("must be a full path or "
				    "shorthand device name\n"));
				return (NULL);
			} else {
				(void) fprintf(stderr,
				    gettext("cannot open '%s': %s\n"),
				    path, strerror(errno));
				return (NULL);
			}
		}
	}

	/*
	 * Determine whether this is a device or a file.
	 */
	if (S_ISBLK(statbuf.st_mode)) {
		type = VDEV_TYPE_DISK;
	} else if (S_ISREG(statbuf.st_mode)) {
		type = VDEV_TYPE_FILE;
	} else {
		(void) fprintf(stderr, gettext("cannot use '%s': must be a "
		    "block device or regular file\n"), path);
		return (NULL);
	}

	/*
	 * Finally, we have the complete device or file, and we know that it is
	 * acceptable to use.  Construct the nvlist to describe this vdev.  All
	 * vdevs have a 'path' element, and devices also have a 'devid' element.
	 */
	verify(nvlist_alloc(&vdev, NV_UNIQUE_NAME, 0) == 0);
	verify(nvlist_add_string(vdev, ZPOOL_CONFIG_PATH, path) == 0);
	verify(nvlist_add_string(vdev, ZPOOL_CONFIG_TYPE, type) == 0);
	if (strcmp(type, VDEV_TYPE_DISK) == 0)
		verify(nvlist_add_uint64(vdev, ZPOOL_CONFIG_WHOLE_DISK,
		    (uint64_t)wholedisk) == 0);

	/*
	 * For a whole disk, defer getting its devid until after labeling it.
	 */
	if (S_ISBLK(statbuf.st_mode) && !wholedisk) {
		/*
		 * Get the devid for the device.
		 */
		int fd;
		ddi_devid_t devid;
		char *minor = NULL, *devid_str = NULL;

		if ((fd = open(path, O_RDONLY)) < 0) {
			(void) fprintf(stderr, gettext("cannot open '%s': "
			    "%s\n"), path, strerror(errno));
			nvlist_free(vdev);
			return (NULL);
		}

		if (devid_get(fd, &devid) == 0) {
			if (devid_get_minor_name(fd, &minor) == 0 &&
			    (devid_str = devid_str_encode(devid, minor)) !=
			    NULL) {
				verify(nvlist_add_string(vdev,
				    ZPOOL_CONFIG_DEVID, devid_str) == 0);
			}
			if (devid_str != NULL)
				devid_str_free(devid_str);
			if (minor != NULL)
				devid_str_free(minor);
			devid_free(devid);
		}

		(void) close(fd);
	}

	return (vdev);
}

/*
 * Go through and verify the replication level of the pool is consistent.
 * Performs the following checks:
 *
 * 	For the new spec, verifies that devices in mirrors and raidz are the
 * 	same size.
 *
 * 	If the current configuration already has inconsistent replication
 * 	levels, ignore any other potential problems in the new spec.
 *
 * 	Otherwise, make sure that the current spec (if there is one) and the new
 * 	spec have consistent replication levels.
 */
typedef struct replication_level {
	char	*type;
	int	level;
} replication_level_t;

/*
 * Given a list of toplevel vdevs, return the current replication level.  If
 * the config is inconsistent, then NULL is returned.  If 'fatal' is set, then
 * an error message will be displayed for each self-inconsistent vdev.
 */
replication_level_t *
get_replication(nvlist_t *nvroot, int fatal)
{
	nvlist_t **top;
	uint_t t, toplevels;
	nvlist_t **child;
	uint_t c, children;
	nvlist_t *nv;
	char *type;
	replication_level_t lastrep, rep, *ret;
	int dontreport;

	ret = safe_malloc(sizeof (replication_level_t));

	verify(nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
	    &top, &toplevels) == 0);

	lastrep.type = NULL;
	for (t = 0; t < toplevels; t++) {
		nv = top[t];

		verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) == 0);

		if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
		    &child, &children) != 0) {
			/*
			 * This is a 'file' or 'disk' vdev.
			 */
			rep.type = type;
			rep.level = 1;
		} else {
			uint64_t vdev_size;

			/*
			 * This is a mirror or RAID-Z vdev.  Go through and make
			 * sure the contents are all the same (files vs. disks),
			 * keeping track of the number of elements in the
			 * process.
			 *
			 * We also check that the size of each vdev (if it can
			 * be determined) is the same.
			 */
			rep.type = type;
			rep.level = 0;

			/*
			 * The 'dontreport' variable indicatest that we've
			 * already reported an error for this spec, so don't
			 * bother doing it again.
			 */
			type = NULL;
			dontreport = 0;
			vdev_size = -1ULL;
			for (c = 0; c < children; c++) {
				nvlist_t *cnv = child[c];
				char *path;
				struct stat64 statbuf;
				uint64_t size = -1ULL;
				char *childtype;
				int fd, err;

				rep.level++;

				verify(nvlist_lookup_string(cnv,
				    ZPOOL_CONFIG_TYPE, &childtype) == 0);
				verify(nvlist_lookup_string(cnv,
				    ZPOOL_CONFIG_PATH, &path) == 0);

				/*
				 * If we have a raidz/mirror that combines disks
				 * with files, report it as an error.
				 */
				if (!dontreport && type != NULL &&
				    strcmp(type, childtype) != 0) {
					if (ret != NULL)
						free(ret);
					ret = NULL;
					if (fatal)
						vdev_error(gettext(
						    "mismatched replication "
						    "level: %s contains both "
						    "files and devices\n"),
						    rep.type);
					else
						return (NULL);
					dontreport = TRUE;
				}

				/*
				 * According to stat(2), the value of 'st_size'
				 * is undefined for block devices and character
				 * devices.  But there is no effective way to
				 * determine the real size in userland.
				 *
				 * Instead, we'll take advantage of an
				 * implementation detail of spec_size().  If the
				 * device is currently open, then we (should)
				 * return a valid size.
				 *
				 * If we still don't get a valid size (indicated
				 * by a size of 0 or MAXOFFSET_T), then ignore
				 * this device altogether.
				 */
				if ((fd = open(path, O_RDONLY)) >= 0) {
					err = fstat64(fd, &statbuf);
					(void) close(fd);
				} else {
					err = stat64(path, &statbuf);
				}

				if (err != 0 ||
				    statbuf.st_size == 0 ||
				    statbuf.st_size == MAXOFFSET_T)
					continue;

				size = statbuf.st_size;

				/*
				 * Also check the size of each device.  If they
				 * differ, then report an error.
				 */
				if (!dontreport && vdev_size != -1ULL &&
				    size != vdev_size) {
					if (ret != NULL)
						free(ret);
					ret = NULL;
					if (fatal)
						vdev_error(gettext(
						    "%s contains devices of "
						    "different sizes\n"),
						    rep.type);
					else
						return (NULL);
					dontreport = TRUE;
				}

				type = childtype;
				vdev_size = size;
			}
		}

		/*
		 * At this point, we have the replication of the last toplevel
		 * vdev in 'rep'.  Compare it to 'lastrep' to see if its
		 * different.
		 */
		if (lastrep.type != NULL) {
			if (strcmp(lastrep.type, rep.type) != 0) {
				if (ret != NULL)
					free(ret);
				ret = NULL;
				if (fatal)
					vdev_error(gettext(
					    "mismatched replication "
					    "level: both %s and %s vdevs are "
					    "present\n"),
					    lastrep.type, rep.type);
				else
					return (NULL);
			} else if (lastrep.level != rep.level) {
				if (ret)
					free(ret);
				ret = NULL;
				if (fatal)
					vdev_error(gettext(
					    "mismatched replication "
					    "level: %d-way %s and %d-way %s "
					    "vdevs are present\n"),
					    lastrep.level, lastrep.type,
					    rep.level, rep.type);
				else
					return (NULL);
			}
		}
		lastrep = rep;
	}

	if (ret != NULL) {
		ret->type = rep.type;
		ret->level = rep.level;
	}

	return (ret);
}

/*
 * Check the replication level of the vdev spec against the current pool.  Calls
 * get_replication() to make sure the new spec is self-consistent.  If the pool
 * has a consistent replication level, then we ignore any errors.  Otherwise,
 * report any difference between the two.
 */
int
check_replication(nvlist_t *config, nvlist_t *newroot)
{
	replication_level_t *current = NULL, *new;
	int ret;

	/*
	 * If we have a current pool configuration, check to see if it's
	 * self-consistent.  If not, simply return success.
	 */
	if (config != NULL) {
		nvlist_t *nvroot;

		verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &nvroot) == 0);
		if ((current = get_replication(nvroot, FALSE)) == NULL)
			return (0);
	}

	/*
	 * Get the replication level of the new vdev spec, reporting any
	 * inconsistencies found.
	 */
	if ((new = get_replication(newroot, TRUE)) == NULL) {
		free(current);
		return (-1);
	}

	/*
	 * Check to see if the new vdev spec matches the replication level of
	 * the current pool.
	 */
	ret = 0;
	if (current != NULL) {
		if (strcmp(current->type, new->type) != 0 ||
		    current->level != new->level) {
			vdev_error(gettext(
			    "mismatched replication level: pool uses %d-way %s "
			    "and new vdev uses %d-way %s\n"),
			    current->level, current->type, new->level,
			    new->type);
			ret = -1;
		}
	}

	free(new);
	if (current != NULL)
		free(current);

	return (ret);
}

/*
 * Label an individual disk.  The name provided is the short name, stripped of
 * any leading /dev path.
 */
int
label_disk(char *name)
{
	char path[MAXPATHLEN];
	struct dk_gpt *vtoc;
	int fd;
	size_t resv = 16384;

	(void) snprintf(path, sizeof (path), "%s/%s%s", RDISK_ROOT, name,
	    BACKUP_SLICE);

	if ((fd = open(path, O_RDWR | O_NDELAY)) < 0) {
		/*
		 * This shouldn't happen.  We've long since verified that this
		 * is a valid device.
		 */
		(void) fprintf(stderr, gettext("cannot open '%s': %s\n"),
		    path, strerror(errno));
		return (-1);
	}


	if (efi_alloc_and_init(fd, 9, &vtoc) != 0) {
		/*
		 * The only way this can fail is if we run out of memory, or we
		 * were unable to read the disk geometry.
		 */
		if (errno == ENOMEM)
			no_memory();

		(void) fprintf(stderr, gettext("cannot label '%s': unable to "
		    "read disk geometry\n"), name);
		(void) close(fd);
		return (-1);
	}

	vtoc->efi_parts[0].p_start = vtoc->efi_first_u_lba;
	vtoc->efi_parts[0].p_size = vtoc->efi_last_u_lba + 1 -
	    vtoc->efi_first_u_lba - resv;

	/*
	 * Why we use V_USR: V_BACKUP confuses users, and is considered
	 * disposable by some EFI utilities (since EFI doesn't have a backup
	 * slice).  V_UNASSIGNED is supposed to be used only for zero size
	 * partitions, and efi_write() will fail if we use it.  V_ROOT, V_BOOT,
	 * etc. were all pretty specific.  V_USR is as close to reality as we
	 * can get, in the absence of V_OTHER.
	 */
	vtoc->efi_parts[0].p_tag = V_USR;
	(void) strcpy(vtoc->efi_parts[0].p_name, "zfs");

	vtoc->efi_parts[8].p_start = vtoc->efi_last_u_lba + 1 - resv;
	vtoc->efi_parts[8].p_size = resv;
	vtoc->efi_parts[8].p_tag = V_RESERVED;

	if (efi_write(fd, vtoc) != 0) {
		/*
		 * Currently, EFI labels are not supported for IDE disks, and it
		 * is likely that they will not be supported on other drives for
		 * some time.  Print out a helpful error message directing the
		 * user to manually label the disk and give a specific slice.
		 */
		(void) fprintf(stderr, gettext("cannot label '%s': failed to "
		    "write EFI label\n"), name);
		(void) fprintf(stderr, gettext("use fdisk(1M) to partition "
		    "the disk, and provide a specific slice\n"));
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);
	return (0);
}

/*
 * Go through and find any whole disks in the vdev specification, labelling them
 * as appropriate.  When constructing the vdev spec, we were unable to open this
 * device in order to provide a devid.  Now that we have labelled the disk and
 * know that slice 0 is valid, we can construct the devid now.
 *
 * If the disk was already labelled with an EFI label, we will have gotten the
 * devid already (because we were able to open the whole disk).  Otherwise, we
 * need to get the devid after we label the disk.
 */
int
make_disks(nvlist_t *nv)
{
	nvlist_t **child;
	uint_t c, children;
	char *type, *path, *diskname;
	char buf[MAXPATHLEN];
	uint64_t wholedisk;
	int fd;
	int ret;
	ddi_devid_t devid;
	char *minor = NULL, *devid_str = NULL;

	verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) == 0);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0) {

		if (strcmp(type, VDEV_TYPE_DISK) != 0)
			return (0);

		/*
		 * We have a disk device.  Get the path to the device
		 * and see if its a whole disk by appending the backup
		 * slice and stat()ing the device.
		 */
		verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) == 0);

		if (nvlist_lookup_uint64(nv, ZPOOL_CONFIG_WHOLE_DISK,
		    &wholedisk) != 0 || !wholedisk)
			return (0);

		diskname = strrchr(path, '/');
		assert(diskname != NULL);
		diskname++;
		if (label_disk(diskname) != 0)
			return (-1);

		/*
		 * Fill in the devid, now that we've labeled the disk.
		 */
		(void) snprintf(buf, sizeof (buf), "%ss0", path);
		if ((fd = open(buf, O_RDONLY)) < 0) {
			(void) fprintf(stderr,
			    gettext("cannot open '%s': %s\n"),
			    buf, strerror(errno));
			return (-1);
		}

		if (devid_get(fd, &devid) == 0) {
			if (devid_get_minor_name(fd, &minor) == 0 &&
			    (devid_str = devid_str_encode(devid, minor)) !=
			    NULL) {
				verify(nvlist_add_string(nv,
				    ZPOOL_CONFIG_DEVID, devid_str) == 0);
			}
			if (devid_str != NULL)
				devid_str_free(devid_str);
			if (minor != NULL)
				devid_str_free(minor);
			devid_free(devid);
		}

		/*
		 * Update the path to refer to the 's0' slice.  The presence of
		 * the 'whole_disk' field indicates to the CLI that we should
		 * chop off the slice number when displaying the device in
		 * future output.
		 */
		verify(nvlist_add_string(nv, ZPOOL_CONFIG_PATH, buf) == 0);

		(void) close(fd);

		return (0);
	}

	for (c = 0; c < children; c++)
		if ((ret = make_disks(child[c])) != 0)
			return (ret);

	return (0);
}

/*
 * Go through and find any devices that are in use.  We rely on libdiskmgt for
 * the majority of this task.
 */
int
check_in_use(nvlist_t *nv, int force)
{
	nvlist_t **child;
	uint_t c, children;
	char *type, *path;
	int ret;

	verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) == 0);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0) {

		verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) == 0);

		if (strcmp(type, VDEV_TYPE_DISK) == 0)
			ret = check_device(path, force);

		if (strcmp(type, VDEV_TYPE_FILE) == 0)
			ret = check_file(path, force);

		return (ret);
	}

	for (c = 0; c < children; c++)
		if ((ret = check_in_use(child[c], force)) != 0)
			return (ret);

	return (0);
}

/*
 * Construct a syntactically valid vdev specification,
 * and ensure that all devices and files exist and can be opened.
 * Note: we don't bother freeing anything in the error paths
 * because the program is just going to exit anyway.
 */
nvlist_t *
construct_spec(int argc, char **argv)
{
	nvlist_t *nvroot, *nv, **top;
	int t, toplevels;

	top = NULL;
	toplevels = 0;

	while (argc > 0) {
		nv = NULL;

		/*
		 * If it's a mirror or raidz, the subsequent arguments are
		 * its leaves -- until we encounter the next mirror or raidz.
		 */
		if (strcmp(argv[0], VDEV_TYPE_MIRROR) == 0 ||
		    strcmp(argv[0], VDEV_TYPE_RAIDZ) == 0) {

			char *type = argv[0];
			nvlist_t **child = NULL;
			int children = 0;
			int c;

			for (c = 1; c < argc; c++) {
				if (strcmp(argv[c], VDEV_TYPE_MIRROR) == 0 ||
				    strcmp(argv[c], VDEV_TYPE_RAIDZ) == 0)
					break;
				children++;
				child = realloc(child,
				    children * sizeof (nvlist_t *));
				if (child == NULL)
					no_memory();
				if ((nv = make_leaf_vdev(argv[c])) == NULL)
					return (NULL);
				child[children - 1] = nv;
			}

			argc -= c;
			argv += c;

			/*
			 * Mirrors and RAID-Z devices require at least
			 * two components.
			 */
			if (children < 2) {
				(void) fprintf(stderr,
				    gettext("invalid vdev specification: "
				    "%s requires at least 2 devices\n"), type);
				return (NULL);
			}

			verify(nvlist_alloc(&nv, NV_UNIQUE_NAME, 0) == 0);
			verify(nvlist_add_string(nv, ZPOOL_CONFIG_TYPE,
			    type) == 0);
			verify(nvlist_add_nvlist_array(nv,
			    ZPOOL_CONFIG_CHILDREN, child, children) == 0);

			for (c = 0; c < children; c++)
				nvlist_free(child[c]);
			free(child);
		} else {
			/*
			 * We have a device.  Pass off to make_leaf_vdev() to
			 * construct the appropriate nvlist describing the vdev.
			 */
			if ((nv = make_leaf_vdev(argv[0])) == NULL)
				return (NULL);
			argc--;
			argv++;
		}

		toplevels++;
		top = realloc(top, toplevels * sizeof (nvlist_t *));
		if (top == NULL)
			no_memory();
		top[toplevels - 1] = nv;
	}

	/*
	 * Finally, create nvroot and add all top-level vdevs to it.
	 */
	verify(nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) == 0);
	verify(nvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE,
	    VDEV_TYPE_ROOT) == 0);
	verify(nvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
	    top, toplevels) == 0);

	for (t = 0; t < toplevels; t++)
		nvlist_free(top[t]);
	free(top);

	return (nvroot);
}

/*
 * Get and validate the contents of the given vdev specification.  This ensures
 * that the nvlist returned is well-formed, that all the devices exist, and that
 * they are not currently in use by any other known consumer.  The 'poolconfig'
 * parameter is the current configuration of the pool when adding devices
 * existing pool, and is used to perform additional checks, such as changing the
 * replication level of the pool.  It can be 'NULL' to indicate that this is a
 * new pool.  The 'force' flag controls whether devices should be forcefully
 * added, even if they appear in use.
 */
nvlist_t *
make_root_vdev(nvlist_t *poolconfig, int force, int check_rep,
    int argc, char **argv)
{
	nvlist_t *newroot;

	is_force = force;

	/*
	 * Construct the vdev specification.  If this is successful, we know
	 * that we have a valid specification, and that all devices can be
	 * opened.
	 */
	if ((newroot = construct_spec(argc, argv)) == NULL)
		return (NULL);

	/*
	 * Validate each device to make sure that its not shared with another
	 * subsystem.  We do this even if 'force' is set, because there are some
	 * uses (such as a dedicated dump device) that even '-f' cannot
	 * override.
	 */
	if (check_in_use(newroot, force) != 0) {
		nvlist_free(newroot);
		return (NULL);
	}

	/*
	 * Check the replication level of the given vdevs and report any errors
	 * found.  We include the existing pool spec, if any, as we need to
	 * catch changes against the existing replication level.
	 */
	if (check_rep && check_replication(poolconfig, newroot) != 0) {
		nvlist_free(newroot);
		return (NULL);
	}

	/*
	 * Run through the vdev specification and label any whole disks found.
	 */
	if (make_disks(newroot) != 0) {
		nvlist_free(newroot);
		return (NULL);
	}

	return (newroot);
}
