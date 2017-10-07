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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2017 Nexenta Systems, Inc.
 */

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/dkio.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/vtoc.h>
#include <unistd.h>
#include <devid.h>
#include <dirent.h>
#include <sys/dktp/fdisk.h>
#include <sys/efi_partition.h>

#include "libdiskmgt.h"
#include "disks_private.h"
#include "partition.h"
#ifndef VT_ENOTSUP
#define	VT_ENOTSUP	(-5)
#endif

#define	FMT_UNKNOWN	0
#define	FMT_VTOC	1
#define	FMT_EFI		2

typedef int (*detectorp)(char *, nvlist_t *, int *);

static detectorp detectors[] = {
	inuse_mnt,
	inuse_active_zpool,
	inuse_lu,
	inuse_dump,
	inuse_vxvm,
	inuse_exported_zpool,
	inuse_fs,  /* fs should always be last */
	NULL
};

static int	add_inuse(char *name, nvlist_t *attrs);
static int	desc_ok(descriptor_t *dp);
static void	dsk2rdsk(char *dsk, char *rdsk, int size);
static int	get_attrs(descriptor_t *dp, int fd,  nvlist_t *attrs);
static descriptor_t **get_fixed_assocs(descriptor_t *desc, int *errp);
static int	get_slice_num(slice_t *devp);
static int	match_fixed_name(disk_t *dp, char *name, int *errp);
static int	make_fixed_descriptors(disk_t *dp);

descriptor_t **
slice_get_assoc_descriptors(descriptor_t *desc, dm_desc_type_t type,
    int *errp)
{
	if (!desc_ok(desc)) {
	    *errp = ENODEV;
	    return (NULL);
	}

	switch (type) {
	case DM_MEDIA:
	    return (media_get_assocs(desc, errp));
	case DM_PARTITION:
	    return (partition_get_assocs(desc, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

/*
 * This is called by media/partition to get the slice descriptors for the given
 * media/partition descriptor.
 * For media, just get the slices, but for a partition, it must be a solaris
 * partition and if there are active partitions, it must be the active one.
 */
descriptor_t **
slice_get_assocs(descriptor_t *desc, int *errp)
{
	/* Just check the first drive name. */
	if (desc->p.disk->aliases == NULL) {
	    *errp = 0;
	    return (libdiskmgt_empty_desc_array(errp));
	}

	return (get_fixed_assocs(desc, errp));
}

nvlist_t *
slice_get_attributes(descriptor_t *dp, int *errp)
{
	nvlist_t	*attrs = NULL;
	int		fd;
	char		devpath[MAXPATHLEN];

	if (!desc_ok(dp)) {
	    *errp = ENODEV;
	    return (NULL);
	}

	if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	/* dp->name is /dev/dsk, need to convert back to /dev/rdsk */
	dsk2rdsk(dp->name, devpath, sizeof (devpath));
	fd = open(devpath, O_RDONLY|O_NDELAY);

	if ((*errp = get_attrs(dp, fd, attrs)) != 0) {
	    nvlist_free(attrs);
	    attrs = NULL;
	}

	if (fd >= 0) {
	    (void) close(fd);
	}

	return (attrs);
}

/*
 * Look for the slice by the slice devpath.
 */
descriptor_t *
slice_get_descriptor_by_name(char *name, int *errp)
{
	int		found = 0;
	disk_t		*dp;

	for (dp = cache_get_disklist(); dp != NULL; dp = dp->next) {
		found = match_fixed_name(dp, name, errp);

		if (found) {
			char	mname[MAXPATHLEN];

			if (*errp != 0) {
			    return (NULL);
			}

			mname[0] = 0;
			(void) media_read_name(dp, mname, sizeof (mname));

			return (cache_get_desc(DM_SLICE, dp, name, mname,
			    errp));
		}
	}

	*errp = ENODEV;
	return (NULL);
}

/* ARGSUSED */
descriptor_t **
slice_get_descriptors(int filter[], int *errp)
{
	return (cache_get_descriptors(DM_SLICE, errp));
}

char *
slice_get_name(descriptor_t *desc)
{
	return (desc->name);
}

nvlist_t *
slice_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	nvlist_t	*stats;

	if (stat_type != DM_SLICE_STAT_USE) {
	    *errp = EINVAL;
	    return (NULL);
	}

	*errp = 0;

	if (nvlist_alloc(&stats, NVATTRS_STAT, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	if ((*errp = add_inuse(dp->name, stats)) != 0) {
		nvlist_free(stats);
		return (NULL);
	}

	return (stats);
}

/*
 * A slice descriptor points to a disk, the name is the devpath and the
 * secondary name is the media name.
 */
int
slice_make_descriptors()
{
	disk_t		*dp;

	dp = cache_get_disklist();
	while (dp != NULL) {
	    int	error;

	    error = make_fixed_descriptors(dp);
	    if (error != 0) {
		return (error);
	    }

	    dp = dp->next;
	}

	return (0);
}

/* convert rdsk paths to dsk paths */
void
slice_rdsk2dsk(char *rdsk, char *dsk, int size)
{
	char	*strp;

	(void) strlcpy(dsk, rdsk, size);

	if ((strp = strstr(dsk, "/rdsk/")) == NULL) {
	    /* not rdsk, check for floppy */
	    strp = strstr(dsk, "/rdiskette");
	}

	if (strp != NULL) {
	    strp++;	/* move ptr to the r in rdsk or rdiskette */

	    /* move the succeeding chars over by one */
	    do {
		*strp = *(strp + 1);
		strp++;
	    } while (*strp);
	}
}

/*
 * Check if/how the slice is used.
 */
static int
add_inuse(char *name, nvlist_t *attrs)
{
	int	i;
	int	error;

	for (i = 0; detectors[i] != NULL; i ++) {
	    if (detectors[i](name, attrs, &error) || error != 0) {
		if (error != 0) {
		    return (error);
		}
		break;
	    }
	}

	return (0);
}

/* return 1 if the slice descriptor is still valid, 0 if not. */
static int
desc_ok(descriptor_t *dp)
{
	/* First verify the media name for removable media */
	if (dp->p.disk->removable) {
	    char	mname[MAXPATHLEN];

	    if (!media_read_name(dp->p.disk, mname, sizeof (mname))) {
		return (0);
	    }

	    if (mname[0] == 0) {
		return (libdiskmgt_str_eq(dp->secondary_name, NULL));
	    } else {
		return (libdiskmgt_str_eq(dp->secondary_name, mname));
	    }
	}

	/*
	 * We could verify the slice is still there, but other code down the
	 * line already does these checks (e.g. see get_attrs).
	 */

	return (1);
}

/* convert dsk paths to rdsk paths */
static void
dsk2rdsk(char *dsk, char *rdsk, int size)
{
	char	*slashp;
	size_t	len;

	(void) strlcpy(rdsk, dsk, size);

	/* make sure there is enough room to add the r to dsk */
	len = strlen(dsk);
	if (len + 2 > size) {
	    return;
	}

	if ((slashp = strstr(rdsk, "/dsk/")) == NULL) {
	    /* not dsk, check for floppy */
	    slashp = strstr(rdsk, "/diskette");
	}

	if (slashp != NULL) {
	    char	*endp;

	    endp = rdsk + len;	/* point to terminating 0 */
	    /* move the succeeding chars over by one */
	    do {
		*(endp + 1) = *endp;
		endp--;
	    } while (endp != slashp);

	    *(endp + 1) = 'r';
	}
}

static int
get_attrs(descriptor_t *dp, int fd,  nvlist_t *attrs)
{
	struct dk_minfo	minfo;
	int		status;
	int		data_format = FMT_UNKNOWN;
	int		snum = -1;
	int		error;
	struct extvtoc	vtoc;
	struct dk_gpt	*efip;
	struct dk_cinfo	dkinfo;
	int		cooked_fd;
	struct stat	buf;

	if (fd < 0) {
	    return (ENODEV);
	}

	/* First make sure media is inserted and spun up. */
	if (!media_read_info(fd, &minfo)) {
	    return (ENODEV);
	}

	if ((status = read_extvtoc(fd, &vtoc)) >= 0) {
	    data_format = FMT_VTOC;
	} else if (status == VT_ENOTSUP && efi_alloc_and_read(fd, &efip) >= 0) {
	    data_format = FMT_EFI;
	    if (nvlist_add_boolean(attrs, DM_EFI) != 0) {
		efi_free(efip);
		return (ENOMEM);
	    }
	}

	if (data_format == FMT_UNKNOWN) {
	    return (ENODEV);
	}

	if (ioctl(fd, DKIOCINFO, &dkinfo) >= 0) {
	    snum = dkinfo.dki_partition;
	}

	/* check the slice */
	if (data_format == FMT_VTOC) {
	    if (snum < 0 || snum >= vtoc.v_nparts ||
		vtoc.v_part[snum].p_size == 0) {
		return (ENODEV);
	    }
	} else { /* data_format == FMT_EFI */
	    if (snum < 0 || snum >= efip->efi_nparts ||
		efip->efi_parts[snum].p_size == 0) {
		efi_free(efip);
		return (ENODEV);
	    }
	}

	/* the slice exists */

	if (nvlist_add_uint32(attrs, DM_INDEX, snum) != 0) {
	    if (data_format == FMT_EFI) {
		efi_free(efip);
	    }
	    return (ENOMEM);
	}

	if (data_format == FMT_VTOC) {
	    if (nvlist_add_uint64(attrs, DM_START, vtoc.v_part[snum].p_start)
		!= 0) {
		return (ENOMEM);
	    }

	    if (nvlist_add_uint64(attrs, DM_SIZE, vtoc.v_part[snum].p_size)
		!= 0) {
		return (ENOMEM);
	    }

	    if (nvlist_add_uint32(attrs, DM_TAG, vtoc.v_part[snum].p_tag)
		!= 0) {
		return (ENOMEM);
	    }

	    if (nvlist_add_uint32(attrs, DM_FLAG, vtoc.v_part[snum].p_flag)
		!= 0) {
		return (ENOMEM);
	    }

	} else { /* data_format == FMT_EFI */
	    if (nvlist_add_uint64(attrs, DM_START,
		efip->efi_parts[snum].p_start) != 0) {
		efi_free(efip);
		return (ENOMEM);
	    }

	    if (nvlist_add_uint64(attrs, DM_SIZE, efip->efi_parts[snum].p_size)
		!= 0) {
		efi_free(efip);
		return (ENOMEM);
	    }

	    if (efip->efi_parts[snum].p_name[0] != 0) {
		char	label[EFI_PART_NAME_LEN + 1];

		(void) snprintf(label, sizeof (label), "%.*s",
		    EFI_PART_NAME_LEN, efip->efi_parts[snum].p_name);
		if (nvlist_add_string(attrs, DM_EFI_NAME, label) != 0) {
		    efi_free(efip);
		    return (ENOMEM);
		}
	    }
	}

	if (data_format == FMT_EFI) {
	    efi_free(efip);
	}

	if (inuse_mnt(dp->name, attrs, &error)) {
	    if (error != 0)
		return (error);
	}

	if (fstat(fd, &buf) != -1) {
	    if (nvlist_add_uint64(attrs, DM_DEVT, buf.st_rdev) != 0) {
		return (ENOMEM);
	    }
	}

	/*
	 * We need to open the cooked slice (not the raw one) to get the
	 * correct devid.
	 */
	cooked_fd = open(dp->name, O_RDONLY|O_NDELAY);

	if (cooked_fd >= 0) {
	    int		no_mem = 0;
	    ddi_devid_t	devid;

	    if (devid_get(cooked_fd, &devid) == 0) {
		char	*minor;

		if (devid_get_minor_name(cooked_fd, &minor) == 0) {
		    char	*devidstr;

		    if ((devidstr = devid_str_encode(devid, minor)) != 0) {

			if (nvlist_add_string(attrs, DM_DEVICEID, devidstr)
			    != 0) {
			    no_mem = 1;
			}

			devid_str_free(devidstr);
		    }
		    devid_str_free(minor);
		}
		devid_free(devid);
	    }
	    (void) close(cooked_fd);

	    if (no_mem) {
		return (ENOMEM);
	    }
	}

	return (0);
}

static descriptor_t **
get_fixed_assocs(descriptor_t *desc, int *errp)
{
	int		fd;
	int		status;
	int		data_format = FMT_UNKNOWN;
	int		cnt;
	struct extvtoc	vtoc;
	struct dk_gpt	*efip;
	int		pos;
	char		*media_name = NULL;
	slice_t		*devp;
	descriptor_t	**slices;

	if ((fd = drive_open_disk(desc->p.disk, NULL, 0)) < 0) {
	    *errp = ENODEV;
	    return (NULL);
	}

	if ((status = read_extvtoc(fd, &vtoc)) >= 0) {
	    data_format = FMT_VTOC;
	} else if (status == VT_ENOTSUP && efi_alloc_and_read(fd, &efip) >= 0) {
	    data_format = FMT_EFI;
	} else {
	    (void) close(fd);
	    *errp = 0;
	    return (libdiskmgt_empty_desc_array(errp));
	}
	(void) close(fd);

	/* count the number of slices */
	for (cnt = 0, devp = desc->p.disk->aliases->devpaths; devp != NULL;
	    devp = devp->next, cnt++);

	/* allocate the array for the descriptors */
	slices = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (slices == NULL) {
	    if (data_format == FMT_EFI) {
		efi_free(efip);
	    }
	    *errp = ENOMEM;
	    return (NULL);
	}

	/* get the media name from the descriptor */
	if (desc->type == DM_MEDIA) {
	    media_name = desc->name;
	} else {
	    /* must be a DM_PARTITION */
	    media_name = desc->secondary_name;
	}

	pos = 0;
	for (devp = desc->p.disk->aliases->devpaths; devp != NULL;
	    devp = devp->next) {

	    int		slice_num;
	    char	devpath[MAXPATHLEN];

	    slice_num = get_slice_num(devp);
	    /* can't get slicenum, so no need to keep trying the drive */
	    if (slice_num == -1) {
		break;
	    }

	    if (data_format == FMT_VTOC) {
		if (slice_num >= vtoc.v_nparts ||
		    vtoc.v_part[slice_num].p_size == 0) {
		    continue;
		}
	    } else { /* data_format == FMT_EFI */
		if (slice_num >= efip->efi_nparts ||
		    efip->efi_parts[slice_num].p_size == 0) {
		    continue;
		}
	    }

	    slice_rdsk2dsk(devp->devpath, devpath, sizeof (devpath));
	    slices[pos] = cache_get_desc(DM_SLICE, desc->p.disk, devpath,
		media_name, errp);
	    if (*errp != 0) {
		cache_free_descriptors(slices);
		if (data_format == FMT_EFI) {
		    efi_free(efip);
		}
		return (NULL);
	    }
	    pos++;
	}
	slices[pos] = NULL;

	if (data_format == FMT_EFI) {
	    efi_free(efip);
	}

	*errp = 0;
	return (slices);
}

static int
get_slice_num(slice_t *devp)
{
	/* check if we already determined the devpath slice number */
	if (devp->slice_num == -1) {
	    int		fd;

	    if ((fd = open(devp->devpath, O_RDONLY|O_NDELAY)) >= 0) {
		struct dk_cinfo	dkinfo;
		if (ioctl(fd, DKIOCINFO, &dkinfo) >= 0) {
		    devp->slice_num = dkinfo.dki_partition;
		}
		(void) close(fd);
	    }
	}

	return (devp->slice_num);
}

static int
make_fixed_descriptors(disk_t *dp)
{
	int		error = 0;
	alias_t		*ap;
	slice_t		*devp;
	char		mname[MAXPATHLEN];
	int		data_format = FMT_UNKNOWN;
	struct extvtoc	vtoc;
	struct dk_gpt	*efip;

	/* Just check the first drive name. */
	if ((ap = dp->aliases) == NULL) {
	    return (0);
	}

	mname[0] = 0;
	(void) media_read_name(dp, mname, sizeof (mname));

	for (devp = ap->devpaths; devp != NULL; devp = devp->next) {
	    int		slice_num;
	    char	devpath[MAXPATHLEN];

	    slice_num = get_slice_num(devp);
	    /* can't get slicenum, so no need to keep trying the drive */
	    if (slice_num == -1) {
		break;
	    }

	    if (data_format == FMT_UNKNOWN) {
		int	fd;
		int	status;

		if ((fd = drive_open_disk(dp, NULL, 0)) >= 0) {
		    if ((status = read_extvtoc(fd, &vtoc)) >= 0) {
			data_format = FMT_VTOC;
		    } else if (status == VT_ENOTSUP &&
			efi_alloc_and_read(fd, &efip) >= 0) {
			data_format = FMT_EFI;
		    }
		    (void) close(fd);
		}
	    }

	    /* can't get slice data, so no need to keep trying the drive */
	    if (data_format == FMT_UNKNOWN) {
		break;
	    }

	    if (data_format == FMT_VTOC) {
		if (slice_num >= vtoc.v_nparts ||
		    vtoc.v_part[slice_num].p_size == 0) {
		    continue;
		}
	    } else { /* data_format == FMT_EFI */
		if (slice_num >= efip->efi_nparts ||
		    efip->efi_parts[slice_num].p_size == 0) {
		    continue;
		}
	    }

	    slice_rdsk2dsk(devp->devpath, devpath, sizeof (devpath));
	    cache_load_desc(DM_SLICE, dp, devpath, mname, &error);
	    if (error != 0) {
		break;
	    }
	}

	if (data_format == FMT_EFI) {
	    efi_free(efip);
	}

	return (error);
}

/*
 * Just look for the name on the devpaths we have cached. Return 1 if we
 * find the name and the size of that slice is non-zero.
 */
static int
match_fixed_name(disk_t *diskp, char *name, int *errp)
{
	slice_t		*dp = NULL;
	alias_t		*ap;
	int		slice_num;
	int		fd;
	int		status;
	int		data_format = FMT_UNKNOWN;
	struct extvtoc	vtoc;
	struct dk_gpt	*efip;

	ap = diskp->aliases;
	while (ap != NULL) {
	    slice_t	*devp;

	    devp = ap->devpaths;
	    while (devp != NULL) {
		char	path[MAXPATHLEN];

		slice_rdsk2dsk(devp->devpath, path, sizeof (path));
		if (libdiskmgt_str_eq(path, name)) {
		    /* found it */
		    dp = devp;
		    break;
		}

		devp = devp->next;
	    }

	    if (dp != NULL) {
		break;
	    }

	    ap = ap->next;
	}

	if (dp == NULL) {
	    *errp = 0;
	    return (0);
	}

	/*
	 * If we found a match on the name we now have to check that this
	 * slice really exists (non-0 size).
	 */

	slice_num = get_slice_num(dp);
	/* can't get slicenum, so no slice */
	if (slice_num == -1) {
	    *errp = ENODEV;
	    return (1);
	}

	if ((fd = drive_open_disk(diskp, NULL, 0)) < 0) {
	    *errp = ENODEV;
	    return (1);
	}

	if ((status = read_extvtoc(fd, &vtoc)) >= 0) {
	    data_format = FMT_VTOC;
	} else if (status == VT_ENOTSUP && efi_alloc_and_read(fd, &efip) >= 0) {
	    data_format = FMT_EFI;
	} else {
	    (void) close(fd);
	    *errp = ENODEV;
	    return (1);
	}
	(void) close(fd);

	if (data_format == FMT_VTOC) {
	    if (slice_num < vtoc.v_nparts &&
		vtoc.v_part[slice_num].p_size > 0) {
		*errp = 0;
		return (1);
	    }
	} else { /* data_format == FMT_EFI */
	    if (slice_num < efip->efi_nparts &&
		efip->efi_parts[slice_num].p_size > 0) {
		efi_free(efip);
		*errp = 0;
		return (1);
	    }
	    efi_free(efip);
	}

	*errp = ENODEV;
	return (1);
}
