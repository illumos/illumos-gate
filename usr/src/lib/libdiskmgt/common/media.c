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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <sys/dkio.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>

#include "libdiskmgt.h"
#include "disks_private.h"
#include "partition.h"

#define	IOCTLRETRIES		2
#define	IOCTLRETRYINTERVAL	1

static descriptor_t	**apply_filter(descriptor_t **media, int filter[],
			    int *errp);
static int		get_attrs(disk_t *dp, int fd, nvlist_t *attrs);
static int		get_rmm_name(disk_t *dp, char *mname, int size);
static int		get_media_type(uint_t media_type);
static int		desc_ok(descriptor_t *dp);

/*
 * This function gets the descriptors we are associated with.
 */
descriptor_t **
media_get_assoc_descriptors(descriptor_t *desc, dm_desc_type_t type,
    int *errp)
{
	if (!desc_ok(desc)) {
		*errp = ENODEV;
		return (NULL);
	}

	switch (type) {
	case DM_DRIVE:
		return (drive_get_assocs(desc, errp));
	case DM_PARTITION:
		return (partition_get_assocs(desc, errp));
	case DM_SLICE:
		return (slice_get_assocs(desc, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

/*
 * Get the media descriptors for the given drive/partition/slice.
 */
descriptor_t **
media_get_assocs(descriptor_t *dp, int *errp)
{
	descriptor_t	**media;
	char		mname[MAXPATHLEN];

	if (!media_read_name(dp->p.disk, mname, sizeof (mname))) {
		/*
		 * For drives, this means no media but slice/part.
		 * require media.
		 */
		if (dp->type == DM_DRIVE) {
			return (libdiskmgt_empty_desc_array(errp));
		} else {
			*errp = ENODEV;
			return (NULL);
		}
	}

	/* make the snapshot */
	media = (descriptor_t **)calloc(2, sizeof (descriptor_t *));
	if (media == NULL) {
		*errp = ENOMEM;
		return (NULL);
	}

	media[0] = cache_get_desc(DM_MEDIA, dp->p.disk, mname, NULL, errp);
	if (*errp != 0) {
		free(media);
		return (NULL);
	}
	media[1] = NULL;

	*errp = 0;
	return (media);
}

nvlist_t *
media_get_attributes(descriptor_t *dp, int *errp)
{
	nvlist_t	*attrs = NULL;
	int		fd;

	if (!desc_ok(dp)) {
		*errp = ENODEV;
		return (NULL);
	}

	if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
		*errp = ENOMEM;
		return (NULL);
	}

	fd = drive_open_disk(dp->p.disk, NULL, 0);

	if ((*errp = get_attrs(dp->p.disk, fd, attrs)) != 0) {
		nvlist_free(attrs);
		attrs = NULL;
	}

	if (fd >= 0) {
		(void) close(fd);
	}

	return (attrs);
}

descriptor_t *
media_get_descriptor_by_name(char *name, int *errp)
{
	descriptor_t	**media;
	int		i;
	descriptor_t	*medium = NULL;

	media = cache_get_descriptors(DM_MEDIA, errp);
	if (*errp != 0) {
		return (NULL);
	}

	for (i = 0; media[i]; i++) {
		if (libdiskmgt_str_eq(name, media[i]->name)) {
			medium = media[i];
		} else {
			/* clean up the unused descriptors */
			cache_free_descriptor(media[i]);
		}
	}
	free(media);

	if (medium == NULL) {
		*errp = ENODEV;
	}

	return (medium);
}

descriptor_t **
media_get_descriptors(int filter[], int *errp)
{
	descriptor_t	**media;

	media = cache_get_descriptors(DM_MEDIA, errp);
	if (*errp != 0) {
		return (NULL);
	}

	if (filter != NULL && filter[0] != DM_FILTER_END) {
		descriptor_t	**found;

		found = apply_filter(media, filter, errp);
		if (*errp != 0) {
			media = NULL;
		} else {
			media = found;
		}
	}

	return (media);
}

char *
media_get_name(descriptor_t *desc)
{
	return (desc->name);
}

/* ARGSUSED */
nvlist_t *
media_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	/* There are no stat types defined for media */
	*errp = EINVAL;
	return (NULL);
}

int
media_make_descriptors()
{
	int		error;
	disk_t		*dp;
	char		mname[MAXPATHLEN];

	dp = cache_get_disklist();
	while (dp != NULL) {
		if (media_read_name(dp, mname, sizeof (mname))) {
			cache_load_desc(DM_MEDIA, dp, mname, NULL, &error);
			if (error != 0) {
				return (error);
			}
		}

		dp = dp->next;
	}

	return (0);
}

/*
 * Read the media information.
 */
int
media_read_info(int fd, struct dk_minfo *minfo)
{
	int	status;
	int	tries = 0;

	minfo->dki_media_type = 0;

	/*
	 * This ioctl can fail if the media is not loaded or spun up.
	 * Retrying can sometimes succeed since the first ioctl will have
	 * started the media before the ioctl timed out so the media may be
	 * spun up on the subsequent attempt.
	 */
	while ((status = ioctl(fd, DKIOCGMEDIAINFO, minfo)) < 0) {
		tries++;
		if (tries >= IOCTLRETRIES) {
			break;
		}
		(void) sleep(IOCTLRETRYINTERVAL);
	}

	if (status < 0) {
		return (0);
	}

	return (1);
}

/* return 1 if there is media, 0 if not. */
int
media_read_name(disk_t *dp, char *mname, int size)
{
	mname[0] = 0;

	if (!dp->removable) {
		/* not removable, so media name is devid */
		if (dp->device_id != NULL) {
			(void) strlcpy(mname, dp->device_id, size);
		}
		return (1);
	}

	/* This is a removable media drive. */
	return (get_rmm_name(dp, mname, size));
}

static descriptor_t **
apply_filter(descriptor_t **media, int filter[], int *errp)
{
	descriptor_t	**found;
	int		i;
	int		cnt = 0;
	int		pos;

	/* count the number of media in the snapshot */
	for (i = 0; media[i]; i++) {
		cnt++;
	}

	found = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (found == NULL) {
		*errp = ENOMEM;
		cache_free_descriptors(media);
		return (NULL);
	}

	pos = 0;
	for (i = 0; media[i]; i++) {
		int	fd;
		struct	dk_minfo minfo;

		if ((fd = drive_open_disk(media[i]->p.disk, NULL, 0)) < 0) {
			continue;
		}

		if (media_read_info(fd, &minfo)) {
			int	mtype;
			int	j;
			int	match;

			mtype = get_media_type(minfo.dki_media_type);

			match = 0;
			for (j = 0; filter[j] != DM_FILTER_END; j++) {
				if (mtype == filter[j]) {
					found[pos++] = media[i];
					match = 1;
					break;
				}
			}

			if (!match) {
				cache_free_descriptor(media[i]);
			}
		}
		(void) close(fd);
	}
	found[pos] = NULL;
	free(media);

	*errp = 0;
	return (found);
}

/* return 1 if the media descriptor is still valid, 0 if not. */
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
			return (libdiskmgt_str_eq(dp->name, NULL));
		} else {
			return (libdiskmgt_str_eq(dp->name, mname));
		}
	}

	return (1);
}

static int
get_attrs(disk_t *dp, int fd, nvlist_t *attrs)
{
	struct	dk_minfo minfo;
	struct	dk_geom	geometry;

	if (fd < 0) {
		return (ENODEV);
	}

	bzero(&minfo, sizeof (struct dk_minfo));

	/* The first thing to do is read the media */
	if (!media_read_info(fd, &minfo)) {
		return (ENODEV);
	}

	if (partition_has_fdisk(dp, fd)) {
		if (nvlist_add_boolean(attrs, DM_FDISK) != 0) {
			return (ENOMEM);
		}
	}

	if (dp->removable) {
		if (nvlist_add_boolean(attrs, DM_REMOVABLE) != 0) {
			return (ENOMEM);
		}

		if (nvlist_add_boolean(attrs, DM_LOADED) != 0) {
			return (ENOMEM);
		}
	}

	if (nvlist_add_uint64(attrs, DM_SIZE, minfo.dki_capacity) != 0) {
		return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_BLOCKSIZE, minfo.dki_lbsize) != 0) {
		return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_MTYPE,
	    get_media_type(minfo.dki_media_type)) != 0) {
		return (ENOMEM);
	}

	/* only for disks < 1TB  and x86 */
#if defined(i386) || defined(__amd64)
	if (ioctl(fd, DKIOCG_PHYGEOM, &geometry) >= 0) {
#else
	/* sparc call */
	if (ioctl(fd, DKIOCGGEOM, &geometry) >= 0) {
#endif
		struct extvtoc	vtoc;

		if (nvlist_add_uint64(attrs, DM_START, 0) != 0) {
			return (ENOMEM);
		}
		if (nvlist_add_uint64(attrs, DM_NACCESSIBLE,
		    geometry.dkg_ncyl * geometry.dkg_nhead * geometry.dkg_nsect)
		    != 0) {
			return (ENOMEM);
		}
		if (nvlist_add_uint32(attrs, DM_NCYLINDERS, geometry.dkg_ncyl)
		    != 0) {
			return (ENOMEM);
		}
		if (nvlist_add_uint32(attrs, DM_NPHYSCYLINDERS,
		    geometry.dkg_pcyl) != 0) {
			return (ENOMEM);
		}
		if (nvlist_add_uint32(attrs, DM_NALTCYLINDERS,
		    geometry.dkg_acyl) != 0) {
			return (ENOMEM);
		}
		if (nvlist_add_uint32(attrs, DM_NHEADS,
		    geometry.dkg_nhead) != 0) {
			return (ENOMEM);
		}
		if (nvlist_add_uint32(attrs, DM_NSECTORS, geometry.dkg_nsect)
		    != 0) {
			return (ENOMEM);
		}
		if (nvlist_add_uint32(attrs, DM_NACTUALCYLINDERS,
		    geometry.dkg_ncyl) != 0) {
			return (ENOMEM);
		}

		if (read_extvtoc(fd, &vtoc) >= 0 && vtoc.v_volume[0] != 0) {
			char	label[LEN_DKL_VVOL + 1];

			(void) snprintf(label, sizeof (label), "%.*s",
			    LEN_DKL_VVOL, vtoc.v_volume);
			if (nvlist_add_string(attrs, DM_LABEL, label) != 0) {
				return (ENOMEM);
			}
		}

	} else {
		/* check for disks > 1TB for accessible size */
		struct dk_gpt	*efip;

		if (efi_alloc_and_read(fd, &efip) >= 0) {
			diskaddr_t	p8size = 0;

			if (nvlist_add_boolean(attrs, DM_EFI) != 0) {
				return (ENOMEM);
			}
			if (nvlist_add_uint64(attrs, DM_START,
			    efip->efi_first_u_lba) != 0) {
				return (ENOMEM);
			}
			/* partition 8 is reserved on EFI labels */
			if (efip->efi_nparts >= 9) {
				p8size = efip->efi_parts[8].p_size;
			}
			if (nvlist_add_uint64(attrs, DM_NACCESSIBLE,
			    (efip->efi_last_u_lba - p8size) -
			    efip->efi_first_u_lba) != 0) {
				efi_free(efip);
				return (ENOMEM);
			}
			efi_free(efip);
		}
	}
	return (0);
}

static int
get_media_type(uint_t media_type)
{
	switch (media_type) {
	case DK_UNKNOWN:
		return (DM_MT_UNKNOWN);
	case DK_MO_ERASABLE:
		return (DM_MT_MO_ERASABLE);
	case DK_MO_WRITEONCE:
		return (DM_MT_MO_WRITEONCE);
	case DK_AS_MO:
		return (DM_MT_AS_MO);
	case DK_CDROM:
		return (DM_MT_CDROM);
	case DK_CDR:
		return (DM_MT_CDR);
	case DK_CDRW:
		return (DM_MT_CDRW);
	case DK_DVDROM:
		return (DM_MT_DVDROM);
	case DK_DVDR:
		return (DM_MT_DVDR);
	case DK_DVDRAM:
		return (DM_MT_DVDRAM);
	case DK_FIXED_DISK:
		return (DM_MT_FIXED);
	case DK_FLOPPY:
		return (DM_MT_FLOPPY);
	case DK_ZIP:
		return (DM_MT_ZIP);
	case DK_JAZ:
		return (DM_MT_JAZ);
	default:
		return (DM_MT_UNKNOWN);
	}
}

/*
 * This function handles removable media.
 */
static int
get_rmm_name(disk_t *dp, char *mname, int size)
{
	int		loaded;
	int		fd;

	loaded = 0;

	if ((fd = drive_open_disk(dp, NULL, 0)) >= 0) {
		struct dk_minfo minfo;

		if ((loaded = media_read_info(fd, &minfo))) {
			struct extvtoc vtoc;

			if (read_extvtoc(fd, &vtoc) >= 0) {
				if (vtoc.v_volume[0] != '\0') {
					if (LEN_DKL_VVOL < size) {
						(void) strlcpy(mname,
						    vtoc.v_volume,
						    LEN_DKL_VVOL);
					} else {
						(void) strlcpy(mname,
						    vtoc.v_volume, size);
					}
				}
			}
		}

		(void) close(fd);
	}

	return (loaded);
}
