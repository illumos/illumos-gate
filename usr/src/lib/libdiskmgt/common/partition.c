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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/dkio.h>

#include "libdiskmgt.h"
#include "disks_private.h"
#include "partition.h"

#ifdef sparc
#define	les(val)	((((val)&0xFF)<<8)|(((val)>>8)&0xFF))
#define	lel(val)	(((unsigned)(les((val)&0x0000FFFF))<<16) | \
			    (les((unsigned)((val)&0xffff0000)>>16)))
#else
#define	les(val)	(val)
#define	lel(val)	(val)
#endif

#define	ISIZE		FD_NUMPART * sizeof (struct ipart)

static int	desc_ok(descriptor_t *dp);
static int	get_attrs(descriptor_t *dp, struct ipart *iparts,
		    nvlist_t *attrs);
static int	get_parts(disk_t *disk, struct ipart *iparts, char *opath,
		    int opath_len);
static int	open_disk(disk_t *diskp, char *opath, int len);
static int	has_slices(descriptor_t *desc, int *errp);

descriptor_t **
partition_get_assoc_descriptors(descriptor_t *desc, dm_desc_type_t type,
    int *errp)
{
	if (!desc_ok(desc)) {
	    *errp = ENODEV;
	    return (NULL);
	}

	switch (type) {
	case DM_MEDIA:
	    return (media_get_assocs(desc, errp));
	case DM_SLICE:
	    if (!has_slices(desc, errp)) {
		if (*errp != 0) {
		    return (NULL);
		}
		return (libdiskmgt_empty_desc_array(errp));
	    }
	    return (slice_get_assocs(desc, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

/*
 * This is called by media/slice to get the associated partitions.
 * For a media desc. we just get all the partitions, but for a slice desc.
 * we just get the active solaris partition.
 */
descriptor_t **
partition_get_assocs(descriptor_t *desc, int *errp)
{
	descriptor_t	**partitions;
	int		pos;
	int		i;
	struct ipart	iparts[FD_NUMPART];
	char		pname[MAXPATHLEN];
	int		conv_flag = 0;

	if (get_parts(desc->p.disk, iparts, pname, sizeof (pname)) != 0) {
	    return (libdiskmgt_empty_desc_array(errp));
	}

	/* allocate the array for the descriptors */
	partitions = (descriptor_t **)calloc(FD_NUMPART + 1,
	    sizeof (descriptor_t *));
	if (partitions == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

#ifdef i386
	{
	    /* convert part. name (e.g. c0d0p0) */
	    int	len;

	    len = strlen(pname);
	    if (len > 1 && *(pname + (len - 2)) == 'p') {
		conv_flag = 1;
		*(pname + (len - 1)) = 0;
	    }
	}
#endif

	/*
	 * If this is a slice desc. we need the first active solaris partition
	 * and if there isn't one then we need the first solaris partition.
	 */
	if (desc->type == DM_SLICE) {
	    for (i = 0; i < FD_NUMPART; i++) {
		if (iparts[i].bootid == ACTIVE &&
		    (iparts[i].systid == SUNIXOS ||
		    iparts[i].systid == SUNIXOS2)) {
			break;
		}
	    }

	    /* no active solaris part., try to get the first solaris part. */
	    if (i >= FD_NUMPART) {
		for (i = 0; i < FD_NUMPART; i++) {
		    if (iparts[i].systid == SUNIXOS ||
			iparts[i].systid == SUNIXOS2) {
			    break;
		    }
		}
	    }

	    if (i < FD_NUMPART) {
		/* we found a solaris partition to use */
		char	part_name[MAXPATHLEN];

		if (conv_flag) {
		    /* convert part. name (e.g. c0d0p0) */
		    (void) snprintf(part_name, sizeof (part_name), "%s%d",
			pname, i);
		} else {
		    (void) snprintf(part_name, sizeof (part_name), "%d", i);
		}

		/* the media name comes from the slice desc. */
		partitions[0] = cache_get_desc(DM_PARTITION, desc->p.disk,
		    part_name, desc->secondary_name, errp);
		if (*errp != 0) {
		    cache_free_descriptors(partitions);
		    return (NULL);
		}
		partitions[1] = NULL;

		return (partitions);

	    }

	    return (libdiskmgt_empty_desc_array(errp));
	}

	/* Must be for media, so get all the parts. */

	pos = 0;
	for (i = 0; i < FD_NUMPART; i++) {
	    if (iparts[i].systid != 0) {
		char	part_name[MAXPATHLEN];

		if (conv_flag) {
		    /* convert part. name (e.g. c0d0p0) */
		    (void) snprintf(part_name, sizeof (part_name), "%s%d",
			pname, i);
		} else {
		    (void) snprintf(part_name, sizeof (part_name), "%d", i);
		}

		/* the media name comes from the media desc. */
		partitions[pos] = cache_get_desc(DM_PARTITION, desc->p.disk,
		    part_name, desc->name, errp);
		if (*errp != 0) {
		    cache_free_descriptors(partitions);
		    return (NULL);
		}

		pos++;
	    }
	}
	partitions[pos] = NULL;

	*errp = 0;
	return (partitions);
}

nvlist_t *
partition_get_attributes(descriptor_t *dp, int *errp)
{
	nvlist_t	*attrs = NULL;
	struct ipart	iparts[FD_NUMPART];

	if (!desc_ok(dp)) {
	    *errp = ENODEV;
	    return (NULL);
	}

	if ((*errp = get_parts(dp->p.disk, iparts, NULL, 0)) != 0) {
	    return (NULL);
	}

	if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	if ((*errp = get_attrs(dp, iparts, attrs)) != 0) {
	    nvlist_free(attrs);
	    attrs = NULL;
	}

	return (attrs);
}

/*
 * Look for the partition by the partition number (which is not too useful).
 */
descriptor_t *
partition_get_descriptor_by_name(char *name, int *errp)
{
	descriptor_t	**partitions;
	int		i;
	descriptor_t	*partition = NULL;

	partitions = cache_get_descriptors(DM_PARTITION, errp);
	if (*errp != 0) {
	    return (NULL);
	}

	for (i = 0; partitions[i]; i++) {
	    if (libdiskmgt_str_eq(name, partitions[i]->name)) {
		partition = partitions[i];
	    } else {
		/* clean up the unused descriptors */
		cache_free_descriptor(partitions[i]);
	    }
	}
	free(partitions);

	if (partition == NULL) {
	    *errp = ENODEV;
	}

	return (partition);
}

/* ARGSUSED */
descriptor_t **
partition_get_descriptors(int filter[], int *errp)
{
	return (cache_get_descriptors(DM_PARTITION, errp));
}

char *
partition_get_name(descriptor_t *desc)
{
	return (desc->name);
}

/* ARGSUSED */
nvlist_t *
partition_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	/* There are no stat types defined for partitions */
	*errp = EINVAL;
	return (NULL);
}

/* ARGSUSED */
int
partition_has_fdisk(disk_t *dp, int fd)
{
	char		bootsect[512 * 3]; /* 3 sectors to be safe */

#ifdef sparc
	if (dp->drv_type == DM_DT_FIXED) {
	    /* on sparc, only removable media can have fdisk parts. */
	    return (0);
	}
#endif

	/*
	 * We assume the caller already made sure media was inserted and
	 * spun up.
	 */

	if ((ioctl(fd, DKIOCGMBOOT, bootsect) < 0) && (errno != ENOTTY)) {
	    return (0);
	}

	return (1);
}

/*
 * A partition descriptor points to a disk, the name is the partition number
 * and the secondary name is the media name.
 */
int
partition_make_descriptors()
{
	int		error;
	disk_t		*dp;

	dp = cache_get_disklist();
	while (dp != NULL) {
	    struct ipart	iparts[FD_NUMPART];
	    char		pname[MAXPATHLEN];

	    if (get_parts(dp, iparts, pname, sizeof (pname)) == 0) {
		int	i;
		char	mname[MAXPATHLEN];
		int	conv_flag = 0;

#ifdef i386
		/* convert part. name (e.g. c0d0p0) */
		int	len;

		len = strlen(pname);
		if (len > 1 && *(pname + (len - 2)) == 'p') {
		    conv_flag = 1;
		    *(pname + (len - 1)) = 0;
		}
#endif

		mname[0] = 0;
		(void) media_read_name(dp, mname, sizeof (mname));

		for (i = 0; i < FD_NUMPART; i++) {
		    if (iparts[i].systid != 0) {
			char	part_name[MAXPATHLEN];

			if (conv_flag) {
			    /* convert part. name (e.g. c0d0p0) */
			    (void) snprintf(part_name, sizeof (part_name),
				"%s%d", pname, i);
			} else {
			    (void) snprintf(part_name, sizeof (part_name),
				"%d", i);
			}

			cache_load_desc(DM_PARTITION, dp, part_name, mname,
			    &error);
			if (error != 0) {
			    return (error);
			}
		    }
		}
	    }
	    dp = dp->next;
	}

	return (0);
}

static int
get_attrs(descriptor_t *dp, struct ipart *iparts, nvlist_t *attrs)
{
	char		*p;
	int		part_num;

	/*
	 * We already made sure the media was loaded and ready in the
	 * get_parts call within partition_get_attributes.
	 */

	p = strrchr(dp->name, 'p');
	if (p == NULL) {
	    p = dp->name;
	} else {
	    p++;
	}
	part_num = atoi(p);
	if (part_num >= FD_NUMPART || iparts[part_num].systid == 0) {
	    return (ENODEV);
	}

	/* we found the partition */

	if (nvlist_add_uint32(attrs, DM_BOOTID,
	    (unsigned int)iparts[part_num].bootid) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_PTYPE,
	    (unsigned int)iparts[part_num].systid) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_BHEAD,
	    (unsigned int)iparts[part_num].beghead) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_BSECT,
	    (unsigned int)((iparts[part_num].begsect) & 0x3f)) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_BCYL, (unsigned int)
	    ((iparts[part_num].begcyl & 0xff) |
	    ((iparts[part_num].begsect & 0xc0) << 2))) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_EHEAD,
	    (unsigned int)iparts[part_num].endhead) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_ESECT,
	    (unsigned int)((iparts[part_num].endsect) & 0x3f)) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_ECYL, (unsigned int)
	    ((iparts[part_num].endcyl & 0xff) |
	    ((iparts[part_num].endsect & 0xc0) << 2))) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_RELSECT,
	    (unsigned int)iparts[part_num].relsect) != 0) {
	    return (ENOMEM);
	}

	if (nvlist_add_uint32(attrs, DM_NSECTORS,
	    (unsigned int)iparts[part_num].numsect) != 0) {
	    return (ENOMEM);
	}

	return (0);
}

static int
get_parts(disk_t *disk, struct ipart *iparts, char *opath, int opath_len)
{
	int		fd;
	struct dk_minfo	minfo;
	struct mboot	bootblk;
	char		bootsect[512];
	int		i;

	/* Can't use drive_open_disk since we need the partition dev name. */
	if ((fd = open_disk(disk, opath, opath_len)) < 0) {
	    return (ENODEV);
	}

	/* First make sure media is inserted and spun up. */
	if (!media_read_info(fd, &minfo)) {
#ifdef i386
	    /* XXX Work around bug 4725434 */
	    if (disk->removable) {
#endif
	    (void) close(fd);
	    return (ENODEV);
#ifdef i386
	    }
#endif
	}

	if (!partition_has_fdisk(disk, fd)) {
	    (void) close(fd);
	    return (ENOTTY);
	}

	if (lseek(fd, 0, 0) == -1) {
	    (void) close(fd);
	    return (ENODEV);
	}

	if (read(fd, bootsect, 512) != 512) {
	    (void) close(fd);
	    return (ENODEV);
	}
	(void) close(fd);

	(void) memcpy(&bootblk, bootsect, sizeof (bootblk));

	if (les(bootblk.signature) != MBB_MAGIC)  {
	    return (ENOTTY);
	}

	(void) memcpy(iparts, bootblk.parts, ISIZE);

	for (i = 0; i < FD_NUMPART; i++) {
	    if (iparts[i].systid != 0) {
		iparts[i].relsect = lel(iparts[i].relsect);
		iparts[i].numsect = lel(iparts[i].numsect);
	    }
	}

	return (0);
}
/* return 1 if the partition descriptor is still valid, 0 if not. */
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
	 * We could verify the partition is still there but this is kind of
	 * expensive and other code down the line will do that (e.g. see
	 * get_attrs).
	 */

	return (1);
}

/*
 * Return 1 if partition has slices, 0 if not.
 */
static int
has_slices(descriptor_t *desc, int *errp)
{
	int		pnum;
	int		i;
	char		*p;
	struct ipart	iparts[FD_NUMPART];

	if (get_parts(desc->p.disk, iparts, NULL, 0) != 0) {
	    *errp = ENODEV;
	    return (0);
	}

	p = strrchr(desc->name, 'p');
	if (p == NULL) {
	    p = desc->name;
	} else {
	    p++;
	}
	pnum = atoi(p);

	/*
	 * Slices are associated with the active solaris partition or if there
	 * is no active solaris partition, then the first solaris partition.
	 */

	*errp = 0;
	if (iparts[pnum].bootid == ACTIVE &&
	    (iparts[pnum].systid == SUNIXOS ||
	    iparts[pnum].systid == SUNIXOS2)) {
		return (1);
	} else {
	    int	active = 0;

	    /* Check if there are no active solaris partitions. */
	    for (i = 0; i < FD_NUMPART; i++) {
		if (iparts[i].bootid == ACTIVE &&
		    (iparts[i].systid == SUNIXOS ||
		    iparts[i].systid == SUNIXOS2)) {
			active = 1;
			break;
		}
	    }

	    if (!active) {
		/* Check if this is the first solaris partition. */
		for (i = 0; i < FD_NUMPART; i++) {
		    if (iparts[i].systid == SUNIXOS ||
			iparts[i].systid == SUNIXOS2) {
			    break;
		    }
		}

		if (i < FD_NUMPART && i == pnum) {
		    return (1);
		}
	    }
	}

	return (0);
}

static int
open_disk(disk_t *diskp, char *opath, int len)
{
	char	rmmedia_devpath[MAXPATHLEN];

	if (diskp->removable && media_get_volm_path(diskp, rmmedia_devpath,
	    sizeof (rmmedia_devpath))) {

	    int		fd;
	    struct stat	buf;

	    if (rmmedia_devpath[0] == 0) {
		/* removable but no media */
		return (-1);
	    }

	    if ((fd = open(rmmedia_devpath, O_RDONLY|O_NDELAY)) < 0) {
		return (-1);
	    }

	    if (fstat(fd, &buf) != 0) {
		(void) close(fd);
		return (-1);
	    }

	    if (buf.st_mode & S_IFCHR) {
		/* opened, is device, so done */
		if (opath != NULL) {
		    (void) strlcpy(opath, rmmedia_devpath, len);
		}
		return (fd);

	    } else if (buf.st_mode & S_IFDIR) {
		/* disk w/ slices so handle the directory */
		DIR		*dirp;
		struct dirent	*dentp;
		int		dfd;
#ifdef _LP64
		struct dirent	*result;
#endif

		/* each device file in the dir represents a slice */

		if ((dirp = fdopendir(fd)) == NULL) {
		    (void) close(fd);
		    return (-1);
		}

		if ((dentp = (struct dirent *)malloc(sizeof (struct dirent) +
		    _PC_NAME_MAX + 1)) == NULL) {
		    /* out of memory */
		    (void) close(fd);
		    return (-1);
		}
#ifdef _LP64
		while (readdir_r(dirp, dentp, &result) != NULL) {
#else
		while (readdir_r(dirp, dentp) != NULL) {
#endif
		    char	slice_path[MAXPATHLEN];

		    if (libdiskmgt_str_eq(".", dentp->d_name) ||
			libdiskmgt_str_eq("..", dentp->d_name)) {
			continue;
		    }

		    (void) snprintf(slice_path, sizeof (slice_path), "%s/%s",
			rmmedia_devpath, dentp->d_name);

		    if ((dfd = open(slice_path, O_RDONLY|O_NDELAY)) < 0) {
			continue;
		    }

		    if (fstat(dfd, &buf) == 0 && (buf.st_mode & S_IFCHR)) {
			/* opened, is device, so done */
			free(dentp);
			(void) close(fd);
			if (opath != NULL) {
			    (void) strlcpy(opath, slice_path, len);
			}
			return (dfd);
		    }

		    /* not a device, keep looking */
		    (void) close(dfd);
		}

		/* did not find a device under the rmmedia_path */
		free(dentp);
		(void) close(fd);
	    }

	    /* didn't find a device under volume management control */
	    return (-1);
	}

	/*
	 * Not removable media under volume management control so just open the
	 * first devpath.
	 */
	if (diskp->aliases != NULL && diskp->aliases->devpaths != NULL) {
#ifdef sparc
	    if (opath != NULL) {
		(void) strlcpy(opath, diskp->aliases->devpaths->devpath, len);
	    }
	    return (open(diskp->aliases->devpaths->devpath, O_RDONLY|O_NDELAY));
#else
	    /* On intel we need to open partition device (e.g. c0d0p0). */
	    char	part_dev[MAXPATHLEN];
	    char	*p;

	    (void) strlcpy(part_dev, diskp->aliases->devpaths->devpath,
		sizeof (part_dev));
	    p = strrchr(part_dev, '/');
	    if (p == NULL) {
		p = strrchr(part_dev, 's');
		if (p != NULL) {
		    *p = 'p';
		}
	    } else {
		char *ps;

		*p = 0;
		ps = strrchr((p + 1), 's');
		if (ps != NULL) {
		    *ps = 'p';
		}
		*p = '/';
	    }

	    if (opath != NULL) {
		(void) strlcpy(opath, part_dev, len);
	    }
	    return (open(part_dev, O_RDONLY|O_NDELAY));
#endif
	}

	return (-1);
}
