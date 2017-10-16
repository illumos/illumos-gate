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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <stropts.h>
#include <sys/dkio.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <unistd.h>
#include <kstat.h>
#include <errno.h>
#include <devid.h>
#include <dirent.h>

/* included for uscsi */
#include <strings.h>
#include <sys/stat.h>
#include <sys/scsi/impl/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/scsi/generic/mode.h>
#include <sys/byteorder.h>

#include "libdiskmgt.h"
#include "disks_private.h"

#define	KSTAT_CLASS_DISK	"disk"
#define	KSTAT_CLASS_ERROR	"device_error"

#define	SCSIBUFLEN		0xffff

/* byte get macros */
#define	b3(a)			(((a)>>24) & 0xFF)
#define	b2(a)			(((a)>>16) & 0xFF)
#define	b1(a)			(((a)>>8) & 0xFF)
#define	b0(a)			(((a)>>0) & 0xFF)

static char *kstat_err_names[] = {
	"Soft Errors",
	"Hard Errors",
	"Transport Errors",
	"Media Error",
	"Device Not Ready",
	"No Device",
	"Recoverable",
	"Illegal Request",
	"Predictive Failure Analysis",
	NULL
};

static char *err_attr_names[] = {
	DM_NSOFTERRS,
	DM_NHARDERRS,
	DM_NTRANSERRS,
	DM_NMEDIAERRS,
	DM_NDNRERRS,
	DM_NNODEVERRS,
	DM_NRECOVERRS,
	DM_NILLREQERRS,
	DM_FAILING,
	NULL
};

/*
 *	**************** begin uscsi stuff ****************
 */

#if defined(_BIT_FIELDS_LTOH)
#elif defined(_BIT_FIELDS_HTOL)
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif

struct conf_feature {
	uchar_t feature[2]; /* common to all */
#if defined(_BIT_FIELDS_LTOH)
	uchar_t current : 1;
	uchar_t persist : 1;
	uchar_t version : 4;
	uchar_t reserved: 2;
#else
	uchar_t reserved: 2;
	uchar_t version : 4;
	uchar_t persist : 1;
	uchar_t current : 1;
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t len;
	union features {
		struct generic {
			uchar_t data[1];
		} gen;
		uchar_t data[1];
		struct profile_list {
			uchar_t profile[2];
#if defined(_BIT_FIELDS_LTOH)
			uchar_t current_p : 1;
			uchar_t reserved1 : 7;
#else
			uchar_t reserved1 : 7;
			uchar_t current_p : 1;
#endif	/* _BIT_FIELDS_LTOH */
			uchar_t reserved2;
		} plist[1];
		struct core {
			uchar_t phys[4];
		} core;
		struct morphing {
#if defined(_BIT_FIELDS_LTOH)
			uchar_t async		: 1;
			uchar_t reserved1	: 7;
#else
			uchar_t reserved1	: 7;
			uchar_t async		: 1;
#endif	/* _BIT_FIELDS_LTOH */
			uchar_t reserved[3];
		} morphing;
		struct removable {
#if defined(_BIT_FIELDS_LTOH)
			uchar_t lock	: 1;
			uchar_t	resv1	: 1;
			uchar_t	pvnt	: 1;
			uchar_t eject	: 1;
			uchar_t resv2	: 1;
			uchar_t loading : 3;
#else
			uchar_t loading : 3;
			uchar_t resv2	: 1;
			uchar_t eject	: 1;
			uchar_t	pvnt	: 1;
			uchar_t	resv1	: 1;
			uchar_t lock	: 1;
#endif	/* _BIT_FIELDS_LTOH */
			uchar_t reserved[3];
		} removable;
		struct random_readable {
			uchar_t lbsize[4];
			uchar_t blocking[2];
#if defined(_BIT_FIELDS_LTOH)
			uchar_t pp		: 1;
			uchar_t reserved1	: 7;
#else
			uchar_t reserved1	: 7;
			uchar_t pp		: 1;
#endif	/* _BIT_FIELDS_LTOH */
			uchar_t reserved;
		} rread;
		struct cd_read {
#if defined(_BIT_FIELDS_LTOH)
			uchar_t cdtext		: 1;
			uchar_t c2flag		: 1;
			uchar_t reserved1	: 6;
#else
			uchar_t reserved1	: 6;
			uchar_t c2flag		: 1;
			uchar_t cdtext		: 1;
#endif	/* _BIT_FIELDS_LTOH */
		} cdread;
		struct cd_audio {
#if defined(_BIT_FIELDS_LTOH)
			uchar_t sv	: 1;
			uchar_t scm	: 1;
			uchar_t scan	: 1;
			uchar_t resv	: 5;
#else
			uchar_t resv	: 5;
			uchar_t scan	: 1;
			uchar_t scm	: 1;
			uchar_t sv	: 1;
#endif	/* _BIT_FIELDS_LTOH */
			uchar_t reserved;
			uchar_t numlevels[2];
		} audio;
		struct dvd_css {
			uchar_t reserved[3];
			uchar_t version;
		} dvdcss;
	} features;
};

#define	PROF_NON_REMOVABLE	0x0001
#define	PROF_REMOVABLE		0x0002
#define	PROF_MAGNETO_OPTICAL	0x0003
#define	PROF_OPTICAL_WO		0x0004
#define	PROF_OPTICAL_ASMO	0x0005
#define	PROF_CDROM		0x0008
#define	PROF_CDR		0x0009
#define	PROF_CDRW		0x000a
#define	PROF_DVDROM		0x0010
#define	PROF_DVDR		0x0011
#define	PROF_DVDRAM		0x0012
#define	PROF_DVDRW_REST		0x0013
#define	PROF_DVDRW_SEQ		0x0014
#define	PROF_DVDRW		0x001a
#define	PROF_DDCD_ROM		0x0020
#define	PROF_DDCD_R		0x0021
#define	PROF_DDCD_RW		0x0022
#define	PROF_NON_CONFORMING	0xffff

struct get_configuration {
	uchar_t len[4];
	uchar_t reserved[2];
	uchar_t curprof[2];
	struct conf_feature feature;
};

struct capabilities {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t pagecode	: 6;
	uchar_t resv1		: 1;
	uchar_t ps		: 1;
#else
	uchar_t ps		: 1;
	uchar_t resv1		: 1;
	uchar_t pagecode	: 6;
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t pagelen;
#if defined(_BIT_FIELDS_LTOH)
	/* read capabilities */
	uchar_t	cdr_read	: 1;
	uchar_t cdrw_read	: 1;
	uchar_t method2		: 1;
	uchar_t dvdrom_read	: 1;
	uchar_t dvdr_read	: 1;
	uchar_t dvdram_read	: 1;
	uchar_t resv2		: 2;
#else
	uchar_t resv2		: 2;
	uchar_t dvdram_read	: 1;
	uchar_t dvdr_read	: 1;
	uchar_t dvdrom_read	: 1;
	uchar_t method2		: 1;
	uchar_t cdrw_read	: 1;
	uchar_t	cdr_read	: 1;
#endif	/* _BIT_FIELDS_LTOH */
#if defined(_BIT_FIELDS_LTOH)
	/* write capabilities */
	uchar_t cdr_write	: 1;
	uchar_t cdrw_write	: 1;
	uchar_t testwrite	: 1;
	uchar_t resv3		: 1;
	uchar_t dvdr_write	: 1;
	uchar_t dvdram_write	: 1;
	uchar_t resv4		: 2;
#else
	/* write capabilities */
	uchar_t resv4		: 2;
	uchar_t dvdram_write	: 1;
	uchar_t dvdr_write	: 1;
	uchar_t resv3		: 1;
	uchar_t testwrite	: 1;
	uchar_t cdrw_write	: 1;
	uchar_t cdr_write	: 1;
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t misc0;
	uchar_t misc1;
	uchar_t misc2;
	uchar_t misc3;
	uchar_t obsolete0[2];
	uchar_t numvlevels[2];
	uchar_t bufsize[2];
	uchar_t obsolete1[4];
	uchar_t resv5;
	uchar_t misc4;
	uchar_t obsolete2;
	uchar_t copymgt[2];
	/* there is more to this page, but nothing we care about */
};

struct mode_header_g2 {
	uchar_t modelen[2];
	uchar_t obsolete;
	uchar_t reserved[3];
	uchar_t desclen[2];
};

/*
 * Mode sense/select page header information
 */
struct scsi_ms_header {
	struct mode_header	mode_header;
	struct block_descriptor	block_descriptor;
};

#define	MODESENSE_PAGE_LEN(p)	(((int)((struct mode_page *)p)->length) + \
				    sizeof (struct mode_page))

#define	MODE_SENSE_PC_CURRENT	(0 << 6)
#define	MODE_SENSE_PC_DEFAULT	(2 << 6)
#define	MODE_SENSE_PC_SAVED	(3 << 6)

#define	MAX_MODE_SENSE_SIZE	255
#define	IMPOSSIBLE_SCSI_STATUS	0xff

/*
 *	********** end of uscsi stuff ************
 */

static descriptor_t	**apply_filter(descriptor_t **drives, int filter[],
			    int *errp);
static int		check_atapi(int fd);
static int		conv_drive_type(uint_t drive_type);
static uint64_t		convnum(uchar_t *nptr, int len);
static void		fill_command_g1(struct uscsi_cmd *cmd,
			    union scsi_cdb *cdb, caddr_t buff, int blen);
static void		fill_general_page_cdb_g1(union scsi_cdb *cdb,
			    int command, int lun, uchar_t c0, uchar_t c1);
static void		fill_mode_page_cdb(union scsi_cdb *cdb, int page);
static descriptor_t	**get_assoc_alias(disk_t *diskp, int *errp);
static descriptor_t	**get_assoc_controllers(descriptor_t *dp, int *errp);
static descriptor_t	**get_assoc_paths(descriptor_t *dp, int *errp);
static int		get_attrs(disk_t *diskp, int fd, char *opath,
			    nvlist_t *nvp);
static int		get_cdrom_drvtype(int fd);
static int		get_disk_kstats(kstat_ctl_t *kc, char *diskname,
			    char *classname, nvlist_t *stats);
static void		get_drive_type(disk_t *dp, int fd);
static int		get_err_kstats(kstat_ctl_t *kc, char *diskname,
			    nvlist_t *stats);
static int		get_io_kstats(kstat_ctl_t *kc, char *diskname,
			    nvlist_t *stats);
static int		get_kstat_vals(kstat_t *ksp, nvlist_t *stats);
static char		*get_err_attr_name(char *kstat_name);
static int		get_rpm(disk_t *dp, int fd);
static int		get_solidstate(disk_t *dp, int fd);
static int		update_stat64(nvlist_t *stats, char *attr,
			    uint64_t value);
static int		update_stat32(nvlist_t *stats, char *attr,
			    uint32_t value);
static int		uscsi_mode_sense(int fd, int page_code,
			    int page_control, caddr_t page_data, int page_size,
			    struct  scsi_ms_header *header);

descriptor_t **
drive_get_assoc_descriptors(descriptor_t *dp, dm_desc_type_t type,
    int *errp)
{
	switch (type) {
	case DM_CONTROLLER:
	    return (get_assoc_controllers(dp, errp));
	case DM_PATH:
	    return (get_assoc_paths(dp, errp));
	case DM_ALIAS:
	    return (get_assoc_alias(dp->p.disk, errp));
	case DM_MEDIA:
	    return (media_get_assocs(dp, errp));
	}

	*errp = EINVAL;
	return (NULL);
}

/*
 * Get the drive descriptors for the given media/alias/devpath.
 */
descriptor_t **
drive_get_assocs(descriptor_t *desc, int *errp)
{
	descriptor_t	**drives;

	/* at most one drive is associated with these descriptors */

	drives = (descriptor_t **)calloc(2, sizeof (descriptor_t *));
	if (drives == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	drives[0] = cache_get_desc(DM_DRIVE, desc->p.disk, NULL, NULL, errp);
	if (*errp != 0) {
	    cache_free_descriptors(drives);
	    return (NULL);
	}

	drives[1] = NULL;

	return (drives);
}

nvlist_t *
drive_get_attributes(descriptor_t *dp, int *errp)
{
	nvlist_t	*attrs = NULL;
	int		fd;
	char		opath[MAXPATHLEN];

	if (nvlist_alloc(&attrs, NVATTRS, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	opath[0] = 0;
	fd = drive_open_disk(dp->p.disk, opath, sizeof (opath));

	if ((*errp = get_attrs(dp->p.disk, fd, opath, attrs)) != 0) {
	    nvlist_free(attrs);
	    attrs = NULL;
	}

	if (fd >= 0) {
	    (void) close(fd);
	}

	return (attrs);
}

/*
 * Check if we have the drive in our list, based upon the device id.
 * We got the device id from the dev tree walk.  This is encoded
 * using devid_str_encode(3DEVID).   In order to check the device ids we need
 * to use the devid_compare(3DEVID) function, so we need to decode the
 * string representation of the device id.
 */
descriptor_t *
drive_get_descriptor_by_name(char *name, int *errp)
{
	ddi_devid_t	devid;
	descriptor_t	**drives;
	descriptor_t	*drive = NULL;
	int		i;

	if (name == NULL || devid_str_decode(name, &devid, NULL) != 0) {
	    *errp = EINVAL;
	    return (NULL);
	}

	drives = cache_get_descriptors(DM_DRIVE, errp);
	if (*errp != 0) {
	    devid_free(devid);
	    return (NULL);
	}

	/*
	 * We have to loop through all of them, freeing the ones we don't
	 * want.  Once drive is set, we don't need to compare any more.
	 */
	for (i = 0; drives[i]; i++) {
	    if (drive == NULL && drives[i]->p.disk->devid != NULL &&
		devid_compare(devid, drives[i]->p.disk->devid) == 0) {
		drive = drives[i];

	    } else {
		/* clean up the unused descriptor */
		cache_free_descriptor(drives[i]);
	    }
	}
	free(drives);
	devid_free(devid);

	if (drive == NULL) {
	    *errp = ENODEV;
	}

	return (drive);
}

descriptor_t **
drive_get_descriptors(int filter[], int *errp)
{
	descriptor_t	**drives;

	drives = cache_get_descriptors(DM_DRIVE, errp);
	if (*errp != 0) {
	    return (NULL);
	}

	if (filter != NULL && filter[0] != DM_FILTER_END) {
	    descriptor_t	**found;
	    found = apply_filter(drives, filter, errp);
	    if (*errp != 0) {
		drives = NULL;
	    } else {
		drives = found;
	    }
	}

	return (drives);
}

char *
drive_get_name(descriptor_t *dp)
{
	return (dp->p.disk->device_id);
}

nvlist_t *
drive_get_stats(descriptor_t *dp, int stat_type, int *errp)
{
	disk_t		*diskp;
	nvlist_t	*stats;

	diskp = dp->p.disk;

	if (nvlist_alloc(&stats, NVATTRS, 0) != 0) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	if (stat_type == DM_DRV_STAT_PERFORMANCE ||
	    stat_type == DM_DRV_STAT_DIAGNOSTIC) {

	    alias_t	*ap;
	    kstat_ctl_t	*kc;

	    ap = diskp->aliases;
	    if (ap == NULL || ap->kstat_name == NULL) {
		nvlist_free(stats);
		*errp = EACCES;
		return (NULL);
	    }

	    if ((kc = kstat_open()) == NULL) {
		nvlist_free(stats);
		*errp = EACCES;
		return (NULL);
	    }

	    while (ap != NULL) {
		int	status;

		if (ap->kstat_name == NULL) {
		    continue;
		}

		if (stat_type == DM_DRV_STAT_PERFORMANCE) {
		    status = get_io_kstats(kc, ap->kstat_name, stats);
		} else {
		    status = get_err_kstats(kc, ap->kstat_name, stats);
		}

		if (status != 0) {
		    nvlist_free(stats);
		    (void) kstat_close(kc);
		    *errp = ENOMEM;
		    return (NULL);
		}

		ap = ap->next;
	    }

	    (void) kstat_close(kc);

	    *errp = 0;
	    return (stats);
	}

	if (stat_type == DM_DRV_STAT_TEMPERATURE) {
	    int		fd;

	    if ((fd = drive_open_disk(diskp, NULL, 0)) >= 0) {
		struct dk_temperature	temp;

		if (ioctl(fd, DKIOCGTEMPERATURE, &temp) >= 0) {
		    if (nvlist_add_uint32(stats, DM_TEMPERATURE,
			temp.dkt_cur_temp) != 0) {
			*errp = ENOMEM;
			nvlist_free(stats);
			return (NULL);
		    }
		} else {
		    *errp = errno;
		    nvlist_free(stats);
		    return (NULL);
		}
		(void) close(fd);
	    } else {
		*errp = errno;
		nvlist_free(stats);
		return (NULL);
	    }

	    *errp = 0;
	    return (stats);
	}

	nvlist_free(stats);
	*errp = EINVAL;
	return (NULL);
}

int
drive_make_descriptors()
{
	int	error;
	disk_t	*dp;

	dp = cache_get_disklist();
	while (dp != NULL) {
	    cache_load_desc(DM_DRIVE, dp, NULL, NULL, &error);
	    if (error != 0) {
		return (error);
	    }
	    dp = dp->next;
	}

	return (0);
}

/*
 * This function opens the disk generically (any slice).
 */
int
drive_open_disk(disk_t *diskp, char *opath, int len)
{
	/*
	 * Just open the first devpath.
	 */
	if (diskp->aliases != NULL && diskp->aliases->devpaths != NULL) {
	    if (opath != NULL) {
		(void) strlcpy(opath, diskp->aliases->devpaths->devpath, len);
	    }
	    return (open(diskp->aliases->devpaths->devpath, O_RDONLY|O_NDELAY));
	}

	return (-1);
}

static descriptor_t **
apply_filter(descriptor_t **drives, int filter[], int *errp)
{
	int		i;
	descriptor_t	**found;
	int		cnt;
	int		pos;

	/* count the number of drives in the snapshot */
	for (cnt = 0; drives[cnt]; cnt++);

	found = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (found == NULL) {
	    *errp = ENOMEM;
	    cache_free_descriptors(drives);
	    return (NULL);
	}

	pos = 0;
	for (i = 0; drives[i]; i++) {
	    int j;
	    int match;

	    /* Make sure the drive type is set */
	    get_drive_type(drives[i]->p.disk, -1);

	    match = 0;
	    for (j = 0; filter[j] != DM_FILTER_END; j++) {
		if (drives[i]->p.disk->drv_type == filter[j]) {
		    found[pos++] = drives[i];
		    match = 1;
		    break;
		}
	    }

	    if (!match) {
		cache_free_descriptor(drives[i]);
	    }
	}
	found[pos] = NULL;
	free(drives);

	*errp = 0;
	return (found);
}

static int
conv_drive_type(uint_t drive_type)
{
	switch (drive_type) {
	case DK_UNKNOWN:
	    return (DM_DT_UNKNOWN);
	case DK_MO_ERASABLE:
	    return (DM_DT_MO_ERASABLE);
	case DK_MO_WRITEONCE:
	    return (DM_DT_MO_WRITEONCE);
	case DK_AS_MO:
	    return (DM_DT_AS_MO);
	case DK_CDROM:
	    return (DM_DT_CDROM);
	case DK_CDR:
	    return (DM_DT_CDR);
	case DK_CDRW:
	    return (DM_DT_CDRW);
	case DK_DVDROM:
	    return (DM_DT_DVDROM);
	case DK_DVDR:
	    return (DM_DT_DVDR);
	case DK_DVDRAM:
	    return (DM_DT_DVDRAM);
	case DK_FIXED_DISK:
	    return (DM_DT_FIXED);
	case DK_FLOPPY:
	    return (DM_DT_FLOPPY);
	case DK_ZIP:
	    return (DM_DT_ZIP);
	case DK_JAZ:
	    return (DM_DT_JAZ);
	default:
	    return (DM_DT_UNKNOWN);
	}
}

static descriptor_t **
get_assoc_alias(disk_t *diskp, int *errp)
{
	alias_t		*aliasp;
	uint_t		cnt;
	descriptor_t	**out_array;
	int		pos;

	*errp = 0;

	aliasp = diskp->aliases;
	cnt = 0;

	while (aliasp != NULL) {
	    if (aliasp->alias != NULL) {
		cnt++;
	    }
	    aliasp = aliasp->next;
	}

	/* set up the new array */
	out_array = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t));
	if (out_array == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	aliasp = diskp->aliases;
	pos = 0;
	while (aliasp != NULL) {
	    if (aliasp->alias != NULL) {
		out_array[pos++] = cache_get_desc(DM_ALIAS, diskp,
		    aliasp->alias, NULL, errp);
		if (*errp != 0) {
		    cache_free_descriptors(out_array);
		    return (NULL);
		}
	    }

	    aliasp = aliasp->next;
	}

	out_array[pos] = NULL;

	return (out_array);
}

static descriptor_t **
get_assoc_controllers(descriptor_t *dp, int *errp)
{
	disk_t		*diskp;
	int		cnt;
	descriptor_t	**controllers;
	int		i;

	diskp = dp->p.disk;

	/* Count how many we have. */
	for (cnt = 0; diskp->controllers[cnt]; cnt++);

	/* make the snapshot */
	controllers = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (controllers == NULL) {
	    *errp = ENOMEM;
	    return (NULL);
	}

	for (i = 0; diskp->controllers[i]; i++) {
	    controllers[i] = cache_get_desc(DM_CONTROLLER,
		diskp->controllers[i], NULL, NULL, errp);
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
get_assoc_paths(descriptor_t *dp, int *errp)
{
	path_t		**pp;
	int		cnt;
	descriptor_t	**paths;
	int		i;

	pp = dp->p.disk->paths;

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
	 * We fill in the name field of the descriptor with the device_id
	 * when we deal with path descriptors originating from a drive.
	 * In that way we can use the device id within the path code to
	 * lookup the path state for this drive.
	 */
	for (i = 0; i < cnt; i++) {
	    paths[i] = cache_get_desc(DM_PATH, pp[i], dp->p.disk->device_id,
		NULL, errp);
	    if (*errp != 0) {
		cache_free_descriptors(paths);
		return (NULL);
	    }
	}

	paths[i] = NULL;

	*errp = 0;
	return (paths);
}

static int
get_attrs(disk_t *diskp, int fd, char *opath, nvlist_t *attrs)
{
	if (diskp->removable) {
	    struct dk_minfo	minfo;

	    if (nvlist_add_boolean(attrs, DM_REMOVABLE) != 0) {
		return (ENOMEM);
	    }

	    /* Make sure media is inserted and spun up. */
	    if (fd >= 0 && media_read_info(fd, &minfo)) {
		if (nvlist_add_boolean(attrs, DM_LOADED) != 0) {
		    return (ENOMEM);
		}
	    }

	    /* can't tell diff between dead & no media on removable drives */
	    if (nvlist_add_uint32(attrs, DM_STATUS, DM_DISK_UP) != 0) {
		return (ENOMEM);
	    }

	    get_drive_type(diskp, fd);

	} else {
	    struct dk_minfo	minfo;

	    /* check if the fixed drive is up or not */
	    if (fd >= 0 && media_read_info(fd, &minfo)) {
		if (nvlist_add_uint32(attrs, DM_STATUS, DM_DISK_UP) != 0) {
		    return (ENOMEM);
		}
	    } else {
		if (nvlist_add_uint32(attrs, DM_STATUS, DM_DISK_DOWN) != 0) {
		    return (ENOMEM);
		}
	    }

	    get_drive_type(diskp, fd);
	}

	if (nvlist_add_uint32(attrs, DM_DRVTYPE, diskp->drv_type) != 0) {
	    return (ENOMEM);
	}

	if (diskp->product_id != NULL) {
	    if (nvlist_add_string(attrs, DM_PRODUCT_ID, diskp->product_id)
		!= 0) {
		return (ENOMEM);
	    }
	}
	if (diskp->vendor_id != NULL) {
	    if (nvlist_add_string(attrs, DM_VENDOR_ID, diskp->vendor_id) != 0) {
		return (ENOMEM);
	    }
	}

	if (diskp->sync_speed != -1) {
	    if (nvlist_add_uint32(attrs, DM_SYNC_SPEED, diskp->sync_speed)
		!= 0) {
		return (ENOMEM);
	    }
	}

	if (diskp->wide == 1) {
	    if (nvlist_add_boolean(attrs, DM_WIDE) != 0) {
		return (ENOMEM);
	    }
	}

	if (diskp->rpm == 0) {
	    diskp->rpm = get_rpm(diskp, fd);
	}

	if (diskp->rpm > 0) {
	    if (nvlist_add_uint32(attrs, DM_RPM, diskp->rpm) != 0) {
		return (ENOMEM);
	    }
	}

	if (strlen(opath) > 0) {
	    if (nvlist_add_string(attrs, DM_OPATH, opath) != 0) {
		return (ENOMEM);
	    }
	}

	if (diskp->solid_state < 0) {
		diskp->solid_state = get_solidstate(diskp, fd);
	}

	if (diskp->solid_state > 0) {
		if (nvlist_add_boolean(attrs, DM_SOLIDSTATE) != 0) {
			return (ENOMEM);
		}
	}

	return (0);
}

static int
get_disk_kstats(kstat_ctl_t *kc, char *diskname, char *classname,
	nvlist_t *stats)
{
	kstat_t		*ksp;
	size_t		class_len;
	int		err = 0;

	class_len = strlen(classname);
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
	    if (strncmp(ksp->ks_class, classname, class_len) == 0) {
		char	kstat_name[KSTAT_STRLEN];
		char	*dname = kstat_name;
		char	*ename = ksp->ks_name;

		/* names are format: "sd0,err" - copy chars up to comma */
		while (*ename && *ename != ',') {
		    *dname++ = *ename++;
		}
		*dname = NULL;

		if (libdiskmgt_str_eq(diskname, kstat_name)) {
		    (void) kstat_read(kc, ksp, NULL);
		    err = get_kstat_vals(ksp, stats);
		    break;
		}
	    }
	}

	return (err);
}

/*
 * Getting the drive type depends on if the dev tree walk indicated that the
 * drive was a CD-ROM or not.  The kernal lumps all of the removable multi-media
 * drives (e.g. CD, DVD, MO, etc.) together as CD-ROMS, so we need to use
 * a uscsi cmd to check the drive type.
 */
static void
get_drive_type(disk_t *dp, int fd)
{
	if (dp->drv_type == DM_DT_UNKNOWN) {
	    int	opened_here = 0;

	    /* We may have already opened the device. */
	    if (fd < 0) {
		fd = drive_open_disk(dp, NULL, 0);
		opened_here = 1;
	    }

	    if (fd >= 0) {
		if (dp->cd_rom) {
		    /* use uscsi to determine drive type */
		    dp->drv_type = get_cdrom_drvtype(fd);

		    /* if uscsi fails, just call it a cd-rom */
		    if (dp->drv_type == DM_DT_UNKNOWN) {
			dp->drv_type = DM_DT_CDROM;
		    }

		} else {
		    struct dk_minfo	minfo;

		    if (media_read_info(fd, &minfo)) {
			dp->drv_type = conv_drive_type(minfo.dki_media_type);
		    }
		}

		if (opened_here) {
		    (void) close(fd);
		}

	    } else {
		/* couldn't open */
		if (dp->cd_rom) {
		    dp->drv_type = DM_DT_CDROM;
		}
	    }
	}
}

static char *
get_err_attr_name(char *kstat_name)
{
	int	i;

	for (i = 0; kstat_err_names[i] != NULL; i++) {
	    if (libdiskmgt_str_eq(kstat_name, kstat_err_names[i])) {
		return (err_attr_names[i]);
	    }
	}

	return (NULL);
}

static int
get_err_kstats(kstat_ctl_t *kc, char *diskname, nvlist_t *stats)
{
	return (get_disk_kstats(kc, diskname, KSTAT_CLASS_ERROR, stats));
}

static int
get_io_kstats(kstat_ctl_t *kc, char *diskname, nvlist_t *stats)
{
	return (get_disk_kstats(kc, diskname, KSTAT_CLASS_DISK, stats));
}

static int
get_kstat_vals(kstat_t *ksp, nvlist_t *stats)
{
	if (ksp->ks_type == KSTAT_TYPE_IO) {
	    kstat_io_t *kiop;

	    kiop = KSTAT_IO_PTR(ksp);

	    /* see sys/kstat.h kstat_io_t struct for more fields */

	    if (update_stat64(stats, DM_NBYTESREAD, kiop->nread) != 0) {
		return (ENOMEM);
	    }
	    if (update_stat64(stats, DM_NBYTESWRITTEN, kiop->nwritten) != 0) {
		return (ENOMEM);
	    }
	    if (update_stat64(stats, DM_NREADOPS, kiop->reads) != 0) {
		return (ENOMEM);
	    }
	    if (update_stat64(stats, DM_NWRITEOPS, kiop->writes) != 0) {
		return (ENOMEM);
	    }

	} else if (ksp->ks_type == KSTAT_TYPE_NAMED) {
	    kstat_named_t *knp;
	    int		i;

	    knp = KSTAT_NAMED_PTR(ksp);
	    for (i = 0; i < ksp->ks_ndata; i++) {
		char	*attr_name;

		if (knp[i].name[0] == 0)
		    continue;

		if ((attr_name = get_err_attr_name(knp[i].name)) == NULL) {
		    continue;

		}

		switch (knp[i].data_type) {
		case KSTAT_DATA_UINT32:
		    if (update_stat32(stats, attr_name, knp[i].value.ui32)
			!= 0) {
			return (ENOMEM);
		    }
		    break;

		default:
		    /* Right now all of the error types are uint32 */
		    break;
		}
	    }
	}
	return (0);
}

static int
update_stat32(nvlist_t *stats, char *attr, uint32_t value)
{
	int32_t	currval;

	if (nvlist_lookup_int32(stats, attr, &currval) == 0) {
	    value += currval;
	}

	return (nvlist_add_uint32(stats, attr, value));
}

/*
 * There can be more than one kstat value when we have multi-path drives
 * that are not under mpxio (since there is more than one kstat name for
 * the drive in this case).  So, we may have merge all of the kstat values
 * to give an accurate set of stats for the drive.
 */
static int
update_stat64(nvlist_t *stats, char *attr, uint64_t value)
{
	int64_t	currval;

	if (nvlist_lookup_int64(stats, attr, &currval) == 0) {
	    value += currval;
	}
	return (nvlist_add_uint64(stats, attr, value));
}

/*
 * uscsi function to get the rpm of the drive
 */
static int
get_rpm(disk_t *dp, int fd)
{
	int	opened_here = 0;
	int	rpm = -1;

	/* We may have already opened the device. */
	if (fd < 0) {
	    fd = drive_open_disk(dp, NULL, 0);
	    opened_here = 1;
	}

	if (fd >= 0) {
	    int				status;
	    struct mode_geometry	*page4;
	    struct scsi_ms_header	header;
	    union {
		struct mode_geometry	page4;
		char			rawbuf[MAX_MODE_SENSE_SIZE];
	    } u_page4;

	    page4 = &u_page4.page4;
	    (void) memset(&u_page4, 0, sizeof (u_page4));

	    status = uscsi_mode_sense(fd, DAD_MODE_GEOMETRY,
		MODE_SENSE_PC_DEFAULT, (caddr_t)page4, MAX_MODE_SENSE_SIZE,
		&header);

	    if (status) {
		status = uscsi_mode_sense(fd, DAD_MODE_GEOMETRY,
		    MODE_SENSE_PC_SAVED, (caddr_t)page4, MAX_MODE_SENSE_SIZE,
		    &header);
	    }

	    if (status) {
		status = uscsi_mode_sense(fd, DAD_MODE_GEOMETRY,
		    MODE_SENSE_PC_CURRENT, (caddr_t)page4, MAX_MODE_SENSE_SIZE,
		    &header);
	    }

	    if (!status) {
#ifdef _LITTLE_ENDIAN
		page4->rpm = ntohs(page4->rpm);
#endif /* _LITTLE_ENDIAN */

		rpm = page4->rpm;
	    }

	    if (opened_here) {
		(void) close(fd);
	    }
	}

	return (rpm);
}

static int
get_solidstate(disk_t *dp, int fd)
{
	int	opened_here = 0;
	int	solid_state = -1;

	/* We may have already opened the device. */
	if (fd < 0) {
		fd = drive_open_disk(dp, NULL, 0);
		opened_here = 1;
	}

	if (fd >= 0) {
		if (ioctl(fd, DKIOCSOLIDSTATE, &solid_state) < 0) {
			solid_state = -1;
		}
	}

	if (opened_here) {
		(void) close(fd);
	}

	return (solid_state);
}

/*
 *	******** the rest of this is uscsi stuff for the drv type ********
 */

/*
 * We try a get_configuration uscsi cmd.  If that fails, try a
 * atapi_capabilities cmd.  If both fail then this is an older CD-ROM.
 */
static int
get_cdrom_drvtype(int fd)
{
	union scsi_cdb cdb;
	struct uscsi_cmd cmd;
	uchar_t buff[SCSIBUFLEN];

	fill_general_page_cdb_g1(&cdb, SCMD_GET_CONFIGURATION, 0,
	    b0(sizeof (buff)), b1(sizeof (buff)));
	fill_command_g1(&cmd, &cdb, (caddr_t)buff, sizeof (buff));

	if (ioctl(fd, USCSICMD, &cmd) >= 0) {
	    struct get_configuration	*config;
	    struct conf_feature		*feature;
	    int				flen;

	    /* The first profile is the preferred one for the drive. */
	    config = (struct get_configuration *)buff;
	    feature = &config->feature;
	    flen = feature->len / sizeof (struct profile_list);
	    if (flen > 0) {
		int prof_num;

		prof_num = (int)convnum(feature->features.plist[0].profile, 2);

		if (dm_debug > 1) {
		    (void) fprintf(stderr, "INFO: uscsi get_configuration %d\n",
			prof_num);
		}

		switch (prof_num) {
		case PROF_MAGNETO_OPTICAL:
		    return (DM_DT_MO_ERASABLE);
		case PROF_OPTICAL_WO:
		    return (DM_DT_MO_WRITEONCE);
		case PROF_OPTICAL_ASMO:
		    return (DM_DT_AS_MO);
		case PROF_CDROM:
		    return (DM_DT_CDROM);
		case PROF_CDR:
		    return (DM_DT_CDR);
		case PROF_CDRW:
		    return (DM_DT_CDRW);
		case PROF_DVDROM:
		    return (DM_DT_DVDROM);
		case PROF_DVDRAM:
		    return (DM_DT_DVDRAM);
		case PROF_DVDRW_REST:
		    return (DM_DT_DVDRW);
		case PROF_DVDRW_SEQ:
		    return (DM_DT_DVDRW);
		case PROF_DVDRW:
		    return (DM_DT_DVDRW);
		case PROF_DDCD_ROM:
		    return (DM_DT_DDCDROM);
		case PROF_DDCD_R:
		    return (DM_DT_DDCDR);
		case PROF_DDCD_RW:
		    return (DM_DT_DDCDRW);
		}
	    }
	}

	/* see if the atapi capabilities give anything */
	return (check_atapi(fd));
}

static int
check_atapi(int fd)
{
	union scsi_cdb cdb;
	struct uscsi_cmd cmd;
	uchar_t buff[SCSIBUFLEN];

	fill_mode_page_cdb(&cdb, ATAPI_CAPABILITIES);
	fill_command_g1(&cmd, &cdb, (caddr_t)buff, sizeof (buff));

	if (ioctl(fd, USCSICMD, &cmd) >= 0) {
	    int			bdesclen;
	    struct capabilities	*cap;
	    struct mode_header_g2 *mode;

	    mode = (struct mode_header_g2 *)buff;

	    bdesclen = (int)convnum(mode->desclen, 2);
	    cap = (struct capabilities *)
		&buff[sizeof (struct mode_header_g2) + bdesclen];

	    if (dm_debug > 1) {
		(void) fprintf(stderr, "INFO: uscsi atapi capabilities\n");
	    }

	    /* These are in order of how we want to report the drv type. */
	    if (cap->dvdram_write) {
		return (DM_DT_DVDRAM);
	    }
	    if (cap->dvdr_write) {
		return (DM_DT_DVDR);
	    }
	    if (cap->dvdrom_read) {
		return (DM_DT_DVDROM);
	    }
	    if (cap->cdrw_write) {
		return (DM_DT_CDRW);
	    }
	    if (cap->cdr_write) {
		return (DM_DT_CDR);
	    }
	    if (cap->cdr_read) {
		return (DM_DT_CDROM);
	    }
	}

	/* everything failed, so this is an older CD-ROM */
	if (dm_debug > 1) {
	    (void) fprintf(stderr, "INFO: uscsi failed\n");
	}

	return (DM_DT_CDROM);
}

static uint64_t
convnum(uchar_t *nptr, int len)
{
	uint64_t value;

	for (value = 0; len > 0; len--, nptr++)
		value = (value << 8) | *nptr;
	return (value);
}

static void
fill_command_g1(struct uscsi_cmd *cmd, union scsi_cdb *cdb,
	caddr_t buff, int blen)
{
	bzero((caddr_t)cmd, sizeof (struct uscsi_cmd));
	bzero(buff, blen);

	cmd->uscsi_cdb = (caddr_t)cdb;
	cmd->uscsi_cdblen = CDB_GROUP1;

	cmd->uscsi_bufaddr = buff;
	cmd->uscsi_buflen = blen;

	cmd->uscsi_flags = USCSI_DIAGNOSE|USCSI_ISOLATE|USCSI_READ;
}

static void
fill_general_page_cdb_g1(union scsi_cdb *cdb, int command, int lun,
	uchar_t c0, uchar_t c1)
{
	bzero((caddr_t)cdb, sizeof (union scsi_cdb));
	cdb->scc_cmd = command;
	cdb->scc_lun = lun;
	cdb->g1_count0 = c0; /* max length for page */
	cdb->g1_count1 = c1; /* max length for page */
}

static void
fill_mode_page_cdb(union scsi_cdb *cdb, int page)
{
	/* group 1 mode page */
	bzero((caddr_t)cdb, sizeof (union scsi_cdb));
	cdb->scc_cmd = SCMD_MODE_SENSE_G1;
	cdb->g1_count0 = 0xff; /* max length for mode page */
	cdb->g1_count1 = 0xff; /* max length for mode page */
	cdb->g1_addr3 = page;
}

static int
uscsi_mode_sense(int fd, int page_code, int page_control, caddr_t page_data,
	int page_size, struct  scsi_ms_header *header)
{
	caddr_t			mode_sense_buf;
	struct mode_header	*hdr;
	struct mode_page	*pg;
	int			nbytes;
	struct uscsi_cmd	ucmd;
	union scsi_cdb		cdb;
	int			status;
	int			maximum;
	char			rqbuf[255];

	/*
	 * Allocate a buffer for the mode sense headers
	 * and mode sense data itself.
	 */
	nbytes = sizeof (struct block_descriptor) +
				sizeof (struct mode_header) + page_size;
	nbytes = page_size;
	if ((mode_sense_buf = malloc((uint_t)nbytes)) == NULL) {
	    return (-1);
	}

	/*
	 * Build and execute the uscsi ioctl
	 */
	(void) memset(mode_sense_buf, 0, nbytes);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	(void) memset((char *)&cdb, 0, sizeof (union scsi_cdb));

	cdb.scc_cmd = SCMD_MODE_SENSE;
	FORMG0COUNT(&cdb, (uchar_t)nbytes);
	cdb.cdb_opaque[2] = page_control | page_code;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = mode_sense_buf;
	ucmd.uscsi_buflen = nbytes;

	ucmd.uscsi_flags |= USCSI_SILENT;
	ucmd.uscsi_flags |= USCSI_READ;
	ucmd.uscsi_timeout = 30;
	ucmd.uscsi_flags |= USCSI_RQENABLE;
	if (ucmd.uscsi_rqbuf == NULL)  {
	    ucmd.uscsi_rqbuf = rqbuf;
	    ucmd.uscsi_rqlen = sizeof (rqbuf);
	    ucmd.uscsi_rqresid = sizeof (rqbuf);
	}
	ucmd.uscsi_rqstatus = IMPOSSIBLE_SCSI_STATUS;

	status = ioctl(fd, USCSICMD, &ucmd);

	if (status || ucmd.uscsi_status != 0) {
	    free(mode_sense_buf);
	    return (-1);
	}

	/*
	 * Verify that the returned data looks reasonabled,
	 * find the actual page data, and copy it into the
	 * user's buffer.  Copy the mode_header and block_descriptor
	 * into the header structure, which can then be used to
	 * return the same data to the drive when issuing a mode select.
	 */
	hdr = (struct mode_header *)mode_sense_buf;
	(void) memset((caddr_t)header, 0, sizeof (struct scsi_ms_header));
	if (hdr->bdesc_length != sizeof (struct block_descriptor) &&
	    hdr->bdesc_length != 0) {
	    free(mode_sense_buf);
	    return (-1);
	}
	(void) memcpy((caddr_t)header, mode_sense_buf,
	    (int) (sizeof (struct mode_header) + hdr->bdesc_length));
	pg = (struct mode_page *)((ulong_t)mode_sense_buf +
	    sizeof (struct mode_header) + hdr->bdesc_length);
	if (pg->code != page_code) {
	    free(mode_sense_buf);
	    return (-1);
	}

	/*
	 * Accept up to "page_size" bytes of mode sense data.
	 * This allows us to accept both CCS and SCSI-2
	 * structures, as long as we request the greater
	 * of the two.
	 */
	maximum = page_size - sizeof (struct mode_page) - hdr->bdesc_length;
	if (((int)pg->length) > maximum) {
	    free(mode_sense_buf);
	    return (-1);
	}

	(void) memcpy(page_data, (caddr_t)pg, MODESENSE_PAGE_LEN(pg));

	free(mode_sense_buf);
	return (0);
}
