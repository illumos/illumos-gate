/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 1999 - 2005 Free Software Foundation, Inc.
	Copyright (C) 2007 Nikhil,Sujay,Nithin,Srivatsa.

    Bug fixes and completion of the module in 2009 by Mark.Logan@sun.com.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
*/

#include <sys/types.h>
#include <sys/mkdev.h>
#include "config.h"
#include "xalloc.h"
#include <sys/dkio.h>

/*
 * __attribute doesn't exist on solaris
 */
#define	__attribute__(X)	/* nothing */

#include <sys/vtoc.h>

#include <parted/parted.h>
#include <parted/debug.h>
#include <parted/solaris.h>
#include <malloc.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <dirent.h>
#include <libdiskmgt.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/swap.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>

#if ENABLE_NLS
#include <libintl.h>
#define	_(String)	dgettext(PACKAGE, String)
#else
#define	_(String)	(String)
#endif /* ENABLE_NLS */

#ifndef UINT_MAX64
#define	UINT_MAX64	0xffffffffffffffffULL
#endif

/*
 * Macro to convert a device number into a partition number
 */
#define	PARTITION(dev)	(minor(dev) & 0x07)


char *
canonicalize_file_name(const char *name)
{
	char *buf;

	buf = malloc(MAXPATHLEN);
	if (!buf) {
		errno = ENOMEM;
		return (NULL);
	}

	return (strcpy(buf, name));
}

static int
_device_stat(PedDevice* dev, struct stat *dev_stat)
{
	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(!dev->external_mode, return (0));

	while (1) {
		if (!stat(dev->path, dev_stat)) {
			return (1);
		} else {
			if (ped_exception_throw(
			    PED_EXCEPTION_ERROR,
			    PED_EXCEPTION_RETRY_CANCEL,
			    _("Could not stat device %s - %s."),
			    dev->path, strerror(errno)) != PED_EXCEPTION_RETRY)
				return (0);
		}
	}
}

static void
_device_set_length_and_sector_size(PedDevice* dev)
{
	SolarisSpecific* arch_specific;
	PedSector size;
	struct dk_minfo dk_minfo;
	struct dk_geom dk_geom;

	PED_ASSERT(dev != NULL, return);
	PED_ASSERT(dev->open_count > 0, return);

	arch_specific = SOLARIS_SPECIFIC(dev);

	dev->sector_size = PED_SECTOR_SIZE_DEFAULT;
	dev->phys_sector_size = PED_SECTOR_SIZE_DEFAULT;

	/* this ioctl requires the raw device */
	if (ioctl(arch_specific->fd, DKIOCGMEDIAINFO, &dk_minfo) < 0) {
		printf("_device_get_length: ioctl DKIOCGMEDIAINFO failed\n");
		ped_exception_throw(
		    PED_EXCEPTION_BUG,
		    PED_EXCEPTION_CANCEL,
		    _("Unable to determine the size of %s (%s)."),
		    dev->path,
		    strerror(errno));
	} else {
		size = dk_minfo.dki_capacity;
		dev->length = size;
		dev->sector_size = dk_minfo.dki_lbsize;
		if (dev->sector_size != PED_SECTOR_SIZE_DEFAULT) {
			ped_exception_throw(
			    PED_EXCEPTION_WARNING,
			    PED_EXCEPTION_OK,
			    _("Device %s has a logical sector size of "
			    "%lld. Not all parts of GNU Parted support "
			    "this at the moment, and the working code "
			    "is HIGHLY EXPERIMENTAL.\n"),
			    dev->path, dev->sector_size);
		}
		if (size > 0) {
			return;
		}
	}

	/*
	 * On some disks DKIOCGMEDIAINFO doesn't work, it returns 0,
	 * so try DKIOCG_PHYGEOM next.
	 */
	/* this ioctl requires the raw device */
	if (ioctl(arch_specific->fd, DKIOCG_PHYGEOM, &dk_geom) < 0) {
		printf("_device_get_length: ioctl DKIOCG_PHYGEOM failed\n");
		ped_exception_throw(
		    PED_EXCEPTION_BUG,
		    PED_EXCEPTION_CANCEL,
		    _("Unable to determine the size of %s (%s)."),
		    dev->path, strerror(errno));

		return;
	}

	/*
	 * XXX For large disks, I am adding 16064 to the size of the disk.
	 * Solaris underreports the size of the disk, because it rounds down to
	 * a multiple of 16065. This causes a problem with Vista because Vista
	 * creates a partition that occupies the whole disk, including the
	 * blocks at the end of the disk that Solaris loses.
	 */
	if (dk_geom.dkg_nhead == 255 && dk_geom.dkg_nsect == 63) {
		size = ((PedSector) dk_geom.dkg_pcyl *
		    (255 * 63)) + ((255*63)-1);
	} else {
		size = (PedSector) dk_geom.dkg_pcyl *
		    dk_geom.dkg_nhead * dk_geom.dkg_nsect;
	}

	dev->length = size;
}

static int
_device_probe_geometry(PedDevice* dev)
{
	SolarisSpecific* arch_specific;
	struct stat dev_stat;
	struct dk_geom dk_geom;

	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(dev->open_count > 0, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	_device_set_length_and_sector_size(dev);
	if (dev->length == 0) {
		printf("_device_probe_geometry: _device_get_length = 0\n");
		return (0);
	}

	dev->bios_geom.sectors = 63;
	dev->bios_geom.heads = 255;
	dev->bios_geom.cylinders = dev->length / (63 * 255);
	if ((ioctl(arch_specific->fd, DKIOCG_PHYGEOM, &dk_geom) >= 0) &&
	    dk_geom.dkg_nsect && dk_geom.dkg_nhead) {
		dev->hw_geom.sectors = dk_geom.dkg_nsect;
		dev->hw_geom.heads = dk_geom.dkg_nhead;
		dev->hw_geom.cylinders = dk_geom.dkg_pcyl;
	} else {
		perror("_device_probe_geometry: DKIOCG_PHYGEOM");
		dev->hw_geom = dev->bios_geom;
	}

	return (1);
}

static int
init_ide(PedDevice *dev)
{
	struct stat dev_stat;

	PED_ASSERT(dev != NULL, return (0));

	if (!_device_stat(dev, &dev_stat)) {
		printf("init_ide: _device_stat failed\n");
		goto error;
	}
	if (!ped_device_open(dev)) {
		printf("init_ide: ped_device_open failed\n");
		goto error;
	}
	if (!_device_probe_geometry(dev)) {
		printf("init_ide: _device_probe_geometry failed\n");
		goto error_close_dev;
	}

	ped_device_close(dev);
	return (1);

error_close_dev:
	ped_device_close(dev);
error:
	return (0);
}

static PedDevice*
solaris_new(const char *path)
{
	PedDevice* dev;

	PED_ASSERT(path != NULL, return (NULL));

	dev = (PedDevice*) ped_malloc(sizeof (PedDevice));
	if (!dev)
		goto error;

	dev->path = strdup(path);
	if (!dev->path)
		goto error_free_dev;

	dev->arch_specific
	    = (SolarisSpecific*) ped_malloc(sizeof (SolarisSpecific));
	if (!dev->arch_specific)
		goto error_free_path;

	dev->open_count = 0;
	dev->read_only = 0;
	dev->external_mode = 0;
	dev->dirty = 0;
	dev->boot_dirty = 0;
	dev->model = strdup("Generic Ide");
	dev->type = PED_DEVICE_IDE;
	if (!init_ide(dev)) {
		goto error_free_arch_specific;
	}

	return (dev);

error_free_arch_specific:
	ped_free(dev->arch_specific);
	ped_free(dev->model);
error_free_path:
	ped_free(dev->path);
error_free_dev:
	ped_free(dev);
error:
	return (NULL);
}

static void
solaris_destroy(PedDevice* dev)
{
	PED_ASSERT(dev != NULL, return);

	ped_free(dev->arch_specific);
	ped_free(dev->model);
	ped_free(dev->path);
	ped_free(dev);
}

/*
 * This function constructs the Solaris device name for
 * partition num on a disk given the *p0 device for that disk.
 * For example: partition 2 of /dev/dsk/c0d0p0 becomes /dev/dsk/c0d0p2.
 */
static char *
_device_get_part_path(PedDevice* dev, int num)
{
	int path_len = strlen(dev->path);
	int result_len = path_len + 16;
	char *result;

	PED_ASSERT(dev != NULL, return (NULL));
	PED_ASSERT(num >= 1, return (NULL));

	result = (char *)ped_malloc(result_len);
	if (!result)
		return (NULL);

	strncpy(result, dev->path, result_len);
	if (path_len > 10 && result[path_len - 2] == 'p' &&
	    result[path_len - 1] == '0') {
		(void) snprintf(result + path_len - 1,
		    result_len - path_len + 1, "%d", num);
	} else {
		(void) snprintf(result, result_len, "partition %d", num);
	}

	return (result);
}

static struct swaptable *
getswapentries(void)
{
	register struct swaptable *st;
	register struct swapent *swapent;
	int	i, num;
	char	fullpathname[MAXPATHLEN];

	/*
	 * get the number of swap entries
	 */
	if ((num = swapctl(SC_GETNSWP, (void *)NULL)) == -1) {
		perror("getswapentries: swapctl SC_GETNSWP");
		return (NULL);
	}
	if (num == 0)
		return (NULL);
	if ((st = (swaptbl_t *)malloc(num * sizeof (swapent_t) + sizeof (int)))
	    == NULL) {
		printf("getswapentries: malloc 1 failed.\n");
		return (NULL);
	}
	swapent = st->swt_ent;
	for (i = 0; i < num; i++, swapent++) {
		if ((swapent->ste_path = malloc(MAXPATHLEN)) == NULL) {
			printf("getswapentries: malloc 2 failed.\n");
			goto error;
		}
	}
	st->swt_n = num;
	if ((num = swapctl(SC_LIST, (void *)st)) == -1) {
		perror("getswapentries: swapctl SC_LIST");
		goto error;
	}
	swapent = st->swt_ent;
	for (i = 0; i < num; i++, swapent++) {
		if (*swapent->ste_path != '/') {
			printf("getswapentries: %s\n", swapent->ste_path);
			(void) snprintf(fullpathname, sizeof (fullpathname),
			    "/dev/%s", swapent->ste_path);
			(void) strcpy(swapent->ste_path, fullpathname);
		}
	}

	return (st);

error:
	free(st);
	return (NULL);
}

static void
freeswapentries(st)
struct swaptable *st;
{
	register struct swapent *swapent;
	int i;

	swapent = st->swt_ent;
	for (i = 0; i < st->swt_n; i++, swapent++)
		free(swapent->ste_path);
	free(st);
}

/*
 *  function getpartition:
 */
static int
getpartition(PedDevice* dev, char *pathname)
{
	SolarisSpecific* arch_specific;
	int		mfd;
	struct dk_cinfo dkinfo;
	struct dk_cinfo cur_disk_dkinfo;
	struct stat	stbuf;
	char		raw_device[MAXPATHLEN];
	int		found = -1;

	PED_ASSERT(dev != NULL, return (found));
	PED_ASSERT(pathname != NULL, return (found));

	arch_specific = SOLARIS_SPECIFIC(dev);

	/*
	 * Map the block device name to the raw device name.
	 * If it doesn't appear to be a device name, skip it.
	 */
	if (strncmp(pathname, "/dev/", 5))
		return (found);
	(void) strcpy(raw_device, "/dev/r");
	(void) strcat(raw_device, pathname + strlen("/dev/"));
	/*
	 * Determine if this appears to be a disk device.
	 * First attempt to open the device.  If if fails, skip it.
	 */
	if ((mfd = open(raw_device, O_RDWR | O_NDELAY)) < 0) {
		return (found);
	}
	if (fstat(mfd, &stbuf) == -1) {
		perror("getpartition: fstat raw_device");
		(void) close(mfd);
		return (found);
	}
	/*
	 * Must be a character device
	 */
	if (!S_ISCHR(stbuf.st_mode)) {
		printf("getpartition: not character device\n");
		(void) close(mfd);
		return (found);
	}
	/*
	 * Attempt to read the configuration info on the disk.
	 */
	if (ioctl(mfd, DKIOCINFO, &dkinfo) < 0) {
		perror("getpartition: ioctl DKIOCINFO raw_device");
		(void) close(mfd);
		return (found);
	}
	/*
	 * Finished with the opened device
	 */
	(void) close(mfd);

	/*
	 * Now get the info about the current disk
	 */
	if (ioctl(arch_specific->fd, DKIOCINFO, &cur_disk_dkinfo) < 0) {
		(void) close(mfd);
		return (found);
	}

	/*
	 * If it's not the disk we're interested in, it doesn't apply.
	 */
	if (cur_disk_dkinfo.dki_ctype != dkinfo.dki_ctype ||
	    cur_disk_dkinfo.dki_cnum != dkinfo.dki_cnum ||
	    cur_disk_dkinfo.dki_unit != dkinfo.dki_unit ||
	    strcmp(cur_disk_dkinfo.dki_dname, dkinfo.dki_dname) != 0) {
		return (found);
	}

	/*
	 *  Extract the partition that is mounted.
	 */
	return (PARTITION(stbuf.st_rdev));
}

/*
 * This Routine checks to see if there are partitions used for swapping overlaps
 * a given portion of a disk. If the start parameter is < 0, it means
 * that the entire disk should be checked
 */
static int
checkswap(PedDevice* dev, diskaddr_t start, diskaddr_t end)
{
	SolarisSpecific* arch_specific;
	struct extvtoc	extvtoc;
	struct swaptable *st;
	struct swapent	*swapent;
	int		i;
	int		found = 0;
	int		part;
	diskaddr_t	p_start;
	diskaddr_t	p_size;

	PED_ASSERT(dev != NULL, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	if (ioctl(arch_specific->fd, DKIOCGEXTVTOC, &extvtoc) == -1) {
		return (0);
	}

	/*
	 * check for swap entries
	 */
	st = getswapentries();
	/*
	 * if there are no swap entries return.
	 */
	if (st == (struct swaptable *)NULL)
		return (0);
	swapent = st->swt_ent;
	for (i = 0; i < st->swt_n; i++, swapent++) {
		if ((part = getpartition(dev, swapent->ste_path)) != -1) {
			if (start == UINT_MAX64) {
				found = -1;
				break;
			}
			p_start = extvtoc.v_part[part].p_start;
			p_size = extvtoc.v_part[part].p_size;
			if (start >= p_start + p_size || end < p_start) {
					continue;
			}
			found = -1;
			break;
		}
	}
	freeswapentries(st);

	return (found);
}

/*
 * Determines if there are partitions that are a part of an SVM, VxVM, zpool
 * volume or a live upgrade device,  overlapping a given portion of a disk.
 * Mounts and swap devices are checked in legacy format code.
 */
static int
checkdevinuse(PedDevice *dev, diskaddr_t start, diskaddr_t end, int print)
{
	int 		error;
	int 		found = 0;
	int		check = 0;
	int 		i;
	int		part = 0;
	uint64_t	slice_start, slice_size;
	dm_descriptor_t	*slices = NULL;
	nvlist_t	*attrs = NULL;
	char		*usage;
	char		*name;
	char		cur_disk_path[MAXPATHLEN];
	char		*pcur_disk_path;

	PED_ASSERT(dev != NULL, return (found));

	/*
	 * Truncate the characters following "d*", such as "s*" or "p*"
	 */
	strcpy(cur_disk_path, dev->path);
	pcur_disk_path = basename(cur_disk_path);
	name = strrchr(pcur_disk_path, 'd');
	if (name) {
		name++;
		for (; (*name <= '9') && (*name >= '0'); name++)
			;
		*name = (char)0;
	}

	/*
	 * For format, we get basic 'in use' details from libdiskmgt. After
	 * that we must do the appropriate checking to see if the 'in use'
	 * details require a bit of additional work.
	 */

	dm_get_slices(pcur_disk_path, &slices, &error);
	if (error) {
		/*
		 * If ENODEV, it actually means the device is not in use.
		 * We will return (0) without displaying error.
		 */
		if (error != ENODEV) {
			printf("checkdevinuse: Error1 occurred with device in "
			    "use checking: %s\n", strerror(error));
			return (found);
		}
	}
	if (slices == NULL)
		return (found);

	for (i = 0; slices[i] != NULL; i++) {
		/*
		 * If we are checking the whole disk
		 * then any and all in use data is
		 * relevant.
		 */
		if (start == UINT_MAX64) {
			name = dm_get_name(slices[i], &error);
			if (error != 0 || !name) {
				printf("checkdevinuse: Error2 occurred with "
				    "device in use checking: %s\n",
				    strerror(error));
				continue;
			}
			printf("checkdevinuse: name1 %s\n", name);
			if (dm_inuse(name, &usage, DM_WHO_FORMAT, &error) ||
			    error) {
				if (error != 0) {
					dm_free_name(name);
					name = NULL;
					printf("checkdevinuse: Error3 "
					    "occurred with device "
					    "in use checking: %s\n",
					    strerror(error));
					continue;
				}
				dm_free_name(name);
				name = NULL;
				/*
				 * If this is a dump device, then it is
				 * a failure. You cannot format a slice
				 * that is a dedicated dump device.
				 */

				if (strstr(usage, DM_USE_DUMP)) {
					if (print) {
						printf(usage);
						free(usage);
					}
					dm_free_descriptors(slices);
					return (1);
				}
				/*
				 * We really found a device that is in use.
				 * Set 'found' for the return value.
				 */
				found ++;
				check = 1;
				if (print) {
					printf(usage);
					free(usage);
				}
			}
		} else {
			/*
			 * Before getting the in use data, verify that the
			 * current slice is within the range we are checking.
			 */
			attrs = dm_get_attributes(slices[i], &error);
			if (error) {
				printf("checkdevinuse: Error4 occurred with "
				    "device in use checking: %s\n",
				    strerror(error));
				continue;
			}
			if (attrs == NULL) {
				continue;
			}

			(void) nvlist_lookup_uint64(attrs, DM_START,
			    &slice_start);
			(void) nvlist_lookup_uint64(attrs, DM_SIZE,
			    &slice_size);
			if (start >= (slice_start + slice_size) ||
			    (end < slice_start)) {
				nvlist_free(attrs);
				attrs = NULL;
				continue;
			}
			name = dm_get_name(slices[i], &error);
			if (error != 0 || !name) {
				printf("checkdevinuse: Error5 occurred with "
				    "device in use checking: %s\n",
				    strerror(error));
				nvlist_free(attrs);
				attrs = NULL;
				continue;
			}
			if (dm_inuse(name, &usage,
			    DM_WHO_FORMAT, &error) || error) {
				if (error != 0) {
					dm_free_name(name);
					name = NULL;
					printf("checkdevinuse: Error6 "
					    "occurred with device "
					    "in use checking: %s\n",
					    strerror(error));
					nvlist_free(attrs);
					attrs = NULL;
					continue;
				}
				dm_free_name(name);
				name = NULL;
				/*
				 * If this is a dump device, then it is
				 * a failure. You cannot format a slice
				 * that is a dedicated dump device.
				 */
				if (strstr(usage, DM_USE_DUMP)) {
					if (print) {
						printf(usage);
						free(usage);
					}
					dm_free_descriptors(slices);
					nvlist_free(attrs);
					return (1);
				}
				/*
				 * We really found a device that is in use.
				 * Set 'found' for the return value.
				 */
				found ++;
				check = 1;
				if (print) {
					printf(usage);
					free(usage);
				}
			}
		}
		/*
		 * If check is set it means we found a slice(the current slice)
		 * on this device in use in some way.  We potentially want
		 * to check this slice when labeling is requested.
		 */
		if (check) {
			name = dm_get_name(slices[i], &error);
			if (error != 0 || !name) {
				printf("checkdevinuse: Error7 occurred with "
				    "device in use checking: %s\n",
				    strerror(error));
				nvlist_free(attrs);
				attrs = NULL;
				continue;
			}
			part = getpartition(dev, name);
			dm_free_name(name);
			name = NULL;
			check = 0;
		}
		/*
		 * If we have attributes then we have successfully
		 * found the slice we were looking for and we also
		 * know this means we are not searching the whole
		 * disk so break out of the loop
		 * now.
		 */
		if (attrs) {
			nvlist_free(attrs);
			break;
		}
	}

	if (slices) {
		dm_free_descriptors(slices);
	}

	return (found);
}

/*
 * This routine checks to see if there are mounted partitions overlapping
 * a given portion of a disk.  If the start parameter is < 0, it means
 * that the entire disk should be checked.
 */
static int
checkmount(PedDevice* dev, diskaddr_t start, diskaddr_t end)
{
	SolarisSpecific* arch_specific;
	struct extvtoc	extvtoc;
	diskaddr_t	p_start;
	diskaddr_t	p_size;
	FILE		*fp;
	int		found = 0;
	int		part;
	struct mnttab	mnt_record;
	struct mnttab	*mp = &mnt_record;

	PED_ASSERT(dev != NULL, return (found));

	arch_specific = SOLARIS_SPECIFIC(dev);

	if (ioctl(arch_specific->fd, DKIOCGEXTVTOC, &extvtoc) == -1) {
		return (0);
	}

	/*
	 * Open the mount table.
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		printf("checkmount: Unable to open mount table.\n");
		return (0);
	}
	/*
	 * Loop through the mount table until we run out of entries.
	 */
	while ((getmntent(fp, mp)) != -1) {

		if ((part = getpartition(dev, mp->mnt_special)) == -1)
			continue;

		/*
		 * It's a mount on the disk we're checking.  If we are
		 * checking whole disk, then we found trouble.  We can
		 * quit searching.
		 */
		if (start == UINT_MAX64) {
			found = -1;
			break;
		}

		/*
		 * If the partition overlaps the zone we're checking,
		 * then we found trouble.  We can quit searching.
		 */
		p_start = extvtoc.v_part[part].p_start;
		p_size = extvtoc.v_part[part].p_size;
		if (start >= p_start + p_size || end < p_start) {
			continue;
		}
		found = -1;
		break;
	}
	/*
	 * Close down the mount table.
	 */
	(void) fclose(fp);

	return (found);
}

/*
 * Return 1 if the device is busy, 0 otherwise.
 */
static int
solaris_is_busy(PedDevice* dev)
{
	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(dev->open_count > 0, return (0));

	if (checkmount(dev, (diskaddr_t)-1, (diskaddr_t)-1))
		return (1);

	if (checkswap(dev, (diskaddr_t)-1, (diskaddr_t)-1))
		return (1);

	if (checkdevinuse(dev, (diskaddr_t)-1, (diskaddr_t)-1, 1))
		return (1);

	return (0);
}

/*
 * This will accept a dev->path that looks like this:
 *	/devices/pci@0,0/pci-ide@1f,2/ide@0/cmdk@0,0:q
 *	/devices/pci@0,0/pci-ide@1f,2/ide@0/cmdk@0,0:q,raw
 * or this:
 *	/dev/dsk/c0d0p0
 *	/dev/rdsk/c0d0p0
 * It has to open the raw device, so it converts to it locally, if necessary.
 */
static int
solaris_open(PedDevice* dev)
{
	SolarisSpecific* arch_specific;
	char rawname[MAXPATHLEN];

	PED_ASSERT(dev != NULL, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	/*
	 * Convert to the raw device, unless it already is.
	 */
	if (strncmp(dev->path, "/devices", 8) == 0) {
		if (strncmp(&dev->path[strlen(dev->path)-4], ",raw", 4)) {
			snprintf(rawname, sizeof (rawname), "%s,raw",
			    dev->path);
		} else {
			strcpy(rawname, dev->path);
		}
	} else {
		/*
		 * Assumes it is of the form: /dev/dsk/ or /dev/rdsk/
		 */
		if (strncmp(dev->path, "/dev/dsk/", 9) == 0) {
			snprintf(rawname, sizeof (rawname), "/dev/rdsk/%s",
			    &dev->path[9]);
		} else {
			strcpy(rawname, dev->path);
		}
	}

retry:
	arch_specific->fd = open(rawname, O_RDWR);

	if (arch_specific->fd == -1) {
		char *rw_error_msg = strerror(errno);

		arch_specific->fd = open(rawname, O_RDONLY);

		if (arch_specific->fd == -1) {
			printf("solaris_open: open(\"%s\") failed\n", rawname);
			if (ped_exception_throw(
			    PED_EXCEPTION_ERROR,
			    PED_EXCEPTION_RETRY_CANCEL,
			    _("Error opening %s: %s"),
			    rawname, strerror(errno)) != PED_EXCEPTION_RETRY) {
				return (0);
			} else {
				goto retry;
			}
		} else {
			ped_exception_throw(
			    PED_EXCEPTION_WARNING,
			    PED_EXCEPTION_OK,
			    _("Unable to open %s read-write (%s). %s has "
			    "been opened read-only."),
			    rawname, rw_error_msg, rawname);
			dev->read_only = 1;
		}
	} else {
		dev->read_only = 0;
	}

	return (1);
}

static int
solaris_refresh_open(PedDevice* dev)
{
	return (1);
}

static int
solaris_close(PedDevice* dev)
{
	SolarisSpecific* arch_specific;

	PED_ASSERT(dev != NULL, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	close(arch_specific->fd);
	return (1);
}

static int
_do_fsync(PedDevice* dev)
{
	SolarisSpecific*	arch_specific;
	int			status;
	PedExceptionOption	ex_status;

	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(dev->open_count > 0, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	while (1) {
		status = fsync(arch_specific->fd);
		if (status >= 0)
			break;

		ex_status = ped_exception_throw(
		    PED_EXCEPTION_ERROR,
		    PED_EXCEPTION_RETRY_IGNORE_CANCEL,
		    _("%s during fsync on %s"),
		    strerror(errno), dev->path);

		switch (ex_status) {
			case PED_EXCEPTION_IGNORE:
				return (1);

			case PED_EXCEPTION_RETRY:
				break;

			case PED_EXCEPTION_UNHANDLED:
				ped_exception_catch();
			case PED_EXCEPTION_CANCEL:
				return (0);
		}
	}
	return (1);
}

static int
solaris_refresh_close(PedDevice* dev)
{
	if (dev->dirty)
		_do_fsync(dev);
	return (1);
}

static int
_device_seek(const PedDevice* dev, PedSector sector)
{
	SolarisSpecific* arch_specific;

	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(dev->sector_size % PED_SECTOR_SIZE_DEFAULT == 0, return (0));
	PED_ASSERT(dev->open_count > 0, return (0));
	PED_ASSERT(!dev->external_mode, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	if (sizeof (off_t) < 8) {
		off64_t	pos = (off64_t)(sector * dev->sector_size);
		return (lseek64(arch_specific->fd, pos, SEEK_SET) == pos);
	} else {
		off_t pos = sector * dev->sector_size;
		return (lseek(arch_specific->fd, pos, SEEK_SET) == pos);
	}
}

static int
solaris_read(const PedDevice* dev, void* vbuffer, PedSector start,
    PedSector count)
{
	SolarisSpecific* arch_specific;
	int status;
	PedExceptionOption ex_status;
	size_t read_length = count * dev->sector_size;
	void *diobuf;
	char *buffer = vbuffer;

	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(dev->sector_size % PED_SECTOR_SIZE_DEFAULT == 0, return (0));
	PED_ASSERT(dev->open_count > 0, return (0));
	PED_ASSERT(!dev->external_mode, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	while (1) {
		if (_device_seek(dev, start))
			break;

		ex_status = ped_exception_throw(
		    PED_EXCEPTION_ERROR,
		    PED_EXCEPTION_RETRY_IGNORE_CANCEL,
		    _("%s during seek for read on %s"),
		    strerror(errno), dev->path);

		switch (ex_status) {
			case PED_EXCEPTION_IGNORE:
				return (1);

			case PED_EXCEPTION_RETRY:
				break;

			case PED_EXCEPTION_UNHANDLED:
				ped_exception_catch();
			case PED_EXCEPTION_CANCEL:
				return (0);
		}
	}

	diobuf = memalign(dev->sector_size, read_length);
	if (diobuf == NULL) {
		printf("solaris_read: cannot memalign %u\n", read_length);
		return (0);
	}

	while (1) {
		status = read(arch_specific->fd, diobuf, read_length);

		if (status > 0)
			memcpy(buffer, diobuf, status);

		if (status == read_length)
			break;

		if (status > 0) {
			printf("solaris_read: partial read %d of %d\n",
			    status, read_length);
			read_length -= status;
			buffer += status;
			continue;
		}

		ex_status = ped_exception_throw(
		    PED_EXCEPTION_ERROR,
		    PED_EXCEPTION_RETRY_IGNORE_CANCEL,
		    _("%s during read on %s"),
		    strerror(errno),
		    dev->path);

		switch (ex_status) {
			case PED_EXCEPTION_IGNORE:
				free(diobuf);
				return (1);

			case PED_EXCEPTION_RETRY:
				break;

			case PED_EXCEPTION_UNHANDLED:
				ped_exception_catch();
			case PED_EXCEPTION_CANCEL:
				free(diobuf);
				return (0);
		}
	}

	free(diobuf);

	return (1);
}

static int
solaris_write(PedDevice* dev, const void* buffer, PedSector start,
    PedSector count)
{
	SolarisSpecific* arch_specific;
	int status;
	PedExceptionOption ex_status;
	size_t write_length = count * dev->sector_size;
	char *diobuf;
	char *diobuf_start;

	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(dev->sector_size % PED_SECTOR_SIZE_DEFAULT == 0, return (0));
	PED_ASSERT(dev->open_count > 0, return (0));
	PED_ASSERT(!dev->external_mode, return (0));

	arch_specific = SOLARIS_SPECIFIC(dev);

	if (dev->read_only) {
		if (ped_exception_throw(
		    PED_EXCEPTION_ERROR,
		    PED_EXCEPTION_IGNORE_CANCEL,
		    _("Can't write to %s, because it is opened read-only."),
		    dev->path) != PED_EXCEPTION_IGNORE)
			return (0);
		else
			return (1);
	}

	while (1) {
		if (_device_seek(dev, start))
			break;

		ex_status = ped_exception_throw(
		    PED_EXCEPTION_ERROR, PED_EXCEPTION_RETRY_IGNORE_CANCEL,
		    _("%s during seek for write on %s"),
		    strerror(errno), dev->path);

		switch (ex_status) {
			case PED_EXCEPTION_IGNORE:
				return (1);

			case PED_EXCEPTION_RETRY:
				break;

			case PED_EXCEPTION_UNHANDLED:
				ped_exception_catch();
			case PED_EXCEPTION_CANCEL:
				return (0);
		}
	}

#ifdef READ_ONLY
	printf("solaris_write(\"%s\", %p, %d, %d)\n",
	    dev->path, buffer, (int)start, (int)count);
#else
	dev->dirty = 1;

	diobuf = memalign((size_t)PED_SECTOR_SIZE_DEFAULT, write_length);
	if (diobuf == NULL) {
		printf("solaris_write: cannot memalign %u\n", write_length);
		return (0);
	}

	memcpy(diobuf, buffer, write_length);
	diobuf_start = diobuf;
	while (1) {
		status = write(arch_specific->fd, diobuf, write_length);
		if (status == write_length)
			break;
		if (status > 0) {
			printf("solaris_write: partial write %d of %d\n",
			    status, write_length);
			write_length -= status;
			diobuf += status;
			continue;
		}

		ex_status = ped_exception_throw(
		    PED_EXCEPTION_ERROR,
		    PED_EXCEPTION_RETRY_IGNORE_CANCEL,
		    _("%s during write on %s"),
		    strerror(errno), dev->path);

		switch (ex_status) {
			case PED_EXCEPTION_IGNORE:
				free(diobuf_start);
				return (1);

			case PED_EXCEPTION_RETRY:
				break;

			case PED_EXCEPTION_UNHANDLED:
				ped_exception_catch();
			case PED_EXCEPTION_CANCEL:
				free(diobuf_start);
				return (0);
		}
	}
	free(diobuf_start);
#endif /* !READ_ONLY */

	return (1);
}


/*
 * returns the number of sectors that are ok.
 * This is never called. It would get called through ped_device_check().
 */
static PedSector
solaris_check(PedDevice* dev, void* buffer, PedSector start, PedSector count)
{
	SolarisSpecific* arch_specific;
	PedSector done;
	int status;
	void* diobuf;

	PED_ASSERT(dev != NULL, return (0LL));
	PED_ASSERT(dev->sector_size % PED_SECTOR_SIZE_DEFAULT == 0,
	    return (0LL));
	PED_ASSERT(dev->open_count > 0, return (0LL));
	PED_ASSERT(!dev->external_mode, return (0LL));

	printf("solaris_check: start %lld count %lld\n", start, count);

	arch_specific = SOLARIS_SPECIFIC(dev);

	if (!_device_seek(dev, start))
		return (0LL);

	diobuf = memalign(PED_SECTOR_SIZE_DEFAULT, count * dev->sector_size);
	if (diobuf == NULL) {
		printf("solaris_check: cannot memalign %u\n",
		    count * dev->sector_size);
		return (0LL);
	}

	for (done = 0; done < count; done += status / dev->sector_size) {
		status = read(arch_specific->fd, diobuf,
		    (size_t)((count - done) * dev->sector_size));
		if (status < 0)
			break;
	}
	free(diobuf);

	return (done);
}

static int
solaris_sync(PedDevice* dev)
{
	PED_ASSERT(dev != NULL, return (0));
	PED_ASSERT(!dev->external_mode, return (0));

	if (dev->read_only)
		return (1);
	if (!_do_fsync(dev))
		return (0);
	return (1);
}

/*
 * Returns all *p0 block devices.
 * open the raw device so ioctl works.
 */
static void
solaris_probe_all()
{
	DIR *dir;
	struct dirent *dp;
	char *pname;
	char block_path[256];
	char raw_path[256];
	struct stat buffer;
	int fd;

	dir = opendir("/dev/dsk");
	while ((dp = readdir(dir)) != NULL) {

		pname = dp->d_name + strlen(dp->d_name) - 2;
		if (strcmp(pname, "p0") == 0) {

			strncpy(block_path, "/dev/dsk/", sizeof (block_path));
			strncat(block_path, dp->d_name, sizeof (block_path));

			strncpy(raw_path, "/dev/rdsk/", sizeof (raw_path));
			strncat(raw_path, dp->d_name, sizeof (raw_path));

			if (stat(block_path, &buffer) == 0) {

				if ((fd = open(raw_path, O_RDONLY)) < 0) {
					continue;
				}

#ifdef DONT_ALLOW_REMOVEABLE_DEVICES
				int n = 0;
				if (ioctl(fd, DKIOCREMOVABLE, &n) < 0) {
					char msg[MAXPATHLEN];
					snprintf(msg, sizeof (msg),
					    "ioctl(\"%s\", DKIOCREMOVABLE)",
					    raw_path);
					perror(msg);
				} else if (!n) {
					/*
					 * Not a removable device
					 * printf("solaris_probe_all: %s\n",
					 * block_path);
					 */
				}
#endif /* DONT_ALLOW_REMOVEABLE_DEVICES */

				_ped_device_probe(block_path);
				close(fd);
			}
		}
	}
}

static char *
solaris_partition_get_path(const PedPartition* part)
{
	return (_device_get_part_path(part->disk->dev, part->num));
}

/*
 * Returns 1 if the partition is busy in some way, 0 otherwise.
 */
static int
solaris_partition_is_busy(const PedPartition* part)
{
	int r1, r2, r3;

	PED_ASSERT(part != NULL, return (0));

	r1 = checkmount(part->geom.dev, part->geom.start, part->geom.end);
	r2 = checkswap(part->geom.dev, part->geom.start, part->geom.end);
	r3 = checkdevinuse(part->geom.dev, part->geom.start, part->geom.end, 1);

	if (r1 || r2 || r3)
		return (1);

	return (0);
}

static int
solaris_disk_commit(PedDisk* disk)
{
	return (1);
}

static PedDeviceArchOps solaris_dev_ops = {
	._new =		 solaris_new,
	.destroy =	 solaris_destroy,
	.is_busy =	 solaris_is_busy,
	.open =		 solaris_open,
	.refresh_open =	 solaris_refresh_open,
	.close =	 solaris_close,
	.refresh_close = solaris_refresh_close,
	.read =		 solaris_read,
	.write =	 solaris_write,
	.check =	 solaris_check,
	.sync =		 solaris_sync,
	.sync_fast =	 solaris_sync,
	.probe_all =	 solaris_probe_all
};

PedDiskArchOps solaris_disk_ops = {
	.partition_get_path =	solaris_partition_get_path,
	.partition_is_busy =	solaris_partition_is_busy,
	.disk_commit =		solaris_disk_commit
};

PedArchitecture ped_solaris_arch = {
	.dev_ops =	&solaris_dev_ops,
	.disk_ops =	&solaris_disk_ops
};
