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



/*
 * This file contains miscellaneous device validation routines.
 */

#include "global.h"
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/autoconf.h>

#include <signal.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#include <sys/modctl.h>
#include <ctype.h>
#include <libdiskmgt.h>
#include <libnvpair.h>
#include "misc.h"
#include "checkdev.h"
#include <sys/efi_partition.h>

/* Function prototypes */
#ifdef	__STDC__

static struct	swaptable *getswapentries(void);
static void	freeswapentries(struct swaptable *);
static int	getpartition(char *pathname);
static int	checkpartitions(int bm_mounted);

#else	/* __STDC__ */

static struct swaptable *getswapentries();
static void freeswapentries();
static int	getpartition();
static int	checkpartitions();

#endif	/* __STDC__ */

extern char	*getfullname();

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
		err_print("swapctl error ");
		fullabort();
	}
	if (num == 0)
		return (NULL);
	if ((st = (swaptbl_t *)malloc(num * sizeof (swapent_t) + sizeof (int)))
	    == NULL) {
		err_print("getswapentries: malloc  failed.\n");
		fullabort();
	}
	swapent = st->swt_ent;
	for (i = 0; i < num; i++, swapent++) {
		if ((swapent->ste_path = malloc(MAXPATHLEN)) == NULL) {
			err_print("getswapentries: malloc  failed.\n");
			fullabort();
		}
	}
	st->swt_n = num;
	if ((num = swapctl(SC_LIST, (void *)st)) == -1) {
		err_print("swapctl error ");
		fullabort();
	}
	swapent = st->swt_ent;
	for (i = 0; i < num; i++, swapent++) {
		if (*swapent->ste_path != '/') {
			(void) snprintf(fullpathname, sizeof (fullpathname),
			    "/dev/%s", swapent->ste_path);
			(void) strcpy(swapent->ste_path, fullpathname);
		}
	}
	return (st);
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
getpartition(pathname)
char *pathname;
{
	int		mfd;
	struct dk_cinfo dkinfo;
	struct stat	stbuf;
	char		raw_device[MAXPATHLEN];
	int		found = -1;

	/*
	 * Map the block device name to the raw device name.
	 * If it doesn't appear to be a device name, skip it.
	 */
	if (match_substr(pathname, "/dev/") == 0)
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
	/*
	 * Must be a character device
	 */
	if (fstat(mfd, &stbuf) == -1 || !S_ISCHR(stbuf.st_mode)) {
		(void) close(mfd);
		return (found);
	}
	/*
	 * Attempt to read the configuration info on the disk.
	 */
	if (ioctl(mfd, DKIOCINFO, &dkinfo) < 0) {
		(void) close(mfd);
		return (found);
	}
	/*
	 * Finished with the opened device
	 */
	(void) close(mfd);

	/*
	 * If it's not the disk we're interested in, it doesn't apply.
	 */
	if (cur_disk->disk_dkinfo.dki_ctype != dkinfo.dki_ctype ||
		cur_disk->disk_dkinfo.dki_cnum != dkinfo.dki_cnum ||
		cur_disk->disk_dkinfo.dki_unit != dkinfo.dki_unit ||
		strcmp(cur_disk->disk_dkinfo.dki_dname,
				dkinfo.dki_dname) != 0) {
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
int
checkswap(start, end)
	diskaddr_t start, end;
{
	struct swaptable *st;
	struct swapent *swapent;
	int		i;
	int		found = 0;
	struct dk_map32	*map;
	int		part;

	/*
	 * If we are only checking part of the disk, the disk must
	 * have a partition map to check against.  If it doesn't,
	 * we hope for the best.
	 */
	if (cur_parts == NULL)
		return (0);

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
		if ((part = getpartition(swapent->ste_path)) != -1) {
			if (start == UINT_MAX64) {
				found = -1;
				break;
			}
			map = &cur_parts->pinfo_map[part];
			if ((start >= (int)(map->dkl_cylno * spc() +
				map->dkl_nblk)) || (end < (int)(map->dkl_cylno
							* spc()))) {
					continue;
			}
			found = -1;
			break;
		};
	}
	freeswapentries(st);
	/*
	 * If we found trouble and we're running from a command file,
	 * quit before doing something we really regret.
	 */

	if (found && option_f) {
		err_print(
"Operation on disks being used for swapping must be interactive.\n");
		cmdabort(SIGINT);
	}

	return (found);


}
/*
 * Determines if there are partitions that are a part of an SVM, VxVM, zpool
 * volume or a live upgrade device,  overlapping a given portion of a disk.
 * Mounts and swap devices are checked in legacy format code.
 */
int
checkdevinuse(char *cur_disk_path, diskaddr_t start, diskaddr_t end, int print,
	int check_label)
{

	int		error;
	int		found = 0;
	int		check = 0;
	int		i;
	int		bm_inuse = 0;
	int		part = 0;
	uint64_t	slice_start, slice_size;
	dm_descriptor_t	*slices = NULL;
	nvlist_t	*attrs = NULL;
	char		*usage;
	char		*name;

	/*
	 * If the user does not want to do in use checking, return immediately.
	 * Normally, this is handled in libdiskmgt. For format, there is more
	 * processing required, so we want to bypass the in use checking
	 * here.
	 */

	if (NOINUSE_SET)
		return (0);

	/*
	 * Skip if it is not a real disk
	 *
	 * There could be two kinds of strings in cur_disk_path
	 * One starts with c?t?d?, while the other is a absolute path of a
	 * block device file.
	 */

	if (*cur_disk_path != 'c') {
		struct	stat	stbuf;
		char		majorname[16];
		major_t		majornum;

		(void) stat(cur_disk_path, &stbuf);
		majornum = major(stbuf.st_rdev);
		(void) modctl(MODGETNAME, majorname, sizeof (majorname),
		    &majornum);

		if (strcmp(majorname, "sd"))
			if (strcmp(majorname, "ssd"))
				if (strcmp(majorname, "cmdk"))
					return (0);
	}

	/*
	 * Truncate the characters following "d*", such as "s*" or "p*"
	 */
	cur_disk_path = basename(cur_disk_path);
	name = strrchr(cur_disk_path, 'd');
	if (name) {
		name++;
		for (; (*name <= '9') && (*name >= '0'); name++) {
		}
		*name = (char)0;
	}


	/*
	 * For format, we get basic 'in use' details from libdiskmgt. After
	 * that we must do the appropriate checking to see if the 'in use'
	 * details require a bit of additional work.
	 */

	dm_get_slices(cur_disk_path, &slices, &error);
	if (error) {
		/*
		 * If ENODEV, it actually means the device is not in use.
		 * We will return 0 without displaying error.
		 */
		if (error != ENODEV) {
			err_print("Error occurred with device in use"
			    "checking: %s\n", strerror(error));
			return (found);
		}
	}
	if (slices == NULL)
		return (found);

	for (i = 0; slices[i] != 0; i++) {
		/*
		 * If we are checking the whole disk
		 * then any and all in use data is
		 * relevant.
		 */
		if (start == UINT_MAX64) {
			name = dm_get_name(slices[i], &error);
			if (error != 0 || !name) {
				err_print("Error occurred with device "
				    "in use checking: %s\n", strerror(error));
				continue;
			}
			if (dm_inuse(name, &usage, DM_WHO_FORMAT, &error) ||
			    error) {
				if (error != 0) {
					dm_free_name(name);
					name = NULL;
					err_print("Error occurred with "
					    "device in use checking: "
					    "%s\n", strerror(error));
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
						err_print(usage);
						free(usage);
					}
					dm_free_descriptors(slices);
					return (1);
				}
				/*
				 * We really found a device that is in use.
				 * Set 'found' for the return value, and set
				 * 'check' to indicate below that we must
				 * get the partition number to set bm_inuse
				 * in the event we are trying to label this
				 * device. check_label is set when we are
				 * checking modifications for in use slices
				 * on the device.
				 */
				found ++;
				check = 1;
				if (print) {
					err_print(usage);
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
				err_print("Error occurred with device in use "
				    "checking: %s\n", strerror(error));
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
				err_print("Error occurred with device "
				    "in use checking: %s\n", strerror(error));
				nvlist_free(attrs);
				attrs = NULL;
				continue;
			}
			if (dm_inuse(name, &usage,
			    DM_WHO_FORMAT, &error) || error) {
				if (error != 0) {
					dm_free_name(name);
					name = NULL;
					err_print("Error occurred with "
					    "device in use checking: "
					    "%s\n", strerror(error));
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
						err_print(usage);
						free(usage);
					}
					dm_free_descriptors(slices);
					nvlist_free(attrs);
					return (1);
				}
				/*
				 * We really found a device that is in use.
				 * Set 'found' for the return value, and set
				 * 'check' to indicate below that we must
				 * get the partition number to set bm_inuse
				 * in the event we are trying to label this
				 * device. check_label is set when we are
				 * checking modifications for in use slices
				 * on the device.
				 */
				found ++;
				check = 1;
				if (print) {
					err_print(usage);
					free(usage);
				}
			}
		}
		/*
		 * If check is set it means we found a slice(the current slice)
		 * on this device in use in some way.  We potentially want
		 * to check this slice when labeling is
		 * requested. We set bm_inuse with this partition value
		 * for use later if check_label was set when called.
		 */
		if (check) {
			name = dm_get_name(slices[i], &error);
			if (error != 0 || !name) {
				err_print("Error occurred with device "
				    "in use checking: %s\n", strerror(error));
				nvlist_free(attrs);
				attrs = NULL;
				continue;
			}
			part = getpartition(name);
			dm_free_name(name);
			name = NULL;
			if (part != -1) {
				bm_inuse |= 1 << part;
			}
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

	/*
	 * The user is trying to label the disk. We have to do special
	 * checking here to ensure they are not trying to modify a slice
	 * that is in use in an incompatible way.
	 */
	if (check_label && bm_inuse) {
		/*
		 * !0 indicates that we found a
		 * problem. In this case, we have overloaded
		 * the use of checkpartitions to work for
		 * in use devices. bm_inuse is representative
		 * of the slice that is in use, not that
		 * is mounted as is in the case of the normal
		 * use of checkpartitions.
		 *
		 * The call to checkpartitions will return !0 if
		 * we are trying to shrink a device that we have found
		 * to be in use above.
		 */
		return (checkpartitions(bm_inuse));
	}

	return (found);
}
/*
 * This routine checks to see if there are mounted partitions overlapping
 * a given portion of a disk.  If the start parameter is < 0, it means
 * that the entire disk should be checked.
 */
int
checkmount(start, end)
	diskaddr_t	start, end;
{
	FILE		*fp;
	int		found = 0;
	struct dk_map32	*map;
	int		part;
	struct mnttab	mnt_record;
	struct mnttab	*mp = &mnt_record;

	/*
	 * If we are only checking part of the disk, the disk must
	 * have a partition map to check against.  If it doesn't,
	 * we hope for the best.
	 */
	if (cur_parts == NULL)
		return (0);

	/*
	 * Lock out interrupts because of the mntent protocol.
	 */
	enter_critical();
	/*
	 * Open the mount table.
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		err_print("Unable to open mount table.\n");
		fullabort();
	}
	/*
	 * Loop through the mount table until we run out of entries.
	 */
	while ((getmntent(fp, mp)) != -1) {

		if ((part = getpartition(mp->mnt_special)) == -1)
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
		map = &cur_parts->pinfo_map[part];
		if ((start >= (int)(map->dkl_cylno * spc() + map->dkl_nblk)) ||
			(end < (int)(map->dkl_cylno * spc()))) {
			continue;
		}
		found = -1;
		break;
	}
	/*
	 * Close down the mount table.
	 */
	(void) fclose(fp);
	exit_critical();

	/*
	 * If we found trouble and we're running from a command file,
	 * quit before doing something we really regret.
	 */

	if (found && option_f) {
		err_print("Operation on mounted disks must be interactive.\n");
		cmdabort(SIGINT);
	}
	/*
	 * Return the result.
	 */
	return (found);
}

int
check_label_with_swap()
{
	int			i;
	struct swaptable *st;
	struct swapent *swapent;
	int	part;
	int	bm_swap = 0;

	/*
	 * If we are only checking part of the disk, the disk must
	 * have a partition map to check against.  If it doesn't,
	 * we hope for the best.
	 */
	if (cur_parts == NULL)
		return (0);	/* Will be checked later */

	/*
	 * Check for swap entries
	 */
	st = getswapentries();
	/*
	 * if there are no swap entries return.
	 */
	if (st == (struct swaptable *)NULL)
		return (0);
	swapent = st->swt_ent;
	for (i = 0; i < st->swt_n; i++, swapent++)
		if ((part = getpartition(swapent->ste_path)) != -1)
				bm_swap |= (1 << part);
	freeswapentries(st);

	return (checkpartitions(bm_swap));
}

/*
 * Check the new label with the existing label on the disk,
 * to make sure that any mounted partitions are not being
 * affected by writing the new label.
 */
int
check_label_with_mount()
{
	FILE			*fp;
	int			part;
	struct mnttab		mnt_record;
	struct mnttab		*mp = &mnt_record;
	int			bm_mounted = 0;


	/*
	 * If we are only checking part of the disk, the disk must
	 * have a partition map to check against.  If it doesn't,
	 * we hope for the best.
	 */
	if (cur_parts == NULL)
		return (0);	/* Will be checked later */

	/*
	 * Lock out interrupts because of the mntent protocol.
	 */
	enter_critical();
	/*
	 * Open the mount table.
	 */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		err_print("Unable to open mount table.\n");
		fullabort();
	}
	/*
	 * Loop through the mount table until we run out of entries.
	 */
	while ((getmntent(fp, mp)) != -1) {
		if ((part = getpartition(mp->mnt_special)) != -1)
			bm_mounted |= (1 << part);
	}
	/*
	 * Close down the mount table.
	 */
	(void) fclose(fp);
	exit_critical();

	return (checkpartitions(bm_mounted));

}

/*
 * This Routine checks if any partitions specified
 * are affected by writing the new label
 */
static int
checkpartitions(int bm_mounted)
{
	struct dk_map32		*n;
	struct dk_map		*o;
	struct dk_allmap	old_map;
	int			i, found = 0;
	struct partition64	o_efi;

	/*
	 * Now we need to check that the current partition list and the
	 * previous partition list (which there must be if we actually
	 * have partitions mounted) overlap  in any way on the mounted
	 * partitions
	 */

	/*
	 * Check if the user wants to online-label an
	 * existing EFI label.
	 */
	if (cur_label == L_TYPE_EFI) {
		for (i = 0; i < EFI_NUMPAR; i++) {
			if (bm_mounted & (1 << i)) {
				o_efi.p_partno = i;
				if (ioctl(cur_file, DKIOCPARTITION, &o_efi)
				    == -1) {
					err_print("Unable to get information "
					    "for EFI partition %d.\n", i);
					return (-1);
				}

				/*
				 * Partition can grow or remain same.
				 */
				if (o_efi.p_start == cur_parts->etoc->
				    efi_parts[i].p_start && o_efi.p_size
				    <= cur_parts->etoc->efi_parts[i].p_size) {
					continue;
				}

				found = -1;
			}
			if (found)
				break;
		}

	} else {

		/*
		 * Get the "real" (on-disk) version of the partition table
		 */
		if (ioctl(cur_file, DKIOCGAPART, &old_map) == -1) {
			err_print("Unable to get current partition map.\n");
			return (-1);
		}
		for (i = 0; i < NDKMAP; i++) {
			if (bm_mounted & (1 << i)) {
				/*
				 * This partition is mounted
				 */
				o = &old_map.dka_map[i];
				n = &cur_parts->pinfo_map[i];
#ifdef DEBUG
				fmt_print(
"checkpartitions :checking partition '%c' \n", i + PARTITION_BASE);
#endif
				/*
				 * If partition is identical, we're fine.
				 * If the partition grows, we're also fine,
				 * because the routines in partition.c check
				 * for overflow. It will (ultimately) be up
				 * to the routines in partition.c to warn
				 * about creation of overlapping partitions.
				 */
				if (o->dkl_cylno == n->dkl_cylno &&
				    o->dkl_nblk <= n->dkl_nblk) {
#ifdef	DEBUG
					if (o->dkl_nblk < n->dkl_nblk) {
						fmt_print(
"- new partition larger by %d blocks", n->dkl_nblk-o->dkl_nblk);
					}
					fmt_print("\n");
#endif
					continue;
				}
#ifdef DEBUG
				fmt_print("- changes; old (%d,%d)->new "
"(%d,%d)\n", o->dkl_cylno, o->dkl_nblk, n->dkl_cylno, n->dkl_nblk);
#endif
				found = -1;
			}
			if (found)
				break;
		}
	}

	/*
	 * If we found trouble and we're running from a command file,
	 * quit before doing something we really regret.
	 */

	if (found && option_f) {
		err_print("Operation on mounted disks or \
disks currently being used for swapping must be interactive.\n");
		cmdabort(SIGINT);
	}
	/*
	 * Return the result.
	 */
	return (found);
}
