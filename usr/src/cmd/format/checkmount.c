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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contians miscellaneous routines.
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
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <ctype.h>
#include "misc.h"
#include "checkmount.h"

/* Function prototypes */
#ifdef	__STDC__

static struct swaptable *getswapentries(void);
static void freeswapentries(struct swaptable *);
static int	getpartition(char *pathname);
static int	checkpartitions(int mounted);

#else	/* __STDC__ */

static struct swaptable *getswapentries();
static void freeswapentries();
static int	getpartition();
static int	checkpartitions();

#endif	/* __STDC__ */

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
 * This Routine checks if any partitions specified by the
 * bit-map of mounted/swap partitions are affected by
 * writing the new label
 */
static int
checkpartitions(bm_mounted)
int bm_mounted;
{
	struct dk_map32		*n;
	struct dk_map		*o;
	struct dk_allmap	old_map;
	int			i, found = 0;

	/*
	 * Now we need to check that the current partition list and the
	 * previous partition list (which there must be if we actually
	 * have partitions mounted) overlap  in any way on the mounted
	 * partitions
	 */

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
			 * If the partition grows, we're also fine, because
			 * the routines in partition.c check for overflow.
			 * It will (ultimately) be up to the routines in
			 * partition.c to warn about creation of overlapping
			 * partitions
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
			fmt_print("- changes; old (%d,%d)->new (%d,%d)\n",
				o->dkl_cylno, o->dkl_nblk, n->dkl_cylno,
				n->dkl_nblk);
#endif
			found = -1;
		}
		if (found)
			break;
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
