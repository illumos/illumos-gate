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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

/*
 * This file contains all the functions that manipulate the file
 * system where the GRUB menu resides.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/efi_partition.h>
#include <sys/vtoc.h>
#include <sys/fs/ufs_mount.h>
#include <sys/dktp/fdisk.h>
#include <libfstyp.h>
#if defined(i386) || defined(__amd64)
#include <libfdisk.h>
#endif

#include "libgrub_impl.h"

static int
slice_match(const char *physpath, int slice)
{
	const char *pos;

	/* always match whole disk slice */
	if (slice == SLCNUM_WHOLE_DISK)
		return (0);

	return ((pos = strrchr(physpath, slice)) == NULL ||
	    pos[1] != 0 || pos[-1] != ':');
}

/*
 * Returns zero if path contains ufs
 */
static int
slice_ufs(const char *path)
{
	int fd, ret;
	const char *id;
	fstyp_handle_t hdl;

	fd = open(path, O_RDONLY);
	if ((ret = fstyp_init(fd, 0, NULL, &hdl)) == 0) {
		ret = fstyp_ident(hdl, "ufs", &id);
		fstyp_fini(hdl);
	}
	(void) close(fd);
	return (ret);
}


static int
get_sol_prtnum(const char *physpath)
{
	int i, fd;
	char *pos;
	size_t sz;
	struct mboot *mb;
	struct ipart *ipart;
	char boot_sect[512];
	char rdev[MAXNAMELEN];
#if defined(i386) || defined(__amd64)
	ext_part_t *epp;
	int ext_part_found = 0;
#endif

	(void) snprintf(rdev, sizeof (rdev), "/devices%s,raw", physpath);

	if ((pos = strrchr(rdev, ':')) == NULL)
		return (PRTNUM_INVALID);

	/*
	 * first check for EFI partitioning, efi_alloc_and_read()
	 * will return partition number.
	 */
	if ((fd = open(rdev, O_RDONLY|O_NDELAY)) >= 0) {
		struct dk_gpt *vtoc;

		if ((i = efi_alloc_and_read(fd, &vtoc)) >= 0) {
			/* zfs is using V_USR */
			if (vtoc->efi_parts[i].p_tag != V_USR)
				i = PRTNUM_INVALID; /* error */
			efi_free(vtoc);
			(void) close(fd);
			return (i);
		}
		(void) close(fd);
	} else {
		return (PRTNUM_INVALID);
	}

	pos[1] = SLCNUM_WHOLE_DISK;

	fd = open(rdev, O_RDONLY);
	sz = read(fd, boot_sect, sizeof (boot_sect));
	(void) close(fd);

	if (sz != sizeof (boot_sect))
		return (PRTNUM_INVALID);

	/* parse fdisk table */
	mb = (struct mboot *)(uintptr_t)boot_sect;
	ipart = (struct ipart *)(uintptr_t)mb->parts;
	for (i = 0; i < FD_NUMPART; ++i) {
		if (ipart[i].systid == SUNIXOS || ipart[i].systid == SUNIXOS2)
			return (i);

#if defined(i386) || defined(__amd64)
		if (!fdisk_is_dos_extended(ipart[i].systid) ||
		    (ext_part_found == 1))
			continue;

		ext_part_found = 1;

		if (libfdisk_init(&epp, rdev, NULL, FDISK_READ_DISK) ==
		    FDISK_SUCCESS) {
			uint32_t begs, nums;
			int pno;
			int rval;

			rval = fdisk_get_solaris_part(epp, &pno, &begs, &nums);

			libfdisk_fini(&epp);

			if (rval == FDISK_SUCCESS)
				return (pno - 1);
		}
#endif
	}
	return (PRTNUM_INVALID);
}

/*
 * Get physpath, topfs and bootfs for ZFS root dataset.
 * Return 0 on success, non-zero (not errno) on failure.
 */
static int
get_zfs_root(zfs_handle_t *zfh, grub_fs_t *fs, grub_root_t *root)
{
	int ret;
	zpool_handle_t *zph;
	const char *name;

	if (zfs_get_type(zfh) != ZFS_TYPE_FILESYSTEM ||
	    (name = zfs_get_name(zfh)) == NULL ||
	    (zph = zpool_open(fs->gf_lzfh, name)) == NULL)
		return (-1);

	if ((ret = zpool_get_physpath(zph, root->gr_physpath,
	    sizeof (root->gr_physpath))) == 0 &&
	    (ret = zpool_get_prop(zph, ZPOOL_PROP_BOOTFS,
	    root->gr_fs[GRBM_ZFS_BOOTFS].gfs_dev,
	    sizeof (root->gr_fs[GRBM_ZFS_BOOTFS].gfs_dev), NULL,
	    B_FALSE)) == 0) {

		(void) strlcpy(root->gr_fs[GRBM_ZFS_TOPFS].gfs_dev, name,
		    sizeof (root->gr_fs[GRBM_ZFS_TOPFS].gfs_dev));
		(void) grub_fsd_get_mountp(root->gr_fs + GRBM_ZFS_BOOTFS,
		    MNTTYPE_ZFS);
		(void) grub_fsd_get_mountp(root->gr_fs + GRBM_ZFS_TOPFS,
		    MNTTYPE_ZFS);
	}

	zpool_close(zph);
	return (ret);
}

/*
 * On entry physpath parameter supposed to contain:
 * <disk_physpath>[<space><disk_physpath>]*.
 * Retrieves first <disk_physpath> that matches both partition and slice.
 * If any partition and slice is acceptable, first <disk_physpath> is returned.
 */
static int
get_one_physpath(char *physpath, uint_t prtnum, uint_t slcnum)
{
	int ret;
	char *tmp, *tok;

	if (!IS_SLCNUM_VALID(slcnum) && !IS_PRTNUM_VALID(prtnum)) {
		(void) strtok(physpath, " ");
		return (0);
	}

	if ((tmp = strdup(physpath)) == NULL)
		return (errno);

	ret = ENODEV;
	for (tok = strtok(tmp, " "); tok != NULL; tok = strtok(NULL, " ")) {
		if ((ret = (slice_match(tok, slcnum) != 0 ||
		    get_sol_prtnum(tok) != prtnum)) == 0) {
			(void) strcpy(physpath, tok);
			break;
		}
	}

	free(tmp);
	if (ret)
		ret = ENODEV;
	return (ret);
}

static int
zfs_bootsign(zfs_handle_t *zfh, void *data)
{
	grub_barg_t *barg;
	grub_menu_t *menu;
	struct stat st;
	char path[MAXPATHLEN];

	barg = (grub_barg_t *)data;
	menu = barg->gb_entry->ge_menu;

	do {
		if (get_zfs_root(zfh, &menu->gm_fs, &barg->gb_root) != 0 ||
		    get_one_physpath(barg->gb_root.gr_physpath, barg->gb_prtnum,
		    barg->gb_slcnum) != 0)
			break;

		/*
		 * if top zfs dataset is not mounted, mount it now
		 */
		if (barg->gb_root.gr_fs[GRBM_ZFS_TOPFS].gfs_mountp[0] == 0) {
			if (grub_fsd_mount_tmp(barg->gb_root.gr_fs +
			    GRBM_ZFS_TOPFS, MNTTYPE_ZFS) != 0)
				break;
		}

		/* check that bootsign exists and it is a regular file */
		(void) snprintf(path, sizeof (path), "%s%s",
		    barg->gb_root.gr_fs[GRBM_ZFS_TOPFS].gfs_mountp,
		    barg->gb_bootsign);

		if (lstat(path, &st) != 0 || S_ISREG(st.st_mode) == 0 ||
		    (st.st_mode & S_IRUSR) == 0)
			break;

		(void) strlcpy(barg->gb_root.gr_fstyp, MNTTYPE_ZFS,
		    sizeof (barg->gb_root.gr_fstyp));
		barg->gb_walkret = 0;
	/* LINTED: E_CONSTANT_CONDITION */
	} while (0);

	grub_fsd_umount_tmp(barg->gb_root.gr_fs + GRBM_ZFS_TOPFS);
	zfs_close(zfh);

	/* return non-zero to terminate the walk */
	return (barg->gb_walkret == 0);
}

static int
get_devlink(di_devlink_t dl, void *arg)
{
	const char *path;
	grub_barg_t *barg;

	barg = (grub_barg_t *)arg;
	if ((path = di_devlink_path(dl)) != NULL)
		(void) strlcpy(barg->gb_root.gr_fs[GRBM_UFS].gfs_dev, path,
		    sizeof (barg->gb_root.gr_fs[GRBM_UFS].gfs_dev));
	return (DI_WALK_TERMINATE);
}

static int
ufs_bootsign_check(grub_barg_t *barg)
{
	int ret;
	struct stat st;
	grub_menu_t *mp;
	char path[MAXPATHLEN];

	mp = barg->gb_entry->ge_menu;

	/* get /dev/dsk link */
	if (di_devlink_walk(mp->gm_fs.gf_dvlh, "^dsk/",
	    barg->gb_root.gr_physpath, DI_PRIMARY_LINK, barg, get_devlink) != 0)
		return (errno);
	/*
	 * if disk is not mounted, mount it now
	 */
	if (grub_fsd_get_mountp(barg->gb_root.gr_fs + GRBM_UFS,
	    MNTTYPE_UFS) != 0) {
		if ((ret =
		    slice_ufs(barg->gb_root.gr_fs[GRBM_UFS].gfs_dev)) != 0 ||
		    (ret = grub_fsd_mount_tmp(barg->gb_root.gr_fs + GRBM_UFS,
		    MNTTYPE_UFS)) != 0)
			return (ret);
	}

	(void) snprintf(path, sizeof (path), "%s%s",
	    barg->gb_root.gr_fs[GRBM_UFS].gfs_mountp, barg->gb_bootsign);

	if (lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
	    (st.st_mode & S_IRUSR) != 0) {
		barg->gb_walkret = 0;
		(void) strlcpy(barg->gb_root.gr_fstyp, MNTTYPE_UFS,
		    sizeof (barg->gb_root.gr_fstyp));
	}

	grub_fsd_umount_tmp(barg->gb_root.gr_fs + GRBM_UFS);
	return (barg->gb_walkret);
}

static int
ufs_bootsign(di_node_t node, di_minor_t minor, void *arg)
{
	uint_t prtnum;
	char *name, *path;
	grub_barg_t *barg;

	barg = (grub_barg_t *)arg;

	if (di_minor_spectype(minor) != S_IFBLK)
		return (DI_WALK_CONTINUE);

	name = di_minor_name(minor);
	if (name[0] != barg->gb_slcnum || name[1] != 0)
		return (DI_WALK_CONTINUE);

	path = di_devfs_path(node);
	(void) snprintf(barg->gb_root.gr_physpath,
	    sizeof (barg->gb_root.gr_physpath), "%s:%c", path, barg->gb_slcnum);
	di_devfs_path_free(path);

	prtnum = get_sol_prtnum(barg->gb_root.gr_physpath);
	if (!IS_PRTNUM_VALID(prtnum))
		return (DI_WALK_CONTINUE);

	/*
	 * check only specified partition, slice
	 */

	if (IS_PRTNUM_VALID(barg->gb_prtnum)) {
		if (prtnum != barg->gb_prtnum || ufs_bootsign_check(barg) != 0)
			return (DI_WALK_CONTINUE);
		return (DI_WALK_TERMINATE);
	}

	/*
	 * Walk through all slices in found solaris partition
	 */

	barg->gb_prtnum = prtnum;
	minor = DI_MINOR_NIL;

	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {

		if (di_minor_spectype(minor) != S_IFBLK)
			continue;

		name = di_minor_name(minor);
		if (!IS_SLCNUM_VALID(name[0]) || name[1] != 0)
			continue;

		barg->gb_slcnum = name[0];
		path = strrchr(barg->gb_root.gr_physpath, ':');
		path[1] = barg->gb_slcnum;

		if (ufs_bootsign_check(barg) == 0)
			return (DI_WALK_TERMINATE);
	}

	barg->gb_prtnum = (uint_t)PRTNUM_INVALID;
	barg->gb_slcnum = (uint_t)SLCNUM_WHOLE_DISK;
	return (DI_WALK_CONTINUE);
}

/*
 * Differs from what GRUB is doing: GRUB searchs through all disks seen by bios
 * for bootsign, if bootsign is found on ufs slice GRUB sets it as a root,
 * if on zfs, then GRUB uses zfs slice as root only if bootsign wasn't found
 * on other slices.
 * That function first searches through all top datasets of active zpools,
 * then if bootsign still not found walks through all disks and tries to
 * find ufs slice with the bootsign.
 */
int
grub_find_bootsign(grub_barg_t *barg)
{
	grub_menu_t *mp;
	mp = barg->gb_entry->ge_menu;

	/* try to find bootsign over zfs pools */
	barg->gb_walkret = EG_BOOTSIGN;
	(void) zfs_iter_root(mp->gm_fs.gf_lzfh, zfs_bootsign, barg);

	/* try ufs now */
	if (barg->gb_walkret != 0 && di_walk_minor(mp->gm_fs.gf_diroot,
	    DDI_NT_BLOCK, 0, barg, ufs_bootsign) != 0)
		return (errno);

	return (barg->gb_walkret);
}

/*
 * Get current root file system.
 * Return 0 on success, errno code on failure.
 */
int
grub_current_root(grub_fs_t *fs, grub_root_t *root)
{
	int rc = 0;
	FILE *fp = NULL;
	char *name = NULL;
	zfs_handle_t *zfh = NULL;
	struct mnttab mp = {0};
	struct mnttab mpref = {0};
	char buf[MAXNAMELEN] = {0};

	mpref.mnt_mountp = "/";

	if ((fp = fopen(MNTTAB, "r")) == NULL)
		return (errno);

	/*
	 * getmntany returns non-zero for failure, and sets errno
	 */
	rc = getmntany(fp, &mp, &mpref);
	if (rc != 0)
		rc = errno;

	(void) fclose(fp);

	if (rc != 0)
		return (rc);

	(void) strlcpy(root->gr_fstyp, mp.mnt_fstype, sizeof (root->gr_fstyp));

	if (strcmp(root->gr_fstyp, MNTTYPE_ZFS) == 0) {

		(void) strlcpy(buf, mp.mnt_special, sizeof (buf));
		if ((name = strtok(buf, "/")) == NULL)
			return (EG_CURROOT);

		if ((zfh = zfs_open(fs->gf_lzfh, name, ZFS_TYPE_FILESYSTEM)) ==
		    NULL)
			return (EG_OPENZFS);

		/*
		 * get_zfs_root returns non-zero on failure, not errno.
		 */
		if (get_zfs_root(zfh, fs, root))
			rc = EG_CURROOT;
		else
			/*
			 * For mirrored root physpath would contain the list of
			 * all bootable devices, pick up the first one.
			 */
			rc = get_one_physpath(root->gr_physpath, SLCNUM_INVALID,
			    PRTNUM_INVALID);

		zfs_close(zfh);

	} else if (strcmp(mp.mnt_fstype, MNTTYPE_UFS) == 0) {
		(void) strlcpy(root->gr_fs[GRBM_UFS].gfs_dev, mp.mnt_special,
		    sizeof (root->gr_fs[GRBM_UFS].gfs_dev));
		(void) strlcpy(root->gr_fs[GRBM_UFS].gfs_mountp, mp.mnt_mountp,
		    sizeof (root->gr_fs[GRBM_UFS].gfs_mountp));
	} else {
		rc = EG_UNKNOWNFS;
	}

	return (rc);
}

grub_fsdesc_t *
grub_get_rootfsd(const grub_root_t *root)
{
	grub_fsdesc_t *fsd = NULL;

	assert(root);
	if (strcmp(MNTTYPE_UFS, root->gr_fstyp) == 0)
		fsd = (grub_fsdesc_t *)root->gr_fs + GRBM_UFS;
	else if (strcmp(MNTTYPE_ZFS, root->gr_fstyp) == 0)
		fsd = (grub_fsdesc_t *)root->gr_fs + GRBM_ZFS_BOOTFS;

	return (fsd);
}

/*
 * Gets file systems mount point if any.
 * Return 0 if filesystem is mounted, errno on failure.
 */
int
grub_fsd_get_mountp(grub_fsdesc_t *fsd, char *fstyp)
{
	int rc;
	FILE *fp = NULL;
	struct mnttab mp = {0};
	struct mnttab mpref = {0};

	fsd->gfs_mountp[0] = 0;

	if ((fp = fopen(MNTTAB, "r")) == NULL)
		return (errno);

	mpref.mnt_special = fsd->gfs_dev;
	mpref.mnt_fstype = fstyp;

	if ((rc = getmntany(fp, &mp, &mpref)) == 0)
		(void) strlcpy(fsd->gfs_mountp, mp.mnt_mountp,
		    sizeof (fsd->gfs_mountp));
	else
		rc = EG_GETMNTTAB;

	(void) fclose(fp);
	return (rc);
}

static const char tmp_mountp[] = "/tmp/.libgrubmgmt.%s.XXXXXX";

/*
 * Mount file system at tmp_mountp.
 * Return 0 on success, errno on failure.
 */
int
grub_fsd_mount_tmp(grub_fsdesc_t *fsd, const char *fstyp)
{
	const char *pos;
	void *data = NULL;
	int dtsz = 0;
	struct ufs_args ufs_args = {UFSMNT_LARGEFILES};
	char mntopts[MNT_LINE_MAX] = "";
	int rc = 0;

	assert(fsd);
	assert(!fsd->gfs_is_tmp_mounted);

	fsd->gfs_mountp[0] = 0;

	if (strcmp(fstyp, MNTTYPE_UFS) == 0) {
		(void) strlcpy(mntopts, MNTOPT_LARGEFILES, sizeof (mntopts));
		data = &ufs_args;
		dtsz = sizeof (ufs_args);
	} else if (strcmp(fstyp, MNTTYPE_ZFS) != 0) {
		return (EG_UNKNOWNFS);
	}

	/* construct name for temporary mount point */
	pos = strrchr(fsd->gfs_dev, '/');
	pos = (pos == NULL) ? fsd->gfs_dev : pos + 1;

	(void) snprintf(fsd->gfs_mountp, sizeof (fsd->gfs_mountp),
	    tmp_mountp, pos);
	if (mkdtemp(fsd->gfs_mountp) != NULL) {
		if ((rc = mount(fsd->gfs_dev, fsd->gfs_mountp,
		    MS_DATA | MS_OPTIONSTR | MS_RDONLY,
		    fstyp, data, dtsz, mntopts, sizeof (mntopts))) != 0) {
			/*
			 * mount failed, collect errno and remove temp dir
			 */
			rc = errno;
			(void) rmdir(fsd->gfs_mountp);
		}
	} else {
		rc = errno;
	}

	if (rc != 0)
		fsd->gfs_mountp[0] = 0;

	/*
	 * Note that valid values for gfs_is_tmp_mounted are 0,1.
	 * Any other value indicates that something bad happened.
	 * Probably grub_fsd_umount_tmp() wasn't called or didn't
	 * work as expected.
	 */
	fsd->gfs_is_tmp_mounted += (rc == 0);
	return (rc);
}

/*
 * Unmount file system at tmp_mountp.
 */
void
grub_fsd_umount_tmp(grub_fsdesc_t *fsd)
{
	if (fsd == NULL)
		return;

	if (fsd->gfs_is_tmp_mounted) {
		if (fsd->gfs_mountp[0] != 0) {
			(void) umount2(fsd->gfs_mountp, 0);
			(void) rmdir(fsd->gfs_mountp);
			fsd->gfs_mountp[0] = 0;
		}
		fsd->gfs_is_tmp_mounted = 0;
	}
}
