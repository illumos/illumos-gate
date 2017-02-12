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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <strings.h>
#include <libfdisk.h>

#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/multiboot.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/efi_partition.h>
#include <libfstyp.h>
#include <uuid/uuid.h>

#include "installboot.h"
#include "../../common/bblk_einfo.h"
#include "../../common/boot_utils.h"
#include "../../common/mboot_extra.h"
#include "getresponse.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

/*
 * BIOS bootblock installation:
 *
 * 1. MBR is first sector of the disk. If the file system on target is
 *    ufs or zfs, the same MBR code is installed on first sector of the
 *    partition as well; this will allow to have real MBR sector to be
 *    replaced by some other boot loader and have illumos chainloaded.
 *
 * installboot will record the start LBA and size of stage2 code in MBR code.
 * On boot, the MBR code will read the stage2 code and executes it.
 *
 * 2. Stage2 location depends on file system type;
 *    In case of zfs, installboot will store stage2 to zfs bootblk area,
 *    which is 512k bytes from partition start and size is 3.5MB.
 *
 *    In case of ufs, the stage2 location is 50 512B sectors from
 *    Solaris2 MBR partition start, within boot slice, boot slice size is
 *    one cylinder.
 *
 *    In case of pcfs, the stage2 location is 50 512B sectors from beginning
 *    of the disk, filling the space between MBR and first partition.
 *    This location assumes no other bootloader and the space is one cylinder,
 *    as first partition is starting from cylinder 1.
 *
 *    In case of GPT partitioning and if file system is not zfs, the boot
 *    support is only possible with dedicated boot partition. For GPT,
 *    the current implementation is using BOOT partition, which must exist.
 *    BOOT partition does only contain raw boot blocks, without any file system.
 *
 * Loader stage2 is created with embedded version, by using fake multiboot (MB)
 * header within first 32k and EINFO block is at the end of the actual
 * boot block. MB header load_addr is set to 0 and load_end_addr is set to
 * actual block end, so the EINFO size is (file size - load_end_addr).
 * installboot does also store the illumos boot partition LBA to MB space,
 * starting from bss_end_addr structure member location; stage2 will
 * detect the partition and file system based on this value.
 *
 * Stored location values in MBR/stage2 also mean the bootblocks must be
 * reinstalled in case the partition content is relocated.
 */

static boolean_t	write_mbr = B_FALSE;
static boolean_t	force_mbr = B_FALSE;
static boolean_t	force_update = B_FALSE;
static boolean_t	do_getinfo = B_FALSE;
static boolean_t	do_version = B_FALSE;
static boolean_t	do_mirror_bblk = B_FALSE;
static boolean_t	strip = B_FALSE;
static boolean_t	verbose_dump = B_FALSE;

/* Versioning string, if present. */
static char		*update_str;

/*
 * Temporary buffer to store the first 32K of data looking for a multiboot
 * signature.
 */
char			mboot_scan[MBOOT_SCAN_SIZE];

/* Function prototypes. */
static void check_options(char *);
static int get_start_sector(ib_device_t *);

static int read_stage1_from_file(char *, ib_data_t *data);
static int read_bootblock_from_file(char *, ib_data_t *data);
static int read_bootblock_from_disk(ib_device_t *device, ib_bootblock_t *,
    char **);
static void add_bootblock_einfo(ib_bootblock_t *, char *);
static int prepare_stage1(ib_data_t *);
static int prepare_bootblock(ib_data_t *, char *);
static int write_stage1(ib_data_t *);
static int write_bootblock(ib_data_t *);
static int init_device(ib_device_t *, char *);
static void cleanup_device(ib_device_t *);
static int commit_to_disk(ib_data_t *, char *);
static int handle_install(char *, char **);
static int handle_getinfo(char *, char **);
static int handle_mirror(char *, char **);
static boolean_t is_update_necessary(ib_data_t *, char *);
static int propagate_bootblock(ib_data_t *, ib_data_t *, char *);
static void usage(char *);

static int
read_stage1_from_file(char *path, ib_data_t *dest)
{
	int	fd;

	assert(dest != NULL);

	/* read the stage1 file from filesystem */
	fd = open(path, O_RDONLY);
	if (fd == -1 ||
	    read(fd, dest->stage1, SECTOR_SIZE) != SECTOR_SIZE) {
		(void) fprintf(stderr, gettext("cannot read stage1 file %s\n"),
		    path);
		return (BC_ERROR);
	}
	(void) close(fd);
	return (BC_SUCCESS);
}

static int
read_bootblock_from_file(char *file, ib_data_t *data)
{
	ib_bootblock_t	*bblock = &data->bootblock;
	struct stat	sb;
	uint32_t	buf_size;
	uint32_t	mboot_off;
	int		fd = -1;
	int		retval = BC_ERROR;

	assert(data != NULL);
	assert(file != NULL);

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		BOOT_DEBUG("Error opening %s\n", file);
		perror("open");
		goto out;
	}

	if (fstat(fd, &sb) == -1) {
		BOOT_DEBUG("Error getting information (stat) about %s", file);
		perror("stat");
		goto outfd;
	}

	/* loader bootblock has version built in */
	buf_size = sb.st_size;

	bblock->buf_size = buf_size;
	BOOT_DEBUG("bootblock in-memory buffer size is %d\n",
	    bblock->buf_size);

	bblock->buf = malloc(buf_size);
	if (bblock->buf == NULL) {
		perror(gettext("Memory allocation failure"));
		goto outbuf;
	}
	bblock->file = bblock->buf;

	if (read(fd, bblock->file, bblock->buf_size) != bblock->buf_size) {
		BOOT_DEBUG("Read from %s failed\n", file);
		perror("read");
		goto outfd;
	}

	if (find_multiboot(bblock->file, MBOOT_SCAN_SIZE, &mboot_off)
	    != BC_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Unable to find multiboot header\n"));
		goto outfd;
	}

	bblock->mboot = (multiboot_header_t *)(bblock->file + mboot_off);
	bblock->mboot_off = mboot_off;

	bblock->file_size =
	    bblock->mboot->load_end_addr - bblock->mboot->load_addr;
	BOOT_DEBUG("bootblock file size is %d\n", bblock->file_size);

	bblock->extra = bblock->buf + P2ROUNDUP(bblock->file_size, 8);
	bblock->extra_size = bblock->buf_size - P2ROUNDUP(bblock->file_size, 8);

	BOOT_DEBUG("mboot at %p offset %d, extra at %p size %d, buf=%p "
	    "(size=%d)\n", bblock->mboot, bblock->mboot_off, bblock->extra,
	    bblock->extra_size, bblock->buf, bblock->buf_size);

	(void) close(fd);
	return (BC_SUCCESS);

outbuf:
	(void) free(bblock->buf);
	bblock->buf = NULL;
outfd:
	(void) close(fd);
out:
	return (retval);
}

static int
read_bootblock_from_disk(ib_device_t *device, ib_bootblock_t *bblock,
    char **path)
{
	int			dev_fd;
	uint32_t		size, offset;
	uint32_t		buf_size;
	uint32_t		mboot_off;
	multiboot_header_t	*mboot;

	assert(device != NULL);
	assert(bblock != NULL);

	if (device->target.fstype == IG_FS_ZFS) {
		dev_fd = device->target.fd;
		offset = BBLK_ZFS_BLK_OFF * SECTOR_SIZE;
		*path = device->target.path;
	} else {
		dev_fd = device->stage.fd;
		offset = device->stage.offset * SECTOR_SIZE;
		*path = device->stage.path;
	}

	if (read_in(dev_fd, mboot_scan, sizeof (mboot_scan), offset)
	    != BC_SUCCESS) {
		BOOT_DEBUG("Error reading bootblock area\n");
		perror("read");
		return (BC_ERROR);
	}

	/* No multiboot means no chance of knowing bootblock size */
	if (find_multiboot(mboot_scan, sizeof (mboot_scan), &mboot_off)
	    != BC_SUCCESS) {
		BOOT_DEBUG("Unable to find multiboot header\n");
		return (BC_NOEXTRA);
	}
	mboot = (multiboot_header_t *)(mboot_scan + mboot_off);

	/*
	 * make sure mboot has sane values
	 */
	if (mboot->load_end_addr == 0 ||
	    mboot->load_end_addr < mboot->load_addr)
		return (BC_NOEXTRA);

	/*
	 * Currently, the amount of space reserved for extra information
	 * is "fixed". We may have to scan for the terminating extra payload
	 * in the future.
	 */
	size = mboot->load_end_addr - mboot->load_addr;
	buf_size = P2ROUNDUP(size + SECTOR_SIZE, SECTOR_SIZE);
	bblock->file_size = size;

	bblock->buf = malloc(buf_size);
	if (bblock->buf == NULL) {
		BOOT_DEBUG("Unable to allocate enough memory to read"
		    " the extra bootblock from the disk\n");
		perror(gettext("Memory allocation failure"));
		return (BC_ERROR);
	}
	bblock->buf_size = buf_size;

	if (read_in(dev_fd, bblock->buf, buf_size, offset) != BC_SUCCESS) {
		BOOT_DEBUG("Error reading the bootblock\n");
		(void) free(bblock->buf);
		bblock->buf = NULL;
		return (BC_ERROR);
	}

	/* Update pointers. */
	bblock->file = bblock->buf;
	bblock->mboot_off = mboot_off;
	bblock->mboot = (multiboot_header_t *)(bblock->buf + bblock->mboot_off);
	bblock->extra = bblock->buf + P2ROUNDUP(bblock->file_size, 8);
	bblock->extra_size = bblock->buf_size - P2ROUNDUP(bblock->file_size, 8);

	BOOT_DEBUG("mboot at %p offset %d, extra at %p size %d, buf=%p "
	    "(size=%d)\n", bblock->mboot, bblock->mboot_off, bblock->extra,
	    bblock->extra_size, bblock->buf, bblock->buf_size);

	return (BC_SUCCESS);
}

static boolean_t
is_update_necessary(ib_data_t *data, char *updt_str)
{
	bblk_einfo_t	*einfo;
	bblk_einfo_t	*einfo_file;
	bblk_hs_t	bblock_hs;
	ib_bootblock_t	bblock_disk;
	ib_bootblock_t	*bblock_file = &data->bootblock;
	ib_device_t	*device = &data->device;
	int		ret;
	char		*path;

	assert(data != NULL);

	bzero(&bblock_disk, sizeof (ib_bootblock_t));

	ret = read_bootblock_from_disk(device, &bblock_disk, &path);
	if (ret != BC_SUCCESS) {
		BOOT_DEBUG("Unable to read bootblock from %s\n", path);
		return (B_TRUE);
	}

	einfo = find_einfo(bblock_disk.extra, bblock_disk.extra_size);
	if (einfo == NULL) {
		BOOT_DEBUG("No extended information available on disk\n");
		return (B_TRUE);
	}

	einfo_file = find_einfo(bblock_file->extra, bblock_file->extra_size);
	if (einfo_file == NULL) {
		/*
		 * loader bootblock is versioned. missing version means
		 * probably incompatible block. installboot can not install
		 * grub, for example.
		 */
		(void) fprintf(stderr,
		    gettext("ERROR: non versioned bootblock in file\n"));
		return (B_FALSE);
	} else {
		if (updt_str == NULL) {
			updt_str = einfo_get_string(einfo_file);
			do_version = B_TRUE;
		}
	}

	if (!do_version || updt_str == NULL) {
		(void) fprintf(stderr,
		    gettext("WARNING: target device %s has a "
		    "versioned bootblock that is going to be overwritten by a "
		    "non versioned one\n"), device->path);
		return (B_TRUE);
	}

	if (force_update) {
		BOOT_DEBUG("Forcing update of %s bootblock\n", device->path);
		return (B_TRUE);
	}

	BOOT_DEBUG("Ready to check installed version vs %s\n", updt_str);

	bblock_hs.src_buf = (unsigned char *)bblock_file->file;
	bblock_hs.src_size = bblock_file->file_size;

	return (einfo_should_update(einfo, &bblock_hs, updt_str));
}

static void
add_bootblock_einfo(ib_bootblock_t *bblock, char *updt_str)
{
	bblk_hs_t	hs;
	uint32_t	avail_space;

	assert(bblock != NULL);

	if (updt_str == NULL) {
		BOOT_DEBUG("WARNING: no update string passed to "
		    "add_bootblock_einfo()\n");
		return;
	}

	/* Fill bootblock hashing source information. */
	hs.src_buf = (unsigned char *)bblock->file;
	hs.src_size = bblock->file_size;
	/* How much space for the extended information structure? */
	avail_space = bblock->buf_size - P2ROUNDUP(bblock->file_size, 8);
	/* Place the extended information structure. */
	add_einfo(bblock->extra, updt_str, &hs, avail_space);
}

/*
 * set up data for case stage1 is installed as MBR
 * set up location and size of bootblock
 * set disk guid to provide unique information for biosdev command
 */
static int
prepare_stage1(ib_data_t *data)
{
	ib_device_t	*device;

	assert(data != NULL);
	device = &data->device;

	/* copy BPB */
	bcopy(device->mbr + STAGE1_BPB_OFFSET,
	    data->stage1 + STAGE1_BPB_OFFSET, STAGE1_BPB_SIZE);


	/* copy MBR, note STAGE1_SIG == BOOTSZ */
	bcopy(device->mbr + STAGE1_SIG, data->stage1 + STAGE1_SIG,
	    SECTOR_SIZE - STAGE1_SIG);

	/* set stage2 size */
	*((uint16_t *)(data->stage1 + STAGE1_STAGE2_SIZE)) =
	    (uint16_t)(data->bootblock.buf_size / SECTOR_SIZE);

	/*
	 * set stage2 location.
	 * for zfs always use zfs embedding, for ufs/pcfs use partition_start
	 * as base for stage2 location, for ufs/pcfs in MBR partition, use
	 * free space after MBR record.
	 */
	if (device->target.fstype == IG_FS_ZFS)
		*((uint64_t *)(data->stage1 + STAGE1_STAGE2_LBA)) =
		    device->target.start + device->target.offset;
	else {
		*((uint64_t *)(data->stage1 + STAGE1_STAGE2_LBA)) =
		    device->stage.start + device->stage.offset;
	}

	/*
	 * set disk uuid. we only need reasonable amount of uniqueness
	 * to allow biosdev to identify disk based on mbr differences.
	 */
	uuid_generate(data->stage1 + STAGE1_STAGE2_UUID);

	return (BC_SUCCESS);
}

static int
prepare_bootblock(ib_data_t *data, char *updt_str)
{
	ib_bootblock_t		*bblock;
	ib_device_t		*device;
	uint64_t		*ptr;

	assert(data != NULL);

	bblock = &data->bootblock;
	device = &data->device;

	ptr = (uint64_t *)(&bblock->mboot->bss_end_addr);
	*ptr = device->target.start;

	/*
	 * the loader bootblock has built in version, if custom
	 * version was provided, update it.
	 */
	if (do_version)
		add_bootblock_einfo(bblock, updt_str);

	return (BC_SUCCESS);
}

static int
write_bootblock(ib_data_t *data)
{
	ib_device_t	*device = &data->device;
	ib_bootblock_t	*bblock = &data->bootblock;
	uint64_t abs;
	int dev_fd, ret;
	off_t offset;
	char *path;

	assert(data != NULL);

	/*
	 * ZFS bootblock area is 3.5MB, make sure we can fit.
	 * buf_size is size of bootblk+EINFO.
	 */
	if (bblock->buf_size > BBLK_ZFS_BLK_SIZE) {
		(void) fprintf(stderr, gettext("bootblock is too large\n"));
		return (BC_ERROR);
	}

	if (device->target.fstype == IG_FS_ZFS) {
		dev_fd = device->target.fd;
		abs = device->target.start + device->target.offset;
		offset = BBLK_ZFS_BLK_OFF * SECTOR_SIZE;
		path = device->target.path;
	} else {
		dev_fd = device->stage.fd;
		abs = device->stage.start + device->stage.offset;
		offset = device->stage.offset * SECTOR_SIZE;
		path = device->stage.path;
		if (bblock->buf_size >
		    (device->stage.size - device->stage.offset) * SECTOR_SIZE) {
			(void) fprintf(stderr, gettext("Device %s is "
			    "too small to fit the stage2\n"), path);
			return (BC_ERROR);
		}
	}
	ret = write_out(dev_fd, bblock->buf, bblock->buf_size, offset);
	if (ret != BC_SUCCESS) {
		BOOT_DEBUG("Error writing the ZFS bootblock "
		    "to %s at offset %d\n", path, offset);
		return (BC_ERROR);
	}

	(void) fprintf(stdout, gettext("bootblock written for %s,"
	    " %d sectors starting at %d (abs %lld)\n"), path,
	    (bblock->buf_size / SECTOR_SIZE) + 1, offset / SECTOR_SIZE, abs);

	return (BC_SUCCESS);
}

/*
 * Partition boot block or volume boot record (VBR). The VBR is
 * stored on partition relative sector 0 and allows chainloading
 * to read boot program from partition.
 *
 * As the VBR will use the first sector of the partition,
 * this means, we need to be sure the space is not used.
 * We do support three partitioning chemes:
 * 1. GPT: zfs and ufs have reserved space for first 8KB, but
 *	only zfs does have space for boot2. The pcfs has support
 *	for VBR, but no space for boot2. So with GPT, to support
 *	ufs or pcfs boot, we must have separate dedicated boot
 *	partition and we will store VBR on it.
 * 2. MBR: we have almost the same situation as with GPT, except that
 *	if the partitions start from cylinder 1, we will have space
 *	between MBR and cylinder 0. If so, we do not require separate
 *	boot partition.
 * 3. MBR+VTOC: with this combination we store VBR in sector 0 of the
 *	solaris2 MBR partition. The slice 0 will start from cylinder 1,
 *	and we do have space for boot2, so we do not require separate
 *	boot partition.
 */
static int
write_stage1(ib_data_t *data)
{
	ib_device_t	*device = &data->device;
	uint64_t	start = 0;

	assert(data != NULL);

	/*
	 * We have separate partition for boot programs and the stage1
	 * location is not absolute sector 0.
	 * We will write VBR and trigger MBR to read 1 sector from VBR.
	 * This case does also cover MBR+VTOC case, as the solaris 2 partition
	 * name and the root file system slice names are different.
	 */
	if (device->stage.start != 0 &&
	    strcmp(device->target.path, device->stage.path)) {
		/* we got separate stage area, use it */
		if (write_out(device->stage.fd, data->stage1,
		    sizeof (data->stage1), 0) != BC_SUCCESS) {
			(void) fprintf(stdout, gettext("cannot write "
			    "partition boot sector\n"));
			perror("write");
			return (BC_ERROR);
		}

		(void) fprintf(stdout, gettext("stage1 written to "
		    "%s %d sector 0 (abs %d)\n"),
		    device->devtype == IG_DEV_MBR? "partition":"slice",
		    device->stage.id, device->stage.start);
		start = device->stage.start;
	}

	/*
	 * We have either GPT or MBR (without VTOC) and if the root
	 * file system is not pcfs, we can store VBR. Also trigger
	 * MBR to read 1 sector from VBR.
	 */
	if (device->devtype != IG_DEV_VTOC &&
	    device->target.fstype != IG_FS_PCFS) {
		if (write_out(device->target.fd, data->stage1,
		    sizeof (data->stage1), 0) != BC_SUCCESS) {
			(void) fprintf(stdout, gettext("cannot write "
			    "partition boot sector\n"));
			perror("write");
			return (BC_ERROR);
		}

		(void) fprintf(stdout, gettext("stage1 written to "
		    "%s %d sector 0 (abs %d)\n"),
		    device->devtype == IG_DEV_MBR? "partition":"slice",
		    device->target.id, device->target.start);
		start = device->target.start;
	}

	if (write_mbr) {
		/*
		 * If we did write partition boot block, update MBR to
		 * read partition boot block, not boot2.
		 */
		if (start != 0) {
			*((uint16_t *)(data->stage1 + STAGE1_STAGE2_SIZE)) = 1;
			*((uint64_t *)(data->stage1 + STAGE1_STAGE2_LBA)) =
			    start;
		}
		if (write_out(device->fd, data->stage1,
		    sizeof (data->stage1), 0) != BC_SUCCESS) {
			(void) fprintf(stdout,
			    gettext("cannot write master boot sector\n"));
			perror("write");
			return (BC_ERROR);
		}
		(void) fprintf(stdout,
		    gettext("stage1 written to master boot sector\n"));
	}

	return (BC_SUCCESS);
}

/*
 * find partition/slice start sector. will be recorded in stage2 and used
 * by stage2 to identify partition with boot file system.
 */
static int
get_start_sector(ib_device_t *device)
{
	uint32_t		secnum = 0, numsec = 0;
	int			i, pno, rval, log_part = 0;
	struct mboot		*mboot;
	struct ipart		*part = NULL;
	ext_part_t		*epp;
	struct part_info	dkpi;
	struct extpart_info	edkpi;

	if (device->devtype == IG_DEV_EFI) {
		struct dk_gpt *vtoc;

		if (efi_alloc_and_read(device->fd, &vtoc) < 0)
			return (BC_ERROR);

		if (device->stage.start == 0) {
			/* zero size means the fstype must be zfs */
			assert(device->target.fstype == IG_FS_ZFS);

			device->stage.start =
			    vtoc->efi_parts[device->stage.id].p_start;
			device->stage.size =
			    vtoc->efi_parts[device->stage.id].p_size;
			device->stage.offset = BBLK_ZFS_BLK_OFF;
			device->target.offset = BBLK_ZFS_BLK_OFF;
		}

		device->target.start =
		    vtoc->efi_parts[device->target.id].p_start;
		device->target.size =
		    vtoc->efi_parts[device->target.id].p_size;

		/* with pcfs we always write MBR */
		if (device->target.fstype == IG_FS_PCFS) {
			force_mbr = 1;
			write_mbr = 1;
		}

		efi_free(vtoc);
		goto found_part;
	}

	mboot = (struct mboot *)device->mbr;

	/* For MBR we have device->stage filled already. */
	if (device->devtype == IG_DEV_MBR) {
		/* MBR partition starts from 0 */
		pno = device->target.id - 1;
		part = (struct ipart *)mboot->parts + pno;

		if (part->relsect == 0) {
			(void) fprintf(stderr, gettext("Partition %d of the "
			    "disk has an incorrect offset\n"),
			    device->target.id);
			return (BC_ERROR);
		}
		device->target.start = part->relsect;
		device->target.size = part->numsect;

		/* with pcfs we always write MBR */
		if (device->target.fstype == IG_FS_PCFS) {
			force_mbr = 1;
			write_mbr = 1;
		}
		if (device->target.fstype == IG_FS_ZFS)
			device->target.offset = BBLK_ZFS_BLK_OFF;

		goto found_part;
	}

	/*
	 * Search for Solaris fdisk partition
	 * Get the solaris partition information from the device
	 * and compare the offset of S2 with offset of solaris partition
	 * from fdisk partition table.
	 */
	if (ioctl(device->target.fd, DKIOCEXTPARTINFO, &edkpi) < 0) {
		if (ioctl(device->target.fd, DKIOCPARTINFO, &dkpi) < 0) {
			(void) fprintf(stderr, gettext("cannot get the "
			    "slice information of the disk\n"));
			return (BC_ERROR);
		} else {
			edkpi.p_start = dkpi.p_start;
			edkpi.p_length = dkpi.p_length;
		}
	}

	device->target.start = edkpi.p_start;
	device->target.size = edkpi.p_length;
	if (device->target.fstype == IG_FS_ZFS)
		device->target.offset = BBLK_ZFS_BLK_OFF;

	for (i = 0; i < FD_NUMPART; i++) {
		part = (struct ipart *)mboot->parts + i;

		if (part->relsect == 0) {
			(void) fprintf(stderr, gettext("Partition %d of the "
			    "disk has an incorrect offset\n"), i+1);
			return (BC_ERROR);
		}

		if (edkpi.p_start >= part->relsect &&
		    edkpi.p_start < (part->relsect + part->numsect)) {
			/* Found the partition */
			break;
		}
	}

	if (i == FD_NUMPART) {
		/* No solaris fdisk partitions (primary or logical) */
		(void) fprintf(stderr, gettext("Solaris partition not found. "
		    "Aborting operation.\n"));
		return (BC_ERROR);
	}

	/*
	 * We have found a Solaris fdisk partition (primary or extended)
	 * Handle the simple case first: Solaris in a primary partition
	 */
	if (!fdisk_is_dos_extended(part->systid)) {
		device->stage.start = part->relsect;
		device->stage.size = part->numsect;
		if (device->target.fstype == IG_FS_ZFS)
			device->stage.offset = BBLK_ZFS_BLK_OFF;
		else
			device->stage.offset = BBLK_BLKLIST_OFF;
		device->stage.id = i + 1;
		goto found_part;
	}

	/*
	 * Solaris in a logical partition. Find that partition in the
	 * extended part.
	 */

	if ((rval = libfdisk_init(&epp, device->path, NULL, FDISK_READ_DISK))
	    != FDISK_SUCCESS) {
		switch (rval) {
			/*
			 * The first 3 cases are not an error per-se, just that
			 * there is no Solaris logical partition
			 */
			case FDISK_EBADLOGDRIVE:
			case FDISK_ENOLOGDRIVE:
			case FDISK_EBADMAGIC:
				(void) fprintf(stderr, gettext("Solaris "
				    "partition not found. "
				    "Aborting operation.\n"));
				return (BC_ERROR);
			case FDISK_ENOVGEOM:
				(void) fprintf(stderr, gettext("Could not get "
				    "virtual geometry\n"));
				return (BC_ERROR);
			case FDISK_ENOPGEOM:
				(void) fprintf(stderr, gettext("Could not get "
				    "physical geometry\n"));
				return (BC_ERROR);
			case FDISK_ENOLGEOM:
				(void) fprintf(stderr, gettext("Could not get "
				    "label geometry\n"));
				return (BC_ERROR);
			default:
				(void) fprintf(stderr, gettext("Failed to "
				    "initialize libfdisk.\n"));
				return (BC_ERROR);
		}
	}

	rval = fdisk_get_solaris_part(epp, &pno, &secnum, &numsec);
	libfdisk_fini(&epp);
	if (rval != FDISK_SUCCESS) {
		/* No solaris logical partition */
		(void) fprintf(stderr, gettext("Solaris partition not found. "
		    "Aborting operation.\n"));
		return (BC_ERROR);
	}

	device->stage.start = secnum;
	device->stage.size = numsec;
	device->stage.id = pno;
	log_part = 1;

found_part:
	/* get confirmation for -m */
	if (write_mbr && !force_mbr) {
		(void) fprintf(stdout, gettext("Updating master boot sector "
		    "destroys existing boot managers (if any).\n"
		    "continue (y/n)? "));
		if (!yes()) {
			write_mbr = 0;
			(void) fprintf(stdout, gettext("master boot sector "
			    "not updated\n"));
			return (BC_ERROR);
		}
	}

	/*
	 * warn, if illumos in primary partition and loader not in MBR and
	 * partition is not active
	 */
	if (device->devtype != IG_DEV_EFI) {
		if (!log_part && part->bootid != 128 && !write_mbr) {
			(void) fprintf(stdout, gettext("Solaris fdisk "
			    "partition is inactive.\n"), device->stage.id);
		}
	}

	return (BC_SUCCESS);
}

static int
open_device(char *path)
{
	struct stat	statbuf = {0};
	int		fd = -1;

	if (nowrite)
		fd = open(path, O_RDONLY);
	else
		fd = open(path, O_RDWR);

	if (fd == -1) {
		BOOT_DEBUG("Unable to open %s\n", path);
		perror("open");
		return (-1);
	}

	if (fstat(fd, &statbuf) != 0) {
		BOOT_DEBUG("Unable to stat %s\n", path);
		perror("stat");
		(void) close(fd);
		return (-1);
	}

	if (S_ISCHR(statbuf.st_mode) == 0) {
		(void) fprintf(stderr, gettext("%s: Not a character device\n"),
		    path);
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

static int
get_boot_partition(ib_device_t *device, struct mboot *mbr)
{
	struct ipart *part;
	char *path, *ptr;
	int i;

	part = (struct ipart *)mbr->parts;
	for (i = 0; i < FD_NUMPART; i++) {
		if (part[i].systid == X86BOOT)
			break;
	}

	/* no X86BOOT, try to use space between MBR and first partition */
	if (i == FD_NUMPART) {
		device->stage.path = strdup(device->path);
		if (device->stage.path == NULL) {
			perror(gettext("Memory allocation failure"));
			return (BC_ERROR);
		}
		device->stage.fd = dup(device->fd);
		device->stage.id = 0;
		device->stage.devtype = IG_DEV_MBR;
		device->stage.fstype = IG_FS_NONE;
		device->stage.start = 0;
		device->stage.size = part[0].relsect;
		device->stage.offset = BBLK_BLKLIST_OFF;
		return (BC_SUCCESS);
	}

	if ((path = strdup(device->path)) == NULL) {
		perror(gettext("Memory allocation failure"));
		return (BC_ERROR);
	}

	ptr = strrchr(path, 'p');
	ptr++;
	*ptr = '\0';
	(void) asprintf(&ptr, "%s%d", path, i+1); /* partitions are p1..p4 */
	free(path);
	if (ptr == NULL) {
		perror(gettext("Memory allocation failure"));
		return (BC_ERROR);
	}
	device->stage.path = ptr;
	device->stage.fd = open_device(ptr);
	device->stage.id = i + 1;
	device->stage.devtype = IG_DEV_MBR;
	device->stage.fstype = IG_FS_NONE;
	device->stage.start = part[i].relsect;
	device->stage.size = part[i].numsect;
	device->stage.offset = 1; /* leave sector 0 for VBR */
	return (BC_SUCCESS);
}

static int
get_boot_slice(ib_device_t *device, struct dk_gpt *vtoc)
{
	uint_t i;
	char *path, *ptr;

	for (i = 0; i < vtoc->efi_nparts; i++) {
		if (vtoc->efi_parts[i].p_tag == V_BOOT) {
			if ((path = strdup(device->target.path)) == NULL) {
				perror(gettext("Memory allocation failure"));
				return (BC_ERROR);
			}
			ptr = strrchr(path, 's');
			ptr++;
			*ptr = '\0';
			(void) asprintf(&ptr, "%s%d", path, i);
			free(path);
			if (ptr == NULL) {
				perror(gettext("Memory allocation failure"));
				return (BC_ERROR);
			}
			device->stage.path = ptr;
			device->stage.fd = open_device(ptr);
			device->stage.id = i;
			device->stage.devtype = IG_DEV_EFI;
			device->stage.fstype = IG_FS_NONE;
			device->stage.start = vtoc->efi_parts[i].p_start;
			device->stage.size = vtoc->efi_parts[i].p_size;
			device->stage.offset = 1; /* leave sector 0 for VBR */
			return (BC_SUCCESS);
		}
	}
	return (BC_SUCCESS);
}

static int
init_device(ib_device_t *device, char *path)
{
	struct dk_gpt *vtoc;
	fstyp_handle_t fhdl;
	const char *fident;
	char *p;
	int pathlen = strlen(path);
	int ret;

	bzero(device, sizeof (*device));
	device->fd = -1;	/* whole disk fd */
	device->stage.fd = -1;	/* bootblock partition fd */
	device->target.fd = -1;	/* target fs partition fd */

	/* basic check, whole disk is not allowed */
	if ((p = strrchr(path, '/')) == NULL)
		p = path;
	if ((strrchr(p, 'p') == NULL && strrchr(p, 's') == NULL) ||
	    (path[pathlen-2] == 'p' && path[pathlen-1] == '0')) {
		(void) fprintf(stderr, gettext("installing loader to "
		    "whole disk device is not supported\n"));
	}

	device->target.path = strdup(path);
	if (device->target.path == NULL) {
		perror(gettext("Memory allocation failure"));
		return (BC_ERROR);
	}
	device->path = strdup(path);
	if (device->path == NULL) {
		perror(gettext("Memory allocation failure"));
		return (BC_ERROR);
	}

	/* change device name to p0 */
	device->path[pathlen - 2] = 'p';
	device->path[pathlen - 1] = '0';

	if (strstr(device->target.path, "diskette")) {
		(void) fprintf(stderr, gettext("installing loader to a floppy "
		    "disk is not supported\n"));
		return (BC_ERROR);
	}

	/* Detect if the target device is a pcfs partition. */
	if (strstr(device->target.path, "p0:boot")) {
		(void) fprintf(stderr, gettext("installing loader to x86 boot "
		    "partition is not supported\n"));
		return (BC_ERROR);
	}

	if ((device->fd = open_device(device->path)) == -1)
		return (BC_ERROR);

	/* read in the device boot sector. */
	if (read(device->fd, device->mbr, SECTOR_SIZE) != SECTOR_SIZE) {
		(void) fprintf(stderr, gettext("Error reading boot sector\n"));
		perror("read");
		return (BC_ERROR);
	}

	device->devtype = IG_DEV_VTOC;
	if (efi_alloc_and_read(device->fd, &vtoc) >= 0) {
		ret = get_boot_slice(device, vtoc);
		device->devtype = IG_DEV_EFI;
		efi_free(vtoc);
		if (ret == BC_ERROR)
			return (BC_ERROR);
	} else if (device->target.path[pathlen - 2] == 'p') {
		device->devtype = IG_DEV_MBR;
		ret = get_boot_partition(device, (struct mboot *)device->mbr);
		if (ret == BC_ERROR)
			return (BC_ERROR);
	} else if (device->target.path[pathlen - 1] == '2') {
		/*
		 * NOTE: we could relax there and allow zfs boot on
		 * slice 2 for instance, but lets keep traditional limits.
		 */
		(void) fprintf(stderr,
		    gettext("raw device must be a root slice (not s2)\n"));
		return (BC_ERROR);
	}

	/* fill stage partition for case there is no boot partition */
	if (device->stage.path == NULL) {
		if ((device->stage.path = strdup(path)) == NULL) {
			perror(gettext("Memory allocation failure"));
			return (BC_ERROR);
		}
		if (device->devtype == IG_DEV_VTOC) {
			/* use slice 2 */
			device->stage.path[pathlen - 2] = 's';
			device->stage.path[pathlen - 1] = '2';
			device->stage.id = 2;
		} else {
			p = strrchr(device->stage.path, 'p');
			if (p == NULL)
				p = strrchr(device->stage.path, 's');
			device->stage.id = atoi(++p);
		}
		device->stage.devtype = device->devtype;
		device->stage.fd = open_device(device->stage.path);
	}

	p = strrchr(device->target.path, 'p');
	if (p == NULL)
		p = strrchr(device->target.path, 's');
	device->target.id = atoi(++p);

	if (strcmp(device->stage.path, device->target.path) == 0)
		device->target.fd = dup(device->stage.fd);
	else
		device->target.fd = open_device(device->target.path);

	if (fstyp_init(device->target.fd, 0, NULL, &fhdl) != 0)
		return (BC_ERROR);

	if (fstyp_ident(fhdl, NULL, &fident) != 0) {
		fstyp_fini(fhdl);
		(void) fprintf(stderr, gettext("Failed to detect file "
		    "system type\n"));
		return (BC_ERROR);
	}

	/* at this moment non-boot partition has no size set, use this fact */
	if (device->devtype == IG_DEV_EFI && strcmp(fident, "zfs") &&
	    device->stage.size == 0) {
		fstyp_fini(fhdl);
		(void) fprintf(stderr, gettext("Booting %s of EFI labeled "
		    "disks requires the boot partition.\n"), fident);
		return (BC_ERROR);
	}
	if (strcmp(fident, "zfs") == 0)
		device->target.fstype = IG_FS_ZFS;
	else if (strcmp(fident, "ufs") == 0) {
		device->target.fstype = IG_FS_UFS;
	} else if (strcmp(fident, "pcfs") == 0) {
		device->target.fstype = IG_FS_PCFS;
	} else {
		(void) fprintf(stderr, gettext("File system %s is not "
		    "supported by loader\n"), fident);
		fstyp_fini(fhdl);
		return (BC_ERROR);
	}
	fstyp_fini(fhdl);

	/* check for boot partition content */
	if (device->stage.size) {
		if (fstyp_init(device->stage.fd, 0, NULL, &fhdl) != 0)
			return (BC_ERROR);

		if (fstyp_ident(fhdl, NULL, &fident) == 0) {
			(void) fprintf(stderr, gettext("Unexpected %s file "
			    "system on boot partition\n"), fident);
			fstyp_fini(fhdl);
			return (BC_ERROR);
		}
		fstyp_fini(fhdl);
	}
	return (get_start_sector(device));
}

static void
cleanup_device(ib_device_t *device)
{
	if (device->path)
		free(device->path);
	if (device->stage.path)
		free(device->stage.path);
	if (device->target.path)
		free(device->target.path);

	if (device->fd != -1)
		(void) close(device->fd);
	if (device->stage.fd != -1)
		(void) close(device->stage.fd);
	if (device->target.fd != -1)
		(void) close(device->target.fd);
	bzero(device, sizeof (*device));
}

static void
cleanup_bootblock(ib_bootblock_t *bblock)
{
	free(bblock->buf);
	bzero(bblock, sizeof (ib_bootblock_t));
}

/*
 * Propagate the bootblock on the source disk to the destination disk and
 * version it with 'updt_str' in the process. Since we cannot trust any data
 * on the attaching disk, we do not perform any specific check on a potential
 * target extended information structure and we just blindly update.
 */
static int
propagate_bootblock(ib_data_t *src, ib_data_t *dest, char *updt_str)
{
	ib_bootblock_t	*src_bblock = &src->bootblock;
	ib_bootblock_t	*dest_bblock = &dest->bootblock;

	assert(src != NULL);
	assert(dest != NULL);

	/* read the stage1 file from source disk */
	if (read(src->device.fd, dest->stage1, SECTOR_SIZE) != SECTOR_SIZE) {
		(void) fprintf(stderr, gettext("cannot read stage1 from %s\n"),
		    src->device.path);
		return (BC_ERROR);
	}

	cleanup_bootblock(dest_bblock);

	dest_bblock->buf_size = src_bblock->buf_size;
	dest_bblock->buf = malloc(dest_bblock->buf_size);
	if (dest_bblock->buf == NULL) {
		perror(gettext("Memory Allocation Failure"));
		return (BC_ERROR);
	}
	dest_bblock->file = dest_bblock->buf;
	dest_bblock->file_size = src_bblock->file_size;
	(void) memcpy(dest_bblock->buf, src_bblock->buf,
	    dest_bblock->buf_size);

	dest_bblock->mboot = (multiboot_header_t *)(dest_bblock->file +
	    src_bblock->mboot_off);
	dest_bblock->mboot_off = src_bblock->mboot_off;
	dest_bblock->extra = (char *)dest_bblock->file +
	    P2ROUNDUP(dest_bblock->file_size, 8);
	dest_bblock->extra_size = src_bblock->extra_size;

	(void) fprintf(stdout, gettext("Propagating %s bootblock to %s\n"),
	    src->device.path, dest->device.path);

	return (commit_to_disk(dest, updt_str));
}

static int
commit_to_disk(ib_data_t *data, char *update_str)
{
	assert(data != NULL);

	if (prepare_bootblock(data, update_str) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error updating the bootblock "
		    "image\n"));
		return (BC_ERROR);
	}

	if (prepare_stage1(data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error updating the stage1 "
		    "image\n"));
		return (BC_ERROR);
	}

	if (write_bootblock(data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error writing bootblock to "
		    "disk\n"));
		return (BC_ERROR);
	}

	return (write_stage1(data));
}

/*
 * Install a new bootblock on the given device. handle_install() expects argv
 * to contain 3 parameters (the target device path and the path to the
 * bootblock.
 *
 * Returns:	BC_SUCCESS - if the installation is successful
 *		BC_ERROR   - if the installation failed
 *		BC_NOUPDT  - if no installation was performed because the
 *		             version currently installed is more recent than the
 *			     supplied one.
 *
 */
static int
handle_install(char *progname, char **argv)
{
	ib_data_t	install_data;
	char		*stage1 = NULL;
	char		*bootblock = NULL;
	char		*device_path = NULL;
	int		ret = BC_ERROR;

	stage1 = strdup(argv[0]);
	bootblock = strdup(argv[1]);
	device_path = strdup(argv[2]);

	if (!device_path || !bootblock || !stage1) {
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname);
		goto out;
	}

	BOOT_DEBUG("device path: %s, stage1 path: %s bootblock path: %s\n",
	    device_path, stage1, bootblock);
	bzero(&install_data, sizeof (ib_data_t));

	if (init_device(&install_data.device, device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to open device %s\n"),
		    device_path);
		goto out;
	}

	if (read_stage1_from_file(stage1, &install_data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error opening %s\n"), stage1);
		goto out_dev;
	}

	if (read_bootblock_from_file(bootblock, &install_data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error reading %s\n"),
		    bootblock);
		goto out_dev;
	}

	/*
	 * is_update_necessary() will take care of checking if versioning and/or
	 * forcing the update have been specified. It will also emit a warning
	 * if a non-versioned update is attempted over a versioned bootblock.
	 */
	if (!is_update_necessary(&install_data, update_str)) {
		(void) fprintf(stderr, gettext("bootblock version installed "
		    "on %s is more recent or identical\n"
		    "Use -F to override or install without the -u option\n"),
		    device_path);
		ret = BC_NOUPDT;
		goto out_dev;
	}

	BOOT_DEBUG("Ready to commit to disk\n");
	ret = commit_to_disk(&install_data, update_str);

out_dev:
	cleanup_device(&install_data.device);
out:
	free(stage1);
	free(bootblock);
	free(device_path);
	return (ret);
}

/*
 * Retrieves from a device the extended information (einfo) associated to the
 * installed stage2.
 * Expects one parameter, the device path, in the form: /dev/rdsk/c?[t?]d?s0.
 * Returns:
 *        - BC_SUCCESS (and prints out einfo contents depending on 'flags')
 *	  - BC_ERROR (on error)
 *        - BC_NOEINFO (no extended information available)
 */
static int
handle_getinfo(char *progname, char **argv)
{

	ib_data_t	data;
	ib_bootblock_t	*bblock = &data.bootblock;
	ib_device_t	*device = &data.device;
	bblk_einfo_t	*einfo;
	uint8_t		flags = 0;
	char		*device_path, *path;
	int		retval = BC_ERROR;
	int		ret;

	device_path = strdup(argv[0]);
	if (!device_path) {
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname);
		goto out;
	}

	bzero(&data, sizeof (ib_data_t));
	BOOT_DEBUG("device path: %s\n", device_path);

	if (init_device(device, device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information from %s\n"), device_path);
		goto out_dev;
	}

	ret = read_bootblock_from_disk(device, bblock, &path);
	if (ret == BC_ERROR) {
		(void) fprintf(stderr, gettext("Error reading bootblock from "
		    "%s\n"), path);
		goto out_dev;
	}

	if (ret == BC_NOEXTRA) {
		BOOT_DEBUG("No multiboot header found on %s, unable "
		    "to locate extra information area (old/non versioned "
		    "bootblock?) \n", device_path);
		(void) fprintf(stderr, gettext("No extended information "
		    "found\n"));
		retval = BC_NOEINFO;
		goto out_dev;
	}

	einfo = find_einfo(bblock->extra, bblock->extra_size);
	if (einfo == NULL) {
		retval = BC_NOEINFO;
		(void) fprintf(stderr, gettext("No extended information "
		    "found\n"));
		goto out_dev;
	}

	/* Print the extended information. */
	if (strip)
		flags |= EINFO_EASY_PARSE;
	if (verbose_dump)
		flags |= EINFO_PRINT_HEADER;

	print_einfo(flags, einfo, bblock->extra_size);
	retval = BC_SUCCESS;

out_dev:
	cleanup_device(&data.device);
out:
	free(device_path);
	return (retval);
}

/*
 * Attempt to mirror (propagate) the current bootblock over the attaching disk.
 *
 * Returns:
 *	- BC_SUCCESS (a successful propagation happened)
 *	- BC_ERROR (an error occurred)
 *	- BC_NOEXTRA (it is not possible to dump the current bootblock since
 *			there is no multiboot information)
 */
static int
handle_mirror(char *progname, char **argv)
{
	ib_data_t	curr_data;
	ib_data_t	attach_data;
	ib_device_t	*curr_device = &curr_data.device;
	ib_device_t	*attach_device = &attach_data.device;
	ib_bootblock_t	*bblock_curr = &curr_data.bootblock;
	ib_bootblock_t	*bblock_attach = &attach_data.bootblock;
	bblk_einfo_t	*einfo_curr = NULL;
	char		*curr_device_path;
	char		*attach_device_path;
	char		*updt_str = NULL;
	char		*path;
	int		retval = BC_ERROR;
	int		ret;

	curr_device_path = strdup(argv[0]);
	attach_device_path = strdup(argv[1]);

	if (!curr_device_path || !attach_device_path) {
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname);
		goto out;
	}
	BOOT_DEBUG("Current device path is: %s, attaching device path is: "
	    " %s\n", curr_device_path, attach_device_path);

	bzero(&curr_data, sizeof (ib_data_t));
	bzero(&attach_data, sizeof (ib_data_t));

	if (init_device(curr_device, curr_device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information from %s (current device)\n"),
		    curr_device_path);
		goto out_currdev;
	}

	if (init_device(attach_device, attach_device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information from %s (attaching device)\n"),
		    attach_device_path);
		goto out_devs;
	}

	ret = read_bootblock_from_disk(curr_device, bblock_curr, &path);
	if (ret == BC_ERROR) {
		BOOT_DEBUG("Error reading bootblock from %s\n", path);
		retval = BC_ERROR;
		goto out_devs;
	}

	if (ret == BC_NOEXTRA) {
		BOOT_DEBUG("No multiboot header found on %s, unable to retrieve"
		    " the bootblock\n", path);
		retval = BC_NOEXTRA;
		goto out_devs;
	}

	write_mbr = B_TRUE;
	force_mbr = B_TRUE;
	einfo_curr = find_einfo(bblock_curr->extra, bblock_curr->extra_size);
	if (einfo_curr != NULL)
		updt_str = einfo_get_string(einfo_curr);

	retval = propagate_bootblock(&curr_data, &attach_data, updt_str);
	cleanup_bootblock(bblock_curr);
	cleanup_bootblock(bblock_attach);
out_devs:
	cleanup_device(attach_device);
out_currdev:
	cleanup_device(curr_device);
out:
	free(curr_device_path);
	free(attach_device_path);
	return (retval);
}

#define	USAGE_STRING	"Usage:\t%s [-h|-m|-f|-n|-F|-u verstr] stage1 stage2 " \
			"raw-device\n"					\
			"\t%s -M [-n] raw-device attach-raw-device\n"	\
			"\t%s [-e|-V] -i raw-device\n"

#define	CANON_USAGE_STR	gettext(USAGE_STRING)

static void
usage(char *progname)
{
	(void) fprintf(stdout, CANON_USAGE_STR, progname, progname, progname);
}

int
main(int argc, char **argv)
{
	int	opt;
	int	params = 3;
	int	ret;
	char	*progname;
	char	**handle_args;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(BC_ERROR);
	}

	while ((opt = getopt(argc, argv, "deFfhiMmnu:V")) != EOF) {
		switch (opt) {
		case 'd':
			boot_debug = B_TRUE;
			break;
		case 'e':
			strip = B_TRUE;
			break;
		case 'F':
			force_update = B_TRUE;
			break;
		case 'f':
			force_mbr = B_TRUE;
			break;
		case 'h':
			usage(argv[0]);
			exit(BC_SUCCESS);
			break;
		case 'i':
			do_getinfo = B_TRUE;
			params = 1;
			break;
		case 'M':
			do_mirror_bblk = B_TRUE;
			params = 2;
			break;
		case 'm':
			write_mbr = B_TRUE;
			break;
		case 'n':
			nowrite = B_TRUE;
			break;
		case 'u':
			do_version = B_TRUE;

			update_str = malloc(strlen(optarg) + 1);
			if (update_str == NULL) {
				perror(gettext("Memory allocation failure"));
				exit(BC_ERROR);
			}
			(void) strlcpy(update_str, optarg, strlen(optarg) + 1);
			break;
		case 'V':
			verbose_dump = B_TRUE;
			break;
		default:
			/* fall through to process non-optional args */
			break;
		}
	}

	/* check arguments */
	if (argc != optind + params) {
		usage(argv[0]);
		exit(BC_ERROR);
	}
	progname = argv[0];
	check_options(progname);
	handle_args = argv + optind;

	if (nowrite)
		(void) fprintf(stdout, gettext("Dry run requested. Nothing will"
		    " be written to disk.\n"));

	if (do_getinfo) {
		ret = handle_getinfo(progname, handle_args);
	} else if (do_mirror_bblk) {
		ret = handle_mirror(progname, handle_args);
	} else {
		ret = handle_install(progname, handle_args);
	}
	return (ret);
}

#define	MEANINGLESS_OPT gettext("%s specified but meaningless, ignoring\n")
static void
check_options(char *progname)
{
	if (do_getinfo && do_mirror_bblk) {
		(void) fprintf(stderr, gettext("Only one of -M and -i can be "
		    "specified at the same time\n"));
		usage(progname);
		exit(BC_ERROR);
	}

	if (do_mirror_bblk) {
		/*
		 * -u and -F may actually reflect a user intent that is not
		 * correct with this command (mirror can be interpreted
		 * "similar" to install. Emit a message and continue.
		 * -e and -V have no meaning, be quiet here and only report the
		 * incongruence if a debug output is requested.
		 */
		if (do_version) {
			(void) fprintf(stderr, MEANINGLESS_OPT, "-u");
			do_version = B_FALSE;
		}
		if (force_update) {
			(void) fprintf(stderr, MEANINGLESS_OPT, "-F");
			force_update = B_FALSE;
		}
		if (strip || verbose_dump) {
			BOOT_DEBUG(MEANINGLESS_OPT, "-e|-V");
			strip = B_FALSE;
			verbose_dump = B_FALSE;
		}
	}

	if (do_getinfo) {
		if (write_mbr || force_mbr || do_version || force_update) {
			BOOT_DEBUG(MEANINGLESS_OPT, "-m|-f|-u|-F");
			write_mbr = force_mbr = do_version = B_FALSE;
			force_update = B_FALSE;
		}
	}
}
