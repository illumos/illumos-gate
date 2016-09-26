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
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/multiboot.h>
#include <sys/sysmacros.h>

#include "installboot.h"
#include "../../common/bblk_einfo.h"
#include "../../common/boot_utils.h"
#include "../../common/mboot_extra.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

/*
 * SPARC bootblock installation:
 *
 * The bootblock resides in blocks 1 to 15 (disk label is at block 0).
 * The ZFS boot block is larger than what will fit into these first 7.5K so we
 * break it up and write the remaining portion into the ZFS provided boot block
 * region at offset 512K. If versioning is requested, we add a multiboot
 * header at the end of the bootblock, followed by the extra payload area and
 * place the extended information structure within the latter.
 */

static boolean_t	force_update = B_FALSE;
static boolean_t	do_getinfo = B_FALSE;
static boolean_t	do_version = B_FALSE;
static boolean_t	do_mirror_bblk = B_FALSE;
static boolean_t	strip = B_FALSE;
static boolean_t	verbose_dump = B_FALSE;

static char		*update_str;
static int		tgt_fs_type = TARGET_IS_UFS;
char			mboot_scan[MBOOT_SCAN_SIZE];

/* Function prototypes. */
static int read_bootblock_from_file(char *, ib_data_t *data);
static int read_bootblock_from_disk(int, ib_bootblock_t *);
static void add_bootblock_einfo(ib_bootblock_t *, char *);
static int prepare_bootblock(ib_data_t *, char *);
static int write_zfs_bootblock(ib_data_t *);
static int write_bootblock(ib_data_t *);
static int open_device(ib_device_t *);
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
read_bootblock_from_file(char *file, ib_data_t *data)
{
	ib_device_t	*device = &data->device;
	ib_bootblock_t	*bblock = &data->bootblock;
	struct stat 	sb;
	uint32_t	buf_size;
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

	bblock->file_size = sb.st_size;
	BOOT_DEBUG("bootblock file size is %x\n", bblock->file_size);

	/* UFS and HSFS bootblocks need to fit in the reserved 7.5K. */
	if (!is_zfs(device->type)) {
		buf_size = P2ROUNDUP(bblock->file_size, SECTOR_SIZE);
		if (buf_size > BBLK_DATA_RSVD_SIZE) {
			BOOT_DEBUG("boot block size is bigger than allowed\n");
			goto outfd;
		}
	} else {
		buf_size = P2ROUNDUP(bblock->file_size + SECTOR_SIZE,
		    SECTOR_SIZE);
		if (buf_size > BBLK_DATA_RSVD_SIZE + MBOOT_SCAN_SIZE) {
			(void) fprintf(stderr, gettext("WARNING, bootblock size"
			    " does not allow to place extended versioning "
			    "information.. skipping\n"));
			do_version = B_FALSE;
		}
	}

	bblock->buf_size = buf_size;
	BOOT_DEBUG("bootblock in-memory buffer size is %x\n",
	    bblock->buf_size);

	bblock->buf = malloc(buf_size);
	if (bblock->buf == NULL) {
		perror(gettext("Memory allocation failure"));
		goto outbuf;
	}
	bblock->file = bblock->buf;

	if (read(fd, bblock->file, bblock->file_size) != bblock->file_size) {
		BOOT_DEBUG("Read from %s failed\n", file);
		perror("read");
		goto outfd;
	}

	/* If not on ZFS, we are done here. */
	if (!is_zfs(device->type)) {
		BOOT_DEBUG("Reading of the bootblock done\n");
		retval = BC_SUCCESS;
		goto outfd;
	}
	/*
	 * We place the multiboot header right after the file, followed by
	 * the extended information structure.
	 */
	bblock->mboot = (multiboot_header_t *)(bblock->file +
	    P2ROUNDUP(bblock->file_size, 8));
	bblock->extra = (char *)bblock->mboot + sizeof (multiboot_header_t);
	BOOT_DEBUG("mboot at %p, extra at %p, buf=%p (size=%d)\n",
	    bblock->mboot, bblock->extra, bblock->buf, bblock->buf_size);

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
read_bootblock_from_disk(int dev_fd, ib_bootblock_t *bblock)
{
	char			*dest;
	uint32_t		size;
	uint32_t		buf_size;
	uint32_t		mboot_off;
	multiboot_header_t	*mboot;

	assert(bblock != NULL);
	assert(dev_fd != -1);

	/*
	 * The ZFS bootblock is divided in two parts, but the fake multiboot
	 * header can only be in the second part (the one contained in the ZFS
	 * reserved area).
	 */
	if (read_in(dev_fd, mboot_scan, sizeof (mboot_scan),
	    BBLK_ZFS_EXTRA_OFF) != BC_SUCCESS) {
		BOOT_DEBUG("Error reading ZFS reserved area\n");
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

	dest = bblock->buf;
	size = BBLK_DATA_RSVD_SIZE;

	if (read_in(dev_fd, dest, size, SECTOR_SIZE) != BC_SUCCESS) {
		BOOT_DEBUG("Error reading first %d bytes of the bootblock\n",
		    size);
		(void) free(bblock->buf);
		bblock->buf = NULL;
		return (BC_ERROR);
	}

	dest += BBLK_DATA_RSVD_SIZE;
	size = bblock->buf_size - BBLK_DATA_RSVD_SIZE;

	if (read_in(dev_fd, dest, size, BBLK_ZFS_EXTRA_OFF) != BC_SUCCESS) {
		BOOT_DEBUG("Error reading ZFS reserved area the second time\n");
		(void) free(bblock->buf);
		bblock->buf = NULL;
		return (BC_ERROR);
	}

	/* Update pointers. */
	bblock->file = bblock->buf;
	bblock->mboot_off = mboot_off;
	bblock->mboot = (multiboot_header_t *)(bblock->buf + bblock->mboot_off
	    + BBLK_DATA_RSVD_SIZE);
	bblock->extra = (char *)bblock->mboot + sizeof (multiboot_header_t);
	bblock->extra_size = bblock->buf_size - bblock->mboot_off
	    - BBLK_DATA_RSVD_SIZE - sizeof (multiboot_header_t);
	return (BC_SUCCESS);
}

static boolean_t
is_update_necessary(ib_data_t *data, char *updt_str)
{
	bblk_einfo_t	*einfo;
	bblk_hs_t	bblock_hs;
	ib_bootblock_t	bblock_disk;
	ib_bootblock_t	*bblock_file = &data->bootblock;
	ib_device_t	*device = &data->device;
	int		dev_fd = device->fd;

	assert(data != NULL);
	assert(device->fd != -1);

	/* Nothing to do if we are not updating a ZFS bootblock. */
	if (!is_zfs(device->type))
		return (B_TRUE);

	bzero(&bblock_disk, sizeof (ib_bootblock_t));

	if (read_bootblock_from_disk(dev_fd, &bblock_disk) != BC_SUCCESS) {
		BOOT_DEBUG("Unable to read bootblock from %s\n", device->path);
		return (B_TRUE);
	}

	einfo = find_einfo(bblock_disk.extra, bblock_disk.extra_size);
	if (einfo == NULL) {
		BOOT_DEBUG("No extended information available\n");
		return (B_TRUE);
	}

	if (!do_version || updt_str == NULL) {
		(void) fprintf(stdout, "WARNING: target device %s has a "
		    "versioned bootblock that is going to be overwritten by a "
		    "non versioned one\n", device->path);
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


static int
prepare_bootblock(ib_data_t *data, char *updt_str)
{
	ib_device_t		*device = &data->device;
	ib_bootblock_t		*bblock = &data->bootblock;
	multiboot_header_t	*mboot;

	assert(data != NULL);

	/* Nothing to do if we are not on ZFS. */
	if (!is_zfs(device->type))
		return (BC_SUCCESS);

	/*
	 * Write the fake multiboot structure followed by the extra information
	 * data. Both mboot and extra pointers have already been filled up to
	 * point to the right location in the buffer. We prepare the fake
	 * multiboot regardless if versioning was requested or not because
	 * we need it for mirroring support.
	 */
	assert(bblock->mboot != NULL);
	assert(bblock->extra != NULL);

	mboot = bblock->mboot;

	mboot->magic = MB_HEADER_MAGIC;
	mboot->flags = MB_HEADER_FLAGS_64;
	mboot->checksum = -(mboot->flags + mboot->magic);
	/*
	 * Flags include the AOUT_KLUDGE and we use the extra members to specify
	 * the size of the bootblock.
	 */
	mboot->header_addr = bblock->mboot_off;
	mboot->load_addr = 0;
	mboot->load_end_addr = bblock->file_size;

	/*
	 * Now that we have the mboot header in place, we can add the extended
	 * versioning information. Since the multiboot header has been placed
	 * after the file image, the hashing will still reflect the one of the
	 * file on the disk.
	 */
	if (do_version)
		add_bootblock_einfo(bblock, updt_str);

	return (BC_SUCCESS);
}

static int
write_zfs_bootblock(ib_data_t *data)
{
	ib_device_t	*device = &data->device;
	ib_bootblock_t	*bblock = &data->bootblock;
	char		*bufptr;
	uint32_t	size;

	assert(data != NULL);
	assert(device->fd != -1);

	/*
	 * In the ZFS case we actually perform two different steps:
	 * - write the first 15 blocks of the bootblock to the reserved disk
	 *   blocks.
	 * - write the remaining blocks in the ZFS reserved area at offset
	 *   512K.
	 */
	bufptr = bblock->buf;
	size = BBLK_DATA_RSVD_SIZE;

	if (write_out(device->fd, bufptr, size, SECTOR_SIZE) != BC_SUCCESS) {
		BOOT_DEBUG("Error writing first 15 blocks of %s\n",
		    device->path);
		perror("write");
		return (BC_ERROR);
	}

	bufptr += BBLK_DATA_RSVD_SIZE;
	size = bblock->buf_size - BBLK_DATA_RSVD_SIZE;

	if (write_out(device->fd, bufptr, size, BBLK_ZFS_EXTRA_OFF)
	    != BC_SUCCESS) {
		BOOT_DEBUG("Error writing the second part of ZFS bootblock "
		    "to %s at offset %d\n", device->path, BBLK_ZFS_EXTRA_OFF);
		return (BC_ERROR);
	}
	return (BC_SUCCESS);
}

static int
write_bootblock(ib_data_t *data)
{
	ib_device_t	*device = &data->device;
	ib_bootblock_t	*bblock = &data->bootblock;
	int		ret;

	assert(data != NULL);

	/*
	 * If we are on UFS or HSFS we simply write out to the reserved
	 * blocks (1 to 15) the boot block.
	 */
	if (!is_zfs(device->type)) {
		if (write_out(device->fd, bblock->buf, bblock->buf_size,
		    SECTOR_SIZE) != BC_SUCCESS) {
			BOOT_DEBUG("Error writing bootblock to %s\n",
			    device->path);
			return (BC_ERROR);
		} else {
			return (BC_SUCCESS);
		}
	} else {
		ret = write_zfs_bootblock(data);
		return (ret);
	}
}

static int
open_device(ib_device_t *device)
{
	struct stat	statbuf;

	device->fd = open(device->path, O_RDWR);
	if (device->fd == -1) {
		BOOT_DEBUG("Unable to open %s\n", device->path);
		perror("open");
		return (BC_ERROR);
	}

	if (fstat(device->fd, &statbuf) != 0) {
		BOOT_DEBUG("Unable to stat %s\n", device->path);
		perror("stat");
		(void) close(device->fd);
		return (BC_ERROR);
	}

	if (S_ISCHR(statbuf.st_mode) == 0) {
		(void) fprintf(stderr, gettext("%s: Not a character device\n"),
		    device->path);
		return (BC_ERROR);
	}

	return (BC_SUCCESS);
}

static int
init_device(ib_device_t *device, char *path)
{
	bzero(device, sizeof (*device));
	device->fd = -1;

	device->path = strdup(path);
	if (path == NULL) {
		perror(gettext("Memory allocation failure"));
		return (BC_ERROR);
	}

	device->type = tgt_fs_type;
	if (open_device(device) != BC_SUCCESS)
		return (BC_ERROR);

	return (BC_SUCCESS);
}

static void
cleanup_device(ib_device_t *device)
{
	free(device->path);
	bzero(device, sizeof (*device));

	if (device->fd != -1)
		(void) close(device->fd);
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
	uint32_t	buf_size;

	assert(src != NULL);
	assert(dest != NULL);

	cleanup_bootblock(dest_bblock);

	if (updt_str != NULL) {
		do_version = B_TRUE;
	} else {
		do_version = B_FALSE;
	}

	buf_size = src_bblock->file_size + SECTOR_SIZE;

	dest_bblock->buf_size = P2ROUNDUP(buf_size, SECTOR_SIZE);
	dest_bblock->buf = malloc(dest_bblock->buf_size);
	if (dest_bblock->buf == NULL) {
		perror(gettext("Memory Allocation Failure"));
		return (BC_ERROR);
	}
	dest_bblock->file = dest_bblock->buf;
	dest_bblock->file_size = src_bblock->file_size;
	(void) memcpy(dest_bblock->file, src_bblock->file,
	    dest_bblock->file_size);

	dest_bblock->mboot = (multiboot_header_t *)(dest_bblock->file +
	    P2ROUNDUP(dest_bblock->file_size, 8));
	dest_bblock->extra = (char *)dest_bblock->mboot +
	    sizeof (multiboot_header_t);

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

	if (write_bootblock(data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error writing bootblock to "
		    "disk\n"));
		return (BC_ERROR);
	}

	return (BC_SUCCESS);
}


/*
 * Install a new bootblock on the given device. handle_install() expects argv
 * to contain 2 parameters (the target device path and the path to the
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
	char		*bootblock = NULL;
	char		*device_path = NULL;
	int		ret = BC_ERROR;

	bootblock = strdup(argv[0]);
	device_path = strdup(argv[1]);

	if (!device_path || !bootblock) {
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname);
		goto out;
	}

	BOOT_DEBUG("device path: %s, bootblock file path: %s\n", device_path,
	    bootblock);
	bzero(&install_data, sizeof (ib_data_t));

	if (init_device(&install_data.device, device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to open device %s\n"),
		    device_path);
		goto out;
	}

	if (read_bootblock_from_file(bootblock, &install_data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error reading %s\n"),
		    bootblock);
		goto out_dev;
	}
	/* Versioning is only supported for the ZFS bootblock. */
	if (do_version && !is_zfs(install_data.device.type)) {
		(void) fprintf(stderr, gettext("Versioning is only supported on"
		    " ZFS... skipping.\n"));
		do_version = B_FALSE;
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
	free(bootblock);
	free(device_path);
	return (ret);
}

/*
 * Retrieves from a device the extended information (einfo) associated to the
 * installed bootblock.
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
	uint32_t	size;
	char		*device_path;
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

	if (!is_zfs(device->type)) {
		(void) fprintf(stderr, gettext("Versioning only supported on "
		    "ZFS\n"));
		goto out_dev;
	}

	ret = read_bootblock_from_disk(device->fd, bblock);
	if (ret == BC_ERROR) {
		(void) fprintf(stderr, gettext("Error reading bootblock from "
		    "%s\n"), device_path);
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

	size = bblock->buf_size - P2ROUNDUP(bblock->file_size, 8) -
	    sizeof (multiboot_header_t);
	print_einfo(flags, einfo, size);
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

	if (tgt_fs_type != TARGET_IS_ZFS) {
		(void) fprintf(stderr, gettext("Mirroring is only supported on "
		    "ZFS\n"));
		return (BC_ERROR);
	}

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

	ret = read_bootblock_from_disk(curr_device->fd, bblock_curr);
	if (ret == BC_ERROR) {
		BOOT_DEBUG("Error reading bootblock from %s\n",
		    curr_device->path);
		retval = BC_ERROR;
		goto out_devs;
	}

	if (ret == BC_NOEXTRA) {
		BOOT_DEBUG("No multiboot header found on %s, unable to retrieve"
		    " the bootblock\n", curr_device->path);
		retval = BC_NOEXTRA;
		goto out_devs;
	}

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

#define	USAGE_STRING	"Usage: %s [-h|-f|-F fstype|-u verstr] bootblk "       \
			"raw-device\n"					       \
			"\t%s [-e|-V] -i -F zfs raw-device\n"	               \
			"\t%s -M -F zfs raw-device attach-raw-device\n"        \
			"\tfstype is one of: 'ufs', 'hsfs' or 'zfs'\n"

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
	int	params = 2;
	int	ret;
	char	*progname;
	char	**handle_args;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "F:efiVMndhu:")) != EOF) {
		switch (opt) {
		case 'F':
			if (strcmp(optarg, "ufs") == 0) {
				tgt_fs_type = TARGET_IS_UFS;
			} else if (strcmp(optarg, "hsfs") == 0) {
				tgt_fs_type = TARGET_IS_HSFS;
			} else if (strcmp(optarg, "zfs") == 0) {
				tgt_fs_type = TARGET_IS_ZFS;
			} else {
				(void) fprintf(stderr, gettext("Wrong "
				    "filesystem specified\n\n"));
				usage(argv[0]);
				exit(BC_ERROR);
			}
			break;
		case 'e':
			strip = B_TRUE;
			break;
		case 'f':
			force_update = B_TRUE;
			break;
		case 'V':
			verbose_dump = B_TRUE;
			break;
		case 'i':
			do_getinfo = B_TRUE;
			params = 1;
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
		case 'M':
			do_mirror_bblk = B_TRUE;
			break;
		case 'h':
			usage(argv[0]);
			exit(BC_SUCCESS);
			break;
		case 'd':
			boot_debug = B_TRUE;
			break;
		case 'n':
			nowrite = B_TRUE;
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
	handle_args = argv + optind;

	/* check options. */
	if (do_getinfo && do_mirror_bblk) {
		(void) fprintf(stderr, gettext("Only one of -M and -i can be "
		    "specified at the same time\n"));
		usage(progname);
		exit(BC_ERROR);
	}

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
