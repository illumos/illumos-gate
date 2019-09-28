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
 * Copyright 2019 Toomas Soome <tsoome@me.com>
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <strings.h>
#include <libfdisk.h>
#include <err.h>
#include <time.h>
#include <spawn.h>

#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/multiboot.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/efi_partition.h>
#include <sys/queue.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/wait.h>
#include <libfstyp.h>
#include <libgen.h>
#include <uuid/uuid.h>

#include "installboot.h"
#include "bblk_einfo.h"
#include "boot_utils.h"
#include "mboot_extra.h"
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

static bool	write_mbr = false;
static bool	write_vbr = false;
static bool	force_mbr = false;
static bool	force_update = false;
static bool	do_getinfo = false;
static bool	do_version = false;
static bool	do_mirror_bblk = false;
static bool	strip = false;
static bool	verbose_dump = false;
static size_t	sector_size = SECTOR_SIZE;

/* Versioning string, if present. */
static char		*update_str;

/* Default location of boot programs. */
static char		*boot_dir = "/boot";

/* Our boot programs */
#define	STAGE1		"pmbr"
#define	STAGE2		"gptzfsboot"
#define	BOOTIA32	"bootia32.efi"
#define	BOOTX64		"bootx64.efi"
#define	LOADER32	"loader32.efi"
#define	LOADER64	"loader64.efi"

static char *stage1;
static char *stage2;
static char *efi32;
static char *efi64;

#define	GRUB_VERSION_OFF (0x3e)
#define	GRUB_COMPAT_VERSION_MAJOR 3
#define	GRUB_COMPAT_VERSION_MINOR 2
#define	GRUB_VERSION (2 << 8 | 3) /* 3.2 */

#define	LOADER_VERSION (1)
#define	LOADER_JOYENT_VERSION (2)

typedef enum {
	MBR_TYPE_UNKNOWN,
	MBR_TYPE_GRUB1,
	MBR_TYPE_LOADER,
	MBR_TYPE_LOADER_JOYENT,
} mbr_type_t;

/*
 * Temporary buffer to store the first 32K of data looking for a multiboot
 * signature.
 */
char			mboot_scan[MBOOT_SCAN_SIZE];

/* Function prototypes. */
static void check_options(char *);
static int open_device(const char *);
static char *make_blkdev(const char *);

static int read_bootblock_from_file(const char *, ib_bootblock_t *);
static void add_bootblock_einfo(ib_bootblock_t *, char *);
static void prepare_bootblock(ib_data_t *, struct partlist *, char *);
static int handle_install(char *, int, char **);
static int handle_getinfo(char *, int, char **);
static int handle_mirror(char *, int, char **);
static void usage(char *, int) __NORETURN;

static char *
stagefs_mount(char *blkdev, struct partlist *plist)
{
	char *path;
	char optbuf[MAX_MNTOPT_STR] = { '\0', };
	char *template = strdup("/tmp/ibootXXXXXX");
	int ret;

	if (template == NULL)
		return (NULL);

	if ((path = mkdtemp(template)) == NULL) {
		free(template);
		return (NULL);
	}

	(void) snprintf(optbuf, MAX_MNTOPT_STR, "timezone=%d",
	    timezone);
	ret = mount(blkdev, path, MS_OPTIONSTR,
	    MNTTYPE_PCFS, NULL, 0, optbuf, MAX_MNTOPT_STR);
	if (ret != 0) {
		(void) rmdir(path);
		free(path);
		path = NULL;
	}
	plist->pl_device->stage.mntpnt = path;
	return (path);
}

static void
install_stage1_cb(void *data, struct partlist *plist)
{
	int rv, fd;
	ib_device_t *device = plist->pl_device;

	if (plist->pl_type == IB_BBLK_MBR && !write_mbr)
		return;

	if ((fd = open_device(plist->pl_devname)) == -1) {
		(void) fprintf(stdout, gettext("cannot open "
		    "device %s\n"), plist->pl_devname);
		perror("open");
		return;
	}

	rv = write_out(fd, plist->pl_stage, sector_size, 0);
	if (rv != BC_SUCCESS) {
		(void) fprintf(stdout, gettext("cannot write "
		    "partition boot sector\n"));
		perror("write");
	} else {
		(void) fprintf(stdout, gettext("stage1 written to "
		    "%s %d sector 0 (abs %d)\n\n"),
		    device->devtype == IB_DEV_MBR? "partition" : "slice",
		    device->stage.id, device->stage.start);
	}
}

static void
install_stage2_cb(void *data, struct partlist *plist)
{
	ib_bootblock_t *bblock = plist->pl_src_data;
	int fd, ret;
	off_t offset;
	uint64_t abs;

	/*
	 * ZFS bootblock area is 3.5MB, make sure we can fit.
	 * buf_size is size of bootblk+EINFO.
	 */
	if (bblock->buf_size > BBLK_ZFS_BLK_SIZE) {
		(void) fprintf(stderr, gettext("bootblock is too large\n"));
		return;
	}

	abs = plist->pl_device->stage.start + plist->pl_device->stage.offset;

	if ((fd = open_device(plist->pl_devname)) == -1) {
		(void) fprintf(stdout, gettext("cannot open "
		    "device %s\n"), plist->pl_devname);
		perror("open");
		return;
	}
	offset = plist->pl_device->stage.offset * SECTOR_SIZE;
	ret = write_out(fd, bblock->buf, bblock->buf_size, offset);
	(void) close(fd);
	if (ret != BC_SUCCESS) {
		BOOT_DEBUG("Error writing the ZFS bootblock "
		    "to %s at offset %d\n", plist->pl_devname, offset);
		return;
	}
	(void) fprintf(stdout, gettext("bootblock written for %s,"
	    " %d sectors starting at %d (abs %lld)\n\n"), plist->pl_devname,
	    (bblock->buf_size / SECTOR_SIZE) + 1, offset / SECTOR_SIZE, abs);
}

static bool
mkfs_pcfs(const char *dev)
{
	pid_t pid, w;
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t file_actions;
	int status;
	char *cmd[7];

	if (posix_spawnattr_init(&attr))
		return (false);
	if (posix_spawn_file_actions_init(&file_actions)) {
		(void) posix_spawnattr_destroy(&attr);
		return (false);
	}

	if (posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP)) {
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&file_actions);
		return (false);
	}
	if (posix_spawn_file_actions_addopen(&file_actions, 0, "/dev/null",
	    O_RDONLY, 0)) {
		(void) posix_spawnattr_destroy(&attr);
		(void) posix_spawn_file_actions_destroy(&file_actions);
		return (false);
	}

	cmd[0] = "/usr/sbin/mkfs";
	cmd[1] = "-F";
	cmd[2] = "pcfs";
	cmd[3] = "-o";
	cmd[4] = "fat=32";
	cmd[5] = (char *)dev;
	cmd[6] = NULL;

	if (posix_spawn(&pid, cmd[0], &file_actions, &attr, cmd, NULL))
		return (false);
	(void) posix_spawnattr_destroy(&attr);
	(void) posix_spawn_file_actions_destroy(&file_actions);

	do {
		w = waitpid(pid, &status, 0);
	} while (w == -1 && errno == EINTR);
	if (w == -1)
		status = -1;

	return (status != -1);
}

static void
install_esp_cb(void *data, struct partlist *plist)
{
	fstyp_handle_t fhdl;
	const char *fident;
	bool pcfs;
	char *blkdev, *path, *file;
	FILE *fp;
	struct mnttab mp, mpref = { 0 };
	ib_bootblock_t *bblock = plist->pl_src_data;
	int fd, ret;

	if ((fd = open_device(plist->pl_devname)) == -1)
		return;

	if (fstyp_init(fd, 0, NULL, &fhdl) != 0) {
		(void) close(fd);
		return;
	}

	pcfs = false;
	if (fstyp_ident(fhdl, NULL, &fident) == 0) {
		if (strcmp(fident, MNTTYPE_PCFS) == 0)
			pcfs = true;
	}
	fstyp_fini(fhdl);
	(void) close(fd);

	if (!pcfs) {
		(void) printf(gettext("Creating pcfs on ESP %s\n"),
		    plist->pl_devname);

		if (!mkfs_pcfs(plist->pl_devname)) {
			(void) fprintf(stderr, gettext("mkfs -F pcfs failed "
			    "on %s\n"), plist->pl_devname);
			return;
		}
	}
	blkdev = make_blkdev(plist->pl_devname);
	if (blkdev == NULL)
		return;

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		perror("fopen");
		free(blkdev);
		return;
	}

	mpref.mnt_special = blkdev;
	ret = getmntany(fp, &mp, &mpref);
	(void) fclose(fp);
	if (ret == 0)
		path = mp.mnt_mountp;
	else
		path = stagefs_mount(blkdev, plist);

	free(blkdev);
	if (path == NULL)
		return;

	if (asprintf(&file, "%s%s", path, "/EFI") < 0) {
		perror(gettext("Memory allocation failure"));
		return;
	}

	ret = mkdir(file, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret == 0 || errno == EEXIST) {
		free(file);
		if (asprintf(&file, "%s%s", path, "/EFI/Boot") < 0) {
			perror(gettext("Memory allocation failure"));
			return;
		}
		ret = mkdir(file,
		    S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		if (errno == EEXIST)
			ret = 0;
	}
	free(file);
	if (ret < 0) {
		perror("mkdir");
		return;
	}

	if (asprintf(&file, "%s%s", path, plist->pl_device->stage.path) < 0) {
		perror(gettext("Memory allocation failure"));
		return;
	}

	/* Write stage file. Should create temp file and rename. */
	(void) chmod(file, S_IRUSR | S_IWUSR);
	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd != -1) {
		ret = write_out(fd, bblock->buf, bblock->buf_size, 0);
		if (ret == BC_SUCCESS) {
			(void) fprintf(stdout,
			    gettext("bootblock written to %s\n\n"), file);
		} else {
			(void) fprintf(stdout,
			    gettext("error while writing %s\n"), file);
		}
		(void) fchmod(fd, S_IRUSR | S_IRGRP | S_IROTH);
		(void) close(fd);
	}
	free(file);
}

/*
 * MBR setup only depends on write_mbr toggle.
 */
static bool
compare_mbr_cb(struct partlist *plist)
{
	/* get confirmation for -m */
	if (write_mbr && !force_mbr) {
		(void) fprintf(stdout, gettext("Updating master boot sector "
		    "destroys existing boot managers (if any).\n"
		    "continue (y/n)? "));
		if (!yes()) {
			write_mbr = false;
			(void) fprintf(stdout, gettext("master boot sector "
			    "not updated\n"));
		}
	}
	if (write_mbr)
		(void) printf("%s is newer than one in %s\n",
		    plist->pl_src_name, plist->pl_devname);
	return (write_mbr);
}

/*
 * VBR setup is done in pair with stage2.
 */
static bool
compare_stage1_cb(struct partlist *plist)
{
	if (write_vbr) {
		(void) printf("%s will be written to %s\n", plist->pl_src_name,
		    plist->pl_devname);
	}
	return (write_vbr);
}

/*
 * Return true if we can update, false if not.
 */
static bool
compare_einfo_cb(struct partlist *plist)
{
	ib_bootblock_t *bblock, *bblock_file;
	bblk_einfo_t *einfo, *einfo_file;
	bblk_hs_t bblock_hs;
	bool rv;

	bblock_file = plist->pl_src_data;
	if (bblock_file == NULL)
		return (false);	/* source is missing, cannot update */

	bblock = plist->pl_stage;
	if (bblock == NULL ||
	    bblock->extra == NULL ||
	    bblock->extra_size == 0) {
		if (plist->pl_type == IB_BBLK_STAGE2)
			write_vbr = true;
		return (true);
	}

	einfo = find_einfo(bblock->extra, bblock->extra_size);
	if (einfo == NULL) {
		BOOT_DEBUG("No extended information available on disk\n");
		if (plist->pl_type == IB_BBLK_STAGE2)
			write_vbr = true;
		return (true);
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
		return (false);
	} else {
		if (update_str == NULL) {
			update_str = einfo_get_string(einfo_file);
			do_version = true;
		}
	}

	if (!do_version || update_str == NULL) {
		(void) fprintf(stderr,
		    gettext("WARNING: target device %s has a "
		    "versioned bootblock that is going to be overwritten by a "
		    "non versioned one\n"), plist->pl_devname);
		if (plist->pl_type == IB_BBLK_STAGE2)
			write_vbr = true;
		return (true);
	}

	if (force_update) {
		BOOT_DEBUG("Forcing update of %s bootblock\n",
		    plist->pl_devname);
		if (plist->pl_type == IB_BBLK_STAGE2)
			write_vbr = true;
		return (true);
	}

	BOOT_DEBUG("Ready to check installed version vs %s\n", update_str);

	bblock_hs.src_buf = (unsigned char *)bblock_file->file;
	bblock_hs.src_size = bblock_file->file_size;

	rv = einfo_should_update(einfo, &bblock_hs, update_str);
	if (rv == false) {
		(void) fprintf(stderr, gettext("Bootblock version installed "
		    "on %s is more recent or identical to\n%s\n"
		    "Use -F to override or install without the -u option.\n\n"),
		    plist->pl_devname, plist->pl_src_name);
	} else {
		(void) printf("%s is newer than one in %s\n",
		    plist->pl_src_name, plist->pl_devname);
		if (plist->pl_type == IB_BBLK_STAGE2)
			write_vbr = true;
	}
	return (rv);
}

static bool
read_stage1_cb(struct partlist *plist)
{
	int fd;
	bool rv = false;

	if ((fd = open_device(plist->pl_devname)) == -1)
		return (rv);

	if (plist->pl_stage == NULL)
		plist->pl_stage = calloc(1, sector_size);

	if (plist->pl_stage == NULL) {
		perror("calloc");
		goto done;
	}

	if (pread(fd, plist->pl_stage, sector_size, 0) == -1) {
		perror("pread");
		goto done;
	}
	rv = true;
done:
	(void) close(fd);
	return (rv);
}

static bool
read_stage1_bbl_cb(struct partlist *plist)
{
	int fd;
	void *data;
	bool rv = false;

	data = malloc(SECTOR_SIZE);
	if (data == NULL)
		return (rv);

	/* read the stage1 file from filesystem */
	fd = open(plist->pl_src_name, O_RDONLY);
	if (fd == -1 ||
	    read(fd, data, SECTOR_SIZE) != SECTOR_SIZE) {
		(void) fprintf(stderr, gettext("cannot read stage1 file %s\n"),
		    plist->pl_src_name);
		free(data);
		if (fd != -1)
			(void) close(fd);
		return (rv);
	}

	plist->pl_src_data = data;
	(void) close(fd);
	return (true);
}

static bool
read_stage2_cb(struct partlist *plist)
{
	ib_device_t		*device;
	ib_bootblock_t		*bblock;
	int			fd;
	uint32_t		size, offset;
	uint32_t		buf_size;
	uint32_t		mboot_off;
	multiboot_header_t	*mboot;
	size_t			scan_size;

	bblock = calloc(1, sizeof (ib_bootblock_t));
	if (bblock == NULL)
		return (false);

	if ((fd = open_device(plist->pl_devname)) == -1) {
		free(bblock);
		return (false);
	}

	device = plist->pl_device;
	plist->pl_stage = bblock;
	offset = device->stage.offset * SECTOR_SIZE;
	scan_size = MIN(sizeof (mboot_scan),
	    (device->stage.size - device->stage.offset) * sector_size);

	if (read_in(fd, mboot_scan, scan_size, offset)
	    != BC_SUCCESS) {
		BOOT_DEBUG("Error reading bootblock area\n");
		perror("read");
		(void) close(fd);
		return (false);
	}

	/* No multiboot means no chance of knowing bootblock size */
	if (find_multiboot(mboot_scan, scan_size, &mboot_off)
	    != BC_SUCCESS) {
		BOOT_DEBUG("Unable to find multiboot header\n");
		(void) close(fd);
		return (false);
	}
	mboot = (multiboot_header_t *)(mboot_scan + mboot_off);

	/*
	 * make sure mboot has sane values
	 */
	if (mboot->load_end_addr == 0 ||
	    mboot->load_end_addr < mboot->load_addr) {
		(void) close(fd);
		return (false);
	}

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
		(void) close(fd);
		return (false);
	}
	bblock->buf_size = buf_size;

	if (read_in(fd, bblock->buf, buf_size, offset) != BC_SUCCESS) {
		BOOT_DEBUG("Error reading the bootblock\n");
		(void) free(bblock->buf);
		bblock->buf = NULL;
		(void) close(fd);
		return (false);
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

	return (true);
}

static bool
read_einfo_file_cb(struct partlist *plist)
{
	int rc;
	void *stage;

	stage = calloc(1, sizeof (ib_bootblock_t));
	if (stage == NULL)
		return (false);

	rc =  read_bootblock_from_file(plist->pl_devname, stage);
	if (rc != BC_SUCCESS) {
		free(stage);
		stage = NULL;
	}
	plist->pl_stage = stage;
	return (rc == BC_SUCCESS);
}

static bool
read_stage2_file_cb(struct partlist *plist)
{
	int rc;
	void *data;

	data = calloc(1, sizeof (ib_bootblock_t));
	if (data == NULL)
		return (false);

	rc = read_bootblock_from_file(plist->pl_src_name, data);
	if (rc != BC_SUCCESS) {
		free(data);
		data = NULL;
	}
	plist->pl_src_data = data;
	return (rc == BC_SUCCESS);
}

/*
 * convert /dev/rdsk/... to /dev/dsk/...
 */
static char *
make_blkdev(const char *path)
{
	char *tmp;
	char *ptr = strdup(path);

	if (ptr == NULL)
		return (ptr);

	tmp = strstr(ptr, "rdsk");
	if (tmp == NULL) {
		free(ptr);
		return (NULL); /* Something is very wrong */
	}
	/* This is safe because we do shorten the string */
	(void) memmove(tmp, tmp + 1, strlen(tmp));
	return (ptr);
}

/*
 * Try to mount ESP and read boot program.
 */
static bool
read_einfo_esp_cb(struct partlist *plist)
{
	fstyp_handle_t fhdl;
	const char *fident;
	char *blkdev, *path, *file;
	bool rv = false;
	FILE *fp;
	struct mnttab mp, mpref = { 0 };
	int fd, ret;

	if ((fd = open_device(plist->pl_devname)) == -1)
		return (rv);

	if (fstyp_init(fd, 0, NULL, &fhdl) != 0) {
		(void) close(fd);
		return (rv);
	}

	if (fstyp_ident(fhdl, NULL, &fident) != 0) {
		fstyp_fini(fhdl);
		(void) close(fd);
		(void) fprintf(stderr, gettext("Failed to detect file "
		    "system type\n"));
		return (rv);
	}

	/* We only do expect pcfs. */
	if (strcmp(fident, MNTTYPE_PCFS) != 0) {
		(void) fprintf(stderr,
		    gettext("File system %s is not supported.\n"), fident);
		fstyp_fini(fhdl);
		(void) close(fd);
		return (rv);
	}
	fstyp_fini(fhdl);
	(void) close(fd);

	blkdev = make_blkdev(plist->pl_devname);
	if (blkdev == NULL)
		return (rv);

	/* mount ESP if needed, read boot program(s) and unmount. */
	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		perror("fopen");
		free(blkdev);
		return (rv);
	}

	mpref.mnt_special = blkdev;
	ret = getmntany(fp, &mp, &mpref);
	(void) fclose(fp);
	if (ret == 0)
		path = mp.mnt_mountp;
	else
		path = stagefs_mount(blkdev, plist);

	free(blkdev);
	if (path == NULL)
		return (rv);

	if (asprintf(&file, "%s%s", path, plist->pl_device->stage.path) < 0) {
		return (rv);
	}

	plist->pl_stage = calloc(1, sizeof (ib_bootblock_t));
	if (plist->pl_stage == NULL) {
		free(file);
		return (rv);
	}
	if (read_bootblock_from_file(file, plist->pl_stage) != BC_SUCCESS) {
		free(plist->pl_stage);
		plist->pl_stage = NULL;
	} else {
		rv = true;
	}

	free(file);
	return (rv);
}

static void
print_stage1_cb(struct partlist *plist)
{
	struct mboot *mbr;
	struct ipart *part;
	mbr_type_t type = MBR_TYPE_UNKNOWN;
	bool pmbr = false;
	char *label;

	mbr = plist->pl_stage;

	if (*((uint16_t *)&mbr->bootinst[GRUB_VERSION_OFF]) == GRUB_VERSION) {
		type = MBR_TYPE_GRUB1;
	} else if (mbr->bootinst[STAGE1_MBR_VERSION] == LOADER_VERSION) {
		type = MBR_TYPE_LOADER;
	} else if (mbr->bootinst[STAGE1_MBR_VERSION] == LOADER_JOYENT_VERSION) {
		type = MBR_TYPE_LOADER_JOYENT;
	}

	part = (struct ipart *)mbr->parts;
	for (int i = 0; i < FD_NUMPART; i++) {
		if (part[i].systid == EFI_PMBR)
			pmbr = true;
	}

	if (plist->pl_type == IB_BBLK_MBR)
		label = pmbr ? "PMBR" : "MBR";
	else
		label = "VBR";

	printf("%s block from %s:\n", label, plist->pl_devname);

	switch (type) {
	case MBR_TYPE_UNKNOWN:
		printf("Format: unknown\n");
		break;
	case MBR_TYPE_GRUB1:
		printf("Format: grub1\n");
		break;
	case MBR_TYPE_LOADER:
		printf("Format: loader (illumos)\n");
		break;
	case MBR_TYPE_LOADER_JOYENT:
		printf("Format: loader (joyent)\n");
		break;
	}

	printf("Signature: 0x%hx (%s)\n", mbr->signature,
	    mbr->signature == MBB_MAGIC ? "valid" : "invalid");

	printf("UniqueMBRDiskSignature: %#lx\n",
	    *(uint32_t *)&mbr->bootinst[STAGE1_SIG]);

	if (type == MBR_TYPE_LOADER || type == MBR_TYPE_LOADER_JOYENT) {
		char uuid[UUID_PRINTABLE_STRING_LENGTH];

		printf("Loader STAGE1_STAGE2_LBA: %llu\n",
		    *(uint64_t *)&mbr->bootinst[STAGE1_STAGE2_LBA]);

		printf("Loader STAGE1_STAGE2_SIZE: %hu\n",
		    *(uint16_t *)&mbr->bootinst[STAGE1_STAGE2_SIZE]);

		uuid_unparse((uchar_t *)&mbr->bootinst[STAGE1_STAGE2_UUID],
		    uuid);

		printf("Loader STAGE1_STAGE2_UUID: %s\n", uuid);
	}
	printf("\n");
}

static void
print_einfo_cb(struct partlist *plist)
{
	uint8_t flags = 0;
	ib_bootblock_t *bblock;
	bblk_einfo_t *einfo = NULL;
	const char *filepath;

	/* No stage, get out. */
	bblock = plist->pl_stage;
	if (bblock == NULL)
		return;

	if (plist->pl_device->stage.path == NULL)
		filepath = "";
	else
		filepath = plist->pl_device->stage.path;

	printf("Boot block from %s:%s\n", plist->pl_devname, filepath);

	if (bblock->extra != NULL)
		einfo = find_einfo(bblock->extra, bblock->extra_size);

	if (einfo == NULL) {
		(void) fprintf(stderr,
		    gettext("No extended information found.\n\n"));
		return;
	}

	/* Print the extended information. */
	if (strip)
		flags |= EINFO_EASY_PARSE;
	if (verbose_dump)
		flags |= EINFO_PRINT_HEADER;

	print_einfo(flags, einfo, bblock->extra_size);
	printf("\n");
}

static size_t
get_media_info(int fd)
{
	struct dk_minfo disk_info;

	if ((ioctl(fd, DKIOCGMEDIAINFO, (caddr_t)&disk_info)) == -1)
		return (SECTOR_SIZE);

	return (disk_info.dki_lbsize);
}

static struct partlist *
partlist_alloc(void)
{
	struct partlist *pl;

	if ((pl = calloc(1, sizeof (*pl))) == NULL) {
		perror("calloc");
		return (NULL);
	}

	pl->pl_device = calloc(1, sizeof (*pl->pl_device));
	if (pl->pl_device == NULL) {
		perror("calloc");
		free(pl);
		return (NULL);
	}

	return (pl);
}

static void
partlist_free(struct partlist *pl)
{
	ib_bootblock_t *bblock;
	ib_device_t *device;

	switch (pl->pl_type) {
	case IB_BBLK_MBR:
	case IB_BBLK_STAGE1:
		free(pl->pl_stage);
		break;
	default:
		if (pl->pl_stage != NULL) {
			bblock = pl->pl_stage;
			free(bblock->buf);
			free(bblock);
		}
	}

	/* umount the stage fs. */
	if (pl->pl_device->stage.mntpnt != NULL) {
		if (umount(pl->pl_device->stage.mntpnt) == 0)
			(void) rmdir(pl->pl_device->stage.mntpnt);
		free(pl->pl_device->stage.mntpnt);
	}
	device = pl->pl_device;
	free(device->target.path);
	free(pl->pl_device);

	free(pl->pl_src_data);
	free(pl->pl_devname);
	free(pl);
}

static bool
probe_fstyp(ib_data_t *data)
{
	fstyp_handle_t fhdl;
	const char *fident;
	char *ptr;
	int fd;
	bool rv = false;

	/* Record partition id */
	ptr = strrchr(data->target.path, 'p');
	if (ptr == NULL)
		ptr = strrchr(data->target.path, 's');
	data->target.id = atoi(++ptr);
	if ((fd = open_device(data->target.path)) == -1)
		return (rv);

	if (fstyp_init(fd, 0, NULL, &fhdl) != 0) {
		(void) close(fd);
		return (rv);
	}

	if (fstyp_ident(fhdl, NULL, &fident) != 0) {
		fstyp_fini(fhdl);
		(void) fprintf(stderr, gettext("Failed to detect file "
		    "system type\n"));
		(void) close(fd);
		return (rv);
	}

	rv = true;
	if (strcmp(fident, MNTTYPE_ZFS) == 0)
		data->target.fstype = IB_FS_ZFS;
	else if (strcmp(fident, MNTTYPE_UFS) == 0) {
		data->target.fstype = IB_FS_UFS;
	} else if (strcmp(fident, MNTTYPE_PCFS) == 0) {
		data->target.fstype = IB_FS_PCFS;
		/* with pcfs we always write MBR */
		force_mbr = true;
		write_mbr = true;
	} else {
		(void) fprintf(stderr, gettext("File system %s is not "
		    "supported by loader\n"), fident);
		rv = false;
	}
	fstyp_fini(fhdl);
	(void) close(fd);
	return (rv);
}

static bool
get_slice(ib_data_t *data, struct partlist *pl, struct dk_gpt *vtoc,
    uint16_t tag)
{
	uint_t i;
	ib_device_t *device = pl->pl_device;
	char *path, *ptr;

	if (tag != V_BOOT && tag != V_SYSTEM)
		return (false);

	for (i = 0; i < vtoc->efi_nparts; i++) {
		if (vtoc->efi_parts[i].p_tag == tag) {
			if ((path = strdup(data->target.path)) == NULL) {
				perror(gettext("Memory allocation failure"));
				return (false);
			}
			ptr = strrchr(path, 's');
			ptr++;
			*ptr = '\0';
			(void) asprintf(&ptr, "%s%d", path, i);
			free(path);
			if (ptr == NULL) {
				perror(gettext("Memory allocation failure"));
				return (false);
			}
			pl->pl_devname = ptr;
			device->stage.id = i;
			device->stage.devtype = IB_DEV_EFI;
			switch (vtoc->efi_parts[i].p_tag) {
			case V_BOOT:
				device->stage.fstype = IB_FS_NONE;
				/* leave sector 0 for VBR */
				device->stage.offset = 1;
				break;
			case V_SYSTEM:
				device->stage.fstype = IB_FS_PCFS;
				break;
			}
			device->stage.tag = vtoc->efi_parts[i].p_tag;
			device->stage.start = vtoc->efi_parts[i].p_start;
			device->stage.size = vtoc->efi_parts[i].p_size;
			break;
		}
	}
	return (true);
}

static bool
allocate_slice(ib_data_t *data, struct dk_gpt *vtoc, uint16_t tag,
    struct partlist **plp)
{
	struct partlist *pl;

	*plp = NULL;
	if ((pl = partlist_alloc()) == NULL)
		return (false);

	pl->pl_device = calloc(1, sizeof (*pl->pl_device));
	if (pl->pl_device == NULL) {
		perror("calloc");
		partlist_free(pl);
		return (false);
	}
	if (!get_slice(data, pl, vtoc, tag)) {
		partlist_free(pl);
		return (false);
	}

	/* tag was not found */
	if (pl->pl_devname == NULL)
		partlist_free(pl);
	else
		*plp = pl;

	return (true);
}

static bool
probe_gpt(ib_data_t *data)
{
	struct partlist *pl;
	struct dk_gpt *vtoc;
	ib_device_t *device;
	int slice, fd;
	bool rv = false;

	if ((fd = open_device(data->target.path)) < 0)
		return (rv);

	slice = efi_alloc_and_read(fd, &vtoc);
	(void) close(fd);
	if (slice < 0)
		return (rv);

	data->device.devtype = IB_DEV_EFI;
	data->target.start = vtoc->efi_parts[slice].p_start;
	data->target.size = vtoc->efi_parts[slice].p_size;

	/* Always update PMBR. */
	force_mbr = true;
	write_mbr = true;

	/*
	 * With GPT we can have boot partition and ESP.
	 * Boot partition can have both stage 1 and stage 2.
	 */
	if (!allocate_slice(data, vtoc, V_BOOT, &pl))
		goto done;
	if (pl != NULL) {
		pl->pl_src_name = stage1;
		pl->pl_type = IB_BBLK_STAGE1;
		pl->pl_cb.compare = compare_stage1_cb;
		pl->pl_cb.install = install_stage1_cb;
		pl->pl_cb.read = read_stage1_cb;
		pl->pl_cb.read_bbl = read_stage1_bbl_cb;
		pl->pl_cb.print = print_stage1_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
	} else if (data->target.fstype != IB_FS_ZFS) {
		(void) fprintf(stderr, gettext("Booting %s from EFI "
		    "labeled disks requires the boot partition.\n"),
		    data->target.fstype == IB_FS_UFS?
		    MNTTYPE_UFS : MNTTYPE_PCFS);
		goto done;
	}
	/* Add stage 2 */
	if (!allocate_slice(data, vtoc, V_BOOT, &pl))
		goto done;
	if (pl != NULL) {
		pl->pl_src_name = stage2;
		pl->pl_type = IB_BBLK_STAGE2;
		pl->pl_cb.compare = compare_einfo_cb;
		pl->pl_cb.install = install_stage2_cb;
		pl->pl_cb.read = read_stage2_cb;
		pl->pl_cb.read_bbl = read_stage2_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
	}

	/* ESP can have 32- and 64-bit boot code. */
	if (!allocate_slice(data, vtoc, V_SYSTEM, &pl))
		goto done;
	if (pl != NULL) {
		pl->pl_device->stage.path = "/EFI/Boot/" BOOTIA32;
		pl->pl_src_name = efi32;
		pl->pl_type = IB_BBLK_EFI;
		pl->pl_cb.compare = compare_einfo_cb;
		pl->pl_cb.install = install_esp_cb;
		pl->pl_cb.read = read_einfo_esp_cb;
		pl->pl_cb.read_bbl = read_stage2_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
	}
	if (!allocate_slice(data, vtoc, V_SYSTEM, &pl))
		goto done;
	if (pl != NULL) {
		pl->pl_device->stage.path = "/EFI/Boot/" BOOTX64;
		pl->pl_src_name = efi64;
		pl->pl_type = IB_BBLK_EFI;
		pl->pl_cb.compare = compare_einfo_cb;
		pl->pl_cb.install = install_esp_cb;
		pl->pl_cb.read = read_einfo_esp_cb;
		pl->pl_cb.read_bbl = read_stage2_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
	}

	/* add stage for our target file system slice */
	pl = partlist_alloc();
	if (pl == NULL)
		goto done;

	device = pl->pl_device;
	device->stage.devtype = data->device.devtype;
	if ((pl->pl_devname = strdup(data->target.path)) == NULL) {
		perror(gettext("Memory allocation failure"));
		partlist_free(pl);
		goto done;
	}

	device->stage.id = slice;
	device->stage.start = vtoc->efi_parts[slice].p_start;
	device->stage.size = vtoc->efi_parts[slice].p_size;

	/* ZFS and UFS can have stage1 in boot area. */
	if (data->target.fstype == IB_FS_ZFS ||
	    data->target.fstype == IB_FS_UFS) {
		pl->pl_src_name = stage1;
		pl->pl_type = IB_BBLK_STAGE1;
		pl->pl_cb.compare = compare_stage1_cb;
		pl->pl_cb.install = install_stage1_cb;
		pl->pl_cb.read = read_stage1_cb;
		pl->pl_cb.read_bbl = read_stage1_bbl_cb;
		pl->pl_cb.print = print_stage1_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
	}

	if (data->target.fstype == IB_FS_ZFS) {
		pl = partlist_alloc();
		if (pl == NULL)
			goto done;

		device = pl->pl_device;
		device->stage.devtype = data->device.devtype;

		if ((pl->pl_devname = strdup(data->target.path)) == NULL) {
			perror(gettext("Memory allocation failure"));
			goto done;
		}

		device->stage.id = slice;
		device->stage.start = vtoc->efi_parts[slice].p_start;
		device->stage.size = vtoc->efi_parts[slice].p_size;

		device->stage.offset = BBLK_ZFS_BLK_OFF;
		pl->pl_src_name = stage2;
		pl->pl_type = IB_BBLK_STAGE2;
		pl->pl_cb.compare = compare_einfo_cb;
		pl->pl_cb.install = install_stage2_cb;
		pl->pl_cb.read = read_stage2_cb;
		pl->pl_cb.read_bbl = read_stage2_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
	}
	rv = true;
done:
	efi_free(vtoc);
	return (rv);
}

static bool
get_start_sector(ib_data_t *data, struct extpartition *v_part,
    diskaddr_t *start)
{
	struct partlist *pl;
	struct mboot *mbr;
	struct ipart *part;
	struct part_info dkpi;
	struct extpart_info edkpi;
	uint32_t secnum, numsec;
	ext_part_t *epp;
	ushort_t i;
	int fd, rval, pno;

	if ((fd = open_device(data->target.path)) < 0)
		return (false);

	if (ioctl(fd, DKIOCEXTPARTINFO, &edkpi) < 0) {
		if (ioctl(fd, DKIOCPARTINFO, &dkpi) < 0) {
			(void) fprintf(stderr, gettext("cannot get the "
			    "slice information of the disk\n"));
			(void) close(fd);
			return (false);
		} else {
			edkpi.p_start = dkpi.p_start;
			edkpi.p_length = dkpi.p_length;
		}
	}
	(void) close(fd);

	/* Set target file system start and size */
	data->target.start = edkpi.p_start;
	data->target.size = edkpi.p_length;

	/* This is our MBR partition start. */
	edkpi.p_start -= v_part->p_start;

	/* Head is always MBR */
	pl = STAILQ_FIRST(data->plist);
	if (!read_stage1_cb(pl))
		return (false);

	mbr = (struct mboot *)pl->pl_stage;
	part = (struct ipart *)mbr->parts;

	for (i = 0; i < FD_NUMPART; i++) {
		if (part[i].relsect == edkpi.p_start) {
			*start = part[i].relsect;
			return (true);
		}
	}

	rval = libfdisk_init(&epp, pl->pl_devname, part, FDISK_READ_DISK);
	if (rval != FDISK_SUCCESS) {
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
				    "Aborting operation. %d\n"), rval);
				return (false);
			case FDISK_ENOVGEOM:
				(void) fprintf(stderr, gettext("Could not get "
				    "virtual geometry\n"));
				return (false);
			case FDISK_ENOPGEOM:
				(void) fprintf(stderr, gettext("Could not get "
				    "physical geometry\n"));
				return (false);
			case FDISK_ENOLGEOM:
				(void) fprintf(stderr, gettext("Could not get "
				    "label geometry\n"));
				return (false);
			default:
				(void) fprintf(stderr, gettext("Failed to "
				    "initialize libfdisk.\n"));
				return (false);
		}
	}
	rval = fdisk_get_solaris_part(epp, &pno, &secnum, &numsec);
	libfdisk_fini(&epp);
	if (rval != FDISK_SUCCESS) {
		/* No solaris logical partition */
		(void) fprintf(stderr, gettext("Solaris partition not found. "
		    "Aborting operation.\n"));
		return (false);
	}
	*start = secnum;
	return (true);
}

/*
 * On x86 the VTOC table is inside MBR partition and to get
 * absolute sectors, we need to add MBR partition start to VTOC slice start.
 */
static bool
probe_vtoc(ib_data_t *data)
{
	struct partlist *pl;
	struct extvtoc exvtoc;
	ib_device_t *device;
	char *path, *ptr;
	ushort_t i;
	int slice, fd;
	diskaddr_t start;
	bool rv;

	rv = false;

	if ((fd = open_device(data->target.path)) < 0)
		return (rv);

	slice = read_extvtoc(fd, &exvtoc);
	(void) close(fd);
	if (slice < 0)
		return (rv);
	data->device.devtype = IB_DEV_VTOC;

	if (!get_start_sector(data, exvtoc.v_part + slice, &start))
		return (rv);

	if (exvtoc.v_part[slice].p_tag == V_BACKUP) {
		/*
		 * NOTE: we could relax there and allow zfs boot on
		 * slice 2, but lets keep traditional limits.
		 */
		(void) fprintf(stderr, gettext(
		    "raw device must be a root slice (not backup)\n"));
		return (rv);
	}

	if ((path = strdup(data->target.path)) == NULL) {
		perror(gettext("Memory allocation failure"));
		return (false);
	}

	data->target.start = start + exvtoc.v_part[slice].p_start;
	data->target.size = exvtoc.v_part[slice].p_size;

	/* Search for boot slice. */
	for (i = 0; i < exvtoc.v_nparts; i++) {
		if (exvtoc.v_part[i].p_tag == V_BOOT)
			break;
	}

	if (i == exvtoc.v_nparts ||
	    exvtoc.v_part[i].p_size == 0) {
		/* fall back to slice V_BACKUP */
		for (i = 0; i < exvtoc.v_nparts; i++) {
			if (exvtoc.v_part[i].p_tag == V_BACKUP)
				break;
		}
		/* Still nothing? Error out. */
		if (i == exvtoc.v_nparts ||
		    exvtoc.v_part[i].p_size == 0) {
			free(path);
			return (false);
		}
	}

	/* Create path. */
	ptr = strrchr(path, 's');
	ptr++;
	*ptr = '\0';
	(void) asprintf(&ptr, "%s%d", path, i);
	free(path);
	if (ptr == NULL) {
		perror(gettext("Memory allocation failure"));
		return (false);
	}

	pl = partlist_alloc();
	if (pl == NULL) {
		free(ptr);
		return (false);
	}
	pl->pl_devname = ptr;
	device = pl->pl_device;
	device->stage.devtype = data->device.devtype;
	device->stage.id = i;
	device->stage.tag = exvtoc.v_part[i].p_tag;
	device->stage.start = start + exvtoc.v_part[i].p_start;
	device->stage.size = exvtoc.v_part[i].p_size;

	/* Fix size if this slice is in fact V_BACKUP */
	if (exvtoc.v_part[i].p_tag == V_BACKUP) {
		for (i = 0; i < exvtoc.v_nparts; i++) {
			if (exvtoc.v_part[i].p_start == 0)
				continue;
			if (exvtoc.v_part[i].p_size == 0)
				continue;
			if (exvtoc.v_part[i].p_start <
			    device->stage.size)
				device->stage.size =
				    exvtoc.v_part[i].p_start;
		}
	}

	pl->pl_src_name = stage1;
	pl->pl_type = IB_BBLK_STAGE1;
	pl->pl_cb.compare = compare_stage1_cb;
	pl->pl_cb.install = install_stage1_cb;
	pl->pl_cb.read = read_stage1_cb;
	pl->pl_cb.read_bbl = read_stage1_bbl_cb;
	pl->pl_cb.print = print_stage1_cb;
	STAILQ_INSERT_TAIL(data->plist, pl, pl_next);

	/* Create instance for stage 2 */
	pl = partlist_alloc();
	if (pl == NULL) {
		free(ptr);
		return (false);
	}
	pl->pl_devname = strdup(ptr);
	if (pl->pl_devname == NULL) {
		partlist_free(pl);
		return (false);
	}
	pl->pl_device->stage.devtype = data->device.devtype;
	pl->pl_device->stage.id = device->stage.id;
	pl->pl_device->stage.offset = BBLK_BLKLIST_OFF;
	pl->pl_device->stage.tag = device->stage.tag;
	pl->pl_device->stage.start = device->stage.start;
	pl->pl_device->stage.size = device->stage.size;
	pl->pl_src_name = stage2;
	pl->pl_type = IB_BBLK_STAGE2;
	pl->pl_cb.compare = compare_einfo_cb;
	pl->pl_cb.install = install_stage2_cb;
	pl->pl_cb.read = read_stage2_cb;
	pl->pl_cb.read_bbl = read_stage2_file_cb;
	pl->pl_cb.print = print_einfo_cb;
	STAILQ_INSERT_TAIL(data->plist, pl, pl_next);

	/* And we are done. */
	rv = true;
	return (rv);
}

static bool
probe_mbr(ib_data_t *data)
{
	struct partlist *pl;
	struct ipart *part;
	struct mboot *mbr;
	ib_device_t *device;
	char *path, *ptr;
	int i, rv;

	data->device.devtype = IB_DEV_MBR;

	/* Head is always MBR */
	pl = STAILQ_FIRST(data->plist);
	if (!read_stage1_cb(pl))
		return (false);

	mbr = (struct mboot *)pl->pl_stage;
	part = (struct ipart *)mbr->parts;

	/* Set target file system start and size */
	data->target.start = part[data->target.id - 1].relsect;
	data->target.size = part[data->target.id - 1].numsect;

	/* Use X86BOOT partition if we have one. */
	for (i = 0; i < FD_NUMPART; i++) {
		if (part[i].systid == X86BOOT)
			break;
	}

	/* Keep device name of whole disk device. */
	path = (char *)pl->pl_devname;
	if ((pl = partlist_alloc()) == NULL)
		return (false);
	device = pl->pl_device;

	/*
	 * No X86BOOT, try to use space between MBR and first
	 * partition.
	 */
	if (i == FD_NUMPART) {
		pl->pl_devname = strdup(path);
		if (pl->pl_devname == NULL) {
			perror(gettext("Memory allocation failure"));
			partlist_free(pl);
			return (false);
		}
		device->stage.id = 0;
		device->stage.devtype = IB_DEV_MBR;
		device->stage.fstype = IB_FS_NONE;
		device->stage.start = 0;
		device->stage.size = part[0].relsect;
		device->stage.offset = BBLK_BLKLIST_OFF;
		pl->pl_src_name = stage2;
		pl->pl_type = IB_BBLK_STAGE2;
		pl->pl_cb.compare = compare_einfo_cb;
		pl->pl_cb.install = install_stage2_cb;
		pl->pl_cb.read = read_stage2_cb;
		pl->pl_cb.read_bbl = read_stage2_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);

		/* We have MBR for stage1 and gap for stage2, we are done. */
		return (true);
	}

	if ((path = strdup(path)) == NULL) {
		perror(gettext("Memory allocation failure"));
		partlist_free(pl);
		return (false);
	}
	ptr = strrchr(path, 'p');
	ptr++;
	*ptr = '\0';
	/* partitions are p1..p4 */
	rv = asprintf(&ptr, "%s%d", path, i + 1);
	free(path);
	if (rv < 0) {
		perror(gettext("Memory allocation failure"));
		partlist_free(pl);
		return (false);
	}
	pl->pl_devname = ptr;
	device->stage.id = i + 1;
	device->stage.devtype = IB_DEV_MBR;
	device->stage.fstype = IB_FS_NONE;
	device->stage.start = part[i].relsect;
	device->stage.size = part[i].numsect;
	pl->pl_src_name = stage1;
	pl->pl_type = IB_BBLK_STAGE1;
	pl->pl_cb.compare = compare_stage1_cb;
	pl->pl_cb.install = install_stage1_cb;
	pl->pl_cb.read = read_stage1_cb;
	pl->pl_cb.read_bbl = read_stage1_bbl_cb;
	pl->pl_cb.print = print_stage1_cb;
	STAILQ_INSERT_TAIL(data->plist, pl, pl_next);

	pl = partlist_alloc();
	if (pl == NULL)
		return (false);
	device = pl->pl_device;
	pl->pl_devname = strdup(ptr);
	if (pl->pl_devname == NULL) {
		perror(gettext("Memory allocation failure"));
		partlist_free(pl);
		return (false);
	}
	device->stage.id = i + 1;
	device->stage.devtype = IB_DEV_MBR;
	device->stage.fstype = IB_FS_NONE;
	device->stage.start = part[i].relsect;
	device->stage.size = part[i].numsect;
	device->stage.offset = 1;
	/* This is boot partition */
	device->stage.tag = V_BOOT;
	pl->pl_src_name = stage2;
	pl->pl_type = IB_BBLK_STAGE2;
	pl->pl_cb.compare = compare_einfo_cb;
	pl->pl_cb.install = install_stage2_cb;
	pl->pl_cb.read = read_stage2_cb;
	pl->pl_cb.read_bbl = read_stage2_file_cb;
	pl->pl_cb.print = print_einfo_cb;
	STAILQ_INSERT_TAIL(data->plist, pl, pl_next);

	return (true);
}

static bool
probe_device(ib_data_t *data, const char *dev)
{
	struct partlist *pl;
	struct stat sb;
	const char *ptr;
	char *p0;
	int fd, len;

	if (dev == NULL)
		return (NULL);

	len = strlen(dev);

	if ((pl = partlist_alloc()) == NULL)
		return (false);

	if (stat(dev, &sb) == -1) {
		perror("stat");
		partlist_free(pl);
		return (false);
	}

	/* We have regular file, register it and we are done. */
	if (S_ISREG(sb.st_mode) != 0) {
		pl->pl_devname = (char *)dev;

		pl->pl_type = IB_BBLK_FILE;
		pl->pl_cb.read = read_einfo_file_cb;
		pl->pl_cb.print = print_einfo_cb;
		STAILQ_INSERT_TAIL(data->plist, pl, pl_next);
		return (true);
	}

	/*
	 * This is block device.
	 * We do not allow to specify whole disk device (cXtYdZp0 or cXtYdZ).
	 */
	if ((ptr = strrchr(dev, '/')) == NULL)
		ptr = dev;
	if ((strrchr(ptr, 'p') == NULL && strrchr(ptr, 's') == NULL) ||
	    (dev[len - 2] == 'p' && dev[len - 1] == '0')) {
		(void) fprintf(stderr,
		    gettext("whole disk device is not supported\n"));
		partlist_free(pl);
		return (false);
	}

	data->target.path = (char *)dev;
	if (!probe_fstyp(data)) {
		partlist_free(pl);
		return (false);
	}

	/* We start from identifying the whole disk. */
	if ((p0 = strdup(dev)) == NULL) {
		perror("calloc");
		partlist_free(pl);
		return (false);
	}

	pl->pl_devname = p0;
	/* Change device name to p0 */
	if ((ptr = strrchr(p0, 'p')) == NULL)
		ptr = strrchr(p0, 's');
	p0 = (char *)ptr;
	p0[0] = 'p';
	p0[1] = '0';
	p0[2] = '\0';

	if ((fd = open_device(pl->pl_devname)) == -1) {
		partlist_free(pl);
		return (false);
	}

	sector_size = get_media_info(fd);
	(void) close(fd);

	pl->pl_src_name = stage1;
	pl->pl_type = IB_BBLK_MBR;
	pl->pl_cb.compare = compare_mbr_cb;
	pl->pl_cb.install = install_stage1_cb;
	pl->pl_cb.read = read_stage1_cb;
	pl->pl_cb.read_bbl = read_stage1_bbl_cb;
	pl->pl_cb.print = print_stage1_cb;
	STAILQ_INSERT_TAIL(data->plist, pl, pl_next);

	if (probe_gpt(data))
		return (true);

	if (data->device.devtype == IB_DEV_UNKNOWN)
		if (probe_vtoc(data))
			return (true);

	if (data->device.devtype == IB_DEV_UNKNOWN)
		return (probe_mbr(data));

	return (false);
}

static int
read_bootblock_from_file(const char *file, ib_bootblock_t *bblock)
{
	struct stat	sb;
	uint32_t	buf_size;
	uint32_t	mboot_off;
	int		fd = -1;
	int		retval = BC_ERROR;

	assert(bblock != NULL);
	assert(file != NULL);

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		BOOT_DEBUG("Error opening %s\n", file);
		goto out;
	}

	if (fstat(fd, &sb) == -1) {
		BOOT_DEBUG("Error getting information (stat) about %s", file);
		perror("stat");
		goto outfd;
	}

	/* loader bootblock has version built in */
	buf_size = sb.st_size;
	if (buf_size == 0)
		goto outfd;

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

	buf_size = MIN(buf_size, MBOOT_SCAN_SIZE);
	if (find_multiboot(bblock->file, buf_size, &mboot_off)
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
	if (retval == BC_ERROR) {
		(void) fprintf(stderr,
		    gettext("Error reading bootblock from %s\n"),
		    file);
	}

	if (retval == BC_NOEXTRA) {
		BOOT_DEBUG("No multiboot header found on %s, unable to "
		    "locate extra information area (old/non versioned "
		    "bootblock?) \n", file);
		(void) fprintf(stderr, gettext("No extended information"
		    " found\n"));
	}
	return (retval);
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
static void
prepare_stage1(struct partlist *stage1, struct partlist *stage2, uuid_t uuid)
{
	char *src, *dest;
	ib_bootblock_t *bblk;
	ib_device_t *device;
	uint16_t size;
	struct mboot *mbr;

	src = stage1->pl_stage;
	dest = stage1->pl_src_data;
	device = stage2->pl_device;

	/* Only copy from valid source. */
	mbr = stage1->pl_stage;
	if (mbr->signature == MBB_MAGIC) {
		/* copy BPB */
		bcopy(src + STAGE1_BPB_OFFSET, dest + STAGE1_BPB_OFFSET,
		    STAGE1_BPB_SIZE);

		/* copy MBR, note STAGE1_SIG == BOOTSZ */
		bcopy(src + STAGE1_SIG, dest + STAGE1_SIG,
		    SECTOR_SIZE - STAGE1_SIG);
	}

	bcopy(uuid, dest + STAGE1_STAGE2_UUID, UUID_LEN);

	/* set stage2 size */
	bblk = stage2->pl_src_data;
	size = bblk->buf_size / SECTOR_SIZE;
	*((uint16_t *)(dest + STAGE1_STAGE2_SIZE)) = size;

	/* set stage2 LBA */
	*((uint64_t *)(dest + STAGE1_STAGE2_LBA)) =
	    device->stage.start + device->stage.offset;

	/* Copy prepared data to stage1 block read from the disk. */
	bcopy(dest, src, SECTOR_SIZE);
}

static void
prepare_bootblock(ib_data_t *data, struct partlist *pl, char *updt_str)
{
	ib_bootblock_t		*bblock;
	uint64_t		*ptr;

	assert(pl != NULL);

	bblock = pl->pl_src_data;
	if (bblock == NULL)
		return;

	ptr = (uint64_t *)(&bblock->mboot->bss_end_addr);
	*ptr = data->target.start;

	/*
	 * the loader bootblock has built in version, if custom
	 * version was provided, update it.
	 */
	if (do_version)
		add_bootblock_einfo(bblock, updt_str);
}

static int
open_device(const char *path)
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

/*
 * We need to record stage2 location and size into pmbr/vbr.
 * We need to record target partiton LBA to stage2.
 */
static void
prepare_bblocks(ib_data_t *data)
{
	struct partlist *pl;
	struct partlist *mbr, *stage1, *stage2;
	uuid_t uuid;

	mbr = stage1 = stage2 = NULL;
	/*
	 * Walk list and pick up BIOS boot blocks. EFI boot programs
	 * can be set in place.
	 */
	STAILQ_FOREACH(pl, data->plist, pl_next) {
		switch (pl->pl_type) {
		case IB_BBLK_MBR:
			mbr = pl;
			break;
		case IB_BBLK_STAGE1:
			stage1 = pl;
			break;
		case IB_BBLK_STAGE2:
			stage2 = pl;
			/* FALLTHROUGH */
		case IB_BBLK_EFI:
			prepare_bootblock(data, pl, update_str);
			break;
		default:
			break;
		}
	}

	/* If stage2 is missing, we are done. */
	if (stage2 == NULL)
		return;

	/*
	 * Create disk uuid. We only need reasonable amount of uniqueness
	 * to allow biosdev to identify disk based on mbr differences.
	 */
	uuid_generate(uuid);

	if (mbr != NULL) {
		prepare_stage1(mbr, stage2, uuid);

		/*
		 * If we have stage1, we point MBR to read stage 1.
		 */
		if (stage1 != NULL) {
			char *dest = mbr->pl_stage;

			*((uint16_t *)(dest + STAGE1_STAGE2_SIZE)) = 1;
			*((uint64_t *)(dest + STAGE1_STAGE2_LBA)) =
			    stage1->pl_device->stage.start;
		}
	}

	if (stage1 != NULL) {
		prepare_stage1(stage1, stage2, uuid);
	}
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
handle_install(char *progname, int argc, char **argv)
{
	struct partlist	*pl;
	ib_data_t	data = { 0 };
	char		*device_path = NULL;
	int		ret = BC_ERROR;

	switch (argc) {
	case 1:
		if ((device_path = strdup(argv[0])) == NULL) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if (asprintf(&stage1, "%s/%s", boot_dir, STAGE1) < 0) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if (asprintf(&stage2, "%s/%s", boot_dir, STAGE2) < 0) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if (asprintf(&efi32, "%s/%s", boot_dir, LOADER32) < 0) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if (asprintf(&efi64, "%s/%s", boot_dir, LOADER64) < 0) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		break;
	case 3:
		if ((stage1 = strdup(argv[0])) == NULL) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if ((stage2 = strdup(argv[1])) == NULL) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if ((device_path = strdup(argv[2])) == NULL) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if (asprintf(&efi32, "%s/%s", boot_dir, LOADER32) < 0) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		if (asprintf(&efi64, "%s/%s", boot_dir, LOADER64) < 0) {
			perror(gettext("Memory Allocation Failure"));
			goto done;
		}
		break;
	default:
		usage(progname, ret);
	}

	data.plist = malloc(sizeof (*data.plist));
	if (data.plist == NULL) {
		perror(gettext("Memory Allocation Failure"));
		goto done;
	}
	STAILQ_INIT(data.plist);

	BOOT_DEBUG("device path: %s, stage1 path: %s bootblock path: %s\n",
	    device_path, stage1, stage2);

	if (probe_device(&data, device_path)) {
		/* Read all data. */
		STAILQ_FOREACH(pl, data.plist, pl_next) {
			if (!pl->pl_cb.read(pl)) {
				printf("\n");
			}
			if (!pl->pl_cb.read_bbl(pl)) {
				/*
				 * We will ignore ESP updates in case of
				 * older system where we are missing
				 * loader64.efi and loader32.efi.
				 */
				if (pl->pl_type != IB_BBLK_EFI)
					goto cleanup;
			}
		}

		/* Prepare data. */
		prepare_bblocks(&data);

		/* Commit data to disk. */
		while ((pl = STAILQ_LAST(data.plist, partlist, pl_next)) !=
		    NULL) {
			if (pl->pl_cb.compare != NULL &&
			    pl->pl_cb.compare(pl)) {
				if (pl->pl_cb.install != NULL)
					pl->pl_cb.install(&data, pl);
			}
			STAILQ_REMOVE(data.plist, pl, partlist, pl_next);
			partlist_free(pl);
		}
	}
	ret = BC_SUCCESS;

cleanup:
	while ((pl = STAILQ_LAST(data.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(data.plist, pl, partlist, pl_next);
		partlist_free(pl);
	}
	free(data.plist);
done:
	free(stage1);
	free(stage2);
	free(efi32);
	free(efi64);
	free(device_path);
	return (ret);
}

/*
 * Retrieves from a device the extended information (einfo) associated to the
 * file or installed stage2.
 * Expects one parameter, the device path, in the form: /dev/rdsk/c?[t?]d?s0
 * or file name.
 * Returns:
 *        - BC_SUCCESS (and prints out einfo contents depending on 'flags')
 *	  - BC_ERROR (on error)
 *        - BC_NOEINFO (no extended information available)
 */
static int
handle_getinfo(char *progname, int argc, char **argv)
{
	struct partlist	*pl;
	ib_data_t	data = { 0 };
	char		*device_path;

	if (argc != 1) {
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname, BC_ERROR);
	}

	if ((device_path = strdup(argv[0])) == NULL) {
		perror(gettext("Memory Allocation Failure"));
		return (BC_ERROR);
	}

	data.plist = malloc(sizeof (*data.plist));
	if (data.plist == NULL) {
		perror("malloc");
		free(device_path);
		return (BC_ERROR);
	}
	STAILQ_INIT(data.plist);

	if (probe_device(&data, device_path)) {
		STAILQ_FOREACH(pl, data.plist, pl_next) {
			if (pl->pl_cb.read(pl))
				pl->pl_cb.print(pl);
			else
				printf("\n");
		}
	}

	while ((pl = STAILQ_LAST(data.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(data.plist, pl, partlist, pl_next);
		partlist_free(pl);
	}
	free(data.plist);

	return (BC_SUCCESS);
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
handle_mirror(char *progname, int argc, char **argv)
{
	ib_data_t src = { 0 };
	ib_data_t dest = { 0 };
	struct partlist *pl_src, *pl_dest;
	char		*curr_device_path = NULL;
	char		*attach_device_path = NULL;
	int		retval = BC_ERROR;

	if (argc == 2) {
		curr_device_path = strdup(argv[0]);
		attach_device_path = strdup(argv[1]);
	}

	if (!curr_device_path || !attach_device_path) {
		free(curr_device_path);
		free(attach_device_path);
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname, BC_ERROR);
	}
	BOOT_DEBUG("Current device path is: %s, attaching device path is: "
	    " %s\n", curr_device_path, attach_device_path);

	src.plist = malloc(sizeof (*src.plist));
	if (src.plist == NULL) {
		perror("malloc");
		return (BC_ERROR);
	}
	STAILQ_INIT(src.plist);

	dest.plist = malloc(sizeof (*dest.plist));
	if (dest.plist == NULL) {
		perror("malloc");
		goto out;
	}
	STAILQ_INIT(dest.plist);

	if (!probe_device(&src, curr_device_path)) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information from %s (current device)\n"),
		    curr_device_path);
		goto out;
	}

	if (!probe_device(&dest, attach_device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information from %s (attaching device)\n"),
		    attach_device_path);
		goto cleanup_src;
	}

	write_vbr = true;
	write_mbr = true;
	force_mbr = true;

	pl_dest = STAILQ_FIRST(dest.plist);
	STAILQ_FOREACH(pl_src, src.plist, pl_next) {
		if (pl_dest == NULL) {
			(void) fprintf(stderr,
			    gettext("Destination disk layout is different "
			    "from source, can not mirror.\n"));
			goto cleanup;
		}
		if (!pl_src->pl_cb.read(pl_src)) {
			(void) fprintf(stderr, gettext("Failed to read "
			    "boot block from %s\n"), pl_src->pl_devname);
			goto cleanup;
		}
		if (!pl_dest->pl_cb.read(pl_dest)) {
			(void) fprintf(stderr, gettext("Failed to read "
			    "boot block from %s\n"), pl_dest->pl_devname);
		}

		/* Set source pl_stage to destination source data */
		pl_dest->pl_src_data = pl_src->pl_stage;
		pl_src->pl_stage = NULL;

		pl_dest = STAILQ_NEXT(pl_dest, pl_next);
	}

	/* Prepare data. */
	prepare_bblocks(&dest);

	/* Commit data to disk. */
	while ((pl_dest = STAILQ_LAST(dest.plist, partlist, pl_next)) != NULL) {
		pl_dest->pl_cb.install(&dest, pl_dest);
		STAILQ_REMOVE(dest.plist, pl_dest, partlist, pl_next);
		partlist_free(pl_dest);

		/* Free source list */
		pl_src = STAILQ_LAST(src.plist, partlist, pl_next);
		STAILQ_REMOVE(src.plist, pl_src, partlist, pl_next);
		partlist_free(pl_src);
	}
	retval = BC_SUCCESS;

cleanup:
	while ((pl_dest = STAILQ_LAST(dest.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(dest.plist, pl_dest, partlist, pl_next);
		partlist_free(pl_dest);
	}
	free(dest.plist);
cleanup_src:
	while ((pl_src = STAILQ_LAST(src.plist, partlist, pl_next)) != NULL) {
		STAILQ_REMOVE(src.plist, pl_src, partlist, pl_next);
		partlist_free(pl_src);
	}
	free(src.plist);
out:
	free(curr_device_path);
	free(attach_device_path);
	return (retval);
}

#define	USAGE_STRING	\
"Usage:\t%s [-fFmn] [-b boot_dir] [-u verstr]\n"	\
"\t\t[stage1 stage2] raw-device\n"			\
"\t%s -M [-n] raw-device attach-raw-device\n"		\
"\t%s [-e|-V] -i raw-device | file\n"

#define	CANON_USAGE_STR	gettext(USAGE_STRING)

static void
usage(char *progname, int rc)
{
	(void) fprintf(stdout, CANON_USAGE_STR, progname, progname, progname);
	fini_yes();
	exit(rc);
}

int
main(int argc, char **argv)
{
	int	opt;
	int	ret;
	char	*progname;
	struct stat sb;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	if (init_yes() < 0)
		errx(BC_ERROR, gettext(ERR_MSG_INIT_YES), strerror(errno));

	/* Needed for mount pcfs. */
	tzset();

	/* Determine our name */
	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv, "b:deFfhiMmnu:V")) != EOF) {
		switch (opt) {
		case 'b':
			boot_dir = strdup(optarg);
			if (boot_dir == NULL) {
				err(BC_ERROR,
				    gettext("Memory allocation failure"));
			}
			if (lstat(boot_dir, &sb) != 0) {
				err(BC_ERROR, boot_dir);
			}
			if (!S_ISDIR(sb.st_mode)) {
				errx(BC_ERROR, gettext("%s: not a directory"),
				    boot_dir);
			}
			break;
		case 'd':
			boot_debug = true;
			break;
		case 'e':
			strip = true;
			break;
		case 'F':
			force_update = true;
			break;
		case 'f':
			force_mbr = true;
			break;
		case 'h':
			usage(progname, BC_SUCCESS);
			break;
		case 'i':
			do_getinfo = true;
			break;
		case 'M':
			do_mirror_bblk = true;
			break;
		case 'm':
			write_mbr = true;
			break;
		case 'n':
			nowrite = true;
			break;
		case 'u':
			do_version = true;

			update_str = strdup(optarg);
			if (update_str == NULL) {
				perror(gettext("Memory allocation failure"));
				exit(BC_ERROR);
			}
			break;
		case 'V':
			verbose_dump = true;
			break;
		default:
			/* fall through to process non-optional args */
			break;
		}
	}

	/* check arguments */
	check_options(progname);

	if (nowrite)
		(void) fprintf(stdout, gettext("Dry run requested. Nothing will"
		    " be written to disk.\n"));

	if (do_getinfo) {
		ret = handle_getinfo(progname, argc - optind, argv + optind);
	} else if (do_mirror_bblk) {
		ret = handle_mirror(progname, argc - optind, argv + optind);
	} else {
		ret = handle_install(progname, argc - optind, argv + optind);
	}
	fini_yes();
	return (ret);
}

#define	MEANINGLESS_OPT gettext("%s specified but meaningless, ignoring\n")
static void
check_options(char *progname)
{
	if (do_getinfo && do_mirror_bblk) {
		(void) fprintf(stderr, gettext("Only one of -M and -i can be "
		    "specified at the same time\n"));
		usage(progname, BC_ERROR);
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
			do_version = false;
		}
		if (force_update) {
			(void) fprintf(stderr, MEANINGLESS_OPT, "-F");
			force_update = false;
		}
		if (strip || verbose_dump) {
			BOOT_DEBUG(MEANINGLESS_OPT, "-e|-V");
			strip = false;
			verbose_dump = false;
		}
	}

	if ((strip || verbose_dump) && !do_getinfo)
		usage(progname, BC_ERROR);

	if (do_getinfo) {
		if (write_mbr || force_mbr || do_version || force_update) {
			BOOT_DEBUG(MEANINGLESS_OPT, "-m|-f|-u|-F");
			write_mbr = force_mbr = do_version = false;
			force_update = false;
		}
	}
}
