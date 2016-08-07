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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <malloc.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>
#include <errno.h>
#include <libfdisk.h>
#include <stdarg.h>
#include <assert.h>

#include <sys/mount.h>
#include <sys/mnttab.h>
#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/multiboot.h>
#include <sys/sysmacros.h>
#include <sys/efi_partition.h>

#include <libnvpair.h>
#include <libfstyp.h>

#include "message.h"
#include "installgrub.h"
#include "./../common/bblk_einfo.h"
#include "./../common/boot_utils.h"
#include "./../common/mboot_extra.h"
#include "getresponse.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

/*
 * Variables to track installgrub desired mode of operation.
 * 'nowrite' and 'boot_debug' come from boot_common.h.
 */
static boolean_t write_mbr = B_FALSE;
static boolean_t force_mbr = B_FALSE;
static boolean_t force_update = B_FALSE;
static boolean_t do_getinfo = B_FALSE;
static boolean_t do_version = B_FALSE;
static boolean_t do_mirror_bblk = B_FALSE;
static boolean_t strip = B_FALSE;
static boolean_t verbose_dump = B_FALSE;

/* Installing the bootblock is the default operation. */
static boolean_t do_install = B_TRUE;

/* Versioning string, if present. */
static char *update_str;

/*
 * Temporary buffer to store the first 32K of data looking for a multiboot
 * signature.
 */
char	mboot_scan[MBOOT_SCAN_SIZE];

/* Function prototypes. */
static void check_options(char *);
static int handle_install(char *, char **);
static int handle_mirror(char *, char **);
static int handle_getinfo(char *, char **);
static int commit_to_disk(ig_data_t *, char *);
static int init_device(ig_device_t *, char *path);
static void cleanup_device(ig_device_t *);
static void cleanup_stage2(ig_stage2_t *);
static int get_start_sector(ig_device_t *);
static int get_disk_fd(ig_device_t *device);
static int get_raw_partition_fd(ig_device_t *);
static char *get_raw_partition_path(ig_device_t *);
static int propagate_bootblock(ig_data_t *, ig_data_t *, char *);
static int find_x86_bootpar(struct mboot *, int *, uint32_t *);
static int write_stage2(ig_data_t *);
static int write_stage1(ig_data_t *);
static void usage(char *);
static int read_stage1_from_file(char *, ig_data_t *);
static int read_stage2_from_file(char *, ig_data_t *);
static int read_stage1_from_disk(int, char *);
static int read_stage2_from_disk(int, ig_stage2_t *, int);
static int prepare_stage1(ig_data_t *);
static int prepare_stage2(ig_data_t *, char *);
static void prepare_fake_multiboot(ig_stage2_t *);
static void add_stage2_einfo(ig_stage2_t *, char *updt_str);
static boolean_t is_update_necessary(ig_data_t *, char *);

extern int read_stage2_blocklist(int, unsigned int *);

int
main(int argc, char *argv[])
{
	int	opt;
	int	params = 3;
	int	ret;
	char	**handle_args;
	char	*progname;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(BC_ERROR);
	}

	/*
	 * retro-compatibility: installing the bootblock is the default
	 * and there is no switch for it.
	 */
	do_install = B_TRUE;

	while ((opt = getopt(argc, argv, "dVMFfmneiu:")) != EOF) {
		switch (opt) {
		case 'm':
			write_mbr = B_TRUE;
			break;
		case 'n':
			nowrite = B_TRUE;
			break;
		case 'f':
			force_mbr = B_TRUE;
			break;
		case 'i':
			do_getinfo = B_TRUE;
			do_install = B_FALSE;
			params = 1;
			break;
		case 'V':
			verbose_dump = B_TRUE;
			break;
		case 'd':
			boot_debug = B_TRUE;
			break;
		case 'F':
			force_update = B_TRUE;
			break;
		case 'e':
			strip = B_TRUE;
			break;
		case 'M':
			do_mirror_bblk = B_TRUE;
			do_install = B_FALSE;
			params = 2;
			break;
		case 'u':
			do_version = B_TRUE;

			update_str = malloc(strlen(optarg) + 1);
			if (update_str == NULL) {
				(void) fprintf(stderr, gettext("Unable to "
				    "allocate memory\n"));
				exit(BC_ERROR);
			}
			(void) strlcpy(update_str, optarg, strlen(optarg) + 1);
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

	/*
	 * clean up options (and bail out if an unrecoverable combination is
	 * requested.
	 */
	progname = argv[0];
	check_options(progname);
	handle_args = argv + optind;

	if (nowrite)
		(void) fprintf(stdout, DRY_RUN);

	if (do_getinfo) {
		ret = handle_getinfo(progname, handle_args);
	} else if (do_mirror_bblk) {
		ret = handle_mirror(progname, handle_args);
	} else {
		ret = handle_install(progname, handle_args);
	}
	return (ret);
}

#define	MEANINGLESS_OPT	gettext("%s specified but meaningless, ignoring\n")
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

/*
 * Install a new stage1/stage2 pair on the specified device. handle_install()
 * expects argv to contain 3 parameters (the path to stage1, the path to stage2,
 * the target device).
 *
 * Returns:	BC_SUCCESS - if the installation is successful
 *		BC_ERROR   - if the installation failed
 *		BC_NOUPDT  - if no installation was performed because the GRUB
 *		             version currently installed is more recent than the
 *			     supplied one.
 *
 */
static int
handle_install(char *progname, char **argv)
{
	ig_data_t	install_data;
	char		*stage1_path = NULL;
	char		*stage2_path = NULL;
	char		*device_path = NULL;
	int		ret = BC_ERROR;

	stage1_path = strdup(argv[0]);
	stage2_path = strdup(argv[1]);
	device_path = strdup(argv[2]);

	bzero(&install_data, sizeof (ig_data_t));

	if (!stage1_path || !stage2_path || !device_path) {
		(void) fprintf(stderr, gettext("Missing parameter"));
		usage(progname);
		goto out;
	}

	BOOT_DEBUG("stage1 path: %s, stage2 path: %s, device: %s\n",
	    stage1_path, stage2_path, device_path);

	if (init_device(&install_data.device, device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information for %s\n"), device_path);
		goto out;
	}

	/* read in stage1 and stage2. */
	if (read_stage1_from_file(stage1_path, &install_data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error opening %s\n"),
		    stage1_path);
		goto out_dev;
	}

	if (read_stage2_from_file(stage2_path, &install_data) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error opening %s\n"),
		    stage2_path);
		goto out_dev;
	}

	/* We do not support versioning on PCFS. */
	if (is_bootpar(install_data.device.type) && do_version)
		do_version = B_FALSE;

	/*
	 * is_update_necessary() will take care of checking if versioning and/or
	 * forcing the update have been specified. It will also emit a warning
	 * if a non-versioned update is attempted over a versioned bootblock.
	 */
	if (!is_update_necessary(&install_data, update_str)) {
		(void) fprintf(stderr, gettext("GRUB version installed "
		    "on %s is more recent or identical\n"
		    "Use -F to override or install without the -u option\n"),
		    device_path);
		ret = BC_NOUPDT;
		goto out_dev;
	}
	/*
	 * We get here if:
	 * - the installed GRUB version is older than the one about to be
	 *   installed.
	 * - no versioning string has been passed through the command line.
	 * - a forced update is requested (-F).
	 */
	BOOT_DEBUG("Ready to commit to disk\n");
	ret = commit_to_disk(&install_data, update_str);

out_dev:
	cleanup_device(&install_data.device);
out:
	free(stage1_path);
	free(stage2_path);
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
	ig_data_t	data;
	ig_stage2_t	*stage2 = &data.stage2;
	ig_device_t	*device = &data.device;
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

	bzero(&data, sizeof (ig_data_t));
	BOOT_DEBUG("device path: %s\n", device_path);

	if (init_device(device, device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information for %s\n"), device_path);
		goto out_dev;
	}

	if (is_bootpar(device->type)) {
		(void) fprintf(stderr, gettext("Versioning not supported on "
		    "PCFS\n"));
		goto out_dev;
	}

	ret = read_stage2_from_disk(device->part_fd, stage2, device->type);
	if (ret == BC_ERROR) {
		(void) fprintf(stderr, gettext("Error reading stage2 from "
		    "%s\n"), device_path);
		goto out_dev;
	}

	if (ret == BC_NOEXTRA) {
		(void) fprintf(stdout, gettext("No multiboot header found on "
		    "%s, unable to locate extra information area\n"),
		    device_path);
		retval = BC_NOEINFO;
		goto out_dev;
	}

	einfo = find_einfo(stage2->extra, stage2->extra_size);
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

	size = stage2->buf_size - P2ROUNDUP(stage2->file_size, 8);
	print_einfo(flags, einfo, size);
	retval = BC_SUCCESS;

out_dev:
	cleanup_device(&data.device);
out:
	free(device_path);
	return (retval);
}

/*
 * Attempt to mirror (propagate) the current stage2 over the attaching disk.
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
	ig_data_t	curr_data;
	ig_data_t	attach_data;
	ig_device_t	*curr_device = &curr_data.device;
	ig_device_t	*attach_device = &attach_data.device;
	ig_stage2_t	*stage2_curr = &curr_data.stage2;
	ig_stage2_t	*stage2_attach = &attach_data.stage2;
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

	bzero(&curr_data, sizeof (ig_data_t));
	bzero(&attach_data, sizeof (ig_data_t));

	if (init_device(curr_device, curr_device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information for %s (current device)\n"), curr_device_path);
		goto out_currdev;
	}

	if (init_device(attach_device, attach_device_path) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Unable to gather device "
		    "information for %s (attaching device)\n"),
		    attach_device_path);
		goto out_devs;
	}

	if (is_bootpar(curr_device->type) || is_bootpar(attach_device->type)) {
		(void) fprintf(stderr, gettext("boot block mirroring is not "
		    "supported on PCFS\n"));
		goto out_devs;
	}

	ret = read_stage2_from_disk(curr_device->part_fd, stage2_curr,
	    curr_device->type);
	if (ret == BC_ERROR) {
		BOOT_DEBUG("Error reading first stage2 blocks from %s\n",
		    curr_device->path);
		retval = BC_ERROR;
		goto out_devs;
	}

	if (ret == BC_NOEXTRA) {
		BOOT_DEBUG("No multiboot header found on %s, unable to grab "
		    "stage2\n", curr_device->path);
		retval = BC_NOEXTRA;
		goto out_devs;
	}

	einfo_curr = find_einfo(stage2_curr->extra, stage2_curr->extra_size);
	if (einfo_curr != NULL)
		updt_str = einfo_get_string(einfo_curr);

	write_mbr = B_TRUE;
	force_mbr = B_TRUE;
	retval = propagate_bootblock(&curr_data, &attach_data, updt_str);
	cleanup_stage2(stage2_curr);
	cleanup_stage2(stage2_attach);

out_devs:
	cleanup_device(attach_device);
out_currdev:
	cleanup_device(curr_device);
out:
	free(curr_device_path);
	free(attach_device_path);
	return (retval);
}

static int
commit_to_disk(ig_data_t *install, char *updt_str)
{
	assert(install != NULL);
	/*
	 * vanilla stage1 and stage2 need to be updated at runtime.
	 * Update stage2 before stage1 because stage1 needs to know the first
	 * sector stage2 will be written to.
	 */
	if (prepare_stage2(install, updt_str) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error building stage2\n"));
		return (BC_ERROR);
	}
	if (prepare_stage1(install) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error building stage1\n"));
		return (BC_ERROR);
	}

	/* Write stage2 out to disk. */
	if (write_stage2(install) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error writing stage2 to "
		    "disk\n"));
		return (BC_ERROR);
	}

	/* Write stage1 to disk and, if requested, to the MBR. */
	if (write_stage1(install) != BC_SUCCESS) {
		(void) fprintf(stderr, gettext("Error writing stage1 to "
		    "disk\n"));
		return (BC_ERROR);
	}

	return (BC_SUCCESS);
}

/*
 * Propagate the bootblock on the source disk to the destination disk and
 * version it with 'updt_str' in the process. Since we cannot trust any data
 * on the attaching disk, we do not perform any specific check on a potential
 * target extended information structure and we just blindly update.
 */
static int
propagate_bootblock(ig_data_t *source, ig_data_t *target, char *updt_str)
{
	ig_device_t	*src_device = &source->device;
	ig_device_t	*dest_device = &target->device;
	ig_stage2_t	*src_stage2 = &source->stage2;
	ig_stage2_t	*dest_stage2 = &target->stage2;
	uint32_t	buf_size;
	int		retval;

	assert(source != NULL);
	assert(target != NULL);

	/* read in stage1 from the source disk. */
	if (read_stage1_from_disk(src_device->part_fd, target->stage1_buf)
	    != BC_SUCCESS)
		return (BC_ERROR);

	/* Prepare target stage2 for commit_to_disk. */
	cleanup_stage2(dest_stage2);

	if (updt_str != NULL)
		do_version = B_TRUE;
	else
		do_version = B_FALSE;

	buf_size = src_stage2->file_size + SECTOR_SIZE;

	dest_stage2->buf_size = P2ROUNDUP(buf_size, SECTOR_SIZE);
	dest_stage2->buf = malloc(dest_stage2->buf_size);
	if (dest_stage2->buf == NULL) {
		perror(gettext("Memory allocation failed"));
		return (BC_ERROR);
	}
	dest_stage2->file = dest_stage2->buf;
	dest_stage2->file_size = src_stage2->file_size;
	memcpy(dest_stage2->file, src_stage2->file, dest_stage2->file_size);
	dest_stage2->extra = dest_stage2->buf +
	    P2ROUNDUP(dest_stage2->file_size, 8);

	/* If we get down here we do have a mboot structure. */
	assert(src_stage2->mboot);

	dest_stage2->mboot_off = src_stage2->mboot_off;
	dest_stage2->mboot = (multiboot_header_t *)(dest_stage2->buf +
	    dest_stage2->mboot_off);

	(void) fprintf(stdout, gettext("Propagating %s stage1/stage2 to %s\n"),
	    src_device->path, dest_device->path);
	retval = commit_to_disk(target, updt_str);

	return (retval);
}

/*
 * open the device and fill the various members of ig_device_t.
 */
static int
init_device(ig_device_t *device, char *path)
{
	struct dk_gpt *vtoc;
	fstyp_handle_t fhdl;
	const char *fident;

	bzero(device, sizeof (*device));
	device->part_fd = -1;
	device->disk_fd = -1;
	device->path_p0 = NULL;

	device->path = strdup(path);
	if (device->path == NULL) {
		perror(gettext("Memory allocation failed"));
		return (BC_ERROR);
	}

	if (strstr(device->path, "diskette")) {
		(void) fprintf(stderr, gettext("installing GRUB to a floppy "
		    "disk is no longer supported\n"));
		return (BC_ERROR);
	}

	/* Detect if the target device is a pcfs partition. */
	if (strstr(device->path, "p0:boot"))
		device->type = IG_DEV_X86BOOTPAR;

	if (get_disk_fd(device) != BC_SUCCESS)
		return (BC_ERROR);

	/* read in the device boot sector. */
	if (read(device->disk_fd, device->boot_sector, SECTOR_SIZE)
	    != SECTOR_SIZE) {
		(void) fprintf(stderr, gettext("Error reading boot sector\n"));
		perror("read");
		return (BC_ERROR);
	}

	if (efi_alloc_and_read(device->disk_fd, &vtoc) >= 0) {
		device->type = IG_DEV_EFI;
		efi_free(vtoc);
	}

	if (get_raw_partition_fd(device) != BC_SUCCESS)
		return (BC_ERROR);

	if (is_efi(device->type)) {
		if (fstyp_init(device->part_fd, 0, NULL, &fhdl) != 0)
			return (BC_ERROR);

		if (fstyp_ident(fhdl, "zfs", &fident) != 0) {
			fstyp_fini(fhdl);
			(void) fprintf(stderr, gettext("Booting of EFI labeled "
			    "disks is only supported with ZFS\n"));
			return (BC_ERROR);
		}
		fstyp_fini(fhdl);
	}

	if (get_start_sector(device) != BC_SUCCESS)
		return (BC_ERROR);

	return (BC_SUCCESS);
}

static void
cleanup_device(ig_device_t *device)
{
	if (device->path)
		free(device->path);
	if (device->path_p0)
		free(device->path_p0);

	if (device->part_fd != -1)
		(void) close(device->part_fd);
	if (device->disk_fd != -1)
		(void) close(device->disk_fd);

	bzero(device, sizeof (ig_device_t));
	device->part_fd = -1;
	device->disk_fd = -1;
}

static void
cleanup_stage2(ig_stage2_t *stage2)
{
	if (stage2->buf)
		free(stage2->buf);
	bzero(stage2, sizeof (ig_stage2_t));
}

static int
get_start_sector(ig_device_t *device)
{
	uint32_t		secnum = 0, numsec = 0;
	int			i, pno, rval, log_part = 0;
	struct mboot		*mboot;
	struct ipart		*part = NULL;
	ext_part_t		*epp;
	struct part_info	dkpi;
	struct extpart_info	edkpi;

	if (is_efi(device->type)) {
		struct dk_gpt *vtoc;

		if (efi_alloc_and_read(device->disk_fd, &vtoc) < 0)
			return (BC_ERROR);

		device->start_sector = vtoc->efi_parts[device->slice].p_start;
		/* GPT doesn't use traditional slice letters */
		device->slice = 0xff;
		device->partition = 0;

		efi_free(vtoc);
		goto found_part;
	}

	mboot = (struct mboot *)device->boot_sector;

	if (is_bootpar(device->type)) {
		if (find_x86_bootpar(mboot, &pno, &secnum) != BC_SUCCESS) {
			(void) fprintf(stderr, NOBOOTPAR);
			return (BC_ERROR);
		} else {
			device->start_sector = secnum;
			device->partition = pno;
			goto found_part;
		}
	}

	/*
	 * Search for Solaris fdisk partition
	 * Get the solaris partition information from the device
	 * and compare the offset of S2 with offset of solaris partition
	 * from fdisk partition table.
	 */
	if (ioctl(device->part_fd, DKIOCEXTPARTINFO, &edkpi) < 0) {
		if (ioctl(device->part_fd, DKIOCPARTINFO, &dkpi) < 0) {
			(void) fprintf(stderr, PART_FAIL);
			return (BC_ERROR);
		} else {
			edkpi.p_start = dkpi.p_start;
		}
	}

	for (i = 0; i < FD_NUMPART; i++) {
		part = (struct ipart *)mboot->parts + i;

		if (part->relsect == 0) {
			(void) fprintf(stderr, BAD_PART, i);
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
		(void) fprintf(stderr, NOSOLPAR);
		return (BC_ERROR);
	}

	/*
	 * We have found a Solaris fdisk partition (primary or extended)
	 * Handle the simple case first: Solaris in a primary partition
	 */
	if (!fdisk_is_dos_extended(part->systid)) {
		device->start_sector = part->relsect;
		device->partition = i;
		goto found_part;
	}

	/*
	 * Solaris in a logical partition. Find that partition in the
	 * extended part.
	 */
	if ((rval = libfdisk_init(&epp, device->path_p0, NULL, FDISK_READ_DISK))
	    != FDISK_SUCCESS) {
		switch (rval) {
			/*
			 * The first 3 cases are not an error per-se, just that
			 * there is no Solaris logical partition
			 */
			case FDISK_EBADLOGDRIVE:
			case FDISK_ENOLOGDRIVE:
			case FDISK_EBADMAGIC:
				(void) fprintf(stderr, NOSOLPAR);
				return (BC_ERROR);
			case FDISK_ENOVGEOM:
				(void) fprintf(stderr, NO_VIRT_GEOM);
				return (BC_ERROR);
			case FDISK_ENOPGEOM:
				(void) fprintf(stderr, NO_PHYS_GEOM);
				return (BC_ERROR);
			case FDISK_ENOLGEOM:
				(void) fprintf(stderr, NO_LABEL_GEOM);
				return (BC_ERROR);
			default:
				(void) fprintf(stderr, LIBFDISK_INIT_FAIL);
				return (BC_ERROR);
		}
	}

	rval = fdisk_get_solaris_part(epp, &pno, &secnum, &numsec);
	libfdisk_fini(&epp);
	if (rval != FDISK_SUCCESS) {
		/* No solaris logical partition */
		(void) fprintf(stderr, NOSOLPAR);
		return (BC_ERROR);
	}

	device->start_sector = secnum;
	device->partition = pno - 1;
	log_part = 1;

found_part:
	/* get confirmation for -m */
	if (write_mbr && !force_mbr) {
		(void) fprintf(stdout, MBOOT_PROMPT);
		if (!yes()) {
			write_mbr = 0;
			(void) fprintf(stdout, MBOOT_NOT_UPDATED);
			return (BC_ERROR);
		}
	}

	/*
	 * Currently if Solaris is in an extended partition we need to
	 * write GRUB to the MBR. Check for this.
	 */
	if (log_part && !write_mbr) {
		(void) fprintf(stdout, gettext("Installing Solaris on an "
		    "extended partition... forcing MBR update\n"));
		write_mbr = 1;
	}

	/*
	 * warn, if Solaris in primary partition and GRUB not in MBR and
	 * partition is not active
	 */
	if (part != NULL) {
		if (!log_part && part->bootid != 128 && !write_mbr) {
			(void) fprintf(stdout, SOLPAR_INACTIVE,
			    device->partition + 1);
		}
	}

	return (BC_SUCCESS);
}

static int
get_disk_fd(ig_device_t *device)
{
	int	i = 0;
	char	save[2] = { '\0', '\0' };
	char	*end = NULL;

	assert(device != NULL);
	assert(device->path != NULL);

	if (is_bootpar(device->type)) {
		end = strstr(device->path, "p0:boot");
		/* tested at the start of init_device() */
		assert(end != NULL);
		/* chop off :boot */
		save[0] = end[2];
		end[2] = '\0';
	} else {
		i = strlen(device->path);
		save[0] = device->path[i - 2];
		save[1] = device->path[i - 1];
		device->path[i - 2] = 'p';
		device->path[i - 1] = '0';
	}

	if (nowrite)
		device->disk_fd = open(device->path, O_RDONLY);
	else
		device->disk_fd = open(device->path, O_RDWR);

	device->path_p0 = strdup(device->path);
	if (device->path_p0 == NULL) {
		perror("strdup");
		return (BC_ERROR);
	}

	if (is_bootpar(device->type)) {
		end[2] = save[0];
	} else {
		device->path[i - 2] = save[0];
		device->path[i - 1] = save[1];
	}

	if (device->disk_fd == -1) {
		perror("open");
		return (BC_ERROR);
	}

	return (BC_SUCCESS);
}

static void
prepare_fake_multiboot(ig_stage2_t *stage2)
{
	multiboot_header_t	*mboot;

	assert(stage2 != NULL);
	assert(stage2->mboot != NULL);
	assert(stage2->buf != NULL);

	mboot = stage2->mboot;

	/*
	 * Currently we expect find_multiboot() to have located a multiboot
	 * header with the AOUT kludge flag set.
	 */
	assert(mboot->flags & BB_MBOOT_AOUT_FLAG);

	/* Insert the information necessary to locate stage2. */
	mboot->header_addr = stage2->mboot_off;
	mboot->load_addr = 0;
	mboot->load_end_addr = stage2->file_size;
}

static void
add_stage2_einfo(ig_stage2_t *stage2, char *updt_str)
{
	bblk_hs_t	hs;
	uint32_t	avail_space;

	assert(stage2 != NULL);

	/* Fill bootblock hashing source information. */
	hs.src_buf = (unsigned char *)stage2->file;
	hs.src_size = stage2->file_size;
	/* How much space for the extended information structure? */
	avail_space = stage2->buf_size - P2ROUNDUP(stage2->file_size, 8);
	add_einfo(stage2->extra, updt_str, &hs, avail_space);
}


static int
write_stage2(ig_data_t *install)
{
	ig_device_t		*device = &install->device;
	ig_stage2_t		*stage2 = &install->stage2;
	off_t			offset;

	assert(install != NULL);

	if (is_bootpar(device->type)) {
		/*
		 * stage2 is already on the filesystem, we only need to update
		 * the first two blocks (that we have modified during
		 * prepare_stage2())
		 */
		if (write_out(device->part_fd, stage2->file, SECTOR_SIZE,
		    stage2->pcfs_first_sectors[0] * SECTOR_SIZE)
		    != BC_SUCCESS ||
		    write_out(device->part_fd, stage2->file + SECTOR_SIZE,
		    SECTOR_SIZE, stage2->pcfs_first_sectors[1] * SECTOR_SIZE)
		    != BC_SUCCESS) {
			(void) fprintf(stderr, WRITE_FAIL_STAGE2);
			return (BC_ERROR);
		}
		(void) fprintf(stdout, WRITE_STAGE2_PCFS);
		return (BC_SUCCESS);
	}

	/*
	 * For disk, write stage2 starting at STAGE2_BLKOFF sector.
	 * Note that we use stage2->buf rather than stage2->file, because we
	 * may have extended information after the latter.
	 *
	 * If we're writing to an EFI-labeled disk where stage2 lives in the
	 * 3.5MB boot loader gap following the ZFS vdev labels, make sure the
	 * size of the buffer doesn't exceed the size of the gap.
	 */
	if (is_efi(device->type) && stage2->buf_size > STAGE2_MAXSIZE) {
		(void) fprintf(stderr, WRITE_FAIL_STAGE2);
		return (BC_ERROR);
	}

	offset = STAGE2_BLKOFF(device->type) * SECTOR_SIZE;

	if (write_out(device->part_fd, stage2->buf, stage2->buf_size,
	    offset) != BC_SUCCESS) {
		perror("write");
		return (BC_ERROR);
	}

	/* Simulate the "old" installgrub output. */
	(void) fprintf(stdout, WRITE_STAGE2_DISK, device->partition,
	    (stage2->buf_size / SECTOR_SIZE) + 1, STAGE2_BLKOFF(device->type),
	    stage2->first_sector);

	return (BC_SUCCESS);
}

static int
write_stage1(ig_data_t *install)
{
	ig_device_t	*device = &install->device;

	assert(install != NULL);

	if (write_out(device->part_fd, install->stage1_buf,
	    sizeof (install->stage1_buf), 0) != BC_SUCCESS) {
		(void) fprintf(stdout, WRITE_FAIL_PBOOT);
		perror("write");
		return (BC_ERROR);
	}

	/* Simulate "old" installgrub output. */
	(void) fprintf(stdout, WRITE_PBOOT, device->partition,
	    device->start_sector);

	if (write_mbr) {
		if (write_out(device->disk_fd, install->stage1_buf,
		    sizeof (install->stage1_buf), 0) != BC_SUCCESS) {
			(void) fprintf(stdout, WRITE_FAIL_BOOTSEC);
			perror("write");
			return (BC_ERROR);
		}
		/* Simulate "old" installgrub output. */
		(void) fprintf(stdout, WRITE_MBOOT);
	}

	return (BC_SUCCESS);
}

#define	USAGE_STRING	"%s [-m|-f|-n|-F|-u verstr] stage1 stage2 device\n"    \
			"%s -M [-n] device1 device2\n"			       \
			"%s [-V|-e] -i device\n"			       \

#define	CANON_USAGE_STR	gettext(USAGE_STRING)

static void
usage(char *progname)
{
	(void) fprintf(stdout, CANON_USAGE_STR, progname, progname, progname);
}


static int
read_stage1_from_file(char *path, ig_data_t *dest)
{
	int	fd;

	assert(dest);

	/* read the stage1 file from filesystem */
	fd = open(path, O_RDONLY);
	if (fd == -1 ||
	    read(fd, dest->stage1_buf, SECTOR_SIZE) != SECTOR_SIZE) {
		(void) fprintf(stderr, READ_FAIL_STAGE1, path);
		return (BC_ERROR);
	}
	(void) close(fd);
	return (BC_SUCCESS);
}

static int
read_stage2_from_file(char *path, ig_data_t *dest)
{
	int		fd;
	struct stat	sb;
	ig_stage2_t	*stage2 = &dest->stage2;
	ig_device_t	*device = &dest->device;
	uint32_t	buf_size;

	assert(dest);
	assert(stage2->buf == NULL);

	fd = open(path, O_RDONLY);
	if (fstat(fd, &sb) == -1) {
		perror("fstat");
		goto out;
	}

	stage2->file_size = sb.st_size;

	if (!is_bootpar(device->type)) {
		/*
		 * buffer size needs to account for stage2 plus the extra
		 * versioning information at the end of it. We reserve one
		 * extra sector (plus we round up to the next sector boundary).
		 */
		buf_size = stage2->file_size + SECTOR_SIZE;
	} else {
		/* In the PCFS case we only need to read in stage2. */
		buf_size = stage2->file_size;
	}

	stage2->buf_size = P2ROUNDUP(buf_size, SECTOR_SIZE);

	BOOT_DEBUG("stage2 buffer size = %d (%d sectors)\n", stage2->buf_size,
	    stage2->buf_size / SECTOR_SIZE);

	stage2->buf = malloc(stage2->buf_size);
	if (stage2->buf == NULL) {
		perror(gettext("Memory allocation failed"));
		goto out_fd;
	}

	stage2->file = stage2->buf;

	/*
	 * Extra information (e.g. the versioning structure) is placed at the
	 * end of stage2, aligned on a 8-byte boundary.
	 */
	if (!(is_bootpar(device->type)))
		stage2->extra = stage2->file + P2ROUNDUP(stage2->file_size, 8);

	if (lseek(fd, 0, SEEK_SET) == -1) {
		perror("lseek");
		goto out_alloc;
	}

	if (read(fd, stage2->file, stage2->file_size) < 0) {
		perror(gettext("unable to read stage2"));
		goto out_alloc;
	}

	(void) close(fd);
	return (BC_SUCCESS);

out_alloc:
	free(stage2->buf);
	stage2->buf = NULL;
out_fd:
	(void) close(fd);
out:
	return (BC_ERROR);
}

static int
prepare_stage1(ig_data_t *install)
{
	ig_device_t	*device = &install->device;

	assert(install != NULL);

	/* If PCFS add the BIOS Parameter Block. */
	if (is_bootpar(device->type)) {
		char	bpb_sect[SECTOR_SIZE];

		if (pread(device->part_fd, bpb_sect, SECTOR_SIZE, 0)
		    != SECTOR_SIZE) {
			(void) fprintf(stderr, READ_FAIL_BPB);
			return (BC_ERROR);
		}
		bcopy(bpb_sect + STAGE1_BPB_OFFSET,
		    install->stage1_buf + STAGE1_BPB_OFFSET, STAGE1_BPB_SIZE);
	}

	/* copy MBR to stage1 in case of overwriting MBR sector. */
	bcopy(device->boot_sector + BOOTSZ, install->stage1_buf + BOOTSZ,
	    SECTOR_SIZE - BOOTSZ);
	/* modify default stage1 file generated by GRUB. */
	*((unsigned char *)(install->stage1_buf + STAGE1_FORCE_LBA)) = 1;
	*((ulong_t *)(install->stage1_buf + STAGE1_STAGE2_SECTOR))
	    = install->stage2.first_sector;
	*((ushort_t *)(install->stage1_buf + STAGE1_STAGE2_ADDRESS))
	    = STAGE2_MEMADDR;
	*((ushort_t *)(install->stage1_buf + STAGE1_STAGE2_SEGMENT))
	    = STAGE2_MEMADDR >> 4;

	return (BC_SUCCESS);
}

/*
 * Grab stage1 from the specified device file descriptor.
 */
static int
read_stage1_from_disk(int dev_fd, char *stage1_buf)
{
	assert(stage1_buf != NULL);

	if (read_in(dev_fd, stage1_buf, SECTOR_SIZE, 0) != BC_SUCCESS) {
		perror(gettext("Unable to read stage1 from disk"));
		return (BC_ERROR);
	}
	return (BC_SUCCESS);
}

static int
read_stage2_from_disk(int dev_fd, ig_stage2_t *stage2, int type)
{
	uint32_t		size;
	uint32_t		buf_size;
	uint32_t		mboot_off;
	multiboot_header_t	*mboot;

	assert(stage2 != NULL);
	assert(dev_fd != -1);

	if (read_in(dev_fd, mboot_scan, sizeof (mboot_scan),
	    STAGE2_BLKOFF(type) * SECTOR_SIZE) != BC_SUCCESS) {
		perror(gettext("Error reading stage2 sectors"));
		return (BC_ERROR);
	}

	/* No multiboot means no chance of knowing stage2 size */
	if (find_multiboot(mboot_scan, sizeof (mboot_scan), &mboot_off)
	    != BC_SUCCESS) {
		BOOT_DEBUG("Unable to find multiboot header\n");
		return (BC_NOEXTRA);
	}
	mboot = (multiboot_header_t *)(mboot_scan + mboot_off);

	/*
	 * Unfilled mboot values mean an older version of installgrub installed
	 * the stage2. Again we have no chance of knowing stage2 size.
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

	stage2->buf = malloc(buf_size);
	if (stage2->buf == NULL) {
		perror(gettext("Memory allocation failed"));
		return (BC_ERROR);
	}
	stage2->buf_size = buf_size;

	if (read_in(dev_fd, stage2->buf, buf_size, STAGE2_BLKOFF(type) *
	    SECTOR_SIZE) != BC_SUCCESS) {
		perror("read");
		free(stage2->buf);
		return (BC_ERROR);
	}

	/* Update pointers. */
	stage2->file = stage2->buf;
	stage2->file_size = size;
	stage2->mboot_off = mboot_off;
	stage2->mboot = (multiboot_header_t *)(stage2->buf + stage2->mboot_off);
	stage2->extra = stage2->buf + P2ROUNDUP(stage2->file_size, 8);
	stage2->extra_size = stage2->buf_size - P2ROUNDUP(stage2->file_size, 8);

	return (BC_SUCCESS);
}

static boolean_t
is_update_necessary(ig_data_t *data, char *updt_str)
{
	bblk_einfo_t	*einfo;
	bblk_hs_t	stage2_hs;
	ig_stage2_t	stage2_disk;
	ig_stage2_t	*stage2_file = &data->stage2;
	ig_device_t	*device = &data->device;
	int		dev_fd = device->part_fd;

	assert(data != NULL);
	assert(device->part_fd != -1);

	bzero(&stage2_disk, sizeof (ig_stage2_t));

	/* Gather stage2 (if present) from the target device. */
	if (read_stage2_from_disk(dev_fd, &stage2_disk, device->type)
	    != BC_SUCCESS) {
		BOOT_DEBUG("Unable to read stage2 from %s\n", device->path);
		BOOT_DEBUG("No multiboot wrapped stage2 on %s\n", device->path);
		return (B_TRUE);
	}

	/*
	 * Look for the extended information structure in the extra payload
	 * area.
	 */
	einfo = find_einfo(stage2_disk.extra, stage2_disk.extra_size);
	if (einfo == NULL) {
		BOOT_DEBUG("No extended information available\n");
		return (B_TRUE);
	}

	if (!do_version || updt_str == NULL) {
		(void) fprintf(stdout, "WARNING: target device %s has a "
		    "versioned stage2 that is going to be overwritten by a non "
		    "versioned one\n", device->path);
		return (B_TRUE);
	}

	if (force_update) {
		BOOT_DEBUG("Forcing update of %s bootblock\n", device->path);
		return (B_TRUE);
	}

	/* Compare the two extended information structures. */
	stage2_hs.src_buf = (unsigned char *)stage2_file->file;
	stage2_hs.src_size = stage2_file->file_size;

	return (einfo_should_update(einfo, &stage2_hs, updt_str));
}


#define	START_BLOCK(pos)	(*(ulong_t *)(pos))
#define	NUM_BLOCK(pos)		(*(ushort_t *)((pos) + 4))
#define	START_SEG(pos)		(*(ushort_t *)((pos) + 6))

static int
prepare_stage2(ig_data_t *install, char *updt_str)
{
	ig_device_t	*device = &install->device;
	ig_stage2_t	*stage2 = &install->stage2;
	uint32_t	mboot_off = 0;

	assert(install != NULL);
	assert(stage2->file != NULL);

	/* New stage2 files come with an embedded stage2. */
	if (find_multiboot(stage2->file, stage2->file_size, &mboot_off)
	    != BC_SUCCESS) {
		BOOT_DEBUG("WARNING: no multiboot structure found in stage2, "
		    "are you using an old GRUB stage2?\n");
		if (do_version == B_TRUE) {
			(void) fprintf(stderr, gettext("Versioning requested "
			    "but stage2 does not support it.. skipping.\n"));
			do_version = B_FALSE;
		}
	} else {
		/* Keep track of where the multiboot header is. */
		stage2->mboot_off = mboot_off;
		stage2->mboot = (multiboot_header_t *)(stage2->file +
		    mboot_off);
		if (do_version) {
			/*
			 * Adding stage2 information needs to happen before
			 * we modify the copy of stage2 we have in memory, so
			 * that the hashing reflects the one of the file.
			 * An error here is not fatal.
			 */
			add_stage2_einfo(stage2, updt_str);
		}
		/*
		 * Fill multiboot information. We add them even without
		 * versioning to support as much as possible mirroring.
		 */
		prepare_fake_multiboot(stage2);
	}

	if (is_bootpar(device->type)) {
		uint32_t	blocklist[SECTOR_SIZE / sizeof (uint32_t)];
		uint32_t	install_addr = STAGE2_MEMADDR + SECTOR_SIZE;
		int		i = 0;
		uchar_t		*pos;

		bzero(blocklist, sizeof (blocklist));
		if (read_stage2_blocklist(device->part_fd, blocklist) != 0) {
			(void) fprintf(stderr, gettext("Error reading pcfs "
			    "stage2 blocklist\n"));
			return (BC_ERROR);
		}

		pos = (uchar_t *)stage2->file + STAGE2_BLOCKLIST;
		stage2->first_sector = device->start_sector + blocklist[0];
		stage2->pcfs_first_sectors[0] = blocklist[0];
		BOOT_DEBUG("stage2 first sector: %d\n", stage2->first_sector);


		if (blocklist[1] > 1) {
			blocklist[0]++;
			blocklist[1]--;
		} else {
			i += 2;
		}

		stage2->pcfs_first_sectors[1] = blocklist[i];

		while (blocklist[i]) {
			if (START_BLOCK(pos - 8) != 0 &&
			    START_BLOCK(pos - 8) != blocklist[i + 2]) {
				(void) fprintf(stderr, PCFS_FRAGMENTED);
				return (BC_ERROR);
			}
			START_BLOCK(pos) = blocklist[i] + device->start_sector;
			START_SEG(pos) = (ushort_t)(install_addr >> 4);
			NUM_BLOCK(pos) = blocklist[i + 1];
			install_addr += blocklist[i + 1] * SECTOR_SIZE;
			pos -= 8;
			i += 2;
		}
	} else {
		/* Solaris VTOC & EFI */
		if (device->start_sector >
		    UINT32_MAX - STAGE2_BLKOFF(device->type)) {
			fprintf(stderr, gettext("Error: partition start sector "
			    "must be less than %lld\n"),
			    (uint64_t)UINT32_MAX - STAGE2_BLKOFF(device->type));
			return (BC_ERROR);
		}
		stage2->first_sector = device->start_sector +
		    STAGE2_BLKOFF(device->type);
		BOOT_DEBUG("stage2 first sector: %d\n", stage2->first_sector);
		/*
		 * In a solaris partition, stage2 is written to contiguous
		 * blocks. So we update the starting block only.
		 */
		*((ulong_t *)(stage2->file + STAGE2_BLOCKLIST)) =
		    stage2->first_sector + 1;
	}

	/* force lba and set disk partition */
	*((unsigned char *) (stage2->file + STAGE2_FORCE_LBA)) = 1;
	*((long *)(stage2->file + STAGE2_INSTALLPART))
	    = (device->partition << 16) | (device->slice << 8) | 0xff;

	return (BC_SUCCESS);
}

static int
find_x86_bootpar(struct mboot *mboot, int *part_num, uint32_t *start_sect)
{
	int	i;

	for (i = 0; i < FD_NUMPART; i++) {
		struct ipart	*part;

		part = (struct ipart *)mboot->parts + i;
		if (part->systid == 0xbe) {
			if (start_sect)
				*start_sect = part->relsect;
			if (part_num)
				*part_num = i;
			/* solaris boot part */
			return (BC_SUCCESS);
		}
	}
	return (BC_ERROR);
}

static char *
get_raw_partition_path(ig_device_t *device)
{
	char	*raw;
	int	len;

	if (is_bootpar(device->type)) {
		int		part;
		struct mboot	*mboot;

		mboot = (struct mboot *)device->boot_sector;
		if (find_x86_bootpar(mboot, &part, NULL) != BC_SUCCESS) {
			(void) fprintf(stderr, BOOTPAR_NOTFOUND,
			    device->path_p0);
			return (NULL);
		}

		raw = strdup(device->path_p0);
		if (raw == NULL) {
			perror(gettext("Memory allocation failed"));
			return (NULL);
		}

		raw[strlen(raw) - 2] = '1' + part;
		return (raw);
	}

	/* For disk, remember slice and return whole fdisk partition  */
	raw = strdup(device->path);
	if (raw == NULL) {
		perror(gettext("Memory allocation failed"));
		return (NULL);
	}

	len = strlen(raw);
	if (!is_efi(device->type) &&
	    (raw[len - 2] != 's' || raw[len - 1] == '2')) {
		(void) fprintf(stderr, NOT_ROOT_SLICE);
		free(raw);
		return (NULL);
	}
	device->slice = atoi(&raw[len - 1]);

	if (!is_efi(device->type)) {
		raw[len - 2] = 's';
		raw[len - 1] = '2';
	}

	return (raw);
}

static int
get_raw_partition_fd(ig_device_t *device)
{
	struct stat	stat = {0};
	char		*raw;

	raw = get_raw_partition_path(device);
	if (raw == NULL)
		return (BC_ERROR);

	if (nowrite)
		device->part_fd = open(raw, O_RDONLY);
	else
		device->part_fd = open(raw, O_RDWR);

	if (device->part_fd < 0 || fstat(device->part_fd, &stat) != 0) {
		(void) fprintf(stderr, OPEN_FAIL, raw);
		free(raw);
		return (BC_ERROR);
	}

	if (S_ISCHR(stat.st_mode) == 0) {
		(void) fprintf(stderr, NOT_RAW_DEVICE, raw);
		(void) close(device->part_fd);
		device->part_fd = -1;
		free(raw);
		return (BC_ERROR);
	}

	free(raw);
	return (BC_SUCCESS);
}
