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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/mnttab.h>
#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>

#include <libintl.h>
#include <locale.h>
#include "message.h"
#include <errno.h>
#include <libfdisk.h>

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

#define	SECTOR_SIZE	0x200
#define	STAGE2_MEMADDR	0x8000	/* loading addr of stage2 */

#define	STAGE1_BPB_OFFSET	0x3
#define	STAGE1_BPB_SIZE		0x3B
#define	STAGE1_BOOT_DRIVE	0x40
#define	STAGE1_FORCE_LBA	0x41
#define	STAGE1_STAGE2_ADDRESS	0x42
#define	STAGE1_STAGE2_SECTOR	0x44
#define	STAGE1_STAGE2_SEGMENT	0x48

#define	STAGE2_BLOCKLIST	(SECTOR_SIZE - 0x8)
#define	STAGE2_INSTALLPART	(SECTOR_SIZE + 0x8)
#define	STAGE2_FORCE_LBA	(SECTOR_SIZE + 0x11)
#define	STAGE2_VER_STRING	(SECTOR_SIZE + 0x12)
#define	STAGE2_BLKOFF		50	/* offset from start of fdisk part */

static int nowrite = 0;
static int write_mboot = 0;
static int force_mboot = 0;
static int is_floppy = 0;
static int is_bootpar = 0;
static int stage2_fd;
static int partition, slice = 0xff;
static char *device_p0;
static uint32_t stage2_first_sector, stage2_second_sector;


static char bpb_sect[SECTOR_SIZE];
static char boot_sect[SECTOR_SIZE];
static char stage1_buffer[SECTOR_SIZE];
static char stage2_buffer[2 * SECTOR_SIZE];
static unsigned int blocklist[SECTOR_SIZE / sizeof (unsigned int)];

static int open_device(char *);
static void read_bpb_sect(int);
static void read_boot_sect(char *);
static void write_boot_sect(char *);
static void read_stage1_stage2(char *, char *);
static void modify_and_write_stage1(int);
static void modify_and_write_stage2(int);
static unsigned int get_start_sector(int);
static void copy_stage2(int, char *);
static char *get_raw_partition(char *);
static void usage(char *);

extern int read_stage2_blocklist(int, unsigned int *);

int
main(int argc, char *argv[])
{
	int dev_fd, opt;
	char *stage1, *stage2, *device;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "fmn")) != EOF) {
		switch (opt) {
		case 'm':
			write_mboot = 1;
			break;
		case 'n':
			nowrite = 1;
			break;
		case 'f':
			force_mboot = 1;
			break;
		default:
			/* fall through to process non-optional args */
			break;
		}
	}

	/* check arguments */
	if (argc != optind + 3) {
		usage(argv[0]);
	}

	if (nowrite) {
		(void) fprintf(stdout, DRY_RUN);
	}

	stage1 = strdup(argv[optind]);
	stage2 = strdup(argv[optind + 1]);
	device = strdup(argv[optind + 2]);

	if (!stage1 || !stage2 || !device) {
		usage(argv[0]);
	}

	/* open and check device type */
	dev_fd = open_device(device);

	/* read in stage1 and stage2 into buffer */
	read_stage1_stage2(stage1, stage2);

	/* In the pcfs case, write a fresh stage2 */
	if (is_floppy || is_bootpar) {
		copy_stage2(dev_fd, device);
		read_bpb_sect(dev_fd);
	}

	/* read in boot sector */
	if (!is_floppy)
		read_boot_sect(device);

	/* modify stage1 based on grub needs */
	modify_and_write_stage1(dev_fd);

	/* modify stage2 and write to media */
	modify_and_write_stage2(dev_fd);

	if (!is_floppy && write_mboot)
		write_boot_sect(device);
	(void) close(dev_fd);

	return (0);
}

static unsigned int
get_start_sector(int fd)
{
	static unsigned int start_sect = 0;
	uint32_t secnum, numsec;
	int i, pno, rval, ext_sol_part_found = 0;
	struct mboot *mboot;
	struct ipart *part;
	ext_part_t *epp;

	if (start_sect)
		return (start_sect);

	mboot = (struct mboot *)boot_sect;
	for (i = 0; i < FD_NUMPART; i++) {
		part = (struct ipart *)mboot->parts + i;
		if (is_bootpar) {
			if (part->systid == 0xbe)
				break;
		}
	}

	/* Read extended partition to find a solaris partition */
	if ((rval = libfdisk_init(&epp, device_p0, NULL, FDISK_READ_DISK))
	    != FDISK_SUCCESS) {
		switch (rval) {
			/*
			 * FDISK_EBADLOGDRIVE and FDISK_ENOLOGDRIVE can
			 * be considered as soft errors and hence
			 * we do not exit
			 */
			case FDISK_EBADLOGDRIVE:
				break;
			case FDISK_ENOLOGDRIVE:
				break;
			case FDISK_ENOVGEOM:
				fprintf(stderr, "Could not get virtual"
				    " geometry for this device\n");
				exit(1);
				break;
			case FDISK_ENOPGEOM:
				fprintf(stderr, "Could not get physical"
				    " geometry for this device\n");
				exit(1);
				break;
			case FDISK_ENOLGEOM:
				fprintf(stderr, "Could not get label"
				    " geometry for this device\n");
				exit(1);
				break;
			default:
				perror("Failed to initialise libfdisk.\n");
				exit(1);
				break;
		}
	}

	rval = fdisk_get_solaris_part(epp, &pno, &secnum, &numsec);
	if (rval == FDISK_SUCCESS) {
		ext_sol_part_found = 1;
	}
	libfdisk_fini(&epp);

	/*
	 * If there is no boot partition, find the solaris partition
	 */

	if (i == FD_NUMPART) {
		struct part_info dkpi;
		struct extpart_info edkpi;

		/*
		 * Get the solaris partition information from the device
		 * and compare the offset of S2 with offset of solaris partition
		 * from fdisk partition table.
		 */
		if (ioctl(fd, DKIOCEXTPARTINFO, &edkpi) < 0) {
			if (ioctl(fd, DKIOCPARTINFO, &dkpi) < 0) {
				(void) fprintf(stderr, PART_FAIL);
				exit(-1);
			} else {
				edkpi.p_start = dkpi.p_start;
			}
		}

		for (i = 0; i < FD_NUMPART; i++) {
			part = (struct ipart *)mboot->parts + i;

			if (part->relsect == 0) {
				(void) fprintf(stderr, BAD_PART, i);
				exit(-1);
			}

			if (fdisk_is_dos_extended(part->systid))
				continue;

			if (edkpi.p_start >= part->relsect &&
			    edkpi.p_start < (part->relsect + part->numsect)) {
				/* Found the partition */
				break;
			}
		}
	}

	if ((i == FD_NUMPART) && (!ext_sol_part_found)) {
		(void) fprintf(stderr, BOOTPAR);
		exit(-1);
	}

	/* get confirmation for -m */
	if (write_mboot && !force_mboot) {
		(void) fprintf(stdout, MBOOT_PROMPT);
		if (getchar() != 'y') {
			write_mboot = 0;
			(void) fprintf(stdout, MBOOT_NOT_UPDATED);
		}
	}

	if ((i == FD_NUMPART) && (ext_sol_part_found)) {
		start_sect = secnum;
		partition = pno;
	} else {
		start_sect = part->relsect;
		partition = i;
	}

	if (part->bootid != 128 && write_mboot == 0) {
		(void) fprintf(stdout, BOOTPAR_INACTIVE, i + 1);
	}

	return (start_sect);
}

static void
usage(char *progname)
{
	(void) fprintf(stderr, USAGE, basename(progname));
	exit(-1);
}

static int
open_device(char *device)
{
	int dev_fd;
	struct stat stat;
	char *raw_part;

	is_floppy = strncmp(device, "/dev/rdsk", strlen("/dev/rdsk")) &&
	    strncmp(device, "/dev/dsk", strlen("/dev/dsk"));

	/* handle boot partition specification */
	if (!is_floppy && strstr(device, "p0:boot")) {
		is_bootpar = 1;
	}

	raw_part = get_raw_partition(device);

	if (nowrite)
		dev_fd = open(raw_part, O_RDONLY);
	else
		dev_fd = open(raw_part, O_RDWR);

	if (dev_fd == -1 || fstat(dev_fd, &stat) != 0) {
		(void) fprintf(stderr, OPEN_FAIL, raw_part);
		exit(-1);
	}
	if (S_ISCHR(stat.st_mode) == 0) {
		(void) fprintf(stderr, NOT_RAW_DEVICE, raw_part);
		exit(-1);
	}

	return (dev_fd);
}

static void
read_stage1_stage2(char *stage1, char *stage2)
{
	int fd;

	/* read the stage1 file from filesystem */
	fd = open(stage1, O_RDONLY);
	if (fd == -1 || read(fd, stage1_buffer, SECTOR_SIZE) != SECTOR_SIZE) {
		(void) fprintf(stderr, READ_FAIL_STAGE1, stage1);
		exit(-1);
	}
	(void) close(fd);

	/* read first two blocks of stage 2 from filesystem */
	stage2_fd = open(stage2, O_RDONLY);
	if (stage2_fd == -1 ||
	    read(stage2_fd, stage2_buffer, 2 * SECTOR_SIZE)
	    != 2 * SECTOR_SIZE) {
		(void) fprintf(stderr, READ_FAIL_STAGE2, stage2);
		exit(-1);
	}
	/* leave the stage2 file open for later */
}

static void
read_bpb_sect(int dev_fd)
{
	if (pread(dev_fd, bpb_sect, SECTOR_SIZE, 0) != SECTOR_SIZE) {
		(void) fprintf(stderr, READ_FAIL_BPB);
		exit(-1);
	}
}

static void
read_boot_sect(char *device)
{
	static int read_mbr = 0;
	int i, fd;
	char save[2];

	if (read_mbr)
		return;
	read_mbr = 1;

	/* get the whole disk (p0) */
	i = strlen(device);
	save[0] = device[i - 2];
	save[1] = device[i - 1];
	device[i - 2] = 'p';
	device[i - 1] = '0';

	device_p0 = strdup(device);
	fd = open(device, O_RDONLY);
	if (fd == -1 || read(fd, boot_sect, SECTOR_SIZE) != SECTOR_SIZE) {
		(void) fprintf(stderr, READ_FAIL_MBR, device);
		if (fd == -1)
			perror("open");
		else
			perror("read");
		exit(-1);
	}
	(void) close(fd);
	device[i - 2] = save[0];
	device[i - 1] = save[1];
}

static void
write_boot_sect(char *device)
{
	int fd, len;
	char *raw, *end;
	struct stat stat;

	/* make a copy and chop off ":boot" */
	raw = strdup(device);
	end = strstr(raw, "p0:boot");
	if (end)
		end[2] = 0;

	/* open p0 (whole disk) */
	len = strlen(raw);
	raw[len - 2] = 'p';
	raw[len - 1] = '0';
	fd = open(raw, O_WRONLY);
	if (fd == -1 || fstat(fd, &stat) != 0) {
		(void) fprintf(stderr, OPEN_FAIL, raw);
		exit(-1);
	}
	if (!nowrite &&
	    pwrite(fd, stage1_buffer, SECTOR_SIZE, 0) != SECTOR_SIZE) {
		(void) fprintf(stderr, WRITE_FAIL_BOOTSEC);
		exit(-1);
	}
	(void) fprintf(stdout, WRITE_MBOOT);
	(void) close(fd);
}

static void
modify_and_write_stage1(int dev_fd)
{
	if (is_floppy) {
		stage2_first_sector = blocklist[0];
		/* copy bios parameter block (for fat fs) */
		bcopy(bpb_sect + STAGE1_BPB_OFFSET,
		    stage1_buffer + STAGE1_BPB_OFFSET, STAGE1_BPB_SIZE);
	} else if (is_bootpar) {
		stage2_first_sector = get_start_sector(dev_fd) + blocklist[0];
		/* copy bios parameter block (for fat fs) and MBR */
		bcopy(bpb_sect + STAGE1_BPB_OFFSET,
		    stage1_buffer + STAGE1_BPB_OFFSET, STAGE1_BPB_SIZE);
		bcopy(boot_sect + BOOTSZ, stage1_buffer + BOOTSZ, 512 - BOOTSZ);
		*((unsigned char *)(stage1_buffer + STAGE1_FORCE_LBA)) = 1;
	} else {
		stage2_first_sector = get_start_sector(dev_fd) + STAGE2_BLKOFF;
		/* copy MBR to stage1 in case of overwriting MBR sector */
		bcopy(boot_sect + BOOTSZ, stage1_buffer + BOOTSZ, 512 - BOOTSZ);
		*((unsigned char *)(stage1_buffer + STAGE1_FORCE_LBA)) = 1;
	}

	/* modify default stage1 file generated by GRUB */
	*((ulong_t *)(stage1_buffer + STAGE1_STAGE2_SECTOR))
	    = stage2_first_sector;
	*((ushort_t *)(stage1_buffer + STAGE1_STAGE2_ADDRESS))
	    = STAGE2_MEMADDR;
	*((ushort_t *)(stage1_buffer + STAGE1_STAGE2_SEGMENT))
	    = STAGE2_MEMADDR >> 4;

	/*
	 * XXX the default grub distribution also:
	 * - Copy the possible MBR/extended part table
	 * - Set the boot drive of stage1
	 */

	/* write stage1/pboot to 1st sector */
	if (!nowrite &&
	    pwrite(dev_fd, stage1_buffer, SECTOR_SIZE, 0) != SECTOR_SIZE) {
		(void) fprintf(stderr, WRITE_FAIL_PBOOT);
		exit(-1);
	}

	if (is_floppy) {
		(void) fprintf(stdout, WRITE_BOOTSEC_FLOPPY);
	} else {
		(void) fprintf(stdout, WRITE_PBOOT,
		    partition, get_start_sector(dev_fd));
	}
}

#define	START_BLOCK(pos)	(*(ulong_t *)(pos))
#define	NUM_BLOCK(pos)		(*(ushort_t *)((pos) + 4))
#define	START_SEG(pos)		(*(ushort_t *)((pos) + 6))

static void
modify_and_write_stage2(int dev_fd)
{
	int nrecord;
	off_t offset;

	if (is_floppy || is_bootpar) {
		int i = 0;
		uint32_t partition_offset;
		uint32_t install_addr = 0x8200;
		uchar_t *pos = (uchar_t *)stage2_buffer + STAGE2_BLOCKLIST;

		stage2_first_sector = blocklist[0];

		/* figure out the second sector */
		if (blocklist[1] > 1) {
			blocklist[0]++;
			blocklist[1]--;
		} else {
			i += 2;
		}
		stage2_second_sector = blocklist[i];

		if (is_floppy)
			partition_offset = 0;
		else	/* solaris boot partition */
			partition_offset = get_start_sector(dev_fd);

		/* install the blocklist at the end of stage2_buffer */
		while (blocklist[i]) {
			if (START_BLOCK(pos - 8) != 0 &&
			    START_BLOCK(pos - 8) != blocklist[i + 2]) {
				(void) fprintf(stderr, PCFS_FRAGMENTED);
				exit(-1);
			}
			START_BLOCK(pos) = blocklist[i] + partition_offset;
			START_SEG(pos) = (ushort_t)(install_addr >> 4);
			NUM_BLOCK(pos) = blocklist[i + 1];
			install_addr += blocklist[i + 1] * SECTOR_SIZE;
			pos -= 8;
			i += 2;
		}

	} else {
		/*
		 * In a solaris partition, stage2 is written to contiguous
		 * blocks. So we update the starting block only.
		 */
		*((ulong_t *)(stage2_buffer + STAGE2_BLOCKLIST)) =
		    stage2_first_sector + 1;
	}

	if (is_floppy) {
		/* modify the config file to add (fd0) */
		char *config_file = stage2_buffer + STAGE2_VER_STRING;
		while (*config_file++)
			;
		strcpy(config_file, "(fd0)/boot/grub/menu.lst");
	} else {
		/* force lba and set disk partition */
		*((unsigned char *) (stage2_buffer + STAGE2_FORCE_LBA)) = 1;
		*((long *)(stage2_buffer + STAGE2_INSTALLPART))
		    = (partition << 16) | (slice << 8) | 0xff;
	}

	/* modification done, now do the writing */
	if (is_floppy || is_bootpar) {
		/* we rewrite block 0 and 1 and that's it */
		if (!nowrite &&
		    (pwrite(dev_fd, stage2_buffer, SECTOR_SIZE,
		    stage2_first_sector * SECTOR_SIZE) != SECTOR_SIZE ||
		    pwrite(dev_fd, stage2_buffer + SECTOR_SIZE, SECTOR_SIZE,
		    stage2_second_sector * SECTOR_SIZE) != SECTOR_SIZE)) {
			(void) fprintf(stderr, WRITE_FAIL_STAGE2);
			exit(-1);
		}
		(void) fprintf(stdout, WRITE_STAGE2_PCFS);
		return;
	}

	/* for disk, write stage2 starting at STAGE2_BLKOFF sector */
	offset = STAGE2_BLKOFF;

	/* write the modified first two sectors */
	if (!nowrite && pwrite(dev_fd, stage2_buffer, 2 * SECTOR_SIZE,
	    offset * SECTOR_SIZE) != 2 * SECTOR_SIZE) {
		(void) fprintf(stderr, WRITE_FAIL_STAGE2);
		exit(-1);
	}

	/* write the remaining sectors */
	nrecord = 2;
	offset += 2;
	for (;;) {
		int nread, nwrite;
		nread = pread(stage2_fd, stage2_buffer, SECTOR_SIZE,
		    nrecord * SECTOR_SIZE);
		if (nread > 0 && !nowrite)
			nwrite = pwrite(dev_fd, stage2_buffer, SECTOR_SIZE,
			    offset * SECTOR_SIZE);
		else
			nwrite = SECTOR_SIZE;
		if (nread < 0 || nwrite != SECTOR_SIZE) {
			(void) fprintf(stderr, WRITE_FAIL_STAGE2_BLOCKS,
			    nread, nwrite);
			break;
		}
		if (nread > 0) {
			nrecord ++;
			offset ++;
		}
		if (nread < SECTOR_SIZE)
			break;	/* end of file */
	}
	(void) fprintf(stdout, WRITE_STAGE2_DISK,
	    partition, nrecord, STAGE2_BLKOFF, stage2_first_sector);
}

static char *
get_raw_partition(char *device)
{
	int len;
	struct mboot *mboot;
	static char *raw = NULL;

	if (raw)
		return (raw);
	raw = strdup(device);

	if (is_floppy)
		return (raw);

	if (is_bootpar) {
		int i;
		char *end = strstr(raw, "p0:boot");

		end[2] = 0;		/* chop off :boot */
		read_boot_sect(raw);
		mboot = (struct mboot *)boot_sect;
		for (i = 0; i < FD_NUMPART; i++) {
			struct ipart *part = (struct ipart *)mboot->parts + i;
			if (part->systid == 0xbe)	/* solaris boot part */
				break;
		}

		if (i == FD_NUMPART) {
			(void) fprintf(stderr, BOOTPAR_NOTFOUND, device);
			exit(-1);
		}
		end[1] = '1' + i;	/* set partition name */
		return (raw);
	}

	/* For disk, remember slice and return whole fdisk partition  */
	len = strlen(raw);
	if (raw[len - 2] != 's' || raw[len - 1] == '2') {
		(void) fprintf(stderr, NOT_ROOT_SLICE);
		exit(-1);
	}
	slice = atoi(&raw[len - 1]);

	raw[len - 2] = 's';
	raw[len - 1] = '2';
	return (raw);
}

#define	TMP_MNTPT	"/tmp/installgrub_pcfs"
static void
copy_stage2(int dev_fd, char *device)
{
	FILE *mntfp;
	int i, pcfs_fp;
	char buf[SECTOR_SIZE];
	char *cp;
	struct mnttab mp = {0}, mpref = {0};

	/* convert raw to block device name by removing the first 'r' */
	(void) strncpy(buf, device, sizeof (buf));
	buf[sizeof (buf) - 1] = 0;
	cp = strchr(buf, 'r');
	if (cp == NULL) {
		(void) fprintf(stderr, CONVERT_FAIL, device);
		exit(-1);
	}
	do {
		*cp = *(cp + 1);
	} while (*(++cp));

	/* get the mount point, if any */
	mntfp = fopen("/etc/mnttab", "r");
	if (mntfp == NULL) {
		(void) fprintf(stderr, OPEN_FAIL_FILE, "/etc/mnttab");
		exit(-1);
	}

	mpref.mnt_special = buf;
	if (getmntany(mntfp, &mp, &mpref) != 0) {
		char cmd[128];

		/* not mounted, try remount */
		(void) mkdir(TMP_MNTPT, S_IRWXU);
		(void) snprintf(cmd, sizeof (cmd), "mount -F pcfs %s %s",
		    buf, TMP_MNTPT);
		(void) system(cmd);
		rewind(mntfp);
		bzero(&mp, sizeof (mp));
		if (getmntany(mntfp, &mp, &mpref) != 0) {
			(void) fprintf(stderr, MOUNT_FAIL, buf);
			exit(-1);
		}
	}

	(void) snprintf(buf, sizeof (buf),
	    "%s/boot", mp.mnt_mountp);
	(void) mkdir(buf, S_IRWXU);
	(void) strcat(buf, "/grub");
	(void) mkdir(buf, S_IRWXU);

	(void) strcat(buf, "/stage2");
	pcfs_fp = open(buf, O_WRONLY | O_CREAT, S_IRWXU);
	if (pcfs_fp == -1) {
		(void) fprintf(stderr, OPEN_FAIL_FILE, buf);
		perror("open:");
		(void) umount(TMP_MNTPT);
		exit(-1);
	}

	/* write stage2 to pcfs */
	for (i = 0; ; i++) {
		int nread, nwrite;
		nread = pread(stage2_fd, buf, SECTOR_SIZE, i * SECTOR_SIZE);
		if (nowrite)
			nwrite = nread;
		else
			nwrite = pwrite(pcfs_fp, buf, nread, i * SECTOR_SIZE);
		if (nread < 0 || nwrite != nread) {
			(void) fprintf(stderr, WRITE_FAIL_STAGE2_BLOCKS,
			    nread, nwrite);
			break;
		}
		if (nread < SECTOR_SIZE)
			break;	/* end of file */
	}
	(void) close(pcfs_fp);
	(void) umount(TMP_MNTPT);

	/*
	 * Now, get the blocklist from the device.
	 */
	bzero(blocklist, sizeof (blocklist));
	if (read_stage2_blocklist(dev_fd, blocklist) != 0)
		exit(-1);
}
