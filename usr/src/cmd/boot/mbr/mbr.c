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
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/dktp/fdisk.h>

#define	SECTOR_SIZE	512
static char boot_sect[SECTOR_SIZE];
static char new_mboot[SECTOR_SIZE];

static void
usage(char *progname)
{
	fprintf(stderr, "Usage: %s [ -d | -n | -o | -r ] <device> [<mboot>]\n",
	    basename(progname));
	fprintf(stderr, "\t-n Set new Solaris partition magic 0xbf\n");
	fprintf(stderr, "\t-o Set old Solaris partition magic 0x82\n");
	fprintf(stderr, "\t-r Replace master boot program "
	    "(/usr/lib/fs/ufs/mboot)\n");
	exit(-1);
}

int
main(int argc, char *argv[])
{
	int c, fd, i, sol_part = -1;
	int setold = 0, setnew = 0, write_mboot = 0, list_hd = 0;
	char *device;
	struct mboot *mboot;
	char *mboot_file = "/usr/lib/fs/ufs/mboot";

	while ((c = getopt(argc, argv, "dnor")) != EOF) {
		switch (c) {
		case 'd':
			list_hd = 1;
			continue;
		case 'n':
			setnew = 1;
			continue;
		case 'o':
			setold = 1;
			continue;
		case 'r':
			write_mboot = 1;
			continue;
		default:
			usage(argv[0]);
		}
	}

	/* check arguments */
	if ((setnew && setold) || argc < optind + 1) {
		usage(argv[0]);
	}

	if (write_mboot && argc > optind + 1) {
		mboot_file = strdup(argv[optind + 1]);
	}
	if (!mboot_file) {
		usage(argv[0]);
	}
	fd = open(mboot_file, O_RDONLY);
	if (fd == -1 || read(fd, new_mboot, SECTOR_SIZE) != SECTOR_SIZE) {
		fprintf(stderr, "cannot read file %s\n", mboot_file);
		if (fd == -1)
			perror("open");
		else
			perror("read");
		exit(-1);
	}
	close(fd);

	device = strdup(argv[optind]);
	if (!device) {
		usage(argv[0]);
	}
	fd = open(device, O_RDWR);
	if (fd == -1 || read(fd, boot_sect, SECTOR_SIZE) != SECTOR_SIZE) {
		fprintf(stderr, "cannot read MBR on %s\n", device);
		if (fd == -1)
			perror("open");
		else
			perror("read");
		exit(-1);
	}

	mboot = (struct mboot *)boot_sect;
	for (i = 0; i < FD_NUMPART; i++) {
		struct ipart *part = (struct ipart *)mboot->parts + i;
		if (!list_hd) {
			if (part->bootid == 128)
				printf("active ");
			else
				printf("       ");
		}
		if (setnew && part->systid == 0x82) {
			part->systid = 0xbf;
			sol_part = i;
		} else if (setold && part->systid == 0xbf) {
			part->systid = 0x82;
			sol_part = i;
		} else if (list_hd &&
		    (part->systid == 0x82 || part->systid == 0xbf)) {
			sol_part = i;
		}
		if (!list_hd)
			printf("%d (0x%2x): start_sect %u, size_sect %u\n",
			    i + 1, part->systid, part->relsect, part->numsect);
	}

	if (list_hd) {
		printf("(hd0,%d,a)\n", sol_part);
		(void) close(fd);
		return (0);
	}

	/* write new mboot */
	if (write_mboot || sol_part != -1) {
		if (write_mboot) {
			/* copy over the new boot program */
			bcopy((void *)new_mboot, (void *)boot_sect, BOOTSZ);
		}

		if ((lseek(fd, 0, SEEK_SET) < 0) ||
		    (write(fd, (void *)boot_sect, SECTOR_SIZE) < 0)) {
			perror("failed to update MBR");
			exit(-1);
		}
		if (sol_part != -1) {
			printf("Changed solaris partition %d", sol_part + 1);
			if (setnew)
				printf("from 0x82 to 0xbf\n");
			else
				printf("from 0xbf to 0x82\n");
		}
		if (write_mboot) {
			printf("Replaced mboot program with %s\n", mboot_file);
		}
	}

	(void) close(fd);
	return (0);
}
