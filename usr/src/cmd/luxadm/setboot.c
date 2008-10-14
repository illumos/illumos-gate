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

/*
 * I18N message number ranges
 *  This file: 6000 - 6499
 *  Shared common messages: 1 - 1999
 */



#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/mnttab.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/openpromio.h>


/*
 * For i18n
 */
#include <stgcom.h>


/*
 * 128 is the size of the largest (currently) property name
 * 8192 - MAXPROPSIZE - sizeof (int) is the size of the largest
 * (currently) property value, viz. nvramrc.
 * the sizeof(uint_t) is from struct openpromio
 */
#define	MAXPROPSIZE		128
#define	MAXVALSIZE		(8192 - MAXPROPSIZE - sizeof (uint_t))

#define	BOOTDEV_PROP_NAME	"boot-device"

static int getbootdevname(char *, char *);
static int setprom(unsigned, unsigned, char *);
extern int devfs_dev_to_prom_name(char *, char *);

/*
 * Call getbootdevname() to get the absolute pathname of boot device
 * and call setprom() to set the boot-device variable.
 */
int
setboot(unsigned int yes, unsigned int verbose, char *fname)
{
	char	bdev[MAXPATHLEN];

	if (!getbootdevname(fname, bdev)) {
		(void) fprintf(stderr, MSGSTR(6000,
			"Cannot determine device name for %s\n"),
			fname);
		return (errno);
	}

	return (setprom(yes, verbose, bdev));
}

/*
 * Read the mnttab and resolve the special device of the fs we are
 * interested in, into an absolute pathname
 */
static int
getbootdevname(char *bootfs, char *bdev)
{
	FILE *f;
	char *fname;
	char *devname;
	struct mnttab m;
	struct stat sbuf;
	int mountpt = 0;
	int found = 0;

	devname = bootfs;

	if (stat(bootfs, &sbuf) < 0) {
		perror(MSGSTR(6001, "stat"));
		return (0);
	}

	switch (sbuf.st_mode & S_IFMT) {
		case S_IFBLK:
			break;
		default:
			mountpt = 1;
			break;
	}

	if (mountpt) {
		fname = MNTTAB;
		f = fopen(fname, "r");
		if (f == NULL) {
			perror(fname);
			return (0);
		}

		while (getmntent(f, &m) == 0) {
			if (strcmp(m.mnt_mountp, bootfs))
				continue;
			else {
				found = 1;
				break;
			}
		}

		(void) fclose(f);

		if (!found) {
			return (0);
		}
		devname = m.mnt_special;
	}

	if (devfs_dev_to_prom_name(devname, bdev) != 0) {
		perror(devname);
		return (0);
	}

	return (1);
}

/*
 * setprom() - use /dev/openprom to read the "boot_device" variable and set
 * it to the new value.
 */
static int
setprom(unsigned yes, unsigned verbose, char *bdev)
{
	struct openpromio	*pio;
	int			fd;
	char			save_bootdev[MAXVALSIZE];

	if ((fd = open("/dev/openprom", O_RDWR)) < 0) {
		perror(MSGSTR(6002, "Could not open openprom dev"));
		return (errno);
	}

	pio = (struct openpromio *)malloc(sizeof (struct openpromio) +
					MAXVALSIZE + MAXPROPSIZE);

	if (pio == (struct openpromio *)NULL) {
		perror(MSGSTR(6003, " Error: Unable to allocate memory."));
		return (errno);
	}

	pio->oprom_size = MAXVALSIZE;
	(void) strcpy(pio->oprom_array, BOOTDEV_PROP_NAME);

	if (ioctl(fd, OPROMGETOPT, pio) < 0) {
		perror(MSGSTR(6004, "openprom getopt ioctl"));
		return (errno);
	}

	/*
	 * save the existing boot-device, so we can use it if setting
	 * to new value fails.
	 */
	(void) strcpy(save_bootdev, pio->oprom_array);

	if (verbose) {
		(void) fprintf(stdout,
			MSGSTR(6005,
			"Current boot-device = %s\n"), pio->oprom_array);
		(void) fprintf(stdout, MSGSTR(6006,
			"New boot-device = %s\n"), bdev);
	}

	if (!yes) {
		(void) fprintf(stdout, MSGSTR(6007,
			"Do you want to change boot-device "
			"to the new setting? (y/n) "));
		switch (getchar()) {
			case 'Y':
			case 'y':
				break;
			default:
				return (0);
		}
	}

	/* set the new value for boot-device */

	pio->oprom_size = (int)strlen(BOOTDEV_PROP_NAME) + 1 +
				(int)strlen(bdev);

	(void) strcpy(pio->oprom_array, BOOTDEV_PROP_NAME);
	(void) strcpy(pio->oprom_array + (int)strlen(BOOTDEV_PROP_NAME) + 1,
					bdev);

	if (ioctl(fd, OPROMSETOPT, pio) < 0) {
		perror(MSGSTR(6008, "openprom setopt ioctl"));
		return (errno);
	}

	/* read back the value that was set */

	pio->oprom_size = MAXVALSIZE;
	(void) strcpy(pio->oprom_array, BOOTDEV_PROP_NAME);

	if (ioctl(fd, OPROMGETOPT, pio) < 0) {
		perror(MSGSTR(6009, "openprom getopt ioctl"));
		return (errno);
	}

	if (strcmp(bdev, pio->oprom_array)) {

		/* could not  set the new device name, set the old one back */

		perror(MSGSTR(6010,
			"Could not set boot-device, reverting to old value"));
		pio->oprom_size = (int)strlen(BOOTDEV_PROP_NAME) + 1 +
			(int)strlen(save_bootdev);

		(void) strcpy(pio->oprom_array, BOOTDEV_PROP_NAME);
			(void) strcpy(pio->oprom_array +
				(int)strlen(BOOTDEV_PROP_NAME) + 1,
				save_bootdev);

		if (ioctl(fd, OPROMSETOPT, pio) < 0) {
			perror(MSGSTR(6011, "openprom setopt ioctl"));
			return (errno);
		}

	}

	(void) close(fd);

	return (0);
}
