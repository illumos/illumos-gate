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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * lofiadm - administer lofi(7d). Very simple, add and remove file<->device
 * associations, and display status. All the ioctls are private between
 * lofi and lofiadm, and so are very simple - device information is
 * communicated via a minor number.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/lofi.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <libdevinfo.h>
#include "utils.h"

static const char USAGE[] =
	"Usage: %s -a file [ device ]\n"
	"       %s -d file | device \n"
	"       %s [ device | file ]\n";

static const char *pname;
static int	addflag = 0;
static int	deleteflag = 0;
static int	errflag = 0;

#define	FORMAT "%-20s     %s\n"

/*
 * Print the list of all the mappings. Including a header.
 */
static void
print_mappings(int fd)
{
	struct lofi_ioctl li;
	int	minor;
	int	maxminor;
	char	path[MAXPATHLEN + 1];

	li.li_minor = 0;
	if (ioctl(fd, LOFI_GET_MAXMINOR, &li) == -1) {
		perror("ioctl");
		exit(E_ERROR);
	}

	maxminor = li.li_minor;

	(void) printf(FORMAT, "Block Device", "File");
	for (minor = 1; minor <= maxminor; minor++) {
		li.li_minor = minor;
		if (ioctl(fd, LOFI_GET_FILENAME, &li) == -1) {
			if (errno == ENXIO)
				continue;
			perror("ioctl");
			break;
		}
		(void) snprintf(path, sizeof (path), "/dev/%s/%d",
		    LOFI_BLOCK_NAME, minor);
		(void) printf(FORMAT, path, li.li_filename);
	}
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(USAGE), pname, pname, pname);
	exit(E_USAGE);
}

/*
 * Translate a lofi device name to a minor number. We might be asked
 * to do this when there is no association (such as when the user specifies
 * a particular device), so we can only look at the string.
 */
static int
name_to_minor(const char *devicename)
{
	int	minor;

	if (sscanf(devicename, "/dev/" LOFI_BLOCK_NAME "/%d", &minor) == 1) {
		return (minor);
	}
	if (sscanf(devicename, "/dev/" LOFI_CHAR_NAME "/%d", &minor) == 1) {
		return (minor);
	}
	return (0);
}

/*
 * This might be the first time we've used this minor number. If so,
 * it might also be that the /dev links are in the process of being created
 * by devfsadmd (or that they'll be created "soon"). We cannot return
 * until they're there or the invoker of lofiadm might try to use them
 * and not find them. This can happen if a shell script is running on
 * an MP.
 */
static int sleeptime = 2;	/* number of seconds to sleep between stat's */
static int maxsleep = 120;	/* maximum number of seconds to sleep */

static void
wait_until_dev_complete(int minor)
{
	struct stat64 buf;
	int	cursleep;
	char	blkpath[MAXPATHLEN + 1];
	char	charpath[MAXPATHLEN + 1];
	di_devlink_handle_t hdl;


	(void) snprintf(blkpath, sizeof (blkpath), "/dev/%s/%d",
	    LOFI_BLOCK_NAME, minor);
	(void) snprintf(charpath, sizeof (charpath), "/dev/%s/%d",
	    LOFI_CHAR_NAME, minor);

	/* Check if links already present */
	if (stat64(blkpath, &buf) == 0 && stat64(charpath, &buf) == 0)
		return;

	/* First use di_devlink_init() */
	if (hdl = di_devlink_init("lofi", DI_MAKE_LINK)) {
		(void) di_devlink_fini(&hdl);
		goto out;
	}

	/*
	 * Under normal conditions, di_devlink_init(DI_MAKE_LINK) above will
	 * only fail if the caller is non-root. In that case, wait for
	 * link creation via sysevents.
	 */
	cursleep = 0;
	while (cursleep < maxsleep) {
		if ((stat64(blkpath, &buf) == -1) ||
		    (stat64(charpath, &buf) == -1)) {
			(void) sleep(sleeptime);
			cursleep += sleeptime;
			continue;
		}
		return;
	}

	/* one last try */

out:
	if (stat64(blkpath, &buf) == -1) {
		die(gettext("%s was not created"), blkpath);
	}
	if (stat64(charpath, &buf) == -1) {
		die(gettext("%s was not created"), charpath);
	}
}

/*
 * Add a device association. If devicename is NULL, let the driver
 * pick a device.
 */
static void
add_mapping(int lfd, const char *devicename, const char *filename)
{
	struct lofi_ioctl li;
	int	minor;

	if (devicename == NULL) {
		/* pick one */
		li.li_minor = 0;
		(void) strcpy(li.li_filename, filename);
		minor = ioctl(lfd, LOFI_MAP_FILE, &li);
		if (minor == -1) {
			die(gettext("could not map file %s"), filename);
		}
		wait_until_dev_complete(minor);
		/* print one picked */
		(void) printf("/dev/%s/%d\n", LOFI_BLOCK_NAME, minor);
		return;
	}
	/* use device we were given */
	minor = name_to_minor(devicename);
	if (minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	(void) strcpy(li.li_filename, filename);
	li.li_minor = minor;
	if (ioctl(lfd, LOFI_MAP_FILE_MINOR, &li) == -1) {
		die(gettext("could not map file %s to %s"), filename,
		    devicename);
	}
	wait_until_dev_complete(minor);
}

/*
 * Remove an association. Delete by device name if non-NULL, or by
 * filename otherwise.
 */
static void
delete_mapping(int lfd, const char *devicename, const char *filename)
{
	struct lofi_ioctl li;

	if (devicename == NULL) {
		/* delete by filename */
		(void) strcpy(li.li_filename, filename);
		li.li_minor = 0;
		if (ioctl(lfd, LOFI_UNMAP_FILE, &li) == -1) {
			die(gettext("could not unmap file %s"), filename);
		}
		return;
	}
	/* delete by device */

	li.li_minor = name_to_minor(devicename);
	if (li.li_minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	if (ioctl(lfd, LOFI_UNMAP_FILE_MINOR, &li) == -1) {
		die(gettext("could not unmap device %s"), devicename);
	}
}

static void
print_one_mapping(int lfd, const char *devicename, const char *filename)
{
	struct lofi_ioctl li;

	if (devicename == NULL) {
		/* given filename, print devicename */
		li.li_minor = 0;
		(void) strcpy(li.li_filename, filename);
		if (ioctl(lfd, LOFI_GET_MINOR, &li) == -1) {
			die(gettext("could not find device for %s"), filename);
		}
		(void) printf("/dev/%s/%d\n", LOFI_BLOCK_NAME, li.li_minor);
		return;
	}

	/* given devicename, print filename */
	li.li_minor = name_to_minor(devicename);
	if (li.li_minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	if (ioctl(lfd, LOFI_GET_FILENAME, &li) == -1) {
		die(gettext("could not find filename for %s"), devicename);
	}
	(void) printf("%s\n", li.li_filename);
}

int
main(int argc, char *argv[])
{
	int	lfd;
	int	c;
	int	error;
	struct stat64 buf;
	const char *devicename = NULL;
	const char *filename = NULL;
	int	openflag;
	int	minor;
	int	fd = -1;
	static char *lofictl = "/dev/" LOFI_CTL_NAME;

	pname = getpname(argv[0]);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "a:d:")) != EOF) {
		switch (c) {
		case 'a':
			addflag = 1;
			filename = optarg;
			fd = open64(filename, O_RDONLY);
			if (fd == -1) {
				die(gettext("open: %s"), filename);
			}
			error = fstat64(fd, &buf);
			if (error == -1) {
				die(gettext("fstat: %s"), filename);
			} else if (!S_ISLOFIABLE(buf.st_mode)) {
				die(gettext("%s is not a regular file, "
				    "block, or character device\n"),
				    filename);
			} else if ((buf.st_size % DEV_BSIZE) != 0) {
				die(gettext("size of %s is not a multiple "
				    "of %d\n"),
				    filename, DEV_BSIZE);
			}
			(void) close(fd);
			minor = name_to_minor(filename);
			if (minor != 0) {
				die(gettext("cannot use " LOFI_DRIVER_NAME
				    " on itself\n"), devicename);
			}
			if (((argc - optind) > 0) && (*argv[optind] != '-')) {
				/* optional device */
				devicename = argv[optind];
				optind++;
			}
			break;
		case 'd':
			deleteflag = 1;

			minor = name_to_minor(optarg);
			if (minor != 0)
				devicename = optarg;
			else
				filename = optarg;
			break;
		case '?':
		default:
			errflag = 1;
			break;
		}
	}
	if (errflag || (addflag && deleteflag))
		usage();

	switch (argc - optind) {
	case 0: /* no more args */
		break;
	case 1: /* one arg without options means print the association */
		if (addflag || deleteflag)
			usage();
		minor = name_to_minor(argv[optind]);
		if (minor != 0)
			devicename = argv[optind];
		else
			filename = argv[optind];
		break;
	default:
		usage();
		break;
	}

	if (filename && !valid_abspath(filename))
		exit(E_ERROR);

	/*
	 * Here, we know the arguments are correct, the filename is an
	 * absolute path, it exists and is a regular file. We don't yet
	 * know that the device name is ok or not.
	 */
	/*
	 * Now to the real work.
	 */
	openflag = O_EXCL;
	if (addflag || deleteflag)
		openflag |= O_RDWR;
	else
		openflag |= O_RDONLY;
	lfd = open(lofictl, openflag);
	if (lfd == -1) {
		if ((errno == EPERM) || (errno == EACCES)) {
			die("you do not have permission to perform "
			    "that operation.\n");
		} else {
			die("%s", lofictl);
		}
		/*NOTREACHED*/
	}
	if (addflag)
		add_mapping(lfd, devicename, filename);
	else if (deleteflag)
		delete_mapping(lfd, devicename, filename);
	else if (filename || devicename)
		print_one_mapping(lfd, devicename, filename);
	else
		print_mappings(lfd);
	(void) close(lfd);
	return (E_SUCCESS);
}
