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
 */


#include <stdio.h>
#include <time.h>
#include <wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <ulimit.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <libintl.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <pkgdev.h>
#include <pkglocs.h>
#include <pwd.h>
#include <pkglib.h>
#include <libinst.h>
#include <libadm.h>
#include <messages.h>

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * open package datastream
 * Arguments:	a_argc - (int) - [RO, *RO]
 *			- number of arguments available in a_argv
 *		a_argv - (char **) - [RO, *RO]
 *			- arguments representing package names to add
 *		a_spoolDir - (char *) - [RO, *RO]
 *			- directory to write the package (spool) into
 *			- if == (char *)NULL then install the packages
 *			- if != (char *)NULL then write packages into directory
 *		a_device - (char *) - [RO, *RO]
 *			- device to read packages from when spooling
 *			- ignored if a_spoolDir == (char *)NULL
 *		r_repeat - (int *) - [RO, *RW]
 *			- set == 0 if no further package names in argc/argv
 *			- set != 0 IF there are package names in argc/argv
 *			- if == (int *)NULL - not set
 *		r_idsName - (char **) - [RW, *RW]
 *			- set to the name of package input data stream device
 *			- if == (char *)NULL - no input data stream; that is,
 *			-- the packages are in a directory and not in a stream
 *			- if != (char *)NULL - this is the device/file that
 *			-- is the datastream that contains the packages to add
 *		a_pkgdev - (struct pkgdev *) - [RO, *RW]
 *			- pkgdev structure containing package device to open
 * Returns:	B_TRUE - datastream opened successfully
 *		B_FALSE - datastream failed to open
 */

boolean_t
open_package_datastream(int a_argc, char **a_argv, char *a_spoolDir,
	char *a_device, int *r_repeat, char **r_idsName, char *a_tmpdir,
	struct pkgdev *a_pkgdev, int a_optind)
{
	int	n;

	/* entry assertions */

	assert(a_argv != (char **)NULL);
	assert(r_idsName != (char **)NULL);
	assert(a_tmpdir != (char *)NULL);
	assert(a_pkgdev != (struct pkgdev *)NULL);

	/* entry debug information */

	echoDebug(DBG_ODS_ENTRY);
	echoDebug(DBG_ODS_ARGS,
			a_pkgdev->bdevice ? a_pkgdev->bdevice : "?",
			a_pkgdev->cdevice ? a_pkgdev->cdevice : "?",
			a_pkgdev->pathname ? a_pkgdev->pathname : "?",
			a_argc, a_device ? a_device : "?");

	/* reset possible return values to defaults */

	*r_idsName = (char *)NULL;
	if (r_repeat != (int *)NULL) {
		*r_repeat = 0;
	}

	/*
	 * Determine how to access the package source "device":
	 * - if a block device is associated with the source:
	 * -- make sure the next "volume" is mounted and ready.
	 * -- input data stream is associated character device
	 * - if char device but no block device associated with device:
	 * -- input data stream is associated character device
	 * - else if a path is associated with device:
	 * -- input data stream is associated path
	 */

	if (a_pkgdev->bdevice != (char *)NULL) {
		/* package source is block device */

		/*
		 * _getvol verifies that the specified device is accessible and
		 * that a volume of the appropriate medium has been inserted.
		 * _getvol is in libadm.h - delivered by ON as part of SUNWcsl
		 * is somewhat analagous to getvol(8) - args are:
		 *  - char *device
		 *  - char *label
		 *  - int options
		 *  - char *prompt
		 *  - char *norewind - no rewind device (NULL to use device)
		 * Returns:
		 *	0 - okay, label matches
		 *	1 - device not accessable
		 *	2 - unknown device (devattr failed)
		 *	3 - user selected quit
		 *	4 - label does not match
		 */

		echoDebug(DBG_ODS_DATASTREAM_BDEV, a_pkgdev->bdevice);

		n = _getvol(a_pkgdev->bdevice, NULL, 0L,
				MSG_INSERT_VOL, a_pkgdev->norewind);

		switch (n) {
		case 0:	/* volume open, label matches */
			if (ds_readbuf(a_pkgdev->cdevice)) {
				(*r_idsName) = a_pkgdev->cdevice;
			}
			break;
		case 3:	/* user selected quit */
			quit(3);
			/* NOTREACHED */
		case 2:	/* unknown device (devattr failed) */
			progerr(ERR_UNKNOWN_DEV, a_pkgdev->name);
			quit(99);
			/* NOTREACHED */
		default:	/* device not accessable */
			progerr(ERR_PKGVOL);
			logerr(LOG_GETVOL_RET, n);
			quit(99);
			/* NOTREACHED */
		}
	} else if (a_pkgdev->cdevice != (char *)NULL) {
		/* package source is character device */

		echoDebug(DBG_ODS_DATASTREAM_CDEV, a_pkgdev->cdevice);

		(*r_idsName) = a_pkgdev->cdevice;
	} else if (a_pkgdev->pathname != (char *)NULL) {
		/* package source is path name to file */

		echoDebug(DBG_ODS_DATASTREAM_ISFILE, a_pkgdev->pathname);

		(*r_idsName) = a_pkgdev->pathname;
	} else {
		echoDebug(DBG_ODS_DATASTREAM_UNK);
	}

	/*
	 * If writing the packages into a spool directory instead of
	 * installing the packages, invoke pkgtrans to perform the
	 * conversion and exit.
	 */

	if (a_spoolDir) {
		return (B_TRUE);
	}

	/* create temp dir for op if input data stream specified */

	if (*r_idsName) {
		/*
		 * initialize datastream,
		 * dirname is set to directory where package is unstreamed
		 */
		if (setup_temporary_directory(&a_pkgdev->dirname, a_tmpdir,
			"dstream") == B_FALSE) {
			progerr(ERR_STREAMDIR, strerror(errno));
			quit(99);
			/* NOTREACHED */
		}
	}

	if (r_repeat != (int *)NULL) {
		*r_repeat = (a_optind >= a_argc);
	}

	/*
	 * mount source device (e.g. floppy) if no input data stream
	 * specified, and the package source device is mountable. If
	 * the pkgmount fails, go back and try to mount the package
	 * source again. When a package is split up into multiple
	 * volumes (such as floppies), it might be possible to go back
	 * and insert a different copy of the required volume/floppy
	 * if the current one cannot be mounted. Otherwise this could
	 * have just called quit() if the mount failed...
	 */

	if (((*r_idsName) == (char *)NULL) && a_pkgdev->mount) {
		echoDebug(DBG_ODS_DATASTREAM_MOUNTING, *r_idsName,
							a_pkgdev->mount);
		a_pkgdev->rdonly++;
		n = pkgmount(a_pkgdev, NULL, 0, 0, 0);
		if (n != 0) {
			/* pkgmount failed */
			return (B_FALSE);
		}
	}

	/*
	 * open and initialize input data stream if specified
	 */

	if ((*r_idsName) != (char *)NULL) {
		echoDebug(DBG_ODS_DATASTREAM_INIT, *r_idsName);

		/* use character device to force rewind of datastream */
		if ((a_pkgdev->cdevice != (char *)NULL) &&
			(a_pkgdev->bdevice == (char *)NULL)) {
			n = _getvol(a_pkgdev->name, NULL, 0L, NULL,
					a_pkgdev->norewind);

			switch (n) {
			case 0:	/* volume open, label matches */
				break;
			case 3:	/* user selected quit */
				quit(3);
				/* NOTREACHED */
			case 2:	/* unknown device (devattr failed) */
				progerr(ERR_UNKNOWN_DEV, a_pkgdev->name);
				quit(99);
				/* NOTREACHED */
			default:
				progerr(ERR_PKGVOL);
				logerr(LOG_GETVOL_RET, n);
				quit(99);
				/* NOTREACHED */
			}
		}

		if (chdir(a_pkgdev->dirname)) {
			progerr(ERR_CHDIR, a_pkgdev->dirname);
			quit(99);
			/* NOTREACHED */
		}

		/*
		 * initialize datastream for subsequent installation;
		 * read the source device;
		 * aquire the header data and check it for validity;
		 * creates subdirectories in package stream directory
		 * (a_pkgdev->dirname) for each package and retrieves each
		 * packages pkginfo and pkgmap files
		 */

		if (ds_init(*r_idsName, &a_argv[a_optind],
						a_pkgdev->norewind)) {
			progerr(ERR_DSINIT, *r_idsName);
			quit(99);
			/* NOTREACHED */
		}
	}

	return (B_TRUE);
}
