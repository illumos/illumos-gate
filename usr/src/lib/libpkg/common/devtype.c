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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "pkgdev.h"
#include "pkglib.h"

extern char	*devattr(char *device, char *attribute);	/* libadm.a */

int
devtype(char *alias, struct pkgdev *devp)
{
	char *name;
	devp->mntflg = 0;
	devp->name = alias;
	devp->dirname = devp->pathname = devp->mount = NULL;
	devp->fstyp = devp->cdevice = devp->bdevice = devp->norewind = NULL;
	devp->rdonly = 0;
	devp->capacity = 0;

	/* see if alias represents an existing file */
	if (alias[0] == '/') {
		if (!isdir(alias)) {
			devp->dirname = devp->name;
			return (0);
		}
	}

	/* see if alias represents a mountable device (e.g., a floppy) */
	if ((devp->mount = devattr(alias, "mountpt")) != NULL &&
	    devp->mount[0] != '\0') {
		devp->bdevice = devattr(alias, "bdevice");
		if (!devp->bdevice || !devp->bdevice[0]) {
			if (devp->bdevice) {
				free(devp->bdevice);
				devp->bdevice = NULL;
			}
			return (-1);
		}
		devp->dirname = devp->mount;
	} else if (devp->mount) {
		free(devp->mount);
		devp->mount = NULL;
	}

	devp->cdevice = devattr(alias, "cdevice");
	if (devp->cdevice && devp->cdevice[0])  {
		/* check for capacity */
		if (name = devattr(alias, "capacity")) {
			if (name[0])
				devp->capacity = atoll(name);
			free(name);
		}
		/* check for norewind device */
		devp->norewind = devattr(alias, "norewind");
		if (devp->norewind && !devp->norewind[0]) {
			free(devp->norewind);
			devp->norewind = NULL;
		}

		/* mountable devices will always have associated raw device */
		return (0);
	}
	if (devp->cdevice) {
		free(devp->cdevice);
		devp->cdevice = NULL;
	}
	/*
	 * if it is not a raw device, it must be a directory or a regular file
	 */
	name = devattr(alias, "pathname");
	if (!name || !name[0]) {
		/* Assume a regular file */
		if (name)
			free(name);
		devp->pathname = alias;
		return (0);
	}
	if (!isdir(name))
		devp->dirname = name;
	else
		devp->pathname = name;
	return (0);
}
