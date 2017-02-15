/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	convert device to linename (as in /dev/linename)
 *	return ptr to LSZ-byte string, "?" if not found
 *	device must be character device
 *	maintains small list in tlist structure for speed
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include "acctdef.h"
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>

static int tsize1;
static struct tlist {
	char	tname[LSZ];	/* linename */
	dev_t	tdev;		/* device */
} tl[TSIZE1];

char	*strncpy();
dev_t	lintodev();

static char dev_dir[] = "/dev";
static char *def_srch_dirs[] = {
	"/dev/term",
	"/dev/pts",
	"/dev/xt",
	NULL
};
char file_name[MAX_DEV_PATH];	/* name being returned */

static int srch_dir();

char *
devtolin(dev_t device)
{
	struct tlist *tp;
	char **srch_dirs;	/* priority directories to search first */
	int found = 0;
	int dirno = 0;

	for (tp = tl; tp < &tl[tsize1]; tp++)
		if (device == tp->tdev)
			return (tp->tname);

	srch_dirs = def_srch_dirs;

	while ((!found) && (srch_dirs[dirno] != NULL)) {
		/*
		 * if /dev is one of the priority directories we should only
		 * search its top level for now (set depth = MAX_SEARCH_DEPTH)
		 */

		found = srch_dir(device, srch_dirs[dirno],
		    ((strcmp(srch_dirs[dirno], dev_dir) == 0) ?
		    MAX_SRCH_DEPTH : 1), NULL);
		dirno++;
	}

	/*
	 * if not yet found search remaining /dev directory skipping the
	 * priority directories
	 */

	if (!found)
		found = srch_dir(device, dev_dir, 0, srch_dirs);

	/*
	 * if found then put it (without the "/dev/" prefix) in the tlist
	 * structure and return the path name without the "/dev/" prefix
	 */

	if (found) {
		if (tsize1 < TSIZE1) {
			tp->tdev = device;
			CPYN(tp->tname, file_name+5);
			tsize1++;
		}
		return (file_name+5);
	} else {
		/*
		 * if not found put "?" in the tlist structure for that device
		 * and return "?"
		 */

		if (tsize1 < TSIZE1) {
			tp->tdev = device;
			CPYN(tp->tname, "?");
			tsize1++;
		}
	}
	return ("?");
}

/*
 * Arguments:
 *	device		device we are looking for
 *	path		current path
 *	depth		current depth
 *	skip_dirs	directories that don't need searched
 */
static int
srch_dir(dev_t device, char *path, int depth, char *skip_dirs[])
{
	DIR *fdev;
	struct dirent *d;
	int dirno = 0;
	int found = 0;
	int path_len;
	char *last_comp;
	struct stat sb;

	/* do we need to search this directory? */

	if ((skip_dirs != NULL) && (depth != 0))
		while (skip_dirs[dirno] != NULL)
			if (strcmp(skip_dirs[dirno++], path) == 0)
				return (0);


	/* open the directory */

	if ((fdev = opendir(path)) == NULL)
		return (0);

	/* initialize file name using path name */

	path_len = strlen(path);
	strcpy(file_name, path);
	last_comp = file_name + path_len;
	*last_comp++ = '/';

	/* start searching this directory */

	while ((!found) && ((d = readdir(fdev)) != NULL)) {
		if (d->d_ino != 0) {

			/*
			 * if name would not be too long append it to
			 * directory name, otherwise skip this entry
			 */

			if ((int)(path_len + strlen(d->d_name) + 2) >
			    MAX_DEV_PATH)
				continue;
			else
				strcpy(last_comp, d->d_name);

			/*
			 * if this directory entry has the device number we
			 * need, then the name is found. Otherwise if it's a
			 * directory (not . or ..) and we haven't gone too
			 * deep, recurse.
			 */

			if (lintodev(file_name+5) == device) {
				found = 1;
				break;
			} else if ((depth < MAX_SRCH_DEPTH) &&
			    (strcmp(d->d_name, ".") != 0) &&
			    (strcmp(d->d_name, "..") != 0) &&
			    (stat(file_name, &sb) != -1) &&
			    ((sb.st_mode & S_IFMT) == S_IFDIR)) {
				found = srch_dir(device, file_name, depth+1,
				    skip_dirs);
			}
		}
	}
	closedir(fdev);
	return (found);
}
