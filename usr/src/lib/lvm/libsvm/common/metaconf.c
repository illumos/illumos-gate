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

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <libsvm.h>
#include <svm.h>
#include <errno.h>


#define	VERSION "1.0"
#define	DISK_DIR "/dev/rdsk"

extern int _map_to_effective_dev();

static int is_blank(char *);

/*
 * is_blank() returns 1 (true) if a line specified is composed of
 * whitespace characters only. otherwise, it returns 0 (false).
 *
 * Note. the argument (line) must be null-terminated.
 */
static int
is_blank(char *line)
{
	for (/* nothing */; *line != '\0'; line++)
		if (!isspace(*line))
			return (0);
	return (1);
}

/*
 * FUNCTION: write_targ_nm_table
 *	creates a tuple table of <driver name, major number > in md.conf
 * INPUT: rootpath
 *
 * RETURN VALUES:
 *	RET_SUCCESS
 *	RET_ERROR
 */

int
write_targ_nm_table(char *path)
{
	FILE	*targfp = NULL;
	FILE	*mdfp = NULL;
	char	buf[PATH_MAX], *cp;
	int	retval = RET_SUCCESS;
	int	first_entry = 1;

	if ((mdfp = fopen(MD_CONF, "a")) == NULL)
		return (RET_ERROR);

	(void) snprintf(buf, sizeof (buf), "%s%s", path, NAME_TO_MAJOR);

	if ((targfp = fopen(buf, "r")) == NULL) {
		(void) fclose(mdfp);
		return (RET_ERROR);
	}

	while (fgets(buf, PATH_MAX, targfp) != NULL &&
	    (retval == RET_SUCCESS)) {
		/* remove a new-line character for md_targ_nm_table */
		if ((cp = strchr(buf, '\n')) != NULL)
			*cp = 0;
		/* cut off comments starting with '#' */
		if ((cp = strchr(buf, '#')) != NULL)
			*cp = 0;
		/* ignore comment or blank lines */
		if (is_blank(buf))
			continue;
		if (first_entry) {
			if (fprintf(mdfp, "md_targ_nm_table=\"%s\"", buf) < 0)
				retval = RET_ERROR;
			first_entry = 0;
		} else {
			if (fprintf(mdfp, ",\"%s\"", buf) < 0)
					retval = RET_ERROR;
		}
	}
	if (!first_entry)
		if (fprintf(mdfp, ";\n") < 0)
			retval = RET_ERROR;
	(void) fclose(mdfp);
	(void) fclose(targfp);
	return (retval);
}

/*
 * FUNCTION: write_xlate_to_mdconf
 *	creates a tuple table of <miniroot devt, target devt> in md.conf
 * INPUT: rootpath
 *
 * RETURN VALUES:
 *	RET_SUCCESS
 *	RET_ERROR
 */

int
write_xlate_to_mdconf(char *path)
{
	FILE		*fptr = NULL;
	struct dirent	*dp;
	DIR		*dirp;
	struct stat	statb_dev;
	struct stat	statb_edev;
	char		*devname;
	char		edevname[PATH_MAX];
	char		targname[PATH_MAX];
	char		diskdir[PATH_MAX];
	char		linkpath[PATH_MAX];
	int		first_devid = 1;
	int		ret = RET_SUCCESS;

	if ((fptr = fopen(MD_CONF, "a")) == NULL) {
		return (RET_ERROR);
	}


	(void) snprintf(diskdir, sizeof (diskdir), "%s%s", path, DISK_DIR);
	if ((dirp = opendir(diskdir)) == NULL) {
		(void) fclose(fptr);
		return (RET_ERROR);
	}

	/* special case to write the first tuple in the table */
	while (((dp = readdir(dirp)) != (struct dirent *)0) &&
	    (ret != RET_ERROR)) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;

		if ((strlen(diskdir) + strlen(dp->d_name) + 2) > PATH_MAX) {
			continue;
		}

		(void) snprintf(targname, sizeof (targname), "%s/%s",
		    diskdir, dp->d_name);

		/*
		 * stat /devices to see if it's a devfs based file system
		 * On Solaris 10 and up, the devfs has been built on the
		 * fly for the mini-root. We need to adjust the path
		 * accordingly.
		 * If it's not devfs, just use the targname as it is.
		 */

		if (stat("/devices", &statb_dev) != 0) {
			continue;
		}

		if (strncmp("devfs", statb_dev.st_fstype, 5) == 0) {
			if (readlink(targname, linkpath,
			    sizeof (linkpath)) == -1) {
				continue;
			}
			/*
			 * turn ../../devices/<path> into /devices/<path>
			 * and stat that into statb_dev
			 */
			if (stat(strstr(linkpath, "/devices"),
			    &statb_dev) != 0) {
				continue;
			}
		} else {
			if (stat(targname, &statb_dev) != 0) {
				continue;
			}
		}

		if ((devname = strstr(targname, DISK_DIR)) == NULL) {
			continue;
		}

		if (_map_to_effective_dev((char *)devname, (char *)&edevname)
		    != 0) {
			continue;
		}

		if (stat(edevname, &statb_edev) != 0) {
			continue;
		}

		if (first_devid) {
			if (fprintf(fptr, "md_xlate_ver=\"%s\";\n"
			    "md_xlate=%lu,%lu", VERSION,
			    statb_edev.st_rdev, statb_dev.st_rdev) < 0)
				ret = RET_ERROR;
			first_devid = 0;
		}
		if (fprintf(fptr, ",%lu,%lu", statb_edev.st_rdev,
		    statb_dev.st_rdev) < 0)
			ret = RET_ERROR;
	} /* end while */

	if (!first_devid)
		if (fprintf(fptr, ";\n") < 0)
			ret = RET_ERROR;
	(void) fclose(fptr);
	(void) closedir(dirp);
	return (ret);
}
