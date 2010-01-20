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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <tsol/label.h>
#include <zone.h>
#include <sys/stat.h>

#include "setupfiles.h"

#define	dperror(s) if (flags & DIAG) perror(s)
#define	dprintf(s, v) if (flags & DBUG) (void) printf(s, v)
#define	dprintf2(s, v1, v2) if (flags & DBUG) (void) printf(s, v1, v2)

static int mkdirs(const char *dir, const char *target, int flags);
static int copyfile(const char *min_home, const char *home, const char *target,
    int flags);
static int linkfile(const char *min_home, const char *home, const char *target,
    int flags);


/*
 *	__setupfiles - Process copy and link files directions in min $HOME.
 *
 *	Entry	pwd = user's password file entry.
 *		min_sl = user's minimum SL.
 *		flags = DBUG, if print debug messages.
 *			DIAG, if print diagnostics (perrors).
 *			IGNE, continue rather than abort on failures.
 *			REPC, if replace existing file.
 *			REPL, if replace existing symbolic link.
 *		process is running as user at correct label.
 *
 *	Exit	None.
 *
 *	Returns	0, if success.
 *		errno, if failure.
 *
 *	Uses	COPY, CP, LINK, MAXPATHLEN.
 *
 *	Calls	blequal, copyfile, feof, fgets, fopen,
 *		mkdirs, getzoneid, getzonelabelbyid, linkfile, strcat, strcpy,
 *		strlen.
 *
 *	This program assumes the /zone is the autofs mountpoint for
 *	cross-zone mounts.
 *
 *	It also assumes that the user's home directory path is the
 *	the same in each zone, relative to the zone's root.
 *
 *	At this point, the cross-zone automounter only supports home
 * 	directories starting with /home
 */

int
__setupfiles(const struct passwd *pwd, const m_label_t *min_sl, int flags)
{
	m_label_t *plabel;		/* process label */
	char	home[MAXPATHLEN];	/* real path to current $HOME */
	char	min_home[MAXPATHLEN];	/* real path to min $HOME */
	char	cl_file[MAXPATHLEN];	/* real path to .copy/.link_files */
	char	file[MAXPATHLEN];	/* file to copy/link */
	FILE	*clf;			/* .copy/.link_file stream */
	char	zoneroot[MAXPATHLEN];
	zoneid_t zoneid;
	zoneid_t min_zoneid;

	zoneid = getzoneid();
	if ((plabel = getzonelabelbyid(zoneid)) == NULL) {

		dperror("setupfiles can't get process label");
		return (errno);
	}

	if (blequal(plabel, min_sl)) {
		/* at min SL no files to setup */

		return (0);
	}

	/* get current home real path */

	(void) strlcpy(home, pwd->pw_dir, MAXPATHLEN);

	/* Get zone id from min_sl */

	if ((min_zoneid = getzoneidbylabel(min_sl)) == -1) {

		dperror("setupfiles can't get zoneid for min sl");
		return (errno);
	}

	/*
	 * Since the global zone home directories aren't public
	 * information, we don't support copy and link files there.
	 */
	if (min_zoneid == GLOBAL_ZONEID)
		return (0);

	/*
	 * Get zone root path from zone id
	 *
	 * Could have used getzonenamebyid() but this assumes that /etc/zones
	 * directory is available, which is not true in labeled zones
	 */

	if (zone_getattr(min_zoneid, ZONE_ATTR_ROOT, zoneroot,
	    sizeof (zoneroot)) == -1) {
		dperror("setupfiles can't get zone root path for min sl");
		return (errno);
	}

	(void) snprintf(min_home, MAXPATHLEN, "%s%s",
	    zoneroot, pwd->pw_dir);

	/* process copy files */

	if ((strlen(min_home) + strlen(COPY)) > (MAXPATHLEN - 1)) {

		dprintf("setupfiles copy path %s", min_home);
		dprintf("%s ", COPY);
		dprintf("greater than %d\n", MAXPATHLEN);
		errno = ENAMETOOLONG;
		dperror("setupfiles copy path");
		return (errno);
	}

	(void) strcpy(cl_file, min_home);
	(void) strcat(cl_file, COPY);

	if ((clf = fopen(cl_file, "r")) != NULL) {

		while (fgets(file, MAXPATHLEN, clf) != NULL) {

			if (!feof(clf))		/* remove trailing \n */
				file[strlen(file) - 1] = '\0';

			dprintf("copy file %s requested\n", file);

			/* make any needed subdirectories */

			if (mkdirs(home, file, flags) != 0) {

				if ((flags & IGNE) == 0)
					return (errno);
				else
					continue;
			}

			/* copy the file */

			if (copyfile(min_home, home, file, flags) != 0) {

				if ((flags & IGNE) == 0)
					return (errno);
				else
					continue;

			}

		}  /* while (fgets( ... ) != NULL) */
	} else {
		if (errno != ENOENT)
			dperror("setupfiles copy file open");
		dprintf("setupfiles no copyfile %s\n", cl_file);
	}  /* process copy files */


	/* process link files */

	if ((strlen(min_home) + strlen(LINK)) > (MAXPATHLEN - 1)) {

		dprintf("setupfiles link path %s", min_home);
		dprintf("%s ", LINK);
		dprintf("greater than %d\n", MAXPATHLEN);
		errno = ENAMETOOLONG;
		dperror("setupfiles link path");
		return (errno);
	}

	(void) strcpy(cl_file, min_home);
	(void) strcat(cl_file, LINK);

	if ((clf = fopen(cl_file, "r")) != NULL) {

		while (fgets(file, MAXPATHLEN, clf) != NULL) {

			if (!feof(clf))		/* remove trailing \n */
				file[strlen(file) - 1] = '\0';

			dprintf("link file %s requested\n", file);

			/* make any needed subdirectories */

			if (mkdirs(home, file, flags) != 0) {

				if ((flags & IGNE) == 0)
					return (errno);
				else
					continue;
			}

			/* link the file */

			if (linkfile(min_home, home, file, flags) != 0) {

				if ((flags & IGNE) == 0)
					return (errno);
				else
					continue;
			}

		}  /* while (fgets ... ) != NULL) */
	} else {
		if (errno != ENOENT)
			dperror("setupfiles link file open");
		dprintf("setupfiles no linkfile %s\n", cl_file);
	}  /* process link files */

	return (0);
}  /* setupfiles() */


/*
 *	mkdirs - Make any needed subdirectories in target's path.
 *
 *	Entry	home = base directory.
 *		file = file to create with intermediate subdirectories.
 *		flags = from __setupfiles -- for dprintf and dperror.
 *
 *	Exit	Needed subdirectories made.
 *
 *	Returns	0, if success.
 *		errno, if failure.
 *
 *	Uses	MAXPATHLEN.
 *
 *	Calls	mkdir, strcat, strcpy, strlen, strtok.
 */

static int
mkdirs(const char *home, const char *file, int flags)
{
	char	path[MAXPATHLEN];
	char	dir[MAXPATHLEN];
	char	*tok;

	if ((strlen(home) + strlen(file)) > (MAXPATHLEN - 2)) {

		dprintf("setupfiles mkdirs path %s", home);
		dprintf("/%s ", file);
		dprintf("greater than %d\n", MAXPATHLEN);
		errno = ENAMETOOLONG;
		dperror("setupfiles mkdirs");
		return (errno);
	}

	(void) strcpy(dir, file);

	if ((tok = strrchr(dir, '/')) == NULL) {

		dprintf("setupfiles no dirs to make in %s\n", dir);
		return (0);
	}

	*tok = '\000';		/* drop last component, it's the target */

	(void) strcpy(path, home);

	for (tok = dir; tok = strtok(tok, "/"); tok = NULL) {

		(void) strcat(path, "/");
		(void) strcat(path, tok);

		if ((mkdir(path, 0777) != 0) && (errno != EEXIST)) {

			dperror("setupfiles mkdir");
			dprintf("setupfiles mkdir path %s\n", path);
			return (errno);
		}

		dprintf("setupfiles dir %s made or already exists\n", path);
	}

	return (0);
}  /* mkdirs() */


/*
 *	copyfile - Copy a file from the base home directory to the current.
 *
 *	Entry	min_home = from home directory.
 *		home = current (to) home directory.
 *		target = file to copy.
 *		flags = from __setupfiles.
 *			REPC, if replace existing file.
 *
 *	Exit	File copied.
 *
 *	Returns	0, if success.
 *		errno, if failure.
 *
 *	Uses	CP, MAXPATHLEN.
 *
 *	Calls	access, execlp, exit, lstat, strcat, strcpy, strlen, unlink,
 *		vfork, waitpid.
 */

static int
copyfile(const char *min_home, const char *home, const char *target, int flags)
{
	char	src[MAXPATHLEN];
	char	dest[MAXPATHLEN];
	struct stat	buf;
	pid_t	child;

	/* prepare target */

	if (snprintf(dest, sizeof (dest), "%s/%s", home, target) >
	    sizeof (dest) - 1) {
		dprintf("setupfiles copy dest %s", dest);
		dprintf("greater than %d\n", sizeof (dest));
		errno = ENAMETOOLONG;
		dperror("setupfiles copy to home");
		return (errno);
	}

	if (lstat(dest, &buf) == 0) {
		/* target exists */

		if (flags & REPC) {
			/* unlink and replace */

			if (unlink(dest) != 0) {

				dperror("setupfiles copy unlink");
				dprintf("setupfiles copy unable to unlink %s\n",
				    dest);
				return (errno);
			}
		} else {
			/* target exists and is not to be replaced */

			return (0);
		}
	} else if (errno != ENOENT) {
		/* error on target */

		dperror("setupfiles copy");
		dprintf("setupfiles copy lstat %s\n", dest);
		return (errno);
	}

	/* prepare source */

	if (snprintf(src, sizeof (src), "%s/%s", min_home, target) >
	    sizeof (src) - 1) {
		dprintf("setupfiles copy path %s", src);
		dprintf("greater than %d\n", sizeof (src));
		errno = ENAMETOOLONG;
		dperror("setupfiles copy from home");
		return (errno);
	}

	if (access(src, R_OK) != 0) {
		/* can't access source */

		dperror("setupfiles copy source access");
		dprintf("setupfiles copy unable to access %s\n", src);
		return (errno);
	}

	/* attempt the copy */

	dprintf("setupfiles attempting to copy %s\n", src);
	dprintf("\tto %s\n", dest);

	if ((child = vfork()) != 0) {	/* parent, wait for child status */
		int	status;	/* child status */

		(void) waitpid(child, &status, 0);  /* wait for child */
		dprintf("setupfiles copy child returned %x\n", status);
	} else {
		/* execute "cp -p min_home home" */

		if (execlp(CP, CP, "-p", src, dest, 0) != 0) {
			/* can't execute cp */

			dperror("setupfiles copy exec");
			dprintf("setupfiles copy couldn't exec \"%s  -p\"\n",
			    CP);
			exit(2);
		}
	}

	return (0);
}  /* copyfile() */


/*
 *	linkfile - Make a symlink from the the current directory to the base
 *			home directory.
 *
 *	Entry	min_home = from home directory.
 *		home = current (to) home directory.
 *		target = file to copy.
 *		flags = from __setupfiles.
 *			REPL, if replace existing symlink.
 *
 *	Exit	File symlinked.
 *
 *	Returns	0, if success.
 *		errno, if failure.
 *
 *	Uses	MAXPATHLEN.
 *
 *	Calls	lstat, symlink, strcat, strcpy, strlen, unlink.
 */

static int
linkfile(const char *min_home, const char *home, const char *target, int flags)
{
	char	src[MAXPATHLEN];
	char	dest[MAXPATHLEN];
	struct stat	buf;

	/* prepare target */

	if (snprintf(dest, sizeof (dest), "%s/%s", home, target) >
	    sizeof (dest) - 1) {
		dprintf("setupfiles link dest %s", dest);
		dprintf("greater than %d\n", sizeof (dest));
		errno = ENAMETOOLONG;
		dperror("setupfiles link to home");
		return (errno);
	}

	if (lstat(dest, &buf) == 0) {
		/* target exists */

		if (flags & REPL) {
			/* unlink and replace */
			if (unlink(dest) != 0) {
				dperror("setupfiles link unlink");
				dprintf("setupfiles link unable to unlink %s\n",
				    dest);
				return (errno);
			}
		} else {
			/* target exists and is not to be replaced */
			return (0);
		}
	} else if (errno != ENOENT) {
		/* error on target */
		dperror("setupfiles link");
		dprintf("setupfiles link lstat %s\n", dest);
		return (errno);
	}

	if (snprintf(src, sizeof (src), "%s/%s", min_home, target) >
	    sizeof (src) - 1) {
		dprintf("setupfiles link path %s", src);
		dprintf("greater than %d\n", sizeof (src));
		errno = ENAMETOOLONG;
		dperror("setupfiles link from home");
		return (errno);
	}

	/* attempt the copy */

	dprintf("setupfiles attempting to link %s\n", dest);
	dprintf("\tto %s\n", src);

	if (symlink(src, dest) != 0) {
		dperror("setupfiles link symlink");
		dprintf("setupfiles link unable to symlink%s\n", "");
		return (errno);
	}

	return (0);
}  /* linkfile */
