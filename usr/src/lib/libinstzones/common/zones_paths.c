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



/*
 * System includes
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <assert.h>
#include <locale.h>
#include <libintl.h>

/*
 * local includes
 */

#include "instzones_lib.h"
#include "zones_strings.h"

#define	isdot(x)	((x[0] == '.') && (!x[1] || (x[1] == '/')))
#define	isdotdot(x)	((x[0] == '.') && (x[1] == '.') && \
		    (!x[2] || (x[2] == '/')))

/*
 * forward declarations
 */

static char		**inheritedFileSystems = (char **)NULL;
static size_t		*inheritedFileSystemsLen = (size_t *)NULL;
static int		numInheritedFileSystems = 0;

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	z_get_inherited_file_systems
 * Description:	Return list of file systems inherited from the global zone;
 *		These file systems are entered into the list when the function
 *		pkgAddInheritedFileSystem() is called.
 * Arguments:	void
 * Returns:	char **
 *			- pointer to array of character pointers, each pointer
 *			being a pointer to a string representing a file
 *			system that is inherited from the global zone
 *			the last entry will be (char *)NULL
 *			- (char **)NULL - no file systems inherited
 *
 */

char **
z_get_inherited_file_systems(void)
{
	return (inheritedFileSystems);
}

/*
 * Name:	z_add_inherited_file_system
 * Description:	Add specified package to internal list of inherited file systems
 * Arguments:	a_inheritedFileSystem - absolute path to file systen "inherited"
 *
 *		This function is called to register a directory (or
 *		file system) as being inherited from the global zone
 *		into the non-global zone being operated on.  The
 *		inherited directory must be specified relative to the
 *		root file system ("/").  For example, if "/usr" is
 *		inherited, then the path specified would be "/usr".
 *
 *		Any path subsequently checked for being present in a
 *		directory inherited read-only from the global zone:
 *
 *		-- will NOT have $PKG_INSTALL_ROOT prepended to it
 *		-- if $PKG_INSTALL_ROOT is set and $BASEDIR is not set.
 *		-- WILL have $BASEDIR prepended to it (if set).
 *		-- $BASEDIR always has $PKG_INSTALL_ROOT included in it.
 *		-- For example, if $PKG_INSTALL_ROOT is set to /a, and
 *		-- the base install directory is set to "/opt", then the
 *		-- $BASEDIR variable will be set to "/a/opt".
 *
 *		Any path that is checked for being present in an inherited
 *		directory will be specified relative to the root file system
 *		of the non-global zone in which the path is located.
 *
 *		When a path to update is checked for being present in
 *		an inherited directory, $PKG_INSTALL_ROOT is stripped
 *		off the path before it is checked.
 *
 *		If the non-global zone is not running, the scratch zone
 *		is used to access the non-global zone.  In this case,
 *		$PKG_INSTALL_ROOT will be set to "/a" and both the
 *		non-global zone's root file system and all inherited
 *		directories will be mounted on "/a". When a path is checked
 *		for being inherited, it will have $PKG_INSTALL_ROOT stripped
 *		from the beginning, so any inherited directories must be
 *		specified relative to "/" and not $PKG_INSTALL_ROOT.
 *
 *		If the non-global zone is running, the non-global zone
 *		is used directly. In this case, $PKG_INSTALL_ROOT will
 *		be set to "/" and both the non-global zone's root file
 *		system and all inherited directories will be mounted on
 *		"/". $PKG_INSTALL_ROOT is set to "/" so the path is unchanged
 *		before being checked against the list of inherited directories.
 *
 * Returns:	boolean_t
 *			B_TRUE - file system successfully added to list
 *			B_FALSE - failed to add file system to list
 */

boolean_t
z_add_inherited_file_system(char *a_inheritedFileSystem)
{
#define	IPSLOP	2		/* for trailing '/' and '\0' */
#define	IPMAX	((sizeof (rp))-IPSLOP)

	char	rp[PATH_MAX+1+IPSLOP] = {'\0'};
	int	n;

	/* file system cannot be empty */

	if (a_inheritedFileSystem == NULL || *a_inheritedFileSystem == '\0') {
		_z_program_error(ERR_INHERITED_PATH_NULL);
		return (B_FALSE);
	}

	/* file system must be absolute */

	if (*a_inheritedFileSystem != '/') {
		_z_program_error(ERR_INHERITED_PATH_NOT_ABSOLUTE,
		    a_inheritedFileSystem);
		return (B_FALSE);
	}

	/* make a local copy of the path and canonize it */

	n = strlcpy(rp, a_inheritedFileSystem, IPMAX);
	if (n > IPMAX) {
		_z_program_error(ERR_INHERITED_PATH_TOO_LONG,
		    strlen(a_inheritedFileSystem), IPMAX,
		    a_inheritedFileSystem);
		return (B_FALSE);
	}

	assert(n > 0);	/* path must have at least 1 byte in it */

	z_path_canonize(rp);	/* remove duplicate "/"s, ./, etc */

	/* add trailing "/" if it's not already there */
	n = strlen(rp);
	if (rp[n-1] != '/') {
		rp[n++] = '/';
	}

	/* null terminate the string */

	rp[n] = '\0';

	/* add file system to internal list */

	if (inheritedFileSystems == (char **)NULL) {
		inheritedFileSystems = (char **)_z_calloc(
		    2 * (sizeof (char **)));
		inheritedFileSystemsLen =
		    (size_t *)_z_calloc(2 * (sizeof (size_t *)));
	} else {
		inheritedFileSystems = (char **)_z_realloc(inheritedFileSystems,
		    sizeof (char **)*(numInheritedFileSystems+2));
		inheritedFileSystemsLen = (size_t *)_z_realloc(
		    inheritedFileSystemsLen,
		    sizeof (size_t *)*(numInheritedFileSystems+2));
	}

	/* add this entry to the end of the list */

	inheritedFileSystemsLen[numInheritedFileSystems] = strlen(rp);
	inheritedFileSystems[numInheritedFileSystems] = _z_strdup(rp);

	numInheritedFileSystems++;

	/* make sure end of the list is properly terminated */

	inheritedFileSystemsLen[numInheritedFileSystems] = 0;
	inheritedFileSystems[numInheritedFileSystems] = (char *)NULL;

	/* exit debugging info */

	_z_echoDebug(DBG_PATHS_ADD_FS, numInheritedFileSystems,
	    inheritedFileSystems[numInheritedFileSystems-1]);

	return (B_TRUE);
}

/*
 * Name:	z_path_is_inherited
 * Description:	Determine if the specified path is in a file system that is
 *		in the internal list of inherited file systems
 * Arguments:	a_path - pointer to string representing path to verify
 *		a_ftype - file "type" if known otherwise '\0'
 *			Type can be "f" (file), or "d" (directory)
 *		a_rootDir - pointer to string representing root directory where
 *			a_path is relative to - typically this would either be
 *			"/" or the path specified as an alternative root to -R
 * Returns:	boolean_t
 *			B_TRUE - the path is in inherited file system space
 *			B_FALSE - the path is NOT in inherited file system space
 */

boolean_t
z_path_is_inherited(char *a_path, char a_ftype, char *a_rootDir)
{
	int	n;
	char	*cp, *path2use;
	char	real_path[PATH_MAX];
	char	path_copy[PATH_MAX];
	boolean_t found = B_FALSE;

	/* entry assertions */

	assert(a_path != (char *)NULL);
	assert(*a_path != '\0');

	/* if no inherited file systems, there can be no match */

	if (numInheritedFileSystems == 0) {
		_z_echoDebug(DBG_PATHS_NOT_INHERITED, a_path);
		return (B_FALSE);
	}

	/* normalize root directory */

	if ((a_rootDir == (char *)NULL) || (*a_rootDir == '\0')) {
		a_rootDir = "/";
	}

	/*
	 * The loop below represents our best effort to identify real path of
	 * a file, which doesn't need to exist. realpath() returns error for
	 * nonexistent path, therefore we need to cut off trailing components
	 * of path until we get path which exists and can be resolved by
	 * realpath(). Lookup of "/dir/symlink/nonexistent-file" would fail
	 * to resolve symlink without this.
	 */
	(void) strlcpy(path_copy, a_path, PATH_MAX);
	for (cp = dirname(path_copy); strlen(cp) > 1; cp = dirname(cp)) {
		if (realpath(cp, real_path) != NULL) {
			found = B_TRUE;
			break;
		} else if (errno != ENOENT)
			break;
	}
	if (found) {
		/*
		 * In the loop above we always strip trailing path component,
		 * so the type of real_path is always 'd'.
		 */
		a_ftype = 'd';
		path2use = real_path;
	} else {
		path2use = a_path;
	}

	/*
	 * if path resides on an inherited filesystem then
	 * it must be read-only.
	 */

	if (z_isPathWritable(path2use) != 0) {
		return (B_FALSE);
	}

	/*
	 * remove the root path from the target path before comparing:
	 * Example 1:
	 * -- path is "/export/zone1/root/usr/test"
	 * -- root path is "/export/zone1/root"
	 * --- final path should be "/usr/test"
	 * Example 2:
	 * -- path is "/usr/test"
	 * -- root path is "/"
	 * --- final path should be "/usr/test"
	 */

	/* advance past given root directory if path begins with it */

	n = strlen(a_rootDir);
	if (strncmp(a_rootDir, path2use, n) == 0) {
		char	*p;

		/* advance past the root path */

		p = path2use + n;

		/* go back to the first occurance of the path separator */

		while ((*p != '/') && (p > path2use)) {
			p--;
		}

		/* use this location in the path to compare */

		path2use = p;
	}

	/*
	 * see if this path is in any inherited file system path
	 * note that all paths in the inherited list are directories
	 * so they end in "/" to prevent a partial match, such as
	 * comparing "/usr/libx" with "/usr/lib" - by making the comparison
	 * "/usr/libx" with "/usr/lib/" the partial false positive will not
	 * occur. This complicates matters when the object to compare is a
	 * directory - in this case, comparing "/usr" with "/usr/" will fail,
	 * so if the object is a directory, compare one less byte from the
	 * inherited file system so that the trailing "/" is ignored.
	 */

	for (n = 0; n < numInheritedFileSystems; n++) {
		int	fslen;

		/* get target fs len; adjust -1 if directory */

		fslen = inheritedFileSystemsLen[n];
		if ((a_ftype == 'd') && (fslen > 1)) {
			fslen--;
		}

		if (strncmp(path2use, inheritedFileSystems[n], fslen) == 0) {
			_z_echoDebug(DBG_PATHS_IS_INHERITED, a_path,
			    inheritedFileSystems[n]);
			return (B_TRUE);
		}
	}

	/* path is not in inherited file system space */

	_z_echoDebug(DBG_PATHS_IS_NOT_INHERITED, a_path, a_rootDir);

	return (B_FALSE);
}

/*
 * Name:	z_make_zone_root
 * Description:	Given its zonepath, generate a string representing the
 *              mountpoint of where the root path for a nonglobal zone is
 *              mounted.  The zone is mounted using 'zoneadm', which mounts
 *              the zone's filesystems wrt <zonepath>/lu/a
 * Arguments:	zone_path - non-NULL pointer to string representing zonepath
 * Returns:	char *	- pointer to string representing zonepath of zone
 *		NULL	- if zone_path is NULL.
 * Notes:	The string returned is in static storage and should not be
 *              free()ed by the caller.
 */
char *
z_make_zone_root(char *zone_path)
{
	static char	zone_root_buf[MAXPATHLEN];

	if (zone_path == NULL)
		return (NULL);

	(void) snprintf(zone_root_buf, MAXPATHLEN, "%s%slu/a", zone_path,
	    (zone_path[0] != '\0' &&
	    zone_path[strlen(zone_path) - 1] == '/') ? "" : "/");

	return (zone_root_buf);
}

void
z_path_canonize(char *a_file)
{
	char	*pt;
	char	*last;
	int	level;

	/* remove references such as "./" and "../" and "//" */
	for (pt = a_file; *pt; /* void */) {
		if (isdot(pt)) {
			(void) strcpy(pt, pt[1] ? pt+2 : pt+1);
		} else if (isdotdot(pt)) {
			level = 0;
			last = pt;
			do {
				level++;
				last += 2;
				if (*last) {
					last++;
				}
			} while (isdotdot(last));
			--pt; /* point to previous '/' */
			while (level--) {
				if (pt <= a_file) {
					return;
				}
				while ((*--pt != '/') && (pt > a_file))
					;
			}
			if (*pt == '/') {
				pt++;
			}
			(void) strcpy(pt, last);
		} else {
			while (*pt && (*pt != '/')) {
				pt++;
			}
			if (*pt == '/') {
				while (pt[1] == '/') {
					(void) strcpy(pt, pt+1);
				}
				pt++;
			}
		}
	}

	if ((--pt > a_file) && (*pt == '/')) {
		*pt = '\0';
	}
}

void
z_canoninplace(char *src)
{
	char *dst;
	char *src_start;

	/* keep a ptr to the beginning of the src string */
	src_start = src;

	dst = src;
	while (*src) {
		if (*src == '/') {
			*dst++ = '/';
			while (*src == '/')
				src++;
		} else
			*dst++ = *src++;
	}

	/*
	 * remove any trailing slashes, unless the whole string is just "/".
	 * If the whole string is "/" (i.e. if the last '/' cahr in dst
	 * in the beginning of the original string), just terminate it
	 * and return "/".
	 */
	if ((*(dst - 1) == '/') && ((dst - 1) != src_start))
		dst--;
	*dst = '\0';
}

void
z_free_inherited_file_systems(void)
{
	int i;

	for (i = 0; i < numInheritedFileSystems; i++) {
		free(inheritedFileSystems[i]);
	}
	free(inheritedFileSystems);
	inheritedFileSystems = NULL;
	free(inheritedFileSystemsLen);
	inheritedFileSystemsLen = NULL;
	numInheritedFileSystems = 0;
}
