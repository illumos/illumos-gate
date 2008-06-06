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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<dirent.h>
#include	<limits.h>
#include	<stdlib.h>
#include	<strings.h>
#include	"_rtld.h"
#include	"msg.h"


#ifndef	EXPAND_RELATIVE

static struct stat	status;

/*
 * Included here (instead of using libc's) to reduce the number of stat calls.
 */
static DIR *
_opendir(const char *file)
{
	DIR	*dirp;
	int	fd;

	if ((fd = open(file, (O_RDONLY | O_NDELAY), 0)) < 0)
		return (0);

	if ((fstat(fd, &status) < 0) ||
	    ((status.st_mode & S_IFMT) != S_IFDIR) ||
	    ((dirp = (DIR *)malloc(sizeof (DIR) + DIRBUF)) == NULL)) {
		(void) close(fd);
		return (0);
	}

	dirp->dd_buf = (char *)dirp + sizeof (DIR);
	dirp->dd_fd = fd;
	dirp->dd_loc = dirp->dd_size = 0;

	return (dirp);
}

static struct dirent *
_readdir(DIR *dirp)
{
	struct dirent	*denp;
	int		saveloc = 0;

	if (dirp->dd_size != 0) {
		/* LINTED */
		denp = (struct dirent *)&dirp->dd_buf[dirp->dd_loc];
		saveloc = dirp->dd_loc;
		dirp->dd_loc += denp->d_reclen;
	}
	if (dirp->dd_loc >= dirp->dd_size)
		dirp->dd_loc = dirp->dd_size = 0;

	if ((dirp->dd_size == 0) &&
	    ((dirp->dd_size = getdents(dirp->dd_fd,
	    /* LINTED */
	    (struct dirent *)dirp->dd_buf, DIRBUF)) <= 0)) {
		if (dirp->dd_size == 0)
			dirp->dd_loc = saveloc;
		return (0);
	}

	/* LINTED */
	denp = (struct dirent *)&dirp->dd_buf[dirp->dd_loc];

	return (denp);
}

static int
_closedir(DIR * dirp)
{
	int 	fd = dirp->dd_fd;

	free((char *)dirp);
	return (close(fd));
}

/*
 * Simplified getcwd(3C), stolen from raf's proc(1) pwdx.
 */
char *
getcwd(char *path, size_t pathsz)
{
	char		_path[PATH_MAX], cwd[PATH_MAX];
	size_t		cwdsz;
	ino_t		cino;
	dev_t		cdev;

	_path[--pathsz] = '\0';

	/*
	 * Stat the present working directory to establish the initial device
	 * and inode pair.
	 */
	(void) strcpy(cwd, MSG_ORIG(MSG_FMT_CWD));
	cwdsz = MSG_FMT_CWD_SIZE;

	if (stat(cwd, &status) == -1)
		return (NULL);

	/* LINTED */
	while (1) {
		DIR		*dirp;
		struct dirent	*denp;
		size_t		len;

		cino = status.st_ino;
		cdev = status.st_dev;

		/*
		 * Open parent directory
		 */
		(void) strcpy(&cwd[cwdsz], MSG_ORIG(MSG_FMT_PARENT));
		cwdsz += MSG_FMT_PARENT_SIZE;

		if ((dirp = _opendir(cwd)) == 0)
			return (NULL);

		/*
		 * Find subdirectory of parent that matches current directory.
		 */
		if (cdev == status.st_dev) {
			if (cino == status.st_ino) {
				/*
				 * At root, return the pathname we've
				 * established.
				 */
				(void) _closedir(dirp);
				(void) strcpy(path, &_path[pathsz]);
				return (path);
			}

			do {
				if ((denp = _readdir(dirp)) == NULL) {
					(void) _closedir(dirp);
					return (NULL);
				}
			} while (denp->d_ino != cino);

		} else {
			/*
			 * The parent director is a different filesystem, so
			 * determine filenames of subdirectories and stat.
			 */
			struct stat	_status;

			cwd[cwdsz] = '/';

			/* LINTED */
			while (1) {
				if ((denp = _readdir(dirp)) == NULL) {
					(void) _closedir(dirp);
					return (NULL);
				}
				if (denp->d_name[0] == '.') {
					if (denp->d_name[1] == '\0')
						continue;
					if (denp->d_name[1] == '.' &&
					    denp->d_name[2] == '\0')
						continue;
				}
				(void) strcpy(&cwd[cwdsz + 1], denp->d_name);

				/*
				 * Silently ignore non-stat'able entries.
				 */
				if (stat(cwd, &_status) == -1)
					continue;

				if ((_status.st_ino == cino) &&
				    (_status.st_dev == cdev))
					break;
			}
		}

		/*
		 * Copy name of current directory into pathname.
		 */
		if ((len = strlen(denp->d_name)) < pathsz) {
			pathsz -= len;
			(void) strncpy(&_path[pathsz], denp->d_name, len);
			_path[--pathsz] = '/';
		}
		(void) _closedir(dirp);
	}

	return (NULL);
}

#endif

/*
 * Take the given link-map file/pathname and prepend the current working
 * directory.
 *
 * When $ORIGIN was first introduced, the expansion of a relative pathname was
 * deferred until it was required.  However now we insure a full pathname is
 * always created - things like the analyzer wish to rely on librtld_db
 * returning a full path.  The overhead of this is perceived to be low,
 * providing the associated libc version of getcwd is available (see 4336878).
 * This getcwd() was ported back to Solaris 8.1.
 */
size_t
fullpath(Rt_map *lmp, const char *rpath)
{
	char	*name, _path[PATH_MAX];

	/*
	 * If a resolved path isn't provided, establish one from the PATHNAME().
	 */
	if (rpath)
		PATHNAME(lmp) = (char *)rpath;
	else {
		char	*path;

		name = path = (char *)PATHNAME(lmp);

		if (path[0] != '/') {
			/*
			 * If we can't determine the current directory (possible
			 * if too many files are open - EMFILE), or if the
			 * created path is too big, simply revert back to the
			 * initial pathname.
			 */
			if (getcwd(_path, (PATH_MAX - 2 - strlen(name))) !=
			    NULL) {
				(void) strcat(_path, MSG_ORIG(MSG_STR_SLASH));
				(void) strcat(_path, name);
				path = _path;
			}
		}

		/*
		 * See if the pathname can be reduced further.
		 */
		if (rtld_flags & RT_FL_EXECNAME) {
			int	size = PATH_MAX - 1;

			if ((size = resolvepath(path, _path, size)) > 0) {
				_path[size] = '\0';
				path = _path;
			}
		}

		/*
		 * If the pathname is different from the original, duplicate it
		 * so that it is available in a core file.  If the duplication
		 * fails simply leave the original pathname alone.
		 */
		if ((name != path) && strcmp(name, path)) {
			if ((PATHNAME(lmp) = strdup(path)) == 0)
				PATHNAME(lmp) = name;
		}
	}

	name = ORIGNAME(lmp) = PATHNAME(lmp);

	/*
	 * Establish the directory name size - this also acts as a flag that the
	 * directory name has been computed.
	 */
	DIRSZ(lmp) = strrchr(name, '/') - name;

	return (DIRSZ(lmp));
}
