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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


/*
 * System includes
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <utime.h>
#include <locale.h>
#include <libintl.h>
#include <pkglocs.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * consolidation pkg command library includes
 */

#include <pkglib.h>

/*
 * local pkg command library includes
 */

#include "libadm.h"
#include "libinst.h"
#include "install.h"
#include "messages.h"
#include "pkginstall.h"

/*
 * forward declarations
 */

static int	write_file(char **r_linknam, int a_ctrl, mode_t a_mode,
			char *a_file);
static int	create_path(int a_ctrl, char *a_file);

/*
 * Name:	cppath
 * Description:	copy a path object (install new file on system)
 * Arguments:
 *    - a_cntrl - determine how the destination file mode is set:
 *	|= MODE_0666 - force mode to 0666
 *      |= MODE_SET - mode is a_mode (no mask SET?ID bits)
 *      |= MODE_SRC - mode from source file (mask SET?ID bits)
 *      |= DIR_DISPLAY - display "%s <implied directory>" if directory created
 *    - a_srcPath - path to source to copy
 *    - a_dstPath - path to copy source to
 *    - a_mode - mode to set a_dstpath to (mode controlled by a_ctrl)
 * Returns:	int
 *	== 0 - success
 *	!= 0 - failure
 */

int
cppath(int a_ctrl, char *a_srcPath, char *a_dstPath, mode_t a_mode)
{
	char		*linknam = (char *)NULL;
	int		dstFd;
	int		len;
	int		srcFd;
	long		status;
	struct stat	srcStatbuf;
	struct utimbuf	times;

	/* entry debugging info */

	echoDebug(DBG_CPPATH_ENTRY, a_ctrl, a_mode, a_srcPath, a_dstPath);

	/* open source file for reading */

	srcFd = open(a_srcPath, O_RDONLY);
	if (srcFd < 0) {
		progerr(ERR_OPEN_READ, a_srcPath,
				errno, strerror(errno));
		return (1);
	}

	/* obtain file status of source file */

	if (fstat(srcFd, &srcStatbuf) != 0) {
		progerr(ERR_FSTAT, srcFd, a_srcPath, errno, strerror(errno));
		(void) close(srcFd);
		return (1);
	}

	/*
	 * Determine the permissions mode for the destination:
	 * - if MODE_SET is specified:
	 * --> use a_mode (do not mask off any portion)
	 * --> If a_mode is unknown (? in the pkgmap), then the file gets
	 * --> installed with the default 0644 mode
	 * - if MODE_SRC is specified:
	 * --> use the mode of the source (srcStatbuf.st_mode) but mask off all
	 * --> non-access mode bits (remove SET?UID bits)
	 * - otherwise:
	 * --> use 0666
	 */

	if (a_ctrl & MODE_SET) {
		mode_t	usemode;

		usemode = (a_mode ^ BADMODE) ? a_mode : 0644;
		if (a_mode != usemode && usemode == 0644) {
			logerr(WRN_DEF_MODE, a_dstPath);
			a_mode = usemode;
		}
	} else if (a_ctrl & MODE_SRC) {
		a_mode = (srcStatbuf.st_mode & S_IAMB);
	} else {
		a_mode = 0666;
	}

	/*
	 * Get fd of newly created destination file or, if this
	 * is an overwrite,  a temporary file (linknam).
	 */

	dstFd = write_file(&linknam, a_ctrl, a_mode, a_dstPath);
	if (dstFd < 0) {
		(void) close(srcFd);
		return (1);
	}

	/*
	 * source and target files are open: copy data
	 */

	status = copyFile(srcFd, dstFd, a_srcPath, a_dstPath, &srcStatbuf, 0);

	(void) close(srcFd);
	(void) close(dstFd);

	if (status != 0) {
		progerr(ERR_INPUT, a_srcPath, errno, strerror(errno));
		if (linknam) {
			(void) remove(linknam);
		}
		return (1);
	}

	/*
	 * If this is an overwrite, rename temp over original
	 */

	if ((linknam != (char *)NULL) && (rename(linknam, a_dstPath) != 0)) {
		FILE	*logfp = (FILE *)NULL;
		char	busylog[PATH_MAX];

		/* output log message if busy else program error */

		if (errno == ETXTBSY) {
			logerr(MSG_PROCMV, linknam);
		} else {
			progerr(ERR_OUTPUT_WRITING, a_dstPath, errno,
				strerror(errno));
		}

		(void) remove(linknam);

		/* open the log file and append log entry */

		len = snprintf(busylog, sizeof (busylog),
				"%s/textbusy", get_PKGADM());
		if (len > sizeof (busylog)) {
			progerr(ERR_CREATE_PATH_2, get_PKGADM(),
				"textbusy");
		} else {
			logfp = fopen(busylog, "a");
			if (logfp == NULL) {
				progerr(ERR_LOG, busylog, errno,
					strerror(errno));
			} else {
				(void) fprintf(logfp, "%s\n", linknam);
				(void) fclose(logfp);
			}
		}
	}

	/* set access/modification times for target */

	times.actime = srcStatbuf.st_atime;
	times.modtime = srcStatbuf.st_mtime;

	if (utime(a_dstPath, &times) != 0) {
		progerr(ERR_MODTIM, a_dstPath, errno, strerror(errno));
		return (1);
	}

	/* success! */

	return (0);
}

/*
 * This function creates all of the directory components of the specified path.
 */
static int
create_path(int a_ctrl, char *a_file)
{
	char	*pt;
	int	found = 0;

	for (pt = a_file; *pt; pt++) {
		/* continue if not at path separator or at start of path */

		if ((*pt != '/') || (pt == a_file)) {
			continue;
		}

		/* at '/' - terminate path at current entry */

		*pt = '\0';

		/* continue if path element exists */

		if (access(a_file, F_OK) == 0) {
			*pt = '/';
			continue;
		}

		/* create directory in path */

		if (mkdir(a_file, 0755)) {
			progerr(ERR_MAKE_DIR, a_file, errno, strerror(errno));
			*pt = '/';
			return (1);
		}

		/* display 'implied directory created' message */

		if (a_ctrl & DIR_DISPLAY) {
			echo(MSG_IMPDIR, a_file);
		}

		found++;

		*pt = '/';
	}

	return (!found);
}

/*
 * Name:	write_file
 * Description:	creates a new destination file if the file does not already
 *		exist; otherwise, creates a temporary file and places a
 *		pointer to the temporary file name in 'r_linknam'.
 * Arguments:	r_linknam - pointer to (char*) where name of temporary file
 *			created is returned
 *		a_ctrl - determine if the destination file name is displayed:
 *		     |= DIR_DISPLAY - display "%s <implied directory>"
 *			if directory created
 *		a_mode - permissions mode to set a_file to
 *		a_file - name of destination file to open
 * Returns:	int
 *			success - file descriptor of the file it opened.
 *			failure - returns -1
 */

static int
write_file(char **r_linknam, int a_ctrl, mode_t a_mode, char *a_file)
{
	int		len;
	int		fd = -1;
	static char	loc_link[PATH_MAX];

	/* entry debugging */

	echoDebug(DBG_WRITEFILE_ENTRY, a_ctrl, a_mode, a_file);

	/* reset pointer to returned 'temporary file name' */

	*r_linknam = (char *)NULL;

	/*
	 * If we are overwriting an existing file, arrange to replace
	 * it transparently.
	 */

	if (access(a_file, F_OK) == 0) {
		/*
		 * link the file to be copied to a temporary name in case
		 * it is executing or it is being written/used (e.g., a shell
		 * script currently being executed
		 */

		if (!RELATIVE(a_file)) {
			len = snprintf(loc_link, sizeof (loc_link),
					"%sXXXXXX", a_file);
			if (len > sizeof (loc_link)) {
				progerr(ERR_CREATE_PATH_2, a_file, "XXXXXX");
			}
		} else {
			logerr(WRN_RELATIVE, a_file);
			len = snprintf(loc_link, sizeof (loc_link),
					"./%sXXXXXX", a_file);
			if (len > sizeof (loc_link)) {
				progerr(ERR_CREATE_PATH_3, "./", a_file,
					"XXXXXX");
			}
		}

		/* create and open temporary file */

		fd = mkstemp(loc_link);
		if (fd == -1) {
			progerr(ERR_MKTEMP, loc_link, errno, strerror(errno));
			return (-1);
		}

		/* remember name of temporary file */

		*r_linknam = loc_link;

		/* make sure temporary file has correct mode */

		if (fchmod(fd, a_mode) < 0) {
			progerr(ERR_FCHMOD, loc_link, a_mode, errno,
				strerror(errno));
		}

		return (fd);
	}

	/*
	 * We are not overwriting an existing file, create a new one directly.
	 */

	fd = open(a_file, O_WRONLY | O_CREAT | O_TRUNC, a_mode);
	if (fd == -1) {
		if (create_path(a_ctrl, a_file) == 0) {
			fd = open(a_file, O_WRONLY | O_CREAT | O_TRUNC, a_mode);
		}
	}

	if (fd == -1) {
		progerr(ERR_OPEN_WRITE, a_file, errno, strerror(errno));
	}

	return (fd);
}
