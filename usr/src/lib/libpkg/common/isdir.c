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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <archives.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "pkglocale.h"
#include "pkglibmsgs.h"

/*
 * Defines for cpio/compression checks.
 */
#define	BIT_MASK		0x1f
#define	BLOCK_MASK		0x80

#define	MASK_CK(x, y)	(((x) & (y)) == (y))
#define	ISCOMPCPIO	((unsigned char) cm.c_mag[0] == m_h[0] && \
			(unsigned char) cm.c_mag[1] == m_h[1] && \
			(MASK_CK((unsigned char) cm.c_mag[2], BLOCK_MASK) || \
			MASK_CK((unsigned char) cm.c_mag[2], BIT_MASK)))

#define	ISCPIO		(cm.b_mag != CMN_BIN && \
			(strcmp(cm.c_mag, CMS_ASC) == 0) && \
			(strcmp(cm.c_mag, CMS_CHR) == 0) && \
			(strcmp(cm.c_mag, CMS_CRC) == 0))

/* location of distributed file system types database */

#define	REMOTE_FS_DBFILE	"/etc/dfs/fstypes"

/* character array used to hold dfs types database contents */

static long		numRemoteFstypes = -1;
static char		**remoteFstypes = (char **)NULL;

/* forward declarations */

static void _InitRemoteFstypes(void);

int isFdRemote(int a_fd);
int isPathRemote(char *a_path);
int isFstypeRemote(char *a_fstype);
int isdir(char *path);
int isfile(char *dir, char *file);
int iscpio(char *path, int *iscomp);

/*
 * Name:	isdir
 * Description:	determine if specified path exists and is a directory
 * Arguments:	path - pointer to string representing the path to verify
 * returns: 0 - directory exists
 *	    1 - directory does not exist or is not a directory
 * NOTE:	errno is set appropriately
 */

int
isdir(char *path)
{
	struct stat statbuf;

	/* return error if path does not exist */

	if (stat(path, &statbuf) != 0) {
		return (1);
	}

	/* return error if path is not a directory */

	if ((statbuf.st_mode & S_IFMT) != S_IFDIR) {
		errno = ENOTDIR;
		return (1);
	}

	return (0);
}

/*
 * Name:	isfile
 * Description:	determine if specified path exists and is a directory
 * Arguments:	dir - pointer to string representing the directory where
 *			the file is located
 *			== NULL - use "file" argument only
 *		file - pointer to string representing the file to verify
 * Returns:	0 - success - file exists
 *		1 - failure - file does not exist OR is not a file
 * NOTE:	errno is set appropriately
 */

int
isfile(char *dir, char *file)
{
	struct stat statbuf;
	char	path[PATH_MAX];

	/* construct full path if directory specified */

	if (dir) {
		(void) snprintf(path, sizeof (path), "%s/%s", dir, file);
		file = path;
	}

	/* return error if path does not exist */

	if (stat(file, &statbuf) != 0) {
		return (1);
	}

	/* return error if path is a directory */

	if ((statbuf.st_mode & S_IFMT) == S_IFDIR) {
		errno = EISDIR;
		return (1);
	}

	/* return error if path is not a file */

	if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
		errno = EINVAL;
		return (1);
	}

	return (0);
}

int
iscpio(char *path, int *iscomp)
{
	/*
	 * Compressed File Header.
	 */
	unsigned char m_h[] = { "\037\235" };		/* 1F 9D */

	static union {
		short int	b_mag;
		char		c_mag[CMS_LEN];
	}	cm;

	struct stat	statb;
	int		fd;


	*iscomp = 0;

	if ((fd = open(path, O_RDONLY, 0)) == -1) {
		if (errno != ENOENT) {
			perror("");
			(void) fprintf(stderr, pkg_gt(ERR_ISCPIO_OPEN), path);
		}
		return (0);
	} else {
		if (fstat(fd, &statb) == -1) {
			perror("");
			(void) fprintf(stderr, pkg_gt(ERR_ISCPIO_FSTAT), path);
			(void) close(fd);
			return (0);
		} else {
			if (S_ISREG(statb.st_mode)) {	/* Must be a file */
				if (read(fd, cm.c_mag, sizeof (cm.c_mag)) !=
				    sizeof (cm.c_mag)) {
					perror("");
					(void) fprintf(stderr,
					    pkg_gt(ERR_ISCPIO_READ), path);
					(void) close(fd);
					return (0);
				}
				/*
				 * Try to determine if the file is a compressed
				 * file, if that fails, try to determine if it
				 * is a cpio archive, if that fails, then we
				 * fail!
				 */
				if (ISCOMPCPIO) {
					*iscomp = 1;
					(void) close(fd);
					return (1);
				} else if (ISCPIO) {
					(void) fprintf(stderr,
					    pkg_gt(ERR_ISCPIO_NOCPIO),
					    path);
					(void) close(fd);
					return (0);
				}
				(void) close(fd);
				return (1);
			} else {
				(void) close(fd);
				return (0);
			}
		}
	}
}

/*
 * Name:	isPathRemote
 * Description:	determine if a path object is local or remote
 * Arguments:	a_path - [RO, *RO] - (char *)
 *			Pointer to string representing the path to check
 * Returns:	int
 *			1 - the path is remote
 *			0 - the path is local to this system
 *			-1 - cannot determine if path is remote or local
 */

int
isPathRemote(char *a_path)
{
	int		r;
	struct stat	statbuf;

	r = lstat(a_path, &statbuf);
	if (r < 0) {
		return (-1);
	}

	return (isFstypeRemote(statbuf.st_fstype));
}

/*
 * Name:	isFdRemote
 * Description:	determine if an open file is local or remote
 * Arguments:	a_fd - [RO, *RO] - (int)
 *			Integer representing open file to check
 * Returns:	int
 *			1 - the path is remote
 *			0 - the path is local to this system
 *			-1 - cannot determine if path is remote or local
 */

int
isFdRemote(int a_fd)
{
	int		r;
	struct stat	statbuf;

	r = fstat(a_fd, &statbuf);
	if (r < 0) {
		return (-1);
	}

	return (isFstypeRemote(statbuf.st_fstype));
}

/*
 * Name:	isFstypeRemote
 * Description:	determine if a file system type is remote (distributed)
 * Arguments:	a_fstype - [RO, *RO] - (char *)
 *			Pointer to string representing the file system type
 *			to check
 * Returns:	int
 *			1 - the file system type is remote
 *			0 - the file system type is local to this system
 */

int
isFstypeRemote(char *a_fstype)
{
	int	i;

	/* initialize the list if it is not yet initialized */

	_InitRemoteFstypes();

	/* scan the list looking for the specified type */

	for (i = 0; i < numRemoteFstypes; i++) {
		if (strcmp(remoteFstypes[i], a_fstype) == 0) {
			return (1);
		}
	}

	/* type not found in remote file system type list - is not remote */

	return (0);
}

/*
 * Name:	_InitRemoteFstypes
 * Description:	initialize table of remote file system type names
 * Arguments:	none
 * Returns:	none
 * Side Effects:
 *	- The global array "(char **)remoteFstypes" is set to the
 *	  address of an array of string pointers, each of which represents
 *	  a single remote file system type
 *	- The global variable "(long) numRemoteFstypes" is set to the total
 *	  number of remote file system type strings (names) that are
 *	  contained in the "remoteFstypes" global array.
 *	- numRemoteFstypes is initialized to "-1" before any attempt has been
 *	  made to read the remote file system type name database.
 */
static void
_InitRemoteFstypes(void)
{
	FILE    *fp;
	char    line_buf[LINE_MAX];

	/* return if already initialized */

	if (numRemoteFstypes > 0) {
		return;
	}

	/* if list is uninitialized, start with zero */

	if (numRemoteFstypes == -1) {
		numRemoteFstypes = 0;
	}

	/* open the remote file system type database file */

	if ((fp = fopen(REMOTE_FS_DBFILE, "r")) == NULL) {
		/* no remote type database: use predefined remote types */
		remoteFstypes = (char **)realloc(remoteFstypes,
		    sizeof (char *) * (numRemoteFstypes+2));
		remoteFstypes[numRemoteFstypes++] = "nfs";	/* +1 */
		remoteFstypes[numRemoteFstypes++] = "autofs";	/* +2 */
		return;
	}

	/*
	 * Read the remote file system type database; from fstypes(4):
	 *
	 * fstypes resides in directory /etc/dfs and lists distributed file
	 * system utilities packages installed on the system. For each installed
	 * distributed file system type, there is a line that begins with the
	 * file system type name (for example, ``nfs''), followed by white space
	 * and descriptive text.
	 *
	 * Lines will look at lot like this:
	 *
	 *	nfs NFS Utilities
	 *	autofs AUTOFS Utilities
	 */

	while (fgets(line_buf, sizeof (line_buf), fp) != NULL) {
		char		buf[LINE_MAX];
		static char	format[128] = {'\0'};

		if (format[0] == '\0') {
			/* create bounded format: %ns */
			(void) snprintf(format, sizeof (format),
			    "%%%ds", sizeof (buf)-1);
		}

		(void) sscanf(line_buf, format, buf);

		remoteFstypes = realloc(remoteFstypes,
		    sizeof (char *) * (numRemoteFstypes+1));
		remoteFstypes[numRemoteFstypes++] = strdup(buf);
	}

	/* close database file and return */

	(void) fclose(fp);
}
