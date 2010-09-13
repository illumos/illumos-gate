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



#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/types.h>
#include <utime.h>
#include <sys/stat.h>
#include <locale.h>
#include <libintl.h>
#include <sys/mman.h>

/*
 * consolidation pkg command library includes
 */

#include "pkglib.h"

/*
 * local pkg command library includes
 */
#include "libinst.h"
#include "libadm.h"
#include "messages.h"

/*
 * MAXMAPSIZE controls the largest mapping to use at a time; please refer
 * to mmap(2) for details of how this size is incremented and rounded; briefly
 * each mapping request has an additional 16Kb added to it - mappings over
 * 4Mb will be rounded to a 4Mb boundary - thus if there were 8mb, adding
 * in the 16Kb overhead the mapping would use another 4Mb-16kb - that is
 * why there is 16Kb subtracted from the total
 */

#define	MAXMAPSIZE	(1024*1024*8)-(1024*16)	/* map at most 8MB */
#define	SMALLFILESIZE	(32*1024)	/* dont mmap files less than 32kb */

/*
 * Name:	copyF
 * Description:	fast copy of file - use mmap()/write() loop if possible
 * Arguments:	char *srcPath - name of source file to copy from
 *		char *dstPath - name of target file to copy to
 *		time_t a_mytime: control setting of access/modification times:
 *			== 0 - replicate source file access/modification times
 *			!= 0 - use specified time for access/modification times
 * Returns:	int
 *		== 0 - successful
 *		!= 0 - failure
 */

int
copyf(char *a_srcPath, char *a_dstPath, time_t a_mytime)
{
	struct stat	srcStatbuf;
	struct utimbuf	times;
	int		srcFd;
	int		dstFd;
	int		status;
	char		*pt;

	/* open source file for reading */

	srcFd = open(a_srcPath, O_RDONLY, 0);
	if (srcFd < 0) {
		progerr(ERR_OPEN_READ, a_srcPath, errno, strerror(errno));
		return (-1);
	}

	/* obtain file status of source file */

	if (fstat(srcFd, &srcStatbuf) != 0) {
		progerr(ERR_FSTAT, srcFd, a_srcPath, errno, strerror(errno));
		(void) close(srcFd);
		return (-1);
	}

	/* open target file for writing */

	dstFd = open(a_dstPath, O_WRONLY | O_TRUNC | O_CREAT,
		srcStatbuf.st_mode);
	if (dstFd < 0) {
		/* create directory structure if missing */
		pt = a_dstPath;
		while (pt = strchr(pt+1, '/')) {
			*pt = '\0';
			if (isdir(a_dstPath)) {
				if (mkdir(a_dstPath, 0755)) {
					progerr(ERR_NODIR, a_dstPath,
						errno, strerror(errno));
					*pt = '/';
					(void) close(srcFd);
					return (-1);
				}
			}
			*pt = '/';
		}

		/* attempt to create target file again */
		dstFd = open(a_dstPath, O_WRONLY | O_TRUNC | O_CREAT,
				srcStatbuf.st_mode);
		if (dstFd < 0) {
			progerr(ERR_OPEN_WRITE, a_dstPath, errno,
							strerror(errno));
			(void) close(srcFd);
			return (-1);
		}
	}

	/*
	 * source and target files are open: copy data
	 */

	status = copyFile(srcFd, dstFd, a_srcPath, a_dstPath, &srcStatbuf, 0);

	(void) close(srcFd);
	(void) close(dstFd);

	/*
	 * determine how to set access/modification times for target:
	 * -- a_mytime == 0: replicate source file access/modification times
	 * -- otherwise: use a_mytime for file access/modification times
	 */

	if (a_mytime == 0) {
		times.actime = srcStatbuf.st_atime;
		times.modtime = srcStatbuf.st_mtime;
	} else {
		times.actime = a_mytime;
		times.modtime = a_mytime;
	}

	/* set access/modification times for target */

	if (utime(a_dstPath, &times) != 0) {
		progerr(ERR_MODTIM, a_dstPath, errno, strerror(errno));
		return (-1);
	}

	/* return error if copy failed */

	if (status != 0) {
		progerr(ERR_READ, a_srcPath, errno, strerror(errno));
		return (-1);
	}

	/* success! */

	return (0);
}

/*
 * Name:	copyFile
 * Description:	fast copy of file - use mmap()/write() loop if possible
 * Arguments:	int srcFd - file descriptor open on source file
 *		int dstFd - file descriptor open on target file
 *		char *srcPath - name of source file (for error messages)
 *		char *dstPath - name of target file (for error messages)
 *		struct stat *a_srcStatbuf - stat structure for source file
 *		long a_iosize - preferred io size for read/write loop
 * Returns:	int
 *		== 0 - successful
 *		!= 0 - failure
 */

int
copyFile(int a_srcFd, int a_dstFd, char *a_srcPath, char *a_dstPath,
	struct stat *a_srcStatbuf, long a_iosize)
{
	caddr_t	cp;
	off_t	filesize = a_srcStatbuf->st_size;
	size_t	mapsize = 0;
	size_t	munmapsize = 0;
	off_t	offset = 0;

	echoDebug(DBG_COPY_FILE, a_srcPath, a_dstPath);

	/*
	 * if the source is a regular file and is not "too small", then cause
	 * the file to be mapped into memory
	 */

	if (S_ISREG(a_srcStatbuf->st_mode) && (filesize > SMALLFILESIZE)) {
		/*
		 * Determine size of initial mapping.  This will determine the
		 * size of the address space chunk we work with.  This initial
		 * mapping size will be used to perform munmap() in the future.
		 */

		mapsize = MAXMAPSIZE;
		if (filesize < mapsize) {
			mapsize = filesize;
		}

		/*
		 * remember size of mapping to "unmap" - if the source file
		 * exceeds MAXMAPSIZE bytes, then the final mapping of the
		 * source file will be less than MAXMAPSIZE, and we need to
		 * make sure that the entire mapping is unmapped when done.
		 */

		munmapsize = mapsize;

		/* map the first segment of the source into memory */

		cp = mmap((caddr_t)NULL, mapsize, PROT_READ,
			(MAP_SHARED|MAP_ALIGN), a_srcFd, (off_t)0);
		if (cp == MAP_FAILED) {
			mapsize = 0;   /* can't mmap today */
		}
	}

	/*
	 * if the source was not mapped into memory, copy via read/write loop
	 */

	if (mapsize == 0) {
		char	*buf = (char *)NULL;
		size_t	blocksize;
		int	pagesize = getpagesize();

		/* set blocksize for copy */

		blocksize = a_iosize;
		if ((blocksize == 0) || (blocksize > SMALLFILESIZE)) {
			blocksize = SMALLFILESIZE;
		} else if (blocksize < pagesize) {
			blocksize = pagesize;
		}

		/* allocate i/o transfer buffer */

		buf = memalign((size_t)pagesize, blocksize);
		if (buf == (char *)NULL) {
			progerr(ERR_COPY_MEMORY, a_srcPath, errno,
				strerror(errno));
			return (1);
		}

		/* copy the file contents */

		for (;;) {
			ssize_t	n;

			/* read next block of data */

			n = read(a_srcFd, buf, blocksize);
			if (n == 0) {
				/* end of file - return success */
				(void) free(buf);
				return (0);
			} else if (n < 0) {
				/* read error - return error */
				progerr(ERR_READ, a_srcPath,
						errno, strerror(errno));
				(void) free(buf);
				return (1);
			}

			/* write out block of data just read in */

			if (vfpSafeWrite(a_dstFd, buf, (size_t)n) != n) {
				/* short write/write error - return error */
				progerr(ERR_WRITE, a_dstPath,
						errno, strerror(errno));
				(void) free(buf);
				return (1);
			}
		}
	}

	/*
	 * the source has been mapped into memory, copy via mappings
	 */

	for (;;) {
		ssize_t	nbytes;

		/* write first mappings worth of data */

		nbytes = write(a_dstFd, cp, mapsize);

		/*
		 * if we write less than the mmaped size it's due to a
		 * media error on the input file or out of space on
		 * the output file.  So, try again, and look for errno.
		 */

		if ((nbytes >= 0) && (nbytes != (ssize_t)mapsize)) {
			size_t	remains;

			remains = mapsize - nbytes;
			while (remains > 0) {
				nbytes = write(a_dstFd,
					(cp + mapsize - remains), remains);
				if (nbytes >= 0) {
					remains -= nbytes;
					if (remains == 0) {
						nbytes = mapsize;
					}
					continue;
				}

				/* i/o error - report and exit */

				if (errno == ENOSPC) {
					progerr(ERR_WRITE, a_dstPath,
						errno, strerror(errno));
				} else {
					progerr(ERR_READ, a_srcPath,
						errno, strerror(errno));
				}

				/* unmap source file mapping */
				(void) munmap(cp, munmapsize);
				return (1);
			}
		}

		/*
		 * although the write manual page doesn't specify this
		 * as a possible errno, it is set when the nfs read
		 * via the mmap'ed file is accessed, so report the
		 * problem as a source access problem, not a target file
		 * problem
		 */

		if (nbytes < 0) {
			if (errno == EACCES) {
				progerr(ERR_READ, a_srcPath,
					errno, strerror(errno));
			} else {
				progerr(ERR_WRITE, a_dstPath,
					errno, strerror(errno));
			}

			/* unmap source file mapping */
			(void) munmap(cp, munmapsize);
			return (1);
		}

		filesize -= nbytes;
		if (filesize == 0) {
			break;
		}

		offset += nbytes;
		if (filesize < mapsize) {
			mapsize = filesize;
		}

		/* map next segment of file on top of existing mapping */

		cp = mmap(cp, mapsize, PROT_READ, (MAP_SHARED|MAP_FIXED),
			a_srcFd, offset);

		if (cp == MAP_FAILED) {
			progerr(ERR_MAPFAILED, a_srcPath, errno,
						strerror(errno));
			/* unmap source file mapping */
			(void) munmap(cp, munmapsize);
			return (1);
		}
	}

	/* unmap source file mapping */

	(void) munmap(cp, munmapsize);

	return (0);
}

/*
 * Name:	openLocal
 * Description:	open a file and assure that the descriptor returned is open on
 *		a file that is local to the current system - if the file is not
 *		local to this system, copy the file to a temporary file first,
 *		and then pass a handle back opened on the temporary file
 * Arguments:	a_path - [RO, *RO] - (char *)
 *			Pointer to string representing the path to the file
 *			to open
 *		a_oflag - [RO, *RO] - (int)
 *			Integer representing the "mode" bits for an open(2) call
 *		a_tmpdir - [RO, *RO] - (char *)
 *			Pointer to string representing the path to a directory
 *			where a temporary copy of the file can be placed if
 *			the source file is not local to this system. If this is
 *			NULL or does not exist, P_tmpdir is used.
 * Returns:	int
 *			>= 0 - file descriptor opened on the file
 *			== -1 - failed to open - errno contains error code
 * NOTE:	If the file is not local and is copied locally, the file is
 *		setup in such a way that it will be removed when the last
 *		file descriptor opened on the file is closed - there is no need
 *		to know the path to the temporary file or to remove it
 *		when done.
 */

int
openLocal(char *a_path, int a_oflag, char *a_tmpdir)
{
	char		*bn;
	char		template[PATH_MAX];
	int		fd;
	int		lerrno;
	int		n;
	int		tmpFd;
	struct stat	statbuf;

	/* open source file */

	fd = open(a_path, a_oflag);
	if (fd < 0) {
		return (fd);
	}

	/* return open fd if the source file is not remote */

	if (!isFdRemote(fd)) {
		return (fd);
	}

	/*
	 * source file is remote - must make a local copy
	 */

	/* get the source file's status */

	n = fstat(fd, &statbuf);
	if (n < 0) {
		lerrno = errno;
		(void) close(fd);
		errno = lerrno;
		return (-1);
	}

	/* generate unique temporary file name */

	if ((a_tmpdir == (char *)NULL) || (*a_tmpdir == '\0') ||
		(isdir(a_tmpdir) != 0)) {
		a_tmpdir = P_tmpdir;
	}
	bn = basename(a_path);
	n = strlen(a_tmpdir);
	n = snprintf(template, sizeof (template), "%s%s%sXXXXXX",
		a_tmpdir, a_tmpdir[n-1] == '/' ? "" : "/", bn);
	if (n > sizeof (template)) {
		(void) close(fd);
		return (EINVAL);
	}

	/* create the temporary file and open it */

	tmpFd = mkstemp(template);
	if (tmpFd < 0) {
		lerrno = errno;
		(void) close(fd);
		errno = lerrno;
		return (tmpFd);
	}

	/* unlink the file so when it is closed it is automatically deleted */

	(void) unlink(template);

	/* copy the source file to the temporary file */

	n = copyFile(fd, tmpFd, a_path, template, &statbuf, 0L);
	lerrno = errno;
	(void) close(fd);
	if (n != 0) {
		(void) close(tmpFd);
		errno = lerrno;
		return (-1);
	}

	/* return handle to temporary file created */

	return (tmpFd);
}
