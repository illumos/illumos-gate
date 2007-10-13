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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <locale.h>
#include <cryptoutil.h>

/*
 * Read file into buffer.  Used to read raw key data or initialization
 * vector data.  Buffer must be freed by caller using free().
 *
 * If file is a regular file, entire file is read and dlen is set
 * to the number of bytes read.  Otherwise, dlen should first be set
 * to the number of bytes requested and will be reset to actual number
 * of bytes returned.
 *
 * Return 0 on success, -1 on error.
 */
int
pkcs11_read_data(char *filename, void **dbuf, size_t *dlen)
{
	int	fd;
	struct stat statbuf;
	boolean_t plain_file;
	void	*filebuf = NULL;
	size_t	filesize = 0;

	if (filename == NULL || dbuf == NULL || dlen == NULL)
		return (-1);

	if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1) {
		cryptoerror(LOG_STDERR, gettext("cannot open %s"), filename);
		return (-1);
	}

	if (fstat(fd, &statbuf) == -1) {
		cryptoerror(LOG_STDERR, gettext("cannot stat %s"), filename);
		(void) close(fd);
		return (-1);
	}

	if (S_ISREG(statbuf.st_mode)) {
		/* read the entire regular file */
		filesize = statbuf.st_size;
		plain_file = B_TRUE;
	} else {
		/* read requested bytes from special file */
		filesize = *dlen;
		plain_file = B_FALSE;
	}

	if (filesize == 0) {
		/*
		 * for decrypt this is an error; for digest this is ok;
		 * make it ok here but also set dbuf = NULL and dlen = 0
		 * to indicate there was no data to read and caller can
		 * retranslate that to an error if it wishes.
		 */
		(void) close(fd);
		*dbuf = NULL;
		*dlen = 0;
		return (0);
	}

	if ((filebuf = malloc(filesize)) == NULL) {
		int	err = errno;
		cryptoerror(LOG_STDERR, gettext("malloc: %s"), strerror(err));
		(void) close(fd);
		return (-1);
	}

	if (plain_file) {
		/* either it got read or it didn't */
		if (read(fd, filebuf, filesize) != filesize) {
			int	err = errno;
			cryptoerror(LOG_STDERR,
			    gettext("error reading file %s: %s"), filename,
			    strerror(err));
			(void) close(fd);
			return (-1);
		}
	} else {
		/* reading from special file may need some coaxing */
		char	*marker = (char *)filebuf;
		size_t	left = filesize;
		ssize_t	nread;
		int	err;

		for (/* */; left > 0; marker += nread, left -= nread) {
			/* keep reading it's going well */
			nread = read(fd, marker, left);
			if (nread > 0 || (nread == 0 && errno == EINTR))
				continue;

			/* might have to be good enough for caller */
			if (nread == 0 && errno == EAGAIN)
				break;

			/* anything else is an error */
			err = errno;
			cryptoerror(LOG_STDERR,
			    gettext("error reading file %s: %s"), filename,
			    strerror(err));
			(void) close(fd);
			return (-1);
		}
		/* reset to actual number of bytes read */
		filesize -= left;
	}

	(void) close(fd);
	*dbuf = filebuf;
	*dlen = filesize;
	return (0);
}
