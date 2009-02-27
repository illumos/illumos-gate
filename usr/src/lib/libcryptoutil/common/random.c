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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <locale.h>
#include <stdarg.h>
#include <cryptoutil.h>

#ifdef	_REENTRANT

#include <pthread.h>

static pthread_mutex_t	random_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t	urandom_mutex = PTHREAD_MUTEX_INITIALIZER;

#define	RAND_LOCK(x)	(void) pthread_mutex_lock(x)
#define	RAND_UNLOCK(x)	(void) pthread_mutex_unlock(x)

#else

#define	RAND_LOCK(x)
#define	RAND_UNLOCK(x)

#endif

#define	RANDOM_DEVICE		"/dev/random"	/* random device name */
#define	URANDOM_DEVICE		"/dev/urandom"	/* urandom device name */

static int	random_fd = -1;
static int	urandom_fd = -1;

/*
 * Equivalent of open(2) insulated from EINTR.
 * Also sets close-on-exec.
 */
int
open_nointr(const char *path, int oflag, ...)
{
	int	fd;
	mode_t	pmode;
	va_list	alist;

	va_start(alist, oflag);
	pmode = va_arg(alist, mode_t);
	va_end(alist);

	do {
		if ((fd = open(path, oflag, pmode)) >= 0) {
			(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
			break;
		}
		/* errno definitely set by failed open() */
	} while (errno == EINTR);
	return (fd);
}

/*
 * Equivalent of read(2) insulated from EINTR.
 */
ssize_t
readn_nointr(int fd, void *dbuf, size_t dlen)
{
	char	*marker = dbuf;
	size_t	left = dlen;
	ssize_t	nread = 0, err;

	for (err = 0; left > 0 && nread != -1; marker += nread, left -= nread) {
		if ((nread = read(fd, marker, left)) < 0) {
			if (errno == EINTR) {	/* keep trying */
				nread = 0;
				continue;
			}
			err = nread;		/* hard error */
			break;
		} else if (nread == 0) {
			break;
		}
	}
	return (err != 0 ? err : dlen - left);
}

/*
 * Equivalent of write(2) insulated from EINTR.
 */
ssize_t
writen_nointr(int fd, void *dbuf, size_t dlen)
{
	char	*marker = dbuf;
	size_t	left = dlen;
	ssize_t	nwrite = 0, err;

	for (err = 0; left > 0 && nwrite != -1; marker += nwrite,
	    left -= nwrite) {
		if ((nwrite = write(fd, marker, left)) < 0) {
			if (errno == EINTR) {	/* keep trying */
				nwrite = 0;
				continue;
			}
			err = nwrite;		/* hard error */
			break;
		} else if (nwrite == 0) {
			break;
		}
	}
	return (err != 0 ? err : dlen - left);
}

/*
 * Opens the random number generator devices if not already open.
 * Always returns the opened fd of the device, or error.
 */
int
pkcs11_open_random(void)
{
	RAND_LOCK(&random_mutex);
	if (random_fd < 0)
		random_fd = open_nointr(RANDOM_DEVICE, O_RDONLY);
	RAND_UNLOCK(&random_mutex);
	return (random_fd);
}

int
pkcs11_open_urandom(void)
{
	RAND_LOCK(&urandom_mutex);
	if (urandom_fd < 0)
		urandom_fd = open_nointr(URANDOM_DEVICE, O_RDONLY);
	RAND_UNLOCK(&urandom_mutex);
	return (urandom_fd);
}

/*
 * Close the random number generator devices if already open.
 */
void
pkcs11_close_random(void)
{
	if (random_fd < 0)
		return;
	RAND_LOCK(&random_mutex);
	(void) close(random_fd);
	random_fd = -1;
	RAND_UNLOCK(&random_mutex);
}

void
pkcs11_close_urandom(void)
{
	if (urandom_fd < 0)
		return;
	RAND_LOCK(&urandom_mutex);
	(void) close(urandom_fd);
	urandom_fd = -1;
	RAND_UNLOCK(&urandom_mutex);
}

/*
 * Put the requested amount of random data into a preallocated buffer.
 * Good for passphrase salts, initialization vectors.
 */
int
pkcs11_random_data(void *dbuf, size_t dlen)
{
	if (dbuf == NULL || dlen == 0)
		return (0);

	/* Read random data directly from /dev/urandom */
	if (pkcs11_open_urandom() < 0)
		return (-1);

	if (readn_nointr(urandom_fd, dbuf, dlen) == dlen)
		return (0);
	return (-1);
}

/*
 * Same as pkcs11_random_data but ensures non zero data.
 */
int
pkcs11_nzero_random_data(void *dbuf, size_t dlen)
{
	char	extrarand[32];
	size_t	bytesleft = 0;
	size_t	i = 0;

	/* Start with some random data */
	if (pkcs11_random_data(dbuf, dlen) < 0)
		return (-1);

	/* Walk through data replacing any 0 bytes with more random data */
	while (i < dlen) {
		if (((char *)dbuf)[i] != 0) {
			i++;
			continue;
		}

		if (bytesleft == 0) {
			bytesleft = sizeof (extrarand);
			if (pkcs11_random_data(extrarand, bytesleft) < 0)
				return (-1);
		}
		bytesleft--;

		((char *)dbuf)[i] = extrarand[bytesleft];
	}
	return (0);
}
