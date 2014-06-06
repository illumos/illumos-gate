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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <locale.h>
#include <stdarg.h>
#include <cryptoutil.h>
#include <pthread.h>

#pragma init(pkcs11_random_init)

static pthread_mutex_t	random_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t	urandom_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t	random_seed_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t	urandom_seed_mutex = PTHREAD_MUTEX_INITIALIZER;

#define	RANDOM_DEVICE		"/dev/random"	/* random device name */
#define	URANDOM_DEVICE		"/dev/urandom"	/* urandom device name */

static int	random_fd = -1;
static int	urandom_fd = -1;

static int	random_seed_fd = -1;
static int	urandom_seed_fd = -1;


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
static int
pkcs11_open_common(int *fd, pthread_mutex_t *mtx, const char *dev, int oflag)
{
	(void) pthread_mutex_lock(mtx);
	if (*fd < 0)
		*fd = open_nointr(dev, oflag);
	(void) pthread_mutex_unlock(mtx);

	return (*fd);
}

static int
pkcs11_open_random(void)
{
	return (pkcs11_open_common(&random_fd, &random_mutex,
	    RANDOM_DEVICE, O_RDONLY));
}

static int
pkcs11_open_urandom(void)
{
	return (pkcs11_open_common(&urandom_fd, &urandom_mutex,
	    URANDOM_DEVICE, O_RDONLY));
}

static int
pkcs11_open_random_seed(void)
{
	return (pkcs11_open_common(&random_seed_fd, &random_seed_mutex,
	    RANDOM_DEVICE, O_WRONLY));
}

static int
pkcs11_open_urandom_seed(void)
{
	return (pkcs11_open_common(&urandom_seed_fd, &urandom_seed_mutex,
	    URANDOM_DEVICE, O_WRONLY));
}

/*
 * Close the random number generator devices if already open.
 */
static void
pkcs11_close_common(int *fd, pthread_mutex_t *mtx)
{
	(void) pthread_mutex_lock(mtx);
	(void) close(*fd);
	*fd = -1;
	(void) pthread_mutex_unlock(mtx);
}

static void
pkcs11_close_random(void)
{
	pkcs11_close_common(&random_fd, &random_mutex);
}

static void
pkcs11_close_urandom(void)
{
	pkcs11_close_common(&urandom_fd, &urandom_mutex);
}

static void
pkcs11_close_random_seed(void)
{
	pkcs11_close_common(&random_seed_fd, &random_seed_mutex);
}

static void
pkcs11_close_urandom_seed(void)
{
	pkcs11_close_common(&urandom_seed_fd, &urandom_seed_mutex);
}

/*
 * Read from the random number generator devices.
 */
static size_t
pkcs11_read_common(int *fd, pthread_mutex_t *mtx, void *dbuf, size_t dlen)
{
	size_t	n;

	(void) pthread_mutex_lock(mtx);
	n = readn_nointr(*fd, dbuf, dlen);
	(void) pthread_mutex_unlock(mtx);

	return (n);
}

static size_t
pkcs11_read_random(void *dbuf, size_t dlen)
{
	return (pkcs11_read_common(&random_fd, &random_mutex, dbuf, dlen));
}

static size_t
pkcs11_read_urandom(void *dbuf, size_t dlen)
{
	return (pkcs11_read_common(&urandom_fd, &urandom_mutex, dbuf, dlen));
}

/*
 * Write to the random number generator devices.
 */
static size_t
pkcs11_write_common(int *fd, pthread_mutex_t *mtx, void *dbuf, size_t dlen)
{
	size_t	n;

	(void) pthread_mutex_lock(mtx);
	n = writen_nointr(*fd, dbuf, dlen);
	(void) pthread_mutex_unlock(mtx);

	return (n);
}

static size_t
pkcs11_write_random_seed(void *dbuf, size_t dlen)
{
	return (pkcs11_write_common(&random_seed_fd, &random_seed_mutex,
	    dbuf, dlen));
}

static size_t
pkcs11_write_urandom_seed(void *dbuf, size_t dlen)
{
	return (pkcs11_write_common(&urandom_seed_fd, &urandom_seed_mutex,
	    dbuf, dlen));
}

/*
 * Seed /dev/random with the data in the buffer.
 */
int
pkcs11_seed_random(void *sbuf, size_t slen)
{
	int	rv;

	if (sbuf == NULL || slen == 0)
		return (0);

	/* Seeding error could mean it's not supported (errno = EACCES) */
	if (pkcs11_open_random_seed() < 0)
		return (-1);

	rv = -1;
	if (pkcs11_write_random_seed(sbuf, slen) == slen)
		rv = 0;

	pkcs11_close_random_seed();
	return (rv);
}

/*
 * Seed /dev/urandom with the data in the buffer.
 */
int
pkcs11_seed_urandom(void *sbuf, size_t slen)
{
	int	rv;

	if (sbuf == NULL || slen == 0)
		return (0);

	/* Seeding error could mean it's not supported (errno = EACCES) */
	if (pkcs11_open_urandom_seed() < 0)
		return (-1);

	rv = -1;
	if (pkcs11_write_urandom_seed(sbuf, slen) == slen)
		rv = 0;

	pkcs11_close_urandom_seed();
	return (rv);
}

/*
 * Put the requested amount of random data into a preallocated buffer.
 * Good for token key data, persistent objects.
 */
int
pkcs11_get_random(void *dbuf, size_t dlen)
{
	if (dbuf == NULL || dlen == 0)
		return (0);

	/* Read random data directly from /dev/random */
	if (pkcs11_open_random() < 0)
		return (-1);

	if (pkcs11_read_random(dbuf, dlen) == dlen)
		return (0);
	return (-1);
}

/*
 * Put the requested amount of random data into a preallocated buffer.
 * Good for passphrase salts, initialization vectors.
 */
int
pkcs11_get_urandom(void *dbuf, size_t dlen)
{
	if (dbuf == NULL || dlen == 0)
		return (0);

	/* Read random data directly from /dev/urandom */
	if (pkcs11_open_urandom() < 0)
		return (-1);

	if (pkcs11_read_urandom(dbuf, dlen) == dlen)
		return (0);
	return (-1);
}

/*
 * Same as pkcs11_get_urandom but ensures non zero data.
 */
int
pkcs11_get_nzero_urandom(void *dbuf, size_t dlen)
{
	char	extrarand[32];
	size_t	bytesleft = 0;
	size_t	i = 0;

	/* Start with some random data */
	if (pkcs11_get_urandom(dbuf, dlen) < 0)
		return (-1);

	/* Walk through data replacing any 0 bytes with more random data */
	while (i < dlen) {
		if (((char *)dbuf)[i] != 0) {
			i++;
			continue;
		}

		if (bytesleft == 0) {
			bytesleft = sizeof (extrarand);
			if (pkcs11_get_urandom(extrarand, bytesleft) < 0)
				return (-1);
		}
		bytesleft--;

		((char *)dbuf)[i] = extrarand[bytesleft];
	}
	return (0);
}

static void
pkcs11_random_prepare(void)
{
	/*
	 * NOTE - None of these are acquired more than one at a time.
	 * I can therefore acquire all four without fear of deadlock.
	 */
	(void) pthread_mutex_lock(&random_mutex);
	(void) pthread_mutex_lock(&urandom_mutex);
	(void) pthread_mutex_lock(&random_seed_mutex);
	(void) pthread_mutex_lock(&urandom_seed_mutex);
}

static void
pkcs11_random_parent_post(void)
{
	/* Drop the mutexes and get back to work! */
	(void) pthread_mutex_unlock(&urandom_seed_mutex);
	(void) pthread_mutex_unlock(&random_seed_mutex);
	(void) pthread_mutex_unlock(&urandom_mutex);
	(void) pthread_mutex_unlock(&random_mutex);
}

static void
pkcs11_random_child_post(void)
{
	pkcs11_random_parent_post();

	/* Also, close the FDs, just in case. */
	pkcs11_close_random();
	pkcs11_close_urandom();
	pkcs11_close_random_seed();
	pkcs11_close_urandom_seed();
}

static void
pkcs11_random_init(void)
{
	(void) pthread_atfork(pkcs11_random_prepare, pkcs11_random_parent_post,
	    pkcs11_random_child_post);
}
