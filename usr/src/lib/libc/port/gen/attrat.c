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

#include "synonyms.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <mtlib.h>
#include <attr.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/filio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>

static int (*nvpacker)(nvlist_t *, char **, size_t *, int, int);
static int (*nvsize)(nvlist_t *, size_t *, int);
static int (*nvunpacker)(char *, size_t, nvlist_t **);
static mutex_t attrlock = DEFAULTMUTEX;
static int initialized;
extern int __openattrdirat(int basefd, const char *name);

static char *xattr_view_name[XATTR_VIEW_LAST] = {
	VIEW_READONLY,
	VIEW_READWRITE
};

static int
attrat_init()
{
	if (initialized == 0) {
		lmutex_lock(&attrlock);
		if (initialized == 1) {
			lmutex_unlock(&attrlock);
			return (0);
		}

		void *libnvhandle = dlopen("libnvpair.so.1", RTLD_LAZY);
		if (libnvhandle == NULL || (nvpacker = (int (*)(nvlist_t *,
		    char **, size_t *, int, int)) dlsym(libnvhandle,
		    "nvlist_pack")) == NULL ||
		    (nvsize = (int (*)(nvlist_t *,
		    size_t *, int)) dlsym(libnvhandle,
		    "nvlist_size")) == NULL ||
		    (nvunpacker = (int (*)(char *, size_t,
		    nvlist_t **)) dlsym(libnvhandle,
		    "nvlist_unpack")) == NULL) {
			if (libnvhandle)
				dlclose(libnvhandle);
			lmutex_unlock(&attrlock);
			return (-1);
		}

		initialized = 1;
		lmutex_unlock(&attrlock);
	}
	return (0);
}

static int
attr_nv_pack(nvlist_t *request, void **nv_request, size_t *nv_requestlen)
{
	size_t bufsize;
	char *packbuf = NULL;

	if (nvsize(request, &bufsize, NV_ENCODE_XDR) != 0) {
		errno = EINVAL;
		return (-1);
	}

	packbuf = malloc(bufsize);
	if (packbuf == NULL)
		return (-1);
	if (nvpacker(request, &packbuf, &bufsize, NV_ENCODE_XDR, 0) != 0) {
		free(packbuf);
		errno = EINVAL;
		return (-1);
	} else {
		*nv_request = (void *)packbuf;
		*nv_requestlen = bufsize;
	}
	return (0);
}

static const char *
view_to_name(xattr_view_t view)
{
	if (view >= XATTR_VIEW_LAST || view < 0)
		return (NULL);
	return (xattr_view_name[view]);
}

static int
xattr_openat(int basefd, xattr_view_t view, int mode)
{
	const char *xattrname;
	int xattrfd;
	int oflag;

	switch (view) {
	case XATTR_VIEW_READONLY:
		oflag = O_RDONLY;
		break;
	case XATTR_VIEW_READWRITE:
		oflag = mode & O_RDWR;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	if (mode & O_XATTR)
		oflag |= O_XATTR;

	xattrname = view_to_name(view);
	xattrfd = openat(basefd, xattrname, oflag);
	if (xattrfd < 0)
		return (xattrfd);
	/* Don't cache sysattr info (advisory) */
	(void) directio(xattrfd, DIRECTIO_ON);
	return (xattrfd);
}

static int
cgetattr(int fd, nvlist_t **response)
{
	int error;
	int bytesread;
	void *nv_response;
	size_t nv_responselen;
	struct stat buf;

	if (error = attrat_init())
		return (error);
	if ((error = fstat(fd, &buf)) != 0)
		return (error);
	nv_responselen = buf.st_size;

	if ((nv_response = malloc(nv_responselen)) == NULL)
		return (-1);
	bytesread = read(fd, nv_response, nv_responselen);
	if (bytesread != nv_responselen) {
		free(nv_response);
		errno = EFAULT;
		return (-1);
	}

	if (nvunpacker(nv_response, nv_responselen, response)) {
		free(nv_response);
		errno = ENOMEM;
		return (-1);
	}

	free(nv_response);
	return (0);
}

static int
csetattr(int fd, nvlist_t *request)
{
	int error, saveerrno;
	int byteswritten;
	void *nv_request;
	size_t nv_requestlen;

	if (error = attrat_init())
		return (error);

	if ((error = attr_nv_pack(request, &nv_request, &nv_requestlen)) != 0)
		return (error);

	byteswritten = write(fd, nv_request, nv_requestlen);
	if (byteswritten != nv_requestlen) {
		saveerrno = errno;
		free(nv_request);
		errno = saveerrno;
		return (-1);
	}

	free(nv_request);
	return (0);
}

int
fgetattr(int basefd, xattr_view_t view, nvlist_t **response)
{
	int error, saveerrno, xattrfd;

	if ((xattrfd = xattr_openat(basefd, view, O_XATTR)) < 0)
		return (xattrfd);

	error = cgetattr(xattrfd, response);
	saveerrno = errno;
	(void) close(xattrfd);
	errno = saveerrno;
	return (error);
}

int
fsetattr(int basefd, xattr_view_t view, nvlist_t *request)
{
	int error, saveerrno, xattrfd;

	if ((xattrfd = xattr_openat(basefd, view, O_RDWR | O_XATTR)) < 0)
		return (xattrfd);
	error = csetattr(xattrfd, request);
	saveerrno = errno;
	(void) close(xattrfd);
	errno = saveerrno;
	return (error);
}

int
getattrat(int basefd, xattr_view_t view, const char *name, nvlist_t **response)
{
	int error, saveerrno, namefd, xattrfd;

	if ((namefd = __openattrdirat(basefd, name)) < 0)
		return (namefd);

	if ((xattrfd = xattr_openat(namefd, view, 0)) < 0) {
		saveerrno = errno;
		(void) close(namefd);
		errno = saveerrno;
		return (xattrfd);
	}

	error = cgetattr(xattrfd, response);
	saveerrno = errno;
	(void) close(namefd);
	(void) close(xattrfd);
	errno = saveerrno;
	return (error);
}

int
setattrat(int basefd, xattr_view_t view, const char *name, nvlist_t *request)
{
	int error, saveerrno, namefd, xattrfd;

	if ((namefd = __openattrdirat(basefd, name)) < 0)
		return (namefd);

	if ((xattrfd = xattr_openat(namefd, view, O_RDWR)) < 0) {
		saveerrno = errno;
		(void) close(namefd);
		errno = saveerrno;
		return (xattrfd);
	}

	error = csetattr(xattrfd, request);
	saveerrno = errno;
	(void) close(namefd);
	(void) close(xattrfd);
	errno = saveerrno;
	return (error);
}
