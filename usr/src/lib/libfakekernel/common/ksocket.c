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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/ksocket.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <unistd.h>
#include <errno.h>
#include <umem.h>

#define	_KSOCKET_MAGIC 0xabcdef09

#define	KSOCKET_VALID(ks) (ks->kso_magic == _KSOCKET_MAGIC)
#define	KSTOSO(ks) (ks->kso_fd)

#ifndef	SS_CLOSING
#define	SS_CLOSING 0x00010000
#endif

/*
 * NB: you can't cast this into a sonode like you can with a normal
 * ksocket_t, but no correct code should ever do that anyway.
 * The ksocket_t type is opaque to prevent exactly that.
 */
struct __ksocket {
	uint32_t kso_magic;
	uint32_t kso_count;
	uint32_t kso_state;
	int kso_fd;
	kmutex_t kso_lock;
	kcondvar_t kso_closing_cv;
};

static umem_cache_t *ksocket_cache = NULL;

/*ARGSUSED*/
static int
_ksocket_ctor(void *buf, void *arg, int flags)
{
	ksocket_t sock = buf;

	bzero(sock, sizeof (*sock));
	mutex_init(&sock->kso_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sock->kso_closing_cv, NULL, CV_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
_ksocket_dtor(void *buf, void *arg)
{
	ksocket_t sock = buf;

	mutex_destroy(&sock->kso_lock);
	cv_destroy(&sock->kso_closing_cv);
}

#pragma init(_ksocket_init)
int
_ksocket_init(void)
{
	ksocket_cache = umem_cache_create("ksocket",
	    sizeof (struct __ksocket), 0,
	    _ksocket_ctor, _ksocket_dtor, NULL, NULL, NULL, 0);
	VERIFY(ksocket_cache != NULL);
	return (0);
}

#pragma fini(_ksocket_fini)
int
_ksocket_fini(void)
{
	umem_cache_destroy(ksocket_cache);
	return (0);
}

static ksocket_t
_ksocket_create(int fd)
{
	ksocket_t ks;

	ks = umem_cache_alloc(ksocket_cache, 0);
	VERIFY(ks != NULL);
	ks->kso_magic = _KSOCKET_MAGIC;
	ks->kso_count = 1;
	ks->kso_fd = fd;
	return (ks);
}

static void
_ksocket_destroy(ksocket_t ks)
{
	ASSERT(ks->kso_count == 1);
	umem_cache_free(ksocket_cache, ks);
}

int
ksocket_socket(ksocket_t *ksp, int domain, int type, int protocol, int flags,
    struct cred *cr)
{
	int fd;
	ksocket_t ks;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	ASSERT(flags == KSOCKET_SLEEP || flags == KSOCKET_NOSLEEP);

	fd = socket(domain, type, protocol);
	if (fd < 0) {
		*ksp = NULL;
		return (errno);
	}

	ks = _ksocket_create(fd);
	*ksp = ks;
	return (0);
}

/*
 * This is marked NODIRECT so the main program linking with this library
 * can provide its own "bind helper" function.  See: fksmbd_ksock.c
 */
/* ARGSUSED */
int
ksocket_bind_helper(int fd, struct sockaddr *addr, uint_t addrlen)
{
	return (EACCES);
}

int
ksocket_bind(ksocket_t ks, struct sockaddr *addr, socklen_t addrlen,
    struct cred *cr)
{
	int err = 0;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (bind(KSTOSO(ks), addr, addrlen) != 0)
		err = errno;

	if (err == EACCES) {
		err = ksocket_bind_helper(KSTOSO(ks), addr, addrlen);
	}

	return (err);
}

int
ksocket_listen(ksocket_t ks, int backlog, struct cred *cr)
{
	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (listen(KSTOSO(ks), backlog) != 0)
		return (errno);

	return (0);
}

int
ksocket_accept(ksocket_t ks, struct sockaddr *addr,
    socklen_t *addrlenp, ksocket_t *nks, struct cred *cr)
{
	int fd;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	*nks = NULL;

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (addr != NULL && addrlenp == NULL)
		return (EFAULT);

	fd = accept(KSTOSO(ks), addr, addrlenp);
	if (fd < 0)
		return (errno);

	*nks = _ksocket_create(fd);

	return (0);
}

int
ksocket_connect(ksocket_t ks, struct sockaddr *addr, socklen_t addrlen,
    struct cred *cr)
{
	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (connect(KSTOSO(ks), addr, addrlen) != 0)
		return (errno);

	return (0);
}

int
ksocket_send(ksocket_t ks, void *msg, size_t msglen, int flags,
    size_t *sent, struct cred *cr)
{
	ssize_t error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks)) {
		if (sent != NULL)
			*sent = 0;
		return (ENOTSOCK);
	}

	error = send(KSTOSO(ks), msg, msglen, flags);
	if (error < 0) {
		if (sent != NULL)
			*sent = 0;
		return (errno);
	}

	if (sent != NULL)
		*sent = (size_t)error;
	return (0);
}

int
ksocket_sendto(ksocket_t ks, void *msg, size_t msglen, int flags,
    struct sockaddr *name, socklen_t namelen, size_t *sent, struct cred *cr)
{
	ssize_t error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks)) {
		if (sent != NULL)
			*sent = 0;
		return (ENOTSOCK);
	}

	error = sendto(KSTOSO(ks), msg, msglen, flags, name, namelen);
	if (error < 0) {
		if (sent != NULL)
			*sent = 0;
		return (errno);
	}

	if (sent != NULL)
		*sent = (size_t)error;
	return (0);
}

int
ksocket_sendmsg(ksocket_t ks, struct nmsghdr *msg, int flags,
    size_t *sent, struct cred *cr)
{
	ssize_t error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks)) {
		if (sent != NULL)
			*sent = 0;
		return (ENOTSOCK);
	}

	error = sendmsg(KSTOSO(ks), msg, flags);
	if (error < 0) {
		if (sent != NULL)
			*sent = 0;
		return (errno);
	}

	if (sent != NULL)
		*sent = (size_t)error;
	return (0);
}

int
ksocket_recv(ksocket_t ks, void *msg, size_t msglen, int flags,
    size_t *recvd, struct cred *cr)
{
	ssize_t error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks)) {
		if (recvd != NULL)
			*recvd = 0;
		return (ENOTSOCK);
	}

	error = recv(KSTOSO(ks), msg, msglen, flags);
	if (error < 0) {
		if (recvd != NULL)
			*recvd = 0;
		return (errno);
	}

	if (recvd != NULL)
		*recvd = (size_t)error;
	return (0);
}

int
ksocket_recvfrom(ksocket_t ks, void *msg, size_t msglen, int flags,
    struct sockaddr *name, socklen_t *namelen, size_t *recvd, struct cred *cr)
{
	ssize_t error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks)) {
		if (recvd != NULL)
			*recvd = 0;
		return (ENOTSOCK);
	}

	error = recvfrom(KSTOSO(ks), msg, msglen, flags, name, namelen);
	if (error != 0) {
		if (recvd != NULL)
			*recvd = 0;
		return (errno);
	}

	if (recvd != NULL)
		*recvd = (ssize_t)error;
	return (0);
}

int
ksocket_recvmsg(ksocket_t ks, struct nmsghdr *msg, int flags, size_t *recvd,
    struct cred *cr)
{
	ssize_t error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks)) {
		if (recvd != NULL)
			*recvd = 0;
		return (ENOTSOCK);
	}

	error = recvmsg(KSTOSO(ks), msg, flags);
	if (error < 0) {
		if (recvd != NULL)
			*recvd = 0;
		return (errno);
	}

	if (recvd != NULL)
		*recvd = (size_t)error;
	return (0);
}

int
ksocket_shutdown(ksocket_t ks, int how, struct cred *cr)
{
	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (shutdown(KSTOSO(ks), how) != 0)
		return (errno);

	return (0);
}

int
ksocket_close(ksocket_t ks, struct cred *cr)
{
	int fd;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	mutex_enter(&ks->kso_lock);

	if (!KSOCKET_VALID(ks)) {
		mutex_exit(&ks->kso_lock);
		return (ENOTSOCK);
	}

	ks->kso_state |= SS_CLOSING;

	/*
	 * The real ksocket wakes up everything.
	 * It seems the only way we can do that
	 * is to go ahead and close the FD.
	 */
	fd = ks->kso_fd;
	ks->kso_fd = -1;
	(void) close(fd);

	while (ks->kso_count > 1)
		cv_wait(&ks->kso_closing_cv, &ks->kso_lock);

	mutex_exit(&ks->kso_lock);
	_ksocket_destroy(ks);

	return (0);
}

int
ksocket_getsockname(ksocket_t ks, struct sockaddr *addr, socklen_t *addrlen,
    struct cred *cr)
{
	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (addrlen == NULL || (addr == NULL && *addrlen != 0))
		return (EFAULT);

	if (getsockname(KSTOSO(ks), addr, addrlen) != 0)
		return (errno);

	return (0);
}

int
ksocket_getpeername(ksocket_t ks, struct sockaddr *addr, socklen_t *addrlen,
    struct cred *cr)
{
	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (addrlen == NULL || (addr == NULL && *addrlen != 0))
		return (EFAULT);

	if (getpeername(KSTOSO(ks), addr, addrlen) != 0)
		return (errno);

	return (0);
}

int
ksocket_setsockopt(ksocket_t ks, int level, int optname, const void *optval,
    int optlen, struct cred *cr)
{
	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (!KSOCKET_VALID(ks))
		return (ENOTSOCK);

	if (optval == NULL)
		optlen = 0;

	if (setsockopt(KSTOSO(ks), level, optname, optval, optlen) != 0)
		return (errno);

	return (0);
}

void
ksocket_hold(ksocket_t ks)
{
	if (!mutex_owned(&ks->kso_lock)) {
		mutex_enter(&ks->kso_lock);
		ks->kso_count++;
		mutex_exit(&ks->kso_lock);
	} else
		ks->kso_count++;
}

void
ksocket_rele(ksocket_t ks)
{
	/*
	 * When so_count equals 1 means no thread working on this ksocket
	 */
	VERIFY3U(ks->kso_count, >, 1);

	if (!mutex_owned(&ks->kso_lock)) {
		mutex_enter(&ks->kso_lock);
		if (--ks->kso_count == 1)
			cv_signal(&ks->kso_closing_cv);
		mutex_exit(&ks->kso_lock);
	} else {
		if (--ks->kso_count == 1)
			cv_signal(&ks->kso_closing_cv);
	}
}
