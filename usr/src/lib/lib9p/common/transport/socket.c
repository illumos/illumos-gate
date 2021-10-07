/*
 * Copyright 2016 Jakub Klama <jceel@FreeBSD.org>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright 2021 Joyent, Inc.
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <sys/types.h>
#ifdef __APPLE__
# include "../apple_endian.h"
#elif __illumos__
# include <sys/param.h>
# include <port.h>
# include "../illumos_endian.h"
#else
# include <sys/endian.h>
#endif
#include <sys/socket.h>
#ifndef __illumos__
# include <sys/event.h>
#endif
#include <sys/uio.h>
#include <netdb.h>
#include "../lib9p.h"
#include "../lib9p_impl.h"
#include "../log.h"
#include "socket.h"

struct l9p_socket_softc
{
	struct l9p_connection *ls_conn;
	struct sockaddr ls_sockaddr;
	socklen_t ls_socklen;
	pthread_t ls_thread;
	int ls_fd;
};

#ifdef __FreeBSD__
struct event_svr {
	struct kevent *ev_kev;
	struct kevent *ev_event;
	int ev_kq;
};
#elif __illumos__
struct event_svr {
	port_event_t *ev_pe;
	int ev_port;
};
#else
#error "No event server defined"
#endif

static int l9p_init_event_svr(struct event_svr *, uint_t);
static uint_t l9p_get_server_addrs(const char *, const char *,
    struct addrinfo **);
static uint_t l9p_bind_addrs(struct event_svr *, struct addrinfo *, uint_t,
    int **);
static int l9p_event_get(struct l9p_server *, struct event_svr *, uint_t,
    void (*cb)(struct l9p_server *, int));
static int l9p_socket_readmsg(struct l9p_socket_softc *, void **, size_t *);
static int l9p_socket_get_response_buffer(struct l9p_request *,
    struct iovec *, size_t *, void *);
static int l9p_socket_send_response(struct l9p_request *, const struct iovec *,
    const size_t, const size_t, void *);
static void l9p_socket_drop_response(struct l9p_request *, const struct iovec *,
    size_t, void *);
static void *l9p_socket_thread(void *);
static ssize_t xread(int, void *, size_t);
static ssize_t xwrite(int, void *, size_t);

int
l9p_start_server(struct l9p_server *server, const char *host, const char *port)
{
	struct addrinfo *res = NULL;
	int *sockets = NULL;
	uint_t naddrs = 0;
	uint_t nsockets = 0;
	uint_t i;
	struct event_svr esvr;

	naddrs = l9p_get_server_addrs(host, port, &res);
	if (naddrs == 0)
		return (-1);

	if (l9p_init_event_svr(&esvr, naddrs) != 0) {
		freeaddrinfo(res);
		return (-1);
	}

	nsockets = l9p_bind_addrs(&esvr, res, naddrs, &sockets);

	/*
	 * We don't need res, after this, so free it and NULL it to prevent
	 * any possible use after free.
	 */
	freeaddrinfo(res);
	res = NULL;

	if (nsockets == 0)
		goto fail;

	for (;;) {
		if (l9p_event_get(server, &esvr, nsockets,
		    l9p_socket_accept) < 0)
			break;
	}

	/* We get here if something failed */
	for (i = 0; i < nsockets; i++)
		close(sockets[i]);

fail:
	free(sockets);

#ifdef __FreeBSD__
	close(esvr.ev_kq);
	free(esvr.ev_kev);
	free(esvr.ev_event);
#elif __illumos__
	close(esvr.ev_port);
	free(esvr.ev_pe);
#else
#error "Port me"
#endif

	return (-1);
}

static uint_t
l9p_get_server_addrs(const char *host, const char *port, struct addrinfo **resp)
{
	struct addrinfo *res, hints;
	uint_t naddrs;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(host, port, &hints, resp);
	if (rc > 0) {
		L9P_LOG(L9P_ERROR, "getaddrinfo(): %s", gai_strerror(rc));
		return (0);
	}

	naddrs = 0;
	for (res = *resp; res != NULL; res = res->ai_next)
		naddrs++;

	if (naddrs == 0) {
		L9P_LOG(L9P_ERROR, "no addresses found for %s:%s", host, port);
	}

	return (naddrs);
}

#ifdef __FreeBSD__
static int
l9p_init_event_svr(struct event_svr *svr, uint_t nsockets)
{
	svr->ev_kev = calloc(nsockets, sizeof(struct kevent));
	if (svr->ev_kev == NULL) {
		L9P_LOG(L9P_ERROR, "calloc(): %s", strerror(errno));
		return (-1);
	}

	svr->ev_event = calloc(nsockets, sizeof(struct kevent));
	if (svr->ev_event == NULL) {
		L9P_LOG(L9P_ERROR, "calloc(): %s", strerror(errno));
		free(svr->ev_key);
		svr->ev_key = NULL;
		return (-1);
	}

	svr->ev_kq = kqueue();
	if (svr->ev_kq == -1) {
		L9P_LOG(L9P_ERROR, "kqueue(): %s", strerror(errno));
		free(svr->ev_kev);
		free(svr->ev_event);
		svr->ev_kev = NULL;
		svr->ev_event = NULL;
		return (-1);
	}

	return (0);
}
#elif __illumos__
static int
l9p_init_event_svr(struct event_svr *svr, uint_t nsockets)
{
	svr->ev_pe = calloc(nsockets, sizeof(port_event_t));
	if (svr->ev_pe == NULL) {
		L9P_LOG(L9P_ERROR, "calloc(): %s", strerror(errno));
		return (-1);
	}

	svr->ev_port = port_create();
	if (svr->ev_port == -1) {
		L9P_LOG(L9P_ERROR, "port_create(): %s", strerror(errno));
		return (-1);
	}

	return (0);
}
#else
#error "No event server defined"
#endif

static uint_t
l9p_bind_addrs(struct event_svr *svr, struct addrinfo *addrs, uint_t naddrs,
    int **socketsp)
{
	struct addrinfo *addr;
	uint_t i, j;

	*socketsp = calloc(naddrs, sizeof(int));
	if (*socketsp == NULL) {
		L9P_LOG(L9P_ERROR, "calloc(): %s", strerror(errno));
		return (0);
	}

	for (i = 0, addr = addrs; addr != NULL; addr = addr->ai_next) {
		int s;
		int val = 1;

		s = socket(addr->ai_family, addr->ai_socktype,
		    addr->ai_protocol);
		if (s == -1) {
			L9P_LOG(L9P_ERROR, "socket(): %s", strerror(errno));
			continue;
		}

		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val,
		    sizeof(val)) < 0) {
			L9P_LOG(L9P_ERROR, "setsockopt(): %s", strerror(errno));
			close(s);
			continue;
		}

		if (bind(s, addr->ai_addr, addr->ai_addrlen) < 0) {
			L9P_LOG(L9P_ERROR, "bind(): %s", strerror(errno));
			close(s);
			continue;
		}

		if (listen(s, 10) < 0) {
			L9P_LOG(L9P_ERROR, "listen(): %s", strerror(errno));
			close(s);
			continue;
		}

#ifdef __FreeBSD__
		EV_SET(&svr->ev_kev[i], s, EVFILT_READ, EV_ADD | EV_ENABLE, 0,
		    0, 0);
#elif __illumos__
		if (port_associate(svr->ev_port, PORT_SOURCE_FD, s,
		    POLLIN|POLLHUP, NULL) < 0) {
			L9P_LOG(L9P_ERROR, "port_associate(%d): %s", s,
			    strerror(errno));
			close(s);
			continue;
		}
#else
#error "Port me"
#endif

		*socketsp[i++] = s;
	}

	if (i < 1) {
		free(*socketsp);
		*socketsp = NULL;
		return (0);
	}

	for (j = i; j < naddrs; j++)
		*socketsp[j++] = -1;

#ifdef __FreeBSD__
	if (kevent(svr->ev_kq, svr->ev_kev, i, NULL, 0, NULL) < 0) {
		L9P_LOG(L9P_ERROR, "kevent(): %s", strerror(errno));

		for (j = 0; j < i; j++)
			close(j);

		free(*socketsp);
		*socketsp = NULL;

		return (0);
	}
#endif

	return (i);
}

#ifdef __FreeBSD__
static int
l9p_event_get(struct l9p_server *l9svr, struct event_svr *esvr, uint_t nsockets,
    void (*cb)(struct l9p_server *, int))
{
	int i, evs;

	evs = kevent(esvr->ev_kq, NULL, 0, esvr->ev_event, nsockets, NULL);
	if (evs < 0) {
		if (errno == EINTR)
			return (0);
		L9P_LOG(L9P_ERROR, "kevent(): %s", strerror(errno));
		return (-1);
	}

	for (i = 0; i < evs; i++)
		cb(l9svr, (int)sevr->ev_event[i].ident);

	return (0);
}
#elif __illumos__
static int
l9p_event_get(struct l9p_server *l9svr, struct event_svr *esvr, uint_t nsockets,
    void (*cb)(struct l9p_server *, int))
{
	uint_t evs = 1;
	int i;

	if (port_getn(esvr->ev_port, esvr->ev_pe, nsockets, &evs, NULL) < 0) {
		if (errno == EINTR)
			return (0);
		L9P_LOG(L9P_ERROR, "port_getn(): %s", strerror(errno));
		return (-1);
	}

	for (i = 0; i < evs; i++) {
		if (esvr->ev_pe[i].portev_source != PORT_SOURCE_FD)
			continue;

		cb(l9svr, (int)esvr->ev_pe[i].portev_object);
	}

	return (0);
}
#else
#error "Port me"
#endif

void
l9p_socket_accept(struct l9p_server *server, int svr_fd)
{
	struct l9p_socket_softc *sc;
	struct l9p_connection *conn;
	char host[NI_MAXHOST + 1];
	char serv[NI_MAXSERV + 1];
	struct sockaddr client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int conn_fd, err;

	conn_fd = accept(svr_fd, &client_addr, &client_addr_len);
	if (conn_fd < 0) {
		L9P_LOG(L9P_WARNING, "accept(): %s", strerror(errno));
		return;
	}

	err = getnameinfo(&client_addr, client_addr_len, host, NI_MAXHOST,
	    serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);

	if (err != 0) {
		L9P_LOG(L9P_WARNING, "cannot look up client name: %s",
		    gai_strerror(err));
	} else {
		L9P_LOG(L9P_INFO, "new connection from %s:%s", host, serv);
	}

	if (l9p_connection_init(server, &conn) != 0) {
		L9P_LOG(L9P_ERROR, "cannot create new connection");
		return;
	}

	sc = l9p_calloc(1, sizeof(*sc));
	sc->ls_conn = conn;
	sc->ls_fd = conn_fd;

	/*
	 * Fill in transport handler functions and aux argument.
	 */
	conn->lc_lt.lt_aux = sc;
	conn->lc_lt.lt_get_response_buffer = l9p_socket_get_response_buffer;
	conn->lc_lt.lt_send_response = l9p_socket_send_response;
	conn->lc_lt.lt_drop_response = l9p_socket_drop_response;

	err = pthread_create(&sc->ls_thread, NULL, l9p_socket_thread, sc);
	if (err) {
		L9P_LOG(L9P_ERROR,
		    "pthread_create (for connection from %s:%s): error %s",
		    host, serv, strerror(err));
		l9p_connection_close(sc->ls_conn);
		free(sc);
	}
}

static void *
l9p_socket_thread(void *arg)
{
	struct l9p_socket_softc *sc = (struct l9p_socket_softc *)arg;
	struct iovec iov;
	void *buf;
	size_t length;

	for (;;) {
		if (l9p_socket_readmsg(sc, &buf, &length) != 0)
			break;

		iov.iov_base = buf;
		iov.iov_len = length;
		l9p_connection_recv(sc->ls_conn, &iov, 1, NULL);
		free(buf);
	}

	L9P_LOG(L9P_INFO, "connection closed");
	l9p_connection_close(sc->ls_conn);
	free(sc);
	return (NULL);
}

static int
l9p_socket_readmsg(struct l9p_socket_softc *sc, void **buf, size_t *size)
{
	uint32_t msize;
	size_t toread;
	ssize_t ret;
	void *buffer;
	int fd = sc->ls_fd;

	assert(fd > 0);

	buffer = l9p_malloc(sizeof(uint32_t));

	ret = xread(fd, buffer, sizeof(uint32_t));
	if (ret < 0) {
		L9P_LOG(L9P_ERROR, "read(): %s", strerror(errno));
		return (-1);
	}

	if (ret != sizeof(uint32_t)) {
		if (ret == 0) {
			L9P_LOG(L9P_DEBUG, "%p: EOF", (void *)sc->ls_conn);
		} else {
			L9P_LOG(L9P_ERROR,
			    "short read: %zd bytes of %zd expected",
			    ret, sizeof(uint32_t));
		}
		return (-1);
	}

	msize = le32toh(*(uint32_t *)buffer);
	toread = msize - sizeof(uint32_t);
	buffer = l9p_realloc(buffer, msize);

	ret = xread(fd, (char *)buffer + sizeof(uint32_t), toread);
	if (ret < 0) {
		L9P_LOG(L9P_ERROR, "read(): %s", strerror(errno));
		return (-1);
	}

	if (ret != (ssize_t)toread) {
		L9P_LOG(L9P_ERROR, "short read: %zd bytes of %zd expected",
		    ret, toread);
		return (-1);
	}

	*size = msize;
	*buf = buffer;
	L9P_LOG(L9P_INFO, "%p: read complete message, buf=%p size=%d",
	    (void *)sc->ls_conn, buffer, msize);

	return (0);
}

static int
l9p_socket_get_response_buffer(struct l9p_request *req, struct iovec *iov,
    size_t *niovp, void *arg __unused)
{
	size_t size = req->lr_conn->lc_msize;
	void *buf;

	buf = l9p_malloc(size);
	iov[0].iov_base = buf;
	iov[0].iov_len = size;

	*niovp = 1;
	return (0);
}

static int
l9p_socket_send_response(struct l9p_request *req __unused,
    const struct iovec *iov, const size_t niov __unused, const size_t iolen,
    void *arg)
{
	struct l9p_socket_softc *sc = (struct l9p_socket_softc *)arg;

	assert(sc->ls_fd >= 0);

	L9P_LOG(L9P_DEBUG, "%p: sending reply, buf=%p, size=%d", arg,
	    iov[0].iov_base, iolen);

	if (xwrite(sc->ls_fd, iov[0].iov_base, iolen) != (int)iolen) {
		L9P_LOG(L9P_ERROR, "short write: %s", strerror(errno));
		return (-1);
	}

	free(iov[0].iov_base);
	return (0);
}

static void
l9p_socket_drop_response(struct l9p_request *req __unused,
    const struct iovec *iov, size_t niov __unused, void *arg)
{

	L9P_LOG(L9P_DEBUG, "%p: drop buf=%p", arg, iov[0].iov_base);
	free(iov[0].iov_base);
}

static ssize_t
xread(int fd, void *buf, size_t count)
{
	size_t done = 0;
	ssize_t ret;

	while (done < count) {
		ret = read(fd, (char *)buf + done, count - done);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			return (-1);
		}

		if (ret == 0)
			return ((ssize_t)done);

		done += (size_t)ret;
	}

	return ((ssize_t)done);
}

static ssize_t
xwrite(int fd, void *buf, size_t count)
{
	size_t done = 0;
	ssize_t ret;

	while (done < count) {
		ret = write(fd, (char *)buf + done, count - done);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			return (-1);
		}

		if (ret == 0)
			return ((ssize_t)done);

		done += (size_t)ret;
	}

	return ((ssize_t)done);
}
