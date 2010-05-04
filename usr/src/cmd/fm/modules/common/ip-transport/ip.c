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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/fm/protocol.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <alloca.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>

#include <fm/fmd_api.h>

#define	IP_MAGIC	"\177FMA" /* magic string identifying a packet header */
#define	IP_MAGLEN	4	/* length of magic string */
#define	IP_DEBUG_OFF	0	/* No informational debugging printed */
#define	IP_DEBUG_FINE	1	/* Basic debug information printed (default) */
#define	IP_DEBUG_FINER	2	/* More debug information printed. */
#define	IP_DEBUG_FINEST	3	/* All debug information printed */

typedef struct ip_hdr {
	char iph_magic[IP_MAGLEN]; /* magic string */
	uint32_t iph_size;	/* packed size */
} ip_hdr_t;

typedef struct ip_buf {
	void *ipb_buf;		/* data buffer */
	size_t ipb_size;	/* size of buffer */
} ip_buf_t;

typedef struct ip_cinfo {	/* Connection specific information */
	struct addrinfo *addr;	/* Connection address(es) */
	char *name;		/* The name of the server or interface */
	int retry;		/* The number of connection retries */
} ip_cinfo_t;

typedef struct ip_xprt {
	fmd_xprt_t *ipx_xprt;	/* transport handle */
	int ipx_flags;		/* transport flags */
	int ipx_fd;		/* socket file descriptor */
	int ipx_done;		/* flag indicating connection closed */
	pthread_t ipx_tid;	/* recv-side auxiliary thread */
	ip_buf_t ipx_sndbuf;	/* buffer for sending events */
	ip_buf_t ipx_rcvbuf;	/* buffer for receiving events */
	ip_cinfo_t *ipx_cinfo;	/* info for reconnect */
	char *ipx_addr;		/* address:port of remote connection */
	struct ip_xprt *ipx_next;	/* next ip_xprt in global list */
} ip_xprt_t;

#define	IPX_ID(a) ((a)->ipx_addr)

typedef struct ip_stat {
	fmd_stat_t ips_accfail;	/* failed accepts */
	fmd_stat_t ips_badmagic; /* invalid packet headers */
	fmd_stat_t ips_packfail; /* failed packs */
	fmd_stat_t ips_unpackfail; /* failed unpacks */
} ip_stat_t;

static void ip_xprt_create(fmd_xprt_t *, int, int, ip_cinfo_t *, char *);
static void ip_xprt_destroy(ip_xprt_t *);

static ip_stat_t ip_stat = {
	{ "accfail", FMD_TYPE_UINT64, "failed accepts" },
	{ "badmagic", FMD_TYPE_UINT64, "invalid packet headers" },
	{ "packfail", FMD_TYPE_UINT64, "failed packs" },
	{ "unpackfail", FMD_TYPE_UINT64, "failed unpacks" },
};

static fmd_hdl_t *ip_hdl;	/* module handle */
static pthread_mutex_t ip_lock;	/* lock for ip_xps list */
static ip_xprt_t *ip_xps;	/* list of active transports */
static nvlist_t *ip_auth;	/* authority to use for transport(s) */
static size_t ip_size;		/* default buffer size */
static volatile int ip_quit;	/* signal to quit */
static int ip_qlen;		/* queue length for listen(3SOCKET) */
static int ip_mtbf;		/* mtbf for simulating packet drop */
static int ip_external;		/* set transport to be "external" */
static int ip_no_remote_repair;	/* disallow remote repair */
static int ip_hconly;		/* only cache faults that are hc-scheme */
static int ip_rdonly;		/* force transport to be rdonly */
static int ip_hc_present_only;	/* only cache faults if hc-scheme and present */
static char *ip_domain_name;	/* set domain name for received list.suspects */
static hrtime_t ip_burp;	/* make mtbf slower by adding this much delay */
static int ip_translate;	/* call fmd_xprt_translate() before sending */
static char *ip_port;		/* port to connect to (or bind to if server) */
static int ip_retry;		/* retry count for ip_xprt_setup() -1=forever */
static hrtime_t ip_sleep;	/* sleep delay for ip_xprt_setup() */
static ip_cinfo_t ip_listen;	/* Transport service conn info for server */
static ip_cinfo_t ip_server;    /* Remote server connection info for client */
static ip_cinfo_t ip_server2;	/* Second remote server conn info for client */
static int ip_debug_level;	/* level for printing debug messages */

/*
 * Prints a debug message to the fmd debug framework if the debug level is set
 * to at least the given level.
 */
static void
ip_debug(int level, char *fmt, ...)
{
	if (ip_debug_level >= level) {
		va_list args;
		va_start(args, fmt);
		fmd_hdl_vdebug(ip_hdl, fmt, args);
		va_end(args);
	}
}

/*
 * Allocate space in ipx_sndbuf for a header and a packed XDR encoding of
 * the specified nvlist, and then send the buffer to our remote peer.
 */
static int
ip_fmdo_send(fmd_hdl_t *hdl, fmd_xprt_t *xp, fmd_event_t *ep, nvlist_t *nvl)
{
	ip_xprt_t *ipx;
	size_t size, nvsize;
	char *buf, *nvbuf;
	ip_hdr_t *iph;
	ssize_t r, n;
	int err;

	if (xp == NULL) {
		ip_debug(IP_DEBUG_FINE, "ip_fmdo_send failed: xp=NULL\n");
		return (FMD_SEND_FAILED);
	}
	ipx = fmd_xprt_getspecific(hdl, xp);

	/*
	 * For testing purposes, if ip_mtbf is non-zero, use this to pseudo-
	 * randomly simulate the need for retries.  If ip_burp is also set,
	 * then we also suspend the transport for a bit and wake it up again.
	 */
	if (ip_mtbf != 0 && gethrtime() % ip_mtbf == 0) {
		if (ip_burp != 0) {
			ip_debug(IP_DEBUG_FINE, "burping ipx %s", IPX_ID(ipx));
			ipx->ipx_flags |= FMD_XPRT_SUSPENDED;
			(void) fmd_timer_install(ip_hdl, ipx, NULL, ip_burp);
			fmd_xprt_suspend(ip_hdl, xp);
		}
		return (FMD_SEND_RETRY);
	}

	if (ip_translate && (nvl = fmd_xprt_translate(hdl, xp, ep)) == NULL) {
		fmd_hdl_error(hdl, "failed to translate event %p", (void *)ep);
		return (FMD_SEND_FAILED);
	}

	(void) nvlist_size(nvl, &nvsize, NV_ENCODE_XDR);
	size = r = sizeof (ip_hdr_t) + nvsize;

	if (ipx->ipx_sndbuf.ipb_size < size) {
		fmd_hdl_free(hdl, ipx->ipx_sndbuf.ipb_buf,
		    ipx->ipx_sndbuf.ipb_size);
		ipx->ipx_sndbuf.ipb_size = P2ROUNDUP(size, 16);
		ipx->ipx_sndbuf.ipb_buf = fmd_hdl_alloc(hdl,
		    ipx->ipx_sndbuf.ipb_size, FMD_SLEEP);
	}

	buf = ipx->ipx_sndbuf.ipb_buf;
	iph = (ip_hdr_t *)(uintptr_t)buf;
	nvbuf = buf + sizeof (ip_hdr_t);

	bcopy(IP_MAGIC, iph->iph_magic, IP_MAGLEN);
	iph->iph_size = htonl(nvsize);
	err = nvlist_pack(nvl, &nvbuf, &nvsize, NV_ENCODE_XDR, 0);

	if (ip_translate)
		nvlist_free(nvl);

	if (err != 0) {
		fmd_hdl_error(ip_hdl, "failed to pack event for "
		    "transport %p: %s\n", (void *)ipx->ipx_xprt, strerror(err));
		ip_stat.ips_packfail.fmds_value.ui64++;
		return (FMD_SEND_FAILED);
	}

	while (!ip_quit && r != 0) {
		if ((n = send(ipx->ipx_fd, buf, r, 0)) < 0) {
			if (errno != EINTR && errno != EWOULDBLOCK) {
				ip_debug(IP_DEBUG_FINE,
				    "failed to send to %s", IPX_ID(ipx));
				return (FMD_SEND_FAILED);
			}
			continue;
		}
		buf += n;
		r -= n;
	}

	ip_debug(IP_DEBUG_FINEST, "Sent event %d bytes to %s",
	    size, IPX_ID(ipx));
	return (FMD_SEND_SUCCESS);
}

/*
 * Sends events over transports that are configured read only.  When the module
 * is in read only mode it will receive all events and only send events that
 * have a subscription set.
 *
 * The configuration file will have to set prop ip_rdonly true and also
 * subscribe for events that are desired to be sent over the transport in order
 * for this function to be used.
 */
/* ARGSUSED */
static void
ip_fmdo_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	int err;
	ip_xprt_t *ipx;

	if (ip_rdonly) {
		(void) pthread_mutex_lock(&ip_lock);

		for (ipx = ip_xps; ipx != NULL; ipx = ipx->ipx_next) {
			err = ip_fmdo_send(hdl, ipx->ipx_xprt, ep, nvl);
			while (FMD_SEND_RETRY == err) {
				err = ip_fmdo_send(hdl, ipx->ipx_xprt, ep, nvl);
			}
		}
		(void) pthread_mutex_unlock(&ip_lock);
	}
}

/*
 * Receive a chunk of data of the specified size from our remote peer.  The
 * data is received into ipx_rcvbuf, and then a pointer to the buffer is
 * returned.  NOTE: The data is only valid until the next call to ip_xprt_recv.
 * If the connection breaks or ip_quit is set during receive, NULL is returned.
 */
static void *
ip_xprt_recv(ip_xprt_t *ipx, size_t size)
{
	char *buf = ipx->ipx_rcvbuf.ipb_buf;
	ssize_t n, r = size;

	if (ipx->ipx_rcvbuf.ipb_size < size) {
		fmd_hdl_free(ip_hdl, ipx->ipx_rcvbuf.ipb_buf,
		    ipx->ipx_rcvbuf.ipb_size);
		ipx->ipx_rcvbuf.ipb_size = P2ROUNDUP(size, 16);
		ipx->ipx_rcvbuf.ipb_buf = buf = fmd_hdl_alloc(ip_hdl,
		    ipx->ipx_rcvbuf.ipb_size, FMD_SLEEP);
	}

	while (!ip_quit && r != 0) {
		if ((n = recv(ipx->ipx_fd, buf, r, MSG_WAITALL)) == 0) {
			ipx->ipx_done++;
			return (NULL);
		}

		if (n < 0) {
			if (errno != EINTR && errno != EWOULDBLOCK) {
				ip_debug(IP_DEBUG_FINE,
				    "failed to recv on ipx %s", IPX_ID(ipx));
			}
			continue;
		}
		/* Reset retry counter after a successful connection */
		if (ipx->ipx_cinfo) {
			ipx->ipx_cinfo->retry = ip_retry;
		}

		buf += n;
		r -= n;
	}

	return (r ? NULL: ipx->ipx_rcvbuf.ipb_buf);
}

/*
 * Sets the address/port of the remote connection in the connection info struct
 * This is called after a TCP session has been set up with a known remote
 * address (sap)
 */
static void
ip_xprt_set_addr(ip_xprt_t *ipx, const struct sockaddr *sap)
{
	const struct sockaddr_in6 *sin6 = (const void *)sap;
	const struct sockaddr_in *sin = (const void *)sap;

	char buf[INET6_ADDRSTRLEN + 16];
	struct in_addr v4addr;
	in_port_t port;
	int n;

	ip_debug(IP_DEBUG_FINER, "Enter ip_xprt_set_addr");

	if (sap->sa_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr, &v4addr);
		(void) inet_ntop(AF_INET, &v4addr, buf, sizeof (buf));
		port = ntohs(sin6->sin6_port);
	} else if (sap->sa_family == AF_INET6) {
		(void) inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof (buf));
		port = ntohs(sin6->sin6_port);
	} else {
		(void) inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof (buf));
		port = ntohs(sin->sin_port);
	}

	n = strlen(buf);
	(void) snprintf(buf + n, sizeof (buf) - n, ":%u", port);

	if (ipx->ipx_addr)
		fmd_hdl_strfree(ip_hdl, ipx->ipx_addr);
	ipx->ipx_addr = fmd_hdl_strdup(ip_hdl, buf, FMD_SLEEP);
	ip_debug(IP_DEBUG_FINE, "connection addr is %s on %p",
	    ipx->ipx_addr, (void *)ipx);
}

static nvlist_t *
ip_xprt_auth(ip_xprt_t *ipx)
{
	nvlist_t *nvl;
	int err;

	ip_debug(IP_DEBUG_FINER, "Enter ip_xprt_auth");

	if (ip_auth != NULL)
		err = nvlist_dup(ip_auth, &nvl, 0);
	else
		err = nvlist_alloc(&nvl, 0, 0);

	if (err != 0) {
		fmd_hdl_abort(ip_hdl, "failed to create nvlist for "
		    "authority: %s\n", strerror(err));
	}

	if (ip_auth != NULL)
		return (nvl);

	ip_debug(IP_DEBUG_FINE, "ip_authority %s=%s\n",
	    FM_FMRI_AUTH_SERVER, ipx->ipx_addr);

	(void) nvlist_add_uint8(nvl, FM_VERSION, FM_FMRI_AUTH_VERSION);
	(void) nvlist_add_string(nvl, FM_FMRI_AUTH_SERVER, ipx->ipx_addr);

	return (nvl);
}

static void
ip_xprt_accept(ip_xprt_t *ipx)
{
	struct sockaddr_storage sa;
	socklen_t salen = sizeof (sa);
	fmd_xprt_t *xp;
	int fd;

	ip_debug(IP_DEBUG_FINER, "Enter ip_xprt_accept");

	if ((fd = accept(ipx->ipx_fd, (struct sockaddr *)&sa, &salen)) == -1) {
		fmd_hdl_error(ip_hdl, "failed to accept connection");
		ip_stat.ips_accfail.fmds_value.ui64++;
		return;
	}
	ip_debug(IP_DEBUG_FINE, "Accepted socket on fd %d", fd);

	ip_xprt_set_addr(ipx, (struct sockaddr *)&sa);
	xp = fmd_xprt_open(ip_hdl, ipx->ipx_flags,
	    ip_xprt_auth(ipx), NULL);
	ip_xprt_create(xp, fd, ipx->ipx_flags, &ip_listen, ipx->ipx_addr);
}

static void
ip_xprt_recv_event(ip_xprt_t *ipx)
{
	ip_hdr_t *iph;
	nvlist_t *nvl;
	size_t size;
	void *buf;
	int err;

	if ((iph = ip_xprt_recv(ipx, sizeof (ip_hdr_t))) == NULL)
		return; /* connection broken */

	if (bcmp(iph->iph_magic, IP_MAGIC, IP_MAGLEN) != 0) {
		fmd_hdl_error(ip_hdl,
		    "invalid hdr magic %x.%x.%x.%x from transport %s\n",
		    iph->iph_magic[0], iph->iph_magic[1], iph->iph_magic[2],
		    iph->iph_magic[3], IPX_ID(ipx));
		ip_stat.ips_badmagic.fmds_value.ui64++;
		return;
	}

	size = ntohl(iph->iph_size);

	if ((buf = ip_xprt_recv(ipx, size)) == NULL)
		return; /* connection broken */

	if ((err = nvlist_unpack(buf, size, &nvl, 0)) != 0) {
		fmd_hdl_error(ip_hdl, "failed to unpack event from "
		    "transport %s: %s\n",
		    IPX_ID(ipx), strerror(err));
		ip_stat.ips_unpackfail.fmds_value.ui64++;
	} else {
		if (ip_domain_name)
			fmd_xprt_add_domain(ip_hdl, nvl, ip_domain_name);
		fmd_xprt_post(ip_hdl, ipx->ipx_xprt, nvl, 0);
	}

	if (fmd_xprt_error(ip_hdl, ipx->ipx_xprt)) {
		fmd_hdl_error(ip_hdl, "protocol error on transport %p",
		    (void *)ipx->ipx_xprt);
		ipx->ipx_done++;
	}
	ip_debug(IP_DEBUG_FINEST, "Recv event %d bytes from %s",
	    size, IPX_ID(ipx));
}

static void
ip_xprt_thread(void *arg)
{
	ip_xprt_t *ipx = arg;
	struct sockaddr_storage sa;
	socklen_t salen = sizeof (sa);
	struct pollfd pfd;
	id_t id;

	ip_debug(IP_DEBUG_FINER, "Enter ip_xprt_thread");

	while (!ip_quit && !ipx->ipx_done) {
		if (ipx->ipx_xprt != NULL || (ipx->ipx_flags & FMD_XPRT_ACCEPT))
			pfd.events = POLLIN;
		else
			pfd.events = POLLOUT;

		pfd.fd = ipx->ipx_fd;
		pfd.revents = 0;

		if (poll(&pfd, 1, -1) <= 0)
			continue; /* loop around and check ip_quit */

		if (pfd.revents & (POLLHUP | POLLERR)) {
			ip_debug(IP_DEBUG_FINE, "hangup fd %d\n", ipx->ipx_fd);
			break;
		}

		if (pfd.revents & POLLOUT) {
			/*
			 * Once we're connected, there's no reason to have our
			 * calls to recv() and send() be non-blocking since we
			 * we have separate threads for each: clear O_NONBLOCK.
			 */
			(void) fcntl(ipx->ipx_fd, F_SETFL,
			    fcntl(ipx->ipx_fd, F_GETFL, 0) & ~O_NONBLOCK);

			if (getpeername(ipx->ipx_fd, (struct sockaddr *)&sa,
			    &salen) != 0) {
				fmd_hdl_error(ip_hdl, "failed to get peer name "
				    "for fd %d", ipx->ipx_fd);
				bzero(&sa, sizeof (sa));
				break;
			}
			ip_xprt_set_addr(ipx, (struct sockaddr *)&sa);
			ipx->ipx_xprt = fmd_xprt_open(ip_hdl, ipx->ipx_flags,
			    ip_xprt_auth(ipx), ipx);

			ip_debug(IP_DEBUG_FINE, "connect fd %d ipx %p",
			    ipx->ipx_fd, (void *)ipx);
			continue;
		}

		if (pfd.revents & POLLIN) {
			if (ipx->ipx_xprt == NULL)
				ip_xprt_accept(ipx);
			else
				ip_xprt_recv_event(ipx);
		}
	}

	id = fmd_timer_install(ip_hdl, ipx, NULL, 0);
	ip_debug(IP_DEBUG_FINE, "close fd %d (timer %d)", ipx->ipx_fd, (int)id);
}

static void
ip_xprt_create(fmd_xprt_t *xp, int fd, int flags, ip_cinfo_t *cinfo, char *addr)
{
	ip_xprt_t *ipx = fmd_hdl_zalloc(ip_hdl, sizeof (ip_xprt_t), FMD_SLEEP);

	ip_debug(IP_DEBUG_FINER, "Enter ip_xprt_create %p", (void *)ipx);

	ipx->ipx_xprt = xp;
	ipx->ipx_flags = flags;
	ipx->ipx_fd = fd;
	ipx->ipx_tid = fmd_thr_create(ip_hdl, ip_xprt_thread, ipx);
	ipx->ipx_cinfo = cinfo;
	ipx->ipx_addr = fmd_hdl_strdup(ip_hdl, addr, FMD_SLEEP);

	if (ipx->ipx_xprt != NULL)
		fmd_xprt_setspecific(ip_hdl, ipx->ipx_xprt, ipx);

	(void) pthread_mutex_lock(&ip_lock);

	ipx->ipx_next = ip_xps;
	ip_xps = ipx;

	(void) pthread_mutex_unlock(&ip_lock);
}

static void
ip_xprt_destroy(ip_xprt_t *ipx)
{
	ip_xprt_t *ipp, **ppx = &ip_xps;

	ip_debug(IP_DEBUG_FINER, "Enter ip_xprt_destory %s %p",
	    IPX_ID(ipx), (void *)ipx);

	(void) pthread_mutex_lock(&ip_lock);

	for (ipp = *ppx; ipp != NULL; ipp = ipp->ipx_next) {
		if (ipp != ipx)
			ppx = &ipp->ipx_next;
		else
			break;
	}

	if (ipp != ipx) {
		(void) pthread_mutex_unlock(&ip_lock);
		fmd_hdl_abort(ip_hdl, "ipx %p not on xps list\n", (void *)ipx);
	}

	*ppx = ipx->ipx_next;
	ipx->ipx_next = NULL;

	(void) pthread_mutex_unlock(&ip_lock);

	fmd_thr_signal(ip_hdl, ipx->ipx_tid);
	fmd_thr_destroy(ip_hdl, ipx->ipx_tid);

	if (ipx->ipx_xprt != NULL)
		fmd_xprt_close(ip_hdl, ipx->ipx_xprt);

	fmd_hdl_free(ip_hdl, ipx->ipx_sndbuf.ipb_buf, ipx->ipx_sndbuf.ipb_size);
	fmd_hdl_free(ip_hdl, ipx->ipx_rcvbuf.ipb_buf, ipx->ipx_rcvbuf.ipb_size);

	(void) close(ipx->ipx_fd);
	if (ipx->ipx_addr) {
		fmd_hdl_strfree(ip_hdl, ipx->ipx_addr);
		ipx->ipx_addr = NULL;
	}
	fmd_hdl_free(ip_hdl, ipx, sizeof (ip_xprt_t));
}

/*
 * Loop through the addresses in the connection info structure that were
 * created by getaddrinfo() in ip_setup_addr during initialization (_fmd_init)
 * and for each one attempt to create a socket and initialize it.  If we are
 * successful, return zero.  If we fail, we check ip_retry: if it is non-zero
 * we return the last errno and let our caller retry ip_xprt_setup() later.  If
 * ip_retry reaches zero, we call fmd_hdl_abort() with an appropriate message.
 */
static int
ip_xprt_setup(fmd_hdl_t *hdl, ip_cinfo_t *cinfo)
{
	int err, fd, oflags, xflags, optval = 1;
	struct addrinfo *aip;
	const char *s1, *s2;
	struct addrinfo *ail = cinfo->addr;

	ip_debug(IP_DEBUG_FINER, "Enter ip_xprt_setup");

	/*
	 * Set up flags as specified in the .conf file. Note that these are
	 * mostly only used for testing purposes, allowing the transport to
	 * be set up in various modes.
	 */
	if (ail != ip_listen.addr)
		xflags = (ip_rdonly == FMD_B_TRUE) ? FMD_XPRT_RDONLY :
		    FMD_XPRT_RDWR;
	else
		xflags = ((ip_rdonly == FMD_B_TRUE) ? FMD_XPRT_RDONLY :
		    FMD_XPRT_RDWR) | FMD_XPRT_ACCEPT;

	if (ip_external == FMD_B_TRUE)
		xflags |= FMD_XPRT_EXTERNAL;
	if (ip_no_remote_repair == FMD_B_TRUE)
		xflags |= FMD_XPRT_NO_REMOTE_REPAIR;
	if (ip_hconly == FMD_B_TRUE)
		xflags |= FMD_XPRT_HCONLY;
	if (ip_hc_present_only == FMD_B_TRUE)
		xflags |= FMD_XPRT_HC_PRESENT_ONLY;

	for (aip = ail; aip != NULL; aip = aip->ai_next) {
		if (aip->ai_family != AF_INET && aip->ai_family != AF_INET6)
			continue; /* ignore anything that isn't IPv4 or IPv6 */

		if ((fd = socket(aip->ai_family,
		    aip->ai_socktype, aip->ai_protocol)) == -1) {
			err = errno;
			continue;
		}

		oflags = fcntl(fd, F_GETFL, 0);
		(void) fcntl(fd, F_SETFL, oflags | O_NONBLOCK);

		if (xflags & FMD_XPRT_ACCEPT) {
			err = setsockopt(fd, SOL_SOCKET,
			    SO_REUSEADDR, &optval, sizeof (optval)) != 0 ||
			    bind(fd, aip->ai_addr, aip->ai_addrlen) != 0 ||
			    listen(fd, ip_qlen) != 0;
		} else {
			err = connect(fd, aip->ai_addr, aip->ai_addrlen);
			if (err)
				err = errno;
			if (err == EINPROGRESS)
				err = 0;
		}

		if (err == 0) {
			ip_xprt_create(NULL, fd, xflags, cinfo, NULL);
			ip_debug(IP_DEBUG_FINER, "Exit ip_xprt_setup");
			return (0);
		}

		ip_debug(IP_DEBUG_FINE, "Error=%d errno=%d", err, errno);

		err = errno;
		(void) close(fd);
	}

	if (cinfo->name != NULL) {
		s1 = "failed to connect to";
		s2 = cinfo->name;
	} else {
		s1 = "failed to listen on";
		s2 = ip_port;
	}

	if (err == EACCES || cinfo->retry-- == 0)
		fmd_hdl_abort(hdl, "%s %s: %s\n", s1, s2, strerror(err));

	ip_debug(IP_DEBUG_FINE, "%s %s: %s (will retry)\n",
	    s1, s2, strerror(err));
	ip_debug(IP_DEBUG_FINER, "Exit ip_xprt_setup");
	return (err);
}

/*
 * Free address based resources
 */
static void
ip_addr_cleanup()
{
	if (ip_listen.addr != NULL) {
		freeaddrinfo(ip_listen.addr);
		ip_listen.addr = NULL;
	}
	if (ip_server.addr != NULL) {
		freeaddrinfo(ip_server.addr);
		ip_server.addr = NULL;
	}
	if (ip_server2.addr != NULL) {
		freeaddrinfo(ip_server2.addr);
		ip_server2.addr = NULL;
	}
	fmd_prop_free_string(ip_hdl, ip_server.name);
	fmd_prop_free_string(ip_hdl, ip_server2.name);
	fmd_prop_free_string(ip_hdl, ip_port);
}

/*
 * Setup a single address for ip connection.
 */
static int
ip_setup_addr(ip_cinfo_t *cinfo)
{
	struct addrinfo aih;
	char *server = cinfo->name;
	int err;

	bzero(&aih, sizeof (aih));
	aih.ai_flags = AI_ADDRCONFIG;
	aih.ai_family = AF_UNSPEC;
	aih.ai_socktype = SOCK_STREAM;
	if (server != NULL) {
		ip_debug(IP_DEBUG_FINE, "resolving %s:%s\n", server, ip_port);
	} else {
		aih.ai_flags |= AI_PASSIVE;
		cinfo->name = "localhost";
	}

	err = getaddrinfo(server, ip_port, &aih, &cinfo->addr);
	if (err != 0) {
		fmd_hdl_error(ip_hdl, "failed to resolve host %s port %s: %s\n",
		    cinfo->name, ip_port, gai_strerror(err));
		cinfo->addr = NULL;
	}
	return (err);
}

/*
 * Setup all IP addresses for network configuration.
 * The listen address for for a service that will bind to clients.
 * A client can connect up to two servers using ip_server and ip_server2
 * properties.
 */
static int
ip_setup_addrs()
{
	int err = 0;
	ip_listen.addr = NULL;
	ip_server.addr = NULL;
	ip_server.retry = ip_retry;
	ip_server2.addr = NULL;

	if ((ip_server.name == NULL && ip_server2.name == NULL) ||
	    ip_listen.name) {
		err = ip_setup_addr(&ip_listen);
	}
	if (ip_server.name != NULL && err == 0) {
		err = ip_setup_addr(&ip_server);
	}
	if (ip_server2.name != NULL && err == 0) {
		err = ip_setup_addr(&ip_server2);
	}
	if (err != 0) {
		ip_addr_cleanup();
	}
	return (err);
}

/*
 * Timeout handler for the transport module.  We use these types of timeouts:
 *
 * (a) arg is ip_cinfo_t: attempt ip_xprt_setup(), re-install timeout to retry
 * (b) arg is ip_xprt_t, FMD_XPRT_SUSPENDED: call fmd_xprt_resume() on arg
 * (c) arg is ip_xprt_t, !FMD_XPRT_SUSPENDED: call ip_xprt_destroy() on arg
 * (d) arg is NULL, ignore as this shouldn't happen
 *
 * Case (c) is required as we need to cause the module's main thread, which
 * runs this timeout handler, to join with the transport's auxiliary thread.
 * If the connection is a client then a timer will be installed to retry
 * connecting to the server.
 */
static void
ip_timeout(fmd_hdl_t *hdl, id_t id, void *arg) {
	int install_timer;
	ip_cinfo_t *cinfo;
	ip_xprt_t *ipx;

	if (arg == NULL) {
		fmd_hdl_error(hdl, "ip_timeout failed because hg arg is NULL");
	} else if (arg == &ip_server || arg == &ip_server2 ||
	    arg == &ip_listen) {
		ip_debug(IP_DEBUG_FINER,
			"Enter ip_timeout (a) install new timer");
		if (ip_xprt_setup(hdl, arg) != 0)
			(void) fmd_timer_install(hdl, arg, NULL, ip_sleep);
	} else {
		ipx = arg;
		if (ipx->ipx_flags & FMD_XPRT_SUSPENDED) {
			ip_debug(IP_DEBUG_FINE, "timer %d waking ipx %p",
				(int)id, arg);
			ipx->ipx_flags &= ~FMD_XPRT_SUSPENDED;
			fmd_xprt_resume(hdl, ipx->ipx_xprt);
		} else {
			ip_debug(IP_DEBUG_FINE, "timer %d closing ipx %p",
				(int)id, arg);
			cinfo = ipx->ipx_cinfo;
			install_timer = (ipx->ipx_flags & FMD_XPRT_ACCEPT) !=
				FMD_XPRT_ACCEPT;
			ip_xprt_destroy(ipx);
			if (install_timer)
				(void) fmd_timer_install(
					hdl, cinfo, NULL, ip_sleep);
		}
	}
}

static const fmd_prop_t fmd_props[] = {
	{ "ip_authority", FMD_TYPE_STRING, NULL },
	{ "ip_bufsize", FMD_TYPE_SIZE, "4k" },
	{ "ip_burp", FMD_TYPE_TIME, "0" },
	{ "ip_enable", FMD_TYPE_BOOL, "false" },
	{ "ip_mtbf", FMD_TYPE_INT32, "0" },
	{ "ip_external", FMD_TYPE_BOOL, "true" },
	{ "ip_no_remote_repair", FMD_TYPE_BOOL, "true" },
	{ "ip_hconly", FMD_TYPE_BOOL, "false" },
	{ "ip_rdonly", FMD_TYPE_BOOL, "false" },
	{ "ip_hc_present_only", FMD_TYPE_BOOL, "false" },
	{ "ip_domain_name", FMD_TYPE_STRING, NULL },
	{ "ip_port", FMD_TYPE_STRING, "664" },
	{ "ip_qlen", FMD_TYPE_INT32, "32" },
	{ "ip_retry", FMD_TYPE_INT32, "-1" },	    /* -1=forever */
	{ "ip_server", FMD_TYPE_STRING, NULL },	    /* server name */
	{ "ip_server2", FMD_TYPE_STRING, NULL },    /* secondary server name */
	{ "ip_sleep", FMD_TYPE_TIME, "10s" },
	{ "ip_translate", FMD_TYPE_BOOL, "false" },
	{ "ip_bind_addr", FMD_TYPE_STRING, NULL },  /* network interface addr */
	{ "ip_debug_level", FMD_TYPE_INT32, "1" },  /* debug levels 0-3 */
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	ip_fmdo_recv,		/* fmdo_recv */
	ip_timeout,		/* fmdo_timeout */
	NULL,			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	ip_fmdo_send,		/* fmdo_send */
};

static const fmd_hdl_info_t fmd_info = {
	"IP Transport Agent", "1.0", &fmd_ops, fmd_props
};

/*
 * Initialize the ip-transport module as either a server or a client.  Note
 * that the ip-transport module is not enabled by default under Solaris:
 * at present we require a developer or tool to "setprop ip_enable true".
 * If ip-transport is needed in the future out-of-the-box on one or more Sun
 * platforms, the code to check 'ip_enable' should be replaced with:
 *
 * (a) configuring ip-transport to operate in client mode by default,
 * (b) a platform-specific configuration mechanism, or
 * (c) a means to assure security and prevent denial-of-service attacks.
 *
 * Note that (c) is only an issue when the transport module operates
 * in server mode (i.e. with the ip_server property set to NULL) on a
 * generic Solaris system which may be exposed directly to the Internet.
 * The property ip_bind_addr can be used to define a private network interface
 * to use so that the service is not exposed to the Internet.
 */
void
_fmd_init(fmd_hdl_t *hdl)
{
	char *auth, *p, *q, *r, *s;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* failed to register handle */

	if (fmd_prop_get_int32(hdl, "ip_enable") == FMD_B_FALSE) {
		fmd_hdl_unregister(hdl);
		return;
	}

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (ip_stat) / sizeof (fmd_stat_t), (fmd_stat_t *)&ip_stat);

	ip_hdl = hdl;
	(void) pthread_mutex_init(&ip_lock, NULL);

	ip_burp = fmd_prop_get_int64(hdl, "ip_burp");
	ip_mtbf = fmd_prop_get_int32(hdl, "ip_mtbf");
	ip_external = fmd_prop_get_int32(hdl, "ip_external");
	ip_no_remote_repair = fmd_prop_get_int32(hdl, "ip_no_remote_repair");
	ip_hconly = fmd_prop_get_int32(hdl, "ip_hconly");
	ip_rdonly = fmd_prop_get_int32(hdl, "ip_rdonly");
	ip_hc_present_only = fmd_prop_get_int32(hdl, "ip_hc_present_only");
	ip_domain_name = fmd_prop_get_string(hdl, "ip_domain_name");
	ip_qlen = fmd_prop_get_int32(hdl, "ip_qlen");
	ip_retry = fmd_prop_get_int32(hdl, "ip_retry");
	ip_sleep = fmd_prop_get_int64(hdl, "ip_sleep");
	ip_translate = fmd_prop_get_int32(hdl, "ip_translate");

	ip_size = (size_t)fmd_prop_get_int64(hdl, "ip_bufsize");
	ip_size = MAX(ip_size, sizeof (ip_hdr_t));

	ip_listen.name = fmd_prop_get_string(hdl, "ip_bind_addr");
	ip_server.name = fmd_prop_get_string(hdl, "ip_server");
	ip_server2.name = fmd_prop_get_string(hdl, "ip_server2");
	ip_port = fmd_prop_get_string(hdl, "ip_port");
	ip_debug_level = fmd_prop_get_int32(hdl, "ip_debug_level");

	if (ip_setup_addrs()) {
		fmd_hdl_abort(hdl, "Unable to setup IP addresses.");
		return;
	}


	/*
	 * If ip_authority is set, tokenize this string and turn it into an
	 * FMA authority represented as a name-value pair list.  We will use
	 * this authority for all transports created by this module.  If
	 * ip_authority isn't set, we'll compute authorities on the fly.
	 */
	if ((auth = fmd_prop_get_string(hdl, "ip_authority")) != NULL) {
		(void) nvlist_alloc(&ip_auth, 0, 0);
		(void) nvlist_add_uint8(ip_auth,
		    FM_VERSION, FM_FMRI_AUTH_VERSION);

		s = alloca(strlen(auth) + 1);
		(void) strcpy(s, auth);
		fmd_prop_free_string(hdl, auth);

		for (p = strtok_r(s, ",", &q); p != NULL;
		    p = strtok_r(NULL, ",", &q)) {

			if ((r = strchr(p, '=')) == NULL) {
				ip_addr_cleanup();
				fmd_hdl_abort(hdl, "ip_authority element <%s> "
				    "must be in <name>=<value> form\n", p);
			}

			*r = '\0';
			(void) nvlist_add_string(ip_auth, p, r + 1);
			*r = '=';
		}
	}

	/*
	 * Start ip transport server to listen for clients
	 */
	if (ip_listen.addr != NULL) {
		if (ip_xprt_setup(hdl, &ip_listen) != 0) {
			(void) fmd_timer_install(hdl, &ip_listen, NULL,
			    ip_sleep);
		}
	}

	/*
	 * Call ip_xprt_setup() to connect to server(s).  If it fails and
	 * ip_retry is non-zero, install a timer to try again after
	 * 'ip_sleep' nsecs.
	 */
	if (ip_server.addr != NULL) {
		if (ip_xprt_setup(hdl, &ip_server) != 0)
			(void) fmd_timer_install(hdl, &ip_server, NULL,
			    ip_sleep);
	}
	if (ip_server2.addr != NULL) {
		if (ip_xprt_setup(hdl, &ip_server2) != 0)
			(void) fmd_timer_install(hdl, &ip_server2, NULL,
			    ip_sleep);
	}
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	ip_quit++; /* set quit flag before signalling auxiliary threads */

	while (ip_xps != NULL)
		ip_xprt_destroy(ip_xps);

	if (ip_auth != NULL)
		nvlist_free(ip_auth);
	ip_addr_cleanup();

	fmd_hdl_unregister(hdl);
}
