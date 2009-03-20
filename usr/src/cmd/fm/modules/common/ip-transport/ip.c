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

#include <fm/fmd_api.h>

#define	IP_MAGIC	"\177FMA" /* magic string identifying a packet header */
#define	IP_MAGLEN	4	/* length of magic string */

typedef struct ip_hdr {
	char iph_magic[IP_MAGLEN]; /* magic string */
	uint32_t iph_size;	/* packed size */
} ip_hdr_t;

typedef struct ip_buf {
	void *ipb_buf;		/* data buffer */
	size_t ipb_size;	/* size of buffer */
} ip_buf_t;

typedef struct ip_xprt {
	fmd_xprt_t *ipx_xprt;	/* transport handle */
	int ipx_flags;		/* transport flags */
	int ipx_fd;		/* socket file descriptor */
	int ipx_done;		/* flag indicating connection closed */
	pthread_t ipx_tid;	/* recv-side auxiliary thread */
	ip_buf_t ipx_sndbuf;	/* buffer for sending events */
	ip_buf_t ipx_rcvbuf;	/* buffer for receiving events */
	struct ip_xprt *ipx_next; /* next ip_xprt in global list */
} ip_xprt_t;

typedef struct ip_stat {
	fmd_stat_t ips_accfail;	/* failed accepts */
	fmd_stat_t ips_badmagic; /* invalid packet headers */
	fmd_stat_t ips_packfail; /* failed packs */
	fmd_stat_t ips_unpackfail; /* failed unpacks */
} ip_stat_t;

static void ip_xprt_create(fmd_xprt_t *, int, int);
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
static char *ip_host;		/* host to connect to (or NULL if server) */
static char *ip_port;		/* port to connect to (or bind to if server) */
static struct addrinfo *ip_ail; /* addr info list for ip_host/ip_port */
static uint_t ip_retry;		/* retry count for ip_xprt_setup() */
static hrtime_t ip_sleep;	/* sleep delay for ip_xprt_setup() */

/*
 * Allocate space in ipx_sndbuf for a header and a packed XDR encoding of
 * the specified nvlist, and then send the buffer to our remote peer.
 */
/*ARGSUSED*/
static int
ip_xprt_send(fmd_hdl_t *hdl, fmd_xprt_t *xp, fmd_event_t *ep, nvlist_t *nvl)
{
	ip_xprt_t *ipx = fmd_xprt_getspecific(hdl, xp);

	size_t size, nvsize;
	char *buf, *nvbuf;
	ip_hdr_t *iph;
	ssize_t r, n;
	int err;

	/*
	 * For testing purposes, if ip_mtbf is non-zero, use this to pseudo-
	 * randomly simulate the need for retries.  If ip_burp is also set,
	 * then we also suspend the transport for a bit and wake it up again.
	 */
	if (ip_mtbf != 0 && gethrtime() % ip_mtbf == 0) {
		if (ip_burp != 0) {
			fmd_hdl_debug(ip_hdl, "burping ipx %p", (void *)ipx);
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
				fmd_hdl_debug(ip_hdl,
				    "failed to send on ipx %p", (void *)ipx);
				return (FMD_SEND_FAILED);
			}
			continue;
		}
		buf += n;
		r -= n;
	}

	return (FMD_SEND_SUCCESS);
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
				fmd_hdl_debug(ip_hdl,
				    "failed to recv on ipx %p", (void *)ipx);
			}
			continue;
		}

		buf += n;
		r -= n;
	}

	return (r ? NULL: ipx->ipx_rcvbuf.ipb_buf);
}

static nvlist_t *
ip_xprt_auth(const struct sockaddr *sap)
{
	const struct sockaddr_in6 *sin6 = (const void *)sap;
	const struct sockaddr_in *sin = (const void *)sap;

	char buf[INET6_ADDRSTRLEN + 16];
	struct in_addr v4addr;
	in_port_t port;

	nvlist_t *nvl;
	size_t n;
	int err;

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
	fmd_hdl_debug(ip_hdl, "ip_authority %s=%s\n", FM_FMRI_AUTH_SERVER, buf);

	(void) nvlist_add_uint8(nvl, FM_VERSION, FM_FMRI_AUTH_VERSION);
	(void) nvlist_add_string(nvl, FM_FMRI_AUTH_SERVER, buf);

	return (nvl);
}

static void
ip_xprt_accept(ip_xprt_t *ipx)
{
	struct sockaddr_storage sa;
	socklen_t salen = sizeof (sa);
	fmd_xprt_t *xp;
	int fd;

	if ((fd = accept(ipx->ipx_fd, (struct sockaddr *)&sa, &salen)) == -1) {
		fmd_hdl_error(ip_hdl, "failed to accept connection");
		ip_stat.ips_accfail.fmds_value.ui64++;
		return;
	}

	xp = fmd_xprt_open(ip_hdl, ipx->ipx_flags,
	    ip_xprt_auth((struct sockaddr *)&sa), NULL);
	ip_xprt_create(xp, fd, ipx->ipx_flags);
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
		    "invalid hdr magic %x.%x.%x.%x from transport %p\n",
		    iph->iph_magic[0], iph->iph_magic[1], iph->iph_magic[2],
		    iph->iph_magic[3], (void *)ipx->ipx_xprt);
		ip_stat.ips_badmagic.fmds_value.ui64++;
		return;
	}

	size = ntohl(iph->iph_size);

	if ((buf = ip_xprt_recv(ipx, size)) == NULL)
		return; /* connection broken */

	if ((err = nvlist_unpack(buf, size, &nvl, 0)) != 0) {
		fmd_hdl_error(ip_hdl, "failed to unpack event from "
		    "transport %p: %s\n", (void *)ipx->ipx_xprt, strerror(err));
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
}

static void
ip_xprt_thread(void *arg)
{
	ip_xprt_t *ipx = arg;
	struct sockaddr_storage sa;
	socklen_t salen = sizeof (sa);
	struct pollfd pfd;
	id_t id;

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
			fmd_hdl_debug(ip_hdl, "hangup fd %d\n", ipx->ipx_fd);
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
			}

			ipx->ipx_xprt = fmd_xprt_open(ip_hdl, ipx->ipx_flags,
			    ip_xprt_auth((struct sockaddr *)&sa), ipx);

			fmd_hdl_debug(ip_hdl, "connect fd %d\n", ipx->ipx_fd);
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
	fmd_hdl_debug(ip_hdl, "close fd %d (timer %d)\n", ipx->ipx_fd, (int)id);
}

static void
ip_xprt_create(fmd_xprt_t *xp, int fd, int flags)
{
	ip_xprt_t *ipx = fmd_hdl_zalloc(ip_hdl, sizeof (ip_xprt_t), FMD_SLEEP);

	ipx->ipx_xprt = xp;
	ipx->ipx_flags = flags;
	ipx->ipx_fd = fd;
	ipx->ipx_tid = fmd_thr_create(ip_hdl, ip_xprt_thread, ipx);

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
	fmd_hdl_free(ip_hdl, ipx, sizeof (ip_xprt_t));
}

/*
 * Loop through the addresses that were returned by getaddrinfo() in _fmd_init
 * and for each one attempt to create a socket and initialize it.  If we are
 * successful, return zero.  If we fail, we check ip_retry: if it is non-zero
 * we return the last errno and let our caller retry ip_xprt_setup() later.  If
 * ip_retry reaches zero, we call fmd_hdl_abort() with an appropriate message.
 */
static int
ip_xprt_setup(fmd_hdl_t *hdl)
{
	int err, fd, oflags, xflags, optval = 1;
	struct addrinfo *aip;
	const char *s1, *s2;

	/*
	 * Set up flags as specified in the .conf file. Note that these are
	 * mostly only used for testing purposes, allowing the transport to
	 * be set up in various modes.
	 */
	if (ip_host != NULL)
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

	for (aip = ip_ail; aip != NULL; aip = aip->ai_next) {
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
			err = connect(fd, aip->ai_addr,
			    aip->ai_addrlen) != 0 && errno != EINPROGRESS;
		}

		if (err == 0) {
			ip_xprt_create(NULL, fd, xflags);
			freeaddrinfo(ip_ail);
			ip_ail = NULL;
			return (0);
		}

		err = errno;
		(void) close(fd);
	}

	if (ip_host != NULL) {
		s1 = "failed to connect to";
		s2 = ip_host;
	} else {
		s1 = "failed to listen on";
		s2 = ip_port;
	}

	if (err == EACCES || ip_retry-- == 0)
		fmd_hdl_abort(hdl, "%s %s: %s\n", s1, s2, strerror(err));

	fmd_hdl_debug(hdl, "%s %s: %s (will retry)\n", s1, s2, strerror(err));
	return (err);
}

/*
 * Timeout handler for the transport module.  We use three types of timeouts:
 *
 * (a) arg is NULL: attempt ip_xprt_setup(), re-install timeout to retry
 * (b) arg is non-NULL, FMD_XPRT_SUSPENDED: call fmd_xprt_resume() on arg
 * (c) arg is non-NULL, !FMD_XPRT_SUSPENDED: call ip_xprt_destroy() on arg
 *
 * Case (c) is required as we need to cause the module's main thread, which
 * runs this timeout handler, to join with the transport's auxiliary thread.
 */
static void
ip_timeout(fmd_hdl_t *hdl, id_t id, void *arg)
{
	ip_xprt_t *ipx = arg;

	if (ipx == NULL) {
		if (ip_xprt_setup(hdl) != 0)
			(void) fmd_timer_install(hdl, NULL, NULL, ip_sleep);
	} else if (ipx->ipx_flags & FMD_XPRT_SUSPENDED) {
		fmd_hdl_debug(hdl, "timer %d waking ipx %p\n", (int)id, arg);
		ipx->ipx_flags &= ~FMD_XPRT_SUSPENDED;
		fmd_xprt_resume(hdl, ipx->ipx_xprt);
	} else {
		fmd_hdl_debug(hdl, "timer %d closing ipx %p\n", (int)id, arg);
		ip_xprt_destroy(ipx);
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
	{ "ip_retry", FMD_TYPE_UINT32, "50" },
	{ "ip_server", FMD_TYPE_STRING, NULL },
	{ "ip_sleep", FMD_TYPE_TIME, "10s" },
	{ "ip_translate", FMD_TYPE_BOOL, "false" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	NULL,			/* fmdo_recv */
	ip_timeout,		/* fmdo_timeout */
	NULL,			/* fmdo_close */
	NULL,			/* fmdo_stats */
	NULL,			/* fmdo_gc */
	ip_xprt_send,		/* fmdo_send */
};

static const fmd_hdl_info_t fmd_info = {
	"IP Transport Agent", "1.0", &fmd_ops, fmd_props
};

/*
 * Initialize the ip-transport module as either a server or a client.  Note
 * that the ip-transport module is not enabled by default under Solaris:
 * at present we require a developer or tool to setprop ip_enable=true.
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
 */
void
_fmd_init(fmd_hdl_t *hdl)
{
	struct addrinfo aih;
	char *auth, *p, *q, *r, *s;
	int err;

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

	ip_host = fmd_prop_get_string(hdl, "ip_server");
	ip_port = fmd_prop_get_string(hdl, "ip_port");

	bzero(&aih, sizeof (aih));
	aih.ai_flags = AI_ADDRCONFIG;
	aih.ai_family = AF_UNSPEC;
	aih.ai_socktype = SOCK_STREAM;

	if (ip_host != NULL)
		fmd_hdl_debug(hdl, "resolving %s:%s\n", ip_host, ip_port);
	else
		aih.ai_flags |= AI_PASSIVE;

	err = getaddrinfo(ip_host, ip_port, &aih, &ip_ail);

	if (err != 0) {
		fmd_prop_free_string(hdl, ip_host);
		fmd_prop_free_string(hdl, ip_port);

		fmd_hdl_abort(hdl, "failed to resolve host %s port %s: %s\n",
		    ip_host ? ip_host : "<none>", ip_port, gai_strerror(err));
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
				fmd_prop_free_string(hdl, ip_host);
				fmd_prop_free_string(hdl, ip_port);
				freeaddrinfo(ip_ail);

				fmd_hdl_abort(hdl, "ip_authority element <%s> "
				    "must be in <name>=<value> form\n", p);
			}

			*r = '\0';
			(void) nvlist_add_string(ip_auth, p, r + 1);
			*r = '=';
		}
	}

	/*
	 * Call ip_xprt_setup() to connect or bind.  If it fails and ip_retry
	 * is non-zero, install a timer to try again after 'ip_sleep' nsecs.
	 */
	if (ip_xprt_setup(hdl) != 0)
		(void) fmd_timer_install(hdl, NULL, NULL, ip_sleep);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	ip_quit++; /* set quit flag before signalling auxiliary threads */

	while (ip_xps != NULL)
		ip_xprt_destroy(ip_xps);

	if (ip_auth != NULL)
		nvlist_free(ip_auth);
	if (ip_ail != NULL)
		freeaddrinfo(ip_ail);

	fmd_prop_free_string(hdl, ip_host);
	fmd_prop_free_string(hdl, ip_port);

	fmd_hdl_unregister(hdl);
}
