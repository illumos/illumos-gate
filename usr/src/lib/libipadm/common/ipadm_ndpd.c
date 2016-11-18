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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

/*
 * This file contains the functions that are required for communicating
 * with in.ndpd while creating autoconfigured addresses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <ipadm_ndpd.h>
#include "libipadm_impl.h"

#define	NDPDTIMEOUT		5000
#define	PREFIXLEN_LINKLOCAL	10

static ipadm_status_t	i_ipadm_create_linklocal(ipadm_handle_t,
			    ipadm_addrobj_t);
static void		i_ipadm_make_linklocal(struct sockaddr_in6 *,
			    const struct in6_addr *);
static ipadm_status_t	i_ipadm_send_ndpd_cmd(const char *,
			    const struct ipadm_addrobj_s *, int);

/*
 * Sends message to in.ndpd asking not to do autoconf for the given interface,
 * until IPADM_CREATE_ADDRS or IPADM_ENABLE_AUTOCONF is sent.
 */
ipadm_status_t
i_ipadm_disable_autoconf(const char *ifname)
{
	return (i_ipadm_send_ndpd_cmd(ifname, NULL, IPADM_DISABLE_AUTOCONF));
}

/*
 * Sends message to in.ndpd to enable autoconf for the given interface,
 * until another IPADM_DISABLE_AUTOCONF is sent.
 */
ipadm_status_t
i_ipadm_enable_autoconf(const char *ifname)
{
	return (i_ipadm_send_ndpd_cmd(ifname, NULL, IPADM_ENABLE_AUTOCONF));
}

ipadm_status_t
i_ipadm_create_ipv6addrs(ipadm_handle_t iph, ipadm_addrobj_t addr,
    uint32_t i_flags)
{
	ipadm_status_t status;

	/*
	 * Create the link local based on the given token. If the same intfid
	 * was already used with a different address object, this step will
	 * fail.
	 */
	status = i_ipadm_create_linklocal(iph, addr);
	if (status != IPADM_SUCCESS)
		return (status);

	/*
	 * Request in.ndpd to start the autoconfiguration.
	 * If autoconfiguration was already started by another means (e.g.
	 * "ifconfig" ), in.ndpd will return EEXIST.
	 */
	if (addr->ipadm_stateless || addr->ipadm_stateful) {
		status = i_ipadm_send_ndpd_cmd(addr->ipadm_ifname, addr,
		    IPADM_CREATE_ADDRS);
		if (status != IPADM_SUCCESS &&
		    status != IPADM_NDPD_NOT_RUNNING) {
			(void) i_ipadm_delete_addr(iph, addr);
			return (status);
		}
	}

	/* Persist the intfid. */
	status = i_ipadm_addr_persist(iph, addr, B_FALSE, i_flags, NULL);
	if (status != IPADM_SUCCESS) {
		(void) i_ipadm_delete_addr(iph, addr);
		(void) i_ipadm_send_ndpd_cmd(addr->ipadm_ifname, addr,
		    IPADM_DELETE_ADDRS);
	}

	return (status);
}

ipadm_status_t
i_ipadm_delete_ipv6addrs(ipadm_handle_t iph, ipadm_addrobj_t ipaddr)
{
	ipadm_status_t status;

	/*
	 * Send a msg to in.ndpd to remove the autoconfigured addresses,
	 * and delete the link local that was created.
	 */
	status = i_ipadm_send_ndpd_cmd(ipaddr->ipadm_ifname, ipaddr,
	    IPADM_DELETE_ADDRS);
	if (status == IPADM_NDPD_NOT_RUNNING)
		status = IPADM_SUCCESS;
	if (status == IPADM_SUCCESS)
		status = i_ipadm_delete_addr(iph, ipaddr);

	return (status);
}

static ipadm_status_t
i_ipadm_create_linklocal(ipadm_handle_t iph, ipadm_addrobj_t addr)
{
	boolean_t addif = B_FALSE;
	struct sockaddr_in6 *sin6;
	struct lifreq lifr;
	int err;
	ipadm_status_t status;
	in6_addr_t ll_template = {0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	/*
	 * Create a logical interface if needed.
	 */
retry:
	status = i_ipadm_do_addif(iph, addr);
	if (status != IPADM_SUCCESS)
		return (status);
	if (!(iph->iph_flags & IPH_INIT)) {
		status = i_ipadm_setlifnum_addrobj(iph, addr);
		if (status == IPADM_ADDROBJ_EXISTS)
			goto retry;
		if (status != IPADM_SUCCESS)
			return (status);
	}

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, addr->ipadm_ifname, LIFNAMSIZ);
	i_ipadm_addrobj2lifname(addr, lifr.lifr_name, sizeof (lifr.lifr_name));
	sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;

	/* Create the link-local address */
	bzero(&lifr.lifr_addr, sizeof (lifr.lifr_addr));
	(void) plen2mask(PREFIXLEN_LINKLOCAL, AF_INET6,
	    (struct sockaddr *)&lifr.lifr_addr);
	if ((err = ioctl(iph->iph_sock6, SIOCSLIFNETMASK, (caddr_t)&lifr)) < 0)
		goto fail;
	if (addr->ipadm_intfidlen == 0) {
		/*
		 * If we have to use the default interface id,
		 * we just need to set the prefix to the link-local prefix.
		 * SIOCSLIFPREFIX sets the address with the given prefix
		 * and the default interface id.
		 */
		sin6->sin6_addr = ll_template;
		err = ioctl(iph->iph_sock6, SIOCSLIFPREFIX, (caddr_t)&lifr);
		if (err < 0)
			goto fail;
	} else {
		/* Make a linklocal address in sin6 and set it */
		i_ipadm_make_linklocal(sin6, &addr->ipadm_intfid.sin6_addr);
		err = ioctl(iph->iph_sock6, SIOCSLIFADDR, (caddr_t)&lifr);
		if (err < 0)
			goto fail;
	}
	if ((err = ioctl(iph->iph_sock6, SIOCGLIFFLAGS, (char *)&lifr)) < 0)
		goto fail;
	lifr.lifr_flags |= IFF_UP;
	if ((err = ioctl(iph->iph_sock6, SIOCSLIFFLAGS, (char *)&lifr)) < 0)
		goto fail;
	return (IPADM_SUCCESS);

fail:
	if (errno == EEXIST)
		status = IPADM_ADDRCONF_EXISTS;
	else
		status = ipadm_errno2status(errno);
	/* Remove the linklocal that was created. */
	if (addif) {
		(void) ioctl(iph->iph_sock6, SIOCLIFREMOVEIF, (caddr_t)&lifr);
	} else {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		lifr.lifr_flags &= ~IFF_UP;
		(void) ioctl(iph->iph_sock6, SIOCSLIFFLAGS, (caddr_t)&lifr);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = in6addr_any;
		(void) ioctl(iph->iph_sock6, SIOCSLIFADDR, (caddr_t)&lifr);
	}
	return (status);
}

/*
 * Make a linklocal address based on the given intfid and copy it into
 * the output parameter `sin6'.
 */
static void
i_ipadm_make_linklocal(struct sockaddr_in6 *sin6, const struct in6_addr *intfid)
{
	int i;
	in6_addr_t ll_template = {0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = *intfid;
	for (i = 0; i < 4; i++) {
		sin6->sin6_addr.s6_addr[i] =
		    sin6->sin6_addr.s6_addr[i] | ll_template.s6_addr[i];
	}
}

/*
 * Function that forms an ndpd msg and sends it to the in.ndpd daemon's loopback
 * listener socket.
 */
static ipadm_status_t
i_ipadm_send_ndpd_cmd(const char *ifname, const struct ipadm_addrobj_s *addr,
    int cmd)
{
	int fd;
	struct sockaddr_un servaddr;
	int flags;
	ipadm_ndpd_msg_t msg;
	int retval;

	if (addr == NULL &&
	    (cmd == IPADM_CREATE_ADDRS || cmd == IPADM_DELETE_ADDRS)) {
		return (IPADM_INVALID_ARG);
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		return (IPADM_FAILURE);

	/* Put the socket in non-blocking mode */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags != -1)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	/* Connect to in.ndpd */
	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;
	(void) strlcpy(servaddr.sun_path, IPADM_UDS_PATH,
	    sizeof (servaddr.sun_path));
	if (connect(fd, (struct sockaddr *)&servaddr, sizeof (servaddr)) == -1)
		goto fail;

	bzero(&msg, sizeof (msg));
	msg.inm_cmd = cmd;
	(void) strlcpy(msg.inm_ifname, ifname, sizeof (msg.inm_ifname));
	if (addr != NULL) {
		msg.inm_intfid = addr->ipadm_intfid;
		msg.inm_intfidlen = addr->ipadm_intfidlen;
		msg.inm_stateless = addr->ipadm_stateless;
		msg.inm_stateful = addr->ipadm_stateful;
		if (cmd == IPADM_CREATE_ADDRS) {
			(void) strlcpy(msg.inm_aobjname, addr->ipadm_aobjname,
			    sizeof (msg.inm_aobjname));
		}
	}
	if (ipadm_ndpd_write(fd, &msg, sizeof (msg)) < 0)
		goto fail;
	if (ipadm_ndpd_read(fd, &retval, sizeof (retval)) < 0)
		goto fail;
	(void) close(fd);
	if (cmd == IPADM_CREATE_ADDRS && retval == EEXIST)
		return (IPADM_ADDRCONF_EXISTS);
	return (ipadm_errno2status(retval));
fail:
	(void) close(fd);
	return (IPADM_NDPD_NOT_RUNNING);
}

/*
 * Attempt to read `buflen' worth of bytes from `fd' into the buffer pointed
 * to by `buf'.
 */
int
ipadm_ndpd_read(int fd, void *buffer, size_t buflen)
{
	int		retval;
	ssize_t		nbytes = 0;	/* total bytes processed */
	ssize_t		prbytes;	/* per-round bytes processed */
	struct pollfd	pfd;

	while (nbytes < buflen) {

		pfd.fd = fd;
		pfd.events = POLLIN;

		/*
		 * Wait for data to come in or for the timeout to fire.
		 */
		retval = poll(&pfd, 1, NDPDTIMEOUT);
		if (retval <= 0) {
			if (retval == 0)
				errno = ETIME;
			break;
		}

		/*
		 * Descriptor is ready; have at it.
		 */
		prbytes = read(fd, (caddr_t)buffer + nbytes, buflen - nbytes);
		if (prbytes <= 0) {
			if (prbytes == -1 && errno == EINTR)
				continue;
			break;
		}
		nbytes += prbytes;
	}

	return (nbytes == buflen ? 0 : -1);
}

/*
 * Write `buflen' bytes from `buffer' to open file `fd'.  Returns 0
 * if all requested bytes were written, or an error code if not.
 */
int
ipadm_ndpd_write(int fd, const void *buffer, size_t buflen)
{
	size_t		nwritten;
	ssize_t		nbytes;
	const char	*buf = buffer;

	for (nwritten = 0; nwritten < buflen; nwritten += nbytes) {
		nbytes = write(fd, &buf[nwritten], buflen - nwritten);
		if (nbytes == -1)
			return (-1);
		if (nbytes == 0) {
			errno = EIO;
			return (-1);
		}
	}

	assert(nwritten == buflen);
	return (0);
}
