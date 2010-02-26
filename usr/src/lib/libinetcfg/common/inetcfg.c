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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/varargs.h>
#include <net/route.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <arpa/inet.h>
#include <libintl.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlpi.h>
#include <libinetutil.h>
#include <zone.h>

#include <inetcfg.h>

#define	ICFG_SOCKADDR_LEN(protocol) \
	(protocol == AF_INET) ? \
	    (socklen_t)sizeof (struct sockaddr_in) : \
	    (socklen_t)sizeof (struct sockaddr_in6)

#define	ICFG_LOGICAL_SEP	':'
#define	LOOPBACK_IF		"lo0"
#define	ARP_MOD_NAME		"arp"

/*
 * Maximum amount of time (in milliseconds) to wait for Duplicate Address
 * Detection to complete in the kernel.
 */
#define	DAD_WAIT_TIME	5000

/* error codes and text descriiption */
static struct icfg_error_info {
	icfg_error_t	error_code;
	const char	*error_desc;
} icfg_errors[] = {
	{ ICFG_SUCCESS,		"No error occurred" },
	{ ICFG_FAILURE,		"Generic failure" },
	{ ICFG_NO_MEMORY,	"Insufficient memory" },
	{ ICFG_NOT_TUNNEL,	"Tunnel operation attempted on non-tunnel" },
	{ ICFG_NOT_SET,		"Could not return non-existent value" },
	{ ICFG_BAD_ADDR,	"Invalid address" },
	{ ICFG_BAD_PROTOCOL,	"Wrong protocol family for operation" },
	{ ICFG_DAD_FAILED,	"Duplicate address detection failure" },
	{ ICFG_DAD_FOUND,	"Duplicate address detected" },
	{ ICFG_IF_UP,		"Interface is up" },
	{ ICFG_EXISTS,		"Interface already exists" },
	{ ICFG_NO_EXIST,	"Interface does not exist" },
	{ ICFG_INVALID_ARG,	"Invalid argument" },
	{ ICFG_INVALID_NAME,	"Invalid name" },
	{ ICFG_DLPI_INVALID_LINK, "Link does not exist" },
	{ ICFG_DLPI_FAILURE,	"DLPI error" },
	{ ICFG_NO_PLUMB_IP,	"Could not plumb IP stream" },
	{ ICFG_NO_PLUMB_ARP,	"Could not plumb ARP stream" },
	{ ICFG_NO_UNPLUMB_IP,	"Could not unplumb IP stream" },
	{ ICFG_NO_UNPLUMB_ARP,	"Could not unplumb ARP stream" },
	{ ICFG_NO_IP_MUX,	"No IP mux set" },
	{ 0,			NULL }
};

/* convert libdlpi error to libinetcfg error */
icfg_error_t
dlpi_error_to_icfg_error(int err)
{
	switch (err) {
	case DLPI_SUCCESS:
		return (ICFG_SUCCESS);
	case DLPI_ELINKNAMEINVAL:
		return (ICFG_INVALID_NAME);
	case DLPI_ENOLINK:
	case DLPI_EBADLINK:
		return (ICFG_DLPI_INVALID_LINK);
	case DLPI_EINVAL:
	case DLPI_ENOTSTYLE2:
	case DLPI_EBADMSG:
	case DLPI_EINHANDLE:
	case DLPI_EVERNOTSUP:
	case DLPI_EMODENOTSUP:
		return (ICFG_INVALID_ARG);
	case DL_BADADDR:
		return (ICFG_BAD_ADDR);
	case DL_SYSERR:
		switch (errno) {
		case ENOMEM:
			return (ICFG_NO_MEMORY);
		case EINVAL:
			return (ICFG_INVALID_ARG);
		}
		/* FALLTHROUGH */
	case DLPI_FAILURE:
	default:
		return (ICFG_DLPI_FAILURE);
	}
}

/*
 * Convert a prefix length to a netmask. Note that the mask array
 * should zero'ed by the caller.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
static int
prefixlen_to_mask(int prefixlen, int maxlen, uchar_t *mask)
{
	if ((prefixlen < 0) || (prefixlen > maxlen)) {
		errno = EINVAL;
		return (ICFG_FAILURE);
	}

	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*mask++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*mask |= 1 << (8 - prefixlen);
		prefixlen--;
	}
	return (ICFG_SUCCESS);
}

/*
 * Copies an an IPv4 or IPv6 address from a sockaddr_storage
 * structure into the appropriate sockaddr structure for the
 * address family (sockaddr_in for AF_INET or sockaddr_in6 for
 * AF_INET6) and verifies that the structure size is large enough
 * for the copy.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
static int
to_sockaddr(sa_family_t af, struct sockaddr *addr,
    socklen_t *addrlen, const struct sockaddr_storage *ssaddr)
{
	socklen_t len;

	assert((af == AF_INET) || (af == AF_INET6));

	len = ICFG_SOCKADDR_LEN(af);
	if (*addrlen < len) {
		errno = ENOSPC;
		return (ICFG_FAILURE);
	}

	(void) memcpy(addr, ssaddr, len);
	*addrlen = len;

	return (ICFG_SUCCESS);
}

/*
 * Copies an an IPv4 or IPv6 address frrom its sockaddr structure
 * into a sockaddr_storage structure and does a simple size of
 * structure verification.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
static int
to_sockaddr_storage(sa_family_t af, const struct sockaddr *addr,
    socklen_t addrlen, struct sockaddr_storage *ssaddr)
{
	socklen_t len;

	assert((af == AF_INET) || (af == AF_INET6));

	len = ICFG_SOCKADDR_LEN(af);
	if (addrlen < len) {
		errno = EINVAL;
		return (ICFG_FAILURE);
	}

	(void) memcpy(ssaddr, addr, len);

	return (ICFG_SUCCESS);
}

/*
 * Return the appropriate error message for a given ICFG error.
 */
const char *
icfg_errmsg(int errcode)
{
	int i;

	for (i = 0; icfg_errors[i].error_desc != NULL; i++) {
		if (errcode == icfg_errors[i].error_code)
			return (dgettext(TEXT_DOMAIN,
			    icfg_errors[i].error_desc));
	}

	return (dgettext(TEXT_DOMAIN, "<unknown error>"));
}

/*
 * Opens the an interface as defined by the interface argument and returns
 * a handle to the interface via the 'handle' argument. The caller is
 * responsible for freeing resources allocated by this API by calling the
 * icfg_close() API.
 *
 * Returns: ICFG_SUCCESS, ICFG_NO_MEMORY or ICFG_FAILURE.
 */
int
icfg_open(icfg_handle_t *handle, const icfg_if_t *interface)
{
	icfg_handle_t loc_handle;
	int sock;
	sa_family_t family;
	int syserr;

	/*
	 * Make sure that a valid protocol family was specified.
	 */
	if ((interface->if_protocol != AF_INET) &&
	    (interface->if_protocol != AF_INET6)) {
		errno = EINVAL;
		return (ICFG_FAILURE);
	}

	family = interface->if_protocol;

	if ((loc_handle = calloc(1, sizeof (struct icfg_handle))) == NULL) {
		return (ICFG_NO_MEMORY);
	}

	if ((sock = socket(family, SOCK_DGRAM, 0)) < 0) {
		syserr = errno;
		free(loc_handle);
		errno = syserr;
		return (ICFG_FAILURE);
	}

	loc_handle->ifh_sock = sock;
	loc_handle->ifh_interface = *interface;

	*handle = loc_handle;

	return (ICFG_SUCCESS);
}

/*
 * Closes the interface opened by icfg_open() and releases all resources
 * associated with the handle.
 */
void
icfg_close(icfg_handle_t handle)
{
	(void) close(handle->ifh_sock);
	free(handle);
}

/*
 * Retrieves the interface name associated with the handle passed in.
 */
const char *
icfg_if_name(icfg_handle_t handle)
{
	return (handle->ifh_interface.if_name);
}

/*
 * Retrieves the protocol associated with the handle passed in.
 */
static int
icfg_if_protocol(icfg_handle_t handle)
{
	return (handle->ifh_interface.if_protocol);
}

/*
 * Any time that flags are changed on an interface where either the new or the
 * existing flags have IFF_UP set, we'll get at least one RTM_IFINFO message to
 * announce the flag status.  Typically, there are two such messages: one
 * saying that the interface is going down, and another saying that it's coming
 * back up.
 *
 * We wait here for that second message, which can take one of two forms:
 * either IFF_UP or IFF_DUPLICATE.  If something's amiss with the kernel,
 * though, we don't wait forever.  (Note that IFF_DUPLICATE is a high-order
 * bit, and we can't see it in the routing socket messages.)
 */
static int
dad_wait(icfg_handle_t handle, int rtsock)
{
	struct pollfd fds[1];
	union {
		struct if_msghdr ifm;
		char buf[1024];
	} msg;
	int index;
	int retv;
	uint64_t flags;
	hrtime_t starttime, now;

	fds[0].fd = rtsock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	if ((retv = icfg_get_index(handle, &index)) != ICFG_SUCCESS)
		return (retv);

	starttime = gethrtime();
	for (;;) {
		now = gethrtime();
		now = (now - starttime) / 1000000;
		if (now >= DAD_WAIT_TIME)
			break;
		if (poll(fds, 1, DAD_WAIT_TIME - (int)now) <= 0)
			break;
		if (read(rtsock, &msg, sizeof (msg)) <= 0)
			break;
		if (msg.ifm.ifm_type != RTM_IFINFO)
			continue;
		/* Note that ifm_index is just 16 bits */
		if (index == msg.ifm.ifm_index && (msg.ifm.ifm_flags & IFF_UP))
			return (ICFG_SUCCESS);
		if ((retv = icfg_get_flags(handle, &flags)) != ICFG_SUCCESS)
			return (retv);
		if (flags & IFF_DUPLICATE)
			return (ICFG_DAD_FOUND);
	}
	return (ICFG_DAD_FAILED);
}

/*
 * Sets the flags for the interface represented by the 'handle'
 * argument to the value contained in the 'flags' argument.
 *
 * If the new flags value will transition the interface from "down" to "up,"
 * then duplicate address detection is performed by the kernel.  This routine
 * waits to get the outcome of that test.
 *
 * Returns: ICFG_SUCCESS, ICFG_DAD_FOUND, ICFG_DAD_FAILED or ICFG_FAILURE.
 */
int
icfg_set_flags(icfg_handle_t handle, uint64_t flags)
{
	struct lifreq lifr;
	uint64_t oflags;
	int ret;
	int rtsock = -1;
	int aware = RTAW_UNDER_IPMP;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if ((ret = icfg_get_flags(handle, &oflags)) != ICFG_SUCCESS)
		return (ret);
	if (oflags == flags)
		return (ICFG_SUCCESS);

	/*
	 * Any time flags are changed on an interface that has IFF_UP set,
	 * you'll get a routing socket message.  We care about the status,
	 * though, only when the new flags are marked "up."  Since we may be
	 * changing an IPMP test address, we enable RTAW_UNDER_IPMP.
	 */
	if (flags & IFF_UP) {
		rtsock = socket(PF_ROUTE, SOCK_RAW, icfg_if_protocol(handle));
		if (rtsock != -1) {
			(void) setsockopt(rtsock, SOL_ROUTE, RT_AWARE, &aware,
			    sizeof (aware));
		}
	}

	lifr.lifr_flags = flags;
	if (ioctl(handle->ifh_sock, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		if (rtsock != -1)
			(void) close(rtsock);
		return (ICFG_FAILURE);
	}

	if (rtsock == -1) {
		return (ICFG_SUCCESS);
	} else {
		ret = dad_wait(handle, rtsock);
		(void) close(rtsock);
		return (ret);
	}
}

/*
 * Sets the metric value for the interface represented by the
 * 'handle' argument to the value contained in the 'metric'
 *  argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_set_metric(icfg_handle_t handle, int metric)
{
	struct lifreq lifr;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);
	lifr.lifr_metric = metric;

	if (ioctl(handle->ifh_sock, SIOCSLIFMETRIC, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the mtu value for the interface represented by the
 * 'handle' argument to the value contained in the 'mtu'
 * argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_set_mtu(icfg_handle_t handle, uint_t mtu)
{
	struct lifreq lifr;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);
	lifr.lifr_mtu = mtu;

	if (ioctl(handle->ifh_sock, SIOCSLIFMTU, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the index value for the interface represented by the
 * 'handle' argument to the value contained in the 'index'
 * argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_set_index(icfg_handle_t handle, int index)
{
	struct lifreq lifr;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);
	lifr.lifr_index = index;

	if (ioctl(handle->ifh_sock, SIOCSLIFINDEX, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the netmask address for the interface represented by
 * 'handle'.
 *
 * The handle must represent an IPv4 interface.
 *
 * The address will be set to the value pointed to by 'addr'.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROTOCOL or ICFG_FAILURE.
 */
int
icfg_set_netmask(icfg_handle_t handle, const struct sockaddr_in *addr)
{
	struct lifreq lifr;
	int ret;

	if (icfg_if_protocol(handle) != AF_INET) {
		return (ICFG_BAD_PROTOCOL);
	}

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(icfg_if_protocol(handle),
	    (struct sockaddr *)addr, sizeof (*addr),
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = AF_INET;

	if (ioctl(handle->ifh_sock, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the broadcast address for the interface represented by
 * 'handle'.
 *
 * The handle must represent an IPv4 interface.
 *
 * The address will be set to the value pointed to by 'addr'.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROTOCOL or ICFG_FAILURE.
 */
int
icfg_set_broadcast(icfg_handle_t handle, const struct sockaddr_in *addr)
{
	struct lifreq lifr;
	int ret;

	if (icfg_if_protocol(handle) != AF_INET) {
		return (ICFG_BAD_PROTOCOL);
	}

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(icfg_if_protocol(handle),
	    (struct sockaddr *)addr, sizeof (*addr),
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = AF_INET;

	if (ioctl(handle->ifh_sock, SIOCSLIFBRDADDR, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the prefixlen value for the interface represented by the handle
 * argument to the value contained in the 'prefixlen' argument. The
 * prefixlen is actually stored internally as a netmask value and the API
 * will convert the value contained in 'prefixlen' into the correct netmask
 * value according to the protocol family of the interface.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_set_prefixlen(icfg_handle_t handle, int prefixlen)
{
	struct lifreq lifr;

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (icfg_if_protocol(handle) == AF_INET6) {
		struct sockaddr_in6 *sin6;
		int ret;

		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		if ((ret = prefixlen_to_mask(prefixlen, IPV6_ABITS,
		    (uchar_t *)&sin6->sin6_addr)) != ICFG_SUCCESS) {
			return (ret);
		}
	} else {
		struct sockaddr_in *sin;
		int ret;

		sin = (struct sockaddr_in *)&lifr.lifr_addr;
		if ((ret = prefixlen_to_mask(prefixlen, IP_ABITS,
		    (uchar_t *)&sin->sin_addr)) != ICFG_SUCCESS) {
			return (ret);
		}
	}

	if (ioctl(handle->ifh_sock, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the address for the interface represented by 'handle'.
 *
 * The 'addr' argument points to either a sockaddr_in structure
 * (for IPv4) or a sockaddr_in6 structure (for IPv6) that holds
 * the IP address. The 'addrlen' argument gives the length of the
 * 'addr' structure.
 *
 * If the interface is an IPv6 interface and the interface is
 * already in the "up" state, then duplicate address detection
 * is performed before the address is set and is set only if no
 * duplicate address is detected.
 *
 * Returns: ICFG_SUCCESS, ICFG_FAILURE, ICFG_DAD_FOUND, ICFG_DAD_FAILED
 *          or ICFG_FAILURE.
 */
int
icfg_set_addr(icfg_handle_t handle, const struct sockaddr *addr,
    socklen_t addrlen)
{
	struct lifreq lifr;
	uint64_t flags;
	int ret;
	int rtsock = -1;
	int aware = RTAW_UNDER_IPMP;

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(icfg_if_protocol(handle), addr, addrlen,
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}

	/*
	 * Need to check duplicate address detection results if the address is
	 * up.  Since this may be an IPMP test address, enable RTAW_UNDER_IPMP.
	 */
	if ((ret = icfg_get_flags(handle, &flags)) != ICFG_SUCCESS)
		return (ret);

	if (flags & IFF_UP) {
		rtsock = socket(PF_ROUTE, SOCK_RAW, icfg_if_protocol(handle));
		if (rtsock != -1) {
			(void) setsockopt(rtsock, SOL_ROUTE, RT_AWARE, &aware,
			    sizeof (aware));
		}
	}

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCSLIFADDR, (caddr_t)&lifr) < 0) {
		if (rtsock != -1)
			(void) close(rtsock);
		return (ICFG_FAILURE);
	}

	if (rtsock == -1) {
		return (ICFG_SUCCESS);
	} else {
		ret = dad_wait(handle, rtsock);
		(void) close(rtsock);
		return (ret);
	}
}

/*
 * Sets the token for the interface represented by 'handle'.
 *
 * The handle must represent an IPv6 interface.
 *
 * The token will be set to the value contained in 'addr' and
 * its associated prefixlen will be set to 'prefixlen'.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROTOCOL or ICFG_FAILURE.
 */
int
icfg_set_token(icfg_handle_t handle, const struct sockaddr_in6 *addr,
    int prefixlen)
{
	struct lifreq lifr;
	int ret;

	if (icfg_if_protocol(handle) != AF_INET6) {
		return (ICFG_BAD_PROTOCOL);
	}

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(icfg_if_protocol(handle),
	    (struct sockaddr *)addr, sizeof (*addr),
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);
	lifr.lifr_addrlen = prefixlen;

	if (ioctl(handle->ifh_sock, SIOCSLIFTOKEN, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the subnet address for the interface represented by 'handle'.
 *
 * The 'addr' argument points to either a sockaddr_in structure
 * (for IPv4) or a sockaddr_in6 structure (for IPv6) that holds
 * the IP address. The 'addrlen' argument gives the length of the
 * 'addr' structure.
 *
 * The prefixlen of the subnet address will be set to 'prefixlen'.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_set_subnet(icfg_handle_t handle, const struct sockaddr *addr,
    socklen_t addrlen, int prefixlen)
{
	struct lifreq lifr;
	int ret;

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if ((ret = to_sockaddr_storage(icfg_if_protocol(handle), addr, addrlen,
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	lifr.lifr_addrlen = prefixlen;

	if (ioctl(handle->ifh_sock, SIOCSLIFSUBNET, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the destination address for the interface represented by
 * 'handle'.
 *
 * The 'addr' argument points to either a sockaddr_in structure
 * (for IPv4) or a sockaddr_in6 structure (for IPv6) that holds
 * the IP address. The 'addrlen' argument gives the length of the
 * 'addr' structure.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_set_dest_addr(icfg_handle_t handle, const struct sockaddr *addr,
    socklen_t addrlen)
{
	struct lifreq lifr;
	int ret;

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if ((ret = to_sockaddr_storage(icfg_if_protocol(handle), addr, addrlen,
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}

	if (ioctl(handle->ifh_sock, SIOCSLIFDSTADDR, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Returns the address and prefixlen of the interface represented
 * by 'handle'.
 *
 * The 'addr' argument is a result parameter that is filled in with
 * the requested address. The format of the 'addr' parameter is
 * determined by the address family of the interface.
 *
 * The 'addrlen' argument is a value-result parameter. Initially, it
 * contains the amount of space pointed to by 'addr'; on return it
 * contains the length in bytes of the address returned.
 *
 * Note that if 'addrlen' is not large enough for the returned address
 * value, then ICFG_FAILURE will be returned and errno will be set to ENOSPC.
 *
 * If the 'force' argument is set to B_TRUE, then non-critical errors in
 * obtaining the address will be ignored and the address will be set to
 * all 0's. Non-critical errors consist of EADDRNOTAVAIL, EAFNOSUPPORT,
 * and ENXIO.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_addr(icfg_handle_t handle, struct sockaddr *addr, socklen_t *addrlen,
    int *prefixlen, boolean_t force)
{
	struct lifreq lifr;
	int ret;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
		if (force && ((errno == EADDRNOTAVAIL) ||
		    (errno == EAFNOSUPPORT) || (errno == ENXIO))) {
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			return (ICFG_FAILURE);
		}
	}

	if ((ret = to_sockaddr(icfg_if_protocol(handle), addr, addrlen,
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	*prefixlen = lifr.lifr_addrlen;

	return (ICFG_SUCCESS);
}

/*
 * Returns the token address and the token prefixlen of the
 * interface represented by 'handle'.
 *
 * The 'addr' argument is a result parameter that is filled in
 * with the requested address.
 *
 * The 'prefixlen' argument is a result paramter that is filled
 * in with the token prefixlen.
 *
 * If the 'force' argument is set to B_TRUE, then non-critical errors in
 * obtaining the token address will be ignored and the address will be set
 * to all 0's. Non-critical errors consist of EADDRNOTAVAIL and EINVAL.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROTOCOL or ICFG_FAILURE.
 */
int
icfg_get_token(icfg_handle_t handle, struct sockaddr_in6 *addr,
    int *prefixlen, boolean_t force)
{
	struct lifreq lifr;
	socklen_t addrlen = sizeof (*addr);

	if (icfg_if_protocol(handle) != AF_INET6) {
		return (ICFG_BAD_PROTOCOL);
	}

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFTOKEN, (caddr_t)&lifr) < 0) {
		if (force && ((errno == EADDRNOTAVAIL) || (errno == EINVAL))) {
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			return (ICFG_FAILURE);
		}
	}

	*prefixlen = lifr.lifr_addrlen;
	return (to_sockaddr(icfg_if_protocol(handle), (struct sockaddr *)addr,
	    &addrlen, &lifr.lifr_addr));
}

/*
 * Returns the subnet address and the subnet prefixlen of the interface
 * represented by 'handle'.
 *
 * The 'addr' argument is a result parameter that is filled in with
 * the requested address. The format of the 'addr' parameter is
 * determined by the address family of the interface.
 *
 * The 'addrlen' argument is a value-result parameter. Initially, it
 * contains the amount of space pointed to by 'addr'; on return it
 * contains the length in bytes of the address returned.
 *
 * Note that if 'addrlen' is not large enough for the returned address
 * value, then ICFG_FAILURE will be returned and errno will be set to ENOSPC.
 *
 * If the 'force' argument is set to B_TRUE, then non-critical errors in
 * obtaining the address will be ignored and the address will be set to all
 * 0's. Non-critical errors consist of EADDRNOTAVAIL, EAFNOSUPPORT,and ENXIO.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_subnet(icfg_handle_t handle, struct sockaddr *addr,
    socklen_t *addrlen, int *prefixlen, boolean_t force)
{
	struct lifreq lifr;
	int ret;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFSUBNET, (caddr_t)&lifr) < 0) {
		if (force && ((errno == EADDRNOTAVAIL) ||
		    (errno == EAFNOSUPPORT) || (errno == ENXIO))) {
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			return (ICFG_FAILURE);
		}
	}

	if ((ret = to_sockaddr(icfg_if_protocol(handle), addr, addrlen,
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	*prefixlen = lifr.lifr_addrlen;

	return (ICFG_SUCCESS);
}

/*
 * Returns the netmask address of the interface represented by 'handle'.
 *
 * The handle must represent an IPv4 interface.
 *
 * The 'addr' argument is a result parameter that is filled in with
 * the requested address.
 *
 * If no netmask address has been set for the interface, an address of
 * all 0's will be returned.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROTOCOL or ICFG_FAILURE.
 */
int
icfg_get_netmask(icfg_handle_t handle, struct sockaddr_in *addr)
{
	struct lifreq lifr;
	socklen_t addrlen = sizeof (*addr);

	if (icfg_if_protocol(handle) != AF_INET) {
		return (ICFG_BAD_PROTOCOL);
	}

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			return (ICFG_FAILURE);
		}
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	}

	return (to_sockaddr(icfg_if_protocol(handle), (struct sockaddr *)addr,
	    &addrlen, &lifr.lifr_addr));
}

/*
 * Returns the broadcast address of the interface represented by 'handle'.
 *
 * The handle must represent an IPv4 interface.
 *
 * The 'addr' argument is a result parameter that is filled in with
 * the requested address.
 *
 * If no broadcast address has been set for the interface, an address
 * of all 0's will be returned.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROTOCOL or ICFG_FAILURE.
 */
int
icfg_get_broadcast(icfg_handle_t handle, struct sockaddr_in *addr)
{
	struct lifreq lifr;
	socklen_t addrlen = sizeof (*addr);

	if (icfg_if_protocol(handle) != AF_INET) {
		return (ICFG_BAD_PROTOCOL);
	}

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFBRDADDR, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			return (ICFG_FAILURE);
		}
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	}

	return (to_sockaddr(icfg_if_protocol(handle), (struct sockaddr *)addr,
	    &addrlen, &lifr.lifr_addr));
}

/*
 * Returns the destination address of the interface represented
 * by 'handle'.
 *
 * The 'addr' argument is a result parameter that is filled in with
 * the requested address. The format of the 'addr' parameter is
 * determined by the address family of the interface.
 *
 * The 'addrlen' argument is a value-result parameter. Initially, it
 * contains the amount of space pointed to by 'addr'; on return it
 * contains the length in bytes of the address returned.
 *
 * Note that if 'addrlen' is not large enough for the returned address
 * value, then ICFG_FAILURE will be returned and errno will be set to
 * ENOSPC.
 *
 * If no destination address has been set for the interface, an address
 * of all 0's will be returned.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_dest_addr(icfg_handle_t handle, struct sockaddr *addr,
    socklen_t *addrlen)
{
	struct lifreq lifr;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFDSTADDR, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			return (ICFG_FAILURE);
		}
		/* No destination address set yet */
		(void) memset(&lifr.lifr_dstaddr, 0,
		    sizeof (lifr.lifr_dstaddr));
	}

	return (to_sockaddr(icfg_if_protocol(handle), addr, addrlen,
	    &lifr.lifr_addr));
}

/*
 * Returns the groupname, if any, of the interface represented by the handle
 * argument into the buffer pointed to by the 'groupname' argument. The size
 * of the groupname buffer is expected to be of 'len' bytes in length and
 * should be large enough to receive the groupname of the interface
 * (i.e., LIFNAMSIZ).
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_SET or ICFG_FAILURE.
 */
int
icfg_get_groupname(icfg_handle_t handle, char *groupname, size_t len)
{
	struct lifreq lifr;

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	(void) memset(lifr.lifr_groupname, 0, sizeof (lifr.lifr_groupname));

	if (ioctl(handle->ifh_sock, SIOCGLIFGROUPNAME, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}

	if (strlen(lifr.lifr_groupname) > 0) {
		(void) strlcpy(groupname, lifr.lifr_groupname, len);
	} else {
		return (ICFG_NOT_SET);
	}

	return (ICFG_SUCCESS);
}

/*
 * Returns the groupinfo, if any, associated with the group identified in
 * the gi_grname field of the passed-in lifgr structure.  Upon successful
 * return, the lifgr structure will be populated with the associated
 * group info.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
static int
icfg_get_groupinfo(icfg_handle_t handle, lifgroupinfo_t *lifgr)
{
	if (ioctl(handle->ifh_sock, SIOCGLIFGROUPINFO, lifgr) < 0)
		return (ICFG_FAILURE);

	return (ICFG_SUCCESS);
}

/*
 * Returns the flags value of the interface represented by the handle
 * argument into the buffer pointed to by the 'flags' argument.
 *
 * Returns: ICFG_SUCCESS, ICFG_NO_EXIST or ICFG_FAILURE.
 */
int
icfg_get_flags(icfg_handle_t handle, uint64_t *flags)
{
	struct lifreq lifr;

	if (flags == NULL)
		return (ICFG_INVALID_ARG);

	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		if (errno == ENXIO)
			return (ICFG_NO_EXIST);
		else
			return (ICFG_FAILURE);
	}
	*flags = lifr.lifr_flags;

	return (ICFG_SUCCESS);
}

/*
 * Returns the metric value of the interface represented by the handle
 * argument into the buffer pointed to by the 'metric' argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_metric(icfg_handle_t handle, int *metric)
{
	struct lifreq lifr;

	if (metric == NULL)
		return (ICFG_INVALID_ARG);

	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFMETRIC, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}
	*metric = lifr.lifr_metric;

	return (ICFG_SUCCESS);
}

/*
 * Returns the mtu value of the interface represented by the handle
 * argument into the buffer pointed to by the 'mtu' argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_mtu(icfg_handle_t handle, uint_t *mtu)
{
	struct lifreq lifr;

	if (mtu == NULL)
		return (ICFG_INVALID_ARG);

	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFMTU, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}
	*mtu = lifr.lifr_mtu;

	return (ICFG_SUCCESS);
}

/*
 * Returns the index value of the interface represented by the handle
 * argument into the buffer pointed to by the 'index' argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_index(icfg_handle_t handle, int *index)
{
	struct lifreq lifr;

	if (index == NULL)
		return (ICFG_INVALID_ARG);

	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = icfg_if_protocol(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFINDEX, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}
	*index = lifr.lifr_index;

	return (ICFG_SUCCESS);
}

/*
 * Walks a list of interfaces and for  each  interface  found,  the
 * caller-supplied function 'callback()' is invoked. The iteration will be
 * interrupted if the caller-supplied function does not return  ICFG_SUCCESS.
 *
 * The 'proto' argument is used by the caller to define which interfaces are
 * to be walked by the API. The possible values for 'proto' are AF_INET,
 * AF_INET6, and AF_UNSPEC.
 *
 * The 'arg' argument is a pointer to caller-specific data.
 *
 * Returns: ICFG_SUCCESS, ICFG_FAILURE or error code returned by callback().
 */
int
icfg_iterate_if(int proto, int type, void *arg,
    int (*callback)(icfg_if_t *interface, void *arg))
{
	icfg_if_t	*if_ids;
	int		len;
	int		i;
	int		ret;

	ret = icfg_get_if_list(&if_ids, &len, proto, type);
	if (ret != ICFG_SUCCESS) {
		return (ret);
	}

	for (i = 0; i < len; i++) {
		if ((ret = callback(&if_ids[i], arg)) != ICFG_SUCCESS) {
			break;
		}
	}

	icfg_free_if_list(if_ids);

	return (ret);

}

/*
 * Returns a list of currently plumbed interfaces. The list of interfaces is
 * returned as an array of icfg_if_t structures. The number of interfaces in
 * the array will be returned via the 'numif' argument. Since the array of
 * interfaces is allocated by this API, the caller is responsible for freeing
 * the memory associated with this array by calling icfg_free_if_list().
 *
 * The 'proto' argument is used by the caller to define which interfaces are
 * to be listed by the API. The possible values for proto are AF_INET,
 * AF_INET6, and AF_UNSPEC.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROTOCOL, ICFG_NO_MEMORY or ICFG_FAILURE.
 */
static int
get_plumbed_if_list(icfg_if_t **list, int *numif, int proto) {
	int sock;
	struct lifconf lifc;
	struct lifnum lifn;
	struct lifreq *lifrp;
	char *buf;
	unsigned bufsize;
	icfg_if_t *loc_list;
	int num;
	sa_family_t lifc_family;
	int lifc_flags = LIFC_NOXMIT;
	int syserr;
	int i;

	/*
	 * Validate the protocol family.
	 */
	if ((proto != AF_UNSPEC) &&
	    (proto != AF_INET) &&
	    (proto != AF_INET6)) {
		errno = EINVAL;
		return (ICFG_BAD_PROTOCOL);
	}
	lifc_family = proto;

	/*
	 * Open a socket. Note that the AF_INET domain seems to
	 * support both IPv4 and IPv6.
	 */
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return (ICFG_FAILURE);
	}

	/*
	 * Get the number of interfaces and allocate a buffer
	 * large enough to allow the interfaces to be enumerated.
	 */
	lifn.lifn_family = lifc_family;
	lifn.lifn_flags = lifc_flags;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		syserr = errno;
		(void) close(sock);
		errno = syserr;
		return (ICFG_FAILURE);
	}
	num = lifn.lifn_count;
	bufsize = num * sizeof (struct lifreq);
	buf = malloc(bufsize);
	if (buf == NULL) {
		syserr = errno;
		(void) close(sock);
		errno = syserr;
		return (ICFG_NO_MEMORY);
	}

	/*
	 * Obtain a list of the interfaces.
	 */
	lifc.lifc_family = lifc_family;
	lifc.lifc_flags = lifc_flags;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	if (ioctl(sock, SIOCGLIFCONF, (char *)&lifc) < 0) {
		syserr = errno;
		(void) close(sock);
		free(buf);
		errno = syserr;
		return (ICFG_FAILURE);
	}
	(void) close(sock);

	bufsize = num * sizeof (icfg_if_t);
	loc_list = malloc(bufsize);
	if (loc_list == NULL) {
		syserr = errno;
		free(buf);
		errno = syserr;
		return (ICFG_NO_MEMORY);
	}

	lifrp = lifc.lifc_req;
	for (i = 0; i < num; i++, lifrp++) {
		(void) strlcpy(loc_list[i].if_name, lifrp->lifr_name,
		    sizeof (loc_list[i].if_name));
		if (lifrp->lifr_addr.ss_family == AF_INET) {
			loc_list[i].if_protocol = AF_INET;
		} else {
			loc_list[i].if_protocol = AF_INET6;
		}
	}

	*list = loc_list;
	*numif = num;

	free(buf);

	return (ICFG_SUCCESS);
}

typedef struct linklist {
	struct linklist	*ll_next;
	char		ll_name[DLPI_LINKNAME_MAX];
} linklist_t;

typedef struct linkwalk {
	linklist_t	*lw_list;
	int		lw_num;
	int		lw_err;
} linkwalk_t;

static boolean_t
add_link_list(const char *link, void *arg)
{
	linkwalk_t	*lwp = (linkwalk_t *)arg;
	linklist_t	*entry = NULL;

	if ((entry = calloc(1, sizeof (linklist_t))) == NULL) {
		lwp->lw_err = ENOMEM;
		return (B_TRUE);
	}
	(void) strlcpy(entry->ll_name, link, DLPI_LINKNAME_MAX);

	if (lwp->lw_list == NULL)
		lwp->lw_list = entry;
	else
		lwp->lw_list->ll_next = entry;

	lwp->lw_num++;
	return (B_FALSE);
}

/*
 * Returns a list of data links that can be plumbed. The list of interfaces is
 * returned as an array of icfg_if_t structures. The number of interfaces in
 * the array will be returned via the 'numif' argument.
 *
 * Returns: ICFG_SUCCESS, ICFG_NO_MEMORY or ICFG_FAILURE.
 */
static int
get_link_list(icfg_if_t **listp, int *numif) {

	linkwalk_t	lw = {NULL, 0, 0};
	linklist_t	*entry, *next;
	icfg_if_t	*list;
	int		save_errno = 0;
	int		ret = ICFG_FAILURE;

	dlpi_walk(add_link_list, &lw, 0);
	if (lw.lw_err != 0) {
		errno = lw.lw_err;
		goto done;
	}
	if (lw.lw_num == 0) {
		/* no links found, nothing else to do */
		*listp = NULL;
		*numif = 0;
		return (ICFG_SUCCESS);
	}

	list = calloc(lw.lw_num, sizeof (icfg_if_t));
	if (list == NULL) {
		ret = ICFG_NO_MEMORY;
		goto done;
	}

	*listp = list;
	for (entry = lw.lw_list; entry != NULL; entry = entry->ll_next) {
		(void) strlcpy(list->if_name, entry->ll_name,
		    sizeof (list->if_name));
		list->if_protocol = AF_UNSPEC;
		list++;
	}
	*numif = lw.lw_num;
	ret = ICFG_SUCCESS;

done:
	save_errno = errno;
	for (entry = lw.lw_list; entry != NULL; entry = next) {
		next = entry->ll_next;
		free(entry);
	}
	errno = save_errno;
	return (ret);
}

/*
 * Returns a list of network interfaces. The list of
 * interfaces is returned as an array of icfg_if_t structures.
 * The number of interfaces in the array will be returned via
 * the 'numif' argument. Since the array of interfaces is
 * allocated by this API, the caller is responsible for freeing
 * the memory associated with this array by calling
 * icfg_free_if_list().
 *
 * The 'proto' argument is used by the caller to define which
 * interfaces are to be listed by the API. The possible values
 * for 'proto' are AF_INET, AF_INET6, and AF_UNSPEC.
 *
 * The 'type' argument is used by the caller specify whether
 * to enumerate installed network interfaces or plumbed
 * network interfaces. The value for 'type' can be ICFG_PLUMBED
 * or ICFG_INSTALLED.
 */
int
icfg_get_if_list(icfg_if_t **list, int *numif, int proto, int type)
{
	if (list == NULL || numif == NULL)
		return (ICFG_INVALID_ARG);

	*list = NULL;
	*numif = 0;

	if (type == ICFG_PLUMBED) {
		return (get_plumbed_if_list(list, numif, proto));
	} else if (type == ICFG_INSTALLED) {
		return (get_link_list(list, numif));
	} else {
		errno = EINVAL;
		return (ICFG_FAILURE);
	}
}

/*
 * Frees the memory allocated by icfg_get_list().
 */
void
icfg_free_if_list(icfg_if_t *list)
{
	free(list);
	list = NULL;
}

/*
 * Determines whether or not an interface name represents
 * a logical interface or not.
 *
 * Returns: B_TRUE if logical, B_FALSE if not.
 *
 * Note: this API can be vastly improved once interface naming
 * is resolved in the future. This will do for now.
 */
boolean_t
icfg_is_logical(icfg_handle_t handle)
{
	return (strchr(icfg_if_name(handle), ICFG_LOGICAL_SEP)
	    != NULL);
}

/*
 * Determines whether or not an interface name represents a loopback
 * interface or not.
 *
 * Returns: B_TRUE if loopback, B_FALSE if not.
 */
static boolean_t
icfg_is_loopback(icfg_handle_t handle)
{
	return (strcmp(icfg_if_name(handle), LOOPBACK_IF) == 0);
}

/*
 * Given a sockaddr representation of an IPv4 or IPv6 address returns the
 * string representation. Note that 'sockaddr' should point at the correct
 * sockaddr structure for the address family (sockaddr_in for AF_INET or
 * sockaddr_in6 for AF_INET6) or alternatively at a sockaddr_storage
 * structure.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_sockaddr_to_str(sa_family_t af, const struct sockaddr *sockaddr,
    char *straddr, size_t len)
{
	const void *addr = sockaddr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	const char *str;
	int ret = ICFG_FAILURE;

	if (af == AF_INET) {
		sin = (struct sockaddr_in *)addr;
		str = inet_ntop(AF_INET, (void *)&sin->sin_addr, straddr, len);
	} else if (af == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)addr;
		str = inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, straddr,
		    len);
	} else {
		errno = EINVAL;
		return (ICFG_FAILURE);
	}

	if (str != NULL) {
		ret = ICFG_SUCCESS;
	}

	return (ret);
}

/*
 * Given a string representation of an IPv4 or IPv6 address returns the
 * sockaddr representation. Note that 'sockaddr' should point at the correct
 * sockaddr structure for the address family (sockaddr_in for AF_INET or
 * sockaddr_in6 for AF_INET6) or alternatively at a sockaddr_storage
 * structure.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_ADDR or ICFG_FAILURE.
 */
int
icfg_str_to_sockaddr(sa_family_t af, const char *straddr,
	struct sockaddr *sockaddr, socklen_t *addrlen)
{
	void *addr = sockaddr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int ret;
	int err;

	if (af == AF_INET) {
		if (*addrlen < sizeof (*sin)) {
			errno = ENOSPC;
			return (ICFG_FAILURE);
		}
		*addrlen = sizeof (*sin);
		sin = (struct sockaddr_in *)addr;
		sin->sin_family = AF_INET;
		err = inet_pton(AF_INET, straddr, &sin->sin_addr);
	} else if (af == AF_INET6) {
		if (*addrlen < sizeof (*sin6)) {
			errno = ENOSPC;
			return (ICFG_FAILURE);
		}
		*addrlen = sizeof (*sin6);
		sin6 = (struct sockaddr_in6 *)addr;
		sin6->sin6_family = AF_INET6;
		err = inet_pton(AF_INET6, straddr, &sin6->sin6_addr);
	} else {
		errno = EINVAL;
		return (ICFG_FAILURE);
	}

	if (err == 0) {
		ret = ICFG_BAD_ADDR;
	} else if (err == 1) {
		ret = ICFG_SUCCESS;
	} else {
		ret = ICFG_FAILURE;
	}

	return (ret);
}

/*
 * Adds the IP address contained in the 'addr' argument to the physical
 * interface represented by the handle passed in.  At present,
 * additional IP addresses assigned to a physical interface are
 * represented as logical interfaces.
 *
 * If the 'handle' argument is a handle to a physical interface, a logical
 * interface will be created, named by the next unused logical unit number
 * for that physical interface.
 *
 * If the 'handle' argument is a handle to an logical interface, then that
 * logical interface is the one that will be created.  If the logical
 * interface model is abandoned in the future, passing in a logical
 * interface name should result in ICFG_UNSUPPORTED being returned.
 *
 * If the 'new_handle' argument is not NULL, then a handle is created for the
 * new IP address alias and returned to the caller via 'new_handle'.
 * At present this handle refers to a logical interface, but in the future
 * it may represent an IP address alias, and be used for setting/retrieving
 * address-related information only.
 *
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_ADDR, ICFG_DAD_FOUND, ICFG_EXISTS
 *          or ICFG_FAILURE.
 */
int
icfg_add_addr(icfg_handle_t handle, icfg_handle_t *new_handle,
    const struct sockaddr *addr, socklen_t addrlen)
{
	struct lifreq lifr;
	size_t addrsize;
	int ret = ICFG_SUCCESS;
	icfg_handle_t loc_handle;

	if (addr->sa_family != icfg_if_protocol(handle))
		return (ICFG_BAD_ADDR);

	switch (addr->sa_family) {
	case AF_INET:
		addrsize = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		addrsize = sizeof (struct sockaddr_in6);
		break;
	default:
		return (ICFG_BAD_ADDR);
	}

	if (addrlen < addrsize) {
		errno = ENOSPC;
		return (ICFG_FAILURE);
	}

	/*
	 * See comments in ifconfig.c as to why this dance is necessary.
	 */
	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));

	if (ioctl(handle->ifh_sock, SIOCLIFADDIF, (caddr_t)&lifr) < 0) {
		if (errno == EEXIST)
			return (ICFG_EXISTS);
		else
			return (ICFG_FAILURE);
	}

	/* Create the handle for the new interface name. */
	ret = icfg_open(&loc_handle, &(handle->ifh_interface));
	if (ret != ICFG_SUCCESS) {
		return (ret);
	}
	(void) strlcpy(loc_handle->ifh_interface.if_name,
	    lifr.lifr_name,
	    sizeof (loc_handle->ifh_interface.if_name));

	if (addr != NULL)
		ret = icfg_set_addr(loc_handle, addr, addrsize);

	if (new_handle != NULL)
		*new_handle = loc_handle;
	else
		icfg_close(loc_handle);

	return (ret);
}

/*
 * Removes specified IP address alias from physical interface. If the
 * If the 'handle' argument is a handle to a physical interface, then
 * the address alias removed must be specified by 'addr'.  If the
 * 'handle' argument is a handle for an IP address alias (currently
 * represented as a logical interface), then that address alias
 * (logical interface) is removed and the 'addr' argument is ignored.
 *
 * Under the logical interface model, an interface may only be removed
 * if the interface is 'down'.
 *
 * Returns: ICFG_SUCCESS, ICFG_BAD_ADDR, ICFG_IF_UP, ICFG_NO_EXIST,
 * or ICFG_FAILURE.
 */
int
icfg_remove_addr(icfg_handle_t handle, const struct sockaddr *addr,
    socklen_t addrlen)
{
	struct lifreq lifr;
	size_t addrsize;

	switch (icfg_if_protocol(handle)) {
	case AF_INET:
		addrsize = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		addrsize = sizeof (struct sockaddr_in6);
		break;
	default:
		return (ICFG_BAD_ADDR);
	}

	if (addr != NULL) {
		if (addrlen < addrsize) {
			errno = ENOSPC;
			return (ICFG_FAILURE);
		}
		(void) memcpy(&lifr.lifr_addr, addr, addrsize);
	} else {
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	}

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));

	if (ioctl(handle->ifh_sock, SIOCLIFREMOVEIF, (caddr_t)&lifr) < 0)
		return (ICFG_FAILURE);

	return (ICFG_SUCCESS);
}

/*
 * Wrapper for sending a nontransparent I_STR ioctl().
 * Returns: Result from ioctl().
 *
 * Same as in usr/src/cmd/cmd-inet/usr.sbin/ifconfig/ifconfig.c
 */
static int
strioctl(int s, int cmd, char *buf, int buflen)
{
	struct strioctl ioc;

	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.ic_cmd = cmd;
	ioc.ic_timout = 0;
	ioc.ic_len = buflen;
	ioc.ic_dp = buf;

	return (ioctl(s, I_STR, (char *)&ioc));
}

/*
 * Open a stream on /dev/udp{,6}, pop off all undesired modules (note that
 * the user may have configured autopush to add modules above
 * udp), and push the arp module onto the resulting stream.
 * This is used to make IP+ARP be able to atomically track the muxid
 * for the I_PLINKed STREAMS, thus it isn't related to ARP running the ARP
 * protocol.
 *
 * Same as in usr/src/cmd/cmd-inet/usr.sbin/ifconfig/ifconfig.c
 */
static int
open_arp_on_udp(char *udp_dev_name)
{
	int fd;

	if ((fd = open(udp_dev_name, O_RDWR)) == -1)
		return (-1);

	errno = 0;
	while (ioctl(fd, I_POP, 0) != -1)
		;

	if (errno == EINVAL && ioctl(fd, I_PUSH, ARP_MOD_NAME) != -1)
		return (fd);

	(void) close(fd);
	return (-1);
}

/*
 * We need to plink both the arp-device stream and the arp-ip-device stream.
 * However the muxid is stored only in IP. Plumbing 2 streams individually
 * is not atomic, and if ifconfig is killed, the resulting plumbing can
 * be inconsistent. For eg. if only the arp stream is plumbed, we have lost
 * the muxid, and the half-baked plumbing can neither be unplumbed nor
 * replumbed, thus requiring a reboot. To avoid the above the following
 * scheme is used.
 *
 * We ask IP to enforce atomicity of plumbing the arp and IP streams.
 * This is done by pushing arp on to the mux (/dev/udp). ARP adds some
 * extra information in the I_PLINK and I_PUNLINK ioctls to let IP know
 * that the plumbing/unplumbing has to be done atomically. Ifconfig plumbs
 * the IP stream first, and unplumbs it last. The kernel (IP) does not
 * allow IP stream to be unplumbed without unplumbing arp stream. Similarly
 * it does not allow arp stream to be plumbed before IP stream is plumbed.
 * There is no need to use SIOCSLIFMUXID, since the whole operation is atomic,
 * and IP uses the info in the I_PLINK message to get the muxid.
 *
 * a. STREAMS does not allow us to use /dev/ip itself as the mux. So we use
 *    /dev/udp{,6}.
 * b. SIOCGLIFMUXID returns the muxid corresponding to the V4 or V6 stream
 *    depending on the open i.e. V4 vs V6 open. So we need to use /dev/udp
 *    or /dev/udp6 for SIOCGLIFMUXID and SIOCSLIFMUXID.
 * c. We need to push ARP in order to get the required kernel support for
 *    atomic plumbings. The actual work done by ARP is explained in arp.c
 *    Without pushing ARP, we will still be able to plumb/unplumb. But
 *    it is not atomic, and is supported by the kernel for backward
 *    compatibility for other utilities like atmifconfig etc. In this case
 *    the utility must use SIOCSLIFMUXID.
 *
 * Returns: ICFG_SUCCESS, ICFG_EXISTS, ICFG_BAD_ADDR, ICFG_FAILURE,
 * ICFG_DLPI_*, ICFG_NO_PLUMB_IP, ICFG_NO_PLUMB_ARP,
 * ICFG_NO_UNPLUMB_ARP
 */
int
icfg_plumb(icfg_handle_t handle)
{
	int ip_muxid;
	int mux_fd, ip_fd, arp_fd;
	uint_t ppa;
	char *udp_dev_name;
	char provider[DLPI_LINKNAME_MAX];
	dlpi_handle_t dh_arp, dh_ip;
	struct lifreq lifr;
	int dlpi_ret, ret = ICFG_SUCCESS;
	int saved_errno; /* to set errno after close() */
	int dh_arp_ret; /* to track if dh_arp was successfully opened */
	zoneid_t zoneid;

	/* Logical and loopback interfaces are just added */
	if (icfg_is_loopback(handle) || icfg_is_logical(handle))
		return (icfg_add_addr(handle, NULL, NULL, 0));

	/*
	 * If we're running in the global zone, we need to
	 * make sure this link is actually assigned to us.
	 *
	 * This is not an issue if we are not in the global
	 * zone, as we simply can't see links we don't own.
	 */
	zoneid = getzoneid();
	if (zoneid == GLOBAL_ZONEID) {
		dladm_handle_t dlh;
		dladm_status_t status;
		datalink_id_t linkid;

		if (dladm_open(&dlh) != DLADM_STATUS_OK)
			return (ICFG_FAILURE);
		status = dladm_name2info(dlh, icfg_if_name(handle), &linkid,
		    NULL, NULL, NULL);
		dladm_close(dlh);
		if (status != DLADM_STATUS_OK)
			return (ICFG_INVALID_ARG);
		zoneid = ALL_ZONES;
		if (zone_check_datalink(&zoneid, linkid) == 0)
			return (ICFG_INVALID_ARG);
	}

	/*
	 * We use DLPI_NOATTACH because the ip module will do the attach
	 * itself for DLPI style-2 devices.
	 */
	if ((dlpi_ret = dlpi_open(icfg_if_name(handle), &dh_ip,
	    DLPI_NOATTACH)) != DLPI_SUCCESS) {
		return (dlpi_error_to_icfg_error(dlpi_ret));
	}
	if ((dlpi_ret = dlpi_parselink(icfg_if_name(handle), provider,
	    &ppa)) != DLPI_SUCCESS) {
		ret = dlpi_error_to_icfg_error(dlpi_ret);
		goto done;
	}

	ip_fd = dlpi_fd(dh_ip);
	if (ioctl(ip_fd, I_PUSH, IP_MOD_NAME) == -1) {
		ret = ICFG_NO_PLUMB_IP;
		goto done;
	}

	/*
	 * Push the ARP module onto the interface stream. IP uses
	 * this to send resolution requests up to ARP. We need to
	 * do this before the SLIFNAME ioctl is sent down because
	 * the interface becomes publicly known as soon as the SLIFNAME
	 * ioctl completes. Thus some other process trying to bring up
	 * the interface after SLIFNAME but before we have pushed ARP
	 * could hang. We pop the module again later if it is not needed.
	 */
	if (ioctl(ip_fd, I_PUSH, ARP_MOD_NAME) == -1) {
		ret = ICFG_NO_PLUMB_ARP;
		goto done;
	}

	/*
	 * Set appropriate IFF flags.  The kernel only allows us to
	 * modify IFF_IPv[46], IFF_BROADCAST, and IFF_XRESOLV in the
	 * SIOCSLIFNAME ioctl call; so we only need to set the ones
	 * from that set that we care about.
	 */
	if (icfg_if_protocol(handle) == AF_INET6)
		lifr.lifr_flags = IFF_IPV6;
	else
		lifr.lifr_flags = IFF_IPV4 | IFF_BROADCAST;

	/* record the device and module names as interface name */
	lifr.lifr_ppa = ppa;
	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));

	/* set the interface name */
	if (ioctl(ip_fd, SIOCSLIFNAME, (char *)&lifr) == -1) {
		if (errno == EALREADY)
			ret = ICFG_EXISTS;
		else
			ret = ICFG_NO_PLUMB_IP;
		goto done;
	}

	/* Get the full set of existing flags for this stream */
	if (ioctl(ip_fd, SIOCGLIFFLAGS, (char *)&lifr) == -1) {
		if (errno == ENXIO)
			ret = ICFG_NO_EXIST;
		else
			ret = ICFG_FAILURE;
		goto done;
	}

	/* Check if arp is not actually needed */
	if (lifr.lifr_flags & (IFF_NOARP|IFF_IPV6)) {
		if (ioctl(ip_fd, I_POP, 0) == -1) {
			ret = ICFG_NO_UNPLUMB_ARP;
			goto done;
		}
	}

	/*
	 * Open "/dev/udp" for use as a multiplexor to PLINK the
	 * interface stream under. We use "/dev/udp" instead of "/dev/ip"
	 * since STREAMS will not let you PLINK a driver under itself,
	 * and "/dev/ip" is typically the driver at the bottom of
	 * the stream for tunneling interfaces.
	 */
	if (icfg_if_protocol(handle) == AF_INET6)
		udp_dev_name = UDP6_DEV_NAME;
	else
		udp_dev_name = UDP_DEV_NAME;

	if ((mux_fd = open_arp_on_udp(udp_dev_name)) == -1) {
		ret = ICFG_NO_PLUMB_ARP;
		goto done;
	}

	/* Check if arp is not needed */
	if (lifr.lifr_flags & (IFF_NOARP|IFF_IPV6)) {
		/*
		 * PLINK the interface stream so that ifconfig can exit
		 * without tearing down the stream.
		 */
		if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1) {
			ret = ICFG_NO_PLUMB_IP;
			goto done;
		}
		(void) close(mux_fd);
		dlpi_close(dh_ip);
		return (ICFG_SUCCESS);
	}

	/*
	 * This interface does use ARP, so set up a separate stream
	 * from the interface to ARP.
	 *
	 * Note: modules specified by the user are pushed
	 * only on the interface stream, not on the ARP stream.
	 *
	 * We use DLPI_NOATTACH because the arp module will do the attach
	 * itself for DLPI style-2 devices.
	 */
	if ((dh_arp_ret = dlpi_open(icfg_if_name(handle), &dh_arp,
	    DLPI_NOATTACH)) != DLPI_SUCCESS) {
		ret = dlpi_error_to_icfg_error(dh_arp_ret);
		goto done;
	}

	arp_fd = dlpi_fd(dh_arp);
	if (ioctl(arp_fd, I_PUSH, ARP_MOD_NAME) == -1) {
		ret = ICFG_NO_PLUMB_ARP;
		goto done;
	}

	/*
	 * Tell ARP the name and unit number for this interface.
	 * Note that arp has no support for transparent ioctls.
	 */
	if (strioctl(arp_fd, SIOCSLIFNAME, (char *)&lifr,
	    sizeof (lifr)) == -1) {
		ret = ICFG_NO_PLUMB_ARP;
		goto done;
	}
	/*
	 * PLINK the IP and ARP streams so that ifconfig can exit
	 * without tearing down the stream.
	 */
	if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1) {
		ret = ICFG_NO_PLUMB_IP;
		goto done;
	}

	if (ioctl(mux_fd, I_PLINK, arp_fd) == -1) {
		(void) ioctl(mux_fd, I_PUNLINK, ip_muxid);
		ret = ICFG_NO_PLUMB_ARP;
	}

done:
	/* dlpi_close() may change errno, so save it */
	saved_errno = errno;

	dlpi_close(dh_ip);
	if (dh_arp_ret == DLPI_SUCCESS)
		dlpi_close(dh_arp);

	if (mux_fd != -1)
		(void) close(mux_fd);
	if (ret != ICFG_SUCCESS)
		errno = saved_errno;

	return (ret);
}

static boolean_t
ifaddr_down(ifaddrlistx_t *ifaddrp)
{
	icfg_handle_t addrh;
	icfg_if_t addrif;
	uint64_t addrflags;
	boolean_t ret;

	addrif.if_protocol = ifaddrp->ia_flags & IFF_IPV6 ? AF_INET6 : AF_INET;
	(void) strlcpy(addrif.if_name, ifaddrp->ia_name,
	    sizeof (addrif.if_name));
	if (icfg_open(&addrh, &addrif) != ICFG_SUCCESS)
		return (B_FALSE);

	if (icfg_get_flags(addrh, &addrflags) != ICFG_SUCCESS)
		return (B_FALSE);

	addrflags &= ~IFF_UP;
	if (icfg_set_flags(addrh, addrflags) != ICFG_SUCCESS) {
		ret = B_FALSE;
		goto done;
	}

	/*
	 * Make sure that DAD activity (observable by IFF_DUPLICATE)
	 * has also been stopped.  If we were successful in downing
	 * the address, the get_flags will fail, as the addr will no
	 * longer exist.
	 */
	if ((icfg_get_flags(addrh, &addrflags) == ICFG_SUCCESS) &&
	    addrflags & IFF_DUPLICATE) {
		struct sockaddr_storage ss;
		socklen_t alen = sizeof (ss);
		int plen;
		/*
		 * getting/setting the address resets DAD; and since
		 * we've already turned off IFF_UP, DAD will remain
		 * disabled.
		 */
		if ((icfg_get_addr(addrh, (struct sockaddr *)&ss, &alen, &plen,
		    B_FALSE) != ICFG_SUCCESS) ||
		    (icfg_set_addr(addrh, (struct sockaddr *)&ss, alen)
		    != ICFG_SUCCESS)) {
			ret = B_FALSE;
			goto done;
		}
	}
	ret = B_TRUE;
done:
	icfg_close(addrh);
	return (ret);
}

/*
 * If this is a physical interface then remove it.
 * If it is a logical interface name use SIOCLIFREMOVEIF to
 * remove it. In both cases fail if it doesn't exist.
 *
 * Returns: ICFG_SUCCESS, ICFG_EXISTS, ICFG_NO_EXIST, ICFG_BAD_ADDR,
 * ICFG_FAILURE, ICFG_NO_UNPLUMB_IP, ICFG_NO_UNPLUMB_ARP,
 * ICFG_INVALID_ARG, ICFG_NO_IP_MUX
 *
 * Same as inetunplumb() in usr/src/cmd/cmd-inet/usr.sbin/ifconfig/ifconfig.c
 */
int
icfg_unplumb(icfg_handle_t handle)
{
	int ip_muxid, arp_muxid;
	int mux_fd;
	int muxid_fd;
	char *udp_dev_name;
	uint64_t flags;
	boolean_t changed_arp_muxid = B_FALSE;
	int save_errno;
	struct lifreq lifr;
	int ret = ICFG_SUCCESS;
	boolean_t v6 = (icfg_if_protocol(handle) == AF_INET6);

	/* Make sure interface exists to start with */
	if ((ret = icfg_get_flags(handle, &flags)) != ICFG_SUCCESS) {
		return (ret);
	}

	if (icfg_is_loopback(handle) || icfg_is_logical(handle)) {
		char *strptr = strchr(icfg_if_name(handle), ICFG_LOGICAL_SEP);

		/* Can't unplumb logical interface zero */
		if (strptr != NULL && strcmp(strptr, ":0") == 0)
			return (ICFG_INVALID_ARG);

		return (icfg_remove_addr(handle, NULL, 0));
	}

	/*
	 * We used /dev/udp or udp6 to set up the mux. So we have to use
	 * the same now for PUNLINK also.
	 */
	if (v6)
		udp_dev_name = UDP6_DEV_NAME;
	else
		udp_dev_name = UDP_DEV_NAME;

	if ((muxid_fd = open(udp_dev_name, O_RDWR)) == -1)
		return (ICFG_NO_UNPLUMB_ARP);

	if ((mux_fd = open_arp_on_udp(udp_dev_name)) == -1) {
		ret = ICFG_NO_UNPLUMB_ARP;
		goto done;
	}

	(void) strlcpy(lifr.lifr_name, icfg_if_name(handle),
	    sizeof (lifr.lifr_name));
	if (ioctl(muxid_fd, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		ret = ICFG_FAILURE;
		goto done;
	}
	flags = lifr.lifr_flags;

	/*
	 * libinetcfg's only current consumer is nwamd; and we expect it to
	 * be replaced before any other consumers come along.  NWAM does not
	 * currently support creation of IPMP groups, so icfg_plumb(), for
	 * example, does not do any IPMP-specific handling.  However, it's
	 * possible nwamd might need to unplumb an IPMP group, so we include
	 * IPMP group handling here.
	 */
again:
	if (flags & IFF_IPMP) {
		lifgroupinfo_t lifgr;
		ifaddrlistx_t *ifaddrs, *ifaddrp;

		/*
		 * There are two reasons the I_PUNLINK can fail with EBUSY:
		 * (1) if IP interfaces are in the group, or (2) if IPMP data
		 * addresses are administratively up.  For case (1), we fail
		 * here with a specific error message.  For case (2), we bring
		 * down the addresses prior to doing the I_PUNLINK.  If the
		 * I_PUNLINK still fails with EBUSY then the configuration
		 * must have changed after our checks, in which case we branch
		 * back up to `again' and rerun this logic.  The net effect is
		 * that unplumbing an IPMP interface will only fail with EBUSY
		 * if IP interfaces are in the group.
		 */
		ret = icfg_get_groupname(handle, lifgr.gi_grname, LIFGRNAMSIZ);
		if (ret != ICFG_SUCCESS)
			return (ret);

		ret = icfg_get_groupinfo(handle, &lifgr);
		if (ret != ICFG_SUCCESS)
			return (ret);

		/* make sure the group is empty */
		if ((v6 && lifgr.gi_nv6 != 0) || (!v6 && lifgr.gi_nv4 != 0))
			return (ICFG_INVALID_ARG);

		/*
		 * The kernel will fail the I_PUNLINK if the IPMP interface
		 * has administratively up addresses; bring 'em down.
		 */
		if (ifaddrlistx(icfg_if_name(handle), IFF_UP|IFF_DUPLICATE,
		    0, &ifaddrs) == -1)
			return (ICFG_FAILURE);

		ifaddrp = ifaddrs;
		for (; ifaddrp != NULL; ifaddrp = ifaddrp->ia_next) {
			if (((ifaddrp->ia_flags & IFF_IPV6) && !v6) ||
			    (!(ifaddrp->ia_flags && IFF_IPV6) && v6))
				continue;

			if (!ifaddr_down(ifaddrp)) {
				ifaddrlistx_free(ifaddrs);
				return (ICFG_FAILURE);
			}
		}
		ifaddrlistx_free(ifaddrs);
	}

	if (ioctl(muxid_fd, SIOCGLIFMUXID, (caddr_t)&lifr) < 0) {
		ret = ICFG_NO_IP_MUX;
		goto done;
	}
	arp_muxid = lifr.lifr_arp_muxid;
	ip_muxid = lifr.lifr_ip_muxid;
	/*
	 * We don't have a good way of knowing whether the arp stream is
	 * plumbed. We can't rely on IFF_NOARP because someone could
	 * have turned it off later using "ifconfig xxx -arp".
	 */
	if (arp_muxid != 0) {
		if (ioctl(mux_fd, I_PUNLINK, arp_muxid) < 0) {
			/*
			 * See the comment before the icfg_get_groupname() call.
			 */
			if (errno == EBUSY && (flags & IFF_IPMP))
				goto again;

			if ((errno == EINVAL) &&
			    (flags & (IFF_NOARP | IFF_IPV6))) {
				/*
				 * Some plumbing utilities set the muxid to
				 * -1 or some invalid value to signify that
				 * there is no arp stream. Set the muxid to 0
				 * before trying to unplumb the IP stream.
				 * IP does not allow the IP stream to be
				 * unplumbed if it sees a non-null arp muxid,
				 * for consistency of IP-ARP streams.
				 */
				lifr.lifr_arp_muxid = 0;
				(void) ioctl(muxid_fd, SIOCSLIFMUXID,
				    (caddr_t)&lifr);
				changed_arp_muxid = B_TRUE;
			} else {
				ret = ICFG_NO_UNPLUMB_ARP;
			}
		}
	}

	if (ioctl(mux_fd, I_PUNLINK, ip_muxid) < 0) {
		if (changed_arp_muxid) {
			/*
			 * Some error occurred, and we need to restore
			 * everything back to what it was.
			 */
			save_errno = errno;
			lifr.lifr_arp_muxid = arp_muxid;
			lifr.lifr_ip_muxid = ip_muxid;
			(void) ioctl(muxid_fd, SIOCSLIFMUXID, (caddr_t)&lifr);
			errno = save_errno;
		}

		/*
		 * See the comment before the icfg_get_groupname() call.
		 */
		if (errno == EBUSY && (flags && IFF_IPMP))
			goto again;

		ret = ICFG_NO_UNPLUMB_IP;
	}
done:
	/* close() may change errno, so save it */
	save_errno = errno;

	(void) close(muxid_fd);
	if (mux_fd != -1)
		(void) close(mux_fd);

	if (ret != ICFG_SUCCESS)
		errno = save_errno;

	return (ret);
}
