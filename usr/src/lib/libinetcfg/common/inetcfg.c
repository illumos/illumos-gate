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
#include <net/route.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <arpa/inet.h>
#include <libintl.h>
#include <libdlpi.h>
#include <inetcfg.h>

#define	ICFG_FAMILY(handle) handle->ifh_interface.if_protocol

#define	ICFG_TUNNEL_PROTOCOL(protocol) \
	(protocol == IFTAP_IPV6) ? AF_INET6 : AF_INET

#define	ICFG_SOCKADDR_LEN(protocol) \
	(protocol == AF_INET) ? \
	    (socklen_t)sizeof (struct sockaddr_in) : \
	    (socklen_t)sizeof (struct sockaddr_in6)

#define	ICFG_LOGICAL_SEP	':'

/*
 * Maximum amount of time (in milliseconds) to wait for Duplicate Address
 * Detection to complete in the kernel.
 */
#define	DAD_WAIT_TIME	5000

/*
 * Note: must be kept in sync with error codes in <inetcfg.h>
 */
static char *errmsgs[ICFG_NERR] = {
/* 0 ICFG_SUCCESS */	"Success",
/* 1 ICFG_FAILURE */	"Failure",
/* 2 ICFG_NOT_TUNNEL */	"Tunnel operation attempted on non-tunnel",
/* 3 ICFG_NOT_SET */	"Could not return non-existent value",
/* 4 ICFG_BAD_ADDR */	"Invalid Address",
/* 5 ICFG_BAD_PROT */	"Wrong protocol family for operation",
/* 6 ICFG_DAD_FAILED */	"Duplicate address detection failure",
/* 7 ICFG_DAD_FOUND */	"Duplicate address detected"
};

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
 * Ensures that the tunnel parameter data for the tunnel associated with
 * the handle is cached. If the 'force_update' argument is TRUE, then the
 * cache should be updated.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
static int
get_tunnel_params(icfg_handle_t handle, boolean_t force_update)
{
	struct iftun_req *params;

	if ((handle->ifh_tunnel_params != NULL) && (!force_update)) {
		return (ICFG_SUCCESS);
	}

	if (strchr(handle->ifh_interface.if_name, ICFG_LOGICAL_SEP) != NULL) {
		return (ICFG_NOT_TUNNEL);
	}

	if ((params = calloc(1, sizeof (struct iftun_req))) == NULL) {
		return (ICFG_FAILURE);
	}

	(void) strlcpy(params->ifta_lifr_name, handle->ifh_interface.if_name,
	    sizeof (params->ifta_lifr_name));

	if (ioctl(handle->ifh_sock, SIOCGTUNPARAM, (caddr_t)params) < 0) {
		free(params);
		if ((errno == EOPNOTSUPP) || (errno == EINVAL)) {
			return (ICFG_NOT_TUNNEL);
		}
		return (ICFG_FAILURE);
	}

	/*
	 * We assert that the iftun_req version is the right one
	 * and that the lower and upper protocols are set to either
	 * IPv4 or IPv6. Otherwise, some of our APIs are buggy.
	 */
	assert((params->ifta_vers == IFTUN_VERSION) &&
	    ((params->ifta_lower == IFTAP_IPV4) ||
	    (params->ifta_lower == IFTAP_IPV6)) &&
	    ((params->ifta_upper == IFTAP_IPV4) ||
	    (params->ifta_upper == IFTAP_IPV6)));

	if (handle->ifh_tunnel_params != NULL) {
		free(handle->ifh_tunnel_params);
	}
	handle->ifh_tunnel_params = params;

	return (ICFG_SUCCESS);
}

/*
 * Sets a tunnel destination or source address (depending upon 'type') on
 * a tunnel interface.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
static int
set_tunnel_address(icfg_handle_t handle, const struct sockaddr *addr,
    socklen_t addrlen, int type)
{
	struct sockaddr_storage laddr;
	sa_family_t lower_family;
	struct iftun_req *params;
	int ret;

	assert((type == IFTUN_SRC) || (type == IFTUN_DST));

	if ((ret = get_tunnel_params(handle, B_TRUE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	if (params->ifta_lower == IFTAP_IPV4) {
		lower_family = AF_INET;
	} else {
		lower_family = AF_INET6;
	}

	ret = to_sockaddr_storage(lower_family, addr, addrlen, &laddr);
	if (ret != ICFG_SUCCESS) {
		return (ret);
	}

	if (type == IFTUN_SRC) {
		params->ifta_saddr = laddr;
	} else {
		params->ifta_daddr = laddr;
	}

	(void) strlcpy(params->ifta_lifr_name, handle->ifh_interface.if_name,
	    sizeof (params->ifta_lifr_name));
	params->ifta_flags |= type;

	if (ioctl(handle->ifh_sock, SIOCSTUNPARAM, (caddr_t)params) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Return the appropriate error message for a given ICFG error.
 */
const char *
icfg_errmsg(int errcode)
{
	if ((errcode < ICFG_SUCCESS) || (errcode >= ICFG_NERR))
		return (dgettext(TEXT_DOMAIN, "<unknown error>"));

	return (dgettext(TEXT_DOMAIN, errmsgs[errcode]));
}

/*
 * Opens the an interface as defined by the interface argument and returns
 * a handle to the interface via the 'handle' argument. The caller is
 * responsible for freeing resources allocated by this API by calling the
 * icfg_close() API.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
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
		return (ICFG_FAILURE);
	}

	if ((sock = socket(family, SOCK_DGRAM, 0)) < 0) {
		syserr = errno;
		free(loc_handle);
		errno = syserr;
		return (ICFG_FAILURE);
	}

	loc_handle->ifh_sock = sock;
	loc_handle->ifh_interface = *interface;
	loc_handle->ifh_tunnel_params = NULL;

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
	if (handle->ifh_tunnel_params != NULL) {
		free(handle->ifh_tunnel_params);
	}
	free(handle);
}

/*
 * Refreshes the tunnel parameter data cache associated with the interface
 * represented by the handle. Tunnel parameter data is cached by the
 * libinetcfg library by the first call to to any of the tunnel related APIs.
 * Since there is no synchronization between consumers of the library and
 * non-users of this library, the cache may contain stale data. Users may
 * wish to use this API to refresh the cache before subsequent calls to the
 * other tunnel related APIs.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
int
icfg_refresh_tunnel_cache(icfg_handle_t handle)
{
	return (get_tunnel_params(handle, B_TRUE));
}

/*
 * Sets the destination address for the tunnel interface represented
 * by 'handle'.
 *
 * The 'addr' argument points to either a sockaddr_in structure
 * (for IPv4) or a sockaddr_in6 structure (for IPv6) that holds
 * the IP address. The 'addrlen' argument gives the length of the
 * 'addr' structure.
 *
 * This API will always result in an update of the tunnel parameter
 * data cache.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
int
icfg_set_tunnel_dest(icfg_handle_t handle, const struct sockaddr *addr,
    socklen_t addrlen)
{
	return (set_tunnel_address(handle, addr, addrlen, IFTUN_DST));
}

/*
 * Sets the source address for the tunnel interface represented
 * by 'handle'.
 *
 * The 'addr' argument points to either a sockaddr_in structure
 * (for IPv4) or a sockaddr_in6 structure (for IPv6) that holds
 * the IP address. The 'addrlen' argument gives the length of the
 * 'addr' structure.
 *
 * This API will always result in an update of the tunnel parameter
 * data cache.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
int
icfg_set_tunnel_src(icfg_handle_t handle, const struct sockaddr *addr,
    socklen_t addrlen)
{
	return (set_tunnel_address(handle, addr, addrlen, IFTUN_SRC));
}

/*
 * Sets the hop limit for the tunnel interface represented by
 * the handle to the value contained in the 'limit' argument.
 *
 * This API will always result in an update of the tunnel parameter data cache.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
int
icfg_set_tunnel_hoplimit(icfg_handle_t handle, uint8_t limit)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_TRUE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	(void) strlcpy(params->ifta_lifr_name, handle->ifh_interface.if_name,
	    sizeof (params->ifta_lifr_name));

	params->ifta_hop_limit = limit;
	params->ifta_flags |= IFTUN_HOPLIMIT;

	if (ioctl(handle->ifh_sock, SIOCSTUNPARAM, (caddr_t)params) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Sets the encapsulation limit for the tunnel interface represented by
 * the handle to the value contained in the 'limit' argument. If the
 * value of the limit is negative, then the encapsulation limit is disabled.
 *
 * This API will always result in an update of the tunnel parameter data cache.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
int
icfg_set_tunnel_encaplimit(icfg_handle_t handle, int16_t limit)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_TRUE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	(void) strlcpy(params->ifta_lifr_name, handle->ifh_interface.if_name,
	    sizeof (params->ifta_lifr_name));

	params->ifta_encap_lim = limit;
	params->ifta_flags |= IFTUN_ENCAP;

	if (ioctl(handle->ifh_sock, SIOCSTUNPARAM, (caddr_t)params) < 0) {
		return (ICFG_FAILURE);
	}

	return (ICFG_SUCCESS);
}

/*
 * Returns the source address for the tunnel interface represented
 * by 'handle'.
 *
 * The 'addr' argument is a result parameter that is filled in with
 * the requested address. The format of the 'addr' parameter is
 * determined by the address family of the interface.
 *
 * The 'addrlen' argument is a value-result parameter. Initially,
 * it contains the amount of space pointed to by 'addr'; on return
 * it contains the length in bytes of the address returned.
 *
 * Note that if 'addrlen' is not large enough for the returned
 * address value, then ICFG_FAILURE will be returned and errno
 * will be set to ENOSPC.
 *
 * This API will retrieve the tunnel source value from the tunnel
 * parameter data cache and will only update the cache if no data has
 * yet been cached for this tunnel.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL, ICFG_NOT_SET or
 *	    ICFG_FAILURE.
 */
int
icfg_get_tunnel_src(icfg_handle_t handle, struct sockaddr *addr,
    socklen_t *addrlen)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_FALSE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	if (!(params->ifta_flags & IFTUN_SRC)) {
		return (ICFG_NOT_SET);
	}

	if (params->ifta_lower == IFTAP_IPV4) {
		assert(params->ifta_saddr.ss_family == AF_INET);
	} else {
		assert(params->ifta_saddr.ss_family == AF_INET6);
	}

	return (to_sockaddr(params->ifta_saddr.ss_family, addr, addrlen,
	    &params->ifta_saddr));
}

/*
 * Returns the destination address for the tunnel interface
 * represented by 'handle'.
 *
 * The 'addr' argument is a result parameter that is filled in
 * with the requested address. The format of the 'addr' parameter
 * is determined by the address family of the interface.
 *
 * The 'addrlen' argument is a value-result parameter. Initially, it
 * contains the amount of space pointed to by 'addr'; on return it
 * contains the length in bytes of the address returned.
 *
 * Note that if 'addrlen' is not large enough for the returned address
 * value, then ICFG_FAILURE will be returned and errno will be set
 * to ENOSPC.
 *
 * This API will retrieve the tunnel destination value from the tunnel
 * parameter data cache and will only update the cache if no data has yet
 * been cached for this tunnel.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL, ICFG_NOT_SET or
 *	    ICFG_FAILURE.
 */
int
icfg_get_tunnel_dest(icfg_handle_t handle, struct sockaddr *addr,
    socklen_t *addrlen)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_FALSE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	if (!(params->ifta_flags & IFTUN_DST)) {
		return (ICFG_NOT_SET);
	}

	if (params->ifta_lower == IFTAP_IPV4) {
		assert(params->ifta_daddr.ss_family == AF_INET);
	} else if (params->ifta_lower == IFTAP_IPV6) {
		assert(params->ifta_daddr.ss_family == AF_INET6);
	}

	return (to_sockaddr(params->ifta_daddr.ss_family, addr, addrlen,
	    &params->ifta_daddr));
}

/*
 * Returns the tunnel hop limit (if any). The value of the limit
 * will be copied into the buffer supplied by the 'limit' argument.
 *
 * This API will retrieve the hoplimit value from the tunnel parameter data
 * cache and will only update the cache if no data has yet been cached for
 * this tunnel.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL, ICFG_NOT_SET or
 *	    ICFG_FAILURE.
 */
int
icfg_get_tunnel_hoplimit(icfg_handle_t handle, uint8_t *limit)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_FALSE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	if (!(params->ifta_flags & IFTUN_HOPLIMIT)) {
		return (ICFG_NOT_SET);
	}

	*limit = params->ifta_hop_limit;

	return (ICFG_SUCCESS);
}

/*
 * Returns the tunnel encapsulation limit (if any). The value of the limit
 * will be copied into the buffer supplied by the 'limit' argument.
 *
 * This API will retrieve the encapsulation limit value from the tunnel
 * parameter data cache and will only update the cache if no data has yet
 * been cached for this tunnel.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL, ICFG_NOT_SET or
 *	    ICFG_FAILURE.
 */
int
icfg_get_tunnel_encaplimit(icfg_handle_t handle, int16_t *limit)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_FALSE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	if (!(params->ifta_flags & IFTUN_ENCAP)) {
		return (ICFG_NOT_SET);
	}

	*limit = params->ifta_encap_lim;

	return (ICFG_SUCCESS);
}

/*
 * Returns the protocol family (AF_INET or AF_INET6) of the protocol
 * actually being used to tunnel the data. The value of the protocol family
 * will be copied into the buffer supplied by the 'protocol' argument.
 *
 * This API will retrieve the protocol value from the tunnel parameter data
 * cache and will only update the cache if no data has yet been cached for
 * this tunnel.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
int
icfg_get_tunnel_lower(icfg_handle_t handle, int *protocol)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_FALSE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	*protocol = ICFG_TUNNEL_PROTOCOL(params->ifta_lower);

	return (ICFG_SUCCESS);
}

/*
 * Returns the protocol family (AF_INET or AF_INET6) of the protocol
 * actually being tunneled. The value of the protocol family will be copied
 * into the buffer supplied by the 'protocol' argument.
 *
 * This API will retrieve the protocolvalue from the tunnel parameter data
 * cache and will only update the cache if no data has yet been cached for
 * this tunnel.
 *
 * Returns: ICFG_SUCCESS, ICFG_NOT_TUNNEL or ICFG_FAILURE.
 */
int
icfg_get_tunnel_upper(icfg_handle_t handle, int *protocol)
{
	struct iftun_req *params;
	int ret;

	if ((ret = get_tunnel_params(handle, B_FALSE)) != ICFG_SUCCESS) {
		return (ret);
	}
	params = handle->ifh_tunnel_params;

	*protocol = ICFG_TUNNEL_PROTOCOL(params->ifta_upper);

	return (ICFG_SUCCESS);
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
	int rtsock;

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if ((ret = icfg_get_flags(handle, &oflags)) != ICFG_SUCCESS)
		return (ret);
	if (oflags == flags)
		return (ICFG_SUCCESS);

	/*
	 * Any time flags are changed on an interface that has IFF_UP set,
	 * you'll get a routing socket message.  We care about the status,
	 * though, only when the new flags are marked "up."
	 */
	rtsock = (flags & IFF_UP) ?
	    socket(PF_ROUTE, SOCK_RAW, ICFG_FAMILY(handle)) : -1;

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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);
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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);
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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);
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
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROT or ICFG_FAILURE.
 */
int
icfg_set_netmask(icfg_handle_t handle, const struct sockaddr_in *addr)
{
	struct lifreq lifr;
	int ret;

	if (ICFG_FAMILY(handle) != AF_INET) {
		return (ICFG_BAD_PROT);
	}

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(ICFG_FAMILY(handle),
	    (struct sockaddr *)addr, sizeof (*addr),
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
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
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROT or ICFG_FAILURE.
 */
int
icfg_set_broadcast(icfg_handle_t handle, const struct sockaddr_in *addr)
{
	struct lifreq lifr;
	int ret;

	if (ICFG_FAMILY(handle) != AF_INET) {
		return (ICFG_BAD_PROT);
	}

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(ICFG_FAMILY(handle),
	    (struct sockaddr *)addr, sizeof (*addr),
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
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
	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ICFG_FAMILY(handle) == AF_INET6) {
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
	int rtsock;

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(ICFG_FAMILY(handle), addr, addrlen,
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}

	/*
	 * Need to do check on duplicate address detection results if the
	 * interface is up.
	 */
	if ((ret = icfg_get_flags(handle, &flags)) != ICFG_SUCCESS) {
		return (ret);
	}

	rtsock = (flags & IFF_UP) ?
	    socket(PF_ROUTE, SOCK_RAW, ICFG_FAMILY(handle)) : -1;

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

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
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROT or ICFG_FAILURE.
 */
int
icfg_set_token(icfg_handle_t handle, const struct sockaddr_in6 *addr,
    int prefixlen)
{
	struct lifreq lifr;
	int ret;

	if (ICFG_FAMILY(handle) != AF_INET6) {
		return (ICFG_BAD_PROT);
	}

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if ((ret = to_sockaddr_storage(ICFG_FAMILY(handle),
	    (struct sockaddr *)addr, sizeof (*addr),
	    &lifr.lifr_addr)) != ICFG_SUCCESS) {
		return (ret);
	}
	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);
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
	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if ((ret = to_sockaddr_storage(ICFG_FAMILY(handle), addr, addrlen,
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
	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if ((ret = to_sockaddr_storage(ICFG_FAMILY(handle), addr, addrlen,
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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
		if (force && ((errno == EADDRNOTAVAIL) ||
		    (errno == EAFNOSUPPORT) || (errno == ENXIO))) {
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			return (ICFG_FAILURE);
		}
	}

	if ((ret = to_sockaddr(ICFG_FAMILY(handle), addr, addrlen,
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
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROT or ICFG_FAILURE.
 */
int
icfg_get_token(icfg_handle_t handle, struct sockaddr_in6 *addr,
    int *prefixlen, boolean_t force)
{
	struct lifreq lifr;
	socklen_t addrlen = sizeof (*addr);

	if (ICFG_FAMILY(handle) != AF_INET6) {
		return (ICFG_BAD_PROT);
	}

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFTOKEN, (caddr_t)&lifr) < 0) {
		if (force && ((errno == EADDRNOTAVAIL) || (errno == EINVAL))) {
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			return (ICFG_FAILURE);
		}
	}

	*prefixlen = lifr.lifr_addrlen;
	return (to_sockaddr(ICFG_FAMILY(handle), (struct sockaddr *)addr,
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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFSUBNET, (caddr_t)&lifr) < 0) {
		if (force && ((errno == EADDRNOTAVAIL) ||
		    (errno == EAFNOSUPPORT) || (errno == ENXIO))) {
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			return (ICFG_FAILURE);
		}
	}

	if ((ret = to_sockaddr(ICFG_FAMILY(handle), addr, addrlen,
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
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROT or ICFG_FAILURE.
 */
int
icfg_get_netmask(icfg_handle_t handle, struct sockaddr_in *addr)
{
	struct lifreq lifr;
	socklen_t addrlen = sizeof (*addr);

	if (ICFG_FAMILY(handle) != AF_INET) {
		return (ICFG_BAD_PROT);
	}

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			return (ICFG_FAILURE);
		}
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	}

	return (to_sockaddr(ICFG_FAMILY(handle), (struct sockaddr *)addr,
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
 * Returns: ICFG_SUCCESS, ICFG_BAD_PROT or ICFG_FAILURE.
 */
int
icfg_get_broadcast(icfg_handle_t handle, struct sockaddr_in *addr)
{
	struct lifreq lifr;
	socklen_t addrlen = sizeof (*addr);

	if (ICFG_FAMILY(handle) != AF_INET) {
		return (ICFG_BAD_PROT);
	}

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFBRDADDR, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			return (ICFG_FAILURE);
		}
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	}

	return (to_sockaddr(ICFG_FAMILY(handle), (struct sockaddr *)addr,
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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFDSTADDR, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL) {
			return (ICFG_FAILURE);
		}
		/* No destination address set yet */
		(void) memset(&lifr.lifr_dstaddr, 0,
		    sizeof (lifr.lifr_dstaddr));
	}

	return (to_sockaddr(ICFG_FAMILY(handle), addr, addrlen,
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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

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
 * Returns the link info of the interface represented by the handle
 * argument into the buffer pointed to by the 'info' argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_linkinfo(icfg_handle_t handle, lif_ifinfo_req_t *info)
{
	struct lifreq lifr;
	char *cp;

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	if ((cp = strchr(lifr.lifr_name, ICFG_LOGICAL_SEP)) != NULL) {
		*cp = '\0';
	}
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFLNKINFO, (caddr_t)&lifr) < 0) {
		return (ICFG_FAILURE);
	}
	*info = lifr.lifr_ifinfo;

	return (ICFG_SUCCESS);
}

/*
 * Returns the flags value of the interface represented by the handle
 * argument into the buffer pointed to by the 'flags' argument.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
 */
int
icfg_get_flags(icfg_handle_t handle, uint64_t *flags)
{
	struct lifreq lifr;

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

	if (ioctl(handle->ifh_sock, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

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

	(void) strlcpy(lifr.lifr_name, handle->ifh_interface.if_name,
	    sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = ICFG_FAMILY(handle);

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
 * the memory associated with this array by calling icfg_free_list().
 *
 * The 'proto' argument is used by the caller to define which interfaces are
 * to be listed by the API. The possible values for proto are AF_INET,
 * AF_INET6, and AF_UNSPEC.
 *
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
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
		return (ICFG_FAILURE);
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
		return (ICFG_FAILURE);
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
		return (ICFG_FAILURE);
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
 * Returns: ICFG_SUCCESS or ICFG_FAILURE.
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

	list = calloc(lw.lw_num, sizeof (icfg_if_t));
	if (list == NULL)
		goto done;

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
 * icfg_free_list().
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
	return (strchr(handle->ifh_interface.if_name, ICFG_LOGICAL_SEP)
	    != NULL);
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
