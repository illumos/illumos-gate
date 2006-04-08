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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libdscp.h>

/*
 * Define the file containing the configured DSCP interface name
 */
#define	DSCP_CONFIGFILE		"/var/run/dscp.ifname"

/*
 * Forward declarations
 */
static int get_ifname(char *);
static int convert_ipv6(struct sockaddr_in6 *, uint32_t *);
static int convert_ipv4(struct sockaddr_in *,
    struct sockaddr_in6 *, int *);

/*
 * dscpBind()
 *
 *	Properly bind a socket to the local DSCP address.
 *	Optionally bind it to a specific port.
 */
int
dscpBind(int domain_id, int sockfd, int port)
{
	int			len;
	int			len6;
	int			error;
	struct sockaddr_in	addr;
	struct sockaddr_in6	addr6;

	/* Check arguments */
	if ((sockfd < 0) || (port >= IPPORT_RESERVED)) {
		return (DSCP_ERROR_INVALID);
	}

	/* Get the local DSCP address used to communicate with the SP */
	error = dscpAddr(domain_id, DSCP_ADDR_LOCAL,
	    (struct sockaddr *)&addr, &len);

	if (error != DSCP_OK) {
		return (error);
	}

	/*
	 * If the caller specified a port, then update the socket address
	 * to also specify the same port.
	 */
	if (port != 0) {
		addr.sin_port = htons(port);
	}

	/*
	 * Bind the socket.
	 *
	 * EINVAL means it is already bound.
	 * EAFNOSUPPORT means try again using IPv6.
	 */
	if (bind(sockfd, (struct sockaddr *)&addr, len) < 0) {

		if (errno == EINVAL) {
			return (DSCP_ERROR_ALREADY);
		}

		if (errno != EAFNOSUPPORT) {
			return (DSCP_ERROR);
		}

		if (convert_ipv4(&addr, &addr6, &len6) < 0) {
			return (DSCP_ERROR);
		}

		if (bind(sockfd, (struct sockaddr *)&addr6, len6) < 0) {
			if (errno == EINVAL) {
				return (DSCP_ERROR_ALREADY);
			}
			return (DSCP_ERROR);
		}
	}

	return (DSCP_OK);
}

/*
 * dscpSecure()
 *
 *	Enable DSCP security mechanisms on a socket.
 *
 *	DSCP uses the IPSec AH (Authentication Headers) protocol with
 *	the SHA-1 algorithm.
 */
/*ARGSUSED*/
int
dscpSecure(int domain_id, int sockfd)
{
	ipsec_req_t	opt;

	/* Check arguments */
	if (sockfd < 0) {
		return (DSCP_ERROR_INVALID);
	}

	/*
	 * Construct a socket option argument that specifies the protocols
	 * and algorithms required for DSCP's use of IPSec.
	 */
	(void) memset(&opt, 0, sizeof (opt));
	opt.ipsr_ah_req = IPSEC_PREF_REQUIRED;
	opt.ipsr_esp_req = IPSEC_PREF_NEVER;
	opt.ipsr_self_encap_req = IPSEC_PREF_NEVER;
	opt.ipsr_auth_alg = SADB_AALG_MD5HMAC;

	/*
	 * Set the socket option that enables IPSec usage upon the socket,
	 * using the socket option argument constructed above.
	 */
	if (setsockopt(sockfd, IPPROTO_IP, IP_SEC_OPT, (const char *)&opt,
	    sizeof (opt)) < 0) {
		return (DSCP_ERROR);
	}

	return (DSCP_OK);
}

/*
 * dscpAuth()
 *
 *	Test whether a connection should be accepted or refused.
 *	The address of the connection request is compared against
 *	the remote address of the specified DSCP link.
 */
/*ARGSUSED*/
int
dscpAuth(int domain_id, struct sockaddr *saddr, int len)
{
	int			dlen;
	struct sockaddr		daddr;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	uint32_t		spaddr;
	uint32_t		reqaddr;

	/* Check arguments */
	if (saddr == NULL) {
		return (DSCP_ERROR_INVALID);
	}

	/*
	 * Get the remote IP address associated with the SP.
	 */
	if (dscpAddr(0, DSCP_ADDR_REMOTE, &daddr, &dlen) != DSCP_OK) {
		return (DSCP_ERROR_DB);
	}

	/*
	 * Convert the request's address to a 32-bit integer.
	 *
	 * This may require a conversion if the caller is
	 * using an IPv6 socket.
	 */
	switch (saddr->sa_family) {
	case AF_INET:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin = (struct sockaddr_in *)saddr;
		reqaddr = ntohl(*((uint32_t *)&(sin->sin_addr)));
		break;
	case AF_INET6:
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6 = (struct sockaddr_in6 *)saddr;
		if (convert_ipv6(sin6, &reqaddr) < 0) {
			return (DSCP_ERROR);
		}
		break;
	default:
		return (DSCP_ERROR);
	}

	/*
	 * Convert the SP's address to a 32-bit integer.
	 */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	sin = (struct sockaddr_in *)&daddr;
	spaddr = ntohl(*((uint32_t *)&(sin->sin_addr)));

	/*
	 * Compare the addresses.  Reject if they don't match.
	 */
	if (reqaddr != spaddr) {
		return (DSCP_ERROR_REJECT);
	}

	return (DSCP_OK);
}

/*
 * dscpAddr()
 *
 *	Get the addresses associated with a specific DSCP link.
 */
/*ARGSUSED*/
int
dscpAddr(int domain_id, int which, struct sockaddr *saddr, int *lenp)
{
	int			error;
	int			sockfd;
	uint64_t		flags;
	char			ifname[LIFNAMSIZ];
	struct lifreq		lifr;

	/* Check arguments */
	if (((saddr == NULL) || (lenp == NULL)) ||
	    ((which != DSCP_ADDR_LOCAL) && (which != DSCP_ADDR_REMOTE))) {
		return (DSCP_ERROR_INVALID);
	}

	/*
	 * Get the DSCP interface name.
	 */
	if (get_ifname(ifname) != 0) {
		return (DSCP_ERROR_DB);
	}

	/*
	 * Open a socket.
	 */
	if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		return (DSCP_ERROR_DB);
	}

	/*
	 * Get the interface flags.
	 */
	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(sockfd, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		(void) close(sockfd);
		return (DSCP_ERROR_DB);
	}
	flags = lifr.lifr_flags;

	/*
	 * The interface must be a PPP link using IPv4.
	 */
	if (((flags & IFF_IPV4) == 0) ||
	    ((flags & IFF_POINTOPOINT) == 0)) {
		(void) close(sockfd);
		return (DSCP_ERROR_DB);
	}

	/*
	 * Get the local or remote address, depending upon 'which'.
	 */
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (which == DSCP_ADDR_LOCAL) {
		error = ioctl(sockfd, SIOCGLIFADDR, (char *)&lifr);
	} else {
		error = ioctl(sockfd, SIOCGLIFDSTADDR, (char *)&lifr);
	}
	if (error < 0) {
		(void) close(sockfd);
		return (DSCP_ERROR_DB);
	}

	/*
	 * Copy the sockaddr value back to the caller.
	 */
	(void) memset(saddr, 0, sizeof (struct sockaddr));
	(void) memcpy(saddr, &lifr.lifr_addr, sizeof (struct sockaddr_in));
	*lenp = sizeof (struct sockaddr_in);

	(void) close(sockfd);
	return (DSCP_OK);
}

/*
 * dscpIdent()
 *
 *	Determine the domain of origin associated with a sockaddr.
 *	(Map a sockaddr to a domain ID.)
 *
 *	In the Solaris version, the remote socket address should always
 *	be the SP.  A call to dscpAuth() is used to confirm this, and
 *	then DSCP_IDENT_SP is returned as a special domain ID.
 */
int
dscpIdent(struct sockaddr *saddr, int len, int *domainp)
{
	int	error;

	/* Check arguments */
	if ((saddr == NULL) || (domainp == NULL)) {
		return (DSCP_ERROR_INVALID);
	}

	/* Confirm that the address is the SP */
	error = dscpAuth(0, saddr, len);
	if (error != DSCP_OK) {
		if (error == DSCP_ERROR_REJECT) {
			return (DSCP_ERROR);
		}
		return (error);
	}

	*domainp = DSCP_IDENT_SP;
	return (DSCP_OK);
}

/*
 * get_ifname()
 *
 *	Retrieve the interface name used by DSCP.
 *	It should be available from a file in /var/run.
 *
 *	Returns: 0 upon success, -1 upon failure.
 */
static int
get_ifname(char *ifname)
{
	int		i;
	int		fd;
	int		len;
	int		size;
	int		count;
	int		end;
	int		begin;
	struct stat	stbuf;

	/*
	 * Initialize the interface name.
	 */
	(void) memset(ifname, 0, LIFNAMSIZ);

	/*
	 * Test for a a valid configuration file.
	 */
	if ((stat(DSCP_CONFIGFILE, &stbuf) < 0) ||
	    (S_ISREG(stbuf.st_mode) == 0) ||
	    (stbuf.st_size > LIFNAMSIZ)) {
		return (-1);
	}

	/*
	 * Open the configuration file and read its contents
	 */

	if ((fd = open(DSCP_CONFIGFILE, O_RDONLY)) < 0) {
		return (-1);
	}

	count = 0;
	size = stbuf.st_size;
	do {
		i = read(fd, &ifname[count], size - count);
		if (i <= 0) {
			(void) close(fd);
			return (-1);
		}
		count += i;
	} while (count < size);

	(void) close(fd);

	/*
	 * Analyze the interface name that was just read,
	 * and clean it up as necessary.  The result should
	 * be a simple NULL terminated string such as "sppp0"
	 * with no extra whitespace or other characters.
	 */

	/* Detect the beginning of the interface name */
	for (begin = -1, i = 0; i < size; i++) {
		if (isalnum(ifname[i]) != 0) {
			begin = i;
			break;
		}
	}

	/* Fail if no such beginning was found */
	if (begin < 0) {
		return (-1);
	}

	/* Detect the end of the interface name */
	for (end = size - 1, i = begin; i < size; i++) {
		if (isalnum(ifname[i]) == 0) {
			end = i;
			break;
		}
	}

	/* Compute the length of the name */
	len = end - begin;

	/* Remove leading whitespace */
	if (begin > 0) {
		(void) memmove(ifname, &ifname[begin], len);
	}

	/* Clear out any remaining garbage */
	if (len < size) {
		(void) memset(&ifname[len], 0, size - len);
	}

	return (0);
}

/*
 * convert_ipv6()
 *
 *	Converts an IPv6 socket address into an equivalent IPv4
 *	address.  The conversion is to a 32-bit integer because
 *	that is sufficient for how libdscp uses IPv4 addresses.
 *
 *	The IPv4 address is additionally converted from network
 *	byte order to host byte order.
 *
 *	Returns:	0 upon success, with 'addrp' updated.
 *			-1 upon failure, with 'addrp' undefined.
 */
static int
convert_ipv6(struct sockaddr_in6 *addr6, uint32_t *addrp)
{
	uint32_t		addr;
	char			*ipv4str;
	char			ipv6str[INET6_ADDRSTRLEN];

	/*
	 * Convert the IPv6 address into a string.
	 */
	if (inet_ntop(AF_INET6, &addr6->sin6_addr, ipv6str,
	    sizeof (ipv6str)) == NULL) {
		return (-1);
	}

	/*
	 * Use the IPv6 string to construct an IPv4 string.
	 */
	if ((ipv4str = strrchr(ipv6str, ':')) != NULL) {
		ipv4str++;
	} else {
		return (-1);
	}

	/*
	 * Convert the IPv4 string into a 32-bit integer.
	 */
	if (inet_pton(AF_INET, ipv4str, &addr) <= 0) {
		return (-1);
	}

	*addrp = ntohl(addr);
	return (0);
}

/*
 * convert_ipv4()
 *
 *	Convert an IPv4 socket address into an equivalent IPv6 address.
 *
 *	Returns:	0 upon success, with 'addr6' and 'lenp' updated.
 *			-1 upon failure, with 'addr6' and 'lenp' undefined.
 */
static int
convert_ipv4(struct sockaddr_in *addr, struct sockaddr_in6 *addr6, int *lenp)
{
	int			len;
	uint32_t		ipv4addr;
	char			ipv4str[INET_ADDRSTRLEN];
	char			ipv6str[INET6_ADDRSTRLEN];

	/*
	 * Convert the IPv4 socket address into a string.
	 */
	ipv4addr = *((uint32_t *)&(addr->sin_addr));
	if (inet_ntop(AF_INET, &ipv4addr, ipv4str, sizeof (ipv4str)) == NULL) {
		return (-1);
	}

	/*
	 * Use the IPv4 string to construct an IPv6 string.
	 */
	len = snprintf(ipv6str, INET6_ADDRSTRLEN, "::ffff:%s", ipv4str);
	if (len >= INET6_ADDRSTRLEN) {
		return (-1);
	}

	/*
	 * Convert the IPv6 string to an IPv6 socket address.
	 */
	(void) memset(addr6, 0, sizeof (*addr6));
	addr6->sin6_family = AF_INET6;
	addr6->sin6_port = addr->sin_port;
	if (inet_pton(AF_INET6, ipv6str, &addr6->sin6_addr) <= 0) {
		return (-1);
	}

	*lenp = sizeof (struct sockaddr_in6);

	return (0);
}
