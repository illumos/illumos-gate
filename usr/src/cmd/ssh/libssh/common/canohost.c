/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for returning the canonical host name of the remote site.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#include "includes.h"
RCSID("$OpenBSD: canohost.c,v 1.34 2002/09/23 20:46:27 stevesk Exp $");

#include "packet.h"
#include "xmalloc.h"
#include "log.h"
#include "canohost.h"

static const char *inet_ntop_native(int af, const void *src,
	char *dst, size_t size);


/*
 * Return the canonical name of the host at the other end of the socket. The
 * caller should free the returned string with xfree.
 */

static char *
get_remote_hostname(int socket, int verify_reverse_mapping)
{
	struct sockaddr_storage from;
	int i, res;
	socklen_t fromlen;
	struct addrinfo hints, *ai, *aitop;
	char name[NI_MAXHOST], ntop[NI_MAXHOST], ntop2[NI_MAXHOST];

	/* Get IP address of client. */
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (getpeername(socket, (struct sockaddr *) &from, &fromlen) < 0) {
		debug("getpeername failed: %.100s", strerror(errno));
		fatal_cleanup();
	}

	if ((res = getnameinfo((struct sockaddr *)&from, fromlen, ntop, sizeof(ntop),
	    NULL, 0, NI_NUMERICHOST)) != 0)
		fatal("get_remote_hostname: getnameinfo NI_NUMERICHOST failed: %d", res);

#ifdef IPV4_IN_IPV6
	if (from.ss_family == AF_INET6) {
		struct sockaddr_in6 *from6 = (struct sockaddr_in6 *)&from;

		(void) inet_ntop_native(from.ss_family,
				from6->sin6_addr.s6_addr,
				ntop, sizeof(ntop));
	}
#endif /* IPV4_IN_IPV6 */

	if (!verify_reverse_mapping)
		return xstrdup(ntop);

	debug3("Trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	if (getnameinfo((struct sockaddr *)&from, fromlen, name, sizeof(name),
	    NULL, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		return xstrdup(ntop);
	}

	/* Got host name. */
	name[sizeof(name) - 1] = '\0';
	/*
	 * Convert it to all lowercase (which is expected by the rest
	 * of this software).
	 */
	for (i = 0; name[i]; i++)
		if (isupper(name[i]))
			name[i] = tolower(name[i]);

	/*
	 * Map it back to an IP address and check that the given
	 * address actually is an address of this host.  This is
	 * necessary because anyone with access to a name server can
	 * define arbitrary names for an IP address. Mapping from
	 * name to IP address can be trusted better (but can still be
	 * fooled if the intruder has access to the name server of
	 * the domain).
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(name, NULL, &hints, &aitop) != 0) {
		log("reverse mapping checking getaddrinfo for %.700s "
		    "failed - POSSIBLE BREAKIN ATTEMPT!", name);
		return xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	for (ai = aitop; ai; ai = ai->ai_next) {
		if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    sizeof(ntop2), NULL, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				break;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	if (!ai) {
		/* Address not found for the host name. */
		log("Address %.100s maps to %.600s, but this does not "
		    "map back to the address - POSSIBLE BREAKIN ATTEMPT!",
		    ntop, name);
		return xstrdup(ntop);
	}
	return xstrdup(name);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

const char *
get_canonical_hostname(int verify_reverse_mapping)
{
	static char *canonical_host_name = NULL;
	static int verify_reverse_mapping_done = 0;

	/* Check if we have previously retrieved name with same option. */
	if (canonical_host_name != NULL) {
		if (verify_reverse_mapping_done != verify_reverse_mapping)
			xfree(canonical_host_name);
		else
			return canonical_host_name;
	}

	/* Get the real hostname if socket; otherwise return UNKNOWN. */
	if (packet_connection_is_on_socket())
		canonical_host_name = get_remote_hostname(
		    packet_get_connection_in(), verify_reverse_mapping);
	else
		canonical_host_name = xstrdup("UNKNOWN");

	verify_reverse_mapping_done = verify_reverse_mapping;
	return canonical_host_name;
}

/*
 * Returns the remote IP-address of socket as a string.  The returned
 * string must be freed.
 */
char *
get_socket_address(int socket, int remote, int flags)
{
	struct sockaddr_storage addr;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
	socklen_t addrlen;
	char ntop[NI_MAXHOST];
	const char *result;
	char abuf[INET6_ADDRSTRLEN];

	/* Get IP address of client. */
	addrlen = sizeof (addr);
	memset(&addr, 0, sizeof (addr));

	if (remote) {
		if (getpeername(socket, (struct sockaddr *)&addr, &addrlen)
		    < 0) {
			debug("get_socket_ipaddr: getpeername failed: %.100s",
			    strerror(errno));
			return (NULL);
		}
	} else {
		if (getsockname(socket, (struct sockaddr *)&addr, &addrlen)
		    < 0) {
			debug("get_socket_ipaddr: getsockname failed: %.100s",
			    strerror(errno));
			return (NULL);
		}
	}

	/* Get the address in ascii. */
	if (getnameinfo((struct sockaddr *)&addr, addrlen, ntop, sizeof (ntop),
	    NULL, 0, flags) != 0) {
		error("get_socket_ipaddr: getnameinfo %d failed", flags);
		return (NULL);
	}

	if (addr.ss_family == AF_INET) {
		return (xstrdup(ntop));
	}

	result = inet_ntop_native(addr.ss_family,
	    addr6->sin6_addr.s6_addr, abuf, sizeof (abuf));

	return (xstrdup(result));
}

char *
get_peer_ipaddr(int socket)
{
	char *p;

	if ((p = get_socket_address(socket, 1, NI_NUMERICHOST)) != NULL)
		return p;
	return xstrdup("UNKNOWN");
}

char *
get_local_ipaddr(int socket)
{
	char *p;

	if ((p = get_socket_address(socket, 0, NI_NUMERICHOST)) != NULL)
		return p;
	return xstrdup("UNKNOWN");
}

char *
get_local_name(int socket)
{
	return get_socket_address(socket, 0, NI_NAMEREQD);
}

/*
 * Returns the IP-address of the remote host as a string.  The returned
 * string must not be freed.
 */

const char *
get_remote_ipaddr(void)
{
	static char *canonical_host_ip = NULL;

	/* Check whether we have cached the ipaddr. */
	if (canonical_host_ip == NULL) {
		if (packet_connection_is_on_socket()) {
			canonical_host_ip =
			    get_peer_ipaddr(packet_get_connection_in());
			if (canonical_host_ip == NULL)
				fatal_cleanup();
		} else {
			/* If not on socket, return UNKNOWN. */
			canonical_host_ip = xstrdup("UNKNOWN");
		}
	}
	return canonical_host_ip;
}

const char *
get_remote_name_or_ip(u_int utmp_len, int verify_reverse_mapping)
{
	static const char *remote = "";
	if (utmp_len > 0)
		remote = get_canonical_hostname(verify_reverse_mapping);
	if (utmp_len == 0 || strlen(remote) > utmp_len)
		remote = get_remote_ipaddr();
	return remote;
}

/* Returns the local/remote port for the socket. */

static int
get_sock_port(int sock, int local)
{
	struct sockaddr_storage from;
	socklen_t fromlen;
	char strport[NI_MAXSERV];

	/* Get IP address of client. */
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (local) {
		if (getsockname(sock, (struct sockaddr *)&from, &fromlen) < 0) {
			error("getsockname failed: %.100s", strerror(errno));
			return 0;
		}
	} else {
		if (getpeername(sock, (struct sockaddr *) & from, &fromlen) < 0) {
			debug("getpeername failed: %.100s", strerror(errno));
			fatal_cleanup();
		}
	}
	/* Return port number. */
	if (getnameinfo((struct sockaddr *)&from, fromlen, NULL, 0,
	    strport, sizeof(strport), NI_NUMERICSERV) != 0)
		fatal("get_sock_port: getnameinfo NI_NUMERICSERV failed");
	return atoi(strport);
}

/* Returns remote/local port number for the current connection. */

static int
get_port(int local)
{
	/*
	 * If the connection is not a socket, return 65535.  This is
	 * intentionally chosen to be an unprivileged port number.
	 */
	if (!packet_connection_is_on_socket())
		return 65535;

	/* Get socket and return the port number. */
	return get_sock_port(packet_get_connection_in(), local);
}

int
get_peer_port(int sock)
{
	return get_sock_port(sock, 0);
}

int
get_remote_port(void)
{
	return get_port(0);
}

int
get_local_port(void)
{
	return get_port(1);
}

/*
 * Taken from inetd.c
 * This is a wrapper function for inet_ntop(). In case the af is AF_INET6
 * and the address pointed by src is a IPv4-mapped IPv6 address, it
 * returns printable IPv4 address, not IPv4-mapped IPv6 address. In other cases
 * it behaves just like inet_ntop().
 */
static const char *
inet_ntop_native(int af, const void *src, char *dst, size_t size)
{
	struct in_addr src4;
	const char *result;

	if (af == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)src)) {
			IN6_V4MAPPED_TO_INADDR((struct in6_addr *)src, &src4);
			result = inet_ntop(AF_INET, &src4, dst, size);
		} else {
			result = inet_ntop(AF_INET6, src, dst, size);
		}
	} else {
		result = inet_ntop(af, src, dst, size);
	}

	return (result);
}
