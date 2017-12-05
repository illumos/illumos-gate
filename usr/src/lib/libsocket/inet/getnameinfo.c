/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>

#define	sa2sin(x)	((struct sockaddr_in *)(x))
#define	sa2sin6(x)	((struct sockaddr_in6 *)(x))

#define	NI_MASK	(NI_NOFQDN | NI_NUMERICHOST | NI_NAMEREQD | NI_NUMERICSERV | \
    NI_DGRAM | NI_WITHSCOPEID)

static int addzoneid(const struct sockaddr_in6 *sa, char *host,
    size_t hostlen);
static size_t getzonestr(const struct sockaddr_in6 *sa, char *zonestr,
    size_t zonelen);
static const char *_inet_ntop_native();
/*
 * getnameinfo:
 *
 * Purpose:
 *   Routine for performing Address-to-nodename in a
 *   protocol-independent fashion.
 * Description:
 *   This function looks up an IP address and port number provided
 *   by the caller in the name service database and returns the nodename
 *   and servname respectively in the buffers provided by the caller.
 * Input Parameters:
 *   sa      - points to either a sockaddr_in structure (for
 *             IPv4) or a sockaddr_in6 structure (for IPv6).
 *   salen   - length of the sockaddr_in or sockaddr_in6 structure.
 *   hostlen - length of caller supplied "host" buffer
 *   servlen - length of caller supplied "serv" buffer
 *   flags   - changes default actions based on setting.
 *       Possible settings for "flags":
 *       NI_NOFQDN - Always return nodename portion of the fully-qualified
 *                   domain name (FQDN).
 *       NI_NUMERICHOST - Always return numeric form of the host's
 *			  address.
 *       NI_NAMEREQD - If hostname cannot be located in database,
 *                     don't return numeric form of address - return
 *                     an error instead.
 *       NI_NUMERICSERV - Always return numeric form of the service address
 *                        instead of its name.
 *       NI_DGRAM - Specifies that the service is a datagram service, and
 *                  causes getservbyport() to be called with a second
 *                  argument of "udp" instead of its default "tcp".
 * Output Parameters:
 *   host - return the nodename associcated with the IP address in the
 *          buffer pointed to by the "host" argument.
 *   serv - return the service name associated with the port number
 *          in the buffer pointed to by the "serv" argument.
 * Return Value:
 *   This function indicates successful completion by a zero return
 *   value; a non-zero return value indicates failure.
 */
int
getnameinfo(const struct sockaddr *sa, socklen_t salen,
    char *host, socklen_t hostlen,
    char *serv, socklen_t servlen, int flags)
{
	char		*addr;
	size_t		alen, slen;
	in_port_t	port;
	int		errnum;
	int		err;

	/* Verify correctness of buffer lengths */
	if ((hostlen == 0) && (servlen == 0))
		return (EAI_FAIL);
	/* Verify correctness of possible flag settings */
	if ((flags != 0) && (flags & ~NI_MASK))
		return (EAI_BADFLAGS);
	if (sa == NULL)
		return (EAI_ADDRFAMILY);
	switch (sa->sa_family) {
	case AF_INET:
		addr = (char *)&sa2sin(sa)->sin_addr;
		alen = sizeof (struct in_addr);
		slen = sizeof (struct sockaddr_in);
		port = (sa2sin(sa)->sin_port); /* network byte order */
		break;
	case AF_INET6:
		addr = (char *)&sa2sin6(sa)->sin6_addr;
		alen = sizeof (struct in6_addr);
		slen = sizeof (struct sockaddr_in6);
		port = (sa2sin6(sa)->sin6_port); /* network byte order */
		break;
	default:
		return (EAI_FAMILY);
	}
	if (salen != slen)
		return (EAI_FAIL);
	/*
	 * Case 1: if Caller sets hostlen != 0, then
	 * fill in "host" buffer that user passed in
	 * with appropriate text string.
	 */
	if (hostlen != 0) {
		if (flags & NI_NUMERICHOST) {
			/* Caller wants the host's numeric address */
			if (inet_ntop(sa->sa_family, addr,
			    host, hostlen) == NULL)
				return (EAI_SYSTEM);
		} else {
			struct hostent	*hp;

			/* Caller wants the name of host */
			hp = getipnodebyaddr(addr, alen, sa->sa_family,
			    &errnum);
			if (hp != NULL) {
				if (flags & NI_NOFQDN) {
					char *dot;
					/*
					 * Caller doesn't want fully-qualified
					 * name.
					 */
					dot = strchr(hp->h_name, '.');
					if (dot != NULL)
						*dot = '\0';
				}
				if (strlen(hp->h_name) + 1 > hostlen) {
					freehostent(hp);
					return (EAI_OVERFLOW);
				}
				(void) strcpy(host, hp->h_name);
				freehostent(hp);
			} else {
				/*
				 * Host's name cannot be located in the name
				 * service database. If NI_NAMEREQD is set,
				 * return error; otherwise, return host's
				 * numeric address.
				 */
				if (flags & NI_NAMEREQD) {
					switch (errnum) {
					case HOST_NOT_FOUND:
						return (EAI_NONAME);
					case TRY_AGAIN:
						return (EAI_AGAIN);
					case NO_RECOVERY:
						return (EAI_FAIL);
					case NO_ADDRESS:
						return (EAI_NODATA);
					default:
						return (EAI_SYSTEM);
					}
				}
				if (_inet_ntop_native(sa->sa_family, addr,
				    host, hostlen) == NULL)
					return (EAI_SYSTEM);
			}
		}

		/*
		 * Check for a non-zero sin6_scope_id, indicating a
		 * zone-id needs to be appended to the resultant 'host'
		 * string.
		 */
		if ((sa->sa_family == AF_INET6) &&
		    (sa2sin6(sa)->sin6_scope_id != 0)) {
			/*
			 * According to draft-ietf-ipngwg-scoping-arch-XX, only
			 * non-global scope addresses can make use of the
			 * <addr>%<zoneid> format.  This implemenation
			 * supports only link scope addresses, since the use of
			 * site-local addressing is not yet fully specified.
			 * If the address meets this criteria, attempt to add a
			 * zone-id to 'host'.  If it does not, return
			 * EAI_NONAME.
			 */
			if (IN6_IS_ADDR_LINKSCOPE(&(sa2sin6(sa)->sin6_addr))) {
				if ((err = addzoneid(sa2sin6(sa), host,
				    hostlen)) != 0) {
					return (err);
				}
			} else {
				return (EAI_NONAME);
			}
		}
	}
	/*
	 * Case 2: if Caller sets servlen != 0, then
	 * fill in "serv" buffer that user passed in
	 * with appropriate text string.
	 */
	if (servlen != 0) {
		char port_buf[10];
		int portlen;

		if (flags & NI_NUMERICSERV) {
			/* Caller wants the textual form of the port number */
			portlen = snprintf(port_buf, sizeof (port_buf), "%hu",
			    ntohs(port));
			if (servlen < portlen + 1)
				return (EAI_OVERFLOW);
			(void) strcpy(serv, port_buf);
		} else {
			struct servent	*sp;
			/*
			 * Caller wants the name of the service.
			 * If NI_DGRAM is set, get service name for
			 * specified port for udp.
			 */
			sp = getservbyport(port,
			    flags & NI_DGRAM ? "udp" : "tcp");
			if (sp != NULL) {
				if (servlen < strlen(sp->s_name) + 1)
					return (EAI_OVERFLOW);
				(void) strcpy(serv, sp->s_name);
			} else {
				/*
				 * if service is not in the name server's
				 * database, fill buffer with numeric form for
				 * port number.
				 */
				portlen = snprintf(port_buf, sizeof (port_buf),
				    "%hu", ntohs(port));
				if (servlen < portlen + 1)
					return (EAI_OVERFLOW);
				(void) strcpy(serv, port_buf);
			}
		}
	}
	return (0);
}

/*
 * addzoneid(sa, host, hostlen)
 *
 * Appends a zone-id to the input 'host' string if the input sin6_scope_id
 * is non-zero.  The resultant 'host' string would be of the form
 * 'host'%'zone-id'.  Where 'zone-id' can be either an interface name or a
 * literal interface index.
 *
 * Return Values:
 * 0 - on success
 * EAI_MEMORY - an error occured when forming the output string
 */
static int
addzoneid(const struct sockaddr_in6 *sa, char *host, size_t hostlen)
{
	char zonestr[LIFNAMSIZ];
	size_t zonelen;
	size_t addrlen = strlen(host);

	/* make sure zonelen is valid sizeof (<addr>%<zoneid>\0) */
	if (((zonelen = getzonestr(sa, zonestr, sizeof (zonestr))) == 0) ||
	    ((addrlen + 1 + zonelen + 1) > hostlen)) {
		return (EAI_MEMORY);
	}

	/* Create address string of form <addr>%<zoneid> */
	host[addrlen] = '%'; /* place address-zoneid delimiter */
	(void) strlcpy((host + addrlen + 1), zonestr, (zonelen + 1));
	return (0);
}

/*
 * getzonestr(sa, zonestr)
 *
 * parse zone string from input sockaddr_in6
 *
 * Note:  This function calls if_indextoname, a very poor interface,
 *        defined in RFC2553, for converting an interface index to an
 *        interface name.  Callers of this function must be sure that
 *        zonestr is atleast LIFNAMSIZ in length, since this is the longest
 *        possible value if_indextoname will return.
 *
 * Return values:
 * 0 an error with calling this function occured
 * >0 zonestr is filled with a valid zoneid string and the return value is the
 *    length of that string.
 */
static size_t
getzonestr(const struct sockaddr_in6 *sa, char *zonestr, size_t zonelen)
{
	uint32_t ifindex;
	char *retstr;

	if (zonestr == NULL) {
		return (0);
	}

	/*
	 * Since this implementation only supports link scope addresses,
	 * there is a one-to-one mapping between interface index and
	 * sin6_scope_id.
	 */
	ifindex = sa->sin6_scope_id;

	if ((retstr = if_indextoname(ifindex, zonestr)) != NULL) {
		return (strlen(retstr));
	} else {
		int n;

		/*
		 * Failed to convert ifindex into an interface name,
		 * simply return the literal value of ifindex as
		 * a string.
		 */
		if ((n = snprintf(zonestr, zonelen, "%u",
		    ifindex)) < 0) {
			return (0);
		} else {
			if (n >= zonelen) {
				return (0);
			}
			return (n);
		}
	}
}


/*
 * This is a wrapper function for inet_ntop(). In case the af is AF_INET6
 * and the address pointed by src is a IPv4-mapped IPv6 address, it
 * returns printable IPv4 address, not IPv4-mapped IPv6 address. In other cases
 * it behaves just like inet_ntop().
 */
static const char *
_inet_ntop_native(int af, const void *src, char *dst, size_t size)
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
