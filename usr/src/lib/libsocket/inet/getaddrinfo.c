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



#include <netdb.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>
#include <net/if.h>

#define	ai2sin(x)	((struct sockaddr_in *)((x)->ai_addr))
#define	ai2sin6(x)	((struct sockaddr_in6 *)((x)->ai_addr))

#define	HOST_BROADCAST	"255.255.255.255"

/*
 * getaddrinfo() returns EAI_NONAME in some cases, however
 * since EAI_NONAME is not part of SUSv3 it needed to be
 * masked in the standards compliant environment.
 * GAIV_DEFAULT and GAIV_XPG6 accomplish this.
 */
#define	GAIV_DEFAULT	0
#define	GAIV_XPG6	1

/*
 * Storage allocation for global variables in6addr_any and
 * in6addr_loopback.  The extern declarations for these
 * variables are defined in <netinet/in.h>.  These two
 * variables could have been defined in any of the "C" files
 * in libsocket. They are defined here with other IPv6
 * related interfaces.
 */
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;

/* AI_MASK:  all valid flags for addrinfo */
#define	AI_MASK		(AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST \
	| AI_ADDRCONFIG | AI_NUMERICSERV | AI_V4MAPPED | AI_ALL)
#define	ANY		0

/*
 * This is a private, undocumented, flag that getaddrinfo() uses for
 * getipnodebyname(). In the case of AI_ADDRCONFIG && AI_V4MAPPED, if there are
 * no IPv6 addresses, getaddrinfo() should return non-IPv4 mapped addresses. On
 * the flip side, getipnodebyname() is defined by RFC 2553 to explicitly do so.
 * Therefore this private flag indicates to getaddrinfo that we shouldn't do
 * this.
 */
#define	AI_ADDRINFO	0x8000

/* function prototypes for used by getaddrinfo() routine */
static int get_addr(int family, const char *hostname, struct addrinfo *aip,
	struct addrinfo *cur, ushort_t port, int version);
static uint_t getscopeidfromzone(const struct sockaddr_in6 *sa,
    const char *zone, uint32_t *sin6_scope_id);
static boolean_t str_isnumber(const char *p);

/*
 * getaddrinfo:
 *
 * Purpose:
 *   Routine for performing Address-to-nodename in a
 *   protocol-independent fashion.
 * Description and history of the routine:
 *   Nodename-to-address translation is done in a protocol-
 *   independent fashion using the getaddrinfo() function
 *   that is taken from the IEEE POSIX 1003.1g.
 *
 *   The official specification for this function will be the
 *   final POSIX standard, with the following additional
 *   requirements:
 *
 *   - getaddrinfo() must be thread safe
 *   - The AI_NUMERICHOST is new.
 *   - All fields in socket address structures returned by
 *
 *  getaddrinfo() that are not filled in through an explicit
 *  argument (e.g., sin6_flowinfo and sin_zero) must be set to 0.
 *  (This makes it easier to compare socket address structures).
 *
 * Input Parameters:
 *  nodename  - pointer to null-terminated strings that represents
 *              a hostname or literal ip address (IPv4/IPv6) or this
 *              pointer can be NULL.
 *  servname  - pointer to null-terminated strings that represents
 *              a servicename or literal port number or this
 *              pointer can be NULL.
 *  hints     - optional argument that points to an addrinfo structure
 *              to provide hints on the type of socket that the caller
 *              supports.
 *   Possible setting of the ai_flags member of the hints structure:
 *   AI_PASSIVE -     If set, the caller plans to use the returned socket
 *                    address in a call to bind().  In this case, it the
 *                    nodename argument is NULL, then the IP address portion
 *                    of the socket address structure will be set to
 *                    INADDR_ANY for IPv4 or IN6ADDR_ANY_INIT for IPv6.
 *   AI_PASSIVE -     If not set, then the returned socket address will be
 *                    ready for a call to connect() (for conn-oriented) or
 *                    connect(), sendto(), or sendmsg() (for connectionless).
 *                    In this case, if nodename is NULL, then the IP address
 *                    portion of the socket address structure will be set to
 *                    the loopback address.
 *   AI_CANONNAME -   If set, then upon successful return the ai_canonname
 *                    field of the first addrinfo structure in the linked
 *                    list will point to a NULL-terminated string
 *                    containing the canonical name of the specified nodename.
 *   AI_NUMERICHOST - If set, then a non-NULL nodename string must be a numeric
 *                    host address string.  Otherwise an error of EAI_NONAME
 *                    is returned.  This flag prevents any type of name
 *                    resolution service from being called.
 *   AI_NUMERICSERV - If set, then a non-null servname string supplied shall
 *                    be a numeric port string. Otherwise, an [EAI_NONAME]
 *                    error shall be returned. This flag shall prevent any
 *                    type of name resolution service from being invoked.
 *   AI_V4MAPPED -    If set, along with an ai_family of AF_INET6, then
 *                    getaddrinfo() shall return IPv4-mapped IPv6 addresses
 *                    on finding no matching IPv6 addresses ( ai_addrlen shall
 *                    be 16). The AI_V4MAPPED flag shall be ignored unless
 *                    ai_family equals AF_INET6.
 *   AI_ALL -	      If the AI_ALL flag is used with the AI_V4MAPPED flag,
 *		      then getaddrinfo() shall return all matching IPv6 and
 *		      IPv4 addresses. The AI_ALL flag without the AI_V4MAPPED
 *		      flag is ignored.
 * Output Parameters:
 *  res       - upon successful return a pointer to a linked list of one
 *              or more addrinfo structures is returned through this
 *              argument.  The caller can process each addrinfo structures
 *              in this list by following the ai_next pointer, until a
 *              NULL pointer is encountered.  In each returned addrinfo
 *              structure the three members ai_family, ai_socktype, and
 *              ai_protocol are corresponding arguments for a call to the
 *              socket() function.  In each addrinfo structure the ai_addr
 *              field points to filled-in socket address structure whose
 *              length is specified by the ai_addrlen member.
 *
 * Return Value:
 *  This function returns 0 upon success or a nonzero error code.  The
 *  following names are nonzero error codes from getaddrinfo(), and are
 *  defined in <netdb.h>.
 *  EAI_ADDRFAMILY - address family not supported
 *  EAI_AGAIN      - DNS temporary failure
 *  EAI_BADFLAGS   - invalid ai_flags
 *  EAI_FAIL       - DNS non-recoverable failure
 *  EAI_FAMILY     - ai_family not supported
 *  EAI_MEMORY     - memory allocation failure
 *  EAI_NODATA     - no address associated with nodename
 *  EAI_NONAME     - host/servname not known
 *  EAI_SERVICE    - servname not supported for ai_socktype
 *  EAI_SOCKTYPE   - ai_socktype not supported
 *  EAI_SYSTEM     - system error in errno
 *
 * Memory Allocation:
 *  All of the information returned by getaddrinfo() is dynamically
 *  allocated:  the addrinfo structures, and the socket address
 *  structures and canonical node name strings pointed to by the
 *  addrinfo structures.
 */


static int
_getaddrinfo(const char *hostname, const char *servname,
	const struct addrinfo *hints, struct addrinfo **res, int version)
{
	struct addrinfo *cur;
	struct addrinfo *aip;
	struct addrinfo ai;
	int		error;
	ushort_t	port;

	cur = &ai;
	aip = &ai;

	aip->ai_flags = 0;
	aip->ai_family = PF_UNSPEC;
	aip->ai_socktype = 0;
	aip->ai_protocol = 0;
#ifdef __sparcv9
	/*
	 * We need to clear _ai_pad to preserve binary
	 * compatibility with previously compiled 64-bit
	 * applications by guaranteeing the upper 32-bits
	 * are empty.
	 */
	aip->_ai_pad = 0;
#endif /* __sparcv9 */
	aip->ai_addrlen = 0;
	aip->ai_canonname = NULL;
	aip->ai_addr = NULL;
	aip->ai_next = NULL;
	port = 0;

	/* if nodename nor servname provided */
	if (hostname == NULL && servname == NULL) {
		*res = NULL;
		return (EAI_NONAME);
	}
	if (hints != NULL) {
		/* check for bad flags in hints */
		if ((hints->ai_flags != 0) && (hints->ai_flags & ~AI_MASK)) {
			*res = NULL;
			return (EAI_BADFLAGS);
		}
		if ((hostname == NULL || *hostname == '\0') &&
		    (hints->ai_flags & AI_CANONNAME)) {
				*res = NULL;
				return (EAI_BADFLAGS);
		}
		if (hints->ai_family != PF_UNSPEC &&
		    hints->ai_family != PF_INET &&
		    hints->ai_family != PF_INET6) {
			*res = NULL;
			return (EAI_FAMILY);
		}

		(void) memcpy(aip, hints, sizeof (*aip));
#ifdef __sparcv9
		/*
		 * We need to clear _ai_pad to preserve binary
		 * compatibility.  See prior comment.
		 */
		aip->_ai_pad = 0;
#endif /* __sparcv9 */
		switch (aip->ai_socktype) {
		case ANY:
			switch (aip->ai_protocol) {
			case ANY:
				break;
			case IPPROTO_UDP:
				aip->ai_socktype = SOCK_DGRAM;
				break;
			case IPPROTO_TCP:
			case IPPROTO_SCTP:
				aip->ai_socktype = SOCK_STREAM;
				break;
			default:
				aip->ai_socktype = SOCK_RAW;
				break;
			}
			break;
		case SOCK_RAW:
			break;
		case SOCK_SEQPACKET:
			/*
			 * If the hint does not have a preference on the
			 * protocol, use SCTP as the default for
			 * SOCK_SEQPACKET.
			 */
			if (aip->ai_protocol == ANY)
				aip->ai_protocol = IPPROTO_SCTP;
			break;
		case SOCK_DGRAM:
			aip->ai_protocol = IPPROTO_UDP;
			break;
		case SOCK_STREAM:
			/*
			 * If the hint does not have a preference on the
			 * protocol, use TCP as the default for SOCK_STREAM.
			 */
			if (aip->ai_protocol == ANY)
				aip->ai_protocol = IPPROTO_TCP;
			break;
		default:
			*res = NULL;
			return (EAI_SOCKTYPE);
		}
	}

	/*
	 *  Get the service.
	 */

	if (servname != NULL) {
		struct servent result;
		int bufsize = 128;
		char *buf = NULL;
		struct servent *sp;
		char *proto = NULL;

		switch (aip->ai_socktype) {
		case ANY:
			proto = NULL;
			break;
		case SOCK_DGRAM:
			proto = "udp";
			break;
		case SOCK_STREAM:
			/*
			 * If there is no hint given, use TCP as the default
			 * protocol.
			 */
			switch (aip->ai_protocol) {
			case ANY:
			case IPPROTO_TCP:
			default:
				proto = "tcp";
				break;
			case IPPROTO_SCTP:
				proto = "sctp";
				break;
			}
			break;
		case SOCK_SEQPACKET:
			/* Default to SCTP if no hint given. */
			switch (aip->ai_protocol) {
			case ANY:
			default:
				proto = "sctp";
				break;
			}
			break;
		}
		/*
		 * Servname string can be a decimal port number.
		 * If we already know the socket type there is no need
		 * to call getservbyport.
		 */
		if (aip->ai_flags & AI_NUMERICSERV) {
			if (!str_isnumber(servname)) {
				return (EAI_NONAME);
			}
			port = htons(atoi(servname));
		} else if (str_isnumber(servname)) {
			port = htons(atoi(servname));
			if (aip->ai_socktype == ANY) {
				do {
					if (buf != NULL)
						free(buf);
					bufsize *= 2;
					buf = malloc(bufsize);
					if (buf == NULL) {
						*res = NULL;
						return (EAI_MEMORY);
					}

					sp = getservbyport_r(port, proto,
					    &result, buf, bufsize);
					if (sp == NULL && errno != ERANGE) {
						free(buf);
						*res = NULL;
						return (EAI_SERVICE);
					}
				/*
				 * errno == ERANGE so our scratch buffer space
				 * wasn't big enough.  Double it and try
				 * again.
				 */
				} while (sp == NULL);
			}
		} else {
			do {
				if (buf != NULL)
					free(buf);
				bufsize *= 2;
				buf = malloc(bufsize);
				if (buf == NULL) {
					*res = NULL;
					return (EAI_MEMORY);
				}

				sp = getservbyname_r(servname, proto, &result,
				    buf, bufsize);
				if (sp == NULL && errno != ERANGE) {
					free(buf);
					*res = NULL;
					return (EAI_SERVICE);
				}
			/*
			 * errno == ERANGE so our scratch buffer space wasn't
			 * big enough.  Double it and try again.
			 */
			} while (sp == NULL);

			port = sp->s_port;
		}
		if (aip->ai_socktype == ANY) {
			if (aip->ai_flags & AI_NUMERICSERV) {
				/*
				 * RFC 2553bis doesn't allow us to use the
				 * any resolver to find out if there is a
				 * match.  We could walk the service file
				 * with *servent().  Given the commonality of
				 * calling getaddrinfo() with a number and
				 * ANY protocol we won't add that at this time.
				 */
				return (EAI_NONAME);
			}

			if (strcmp(sp->s_proto, "udp") == 0) {
				aip->ai_socktype = SOCK_DGRAM;
				aip->ai_protocol = IPPROTO_UDP;
			} else if (strcmp(sp->s_proto, "tcp") == 0) {
				aip->ai_socktype = SOCK_STREAM;
				aip->ai_protocol = IPPROTO_TCP;
			} else if (strcmp(sp->s_proto, "sctp") == 0) {
				aip->ai_socktype = SOCK_STREAM;
				aip->ai_protocol = IPPROTO_SCTP;
			} else {
				if (buf != NULL)
					free(buf);

				*res = NULL;
				errno = EPROTONOSUPPORT;
				return (EAI_SYSTEM);
			}
		}

		if (buf != NULL)
			free(buf);
	}

	/*
	 * hostname is NULL
	 * case 1: AI_PASSIVE bit set : anyaddr 0.0.0.0 or ::
	 * case 2: AI_PASSIVE bit not set : localhost 127.0.0.1 or ::1
	 */

	if (hostname == NULL) {
		struct addrinfo *nai;
		socklen_t addrlen;
		char *canonname;

		if (aip->ai_family == PF_INET)
			goto v4only;
		/* create IPv6 addrinfo */
		nai = malloc(sizeof (struct addrinfo));
		if (nai == NULL)
			goto nomem;
		*nai = *aip;
		addrlen = sizeof (struct sockaddr_in6);
		nai->ai_addr = malloc(addrlen);
		if (nai->ai_addr == NULL) {
			freeaddrinfo(nai);
			goto nomem;
		}
		bzero(nai->ai_addr, addrlen);
		nai->ai_addrlen = addrlen;
		nai->ai_family = PF_INET6;
		nai->ai_canonname = NULL;
		if (nai->ai_flags & AI_PASSIVE) {
			ai2sin6(nai)->sin6_addr = in6addr_any;
		} else {
			ai2sin6(nai)->sin6_addr = in6addr_loopback;
			if (nai->ai_flags & AI_CANONNAME) {
				canonname = strdup("loopback");
				if (canonname == NULL) {
					freeaddrinfo(nai);
					goto nomem;
				}
				nai->ai_canonname = canonname;
			}
		}
		ai2sin6(nai)->sin6_family = PF_INET6;
		ai2sin6(nai)->sin6_port = port;
		cur->ai_next = nai;
		cur = nai;
		if (aip->ai_family == PF_INET6) {
			cur->ai_next = NULL;
			goto success;
		}
		/* If address family is PF_UNSPEC or PF_INET */
v4only:
		/* create IPv4 addrinfo */
		nai = malloc(sizeof (struct addrinfo));
		if (nai == NULL)
			goto nomem;
		*nai = *aip;
		addrlen = sizeof (struct sockaddr_in);
		nai->ai_addr = malloc(addrlen);
		if (nai->ai_addr == NULL) {
			freeaddrinfo(nai);
			goto nomem;
		}
		bzero(nai->ai_addr, addrlen);
		nai->ai_addrlen = addrlen;
		nai->ai_family = PF_INET;
		nai->ai_canonname = NULL;
		if (nai->ai_flags & AI_PASSIVE) {
			ai2sin(nai)->sin_addr.s_addr = INADDR_ANY;
		} else {
			ai2sin(nai)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			if (nai->ai_flags & AI_CANONNAME &&
			    nai->ai_family != PF_UNSPEC) {
				canonname = strdup("loopback");
				if (canonname == NULL) {
					freeaddrinfo(nai);
					goto nomem;
				}
				nai->ai_canonname = canonname;
			}
		}
		ai2sin(nai)->sin_family = PF_INET;
		ai2sin(nai)->sin_port = port;
		cur->ai_next = nai;
		cur = nai;
		cur->ai_next = NULL;
		goto success;
	}

	/* hostname string is a literal address or an alphabetical name */
	error = get_addr(aip->ai_family, hostname, aip, cur, port, version);
	if (error) {
		*res = NULL;
		return (error);
	}

success:
	*res = aip->ai_next;
	return (0);

nomem:
	return (EAI_MEMORY);
}

int
getaddrinfo(const char *hostname, const char *servname,
	const struct addrinfo *hints, struct addrinfo **res)
{
	return (_getaddrinfo(hostname, servname, hints, res, GAIV_DEFAULT));
}

int
__xnet_getaddrinfo(const char *hostname, const char *servname,
	const struct addrinfo *hints, struct addrinfo **res)
{
	return (_getaddrinfo(hostname, servname, hints, res, GAIV_XPG6));
}

static int
get_addr(int family, const char *hostname, struct addrinfo *aip, struct
	addrinfo *cur, ushort_t port, int version)
{
	struct hostent		*hp;
	char			_hostname[MAXHOSTNAMELEN];
	int			i, errnum;
	struct addrinfo		*nai;
	int			addrlen;
	char			*canonname;
	boolean_t		firsttime = B_TRUE;
	boolean_t		create_v6_addrinfo;
	struct in_addr		v4addr;
	struct in6_addr		v6addr;
	struct in6_addr		*v6addrp;
	char			*zonestr = NULL;

	/*
	 * Check for existence of address-zoneid delimiter '%'
	 * If the delimiter exists, parse the zoneid portion of
	 * <addr>%<zone_id>
	 */
	if ((zonestr = strchr(hostname, '%')) != NULL) {
		/* make sure we have room for <addr> portion of hostname */
		if (((zonestr - hostname) + 1) > sizeof (_hostname)) {
			return (EAI_MEMORY);
		}

		/* chop off and save <zone_id> portion */
		(void) strlcpy(_hostname, hostname, (zonestr - hostname) + 1);
		++zonestr;	/* make zonestr point at start of <zone-id> */
		/* ensure zone is valid */
		if ((*zonestr == '\0') || (strlen(zonestr) > LIFNAMSIZ))  {
			return (EAI_NONAME);
		}
	} else {
		size_t hlen = sizeof (_hostname);

		if (strlcpy(_hostname, hostname, hlen) >= hlen) {
			return (EAI_MEMORY);
		}
	}

	/* Check to see if AI_NUMERICHOST bit is set */
	if (aip->ai_flags & AI_NUMERICHOST) {
		/* check to see if _hostname points to a literal IP address */
		if (!((inet_addr(_hostname) != ((in_addr_t)-1)) ||
		    (strcmp(_hostname, HOST_BROADCAST) == 0) ||
		    (inet_pton(AF_INET6, _hostname, &v6addr) > 0))) {
			return (EAI_NONAME);
		}
	}

	/* if hostname argument is literal, name service doesn't get called */
	if (family == PF_UNSPEC) {
		hp = getipnodebyname(_hostname, AF_INET6, AI_ALL |
		    aip->ai_flags | AI_V4MAPPED | AI_ADDRINFO, &errnum);
	} else {
		hp = getipnodebyname(_hostname, family, aip->ai_flags, &errnum);
	}

	if (hp == NULL) {
		switch (errnum) {
		case HOST_NOT_FOUND:
			return (EAI_NONAME);
		case TRY_AGAIN:
			return (EAI_AGAIN);
		case NO_RECOVERY:
			return (EAI_FAIL);
		case NO_ADDRESS:
			if (version == GAIV_XPG6)
				return (EAI_NONAME);
			return (EAI_NODATA);
		default:
		return (EAI_SYSTEM);
		}
	}

	for (i = 0; hp->h_addr_list[i]; i++) {
		/* Determine if an IPv6 addrinfo structure should be created */
		create_v6_addrinfo = B_TRUE;
		if (hp->h_addrtype == AF_INET6) {
			v6addrp = (struct in6_addr *)hp->h_addr_list[i];
			if (!(aip->ai_flags & AI_V4MAPPED) &&
			    IN6_IS_ADDR_V4MAPPED(v6addrp)) {
				create_v6_addrinfo = B_FALSE;
				IN6_V4MAPPED_TO_INADDR(v6addrp, &v4addr);
			}
		} else	if (hp->h_addrtype == AF_INET) {
			create_v6_addrinfo = B_FALSE;
			(void) memcpy(&v4addr, hp->h_addr_list[i],
			    sizeof (struct in_addr));
		} else {
			return (EAI_SYSTEM);
		}

		if (create_v6_addrinfo) {
			/* create IPv6 addrinfo */
			nai = malloc(sizeof (struct addrinfo));
			if (nai == NULL)
				goto nomem;
			*nai = *aip;
			addrlen = sizeof (struct sockaddr_in6);
			nai->ai_addr = malloc(addrlen);
			if (nai->ai_addr == NULL) {
				freeaddrinfo(nai);
				goto nomem;
			}
			bzero(nai->ai_addr, addrlen);
			nai->ai_addrlen = addrlen;
			nai->ai_family = PF_INET6;

			(void) memcpy(ai2sin6(nai)->sin6_addr.s6_addr,
			    hp->h_addr_list[i], sizeof (struct in6_addr));
			nai->ai_canonname = NULL;
			if ((nai->ai_flags & AI_CANONNAME) && firsttime) {
				canonname = strdup(hp->h_name);
				if (canonname == NULL) {
					freeaddrinfo(nai);
					goto nomem;
				}
				nai->ai_canonname = canonname;
				firsttime = B_FALSE;
			}
			ai2sin6(nai)->sin6_family = PF_INET6;
			ai2sin6(nai)->sin6_port = port;
			/* set sin6_scope_id */
			if (zonestr != NULL) {
				/*
				 * Translate 'zonestr' into a valid
				 * sin6_scope_id.
				 */
				if ((errnum =
				    getscopeidfromzone(ai2sin6(nai), zonestr,
				    &ai2sin6(nai)->sin6_scope_id)) != 0) {
					return (errnum);
				}
			} else {
				ai2sin6(nai)->sin6_scope_id = 0;
			}
		} else {
			/* create IPv4 addrinfo */
			nai = malloc(sizeof (struct addrinfo));
			if (nai == NULL)
				goto nomem;
			*nai = *aip;
			addrlen = sizeof (struct sockaddr_in);
			nai->ai_addr = malloc(addrlen);
			if (nai->ai_addr == NULL) {
				freeaddrinfo(nai);
				goto nomem;
			}
			bzero(nai->ai_addr, addrlen);
			nai->ai_addrlen = addrlen;
			nai->ai_family = PF_INET;
			(void) memcpy(&(ai2sin(nai)->sin_addr.s_addr),
			    &v4addr, sizeof (struct in_addr));
			nai->ai_canonname = NULL;
			if (nai->ai_flags & AI_CANONNAME && firsttime) {
				canonname = strdup(hp->h_name);
				if (canonname == NULL) {
					freeaddrinfo(nai);
					goto nomem;
				}
				nai->ai_canonname = canonname;
				firsttime = B_FALSE;
			}
			ai2sin(nai)->sin_family = PF_INET;
			ai2sin(nai)->sin_port = port;
		}

		cur->ai_next = nai;
		cur = nai;
	}
	cur->ai_next = NULL;
	freehostent(hp);
	return (0);

nomem:
	freehostent(hp);
	return (EAI_MEMORY);

}

/*
 * getscopeidfromzone(sa, zone, sin6_scope_id)
 *
 * Converts the string pointed to by 'zone' into a sin6_scope_id.
 * 'zone' will either be a pointer to an interface name or will
 * be a literal sin6_scope_id.
 *
 * 0 is returned on success and the output parameter 'sin6_scope_id' will
 *   be set to a valid sin6_scope_id.
 * EAI_NONAME is returned for either of two reasons:
 *	1.  The IPv6 address pointed to by sa->sin6_addr is not
 *	    part of the 'link scope' (ie link local, nodelocal multicast or
 *	    linklocal multicast address)
 *	2.  The string pointed to by 'zone' can not be translate to a valid
 *	    sin6_scope_id.
 */
static uint_t
getscopeidfromzone(const struct sockaddr_in6 *sa, const char *zone,
    uint32_t *sin6_scope_id) {
	const in6_addr_t *addr = &sa->sin6_addr;
	ulong_t ul_scope_id;
	char *endp;

	if (IN6_IS_ADDR_LINKSCOPE(addr)) {
		/*
		 * Look up interface index associated with interface name
		 * pointed to by 'zone'.  Since the address is part of the link
		 * scope, there is a one-to-one relationship between interface
		 * index and sin6_scope_id.
		 * If an interface index can not be found for 'zone', then
		 * treat 'zone' as a literal sin6_scope_id value.
		 */
		if ((*sin6_scope_id = if_nametoindex(zone)) != 0) {
			return (0);
		} else {
			if ((ul_scope_id = strtoul(zone, &endp, 10)) != 0) {
				/* check that entire string was read */
				if (*endp != '\0') {
					return (EAI_NONAME);
				}
				*sin6_scope_id =
				    (uint32_t)(ul_scope_id & 0xffffffffUL);
			} else {
				return (EAI_NONAME);
			}
		}
	} else {
		return (EAI_NONAME);
	}
	return (0);
}


void
freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

	do {
		next = ai->ai_next;
		if (ai->ai_canonname)
			free(ai->ai_canonname);
		if (ai->ai_addr)
			free(ai->ai_addr);
		free(ai);
		ai = next;
	} while (ai != NULL);
}

static boolean_t
str_isnumber(const char *p)
{
	char *q = (char *)p;
	while (*q) {
		if (!isdigit(*q))
			return (B_FALSE);
		q++;
	}
	return (B_TRUE);
}
static const char *gai_errlist[] = {
	"name translation error 0 (no error)",		/* 0 */
	"specified address family not supported",	/* 1 EAI_ADDRFAMILY */
	"temporary name resolution failure",		/* 2 EAI_AGAIN */
	"invalid flags",				/* 3 EAI_BADFLAGS */
	"non-recoverable name resolution failure",	/* 4 EAI_FAIL */
	"specified address family not supported",	/* 5 EAI_FAMILY */
	"memory allocation failure",			/* 6 EAI_MEMORY */
	"no address for the specified node name",	/* 7 EAI_NODATA */
	"node name or service name not known",		/* 8 EAI_NONAME */
	"service name not available for the specified socket type",
							/* 9 EAI_SERVICE */
	"specified socket type not supported",		/* 10 EAI_SOCKTYPE */
	"system error",					/* 11 EAI_SYSTEM */
};
static int gai_nerr = { sizeof (gai_errlist)/sizeof (gai_errlist[0]) };

const char *
gai_strerror(int ecode)
{
	if (ecode < 0)
		return (dgettext(TEXT_DOMAIN,
		    "name translation internal error"));
	else if (ecode < gai_nerr)
		return (dgettext(TEXT_DOMAIN, gai_errlist[ecode]));
	return (dgettext(TEXT_DOMAIN, "unknown name translation error"));
}
