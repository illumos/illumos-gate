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

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <netdb.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>
#include <sys/debug.h>
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
 * getaddrinfo() returns EAI_NONAME in some cases, however since EAI_NONAME is
 * not part of SUSv3 it needed to be masked in the standards compliant
 * environment. GAIV_DEFAULT and GAIV_XPG6 accomplish this.
 */
#define	GAIV_DEFAULT	0
#define	GAIV_XPG6	1

/*
 * Storage allocation for global variables in6addr_any and in6addr_loopback.
 * The extern declarations for these variables are defined in <netinet/in.h>.
 * These two variables could have been defined in any of the "C" files in
 * libsocket. They are defined here with other IPv6 related interfaces.
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

typedef struct {
	int		si_socktype;
	int		si_protocol;
	ushort_t	si_port;
} spinfo_t;

/* function prototypes for used by getaddrinfo() routine */
static int get_addr(int, const char *, struct addrinfo *,
	struct addrinfo *, spinfo_t *, uint_t, int);
static uint_t getscopeidfromzone(const struct sockaddr_in6 *,
    const char *, uint32_t *);
static void servtype(const char *, int *, int *);
static boolean_t str_isnumber(const char *);

/*
 * getaddrinfo:
 *
 * Purpose:
 *   Routine for performing Address-to-nodename in a protocol-independent
 *   fashion.
 * Description and history of the routine:
 *   Nodename-to-address translation is done in a protocol- independent fashion
 *   using the getaddrinfo() function that is taken from IEEE POSIX 1003.1g.
 *
 *   The official specification for this function will be the final POSIX
 *   standard, with the following additional requirements:
 *
 *   - getaddrinfo() must be thread safe
 *   - The AI_NUMERICHOST is new.
 *   - All fields in socket address structures returned by getaddrinfo() that
 *     are not filled in through an explicit argument (e.g., sin6_flowinfo and
 *     sin_zero) must be set to 0. (This makes it easier to compare socket
 *     address structures).
 *
 * Input Parameters:
 *
 *   nodename       - pointer to a null-terminated string that represents
 *                    a hostname or literal ip address (IPv4/IPv6), or this
 *                    pointer can be NULL.
 *   servname       - pointer to a null-terminated string that represents
 *                    a servicename or literal port number, or this
 *                    pointer can be NULL.
 *   hints          - optional argument that points to an addrinfo structure
 *                    to provide hints on the type of socket that the caller
 *                    supports.
 *
 * Possible setting of the ai_flags member of the hints structure:
 *
 *   AI_PASSIVE     - If set, the caller plans to use the returned socket
 *                    address in a call to bind().  In this case, it the
 *                    nodename argument is NULL, then the IP address portion
 *                    of the socket address structure will be set to
 *                    INADDR_ANY for IPv4 or IN6ADDR_ANY_INIT for IPv6.
 *                    If not set, then the returned socket address will be
 *                    ready for a call to connect() (for conn-oriented) or
 *                    connect(), sendto(), or sendmsg() (for connectionless).
 *                    In this case, if nodename is NULL, then the IP address
 *                    portion of the socket address structure will be set to
 *                    the loopback address.
 *   AI_CANONNAME   - If set, then upon successful return the ai_canonname
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
 *   AI_ADDRCONFIG  - If set, IPv4 addresses are returned only if an IPv4
 *                    address is configured on the local system, and IPv6
 *                    addresses are returned only if an IPv6 address is
 *                    configured on the local system.
 *   AI_V4MAPPED    - If set, along with an ai_family of AF_INET6, then
 *                    getaddrinfo() shall return IPv4-mapped IPv6 addresses
 *                    on finding no matching IPv6 addresses (ai_addrlen shall
 *                    be 16). The AI_V4MAPPED flag shall be ignored unless
 *                    ai_family equals AF_INET6.
 *   AI_ALL         - If the AI_ALL flag is used with the AI_V4MAPPED flag,
 *		      then getaddrinfo() shall return all matching IPv6 and
 *		      IPv4 addresses. The AI_ALL flag without the AI_V4MAPPED
 *		      flag is ignored.
 *
 * Output Parameters:
 *
 *   res            - upon successful return a pointer to a linked list of one
 *                    or more addrinfo structures is returned through this
 *                    argument.  The caller can process each addrinfo structures
 *                    in this list by following the ai_next pointer, until a
 *                    NULL pointer is encountered.  In each returned addrinfo
 *                    structure the three members ai_family, ai_socktype, and
 *                    ai_protocol are corresponding arguments for a call to the
 *                    socket() function.  In each addrinfo structure the ai_addr
 *                    field points to filled-in socket address structure whose
 *                    length is specified by the ai_addrlen member.
 *
 * Return Value:
 *  This function returns 0 upon success or a nonzero error code.  The
 *  following names are nonzero error codes from getaddrinfo(), and are
 *  defined in <netdb.h>.
 *      EAI_ADDRFAMILY - address family not supported
 *      EAI_AGAIN      - DNS temporary failure
 *      EAI_BADFLAGS   - invalid ai_flags
 *      EAI_FAIL       - DNS non-recoverable failure
 *      EAI_FAMILY     - ai_family not supported
 *      EAI_MEMORY     - memory allocation failure
 *      EAI_NODATA     - no address associated with nodename
 *      EAI_NONAME     - host/servname not known
 *      EAI_SERVICE    - servname not supported for ai_socktype
 *      EAI_SOCKTYPE   - ai_socktype not supported
 *      EAI_SYSTEM     - system error in errno
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
	int error;
	uint_t i;

	/*
	 * We currently accumulate three services in the
	 * SOCKTYPE_ANY/AI_NUMERICSERV case and one otherwise. If the logic in
	 * this function is extended to return all matches from the services
	 * database when AI_NUMERICSERV is not specified, this will need
	 * revisiting.
	 */
#define	SPINFO_SIZE 3
	spinfo_t spinfo[SPINFO_SIZE];
	uint_t spidx = 0;
	/* Note that these macros require spinfo and spidx to be in scope */
#define	SP_ADDX(type, proto, port) \
	do { \
		ASSERT3U(spidx, <, SPINFO_SIZE); \
		spinfo[spidx].si_socktype = (type); \
		spinfo[spidx].si_protocol = (proto); \
		spinfo[spidx].si_port = (port); \
		spidx++; \
	} while (0)
#define	SP_ADD(sp) \
	do { \
		int _type, _proto; \
		servtype((sp)->s_proto, &_type, &_proto); \
		SP_ADDX(_type, _proto, (sp)->s_port); \
	} while (0)

	*res = NULL;

	if (hostname == NULL && servname == NULL)
		return (EAI_NONAME);

	cur = &ai;
	aip = &ai;

	if (hints == NULL) {
		aip->ai_flags = 0;
		aip->ai_family = PF_UNSPEC;
		aip->ai_socktype = ANY;
		aip->ai_protocol = ANY;
	} else {
		(void) memcpy(aip, hints, sizeof (*aip));

		/* check for bad flags in hints */
		if (hints->ai_flags != 0 && (hints->ai_flags & ~AI_MASK))
			return (EAI_BADFLAGS);

		if ((hostname == NULL || *hostname == '\0') &&
		    (hints->ai_flags & AI_CANONNAME)) {
			return (EAI_BADFLAGS);
		}

		if (hints->ai_family != PF_UNSPEC &&
		    hints->ai_family != PF_INET &&
		    hints->ai_family != PF_INET6) {
			return (EAI_FAMILY);
		}

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
			return (EAI_SOCKTYPE);
		}
	}

	aip->ai_addrlen = 0;
	aip->ai_canonname = NULL;
	aip->ai_addr = NULL;
	aip->ai_next = NULL;
#ifdef __sparcv9
	/*
	 * We need to clear _ai_pad to preserve binary compatibility with
	 * previously compiled 64-bit applications by guaranteeing the upper
	 * 32-bits are empty.
	 */
	aip->_ai_pad = 0;
#endif /* __sparcv9 */

	/*
	 * Get the service.
	 */

	if (servname != NULL) {
		struct servent result;
		int bufsize = 128;
		char *buf = NULL;
		struct servent *sp;
		const char *proto = NULL;

		switch (aip->ai_socktype) {
		case ANY:
		case SOCK_RAW:
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
		 */
		if (aip->ai_flags & AI_NUMERICSERV) {
			ushort_t port;

			if (!str_isnumber(servname))
				return (EAI_NONAME);

			port = htons(atoi(servname));
			if (aip->ai_socktype == ANY) {
				/*
				 * We cannot perform any name service lookups
				 * here, per RFC3493, and so we return one
				 * result for each of these types.
				 */
				SP_ADDX(SOCK_STREAM, IPPROTO_TCP, port);
				SP_ADDX(SOCK_DGRAM, IPPROTO_UDP, port);
				SP_ADDX(SOCK_STREAM, IPPROTO_SCTP, port);
			} else {
				SP_ADDX(aip->ai_socktype, aip->ai_protocol,
				    port);
			}
		} else if (str_isnumber(servname)) {
			ushort_t port = htons(atoi(servname));

			if (aip->ai_socktype != ANY) {
				/*
				 * If we already know the socket type there is
				 * no need to call getservbyport.
				 */
				SP_ADDX(aip->ai_socktype, aip->ai_protocol,
				    port);
			} else {
				do {
					buf = reallocf(buf, bufsize);
					if (buf == NULL)
						return (EAI_MEMORY);

					sp = getservbyport_r(port, proto,
					    &result, buf, bufsize);
					if (sp == NULL && errno != ERANGE) {
						free(buf);
						return (EAI_SERVICE);
					}
					/*
					 * errno == ERANGE so our scratch
					 * buffer space wasn't big enough.
					 * Double it and try again.
					 */
					bufsize *= 2;
				} while (sp == NULL);
				SP_ADD(sp);
			}
		} else {
			/*
			 * Look up the provided service name in the service
			 * database.
			 */
			do {
				buf = reallocf(buf, bufsize);
				if (buf == NULL)
					return (EAI_MEMORY);

				sp = getservbyname_r(servname, proto, &result,
				    buf, bufsize);
				if (sp == NULL && errno != ERANGE) {
					free(buf);
					return (EAI_SERVICE);
				}
				/*
				 * errno == ERANGE so our scratch buffer space
				 * wasn't big enough.  Double it and try again.
				 */
				bufsize *= 2;
			} while (sp == NULL);
			if (aip->ai_socktype != ANY) {
				SP_ADDX(aip->ai_socktype, aip->ai_protocol,
				    sp->s_port);
			} else {
				SP_ADD(sp);
			}
		}
		free(buf);

		if (spidx == 0)
			return (EAI_SERVICE);
	} else {
		SP_ADDX(aip->ai_socktype, aip->ai_protocol, 0);
	}

	error = get_addr(aip->ai_family, hostname, aip, cur,
	    spinfo, spidx, version);

	if (error != 0) {
		if (aip->ai_next != NULL)
			freeaddrinfo(aip->ai_next);
		return (error);
	}

	*res = aip->ai_next;
	return (0);
}
#undef SP_ADD
#undef SP_ADDX

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
add_address4(struct addrinfo *aip, struct addrinfo **cur,
    struct in_addr *addr, const char *canonname, spinfo_t *info)
{
	struct addrinfo *nai;
	int addrlen;

	nai = malloc(sizeof (struct addrinfo));
	if (nai == NULL)
		return (EAI_MEMORY);

	*nai = *aip;
	nai->ai_next = NULL;
	addrlen = sizeof (struct sockaddr_in);

	nai->ai_addr = malloc(addrlen);
	if (nai->ai_addr == NULL) {
		freeaddrinfo(nai);
		return (EAI_MEMORY);
	}

	bzero(nai->ai_addr, addrlen);
	nai->ai_addrlen = addrlen;
	nai->ai_family = PF_INET;

	(void) memcpy(&ai2sin(nai)->sin_addr, addr, sizeof (struct in_addr));
	nai->ai_canonname = NULL;
	if ((nai->ai_flags & AI_CANONNAME) && canonname != NULL) {
		canonname = strdup(canonname);
		if (canonname == NULL) {
			freeaddrinfo(nai);
			return (EAI_MEMORY);
		}
		nai->ai_canonname = (char *)canonname;
	}
	ai2sin(nai)->sin_family = PF_INET;
	ai2sin(nai)->sin_port = info->si_port;
	nai->ai_socktype = info->si_socktype;
	nai->ai_protocol = info->si_protocol;

	(*cur)->ai_next = nai;
	*cur = nai;

	return (0);
}

static int
add_address6(struct addrinfo *aip, struct addrinfo **cur,
    struct in6_addr *addr, const char *zonestr, const char *canonname,
    spinfo_t *info)
{
	struct addrinfo *nai;
	int addrlen;

	nai = malloc(sizeof (struct addrinfo));
	if (nai == NULL)
		return (EAI_MEMORY);

	*nai = *aip;
	nai->ai_next = NULL;
	addrlen = sizeof (struct sockaddr_in6);

	nai->ai_addr = malloc(addrlen);
	if (nai->ai_addr == NULL) {
		freeaddrinfo(nai);
		return (EAI_MEMORY);
	}

	bzero(nai->ai_addr, addrlen);
	nai->ai_addrlen = addrlen;
	nai->ai_family = PF_INET6;

	(void) memcpy(ai2sin6(nai)->sin6_addr.s6_addr,
	    &addr->s6_addr, sizeof (struct in6_addr));
	nai->ai_canonname = NULL;
	if ((nai->ai_flags & AI_CANONNAME) && canonname != NULL) {
		canonname = strdup(canonname);
		if (canonname == NULL) {
			freeaddrinfo(nai);
			return (EAI_MEMORY);
		}
		nai->ai_canonname = (char *)canonname;
	}
	ai2sin6(nai)->sin6_family = PF_INET6;
	ai2sin6(nai)->sin6_port = info->si_port;
	nai->ai_socktype = info->si_socktype;
	nai->ai_protocol = info->si_protocol;

	/* set sin6_scope_id */
	if (zonestr != NULL) {
		/* Translate 'zonestr' into a valid sin6_scope_id. */
		int err = getscopeidfromzone(ai2sin6(nai), zonestr,
		    &ai2sin6(nai)->sin6_scope_id);
		if (err != 0) {
			freeaddrinfo(nai);
			return (err);
		}
	} else {
		ai2sin6(nai)->sin6_scope_id = 0;
	}

	(*cur)->ai_next = nai;
	*cur = nai;

	return (0);
}

static int
get_addr(int family, const char *hostname, struct addrinfo *aip,
    struct addrinfo *cur, spinfo_t *ports, uint_t nport, int version)
{
	struct hostent		*hp;
	char			_hostname[MAXHOSTNAMELEN];
	int			errnum;
	boolean_t		firsttime = B_TRUE;
	char			*zonestr = NULL;
	uint_t			i;

	if (hostname == NULL) {
		/*
		 * case 1: AI_PASSIVE bit set : anyaddr 0.0.0.0 or ::
		 * case 2: AI_PASSIVE bit not set : localhost 127.0.0.1 or ::1
		 */
		const char *canon = "loopback";
		errnum = 0;

		/*
		 * PF_INET gets IPv4 only, PF_INET6 gets IPv6 only.
		 * PF_UNSPEC gets both.
		 */
		if (family != PF_INET) {
			struct in6_addr v6addr;

			if (aip->ai_flags & AI_PASSIVE) {
				(void) memcpy(&v6addr.s6_addr,
				    in6addr_any.s6_addr,
				    sizeof (struct in6_addr));
				canon = NULL;
			} else {
				(void) memcpy(&v6addr.s6_addr,
				    in6addr_loopback.s6_addr,
				    sizeof (struct in6_addr));
			}

			for (i = 0; i < nport; i++) {
				errnum = add_address6(aip, &cur, &v6addr, NULL,
				    canon, &ports[i]);
				canon = NULL;
				if (errnum != 0)
					break;
			}
		}

		if (errnum == 0 && family != PF_INET6) {
			struct in_addr addr;

			if (aip->ai_flags & AI_PASSIVE) {
				addr.s_addr = INADDR_ANY;
				canon = NULL;
			} else {
				addr.s_addr = htonl(INADDR_LOOPBACK);
			}

			for (i = 0; i < nport; i++) {
				errnum = add_address4(aip, &cur, &addr, canon,
				    &ports[i]);
				canon = NULL;
				if (errnum != 0)
					break;
			}
		}

		return (errnum);
	}

	/*
	 * Check for existence of address-zoneid delimiter '%'
	 * If the delimiter exists, parse the zoneid portion of
	 * <addr>%<zone_id>
	 */
	if ((zonestr = strchr(hostname, '%')) != NULL) {
		/* make sure we have room for <addr> portion of hostname */
		if ((zonestr - hostname) + 1 > sizeof (_hostname))
			return (EAI_MEMORY);

		/* chop off and save <zone_id> portion */
		(void) strlcpy(_hostname, hostname, (zonestr - hostname) + 1);
		++zonestr;	/* make zonestr point at start of <zone-id> */
		/* ensure zone is valid */
		if (*zonestr == '\0' || strlen(zonestr) > LIFNAMSIZ)
			return (EAI_NONAME);
	} else {
		size_t hlen = sizeof (_hostname);

		if (strlcpy(_hostname, hostname, hlen) >= hlen)
			return (EAI_MEMORY);
	}

	/* Check to see if AI_NUMERICHOST bit is set */
	if (aip->ai_flags & AI_NUMERICHOST) {
		struct in6_addr v6addr;

		/* check to see if _hostname points to a literal IP address */
		if (!(inet_addr(_hostname) != ((in_addr_t)-1) ||
		    strcmp(_hostname, HOST_BROADCAST) == 0 ||
		    inet_pton(AF_INET6, _hostname, &v6addr) > 0)) {
			return (EAI_NONAME);
		}
	}

	/* if hostname argument is literal, name service doesn't get called */
	if (family == PF_UNSPEC) {
		hp = getipnodebyname(_hostname, AF_INET6,
		    AI_ALL | aip->ai_flags | AI_V4MAPPED | AI_ADDRINFO,
		    &errnum);
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
		boolean_t create_v6_addrinfo = B_TRUE;
		struct in_addr v4addr;
		struct in6_addr v6addr;
		uint_t j;

		/* Determine if an IPv6 addrinfo structure should be created */
		if (hp->h_addrtype == AF_INET6) {
			struct in6_addr *v6addrp;

			v6addrp = (struct in6_addr *)hp->h_addr_list[i];
			if (!(aip->ai_flags & AI_V4MAPPED) &&
			    IN6_IS_ADDR_V4MAPPED(v6addrp)) {
				create_v6_addrinfo = B_FALSE;
				IN6_V4MAPPED_TO_INADDR(v6addrp, &v4addr);
			} else {
				(void) memcpy(&v6addr.s6_addr,
				    hp->h_addr_list[i],
				    sizeof (struct in6_addr));
			}
		} else if (hp->h_addrtype == AF_INET) {
			create_v6_addrinfo = B_FALSE;
			(void) memcpy(&v4addr.s_addr, hp->h_addr_list[i],
			    sizeof (struct in_addr));
		} else {
			return (EAI_SYSTEM);
		}

		for (j = 0; j < nport; j++) {
			if (create_v6_addrinfo) {
				errnum = add_address6(aip, &cur, &v6addr,
				    zonestr, firsttime ? hp->h_name : NULL,
				    &ports[j]);
			} else {
				errnum = add_address4(aip, &cur, &v4addr,
				    firsttime ? hp->h_name : NULL,
				    &ports[j]);
			}
			firsttime = B_FALSE;
			if (errnum != 0) {
				freehostent(hp);
				return (errnum);
			}
		}
	}
	freehostent(hp);
	return (0);
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
    uint32_t *sin6_scope_id)
{
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
		free(ai->ai_canonname);
		free(ai->ai_addr);
		free(ai);
		ai = next;
	} while (ai != NULL);
}

static void
servtype(const char *tag, int *type, int *proto)
{
	*type = *proto = 0;
	if (strcmp(tag, "udp") == 0) {
		*type = SOCK_DGRAM;
		*proto = IPPROTO_UDP;
	} else if (strcmp(tag, "tcp") == 0) {
		*type = SOCK_STREAM;
		*proto = IPPROTO_TCP;
	} else if (strcmp(tag, "sctp") == 0) {
		*type = SOCK_STREAM;
		*proto = IPPROTO_SCTP;
	}
}

static boolean_t
str_isnumber(const char *p)
{
	char *q = (char *)p;
	while (*q != '\0') {
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
