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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * This is where we have chosen to combine every useful bit of code for
 * all the Solaris frontends to lookup hosts, services, and netdir information
 * for inet family (udp, tcp) transports. gethostbyYY(), getservbyYY(), and
 * netdir_getbyYY() are all implemented on top of this code. Similarly,
 * netdir_options, taddr2uaddr, and uaddr2taddr for inet transports also
 * find a home here.
 *
 * If the netconfig structure supplied has NO nametoaddr libs (i.e. a "-"
 * in /etc/netconfig), this code calls the name service switch, and
 * therefore, /etc/nsswitch.conf is effectively the only place that
 * dictates hosts/serv lookup policy.
 * If an administrator chooses to bypass the name service switch by
 * specifying third party supplied nametoaddr libs in /etc/netconfig, this
 * implementation does NOT call the name service switch, it merely loops
 * through the nametoaddr libs. In this case, if this code was called
 * from gethost/servbyYY() we marshal the inet specific struct into
 * transport independent netbuf or hostserv, and unmarshal the resulting
 * nd_addrlist or hostservlist back into hostent and servent, as the case
 * may be.
 *
 * Goes without saying that most of the future bugs in gethost/servbyYY
 * and netdir_getbyYY are lurking somewhere here.
 */

#include "mt.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <thread.h>
#include <synch.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <netconfig.h>
#include <netdir.h>
#include <tiuser.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <inet/ip.h>
#include <inet/ip6_asp.h>
#include <sys/dlpi.h>
#include <nss_dbdefs.h>
#include <nss_netdir.h>
#include <syslog.h>
#include <nsswitch.h>
#include "nss.h"

#define	MAXIFS 32
#define	UDPDEV	"/dev/udp"
#define	UDP6DEV	"/dev/udp6"

#define	DOOR_GETHOSTBYNAME_R	_switch_gethostbyname_r
#define	DOOR_GETHOSTBYADDR_R	_switch_gethostbyaddr_r
#define	DOOR_GETIPNODEBYNAME_R	_switch_getipnodebyname_r
#define	DOOR_GETIPNODEBYADDR_R	_switch_getipnodebyaddr_r

#define	DONT_SORT	"SORT_ADDRS=NO"
#define	DONT_SORT2	"SORT_ADDRS=FALSE"
#define	LINESIZE	100

/*
 * constant values of addresses for HOST_SELF_BIND, HOST_SELF_CONNECT
 * and localhost.
 *
 * The following variables are static to the extent that they should
 * not be visible outside of this file.
 */
static char *localaddr[] = {"\000\000\000\000", NULL};
static char *connectaddr[] = {"\177\000\000\001", NULL};
static char *localaddr6[] =
{"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000", NULL};
static char *connectaddr6[] =
{"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001", NULL};

/* IPv4 nd_addrlist */
static mutex_t	nd_addr_lock = DEFAULTMUTEX;
static struct sockaddr_in sa_con;
static struct netbuf nd_conbuf = {sizeof (sa_con),\
    sizeof (sa_con), (char *)&sa_con};
static struct nd_addrlist nd_conaddrlist = {1, &nd_conbuf};

/* IPv6 nd_addrlist */
static mutex_t	nd6_addr_lock = DEFAULTMUTEX;
static struct sockaddr_in6 sa6_con;
static struct netbuf nd6_conbuf = {sizeof (sa6_con),\
	sizeof (sa6_con), (char *)&sa6_con};
static struct nd_addrlist nd6_conaddrlist = {1, &nd6_conbuf};

#define	LOCALHOST "localhost"

struct servent *_switch_getservbyname_r(const char *, const char *,
    struct servent *, char *, int);
struct servent *_switch_getservbyport_r(int, const char *, struct servent *,
    char *, int);

static int __herrno2netdir(int h_errnop);
static struct ifinfo *get_local_info(void);
static int getbroadcastnets(struct netconfig *, struct in_addr **);
static int hent2ndaddr(int, char **, int *, struct nd_addrlist **);
static int ndaddr2hent(int, const char *, struct nd_addrlist *,
    struct hostent *, char *, int);
static int hsents2ndhostservs(struct hostent *, struct servent *, ushort_t,
    struct nd_hostservlist **);
static int ndaddr2srent(const char *, const char *, ushort_t, struct servent *,
    char *, int);
static int ndhostserv2hent(struct netbuf *, struct nd_hostservlist *,
    struct hostent *, char *, int);
static int ndhostserv2srent(int, const char *, struct nd_hostservlist *,
    struct servent *, char *, int);
static int nd2herrno(int nerr);
static void order_haddrlist_inet(char **haddrlist, size_t addrcount);
static void order_haddrlist_inet6(char **haddrlist, size_t addrcount);
static int dstcmp(const void *, const void *);
static int nss_strioctl(int af, int cmd, void *ptr, int ilen);
static struct in_addr _inet_makeaddr(in_addr_t, in_addr_t);
static boolean_t _read_nsw_file(void);

/*
 * Begin: PART I
 * Top Level Interfaces that gethost/serv/netdir funnel through.
 */

static int
inetdir_free(int ret, struct in_addr *inaddrs, char **baddrlist)
{
	if (inaddrs)
		free(inaddrs);
	if (baddrlist)
		free(baddrlist);
	_nderror = ret;
	return (ret);
}

/*
 * gethost/servbyname always call this function; if they call
 * with nametoaddr libs in nconf, we call netdir_getbyname
 * implementation: __classic_netdir_getbyname, otherwise nsswitch.
 *
 * netdir_getbyname calls this only if nametoaddr libs are NOT
 * specified for inet transports; i.e. it's supposed to follow
 * the name service switch.
 */
int
_get_hostserv_inetnetdir_byname(struct netconfig *nconf,
    struct nss_netdirbyname_in *args, union nss_netdirbyname_out *res)
{
	int	server_port;
	int *servp = &server_port;
	char	**haddrlist;
	uint32_t dotnameaddr;
	char	*dotnamelist[2];
	struct in_addr	*inaddrs = NULL;
	struct in6_addr	v6nameaddr;
	char	**baddrlist = NULL;

	if (nconf == NULL) {
		_nderror = ND_BADARG;
		return (ND_BADARG);
	}

	/*
	 * 1. gethostbyname()/netdir_getbyname() special cases:
	 */
	switch (args->op_t) {

		case NSS_HOST:
		/*
		 * Worth the performance gain -- assuming a lot of inet apps
		 * actively use "localhost".
		 */
		if (strcmp(args->arg.nss.host.name, LOCALHOST) == 0) {

			(void) mutex_lock(&nd_addr_lock);
			IN_SET_LOOPBACK_ADDR(&sa_con);
			_nderror = ndaddr2hent(AF_INET, args->arg.nss.host.name,
			    &nd_conaddrlist, res->nss.host.hent,
			    args->arg.nss.host.buf,
			    args->arg.nss.host.buflen);
			(void) mutex_unlock(&nd_addr_lock);
			if (_nderror != ND_OK)
				*(res->nss.host.herrno_p) =
				    nd2herrno(_nderror);
			return (_nderror);
		}
		/*
		 * If the caller passed in a dot separated IP notation to
		 * gethostbyname, return that back as the address.
		 * The nd_addr_lock mutex was added to be truely re-entrant.
		 */
		if (inet_aton(args->arg.nss.host.name,
		    (struct in_addr *)&dotnameaddr)) {
			(void) mutex_lock(&nd_addr_lock);
			(void) memset(&sa_con, 0, sizeof (sa_con));
			sa_con.sin_family = AF_INET;
			sa_con.sin_addr.s_addr = dotnameaddr;
			_nderror = ndaddr2hent(AF_INET, args->arg.nss.host.name,
			    &nd_conaddrlist, res->nss.host.hent,
			    args->arg.nss.host.buf,
			    args->arg.nss.host.buflen);
			(void) mutex_unlock(&nd_addr_lock);
			if (_nderror != ND_OK)
				*(res->nss.host.herrno_p) =
				    nd2herrno(_nderror);
			return (_nderror);
		}
		break;

		case NSS_HOST6:
		/*
		 * Handle case of literal address string.
		 */
		if (strchr(args->arg.nss.host6.name, ':') != NULL &&
		    (inet_pton(AF_INET6, args->arg.nss.host6.name,
		    &v6nameaddr) != 0)) {
			int	ret;

			(void) mutex_lock(&nd6_addr_lock);
			(void) memset(&sa6_con, 0, sizeof (sa6_con));
			sa6_con.sin6_family = AF_INET6;
			(void) memcpy(&(sa6_con.sin6_addr.s6_addr),
			    &v6nameaddr, sizeof (struct in6_addr));
			ret = ndaddr2hent(AF_INET6,
			    args->arg.nss.host6.name,
			    &nd6_conaddrlist, res->nss.host.hent,
			    args->arg.nss.host6.buf,
			    args->arg.nss.host6.buflen);
			(void) mutex_unlock(&nd6_addr_lock);
			if (ret != ND_OK)
				*(res->nss.host.herrno_p) = nd2herrno(ret);
			else
				res->nss.host.hent->h_aliases = NULL;
			return (ret);
		}
		break;

		case NETDIR_BY:
			if (args->arg.nd_hs == 0) {
				_nderror = ND_BADARG;
				return (ND_BADARG);
			}
			/*
			 * If servname is NULL, return 0 as the port number
			 * If servname is rpcbind, return 111 as the port number
			 * If servname is a number, return it back as the port
			 * number.
			 */
			if (args->arg.nd_hs->h_serv == 0) {
				*servp = htons(0);
			} else if (strcmp(args->arg.nd_hs->h_serv,
			    "rpcbind") == 0) {
				*servp = htons(111);
			} else if (strspn(args->arg.nd_hs->h_serv,
			    "0123456789") ==
			    strlen(args->arg.nd_hs->h_serv)) {
				*servp = htons(atoi(args->arg.nd_hs->h_serv));
			} else {
				/* i.e. need to call a name service on this */
				servp = NULL;
			}

			/*
			 * If the hostname is HOST_SELF_BIND, we return 0.0.0.0
			 * so the  binding can be contacted through all
			 * interfaces. If the hostname is HOST_SELF_CONNECT,
			 * we return 127.0.0.1 so the address can be connected
			 * to locally. If the hostname is HOST_ANY, we return
			 * no addresses because IP doesn't know how to specify
			 * a service without a host. And finally if we specify
			 * HOST_BROADCAST then we ask a tli fd to tell us what
			 * the broadcast addresses are for any udp
			 * interfaces on this machine.
			 */
			if (args->arg.nd_hs->h_host == 0) {
				_nderror = ND_NOHOST;
				return (ND_NOHOST);
			} else if ((strcmp(args->arg.nd_hs->h_host,
			    HOST_SELF_BIND) == 0)) {
				haddrlist = localaddr;
			} else if ((strcmp(args->arg.nd_hs->h_host,
			    HOST_SELF_CONNECT) == 0)) {
				haddrlist = connectaddr;
			} else if ((strcmp(args->arg.nd_hs->h_host,
			    LOCALHOST) == 0)) {
				haddrlist = connectaddr;
			} else if ((int)(dotnameaddr =
			    inet_addr(args->arg.nd_hs->h_host)) != -1) {
				/*
				 * If the caller passed in a dot separated IP
				 * notation to netdir_getbyname, convert that
				 * back into address.
				 */

				dotnamelist[0] = (char *)&dotnameaddr;
				dotnamelist[1] = NULL;
				haddrlist = dotnamelist;
			} else if ((strcmp(args->arg.nd_hs->h_host,
			    HOST_BROADCAST) == 0)) {
				/*
				 * Now that inaddrs and baddrlist are
				 * dynamically allocated, care must be
				 * taken in freeing up the
				 * memory at each 'return()' point.
				 *
				 * Early return protection (using
				 * inetdir_free()) is needed only in NETDIR_BY
				 * cases because dynamic allocation is used
				 * when args->op_t == NETDIR_BY.
				 *
				 * Early return protection is not needed in
				 * haddrlist==0 conditionals because dynamic
				 * allocation guarantees haddrlist!=0.
				 *
				 * Early return protection is not needed in most
				 * servp!=0 conditionals because this is handled
				 * (and returned) first.
				 */
				int i, bnets;

				bnets = getbroadcastnets(nconf, &inaddrs);
				if (bnets == 0) {
					_nderror = ND_NOHOST;
					return (ND_NOHOST);
				}
				baddrlist = malloc((bnets+1)*sizeof (char *));
				if (baddrlist == NULL)
					return (inetdir_free(ND_NOMEM, inaddrs,
					    baddrlist));
				for (i = 0; i < bnets; i++)
					baddrlist[i] = (char *)&inaddrs[i];
				baddrlist[i] = NULL;
				haddrlist = baddrlist;
			} else {
				/* i.e. need to call a name service on this */
				haddrlist = 0;
			}

			if (haddrlist && servp) {
				int ret;
				/*
				 * Convert h_addr_list into nd_addrlist.
				 * malloc's will be done, freed using
				 * netdir_free.
				 */
				ret = hent2ndaddr(AF_INET, haddrlist, servp,
				    res->nd_alist);
				return (inetdir_free(ret, inaddrs, baddrlist));
			}
			break;


		case NETDIR_BY6:
			if (args->arg.nd_hs == 0) {
				_nderror = ND_BADARG;
				return (ND_BADARG);
			}
			/*
			 * If servname is NULL, return 0 as the port number.
			 * If servname is rpcbind, return 111 as the port number
			 * If servname is a number, return it back as the port
			 * number.
			 */
			if (args->arg.nd_hs->h_serv == 0) {
				*servp = htons(0);
			} else if (strcmp(args->arg.nd_hs->h_serv,
			    "rpcbind") == 0) {
				*servp = htons(111);
			} else if (strspn(args->arg.nd_hs->h_serv, "0123456789")
			    == strlen(args->arg.nd_hs->h_serv)) {
				*servp = htons(atoi(args->arg.nd_hs->h_serv));
			} else {
				/* i.e. need to call a name service on this */
				servp = NULL;
			}

			/*
			 * If the hostname is HOST_SELF_BIND, we return ipv6
			 * localaddress so the binding can be contacted through
			 * all interfaces.
			 * If the hostname is HOST_SELF_CONNECT, we return
			 * ipv6 loopback address so the address can be connected
			 * to locally.
			 * If the hostname is HOST_ANY, we return no addresses
			 * because IP doesn't know how to specify a service
			 * without a host.
			 * And finally if we specify HOST_BROADCAST then we
			 * disallow since IPV6 does not have any
			 * broadcast concept.
			 */
			if (args->arg.nd_hs->h_host == 0) {
				return (ND_NOHOST);
			} else if ((strcmp(args->arg.nd_hs->h_host,
			    HOST_SELF_BIND) == 0)) {
				haddrlist = localaddr6;
			} else if ((strcmp(args->arg.nd_hs->h_host,
			    HOST_SELF_CONNECT) == 0)) {
				haddrlist = connectaddr6;
			} else if ((strcmp(args->arg.nd_hs->h_host,
			    LOCALHOST) == 0)) {
				haddrlist = connectaddr6;
			} else if (strchr(args->arg.nd_hs->h_host, ':')
			    != NULL) {

			/*
			 * If the caller passed in a dot separated IP notation
			 * to netdir_getbyname, convert that back into address.
			 */

				if ((inet_pton(AF_INET6,
				    args->arg.nd_hs->h_host,
				    &v6nameaddr)) != 0) {
					dotnamelist[0] = (char *)&v6nameaddr;
					dotnamelist[1] = NULL;
					haddrlist = dotnamelist;
				}
				else
					/* not sure what to return */
					return (ND_NOHOST);

			} else if ((strcmp(args->arg.nd_hs->h_host,
			    HOST_BROADCAST) == 0)) {
				/*
				 * Don't support broadcast in
				 * IPV6
				 */
				return (ND_NOHOST);
			} else {
				/* i.e. need to call a name service on this */
				haddrlist = 0;
			}

			if (haddrlist && servp) {
				int ret;
				/*
				 * Convert h_addr_list into nd_addrlist.
				 * malloc's will be done, freed
				 * using netdir_free.
				 */
				ret = hent2ndaddr(AF_INET6, haddrlist,
				    servp, res->nd_alist);
				return (inetdir_free(ret, inaddrs, baddrlist));
			}
			break;


	}

	/*
	 * 2. Most common scenario. This is the way we ship /etc/netconfig.
	 *    Emphasis on improving performance in the "if" part.
	 */
	if (nconf->nc_nlookups == 0) {
		struct hostent	*he = NULL, *tmphe;
		struct servent	*se;
		int	ret;
		nss_XbyY_buf_t	*ndbuf4switch = 0;

	switch (args->op_t) {

		case NSS_HOST:

		he = DOOR_GETHOSTBYNAME_R(args->arg.nss.host.name,
		    res->nss.host.hent, args->arg.nss.host.buf,
		    args->arg.nss.host.buflen,
		    res->nss.host.herrno_p);
		if (he == NULL)
			return (_nderror = ND_NOHOST);
		return (_nderror = ND_OK);

		case NSS_HOST6:

		he = DOOR_GETIPNODEBYNAME_R(args->arg.nss.host6.name,
		    res->nss.host.hent, args->arg.nss.host.buf,
		    args->arg.nss.host6.buflen,
		    args->arg.nss.host6.af_family,
		    args->arg.nss.host6.flags,
		    res->nss.host.herrno_p);

		if (he == NULL)
			return (_nderror = ND_NOHOST);
		return (_nderror = ND_OK);

		case NSS_SERV:

		se = _switch_getservbyname_r(args->arg.nss.serv.name,
		    args->arg.nss.serv.proto,
		    res->nss.serv, args->arg.nss.serv.buf,
		    args->arg.nss.serv.buflen);

		_nderror = ND_OK;
		if (se == 0)
			_nderror = ND_NOSERV;
		return (_nderror);

		case NETDIR_BY:

		if (servp == 0) {
			char	*proto = (strcmp(nconf->nc_proto,
			    NC_TCP) == 0) ? NC_TCP : NC_UDP;

			/*
			 * We go through all this for just one port number,
			 * which is most often constant. How about linking in
			 * an indexed database of well-known ports in the name
			 * of performance ?
			 */
			ndbuf4switch = _nss_XbyY_buf_alloc(
			    sizeof (struct servent), NSS_BUFLEN_SERVICES);
			if (ndbuf4switch == 0)
				return (inetdir_free(ND_NOMEM, inaddrs,
				    baddrlist));
			se = _switch_getservbyname_r(args->arg.nd_hs->h_serv,
			    proto, ndbuf4switch->result,
			    ndbuf4switch->buffer, ndbuf4switch->buflen);
			if (!se) {
				NSS_XbyY_FREE(&ndbuf4switch);
				return (inetdir_free(ND_NOSERV, inaddrs,
				    baddrlist));
			}
			server_port = se->s_port;
			NSS_XbyY_FREE(&ndbuf4switch);
		}

		if (haddrlist == 0) {
			int	h_errnop = 0;

			ndbuf4switch = _nss_XbyY_buf_alloc(
			    sizeof (struct hostent),
			    NSS_BUFLEN_HOSTS);
			if (ndbuf4switch == 0) {
				_nderror = ND_NOMEM;
				return (ND_NOMEM);
			}
			/*
			 * Search the ipnodes (v6) path first,
			 * search will return the v4 addresses
			 * as v4mapped addresses.
			 */
			if ((tmphe = DOOR_GETIPNODEBYNAME_R(
			    args->arg.nd_hs->h_host,
			    ndbuf4switch->result, ndbuf4switch->buffer,
			    ndbuf4switch->buflen, args->arg.nss.host6.af_family,
			    args->arg.nss.host6.flags, &h_errnop)) != NULL)
				he = __mappedtov4(tmphe, &h_errnop);

			if (he == NULL) {
				/* Failover case, try hosts db for v4 address */
				he = DOOR_GETHOSTBYNAME_R(
				    args->arg.nd_hs->h_host,
				    ndbuf4switch->result, ndbuf4switch->buffer,
				    ndbuf4switch->buflen, &h_errnop);
				if (he == NULL) {
					NSS_XbyY_FREE(&ndbuf4switch);
					_nderror = __herrno2netdir(h_errnop);
					return (_nderror);
				}
				/*
				 * Convert h_addr_list into nd_addrlist.
				 * malloc's will be done, freed using
				 * netdir_free.
				 */
				ret = hent2ndaddr(AF_INET, he->h_addr_list,
				    &server_port, res->nd_alist);
			} else {
				/*
				 * Convert h_addr_list into nd_addrlist.
				 * malloc's will be done, freed using
				 * netdir_free.
				 */
				ret = hent2ndaddr(AF_INET, he->h_addr_list,
				    &server_port, res->nd_alist);
				freehostent(he);
			}

			_nderror = ret;
			NSS_XbyY_FREE(&ndbuf4switch);
			return (ret);
		} else {
			int ret;
			/*
			 * Convert h_addr_list into nd_addrlist.
			 * malloc's will be done, freed using netdir_free.
			 */
			ret = hent2ndaddr(AF_INET, haddrlist,
			    &server_port, res->nd_alist);
			return (inetdir_free(ret, inaddrs, baddrlist));
		}


		case NETDIR_BY6:

			if (servp == 0) {
				char	*proto = (strcmp(nconf->nc_proto,
				    NC_TCP) == 0) ? NC_TCP : NC_UDP;

				/*
				 * We go through all this for just
				 * one port number,
				 * which is most often constant.
				 * How about linking in
				 * an indexed database of well-known
				 * ports in the name
				 * of performance ?
				 */
				ndbuf4switch = _nss_XbyY_buf_alloc(
				    sizeof (struct servent),
				    NSS_BUFLEN_SERVICES);
				if (ndbuf4switch == 0)
					return (inetdir_free(ND_NOMEM, inaddrs,
					    baddrlist));
				se = _switch_getservbyname_r(
				    args->arg.nd_hs->h_serv,
				    proto, ndbuf4switch->result,
				    ndbuf4switch->buffer, ndbuf4switch->buflen);
				if (!se) {
					NSS_XbyY_FREE(&ndbuf4switch);
					return (inetdir_free(ND_NOSERV, inaddrs,
					    baddrlist));
				}
				server_port = se->s_port;
				NSS_XbyY_FREE(&ndbuf4switch);
			}

			if (haddrlist == 0) {
				int	h_errnop = 0;

				ndbuf4switch = _nss_XbyY_buf_alloc(
				    sizeof (struct hostent),
				    NSS_BUFLEN_HOSTS);
				if (ndbuf4switch == 0) {
					_nderror = ND_NOMEM;
					return (ND_NOMEM);
				}
				he = DOOR_GETIPNODEBYNAME_R(
				    args->arg.nd_hs->h_host,
				    ndbuf4switch->result, ndbuf4switch->buffer,
				    ndbuf4switch->buflen,
				    args->arg.nss.host6.af_family,
				    args->arg.nss.host6.flags, &h_errnop);
				if (he == NULL) {
					NSS_XbyY_FREE(&ndbuf4switch);
					_nderror = __herrno2netdir(h_errnop);
					return (_nderror);
				}
				/*
				 * Convert h_addr_list into nd_addrlist.
				 * malloc's will be done,
				 * freed using netdir_free.
				 */
				ret = hent2ndaddr(AF_INET6,
				    ((struct hostent *)
				    (ndbuf4switch->result))->h_addr_list,
				    &server_port, res->nd_alist);
				_nderror = ret;
				NSS_XbyY_FREE(&ndbuf4switch);
				return (ret);
			} else {
				int ret;
				/*
				 * Convert h_addr_list into nd_addrlist.
				 * malloc's will be done,
				 * freed using netdir_free.
				 */
				ret = hent2ndaddr(AF_INET6, haddrlist,
				    &server_port, res->nd_alist);
				return (inetdir_free(ret, inaddrs, baddrlist));
			}

		default:
			_nderror = ND_BADARG;
			return (ND_BADARG); /* should never happen */
	}

	} else {
		/* haddrlist is no longer used, so clean up */
		if (inaddrs)
			free(inaddrs);
		if (baddrlist)
			free(baddrlist);
	}

	/*
	 * 3. We come this far only if nametoaddr libs are specified for
	 *    inet transports and we are called by gethost/servbyname only.
	 */
	switch (args->op_t) {
		struct	nd_hostserv service;
		struct	nd_addrlist *addrs;
		int ret;

		case NSS_HOST:

		service.h_host = (char *)args->arg.nss.host.name;
		service.h_serv = NULL;
		if ((_nderror = __classic_netdir_getbyname(nconf,
		    &service, &addrs)) != ND_OK) {
			*(res->nss.host.herrno_p) = nd2herrno(_nderror);
			return (_nderror);
		}
		/*
		 * convert addresses back into sockaddr for gethostbyname.
		 */
		ret = ndaddr2hent(AF_INET, service.h_host, addrs,
		    res->nss.host.hent, args->arg.nss.host.buf,
		    args->arg.nss.host.buflen);
		if (ret != ND_OK)
			*(res->nss.host.herrno_p) = nd2herrno(ret);
		netdir_free((char *)addrs, ND_ADDRLIST);
		_nderror = ret;
		return (ret);

		case NSS_SERV:

		if (args->arg.nss.serv.proto == NULL) {
			/*
			 * A similar HACK showed up in Solaris 2.3.
			 * The caller wild-carded proto -- i.e. will
			 * accept a match using tcp or udp for the port
			 * number. Since we have no hope of getting
			 * directly to a name service switch backend
			 * from here that understands this semantics,
			 * we try calling the netdir interfaces first
			 * with "tcp" and then "udp".
			 */
			args->arg.nss.serv.proto = "tcp";
			_nderror = _get_hostserv_inetnetdir_byname(nconf, args,
			    res);
			if (_nderror != ND_OK) {
				args->arg.nss.serv.proto = "udp";
				_nderror =
				    _get_hostserv_inetnetdir_byname(nconf,
				    args, res);
			}
			return (_nderror);
		}

		/*
		 * Third-parties should optimize their nametoaddr
		 * libraries for the HOST_SELF case.
		 */
		service.h_host = HOST_SELF;
		service.h_serv = (char *)args->arg.nss.serv.name;
		if ((_nderror = __classic_netdir_getbyname(nconf,
		    &service, &addrs)) != ND_OK) {
			return (_nderror);
		}
		/*
		 * convert addresses back into servent for getservbyname.
		 */
		_nderror = ndaddr2srent(service.h_serv,
		    args->arg.nss.serv.proto,
		    /* LINTED pointer cast */
		    ((struct sockaddr_in *)addrs->n_addrs->buf)->sin_port,
		    res->nss.serv,
		    args->arg.nss.serv.buf, args->arg.nss.serv.buflen);
		netdir_free((char *)addrs, ND_ADDRLIST);
		return (_nderror);

		default:
		_nderror = ND_BADARG;
		return (ND_BADARG); /* should never happen */
	}
}

/*
 * gethostbyaddr/servbyport always call this function; if they call
 * with nametoaddr libs in nconf, we call netdir_getbyaddr
 * implementation __classic_netdir_getbyaddr, otherwise nsswitch.
 *
 * netdir_getbyaddr calls this only if nametoaddr libs are NOT
 * specified for inet transports; i.e. it's supposed to follow
 * the name service switch.
 */
int
_get_hostserv_inetnetdir_byaddr(struct netconfig *nconf,
    struct nss_netdirbyaddr_in *args, union nss_netdirbyaddr_out *res)
{
	if (nconf == 0) {
		_nderror = ND_BADARG;
		return (_nderror);
	}

	/*
	 * 1. gethostbyaddr()/netdir_getbyaddr() special cases:
	 */
	switch (args->op_t) {

		case NSS_HOST:
		/*
		 * Worth the performance gain: assuming a lot of inet apps
		 * actively use "127.0.0.1".
		 */
		/* LINTED pointer cast */
		if (*(uint32_t *)(args->arg.nss.host.addr) ==
		    htonl(INADDR_LOOPBACK)) {
			(void) mutex_lock(&nd_addr_lock);
			IN_SET_LOOPBACK_ADDR(&sa_con);
			_nderror = ndaddr2hent(AF_INET, LOCALHOST,
			    &nd_conaddrlist, res->nss.host.hent,
			    args->arg.nss.host.buf,
			    args->arg.nss.host.buflen);
			(void) mutex_unlock(&nd_addr_lock);
			if (_nderror != ND_OK)
				*(res->nss.host.herrno_p) =
				    nd2herrno(_nderror);
			return (_nderror);
		}
		break;

		case NETDIR_BY:
		case NETDIR_BY_NOSRV:
		{
			struct sockaddr_in *sin;

			if (args->arg.nd_nbuf == NULL) {
				_nderror = ND_BADARG;
				return (_nderror);
			}

			/*
			 * Validate the address which was passed
			 * as the request.
			 */
			/* LINTED pointer cast */
			sin = (struct sockaddr_in *)args->arg.nd_nbuf->buf;

			if ((args->arg.nd_nbuf->len !=
			    sizeof (struct sockaddr_in)) ||
			    (sin->sin_family != AF_INET)) {
				_nderror = ND_BADARG;
				return (_nderror);
			}
		}
		break;

		case NETDIR_BY6:
		case NETDIR_BY_NOSRV6:
		{
			struct sockaddr_in6 *sin6;

			if (args->arg.nd_nbuf == NULL) {
				_nderror = ND_BADARG;
				return (_nderror);
			}

			/*
			 * Validate the address which was passed
			 * as the request.
			 */
			/* LINTED pointer cast */
			sin6 = (struct sockaddr_in6 *)args->arg.nd_nbuf->buf;

			if ((args->arg.nd_nbuf->len !=
			    sizeof (struct sockaddr_in6)) ||
			    (sin6->sin6_family != AF_INET6)) {
				_nderror = ND_BADARG;
				return (_nderror);
			}
		}
		break;

	}

	/*
	 * 2. Most common scenario. This is the way we ship /etc/netconfig.
	 *    Emphasis on improving performance in the "if" part.
	 */
	if (nconf->nc_nlookups == 0) {
		struct hostent	*he = NULL, *tmphe;
		struct servent	*se = NULL;
		nss_XbyY_buf_t	*ndbuf4host = 0;
		nss_XbyY_buf_t	*ndbuf4serv = 0;
		char	*proto =
		    (strcmp(nconf->nc_proto, NC_TCP) == 0) ? NC_TCP : NC_UDP;
		struct	sockaddr_in *sa;
		struct sockaddr_in6 *sin6;
		struct in_addr *addr4 = 0;
		struct in6_addr v4mapbuf;
		int	h_errnop;

	switch (args->op_t) {

		case NSS_HOST:

		he = DOOR_GETHOSTBYADDR_R(args->arg.nss.host.addr,
		    args->arg.nss.host.len, args->arg.nss.host.type,
		    res->nss.host.hent, args->arg.nss.host.buf,
		    args->arg.nss.host.buflen,
		    res->nss.host.herrno_p);
		if (he == 0)
			_nderror = ND_NOHOST;
		else
			_nderror = ND_OK;
		return (_nderror);


		case NSS_HOST6:
		he = DOOR_GETIPNODEBYADDR_R(args->arg.nss.host.addr,
		    args->arg.nss.host.len, args->arg.nss.host.type,
		    res->nss.host.hent, args->arg.nss.host.buf,
		    args->arg.nss.host.buflen,
		    res->nss.host.herrno_p);

		if (he == 0)
			return (ND_NOHOST);
		return (ND_OK);


		case NSS_SERV:

		se = _switch_getservbyport_r(args->arg.nss.serv.port,
		    args->arg.nss.serv.proto,
		    res->nss.serv, args->arg.nss.serv.buf,
		    args->arg.nss.serv.buflen);

		if (se == 0)
			_nderror = ND_NOSERV;
		else
			_nderror = ND_OK;
		return (_nderror);

		case NETDIR_BY:
		case NETDIR_BY_NOSRV:

		ndbuf4serv = _nss_XbyY_buf_alloc(sizeof (struct servent),
		    NSS_BUFLEN_SERVICES);
		if (ndbuf4serv == 0) {
			_nderror = ND_NOMEM;
			return (_nderror);
		}
		/* LINTED pointer cast */
		sa = (struct sockaddr_in *)(args->arg.nd_nbuf->buf);
		addr4 = (struct in_addr *)&(sa->sin_addr);

		/*
		 * if NETDIR_BY_NOSRV or port == 0 skip the service
		 * lookup.
		 */
		if (args->op_t != NETDIR_BY_NOSRV && sa->sin_port != 0) {
			se = _switch_getservbyport_r(sa->sin_port, proto,
			    ndbuf4serv->result, ndbuf4serv->buffer,
			    ndbuf4serv->buflen);
			if (!se) {
				NSS_XbyY_FREE(&ndbuf4serv);
				/*
				 * We can live with this - i.e. the address
				 * does not
				 * belong to a well known service. The caller
				 * traditionally accepts a stringified port
				 * number
				 * as the service name. The state of se is used
				 * ahead to indicate the same.
				 * However, we do not tolerate this nonsense
				 * when we cannot get a host name. See below.
				 */
			}
		}

		ndbuf4host = _nss_XbyY_buf_alloc(sizeof (struct hostent),
		    NSS_BUFLEN_HOSTS);
		if (ndbuf4host == 0) {
			if (ndbuf4serv)
				NSS_XbyY_FREE(&ndbuf4serv);
			_nderror = ND_NOMEM;
			return (_nderror);
		}

		/*
		 * Since we're going to search the ipnodes (v6) path first,
		 * we need to treat the address as a v4mapped address.
		 */

		IN6_INADDR_TO_V4MAPPED(addr4, &v4mapbuf);
		if ((tmphe = DOOR_GETIPNODEBYADDR_R((char *)&v4mapbuf,
		    16, AF_INET6, ndbuf4host->result,
		    ndbuf4host->buffer,
		    ndbuf4host->buflen, &h_errnop)) != NULL)
			he = __mappedtov4(tmphe, &h_errnop);

		if (!he) {
			/* Failover case, try hosts db for v4 address */
			he = DOOR_GETHOSTBYADDR_R((char *)
			    &(sa->sin_addr.s_addr), 4,
			    sa->sin_family, ndbuf4host->result,
			    ndbuf4host->buffer, ndbuf4host->buflen,
			    &h_errnop);
			if (!he) {
				NSS_XbyY_FREE(&ndbuf4host);
				if (ndbuf4serv)
					NSS_XbyY_FREE(&ndbuf4serv);
				_nderror = __herrno2netdir(h_errnop);
				return (_nderror);
			}
			/*
			 * Convert host names and service names into hostserv
			 * pairs. malloc's will be done, freed using
			 * netdir_free.
			 */
			h_errnop = hsents2ndhostservs(he, se,
			    sa->sin_port, res->nd_hslist);
		} else {
			/*
			 * Convert host names and service names into hostserv
			 * pairs. malloc's will be done, freed using
			 * netdir_free.
			 */
			h_errnop = hsents2ndhostservs(he, se,
			    sa->sin_port, res->nd_hslist);
			freehostent(he);
		}

		NSS_XbyY_FREE(&ndbuf4host);
		if (ndbuf4serv)
			NSS_XbyY_FREE(&ndbuf4serv);
		_nderror = __herrno2netdir(h_errnop);
		return (_nderror);

		case NETDIR_BY6:
		case NETDIR_BY_NOSRV6:

		ndbuf4serv = _nss_XbyY_buf_alloc(sizeof (struct servent),
		    NSS_BUFLEN_SERVICES);
		if (ndbuf4serv == 0) {
			_nderror = ND_NOMEM;
			return (ND_NOMEM);
		}
		/* LINTED pointer cast */
		sin6 = (struct sockaddr_in6 *)(args->arg.nd_nbuf->buf);

		/*
		 * if NETDIR_BY_NOSRV6 or port == 0 skip the service
		 * lookup.
		 */
		if (args->op_t != NETDIR_BY_NOSRV6 && sin6->sin6_port == 0) {
			se = _switch_getservbyport_r(sin6->sin6_port, proto,
			    ndbuf4serv->result, ndbuf4serv->buffer,
			    ndbuf4serv->buflen);
			if (!se) {
				NSS_XbyY_FREE(&ndbuf4serv);
				/*
				 * We can live with this - i.e. the address does
				 * not * belong to a well known service. The
				 * caller traditionally accepts a stringified
				 * port number
				 * as the service name. The state of se is used
				 * ahead to indicate the same.
				 * However, we do not tolerate this nonsense
				 * when we cannot get a host name. See below.
				 */
			}
		}

		ndbuf4host = _nss_XbyY_buf_alloc(sizeof (struct hostent),
		    NSS_BUFLEN_HOSTS);
		if (ndbuf4host == 0) {
			if (ndbuf4serv)
				NSS_XbyY_FREE(&ndbuf4serv);
			_nderror = ND_NOMEM;
			return (_nderror);
		}
		he = DOOR_GETIPNODEBYADDR_R((char *)&(sin6->sin6_addr),
		    16, sin6->sin6_family, ndbuf4host->result,
		    ndbuf4host->buffer,
		    ndbuf4host->buflen, &h_errnop);
		if (!he) {
			NSS_XbyY_FREE(&ndbuf4host);
			if (ndbuf4serv)
				NSS_XbyY_FREE(&ndbuf4serv);
			_nderror = __herrno2netdir(h_errnop);
			return (_nderror);
		}
		/*
		 * Convert host names and service names into hostserv
		 * pairs. malloc's will be done, freed using netdir_free.
		 */
		h_errnop = hsents2ndhostservs(he, se,
		    sin6->sin6_port, res->nd_hslist);

		NSS_XbyY_FREE(&ndbuf4host);
		if (ndbuf4serv)
			NSS_XbyY_FREE(&ndbuf4serv);
		_nderror = __herrno2netdir(h_errnop);
		return (_nderror);

		default:
		_nderror = ND_BADARG;
		return (_nderror); /* should never happen */
	}

	}
	/*
	 * 3. We come this far only if nametoaddr libs are specified for
	 *    inet transports and we are called by gethost/servbyname only.
	 */
	switch (args->op_t) {
		struct	netbuf nbuf;
		struct	nd_hostservlist *addrs;
		struct	sockaddr_in sa;

		case NSS_HOST:

		/* LINTED pointer cast */
		sa.sin_addr.s_addr = *(uint32_t *)args->arg.nss.host.addr;
		sa.sin_family = AF_INET;
		/* Hopefully, third-parties get this optimization */
		sa.sin_port = 0;
		nbuf.buf = (char *)&sa;
		nbuf.len = nbuf.maxlen = sizeof (sa);
		if ((_nderror = __classic_netdir_getbyaddr(nconf,
		    &addrs, &nbuf)) != 0) {
			*(res->nss.host.herrno_p) = nd2herrno(_nderror);
			return (_nderror);
		}
		/*
		 * convert the host-serv pairs into h_aliases and hent.
		 */
		_nderror = ndhostserv2hent(&nbuf, addrs, res->nss.host.hent,
		    args->arg.nss.host.buf, args->arg.nss.host.buflen);
		if (_nderror != ND_OK)
			*(res->nss.host.herrno_p) = nd2herrno(_nderror);
		netdir_free((char *)addrs, ND_HOSTSERVLIST);
		return (_nderror);

		case NSS_SERV:

		if (args->arg.nss.serv.proto == NULL) {
			/*
			 * A similar HACK showed up in Solaris 2.3.
			 * The caller wild-carded proto -- i.e. will
			 * accept a match on tcp or udp for the port
			 * number. Since we have no hope of getting
			 * directly to a name service switch backend
			 * from here that understands this semantics,
			 * we try calling the netdir interfaces first
			 * with "tcp" and then "udp".
			 */
			args->arg.nss.serv.proto = "tcp";
			_nderror = _get_hostserv_inetnetdir_byaddr(nconf, args,
			    res);
			if (_nderror != ND_OK) {
				args->arg.nss.serv.proto = "udp";
				_nderror =
				    _get_hostserv_inetnetdir_byaddr(nconf,
				    args, res);
			}
			return (_nderror);
		}

		/*
		 * Third-party nametoaddr_libs should be optimized for
		 * this case. It also gives a special semantics twist to
		 * netdir_getbyaddr. Only for the INADDR_ANY case, it gives
		 * higher priority to service lookups (over host lookups).
		 * If service lookup fails, the backend returns ND_NOSERV to
		 * facilitate lookup in the "next" naming service.
		 * BugId: 1075403.
		 */
		sa.sin_addr.s_addr = INADDR_ANY;
		sa.sin_family = AF_INET;
		sa.sin_port = (ushort_t)args->arg.nss.serv.port;
		sa.sin_zero[0] = '\0';
		nbuf.buf = (char *)&sa;
		nbuf.len = nbuf.maxlen = sizeof (sa);
		if ((_nderror = __classic_netdir_getbyaddr(nconf,
		    &addrs, &nbuf)) != ND_OK) {
			return (_nderror);
		}
		/*
		 * convert the host-serv pairs into s_aliases and servent.
		 */
		_nderror = ndhostserv2srent(args->arg.nss.serv.port,
		    args->arg.nss.serv.proto, addrs, res->nss.serv,
		    args->arg.nss.serv.buf, args->arg.nss.serv.buflen);
		netdir_free((char *)addrs, ND_HOSTSERVLIST);
		return (_nderror);

		default:
		_nderror = ND_BADARG;
		return (_nderror); /* should never happen */
	}
}

/*
 * Part II: Name Service Switch interfacing routines.
 */

static DEFINE_NSS_DB_ROOT(db_root_hosts);
static DEFINE_NSS_DB_ROOT(db_root_ipnodes);
static DEFINE_NSS_DB_ROOT(db_root_services);


/*
 * There is a copy of __nss2herrno() in nsswitch/files/gethostent.c.
 * It is there because /etc/lib/nss_files.so.1 cannot call
 * routines in libnsl.  Care should be taken to keep the two copies
 * in sync (except that case NSS_NISSERVDNS_TRYAGAIN is not needed in
 * nsswitch/files).
 */
int
__nss2herrno(nss_status_t nsstat)
{
	switch (nsstat) {
	case NSS_SUCCESS:
		/* no macro-defined success code for h_errno */
		return (0);
	case NSS_NOTFOUND:
		return (HOST_NOT_FOUND);
	case NSS_TRYAGAIN:
		return (TRY_AGAIN);
	case NSS_UNAVAIL:
		return (NO_RECOVERY);
	case NSS_NISSERVDNS_TRYAGAIN:
		return (TRY_AGAIN);
	}
	/* anything else */
	return (NO_RECOVERY);
}

nss_status_t
_herrno2nss(int h_errno)
{
	switch (h_errno) {
	case 0:
		return (NSS_SUCCESS);
	case TRY_AGAIN:
		return (NSS_TRYAGAIN);
	case NO_RECOVERY:
	case NETDB_INTERNAL:
		return (NSS_UNAVAIL);
	case HOST_NOT_FOUND:
	case NO_DATA:
	default:
		return (NSS_NOTFOUND);
	}
}

static int
__herrno2netdir(int h_errnop)
{
	switch (h_errnop) {
		case 0:
			return (ND_OK);
		case HOST_NOT_FOUND:
			return (ND_NOHOST);
		case TRY_AGAIN:
			return (ND_TRY_AGAIN);
		case NO_RECOVERY:
		case NETDB_INTERNAL:
			return (ND_NO_RECOVERY);
		case NO_DATA:
			return (ND_NO_DATA);
		default:
			return (ND_NOHOST);
	}
}

/*
 * The _switch_getXXbyYY_r() routines should be static.  They used to
 * be exported in SunOS 5.3, and in fact publicised as work-around
 * interfaces for getting CNAME/aliases, and therefore, we preserve
 * their signatures here. Just in case.
 */

struct hostent *
_switch_gethostbyname_r(const char *name, struct hostent *result, char *buffer,
    int buflen, int *h_errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2hostent);
	arg.key.name	= name;
	arg.stayopen	= 0;
	res = nss_search(&db_root_hosts, _nss_initf_hosts,
	    NSS_DBOP_HOSTS_BYNAME, &arg);
	arg.status = res;
	if (res != NSS_SUCCESS)
		*h_errnop = arg.h_errno ? arg.h_errno : __nss2herrno(res);
	if (arg.returnval != NULL)
		order_haddrlist_af(result->h_addrtype, result->h_addr_list);
	return ((struct hostent *)NSS_XbyY_FINI(&arg));
}

struct hostent *
_switch_getipnodebyname_r(const char *name, struct hostent *result,
    char *buffer, int buflen, int af_family, int flags, int *h_errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2hostent6);
	arg.key.ipnode.name	= name;
	arg.key.ipnode.af_family = af_family;
	arg.key.ipnode.flags = flags;
	arg.stayopen	= 0;
	res = nss_search(&db_root_ipnodes, _nss_initf_ipnodes,
	    NSS_DBOP_IPNODES_BYNAME, &arg);
	arg.status = res;
	if (res != NSS_SUCCESS)
		*h_errnop = arg.h_errno ? arg.h_errno : __nss2herrno(res);
	if (arg.returnval != NULL)
		order_haddrlist_af(result->h_addrtype, result->h_addr_list);
	return ((struct hostent *)NSS_XbyY_FINI(&arg));
}

struct hostent *
_switch_gethostbyaddr_r(const char *addr, int len, int type,
    struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2hostent);
	arg.key.hostaddr.addr	= addr;
	arg.key.hostaddr.len	= len;
	arg.key.hostaddr.type	= type;
	arg.stayopen		= 0;
	res = nss_search(&db_root_hosts, _nss_initf_hosts,
	    NSS_DBOP_HOSTS_BYADDR, &arg);
	arg.status = res;
	if (res != NSS_SUCCESS)
		*h_errnop = arg.h_errno ? arg.h_errno : __nss2herrno(res);
	return (struct hostent *)NSS_XbyY_FINI(&arg);
}

struct hostent *
_switch_getipnodebyaddr_r(const char *addr, int len, int type,
    struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2hostent6);
	arg.key.hostaddr.addr	= addr;
	arg.key.hostaddr.len	= len;
	arg.key.hostaddr.type	= type;
	arg.stayopen		= 0;
	res = nss_search(&db_root_ipnodes, _nss_initf_ipnodes,
	    NSS_DBOP_IPNODES_BYADDR, &arg);
	arg.status = res;
	if (res != NSS_SUCCESS)
		*h_errnop = arg.h_errno ? arg.h_errno : __nss2herrno(res);
	return (struct hostent *)NSS_XbyY_FINI(&arg);
}

static void
_nss_initf_services(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_SERVICES;
	p->default_config = NSS_DEFCONF_SERVICES;
}

struct servent *
_switch_getservbyname_r(const char *name, const char *proto,
    struct servent *result, char *buffer, int buflen)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2servent);
	arg.key.serv.serv.name	= name;
	arg.key.serv.proto	= proto;
	arg.stayopen		= 0;
	res = nss_search(&db_root_services, _nss_initf_services,
	    NSS_DBOP_SERVICES_BYNAME, &arg);
	arg.status = res;
	return ((struct servent *)NSS_XbyY_FINI(&arg));
}

struct servent *
_switch_getservbyport_r(int port, const char *proto, struct servent *result,
    char *buffer, int buflen)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2servent);
	arg.key.serv.serv.port	= port;
	arg.key.serv.proto	= proto;
	arg.stayopen		= 0;
	res = nss_search(&db_root_services, _nss_initf_services,
	    NSS_DBOP_SERVICES_BYPORT, &arg);
	arg.status = res;
	return ((struct servent *)NSS_XbyY_FINI(&arg));
}


/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 *
 * Defined here because we need it and we (libnsl) cannot have a dependency
 * on libsocket (however, libsocket always depends on libnsl).
 */
int
str2servent(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	struct servent	*serv	= (struct servent *)ent;
	const char	*p, *fieldstart, *limit, *namestart;
	ssize_t		fieldlen, namelen = 0;
	char		numbuf[12];
	char		*numend;

	if ((instr >= buffer && (buffer + buflen) > instr) ||
	    (buffer >= instr && (instr + lenstr) > buffer)) {
		return (NSS_STR_PARSE_PARSE);
	}

	p = instr;
	limit = p + lenstr;

	while (p < limit && isspace(*p)) {
		p++;
	}
	namestart = p;
	while (p < limit && !isspace(*p)) {
		p++;		/* Skip over the canonical name */
	}
	namelen = p - namestart;

	if (buflen <= namelen) { /* not enough buffer */
		return (NSS_STR_PARSE_ERANGE);
	}
	(void) memcpy(buffer, namestart, namelen);
	buffer[namelen] = '\0';
	serv->s_name = buffer;

	while (p < limit && isspace(*p)) {
		p++;
	}

	fieldstart = p;
	do {
		if (p > limit || isspace(*p)) {
			/* Syntax error -- no port/proto */
			return (NSS_STR_PARSE_PARSE);
		}
	} while (*p++ != '/');
	fieldlen = p - fieldstart - 1;
	if (fieldlen == 0 || fieldlen >= sizeof (numbuf)) {
		/* Syntax error -- supposed number is empty or too long */
		return (NSS_STR_PARSE_PARSE);
	}
	(void) memcpy(numbuf, fieldstart, fieldlen);
	numbuf[fieldlen] = '\0';
	serv->s_port = htons((int)strtol(numbuf, &numend, 10));
	if (*numend != '\0') {
		/* Syntax error -- port number isn't a number */
		return (NSS_STR_PARSE_PARSE);
	}

	fieldstart = p;
	while (p < limit && !isspace(*p)) {
		p++;		/* Scan the protocol name */
	}
	fieldlen = p - fieldstart + 1;		/* Include '\0' this time */
	if (fieldlen > buflen - namelen - 1) {
		return (NSS_STR_PARSE_ERANGE);
	}
	serv->s_proto = buffer + namelen + 1;
	(void) memcpy(serv->s_proto, fieldstart, fieldlen - 1);
	serv->s_proto[fieldlen - 1] = '\0';

	while (p < limit && isspace(*p)) {
		p++;
	}
	/*
	 * Although nss_files_XY_all calls us with # stripped,
	 * we should be able to deal with it here in order to
	 * be more useful.
	 */
	if (p >= limit || *p == '#') { /* no aliases, no problem */
		char **ptr;

		ptr = (char **)ROUND_UP(buffer + namelen + 1 + fieldlen,
		    sizeof (char *));
		if ((char *)ptr >= buffer + buflen) {
			/* hope they don't try to peek in */
			serv->s_aliases = 0;
			return (NSS_STR_PARSE_ERANGE);
		} else {
			*ptr = 0;
			serv->s_aliases = ptr;
			return (NSS_STR_PARSE_SUCCESS);
		}
	}
	serv->s_aliases = _nss_netdb_aliases(p, (int)(lenstr - (p - instr)),
	    buffer + namelen + 1 + fieldlen,
	    (int)(buflen - namelen - 1 - fieldlen));
	return (NSS_STR_PARSE_SUCCESS);
}

/*
 * Part III: All `n sundry routines that are useful only in this
 * module. In the interest of keeping this source file shorter,
 * we would create them a new module only if the linker allowed
 * "library-static" functions.
 *
 * Routines to order addresses based on local interfaces and netmasks,
 * to get and check reserved ports, and to get broadcast nets.
 */

union __v4v6addr {
	struct in6_addr	in6;
	struct in_addr	in4;
};

struct __ifaddr {
	sa_family_t		af;
	union __v4v6addr	addr;
	union __v4v6addr	mask;
};

struct ifinfo {
	int		count;
	struct __ifaddr	*addresses;
};

typedef enum {ADDR_ONLINK = 0, ADDR_OFFLINK} addr_class_t;
#define	ADDR_NUMCLASSES	2

typedef enum {IF_ADDR, IF_MASK}	__ifaddr_type;
static int	__inet_ifassign(sa_family_t, struct __ifaddr *, __ifaddr_type,
				void *);
int		__inet_address_is_local_af(void *, sa_family_t, void *);

#define	ifaf(index)	(localinfo->addresses[index].af)
#define	ifaddr4(index)	(localinfo->addresses[index].addr.in4)
#define	ifaddr6(index)	(localinfo->addresses[index].addr.in6)
#define	ifmask4(index)	(localinfo->addresses[index].mask.in4)
#define	ifmask6(index)	(localinfo->addresses[index].mask.in6)
#define	ifinfosize(n)	(sizeof (struct ifinfo) + (n)*sizeof (struct __ifaddr))

#define	lifraddrp(lifr)	((lifr.lifr_addr.ss_family == AF_INET6) ? \
	(void *)&((struct sockaddr_in6 *)&lifr.lifr_addr)->sin6_addr : \
	(void *)&((struct sockaddr_in *)&lifr.lifr_addr)->sin_addr)

#define	ifassign(lifr, index, type) \
			__inet_ifassign(lifr.lifr_addr.ss_family, \
				&localinfo->addresses[index], type, \
				lifraddrp(lifr))

/*
 * The number of nanoseconds the order_haddrlist_inet() function waits
 * to retreive IP interface information.  The default is five minutes.
 */
#define	IFINFOTIMEOUT	((hrtime_t)300 * NANOSEC)

/*
 * Sort the addresses in haddrlist.  Since the sorting algorithms are
 * address-family specific, the work is done in the address-family
 * specific order_haddrlist_<family> functions.
 *
 * Do not sort addresses if SORT_ADDRS variable is set to NO or FALSE
 * in the configuration file /etc/default/nss. This is useful in case
 * the order of addresses returned by the nameserver needs to be
 * maintained. (DNS round robin feature is one example)
 */
void
order_haddrlist_af(sa_family_t af, char **haddrlist)
{
	size_t			addrcount;
	char			**addrptr;
	static boolean_t	checksortcfg = B_TRUE;
	static boolean_t	nosort = B_FALSE;
	static mutex_t		checksortcfg_lock = DEFAULTMUTEX;

	if (haddrlist == NULL)
		return;

	/*
	 * Check if SORT_ADDRS is set to NO or FALSE in the configuration
	 * file.  We do not have to sort addresses in that case.
	 */
	(void) mutex_lock(&checksortcfg_lock);
	if (checksortcfg == B_TRUE) {
		checksortcfg = B_FALSE;
		nosort = _read_nsw_file();
	}
	(void) mutex_unlock(&checksortcfg_lock);

	if (nosort)
		return;

	/* Count the addresses to sort */
	addrcount = 0;
	for (addrptr = haddrlist; *addrptr != NULL; addrptr++)
		addrcount++;

	/*
	 * If there's only one address or no addresses to sort, then
	 * there's nothing for us to do.
	 */
	if (addrcount <= 1)
		return;

	/* Call the address-family specific sorting functions. */
	switch (af) {
	case AF_INET:
		order_haddrlist_inet(haddrlist, addrcount);
		break;
	case AF_INET6:
		order_haddrlist_inet6(haddrlist, addrcount);
		break;
	default:
		break;
	}
}

/*
 * Move any local (on-link) addresses toward the beginning of haddrlist.
 * The order within these two classes is preserved.
 *
 * The interface list is retrieved no more often than every
 * IFINFOTIMEOUT nanoseconds. Access to the interface list is
 * protected by an RW lock.
 *
 * If this function encounters an error, haddrlist is unaltered.
 */
static void
order_haddrlist_inet(char **haddrlist, size_t addrcount)
{
	static struct	ifinfo *localinfo = NULL;
	static hrtime_t	then = 0; /* the last time localinfo was updated */
	hrtime_t	now;
	static rwlock_t	localinfo_lock = DEFAULTRWLOCK;
	uint8_t		*sortbuf;
	size_t		sortbuf_size;
	struct in_addr	**inaddrlist = (struct in_addr **)haddrlist;
	struct in_addr	**sorted;
	struct in_addr	**classnext[ADDR_NUMCLASSES];
	uint_t		classcount[ADDR_NUMCLASSES];
	addr_class_t	*sortclass;
	int		i;
	int		rc;


	/*
	 * The classes in the sortclass array correspond to the class
	 * of the address in the haddrlist list of the same index.
	 * The classes are:
	 *
	 * ADDR_ONLINK	on-link address
	 * ADDR_OFFLINK	off-link address
	 */
	sortbuf_size = addrcount *
	    (sizeof (struct in_addr *) + sizeof (addr_class_t));
	if ((sortbuf = malloc(sortbuf_size)) == NULL)
		return;
	/* LINTED pointer cast */
	sorted = (struct in_addr **)sortbuf;
	/* LINTED pointer cast */
	sortclass = (addr_class_t *)(sortbuf +
	    (addrcount * sizeof (struct in_addr *)));

	/*
	 * Get a read lock, and check if the interface information
	 * is too old.
	 */
	(void) rw_rdlock(&localinfo_lock);
	now = gethrtime();
	if (localinfo == NULL || ((now - then) > IFINFOTIMEOUT)) {
		/* Need to update I/F info. Upgrade to write lock. */
		(void) rw_unlock(&localinfo_lock);
		(void) rw_wrlock(&localinfo_lock);
		/*
		 * Another thread might have updated "then" between
		 * the rw_unlock() and rw_wrlock() calls above, so
		 * re-check the timeout.
		 */
		if (localinfo == NULL || ((now - then) > IFINFOTIMEOUT)) {
			if (localinfo != NULL)
				free(localinfo);
			if ((localinfo = get_local_info()) == NULL) {
				(void) rw_unlock(&localinfo_lock);
				free(sortbuf);
				return;
			}
			then = now;
		}
		/* Downgrade to read lock */
		(void) rw_unlock(&localinfo_lock);
		(void) rw_rdlock(&localinfo_lock);
		/*
		 * Another thread may have updated the I/F info,
		 * so verify that the 'localinfo' pointer still
		 * is non-NULL.
		 */
		if (localinfo == NULL) {
			(void) rw_unlock(&localinfo_lock);
			free(sortbuf);
			return;
		}
	}

	/*
	 * Classify the addresses.  We also maintain the classcount
	 * array to keep track of the number of addresses in each
	 * class.
	 */
	(void) memset(classcount, 0, sizeof (classcount));
	for (i = 0; i < addrcount; i++) {
		if (__inet_address_is_local_af(localinfo, AF_INET,
		    inaddrlist[i]))
			sortclass[i] = ADDR_ONLINK;
		else
			sortclass[i] = ADDR_OFFLINK;
		classcount[sortclass[i]]++;
	}

	/* Don't need the interface list anymore in this call */
	(void) rw_unlock(&localinfo_lock);

	/*
	 * Each element in the classnext array points to the next
	 * element for that class in the sorted address list. 'rc' is
	 * the running count of elements as we sum the class
	 * sub-totals.
	 */
	for (rc = 0, i = 0; i < ADDR_NUMCLASSES; i++) {
		classnext[i] = &sorted[rc];
		rc += classcount[i];
	}

	/* Now for the actual rearrangement of the addresses */
	for (i = 0; i < addrcount; i++) {
		*(classnext[sortclass[i]]) = inaddrlist[i];
		classnext[sortclass[i]]++;
	}

	/* Copy the sorted list to inaddrlist */
	(void) memcpy(inaddrlist, sorted,
	    addrcount * sizeof (struct in_addr *));
	free(sortbuf);
}

/*
 * This function implements the IPv6 Default Address Selection's
 * destination address ordering mechanism.  The algorithm is described
 * in getaddrinfo(3SOCKET).
 */
static void
order_haddrlist_inet6(char **haddrlist, size_t addrcount)
{
	struct dstinforeq *dinfo, *dinfoptr;
	struct in6_addr **in6addrlist = (struct in6_addr **)haddrlist;
	struct in6_addr	**in6addr;

	if ((dinfo = calloc(addrcount, sizeof (struct dstinforeq))) == NULL)
		return;

	/* Initialize the dstinfo array we'll use for SIOCGDSTINFO */
	dinfoptr = dinfo;
	for (in6addr = in6addrlist; *in6addr != NULL; in6addr++) {
		dinfoptr->dir_daddr = **in6addr;
		dinfoptr++;
	}

	if (nss_strioctl(AF_INET6, SIOCGDSTINFO, dinfo,
	    addrcount * sizeof (struct dstinforeq)) < 0) {
		free(dinfo);
		return;
	}

	/* Sort the dinfo array */
	qsort(dinfo, addrcount, sizeof (struct dstinforeq), dstcmp);

	/* Copy the addresses back into in6addrlist */
	dinfoptr = dinfo;
	for (in6addr = in6addrlist; *in6addr != NULL; in6addr++) {
		**in6addr = dinfoptr->dir_daddr;
		dinfoptr++;
	}

	free(dinfo);
}

/*
 * Determine number of leading bits that are common between two addresses.
 * Only consider bits which fall within the prefix length plen.
 */
static uint_t
ip_addr_commonbits_v6(const in6_addr_t *a1, const in6_addr_t *a2)
{
	uint_t		bits;
	uint_t		i;
	uint32_t	diff;	/* Bits that differ */

	for (i = 0; i < 4; i++) {
		if (a1->_S6_un._S6_u32[i] != a2->_S6_un._S6_u32[i])
			break;
	}
	bits = i * 32;

	if (bits == IPV6_ABITS)
		return (IPV6_ABITS);

	/*
	 * Find number of leading common bits in the word which might
	 * have some common bits by searching for the first one from the left
	 * in the xor of the two addresses.
	 */
	diff = ntohl(a1->_S6_un._S6_u32[i] ^ a2->_S6_un._S6_u32[i]);
	if (diff & 0xffff0000ul)
		diff >>= 16;
	else
		bits += 16;
	if (diff & 0xff00)
		diff >>= 8;
	else
		bits += 8;
	if (diff & 0xf0)
		diff >>= 4;
	else
		bits += 4;
	if (diff & 0xc)
		diff >>= 2;
	else
		bits += 2;
	if (!(diff & 2))
		bits++;

	/*
	 * We don't need to shift and check for the last bit.  The
	 * check for IPV6_ABITS above would have caught that.
	 */

	return (bits);
}


/*
 * The following group of functions named rule_*() are individual
 * sorting rules for the AF_INET6 address sorting algorithm.  The
 * functions compare two addresses (described by two dstinforeq
 * structures), and determines if one is "greater" than the other, or
 * if the two are equal according to that rule.
 */
typedef	int (*rulef_t)(const struct dstinforeq *, const struct dstinforeq *);

/*
 * These values of these constants are no accident.  Since qsort()
 * implements the AF_INET6 address sorting, the comparison function
 * must return an integer less than, equal to, or greater than zero to
 * indicate if the first address is considered "less than", "equal
 * to", or "greater than" the second one.  Since we want the best
 * addresses first on the list, "less than" is considered preferrable.
 */
#define	RULE_PREFER_DA	-1
#define	RULE_PREFER_DB	1
#define	RULE_EQUAL	0

/* Prefer the addresses that is reachable. */
static int
rule_reachable(const struct dstinforeq *da, const struct dstinforeq *db)
{
	if (da->dir_dreachable == db->dir_dreachable)
		return (RULE_EQUAL);
	if (da->dir_dreachable)
		return (RULE_PREFER_DA);
	return (RULE_PREFER_DB);
}

/* Prefer the address whose scope matches that of its source address. */
static int
rule_matchscope(const struct dstinforeq *da, const struct dstinforeq *db)
{
	boolean_t da_scope_match, db_scope_match;

	da_scope_match = da->dir_dscope == da->dir_sscope;
	db_scope_match = db->dir_dscope == db->dir_sscope;

	if (da_scope_match == db_scope_match)
		return (RULE_EQUAL);
	if (da_scope_match)
		return (RULE_PREFER_DA);
	return (RULE_PREFER_DB);
}

/* Avoid the address with the link local source address. */
static int
rule_avoidlinklocal(const struct dstinforeq *da, const struct dstinforeq *db)
{
	if (da->dir_sscope == IP6_SCOPE_LINKLOCAL &&
	    da->dir_dscope != IP6_SCOPE_LINKLOCAL &&
	    db->dir_sscope != IP6_SCOPE_LINKLOCAL)
		return (RULE_PREFER_DB);
	if (db->dir_sscope == IP6_SCOPE_LINKLOCAL &&
	    db->dir_dscope != IP6_SCOPE_LINKLOCAL &&
	    da->dir_sscope != IP6_SCOPE_LINKLOCAL)
		return (RULE_PREFER_DA);
	return (RULE_EQUAL);
}

/* Prefer the address whose source address isn't deprecated. */
static int
rule_deprecated(const struct dstinforeq *da, const struct dstinforeq *db)
{
	if (da->dir_sdeprecated == db->dir_sdeprecated)
		return (RULE_EQUAL);
	if (db->dir_sdeprecated)
		return (RULE_PREFER_DA);
	return (RULE_PREFER_DB);
}

/* Prefer the address whose label matches that of its source address. */
static int
rule_label(const struct dstinforeq *da, const struct dstinforeq *db)
{
	if (da->dir_labelmatch == db->dir_labelmatch)
		return (RULE_EQUAL);
	if (da->dir_labelmatch)
		return (RULE_PREFER_DA);
	return (RULE_PREFER_DB);
}

/* Prefer the address with the higher precedence. */
static int
rule_precedence(const struct dstinforeq *da, const struct dstinforeq *db)
{
	if (da->dir_precedence == db->dir_precedence)
		return (RULE_EQUAL);
	if (da->dir_precedence > db->dir_precedence)
		return (RULE_PREFER_DA);
	return (RULE_PREFER_DB);
}

/* Prefer the address whose output interface isn't an IP tunnel */
static int
rule_native(const struct dstinforeq *da, const struct dstinforeq *db)
{
	boolean_t isatun, isbtun;

	/* Get the common case out of the way early */
	if (da->dir_dmactype == db->dir_dmactype)
		return (RULE_EQUAL);

	isatun = da->dir_dmactype == DL_IPV4 || da->dir_dmactype == DL_IPV6;
	isbtun = db->dir_dmactype == DL_IPV4 || db->dir_dmactype == DL_IPV6;

	if (isatun == isbtun)
		return (RULE_EQUAL);
	if (isbtun)
		return (RULE_PREFER_DA);
	return (RULE_PREFER_DB);
}

/* Prefer the address with the smaller scope. */
static int
rule_scope(const struct dstinforeq *da, const struct dstinforeq *db)
{
	if (da->dir_dscope == db->dir_dscope)
		return (RULE_EQUAL);
	if (da->dir_dscope < db->dir_dscope)
		return (RULE_PREFER_DA);
	return (RULE_PREFER_DB);
}

/*
 * Prefer the address that has the most leading bits in common with its
 * source address.
 */
static int
rule_prefix(const struct dstinforeq *da, const struct dstinforeq *db)
{
	uint_t da_commonbits, db_commonbits;
	boolean_t da_isipv4, db_isipv4;

	da_isipv4 = IN6_IS_ADDR_V4MAPPED(&da->dir_daddr);
	db_isipv4 = IN6_IS_ADDR_V4MAPPED(&db->dir_daddr);

	/*
	 * At this point, the order doesn't matter if the two addresses
	 * aren't of the same address family.
	 */
	if (da_isipv4 != db_isipv4)
		return (RULE_EQUAL);

	da_commonbits = ip_addr_commonbits_v6(&da->dir_daddr, &da->dir_saddr);
	db_commonbits = ip_addr_commonbits_v6(&db->dir_daddr, &db->dir_saddr);

	if (da_commonbits > db_commonbits)
		return (RULE_PREFER_DA);
	if (da_commonbits < db_commonbits)
		return (RULE_PREFER_DB);
	return (RULE_EQUAL);
}

/*
 * This is the function passed to qsort() that does the AF_INET6
 * address comparisons.  It compares two addresses using a list of
 * rules.  The rules are applied in order until one prefers one
 * address over the other.
 */
static int
dstcmp(const void *da, const void *db)
{
	int index, result;
	rulef_t rules[] = {
	    rule_reachable,
	    rule_matchscope,
	    rule_avoidlinklocal,
	    rule_deprecated,
	    rule_label,
	    rule_precedence,
	    rule_native,
	    rule_scope,
	    rule_prefix,
	    NULL
	};

	result = 0;
	for (index = 0; rules[index] != NULL; index++) {
		result = (rules[index])(da, db);
		if (result != RULE_EQUAL)
			break;
	}

	return (result);
}

/*
 * Given haddrlist and a port number, mallocs and populates a new
 * nd_addrlist.  The new nd_addrlist maintains the order of the addresses
 * in haddrlist, which have already been sorted by order_haddrlist_inet()
 * or order_haddrlist_inet6().  For IPv6 this function filters out
 * IPv4-mapped IPv6 addresses.
 */
int
hent2ndaddr(int af, char **haddrlist, int *servp, struct nd_addrlist **nd_alist)
{
	struct nd_addrlist	*result;
	int			num;
	struct netbuf		*na;
	struct sockaddr_in	*sinbuf, *sin;
	struct sockaddr_in6	*sin6buf, *sin6;
	struct in_addr		**inaddr, **inaddrlist;
	struct in6_addr		**in6addr, **in6addrlist;

	/* Address count */
	num = 0;
	if (af == AF_INET6) {
		in6addrlist = (struct in6_addr **)haddrlist;

		/*
		 * Exclude IPv4-mapped IPv6 addresses from the count, as
		 * these are not included in the nd_addrlist we return.
		 */
		for (in6addr = in6addrlist; *in6addr != NULL; in6addr++)
			if (!IN6_IS_ADDR_V4MAPPED(*in6addr))
				num++;
	} else {
		inaddrlist = (struct in_addr **)haddrlist;

		for (inaddr = inaddrlist; *inaddr != NULL; inaddr++)
			num++;
	}
	if (num == 0)
		return (ND_NOHOST);

	result = malloc(sizeof (struct nd_addrlist));
	if (result == 0)
		return (ND_NOMEM);

	result->n_cnt = num;
	result->n_addrs = calloc(num, sizeof (struct netbuf));
	if (result->n_addrs == 0) {
		free(result);
		return (ND_NOMEM);
	}

	na = result->n_addrs;
	if (af == AF_INET) {
		sinbuf = calloc(num, sizeof (struct sockaddr_in));
		if (sinbuf == NULL) {
			free(result->n_addrs);
			free(result);
			return (ND_NOMEM);
		}

		sin = sinbuf;
		for (inaddr = inaddrlist; *inaddr != NULL; inaddr++) {
			na->len = na->maxlen = sizeof (struct sockaddr_in);
			na->buf = (char *)sin;
			sin->sin_family = AF_INET;
			sin->sin_addr = **inaddr;
			sin->sin_port = *servp;
			na++;
			sin++;
		}
	} else if (af == AF_INET6) {
		sin6buf = calloc(num, sizeof (struct sockaddr_in6));
		if (sin6buf == NULL) {
			free(result->n_addrs);
			free(result);
			return (ND_NOMEM);
		}

		sin6 = sin6buf;
		for (in6addr = in6addrlist; *in6addr != NULL; in6addr++) {
			if (IN6_IS_ADDR_V4MAPPED(*in6addr))
				continue;

			na->len = na->maxlen = sizeof (struct sockaddr_in6);
			na->buf = (char *)sin6;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = **in6addr;
			sin6->sin6_port = *servp;
			na++;
			sin6++;
		}
	}
	*(nd_alist) = result;
	return (ND_OK);
}

/*
 * Given a hostent and a servent, mallocs and populates
 * a new nd_hostservlist with host and service names.
 *
 * We could be passed in a NULL servent, in which case stringify port.
 */
int
hsents2ndhostservs(struct hostent *he, struct servent *se,
    ushort_t port, struct nd_hostservlist **hslist)
{
	struct	nd_hostservlist *result;
	struct	nd_hostserv *hs;
	int	hosts, servs, i, j;
	char	**hn, **sn;

	if ((result = malloc(sizeof (struct nd_hostservlist))) == 0)
		return (ND_NOMEM);

	/*
	 * We initialize the counters to 1 rather than zero because
	 * we have to count the "official" name as well as the aliases.
	 */
	for (hn = he->h_aliases, hosts = 1; hn && *hn; hn++, hosts++) {};
	if (se) {
		for (sn = se->s_aliases, servs = 1; sn && *sn; sn++, servs++) {
		};
	} else
		servs = 1;

	if ((hs = calloc(hosts * servs, sizeof (struct nd_hostserv))) == 0) {
		free(result);
		return (ND_NOMEM);
	}

	result->h_cnt	= servs * hosts;
	result->h_hostservs = hs;

	for (i = 0, hn = he->h_aliases; i < hosts; i++) {
		sn = se ? se->s_aliases : NULL;

		for (j = 0; j < servs; j++) {
			if (i == 0)
				hs->h_host = strdup(he->h_name);
			else
				hs->h_host = strdup(*hn);
			if (j == 0) {
				if (se)
					hs->h_serv = strdup(se->s_name);
				else {
					/* Convert to a number string */
					char stmp[16];

					(void) sprintf(stmp, "%d", port);
					hs->h_serv = strdup(stmp);
				}
			} else
				hs->h_serv = strdup(*sn++);

			if ((hs->h_host == 0) || (hs->h_serv == 0)) {
				free(result->h_hostservs);
				free(result);
				return (ND_NOMEM);
			}
			hs++;
		}
		if (i)
			hn++;
	}
	*(hslist) = result;
	return (ND_OK);
}

/*
 * Process results from nd_addrlist ( returned by netdir_getbyname)
 * into a hostent using buf.
 * *** ASSUMES that nd_addrlist->n_addrs->buf contains IP addresses in
 * sockaddr_in's ***
 */
int
ndaddr2hent(int af, const char *nam, struct nd_addrlist *addrs,
    struct hostent *result, char *buffer, int buflen)
{
	int	i, count;
	struct	in_addr *addrp;
	struct	in6_addr *addr6p;
	char	**addrvec;
	struct	netbuf *na;
	size_t	len;

	result->h_name		= buffer;
	result->h_addrtype	= af;
	result->h_length	= (af == AF_INET) ? sizeof (*addrp):
	    sizeof (*addr6p);

	/*
	 * Build addrlist at start of buffer (after name);  store the
	 * addresses themselves at the end of the buffer.
	 */
	len = strlen(nam) + 1;
	addrvec = (char **)ROUND_UP(buffer + len, sizeof (*addrvec));
	result->h_addr_list 	= addrvec;

	if (af == AF_INET) {
		addrp = (struct in_addr *)ROUND_DOWN(buffer + buflen,
		    sizeof (*addrp));

		count = addrs->n_cnt;
		if ((char *)(&addrvec[count + 1]) > (char *)(&addrp[-count]))
			return (ND_NOMEM);

		(void) memcpy(buffer, nam, len);

		for (na = addrs->n_addrs, i = 0;  i < count;  na++, i++) {
			--addrp;
			(void) memcpy(addrp,
			    /* LINTED pointer cast */
			    &((struct sockaddr_in *)na->buf)->sin_addr,
			    sizeof (*addrp));
			*addrvec++ = (char *)addrp;
		}
	} else {
		addr6p = (struct in6_addr *)ROUND_DOWN(buffer + buflen,
		    sizeof (*addr6p));

		count = addrs->n_cnt;
		if ((char *)(&addrvec[count + 1]) > (char *)(&addr6p[-count]))
			return (ND_NOMEM);

		(void) memcpy(buffer, nam, len);

		for (na = addrs->n_addrs, i = 0;  i < count;  na++, i++) {
			--addr6p;
			(void) memcpy(addr6p,
			    /* LINTED pointer cast */
			    &((struct sockaddr_in6 *)na->buf)->sin6_addr,
			    sizeof (*addr6p));
			*addrvec++ = (char *)addr6p;
		}
	}
	*addrvec = 0;
	result->h_aliases = addrvec;

	return (ND_OK);
}

/*
 * Process results from nd_addrlist ( returned by netdir_getbyname)
 * into a servent using buf.
 */
int
ndaddr2srent(const char *name, const char *proto, ushort_t port,
    struct servent *result, char *buffer, int buflen)
{
	size_t	i;
	char	*bufend = (buffer + buflen);

	result->s_port = (int)port;

	result->s_aliases =
	    (char **)ROUND_UP(buffer, sizeof (char *));
	result->s_aliases[0] = NULL;
	buffer = (char *)&result->s_aliases[1];
	result->s_name = buffer;
	i = strlen(name) + 1;
	if ((buffer + i) > bufend)
		return (ND_NOMEM);
	(void) memcpy(buffer, name, i);
	buffer += i;

	result->s_proto	= buffer;
	i = strlen(proto) + 1;
	if ((buffer + i) > bufend)
		return (ND_NOMEM);
	(void) memcpy(buffer, proto, i);
	buffer += i;

	return (ND_OK);
}

/*
 * Process results from nd_hostservlist ( returned by netdir_getbyaddr)
 * into a hostent using buf.
 * *** ASSUMES that nd_buf->buf is a sockaddr_in ***
 */
int
ndhostserv2hent(struct netbuf *nbuf, struct nd_hostservlist *addrs,
    struct hostent *result, char *buffer, int buflen)
{
	int	i, count;
	char	*aliasp;
	char	**aliasvec;
	struct	sockaddr_in *sa;
	struct	nd_hostserv *hs;
	const	char *la;
	size_t	length;

	/* First, give the lonely address a specious home in h_addr_list. */
	aliasp   = (char  *)ROUND_UP(buffer, sizeof (sa->sin_addr));
	/* LINTED pointer cast */
	sa = (struct sockaddr_in *)nbuf->buf;
	(void) memcpy(aliasp, &(sa->sin_addr), sizeof (sa->sin_addr));
	aliasvec = (char **)ROUND_UP(aliasp + sizeof (sa->sin_addr),
	    sizeof (*aliasvec));
	result->h_addr_list = aliasvec;
	*aliasvec++ = aliasp;
	*aliasvec++ = 0;

	/*
	 * Build h_aliases at start of buffer (after addr and h_addr_list);
	 * store the alias strings at the end of the buffer (before h_name).
	 */

	aliasp = buffer + buflen;

	result->h_aliases	= aliasvec;

	hs = addrs->h_hostservs;
	if (!hs)
		return (ND_NOHOST);

	length = strlen(hs->h_host) + 1;
	aliasp -= length;
	if ((char *)(&aliasvec[1]) > aliasp)
		return (ND_NOMEM);
	(void) memcpy(aliasp, hs->h_host, length);

	result->h_name		= aliasp;
	result->h_addrtype	= AF_INET;
	result->h_length	= sizeof (sa->sin_addr);

	/*
	 * Assumption: the netdir nametoaddr_libs
	 * sort the vector of (host, serv) pairs in such a way that
	 * all pairs with the same host name are contiguous.
	 */
	la = hs->h_host;
	count = addrs->h_cnt;
	for (i = 0;  i < count;  i++, hs++)
		if (strcmp(la, hs->h_host) != 0) {
			size_t len = strlen(hs->h_host) + 1;

			aliasp -= len;
			if ((char *)(&aliasvec[2]) > aliasp)
				return (ND_NOMEM);
			(void) memcpy(aliasp, hs->h_host, len);
			*aliasvec++ = aliasp;
			la = hs->h_host;
		}
	*aliasvec = 0;

	return (ND_OK);
}

/*
 * Process results from nd_hostservlist ( returned by netdir_getbyaddr)
 * into a servent using buf.
 */
int
ndhostserv2srent(int port, const char *proto, struct nd_hostservlist *addrs,
    struct servent *result, char *buffer, int buflen)
{
	int	i, count;
	char	*aliasp;
	char	**aliasvec;
	struct	nd_hostserv *hs;
	const	char *host_cname;
	size_t	leni, lenj;

	result->s_port = port;
	/*
	 * Build s_aliases at start of buffer;
	 * store proto and aliases at the end of the buffer (before h_name).
	 */

	aliasp = buffer + buflen;
	aliasvec = (char **)ROUND_UP(buffer, sizeof (char *));

	result->s_aliases	= aliasvec;

	hs = addrs->h_hostservs;
	if (!hs)
		return (ND_NOHOST);
	host_cname = hs->h_host;

	leni = strlen(proto) + 1;
	lenj = strlen(hs->h_serv) + 1;
	if ((char *)(&aliasvec[2]) > (aliasp - leni - lenj))
		return (ND_NOMEM);

	aliasp -= leni;
	(void) memcpy(aliasp, proto, leni);
	result->s_proto = aliasp;

	aliasp -= lenj;
	(void) memcpy(aliasp, hs->h_serv, lenj);
	result->s_name = aliasp;

	/*
	 * Assumption: the netdir nametoaddr_libs
	 * do a host aliases first and serv aliases next
	 * enumeration for creating the list of hostserv
	 * structures.
	 */
	count = addrs->h_cnt;
	for (i = 0;
	    i < count && hs->h_serv && strcmp(hs->h_host, host_cname) == 0;
	    i++, hs++) {
		size_t len = strlen(hs->h_serv) + 1;

		aliasp -= len;
		if ((char *)(&aliasvec[2]) > aliasp)
			return (ND_NOMEM);
		(void) memcpy(aliasp, hs->h_serv, len);
		*aliasvec++ = aliasp;
	}
	*aliasvec = NULL;

	return (ND_OK);
}


static int
nd2herrno(int nerr)
{
	switch (nerr) {
	case ND_OK:
		return (0);
	case ND_TRY_AGAIN:
		return (TRY_AGAIN);
	case ND_NO_RECOVERY:
	case ND_BADARG:
	case ND_NOMEM:
		return (NO_RECOVERY);
	case ND_NO_DATA:
		return (NO_DATA);
	case ND_NOHOST:
	case ND_NOSERV:
		return (HOST_NOT_FOUND);
	default:
		return (NO_RECOVERY);
	}
}

/*
 * This is a utility function so that various parts of libnsl can
 * easily send ioctls down to ip.
 *
 */
int
nss_ioctl(int af, int cmd, void *arg)
{
	int	fd;
	char	*devpath;
	int	retv;

	switch (af) {
	case AF_INET6:
		devpath = UDP6DEV;
		break;
	case AF_INET:
	case AF_UNSPEC:
	default:
		devpath = UDPDEV;
	}
	if ((fd = open(devpath, O_RDONLY)) < 0) {
		return (-1);
	}
	while ((retv = ioctl(fd, cmd, arg)) == -1) {
		if (errno != EINTR)
	break;
	}
	(void) close(fd);
	return (retv);
}

static int
nss_strioctl(int af, int cmd, void *ptr, int ilen)
{
	struct strioctl str;

	str.ic_cmd = cmd;
	str.ic_timout = 0;
	str.ic_len = ilen;
	str.ic_dp = ptr;

	return (nss_ioctl(af, I_STR, &str));
}

static struct ifinfo *
get_local_info(void)
{
	int	numifs;
	int	n;
	char	*buf = NULL;
	size_t	needed;
	struct lifconf	lifc;
	struct lifreq	lifreq, *lifr;
	struct lifnum	lifn;
	struct ifinfo	*localinfo;

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = 0;

getifnum:
	if (nss_ioctl(AF_UNSPEC, SIOCGLIFNUM, &lifn) == -1) {
		numifs = MAXIFS;
	} else {
		numifs = lifn.lifn_count;
	}

	/*
	 * Add a small fudge factor in case interfaces get plumbed between
	 * the call to SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	needed = (numifs + 4) * sizeof (lifreq);
	if (buf == NULL)
		buf = malloc(needed);
	else
		buf = realloc(buf, needed);
	if (buf == NULL) {
		(void) syslog(LOG_ERR, "n2a get_local_info: malloc failed: %m");
		_nderror = ND_NOMEM;
		return (NULL);
	}
	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = 0;
	lifc.lifc_len = needed;
	lifc.lifc_buf = buf;
	if (nss_ioctl(AF_UNSPEC, SIOCGLIFCONF, &lifc) == -1) {
		/*
		 * IP returns EINVAL if the buffer was too small to fit
		 * all of the entries.  If that's the case, go back and
		 * try again.
		 */
		if (errno == EINVAL)
			goto getifnum;

		(void) syslog(LOG_ERR, "n2a get_local_info: "
		    "ioctl (get interface configuration): %m");
		free(buf);
		_nderror = ND_SYSTEM;
		return (NULL);
	}
	/* LINTED pointer cast */
	lifr = (struct lifreq *)buf;
	numifs = lifc.lifc_len/sizeof (lifreq);
	localinfo = malloc(ifinfosize(numifs));
	if (localinfo == NULL) {
		(void) syslog(LOG_ERR, "n2a get_local_info: malloc failed: %m");
		free(buf);
		_nderror = ND_SYSTEM;
		return (NULL);
	}

	/* LINTED pointer cast */
	localinfo->addresses = (struct __ifaddr *)
	    ((char *)localinfo + sizeof (struct ifinfo));

	for (localinfo->count = 0, n = numifs; n > 0; n--, lifr++) {
		int af;

		lifreq = *lifr;
		af = lifreq.lifr_addr.ss_family;

		/* Squirrel away the address */
		if (ifassign(lifreq, localinfo->count, IF_ADDR) == 0)
			continue;

		if (nss_ioctl(af, SIOCGLIFFLAGS, &lifreq) < 0) {
			(void) syslog(LOG_ERR,
			    "n2a get_local_info: "
			    "ioctl (get interface flags): %m");
			continue;
		}
		if (!(lifreq.lifr_flags & IFF_UP))
			continue;

		if (nss_ioctl(af, SIOCGLIFNETMASK, &lifreq) < 0) {
			(void) syslog(LOG_ERR,
			    "n2a get_local_info: "
			    "ioctl (get interface netmask): %m");
			continue;
		}

		if (ifassign(lifreq, localinfo->count, IF_MASK) == 0)
			continue;

		localinfo->count++;
	}

	free(buf);
	return (localinfo);
}

static int
__inet_ifassign(sa_family_t af, struct __ifaddr *ifa, __ifaddr_type type,
    void *addr) {
	switch (type) {
	case IF_ADDR:
		ifa->af = af;
		if (af == AF_INET6) {
			ifa->addr.in6 = *(struct in6_addr *)addr;
		} else {
			ifa->addr.in4 = *(struct in_addr *)addr;
		}
		break;
	case IF_MASK:
		if (ifa->af == af) {
			if (af == AF_INET6) {
				ifa->mask.in6 = *(struct in6_addr *)addr;
			} else {
				ifa->mask.in4 = *(struct in_addr *)addr;
			}
		} else {
			return (0);
		}
		break;
	default:
		return (0);
	}

	return (1);
}

/*
 *  Some higher-level routines for determining if an address is
 *  on a local network.
 *
 *      __inet_get_local_interfaces() - get an opaque handle with
 *          with a list of local interfaces
 *      __inet_address_is_local() - return 1 if an address is
 *          on a local network; 0 otherwise
 *      __inet_free_local_interfaces() - free handle that was
 *          returned by __inet_get_local_interfaces()
 *
 *  A typical calling sequence is:
 *
 *      p = __inet_get_local_interfaces();
 *      if (__inet_address_is_local(p, inaddr)) {
 *          ...
 *      }
 *      __inet_free_local_interfaces(p);
 */

/*
 *  Return an opaque pointer to a list of configured interfaces.
 */
void *
__inet_get_local_interfaces(void)
{
	return (get_local_info());
}

/*
 *  Free memory allocated by inet_local_interfaces().
 */
void
__inet_free_local_interfaces(void *p)
{
	free(p);
}

/*
 *  Determine if an address is on a local network.
 *
 *  Might have made sense to use SIOCTONLINK, except that it doesn't
 *  handle matching on IPv4 network addresses.
 */
int
__inet_address_is_local_af(void *p, sa_family_t af, void *addr) {

	struct ifinfo	*localinfo = (struct ifinfo *)p;
	int		i, a;
	struct in_addr	v4addr;

	if (localinfo == 0)
		return (0);

	if (af == AF_INET6 && IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr)) {
		IN6_V4MAPPED_TO_INADDR((struct in6_addr *)addr, &v4addr);
		af = AF_INET;
		addr = (void *)&v4addr;
	}

	for (i = 0; i < localinfo->count; i++) {
		if (ifaf(i) == af) {
			if (af == AF_INET6) {
				struct in6_addr *a6 = (struct in6_addr *)addr;
				for (a = 0; a < sizeof (a6->s6_addr); a++) {
					if ((a6->s6_addr[a] &
						ifmask6(i).s6_addr[a]) !=
						(ifaddr6(i).s6_addr[a] &
						ifmask6(i).s6_addr[a]))
						break;
				}
				if (a >= sizeof (a6->s6_addr))
					return (1);
			} else {
				if ((((struct in_addr *)addr)->s_addr &
						ifmask4(i).s_addr) ==
					(ifaddr4(i).s_addr &
						ifmask4(i).s_addr))
					return (1);
			}
		}
	}

	return (0);
}

int
__inet_address_is_local(void *p, struct in_addr addr)
{
	return (__inet_address_is_local_af(p, AF_INET, &addr));
}

int
__inet_uaddr_is_local(void *p, struct netconfig *nc, char *uaddr)
{
	struct netbuf		*taddr;
	sa_family_t		af;
	int			ret;

	taddr = uaddr2taddr(nc, uaddr);
	if (taddr == 0)
		return (0);

	/* LINTED pointer cast */
	af = ((struct sockaddr *)taddr->buf)->sa_family;

	ret = __inet_address_is_local_af(p, af, (af == AF_INET6) ?
	    /* LINTED pointer cast */
	    (void *)&((struct sockaddr_in6 *)taddr->buf)->sin6_addr :
	    /* LINTED pointer cast */
	    (void *)&((struct sockaddr_in *)taddr->buf)->sin_addr);

	netdir_free(taddr, ND_ADDR);
	return (ret);
}


int
__inet_address_count(void *p)
{
	struct ifinfo *lp = (struct ifinfo *)p;

	if (lp != 0) {
		return (lp->count);
	} else {
		return (0);
	}
}

uint32_t
__inet_get_addr(void *p, int n)
{
	struct ifinfo *localinfo = (struct ifinfo *)p;

	if (localinfo == 0 || n >= localinfo->count || ifaf(n) != AF_INET)
		return (0);

	return (ifaddr4(n).s_addr);
}

uint32_t
__inet_get_network(void *p, int n)
{
	struct ifinfo *localinfo = (struct ifinfo *)p;

	if (localinfo == 0 || n >= localinfo->count || ifaf(n) != AF_INET)
		return (0);

	return (ifaddr4(n).s_addr & ifmask4(n).s_addr);
}

char *
__inet_get_uaddr(void *p, struct netconfig *nc, int n)
{
	struct ifinfo *localinfo = (struct ifinfo *)p;
	char *uaddr;
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
	struct netbuf nb;

	if (localinfo == 0 || nc == 0 || n >= localinfo->count)
		return (0);

	if (ifaf(n) == AF_INET6) {
		if (strcmp(NC_INET6, nc->nc_protofmly) != 0)
			return (0);
		(void) memset(&sin6, 0, sizeof (sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = ifaddr6(n);
		nb.buf = (char *)&sin6;
		nb.len = sizeof (sin6);
	} else {
		if (strcmp(NC_INET, nc->nc_protofmly) != 0)
			return (0);
		(void) memset(&sin4, 0, sizeof (sin4));
		sin4.sin_family = AF_INET;
		sin4.sin_addr = ifaddr4(n);
		nb.buf = (char *)&sin4;
		nb.len = sizeof (sin4);
	}

	nb.maxlen = nb.len;

	uaddr = taddr2uaddr(nc, &nb);
	return (uaddr);
}

char *
__inet_get_networka(void *p, int n)
{
	struct ifinfo	*localinfo = (struct ifinfo *)p;

	if (localinfo == 0 || n >= localinfo->count)
		return (0);

	if (ifaf(n) == AF_INET6) {
		char		buf[INET6_ADDRSTRLEN];
		struct in6_addr	in6;
		int		i;

		for (i = 0; i < sizeof (in6.s6_addr); i++) {
			in6.s6_addr[i] = ifaddr6(n).s6_addr[i] &
			    ifmask6(n).s6_addr[i];
		}
		return (strdup(inet_ntop(AF_INET6, &in6, buf, sizeof (buf))));
	} else {
		struct in_addr	in4;

		in4.s_addr = ifaddr4(n).s_addr & ifmask4(n).s_addr;
		return (strdup(inet_ntoa(in4)));
	}
}

static int
in_list(struct in_addr *addrs, int n, struct in_addr a)
{
	int i;

	for (i = 0; i < n; i++) {
		if (addrs[i].s_addr == a.s_addr)
			return (1);
	}
	return (0);
}

static int
getbroadcastnets(struct netconfig *tp, struct in_addr **addrs)
{
	struct ifconf ifc;
	struct ifreq ifreq, *ifr;
	struct sockaddr_in *sin;
	struct in_addr a;
	int fd;
	int n, i, numifs;
	char *buf;
	int	use_loopback = 0;

	_nderror = ND_SYSTEM;
	fd = open(tp->nc_device, O_RDONLY);
	if (fd < 0) {
		(void) syslog(LOG_ERR,
	    "broadcast: open to get interface configuration: %m");
		return (0);
	}
	if (ioctl(fd, SIOCGIFNUM, (char *)&numifs) < 0)
		numifs = MAXIFS;
	buf = malloc(numifs * sizeof (struct ifreq));
	if (buf == NULL) {
		(void) syslog(LOG_ERR, "broadcast: malloc failed: %m");
		(void) close(fd);
		return (0);
	}
	*addrs = malloc(numifs * sizeof (struct in_addr));
	if (*addrs == NULL) {
		(void) syslog(LOG_ERR, "broadcast: malloc failed: %m");
		free(buf);
		(void) close(fd);
		return (0);
	}
	ifc.ifc_len = numifs * (int)sizeof (struct ifreq);
	ifc.ifc_buf = buf;
	/*
	 * Ideally, this ioctl should also tell me, how many bytes were
	 * finally allocated, but it doesnt.
	 */
	if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0) {
		(void) syslog(LOG_ERR,
	    "broadcast: ioctl (get interface configuration): %m");
		free(buf);
		free(*addrs);
		(void) close(fd);
		return (0);
	}

retry:
	/* LINTED pointer cast */
	ifr = (struct ifreq *)buf;
	for (i = 0, n = ifc.ifc_len / (int)sizeof (struct ifreq);
	    n > 0; n--, ifr++) {
		ifreq = *ifr;
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
			(void) syslog(LOG_ERR, "broadcast: "
			    "ioctl (get interface flags): %m");
			continue;
		}
		if (!(ifreq.ifr_flags & IFF_UP) ||
		    (ifr->ifr_addr.sa_family != AF_INET))
			continue;
		if (ifreq.ifr_flags & IFF_BROADCAST) {
			/* LINTED pointer cast */
			sin = (struct sockaddr_in *)&ifr->ifr_addr;
			if (ioctl(fd, SIOCGIFBRDADDR, (char *)&ifreq) < 0) {
				/* May not work with other implementation */
				a = _inet_makeaddr(
				    inet_netof(sin->sin_addr),
				    INADDR_ANY);
				if (!in_list(*addrs, i, a))
					(*addrs)[i++] = a;
			} else {
				/* LINTED pointer cast */
				a = ((struct sockaddr_in *)
				    &ifreq.ifr_addr)->sin_addr;
				if (!in_list(*addrs, i, a))
					(*addrs)[i++] = a;
			}
			continue;
		}
		if (use_loopback && (ifreq.ifr_flags & IFF_LOOPBACK)) {
			/* LINTED pointer cast */
			sin = (struct sockaddr_in *)&ifr->ifr_addr;
			a = sin->sin_addr;
			if (!in_list(*addrs, i, a))
				(*addrs)[i++] = a;
			continue;
		}
		if (ifreq.ifr_flags & IFF_POINTOPOINT) {
			if (ioctl(fd, SIOCGIFDSTADDR, (char *)&ifreq) < 0)
				continue;
			/* LINTED pointer cast */
			a = ((struct sockaddr_in *)
			    &ifreq.ifr_addr)->sin_addr;
			if (!in_list(*addrs, i, a))
				(*addrs)[i++] = a;
			continue;
		}
	}
	if (i == 0 && !use_loopback) {
		use_loopback = 1;
		goto retry;
	}
	free(buf);
	(void) close(fd);
	if (i)
		_nderror = ND_OK;
	else
		free(*addrs);
	return (i);
}

/*
 * This is lifted straight from libsocket/inet/inet_mkaddr.c.
 * Copied here to avoid our dependency on libsocket. More importantly,
 * to make sure partially static apps that use libnsl, but not
 * libsocket, don't get screwed up.
 * If you understand the above paragraph, try to get rid of
 * this copy of inet_makeaddr; if you don;t, leave it alone.
 *
 * Formulate an Internet address from network + host.  Used in
 * building addresses stored in the ifnet structure.
 */
static struct in_addr
_inet_makeaddr(in_addr_t net, in_addr_t host)
{
	in_addr_t addr;
	struct in_addr inaddr;

	if (net < 128)
		addr = (net << IN_CLASSA_NSHIFT) | (host & IN_CLASSA_HOST);
	else if (net < 65536)
		addr = (net << IN_CLASSB_NSHIFT) | (host & IN_CLASSB_HOST);
	else if (net < 16777216L)
		addr = (net << IN_CLASSC_NSHIFT) | (host & IN_CLASSC_HOST);
	else
		addr = net | host;
	inaddr.s_addr = htonl(addr);
	return (inaddr);
}

/*
 * Routine to read the default configuration file and check if SORT_ADDRS
 * is set to NO or FALSE. This routine is called by order_haddrlist_af()
 * to determine if the addresses need to be sorted.
 */
static boolean_t
_read_nsw_file(void)
{
	char	defval[LINESIZE];
	FILE	*defl;
	boolean_t	nosort = B_FALSE;


	do {
		defl = fopen(__NSW_DEFAULT_FILE, "rF");
	} while ((defl == NULL) && (errno == EINTR));

	if (defl == NULL)
		return (B_FALSE);

	while (fgets(defval, sizeof (defval), defl) != NULL) {
		if ((strncmp(DONT_SORT, defval, sizeof (DONT_SORT) - 1) == 0) ||
		    (strncmp(DONT_SORT2, defval,
		    sizeof (DONT_SORT2) - 1) == 0)) {
			nosort = B_TRUE;
			break;
		}
	}
	(void) fclose(defl);
	return (nosort);
}
