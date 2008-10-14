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

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <varargs.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/pathconf.h>
#include <netdir.h>
#include <netconfig.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <syslog.h>
#include <netinet/in.h>
#include <nfs/nfs_sec.h>
#include <strings.h>
#include <sys/nsctl/rdc_prot.h>
#include <nsctl.h>

#include "librdc.h"

#define	MAXIFS 32

/* number of transports to try */
#define	MNT_PREF_LISTLEN	2
#define	FIRST_TRY		1
#define	SECOND_TRY		2


int
Is_ipv6present(void)
{
#ifdef AF_INET6
	int sock;
	struct lifnum lifn;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0)
		return (0);

	lifn.lifn_family = AF_INET6;
	lifn.lifn_flags = 0;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		close(sock);
		return (0);
	}
	close(sock);
	if (lifn.lifn_count == 0)
		return (0);
	return (1);
#else
	return (0);
#endif
}

/*
 * The following is stolen from autod_nfs.c
 */
static void
getmyaddrs(struct ifconf *ifc)
{
	int sock;
	int numifs;
	char *buf;
	int family;

	ifc->ifc_buf = NULL;
	ifc->ifc_len = 0;

#ifdef AF_INET6
	family = AF_INET6;
#else
	family = AF_INET;
#endif
	if ((sock = socket(family, SOCK_DGRAM, 0)) < 0) {
#ifdef DEBUG
		perror("getmyaddrs(): socket");
#endif
		return;
	}

	if (ioctl(sock, SIOCGIFNUM, (char *)&numifs) < 0) {
#ifdef DEBUG
		perror("getmyaddrs(): SIOCGIFNUM");
#endif
		numifs = MAXIFS;
	}

	buf = (char *)malloc(numifs * sizeof (struct ifreq));
	if (buf == NULL) {
#ifdef DEBUG
		fprintf(stderr, "getmyaddrs(): malloc failed\n");
#endif
		(void) close(sock);
		return;
	}

	ifc->ifc_buf = buf;
	ifc->ifc_len = numifs * sizeof (struct ifreq);

	if (ioctl(sock, SIOCGIFCONF, (char *)ifc) < 0) {
#ifdef DEBUG
		perror("getmyaddrs(): SIOCGIFCONF");
#else
		;
		/*EMPTY*/
#endif
	}

	(void) close(sock);
}

int
self_check(char *hostname)
{
	int n;
	struct sockaddr_in *s1, *s2;
	struct ifreq *ifr;
	struct nd_hostserv hs;
	struct nd_addrlist *retaddrs;
	struct netconfig *nconfp;
	struct ifconf *ifc;
	int retval;

	ifc = malloc(sizeof (struct ifconf));
	if (ifc == NULL)
		return (0);
	memset((char *)ifc, 0, sizeof (struct ifconf));
	getmyaddrs(ifc);
	/*
	 * Get the IP address for hostname
	 */
	nconfp = getnetconfigent("udp");
	if (nconfp == NULL) {
#ifdef DEBUG
		fprintf(stderr, "self_check(): getnetconfigent failed\n");
#endif
		retval = 0;
		goto out;
	}
	hs.h_host = hostname;
	hs.h_serv = "rpcbind";
	if (netdir_getbyname(nconfp, &hs, &retaddrs) != ND_OK) {
		freenetconfigent(nconfp);
		retval = 0;
		goto out;
	}
	freenetconfigent(nconfp);
	/* LINTED pointer alignment */
	s1 = (struct sockaddr_in *)retaddrs->n_addrs->buf;

	/*
	 * Now compare it against the list of
	 * addresses for the interfaces on this
	 * host.
	 */
	ifr = ifc->ifc_req;
	n = ifc->ifc_len / sizeof (struct ifreq);
	s2 = NULL;
	for (; n > 0; n--, ifr++) {
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;

		/* LINTED pointer alignment */
		s2 = (struct sockaddr_in *)&ifr->ifr_addr;

		if (memcmp((char *)&s2->sin_addr,
			(char *)&s1->sin_addr, sizeof (s1->sin_addr)) == 0) {
			netdir_free((void *)retaddrs, ND_ADDRLIST);
			retval = 1;
			goto out;	/* it's me */
		}
	}
	netdir_free((void *)retaddrs, ND_ADDRLIST);
	retval = 0;

out:
	if (ifc->ifc_buf != NULL)
		free(ifc->ifc_buf);
	free(ifc);
	return (retval);
}


int
convert_nconf_to_knconf(struct netconfig *nconf, struct knetconfig *knconf)
{
	struct stat sb;

	if (stat(nconf->nc_device, &sb) < 0) {
		(void) syslog(LOG_ERR, "can't find device for transport %s\n",
				nconf->nc_device);
		return (-1);
	}
#ifdef DEBUG_ADDR
	printf("lib knconf %x %s %s %x\n", nconf->nc_semantics,
		nconf->nc_protofmly, nconf->nc_proto, sb.st_rdev);
#endif

	knconf->knc_semantics = nconf->nc_semantics;
	knconf->knc_protofmly = nconf->nc_protofmly;
	knconf->knc_proto = nconf->nc_proto;
	knconf->knc_rdev = sb.st_rdev;

	return (0);
}

struct hostent *
gethost_byname(const char *name)
{
	int errnum;
#ifdef AF_INET6
	return (getipnodebyname(name, AF_INET6, AI_DEFAULT, &errnum));
#else /* !AF_INET6 */
	return (gethostbyname(name));
#endif /* AF_INET6 */
}

int
gethost_netaddrs(char *fromhost, char *tohost,
	char *fromnetaddr, char *tonetaddr)
{
	struct hostent *host;
	int j;
	int errnum;

#ifdef AF_INET6
	host = getipnodebyname(fromhost, AF_INET6, AI_DEFAULT, &errnum);
	if (host == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, dgettext("sndr",
		    "Could not find host %s"), fromhost);
#endif
		return (-1);
	}
	for (j = 0; j < host->h_length; j++)
		fromnetaddr[j] = host->h_addr[j];
	freehostent(host);
#else /* !AF_INET6 */
	host = gethostbyname(fromhost);
	if (host == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, dgettext("sndr",
		    "Could not find host %s"), fromhost);
#endif
		return (-1);
	}

	if (host->h_length < 4) {
#ifdef DEBUG
		fprintf(stderr, "host->h_length(%d) < 4!\n", host->h_length);
#endif
		return (-1);
	}

	for (j = 0; j < host->h_length; j++)
		fromnetaddr[j] = host->h_addr[j];
#endif /* AF_INET6 */

#ifdef AF_INET6
	host = getipnodebyname(tohost, AF_INET6, AI_DEFAULT, &errnum);
	if (host == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, dgettext("sndr",
		    "Could not find host %s"), tohost);
#endif
		return (-1);
	}
	for (j = 0; j < host->h_length; j++)
		tonetaddr[j] = host->h_addr[j];
	freehostent(host);
#else /* !AF_INET6 */
	host = gethostbyname(tohost);
	if (host == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, dgettext("sndr",
		    "Could not find host %s"), tohost);
#endif
		return (-1);
	}

	if (host->h_length < 4) {
#ifdef DEBUG
		fprintf(stderr, "host->h_length(%d) < 4!\n", host->h_length);
#endif
		return (-1);
	}

	for (j = 0; j < host->h_length; j++)
		tonetaddr[j] = host->h_addr[j];
#endif /* AF_INET6 */
	return (0);
}

/*
 * Get the network address on "hostname" for program "prog"
 * with version "vers" by using the nconf configuration data
 * passed in.
 *
 * If the address of a netconfig pointer is null then
 * information is not sufficient and no netbuf will be returned.
 *
 * Finally, ping the null procedure of that service.
 *
 */
static struct netbuf *
get_the_addr(char *hostname, ulong_t prog, ulong_t vers,
	struct netconfig *nconf, ushort_t port, struct t_info *tinfo,
	int portmap)
{
	struct netbuf *nb = NULL;
	struct t_bind *tbind = NULL;
	CLIENT *cl = NULL;
	struct timeval tv;
	int fd = -1;
	AUTH *ah = NULL;

	if (nconf == NULL)
		return (NULL);

	if ((fd = t_open(nconf->nc_device, O_RDWR, tinfo)) == -1)
		    goto done;

	/* LINTED pointer alignment */
	if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR)) == NULL)
		goto done;

	if (portmap) { /* contact rpcbind */
		if (rpcb_getaddr(prog, vers, nconf, &tbind->addr,
		    hostname) == FALSE) {
			goto done;
		}

		if (port) {
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
			    /* LINTED pointer alignment */
			    ((struct sockaddr_in *)tbind->addr.buf)->sin_port
					= port;
#ifdef NC_INET6
			else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
			    /* LINTED pointer alignment */
			    ((struct sockaddr_in6 *)tbind->addr.buf)->sin6_port
					= port;
#endif
		}

		/* Simon -- we never use the client we create?! */
		cl = clnt_tli_create(fd, nconf, &tbind->addr, prog, vers, 0, 0);
		if (cl == NULL)
			goto done;

		ah = authsys_create_default();
		if (ah != NULL)
			cl->cl_auth = ah;

		tv.tv_sec = 5;
		tv.tv_usec = 0;

		(void) clnt_control(cl, CLSET_TIMEOUT, (char *)&tv);
	} else { /* create our own address and skip rpcbind */
		struct netbuf *nb;
		struct hostent *hp;
		int j;
		int errnum;
		unsigned short family;
		nb = &(tbind->addr);

#ifdef AF_INET6
		if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
			hp = getipnodebyname(hostname, AF_INET6, 0, &errnum);
			family = AF_INET6;
			nb->len = nb->maxlen = sizeof (struct sockaddr_in6);
		} else {
			hp = getipnodebyname(hostname, AF_INET, 0, &errnum);
			family = AF_INET;
			nb->len = nb->maxlen = sizeof (struct sockaddr_in);
		}
		if (hp == NULL) {
#ifdef DEBUG_ADDR
				(void) fprintf(stderr, dgettext("sndr",
				    "Could not find host %s\n"), hostname);
#endif
				goto done;
		}
		nb->buf = (char *)calloc(1, nb->maxlen);
		if (nb->buf == NULL) {
			(void) printf(dgettext("sndr", "no memory\n"));
			goto done;
		}

		if (family == AF_INET) {
			for (j = 0; j < hp->h_length; j++)
				nb->buf[j+4] = hp->h_addr[j];
			/* LINTED pointer alignment */
			((struct sockaddr_in *)(nb->buf))->sin_port = port;
			/* LINTED pointer alignment */
			((struct sockaddr_in *)(nb->buf))->sin_family = AF_INET;
		} else {
			for (j = 0; j < hp->h_length; j++)
				nb->buf[j+8] = hp->h_addr[j];
			/* LINTED pointer alignment */
			((struct sockaddr_in6 *)(nb->buf))->sin6_port = port;
			/* LINTED pointer alignment */
			((struct sockaddr_in6 *)(nb->buf))->sin6_family =
			    AF_INET6;
		}
		freehostent(hp);
#else
		hp = gethostbyname(hostname);
		if (hp == NULL) {
#ifdef DEBUG
			(void) fprintf(stderr, dgettext("sndr",
			    "Could not find host %s"), hostname);
#endif
			goto done;
		}

		nb->len = nb->maxlen = sizeof (struct sockaddr_in);
		nb->buf = (char *)calloc(1, nb->maxlen);
		if (nb->buf == NULL) {
			(void) printf(dgettext("sndr", "no memory\n"));
			free(nb);
			nb = NULL;
			goto done;
		}

		for (j = 0; j < hp->h_length; j++)
			nb->buf[j+4] = hp->h_addr[j];

		if (hp->h_addrtype == AF_INET) {
			((struct sockaddr_in *)(nb->buf))->sin_port = port;
			((struct sockaddr_in *)(nb->buf))->sin_family = AF_INET;
		}
#endif
	}

	/*
	 * Make a copy of the netbuf to return
	 */
	nb = (struct netbuf *)calloc(1, sizeof (*nb));
	if (nb == NULL) {
		(void) printf(dgettext("sndr", "no memory\n"));
		goto done;
	}

	*nb = tbind->addr;	/* structure copy */

	nb->buf = (char *)calloc(1, nb->maxlen);
	if (nb->buf == NULL) {
		(void) printf(dgettext("sndr", "no memory\n"));
		free(nb);
		nb = NULL;
		goto done;
	}

	(void) memcpy(nb->buf, tbind->addr.buf, tbind->addr.len);

done:
	if (cl) {
		if (ah != NULL) {
		    AUTH_DESTROY(cl->cl_auth);
		    cl->cl_auth = NULL;
		}

		clnt_destroy(cl);
		cl = NULL;
	}

	if (tbind) {
		t_free((char *)tbind, T_BIND);
		tbind = NULL;
	}

	if (fd >= 0)
		(void) t_close(fd);
	return (nb);
}

/*
 * Get a network address on "hostname" for program "prog"
 * with version "vers".  If the port number is specified (non zero)
 * then try for a TCP/UDP transport and set the port number of the
 * resulting IP address.
 *
 * If the address of a netconfig pointer was passed and
 * if it's not null, use it as the netconfig otherwise
 * assign the address of the netconfig that was used to
 * establish contact with the service.
 * If portmap is false, we return a similiar address and we do not
 * contact rpcbind
 *
 */
struct netbuf *
get_addr(char *hostname, ulong_t prog, ulong_t vers, struct netconfig **nconfp,
	char *proto, char *srvport, struct t_info *tinfo, int portmap)
{
	struct netbuf *nb = NULL;
	struct netconfig *nconf = NULL;
	NCONF_HANDLE *nc = NULL;
	int nthtry = FIRST_TRY;
	struct servent *svp;
	ushort_t port;

	/*
	 * First lets get the requested port
	 */

	if ((svp = getservbyname(srvport, proto)) == NULL)
		goto done;
	port = svp->s_port;
	/*
	 * No nconf passed in.
	 *
	 * Try to get a nconf from /etc/netconfig filtered by
	 * the NETPATH environment variable.
	 * First search for COTS, second for CLTS unless proto
	 * is specified.  When we retry, we reset the
	 * netconfig list so that we would search the whole list
	 * all over again.
	 */
	if ((nc = setnetpath()) == NULL)
		goto done;

	/*
	 * If proto is specified, then only search for the match,
	 * otherwise try COTS first, if failed, try CLTS.
	 */
	if (proto) {
		while (nconf = getnetpath(nc)) {
			if (strcmp(nconf->nc_netid, proto) == 0) {
				/*
				 * If the port number is specified then TCP/UDP
				 * is needed. Otherwise any cots/clts will do.
				 */
				if (port == 0)
					break;

				if ((strcmp(nconf->nc_protofmly, NC_INET) == 0
#ifdef NC_INET6
				/* CSTYLED */
				|| strcmp(nconf->nc_protofmly, NC_INET6) == 0
#endif
				/* CSTYLED */
				) &&
				(strcmp(nconf->nc_proto, NC_TCP) == 0 ||
				strcmp(nconf->nc_proto, NC_UDP) == 0))
					break;
				else {
					nconf = NULL;
					break;
				}
			}
		}
		if (nconf == NULL)
			goto done;
		if ((nb = get_the_addr(hostname, prog, vers, nconf, port,
				tinfo, portmap)) == NULL) {
			goto done;
		}
	} else {
retry:
		while (nconf = getnetpath(nc)) {
			if (nconf->nc_flag & NC_VISIBLE) {
			    if (nthtry == FIRST_TRY) {
				if ((nconf->nc_semantics == NC_TPI_COTS_ORD) ||
					(nconf->nc_semantics == NC_TPI_COTS)) {
				    if (port == 0)
					break;
				    if ((strcmp(nconf->nc_protofmly,
					NC_INET) == 0
#ifdef NC_INET6
					/* CSTYLED */
					|| strcmp(nconf->nc_protofmly,
					NC_INET6) == 0
#endif
					/* CSTYLED */
					) &&
					(strcmp(nconf->nc_proto, NC_TCP) == 0))
					break;
				}
			    }
			}
		} /* while */
		if (nconf == NULL) {
			if (++nthtry <= MNT_PREF_LISTLEN) {
				endnetpath(nc);
				if ((nc = setnetpath()) == NULL)
					goto done;
				goto retry;
			} else
				goto done;
		} else {
			if ((nb = get_the_addr(hostname, prog, vers, nconf,
			    port, tinfo, portmap)) == NULL) {
				/*
				 * Continue the same search path in the
				 * netconfig db until no more matched
				 * nconf (nconf == NULL).
				 */
				goto retry;
			}
#ifdef AF_INET6
			if ((nb->len == 8) &&
			    (strcmp(nconf->nc_protofmly, NC_INET6) == 0)) {
				/*
				 * We have a mismatch in the netconfig retry
				 */
				free(nb);
				goto retry;
			}
#endif
		}
	}

	/*
	 * Got nconf and nb.  Now dup the netconfig structure (nconf)
	 * and return it thru nconfp.
	 */
	*nconfp = getnetconfigent(nconf->nc_netid);
	if (*nconfp == NULL) {
		syslog(LOG_ERR, "no memory\n");
		free(nb);
		nb = NULL;
	}
done:
	if (nc)
		endnetpath(nc);
	return (nb);
}


/* return values as for nsc_check_release() */
int
rdc_check_release(char **reqd)
{
	/* librdc.so must be built on the runtime OS release */
	return (nsc_check_release(BUILD_REV_STR, NULL, reqd));
}
