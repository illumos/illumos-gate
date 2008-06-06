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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

/*
 * XXX The functions in this file are only needed to support transport
 * providers that have not yet been converted to use /etc/sock2path.
 * Once all transport providers have been converted this file can be
 * removed.
 */

static struct netconfig *_s_match_netconf(int family, int type, int proto,
		void **nethandle);

/*
 * The following two string arrays map a number as specified
 * by a user of sockets, to the string as would be returned
 * by a call to getnetconfig().
 *
 * They are used by _s_match_netconf();
 *
 * proto_sw contains protocol entries for which there is a corresponding
 * /dev device. All others would presumably use raw IP and download the
 * desired protocol.
 */
static char *proto_sw[] = {
	"",
	"icmp",		/* 1 = ICMP */
	"",
	"",
	"",
	"",
	"tcp",		/* 6 = TCP */
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"udp",		/* 17 = UDP */
};

static char *family_sw[] = {
	"-",		/* 0 = AF_UNSPEC */
	"loopback",	/* 1 = AF_UNIX */
	"inet",		/* 2 = AF_INET */
	"implink",	/* 3 = AF_IMPLINK */
	"pup",		/* 4 = AF_PUP */
	"chaos",	/* 5 = AF_CHAOS */
	"ns",		/* 6 = AF_NS */
	"nbs",		/* 7 = AF_NBS */
	"ecma",		/* 8 = AF_ECMA */
	"datakit",	/* 9 = AF_DATAKIT */
	"ccitt",	/* 10 = AF_CCITT */
	"sna",		/* 11 = AF_SNA */
	"decnet",	/* 12 = AF_DECnet */
	"dli",		/* 13 = AF_DLI */
	"lat",		/* 14 = AF_LAT */
	"hylink",	/* 15 = AF_HYLINK */
	"appletalk",	/* 16 = AF_APPLETALK */
	"nit",		/* 17 = AF_NIT */
	"ieee802",	/* 18 = AF_802 */
	"osi",		/* 19 = AF_OSI */
	"x25",		/* 20 = AF_X25 */
	"osinet",	/* 21 = AF_OSINET */
	"gosip",	/* 22 = AF_GOSIP */
	"ipx",		/* 23 = AF_IPX */
	"route",	/* 24 = AF_ROUTE */
	"link",		/* 25 = AF_LINK */
	"inet6",	/* 26 = AF_INET6 */
	"key",		/* 27 = AF_KEY */
};

/*
 * Lookup family/type/protocol in /etc/netconfig.
 * Returns the pathname and a prototype value (to be passed into SO_PROTOTYPE)
 * The path is malloc'ed and has to be freed by the caller.
 */
int
_s_netconfig_path(int family, int type, int protocol,
	char **pathp, int *prototype)
{
	struct netconfig	*net;
	void				*nethandle;
	struct stat			stats;

	net = _s_match_netconf(family, type, protocol, &nethandle);
	if (net == NULL)
		return (-1);

	if (strcmp(net->nc_proto, NC_NOPROTO) != 0)
		*prototype = 0;
	else
		*prototype = protocol;

retry:
#if defined(i386)
	if (_xstat(_STAT_VER, net->nc_device, &stats) < 0) {
#else
	if (stat(net->nc_device, &stats) < 0) {
#endif
		switch (errno) {
		case EINTR:
			goto retry;

		case ENOENT:
		case ENOLINK:
		case ELOOP:
		case EMULTIHOP:
		case ENOTDIR:
			errno = EPFNOSUPPORT;
			break;
		}
		endnetconfig(nethandle); /* finished with netconfig struct */
		return (-1);
	}
	if (!S_ISCHR(stats.st_mode)) {
		errno = EPFNOSUPPORT;
		endnetconfig(nethandle); /* finished with netconfig struct */
		return (-1);
	}
	*pathp = malloc(strlen(net->nc_device) + 1);
	if (*pathp == NULL) {
		endnetconfig(nethandle);
		errno = ENOMEM;
		return (-1);
	}
	(void) strcpy(*pathp, net->nc_device);
	endnetconfig(nethandle); /* finished with netconfig struct */
	return (0);
}

/*
 * Match config entry for protocol
 * requested.
 */
static struct netconfig *
_s_match_netconf(int family, int type, int proto, void **nethandle)
{
	struct netconfig	*net;
	struct netconfig	*maybe;
	char			*oproto;

	if (family < 0 ||
	    family >= (int)sizeof (family_sw) / (int)sizeof (char *) ||
	    proto < 0 || proto >= IPPROTO_MAX)  {
		errno = EPROTONOSUPPORT;
		return (NULL);
	}
	if (proto) {
		if (proto >= (int)sizeof (proto_sw) / (int)sizeof (char *))
			oproto = "";
		else
			oproto = proto_sw[proto];
	}

	/*
	 * Loop through each entry in netconfig
	 * until one matches or we reach the end.
	 */
	if ((*nethandle = setnetconfig()) == NULL) {
		return (NULL);
	}

	maybe = NULL;
	while ((net = getnetconfig(*nethandle)) != NULL) {
		/*
		 * We make a copy of net->nc_semantics rather than modifying
		 * it in place because the network selection code shares the
		 * structures returned by getnetconfig() among all its callers.
		 * See bug #1160886 for more details.
		 */
		unsigned int semantics = net->nc_semantics;

		if (semantics == NC_TPI_COTS_ORD)
			semantics = NC_TPI_COTS;
		if (proto) {
			if (strcmp(net->nc_protofmly, family_sw[family]) == 0 &&
			    semantics == type &&
			    strcmp(net->nc_proto, oproto) == 0)
				break;

			if (strcmp(net->nc_protofmly, family_sw[family]) == 0 &&
			    type == SOCK_RAW &&
			    semantics == SOCK_RAW &&
			    strcmp(net->nc_proto, NC_NOPROTO) == 0 &&
			    maybe == NULL)
				maybe = net;	/* in case no exact match */

			continue;
		} else	{
			if (strcmp(net->nc_protofmly, family_sw[family]) == 0 &&
			    semantics == type) {
				break;
			}
		}
	}
	if (net == NULL && maybe)
		net = maybe;

	if (net == NULL) {
		endnetconfig(*nethandle);
		errno = EPROTONOSUPPORT;
		return (NULL);
	}

	return (net);
}
