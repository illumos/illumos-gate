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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <netdb.h>
#include <nss_dbdefs.h>
#include <slp-internal.h>
#include <slp_net_utils.h>

typedef struct slp_ifinfo {
	struct sockaddr_in addr;
	struct sockaddr_in netmask;
	struct sockaddr_in bc_addr;
	short flags;
} slp_ifinfo_t;

typedef struct slp_handle_ifinfo {
	slp_ifinfo_t *all_ifs;
	int numifs;
} slp_handle_ifinfo_t;


static SLPError get_all_interfaces(slp_handle_ifinfo_t *info);

/*
 * Obtains the broadcast addresses for all local interfaces given in
 * addrs.
 *
 * hp		IN / OUT holds cached-per-handle if info
 * given_ifs	IN	an array of local interfaces
 * num_givenifs	IN	number of addresses in given_ifs
 * bc_addrs	OUT	an array of broadcast addresses for local interfaces
 * num_addrs	OUT	number of addrs returned in bc_addrs
 *
 * Returns SLP_OK if at least one broadcast address was found; if none
 * were found, returns err != SLP_OK and *bc_addrs = NULL;
 * Caller must free *bc_addrs when done.
 */
SLPError slp_broadcast_addrs(slp_handle_impl_t *hp, struct in_addr *given_ifs,
				int num_givenifs,
				struct sockaddr_in *bc_addrs[],
				int *num_addrs) {

	SLPError err;
	int i, j;
	slp_ifinfo_t *all_ifs;
	slp_handle_ifinfo_t *ifinfo;
	int numifs;

	if (!hp->ifinfo) {
		if (!(ifinfo = malloc(sizeof (*ifinfo)))) {
			slp_err(LOG_CRIT, 0, "slp_broadcast_addrs",
				"out of memory");
			return (SLP_MEMORY_ALLOC_FAILED);
		}
		if ((err = get_all_interfaces(ifinfo)) != SLP_OK) {
			free(ifinfo);
			return (err);
		}
		hp->ifinfo = ifinfo;
	}
	all_ifs = ((slp_handle_ifinfo_t *)hp->ifinfo)->all_ifs;
	numifs = ((slp_handle_ifinfo_t *)hp->ifinfo)->numifs;

	/* allocate memory for reply */
	if (!(*bc_addrs = calloc(num_givenifs, sizeof (**bc_addrs)))) {
		slp_err(LOG_CRIT, 0, "slp_broadcast_addrs", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	/* copy bc addrs for all desired interfaces which are bc-enabled */
	*num_addrs = 0;
	for (j = 0; j < num_givenifs; j++) {
	    for (i = 0; i < numifs; i++) {

		if (!(all_ifs[i].flags & IFF_BROADCAST)) {
			continue;
		}

		if (memcmp(&(all_ifs[i].addr.sin_addr.s_addr),
			    &(given_ifs[j].s_addr),
			    sizeof (given_ifs[j].s_addr)) == 0 &&
		    all_ifs[i].bc_addr.sin_addr.s_addr != 0) {

		    /* got it, so copy it to bc_addrs */
		    (void) memcpy(
				    *bc_addrs + *num_addrs,
				    &(all_ifs[i].bc_addr),
				    sizeof (all_ifs[i].bc_addr));
		    (*num_addrs)++;

		    break;
		}
	    }
	}

	if (*num_addrs == 0) {
		/* none found */
		free (*bc_addrs);
		bc_addrs = NULL;
		return (SLP_INTERNAL_SYSTEM_ERROR);
	}
	return (SLP_OK);
}

/*
 * Returns true if addr is on a subnet local to the local host.
 */
SLPBoolean slp_on_subnet(slp_handle_impl_t *hp, struct in_addr addr) {
	int i;
	struct in_addr netmask, net_addr, masked_addr;
	slp_ifinfo_t *all_ifs;
	slp_handle_ifinfo_t *ifinfo;
	int numifs;

	if (!hp->ifinfo) {
		if (!(ifinfo = malloc(sizeof (*ifinfo)))) {
			slp_err(LOG_CRIT, 0, "slp_broadcast_addrs",
				"out of memory");
			return (SLP_FALSE);
		}
		if (get_all_interfaces(ifinfo) != SLP_OK) {
			free(ifinfo);
			return (SLP_FALSE);
		}
		hp->ifinfo = ifinfo;
	}
	all_ifs = ((slp_handle_ifinfo_t *)hp->ifinfo)->all_ifs;
	numifs = ((slp_handle_ifinfo_t *)hp->ifinfo)->numifs;

	for (i = 0; i < numifs; i++) {
		/* get netmask */
		netmask.s_addr = all_ifs[i].netmask.sin_addr.s_addr;
		/* get network address */
		net_addr.s_addr =
			all_ifs[i].addr.sin_addr.s_addr & netmask.s_addr;
		/* apply netmask to input addr */
		masked_addr.s_addr = addr.s_addr & netmask.s_addr;

		if (memcmp(&(masked_addr.s_addr), &(net_addr.s_addr),
				sizeof (net_addr.s_addr)) == 0) {
			return (SLP_TRUE);
		}
	}

	return (SLP_FALSE);
}

/*
 * Returns true if any local interface if configured with addr.
 */
SLPBoolean slp_on_localhost(slp_handle_impl_t *hp, struct in_addr addr) {
	int i;
	slp_ifinfo_t *all_ifs;
	slp_handle_ifinfo_t *ifinfo;
	int numifs;

	if (!hp->ifinfo) {
		if (!(ifinfo = malloc(sizeof (*ifinfo)))) {
			slp_err(LOG_CRIT, 0, "slp_broadcast_addrs",
				"out of memory");
			return (SLP_FALSE);
		}
		if (get_all_interfaces(ifinfo) != SLP_OK) {
			free(ifinfo);
			return (SLP_FALSE);
		}
		hp->ifinfo = ifinfo;
	}
	all_ifs = ((slp_handle_ifinfo_t *)hp->ifinfo)->all_ifs;
	numifs = ((slp_handle_ifinfo_t *)hp->ifinfo)->numifs;

	for (i = 0; i < numifs; i++) {
		if (memcmp(&(addr.s_addr), &(all_ifs[i].addr.sin_addr.s_addr),
				sizeof (addr)) == 0) {

			return (SLP_TRUE);
		}
	}

	return (SLP_FALSE);
}

void slp_free_ifinfo(void *hi) {
	free(((slp_handle_ifinfo_t *)hi)->all_ifs);
}

/*
 * Populates all_ifs.
 */
static SLPError get_all_interfaces(slp_handle_ifinfo_t *info) {
	int i, n, s = 0;
	int numifs;
	char *buf = NULL;
	size_t bufsize;
	struct ifconf ifc;
	struct ifreq *ifrp, ifr;
	slp_ifinfo_t *all_ifs = NULL;
	SLPError err = SLP_OK;

	/* create a socket with which to get interface info */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		goto cleanup;
	}

	/* how many interfaces are configured? */
	if (ioctl(s, SIOCGIFNUM, (char *)&numifs) < 0) {
		goto cleanup;
	}

	/* allocate memory for ifinfo_t array */
	if (!(all_ifs = calloc(numifs, sizeof (*all_ifs)))) {
		slp_err(LOG_CRIT, 0, "get_all_interfaces", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto cleanup;
	}

	/* allocate memory for interface info */
	bufsize = numifs * sizeof (struct ifreq);
	if (!(buf = malloc(bufsize))) {
		slp_err(LOG_CRIT, 0, "get_all_interfaces", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto cleanup;
	}

	/* get if info */
	ifc.ifc_len = bufsize;
	ifc.ifc_buf = buf;
	if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
		goto cleanup;
	}

	ifrp = ifc.ifc_req;
	i = 0;
	for (n = ifc.ifc_len / sizeof (struct ifreq); n > 0; n--, ifrp++) {

	    /* ignore if interface is not up */
	    (void) memset((char *)&ifr, 0, sizeof (ifr));
	    (void) strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof (ifr.ifr_name));
	    if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		continue;
	    }
	    if (!(ifr.ifr_flags & IFF_UP)) {
		continue;
	    }

	    all_ifs[i].flags = ifr.ifr_flags;

	    /* get the interface's address */
	    if (ioctl(s, SIOCGIFADDR, (caddr_t)&ifr) < 0) {
		continue;
	    }

	    (void) memcpy(&(all_ifs[i].addr), &ifr.ifr_addr,
				sizeof (all_ifs[i].addr));

	    /* get the interface's broadcast address */
	    if (ioctl(s, SIOCGIFBRDADDR, (caddr_t)&ifr) < 0) {
		(void) memset(&(all_ifs[i].bc_addr), 0,
				sizeof (all_ifs[i].bc_addr));
	    } else {
		(void) memcpy(&(all_ifs[i].bc_addr), &ifr.ifr_addr,
				sizeof (all_ifs[i].bc_addr));
	    }

	    /* get the interface's subnet mask */
	    if (ioctl(s, SIOCGIFNETMASK, (caddr_t)&ifr) < 0) {
		(void) memset(&(all_ifs[i].netmask), 0,
				sizeof (all_ifs[i].netmask));
	    } else {
		(void) memcpy(&(all_ifs[i].netmask), &ifr.ifr_addr,
				sizeof (all_ifs[i].netmask));
	    }

	    i++;
	}

	/* i contains the number we actually got info on */
	info->numifs = i;
	info->all_ifs = all_ifs;

	if (i == 0) {
		err = SLP_INTERNAL_SYSTEM_ERROR;
		free(all_ifs);
		info->all_ifs = NULL;
	}

cleanup:
	if (s) (void) close(s);
	if (buf) free(buf);

	return (err);
}

/*
 * Converts a SLPSrvURL to a network address. 'sa' must have been
 * allocated by the caller.
 * Assumes that addresses are given as specified in the protocol spec,
 * i.e. as IP addresses and not host names.
 */
SLPError slp_surl2sin(SLPSrvURL *surl, struct sockaddr_in *sa) {
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	if (slp_pton(surl->s_pcHost, &(sin->sin_addr)) < 1)
		return (SLP_PARAMETER_BAD);
	sin->sin_family = AF_INET;
	/* port number */
	sin->sin_port = htons(
		(surl->s_iPort == 0 ? SLP_PORT : surl->s_iPort));

	return (SLP_OK);
}

/*
 * A wrapper around gethostbyaddr_r. This checks the useGetXXXbyYYY
 * property first to determine whether a name service lookup should
 * be used. If not, it converts the address in 'addr' to a string
 * and just returns that.
 *
 * The core functionality herein will be replaced with getaddrinfo
 * when it becomes available.
 */

char *slp_gethostbyaddr(const char *addr, int size) {
	char storebuf[SLP_NETDB_BUFSZ], addrbuf[INET6_ADDRSTRLEN], *cname;
	const char *use_xbyy;
	struct hostent namestruct[1], *name;
	int herrno;

	/* default: copy in the IP address */
	cname = slp_ntop(addrbuf, INET6_ADDRSTRLEN, (const void *) addr);
	if (cname && !(cname = strdup(cname))) {
		slp_err(LOG_CRIT, 0, "slp_gethostbyaddr", "out of memory");
		return (NULL);
	}

	if ((use_xbyy = SLPGetProperty(SLP_CONFIG_USEGETXXXBYYYY)) != NULL &&
	    strcasecmp(use_xbyy, "false") == 0) {
		return (cname);
	}

	while (!(name = gethostbyaddr_r(addr, size,
					AF_INET,
					namestruct,
					storebuf,
					SLP_NETDB_BUFSZ,
					&herrno))) {
		switch (herrno) {
		case NO_RECOVERY:
		case NO_DATA:
			return (cname);
		case TRY_AGAIN:
			continue;
		default:
			return (cname);	/* IP address */
		}
	}

	free(cname);
	if (!(cname = strdup(name->h_name))) {
		slp_err(LOG_CRIT, 0, "slp_gethostbyaddr", "out of memory");
		return (NULL);
	}

	return (cname);
}

/* @@@ currently getting these from libresolv2 -> change? */

/*
 * Converts the address pointed to by 'addr' to a string. Currently
 * just calls inet_ntoa, but is structured to be a wrapper to
 * inet_ntop. Returns NULL on failure.
 *
 * This wrapper allows callers to be protocol agnostic. Right now it
 * only handles IPv4.
 */
/*ARGSUSED*/
char *slp_ntop(char *buf, int buflen, const void *addr) {
	return (inet_ntoa(*(struct in_addr *)addr));
}

/*
 * convert from presentation format (which usually means ASCII printable)
 * to network format (which is usually some kind of binary format).
 * return:
 *	1 if the address was valid for the specified address family
 *	0 if the address wasn't valid (`dst' is untouched in this case)
 *	-1 if some other error occurred (`dst' is untouched in this case, too)
 *
 * This wrapper allows callers to be protocol agnostic. Right now it
 * only handles IPv4.
 */
int slp_pton(const char *addrstr, void *addr) {
	return (inet_pton(AF_INET, addrstr, addr));
}
