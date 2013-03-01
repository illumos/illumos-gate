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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include "defs.h"
#include "ifconfig.h"
#include <sys/types.h>
#include <libdlpi.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <deflt.h>

#define	IPADDRL		sizeof (struct in_addr)
#define	RARPRETRIES	5

/*
 * The following value (8) is determined to work reliably in switched 10/100MB
 * ethernet environments. Use caution if you plan on decreasing it.
 */
#define	RARPTIMEOUT	8

static char	defaultfile[] = "/etc/inet/rarp";
static char	retries_var[] = "RARP_RETRIES=";
static int rarp_timeout = RARPTIMEOUT;
static int rarp_retries = RARPRETRIES;

static dlpi_handle_t rarp_open(const char *, size_t *, uchar_t *, uchar_t *);
static int rarp_recv(dlpi_handle_t, struct arphdr *, size_t, size_t, int64_t);

int
doifrevarp(const char *linkname, struct sockaddr_in *laddr)
{
	int			s, retval;
	struct arphdr		*req, *ans;
	struct in_addr		from;
	struct in_addr		answer;
	struct lifreq		lifr;
	int			tries_left;
	size_t			physaddrlen, ifrarplen;
	uchar_t			my_macaddr[DLPI_PHYSADDR_MAX];
	uchar_t 		my_broadcast[DLPI_PHYSADDR_MAX];
	dlpi_handle_t		dh;

	if (linkname[0] == '\0') {
		(void) fprintf(stderr, "ifconfig: doifrevarp: name not set\n");
		exit(1);
	}

	if (debug)
		(void) printf("doifrevarp interface %s\n", linkname);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		Perror0_exit("socket");

	(void) strlcpy(lifr.lifr_name, linkname, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		(void) close(s);
		Perror0_exit("SIOCGLIFFLAGS");
	}

	/* don't try to revarp if we know it won't work */
	if ((lifr.lifr_flags & IFF_LOOPBACK) ||
	    (lifr.lifr_flags & IFF_NOARP) ||
	    (lifr.lifr_flags & IFF_IPMP) ||
	    (lifr.lifr_flags & IFF_POINTOPOINT)) {
		(void) close(s);
		return (0);
	}

	/* open rarp interface */
	dh = rarp_open(linkname, &physaddrlen, my_macaddr, my_broadcast);
	if (dh == NULL) {
		(void) close(s);
		return (0);
	}

	/*
	 * RARP looks at /etc/ethers and NIS, which only works
	 * with 6 byte addresses currently.
	 */
	if (physaddrlen != ETHERADDRL) {
		dlpi_close(dh);
		(void) close(s);
		return (0);
	}

	ifrarplen = sizeof (struct arphdr) + (2 * IPADDRL) + (2 * physaddrlen);

	/* look for adjustments to rarp_retries in the RARP defaults file */
	if (defopen(defaultfile) == 0) {
		char	*cp;

		if (cp = defread(retries_var)) {
			int	ntries;

			ntries = atoi(cp);
			if (ntries > 0)
				rarp_retries = ntries;
		}
		(void) defopen(NULL);	/* close default file */
	}

	/* allocate request and response buffers */
	if (((req = malloc(ifrarplen)) == NULL) ||
	    ((ans = malloc(ifrarplen)) == NULL)) {
		dlpi_close(dh);
		(void) close(s);
		free(req);
		return (0);
	}

	/* create rarp request */
	(void) memset(req, 0, ifrarplen);
	req->ar_hrd = htons(ARPHRD_ETHER);
	req->ar_pro = htons(ETHERTYPE_IP);
	req->ar_hln = physaddrlen;
	req->ar_pln = IPADDRL;
	req->ar_op = htons(REVARP_REQUEST);

	(void) memcpy(&req[1], my_macaddr, physaddrlen);
	(void) memcpy((uchar_t *)req + sizeof (struct arphdr) + IPADDRL +
	    physaddrlen, my_macaddr, physaddrlen);

	for (tries_left = rarp_retries; tries_left > 0; --tries_left) {
		/* send the request */
		retval = dlpi_send(dh, my_broadcast, physaddrlen, req,
		    ifrarplen, NULL);
		if (retval != DLPI_SUCCESS) {
			Perrdlpi("doifrevarp: cannot send rarp request",
			    linkname, retval);
			break;
		}

		if (debug)
			(void) printf("rarp sent\n");

		retval = rarp_recv(dh, ans, ifrarplen, physaddrlen,
		    rarp_timeout * MILLISEC);

		if (retval != DLPI_ETIMEDOUT)
			break;

		if (debug)
			(void) printf("rarp retry\n");
	}

	if (retval == DLPI_SUCCESS) {
		(void) memcpy(&answer, (uchar_t *)ans +
		    sizeof (struct arphdr) + (2 * physaddrlen) + IPADDRL,
		    sizeof (answer));
		(void) memcpy(&from, (uchar_t *)ans + physaddrlen +
		    sizeof (struct arphdr), sizeof (from));

		if (debug) {
			(void) printf("answer: %s", inet_ntoa(answer));
			(void) printf(" [from %s]\n", inet_ntoa(from));
		}
		laddr->sin_addr = answer;
	} else if (debug) {
		Perrdlpi("doifrevarp: could not receive rarp reply",
		    linkname, retval);
	}

	dlpi_close(dh);
	(void) close(s);
	free(req);
	free(ans);
	return (retval == DLPI_SUCCESS);
}

/*
 * Open the datalink provider device and bind to the REVARP type.
 * Return the resulting DLPI handle.
 */
static	dlpi_handle_t
rarp_open(const char *linkname, size_t *alen, uchar_t *myaddr, uchar_t *mybaddr)
{
	int		retval;
	char		*physaddr, *bcastaddr;
	dlpi_info_t	dlinfo;
	dlpi_handle_t	dh;

	if (debug)
		(void) printf("rarp_open %s\n", linkname);

	if ((retval = dlpi_open(linkname, &dh, 0)) != DLPI_SUCCESS) {
		Perrdlpi("rarp_open: dlpi_open failed", linkname, retval);
		return (NULL);
	}

	if ((retval = dlpi_bind(dh, ETHERTYPE_REVARP, NULL)) != DLPI_SUCCESS) {
		Perrdlpi("rarp_open: dlpi_bind failed", linkname, retval);
		goto failed;
	}

	if ((retval = dlpi_info(dh, &dlinfo, 0)) != DLPI_SUCCESS) {
		Perrdlpi("rarp_open: dlpi_info failed", linkname, retval);
		goto failed;
	}

	if (dlinfo.di_bcastaddrlen == 0) {
		(void) fprintf(stderr, "ifconfig: rarp_open: %s broadcast "
		    "not supported\n", linkname);
		goto failed;
	}

	/* we assume the following are equal and fill in 'alen' */
	assert(dlinfo.di_bcastaddrlen == dlinfo.di_physaddrlen);

	(void) memcpy(mybaddr, dlinfo.di_bcastaddr, dlinfo.di_bcastaddrlen);

	*alen = dlinfo.di_physaddrlen;

	(void) memcpy(myaddr, dlinfo.di_physaddr, dlinfo.di_physaddrlen);

	if (debug) {
		bcastaddr = _link_ntoa(mybaddr, NULL, dlinfo.di_bcastaddrlen,
		    IFT_OTHER);

		physaddr = _link_ntoa(myaddr, NULL, dlinfo.di_physaddrlen,
		    IFT_OTHER);

		if (physaddr != NULL && bcastaddr != NULL) {
			(void) printf("device %s: broadcast address %s, mac "
			    "address %s\n", linkname, bcastaddr, physaddr);
		}

		free(physaddr);
		free(bcastaddr);

		(void) printf("rarp_open: addr length = %d\n",
		    dlinfo.di_physaddrlen);
	}

	return (dh);

failed:
	dlpi_close(dh);
	return (NULL);
}

/*
 * Read reply for RARP request. If a reply is received within waitms,
 * validate the reply. If it is a correct RARP reply return DLPI_SUCCESS,
 * otherwise return DLPI_ETIMEDOUT. If there is an error while reading retrun
 * the error code.
 */
static int
rarp_recv(dlpi_handle_t dh, struct arphdr *ans, size_t msglen,
    size_t physaddrlen, int64_t waitms)
{
	int		retval;
	char		*cause;
	size_t		anslen = msglen;
	hrtime_t	endtime = gethrtime() + MSEC2NSEC(waitms);
	hrtime_t	currtime;

	while ((currtime = gethrtime()) < endtime) {
		waitms = NSEC2MSEC(endtime - currtime);
		retval = dlpi_recv(dh, NULL, NULL, ans, &anslen, waitms, NULL);
		if (retval == DLPI_SUCCESS) {
			cause = NULL;

			if (anslen < msglen)
				cause = "short packet";
			else if (ans->ar_hrd != htons(ARPHRD_ETHER))
				cause = "hardware type not Ethernet";
			else if (ans->ar_pro != htons(ETHERTYPE_IP))
				cause = "protocol type not IP";
			else if (ans->ar_hln != physaddrlen)
				cause = "unexpected hardware address length";
			else if (ans->ar_pln != IPADDRL)
				cause = "unexpected protocol address length";
			if (cause != NULL) {
				(void) fprintf(stderr, "RARP packet received "
				    "but discarded (%s)\n", cause);
				continue;
			}
			switch (ntohs(ans->ar_op)) {
			case REVARP_REQUEST:
				if (debug)
					(void) printf("Got a rarp request.\n");
				break;

			case REVARP_REPLY:
				return (DLPI_SUCCESS);

			default:
				(void) fprintf(stderr, "ifconfig: unknown "
				    "RARP opcode 0x%x\n", ans->ar_op);
				break;
			}
		} else if (retval != DLPI_ETIMEDOUT) {
			Perrdlpi("doifrevarp: dlpi_recv failed",
			    dlpi_linkname(dh), retval);
			return (retval);
		}
	}

	return (DLPI_ETIMEDOUT);
}

void
dlpi_print_address(const char *linkname)
{
	uint_t	physaddrlen = DLPI_PHYSADDR_MAX;
	uchar_t	physaddr[DLPI_PHYSADDR_MAX];
	char	*str;
	int	retv;
	dlpi_handle_t	dh;
	dlpi_info_t	dlinfo;

	if (dlpi_open(linkname, &dh, 0) != DLPI_SUCCESS) {
		/* Do not report an error */
		return;
	}

	retv = dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR, physaddr, &physaddrlen);
	if (retv != DLPI_SUCCESS) {
		Perrdlpi("dlpi_get_physaddr failed", linkname, retv);
		dlpi_close(dh);
		return;
	}

	retv = dlpi_info(dh, &dlinfo, 0);
	if (retv != DLPI_SUCCESS) {
		Perrdlpi("dlpi_info failed", linkname, retv);
		dlpi_close(dh);
		return;
	}
	dlpi_close(dh);

	str = _link_ntoa(physaddr, NULL, physaddrlen, IFT_OTHER);

	if (str != NULL && physaddrlen != 0) {
		switch (dlinfo.di_mactype) {
			case DL_IB:
				(void) printf("\tipib %s \n", str);
				break;
			default:
				(void) printf("\tether %s \n", str);
				break;
		}
		free(str);
	}
}
