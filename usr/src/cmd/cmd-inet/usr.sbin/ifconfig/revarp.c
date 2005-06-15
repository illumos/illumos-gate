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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"
#include "ifconfig.h"
#include <sys/types.h>
#include <sys/dlpi.h>
#include <libdlpi.h>
#include <sys/sysmacros.h>
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

static int	rarp_write(int, struct arphdr *, uchar_t *, size_t, size_t);
static int	rarp_open(char *, t_uscalar_t, size_t *, uchar_t **,
    uchar_t **);

/* ARGSUSED */
int
doifrevarp(char *ifname, struct sockaddr_in *laddr)
{
	int			if_fd;
	struct pollfd		pfd;
	int			s, flags, ret;
	char			*ctlbuf, *databuf, *cause;
	struct strbuf		ctl, data;
	struct arphdr		*req, *ans;
	struct in_addr		from;
	struct in_addr		answer;
	union DL_primitives	*dlp;
	struct lifreq		lifr;
	struct timeval		senttime;
	struct timeval		currenttime;
	int			waittime;
	int			tries_left;
	size_t			ifaddrlen, ifrarplen;
	uchar_t			*my_macaddr = NULL, *my_broadcast = NULL;


	if (ifname[0] == '\0') {
		(void) fprintf(stderr, "ifconfig: doifrevarp: name not set\n");
		exit(1);
	}

	if (debug)
		(void) printf("doifrevarp interface %s\n", ifname);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		Perror0_exit("socket");
	}
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (char *)&lifr) < 0)
		Perror0_exit("SIOCGLIFFLAGS");

	/* don't try to revarp if we know it won't work */
	if ((lifr.lifr_flags & IFF_LOOPBACK) ||
	    (lifr.lifr_flags & IFF_NOARP) ||
	    (lifr.lifr_flags & IFF_POINTOPOINT))
		return (0);

	/* open rarp interface */
	if_fd = rarp_open(ifname, ETHERTYPE_REVARP, &ifaddrlen, &my_macaddr,
	    &my_broadcast);
	if (if_fd < 0)
		return (0);

	/*
	 * RARP looks at /etc/ethers and NIS, which only works
	 * with 6 byte addresses currently.
	 */
	if (ifaddrlen != ETHERADDRL) {
		(void) close(if_fd);
		free(my_macaddr);
		free(my_broadcast);
		return (0);
	}

	ifrarplen = sizeof (struct arphdr) + (2 * IPADDRL) + (2 * ifaddrlen);

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
	if (((req = (struct arphdr *)malloc(ifrarplen)) == NULL) ||
	    ((ans = (struct arphdr *)malloc(ifrarplen)) == NULL)) {
		(void) close(if_fd);
		free(req);
		free(my_macaddr);
		free(my_broadcast);
		return (0);
	}

	/* create rarp request */
	(void) memset(req, 0, ifrarplen);
	req->ar_hrd = htons(ARPHRD_ETHER);
	req->ar_pro = htons(ETHERTYPE_IP);
	req->ar_hln = ifaddrlen;
	req->ar_pln = IPADDRL;
	req->ar_op = htons(REVARP_REQUEST);

	(void) memcpy((uchar_t *)req + sizeof (struct arphdr), my_macaddr,
	    ifaddrlen);
	(void) memcpy((uchar_t *)req + sizeof (struct arphdr) + IPADDRL +
	    ifaddrlen, my_macaddr, ifaddrlen);

	tries_left = rarp_retries;
rarp_retry:
	/* send the request */
	if (rarp_write(if_fd, req, my_broadcast, ifaddrlen, ifrarplen) < 0)
		goto fail;

	gettimeofday(&senttime, NULL);

	if (debug)
		(void) printf("rarp sent\n");


	/* read the answers */
	if ((databuf = malloc(BUFSIZ)) == NULL) {
		(void) fprintf(stderr, "ifconfig: malloc() failed\n");
		goto fail;
	}
	if ((ctlbuf = malloc(BUFSIZ)) == NULL) {
		(void) fprintf(stderr, "ifconfig: malloc() failed\n");
		goto fail;
	}
	for (;;) {
		ctl.len = 0;
		ctl.maxlen = BUFSIZ;
		ctl.buf = ctlbuf;
		data.len = 0;
		data.maxlen = BUFSIZ;
		data.buf = databuf;
		flags = 0;

		/*
		 * Check to see when the packet was last sent.
		 * If we have not sent a packet in the last
		 * RARP_TIMEOUT seconds, we should send one now.
		 * Note that if some other host on the network is
		 * sending a broadcast packet, poll will return and we
		 * will find out that it does not match the reply we
		 * are waiting for and then go back to poll. If the
		 * frequency of such packets is > rarp_timeout, we don't
		 * want to just go back to poll. We should send out one
		 * more RARP request before blocking in poll.
		 */

		gettimeofday(&currenttime, NULL);
		waittime = rarp_timeout -
				(currenttime.tv_sec - senttime.tv_sec);

		if (waittime <= 0) {
			if (--tries_left > 0) {
				if (debug)
					(void) printf("rarp retry\n");
				goto rarp_retry;
			} else {
				if (debug)
					(void) printf("rarp timeout\n");
				goto fail;
			}
		}

		/* start RARP reply timeout */
		pfd.fd = if_fd;
		pfd.events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
		if ((ret = poll(&pfd, 1, waittime * 1000)) == 0) {
			if (--tries_left > 0) {
				if (debug)
					(void) printf("rarp retry\n");
				goto rarp_retry;
			} else {
				if (debug)
					(void) printf("rarp timeout\n");
				goto fail;
			}
		} else if (ret == -1) {
			perror("ifconfig:  RARP reply poll");
			goto fail;
		}

		/* poll returned > 0 for this fd so getmsg should not block */
		if ((ret = getmsg(if_fd, &ctl, &data, &flags)) < 0) {
			perror("ifconfig: RARP reply getmsg");
			goto fail;
		}

		if (debug) {
			(void) printf("rarp: ret[%d] ctl.len[%d] data.len[%d] "
			    "flags[%d]\n", ret, ctl.len, data.len, flags);
		}
		/* Validate DL_UNITDATA_IND.  */
		/* LINTED: malloc returns a pointer aligned for any use */
		dlp = (union DL_primitives *)ctlbuf;
		if (debug) {
			(void) printf("rarp: dl_primitive[%lu]\n",
				dlp->dl_primitive);
			if (dlp->dl_primitive == DL_ERROR_ACK) {
				(void) printf(
				    "rarp: err ak: dl_errno %lu errno %lu\n",
				    dlp->error_ack.dl_errno,
				    dlp->error_ack.dl_unix_errno);
			}
			if (dlp->dl_primitive == DL_UDERROR_IND) {
				(void) printf("rarp: ud err: err[%lu] len[%lu] "
				    "off[%lu]\n",
				    dlp->uderror_ind.dl_errno,
				    dlp->uderror_ind.dl_dest_addr_length,
				    dlp->uderror_ind.dl_dest_addr_offset);
			}
		}
		(void) memcpy(ans, databuf, ifrarplen);
		cause = NULL;
		if (ret & MORECTL)
			cause = "MORECTL flag";
		else if (ret & MOREDATA)
			cause = "MOREDATA flag";
		else if (ctl.len == 0)
			cause = "missing control part of message";
		else if (ctl.len < 0)
			cause = "short control part of message";
		else if (dlp->dl_primitive != DL_UNITDATA_IND)
			cause = "not unitdata_ind";
		else if (ctl.len < DL_UNITDATA_IND_SIZE)
			cause = "short unitdata_ind";

		else if (data.len < ifrarplen)
			cause = "short arp";
		else if (ans->ar_hrd != htons(ARPHRD_ETHER))
			cause = "hrd";
		else if (ans->ar_pro != htons(ETHERTYPE_IP))
			cause = "pro";
		else if (ans->ar_hln != ifaddrlen)
			cause = "hln";
		else if (ans->ar_pln != IPADDRL)
			cause = "pln";
		if (cause) {
			(void) fprintf(stderr,
				"sanity check failed; cause: %s\n", cause);
			continue;
		}

		switch (ntohs(ans->ar_op)) {
		case ARPOP_REQUEST:
			if (debug)
				(void) printf("Got an arp request\n");
			break;

		case ARPOP_REPLY:
			if (debug)
				(void) printf("Got an arp reply.\n");
			break;

		case REVARP_REQUEST:
			if (debug)
				(void) printf("Got a rarp request.\n");
			break;

		case REVARP_REPLY:

			(void) memcpy(&answer, (uchar_t *)ans +
			    sizeof (struct arphdr) + (2 * ifaddrlen) +
			    IPADDRL, sizeof (answer));
			(void) memcpy(&from, (uchar_t *)ans +
			    sizeof (struct arphdr) + ifaddrlen, sizeof (from));
			if (debug) {
				(void) printf("answer: %s", inet_ntoa(answer));
				(void) printf(" [from %s]\n", inet_ntoa(from));
			}
			laddr->sin_addr = answer;
			(void) close(if_fd);
			free(req);
			free(ans);
			free(my_macaddr);
			free(my_broadcast);
			return (1);

		default:
			(void) fprintf(stderr,
			    "ifconfig: unknown opcode 0x%xd\n", ans->ar_op);
			break;
		}
	}
	/* NOTREACHED */
fail:
	(void) close(if_fd);
	free(req);
	free(ans);
	free(my_macaddr);
	free(my_broadcast);
	return (0);
}

/*
 * Open the datalink provider device and bind to the REVARP type.
 * Return the resulting descriptor.
 */
static int
rarp_open(char *ifname, t_uscalar_t type, size_t *alen, uchar_t **myaddr,
    uchar_t **mybaddr)
{
	int			fd, len;
	char			*str;
	dl_info_ack_t		dlinfo;
	dlpi_if_attr_t		dia;
	int			i;

	if (debug)
		(void) printf("rarp_open %s\n", ifname);

	fd = dlpi_if_open(ifname, &dia, _B_FALSE);
	if (fd < 0) {
		(void) fprintf(stderr, "ifconfig: could not open device for "
		    "%s\n", ifname);
		return (-1);
	}

	if (dlpi_info(fd, -1, &dlinfo, NULL, NULL, NULL, NULL, NULL,
	    NULL) < 0) {
		(void) fprintf(stderr, "ifconfig: info req failed\n");
		goto failed;
	}

	if ((*mybaddr = malloc(dlinfo.dl_brdcst_addr_length)) == NULL) {
		(void) fprintf(stderr, "rarp_open: malloc() failed\n");
		goto failed;
	}

	if (dlpi_info(fd, -1, &dlinfo, NULL, NULL, NULL, NULL, *mybaddr,
	    NULL) < 0) {
		(void) fprintf(stderr, "ifconfig: info req failed\n");
		goto failed;
	}

	if (debug) {
		(void) printf("broadcast addr: ");
		for (i = 0; i < dlinfo.dl_brdcst_addr_length; i++)
			(void) printf("%02x", (*mybaddr)[i]);
		(void) printf("\n");
	}

	len = *alen = dlinfo.dl_addr_length - abs(dlinfo.dl_sap_length);

	if (debug)
		(void) printf("rarp_open: addr length = %d\n", len);

	if ((*myaddr = malloc(len)) == NULL) {
		(void) fprintf(stderr, "rarp_open: malloc() failed\n");
		goto failed;
	}

	if (dlpi_bind(fd, -1, type, DL_CLDLS, _B_FALSE, NULL, NULL,
	    *myaddr, NULL) < 0) {
		(void) fprintf(stderr, "rarp_open: dlpi_bind failed\n");
		goto failed;
	}

	if (debug) {
		str = _link_ntoa(*myaddr, str, len, IFT_OTHER);
		if (str != NULL) {
			(void) printf("device %s mac address %s\n",
			    ifname, str);
			free(str);
		}
	}

	return (fd);

failed:
	(void) dlpi_close(fd);
	free(*mybaddr);
	free(*myaddr);
	return (-1);
}

static int
rarp_write(int fd, struct arphdr *ahdr, uchar_t *dhost, size_t maclen,
    size_t rarplen)
{
	struct strbuf		ctl, data;
	union DL_primitives	*dlp;
	char			*ctlbuf;
	int			ret;
	ushort_t		etype = ETHERTYPE_REVARP;

	/*
	 * Construct DL_UNITDATA_REQ. Allocate at least BUFSIZ bytes.
	 */
	ctl.len = DL_UNITDATA_REQ_SIZE + maclen + sizeof (ushort_t);
	if ((ctl.buf = ctlbuf = malloc(ctl.len)) == NULL) {
		(void) fprintf(stderr, "ifconfig: malloc() failed\n");
		return (-1);
	}
	/* LINTED: malloc returns a pointer aligned for any use */
	dlp = (union DL_primitives *)ctlbuf;
	dlp->unitdata_req.dl_primitive = DL_UNITDATA_REQ;
	dlp->unitdata_req.dl_dest_addr_length = maclen + sizeof (ushort_t);
	dlp->unitdata_req.dl_dest_addr_offset = DL_UNITDATA_REQ_SIZE;
	dlp->unitdata_req.dl_priority.dl_min = 0;
	dlp->unitdata_req.dl_priority.dl_max = 0;

	/*
	 * XXX FIXME Assumes a specific DLPI address format.
	 */
	(void) memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE, dhost, maclen);
	(void) memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE + maclen, &etype,
	    sizeof (etype));

	/* Send DL_UNITDATA_REQ.  */
	data.len = rarplen;
	data.buf = (char *)ahdr;
	ret = putmsg(fd, &ctl, &data, 0);
	free(ctlbuf);
	return (ret);
}

int
dlpi_set_address(char *ifname, uchar_t *ea, int length)
{
	int		fd;
	dlpi_if_attr_t	dia;

	fd = dlpi_if_open(ifname, &dia, _B_FALSE);
	if (fd < 0) {
		(void) fprintf(stderr, "ifconfig: could not open device for "
		    "%s\n", ifname);
		return (-1);
	}

	if (dlpi_set_phys_addr(fd, -1, ea, length) < 0) {
		(void) dlpi_close(fd);
		return (-1);
	}

	(void) dlpi_close(fd);
	return (0);
}

void
dlpi_print_address(char *ifname)
{
	int 	fd, len;
	uchar_t	*laddr;
	dl_info_ack_t dl_info;
	char	*str = NULL;
	dlpi_if_attr_t	dia;

	fd = dlpi_if_open(ifname, &dia, _B_FALSE);
	if (fd < 0) {
		/* Do not report an error */
		return;
	}

	if (dlpi_info(fd, -1, &dl_info, NULL, NULL, NULL, NULL, NULL,
	    NULL) < 0) {
		(void) fprintf(stderr, "ifconfig: info req failed\n");
		(void) dlpi_close(fd);
		return;
	}

	len = dl_info.dl_addr_length - abs(dl_info.dl_sap_length);
	if ((laddr = malloc(len)) == NULL) {
		goto failed;
	}

	if (dlpi_phys_addr(fd, -1, DL_CURR_PHYS_ADDR, laddr, NULL) < 0) {
		(void) fprintf(stderr, "ifconfig: phys_addr failed\n");
		goto failed;
	}

	(void) dlpi_close(fd);
	str = _link_ntoa(laddr, str, len, IFT_OTHER);
	if (str != NULL) {
		switch (dl_info.dl_mac_type) {
			case DL_IB:
				(void) printf("\tipib %s \n", str);
				break;
			default:
				(void) printf("\tether %s \n", str);
				break;
		}
		free(str);
	}

failed:
	free(laddr);
	(void) dlpi_close(fd);
}
