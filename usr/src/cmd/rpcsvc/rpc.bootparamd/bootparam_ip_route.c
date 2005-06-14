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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include <sys/timod.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if.h>

#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_mroute.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <nss_dbdefs.h>
#include <fcntl.h>
#include <stropts.h>

#include "bootparam_private.h"

typedef struct mib_item_s {
	struct mib_item_s	*next_item;
	long			group;
	long			mib_id;
	long			length;
	char			*valp;
} mib_item_t;

static void free_itemlist(mib_item_t *);

static mib_item_t *
mibget(int sd)
{
	char			buf[512];
	int			flags;
	int			i, j, getcode;
	struct strbuf		ctlbuf, databuf;
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)(void *)buf;
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)(void *)buf;
	struct T_error_ack	*tea = (struct T_error_ack *)(void *)buf;
	struct opthdr		*req;
	mib_item_t		*first_item = nilp(mib_item_t);
	mib_item_t		*last_item  = nilp(mib_item_t);
	mib_item_t		*temp;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;
	req = (struct opthdr *)&tor[1];
	req->level = MIB2_IP;		/* any MIB2_xxx value ok here */
	req->name  = 0;
	req->len   = 0;

	ctlbuf.buf = buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	flags = 0;
	if (putmsg(sd, &ctlbuf, nilp(struct strbuf), flags) == -1) {
		perror("mibget: putmsg(ctl) failed");
		goto error_exit;
	}
	/*
	 * each reply consists of a ctl part for one fixed structure
	 * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
	 * containing an opthdr structure.  level/name identify the entry,
	 * len is the size of the data part of the message.
	 */
	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof (buf);
	for (j = 1; ; j++) {
		flags = 0;
		getcode = getmsg(sd, &ctlbuf, nilp(struct strbuf), &flags);
		if (getcode == -1) {
			perror("mibget getmsg(ctl) failed");
			if (debug) {
				msgout("#   level   name    len");
				i = 0;
				for (last_item = first_item; last_item;
					last_item = last_item->next_item)
					msgout("%d  %4ld   %5ld   %ld", ++i,
						last_item->group,
						last_item->mib_id,
						last_item->length);
			}
			goto error_exit;
		}
		if ((getcode == 0) &&
		    (ctlbuf.len >= sizeof (struct T_optmgmt_ack))&&
		    (toa->PRIM_type == T_OPTMGMT_ACK) &&
		    (toa->MGMT_flags == T_SUCCESS) &&
		    (req->len == 0)) {
			if (debug)
				msgout("mibget getmsg() %d returned EOD "
				    "(level %lu, name %lu)",
				    j, req->level, req->name);
			return (first_item);		/* this is EOD msg */
		}

		if (ctlbuf.len >= sizeof (struct T_error_ack) &&
		    tea->PRIM_type == T_ERROR_ACK) {
			msgout("mibget %d gives T_ERROR_ACK: "
			    "TLI_error = 0x%lx, UNIX_error = 0x%lx",
			    j, tea->TLI_error, tea->UNIX_error);
			errno = (tea->TLI_error == TSYSERR)
				? tea->UNIX_error : EPROTO;
			goto error_exit;
		}

		if (getcode != MOREDATA ||
		    ctlbuf.len < sizeof (struct T_optmgmt_ack) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS) {
			msgout("mibget getmsg(ctl) %d returned %d, "
			    "ctlbuf.len = %d, PRIM_type = %ld",
			    j, getcode, ctlbuf.len, toa->PRIM_type);
			if (toa->PRIM_type == T_OPTMGMT_ACK)
				msgout("T_OPTMGMT_ACK: MGMT_flags = 0x%lx, "
				    "req->len = %lu",
				    toa->MGMT_flags, req->len);
			errno = ENOMSG;
			goto error_exit;
		}

		temp = (mib_item_t *)malloc(sizeof (mib_item_t));
		if (!temp) {
			perror("mibget malloc failed");
			goto error_exit;
		}
		if (last_item)
			last_item->next_item = temp;
		else
			first_item = temp;
		last_item = temp;
		last_item->next_item = nilp(mib_item_t);
		last_item->group = req->level;
		last_item->mib_id = req->name;
		last_item->length = req->len;
		last_item->valp = (char *)malloc(req->len);
		if (debug)
			msgout(
			"msg %d:  group = %4ld   mib_id = %5ld   length = %ld",
				j, last_item->group, last_item->mib_id,
				last_item->length);

		databuf.maxlen = last_item->length;
		databuf.buf    = last_item->valp;
		databuf.len    = 0;
		flags = 0;
		getcode = getmsg(sd, nilp(struct strbuf), &databuf, &flags);
		if (getcode == -1) {
			perror("mibget getmsg(data) failed");
			goto error_exit;
		} else if (getcode != 0) {
			msgout("xmibget getmsg(data) returned %d, "
			    "databuf.maxlen = %d, databuf.len = %d",
			    getcode, databuf.maxlen, databuf.len);
			goto error_exit;
		}
	}

error_exit:
	free_itemlist(first_item);
	return (NULL);
}

static void
free_itemlist(mib_item_t *item_list)
{
	mib_item_t	*item;

	while (item_list) {
		item = item_list;
		item_list = item->next_item;
		if (item->valp)
			free(item->valp);
		free(item);
	}
}

/*
 * If we are a router, return address of interface closest to client.
 * If we are not a router, look through our routing table and return
 * address of "best" router that is on same net as client.
 *
 * We expect the router flag to show up first, followed by interface
 * addr group, followed by the routing table.
 */

in_addr_t
get_ip_route(struct in_addr client_addr)
{
	boolean_t	found;
	mib_item_t	*item_list;
	mib_item_t	*item;
	int		sd;
	mib2_ip_t		*mip;
	mib2_ipAddrEntry_t	*map;
	mib2_ipRouteEntry_t	*rp;
	int			ip_forwarding = 2;	/* off */
	/* mask of interface used to route to client and best_router */
	struct in_addr		interface_mask;
	/* address of interface used to route to client and best_router */
	struct in_addr		interface_addr;
	/* address of "best router"; i.e. the answer */
	struct in_addr		best_router;

	interface_mask.s_addr = 0L;
	interface_addr.s_addr = 0L;
	best_router.s_addr = 0L;

	/* open a stream to IP */
	sd = open("/dev/ip", O_RDWR);
	if (sd == -1) {
		perror("ip open");
		(void) close(sd);
		msgout("can't open mib stream");
		return (0);
	}

	/* send down a request and suck up all the mib info from IP */
	if ((item_list = mibget(sd)) == nilp(mib_item_t)) {
		msgout("mibget() failed");
		(void) close(sd);
		return (0);
	}

	/*
	 * We make three passes through the list of collected IP mib
	 * information.  First we figure out if we are a router.  Next,
	 * we find which of our interfaces is on the same subnet as
	 * the client.  Third, we paw through our own routing table
	 * looking for a useful router address.
	 */

	/*
	 * The general IP group.
	 */
	for (item = item_list; item; item = item->next_item) {
		if ((item->group == MIB2_IP) && (item->mib_id == 0)) {
			/* are we an IP router? */
			mip = (mib2_ip_t *)(void *)item->valp;
			ip_forwarding = mip->ipForwarding;
			break;
		}
	}

	/*
	 * The interface group.
	 */
	for (item = item_list, found = B_FALSE; item != NULL && !found;
	    item = item->next_item) {
		if ((item->group == MIB2_IP) && (item->mib_id == MIB2_IP_20)) {
			/*
			 * Try to find out which interface is up, configured,
			 * not loopback, and on the same subnet as the client.
			 * Save its address and netmask.
			 */
			map = (mib2_ipAddrEntry_t *)(void *)item->valp;
			while ((char *)map < item->valp + item->length) {
				in_addr_t	addr, mask, net;
				int		ifflags;

				ifflags = map->ipAdEntInfo.ae_flags;
				addr = map->ipAdEntAddr;
				mask =  map->ipAdEntNetMask;
				net = addr & mask;

				if ((ifflags & IFF_LOOPBACK | IFF_UP) ==
				    IFF_UP && addr != INADDR_ANY &&
				    net == (client_addr.s_addr & mask)) {
					interface_addr.s_addr = addr;
					interface_mask.s_addr = mask;
					found = B_TRUE;
					break;
				}
				map++;
			}
		}
	}

	/*
	 * If this exercise found no interface on the same subnet as
	 * the client, then we can't suggest any router address to
	 * use.
	 */
	if (interface_addr.s_addr == 0) {
		if (debug)
			msgout("get_ip_route: no interface on same net "
			    "as client");
		(void) close(sd);
		free_itemlist(item_list);
		return (0);
	}

	/*
	 * If we are a router, we return to client the address of our
	 * interface on the same net as the client.
	 */
	if (ip_forwarding == 1) {
		if (debug)
			msgout("get_ip_route: returning local addr %s",
				inet_ntoa(interface_addr));
		(void) close(sd);
		free_itemlist(item_list);
		return (interface_addr.s_addr);
	}

	if (debug) {
		msgout("interface_addr = %s.", inet_ntoa(interface_addr));
		msgout("interface_mask = %s", inet_ntoa(interface_mask));
	}


	/*
	 * The routing table group.
	 */
	for (item = item_list; item; item = item->next_item) {
		if ((item->group == MIB2_IP) && (item->mib_id == MIB2_IP_21)) {
			if (debug)
				msgout("%lu records for ipRouteEntryTable",
					item->length /
					sizeof (mib2_ipRouteEntry_t));

			for (rp = (mib2_ipRouteEntry_t *)(void *)item->valp;
				(char *)rp < item->valp + item->length;
				rp++) {
				if (debug >= 2)
					msgout("ire_type = %d, next_hop = 0x%x",
						rp->ipRouteInfo.re_ire_type,
						rp->ipRouteNextHop);

				/*
				 * We are only interested in real
				 * gateway routes.
				 */
				if ((rp->ipRouteInfo.re_ire_type !=
				    IRE_DEFAULT) &&
				    (rp->ipRouteInfo.re_ire_type !=
				    IRE_PREFIX) &&
				    (rp->ipRouteInfo.re_ire_type !=
				    IRE_HOST) &&
				    (rp->ipRouteInfo.re_ire_type !=
				    IRE_HOST_REDIRECT))
					continue;

				/*
				 * We are only interested in routes with
				 * a next hop on the same subnet as
				 * the client.
				 */
				if ((rp->ipRouteNextHop &
					interface_mask.s_addr) !=
				    (interface_addr.s_addr &
					interface_mask.s_addr))
					continue;

				/*
				 * We have a valid route.  Give preference
				 * to default routes.
				 */
				if ((rp->ipRouteDest == 0) ||
				    (best_router.s_addr == 0))
					best_router.s_addr =
						rp->ipRouteNextHop;
			}
		}
	}

	if (debug && (best_router.s_addr == 0))
		msgout("get_ip_route: no route found for client");

	(void) close(sd);
	free_itemlist(item_list);
	return (best_router.s_addr);
}

/*
 * Return address of server interface closest to client.
 *
 * If the server has only a single IP address return it. Otherwise check
 * if the server has an interface on the same subnet as the client and
 * return the address of that interface.
 */

in_addr_t
find_best_server_int(char **addr_list, char *client_name)
{
	in_addr_t		server_addr = 0;
	struct hostent		h, *hp;
	char			hbuf[NSS_BUFLEN_HOSTS];
	int			err;
	struct in_addr		client_addr;
	mib_item_t		*item_list;
	mib_item_t		*item;
	int			sd;
	mib2_ipAddrEntry_t	*map;
	in_addr_t		client_net = 0, client_mask = 0;
	boolean_t		found_client_int;

	(void) memcpy(&server_addr, addr_list[0], sizeof (in_addr_t));
	if (addr_list[1] == NULL)
		return (server_addr);

	hp = gethostbyname_r(client_name, &h, hbuf, sizeof (hbuf), &err);
	if (hp == NULL)
		return (server_addr);
	(void) memcpy(&client_addr, hp->h_addr_list[0], sizeof (client_addr));

	/* open a stream to IP */
	sd = open("/dev/ip", O_RDWR);
	if (sd == -1) {
		perror("ip open");
		(void) close(sd);
		msgout("can't open mib stream");
		return (server_addr);
	}

	/* send down a request and suck up all the mib info from IP */
	if ((item_list = mibget(sd)) == nilp(mib_item_t)) {
		msgout("mibget() failed");
		(void) close(sd);
		return (server_addr);
	}
	(void) close(sd);

	/*
	 * Search through the list for our interface which is on the same
	 * subnet as the client and get the netmask.
	 */
	for (item = item_list, found_client_int = B_FALSE;
	    item != NULL && !found_client_int; item = item->next_item) {
		if ((item->group == MIB2_IP) && (item->mib_id == MIB2_IP_20)) {
			/*
			 * Try to find out which interface is up, configured,
			 * not loopback, and on the same subnet as the client.
			 * Save its address and netmask.
			 */
			map = (mib2_ipAddrEntry_t *)(void *)item->valp;
			while ((char *)map < item->valp + item->length) {
				in_addr_t	addr, mask, net;
				int		ifflags;

				ifflags = map->ipAdEntInfo.ae_flags;
				addr = map->ipAdEntAddr;
				mask =  map->ipAdEntNetMask;
				net = addr & mask;

				if ((ifflags & IFF_LOOPBACK|IFF_UP) == IFF_UP &&
				    addr != INADDR_ANY &&
				    (client_addr.s_addr & mask) == net) {
					client_net = net;
					client_mask = mask;
					found_client_int = B_TRUE;
					break;
				}
				map++;
			}
		}
	}

	/*
	 * If we found the interface check which is the best IP address.
	 */
	if (found_client_int) {
		while (*addr_list != NULL) {
			in_addr_t	addr;

			(void) memcpy(&addr, *addr_list, sizeof (in_addr_t));
			if ((addr & client_mask) == client_net) {
				server_addr = addr;
				break;
			}
			addr_list++;
		}
	}

	if (debug && server_addr == 0)
		msgout("No usable interface for returning reply");

	free_itemlist(item_list);
	return (server_addr);
}
