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
 *
 * Standalone dhcp client.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/salib.h>
#include <sys/bootconf.h>
#include <sys/bootcmn.h>
#include <sys/socket.h>
#include <sys/isa_defs.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/inetutil.h>
#include <netinet/dhcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <dhcp_impl.h>
#include <net/if_types.h>
#include <sys/promif.h>
#include <sys/platnames.h>
#include <socket_inet.h>

#include "ipv4.h"
#include "mac.h"
#include <sys/bootdebug.h>
#include "dhcpv4.h"

static char		*s_n = "INIT";
static enum DHCPSTATE 	dhcp_state = INIT;

static PKT		*dhcp_snd_bufp, *dhcp_rcv_bufp;
static int		dhcp_buf_size;

static const uint8_t	magic[] = BOOTMAGIC;	/* RFC1048 */
static uint8_t		opt_discover[]  = { CD_DHCP_TYPE, 1, DISCOVER };
static uint8_t		opt_request[]   = { CD_DHCP_TYPE, 1, REQUEST };
static uint8_t		opt_decline[]   = { CD_DHCP_TYPE, 1, DECLINE };

static uint8_t		dhcp_classid[DHCP_MAX_OPT_SIZE + 3];
static uint8_t		dhcp_clientid[DHCP_MAX_CID_LEN];
static uint8_t		dhcp_clientid_len = 0;

static uint32_t		dhcp_start_time;	/* start time (msecs */
static time_t		dhcp_secs;
static uint32_t		timeout;	/* timeout in milliseconds */

static int		pkt_counter;
PKT_LIST		*list_tl, *list_hd;
PKT_LIST		*state_pl = NULL;

#define	PROM_BOOT_CACHED	"bootp-response"
extern char	*bootp_response;	/* bootprop.c */
extern int	pagesize;

/*
 * Do whatever reset actions/initialization actions are generic for every
 * DHCP/bootp message. Set the message type.
 *
 * Returns: the updated options ptr.
 */
static uint8_t *
init_msg(PKT *pkt, uint8_t *pkttype)
{
	static uint32_t xid;

	bzero(pkt, dhcp_buf_size);
	bcopy(magic, pkt->cookie, sizeof (pkt->cookie));
	pkt->op = BOOTREQUEST;
	if (xid == 0)
		bcopy(mac_get_addr_buf()+2, &xid, 4);
	else
		xid++;
	pkt->xid = xid;
	bcopy(pkttype, pkt->options, 3);
	return ((uint8_t *)(pkt->options + 3));
}

/*
 *  Parameter request list.
 */
static void
parameter_request_list(uint8_t **opt)
{
	/*
	 * This parameter request list is used in the normal 4-packet
	 * DHCPDISCOVER/OFFER/REQUEST/ACK exchange; it must not contain
	 * CD_REQUESTED_IP_ADDR or CD_LEASE_TIME.
	 */
	static uint8_t	prlist[] = {
	    CD_REQUEST_LIST,	/* parameter request list option number */
	    4,			/* number of options requested */
	    CD_SUBNETMASK,
	    CD_ROUTER,
	    CD_HOSTNAME,
	    CD_VENDOR_SPEC
	    };
	if (opt && *opt) {
		bcopy(prlist, *opt, sizeof (prlist));
		*opt += sizeof (prlist);
	}
}

/*
 * Set hardware specific fields
 */
static void
set_hw_spec_data(PKT *p, uint8_t **opt, uint8_t *pkttype)
{
	char mfg[DHCP_MAX_OPT_SIZE + 1], cbuf[DHCP_MAX_OPT_SIZE + 1];
	uint8_t *tp, *dp;
	int adjust_len, len, i;

	p->htype = mac_arp_type(mac_get_type());
	len = (uchar_t)mac_get_addr_len();
	if (len <= sizeof (p->chaddr)) {
		p->hlen = len;
		bcopy(mac_get_addr_buf(), p->chaddr, len);
	} else {
		uint8_t type = *(pkttype + 2);
		/*
		 * The mac address does not fit in the chaddr
		 * field, thus it can not be sent to the server,
		 * thus server can not unicast the reply. Per
		 * RFC 2131 4.4.1, client can set this bit in
		 * DISCOVER/REQUEST.
		 */
		if ((type == DISCOVER) || (type == REQUEST))
			p->flags = htons(BCAST_MASK);
	}

	if (opt && *opt) {
		if (dhcp_classid[0] == '\0') {
			/*
			 * Classids based on mfg name: Commas (,) are
			 * converted to periods (.), and spaces ( ) are removed.
			 */
			dhcp_classid[0] = CD_CLASS_ID;

			(void) strncpy(mfg, get_mfg_name(), sizeof (mfg));
			if (strncmp(mfg, "SUNW", strlen("SUNW")) != 0) {
				len = strlen("SUNW.");
				(void) strcpy(cbuf, "SUNW.");
			} else {
				len = 0;
				cbuf[0] = '\0';
			}
			len += strlen(mfg);

			if ((len + 2) < DHCP_MAX_OPT_SIZE) {
				tp = (uint8_t *)strcat(cbuf, mfg);
				dp = &dhcp_classid[2];
				adjust_len = 0;
				for (i = 0; i < len; i++, tp++) {
					if (*tp == ',') {
						*dp++ = '.';
					} else if (*tp == ' ') {
						adjust_len++;
					} else {
						*dp++ = *tp;
					}
				}
				len -= adjust_len;
				dhcp_classid[1] = (uint8_t)len;
			} else
				prom_panic("Not enough space for class id");
#ifdef	DHCP_DEBUG
			printf("%s: Classid: %s\n", s_n, &dhcp_classid[2]);
#endif	/* DHCP_DEBUG */
		}
		bcopy(dhcp_classid, *opt, dhcp_classid[1] + 2);
		*opt += dhcp_classid[1] + 2;
	}
}

static void
flush_list(void)
{
	PKT_LIST *wk, *tmp;

	wk = list_hd;
	while (wk != NULL) {
		tmp = wk;
		wk = wk->next;
		bkmem_free((char *)tmp->pkt, tmp->len);
		bkmem_free((char *)tmp, sizeof (PKT_LIST));
	}
	list_hd = list_tl = NULL;
	pkt_counter = 0;
}

static void
remove_list(PKT_LIST *pl, int flag)
{
	if (list_hd == NULL)
		return;

	if (list_hd == list_tl) {
		list_hd = list_tl = NULL;
	} else if (list_hd == pl) {
		list_hd = pl->next;
		list_hd->prev = NULL;
	} else if (list_tl == pl) {
		list_tl = list_tl->prev;
		list_tl->next = NULL;
	} else {
		pl->prev->next = pl->next;
		pl->next->prev = pl->prev;
	}
	pkt_counter--;
	if (flag) {
		bkmem_free((char *)pl->pkt, pl->len);
		bkmem_free((char *)pl, sizeof (PKT_LIST));
	}
}

/*
 * Collects BOOTP responses. Length has to be right, it has to be
 * a BOOTP reply pkt, with the same XID and HW address as ours. Adds
 * them to the pkt list.
 *
 * Returns 0 if no error processing packet, 1 if an error occurred and/or
 * collection of replies should stop. Used in inet() calls.
 */
static int
bootp_collect(int len)
{
	PKT		*s = (PKT *)dhcp_snd_bufp;
	PKT		*r = (PKT *)dhcp_rcv_bufp;
	PKT_LIST	*pl;

	if (len < sizeof (PKT)) {
		dprintf("%s: BOOTP reply too small: %d\n", s_n, len);
		return (1);
	}
	if (r->op == BOOTREPLY && r->xid == s->xid &&
	    bcmp((caddr_t)s->chaddr, (caddr_t)r->chaddr, s->hlen) == 0) {
		/* Add a packet to the pkt list */
		if (pkt_counter > (MAX_PKT_LIST - 1))
			return (1);	/* got enough packets already */
		if (((pl = (PKT_LIST *)bkmem_zalloc(sizeof (PKT_LIST))) ==
		    NULL) || ((pl->pkt = (PKT *)bkmem_zalloc(len)) == NULL)) {
			errno = ENOMEM;
			if (pl != NULL)
				bkmem_free((char *)pl, sizeof (PKT_LIST));
			return (1);
		}
		bcopy(dhcp_rcv_bufp, pl->pkt, len);
		pl->len = len;
		if (list_hd == NULL) {
			list_hd = list_tl = pl;
			pl->prev = NULL;
		} else {
			list_tl->next = pl;
			pl->prev = list_tl;
			list_tl = pl;
		}
		pkt_counter++;
		pl->next = NULL;
	}
	return (0);
}

/*
 * Checks if BOOTP exchange(s) were successful. Returns 1 if they
 * were, 0 otherwise. Used in inet() calls.
 */
static int
bootp_success(void)
{
	PKT	*s = (PKT *)dhcp_snd_bufp;

	if (list_hd != NULL) {
		/* remember the secs - we may need them later */
		dhcp_secs = ntohs(s->secs);
		return (1);
	}
	s->secs = htons((uint16_t)((prom_gettime() - dhcp_start_time)/1000));
	return (0);
}

/*
 * This function accesses the network. Opens a connection, and binds to
 * it if a client binding doesn't already exist. If 'tries' is 0, then
 * no reply is expected/returned. If 'tries' is non-zero, then 'tries'
 * attempts are made to get a valid response. If 'tol' is not zero,
 * then this function will wait for 'tol' milliseconds for more than one
 * response to a transmit.
 *
 * Returns 0 for success, errno otherwise.
 */
static int
inet(uint32_t size, struct in_addr *src, struct in_addr *dest, uint32_t tries,
    uint32_t tol)
{
	int			done = B_FALSE, flags, len;
	uint32_t		attempts = 0;
	int			sd;
	uint32_t		wait_time;	/* Max time collect replies */
	uint32_t		init_timeout;	/* Max time wait ANY reply */
	uint32_t		now;
	struct sockaddr_in	saddr, daddr;

	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		dprintf("%s: Can't open a socket.\n", s_n);
		return (errno);
	}

	flags = 0;

	bzero(&saddr, sizeof (struct sockaddr_in));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(IPPORT_BOOTPC);
	saddr.sin_addr.s_addr = htonl(src->s_addr);

	if (bind(sd, (struct sockaddr *)&saddr, sizeof (saddr)) < 0) {
		dprintf("%s: Cannot bind to port %d, errno: %d\n",
		    s_n, IPPORT_BOOTPC, errno);
		(void) socket_close(sd);
		return (errno);
	}

	if (ntohl(dest->s_addr) == INADDR_BROADCAST) {
		int dontroute = B_TRUE;
		(void) setsockopt(sd, SOL_SOCKET, SO_DONTROUTE,
		    (const void *)&dontroute, sizeof (dontroute));
	}

	bzero(&daddr, sizeof (struct sockaddr_in));
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(IPPORT_BOOTPS);
	daddr.sin_addr.s_addr = htonl(dest->s_addr);
	wait_time = prom_gettime() + tol;

	do {
		if (sendto(sd, (char *)dhcp_snd_bufp, size, flags,
		    (struct sockaddr *)&daddr, sizeof (daddr)) < 0) {
			dprintf("%s: sendto failed with errno: %d\n",
			    s_n, errno);
			(void) socket_close(sd);
			return (errno);
		}
		if (!tries)
			break;   /* don't bother to check for reply */

		now = prom_gettime();
		if (timeout == 0)
			timeout = 4000;
		else {
			timeout <<= 1;
			if (timeout > 64000)
				timeout = 64000;
		}
		init_timeout = now + timeout;
		wait_time = now + tol;
		do {
			if ((len = recvfrom(sd, (char *)dhcp_rcv_bufp,
			    (int)dhcp_buf_size, MSG_DONTWAIT, NULL,
			    NULL)) < 0) {
				if (errno == EWOULDBLOCK)
					continue;	/* DONT WAIT */
				(void) socket_close(sd);
				flush_list();
				return (errno);
			}

			if (bootp_collect(len))
				break;	/* Stop collecting */

			if (tol != 0) {
				if (wait_time < prom_gettime())
					break; /* collection timeout */
			}
		} while (prom_gettime() < init_timeout);

		if (bootp_success()) {
			done = B_TRUE;
			break;  /* got the goods */
		}
	} while (++attempts < tries);

	(void) socket_close(sd);

	return (done ? 0 : DHCP_NO_DATA);
}

/*
 * Print the message from the server.
 */
static void
prt_server_msg(DHCP_OPT *p)
{
	int len = p->len;
	char scratch[DHCP_MAX_OPT_SIZE + 1];

	if (len > DHCP_MAX_OPT_SIZE)
		len = DHCP_MAX_OPT_SIZE;
	bcopy(p->value, scratch, len);
	scratch[len] = '\0';
	printf("%s: Message from server: '%s'\n", s_n, scratch);
}

/*
 * This function scans the list of OFFERS, and returns the "best" offer.
 * The criteria used for determining this is:
 *
 * The best:
 * DHCP OFFER (not BOOTP), same client_id as ours, same class_id,
 * Longest lease, all the options we need.
 *
 * Not quite as good:
 * DHCP OFFER, no class_id, short lease, only some of the options we need.
 *
 * We're really reach'in
 * BOOTP reply.
 *
 * DON'T select an offer from a server that gave us a configuration we
 * couldn't use. Take this server off the "bad" list when this is done.
 * Next time, we could potentially retry this server's configuration.
 *
 * NOTE: perhaps this bad server should have a counter associated with it.
 */
static PKT_LIST *
select_best(void)
{
	PKT_LIST	*wk, *tk, *best;
	int		err = 0;

	/* Pass one. Scan for options, set appropriate opt field. */
	wk = list_hd;
	while (wk != NULL) {
		if ((err = dhcp_options_scan(wk, B_TRUE)) != 0) {
			/* Garbled Options. Nuke this pkt. */
			if (boothowto & RB_DEBUG) {
				switch (err) {
				case DHCP_WRONG_MSG_TYPE:
					printf("%s: Unexpected DHCP message.\n",
					    s_n);
					break;
				case DHCP_GARBLED_MSG_TYPE:
					printf(
					    "%s: Garbled DHCP message type.\n",
					    s_n);
					break;
				case DHCP_BAD_OPT_OVLD:
					printf("%s: Bad option overload.\n",
					    s_n);
					break;
				}
			}
			tk = wk;
			wk = wk->next;
			remove_list(tk, B_TRUE);
			continue;
		}
		wk = wk->next;
	}

	/*
	 * Pass two. Pick out the best offer. Point system.
	 * What's important?
	 *	0) DHCP
	 *	1) No option overload
	 *	2) Encapsulated vendor option
	 *	3) Non-null sname and siaddr fields
	 *	4) Non-null file field
	 *	5) Hostname
	 *	6) Subnetmask
	 *	7) Router
	 */
	best = NULL;
	for (wk = list_hd; wk != NULL; wk = wk->next) {
		wk->offset = 0;
		if (wk->opts[CD_DHCP_TYPE] &&
		    wk->opts[CD_DHCP_TYPE]->len == 1) {
			if (*wk->opts[CD_DHCP_TYPE]->value != OFFER) {
				dprintf("%s: Unexpected DHCP message."
				    " Expected OFFER message.\n", s_n);
				continue;
			}
			if (!wk->opts[CD_LEASE_TIME]) {
				dprintf("%s: DHCP OFFER message without lease "
				    "time parameter.\n", s_n);
				continue;
			} else {
				if (wk->opts[CD_LEASE_TIME]->len != 4) {
					dprintf("%s: Lease expiration time is "
					    "garbled.\n", s_n);
					continue;
				}
			}
			if (!wk->opts[CD_SERVER_ID]) {
				dprintf("%s: DHCP OFFER message without server "
				    "id parameter.\n", s_n);
				continue;
			} else {
				if (wk->opts[CD_SERVER_ID]->len != 4) {
					dprintf("%s: Server identifier "
					    "parameter is garbled.\n", s_n);
					continue;
				}
			}
			/* Valid DHCP OFFER. See if we got our parameters. */
			dprintf("%s: Found valid DHCP OFFER message.\n", s_n);

			wk->offset += 30;

			/*
			 * Also could be faked, though more difficult
			 * because the encapsulation is hard to encode
			 * on a BOOTP server; plus there's not as much
			 * real estate in the packet for options, so
			 * it's likely this option would get dropped.
			 */
			if (wk->opts[CD_VENDOR_SPEC])
				wk->offset += 80;
		} else
			dprintf("%s: Found valid BOOTP reply.\n", s_n);

		/*
		 * RFC1048 BOOTP?
		 */
		if (bcmp((caddr_t)wk->pkt->cookie, (caddr_t)magic,
		    sizeof (magic)) == 0) {
			wk->offset += 5;
			if (wk->opts[CD_SUBNETMASK])
				wk->offset++;
			if (wk->opts[CD_ROUTER])
				wk->offset++;
			if (wk->opts[CD_HOSTNAME])
				wk->offset += 5;

			/*
			 * Prefer options that have diskless boot significance
			 */
			if (ntohl(wk->pkt->siaddr.s_addr) != INADDR_ANY)
				wk->offset += 10; /* server ip */
			if (wk->opts[CD_OPTION_OVERLOAD] == NULL) {
				if (wk->pkt->sname[0] != '\0')
					wk->offset += 10; /* server name */
				if (wk->pkt->file[0] != '\0')
					wk->offset += 5; /* File to load */
			}
		}
#ifdef	DHCP_DEBUG
		printf("%s: This server configuration has '%d' points.\n", s_n,
		    wk->offset);
#endif	/* DHCP_DEBUG */
		if (!best)
			best = wk;
		else {
			if (best->offset < wk->offset)
				best = wk;
		}
	}
	if (best) {
#ifdef	DHCP_DEBUG
		printf("%s: Found best: points: %d\n", s_n, best->offset);
#endif	/* DHCP_DEBUG */
		remove_list(best, B_FALSE);
	} else {
		dprintf("%s: No valid BOOTP reply or DHCP OFFER was found.\n",
		    s_n);
	}
	flush_list();	/* toss the remaining list */
	return (best);
}

/*
 * Send a decline message to the generator of the DHCPACK.
 */
static void
dhcp_decline(char *msg, PKT_LIST *pl)
{
	PKT		*pkt;
	uint8_t		*opt, ulen;
	int		pkt_size;
	struct in_addr	nets, ours, t_server, t_yiaddr;

	if (pl != NULL) {
		if (pl->opts[CD_SERVER_ID] != NULL &&
		    pl->opts[CD_SERVER_ID]->len == sizeof (struct in_addr)) {
			bcopy(pl->opts[CD_SERVER_ID]->value,
			    &t_server, pl->opts[CD_SERVER_ID]->len);
		} else
			t_server.s_addr = htonl(INADDR_BROADCAST);
		t_yiaddr.s_addr = pl->pkt->yiaddr.s_addr;
	}
	pkt = (PKT *)dhcp_snd_bufp;
	opt = init_msg(pkt, opt_decline);
	set_hw_spec_data(pkt, &opt, opt_decline);

	*opt++ = CD_SERVER_ID;
	*opt++ = sizeof (struct in_addr);
	bcopy(&t_server, opt, sizeof (struct in_addr));
	opt += sizeof (struct in_addr);
	nets.s_addr = htonl(INADDR_BROADCAST);

	/*
	 * Use the given yiaddr in our ciaddr field so server can identify us.
	 */
	pkt->ciaddr.s_addr = t_yiaddr.s_addr;

	ipv4_getipaddr(&ours);	/* Could be 0, could be yiaddr */
	ours.s_addr = htonl(ours.s_addr);

	ulen = (uint8_t)strlen(msg);
	*opt++ = CD_MESSAGE;
	*opt++ = ulen;
	bcopy(msg, opt, ulen);
	opt += ulen;
	*opt++ = CD_END;

	pkt_size = (uint8_t *)opt - (uint8_t *)pkt;
	if (pkt_size < sizeof (PKT))
		pkt_size = sizeof (PKT);

	timeout = 0;	/* reset timeout */
	(void) inet(pkt_size, &ours, &nets, 0, 0L);
}

/*
 * Implementings SELECTING state of DHCP client state machine.
 */
static int
dhcp_selecting(void)
{
	int		pkt_size;
	PKT		*pkt;
	uint8_t		*opt;
	uint16_t	size;
	uint32_t	lease;
	struct in_addr	nets, ours;

	pkt = (PKT *)dhcp_snd_bufp;
	opt = init_msg(pkt, opt_discover);
	pkt->secs = htons((uint16_t)((prom_gettime() - dhcp_start_time)/1000));

	*opt++ = CD_MAX_DHCP_SIZE;
	*opt++ = sizeof (size);
	size = (uint16_t)(dhcp_buf_size - sizeof (struct ip) -
	    sizeof (struct udphdr));
	size = htons(size);
	bcopy(&size, opt, sizeof (size));
	opt += sizeof (size);

	set_hw_spec_data(pkt, &opt, opt_discover);

	*opt++ = CD_LEASE_TIME;
	*opt++ = sizeof (lease);
	lease = htonl(DHCP_PERM);	/* ask for a permanent lease */
	bcopy(&lease, opt, sizeof (lease));
	opt += sizeof (lease);

	/*
	 * If a clientid was set using dhcp_set_client_id(), add this
	 * to the options.
	 */
	if (dhcp_clientid_len > 0) {
		*opt++ = CD_CLIENT_ID;
		*opt++ = dhcp_clientid_len;
		bcopy(dhcp_clientid, opt, dhcp_clientid_len);
		opt += dhcp_clientid_len;
	}

	parameter_request_list(&opt);

	*opt++ = CD_END;

	pkt_size = (uint8_t *)opt - (uint8_t *)pkt;
	if (pkt_size < sizeof (PKT))
		pkt_size = sizeof (PKT);

	nets.s_addr = INADDR_BROADCAST;
	ours.s_addr = INADDR_ANY;
	timeout = 0;	/* reset timeout */

	return (inet(pkt_size, &ours, &nets, DHCP_RETRIES, DHCP_WAIT));
}

/*
 * implements the REQUESTING state of the DHCP client state machine.
 */
static int
dhcp_requesting(void)
{
	PKT_LIST	*pl, *wk;
	PKT		*pkt, *pl_pkt;
	uint8_t		*opt;
	int		pkt_size, err;
	uint32_t	t_time;
	struct in_addr	nets, ours;
	DHCP_OPT	*doptp;
	uint16_t	size;

	/* here we scan the list of OFFERS, select the best one. */
	state_pl = NULL;

	if ((pl = select_best()) == NULL) {
		dprintf("%s: No valid BOOTP reply or DHCP OFFER was found.\n",
		    s_n);
		return (1);
	}

	pl_pkt = pl->pkt;

	/*
	 * Check to see if we got an OFFER pkt(s). If not, then We only got
	 * a response from a BOOTP server. We'll go to the bound state and
	 * try to use that configuration.
	 */
	if (pl->opts[CD_DHCP_TYPE] == NULL) {
		if (mac_call_arp(&pl_pkt->yiaddr, NULL, DHCP_ARP_TIMEOUT)) {
			/* Someone responded! go back to SELECTING state. */
			printf("%s: Some host already using BOOTP %s.\n", s_n,
			    inet_ntoa(pl_pkt->yiaddr));
			bkmem_free((char *)pl->pkt, pl->len);
			bkmem_free((char *)pl, sizeof (PKT_LIST));
			return (1);
		}
		state_pl = pl;
		return (0);
	}

	/*
	 * if we got a message from the server, display it.
	 */
	if (pl->opts[CD_MESSAGE])
		prt_server_msg(pl->opts[CD_MESSAGE]);
	/*
	 * Assemble a DHCPREQUEST, with the ciaddr field set to 0, since we
	 * got here from DISCOVER state. Keep secs field the same for relay
	 * agents. We start with the DHCPOFFER packet we got, and the
	 * options contained in it to make a requested option list.
	 */
	pkt = (PKT *)dhcp_snd_bufp;
	opt = init_msg(pkt, opt_request);

	/* Time from Successful DISCOVER message. */
	pkt->secs = htons((uint16_t)dhcp_secs);

	size = (uint16_t)(dhcp_buf_size - sizeof (struct ip) -
	    sizeof (struct udphdr));
	size = htons(size);
	*opt++ = CD_MAX_DHCP_SIZE;
	*opt++ = sizeof (size);
	bcopy(&size, opt, sizeof (size));
	opt += sizeof (size);

	set_hw_spec_data(pkt, &opt, opt_request);
	*opt++ = CD_SERVER_ID;
	*opt++ = pl->opts[CD_SERVER_ID]->len;
	bcopy(pl->opts[CD_SERVER_ID]->value, opt,
	    pl->opts[CD_SERVER_ID]->len);
	opt += pl->opts[CD_SERVER_ID]->len;

	/* our offered lease minus boot time */
	*opt++ = CD_LEASE_TIME;
	*opt++ = 4;
	bcopy(pl->opts[CD_LEASE_TIME]->value, &t_time,
	    sizeof (t_time));
	t_time = ntohl(t_time);
	if ((uint32_t)t_time != DHCP_PERM)
		t_time -= (uint32_t)dhcp_secs;
	t_time = htonl(t_time);
	bcopy(&t_time, opt, sizeof (t_time));
	opt += sizeof (t_time);

	/* our offered IP address, as required. */
	*opt++ = CD_REQUESTED_IP_ADDR;
	*opt++ = sizeof (struct in_addr);
	bcopy(&pl_pkt->yiaddr, opt, sizeof (struct in_addr));
	opt += sizeof (struct in_addr);

	/*
	 * If a clientid was set using dhcp_set_client_id(), add this
	 * to the options.
	 */
	if (dhcp_clientid_len > 0) {
		*opt++ = CD_CLIENT_ID;
		*opt++ = dhcp_clientid_len;
		bcopy(dhcp_clientid, opt, dhcp_clientid_len);
		opt += dhcp_clientid_len;
	}

	parameter_request_list(&opt);

	*opt++ = CD_END;

	/* Done with the OFFER pkt. */
	bkmem_free((char *)pl->pkt, pl->len);
	bkmem_free((char *)pl, sizeof (PKT_LIST));

	/*
	 * We make 4 attempts here. We wait for 2 seconds to accumulate
	 * requests, just in case a BOOTP server is too fast!
	 */
	pkt_size = (uint8_t *)opt - (uint8_t *)pkt;
	if (pkt_size < sizeof (PKT))
		pkt_size = sizeof (PKT);

	nets.s_addr = INADDR_BROADCAST;
	ours.s_addr = INADDR_ANY;
	timeout = 0;	/* reset timeout */

	if ((err = inet(pkt_size, &ours, &nets, 4, (time_t)2L)) != 0)
		return (err);
	for (wk = list_hd; wk != NULL && state_pl == NULL; wk = wk->next) {
		if (dhcp_options_scan(wk, B_TRUE) != 0 ||
		    !wk->opts[CD_DHCP_TYPE])
			continue;	/* garbled options */
		switch (*wk->opts[CD_DHCP_TYPE]->value) {
		case ACK:
			remove_list(wk, B_FALSE);
			state_pl = wk;
			break;
		case NAK:
			printf("%s: rejected by DHCP server: %s\n",
			    s_n, inet_ntoa(*((struct in_addr *)wk->
			    opts[CD_SERVER_ID]->value)));
			if (wk->opts[CD_MESSAGE])
				prt_server_msg(wk->opts[CD_MESSAGE]);
			break;
		default:
			dprintf("%s: Unexpected DHCP message type.\n", s_n);
			break;
		}
	}
	flush_list();
	if (state_pl != NULL) {
		if (state_pl->opts[CD_MESSAGE])
			prt_server_msg(state_pl->opts[CD_MESSAGE]);
		pl_pkt = state_pl->pkt;
		/* arp our new address, just to make sure */
		if (!mac_call_arp(&pl_pkt->yiaddr, NULL, DHCP_ARP_TIMEOUT)) {
			/*
			 * No response. Check if lease is ok.
			 */
			doptp = state_pl->opts[CD_LEASE_TIME];
			if (state_pl->opts[CD_DHCP_TYPE] && (!doptp ||
			    (doptp->len % 4) != 0)) {
				dhcp_decline("Missing or corrupted lease time",
				    state_pl);
				err++;
			}
		} else {
			dhcp_decline("IP Address already being used!",
			    state_pl);
			err++;
		}
		if (err) {
			bkmem_free((char *)state_pl->pkt, state_pl->len);
			bkmem_free((char *)state_pl, sizeof (PKT_LIST));
			state_pl = NULL;
		} else
			return (0);	/* passes the tests! */
	}
	dprintf("%s: No valid DHCP acknowledge messages received.\n", s_n);
	return (1);
}

/*
 * Implements BOUND state of DHCP client state machine.
 */
static int
dhcp_bound(void)
{
	PKT		*pl_pkt = state_pl->pkt;
	DHCP_OPT	*doptp;
	uint8_t		*tp, *hp;
	int		items, i, fnd, k;
	char		hostname[MAXHOSTNAMELEN+1];
	struct in_addr	subnet, defr, savr, *ipp, xip;

#ifdef	DHCP_DEBUG
	if (dhcp_classid[0] != 0) {
		char 	scratch[DHCP_MAX_OPT_SIZE + 1];

		bcopy(&dhcp_classid[2], scratch, dhcp_classid[1]);
		scratch[dhcp_classid[1]] = '\0';
		printf("Your machine is of the class: '%s'.\n", scratch);
	}
#endif	/* DHCP_DEBUG */

	/* First, set the bare essentials. (IP layer parameters) */

	ipv4_getipaddr(&xip);
	if (xip.s_addr != INADDR_ANY)
		ipp = &xip;
	else {
		ipp = &pl_pkt->yiaddr;
		ipp->s_addr = ntohl(ipp->s_addr);
		ipv4_setipaddr(ipp);
	}

	ipp->s_addr = htonl(ipp->s_addr);

	if (boothowto & RB_VERBOSE)
		printf("%s: IP address is: %s\n", s_n, inet_ntoa(*ipp));

	/*
	 * Ensure that the Boot NFS READ size, if given, is an int16_t.
	 */
	if (state_pl->vs[VS_BOOT_NFS_READSIZE] != NULL) {
		doptp = state_pl->vs[VS_BOOT_NFS_READSIZE];
		if (doptp->len != sizeof (int16_t))
			state_pl->vs[VS_BOOT_NFS_READSIZE] = NULL;
	}

	/*
	 * Set subnetmask. Nice, but not required.
	 */
	if (state_pl->opts[CD_SUBNETMASK] != NULL) {
		doptp = state_pl->opts[CD_SUBNETMASK];
		if (doptp->len != 4)
			state_pl->opts[CD_SUBNETMASK] = NULL;
		else {
			bcopy(doptp->value, &subnet,
			    sizeof (struct in_addr));
			dprintf("%s: Setting netmask to: %s\n", s_n,
			    inet_ntoa(subnet));
			subnet.s_addr = ntohl(subnet.s_addr);
			ipv4_setnetmask(&subnet);
		}
	}

	/*
	 * Set default IP TTL. Nice, but not required.
	 */
	if (state_pl->opts[CD_IPTTL] != NULL) {
		doptp = state_pl->opts[CD_IPTTL];
		if (doptp->len > 1)
			state_pl->opts[CD_IPTTL] = NULL;
		else {
			doptp = state_pl->opts[CD_IPTTL];
			ipv4_setmaxttl(*(uint8_t *)doptp->value);
			dprintf("%s: Setting IP TTL to: %d\n", s_n,
			    *(uint8_t *)doptp->value);
		}
	}

	/*
	 * Set default router. Not required, although we'll know soon
	 * enough...
	 */
	if (state_pl->opts[CD_ROUTER] != NULL) {
		doptp = state_pl->opts[CD_ROUTER];
		if ((doptp->len % 4) != 0) {
			state_pl->opts[CD_ROUTER] = NULL;
		} else {
			if ((hp = (uint8_t *)bkmem_alloc(
			    mac_get_hdr_len())) == NULL) {
				errno = ENOMEM;
				return (-1);
			}
			items = doptp->len / sizeof (struct in_addr);
			tp = doptp->value;
			bcopy(tp, &savr, sizeof (struct in_addr));
			for (i = 0, fnd = 0; i < items; i++) {
				bcopy(tp, &defr, sizeof (struct in_addr));
				for (k = 0, fnd = 0; k < 2 && fnd == 0; k++) {
					fnd = mac_get_arp(&defr, hp,
					    mac_get_hdr_len(),
					    mac_get_arp_timeout());
				}
				if (fnd)
					break;
				dprintf(
				    "%s: Warning: Router %s is unreachable.\n",
				    s_n, inet_ntoa(defr));
				tp += sizeof (struct in_addr);
			}
			bkmem_free((char *)hp, mac_get_hdr_len());

			/*
			 * If fnd is 0, we didn't find a working router. We'll
			 * still try to use first default router. If we got
			 * a bad router address (like not on the same net),
			 * we're hosed anyway.
			 */
			if (!fnd) {
				dprintf(
				    "%s: Warning: Using default router: %s\n",
				    s_n, inet_ntoa(savr));
				defr.s_addr = savr.s_addr;
			}
			/* ipv4_route expects network order IP addresses */
			(void) ipv4_route(IPV4_ADD_ROUTE, RT_DEFAULT, NULL,
			    &defr);
		}
	}

	/*
	 * Set hostname. Not required.
	 */
	if (state_pl->opts[CD_HOSTNAME] != NULL) {
		doptp = state_pl->opts[CD_HOSTNAME];
		i = doptp->len;
		if (i > MAXHOSTNAMELEN)
			i = MAXHOSTNAMELEN;
		bcopy(doptp->value, hostname, i);
		hostname[i] = '\0';
		(void) sethostname(hostname, i);
		if (boothowto & RB_VERBOSE)
			printf("%s: Hostname is %s\n", s_n, hostname);
	}

	/*
	 * We don't care about the lease time.... We can't enforce it anyway.
	 */
	return (0);
}

/*
 * Convert the DHCPACK into a pure ASCII boot property for use by the kernel
 * later in the boot process.
 */
static void
create_bootpresponse_bprop(PKT_LIST *pl)
{
	uint_t	buflen;

	if (pl == NULL || bootp_response != NULL)
		return;

	buflen = (pl->len * 2) + 1;	/* extra space for null (1) */
	if ((bootp_response = bkmem_alloc(buflen)) == NULL)
		return;

	if (octet_to_hexascii((uint8_t *)pl->pkt, pl->len, bootp_response,
	    &buflen) != 0) {
		bkmem_free(bootp_response, (pl->len * 2) + 1);
		bootp_response = NULL;
	}

#if defined(__sparc)
	prom_create_encoded_prop("bootp-response", pl->pkt, pl->len,
	    ENCODE_BYTES);
#endif	/* __sparc */
}

/*
 * Examines /chosen node for "bootp-response" property. If it exists, this
 * property is the DHCPACK cached there by the PROM's DHCP implementation.
 *
 * If cache_present is B_TRUE, we simply return B_TRUE if the property exists
 * w/o decoding it. If cache_present is B_FALSE, we decode the packet and
 * use it as our state packet for the jump to BOUND mode. Note that it's good
 * enough that the cache exists w/o validation for determining if that's what
 * the user intended.
 *
 * We'll short-circuit the DHCP exchange by accepting this packet. We build a
 * PKT_LIST structure, and copy the bootp-response property value into a
 * PKT buffer we allocated. We then scan the PKT for options, and then
 * set state_pl to point to it.
 *
 * Returns B_TRUE if a packet was cached (and was processed correctly), false
 * otherwise. The caller needs to make the state change from SELECTING to
 * BOUND upon a B_TRUE return from this function.
 */
int
prom_cached_reply(int cache_present)
{
	PKT_LIST	*pl;
	int	len;
	pnode_t	chosen;
	char	*prop = PROM_BOOT_CACHED;

	chosen = prom_finddevice("/chosen");
	if (chosen == OBP_NONODE || chosen == OBP_BADNODE)
		chosen = prom_nextnode((pnode_t)0);	/* root node */

	if ((len = prom_getproplen(chosen, prop)) <= 0)
		return (B_FALSE);

	if (cache_present)
		return (B_TRUE);

	if (((pl = (PKT_LIST *)bkmem_zalloc(sizeof (PKT_LIST))) == NULL) ||
	    ((pl->pkt = (PKT *)bkmem_zalloc(len)) == NULL)) {
		errno = ENOMEM;
		if (pl != NULL)
			bkmem_free((char *)pl, sizeof (PKT_LIST));
		return (B_FALSE);
	}

	(void) prom_getprop(chosen, prop, (caddr_t)pl->pkt);

	pl->len = len;

	if (dhcp_options_scan(pl, B_TRUE) != 0) {
		/* garbled packet */
		bkmem_free((char *)pl->pkt, pl->len);
		bkmem_free((char *)pl, sizeof (PKT_LIST));
		return (B_FALSE);
	}

	state_pl = pl;
	return (B_TRUE);
}

/*
 * Perform DHCP to acquire what we used to get using rarp/bootparams.
 * Returns 0 for success, nonzero otherwise.
 *
 * DHCP client state machine.
 */
int
dhcp(void)
{
	int	err = 0;
	int	done = B_FALSE;

	dhcp_buf_size = mac_get_mtu();
	dhcp_snd_bufp = (PKT *)bkmem_alloc(dhcp_buf_size);
	dhcp_rcv_bufp = (PKT *)bkmem_alloc(dhcp_buf_size);

	if (dhcp_snd_bufp == NULL || dhcp_rcv_bufp == NULL) {
		if (dhcp_snd_bufp != NULL)
			bkmem_free((char *)dhcp_snd_bufp, dhcp_buf_size);
		if (dhcp_rcv_bufp != NULL)
			bkmem_free((char *)dhcp_rcv_bufp, dhcp_buf_size);
		errno = ENOMEM;
		return (-1);
	}

	while (err == 0 && !done) {
		switch (dhcp_state) {
		case INIT:

			s_n = "INIT";
			if (prom_cached_reply(B_FALSE)) {
				dprintf("%s: Using PROM cached BOOT reply...\n",
				    s_n);
				dhcp_state = BOUND;
			} else {
				dhcp_state = SELECTING;
				dhcp_start_time = prom_gettime();
			}
			break;

		case SELECTING:

			s_n = "SELECTING";
			err = dhcp_selecting();
			switch (err) {
			case 0:
				dhcp_state = REQUESTING;
				break;
			case DHCP_NO_DATA:
				dprintf(
				    "%s: No DHCP response after %d tries.\n",
				    s_n, DHCP_RETRIES);
				break;
			default:
				/* major network problems */
				dprintf("%s: Network transaction failed: %d\n",
				    s_n, err);
				break;
			}
			break;

		case REQUESTING:

			s_n = "REQUESTING";
			err = dhcp_requesting();
			switch (err) {
			case 0:
				dhcp_state = BOUND;
				break;
			case DHCP_NO_DATA:
				dprintf("%s: Request timed out.\n", s_n);
				dhcp_state = SELECTING;
				err = 0;
				(void) sleep(10);
				break;
			default:
				/* major network problems */
				dprintf("%s: Network transaction failed: %d\n",
				    s_n, err);
				break;
			}
			break;

		case BOUND:

			/*
			 * We just "give up" if bound state fails.
			 */
			s_n = "BOUND";
			if ((err = dhcp_bound()) == 0) {
				dhcp_state = CONFIGURED;
			}
			break;

		case CONFIGURED:
			s_n = "CONFIGURED";
			create_bootpresponse_bprop(state_pl);
			done = B_TRUE;
			break;
		}
	}
	bkmem_free((char *)dhcp_snd_bufp, dhcp_buf_size);
	bkmem_free((char *)dhcp_rcv_bufp, dhcp_buf_size);

	return (err);
}

/*
 * Returns a copy of the DHCP-supplied value of the parameter requested
 * by code.
 */
boolean_t
dhcp_getinfo(uchar_t optcat, uint16_t code, uint16_t optsize, void *value,
    size_t *vallenp)
{
	size_t		len = *vallenp;

	if (dhcp_getinfo_pl(state_pl, optcat, code,
	    optsize, value, &len)) {

		if (len <= *vallenp) {
			*vallenp = len;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Sets the clientid option.
 */
void
dhcp_set_client_id(uint8_t *clientid, uint8_t clientid_len)
{
	bcopy(clientid, dhcp_clientid, clientid_len);
	dhcp_clientid_len = clientid_len;
}
