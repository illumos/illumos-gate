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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ethernet routines. Includes ARP and Reverse ARP. Used for ethernet-like
 * media also - so be sure NOT to use ETHERMTU as a mtu limit. macinit()
 * will set this appropriately.
 */

#include <sys/types.h>
#include <socket_impl.h>
#include <socket_inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/salib.h>
#include <sys/bootdebug.h>

#include "ipv4.h"
#include "ipv4_impl.h"
#include "mac.h"
#include "mac_impl.h"
#include "ethernet_inet.h"

ether_addr_t etherbroadcastaddr = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

struct arp_packet {
	struct ether_header	arp_eh;
	struct ether_arp	arp_ea;
#define	USED_SIZE (sizeof (struct ether_header) + sizeof (struct ether_arp))
	char	filler[ETHERMIN - sizeof (struct ether_arp)];
};

static char *
ether_print(ether_addr_t ea)
{
	static char eprintbuf[20];

	(void) sprintf(eprintbuf, "%x:%x:%x:%x:%x:%x", ea[0], ea[1], ea[2],
	    ea[3], ea[4], ea[5]);
	return (eprintbuf);
}

/*
 * Common ARP code. Broadcast the packet and wait for the right response.
 *
 * If rarp is called for, caller expects an IPv4 address in the target
 * protocol address (tpa) field of the "out" argument.
 *
 * If arp is called for, caller expects a hardware address in the
 * source hardware address (sha) field of the "out" argument.
 *
 * Returns TRUE if transaction succeeded, FALSE otherwise.
 *
 * The timeout argument is the number of milliseconds to wait for a
 * response. An infinite timeout can be specified as 0xffffffff.
 */
static int
ether_comarp(struct arp_packet *out, uint32_t timeout)
{
	struct arp_packet *in = (struct arp_packet *)mac_state.mac_buf;
	int count, time, feedback, len, delay = 2;
	char    *ind = "-\\|/";
	struct in_addr tmp_ia;
	uint32_t wait_time;

	bcopy((caddr_t)etherbroadcastaddr, (caddr_t)&out->arp_eh.ether_dhost,
	    sizeof (ether_addr_t));
	bcopy((caddr_t)mac_state.mac_addr_buf,
	    (caddr_t)&out->arp_eh.ether_shost, sizeof (ether_addr_t));

	out->arp_ea.arp_hrd =  htons(ARPHRD_ETHER);
	out->arp_ea.arp_pro = htons(ETHERTYPE_IP);
	out->arp_ea.arp_hln = sizeof (ether_addr_t);
	out->arp_ea.arp_pln = sizeof (struct in_addr);
	bcopy(mac_state.mac_addr_buf, (caddr_t)&out->arp_ea.arp_sha,
	    sizeof (ether_addr_t));
	ipv4_getipaddr(&tmp_ia);
	tmp_ia.s_addr = htonl(tmp_ia.s_addr);
	bcopy((caddr_t)&tmp_ia, (caddr_t)out->arp_ea.arp_spa,
	    sizeof (struct in_addr));
	feedback = 0;

	wait_time = prom_gettime() + timeout;
	for (count = 0; timeout == ~0U || prom_gettime() < wait_time; count++) {
		if (count == ETHER_WAITCNT) {
			if (out->arp_ea.arp_op == ARPOP_REQUEST) {
				bcopy((caddr_t)out->arp_ea.arp_tpa,
				    (caddr_t)&tmp_ia, sizeof (struct in_addr));
				printf(
				    "\nRequesting Ethernet address for: %s\n",
				    inet_ntoa(tmp_ia));
			} else {
				printf("\nRequesting Internet address for %s\n",
				    ether_print(out->arp_ea.arp_tha));
			}
		}

		(void) prom_write(mac_state.mac_dev, (caddr_t)out,
		    sizeof (*out), 0, NETWORK);

		if (count >= ETHER_WAITCNT)
			printf("%c\b", ind[feedback++ % 4]); /* activity */

		time = prom_gettime() + (delay * 1000);	/* broadcast delay */
		while (prom_gettime() <= time) {
			len = prom_read(mac_state.mac_dev, mac_state.mac_buf,
			    mac_state.mac_mtu, 0, NETWORK);
			if (len < USED_SIZE)
				continue;
			if (in->arp_ea.arp_pro != ntohs(ETHERTYPE_IP))
				continue;
			if (out->arp_ea.arp_op == ntohs(ARPOP_REQUEST)) {
				if (in->arp_eh.ether_type !=
				    ntohs(ETHERTYPE_ARP))
					continue;
				if (in->arp_ea.arp_op != ntohs(ARPOP_REPLY))
					continue;
				if (bcmp((caddr_t)in->arp_ea.arp_spa,
				    (caddr_t)out->arp_ea.arp_tpa,
				    sizeof (struct in_addr)) != 0)
					continue;
				if (boothowto & RB_VERBOSE) {
					bcopy((caddr_t)in->arp_ea.arp_spa,
					    (caddr_t)&tmp_ia,
					    sizeof (struct in_addr));
					printf("Found %s @ %s\n",
					    inet_ntoa(tmp_ia),
					    ether_print(in->arp_ea.arp_sha));
				}
				/* copy hardware addr into "out" for caller */
				bcopy((caddr_t)&in->arp_ea.arp_sha,
				    (caddr_t)&out->arp_ea.arp_sha,
				    sizeof (ether_addr_t));
				return (TRUE);
			} else {		/* Reverse ARP */
				if (in->arp_eh.ether_type !=
				    ntohs(ETHERTYPE_REVARP))
					continue;
				if (in->arp_ea.arp_op != ntohs(REVARP_REPLY))
					continue;
				if (bcmp((caddr_t)in->arp_ea.arp_tha,
				    (caddr_t)out->arp_ea.arp_tha,
				    sizeof (ether_addr_t)) != 0)
					continue;
				if (boothowto & RB_VERBOSE) {
					bcopy((caddr_t)in->arp_ea.arp_tpa,
					    (caddr_t)&tmp_ia,
					    sizeof (struct in_addr));
					printf("Internet address is: %s\n",
					    inet_ntoa(tmp_ia));
				}
				/* copy IP address into "out" for caller */
				bcopy((caddr_t)in->arp_ea.arp_tpa,
				    (caddr_t)out->arp_ea.arp_tpa,
				    sizeof (struct in_addr));
				return (TRUE);
			}
		}

		delay = delay * 2;	/* Double the request delay */
		if (delay > 64)		/* maximum delay is 64 seconds */
			delay = 64;
	}
	return (FALSE);
}

/*
 * ARP client side
 * Broadcasts to determine MAC address given network order IP address.
 * See RFC 826
 *
 * Returns TRUE if successful, FALSE otherwise.
 */
int
ether_arp(struct in_addr *ip, void *hap, uint32_t timeout)
{
	ether_addr_t *ep = (ether_addr_t *)hap;
	struct arp_packet out;
	int result;

	if (!initialized)
		prom_panic("Ethernet device is not initialized.");

	bzero((char *)&out, sizeof (struct arp_packet));

	out.arp_eh.ether_type = htons(ETHERTYPE_ARP);
	out.arp_ea.arp_op = htons(ARPOP_REQUEST);
	bcopy((caddr_t)etherbroadcastaddr, (caddr_t)&out.arp_ea.arp_tha,
	    sizeof (ether_addr_t));
	bcopy((caddr_t)ip, (caddr_t)out.arp_ea.arp_tpa,
	    sizeof (struct in_addr));

	result = ether_comarp(&out, timeout);

	if (result && (ep != NULL)) {
		bcopy((caddr_t)&out.arp_ea.arp_sha, (caddr_t)ep,
		    sizeof (ether_addr_t));
	}
	return (result);
}

/*
 * Reverse ARP client side
 * Determine our Internet address given our MAC address
 * See RFC 903
 */
void
ether_revarp(void)
{
	struct in_addr	ip;
	struct arp_packet out;

	if (!initialized)
		prom_panic("Ethernet device is not initialized.");

	bzero((char *)&out, sizeof (struct arp_packet));

	out.arp_eh.ether_type = htons(ETHERTYPE_REVARP);
	out.arp_ea.arp_op = htons(REVARP_REQUEST);
	bcopy(mac_state.mac_addr_buf, (caddr_t)&out.arp_ea.arp_tha,
	    sizeof (ether_addr_t));

	/* Wait forever */
	(void) ether_comarp(&out, 0xffffffff);

	bcopy((caddr_t)&out.arp_ea.arp_tpa, (caddr_t)&ip,
	    sizeof (struct in_addr));

	ip.s_addr = ntohl(ip.s_addr);
	ipv4_setipaddr(&ip);
}

/* ARGSUSED */
int
ether_header_len(struct inetgram *igm)
{
	return (sizeof (struct ether_header));
}

/*
 * Handle a IP datagram addressed to our ethernet address or to the
 * ethernet broadcast address. Also respond to ARP requests. Generates
 * inetgrams as long as there's data and the mac level IP timeout timer
 * hasn't expired. As soon as there is no data, we try for
 * ETHER_INPUT_ATTEMPTS for more, then exit the loop, even if there is time
 * left, since we expect to have data waiting for us when we're called, we just
 * don't know how much.
 *
 * We workaround slow proms (some proms have hard sleeps for as much as 3msec)
 * even though there are is data waiting.
 *
 * Returns the total number of MEDIA_LVL frames placed on the socket.
 * Caller is expected to free up the inetgram resources.
 */
int
ether_input(int index)
{
	struct inetgram		*inp;
	struct ether_header	*eh;
	int		frames = 0;	/* successful frames */
	int		attempts = 0;	/* failed attempts after success */
	int16_t		len = 0, data_len;
	uint32_t	timeout, reltime;
	uint32_t	pre_pr, post_pr; /* prom_read interval */

#ifdef	DEBUG
	int		failures = 0;		/* total failures */
	int		total_attempts = 0;	/* total prom_read */
	int		no_data = 0;		/* no data in prom */
	int		arps = 0;		/* arp requests processed */
	uint32_t	tot_pr = 0;		/* prom_read time */
	uint32_t	tot_pc = 0;		/* inetgram creation time */
	uint32_t	pre_pc;
	uint32_t	now;
#endif	/* DEBUG */

	if (!initialized)
		prom_panic("Ethernet device is not initialized.");

	if ((reltime = sockets[index].in_timeout) == 0)
		reltime = mac_state.mac_in_timeout;
	timeout = prom_gettime() + reltime;

	do {
		if (frames > ETHER_MAX_FRAMES) {
			/* someone is trying a denial of service attack */
			break;
		}

		/*
		 * The following is a workaround for a calvin prom (V2) bug
		 * where prom_read() returns a nonzero length, even when it's
		 * not read a packet. So we zero out the header to compensate.
		 */
		bzero(mac_state.mac_buf, sizeof (struct ether_header));

		/*
		 * Prom_read() will return 0 or -2 if no data is present. A
		 * return value of -1 means an error has occurred. We adjust
		 * the timeout by calling the time spent in prom_read() "free".
		 * prom_read() returns the number of bytes actually read, but
		 * will only copy "len" bytes into our buffer. Adjust in
		 * case the MTU is wrong.
		 */
		pre_pr = prom_gettime();
		len = prom_read(mac_state.mac_dev, mac_state.mac_buf,
		    mac_state.mac_mtu, 0, NETWORK);
		post_pr = prom_gettime();
		timeout += (post_pr - pre_pr);
#ifdef	DEBUG
		tot_pr += (post_pr - pre_pr);
		total_attempts++;
#endif	/* DEBUG */

		if (len > mac_state.mac_mtu) {
			dprintf("ether_input: adjusting MTU %d -> %d\n",
			    mac_state.mac_mtu, len);
			bkmem_free(mac_state.mac_buf, mac_state.mac_mtu);
			mac_state.mac_mtu = len;
			mac_state.mac_buf = bkmem_alloc(mac_state.mac_mtu);
			if (mac_state.mac_buf == NULL) {
				prom_panic("ether_input: Cannot reallocate "
				    "netbuf memory.");
			}
			len = 0; /* pretend there was no data */
		}

		if (len == -1) {
#ifdef	DEBUG
			failures++;
#endif	/* DEBUG */
			break;
		}
		if (len == 0 || len == -2) {
			if (frames != 0)
				attempts++;
#ifdef	DEBUG
			no_data++;
#endif	/* DEBUG */
			continue;
		}

		eh = (struct ether_header *)mac_state.mac_buf;
		if (eh->ether_type == ntohs(ETHERTYPE_IP) &&
		    len >= (sizeof (struct ether_header) +
		    sizeof (struct ip))) {

			int offset;
#ifdef	DEBUG
			pre_pc = prom_gettime();
#endif	/* DEBUG */

			inp = (struct inetgram *)bkmem_zalloc(
			    sizeof (struct inetgram));
			if (inp == NULL) {
				errno = ENOMEM;
				return (frames == 0 ? -1 : frames);
			}
			offset = sizeof (struct ether_header);
			data_len = len - offset;
			inp->igm_mp = allocb(data_len, 0);
			if (inp->igm_mp == NULL) {
				errno = ENOMEM;
				bkmem_free((caddr_t)inp,
				    sizeof (struct inetgram));
				return (frames == 0 ? -1 : frames);
			}
			bcopy((caddr_t)(mac_state.mac_buf + offset),
			    inp->igm_mp->b_rptr, data_len);
			inp->igm_mp->b_wptr += data_len;
			inp->igm_level = NETWORK_LVL;
			add_grams(&sockets[index].inq, inp);
			frames++;
			attempts = 0;
#ifdef	DEBUG
			tot_pc += prom_gettime() - pre_pc;
#endif	/* DEBUG */
			continue;
		}

		if (eh->ether_type == ntohs(ETHERTYPE_ARP) &&
		    len >= (sizeof (struct ether_header) +
		    sizeof (struct ether_arp))) {

			struct in_addr		ip;
			struct ether_arp	*ea;

#ifdef	DEBUG
			printf("ether_input: ARP message received\n");
			arps++;
#endif	/* DEBUG */

			ea = (struct ether_arp *)(mac_state.mac_buf +
			    sizeof (struct ether_header));
			if (ea->arp_pro != ntohs(ETHERTYPE_IP))
				continue;

			ipv4_getipaddr(&ip);
			ip.s_addr = ntohl(ip.s_addr);

			if (ea->arp_op == ntohs(ARPOP_REQUEST) &&
			    ip.s_addr != INADDR_ANY &&
			    (bcmp((caddr_t)ea->arp_tpa, (caddr_t)&ip,
			    sizeof (struct in_addr)) == 0)) {
				ea->arp_op = htons(ARPOP_REPLY);
				bcopy((caddr_t)ea->arp_sha,
				    (caddr_t)&eh->ether_dhost,
				    sizeof (ether_addr_t));
				bcopy(mac_state.mac_addr_buf,
				    (caddr_t)&eh->ether_shost,
				    mac_state.mac_addr_len);
				bcopy((caddr_t)ea->arp_sha,
				    (caddr_t)ea->arp_tha,
				    sizeof (ether_addr_t));
				bcopy((caddr_t)ea->arp_spa,
				    (caddr_t)ea->arp_tpa,
				    sizeof (struct in_addr));
				bcopy(mac_state.mac_addr_buf,
				    (caddr_t)ea->arp_sha,
				    mac_state.mac_addr_len);
				bcopy((caddr_t)&ip, (caddr_t)ea->arp_spa,
				    sizeof (struct in_addr));
				(void) prom_write(mac_state.mac_dev,
				    mac_state.mac_buf,
				    sizeof (struct arp_packet),
				    0, NETWORK);
				/* don't charge for ARP replies */
				timeout += reltime;
			}
		}
	} while (attempts < ETHER_INPUT_ATTEMPTS &&
#ifdef	DEBUG
		(now = prom_gettime()) < timeout);
#else
		prom_gettime() < timeout);
#endif	/* DEBUG */

#ifdef	DEBUG
	printf("ether_input(%d): T/S/N/A/F/P/M: %d/%d/%d/%d/%d/%d/%d "
	    "T/O: %d < %d = %s\n", index, total_attempts, frames, no_data,
	    arps, failures, tot_pr, tot_pc, now, timeout,
	    (now < timeout) ? "TRUE" : "FALSE");
#endif	/* DEBUG */
	return (frames);
}

/*
 * Send out an ethernet datagram. We expect a IP frame appropriately fragmented
 * at this level.
 *
 * Errno is set and -1 is returned if an error occurs. Number of bytes sent
 * is returned on success.
 */
/* ARGSUSED */
int
ether_output(int index, struct inetgram *ogp)
{
	int			header_len, result;
	struct ether_header	eh;
	struct ip		*ip;
	struct in_addr		tmpip, ipdst, netid;
	int			broadcast = FALSE;
	int			size;
	mblk_t			*mp;


#ifdef DEBUG
	printf("ether_output (%d): size %d\n", index,
	    ogp->igm_mp->b_wptr - ogp->igm_mp->b_rptr);
#endif
	if (!initialized)
		prom_panic("Ethernet device is not initialized.");

	if (ogp->igm_level != MEDIA_LVL) {
		dprintf("ether_output: frame type wrong: socket: %d\n",
		    index * SOCKETTYPE);
		errno = EINVAL;
		return (-1);
	}

	header_len = sizeof (struct ether_header);
	mp = ogp->igm_mp;
	size = mp->b_wptr - mp->b_rptr;
	if (size > mac_state.mac_mtu) {
		dprintf("ether_output: frame size too big: %d\n", size);
		errno = E2BIG;
		return (-1);
	}

	size += header_len;
	ip = (struct ip *)(mp->b_rptr);

	eh.ether_type = htons(ETHERTYPE_IP);
	bcopy(mac_state.mac_addr_buf, (caddr_t)&eh.ether_shost,
	    mac_state.mac_addr_len);
	bcopy((caddr_t)&ip->ip_dst, (caddr_t)&ipdst, sizeof (ipdst));

	if (ipdst.s_addr == htonl(INADDR_BROADCAST))
		broadcast = TRUE; /* limited broadcast */

	if (!broadcast) {
		struct in_addr mask;

		ipv4_getnetid(&netid);
		ipv4_getnetmask(&mask);
		mask.s_addr = htonl(mask.s_addr);
		netid.s_addr = htonl(netid.s_addr);

		/*
		 * check for all-hosts directed broadcast for
		 * to its own subnet.
		 */
		if (mask.s_addr != htonl(INADDR_BROADCAST) &&
		    (ipdst.s_addr & ~mask.s_addr) == 0 &&
		    (ipdst.s_addr & mask.s_addr) ==  netid.s_addr) {
			broadcast = TRUE; /* directed broadcast */
		} else {
			if (ogp->igm_router.s_addr != htonl(INADDR_ANY))
				tmpip.s_addr = ogp->igm_router.s_addr;
			else
				tmpip.s_addr = ipdst.s_addr;

			result = mac_get_arp(&tmpip, (void *)&eh.ether_dhost,
			    sizeof (ether_addr_t), mac_state.mac_arp_timeout);
			if (!result) {
				errno = ETIMEDOUT;
				dprintf("ether_output: ARP request for %s "
				    "timed out.\n", inet_ntoa(tmpip));
				return (-1);
			}
		}
	}

	if (broadcast) {
		bcopy((caddr_t)etherbroadcastaddr,
		    (caddr_t)&eh.ether_dhost, sizeof (ether_addr_t));
	}

	/* add the ethernet header */
	mp->b_rptr -= sizeof (eh);
	bcopy((caddr_t)&eh, mp->b_rptr, sizeof (eh));
#ifdef	DEBUG
	printf("ether_output(%d): level(%d) frame(0x%x) len(%d)\n",
	    index, ogp->igm_level, mp->b_rptr, size);
#if DEBUG > 1
	printf("Dump ethernet (%d): \n", size);
	hexdump((char *)mp->b_rptr, size);
	printf("\n");
#endif /* DEBUG > 1 */
#endif	/* DEBUG */
	return (prom_write(mac_state.mac_dev, (char *)mp->b_rptr, size,
	    0, NETWORK));
}
