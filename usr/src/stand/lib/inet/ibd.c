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

#include <dhcp_impl.h>
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
#include <sys/ib/clients/ibd/ibd.h>

#include "ipv4.h"
#include "dhcpv4.h"
#include "ipv4_impl.h"
#include "mac.h"
#include "mac_impl.h"
#include "ibd_inet.h"

struct ibd_arp {
	struct arphdr	ea_hdr;		/* fixed-size header */
	ipoib_mac_t	arp_sha;	/* sender hardware address */
	uchar_t		arp_spa[4];	/* sender protocol address */
	ipoib_mac_t	arp_tha;	/* target hardware address */
	uchar_t		arp_tpa[4];	/* target protocol address */
};

extern int errno;
ipoib_mac_t ibdbroadcastaddr;

/*
 * Assumptions about OBP behavior (refer FWARC 2002/702, 2003/251):
 * 1. prom_write() accepts the 20 byte destination address as the
 * first component in the send buffer. The buffer pointer points
 * to the start of this 20 byte address. The length parameter is
 * the IPoIB datagram size with the 20 byte of destination
 * address.
 * 2. OBP will not provide max-frame-size, since obp can only
 * determine that by querying the IBA mcg, and thus the property
 * has to be /chosen:ipib-frame-size. This will refer to the IPoIB
 * link MTU as per section 4.0 of ietf i/d, ie, the 4 byte IPoIB
 * header plus the IP payload mtu. Plus the 20 bytes of addressing
 * information.
 * 3. OBP will not provide mac-address property for IPoIB since there
 * are built in assumptions about 6 byte address with that. Instead,
 * /chosen:ipib-address will provide the local address.
 * 4. prom_read() returns 20 byte 0'ed filler followed by 4 byte
 * IPoIB header followed by IP payload. The return value is -2,
 * -1, 0, or the length of the received IPoIB datagram alongwith
 * the 20 bytes MBZ. The buffer pointer points to the start of
 * the 20 MBZ bytes. The length parameter reflects the max data
 * size that should be copied into the buffer including the 20
 * MBZ bytes.
 * 5. OBP will not provide chosen-network-type, only
 * network-interface-type = ipib. On an Infiniband device, this
 * however does not guarantee that it is a network device.
 * 6. OBP will provide the DHCP client id in /chosen:client-id.
 * 7. /chosen:ipib-broadcast will provide the broadcast address.
 * 8. OBP will validate that RARP is not being used before
 * allowing boot to proceed to inetboot.
 */

struct arp_packet {
	ipoib_ptxhdr_t		arp_eh;
	struct ibd_arp		arp_ea;
};

#define	dprintf	if (boothowto & RB_DEBUG) printf

static char *
ibd_print(ipoib_mac_t *ea)
{
	unsigned char *macaddr = (unsigned char *)ea;
	static char pbuf[(3 * IPOIB_ADDRL) + 1];
	int i;
	char *ptr = pbuf;

	ptr = pbuf + sprintf(pbuf, "%x", *macaddr++);
	for (i = 0; i < (IPOIB_ADDRL - 1); i++)
		ptr += sprintf(ptr, ":%x", *macaddr++);
	return (pbuf);
}


/*
 * Common ARP code. Broadcast the packet and wait for the right response.
 *
 * If arp is called for, caller expects a hardware address in the
 * source hardware address (sha) field of the "out" argument.
 *
 * IPoIB does not support RARP (see ibd_revarp()).
 *
 * Returns TRUE if transaction succeeded, FALSE otherwise.
 *
 * The timeout argument is the number of milliseconds to wait for a
 * response. An infinite timeout can be specified as 0xffffffff.
 */
static int
ibd_comarp(struct arp_packet *out, uint32_t timeout)
{
	struct arp_packet *in = (struct arp_packet *)mac_state.mac_buf;
	int count, time, feedback, len, delay = 2;
	char    *ind = "-\\|/";
	struct in_addr tmp_ia;
	uint32_t wait_time;

	bcopy((caddr_t)&ibdbroadcastaddr, (caddr_t)&out->arp_eh.ipoib_dest,
	    IPOIB_ADDRL);

	out->arp_ea.arp_hrd =  htons(ARPHRD_IB);
	out->arp_ea.arp_pro = htons(ETHERTYPE_IP);
	out->arp_ea.arp_hln = IPOIB_ADDRL;
	out->arp_ea.arp_pln = sizeof (struct in_addr);
	bcopy(mac_state.mac_addr_buf, (caddr_t)&out->arp_ea.arp_sha,
	    IPOIB_ADDRL);
	ipv4_getipaddr(&tmp_ia);
	tmp_ia.s_addr = htonl(tmp_ia.s_addr);
	bcopy((caddr_t)&tmp_ia, (caddr_t)out->arp_ea.arp_spa,
	    sizeof (struct in_addr));
	feedback = 0;

	wait_time = prom_gettime() + timeout;
	for (count = 0; timeout == ~0U || prom_gettime() < wait_time; count++) {
		if (count == IBD_WAITCNT) {
			/*
			 * Since IPoIB does not support RARP (see ibd_revarp),
			 * we know that out->arp_ea.arp_op == ARPOP_REQUEST.
			 */
			bcopy((caddr_t)out->arp_ea.arp_tpa,
			    (caddr_t)&tmp_ia, sizeof (struct in_addr));
			printf("\nRequesting MAC address for: %s\n",
			    inet_ntoa(tmp_ia));
		}

		(void) prom_write(mac_state.mac_dev, (caddr_t)out,
		    sizeof (*out), 0, NETWORK);

		if (count >= IBD_WAITCNT)
			printf("%c\b", ind[feedback++ % 4]); /* activity */

		time = prom_gettime() + (delay * 1000);	/* broadcast delay */
		while (prom_gettime() <= time) {
			len = prom_read(mac_state.mac_dev, mac_state.mac_buf,
			    mac_state.mac_mtu, 0, NETWORK);
			if (len < sizeof (struct arp_packet))
				continue;
			if (in->arp_ea.arp_pro != ntohs(ETHERTYPE_IP))
				continue;
			/*
			 * Since IPoIB does not support RARP (see ibd_revarp),
			 * we know that out->arp_ea.arp_op == ARPOP_REQUEST.
			 */
			if (in->arp_eh.ipoib_rhdr.ipoib_type !=
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
				    ibd_print(&in->arp_ea.arp_sha));
			}
			/* copy hardware addr into "out" for caller */
			bcopy((caddr_t)&in->arp_ea.arp_sha,
			    (caddr_t)&out->arp_ea.arp_sha, IPOIB_ADDRL);
			return (TRUE);
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
static int
ibd_arp(struct in_addr *ip, void *hap, uint32_t timeout)
{
	ipoib_mac_t *ep = (ipoib_mac_t *)hap;
	struct arp_packet out;
	int result;

	if (!initialized)
		prom_panic("IPoIB device is not initialized.");

	bzero((char *)&out, sizeof (struct arp_packet));

	out.arp_eh.ipoib_rhdr.ipoib_type = htons(ETHERTYPE_ARP);
	out.arp_ea.arp_op = htons(ARPOP_REQUEST);
	bcopy((caddr_t)&ibdbroadcastaddr, (caddr_t)&out.arp_ea.arp_tha,
	    IPOIB_ADDRL);
	bcopy((caddr_t)ip, (caddr_t)out.arp_ea.arp_tpa,
	    sizeof (struct in_addr));

	result = ibd_comarp(&out, timeout);

	if (result && (ep != NULL)) {
		bcopy((caddr_t)&out.arp_ea.arp_sha, (caddr_t)ep, IPOIB_ADDRL);
	}
	return (result);
}

/*
 * Reverse ARP client side
 * Determine our Internet address given our MAC address
 * See RFC 903
 */
static void
ibd_revarp(void)
{
	prom_panic("IPoIB can not boot with RARP.");
}

/* ARGSUSED */
static int
ibd_header_len(struct inetgram *igm)
{
	/*
	 * We indicate to upper layers to leave enough space
	 * in output buffers for filling in the IPoIB header
	 * and the 20 byte destination address in ibd_output().
	 */
	return (IPOIB_HDRSIZE + IPOIB_ADDRL);
}

/*
 * Handle a IP datagram addressed to our MAC address or to the link
 * layer broadcast address. Also respond to ARP requests. Generates
 * inetgrams as long as there's data and the mac level IP timeout timer
 * hasn't expired. As soon as there is no data, we try for
 * IBD_INPUT_ATTEMPTS for more, then exit the loop, even if there is time
 * left, since we expect to have data waiting for us when we're called, we just
 * don't know how much.
 *
 * We workaround slow proms (some proms have hard sleeps for as much as 3msec)
 * even though there are is data waiting.
 *
 * Returns the total number of MEDIA_LVL frames placed on the socket.
 * Caller is expected to free up the inetgram resources.
 */
static int
ibd_input(int index)
{
	struct inetgram		*inp;
	ipoib_ptxhdr_t		*eh;
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
		prom_panic("IPoIB device is not initialized.");

	if ((reltime = sockets[index].in_timeout) == 0)
		reltime = mac_state.mac_in_timeout;
	timeout = prom_gettime() + reltime;

	do {
		if (frames > IBD_MAX_FRAMES) {
			/* someone is trying a denial of service attack */
			break;
		}

		/*
		 * The following is being paranoid about possible bugs
		 * where prom_read() returns a nonzero length, even when
		 * it's not read a packet; it zeroes out the header to
		 * compensate. Paranoia from calvin prom (V2) days.
		 */
		bzero(mac_state.mac_buf, sizeof (ipoib_ptxhdr_t));

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
			dprintf("ibd_input: adjusting MTU %d -> %d\n",
			    mac_state.mac_mtu, len);
			bkmem_free(mac_state.mac_buf, mac_state.mac_mtu);
			mac_state.mac_mtu = len;
			mac_state.mac_buf = bkmem_alloc(mac_state.mac_mtu);
			if (mac_state.mac_buf == NULL) {
				prom_panic("ibd_input: Cannot reallocate "
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

		eh = (ipoib_ptxhdr_t *)mac_state.mac_buf;
		if (eh->ipoib_rhdr.ipoib_type == ntohs(ETHERTYPE_IP) &&
		    len >= (sizeof (ipoib_ptxhdr_t) + sizeof (struct ip))) {

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
			offset = sizeof (ipoib_ptxhdr_t);
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

		if (eh->ipoib_rhdr.ipoib_type == ntohs(ETHERTYPE_ARP) &&
		    len >= sizeof (struct arp_packet)) {

			struct in_addr		ip;
			struct ibd_arp		*ea;

#ifdef	DEBUG
			printf("ibd_input: ARP message received\n");
			arps++;
#endif	/* DEBUG */

			ea = (struct ibd_arp *)(mac_state.mac_buf +
			    sizeof (ipoib_ptxhdr_t));
			if (ea->arp_pro != ntohs(ETHERTYPE_IP))
				continue;

			ipv4_getipaddr(&ip);
			ip.s_addr = ntohl(ip.s_addr);

			if (ea->arp_op == ntohs(ARPOP_REQUEST) &&
			    ip.s_addr != INADDR_ANY &&
			    (bcmp((caddr_t)ea->arp_tpa, (caddr_t)&ip,
			    sizeof (struct in_addr)) == 0)) {
				ea->arp_op = htons(ARPOP_REPLY);
				bcopy((caddr_t)&ea->arp_sha,
				    (caddr_t)&eh->ipoib_dest, IPOIB_ADDRL);
				bcopy((caddr_t)&ea->arp_sha,
				    (caddr_t)&ea->arp_tha, IPOIB_ADDRL);
				bcopy((caddr_t)ea->arp_spa,
				    (caddr_t)ea->arp_tpa,
				    sizeof (struct in_addr));
				bcopy(mac_state.mac_addr_buf,
				    (caddr_t)&ea->arp_sha,
				    mac_state.mac_addr_len);
				bcopy((caddr_t)&ip, (caddr_t)ea->arp_spa,
				    sizeof (struct in_addr));
				(void) prom_write(mac_state.mac_dev,
				    mac_state.mac_buf,
				    sizeof (struct arp_packet), 0, NETWORK);
				/* don't charge for ARP replies */
				timeout += reltime;
			}
		}
	} while (attempts < IBD_INPUT_ATTEMPTS &&
#ifdef	DEBUG
	    (now = prom_gettime()) < timeout);
#else
	    prom_gettime() < timeout);
#endif	/* DEBUG */

#ifdef	DEBUG
	printf("ibd_input(%d): T/S/N/A/F/P/M: %d/%d/%d/%d/%d/%d/%d "
	    "T/O: %d < %d = %s\n", index, total_attempts, frames, no_data,
	    arps, failures, tot_pr, tot_pc, now, timeout,
	    (now < timeout) ? "TRUE" : "FALSE");
#endif	/* DEBUG */
	return (frames);
}

/*
 * Send out an IPoIB datagram. We expect a IP frame appropriately fragmented
 * at this level.
 *
 * Errno is set and -1 is returned if an error occurs. Number of bytes sent
 * is returned on success.
 */
/* ARGSUSED */
static int
ibd_output(int index, struct inetgram *ogp)
{
	int			header_len, result;
	ipoib_ptxhdr_t		eh;
	struct ip		*ip;
	struct in_addr		tmpip, ipdst;
	int			broadcast = FALSE;
	int			size;
	mblk_t			*mp;

	if (!initialized)
		prom_panic("IPoIB device is not initialized.");

	if (ogp->igm_level != MEDIA_LVL) {
		dprintf("ibd_output: frame type wrong: socket: %d\n",
		    index * SOCKETTYPE);
		errno = EINVAL;
		return (-1);
	}

	header_len = IPOIB_HDRSIZE + IPOIB_ADDRL;
	mp = ogp->igm_mp;
	size = mp->b_wptr - mp->b_rptr;
	if (size > (mac_state.mac_mtu - IPOIB_ADDRL)) {
		dprintf("ibd_output: frame size too big: %d\n", size);
		errno = E2BIG;
		return (-1);
	}

	size += header_len;
	ip = (struct ip *)(mp->b_rptr);

	eh.ipoib_rhdr.ipoib_type = htons(ETHERTYPE_IP);
	eh.ipoib_rhdr.ipoib_mbz = 0;
	bcopy((caddr_t)&ip->ip_dst, (caddr_t)&ipdst, sizeof (ipdst));

	if (ipdst.s_addr == htonl(INADDR_BROADCAST))
		broadcast = TRUE; /* limited broadcast */

	if (!broadcast) {
		struct in_addr mask;

		ipv4_getnetmask(&mask);
		mask.s_addr = htonl(mask.s_addr);
		if (mask.s_addr != htonl(INADDR_BROADCAST) &&
		    (ipdst.s_addr & ~mask.s_addr) == 0) {
			broadcast = TRUE; /* directed broadcast */
		} else {
			if (ogp->igm_router.s_addr != htonl(INADDR_ANY))
				tmpip.s_addr = ogp->igm_router.s_addr;
			else
				tmpip.s_addr = ipdst.s_addr;

			result = mac_get_arp(&tmpip, (void *)&eh.ipoib_dest,
			    IPOIB_ADDRL, mac_state.mac_arp_timeout);
			if (!result) {
				errno = ETIMEDOUT;
				dprintf("ibd_output: ARP request for %s "
				    "timed out.\n", inet_ntoa(tmpip));
				return (-1);
			}
		}
	}

	if (broadcast)
		bcopy((caddr_t)&ibdbroadcastaddr, (caddr_t)&eh.ipoib_dest,
		    IPOIB_ADDRL);

	/* add the ibd header */
	mp->b_rptr -= sizeof (eh);
	bcopy((caddr_t)&eh, mp->b_rptr, sizeof (eh));

#ifdef	DEBUG
	printf("ibd_output(%d): level(%d) frame(0x%x) len(%d)\n",
	    index, ogp->igm_level, mp->b_rptr, size);
#endif	/* DEBUG */

	return (prom_write(mac_state.mac_dev, (char *)mp->b_rptr, size,
	    0, NETWORK));
}

void
ibd_init(void)
{
	pnode_t	chosen;
	char	*mtuprop = "ipib-frame-size";
	char	*bcastprop = "ipib-broadcast";
	char	*addrprop = "ipib-address";
	char	*cidprop = "client-id";
	int	cidlen;
	uint8_t	dhcpcid[DHCP_MAX_CID_LEN];

	mac_state.mac_addr_len = IPOIB_ADDRL;
	mac_state.mac_addr_buf = bkmem_alloc(mac_state.mac_addr_len);
	if (mac_state.mac_addr_buf == NULL)
		prom_panic("ibd_init: Cannot allocate memory.");

	chosen = prom_finddevice("/chosen");
	if (chosen == OBP_NONODE || chosen == OBP_BADNODE)
		prom_panic("ibd_init: Cannot find /chosen.");

	if (prom_getprop(chosen, addrprop, (caddr_t)mac_state.mac_addr_buf) !=
	    IPOIB_ADDRL)
		prom_panic("ibd_init: Cannot find /chosen:ipib-address\n.");

	if (prom_getprop(chosen, bcastprop, (caddr_t)&ibdbroadcastaddr) !=
	    IPOIB_ADDRL)
		prom_panic("ibd_init: Cannot find /chosen:ipib-broadcast\n.");

	if (((cidlen = prom_getproplen(chosen, cidprop)) <= 0) ||
	    (cidlen > DHCP_MAX_CID_LEN) || (prom_getprop(chosen, cidprop,
	    (caddr_t)&dhcpcid) != cidlen))
		prom_panic("ibd_init: Invalid /chosen:client-id\n.");
	dhcp_set_client_id(dhcpcid, cidlen);

	/*
	 * Note that prom reports mtu including 20 bytes of
	 * addressing information.
	 */
	if (prom_getprop(chosen, mtuprop,
	    (caddr_t)&mac_state.mac_mtu) <= 0)
		mac_state.mac_mtu = IBDSIZE + IPOIB_ADDRL;

	/*
	 * Tell upper layers that we can support a little
	 * more. We will be taking off these 20 bytes at
	 * the start before we invoke prom_write() to send
	 * over the wire.
	 */
	mac_state.mac_arp_timeout = IBD_ARP_TIMEOUT;
	mac_state.mac_in_timeout = IBD_IN_TIMEOUT;

	mac_state.mac_arp = ibd_arp;
	mac_state.mac_rarp = ibd_revarp;
	mac_state.mac_header_len = ibd_header_len;
	mac_state.mac_input = ibd_input;
	mac_state.mac_output = ibd_output;
}
