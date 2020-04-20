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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ipv4.c, Code implementing the IPv4 internet protocol.
 */

#include <sys/types.h>
#include <socket_impl.h>
#include <socket_inet.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/fcntl.h>
#include <sys/salib.h>

#include "icmp4.h"
#include "ipv4.h"
#include "ipv4_impl.h"
#include "mac.h"
#include "mac_impl.h"
#include "v4_sum_impl.h"
#include <sys/bootdebug.h>

static struct ip_frag	fragment[FRAG_MAX];	/* ip fragment buffers */
static int		fragments;		/* Number of fragments */
static uint8_t		ttl = MAXTTL;		/* IP ttl */
static struct in_addr	myip;			/* our network-order IP addr */
static struct in_addr	mynet;			/* net-order netaddr */
static struct in_addr	netmask =
	{ 0xff, 0xff, 0xff, 0xff };		/* our network-order netmask */
static boolean_t	netmask_set = B_FALSE;	/* has anyone set netmask? */
static struct in_addr	defaultrouter;		/* net-order defaultrouter */
static int		promiscuous;		/* promiscuous mode */
static struct routing table[IPV4_ROUTE_TABLE_SIZE];

static uint16_t	g_ip_id;

#ifdef	DEBUG
#define	FRAG_DEBUG
#endif	/* DEBUG */

#ifdef FRAG_DEBUG
/*
 * display the fragment list. For debugging purposes.
 */
static void
frag_disp(uint16_t size)
{
	int	i;
	uint_t	total = 0;

	printf("Dumping fragment info: (%d)\n\n", fragments);
	printf("More:\tOffset:\tDatap:\t\tIPid:\t\tIPlen:\tIPhlen:\n");
	for (i = 0; i < FRAG_MAX; i++) {
		if (fragment[i].mp == NULL)
			continue;
		printf("%d\t%d\t0x%x\t%d\t\t%d\t%d\n", fragment[i].more,
		    fragment[i].offset, fragment[i].mp->b_rptr,
		    fragment[i].ipid, fragment[i].iplen, fragment[i].iphlen);
		total += (fragment[i].iplen - fragment[i].iphlen);
	}
	printf("Total length is: %d. It should be: %d\n\n", total, size);
}
#endif /* FRAG_DEBUG */

/*
 * This function returns index of fragment 0 of the current fragmented DGRAM
 * (which would contain the transport header). Return the fragment number
 * for success, -1 if we don't yet have the first fragment.
 */
static int
frag_first(void)
{
	int		i;

	if (fragments == 0)
		return (-1);

	for (i = 0; i < FRAG_MAX; i++) {
		if (fragment[i].mp != NULL && fragment[i].offset == 0)
			return (i);
	}
	return (-1);
}

/*
 * This function returns index of the last fragment of the current DGRAM.
 * Returns the fragment number for success, -1 if we don't yet have the
 * last fragment.
 */
static int
frag_last(void)
{
	int		i;

	if (fragments == 0)
		return (-1);

	for (i = 0; i < FRAG_MAX; i++) {
		if (fragment[i].mp != NULL && !fragment[i].more)
			return (i);
	}
	return (-1);
}

/*
 * This function adds a fragment to the current pkt fragment list. Returns
 * FRAG_NOSLOTS if there are no more slots, FRAG_DUP if the fragment is
 * a duplicate, or FRAG_SUCCESS if it is successful.
 */
static int
frag_add(int16_t offset, mblk_t *mp, uint16_t ipid,
    int16_t iplen, int16_t iphlen, uint8_t ipp)
{
	int	i;
	int16_t	true_offset = IPV4_OFFSET(offset);

	/* first pass - look for duplicates */
	for (i = 0; i < FRAG_MAX; i++) {
		if (fragment[i].mp != NULL &&
		    fragment[i].offset == true_offset)
			return (FRAG_DUP);
	}

	/* second pass - fill in empty slot */
	for (i = 0; i < FRAG_MAX; i++) {
		if (fragment[i].mp == NULL) {
			fragment[i].more = (offset & IP_MF);
			fragment[i].offset = true_offset;
			fragment[i].mp = mp;
			fragment[i].ipid = ipid;
			fragment[i].iplen = iplen;
			fragment[i].iphlen = iphlen;
			fragment[i].ipp = ipp;
			fragments++;
			return (FRAG_SUCCESS);
		}
	}
	return (FRAG_NOSLOTS);
}

/*
 * Nuke a fragment.
 */
static void
frag_free(int index)
{
	if (fragment[index].mp != NULL) {
		freeb(fragment[index].mp);
		fragments--;
	}
	bzero((caddr_t)&fragment[index], sizeof (struct ip_frag));
}

/*
 * zero the frag list.
 */
static void
frag_flush(void)
{
	int i;

	for (i = 0; i < FRAG_MAX; i++)
		frag_free(i);

	fragments = 0;
}

/*
 * Analyze the fragment list - see if we captured all our fragments.
 *
 * Returns TRUE if we've got all the fragments, and FALSE if we don't.
 */
static int
frag_chk(void)
{
	int		i, first_frag, last_frag;
	int16_t		actual, total;
	uint16_t	ip_id;
	uint8_t		ipp;

	if (fragments == 0 || (first_frag = frag_first()) < 0 ||
	    (last_frag = frag_last()) < 0)
		return (FALSE);

	/*
	 * Validate the ipid's of our fragments - nuke those that don't
	 * match the id of the first fragment or don't match the IP
	 * protocol of the first fragment.
	 */
	ip_id = fragment[first_frag].ipid;
	ipp = fragment[first_frag].ipp;
	for (i = 0; i < FRAG_MAX; i++) {
		if (fragment[i].mp != NULL && ip_id != fragment[i].ipid &&
			fragment[i].ipp != ipp) {
#ifdef FRAG_DEBUG
			printf("ipv4: Frag id mismatch: %x != %x\n",
			    fragment[i].ipid, ip_id);
#endif /* FRAG_DEBUG */
			frag_free(i);
		}
	}

	if (frag_last() < 0)
		return (FALSE);

	total = fragment[last_frag].offset + fragment[last_frag].iplen -
	    fragment[last_frag].iphlen;

	for (i = 0, actual = 0; i < FRAG_MAX; i++)
		actual += (fragment[i].iplen - fragment[i].iphlen);

#ifdef FRAG_DEBUG
	frag_disp(total);
#endif /* FRAG_DEBUG */

	return (total == actual);
}

/*
 * Load the assembled fragments into igp. Returns 0 for success, nonzero
 * otherwise.
 */
static int
frag_load(struct inetgram *igp)
{
	int	i;
	int16_t	len;
	uint_t	total_len;
	boolean_t first_frag = B_FALSE;
	mblk_t *mp;
	struct ip *iph;
	int first_iph_len;

	if (fragments == 0)
		return (ENOENT);

	mp = igp->igm_mp;
	/* Get the IP header length of the first fragment. */
	i = frag_first();
	assert(i >= 0);
	first_iph_len = fragment[i].iphlen;
	for (i = 0, len = 0, total_len = 0; i < FRAG_MAX; i++) {
		if (fragment[i].mp != NULL) {
			/*
			 * Copy just the data (omit the ip header of all
			 * fragments except the first one which contains
			 * all the info...)
			 */
			if (fragment[i].offset == 0) {
				len = fragment[i].iplen;
				first_frag = B_TRUE;
			} else {
				len = fragment[i].iplen - fragment[i].iphlen;
			}
			total_len += len;
			if (total_len > mp->b_size)
				return (E2BIG);
			if (first_frag) {
				bcopy((caddr_t)(fragment[i].mp->b_rptr),
				    (caddr_t)mp->b_rptr, len);
				first_frag = B_FALSE;
			} else {
				bcopy((caddr_t)(fragment[i].mp->b_rptr +
				    fragment[i].iphlen),
				    (caddr_t)(mp->b_rptr + first_iph_len +
				    fragment[i].offset), len);
			}
			mp->b_wptr += len;
		}
	}
	/* Fix the total length in the IP header. */
	iph = (struct ip *)mp->b_rptr;
	iph->ip_len = htons(total_len);
	return (0);
}

/*
 * Locate a routing table entry based upon arguments. IP addresses expected
 * in network order. Returns index for success, -1 if entry not found.
 */
static int
find_route(uint8_t *flagp, struct in_addr *destp, struct in_addr *gatewayp)
{
	int i, table_entry = -1;

	for (i = 0; table_entry == -1 && i < IPV4_ROUTE_TABLE_SIZE; i++) {
		if (flagp != NULL) {
			if (*flagp & table[i].flag)
				table_entry = i;
		}
		if (destp != NULL) {
			if (destp->s_addr == table[i].dest.s_addr)
				table_entry = i;
			else
				table_entry = -1;
		}
		if (gatewayp != NULL) {
			if (gatewayp->s_addr == table[i].gateway.s_addr)
				table_entry = i;
			else
				table_entry = -1;
		}
	}
	return (table_entry);
}

/*
 * ADD or DEL a routing table entry. Returns 0 for success, -1 and errno
 * otherwise. IP addresses are expected in network order.
 */
int
ipv4_route(int cmd, uint8_t flag, struct in_addr *destp,
    struct in_addr *gatewayp)
{
	static	int	routing_table_initialized;
	int		index;
	uint8_t 	tmp_flag;

	if (gatewayp == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* initialize routing table */
	if (routing_table_initialized == 0) {
		for (index = 0; index < IPV4_ROUTE_TABLE_SIZE; index++)
			table[index].flag = RT_UNUSED;
		routing_table_initialized = 1;
	}

	switch (cmd) {
	case IPV4_ADD_ROUTE:
		tmp_flag = (uint8_t)RT_UNUSED;
		if ((index = find_route(&tmp_flag, NULL, NULL)) == -1) {
			dprintf("ipv4_route: routing table full.\n");
			errno = ENOSPC;
			return (-1);
		}
		table[index].flag = flag;
		if (destp != NULL)
			table[index].dest.s_addr = destp->s_addr;
		else
			table[index].dest.s_addr = htonl(INADDR_ANY);
		table[index].gateway.s_addr = gatewayp->s_addr;
		break;
	case IPV4_BAD_ROUTE:
		/* FALLTHRU */
	case IPV4_DEL_ROUTE:
		if ((index = find_route(&flag, destp, gatewayp)) == -1) {
			dprintf("ipv4_route: No such routing entry.\n");
			errno = ENOENT;
			return (-1);
		}
		if (cmd == IPV4_DEL_ROUTE) {
			table[index].flag = RT_UNUSED;
			table[index].dest.s_addr = htonl(INADDR_ANY);
			table[index].gateway.s_addr = htonl(INADDR_ANY);
		} else
			table[index].flag = RT_NG;
	default:
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

/*
 * Return gateway to destination. Returns gateway IP address in network order
 * for success, NULL if no route to destination exists.
 */
struct in_addr *
ipv4_get_route(uint8_t flag, struct in_addr *destp, struct in_addr *gatewayp)
{
	int index;
	if ((index = find_route(&flag, destp, gatewayp)) == -1)
		return (NULL);
	return (&table[index].gateway);
}

/*
 * Initialize the IPv4 generic parts of the socket, as well as the routing
 * table.
 */
void
ipv4_socket_init(struct inetboot_socket *isp)
{
	isp->input[NETWORK_LVL] = ipv4_input;
	isp->output[NETWORK_LVL] = ipv4_output;
	isp->close[NETWORK_LVL] = NULL;
	isp->headerlen[NETWORK_LVL] = ipv4_header_len;
}

/*
 * Initialize a raw ipv4 socket.
 */
void
ipv4_raw_socket(struct inetboot_socket *isp, uint8_t proto)
{
	isp->type = INETBOOT_RAW;
	if (proto == 0)
		isp->proto = IPPROTO_IP;
	else
		isp->proto = proto;
	isp->input[TRANSPORT_LVL] = NULL;
	isp->output[TRANSPORT_LVL] = NULL;
	isp->headerlen[TRANSPORT_LVL] = NULL;
	isp->ports = NULL;
}

/*
 * Return the size of an IPv4 header (no options)
 */
/* ARGSUSED */
int
ipv4_header_len(struct inetgram *igm)
{
	return (sizeof (struct ip));
}

/*
 * Set our source address.
 * Argument is assumed to be host order.
 */
void
ipv4_setipaddr(struct in_addr *ip)
{
	myip.s_addr = htonl(ip->s_addr);
}

/*
 * Returns our current source address in host order.
 */
void
ipv4_getipaddr(struct in_addr *ip)
{
	ip->s_addr = ntohl(myip.s_addr);
}

/*
 * Set our netmask.
 * Argument is assumed to be host order.
 */
void
ipv4_setnetmask(struct in_addr *ip)
{
	netmask_set = B_TRUE;
	netmask.s_addr = htonl(ip->s_addr);
	mynet.s_addr = netmask.s_addr & myip.s_addr; /* implicit */
}

void
ipv4_getnetid(struct in_addr *my_netid)
{
	struct in_addr my_netmask;
	if (mynet.s_addr != 0)
		my_netid->s_addr = ntohl(mynet.s_addr);
	else {
		ipv4_getnetmask(&my_netmask);
		my_netid->s_addr = my_netmask.s_addr & ntohl(myip.s_addr);
	}
}

/*
 * Returns our current netmask in host order.
 * Neither OBP nor the standalone DHCP client mandate
 * that the netmask be specified, so in the absence of
 * a netmask, we attempt to derive it using class-based
 * heuristics.
 */
void
ipv4_getnetmask(struct in_addr *ip)
{
	if (netmask_set || (myip.s_addr == 0))
		ip->s_addr = ntohl(netmask.s_addr);
	else {
		/* base the netmask on our IP address */
		if (IN_CLASSA(ntohl(myip.s_addr)))
			ip->s_addr = ntohl(IN_CLASSA_NET);
		else if (IN_CLASSB(ntohl(myip.s_addr)))
			ip->s_addr = ntohl(IN_CLASSB_NET);
		else if (IN_CLASSC(ntohl(myip.s_addr)))
			ip->s_addr = ntohl(IN_CLASSC_NET);
		else
			ip->s_addr = ntohl(IN_CLASSE_NET);
	}
}

/*
 * Set our default router.
 * Argument is assumed to be host order, and *MUST* be on the same network
 * as our source IP address.
 */
void
ipv4_setdefaultrouter(struct in_addr *ip)
{
	defaultrouter.s_addr = htonl(ip->s_addr);
}

/*
 * Returns our current default router in host order.
 */
void
ipv4_getdefaultrouter(struct in_addr *ip)
{
	ip->s_addr = ntohl(defaultrouter.s_addr);
}

/*
 * Toggle promiscuous flag. If set, client disregards destination IP
 * address. Otherwise, only limited broadcast, network broadcast, and
 * unicast traffic get through. Returns previous setting.
 */
int
ipv4_setpromiscuous(int toggle)
{
	int old = promiscuous;

	promiscuous = toggle;

	return (old);
}

/*
 * Set IP TTL.
 */
void
ipv4_setmaxttl(uint8_t cttl)
{
	ttl = cttl;
}

/*
 * Convert an ipv4 address to dotted notation.
 * Returns ptr to statically allocated buffer containing dotted string.
 */
char *
inet_ntoa(struct in_addr ip)
{
	uint8_t *p;
	static char ipaddr[16];

	p = (uint8_t *)&ip.s_addr;
	(void) sprintf(ipaddr, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
	return (ipaddr);
}

/*
 * Construct a transport datagram from a series of IP fragments (igp == NULL)
 * or from a single IP datagram (igp != NULL). Return the address of the
 * contructed transport datagram.
 */
struct inetgram *
make_trans_datagram(int index, struct inetgram *igp, struct in_addr ipsrc,
    struct in_addr ipdst, uint16_t iphlen)
{
	uint16_t	trans_len, *transp, new_len;
	int		first_frag, last_frag;
	boolean_t	fragmented;
	struct inetgram	*ngp;
	struct ip	*iph;

	fragmented = (igp == NULL);

	ngp = (struct inetgram *)bkmem_zalloc(sizeof (struct inetgram));
	if (ngp == NULL) {
		errno = ENOMEM;
		if (fragmented)
			frag_flush();
		return (NULL);
	}

	if (fragmented) {
		last_frag = frag_last();
		trans_len = fragment[last_frag].offset +
		    fragment[last_frag].iplen - fragment[last_frag].iphlen;
		first_frag = frag_first();
		/*
		 * The returned buffer contains the IP header of the
		 * first fragment.
		 */
		trans_len += fragment[first_frag].iphlen;
		transp = (uint16_t *)(fragment[first_frag].mp->b_rptr +
		    fragment[first_frag].iphlen);
	} else {
		/*
		 * Note that igm_len may not be the real length of an
		 * IP packet because some network interface, such as
		 * Ethernet, as a minimum frame size.  So we should not
		 * use the interface frame size to determine the
		 * length of an IP packet.  We should use the IP
		 * length field in the IP header.
		 */
		iph = (struct ip *)igp->igm_mp->b_rptr;
		trans_len = ntohs(iph->ip_len);
		transp = (uint16_t *)(igp->igm_mp->b_rptr + iphlen);
	}

	ngp->igm_saddr.sin_addr.s_addr = ipsrc.s_addr;
	ngp->igm_saddr.sin_port = sockets[index].ports(transp, SOURCE);
	ngp->igm_target.s_addr = ipdst.s_addr;
	ngp->igm_level = TRANSPORT_LVL;

	/*
	 * Align to 16bit value.  Checksum code may require an extra byte
	 * for padding.
	 */
	new_len = ((trans_len + sizeof (int16_t) - 1) &
	    ~(sizeof (int16_t) - 1));
	if ((ngp->igm_mp = allocb(new_len, 0)) == NULL) {
		errno = ENOMEM;
		bkmem_free((caddr_t)ngp, sizeof (struct inetgram));
		if (fragmented)
			frag_flush();
		return (NULL);
	}

	if (fragmented) {
		if (frag_load(ngp) != 0) {
			freeb(ngp->igm_mp);
			bkmem_free((caddr_t)ngp, sizeof (struct inetgram));
			frag_flush();
			return (NULL);
		}
		frag_flush();
	} else {
		bcopy((caddr_t)(igp->igm_mp->b_rptr),
		    (caddr_t)ngp->igm_mp->b_rptr, trans_len);
		ngp->igm_mp->b_wptr += trans_len;
	}
	return (ngp);
}

/*
 * ipv4_input: Pull in IPv4 datagrams addressed to us. Handle IP fragmentation
 * (fragments received in any order) and ICMP at this level.
 *
 * Note that because our network is serviced by polling when we expect
 * something (upon a referenced socket), we don't go through the work of
 * locating the appropriate socket a datagram is destined for. We'll only
 * accept data for the referenced socket. This means we don't have
 * asynchronous networking, but since we can't service the net using an
 * interrupt handler, it doesn't do us any good to try to service datagrams
 * destined for sockets other than the referenced one. Data is handled in
 * a fifo manner.
 *
 * The mac layer will grab all frames for us. If we find we don't have all
 * the necessary fragments to reassemble the datagram, we'll call the mac
 * layer again for FRAG_ATTEMPTS to see if it has any more frames.
 *
 * Supported protocols: IPPROTO_IP, IPPROTO_ICMP, IPPROTO_UDP.
 *
 * Returns: number of NETWORK_LVL datagrams placed on socket , -1 if error
 * occurred.
 *
 * Note: errno is set to ETIMEDOUT if fragment reassembly fails.
 */
int
ipv4_input(int index)
{
	int			datagrams = 0;
	int			frag_stat, input_attempts = 0;
	uint16_t		iphlen, iplen, ip_id;
	int16_t			curr_off;
	struct ip		*iphp;
	struct inetgram		*igp, *newgp = NULL, *ipv4_listp = NULL;
	struct in_addr		ipdst, ipsrc;
	mblk_t			*mp;
	enum SockType		type;

#ifdef	DEBUG
	printf("ipv4_input(%d): start ######################################\n",
	    index);
#endif	/* DEBUG */

	frag_flush();

ipv4_try_again:

	while ((igp = sockets[index].inq) != NULL) {
		if (igp->igm_level != NETWORK_LVL) {
#ifdef	DEBUG
			printf("ipv4_input(%d): unexpected frame type: %d\n",
			    index, igp->igm_level);
#endif	/* DEBUG */
			del_gram(&sockets[index].inq, igp, TRUE);
			continue;
		}
		iphp = (struct ip *)igp->igm_mp->b_rptr;
		if (iphp->ip_v != IPVERSION) {
			dprintf("ipv4_input(%d): IPv%d datagram discarded\n",
			index, iphp->ip_v);
			del_gram(&sockets[index].inq, igp, TRUE);
			continue;
		}
		iphlen = iphp->ip_hl << 2;
		if (iphlen < sizeof (struct ip)) {
			dprintf("ipv4_input(%d): IP msg too short (%d < %u)\n",
			    index, iphlen, (uint_t)sizeof (struct ip));
			del_gram(&sockets[index].inq, igp, TRUE);
			continue;
		}
		iplen = ntohs(iphp->ip_len);
		if (iplen > msgdsize(igp->igm_mp)) {
			dprintf("ipv4_input(%d): IP len/buffer mismatch "
			    "(%d > %lu)\n", index, iplen, igp->igm_mp->b_size);
			del_gram(&sockets[index].inq, igp, TRUE);
			continue;
		}

		bcopy((caddr_t)&(iphp->ip_dst), (caddr_t)&ipdst,
		    sizeof (ipdst));
		bcopy((caddr_t)&(iphp->ip_src), (caddr_t)&ipsrc,
		    sizeof (ipsrc));

		/* igp->igm_mp->b_datap is guaranteed to be 64 bit aligned] */
		if (ipv4cksum((uint16_t *)iphp, iphlen) != 0) {
			dprintf("ipv4_input(%d): Bad IP header checksum "
			    "(to %s)\n", index, inet_ntoa(ipdst));
			del_gram(&sockets[index].inq, igp, TRUE);
			continue;
		}

		if (!promiscuous) {
			/* validate destination address */
			if (ipdst.s_addr != htonl(INADDR_BROADCAST) &&
			    ipdst.s_addr != (mynet.s_addr | ~netmask.s_addr) &&
			    ipdst.s_addr != myip.s_addr) {
#ifdef	DEBUG
				printf("ipv4_input(%d): msg to %s discarded.\n",
				    index, inet_ntoa(ipdst));
#endif	/* DEBUG */
				/* not ours */
				del_gram(&sockets[index].inq, igp, TRUE);
				continue;
			}
		}

		/* Intercept ICMP first */
		if (!promiscuous && (iphp->ip_p == IPPROTO_ICMP)) {
			icmp4(igp, iphp, iphlen, ipsrc);
			del_gram(&sockets[index].inq, igp, TRUE);
			continue;
		}

#ifdef	DEBUG
		printf("ipv4_input(%d): processing ID: 0x%x protocol %d "
		    "(0x%x) (0x%x,%d)\n",
		    index, ntohs(iphp->ip_id), iphp->ip_p, igp, igp->igm_mp,
		    igp->igm_mp->b_size);
#endif	/* DEBUG */
		type = sockets[index].type;
		if (type == INETBOOT_RAW) {
			/* No fragmentation - Just the raw packet. */
#ifdef	DEBUG
			printf("ipv4_input(%d): Raw packet.\n", index);
#endif	/* DEBUG */
			del_gram(&sockets[index].inq, igp, FALSE);
			add_grams(&ipv4_listp, igp);
			igp->igm_mp->b_rptr += iphlen;
			igp->igm_mp->b_wptr = igp->igm_mp->b_rptr + iplen;
			datagrams++;
			continue;
		}

		if ((type == INETBOOT_DGRAM && iphp->ip_p != IPPROTO_UDP) ||
		    (type == INETBOOT_STREAM && iphp->ip_p != IPPROTO_TCP)) {
			/* Wrong protocol. */
			dprintf("ipv4_input(%d): unexpected protocol: "
			    "%d for socket type %d\n", index, iphp->ip_p, type);
			del_gram(&sockets[index].inq, igp, TRUE);
			continue;
		}

		/*
		 * The following code is common to both STREAM and DATAGRAM
		 * sockets.
		 */

		/*
		 * Once we process the first fragment, we won't have
		 * the transport header, so we'll have to  match on
		 * IP id.
		 */
		curr_off = ntohs(iphp->ip_off);
		if ((curr_off & ~(IP_DF | IP_MF)) == 0) {
			uint16_t	*transp;

			/* Validate transport header. */
			mp = igp->igm_mp;
			if ((mp->b_wptr - mp->b_rptr - iphlen) <
			    sockets[index].headerlen[TRANSPORT_LVL](igp)) {
				dprintf("ipv4_input(%d): datagram 0 "
				    "too small to hold transport header "
				    "(from %s)\n", index, inet_ntoa(ipsrc));
				del_gram(&sockets[index].inq, igp, TRUE);
				continue;
			}

			/*
			 * check alignment - transport elements are 16
			 * bit aligned..
			 */
			transp = (uint16_t *)(mp->b_rptr + iphlen);
			if ((uintptr_t)transp % sizeof (uint16_t)) {
				dprintf("ipv4_input(%d): Transport "
				    "header is not 16-bit aligned "
				    "(0x%lx, from %s)\n", index, (long)transp,
				    inet_ntoa(ipsrc));
				del_gram(&sockets[index].inq, igp, TRUE);
				continue;
			}

			if (curr_off & IP_MF) {
				/* fragment 0 of fragmented datagram */
				ip_id = ntohs(iphp->ip_id);
				frag_stat = frag_add(curr_off, igp->igm_mp,
				    ip_id, iplen, iphlen, iphp->ip_p);
				if (frag_stat != FRAG_SUCCESS) {
#ifdef	FRAG_DEBUG
					if (frag_stat == FRAG_DUP) {
						printf("ipv4_input"
						    "(%d): Frag dup.\n", index);
					} else {
						printf("ipv4_input"
						    "(%d): too many "
						    "frags\n", index);
					}
#endif	/* FRAG_DEBUG */
					del_gram(&sockets[index].inq,
					    igp, TRUE);
					continue;
				}

				del_gram(&sockets[index].inq, igp, FALSE);
				/* keep the data, lose the inetgram */
				bkmem_free((caddr_t)igp,
				    sizeof (struct inetgram));
#ifdef	FRAG_DEBUG
				printf("ipv4_input(%d): Frag/Off/Id "
				    "(%d/%d/%x)\n", index, fragments,
				    IPV4_OFFSET(curr_off), ip_id);
#endif	/* FRAG_DEBUG */
			} else {
				/* Single, unfragmented datagram */
				newgp = make_trans_datagram(index, igp,
				    ipsrc, ipdst, iphlen);
				if (newgp != NULL) {
					add_grams(&ipv4_listp, newgp);
					datagrams++;
				}
				del_gram(&sockets[index].inq, igp,
				    TRUE);
				continue;
			}
		} else {
			/* fragments other than 0 */
			frag_stat = frag_add(curr_off, igp->igm_mp,
			    ntohs(iphp->ip_id), iplen, iphlen, iphp->ip_p);

			if (frag_stat == FRAG_SUCCESS) {
#ifdef	FRAG_DEBUG
				printf("ipv4_input(%d): Frag(%d) "
				    "off(%d) id(%x)\n", index,
				    fragments, IPV4_OFFSET(curr_off),
				    ntohs(iphp->ip_id));
#endif	/* FRAG_DEBUG */
				del_gram(&sockets[index].inq, igp, FALSE);
				/* keep the data, lose the inetgram */
				bkmem_free((caddr_t)igp,
				    sizeof (struct inetgram));
			} else {
#ifdef	FRAG_DEBUG
				if (frag_stat == FRAG_DUP)
					printf("ipv4_input(%d): Frag "
					    "dup.\n", index);
				else {
					printf("ipv4_input(%d): too "
					    "many frags\n", index);
				}
#endif	/* FRAG_DEBUG */
				del_gram(&sockets[index].inq, igp, TRUE);
				continue;
			}
		}

		/*
		 * Determine if we have all of the fragments.
		 *
		 * NOTE: at this point, we've placed the data in the
		 * fragment table, and the inetgram (igp) has been
		 * deleted.
		 */
		if (!frag_chk())
			continue;

		newgp = make_trans_datagram(index, NULL, ipsrc, ipdst, iphlen);
		if (newgp == NULL)
			continue;
		add_grams(&ipv4_listp, newgp);
		datagrams++;
	}
	if (ipv4_listp == NULL && fragments != 0) {
		if (++input_attempts > FRAG_ATTEMPTS) {
			dprintf("ipv4_input(%d): reassembly(%d) timed out in "
			    "%d msecs.\n", index, fragments,
			    sockets[index].in_timeout * input_attempts);
			frag_flush();
			errno = ETIMEDOUT;
			return (-1);
		} else {
			/*
			 * Call the media layer again... there may be more
			 * packets waiting.
			 */
			if (sockets[index].input[MEDIA_LVL](index) < 0) {
				/* errno will be set appropriately */
				frag_flush();
				return (-1);
			}
			goto ipv4_try_again;
		}
	}

	add_grams(&sockets[index].inq, ipv4_listp);

	return (datagrams);
}

/*
 * ipv4_output: Generate IPv4 datagram(s) for the payload and deliver them.
 * Routing is handled here as well, by reusing the saddr field to hold the
 * router's IP address.
 *
 * We don't deal with fragmentation on the outgoing side.
 *
 * Arguments: index to socket, inetgram to send.
 *
 * Returns: 0 for success, -1 if error occurred.
 */
int
ipv4_output(int index, struct inetgram *ogp)
{
	struct ip	*iphp;
	uint64_t	iphbuffer[sizeof (struct ip)];

#ifdef	DEBUG
	printf("ipv4_output(%d): size %d\n", index,
	    ogp->igm_mp->b_wptr - ogp->igm_mp->b_rptr);
#endif	/* DEBUG */

	/* we don't deal (yet) with fragmentation. Maybe never will */
	if ((ogp->igm_mp->b_wptr - ogp->igm_mp->b_rptr) > mac_get_mtu()) {
		dprintf("ipv4: datagram too big for MAC layer.\n");
		errno = E2BIG;
		return (-1);
	}

	if (ogp->igm_level != NETWORK_LVL) {
#ifdef	DEBUG
		printf("ipv4_output(%d): unexpected frame type: %d\n", index,
		    ogp->igm_level);
#endif	/* DEBUG */
		errno = EINVAL;
		return (-1);
	}

	if (sockets[index].out_flags & SO_DONTROUTE)
		ogp->igm_oflags |= MSG_DONTROUTE;

	iphp = (struct ip *)&iphbuffer;
	iphp->ip_v = IPVERSION;
	iphp->ip_hl = sizeof (struct ip) / 4;
	iphp->ip_tos = 0;
	iphp->ip_len = htons(ogp->igm_mp->b_wptr - ogp->igm_mp->b_rptr +
	    sizeof (struct ip));
	iphp->ip_id = htons(++g_ip_id);
	iphp->ip_off = htons(IP_DF);
	iphp->ip_p = sockets[index].proto;
	iphp->ip_sum = htons(0);
	iphp->ip_ttl = ttl;

	/* struct copies */
	iphp->ip_src = myip;
	iphp->ip_dst = ogp->igm_saddr.sin_addr;

	/*
	 * On local / limited broadcasts, don't route. From a purist's
	 * perspective, we should be setting the TTL to 1. But
	 * operational experience has shown that some BOOTP relay agents
	 * (ciscos) discard our packets. Furthermore, these devices also
	 * *don't* reset the TTL to MAXTTL on the unicast side of the
	 * BOOTP relay agent! Sigh. Thus to work correctly in these
	 * environments, we leave the TTL as it has been been set by
	 * the application layer, and simply don't check for a route.
	 */
	if (iphp->ip_dst.s_addr == htonl(INADDR_BROADCAST) ||
	    (netmask.s_addr != htonl(INADDR_BROADCAST) &&
	    iphp->ip_dst.s_addr == (mynet.s_addr | ~netmask.s_addr))) {
		ogp->igm_oflags |= MSG_DONTROUTE;
	}

	/* Routing necessary? */
	if ((ogp->igm_oflags & MSG_DONTROUTE) == 0 &&
	    ((iphp->ip_dst.s_addr & netmask.s_addr) != mynet.s_addr)) {
		struct in_addr *rip;
		if ((rip = ipv4_get_route(RT_HOST, &iphp->ip_dst,
		    NULL)) == NULL) {
			rip = ipv4_get_route(RT_DEFAULT, NULL, NULL);
		}
		if (rip == NULL) {
			dprintf("ipv4(%d): No route to %s.\n",
			    index, inet_ntoa(iphp->ip_dst));
			errno = EHOSTUNREACH;
			return (-1);
		}
		ogp->igm_router.s_addr = rip->s_addr;
	} else
		ogp->igm_router.s_addr = htonl(INADDR_ANY);

	iphp->ip_sum = ipv4cksum((uint16_t *)iphp, sizeof (struct ip));
	ogp->igm_mp->b_rptr -= sizeof (struct ip);
	bcopy((caddr_t)iphp, (caddr_t)(ogp->igm_mp->b_rptr),
	    sizeof (struct ip));

	ogp->igm_level = MEDIA_LVL;

	return (0);
}

/*
 * Function to be called by TCP to send out a packet.  This is used
 * when TCP wants to send out packets which it has already filled in
 * most of the header fields.
 */
int
ipv4_tcp_output(int sock_id, mblk_t *pkt)
{
	struct ip *iph;
	struct in_addr *rip = NULL;
	struct inetgram datagram;

	iph = (struct ip *)pkt->b_rptr;

	bzero(&datagram, sizeof (struct inetgram));

	/*
	 * Bootparams doesn't know about subnet masks, so we need to
	 * explicitly check for this flag.
	 */
	if (sockets[sock_id].out_flags & SO_DONTROUTE)
		datagram.igm_oflags |= MSG_DONTROUTE;

	/* Routing necessary? */
	if (((datagram.igm_oflags & MSG_DONTROUTE) == 0) &&
		((iph->ip_dst.s_addr & netmask.s_addr) != mynet.s_addr)) {
		if ((rip = ipv4_get_route(RT_HOST, &iph->ip_dst,
		    NULL)) == NULL) {
			rip = ipv4_get_route(RT_DEFAULT, NULL, NULL);
		}
		if (rip == NULL) {
			dprintf("ipv4(%d): No route to %s.\n",
			    sock_id, inet_ntoa(iph->ip_dst));
			errno = EHOSTUNREACH;
			return (-1);
		}
	}

	iph->ip_id = htons(++g_ip_id);
	iph->ip_sum = ipv4cksum((uint16_t *)iph, sizeof (struct ip));
#if DEBUG > 1
	printf("ipv4_tcp_output: dump IP packet(%d)\n", iph->ip_len);
	hexdump((char *)pkt->b_rptr, iph->ip_len);
#endif
	/* Call the MAC layer output routine to send it out. */
	datagram.igm_mp = pkt;
	datagram.igm_level = MEDIA_LVL;
	if (rip != NULL)
		datagram.igm_router.s_addr = rip->s_addr;
	else
		datagram.igm_router.s_addr = 0;
	return (mac_state.mac_output(sock_id, &datagram));
}

/*
 * Internet address interpretation routine.
 * All the network library routines call this
 * routine to interpret entries in the data bases
 * which are expected to be an address.
 * The value returned is in network order.
 */
in_addr_t
inet_addr(const char *cp)
{
	uint32_t val, base, n;
	char c;
	uint32_t parts[4], *pp = parts;

	if (*cp == '\0')
		return ((uint32_t)-1); /* disallow null string in cp */
again:
	/*
	 * Collect number up to ``.''.
	 * Values are specified as for C:
	 * 0x=hex, 0=octal, other=decimal.
	 */
	val = 0; base = 10;
	if (*cp == '0') {
		if (*++cp == 'x' || *cp == 'X')
			base = 16, cp++;
		else
			base = 8;
	}
	while ((c = *cp) != '\0') {
		if (isdigit(c)) {
			if ((c - '0') >= base)
			    break;
			val = (val * base) + (c - '0');
			cp++;
			continue;
		}
		if (base == 16 && isxdigit(c)) {
			val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
			cp++;
			continue;
		}
		break;
	}
	if (*cp == '.') {
		/*
		 * Internet format:
		 *	a.b.c.d
		 *	a.b.c	(with c treated as 16-bits)
		 *	a.b	(with b treated as 24 bits)
		 */
		if ((pp >= parts + 3) || (val > 0xff)) {
			return ((uint32_t)-1);
		}
		*pp++ = val, cp++;
		goto again;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && !isspace(*cp)) {
		return ((uint32_t)-1);
	}
	*pp++ = val;
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts;
	switch (n) {

	case 1:				/* a -- 32 bits */
		val = parts[0];
		break;

	case 2:				/* a.b -- 8.24 bits */
		if (parts[1] > 0xffffff)
		    return ((uint32_t)-1);
		val = (parts[0] << 24) | (parts[1] & 0xffffff);
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if (parts[2] > 0xffff)
		    return ((uint32_t)-1);
		val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
			(parts[2] & 0xffff);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if (parts[3] > 0xff)
		    return ((uint32_t)-1);
		val = (parts[0] << 24) | ((parts[1] & 0xff) << 16) |
		    ((parts[2] & 0xff) << 8) | (parts[3] & 0xff);
		break;

	default:
		return ((uint32_t)-1);
	}
	val = htonl(val);
	return (val);
}

void
hexdump(char *data, int datalen)
{
	char *p;
	ushort_t *p16 = (ushort_t *)data;
	char *p8 = data;
	int i, left, len;
	int chunk = 16;  /* 16 bytes per line */

	printf("\n");

	for (p = data; p < data + datalen; p += chunk) {
		printf("\t%4d: ", (int)(p - data));
		left = (data + datalen) - p;
		len = MIN(chunk, left);
		for (i = 0; i < (len / 2); i++)
			printf("%04x ", ntohs(*p16++) & 0xffff);
		if (len % 2) {
			printf("%02x   ", *((unsigned char *)p16));
		}
		for (i = 0; i < (chunk - left) / 2; i++)
			printf("     ");

		printf("   ");
		for (i = 0; i < len; i++, p8++)
			printf("%c", isprint(*p8) ? *p8 : '.');
		printf("\n");
	}

	printf("\n");
}
