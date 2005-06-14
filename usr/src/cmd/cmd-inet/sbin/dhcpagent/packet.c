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

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <dhcpmsg.h>
#include <stddef.h>
#include <assert.h>

#include "states.h"
#include "interface.h"
#include "agent.h"
#include "packet.h"
#include "util.h"

static double	fuzzify(uint32_t, double);
static void 	retransmit(iu_tq_t *, void *);
static uint32_t	next_retransmission(uint32_t);
static int	send_pkt_internal(struct ifslist *);
static uchar_t	pkt_type(PKT *);

/*
 * dhcp_type_ptob(): converts the DHCP packet type values in RFC2131 into
 *		     values which can be used for recv_pkt()
 *
 *   input: uchar_t: a DHCP packet type value, as defined in RFC2131
 *  output: dhcp_message_type_t: a packet type value for use with recv_pkt()
 */

static dhcp_message_type_t
dhcp_type_ptob(uchar_t type)
{
	/*
	 * note: the ordering here allows direct indexing of the table
	 *	 based on the RFC2131 packet type value passed in.
	 */

	static dhcp_message_type_t type_map[] = {
		DHCP_PUNTYPED, DHCP_PDISCOVER, DHCP_POFFER, DHCP_PREQUEST,
		DHCP_PDECLINE, DHCP_PACK, DHCP_PNAK, DHCP_PRELEASE, DHCP_PINFORM
	};

	if (type < (sizeof (type_map) / sizeof (*type_map)))
		return (type_map[type]);

	return (0);
}

/*
 * pkt_type(): returns an integer representing the packet's type; only
 *	       for use with outbound packets.
 *
 *   input: PKT *: the packet to examine
 *  output: uchar_t: the packet type (0 if unknown)
 */

static uchar_t
pkt_type(PKT *pkt)
{
	uchar_t	*option = pkt->options;

	/*
	 * this is a little dirty but it should get the job done.
	 * assumes that the type is in the statically allocated part
	 * of the options field.
	 */

	while (*option != CD_DHCP_TYPE) {
		if (option + 2 - pkt->options >= sizeof (pkt->options))
			return (0);

		option++;
		option += *option;
	}

	return (option[2]);
}

/*
 * init_pkt(): initializes and returns a packet of a given type
 *
 *   input: struct ifslist *: the interface the packet will be going out
 *	    uchar_t: the packet type (DHCP message type)
 *  output: dhcp_pkt_t *: a pointer to the initialized packet
 */

dhcp_pkt_t *
init_pkt(struct ifslist *ifsp, uchar_t type)
{
	uint8_t		bootmagic[] = BOOTMAGIC;
	dhcp_pkt_t	*dpkt = &ifsp->if_send_pkt;
	uint32_t	xid;

	dpkt->pkt_max_len = ifsp->if_max;
	dpkt->pkt_cur_len = offsetof(PKT, options);

	(void) memset(dpkt->pkt, 0, ifsp->if_max);
	(void) memcpy(dpkt->pkt->cookie, bootmagic, sizeof (bootmagic));
	if (ifsp->if_hwlen <= sizeof (dpkt->pkt->chaddr)) {
		dpkt->pkt->hlen  = ifsp->if_hwlen;
		(void) memcpy(dpkt->pkt->chaddr, ifsp->if_hwaddr,
		    ifsp->if_hwlen);
	} else {
		/*
		 * The mac address does not fit in the chaddr
		 * field, thus it can not be sent to the server,
		 * thus server can not unicast the reply. Per
		 * RFC 2131 4.4.1, client can set this bit in
		 * DISCOVER/REQUEST. If the client is already
		 * in BOUND/REBINDING/RENEWING state, do not set
		 * this bit, as it can respond to unicast responses
		 * from server using the 'ciaddr' address.
		 */
		if ((type == DISCOVER) || ((type == REQUEST) &&
		    (ifsp->if_state != RENEWING) &&
		    (ifsp->if_state != REBINDING) &&
		    (ifsp->if_state != BOUND)))
			dpkt->pkt->flags = htons(BCAST_MASK);
	}

	/*
	 * since multiple dhcp leases may be maintained over the same dlpi
	 * device (e.g. "hme0" and "hme0:1"), make sure the xid is unique.
	 */

	do {
		xid = mrand48();
	} while (lookup_ifs_by_xid(xid) != NULL);

	dpkt->pkt->xid	 = xid;
	dpkt->pkt->op    = BOOTREQUEST;
	dpkt->pkt->htype = ifsp->if_hwtype;

	add_pkt_opt(dpkt, CD_DHCP_TYPE, &type, 1);
	add_pkt_opt(dpkt, CD_CLIENT_ID, ifsp->if_cid, ifsp->if_cidlen);

	return (dpkt);
}

/*
 * add_pkt_opt(): adds an option to a dhcp_pkt_t
 *
 *   input: dhcp_pkt_t *: the packet to add the option to
 *	    uchar_t: the type of option being added
 *	    const void *: the value of that option
 *	    uchar_t: the length of the value of the option
 *  output: void
 */

void
add_pkt_opt(dhcp_pkt_t *dpkt, uchar_t opt_type, const void *opt_val,
    uchar_t opt_len)
{
	caddr_t		raw_pkt = (caddr_t)dpkt->pkt;
	int16_t		req_len = opt_len + 2; /* + 2 for code & length bytes */

	/* CD_END and CD_PAD options don't have a length field */
	if (opt_type == CD_END || opt_type == CD_PAD)
		req_len--;
	else if (opt_val == NULL)
		return;

	if ((dpkt->pkt_cur_len + req_len) > dpkt->pkt_max_len) {
		dhcpmsg(MSG_WARNING, "add_pkt_opt: not enough room for option "
		    "%d in packet", opt_type);
		return;
	}

	raw_pkt[dpkt->pkt_cur_len++] = opt_type;

	if (opt_len > 0) {
		raw_pkt[dpkt->pkt_cur_len++] = opt_len;
		(void) memcpy(&raw_pkt[dpkt->pkt_cur_len], opt_val, opt_len);
		dpkt->pkt_cur_len += opt_len;
	}
}

/*
 * add_pkt_opt16(): adds an option with a 16-bit value to a dhcp_pkt_t
 *
 *   input: dhcp_pkt_t *: the packet to add the option to
 *	    uchar_t: the type of option being added
 *	    uint16_t: the value of that option
 *  output: void
 */

void
add_pkt_opt16(dhcp_pkt_t *dpkt, uchar_t opt_type, uint16_t opt_value)
{
	add_pkt_opt(dpkt, opt_type, &opt_value, 2);
}

/*
 * add_pkt_opt32(): adds an option with a 32-bit value to a dhcp_pkt_t
 *
 *   input: dhcp_pkt_t *: the packet to add the option to
 *	    uchar_t: the type of option being added
 *	    uint32_t: the value of that option
 *  output: void
 */

void
add_pkt_opt32(dhcp_pkt_t *dpkt, uchar_t opt_type, uint32_t opt_value)
{
	add_pkt_opt(dpkt, opt_type, &opt_value, 4);
}

/*
 * get_pkt_times(): pulls the lease times out of a packet and stores them as
 *		    host-byteorder relative times in the passed in parameters
 *
 *   input: PKT_LIST *: the packet to pull the packet times from
 *	    lease_t *: where to store the relative lease time in hbo
 *	    lease_t *: where to store the relative t1 time in hbo
 *	    lease_t *: where to store the relative t2 time in hbo
 *  output: void
 */

void
get_pkt_times(PKT_LIST *ack, lease_t *lease, lease_t *t1, lease_t *t2)
{
	*lease	= DHCP_PERM;
	*t1	= DHCP_PERM;
	*t2	= DHCP_PERM;

	if (ack->opts[CD_DHCP_TYPE]  == NULL ||
	    ack->opts[CD_LEASE_TIME] == NULL ||
	    ack->opts[CD_LEASE_TIME]->len != sizeof (lease_t))
		return;

	(void) memcpy(lease, ack->opts[CD_LEASE_TIME]->value, sizeof (lease_t));
	*lease = ntohl(*lease);

	if (*lease == DHCP_PERM)
		return;

	if (ack->opts[CD_T1_TIME] != NULL &&
	    ack->opts[CD_T1_TIME]->len == sizeof (lease_t)) {
		(void) memcpy(t1, ack->opts[CD_T1_TIME]->value, sizeof (*t1));
		*t1 = ntohl(*t1);
	}

	if ((*t1 == DHCP_PERM) || (*t1 >= *lease))
		*t1 = (lease_t)fuzzify(*lease, DHCP_T1_FACT);

	if (ack->opts[CD_T2_TIME] != NULL &&
	    ack->opts[CD_T2_TIME]->len == sizeof (lease_t)) {
		(void) memcpy(t2, ack->opts[CD_T2_TIME]->value, sizeof (*t2));
		*t2 = ntohl(*t2);
	}

	if ((*t2 == DHCP_PERM) || (*t2 > *lease) || (*t2 <= *t1))
		*t2 = (lease_t)fuzzify(*lease, DHCP_T2_FACT);
}

/*
 * fuzzify(): adds some "fuzz" to a t1/t2 time, in accordance with RFC2131
 *
 *   input: uint32_t: the number of seconds until lease expiration
 *	    double: the approximate percentage of that time to return
 *  output: double: a number approximating (sec * pct)
 */

static double
fuzzify(uint32_t sec, double pct)
{
	return (sec * (pct + (drand48() - 0.5) / 25.0));
}

/*
 * free_pkt_list(): frees a packet list
 *
 *   input: PKT_LIST **: the packet list to free
 *  output: void
 */

void
free_pkt_list(PKT_LIST **plp)
{
	PKT_LIST	*plp_next;

	for (; *plp != NULL; *plp = plp_next) {
		plp_next = (*plp)->next;
		free((*plp)->pkt);
		free(*plp);
	}
}

/*
 * prepend_to_pkt_list(): prepends a packet to a packet list
 *
 *   input: PKT_LIST **: the packet list
 *	    PKT_LIST *: the packet to prepend
 *  output: void
 */

static void
prepend_to_pkt_list(PKT_LIST **list_head, PKT_LIST *new_entry)
{
	new_entry->next = *list_head;
	new_entry->prev = NULL;

	if (*list_head != NULL)
		(*list_head)->prev = new_entry;

	*list_head = new_entry;
}

/*
 * remove_from_pkt_list(): removes a given packet from a packet list
 *
 *   input: PKT_LIST **: the packet list
 *	    PKT_LIST *: the packet to remove
 *  output: void
 */

void
remove_from_pkt_list(PKT_LIST **list_head, PKT_LIST *remove)
{
	if (*list_head == NULL)
		return;

	if (*list_head == remove) {
		*list_head = remove->next;
		if (*list_head != NULL)
			(*list_head)->prev = NULL;
	} else {
		remove->prev->next = remove->next;
		if (remove->next != NULL)
			remove->next->prev = remove->prev;
	}

	remove->next = NULL;
	remove->prev = NULL;
}

/*
 * send_pkt_internal(): sends a packet out on an interface
 *
 *   input: struct ifslist *: the interface to send the packet out on
 *  output: int: 1 if the packet is sent, 0 otherwise
 */

static int
send_pkt_internal(struct ifslist *ifsp)
{
	ssize_t		n_bytes;
	dhcp_pkt_t	*dpkt = &ifsp->if_send_pkt;
	const char	*pkt_name = pkt_type_to_string(pkt_type(dpkt->pkt));

	/*
	 * if needed, schedule a retransmission timer, then attempt to
	 * send the packet.  if we fail, then log the error.  our
	 * return value should indicate whether or not we were
	 * successful in sending the request, independent of whether
	 * we could schedule a timer.
	 */

	if (ifsp->if_send_timeout != 0) {
		if ((ifsp->if_retrans_timer = iu_schedule_timer_ms(tq,
		    ifsp->if_send_timeout, retransmit, ifsp)) == -1)
			dhcpmsg(MSG_WARNING, "send_pkt_internal: cannot "
			    "schedule retransmit timer for %s packet",
			    pkt_name);
		else
			hold_ifs(ifsp);
	}

	/*
	 * set the `pkt->secs' field depending on the type of packet.
	 * it should be zero, except in the following cases:
	 *
	 * DISCOVER:	set to the number of seconds since we started
	 *		trying to obtain a lease.
	 *
	 * INFORM:	set to the number of seconds since we started
	 *		trying to get configuration parameters.
	 *
	 * REQUEST:	if in the REQUESTING state, then same value as
	 *		DISCOVER, otherwise the number of seconds
	 *		since we started trying to obtain a lease.
	 *
	 * we also set `if_newstart_monosec', to the time we sent a
	 * REQUEST or DISCOVER packet, so we know the lease start
	 * time (the DISCOVER case is for handling BOOTP servers).
	 */

	switch (pkt_type(dpkt->pkt)) {

	case DISCOVER:
		ifsp->if_newstart_monosec = monosec();
		ifsp->if_disc_secs = monosec() - ifsp->if_neg_monosec;
		dpkt->pkt->secs = htons(ifsp->if_disc_secs);
		break;

	case INFORM:
		dpkt->pkt->secs = htons(monosec() - ifsp->if_neg_monosec);
		break;

	case REQUEST:
		ifsp->if_newstart_monosec = monosec();

		if (ifsp->if_state == REQUESTING) {
			dpkt->pkt->secs = htons(ifsp->if_disc_secs);
			break;
		}

		dpkt->pkt->secs = htons(monosec() - ifsp->if_neg_monosec);
		break;

	default:
		dpkt->pkt->secs = htons(0);
	}

	switch (ifsp->if_state) {

	case BOUND:
	case RENEWING:
	case REBINDING:
		n_bytes = sendto(ifsp->if_sock_ip_fd, dpkt->pkt,
		    dpkt->pkt_cur_len, 0,
		    (struct sockaddr *)&ifsp->if_send_dest,
		    sizeof (struct sockaddr_in));
		break;

	default:
		n_bytes = dlpi_sendto(ifsp->if_dlpi_fd, dpkt->pkt,
		    dpkt->pkt_cur_len, &ifsp->if_send_dest,
		    ifsp->if_daddr, ifsp->if_dlen);
		break;
	}

	if (n_bytes != dpkt->pkt_cur_len) {
		if (ifsp->if_retrans_timer == -1)
			dhcpmsg(MSG_WARNING, "send_pkt_internal: cannot send "
			    "%s packet to server", pkt_name);
		else
			dhcpmsg(MSG_WARNING, "send_pkt_internal: cannot send "
			    "%s packet to server (will retry in %u seconds)",
			    pkt_name, ifsp->if_send_timeout / MILLISEC);
		return (0);
	}

	dhcpmsg(MSG_VERBOSE, "sent %s packet out %s", pkt_name,
	    ifsp->if_name);

	ifsp->if_packet_sent++;
	ifsp->if_sent++;
	return (1);
}

/*
 * send_pkt(): sends a packet out on an interface
 *
 *   input: struct ifslist *: the interface to send the packet out on
 *	    dhcp_pkt_t *: the packet to send out
 *	    in_addr_t: the destination IP address for the packet
 *	    stop_func_t *: a pointer to function to indicate when to stop
 *			   retransmitting the packet (if NULL, packet is
 *			   not retransmitted)
 *  output: int: 1 if the packet was sent, 0 otherwise
 */

int
send_pkt(struct ifslist *ifsp, dhcp_pkt_t *dpkt, in_addr_t dest,
    stop_func_t *stop)
{
	/*
	 * packets must be at least sizeof (PKT) or they may be dropped
	 * by routers.  pad out the packet in this case.
	 */

	dpkt->pkt_cur_len = MAX(dpkt->pkt_cur_len, sizeof (PKT));

	ifsp->if_packet_sent = 0;

	(void) memset(&ifsp->if_send_dest, 0, sizeof (ifsp->if_send_dest));
	ifsp->if_send_dest.sin_addr.s_addr = dest;
	ifsp->if_send_dest.sin_family	   = AF_INET;
	ifsp->if_send_dest.sin_port	   = htons(IPPORT_BOOTPS);
	ifsp->if_send_stop_func		   = stop;

	/*
	 * TODO: dispose of this gruesome assumption (there's no real
	 * technical gain from doing so, but it would be cleaner)
	 */

	assert(dpkt == &ifsp->if_send_pkt);

	/*
	 * clear out any packets which had been previously received
	 * but not pulled off of the recv_packet queue.
	 */

	free_pkt_list(&ifsp->if_recv_pkt_list);

	if (stop == NULL) {
		ifsp->if_retrans_timer = -1;
		ifsp->if_send_timeout = 0;	/* prevents retransmissions */
	} else
		ifsp->if_send_timeout = next_retransmission(0);

	return (send_pkt_internal(ifsp));
}

/*
 * retransmit(): retransmits the current packet on an interface
 *
 *   input: iu_tq_t *: unused
 *	    void *: the struct ifslist * to send the packet on
 *  output: void
 */

/* ARGSUSED */
static void
retransmit(iu_tq_t *tqp, void *arg)
{
	struct ifslist		*ifsp = (struct ifslist *)arg;

	if (check_ifs(ifsp) == 0) {
		(void) release_ifs(ifsp);
		return;
	}

	/*
	 * check the callback to see if we should keep sending retransmissions
	 */

	if (ifsp->if_send_stop_func(ifsp, ifsp->if_packet_sent))
		return;

	ifsp->if_send_timeout = next_retransmission(ifsp->if_send_timeout);
	(void) send_pkt_internal(ifsp);
}

/*
 * stop_pkt_retransmission(): stops retransmission of last sent packet
 *
 *   input: struct ifslist *: the interface to stop retransmission on
 *  output: void
 */

void
stop_pkt_retransmission(struct ifslist *ifsp)
{
	if (ifsp->if_retrans_timer != -1) {
		if (iu_cancel_timer(tq, ifsp->if_retrans_timer, NULL) == 1) {
			(void) release_ifs(ifsp);
			ifsp->if_retrans_timer = -1;
		}
	}
}

/*
 * recv_pkt(): receives packets on an interface (put on ifsp->if_recv_pkt_list)
 *
 *   input: struct ifslist *: the interface to receive packets on
 *	    int: the file descriptor to receive the packet on
 *	    dhcp_message_type_t: the types of packets to receive
 *	    boolean_t: if B_TRUE, more than one packet can be received
 *  output: int: 1 if a packet was received successfully, 0 otherwise
 */

int
recv_pkt(struct ifslist *ifsp, int fd, dhcp_message_type_t type,
    boolean_t chain)
{
	PKT_LIST	*plp;
	PKT		*pkt;
	ssize_t		retval;
	uchar_t		recv_pkt_type;
	const char	*recv_pkt_name;

	/*
	 * collect replies.  chain them up if the chain flag is set
	 * and we've already got one, otherwise drop the packet.
	 * calloc the PKT_LIST since dhcp_options_scan() relies on it
	 * being zeroed.
	 */

	pkt = calloc(1, ifsp->if_max);
	plp = calloc(1, sizeof (PKT_LIST));
	if (pkt == NULL || plp == NULL) {
		dhcpmsg(MSG_ERR, "recv_pkt: dropped packet");
		goto failure;
	}

	plp->pkt = pkt;

	switch (ifsp->if_state) {

	case BOUND:
	case RENEWING:
	case REBINDING:
		retval = recvfrom(fd, pkt, ifsp->if_max, 0, NULL, 0);
		break;

	default:
		retval = dlpi_recvfrom(fd, pkt, ifsp->if_max, 0);
		break;
	}

	if (retval == -1) {
		dhcpmsg(MSG_ERR, "recv_pkt: recvfrom failed, dropped");
		goto failure;
	}

	plp->len = retval;

	switch (dhcp_options_scan(plp, B_TRUE)) {

	case DHCP_WRONG_MSG_TYPE:
		dhcpmsg(MSG_WARNING, "recv_pkt: unexpected DHCP message");
		goto failure;

	case DHCP_GARBLED_MSG_TYPE:
		dhcpmsg(MSG_WARNING, "recv_pkt: garbled DHCP message type");
		goto failure;

	case DHCP_BAD_OPT_OVLD:
		dhcpmsg(MSG_WARNING, "recv_pkt: bad option overload");
		goto failure;

	case 0:
		break;

	default:
		dhcpmsg(MSG_WARNING, "recv_pkt: packet corrupted, dropped");
		goto failure;
	}

	/*
	 * make sure the packet we got in was one we were expecting --
	 * it needs to have the right type and to have the same xid.
	 */

	if (plp->opts[CD_DHCP_TYPE] != NULL)
		recv_pkt_type = *plp->opts[CD_DHCP_TYPE]->value;
	else
		recv_pkt_type = 0;

	recv_pkt_name = pkt_type_to_string(recv_pkt_type);

	if ((dhcp_type_ptob(recv_pkt_type) & type) == 0) {
		dhcpmsg(MSG_VERBOSE, "received unexpected %s packet on "
		    "%s, dropped", recv_pkt_name, ifsp->if_name);
		goto failure;
	}

	/* the xid is opaque -- no byteorder work */
	if (plp->pkt->xid != ifsp->if_send_pkt.pkt->xid) {
		dhcpmsg(MSG_VERBOSE, "received unexpected packet xid (%#x "
		    "instead of %#x) on %s, dropped", plp->pkt->xid,
		    ifsp->if_send_pkt.pkt->xid, ifsp->if_name);
		goto failure;
	}

	if (ifsp->if_recv_pkt_list != NULL) {
		if (chain == B_FALSE) {
			dhcpmsg(MSG_WARNING, "recv_pkt: unexpected additional "
			    "%s packet, dropped", recv_pkt_name);
			goto failure;
		}
	}

	dhcpmsg(MSG_VERBOSE, "received %s packet on %s", recv_pkt_name,
	    ifsp->if_name);

	prepend_to_pkt_list(&ifsp->if_recv_pkt_list, plp);
	ifsp->if_received++;
	return (1);

failure:
	free(pkt);
	free(plp);
	return (0);
}

/*
 * next_retransmission(): returns the number of seconds until the next
 *			  retransmission, based on the algorithm in RFC2131
 *
 *   input: uint32_t: the number of milliseconds for the last retransmission
 *  output: uint32_t: the number of milliseconds until the next retransmission
 */

static uint32_t
next_retransmission(uint32_t last_timeout_ms)
{
	uint32_t	timeout_ms;

	/*
	 * start at 4, and increase by a factor of 2 up to 64.  at each
	 * iteration, jitter the timeout by some fraction of a second.
	 */
	if (last_timeout_ms == 0)
		timeout_ms = 4 * MILLISEC;
	else
		timeout_ms = MIN(last_timeout_ms << 1, 64 * MILLISEC);

	return (timeout_ms + ((lrand48() % (2 * MILLISEC)) - MILLISEC));
}
