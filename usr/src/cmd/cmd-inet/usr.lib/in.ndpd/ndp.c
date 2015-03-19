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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015, OmniTI Computer Consulting, Inc. All rights reserved.
 */

#include "defs.h"
#include "tables.h"

#include <sys/sysmacros.h>

#include <dhcpagent_ipc.h>
#include <dhcpagent_util.h>

static boolean_t verify_opt_len(struct nd_opt_hdr *opt, int optlen,
		    struct phyint *pi, struct sockaddr_in6 *from);

static void	incoming_rs(struct phyint *pi, struct nd_router_solicit *rs,
		    int len, struct sockaddr_in6 *from);

void		incoming_ra(struct phyint *pi, struct nd_router_advert *ra,
		    int len, struct sockaddr_in6 *from, boolean_t loopback);
static void	incoming_prefix_opt(struct phyint *pi, uchar_t *opt,
		    struct sockaddr_in6 *from, boolean_t loopback);
static void	incoming_prefix_onlink(struct phyint *pi, uchar_t *opt);
void		incoming_prefix_onlink_process(struct prefix *pr,
		    uchar_t *opt);
static void	incoming_prefix_stateful(struct phyint *, uchar_t *);
static boolean_t	incoming_prefix_addrconf(struct phyint *pi,
		    uchar_t *opt, struct sockaddr_in6 *from,
		    boolean_t loopback);
boolean_t	incoming_prefix_addrconf_process(struct phyint *pi,
		    struct prefix *pr, uchar_t *opt,
		    struct sockaddr_in6 *from, boolean_t loopback,
		    boolean_t new_prefix);
static void	incoming_mtu_opt(struct phyint *pi, uchar_t *opt,
		    struct sockaddr_in6 *from);
static void	incoming_lla_opt(struct phyint *pi, uchar_t *opt,
		    struct sockaddr_in6 *from, int isrouter);

static void	verify_ra_consistency(struct phyint *pi,
		    struct nd_router_advert *ra,
		    int len, struct sockaddr_in6 *from);
static void	verify_prefix_opt(struct phyint *pi, uchar_t *opt,
		    char *frombuf);
static void	verify_mtu_opt(struct phyint *pi, uchar_t *opt,
		    char *frombuf);

static void	update_ra_flag(const struct phyint *pi,
		    const struct sockaddr_in6 *from, int isrouter);

/*
 * Return a pointer to the specified option buffer.
 * If not found return NULL.
 */
static void *
find_ancillary(struct msghdr *msg, int cmsg_type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == cmsg_type) {
			return (CMSG_DATA(cmsg));
		}
	}
	return (NULL);
}

void
in_data(struct phyint *pi)
{
	struct sockaddr_in6 from;
	struct icmp6_hdr *icmp;
	struct nd_router_solicit *rs;
	struct nd_router_advert *ra;
	static uint64_t in_packet[(IP_MAXPACKET + 1)/8];
	static uint64_t ancillary_data[(IP_MAXPACKET + 1)/8];
	int len;
	char abuf[INET6_ADDRSTRLEN];
	const char *msgbuf;
	struct msghdr msg;
	struct iovec iov;
	uchar_t *opt;
	uint_t hoplimit;

	iov.iov_base = (char *)in_packet;
	iov.iov_len = sizeof (in_packet);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = (struct sockaddr *)&from;
	msg.msg_namelen = sizeof (from);
	msg.msg_control = ancillary_data;
	msg.msg_controllen = sizeof (ancillary_data);

	if ((len = recvmsg(pi->pi_sock, &msg, 0)) < 0) {
		logperror_pi(pi, "in_data: recvfrom");
		return;
	}
	if (len == 0)
		return;

	if (inet_ntop(AF_INET6, (void *)&from.sin6_addr,
	    abuf, sizeof (abuf)) == NULL)
		msgbuf = "Unspecified Router";
	else
		msgbuf = abuf;

	/* Ignore packets > 64k or control buffers that don't fit */
	if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
		if (debug & D_PKTBAD) {
			logmsg(LOG_DEBUG, "Truncated message: msg_flags 0x%x "
			    "from %s\n", msg.msg_flags, msgbuf);
		}
		return;
	}

	icmp = (struct icmp6_hdr *)in_packet;

	if (len < ICMP6_MINLEN) {
		logmsg(LOG_INFO, "Too short ICMP packet: %d bytes "
		    "from %s on %s\n",
		    len, msgbuf, pi->pi_name);
		return;
	}

	opt = find_ancillary(&msg, IPV6_HOPLIMIT);
	if (opt == NULL) {
		/* Unknown hoplimit - must drop */
		logmsg(LOG_INFO, "Unknown hop limit from %s on %s\n",
		    msgbuf, pi->pi_name);
		return;
	}
	hoplimit = *(uint_t *)opt;
	opt = find_ancillary(&msg, IPV6_RTHDR);
	if (opt != NULL) {
		/* Can't allow routing headers in ND messages */
		logmsg(LOG_INFO, "ND message with routing header "
		    "from %s on %s\n",
		    msgbuf, pi->pi_name);
		return;
	}
	switch (icmp->icmp6_type) {
	case ND_ROUTER_SOLICIT:
		if (!pi->pi_AdvSendAdvertisements)
			return;
		if (pi->pi_flags & IFF_NORTEXCH) {
			if (debug & D_PKTIN) {
				logmsg(LOG_DEBUG, "Ignore received RS packet "
				    "on %s (no route exchange on interface)\n",
				    pi->pi_name);
			}
			return;
		}

		/*
		 * Assumes that the kernel has verified the AH (if present)
		 * and the ICMP checksum.
		 */
		if (hoplimit != IPV6_MAX_HOPS) {
			logmsg(LOG_DEBUG, "RS hop limit: %d from %s on %s\n",
			    hoplimit, msgbuf, pi->pi_name);
			return;
		}

		if (icmp->icmp6_code != 0) {
			logmsg(LOG_INFO, "RS code: %d from %s on %s\n",
			    icmp->icmp6_code, msgbuf, pi->pi_name);
			return;
		}

		if (len < sizeof (struct nd_router_solicit)) {
			logmsg(LOG_INFO, "RS too short: %d bytes "
			    "from %s on %s\n",
			    len, msgbuf, pi->pi_name);
			return;
		}
		rs = (struct nd_router_solicit *)icmp;
		if (len > sizeof (struct nd_router_solicit)) {
			if (!verify_opt_len((struct nd_opt_hdr *)&rs[1],
			    len - sizeof (struct nd_router_solicit), pi, &from))
				return;
		}
		if (debug & D_PKTIN) {
			print_route_sol("Received valid solicit from ", pi,
			    rs, len, &from);
		}
		incoming_rs(pi, rs, len, &from);
		break;

	case ND_ROUTER_ADVERT:
		if (IN6_IS_ADDR_UNSPECIFIED(&from.sin6_addr)) {
			/*
			 * Router advt. must have address!
			 * Logging the news and returning.
			 */
			logmsg(LOG_DEBUG,
			    "Router's address unspecified in advertisement\n");
			return;
		}
		if (pi->pi_flags & IFF_NORTEXCH) {
			if (debug & D_PKTIN) {
				logmsg(LOG_DEBUG, "Ignore received RA packet "
				    "on %s (no route exchange on interface)\n",
				    pi->pi_name);
			}
			return;
		}

		/*
		 * Assumes that the kernel has verified the AH (if present)
		 * and the ICMP checksum.
		 */
		if (!IN6_IS_ADDR_LINKLOCAL(&from.sin6_addr)) {
			logmsg(LOG_DEBUG, "RA from %s - not link local on %s\n",
			    msgbuf, pi->pi_name);
			return;
		}

		if (hoplimit != IPV6_MAX_HOPS) {
			logmsg(LOG_INFO, "RA hop limit: %d from %s on %s\n",
			    hoplimit, msgbuf, pi->pi_name);
			return;
		}

		if (icmp->icmp6_code != 0) {
			logmsg(LOG_INFO, "RA code: %d from %s on %s\n",
			    icmp->icmp6_code, msgbuf, pi->pi_name);
			return;
		}

		if (len < sizeof (struct nd_router_advert)) {
			logmsg(LOG_INFO, "RA too short: %d bytes "
			    "from %s on %s\n",
			    len, msgbuf, pi->pi_name);
			return;
		}
		ra = (struct nd_router_advert *)icmp;
		if (len > sizeof (struct nd_router_advert)) {
			if (!verify_opt_len((struct nd_opt_hdr *)&ra[1],
			    len - sizeof (struct nd_router_advert), pi, &from))
				return;
		}
		if (debug & D_PKTIN) {
			print_route_adv("Received valid advert from ", pi,
			    ra, len, &from);
		}
		if (pi->pi_AdvSendAdvertisements)
			verify_ra_consistency(pi, ra, len, &from);
		else
			incoming_ra(pi, ra, len, &from, _B_FALSE);
		break;
	}
}

/*
 * Process a received router solicitation.
 * Check for source link-layer address option and check if it
 * is time to advertise.
 */
static void
incoming_rs(struct phyint *pi, struct nd_router_solicit *rs, int len,
    struct sockaddr_in6 *from)
{
	struct nd_opt_hdr *opt;
	int optlen;

	/* Process any options */
	len -= sizeof (struct nd_router_solicit);
	opt = (struct nd_opt_hdr *)&rs[1];
	while (len >= sizeof (struct nd_opt_hdr)) {
		optlen = opt->nd_opt_len * 8;
		switch (opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
			incoming_lla_opt(pi, (uchar_t *)opt,
			    from, NDF_ISROUTER_OFF);
			break;
		default:
			break;
		}
		opt = (struct nd_opt_hdr *)((char *)opt + optlen);
		len -= optlen;
	}
	/* Simple algorithm: treat unicast and multicast RSs the same */
	check_to_advertise(pi, RECEIVED_SOLICIT);
}

/*
 * Function that sends commands to dhcpagent daemon.
 */
int
dhcp_op(struct phyint *pi, int type)
{
	dhcp_ipc_request_t	*request;
	dhcp_ipc_reply_t	*reply	= NULL;
	int			error;

	request = dhcp_ipc_alloc_request(type | DHCP_V6, pi->pi_name, NULL, 0,
	    DHCP_TYPE_NONE);
	if (request == NULL) {
		logmsg(LOG_ERR, "dhcp_op: out of memory\n");
		/* make sure we try again next time there's a chance */
		if (type != DHCP_RELEASE) {
			pi->pi_ra_flags &=
			    ~ND_RA_FLAG_MANAGED & ~ND_RA_FLAG_OTHER;
		}
		return (DHCP_IPC_E_MEMORY);
	}

	error = dhcp_ipc_make_request(request, &reply, 0);
	free(request);
	if (error != 0) {
		logmsg(LOG_ERR, "could not send request to dhcpagent: "
		    "%s: %s\n", pi->pi_name, dhcp_ipc_strerror(error));
		return (error);
	}

	error = reply->return_code;
	free(reply);

	return (error);
}

/*
 * Start up DHCPv6 on a given physical interface. Does not wait for
 * a message to be returned from the daemon.
 */
void
start_dhcp(struct phyint *pi)
{
	int	error;
	int	type;

	if (dhcp_start_agent(DHCP_IPC_MAX_WAIT) == -1) {
		logmsg(LOG_ERR, "unable to start %s\n", DHCP_AGENT_PATH);
		/* make sure we try again next time there's a chance */
		pi->pi_ra_flags &= ~ND_RA_FLAG_MANAGED & ~ND_RA_FLAG_OTHER;
		return;
	}

	else if (pi->pi_ra_flags & ND_RA_FLAG_MANAGED)
		type = DHCP_START;
	else
		type = DHCP_INFORM;

	error = dhcp_op(pi, type);
	/*
	 * Timeout is considered to be "success" because we don't wait for DHCP
	 * to do its exchange.
	 */
	if (error != DHCP_IPC_SUCCESS && error != DHCP_IPC_E_RUNNING &&
	    error != DHCP_IPC_E_TIMEOUT) {
		logmsg(LOG_ERR, "Error in dhcpagent: %s: %s\n",
		    pi->pi_name, dhcp_ipc_strerror(error));
	}
}

/*
 * Release the acquired DHCPv6 lease on a given physical interface.
 * Does not wait for a message to be returned from the daemon.
 */
void
release_dhcp(struct phyint *pi)
{
	int	error;
	int	type;

	type = DHCP_RELEASE;
retry:
	error = dhcp_op(pi, type);
	if (error != DHCP_IPC_SUCCESS && error != DHCP_IPC_E_RUNNING &&
	    error != DHCP_IPC_E_TIMEOUT) {
		if (type == DHCP_RELEASE && error == DHCP_IPC_E_OUTSTATE) {
			/*
			 * Drop the dhcp control if we cannot release it.
			 */
			type = DHCP_DROP;
			goto retry;
		}
		logmsg(LOG_ERR, "Error in dhcpagent: %s: %s\n",
		    pi->pi_name, dhcp_ipc_strerror(error));
	}
}

/*
 * Globals to check if we're seeing unusual hop counts in Router
 * Advertisements (RAs).  We record the hopcounts in the kernel using
 * SIOCSLIFLNKINFO, but the kernel ignores these when actually setting IPv6
 * hop counts for packets.
 *
 * RFC 3756 does mention the possibility of an adversary throttling down
 * hopcounts using unsolicited RAs.  These variables can be tuned with 'mdb -p'
 * to reduce/increase our logging threshholds.
 */
/* Really a boolean... if set, also log the offending sending address. */
int bad_hopcount_record_addr = 0;
/* Anything less triggers a warning.  Set to 0 to disable. */
int bad_hopcount_threshhold = 16;
/* Number of packets received below the threshhold. */
uint64_t bad_hopcount_packets;

/*
 * Process a received router advertisement.
 * Called both when packets arrive as well as when we send RAs.
 * In the latter case 'loopback' is set.
 */
void
incoming_ra(struct phyint *pi, struct nd_router_advert *ra, int len,
    struct sockaddr_in6 *from, boolean_t loopback)
{
	struct nd_opt_hdr *opt;
	int optlen;
	struct lifreq lifr;
	boolean_t set_needed = _B_FALSE;
	struct router *dr;
	uint16_t router_lifetime;
	uint_t reachable, retrans;
	boolean_t reachable_time_changed = _B_FALSE;
	boolean_t slla_opt_present	 = _B_FALSE;

	if (no_loopback && loopback)
		return;

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));

	if (ra->nd_ra_curhoplimit != CURHOP_UNSPECIFIED &&
	    ra->nd_ra_curhoplimit != pi->pi_CurHopLimit) {
		pi->pi_CurHopLimit = ra->nd_ra_curhoplimit;
		lifr.lifr_ifinfo.lir_maxhops = pi->pi_CurHopLimit;
		set_needed = _B_TRUE;

		if (pi->pi_CurHopLimit < bad_hopcount_threshhold) {
			char abuf[INET6_ADDRSTRLEN];

			bad_hopcount_packets++;
			logmsg(LOG_ALERT,
			    "Low hopcount %d received on %s%s%s\n",
			    pi->pi_CurHopLimit, pi->pi_name,
			    bad_hopcount_record_addr ? " from " : "",
			    bad_hopcount_record_addr ?
			    inet_ntop(AF_INET6, &from->sin6_addr, abuf,
			    INET6_ADDRSTRLEN) : "");
		}
	}

	reachable = ntohl(ra->nd_ra_reachable);
	if (reachable != 0 &&
	    reachable != pi->pi_BaseReachableTime) {
		pi->pi_BaseReachableTime = reachable;
		reachable_time_changed = _B_TRUE;
	}

	if (pi->pi_reach_time_since_random < MIN_REACH_RANDOM_INTERVAL ||
	    reachable_time_changed) {
		phyint_reach_random(pi, _B_FALSE);
		set_needed = _B_TRUE;
	}
	lifr.lifr_ifinfo.lir_reachtime = pi->pi_ReachableTime;

	retrans = ntohl(ra->nd_ra_retransmit);
	if (retrans != 0 &&
	    pi->pi_RetransTimer != retrans) {
		pi->pi_RetransTimer = retrans;
		lifr.lifr_ifinfo.lir_reachretrans = pi->pi_RetransTimer;
		set_needed = _B_TRUE;
	}

	if (set_needed) {
		if (ioctl(pi->pi_sock, SIOCSLIFLNKINFO, (char *)&lifr) < 0) {
			logperror_pi(pi, "incoming_ra: SIOCSLIFLNKINFO");
			return;
		}
	}

	/*
	 * If the "managed" flag is set, then just assume that the "other" flag
	 * is set as well.  It's not legal to get addresses alone without
	 * getting other data.
	 */
	if (ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED)
		ra->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;

	/*
	 * If either the "managed" or "other" bits have turned on, then it's
	 * now time to invoke DHCP.  If only the "other" bit is set, then don't
	 * get addresses via DHCP; only "other" data.  If "managed" is set,
	 * then we must always get both addresses and "other" data.
	 */
	if (pi->pi_autoconf && pi->pi_stateful &&
	    (ra->nd_ra_flags_reserved & ~pi->pi_ra_flags &
	    (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER))) {
		if (debug & D_DHCP) {
			logmsg(LOG_DEBUG,
			    "incoming_ra: trigger dhcp %s on %s\n",
			    (ra->nd_ra_flags_reserved & ~pi->pi_ra_flags &
			    ND_RA_FLAG_MANAGED) ? "MANAGED" : "OTHER",
			    pi->pi_name);
		}
		pi->pi_ra_flags |= ra->nd_ra_flags_reserved;
		start_dhcp(pi);
	}

	/* Skip default router code if sent from ourselves */
	if (!loopback) {
		/* Find and update or add default router in list */
		dr = router_lookup(pi, from->sin6_addr);
		router_lifetime = ntohs(ra->nd_ra_router_lifetime);
		if (dr == NULL) {
			if (router_lifetime != 0) {
				dr = router_create(pi, from->sin6_addr,
				    MILLISEC * router_lifetime);
				timer_schedule(dr->dr_lifetime);
			}
		} else {
			dr->dr_lifetime = MILLISEC * router_lifetime;
			if (dr->dr_lifetime != 0)
				timer_schedule(dr->dr_lifetime);
			if ((dr->dr_lifetime != 0 && !dr->dr_inkernel) ||
			    (dr->dr_lifetime == 0 && dr->dr_inkernel))
				router_update_k(dr);
		}
	}
	/* Process any options */
	len -= sizeof (struct nd_router_advert);
	opt = (struct nd_opt_hdr *)&ra[1];
	while (len >= sizeof (struct nd_opt_hdr)) {
		optlen = opt->nd_opt_len * 8;
		switch (opt->nd_opt_type) {
		case ND_OPT_PREFIX_INFORMATION:
			incoming_prefix_opt(pi, (uchar_t *)opt, from,
			    loopback);
			break;
		case ND_OPT_MTU:
			incoming_mtu_opt(pi, (uchar_t *)opt, from);
			break;
		case ND_OPT_SOURCE_LINKADDR:
			/* skip lla option if sent from ourselves! */
			if (!loopback) {
				incoming_lla_opt(pi, (uchar_t *)opt,
				    from, NDF_ISROUTER_ON);
				slla_opt_present = _B_TRUE;
			}
			break;
		default:
			break;
		}
		opt = (struct nd_opt_hdr *)((char *)opt + optlen);
		len -= optlen;
	}
	if (!loopback && !slla_opt_present)
		update_ra_flag(pi, from, NDF_ISROUTER_ON);
	/* Stop sending solicitations */
	check_to_solicit(pi, SOLICIT_DONE);
}

/*
 * Process a received prefix option.
 * Unless addrconf is turned off we process both the addrconf and the
 * onlink aspects of the prefix option.
 *
 * Note that when a flag (onlink or auto) is turned off we do nothing -
 * the prefix will time out.
 */
static void
incoming_prefix_opt(struct phyint *pi, uchar_t *opt,
    struct sockaddr_in6 *from, boolean_t loopback)
{
	struct nd_opt_prefix_info *po = (struct nd_opt_prefix_info *)opt;
	boolean_t	good_prefix = _B_TRUE;

	if (8 * po->nd_opt_pi_len != sizeof (*po)) {
		char abuf[INET6_ADDRSTRLEN];

		(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
		    abuf, sizeof (abuf));
		logmsg(LOG_INFO, "prefix option from %s on %s wrong size "
		    "(%d bytes)\n",
		    abuf, pi->pi_name,
		    8 * (int)po->nd_opt_pi_len);
		return;
	}
	if (IN6_IS_ADDR_LINKLOCAL(&po->nd_opt_pi_prefix)) {
		char abuf[INET6_ADDRSTRLEN];

		(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
		    abuf, sizeof (abuf));
		logmsg(LOG_INFO, "RA from %s on %s contains link-local prefix "
		    "- ignored\n",
		    abuf, pi->pi_name);
		return;
	}
	if ((po->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) &&
	    pi->pi_stateless && pi->pi_autoconf) {
		good_prefix = incoming_prefix_addrconf(pi, opt, from, loopback);
	}
	if ((po->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) &&
	    good_prefix) {
		incoming_prefix_onlink(pi, opt);
	}
	if (pi->pi_stateful && pi->pi_autoconf)
		incoming_prefix_stateful(pi, opt);
}

/*
 * Process prefix options with the onlink flag set.
 *
 * If there are no routers ndpd will add an onlink
 * default route which will allow communication
 * between neighbors.
 *
 * This function needs to loop to find the same prefix multiple times
 * as if a failover happened earlier, the addresses belonging to
 * a different interface may be found here on this interface.
 */
static void
incoming_prefix_onlink(struct phyint *pi, uchar_t *opt)
{
	struct nd_opt_prefix_info *po = (struct nd_opt_prefix_info *)opt;
	int plen;
	struct prefix *pr;
	uint32_t validtime;	/* Without 2 hour rule */
	boolean_t found_one = _B_FALSE;

	plen = po->nd_opt_pi_prefix_len;
	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next) {
		if (pr->pr_prefix_len == plen &&
		    prefix_equal(po->nd_opt_pi_prefix, pr->pr_prefix, plen)) {
			/* Exclude static prefixes */
			if (pr->pr_state & PR_STATIC)
				continue;
			found_one = _B_TRUE;
			incoming_prefix_onlink_process(pr, opt);
		}
	}

	validtime = ntohl(po->nd_opt_pi_valid_time);
	/*
	 * If we have found a matching prefix already or validtime
	 * is zero, we have nothing to do.
	 */
	if (validtime == 0 || found_one)
		return;
	pr = prefix_create(pi, po->nd_opt_pi_prefix, plen, 0);
	if (pr == NULL)
		return;
	incoming_prefix_onlink_process(pr, opt);
}

void
incoming_prefix_onlink_process(struct prefix *pr, uchar_t *opt)
{
	struct nd_opt_prefix_info *po = (struct nd_opt_prefix_info *)opt;
	uint32_t validtime;	/* Without 2 hour rule */
	char abuf[INET6_ADDRSTRLEN];

	validtime = ntohl(po->nd_opt_pi_valid_time);
	if (validtime != 0)
		pr->pr_state |= PR_ONLINK;
	else
		pr->pr_state &= ~PR_ONLINK;

	/*
	 * Convert from seconds to milliseconds avoiding overflow.
	 * If the lifetime in the packet is e.g. PREFIX_INFINITY - 1
	 * (4 billion seconds - about 130 years) we will in fact time
	 * out the prefix after 4 billion milliseconds - 46 days).
	 * Thus the longest lifetime (apart from infinity) is 46 days.
	 * Note that this ensures that PREFIX_INFINITY still means "forever".
	 */
	if (pr->pr_flags & IFF_TEMPORARY) {
		pr->pr_OnLinkLifetime = pr->pr_ValidLifetime;
	} else {
		if (validtime >= PREFIX_INFINITY / MILLISEC)
			pr->pr_OnLinkLifetime = PREFIX_INFINITY - 1;
		else
			pr->pr_OnLinkLifetime = validtime * MILLISEC;
	}
	pr->pr_OnLinkFlag = _B_TRUE;
	if (debug & (D_PREFIX|D_TMP)) {
		logmsg(LOG_DEBUG, "incoming_prefix_onlink_process(%s, %s/%u) "
		    "onlink %u state 0x%x, kstate 0x%x\n",
		    pr->pr_name, inet_ntop(AF_INET6, (void *)&pr->pr_prefix,
		    abuf, sizeof (abuf)), pr->pr_prefix_len,
		    pr->pr_OnLinkLifetime, pr->pr_state, pr->pr_kernel_state);
	}

	if (pr->pr_kernel_state != pr->pr_state) {
		prefix_update_k(pr);
	}

	if (pr->pr_OnLinkLifetime != 0)
		timer_schedule(pr->pr_OnLinkLifetime);
}

/*
 * Process all prefix options by locating the DHCPv6-configured interfaces, and
 * applying the netmasks as needed.
 */
static void
incoming_prefix_stateful(struct phyint *pi, uchar_t *opt)
{
	struct nd_opt_prefix_info *po = (struct nd_opt_prefix_info *)opt;
	struct prefix *pr;
	boolean_t foundpref;
	char abuf[INET6_ADDRSTRLEN];

	/* Make sure it's a valid prefix. */
	if (ntohl(po->nd_opt_pi_valid_time) == 0) {
		if (debug & D_DHCP)
			logmsg(LOG_DEBUG, "incoming_prefix_stateful: ignoring "
			    "prefix with no valid time\n");
		return;
	}

	if (debug & D_DHCP)
		logmsg(LOG_DEBUG, "incoming_prefix_stateful(%s, %s/%d)\n",
		    pi->pi_name, inet_ntop(AF_INET6,
		    (void *)&po->nd_opt_pi_prefix, abuf, sizeof (abuf)),
		    po->nd_opt_pi_prefix_len);
	foundpref = _B_FALSE;
	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next) {
		if (prefix_equal(po->nd_opt_pi_prefix, pr->pr_prefix,
		    po->nd_opt_pi_prefix_len)) {
			if ((pr->pr_flags & IFF_DHCPRUNNING) &&
			    pr->pr_prefix_len != po->nd_opt_pi_prefix_len) {
				pr->pr_prefix_len = po->nd_opt_pi_prefix_len;
				if (pr->pr_flags & IFF_UP) {
					if (debug & D_DHCP)
						logmsg(LOG_DEBUG,
						    "incoming_prefix_stateful:"
						    " set mask on DHCP %s\n",
						    pr->pr_name);
					prefix_update_dhcp(pr);
				}
			}
			if (pr->pr_prefix_len == po->nd_opt_pi_prefix_len &&
			    (!(pr->pr_state & PR_STATIC) ||
			    (pr->pr_flags & IFF_DHCPRUNNING)))
				foundpref = _B_TRUE;
		}
	}
	/*
	 * If there's no matching DHCPv6 prefix present, then create an empty
	 * one so that we'll be able to configure it later.
	 */
	if (!foundpref) {
		pr = prefix_create(pi, po->nd_opt_pi_prefix,
		    po->nd_opt_pi_prefix_len, IFF_DHCPRUNNING);
		if (pr != NULL) {
			pr->pr_state = PR_STATIC;
			if (debug & D_DHCP)
				logmsg(LOG_DEBUG,
				    "incoming_prefix_stateful: created dummy "
				    "prefix for later\n");
		}
	}
}

/*
 * Process prefix options with the autonomous flag set.
 * Returns false if this prefix results in a bad address (duplicate)
 * This function needs to loop to find the same prefix multiple times
 * as if a failover happened earlier, the addresses belonging to
 * a different interface may be found here on this interface.
 */
static boolean_t
incoming_prefix_addrconf(struct phyint *pi, uchar_t *opt,
    struct sockaddr_in6 *from, boolean_t loopback)
{
	struct nd_opt_prefix_info *po = (struct nd_opt_prefix_info *)opt;
	int plen;
	struct prefix *pr;
	uint32_t validtime, preftime;	/* In seconds */
	char abuf[INET6_ADDRSTRLEN];
	char pbuf[INET6_ADDRSTRLEN];
	boolean_t found_pub = _B_FALSE;
	boolean_t found_tmp = _B_FALSE;
	boolean_t ret;

	validtime = ntohl(po->nd_opt_pi_valid_time);
	preftime = ntohl(po->nd_opt_pi_preferred_time);
	plen = po->nd_opt_pi_prefix_len;

	/* Sanity checks */
	if (validtime < preftime) {
		(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
		    abuf, sizeof (abuf));
		(void) inet_ntop(AF_INET6,
		    (void *)&po->nd_opt_pi_prefix,
		    pbuf, sizeof (pbuf));
		logmsg(LOG_WARNING, "prefix option %s/%u from %s on %s: "
		    "valid %u < pref %u ignored\n",
		    pbuf, plen, abuf, pi->pi_name,
		    validtime, preftime);
		return (_B_FALSE);
	}

	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next) {
		if (pr->pr_prefix_len == plen &&
		    prefix_equal(po->nd_opt_pi_prefix, pr->pr_prefix, plen)) {

			/* Exclude static prefixes and DHCP */
			if ((pr->pr_state & PR_STATIC) ||
			    (pr->pr_flags & IFF_DHCPRUNNING))
				continue;
			if (pr->pr_flags & IFF_TEMPORARY) {
				/*
				 * If this address is deprecated and its token
				 * doesn't match the current tmp token, we want
				 * to create a new address with the current
				 * token.  So don't count this addr as a match.
				 */
				if (!((pr->pr_flags & IFF_DEPRECATED) &&
				    !token_equal(pi->pi_tmp_token,
				    pr->pr_address, TMP_TOKEN_BITS)))
					found_tmp = _B_TRUE;
			} else {
				found_pub = _B_TRUE;
			}
			(void) incoming_prefix_addrconf_process(pi, pr, opt,
			    from, loopback, _B_FALSE);
		}
	}

	/*
	 * If we have found a matching prefix (for public and, if temp addrs
	 * are enabled, for temporary) already or validtime is zero, we have
	 * nothing to do.
	 */
	if (validtime == 0 ||
	    (found_pub && (!pi->pi_TmpAddrsEnabled || found_tmp)))
		return (_B_TRUE);

	if (!found_pub) {
		pr = prefix_create(pi, po->nd_opt_pi_prefix, plen, 0);
		if (pr == NULL)
			return (_B_TRUE);
		ret = incoming_prefix_addrconf_process(pi, pr, opt, from,
		    loopback, _B_TRUE);
	}
	/*
	 * if processing of the public address failed,
	 * don't bother with the temporary address.
	 */
	if (ret == _B_FALSE)
		return (_B_FALSE);

	if (pi->pi_TmpAddrsEnabled && !found_tmp) {
		pr = prefix_create(pi, po->nd_opt_pi_prefix, plen,
		    IFF_TEMPORARY);
		if (pr == NULL)
			return (_B_TRUE);
		ret = incoming_prefix_addrconf_process(pi, pr, opt, from,
		    loopback, _B_TRUE);
	}

	return (ret);
}

boolean_t
incoming_prefix_addrconf_process(struct phyint *pi, struct prefix *pr,
    uchar_t *opt, struct sockaddr_in6 *from, boolean_t loopback,
    boolean_t new_prefix)
{
	struct nd_opt_prefix_info *po = (struct nd_opt_prefix_info *)opt;
	char abuf[INET6_ADDRSTRLEN];
	char pbuf[INET6_ADDRSTRLEN];
	uint32_t validtime, preftime;	/* In seconds */
	uint32_t recorded_validtime;	/* In seconds */
	int plen;
	struct prefix *other_pr;

	validtime = ntohl(po->nd_opt_pi_valid_time);
	preftime = ntohl(po->nd_opt_pi_preferred_time);
	plen = po->nd_opt_pi_prefix_len;
	if (!new_prefix) {
		/*
		 * Check 2 hour rule on valid lifetime.
		 * Follows: RFC 2462
		 * If we advertised this prefix ourselves we skip
		 * these checks. They are also skipped if we did not
		 * previously do addrconf on this prefix.
		 */
		recorded_validtime = pr->pr_ValidLifetime / MILLISEC;

		if (loopback || !(pr->pr_state & PR_AUTO) ||
		    validtime >= MIN_VALID_LIFETIME ||
		    /* LINTED - statement has no consequent */
		    validtime >= recorded_validtime) {
			/* OK */
		} else if (recorded_validtime < MIN_VALID_LIFETIME &&
		    validtime < recorded_validtime) {
			/* Ignore the prefix */
			(void) inet_ntop(AF_INET6,
			    (void *)&from->sin6_addr,
			    abuf, sizeof (abuf));
			(void) inet_ntop(AF_INET6,
			    (void *)&po->nd_opt_pi_prefix,
			    pbuf, sizeof (pbuf));
			logmsg(LOG_INFO, "prefix option %s/%u from %s on %s: "
			    "too short valid lifetime %u stored %u "
			    "- ignored\n",
			    pbuf, plen, abuf, pi->pi_name,
			    validtime, recorded_validtime);
			return (_B_TRUE);
		} else {
			/*
			 * If the router clock runs slower than the
			 * host by 1 second over 2 hours then this
			 * test will set the lifetime back to 2 hours
			 * once i.e. a lifetime decrementing in
			 * realtime might cause the prefix to live an
			 * extra 2 hours on the host.
			 */
			(void) inet_ntop(AF_INET6,
			    (void *)&from->sin6_addr,
			    abuf, sizeof (abuf));
			(void) inet_ntop(AF_INET6,
			    (void *)&po->nd_opt_pi_prefix,
			    pbuf, sizeof (pbuf));
			logmsg(LOG_INFO, "prefix option %s/%u from %s on %s: "
			    "valid time %u stored %u rounded up "
			    "to %u\n",
			    pbuf, plen, abuf, pi->pi_name,
			    validtime, recorded_validtime,
			    MIN_VALID_LIFETIME);
			validtime = MIN_VALID_LIFETIME;
		}
	}

	/*
	 * For RFC3041 addresses, need to take token lifetime
	 * into account, too.
	 */
	if (pr->pr_flags & IFF_TEMPORARY) {
		uint_t	cur_tpreftime =
		    pi->pi_TmpPreferredLifetime - pi->pi_TmpDesyncFactor;

		if (new_prefix) {
			validtime = MIN(validtime, pi->pi_TmpValidLifetime);
			preftime = MIN(preftime, cur_tpreftime);
		} else {
			uint_t cur_vexp, cur_pexp, curtime;
			curtime = getcurrenttime() / MILLISEC;

			cur_vexp = pr->pr_CreateTime + pi->pi_TmpValidLifetime;
			cur_pexp = pr->pr_CreateTime + cur_tpreftime;
			if (curtime > cur_vexp)
				validtime = 0;
			else if ((curtime + validtime) > cur_vexp)
				validtime = cur_vexp - curtime;
			/*
			 * If this is an existing address which was deprecated
			 * because of a bad token, we don't want to update its
			 * preferred lifetime!
			 */
			if ((pr->pr_PreferredLifetime == 0) &&
			    !token_equal(pr->pr_address, pi->pi_tmp_token,
			    TMP_TOKEN_BITS))
				preftime = 0;
			else if (curtime > cur_pexp)
				preftime = 0;
			else if ((curtime + preftime) > cur_pexp)
				preftime = cur_pexp - curtime;
		}
		if ((preftime != 0) && (preftime <= pi->pi_TmpRegenAdvance)) {
			(void) inet_ntop(AF_INET6,
			    (void *)&from->sin6_addr,
			    abuf, sizeof (abuf));
			(void) inet_ntop(AF_INET6,
			    (void *)&po->nd_opt_pi_prefix,
			    pbuf, sizeof (pbuf));
			logmsg(LOG_WARNING, "prefix opt %s/%u from %s on %s: "
			    "preferred lifetime(%d) <= TmpRegenAdvance(%d)\n",
			    pbuf, plen, abuf, pi->pi_name, preftime,
			    pi->pi_TmpRegenAdvance);
			if (new_prefix) {
				prefix_update_ipadm_addrobj(pr, _B_FALSE);
				prefix_delete(pr);
			}
			return (_B_TRUE);
		}
	}
	if (debug & D_TMP)
		logmsg(LOG_DEBUG, "calculated lifetimes(%s, 0x%llx): v %d, "
		    "p %d\n", pr->pr_name, pr->pr_flags, validtime, preftime);

	if (!(pr->pr_state & PR_AUTO)) {
		int i, tokenlen;
		in6_addr_t *token;
		/*
		 * Form a new local address if the lengths match.
		 */
		if (pr->pr_flags & IFF_TEMPORARY) {
			if (IN6_IS_ADDR_UNSPECIFIED(&pi->pi_tmp_token)) {
				if (!tmptoken_create(pi)) {
					prefix_delete(pr);
					return (_B_TRUE);
				}
			}
			tokenlen = TMP_TOKEN_BITS;
			token = &pi->pi_tmp_token;
		} else {
			tokenlen = pi->pi_token_length;
			token = &pi->pi_token;
		}
		if (pr->pr_prefix_len + tokenlen != IPV6_ABITS) {
			(void) inet_ntop(AF_INET6,
			    (void *)&from->sin6_addr,
			    abuf, sizeof (abuf));
			(void) inet_ntop(AF_INET6,
			    (void *)&po->nd_opt_pi_prefix,
			    pbuf, sizeof (pbuf));
			logmsg(LOG_INFO, "prefix option %s/%u from %s on %s: "
			    "mismatched length %d token length %d\n",
			    pbuf, plen, abuf, pi->pi_name,
			    pr->pr_prefix_len, tokenlen);
			return (_B_TRUE);
		}
		for (i = 0; i < 16; i++) {
			/*
			 * prefix_create ensures that pr_prefix has all-zero
			 * bits after prefixlen.
			 */
			pr->pr_address.s6_addr[i] = pr->pr_prefix.s6_addr[i] |
			    token->s6_addr[i];
		}
		/*
		 * Check if any other physical interface has the same
		 * address configured already
		 */
		if ((other_pr = prefix_lookup_addr_match(pr)) != NULL) {
			/*
			 * Delete this prefix structure as kernel
			 * does not allow duplicated addresses
			 */
			logmsg(LOG_ERR, "incoming_prefix_addrconf_process: "
			    "Duplicate prefix %s received on interface %s\n",
			    inet_ntop(AF_INET6, &po->nd_opt_pi_prefix, abuf,
			    sizeof (abuf)), pi->pi_name);
			logmsg(LOG_ERR, "incoming_prefix_addrconf_process: "
			    "Prefix already exists in interface %s\n",
			    other_pr->pr_physical->pi_name);
			if (new_prefix) {
				prefix_update_ipadm_addrobj(pr, _B_FALSE);
				prefix_delete(pr);
				return (_B_FALSE);
			}
			/* Ignore for addrconf purposes */
			validtime = preftime = 0;
		}
		if ((pr->pr_flags & IFF_TEMPORARY) && new_prefix) {
			pr->pr_CreateTime = getcurrenttime() / MILLISEC;
			if (debug & D_TMP)
				logmsg(LOG_DEBUG,
				    "created tmp addr(%s v %d p %d)\n",
				    pr->pr_name, validtime, preftime);
		}
	}

	if (validtime != 0)
		pr->pr_state |= PR_AUTO;
	else
		pr->pr_state &= ~(PR_AUTO|PR_DEPRECATED);
	if (preftime != 0 || !(pr->pr_state & PR_AUTO))
		pr->pr_state &= ~PR_DEPRECATED;
	else
		pr->pr_state |= PR_DEPRECATED;

	/*
	 * Convert from seconds to milliseconds avoiding overflow.
	 * If the lifetime in the packet is e.g. PREFIX_INFINITY - 1
	 * (4 billion seconds - about 130 years) we will in fact time
	 * out the prefix after 4 billion milliseconds - 46 days).
	 * Thus the longest lifetime (apart from infinity) is 46 days.
	 * Note that this ensures that PREFIX_INFINITY still means "forever".
	 */
	if (validtime >= PREFIX_INFINITY / MILLISEC)
		pr->pr_ValidLifetime = PREFIX_INFINITY - 1;
	else
		pr->pr_ValidLifetime = validtime * MILLISEC;
	if (preftime >= PREFIX_INFINITY / MILLISEC)
		pr->pr_PreferredLifetime = PREFIX_INFINITY - 1;
	else
		pr->pr_PreferredLifetime = preftime * MILLISEC;
	pr->pr_AutonomousFlag = _B_TRUE;

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "incoming_prefix_addrconf_process(%s, %s/%u) "
		    "valid %u pref %u\n",
		    pr->pr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&pr->pr_prefix,
		    abuf, sizeof (abuf)), pr->pr_prefix_len,
		    pr->pr_ValidLifetime, pr->pr_PreferredLifetime);
	}

	if (pr->pr_state & PR_AUTO) {
		/* Take the min of the two timeouts by calling it twice */
		if (pr->pr_ValidLifetime != 0)
			timer_schedule(pr->pr_ValidLifetime);
		if (pr->pr_PreferredLifetime != 0)
			timer_schedule(pr->pr_PreferredLifetime);
	}
	if (pr->pr_kernel_state != pr->pr_state) {
		/* Log a message when an addrconf prefix goes away */
		if ((pr->pr_kernel_state & PR_AUTO) &&
		    !(pr->pr_state & PR_AUTO)) {
			char abuf[INET6_ADDRSTRLEN];

			logmsg(LOG_WARNING, "Address removed due to zero "
			    "valid lifetime %s\n",
			    inet_ntop(AF_INET6, (void *)&pr->pr_address,
			    abuf, sizeof (abuf)));
		}
		prefix_update_k(pr);
	}
	return (_B_TRUE);
}

/*
 * Process an MTU option received in a router advertisement.
 */
static void
incoming_mtu_opt(struct phyint *pi, uchar_t *opt,
    struct sockaddr_in6 *from)
{
	struct nd_opt_mtu *mo = (struct nd_opt_mtu *)opt;
	struct lifreq lifr;
	uint32_t mtu;

	if (8 * mo->nd_opt_mtu_len != sizeof (*mo)) {
		char abuf[INET6_ADDRSTRLEN];

		(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
		    abuf, sizeof (abuf));
		logmsg(LOG_INFO, "mtu option from %s on %s wrong size "
		    "(%d bytes)\n",
		    abuf, pi->pi_name,
		    8 * (int)mo->nd_opt_mtu_len);
		return;
	}
	mtu = ntohl(mo->nd_opt_mtu_mtu);
	if (pi->pi_LinkMTU == mtu)
		return;	/* No change */
	if (mtu > pi->pi_mtu) {
		/* Can't exceed physical MTU */
		char abuf[INET6_ADDRSTRLEN];

		(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
		    abuf, sizeof (abuf));
		logmsg(LOG_INFO, "mtu option from %s on %s too large "
		    "MTU %d - %d\n", abuf, pi->pi_name, mtu, pi->pi_mtu);
		return;
	}
	if (mtu < IPV6_MIN_MTU) {
		char abuf[INET6_ADDRSTRLEN];

		(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
		    abuf, sizeof (abuf));
		logmsg(LOG_INFO, "mtu option from %s on %s too small "
		    "MTU (%d)\n", abuf, pi->pi_name, mtu);
		return;
	}

	pi->pi_LinkMTU = mtu;
	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));
	lifr.lifr_ifinfo.lir_maxmtu = pi->pi_LinkMTU;
	if (ioctl(pi->pi_sock, SIOCSLIFLNKINFO, (char *)&lifr) < 0) {
		logperror_pi(pi, "incoming_mtu_opt: SIOCSLIFLNKINFO");
		return;
	}
}

/*
 * Process a source link-layer address option received in a router
 * advertisement or solicitation.
 */
static void
incoming_lla_opt(struct phyint *pi, uchar_t *opt,
    struct sockaddr_in6 *from, int isrouter)
{
	struct nd_opt_lla *lo = (struct nd_opt_lla *)opt;
	struct lifreq lifr;
	struct sockaddr_in6 *sin6;
	int max_content_len;

	/*
	 * Get our link-layer address length.  We may not have one, in which
	 * case we can just bail.
	 */
	if (phyint_get_lla(pi, &lifr) != 0)
		return;

	/*
	 * Can't remove padding since it is link type specific.
	 * However, we check against the length of our link-layer address.
	 * Note: assumes that all links have a fixed length address.
	 */
	max_content_len = lo->nd_opt_lla_len * 8 - sizeof (struct nd_opt_hdr);
	if (max_content_len < lifr.lifr_nd.lnr_hdw_len ||
	    (max_content_len >= 8 &&
	    max_content_len - 7 > lifr.lifr_nd.lnr_hdw_len)) {
		char abuf[INET6_ADDRSTRLEN];

		(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
		    abuf, sizeof (abuf));
		logmsg(LOG_INFO, "lla option from %s on %s too long with bad "
		    "physaddr length (%d vs. %d bytes)\n", abuf, pi->pi_name,
		    max_content_len, lifr.lifr_nd.lnr_hdw_len);
		return;
	}

	bcopy(lo->nd_opt_lla_hdw_addr, lifr.lifr_nd.lnr_hdw_addr,
	    lifr.lifr_nd.lnr_hdw_len);

	sin6 = (struct sockaddr_in6 *)&lifr.lifr_nd.lnr_addr;
	bzero(sin6, sizeof (struct sockaddr_in6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = from->sin6_addr;

	/*
	 * Set IsRouter flag if RA; clear if RS.
	 */
	lifr.lifr_nd.lnr_state_create = ND_STALE;
	lifr.lifr_nd.lnr_state_same_lla = ND_UNCHANGED;
	lifr.lifr_nd.lnr_state_diff_lla = ND_STALE;
	lifr.lifr_nd.lnr_flags = isrouter;
	(void) strlcpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));
	if (ioctl(pi->pi_sock, SIOCLIFSETND, (char *)&lifr) < 0) {
		logperror_pi(pi, "incoming_lla_opt: SIOCLIFSETND");
		return;
	}
}

/*
 * Verify the content of the received router advertisement against our
 * own configuration as specified in RFC 2461.
 */
static void
verify_ra_consistency(struct phyint *pi, struct nd_router_advert *ra, int len,
    struct sockaddr_in6 *from)
{
	char frombuf[INET6_ADDRSTRLEN];
	struct nd_opt_hdr *opt;
	int optlen;
	uint_t reachable, retrans;
	boolean_t pktflag, myflag;

	(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
	    frombuf, sizeof (frombuf));

	if (ra->nd_ra_curhoplimit != 0 &&
	    pi->pi_AdvCurHopLimit != 0 &&
	    ra->nd_ra_curhoplimit != pi->pi_AdvCurHopLimit) {
		logmsg(LOG_INFO, "RA from %s on %s inconsistent cur hop "
		    "limit:\n\treceived %d configuration %d\n",
		    frombuf, pi->pi_name,
		    ra->nd_ra_curhoplimit, pi->pi_AdvCurHopLimit);
	}

	reachable = ntohl(ra->nd_ra_reachable);
	if (reachable != 0 && pi->pi_AdvReachableTime != 0 &&
	    reachable != pi->pi_AdvReachableTime) {
		logmsg(LOG_INFO, "RA from %s on %s inconsistent reachable "
		    "time:\n\treceived %d configuration %d\n",
		    frombuf, pi->pi_name,
		    reachable, pi->pi_AdvReachableTime);
	}

	retrans = ntohl(ra->nd_ra_retransmit);
	if (retrans != 0 && pi->pi_AdvRetransTimer != 0 &&
	    retrans != pi->pi_AdvRetransTimer) {
		logmsg(LOG_INFO, "RA from %s on %s inconsistent retransmit "
		    "timer:\n\treceived %d configuration %d\n",
		    frombuf, pi->pi_name,
		    retrans, pi->pi_AdvRetransTimer);
	}

	pktflag = ((ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED) != 0);
	myflag = (pi->pi_AdvManagedFlag != 0);
	if (pktflag != myflag) {
		logmsg(LOG_INFO, "RA from %s on %s inconsistent managed "
		    "flag:\n\treceived %s configuration %s\n",
		    frombuf, pi->pi_name,
		    (pktflag ? "ON" : "OFF"),
		    (myflag ? "ON" : "OFF"));
	}
	pktflag = ((ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER) != 0);
	myflag = (pi->pi_AdvOtherConfigFlag != 0);
	if (pktflag != myflag) {
		logmsg(LOG_INFO, "RA from %s on %s inconsistent other config "
		    "flag:\n\treceived %s configuration %s\n",
		    frombuf, pi->pi_name,
		    (pktflag ? "ON" : "OFF"),
		    (myflag ? "ON" : "OFF"));
	}

	/* Process any options */
	len -= sizeof (struct nd_router_advert);
	opt = (struct nd_opt_hdr *)&ra[1];
	while (len >= sizeof (struct nd_opt_hdr)) {
		optlen = opt->nd_opt_len * 8;
		switch (opt->nd_opt_type) {
		case ND_OPT_PREFIX_INFORMATION:
			verify_prefix_opt(pi, (uchar_t *)opt, frombuf);
			break;
		case ND_OPT_MTU:
			verify_mtu_opt(pi, (uchar_t *)opt, frombuf);
			break;
		default:
			break;
		}
		opt = (struct nd_opt_hdr *)((char *)opt + optlen);
		len -= optlen;
	}
}

/*
 * Verify that the lifetimes and onlink/auto flags are consistent
 * with our settings.
 */
static void
verify_prefix_opt(struct phyint *pi, uchar_t *opt, char *frombuf)
{
	struct nd_opt_prefix_info *po = (struct nd_opt_prefix_info *)opt;
	int plen;
	struct adv_prefix *adv_pr;
	uint32_t validtime, preftime;
	char prefixbuf[INET6_ADDRSTRLEN];
	int pktflag, myflag;

	if (8 * po->nd_opt_pi_len != sizeof (*po)) {
		logmsg(LOG_INFO, "RA prefix option from %s on %s wrong size "
		    "(%d bytes)\n",
		    frombuf, pi->pi_name,
		    8 * (int)po->nd_opt_pi_len);
		return;
	}
	if (IN6_IS_ADDR_LINKLOCAL(&po->nd_opt_pi_prefix)) {
		logmsg(LOG_INFO, "RA from %s on %s contains link-local "
		    "prefix - ignored\n",
		    frombuf, pi->pi_name);
		return;
	}
	plen = po->nd_opt_pi_prefix_len;
	adv_pr = adv_prefix_lookup(pi, po->nd_opt_pi_prefix, plen);
	if (adv_pr == NULL)
		return;

	/* Ignore prefixes which we do not advertise */
	if (!adv_pr->adv_pr_AdvAutonomousFlag && !adv_pr->adv_pr_AdvOnLinkFlag)
		return;
	(void) inet_ntop(AF_INET6, (void *)&adv_pr->adv_pr_prefix,
	    prefixbuf, sizeof (prefixbuf));
	pktflag = ((po->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) != 0);
	myflag = (adv_pr->adv_pr_AdvAutonomousFlag != 0);
	if (pktflag != myflag) {
		logmsg(LOG_INFO,
		    "RA from %s on %s inconsistent autonomous flag for \n\t"
		    "prefix %s/%u: received %s configuration %s\n",
		    frombuf, pi->pi_name, prefixbuf, adv_pr->adv_pr_prefix_len,
		    (pktflag ? "ON" : "OFF"),
		    (myflag ? "ON" : "OFF"));
	}

	pktflag = ((po->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) != 0);
	myflag = (adv_pr->adv_pr_AdvOnLinkFlag != 0);
	if (pktflag != myflag) {
		logmsg(LOG_INFO, "RA from %s on %s inconsistent on link flag "
		    "for \n\tprefix %s/%u: received %s configuration %s\n",
		    frombuf, pi->pi_name, prefixbuf, adv_pr->adv_pr_prefix_len,
		    (pktflag ? "ON" : "OFF"),
		    (myflag ? "ON" : "OFF"));
	}
	validtime = ntohl(po->nd_opt_pi_valid_time);
	preftime = ntohl(po->nd_opt_pi_preferred_time);

	/*
	 * Take into account variation for lifetimes decrementing
	 * in real time. Allow +/- 10 percent and +/- 10 seconds.
	 */
#define	LOWER_LIMIT(val)	((val) - (val)/10 - 10)
#define	UPPER_LIMIT(val)	((val) + (val)/10 + 10)
	if (adv_pr->adv_pr_AdvValidRealTime) {
		if (adv_pr->adv_pr_AdvValidExpiration > 0 &&
		    (validtime <
		    LOWER_LIMIT(adv_pr->adv_pr_AdvValidExpiration) ||
		    validtime >
		    UPPER_LIMIT(adv_pr->adv_pr_AdvValidExpiration))) {
			logmsg(LOG_INFO, "RA from %s on %s inconsistent valid "
			    "lifetime for\n\tprefix %s/%u: received %d "
			    "configuration %d\n",
			    frombuf, pi->pi_name, prefixbuf,
			    adv_pr->adv_pr_prefix_len,
			    validtime, adv_pr->adv_pr_AdvValidExpiration);
		}
	} else {
		if (validtime != adv_pr->adv_pr_AdvValidLifetime) {
			logmsg(LOG_INFO, "RA from %s on %s inconsistent valid "
			    "lifetime for\n\tprefix %s/%u: received %d "
			    "configuration %d\n",
			    frombuf, pi->pi_name, prefixbuf,
			    adv_pr->adv_pr_prefix_len,
			    validtime, adv_pr->adv_pr_AdvValidLifetime);
		}
	}

	if (adv_pr->adv_pr_AdvPreferredRealTime) {
		if (adv_pr->adv_pr_AdvPreferredExpiration > 0 &&
		    (preftime <
		    LOWER_LIMIT(adv_pr->adv_pr_AdvPreferredExpiration) ||
		    preftime >
		    UPPER_LIMIT(adv_pr->adv_pr_AdvPreferredExpiration))) {
			logmsg(LOG_INFO, "RA from %s on %s inconsistent "
			    "preferred lifetime for\n\tprefix %s/%u: "
			    "received %d configuration %d\n",
			    frombuf, pi->pi_name, prefixbuf,
			    adv_pr->adv_pr_prefix_len,
			    preftime, adv_pr->adv_pr_AdvPreferredExpiration);
		}
	} else {
		if (preftime != adv_pr->adv_pr_AdvPreferredLifetime) {
			logmsg(LOG_INFO, "RA from %s on %s inconsistent "
			    "preferred lifetime for\n\tprefix %s/%u: "
			    "received %d configuration %d\n",
			    frombuf, pi->pi_name, prefixbuf,
			    adv_pr->adv_pr_prefix_len,
			    preftime, adv_pr->adv_pr_AdvPreferredLifetime);
		}
	}
}

/*
 * Verify the received MTU against our own configuration.
 */
static void
verify_mtu_opt(struct phyint *pi, uchar_t *opt, char *frombuf)
{
	struct nd_opt_mtu *mo = (struct nd_opt_mtu *)opt;
	uint32_t mtu;

	if (8 * mo->nd_opt_mtu_len != sizeof (*mo)) {
		logmsg(LOG_INFO, "mtu option from %s on %s wrong size "
		    "(%d bytes)\n",
		    frombuf, pi->pi_name,
		    8 * (int)mo->nd_opt_mtu_len);
		return;
	}
	mtu = ntohl(mo->nd_opt_mtu_mtu);
	if (pi->pi_AdvLinkMTU != 0 &&
	    pi->pi_AdvLinkMTU != mtu) {
		logmsg(LOG_INFO, "RA from %s on %s inconsistent MTU: "
		    "received %d configuration %d\n",
		    frombuf, pi->pi_name,
		    mtu, pi->pi_AdvLinkMTU);
	}
}

/*
 * Verify that all options have a non-zero length and that
 * the options fit within the total length of the packet (optlen).
 */
static boolean_t
verify_opt_len(struct nd_opt_hdr *opt, int optlen,
    struct phyint *pi, struct sockaddr_in6 *from)
{
	while (optlen > 0) {
		if (opt->nd_opt_len == 0) {
			char abuf[INET6_ADDRSTRLEN];

			(void) inet_ntop(AF_INET6,
			    (void *)&from->sin6_addr,
			    abuf, sizeof (abuf));

			logmsg(LOG_INFO, "Zero length option type 0x%x "
			    "from %s on %s\n",
			    opt->nd_opt_type, abuf, pi->pi_name);
			return (_B_FALSE);
		}
		optlen -= 8 * opt->nd_opt_len;
		if (optlen < 0) {
			char abuf[INET6_ADDRSTRLEN];

			(void) inet_ntop(AF_INET6,
			    (void *)&from->sin6_addr,
			    abuf, sizeof (abuf));

			logmsg(LOG_INFO, "Too large option: type 0x%x len %u "
			    "from %s on %s\n",
			    opt->nd_opt_type, opt->nd_opt_len,
			    abuf, pi->pi_name);
			return (_B_FALSE);
		}
		opt = (struct nd_opt_hdr *)((char *)opt +
		    8 * opt->nd_opt_len);
	}
	return (_B_TRUE);
}

/*
 * Update IsRouter Flag for Host turning into a router or vice-versa.
 */
static void
update_ra_flag(const struct phyint *pi, const struct sockaddr_in6 *from,
    int isrouter)
{
	struct lifreq lifr;
	char abuf[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6;

	/* check if valid flag is being set */
	if ((isrouter != NDF_ISROUTER_ON) &&
	    (isrouter != NDF_ISROUTER_OFF)) {
		logmsg(LOG_ERR, "update_ra_flag: Invalid IsRouter "
		    "flag %d\n", isrouter);
		return;
	}

	sin6 = (struct sockaddr_in6 *)&lifr.lifr_nd.lnr_addr;
	bzero(sin6, sizeof (*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = from->sin6_addr;

	(void) strlcpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));

	if (ioctl(pi->pi_sock, SIOCLIFGETND, (char *)&lifr) < 0) {
		if (errno == ESRCH) {
			if (debug & D_IFSCAN) {
				logmsg(LOG_DEBUG,
"update_ra_flag: SIOCLIFGETND: nce doesn't exist, not setting IFF_ROUTER");
			}
		} else {
			logperror_pi(pi, "update_ra_flag: SIOCLIFGETND");
		}
	} else {
		/*
		 * The lif_nd_req structure has three state values to be used
		 * when changing/updating nces :
		 * lnr_state_create, lnr_state_same_lla, and lnr_state_diff_lla.
		 *
		 * In this case, we're updating an nce, without changing lla;
		 * so we set lnr_state_same_lla to ND_UNCHANGED, indicating that
		 * nce's state should not be affected by our flag change.
		 *
		 * The kernel implementation also expects the lnr_state_create
		 * field be always set, before processing ioctl request for NCE
		 * update.
		 * We use the state as STALE, while addressing the possibility
		 * of NCE deletion when ioctl with SIOCLIFGETND argument
		 * in earlier step is returned - further in such case we don't
		 * want to re-create the entry in the reachable state.
		 */
		lifr.lifr_nd.lnr_state_create = ND_STALE;
		lifr.lifr_nd.lnr_state_same_lla = ND_UNCHANGED;
		lifr.lifr_nd.lnr_flags = isrouter;
		if ((ioctl(pi->pi_sock, SIOCLIFSETND, (char *)&lifr)) < 0) {
			logperror_pi(pi, "update_ra_flag: SIOCLIFSETND");
		} else {
			(void) inet_ntop(AF_INET6, (void *)&from->sin6_addr,
			    abuf, sizeof (abuf));
			logmsg(LOG_INFO, "update_ra_flag: IsRouter flag "
			    "updated for %s\n", abuf);
		}
	}
}
