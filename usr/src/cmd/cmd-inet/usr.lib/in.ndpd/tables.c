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
 *
 * Copyright 2024 Oxide Computer Company
 */

#include "defs.h"
#include "tables.h"

#include <time.h>
#include <assert.h>

struct phyint *phyints = NULL;
int num_of_phyints = 0;

static void	phyint_print(struct phyint *pi);
static void	phyint_insert(struct phyint *pi);

static boolean_t tmptoken_isvalid(struct in6_addr *token);

static void	prefix_print(struct prefix *pr);
static void	prefix_insert(struct phyint *pi, struct prefix *pr);
static char	*prefix_print_state(int state, char *buf, int buflen);
static void	prefix_set(struct in6_addr *prefix, struct in6_addr addr,
		    int bits);

static void	adv_prefix_print(struct adv_prefix *adv_pr);
static void	adv_prefix_insert(struct phyint *pi, struct adv_prefix *adv_pr);
static void	adv_prefix_delete(struct adv_prefix *adv_pr);

static void	router_print(struct router *dr);
static void	router_insert(struct phyint *pi, struct router *dr);
static void	router_delete(struct router *dr);
static void	router_add_k(struct router *dr);
static void	router_delete_k(struct router *dr);

static int	rtmseq;				/* rtm_seq sequence number */

/* 1 week in ms */
#define	NDP_PREFIX_DEFAULT_LIFETIME	(7*24*60*60*1000)
struct phyint *
phyint_lookup(char *name)
{
	struct phyint *pi;

	if (debug & D_PHYINT)
		logmsg(LOG_DEBUG, "phyint_lookup(%s)\n", name);

	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		if (strcmp(pi->pi_name, name) == 0)
			break;
	}
	return (pi);
}

struct phyint *
phyint_lookup_on_index(uint_t ifindex)
{
	struct phyint *pi;

	if (debug & D_PHYINT)
		logmsg(LOG_DEBUG, "phyint_lookup_on_index(%d)\n", ifindex);

	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		if (pi->pi_index == ifindex)
			break;
	}
	return (pi);
}

struct phyint *
phyint_create(char *name)
{
	struct phyint *pi;
	int i;

	if (debug & D_PHYINT)
		logmsg(LOG_DEBUG, "phyint_create(%s)\n", name);

	pi = (struct phyint *)calloc(sizeof (struct phyint), 1);
	if (pi == NULL) {
		logmsg(LOG_ERR, "phyint_create: out of memory\n");
		return (NULL);
	}
	(void) strncpy(pi->pi_name, name, sizeof (pi->pi_name));
	pi->pi_name[sizeof (pi->pi_name) - 1] = '\0';

	/*
	 * Copy the defaults from the defaults array.
	 * Do not copy the cf_notdefault fields since these have not
	 * been explicitly set for the phyint.
	 */
	for (i = 0; i < I_IFSIZE; i++)
		pi->pi_config[i].cf_value = ifdefaults[i].cf_value;

	/*
	 * TmpDesyncFactor is used to desynchronize temporary token
	 * generation among systems; the actual preferred lifetime value
	 * of a temporary address will be (TmpPreferredLifetime -
	 * TmpDesyncFactor).  It's a random value, with a user-configurable
	 * maximum value.  The value is constant throughout the lifetime
	 * of the in.ndpd process, but can change if the daemon is restarted,
	 * per RFC3041.
	 */
	if (pi->pi_TmpMaxDesyncFactor != 0) {
		time_t seed = time(NULL);
		srand((uint_t)seed);
		pi->pi_TmpDesyncFactor = rand() % pi->pi_TmpMaxDesyncFactor;
		/* we actually want [1,max], not [0,(max-1)] */
		pi->pi_TmpDesyncFactor++;
	}
	pi->pi_TmpRegenCountdown = TIMER_INFINITY;

	pi->pi_sock = -1;
	pi->pi_stateless = pi->pi_StatelessAddrConf;
	pi->pi_stateful = pi->pi_StatefulAddrConf;
	pi->pi_autoconf = _B_TRUE;
	pi->pi_default_token = _B_TRUE;
	if (phyint_init_from_k(pi) == -1) {
		free(pi);
		return (NULL);
	}
	phyint_insert(pi);
	if (pi->pi_sock != -1) {
		if (poll_add(pi->pi_sock) == -1) {
			phyint_delete(pi);
			return (NULL);
		}
	}
	return (pi);
}

/* Insert in linked list */
static void
phyint_insert(struct phyint *pi)
{
	/* Insert in list */
	pi->pi_next = phyints;
	pi->pi_prev = NULL;
	if (phyints)
		phyints->pi_prev = pi;
	phyints = pi;
	num_of_phyints++;
}

/*
 * Initialize both the phyint data structure and the pi_sock for
 * sending and receving on the interface.
 * Extract information from the kernel (if present) and set pi_kernel_state.
 */
int
phyint_init_from_k(struct phyint *pi)
{
	struct ipv6_mreq v6mcastr;
	struct lifreq lifr;
	int fd;
	int save_errno;
	boolean_t newsock;
	uint_t ttl;
	struct sockaddr_in6 *sin6;

	if (debug & D_PHYINT)
		logmsg(LOG_DEBUG, "phyint_init_from_k(%s)\n", pi->pi_name);

start_over:

	if (pi->pi_sock < 0) {
		pi->pi_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (pi->pi_sock < 0) {
			logperror_pi(pi, "phyint_init_from_k: socket");
			return (-1);
		}
		newsock = _B_TRUE;
	} else {
		newsock = _B_FALSE;
	}
	fd = pi->pi_sock;

	(void) strncpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
	if (ioctl(fd, SIOCGLIFINDEX, (char *)&lifr) < 0) {
		if (errno == ENXIO) {
			if (newsock) {
				(void) close(pi->pi_sock);
				pi->pi_sock = -1;
			}
			if (debug & D_PHYINT) {
				logmsg(LOG_DEBUG, "phyint_init_from_k(%s): "
				    "not exist\n", pi->pi_name);
			}
			return (0);
		}
		logperror_pi(pi, "phyint_init_from_k: SIOCGLIFINDEX");
		goto error;
	}

	if (!newsock && (pi->pi_index != lifr.lifr_index)) {
		/*
		 * Interface has been re-plumbed, lets open a new socket.
		 * This situation can occur if plumb/unplumb are happening
		 * quite frequently.
		 */

		phyint_cleanup(pi);
		goto start_over;
	}

	pi->pi_index = lifr.lifr_index;

	if (ioctl(fd, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		logperror_pi(pi, "phyint_init_from_k: ioctl (get flags)");
		goto error;
	}
	pi->pi_flags = lifr.lifr_flags;

	/*
	 * If the link local interface is not up yet or it's IFF_UP and the
	 * IFF_NOLOCAL flag is set, then ignore the interface.
	 */
	if (!(pi->pi_flags & IFF_UP) || (pi->pi_flags & IFF_NOLOCAL)) {
		if (newsock) {
			(void) close(pi->pi_sock);
			pi->pi_sock = -1;
		}

		if (debug & D_PHYINT) {
			logmsg(LOG_DEBUG, "phyint_init_from_k(%s): "
			    "IFF_NOLOCAL or not IFF_UP\n", pi->pi_name);
		}
		return (0);
	}
	pi->pi_kernel_state |= PI_PRESENT;

	if (ioctl(fd, SIOCGLIFMTU, (caddr_t)&lifr) < 0) {
		logperror_pi(pi, "phyint_init_from_k: ioctl (get mtu)");
		goto error;
	}
	pi->pi_mtu = lifr.lifr_mtu;

	if (ioctl(fd, SIOCGLIFADDR, (char *)&lifr) < 0) {
		logperror_pi(pi, "phyint_init_from_k: SIOCGLIFADDR");
		goto error;
	}
	sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
	pi->pi_ifaddr = sin6->sin6_addr;

	if (pi->pi_autoconf && pi->pi_default_token) {
		if (ioctl(fd, SIOCGLIFTOKEN, (char *)&lifr) < 0) {
			logperror_pi(pi, "phyint_init_from_k: SIOCGLIFTOKEN");
			goto error;
		}
		/* Ignore interface if the token is all zeros */
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_token;
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			logmsg(LOG_ERR, "ignoring interface %s: zero token\n",
			    pi->pi_name);
			goto error;
		}
		pi->pi_token = sin6->sin6_addr;
		pi->pi_token_length = lifr.lifr_addrlen;
	}

	/*
	 * Guess a remote token for POINTOPOINT by looking at
	 * the link-local destination address.
	 */
	if (pi->pi_flags & IFF_POINTOPOINT) {
		if (ioctl(fd, SIOCGLIFDSTADDR, (char *)&lifr) < 0) {
			logperror_pi(pi, "phyint_init_from_k: SIOCGLIFDSTADDR");
			goto error;
		}
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		if (sin6->sin6_family != AF_INET6 ||
		    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
		    !IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
			pi->pi_dst_token = in6addr_any;
		} else {
			pi->pi_dst_token = sin6->sin6_addr;
			/* Clear link-local prefix (first 10 bits) */
			pi->pi_dst_token.s6_addr[0] = 0;
			pi->pi_dst_token.s6_addr[1] &= 0x3f;
		}
	} else {
		pi->pi_dst_token = in6addr_any;
	}

	if (newsock) {
		icmp6_filter_t filter;
		int on = 1;

		/* Set default values */
		pi->pi_LinkMTU = pi->pi_mtu;
		pi->pi_CurHopLimit = 0;
		pi->pi_BaseReachableTime = ND_REACHABLE_TIME;
		phyint_reach_random(pi, _B_FALSE);
		pi->pi_RetransTimer = ND_RETRANS_TIMER;

		/* Setup socket for transmission and reception */
		if (setsockopt(fd, IPPROTO_IPV6,
		    IPV6_BOUND_IF, (char *)&pi->pi_index,
		    sizeof (pi->pi_index)) < 0) {
			logperror_pi(pi, "phyint_init_from_k: setsockopt "
			    "IPV6_BOUND_IF");
			goto error;
		}

		ttl = IPV6_MAX_HOPS;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
		    (char *)&ttl, sizeof (ttl)) < 0) {
			logperror_pi(pi, "phyint_init_from_k: setsockopt "
			    "IPV6_UNICAST_HOPS");
			goto error;
		}

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		    (char *)&ttl, sizeof (ttl)) < 0) {
			logperror_pi(pi, "phyint_init_from_k: setsockopt "
			    "IPV6_MULTICAST_HOPS");
			goto error;
		}

		v6mcastr.ipv6mr_multiaddr = all_nodes_mcast;
		v6mcastr.ipv6mr_interface = pi->pi_index;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		    (char *)&v6mcastr, sizeof (v6mcastr)) < 0) {
			/*
			 * One benign reason IPV6_JOIN_GROUP could fail is
			 * when `pi' has been placed into an IPMP group and we
			 * haven't yet processed the routing socket message
			 * informing us of its disappearance.  As such, if
			 * it's now in a group, don't print an error.
			 */
			save_errno = errno;
			(void) strlcpy(lifr.lifr_name, pi->pi_name, LIFNAMSIZ);
			if (ioctl(fd, SIOCGLIFGROUPNAME, &lifr) == -1 ||
			    lifr.lifr_groupname[0] == '\0') {
				errno = save_errno;
				logperror_pi(pi, "phyint_init_from_k: "
				    "setsockopt IPV6_JOIN_GROUP");
			}
			goto error;
		}
		pi->pi_state |= PI_JOINED_ALLNODES;
		pi->pi_kernel_state |= PI_JOINED_ALLNODES;

		/*
		 * Filter out so that we only receive router advertisements and
		 * router solicitations.
		 */
		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
		ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

		if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER,
		    (char *)&filter, sizeof (filter)) < 0) {
			logperror_pi(pi, "phyint_init_from_k: setsockopt "
			    "ICMP6_FILTER");
			goto error;
		}

		/* Enable receipt of ancillary data */
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		    (char *)&on, sizeof (on)) < 0) {
			logperror_pi(pi, "phyint_init_from_k: setsockopt "
			    "IPV6_RECVHOPLIMIT");
			goto error;
		}
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVRTHDR,
		    (char *)&on, sizeof (on)) < 0) {
			logperror_pi(pi, "phyint_init_from_k: setsockopt "
			    "IPV6_RECVRTHDR");
			goto error;
		}
	}

	if (pi->pi_AdvSendAdvertisements &&
	    !(pi->pi_kernel_state & PI_JOINED_ALLROUTERS)) {
		v6mcastr.ipv6mr_multiaddr = all_routers_mcast;
		v6mcastr.ipv6mr_interface = pi->pi_index;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		    (char *)&v6mcastr, sizeof (v6mcastr)) < 0) {
			/*
			 * See IPV6_JOIN_GROUP comment above.
			 */
			save_errno = errno;
			(void) strlcpy(lifr.lifr_name, pi->pi_name, LIFNAMSIZ);
			if (ioctl(fd, SIOCGLIFGROUPNAME, &lifr) == -1 ||
			    lifr.lifr_groupname[0] == '\0') {
				errno = save_errno;
				logperror_pi(pi, "phyint_init_from_k: "
				    "setsockopt IPV6_JOIN_GROUP");
			}
			goto error;
		}
		pi->pi_state |= PI_JOINED_ALLROUTERS;
		pi->pi_kernel_state |= PI_JOINED_ALLROUTERS;
	}
	/*
	 * If not already set, set the IFF_ROUTER interface flag based on
	 * AdvSendAdvertisements.  Note that this will also enable IPv6
	 * forwarding on the interface.  We don't clear IFF_ROUTER if we're
	 * not advertising on an interface, because we could still be
	 * forwarding on those interfaces.
	 */
	(void) strncpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
	if (ioctl(fd, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		logperror_pi(pi, "phyint_init_from_k: SIOCGLIFFLAGS");
		goto error;
	}
	if (!(lifr.lifr_flags & IFF_ROUTER) && pi->pi_AdvSendAdvertisements) {
		lifr.lifr_flags |= IFF_ROUTER;

		if (ioctl(fd, SIOCSLIFFLAGS, (char *)&lifr) < 0) {
			logperror_pi(pi, "phyint_init_from_k: SIOCSLIFFLAGS");
			goto error;
		}
		pi->pi_flags = lifr.lifr_flags;
	}

	/* Set linkinfo parameters */
	(void) strncpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
	lifr.lifr_ifinfo.lir_maxhops = pi->pi_CurHopLimit;
	lifr.lifr_ifinfo.lir_reachtime = pi->pi_ReachableTime;
	lifr.lifr_ifinfo.lir_reachretrans = pi->pi_RetransTimer;
	/* Setting maxmtu to 0 means that we're leaving the MTU alone */
	lifr.lifr_ifinfo.lir_maxmtu = 0;
	if (ioctl(fd, SIOCSLIFLNKINFO, (char *)&lifr) < 0) {
		logperror_pi(pi, "phyint_init_from_k: SIOCSLIFLNKINFO");
		goto error;
	}
	if (debug & D_PHYINT) {
		logmsg(LOG_DEBUG, "phyint_init_from_k(%s): done\n",
		    pi->pi_name);
	}
	return (0);

error:
	/* Pretend the interface does not exist in the kernel */
	pi->pi_kernel_state &= ~PI_PRESENT;
	if (newsock) {
		(void) close(pi->pi_sock);
		pi->pi_sock = -1;
	}
	return (-1);
}

/*
 * Delete (unlink and free).
 * Handles delete of things that have not yet been inserted in the list.
 */
void
phyint_delete(struct phyint *pi)
{
	if (debug & D_PHYINT)
		logmsg(LOG_DEBUG, "phyint_delete(%s)\n", pi->pi_name);

	assert(num_of_phyints > 0);

	while (pi->pi_router_list)
		router_delete(pi->pi_router_list);
	while (pi->pi_prefix_list) {
		prefix_update_ipadm_addrobj(pi->pi_prefix_list, _B_FALSE);
		prefix_delete(pi->pi_prefix_list);
	}
	while (pi->pi_adv_prefix_list)
		adv_prefix_delete(pi->pi_adv_prefix_list);

	if (pi->pi_sock != -1) {
		(void) poll_remove(pi->pi_sock);
		if (close(pi->pi_sock) < 0) {
			logperror_pi(pi, "phyint_delete: close");
		}
		pi->pi_sock = -1;
	}

	if (pi->pi_prev == NULL) {
		if (phyints == pi)
			phyints = pi->pi_next;
	} else {
		pi->pi_prev->pi_next = pi->pi_next;
	}
	if (pi->pi_next != NULL)
		pi->pi_next->pi_prev = pi->pi_prev;
	pi->pi_next = pi->pi_prev = NULL;
	free(pi);
	num_of_phyints--;
}

/*
 * Called with the number of milliseconds elapsed since the last call.
 * Determines if any timeout event has occurred and
 * returns the number of milliseconds until the next timeout event
 * for the phyint itself (excluding prefixes and routers).
 * Returns TIMER_INFINITY for "never".
 */
uint_t
phyint_timer(struct phyint *pi, uint_t elapsed)
{
	uint_t next = TIMER_INFINITY;

	if (pi->pi_AdvSendAdvertisements) {
		if (pi->pi_adv_state != NO_ADV) {
			int old_state = pi->pi_adv_state;

			if (debug & (D_STATE|D_PHYINT)) {
				logmsg(LOG_DEBUG, "phyint_timer ADV(%s) "
				    "state %d\n", pi->pi_name, (int)old_state);
			}
			next = advertise_event(pi, ADV_TIMER, elapsed);
			if (debug & D_STATE) {
				logmsg(LOG_DEBUG, "phyint_timer ADV(%s) "
				    "state %d -> %d\n",
				    pi->pi_name, (int)old_state,
				    (int)pi->pi_adv_state);
			}
		}
	} else {
		if (pi->pi_sol_state != NO_SOLICIT) {
			int old_state = pi->pi_sol_state;

			if (debug & (D_STATE|D_PHYINT)) {
				logmsg(LOG_DEBUG, "phyint_timer SOL(%s) "
				    "state %d\n", pi->pi_name, (int)old_state);
			}
			next = solicit_event(pi, SOL_TIMER, elapsed);
			if (debug & D_STATE) {
				logmsg(LOG_DEBUG, "phyint_timer SOL(%s) "
				    "state %d -> %d\n",
				    pi->pi_name, (int)old_state,
				    (int)pi->pi_sol_state);
			}
		}
	}

	/*
	 * If the phyint has been unplumbed, we don't want to call
	 * phyint_reach_random. We will be in the NO_ADV or NO_SOLICIT state.
	 */
	if ((pi->pi_AdvSendAdvertisements && (pi->pi_adv_state != NO_ADV)) ||
	    (!pi->pi_AdvSendAdvertisements &&
	    (pi->pi_sol_state != NO_SOLICIT))) {
		pi->pi_reach_time_since_random += elapsed;
		if (pi->pi_reach_time_since_random >= MAX_REACH_RANDOM_INTERVAL)
			phyint_reach_random(pi, _B_TRUE);
	}

	return (next);
}

static void
phyint_print(struct phyint *pi)
{
	struct prefix *pr;
	struct adv_prefix *adv_pr;
	struct router *dr;
	char abuf[INET6_ADDRSTRLEN];

	logmsg(LOG_DEBUG, "Phyint %s index %d state %x, kernel %x, "
	    "num routers %d\n",
	    pi->pi_name, pi->pi_index, pi->pi_state, pi->pi_kernel_state,
	    pi->pi_num_k_routers);
	logmsg(LOG_DEBUG, "\taddress: %s flags %llx\n",
	    inet_ntop(AF_INET6, (void *)&pi->pi_ifaddr,
	    abuf, sizeof (abuf)), pi->pi_flags);
	logmsg(LOG_DEBUG, "\tsock %d mtu %d\n", pi->pi_sock, pi->pi_mtu);
	logmsg(LOG_DEBUG, "\ttoken: len %d %s\n", pi->pi_token_length,
	    inet_ntop(AF_INET6, (void *)&pi->pi_token,
	    abuf, sizeof (abuf)));
	if (pi->pi_TmpAddrsEnabled) {
		logmsg(LOG_DEBUG, "\ttmp_token: %s\n",
		    inet_ntop(AF_INET6, (void *)&pi->pi_tmp_token,
		    abuf, sizeof (abuf)));
		logmsg(LOG_DEBUG, "\ttmp config: pref %d valid %d "
		    "maxdesync %d desync %d regen %d\n",
		    pi->pi_TmpPreferredLifetime, pi->pi_TmpValidLifetime,
		    pi->pi_TmpMaxDesyncFactor, pi->pi_TmpDesyncFactor,
		    pi->pi_TmpRegenAdvance);
	}
	if (pi->pi_flags & IFF_POINTOPOINT) {
		logmsg(LOG_DEBUG, "\tdst_token: %s\n",
		    inet_ntop(AF_INET6, (void *)&pi->pi_dst_token,
		    abuf, sizeof (abuf)));
	}
	logmsg(LOG_DEBUG, "\tLinkMTU %d CurHopLimit %d "
	    "BaseReachableTime %d\n\tReachableTime %d RetransTimer %d\n",
	    pi->pi_LinkMTU, pi->pi_CurHopLimit, pi->pi_BaseReachableTime,
	    pi->pi_ReachableTime, pi->pi_RetransTimer);
	if (!pi->pi_AdvSendAdvertisements) {
		/* Solicit state */
		logmsg(LOG_DEBUG, "\tSOLICIT: time_left %d state %d count %d\n",
		    pi->pi_sol_time_left, pi->pi_sol_state, pi->pi_sol_count);
	} else {
		/* Advertise state */
		logmsg(LOG_DEBUG, "\tADVERT: time_left %d state %d count %d "
		    "since last %d\n",
		    pi->pi_adv_time_left, pi->pi_adv_state, pi->pi_adv_count,
		    pi->pi_adv_time_since_sent);
		print_iflist(pi->pi_config);
	}
	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next)
		prefix_print(pr);

	for (adv_pr = pi->pi_adv_prefix_list; adv_pr != NULL;
	    adv_pr = adv_pr->adv_pr_next) {
		adv_prefix_print(adv_pr);
	}

	for (dr = pi->pi_router_list; dr != NULL; dr = dr->dr_next)
		router_print(dr);

	logmsg(LOG_DEBUG, "\n");
}


/*
 * Store the LLA for the phyint `pi' `lifrp'.  Returns 0 on success, or
 * -1 on failure.
 *
 * Note that we do not cache the hardware address since there's no reliable
 * mechanism to determine when it's become stale.
 */
int
phyint_get_lla(struct phyint *pi, struct lifreq *lifrp)
{
	struct sockaddr_in6 *sin6;

	/* If this phyint doesn't have a link-layer address, bail */
	if (!(pi->pi_flags & IFF_MULTICAST) ||
	    (pi->pi_flags & IFF_POINTOPOINT)) {
		return (-1);
	}

	(void) strlcpy(lifrp->lifr_name, pi->pi_name, LIFNAMSIZ);
	sin6 = (struct sockaddr_in6 *)&(lifrp->lifr_nd.lnr_addr);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = pi->pi_ifaddr;
	if (ioctl(pi->pi_sock, SIOCLIFGETND, lifrp) < 0) {
		/*
		 * For IPMP interfaces, don't report ESRCH errors since that
		 * merely indicates that there are no active interfaces in the
		 * IPMP group (and thus there's no working hardware address),
		 * and the packet will thus never make it out anyway.
		 */
		if (!(pi->pi_flags & IFF_IPMP) || errno != ESRCH)
			logperror_pi(pi, "phyint_get_lla: SIOCLIFGETND");
		return (-1);
	}
	return (0);
}

/*
 * Randomize pi->pi_ReachableTime.
 * Done periodically when there are no RAs and at a maximum frequency when
 * RA's arrive.
 * Assumes that caller has determined that it is time to generate
 * a new random ReachableTime.
 */
void
phyint_reach_random(struct phyint *pi, boolean_t set_needed)
{
	struct lifreq lifr;

	pi->pi_ReachableTime = GET_RANDOM(
	    (int)(ND_MIN_RANDOM_FACTOR * pi->pi_BaseReachableTime),
	    (int)(ND_MAX_RANDOM_FACTOR * pi->pi_BaseReachableTime));
	if (set_needed) {
		bzero(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, pi->pi_name, LIFNAMSIZ);
		lifr.lifr_ifinfo.lir_reachtime = pi->pi_ReachableTime;
		if (ioctl(pi->pi_sock, SIOCSLIFLNKINFO, (char *)&lifr) < 0) {
			logperror_pi(pi,
			    "phyint_reach_random: SIOCSLIFLNKINFO");
			return;
		}
	}
	pi->pi_reach_time_since_random = 0;
}

/*
 * Validate a temporary token against a list of known bad values.
 * Currently assumes that token is 8 bytes long!  Current known
 * bad values include 0, reserved anycast tokens (RFC 2526), tokens
 * used by ISATAP (draft-ietf-ngtrans-isatap-N), any token already
 * assigned to this interface, or any token for which the global
 * bit is set.
 *
 * Called by tmptoken_create().
 *
 * Return _B_TRUE if token is valid (no match), _B_FALSE if not.
 */
static boolean_t
tmptoken_isvalid(struct in6_addr *token)
{
	struct phyint *pi;
	struct in6_addr mask;
	struct in6_addr isatap = { 0, 0, 0, 0, 0, 0, 0, 0, \
				    0, 0, 0x5e, 0xfe, 0, 0, 0, 0 };
	struct in6_addr anycast = { 0, 0, 0, 0, \
				    0, 0, 0, 0, \
				    0xfd, 0xff, 0xff, 0xff, \
				    0xff, 0xff, 0xff, 0x80 };

	if (IN6_IS_ADDR_UNSPECIFIED(token))
		return (_B_FALSE);

	if (token->s6_addr[8] & 0x2)
		return (_B_FALSE);

	(void) memcpy(&mask, token, sizeof (mask));
	mask._S6_un._S6_u32[3] = 0;
	if (IN6_ARE_ADDR_EQUAL(&isatap, token))
		return (_B_FALSE);

	mask._S6_un._S6_u32[3] = token->_S6_un._S6_u32[3] & 0xffffff80;
	if (IN6_ARE_ADDR_EQUAL(&anycast, token))
		return (_B_FALSE);

	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		if (((pi->pi_token_length == TMP_TOKEN_BITS) &&
		    IN6_ARE_ADDR_EQUAL(&pi->pi_token, token)) ||
		    IN6_ARE_ADDR_EQUAL(&pi->pi_tmp_token, token))
			return (_B_FALSE);
	}

	/* none of our tests failed, must be a good one! */
	return (_B_TRUE);
}

/*
 * Generate a temporary token and set up its timer
 *
 * Called from incoming_prefix_addrconf_process() (when token is first
 * needed) and from tmptoken_timer() (when current token expires).
 *
 * Returns _B_TRUE if a token was successfully generated, _B_FALSE if not.
 */
boolean_t
tmptoken_create(struct phyint *pi)
{
	int fd, i = 0, max_tries = 15;
	struct in6_addr token;
	uint32_t *tokenp = &(token._S6_un._S6_u32[2]);
	char buf[INET6_ADDRSTRLEN];

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		perror("open /dev/urandom");
		goto no_token;
	}

	bzero((char *)&token, sizeof (token));
	do {
		if (read(fd, (void *)tokenp, TMP_TOKEN_BYTES) == -1) {
			perror("read /dev/urandom");
			(void) close(fd);
			goto no_token;
		}

		/*
		 * Assume EUI-64 formatting, and thus 64-bit
		 * token len; need to clear global bit.
		 */
		token.s6_addr[8] &= 0xfd;

		i++;

	} while (!tmptoken_isvalid(&token) && i < max_tries);

	(void) close(fd);

	if (i == max_tries) {
no_token:
		logmsg(LOG_WARNING, "tmptoken_create(%s): failed to create "
		    "token; disabling temporary addresses on %s\n",
		    pi->pi_name, pi->pi_name);
		pi->pi_TmpAddrsEnabled = 0;
		return (_B_FALSE);
	}

	pi->pi_tmp_token = token;

	if (debug & D_TMP)
		logmsg(LOG_DEBUG, "tmptoken_create(%s): created temporary "
		    "token %s\n", pi->pi_name,
		    inet_ntop(AF_INET6, &pi->pi_tmp_token, buf, sizeof (buf)));

	pi->pi_TmpRegenCountdown = (pi->pi_TmpPreferredLifetime -
	    pi->pi_TmpDesyncFactor - pi->pi_TmpRegenAdvance) * MILLISEC;
	if (pi->pi_TmpRegenCountdown != 0)
		timer_schedule(pi->pi_TmpRegenCountdown);

	return (_B_TRUE);
}

/*
 * Delete a temporary token.  This is outside the normal timeout process,
 * so mark any existing addresses based on this token DEPRECATED and set
 * their preferred lifetime to 0.  Don't tamper with valid lifetime, that
 * will be used to eventually remove the address.  Also reset the current
 * pi_tmp_token value to 0.
 *
 * Called from incoming_prefix_addrconf_process() if DAD fails on a temp
 * addr.
 */
void
tmptoken_delete(struct phyint *pi)
{
	struct prefix *pr;

	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next) {
		if (!(pr->pr_flags & IFF_TEMPORARY) ||
		    (pr->pr_flags & IFF_DEPRECATED) ||
		    (!token_equal(pr->pr_address, pi->pi_tmp_token,
		    TMP_TOKEN_BITS))) {
			continue;
		}
		pr->pr_PreferredLifetime = 0;
		pr->pr_state |= PR_DEPRECATED;
		prefix_update_k(pr);
	}

	(void) memset(&pi->pi_tmp_token, 0, sizeof (pi->pi_tmp_token));
}

/*
 * Called from run_timeouts() with the number of milliseconds elapsed
 * since the last call.  Determines if any timeout event has occurred
 * and returns the number of milliseconds until the next timeout event
 * for the tmp token.  Returns TIMER_INFINITY for "never".
 */
uint_t
tmptoken_timer(struct phyint *pi, uint_t elapsed)
{
	struct nd_opt_prefix_info opt;
	struct sockaddr_in6 sin6;
	struct prefix *pr, *newpr;

	if (debug & D_TMP) {
		logmsg(LOG_DEBUG, "tmptoken_timer(%s, %d) regencountdown %d\n",
		    pi->pi_name, (int)elapsed, pi->pi_TmpRegenCountdown);
	}
	if (!pi->pi_TmpAddrsEnabled ||
	    (pi->pi_TmpRegenCountdown == TIMER_INFINITY))
		return (TIMER_INFINITY);

	if (pi->pi_TmpRegenCountdown > elapsed) {
		pi->pi_TmpRegenCountdown -= elapsed;
		return (pi->pi_TmpRegenCountdown);
	}

	/*
	 * Tmp token timer has expired.  Start by generating a new token.
	 * If we can't get a new token, tmp addrs are disabled on this
	 * interface, so there's no need to continue, or to set a timer.
	 */
	if (!tmptoken_create(pi))
		return (TIMER_INFINITY);

	/*
	 * Now that we have a new token, walk the list of prefixes to
	 * find which ones need a corresponding tmp addr generated.
	 */
	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next) {

		if (!(pr->pr_state & PR_AUTO) || pr->pr_state & PR_STATIC ||
		    pr->pr_state & PR_DEPRECATED ||
		    pr->pr_flags & IFF_TEMPORARY)
			continue;

		newpr = prefix_create(pi, pr->pr_prefix, pr->pr_prefix_len,
		    IFF_TEMPORARY);
		if (newpr == NULL) {
			char pbuf[INET6_ADDRSTRLEN];
			char tbuf[INET6_ADDRSTRLEN];
			(void) inet_ntop(AF_INET6, &pr->pr_prefix, pbuf,
			    sizeof (pbuf));
			(void) inet_ntop(AF_INET6, &pi->pi_tmp_token, tbuf,
			    sizeof (tbuf));
			logmsg(LOG_ERR, "can't create new tmp addr "
			    "(%s, %s, %s)\n", pi->pi_name, pbuf, tbuf);
			continue;
		}

		/*
		 * We want to use incoming_prefix_*_process() functions to
		 * set up the new tmp addr, so cobble together a prefix
		 * info option struct based on the existing prefix to pass
		 * in.  The lifetimes will be based on the current time
		 * remaining.
		 *
		 * The "from" param is only used for messages; pass in
		 * ::0 for that.
		 */
		opt.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		opt.nd_opt_pi_len = sizeof (opt) / 8;
		opt.nd_opt_pi_prefix_len = pr->pr_prefix_len;
		opt.nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_AUTO;
		opt.nd_opt_pi_valid_time =
		    htonl(pr->pr_ValidLifetime / 1000);
		opt.nd_opt_pi_preferred_time =
		    htonl(pr->pr_PreferredLifetime / 1000);
		if (pr->pr_state & PR_ONLINK)
			opt.nd_opt_pi_flags_reserved &= ND_OPT_PI_FLAG_ONLINK;
		opt.nd_opt_pi_prefix = pr->pr_prefix;

		(void) memset(&sin6, 0, sizeof (sin6));

		if (!incoming_prefix_addrconf_process(pi, newpr,
		    (uchar_t *)&opt, &sin6, _B_FALSE, _B_TRUE)) {
			char pbuf[INET6_ADDRSTRLEN];
			char tbuf[INET6_ADDRSTRLEN];
			(void) inet_ntop(AF_INET6, &pr->pr_prefix, pbuf,
			    sizeof (pbuf));
			(void) inet_ntop(AF_INET6, &pi->pi_tmp_token, tbuf,
			    sizeof (tbuf));
			logmsg(LOG_ERR, "can't create new tmp addr "
			    "(%s, %s, %s)\n", pi->pi_name, pbuf, tbuf);
			continue;
		}

		if (pr->pr_state & PR_ONLINK) {
			incoming_prefix_onlink_process(newpr, (uchar_t *)&opt);
		}
	}

	/*
	 * appropriate timers were scheduled when
	 * the token and addresses were created.
	 */
	return (TIMER_INFINITY);
}

/*
 * tlen specifies the token length in bits.  Compares the lower
 * tlen bits of the two addresses provided and returns _B_TRUE if
 * they match, _B_FALSE if not.  Also returns _B_FALSE for invalid
 * values of tlen.
 */
boolean_t
token_equal(struct in6_addr t1, struct in6_addr t2, int tlen)
{
	uchar_t mask;
	int j, abytes, tbytes, tbits;

	if (tlen < 0 || tlen > IPV6_ABITS)
		return (_B_FALSE);

	abytes = IPV6_ABITS >> 3;
	tbytes = tlen >> 3;
	tbits = tlen & 7;

	for (j = abytes - 1; j >= abytes - tbytes; j--)
		if (t1.s6_addr[j] != t2.s6_addr[j])
			return (_B_FALSE);

	if (tbits == 0)
		return (_B_TRUE);

	/* We only care about the tbits rightmost bits */
	mask = 0xff >> (8 - tbits);
	if ((t1.s6_addr[j] & mask) != (t2.s6_addr[j] & mask))
		return (_B_FALSE);

	return (_B_TRUE);
}

/*
 * Lookup prefix structure that matches the prefix and prefix length.
 * Assumes that the bits after prefixlen might not be zero.
 */
static struct prefix *
prefix_lookup(struct phyint *pi, struct in6_addr prefix, int prefixlen)
{
	struct prefix *pr;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_lookup(%s, %s/%u)\n", pi->pi_name,
		    inet_ntop(AF_INET6, (void *)&prefix,
		    abuf, sizeof (abuf)), prefixlen);
	}

	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next) {
		if (pr->pr_prefix_len == prefixlen &&
		    prefix_equal(prefix, pr->pr_prefix, prefixlen))
			return (pr);
	}
	return (NULL);
}

/*
 * Compare two prefixes that have the same prefix length.
 * Fails if the prefix length is unreasonable.
 */
boolean_t
prefix_equal(struct in6_addr p1, struct in6_addr p2, int plen)
{
	uchar_t mask;
	int j, pbytes, pbits;

	if (plen < 0 || plen > IPV6_ABITS)
		return (_B_FALSE);

	pbytes = plen >> 3;
	pbits = plen & 7;

	for (j = 0; j < pbytes; j++)
		if (p1.s6_addr[j] != p2.s6_addr[j])
			return (_B_FALSE);

	if (pbits == 0)
		return (_B_TRUE);

	/* Make the N leftmost bits one */
	mask = 0xff << (8 - pbits);
	if ((p1.s6_addr[j] & mask) != (p2.s6_addr[j] & mask))
		return (_B_FALSE);

	return (_B_TRUE);
}

/*
 * Set a prefix from an address and a prefix length.
 * Force all the bits after the prefix length to be zero.
 */
void
prefix_set(struct in6_addr *prefix, struct in6_addr addr, int prefix_len)
{
	uchar_t mask;
	int j;

	if (prefix_len < 0 || prefix_len > IPV6_ABITS)
		return;

	bzero((char *)prefix, sizeof (*prefix));

	for (j = 0; prefix_len > 8; prefix_len -= 8, j++)
		prefix->s6_addr[j] = addr.s6_addr[j];

	/* Make the N leftmost bits one */
	mask = 0xff << (8 - prefix_len);
	prefix->s6_addr[j] = addr.s6_addr[j] & mask;
}

/*
 * Lookup a prefix based on the kernel's interface name.
 */
struct prefix *
prefix_lookup_name(struct phyint *pi, char *name)
{
	struct prefix *pr;

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_lookup_name(%s, %s)\n",
		    pi->pi_name, name);
	}
	if (name[0] == '\0')
		return (NULL);

	for (pr = pi->pi_prefix_list; pr != NULL; pr = pr->pr_next) {
		if (strcmp(name, pr->pr_name) == 0)
			return (pr);
	}
	return (NULL);
}

/*
 * Search the phyints list to make sure that this new prefix does
 * not already exist in any  other physical interfaces that have
 * the same address as this one
 */
struct prefix *
prefix_lookup_addr_match(struct prefix *pr)
{
	char abuf[INET6_ADDRSTRLEN];
	struct phyint *pi;
	struct prefix *otherpr = NULL;
	struct in6_addr prefix;
	int	prefixlen;

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_lookup_addr_match(%s/%u)\n",
		    inet_ntop(AF_INET6, (void *)&pr->pr_address,
		    abuf, sizeof (abuf)), pr->pr_prefix_len);
	}
	prefix = pr->pr_prefix;
	prefixlen = pr->pr_prefix_len;
	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		otherpr = prefix_lookup(pi, prefix, prefixlen);
		if (otherpr == pr)
			continue;
		if (otherpr != NULL && (otherpr->pr_state & PR_AUTO) &&
		    IN6_ARE_ADDR_EQUAL(&pr->pr_address,
		    &otherpr->pr_address))
			return (otherpr);
	}
	return (NULL);
}

/*
 * Initialize a new prefix without setting lifetimes etc.
 */
struct prefix *
prefix_create(struct phyint *pi, struct in6_addr prefix, int prefixlen,
    uint64_t flags)
{
	struct prefix *pr;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_create(%s, %s/%u, 0x%llx)\n",
		    pi->pi_name, inet_ntop(AF_INET6, (void *)&prefix,
		    abuf, sizeof (abuf)), prefixlen, flags);
	}
	pr = (struct prefix *)calloc(sizeof (struct prefix), 1);
	if (pr == NULL) {
		logmsg(LOG_ERR, "prefix_create: out of memory\n");
		return (NULL);
	}
	/*
	 * The prefix might have non-zero bits after the prefix len bits.
	 * Force them to be zero.
	 */
	prefix_set(&pr->pr_prefix, prefix, prefixlen);
	pr->pr_prefix_len = prefixlen;
	pr->pr_PreferredLifetime = PREFIX_INFINITY;
	pr->pr_ValidLifetime = PREFIX_INFINITY;
	pr->pr_OnLinkLifetime = PREFIX_INFINITY;
	pr->pr_kernel_state = 0;
	pr->pr_flags |= flags;
	prefix_insert(pi, pr);
	return (pr);
}

/*
 * Create a new named prefix. Caller should use prefix_init_from_k
 * to initialize the content.
 */
struct prefix *
prefix_create_name(struct phyint *pi, char *name)
{
	struct prefix *pr;

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_create_name(%s, %s)\n",
		    pi->pi_name, name);
	}
	pr = (struct prefix *)calloc(sizeof (struct prefix), 1);
	if (pr == NULL) {
		logmsg(LOG_ERR, "prefix_create_name: out of memory\n");
		return (NULL);
	}
	(void) strncpy(pr->pr_name, name, sizeof (pr->pr_name));
	pr->pr_name[sizeof (pr->pr_name) - 1] = '\0';
	prefix_insert(pi, pr);
	return (pr);
}

/* Insert in linked list */
static void
prefix_insert(struct phyint *pi, struct prefix *pr)
{
	pr->pr_next = pi->pi_prefix_list;
	pr->pr_prev = NULL;
	if (pi->pi_prefix_list != NULL)
		pi->pi_prefix_list->pr_prev = pr;
	pi->pi_prefix_list = pr;
	pr->pr_physical = pi;
}

/*
 * Initialize the prefix from the content of the kernel.
 * If IFF_ADDRCONF is set we treat it as PR_AUTO (i.e. an addrconf
 * prefix).  However, we cannot derive the lifetime from
 * the kernel, thus it is set to 1 week.
 * Ignore the prefix if the interface is not IFF_UP.
 * If it's from DHCPv6, then we set the netmask.
 */
int
prefix_init_from_k(struct prefix *pr)
{
	struct lifreq lifr;
	struct sockaddr_in6 *sin6;
	int sock = pr->pr_physical->pi_sock;

	(void) strncpy(lifr.lifr_name, pr->pr_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
	if (ioctl(sock, SIOCGLIFADDR, (char *)&lifr) < 0) {
		logperror_pr(pr, "prefix_init_from_k: ioctl (get addr)");
		goto error;
	}
	if (lifr.lifr_addr.ss_family != AF_INET6) {
		logmsg(LOG_ERR, "ignoring interface %s: not AF_INET6\n",
		    pr->pr_name);
		goto error;
	}
	sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
	pr->pr_address = sin6->sin6_addr;

	if (ioctl(sock, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		logperror_pr(pr, "prefix_init_from_k: ioctl (get flags)");
		goto error;
	}
	pr->pr_flags = lifr.lifr_flags;

	/*
	 * If this is a DHCPv6 interface, then we control the netmask.
	 */
	if (lifr.lifr_flags & IFF_DHCPRUNNING) {
		struct phyint *pi = pr->pr_physical;
		struct prefix *pr2;

		pr->pr_prefix_len = IPV6_ABITS;
		if (!(lifr.lifr_flags & IFF_UP) ||
		    IN6_IS_ADDR_UNSPECIFIED(&pr->pr_address) ||
		    IN6_IS_ADDR_LINKLOCAL(&pr->pr_address)) {
			if (debug & D_DHCP)
				logmsg(LOG_DEBUG, "prefix_init_from_k: "
				    "ignoring DHCP %s not ready\n",
				    pr->pr_name);
			return (0);
		}

		for (pr2 = pi->pi_prefix_list; pr2 != NULL;
		    pr2 = pr2->pr_next) {
			/*
			 * Examine any non-static (autoconfigured) prefixes as
			 * well as existing DHCP-controlled prefixes for valid
			 * prefix length information.
			 */
			if (pr2->pr_prefix_len != IPV6_ABITS &&
			    (!(pr2->pr_state & PR_STATIC) ||
			    (pr2->pr_flags & IFF_DHCPRUNNING)) &&
			    prefix_equal(pr->pr_prefix, pr2->pr_prefix,
			    pr2->pr_prefix_len)) {
				pr->pr_prefix_len = pr2->pr_prefix_len;
				break;
			}
		}
		if (pr2 == NULL) {
			if (debug & D_DHCP)
				logmsg(LOG_DEBUG, "prefix_init_from_k: no "
				    "saved mask for DHCP %s; need to "
				    "resolicit\n", pr->pr_name);
			(void) check_to_solicit(pi, RESTART_INIT_SOLICIT);
		} else {
			if (debug & D_DHCP)
				logmsg(LOG_DEBUG, "prefix_init_from_k: using "
				    "%s mask for DHCP %s\n",
				    pr2->pr_name[0] == '\0' ? "saved" :
				    pr2->pr_name, pr->pr_name);
			prefix_update_dhcp(pr);
		}
		/*
		 * If this interface was created using ipadm, store the
		 * addrobj for the DHCPv6 interface in ipmgmtd daemon's
		 * in-memory aobjmap.
		 */
		prefix_update_ipadm_addrobj(pr, _B_TRUE);
	} else {
		if (ioctl(sock, SIOCGLIFSUBNET, (char *)&lifr) < 0) {
			logperror_pr(pr,
			    "prefix_init_from_k: ioctl (get subnet)");
			goto error;
		}
		if (lifr.lifr_subnet.ss_family != AF_INET6) {
			logmsg(LOG_ERR,
			    "ignoring interface %s: not AF_INET6\n",
			    pr->pr_name);
			goto error;
		}
		/*
		 * Guard against the prefix having non-zero bits after the
		 * prefix len bits.
		 */
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_subnet;
		pr->pr_prefix_len = lifr.lifr_addrlen;
		prefix_set(&pr->pr_prefix, sin6->sin6_addr, pr->pr_prefix_len);

		if (pr->pr_prefix_len != IPV6_ABITS &&
		    (pr->pr_flags & IFF_UP) &&
		    IN6_ARE_ADDR_EQUAL(&pr->pr_address, &pr->pr_prefix)) {
			char abuf[INET6_ADDRSTRLEN];

			logmsg(LOG_ERR, "ignoring interface %s: it appears to "
			    "be configured with an invalid interface id "
			    "(%s/%u)\n",
			    pr->pr_name,
			    inet_ntop(AF_INET6, (void *)&pr->pr_address,
			    abuf, sizeof (abuf)), pr->pr_prefix_len);
			goto error;
		}
	}
	pr->pr_kernel_state = 0;
	if (pr->pr_prefix_len != IPV6_ABITS)
		pr->pr_kernel_state |= PR_ONLINK;
	if (!(pr->pr_flags & (IFF_NOLOCAL | IFF_DHCPRUNNING)))
		pr->pr_kernel_state |= PR_AUTO;
	if ((pr->pr_flags & IFF_DEPRECATED) && (pr->pr_kernel_state & PR_AUTO))
		pr->pr_kernel_state |= PR_DEPRECATED;
	if (!(pr->pr_flags & IFF_ADDRCONF)) {
		/* Prevent ndpd from stepping on this prefix */
		pr->pr_kernel_state |= PR_STATIC;
	}
	pr->pr_state = pr->pr_kernel_state;
	/* Adjust pr_prefix_len based if PR_AUTO is set */
	if (pr->pr_state & PR_AUTO) {
		pr->pr_prefix_len =
		    IPV6_ABITS - pr->pr_physical->pi_token_length;
		prefix_set(&pr->pr_prefix, pr->pr_prefix, pr->pr_prefix_len);
	}

	/* Can't extract lifetimes from the kernel - use 1 week */
	pr->pr_ValidLifetime = NDP_PREFIX_DEFAULT_LIFETIME;
	pr->pr_PreferredLifetime = NDP_PREFIX_DEFAULT_LIFETIME;
	pr->pr_OnLinkLifetime = NDP_PREFIX_DEFAULT_LIFETIME;

	/*
	 * If this is a temp addr, the creation time needs to be set.
	 * Though it won't be entirely accurate, the current time is
	 * an okay approximation.
	 */
	if (pr->pr_flags & IFF_TEMPORARY)
		pr->pr_CreateTime = getcurrenttime() / MILLISEC;

	if (pr->pr_kernel_state == 0)
		pr->pr_name[0] = '\0';
	return (0);

error:
	/* Pretend that the prefix does not exist in the kernel */
	pr->pr_kernel_state = 0;
	pr->pr_name[0] = '\0';
	return (-1);
}

/*
 * Delete (unlink and free) and remove from kernel if the prefix
 * was added by in.ndpd (i.e. PR_STATIC is not set).
 * Handles delete of things that have not yet been inserted in the list
 * i.e. pr_physical is NULL.
 * Removes the ipadm addrobj created for the prefix.
 */
void
prefix_delete(struct prefix *pr)
{
	struct phyint *pi;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_delete(%s, %s, %s/%u)\n",
		    pr->pr_physical->pi_name, pr->pr_name,
		    inet_ntop(AF_INET6, (void *)&pr->pr_prefix,
		    abuf, sizeof (abuf)), pr->pr_prefix_len);
	}
	pi = pr->pr_physical;

	/* Remove non-static prefixes from the kernel. */
	pr->pr_state &= PR_STATIC;
	if (pr->pr_kernel_state != pr->pr_state)
		prefix_update_k(pr);

	if (pr->pr_prev == NULL) {
		if (pi != NULL)
			pi->pi_prefix_list = pr->pr_next;
	} else {
		pr->pr_prev->pr_next = pr->pr_next;
	}
	if (pr->pr_next != NULL)
		pr->pr_next->pr_prev = pr->pr_prev;
	pr->pr_next = pr->pr_prev = NULL;

	free(pr);
}

/*
 * Toggle one or more IFF_ flags for a prefix. Turn on 'onflags' and
 * turn off 'offflags'.
 */
static int
prefix_modify_flags(struct prefix *pr, uint64_t onflags, uint64_t offflags)
{
	struct lifreq lifr;
	struct phyint *pi = pr->pr_physical;
	uint64_t old_flags;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_modify_flags(%s, %s, %s/%u) "
		    "flags %llx on %llx off %llx\n",
		    pr->pr_physical->pi_name,
		    pr->pr_name,
		    inet_ntop(AF_INET6, (void *)&pr->pr_prefix,
		    abuf, sizeof (abuf)), pr->pr_prefix_len,
		    pr->pr_flags, onflags, offflags);
	}
	/* Assumes that only the PR_STATIC link-local matches the pi_name */
	if (!(pr->pr_state & PR_STATIC) &&
	    strcmp(pr->pr_name, pi->pi_name) == 0) {
		logmsg(LOG_ERR, "prefix_modify_flags(%s, on %llx, off %llx): "
		    "name matches interface name\n",
		    pi->pi_name, onflags, offflags);
		return (-1);
	}

	(void) strncpy(lifr.lifr_name, pr->pr_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
	if (ioctl(pi->pi_sock, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		if (errno != ENXIO) {
			logperror_pr(pr, "prefix_modify_flags: SIOCGLIFFLAGS");
			logmsg(LOG_ERR, "prefix_modify_flags(%s, %s) old 0x%llx"
			    " on 0x%llx off 0x%llx\n", pr->pr_physical->pi_name,
			    pr->pr_name, pr->pr_flags, onflags, offflags);
		}
		return (-1);
	}
	old_flags = lifr.lifr_flags;
	lifr.lifr_flags |= onflags;
	lifr.lifr_flags &= ~offflags;
	pr->pr_flags = lifr.lifr_flags;
	if (ioctl(pi->pi_sock, SIOCSLIFFLAGS, (char *)&lifr) < 0) {
		if (errno != ENXIO) {
			logperror_pr(pr, "prefix_modify_flags: SIOCSLIFFLAGS");
			logmsg(LOG_ERR, "prefix_modify_flags(%s, %s) old 0x%llx"
			    " new 0x%llx on 0x%llx off 0x%llx\n",
			    pr->pr_physical->pi_name, pr->pr_name,
			    old_flags, lifr.lifr_flags, onflags, offflags);
		}
		return (-1);
	}
	return (0);
}

/*
 * Update the subnet mask for this interface under DHCPv6 control.
 */
void
prefix_update_dhcp(struct prefix *pr)
{
	struct lifreq lifr;

	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, pr->pr_name, sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = AF_INET6;
	prefix_set(&((struct sockaddr_in6 *)&lifr.lifr_addr)->sin6_addr,
	    pr->pr_address, pr->pr_prefix_len);
	lifr.lifr_addrlen = pr->pr_prefix_len;
	/*
	 * Ignore ENXIO, as the dhcpagent process is responsible for plumbing
	 * and unplumbing these.
	 */
	if (ioctl(pr->pr_physical->pi_sock, SIOCSLIFSUBNET, (char *)&lifr) ==
	    -1 && errno != ENXIO)
		logperror_pr(pr, "prefix_update_dhcp: ioctl (set subnet)");
}

/*
 * Make the kernel state match what is in the prefix structure.
 * This includes creating the prefix (allocating a new interface name)
 * as well as setting the local address and on-link subnet prefix
 * and controlling the IFF_ADDRCONF and IFF_DEPRECATED flags.
 */
void
prefix_update_k(struct prefix *pr)
{
	struct lifreq lifr;
	char abuf[INET6_ADDRSTRLEN];
	char buf1[PREFIX_STATESTRLEN], buf2[PREFIX_STATESTRLEN];
	struct phyint *pi = pr->pr_physical;
	struct sockaddr_in6 *sin6;

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "prefix_update_k(%s, %s, %s/%u) "
		    "from %s to %s\n", pr->pr_physical->pi_name, pr->pr_name,
		    inet_ntop(AF_INET6, (void *)&pr->pr_prefix,
		    abuf, sizeof (abuf)), pr->pr_prefix_len,
		    prefix_print_state(pr->pr_kernel_state, buf1,
		    sizeof (buf1)),
		    prefix_print_state(pr->pr_state, buf2, sizeof (buf2)));
	}

	if (pr->pr_kernel_state == pr->pr_state)
		return;		/* No changes */

	/* Skip static prefixes */
	if (pr->pr_state & PR_STATIC)
		return;

	if (pr->pr_kernel_state == 0) {
		uint64_t onflags;
		/*
		 * Create a new logical interface name and store in pr_name.
		 * Set IFF_ADDRCONF. Do not set an address (yet).
		 */
		if (pr->pr_name[0] != '\0') {
			/* Name already set! */
			logmsg(LOG_ERR, "prefix_update_k(%s, %s, %s/%u) "
			    "from %s to %s name is already allocated\n",
			    pr->pr_physical->pi_name, pr->pr_name,
			    inet_ntop(AF_INET6, (void *)&pr->pr_prefix,
			    abuf, sizeof (abuf)), pr->pr_prefix_len,
			    prefix_print_state(pr->pr_kernel_state, buf1,
			    sizeof (buf1)),
			    prefix_print_state(pr->pr_state, buf2,
			    sizeof (buf2)));
			return;
		}

		(void) strncpy(lifr.lifr_name, pi->pi_name,
		    sizeof (lifr.lifr_name));
		lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
		lifr.lifr_addr.ss_family = AF_UNSPEC;
		if (ioctl(pi->pi_sock, SIOCLIFADDIF, (char *)&lifr) < 0) {
			logperror_pr(pr, "prefix_update_k: SIOCLIFADDIF");
			return;
		}
		(void) strncpy(pr->pr_name, lifr.lifr_name,
		    sizeof (pr->pr_name));
		pr->pr_name[sizeof (pr->pr_name) - 1] = '\0';
		if (debug & D_PREFIX) {
			logmsg(LOG_DEBUG, "prefix_update_k: new name %s\n",
			    pr->pr_name);
		}
		/*
		 * The IFF_TEMPORARY flag might have already been set; if
		 * so, it needs to be or'd into the flags we're turning on.
		 * But be careful, we might be re-creating a manually
		 * removed interface, in which case we don't want to try
		 * to set *all* the flags we might have in our copy of the
		 * flags yet.
		 */
		onflags = IFF_ADDRCONF;
		if (pr->pr_flags & IFF_TEMPORARY)
			onflags |= IFF_TEMPORARY;
		if (prefix_modify_flags(pr, onflags, 0) == -1)
			return;
	}
	if ((pr->pr_state & (PR_ONLINK|PR_AUTO)) == 0) {
		/* Remove the interface */
		if (prefix_modify_flags(pr, 0, IFF_UP|IFF_DEPRECATED) == -1)
			return;
		(void) strncpy(lifr.lifr_name, pr->pr_name,
		    sizeof (lifr.lifr_name));
		lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';

		if (debug & D_PREFIX) {
			logmsg(LOG_DEBUG, "prefix_update_k: remove name %s\n",
			    pr->pr_name);
		}

		/*
		 * Assumes that only the PR_STATIC link-local matches
		 * the pi_name
		 */
		if (!(pr->pr_state & PR_STATIC) &&
		    strcmp(pr->pr_name, pi->pi_name) == 0) {
			logmsg(LOG_ERR, "prefix_update_k(%s): "
			    "name matches if\n", pi->pi_name);
			return;
		}

		/* Remove logical interface based on pr_name */
		lifr.lifr_addr.ss_family = AF_UNSPEC;
		if (ioctl(pi->pi_sock, SIOCLIFREMOVEIF, (char *)&lifr) < 0 &&
		    errno != ENXIO) {
			logperror_pr(pr, "prefix_update_k: SIOCLIFREMOVEIF");
		}
		pr->pr_kernel_state = 0;
		pr->pr_name[0] = '\0';
		return;
	}
	if ((pr->pr_state & PR_AUTO) && !(pr->pr_kernel_state & PR_AUTO)) {
		/*
		 * Set local address and set the prefix length to 128.
		 * Turn off IFF_NOLOCAL in case it was set.
		 * Turn on IFF_UP.
		 */
		(void) strncpy(lifr.lifr_name, pr->pr_name,
		    sizeof (lifr.lifr_name));
		lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		bzero(sin6, sizeof (struct sockaddr_in6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = pr->pr_address;
		if (debug & D_PREFIX) {
			logmsg(LOG_DEBUG, "prefix_update_k(%s) set addr %s "
			    "for PR_AUTO on\n",
			    pr->pr_name,
			    inet_ntop(AF_INET6, (void *)&pr->pr_address,
			    abuf, sizeof (abuf)));
		}
		if (ioctl(pi->pi_sock, SIOCSLIFADDR, (char *)&lifr) < 0) {
			logperror_pr(pr, "prefix_update_k: SIOCSLIFADDR");
			return;
		}
		/*
		 * If this interface was created using ipadm, store the
		 * addrobj for the prefix in ipmgmtd daemon's aobjmap.
		 */
		prefix_update_ipadm_addrobj(pr, _B_TRUE);
		if (pr->pr_state & PR_ONLINK) {
			sin6->sin6_addr = pr->pr_prefix;
			lifr.lifr_addrlen = pr->pr_prefix_len;
		} else {
			sin6->sin6_addr = pr->pr_address;
			lifr.lifr_addrlen = IPV6_ABITS;
		}
		if (debug & D_PREFIX) {
			logmsg(LOG_DEBUG, "prefix_update_k(%s) set subnet "
			    "%s/%u for PR_AUTO on\n", pr->pr_name,
			    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    abuf, sizeof (abuf)), lifr.lifr_addrlen);
		}
		if (ioctl(pi->pi_sock, SIOCSLIFSUBNET, (char *)&lifr) < 0) {
			logperror_pr(pr, "prefix_update_k: SIOCSLIFSUBNET");
			return;
		}
		/*
		 * For ptp interfaces, create a destination based on
		 * prefix and prefix len together with the remote token
		 * extracted from the remote pt-pt address.  This is used by
		 * ip to choose a proper source for outgoing packets.
		 */
		if (pi->pi_flags & IFF_POINTOPOINT) {
			int i;

			sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
			bzero(sin6, sizeof (struct sockaddr_in6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = pr->pr_prefix;
			for (i = 0; i < 16; i++) {
				sin6->sin6_addr.s6_addr[i] |=
				    pi->pi_dst_token.s6_addr[i];
			}
			if (debug & D_PREFIX) {
				logmsg(LOG_DEBUG, "prefix_update_k(%s) "
				    "set dstaddr %s for PR_AUTO on\n",
				    pr->pr_name, inet_ntop(AF_INET6,
				    (void *)&sin6->sin6_addr,
				    abuf, sizeof (abuf)));
			}
			if (ioctl(pi->pi_sock, SIOCSLIFDSTADDR,
			    (char *)&lifr) < 0) {
				logperror_pr(pr,
				    "prefix_update_k: SIOCSLIFDSTADDR");
				return;
			}
		}
		if (prefix_modify_flags(pr, IFF_UP, IFF_NOLOCAL) == -1)
			return;
		pr->pr_kernel_state |= PR_AUTO;
		if (pr->pr_state & PR_ONLINK)
			pr->pr_kernel_state |= PR_ONLINK;
		else
			pr->pr_kernel_state &= ~PR_ONLINK;
	}
	if (!(pr->pr_state & PR_AUTO) && (pr->pr_kernel_state & PR_AUTO)) {
		/* Turn on IFF_NOLOCAL and set the local address to all zero */
		if (prefix_modify_flags(pr, IFF_NOLOCAL, 0) == -1)
			return;
		(void) strncpy(lifr.lifr_name, pr->pr_name,
		    sizeof (lifr.lifr_name));
		lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		bzero(sin6, sizeof (struct sockaddr_in6));
		sin6->sin6_family = AF_INET6;
		if (debug & D_PREFIX) {
			logmsg(LOG_DEBUG, "prefix_update_k(%s) set addr %s "
			    "for PR_AUTO off\n", pr->pr_name,
			    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    abuf, sizeof (abuf)));
		}
		if (ioctl(pi->pi_sock, SIOCSLIFADDR, (char *)&lifr) < 0) {
			logperror_pr(pr, "prefix_update_k: SIOCSLIFADDR");
			return;
		}
		pr->pr_kernel_state &= ~PR_AUTO;
	}
	if ((pr->pr_state & PR_DEPRECATED) &&
	    !(pr->pr_kernel_state & PR_DEPRECATED) &&
	    (pr->pr_kernel_state & PR_AUTO)) {
		/* Only applies if PR_AUTO */
		if (prefix_modify_flags(pr, IFF_DEPRECATED, 0) == -1)
			return;
		pr->pr_kernel_state |= PR_DEPRECATED;
	}
	if (!(pr->pr_state & PR_DEPRECATED) &&
	    (pr->pr_kernel_state & PR_DEPRECATED)) {
		if (prefix_modify_flags(pr, 0, IFF_DEPRECATED) == -1)
			return;
		pr->pr_kernel_state &= ~PR_DEPRECATED;
	}
	if ((pr->pr_state & PR_ONLINK) && !(pr->pr_kernel_state & PR_ONLINK)) {
		/* Set the subnet and set IFF_UP */
		(void) strncpy(lifr.lifr_name, pr->pr_name,
		    sizeof (lifr.lifr_name));
		lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		bzero(sin6, sizeof (struct sockaddr_in6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = pr->pr_prefix;
		lifr.lifr_addrlen = pr->pr_prefix_len;
		if (debug & D_PREFIX) {
			logmsg(LOG_DEBUG, "prefix_update_k(%s) set subnet "
			    "%s/%d for PR_ONLINK on\n", pr->pr_name,
			    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    abuf, sizeof (abuf)), lifr.lifr_addrlen);
		}
		if (ioctl(pi->pi_sock, SIOCSLIFSUBNET, (char *)&lifr) < 0) {
			logperror_pr(pr, "prefix_update_k: SIOCSLIFSUBNET");
			return;
		}
		/*
		 * If we've previously marked the interface "up" while
		 * processing the PR_AUTO flag -- via incoming_prefix_addrconf
		 * -- then there's no need to set it "up" again.  We're done;
		 * just set PR_ONLINK to indicate that we've set the subnet.
		 */
		if (!(pr->pr_state & PR_AUTO) &&
		    prefix_modify_flags(pr, IFF_UP | IFF_NOLOCAL, 0) == -1)
			return;
		pr->pr_kernel_state |= PR_ONLINK;
	}
	if (!(pr->pr_state & PR_ONLINK) && (pr->pr_kernel_state & PR_ONLINK)) {
		/* Set the prefixlen to 128 */
		(void) strncpy(lifr.lifr_name, pr->pr_name,
		    sizeof (lifr.lifr_name));
		lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		bzero(sin6, sizeof (struct sockaddr_in6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = pr->pr_address;
		lifr.lifr_addrlen = IPV6_ABITS;
		if (debug & D_PREFIX) {
			logmsg(LOG_DEBUG, "prefix_update_k(%s) set subnet "
			    "%s/%d for PR_ONLINK off\n", pr->pr_name,
			    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    abuf, sizeof (abuf)), lifr.lifr_addrlen);
		}
		if (ioctl(pi->pi_sock, SIOCSLIFSUBNET, (char *)&lifr) < 0) {
			logperror_pr(pr, "prefix_update_k: SIOCSLIFSUBNET");
			return;
		}
		pr->pr_kernel_state &= ~PR_ONLINK;
	}
}

/*
 * Called with the number of millseconds elapsed since the last call.
 * Determines if any timeout event has occurred and
 * returns the number of milliseconds until the next timeout event.
 * Returns TIMER_INFINITY for "never".
 */
uint_t
prefix_timer(struct prefix *pr, uint_t elapsed)
{
	uint_t next = TIMER_INFINITY;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & (D_PREFIX|D_TMP)) {
		logmsg(LOG_DEBUG, "prefix_timer(%s, %s/%u, %d) "
		    "valid %d pref %d onlink %d\n",
		    pr->pr_name,
		    inet_ntop(AF_INET6, (void *)&pr->pr_prefix,
		    abuf, sizeof (abuf)), pr->pr_prefix_len,
		    elapsed, pr->pr_ValidLifetime, pr->pr_PreferredLifetime,
		    pr->pr_OnLinkLifetime);
	}

	/* Exclude static prefixes */
	if (pr->pr_state & PR_STATIC)
		return (next);

	if (pr->pr_AutonomousFlag &&
	    (pr->pr_PreferredLifetime != PREFIX_INFINITY)) {
		if (pr->pr_PreferredLifetime <= elapsed) {
			pr->pr_PreferredLifetime = 0;
		} else {
			pr->pr_PreferredLifetime -= elapsed;
			if (pr->pr_PreferredLifetime < next)
				next = pr->pr_PreferredLifetime;
		}
	}
	if (pr->pr_AutonomousFlag &&
	    (pr->pr_ValidLifetime != PREFIX_INFINITY)) {
		if (pr->pr_ValidLifetime <= elapsed) {
			pr->pr_ValidLifetime = 0;
		} else {
			pr->pr_ValidLifetime -= elapsed;
			if (pr->pr_ValidLifetime < next)
				next = pr->pr_ValidLifetime;
		}
	}
	if (pr->pr_OnLinkFlag &&
	    (pr->pr_OnLinkLifetime != PREFIX_INFINITY)) {
		if (pr->pr_OnLinkLifetime <= elapsed) {
			pr->pr_OnLinkLifetime = 0;
		} else {
			pr->pr_OnLinkLifetime -= elapsed;
			if (pr->pr_OnLinkLifetime < next)
				next = pr->pr_OnLinkLifetime;
		}
	}
	if (pr->pr_AutonomousFlag && pr->pr_ValidLifetime == 0)
		pr->pr_state &= ~(PR_AUTO|PR_DEPRECATED);
	if (pr->pr_AutonomousFlag && pr->pr_PreferredLifetime == 0 &&
	    (pr->pr_state & PR_AUTO)) {
		pr->pr_state |= PR_DEPRECATED;
		if (debug & D_TMP)
			logmsg(LOG_WARNING, "prefix_timer: deprecated "
			    "prefix(%s)\n", pr->pr_name);
	}
	if (pr->pr_OnLinkFlag && pr->pr_OnLinkLifetime == 0)
		pr->pr_state &= ~PR_ONLINK;

	if (pr->pr_state != pr->pr_kernel_state) {
		/* Might cause prefix to be deleted! */

		/* Log a message when an addrconf prefix goes away */
		if ((pr->pr_kernel_state & PR_AUTO) &&
		    !(pr->pr_state & PR_AUTO)) {
			char abuf[INET6_ADDRSTRLEN];

			logmsg(LOG_WARNING,
			    "Address removed due to timeout %s\n",
			    inet_ntop(AF_INET6, (void *)&pr->pr_address,
			    abuf, sizeof (abuf)));
		}
		prefix_update_k(pr);
	}

	return (next);
}

static char *
prefix_print_state(int state, char *buf, int buflen)
{
	char *cp;
	int cplen = buflen;

	cp = buf;
	cp[0] = '\0';

	if (state & PR_ONLINK) {
		if (strlcat(cp, "ONLINK ", cplen) >= cplen)
			return (buf);
		cp += strlen(cp);
		cplen = buflen - (cp - buf);
	}
	if (state & PR_AUTO) {
		if (strlcat(cp, "AUTO ", cplen) >= cplen)
			return (buf);
		cp += strlen(cp);
		cplen = buflen - (cp - buf);
	}
	if (state & PR_DEPRECATED) {
		if (strlcat(cp, "DEPRECATED ", cplen) >= cplen)
			return (buf);
		cp += strlen(cp);
		cplen = buflen - (cp - buf);
	}
	if (state & PR_STATIC) {
		if (strlcat(cp, "STATIC ", cplen) >= cplen)
			return (buf);
		cp += strlen(cp);
		cplen = buflen - (cp - buf);
	}
	return (buf);
}

static void
prefix_print(struct prefix *pr)
{
	char abuf[INET6_ADDRSTRLEN];
	char buf1[PREFIX_STATESTRLEN], buf2[PREFIX_STATESTRLEN];

	logmsg(LOG_DEBUG, "Prefix name: %s prefix %s/%u state %s "
	    "kernel_state %s\n", pr->pr_name,
	    inet_ntop(AF_INET6, (void *)&pr->pr_prefix, abuf, sizeof (abuf)),
	    pr->pr_prefix_len,
	    prefix_print_state(pr->pr_state, buf2, sizeof (buf2)),
	    prefix_print_state(pr->pr_kernel_state, buf1, sizeof (buf1)));
	logmsg(LOG_DEBUG, "\tAddress: %s flags %llx in_use %d\n",
	    inet_ntop(AF_INET6, (void *)&pr->pr_address, abuf, sizeof (abuf)),
	    pr->pr_flags, pr->pr_in_use);
	logmsg(LOG_DEBUG, "\tValidLifetime %u PreferredLifetime %u "
	    "OnLinkLifetime %u\n", pr->pr_ValidLifetime,
	    pr->pr_PreferredLifetime, pr->pr_OnLinkLifetime);
	logmsg(LOG_DEBUG, "\tOnLink %d Auto %d\n",
	    pr->pr_OnLinkFlag, pr->pr_AutonomousFlag);
	logmsg(LOG_DEBUG, "\n");
}

/*
 * Lookup advertisement prefix structure that matches the prefix and
 * prefix length.
 * Assumes that the bits after prefixlen might not be zero.
 */
struct adv_prefix *
adv_prefix_lookup(struct phyint *pi, struct in6_addr prefix, int prefixlen)
{
	struct adv_prefix *adv_pr;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "adv_prefix_lookup(%s, %s/%u)\n",
		    pi->pi_name, inet_ntop(AF_INET6, (void *)&prefix,
		    abuf, sizeof (abuf)), prefixlen);
	}

	for (adv_pr = pi->pi_adv_prefix_list; adv_pr != NULL;
	    adv_pr = adv_pr->adv_pr_next) {
		if (adv_pr->adv_pr_prefix_len == prefixlen &&
		    prefix_equal(prefix, adv_pr->adv_pr_prefix, prefixlen))
			return (adv_pr);
	}
	return (NULL);
}

/*
 * Initialize a new advertisement prefix.
 */
struct adv_prefix *
adv_prefix_create(struct phyint *pi, struct in6_addr prefix, int prefixlen)
{
	struct adv_prefix *adv_pr;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "adv_prefix_create(%s, %s/%u)\n",
		    pi->pi_name, inet_ntop(AF_INET6, (void *)&prefix,
		    abuf, sizeof (abuf)), prefixlen);
	}
	adv_pr = (struct adv_prefix *)calloc(sizeof (struct adv_prefix), 1);
	if (adv_pr == NULL) {
		logmsg(LOG_ERR, "adv_prefix_create: calloc\n");
		return (NULL);
	}
	/*
	 * The prefix might have non-zero bits after the prefix len bits.
	 * Force them to be zero.
	 */
	prefix_set(&adv_pr->adv_pr_prefix, prefix, prefixlen);
	adv_pr->adv_pr_prefix_len = prefixlen;
	adv_prefix_insert(pi, adv_pr);
	return (adv_pr);
}

/* Insert in linked list */
static void
adv_prefix_insert(struct phyint *pi, struct adv_prefix *adv_pr)
{
	adv_pr->adv_pr_next = pi->pi_adv_prefix_list;
	adv_pr->adv_pr_prev = NULL;
	if (pi->pi_adv_prefix_list != NULL)
		pi->pi_adv_prefix_list->adv_pr_prev = adv_pr;
	pi->pi_adv_prefix_list = adv_pr;
	adv_pr->adv_pr_physical = pi;
}

/*
 * Delete (unlink and free) from our tables. There should be
 * a corresponding "struct prefix *" which will clean up the kernel
 * if necessary. adv_prefix is just used for sending out advertisements.
 */
static void
adv_prefix_delete(struct adv_prefix *adv_pr)
{
	struct phyint *pi;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "adv_prefix_delete(%s, %s/%u)\n",
		    adv_pr->adv_pr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&adv_pr->adv_pr_prefix,
		    abuf, sizeof (abuf)), adv_pr->adv_pr_prefix_len);
	}
	pi = adv_pr->adv_pr_physical;

	if (adv_pr->adv_pr_prev == NULL) {
		if (pi != NULL)
			pi->pi_adv_prefix_list = adv_pr->adv_pr_next;
	} else {
		adv_pr->adv_pr_prev->adv_pr_next = adv_pr->adv_pr_next;
	}
	if (adv_pr->adv_pr_next != NULL)
		adv_pr->adv_pr_next->adv_pr_prev = adv_pr->adv_pr_prev;
	adv_pr->adv_pr_next = adv_pr->adv_pr_prev = NULL;
	free(adv_pr);
}

/*
 * Called with the number of millseconds elapsed since the last call.
 * Determines if any timeout event has occurred and
 * returns the number of milliseconds until the next timeout event.
 * Returns TIMER_INFINITY for "never".
 */
uint_t
adv_prefix_timer(struct adv_prefix *adv_pr, uint_t elapsed)
{
	int seconds_elapsed = (elapsed + 500) / 1000;	/* Rounded */
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_PREFIX) {
		logmsg(LOG_DEBUG, "adv_prefix_timer(%s, %s/%u, %d)\n",
		    adv_pr->adv_pr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&adv_pr->adv_pr_prefix,
		    abuf, sizeof (abuf)), adv_pr->adv_pr_prefix_len,
		    elapsed);
	}

	/* Decrement Expire time left for real-time lifetimes */
	if (adv_pr->adv_pr_AdvValidRealTime) {
		if (adv_pr->adv_pr_AdvValidExpiration > seconds_elapsed)
			adv_pr->adv_pr_AdvValidExpiration -= seconds_elapsed;
		else
			adv_pr->adv_pr_AdvValidExpiration = 0;
	}
	if (adv_pr->adv_pr_AdvPreferredRealTime) {
		if (adv_pr->adv_pr_AdvPreferredExpiration > seconds_elapsed) {
			adv_pr->adv_pr_AdvPreferredExpiration -=
			    seconds_elapsed;
		} else {
			adv_pr->adv_pr_AdvPreferredExpiration = 0;
		}
	}
	return (TIMER_INFINITY);
}

static void
adv_prefix_print(struct adv_prefix *adv_pr)
{
	print_prefixlist(adv_pr->adv_pr_config);
}

/* Lookup router on its link-local IPv6 address */
struct router *
router_lookup(struct phyint *pi, struct in6_addr addr)
{
	struct router *dr;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_ROUTER) {
		logmsg(LOG_DEBUG, "router_lookup(%s, %s)\n", pi->pi_name,
		    inet_ntop(AF_INET6, (void *)&addr,
		    abuf, sizeof (abuf)));
	}

	for (dr = pi->pi_router_list; dr != NULL; dr = dr->dr_next) {
		if (bcmp((char *)&addr, (char *)&dr->dr_address,
		    sizeof (addr)) == 0)
			return (dr);
	}
	return (NULL);
}

/*
 * Create a default router entry.
 * The lifetime parameter is in seconds.
 */
struct router *
router_create(struct phyint *pi, struct in6_addr addr, uint_t lifetime)
{
	struct router *dr;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_ROUTER) {
		logmsg(LOG_DEBUG, "router_create(%s, %s, %u)\n", pi->pi_name,
		    inet_ntop(AF_INET6, (void *)&addr,
		    abuf, sizeof (abuf)), lifetime);
	}

	dr = (struct router *)calloc(sizeof (struct router), 1);
	if (dr == NULL) {
		logmsg(LOG_ERR, "router_create: out of memory\n");
		return (NULL);
	}
	dr->dr_address = addr;
	dr->dr_lifetime = lifetime;
	router_insert(pi, dr);
	if (dr->dr_lifetime != 0)
		router_add_k(dr);
	return (dr);
}

/* Insert in linked list */
static void
router_insert(struct phyint *pi, struct router *dr)
{
	dr->dr_next = pi->pi_router_list;
	dr->dr_prev = NULL;
	if (pi->pi_router_list != NULL)
		pi->pi_router_list->dr_prev = dr;
	pi->pi_router_list = dr;
	dr->dr_physical = pi;
}

/*
 * Delete (unlink and free).
 * Handles delete of things that have not yet been inserted in the list
 * i.e. dr_physical is NULL.
 */
static void
router_delete(struct router *dr)
{
	struct phyint *pi;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_ROUTER) {
		logmsg(LOG_DEBUG, "router_delete(%s, %s, %u)\n",
		    dr->dr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&dr->dr_address,
		    abuf, sizeof (abuf)), dr->dr_lifetime);
	}
	pi = dr->dr_physical;
	if (dr->dr_inkernel && (pi->pi_kernel_state & PI_PRESENT))
		router_delete_k(dr);

	if (dr->dr_prev == NULL) {
		if (pi != NULL)
			pi->pi_router_list = dr->dr_next;
	} else {
		dr->dr_prev->dr_next = dr->dr_next;
	}
	if (dr->dr_next != NULL)
		dr->dr_next->dr_prev = dr->dr_prev;
	dr->dr_next = dr->dr_prev = NULL;
	free(dr);
}

/*
 * Update the kernel to match dr_lifetime
 */
void
router_update_k(struct router *dr)
{
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_ROUTER) {
		logmsg(LOG_DEBUG, "router_update_k(%s, %s, %u)\n",
		    dr->dr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&dr->dr_address,
		    abuf, sizeof (abuf)), dr->dr_lifetime);
	}

	if (dr->dr_lifetime == 0 && dr->dr_inkernel) {
		/* Log a message when last router goes away */
		if (dr->dr_physical->pi_num_k_routers == 1) {
			logmsg(LOG_WARNING,
			    "Last default router (%s) removed on %s\n",
			    inet_ntop(AF_INET6, (void *)&dr->dr_address,
			    abuf, sizeof (abuf)), dr->dr_physical->pi_name);
		}
		router_delete(dr);
	} else if (dr->dr_lifetime != 0 && !dr->dr_inkernel)
		router_add_k(dr);
}

/*
 * Called with the number of millseconds elapsed since the last call.
 * Determines if any timeout event has occurred and
 * returns the number of milliseconds until the next timeout event.
 * Returns TIMER_INFINITY for "never".
 */
uint_t
router_timer(struct router *dr, uint_t elapsed)
{
	uint_t next = TIMER_INFINITY;
	char abuf[INET6_ADDRSTRLEN];

	if (debug & D_ROUTER) {
		logmsg(LOG_DEBUG, "router_timer(%s, %s, %u, %d)\n",
		    dr->dr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&dr->dr_address,
		    abuf, sizeof (abuf)), dr->dr_lifetime, elapsed);
	}
	if (dr->dr_lifetime <= elapsed) {
		dr->dr_lifetime = 0;
	} else {
		dr->dr_lifetime -= elapsed;
		if (dr->dr_lifetime < next)
			next = dr->dr_lifetime;
	}

	if (dr->dr_lifetime == 0) {
		/* Log a message when last router goes away */
		if (dr->dr_physical->pi_num_k_routers == 1) {
			logmsg(LOG_WARNING,
			    "Last default router (%s) timed out on %s\n",
			    inet_ntop(AF_INET6, (void *)&dr->dr_address,
			    abuf, sizeof (abuf)), dr->dr_physical->pi_name);
		}
		router_delete(dr);
	}
	return (next);
}

/*
 * Add a default route to the kernel (unless the lifetime is zero)
 * Handles onlink default routes.
 */
static void
router_add_k(struct router *dr)
{
	struct phyint *pi = dr->dr_physical;
	char abuf[INET6_ADDRSTRLEN];
	int rlen;

	if (debug & D_ROUTER) {
		logmsg(LOG_DEBUG, "router_add_k(%s, %s, %u)\n",
		    dr->dr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&dr->dr_address,
		    abuf, sizeof (abuf)), dr->dr_lifetime);
	}

	rta_gateway->sin6_addr = dr->dr_address;

	rta_ifp->sdl_index = if_nametoindex(pi->pi_name);
	if (rta_ifp->sdl_index == 0) {
		logperror_pi(pi, "router_add_k: if_nametoindex");
		return;
	}

	rt_msg->rtm_flags = RTF_GATEWAY;
	rt_msg->rtm_type = RTM_ADD;
	rt_msg->rtm_seq = ++rtmseq;
	rlen = write(rtsock, rt_msg, rt_msg->rtm_msglen);
	if (rlen < 0) {
		if (errno != EEXIST) {
			logperror_pi(pi, "router_add_k: RTM_ADD");
			return;
		}
	} else if (rlen < rt_msg->rtm_msglen) {
		logmsg(LOG_ERR, "router_add_k: write to routing socket got "
		    "only %d for rlen (interface %s)\n", rlen, pi->pi_name);
		return;
	}
	dr->dr_inkernel = _B_TRUE;
	pi->pi_num_k_routers++;
}

/*
 * Delete a route from the kernel.
 * Handles onlink default routes.
 */
static void
router_delete_k(struct router *dr)
{
	struct phyint *pi = dr->dr_physical;
	char abuf[INET6_ADDRSTRLEN];
	int rlen;

	if (debug & D_ROUTER) {
		logmsg(LOG_DEBUG, "router_delete_k(%s, %s, %u)\n",
		    dr->dr_physical->pi_name,
		    inet_ntop(AF_INET6, (void *)&dr->dr_address,
		    abuf, sizeof (abuf)), dr->dr_lifetime);
	}

	rta_gateway->sin6_addr = dr->dr_address;

	rta_ifp->sdl_index = if_nametoindex(pi->pi_name);
	if (rta_ifp->sdl_index == 0) {
		logperror_pi(pi, "router_delete_k: if_nametoindex");
		return;
	}

	rt_msg->rtm_flags = RTF_GATEWAY;
	rt_msg->rtm_type = RTM_DELETE;
	rt_msg->rtm_seq = ++rtmseq;
	rlen = write(rtsock, rt_msg, rt_msg->rtm_msglen);
	if (rlen < 0) {
		if (errno != ESRCH) {
			logperror_pi(pi, "router_delete_k: RTM_DELETE");
		}
	} else if (rlen < rt_msg->rtm_msglen) {
		logmsg(LOG_ERR, "router_delete_k: write to routing socket got "
		    "only %d for rlen (interface %s)\n", rlen, pi->pi_name);
	}
	dr->dr_inkernel = _B_FALSE;
	pi->pi_num_k_routers--;
}

static void
router_print(struct router *dr)
{
	char abuf[INET6_ADDRSTRLEN];

	logmsg(LOG_DEBUG, "Router %s on %s inkernel %d lifetime %u\n",
	    inet_ntop(AF_INET6, (void *)&dr->dr_address, abuf, sizeof (abuf)),
	    dr->dr_physical->pi_name, dr->dr_inkernel, dr->dr_lifetime);
}

void
phyint_print_all(void)
{
	struct phyint *pi;

	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		phyint_print(pi);
	}
}

void
phyint_cleanup(struct phyint *pi)
{
	pi->pi_state = 0;
	pi->pi_kernel_state = 0;

	if (pi->pi_AdvSendAdvertisements) {
		check_to_advertise(pi, ADV_OFF);
	} else {
		check_to_solicit(pi, SOLICIT_OFF);
	}

	while (pi->pi_router_list)
		router_delete(pi->pi_router_list);
	(void) poll_remove(pi->pi_sock);
	(void) close(pi->pi_sock);
	pi->pi_sock = -1;
	pi->pi_stateless = pi->pi_StatelessAddrConf;
	pi->pi_stateful = pi->pi_StatefulAddrConf;
	pi->pi_ipadm_aobjname[0] = '\0';
	pi->pi_ifaddr = in6addr_any;
}

/*
 * Sets/removes the ipadm address object name for the given prefix.
 */
void
prefix_update_ipadm_addrobj(struct prefix *pr, boolean_t add)
{
	struct phyint *pi = pr->pr_physical;
	int lnum = 0;
	char *cp;
	ipadm_handle_t iph;
	ipadm_status_t status;

	/*
	 * If ipadm was used to autoconfigure this interface,
	 * pi_ipadm_aobjname will contain the address object name
	 * that is used to identify the addresses. Use the same
	 * address object name for this prefix.
	 */
	if (pi->pi_ipadm_aobjname[0] == '\0' ||
	    pr->pr_name[0] == '\0' || IN6_IS_ADDR_LINKLOCAL(&pr->pr_address) ||
	    (!(pr->pr_flags & IFF_ADDRCONF) &&
	    !(pr->pr_flags & IFF_DHCPRUNNING))) {
		return;
	}
	if ((status = ipadm_open(&iph, 0)) != IPADM_SUCCESS) {
		logmsg(LOG_ERR, "Could not open handle to libipadm: %s\n",
		    ipadm_status2str(status));
		return;
	}
	cp = strrchr(pr->pr_name, ':');
	if (cp != NULL)
		lnum = atoi(++cp);
	if (add) {
		status = ipadm_add_aobjname(iph, pi->pi_name, AF_INET6,
		    pi->pi_ipadm_aobjname, IPADM_ADDR_IPV6_ADDRCONF, lnum);
	} else {
		status = ipadm_delete_aobjname(iph, pi->pi_name, AF_INET6,
		    pi->pi_ipadm_aobjname, IPADM_ADDR_IPV6_ADDRCONF, lnum);
	}
	/* Ignore the error if the ipmgmtd daemon is not running */
	if (status != IPADM_SUCCESS && status != IPADM_IPC_ERROR) {
		logmsg(LOG_ERR, "ipadm error in %s '%s' : %s\n",
		    (add ? "adding" : "deleting"), pi->pi_ipadm_aobjname,
		    ipadm_status2str(status));
	}
	ipadm_close(iph);
}
