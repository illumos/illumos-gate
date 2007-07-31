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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mpd_defs.h"
#include "mpd_tables.h"

/*
 * Global list of phyints, phyint instances, phyint groups and the anonymous
 * group; the latter is initialized in phyint_init().
 */
struct phyint *phyints = NULL;
struct phyint_instance	*phyint_instances = NULL;
struct phyint_group *phyint_groups = NULL;
struct phyint_group *phyint_anongroup;

/*
 * Grouplist signature; initialized in phyint_init().
 */
static uint64_t phyint_grouplistsig;

static void phyint_inst_insert(struct phyint_instance *pii);
static void phyint_inst_print(struct phyint_instance *pii);

static void phyint_insert(struct phyint *pi, struct phyint_group *pg);
static void phyint_delete(struct phyint *pi);

static void phyint_group_insert(struct phyint_group *pg);
static void phyint_group_delete(struct phyint_group *pg);
static struct phyint_group *phyint_group_lookup(const char *pg_name);
static struct phyint_group *phyint_group_create(const char *pg_name);

static void logint_print(struct logint *li);
static void logint_insert(struct phyint_instance *pii, struct logint *li);
static struct logint *logint_lookup(struct phyint_instance *pii, char *li_name);

static void target_print(struct target *tg);
static void target_insert(struct phyint_instance *pii, struct target *tg);
static struct target *target_first(struct phyint_instance *pii);
static struct target *target_select_best(struct phyint_instance *pii);
static void target_flush_hosts(struct phyint_group *pg);

static void reset_pii_probes(struct phyint_instance *pii, struct target *tg);

static boolean_t phyint_inst_v6_sockinit(struct phyint_instance *pii);
static boolean_t phyint_inst_v4_sockinit(struct phyint_instance *pii);

static void ip_index_to_mask_v6(uint_t masklen, struct in6_addr *bitmask);
static boolean_t prefix_equal(struct in6_addr p1, struct in6_addr p2,
    int prefix_len);

static int phyint_state_event(struct phyint_group *pg, struct phyint *pi);
static int phyint_group_state_event(struct phyint_group *pg);
static int phyint_group_change_event(struct phyint_group *pg, ipmp_group_op_t);
static int phyint_group_member_event(struct phyint_group *pg, struct phyint *pi,
    ipmp_if_op_t op);

static uint64_t gensig(void);

/* Initialize any per-file global state.  Returns 0 on success, -1 on failure */
int
phyint_init(void)
{
	phyint_grouplistsig = gensig();
	if (track_all_phyints) {
		phyint_anongroup = phyint_group_create("");
		if (phyint_anongroup == NULL)
			return (-1);
		phyint_group_insert(phyint_anongroup);
	}
	return (0);
}

/* Return the phyint with the given name */
struct phyint *
phyint_lookup(const char *name)
{
	struct phyint *pi;

	if (debug & D_PHYINT)
		logdebug("phyint_lookup(%s)\n", name);

	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		if (strncmp(pi->pi_name, name, sizeof (pi->pi_name)) == 0)
			break;
	}
	return (pi);
}

/* Return the phyint instance with the given name and the given family */
struct phyint_instance *
phyint_inst_lookup(int af, char *name)
{
	struct phyint *pi;

	if (debug & D_PHYINT)
		logdebug("phyint_inst_lookup(%s %s)\n", AF_STR(af), name);

	assert(af == AF_INET || af == AF_INET6);

	pi = phyint_lookup(name);
	if (pi == NULL)
		return (NULL);

	return (PHYINT_INSTANCE(pi, af));
}

static struct phyint_group *
phyint_group_lookup(const char *pg_name)
{
	struct phyint_group *pg;

	if (debug & D_PHYINT)
		logdebug("phyint_group_lookup(%s)\n", pg_name);

	for (pg = phyint_groups; pg != NULL; pg = pg->pg_next) {
		if (strncmp(pg->pg_name, pg_name, sizeof (pg->pg_name)) == 0)
			break;
	}
	return (pg);
}

/*
 * Insert the phyint in the linked list of all phyints. If the phyint belongs
 * to some group, insert it in the phyint group list.
 */
static void
phyint_insert(struct phyint *pi, struct phyint_group *pg)
{
	if (debug & D_PHYINT)
		logdebug("phyint_insert(%s '%s')\n", pi->pi_name, pg->pg_name);

	/* Insert the phyint at the head of the 'all phyints' list */
	pi->pi_next = phyints;
	pi->pi_prev = NULL;
	if (phyints != NULL)
		phyints->pi_prev = pi;
	phyints = pi;

	/*
	 * Insert the phyint at the head of the 'phyint_group members' list
	 * of the phyint group to which it belongs.
	 */
	pi->pi_pgnext = NULL;
	pi->pi_pgprev = NULL;
	pi->pi_group = pg;

	pi->pi_pgnext = pg->pg_phyint;
	if (pi->pi_pgnext != NULL)
		pi->pi_pgnext->pi_pgprev = pi;
	pg->pg_phyint = pi;

	pg->pg_sig++;
	(void) phyint_group_member_event(pg, pi, IPMP_IF_ADD);
}

/* Insert the phyint instance in the linked list of all phyint instances. */
static void
phyint_inst_insert(struct phyint_instance *pii)
{
	if (debug & D_PHYINT) {
		logdebug("phyint_inst_insert(%s %s)\n",
		    AF_STR(pii->pii_af), pii->pii_name);
	}

	/*
	 * Insert the phyint at the head of the 'all phyint instances' list.
	 */
	pii->pii_next = phyint_instances;
	pii->pii_prev = NULL;
	if (phyint_instances != NULL)
		phyint_instances->pii_prev = pii;
	phyint_instances = pii;
}

/*
 * Create a new phyint with the given parameters. Also insert it into
 * the list of all phyints and the list of phyint group members by calling
 * phyint_insert().
 */
static struct phyint *
phyint_create(char *pi_name, struct phyint_group *pg, uint_t ifindex,
    uint64_t flags)
{
	struct phyint *pi;

	pi = calloc(1, sizeof (struct phyint));
	if (pi == NULL) {
		logperror("phyint_create: calloc");
		return (NULL);
	}

	/*
	 * Record the phyint values. Also insert the phyint into the
	 * phyint group by calling phyint_insert().
	 */
	(void) strlcpy(pi->pi_name, pi_name, sizeof (pi->pi_name));
	pi->pi_taddrthresh = getcurrentsec() + TESTADDR_CONF_TIME;
	pi->pi_ifindex = ifindex;
	pi->pi_icmpid =
	    htons(((getpid() & 0xFF) << 8) | (pi->pi_ifindex & 0xFF));
	/*
	 * We optimistically start in the PI_RUNNING state.  Later (in
	 * process_link_state_changes()), we will readjust this to match the
	 * current state of the link.  Further, if test addresses are
	 * subsequently assigned, we will transition to PI_NOTARGETS and then
	 * either PI_RUNNING or PI_FAILED, depending on the result of the test
	 * probes.
	 */
	pi->pi_state = PI_RUNNING;
	pi->pi_flags = PHYINT_FLAGS(flags);
	/*
	 * Initialise the link state.  The link state is initialised to
	 * up, so that if the link is down when IPMP starts monitoring
	 * the interface, it will appear as though there has been a
	 * transition from the link up to link down.  This avoids
	 * having to treat this situation as a special case.
	 */
	INIT_LINK_STATE(pi);

	/*
	 * Insert the phyint in the list of all phyints, and the
	 * list of phyint group members
	 */
	phyint_insert(pi, pg);

	/*
	 * If we are joining a failed group, mark the interface as
	 * failed.
	 */
	if (GROUP_FAILED(pg))
		(void) change_lif_flags(pi, IFF_FAILED, _B_TRUE);

	return (pi);
}

/*
 * Create a new phyint instance belonging to the phyint 'pi' and address
 * family 'af'. Also insert it into the list of all phyint instances by
 * calling phyint_inst_insert().
 */
static struct phyint_instance *
phyint_inst_create(struct phyint *pi, int af)
{
	struct phyint_instance *pii;

	pii = calloc(1, sizeof (struct phyint_instance));
	if (pii == NULL) {
		logperror("phyint_inst_create: calloc");
		return (NULL);
	}

	/*
	 * Attach the phyint instance to the phyint.
	 * Set the back pointers as well
	 */
	pii->pii_phyint = pi;
	if (af == AF_INET)
		pi->pi_v4 = pii;
	else
		pi->pi_v6 = pii;

	pii->pii_in_use = 1;
	pii->pii_probe_sock = -1;
	pii->pii_snxt = 1;
	pii->pii_af = af;
	pii->pii_fd_hrtime = gethrtime() +
	    (FAILURE_DETECTION_QP * (hrtime_t)NANOSEC);
	pii->pii_flags = pi->pi_flags;

	/* Insert the phyint instance in the list of all phyint instances. */
	phyint_inst_insert(pii);
	return (pii);
}

/*
 * Change the state of phyint `pi' to state `state'.
 */
void
phyint_chstate(struct phyint *pi, enum pi_state state)
{
	/*
	 * To simplify things, some callers always set a given state
	 * regardless of the previous state of the phyint (e.g., setting
	 * PI_RUNNING when it's already set).  We shouldn't bother
	 * generating an event or consuming a signature for these, since
	 * the actual state of the interface is unchanged.
	 */
	if (pi->pi_state == state)
		return;

	pi->pi_state = state;
	pi->pi_group->pg_sig++;
	(void) phyint_state_event(pi->pi_group, pi);
}

/*
 * Note that the type of phyint `pi' has changed.
 */
void
phyint_newtype(struct phyint *pi)
{
	pi->pi_group->pg_sig++;
	(void) phyint_state_event(pi->pi_group, pi);
}

/*
 * Insert the phyint group in the linked list of all phyint groups
 * at the head of the list
 */
static void
phyint_group_insert(struct phyint_group *pg)
{
	pg->pg_next = phyint_groups;
	pg->pg_prev = NULL;
	if (phyint_groups != NULL)
		phyint_groups->pg_prev = pg;
	phyint_groups = pg;

	phyint_grouplistsig++;
	(void) phyint_group_change_event(pg, IPMP_GROUP_ADD);
}

/*
 * Create a new phyint group called 'name'.
 */
static struct phyint_group *
phyint_group_create(const char *name)
{
	struct	phyint_group *pg;

	if (debug & D_PHYINT)
		logdebug("phyint_group_create(%s)\n", name);

	pg = calloc(1, sizeof (struct phyint_group));
	if (pg == NULL) {
		logperror("phyint_group_create: calloc");
		return (NULL);
	}

	(void) strlcpy(pg->pg_name, name, sizeof (pg->pg_name));
	pg->pg_sig = gensig();

	pg->pg_fdt = user_failure_detection_time;
	pg->pg_probeint = user_probe_interval;

	return (pg);
}

/*
 * Change the state of the phyint group `pg' to state `state'.
 */
void
phyint_group_chstate(struct phyint_group *pg, enum pg_state state)
{
	assert(pg != phyint_anongroup);

	switch (state) {
	case PG_FAILED:
		pg->pg_groupfailed = 1;

		/*
		 * We can never know with certainty that a group has
		 * failed.  It is possible that all known targets have
		 * failed simultaneously, and new targets have come up
		 * instead. If the targets are routers then router
		 * discovery will kick in, and we will see the new routers
		 * thru routing socket messages. But if the targets are
		 * hosts, we have to discover it by multicast.	So flush
		 * all the host targets. The next probe will send out a
		 * multicast echo request. If this is a group failure, we
		 * will still not see any response, otherwise we will
		 * clear the pg_groupfailed flag after we get
		 * NUM_PROBE_REPAIRS consecutive unicast replies on any
		 * phyint.
		 */
		target_flush_hosts(pg);
		break;

	case PG_RUNNING:
		pg->pg_groupfailed = 0;
		break;

	default:
		logerr("phyint_group_chstate: invalid group state %d; "
		    "aborting\n", state);
		abort();
	}

	pg->pg_sig++;
	(void) phyint_group_state_event(pg);
}

/*
 * Create a new phyint instance and initialize it from the values supplied by
 * the kernel. Always check for ENXIO before logging any error, because the
 * interface could have vanished after completion of SIOCGLIFCONF.
 * Return values:
 *	pointer to the phyint instance on success
 *	NULL on failure Eg. if the phyint instance is not found in the kernel
 */
struct phyint_instance *
phyint_inst_init_from_k(int af, char *pi_name)
{
	char	pg_name[LIFNAMSIZ + 1];
	int	ifsock;
	uint_t	ifindex;
	uint64_t	flags;
	struct lifreq	lifr;
	struct phyint	*pi;
	struct phyint_instance	*pii;
	boolean_t	pg_created;
	boolean_t	pi_created;
	struct phyint_group	*pg;

retry:
	pii = NULL;
	pi = NULL;
	pg = NULL;
	pi_created = _B_FALSE;
	pg_created = _B_FALSE;

	if (debug & D_PHYINT) {
		logdebug("phyint_inst_init_from_k(%s %s)\n",
		    AF_STR(af), pi_name);
	}

	assert(af == AF_INET || af == AF_INET6);

	/* Get the socket for doing ioctls */
	ifsock = (af == AF_INET) ? ifsock_v4 : ifsock_v6;

	/*
	 * Get the interface flags. Ignore loopback and multipoint
	 * interfaces.
	 */
	(void) strncpy(lifr.lifr_name, pi_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
	if (ioctl(ifsock, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		if (errno != ENXIO) {
			logperror("phyint_inst_init_from_k:"
			    " ioctl (get flags)");
		}
		return (NULL);
	}
	flags = lifr.lifr_flags;
	if (!(flags & IFF_MULTICAST) || (flags & IFF_LOOPBACK))
		return (NULL);

	/*
	 * Get the ifindex for recording later in our tables, in case we need
	 * to create a new phyint.
	 */
	if (ioctl(ifsock, SIOCGLIFINDEX, (char *)&lifr) < 0) {
		if (errno != ENXIO) {
			logperror("phyint_inst_init_from_k: "
			    " ioctl (get lifindex)");
		}
		return (NULL);
	}
	ifindex = lifr.lifr_index;

	/*
	 * Get the phyint group name of this phyint, from the kernel.
	 */
	if (ioctl(ifsock, SIOCGLIFGROUPNAME, (char *)&lifr) < 0) {
		if (errno != ENXIO) {
			logperror("phyint_inst_init_from_k: "
			    "ioctl (get group name)");
		}
		return (NULL);
	}
	(void) strncpy(pg_name, lifr.lifr_groupname, sizeof (pg_name));
	pg_name[sizeof (pg_name) - 1] = '\0';

	/*
	 * If the phyint is not part of any group, pg_name is the
	 * null string. If 'track_all_phyints' is false, there is no
	 * need to create a phyint.
	 */
	if (pg_name[0] == '\0' && !track_all_phyints) {
		/*
		 * If the IFF_FAILED or IFF_OFFLINE flags are set, reset
		 * them. These flags shouldn't be set if IPMP isn't
		 * tracking the interface.
		 */
		if ((flags & (IFF_FAILED | IFF_OFFLINE)) != 0) {
			lifr.lifr_flags = flags & ~(IFF_FAILED | IFF_OFFLINE);
			if (ioctl(ifsock, SIOCSLIFFLAGS, (char *)&lifr) < 0) {
				if (errno != ENXIO) {
					logperror("phyint_inst_init_from_k:"
					    " ioctl (set flags)");
				}
			}
		}
		return (NULL);
	}

	/*
	 * We need to create a new phyint instance. A phyint instance
	 * belongs to a phyint, and the phyint belongs to a phyint group.
	 * So we first lookup the 'parents' and if they don't exist then
	 * we create them.
	 */
	pg = phyint_group_lookup(pg_name);
	if (pg == NULL) {
		pg = phyint_group_create(pg_name);
		if (pg == NULL) {
			logerr("phyint_inst_init_from_k:"
			    " unable to create group %s\n", pg_name);
			return (NULL);
		}
		phyint_group_insert(pg);
		pg_created = _B_TRUE;
	}

	/*
	 * Lookup the phyint. If the phyint does not exist create it.
	 */
	pi = phyint_lookup(pi_name);
	if (pi == NULL) {
		pi = phyint_create(pi_name, pg, ifindex, flags);
		if (pi == NULL) {
			logerr("phyint_inst_init_from_k:"
			    " unable to create phyint %s\n", pi_name);
			if (pg_created)
				phyint_group_delete(pg);
			return (NULL);
		}
		pi_created = _B_TRUE;
	} else {
		/* The phyint exists already. */
		assert(pi_created == _B_FALSE);
		/*
		 * Normally we should see consistent values for the IPv4 and
		 * IPv6 instances, for phyint properties. If we don't, it
		 * means things have changed underneath us, and we should
		 * resync our tables with the kernel. Check whether the
		 * interface index has changed. If so, it is most likely
		 * the interface has been unplumbed and replumbed,
		 * while we are yet to update our tables. Do it now.
		 */
		if (pi->pi_ifindex != ifindex) {
			if (pg_created)
				phyint_group_delete(pg);
			phyint_inst_delete(PHYINT_INSTANCE(pi, AF_OTHER(af)));
			goto retry;
		}
		assert(PHYINT_INSTANCE(pi, af) == NULL);

		/*
		 * If the group name seen by the IPv4 and IPv6 instances
		 * are different, it is most likely the groupname has
		 * changed, while we are yet to update our tables. Do it now.
		 */
		if (strcmp(pi->pi_group->pg_name, pg_name) != 0) {
			if (pg_created)
				phyint_group_delete(pg);
			restore_phyint(pi);
			phyint_inst_delete(PHYINT_INSTANCE(pi,
			    AF_OTHER(af)));
			goto retry;
		}
	}

	/*
	 * Create a new phyint instance, corresponding to the 'af'
	 * passed in.
	 */
	pii = phyint_inst_create(pi, af);
	if (pii == NULL) {
		logerr("phyint_inst_init_from_k: unable to create"
		    "phyint inst %s\n", pi->pi_name);
		if (pi_created) {
			/*
			 * Deleting the phyint will delete the phyint group
			 * if this is the last phyint in the group.
			 */
			phyint_delete(pi);
		}
		return (NULL);
	}

	return (pii);
}

/*
 * Bind pii_probe_sock to the address associated with pii_probe_logint.
 * This socket will be used for sending and receiving ICMP/ICMPv6 probes to
 * targets. Do the common part in this function, and complete the
 * initializations by calling the protocol specific functions
 * phyint_inst_v{4,6}_sockinit() respectively.
 *
 * Return values: _B_TRUE/_B_FALSE for success or failure respectively.
 */
boolean_t
phyint_inst_sockinit(struct phyint_instance *pii)
{
	boolean_t success;
	struct phyint_group *pg;

	if (debug & D_PHYINT) {
		logdebug("phyint_inst_sockinit(%s %s)\n",
		    AF_STR(pii->pii_af), pii->pii_name);
	}

	assert(pii->pii_probe_logint != NULL);
	assert(pii->pii_probe_logint->li_flags & IFF_UP);
	assert(pii->pii_probe_logint->li_flags & IFF_NOFAILOVER);
	assert(pii->pii_af == AF_INET || pii->pii_af == AF_INET6);

	/*
	 * If the socket is already bound, close pii_probe_sock
	 */
	if (pii->pii_probe_sock != -1)
		close_probe_socket(pii, _B_TRUE);

	/*
	 * If the phyint is not part of a named group and track_all_phyints is
	 * false, simply return.
	 */
	pg = pii->pii_phyint->pi_group;
	if (pg == phyint_anongroup && !track_all_phyints) {
		if (debug & D_PHYINT)
			logdebug("phyint_inst_sockinit: no group\n");
		return (_B_FALSE);
	}

	/*
	 * Initialize the socket by calling the protocol specific function.
	 * If it succeeds, add the socket to the poll list.
	 */
	if (pii->pii_af == AF_INET6)
		success = phyint_inst_v6_sockinit(pii);
	else
		success = phyint_inst_v4_sockinit(pii);

	if (success && (poll_add(pii->pii_probe_sock) == 0))
		return (_B_TRUE);

	/* Something failed, cleanup and return false */
	if (pii->pii_probe_sock != -1)
		close_probe_socket(pii, _B_FALSE);

	return (_B_FALSE);
}

/*
 * IPv6 specific part in initializing the pii_probe_sock. This socket is
 * used to send/receive ICMPv6 probe packets.
 */
static boolean_t
phyint_inst_v6_sockinit(struct phyint_instance *pii)
{
	icmp6_filter_t filter;
	int hopcount = 1;
	int int_op;
	struct	sockaddr_in6	testaddr;

	/*
	 * Open a raw socket with ICMPv6 protocol.
	 *
	 * Use IPV6_DONTFAILOVER_IF to make sure that probes go out
	 * on the specified phyint only, and are not subject to load
	 * balancing. Bind to the src address chosen will ensure that
	 * the responses are received only on the specified phyint.
	 *
	 * Set the hopcount to 1 so that probe packets are not routed.
	 * Disable multicast loopback. Set the receive filter to
	 * receive only ICMPv6 echo replies.
	 */
	pii->pii_probe_sock = socket(pii->pii_af, SOCK_RAW, IPPROTO_ICMPV6);
	if (pii->pii_probe_sock < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: socket");
		return (_B_FALSE);
}

	bzero(&testaddr, sizeof (testaddr));
	testaddr.sin6_family = AF_INET6;
	testaddr.sin6_port = 0;
	testaddr.sin6_addr = pii->pii_probe_logint->li_addr;

	if (bind(pii->pii_probe_sock, (struct sockaddr *)&testaddr,
	    sizeof (testaddr)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: IPv6 bind");
		return (_B_FALSE);
	}

	/*
	 * IPV6_DONTFAILOVER_IF option takes precedence over setting
	 * IP_MULTICAST_IF. So we don't set IPV6_MULTICAST_IF again.
	 */
	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_DONTFAILOVER_IF,
	    (char *)&pii->pii_ifindex, sizeof (uint_t)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_DONTFAILOVER_IF");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
	    (char *)&hopcount, sizeof (hopcount)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_UNICAST_HOPS");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	    (char *)&hopcount, sizeof (hopcount)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_MULTICAST_HOPS");
		return (_B_FALSE);
	}

	int_op = 0;	/* used to turn off option */
	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
	    (char *)&int_op, sizeof (int_op)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_MULTICAST_LOOP");
		return (_B_FALSE);
	}

	/*
	 * Filter out so that we only receive ICMP echo replies
	 */
	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);

	if (setsockopt(pii->pii_probe_sock, IPPROTO_ICMPV6, ICMP6_FILTER,
	    (char *)&filter, sizeof (filter)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " ICMP6_FILTER");
		return (_B_FALSE);
	}

	/* Enable receipt of ancillary data */
	int_op = 1;
	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
	    (char *)&int_op, sizeof (int_op)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_RECVHOPLIMIT");
		return (_B_FALSE);
	}

	return (_B_TRUE);
}

/*
 * IPv4 specific part in initializing the pii_probe_sock. This socket is
 * used to send/receive ICMPv4 probe packets.
 */
static boolean_t
phyint_inst_v4_sockinit(struct phyint_instance *pii)
{
	struct sockaddr_in  testaddr;
	char	char_op;
	int	ttl = 1;
	char	char_ttl = 1;

	/*
	 * Open a raw socket with ICMPv4 protocol.
	 *
	 * Use IP_DONTFAILOVER_IF to make sure that probes go out
	 * on the specified phyint only, and are not subject to load
	 * balancing. Bind to the src address chosen will ensure that
	 * the responses are received only on the specified phyint.
	 *
	 * Set the ttl to 1 so that probe packets are not routed.
	 * Disable multicast loopback.
	 */
	pii->pii_probe_sock = socket(pii->pii_af, SOCK_RAW, IPPROTO_ICMP);
	if (pii->pii_probe_sock < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: socket");
		return (_B_FALSE);
	}

	bzero(&testaddr, sizeof (testaddr));
	testaddr.sin_family = AF_INET;
	testaddr.sin_port = 0;
	IN6_V4MAPPED_TO_INADDR(&pii->pii_probe_logint->li_addr,
	    &testaddr.sin_addr);

	if (bind(pii->pii_probe_sock, (struct sockaddr *)&testaddr,
	    sizeof (testaddr)) < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: IPv4 bind");
		return (_B_FALSE);
	}

	/*
	 * IP_DONTFAILOVER_IF option takes precedence over setting
	 * IP_MULTICAST_IF. So we don't set IP_MULTICAST_IF again.
	 */
	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_DONTFAILOVER_IF,
	    (char *)&testaddr.sin_addr, sizeof (struct in_addr)) < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " IP_DONTFAILOVER");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_TTL,
	    (char *)&ttl, sizeof (ttl)) < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " IP_TTL");
		return (_B_FALSE);
	}

	char_op = 0;	/* used to turn off option */
	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
	    (char *)&char_op, sizeof (char_op)) == -1) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " IP_MULTICAST_LOOP");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_MULTICAST_TTL,
	    (char *)&char_ttl, sizeof (char_ttl)) == -1) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " IP_MULTICAST_TTL");
		return (_B_FALSE);
	}

	return (_B_TRUE);
}

/*
 * Remove the phyint group from the list of 'all phyint groups'
 * and free it.
 */
static void
phyint_group_delete(struct phyint_group *pg)
{
	/*
	 * The anonymous group always exists, even when empty.
	 */
	if (pg == phyint_anongroup)
		return;

	if (debug & D_PHYINT)
		logdebug("phyint_group_delete('%s')\n", pg->pg_name);

	/*
	 * The phyint group must be empty, and must not have any phyints.
	 * The phyint group must be in the list of all phyint groups
	 */
	assert(pg->pg_phyint == NULL);
	assert(phyint_groups == pg || pg->pg_prev != NULL);

	if (pg->pg_prev != NULL)
		pg->pg_prev->pg_next = pg->pg_next;
	else
		phyint_groups = pg->pg_next;

	if (pg->pg_next != NULL)
		pg->pg_next->pg_prev = pg->pg_prev;

	pg->pg_next = NULL;
	pg->pg_prev = NULL;

	phyint_grouplistsig++;
	(void) phyint_group_change_event(pg, IPMP_GROUP_REMOVE);

	free(pg);
}

/*
 * Extract information from the kernel about the desired phyint.
 * Look only for properties of the phyint and not properties of logints.
 * Take appropriate action on the changes.
 * Return codes:
 *	PI_OK
 *		The phyint exists in the kernel and matches our knowledge
 *		of the phyint.
 *	PI_DELETED
 *		The phyint has vanished in the kernel.
 *	PI_IFINDEX_CHANGED
 *		The phyint's interface index has changed.
 *		Ask the caller to delete and recreate the phyint.
 *	PI_IOCTL_ERROR
 *		Some ioctl error. Don't change anything.
 *	PI_GROUP_CHANGED
 *		The phyint has changed group.
 */
int
phyint_inst_update_from_k(struct phyint_instance *pii)
{
	struct lifreq lifr;
	int	ifsock;
	struct phyint *pi;

	pi = pii->pii_phyint;

	if (debug & D_PHYINT) {
		logdebug("phyint_inst_update_from_k(%s %s)\n",
		    AF_STR(pii->pii_af), pi->pi_name);
	}

	/*
	 * Get the ifindex from the kernel, for comparison with the
	 * value in our tables.
	 */
	(void) strncpy(lifr.lifr_name, pi->pi_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';

	ifsock = (pii->pii_af == AF_INET) ? ifsock_v4 : ifsock_v6;
	if (ioctl(ifsock, SIOCGLIFINDEX, &lifr) < 0) {
		if (errno == ENXIO) {
			return (PI_DELETED);
		} else {
			logperror_pii(pii, "phyint_inst_update_from_k:"
			    " ioctl (get lifindex)");
			return (PI_IOCTL_ERROR);
		}
	}

	if (lifr.lifr_index != pi->pi_ifindex) {
		/*
		 * The index has changed. Most likely the interface has
		 * been unplumbed and replumbed. Ask the caller to take
		 * appropriate action.
		 */
		if (debug & D_PHYINT) {
			logdebug("phyint_inst_update_from_k:"
			    " old index %d new index %d\n",
			    pi->pi_ifindex, lifr.lifr_index);
		}
		return (PI_IFINDEX_CHANGED);
	}

	/*
	 * Get the group name from the kernel, for comparison with
	 * the value in our tables.
	 */
	if (ioctl(ifsock, SIOCGLIFGROUPNAME, &lifr) < 0) {
		if (errno == ENXIO) {
			return (PI_DELETED);
		} else {
			logperror_pii(pii, "phyint_inst_update_from_k:"
			    " ioctl (get groupname)");
			return (PI_IOCTL_ERROR);
		}
	}

	/*
	 * If the phyint has changed group i.e. if the phyint group name
	 * returned by the kernel is different, ask the caller to delete
	 * and recreate the phyint in the right group
	 */
	if (strcmp(lifr.lifr_groupname, pi->pi_group->pg_name) != 0) {
		/* Groupname has changed */
		if (debug & D_PHYINT) {
			logdebug("phyint_inst_update_from_k:"
			    " groupname change\n");
		}
		return (PI_GROUP_CHANGED);
	}

	/*
	 * Get the current phyint flags from the kernel, and determine what
	 * flags have changed by comparing against our tables.	Note that the
	 * IFF_INACTIVE processing in initifs() relies on this call to ensure
	 * that IFF_INACTIVE is really still set on the interface.
	 */
	if (ioctl(ifsock, SIOCGLIFFLAGS, &lifr) < 0) {
		if (errno == ENXIO) {
			return (PI_DELETED);
		} else {
			logperror_pii(pii, "phyint_inst_update_from_k: "
			    " ioctl (get flags)");
			return (PI_IOCTL_ERROR);
		}
	}

	pi->pi_flags = PHYINT_FLAGS(lifr.lifr_flags);
	if (pi->pi_v4 != NULL)
		pi->pi_v4->pii_flags = pi->pi_flags;
	if (pi->pi_v6 != NULL)
		pi->pi_v6->pii_flags = pi->pi_flags;

	if (pi->pi_flags & IFF_FAILED) {
		/*
		 * If we are in the running and full state, we have
		 * completed failbacks successfully and we would have
		 * expected IFF_FAILED to have been clear. That it is
		 * set means there was a race condition. Some other
		 * process turned on the IFF_FAILED flag. Since the
		 * flag setting is not atomic, i.e. a get ioctl followed
		 * by a set ioctl, and since there is no way to set an
		 * individual flag bit, this could have occurred.
		 */
		if (pi->pi_state == PI_RUNNING && pi->pi_full)
			(void) change_lif_flags(pi, IFF_FAILED, _B_FALSE);
	} else {
		/*
		 * If we are in the failed state, there was a race.
		 * we have completed failover successfully because our
		 * state is failed and empty. Some other process turned
		 * off the IFF_FAILED flag. Same comment as above
		 */
		if (pi->pi_state == PI_FAILED && pi->pi_empty)
			(void) change_lif_flags(pi, IFF_FAILED, _B_TRUE);
	}

	/* No change in phyint status */
	return (PI_OK);
}

/*
 * Delete the phyint. Remove it from the list of all phyints, and the
 * list of phyint group members. If the group becomes empty, delete the
 * group also.
 */
static void
phyint_delete(struct phyint *pi)
{
	struct phyint_group *pg = pi->pi_group;

	if (debug & D_PHYINT)
		logdebug("phyint_delete(%s)\n", pi->pi_name);

	/* Both IPv4 and IPv6 phyint instances must have been deleted. */
	assert(pi->pi_v4 == NULL && pi->pi_v6 == NULL);

	/*
	 * The phyint must belong to a group.
	 */
	assert(pg->pg_phyint == pi || pi->pi_pgprev != NULL);

	/* The phyint must be in the list of all phyints */
	assert(phyints == pi || pi->pi_prev != NULL);

	/* Remove the phyint from the phyint group list */
	pg->pg_sig++;
	(void) phyint_group_member_event(pg, pi, IPMP_IF_REMOVE);

	if (pi->pi_pgprev == NULL) {
		/* Phyint is the 1st in the phyint group list */
		pg->pg_phyint = pi->pi_pgnext;
	} else {
		pi->pi_pgprev->pi_pgnext = pi->pi_pgnext;
	}
	if (pi->pi_pgnext != NULL)
		pi->pi_pgnext->pi_pgprev = pi->pi_pgprev;
	pi->pi_pgnext = NULL;
	pi->pi_pgprev = NULL;

	/* Remove the phyint from the global list of phyints */
	if (pi->pi_prev == NULL) {
		/* Phyint is the 1st in the list */
		phyints = pi->pi_next;
	} else {
		pi->pi_prev->pi_next = pi->pi_next;
	}
	if (pi->pi_next != NULL)
		pi->pi_next->pi_prev = pi->pi_prev;
	pi->pi_next = NULL;
	pi->pi_prev = NULL;

	free(pi);

	/* Delete the phyint_group if the last phyint has been deleted */
	if (pg->pg_phyint == NULL)
		phyint_group_delete(pg);
}

/*
 * Delete (unlink and free), the phyint instance.
 */
void
phyint_inst_delete(struct phyint_instance *pii)
{
	struct phyint *pi = pii->pii_phyint;

	assert(pi != NULL);

	if (debug & D_PHYINT) {
		logdebug("phyint_inst_delete(%s %s)\n",
		    AF_STR(pii->pii_af), pi->pi_name);
	}

	/*
	 * If the phyint instance has associated probe targets
	 * delete all the targets
	 */
	while (pii->pii_targets != NULL)
		target_delete(pii->pii_targets);

	/*
	 * Delete all the logints associated with this phyint
	 * instance.
	 */
	while (pii->pii_logint != NULL)
		logint_delete(pii->pii_logint);

	/*
	 * Close the socket used to send probes to targets from this phyint.
	 */
	if (pii->pii_probe_sock != -1)
		close_probe_socket(pii, _B_TRUE);

	/*
	 * Phyint instance must be in the list of all phyint instances.
	 * Remove phyint instance from the global list of phyint instances.
	 */
	assert(phyint_instances == pii || pii->pii_prev != NULL);
	if (pii->pii_prev == NULL) {
		/* Phyint is the 1st in the list */
		phyint_instances = pii->pii_next;
	} else {
		pii->pii_prev->pii_next = pii->pii_next;
	}
	if (pii->pii_next != NULL)
		pii->pii_next->pii_prev = pii->pii_prev;
	pii->pii_next = NULL;
	pii->pii_prev = NULL;

	/*
	 * Reset the phyint instance pointer in the phyint.
	 * If this is the last phyint instance (being deleted) on this
	 * phyint, then delete the phyint.
	 */
	if (pii->pii_af == AF_INET)
		pi->pi_v4 = NULL;
	else
		pi->pi_v6 = NULL;

	if (pi->pi_v4 == NULL && pi->pi_v6 == NULL)
		phyint_delete(pi);

	free(pii);
}

static void
phyint_inst_print(struct phyint_instance *pii)
{
	struct logint *li;
	struct target *tg;
	char abuf[INET6_ADDRSTRLEN];
	int most_recent;
	int i;

	if (pii->pii_phyint == NULL) {
		logdebug("pii->pi_phyint NULL can't print\n");
		return;
	}

	logdebug("\nPhyint instance: %s %s index %u state %x flags %llx	 "
	    "sock %x in_use %d empty %x full %x\n",
	    AF_STR(pii->pii_af), pii->pii_name, pii->pii_ifindex,
	    pii->pii_state, pii->pii_phyint->pi_flags, pii->pii_probe_sock,
	    pii->pii_in_use, pii->pii_phyint->pi_empty,
	    pii->pii_phyint->pi_full);

	for (li = pii->pii_logint; li != NULL; li = li->li_next)
		logint_print(li);

	logdebug("\n");
	for (tg = pii->pii_targets; tg != NULL; tg = tg->tg_next)
		target_print(tg);

	if (pii->pii_targets == NULL)
		logdebug("pi_targets NULL\n");

	if (pii->pii_target_next != NULL) {
		logdebug("pi_target_next %s %s\n", AF_STR(pii->pii_af),
		    pr_addr(pii->pii_af, pii->pii_target_next->tg_address,
		    abuf, sizeof (abuf)));
	} else {
		logdebug("pi_target_next NULL\n");
	}

	if (pii->pii_rtt_target_next != NULL) {
		logdebug("pi_rtt_target_next %s %s\n", AF_STR(pii->pii_af),
		    pr_addr(pii->pii_af, pii->pii_rtt_target_next->tg_address,
		    abuf, sizeof (abuf)));
	} else {
		logdebug("pi_rtt_target_next NULL\n");
	}

	if (pii->pii_targets != NULL) {
		most_recent = PROBE_INDEX_PREV(pii->pii_probe_next);

		i = most_recent;
		do {
			if (pii->pii_probes[i].pr_target != NULL) {
				logdebug("#%d target %s ", i,
				    pr_addr(pii->pii_af,
				    pii->pii_probes[i].pr_target->tg_address,
				    abuf, sizeof (abuf)));
			} else {
				logdebug("#%d target NULL ", i);
			}
			logdebug("time_sent %u status %d time_ack/lost %u\n",
			    pii->pii_probes[i].pr_time_sent,
			    pii->pii_probes[i].pr_status,
			    pii->pii_probes[i].pr_time_lost);
			i = PROBE_INDEX_PREV(i);
		} while (i != most_recent);
	}
}

/*
 * Lookup a logint based on the logical interface name, on the given
 * phyint instance.
 */
static struct logint *
logint_lookup(struct phyint_instance *pii, char *name)
{
	struct logint *li;

	if (debug & D_LOGINT) {
		logdebug("logint_lookup(%s, %s)\n",
		    AF_STR(pii->pii_af), name);
	}

	for (li = pii->pii_logint; li != NULL; li = li->li_next) {
		if (strncmp(name, li->li_name, sizeof (li->li_name)) == 0)
			break;
	}
	return (li);
}

/*
 * Insert a logint at the head of the list of logints of the given
 * phyint instance
 */
static void
logint_insert(struct phyint_instance *pii, struct logint *li)
{
	li->li_next = pii->pii_logint;
	li->li_prev = NULL;
	if (pii->pii_logint != NULL)
		pii->pii_logint->li_prev = li;
	pii->pii_logint = li;
	li->li_phyint_inst = pii;
}

/*
 * Create a new named logint, on the specified phyint instance.
 */
static struct logint *
logint_create(struct phyint_instance *pii, char *name)
{
	struct logint *li;

	if (debug & D_LOGINT) {
		logdebug("logint_create(%s %s %s)\n",
		    AF_STR(pii->pii_af), pii->pii_name, name);
	}

	li = calloc(1, sizeof (struct logint));
	if (li == NULL) {
		logperror("logint_create: calloc");
		return (NULL);
	}

	(void) strncpy(li->li_name, name, sizeof (li->li_name));
	li->li_name[sizeof (li->li_name) - 1] = '\0';
	logint_insert(pii, li);
	return (li);
}

/*
 * Initialize the logint based on the data returned by the kernel.
 */
void
logint_init_from_k(struct phyint_instance *pii, char *li_name)
{
	int	ifsock;
	uint64_t flags;
	uint64_t saved_flags;
	struct	logint	*li;
	struct lifreq	lifr;
	struct in6_addr	test_subnet;
	struct in6_addr	test_subnet_mask;
	struct in6_addr	testaddr;
	int	test_subnet_len;
	struct sockaddr_in6	*sin6;
	struct sockaddr_in	*sin;
	char abuf[INET6_ADDRSTRLEN];
	boolean_t  ptp = _B_FALSE;
	struct in6_addr tgaddr;

	if (debug & D_LOGINT) {
		logdebug("logint_init_from_k(%s %s)\n",
		    AF_STR(pii->pii_af), li_name);
	}

	/* Get the socket for doing ioctls */
	ifsock = (pii->pii_af == AF_INET) ? ifsock_v4 : ifsock_v6;

	/*
	 * Get the flags from the kernel. Also serves as a check whether
	 * the logical still exists. If it doesn't exist, no need to proceed
	 * any further. li_in_use will make the caller clean up the logint
	 */
	(void) strncpy(lifr.lifr_name, li_name, sizeof (lifr.lifr_name));
	lifr.lifr_name[sizeof (lifr.lifr_name) - 1] = '\0';
	if (ioctl(ifsock, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		/* Interface may have vanished */
		if (errno != ENXIO) {
			logperror_pii(pii, "logint_init_from_k: "
			    "ioctl (get flags)");
		}
		return;
	}

	flags = lifr.lifr_flags;

	/*
	 * Verified the logint exists. Now lookup the logint in our tables.
	 * If it does not exist, create a new logint.
	 */
	li = logint_lookup(pii, li_name);
	if (li == NULL) {
		li = logint_create(pii, li_name);
		if (li == NULL) {
			/*
			 * Pretend the interface does not exist
			 * in the kernel
			 */
			return;
		}
	}

	/*
	 * Update li->li_flags with the new flags, after saving the old
	 * value. This is used later to check what flags has changed and
	 * take any action
	 */
	saved_flags = li->li_flags;
	li->li_flags = flags;

	/*
	 * Get the address, prefix, prefixlength and update the logint.
	 * Check if anything has changed. If the logint used for the
	 * test address has changed, take suitable action.
	 */
	if (ioctl(ifsock, SIOCGLIFADDR, (char *)&lifr) < 0) {
		/* Interface may have vanished */
		if (errno != ENXIO) {
			logperror_li(li, "logint_init_from_k: (get addr)");
		}
		goto error;
	}

	if (pii->pii_af == AF_INET) {
		sin = (struct sockaddr_in *)&lifr.lifr_addr;
		IN6_INADDR_TO_V4MAPPED(&sin->sin_addr, &testaddr);
	} else {
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		testaddr = sin6->sin6_addr;
	}

	if (pii->pii_phyint->pi_flags & IFF_POINTOPOINT) {
		ptp = _B_TRUE;
		if (ioctl(ifsock, SIOCGLIFDSTADDR, (char *)&lifr) < 0) {
			if (errno != ENXIO) {
				logperror_li(li, "logint_init_from_k:"
				    " (get dstaddr)");
			}
			goto error;
		}
		if (pii->pii_af == AF_INET) {
			sin = (struct sockaddr_in *)&lifr.lifr_addr;
			IN6_INADDR_TO_V4MAPPED(&sin->sin_addr, &tgaddr);
		} else {
			sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
			tgaddr = sin6->sin6_addr;
		}
	} else {
		if (ioctl(ifsock, SIOCGLIFSUBNET, (char *)&lifr) < 0) {
			/* Interface may have vanished */
			if (errno != ENXIO) {
				logperror_li(li, "logint_init_from_k:"
				    " (get subnet)");
			}
			goto error;
		}
		if (lifr.lifr_subnet.ss_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)&lifr.lifr_subnet;
			test_subnet = sin6->sin6_addr;
			test_subnet_len = lifr.lifr_addrlen;
		} else {
			sin = (struct sockaddr_in *)&lifr.lifr_subnet;
			IN6_INADDR_TO_V4MAPPED(&sin->sin_addr, &test_subnet);
			test_subnet_len = lifr.lifr_addrlen +
			    (IPV6_ABITS - IP_ABITS);
		}
		(void) ip_index_to_mask_v6(test_subnet_len, &test_subnet_mask);
	}

	/*
	 * Also record the OINDEX for completeness. This information is
	 * not used.
	 */
	if (ioctl(ifsock, SIOCGLIFOINDEX, (char *)&lifr) < 0) {
		if (errno != ENXIO)  {
			logperror_li(li, "logint_init_from_k:"
			    " (get lifoindex)");
		}
		goto error;
	}

	/*
	 * If this is the logint corresponding to the test address used for
	 * sending probes, then if anything significant has changed we need to
	 * determine the test address again.  We ignore changes to the
	 * IFF_FAILED and IFF_RUNNING flags since those happen as a matter of
	 * course.
	 */
	if (pii->pii_probe_logint == li) {
		if (((li->li_flags ^ saved_flags) &
		    ~(IFF_FAILED | IFF_RUNNING)) != 0 ||
		    !IN6_ARE_ADDR_EQUAL(&testaddr, &li->li_addr) ||
		    (!ptp && !IN6_ARE_ADDR_EQUAL(&test_subnet,
		    &li->li_subnet)) ||
		    (!ptp && test_subnet_len != li->li_subnet_len) ||
		    (ptp && !IN6_ARE_ADDR_EQUAL(&tgaddr, &li->li_dstaddr))) {
			/*
			 * Something significant that affects the testaddress
			 * has changed. Redo the testaddress selection later on
			 * in select_test_ifs(). For now do the cleanup and
			 * set pii_probe_logint to NULL.
			 */
			if (pii->pii_probe_sock != -1)
				close_probe_socket(pii, _B_TRUE);
			pii->pii_probe_logint = NULL;
		}
	}


	/* Update the logint with the values obtained from the kernel.	*/
	li->li_addr = testaddr;
	li->li_in_use = 1;
	li->li_oifindex = lifr.lifr_index;
	if (ptp) {
		li->li_dstaddr = tgaddr;
		li->li_subnet_len = (pii->pii_af == AF_INET) ?
		    IP_ABITS : IPV6_ABITS;
	} else {
		li->li_subnet = test_subnet;
		li->li_subnet_len = test_subnet_len;
	}

	if (debug & D_LOGINT)
		logint_print(li);

	return;

error:
	logerr("logint_init_from_k: IGNORED %s %s %s addr %s\n",
	    AF_STR(pii->pii_af), pii->pii_name, li->li_name,
	    pr_addr(pii->pii_af, testaddr, abuf, sizeof (abuf)));
	logint_delete(li);
}

/*
 * Delete (unlink and free) a logint.
 */
void
logint_delete(struct logint *li)
{
	struct phyint_instance *pii;

	pii = li->li_phyint_inst;
	assert(pii != NULL);

	if (debug & D_LOGINT) {
		int af;
		char abuf[INET6_ADDRSTRLEN];

		af = pii->pii_af;
		logdebug("logint_delete(%s %s %s/%u)\n",
		    AF_STR(af), li->li_name,
		    pr_addr(af, li->li_addr, abuf, sizeof (abuf)),
		    li->li_subnet_len);
	}

	/* logint must be in the list of logints */
	assert(pii->pii_logint == li || li->li_prev != NULL);

	/* Remove the logint from the list of logints  */
	if (li->li_prev == NULL) {
		/* logint is the 1st in the list */
		pii->pii_logint = li->li_next;
	} else {
		li->li_prev->li_next = li->li_next;
	}
	if (li->li_next != NULL)
		li->li_next->li_prev = li->li_prev;
	li->li_next = NULL;
	li->li_prev = NULL;

	/*
	 * If this logint is also being used for probing, then close the
	 * associated socket, if it exists.
	 */
	if (pii->pii_probe_logint == li) {
		if (pii->pii_probe_sock != -1)
			close_probe_socket(pii, _B_TRUE);
		pii->pii_probe_logint = NULL;
	}

	free(li);
}

static void
logint_print(struct logint *li)
{
	char abuf[INET6_ADDRSTRLEN];
	int af;

	af = li->li_phyint_inst->pii_af;

	logdebug("logint: %s %s addr %s/%u", AF_STR(af), li->li_name,
	    pr_addr(af, li->li_addr, abuf, sizeof (abuf)), li->li_subnet_len);

	logdebug("\tFlags: %llx in_use %d oifindex %d\n",
	    li->li_flags, li->li_in_use, li->li_oifindex);
}

char *
pr_addr(int af, struct in6_addr addr, char *abuf, int len)
{
	struct in_addr	addr_v4;

	if (af == AF_INET) {
		IN6_V4MAPPED_TO_INADDR(&addr, &addr_v4);
		(void) inet_ntop(AF_INET, (void *)&addr_v4, abuf, len);
	} else {
		(void) inet_ntop(AF_INET6, (void *)&addr, abuf, len);
	}
	return (abuf);
}

/* Lookup target on its address */
struct target *
target_lookup(struct phyint_instance *pii, struct in6_addr addr)
{
	struct target *tg;

	if (debug & D_TARGET) {
		char abuf[INET6_ADDRSTRLEN];

		logdebug("target_lookup(%s %s): addr %s\n",
		    AF_STR(pii->pii_af), pii->pii_name,
		    pr_addr(pii->pii_af, addr, abuf, sizeof (abuf)));
	}

	for (tg = pii->pii_targets; tg != NULL; tg = tg->tg_next) {
		if (IN6_ARE_ADDR_EQUAL(&tg->tg_address, &addr))
			break;
	}
	return (tg);
}

/*
 * Find and return the next active target, for the next probe.
 * If no active targets are available, return NULL.
 */
struct target *
target_next(struct target *tg)
{
	struct	phyint_instance	*pii = tg->tg_phyint_inst;
	struct	target	*marker = tg;
	hrtime_t now;

	now = gethrtime();

	/*
	 * Target must be in the list of targets for this phyint
	 * instance.
	 */
	assert(pii->pii_targets == tg || tg->tg_prev != NULL);
	assert(pii->pii_targets != NULL);

	/* Return the next active target */
	do {
		/*
		 * Go to the next target. If we hit the end,
		 * reset the ptr to the head
		 */
		tg = tg->tg_next;
		if (tg == NULL)
			tg = pii->pii_targets;

		assert(TG_STATUS_VALID(tg->tg_status));

		switch (tg->tg_status) {
		case TG_ACTIVE:
			return (tg);

		case TG_UNUSED:
			assert(pii->pii_targets_are_routers);
			if (pii->pii_ntargets < MAX_PROBE_TARGETS) {
				/*
				 * Bubble up the unused target to active
				 */
				tg->tg_status = TG_ACTIVE;
				pii->pii_ntargets++;
				return (tg);
			}
			break;

		case TG_SLOW:
			assert(pii->pii_targets_are_routers);
			if (tg->tg_latime + MIN_RECOVERY_TIME < now) {
				/*
				 * Bubble up the slow target to unused
				 */
				tg->tg_status = TG_UNUSED;
			}
			break;

		case TG_DEAD:
			assert(pii->pii_targets_are_routers);
			if (tg->tg_latime + MIN_RECOVERY_TIME < now) {
				/*
				 * Bubble up the dead target to slow
				 */
				tg->tg_status = TG_SLOW;
				tg->tg_latime = now;
			}
			break;
		}

	} while (tg != marker);

	return (NULL);
}

/*
 * Select the best available target, that is not already TG_ACTIVE,
 * for the caller. The caller will determine whether it wants to
 * make the returned target TG_ACTIVE.
 * The selection order is as follows.
 * 1. pick a TG_UNSED target, if it exists.
 * 2. else pick a TG_SLOW target that has recovered, if it exists
 * 3. else pick any TG_SLOW target, if it exists
 * 4. else pick a TG_DEAD target that has recovered, if it exists
 * 5. else pick any TG_DEAD target, if it exists
 * 6. else return null
 */
static struct target *
target_select_best(struct phyint_instance *pii)
{
	struct target *tg;
	struct target *slow = NULL;
	struct target *dead = NULL;
	struct target *slow_recovered = NULL;
	struct target *dead_recovered = NULL;
	hrtime_t now;

	now = gethrtime();

	for (tg = pii->pii_targets; tg != NULL; tg = tg->tg_next) {
		assert(TG_STATUS_VALID(tg->tg_status));

		switch (tg->tg_status) {
		case TG_UNUSED:
			return (tg);

		case TG_SLOW:
			if (tg->tg_latime + MIN_RECOVERY_TIME < now) {
				slow_recovered = tg;
				/*
				 * Promote the slow_recoverd to unused
				 */
				tg->tg_status = TG_UNUSED;
			} else {
				slow = tg;
			}
			break;

		case TG_DEAD:
			if (tg->tg_latime + MIN_RECOVERY_TIME < now) {
				dead_recovered = tg;
				/*
				 * Promote the dead_recoverd to slow
				 */
				tg->tg_status = TG_SLOW;
				tg->tg_latime = now;
			} else {
				dead = tg;
			}
			break;

		default:
			break;
		}
	}

	if (slow_recovered != NULL)
		return (slow_recovered);
	else if (slow != NULL)
		return (slow);
	else if (dead_recovered != NULL)
		return (dead_recovered);
	else
		return (dead);
}

/*
 * Some target was deleted. If we don't have even MIN_PROBE_TARGETS
 * that are active, pick the next best below.
 */
static void
target_activate_all(struct phyint_instance *pii)
{
	struct target *tg;

	assert(pii->pii_ntargets == 0);
	assert(pii->pii_target_next == NULL);
	assert(pii->pii_rtt_target_next == NULL);
	assert(pii->pii_targets_are_routers);

	while (pii->pii_ntargets < MIN_PROBE_TARGETS) {
		tg = target_select_best(pii);
		if (tg == NULL) {
			/* We are out of targets */
			return;
		}

		assert(TG_STATUS_VALID(tg->tg_status));
		assert(tg->tg_status != TG_ACTIVE);
		tg->tg_status = TG_ACTIVE;
		pii->pii_ntargets++;
		if (pii->pii_target_next == NULL) {
			pii->pii_target_next = tg;
			pii->pii_rtt_target_next = tg;
		}
	}
}

static struct target *
target_first(struct phyint_instance *pii)
{
	struct target *tg;

	for (tg = pii->pii_targets; tg != NULL; tg = tg->tg_next) {
		assert(TG_STATUS_VALID(tg->tg_status));
		if (tg->tg_status == TG_ACTIVE)
			break;
	}

	return (tg);
}

/*
 * Create a default target entry.
 */
void
target_create(struct phyint_instance *pii, struct in6_addr addr,
    boolean_t is_router)
{
	struct target *tg;
	struct phyint *pi;
	struct logint *li;

	if (debug & D_TARGET) {
		char abuf[INET6_ADDRSTRLEN];

		logdebug("target_create(%s %s, %s)\n",
		    AF_STR(pii->pii_af), pii->pii_name,
		    pr_addr(pii->pii_af, addr, abuf, sizeof (abuf)));
	}

	/*
	 * If the test address is not yet initialized, do not add
	 * any target, since we cannot determine whether the target
	 * belongs to the same subnet as the test address.
	 */
	li = pii->pii_probe_logint;
	if (li == NULL)
		return;

	/*
	 * If there are multiple subnets associated with an interface, then
	 * add the target to this phyint instance, only if it belongs to the
	 * same subnet as the test address. The reason is that interface
	 * routes derived from non-test-addresses i.e. non-IFF_NOFAILOVER
	 * addresses, will disappear after failover, and the targets will not
	 * be reachable from this interface.
	 */
	if (!prefix_equal(li->li_subnet, addr, li->li_subnet_len))
		return;

	if (pii->pii_targets != NULL) {
		assert(pii->pii_ntargets <= MAX_PROBE_TARGETS);
		if (is_router) {
			if (!pii->pii_targets_are_routers) {
				/*
				 * Prefer router over hosts. Using hosts is a
				 * fallback mechanism, hence delete all host
				 * targets.
				 */
				while (pii->pii_targets != NULL)
					target_delete(pii->pii_targets);
			}
		} else {
			/*
			 * Routers take precedence over hosts. If this
			 * is a router list and we are trying to add a
			 * host, just return. If this is a host list
			 * and if we have sufficient targets, just return
			 */
			if (pii->pii_targets_are_routers ||
			    pii->pii_ntargets == MAX_PROBE_TARGETS)
				return;
		}
	}

	tg = calloc(1, sizeof (struct target));
	if (tg == NULL) {
		logperror("target_create: calloc");
		return;
	}

	tg->tg_phyint_inst = pii;
	tg->tg_address = addr;
	tg->tg_in_use = 1;
	tg->tg_rtt_sa = -1;
	tg->tg_num_deferred = 0;

	/*
	 * If this is the first target, set 'pii_targets_are_routers'
	 * The list of targets is either a list of hosts or list or
	 * routers, but not a mix.
	 */
	if (pii->pii_targets == NULL) {
		assert(pii->pii_ntargets == 0);
		assert(pii->pii_target_next == NULL);
		assert(pii->pii_rtt_target_next == NULL);
		pii->pii_targets_are_routers = is_router ? 1 : 0;
	}

	if (pii->pii_ntargets == MAX_PROBE_TARGETS) {
		assert(pii->pii_targets_are_routers);
		assert(pii->pii_target_next != NULL);
		assert(pii->pii_rtt_target_next != NULL);
		tg->tg_status = TG_UNUSED;
	} else {
		if (pii->pii_ntargets == 0) {
			assert(pii->pii_target_next == NULL);
			pii->pii_target_next = tg;
			pii->pii_rtt_target_next = tg;
		}
		pii->pii_ntargets++;
		tg->tg_status = TG_ACTIVE;
	}

	target_insert(pii, tg);

	/*
	 * Change state to PI_RUNNING if this phyint instance is capable of
	 * sending and receiving probes -- that is, if we know of at least 1
	 * target, and this phyint instance is probe-capable.  For more
	 * details, see the phyint state diagram in mpd_probe.c.
	 */
	pi = pii->pii_phyint;
	if (pi->pi_state == PI_NOTARGETS && PROBE_CAPABLE(pii)) {
		if (pi->pi_flags & IFF_FAILED)
			phyint_chstate(pi, PI_FAILED);
		else
			phyint_chstate(pi, PI_RUNNING);
	}
}

/*
 * Add the target address named by `addr' to phyint instance `pii' if it does
 * not already exist.  If the target is a router, `is_router' should be set to
 * B_TRUE.
 */
void
target_add(struct phyint_instance *pii, struct in6_addr addr,
    boolean_t is_router)
{
	struct target *tg;

	if (pii == NULL)
		return;

	tg = target_lookup(pii, addr);

	/*
	 * If the target does not exist, create it; target_create() will set
	 * tg_in_use to true.  If it exists already, and it is a router
	 * target, set tg_in_use to to true, so that init_router_targets()
	 * won't delete it
	 */
	if (tg == NULL)
		target_create(pii, addr, is_router);
	else if (is_router)
		tg->tg_in_use = 1;
}

/*
 * Insert target at head of linked list of targets for the associated
 * phyint instance
 */
static void
target_insert(struct phyint_instance *pii, struct target *tg)
{
	tg->tg_next = pii->pii_targets;
	tg->tg_prev = NULL;
	if (tg->tg_next != NULL)
		tg->tg_next->tg_prev = tg;
	pii->pii_targets = tg;
}

/*
 * Delete a target (unlink and free).
 */
void
target_delete(struct target *tg)
{
	int af;
	struct phyint_instance	*pii;
	struct phyint_instance	*pii_other;

	pii = tg->tg_phyint_inst;
	af = pii->pii_af;

	if (debug & D_TARGET) {
		char abuf[INET6_ADDRSTRLEN];

		logdebug("target_delete(%s %s, %s)\n",
		    AF_STR(af), pii->pii_name,
		    pr_addr(af, tg->tg_address, abuf, sizeof (abuf)));
	}

	/*
	 * Target must be in the list of targets for this phyint
	 * instance.
	 */
	assert(pii->pii_targets == tg || tg->tg_prev != NULL);

	/*
	 * Reset all references to 'tg' in the probe information
	 * for this phyint.
	 */
	reset_pii_probes(pii, tg);

	/*
	 * Remove this target from the list of targets of this
	 * phyint instance.
	 */
	if (tg->tg_prev == NULL) {
		pii->pii_targets = tg->tg_next;
	} else {
		tg->tg_prev->tg_next = tg->tg_next;
	}

	if (tg->tg_next != NULL)
		tg->tg_next->tg_prev = tg->tg_prev;

	tg->tg_next = NULL;
	tg->tg_prev = NULL;

	if (tg->tg_status == TG_ACTIVE)
		pii->pii_ntargets--;

	/*
	 * Adjust the next target to probe, if it points to
	 * to the currently deleted target.
	 */
	if (pii->pii_target_next == tg)
		pii->pii_target_next = target_first(pii);

	if (pii->pii_rtt_target_next == tg)
		pii->pii_rtt_target_next = target_first(pii);

	free(tg);

	/*
	 * The number of active targets pii_ntargets == 0 iff
	 * the next active target pii->pii_target_next == NULL
	 */
	if (pii->pii_ntargets != 0) {
		assert(pii->pii_target_next != NULL);
		assert(pii->pii_rtt_target_next != NULL);
		assert(pii->pii_target_next->tg_status == TG_ACTIVE);
		assert(pii->pii_rtt_target_next->tg_status == TG_ACTIVE);
		return;
	}

	/* At this point, we don't have any active targets. */
	assert(pii->pii_target_next == NULL);
	assert(pii->pii_rtt_target_next == NULL);

	if (pii->pii_targets_are_routers) {
		/*
		 * Activate any TG_SLOW or TG_DEAD router targets,
		 * since we don't have any other targets
		 */
		target_activate_all(pii);

		if (pii->pii_ntargets != 0) {
			assert(pii->pii_target_next != NULL);
			assert(pii->pii_rtt_target_next != NULL);
			assert(pii->pii_target_next->tg_status == TG_ACTIVE);
			assert(pii->pii_rtt_target_next->tg_status ==
			    TG_ACTIVE);
			return;
		}
	}

	/*
	 * If we still don't have any active targets, the list must
	 * must be really empty. There aren't even TG_SLOW or TG_DEAD
	 * targets. Zero out the probe stats since it will not be
	 * relevant any longer.
	 */
	assert(pii->pii_targets == NULL);
	clear_pii_probe_stats(pii);
	pii_other = phyint_inst_other(pii);

	/*
	 * If there are no targets on both instances and the interface is
	 * online, go back to PI_NOTARGETS state, since we cannot probe this
	 * phyint any more.  For more details, please see phyint state
	 * diagram in mpd_probe.c.
	 */
	if (!PROBE_CAPABLE(pii_other) &&
	    pii->pii_phyint->pi_state != PI_OFFLINE)
		phyint_chstate(pii->pii_phyint, PI_NOTARGETS);
}

/*
 * Flush the target list of every phyint in the group, if the list
 * is a host target list. This is called if group failure is suspected.
 * If all targets have failed, multicast will subsequently discover new
 * targets. Else it is a group failure.
 * Note: This function is a no-op if the list is a router target list.
 */
static void
target_flush_hosts(struct phyint_group *pg)
{
	struct phyint *pi;
	struct phyint_instance *pii;

	if (debug & D_TARGET)
		logdebug("target_flush_hosts(%s)\n", pg->pg_name);

	for (pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext) {
		pii = pi->pi_v4;
		if (pii != NULL && !pii->pii_targets_are_routers) {
			/*
			 * Delete all the targets. When the list becomes
			 * empty, target_delete() will set pii->pii_targets
			 * to NULL.
			 */
			while (pii->pii_targets != NULL)
				target_delete(pii->pii_targets);
		}
		pii = pi->pi_v6;
		if (pii != NULL && !pii->pii_targets_are_routers) {
			/*
			 * Delete all the targets. When the list becomes
			 * empty, target_delete() will set pii->pii_targets
			 * to NULL.
			 */
			while (pii->pii_targets != NULL)
				target_delete(pii->pii_targets);
		}
	}
}

/*
 * Reset all references to 'target' in the probe info, as this target is
 * being deleted. The pr_target field is guaranteed to be non-null if
 * pr_status is PR_UNACKED. So we change the pr_status to PR_LOST, so that
 * pr_target will not be accessed unconditionally.
 */
static void
reset_pii_probes(struct phyint_instance *pii, struct target *tg)
{
	int i;

	for (i = 0; i < PROBE_STATS_COUNT; i++) {
		if (pii->pii_probes[i].pr_target == tg) {
			pii->pii_probes[i].pr_target = NULL;
			if (pii->pii_probes[i].pr_status == PR_UNACKED)
				pii->pii_probes[i].pr_status = PR_LOST;
		}
	}

}

/*
 * Clear the probe statistics array.
 */
void
clear_pii_probe_stats(struct phyint_instance *pii)
{
	bzero(pii->pii_probes, sizeof (struct probe_stats) * PROBE_STATS_COUNT);
	/* Reset the next probe index in the probe stats array */
	pii->pii_probe_next = 0;
}

static void
target_print(struct target *tg)
{
	char	abuf[INET6_ADDRSTRLEN];
	char	buf[128];
	char	buf2[128];
	int	af;
	int	i;

	af = tg->tg_phyint_inst->pii_af;

	logdebug("Target on %s %s addr %s\n"
	    "status %d rtt_sa %d rtt_sd %d crtt %d tg_in_use %d\n",
	    AF_STR(af), tg->tg_phyint_inst->pii_name,
	    pr_addr(af, tg->tg_address, abuf, sizeof (abuf)),
	    tg->tg_status, tg->tg_rtt_sa, tg->tg_rtt_sd,
	    tg->tg_crtt, tg->tg_in_use);

	buf[0] = '\0';
	for (i = 0; i < tg->tg_num_deferred; i++) {
		(void) snprintf(buf2, sizeof (buf2), " %dms",
		    tg->tg_deferred[i]);
		(void) strlcat(buf, buf2, sizeof (buf));
	}
	logdebug("deferred rtts:%s\n", buf);
}

void
phyint_inst_print_all(void)
{
	struct phyint_instance *pii;

	for (pii = phyint_instances; pii != NULL; pii = pii->pii_next) {
		phyint_inst_print(pii);
	}
}

/*
 * Convert length for a mask to the mask.
 */
static void
ip_index_to_mask_v6(uint_t masklen, struct in6_addr *bitmask)
{
	int	j;

	assert(masklen <= IPV6_ABITS);
	bzero((char *)bitmask, sizeof (*bitmask));

	/* Make the 'masklen' leftmost bits one */
	for (j = 0; masklen > 8; masklen -= 8, j++)
		bitmask->s6_addr[j] = 0xff;

	bitmask->s6_addr[j] = 0xff << (8 - masklen);

}

/*
 * Compare two prefixes that have the same prefix length.
 * Fails if the prefix length is unreasonable.
 */
static boolean_t
prefix_equal(struct in6_addr p1, struct in6_addr p2, int prefix_len)
{
	uchar_t mask;
	int j;

	if (prefix_len < 0 || prefix_len > IPV6_ABITS)
		return (_B_FALSE);

	for (j = 0; prefix_len > 8; prefix_len -= 8, j++)
		if (p1.s6_addr[j] != p2.s6_addr[j])
			return (_B_FALSE);

	/* Make the N leftmost bits one */
	mask = 0xff << (8 - prefix_len);
	if ((p1.s6_addr[j] & mask) != (p2.s6_addr[j] & mask))
		return (_B_FALSE);

	return (_B_TRUE);
}

/*
 * Get the number of UP logints (excluding IFF_NOFAILOVERs), on both
 * IPv4 and IPv6 put together. The phyint with the least such number
 * will be used as the failover destination, if no standby interface is
 * available
 */
int
logint_upcount(struct phyint *pi)
{
	struct	logint	*li;
	struct	phyint_instance *pii;
	int count = 0;

	pii = pi->pi_v4;
	if (pii != NULL) {
		for (li = pii->pii_logint; li != NULL; li = li->li_next) {
			if ((li->li_flags &
			    (IFF_UP | IFF_NOFAILOVER)) == IFF_UP) {
				count++;
			}
		}
	}

	pii = pi->pi_v6;
	if (pii != NULL) {
		for (li = pii->pii_logint; li != NULL; li = li->li_next) {
			if ((li->li_flags &
			    (IFF_UP | IFF_NOFAILOVER)) == IFF_UP) {
				count++;
			}
		}
	}

	return (count);
}

/*
 * Get the phyint instance with the other (IPv4 / IPv6) protocol
 */
struct phyint_instance *
phyint_inst_other(struct phyint_instance *pii)
{
	if (pii->pii_af == AF_INET)
		return (pii->pii_phyint->pi_v6);
	else
		return (pii->pii_phyint->pi_v4);
}

/*
 * Post an EC_IPMP sysevent of subclass `subclass' and attributes `nvl'.
 * Before sending the event, it prepends the current version of the IPMP
 * sysevent API.  Returns 0 on success, -1 on failure (in either case,
 * `nvl' is freed).
 */
static int
post_event(const char *subclass, nvlist_t *nvl)
{
	sysevent_id_t eid;

	/*
	 * Since sysevents don't work yet in non-global zones, there cannot
	 * possibly be any consumers yet, so don't bother trying to generate
	 * them.  (Otherwise, we'll spew warnings.)
	 */
	if (getzoneid() != GLOBAL_ZONEID) {
		nvlist_free(nvl);
		return (0);
	}

	errno = nvlist_add_uint32(nvl, IPMP_EVENT_VERSION,
	    IPMP_EVENT_CUR_VERSION);
	if (errno != 0) {
		logerr("cannot create `%s' event: %s", subclass,
		    strerror(errno));
		goto failed;
	}

	if (sysevent_post_event(EC_IPMP, (char *)subclass, SUNW_VENDOR,
	    "in.mpathd", nvl, &eid) == -1) {
		logerr("cannot send `%s' event: %s\n", subclass,
		    strerror(errno));
		goto failed;
	}

	nvlist_free(nvl);
	return (0);
failed:
	nvlist_free(nvl);
	return (-1);
}

/*
 * Return the external IPMP state associated with phyint `pi'.
 */
static ipmp_if_state_t
ifstate(struct phyint *pi)
{
	switch (pi->pi_state) {
	case PI_NOTARGETS:
		return (IPMP_IF_UNKNOWN);

	case PI_OFFLINE:
		return (IPMP_IF_OFFLINE);

	case PI_FAILED:
		return (IPMP_IF_FAILED);

	case PI_RUNNING:
		return (IPMP_IF_OK);
	}

	logerr("ifstate: unknown state %d; aborting\n", pi->pi_state);
	abort();
	/* NOTREACHED */
}

/*
 * Return the external IPMP interface type associated with phyint `pi'.
 */
static ipmp_if_type_t
iftype(struct phyint *pi)
{
	if (pi->pi_flags & IFF_STANDBY)
		return (IPMP_IF_STANDBY);
	else
		return (IPMP_IF_NORMAL);
}

/*
 * Return the external IPMP group state associated with phyint group `pg'.
 */
static ipmp_group_state_t
groupstate(struct phyint_group *pg)
{
	return (GROUP_FAILED(pg) ? IPMP_GROUP_FAILED : IPMP_GROUP_OK);
}

/*
 * Generate an ESC_IPMP_GROUP_STATE sysevent for phyint group `pg'.
 * Returns 0 on success, -1 on failure.
 */
static int
phyint_group_state_event(struct phyint_group *pg)
{
	nvlist_t	*nvl;

	errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (errno != 0) {
		logperror("cannot create `group state change' event");
		return (-1);
	}

	errno = nvlist_add_string(nvl, IPMP_GROUP_NAME, pg->pg_name);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint64(nvl, IPMP_GROUP_SIGNATURE, pg->pg_sig);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_GROUP_STATE, groupstate(pg));
	if (errno != 0)
		goto failed;

	return (post_event(ESC_IPMP_GROUP_STATE, nvl));
failed:
	logperror("cannot create `group state change' event");
	nvlist_free(nvl);
	return (-1);
}

/*
 * Generate an ESC_IPMP_GROUP_CHANGE sysevent of type `op' for phyint group
 * `pg'.  Returns 0 on success, -1 on failure.
 */
static int
phyint_group_change_event(struct phyint_group *pg, ipmp_group_op_t op)
{
	nvlist_t *nvl;

	errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (errno != 0) {
		logperror("cannot create `group change' event");
		return (-1);
	}

	errno = nvlist_add_string(nvl, IPMP_GROUP_NAME, pg->pg_name);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint64(nvl, IPMP_GROUP_SIGNATURE, pg->pg_sig);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint64(nvl, IPMP_GROUPLIST_SIGNATURE,
	    phyint_grouplistsig);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_GROUP_OPERATION, op);
	if (errno != 0)
		goto failed;

	return (post_event(ESC_IPMP_GROUP_CHANGE, nvl));
failed:
	logperror("cannot create `group change' event");
	nvlist_free(nvl);
	return (-1);
}

/*
 * Generate an ESC_IPMP_GROUP_MEMBER_CHANGE sysevent for phyint `pi' in
 * group `pg'.	Returns 0 on success, -1 on failure.
 */
static int
phyint_group_member_event(struct phyint_group *pg, struct phyint *pi,
    ipmp_if_op_t op)
{
	nvlist_t *nvl;

	errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (errno != 0) {
		logperror("cannot create `group member change' event");
		return (-1);
	}

	errno = nvlist_add_string(nvl, IPMP_GROUP_NAME, pg->pg_name);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint64(nvl, IPMP_GROUP_SIGNATURE, pg->pg_sig);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_IF_OPERATION, op);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_string(nvl, IPMP_IF_NAME, pi->pi_name);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_IF_TYPE, iftype(pi));
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_IF_STATE, ifstate(pi));
	if (errno != 0)
		goto failed;

	return (post_event(ESC_IPMP_GROUP_MEMBER_CHANGE, nvl));
failed:
	logperror("cannot create `group member change' event");
	nvlist_free(nvl);
	return (-1);

}

/*
 * Generate an ESC_IPMP_IF_CHANGE sysevent for phyint `pi' in group `pg'.
 * Returns 0 on success, -1 on failure.
 */
static int
phyint_state_event(struct phyint_group *pg, struct phyint *pi)
{
	nvlist_t *nvl;

	errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (errno != 0) {
		logperror("cannot create `interface change' event");
		return (-1);
	}

	errno = nvlist_add_string(nvl, IPMP_GROUP_NAME, pg->pg_name);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint64(nvl, IPMP_GROUP_SIGNATURE, pg->pg_sig);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_string(nvl, IPMP_IF_NAME, pi->pi_name);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_IF_TYPE, iftype(pi));
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_IF_STATE, ifstate(pi));
	if (errno != 0)
		goto failed;

	return (post_event(ESC_IPMP_IF_CHANGE, nvl));
failed:
	logperror("cannot create `interface change' event");
	nvlist_free(nvl);
	return (-1);

}

/*
 * Generate a signature for use.  The signature is conceptually divided
 * into two pieces: a random 16-bit "generation number" and a 48-bit
 * monotonically increasing integer.  The generation number protects
 * against stale updates to entities (e.g., IPMP groups) that have been
 * deleted and since recreated.
 */
static uint64_t
gensig(void)
{
	static int seeded = 0;

	if (seeded == 0) {
		srand48((long)gethrtime());
		seeded++;
	}

	return ((uint64_t)lrand48() << 48 | 1);
}

/*
 * Store the information associated with group `grname' into a dynamically
 * allocated structure pointed to by `*grinfopp'.  Returns an IPMP error code.
 */
unsigned int
getgroupinfo(const char *grname, ipmp_groupinfo_t **grinfopp)
{
	struct phyint_group	*pg;
	struct phyint		*pi;
	char			(*ifs)[LIFNAMSIZ];
	unsigned int		nif, i;

	pg = phyint_group_lookup(grname);
	if (pg == NULL)
		return (IPMP_EUNKGROUP);

	/*
	 * Tally up the number of interfaces, allocate an array to hold them,
	 * and insert their names into the array.
	 */
	for (nif = 0, pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext)
		nif++;

	ifs = alloca(nif * sizeof (*ifs));
	for (i = 0, pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext, i++) {
		assert(i < nif);
		(void) strlcpy(ifs[i], pi->pi_name, LIFNAMSIZ);
	}
	assert(i == nif);

	*grinfopp = ipmp_groupinfo_create(pg->pg_name, pg->pg_sig,
	    groupstate(pg), nif, ifs);
	return (*grinfopp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
}

/*
 * Store the information associated with interface `ifname' into a dynamically
 * allocated structure pointed to by `*ifinfopp'.  Returns an IPMP error code.
 */
unsigned int
getifinfo(const char *ifname, ipmp_ifinfo_t **ifinfopp)
{
	struct phyint	*pi;

	pi = phyint_lookup(ifname);
	if (pi == NULL)
		return (IPMP_EUNKIF);

	*ifinfopp = ipmp_ifinfo_create(pi->pi_name, pi->pi_group->pg_name,
	    ifstate(pi), iftype(pi));
	return (*ifinfopp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
}

/*
 * Store the current list of IPMP groups into a dynamically allocated
 * structure pointed to by `*grlistpp'.	 Returns an IPMP error code.
 */
unsigned int
getgrouplist(ipmp_grouplist_t **grlistpp)
{
	struct phyint_group	*pg;
	char			(*groups)[LIFGRNAMSIZ];
	unsigned int		i, ngroup;

	/*
	 * Tally up the number of groups, allocate an array to hold them, and
	 * insert their names into the array.
	 */
	for (ngroup = 0, pg = phyint_groups; pg != NULL; pg = pg->pg_next)
		ngroup++;

	groups = alloca(ngroup * sizeof (*groups));
	for (i = 0, pg = phyint_groups; pg != NULL; pg = pg->pg_next, i++) {
		assert(i < ngroup);
		(void) strlcpy(groups[i], pg->pg_name, LIFGRNAMSIZ);
	}
	assert(i == ngroup);

	*grlistpp = ipmp_grouplist_create(phyint_grouplistsig, ngroup, groups);
	return (*grlistpp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
}

/*
 * Store a snapshot of the IPMP subsystem into a dynamically allocated
 * structure pointed to by `*snapp'.  Returns an IPMP error code.
 */
unsigned int
getsnap(ipmp_snap_t **snapp)
{
	ipmp_grouplist_t	*grlistp;
	ipmp_groupinfo_t	*grinfop;
	ipmp_ifinfo_t		*ifinfop;
	ipmp_snap_t		*snap;
	struct phyint		*pi;
	unsigned int		i;
	int			retval;

	snap = ipmp_snap_create();
	if (snap == NULL)
		return (IPMP_ENOMEM);

	/*
	 * Add group list.
	 */
	retval = getgrouplist(&snap->sn_grlistp);
	if (retval != IPMP_SUCCESS) {
		ipmp_snap_free(snap);
		return (retval);
	}

	/*
	 * Add information for each group in the list.
	 */
	grlistp = snap->sn_grlistp;
	for (i = 0; i < grlistp->gl_ngroup; i++) {
		retval = getgroupinfo(grlistp->gl_groups[i], &grinfop);
		if (retval != IPMP_SUCCESS) {
			ipmp_snap_free(snap);
			return (retval);
		}
		retval = ipmp_snap_addgroupinfo(snap, grinfop);
		if (retval != IPMP_SUCCESS) {
			ipmp_freegroupinfo(grinfop);
			ipmp_snap_free(snap);
			return (retval);
		}
	}

	/*
	 * Add information for each configured phyint.
	 */
	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		retval = getifinfo(pi->pi_name, &ifinfop);
		if (retval != IPMP_SUCCESS) {
			ipmp_snap_free(snap);
			return (retval);
		}
		retval = ipmp_snap_addifinfo(snap, ifinfop);
		if (retval != IPMP_SUCCESS) {
			ipmp_freeifinfo(ifinfop);
			ipmp_snap_free(snap);
			return (retval);
		}
	}

	*snapp = snap;
	return (IPMP_SUCCESS);
}
