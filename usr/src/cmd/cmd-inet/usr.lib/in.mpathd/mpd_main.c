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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "mpd_defs.h"
#include "mpd_tables.h"

int debug = 0;				/* Debug flag */
static int pollfd_num = 0;		/* Num. of poll descriptors */
static struct pollfd *pollfds = NULL;	/* Array of poll descriptors */
					/* All times below in ms */
int	user_failure_detection_time;	/* user specified failure detection */
					/* time (fdt) */
int	user_probe_interval;		/* derived from user specified fdt */

/*
 * Structure to store mib2 information returned by the kernel.
 * This is used to process routing table information.
 */
typedef struct mib_item_s {
	struct mib_item_s	*mi_next;
	struct opthdr		mi_opthdr;
	void			*mi_valp;
} mib_item_t;

static int	rtsock_v4;		/* AF_INET routing socket */
static int	rtsock_v6;		/* AF_INET6 routing socket */
int	ifsock_v4 = -1;			/* IPv4 socket for ioctls  */
int	ifsock_v6 = -1;			/* IPv6 socket for ioctls  */
static int	lsock_v4;		/* Listen socket to detect mpathd */
static int	lsock_v6;		/* Listen socket to detect mpathd */
static int	mibfd = -1;		/* fd to get mib info */
static boolean_t force_mcast = _B_FALSE; /* Only for test purposes */

static uint_t	last_initifs_time;	/* Time when initifs was last run */
static	char **argv0;			/* Saved for re-exec on SIGHUP */
boolean_t handle_link_notifications = _B_TRUE;
static int	ipRouteEntrySize;	/* Size of IPv4 route entry */
static int	ipv6RouteEntrySize;	/* Size of IPv6 route entry */

static void	initlog(void);
static void	run_timeouts(void);
static void	initifs(void);
static void	check_if_removed(struct phyint_instance *pii);
static void	select_test_ifs(void);
static void	update_router_list(mib_item_t *item);
static void	mib_get_constants(mib_item_t *item);
static int	mibwalk(void (*proc)(mib_item_t *));
static void	ire_process_v4(mib2_ipRouteEntry_t *buf, size_t len);
static void	ire_process_v6(mib2_ipv6RouteEntry_t *buf, size_t len);
static void	router_add_common(int af, char *ifname,
    struct in6_addr nexthop);
static void	init_router_targets();
static void	cleanup(void);
static int	setup_listener(int af);
static void	check_config(void);
static void	check_testconfig(void);
static void	check_addr_unique(struct phyint_instance *,
    struct sockaddr_storage *);
static void	init_host_targets(void);
static void	dup_host_targets(struct phyint_instance *desired_pii);
static void	loopback_cmd(int sock, int family);
static boolean_t daemonize(void);
static int	closefunc(void *, int);
static unsigned int process_cmd(int newfd, union mi_commands *mpi);
static unsigned int process_query(int fd, mi_query_t *miq);
static unsigned int send_addrinfo(int fd, ipmp_addrinfo_t *adinfop);
static unsigned int send_groupinfo(int fd, ipmp_groupinfo_t *grinfop);
static unsigned int send_grouplist(int fd, ipmp_grouplist_t *grlistp);
static unsigned int send_ifinfo(int fd, ipmp_ifinfo_t *ifinfop);
static unsigned int send_result(int fd, unsigned int error, int syserror);

addrlist_t *localaddrs;

/*
 * Return the current time in milliseconds (from an arbitrary reference)
 * truncated to fit into an int. Truncation is ok since we are interested
 * only in differences and not the absolute values.
 */
uint_t
getcurrenttime(void)
{
	uint_t	cur_time;	/* In ms */

	/*
	 * Use of a non-user-adjustable source of time is
	 * required. However millisecond precision is sufficient.
	 * divide by 10^6
	 */
	cur_time = (uint_t)(gethrtime() / 1000000LL);
	return (cur_time);
}

uint64_t
getcurrentsec(void)
{
	return (gethrtime() / NANOSEC);
}

/*
 * Add fd to the set being polled. Returns 0 if ok; -1 if failed.
 */
int
poll_add(int fd)
{
	int i;
	int new_num;
	struct pollfd *newfds;
retry:
	/* Check if already present */
	for (i = 0; i < pollfd_num; i++) {
		if (pollfds[i].fd == fd)
			return (0);
	}
	/* Check for empty spot already present */
	for (i = 0; i < pollfd_num; i++) {
		if (pollfds[i].fd == -1) {
			pollfds[i].fd = fd;
			return (0);
		}
	}

	/* Allocate space for 32 more fds and initialize to -1 */
	new_num = pollfd_num + 32;
	newfds = realloc(pollfds, new_num * sizeof (struct pollfd));
	if (newfds == NULL) {
		logperror("poll_add: realloc");
		return (-1);
	}
	for (i = pollfd_num; i < new_num; i++) {
		newfds[i].fd = -1;
		newfds[i].events = POLLIN;
	}
	pollfd_num = new_num;
	pollfds = newfds;
	goto retry;
}

/*
 * Remove fd from the set being polled. Returns 0 if ok; -1 if failed.
 */
int
poll_remove(int fd)
{
	int i;

	/* Check if already present */
	for (i = 0; i < pollfd_num; i++) {
		if (pollfds[i].fd == fd) {
			pollfds[i].fd = -1;
			return (0);
		}
	}
	return (-1);
}

/*
 * Extract information about the phyint instance. If the phyint instance still
 * exists in the kernel then set pii_in_use, else clear it. check_if_removed()
 * will use it to detect phyint instances that don't exist any longer and
 * remove them, from our database of phyint instances.
 * Return value:
 *	returns true if the phyint instance exists in the kernel,
 *	returns false otherwise
 */
static boolean_t
pii_process(int af, char *name, struct phyint_instance **pii_p)
{
	int err;
	struct phyint_instance *pii;
	struct phyint_instance *pii_other;

	if (debug & D_PHYINT)
		logdebug("pii_process(%s %s)\n", AF_STR(af), name);

	pii = phyint_inst_lookup(af, name);
	if (pii == NULL) {
		/*
		 * Phyint instance does not exist in our tables,
		 * create new phyint instance
		 */
		pii = phyint_inst_init_from_k(af, name);
	} else {
		/* Phyint exists in our tables */
		err = phyint_inst_update_from_k(pii);

		switch (err) {
		case PI_IOCTL_ERROR:
			/* Some ioctl error. don't change anything */
			pii->pii_in_use = 1;
			break;

		case PI_GROUP_CHANGED:
		case PI_IFINDEX_CHANGED:
			/*
			 * Interface index or group membership has changed.
			 * Delete the old state and recreate based on the new
			 * state (it may no longer be in a group).
			 */
			pii_other = phyint_inst_other(pii);
			if (pii_other != NULL)
				phyint_inst_delete(pii_other);
			phyint_inst_delete(pii);
			pii = phyint_inst_init_from_k(af, name);
			break;

		case PI_DELETED:
			/* Phyint instance has disappeared from kernel */
			pii->pii_in_use = 0;
			break;

		case PI_OK:
			/* Phyint instance exists and is fine */
			pii->pii_in_use = 1;
			break;

		default:
			/* Unknown status */
			logerr("pii_process: Unknown status %d\n", err);
			break;
		}
	}

	*pii_p = pii;
	if (pii != NULL)
		return (pii->pii_in_use ? _B_TRUE : _B_FALSE);
	else
		return (_B_FALSE);
}

/*
 * Scan all interfaces to detect changes as well as new and deleted interfaces
 */
static void
initifs()
{
	int	i, nlifr;
	int	af;
	char	*cp;
	char	*buf;
	int	sockfd;
	uint64_t	flags;
	struct lifnum	lifn;
	struct lifconf	lifc;
	struct lifreq	lifreq;
	struct lifreq	*lifr;
	struct logint	*li;
	struct phyint_instance *pii;
	struct phyint_instance *next_pii;
	struct phyint_group *pg, *next_pg;
	char		pi_name[LIFNAMSIZ + 1];

	if (debug & D_PHYINT)
		logdebug("initifs: Scanning interfaces\n");

	last_initifs_time = getcurrenttime();

	/*
	 * Free the existing local address list; we'll build a new list below.
	 */
	addrlist_free(&localaddrs);

	/*
	 * Mark the interfaces so that we can find phyints and logints
	 * which have disappeared from the kernel. pii_process() and
	 * logint_init_from_k() will set {pii,li}_in_use when they find
	 * the interface in the kernel. Also, clear dupaddr bit on probe
	 * logint. check_addr_unique() will set the dupaddr bit on the
	 * probe logint, if the testaddress is not unique.
	 */
	for (pii = phyint_instances; pii != NULL; pii = pii->pii_next) {
		pii->pii_in_use = 0;
		for (li = pii->pii_logint; li != NULL; li = li->li_next) {
			li->li_in_use = 0;
			if (pii->pii_probe_logint == li)
				li->li_dupaddr = 0;
		}
	}

	/*
	 * As above, mark groups so that we can detect IPMP interfaces which
	 * have been removed from the kernel.  Also, delete the group address
	 * list since we'll iteratively recreate it below.
	 */
	for (pg = phyint_groups; pg != NULL; pg = pg->pg_next) {
		pg->pg_in_use = _B_FALSE;
		addrlist_free(&pg->pg_addrs);
	}

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = LIFC_ALLZONES | LIFC_UNDER_IPMP;
again:
	if (ioctl(ifsock_v4, SIOCGLIFNUM, (char *)&lifn) < 0) {
		logperror("initifs: ioctl (get interface count)");
		return;
	}
	/*
	 * Pad the interface count to detect when additional interfaces have
	 * been configured between SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	lifn.lifn_count += 4;

	if ((buf = calloc(lifn.lifn_count, sizeof (struct lifreq))) == NULL) {
		logperror("initifs: calloc");
		return;
	}

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = LIFC_ALLZONES | LIFC_UNDER_IPMP;
	lifc.lifc_len = lifn.lifn_count * sizeof (struct lifreq);
	lifc.lifc_buf = buf;

	if (ioctl(ifsock_v4, SIOCGLIFCONF, (char *)&lifc) < 0) {
		logperror("initifs: ioctl (get interface configuration)");
		free(buf);
		return;
	}

	/*
	 * If every lifr_req slot is taken, then additional interfaces must
	 * have been plumbed between the SIOCGLIFNUM and the SIOCGLIFCONF.
	 * Recalculate to make sure we didn't miss any interfaces.
	 */
	nlifr = lifc.lifc_len / sizeof (struct lifreq);
	if (nlifr >= lifn.lifn_count) {
		free(buf);
		goto again;
	}

	/*
	 * Walk through the lifreqs returned by SIOGGLIFCONF, and refresh the
	 * global list of addresses, phyint groups, phyints, and logints.
	 */
	for (lifr = lifc.lifc_req, i = 0; i < nlifr; i++, lifr++) {
		af = lifr->lifr_addr.ss_family;
		sockfd = (af == AF_INET) ? ifsock_v4 : ifsock_v6;
		(void) strlcpy(lifreq.lifr_name, lifr->lifr_name, LIFNAMSIZ);

		if (ioctl(sockfd, SIOCGLIFFLAGS, &lifreq) == -1) {
			if (errno != ENXIO)
				logperror("initifs: ioctl (SIOCGLIFFLAGS)");
			continue;
		}
		flags = lifreq.lifr_flags;

		/*
		 * If the address is IFF_UP, add it to the local address list.
		 * (We ignore addresses that aren't IFF_UP since another node
		 * might legitimately have that address IFF_UP.)
		 */
		if (flags & IFF_UP) {
			(void) addrlist_add(&localaddrs, lifr->lifr_name, flags,
			    &lifr->lifr_addr);
		}

		/*
		 * If this address is on an IPMP meta-interface, update our
		 * phyint_group information (either by recording that group
		 * still exists or creating a new group), and track what
		 * group the address is part of.
		 */
		if (flags & IFF_IPMP) {
			if (ioctl(sockfd, SIOCGLIFGROUPNAME, &lifreq) == -1) {
				if (errno != ENXIO)
					logperror("initifs: ioctl "
					    "(SIOCGLIFGROUPNAME)");
				continue;
			}

			pg = phyint_group_lookup(lifreq.lifr_groupname);
			if (pg == NULL) {
				pg = phyint_group_create(lifreq.lifr_groupname);
				if (pg == NULL) {
					logerr("initifs: cannot create group "
					    "%s\n", lifreq.lifr_groupname);
					continue;
				}
				phyint_group_insert(pg);
			}
			pg->pg_in_use = _B_TRUE;

			/*
			 * Add this to the group's list of data addresses.
			 */
			if (!addrlist_add(&pg->pg_addrs, lifr->lifr_name, flags,
			    &lifr->lifr_addr)) {
				logerr("initifs: insufficient memory to track "
				    "data address information for %s\n",
				    lifr->lifr_name);
			}
			continue;
		}

		/*
		 * This isn't an address on an IPMP meta-interface, so it's
		 * either on an underlying interface or not related to any
		 * group.  Update our phyint and logint information (via
		 * pii_process() and logint_init_from_k()) -- but first,
		 * convert the logint name to a phyint name so we can call
		 * pii_process().
		 */
		(void) strlcpy(pi_name, lifr->lifr_name, sizeof (pi_name));
		if ((cp = strchr(pi_name, IF_SEPARATOR)) != NULL)
			*cp = '\0';

		if (pii_process(af, pi_name, &pii)) {
			/* The phyint is fine. So process the logint */
			logint_init_from_k(pii, lifr->lifr_name);
			check_addr_unique(pii, &lifr->lifr_addr);
		}
	}
	free(buf);

	/*
	 * Scan for groups, phyints and logints that have disappeared from the
	 * kernel, and delete them.
	 */
	for (pii = phyint_instances; pii != NULL; pii = next_pii) {
		next_pii = pii->pii_next;
		check_if_removed(pii);
	}

	for (pg = phyint_groups; pg != NULL; pg = next_pg) {
		next_pg = pg->pg_next;
		if (!pg->pg_in_use) {
			phyint_group_delete(pg);
			continue;
		}
		/*
		 * Refresh the group's state.  This is necessary since the
		 * group's state is defined by the set of usable interfaces in
		 * the group, and an interface is considered unusable if all
		 * of its addresses are down.  When an address goes down/up,
		 * the RTM_DELADDR/RTM_NEWADDR brings us through here.
		 */
		phyint_group_refresh_state(pg);
	}

	/*
	 * Select a test address for sending probes on each phyint instance
	 */
	select_test_ifs();

	/*
	 * Handle link up/down notifications.
	 */
	process_link_state_changes();
}

/*
 * Check that a given test address is unique across all of the interfaces in a
 * group.  (e.g., IPv6 link-locals may not be inherently unique, and binding
 * to such an (IFF_NOFAILOVER) address can produce unexpected results.)
 * Any issues will be reported by check_testconfig().
 */
static void
check_addr_unique(struct phyint_instance *ourpii, struct sockaddr_storage *ss)
{
	struct phyint		*pi;
	struct phyint_group	*pg;
	struct in6_addr		addr;
	struct phyint_instance	*pii;
	struct sockaddr_in	*sin;

	if (ss->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)ss;
		IN6_INADDR_TO_V4MAPPED(&sin->sin_addr, &addr);
	} else {
		assert(ss->ss_family == AF_INET6);
		addr = ((struct sockaddr_in6 *)ss)->sin6_addr;
	}

	/*
	 * For anonymous groups, every interface is assumed to be on its own
	 * link, so there is no chance of overlapping addresses.
	 */
	pg = ourpii->pii_phyint->pi_group;
	if (pg == phyint_anongroup)
		return;

	/*
	 * Walk the list of phyint instances in the group and check for test
	 * addresses matching ours.  Of course, we skip ourself.
	 */
	for (pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext) {
		pii = PHYINT_INSTANCE(pi, ss->ss_family);
		if (pii == NULL || pii == ourpii ||
		    pii->pii_probe_logint == NULL)
			continue;

		/*
		 * If this test address is not unique, set the dupaddr bit.
		 */
		if (IN6_ARE_ADDR_EQUAL(&addr, &pii->pii_probe_logint->li_addr))
			pii->pii_probe_logint->li_dupaddr = 1;
	}
}

/*
 * Stop probing an interface.  Called when an interface is offlined.
 * The probe socket is closed on each interface instance, and the
 * interface state set to PI_OFFLINE.
 */
void
stop_probing(struct phyint *pi)
{
	struct phyint_instance *pii;

	pii = pi->pi_v4;
	if (pii != NULL) {
		if (pii->pii_probe_sock != -1)
			close_probe_socket(pii, _B_TRUE);
		pii->pii_probe_logint = NULL;
	}

	pii = pi->pi_v6;
	if (pii != NULL) {
		if (pii->pii_probe_sock != -1)
			close_probe_socket(pii, _B_TRUE);
		pii->pii_probe_logint = NULL;
	}

	phyint_chstate(pi, PI_OFFLINE);
}

enum { BAD_TESTFLAGS, OK_TESTFLAGS, BEST_TESTFLAGS };

/*
 * Rate the provided test flags.  By definition, IFF_NOFAILOVER must be set.
 * IFF_UP must also be set so that the associated address can be used as a
 * source address.  Further, we must be able to exchange packets with local
 * destinations, so IFF_NOXMIT and IFF_NOLOCAL must be clear.  For historical
 * reasons, we have a proclivity for IFF_DEPRECATED IPv4 test addresses.
 */
static int
rate_testflags(uint64_t flags)
{
	if ((flags & (IFF_NOFAILOVER | IFF_UP)) != (IFF_NOFAILOVER | IFF_UP))
		return (BAD_TESTFLAGS);

	if ((flags & (IFF_NOXMIT | IFF_NOLOCAL)) != 0)
		return (BAD_TESTFLAGS);

	if ((flags & (IFF_IPV6 | IFF_DEPRECATED)) == IFF_DEPRECATED)
		return (BEST_TESTFLAGS);

	if ((flags & (IFF_IPV6 | IFF_DEPRECATED)) == IFF_IPV6)
		return (BEST_TESTFLAGS);

	return (OK_TESTFLAGS);
}

/*
 * Attempt to select a test address for each phyint instance.
 * Call phyint_inst_sockinit() to complete the initializations.
 */
static void
select_test_ifs(void)
{
	struct phyint		*pi;
	struct phyint_instance	*pii;
	struct phyint_instance	*next_pii;
	struct logint		*li;
	struct logint  		*probe_logint;
	boolean_t		target_scan_reqd = _B_FALSE;
	int			rating;

	if (debug & D_PHYINT)
		logdebug("select_test_ifs\n");

	/*
	 * For each phyint instance, do the test address selection
	 */
	for (pii = phyint_instances; pii != NULL; pii = next_pii) {
		next_pii = pii->pii_next;
		probe_logint = NULL;

		/*
		 * An interface that is offline should not be probed.
		 * IFF_OFFLINE interfaces should always be PI_OFFLINE
		 * unless some other entity has set the offline flag.
		 */
		if (pii->pii_phyint->pi_flags & IFF_OFFLINE) {
			if (pii->pii_phyint->pi_state != PI_OFFLINE) {
				logerr("shouldn't be probing offline"
				    " interface %s (state is: %u)."
				    " Stopping probes.\n",
				    pii->pii_phyint->pi_name,
				    pii->pii_phyint->pi_state);
				stop_probing(pii->pii_phyint);
			}
			continue;
		} else {
			/*
			 * If something cleared IFF_OFFLINE (e.g., by accident
			 * because the SIOCGLIFFLAGS/SIOCSLIFFLAGS sequence is
			 * inherently racy), the phyint may still be offline.
			 * Just ignore it.
			 */
			if (pii->pii_phyint->pi_state == PI_OFFLINE)
				continue;
		}

		li = pii->pii_probe_logint;
		if (li != NULL) {
			/*
			 * We've already got a test address; only proceed
			 * if it's suboptimal.
			 */
			if (rate_testflags(li->li_flags) == BEST_TESTFLAGS)
				continue;
		}

		/*
		 * Walk the logints of this phyint instance, and select
		 * the best available test address
		 */
		for (li = pii->pii_logint; li != NULL; li = li->li_next) {
			/*
			 * Skip 0.0.0.0 addresses, as those are never
			 * actually usable.
			 */
			if (pii->pii_af == AF_INET &&
			    IN6_IS_ADDR_V4MAPPED_ANY(&li->li_addr))
				continue;

			/*
			 * Skip any IPv6 logints that are not link-local,
			 * since we should always have a link-local address
			 * anyway and in6_data() expects link-local replies.
			 */
			if (pii->pii_af == AF_INET6 &&
			    !IN6_IS_ADDR_LINKLOCAL(&li->li_addr))
				continue;

			/*
			 * Rate the testflags. If we've found an optimal
			 * match, then break out; otherwise, record the most
			 * recent OK one.
			 */
			rating = rate_testflags(li->li_flags);
			if (rating == BAD_TESTFLAGS)
				continue;

			probe_logint = li;
			if (rating == BEST_TESTFLAGS)
				break;
		}

		/*
		 * If the probe logint has changed, ditch the old one.
		 */
		if (pii->pii_probe_logint != NULL &&
		    pii->pii_probe_logint != probe_logint) {
			if (pii->pii_probe_sock != -1)
				close_probe_socket(pii, _B_TRUE);
			pii->pii_probe_logint = NULL;
		}

		if (probe_logint == NULL) {
			/*
			 * We don't have a test address; zero out the probe
			 * stats array since it is no longer relevant.
			 * Optimize by checking if it is already zeroed out.
			 */
			int pr_ndx;

			pr_ndx = PROBE_INDEX_PREV(pii->pii_probe_next);
			if (pii->pii_probes[pr_ndx].pr_status != PR_UNUSED) {
				clear_pii_probe_stats(pii);
				reset_crtt_all(pii->pii_phyint);
			}
			continue;
		} else if (probe_logint == pii->pii_probe_logint) {
			/*
			 * If we didn't find any new test addr, go to the
			 * next phyint.
			 */
			continue;
		}

		/*
		 * The phyint is either being assigned a new testaddr
		 * or is being assigned a testaddr for the 1st time.
		 * Need to initialize the phyint socket
		 */
		pii->pii_probe_logint = probe_logint;
		if (!phyint_inst_sockinit(pii)) {
			if (debug & D_PHYINT) {
				logdebug("select_test_ifs: "
				    "phyint_sockinit failed\n");
			}
			phyint_inst_delete(pii);
			continue;
		}

		/*
		 * This phyint instance is now enabled for probes; this
		 * impacts our state machine in two ways:
		 *
		 * 1. If we're probe *capable* as well (i.e., we have
		 *    probe targets) and the interface is in PI_NOTARGETS,
		 *    then transition to PI_RUNNING.
		 *
		 * 2. If we're not probe capable, and the other phyint
		 *    instance is also not probe capable, and we were in
		 *    PI_RUNNING, then transition to PI_NOTARGETS.
		 *
		 * Also see the state diagram in mpd_probe.c.
		 */
		if (PROBE_CAPABLE(pii)) {
			if (pii->pii_phyint->pi_state == PI_NOTARGETS)
				phyint_chstate(pii->pii_phyint, PI_RUNNING);
		} else if (!PROBE_CAPABLE(phyint_inst_other(pii))) {
			if (pii->pii_phyint->pi_state == PI_RUNNING)
				phyint_chstate(pii->pii_phyint, PI_NOTARGETS);
		}

		/*
		 * If no targets are currently known for this phyint
		 * we need to call init_router_targets. Since
		 * init_router_targets() initializes the list of targets
		 * for all phyints it is done below the loop.
		 */
		if (pii->pii_targets == NULL)
			target_scan_reqd = _B_TRUE;

		/*
		 * Start the probe timer for this instance.
		 */
		if (!pii->pii_basetime_inited && PROBE_ENABLED(pii)) {
			start_timer(pii);
			pii->pii_basetime_inited = 1;
		}
	}

	/*
	 * Scan the interface list for any interfaces that are PI_FAILED or
	 * PI_NOTARGETS but no longer enabled to send probes, and call
	 * phyint_check_for_repair() to see if the link state indicates that
	 * the interface should be repaired.  Also see the state diagram in
	 * mpd_probe.c.
	 */
	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		if ((!PROBE_ENABLED(pi->pi_v4) && !PROBE_ENABLED(pi->pi_v6)) &&
		    (pi->pi_state == PI_FAILED ||
		    pi->pi_state == PI_NOTARGETS)) {
			phyint_check_for_repair(pi);
		}
	}

	check_testconfig();

	/*
	 * Try to populate the target list. init_router_targets populates
	 * the target list from the routing table. If our target list is
	 * still empty, init_host_targets adds host targets based on the
	 * host target list of other phyints in the group.
	 */
	if (target_scan_reqd) {
		init_router_targets();
		init_host_targets();
	}
}

/*
 * Check test address configuration, and log notices/errors if appropriate.
 * Note that this function only logs pre-existing conditions (e.g., that
 * probe-based failure detection is disabled).
 */
static void
check_testconfig(void)
{
	struct phyint	*pi;
	struct logint  	*li;
	char		abuf[INET6_ADDRSTRLEN];
	int		pri;

	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		if (pi->pi_flags & IFF_OFFLINE)
			continue;

		if (PROBE_ENABLED(pi->pi_v4) || PROBE_ENABLED(pi->pi_v6)) {
			if (pi->pi_taddrmsg_printed ||
			    pi->pi_duptaddrmsg_printed) {
				if (pi->pi_duptaddrmsg_printed)
					pri = LOG_ERR;
				else
					pri = LOG_INFO;
				logmsg(pri, "Test address now configured on "
				    "interface %s; enabling probe-based "
				    "failure detection on it\n", pi->pi_name);
				pi->pi_taddrmsg_printed = 0;
				pi->pi_duptaddrmsg_printed = 0;
			}
			continue;
		}

		li = NULL;
		if (pi->pi_v4 != NULL && pi->pi_v4->pii_probe_logint != NULL &&
		    pi->pi_v4->pii_probe_logint->li_dupaddr)
			li = pi->pi_v4->pii_probe_logint;

		if (pi->pi_v6 != NULL && pi->pi_v6->pii_probe_logint != NULL &&
		    pi->pi_v6->pii_probe_logint->li_dupaddr)
			li = pi->pi_v6->pii_probe_logint;

		if (li != NULL && li->li_dupaddr) {
			if (pi->pi_duptaddrmsg_printed)
				continue;
			logerr("Test address %s is not unique in group; "
			    "disabling probe-based failure detection on %s\n",
			    pr_addr(li->li_phyint_inst->pii_af,
			    li->li_addr, abuf, sizeof (abuf)), pi->pi_name);
			pi->pi_duptaddrmsg_printed = 1;
			continue;
		}

		if (getcurrentsec() < pi->pi_taddrthresh)
			continue;

		if (!pi->pi_taddrmsg_printed) {
			logtrace("No test address configured on interface %s; "
			    "disabling probe-based failure detection on it\n",
			    pi->pi_name);
			pi->pi_taddrmsg_printed = 1;
		}
	}
}

/*
 * Check phyint group configuration, to detect any inconsistencies,
 * and log an error message. This is called from runtimeouts every
 * 20 secs. But the error message is displayed once. If the
 * consistency is resolved by the admin, a recovery message is displayed
 * once.
 */
static void
check_config(void)
{
	struct phyint_group *pg;
	struct phyint *pi;
	boolean_t v4_in_group;
	boolean_t v6_in_group;

	/*
	 * All phyints of a group must be homogeneous to ensure that they can
	 * take over for one another.  If any phyint in a group has IPv4
	 * plumbed, check that all phyints have IPv4 plumbed.  Do a similar
	 * check for IPv6.
	 */
	for (pg = phyint_groups; pg != NULL; pg = pg->pg_next) {
		if (pg == phyint_anongroup)
			continue;

		v4_in_group = _B_FALSE;
		v6_in_group = _B_FALSE;
		/*
		 * 1st pass. Determine if at least 1 phyint in the group
		 * has IPv4 plumbed and if so set v4_in_group to true.
		 * Repeat similarly for IPv6.
		 */
		for (pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext) {
			if (pi->pi_v4 != NULL)
				v4_in_group = _B_TRUE;
			if (pi->pi_v6 != NULL)
				v6_in_group = _B_TRUE;
		}

		/*
		 * 2nd pass. If v4_in_group is true, check that phyint
		 * has IPv4 plumbed. Repeat similarly for IPv6. Print
		 * out a message the 1st time only.
		 */
		for (pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext) {
			if (pi->pi_flags & IFF_OFFLINE)
				continue;

			if (v4_in_group == _B_TRUE && pi->pi_v4 == NULL) {
				if (!pi->pi_cfgmsg_printed) {
					logerr("IP interface %s in group %s is"
					    " not plumbed for IPv4, affecting"
					    " IPv4 connectivity\n",
					    pi->pi_name,
					    pi->pi_group->pg_name);
					pi->pi_cfgmsg_printed = 1;
				}
			} else if (v6_in_group == _B_TRUE &&
			    pi->pi_v6 == NULL) {
				if (!pi->pi_cfgmsg_printed) {
					logerr("IP interface %s in group %s is"
					    " not plumbed for IPv6, affecting"
					    " IPv6 connectivity\n",
					    pi->pi_name,
					    pi->pi_group->pg_name);
					pi->pi_cfgmsg_printed = 1;
				}
			} else {
				/*
				 * The phyint matches the group configuration,
				 * if we have reached this point. If it was
				 * improperly configured earlier, log an
				 * error recovery message
				 */
				if (pi->pi_cfgmsg_printed) {
					logerr("IP interface %s is now"
					    " consistent with group %s "
					    " and connectivity is restored\n",
					    pi->pi_name, pi->pi_group->pg_name);
					pi->pi_cfgmsg_printed = 0;
				}
			}

		}
	}
}

/*
 * Timer mechanism using relative time (in milliseconds) from the
 * previous timer event. Timers exceeding TIMER_INFINITY milliseconds
 * will fire after TIMER_INFINITY milliseconds.
 * Unsigned arithmetic note: We assume a 32-bit circular sequence space for
 * time values. Hence 2 consecutive timer events cannot be spaced farther
 * than 0x7fffffff. We call this TIMER_INFINITY, and it is the maximum value
 * that can be passed for the delay parameter of timer_schedule()
 */
static uint_t timer_next;	/* Currently scheduled timeout */
static boolean_t timer_active = _B_FALSE; /* SIGALRM has not yet occurred */

static void
timer_init(void)
{
	timer_next = getcurrenttime() + TIMER_INFINITY;
	/*
	 * The call to run_timeouts() will get the timer started
	 * Since there are no phyints at this point, the timer will
	 * be set for IF_SCAN_INTERVAL ms.
	 */
	run_timeouts();
}

/*
 * Make sure the next SIGALRM occurs delay milliseconds from the current
 * time if not earlier. We are interested only in time differences.
 */
void
timer_schedule(uint_t delay)
{
	uint_t now;
	struct itimerval itimerval;

	if (debug & D_TIMER)
		logdebug("timer_schedule(%u)\n", delay);

	assert(delay <= TIMER_INFINITY);

	now = getcurrenttime();
	if (delay == 0) {
		/* Minimum allowed delay */
		delay = 1;
	}
	/* Will this timer occur before the currently scheduled SIGALRM? */
	if (timer_active && TIME_GE(now + delay, timer_next)) {
		if (debug & D_TIMER) {
			logdebug("timer_schedule(%u) - no action: "
			    "now %u next %u\n", delay, now, timer_next);
		}
		return;
	}
	timer_next = now + delay;

	itimerval.it_value.tv_sec = delay / 1000;
	itimerval.it_value.tv_usec = (delay % 1000) * 1000;
	itimerval.it_interval.tv_sec = 0;
	itimerval.it_interval.tv_usec = 0;
	if (debug & D_TIMER) {
		logdebug("timer_schedule(%u): sec %ld usec %ld\n",
		    delay, itimerval.it_value.tv_sec,
		    itimerval.it_value.tv_usec);
	}
	timer_active = _B_TRUE;
	if (setitimer(ITIMER_REAL, &itimerval, NULL) < 0) {
		logperror("timer_schedule: setitimer");
		exit(2);
	}
}

static void
timer_cancel(void)
{
	struct itimerval itimerval;

	if (debug & D_TIMER)
		logdebug("timer_cancel()\n");

	bzero(&itimerval, sizeof (itimerval));
	if (setitimer(ITIMER_REAL, &itimerval, NULL) < 0)
		logperror("timer_cancel: setitimer");
}

/*
 * Timer has fired. Determine when the next timer event will occur by asking
 * all the timer routines. Should not be called from a timer routine.
 */
static void
run_timeouts(void)
{
	uint_t next;
	uint_t next_event_time;
	struct phyint_instance *pii;
	struct phyint_instance *next_pii;
	static boolean_t timeout_running;

	/* assert that recursive timeouts don't happen. */
	assert(!timeout_running);

	timeout_running = _B_TRUE;

	if (debug & D_TIMER)
		logdebug("run_timeouts()\n");

	if ((getcurrenttime() - last_initifs_time) > IF_SCAN_INTERVAL) {
		initifs();
		check_config();
	}

	next = TIMER_INFINITY;

	for (pii = phyint_instances; pii != NULL; pii = next_pii) {
		next_pii = pii->pii_next;
		next_event_time = phyint_inst_timer(pii);
		if (next_event_time != TIMER_INFINITY && next_event_time < next)
			next = next_event_time;

		if (debug & D_TIMER) {
			logdebug("run_timeouts(%s %s): next scheduled for"
			    " this phyint inst %u, next scheduled global"
			    " %u ms\n",
			    AF_STR(pii->pii_af), pii->pii_phyint->pi_name,
			    next_event_time, next);
		}
	}

	/*
	 * Make sure initifs() is called at least once every
	 * IF_SCAN_INTERVAL, to make sure that we are in sync
	 * with the kernel, in case we have missed any routing
	 * socket messages.
	 */
	if (next > IF_SCAN_INTERVAL)
		next = IF_SCAN_INTERVAL;

	if (debug & D_TIMER)
		logdebug("run_timeouts: %u ms\n", next);

	timer_schedule(next);
	timeout_running = _B_FALSE;
}

static int eventpipe_read = -1;	/* Used for synchronous signal delivery */
static int eventpipe_write = -1;
boolean_t cleanup_started = _B_FALSE;	/* true if we're going away */

/*
 * Ensure that signals are processed synchronously with the rest of
 * the code by just writing a one character signal number on the pipe.
 * The poll loop will pick this up and process the signal event.
 */
static void
sig_handler(int signo)
{
	uchar_t buf = (uchar_t)signo;

	/*
	 * Don't write to pipe if cleanup has already begun. cleanup()
	 * might have closed the pipe already
	 */
	if (cleanup_started)
		return;

	if (eventpipe_write == -1) {
		logerr("sig_handler: no pipe found\n");
		return;
	}
	if (write(eventpipe_write, &buf, sizeof (buf)) < 0)
		logperror("sig_handler: write");
}

extern struct probes_missed probes_missed;

/*
 * Pick up a signal "byte" from the pipe and process it.
 */
static void
in_signal(int fd)
{
	uchar_t buf;
	uint64_t  sent, acked, lost, unacked, unknown;
	struct phyint_instance *pii;
	int pr_ndx;

	switch (read(fd, &buf, sizeof (buf))) {
	case -1:
		logperror("in_signal: read");
		exit(1);
		/* NOTREACHED */
	case 1:
		break;
	case 0:
		logerr("in_signal: read end of file\n");
		exit(1);
		/* NOTREACHED */
	default:
		logerr("in_signal: read > 1\n");
		exit(1);
	}

	if (debug & D_TIMER)
		logdebug("in_signal() got %d\n", buf);

	switch (buf) {
	case SIGALRM:
		if (debug & D_TIMER) {
			uint_t now = getcurrenttime();

			logdebug("in_signal(SIGALRM) delta %u\n",
			    now - timer_next);
		}
		timer_active = _B_FALSE;
		run_timeouts();
		break;
	case SIGUSR1:
		logdebug("Printing configuration:\n");
		/* Print out the internal tables */
		phyint_inst_print_all();

		/*
		 * Print out the accumulated statistics about missed
		 * probes (happens due to scheduling delay).
		 */
		logerr("Missed sending total of %d probes spread over"
		    " %d occurrences\n", probes_missed.pm_nprobes,
		    probes_missed.pm_ntimes);

		/*
		 * Print out the accumulated statistics about probes
		 * that were sent.
		 */
		for (pii = phyint_instances; pii != NULL;
		    pii = pii->pii_next) {
			unacked = 0;
			acked = pii->pii_cum_stats.acked;
			lost = pii->pii_cum_stats.lost;
			sent = pii->pii_cum_stats.sent;
			unknown = pii->pii_cum_stats.unknown;
			for (pr_ndx = 0; pr_ndx < PROBE_STATS_COUNT; pr_ndx++) {
				switch (pii->pii_probes[pr_ndx].pr_status) {
				case PR_ACKED:
					acked++;
					break;
				case PR_LOST:
					lost++;
					break;
				case PR_UNACKED:
					unacked++;
					break;
				}
			}
			logerr("\nProbe stats on (%s %s)\n"
			    "Number of probes sent %lld\n"
			    "Number of probe acks received %lld\n"
			    "Number of probes/acks lost %lld\n"
			    "Number of valid unacknowledged probes %lld\n"
			    "Number of ambiguous probe acks received %lld\n",
			    AF_STR(pii->pii_af), pii->pii_name,
			    sent, acked, lost, unacked, unknown);
		}
		break;
	case SIGHUP:
		logerr("SIGHUP: restart and reread config file\n");
		/*
		 * Cancel the interval timer.  Needed since setitimer() uses
		 * alarm() and the time left is inherited across exec(), and
		 * thus the SIGALRM may be delivered before a handler has been
		 * setup, causing in.mpathd to erroneously exit.
		 */
		timer_cancel();
		cleanup();
		(void) execv(argv0[0], argv0);
		_exit(0177);
		/* NOTREACHED */
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		cleanup();
		exit(0);
		/* NOTREACHED */
	default:
		logerr("in_signal: unknown signal: %d\n", buf);
	}
}

static void
cleanup(void)
{
	struct phyint_instance *pii;
	struct phyint_instance *next_pii;

	/*
	 * Make sure that we don't write to eventpipe in
	 * sig_handler() if any signal notably SIGALRM,
	 * occurs after we close the eventpipe descriptor below
	 */
	cleanup_started = _B_TRUE;

	for (pii = phyint_instances; pii != NULL; pii = next_pii) {
		next_pii = pii->pii_next;
		phyint_inst_delete(pii);
	}

	(void) close(ifsock_v4);
	(void) close(ifsock_v6);
	(void) close(rtsock_v4);
	(void) close(rtsock_v6);
	(void) close(lsock_v4);
	(void) close(lsock_v6);
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) close(mibfd);
	(void) close(eventpipe_read);
	(void) close(eventpipe_write);
}

/*
 * Create pipe for signal delivery and set up signal handlers.
 */
static void
setup_eventpipe(void)
{
	int fds[2];
	struct sigaction act;

	if ((pipe(fds)) < 0) {
		logperror("setup_eventpipe: pipe");
		exit(1);
	}
	eventpipe_read = fds[0];
	eventpipe_write = fds[1];
	if (poll_add(eventpipe_read) == -1) {
		exit(1);
	}

	act.sa_handler = sig_handler;
	act.sa_flags = SA_RESTART;
	(void) sigaction(SIGALRM, &act, NULL);

	(void) sigset(SIGHUP, sig_handler);
	(void) sigset(SIGUSR1, sig_handler);
	(void) sigset(SIGTERM, sig_handler);
	(void) sigset(SIGINT, sig_handler);
	(void) sigset(SIGQUIT, sig_handler);
}

/*
 * Create a routing socket for receiving RTM_IFINFO messages.
 */
static int
setup_rtsock(int af)
{
	int	s;
	int	flags;
	int	aware = RTAW_UNDER_IPMP;

	s = socket(PF_ROUTE, SOCK_RAW, af);
	if (s == -1) {
		logperror("setup_rtsock: socket PF_ROUTE");
		exit(1);
	}

	if (setsockopt(s, SOL_ROUTE, RT_AWARE, &aware, sizeof (aware)) == -1) {
		logperror("setup_rtsock: setsockopt RT_AWARE");
		(void) close(s);
		exit(1);
	}

	if ((flags = fcntl(s, F_GETFL, 0)) < 0) {
		logperror("setup_rtsock: fcntl F_GETFL");
		(void) close(s);
		exit(1);
	}
	if ((fcntl(s, F_SETFL, flags | O_NONBLOCK)) < 0) {
		logperror("setup_rtsock: fcntl F_SETFL");
		(void) close(s);
		exit(1);
	}
	if (poll_add(s) == -1) {
		(void) close(s);
		exit(1);
	}
	return (s);
}

/*
 * Process an RTM_IFINFO message received on a routing socket.
 * The return value indicates whether a full interface scan is required.
 * Link up/down notifications are reflected in the IFF_RUNNING flag.
 * If just the state of the IFF_RUNNING interface flag has changed, a
 * a full interface scan isn't required.
 */
static boolean_t
process_rtm_ifinfo(if_msghdr_t *ifm, int type)
{
	struct sockaddr_dl *sdl;
	struct phyint *pi;
	uint64_t old_flags;
	struct phyint_instance *pii;

	assert(ifm->ifm_type == RTM_IFINFO && ifm->ifm_addrs == RTA_IFP);

	/*
	 * Although the sockaddr_dl structure is directly after the
	 * if_msghdr_t structure. At the time of writing, the size of the
	 * if_msghdr_t structure is different on 32 and 64 bit kernels, due
	 * to the presence of a timeval structure, which contains longs,
	 * in the if_data structure.  Anyway, we know where the message ends,
	 * so we work backwards to get the start of the sockaddr_dl structure.
	 */
	/*LINTED*/
	sdl = (struct sockaddr_dl *)((char *)ifm + ifm->ifm_msglen -
	    sizeof (struct sockaddr_dl));

	assert(sdl->sdl_family == AF_LINK);

	/*
	 * The interface name is in sdl_data.
	 * RTM_IFINFO messages are only generated for logical interface
	 * zero, so there is no colon and logical interface number to
	 * strip from the name.	 The name is not null terminated, but
	 * there should be enough space in sdl_data to add the null.
	 */
	if (sdl->sdl_nlen >= sizeof (sdl->sdl_data)) {
		if (debug & D_LINKNOTE)
			logdebug("process_rtm_ifinfo: phyint name too long\n");
		return (_B_TRUE);
	}
	sdl->sdl_data[sdl->sdl_nlen] = 0;

	pi = phyint_lookup(sdl->sdl_data);
	if (pi == NULL) {
		if (debug & D_LINKNOTE)
			logdebug("process_rtm_ifinfo: phyint lookup failed"
			    " for %s\n", sdl->sdl_data);
		return (_B_TRUE);
	}

	/*
	 * We want to try and avoid doing a full interface scan for
	 * link state notifications from the datalink layer, as indicated
	 * by the state of the IFF_RUNNING flag.  If just the
	 * IFF_RUNNING flag has changed state, the link state changes
	 * are processed without a full scan.
	 * If there is both an IPv4 and IPv6 instance associated with
	 * the physical interface, we will get an RTM_IFINFO message
	 * for each instance.  If we just maintained a single copy of
	 * the physical interface flags, it would appear that no flags
	 * had changed when the second message is processed, leading us
	 * to believe that the message wasn't generated by a flags change,
	 * and that a full interface scan is required.
	 * To get around this problem, two additional copies of the flags
	 * are kept, one copy for each instance.  These are only used in
	 * this routine.  At any one time, all three copies of the flags
	 * should be identical except for the IFF_RUNNING flag.	 The
	 * copy of the flags in the "phyint" structure is always up to
	 * date.
	 */
	pii = (type == AF_INET) ? pi->pi_v4 : pi->pi_v6;
	if (pii == NULL) {
		if (debug & D_LINKNOTE)
			logdebug("process_rtm_ifinfo: no instance of address "
			    "family %s for %s\n", AF_STR(type), pi->pi_name);
		return (_B_TRUE);
	}

	old_flags = pii->pii_flags;
	pii->pii_flags = PHYINT_FLAGS(ifm->ifm_flags);
	pi->pi_flags = pii->pii_flags;

	if (debug & D_LINKNOTE) {
		logdebug("process_rtm_ifinfo: %s address family: %s, "
		    "old flags: %llx, new flags: %llx\n", pi->pi_name,
		    AF_STR(type), old_flags, pi->pi_flags);
	}

	/*
	 * If IFF_STANDBY has changed, indicate that the interface has changed
	 * types and refresh IFF_INACTIVE if need be.
	 */
	if ((old_flags ^ pii->pii_flags) & IFF_STANDBY) {
		phyint_changed(pi);
		if (pii->pii_flags & IFF_STANDBY)
			phyint_standby_refresh_inactive(pi);
	}

	/* Has just the IFF_RUNNING flag changed state ? */
	if ((old_flags ^ pii->pii_flags) != IFF_RUNNING) {
		struct phyint_instance *pii_other;
		/*
		 * It wasn't just a link state change.	Update
		 * the other instance's copy of the flags.
		 */
		pii_other = phyint_inst_other(pii);
		if (pii_other != NULL)
			pii_other->pii_flags = pii->pii_flags;
		return (_B_TRUE);
	}

	return (_B_FALSE);
}

/*
 * Retrieve as many routing socket messages as possible, and try to
 * empty the routing sockets. Initiate full scan of targets or interfaces
 * as needed.
 * We listen on separate IPv4 an IPv6 sockets so that we can accurately
 * detect changes in certain flags (see "process_rtm_ifinfo()" above).
 */
static void
process_rtsock(int rtsock_v4, int rtsock_v6)
{
	int	nbytes;
	int64_t msg[2048 / 8];
	struct rt_msghdr *rtm;
	boolean_t need_if_scan = _B_FALSE;
	boolean_t need_rt_scan = _B_FALSE;
	boolean_t rtm_ifinfo_seen = _B_FALSE;
	int type;

	/* Read as many messages as possible and try to empty the sockets */
	for (type = AF_INET; ; type = AF_INET6) {
		for (;;) {
			nbytes = read((type == AF_INET) ? rtsock_v4 :
			    rtsock_v6, msg, sizeof (msg));
			if (nbytes <= 0) {
				/* No more messages */
				break;
			}
			rtm = (struct rt_msghdr *)msg;
			if (rtm->rtm_version != RTM_VERSION) {
				logerr("process_rtsock: version %d "
				    "not understood\n", rtm->rtm_version);
				break;
			}

			if (debug & D_PHYINT) {
				logdebug("process_rtsock: message %d\n",
				    rtm->rtm_type);
			}

			switch (rtm->rtm_type) {
			case RTM_NEWADDR:
			case RTM_DELADDR:
				/*
				 * Some logical interface has changed,
				 * have to scan everything to determine
				 * what actually changed.
				 */
				need_if_scan = _B_TRUE;
				break;

			case RTM_IFINFO:
				rtm_ifinfo_seen = _B_TRUE;
				need_if_scan |= process_rtm_ifinfo(
				    (if_msghdr_t *)rtm, type);
				break;

			case RTM_ADD:
			case RTM_DELETE:
			case RTM_CHANGE:
			case RTM_OLDADD:
			case RTM_OLDDEL:
				need_rt_scan = _B_TRUE;
				break;

			default:
				/* Not interesting */
				break;
			}
		}
		if (type == AF_INET6)
			break;
	}

	if (need_if_scan) {
		if (debug & D_LINKNOTE && rtm_ifinfo_seen)
			logdebug("process_rtsock: synchronizing with kernel\n");
		initifs();
	} else if (rtm_ifinfo_seen) {
		if (debug & D_LINKNOTE)
			logdebug("process_rtsock: "
			    "link up/down notification(s) seen\n");
		process_link_state_changes();
	}

	if (need_rt_scan)
		init_router_targets();
}

/*
 * Look if the phyint instance or one of its logints have been removed from
 * the kernel and take appropriate action.
 * Uses {pii,li}_in_use.
 */
static void
check_if_removed(struct phyint_instance *pii)
{
	struct logint *li;
	struct logint *next_li;

	/* Detect phyints that have been removed from the kernel. */
	if (!pii->pii_in_use) {
		logtrace("%s %s has been removed from kernel\n",
		    AF_STR(pii->pii_af), pii->pii_phyint->pi_name);
		phyint_inst_delete(pii);
	} else {
		/* Detect logints that have been removed. */
		for (li = pii->pii_logint; li != NULL; li = next_li) {
			next_li = li->li_next;
			if (!li->li_in_use) {
				logint_delete(li);
			}
		}
	}
}

/*
 * Parse the supplied mib2 information to extract the routing information
 * table. Process the routing table to get the list of known onlink routers
 * and update our database. These onlink routers will serve as probe
 * targets.
 */
static void
update_router_list(mib_item_t *item)
{
	for (; item != NULL; item = item->mi_next) {
		if (item->mi_opthdr.name == 0)
			continue;
		if (item->mi_opthdr.level == MIB2_IP &&
		    item->mi_opthdr.name == MIB2_IP_ROUTE) {
			ire_process_v4((mib2_ipRouteEntry_t *)item->mi_valp,
			    item->mi_opthdr.len);
		} else if (item->mi_opthdr.level == MIB2_IP6 &&
		    item->mi_opthdr.name == MIB2_IP6_ROUTE) {
			ire_process_v6((mib2_ipv6RouteEntry_t *)item->mi_valp,
			    item->mi_opthdr.len);
		}
	}
}


/*
 * Convert octet `octp' to a phyint name and store in `ifname'
 */
static void
oct2ifname(const Octet_t *octp, char *ifname, size_t ifsize)
{
	char *cp;
	size_t len = MIN(octp->o_length, ifsize - 1);

	(void) strncpy(ifname, octp->o_bytes, len);
	ifname[len] = '\0';

	if ((cp = strchr(ifname, IF_SEPARATOR)) != NULL)
		*cp = '\0';
}

/*
 * Examine the IPv4 routing table `buf' for possible targets.  For each
 * possible target, if it's on the same subnet an interface route, pass
 * it to router_add_common() for further consideration.
 */
static void
ire_process_v4(mib2_ipRouteEntry_t *buf, size_t len)
{
	char ifname[LIFNAMSIZ];
	mib2_ipRouteEntry_t	*rp, *rp1, *endp;
	struct in_addr		nexthop_v4;
	struct in6_addr		nexthop;

	if (debug & D_TARGET)
		logdebug("ire_process_v4(len %d)\n", len);

	if (len == 0)
		return;

	assert((len % ipRouteEntrySize) == 0);
	endp = buf + (len / ipRouteEntrySize);

	/*
	 * Scan the routing table entries for any IRE_OFFSUBNET entries, and
	 * cross-reference them with the interface routes to determine if
	 * they're possible probe targets.
	 */
	for (rp = buf; rp < endp; rp++) {
		if (!(rp->ipRouteInfo.re_ire_type & IRE_OFFSUBNET))
			continue;

		/* Get the nexthop address. */
		nexthop_v4.s_addr = rp->ipRouteNextHop;

		/*
		 * Rescan the routing table looking for interface routes that
		 * are on the same subnet, and try to add them.  If they're
		 * not relevant (e.g., the interface route isn't part of an
		 * IPMP group, router_add_common() will discard).
		 */
		for (rp1 = buf; rp1 < endp; rp1++) {
			if (!(rp1->ipRouteInfo.re_ire_type & IRE_INTERFACE) ||
			    rp1->ipRouteIfIndex.o_length == 0)
				continue;

			if ((rp1->ipRouteDest & rp1->ipRouteMask) !=
			    (nexthop_v4.s_addr & rp1->ipRouteMask))
				continue;

			oct2ifname(&rp1->ipRouteIfIndex, ifname, LIFNAMSIZ);
			IN6_INADDR_TO_V4MAPPED(&nexthop_v4, &nexthop);
			router_add_common(AF_INET, ifname, nexthop);
		}
	}
}

void
router_add_common(int af, char *ifname, struct in6_addr nexthop)
{
	struct phyint_instance *pii;
	struct phyint *pi;

	if (debug & D_TARGET)
		logdebug("router_add_common(%s %s)\n", AF_STR(af), ifname);

	/*
	 * Retrieve the phyint instance; bail if it's not known to us yet.
	 */
	pii = phyint_inst_lookup(af, ifname);
	if (pii == NULL)
		return;

	/*
	 * Don't use our own addresses as targets.
	 */
	if (own_address(nexthop))
		return;

	/*
	 * If the phyint is part a named group, then add the address to all
	 * members of the group; note that this is suboptimal in the IPv4 case
	 * as it has already been added to all matching interfaces in
	 * ire_process_v4(). Otherwise, add the address only to the phyint
	 * itself, since other phyints in the anongroup may not be on the same
	 * subnet.
	 */
	pi = pii->pii_phyint;
	if (pi->pi_group == phyint_anongroup) {
		target_add(pii, nexthop, _B_TRUE);
	} else {
		pi = pi->pi_group->pg_phyint;
		for (; pi != NULL; pi = pi->pi_pgnext)
			target_add(PHYINT_INSTANCE(pi, af), nexthop, _B_TRUE);
	}
}

/*
 * Examine the IPv6 routing table `buf' for possible link-local targets, and
 * pass any contenders to router_add_common() for further consideration.
 */
static void
ire_process_v6(mib2_ipv6RouteEntry_t *buf, size_t len)
{
	struct lifreq lifr;
	char ifname[LIFNAMSIZ];
	char grname[LIFGRNAMSIZ];
	mib2_ipv6RouteEntry_t *rp, *rp1, *endp;
	struct in6_addr nexthop_v6;

	if (debug & D_TARGET)
		logdebug("ire_process_v6(len %d)\n", len);

	if (len == 0)
		return;

	assert((len % ipv6RouteEntrySize) == 0);
	endp = buf + (len / ipv6RouteEntrySize);

	/*
	 * Scan the routing table entries for any IRE_OFFSUBNET entries, and
	 * cross-reference them with the interface routes to determine if
	 * they're possible probe targets.
	 */
	for (rp = buf; rp < endp; rp++) {
		if (!(rp->ipv6RouteInfo.re_ire_type & IRE_OFFSUBNET) ||
		    !IN6_IS_ADDR_LINKLOCAL(&rp->ipv6RouteNextHop))
			continue;

		/* Get the nexthop address. */
		nexthop_v6 = rp->ipv6RouteNextHop;

		/*
		 * The interface name should always exist for link-locals;
		 * we use it to map this entry to an IPMP group name.
		 */
		if (rp->ipv6RouteIfIndex.o_length == 0)
			continue;

		oct2ifname(&rp->ipv6RouteIfIndex, lifr.lifr_name, LIFNAMSIZ);
		if (ioctl(ifsock_v6, SIOCGLIFGROUPNAME, &lifr) == -1 ||
		    strlcpy(grname, lifr.lifr_groupname, LIFGRNAMSIZ) == 0) {
			continue;
		}

		/*
		 * Rescan the list of routes for interface routes, and add the
		 * above target to any interfaces in the same IPMP group.
		 */
		for (rp1 = buf; rp1 < endp; rp1++) {
			if (!(rp1->ipv6RouteInfo.re_ire_type & IRE_INTERFACE) ||
			    rp1->ipv6RouteIfIndex.o_length == 0) {
				continue;
			}
			oct2ifname(&rp1->ipv6RouteIfIndex, ifname, LIFNAMSIZ);
			(void) strlcpy(lifr.lifr_name, ifname, LIFNAMSIZ);

			if (ioctl(ifsock_v6, SIOCGLIFGROUPNAME, &lifr) != -1 &&
			    strcmp(lifr.lifr_groupname, grname) == 0) {
				router_add_common(AF_INET6, ifname, nexthop_v6);
			}
		}
	}
}

/*
 * Build a list of target routers, by scanning the routing tables.
 * It is assumed that interface routes exist, to reach the routers.
 */
static void
init_router_targets(void)
{
	struct	target *tg;
	struct	target *next_tg;
	struct	phyint_instance *pii;
	struct	phyint *pi;

	if (force_mcast)
		return;

	for (pii = phyint_instances; pii != NULL; pii = pii->pii_next) {
		pi = pii->pii_phyint;
		/*
		 * Set tg_in_use to false only for router targets.
		 */
		if (!pii->pii_targets_are_routers)
			continue;

		for (tg = pii->pii_targets; tg != NULL; tg = tg->tg_next)
			tg->tg_in_use = 0;
	}

	if (mibwalk(update_router_list) == -1)
		exit(1);

	for (pii = phyint_instances; pii != NULL; pii = pii->pii_next) {
		pi = pii->pii_phyint;
		if (!pii->pii_targets_are_routers)
			continue;

		for (tg = pii->pii_targets; tg != NULL; tg = next_tg) {
			next_tg = tg->tg_next;
			/*
			 * If the group has failed, it's likely the route was
			 * removed by an application affected by that failure.
			 * In that case, we keep the target so that we can
			 * reliably repair, at which point we'll refresh the
			 * target list again.
			 */
			if (!tg->tg_in_use && !GROUP_FAILED(pi->pi_group))
				target_delete(tg);
		}
	}
}

/*
 * Attempt to assign host targets to any interfaces that do not currently
 * have probe targets by sharing targets with other interfaces in the group.
 */
static void
init_host_targets(void)
{
	struct phyint_instance *pii;
	struct phyint_group *pg;

	for (pii = phyint_instances; pii != NULL; pii = pii->pii_next) {
		pg = pii->pii_phyint->pi_group;
		if (pg != phyint_anongroup && pii->pii_targets == NULL)
			dup_host_targets(pii);
	}
}

/*
 * Duplicate host targets from other phyints of the group to
 * the phyint instance 'desired_pii'.
 */
static void
dup_host_targets(struct phyint_instance	 *desired_pii)
{
	int af;
	struct phyint *pi;
	struct phyint_instance *pii;
	struct target *tg;

	assert(desired_pii->pii_phyint->pi_group != phyint_anongroup);

	af = desired_pii->pii_af;

	/*
	 * For every phyint in the same group as desired_pii, check if
	 * it has any host targets. If so add them to desired_pii.
	 */
	for (pi = desired_pii->pii_phyint; pi != NULL; pi = pi->pi_pgnext) {
		pii = PHYINT_INSTANCE(pi, af);
		/*
		 * We know that we don't have targets on this phyint instance
		 * since we have been called. But we still check for
		 * pii_targets_are_routers because another phyint instance
		 * could have router targets, since IFF_NOFAILOVER addresses
		 * on different phyint instances may belong to different
		 * subnets.
		 */
		if ((pii == NULL) || (pii == desired_pii) ||
		    pii->pii_targets_are_routers)
			continue;
		for (tg = pii->pii_targets; tg != NULL; tg = tg->tg_next) {
			target_create(desired_pii, tg->tg_address, _B_FALSE);
		}
	}
}

static void
usage(char *cmd)
{
	(void) fprintf(stderr, "usage: %s\n", cmd);
}


#define	MPATHD_DEFAULT_FILE	"/etc/default/mpathd"

/* Get an option from the /etc/default/mpathd file */
static char *
getdefault(char *name)
{
	char namebuf[BUFSIZ];
	char *value = NULL;

	if (defopen(MPATHD_DEFAULT_FILE) == 0) {
		char	*cp;
		int	flags;

		/*
		 * ignore case
		 */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		/* Add "=" to the name */
		(void) strncpy(namebuf, name, sizeof (namebuf) - 2);
		(void) strncat(namebuf, "=", 2);

		if ((cp = defread(namebuf)) != NULL)
			value = strdup(cp);

		/* close */
		(void) defopen((char *)NULL);
	}
	return (value);
}


/*
 * Command line options below
 */
boolean_t	failback_enabled = _B_TRUE;	/* failback enabled/disabled */
boolean_t	track_all_phyints = _B_FALSE;	/* track all IP interfaces */
static boolean_t adopt = _B_FALSE;
static boolean_t foreground = _B_FALSE;

int
main(int argc, char *argv[])
{
	int i;
	int c;
	struct phyint *pi;
	struct phyint_instance *pii;
	char *value;

	argv0 = argv;		/* Saved for re-exec on SIGHUP */
	srandom(gethostid());	/* Initialize the random number generator */

	/*
	 * NOTE: The messages output by in.mpathd are not suitable for
	 * translation, so we do not call textdomain().
	 */
	(void) setlocale(LC_ALL, "");

	/*
	 * Get the user specified value of 'failure detection time'
	 * from /etc/default/mpathd
	 */
	value = getdefault("FAILURE_DETECTION_TIME");
	if (value != NULL) {
		user_failure_detection_time =
		    (int)strtol((char *)value, NULL, 0);

		if (user_failure_detection_time <= 0) {
			user_failure_detection_time = FAILURE_DETECTION_TIME;
			logerr("Invalid failure detection time %s, assuming "
			    "default of %d ms\n", value,
			    user_failure_detection_time);

		} else if (user_failure_detection_time <
		    MIN_FAILURE_DETECTION_TIME) {
			user_failure_detection_time =
			    MIN_FAILURE_DETECTION_TIME;
			logerr("Too small failure detection time of %s, "
			    "assuming minimum of %d ms\n", value,
			    user_failure_detection_time);
		}
		free(value);
	} else {
		/* User has not specified the parameter, Use default value */
		user_failure_detection_time = FAILURE_DETECTION_TIME;
	}

	/*
	 * This gives the frequency at which probes will be sent.
	 * When fdt ms elapses, we should be able to determine
	 * whether 5 consecutive probes have failed or not.
	 * 1 probe will be sent in every user_probe_interval ms,
	 * randomly anytime in the (0.5  - 1.0) 2nd half of every
	 * user_probe_interval. Thus when we send out probe 'n' we
	 * can be sure that probe 'n - 2' is lost, if we have not
	 * got the ack. (since the probe interval is > crtt). But
	 * probe 'n - 1' may be a valid unacked probe, since the
	 * time between 2 successive probes could be as small as
	 * 0.5 * user_probe_interval.  Hence the NUM_PROBE_FAILS + 2
	 */
	user_probe_interval = user_failure_detection_time /
	    (NUM_PROBE_FAILS + 2);

	/*
	 * Get the user specified value of failback_enabled from
	 * /etc/default/mpathd
	 */
	value = getdefault("FAILBACK");
	if (value != NULL) {
		if (strcasecmp(value, "yes") == 0)
			failback_enabled = _B_TRUE;
		else if (strcasecmp(value, "no") == 0)
			failback_enabled = _B_FALSE;
		else
			logerr("Invalid value for FAILBACK %s\n", value);
		free(value);
	} else {
		failback_enabled = _B_TRUE;
	}

	/*
	 * Get the user specified value of track_all_phyints from
	 * /etc/default/mpathd. The sense is reversed in
	 * TRACK_INTERFACES_ONLY_WITH_GROUPS.
	 */
	value = getdefault("TRACK_INTERFACES_ONLY_WITH_GROUPS");
	if (value != NULL) {
		if (strcasecmp(value, "yes") == 0)
			track_all_phyints = _B_FALSE;
		else if (strcasecmp(value, "no") == 0)
			track_all_phyints = _B_TRUE;
		else
			logerr("Invalid value for "
			    "TRACK_INTERFACES_ONLY_WITH_GROUPS %s\n", value);
		free(value);
	} else {
		track_all_phyints = _B_FALSE;
	}

	while ((c = getopt(argc, argv, "adD:ml")) != EOF) {
		switch (c) {
		case 'a':
			adopt = _B_TRUE;
			break;
		case 'm':
			force_mcast = _B_TRUE;
			break;
		case 'd':
			debug = D_ALL;
			foreground = _B_TRUE;
			break;
		case 'D':
			i = (int)strtol(optarg, NULL, 0);
			if (i == 0) {
				(void) fprintf(stderr, "Bad debug flags: %s\n",
				    optarg);
				exit(1);
			}
			debug |= i;
			foreground = _B_TRUE;
			break;
		case 'l':
			/*
			 * Turn off link state notification handling.
			 * Undocumented command line flag, for debugging
			 * purposes.
			 */
			handle_link_notifications = _B_FALSE;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	/*
	 * The sockets for the loopback command interface should be listening
	 * before we fork and exit in daemonize(). This way, whoever started us
	 * can use the loopback interface as soon as they get a zero exit
	 * status.
	 */
	lsock_v4 = setup_listener(AF_INET);
	lsock_v6 = setup_listener(AF_INET6);

	if (lsock_v4 < 0 && lsock_v6 < 0) {
		logerr("main: setup_listener failed for both IPv4 and IPv6\n");
		exit(1);
	}

	if (!foreground) {
		if (!daemonize()) {
			logerr("cannot daemonize\n");
			exit(EXIT_FAILURE);
		}
		initlog();
	}

	/*
	 * Initializations:
	 * 1. Create ifsock* sockets. These are used for performing SIOC*
	 *    ioctls. We have 2 sockets 1 each for IPv4 and IPv6.
	 * 2. Initialize a pipe for handling/recording signal events.
	 * 3. Create the routing sockets,  used for listening
	 *    to routing / interface changes.
	 * 4. phyint_init() - Initialize physical interface state
	 *    (in mpd_tables.c).  Must be done before creating interfaces,
	 *    which timer_init() does indirectly.
	 * 5. Query kernel for route entry sizes (v4 and v6).
	 * 6. timer_init()  - Initialize timer related stuff
	 * 7. initifs() - Initialize our database of all known interfaces
	 * 8. init_router_targets() - Initialize our database of all known
	 *    router targets.
	 */
	ifsock_v4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifsock_v4 < 0) {
		logperror("main: IPv4 socket open");
		exit(1);
	}

	ifsock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (ifsock_v6 < 0) {
		logperror("main: IPv6 socket open");
		exit(1);
	}

	setup_eventpipe();

	rtsock_v4 = setup_rtsock(AF_INET);
	rtsock_v6 = setup_rtsock(AF_INET6);

	if (phyint_init() == -1) {
		logerr("cannot initialize physical interface structures");
		exit(1);
	}

	if (mibwalk(mib_get_constants) == -1)
		exit(1);

	timer_init();

	initifs();

	/*
	 * If we're operating in "adopt" mode and no interfaces need to be
	 * tracked, shut down (ifconfig(1M) will restart us on demand if
	 * interfaces are subsequently put into multipathing groups).
	 */
	if (adopt && phyint_instances == NULL)
		exit(0);

	/*
	 * Main body. Keep listening for activity on any of the sockets
	 * that we are monitoring and take appropriate action as necessary.
	 * signals are also handled synchronously.
	 */
	for (;;) {
		if (poll(pollfds, pollfd_num, -1) < 0) {
			if (errno == EINTR)
				continue;
			logperror("main: poll");
			exit(1);
		}
		for (i = 0; i < pollfd_num; i++) {
			if ((pollfds[i].fd == -1) ||
			    !(pollfds[i].revents & POLLIN))
				continue;
			if (pollfds[i].fd == eventpipe_read) {
				in_signal(eventpipe_read);
				break;
			}
			if (pollfds[i].fd == rtsock_v4 ||
			    pollfds[i].fd == rtsock_v6) {
				process_rtsock(rtsock_v4, rtsock_v6);
				break;
			}

			for (pii = phyint_instances; pii != NULL;
			    pii = pii->pii_next) {
				if (pollfds[i].fd == pii->pii_probe_sock) {
					if (pii->pii_af == AF_INET)
						in_data(pii);
					else
						in6_data(pii);
					break;
				}
			}

			for (pi = phyints; pi != NULL; pi = pi->pi_next) {
				if (pi->pi_notes != 0 &&
				    pollfds[i].fd == dlpi_fd(pi->pi_dh)) {
					(void) dlpi_recv(pi->pi_dh, NULL, NULL,
					    NULL, NULL, 0, NULL);
					break;
				}
			}

			if (pollfds[i].fd == lsock_v4)
				loopback_cmd(lsock_v4, AF_INET);
			else if (pollfds[i].fd == lsock_v6)
				loopback_cmd(lsock_v6, AF_INET6);
		}
	}
	/* NOTREACHED */
	return (EXIT_SUCCESS);
}

static int
setup_listener(int af)
{
	int sock;
	int on;
	int len;
	int ret;
	struct sockaddr_storage laddr;
	struct sockaddr_in  *sin;
	struct sockaddr_in6 *sin6;
	struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;

	assert(af == AF_INET || af == AF_INET6);

	sock = socket(af, SOCK_STREAM, 0);
	if (sock < 0) {
		logperror("setup_listener: socket");
		exit(1);
	}

	on = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
	    sizeof (on)) < 0) {
		logperror("setup_listener: setsockopt (SO_REUSEADDR)");
		exit(1);
	}

	bzero(&laddr, sizeof (laddr));
	laddr.ss_family = af;

	if (af == AF_INET) {
		sin = (struct sockaddr_in *)&laddr;
		sin->sin_port = htons(MPATHD_PORT);
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		len = sizeof (struct sockaddr_in);
	} else {
		sin6 = (struct sockaddr_in6 *)&laddr;
		sin6->sin6_port = htons(MPATHD_PORT);
		sin6->sin6_addr = loopback_addr;
		len = sizeof (struct sockaddr_in6);
	}

	ret = bind(sock, (struct sockaddr *)&laddr, len);
	if (ret < 0) {
		if (errno == EADDRINUSE) {
			/*
			 * Another instance of mpathd may be already active.
			 */
			logerr("main: is another instance of in.mpathd "
			    "already active?\n");
			exit(1);
		} else {
			(void) close(sock);
			return (-1);
		}
	}
	if (listen(sock, 30) < 0) {
		logperror("main: listen");
		exit(1);
	}
	if (poll_add(sock) == -1) {
		(void) close(sock);
		exit(1);
	}

	return (sock);
}

/*
 * Table of commands and their expected size; used by loopback_cmd().
 */
static struct {
	const char	*name;
	unsigned int	size;
} commands[] = {
	{ "MI_PING",		sizeof (uint32_t)	},
	{ "MI_OFFLINE",		sizeof (mi_offline_t)	},
	{ "MI_UNDO_OFFLINE",	sizeof (mi_undo_offline_t) },
	{ "MI_QUERY",		sizeof (mi_query_t)	}
};

/*
 * Commands received over the loopback interface come here (via libipmp).
 */
static void
loopback_cmd(int sock, int family)
{
	int newfd;
	ssize_t len;
	boolean_t is_priv = _B_FALSE;
	struct sockaddr_storage	peer;
	struct sockaddr_in	*peer_sin;
	struct sockaddr_in6	*peer_sin6;
	socklen_t peerlen;
	union mi_commands mpi;
	char abuf[INET6_ADDRSTRLEN];
	uint_t cmd;
	int retval;

	peerlen = sizeof (peer);
	newfd = accept(sock, (struct sockaddr *)&peer, &peerlen);
	if (newfd < 0) {
		logperror("loopback_cmd: accept");
		return;
	}

	switch (family) {
	case AF_INET:
		/*
		 * Validate the address and port to make sure that
		 * non privileged processes don't connect and start
		 * talking to us.
		 */
		if (peerlen != sizeof (struct sockaddr_in)) {
			logerr("loopback_cmd: AF_INET peerlen %d\n", peerlen);
			(void) close(newfd);
			return;
		}
		peer_sin = (struct sockaddr_in *)&peer;
		is_priv = ntohs(peer_sin->sin_port) < IPPORT_RESERVED;
		(void) inet_ntop(AF_INET, &peer_sin->sin_addr.s_addr,
		    abuf, sizeof (abuf));

		if (ntohl(peer_sin->sin_addr.s_addr) != INADDR_LOOPBACK) {
			logerr("Attempt to connect from addr %s port %d\n",
			    abuf, ntohs(peer_sin->sin_port));
			(void) close(newfd);
			return;
		}
		break;

	case AF_INET6:
		if (peerlen != sizeof (struct sockaddr_in6)) {
			logerr("loopback_cmd: AF_INET6 peerlen %d\n", peerlen);
			(void) close(newfd);
			return;
		}
		/*
		 * Validate the address and port to make sure that
		 * non privileged processes don't connect and start
		 * talking to us.
		 */
		peer_sin6 = (struct sockaddr_in6 *)&peer;
		is_priv = ntohs(peer_sin6->sin6_port) < IPPORT_RESERVED;
		(void) inet_ntop(AF_INET6, &peer_sin6->sin6_addr, abuf,
		    sizeof (abuf));
		if (!IN6_IS_ADDR_LOOPBACK(&peer_sin6->sin6_addr)) {
			logerr("Attempt to connect from addr %s port %d\n",
			    abuf, ntohs(peer_sin6->sin6_port));
			(void) close(newfd);
			return;
		}
		break;

	default:
		logdebug("loopback_cmd: family %d\n", family);
		(void) close(newfd);
		return;
	}

	/*
	 * The sizeof the 'mpi' buffer corresponds to the maximum size of
	 * all supported commands
	 */
	len = read(newfd, &mpi, sizeof (mpi));

	/*
	 * In theory, we can receive any sized message for a stream socket,
	 * but we don't expect that to happen for a small message over a
	 * loopback connection.
	 */
	if (len < sizeof (uint32_t)) {
		logerr("loopback_cmd: bad command format or read returns "
		    "partial data %d\n", len);
		(void) close(newfd);
		return;
	}

	cmd = mpi.mi_command;
	if (cmd >= MI_NCMD) {
		logerr("loopback_cmd: unknown command id `%d'\n", cmd);
		(void) close(newfd);
		return;
	}

	/*
	 * Only MI_PING and MI_QUERY can come from unprivileged sources.
	 */
	if (!is_priv && (cmd != MI_QUERY && cmd != MI_PING)) {
		logerr("Unprivileged request from %s for privileged "
		    "command %s\n", abuf, commands[cmd].name);
		(void) close(newfd);
		return;
	}

	if (len < commands[cmd].size) {
		logerr("loopback_cmd: short %s command (expected %d, got %d)\n",
		    commands[cmd].name, commands[cmd].size, len);
		(void) close(newfd);
		return;
	}

	retval = process_cmd(newfd, &mpi);
	if (retval != IPMP_SUCCESS) {
		logerr("failed processing %s: %s\n", commands[cmd].name,
		    ipmp_errmsg(retval));
	}
	(void) close(newfd);
}

/*
 * Process the commands received via libipmp.
 */
static unsigned int
process_cmd(int newfd, union mi_commands *mpi)
{
	struct phyint *pi;
	struct mi_offline *mio;
	struct mi_undo_offline *miu;
	unsigned int retval;

	switch (mpi->mi_command) {
	case MI_PING:
		return (send_result(newfd, IPMP_SUCCESS, 0));

	case MI_OFFLINE:
		mio = &mpi->mi_ocmd;

		pi = phyint_lookup(mio->mio_ifname);
		if (pi == NULL)
			return (send_result(newfd, IPMP_EUNKIF, 0));

		retval = phyint_offline(pi, mio->mio_min_redundancy);
		if (retval == IPMP_FAILURE)
			return (send_result(newfd, IPMP_FAILURE, errno));

		return (send_result(newfd, retval, 0));

	case MI_UNDO_OFFLINE:
		miu = &mpi->mi_ucmd;

		pi = phyint_lookup(miu->miu_ifname);
		if (pi == NULL)
			return (send_result(newfd, IPMP_EUNKIF, 0));

		retval = phyint_undo_offline(pi);
		if (retval == IPMP_FAILURE)
			return (send_result(newfd, IPMP_FAILURE, errno));

		return (send_result(newfd, retval, 0));

	case MI_QUERY:
		return (process_query(newfd, &mpi->mi_qcmd));

	default:
		break;
	}

	return (send_result(newfd, IPMP_EPROTO, 0));
}

/*
 * Process the query request pointed to by `miq' and send a reply on file
 * descriptor `fd'.  Returns an IPMP error code.
 */
static unsigned int
process_query(int fd, mi_query_t *miq)
{
	ipmp_addrinfo_t		*adinfop;
	ipmp_addrinfolist_t	*adlp;
	ipmp_groupinfo_t	*grinfop;
	ipmp_groupinfolist_t	*grlp;
	ipmp_grouplist_t	*grlistp;
	ipmp_ifinfo_t		*ifinfop;
	ipmp_ifinfolist_t	*iflp;
	ipmp_snap_t		*snap;
	unsigned int		retval;

	switch (miq->miq_inforeq) {
	case IPMP_ADDRINFO:
		retval = getgraddrinfo(miq->miq_grname, &miq->miq_addr,
		    &adinfop);
		if (retval != IPMP_SUCCESS)
			return (send_result(fd, retval, errno));

		retval = send_result(fd, IPMP_SUCCESS, 0);
		if (retval == IPMP_SUCCESS)
			retval = send_addrinfo(fd, adinfop);

		ipmp_freeaddrinfo(adinfop);
		return (retval);

	case IPMP_GROUPLIST:
		retval = getgrouplist(&grlistp);
		if (retval != IPMP_SUCCESS)
			return (send_result(fd, retval, errno));

		retval = send_result(fd, IPMP_SUCCESS, 0);
		if (retval == IPMP_SUCCESS)
			retval = send_grouplist(fd, grlistp);

		ipmp_freegrouplist(grlistp);
		return (retval);

	case IPMP_GROUPINFO:
		miq->miq_grname[LIFGRNAMSIZ - 1] = '\0';
		retval = getgroupinfo(miq->miq_grname, &grinfop);
		if (retval != IPMP_SUCCESS)
			return (send_result(fd, retval, errno));

		retval = send_result(fd, IPMP_SUCCESS, 0);
		if (retval == IPMP_SUCCESS)
			retval = send_groupinfo(fd, grinfop);

		ipmp_freegroupinfo(grinfop);
		return (retval);

	case IPMP_IFINFO:
		miq->miq_ifname[LIFNAMSIZ - 1] = '\0';
		retval = getifinfo(miq->miq_ifname, &ifinfop);
		if (retval != IPMP_SUCCESS)
			return (send_result(fd, retval, errno));

		retval = send_result(fd, IPMP_SUCCESS, 0);
		if (retval == IPMP_SUCCESS)
			retval = send_ifinfo(fd, ifinfop);

		ipmp_freeifinfo(ifinfop);
		return (retval);

	case IPMP_SNAP:
		/*
		 * Before taking the snapshot, sync with the kernel.
		 */
		initifs();

		retval = getsnap(&snap);
		if (retval != IPMP_SUCCESS)
			return (send_result(fd, retval, errno));

		retval = send_result(fd, IPMP_SUCCESS, 0);
		if (retval != IPMP_SUCCESS)
			goto out;

		retval = ipmp_writetlv(fd, IPMP_SNAP, sizeof (*snap), snap);
		if (retval != IPMP_SUCCESS)
			goto out;

		retval = send_grouplist(fd, snap->sn_grlistp);
		if (retval != IPMP_SUCCESS)
			goto out;

		iflp = snap->sn_ifinfolistp;
		for (; iflp != NULL; iflp = iflp->ifl_next) {
			retval = send_ifinfo(fd, iflp->ifl_ifinfop);
			if (retval != IPMP_SUCCESS)
				goto out;
		}

		grlp = snap->sn_grinfolistp;
		for (; grlp != NULL; grlp = grlp->grl_next) {
			retval = send_groupinfo(fd, grlp->grl_grinfop);
			if (retval != IPMP_SUCCESS)
				goto out;
		}

		adlp = snap->sn_adinfolistp;
		for (; adlp != NULL; adlp = adlp->adl_next) {
			retval = send_addrinfo(fd, adlp->adl_adinfop);
			if (retval != IPMP_SUCCESS)
				goto out;
		}
	out:
		ipmp_snap_free(snap);
		return (retval);

	default:
		break;

	}
	return (send_result(fd, IPMP_EPROTO, 0));
}

/*
 * Send the group information pointed to by `grinfop' on file descriptor `fd'.
 * Returns an IPMP error code.
 */
static unsigned int
send_groupinfo(int fd, ipmp_groupinfo_t *grinfop)
{
	ipmp_iflist_t	*iflistp = grinfop->gr_iflistp;
	ipmp_addrlist_t	*adlistp = grinfop->gr_adlistp;
	unsigned int	retval;

	retval = ipmp_writetlv(fd, IPMP_GROUPINFO, sizeof (*grinfop), grinfop);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_writetlv(fd, IPMP_IFLIST,
	    IPMP_IFLIST_SIZE(iflistp->il_nif), iflistp);
	if (retval != IPMP_SUCCESS)
		return (retval);

	return (ipmp_writetlv(fd, IPMP_ADDRLIST,
	    IPMP_ADDRLIST_SIZE(adlistp->al_naddr), adlistp));
}

/*
 * Send the interface information pointed to by `ifinfop' on file descriptor
 * `fd'.  Returns an IPMP error code.
 */
static unsigned int
send_ifinfo(int fd, ipmp_ifinfo_t *ifinfop)
{
	ipmp_addrlist_t	*adlist4p = ifinfop->if_targinfo4.it_targlistp;
	ipmp_addrlist_t	*adlist6p = ifinfop->if_targinfo6.it_targlistp;
	unsigned int	retval;

	retval = ipmp_writetlv(fd, IPMP_IFINFO, sizeof (*ifinfop), ifinfop);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_writetlv(fd, IPMP_ADDRLIST,
	    IPMP_ADDRLIST_SIZE(adlist4p->al_naddr), adlist4p);
	if (retval != IPMP_SUCCESS)
		return (retval);

	return (ipmp_writetlv(fd, IPMP_ADDRLIST,
	    IPMP_ADDRLIST_SIZE(adlist6p->al_naddr), adlist6p));
}

/*
 * Send the address information pointed to by `adinfop' on file descriptor
 * `fd'.  Returns an IPMP error code.
 */
static unsigned int
send_addrinfo(int fd, ipmp_addrinfo_t *adinfop)
{
	return (ipmp_writetlv(fd, IPMP_ADDRINFO, sizeof (*adinfop), adinfop));
}

/*
 * Send the group list pointed to by `grlistp' on file descriptor `fd'.
 * Returns an IPMP error code.
 */
static unsigned int
send_grouplist(int fd, ipmp_grouplist_t *grlistp)
{
	return (ipmp_writetlv(fd, IPMP_GROUPLIST,
	    IPMP_GROUPLIST_SIZE(grlistp->gl_ngroup), grlistp));
}

/*
 * Initialize an mi_result_t structure using `error' and `syserror' and
 * send it on file descriptor `fd'.  Returns an IPMP error code.
 */
static unsigned int
send_result(int fd, unsigned int error, int syserror)
{
	mi_result_t me;

	me.me_mpathd_error = error;
	if (error == IPMP_FAILURE)
		me.me_sys_error = syserror;
	else
		me.me_sys_error = 0;

	return (ipmp_write(fd, &me, sizeof (me)));
}

/*
 * Daemonize the process.
 */
static boolean_t
daemonize(void)
{
	switch (fork()) {
	case -1:
		return (_B_FALSE);

	case  0:
		/*
		 * Lose our controlling terminal, and become both a session
		 * leader and a process group leader.
		 */
		if (setsid() == -1)
			return (_B_FALSE);

		/*
		 * Under POSIX, a session leader can accidentally (through
		 * open(2)) acquire a controlling terminal if it does not
		 * have one.  Just to be safe, fork() again so we are not a
		 * session leader.
		 */
		switch (fork()) {
		case -1:
			return (_B_FALSE);

		case 0:
			(void) chdir("/");
			(void) umask(022);
			(void) fdwalk(closefunc, NULL);
			break;

		default:
			_exit(EXIT_SUCCESS);
		}
		break;

	default:
		_exit(EXIT_SUCCESS);
	}

	return (_B_TRUE);
}

/*
 * The parent has created some fds before forking on purpose, keep them open.
 */
static int
closefunc(void *not_used, int fd)
/* ARGSUSED */
{
	if (fd != lsock_v4 && fd != lsock_v6)
		(void) close(fd);
	return (0);
}

/* LOGGER */

#include <syslog.h>

/*
 * Logging routines.  All routines log to syslog, unless the daemon is
 * running in the foreground, in which case the logging goes to stderr.
 *
 * The following routines are available:
 *
 *	logdebug(): A printf-like function for outputting debug messages
 *	(messages at LOG_DEBUG) that are only of use to developers.
 *
 *	logtrace(): A printf-like function for outputting tracing messages
 *	(messages at LOG_INFO) from the daemon.	 This is typically used
 *	to log the receipt of interesting network-related conditions.
 *
 *	logerr(): A printf-like function for outputting error messages
 *	(messages at LOG_ERR) from the daemon.
 *
 *	logperror*(): A set of functions used to output error messages
 *	(messages at LOG_ERR); these automatically append strerror(errno)
 *	and a newline to the message passed to them.
 *
 * NOTE: since the logging functions write to syslog, the messages passed
 *	 to them are not eligible for localization.  Thus, gettext() must
 *	 *not* be used.
 */

static int logging = 0;

static void
initlog(void)
{
	logging++;
	openlog("in.mpathd", LOG_PID, LOG_DAEMON);
}

/* PRINTFLIKE2 */
void
logmsg(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (logging)
		vsyslog(pri, fmt, ap);
	else
		(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* PRINTFLIKE1 */
void
logperror(const char *str)
{
	if (logging)
		syslog(LOG_ERR, "%s: %m\n", str);
	else
		(void) fprintf(stderr, "%s: %s\n", str, strerror(errno));
}

void
logperror_pii(struct phyint_instance *pii, const char *str)
{
	if (logging) {
		syslog(LOG_ERR, "%s (%s %s): %m\n",
		    str, AF_STR(pii->pii_af), pii->pii_phyint->pi_name);
	} else {
		(void) fprintf(stderr, "%s (%s %s): %s\n",
		    str, AF_STR(pii->pii_af), pii->pii_phyint->pi_name,
		    strerror(errno));
	}
}

void
logperror_li(struct logint *li, const char *str)
{
	struct	phyint_instance	*pii = li->li_phyint_inst;

	if (logging) {
		syslog(LOG_ERR, "%s (%s %s): %m\n",
		    str, AF_STR(pii->pii_af), li->li_name);
	} else {
		(void) fprintf(stderr, "%s (%s %s): %s\n",
		    str, AF_STR(pii->pii_af), li->li_name,
		    strerror(errno));
	}
}

void
close_probe_socket(struct phyint_instance *pii, boolean_t polled)
{
	if (polled)
		(void) poll_remove(pii->pii_probe_sock);
	(void) close(pii->pii_probe_sock);
	pii->pii_probe_sock = -1;
	pii->pii_basetime_inited = 0;
}

boolean_t
addrlist_add(addrlist_t **addrsp, const char *name, uint64_t flags,
    struct sockaddr_storage *ssp)
{
	addrlist_t *addrp;

	if ((addrp = malloc(sizeof (addrlist_t))) == NULL)
		return (_B_FALSE);

	(void) strlcpy(addrp->al_name, name, LIFNAMSIZ);
	addrp->al_flags = flags;
	addrp->al_addr = *ssp;
	addrp->al_next = *addrsp;
	*addrsp = addrp;
	return (_B_TRUE);
}

void
addrlist_free(addrlist_t **addrsp)
{
	addrlist_t *addrp, *next_addrp;

	for (addrp = *addrsp; addrp != NULL; addrp = next_addrp) {
		next_addrp = addrp->al_next;
		free(addrp);
	}
	*addrsp = NULL;
}

/*
 * Send down a T_OPTMGMT_REQ to ip asking for all data in the various
 * tables defined by mib2.h. Pass the table information returned to the
 * supplied function.
 */
static int
mibwalk(void (*proc)(mib_item_t *))
{
	mib_item_t		*head_item = NULL;
	mib_item_t		*last_item = NULL;
	mib_item_t		*tmp;
	struct strbuf		ctlbuf, databuf;
	int			flags;
	int			rval;
	uintptr_t		buf[512 / sizeof (uintptr_t)];
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)buf;
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)buf;
	struct T_error_ack	*tea = (struct T_error_ack *)buf;
	struct opthdr		*req, *optp;
	int			status = -1;

	if (mibfd == -1) {
		if ((mibfd = open("/dev/ip", O_RDWR)) < 0) {
			logperror("mibwalk(): ip open");
			return (status);
		}
	}

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;

	/*
	 * Note: we use the special level value below so that IP will return
	 * us information concerning IRE_MARK_TESTHIDDEN routes.
	 */
	req = (struct opthdr *)&tor[1];
	req->level = EXPER_IP_AND_ALL_IRES;
	req->name  = 0;
	req->len   = 0;

	ctlbuf.buf = (char *)&buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;

	if (putmsg(mibfd, &ctlbuf, NULL, 0) == -1) {
		logperror("mibwalk(): putmsg(ctl)");
		return (status);
	}

	/*
	 * The response consists of multiple T_OPTMGMT_ACK msgs, 1 msg for
	 * each table defined in mib2.h.  Each T_OPTMGMT_ACK msg contains
	 * a control and data part. The control part contains a struct
	 * T_optmgmt_ack followed by a struct opthdr. The 'opthdr' identifies
	 * the level, name and length of the data in the data part. The
	 * data part contains the actual table data. The last message
	 * is an end-of-data (EOD), consisting of a T_OPTMGMT_ACK and a
	 * single option with zero optlen.
	 */
	for (;;) {
		errno = flags = 0;
		ctlbuf.maxlen = sizeof (buf);
		rval = getmsg(mibfd, &ctlbuf, NULL, &flags);
		if (rval & MORECTL || rval < 0) {
			if (errno == EINTR)
				continue;
			logerr("mibwalk(): getmsg(ctl) ret: %d err: %d\n",
			    rval, errno);
			goto error;
		}
		if (ctlbuf.len < sizeof (t_scalar_t)) {
			logerr("mibwalk(): ctlbuf.len %d\n", ctlbuf.len);
			goto error;
		}

		switch (toa->PRIM_type) {
		case T_ERROR_ACK:
			if (ctlbuf.len < sizeof (struct T_error_ack)) {
				logerr("mibwalk(): T_ERROR_ACK ctlbuf "
				    "too short: %d\n", ctlbuf.len);
				goto error;
			}
			logerr("mibwalk(): T_ERROR_ACK: TLI_err = 0x%lx: %s\n"
			    " UNIX_err = 0x%lx\n", tea->TLI_error,
			    t_strerror(tea->TLI_error), tea->UNIX_error);
			goto error;

		case T_OPTMGMT_ACK:
			optp = (struct opthdr *)&toa[1];
			if (ctlbuf.len < (sizeof (struct T_optmgmt_ack) +
			    sizeof (struct opthdr))) {
				logerr("mibwalk(): T_OPTMGMT_ACK ctlbuf too "
				    "short: %d\n", ctlbuf.len);
				goto error;
			}
			if (toa->MGMT_flags != T_SUCCESS) {
				logerr("mibwalk(): MGMT_flags != T_SUCCESS: "
				    "0x%lx\n", toa->MGMT_flags);
				goto error;
			}
			break;

		default:
			goto error;
		}
		/* The following assert also implies MGMT_flags == T_SUCCESS */
		assert(toa->PRIM_type == T_OPTMGMT_ACK);

		/*
		 * We have reached the end of this T_OPTMGMT_ACK
		 * message. If this is the last message i.e EOD,
		 * break, else process the next T_OPTMGMT_ACK msg.
		 */
		if (rval == 0) {
			if (optp->len == 0 && optp->name == 0 &&
			    optp->level == 0) {
				/* This is the EOD message. */
				break;
			}
			/* Not EOD but no data to retrieve */
			continue;
		}

		/*
		 * We should only be here if MOREDATA was set.
		 * Allocate an empty mib_item_t and link into the list
		 * of MIB items.
		 */
		if ((tmp = malloc(sizeof (*tmp))) == NULL) {
			logperror("mibwalk(): malloc() failed.");
			goto error;
		}
		if (last_item != NULL)
			last_item->mi_next = tmp;
		else
			head_item = tmp;
		last_item = tmp;
		last_item->mi_next = NULL;
		last_item->mi_opthdr = *optp;
		last_item->mi_valp = malloc(optp->len);
		if (last_item->mi_valp == NULL) {
			logperror("mibwalk(): malloc() failed.");
			goto error;
		}

		databuf.maxlen = last_item->mi_opthdr.len;
		databuf.buf = (char *)last_item->mi_valp;
		databuf.len = 0;

		/* Retrieve the actual MIB data */
		for (;;) {
			flags = 0;
			if ((rval = getmsg(mibfd, NULL, &databuf,
			    &flags)) != 0) {
				if (rval < 0 && errno == EINTR)
					continue;
				/*
				 * We shouldn't get MOREDATA here so treat that
				 * as an error.
				 */
				logperror("mibwalk(): getmsg(data)");
				goto error;
			}
			break;
		}
	}
	status = 0;
	/* Pass the accumulated MIB data to the supplied function pointer */
	(*proc)(head_item);
error:
	while (head_item != NULL) {
		tmp = head_item;
		head_item = tmp->mi_next;
		free(tmp->mi_valp);
		free(tmp);
	}
	return (status);
}

/*
 * Parse the supplied mib2 information to get the size of routing table
 * entries. This is needed when running in a branded zone where the
 * Solaris application environment and the Solaris kernel may not be the
 * the same release version.
 */
static void
mib_get_constants(mib_item_t *item)
{
	mib2_ip_t		*ipv4;
	mib2_ipv6IfStatsEntry_t	*ipv6;

	for (; item != NULL; item = item->mi_next) {
		if (item->mi_opthdr.name != 0)
			continue;
		if (item->mi_opthdr.level == MIB2_IP) {
			ipv4 = (mib2_ip_t *)item->mi_valp;
			ipRouteEntrySize = ipv4->ipRouteEntrySize;
		} else if (item->mi_opthdr.level == MIB2_IP6) {
			ipv6 = (mib2_ipv6IfStatsEntry_t *)item->mi_valp;
			ipv6RouteEntrySize = ipv6->ipv6RouteEntrySize;
		}
	}
}
