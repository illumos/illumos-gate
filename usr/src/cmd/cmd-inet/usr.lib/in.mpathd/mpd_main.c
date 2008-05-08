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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mpd_defs.h"
#include "mpd_tables.h"

int debug = 0;				/* Debug flag */
static int pollfd_num = 0;		/* Num. of poll descriptors */
static struct pollfd *pollfds = NULL;	/* Array of poll descriptors */

					/* All times below in ms */
int	user_failure_detection_time;	/* user specified failure detection */
					/* time (fdt) */
int	user_probe_interval;		/* derived from user specified fdt */

static int	rtsock_v4;		/* AF_INET routing socket */
static int	rtsock_v6;		/* AF_INET6 routing socket */
int	ifsock_v4 = -1;			/* IPv4 socket for ioctls  */
int	ifsock_v6 = -1;			/* IPv6 socket for ioctls  */
static int	lsock_v4;		/* Listen socket to detect mpathd */
static int	lsock_v6;		/* Listen socket to detect mpathd */
static int	mibfd = -1;		/* fd to get mib info */
static boolean_t force_mcast = _B_FALSE; /* Only for test purposes */

boolean_t	full_scan_required = _B_FALSE;
static uint_t	last_initifs_time;	/* Time when initifs was last run */
static	char **argv0;			/* Saved for re-exec on SIGHUP */
boolean_t handle_link_notifications = _B_TRUE;

static void	initlog(void);
static void	run_timeouts(void);
static void	initifs(void);
static void	check_if_removed(struct phyint_instance *pii);
static void	select_test_ifs(void);
static void	ire_process_v4(mib2_ipRouteEntry_t *buf, size_t len);
static void	ire_process_v6(mib2_ipv6RouteEntry_t *buf, size_t len);
static void	router_add_v4(mib2_ipRouteEntry_t *rp1,
    struct in_addr nexthop_v4);
static void	router_add_v6(mib2_ipv6RouteEntry_t *rp1,
    struct in6_addr nexthop_v6);
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
static int	poll_remove(int fd);
static boolean_t daemonize(void);
static int	closefunc(void *, int);
static unsigned int process_cmd(int newfd, union mi_commands *mpi);
static unsigned int process_query(int fd, mi_query_t *miq);
static unsigned int send_groupinfo(int fd, ipmp_groupinfo_t *grinfop);
static unsigned int send_grouplist(int fd, ipmp_grouplist_t *grlistp);
static unsigned int send_ifinfo(int fd, ipmp_ifinfo_t *ifinfop);
static unsigned int send_result(int fd, unsigned int error, int syserror);

struct local_addr *laddr_list = NULL;

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
static int
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
			/*
			 * The phyint has changed group.
			 */
			restore_phyint(pii->pii_phyint);
			/* FALLTHRU */

		case PI_IFINDEX_CHANGED:
			/*
			 * Interface index has changed. Delete and
			 * recreate the phyint as it is quite likely
			 * the interface has been unplumbed and replumbed.
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
 * This phyint is leaving the group. Try to restore the phyint to its
 * initial state. Return the addresses that belong to other group members,
 * to the group, and take back any addresses owned by this phyint
 */
void
restore_phyint(struct phyint *pi)
{
	if (pi->pi_group == phyint_anongroup)
		return;

	/*
	 * Move everthing to some other member in the group.
	 * The phyint has changed group in the kernel. But we
	 * have yet to do it in our tables.
	 */
	if (!pi->pi_empty)
		(void) try_failover(pi, FAILOVER_TO_ANY);
	/*
	 * Move all addresses owned by 'pi' back to pi, from each
	 * of the other members of the group
	 */
	(void) try_failback(pi);
}

/*
 * Scan all interfaces to detect changes as well as new and deleted interfaces
 */
static void
initifs()
{
	int	n;
	int	af;
	char	*cp;
	char	*buf;
	int	numifs;
	struct lifnum	lifn;
	struct lifconf	lifc;
	struct lifreq	*lifr;
	struct logint	*li;
	struct phyint_instance *pii;
	struct phyint_instance *next_pii;
	char	pi_name[LIFNAMSIZ + 1];
	boolean_t exists;
	struct phyint	*pi;
	struct local_addr *next;

	if (debug & D_PHYINT)
		logdebug("initifs: Scanning interfaces\n");

	last_initifs_time = getcurrenttime();

	/*
	 * Free the laddr_list before collecting the local addresses.
	 */
	while (laddr_list != NULL) {
		next = laddr_list->next;
		free(laddr_list);
		laddr_list = next;
	}

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

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = LIFC_ALLZONES;
	if (ioctl(ifsock_v4, SIOCGLIFNUM, (char *)&lifn) < 0) {
		logperror("initifs: ioctl (get interface numbers)");
		return;
	}
	numifs = lifn.lifn_count;

	buf = (char *)calloc(numifs, sizeof (struct lifreq));
	if (buf == NULL) {
		logperror("initifs: calloc");
		return;
	}

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = LIFC_ALLZONES;
	lifc.lifc_len = numifs * sizeof (struct lifreq);
	lifc.lifc_buf = buf;

	if (ioctl(ifsock_v4, SIOCGLIFCONF, (char *)&lifc) < 0) {
		/*
		 * EINVAL is commonly encountered, when things change
		 * underneath us rapidly, (eg. at boot, when new interfaces
		 * are plumbed successively) and the kernel finds the buffer
		 * size we passed as too small. We will retry again
		 * when we see the next routing socket msg, or at worst after
		 * IF_SCAN_INTERVAL ms.
		 */
		if (errno != EINVAL) {
			logperror("initifs: ioctl"
			    " (get interface configuration)");
		}
		free(buf);
		return;
	}

	lifr = (struct lifreq *)lifc.lifc_req;

	/*
	 * For each lifreq returned by SIOGGLIFCONF, call pii_process()
	 * and get the state of the corresponding phyint_instance. If it is
	 * successful, then call logint_init_from_k() to get the state of the
	 * logint.
	 */
	for (n = lifc.lifc_len / sizeof (struct lifreq); n > 0; n--, lifr++) {
		int	sockfd;
		struct local_addr	*taddr;
		struct sockaddr_in	*sin;
		struct sockaddr_in6	*sin6;
		struct lifreq	lifreq;

		af = lifr->lifr_addr.ss_family;

		/*
		 * Collect all local addresses.
		 */
		sockfd = (af == AF_INET) ? ifsock_v4 : ifsock_v6;
		(void) memset(&lifreq, 0, sizeof (lifreq));
		(void) strlcpy(lifreq.lifr_name, lifr->lifr_name,
		    sizeof (lifreq.lifr_name));

		if (ioctl(sockfd, SIOCGLIFFLAGS, &lifreq) == -1) {
			if (errno != ENXIO)
				logperror("initifs: ioctl (SIOCGLIFFLAGS)");
			continue;
		}

		/*
		 * Add the interface address to laddr_list.
		 * Another node might have the same IP address which is up.
		 * In that case, it is appropriate  to use the address as a
		 * target, even though it is also configured (but not up) on
		 * the local system.
		 * Hence,the interface address is not added to laddr_list
		 * unless it is IFF_UP.
		 */
		if (lifreq.lifr_flags & IFF_UP) {
			taddr = malloc(sizeof (struct local_addr));
			if (taddr == NULL) {
				logperror("initifs: malloc");
				continue;
			}
			if (af == AF_INET) {
				sin = (struct sockaddr_in *)&lifr->lifr_addr;
				IN6_INADDR_TO_V4MAPPED(&sin->sin_addr,
				    &taddr->addr);
			} else {
				sin6 = (struct sockaddr_in6 *)&lifr->lifr_addr;
				taddr->addr = sin6->sin6_addr;
			}
			taddr->next = laddr_list;
			laddr_list = taddr;
		}

		/*
		 * Need to pass a phyint name to pii_process. Insert the
		 * null where the ':' IF_SEPARATOR is found in the logical
		 * name.
		 */
		(void) strlcpy(pi_name, lifr->lifr_name, sizeof (pi_name));
		if ((cp = strchr(pi_name, IF_SEPARATOR)) != NULL)
			*cp = '\0';

		exists = pii_process(af, pi_name, &pii);
		if (exists) {
			/* The phyint is fine. So process the logint */
			logint_init_from_k(pii, lifr->lifr_name);
			check_addr_unique(pii, &lifr->lifr_addr);
		}

	}

	free(buf);

	/*
	 * Scan for phyints and logints that have disappeared from the
	 * kernel, and delete them.
	 */
	for (pii = phyint_instances; pii != NULL; pii = next_pii) {
		next_pii = pii->pii_next;
		check_if_removed(pii);
	}

	/*
	 * Select a test address for sending probes on each phyint instance
	 */
	select_test_ifs();

	/*
	 * Handle link up/down notifications from the NICs.
	 */
	process_link_state_changes();

	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		/*
		 * If this is a case of group failure, we don't have much
		 * to do until the group recovers again.
		 */
		if (GROUP_FAILED(pi->pi_group))
			continue;

		/*
		 * Try/Retry any pending failovers / failbacks, that did not
		 * not complete, or that could not be initiated previously.
		 * This implements the 3 invariants described in the big block
		 * comment at the beginning of probe.c
		 */
		if (pi->pi_flags & IFF_INACTIVE) {
			if (!pi->pi_empty && (pi->pi_flags & IFF_STANDBY))
				(void) try_failover(pi, FAILOVER_TO_NONSTANDBY);
		} else {
			struct phyint_instance *pii;

			/*
			 * Skip LINK UP interfaces which are not capable
			 * of probing.
			 */
			pii = pi->pi_v4;
			if (pii == NULL ||
			    (LINK_UP(pi) && !PROBE_CAPABLE(pii))) {
				pii = pi->pi_v6;
				if (pii == NULL ||
				    (LINK_UP(pi) && !PROBE_CAPABLE(pii)))
					continue;
			}

			/*
			 * It is possible that the phyint has started
			 * receiving packets, after it has been marked
			 * PI_FAILED. Don't initiate failover, if the
			 * phyint has started recovering. failure_state()
			 * captures this check. A similar logic is used
			 * for failback/repair case.
			 */
			if (pi->pi_state == PI_FAILED && !pi->pi_empty &&
			    (failure_state(pii) == PHYINT_FAILURE)) {
				(void) try_failover(pi, FAILOVER_NORMAL);
			} else if (pi->pi_state == PI_RUNNING && !pi->pi_full) {
				if (try_failback(pi) != IPMP_FAILURE) {
					(void) change_lif_flags(pi, IFF_FAILED,
					    _B_FALSE);
					/* Per state diagram */
					pi->pi_empty = 0;
				}
			}
		}
	}
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
static void
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
	struct target		*tg;
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
		 * An interface that is offline, should not be probed.
		 * Offline interfaces should always in PI_OFFLINE state,
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

		if (pii->pii_phyint->pi_flags & IFF_POINTOPOINT) {
			tg = pii->pii_targets;
			if (tg != NULL)
				target_delete(tg);
			assert(pii->pii_targets == NULL);
			assert(pii->pii_target_next == NULL);
			assert(pii->pii_ntargets == 0);
			target_create(pii, probe_logint->li_dstaddr,
			    _B_TRUE);
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
	 * Check the interface list for any interfaces that are marked
	 * PI_FAILED but no longer enabled to send probes, and call
	 * phyint_check_for_repair() to see if the link now indicates that the
	 * interface should be repaired.  Also see the state diagram in
	 * mpd_probe.c.
	 */
	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		if (pi->pi_state == PI_FAILED &&
		    !PROBE_ENABLED(pi->pi_v4) && !PROBE_ENABLED(pi->pi_v6)) {
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

		if (li != NULL) {
			if (!pi->pi_duptaddrmsg_printed) {
				(void) pr_addr(li->li_phyint_inst->pii_af,
				    li->li_addr, abuf, sizeof (abuf));
				logerr("Test address %s is not unique in "
				    "group; disabling probe-based failure "
				    "detection on %s\n", abuf, pi->pi_name);
				pi->pi_duptaddrmsg_printed = 1;
			}
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
	 * All phyints of a group must be homogenous to ensure that
	 * failover or failback can be done. If any phyint in a group
	 * has IPv4 plumbed, check that all phyints have IPv4 plumbed.
	 * Do a similar check for IPv6.
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
					logerr("NIC %s of group %s is"
					    " not plumbed for IPv4 and may"
					    " affect failover capability\n",
					    pi->pi_name,
					    pi->pi_group->pg_name);
					pi->pi_cfgmsg_printed = 1;
				}
			} else if (v6_in_group == _B_TRUE &&
			    pi->pi_v6 == NULL) {
				if (!pi->pi_cfgmsg_printed) {
					logerr("NIC %s of group %s is"
					    " not plumbed for IPv6 and may"
					    " affect failover capability\n",
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
					logerr("NIC %s is now consistent with "
					    "group %s and failover capability "
					    "is restored\n", pi->pi_name,
					    pi->pi_group->pg_name);
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
static boolean_t cleanup_started = _B_FALSE;
				/* Don't write to eventpipe if in cleanup */
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
			    "Number of valid unacknowled probes %lld\n"
			    "Number of ambiguous probe acks received %lld\n",
			    AF_STR(pii->pii_af), pii->pii_name,
			    sent, acked, lost, unacked, unknown);
		}
		break;
	case SIGHUP:
		logerr("SIGHUP: restart and reread config file\n");
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

	s = socket(PF_ROUTE, SOCK_RAW, af);
	if (s == -1) {
		logperror("setup_rtsock: socket PF_ROUTE");
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
 * Link up/down notifications from the NICs are reflected in the
 * IFF_RUNNING flag.
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
	 * link state notifications from the NICs, as indicated
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
	 * types.
	 */
	if ((old_flags ^ pii->pii_flags) & IFF_STANDBY)
		phyint_newtype(pi);

	/*
	 * If IFF_INACTIVE has been set, then no data addresses should be
	 * hosted on the interface.  If IFF_INACTIVE has been cleared, then
	 * move previously failed-over addresses back to it, provided it is
	 * not failed.	For details, see the state diagram in mpd_probe.c.
	 */
	if ((old_flags ^ pii->pii_flags) & IFF_INACTIVE) {
		if (pii->pii_flags & IFF_INACTIVE) {
			if (!pi->pi_empty && (pi->pi_flags & IFF_STANDBY))
				(void) try_failover(pi, FAILOVER_TO_NONSTANDBY);
		} else {
			if (pi->pi_state == PI_RUNNING && !pi->pi_full) {
				pi->pi_empty = 0;
				(void) try_failback(pi);
			}
		}
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
 * Send down a T_OPTMGMT_REQ to ip asking for all data in the various
 * tables defined by mib2.h. Parse the returned data and extract
 * the 'routing' information table. Process the 'routing' table
 * to get the list of known onlink routers, and update our database.
 * These onlink routers will serve as our probe targets.
 * Returns false, if any system calls resulted in errors, true otherwise.
 */
static boolean_t
update_router_list(int fd)
{
	union {
		char	ubuf[1024];
		union T_primitives uprim;
	} buf;

	int			flags;
	struct strbuf		ctlbuf;
	struct strbuf		databuf;
	struct T_optmgmt_req	*tor;
	struct T_optmgmt_ack	*toa;
	struct T_error_ack	*tea;
	struct opthdr		*optp;
	struct opthdr		*req;
	int			status;
	t_scalar_t		prim;

	tor = (struct T_optmgmt_req *)&buf;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;

	req = (struct opthdr *)&tor[1];
	req->level = MIB2_IP;	/* any MIB2_xxx value ok here */
	req->name  = 0;
	req->len   = 0;

	ctlbuf.buf = (char *)&buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	ctlbuf.maxlen = sizeof (buf);
	flags = 0;
	if (putmsg(fd, &ctlbuf, NULL, flags) == -1) {
		logperror("update_router_list: putmsg(ctl)");
		return (_B_FALSE);
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
		/*
		 * Go around this loop once for each table. Ignore
		 * all tables except the routing information table.
		 */
		flags = 0;
		status = getmsg(fd, &ctlbuf, NULL, &flags);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			logperror("update_router_list: getmsg(ctl)");
			return (_B_FALSE);
		}
		if (ctlbuf.len < sizeof (t_scalar_t)) {
			logerr("update_router_list: ctlbuf.len %d\n",
			    ctlbuf.len);
			return (_B_FALSE);
		}

		prim = buf.uprim.type;

		switch (prim) {

		case T_ERROR_ACK:
			tea = &buf.uprim.error_ack;
			if (ctlbuf.len < sizeof (struct T_error_ack)) {
				logerr("update_router_list: T_ERROR_ACK"
				    " ctlbuf.len %d\n", ctlbuf.len);
				return (_B_FALSE);
			}
			logerr("update_router_list: T_ERROR_ACK:"
			    " TLI_error = 0x%lx, UNIX_error = 0x%lx\n",
			    tea->TLI_error, tea->UNIX_error);
			return (_B_FALSE);

		case T_OPTMGMT_ACK:
			toa = &buf.uprim.optmgmt_ack;
			optp = (struct opthdr *)&toa[1];
			if (ctlbuf.len < sizeof (struct T_optmgmt_ack)) {
				logerr("update_router_list: ctlbuf.len %d\n",
				    ctlbuf.len);
				return (_B_FALSE);
			}
			if (toa->MGMT_flags != T_SUCCESS) {
				logerr("update_router_list: MGMT_flags 0x%lx\n",
				    toa->MGMT_flags);
				return (_B_FALSE);
			}
			break;

		default:
			logerr("update_router_list: unknown primitive %ld\n",
			    prim);
			return (_B_FALSE);
		}

		/* Process the T_OPGMGMT_ACK below */
		assert(prim == T_OPTMGMT_ACK);

		switch (status) {
		case 0:
			/*
			 * We have reached the end of this T_OPTMGMT_ACK
			 * message. If this is the last message i.e EOD,
			 * return, else process the next T_OPTMGMT_ACK msg.
			 */
			if ((ctlbuf.len == sizeof (struct T_optmgmt_ack) +
			    sizeof (struct opthdr)) && optp->len == 0 &&
			    optp->name == 0 && optp->level == 0) {
				/*
				 * This is the EOD message. Return
				 */
				return (_B_TRUE);
			}
			continue;

		case MORECTL:
		case MORECTL | MOREDATA:
			/*
			 * This should not happen. We should be able to read
			 * the control portion in a single getmsg.
			 */
			logerr("update_router_list: MORECTL\n");
			return (_B_FALSE);

		case MOREDATA:
			databuf.maxlen = optp->len;
			/* malloc of 0 bytes is ok */
			databuf.buf = malloc((size_t)optp->len);
			if (databuf.maxlen != 0 && databuf.buf == NULL) {
				logperror("update_router_list: malloc");
				return (_B_FALSE);
			}
			databuf.len = 0;
			flags = 0;
			for (;;) {
				status = getmsg(fd, NULL, &databuf, &flags);
				if (status >= 0) {
					break;
				} else if (errno == EINTR) {
					continue;
				} else {
					logperror("update_router_list:"
					    " getmsg(data)");
					free(databuf.buf);
					return (_B_FALSE);
				}
			}

			if (optp->level == MIB2_IP &&
			    optp->name == MIB2_IP_ROUTE) {
				/* LINTED */
				ire_process_v4((mib2_ipRouteEntry_t *)
				    databuf.buf, databuf.len);
			} else if (optp->level == MIB2_IP6 &&
			    optp->name == MIB2_IP6_ROUTE) {
				/* LINTED */
				ire_process_v6((mib2_ipv6RouteEntry_t *)
				    databuf.buf, databuf.len);
			}
			free(databuf.buf);
		}
	}
	/* NOTREACHED */
}

/*
 * Examine the IPv4 routing table, for default routers. For each default
 * router, populate the list of targets of each phyint that is on the same
 * link as the default router
 */
static void
ire_process_v4(mib2_ipRouteEntry_t *buf, size_t len)
{
	mib2_ipRouteEntry_t	*rp;
	mib2_ipRouteEntry_t	*rp1;
	struct	in_addr		nexthop_v4;
	mib2_ipRouteEntry_t	*endp;

	if (len == 0)
		return;
	assert((len % sizeof (mib2_ipRouteEntry_t)) == 0);

	endp = buf + (len / sizeof (mib2_ipRouteEntry_t));

	/*
	 * Loop thru the routing table entries. Process any IRE_DEFAULT,
	 * IRE_PREFIX, IRE_HOST, IRE_HOST_REDIRECT ire. Ignore the others.
	 * For each such IRE_OFFSUBNET ire, get the nexthop gateway address.
	 * This is a potential target for probing, which we try to add
	 * to the list of probe targets.
	 */
	for (rp = buf; rp < endp; rp++) {
		if (!(rp->ipRouteInfo.re_ire_type & IRE_OFFSUBNET))
			continue;

		/*  Get the nexthop address. */
		nexthop_v4.s_addr = rp->ipRouteNextHop;

		/*
		 * Get the nexthop address. Then determine the outgoing
		 * interface, by examining all interface IREs, and picking the
		 * match. We don't look at the interface specified in the route
		 * because we need to add the router target on all matching
		 * interfaces anyway; the goal is to avoid falling back to
		 * multicast when some interfaces are in the same subnet but
		 * not in the same group.
		 */
		for (rp1 = buf; rp1 < endp; rp1++) {
			if (!(rp1->ipRouteInfo.re_ire_type & IRE_INTERFACE)) {
				continue;
			}

			/*
			 * Determine the interface IRE that matches the nexthop.
			 * i.e.	 (IRE addr & IRE mask) == (nexthop & IRE mask)
			 */
			if ((rp1->ipRouteDest & rp1->ipRouteMask) ==
			    (nexthop_v4.s_addr & rp1->ipRouteMask)) {
				/*
				 * We found the interface ire
				 */
				router_add_v4(rp1, nexthop_v4);
			}
		}
	}
}

void
router_add_v4(mib2_ipRouteEntry_t *rp1, struct in_addr nexthop_v4)
{
	char *cp;
	char ifname[LIFNAMSIZ + 1];
	struct in6_addr	nexthop;
	int len;

	if (debug & D_TARGET)
		logdebug("router_add_v4()\n");

	len = MIN(rp1->ipRouteIfIndex.o_length, sizeof (ifname) - 1);
	(void) memcpy(ifname, rp1->ipRouteIfIndex.o_bytes, len);
	ifname[len] = '\0';

	if (ifname[0] == '\0')
		return;

	cp = strchr(ifname, IF_SEPARATOR);
	if (cp != NULL)
		*cp = '\0';

	IN6_INADDR_TO_V4MAPPED(&nexthop_v4, &nexthop);
	router_add_common(AF_INET, ifname, nexthop);
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
 * Examine the IPv6 routing table, for default routers. For each default
 * router, populate the list of targets of each phyint that is on the same
 * link as the default router
 */
static void
ire_process_v6(mib2_ipv6RouteEntry_t *buf, size_t len)
{
	mib2_ipv6RouteEntry_t	*rp;
	mib2_ipv6RouteEntry_t	*endp;
	struct	in6_addr nexthop_v6;

	if (debug & D_TARGET)
		logdebug("ire_process_v6(len %d)\n", len);

	if (len == 0)
		return;

	assert((len % sizeof (mib2_ipv6RouteEntry_t)) == 0);
	endp = buf + (len / sizeof (mib2_ipv6RouteEntry_t));

	/*
	 * Loop thru the routing table entries. Process any IRE_DEFAULT,
	 * IRE_PREFIX, IRE_HOST, IRE_HOST_REDIRECT ire. Ignore the others.
	 * For each such IRE_OFFSUBNET ire, get the nexthop gateway address.
	 * This is a potential target for probing, which we try to add
	 * to the list of probe targets.
	 */
	for (rp = buf; rp < endp; rp++) {
		if (!(rp->ipv6RouteInfo.re_ire_type & IRE_OFFSUBNET))
			continue;

		/*
		 * We have the outgoing interface in ipv6RouteIfIndex
		 * if ipv6RouteIfindex.o_length is non-zero. The outgoing
		 * interface must be present for link-local addresses. Since
		 * we use only link-local addreses for probing, we don't
		 * consider the case when the outgoing interface is not
		 * known and we need to scan interface ires
		 */
		nexthop_v6 = rp->ipv6RouteNextHop;
		if (rp->ipv6RouteIfIndex.o_length != 0) {
			/*
			 * We already have the outgoing interface
			 * in ipv6RouteIfIndex.
			 */
			router_add_v6(rp, nexthop_v6);
		}
	}
}


void
router_add_v6(mib2_ipv6RouteEntry_t *rp1, struct in6_addr nexthop_v6)
{
	char ifname[LIFNAMSIZ + 1];
	char *cp;
	int  len;

	if (debug & D_TARGET)
		logdebug("router_add_v6()\n");

	len = MIN(rp1->ipv6RouteIfIndex.o_length, sizeof (ifname) - 1);
	(void) memcpy(ifname, rp1->ipv6RouteIfIndex.o_bytes, len);
	ifname[len] = '\0';

	if (ifname[0] == '\0')
		return;

	cp = strchr(ifname, IF_SEPARATOR);
	if (cp != NULL)
		*cp = '\0';

	router_add_common(AF_INET6, ifname, nexthop_v6);
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
		 * Exclude ptp and host targets. Set tg_in_use to false,
		 * only for router targets.
		 */
		if (!pii->pii_targets_are_routers ||
		    (pi->pi_flags & IFF_POINTOPOINT))
			continue;

		for (tg = pii->pii_targets; tg != NULL; tg = tg->tg_next)
			tg->tg_in_use = 0;
	}

	if (mibfd < 0) {
		mibfd = open("/dev/ip", O_RDWR);
		if (mibfd < 0) {
			logperror("mibopen: ip open");
			exit(1);
		}
	}

	if (!update_router_list(mibfd)) {
		(void) close(mibfd);
		mibfd = -1;
	}

	for (pii = phyint_instances; pii != NULL; pii = pii->pii_next) {
		if (!pii->pii_targets_are_routers ||
		    (pi->pi_flags & IFF_POINTOPOINT))
			continue;

		for (tg = pii->pii_targets; tg != NULL; tg = next_tg) {
			next_tg = tg->tg_next;
			if (!tg->tg_in_use) {
				target_delete(tg);
			}
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
boolean_t	track_all_phyints = _B_FALSE;	/* option to track all NICs */
static boolean_t adopt = _B_FALSE;
static boolean_t foreground = _B_FALSE;

int
main(int argc, char *argv[])
{
	int i;
	int c;
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
			    "default %d\n", value, user_failure_detection_time);

		} else if (user_failure_detection_time <
		    MIN_FAILURE_DETECTION_TIME) {
			user_failure_detection_time =
			    MIN_FAILURE_DETECTION_TIME;
			logerr("Too small failure detection time of %s, "
			    "assuming minimum %d\n", value,
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
		if (strncasecmp(value, "yes", 3) == 0)
			failback_enabled = _B_TRUE;
		else if (strncasecmp(value, "no", 2) == 0)
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
		if (strncasecmp(value, "yes", 3) == 0)
			track_all_phyints = _B_FALSE;
		else if (strncasecmp(value, "no", 2) == 0)
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
	 * 5. timer_init()  - Initialize timer related stuff
	 * 6. initifs() - Initialize our database of all known interfaces
	 * 7. init_router_targets() - Initialize our database of all known
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

	timer_init();

	initifs();

	/* Inform kernel whether failback is enabled or disabled */
	if (ioctl(ifsock_v4, SIOCSIPMPFAILBACK, (int *)&failback_enabled) < 0) {
		logperror("main: ioctl (SIOCSIPMPFAILBACK)");
		exit(1);
	}

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
			if (pollfds[i].fd == lsock_v4)
				loopback_cmd(lsock_v4, AF_INET);
			else if (pollfds[i].fd == lsock_v6)
				loopback_cmd(lsock_v6, AF_INET6);
		}
		if (full_scan_required) {
			initifs();
			full_scan_required = _B_FALSE;
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
	{ "MI_SETOINDEX",	sizeof (mi_setoindex_t) },
	{ "MI_QUERY",		sizeof (mi_query_t)	}
};

/*
 * Commands received over the loopback interface come here. Currently
 * the agents that send commands are ifconfig, if_mpadm and the RCM IPMP
 * module. ifconfig only makes a connection, and closes it to check if
 * in.mpathd is running.
 * if_mpadm sends commands in the format specified by the mpathd_interface
 * structure.
 */
static void
loopback_cmd(int sock, int family)
{
	int newfd;
	ssize_t len;
	struct sockaddr_storage	peer;
	struct sockaddr_in	*peer_sin;
	struct sockaddr_in6	*peer_sin6;
	socklen_t peerlen;
	union mi_commands mpi;
	struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;
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
		if ((ntohs(peer_sin->sin_port) >= IPPORT_RESERVED) ||
		    (ntohl(peer_sin->sin_addr.s_addr) != INADDR_LOOPBACK)) {
			(void) inet_ntop(AF_INET, &peer_sin->sin_addr.s_addr,
			    abuf, sizeof (abuf));
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
		if ((ntohs(peer_sin6->sin6_port) >= IPPORT_RESERVED) ||
		    (!IN6_ARE_ADDR_EQUAL(&peer_sin6->sin6_addr,
		    &loopback_addr))) {
			(void) inet_ntop(AF_INET6, &peer_sin6->sin6_addr, abuf,
			    sizeof (abuf));
			logerr("Attempt to connect from addr %s port %d\n",
			    abuf, ntohs(peer_sin6->sin6_port));
			(void) close(newfd);
			return;
		}

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
	 * ifconfig does not send any data. Just tests to see if mpathd
	 * is already running.
	 */
	if (len <= 0) {
		(void) close(newfd);
		return;
	}

	/*
	 * In theory, we can receive any sized message for a stream socket,
	 * but we don't expect that to happen for a small message over a
	 * loopback connection.
	 */
	if (len < sizeof (uint32_t)) {
		logerr("loopback_cmd: bad command format or read returns "
		    "partial data %d\n", len);
	}

	cmd = mpi.mi_command;
	if (cmd >= MI_NCMD) {
		logerr("loopback_cmd: unknown command id `%d'\n", cmd);
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

extern int global_errno;	/* set by failover() or failback() */

/*
 * Process the offline, undo offline and set original index commands,
 * received from if_mpadm(1M)
 */
static unsigned int
process_cmd(int newfd, union mi_commands *mpi)
{
	uint_t	nif = 0;
	uint32_t cmd;
	struct phyint *pi;
	struct phyint *pi2;
	struct phyint_group *pg;
	boolean_t success;
	int error;
	struct mi_offline *mio;
	struct mi_undo_offline *miu;
	struct lifreq lifr;
	int ifsock;
	struct mi_setoindex *mis;

	cmd = mpi->mi_command;

	switch (cmd) {
	case MI_OFFLINE:
		mio = &mpi->mi_ocmd;
		/*
		 * Lookup the interface that needs to be offlined.
		 * If it does not exist, return a suitable error.
		 */
		pi = phyint_lookup(mio->mio_ifname);
		if (pi == NULL)
			return (send_result(newfd, IPMP_FAILURE, EINVAL));

		/*
		 * Verify that the minimum redundancy requirements are met.
		 * The multipathing group must have at least the specified
		 * number of functional interfaces after offlining the
		 * requested interface. Otherwise return a suitable error.
		 */
		pg = pi->pi_group;
		nif = 0;
		if (pg != phyint_anongroup) {
			for (nif = 0, pi2 = pg->pg_phyint; pi2 != NULL;
			    pi2 = pi2->pi_pgnext) {
				if ((pi2->pi_state == PI_RUNNING) ||
				    (pg->pg_groupfailed &&
				    !(pi2->pi_flags & IFF_OFFLINE)))
					nif++;
			}
		}
		if (nif < mio->mio_min_redundancy)
			return (send_result(newfd, IPMP_EMINRED, 0));

		/*
		 * The order of operation is to set IFF_OFFLINE, followed by
		 * failover. Setting IFF_OFFLINE ensures that no new ipif's
		 * can be created. Subsequent failover moves everything on
		 * the OFFLINE interface to some other functional interface.
		 */
		success = change_lif_flags(pi, IFF_OFFLINE, _B_TRUE);
		if (success) {
			if (!pi->pi_empty) {
				error = try_failover(pi, FAILOVER_NORMAL);
				if (error != 0) {
					if (!change_lif_flags(pi, IFF_OFFLINE,
					    _B_FALSE)) {
						logerr("process_cmd: couldn't"
						    " clear OFFLINE flag on"
						    " %s\n", pi->pi_name);
						/*
						 * Offline interfaces should
						 * not be probed.
						 */
						stop_probing(pi);
					}
					return (send_result(newfd, error,
					    global_errno));
				}
			}
		} else {
			return (send_result(newfd, IPMP_FAILURE, errno));
		}

		/*
		 * The interface is now Offline, so stop probing it.
		 * Note that if_mpadm(1M) will down the test addresses,
		 * after receiving a success reply from us. The routing
		 * socket message will then make us close the socket used
		 * for sending probes. But it is more logical that an
		 * offlined interface must not be probed, even if it has
		 * test addresses.
		 */
		stop_probing(pi);
		return (send_result(newfd, IPMP_SUCCESS, 0));

	case MI_UNDO_OFFLINE:
		miu = &mpi->mi_ucmd;
		/*
		 * Undo the offline command. As usual lookup the interface.
		 * Send an error if it does not exist or is not offline.
		 */
		pi = phyint_lookup(miu->miu_ifname);
		if (pi == NULL || pi->pi_state != PI_OFFLINE)
			return (send_result(newfd, IPMP_FAILURE, EINVAL));

		/*
		 * Reset the state of the interface based on the current link
		 * state; if this phyint subsequently acquires a test address,
		 * the state will be updated later as a result of the probes.
		 */
		if (LINK_UP(pi))
			phyint_chstate(pi, PI_RUNNING);
		else
			phyint_chstate(pi, PI_FAILED);

		if (pi->pi_state == PI_RUNNING) {
			/*
			 * Note that the success of MI_UNDO_OFFLINE is not
			 * contingent on actually failing back; in the odd
			 * case where we cannot do it here, we will try again
			 * in initifs() since pi->pi_full will still be zero.
			 */
			if (do_failback(pi) != IPMP_SUCCESS) {
				logdebug("process_cmd: cannot failback from "
				    "%s during MI_UNDO_OFFLINE\n", pi->pi_name);
			}
		}

		/*
		 * Clear the IFF_OFFLINE flag.  We have to do this last
		 * because do_failback() relies on it being set to decide
		 * when to display messages.
		 */
		(void) change_lif_flags(pi, IFF_OFFLINE, _B_FALSE);

		/*
		 * Give the requestor time to configure test addresses
		 * before complaining that they're missing.
		 */
		pi->pi_taddrthresh = getcurrentsec() + TESTADDR_CONF_TIME;

		return (send_result(newfd, IPMP_SUCCESS, 0));

	case MI_SETOINDEX:
		mis = &mpi->mi_scmd;

		/* Get the socket for doing ioctls */
		ifsock = (mis->mis_iftype == AF_INET) ? ifsock_v4 : ifsock_v6;

		/*
		 * Get index of new original interface.
		 * The index is returned in lifr.lifr_index.
		 */
		(void) strlcpy(lifr.lifr_name, mis->mis_new_pifname,
		    sizeof (lifr.lifr_name));

		if (ioctl(ifsock, SIOCGLIFINDEX, (char *)&lifr) < 0)
			return (send_result(newfd, IPMP_FAILURE, errno));

		/*
		 * Set new original interface index.
		 * The new index was put into lifr.lifr_index by the
		 * SIOCGLIFINDEX ioctl.
		 */
		(void) strlcpy(lifr.lifr_name, mis->mis_lifname,
		    sizeof (lifr.lifr_name));

		if (ioctl(ifsock, SIOCSLIFOINDEX, (char *)&lifr) < 0)
			return (send_result(newfd, IPMP_FAILURE, errno));

		return (send_result(newfd, IPMP_SUCCESS, 0));

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
	ipmp_groupinfo_t	*grinfop;
	ipmp_groupinfolist_t	*grlp;
	ipmp_grouplist_t	*grlistp;
	ipmp_ifinfo_t		*ifinfop;
	ipmp_ifinfolist_t	*iflp;
	ipmp_snap_t		*snap;
	unsigned int		retval;

	switch (miq->miq_inforeq) {
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
		retval = getgroupinfo(miq->miq_ifname, &grinfop);
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
	unsigned int	retval;

	retval = ipmp_writetlv(fd, IPMP_GROUPINFO, sizeof (*grinfop), grinfop);
	if (retval != IPMP_SUCCESS)
		return (retval);

	return (ipmp_writetlv(fd, IPMP_IFLIST,
	    IPMP_IFLIST_SIZE(iflistp->il_nif), iflistp));
}

/*
 * Send the interface information pointed to by `ifinfop' on file descriptor
 * `fd'.  Returns an IPMP error code.
 */
static unsigned int
send_ifinfo(int fd, ipmp_ifinfo_t *ifinfop)
{
	return (ipmp_writetlv(fd, IPMP_IFINFO, sizeof (*ifinfop), ifinfop));
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
