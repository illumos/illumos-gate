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
static boolean_t phyint_is_usable(struct phyint *pi);

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

static int phyint_state_event(struct phyint_group *pg, struct phyint *pi);
static int phyint_group_state_event(struct phyint_group *pg);
static int phyint_group_change_event(struct phyint_group *pg, ipmp_group_op_t);
static int phyint_group_member_event(struct phyint_group *pg, struct phyint *pi,
    ipmp_if_op_t op);

static int logint_upcount(struct phyint *pi);
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

/*
 * Lookup a phyint in the group that has the same hardware address as `pi', or
 * NULL if there's none.  If `online_only' is set, then only online phyints
 * are considered when matching.  Otherwise, phyints that had been offlined
 * due to a duplicate hardware address will also be considered.
 */
static struct phyint *
phyint_lookup_hwaddr(struct phyint *pi, boolean_t online_only)
{
	struct phyint *pi2;

	if (pi->pi_group == phyint_anongroup)
		return (NULL);

	for (pi2 = pi->pi_group->pg_phyint; pi2 != NULL; pi2 = pi2->pi_pgnext) {
		if (pi2 == pi)
			continue;

		/*
		 * NOTE: even when online_only is B_FALSE, we ignore phyints
		 * that are administratively offline (rather than offline
		 * because they're dups); when they're brought back online,
		 * they'll be flagged as dups if need be.
		 */
		if (pi2->pi_state == PI_OFFLINE &&
		    (online_only || !pi2->pi_hwaddrdup))
			continue;

		if (pi2->pi_hwaddrlen == pi->pi_hwaddrlen &&
		    bcmp(pi2->pi_hwaddr, pi->pi_hwaddr, pi->pi_hwaddrlen) == 0)
			return (pi2);
	}
	return (NULL);
}

/*
 * Respond to DLPI notifications.  Currently, this only processes physical
 * address changes for the phyint passed via `arg' by onlining or offlining
 * phyints in the group.
 */
/* ARGSUSED */
static void
phyint_link_notify(dlpi_handle_t dh, dlpi_notifyinfo_t *dnip, void *arg)
{
	struct phyint *pi = arg;
	struct phyint *oduppi = NULL, *duppi = NULL;

	assert((dnip->dni_note & pi->pi_notes) != 0);

	if (dnip->dni_note != DL_NOTE_PHYS_ADDR)
		return;

	assert(dnip->dni_physaddrlen <= DLPI_PHYSADDR_MAX);

	/*
	 * If our hardware address hasn't changed, there's nothing to do.
	 */
	if (pi->pi_hwaddrlen == dnip->dni_physaddrlen &&
	    bcmp(pi->pi_hwaddr, dnip->dni_physaddr, pi->pi_hwaddrlen) == 0)
		return;

	oduppi = phyint_lookup_hwaddr(pi, _B_FALSE);
	pi->pi_hwaddrlen = dnip->dni_physaddrlen;
	(void) memcpy(pi->pi_hwaddr, dnip->dni_physaddr, pi->pi_hwaddrlen);
	duppi = phyint_lookup_hwaddr(pi, _B_FALSE);

	if (oduppi != NULL || pi->pi_hwaddrdup) {
		/*
		 * Our old hardware address was a duplicate.  If we'd been
		 * offlined because of it, and our new hardware address is not
		 * a duplicate, then bring us online.  Otherwise, `oduppi'
		 * must've been the one brought offline; bring it online.
		 */
		if (pi->pi_hwaddrdup) {
			if (duppi == NULL)
				(void) phyint_undo_offline(pi);
		} else {
			assert(oduppi->pi_hwaddrdup);
			(void) phyint_undo_offline(oduppi);
		}
	}

	if (duppi != NULL && !pi->pi_hwaddrdup) {
		/*
		 * Our new hardware address was a duplicate and we're not
		 * yet flagged as a duplicate; bring us offline.
		 */
		pi->pi_hwaddrdup = _B_TRUE;
		(void) phyint_offline(pi, 0);
	}
}

/*
 * Initialize information about the underlying link for `pi', and set us
 * up to be notified about future changes.  Returns _B_TRUE on success.
 */
boolean_t
phyint_link_init(struct phyint *pi)
{
	int retval;
	uint_t notes;
	const char *errmsg;
	dlpi_notifyid_t id;

	pi->pi_notes = 0;
	retval = dlpi_open(pi->pi_name, &pi->pi_dh, 0);
	if (retval != DLPI_SUCCESS) {
		pi->pi_dh = NULL;
		errmsg = "cannot open";
		goto failed;
	}

	pi->pi_hwaddrlen = DLPI_PHYSADDR_MAX;
	retval = dlpi_get_physaddr(pi->pi_dh, DL_CURR_PHYS_ADDR, pi->pi_hwaddr,
	    &pi->pi_hwaddrlen);
	if (retval != DLPI_SUCCESS) {
		errmsg = "cannot get hardware address";
		goto failed;
	}

	/*
	 * Check if the link supports DLPI link state notifications.  For
	 * historical reasons, the actual changes are tracked through routing
	 * sockets, so we immediately disable the notification upon success.
	 */
	notes = DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN;
	retval = dlpi_enabnotify(pi->pi_dh, notes, phyint_link_notify, pi, &id);
	if (retval == DLPI_SUCCESS) {
		(void) dlpi_disabnotify(pi->pi_dh, id, NULL);
		pi->pi_notes |= notes;
	}

	/*
	 * Enable notification of hardware address changes to keep pi_hwaddr
	 * up-to-date and track if we need to offline/undo-offline phyints.
	 */
	notes = DL_NOTE_PHYS_ADDR;
	retval = dlpi_enabnotify(pi->pi_dh, notes, phyint_link_notify, pi, &id);
	if (retval == DLPI_SUCCESS && poll_add(dlpi_fd(pi->pi_dh)) == 0)
		pi->pi_notes |= notes;

	return (_B_TRUE);
failed:
	logerr("%s: %s: %s\n", pi->pi_name, errmsg, dlpi_strerror(retval));
	if (pi->pi_dh != NULL) {
		dlpi_close(pi->pi_dh);
		pi->pi_dh = NULL;
	}
	return (_B_FALSE);
}

/*
 * Close use of link on `pi'.
 */
void
phyint_link_close(struct phyint *pi)
{
	if (pi->pi_notes & DL_NOTE_PHYS_ADDR) {
		(void) poll_remove(dlpi_fd(pi->pi_dh));
		pi->pi_notes &= ~DL_NOTE_PHYS_ADDR;
	}

	/*
	 * NOTE: we don't clear pi_notes here so that iflinkstate() can still
	 * properly report the link state even when offline (which is possible
	 * since we use IFF_RUNNING to track link state).
	 */
	dlpi_close(pi->pi_dh);
	pi->pi_dh = NULL;
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

struct phyint_group *
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

	/* Refresh the group state now that this phyint has been added */
	phyint_group_refresh_state(pg);

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
	 * Record the phyint values.
	 */
	(void) strlcpy(pi->pi_name, pi_name, sizeof (pi->pi_name));
	pi->pi_taddrthresh = getcurrentsec() + TESTADDR_CONF_TIME;
	pi->pi_ifindex = ifindex;
	pi->pi_icmpid = htons(((getpid() & 0xFF) << 8) | (ifindex & 0xFF));

	pi->pi_state = PI_INIT;
	pi->pi_flags = PHYINT_FLAGS(flags);

	/*
	 * Initialize the link state.  The link state is initialized to
	 * up, so that if the link is down when IPMP starts monitoring
	 * the interface, it will appear as though there has been a
	 * transition from the link up to link down.  This avoids
	 * having to treat this situation as a special case.
	 */
	INIT_LINK_STATE(pi);

	if (!phyint_link_init(pi)) {
		free(pi);
		return (NULL);
	}

	/*
	 * Insert the phyint in the list of all phyints, and the
	 * list of phyint group members
	 */
	phyint_insert(pi, pg);

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
	phyint_changed(pi);
}

/*
 * Note that `pi' has changed state.
 */
void
phyint_changed(struct phyint *pi)
{
	pi->pi_group->pg_sig++;
	(void) phyint_state_event(pi->pi_group, pi);
}

/*
 * Insert the phyint group in the linked list of all phyint groups
 * at the head of the list
 */
void
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
struct phyint_group *
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
	pg->pg_in_use = _B_TRUE;

	/*
	 * Normal groups always start in the PG_FAILED state since they
	 * have no active interfaces.  In contrast, anonymous groups are
	 * heterogeneous and thus always PG_OK.
	 */
	pg->pg_state = (name[0] == '\0' ? PG_OK : PG_FAILED);

	return (pg);
}

/*
 * Change the state of the phyint group `pg' to state `state'.
 */
void
phyint_group_chstate(struct phyint_group *pg, enum pg_state state)
{
	assert(pg != phyint_anongroup);

	/*
	 * To simplify things, some callers always set a given state
	 * regardless of the previous state of the group (e.g., setting
	 * PG_DEGRADED when it's already set).  We shouldn't bother
	 * generating an event or consuming a signature for these, since
	 * the actual state of the group is unchanged.
	 */
	if (pg->pg_state == state)
		return;

	pg->pg_state = state;

	switch (state) {
	case PG_FAILED:
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
		 * will still not see any response, otherwise the group
		 * will be repaired after we get NUM_PROBE_REPAIRS
		 * consecutive unicast replies on any phyint.
		 */
		target_flush_hosts(pg);
		break;

	case PG_OK:
	case PG_DEGRADED:
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
	boolean_t	pi_created;
	struct phyint_group	*pg;

retry:
	pii = NULL;
	pi = NULL;
	pg = NULL;
	pi_created = _B_FALSE;

	if (debug & D_PHYINT) {
		logdebug("phyint_inst_init_from_k(%s %s)\n",
		    AF_STR(af), pi_name);
	}

	assert(af == AF_INET || af == AF_INET6);

	/* Get the socket for doing ioctls */
	ifsock = (af == AF_INET) ? ifsock_v4 : ifsock_v6;

	/*
	 * Get the interface flags.  Ignore virtual interfaces, IPMP
	 * meta-interfaces, point-to-point interfaces, and interfaces
	 * that can't support multicast.
	 */
	(void) strlcpy(lifr.lifr_name, pi_name, sizeof (lifr.lifr_name));
	if (ioctl(ifsock, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
		if (errno != ENXIO) {
			logperror("phyint_inst_init_from_k:"
			    " ioctl (get flags)");
		}
		return (NULL);
	}
	flags = lifr.lifr_flags;
	if (!(flags & IFF_MULTICAST) ||
	    (flags & (IFF_VIRTUAL|IFF_IPMP|IFF_POINTOPOINT)))
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
	(void) strlcpy(pg_name, lifr.lifr_groupname, sizeof (pg_name));

	/*
	 * If the phyint is not part of any group, pg_name is the
	 * null string. If 'track_all_phyints' is false, there is no
	 * need to create a phyint.
	 */
	if (pg_name[0] == '\0' && !track_all_phyints) {
		/*
		 * If the IFF_FAILED, IFF_INACTIVE, or IFF_OFFLINE flags are
		 * set, reset them. These flags shouldn't be set if in.mpathd
		 * isn't tracking the interface.
		 */
		if ((flags & (IFF_FAILED | IFF_INACTIVE | IFF_OFFLINE))) {
			lifr.lifr_flags = flags &
			    ~(IFF_FAILED | IFF_INACTIVE | IFF_OFFLINE);
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
	 * We need to create a new phyint instance.  We may also need to
	 * create the group if e.g. the SIOCGLIFCONF loop in initifs() found
	 * an underlying interface before it found its IPMP meta-interface.
	 * Note that we keep any created groups even if phyint_inst_from_k()
	 * fails since a group's existence is not dependent on the ability of
	 * in.mpathd to the track the group's interfaces.
	 */
	if ((pg = phyint_group_lookup(pg_name)) == NULL) {
		if ((pg = phyint_group_create(pg_name)) == NULL) {
			logerr("phyint_inst_init_from_k: cannot create group "
			    "%s\n", pg_name);
			return (NULL);
		}
		phyint_group_insert(pg);
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
		if (pi_created)
			phyint_delete(pi);

		return (NULL);
	}

	/*
	 * NOTE: the change_pif_flags() implementation requires a phyint
	 * instance before it can function, so a number of tasks that would
	 * otherwise be done in phyint_create() are deferred to here.
	 */
	if (pi_created) {
		/*
		 * If the interface is offline, set the state to PI_OFFLINE.
		 * Otherwise, optimistically consider this interface running.
		 * Later (in process_link_state_changes()), we will adjust
		 * this to match the current state of the link.  Further, if
		 * test addresses are subsequently assigned, we will
		 * transition to PI_NOTARGETS and then to either PI_RUNNING or
		 * PI_FAILED depending on the probe results.
		 */
		if (pi->pi_flags & IFF_OFFLINE) {
			phyint_chstate(pi, PI_OFFLINE);
		} else {
			/* calls phyint_chstate() */
			phyint_transition_to_running(pi);
		}

		/*
		 * If this a standby phyint, determine whether it should be
		 * IFF_INACTIVE.
		 */
		if (pi->pi_flags & IFF_STANDBY)
			phyint_standby_refresh_inactive(pi);

		/*
		 * If this phyint does not have a unique hardware address in its
		 * group, offline it.
		 */
		if (phyint_lookup_hwaddr(pi, _B_TRUE) != NULL) {
			pi->pi_hwaddrdup = _B_TRUE;
			(void) phyint_offline(pi, 0);
		}
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
	int off = 0;
	int on = 1;
	struct	sockaddr_in6	testaddr;
	int flags;

	/*
	 * Open a raw socket with ICMPv6 protocol.
	 *
	 * Use IPV6_BOUND_IF to make sure that probes are sent and received on
	 * the specified phyint only.  Bind to the test address to ensure that
	 * the responses are sent to the specified phyint.
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

	/*
	 * Probes must not block in case of lower layer issues.
	 */
	if ((flags = fcntl(pii->pii_probe_sock, F_GETFL, 0)) == -1) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: fcntl"
		    " F_GETFL");
		return (_B_FALSE);
	}
	if (fcntl(pii->pii_probe_sock, F_SETFL,
	    flags | O_NONBLOCK) == -1) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: fcntl"
		    " F_SETFL O_NONBLOCK");
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

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
	    (char *)&pii->pii_ifindex, sizeof (uint_t)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_MULTICAST_IF");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_BOUND_IF,
	    &pii->pii_ifindex, sizeof (uint_t)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_BOUND_IF");
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

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
	    (char *)&off, sizeof (off)) < 0) {
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

	/* Enable receipt of hoplimit */
	if (setsockopt(pii->pii_probe_sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
	    &on, sizeof (on)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " IPV6_RECVHOPLIMIT");
		return (_B_FALSE);
	}

	/* Enable receipt of timestamp */
	if (setsockopt(pii->pii_probe_sock, SOL_SOCKET, SO_TIMESTAMP,
	    &on, sizeof (on)) < 0) {
		logperror_pii(pii, "phyint_inst_v6_sockinit: setsockopt"
		    " SO_TIMESTAMP");
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
	char	char_off = 0;
	int	ttl = 1;
	char	char_ttl = 1;
	int	on = 1;
	int	flags;

	/*
	 * Open a raw socket with ICMPv4 protocol.
	 *
	 * Use IP_BOUND_IF to make sure that probes are sent and received on
	 * the specified phyint only.  Bind to the test address to ensure that
	 * the responses are sent to the specified phyint.
	 *
	 * Set the ttl to 1 so that probe packets are not routed.
	 * Disable multicast loopback.  Enable receipt of timestamp.
	 */
	pii->pii_probe_sock = socket(pii->pii_af, SOCK_RAW, IPPROTO_ICMP);
	if (pii->pii_probe_sock < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: socket");
		return (_B_FALSE);
	}

	/*
	 * Probes must not block in case of lower layer issues.
	 */
	if ((flags = fcntl(pii->pii_probe_sock, F_GETFL, 0)) == -1) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: fcntl"
		    " F_GETFL");
		return (_B_FALSE);
	}
	if (fcntl(pii->pii_probe_sock, F_SETFL,
	    flags | O_NONBLOCK) == -1) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: fcntl"
		    " F_SETFL O_NONBLOCK");
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

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_BOUND_IF,
	    &pii->pii_ifindex, sizeof (uint_t)) < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " IP_BOUND_IF");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_MULTICAST_IF,
	    (char *)&testaddr.sin_addr, sizeof (struct in_addr)) < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " IP_MULTICAST_IF");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_TTL,
	    (char *)&ttl, sizeof (ttl)) < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " IP_TTL");
		return (_B_FALSE);
	}

	if (setsockopt(pii->pii_probe_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
	    (char *)&char_off, sizeof (char_off)) == -1) {
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

	if (setsockopt(pii->pii_probe_sock, SOL_SOCKET, SO_TIMESTAMP, &on,
	    sizeof (on)) < 0) {
		logperror_pii(pii, "phyint_inst_v4_sockinit: setsockopt"
		    " SO_TIMESTAMP");
		return (_B_FALSE);
	}

	return (_B_TRUE);
}

/*
 * Remove the phyint group from the list of 'all phyint groups'
 * and free it.
 */
void
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

	addrlist_free(&pg->pg_addrs);
	free(pg);
}

/*
 * Refresh the state of `pg' based on its current members.
 */
void
phyint_group_refresh_state(struct phyint_group *pg)
{
	enum pg_state state;
	enum pg_state origstate = pg->pg_state;
	struct phyint *pi, *usablepi;
	uint_t nif = 0, nusable = 0;

	/*
	 * Anonymous groups never change state.
	 */
	if (pg == phyint_anongroup)
		return;

	for (pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext) {
		nif++;
		if (phyint_is_usable(pi)) {
			nusable++;
			usablepi = pi;
		}
	}

	if (nusable == 0)
		state = PG_FAILED;
	else if (nif == nusable)
		state = PG_OK;
	else
		state = PG_DEGRADED;

	phyint_group_chstate(pg, state);

	/*
	 * If we're shutting down, skip logging messages since otherwise our
	 * shutdown housecleaning will make us report that groups are unusable.
	 */
	if (cleanup_started)
		return;

	/*
	 * NOTE: We use pg_failmsg_printed rather than origstate since
	 * otherwise at startup we'll log a "now usable" message when the
	 * first usable phyint is added to an empty group.
	 */
	if (state != PG_FAILED && pg->pg_failmsg_printed) {
		assert(origstate == PG_FAILED);
		logerr("At least 1 IP interface (%s) in group %s is now "
		    "usable\n", usablepi->pi_name, pg->pg_name);
		pg->pg_failmsg_printed = _B_FALSE;
	} else if (origstate != PG_FAILED && state == PG_FAILED) {
		logerr("All IP interfaces in group %s are now unusable\n",
		    pg->pg_name);
		pg->pg_failmsg_printed = _B_TRUE;
	}
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

	/*
	 * Make sure the IFF_FAILED flag is set if and only if we think
	 * the interface should be failed.
	 */
	if (pi->pi_flags & IFF_FAILED) {
		if (pi->pi_state == PI_RUNNING)
			(void) change_pif_flags(pi, 0, IFF_FAILED);
	} else {
		if (pi->pi_state == PI_FAILED)
			(void) change_pif_flags(pi, IFF_FAILED, IFF_INACTIVE);
	}

	/* No change in phyint status */
	return (PI_OK);
}

/*
 * Delete the phyint. Remove it from the list of all phyints, and the
 * list of phyint group members.
 */
static void
phyint_delete(struct phyint *pi)
{
	boolean_t active;
	struct phyint *pi2;
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

	/* Refresh the group state now that this phyint has been removed */
	phyint_group_refresh_state(pg);

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

	/*
	 * See if another phyint in the group had been offlined because
	 * it was a dup of `pi' -- and if so, online it.
	 */
	if (!pi->pi_hwaddrdup &&
	    (pi2 = phyint_lookup_hwaddr(pi, _B_FALSE)) != NULL) {
		assert(pi2->pi_hwaddrdup);
		(void) phyint_undo_offline(pi2);
	}

	/*
	 * If the interface was in a named group and was either an active
	 * standby or the last active interface, try to activate another
	 * interface to compensate.
	 */
	if (pg != phyint_anongroup) {
		active = _B_FALSE;
		for (pi2 = pg->pg_phyint; pi2 != NULL; pi2 = pi2->pi_pgnext) {
			if (phyint_is_functioning(pi2) &&
			    !(pi2->pi_flags & IFF_INACTIVE)) {
				active = _B_TRUE;
				break;
			}
		}

		if (!active ||
		    (pi->pi_flags & (IFF_STANDBY|IFF_INACTIVE)) == IFF_STANDBY)
			phyint_activate_another(pi);
	}

	phyint_link_close(pi);
	free(pi);
}

/*
 * Offline phyint `pi' if at least `minred' usable interfaces remain in the
 * group.  Returns an IPMP error code.
 */
int
phyint_offline(struct phyint *pi, uint_t minred)
{
	boolean_t was_active;
	unsigned int nusable = 0;
	struct phyint *pi2;
	struct phyint_group *pg = pi->pi_group;

	/*
	 * Verify that enough usable interfaces in the group would remain.
	 * As a special case, if the group has failed, allow any non-offline
	 * phyints to be offlined.
	 */
	if (pg != phyint_anongroup) {
		for (pi2 = pg->pg_phyint; pi2 != NULL; pi2 = pi2->pi_pgnext) {
			if (pi2 == pi)
				continue;
			if (phyint_is_usable(pi2) ||
			    (GROUP_FAILED(pg) && pi2->pi_state != PI_OFFLINE))
				nusable++;
		}
	}
	if (nusable < minred)
		return (IPMP_EMINRED);

	was_active = ((pi->pi_flags & IFF_INACTIVE) == 0);

	if (!change_pif_flags(pi, IFF_OFFLINE, IFF_INACTIVE))
		return (IPMP_FAILURE);

	/*
	 * The interface is now offline, so stop probing it.  Note that
	 * if_mpadm(8) will down the test addresses, after receiving a
	 * success reply from us. The routing socket message will then make us
	 * close the socket used for sending probes. But it is more logical
	 * that an offlined interface must not be probed, even if it has test
	 * addresses.
	 *
	 * NOTE: stop_probing() also sets PI_OFFLINE.
	 */
	stop_probing(pi);

	/*
	 * If we're offlining the phyint because it has a duplicate hardware
	 * address, print a warning -- and leave the link open so that we can
	 * be notified of hardware address changes that make it usable again.
	 * Otherwise, close the link so that we won't prevent a detach.
	 */
	if (pi->pi_hwaddrdup) {
		logerr("IP interface %s has a hardware address which is not "
		    "unique in group %s; offlining\n", pi->pi_name,
		    pg->pg_name);
	} else {
		phyint_link_close(pi);
	}

	/*
	 * If this phyint was preventing another phyint with a duplicate
	 * hardware address from being online, bring that one online now.
	 */
	if (!pi->pi_hwaddrdup &&
	    (pi2 = phyint_lookup_hwaddr(pi, _B_FALSE)) != NULL) {
		assert(pi2->pi_hwaddrdup);
		(void) phyint_undo_offline(pi2);
	}

	/*
	 * If this interface was active, try to activate another INACTIVE
	 * interface in the group.
	 */
	if (was_active)
		phyint_activate_another(pi);

	return (IPMP_SUCCESS);
}

/*
 * Undo a previous offline of `pi'.  Returns an IPMP error code.
 */
int
phyint_undo_offline(struct phyint *pi)
{
	if (pi->pi_state != PI_OFFLINE) {
		errno = EINVAL;
		return (IPMP_FAILURE);
	}

	/*
	 * If necessary, reinitialize our link information and verify that its
	 * hardware address is still unique across the group.
	 */
	if (pi->pi_dh == NULL && !phyint_link_init(pi)) {
		errno = EIO;
		return (IPMP_FAILURE);
	}

	if (phyint_lookup_hwaddr(pi, _B_TRUE) != NULL) {
		pi->pi_hwaddrdup = _B_TRUE;
		return (IPMP_EHWADDRDUP);
	}

	if (pi->pi_hwaddrdup) {
		logerr("IP interface %s now has a unique hardware address in "
		    "group %s; onlining\n", pi->pi_name, pi->pi_group->pg_name);
		pi->pi_hwaddrdup = _B_FALSE;
	}

	if (!change_pif_flags(pi, 0, IFF_OFFLINE))
		return (IPMP_FAILURE);

	/*
	 * While the interface was offline, it may have failed (e.g. the link
	 * may have gone down).  phyint_inst_check_for_failure() will have
	 * already set pi_flags with IFF_FAILED, so we can use that to decide
	 * whether the phyint should transition to running.  Note that after
	 * we transition to running, we will start sending probes again (if
	 * test addresses are configured), which may also reveal that the
	 * interface is in fact failed.
	 */
	if (pi->pi_flags & IFF_FAILED) {
		phyint_chstate(pi, PI_FAILED);
	} else {
		/* calls phyint_chstate() */
		phyint_transition_to_running(pi);
	}

	/*
	 * Give the requestor time to configure test addresses before
	 * complaining that they're missing.
	 */
	pi->pi_taddrthresh = getcurrentsec() + TESTADDR_CONF_TIME;

	return (IPMP_SUCCESS);
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
	    "sock %x in_use %d\n",
	    AF_STR(pii->pii_af), pii->pii_name, pii->pii_ifindex,
	    pii->pii_state, pii->pii_phyint->pi_flags, pii->pii_probe_sock,
	    pii->pii_in_use);

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
			logdebug("time_start %lld status %d "
			    "time_ackproc %lld time_lost %u",
			    pii->pii_probes[i].pr_hrtime_start,
			    pii->pii_probes[i].pr_status,
			    pii->pii_probes[i].pr_hrtime_ackproc,
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

	if (ioctl(ifsock, SIOCGLIFSUBNET, (char *)&lifr) < 0) {
		/* Interface may have vanished */
		if (errno != ENXIO)
			logperror_li(li, "logint_init_from_k: (get subnet)");
		goto error;
	}
	if (lifr.lifr_subnet.ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_subnet;
		test_subnet = sin6->sin6_addr;
		test_subnet_len = lifr.lifr_addrlen;
	} else {
		sin = (struct sockaddr_in *)&lifr.lifr_subnet;
		IN6_INADDR_TO_V4MAPPED(&sin->sin_addr, &test_subnet);
		test_subnet_len = lifr.lifr_addrlen + (IPV6_ABITS - IP_ABITS);
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
	int af = li->li_phyint_inst->pii_af;

	logdebug("logint: %s %s addr %s/%u", AF_STR(af), li->li_name,
	    pr_addr(af, li->li_addr, abuf, sizeof (abuf)), li->li_subnet_len);

	logdebug("\tFlags: %llx in_use %d\n", li->li_flags, li->li_in_use);
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

/*
 * Fill in the sockaddr_storage pointed to by `ssp' with the IP address
 * represented by the [`af',`addr'] pair.  Needed because in.mpathd internally
 * stores all addresses as in6_addrs, but we don't want to expose that.
 */
void
addr2storage(int af, const struct in6_addr *addr, struct sockaddr_storage *ssp)
{
	struct sockaddr_in *sinp = (struct sockaddr_in *)ssp;
	struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *)ssp;

	assert(af == AF_INET || af == AF_INET6);

	switch (af) {
	case AF_INET:
		(void) memset(sinp, 0, sizeof (*sinp));
		sinp->sin_family = AF_INET;
		IN6_V4MAPPED_TO_INADDR(addr, &sinp->sin_addr);
		break;
	case AF_INET6:
		(void) memset(sin6p, 0, sizeof (*sin6p));
		sin6p->sin6_family = AF_INET6;
		sin6p->sin6_addr = *addr;
		break;
	}
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
				 * Promote the slow_recovered to unused
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
				 * Promote the dead_recovered to slow
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
	 * add the target to this phyint instance only if it belongs to the
	 * same subnet as the test address.  This assures us that we will
	 * be able to reach this target through our routing table.
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
	 * tg_in_use to true.  Even if it exists already, if it's a router
	 * target and we'd previously learned of it through multicast, then we
	 * need to recreate it as a router target.  Otherwise, just set
	 * tg_in_use to to true so that init_router_targets() won't delete it.
	 */
	if (tg == NULL || (is_router && !pii->pii_targets_are_routers))
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
	pii->pii_targets_are_routers = _B_FALSE;
	clear_pii_probe_stats(pii);
	pii_other = phyint_inst_other(pii);

	/*
	 * If there are no targets on both instances and the interface would
	 * otherwise be considered PI_RUNNING, go back to PI_NOTARGETS state,
	 * since we cannot probe this phyint any more.  For more details,
	 * please see phyint state diagram in mpd_probe.c.
	 */
	if (!PROBE_CAPABLE(pii_other) && LINK_UP(pii->pii_phyint) &&
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
			if (pii->pii_probes[i].pr_status == PR_UNACKED) {
				probe_chstate(&pii->pii_probes[i], pii,
				    PR_LOST);
			}
			pii->pii_probes[i].pr_target = NULL;
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
	    "status %d rtt_sa %lld rtt_sd %lld crtt %d tg_in_use %d\n",
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
 * Compare two prefixes that have the same prefix length.
 * Fails if the prefix length is unreasonable.
 */
boolean_t
prefix_equal(struct in6_addr p1, struct in6_addr p2, uint_t prefix_len)
{
	uchar_t mask;
	int j;

	if (prefix_len > IPV6_ABITS)
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
 * Get the number of UP logints on phyint `pi'.
 */
static int
logint_upcount(struct phyint *pi)
{
	struct	logint	*li;
	int count = 0;

	if (pi->pi_v4 != NULL) {
		for (li = pi->pi_v4->pii_logint; li != NULL; li = li->li_next) {
			if (li->li_flags & IFF_UP)
				count++;
		}
	}

	if (pi->pi_v6 != NULL) {
		for (li = pi->pi_v6->pii_logint; li != NULL; li = li->li_next) {
			if (li->li_flags & IFF_UP)
				count++;
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
 * Check whether a phyint is functioning.
 */
boolean_t
phyint_is_functioning(struct phyint *pi)
{
	if (pi->pi_state == PI_RUNNING)
		return (_B_TRUE);
	return (pi->pi_state == PI_NOTARGETS && !(pi->pi_flags & IFF_FAILED));
}

/*
 * Check whether a phyint is usable.
 */
boolean_t
phyint_is_usable(struct phyint *pi)
{
	if (logint_upcount(pi) == 0)
		return (_B_FALSE);
	return (phyint_is_functioning(pi));
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
	static evchan_t *evchp = NULL;

	/*
	 * Initialize the event channel if we haven't already done so.
	 */
	if (evchp == NULL) {
		errno = sysevent_evc_bind(IPMP_EVENT_CHAN, &evchp, EVCH_CREAT);
		if (errno != 0) {
			logerr("cannot create event channel `%s': %s\n",
			    IPMP_EVENT_CHAN, strerror(errno));
			goto failed;
		}
	}

	errno = nvlist_add_uint32(nvl, IPMP_EVENT_VERSION,
	    IPMP_EVENT_CUR_VERSION);
	if (errno != 0) {
		logerr("cannot create `%s' event: %s", subclass,
		    strerror(errno));
		goto failed;
	}

	errno = sysevent_evc_publish(evchp, EC_IPMP, subclass, "com.sun",
	    "in.mpathd", nvl, EVCH_NOSLEEP);
	if (errno != 0) {
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
	case PI_INIT:
		return (IPMP_IF_UNKNOWN);

	case PI_NOTARGETS:
		if (pi->pi_flags & IFF_FAILED)
			return (IPMP_IF_FAILED);
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
 * Return the external IPMP link state associated with phyint `pi'.
 */
static ipmp_if_linkstate_t
iflinkstate(struct phyint *pi)
{
	if (!(pi->pi_notes & (DL_NOTE_LINK_UP|DL_NOTE_LINK_DOWN)))
		return (IPMP_LINK_UNKNOWN);

	return (LINK_DOWN(pi) ? IPMP_LINK_DOWN : IPMP_LINK_UP);
}

/*
 * Return the external IPMP probe state associated with phyint `pi'.
 */
static ipmp_if_probestate_t
ifprobestate(struct phyint *pi)
{
	if (!PROBE_ENABLED(pi->pi_v4) && !PROBE_ENABLED(pi->pi_v6))
		return (IPMP_PROBE_DISABLED);

	if (pi->pi_state == PI_FAILED)
		return (IPMP_PROBE_FAILED);

	if (!PROBE_CAPABLE(pi->pi_v4) && !PROBE_CAPABLE(pi->pi_v6))
		return (IPMP_PROBE_UNKNOWN);

	return (IPMP_PROBE_OK);
}

/*
 * Return the external IPMP target mode associated with phyint instance `pii'.
 */
static ipmp_if_targmode_t
iftargmode(struct phyint_instance *pii)
{
	if (!PROBE_ENABLED(pii))
		return (IPMP_TARG_DISABLED);
	else if (pii->pii_targets_are_routers)
		return (IPMP_TARG_ROUTES);
	else
		return (IPMP_TARG_MULTICAST);
}

/*
 * Return the external IPMP flags associated with phyint `pi'.
 */
static ipmp_if_flags_t
ifflags(struct phyint *pi)
{
	ipmp_if_flags_t flags = 0;

	if (logint_upcount(pi) == 0)
		flags |= IPMP_IFFLAG_DOWN;
	if (pi->pi_flags & IFF_INACTIVE)
		flags |= IPMP_IFFLAG_INACTIVE;
	if (pi->pi_hwaddrdup)
		flags |= IPMP_IFFLAG_HWADDRDUP;
	if (phyint_is_functioning(pi) && flags == 0)
		flags |= IPMP_IFFLAG_ACTIVE;

	return (flags);
}

/*
 * Store the test address used on phyint instance `pii' in `ssp'.  If there's
 * no test address, 0.0.0.0 is stored.
 */
static struct sockaddr_storage *
iftestaddr(struct phyint_instance *pii, struct sockaddr_storage *ssp)
{
	if (PROBE_ENABLED(pii))
		addr2storage(pii->pii_af, &pii->pii_probe_logint->li_addr, ssp);
	else
		addr2storage(AF_INET6, &in6addr_any, ssp);

	return (ssp);
}

/*
 * Return the external IPMP group state associated with phyint group `pg'.
 */
static ipmp_group_state_t
groupstate(struct phyint_group *pg)
{
	switch (pg->pg_state) {
	case PG_FAILED:
		return (IPMP_GROUP_FAILED);
	case PG_DEGRADED:
		return (IPMP_GROUP_DEGRADED);
	case PG_OK:
		return (IPMP_GROUP_OK);
	}

	logerr("groupstate: unknown state %d; aborting\n", pg->pg_state);
	abort();
	/* NOTREACHED */
}

/*
 * Return the external IPMP probe state associated with probe `ps'.
 */
static ipmp_probe_state_t
probestate(struct probe_stats *ps)
{
	switch (ps->pr_status) {
	case PR_UNUSED:
	case PR_LOST:
		return (IPMP_PROBE_LOST);
	case PR_UNACKED:
		return (IPMP_PROBE_SENT);
	case PR_ACKED:
		return (IPMP_PROBE_ACKED);
	}

	logerr("probestate: unknown state %d; aborting\n", ps->pr_status);
	abort();
	/* NOTREACHED */
}

/*
 * Generate an ESC_IPMP_PROBE_STATE sysevent for the probe described by `pr'
 * on phyint instance `pii'.  Returns 0 on success, -1 on failure.
 */
int
probe_state_event(struct probe_stats *pr, struct phyint_instance *pii)
{
	nvlist_t *nvl;
	hrtime_t proc_time = 0, recv_time = 0;
	struct sockaddr_storage ss;
	struct target *tg = pr->pr_target;
	int64_t rttavg, rttdev;

	errno = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (errno != 0) {
		logperror("cannot create `interface change' event");
		return (-1);
	}

	errno = nvlist_add_uint32(nvl, IPMP_PROBE_ID, pr->pr_id);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_string(nvl, IPMP_IF_NAME, pii->pii_phyint->pi_name);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_uint32(nvl, IPMP_PROBE_STATE, probestate(pr));
	if (errno != 0)
		goto failed;

	errno = nvlist_add_hrtime(nvl, IPMP_PROBE_START_TIME,
	    pr->pr_hrtime_start);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_hrtime(nvl, IPMP_PROBE_SENT_TIME,
	    pr->pr_hrtime_sent);
	if (errno != 0)
		goto failed;

	if (pr->pr_status == PR_ACKED) {
		recv_time = pr->pr_hrtime_ackrecv;
		proc_time = pr->pr_hrtime_ackproc;
	}

	errno = nvlist_add_hrtime(nvl, IPMP_PROBE_ACKRECV_TIME, recv_time);
	if (errno != 0)
		goto failed;

	errno = nvlist_add_hrtime(nvl, IPMP_PROBE_ACKPROC_TIME, proc_time);
	if (errno != 0)
		goto failed;

	if (tg != NULL)
		addr2storage(pii->pii_af, &tg->tg_address, &ss);
	else
		addr2storage(pii->pii_af, &in6addr_any, &ss);

	errno = nvlist_add_byte_array(nvl, IPMP_PROBE_TARGET, (uchar_t *)&ss,
	    sizeof (ss));
	if (errno != 0)
		goto failed;

	rttavg = (tg != NULL) ? (tg->tg_rtt_sa / 8) : 0;
	errno = nvlist_add_int64(nvl, IPMP_PROBE_TARGET_RTTAVG, rttavg);
	if (errno != 0)
		goto failed;

	rttdev = (tg != NULL) ? (tg->tg_rtt_sd / 4) : 0;
	errno = nvlist_add_int64(nvl, IPMP_PROBE_TARGET_RTTDEV, rttdev);
	if (errno != 0)
		goto failed;

	return (post_event(ESC_IPMP_PROBE_STATE, nvl));
failed:
	logperror("cannot create `probe state' event");
	nvlist_free(nvl);
	return (-1);
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
	struct phyint		*pi;
	struct phyint_group	*pg;
	char			(*ifs)[LIFNAMSIZ];
	unsigned int		i, j;
	unsigned int		nif = 0, naddr = 0;
	lifgroupinfo_t		lifgr;
	addrlist_t		*addrp;
	struct sockaddr_storage	*addrs;
	int			fdt = 0;

	pg = phyint_group_lookup(grname);
	if (pg == NULL)
		return (IPMP_EUNKGROUP);

	/*
	 * Tally up the number of interfaces, allocate an array to hold them,
	 * and insert their names into the array.  While we're at it, if any
	 * interface is actually enabled to send probes, save the group fdt.
	 */
	for (pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext)
		nif++;

	ifs = alloca(nif * sizeof (*ifs));
	for (i = 0, pi = pg->pg_phyint; pi != NULL; pi = pi->pi_pgnext, i++) {
		assert(i < nif);
		(void) strlcpy(ifs[i], pi->pi_name, LIFNAMSIZ);
		if (PROBE_ENABLED(pi->pi_v4) || PROBE_ENABLED(pi->pi_v6))
			fdt = pg->pg_fdt;
	}
	assert(i == nif);

	/*
	 * If this is the anonymous group, there's no other information to
	 * collect (since there's no IPMP interface).
	 */
	if (pg == phyint_anongroup) {
		*grinfopp = ipmp_groupinfo_create(pg->pg_name, pg->pg_sig, fdt,
		    groupstate(pg), nif, ifs, "", "", "", "", 0, NULL);
		return (*grinfopp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
	}

	/*
	 * Grab some additional information about the group from the kernel.
	 * (NOTE: since SIOCGLIFGROUPINFO does not look up by interface name,
	 * we can use ifsock_v4 even for a V6-only group.)
	 */
	(void) strlcpy(lifgr.gi_grname, grname, LIFGRNAMSIZ);
	if (ioctl(ifsock_v4, SIOCGLIFGROUPINFO, &lifgr) == -1) {
		if (errno == ENOENT)
			return (IPMP_EUNKGROUP);

		logperror("getgroupinfo: SIOCGLIFGROUPINFO");
		return (IPMP_FAILURE);
	}

	/*
	 * Tally up the number of data addresses, allocate an array to hold
	 * them, and insert their values into the array.
	 */
	for (addrp = pg->pg_addrs; addrp != NULL; addrp = addrp->al_next)
		naddr++;

	addrs = alloca(naddr * sizeof (*addrs));
	i = 0;
	for (addrp = pg->pg_addrs; addrp != NULL; addrp = addrp->al_next) {
		/*
		 * It's possible to have duplicate addresses (if some are
		 * down).  Weed the dups out to avoid confusing consumers.
		 * (If groups start having tons of addresses, we'll need a
		 * better algorithm here.)
		 */
		for (j = 0; j < i; j++) {
			if (sockaddrcmp(&addrs[j], &addrp->al_addr))
				break;
		}
		if (j == i) {
			assert(i < naddr);
			addrs[i++] = addrp->al_addr;
		}
	}
	naddr = i;

	*grinfopp = ipmp_groupinfo_create(pg->pg_name, pg->pg_sig, fdt,
	    groupstate(pg), nif, ifs, lifgr.gi_grifname, lifgr.gi_m4ifname,
	    lifgr.gi_m6ifname, lifgr.gi_bcifname, naddr, addrs);
	return (*grinfopp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
}

/*
 * Store the target information associated with phyint instance `pii' into a
 * dynamically allocated structure pointed to by `*targinfopp'.  Returns an
 * IPMP error code.
 */
unsigned int
gettarginfo(struct phyint_instance *pii, const char *name,
    ipmp_targinfo_t **targinfopp)
{
	uint_t ntarg = 0;
	struct target *tg;
	struct sockaddr_storage	ss;
	struct sockaddr_storage *targs = NULL;

	if (PROBE_CAPABLE(pii)) {
		targs = alloca(pii->pii_ntargets * sizeof (*targs));
		tg = pii->pii_target_next;
		do {
			if (tg->tg_status == TG_ACTIVE) {
				assert(ntarg < pii->pii_ntargets);
				addr2storage(pii->pii_af, &tg->tg_address,
				    &targs[ntarg++]);
			}
			if ((tg = tg->tg_next) == NULL)
				tg = pii->pii_targets;
		} while (tg != pii->pii_target_next);

		assert(ntarg == pii->pii_ntargets);
	}

	*targinfopp = ipmp_targinfo_create(name, iftestaddr(pii, &ss),
	    iftargmode(pii), ntarg, targs);
	return (*targinfopp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
}

/*
 * Store the information associated with interface `ifname' into a dynamically
 * allocated structure pointed to by `*ifinfopp'.  Returns an IPMP error code.
 */
unsigned int
getifinfo(const char *ifname, ipmp_ifinfo_t **ifinfopp)
{
	int		retval;
	struct phyint	*pi;
	ipmp_targinfo_t	*targinfo4;
	ipmp_targinfo_t	*targinfo6;

	pi = phyint_lookup(ifname);
	if (pi == NULL)
		return (IPMP_EUNKIF);

	if ((retval = gettarginfo(pi->pi_v4, pi->pi_name, &targinfo4)) != 0 ||
	    (retval = gettarginfo(pi->pi_v6, pi->pi_name, &targinfo6)) != 0)
		goto out;

	*ifinfopp = ipmp_ifinfo_create(pi->pi_name, pi->pi_group->pg_name,
	    ifstate(pi), iftype(pi), iflinkstate(pi), ifprobestate(pi),
	    ifflags(pi), targinfo4, targinfo6);
	retval = (*ifinfopp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
out:
	if (targinfo4 != NULL)
		ipmp_freetarginfo(targinfo4);
	if (targinfo6 != NULL)
		ipmp_freetarginfo(targinfo6);
	return (retval);
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
 * Store the address information for `ssp' (in group `grname') into a
 * dynamically allocated structure pointed to by `*adinfopp'.  Returns an IPMP
 * error code.  (We'd call this function getaddrinfo(), but it would conflict
 * with getaddrinfo(3SOCKET)).
 */
unsigned int
getgraddrinfo(const char *grname, struct sockaddr_storage *ssp,
    ipmp_addrinfo_t **adinfopp)
{
	int ifsock;
	addrlist_t *addrp, *addrmatchp = NULL;
	ipmp_addr_state_t state;
	const char *binding = "";
	struct lifreq lifr;
	struct phyint_group *pg;

	if ((pg = phyint_group_lookup(grname)) == NULL)
		return (IPMP_EUNKADDR);

	/*
	 * Walk through the data addresses, and find a match.  Note that since
	 * some of the addresses may be down, more than one may match.  We
	 * prefer an up address (if one exists).
	 */
	for (addrp = pg->pg_addrs; addrp != NULL; addrp = addrp->al_next) {
		if (sockaddrcmp(ssp, &addrp->al_addr)) {
			addrmatchp = addrp;
			if (addrmatchp->al_flags & IFF_UP)
				break;
		}
	}

	if (addrmatchp == NULL)
		return (IPMP_EUNKADDR);

	state = (addrmatchp->al_flags & IFF_UP) ? IPMP_ADDR_UP : IPMP_ADDR_DOWN;
	if (state == IPMP_ADDR_UP) {
		ifsock = (ssp->ss_family == AF_INET) ? ifsock_v4 : ifsock_v6;
		(void) strlcpy(lifr.lifr_name, addrmatchp->al_name, LIFNAMSIZ);
		if (ioctl(ifsock, SIOCGLIFBINDING, &lifr) >= 0)
			binding = lifr.lifr_binding;
	}

	*adinfopp = ipmp_addrinfo_create(ssp, state, pg->pg_name, binding);
	return (*adinfopp == NULL ? IPMP_ENOMEM : IPMP_SUCCESS);
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
	ipmp_addrinfo_t		*adinfop;
	ipmp_addrlist_t		*adlistp;
	ipmp_ifinfo_t		*ifinfop;
	ipmp_snap_t		*snap;
	struct phyint		*pi;
	unsigned int		i, j;
	int			retval;

	snap = ipmp_snap_create();
	if (snap == NULL)
		return (IPMP_ENOMEM);

	/*
	 * Add group list.
	 */
	retval = getgrouplist(&snap->sn_grlistp);
	if (retval != IPMP_SUCCESS)
		goto failed;

	/*
	 * Add information for each group in the list, along with all of its
	 * data addresses.
	 */
	grlistp = snap->sn_grlistp;
	for (i = 0; i < grlistp->gl_ngroup; i++) {
		retval = getgroupinfo(grlistp->gl_groups[i], &grinfop);
		if (retval != IPMP_SUCCESS)
			goto failed;

		retval = ipmp_snap_addgroupinfo(snap, grinfop);
		if (retval != IPMP_SUCCESS) {
			ipmp_freegroupinfo(grinfop);
			goto failed;
		}

		adlistp = grinfop->gr_adlistp;
		for (j = 0; j < adlistp->al_naddr; j++) {
			retval = getgraddrinfo(grinfop->gr_name,
			    &adlistp->al_addrs[j], &adinfop);
			if (retval != IPMP_SUCCESS)
				goto failed;

			retval = ipmp_snap_addaddrinfo(snap, adinfop);
			if (retval != IPMP_SUCCESS) {
				ipmp_freeaddrinfo(adinfop);
				goto failed;
			}
		}
	}

	/*
	 * Add information for each configured phyint.
	 */
	for (pi = phyints; pi != NULL; pi = pi->pi_next) {
		retval = getifinfo(pi->pi_name, &ifinfop);
		if (retval != IPMP_SUCCESS)
			goto failed;

		retval = ipmp_snap_addifinfo(snap, ifinfop);
		if (retval != IPMP_SUCCESS) {
			ipmp_freeifinfo(ifinfop);
			goto failed;
		}
	}

	*snapp = snap;
	return (IPMP_SUCCESS);
failed:
	ipmp_snap_free(snap);
	return (retval);
}
