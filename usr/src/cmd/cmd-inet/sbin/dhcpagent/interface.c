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
 * Copyright 2019 Joshua M. Clulow <josh@sysmgr.org>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <string.h>
#include <unistd.h>
#include <search.h>
#include <libdevinfo.h>
#include <libdlpi.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <dhcpmsg.h>

#include "agent.h"
#include "interface.h"
#include "util.h"
#include "packet.h"
#include "states.h"

dhcp_pif_t *v4root;
dhcp_pif_t *v6root;

static uint_t cached_v4_max_mtu, cached_v6_max_mtu;

/*
 * Interface flags to watch: things that should be under our direct control.
 */
#define	DHCP_IFF_WATCH	(IFF_DHCPRUNNING | IFF_DEPRECATED | IFF_ADDRCONF | \
	IFF_TEMPORARY)

static void clear_lif_dhcp(dhcp_lif_t *);
static void update_pif_mtu(dhcp_pif_t *);

/*
 * insert_pif(): creates a new physical interface structure and chains it on
 *		 the list.  Initializes state that remains consistent across
 *		 all use of the physical interface entry.
 *
 *   input: const char *: the name of the physical interface
 *	    boolean_t: if B_TRUE, this is DHCPv6
 *	    int *: ignored on input; if insert_pif fails, set to a DHCP_IPC_E_*
 *		   error code with the reason why
 *  output: dhcp_pif_t *: a pointer to the new entry, or NULL on failure
 */

dhcp_pif_t *
insert_pif(const char *pname, boolean_t isv6, int *error)
{
	dhcp_pif_t *pif;
	struct lifreq lifr;
	lifgroupinfo_t lifgr;
	dlpi_handle_t dh = NULL;
	int fd = isv6 ? v6_sock_fd : v4_sock_fd;

	if ((pif = calloc(1, sizeof (*pif))) == NULL) {
		dhcpmsg(MSG_ERR, "insert_pif: cannot allocate pif entry for "
		    "%s", pname);
		*error = DHCP_IPC_E_MEMORY;
		return (NULL);
	}

	pif->pif_isv6 = isv6;
	pif->pif_hold_count = 1;
	pif->pif_running = B_TRUE;

	if (strlcpy(pif->pif_name, pname, LIFNAMSIZ) >= LIFNAMSIZ) {
		dhcpmsg(MSG_ERROR, "insert_pif: interface name %s is too long",
		    pname);
		*error = DHCP_IPC_E_INVIF;
		goto failure;
	}

	/*
	 * This is a bit gross, but IP has a confused interface.  We must
	 * assume that the zeroth LIF is plumbed, and must query there to get
	 * the interface index number.
	 */
	(void) strlcpy(lifr.lifr_name, pname, LIFNAMSIZ);

	if (ioctl(fd, SIOCGLIFINDEX, &lifr) == -1) {
		*error = (errno == ENXIO) ? DHCP_IPC_E_INVIF : DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_pif: SIOCGLIFINDEX for %s", pname);
		goto failure;
	}
	pif->pif_index = lifr.lifr_index;

	/*
	 * Check if this is a VRRP interface. If yes, its IP addresses (the
	 * VRRP virtual addresses) cannot be configured using DHCP.
	 */
	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		*error = (errno == ENXIO) ? DHCP_IPC_E_INVIF : DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_pif: SIOCGLIFFLAGS for %s", pname);
		goto failure;
	}

	if (lifr.lifr_flags & IFF_VRRP) {
		*error = DHCP_IPC_E_INVIF;
		dhcpmsg(MSG_ERROR, "insert_pif: VRRP virtual addresses over %s "
		    "cannot be configured using DHCP", pname);
		goto failure;
	}

	if (ioctl(fd, SIOCGLIFMTU, &lifr) == -1) {
		*error = (errno == ENXIO) ? DHCP_IPC_E_INVIF : DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_pif: SIOCGLIFMTU for %s", pname);
		goto failure;
	}
	pif->pif_mtu_orig = pif->pif_mtu = lifr.lifr_mtu;
	dhcpmsg(MSG_DEBUG, "insert_pif: original MTU of %s is %u", pname,
	    pif->pif_mtu_orig);

	if (pif->pif_mtu < DHCP_DEF_MAX_SIZE) {
		dhcpmsg(MSG_ERROR, "insert_pif: MTU of %s is too small to "
		    "support DHCP (%u < %u)", pname, pif->pif_mtu,
		    DHCP_DEF_MAX_SIZE);
		*error = DHCP_IPC_E_INVIF;
		goto failure;
	}

	/*
	 * Check if the pif is in an IPMP group.  Interfaces using IPMP don't
	 * have dedicated hardware addresses, and get their hardware type from
	 * the SIOCGLIFGROUPINFO ioctl rather than DLPI.
	 */
	if (ioctl(fd, SIOCGLIFGROUPNAME, &lifr) == -1) {
		*error = DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_pif: SIOCGLIFGROUPNAME for %s", pname);
		goto failure;
	}

	if (lifr.lifr_groupname[0] != '\0') {
		(void) strlcpy(lifgr.gi_grname, lifr.lifr_groupname,
		    LIFGRNAMSIZ);
		if (ioctl(fd, SIOCGLIFGROUPINFO, &lifgr) == -1) {
			*error = DHCP_IPC_E_INT;
			dhcpmsg(MSG_ERR, "insert_pif: SIOCGLIFGROUPINFO for %s",
			    lifgr.gi_grname);
			goto failure;
		}

		pif->pif_hwtype = dlpi_arptype(lifgr.gi_mactype);
		pif->pif_under_ipmp = (strcmp(pname, lifgr.gi_grifname) != 0);
		(void) strlcpy(pif->pif_grifname, lifgr.gi_grifname, LIFNAMSIZ);

		/*
		 * For IPMP underlying interfaces, stash the interface index
		 * of the IPMP meta-interface; we'll use it to send/receive
		 * traffic.  This is both necessary (since IP_BOUND_IF for
		 * non-unicast traffic won't work on underlying interfaces)
		 * and preferred (since a test address lease will be able to
		 * be maintained as long as another interface in the group is
		 * still functioning).
		 */
		if (pif->pif_under_ipmp) {
			(void) strlcpy(lifr.lifr_name, pif->pif_grifname,
			    LIFNAMSIZ);

			if (ioctl(fd, SIOCGLIFINDEX, &lifr) == -1) {
				*error = DHCP_IPC_E_INT;
				dhcpmsg(MSG_ERR, "insert_pif: SIOCGLIFINDEX "
				    "for %s", lifr.lifr_name);
				goto failure;
			}
			pif->pif_grindex = lifr.lifr_index;
		}
	}

	/*
	 * For IPv4, if the hardware type is still unknown, use DLPI to
	 * determine it, the hardware address, and hardware address length.
	 */
	if (!isv6 && pif->pif_hwtype == 0) {
		int			rc;
		dlpi_info_t		dlinfo;

		if ((rc = dlpi_open(pname, &dh, 0)) != DLPI_SUCCESS) {
			dhcpmsg(MSG_ERROR, "insert_pif: dlpi_open: %s",
			    dlpi_strerror(rc));
			*error = DHCP_IPC_E_INVIF;
			goto failure;
		}

		if ((rc = dlpi_bind(dh, ETHERTYPE_IP, NULL)) != DLPI_SUCCESS) {
			dhcpmsg(MSG_ERROR, "insert_pif: dlpi_bind: %s",
			    dlpi_strerror(rc));
			*error = DHCP_IPC_E_INVIF;
			goto failure;
		}

		if ((rc = dlpi_info(dh, &dlinfo, 0)) != DLPI_SUCCESS) {
			dhcpmsg(MSG_ERROR, "insert_pif: dlpi_info: %s",
			    dlpi_strerror(rc));
			*error = DHCP_IPC_E_INVIF;
			goto failure;
		}

		pif->pif_hwtype = dlpi_arptype(dlinfo.di_mactype);
		pif->pif_hwlen  = dlinfo.di_physaddrlen;

		dhcpmsg(MSG_DEBUG, "insert_pif: %s: hwtype %d, hwlen %d",
		    pname, pif->pif_hwtype, pif->pif_hwlen);

		if (pif->pif_hwlen > 0) {
			pif->pif_hwaddr = malloc(pif->pif_hwlen);
			if (pif->pif_hwaddr == NULL) {
				dhcpmsg(MSG_ERR, "insert_pif: cannot allocate "
				    "pif_hwaddr for %s", pname);
				*error = DHCP_IPC_E_MEMORY;
				goto failure;
			}
			(void) memcpy(pif->pif_hwaddr, dlinfo.di_physaddr,
			    pif->pif_hwlen);
		}

		dlpi_close(dh);
		dh = NULL;
	}

	insque(pif, isv6 ? &v6root : &v4root);

	return (pif);
failure:
	if (dh != NULL)
		dlpi_close(dh);
	release_pif(pif);
	return (NULL);
}

/*
 * hold_pif(): acquire a hold on a physical interface structure.
 *
 *   input: dhcp_pif_t *: a pointer to the PIF structure
 *  output: none
 */

void
hold_pif(dhcp_pif_t *pif)
{
	pif->pif_hold_count++;
	dhcpmsg(MSG_DEBUG2, "hold_pif: hold count on %s: %u", pif->pif_name,
	    pif->pif_hold_count);
}

/*
 * release_pif(): release a hold on a physical interface structure; will
 *		  destroy the structure on the last hold removed.
 *
 *   input: dhcp_pif_t *: a pointer to the PIF structure
 *  output: none
 */

void
release_pif(dhcp_pif_t *pif)
{
	if (pif->pif_hold_count == 0) {
		dhcpmsg(MSG_CRIT, "release_pif: extraneous release");
		return;
	}

	if (--pif->pif_hold_count == 0) {
		dhcpmsg(MSG_DEBUG, "release_pif: freeing PIF %s",
		    pif->pif_name);

		/*
		 * Unplumbing the last logical interface on top of this
		 * physical interface should have returned the MTU to its
		 * original value.
		 */
		update_pif_mtu(pif);
		if (pif->pif_mtu != pif->pif_mtu_orig) {
			dhcpmsg(MSG_CRIT, "release_pif: PIF %s MTU is %u, "
			    "expected %u", pif->pif_name, pif->pif_mtu,
			    pif->pif_mtu_orig);
		}

		remque(pif);
		free(pif->pif_hwaddr);
		free(pif);
	} else {
		dhcpmsg(MSG_DEBUG2, "release_pif: hold count on %s: %u",
		    pif->pif_name, pif->pif_hold_count);
	}
}

/*
 * lookup_pif_by_uindex(): Looks up PIF entries given truncated index and
 *			   previous PIF pointer (or NULL for list start).
 *			   Caller is expected to iterate through all
 *			   potential matches to find interface of interest.
 *
 *   input: uint16_t: the interface index (truncated)
 *	    dhcp_pif_t *: the previous PIF, or NULL for list start
 *	    boolean_t: B_TRUE if using DHCPv6, B_FALSE otherwise
 *  output: dhcp_pif_t *: the next matching PIF, or NULL if not found
 *    note: This operates using the 'truncated' (16-bit) ifindex as seen by
 *	    routing socket clients.  The value stored in pif_index is the
 *	    32-bit ifindex from the ioctl interface.
 */

dhcp_pif_t *
lookup_pif_by_uindex(uint16_t ifindex, dhcp_pif_t *pif, boolean_t isv6)
{
	if (pif == NULL)
		pif = isv6 ? v6root : v4root;
	else
		pif = pif->pif_next;

	for (; pif != NULL; pif = pif->pif_next) {
		if ((pif->pif_index & 0xffff) == ifindex)
			break;
	}

	return (pif);
}

/*
 * lookup_pif_by_name(): Looks up a physical interface entry given a name.
 *
 *   input: const char *: the physical interface name
 *	    boolean_t: B_TRUE if using DHCPv6, B_FALSE otherwise
 *  output: dhcp_pif_t *: the matching PIF, or NULL if not found
 */

dhcp_pif_t *
lookup_pif_by_name(const char *pname, boolean_t isv6)
{
	dhcp_pif_t *pif;

	pif = isv6 ? v6root : v4root;

	for (; pif != NULL; pif = pif->pif_next) {
		if (strcmp(pif->pif_name, pname) == 0)
			break;
	}

	return (pif);
}

/*
 * pif_status(): update the physical interface up/down status.
 *
 *   input: dhcp_pif_t *: the physical interface to be updated
 *	    boolean_t: B_TRUE if the interface is going up
 *  output: none
 */

void
pif_status(dhcp_pif_t *pif, boolean_t isup)
{
	dhcp_lif_t *lif;
	dhcp_smach_t *dsmp;

	pif->pif_running = isup;
	dhcpmsg(MSG_DEBUG, "interface %s has %s", pif->pif_name,
	    isup ? "come back up" : "gone down");
	for (lif = pif->pif_lifs; lif != NULL; lif = lif->lif_next) {
		for (dsmp = lif->lif_smachs; dsmp != NULL;
		    dsmp = dsmp->dsm_next) {
			if (isup)
				refresh_smach(dsmp);
			else
				remove_default_routes(dsmp);
		}
	}
}

/* Helper for insert_lif: extract addresses as defined */
#define	ASSIGN_ADDR(v4, v6, lf) \
	if (pif->pif_isv6) { \
		lif->v6 = ((struct sockaddr_in6 *)&lifr.lf)->sin6_addr; \
	} else { \
		lif->v4 = ((struct sockaddr_in *)&lifr.lf)->sin_addr.s_addr; \
	}

/*
 * insert_lif(): Creates a new logical interface structure and chains it on
 *		 the list for a given physical interface.  Initializes state
 *		 that remains consistent across all use of the logical
 *		 interface entry.  Caller's PIF hold is transferred to the
 *		 LIF on success, and is dropped on failure.
 *
 *   input: dhcp_pif_t *: pointer to the physical interface for this LIF
 *	    const char *: the name of the logical interface
 *	    int *: ignored on input; if insert_pif fails, set to a DHCP_IPC_E_*
 *		   error code with the reason why
 *  output: dhcp_lif_t *: a pointer to the new entry, or NULL on failure
 */

dhcp_lif_t *
insert_lif(dhcp_pif_t *pif, const char *lname, int *error)
{
	dhcp_lif_t *lif;
	int fd;
	struct lifreq lifr;

	if ((lif = calloc(1, sizeof (*lif))) == NULL) {
		dhcpmsg(MSG_ERR, "insert_lif: cannot allocate lif entry for "
		    "%s", lname);
		*error = DHCP_IPC_E_MEMORY;
		return (NULL);
	}

	lif->lif_sock_ip_fd = -1;
	lif->lif_packet_id = -1;
	lif->lif_iaid_id = -1;
	lif->lif_hold_count = 1;
	lif->lif_pif = pif;
	lif->lif_removed = B_TRUE;
	init_timer(&lif->lif_preferred, 0);
	init_timer(&lif->lif_expire, 0);

	if (strlcpy(lif->lif_name, lname, LIFNAMSIZ) >= LIFNAMSIZ) {
		dhcpmsg(MSG_ERROR, "insert_lif: interface name %s is too long",
		    lname);
		*error = DHCP_IPC_E_INVIF;
		goto failure;
	}

	(void) strlcpy(lifr.lifr_name, lname, LIFNAMSIZ);

	fd = pif->pif_isv6 ? v6_sock_fd : v4_sock_fd;

	if (ioctl(fd, SIOCGLIFADDR, &lifr) == -1) {
		if (errno == ENXIO)
			*error = DHCP_IPC_E_INVIF;
		else
			*error = DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_lif: SIOCGLIFADDR for %s", lname);
		goto failure;
	}
	ASSIGN_ADDR(lif_addr, lif_v6addr, lifr_addr);

	if (ioctl(fd, SIOCGLIFNETMASK, &lifr) == -1) {
		if (errno == ENXIO)
			*error = DHCP_IPC_E_INVIF;
		else
			*error = DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_lif: SIOCGLIFNETMASK for %s", lname);
		goto failure;
	}
	ASSIGN_ADDR(lif_netmask, lif_v6mask, lifr_addr);

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		*error = DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_lif: SIOCGLIFFLAGS for %s", lname);
		goto failure;
	}
	lif->lif_flags = lifr.lifr_flags;

	/*
	 * If we've just detected the interface going up or down, then signal
	 * an appropriate action.  There may be other state machines here.
	 */
	if ((lifr.lifr_flags & IFF_RUNNING) && !pif->pif_running) {
		pif_status(pif, B_TRUE);
	} else if (!(lifr.lifr_flags & IFF_RUNNING) && pif->pif_running) {
		pif_status(pif, B_FALSE);
	}

	if (lifr.lifr_flags & IFF_POINTOPOINT) {
		if (ioctl(fd, SIOCGLIFDSTADDR, &lifr) == -1) {
			*error = DHCP_IPC_E_INT;
			dhcpmsg(MSG_ERR, "insert_lif: SIOCGLIFDSTADDR for %s",
			    lname);
			goto failure;
		}
		ASSIGN_ADDR(lif_peer, lif_v6peer, lifr_dstaddr);
	} else if (!pif->pif_isv6 && (lifr.lifr_flags & IFF_BROADCAST)) {
		if (ioctl(fd, SIOCGLIFBRDADDR, &lifr) == -1) {
			*error = DHCP_IPC_E_INT;
			dhcpmsg(MSG_ERR, "insert_lif: SIOCGLIFBRDADDR for %s",
			    lname);
			goto failure;
		}
		lif->lif_broadcast =
		    ((struct sockaddr_in *)&lifr.lifr_broadaddr)->sin_addr.
		    s_addr;
	}

	if (pif->pif_isv6)
		cached_v6_max_mtu = 0;
	else
		cached_v4_max_mtu = 0;

	lif->lif_removed = B_FALSE;
	insque(lif, &pif->pif_lifs);

	return (lif);

failure:
	release_lif(lif);
	return (NULL);
}

/*
 * hold_lif(): acquire a hold on a logical interface structure.
 *
 *   input: dhcp_lif_t *: a pointer to the LIF structure
 *  output: none
 */

void
hold_lif(dhcp_lif_t *lif)
{
	lif->lif_hold_count++;
	dhcpmsg(MSG_DEBUG2, "hold_lif: hold count on %s: %u", lif->lif_name,
	    lif->lif_hold_count);
}

/*
 * release_lif(): release a hold on a logical interface structure; will
 *		  destroy the structure on the last hold removed.
 *
 *   input: dhcp_lif_t *: a pointer to the LIF structure
 *  output: none
 */

void
release_lif(dhcp_lif_t *lif)
{
	if (lif->lif_hold_count == 0) {
		dhcpmsg(MSG_CRIT, "release_lif: extraneous release on %s",
		    lif->lif_name);
		return;
	}

	if (lif->lif_hold_count == 1 && !lif->lif_removed) {
		unplumb_lif(lif);
		return;
	}

	if (--lif->lif_hold_count == 0) {
		dhcp_pif_t *pif;

		dhcpmsg(MSG_DEBUG, "release_lif: freeing LIF %s",
		    lif->lif_name);

		if (lif->lif_lease != NULL)
			dhcpmsg(MSG_CRIT,
			    "release_lif: still holding lease at last hold!");
		close_ip_lif(lif);
		pif = lif->lif_pif;
		if (pif->pif_isv6)
			cached_v6_max_mtu = 0;
		else
			cached_v4_max_mtu = 0;
		release_pif(pif);
		free(lif);
	} else {
		dhcpmsg(MSG_DEBUG2, "release_lif: hold count on %s: %u",
		    lif->lif_name, lif->lif_hold_count);
	}
}

/*
 * remove_lif(): remove a logical interface from its PIF and lease (if any) and
 *		 the lease's hold on the LIF.  Assumes that we did not plumb
 *		 the interface.
 *
 *   input: dhcp_lif_t *: a pointer to the LIF structure
 *  output: none
 */

void
remove_lif(dhcp_lif_t *lif)
{
	if (lif->lif_plumbed) {
		dhcpmsg(MSG_CRIT, "remove_lif: attempted invalid removal of %s",
		    lif->lif_name);
		return;
	}
	if (lif->lif_removed) {
		dhcpmsg(MSG_CRIT, "remove_lif: extraneous removal of %s",
		    lif->lif_name);
	} else {
		dhcp_lif_t *lifnext;
		dhcp_lease_t *dlp;

		dhcpmsg(MSG_DEBUG2, "remove_lif: removing %s", lif->lif_name);
		lif->lif_removed = B_TRUE;
		lifnext = lif->lif_next;
		clear_lif_dhcp(lif);
		cancel_lif_timers(lif);
		if (lif->lif_iaid_id != -1 &&
		    iu_cancel_timer(tq, lif->lif_iaid_id, NULL) == 1) {
			lif->lif_iaid_id = -1;
			release_lif(lif);
		}

		/* Remove from PIF list */
		remque(lif);

		/* If we were part of a lease, then remove ourselves */
		if ((dlp = lif->lif_lease) != NULL) {
			if (--dlp->dl_nlifs == 0)
				dlp->dl_lifs = NULL;
			else if (dlp->dl_lifs == lif)
				dlp->dl_lifs = lifnext;
			if (lif->lif_declined != NULL) {
				dlp->dl_smach->dsm_lif_down--;
				lif->lif_declined = NULL;
			}
			if (lif->lif_dad_wait) {
				lif->lif_dad_wait = _B_FALSE;
				dlp->dl_smach->dsm_lif_wait--;
			}
			lif->lif_lease = NULL;
			release_lif(lif);
		}
	}
}

/*
 * lookup_lif_by_name(): Looks up a logical interface entry given a name and
 *			 a physical interface.
 *
 *   input: const char *: the logical interface name
 *	    const dhcp_pif_t *: the physical interface
 *  output: dhcp_lif_t *: the matching LIF, or NULL if not found
 */

dhcp_lif_t *
lookup_lif_by_name(const char *lname, const dhcp_pif_t *pif)
{
	dhcp_lif_t *lif;

	for (lif = pif->pif_lifs; lif != NULL; lif = lif->lif_next) {
		if (strcmp(lif->lif_name, lname) == 0)
			break;
	}

	return (lif);
}

/*
 * checkaddr(): checks if the given address is still set on the given LIF
 *
 *   input: const dhcp_lif_t *: the LIF to check
 *	    int: the address to look up on the interface (ioctl)
 *	    const in6_addr_t *: the address to compare to
 *	    const char *: name of the address for logging purposes
 *  output: boolean_t: B_TRUE if the address is still set; B_FALSE if not
 */

static boolean_t
checkaddr(const dhcp_lif_t *lif, int ioccmd, const in6_addr_t *addr,
    const char *aname)
{
	boolean_t isv6;
	int fd;
	struct lifreq lifr;
	char abuf1[INET6_ADDRSTRLEN];
	char abuf2[INET6_ADDRSTRLEN];

	(void) memset(&lifr, 0, sizeof (struct lifreq));
	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	isv6 = lif->lif_pif->pif_isv6;
	fd = isv6 ? v6_sock_fd : v4_sock_fd;

	if (ioctl(fd, ioccmd, &lifr) == -1) {
		if (errno == ENXIO) {
			dhcpmsg(MSG_WARNING, "checkaddr: interface %s is gone",
			    lif->lif_name);
			return (B_FALSE);
		}
		dhcpmsg(MSG_DEBUG,
		    "checkaddr: ignoring ioctl error on %s %x: %s",
		    lif->lif_name, ioccmd, strerror(errno));
	} else if (isv6) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&lifr.lifr_addr;

		if (!IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, addr)) {
			dhcpmsg(MSG_WARNING,
			    "checkaddr: expected %s %s on %s, have %s", aname,
			    inet_ntop(AF_INET6, addr, abuf1, sizeof (abuf1)),
			    lif->lif_name, inet_ntop(AF_INET6, &sin6->sin6_addr,
			    abuf2, sizeof (abuf2)));
			return (B_FALSE);
		}
	} else {
		struct sockaddr_in *sinp =
		    (struct sockaddr_in *)&lifr.lifr_addr;
		ipaddr_t v4addr;

		IN6_V4MAPPED_TO_IPADDR(addr, v4addr);
		if (sinp->sin_addr.s_addr != v4addr) {
			dhcpmsg(MSG_WARNING,
			    "checkaddr: expected %s %s on %s, have %s", aname,
			    inet_ntop(AF_INET, &v4addr, abuf1, sizeof (abuf1)),
			    lif->lif_name, inet_ntop(AF_INET, &sinp->sin_addr,
			    abuf2, sizeof (abuf2)));
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

/*
 * verify_lif(): verifies than a LIF is still valid (i.e., has not been
 *		 explicitly or implicitly dropped or released)
 *
 *   input: const dhcp_lif_t *: the LIF to verify
 *  output: boolean_t: B_TRUE if the LIF is still valid, B_FALSE otherwise
 */

boolean_t
verify_lif(const dhcp_lif_t *lif)
{
	boolean_t isv6;
	int fd;
	struct lifreq lifr;
	dhcp_pif_t *pif = lif->lif_pif;

	(void) memset(&lifr, 0, sizeof (struct lifreq));
	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	isv6 = pif->pif_isv6;
	fd = isv6 ? v6_sock_fd : v4_sock_fd;

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		if (errno != ENXIO) {
			dhcpmsg(MSG_ERR,
			    "verify_lif: SIOCGLIFFLAGS failed on %s",
			    lif->lif_name);
		}
		return (B_FALSE);
	}

	/*
	 * If important flags have changed, then abandon the interface.
	 */
	if ((lif->lif_flags ^ lifr.lifr_flags) & DHCP_IFF_WATCH) {
		dhcpmsg(MSG_DEBUG, "verify_lif: unexpected flag change on %s: "
		    "%llx to %llx (%llx)", lif->lif_name, lif->lif_flags,
		    lifr.lifr_flags, (lif->lif_flags ^ lifr.lifr_flags) &
		    DHCP_IFF_WATCH);
		return (B_FALSE);
	}

	/*
	 * Check for delete and recreate.
	 */
	if (ioctl(fd, SIOCGLIFINDEX, &lifr) == -1) {
		if (errno != ENXIO) {
			dhcpmsg(MSG_ERR, "verify_lif: SIOCGLIFINDEX failed "
			    "on %s", lif->lif_name);
		}
		return (B_FALSE);
	}
	if (lifr.lifr_index != pif->pif_index) {
		dhcpmsg(MSG_DEBUG,
		    "verify_lif: ifindex on %s changed: %u to %u",
		    lif->lif_name, pif->pif_index, lifr.lifr_index);
		return (B_FALSE);
	}

	if (pif->pif_under_ipmp) {
		(void) strlcpy(lifr.lifr_name, pif->pif_grifname, LIFNAMSIZ);

		if (ioctl(fd, SIOCGLIFINDEX, &lifr) == -1) {
			if (errno != ENXIO) {
				dhcpmsg(MSG_ERR, "verify_lif: SIOCGLIFINDEX "
				    "failed on %s", lifr.lifr_name);
			}
			return (B_FALSE);
		}

		if (lifr.lifr_index != pif->pif_grindex) {
			dhcpmsg(MSG_DEBUG, "verify_lif: IPMP group ifindex "
			    "on %s changed: %u to %u", lifr.lifr_name,
			    pif->pif_grindex, lifr.lifr_index);
			return (B_FALSE);
		}
	}

	/*
	 * If the IP address, netmask, or broadcast address have changed, or
	 * the interface has been unplumbed, then we act like there has been an
	 * implicit drop.  (Note that the netmask is under DHCP control for
	 * IPv4, but not for DHCPv6, and that IPv6 doesn't have broadcast
	 * addresses.)
	 */

	if (!checkaddr(lif, SIOCGLIFADDR, &lif->lif_v6addr, "local address"))
		return (B_FALSE);

	if (isv6) {
		/*
		 * If it's not point-to-point, we're done.  If it is, then
		 * check the peer's address as well.
		 */
		return (!(lif->lif_flags & IFF_POINTOPOINT) ||
		    checkaddr(lif, SIOCGLIFDSTADDR, &lif->lif_v6peer,
		    "peer address"));
	} else {
		if (!checkaddr(lif, SIOCGLIFNETMASK, &lif->lif_v6mask,
		    "netmask"))
			return (B_FALSE);

		return (checkaddr(lif,
		    (lif->lif_flags & IFF_POINTOPOINT) ? SIOCGLIFDSTADDR :
		    SIOCGLIFBRDADDR, &lif->lif_v6peer, "peer address"));
	}
}

/*
 * canonize_lif(): puts the interface in a canonical (zeroed) form.  This is
 *		   used only on the "main" LIF for IPv4.  All other interfaces
 *		   are under dhcpagent control and are removed using
 *		   unplumb_lif().
 *
 *   input: dhcp_lif_t *: the interface to canonize
 *	    boolean_t: only canonize lif if it's under DHCP control
 *  output: none
 */

static void
canonize_lif(dhcp_lif_t *lif, boolean_t dhcponly)
{
	boolean_t isv6;
	int fd;
	struct lifreq lifr;

	/*
	 * If there's nothing here, then don't touch the interface.  This can
	 * happen when an already-canonized LIF is recanonized.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&lif->lif_v6addr))
		return;

	isv6 = lif->lif_pif->pif_isv6;
	dhcpmsg(MSG_VERBOSE, "canonizing IPv%d interface %s",
	    isv6 ? 6 : 4, lif->lif_name);

	lif->lif_v6addr = my_in6addr_any;
	lif->lif_v6mask = my_in6addr_any;
	lif->lif_v6peer = my_in6addr_any;

	(void) memset(&lifr, 0, sizeof (struct lifreq));
	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	fd = isv6 ? v6_sock_fd : v4_sock_fd;

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		if (errno != ENXIO) {
			dhcpmsg(MSG_ERR, "canonize_lif: can't get flags for %s",
			    lif->lif_name);
		}
		return;
	}
	lif->lif_flags = lifr.lifr_flags;

	if (dhcponly && !(lifr.lifr_flags & IFF_DHCPRUNNING)) {
		dhcpmsg(MSG_INFO,
		    "canonize_lif: cannot clear %s; flags are %llx",
		    lif->lif_name, lifr.lifr_flags);
		return;
	}

	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	if (isv6) {
		struct sockaddr_in6 *sin6 =
		    (struct sockaddr_in6 *)&lifr.lifr_addr;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = my_in6addr_any;
	} else {
		struct sockaddr_in *sinv =
		    (struct sockaddr_in *)&lifr.lifr_addr;

		sinv->sin_family = AF_INET;
		sinv->sin_addr.s_addr = htonl(INADDR_ANY);
	}

	if (ioctl(fd, SIOCSLIFADDR, &lifr) == -1) {
		dhcpmsg(MSG_ERR,
		    "canonize_lif: can't clear local address on %s",
		    lif->lif_name);
	}

	/* Clearing the address means that we're no longer waiting on DAD */
	if (lif->lif_dad_wait) {
		lif->lif_dad_wait = _B_FALSE;
		lif->lif_lease->dl_smach->dsm_lif_wait--;
	}

	if (lif->lif_flags & IFF_POINTOPOINT) {
		if (ioctl(fd, SIOCSLIFDSTADDR, &lifr) == -1) {
			dhcpmsg(MSG_ERR,
			    "canonize_lif: can't clear remote address on %s",
			    lif->lif_name);
		}
	} else if (!isv6) {
		if (ioctl(fd, SIOCSLIFBRDADDR, &lifr) == -1) {
			dhcpmsg(MSG_ERR,
			    "canonize_lif: can't clear broadcast address on %s",
			    lif->lif_name);
		}
	}

	/*
	 * Clear the netmask last as it has to be refetched after clearing.
	 * Netmask is under in.ndpd control with IPv6.
	 */
	if (!isv6) {
		/* Clear the netmask */
		if (ioctl(fd, SIOCSLIFNETMASK, &lifr) == -1) {
			dhcpmsg(MSG_ERR,
			    "canonize_lif: can't clear netmask on %s",
			    lif->lif_name);
		} else  {
			/*
			 * When the netmask is cleared, the kernel actually sets
			 * the netmask to 255.0.0.0.  So, refetch that netmask.
			 */
			if (ioctl(fd, SIOCGLIFNETMASK, &lifr) == -1) {
				dhcpmsg(MSG_ERR,
				    "canonize_lif: can't reload cleared "
				    "netmask on %s", lif->lif_name);
			} else {
				/* Refetch succeeded, update LIF */
				lif->lif_netmask =
				    ((struct sockaddr_in *)&lifr.lifr_addr)->
				    sin_addr.s_addr;
			}
		}
	}
}

/*
 * plumb_lif(): Adds the LIF to the system.  This is used for all
 *		DHCPv6-derived interfaces.  The returned LIF has a hold
 *		on it.  The caller (configure_v6_leases) deals with the DAD
 *		wait counters.
 *
 *   input: dhcp_lif_t *: the interface to unplumb
 *  output: none
 */

dhcp_lif_t *
plumb_lif(dhcp_pif_t *pif, const in6_addr_t *addr)
{
	dhcp_lif_t *lif;
	char abuf[INET6_ADDRSTRLEN];
	struct lifreq lifr;
	struct sockaddr_in6 *sin6;
	int error;

	(void) inet_ntop(AF_INET6, addr, abuf, sizeof (abuf));

	for (lif = pif->pif_lifs; lif != NULL; lif = lif->lif_next) {
		if (IN6_ARE_ADDR_EQUAL(&lif->lif_v6addr, addr)) {
			dhcpmsg(MSG_ERR,
			    "plumb_lif: entry for %s already exists!", abuf);
			return (NULL);
		}
	}

	/* First, create a new zero-address logical interface */
	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, pif->pif_name, sizeof (lifr.lifr_name));
	if (ioctl(v6_sock_fd, SIOCLIFADDIF, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "plumb_lif: SIOCLIFADDIF %s", pif->pif_name);
		return (NULL);
	}

	/* Next, set the netmask to all ones */
	sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
	sin6->sin6_family = AF_INET6;
	(void) memset(&sin6->sin6_addr, 0xff, sizeof (sin6->sin6_addr));
	if (ioctl(v6_sock_fd, SIOCSLIFNETMASK, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "plumb_lif: SIOCSLIFNETMASK %s",
		    lifr.lifr_name);
		goto failure;
	}

	/* Now set the interface address */
	sin6->sin6_addr = *addr;
	if (ioctl(v6_sock_fd, SIOCSLIFADDR, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "plumb_lif: SIOCSLIFADDR %s %s",
		    lifr.lifr_name, abuf);
		goto failure;
	}

	/* Mark the interface up */
	if (ioctl(v6_sock_fd, SIOCGLIFFLAGS, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "plumb_lif: SIOCGLIFFLAGS %s",
		    lifr.lifr_name);
		goto failure;
	}

	/*
	 * See comment in set_lif_dhcp().
	 */
	if (pif->pif_under_ipmp && !(lifr.lifr_flags & IFF_NOFAILOVER))
		lifr.lifr_flags |= IFF_NOFAILOVER | IFF_DEPRECATED;

	lifr.lifr_flags |= IFF_UP | IFF_DHCPRUNNING;
	if (ioctl(v6_sock_fd, SIOCSLIFFLAGS, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "plumb_lif: SIOCSLIFFLAGS %s",
		    lifr.lifr_name);
		goto failure;
	}

	/* Now we can create the internal LIF structure */
	hold_pif(pif);
	if ((lif = insert_lif(pif, lifr.lifr_name, &error)) == NULL)
		goto failure;

	dhcpmsg(MSG_DEBUG, "plumb_lif: plumbed up %s on %s", abuf,
	    lif->lif_name);
	lif->lif_plumbed = B_TRUE;

	return (lif);

failure:
	if (ioctl(v6_sock_fd, SIOCLIFREMOVEIF, &lifr) == -1 &&
	    errno != ENXIO) {
		dhcpmsg(MSG_ERR, "plumb_lif: SIOCLIFREMOVEIF %s",
		    lifr.lifr_name);
	}
	return (NULL);
}

/*
 * unplumb_lif(): Removes the LIF from dhcpagent and the system.  This is used
 *		  for all interfaces configured by DHCP (those in leases).
 *
 *   input: dhcp_lif_t *: the interface to unplumb
 *  output: none
 */

void
unplumb_lif(dhcp_lif_t *lif)
{
	dhcp_lease_t *dlp;

	/*
	 * If we adjusted the MTU for this interface, put it back now:
	 */
	clear_lif_mtu(lif);

	if (lif->lif_plumbed) {
		struct lifreq lifr;

		(void) memset(&lifr, 0, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, lif->lif_name,
		    sizeof (lifr.lifr_name));

		if (ioctl(v6_sock_fd, SIOCLIFREMOVEIF, &lifr) == -1 &&
		    errno != ENXIO) {
			dhcpmsg(MSG_ERR, "unplumb_lif: SIOCLIFREMOVEIF %s",
			    lif->lif_name);
		}
		lif->lif_plumbed = B_FALSE;
	}

	/*
	 * Special case: if we're "unplumbing" the main LIF for DHCPv4, then
	 * just canonize it and remove it from the lease.  The DAD wait flags
	 * are handled by canonize_lif or by remove_lif.
	 */
	if ((dlp = lif->lif_lease) != NULL && dlp->dl_smach->dsm_lif == lif) {
		canonize_lif(lif, B_TRUE);
		cancel_lif_timers(lif);
		if (lif->lif_declined != NULL) {
			dlp->dl_smach->dsm_lif_down--;
			lif->lif_declined = NULL;
		}
		dlp->dl_nlifs = 0;
		dlp->dl_lifs = NULL;
		lif->lif_lease = NULL;
		release_lif(lif);
	} else {
		remove_lif(lif);
	}
}

/*
 * attach_lif(): create a new logical interface, creating the physical
 *		 interface as necessary.
 *
 *   input: const char *: the logical interface name
 *	    boolean_t: B_TRUE for IPv6
 *	    int *: set to DHCP_IPC_E_* if creation fails
 *  output: dhcp_lif_t *: pointer to new entry, or NULL on failure
 */

dhcp_lif_t *
attach_lif(const char *lname, boolean_t isv6, int *error)
{
	dhcp_pif_t *pif;
	char pname[LIFNAMSIZ], *cp;

	(void) strlcpy(pname, lname, sizeof (pname));
	if ((cp = strchr(pname, ':')) != NULL)
		*cp = '\0';

	if ((pif = lookup_pif_by_name(pname, isv6)) != NULL)
		hold_pif(pif);
	else if ((pif = insert_pif(pname, isv6, error)) == NULL)
		return (NULL);

	if (lookup_lif_by_name(lname, pif) != NULL) {
		dhcpmsg(MSG_ERROR, "attach_lif: entry for %s already exists!",
		    lname);
		release_pif(pif);
		*error = DHCP_IPC_E_INVIF;
		return (NULL);
	}

	/* If LIF creation fails, then insert_lif discards our PIF hold */
	return (insert_lif(pif, lname, error));
}

/*
 * set_lif_dhcp(): Set logical interface flags to show that it's managed
 *		   by DHCP.
 *
 *   input: dhcp_lif_t *: the logical interface
 *  output: int: set to DHCP_IPC_E_* if operation fails
 */

int
set_lif_dhcp(dhcp_lif_t *lif)
{
	int fd;
	int err;
	struct lifreq lifr;
	dhcp_pif_t *pif = lif->lif_pif;

	fd = pif->pif_isv6 ? v6_sock_fd : v4_sock_fd;

	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		err = errno;
		dhcpmsg(MSG_ERR, "set_lif_dhcp: SIOCGLIFFLAGS for %s",
		    lif->lif_name);
		return (err == ENXIO ? DHCP_IPC_E_INVIF : DHCP_IPC_E_INT);
	}
	lif->lif_flags = lifr.lifr_flags;

	/*
	 * Check for conflicting sources of address control, and other
	 * unacceptable configurations.
	 */
	if (lifr.lifr_flags & (IFF_LOOPBACK|IFF_ADDRCONF|IFF_TEMPORARY|
	    IFF_VIRTUAL)) {
		dhcpmsg(MSG_ERR, "set_lif_dhcp: cannot use %s: flags are %llx",
		    lif->lif_name, lifr.lifr_flags);
		return (DHCP_IPC_E_INVIF);
	}

	/*
	 * If IFF_DHCPRUNNING is already set on the interface and we're not
	 * adopting it, the agent probably crashed and burned.  Note it, but
	 * don't let it stop the proceedings (we're pretty sure we're not
	 * already running, since we were able to bind to our IPC port).
	 */
	if (lifr.lifr_flags & IFF_DHCPRUNNING) {
		dhcpmsg(MSG_VERBOSE, "set_lif_dhcp: IFF_DHCPRUNNING already set"
		    " on %s", lif->lif_name);
	} else {
		/*
		 * If the lif is on an interface under IPMP, IFF_NOFAILOVER
		 * must be set or the kernel will prevent us from setting
		 * IFF_DHCPRUNNING (since the subsequent IFF_UP would lead to
		 * migration).  We set IFF_DEPRECATED too since the kernel
		 * will set it automatically when setting IFF_NOFAILOVER,
		 * causing our lif_flags value to grow stale.
		 */
		if (pif->pif_under_ipmp && !(lifr.lifr_flags & IFF_NOFAILOVER))
			lifr.lifr_flags |= IFF_NOFAILOVER | IFF_DEPRECATED;

		lifr.lifr_flags |= IFF_DHCPRUNNING;
		if (ioctl(fd, SIOCSLIFFLAGS, &lifr) == -1) {
			dhcpmsg(MSG_ERR, "set_lif_dhcp: SIOCSLIFFLAGS for %s",
			    lif->lif_name);
			return (DHCP_IPC_E_INT);
		}
		lif->lif_flags = lifr.lifr_flags;
	}
	return (DHCP_IPC_SUCCESS);
}

/*
 * clear_lif_dhcp(): Clear logical interface flags to show that it's no longer
 *		     managed by DHCP.
 *
 *   input: dhcp_lif_t *: the logical interface
 *  output: none
 */

static void
clear_lif_dhcp(dhcp_lif_t *lif)
{
	int fd;
	struct lifreq lifr;

	fd = lif->lif_pif->pif_isv6 ? v6_sock_fd : v4_sock_fd;

	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1)
		return;

	if (!(lifr.lifr_flags & IFF_DHCPRUNNING))
		return;

	lif->lif_flags = lifr.lifr_flags &= ~IFF_DHCPRUNNING;
	(void) ioctl(fd, SIOCSLIFFLAGS, &lifr);
}

static void
update_pif_mtu(dhcp_pif_t *pif)
{
	/*
	 * Find the smallest requested MTU, if any, for the logical interfaces
	 * on this physical interface:
	 */
	uint_t mtu = 0;
	for (dhcp_lif_t *lif = pif->pif_lifs; lif != NULL;
	    lif = lif->lif_next) {
		if (lif->lif_mtu == 0) {
			/*
			 * This logical interface has not requested a specific
			 * MTU.
			 */
			continue;
		}

		if (mtu == 0 || mtu > lif->lif_mtu) {
			mtu = lif->lif_mtu;
		}
	}

	if (mtu == 0) {
		/*
		 * There are no remaining requests for a specific MTU.  Return
		 * the interface to its original MTU.
		 */
		dhcpmsg(MSG_DEBUG2, "update_pif_mtu: restoring %s MTU to "
		    "original %u", pif->pif_name, pif->pif_mtu_orig);
		mtu = pif->pif_mtu_orig;
	}

	if (pif->pif_mtu == mtu) {
		/*
		 * The MTU is already correct.
		 */
		dhcpmsg(MSG_DEBUG2, "update_pif_mtu: %s MTU is already %u",
		    pif->pif_name, mtu);
		return;
	}

	dhcpmsg(MSG_DEBUG, "update_pif_mtu: %s MTU change: %u -> %u",
	    pif->pif_name, pif->pif_mtu, mtu);

	struct lifreq lifr;
	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, pif->pif_name, LIFNAMSIZ);
	lifr.lifr_mtu = mtu;

	int fd = pif->pif_isv6 ? v6_sock_fd : v4_sock_fd;
	if (ioctl(fd, SIOCSLIFMTU, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "update_pif_mtu: SIOCSLIFMTU (%u) failed "
		    "for %s", mtu, pif->pif_name);
		return;
	}

	pif->pif_mtu = mtu;
}

void
set_lif_mtu(dhcp_lif_t *lif, uint_t mtu)
{
	dhcpmsg(MSG_DEBUG, "set_lif_mtu: %s requests MTU %u", lif->lif_name,
	    mtu);

	lif->lif_mtu = mtu;
	update_pif_mtu(lif->lif_pif);
}

void
clear_lif_mtu(dhcp_lif_t *lif)
{
	if (lif->lif_mtu != 0) {
		dhcpmsg(MSG_DEBUG, "clear_lif_mtu: %s clears MTU request",
		    lif->lif_name);
	}

	/*
	 * Remove our prior request and update the physical interface.
	 */
	lif->lif_mtu = 0;
	update_pif_mtu(lif->lif_pif);
}

/*
 * set_lif_deprecated(): Set the "deprecated" flag to tell users that this
 *			 address will be going away.  As the interface is
 *			 going away, we don't care if there are errors.
 *
 *   input: dhcp_lif_t *: the logical interface
 *  output: none
 */

void
set_lif_deprecated(dhcp_lif_t *lif)
{
	int fd;
	struct lifreq lifr;

	if (lif->lif_flags & IFF_DEPRECATED)
		return;

	fd = lif->lif_pif->pif_isv6 ? v6_sock_fd : v4_sock_fd;

	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1)
		return;

	if (lifr.lifr_flags & IFF_DEPRECATED)
		return;

	lifr.lifr_flags |= IFF_DEPRECATED;
	(void) ioctl(fd, SIOCSLIFFLAGS, &lifr);
	lif->lif_flags = lifr.lifr_flags;
}

/*
 * clear_lif_deprecated(): Clear the "deprecated" flag to tell users that this
 *			   address will not be going away.  This happens if we
 *			   get a renewal after preferred lifetime but before
 *			   the valid lifetime.
 *
 *   input: dhcp_lif_t *: the logical interface
 *  output: boolean_t: B_TRUE on success.
 */

boolean_t
clear_lif_deprecated(dhcp_lif_t *lif)
{
	int fd;
	struct lifreq lifr;

	fd = lif->lif_pif->pif_isv6 ? v6_sock_fd : v4_sock_fd;

	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "clear_lif_deprecated: SIOCGLIFFLAGS for %s",
		    lif->lif_name);
		return (B_FALSE);
	}

	/*
	 * Check for conflicting sources of address control, and other
	 * unacceptable configurations.
	 */
	if (lifr.lifr_flags & (IFF_LOOPBACK|IFF_ADDRCONF|IFF_TEMPORARY|
	    IFF_VIRTUAL)) {
		dhcpmsg(MSG_ERR, "clear_lif_deprecated: cannot use %s: flags "
		    "are %llx", lif->lif_name, lifr.lifr_flags);
		return (B_FALSE);
	}

	/*
	 * Don't try to clear IFF_DEPRECATED if this is a test address,
	 * since IPMP's use of IFF_DEPRECATED is not compatible with ours.
	 */
	if (lifr.lifr_flags & IFF_NOFAILOVER)
		return (B_TRUE);

	if (!(lifr.lifr_flags & IFF_DEPRECATED))
		return (B_TRUE);

	lifr.lifr_flags &= ~IFF_DEPRECATED;
	if (ioctl(fd, SIOCSLIFFLAGS, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "clear_lif_deprecated: SIOCSLIFFLAGS for %s",
		    lif->lif_name);
		return (B_FALSE);
	} else {
		lif->lif_flags = lifr.lifr_flags;
		return (B_TRUE);
	}
}

/*
 * open_ip_lif(): open up an IP socket for I/O on a given LIF (v4 only).
 *
 *   input: dhcp_lif_t *: the logical interface to operate on
 *	    in_addr_t: the address the socket will be bound to (in hbo)
 *	    boolean_t: B_TRUE if the address should be brought up (if needed)
 *  output: boolean_t: B_TRUE if the socket was opened successfully.
 */

boolean_t
open_ip_lif(dhcp_lif_t *lif, in_addr_t addr_hbo, boolean_t bringup)
{
	const char *errmsg;
	struct lifreq lifr;
	int on = 1;
	uchar_t ttl = 255;
	uint32_t ifindex;
	dhcp_pif_t *pif = lif->lif_pif;

	if (lif->lif_sock_ip_fd != -1) {
		dhcpmsg(MSG_WARNING, "open_ip_lif: socket already open on %s",
		    lif->lif_name);
		return (B_FALSE);
	}

	lif->lif_sock_ip_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (lif->lif_sock_ip_fd == -1) {
		errmsg = "cannot create v4 socket";
		goto failure;
	}

	if (!bind_sock(lif->lif_sock_ip_fd, IPPORT_BOOTPC, addr_hbo)) {
		errmsg = "cannot bind v4 socket";
		goto failure;
	}

	/*
	 * If we bound to INADDR_ANY, we have no IFF_UP source address to use.
	 * Thus, enable IP_UNSPEC_SRC so that we can send packets with an
	 * unspecified (0.0.0.0) address.  Also, enable IP_DHCPINIT_IF so that
	 * the IP module will accept unicast DHCP traffic regardless of the IP
	 * address it's sent to.  (We'll then figure out which packets are
	 * ours based on the xid.)
	 */
	if (addr_hbo == INADDR_ANY) {
		if (setsockopt(lif->lif_sock_ip_fd, IPPROTO_IP, IP_UNSPEC_SRC,
		    &on, sizeof (int)) == -1) {
			errmsg = "cannot set IP_UNSPEC_SRC";
			goto failure;
		}

		if (setsockopt(lif->lif_sock_ip_fd, IPPROTO_IP, IP_DHCPINIT_IF,
		    &pif->pif_index, sizeof (int)) == -1) {
			errmsg = "cannot set IP_DHCPINIT_IF";
			goto failure;
		}
	}

	/*
	 * Unfortunately, some hardware (such as the Linksys WRT54GC)
	 * decrements the TTL *prior* to accepting DHCP traffic destined
	 * for it.  To workaround this, tell IP to use a TTL of 255 for
	 * broadcast packets sent from this socket.
	 */
	if (setsockopt(lif->lif_sock_ip_fd, IPPROTO_IP, IP_BROADCAST_TTL, &ttl,
	    sizeof (uchar_t)) == -1) {
		errmsg = "cannot set IP_BROADCAST_TTL";
		goto failure;
	}

	ifindex = pif->pif_under_ipmp ? pif->pif_grindex : pif->pif_index;
	if (setsockopt(lif->lif_sock_ip_fd, IPPROTO_IP, IP_BOUND_IF, &ifindex,
	    sizeof (int)) == -1) {
		errmsg = "cannot set IP_BOUND_IF";
		goto failure;
	}

	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);
	if (ioctl(v4_sock_fd, SIOCGLIFFLAGS, &lifr) == -1) {
		errmsg = "cannot get interface flags";
		goto failure;
	}

	/*
	 * If the lif is part of an interface under IPMP, IFF_NOFAILOVER must
	 * be set or the kernel will prevent us from setting IFF_DHCPRUNNING
	 * (since the subsequent IFF_UP would lead to migration).  We set
	 * IFF_DEPRECATED too since the kernel will set it automatically when
	 * setting IFF_NOFAILOVER, causing our lif_flags value to grow stale.
	 */
	if (pif->pif_under_ipmp && !(lifr.lifr_flags & IFF_NOFAILOVER)) {
		lifr.lifr_flags |= IFF_NOFAILOVER | IFF_DEPRECATED;
		if (ioctl(v4_sock_fd, SIOCSLIFFLAGS, &lifr) == -1) {
			errmsg = "cannot set IFF_NOFAILOVER";
			goto failure;
		}
	}
	lif->lif_flags = lifr.lifr_flags;

	/*
	 * If this is initial bringup, make sure the address we're acquiring a
	 * lease on is IFF_UP.
	 */
	if (bringup && !(lifr.lifr_flags & IFF_UP)) {
		/*
		 * Start from a clean slate.
		 */
		canonize_lif(lif, B_FALSE);

		lifr.lifr_flags |= IFF_UP;
		if (ioctl(v4_sock_fd, SIOCSLIFFLAGS, &lifr) == -1) {
			errmsg = "cannot bring up";
			goto failure;
		}
		lif->lif_flags = lifr.lifr_flags;

		/*
		 * When bringing 0.0.0.0 IFF_UP, the kernel changes the
		 * netmask to 255.0.0.0, so re-fetch our expected netmask.
		 */
		if (ioctl(v4_sock_fd, SIOCGLIFNETMASK, &lifr) == -1) {
			errmsg = "cannot get netmask";
			goto failure;
		}

		lif->lif_netmask =
		    ((struct sockaddr_in *)&lifr.lifr_addr)->sin_addr.s_addr;
	}

	/*
	 * Usually, bringing up the address we're acquiring a lease on is
	 * sufficient to allow packets to be sent and received via the
	 * IP_BOUND_IF we did earlier.  However, if we're acquiring a lease on
	 * an underlying IPMP interface, the group interface will be used for
	 * sending and receiving IP packets via IP_BOUND_IF.  Thus, ensure at
	 * least one address on the group interface is IFF_UP.
	 */
	if (bringup && pif->pif_under_ipmp) {
		(void) strlcpy(lifr.lifr_name, pif->pif_grifname, LIFNAMSIZ);
		if (ioctl(v4_sock_fd, SIOCGLIFFLAGS, &lifr) == -1) {
			errmsg = "cannot get IPMP group interface flags";
			goto failure;
		}

		if (!(lifr.lifr_flags & IFF_UP)) {
			lifr.lifr_flags |= IFF_UP;
			if (ioctl(v4_sock_fd, SIOCSLIFFLAGS, &lifr) == -1) {
				errmsg = "cannot bring up IPMP group interface";
				goto failure;
			}
		}
	}

	lif->lif_packet_id = iu_register_event(eh, lif->lif_sock_ip_fd, POLLIN,
	    dhcp_packet_lif, lif);
	if (lif->lif_packet_id == -1) {
		errmsg = "cannot register to receive DHCP packets";
		goto failure;
	}

	return (B_TRUE);
failure:
	dhcpmsg(MSG_ERR, "open_ip_lif: %s: %s", lif->lif_name, errmsg);
	close_ip_lif(lif);
	return (B_FALSE);
}

/*
 * close_ip_lif(): close an IP socket for I/O on a given LIF.
 *
 *   input: dhcp_lif_t *: the logical interface to operate on
 *  output: none
 */

void
close_ip_lif(dhcp_lif_t *lif)
{
	if (lif->lif_packet_id != -1) {
		(void) iu_unregister_event(eh, lif->lif_packet_id, NULL);
		lif->lif_packet_id = -1;
	}
	if (lif->lif_sock_ip_fd != -1) {
		(void) close(lif->lif_sock_ip_fd);
		lif->lif_sock_ip_fd = -1;
	}
}

/*
 * lif_mark_decline(): mark a LIF as having been declined due to a duplicate
 *		       address or some other conflict.  This is used in
 *		       send_declines() to report failure back to the server.
 *
 *   input: dhcp_lif_t *: the logical interface to operate on
 *	    const char *: text string explaining why the address is declined
 *  output: none
 */

void
lif_mark_decline(dhcp_lif_t *lif, const char *reason)
{
	if (lif->lif_declined == NULL) {
		dhcp_lease_t *dlp;

		lif->lif_declined = reason;
		if ((dlp = lif->lif_lease) != NULL)
			dlp->dl_smach->dsm_lif_down++;
	}
}

/*
 * schedule_lif_timer(): schedules the LIF-related timer
 *
 *   input: dhcp_lif_t *: the logical interface to operate on
 *	    dhcp_timer_t *: the timer to schedule
 *	    iu_tq_callback_t *: the callback to call upon firing
 *  output: boolean_t: B_TRUE if the timer was scheduled successfully
 */

boolean_t
schedule_lif_timer(dhcp_lif_t *lif, dhcp_timer_t *dt, iu_tq_callback_t *expire)
{
	/*
	 * If there's a timer running, cancel it and release its lease
	 * reference.
	 */
	if (dt->dt_id != -1) {
		if (!cancel_timer(dt))
			return (B_FALSE);
		release_lif(lif);
	}

	if (schedule_timer(dt, expire, lif)) {
		hold_lif(lif);
		return (B_TRUE);
	} else {
		dhcpmsg(MSG_WARNING,
		    "schedule_lif_timer: cannot schedule timer");
		return (B_FALSE);
	}
}

/*
 * cancel_lif_timer(): cancels a LIF-related timer
 *
 *   input: dhcp_lif_t *: the logical interface to operate on
 *	    dhcp_timer_t *: the timer to cancel
 *  output: none
 */

static void
cancel_lif_timer(dhcp_lif_t *lif, dhcp_timer_t *dt)
{
	if (dt->dt_id == -1)
		return;
	if (cancel_timer(dt)) {
		dhcpmsg(MSG_DEBUG2,
		    "cancel_lif_timer: canceled expiry timer on %s",
		    lif->lif_name);
		release_lif(lif);
	} else {
		dhcpmsg(MSG_WARNING,
		    "cancel_lif_timer: cannot cancel timer on %s",
		    lif->lif_name);
	}
}

/*
 * cancel_lif_timers(): cancels the LIF-related timers
 *
 *   input: dhcp_lif_t *: the logical interface to operate on
 *  output: none
 */

void
cancel_lif_timers(dhcp_lif_t *lif)
{
	cancel_lif_timer(lif, &lif->lif_preferred);
	cancel_lif_timer(lif, &lif->lif_expire);
}

/*
 * get_max_mtu(): find the maximum MTU of all interfaces for I/O on common
 *		  file descriptors (v4_sock_fd and v6_sock_fd).
 *
 *   input: boolean_t: B_TRUE for IPv6, B_FALSE for IPv4
 *  output: none
 */

uint_t
get_max_mtu(boolean_t isv6)
{
	uint_t *mtup = isv6 ? &cached_v6_max_mtu : &cached_v4_max_mtu;

	if (*mtup == 0) {
		dhcp_pif_t *pif;
		dhcp_lif_t *lif;
		struct lifreq lifr;

		/* Set an arbitrary lower bound */
		*mtup = 1024;
		pif = isv6 ? v6root : v4root;
		for (; pif != NULL; pif = pif->pif_next) {
			for (lif = pif->pif_lifs; lif != NULL;
			    lif = lif->lif_next) {
				(void) strlcpy(lifr.lifr_name, lif->lif_name,
				    LIFNAMSIZ);
				if (ioctl(v4_sock_fd, SIOCGLIFMTU, &lifr) !=
				    -1 && lifr.lifr_mtu > *mtup) {
					*mtup = lifr.lifr_mtu;
				}
			}
		}
	}
	return (*mtup);
}

/*
 * expired_lif_state(): summarize the state of expired LIFs on a given state
 *			machine.
 *
 *   input: dhcp_smach_t *: the state machine to scan
 *  output: dhcp_expire_t: overall state
 */

dhcp_expire_t
expired_lif_state(dhcp_smach_t *dsmp)
{
	dhcp_lease_t *dlp;
	dhcp_lif_t *lif;
	uint_t nlifs;
	uint_t numlifs;
	uint_t numexp;

	numlifs = numexp = 0;
	for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next) {
		lif = dlp->dl_lifs;
		nlifs = dlp->dl_nlifs;
		numlifs += nlifs;
		for (; nlifs > 0; nlifs--, lif = lif->lif_next) {
			if (lif->lif_expired)
				numexp++;
		}
	}
	if (numlifs == 0)
		return (DHCP_EXP_NOLIFS);
	else if (numexp == 0)
		return (DHCP_EXP_NOEXP);
	else if (numlifs == numexp)
		return (DHCP_EXP_ALLEXP);
	else
		return (DHCP_EXP_SOMEEXP);
}

/*
 * find_expired_lif(): find the first expired LIF on a given state machine
 *
 *   input: dhcp_smach_t *: the state machine to scan
 *  output: dhcp_lif_t *: the first expired LIF, or NULL if none.
 */

dhcp_lif_t *
find_expired_lif(dhcp_smach_t *dsmp)
{
	dhcp_lease_t *dlp;
	dhcp_lif_t *lif;
	uint_t nlifs;

	for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next) {
		lif = dlp->dl_lifs;
		nlifs = dlp->dl_nlifs;
		for (; nlifs > 0; nlifs--, lif = lif->lif_next) {
			if (lif->lif_expired)
				return (lif);
		}
	}
	return (NULL);
}

/*
 * remove_v6_strays(): remove any stray interfaces marked as DHCPRUNNING.  Used
 *		       only for DHCPv6.
 *
 *   input: none
 *  output: none
 */

void
remove_v6_strays(void)
{
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifrp, *lifrmax;
	uint_t numifs;
	uint64_t flags;

	/*
	 * Get the approximate number of interfaces in the system.  It's only
	 * approximate because the system is dynamic -- interfaces may be
	 * plumbed or unplumbed at any time.  This is also the reason for the
	 * "+ 10" fudge factor: we're trying to avoid unnecessary looping.
	 */
	(void) memset(&lifn, 0, sizeof (lifn));
	lifn.lifn_family = AF_INET6;
	lifn.lifn_flags = LIFC_ALLZONES | LIFC_NOXMIT | LIFC_TEMPORARY;
	if (ioctl(v6_sock_fd, SIOCGLIFNUM, &lifn) == -1) {
		dhcpmsg(MSG_ERR,
		    "remove_v6_strays: cannot read number of interfaces");
		numifs = 10;
	} else {
		numifs = lifn.lifn_count + 10;
	}

	/*
	 * Get the interface information.  We do this in a loop so that we can
	 * recover from EINVAL from the kernel -- delivered when the buffer is
	 * too small.
	 */
	(void) memset(&lifc, 0, sizeof (lifc));
	lifc.lifc_family = AF_INET6;
	lifc.lifc_flags = LIFC_ALLZONES | LIFC_NOXMIT | LIFC_TEMPORARY;
	for (;;) {
		lifc.lifc_len = numifs * sizeof (*lifrp);
		lifrp = realloc(lifc.lifc_buf, lifc.lifc_len);
		if (lifrp == NULL) {
			dhcpmsg(MSG_ERR,
			    "remove_v6_strays: cannot allocate memory");
			free(lifc.lifc_buf);
			return;
		}
		lifc.lifc_buf = (caddr_t)lifrp;
		errno = 0;
		if (ioctl(v6_sock_fd, SIOCGLIFCONF, &lifc) == 0 &&
		    lifc.lifc_len < numifs * sizeof (*lifrp))
			break;
		if (errno == 0 || errno == EINVAL) {
			numifs <<= 1;
		} else {
			dhcpmsg(MSG_ERR, "remove_v6_strays: SIOCGLIFCONF");
			free(lifc.lifc_buf);
			return;
		}
	}

	lifrmax = lifrp + lifc.lifc_len / sizeof (*lifrp);
	for (; lifrp < lifrmax; lifrp++) {
		/*
		 * Get the interface flags; we're interested in the DHCP ones.
		 */
		if (ioctl(v6_sock_fd, SIOCGLIFFLAGS, lifrp) == -1)
			continue;
		flags = lifrp->lifr_flags;
		if (!(flags & IFF_DHCPRUNNING))
			continue;
		/*
		 * If the interface has a link-local address, then we don't
		 * control it.  Just remove the flag.
		 */
		if (ioctl(v6_sock_fd, SIOCGLIFADDR, lifrp) == -1)
			continue;
		if (IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)&lifrp->
		    lifr_addr)->sin6_addr)) {
			lifrp->lifr_flags = flags & ~IFF_DHCPRUNNING;
			(void) ioctl(v6_sock_fd, SIOCSLIFFLAGS, lifrp);
			continue;
		}
		/*
		 * All others are (or were) under our control.  Clean up by
		 * removing them.
		 */
		if (ioctl(v6_sock_fd, SIOCLIFREMOVEIF, lifrp) == 0) {
			dhcpmsg(MSG_DEBUG, "remove_v6_strays: removed %s",
			    lifrp->lifr_name);
		} else if (errno != ENXIO) {
			dhcpmsg(MSG_ERR,
			    "remove_v6_strays: SIOCLIFREMOVEIF %s",
			    lifrp->lifr_name);
		}
	}
	free(lifc.lifc_buf);
}
