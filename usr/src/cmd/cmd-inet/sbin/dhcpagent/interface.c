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

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/dlpi.h>
#include <stdlib.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <dhcpmsg.h>
#include <libdevinfo.h>

#include "interface.h"
#include "util.h"
#include "dlpi_io.h"
#include "packet.h"
#include "defaults.h"
#include "states.h"
#include "script_handler.h"

/*
 * note to the reader:
 *
 * the terminology in here is slightly confusing.  in particular, the
 * term `ifslist' is used to refer both to the `struct ifslist' entry
 * that makes up a specific interface entry, and the `internal
 * ifslist' which is a linked list of struct ifslists.  to reduce
 * confusion, in the comments, a `struct ifslist' is referred to as
 * an `ifs', and `ifslist' refers to the internal ifslist.
 *
 */

static struct ifslist	*ifsheadp;
static unsigned int	ifscount;

static void	init_ifs(struct ifslist *);
static void	free_ifs(struct ifslist *);
static void	cancel_ifs_timer(struct ifslist *, int);

static boolean_t	get_prom_prop(const char *, const char *, uchar_t **,
			    unsigned int *);

/*
 * insert_ifs(): creates a new ifs and chains it on the ifslist.  initializes
 *		 state which remains consistent across all use of the ifs entry
 *
 *   input: const char *: the name of the ifs entry (interface name)
 *	    boolean_t: if B_TRUE, we're adopting the interface
 *	    int *: ignored on input; if insert_ifs fails, set to a DHCP_IPC_E_*
 *		   error code with the reason why
 *  output: struct ifslist *: a pointer to the new ifs entry, or NULL on failure
 */

struct ifslist *
insert_ifs(const char *if_name, boolean_t is_adopting, int *error)
{
	uint32_t		buf[DLPI_BUF_MAX / sizeof (uint32_t)];
	dl_info_ack_t		*dlia = (dl_info_ack_t *)buf;
	caddr_t			dl_addr;
	struct ifreq    	ifr;
	unsigned int		i, client_id_len = 0;
	uchar_t			*client_id = NULL;
	const char		*prl;
	struct ifslist		*ifsp;
	long			seed;

	ifsp = lookup_ifs(if_name);
	if (ifsp != NULL) {
		*error = DHCP_IPC_E_INT;	/* should never happen */
		return (NULL);
	}

	/*
	 * okay, we've got a request to put a new interface under our
	 * control.  it's our job to set everything that doesn't
	 * change for the life of the interface.  (state that changes
	 * should be initialized in init_ifs() and reset by reset_ifs())
	 *
	 *  1. verify the interface can support DHCP
	 *  2. get the interface mtu
	 *  3. get the interface hardware type and hardware length
	 *  4. get the interface hardware address
	 *  5. get the interface broadcast address
	 *  6. get the interface flags
	 */

	ifsp = calloc(1, sizeof (struct ifslist));
	if (ifsp == NULL) {
		dhcpmsg(MSG_ERR, "insert_ifs: cannot allocate ifs entry for "
		    "%s", if_name);
		*error = DHCP_IPC_E_MEMORY;
		return (NULL);
	}

	(void) strlcpy(ifsp->if_name, if_name, IFNAMSIZ);

	/* step 1 */
	ifsp->if_dlpi_fd = dlpi_open(if_name, dlia, sizeof (buf), ETHERTYPE_IP);
	if (ifsp->if_dlpi_fd == -1) {
		*error = DHCP_IPC_E_INVIF;
		goto failure;
	}

	init_ifs(ifsp);			/* ifsp->if_dlpi_fd must be valid */
	ipc_action_init(ifsp);

	/* step 2 */
	ifsp->if_max = dlia->dl_max_sdu;
	ifsp->if_opt = ifsp->if_max - BASE_PKT_SIZE;
	ifsp->if_min = dlia->dl_min_sdu;

	if (ifsp->if_max < DHCP_DEF_MAX_SIZE) {
		dhcpmsg(MSG_ERROR, "insert_ifs: %s does not have a large "
		    "enough maximum SDU to support DHCP", if_name);
		*error = DHCP_IPC_E_INVIF;
		goto failure;
	}

	/* step 3 */
	ifsp->if_hwtype = dlpi_to_arp(dlia->dl_mac_type);
	ifsp->if_hwlen  = dlia->dl_addr_length - abs(dlia->dl_sap_length);

	dhcpmsg(MSG_DEBUG, "insert_ifs: %s: sdumax %d, optmax %d, hwtype %d, "
	    "hwlen %d", if_name, ifsp->if_max, ifsp->if_opt, ifsp->if_hwtype,
	    ifsp->if_hwlen);

	/* step 4 */
	ifsp->if_hwaddr = malloc(ifsp->if_hwlen);
	if (ifsp->if_hwaddr == NULL) {
		dhcpmsg(MSG_ERR, "insert_ifs: cannot allocate if_hwaddr "
		    "for %s", if_name);
		*error = DHCP_IPC_E_MEMORY;
		goto failure;
	}

	/*
	 * depending on the DLPI device, the sap and hardware addresses
	 * can be in either order within the dlsap address; find the
	 * location of the hardware address using dl_sap_length.  see the
	 * DLPI specification for more on this braindamage.
	 */

	dl_addr = (caddr_t)dlia + dlia->dl_addr_offset;
	if (dlia->dl_sap_length > 0) {
		ifsp->if_sap_before++;
		dl_addr += dlia->dl_sap_length;
	}

	(void) memcpy(ifsp->if_hwaddr, dl_addr, ifsp->if_hwlen);

	/* step 5 */
	ifsp->if_saplen = abs(dlia->dl_sap_length);
	ifsp->if_daddr  = build_broadcast_dest(dlia, &ifsp->if_dlen);
	if (ifsp->if_daddr == NULL) {
		dhcpmsg(MSG_ERR, "insert_ifs: cannot allocate if_daddr "
		    "for %s", if_name);
		*error = DHCP_IPC_E_MEMORY;
		goto failure;
	}

	/* step 6 */
	(void) strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);

	if (ioctl(ifsp->if_sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
		if (errno == ENXIO)
			*error = DHCP_IPC_E_INVIF;
		else
			*error = DHCP_IPC_E_INT;
		dhcpmsg(MSG_ERR, "insert_ifs: SIOCGIFFLAGS for %s", if_name);
		goto failure;
	}

	/*
	 * if DHCPRUNNING is already set on the interface and we're
	 * not adopting it, the agent probably crashed and burned.
	 * note it, but don't let it stop the proceedings.  we're
	 * pretty sure we're not already running, since we wouldn't
	 * have been able to bind to our IPC port.
	 */

	if ((is_adopting == B_FALSE) && (ifr.ifr_flags & IFF_DHCPRUNNING))
		dhcpmsg(MSG_WARNING, "insert_ifs: DHCP flag already set on %s",
		    if_name);

	ifr.ifr_flags |= IFF_DHCPRUNNING;
	(void) ioctl(ifsp->if_sock_fd, SIOCSIFFLAGS, &ifr);

	ifsp->if_send_pkt.pkt = calloc(ifsp->if_max, 1);
	if (ifsp->if_send_pkt.pkt == NULL) {
		dhcpmsg(MSG_ERR, "insert_ifs: cannot allocate if_send_pkt "
		    "for %s", if_name);
		*error = DHCP_IPC_E_MEMORY;
		goto failure;
	}

	if (is_adopting) {
		/*
		 * if the agent is adopting a lease OBP is initially
		 * searched for a client-id
		 */

		dhcpmsg(MSG_DEBUG, "insert_ifs: getting /chosen:clientid "
		    "property");

		if (!get_prom_prop("chosen", "client-id", &ifsp->if_cid,
		    &client_id_len)) {
			/*
			 * a failure occurred trying to acquire the client-id
			 */

			dhcpmsg(MSG_DEBUG, "insert_ifs: cannot allocate client "
			    "id for %s", if_name);
			*error = DHCP_IPC_E_INT;
			goto failure;
		} else if (dlia->dl_mac_type == DL_IB && ifsp->if_cid == NULL) {
			/*
			 * when the interface is infiniband and the agent
			 * is adopting the lease there must be an OBP
			 * client-id.
			 */

			dhcpmsg(MSG_DEBUG, "insert_ifs: no /chosen:clientid"
			    "id for %s", if_name);
			*error = DHCP_IPC_E_INT;
			goto failure;
		}

		ifsp->if_cidlen = client_id_len;
	} else {
		/*
		 * look in defaults file for the client-id
		 */

		dhcpmsg(MSG_DEBUG, "insert_ifs: getting defaults client-id "
		    "property");

		client_id = df_get_octet(if_name, DF_CLIENT_ID, &client_id_len);

		/*
		 * at this point, all logical interfaces must be explicitly
		 * configured with a client id by the administrator.
		 */

		if (client_id == NULL && strchr(if_name, ':') != NULL) {
			dhcpmsg(MSG_ERROR, "no client id configured for "
			    "logical interface %s; cannot manage", if_name);
			*error = DHCP_IPC_E_NOIFCID;
			goto failure;
		}

		if (client_id != NULL) {
			/*
			 * the defaults client-id value must be copied out to
			 * another buffer
			 */

			ifsp->if_cid = calloc(client_id_len, sizeof (uchar_t));

			if (ifsp->if_cid == NULL) {
				dhcpmsg(MSG_ERR, "insert_ifs: cannot "
				    "allocate client id for %s", if_name);
				*error = DHCP_IPC_E_MEMORY;
				goto failure;
			}

			(void) memcpy(ifsp->if_cid, client_id, client_id_len);

			ifsp->if_cidlen = client_id_len;
		} else if (dlia->dl_mac_type == DL_IB) {
			/*
			 * This comes from DHCP over IPoIB spec. In the absence
			 * of an user specified client id, IPoIB automatically
			 * uses the required format, with the unique 4 octet
			 * value set to 0 (since IPoIB driver allows only a
			 * single interface on a port with a specific GID to
			 * belong to an IP subnet (PSARC 2001/289,
			 * FWARC 2002/702).
			 *
			 *   Type  Client-Identifier
			 * +-----+-----+-----+-----+-----+----....----+
			 * |  0  |  0 (4 octets)   |   GID (16 octets)|
			 * +-----+-----+-----+-----+-----+----....----+
			 */
			ifsp->if_cidlen = 1 + 4 + 16;
			ifsp->if_cid = client_id = malloc(ifsp->if_cidlen);
			if (ifsp->if_cid == NULL) {
				dhcpmsg(MSG_ERR, "insert_ifs: cannot "
				    "allocate client id for %s", if_name);
				*error = DHCP_IPC_E_MEMORY;
				goto failure;
			}

			/*
			 * Pick the GID from the mac address. The format
			 * of the hardware address is:
			 * +-----+-----+-----+-----+----....----+
			 * | QPN (4 octets)  |   GID (16 octets)|
			 * +-----+-----+-----+-----+----....----+
			 */
			(void) memcpy(client_id + 5, ifsp->if_hwaddr + 4,
			    ifsp->if_hwlen - 4);
			(void) memset(client_id, 0, 5);
		}
	}

	/*
	 * initialize the parameter request list, if there is one.
	 */

	prl = df_get_string(if_name, DF_PARAM_REQUEST_LIST);
	if (prl == NULL)
		ifsp->if_prl = NULL;
	else {
		for (ifsp->if_prllen = 1, i = 0; prl[i] != '\0'; i++)
			if (prl[i] == ',')
				ifsp->if_prllen++;

		ifsp->if_prl = malloc(ifsp->if_prllen);
		if (ifsp->if_prl == NULL) {
			dhcpmsg(MSG_WARNING, "insert_ifs: cannot allocate "
			    "parameter request list for %s (continuing)",
			    if_name);
		} else {
			for (i = 0; i < ifsp->if_prllen; prl++, i++) {
				ifsp->if_prl[i] = strtoul(prl, NULL, 0);
				while (*prl != ',' && *prl != '\0')
					prl++;
				if (*prl == '\0')
					break;
			}
		}
	}

	ifsp->if_offer_wait = df_get_int(if_name, DF_OFFER_WAIT);

	/*
	 * we're past the point of failure; chain it on.
	 */

	ifsp->next	= ifsheadp;
	ifsp->prev	= NULL;
	ifsheadp	= ifsp;

	if (ifsheadp->next != NULL)
		ifsheadp->next->prev = ifsheadp;

	hold_ifs(ifsp);
	ifscount++;

	if (inactivity_id != -1) {
		if (iu_cancel_timer(tq, inactivity_id, NULL) == 1)
			inactivity_id = -1;
	}

	/*
	 * seed the random number generator, since we're going to need it
	 * to set transaction id's and for exponential backoff.  if an
	 * interface is already initialized, then we just end up harmlessly
	 * reseeding it.  note that we try to spread the hardware address
	 * over as many bits of the seed as possible.
	 */
	seed = gethrtime();
	for (i = 0; i < ifsp->if_hwlen; i++)
		seed += ifsp->if_hwaddr[i] << ((i % 7) * 4);
	seed ^= getpid();
	srand48(seed);

	dhcpmsg(MSG_DEBUG, "insert_ifs: inserted interface %s", if_name);
	return (ifsp);

failure:
	free_ifs(ifsp);
	return (NULL);
}

/*
 * init_ifs(): puts an ifs in its initial state
 *
 *   input: struct ifslist *: the ifs to initialize
 *  output: void
 *    note: if the interface isn't fresh, use reset_ifs()
 */

static void
init_ifs(struct ifslist *ifsp)
{
	/*
	 * if_sock_ip_fd is created and bound in configure_if().
	 * if_sock_fd is bound in configure_if(); see comments in
	 * bound.c for more details on why.  if creation of if_sock_fd
	 * fails, we'll need more context anyway, so don't check.
	 */

	ifsp->if_sock_fd	= socket(AF_INET, SOCK_DGRAM, 0);
	ifsp->if_sock_ip_fd	= -1;
	ifsp->if_state		= INIT;
	ifsp->if_routers	= NULL;
	ifsp->if_nrouters	= 0;
	ifsp->if_ack		= NULL;
	ifsp->if_orig_ack	= NULL;
	ifsp->if_server.s_addr  = htonl(INADDR_BROADCAST);
	ifsp->if_neg_monosec 	= monosec();
	ifsp->if_lease 		= 0;
	ifsp->if_t1 		= 0;
	ifsp->if_t2 		= 0;
	ifsp->if_reqhost	= NULL;

	ifsp->if_script_helper_pid	= -1;
	ifsp->if_script_callback	= NULL;
	ifsp->if_script_event		= NULL;
	ifsp->if_callback_msg		= NULL;
	ifsp->if_script_event_id	= -1;
	ifsp->if_script_pid		= -1;
	ifsp->if_script_fd		= -1;

	ifsp->if_offer_id		= -1;
	ifsp->if_acknak_id		= -1;
	ifsp->if_acknak_bcast_id	= -1;
	ifsp->if_timer[DHCP_T1_TIMER]	= -1;
	ifsp->if_timer[DHCP_T2_TIMER]   = -1;
	ifsp->if_timer[DHCP_LEASE_TIMER] = -1;

	set_packet_filter(ifsp->if_dlpi_fd, dhcp_filter, NULL, "DHCP");

	dhcpmsg(MSG_DEBUG, "init_ifs: initted interface %s", ifsp->if_name);
}

/*
 * remove_ifs_default_routes(): removes an ifs's default routes
 *
 *   input: struct ifslist *: the ifs whose default routes need to be removed
 *  output: void
 */

static void
remove_ifs_default_routes(struct ifslist *ifsp)
{
	if (ifsp->if_routers != NULL) {
		while (ifsp->if_nrouters > 0) {
			(void) del_default_route(ifsp->if_name,
			    &ifsp->if_routers[--ifsp->if_nrouters]);
		}
		free(ifsp->if_routers);
		ifsp->if_routers = NULL;
	}
}

/*
 * reset_ifs(): resets an ifs to its initial state
 *
 *   input: struct ifslist *: the ifs to reset
 *  output: void
 */

void
reset_ifs(struct ifslist *ifsp)
{
	ifsp->if_dflags &= ~DHCP_IF_FAILED;

	remove_ifs_default_routes(ifsp);

	if (ifsp->if_sock_fd != -1)
		(void) close(ifsp->if_sock_fd);

	if (ifsp->if_orig_ack != ifsp->if_ack)
		free_pkt_list(&ifsp->if_orig_ack);

	free_pkt_list(&ifsp->if_ack);

	if (ifsp->if_sock_ip_fd != -1)
		(void) close(ifsp->if_sock_ip_fd);

	if (ifsp->if_offer_id != -1) {
		if (iu_unregister_event(eh, ifsp->if_offer_id, NULL) != 0)
			(void) release_ifs(ifsp);
	}

	(void) unregister_acknak(ifsp);		/* just in case */

	cancel_ifs_timers(ifsp);
	init_ifs(ifsp);
}

/*
 * lookup_ifs(): looks up an ifs, given its name
 *
 *   input: const char *: the name of the ifs entry (the interface name)
 *			  the name "" searches for the primary interface
 *  output: struct ifslist *: the corresponding ifs, or NULL if not found
 */

struct ifslist *
lookup_ifs(const char *if_name)
{
	struct ifslist	*ifs;

	for (ifs = ifsheadp; ifs != NULL; ifs = ifs->next)
		if (*if_name != '\0') {
			if (strcmp(ifs->if_name, if_name) == 0)
				break;
		} else if (ifs->if_dflags & DHCP_IF_PRIMARY)
			break;

	return (ifs);
}

/*
 * lookup_ifs_by_xid(): looks up an ifs, given its last used transaction id
 *
 *   input: int: the transaction id to look up
 *  output: struct ifslist *: the corresponding ifs, or NULL if not found
 */

struct ifslist *
lookup_ifs_by_xid(uint32_t xid)
{
	struct ifslist *ifs;

	for (ifs = ifsheadp; ifs != NULL; ifs = ifs->next) {
		if (ifs->if_send_pkt.pkt->xid == xid)
			break;
	}

	return (ifs);
}

/*
 * remove_ifs(): removes a given ifs from the ifslist.  marks the ifs
 *		 for being freed (but may not actually free it).
 *
 *   input: struct ifslist *: the ifs to remove
 *  output: void
 *    note: see interface.h for a discussion of ifs memory management
 */

void
remove_ifs(struct ifslist *ifsp)
{
	struct ifreq	ifr;

	if (ifsp->if_dflags & DHCP_IF_REMOVED)
		return;

	(void) memset(&ifr, 0, sizeof (struct ifreq));
	(void) strlcpy(ifr.ifr_name, ifsp->if_name, IFNAMSIZ);

	if (ioctl(ifsp->if_sock_fd, SIOCGIFFLAGS, &ifr) == 0) {
		ifr.ifr_flags &= ~IFF_DHCPRUNNING;
		(void) ioctl(ifsp->if_sock_fd, SIOCSIFFLAGS, &ifr);
	}

	ifsp->if_dflags |= DHCP_IF_REMOVED;

	/*
	 * if we have long term timers, cancel them so that interface
	 * resources can be reclaimed in a reasonable amount of time.
	 */

	cancel_ifs_timers(ifsp);

	if (ifsp->prev != NULL)
		ifsp->prev->next = ifsp->next;
	else
		ifsheadp = ifsp->next;

	if (ifsp->next != NULL)
		ifsp->next->prev = ifsp->prev;

	ifscount--;
	(void) release_ifs(ifsp);

	/* no big deal if this fails */
	if (ifscount == 0) {
		inactivity_id = iu_schedule_timer(tq, DHCP_INACTIVITY_WAIT,
		    inactivity_shutdown, NULL);
	}
}

/*
 * hold_ifs(): acquires a hold on an ifs
 *
 *   input: struct ifslist *: the ifs entry to acquire a hold on
 *  output: void
 */

void
hold_ifs(struct ifslist *ifsp)
{
	ifsp->if_hold_count++;

	dhcpmsg(MSG_DEBUG2, "hold_ifs: hold count on %s: %d",
	    ifsp->if_name, ifsp->if_hold_count);
}

/*
 * release_ifs(): releases a hold previously acquired on an ifs.  if the
 *		  hold count reaches 0, the ifs is freed
 *
 *   input: struct ifslist *: the ifs entry to release the hold on
 *  output: int: the number of holds outstanding on the ifs
 */

int
release_ifs(struct ifslist *ifsp)
{
	if (ifsp->if_hold_count == 0) {
		dhcpmsg(MSG_CRIT, "release_ifs: extraneous release");
		return (0);
	}

	if (--ifsp->if_hold_count == 0) {
		free_ifs(ifsp);
		return (0);
	}

	dhcpmsg(MSG_DEBUG2, "release_ifs: hold count on %s: %d",
	    ifsp->if_name, ifsp->if_hold_count);

	return (ifsp->if_hold_count);
}

/*
 * free_ifs(): frees the memory occupied by an ifs entry
 *
 *   input: struct ifslist *: the ifs entry to free
 *  output: void
 */

static void
free_ifs(struct ifslist *ifsp)
{
	dhcpmsg(MSG_DEBUG, "free_ifs: freeing interface %s", ifsp->if_name);

	free_pkt_list(&ifsp->if_recv_pkt_list);
	if (ifsp->if_ack != ifsp->if_orig_ack)
		free_pkt_list(&ifsp->if_orig_ack);
	free_pkt_list(&ifsp->if_ack);
	free(ifsp->if_send_pkt.pkt);
	free(ifsp->if_cid);
	free(ifsp->if_daddr);
	free(ifsp->if_hwaddr);
	free(ifsp->if_prl);
	free(ifsp->if_reqhost);
	free(ifsp->if_routers);

	if (ifsp->if_sock_fd != -1)
		(void) close(ifsp->if_sock_fd);

	if (ifsp->if_sock_ip_fd != -1)
		(void) close(ifsp->if_sock_ip_fd);

	if (ifsp->if_dlpi_fd != -1)
		(void) dlpi_close(ifsp->if_dlpi_fd);

	free(ifsp);
}

/*
 * checkaddr(): checks if the given address is still set on the given ifs
 *
 *   input: struct ifslist *: the ifs to check
 *	    int: the address to lookup on the interface
 *	    struct in_addr *: the address to compare to
 *  output: boolean_t: B_TRUE if the address is still set; B_FALSE if not
 */

static boolean_t
checkaddr(struct ifslist *ifsp, int ioccmd, struct in_addr *addr)
{
	struct ifreq		ifr;
	struct sockaddr_in 	*sin;

	/* LINTED [ifr_addr is a sockaddr which will be aligned] */
	sin = (struct sockaddr_in *)&ifr.ifr_addr;

	(void) memset(&ifr, 0, sizeof (struct ifreq));
	(void) strlcpy(ifr.ifr_name, ifsp->if_name, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	switch (ioctl(ifsp->if_sock_fd, ioccmd, &ifr)) {
	case 0:
		if (sin->sin_addr.s_addr != addr->s_addr)
			return (B_FALSE);
		break;
	case -1:
		if (errno == ENXIO)
			return (B_FALSE);
		break;
	}
	return (B_TRUE);
}

/*
 * verify_ifs(): verifies than an ifs is still valid (i.e., has not been
 *		 explicitly or implicitly dropped or released)
 *
 *   input: struct ifslist *: the ifs to verify
 *  output: int: 1 if the ifs is still valid, 0 if the interface is invalid
 */

int
verify_ifs(struct ifslist *ifsp)
{
	struct ifreq 		ifr;

	if (ifsp->if_dflags & DHCP_IF_REMOVED)
		return (0);

	(void) memset(&ifr, 0, sizeof (struct ifreq));
	(void) strlcpy(ifr.ifr_name, ifsp->if_name, IFNAMSIZ);

	ifr.ifr_addr.sa_family = AF_INET;

	switch (ifsp->if_state) {

	case BOUND:
	case RENEWING:
	case REBINDING:

		/*
		 * if the interface has gone down or been unplumbed, then we
		 * act like there has been an implicit drop.
		 */

		switch (ioctl(ifsp->if_sock_fd, SIOCGIFFLAGS, &ifr)) {
		case 0:
			if ((ifr.ifr_flags & (IFF_UP|IFF_DHCPRUNNING)) !=
			    (IFF_UP|IFF_DHCPRUNNING))
				goto abandon;
			break;
		case -1:
			if (errno == ENXIO)
				goto abandon;
			break;
		}
		/* FALLTHRU */

	case INIT_REBOOT:
	case SELECTING:
	case REQUESTING:

		/*
		 * if the IP address, netmask, or broadcast address have
		 * changed, or the interface has been unplumbed, then we act
		 * like there has been an implicit drop.
		 */

		if (!checkaddr(ifsp, SIOCGIFADDR, &ifsp->if_addr) ||
		    !checkaddr(ifsp, SIOCGIFNETMASK, &ifsp->if_netmask) ||
		    !checkaddr(ifsp, SIOCGIFBRDADDR, &ifsp->if_broadcast))
			goto abandon;
	}

	return (1);
abandon:
	dhcpmsg(MSG_WARNING, "verify_ifs: %s has changed properties, "
	    "abandoning", ifsp->if_name);

	remove_ifs(ifsp);
	return (0);
}

/*
 * canonize_ifs(): puts the interface in a canonical (zeroed) form
 *
 *   input: struct ifslist *: the interface to canonize
 *  output: int: 1 on success, 0 on failure
 */

int
canonize_ifs(struct ifslist *ifsp)
{
	struct sockaddr_in	*sin;
	struct ifreq		ifr;

	dhcpmsg(MSG_VERBOSE, "canonizing interface %s", ifsp->if_name);

	/*
	 * note that due to infelicities in the routing code, any default
	 * routes must be removed prior to clearing the UP flag.
	 */

	remove_ifs_default_routes(ifsp);

	/* LINTED [ifr_addr is a sockaddr which will be aligned] */
	sin = (struct sockaddr_in *)&ifr.ifr_addr;

	(void) memset(&ifr, 0, sizeof (struct ifreq));
	(void) strlcpy(ifr.ifr_name, ifsp->if_name, IFNAMSIZ);

	if (ioctl(ifsp->if_sock_fd, SIOCGIFFLAGS, &ifr) == -1)
		return (0);

	/*
	 * clear the UP flag, but don't clear DHCPRUNNING since
	 * that should only be done when the interface is removed
	 * (see remove_ifs())
	 */

	ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(ifsp->if_sock_fd, SIOCSIFFLAGS, &ifr) == -1)
		return (0);

	/*
	 * since ifr is actually a union, we need to explicitly zero
	 * the flags field before we reuse the structure, or otherwise
	 * cruft may leak over into other members of the union.
	 */

	ifr.ifr_flags = 0;
	ifr.ifr_addr.sa_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);

	if (ioctl(ifsp->if_sock_fd, SIOCSIFADDR, &ifr) == -1)
		return (0);

	if (ioctl(ifsp->if_sock_fd, SIOCSIFNETMASK, &ifr) == -1)
		return (0);

	if (ioctl(ifsp->if_sock_fd, SIOCSIFBRDADDR, &ifr) == -1)
		return (0);

	/*
	 * any time we change the IP address, netmask, or broadcast we
	 * must be careful to also reset bookkeeping of what these are
	 * set to.  this is so we can detect if these characteristics
	 * are changed by another process.
	 */

	ifsp->if_addr.s_addr	  = htonl(INADDR_ANY);
	ifsp->if_netmask.s_addr   = htonl(INADDR_ANY);
	ifsp->if_broadcast.s_addr = htonl(INADDR_ANY);

	return (1);
}

/*
 * check_ifs(): makes sure an ifs is still valid, and if it is, releases the
 *		ifs.  otherwise, it informs the caller the ifs is going away
 *		and expects the caller to perform the release
 *
 *   input: struct ifslist *: the ifs to check
 *  output: int: 1 if the interface is valid, 0 otherwise
 */

int
check_ifs(struct ifslist *ifsp)
{
	hold_ifs(ifsp);
	if (release_ifs(ifsp) == 1 || verify_ifs(ifsp) == 0) {

		/*
		 * this interface is going away.  if there's an
		 * uncancelled IPC event roaming around, cancel it
		 * now.  we leave the hold on in case anyone else has
		 * any cleanup work that needs to be done before the
		 * interface goes away.
		 */

		ipc_action_finish(ifsp, DHCP_IPC_E_UNKIF);
		async_finish(ifsp);
		return (0);
	}

	(void) release_ifs(ifsp);
	return (1);
}

/*
 * nuke_ifslist(): delete the ifslist (for use when the dhcpagent is exiting)
 *
 *   input: boolean_t: B_TRUE if the agent is exiting due to SIGTERM
 *  output: void
 */

void
nuke_ifslist(boolean_t onterm)
{
	int	status;
	struct ifslist	*ifsp, *ifsp_next;

	for (ifsp = ifsheadp; ifsp != NULL; ifsp = ifsp_next) {
		ifsp_next = ifsp->next;

		cancel_ifs_timers(ifsp);
		if (ifsp->if_script_pid != -1) {
			/* stop a script if it is not for DROP or RELEASE */
			if (strcmp(ifsp->if_script_event, EVENT_DROP) == 0 ||
			    strcmp(ifsp->if_script_event, EVENT_RELEASE) == 0) {
				continue;
			}
			script_stop(ifsp);
		}

		/*
		 * if the script is started by script_start, dhcp_drop and
		 * dhcp_release should and will only be called after the
		 * script exits.
		 */
		if (onterm &&
		    df_get_bool(ifsp->if_name, DF_RELEASE_ON_SIGTERM)) {
			if (script_start(ifsp, EVENT_RELEASE, dhcp_release,
			    "DHCP agent is exiting", &status) == 1) {
				continue;
			}
			if (status == 1)
				continue;
		}
		(void) script_start(ifsp, EVENT_DROP, dhcp_drop, NULL, NULL);
	}
}

/*
 * refresh_ifslist(): refreshes all finite leases under DHCP control
 *
 *   input: iu_eh_t *: unused
 *	    int: unused
 *	    void *: unused
 *  output: void
 */

/* ARGSUSED */
void
refresh_ifslist(iu_eh_t *eh, int sig, void *arg)
{
	struct ifslist *ifsp;

	for (ifsp = ifsheadp; ifsp != NULL; ifsp = ifsp->next) {

		if (ifsp->if_state != BOUND && ifsp->if_state != RENEWING &&
		    ifsp->if_state != REBINDING)
			continue;

		if (ifsp->if_lease == DHCP_PERM)
			continue;

		/*
		 * this interface has a finite lease and we do not know
		 * how long the machine's been off for.  refresh it.
		 */

		dhcpmsg(MSG_WARNING, "refreshing lease on %s", ifsp->if_name);
		cancel_ifs_timer(ifsp, DHCP_T1_TIMER);
		cancel_ifs_timer(ifsp, DHCP_T2_TIMER);
		(void) iu_adjust_timer(tq, ifsp->if_timer[DHCP_LEASE_TIMER], 0);
	}
}

/*
 * ifs_count(): returns the number of interfaces currently managed
 *
 *   input: void
 *  output: unsigned int: the number of interfaces currently managed
 */

unsigned int
ifs_count(void)
{
	return (ifscount);
}

/*
 * cancel_ifs_timer(): cancels a lease-related timer on an interface
 *
 *   input: struct ifslist *: the interface to operate on
 *	    int: the timer id of the timer to cancel
 *  output: void
 */

static void
cancel_ifs_timer(struct ifslist *ifsp, int timer_id)
{
	if (ifsp->if_timer[timer_id] != -1) {
		if (iu_cancel_timer(tq, ifsp->if_timer[timer_id], NULL) == 1) {
			(void) release_ifs(ifsp);
			ifsp->if_timer[timer_id] = -1;
		} else
			dhcpmsg(MSG_WARNING, "cancel_ifs_timer: cannot cancel "
			    "if_timer[%d]", timer_id);
	}
}

/*
 * cancel_ifs_timers(): cancels an interface's pending lease-related timers
 *
 *   input: struct ifslist *: the interface to operate on
 *  output: void
 */

void
cancel_ifs_timers(struct ifslist *ifsp)
{
	cancel_ifs_timer(ifsp, DHCP_T1_TIMER);
	cancel_ifs_timer(ifsp, DHCP_T2_TIMER);
	cancel_ifs_timer(ifsp, DHCP_LEASE_TIMER);
}

/*
 * schedule_ifs_timer(): schedules a lease-related timer on an interface
 *
 *   input: struct ifslist *: the interface to operate on
 *	    int: the timer to schedule
 *	    uint32_t: the number of seconds in the future it should fire
 *	    iu_tq_callback_t *: the callback to call upon firing
 *  output: int: 1 if the timer was scheduled successfully, 0 on failure
 */

int
schedule_ifs_timer(struct ifslist *ifsp, int timer_id, uint32_t sec,
    iu_tq_callback_t *expire)
{
	cancel_ifs_timer(ifsp, timer_id);		/* just in case */

	ifsp->if_timer[timer_id] = iu_schedule_timer(tq, sec, expire, ifsp);
	if (ifsp->if_timer[timer_id] == -1) {
		dhcpmsg(MSG_WARNING, "schedule_ifs_timer: cannot schedule "
		    "if_timer[%d]", timer_id);
		return (0);
	}

	hold_ifs(ifsp);
	return (1);
}

/*
 * Get the value of the named property on the named node in devinfo root.
 *
 *   input: const char *: The name of the node containing the property.
 *	    const char *: The name of the property.
 *	    uchar_t **: The property value, modified iff B_TRUE is returned.
 *                      If no value is found the value is set to NULL.
 *	    unsigned int *: The length of the property value
 *  output: boolean_t: Returns B_TRUE if successful (no problems),
 *                     otherwise B_FALSE.
 *    note: The memory allocated by this function must be freed by
 *          the caller. This code is derived from
 *          usr/src/lib/libwanboot/common/bootinfo_aux.c.
 */

static boolean_t
get_prom_prop(const char *nodename, const char *propname, uchar_t **propvaluep,
    unsigned int *lenp)
{
	di_node_t		root_node = DI_NODE_NIL;
	di_node_t		node;
	di_prom_handle_t	phdl = DI_PROM_HANDLE_NIL;
	di_prom_prop_t		pp;
	uchar_t			*value = NULL;
	unsigned int		len = 0;
	boolean_t		success = B_TRUE;

	/*
	 * locate root node
	 */

	if ((root_node = di_init("/", DINFOCPYALL)) == DI_NODE_NIL ||
	    (phdl = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		dhcpmsg(MSG_DEBUG, "get_prom_prop: property root node "
		    "not found");
		goto get_prom_prop_cleanup;
	}

	/*
	 * locate nodename within '/'
	 */

	for (node = di_child_node(root_node);
	    node != DI_NODE_NIL;
	    node = di_sibling_node(node)) {
		if (strcmp(di_node_name(node), nodename) == 0) {
			break;
		}
	}

	if (node == DI_NODE_NIL) {
		dhcpmsg(MSG_DEBUG, "get_prom_prop: node not found");
		goto get_prom_prop_cleanup;
	}

	/*
	 * scan all properties of /nodename for the 'propname' property
	 */

	for (pp = di_prom_prop_next(phdl, node, DI_PROM_PROP_NIL);
	    pp != DI_PROM_PROP_NIL;
	    pp = di_prom_prop_next(phdl, node, pp)) {

		dhcpmsg(MSG_DEBUG, "get_prom_prop: property = %s",
		    di_prom_prop_name(pp));

		if (strcmp(propname, di_prom_prop_name(pp)) == 0) {
			break;
		}
	}

	if (pp == DI_PROM_PROP_NIL) {
		dhcpmsg(MSG_DEBUG, "get_prom_prop: property not found");
		goto get_prom_prop_cleanup;
	}

	/*
	 * get the property; allocate some memory copy it out
	 */

	len = di_prom_prop_data(pp, (uchar_t **)&value);

	if (value == NULL) {
		/*
		 * property data read problems
		 */

		success = B_FALSE;
		dhcpmsg(MSG_ERR, "get_prom_prop: cannot read property data");
		goto get_prom_prop_cleanup;
	}

	if (propvaluep != NULL) {
		/*
		 * allocate somewhere to copy the property value to
		 */

		*propvaluep = calloc(len, sizeof (uchar_t));

		if (*propvaluep == NULL) {
			/*
			 * allocation problems
			 */

			success = B_FALSE;
			dhcpmsg(MSG_ERR, "get_prom_prop: cannot allocate "
			    "memory for property value");
			goto get_prom_prop_cleanup;
		}

		/*
		 * copy data out
		 */

		(void) memcpy(*propvaluep, value, len);

		/*
		 * copy out the length if a suitable pointer has
		 * been supplied
		 */

		if (lenp != NULL) {
			*lenp = len;
		}

		dhcpmsg(MSG_DEBUG, "get_prom_prop: property value "
		    "length = %d", len);
	}

get_prom_prop_cleanup:

	if (phdl != DI_PROM_HANDLE_NIL) {
		di_prom_fini(phdl);
	}

	if (root_node != DI_NODE_NIL) {
		di_fini(root_node);
	}

	return (success);
}
