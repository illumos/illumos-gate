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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * BOUND state of the DHCP client state machine.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <dhcp_hostconf.h>
#include <dhcpmsg.h>

#include "states.h"
#include "packet.h"
#include "util.h"
#include "agent.h"
#include "interface.h"
#include "script_handler.h"

#define	IS_DHCP(plp)	((plp)->opts[CD_DHCP_TYPE] != NULL)

static int	configure_if(struct ifslist *);
static int	configure_bound(struct ifslist *);
static int	configure_timers(struct ifslist *);

/*
 * bound_event_cb(): callback for script_start on the event EVENT_BOUND
 *
 *   input: struct ifslist *: the interface configured
 *	    const char *: unused
 *  output: int: always 1
 */

/* ARGSUSED */
static int
bound_event_cb(struct ifslist *ifsp, const char *msg)
{
	ipc_action_finish(ifsp, DHCP_IPC_SUCCESS);
	async_finish(ifsp);
	return (1);
}

/*
 * dhcp_bound(): configures an interface and ifs using information contained
 *		 in the ACK packet and sets up lease timers.  before starting,
 *		 the requested address is arped to make sure it's not in use.
 *
 *   input: struct ifslist *: the interface to move to bound
 *	    PKT_LIST *: the ACK packet, or NULL if it should use ifsp->if_ack
 *  output: int: 0 on failure, 1 on success
 */

int
dhcp_bound(struct ifslist *ifsp, PKT_LIST *ack)
{
	lease_t		cur_lease, new_lease;
	int		msg_level;
	const char	*noext = "lease renewed but time not extended";
	uint_t		minleft;

	if (ack != NULL) {
		/* If ack we're replacing is not the original, then free it */
		if (ifsp->if_ack != ifsp->if_orig_ack)
			free_pkt_list(&ifsp->if_ack);
		ifsp->if_ack = ack;
		/* Save the first ack as the original */
		if (ifsp->if_orig_ack == NULL)
			ifsp->if_orig_ack = ack;
	}

	switch (ifsp->if_state) {

	case ADOPTING:

		/*
		 * if we're adopting an interface, the lease timers
		 * only provide an upper bound since we don't know
		 * from what time they are relative to.  assume we
		 * have a lease time of at most DHCP_ADOPT_LEASE_MAX.
		 */

		if (!IS_DHCP(ifsp->if_ack))
			return (0);

		(void) memcpy(&new_lease,
		    ifsp->if_ack->opts[CD_LEASE_TIME]->value, sizeof (lease_t));

		new_lease = htonl(MIN(ntohl(new_lease), DHCP_ADOPT_LEASE_MAX));

		(void) memcpy(ifsp->if_ack->opts[CD_LEASE_TIME]->value,
		    &new_lease, sizeof (lease_t));

		if (configure_bound(ifsp) == 0)
			return (0);

		/*
		 * we have no idea when the REQUEST that generated
		 * this ACK was sent, but for diagnostic purposes
		 * we'll assume its close to the current time.
		 */
		ifsp->if_newstart_monosec = monosec();

		if (configure_timers(ifsp) == 0)
			return (0);

		/*
		 * if the state is ADOPTING, event loop has not been started
		 * at this time; so don't run the EVENT_BOUND script.
		 */
		ifsp->if_curstart_monosec = ifsp->if_newstart_monosec;
		ifsp->if_state = BOUND;
		break;

	case REQUESTING:
	case INIT_REBOOT:

		if (configure_if(ifsp) == 0)
			return (0);

		if (configure_timers(ifsp) == 0)
			return (0);

		/*
		 * We will continue configuring this interface via
		 * dhcp_bound_complete, once kernel DAD completes.
		 */
		ifsp->if_state = PRE_BOUND;
		break;

	case PRE_BOUND:
		/* This is just a duplicate ack; silently ignore it */
		return (1);

	case RENEWING:
	case REBINDING:
	case BOUND:
		cur_lease = ifsp->if_lease;
		if (configure_timers(ifsp) == 0)
			return (0);

		/*
		 * if the current lease is mysteriously close to the new
		 * lease, warn the user.  unless there's less than a minute
		 * left, round to the closest minute.
		 */

		if (abs((ifsp->if_newstart_monosec + ifsp->if_lease) -
		    (ifsp->if_curstart_monosec + cur_lease)) < DHCP_LEASE_EPS) {

			if (ifsp->if_lease < DHCP_LEASE_ERROR_THRESH)
				msg_level = MSG_ERROR;
			else
				msg_level = MSG_VERBOSE;

			minleft = (ifsp->if_lease + 30) / 60;

			if (ifsp->if_lease < 60) {
				dhcpmsg(msg_level, "%s; expires in %d seconds",
				    noext, ifsp->if_lease);
			} else if (minleft == 1) {
				dhcpmsg(msg_level, "%s; expires in 1 minute",
				    noext);
			} else {
				dhcpmsg(msg_level, "%s; expires in %d minutes",
				    noext, minleft);
			}
		}

		(void) script_start(ifsp, EVENT_EXTEND, bound_event_cb,
		    NULL, NULL);

		ifsp->if_state = BOUND;
		ifsp->if_curstart_monosec = ifsp->if_newstart_monosec;
		break;

	case INFORM_SENT:

		(void) bound_event_cb(ifsp, NULL);
		ifsp->if_state = INFORMATION;
		break;

	default:
		/* something is really bizarre... */
		dhcpmsg(MSG_DEBUG, "dhcp_bound: called in unexpected state");
		return (0);
	}

	/*
	 * remove any stale hostconf file that might be lying around for
	 * this interface. (in general, it's harmless, since we'll write a
	 * fresh one when we exit anyway, but just to reduce confusion..)
	 */

	(void) remove_hostconf(ifsp->if_name);
	return (1);
}

/*
 * dhcp_bound_complete(): complete interface configuration after DAD
 *
 *   input: struct ifslist *: the interface to configure
 *  output: none
 */

void
dhcp_bound_complete(struct ifslist *ifsp)
{
	if (configure_bound(ifsp) == 0)
		return;

	(void) script_start(ifsp, EVENT_BOUND, bound_event_cb, NULL, NULL);

	ifsp->if_state = BOUND;
	ifsp->if_curstart_monosec = ifsp->if_newstart_monosec;
}

/*
 * configure_timers(): configures the lease timers on an interface
 *
 *   input: struct ifslist *: the interface to configure (with a valid if_ack)
 *  output: int: 1 on success, 0 on failure
 */

static int
configure_timers(struct ifslist *ifsp)
{
	lease_t		lease, t1, t2;

	if (ifsp->if_ack->opts[CD_DHCP_TYPE] != NULL &&
	    (ifsp->if_ack->opts[CD_LEASE_TIME] == NULL ||
	    ifsp->if_ack->opts[CD_LEASE_TIME]->len != sizeof (lease_t))) {
		send_decline(ifsp, "Missing or corrupted lease time",
		    &ifsp->if_ack->pkt->yiaddr);
		dhcpmsg(MSG_WARNING, "configure_timers: missing or corrupted "
		    "lease time in ACK on %s", ifsp->if_name);
		return (0);
	}

	cancel_ifs_timers(ifsp);

	/*
	 * type has already been verified as ACK.  if type is not set,
	 * then we got a BOOTP packet.  we now fetch the t1, t2, and
	 * lease options out of the packet into variables.  they are
	 * returned as relative host-byte-ordered times.
	 */

	get_pkt_times(ifsp->if_ack, &lease, &t1, &t2);

	ifsp->if_t1	= t1;
	ifsp->if_t2	= t2;
	ifsp->if_lease	= lease;

	if (ifsp->if_lease == DHCP_PERM) {
		dhcpmsg(MSG_INFO, "%s acquired permanent lease", ifsp->if_name);
		return (1);
	}

	dhcpmsg(MSG_INFO, "%s acquired lease, expires %s", ifsp->if_name,
	    monosec_to_string(ifsp->if_newstart_monosec + ifsp->if_lease));

	dhcpmsg(MSG_INFO, "%s begins renewal at %s", ifsp->if_name,
	    monosec_to_string(ifsp->if_newstart_monosec + ifsp->if_t1));

	dhcpmsg(MSG_INFO, "%s begins rebinding at %s", ifsp->if_name,
	    monosec_to_string(ifsp->if_newstart_monosec + ifsp->if_t2));

	/*
	 * according to RFC2131, there is no minimum lease time, but don't
	 * set up renew/rebind timers if lease is shorter than DHCP_REBIND_MIN.
	 */

	if (schedule_ifs_timer(ifsp, DHCP_LEASE_TIMER, lease, dhcp_expire) == 0)
		goto failure;

	if (lease < DHCP_REBIND_MIN) {
		dhcpmsg(MSG_WARNING, "dhcp_bound: lease on %s is for "
		    "less than %d seconds!", ifsp->if_name, DHCP_REBIND_MIN);
		return (1);
	}

	if (schedule_ifs_timer(ifsp, DHCP_T1_TIMER, t1, dhcp_renew) == 0)
		goto failure;

	if (schedule_ifs_timer(ifsp, DHCP_T2_TIMER, t2, dhcp_rebind) == 0)
		goto failure;

	return (1);

failure:
	cancel_ifs_timers(ifsp);
	dhcpmsg(MSG_WARNING, "dhcp_bound: cannot schedule lease timers");
	return (0);
}

/*
 * configure_if(): configures an interface with DHCP parameters from an ACK
 *
 *   input: struct ifslist *: the interface to configure (with a valid if_ack)
 *  output: int: 1 on success, 0 on failure
 */

static int
configure_if(struct ifslist *ifsp)
{
	struct ifreq		ifr;
	struct sockaddr_in	*sin;
	PKT_LIST		*ack = ifsp->if_ack;

	/*
	 * if we're using DHCP, then we'll have a valid CD_SERVER_ID
	 * (we checked in dhcp_acknak()); set it now so that
	 * ifsp->if_server is valid in case we need to send_decline().
	 * note that we use comparisons against opts[CD_DHCP_TYPE]
	 * since we haven't set DHCP_IF_BOOTP yet (we don't do that
	 * until we're sure we want the offered address.)
	 */

	if (ifsp->if_ack->opts[CD_DHCP_TYPE] != NULL)
		(void) memcpy(&ifsp->if_server.s_addr,
		    ack->opts[CD_SERVER_ID]->value, sizeof (ipaddr_t));

	ifsp->if_addr.s_addr = ack->pkt->yiaddr.s_addr;
	if (ifsp->if_addr.s_addr == htonl(INADDR_ANY)) {
		dhcpmsg(MSG_ERROR, "configure_if: got invalid IP address");
		return (0);
	}

	(void) memset(&ifr, 0, sizeof (struct ifreq));
	(void) strlcpy(ifr.ifr_name, ifsp->if_name, IFNAMSIZ);

	/*
	 * bring the interface online.  note that there is no optimal
	 * order here: it is considered bad taste (and in > solaris 7,
	 * likely illegal) to bring an interface up before it has an
	 * ip address.  however, due to an apparent bug in sun fddi
	 * 5.0, fddi will not obtain a network routing entry unless
	 * the interface is brought up before it has an ip address.
	 * we take the lesser of the two evils; if fddi customers have
	 * problems, they can get a newer fddi distribution which
	 * fixes the problem.
	 */

	/* LINTED [ifr_addr is a sockaddr which will be aligned] */
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;

	if (ack->opts[CD_SUBNETMASK] != NULL &&
	    ack->opts[CD_SUBNETMASK]->len == sizeof (ipaddr_t)) {

		(void) memcpy(&ifsp->if_netmask.s_addr,
		    ack->opts[CD_SUBNETMASK]->value, sizeof (ipaddr_t));

	} else {

		if (ack->opts[CD_SUBNETMASK] != NULL &&
		    ack->opts[CD_SUBNETMASK]->len != sizeof (ipaddr_t))
			dhcpmsg(MSG_WARNING, "configure_if: specified subnet "
			    "mask length is %d instead of %d, ignoring",
			    ack->opts[CD_SUBNETMASK]->len, sizeof (ipaddr_t));

		/*
		 * no legitimate IP subnet mask specified..  use best
		 * guess.  recall that if_addr is in network order, so
		 * imagine it's 0x11223344: then when it is read into
		 * a register on x86, it becomes 0x44332211, so we
		 * must ntohl() it to convert it to 0x11223344 in
		 * order to use the macros in <netinet/in.h>.
		 */

		if (IN_CLASSA(ntohl(ifsp->if_addr.s_addr)))
			ifsp->if_netmask.s_addr = htonl(IN_CLASSA_NET);
		else if (IN_CLASSB(ntohl(ifsp->if_addr.s_addr)))
			ifsp->if_netmask.s_addr = htonl(IN_CLASSB_NET);
		else if (IN_CLASSC(ntohl(ifsp->if_addr.s_addr)))
			ifsp->if_netmask.s_addr = htonl(IN_CLASSC_NET);
		else	/* must be class d */
			ifsp->if_netmask.s_addr = htonl(IN_CLASSD_NET);

		dhcpmsg(MSG_WARNING, "configure_if: no IP netmask specified "
		    "for %s, making best guess", ifsp->if_name);
	}

	dhcpmsg(MSG_INFO, "setting IP netmask to %s on %s",
	    inet_ntoa(ifsp->if_netmask), ifsp->if_name);

	sin->sin_addr = ifsp->if_netmask;
	if (ioctl(ifsp->if_sock_fd, SIOCSIFNETMASK, &ifr) == -1) {
		dhcpmsg(MSG_ERR, "cannot set IP netmask on %s", ifsp->if_name);
		return (0);
	}

	dhcpmsg(MSG_INFO, "setting IP address to %s on %s",
	    inet_ntoa(ifsp->if_addr), ifsp->if_name);

	sin->sin_addr = ifsp->if_addr;
	if (ioctl(ifsp->if_sock_fd, SIOCSIFADDR, &ifr) == -1) {
		dhcpmsg(MSG_ERR, "configure_if: cannot set IP address on %s",
		    ifsp->if_name);
		return (0);
	}

	if (ack->opts[CD_BROADCASTADDR] != NULL &&
	    ack->opts[CD_BROADCASTADDR]->len == sizeof (ipaddr_t)) {

		(void) memcpy(&ifsp->if_broadcast.s_addr,
		    ack->opts[CD_BROADCASTADDR]->value, sizeof (ipaddr_t));

	} else {

		if (ack->opts[CD_BROADCASTADDR] != NULL &&
		    ack->opts[CD_BROADCASTADDR]->len != sizeof (ipaddr_t))
			dhcpmsg(MSG_WARNING, "configure_if: specified "
			    "broadcast address length is %d instead of %d, "
			    "ignoring", ack->opts[CD_BROADCASTADDR]->len,
			    sizeof (ipaddr_t));

		/*
		 * no legitimate IP broadcast specified.  compute it
		 * from the IP address and netmask.
		 */

		ifsp->if_broadcast.s_addr = ifsp->if_addr.s_addr &
			ifsp->if_netmask.s_addr | ~ifsp->if_netmask.s_addr;

		dhcpmsg(MSG_WARNING, "configure_if: no IP broadcast specified "
		    "for %s, making best guess", ifsp->if_name);
	}

	if (ioctl(ifsp->if_sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
		dhcpmsg(MSG_ERR, "configure_if: cannot get interface flags for "
		    "%s", ifsp->if_name);
		return (0);
	}

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(ifsp->if_sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
		dhcpmsg(MSG_ERR, "configure_if: cannot set interface flags for "
		    "%s", ifsp->if_name);
		return (0);
	}

	/*
	 * the kernel will set the broadcast address for us as part of
	 * bringing the interface up.  since experience has shown that dhcp
	 * servers sometimes provide a bogus broadcast address, we let the
	 * kernel set it so that it's guaranteed to be correct.
	 *
	 * also, note any inconsistencies and save the broadcast address the
	 * kernel set so that we can watch for changes to it.
	 */

	if (ioctl(ifsp->if_sock_fd, SIOCGIFBRDADDR, &ifr) == -1) {
		dhcpmsg(MSG_ERR, "configure_if: cannot get broadcast address "
		    "for %s", ifsp->if_name);
		return (0);
	}

	if (ifsp->if_broadcast.s_addr != sin->sin_addr.s_addr) {
		dhcpmsg(MSG_WARNING, "incorrect broadcast address %s specified "
		    "for %s; ignoring", inet_ntoa(ifsp->if_broadcast),
		    ifsp->if_name);
	}

	ifsp->if_broadcast = sin->sin_addr;
	dhcpmsg(MSG_INFO, "using broadcast address %s on %s",
	    inet_ntoa(ifsp->if_broadcast), ifsp->if_name);
	return (1);
}

/*
 * configure_bound(): configures routing with DHCP parameters from an ACK,
 *		      and sets up the if_sock_ip_fd socket used for lease
 *		      renewal.
 *
 *   input: struct ifslist *: the interface to configure (with a valid if_ack)
 *  output: int: 1 on success, 0 on failure
 */

static int
configure_bound(struct ifslist *ifsp)
{
	PKT_LIST		*ack = ifsp->if_ack;
	DHCP_OPT		*router_list;
	int			i;

	/*
	 * add each provided router; we'll clean them up when the
	 * interface goes away or when our lease expires.
	 */

	router_list = ack->opts[CD_ROUTER];
	if (router_list && (router_list->len % sizeof (ipaddr_t)) == 0) {

		ifsp->if_nrouters = router_list->len / sizeof (ipaddr_t);
		ifsp->if_routers  = malloc(router_list->len);
		if (ifsp->if_routers == NULL) {
			dhcpmsg(MSG_ERR, "configure_bound: cannot allocate "
			    "default router list, ignoring default routers");
			ifsp->if_nrouters = 0;
		}

		for (i = 0; i < ifsp->if_nrouters; i++) {

			(void) memcpy(&ifsp->if_routers[i].s_addr,
			    router_list->value + (i * sizeof (ipaddr_t)),
			    sizeof (ipaddr_t));

			if (add_default_route(ifsp->if_name,
			    &ifsp->if_routers[i]) == 0) {
				dhcpmsg(MSG_ERR, "configure_bound: cannot add "
				    "default router %s on %s", inet_ntoa(
				    ifsp->if_routers[i]), ifsp->if_name);
				ifsp->if_routers[i].s_addr = htonl(INADDR_ANY);
				continue;
			}

			dhcpmsg(MSG_INFO, "added default router %s on %s",
			    inet_ntoa(ifsp->if_routers[i]), ifsp->if_name);
		}
	}

	ifsp->if_sock_ip_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifsp->if_sock_ip_fd == -1) {
		dhcpmsg(MSG_ERR, "configure_bound: cannot create socket on %s",
		    ifsp->if_name);
		return (0);
	}

	if (bind_sock(ifsp->if_sock_ip_fd, IPPORT_BOOTPC,
	    ntohl(ifsp->if_addr.s_addr)) == 0) {
		dhcpmsg(MSG_ERR, "configure_bound: cannot bind socket on %s",
		    ifsp->if_name);
		return (0);
	}

	/*
	 * we wait until here to bind if_sock_fd because it turns out
	 * the kernel has difficulties doing binds before interfaces
	 * are up (although it may work sometimes, it doesn't work all
	 * the time.)  that's okay, because we don't use if_sock_fd
	 * for receiving data until we're BOUND anyway.
	 */

	if (bind_sock(ifsp->if_sock_fd, IPPORT_BOOTPC, INADDR_BROADCAST) == 0) {
		dhcpmsg(MSG_ERR, "configure_bound: cannot bind broadcast "
		    "socket on %s", ifsp->if_name);
		return (0);
	}

	/*
	 * we'll be using if_sock_fd for the remainder of the lease;
	 * blackhole if_dlpi_fd.
	 */

	set_packet_filter(ifsp->if_dlpi_fd, blackhole_filter, 0, "blackhole");

	if (ack->opts[CD_DHCP_TYPE] == NULL)
		ifsp->if_dflags	|= DHCP_IF_BOOTP;

	dhcpmsg(MSG_DEBUG, "configure_bound: bound ifsp->if_sock_ip_fd");
	return (1);
}
