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

#ifndef _STRUCTURES_H
#define	_STRUCTURES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <net/if.h>
#include <libscf.h>
#include <libdlwlan.h>

/*
 * XXX More work on the state machine is needed.  In the future,
 * events will be more like EV_NEWADDR, identifying the actual
 * event that we care about, rather than the source of the event
 * that we originally implemented.  For example, EV_ROUTING should
 * be split into EV_LINK_UP and EV_LINK_DOWN.  It's a bit of a mix
 * right now.
 */
enum np_event_type {
	EV_ROUTING,
	EV_SYS,
	EV_TIMER,
	EV_SHUTDOWN,
	EV_NEWADDR
};

enum interface_type {
	IF_UNKNOWN,
	IF_WIRED,
	IF_WIRELESS,
	IF_TUN
};

struct np_event {
	enum np_event_type npe_type;
	char *npe_name;
	struct np_event *npe_next;
};

/*
 * This structure is used to represent the current state of the system.  We
 * maintain these for IPv4 as proxies for links in the system.  This is
 * differentiated from the LLP which contains the intended configuration of
 * the system.
 *
 * Currently these are stored on ifs_head with the wired interfaces sorted
 * together and the wireless ones sorted together with ifs_wired and
 * ifs_wireless pointed at these sublists.  Access to these lists is not
 * currently MT-safe.
 *
 * We explicitly do not maintain IPv6 interface structures.  In the current
 * state machine, IPv6 interfaces are completely dependent on their IPv4
 * counterparts.  For example, we make a decision to bring up an interface
 * based on routing socket messages read from an AF_INET socket; we will
 * always bring up v4, and may additionally bring up v6.  Also, when we
 * start up, we find all interfaces in the system by doing 'ifconfig -a
 * plumb', which will plumb v4 on all links; we always keep the v4 interface
 * plumbed, taking it up and down depending on whether it's currently in use
 * or not.  v6 interfaces are not plumbed initially; when we decide a link
 * should be active (and its llp tells us to do v6), we'll mark the (already
 * existing) v4 interface up, and 'plumb up' the v6 interface.  Conversely,
 * when a link is no longer active, we 'down unplumb' the v6 interface, but
 * only 'down' the v4 interface.
 */
struct interface {
	char *if_name;
	datalink_id_t if_linkid;
	sa_family_t if_family;
	uint64_t if_flags;
	uint32_t if_lflags;
	enum interface_type if_type;
	uint32_t if_timer_expire;
	struct sockaddr *if_ipaddr;
	struct interface *if_next;
};

/*
 * interface local flag values
 */
/*
 * IF_DHCPFAILED: indicates that we timed out a dhcp request.  Will be
 * cleared if the request eventually succeeds, or if the IFF_RUNNING flag
 * is toggled off/on (i.e. the cable is unplugged/plugged)
 */
#define	IF_DHCPFAILED	0x01
/*
 * IF_DHCPSTARTED: much like IFF_DHCPRUNNING; but means specifically that
 * we have inititated dhcp on this interface.  Used to prevent overlapping
 * invocations of dhcp.
 */
#define	IF_DHCPSTARTED	0x02
/*
 * IF_DHCPACQUIRED: indicates that dhcp successfully acquired a lease.
 */
#define	IF_DHCPACQUIRED	0x04

#define	IF_DHCPFLAGS	(IF_DHCPFAILED | IF_DHCPSTARTED | IF_DHCPACQUIRED)

/*
 * visited_wlans are stored on visited_wlan_list of type visisted_wlans_list.
 * Access is protected by wifi_mutex.
 */
struct visited_wlans {
	struct wireless_lan *wifi_net;
	struct visited_wlans *next;
};

struct visited_wlans_list {
	struct visited_wlans *head;
	int total;
};

typedef enum {
	IPV4SRC_STATIC,
	IPV4SRC_DHCP
} ipv4src_t;

/*
 * This structure contains the intended configuration of the system as
 * differentiated from the actual IPv4 configuration of the system represented
 * by the interface structures.
 *
 * llp structures are held on the list llp_head.  Access to this list is
 * protected by llp_lock.
 */
typedef struct llp {
	struct llp *llp_next;
	char	llp_lname[LIFNAMSIZ];
	int	llp_pri;		/* lower number => higher priority */
	enum interface_type llp_type;
	ipv4src_t llp_ipv4src;
	char	*llp_ipv4addrstr;	/* if ipsrc is STATIC */
	char	*llp_ipv6addrstr;	/* if the user provided a static addr */
	boolean_t llp_ipv6onlink;	/* true if we plumb up a v6 interface */
} llp_t;

/*
 * These entries are user allocated and should be managed by whomever
 * originates the structure.
 */
struct wireless_lan {
	char *essid;
	char *bssid;
	char *signal_strength;
	char *raw_key;
	dladm_wlan_key_t *cooked_key;
	dladm_wlan_secmode_t sec_mode;
	char *wl_if_name;
};

/*
 * A holder for all the resources needed to get a property value
 * using libscf.
 */
typedef struct scf_resources {
	scf_handle_t *sr_handle;
	scf_instance_t *sr_inst;
	scf_snapshot_t *sr_snap;
	scf_propertygroup_t *sr_pg;
	scf_property_t *sr_prop;
	scf_value_t *sr_val;
} scf_resources_t;


#endif /* _STRUCTURES_H */
