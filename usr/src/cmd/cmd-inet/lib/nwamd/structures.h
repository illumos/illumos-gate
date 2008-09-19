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

#include <search.h>
#include <net/if.h>
#include <libscf.h>
#include <libdlwlan.h>
#include <libnwam.h>

/*
 * XXX More work on the state machine is needed.  In the future,
 * events will be more like EV_NEWADDR, identifying the actual
 * event that we care about, rather than the source of the event
 * that we originally implemented.  It's a bit of a mix
 * right now.
 */
enum np_event_type {
	EV_LINKDROP,		/* IFF_RUNNING flag dropped */
	EV_LINKUP,		/* Wired link is up */
	EV_LINKFADE,		/* Wireless link has poor signal */
	EV_LINKDISC,		/* Wireless link has disconnected */
	EV_NEWAP,		/* New AP in list / wireless link up */
	EV_USER,		/* User altered interface priority */
	EV_TIMER,		/* Timer(s) have expired */
	EV_SHUTDOWN,		/* Nwamd is shutting down */
	EV_NEWADDR,		/* Address established on interface */
	EV_RESELECT,		/* Client disconnect; retry operations */
	EV_DOOR_TIME,		/* Door server needs new timer */
	EV_ADDIF,		/* New interface detected */
	EV_REMIF,		/* Old interface removed */
	EV_TAKEDOWN		/* Take interface down; AP reselected */
};

/*
 * Three-valued return types; used for cases where the processing terminates in
 * a wait for the user.
 */
typedef enum {
	SUCCESS = 0,
	FAILURE,
	WAITING
} return_vals_t;

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
	char if_name[LIFNAMSIZ];
	sa_family_t if_family;
	uint64_t if_flags;
	uint32_t if_lflags;
	libnwam_interface_type_t if_type;
	uint32_t if_timer_expire;
	boolean_t if_v6onlink;
	boolean_t if_up_attempted;
	dladm_wlan_strength_t if_strength;
	in_addr_t if_ipv4addr;
	pthread_t if_thr;
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
 * This structure contains the intended configuration of the system as
 * differentiated from the actual IPv4 configuration of the system represented
 * by the interface structures.
 *
 * llp structures are held on the list llp_head.  Access to this list is
 * protected by llp_lock.
 */
typedef struct llp {
	struct qelem llp_links;
	char	llp_lname[LIFNAMSIZ];
	int	llp_pri;		/* lower number => higher priority */
	int	llp_fileorder;
	libnwam_interface_type_t llp_type;
	boolean_t llp_failed;		/* interface bringup failed */
	boolean_t llp_waiting;		/* waiting for user interface */
	libnwam_ipv4src_t llp_ipv4src;
	char	*llp_ipv4addrstr;	/* if ipsrc is STATIC */
	char	*llp_ipv6addrstr;	/* if the user provided a static addr */
	boolean_t llp_ipv6onlink;	/* true if we plumb up a v6 interface */

	/* These are used only with door communication */
	boolean_t llp_dhcp_failed;
	boolean_t llp_link_up;
	boolean_t llp_need_wlan;
	boolean_t llp_need_key;
} llp_t;

/*
 * The wireless module uses a separate thread to check AP status and scan for
 * AP changes.  Some wireless operations (such as scanning) may take a long
 * time.  For that reason, we maintain our own wireless interface structure to
 * keep interface-specific wireless state.
 */
typedef struct wireless_if_s {
	struct qelem wi_links;
	char wi_name[LIFNAMSIZ];
	datalink_id_t wi_linkid;
	boolean_t wi_scan_running;
	boolean_t wi_wireless_done;
	boolean_t wi_need_key;
	dladm_wlan_strength_t wi_strength;
} wireless_if_t;

/*
 * These entries are user allocated and should be managed by whoever
 * originates the structure.
 */
struct wireless_lan {
	dladm_wlan_attr_t attrs;
	boolean_t known;
	boolean_t connected;
	boolean_t scanned;
	boolean_t rescan;
	char *essid;
	char *bssid;
	char *signal_strength;
	char *raw_key;
	dladm_wlan_key_t *cooked_key;
	char wl_if_name[LIFNAMSIZ];
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

/*
 * These are used to deliver events to the GUI.  See door.c and libnwam.
 */
typedef struct nwam_descr_event_s {
	libnwam_descr_evtype_t	nde_type;
	libnwam_diag_cause_t	nde_cause;
	struct in_addr		nde_v4address;
	int			nde_prefixlen;
	dladm_wlan_attr_t	nde_attrs;
	struct wireless_lan	*nde_wlans;
	size_t			nde_wlansize;
	char			nde_interface[LIFNAMSIZ];
} nwam_descr_event_t;

typedef enum nwam_door_cmd_type_e {
	ndcNull,
	ndcWaitEvent,
	ndcGetLLPList,
	ndcSetLLPPriority,
	ndcLockLLP,
	ndcGetWlanList,
	ndcSelectWlan,
	ndcWlanKey,
	ndcStartRescan,
	ndcGetKnownAPList,
	ndcAddKnownAP,
	ndcDeleteKnownAP
} nwam_door_cmd_type_t;

typedef struct nwam_door_cmd_s {
	nwam_door_cmd_type_t	ndc_type;
	char			ndc_interface[LIFNAMSIZ];
	int			ndc_priority;
	char			ndc_essid[DLADM_STRSIZE];
	char			ndc_bssid[DLADM_STRSIZE];
	char			ndc_key[DLADM_STRSIZE];
} nwam_door_cmd_t;

typedef struct nwam_llp_data_s {
	uint_t	nld_count;		/* number of llp_t struct following */
	char	nld_selected[LIFNAMSIZ];
	char	nld_locked[LIFNAMSIZ];
} nwam_llp_data_t;

typedef struct nwam_known_ap_s {
	uint_t	nka_count;		/* number of libnwam_known_ap_t */
} nwam_known_ap_t;

#endif /* _STRUCTURES_H */
