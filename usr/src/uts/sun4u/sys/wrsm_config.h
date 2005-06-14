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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _WRSM_CONFIG_H
#define	_WRSM_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#include <sys/types.h>
#include <sys/wrsm_types.h>
#endif /* _ASM */

/*
 * Macro to guarantee proper pointer alignment in 32 or 64 bit mode
 */
#if defined(_LP64)
#define	WRSM_ALIGN_64(t, n) t n
#define	WRSM_ALIGN_PTR(n) n
#else
#define	WRSM_ALIGN_64(t, n) union {  struct {uint32_t pad; t n; } val; \
				uint64_t align; } u_##n
#define	WRSM_ALIGN_PTR(n) u_##n.val.##n
#endif
/*
 * If any of the data structures in this file are changed,
 * WRSM_CF_IOCTL_VERSION must be incremented.
 */
#define	WRSM_CF_IOCTL_VERSION 0x0e
#define	CONFIG_PROTOCOL_VERSION 0x2

#define	WRSM_MAX_WCIS		(18 * 3) /* CPU WIB + IO WIB in Starcat */
#define	WRSM_MAX_SWITCHES	38
#define	WRSM_HOSTNAMELEN	255

#ifndef _ASM

/*
 *  network routing methods used by preferred_route
 */
typedef enum {
	routing_multihop,
	routing_passthrough
} wrsm_routing_method_t;

/*
 *  network topology types used to give hints to the multihop routing
 *  algorithm.
 */
typedef enum {
	topology_central_switch,
	topology_distributed_switch,
	topology_san_switch
} wrsm_topology_t;

typedef enum {
	ncslice_invalid = 0x0,
	ncslice_passthrough = 0x1,
	ncslice_small_page = 0x2,
	ncslice_large_page = 0x3
} wrsm_ncslice_mode_t;

/*
 * information about each link attached to a wci
 */
typedef struct wrsm_link_data {
	boolean_t present;	 /* does this link exist? */
	wrsm_gnid_t remote_gnid; /* gnid of wci on remote side */
	wrsm_safari_port_t remote_port; /* bus port number of remote wci */
	uint32_t remote_link_num;
} wrsm_link_data_t;


/*
 * routing related information about each wci
 */
struct wrsm_wci_data {
	/*
	 * bus port number - unique within a chassis
	 */
	wrsm_safari_port_t port;
	wrsm_wnodeid_t local_wnode;
	wrsm_gnid_t local_gnid;	 /* This Wci's gnid */
	boolean_t route_map_striping;
	wrsm_topology_t topology_type;
	/* cnodes potentially accessible through this WCI, indexed by wnodeid */
	wrsm_cnodeid_t reachable[WRSM_MAX_WNODES];
	/* gnid to wnode mapping for this WCI, indexed by gnid */
	wrsm_wnodeid_t gnid_to_wnode[WRSM_MAX_WNODES];
	/*
	 * if wnode_reachable[n] == B_TRUE then reachable[n]
	 * contains a valid reachable cnodeid and gnid_to_wnode[n]
	 * contains a valid wnode.
	 */
	boolean_t wnode_reachable[WRSM_MAX_WNODES];
	/* Data about links directly connected to this WCI. */
	wrsm_link_data_t links[WRSM_MAX_LINKS_PER_WCI];
};

/*
 * identify wcis which may be used together for striping
 */
typedef struct wrsm_stripe_group {
	uint32_t group_id;
	int nwcis;
	/*
	 * The order of the wcis in this list determines which address
	 * stripe each wci is assigned.  For Starcat, it is required that
	 * the wcis are in adjacent expanders, that the lower wci is
	 * specified first, and that the first expander has an expander id
	 * that's divisible by 2 (0,2,4..).  Also, for Starcat a maximum of
	 * 2 wcis can be striped.
	 */
	wrsm_safari_port_t wcis[WRSM_MAX_WCIS_PER_STRIPE];
} wrsm_stripe_group_t;

/*
 * Description of one possible method to route data to a remote node.
 */
typedef struct wrsm_preferred_route {
	int striping_level;   /* level of striping desired */
	wrsm_routing_method_t method;
	/*
	 * ordered list of preferred passthrough cnodeids
	 */
	int nswitches;
	wrsm_cnodeid_t switches[WRSM_MAX_SWITCHES];
	/*
	 * A preferred route may indicate either a WCI
	 * to use or a stripe group, but not both.
	 */
	enum {
		route_stripe_group = 1,
		route_wci
	} route_type;
	union {
		uint_t stripe_group_id;
		wrsm_safari_port_t wci_id;
	} route;
} wrsm_preferred_route_t;

/*
 * Information about how to route data to remote network members.
 */
typedef struct wrsm_routing_policy {
	wrsm_cnodeid_t cnodeid;	  /* destination cnodeid */
	/*
	 * must the number of links per WCI be equal?
	 */
	boolean_t wcis_balanced;
	/*
	 * Is the number of stripes more important than the order of
	 * the preferred routes?
	 */
	boolean_t striping_important;
	/*
	 * is passthrough forwarding to this node allowed?
	 */
	boolean_t forwarding_allowed;
	/*
	 * If forwarding is allowed, this bitmask contains import ncslice ids
	 * each remote network member uses to access ncslices exported by this
	 * node.
	 */
	wrsm_ncslice_bitmask_t forwarding_ncslices;

	int nroutes;		  /* number of preferred routes */
	WRSM_ALIGN_64(wrsm_preferred_route_t **, preferred_routes);
} wrsm_routing_policy_t;

/*
 * Information on how to communicate with all the remote rsm nodes.
 */
typedef struct wrsm_routing_data {
	int nwcis;
	int ngroups;
	int npolicy;
	boolean_t other_routes_allowed;

	/*
	 * WCIs owned by this controller, sorted in ascending
	 * order by the safari port id of the wci.
	 */
	WRSM_ALIGN_64(wrsm_wci_data_t **, wcis);
	/*
	 * List of stripe groups sorted in ascending
	 * order by stripe group id.
	 */
	WRSM_ALIGN_64(wrsm_stripe_group_t **, stripe_groups);
	/*
	 * list of routing policies for each remote cnode,
	 * sorted in ascending order by cnodeid.
	 */
	WRSM_ALIGN_64(wrsm_routing_policy_t **, policy);
	/*
	 * Are routes not explicitly listed permitted given the
	 * available connectivity in the network?
	 */
} wrsm_routing_data_t;

/*
 * Information the local node needs to know about every other rsm node
 * in the network.
 */
struct wrsm_net_member {
	wrsm_cnodeid_t cnodeid;		/* wrsm_net member's cnode id */
	wrsm_fmnodeid_t fmnodeid;	/* FM node id */
	char hostname[WRSM_HOSTNAMELEN];

	/*
	 * Exported_ncslices is the ncslices the remote node (the node this
	 * wrsm_net_member is describing) exports memory through; these are
	 * the ncslices the local node (the node that is using the config
	 * containing this wrsm_net_member) uses to import the remote
	 * node's memory.
	 */
	wrsm_node_ncslice_array_t exported_ncslices;

	/*
	 * Imported ncslices is the set of ncslices the remote node uses to
	 * access the local node's exported memory.  Each node may use
	 * different ncslices to import memory from the local node.  The
	 * local node sets up the WCI hardware to allow access using these
	 * ncslices.
	 */
	wrsm_node_ncslice_array_t imported_ncslices;

	/*
	 * ncslice and offset to use to send interrupt based communication to
	 * wrsm_net_member's driver
	 */
	wrsm_ncslice_t comm_ncslice;
	uint64_t comm_offset;
	/*
	 * offset that should be set up to allow interrupts to be received
	 * from wrsm_net_member's driver (the ncslice is the small page
	 * ncslice specified in the exported_ncslices structure of the
	 * wrsm_net_member structure for the local controller).
	 */
	uint64_t local_offset;
};


/*
 * Configuration data about a particular rsm controller.
 *
 * An RSM network is a set of communicating RSM nodes.  A "controller" is
 * the node-local view of an RSM network.  The wrsm_controller_t structure
 * contains the configuration information the node needs to participate in
 * the network.  There is one controller for each node in a network, and
 * the controller_id of each communicating controller matches the network
 * id of the network it is part of.
 */
typedef struct wrsm_controller {
	/*
	 * version number to track changes in the definition of
	 * the data structures in this file.
	 */
	uint32_t config_protocol_version;
	uint32_t controller_id;		/* RSM network id */
	wrsm_fmnodeid_t fmnodeid;  	/* FM node id */
	char hostname[WRSM_HOSTNAMELEN]; /* solaris hostname of local node */
	/*
	 * version number to identify the version of the RSM network
	 * this wrsm_controller_t is participating in.
	 */
	uint64_t version_stamp;
	wrsm_cnodeid_t cnodeid;
	int nmembers;	/* number of elements in the members list */
	/*
	 * routing data
	 */
	WRSM_ALIGN_64(wrsm_routing_data_t *, routing);
	/*
	 * List of network members sorted by cnodeid
	 */
	WRSM_ALIGN_64(wrsm_net_member_t **, members);
} wrsm_controller_t;



/*
 * Used as argument to INITIALCFG, REPLACECFG and GETCFG ioctls
 */
typedef struct wrsm_admin_arg_config {
	uint32_t ioctl_version;
	uint32_t controller_id;
	uint64_t controller_data_size;
	WRSM_ALIGN_64(wrsm_controller_t *, controller);
} wrsm_admin_arg_config_t;

/*
 * Used as argument to INSTALLCFG, CHECKCFG, and ENABLECFG ioctls
 */
typedef struct wrsm_admin_arg_wci {
	uint32_t ioctl_version;
	uint32_t controller_id;
	uint64_t nwcis;
	WRSM_ALIGN_64(wrsm_safari_port_t *, wci_ids);
} wrsm_admin_arg_wci_t;

/*
 * Used as argument to CTLR_PING ioctl
 */
typedef struct wrsm_ping_arg {
	uint32_t ioctl_version;
	wrsm_cnodeid_t target;
	uint32_t count;
	uint64_t time;   /* total ping time in us */
} wrsm_ping_arg_t;

/*
 * Used as argument to CTLR_MBOX ioctl
 */
typedef struct wrsm_link_arg {
	uint32_t ioctl_version;
	int cmd;
	wrsm_safari_port_t wci_id;
	wrsm_linkid_t link_num;
	uint32_t led_state;
	uint32_t link_state;
} wrsm_link_arg_t;


/*
 * Used as argument to CTLR_SEG ioctl
 */
typedef struct wrsm_seg_arg {
	uint32_t ioctl_version;
	int cmd;
	uint_t segid;
	uint_t addr;
	uint64_t bytes;
	uint64_t offset;
	uint64_t length;
	char *datap;
	uint_t barrier_mode;
} wrsm_seg_arg_t;


/*
 * Used as argument to CTLR_SESS ioctls
 */
typedef struct wrsm_sess_arg {
	uint32_t ioctl_version;
	int cmd;
	wrsm_cnodeid_t cnodeid;
	wrsm_cnode_bitmask_t cnode_bitmask;
} wrsm_sess_arg_t;

extern void *wrsm_cf_pack(wrsm_controller_t *cont, int *sizep);

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_CONFIG_H */
