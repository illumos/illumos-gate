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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _WRSM_COMMON_H
#define	_WRSM_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/param.h>
#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/thread.h>
#include <sys/kstat.h>

#ifdef _KERNEL
#include <vm/page.h>
#include <sys/ddidevmap.h>
#include <sys/rsm/rsmpi.h>
#endif
#include <sys/wci_offsets.h>
#include <sys/wrsm_types.h>


#ifdef	__cplusplus
extern "C" {
#endif

typedef wrsm_ncslice_bitmask_t ncslice_bitmask_t;
typedef wrsm_cnode_bitmask_t cnode_bitmask_t;
typedef wrsm_wnode_bitmask_t wnode_bitmask_t;
typedef wrsm_fmnodeid_t fmnodeid_t;
typedef wrsm_cnodeid_t cnodeid_t;
typedef wrsm_wnodeid_t wnodeid_t;
typedef wrsm_gnid_t gnid_t;
typedef wrsm_ncslice_t ncslice_t;
typedef wrsm_linkid_t linkid_t;
typedef wrsm_safari_port_t safari_port_t;

/*
 * Cacheline-size related constants
 */
#define	WRSM_CACHELINE_SIZE	64
#define	WRSM_CACHELINE_SHIFT	6
#define	WRSM_CACHELINE_MASK	(WRSM_CACHELINE_SIZE - 1)

/*
 * This is a more meaningful name for the errno return value of 0. It
 * is used by functions that return/expect errno values.
 */
#define	WRSM_SUCCESS	0

/*
 * Hash for fmnodeid to node pointer mapping.
 * Most likely the fmnodeid will be a low integer.
 */
#define	WRSM_CNODE_HASH_SIZE	0x100	/*  number of entries in hash table */
#define	WRSM_CNODE_HASH_MASK	(WRSM_CNODE_HASH_SIZE - 1)
#define	WRSM_CNODE_HASH_FUNC(r) \
		(((uint_t)r) & WRSM_CNODE_HASH_MASK)

/*
 * 8 is the lower bound allowed before we are required to start freezing
 * Request Agent (RAG) instances per PRM
 */
#define	WRSM_RAG_FREEZE_NODE_LIMIT 8
/*
 * additional bit mask manipulation macros
 */
uint_t wrsmset_cmp(uint32_t *s1, uint32_t *s2, int masksize);
uint_t wrsmset_isnull(uint32_t *s, int masksize);

/* Copy bits from set1 to set2 */
#define	WRSMSET_COPY(src, dest) bcopy(&(src), &(dest), sizeof (src))
#define	WRSMSET_ISEQUAL(set1, set2) \
	(wrsmset_cmp((uint32_t *)&(set1), (uint32_t *)&(set2),	\
	WRSMMASKSIZE(set1)))
#define	WRSMSET_ISNULL(set) \
	(wrsmset_isnull((uint32_t *)&(set), WRSMMASKSIZE(set)))

#define	WRSMSET_OR(set1, set2) {				\
		int _i;						\
		uint32_t *_s1 = (uint32_t *)&(set1);		\
		uint32_t *_s2 = (uint32_t *)&(set2);		\
		for (_i = 0; _i < WRSMMASKSIZE(set1); _i++)	\
			*_s1++ |= *_s2++;			\
	}

#define	WRSMSET_AND(set1, set2) {				\
		int _i;						\
		uint32_t *_s1 = (uint32_t *)&(set1);		\
		uint32_t *_s2 = (uint32_t *)&(set2);		\
		for (_i = 0; _i < WRSMMASKSIZE(set1); _i++)	\
			*_s1++ &= *_s2++;			\
	}

#define	WRSMSET_DIFF(set1, set2) {				\
		int _i;						\
		uint32_t *_s1 = (uint32_t *)&(set1);		\
		uint32_t *_s2 = (uint32_t *)&(set2);		\
		for (_i = 0; _i < WRSMMASKSIZE(set1); _i++)	\
			*_s1++ &= ~*_s2++;			\
	}


/*
 * in the node->link_stripes field, this is the number of bits to
 * shift to get to the bit referring to the next link in the same wci
 */
#define	BBIT_LINK_STRIDE	4


/* opaque type for LC's handle */
typedef struct wrsm_soft_state *lcwci_handle_t;
/* opaque type for NC's handle */
typedef struct wrsm_ncwci *ncwci_handle_t;


/*
 * typedefs for opaque structure definitions (for structures private to
 * particular wrsm modules, declared in module specific header files)
 */
typedef struct wrsm_node_routeinfo wrsm_node_routeinfo_t;
typedef struct wrsm_node_memseg wrsm_node_memseg_t;

typedef struct wrsm_transport wrsm_transport_t;
typedef struct wrsm_session wrsm_session_t;
typedef struct wrsm_cmmu_alloc wrsm_cmmu_alloc_t;
typedef struct wrsm_interrupt wrsm_interrupt_t;
typedef struct wrsm_nr wrsm_nr_t;
typedef struct wrsm_memseg wrsm_memseg_t;

typedef struct __rsm_controller_handle wrsm_network_t;
typedef struct wrsm_node wrsm_node_t;

typedef struct wrsm_cmmu_tuple wrsm_cmmu_tuple_t;



/*
 * configuration states
 */
typedef enum {
	wrsm_disabled,	/* new config, no ncslice rerouting allowed */
	wrsm_pending,	/* can reroute using old/new config intersection */
	wrsm_installed,	/* ncslice routes are not using old config */
	wrsm_installed_up,	/* all links in new config are up */
	wrsm_enabled		/* ncslice routes are using new config */
} wrsm_availability_t;

#define	WRSM_INSTALLED(n)			\
	((n)->availability == wrsm_enabled ||	\
	(n)->availability == wrsm_installed ||	\
	(n)->availability == wrsm_installed_up)

/*
 * state of communication to node
 */
typedef enum {
	wrsm_node_needroute,	/* no ncslice routes to node */
	wrsm_node_haveroute	/* ncslice route set up */
} wrsm_node_comm_state_t;

#define	WRSM_NODE_HAVE_ROUTE(n) ((n)->state == wrsm_node_haveroute)



/*
 * information about a remote node participating in an RSM network
 */
struct wrsm_node {
	wrsm_network_t *network;		/* this node's RSM network */
	wrsm_net_member_t *config;		/* node config info */
	wrsm_availability_t availability;	/* configuration state */
	wrsm_node_comm_state_t state;		/* communication state */
	uint32_t *link_stripesp;		/* stripe info for barrier */

	/*
	 * wrsm module private info about node
	 */
	wrsm_node_routeinfo_t *routeinfo;	/* routing config for node */

	/*
	 * The following structures are for tracking RSMPI data structures.
	 */
	wrsm_node_memseg_t *memseg;		/* RSMPI segments */
	caddr_t cesr_vaddr;		/* vaddr of WCI CESRs for barriers */
	caddr_t lockout_vaddr;		/* vaddr of write lockout page */

	/*
	 * links
	 */
	struct wrsm_node *hash;		/* linked list for hash table */
};




/*
 * The RSM controller's view of the RSM network it is participating in.
 */
#ifdef _KERNEL
struct __rsm_controller_handle {
	uint32_t rsm_ctlr_id;		/* ctlr id == device instance # */
	kmutex_t lock;
	dev_info_t *dip;		/* dev_info_t for controller */
	uint64_t version_stamp;		/* configuration version number */
	boolean_t registered;		/* registered with RSMPI module */
	wrsm_availability_t availability; /* state of the configuration */
	cnodeid_t cnodeid;		/* local node's cnodeid */
	wrsm_node_t *mynode;		/* local node info */
	wrsm_node_ncslice_array_t exported_ncslices;
					/* ncslices local node exports */
	int wrsm_ncslice_users[WRSM_MAX_NCSLICES];
					/* per ncslice count of ncslice users */
	boolean_t have_lg_page_ncslice;	/* any ncslices for large pages? */
	wrsm_cmmu_tuple_t *errorpage_tuple; /* loopback error CMMU entry */
	pfn_t errorpage_pfn;		/* pfn for loopback error page */
	kmutex_t errorpage_lock;	/* updating errorpage_mappings */
	uint_t errorpage_mappings;	/* # mappings to error page */

	wrsm_node_t *nodes[WRSM_MAX_CNODES]; /* array of remote node info */
	wrsm_node_t *node_hash[WRSM_CNODE_HASH_SIZE]; /* nodeinfo hashtable */

	/*
	 * route_umem is the kernel allocated address space that
	 * can also be mapped to user space. both route_countp
	 * and reroutingp will point to an address range within
	 * route_umem. the wrsm plug-in uses this address range
	 * when it mmaps route_counter and rerouting to user space
	 * the plug-in requires these fields when it must preform
	 * explicit barriers, as the plugin must check to see if the
	 * routing has changed.
	 */
	void *route_umem;		/* returned by ddi_umem_alloc  */
	uint32_t *route_counterp;	/* increment on ncslice route change */
	uint32_t *reroutingp;		/* in process of ncslice rerouting */
	ddi_umem_cookie_t route_cookie; /* cookie needed to free *route_umem */
	uint_t passthrough_routes;	/* how many PT routes been set up? */

	/* keeps track of controller opened by plugin library */
	boolean_t is_controller_open;

	/*
	 * wrsm module private info about network
	 */
	wrsm_interrupt_t *interrupt;
	wrsm_transport_t *transport;	/* transport info */
	wrsm_session_t *session;	/* session info */
	wrsm_cmmu_alloc_t *cmmu;	/* cmmu allocator info */
	wrsm_nr_t *nr;			/* network router info */
	int wrsm_num_nodes;		/* number of nodes in this network */
	boolean_t free_rag_instance;	/* frozen RAG instances can be freed */

	/*
	 * NC info
	 */
	boolean_t auto_enable;		/* links-up/timeout enables network */
	timeout_id_t enable_timeout_id;

	/*
	 * links
	 */
	wrsm_network_t *next;

	/*
	 * RSMPI information
	 */
	wrsm_memseg_t *memseg;		/* RSMPI segments */
	rsm_controller_attr_t attr;	/* RSMPI controller attributes */

	/*
	 * Kstat for the controller
	 */
	kstat_t *wrsm_rsmpi_stat_ksp;
	uint_t num_reconfigs;
	uint_t sendqs_num;
	uint_t handler_num;
};

#endif /* KERNEL */

extern dev_info_t *wrsm_ncslice_dip;	/* devinfo for ncslice mappings */
#define	PROTOCOLS_SUPPORTED	1
/*
 * The protocol_versions_supported is a bit mask representing all the
 * protocol versions that this driver supports.
 */
extern uint32_t protocol_versions_supported;
extern int protocol_version;		/* version native to this driver */

wrsm_node_t *
wrsm_fmnodeid_to_node(wrsm_network_t *network,
    fmnodeid_t fmnodeid);

int
wrsm_fmnodeid_to_cnodeid(wrsm_network_t *network,
    fmnodeid_t fmnodeid, cnodeid_t *cnodeidp);

wrsm_network_t *wrsm_dip_to_network(dev_info_t *dip);

/*
 * initialization and teardown functions for WRSM modules - called from
 * driver _init and _fini
 */
extern void wrsm_nc_init(void);
extern int wrsm_nc_fini(void);
/*
 * Functions which make up wrsm_nc_fini() - these can be called individually
 * to separate checks from cleanup - called from driver _fini
 */
extern int wrsm_nc_check(void);
extern void wrsm_nc_cleanup(void);

#ifdef DEBUG
#define	DEBUG_LOG
extern void dprintnodes(cnode_bitmask_t);
#define	DPRINTNODES(c) dprintnodes(c)
extern kmutex_t wrsmdbglock;
extern int wrsmdbginit;
extern char wrsmdbgbuf[];
extern int wrsmdbgsize;
extern int wrsmdbgnext;
void wrsmdprintf(int ce, const char *fmt, ...);
#else
#define	DPRINTNODES(c)
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_COMMON_H */
