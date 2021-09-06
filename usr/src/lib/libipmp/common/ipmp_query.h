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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#ifndef _IPMP_QUERY_H
#define	_IPMP_QUERY_H

#include <sys/types.h>
#include <sys/socket.h>			/* needed by <net/if.h> */
#include <net/if.h>			/* for LIF*NAMSIZ */
#include <ipmp.h>

/*
 * IPMP query interfaces.
 *
 * These interfaces may only be used within ON or after signing a contract
 * with ON.  For documentation, refer to PSARC/2002/615 and PSARC/2007/272.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Assorted enumerations used in the data types described below.
 */
typedef enum ipmp_if_probestate {
	IPMP_PROBE_OK,		/* probes detect no problems */
	IPMP_PROBE_FAILED,	/* probes detect failure */
	IPMP_PROBE_UNKNOWN,	/* probe detection unavailable */
	IPMP_PROBE_DISABLED	/* probe detection disabled */
} ipmp_if_probestate_t;

typedef enum ipmp_if_linkstate {
	IPMP_LINK_UP,		/* link detects up */
	IPMP_LINK_DOWN,		/* link detects down */
	IPMP_LINK_UNKNOWN	/* link detection unavailable */
} ipmp_if_linkstate_t;

typedef enum ipmp_if_flags {
	IPMP_IFFLAG_INACTIVE	= 0x1,
	IPMP_IFFLAG_HWADDRDUP	= 0x2,
	IPMP_IFFLAG_ACTIVE	= 0x4,
	IPMP_IFFLAG_DOWN	= 0x8
} ipmp_if_flags_t;

typedef enum ipmp_addr_state {
	IPMP_ADDR_UP,		/* address is up */
	IPMP_ADDR_DOWN		/* address is down */
} ipmp_addr_state_t;

typedef enum ipmp_if_targmode {
	IPMP_TARG_DISABLED,	/* use of targets is disabled */
	IPMP_TARG_ROUTES,	/* route-learned targets */
	IPMP_TARG_MULTICAST	/* multicast-learned targets */
} ipmp_if_targmode_t;

#define	IPMP_LIST_SIZE(listtype, elsize, nel) \
	((sizeof (ipmp_ ## listtype ## _t) - (elsize)) + ((nel) * (elsize)))

/*
 * Data type describing a list of IPMP groups.
 */
typedef struct ipmp_grouplist {
	uint64_t	gl_sig;
	unsigned int	gl_ngroup;
	uint32_t	gl_pad;
	char		gl_groups[1][LIFGRNAMSIZ];
} ipmp_grouplist_t;

#define	IPMP_GROUPLIST_SIZE(ngr)	\
	IPMP_LIST_SIZE(grouplist, LIFGRNAMSIZ, ngr)

/*
 * Data type describing a list of interfaces.
 */
typedef struct ipmp_iflist {
	unsigned int	il_nif;
	char		il_ifs[1][LIFNAMSIZ];
} ipmp_iflist_t;

#define	IPMP_IFLIST_SIZE(nif)		\
	IPMP_LIST_SIZE(iflist, LIFNAMSIZ, nif)

/*
 * Data type describing a list of addresses.
 */
typedef struct ipmp_addrlist {
	unsigned int		al_naddr;
	uint32_t		al_pad;
	struct sockaddr_storage al_addrs[1];
} ipmp_addrlist_t;

#define	IPMP_ADDRLIST_SIZE(naddr)	\
	IPMP_LIST_SIZE(addrlist, sizeof (struct sockaddr_storage), naddr)

/*
 * Data type describing the state of an IPMP group, and a subset data type
 * used for communication between libipmp and in.mpathd.
 */
typedef struct ipmp_groupinfo {
	char			gr_name[LIFGRNAMSIZ];
	uint64_t		gr_sig;
	ipmp_group_state_t	gr_state;
	ipmp_iflist_t		*gr_iflistp;
	ipmp_addrlist_t		*gr_adlistp;
	char			gr_ifname[LIFNAMSIZ];
	char			gr_m4ifname[LIFNAMSIZ];
	char			gr_m6ifname[LIFNAMSIZ];
	char			gr_bcifname[LIFNAMSIZ];
	unsigned int		gr_fdt;
} ipmp_groupinfo_t;

typedef struct ipmp_groupinfo_xfer {
	char			grx_name[LIFGRNAMSIZ];
	uint64_t		grx_sig;
	ipmp_group_state_t	grx_state;
	char			grx_ifname[LIFNAMSIZ];
	char			grx_m4ifname[LIFNAMSIZ];
	char			grx_m6ifname[LIFNAMSIZ];
	char			grx_bcifname[LIFNAMSIZ];
	unsigned int		grx_fdt;
} ipmp_groupinfo_xfer_t;

/*
 * Data type describing IPMP target information for a particular interface,
 * and a subset data type used for communication between libipmp and in.mpathd.
 */
typedef struct ipmp_targinfo {
	char			it_name[LIFNAMSIZ];
	struct sockaddr_storage	it_testaddr;
	ipmp_if_targmode_t	it_targmode;
	ipmp_addrlist_t		*it_targlistp;
} ipmp_targinfo_t;

typedef struct ipmp_targinfo_xfer {
	char			itx_name[LIFNAMSIZ];
	struct sockaddr_storage	itx_testaddr;
	ipmp_if_targmode_t	itx_targmode;
	uint32_t		itx_pad;
} ipmp_targinfo_xfer_t;


/*
 * Data type describing the IPMP-related state of an interface, and a subset
 * data type used for communication between libipmp and in.mpathd.
 */
typedef struct ipmp_ifinfo {
	char			if_name[LIFNAMSIZ];
	char			if_group[LIFGRNAMSIZ];
	ipmp_if_state_t		if_state;
	ipmp_if_type_t		if_type;
	ipmp_if_linkstate_t	if_linkstate;
	ipmp_if_probestate_t	if_probestate;
	ipmp_if_flags_t		if_flags;
	ipmp_targinfo_t		if_targinfo4;
	ipmp_targinfo_t		if_targinfo6;
} ipmp_ifinfo_t;

typedef struct ipmp_ifinfo_xfer {
	char			ifx_name[LIFNAMSIZ];
	char			ifx_group[LIFGRNAMSIZ];
	ipmp_if_state_t		ifx_state;
	ipmp_if_type_t		ifx_type;
	ipmp_if_linkstate_t	ifx_linkstate;
	ipmp_if_probestate_t	ifx_probestate;
	ipmp_if_flags_t		ifx_flags;
	uint32_t		ifx_pad;
	ipmp_targinfo_xfer_t	ifx_targinfo4;
	ipmp_targinfo_xfer_t	ifx_targinfo6;
} ipmp_ifinfo_xfer_t;


/*
 * Data type describing an IPMP data address.
 */
typedef struct ipmp_addrinfo {
	struct sockaddr_storage	ad_addr;
	ipmp_addr_state_t	ad_state;
	char			ad_group[LIFGRNAMSIZ];
	char			ad_binding[LIFNAMSIZ];
	uint32_t		ad_pad;
} ipmp_addrinfo_t;

typedef enum {
	IPMP_QCONTEXT_LIVE,
	IPMP_QCONTEXT_SNAP
} ipmp_qcontext_t;

extern int  ipmp_setqcontext(ipmp_handle_t, ipmp_qcontext_t);
extern int  ipmp_getgrouplist(ipmp_handle_t, ipmp_grouplist_t **);
extern void ipmp_freegrouplist(ipmp_grouplist_t *);
extern int  ipmp_getgroupinfo(ipmp_handle_t, const char *, ipmp_groupinfo_t **);
extern void ipmp_freegroupinfo(ipmp_groupinfo_t *);
extern int  ipmp_getifinfo(ipmp_handle_t, const char *, ipmp_ifinfo_t **);
extern void ipmp_freeifinfo(ipmp_ifinfo_t *);
extern int  ipmp_getaddrinfo(ipmp_handle_t, const char *,
    struct sockaddr_storage *, ipmp_addrinfo_t **);
extern void ipmp_freeaddrinfo(ipmp_addrinfo_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IPMP_QUERY_H */
