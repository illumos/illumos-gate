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
/* Copyright (c) 1990 Mentat Inc. */

/*
 * This file contains the interface control functions for IP.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/strlog.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/debug.h>
#include <sys/zone.h>
#include <sys/sunldi.h>
#include <sys/file.h>
#include <sys/bitmap.h>
#include <sys/cpuvar.h>
#include <sys/time.h>
#include <sys/ctype.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/isa_defs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/igmp_var.h>
#include <sys/policy.h>
#include <sys/ethernet.h>
#include <sys/callb.h>
#include <sys/md5.h>

#include <inet/common.h>   /* for various inet/mi.h and inet/nd.h needs */
#include <inet/mi.h>
#include <inet/nd.h>
#include <inet/arp.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip6_asp.h>
#include <inet/tcp.h>
#include <inet/ip_multi.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_rts.h>
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <inet/ip_impl.h>
#include <inet/tun.h>
#include <inet/sctp_ip.h>
#include <inet/ip_netinfo.h>

#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>
#include <inet/sadb.h>
#include <inet/ipsec_impl.h>
#include <sys/iphada.h>

#include <netinet/igmp.h>
#include <inet/ip_listutils.h>
#include <inet/ipclassifier.h>
#include <sys/mac_client.h>
#include <sys/dld.h>

#include <sys/systeminfo.h>
#include <sys/bootconf.h>

#include <sys/tsol/tndb.h>
#include <sys/tsol/tnet.h>

/* The character which tells where the ill_name ends */
#define	IPIF_SEPARATOR_CHAR	':'

/* IP ioctl function table entry */
typedef struct ipft_s {
	int	ipft_cmd;
	pfi_t	ipft_pfi;
	int	ipft_min_size;
	int	ipft_flags;
} ipft_t;
#define	IPFT_F_NO_REPLY		0x1	/* IP ioctl does not expect any reply */
#define	IPFT_F_SELF_REPLY	0x2	/* ioctl callee does the ioctl reply */

typedef struct ip_sock_ar_s {
	union {
		area_t	ip_sock_area;
		ared_t	ip_sock_ared;
		areq_t	ip_sock_areq;
	} ip_sock_ar_u;
	queue_t	*ip_sock_ar_q;
} ip_sock_ar_t;

static int	nd_ill_forward_get(queue_t *, mblk_t *, caddr_t, cred_t *);
static int	nd_ill_forward_set(queue_t *q, mblk_t *mp,
		    char *value, caddr_t cp, cred_t *ioc_cr);

static boolean_t ill_is_quiescent(ill_t *);
static boolean_t ip_addr_ok_v4(ipaddr_t addr, ipaddr_t subnet_mask);
static ip_m_t	*ip_m_lookup(t_uscalar_t mac_type);
static int	ip_sioctl_addr_tail(ipif_t *ipif, sin_t *sin, queue_t *q,
    mblk_t *mp, boolean_t need_up);
static int	ip_sioctl_dstaddr_tail(ipif_t *ipif, sin_t *sin, queue_t *q,
    mblk_t *mp, boolean_t need_up);
static int	ip_sioctl_slifzone_tail(ipif_t *ipif, zoneid_t zoneid,
    queue_t *q, mblk_t *mp, boolean_t need_up);
static int	ip_sioctl_flags_tail(ipif_t *ipif, uint64_t flags, queue_t *q,
    mblk_t *mp);
static int	ip_sioctl_netmask_tail(ipif_t *ipif, sin_t *sin, queue_t *q,
    mblk_t *mp);
static int	ip_sioctl_subnet_tail(ipif_t *ipif, in6_addr_t, in6_addr_t,
    queue_t *q, mblk_t *mp, boolean_t need_up);
static int	ip_sioctl_plink_ipmod(ipsq_t *ipsq, queue_t *q, mblk_t *mp,
    int ioccmd, struct linkblk *li, boolean_t doconsist);
static ipaddr_t	ip_subnet_mask(ipaddr_t addr, ipif_t **, ip_stack_t *);
static void	ip_wput_ioctl(queue_t *q, mblk_t *mp);
static void	ipsq_flush(ill_t *ill);

static	int	ip_sioctl_token_tail(ipif_t *ipif, sin6_t *sin6, int addrlen,
    queue_t *q, mblk_t *mp, boolean_t need_up);
static void	ipsq_delete(ipsq_t *);

static ipif_t	*ipif_allocate(ill_t *ill, int id, uint_t ire_type,
    boolean_t initialize, boolean_t insert);
static void	ipif_check_bcast_ires(ipif_t *test_ipif);
static ire_t	**ipif_create_bcast_ires(ipif_t *ipif, ire_t **irep);
static boolean_t ipif_comp_multi(ipif_t *old_ipif, ipif_t *new_ipif,
		    boolean_t isv6);
static void	ipif_down_delete_ire(ire_t *ire, char *ipif);
static void	ipif_delete_cache_ire(ire_t *, char *);
static int	ipif_logical_down(ipif_t *ipif, queue_t *q, mblk_t *mp);
static void	ipif_free(ipif_t *ipif);
static void	ipif_free_tail(ipif_t *ipif);
static void	ipif_mtu_change(ire_t *ire, char *ipif_arg);
static void	ipif_recreate_interface_routes(ipif_t *old_ipif, ipif_t *ipif);
static void	ipif_set_default(ipif_t *ipif);
static int	ipif_set_values(queue_t *q, mblk_t *mp,
    char *interf_name, uint_t *ppa);
static int	ipif_set_values_tail(ill_t *ill, ipif_t *ipif, mblk_t *mp,
    queue_t *q);
static ipif_t	*ipif_lookup_on_name(char *name, size_t namelen,
    boolean_t do_alloc, boolean_t *exists, boolean_t isv6, zoneid_t zoneid,
    queue_t *q, mblk_t *mp, ipsq_func_t func, int *error, ip_stack_t *);
static void	ipif_update_other_ipifs(ipif_t *old_ipif);

static int	ill_alloc_ppa(ill_if_t *, ill_t *);
static int	ill_arp_off(ill_t *ill);
static int	ill_arp_on(ill_t *ill);
static void	ill_delete_interface_type(ill_if_t *);
static int	ill_dl_up(ill_t *ill, ipif_t *ipif, mblk_t *mp, queue_t *q);
static void	ill_dl_down(ill_t *ill);
static void	ill_down(ill_t *ill);
static void	ill_downi(ire_t *ire, char *ill_arg);
static void	ill_free_mib(ill_t *ill);
static void	ill_glist_delete(ill_t *);
static void	ill_phyint_reinit(ill_t *ill);
static void	ill_set_nce_router_flags(ill_t *, boolean_t);
static void	ill_set_phys_addr_tail(ipsq_t *, queue_t *, mblk_t *, void *);
static ip_v6intfid_func_t ip_ether_v6intfid, ip_ib_v6intfid;
static ip_v6intfid_func_t ip_ipmp_v6intfid, ip_nodef_v6intfid;
static ip_v6mapinfo_func_t ip_ether_v6mapinfo, ip_ib_v6mapinfo;
static ip_v4mapinfo_func_t ip_ether_v4mapinfo, ip_ib_v4mapinfo;
static void	ipif_save_ire(ipif_t *, ire_t *);
static void	ipif_remove_ire(ipif_t *, ire_t *);
static void 	ip_cgtp_bcast_add(ire_t *, ire_t *, ip_stack_t *);
static void 	ip_cgtp_bcast_delete(ire_t *, ip_stack_t *);
static void	phyint_free(phyint_t *);

/*
 * Per-ill IPsec capabilities management.
 */
static ill_ipsec_capab_t *ill_ipsec_capab_alloc(void);
static void	ill_ipsec_capab_free(ill_ipsec_capab_t *);
static void	ill_ipsec_capab_add(ill_t *, uint_t, boolean_t);
static void	ill_ipsec_capab_delete(ill_t *, uint_t);
static boolean_t ill_ipsec_capab_resize_algparm(ill_ipsec_capab_t *, int);
static void ill_capability_dispatch(ill_t *, mblk_t *, dl_capability_sub_t *,
    boolean_t);
static void ill_capability_id_ack(ill_t *, mblk_t *, dl_capability_sub_t *);
static void ill_capability_mdt_ack(ill_t *, mblk_t *, dl_capability_sub_t *);
static void ill_capability_mdt_reset_fill(ill_t *, mblk_t *);
static void ill_capability_ipsec_ack(ill_t *, mblk_t *, dl_capability_sub_t *);
static void ill_capability_ipsec_reset_fill(ill_t *, mblk_t *);
static void ill_capability_hcksum_ack(ill_t *, mblk_t *, dl_capability_sub_t *);
static void ill_capability_hcksum_reset_fill(ill_t *, mblk_t *);
static void ill_capability_zerocopy_ack(ill_t *, mblk_t *,
    dl_capability_sub_t *);
static void ill_capability_zerocopy_reset_fill(ill_t *, mblk_t *);
static int  ill_capability_ipsec_reset_size(ill_t *, int *, int *, int *,
    int *);
static void	ill_capability_dld_reset_fill(ill_t *, mblk_t *);
static void	ill_capability_dld_ack(ill_t *, mblk_t *,
		    dl_capability_sub_t *);
static void	ill_capability_dld_enable(ill_t *);
static void	ill_capability_ack_thr(void *);
static void	ill_capability_lso_enable(ill_t *);
static void	ill_capability_send(ill_t *, mblk_t *);

static ill_t	*ill_prev_usesrc(ill_t *);
static int	ill_relink_usesrc_ills(ill_t *, ill_t *, uint_t);
static void	ill_disband_usesrc_group(ill_t *);
static void	conn_cleanup_stale_ire(conn_t *, caddr_t);

#ifdef DEBUG
static  void    ill_trace_cleanup(const ill_t *);
static  void    ipif_trace_cleanup(const ipif_t *);
#endif

/*
 * if we go over the memory footprint limit more than once in this msec
 * interval, we'll start pruning aggressively.
 */
int ip_min_frag_prune_time = 0;

/*
 * max # of IPsec algorithms supported.  Limited to 1 byte by PF_KEY
 * and the IPsec DOI
 */
#define	MAX_IPSEC_ALGS	256

#define	BITSPERBYTE	8
#define	BITS(type)	(BITSPERBYTE * (long)sizeof (type))

#define	IPSEC_ALG_ENABLE(algs, algid) \
		((algs)[(algid) / BITS(ipsec_capab_elem_t)] |= \
		(1 << ((algid) % BITS(ipsec_capab_elem_t))))

#define	IPSEC_ALG_IS_ENABLED(algid, algs) \
		((algs)[(algid) / BITS(ipsec_capab_elem_t)] & \
		(1 << ((algid) % BITS(ipsec_capab_elem_t))))

typedef uint8_t ipsec_capab_elem_t;

/*
 * Per-algorithm parameters.  Note that at present, only encryption
 * algorithms have variable keysize (IKE does not provide a way to negotiate
 * auth algorithm keysize).
 *
 * All sizes here are in bits.
 */
typedef struct
{
	uint16_t	minkeylen;
	uint16_t	maxkeylen;
} ipsec_capab_algparm_t;

/*
 * Per-ill capabilities.
 */
struct ill_ipsec_capab_s {
	ipsec_capab_elem_t *encr_hw_algs;
	ipsec_capab_elem_t *auth_hw_algs;
	uint32_t algs_size;	/* size of _hw_algs in bytes */
	/* algorithm key lengths */
	ipsec_capab_algparm_t *encr_algparm;
	uint32_t encr_algparm_size;
	uint32_t encr_algparm_end;
};

/*
 * The field values are larger than strictly necessary for simple
 * AR_ENTRY_ADDs but the padding lets us accomodate the socket ioctls.
 */
static area_t	ip_area_template = {
	AR_ENTRY_ADD,			/* area_cmd */
	sizeof (ip_sock_ar_t) + (IP_ADDR_LEN*2) + sizeof (struct sockaddr_dl),
					/* area_name_offset */
	/* area_name_length temporarily holds this structure length */
	sizeof (area_t),			/* area_name_length */
	IP_ARP_PROTO_TYPE,		/* area_proto */
	sizeof (ip_sock_ar_t),		/* area_proto_addr_offset */
	IP_ADDR_LEN,			/* area_proto_addr_length */
	sizeof (ip_sock_ar_t) + IP_ADDR_LEN,
					/* area_proto_mask_offset */
	0,				/* area_flags */
	sizeof (ip_sock_ar_t) + IP_ADDR_LEN + IP_ADDR_LEN,
					/* area_hw_addr_offset */
	/* Zero length hw_addr_length means 'use your idea of the address' */
	0				/* area_hw_addr_length */
};

/*
 * AR_ENTRY_ADD/DELETE templates have been added for IPv6 external resolver
 * support
 */
static area_t	ip6_area_template = {
	AR_ENTRY_ADD,			/* area_cmd */
	sizeof (ip_sock_ar_t) + (IPV6_ADDR_LEN*2) + sizeof (sin6_t),
					/* area_name_offset */
	/* area_name_length temporarily holds this structure length */
	sizeof (area_t),			/* area_name_length */
	IP_ARP_PROTO_TYPE,		/* area_proto */
	sizeof (ip_sock_ar_t),		/* area_proto_addr_offset */
	IPV6_ADDR_LEN,			/* area_proto_addr_length */
	sizeof (ip_sock_ar_t) + IPV6_ADDR_LEN,
					/* area_proto_mask_offset */
	0,				/* area_flags */
	sizeof (ip_sock_ar_t) + IPV6_ADDR_LEN + IPV6_ADDR_LEN,
					/* area_hw_addr_offset */
	/* Zero length hw_addr_length means 'use your idea of the address' */
	0				/* area_hw_addr_length */
};

static ared_t	ip_ared_template = {
	AR_ENTRY_DELETE,
	sizeof (ared_t) + IP_ADDR_LEN,
	sizeof (ared_t),
	IP_ARP_PROTO_TYPE,
	sizeof (ared_t),
	IP_ADDR_LEN,
	0
};

static ared_t	ip6_ared_template = {
	AR_ENTRY_DELETE,
	sizeof (ared_t) + IPV6_ADDR_LEN,
	sizeof (ared_t),
	IP_ARP_PROTO_TYPE,
	sizeof (ared_t),
	IPV6_ADDR_LEN,
	0
};

/*
 * A template for an IPv6 AR_ENTRY_QUERY template has not been created, as
 * as the areq doesn't include an IP address in ill_dl_up() (the only place a
 * areq is used).
 */
static areq_t	ip_areq_template = {
	AR_ENTRY_QUERY,			/* cmd */
	sizeof (areq_t)+(2*IP_ADDR_LEN),	/* name offset */
	sizeof (areq_t),	/* name len (filled by ill_arp_alloc) */
	IP_ARP_PROTO_TYPE,		/* protocol, from arps perspective */
	sizeof (areq_t),			/* target addr offset */
	IP_ADDR_LEN,			/* target addr_length */
	0,				/* flags */
	sizeof (areq_t) + IP_ADDR_LEN,	/* sender addr offset */
	IP_ADDR_LEN,			/* sender addr length */
	AR_EQ_DEFAULT_XMIT_COUNT,	/* xmit_count */
	AR_EQ_DEFAULT_XMIT_INTERVAL,	/* (re)xmit_interval in milliseconds */
	AR_EQ_DEFAULT_MAX_BUFFERED	/* max # of requests to buffer */
	/* anything else filled in by the code */
};

static arc_t	ip_aru_template = {
	AR_INTERFACE_UP,
	sizeof (arc_t),		/* Name offset */
	sizeof (arc_t)		/* Name length (set by ill_arp_alloc) */
};

static arc_t	ip_ard_template = {
	AR_INTERFACE_DOWN,
	sizeof (arc_t),		/* Name offset */
	sizeof (arc_t)		/* Name length (set by ill_arp_alloc) */
};

static arc_t	ip_aron_template = {
	AR_INTERFACE_ON,
	sizeof (arc_t),		/* Name offset */
	sizeof (arc_t)		/* Name length (set by ill_arp_alloc) */
};

static arc_t	ip_aroff_template = {
	AR_INTERFACE_OFF,
	sizeof (arc_t),		/* Name offset */
	sizeof (arc_t)		/* Name length (set by ill_arp_alloc) */
};

static arma_t	ip_arma_multi_template = {
	AR_MAPPING_ADD,
	sizeof (arma_t) + 3*IP_ADDR_LEN + IP_MAX_HW_LEN,
				/* Name offset */
	sizeof (arma_t),	/* Name length (set by ill_arp_alloc) */
	IP_ARP_PROTO_TYPE,
	sizeof (arma_t),			/* proto_addr_offset */
	IP_ADDR_LEN,				/* proto_addr_length */
	sizeof (arma_t) + IP_ADDR_LEN,		/* proto_mask_offset */
	sizeof (arma_t) + 2*IP_ADDR_LEN,	/* proto_extract_mask_offset */
	ACE_F_PERMANENT | ACE_F_MAPPING,	/* flags */
	sizeof (arma_t) + 3*IP_ADDR_LEN,	/* hw_addr_offset */
	IP_MAX_HW_LEN,				/* hw_addr_length */
	0,					/* hw_mapping_start */
};

static ipft_t	ip_ioctl_ftbl[] = {
	{ IP_IOC_IRE_DELETE, ip_ire_delete, sizeof (ipid_t), 0 },
	{ IP_IOC_IRE_DELETE_NO_REPLY, ip_ire_delete, sizeof (ipid_t),
		IPFT_F_NO_REPLY },
	{ IP_IOC_IRE_ADVISE_NO_REPLY, ip_ire_advise, sizeof (ipic_t),
		IPFT_F_NO_REPLY },
	{ IP_IOC_RTS_REQUEST, ip_rts_request, 0, IPFT_F_SELF_REPLY },
	{ 0 }
};

/* Simple ICMP IP Header Template */
static ipha_t icmp_ipha = {
	IP_SIMPLE_HDR_VERSION, 0, 0, 0, 0, 0, IPPROTO_ICMP
};

/* Flag descriptors for ip_ipif_report */
static nv_t	ipif_nv_tbl[] = {
	{ IPIF_UP,		"UP" },
	{ IPIF_BROADCAST,	"BROADCAST" },
	{ ILLF_DEBUG,		"DEBUG" },
	{ PHYI_LOOPBACK,	"LOOPBACK" },
	{ IPIF_POINTOPOINT,	"POINTOPOINT" },
	{ ILLF_NOTRAILERS,	"NOTRAILERS" },
	{ PHYI_RUNNING,		"RUNNING" },
	{ ILLF_NOARP,		"NOARP" },
	{ PHYI_PROMISC,		"PROMISC" },
	{ PHYI_ALLMULTI,	"ALLMULTI" },
	{ PHYI_INTELLIGENT,	"INTELLIGENT" },
	{ ILLF_MULTICAST,	"MULTICAST" },
	{ PHYI_MULTI_BCAST,	"MULTI_BCAST" },
	{ IPIF_UNNUMBERED,	"UNNUMBERED" },
	{ IPIF_DHCPRUNNING,	"DHCP" },
	{ IPIF_PRIVATE,		"PRIVATE" },
	{ IPIF_NOXMIT,		"NOXMIT" },
	{ IPIF_NOLOCAL,		"NOLOCAL" },
	{ IPIF_DEPRECATED,	"DEPRECATED" },
	{ IPIF_PREFERRED,	"PREFERRED" },
	{ IPIF_TEMPORARY,	"TEMPORARY" },
	{ IPIF_ADDRCONF,	"ADDRCONF" },
	{ PHYI_VIRTUAL,		"VIRTUAL" },
	{ ILLF_ROUTER,		"ROUTER" },
	{ ILLF_NONUD,		"NONUD" },
	{ IPIF_ANYCAST,		"ANYCAST" },
	{ ILLF_NORTEXCH,	"NORTEXCH" },
	{ ILLF_IPV4,		"IPV4" },
	{ ILLF_IPV6,		"IPV6" },
	{ IPIF_NOFAILOVER,	"NOFAILOVER" },
	{ PHYI_FAILED,		"FAILED" },
	{ PHYI_STANDBY,		"STANDBY" },
	{ PHYI_INACTIVE,	"INACTIVE" },
	{ PHYI_OFFLINE,		"OFFLINE" },
	{ PHYI_IPMP,		"IPMP" }
};

static uchar_t	ip_six_byte_all_ones[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static ip_m_t   ip_m_tbl[] = {
	{ DL_ETHER, IFT_ETHER, ip_ether_v4mapinfo, ip_ether_v6mapinfo,
	    ip_ether_v6intfid },
	{ DL_CSMACD, IFT_ISO88023, ip_ether_v4mapinfo, ip_ether_v6mapinfo,
	    ip_nodef_v6intfid },
	{ DL_TPB, IFT_ISO88024, ip_ether_v4mapinfo, ip_ether_v6mapinfo,
	    ip_nodef_v6intfid },
	{ DL_TPR, IFT_ISO88025, ip_ether_v4mapinfo, ip_ether_v6mapinfo,
	    ip_nodef_v6intfid },
	{ DL_FDDI, IFT_FDDI, ip_ether_v4mapinfo, ip_ether_v6mapinfo,
	    ip_ether_v6intfid },
	{ DL_IB, IFT_IB, ip_ib_v4mapinfo, ip_ib_v6mapinfo,
	    ip_ib_v6intfid },
	{ SUNW_DL_VNI, IFT_OTHER, NULL, NULL, NULL },
	{ SUNW_DL_IPMP, IFT_OTHER, NULL, NULL, ip_ipmp_v6intfid },
	{ DL_OTHER, IFT_OTHER, ip_ether_v4mapinfo, ip_ether_v6mapinfo,
	    ip_nodef_v6intfid }
};

static ill_t	ill_null;		/* Empty ILL for init. */
char	ipif_loopback_name[] = "lo0";
static char *ipv4_forward_suffix = ":ip_forwarding";
static char *ipv6_forward_suffix = ":ip6_forwarding";
static	sin6_t	sin6_null;	/* Zero address for quick clears */
static	sin_t	sin_null;	/* Zero address for quick clears */

/* When set search for unused ipif_seqid */
static ipif_t	ipif_zero;

/*
 * ppa arena is created after these many
 * interfaces have been plumbed.
 */
uint_t	ill_no_arena = 12;	/* Setable in /etc/system */

/*
 * Allocate per-interface mibs.
 * Returns true if ok. False otherwise.
 *  ipsq  may not yet be allocated (loopback case ).
 */
static boolean_t
ill_allocate_mibs(ill_t *ill)
{
	/* Already allocated? */
	if (ill->ill_ip_mib != NULL) {
		if (ill->ill_isv6)
			ASSERT(ill->ill_icmp6_mib != NULL);
		return (B_TRUE);
	}

	ill->ill_ip_mib = kmem_zalloc(sizeof (*ill->ill_ip_mib),
	    KM_NOSLEEP);
	if (ill->ill_ip_mib == NULL) {
		return (B_FALSE);
	}

	/* Setup static information */
	SET_MIB(ill->ill_ip_mib->ipIfStatsEntrySize,
	    sizeof (mib2_ipIfStatsEntry_t));
	if (ill->ill_isv6) {
		ill->ill_ip_mib->ipIfStatsIPVersion = MIB2_INETADDRESSTYPE_ipv6;
		SET_MIB(ill->ill_ip_mib->ipIfStatsAddrEntrySize,
		    sizeof (mib2_ipv6AddrEntry_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsRouteEntrySize,
		    sizeof (mib2_ipv6RouteEntry_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsNetToMediaEntrySize,
		    sizeof (mib2_ipv6NetToMediaEntry_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsMemberEntrySize,
		    sizeof (ipv6_member_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsGroupSourceEntrySize,
		    sizeof (ipv6_grpsrc_t));
	} else {
		ill->ill_ip_mib->ipIfStatsIPVersion = MIB2_INETADDRESSTYPE_ipv4;
		SET_MIB(ill->ill_ip_mib->ipIfStatsAddrEntrySize,
		    sizeof (mib2_ipAddrEntry_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsRouteEntrySize,
		    sizeof (mib2_ipRouteEntry_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsNetToMediaEntrySize,
		    sizeof (mib2_ipNetToMediaEntry_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsMemberEntrySize,
		    sizeof (ip_member_t));
		SET_MIB(ill->ill_ip_mib->ipIfStatsGroupSourceEntrySize,
		    sizeof (ip_grpsrc_t));

		/*
		 * For a v4 ill, we are done at this point, because per ill
		 * icmp mibs are only used for v6.
		 */
		return (B_TRUE);
	}

	ill->ill_icmp6_mib = kmem_zalloc(sizeof (*ill->ill_icmp6_mib),
	    KM_NOSLEEP);
	if (ill->ill_icmp6_mib == NULL) {
		kmem_free(ill->ill_ip_mib, sizeof (*ill->ill_ip_mib));
		ill->ill_ip_mib = NULL;
		return (B_FALSE);
	}
	/* static icmp info */
	ill->ill_icmp6_mib->ipv6IfIcmpEntrySize =
	    sizeof (mib2_ipv6IfIcmpEntry_t);
	/*
	 * The ipIfStatsIfindex and ipv6IfIcmpIndex will be assigned later
	 * after the phyint merge occurs in ipif_set_values -> ill_glist_insert
	 * -> ill_phyint_reinit
	 */
	return (B_TRUE);
}

/*
 * Common code for preparation of ARP commands.  Two points to remember:
 * 	1) The ill_name is tacked on at the end of the allocated space so
 *	   the templates name_offset field must contain the total space
 *	   to allocate less the name length.
 *
 *	2) The templates name_length field should contain the *template*
 *	   length.  We use it as a parameter to bcopy() and then write
 *	   the real ill_name_length into the name_length field of the copy.
 * (Always called as writer.)
 */
mblk_t *
ill_arp_alloc(ill_t *ill, const uchar_t *template, caddr_t addr)
{
	arc_t	*arc = (arc_t *)template;
	char	*cp;
	int	len;
	mblk_t	*mp;
	uint_t	name_length = ill->ill_name_length;
	uint_t	template_len = arc->arc_name_length;

	len = arc->arc_name_offset + name_length;
	mp = allocb(len, BPRI_HI);
	if (mp == NULL)
		return (NULL);
	cp = (char *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)&cp[len];
	if (template_len)
		bcopy(template, cp, template_len);
	if (len > template_len)
		bzero(&cp[template_len], len - template_len);
	mp->b_datap->db_type = M_PROTO;

	arc = (arc_t *)cp;
	arc->arc_name_length = name_length;
	cp = (char *)arc + arc->arc_name_offset;
	bcopy(ill->ill_name, cp, name_length);

	if (addr) {
		area_t	*area = (area_t *)mp->b_rptr;

		cp = (char *)area + area->area_proto_addr_offset;
		bcopy(addr, cp, area->area_proto_addr_length);
		if (area->area_cmd == AR_ENTRY_ADD) {
			cp = (char *)area;
			len = area->area_proto_addr_length;
			if (area->area_proto_mask_offset)
				cp += area->area_proto_mask_offset;
			else
				cp += area->area_proto_addr_offset + len;
			while (len-- > 0)
				*cp++ = (char)~0;
		}
	}
	return (mp);
}

mblk_t *
ipif_area_alloc(ipif_t *ipif, uint_t optflags)
{
	caddr_t	addr;
	mblk_t 	*mp;
	area_t	*area;
	uchar_t	*areap;
	ill_t	*ill = ipif->ipif_ill;

	if (ill->ill_isv6) {
		ASSERT(ill->ill_flags & ILLF_XRESOLV);
		addr = (caddr_t)&ipif->ipif_v6lcl_addr;
		areap = (uchar_t *)&ip6_area_template;
	} else {
		addr = (caddr_t)&ipif->ipif_lcl_addr;
		areap = (uchar_t *)&ip_area_template;
	}

	if ((mp = ill_arp_alloc(ill, areap, addr)) == NULL)
		return (NULL);

	/*
	 * IPMP requires that the hardware address be included in all
	 * AR_ENTRY_ADD requests so that ARP can deduce the arl to send on.
	 * If there are no active underlying ills in the group (and thus no
	 * hardware address, DAD will be deferred until an underlying ill
	 * becomes active.
	 */
	if (IS_IPMP(ill)) {
		if ((ill = ipmp_ipif_hold_bound_ill(ipif)) == NULL) {
			freemsg(mp);
			return (NULL);
		}
	} else {
		ill_refhold(ill);
	}

	area = (area_t *)mp->b_rptr;
	area->area_flags = ACE_F_PERMANENT | ACE_F_PUBLISH | ACE_F_MYADDR;
	area->area_flags |= optflags;
	area->area_hw_addr_length = ill->ill_phys_addr_length;
	bcopy(ill->ill_phys_addr, mp->b_rptr + area->area_hw_addr_offset,
	    area->area_hw_addr_length);

	ill_refrele(ill);
	return (mp);
}

mblk_t *
ipif_ared_alloc(ipif_t *ipif)
{
	caddr_t	addr;
	uchar_t	*aredp;

	if (ipif->ipif_ill->ill_isv6) {
		ASSERT(ipif->ipif_ill->ill_flags & ILLF_XRESOLV);
		addr = (caddr_t)&ipif->ipif_v6lcl_addr;
		aredp = (uchar_t *)&ip6_ared_template;
	} else {
		addr = (caddr_t)&ipif->ipif_lcl_addr;
		aredp = (uchar_t *)&ip_ared_template;
	}

	return (ill_arp_alloc(ipif->ipif_ill, aredp, addr));
}

mblk_t *
ill_ared_alloc(ill_t *ill, ipaddr_t addr)
{
	return (ill_arp_alloc(ill, (uchar_t *)&ip_ared_template,
	    (char *)&addr));
}

mblk_t *
ill_arie_alloc(ill_t *ill, const char *grifname, const void *template)
{
	mblk_t	*mp = ill_arp_alloc(ill, template, 0);
	arie_t	*arie;

	if (mp != NULL) {
		arie = (arie_t *)mp->b_rptr;
		(void) strlcpy(arie->arie_grifname, grifname, LIFNAMSIZ);
	}
	return (mp);
}

/*
 * Completely vaporize a lower level tap and all associated interfaces.
 * ill_delete is called only out of ip_close when the device control
 * stream is being closed.
 */
void
ill_delete(ill_t *ill)
{
	ipif_t	*ipif;
	ill_t	*prev_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	/*
	 * ill_delete may be forcibly entering the ipsq. The previous
	 * ioctl may not have completed and may need to be aborted.
	 * ipsq_flush takes care of it. If we don't need to enter the
	 * the ipsq forcibly, the 2nd invocation of ipsq_flush in
	 * ill_delete_tail is sufficient.
	 */
	ipsq_flush(ill);

	/*
	 * Nuke all interfaces.  ipif_free will take down the interface,
	 * remove it from the list, and free the data structure.
	 * Walk down the ipif list and remove the logical interfaces
	 * first before removing the main ipif. We can't unplumb
	 * zeroth interface first in the case of IPv6 as reset_conn_ill
	 * -> ip_ll_delmulti_v6 de-references ill_ipif for checking
	 * POINTOPOINT.
	 *
	 * If ill_ipif was not properly initialized (i.e low on memory),
	 * then no interfaces to clean up. In this case just clean up the
	 * ill.
	 */
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next)
		ipif_free(ipif);

	/*
	 * Used only by ill_arp_on and ill_arp_off, which are writers.
	 * So nobody can be using this mp now. Free the mp allocated for
	 * honoring ILLF_NOARP
	 */
	freemsg(ill->ill_arp_on_mp);
	ill->ill_arp_on_mp = NULL;

	/* Clean up msgs on pending upcalls for mrouted */
	reset_mrt_ill(ill);

	/*
	 * ipif_free -> reset_conn_ipif will remove all multicast
	 * references for IPv4. For IPv6, we need to do it here as
	 * it points only at ills.
	 */
	reset_conn_ill(ill);

	/*
	 * Remove multicast references added as a result of calls to
	 * ip_join_allmulti().
	 */
	ip_purge_allmulti(ill);

	/*
	 * If the ill being deleted is under IPMP, boot it out of the illgrp.
	 */
	if (IS_UNDER_IPMP(ill))
		ipmp_ill_leave_illgrp(ill);

	/*
	 * ill_down will arrange to blow off any IRE's dependent on this
	 * ILL, and shut down fragmentation reassembly.
	 */
	ill_down(ill);

	/* Let SCTP know, so that it can remove this from its list. */
	sctp_update_ill(ill, SCTP_ILL_REMOVE);

	/*
	 * If an address on this ILL is being used as a source address then
	 * clear out the pointers in other ILLs that point to this ILL.
	 */
	rw_enter(&ipst->ips_ill_g_usesrc_lock, RW_WRITER);
	if (ill->ill_usesrc_grp_next != NULL) {
		if (ill->ill_usesrc_ifindex == 0) { /* usesrc ILL ? */
			ill_disband_usesrc_group(ill);
		} else {	/* consumer of the usesrc ILL */
			prev_ill = ill_prev_usesrc(ill);
			prev_ill->ill_usesrc_grp_next =
			    ill->ill_usesrc_grp_next;
		}
	}
	rw_exit(&ipst->ips_ill_g_usesrc_lock);
}

static void
ipif_non_duplicate(ipif_t *ipif)
{
	ill_t *ill = ipif->ipif_ill;
	mutex_enter(&ill->ill_lock);
	if (ipif->ipif_flags & IPIF_DUPLICATE) {
		ipif->ipif_flags &= ~IPIF_DUPLICATE;
		ASSERT(ill->ill_ipif_dup_count > 0);
		ill->ill_ipif_dup_count--;
	}
	mutex_exit(&ill->ill_lock);
}

/*
 * ill_delete_tail is called from ip_modclose after all references
 * to the closing ill are gone. The wait is done in ip_modclose
 */
void
ill_delete_tail(ill_t *ill)
{
	mblk_t	**mpp;
	ipif_t	*ipif;
	ip_stack_t	*ipst = ill->ill_ipst;

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		ipif_non_duplicate(ipif);
		ipif_down_tail(ipif);
	}

	ASSERT(ill->ill_ipif_dup_count == 0 &&
	    ill->ill_arp_down_mp == NULL &&
	    ill->ill_arp_del_mapping_mp == NULL);

	/*
	 * If polling capability is enabled (which signifies direct
	 * upcall into IP and driver has ill saved as a handle),
	 * we need to make sure that unbind has completed before we
	 * let the ill disappear and driver no longer has any reference
	 * to this ill.
	 */
	mutex_enter(&ill->ill_lock);
	while (ill->ill_state_flags & ILL_DL_UNBIND_IN_PROGRESS)
		cv_wait(&ill->ill_cv, &ill->ill_lock);
	mutex_exit(&ill->ill_lock);
	ASSERT(!(ill->ill_capabilities &
	    (ILL_CAPAB_DLD | ILL_CAPAB_DLD_POLL | ILL_CAPAB_DLD_DIRECT)));

	if (ill->ill_net_type != IRE_LOOPBACK)
		qprocsoff(ill->ill_rq);

	/*
	 * We do an ipsq_flush once again now. New messages could have
	 * landed up from below (M_ERROR or M_HANGUP). Similarly ioctls
	 * could also have landed up if an ioctl thread had looked up
	 * the ill before we set the ILL_CONDEMNED flag, but not yet
	 * enqueued the ioctl when we did the ipsq_flush last time.
	 */
	ipsq_flush(ill);

	/*
	 * Free capabilities.
	 */
	if (ill->ill_ipsec_capab_ah != NULL) {
		ill_ipsec_capab_delete(ill, DL_CAPAB_IPSEC_AH);
		ill_ipsec_capab_free(ill->ill_ipsec_capab_ah);
		ill->ill_ipsec_capab_ah = NULL;
	}

	if (ill->ill_ipsec_capab_esp != NULL) {
		ill_ipsec_capab_delete(ill, DL_CAPAB_IPSEC_ESP);
		ill_ipsec_capab_free(ill->ill_ipsec_capab_esp);
		ill->ill_ipsec_capab_esp = NULL;
	}

	if (ill->ill_mdt_capab != NULL) {
		kmem_free(ill->ill_mdt_capab, sizeof (ill_mdt_capab_t));
		ill->ill_mdt_capab = NULL;
	}

	if (ill->ill_hcksum_capab != NULL) {
		kmem_free(ill->ill_hcksum_capab, sizeof (ill_hcksum_capab_t));
		ill->ill_hcksum_capab = NULL;
	}

	if (ill->ill_zerocopy_capab != NULL) {
		kmem_free(ill->ill_zerocopy_capab,
		    sizeof (ill_zerocopy_capab_t));
		ill->ill_zerocopy_capab = NULL;
	}

	if (ill->ill_lso_capab != NULL) {
		kmem_free(ill->ill_lso_capab, sizeof (ill_lso_capab_t));
		ill->ill_lso_capab = NULL;
	}

	if (ill->ill_dld_capab != NULL) {
		kmem_free(ill->ill_dld_capab, sizeof (ill_dld_capab_t));
		ill->ill_dld_capab = NULL;
	}

	while (ill->ill_ipif != NULL)
		ipif_free_tail(ill->ill_ipif);

	/*
	 * We have removed all references to ilm from conn and the ones joined
	 * within the kernel.
	 *
	 * We don't walk conns, mrts and ires because
	 *
	 * 1) reset_conn_ill and reset_mrt_ill cleans up conns and mrts.
	 * 2) ill_down ->ill_downi walks all the ires and cleans up
	 *    ill references.
	 */
	ASSERT(ilm_walk_ill(ill) == 0);

	/*
	 * If this ill is an IPMP meta-interface, blow away the illgrp.  This
	 * is safe to do because the illgrp has already been unlinked from the
	 * group by I_PUNLINK, and thus SIOCSLIFGROUPNAME cannot find it.
	 */
	if (IS_IPMP(ill)) {
		ipmp_illgrp_destroy(ill->ill_grp);
		ill->ill_grp = NULL;
	}

	/*
	 * Take us out of the list of ILLs. ill_glist_delete -> phyint_free
	 * could free the phyint. No more reference to the phyint after this
	 * point.
	 */
	(void) ill_glist_delete(ill);

	rw_enter(&ipst->ips_ip_g_nd_lock, RW_WRITER);
	if (ill->ill_ndd_name != NULL)
		nd_unload(&ipst->ips_ip_g_nd, ill->ill_ndd_name);
	rw_exit(&ipst->ips_ip_g_nd_lock);

	if (ill->ill_frag_ptr != NULL) {
		uint_t count;

		for (count = 0; count < ILL_FRAG_HASH_TBL_COUNT; count++) {
			mutex_destroy(&ill->ill_frag_hash_tbl[count].ipfb_lock);
		}
		mi_free(ill->ill_frag_ptr);
		ill->ill_frag_ptr = NULL;
		ill->ill_frag_hash_tbl = NULL;
	}

	freemsg(ill->ill_nd_lla_mp);
	/* Free all retained control messages. */
	mpp = &ill->ill_first_mp_to_free;
	do {
		while (mpp[0]) {
			mblk_t  *mp;
			mblk_t  *mp1;

			mp = mpp[0];
			mpp[0] = mp->b_next;
			for (mp1 = mp; mp1 != NULL; mp1 = mp1->b_cont) {
				mp1->b_next = NULL;
				mp1->b_prev = NULL;
			}
			freemsg(mp);
		}
	} while (mpp++ != &ill->ill_last_mp_to_free);

	ill_free_mib(ill);

#ifdef DEBUG
	ill_trace_cleanup(ill);
#endif

	/* Drop refcnt here */
	netstack_rele(ill->ill_ipst->ips_netstack);
	ill->ill_ipst = NULL;
}

static void
ill_free_mib(ill_t *ill)
{
	ip_stack_t *ipst = ill->ill_ipst;

	/*
	 * MIB statistics must not be lost, so when an interface
	 * goes away the counter values will be added to the global
	 * MIBs.
	 */
	if (ill->ill_ip_mib != NULL) {
		if (ill->ill_isv6) {
			ip_mib2_add_ip_stats(&ipst->ips_ip6_mib,
			    ill->ill_ip_mib);
		} else {
			ip_mib2_add_ip_stats(&ipst->ips_ip_mib,
			    ill->ill_ip_mib);
		}

		kmem_free(ill->ill_ip_mib, sizeof (*ill->ill_ip_mib));
		ill->ill_ip_mib = NULL;
	}
	if (ill->ill_icmp6_mib != NULL) {
		ip_mib2_add_icmp6_stats(&ipst->ips_icmp6_mib,
		    ill->ill_icmp6_mib);
		kmem_free(ill->ill_icmp6_mib, sizeof (*ill->ill_icmp6_mib));
		ill->ill_icmp6_mib = NULL;
	}
}

/*
 * Concatenate together a physical address and a sap.
 *
 * Sap_lengths are interpreted as follows:
 *   sap_length == 0	==>	no sap
 *   sap_length > 0	==>	sap is at the head of the dlpi address
 *   sap_length < 0	==>	sap is at the tail of the dlpi address
 */
static void
ill_dlur_copy_address(uchar_t *phys_src, uint_t phys_length,
    t_scalar_t sap_src, t_scalar_t sap_length, uchar_t *dst)
{
	uint16_t sap_addr = (uint16_t)sap_src;

	if (sap_length == 0) {
		if (phys_src == NULL)
			bzero(dst, phys_length);
		else
			bcopy(phys_src, dst, phys_length);
	} else if (sap_length < 0) {
		if (phys_src == NULL)
			bzero(dst, phys_length);
		else
			bcopy(phys_src, dst, phys_length);
		bcopy(&sap_addr, (char *)dst + phys_length, sizeof (sap_addr));
	} else {
		bcopy(&sap_addr, dst, sizeof (sap_addr));
		if (phys_src == NULL)
			bzero((char *)dst + sap_length, phys_length);
		else
			bcopy(phys_src, (char *)dst + sap_length, phys_length);
	}
}

/*
 * Generate a dl_unitdata_req mblk for the device and address given.
 * addr_length is the length of the physical portion of the address.
 * If addr is NULL include an all zero address of the specified length.
 * TRUE? In any case, addr_length is taken to be the entire length of the
 * dlpi address, including the absolute value of sap_length.
 */
mblk_t *
ill_dlur_gen(uchar_t *addr, uint_t addr_length, t_uscalar_t sap,
		t_scalar_t sap_length)
{
	dl_unitdata_req_t *dlur;
	mblk_t	*mp;
	t_scalar_t	abs_sap_length;		/* absolute value */

	abs_sap_length = ABS(sap_length);
	mp = ip_dlpi_alloc(sizeof (*dlur) + addr_length + abs_sap_length,
	    DL_UNITDATA_REQ);
	if (mp == NULL)
		return (NULL);
	dlur = (dl_unitdata_req_t *)mp->b_rptr;
	/* HACK: accomodate incompatible DLPI drivers */
	if (addr_length == 8)
		addr_length = 6;
	dlur->dl_dest_addr_length = addr_length + abs_sap_length;
	dlur->dl_dest_addr_offset = sizeof (*dlur);
	dlur->dl_priority.dl_min = 0;
	dlur->dl_priority.dl_max = 0;
	ill_dlur_copy_address(addr, addr_length, sap, sap_length,
	    (uchar_t *)&dlur[1]);
	return (mp);
}

/*
 * Add the 'mp' to the list of pending mp's headed by ill_pending_mp
 * Return an error if we already have 1 or more ioctls in progress.
 * This is used only for non-exclusive ioctls. Currently this is used
 * for SIOC*ARP and SIOCGTUNPARAM ioctls. Most set ioctls are exclusive
 * and thus need to use ipsq_pending_mp_add.
 */
boolean_t
ill_pending_mp_add(ill_t *ill, conn_t *connp, mblk_t *add_mp)
{
	ASSERT(MUTEX_HELD(&ill->ill_lock));
	ASSERT((add_mp->b_next == NULL) && (add_mp->b_prev == NULL));
	/*
	 * M_IOCDATA from ioctls, M_IOCTL from tunnel ioctls.
	 */
	ASSERT((add_mp->b_datap->db_type == M_IOCDATA) ||
	    (add_mp->b_datap->db_type == M_IOCTL));

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	/*
	 * Return error if the conn has started closing. The conn
	 * could have finished cleaning up the pending mp list,
	 * If so we should not add another mp to the list negating
	 * the cleanup.
	 */
	if (connp->conn_state_flags & CONN_CLOSING)
		return (B_FALSE);
	/*
	 * Add the pending mp to the head of the list, chained by b_next.
	 * Note down the conn on which the ioctl request came, in b_prev.
	 * This will be used to later get the conn, when we get a response
	 * on the ill queue, from some other module (typically arp)
	 */
	add_mp->b_next = (void *)ill->ill_pending_mp;
	add_mp->b_queue = CONNP_TO_WQ(connp);
	ill->ill_pending_mp = add_mp;
	if (connp != NULL)
		connp->conn_oper_pending_ill = ill;
	return (B_TRUE);
}

/*
 * Retrieve the ill_pending_mp and return it. We have to walk the list
 * of mblks starting at ill_pending_mp, and match based on the ioc_id.
 */
mblk_t *
ill_pending_mp_get(ill_t *ill, conn_t **connpp, uint_t ioc_id)
{
	mblk_t	*prev = NULL;
	mblk_t	*curr = NULL;
	uint_t	id;
	conn_t	*connp;

	/*
	 * When the conn closes, conn_ioctl_cleanup needs to clean
	 * up the pending mp, but it does not know the ioc_id and
	 * passes in a zero for it.
	 */
	mutex_enter(&ill->ill_lock);
	if (ioc_id != 0)
		*connpp = NULL;

	/* Search the list for the appropriate ioctl based on ioc_id */
	for (prev = NULL, curr = ill->ill_pending_mp; curr != NULL;
	    prev = curr, curr = curr->b_next) {
		id = ((struct iocblk *)curr->b_rptr)->ioc_id;
		connp = Q_TO_CONN(curr->b_queue);
		/* Match based on the ioc_id or based on the conn */
		if ((id == ioc_id) || (ioc_id == 0 && connp == *connpp))
			break;
	}

	if (curr != NULL) {
		/* Unlink the mblk from the pending mp list */
		if (prev != NULL) {
			prev->b_next = curr->b_next;
		} else {
			ASSERT(ill->ill_pending_mp == curr);
			ill->ill_pending_mp = curr->b_next;
		}

		/*
		 * conn refcnt must have been bumped up at the start of
		 * the ioctl. So we can safely access the conn.
		 */
		ASSERT(CONN_Q(curr->b_queue));
		*connpp = Q_TO_CONN(curr->b_queue);
		curr->b_next = NULL;
		curr->b_queue = NULL;
	}

	mutex_exit(&ill->ill_lock);

	return (curr);
}

/*
 * Add the pending mp to the list. There can be only 1 pending mp
 * in the list. Any exclusive ioctl that needs to wait for a response
 * from another module or driver needs to use this function to set
 * the ipx_pending_mp to the ioctl mblk and wait for the response from
 * the other module/driver. This is also used while waiting for the
 * ipif/ill/ire refcnts to drop to zero in bringing down an ipif.
 */
boolean_t
ipsq_pending_mp_add(conn_t *connp, ipif_t *ipif, queue_t *q, mblk_t *add_mp,
    int waitfor)
{
	ipxop_t	*ipx = ipif->ipif_ill->ill_phyint->phyint_ipsq->ipsq_xop;

	ASSERT(IAM_WRITER_IPIF(ipif));
	ASSERT(MUTEX_HELD(&ipif->ipif_ill->ill_lock));
	ASSERT((add_mp->b_next == NULL) && (add_mp->b_prev == NULL));
	ASSERT(ipx->ipx_pending_mp == NULL);
	/*
	 * The caller may be using a different ipif than the one passed into
	 * ipsq_current_start() (e.g., suppose an ioctl that came in on the V4
	 * ill needs to wait for the V6 ill to quiesce).  So we can't ASSERT
	 * that `ipx_current_ipif == ipif'.
	 */
	ASSERT(ipx->ipx_current_ipif != NULL);

	/*
	 * M_IOCDATA from ioctls, M_IOCTL from tunnel ioctls,
	 * M_ERROR/M_HANGUP/M_PROTO/M_PCPROTO from the driver.
	 */
	ASSERT((DB_TYPE(add_mp) == M_IOCDATA) || (DB_TYPE(add_mp) == M_IOCTL) ||
	    (DB_TYPE(add_mp) == M_ERROR) || (DB_TYPE(add_mp) == M_HANGUP) ||
	    (DB_TYPE(add_mp) == M_PROTO) || (DB_TYPE(add_mp) == M_PCPROTO));

	if (connp != NULL) {
		ASSERT(MUTEX_HELD(&connp->conn_lock));
		/*
		 * Return error if the conn has started closing. The conn
		 * could have finished cleaning up the pending mp list,
		 * If so we should not add another mp to the list negating
		 * the cleanup.
		 */
		if (connp->conn_state_flags & CONN_CLOSING)
			return (B_FALSE);
	}
	mutex_enter(&ipx->ipx_lock);
	ipx->ipx_pending_ipif = ipif;
	/*
	 * Note down the queue in b_queue. This will be returned by
	 * ipsq_pending_mp_get. Caller will then use these values to restart
	 * the processing
	 */
	add_mp->b_next = NULL;
	add_mp->b_queue = q;
	ipx->ipx_pending_mp = add_mp;
	ipx->ipx_waitfor = waitfor;
	mutex_exit(&ipx->ipx_lock);

	if (connp != NULL)
		connp->conn_oper_pending_ill = ipif->ipif_ill;

	return (B_TRUE);
}

/*
 * Retrieve the ipx_pending_mp and return it. There can be only 1 mp
 * queued in the list.
 */
mblk_t *
ipsq_pending_mp_get(ipsq_t *ipsq, conn_t **connpp)
{
	mblk_t	*curr = NULL;
	ipxop_t	*ipx = ipsq->ipsq_xop;

	*connpp = NULL;
	mutex_enter(&ipx->ipx_lock);
	if (ipx->ipx_pending_mp == NULL) {
		mutex_exit(&ipx->ipx_lock);
		return (NULL);
	}

	/* There can be only 1 such excl message */
	curr = ipx->ipx_pending_mp;
	ASSERT(curr->b_next == NULL);
	ipx->ipx_pending_ipif = NULL;
	ipx->ipx_pending_mp = NULL;
	ipx->ipx_waitfor = 0;
	mutex_exit(&ipx->ipx_lock);

	if (CONN_Q(curr->b_queue)) {
		/*
		 * This mp did a refhold on the conn, at the start of the ioctl.
		 * So we can safely return a pointer to the conn to the caller.
		 */
		*connpp = Q_TO_CONN(curr->b_queue);
	} else {
		*connpp = NULL;
	}
	curr->b_next = NULL;
	curr->b_prev = NULL;
	return (curr);
}

/*
 * Cleanup the ioctl mp queued in ipx_pending_mp
 * - Called in the ill_delete path
 * - Called in the M_ERROR or M_HANGUP path on the ill.
 * - Called in the conn close path.
 */
boolean_t
ipsq_pending_mp_cleanup(ill_t *ill, conn_t *connp)
{
	mblk_t	*mp;
	ipxop_t	*ipx;
	queue_t	*q;
	ipif_t	*ipif;

	ASSERT(IAM_WRITER_ILL(ill));
	ipx = ill->ill_phyint->phyint_ipsq->ipsq_xop;

	/*
	 * If connp is null, unconditionally clean up the ipx_pending_mp.
	 * This happens in M_ERROR/M_HANGUP. We need to abort the current ioctl
	 * even if it is meant for another ill, since we have to enqueue
	 * a new mp now in ipx_pending_mp to complete the ipif_down.
	 * If connp is non-null we are called from the conn close path.
	 */
	mutex_enter(&ipx->ipx_lock);
	mp = ipx->ipx_pending_mp;
	if (mp == NULL || (connp != NULL &&
	    mp->b_queue != CONNP_TO_WQ(connp))) {
		mutex_exit(&ipx->ipx_lock);
		return (B_FALSE);
	}
	/* Now remove from the ipx_pending_mp */
	ipx->ipx_pending_mp = NULL;
	q = mp->b_queue;
	mp->b_next = NULL;
	mp->b_prev = NULL;
	mp->b_queue = NULL;

	ipif = ipx->ipx_pending_ipif;
	ipx->ipx_pending_ipif = NULL;
	ipx->ipx_waitfor = 0;
	ipx->ipx_current_ipif = NULL;
	ipx->ipx_current_ioctl = 0;
	ipx->ipx_current_done = B_TRUE;
	mutex_exit(&ipx->ipx_lock);

	if (DB_TYPE(mp) == M_IOCTL || DB_TYPE(mp) == M_IOCDATA) {
		if (connp == NULL) {
			ip_ioctl_finish(q, mp, ENXIO, NO_COPYOUT, NULL);
		} else {
			ip_ioctl_finish(q, mp, ENXIO, CONN_CLOSE, NULL);
			mutex_enter(&ipif->ipif_ill->ill_lock);
			ipif->ipif_state_flags &= ~IPIF_CHANGING;
			mutex_exit(&ipif->ipif_ill->ill_lock);
		}
	} else {
		/*
		 * IP-MT XXX In the case of TLI/XTI bind / optmgmt this can't
		 * be just inet_freemsg. we have to restart it
		 * otherwise the thread will be stuck.
		 */
		inet_freemsg(mp);
	}
	return (B_TRUE);
}

/*
 * The ill is closing. Cleanup all the pending mps. Called exclusively
 * towards the end of ill_delete. The refcount has gone to 0. So nobody
 * knows this ill, and hence nobody can add an mp to this list
 */
static void
ill_pending_mp_cleanup(ill_t *ill)
{
	mblk_t	*mp;
	queue_t	*q;

	ASSERT(IAM_WRITER_ILL(ill));

	mutex_enter(&ill->ill_lock);
	/*
	 * Every mp on the pending mp list originating from an ioctl
	 * added 1 to the conn refcnt, at the start of the ioctl.
	 * So bump it down now.  See comments in ip_wput_nondata()
	 */
	while (ill->ill_pending_mp != NULL) {
		mp = ill->ill_pending_mp;
		ill->ill_pending_mp = mp->b_next;
		mutex_exit(&ill->ill_lock);

		q = mp->b_queue;
		ASSERT(CONN_Q(q));
		mp->b_next = NULL;
		mp->b_prev = NULL;
		mp->b_queue = NULL;
		ip_ioctl_finish(q, mp, ENXIO, NO_COPYOUT, NULL);
		mutex_enter(&ill->ill_lock);
	}
	ill->ill_pending_ipif = NULL;

	mutex_exit(&ill->ill_lock);
}

/*
 * Called in the conn close path and ill delete path
 */
static void
ipsq_xopq_mp_cleanup(ill_t *ill, conn_t *connp)
{
	ipsq_t	*ipsq;
	mblk_t	*prev;
	mblk_t	*curr;
	mblk_t	*next;
	queue_t	*q;
	mblk_t	*tmp_list = NULL;

	ASSERT(IAM_WRITER_ILL(ill));
	if (connp != NULL)
		q = CONNP_TO_WQ(connp);
	else
		q = ill->ill_wq;

	ipsq = ill->ill_phyint->phyint_ipsq;
	/*
	 * Cleanup the ioctl mp's queued in ipsq_xopq_pending_mp if any.
	 * In the case of ioctl from a conn, there can be only 1 mp
	 * queued on the ipsq. If an ill is being unplumbed, only messages
	 * related to this ill are flushed, like M_ERROR or M_HANGUP message.
	 * ioctls meant for this ill form conn's are not flushed. They will
	 * be processed during ipsq_exit and will not find the ill and will
	 * return error.
	 */
	mutex_enter(&ipsq->ipsq_lock);
	for (prev = NULL, curr = ipsq->ipsq_xopq_mphead; curr != NULL;
	    curr = next) {
		next = curr->b_next;
		if (curr->b_queue == q || curr->b_queue == RD(q)) {
			/* Unlink the mblk from the pending mp list */
			if (prev != NULL) {
				prev->b_next = curr->b_next;
			} else {
				ASSERT(ipsq->ipsq_xopq_mphead == curr);
				ipsq->ipsq_xopq_mphead = curr->b_next;
			}
			if (ipsq->ipsq_xopq_mptail == curr)
				ipsq->ipsq_xopq_mptail = prev;
			/*
			 * Create a temporary list and release the ipsq lock
			 * New elements are added to the head of the tmp_list
			 */
			curr->b_next = tmp_list;
			tmp_list = curr;
		} else {
			prev = curr;
		}
	}
	mutex_exit(&ipsq->ipsq_lock);

	while (tmp_list != NULL) {
		curr = tmp_list;
		tmp_list = curr->b_next;
		curr->b_next = NULL;
		curr->b_prev = NULL;
		curr->b_queue = NULL;
		if (DB_TYPE(curr) == M_IOCTL || DB_TYPE(curr) == M_IOCDATA) {
			ip_ioctl_finish(q, curr, ENXIO, connp != NULL ?
			    CONN_CLOSE : NO_COPYOUT, NULL);
		} else {
			/*
			 * IP-MT XXX In the case of TLI/XTI bind / optmgmt
			 * this can't be just inet_freemsg. we have to
			 * restart it otherwise the thread will be stuck.
			 */
			inet_freemsg(curr);
		}
	}
}

/*
 * This conn has started closing. Cleanup any pending ioctl from this conn.
 * STREAMS ensures that there can be at most 1 ioctl pending on a stream.
 */
void
conn_ioctl_cleanup(conn_t *connp)
{
	mblk_t *curr;
	ipsq_t	*ipsq;
	ill_t	*ill;
	boolean_t refheld;

	/*
	 * Is any exclusive ioctl pending ? If so clean it up. If the
	 * ioctl has not yet started, the mp is pending in the list headed by
	 * ipsq_xopq_head. If the ioctl has started the mp could be present in
	 * ipx_pending_mp. If the ioctl timed out in the streamhead but
	 * is currently executing now the mp is not queued anywhere but
	 * conn_oper_pending_ill is null. The conn close will wait
	 * till the conn_ref drops to zero.
	 */
	mutex_enter(&connp->conn_lock);
	ill = connp->conn_oper_pending_ill;
	if (ill == NULL) {
		mutex_exit(&connp->conn_lock);
		return;
	}

	curr = ill_pending_mp_get(ill, &connp, 0);
	if (curr != NULL) {
		mutex_exit(&connp->conn_lock);
		CONN_DEC_REF(connp);
		inet_freemsg(curr);
		return;
	}
	/*
	 * We may not be able to refhold the ill if the ill/ipif
	 * is changing. But we need to make sure that the ill will
	 * not vanish. So we just bump up the ill_waiter count.
	 */
	refheld = ill_waiter_inc(ill);
	mutex_exit(&connp->conn_lock);
	if (refheld) {
		if (ipsq_enter(ill, B_TRUE, NEW_OP)) {
			ill_waiter_dcr(ill);
			/*
			 * Check whether this ioctl has started and is
			 * pending. If it is not found there then check
			 * whether this ioctl has not even started and is in
			 * the ipsq_xopq list.
			 */
			if (!ipsq_pending_mp_cleanup(ill, connp))
				ipsq_xopq_mp_cleanup(ill, connp);
			ipsq = ill->ill_phyint->phyint_ipsq;
			ipsq_exit(ipsq);
			return;
		}
	}

	/*
	 * The ill is also closing and we could not bump up the
	 * ill_waiter_count or we could not enter the ipsq. Leave
	 * the cleanup to ill_delete
	 */
	mutex_enter(&connp->conn_lock);
	while (connp->conn_oper_pending_ill != NULL)
		cv_wait(&connp->conn_refcv, &connp->conn_lock);
	mutex_exit(&connp->conn_lock);
	if (refheld)
		ill_waiter_dcr(ill);
}

/*
 * ipcl_walk function for cleaning up conn_*_ill fields.
 */
static void
conn_cleanup_ill(conn_t *connp, caddr_t arg)
{
	ill_t	*ill = (ill_t *)arg;
	ire_t	*ire;

	mutex_enter(&connp->conn_lock);
	if (connp->conn_multicast_ill == ill) {
		/* Revert to late binding */
		connp->conn_multicast_ill = NULL;
	}
	if (connp->conn_incoming_ill == ill)
		connp->conn_incoming_ill = NULL;
	if (connp->conn_outgoing_ill == ill)
		connp->conn_outgoing_ill = NULL;
	if (connp->conn_dhcpinit_ill == ill) {
		connp->conn_dhcpinit_ill = NULL;
		ASSERT(ill->ill_dhcpinit != 0);
		atomic_dec_32(&ill->ill_dhcpinit);
	}
	if (connp->conn_ire_cache != NULL) {
		ire = connp->conn_ire_cache;
		/*
		 * Source address selection makes it possible for IRE_CACHE
		 * entries to be created with ire_stq coming from interface X
		 * and ipif coming from interface Y.  Thus whenever interface
		 * X goes down, remove all references to it by checking both
		 * on ire_ipif and ire_stq.
		 */
		if ((ire->ire_ipif != NULL && ire->ire_ipif->ipif_ill == ill) ||
		    (ire->ire_type == IRE_CACHE &&
		    ire->ire_stq == ill->ill_wq)) {
			connp->conn_ire_cache = NULL;
			mutex_exit(&connp->conn_lock);
			ire_refrele_notr(ire);
			return;
		}
	}
	mutex_exit(&connp->conn_lock);
}

/* ARGSUSED */
void
ipif_all_down_tail(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	ill_t	*ill = q->q_ptr;
	ipif_t	*ipif;

	ASSERT(IAM_WRITER_IPSQ(ipsq));
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		ipif_non_duplicate(ipif);
		ipif_down_tail(ipif);
	}
	freemsg(mp);
	ipsq_current_finish(ipsq);
}

/*
 * ill_down_start is called when we want to down this ill and bring it up again
 * It is called when we receive an M_ERROR / M_HANGUP. In this case we shut down
 * all interfaces, but don't tear down any plumbing.
 */
boolean_t
ill_down_start(queue_t *q, mblk_t *mp)
{
	ill_t	*ill = q->q_ptr;
	ipif_t	*ipif;

	ASSERT(IAM_WRITER_ILL(ill));

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next)
		(void) ipif_down(ipif, NULL, NULL);

	ill_down(ill);

	(void) ipsq_pending_mp_cleanup(ill, NULL);

	ipsq_current_start(ill->ill_phyint->phyint_ipsq, ill->ill_ipif, 0);

	/*
	 * Atomically test and add the pending mp if references are active.
	 */
	mutex_enter(&ill->ill_lock);
	if (!ill_is_quiescent(ill)) {
		/* call cannot fail since `conn_t *' argument is NULL */
		(void) ipsq_pending_mp_add(NULL, ill->ill_ipif, ill->ill_rq,
		    mp, ILL_DOWN);
		mutex_exit(&ill->ill_lock);
		return (B_FALSE);
	}
	mutex_exit(&ill->ill_lock);
	return (B_TRUE);
}

static void
ill_down(ill_t *ill)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	/* Blow off any IREs dependent on this ILL. */
	ire_walk(ill_downi, ill, ipst);

	/* Remove any conn_*_ill depending on this ill */
	ipcl_walk(conn_cleanup_ill, (caddr_t)ill, ipst);
}

/*
 * ire_walk routine used to delete every IRE that depends on queues
 * associated with 'ill'.  (Always called as writer.)
 */
static void
ill_downi(ire_t *ire, char *ill_arg)
{
	ill_t	*ill = (ill_t *)ill_arg;

	/*
	 * Source address selection makes it possible for IRE_CACHE
	 * entries to be created with ire_stq coming from interface X
	 * and ipif coming from interface Y.  Thus whenever interface
	 * X goes down, remove all references to it by checking both
	 * on ire_ipif and ire_stq.
	 */
	if ((ire->ire_ipif != NULL && ire->ire_ipif->ipif_ill == ill) ||
	    (ire->ire_type == IRE_CACHE && ire->ire_stq == ill->ill_wq)) {
		ire_delete(ire);
	}
}

/*
 * Remove ire/nce from the fastpath list.
 */
void
ill_fastpath_nack(ill_t *ill)
{
	nce_fastpath_list_dispatch(ill, NULL, NULL);
}

/* Consume an M_IOCACK of the fastpath probe. */
void
ill_fastpath_ack(ill_t *ill, mblk_t *mp)
{
	mblk_t	*mp1 = mp;

	/*
	 * If this was the first attempt turn on the fastpath probing.
	 */
	mutex_enter(&ill->ill_lock);
	if (ill->ill_dlpi_fastpath_state == IDS_INPROGRESS)
		ill->ill_dlpi_fastpath_state = IDS_OK;
	mutex_exit(&ill->ill_lock);

	/* Free the M_IOCACK mblk, hold on to the data */
	mp = mp->b_cont;
	freeb(mp1);
	if (mp == NULL)
		return;
	if (mp->b_cont != NULL) {
		/*
		 * Update all IRE's or NCE's that are waiting for
		 * fastpath update.
		 */
		nce_fastpath_list_dispatch(ill, ndp_fastpath_update, mp);
		mp1 = mp->b_cont;
		freeb(mp);
		mp = mp1;
	} else {
		ip0dbg(("ill_fastpath_ack:  no b_cont\n"));
	}

	freeb(mp);
}

/*
 * Throw an M_IOCTL message downstream asking "do you know fastpath?"
 * The data portion of the request is a dl_unitdata_req_t template for
 * what we would send downstream in the absence of a fastpath confirmation.
 */
int
ill_fastpath_probe(ill_t *ill, mblk_t *dlur_mp)
{
	struct iocblk	*ioc;
	mblk_t	*mp;

	if (dlur_mp == NULL)
		return (EINVAL);

	mutex_enter(&ill->ill_lock);
	switch (ill->ill_dlpi_fastpath_state) {
	case IDS_FAILED:
		/*
		 * Driver NAKed the first fastpath ioctl - assume it doesn't
		 * support it.
		 */
		mutex_exit(&ill->ill_lock);
		return (ENOTSUP);
	case IDS_UNKNOWN:
		/* This is the first probe */
		ill->ill_dlpi_fastpath_state = IDS_INPROGRESS;
		break;
	default:
		break;
	}
	mutex_exit(&ill->ill_lock);

	if ((mp = mkiocb(DL_IOC_HDR_INFO)) == NULL)
		return (EAGAIN);

	mp->b_cont = copyb(dlur_mp);
	if (mp->b_cont == NULL) {
		freeb(mp);
		return (EAGAIN);
	}

	ioc = (struct iocblk *)mp->b_rptr;
	ioc->ioc_count = msgdsize(mp->b_cont);

	putnext(ill->ill_wq, mp);
	return (0);
}

void
ill_capability_probe(ill_t *ill)
{
	mblk_t	*mp;

	ASSERT(IAM_WRITER_ILL(ill));

	if (ill->ill_dlpi_capab_state != IDCS_UNKNOWN &&
	    ill->ill_dlpi_capab_state != IDCS_FAILED)
		return;

	/*
	 * We are starting a new cycle of capability negotiation.
	 * Free up the capab reset messages of any previous incarnation.
	 * We will do a fresh allocation when we get the response to our probe
	 */
	if (ill->ill_capab_reset_mp != NULL) {
		freemsg(ill->ill_capab_reset_mp);
		ill->ill_capab_reset_mp = NULL;
	}

	ip1dbg(("ill_capability_probe: starting capability negotiation\n"));

	mp = ip_dlpi_alloc(sizeof (dl_capability_req_t), DL_CAPABILITY_REQ);
	if (mp == NULL)
		return;

	ill_capability_send(ill, mp);
	ill->ill_dlpi_capab_state = IDCS_PROBE_SENT;
}

void
ill_capability_reset(ill_t *ill, boolean_t reneg)
{
	ASSERT(IAM_WRITER_ILL(ill));

	if (ill->ill_dlpi_capab_state != IDCS_OK)
		return;

	ill->ill_dlpi_capab_state = reneg ? IDCS_RENEG : IDCS_RESET_SENT;

	ill_capability_send(ill, ill->ill_capab_reset_mp);
	ill->ill_capab_reset_mp = NULL;
	/*
	 * We turn off all capabilities except those pertaining to
	 * direct function call capabilities viz. ILL_CAPAB_DLD*
	 * which will be turned off by the corresponding reset functions.
	 */
	ill->ill_capabilities &= ~(ILL_CAPAB_MDT | ILL_CAPAB_HCKSUM  |
	    ILL_CAPAB_ZEROCOPY | ILL_CAPAB_AH | ILL_CAPAB_ESP);
}

static void
ill_capability_reset_alloc(ill_t *ill)
{
	mblk_t *mp;
	size_t	size = 0;
	int	err;
	dl_capability_req_t	*capb;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(ill->ill_capab_reset_mp == NULL);

	if (ILL_MDT_CAPABLE(ill))
		size += sizeof (dl_capability_sub_t) + sizeof (dl_capab_mdt_t);

	if (ILL_HCKSUM_CAPABLE(ill)) {
		size += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_hcksum_t);
	}

	if (ill->ill_capabilities & ILL_CAPAB_ZEROCOPY) {
		size += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_zerocopy_t);
	}

	if (ill->ill_capabilities & (ILL_CAPAB_AH | ILL_CAPAB_ESP)) {
		size += sizeof (dl_capability_sub_t);
		size += ill_capability_ipsec_reset_size(ill, NULL, NULL,
		    NULL, NULL);
	}

	if (ill->ill_capabilities & ILL_CAPAB_DLD) {
		size += sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_dld_t);
	}

	mp = allocb_wait(size + sizeof (dl_capability_req_t), BPRI_MED,
	    STR_NOSIG, &err);

	mp->b_datap->db_type = M_PROTO;
	bzero(mp->b_rptr, size + sizeof (dl_capability_req_t));

	capb = (dl_capability_req_t *)mp->b_rptr;
	capb->dl_primitive = DL_CAPABILITY_REQ;
	capb->dl_sub_offset = sizeof (dl_capability_req_t);
	capb->dl_sub_length = size;

	mp->b_wptr += sizeof (dl_capability_req_t);

	/*
	 * Each handler fills in the corresponding dl_capability_sub_t
	 * inside the mblk,
	 */
	ill_capability_mdt_reset_fill(ill, mp);
	ill_capability_hcksum_reset_fill(ill, mp);
	ill_capability_zerocopy_reset_fill(ill, mp);
	ill_capability_ipsec_reset_fill(ill, mp);
	ill_capability_dld_reset_fill(ill, mp);

	ill->ill_capab_reset_mp = mp;
}

static void
ill_capability_id_ack(ill_t *ill, mblk_t *mp, dl_capability_sub_t *outers)
{
	dl_capab_id_t *id_ic;
	uint_t sub_dl_cap = outers->dl_cap;
	dl_capability_sub_t *inners;
	uint8_t *capend;

	ASSERT(sub_dl_cap == DL_CAPAB_ID_WRAPPER);

	/*
	 * Note: range checks here are not absolutely sufficient to
	 * make us robust against malformed messages sent by drivers;
	 * this is in keeping with the rest of IP's dlpi handling.
	 * (Remember, it's coming from something else in the kernel
	 * address space)
	 */

	capend = (uint8_t *)(outers + 1) + outers->dl_length;
	if (capend > mp->b_wptr) {
		cmn_err(CE_WARN, "ill_capability_id_ack: "
		    "malformed sub-capability too long for mblk");
		return;
	}

	id_ic = (dl_capab_id_t *)(outers + 1);

	if (outers->dl_length < sizeof (*id_ic) ||
	    (inners = &id_ic->id_subcap,
	    inners->dl_length > (outers->dl_length - sizeof (*inners)))) {
		cmn_err(CE_WARN, "ill_capability_id_ack: malformed "
		    "encapsulated capab type %d too long for mblk",
		    inners->dl_cap);
		return;
	}

	if (!dlcapabcheckqid(&id_ic->id_mid, ill->ill_lmod_rq)) {
		ip1dbg(("ill_capability_id_ack: mid token for capab type %d "
		    "isn't as expected; pass-thru module(s) detected, "
		    "discarding capability\n", inners->dl_cap));
		return;
	}

	/* Process the encapsulated sub-capability */
	ill_capability_dispatch(ill, mp, inners, B_TRUE);
}

/*
 * Process Multidata Transmit capability negotiation ack received from a
 * DLS Provider.  isub must point to the sub-capability (DL_CAPAB_MDT) of a
 * DL_CAPABILITY_ACK message.
 */
static void
ill_capability_mdt_ack(ill_t *ill, mblk_t *mp, dl_capability_sub_t *isub)
{
	mblk_t *nmp = NULL;
	dl_capability_req_t *oc;
	dl_capab_mdt_t *mdt_ic, *mdt_oc;
	ill_mdt_capab_t **ill_mdt_capab;
	uint_t sub_dl_cap = isub->dl_cap;
	uint8_t *capend;

	ASSERT(sub_dl_cap == DL_CAPAB_MDT);

	ill_mdt_capab = (ill_mdt_capab_t **)&ill->ill_mdt_capab;

	/*
	 * Note: range checks here are not absolutely sufficient to
	 * make us robust against malformed messages sent by drivers;
	 * this is in keeping with the rest of IP's dlpi handling.
	 * (Remember, it's coming from something else in the kernel
	 * address space)
	 */

	capend = (uint8_t *)(isub + 1) + isub->dl_length;
	if (capend > mp->b_wptr) {
		cmn_err(CE_WARN, "ill_capability_mdt_ack: "
		    "malformed sub-capability too long for mblk");
		return;
	}

	mdt_ic = (dl_capab_mdt_t *)(isub + 1);

	if (mdt_ic->mdt_version != MDT_VERSION_2) {
		cmn_err(CE_CONT, "ill_capability_mdt_ack: "
		    "unsupported MDT sub-capability (version %d, expected %d)",
		    mdt_ic->mdt_version, MDT_VERSION_2);
		return;
	}

	if (!dlcapabcheckqid(&mdt_ic->mdt_mid, ill->ill_lmod_rq)) {
		ip1dbg(("ill_capability_mdt_ack: mid token for MDT "
		    "capability isn't as expected; pass-thru module(s) "
		    "detected, discarding capability\n"));
		return;
	}

	if (mdt_ic->mdt_flags & DL_CAPAB_MDT_ENABLE) {

		if (*ill_mdt_capab == NULL) {
			*ill_mdt_capab = kmem_zalloc(sizeof (ill_mdt_capab_t),
			    KM_NOSLEEP);
			if (*ill_mdt_capab == NULL) {
				cmn_err(CE_WARN, "ill_capability_mdt_ack: "
				    "could not enable MDT version %d "
				    "for %s (ENOMEM)\n", MDT_VERSION_2,
				    ill->ill_name);
				return;
			}
		}

		ip1dbg(("ill_capability_mdt_ack: interface %s supports "
		    "MDT version %d (%d bytes leading, %d bytes trailing "
		    "header spaces, %d max pld bufs, %d span limit)\n",
		    ill->ill_name, MDT_VERSION_2,
		    mdt_ic->mdt_hdr_head, mdt_ic->mdt_hdr_tail,
		    mdt_ic->mdt_max_pld, mdt_ic->mdt_span_limit));

		(*ill_mdt_capab)->ill_mdt_version = MDT_VERSION_2;
		(*ill_mdt_capab)->ill_mdt_on = 1;
		/*
		 * Round the following values to the nearest 32-bit; ULP
		 * may further adjust them to accomodate for additional
		 * protocol headers.  We pass these values to ULP during
		 * bind time.
		 */
		(*ill_mdt_capab)->ill_mdt_hdr_head =
		    roundup(mdt_ic->mdt_hdr_head, 4);
		(*ill_mdt_capab)->ill_mdt_hdr_tail =
		    roundup(mdt_ic->mdt_hdr_tail, 4);
		(*ill_mdt_capab)->ill_mdt_max_pld = mdt_ic->mdt_max_pld;
		(*ill_mdt_capab)->ill_mdt_span_limit = mdt_ic->mdt_span_limit;

		ill->ill_capabilities |= ILL_CAPAB_MDT;
	} else {
		uint_t size;
		uchar_t *rptr;

		size = sizeof (dl_capability_req_t) +
		    sizeof (dl_capability_sub_t) + sizeof (dl_capab_mdt_t);

		if ((nmp = ip_dlpi_alloc(size, DL_CAPABILITY_REQ)) == NULL) {
			cmn_err(CE_WARN, "ill_capability_mdt_ack: "
			    "could not enable MDT for %s (ENOMEM)\n",
			    ill->ill_name);
			return;
		}

		rptr = nmp->b_rptr;
		/* initialize dl_capability_req_t */
		oc = (dl_capability_req_t *)nmp->b_rptr;
		oc->dl_sub_offset = sizeof (dl_capability_req_t);
		oc->dl_sub_length = sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_mdt_t);
		nmp->b_rptr += sizeof (dl_capability_req_t);

		/* initialize dl_capability_sub_t */
		bcopy(isub, nmp->b_rptr, sizeof (*isub));
		nmp->b_rptr += sizeof (*isub);

		/* initialize dl_capab_mdt_t */
		mdt_oc = (dl_capab_mdt_t *)nmp->b_rptr;
		bcopy(mdt_ic, mdt_oc, sizeof (*mdt_ic));

		nmp->b_rptr = rptr;

		ip1dbg(("ill_capability_mdt_ack: asking interface %s "
		    "to enable MDT version %d\n", ill->ill_name,
		    MDT_VERSION_2));

		/* set ENABLE flag */
		mdt_oc->mdt_flags |= DL_CAPAB_MDT_ENABLE;

		/* nmp points to a DL_CAPABILITY_REQ message to enable MDT */
		ill_capability_send(ill, nmp);
	}
}

static void
ill_capability_mdt_reset_fill(ill_t *ill, mblk_t *mp)
{
	dl_capab_mdt_t *mdt_subcap;
	dl_capability_sub_t *dl_subcap;

	if (!ILL_MDT_CAPABLE(ill))
		return;

	ASSERT(ill->ill_mdt_capab != NULL);

	dl_subcap = (dl_capability_sub_t *)mp->b_wptr;
	dl_subcap->dl_cap = DL_CAPAB_MDT;
	dl_subcap->dl_length = sizeof (*mdt_subcap);

	mdt_subcap = (dl_capab_mdt_t *)(dl_subcap + 1);
	mdt_subcap->mdt_version = ill->ill_mdt_capab->ill_mdt_version;
	mdt_subcap->mdt_flags = 0;
	mdt_subcap->mdt_hdr_head = 0;
	mdt_subcap->mdt_hdr_tail = 0;

	mp->b_wptr += sizeof (*dl_subcap) + sizeof (*mdt_subcap);
}

static void
ill_capability_dld_reset_fill(ill_t *ill, mblk_t *mp)
{
	dl_capability_sub_t *dl_subcap;

	if (!(ill->ill_capabilities & ILL_CAPAB_DLD))
		return;

	/*
	 * The dl_capab_dld_t that follows the dl_capability_sub_t is not
	 * initialized below since it is not used by DLD.
	 */
	dl_subcap = (dl_capability_sub_t *)mp->b_wptr;
	dl_subcap->dl_cap = DL_CAPAB_DLD;
	dl_subcap->dl_length = sizeof (dl_capab_dld_t);

	mp->b_wptr += sizeof (dl_capability_sub_t) + sizeof (dl_capab_dld_t);
}

/*
 * Send a DL_NOTIFY_REQ to the specified ill to enable
 * DL_NOTE_PROMISC_ON/OFF_PHYS notifications.
 * Invoked by ill_capability_ipsec_ack() before enabling IPsec hardware
 * acceleration.
 * Returns B_TRUE on success, B_FALSE if the message could not be sent.
 */
static boolean_t
ill_enable_promisc_notify(ill_t *ill)
{
	mblk_t *mp;
	dl_notify_req_t *req;

	IPSECHW_DEBUG(IPSECHW_PKT, ("ill_enable_promisc_notify:\n"));

	mp = ip_dlpi_alloc(sizeof (dl_notify_req_t), DL_NOTIFY_REQ);
	if (mp == NULL)
		return (B_FALSE);

	req = (dl_notify_req_t *)mp->b_rptr;
	req->dl_notifications = DL_NOTE_PROMISC_ON_PHYS |
	    DL_NOTE_PROMISC_OFF_PHYS;

	ill_dlpi_send(ill, mp);

	return (B_TRUE);
}

/*
 * Allocate an IPsec capability request which will be filled by our
 * caller to turn on support for one or more algorithms.
 */
static mblk_t *
ill_alloc_ipsec_cap_req(ill_t *ill, dl_capability_sub_t *isub)
{
	mblk_t *nmp;
	dl_capability_req_t	*ocap;
	dl_capab_ipsec_t	*ocip;
	dl_capab_ipsec_t	*icip;
	uint8_t			*ptr;
	icip = (dl_capab_ipsec_t *)(isub + 1);

	/*
	 * The first time around, we send a DL_NOTIFY_REQ to enable
	 * PROMISC_ON/OFF notification from the provider. We need to
	 * do this before enabling the algorithms to avoid leakage of
	 * cleartext packets.
	 */

	if (!ill_enable_promisc_notify(ill))
		return (NULL);

	/*
	 * Allocate new mblk which will contain a new capability
	 * request to enable the capabilities.
	 */

	nmp = ip_dlpi_alloc(sizeof (dl_capability_req_t) +
	    sizeof (dl_capability_sub_t) + isub->dl_length, DL_CAPABILITY_REQ);
	if (nmp == NULL)
		return (NULL);

	ptr = nmp->b_rptr;

	/* initialize dl_capability_req_t */
	ocap = (dl_capability_req_t *)ptr;
	ocap->dl_sub_offset = sizeof (dl_capability_req_t);
	ocap->dl_sub_length = sizeof (dl_capability_sub_t) + isub->dl_length;
	ptr += sizeof (dl_capability_req_t);

	/* initialize dl_capability_sub_t */
	bcopy(isub, ptr, sizeof (*isub));
	ptr += sizeof (*isub);

	/* initialize dl_capab_ipsec_t */
	ocip = (dl_capab_ipsec_t *)ptr;
	bcopy(icip, ocip, sizeof (*icip));

	nmp->b_wptr = (uchar_t *)(&ocip->cip_data[0]);
	return (nmp);
}

/*
 * Process an IPsec capability negotiation ack received from a DLS Provider.
 * isub must point to the sub-capability (DL_CAPAB_IPSEC_AH or
 * DL_CAPAB_IPSEC_ESP) of a DL_CAPABILITY_ACK message.
 */
static void
ill_capability_ipsec_ack(ill_t *ill, mblk_t *mp, dl_capability_sub_t *isub)
{
	dl_capab_ipsec_t	*icip;
	dl_capab_ipsec_alg_t	*ialg;	/* ptr to input alg spec. */
	dl_capab_ipsec_alg_t	*oalg;	/* ptr to output alg spec. */
	uint_t cipher, nciphers;
	mblk_t *nmp;
	uint_t alg_len;
	boolean_t need_sadb_dump;
	uint_t sub_dl_cap = isub->dl_cap;
	ill_ipsec_capab_t **ill_capab;
	uint64_t ill_capab_flag;
	uint8_t *capend, *ciphend;
	boolean_t sadb_resync;

	ASSERT(sub_dl_cap == DL_CAPAB_IPSEC_AH ||
	    sub_dl_cap == DL_CAPAB_IPSEC_ESP);

	if (sub_dl_cap == DL_CAPAB_IPSEC_AH) {
		ill_capab = (ill_ipsec_capab_t **)&ill->ill_ipsec_capab_ah;
		ill_capab_flag = ILL_CAPAB_AH;
	} else {
		ill_capab = (ill_ipsec_capab_t **)&ill->ill_ipsec_capab_esp;
		ill_capab_flag = ILL_CAPAB_ESP;
	}

	/*
	 * If the ill capability structure exists, then this incoming
	 * DL_CAPABILITY_ACK is a response to a "renegotiation" cycle.
	 * If this is so, then we'd need to resynchronize the SADB
	 * after re-enabling the offloaded ciphers.
	 */
	sadb_resync = (*ill_capab != NULL);

	/*
	 * Note: range checks here are not absolutely sufficient to
	 * make us robust against malformed messages sent by drivers;
	 * this is in keeping with the rest of IP's dlpi handling.
	 * (Remember, it's coming from something else in the kernel
	 * address space)
	 */

	capend = (uint8_t *)(isub + 1) + isub->dl_length;
	if (capend > mp->b_wptr) {
		cmn_err(CE_WARN, "ill_capability_ipsec_ack: "
		    "malformed sub-capability too long for mblk");
		return;
	}

	/*
	 * There are two types of acks we process here:
	 * 1. acks in reply to a (first form) generic capability req
	 *    (no ENABLE flag set)
	 * 2. acks in reply to a ENABLE capability req.
	 *    (ENABLE flag set)
	 *
	 * We process the subcapability passed as argument as follows:
	 * 1 do initializations
	 *   1.1 initialize nmp = NULL
	 *   1.2 set need_sadb_dump to B_FALSE
	 * 2 for each cipher in subcapability:
	 *   2.1 if ENABLE flag is set:
	 *	2.1.1 update per-ill ipsec capabilities info
	 *	2.1.2 set need_sadb_dump to B_TRUE
	 *   2.2 if ENABLE flag is not set:
	 *	2.2.1 if nmp is NULL:
	 *		2.2.1.1 allocate and initialize nmp
	 *		2.2.1.2 init current pos in nmp
	 *	2.2.2 copy current cipher to current pos in nmp
	 *	2.2.3 set ENABLE flag in nmp
	 *	2.2.4 update current pos
	 * 3 if nmp is not equal to NULL, send enable request
	 *   3.1 send capability request
	 * 4 if need_sadb_dump is B_TRUE
	 *   4.1 enable promiscuous on/off notifications
	 *   4.2 call ill_dlpi_send(isub->dlcap) to send all
	 *	AH or ESP SA's to interface.
	 */

	nmp = NULL;
	oalg = NULL;
	need_sadb_dump = B_FALSE;
	icip = (dl_capab_ipsec_t *)(isub + 1);
	ialg = (dl_capab_ipsec_alg_t *)(&icip->cip_data[0]);

	nciphers = icip->cip_nciphers;
	ciphend = (uint8_t *)(ialg + icip->cip_nciphers);

	if (ciphend > capend) {
		cmn_err(CE_WARN, "ill_capability_ipsec_ack: "
		    "too many ciphers for sub-capability len");
		return;
	}

	for (cipher = 0; cipher < nciphers; cipher++) {
		alg_len = sizeof (dl_capab_ipsec_alg_t);

		if (ialg->alg_flag & DL_CAPAB_ALG_ENABLE) {
			/*
			 * TBD: when we provide a way to disable capabilities
			 * from above, need to manage the request-pending state
			 * and fail if we were not expecting this ACK.
			 */
			IPSECHW_DEBUG(IPSECHW_CAPAB,
			    ("ill_capability_ipsec_ack: got ENABLE ACK\n"));

			/*
			 * Update IPsec capabilities for this ill
			 */

			if (*ill_capab == NULL) {
				IPSECHW_DEBUG(IPSECHW_CAPAB,
				    ("ill_capability_ipsec_ack: "
				    "allocating ipsec_capab for ill\n"));
				*ill_capab = ill_ipsec_capab_alloc();

				if (*ill_capab == NULL) {
					cmn_err(CE_WARN,
					    "ill_capability_ipsec_ack: "
					    "could not enable IPsec Hardware "
					    "acceleration for %s (ENOMEM)\n",
					    ill->ill_name);
					return;
				}
			}

			ASSERT(ialg->alg_type == DL_CAPAB_IPSEC_ALG_AUTH ||
			    ialg->alg_type == DL_CAPAB_IPSEC_ALG_ENCR);

			if (ialg->alg_prim >= MAX_IPSEC_ALGS) {
				cmn_err(CE_WARN,
				    "ill_capability_ipsec_ack: "
				    "malformed IPsec algorithm id %d",
				    ialg->alg_prim);
				continue;
			}

			if (ialg->alg_type == DL_CAPAB_IPSEC_ALG_AUTH) {
				IPSEC_ALG_ENABLE((*ill_capab)->auth_hw_algs,
				    ialg->alg_prim);
			} else {
				ipsec_capab_algparm_t *alp;

				IPSEC_ALG_ENABLE((*ill_capab)->encr_hw_algs,
				    ialg->alg_prim);
				if (!ill_ipsec_capab_resize_algparm(*ill_capab,
				    ialg->alg_prim)) {
					cmn_err(CE_WARN,
					    "ill_capability_ipsec_ack: "
					    "no space for IPsec alg id %d",
					    ialg->alg_prim);
					continue;
				}
				alp = &((*ill_capab)->encr_algparm[
				    ialg->alg_prim]);
				alp->minkeylen = ialg->alg_minbits;
				alp->maxkeylen = ialg->alg_maxbits;
			}
			ill->ill_capabilities |= ill_capab_flag;
			/*
			 * indicate that a capability was enabled, which
			 * will be used below to kick off a SADB dump
			 * to the ill.
			 */
			need_sadb_dump = B_TRUE;
		} else {
			IPSECHW_DEBUG(IPSECHW_CAPAB,
			    ("ill_capability_ipsec_ack: enabling alg 0x%x\n",
			    ialg->alg_prim));

			if (nmp == NULL) {
				nmp = ill_alloc_ipsec_cap_req(ill, isub);
				if (nmp == NULL) {
					/*
					 * Sending the PROMISC_ON/OFF
					 * notification request failed.
					 * We cannot enable the algorithms
					 * since the Provider will not
					 * notify IP of promiscous mode
					 * changes, which could lead
					 * to leakage of packets.
					 */
					cmn_err(CE_WARN,
					    "ill_capability_ipsec_ack: "
					    "could not enable IPsec Hardware "
					    "acceleration for %s (ENOMEM)\n",
					    ill->ill_name);
					return;
				}
				/* ptr to current output alg specifier */
				oalg = (dl_capab_ipsec_alg_t *)nmp->b_wptr;
			}

			/*
			 * Copy current alg specifier, set ENABLE
			 * flag, and advance to next output alg.
			 * For now we enable all IPsec capabilities.
			 */
			ASSERT(oalg != NULL);
			bcopy(ialg, oalg, alg_len);
			oalg->alg_flag |= DL_CAPAB_ALG_ENABLE;
			nmp->b_wptr += alg_len;
			oalg = (dl_capab_ipsec_alg_t *)nmp->b_wptr;
		}

		/* move to next input algorithm specifier */
		ialg = (dl_capab_ipsec_alg_t *)
		    ((char *)ialg + alg_len);
	}

	if (nmp != NULL)
		/*
		 * nmp points to a DL_CAPABILITY_REQ message to enable
		 * IPsec hardware acceleration.
		 */
		ill_capability_send(ill, nmp);

	if (need_sadb_dump)
		/*
		 * An acknowledgement corresponding to a request to
		 * enable acceleration was received, notify SADB.
		 */
		ill_ipsec_capab_add(ill, sub_dl_cap, sadb_resync);
}

/*
 * Given an mblk with enough space in it, create sub-capability entries for
 * DL_CAPAB_IPSEC_{AH,ESP} types which consist of previously-advertised
 * offloaded ciphers (both AUTH and ENCR) with their enable flags cleared,
 * in preparation for the reset the DL_CAPABILITY_REQ message.
 */
static void
ill_fill_ipsec_reset(uint_t nciphers, int stype, uint_t slen,
    ill_ipsec_capab_t *ill_cap, mblk_t *mp)
{
	dl_capab_ipsec_t *oipsec;
	dl_capab_ipsec_alg_t *oalg;
	dl_capability_sub_t *dl_subcap;
	int i, k;

	ASSERT(nciphers > 0);
	ASSERT(ill_cap != NULL);
	ASSERT(mp != NULL);
	ASSERT(MBLKTAIL(mp) >= sizeof (*dl_subcap) + sizeof (*oipsec) + slen);

	/* dl_capability_sub_t for "stype" */
	dl_subcap = (dl_capability_sub_t *)mp->b_wptr;
	dl_subcap->dl_cap = stype;
	dl_subcap->dl_length = sizeof (dl_capab_ipsec_t) + slen;
	mp->b_wptr += sizeof (dl_capability_sub_t);

	/* dl_capab_ipsec_t for "stype" */
	oipsec = (dl_capab_ipsec_t *)mp->b_wptr;
	oipsec->cip_version = 1;
	oipsec->cip_nciphers = nciphers;
	mp->b_wptr = (uchar_t *)&oipsec->cip_data[0];

	/* create entries for "stype" AUTH ciphers */
	for (i = 0; i < ill_cap->algs_size; i++) {
		for (k = 0; k < BITSPERBYTE; k++) {
			if ((ill_cap->auth_hw_algs[i] & (1 << k)) == 0)
				continue;

			oalg = (dl_capab_ipsec_alg_t *)mp->b_wptr;
			bzero((void *)oalg, sizeof (*oalg));
			oalg->alg_type = DL_CAPAB_IPSEC_ALG_AUTH;
			oalg->alg_prim = k + (BITSPERBYTE * i);
			mp->b_wptr += sizeof (dl_capab_ipsec_alg_t);
		}
	}
	/* create entries for "stype" ENCR ciphers */
	for (i = 0; i < ill_cap->algs_size; i++) {
		for (k = 0; k < BITSPERBYTE; k++) {
			if ((ill_cap->encr_hw_algs[i] & (1 << k)) == 0)
				continue;

			oalg = (dl_capab_ipsec_alg_t *)mp->b_wptr;
			bzero((void *)oalg, sizeof (*oalg));
			oalg->alg_type = DL_CAPAB_IPSEC_ALG_ENCR;
			oalg->alg_prim = k + (BITSPERBYTE * i);
			mp->b_wptr += sizeof (dl_capab_ipsec_alg_t);
		}
	}
}

/*
 * Macro to count number of 1s in a byte (8-bit word).  The total count is
 * accumulated into the passed-in argument (sum).  We could use SPARCv9's
 * POPC instruction, but our macro is more flexible for an arbitrary length
 * of bytes, such as {auth,encr}_hw_algs.  These variables are currently
 * 256-bits long (MAX_IPSEC_ALGS), so if we know for sure that the length
 * stays that way, we can reduce the number of iterations required.
 */
#define	COUNT_1S(val, sum) {					\
	uint8_t x = val & 0xff;					\
	x = (x & 0x55) + ((x >> 1) & 0x55);			\
	x = (x & 0x33) + ((x >> 2) & 0x33);			\
	sum += (x & 0xf) + ((x >> 4) & 0xf);			\
}

/* ARGSUSED */
static int
ill_capability_ipsec_reset_size(ill_t *ill, int *ah_cntp, int *ah_lenp,
    int *esp_cntp, int *esp_lenp)
{
	ill_ipsec_capab_t *cap_ah = ill->ill_ipsec_capab_ah;
	ill_ipsec_capab_t *cap_esp = ill->ill_ipsec_capab_esp;
	uint64_t ill_capabilities = ill->ill_capabilities;
	int ah_cnt = 0, esp_cnt = 0;
	int ah_len = 0, esp_len = 0;
	int i, size = 0;

	if (!(ill_capabilities & (ILL_CAPAB_AH | ILL_CAPAB_ESP)))
		return (0);

	ASSERT(cap_ah != NULL || !(ill_capabilities & ILL_CAPAB_AH));
	ASSERT(cap_esp != NULL || !(ill_capabilities & ILL_CAPAB_ESP));

	/* Find out the number of ciphers for AH */
	if (cap_ah != NULL) {
		for (i = 0; i < cap_ah->algs_size; i++) {
			COUNT_1S(cap_ah->auth_hw_algs[i], ah_cnt);
			COUNT_1S(cap_ah->encr_hw_algs[i], ah_cnt);
		}
		if (ah_cnt > 0) {
			size += sizeof (dl_capability_sub_t) +
			    sizeof (dl_capab_ipsec_t);
			/* dl_capab_ipsec_t contains one dl_capab_ipsec_alg_t */
			ah_len = (ah_cnt - 1) * sizeof (dl_capab_ipsec_alg_t);
			size += ah_len;
		}
	}

	/* Find out the number of ciphers for ESP */
	if (cap_esp != NULL) {
		for (i = 0; i < cap_esp->algs_size; i++) {
			COUNT_1S(cap_esp->auth_hw_algs[i], esp_cnt);
			COUNT_1S(cap_esp->encr_hw_algs[i], esp_cnt);
		}
		if (esp_cnt > 0) {
			size += sizeof (dl_capability_sub_t) +
			    sizeof (dl_capab_ipsec_t);
			/* dl_capab_ipsec_t contains one dl_capab_ipsec_alg_t */
			esp_len = (esp_cnt - 1) * sizeof (dl_capab_ipsec_alg_t);
			size += esp_len;
		}
	}

	if (ah_cntp != NULL)
		*ah_cntp = ah_cnt;
	if (ah_lenp != NULL)
		*ah_lenp = ah_len;
	if (esp_cntp != NULL)
		*esp_cntp = esp_cnt;
	if (esp_lenp != NULL)
		*esp_lenp = esp_len;

	return (size);
}

/* ARGSUSED */
static void
ill_capability_ipsec_reset_fill(ill_t *ill, mblk_t *mp)
{
	ill_ipsec_capab_t *cap_ah = ill->ill_ipsec_capab_ah;
	ill_ipsec_capab_t *cap_esp = ill->ill_ipsec_capab_esp;
	int ah_cnt = 0, esp_cnt = 0;
	int ah_len = 0, esp_len = 0;
	int size;

	size = ill_capability_ipsec_reset_size(ill, &ah_cnt, &ah_len,
	    &esp_cnt, &esp_len);
	if (size == 0)
		return;

	/*
	 * Clear the capability flags for IPsec HA but retain the ill
	 * capability structures since it's possible that another thread
	 * is still referring to them.  The structures only get deallocated
	 * when we destroy the ill.
	 *
	 * Various places check the flags to see if the ill is capable of
	 * hardware acceleration, and by clearing them we ensure that new
	 * outbound IPsec packets are sent down encrypted.
	 */

	/* Fill in DL_CAPAB_IPSEC_AH sub-capability entries */
	if (ah_cnt > 0) {
		ill_fill_ipsec_reset(ah_cnt, DL_CAPAB_IPSEC_AH, ah_len,
		    cap_ah, mp);
	}

	/* Fill in DL_CAPAB_IPSEC_ESP sub-capability entries */
	if (esp_cnt > 0) {
		ill_fill_ipsec_reset(esp_cnt, DL_CAPAB_IPSEC_ESP, esp_len,
		    cap_esp, mp);
	}

	/*
	 * At this point we've composed a bunch of sub-capabilities to be
	 * encapsulated in a DL_CAPABILITY_REQ and later sent downstream
	 * by the caller.  Upon receiving this reset message, the driver
	 * must stop inbound decryption (by destroying all inbound SAs)
	 * and let the corresponding packets come in encrypted.
	 */
}

static void
ill_capability_dispatch(ill_t *ill, mblk_t *mp, dl_capability_sub_t *subp,
    boolean_t encapsulated)
{
	boolean_t legacy = B_FALSE;

	/*
	 * Note that only the following two sub-capabilities may be
	 * considered as "legacy", since their original definitions
	 * do not incorporate the dl_mid_t module ID token, and hence
	 * may require the use of the wrapper sub-capability.
	 */
	switch (subp->dl_cap) {
	case DL_CAPAB_IPSEC_AH:
	case DL_CAPAB_IPSEC_ESP:
		legacy = B_TRUE;
		break;
	}

	/*
	 * For legacy sub-capabilities which don't incorporate a queue_t
	 * pointer in their structures, discard them if we detect that
	 * there are intermediate modules in between IP and the driver.
	 */
	if (!encapsulated && legacy && ill->ill_lmod_cnt > 1) {
		ip1dbg(("ill_capability_dispatch: unencapsulated capab type "
		    "%d discarded; %d module(s) present below IP\n",
		    subp->dl_cap, ill->ill_lmod_cnt));
		return;
	}

	switch (subp->dl_cap) {
	case DL_CAPAB_IPSEC_AH:
	case DL_CAPAB_IPSEC_ESP:
		ill_capability_ipsec_ack(ill, mp, subp);
		break;
	case DL_CAPAB_MDT:
		ill_capability_mdt_ack(ill, mp, subp);
		break;
	case DL_CAPAB_HCKSUM:
		ill_capability_hcksum_ack(ill, mp, subp);
		break;
	case DL_CAPAB_ZEROCOPY:
		ill_capability_zerocopy_ack(ill, mp, subp);
		break;
	case DL_CAPAB_DLD:
		ill_capability_dld_ack(ill, mp, subp);
		break;
	default:
		ip1dbg(("ill_capability_dispatch: unknown capab type %d\n",
		    subp->dl_cap));
	}
}

/*
 * Process a hardware checksum offload capability negotiation ack received
 * from a DLS Provider.isub must point to the sub-capability (DL_CAPAB_HCKSUM)
 * of a DL_CAPABILITY_ACK message.
 */
static void
ill_capability_hcksum_ack(ill_t *ill, mblk_t *mp, dl_capability_sub_t *isub)
{
	dl_capability_req_t	*ocap;
	dl_capab_hcksum_t	*ihck, *ohck;
	ill_hcksum_capab_t	**ill_hcksum;
	mblk_t			*nmp = NULL;
	uint_t			sub_dl_cap = isub->dl_cap;
	uint8_t			*capend;

	ASSERT(sub_dl_cap == DL_CAPAB_HCKSUM);

	ill_hcksum = (ill_hcksum_capab_t **)&ill->ill_hcksum_capab;

	/*
	 * Note: range checks here are not absolutely sufficient to
	 * make us robust against malformed messages sent by drivers;
	 * this is in keeping with the rest of IP's dlpi handling.
	 * (Remember, it's coming from something else in the kernel
	 * address space)
	 */
	capend = (uint8_t *)(isub + 1) + isub->dl_length;
	if (capend > mp->b_wptr) {
		cmn_err(CE_WARN, "ill_capability_hcksum_ack: "
		    "malformed sub-capability too long for mblk");
		return;
	}

	/*
	 * There are two types of acks we process here:
	 * 1. acks in reply to a (first form) generic capability req
	 *    (no ENABLE flag set)
	 * 2. acks in reply to a ENABLE capability req.
	 *    (ENABLE flag set)
	 */
	ihck = (dl_capab_hcksum_t *)(isub + 1);

	if (ihck->hcksum_version != HCKSUM_VERSION_1) {
		cmn_err(CE_CONT, "ill_capability_hcksum_ack: "
		    "unsupported hardware checksum "
		    "sub-capability (version %d, expected %d)",
		    ihck->hcksum_version, HCKSUM_VERSION_1);
		return;
	}

	if (!dlcapabcheckqid(&ihck->hcksum_mid, ill->ill_lmod_rq)) {
		ip1dbg(("ill_capability_hcksum_ack: mid token for hardware "
		    "checksum capability isn't as expected; pass-thru "
		    "module(s) detected, discarding capability\n"));
		return;
	}

#define	CURR_HCKSUM_CAPAB				\
	(HCKSUM_INET_PARTIAL | HCKSUM_INET_FULL_V4 |	\
	HCKSUM_INET_FULL_V6 | HCKSUM_IPHDRCKSUM)

	if ((ihck->hcksum_txflags & HCKSUM_ENABLE) &&
	    (ihck->hcksum_txflags & CURR_HCKSUM_CAPAB)) {
		/* do ENABLE processing */
		if (*ill_hcksum == NULL) {
			*ill_hcksum = kmem_zalloc(sizeof (ill_hcksum_capab_t),
			    KM_NOSLEEP);

			if (*ill_hcksum == NULL) {
				cmn_err(CE_WARN, "ill_capability_hcksum_ack: "
				    "could not enable hcksum version %d "
				    "for %s (ENOMEM)\n", HCKSUM_CURRENT_VERSION,
				    ill->ill_name);
				return;
			}
		}

		(*ill_hcksum)->ill_hcksum_version = ihck->hcksum_version;
		(*ill_hcksum)->ill_hcksum_txflags = ihck->hcksum_txflags;
		ill->ill_capabilities |= ILL_CAPAB_HCKSUM;
		ip1dbg(("ill_capability_hcksum_ack: interface %s "
		    "has enabled hardware checksumming\n ",
		    ill->ill_name));
	} else if (ihck->hcksum_txflags & CURR_HCKSUM_CAPAB) {
		/*
		 * Enabling hardware checksum offload
		 * Currently IP supports {TCP,UDP}/IPv4
		 * partial and full cksum offload and
		 * IPv4 header checksum offload.
		 * Allocate new mblk which will
		 * contain a new capability request
		 * to enable hardware checksum offload.
		 */
		uint_t	size;
		uchar_t	*rptr;

		size = sizeof (dl_capability_req_t) +
		    sizeof (dl_capability_sub_t) + isub->dl_length;

		if ((nmp = ip_dlpi_alloc(size, DL_CAPABILITY_REQ)) == NULL) {
			cmn_err(CE_WARN, "ill_capability_hcksum_ack: "
			    "could not enable hardware cksum for %s (ENOMEM)\n",
			    ill->ill_name);
			return;
		}

		rptr = nmp->b_rptr;
		/* initialize dl_capability_req_t */
		ocap = (dl_capability_req_t *)nmp->b_rptr;
		ocap->dl_sub_offset =
		    sizeof (dl_capability_req_t);
		ocap->dl_sub_length =
		    sizeof (dl_capability_sub_t) +
		    isub->dl_length;
		nmp->b_rptr += sizeof (dl_capability_req_t);

		/* initialize dl_capability_sub_t */
		bcopy(isub, nmp->b_rptr, sizeof (*isub));
		nmp->b_rptr += sizeof (*isub);

		/* initialize dl_capab_hcksum_t */
		ohck = (dl_capab_hcksum_t *)nmp->b_rptr;
		bcopy(ihck, ohck, sizeof (*ihck));

		nmp->b_rptr = rptr;
		ASSERT(nmp->b_wptr == (nmp->b_rptr + size));

		/* Set ENABLE flag */
		ohck->hcksum_txflags &= CURR_HCKSUM_CAPAB;
		ohck->hcksum_txflags |= HCKSUM_ENABLE;

		/*
		 * nmp points to a DL_CAPABILITY_REQ message to enable
		 * hardware checksum acceleration.
		 */
		ill_capability_send(ill, nmp);
	} else {
		ip1dbg(("ill_capability_hcksum_ack: interface %s has "
		    "advertised %x hardware checksum capability flags\n",
		    ill->ill_name, ihck->hcksum_txflags));
	}
}

static void
ill_capability_hcksum_reset_fill(ill_t *ill, mblk_t *mp)
{
	dl_capab_hcksum_t *hck_subcap;
	dl_capability_sub_t *dl_subcap;

	if (!ILL_HCKSUM_CAPABLE(ill))
		return;

	ASSERT(ill->ill_hcksum_capab != NULL);

	dl_subcap = (dl_capability_sub_t *)mp->b_wptr;
	dl_subcap->dl_cap = DL_CAPAB_HCKSUM;
	dl_subcap->dl_length = sizeof (*hck_subcap);

	hck_subcap = (dl_capab_hcksum_t *)(dl_subcap + 1);
	hck_subcap->hcksum_version = ill->ill_hcksum_capab->ill_hcksum_version;
	hck_subcap->hcksum_txflags = 0;

	mp->b_wptr += sizeof (*dl_subcap) + sizeof (*hck_subcap);
}

static void
ill_capability_zerocopy_ack(ill_t *ill, mblk_t *mp, dl_capability_sub_t *isub)
{
	mblk_t *nmp = NULL;
	dl_capability_req_t *oc;
	dl_capab_zerocopy_t *zc_ic, *zc_oc;
	ill_zerocopy_capab_t **ill_zerocopy_capab;
	uint_t sub_dl_cap = isub->dl_cap;
	uint8_t *capend;

	ASSERT(sub_dl_cap == DL_CAPAB_ZEROCOPY);

	ill_zerocopy_capab = (ill_zerocopy_capab_t **)&ill->ill_zerocopy_capab;

	/*
	 * Note: range checks here are not absolutely sufficient to
	 * make us robust against malformed messages sent by drivers;
	 * this is in keeping with the rest of IP's dlpi handling.
	 * (Remember, it's coming from something else in the kernel
	 * address space)
	 */
	capend = (uint8_t *)(isub + 1) + isub->dl_length;
	if (capend > mp->b_wptr) {
		cmn_err(CE_WARN, "ill_capability_zerocopy_ack: "
		    "malformed sub-capability too long for mblk");
		return;
	}

	zc_ic = (dl_capab_zerocopy_t *)(isub + 1);
	if (zc_ic->zerocopy_version != ZEROCOPY_VERSION_1) {
		cmn_err(CE_CONT, "ill_capability_zerocopy_ack: "
		    "unsupported ZEROCOPY sub-capability (version %d, "
		    "expected %d)", zc_ic->zerocopy_version,
		    ZEROCOPY_VERSION_1);
		return;
	}

	if (!dlcapabcheckqid(&zc_ic->zerocopy_mid, ill->ill_lmod_rq)) {
		ip1dbg(("ill_capability_zerocopy_ack: mid token for zerocopy "
		    "capability isn't as expected; pass-thru module(s) "
		    "detected, discarding capability\n"));
		return;
	}

	if ((zc_ic->zerocopy_flags & DL_CAPAB_VMSAFE_MEM) != 0) {
		if (*ill_zerocopy_capab == NULL) {
			*ill_zerocopy_capab =
			    kmem_zalloc(sizeof (ill_zerocopy_capab_t),
			    KM_NOSLEEP);

			if (*ill_zerocopy_capab == NULL) {
				cmn_err(CE_WARN, "ill_capability_zerocopy_ack: "
				    "could not enable Zero-copy version %d "
				    "for %s (ENOMEM)\n", ZEROCOPY_VERSION_1,
				    ill->ill_name);
				return;
			}
		}

		ip1dbg(("ill_capability_zerocopy_ack: interface %s "
		    "supports Zero-copy version %d\n", ill->ill_name,
		    ZEROCOPY_VERSION_1));

		(*ill_zerocopy_capab)->ill_zerocopy_version =
		    zc_ic->zerocopy_version;
		(*ill_zerocopy_capab)->ill_zerocopy_flags =
		    zc_ic->zerocopy_flags;

		ill->ill_capabilities |= ILL_CAPAB_ZEROCOPY;
	} else {
		uint_t size;
		uchar_t *rptr;

		size = sizeof (dl_capability_req_t) +
		    sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_zerocopy_t);

		if ((nmp = ip_dlpi_alloc(size, DL_CAPABILITY_REQ)) == NULL) {
			cmn_err(CE_WARN, "ill_capability_zerocopy_ack: "
			    "could not enable zerocopy for %s (ENOMEM)\n",
			    ill->ill_name);
			return;
		}

		rptr = nmp->b_rptr;
		/* initialize dl_capability_req_t */
		oc = (dl_capability_req_t *)rptr;
		oc->dl_sub_offset = sizeof (dl_capability_req_t);
		oc->dl_sub_length = sizeof (dl_capability_sub_t) +
		    sizeof (dl_capab_zerocopy_t);
		rptr += sizeof (dl_capability_req_t);

		/* initialize dl_capability_sub_t */
		bcopy(isub, rptr, sizeof (*isub));
		rptr += sizeof (*isub);

		/* initialize dl_capab_zerocopy_t */
		zc_oc = (dl_capab_zerocopy_t *)rptr;
		*zc_oc = *zc_ic;

		ip1dbg(("ill_capability_zerocopy_ack: asking interface %s "
		    "to enable zero-copy version %d\n", ill->ill_name,
		    ZEROCOPY_VERSION_1));

		/* set VMSAFE_MEM flag */
		zc_oc->zerocopy_flags |= DL_CAPAB_VMSAFE_MEM;

		/* nmp points to a DL_CAPABILITY_REQ message to enable zcopy */
		ill_capability_send(ill, nmp);
	}
}

static void
ill_capability_zerocopy_reset_fill(ill_t *ill, mblk_t *mp)
{
	dl_capab_zerocopy_t *zerocopy_subcap;
	dl_capability_sub_t *dl_subcap;

	if (!(ill->ill_capabilities & ILL_CAPAB_ZEROCOPY))
		return;

	ASSERT(ill->ill_zerocopy_capab != NULL);

	dl_subcap = (dl_capability_sub_t *)mp->b_wptr;
	dl_subcap->dl_cap = DL_CAPAB_ZEROCOPY;
	dl_subcap->dl_length = sizeof (*zerocopy_subcap);

	zerocopy_subcap = (dl_capab_zerocopy_t *)(dl_subcap + 1);
	zerocopy_subcap->zerocopy_version =
	    ill->ill_zerocopy_capab->ill_zerocopy_version;
	zerocopy_subcap->zerocopy_flags = 0;

	mp->b_wptr += sizeof (*dl_subcap) + sizeof (*zerocopy_subcap);
}

/*
 * DLD capability
 * Refer to dld.h for more information regarding the purpose and usage
 * of this capability.
 */
static void
ill_capability_dld_ack(ill_t *ill, mblk_t *mp, dl_capability_sub_t *isub)
{
	dl_capab_dld_t		*dld_ic, dld;
	uint_t			sub_dl_cap = isub->dl_cap;
	uint8_t			*capend;
	ill_dld_capab_t		*idc;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(sub_dl_cap == DL_CAPAB_DLD);

	/*
	 * Note: range checks here are not absolutely sufficient to
	 * make us robust against malformed messages sent by drivers;
	 * this is in keeping with the rest of IP's dlpi handling.
	 * (Remember, it's coming from something else in the kernel
	 * address space)
	 */
	capend = (uint8_t *)(isub + 1) + isub->dl_length;
	if (capend > mp->b_wptr) {
		cmn_err(CE_WARN, "ill_capability_dld_ack: "
		    "malformed sub-capability too long for mblk");
		return;
	}
	dld_ic = (dl_capab_dld_t *)(isub + 1);
	if (dld_ic->dld_version != DLD_CURRENT_VERSION) {
		cmn_err(CE_CONT, "ill_capability_dld_ack: "
		    "unsupported DLD sub-capability (version %d, "
		    "expected %d)", dld_ic->dld_version,
		    DLD_CURRENT_VERSION);
		return;
	}
	if (!dlcapabcheckqid(&dld_ic->dld_mid, ill->ill_lmod_rq)) {
		ip1dbg(("ill_capability_dld_ack: mid token for dld "
		    "capability isn't as expected; pass-thru module(s) "
		    "detected, discarding capability\n"));
		return;
	}

	/*
	 * Copy locally to ensure alignment.
	 */
	bcopy(dld_ic, &dld, sizeof (dl_capab_dld_t));

	if ((idc = ill->ill_dld_capab) == NULL) {
		idc = kmem_zalloc(sizeof (ill_dld_capab_t), KM_NOSLEEP);
		if (idc == NULL) {
			cmn_err(CE_WARN, "ill_capability_dld_ack: "
			    "could not enable DLD version %d "
			    "for %s (ENOMEM)\n", DLD_CURRENT_VERSION,
			    ill->ill_name);
			return;
		}
		idc->idc_capab_df = (ip_capab_func_t)dld.dld_capab;
		idc->idc_capab_dh = (void *)dld.dld_capab_handle;
		ill->ill_dld_capab = idc;
	}
	ip1dbg(("ill_capability_dld_ack: interface %s "
	    "supports DLD version %d\n", ill->ill_name, DLD_CURRENT_VERSION));

	ill_capability_dld_enable(ill);
}

/*
 * Typically capability negotiation between IP and the driver happens via
 * DLPI message exchange. However GLD also offers a direct function call
 * mechanism to exchange the DLD_DIRECT_CAPAB and DLD_POLL_CAPAB capabilities,
 * But arbitrary function calls into IP or GLD are not permitted, since both
 * of them are protected by their own perimeter mechanism. The perimeter can
 * be viewed as a coarse lock or serialization mechanism. The hierarchy of
 * these perimeters is IP -> MAC. Thus for example to enable the squeue
 * polling, IP needs to enter its perimeter, then call ill_mac_perim_enter
 * to enter the mac perimeter and then do the direct function calls into
 * GLD to enable squeue polling. The ring related callbacks from the mac into
 * the stack to add, bind, quiesce, restart or cleanup a ring are all
 * protected by the mac perimeter.
 */
static void
ill_mac_perim_enter(ill_t *ill, mac_perim_handle_t *mphp)
{
	ill_dld_capab_t		*idc = ill->ill_dld_capab;
	int			err;

	err = idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_PERIM, mphp,
	    DLD_ENABLE);
	ASSERT(err == 0);
}

static void
ill_mac_perim_exit(ill_t *ill, mac_perim_handle_t mph)
{
	ill_dld_capab_t		*idc = ill->ill_dld_capab;
	int			err;

	err = idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_PERIM, mph,
	    DLD_DISABLE);
	ASSERT(err == 0);
}

boolean_t
ill_mac_perim_held(ill_t *ill)
{
	ill_dld_capab_t		*idc = ill->ill_dld_capab;

	return (idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_PERIM, NULL,
	    DLD_QUERY));
}

static void
ill_capability_direct_enable(ill_t *ill)
{
	ill_dld_capab_t		*idc = ill->ill_dld_capab;
	ill_dld_direct_t	*idd = &idc->idc_direct;
	dld_capab_direct_t	direct;
	int			rc;

	ASSERT(!ill->ill_isv6 && IAM_WRITER_ILL(ill));

	bzero(&direct, sizeof (direct));
	direct.di_rx_cf = (uintptr_t)ip_input;
	direct.di_rx_ch = ill;

	rc = idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_DIRECT, &direct,
	    DLD_ENABLE);
	if (rc == 0) {
		idd->idd_tx_df = (ip_dld_tx_t)direct.di_tx_df;
		idd->idd_tx_dh = direct.di_tx_dh;
		idd->idd_tx_cb_df = (ip_dld_callb_t)direct.di_tx_cb_df;
		idd->idd_tx_cb_dh = direct.di_tx_cb_dh;
		/*
		 * One time registration of flow enable callback function
		 */
		ill->ill_flownotify_mh = idd->idd_tx_cb_df(idd->idd_tx_cb_dh,
		    ill_flow_enable, ill);
		ill->ill_capabilities |= ILL_CAPAB_DLD_DIRECT;
		DTRACE_PROBE1(direct_on, (ill_t *), ill);
	} else {
		cmn_err(CE_WARN, "warning: could not enable DIRECT "
		    "capability, rc = %d\n", rc);
		DTRACE_PROBE2(direct_off, (ill_t *), ill, (int), rc);
	}
}

static void
ill_capability_poll_enable(ill_t *ill)
{
	ill_dld_capab_t		*idc = ill->ill_dld_capab;
	dld_capab_poll_t	poll;
	int			rc;

	ASSERT(!ill->ill_isv6 && IAM_WRITER_ILL(ill));

	bzero(&poll, sizeof (poll));
	poll.poll_ring_add_cf = (uintptr_t)ip_squeue_add_ring;
	poll.poll_ring_remove_cf = (uintptr_t)ip_squeue_clean_ring;
	poll.poll_ring_quiesce_cf = (uintptr_t)ip_squeue_quiesce_ring;
	poll.poll_ring_restart_cf = (uintptr_t)ip_squeue_restart_ring;
	poll.poll_ring_bind_cf = (uintptr_t)ip_squeue_bind_ring;
	poll.poll_ring_ch = ill;
	rc = idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_POLL, &poll,
	    DLD_ENABLE);
	if (rc == 0) {
		ill->ill_capabilities |= ILL_CAPAB_DLD_POLL;
		DTRACE_PROBE1(poll_on, (ill_t *), ill);
	} else {
		ip1dbg(("warning: could not enable POLL "
		    "capability, rc = %d\n", rc));
		DTRACE_PROBE2(poll_off, (ill_t *), ill, (int), rc);
	}
}

/*
 * Enable the LSO capability.
 */
static void
ill_capability_lso_enable(ill_t *ill)
{
	ill_dld_capab_t	*idc = ill->ill_dld_capab;
	dld_capab_lso_t	lso;
	int rc;

	ASSERT(!ill->ill_isv6 && IAM_WRITER_ILL(ill));

	if (ill->ill_lso_capab == NULL) {
		ill->ill_lso_capab = kmem_zalloc(sizeof (ill_lso_capab_t),
		    KM_NOSLEEP);
		if (ill->ill_lso_capab == NULL) {
			cmn_err(CE_WARN, "ill_capability_lso_enable: "
			    "could not enable LSO for %s (ENOMEM)\n",
			    ill->ill_name);
			return;
		}
	}

	bzero(&lso, sizeof (lso));
	if ((rc = idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_LSO, &lso,
	    DLD_ENABLE)) == 0) {
		ill->ill_lso_capab->ill_lso_flags = lso.lso_flags;
		ill->ill_lso_capab->ill_lso_max = lso.lso_max;
		ill->ill_capabilities |= ILL_CAPAB_DLD_LSO;
		ip1dbg(("ill_capability_lso_enable: interface %s "
		    "has enabled LSO\n ", ill->ill_name));
	} else {
		kmem_free(ill->ill_lso_capab, sizeof (ill_lso_capab_t));
		ill->ill_lso_capab = NULL;
		DTRACE_PROBE2(lso_off, (ill_t *), ill, (int), rc);
	}
}

static void
ill_capability_dld_enable(ill_t *ill)
{
	mac_perim_handle_t mph;

	ASSERT(IAM_WRITER_ILL(ill));

	if (ill->ill_isv6)
		return;

	ill_mac_perim_enter(ill, &mph);
	if (!ill->ill_isv6) {
		ill_capability_direct_enable(ill);
		ill_capability_poll_enable(ill);
		ill_capability_lso_enable(ill);
	}
	ill->ill_capabilities |= ILL_CAPAB_DLD;
	ill_mac_perim_exit(ill, mph);
}

static void
ill_capability_dld_disable(ill_t *ill)
{
	ill_dld_capab_t	*idc;
	ill_dld_direct_t *idd;
	mac_perim_handle_t	mph;

	ASSERT(IAM_WRITER_ILL(ill));

	if (!(ill->ill_capabilities & ILL_CAPAB_DLD))
		return;

	ill_mac_perim_enter(ill, &mph);

	idc = ill->ill_dld_capab;
	if ((ill->ill_capabilities & ILL_CAPAB_DLD_DIRECT) != 0) {
		/*
		 * For performance we avoid locks in the transmit data path
		 * and don't maintain a count of the number of threads using
		 * direct calls. Thus some threads could be using direct
		 * transmit calls to GLD, even after the capability mechanism
		 * turns it off. This is still safe since the handles used in
		 * the direct calls continue to be valid until the unplumb is
		 * completed. Remove the callback that was added (1-time) at
		 * capab enable time.
		 */
		mutex_enter(&ill->ill_lock);
		ill->ill_capabilities &= ~ILL_CAPAB_DLD_DIRECT;
		mutex_exit(&ill->ill_lock);
		if (ill->ill_flownotify_mh != NULL) {
			idd = &idc->idc_direct;
			idd->idd_tx_cb_df(idd->idd_tx_cb_dh, NULL,
			    ill->ill_flownotify_mh);
			ill->ill_flownotify_mh = NULL;
		}
		(void) idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_DIRECT,
		    NULL, DLD_DISABLE);
	}

	if ((ill->ill_capabilities & ILL_CAPAB_DLD_POLL) != 0) {
		ill->ill_capabilities &= ~ILL_CAPAB_DLD_POLL;
		ip_squeue_clean_all(ill);
		(void) idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_POLL,
		    NULL, DLD_DISABLE);
	}

	if ((ill->ill_capabilities & ILL_CAPAB_DLD_LSO) != 0) {
		ASSERT(ill->ill_lso_capab != NULL);
		/*
		 * Clear the capability flag for LSO but retain the
		 * ill_lso_capab structure since it's possible that another
		 * thread is still referring to it.  The structure only gets
		 * deallocated when we destroy the ill.
		 */

		ill->ill_capabilities &= ~ILL_CAPAB_DLD_LSO;
		(void) idc->idc_capab_df(idc->idc_capab_dh, DLD_CAPAB_LSO,
		    NULL, DLD_DISABLE);
	}

	ill->ill_capabilities &= ~ILL_CAPAB_DLD;
	ill_mac_perim_exit(ill, mph);
}

/*
 * Capability Negotiation protocol
 *
 * We don't wait for DLPI capability operations to finish during interface
 * bringup or teardown. Doing so would introduce more asynchrony and the
 * interface up/down operations will need multiple return and restarts.
 * Instead the 'ipsq_current_ipif' of the ipsq is not cleared as long as
 * the 'ill_dlpi_deferred' chain is non-empty. This ensures that the next
 * exclusive operation won't start until the DLPI operations of the previous
 * exclusive operation complete.
 *
 * The capability state machine is shown below.
 *
 * state		next state		event, action
 *
 * IDCS_UNKNOWN 	IDCS_PROBE_SENT		ill_capability_probe
 * IDCS_PROBE_SENT	IDCS_OK			ill_capability_ack
 * IDCS_PROBE_SENT	IDCS_FAILED		ip_rput_dlpi_writer (nack)
 * IDCS_OK		IDCS_RENEG		Receipt of DL_NOTE_CAPAB_RENEG
 * IDCS_OK		IDCS_RESET_SENT		ill_capability_reset
 * IDCS_RESET_SENT	IDCS_UNKNOWN		ill_capability_ack_thr
 * IDCS_RENEG		IDCS_PROBE_SENT		ill_capability_ack_thr ->
 *						    ill_capability_probe.
 */

/*
 * Dedicated thread started from ip_stack_init that handles capability
 * disable. This thread ensures the taskq dispatch does not fail by waiting
 * for resources using TQ_SLEEP. The taskq mechanism is used to ensure
 * that direct calls to DLD are done in a cv_waitable context.
 */
void
ill_taskq_dispatch(ip_stack_t *ipst)
{
	callb_cpr_t cprinfo;
	char 	name[64];
	mblk_t	*mp;

	(void) snprintf(name, sizeof (name), "ill_taskq_dispatch_%d",
	    ipst->ips_netstack->netstack_stackid);
	CALLB_CPR_INIT(&cprinfo, &ipst->ips_capab_taskq_lock, callb_generic_cpr,
	    name);
	mutex_enter(&ipst->ips_capab_taskq_lock);

	for (;;) {
		mp = list_head(&ipst->ips_capab_taskq_list);
		while (mp != NULL) {
			list_remove(&ipst->ips_capab_taskq_list, mp);
			mutex_exit(&ipst->ips_capab_taskq_lock);
			VERIFY(taskq_dispatch(system_taskq,
			    ill_capability_ack_thr, mp, TQ_SLEEP) != 0);
			mutex_enter(&ipst->ips_capab_taskq_lock);
			mp = list_head(&ipst->ips_capab_taskq_list);
		}

		if (ipst->ips_capab_taskq_quit)
			break;
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&ipst->ips_capab_taskq_cv, &ipst->ips_capab_taskq_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &ipst->ips_capab_taskq_lock);
	}
	VERIFY(list_head(&ipst->ips_capab_taskq_list) == NULL);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * Consume a new-style hardware capabilities negotiation ack.
 * Called via taskq on receipt of DL_CAPABBILITY_ACK.
 */
static void
ill_capability_ack_thr(void *arg)
{
	mblk_t	*mp = arg;
	dl_capability_ack_t *capp;
	dl_capability_sub_t *subp, *endp;
	ill_t	*ill;
	boolean_t reneg;

	ill = (ill_t *)mp->b_prev;
	VERIFY(ipsq_enter(ill, B_FALSE, CUR_OP) == B_TRUE);

	if (ill->ill_dlpi_capab_state == IDCS_RESET_SENT ||
	    ill->ill_dlpi_capab_state == IDCS_RENEG) {
		/*
		 * We have received the ack for our DL_CAPAB reset request.
		 * There isnt' anything in the message that needs processing.
		 * All message based capabilities have been disabled, now
		 * do the function call based capability disable.
		 */
		reneg = ill->ill_dlpi_capab_state == IDCS_RENEG;
		ill_capability_dld_disable(ill);
		ill->ill_dlpi_capab_state = IDCS_UNKNOWN;
		if (reneg)
			ill_capability_probe(ill);
		goto done;
	}

	if (ill->ill_dlpi_capab_state == IDCS_PROBE_SENT)
		ill->ill_dlpi_capab_state = IDCS_OK;

	capp = (dl_capability_ack_t *)mp->b_rptr;

	if (capp->dl_sub_length == 0) {
		/* no new-style capabilities */
		goto done;
	}

	/* make sure the driver supplied correct dl_sub_length */
	if ((sizeof (*capp) + capp->dl_sub_length) > MBLKL(mp)) {
		ip0dbg(("ill_capability_ack: bad DL_CAPABILITY_ACK, "
		    "invalid dl_sub_length (%d)\n", capp->dl_sub_length));
		goto done;
	}


#define	SC(base, offset) (dl_capability_sub_t *)(((uchar_t *)(base))+(offset))
	/*
	 * There are sub-capabilities. Process the ones we know about.
	 * Loop until we don't have room for another sub-cap header..
	 */
	for (subp = SC(capp, capp->dl_sub_offset),
	    endp = SC(subp, capp->dl_sub_length - sizeof (*subp));
	    subp <= endp;
	    subp = SC(subp, sizeof (dl_capability_sub_t) + subp->dl_length)) {

		switch (subp->dl_cap) {
		case DL_CAPAB_ID_WRAPPER:
			ill_capability_id_ack(ill, mp, subp);
			break;
		default:
			ill_capability_dispatch(ill, mp, subp, B_FALSE);
			break;
		}
	}
#undef SC
done:
	inet_freemsg(mp);
	ill_capability_done(ill);
	ipsq_exit(ill->ill_phyint->phyint_ipsq);
}

/*
 * This needs to be started in a taskq thread to provide a cv_waitable
 * context.
 */
void
ill_capability_ack(ill_t *ill, mblk_t *mp)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	mp->b_prev = (mblk_t *)ill;
	if (taskq_dispatch(system_taskq, ill_capability_ack_thr, mp,
	    TQ_NOSLEEP) != 0)
		return;

	/*
	 * The taskq dispatch failed. Signal the ill_taskq_dispatch thread
	 * which will do the dispatch using TQ_SLEEP to guarantee success.
	 */
	mutex_enter(&ipst->ips_capab_taskq_lock);
	list_insert_tail(&ipst->ips_capab_taskq_list, mp);
	cv_signal(&ipst->ips_capab_taskq_cv);
	mutex_exit(&ipst->ips_capab_taskq_lock);
}

/*
 * This routine is called to scan the fragmentation reassembly table for
 * the specified ILL for any packets that are starting to smell.
 * dead_interval is the maximum time in seconds that will be tolerated.  It
 * will either be the value specified in ip_g_frag_timeout, or zero if the
 * ILL is shutting down and it is time to blow everything off.
 *
 * It returns the number of seconds (as a time_t) that the next frag timer
 * should be scheduled for, 0 meaning that the timer doesn't need to be
 * re-started.  Note that the method of calculating next_timeout isn't
 * entirely accurate since time will flow between the time we grab
 * current_time and the time we schedule the next timeout.  This isn't a
 * big problem since this is the timer for sending an ICMP reassembly time
 * exceeded messages, and it doesn't have to be exactly accurate.
 *
 * This function is
 * sometimes called as writer, although this is not required.
 */
time_t
ill_frag_timeout(ill_t *ill, time_t dead_interval)
{
	ipfb_t	*ipfb;
	ipfb_t	*endp;
	ipf_t	*ipf;
	ipf_t	*ipfnext;
	mblk_t	*mp;
	time_t	current_time = gethrestime_sec();
	time_t	next_timeout = 0;
	uint32_t	hdr_length;
	mblk_t	*send_icmp_head;
	mblk_t	*send_icmp_head_v6;
	zoneid_t zoneid;
	ip_stack_t *ipst = ill->ill_ipst;

	ipfb = ill->ill_frag_hash_tbl;
	if (ipfb == NULL)
		return (B_FALSE);
	endp = &ipfb[ILL_FRAG_HASH_TBL_COUNT];
	/* Walk the frag hash table. */
	for (; ipfb < endp; ipfb++) {
		send_icmp_head = NULL;
		send_icmp_head_v6 = NULL;
		mutex_enter(&ipfb->ipfb_lock);
		while ((ipf = ipfb->ipfb_ipf) != 0) {
			time_t frag_time = current_time - ipf->ipf_timestamp;
			time_t frag_timeout;

			if (frag_time < dead_interval) {
				/*
				 * There are some outstanding fragments
				 * that will timeout later.  Make note of
				 * the time so that we can reschedule the
				 * next timeout appropriately.
				 */
				frag_timeout = dead_interval - frag_time;
				if (next_timeout == 0 ||
				    frag_timeout < next_timeout) {
					next_timeout = frag_timeout;
				}
				break;
			}
			/* Time's up.  Get it out of here. */
			hdr_length = ipf->ipf_nf_hdr_len;
			ipfnext = ipf->ipf_hash_next;
			if (ipfnext)
				ipfnext->ipf_ptphn = ipf->ipf_ptphn;
			*ipf->ipf_ptphn = ipfnext;
			mp = ipf->ipf_mp->b_cont;
			for (; mp; mp = mp->b_cont) {
				/* Extra points for neatness. */
				IP_REASS_SET_START(mp, 0);
				IP_REASS_SET_END(mp, 0);
			}
			mp = ipf->ipf_mp->b_cont;
			atomic_add_32(&ill->ill_frag_count, -ipf->ipf_count);
			ASSERT(ipfb->ipfb_count >= ipf->ipf_count);
			ipfb->ipfb_count -= ipf->ipf_count;
			ASSERT(ipfb->ipfb_frag_pkts > 0);
			ipfb->ipfb_frag_pkts--;
			/*
			 * We do not send any icmp message from here because
			 * we currently are holding the ipfb_lock for this
			 * hash chain. If we try and send any icmp messages
			 * from here we may end up via a put back into ip
			 * trying to get the same lock, causing a recursive
			 * mutex panic. Instead we build a list and send all
			 * the icmp messages after we have dropped the lock.
			 */
			if (ill->ill_isv6) {
				if (hdr_length != 0) {
					mp->b_next = send_icmp_head_v6;
					send_icmp_head_v6 = mp;
				} else {
					freemsg(mp);
				}
			} else {
				if (hdr_length != 0) {
					mp->b_next = send_icmp_head;
					send_icmp_head = mp;
				} else {
					freemsg(mp);
				}
			}
			BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmFails);
			freeb(ipf->ipf_mp);
		}
		mutex_exit(&ipfb->ipfb_lock);
		/*
		 * Now need to send any icmp messages that we delayed from
		 * above.
		 */
		while (send_icmp_head_v6 != NULL) {
			ip6_t *ip6h;

			mp = send_icmp_head_v6;
			send_icmp_head_v6 = send_icmp_head_v6->b_next;
			mp->b_next = NULL;
			if (mp->b_datap->db_type == M_CTL)
				ip6h = (ip6_t *)mp->b_cont->b_rptr;
			else
				ip6h = (ip6_t *)mp->b_rptr;
			zoneid = ipif_lookup_addr_zoneid_v6(&ip6h->ip6_dst,
			    ill, ipst);
			if (zoneid == ALL_ZONES) {
				freemsg(mp);
			} else {
				icmp_time_exceeded_v6(ill->ill_wq, mp,
				    ICMP_REASSEMBLY_TIME_EXCEEDED, B_FALSE,
				    B_FALSE, zoneid, ipst);
			}
		}
		while (send_icmp_head != NULL) {
			ipaddr_t dst;

			mp = send_icmp_head;
			send_icmp_head = send_icmp_head->b_next;
			mp->b_next = NULL;

			if (mp->b_datap->db_type == M_CTL)
				dst = ((ipha_t *)mp->b_cont->b_rptr)->ipha_dst;
			else
				dst = ((ipha_t *)mp->b_rptr)->ipha_dst;

			zoneid = ipif_lookup_addr_zoneid(dst, ill, ipst);
			if (zoneid == ALL_ZONES) {
				freemsg(mp);
			} else {
				icmp_time_exceeded(ill->ill_wq, mp,
				    ICMP_REASSEMBLY_TIME_EXCEEDED, zoneid,
				    ipst);
			}
		}
	}
	/*
	 * A non-dying ILL will use the return value to decide whether to
	 * restart the frag timer, and for how long.
	 */
	return (next_timeout);
}

/*
 * This routine is called when the approximate count of mblk memory used
 * for the specified ILL has exceeded max_count.
 */
void
ill_frag_prune(ill_t *ill, uint_t max_count)
{
	ipfb_t	*ipfb;
	ipf_t	*ipf;
	size_t	count;

	/*
	 * If we are here within ip_min_frag_prune_time msecs remove
	 * ill_frag_free_num_pkts oldest packets from each bucket and increment
	 * ill_frag_free_num_pkts.
	 */
	mutex_enter(&ill->ill_lock);
	if (TICK_TO_MSEC(lbolt - ill->ill_last_frag_clean_time) <=
	    (ip_min_frag_prune_time != 0 ?
	    ip_min_frag_prune_time : msec_per_tick)) {

		ill->ill_frag_free_num_pkts++;

	} else {
		ill->ill_frag_free_num_pkts = 0;
	}
	ill->ill_last_frag_clean_time = lbolt;
	mutex_exit(&ill->ill_lock);

	/*
	 * free ill_frag_free_num_pkts oldest packets from each bucket.
	 */
	if (ill->ill_frag_free_num_pkts != 0) {
		int ix;

		for (ix = 0; ix < ILL_FRAG_HASH_TBL_COUNT; ix++) {
			ipfb = &ill->ill_frag_hash_tbl[ix];
			mutex_enter(&ipfb->ipfb_lock);
			if (ipfb->ipfb_ipf != NULL) {
				ill_frag_free_pkts(ill, ipfb, ipfb->ipfb_ipf,
				    ill->ill_frag_free_num_pkts);
			}
			mutex_exit(&ipfb->ipfb_lock);
		}
	}
	/*
	 * While the reassembly list for this ILL is too big, prune a fragment
	 * queue by age, oldest first.
	 */
	while (ill->ill_frag_count > max_count) {
		int	ix;
		ipfb_t	*oipfb = NULL;
		uint_t	oldest = UINT_MAX;

		count = 0;
		for (ix = 0; ix < ILL_FRAG_HASH_TBL_COUNT; ix++) {
			ipfb = &ill->ill_frag_hash_tbl[ix];
			mutex_enter(&ipfb->ipfb_lock);
			ipf = ipfb->ipfb_ipf;
			if (ipf != NULL && ipf->ipf_gen < oldest) {
				oldest = ipf->ipf_gen;
				oipfb = ipfb;
			}
			count += ipfb->ipfb_count;
			mutex_exit(&ipfb->ipfb_lock);
		}
		if (oipfb == NULL)
			break;

		if (count <= max_count)
			return;	/* Somebody beat us to it, nothing to do */
		mutex_enter(&oipfb->ipfb_lock);
		ipf = oipfb->ipfb_ipf;
		if (ipf != NULL) {
			ill_frag_free_pkts(ill, oipfb, ipf, 1);
		}
		mutex_exit(&oipfb->ipfb_lock);
	}
}

/*
 * free 'free_cnt' fragmented packets starting at ipf.
 */
void
ill_frag_free_pkts(ill_t *ill, ipfb_t *ipfb, ipf_t *ipf, int free_cnt)
{
	size_t	count;
	mblk_t	*mp;
	mblk_t	*tmp;
	ipf_t **ipfp = ipf->ipf_ptphn;

	ASSERT(MUTEX_HELD(&ipfb->ipfb_lock));
	ASSERT(ipfp != NULL);
	ASSERT(ipf != NULL);

	while (ipf != NULL && free_cnt-- > 0) {
		count = ipf->ipf_count;
		mp = ipf->ipf_mp;
		ipf = ipf->ipf_hash_next;
		for (tmp = mp; tmp; tmp = tmp->b_cont) {
			IP_REASS_SET_START(tmp, 0);
			IP_REASS_SET_END(tmp, 0);
		}
		atomic_add_32(&ill->ill_frag_count, -count);
		ASSERT(ipfb->ipfb_count >= count);
		ipfb->ipfb_count -= count;
		ASSERT(ipfb->ipfb_frag_pkts > 0);
		ipfb->ipfb_frag_pkts--;
		freemsg(mp);
		BUMP_MIB(ill->ill_ip_mib, ipIfStatsReasmFails);
	}

	if (ipf)
		ipf->ipf_ptphn = ipfp;
	ipfp[0] = ipf;
}

#define	ND_FORWARD_WARNING	"The <if>:ip*_forwarding ndd variables are " \
	"obsolete and may be removed in a future release of Solaris.  Use " \
	"ifconfig(1M) to manipulate the forwarding status of an interface."

/*
 * For obsolete per-interface forwarding configuration;
 * called in response to ND_GET.
 */
/* ARGSUSED */
static int
nd_ill_forward_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *ioc_cr)
{
	ill_t *ill = (ill_t *)cp;

	cmn_err(CE_WARN, ND_FORWARD_WARNING);

	(void) mi_mpprintf(mp, "%d", (ill->ill_flags & ILLF_ROUTER) != 0);
	return (0);
}

/*
 * For obsolete per-interface forwarding configuration;
 * called in response to ND_SET.
 */
/* ARGSUSED */
static int
nd_ill_forward_set(queue_t *q, mblk_t *mp, char *valuestr, caddr_t cp,
    cred_t *ioc_cr)
{
	long value;
	int retval;
	ip_stack_t *ipst = CONNQ_TO_IPST(q);

	cmn_err(CE_WARN, ND_FORWARD_WARNING);

	if (ddi_strtol(valuestr, NULL, 10, &value) != 0 ||
	    value < 0 || value > 1) {
		return (EINVAL);
	}

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	retval = ill_forward_set((ill_t *)cp, (value != 0));
	rw_exit(&ipst->ips_ill_g_lock);
	return (retval);
}

/*
 * Helper function for ill_forward_set().
 */
static void
ill_forward_set_on_ill(ill_t *ill, boolean_t enable)
{
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_ILL(ill) || RW_READ_HELD(&ipst->ips_ill_g_lock));

	ip1dbg(("ill_forward_set: %s %s forwarding on %s",
	    (enable ? "Enabling" : "Disabling"),
	    (ill->ill_isv6 ? "IPv6" : "IPv4"), ill->ill_name));
	mutex_enter(&ill->ill_lock);
	if (enable)
		ill->ill_flags |= ILLF_ROUTER;
	else
		ill->ill_flags &= ~ILLF_ROUTER;
	mutex_exit(&ill->ill_lock);
	if (ill->ill_isv6)
		ill_set_nce_router_flags(ill, enable);
	/* Notify routing socket listeners of this change. */
	ip_rts_ifmsg(ill->ill_ipif, RTSQ_DEFAULT);
}

/*
 * Set an ill's ILLF_ROUTER flag appropriately.  Send up RTS_IFINFO routing
 * socket messages for each interface whose flags we change.
 */
int
ill_forward_set(ill_t *ill, boolean_t enable)
{
	ipmp_illgrp_t *illg;
	ip_stack_t *ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_ILL(ill) || RW_READ_HELD(&ipst->ips_ill_g_lock));

	if ((enable && (ill->ill_flags & ILLF_ROUTER)) ||
	    (!enable && !(ill->ill_flags & ILLF_ROUTER)))
		return (0);

	if (IS_LOOPBACK(ill))
		return (EINVAL);

	if (IS_IPMP(ill) || IS_UNDER_IPMP(ill)) {
		/*
		 * Update all of the interfaces in the group.
		 */
		illg = ill->ill_grp;
		ill = list_head(&illg->ig_if);
		for (; ill != NULL; ill = list_next(&illg->ig_if, ill))
			ill_forward_set_on_ill(ill, enable);

		/*
		 * Update the IPMP meta-interface.
		 */
		ill_forward_set_on_ill(ipmp_illgrp_ipmp_ill(illg), enable);
		return (0);
	}

	ill_forward_set_on_ill(ill, enable);
	return (0);
}

/*
 * Based on the ILLF_ROUTER flag of an ill, make sure all local nce's for
 * addresses assigned to the ill have the NCE_F_ISROUTER flag appropriately
 * set or clear.
 */
static void
ill_set_nce_router_flags(ill_t *ill, boolean_t enable)
{
	ipif_t *ipif;
	nce_t *nce;

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		/*
		 * NOTE: we match across the illgrp because nce's for
		 * addresses on IPMP interfaces have an nce_ill that points to
		 * the bound underlying ill.
		 */
		nce = ndp_lookup_v6(ill, B_TRUE, &ipif->ipif_v6lcl_addr,
		    B_FALSE);
		if (nce != NULL) {
			mutex_enter(&nce->nce_lock);
			if (enable)
				nce->nce_flags |= NCE_F_ISROUTER;
			else
				nce->nce_flags &= ~NCE_F_ISROUTER;
			mutex_exit(&nce->nce_lock);
			NCE_REFRELE(nce);
		}
	}
}

/*
 * Given an ill with a _valid_ name, add the ip_forwarding ndd variable
 * for this ill.  Make sure the v6/v4 question has been answered about this
 * ill.  The creation of this ndd variable is only for backwards compatibility.
 * The preferred way to control per-interface IP forwarding is through the
 * ILLF_ROUTER interface flag.
 */
static int
ill_set_ndd_name(ill_t *ill)
{
	char *suffix;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_ILL(ill));

	if (ill->ill_isv6)
		suffix = ipv6_forward_suffix;
	else
		suffix = ipv4_forward_suffix;

	ill->ill_ndd_name = ill->ill_name + ill->ill_name_length;
	bcopy(ill->ill_name, ill->ill_ndd_name, ill->ill_name_length - 1);
	/*
	 * Copies over the '\0'.
	 * Note that strlen(suffix) is always bounded.
	 */
	bcopy(suffix, ill->ill_ndd_name + ill->ill_name_length - 1,
	    strlen(suffix) + 1);

	/*
	 * Use of the nd table requires holding the reader lock.
	 * Modifying the nd table thru nd_load/nd_unload requires
	 * the writer lock.
	 */
	rw_enter(&ipst->ips_ip_g_nd_lock, RW_WRITER);
	if (!nd_load(&ipst->ips_ip_g_nd, ill->ill_ndd_name, nd_ill_forward_get,
	    nd_ill_forward_set, (caddr_t)ill)) {
		/*
		 * If the nd_load failed, it only meant that it could not
		 * allocate a new bunch of room for further NDD expansion.
		 * Because of that, the ill_ndd_name will be set to 0, and
		 * this interface is at the mercy of the global ip_forwarding
		 * variable.
		 */
		rw_exit(&ipst->ips_ip_g_nd_lock);
		ill->ill_ndd_name = NULL;
		return (ENOMEM);
	}
	rw_exit(&ipst->ips_ip_g_nd_lock);
	return (0);
}

/*
 * Intializes the context structure and returns the first ill in the list
 * cuurently start_list and end_list can have values:
 * MAX_G_HEADS		Traverse both IPV4 and IPV6 lists.
 * IP_V4_G_HEAD		Traverse IPV4 list only.
 * IP_V6_G_HEAD		Traverse IPV6 list only.
 */

/*
 * We don't check for CONDEMNED ills here. Caller must do that if
 * necessary under the ill lock.
 */
ill_t *
ill_first(int start_list, int end_list, ill_walk_context_t *ctx,
    ip_stack_t *ipst)
{
	ill_if_t *ifp;
	ill_t *ill;
	avl_tree_t *avl_tree;

	ASSERT(RW_LOCK_HELD(&ipst->ips_ill_g_lock));
	ASSERT(end_list <= MAX_G_HEADS && start_list >= 0);

	/*
	 * setup the lists to search
	 */
	if (end_list != MAX_G_HEADS) {
		ctx->ctx_current_list = start_list;
		ctx->ctx_last_list = end_list;
	} else {
		ctx->ctx_last_list = MAX_G_HEADS - 1;
		ctx->ctx_current_list = 0;
	}

	while (ctx->ctx_current_list <= ctx->ctx_last_list) {
		ifp = IP_VX_ILL_G_LIST(ctx->ctx_current_list, ipst);
		if (ifp != (ill_if_t *)
		    &IP_VX_ILL_G_LIST(ctx->ctx_current_list, ipst)) {
			avl_tree = &ifp->illif_avl_by_ppa;
			ill = avl_first(avl_tree);
			/*
			 * ill is guaranteed to be non NULL or ifp should have
			 * not existed.
			 */
			ASSERT(ill != NULL);
			return (ill);
		}
		ctx->ctx_current_list++;
	}

	return (NULL);
}

/*
 * returns the next ill in the list. ill_first() must have been called
 * before calling ill_next() or bad things will happen.
 */

/*
 * We don't check for CONDEMNED ills here. Caller must do that if
 * necessary under the ill lock.
 */
ill_t *
ill_next(ill_walk_context_t *ctx, ill_t *lastill)
{
	ill_if_t *ifp;
	ill_t *ill;
	ip_stack_t	*ipst = lastill->ill_ipst;

	ASSERT(lastill->ill_ifptr != (ill_if_t *)
	    &IP_VX_ILL_G_LIST(ctx->ctx_current_list, ipst));
	if ((ill = avl_walk(&lastill->ill_ifptr->illif_avl_by_ppa, lastill,
	    AVL_AFTER)) != NULL) {
		return (ill);
	}

	/* goto next ill_ifp in the list. */
	ifp = lastill->ill_ifptr->illif_next;

	/* make sure not at end of circular list */
	while (ifp ==
	    (ill_if_t *)&IP_VX_ILL_G_LIST(ctx->ctx_current_list, ipst)) {
		if (++ctx->ctx_current_list > ctx->ctx_last_list)
			return (NULL);
		ifp = IP_VX_ILL_G_LIST(ctx->ctx_current_list, ipst);
	}

	return (avl_first(&ifp->illif_avl_by_ppa));
}

/*
 * Check interface name for correct format: [a-zA-Z]+[a-zA-Z0-9._]*[0-9]+
 * The final number (PPA) must not have any leading zeros.  Upon success, a
 * pointer to the start of the PPA is returned; otherwise NULL is returned.
 */
static char *
ill_get_ppa_ptr(char *name)
{
	int namelen = strlen(name);
	int end_ndx = namelen - 1;
	int ppa_ndx, i;

	/*
	 * Check that the first character is [a-zA-Z], and that the last
	 * character is [0-9].
	 */
	if (namelen == 0 || !isalpha(name[0]) || !isdigit(name[end_ndx]))
		return (NULL);

	/*
	 * Set `ppa_ndx' to the PPA start, and check for leading zeroes.
	 */
	for (ppa_ndx = end_ndx; ppa_ndx > 0; ppa_ndx--)
		if (!isdigit(name[ppa_ndx - 1]))
			break;

	if (name[ppa_ndx] == '0' && ppa_ndx < end_ndx)
		return (NULL);

	/*
	 * Check that the intermediate characters are [a-z0-9.]
	 */
	for (i = 1; i < ppa_ndx; i++) {
		if (!isalpha(name[i]) && !isdigit(name[i]) &&
		    name[i] != '.' && name[i] != '_') {
			return (NULL);
		}
	}

	return (name + ppa_ndx);
}

/*
 * use avl tree to locate the ill.
 */
static ill_t *
ill_find_by_name(char *name, boolean_t isv6, queue_t *q, mblk_t *mp,
    ipsq_func_t func, int *error, ip_stack_t *ipst)
{
	char *ppa_ptr = NULL;
	int len;
	uint_t ppa;
	ill_t *ill = NULL;
	ill_if_t *ifp;
	int list;
	ipsq_t *ipsq;

	if (error != NULL)
		*error = 0;

	/*
	 * get ppa ptr
	 */
	if (isv6)
		list = IP_V6_G_HEAD;
	else
		list = IP_V4_G_HEAD;

	if ((ppa_ptr = ill_get_ppa_ptr(name)) == NULL) {
		if (error != NULL)
			*error = ENXIO;
		return (NULL);
	}

	len = ppa_ptr - name + 1;

	ppa = stoi(&ppa_ptr);

	ifp = IP_VX_ILL_G_LIST(list, ipst);

	while (ifp != (ill_if_t *)&IP_VX_ILL_G_LIST(list, ipst)) {
		/*
		 * match is done on len - 1 as the name is not null
		 * terminated it contains ppa in addition to the interface
		 * name.
		 */
		if ((ifp->illif_name_len == len) &&
		    bcmp(ifp->illif_name, name, len - 1) == 0) {
			break;
		} else {
			ifp = ifp->illif_next;
		}
	}

	if (ifp == (ill_if_t *)&IP_VX_ILL_G_LIST(list, ipst)) {
		/*
		 * Even the interface type does not exist.
		 */
		if (error != NULL)
			*error = ENXIO;
		return (NULL);
	}

	ill = avl_find(&ifp->illif_avl_by_ppa, (void *) &ppa, NULL);
	if (ill != NULL) {
		/*
		 * The block comment at the start of ipif_down
		 * explains the use of the macros used below
		 */
		GRAB_CONN_LOCK(q);
		mutex_enter(&ill->ill_lock);
		if (ILL_CAN_LOOKUP(ill)) {
			ill_refhold_locked(ill);
			mutex_exit(&ill->ill_lock);
			RELEASE_CONN_LOCK(q);
			return (ill);
		} else if (ILL_CAN_WAIT(ill, q)) {
			ipsq = ill->ill_phyint->phyint_ipsq;
			mutex_enter(&ipsq->ipsq_lock);
			mutex_enter(&ipsq->ipsq_xop->ipx_lock);
			mutex_exit(&ill->ill_lock);
			ipsq_enq(ipsq, q, mp, func, NEW_OP, ill);
			mutex_exit(&ipsq->ipsq_xop->ipx_lock);
			mutex_exit(&ipsq->ipsq_lock);
			RELEASE_CONN_LOCK(q);
			if (error != NULL)
				*error = EINPROGRESS;
			return (NULL);
		}
		mutex_exit(&ill->ill_lock);
		RELEASE_CONN_LOCK(q);
	}
	if (error != NULL)
		*error = ENXIO;
	return (NULL);
}

/*
 * comparison function for use with avl.
 */
static int
ill_compare_ppa(const void *ppa_ptr, const void *ill_ptr)
{
	uint_t ppa;
	uint_t ill_ppa;

	ASSERT(ppa_ptr != NULL && ill_ptr != NULL);

	ppa = *((uint_t *)ppa_ptr);
	ill_ppa = ((const ill_t *)ill_ptr)->ill_ppa;
	/*
	 * We want the ill with the lowest ppa to be on the
	 * top.
	 */
	if (ill_ppa < ppa)
		return (1);
	if (ill_ppa > ppa)
		return (-1);
	return (0);
}

/*
 * remove an interface type from the global list.
 */
static void
ill_delete_interface_type(ill_if_t *interface)
{
	ASSERT(interface != NULL);
	ASSERT(avl_numnodes(&interface->illif_avl_by_ppa) == 0);

	avl_destroy(&interface->illif_avl_by_ppa);
	if (interface->illif_ppa_arena != NULL)
		vmem_destroy(interface->illif_ppa_arena);

	remque(interface);

	mi_free(interface);
}

/*
 * remove ill from the global list.
 */
static void
ill_glist_delete(ill_t *ill)
{
	ip_stack_t	*ipst;
	phyint_t	*phyi;

	if (ill == NULL)
		return;
	ipst = ill->ill_ipst;
	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);

	/*
	 * If the ill was never inserted into the AVL tree
	 * we skip the if branch.
	 */
	if (ill->ill_ifptr != NULL) {
		/*
		 * remove from AVL tree and free ppa number
		 */
		avl_remove(&ill->ill_ifptr->illif_avl_by_ppa, ill);

		if (ill->ill_ifptr->illif_ppa_arena != NULL) {
			vmem_free(ill->ill_ifptr->illif_ppa_arena,
			    (void *)(uintptr_t)(ill->ill_ppa+1), 1);
		}
		if (avl_numnodes(&ill->ill_ifptr->illif_avl_by_ppa) == 0) {
			ill_delete_interface_type(ill->ill_ifptr);
		}

		/*
		 * Indicate ill is no longer in the list.
		 */
		ill->ill_ifptr = NULL;
		ill->ill_name_length = 0;
		ill->ill_name[0] = '\0';
		ill->ill_ppa = UINT_MAX;
	}

	/* Generate one last event for this ill. */
	ill_nic_event_dispatch(ill, 0, NE_UNPLUMB, ill->ill_name,
	    ill->ill_name_length);

	ASSERT(ill->ill_phyint != NULL);
	phyi = ill->ill_phyint;
	ill->ill_phyint = NULL;

	/*
	 * ill_init allocates a phyint always to store the copy
	 * of flags relevant to phyint. At that point in time, we could
	 * not assign the name and hence phyint_illv4/v6 could not be
	 * initialized. Later in ipif_set_values, we assign the name to
	 * the ill, at which point in time we assign phyint_illv4/v6.
	 * Thus we don't rely on phyint_illv6 to be initialized always.
	 */
	if (ill->ill_flags & ILLF_IPV6)
		phyi->phyint_illv6 = NULL;
	else
		phyi->phyint_illv4 = NULL;

	if (phyi->phyint_illv4 != NULL || phyi->phyint_illv6 != NULL) {
		rw_exit(&ipst->ips_ill_g_lock);
		return;
	}

	/*
	 * There are no ills left on this phyint; pull it out of the phyint
	 * avl trees, and free it.
	 */
	if (phyi->phyint_ifindex > 0) {
		avl_remove(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
		    phyi);
		avl_remove(&ipst->ips_phyint_g_list->phyint_list_avl_by_name,
		    phyi);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	phyint_free(phyi);
}

/*
 * allocate a ppa, if the number of plumbed interfaces of this type are
 * less than ill_no_arena do a linear search to find a unused ppa.
 * When the number goes beyond ill_no_arena switch to using an arena.
 * Note: ppa value of zero cannot be allocated from vmem_arena as it
 * is the return value for an error condition, so allocation starts at one
 * and is decremented by one.
 */
static int
ill_alloc_ppa(ill_if_t *ifp, ill_t *ill)
{
	ill_t *tmp_ill;
	uint_t start, end;
	int ppa;

	if (ifp->illif_ppa_arena == NULL &&
	    (avl_numnodes(&ifp->illif_avl_by_ppa) + 1 > ill_no_arena)) {
		/*
		 * Create an arena.
		 */
		ifp->illif_ppa_arena = vmem_create(ifp->illif_name,
		    (void *)1, UINT_MAX - 1, 1, NULL, NULL,
		    NULL, 0, VM_SLEEP | VMC_IDENTIFIER);
			/* allocate what has already been assigned */
		for (tmp_ill = avl_first(&ifp->illif_avl_by_ppa);
		    tmp_ill != NULL; tmp_ill = avl_walk(&ifp->illif_avl_by_ppa,
		    tmp_ill, AVL_AFTER)) {
			ppa = (int)(uintptr_t)vmem_xalloc(ifp->illif_ppa_arena,
			    1,		/* size */
			    1,		/* align/quantum */
			    0,		/* phase */
			    0,		/* nocross */
			    /* minaddr */
			    (void *)((uintptr_t)tmp_ill->ill_ppa + 1),
			    /* maxaddr */
			    (void *)((uintptr_t)tmp_ill->ill_ppa + 2),
			    VM_NOSLEEP|VM_FIRSTFIT);
			if (ppa == 0) {
				ip1dbg(("ill_alloc_ppa: ppa allocation"
				    " failed while switching"));
				vmem_destroy(ifp->illif_ppa_arena);
				ifp->illif_ppa_arena = NULL;
				break;
			}
		}
	}

	if (ifp->illif_ppa_arena != NULL) {
		if (ill->ill_ppa == UINT_MAX) {
			ppa = (int)(uintptr_t)vmem_alloc(ifp->illif_ppa_arena,
			    1, VM_NOSLEEP|VM_FIRSTFIT);
			if (ppa == 0)
				return (EAGAIN);
			ill->ill_ppa = --ppa;
		} else {
			ppa = (int)(uintptr_t)vmem_xalloc(ifp->illif_ppa_arena,
			    1, 		/* size */
			    1, 		/* align/quantum */
			    0, 		/* phase */
			    0, 		/* nocross */
			    (void *)(uintptr_t)(ill->ill_ppa + 1), /* minaddr */
			    (void *)(uintptr_t)(ill->ill_ppa + 2), /* maxaddr */
			    VM_NOSLEEP|VM_FIRSTFIT);
			/*
			 * Most likely the allocation failed because
			 * the requested ppa was in use.
			 */
			if (ppa == 0)
				return (EEXIST);
		}
		return (0);
	}

	/*
	 * No arena is in use and not enough (>ill_no_arena) interfaces have
	 * been plumbed to create one. Do a linear search to get a unused ppa.
	 */
	if (ill->ill_ppa == UINT_MAX) {
		end = UINT_MAX - 1;
		start = 0;
	} else {
		end = start = ill->ill_ppa;
	}

	tmp_ill = avl_find(&ifp->illif_avl_by_ppa, (void *)&start, NULL);
	while (tmp_ill != NULL && tmp_ill->ill_ppa == start) {
		if (start++ >= end) {
			if (ill->ill_ppa == UINT_MAX)
				return (EAGAIN);
			else
				return (EEXIST);
		}
		tmp_ill = avl_walk(&ifp->illif_avl_by_ppa, tmp_ill, AVL_AFTER);
	}
	ill->ill_ppa = start;
	return (0);
}

/*
 * Insert ill into the list of configured ill's. Once this function completes,
 * the ill is globally visible and is available through lookups. More precisely
 * this happens after the caller drops the ill_g_lock.
 */
static int
ill_glist_insert(ill_t *ill, char *name, boolean_t isv6)
{
	ill_if_t *ill_interface;
	avl_index_t where = 0;
	int error;
	int name_length;
	int index;
	boolean_t check_length = B_FALSE;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(RW_WRITE_HELD(&ipst->ips_ill_g_lock));

	name_length = mi_strlen(name) + 1;

	if (isv6)
		index = IP_V6_G_HEAD;
	else
		index = IP_V4_G_HEAD;

	ill_interface = IP_VX_ILL_G_LIST(index, ipst);
	/*
	 * Search for interface type based on name
	 */
	while (ill_interface != (ill_if_t *)&IP_VX_ILL_G_LIST(index, ipst)) {
		if ((ill_interface->illif_name_len == name_length) &&
		    (strcmp(ill_interface->illif_name, name) == 0)) {
			break;
		}
		ill_interface = ill_interface->illif_next;
	}

	/*
	 * Interface type not found, create one.
	 */
	if (ill_interface == (ill_if_t *)&IP_VX_ILL_G_LIST(index, ipst)) {

		ill_g_head_t ghead;

		/*
		 * allocate ill_if_t structure
		 */

		ill_interface = (ill_if_t *)mi_zalloc(sizeof (ill_if_t));
		if (ill_interface == NULL) {
			return (ENOMEM);
		}



		(void) strcpy(ill_interface->illif_name, name);
		ill_interface->illif_name_len = name_length;

		avl_create(&ill_interface->illif_avl_by_ppa,
		    ill_compare_ppa, sizeof (ill_t),
		    offsetof(struct ill_s, ill_avl_byppa));

		/*
		 * link the structure in the back to maintain order
		 * of configuration for ifconfig output.
		 */
		ghead = ipst->ips_ill_g_heads[index];
		insque(ill_interface, ghead.ill_g_list_tail);

	}

	if (ill->ill_ppa == UINT_MAX)
		check_length = B_TRUE;

	error = ill_alloc_ppa(ill_interface, ill);
	if (error != 0) {
		if (avl_numnodes(&ill_interface->illif_avl_by_ppa) == 0)
			ill_delete_interface_type(ill->ill_ifptr);
		return (error);
	}

	/*
	 * When the ppa is choosen by the system, check that there is
	 * enough space to insert ppa. if a specific ppa was passed in this
	 * check is not required as the interface name passed in will have
	 * the right ppa in it.
	 */
	if (check_length) {
		/*
		 * UINT_MAX - 1 should fit in 10 chars, alloc 12 chars.
		 */
		char buf[sizeof (uint_t) * 3];

		/*
		 * convert ppa to string to calculate the amount of space
		 * required for it in the name.
		 */
		numtos(ill->ill_ppa, buf);

		/* Do we have enough space to insert ppa ? */

		if ((mi_strlen(name) + mi_strlen(buf) + 1) > LIFNAMSIZ) {
			/* Free ppa and interface type struct */
			if (ill_interface->illif_ppa_arena != NULL) {
				vmem_free(ill_interface->illif_ppa_arena,
				    (void *)(uintptr_t)(ill->ill_ppa+1), 1);
			}
			if (avl_numnodes(&ill_interface->illif_avl_by_ppa) == 0)
				ill_delete_interface_type(ill->ill_ifptr);

			return (EINVAL);
		}
	}

	(void) sprintf(ill->ill_name, "%s%u", name, ill->ill_ppa);
	ill->ill_name_length = mi_strlen(ill->ill_name) + 1;

	(void) avl_find(&ill_interface->illif_avl_by_ppa, &ill->ill_ppa,
	    &where);
	ill->ill_ifptr = ill_interface;
	avl_insert(&ill_interface->illif_avl_by_ppa, ill, where);

	ill_phyint_reinit(ill);
	return (0);
}

/* Initialize the per phyint ipsq used for serialization */
static boolean_t
ipsq_init(ill_t *ill, boolean_t enter)
{
	ipsq_t  *ipsq;
	ipxop_t	*ipx;

	if ((ipsq = kmem_zalloc(sizeof (ipsq_t), KM_NOSLEEP)) == NULL)
		return (B_FALSE);

	ill->ill_phyint->phyint_ipsq = ipsq;
	ipx = ipsq->ipsq_xop = &ipsq->ipsq_ownxop;
	ipx->ipx_ipsq = ipsq;
	ipsq->ipsq_next = ipsq;
	ipsq->ipsq_phyint = ill->ill_phyint;
	mutex_init(&ipsq->ipsq_lock, NULL, MUTEX_DEFAULT, 0);
	mutex_init(&ipx->ipx_lock, NULL, MUTEX_DEFAULT, 0);
	ipsq->ipsq_ipst = ill->ill_ipst;	/* No netstack_hold */
	if (enter) {
		ipx->ipx_writer = curthread;
		ipx->ipx_forced = B_FALSE;
		ipx->ipx_reentry_cnt = 1;
#ifdef DEBUG
		ipx->ipx_depth = getpcstack(ipx->ipx_stack, IPX_STACK_DEPTH);
#endif
	}
	return (B_TRUE);
}

/*
 * ill_init is called by ip_open when a device control stream is opened.
 * It does a few initializations, and shoots a DL_INFO_REQ message down
 * to the driver.  The response is later picked up in ip_rput_dlpi and
 * used to set up default mechanisms for talking to the driver.  (Always
 * called as writer.)
 *
 * If this function returns error, ip_open will call ip_close which in
 * turn will call ill_delete to clean up any memory allocated here that
 * is not yet freed.
 */
int
ill_init(queue_t *q, ill_t *ill)
{
	int	count;
	dl_info_req_t	*dlir;
	mblk_t	*info_mp;
	uchar_t *frag_ptr;

	/*
	 * The ill is initialized to zero by mi_alloc*(). In addition
	 * some fields already contain valid values, initialized in
	 * ip_open(), before we reach here.
	 */
	mutex_init(&ill->ill_lock, NULL, MUTEX_DEFAULT, 0);

	ill->ill_rq = q;
	ill->ill_wq = WR(q);

	info_mp = allocb(MAX(sizeof (dl_info_req_t), sizeof (dl_info_ack_t)),
	    BPRI_HI);
	if (info_mp == NULL)
		return (ENOMEM);

	/*
	 * Allocate sufficient space to contain our fragment hash table and
	 * the device name.
	 */
	frag_ptr = (uchar_t *)mi_zalloc(ILL_FRAG_HASH_TBL_SIZE +
	    2 * LIFNAMSIZ + 5 + strlen(ipv6_forward_suffix));
	if (frag_ptr == NULL) {
		freemsg(info_mp);
		return (ENOMEM);
	}
	ill->ill_frag_ptr = frag_ptr;
	ill->ill_frag_free_num_pkts = 0;
	ill->ill_last_frag_clean_time = 0;
	ill->ill_frag_hash_tbl = (ipfb_t *)frag_ptr;
	ill->ill_name = (char *)(frag_ptr + ILL_FRAG_HASH_TBL_SIZE);
	for (count = 0; count < ILL_FRAG_HASH_TBL_COUNT; count++) {
		mutex_init(&ill->ill_frag_hash_tbl[count].ipfb_lock,
		    NULL, MUTEX_DEFAULT, NULL);
	}

	ill->ill_phyint = (phyint_t *)mi_zalloc(sizeof (phyint_t));
	if (ill->ill_phyint == NULL) {
		freemsg(info_mp);
		mi_free(frag_ptr);
		return (ENOMEM);
	}

	mutex_init(&ill->ill_phyint->phyint_lock, NULL, MUTEX_DEFAULT, 0);
	/*
	 * For now pretend this is a v4 ill. We need to set phyint_ill*
	 * at this point because of the following reason. If we can't
	 * enter the ipsq at some point and cv_wait, the writer that
	 * wakes us up tries to locate us using the list of all phyints
	 * in an ipsq and the ills from the phyint thru the phyint_ill*.
	 * If we don't set it now, we risk a missed wakeup.
	 */
	ill->ill_phyint->phyint_illv4 = ill;
	ill->ill_ppa = UINT_MAX;
	ill->ill_fastpath_list = &ill->ill_fastpath_list;

	if (!ipsq_init(ill, B_TRUE)) {
		freemsg(info_mp);
		mi_free(frag_ptr);
		mi_free(ill->ill_phyint);
		return (ENOMEM);
	}

	ill->ill_state_flags |= ILL_LL_SUBNET_PENDING;

	/* Frag queue limit stuff */
	ill->ill_frag_count = 0;
	ill->ill_ipf_gen = 0;

	ill->ill_global_timer = INFINITY;
	ill->ill_mcast_v1_time = ill->ill_mcast_v2_time = 0;
	ill->ill_mcast_v1_tset = ill->ill_mcast_v2_tset = 0;
	ill->ill_mcast_rv = MCAST_DEF_ROBUSTNESS;
	ill->ill_mcast_qi = MCAST_DEF_QUERY_INTERVAL;

	/*
	 * Initialize IPv6 configuration variables.  The IP module is always
	 * opened as an IPv4 module.  Instead tracking down the cases where
	 * it switches to do ipv6, we'll just initialize the IPv6 configuration
	 * here for convenience, this has no effect until the ill is set to do
	 * IPv6.
	 */
	ill->ill_reachable_time = ND_REACHABLE_TIME;
	ill->ill_reachable_retrans_time = ND_RETRANS_TIMER;
	ill->ill_xmit_count = ND_MAX_MULTICAST_SOLICIT;
	ill->ill_max_buf = ND_MAX_Q;
	ill->ill_refcnt = 0;

	/* Send down the Info Request to the driver. */
	info_mp->b_datap->db_type = M_PCPROTO;
	dlir = (dl_info_req_t *)info_mp->b_rptr;
	info_mp->b_wptr = (uchar_t *)&dlir[1];
	dlir->dl_primitive = DL_INFO_REQ;

	ill->ill_dlpi_pending = DL_PRIM_INVAL;

	qprocson(q);
	ill_dlpi_send(ill, info_mp);

	return (0);
}

/*
 * ill_dls_info
 * creates datalink socket info from the device.
 */
int
ill_dls_info(struct sockaddr_dl *sdl, const ipif_t *ipif)
{
	size_t	len;
	ill_t	*ill = ipif->ipif_ill;

	sdl->sdl_family = AF_LINK;
	sdl->sdl_index = ill->ill_phyint->phyint_ifindex;
	sdl->sdl_type = ill->ill_type;
	ipif_get_name(ipif, sdl->sdl_data, sizeof (sdl->sdl_data));
	len = strlen(sdl->sdl_data);
	ASSERT(len < 256);
	sdl->sdl_nlen = (uchar_t)len;
	sdl->sdl_alen = ill->ill_phys_addr_length;
	sdl->sdl_slen = 0;
	if (ill->ill_phys_addr_length != 0 && ill->ill_phys_addr != NULL)
		bcopy(ill->ill_phys_addr, &sdl->sdl_data[len], sdl->sdl_alen);

	return (sizeof (struct sockaddr_dl));
}

/*
 * ill_xarp_info
 * creates xarp info from the device.
 */
static int
ill_xarp_info(struct sockaddr_dl *sdl, ill_t *ill)
{
	sdl->sdl_family = AF_LINK;
	sdl->sdl_index = ill->ill_phyint->phyint_ifindex;
	sdl->sdl_type = ill->ill_type;
	ipif_get_name(ill->ill_ipif, sdl->sdl_data, sizeof (sdl->sdl_data));
	sdl->sdl_nlen = (uchar_t)mi_strlen(sdl->sdl_data);
	sdl->sdl_alen = ill->ill_phys_addr_length;
	sdl->sdl_slen = 0;
	return (sdl->sdl_nlen);
}

static int
loopback_kstat_update(kstat_t *ksp, int rw)
{
	kstat_named_t *kn;
	netstackid_t	stackid;
	netstack_t	*ns;
	ip_stack_t	*ipst;

	if (ksp == NULL || ksp->ks_data == NULL)
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	kn = KSTAT_NAMED_PTR(ksp);
	stackid = (zoneid_t)(uintptr_t)ksp->ks_private;

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);

	ipst = ns->netstack_ip;
	if (ipst == NULL) {
		netstack_rele(ns);
		return (-1);
	}
	kn[0].value.ui32 = ipst->ips_loopback_packets;
	kn[1].value.ui32 = ipst->ips_loopback_packets;
	netstack_rele(ns);
	return (0);
}

/*
 * Has ifindex been plumbed already?
 */
static boolean_t
phyint_exists(uint_t index, ip_stack_t *ipst)
{
	ASSERT(index != 0);
	ASSERT(RW_LOCK_HELD(&ipst->ips_ill_g_lock));

	return (avl_find(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
	    &index, NULL) != NULL);
}

/* Pick a unique ifindex */
boolean_t
ip_assign_ifindex(uint_t *indexp, ip_stack_t *ipst)
{
	uint_t starting_index;

	if (!ipst->ips_ill_index_wrap) {
		*indexp = ipst->ips_ill_index++;
		if (ipst->ips_ill_index == 0) {
			/* Reached the uint_t limit Next time wrap  */
			ipst->ips_ill_index_wrap = B_TRUE;
		}
		return (B_TRUE);
	}

	/*
	 * Start reusing unused indexes. Note that we hold the ill_g_lock
	 * at this point and don't want to call any function that attempts
	 * to get the lock again.
	 */
	starting_index = ipst->ips_ill_index++;
	for (; ipst->ips_ill_index != starting_index; ipst->ips_ill_index++) {
		if (ipst->ips_ill_index != 0 &&
		    !phyint_exists(ipst->ips_ill_index, ipst)) {
			/* found unused index - use it */
			*indexp = ipst->ips_ill_index;
			return (B_TRUE);
		}
	}

	/*
	 * all interface indicies are inuse.
	 */
	return (B_FALSE);
}

/*
 * Assign a unique interface index for the phyint.
 */
static boolean_t
phyint_assign_ifindex(phyint_t *phyi, ip_stack_t *ipst)
{
	ASSERT(phyi->phyint_ifindex == 0);
	return (ip_assign_ifindex(&phyi->phyint_ifindex, ipst));
}

/*
 * Return a pointer to the ill which matches the supplied name.  Note that
 * the ill name length includes the null termination character.  (May be
 * called as writer.)
 * If do_alloc and the interface is "lo0" it will be automatically created.
 * Cannot bump up reference on condemned ills. So dup detect can't be done
 * using this func.
 */
ill_t *
ill_lookup_on_name(char *name, boolean_t do_alloc, boolean_t isv6,
    queue_t *q, mblk_t *mp, ipsq_func_t func, int *error, boolean_t *did_alloc,
    ip_stack_t *ipst)
{
	ill_t	*ill;
	ipif_t	*ipif;
	ipsq_t	*ipsq;
	kstat_named_t	*kn;
	boolean_t isloopback;
	in6_addr_t ov6addr;

	isloopback = mi_strcmp(name, ipif_loopback_name) == 0;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ill_find_by_name(name, isv6, q, mp, func, error, ipst);
	rw_exit(&ipst->ips_ill_g_lock);
	if (ill != NULL || (error != NULL && *error == EINPROGRESS))
		return (ill);

	/*
	 * Couldn't find it.  Does this happen to be a lookup for the
	 * loopback device and are we allowed to allocate it?
	 */
	if (!isloopback || !do_alloc)
		return (NULL);

	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);

	ill = ill_find_by_name(name, isv6, q, mp, func, error, ipst);
	if (ill != NULL || (error != NULL && *error == EINPROGRESS)) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (ill);
	}

	/* Create the loopback device on demand */
	ill = (ill_t *)(mi_alloc(sizeof (ill_t) +
	    sizeof (ipif_loopback_name), BPRI_MED));
	if (ill == NULL)
		goto done;

	*ill = ill_null;
	mutex_init(&ill->ill_lock, NULL, MUTEX_DEFAULT, NULL);
	ill->ill_ipst = ipst;
	netstack_hold(ipst->ips_netstack);
	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make IP operate as if in the global zone.
	 */
	ill->ill_zoneid = GLOBAL_ZONEID;

	ill->ill_phyint = (phyint_t *)mi_zalloc(sizeof (phyint_t));
	if (ill->ill_phyint == NULL)
		goto done;

	if (isv6)
		ill->ill_phyint->phyint_illv6 = ill;
	else
		ill->ill_phyint->phyint_illv4 = ill;
	mutex_init(&ill->ill_phyint->phyint_lock, NULL, MUTEX_DEFAULT, 0);
	ill->ill_max_frag = IP_LOOPBACK_MTU;
	/* Add room for tcp+ip headers */
	if (isv6) {
		ill->ill_isv6 = B_TRUE;
		ill->ill_max_frag += IPV6_HDR_LEN + 20;	/* for TCP */
	} else {
		ill->ill_max_frag += IP_SIMPLE_HDR_LENGTH + 20;
	}
	if (!ill_allocate_mibs(ill))
		goto done;
	ill->ill_max_mtu = ill->ill_max_frag;
	/*
	 * ipif_loopback_name can't be pointed at directly because its used
	 * by both the ipv4 and ipv6 interfaces.  When the ill is removed
	 * from the glist, ill_glist_delete() sets the first character of
	 * ill_name to '\0'.
	 */
	ill->ill_name = (char *)ill + sizeof (*ill);
	(void) strcpy(ill->ill_name, ipif_loopback_name);
	ill->ill_name_length = sizeof (ipif_loopback_name);
	/* Set ill_dlpi_pending for ipsq_current_finish() to work properly */
	ill->ill_dlpi_pending = DL_PRIM_INVAL;

	ill->ill_global_timer = INFINITY;
	ill->ill_mcast_v1_time = ill->ill_mcast_v2_time = 0;
	ill->ill_mcast_v1_tset = ill->ill_mcast_v2_tset = 0;
	ill->ill_mcast_rv = MCAST_DEF_ROBUSTNESS;
	ill->ill_mcast_qi = MCAST_DEF_QUERY_INTERVAL;

	/* No resolver here. */
	ill->ill_net_type = IRE_LOOPBACK;

	/* Initialize the ipsq */
	if (!ipsq_init(ill, B_FALSE))
		goto done;

	ipif = ipif_allocate(ill, 0L, IRE_LOOPBACK, B_TRUE, B_TRUE);
	if (ipif == NULL)
		goto done;

	ill->ill_flags = ILLF_MULTICAST;

	ov6addr = ipif->ipif_v6lcl_addr;
	/* Set up default loopback address and mask. */
	if (!isv6) {
		ipaddr_t inaddr_loopback = htonl(INADDR_LOOPBACK);

		IN6_IPADDR_TO_V4MAPPED(inaddr_loopback, &ipif->ipif_v6lcl_addr);
		ipif->ipif_v6src_addr = ipif->ipif_v6lcl_addr;
		V4MASK_TO_V6(htonl(IN_CLASSA_NET), ipif->ipif_v6net_mask);
		V6_MASK_COPY(ipif->ipif_v6lcl_addr, ipif->ipif_v6net_mask,
		    ipif->ipif_v6subnet);
		ill->ill_flags |= ILLF_IPV4;
	} else {
		ipif->ipif_v6lcl_addr = ipv6_loopback;
		ipif->ipif_v6src_addr = ipif->ipif_v6lcl_addr;
		ipif->ipif_v6net_mask = ipv6_all_ones;
		V6_MASK_COPY(ipif->ipif_v6lcl_addr, ipif->ipif_v6net_mask,
		    ipif->ipif_v6subnet);
		ill->ill_flags |= ILLF_IPV6;
	}

	/*
	 * Chain us in at the end of the ill list. hold the ill
	 * before we make it globally visible. 1 for the lookup.
	 */
	ill->ill_refcnt = 0;
	ill_refhold(ill);

	ill->ill_frag_count = 0;
	ill->ill_frag_free_num_pkts = 0;
	ill->ill_last_frag_clean_time = 0;

	ipsq = ill->ill_phyint->phyint_ipsq;

	if (ill_glist_insert(ill, "lo", isv6) != 0)
		cmn_err(CE_PANIC, "cannot insert loopback interface");

	/* Let SCTP know so that it can add this to its list */
	sctp_update_ill(ill, SCTP_ILL_INSERT);

	/*
	 * We have already assigned ipif_v6lcl_addr above, but we need to
	 * call sctp_update_ipif_addr() after SCTP_ILL_INSERT, which
	 * requires to be after ill_glist_insert() since we need the
	 * ill_index set. Pass on ipv6_loopback as the old address.
	 */
	sctp_update_ipif_addr(ipif, ov6addr);

	/*
	 * ill_glist_insert() -> ill_phyint_reinit() may have merged IPSQs.
	 * If so, free our original one.
	 */
	if (ipsq != ill->ill_phyint->phyint_ipsq)
		ipsq_delete(ipsq);

	/*
	 * Delay this till the ipif is allocated as ipif_allocate
	 * de-references ill_phyint for getting the ifindex. We
	 * can't do this before ipif_allocate because ill_phyint_reinit
	 * -> phyint_assign_ifindex expects ipif to be present.
	 */
	mutex_enter(&ill->ill_phyint->phyint_lock);
	ill->ill_phyint->phyint_flags |= PHYI_LOOPBACK | PHYI_VIRTUAL;
	mutex_exit(&ill->ill_phyint->phyint_lock);

	if (ipst->ips_loopback_ksp == NULL) {
		/* Export loopback interface statistics */
		ipst->ips_loopback_ksp = kstat_create_netstack("lo", 0,
		    ipif_loopback_name, "net",
		    KSTAT_TYPE_NAMED, 2, 0,
		    ipst->ips_netstack->netstack_stackid);
		if (ipst->ips_loopback_ksp != NULL) {
			ipst->ips_loopback_ksp->ks_update =
			    loopback_kstat_update;
			kn = KSTAT_NAMED_PTR(ipst->ips_loopback_ksp);
			kstat_named_init(&kn[0], "ipackets", KSTAT_DATA_UINT32);
			kstat_named_init(&kn[1], "opackets", KSTAT_DATA_UINT32);
			ipst->ips_loopback_ksp->ks_private =
			    (void *)(uintptr_t)ipst->ips_netstack->
			    netstack_stackid;
			kstat_install(ipst->ips_loopback_ksp);
		}
	}

	if (error != NULL)
		*error = 0;
	*did_alloc = B_TRUE;
	rw_exit(&ipst->ips_ill_g_lock);
	ill_nic_event_dispatch(ill, MAP_IPIF_ID(ill->ill_ipif->ipif_id),
	    NE_PLUMB, ill->ill_name, ill->ill_name_length);
	return (ill);
done:
	if (ill != NULL) {
		if (ill->ill_phyint != NULL) {
			ipsq = ill->ill_phyint->phyint_ipsq;
			if (ipsq != NULL) {
				ipsq->ipsq_phyint = NULL;
				ipsq_delete(ipsq);
			}
			mi_free(ill->ill_phyint);
		}
		ill_free_mib(ill);
		if (ill->ill_ipst != NULL)
			netstack_rele(ill->ill_ipst->ips_netstack);
		mi_free(ill);
	}
	rw_exit(&ipst->ips_ill_g_lock);
	if (error != NULL)
		*error = ENOMEM;
	return (NULL);
}

/*
 * For IPP calls - use the ip_stack_t for global stack.
 */
ill_t *
ill_lookup_on_ifindex_global_instance(uint_t index, boolean_t isv6,
    queue_t *q, mblk_t *mp, ipsq_func_t func, int *err)
{
	ip_stack_t	*ipst;
	ill_t		*ill;

	ipst = netstack_find_by_stackid(GLOBAL_NETSTACKID)->netstack_ip;
	if (ipst == NULL) {
		cmn_err(CE_WARN, "No ip_stack_t for zoneid zero!\n");
		return (NULL);
	}

	ill = ill_lookup_on_ifindex(index, isv6, q, mp, func, err, ipst);
	netstack_rele(ipst->ips_netstack);
	return (ill);
}

/*
 * Return a pointer to the ill which matches the index and IP version type.
 */
ill_t *
ill_lookup_on_ifindex(uint_t index, boolean_t isv6, queue_t *q, mblk_t *mp,
    ipsq_func_t func, int *err, ip_stack_t *ipst)
{
	ill_t	*ill;
	ipsq_t  *ipsq;
	phyint_t *phyi;

	ASSERT((q == NULL && mp == NULL && func == NULL && err == NULL) ||
	    (q != NULL && mp != NULL && func != NULL && err != NULL));

	if (err != NULL)
		*err = 0;

	/*
	 * Indexes are stored in the phyint - a common structure
	 * to both IPv4 and IPv6.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	phyi = avl_find(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
	    (void *) &index, NULL);
	if (phyi != NULL) {
		ill = isv6 ? phyi->phyint_illv6: phyi->phyint_illv4;
		if (ill != NULL) {
			/*
			 * The block comment at the start of ipif_down
			 * explains the use of the macros used below
			 */
			GRAB_CONN_LOCK(q);
			mutex_enter(&ill->ill_lock);
			if (ILL_CAN_LOOKUP(ill)) {
				ill_refhold_locked(ill);
				mutex_exit(&ill->ill_lock);
				RELEASE_CONN_LOCK(q);
				rw_exit(&ipst->ips_ill_g_lock);
				return (ill);
			} else if (ILL_CAN_WAIT(ill, q)) {
				ipsq = ill->ill_phyint->phyint_ipsq;
				mutex_enter(&ipsq->ipsq_lock);
				mutex_enter(&ipsq->ipsq_xop->ipx_lock);
				rw_exit(&ipst->ips_ill_g_lock);
				mutex_exit(&ill->ill_lock);
				ipsq_enq(ipsq, q, mp, func, NEW_OP, ill);
				mutex_exit(&ipsq->ipsq_xop->ipx_lock);
				mutex_exit(&ipsq->ipsq_lock);
				RELEASE_CONN_LOCK(q);
				if (err != NULL)
					*err = EINPROGRESS;
				return (NULL);
			}
			RELEASE_CONN_LOCK(q);
			mutex_exit(&ill->ill_lock);
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);
	if (err != NULL)
		*err = ENXIO;
	return (NULL);
}

/*
 * Return the ifindex next in sequence after the passed in ifindex.
 * If there is no next ifindex for the given protocol, return 0.
 */
uint_t
ill_get_next_ifindex(uint_t index, boolean_t isv6, ip_stack_t *ipst)
{
	phyint_t *phyi;
	phyint_t *phyi_initial;
	uint_t   ifindex;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	if (index == 0) {
		phyi = avl_first(
		    &ipst->ips_phyint_g_list->phyint_list_avl_by_index);
	} else {
		phyi = phyi_initial = avl_find(
		    &ipst->ips_phyint_g_list->phyint_list_avl_by_index,
		    (void *) &index, NULL);
	}

	for (; phyi != NULL;
	    phyi = avl_walk(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
	    phyi, AVL_AFTER)) {
		/*
		 * If we're not returning the first interface in the tree
		 * and we still haven't moved past the phyint_t that
		 * corresponds to index, avl_walk needs to be called again
		 */
		if (!((index != 0) && (phyi == phyi_initial))) {
			if (isv6) {
				if ((phyi->phyint_illv6) &&
				    ILL_CAN_LOOKUP(phyi->phyint_illv6) &&
				    (phyi->phyint_illv6->ill_isv6 == 1))
					break;
			} else {
				if ((phyi->phyint_illv4) &&
				    ILL_CAN_LOOKUP(phyi->phyint_illv4) &&
				    (phyi->phyint_illv4->ill_isv6 == 0))
					break;
			}
		}
	}

	rw_exit(&ipst->ips_ill_g_lock);

	if (phyi != NULL)
		ifindex = phyi->phyint_ifindex;
	else
		ifindex = 0;

	return (ifindex);
}

/*
 * Return the ifindex for the named interface.
 * If there is no next ifindex for the interface, return 0.
 */
uint_t
ill_get_ifindex_by_name(char *name, ip_stack_t *ipst)
{
	phyint_t	*phyi;
	avl_index_t	where = 0;
	uint_t		ifindex;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	if ((phyi = avl_find(&ipst->ips_phyint_g_list->phyint_list_avl_by_name,
	    name, &where)) == NULL) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (0);
	}

	ifindex = phyi->phyint_ifindex;

	rw_exit(&ipst->ips_ill_g_lock);

	return (ifindex);
}

/*
 * Obtain a reference to the ill. The ill_refcnt is a dynamic refcnt
 * that gives a running thread a reference to the ill. This reference must be
 * released by the thread when it is done accessing the ill and related
 * objects. ill_refcnt can not be used to account for static references
 * such as other structures pointing to an ill. Callers must generally
 * check whether an ill can be refheld by using ILL_CAN_LOOKUP macros
 * or be sure that the ill is not being deleted or changing state before
 * calling the refhold functions. A non-zero ill_refcnt ensures that the
 * ill won't change any of its critical state such as address, netmask etc.
 */
void
ill_refhold(ill_t *ill)
{
	mutex_enter(&ill->ill_lock);
	ill->ill_refcnt++;
	ILL_TRACE_REF(ill);
	mutex_exit(&ill->ill_lock);
}

void
ill_refhold_locked(ill_t *ill)
{
	ASSERT(MUTEX_HELD(&ill->ill_lock));
	ill->ill_refcnt++;
	ILL_TRACE_REF(ill);
}

int
ill_check_and_refhold(ill_t *ill)
{
	mutex_enter(&ill->ill_lock);
	if (ILL_CAN_LOOKUP(ill)) {
		ill_refhold_locked(ill);
		mutex_exit(&ill->ill_lock);
		return (0);
	}
	mutex_exit(&ill->ill_lock);
	return (ILL_LOOKUP_FAILED);
}

/*
 * Must not be called while holding any locks. Otherwise if this is
 * the last reference to be released, there is a chance of recursive mutex
 * panic due to ill_refrele -> ipif_ill_refrele_tail -> qwriter_ip trying
 * to restart an ioctl.
 */
void
ill_refrele(ill_t *ill)
{
	mutex_enter(&ill->ill_lock);
	ASSERT(ill->ill_refcnt != 0);
	ill->ill_refcnt--;
	ILL_UNTRACE_REF(ill);
	if (ill->ill_refcnt != 0) {
		/* Every ire pointing to the ill adds 1 to ill_refcnt */
		mutex_exit(&ill->ill_lock);
		return;
	}

	/* Drops the ill_lock */
	ipif_ill_refrele_tail(ill);
}

/*
 * Obtain a weak reference count on the ill. This reference ensures the
 * ill won't be freed, but the ill may change any of its critical state
 * such as netmask, address etc. Returns an error if the ill has started
 * closing.
 */
boolean_t
ill_waiter_inc(ill_t *ill)
{
	mutex_enter(&ill->ill_lock);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		return (B_FALSE);
	}
	ill->ill_waiters++;
	mutex_exit(&ill->ill_lock);
	return (B_TRUE);
}

void
ill_waiter_dcr(ill_t *ill)
{
	mutex_enter(&ill->ill_lock);
	ill->ill_waiters--;
	if (ill->ill_waiters == 0)
		cv_broadcast(&ill->ill_cv);
	mutex_exit(&ill->ill_lock);
}

/*
 * Named Dispatch routine to produce a formatted report on all ILLs.
 * This report is accessed by using the ndd utility to "get" ND variable
 * "ip_ill_status".
 */
/* ARGSUSED */
int
ip_ill_report(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *ioc_cr)
{
	ill_t		*ill;
	ill_walk_context_t ctx;
	ip_stack_t	*ipst;

	ipst = CONNQ_TO_IPST(q);

	(void) mi_mpprintf(mp,
	    "ILL      " MI_COL_HDRPAD_STR
	/*   01234567[89ABCDEF] */
	    "rq       " MI_COL_HDRPAD_STR
	/*   01234567[89ABCDEF] */
	    "wq       " MI_COL_HDRPAD_STR
	/*   01234567[89ABCDEF] */
	    "upcnt mxfrg err name");
	/*   12345 12345 123 xxxxxxxx  */

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_ALL(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		(void) mi_mpprintf(mp,
		    MI_COL_PTRFMT_STR MI_COL_PTRFMT_STR MI_COL_PTRFMT_STR
		    "%05u %05u %03d %s",
		    (void *)ill, (void *)ill->ill_rq, (void *)ill->ill_wq,
		    ill->ill_ipif_up_count,
		    ill->ill_max_frag, ill->ill_error, ill->ill_name);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	return (0);
}

/*
 * Named Dispatch routine to produce a formatted report on all IPIFs.
 * This report is accessed by using the ndd utility to "get" ND variable
 * "ip_ipif_status".
 */
/* ARGSUSED */
int
ip_ipif_report(queue_t *q, mblk_t *mp, caddr_t arg, cred_t *ioc_cr)
{
	char	buf1[INET6_ADDRSTRLEN];
	char	buf2[INET6_ADDRSTRLEN];
	char	buf3[INET6_ADDRSTRLEN];
	char	buf4[INET6_ADDRSTRLEN];
	char	buf5[INET6_ADDRSTRLEN];
	char	buf6[INET6_ADDRSTRLEN];
	char	buf[LIFNAMSIZ];
	ill_t	*ill;
	ipif_t	*ipif;
	nv_t	*nvp;
	uint64_t flags;
	zoneid_t zoneid;
	ill_walk_context_t ctx;
	ip_stack_t *ipst = CONNQ_TO_IPST(q);

	(void) mi_mpprintf(mp,
	    "IPIF metric mtu in/out/forward name zone flags...\n"
	    "\tlocal address\n"
	    "\tsrc address\n"
	    "\tsubnet\n"
	    "\tmask\n"
	    "\tbroadcast\n"
	    "\tp-p-dst");

	ASSERT(q->q_next == NULL);
	zoneid = Q_TO_CONN(q)->conn_zoneid;	/* IP is a driver */

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_ALL(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != GLOBAL_ZONEID &&
			    zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;

			ipif_get_name(ipif, buf, sizeof (buf));
			(void) mi_mpprintf(mp,
			    MI_COL_PTRFMT_STR
			    "%04u %05u %u/%u/%u %s %d",
			    (void *)ipif,
			    ipif->ipif_metric, ipif->ipif_mtu,
			    ipif->ipif_ib_pkt_count,
			    ipif->ipif_ob_pkt_count,
			    ipif->ipif_fo_pkt_count,
			    buf,
			    ipif->ipif_zoneid);

		flags = ipif->ipif_flags | ipif->ipif_ill->ill_flags |
		    ipif->ipif_ill->ill_phyint->phyint_flags;

		/* Tack on text strings for any flags. */
		nvp = ipif_nv_tbl;
		for (; nvp < A_END(ipif_nv_tbl); nvp++) {
			if (nvp->nv_value & flags)
				(void) mi_mpprintf_nr(mp, " %s",
				    nvp->nv_name);
		}
		(void) mi_mpprintf(mp,
		    "\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s",
		    inet_ntop(AF_INET6,
		    &ipif->ipif_v6lcl_addr, buf1, sizeof (buf1)),
		    inet_ntop(AF_INET6,
		    &ipif->ipif_v6src_addr, buf2, sizeof (buf2)),
		    inet_ntop(AF_INET6,
		    &ipif->ipif_v6subnet, buf3, sizeof (buf3)),
		    inet_ntop(AF_INET6,
		    &ipif->ipif_v6net_mask, buf4, sizeof (buf4)),
		    inet_ntop(AF_INET6,
		    &ipif->ipif_v6brd_addr, buf5, sizeof (buf5)),
		    inet_ntop(AF_INET6,
		    &ipif->ipif_v6pp_dst_addr, buf6, sizeof (buf6)));
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);
	return (0);
}

/*
 * ip_ll_subnet_defaults is called when we get the DL_INFO_ACK back from the
 * driver.  We construct best guess defaults for lower level information that
 * we need.  If an interface is brought up without injection of any overriding
 * information from outside, we have to be ready to go with these defaults.
 * When we get the first DL_INFO_ACK (from ip_open() sending a DL_INFO_REQ)
 * we primarely want the dl_provider_style.
 * The subsequent DL_INFO_ACK is received after doing a DL_ATTACH and DL_BIND
 * at which point we assume the other part of the information is valid.
 */
void
ip_ll_subnet_defaults(ill_t *ill, mblk_t *mp)
{
	uchar_t		*brdcst_addr;
	uint_t		brdcst_addr_length, phys_addr_length;
	t_scalar_t	sap_length;
	dl_info_ack_t	*dlia;
	ip_m_t		*ipm;
	dl_qos_cl_sel1_t *sel1;
	int		min_mtu;

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Till the ill is fully up ILL_CHANGING will be set and
	 * the ill is not globally visible. So no need for a lock.
	 */
	dlia = (dl_info_ack_t *)mp->b_rptr;
	ill->ill_mactype = dlia->dl_mac_type;

	ipm = ip_m_lookup(dlia->dl_mac_type);
	if (ipm == NULL) {
		ipm = ip_m_lookup(DL_OTHER);
		ASSERT(ipm != NULL);
	}
	ill->ill_media = ipm;

	/*
	 * When the new DLPI stuff is ready we'll pull lengths
	 * from dlia.
	 */
	if (dlia->dl_version == DL_VERSION_2) {
		brdcst_addr_length = dlia->dl_brdcst_addr_length;
		brdcst_addr = mi_offset_param(mp, dlia->dl_brdcst_addr_offset,
		    brdcst_addr_length);
		if (brdcst_addr == NULL) {
			brdcst_addr_length = 0;
		}
		sap_length = dlia->dl_sap_length;
		phys_addr_length = dlia->dl_addr_length - ABS(sap_length);
		ip1dbg(("ip: bcast_len %d, sap_len %d, phys_len %d\n",
		    brdcst_addr_length, sap_length, phys_addr_length));
	} else {
		brdcst_addr_length = 6;
		brdcst_addr = ip_six_byte_all_ones;
		sap_length = -2;
		phys_addr_length = brdcst_addr_length;
	}

	ill->ill_bcast_addr_length = brdcst_addr_length;
	ill->ill_phys_addr_length = phys_addr_length;
	ill->ill_sap_length = sap_length;

	/*
	 * Synthetic DLPI types such as SUNW_DL_IPMP specify a zero SDU,
	 * but we must ensure a minimum IP MTU is used since other bits of
	 * IP will fly apart otherwise.
	 */
	min_mtu = ill->ill_isv6 ? IPV6_MIN_MTU : IP_MIN_MTU;
	ill->ill_max_frag  = MAX(min_mtu, dlia->dl_max_sdu);
	ill->ill_max_mtu = ill->ill_max_frag;

	ill->ill_type = ipm->ip_m_type;

	if (!ill->ill_dlpi_style_set) {
		if (dlia->dl_provider_style == DL_STYLE2)
			ill->ill_needs_attach = 1;

		/*
		 * Allocate the first ipif on this ill. We don't delay it
		 * further as ioctl handling assumes atleast one ipif to
		 * be present.
		 *
		 * At this point we don't know whether the ill is v4 or v6.
		 * We will know this whan the SIOCSLIFNAME happens and
		 * the correct value for ill_isv6 will be assigned in
		 * ipif_set_values(). We need to hold the ill lock and
		 * clear the ILL_LL_SUBNET_PENDING flag and atomically do
		 * the wakeup.
		 */
		(void) ipif_allocate(ill, 0, IRE_LOCAL,
		    dlia->dl_provider_style != DL_STYLE2, B_TRUE);
		mutex_enter(&ill->ill_lock);
		ASSERT(ill->ill_dlpi_style_set == 0);
		ill->ill_dlpi_style_set = 1;
		ill->ill_state_flags &= ~ILL_LL_SUBNET_PENDING;
		cv_broadcast(&ill->ill_cv);
		mutex_exit(&ill->ill_lock);
		freemsg(mp);
		return;
	}
	ASSERT(ill->ill_ipif != NULL);
	/*
	 * We know whether it is IPv4 or IPv6 now, as this is the
	 * second DL_INFO_ACK we are recieving in response to the
	 * DL_INFO_REQ sent in ipif_set_values.
	 */
	if (ill->ill_isv6)
		ill->ill_sap = IP6_DL_SAP;
	else
		ill->ill_sap = IP_DL_SAP;
	/*
	 * Set ipif_mtu which is used to set the IRE's
	 * ire_max_frag value. The driver could have sent
	 * a different mtu from what it sent last time. No
	 * need to call ipif_mtu_change because IREs have
	 * not yet been created.
	 */
	ill->ill_ipif->ipif_mtu = ill->ill_max_mtu;
	/*
	 * Clear all the flags that were set based on ill_bcast_addr_length
	 * and ill_phys_addr_length (in ipif_set_values) as these could have
	 * changed now and we need to re-evaluate.
	 */
	ill->ill_flags &= ~(ILLF_MULTICAST | ILLF_NONUD | ILLF_NOARP);
	ill->ill_ipif->ipif_flags &= ~(IPIF_BROADCAST | IPIF_POINTOPOINT);

	/*
	 * Free ill_resolver_mp and ill_bcast_mp as things could have
	 * changed now.
	 *
	 * NOTE: The IPMP meta-interface is special-cased because it starts
	 * with no underlying interfaces (and thus an unknown broadcast
	 * address length), but we enforce that an interface is broadcast-
	 * capable as part of allowing it to join a group.
	 */
	if (ill->ill_bcast_addr_length == 0 && !IS_IPMP(ill)) {
		if (ill->ill_resolver_mp != NULL)
			freemsg(ill->ill_resolver_mp);
		if (ill->ill_bcast_mp != NULL)
			freemsg(ill->ill_bcast_mp);
		if (ill->ill_flags & ILLF_XRESOLV)
			ill->ill_net_type = IRE_IF_RESOLVER;
		else
			ill->ill_net_type = IRE_IF_NORESOLVER;
		ill->ill_resolver_mp = ill_dlur_gen(NULL,
		    ill->ill_phys_addr_length,
		    ill->ill_sap,
		    ill->ill_sap_length);
		ill->ill_bcast_mp = copymsg(ill->ill_resolver_mp);

		if (ill->ill_isv6)
			/*
			 * Note: xresolv interfaces will eventually need NOARP
			 * set here as well, but that will require those
			 * external resolvers to have some knowledge of
			 * that flag and act appropriately. Not to be changed
			 * at present.
			 */
			ill->ill_flags |= ILLF_NONUD;
		else
			ill->ill_flags |= ILLF_NOARP;

		if (ill->ill_phys_addr_length == 0) {
			if (ill->ill_media->ip_m_mac_type == SUNW_DL_VNI) {
				ill->ill_ipif->ipif_flags |= IPIF_NOXMIT;
				ill->ill_phyint->phyint_flags |= PHYI_VIRTUAL;
			} else {
				/* pt-pt supports multicast. */
				ill->ill_flags |= ILLF_MULTICAST;
				ill->ill_ipif->ipif_flags |= IPIF_POINTOPOINT;
			}
		}
	} else {
		ill->ill_net_type = IRE_IF_RESOLVER;
		if (ill->ill_bcast_mp != NULL)
			freemsg(ill->ill_bcast_mp);
		ill->ill_bcast_mp = ill_dlur_gen(brdcst_addr,
		    ill->ill_bcast_addr_length, ill->ill_sap,
		    ill->ill_sap_length);
		/*
		 * Later detect lack of DLPI driver multicast
		 * capability by catching DL_ENABMULTI errors in
		 * ip_rput_dlpi.
		 */
		ill->ill_flags |= ILLF_MULTICAST;
		if (!ill->ill_isv6)
			ill->ill_ipif->ipif_flags |= IPIF_BROADCAST;
	}

	/* For IPMP, PHYI_IPMP should already be set by ipif_allocate() */
	if (ill->ill_mactype == SUNW_DL_IPMP)
		ASSERT(ill->ill_phyint->phyint_flags & PHYI_IPMP);

	/* By default an interface does not support any CoS marking */
	ill->ill_flags &= ~ILLF_COS_ENABLED;

	/*
	 * If we get QoS information in DL_INFO_ACK, the device supports
	 * some form of CoS marking, set ILLF_COS_ENABLED.
	 */
	sel1 = (dl_qos_cl_sel1_t *)mi_offset_param(mp, dlia->dl_qos_offset,
	    dlia->dl_qos_length);
	if ((sel1 != NULL) && (sel1->dl_qos_type == DL_QOS_CL_SEL1)) {
		ill->ill_flags |= ILLF_COS_ENABLED;
	}

	/* Clear any previous error indication. */
	ill->ill_error = 0;
	freemsg(mp);
}

/*
 * Perform various checks to verify that an address would make sense as a
 * local, remote, or subnet interface address.
 */
static boolean_t
ip_addr_ok_v4(ipaddr_t addr, ipaddr_t subnet_mask)
{
	ipaddr_t	net_mask;

	/*
	 * Don't allow all zeroes, or all ones, but allow
	 * all ones netmask.
	 */
	if ((net_mask = ip_net_mask(addr)) == 0)
		return (B_FALSE);
	/* A given netmask overrides the "guess" netmask */
	if (subnet_mask != 0)
		net_mask = subnet_mask;
	if ((net_mask != ~(ipaddr_t)0) && ((addr == (addr & net_mask)) ||
	    (addr == (addr | ~net_mask)))) {
		return (B_FALSE);
	}

	/*
	 * Even if the netmask is all ones, we do not allow address to be
	 * 255.255.255.255
	 */
	if (addr == INADDR_BROADCAST)
		return (B_FALSE);

	if (CLASSD(addr))
		return (B_FALSE);

	return (B_TRUE);
}

#define	V6_IPIF_LINKLOCAL(p)	\
	IN6_IS_ADDR_LINKLOCAL(&(p)->ipif_v6lcl_addr)

/*
 * Compare two given ipifs and check if the second one is better than
 * the first one using the order of preference (not taking deprecated
 * into acount) specified in ipif_lookup_multicast().
 */
static boolean_t
ipif_comp_multi(ipif_t *old_ipif, ipif_t *new_ipif, boolean_t isv6)
{
	/* Check the least preferred first. */
	if (IS_LOOPBACK(old_ipif->ipif_ill)) {
		/* If both ipifs are the same, use the first one. */
		if (IS_LOOPBACK(new_ipif->ipif_ill))
			return (B_FALSE);
		else
			return (B_TRUE);
	}

	/* For IPv6, check for link local address. */
	if (isv6 && V6_IPIF_LINKLOCAL(old_ipif)) {
		if (IS_LOOPBACK(new_ipif->ipif_ill) ||
		    V6_IPIF_LINKLOCAL(new_ipif)) {
			/* The second one is equal or less preferred. */
			return (B_FALSE);
		} else {
			return (B_TRUE);
		}
	}

	/* Then check for point to point interface. */
	if (old_ipif->ipif_flags & IPIF_POINTOPOINT) {
		if (IS_LOOPBACK(new_ipif->ipif_ill) ||
		    (isv6 && V6_IPIF_LINKLOCAL(new_ipif)) ||
		    (new_ipif->ipif_flags & IPIF_POINTOPOINT)) {
			return (B_FALSE);
		} else {
			return (B_TRUE);
		}
	}

	/* old_ipif is a normal interface, so no need to use the new one. */
	return (B_FALSE);
}

/*
 * Find a mulitcast-capable ipif given an IP instance and zoneid.
 * The ipif must be up, and its ill must multicast-capable, not
 * condemned, not an underlying interface in an IPMP group, and
 * not a VNI interface.  Order of preference:
 *
 * 	1a. normal
 * 	1b. normal, but deprecated
 * 	2a. point to point
 * 	2b. point to point, but deprecated
 * 	3a. link local
 * 	3b. link local, but deprecated
 * 	4. loopback.
 */
ipif_t *
ipif_lookup_multicast(ip_stack_t *ipst, zoneid_t zoneid, boolean_t isv6)
{
	ill_t			*ill;
	ill_walk_context_t	ctx;
	ipif_t			*ipif;
	ipif_t			*saved_ipif = NULL;
	ipif_t			*dep_ipif = NULL;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (isv6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_V4(&ctx, ipst);

	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		mutex_enter(&ill->ill_lock);
		if (IS_VNI(ill) || IS_UNDER_IPMP(ill) || !ILL_CAN_LOOKUP(ill) ||
		    !(ill->ill_flags & ILLF_MULTICAST)) {
			mutex_exit(&ill->ill_lock);
			continue;
		}
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != ipif->ipif_zoneid &&
			    zoneid != ALL_ZONES &&
			    ipif->ipif_zoneid != ALL_ZONES) {
				continue;
			}
			if (!(ipif->ipif_flags & IPIF_UP) ||
			    !IPIF_CAN_LOOKUP(ipif)) {
				continue;
			}

			/*
			 * Found one candidate.  If it is deprecated,
			 * remember it in dep_ipif.  If it is not deprecated,
			 * remember it in saved_ipif.
			 */
			if (ipif->ipif_flags & IPIF_DEPRECATED) {
				if (dep_ipif == NULL) {
					dep_ipif = ipif;
				} else if (ipif_comp_multi(dep_ipif, ipif,
				    isv6)) {
					/*
					 * If the previous dep_ipif does not
					 * belong to the same ill, we've done
					 * a ipif_refhold() on it.  So we need
					 * to release it.
					 */
					if (dep_ipif->ipif_ill != ill)
						ipif_refrele(dep_ipif);
					dep_ipif = ipif;
				}
				continue;
			}
			if (saved_ipif == NULL) {
				saved_ipif = ipif;
			} else {
				if (ipif_comp_multi(saved_ipif, ipif, isv6)) {
					if (saved_ipif->ipif_ill != ill)
						ipif_refrele(saved_ipif);
					saved_ipif = ipif;
				}
			}
		}
		/*
		 * Before going to the next ill, do a ipif_refhold() on the
		 * saved ones.
		 */
		if (saved_ipif != NULL && saved_ipif->ipif_ill == ill)
			ipif_refhold_locked(saved_ipif);
		if (dep_ipif != NULL && dep_ipif->ipif_ill == ill)
			ipif_refhold_locked(dep_ipif);
		mutex_exit(&ill->ill_lock);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	/*
	 * If we have only the saved_ipif, return it.  But if we have both
	 * saved_ipif and dep_ipif, check to see which one is better.
	 */
	if (saved_ipif != NULL) {
		if (dep_ipif != NULL) {
			if (ipif_comp_multi(saved_ipif, dep_ipif, isv6)) {
				ipif_refrele(saved_ipif);
				return (dep_ipif);
			} else {
				ipif_refrele(dep_ipif);
				return (saved_ipif);
			}
		}
		return (saved_ipif);
	} else {
		return (dep_ipif);
	}
}

/*
 * This function is called when an application does not specify an interface
 * to be used for multicast traffic (joining a group/sending data).  It
 * calls ire_lookup_multi() to look for an interface route for the
 * specified multicast group.  Doing this allows the administrator to add
 * prefix routes for multicast to indicate which interface to be used for
 * multicast traffic in the above scenario.  The route could be for all
 * multicast (224.0/4), for a single multicast group (a /32 route) or
 * anything in between.  If there is no such multicast route, we just find
 * any multicast capable interface and return it.  The returned ipif
 * is refhold'ed.
 */
ipif_t *
ipif_lookup_group(ipaddr_t group, zoneid_t zoneid, ip_stack_t *ipst)
{
	ire_t			*ire;
	ipif_t			*ipif;

	ire = ire_lookup_multi(group, zoneid, ipst);
	if (ire != NULL) {
		ipif = ire->ire_ipif;
		ipif_refhold(ipif);
		ire_refrele(ire);
		return (ipif);
	}

	return (ipif_lookup_multicast(ipst, zoneid, B_FALSE));
}

/*
 * Look for an ipif with the specified interface address and destination.
 * The destination address is used only for matching point-to-point interfaces.
 */
ipif_t *
ipif_lookup_interface(ipaddr_t if_addr, ipaddr_t dst, queue_t *q, mblk_t *mp,
    ipsq_func_t func, int *error, ip_stack_t *ipst)
{
	ipif_t	*ipif;
	ill_t	*ill;
	ill_walk_context_t ctx;
	ipsq_t	*ipsq;

	if (error != NULL)
		*error = 0;

	/*
	 * First match all the point-to-point interfaces
	 * before looking at non-point-to-point interfaces.
	 * This is done to avoid returning non-point-to-point
	 * ipif instead of unnumbered point-to-point ipif.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		GRAB_CONN_LOCK(q);
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			/* Allow the ipif to be down */
			if ((ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    (ipif->ipif_lcl_addr == if_addr) &&
			    (ipif->ipif_pp_dst_addr == dst)) {
				/*
				 * The block comment at the start of ipif_down
				 * explains the use of the macros used below
				 */
				if (IPIF_CAN_LOOKUP(ipif)) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					RELEASE_CONN_LOCK(q);
					rw_exit(&ipst->ips_ill_g_lock);
					return (ipif);
				} else if (IPIF_CAN_WAIT(ipif, q)) {
					ipsq = ill->ill_phyint->phyint_ipsq;
					mutex_enter(&ipsq->ipsq_lock);
					mutex_enter(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					ipsq_enq(ipsq, q, mp, func, NEW_OP,
					    ill);
					mutex_exit(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ipsq->ipsq_lock);
					RELEASE_CONN_LOCK(q);
					if (error != NULL)
						*error = EINPROGRESS;
					return (NULL);
				}
			}
		}
		mutex_exit(&ill->ill_lock);
		RELEASE_CONN_LOCK(q);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	/* lookup the ipif based on interface address */
	ipif = ipif_lookup_addr(if_addr, NULL, ALL_ZONES, q, mp, func, error,
	    ipst);
	ASSERT(ipif == NULL || !ipif->ipif_isv6);
	return (ipif);
}

/*
 * Common function for ipif_lookup_addr() and ipif_lookup_addr_exact().
 */
static ipif_t *
ipif_lookup_addr_common(ipaddr_t addr, ill_t *match_ill, boolean_t match_illgrp,
    zoneid_t zoneid, queue_t *q, mblk_t *mp, ipsq_func_t func, int *error,
    ip_stack_t *ipst)
{
	ipif_t  *ipif;
	ill_t   *ill;
	boolean_t ptp = B_FALSE;
	ipsq_t	*ipsq;
	ill_walk_context_t	ctx;

	if (error != NULL)
		*error = 0;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	/*
	 * Repeat twice, first based on local addresses and
	 * next time for pointopoint.
	 */
repeat:
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (match_ill != NULL && ill != match_ill &&
		    (!match_illgrp || !IS_IN_SAME_ILLGRP(ill, match_ill))) {
			continue;
		}
		GRAB_CONN_LOCK(q);
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != ALL_ZONES &&
			    zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			/* Allow the ipif to be down */
			if ((!ptp && (ipif->ipif_lcl_addr == addr) &&
			    ((ipif->ipif_flags & IPIF_UNNUMBERED) == 0)) ||
			    (ptp && (ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    (ipif->ipif_pp_dst_addr == addr))) {
				/*
				 * The block comment at the start of ipif_down
				 * explains the use of the macros used below
				 */
				if (IPIF_CAN_LOOKUP(ipif)) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					RELEASE_CONN_LOCK(q);
					rw_exit(&ipst->ips_ill_g_lock);
					return (ipif);
				} else if (IPIF_CAN_WAIT(ipif, q)) {
					ipsq = ill->ill_phyint->phyint_ipsq;
					mutex_enter(&ipsq->ipsq_lock);
					mutex_enter(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					ipsq_enq(ipsq, q, mp, func, NEW_OP,
					    ill);
					mutex_exit(&ipsq->ipsq_xop->ipx_lock);
					mutex_exit(&ipsq->ipsq_lock);
					RELEASE_CONN_LOCK(q);
					if (error != NULL)
						*error = EINPROGRESS;
					return (NULL);
				}
			}
		}
		mutex_exit(&ill->ill_lock);
		RELEASE_CONN_LOCK(q);
	}

	/* If we already did the ptp case, then we are done */
	if (ptp) {
		rw_exit(&ipst->ips_ill_g_lock);
		if (error != NULL)
			*error = ENXIO;
		return (NULL);
	}
	ptp = B_TRUE;
	goto repeat;
}

/*
 * Check if the address exists in the system.
 * We don't hold the conn_lock as we will not perform defered ipsqueue
 * operation.
 */
boolean_t
ip_addr_exists(ipaddr_t addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	ipif_t  *ipif;
	ill_t   *ill;
	ill_walk_context_t	ctx;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != ALL_ZONES &&
			    zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			/* Allow the ipif to be down */
			/*
			 * XXX Different from ipif_lookup_addr(), we don't do
			 * twice lookups. As from bind()'s point of view, we
			 * may return once we find a match.
			 */
			if (((ipif->ipif_lcl_addr == addr) &&
			    ((ipif->ipif_flags & IPIF_UNNUMBERED) == 0)) ||
			    ((ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    (ipif->ipif_pp_dst_addr == addr))) {
				/*
				 * Allow bind() to be successful even if the
				 * ipif is with IPIF_CHANGING bit set.
				 */
				mutex_exit(&ill->ill_lock);
				rw_exit(&ipst->ips_ill_g_lock);
				return (B_TRUE);
			}
		}
		mutex_exit(&ill->ill_lock);
	}

	rw_exit(&ipst->ips_ill_g_lock);
	return (B_FALSE);
}

/*
 * Lookup an ipif with the specified address.  For point-to-point links we
 * look for matches on either the destination address or the local address,
 * but we skip the local address check if IPIF_UNNUMBERED is set.  If the
 * `match_ill' argument is non-NULL, the lookup is restricted to that ill
 * (or illgrp if `match_ill' is in an IPMP group).
 */
ipif_t *
ipif_lookup_addr(ipaddr_t addr, ill_t *match_ill, zoneid_t zoneid, queue_t *q,
    mblk_t *mp, ipsq_func_t func, int *error, ip_stack_t *ipst)
{
	return (ipif_lookup_addr_common(addr, match_ill, B_TRUE, zoneid, q, mp,
	    func, error, ipst));
}

/*
 * Special abbreviated version of ipif_lookup_addr() that doesn't match
 * `match_ill' across the IPMP group.  This function is only needed in some
 * corner-cases; almost everything should use ipif_lookup_addr().
 */
static ipif_t *
ipif_lookup_addr_exact(ipaddr_t addr, ill_t *match_ill, ip_stack_t *ipst)
{
	ASSERT(match_ill != NULL);
	return (ipif_lookup_addr_common(addr, match_ill, B_FALSE, ALL_ZONES,
	    NULL, NULL, NULL, NULL, ipst));
}

/*
 * Look for an ipif with the specified address. For point-point links
 * we look for matches on either the destination address and the local
 * address, but we ignore the check on the local address if IPIF_UNNUMBERED
 * is set.
 * If the `match_ill' argument is non-NULL, the lookup is restricted to that
 * ill (or illgrp if `match_ill' is in an IPMP group).
 * Return the zoneid for the ipif which matches. ALL_ZONES if no match.
 */
zoneid_t
ipif_lookup_addr_zoneid(ipaddr_t addr, ill_t *match_ill, ip_stack_t *ipst)
{
	zoneid_t zoneid;
	ipif_t  *ipif;
	ill_t   *ill;
	boolean_t ptp = B_FALSE;
	ill_walk_context_t	ctx;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	/*
	 * Repeat twice, first based on local addresses and
	 * next time for pointopoint.
	 */
repeat:
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (match_ill != NULL && ill != match_ill &&
		    !IS_IN_SAME_ILLGRP(ill, match_ill)) {
			continue;
		}
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			/* Allow the ipif to be down */
			if ((!ptp && (ipif->ipif_lcl_addr == addr) &&
			    ((ipif->ipif_flags & IPIF_UNNUMBERED) == 0)) ||
			    (ptp && (ipif->ipif_flags & IPIF_POINTOPOINT) &&
			    (ipif->ipif_pp_dst_addr == addr)) &&
			    !(ipif->ipif_state_flags & IPIF_CONDEMNED)) {
				zoneid = ipif->ipif_zoneid;
				mutex_exit(&ill->ill_lock);
				rw_exit(&ipst->ips_ill_g_lock);
				/*
				 * If ipif_zoneid was ALL_ZONES then we have
				 * a trusted extensions shared IP address.
				 * In that case GLOBAL_ZONEID works to send.
				 */
				if (zoneid == ALL_ZONES)
					zoneid = GLOBAL_ZONEID;
				return (zoneid);
			}
		}
		mutex_exit(&ill->ill_lock);
	}

	/* If we already did the ptp case, then we are done */
	if (ptp) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (ALL_ZONES);
	}
	ptp = B_TRUE;
	goto repeat;
}

/*
 * Look for an ipif that matches the specified remote address i.e. the
 * ipif that would receive the specified packet.
 * First look for directly connected interfaces and then do a recursive
 * IRE lookup and pick the first ipif corresponding to the source address in the
 * ire.
 * Returns: held ipif
 */
ipif_t *
ipif_lookup_remote(ill_t *ill, ipaddr_t addr, zoneid_t zoneid)
{
	ipif_t	*ipif;
	ire_t	*ire;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(!ill->ill_isv6);

	/*
	 * Someone could be changing this ipif currently or change it
	 * after we return this. Thus  a few packets could use the old
	 * old values. However structure updates/creates (ire, ilg, ilm etc)
	 * will atomically be updated or cleaned up with the new value
	 * Thus we don't need a lock to check the flags or other attrs below.
	 */
	mutex_enter(&ill->ill_lock);
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (!IPIF_CAN_LOOKUP(ipif))
			continue;
		if (zoneid != ALL_ZONES && zoneid != ipif->ipif_zoneid &&
		    ipif->ipif_zoneid != ALL_ZONES)
			continue;
		/* Allow the ipif to be down */
		if (ipif->ipif_flags & IPIF_POINTOPOINT) {
			if ((ipif->ipif_pp_dst_addr == addr) ||
			    (!(ipif->ipif_flags & IPIF_UNNUMBERED) &&
			    ipif->ipif_lcl_addr == addr)) {
				ipif_refhold_locked(ipif);
				mutex_exit(&ill->ill_lock);
				return (ipif);
			}
		} else if (ipif->ipif_subnet == (addr & ipif->ipif_net_mask)) {
			ipif_refhold_locked(ipif);
			mutex_exit(&ill->ill_lock);
			return (ipif);
		}
	}
	mutex_exit(&ill->ill_lock);
	ire = ire_route_lookup(addr, 0, 0, 0, NULL, NULL, zoneid,
	    NULL, MATCH_IRE_RECURSIVE, ipst);
	if (ire != NULL) {
		/*
		 * The callers of this function wants to know the
		 * interface on which they have to send the replies
		 * back. For IREs that have ire_stq and ire_ipif
		 * derived from different ills, we really don't care
		 * what we return here.
		 */
		ipif = ire->ire_ipif;
		if (ipif != NULL) {
			ipif_refhold(ipif);
			ire_refrele(ire);
			return (ipif);
		}
		ire_refrele(ire);
	}
	/* Pick the first interface */
	ipif = ipif_get_next_ipif(NULL, ill);
	return (ipif);
}

/*
 * This func does not prevent refcnt from increasing. But if
 * the caller has taken steps to that effect, then this func
 * can be used to determine whether the ill has become quiescent
 */
static boolean_t
ill_is_quiescent(ill_t *ill)
{
	ipif_t	*ipif;

	ASSERT(MUTEX_HELD(&ill->ill_lock));

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (ipif->ipif_refcnt != 0 || !IPIF_DOWN_OK(ipif)) {
			return (B_FALSE);
		}
	}
	if (!ILL_DOWN_OK(ill) || ill->ill_refcnt != 0) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

boolean_t
ill_is_freeable(ill_t *ill)
{
	ipif_t	*ipif;

	ASSERT(MUTEX_HELD(&ill->ill_lock));

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (ipif->ipif_refcnt != 0 || !IPIF_FREE_OK(ipif)) {
			return (B_FALSE);
		}
	}
	if (!ILL_FREE_OK(ill) || ill->ill_refcnt != 0) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * This func does not prevent refcnt from increasing. But if
 * the caller has taken steps to that effect, then this func
 * can be used to determine whether the ipif has become quiescent
 */
static boolean_t
ipif_is_quiescent(ipif_t *ipif)
{
	ill_t *ill;

	ASSERT(MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	if (ipif->ipif_refcnt != 0 || !IPIF_DOWN_OK(ipif)) {
		return (B_FALSE);
	}

	ill = ipif->ipif_ill;
	if (ill->ill_ipif_up_count != 0 || ill->ill_ipif_dup_count != 0 ||
	    ill->ill_logical_down) {
		return (B_TRUE);
	}

	/* This is the last ipif going down or being deleted on this ill */
	if (!ILL_DOWN_OK(ill) || ill->ill_refcnt != 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * return true if the ipif can be destroyed: the ipif has to be quiescent
 * with zero references from ire/nce/ilm to it.
 */
static boolean_t
ipif_is_freeable(ipif_t *ipif)
{
	ASSERT(MUTEX_HELD(&ipif->ipif_ill->ill_lock));
	ASSERT(ipif->ipif_id != 0);
	return (ipif->ipif_refcnt == 0 && IPIF_FREE_OK(ipif));
}

/*
 * The ipif/ill/ire has been refreled. Do the tail processing.
 * Determine if the ipif or ill in question has become quiescent and if so
 * wakeup close and/or restart any queued pending ioctl that is waiting
 * for the ipif_down (or ill_down)
 */
void
ipif_ill_refrele_tail(ill_t *ill)
{
	mblk_t	*mp;
	conn_t	*connp;
	ipsq_t	*ipsq;
	ipxop_t	*ipx;
	ipif_t	*ipif;
	dl_notify_ind_t *dlindp;

	ASSERT(MUTEX_HELD(&ill->ill_lock));

	if ((ill->ill_state_flags & ILL_CONDEMNED) && ill_is_freeable(ill)) {
		/* ip_modclose() may be waiting */
		cv_broadcast(&ill->ill_cv);
	}

	ipsq = ill->ill_phyint->phyint_ipsq;
	mutex_enter(&ipsq->ipsq_lock);
	ipx = ipsq->ipsq_xop;
	mutex_enter(&ipx->ipx_lock);
	if (ipx->ipx_waitfor == 0)	/* no one's waiting; bail */
		goto unlock;

	ASSERT(ipx->ipx_pending_mp != NULL && ipx->ipx_pending_ipif != NULL);

	ipif = ipx->ipx_pending_ipif;
	if (ipif->ipif_ill != ill) 	/* wait is for another ill; bail */
		goto unlock;

	switch (ipx->ipx_waitfor) {
	case IPIF_DOWN:
		if (!ipif_is_quiescent(ipif))
			goto unlock;
		break;
	case IPIF_FREE:
		if (!ipif_is_freeable(ipif))
			goto unlock;
		break;
	case ILL_DOWN:
		if (!ill_is_quiescent(ill))
			goto unlock;
		break;
	case ILL_FREE:
		/*
		 * ILL_FREE is only for loopback; normal ill teardown waits
		 * synchronously in ip_modclose() without using ipx_waitfor,
		 * handled by the cv_broadcast() at the top of this function.
		 */
		if (!ill_is_freeable(ill))
			goto unlock;
		break;
	default:
		cmn_err(CE_PANIC, "ipsq: %p unknown ipx_waitfor %d\n",
		    (void *)ipsq, ipx->ipx_waitfor);
	}

	ill_refhold_locked(ill);	/* for qwriter_ip() call below */
	mutex_exit(&ipx->ipx_lock);
	mp = ipsq_pending_mp_get(ipsq, &connp);
	mutex_exit(&ipsq->ipsq_lock);
	mutex_exit(&ill->ill_lock);

	ASSERT(mp != NULL);
	/*
	 * NOTE: all of the qwriter_ip() calls below use CUR_OP since
	 * we can only get here when the current operation decides it
	 * it needs to quiesce via ipsq_pending_mp_add().
	 */
	switch (mp->b_datap->db_type) {
	case M_PCPROTO:
	case M_PROTO:
		/*
		 * For now, only DL_NOTIFY_IND messages can use this facility.
		 */
		dlindp = (dl_notify_ind_t *)mp->b_rptr;
		ASSERT(dlindp->dl_primitive == DL_NOTIFY_IND);

		switch (dlindp->dl_notification) {
		case DL_NOTE_PHYS_ADDR:
			qwriter_ip(ill, ill->ill_rq, mp,
			    ill_set_phys_addr_tail, CUR_OP, B_TRUE);
			return;
		default:
			ASSERT(0);
			ill_refrele(ill);
		}
		break;

	case M_ERROR:
	case M_HANGUP:
		qwriter_ip(ill, ill->ill_rq, mp, ipif_all_down_tail, CUR_OP,
		    B_TRUE);
		return;

	case M_IOCTL:
	case M_IOCDATA:
		qwriter_ip(ill, (connp != NULL ? CONNP_TO_WQ(connp) :
		    ill->ill_wq), mp, ip_reprocess_ioctl, CUR_OP, B_TRUE);
		return;

	default:
		cmn_err(CE_PANIC, "ipif_ill_refrele_tail mp %p "
		    "db_type %d\n", (void *)mp, mp->b_datap->db_type);
	}
	return;
unlock:
	mutex_exit(&ipsq->ipsq_lock);
	mutex_exit(&ipx->ipx_lock);
	mutex_exit(&ill->ill_lock);
}

#ifdef DEBUG
/* Reuse trace buffer from beginning (if reached the end) and record trace */
static void
th_trace_rrecord(th_trace_t *th_trace)
{
	tr_buf_t *tr_buf;
	uint_t lastref;

	lastref = th_trace->th_trace_lastref;
	lastref++;
	if (lastref == TR_BUF_MAX)
		lastref = 0;
	th_trace->th_trace_lastref = lastref;
	tr_buf = &th_trace->th_trbuf[lastref];
	tr_buf->tr_time = lbolt;
	tr_buf->tr_depth = getpcstack(tr_buf->tr_stack, TR_STACK_DEPTH);
}

static void
th_trace_free(void *value)
{
	th_trace_t *th_trace = value;

	ASSERT(th_trace->th_refcnt == 0);
	kmem_free(th_trace, sizeof (*th_trace));
}

/*
 * Find or create the per-thread hash table used to track object references.
 * The ipst argument is NULL if we shouldn't allocate.
 *
 * Accesses per-thread data, so there's no need to lock here.
 */
static mod_hash_t *
th_trace_gethash(ip_stack_t *ipst)
{
	th_hash_t *thh;

	if ((thh = tsd_get(ip_thread_data)) == NULL && ipst != NULL) {
		mod_hash_t *mh;
		char name[256];
		size_t objsize, rshift;
		int retv;

		if ((thh = kmem_alloc(sizeof (*thh), KM_NOSLEEP)) == NULL)
			return (NULL);
		(void) snprintf(name, sizeof (name), "th_trace_%p",
		    (void *)curthread);

		/*
		 * We use mod_hash_create_extended here rather than the more
		 * obvious mod_hash_create_ptrhash because the latter has a
		 * hard-coded KM_SLEEP, and we'd prefer to fail rather than
		 * block.
		 */
		objsize = MAX(MAX(sizeof (ill_t), sizeof (ipif_t)),
		    MAX(sizeof (ire_t), sizeof (nce_t)));
		rshift = highbit(objsize);
		mh = mod_hash_create_extended(name, 64, mod_hash_null_keydtor,
		    th_trace_free, mod_hash_byptr, (void *)rshift,
		    mod_hash_ptrkey_cmp, KM_NOSLEEP);
		if (mh == NULL) {
			kmem_free(thh, sizeof (*thh));
			return (NULL);
		}
		thh->thh_hash = mh;
		thh->thh_ipst = ipst;
		/*
		 * We trace ills, ipifs, ires, and nces.  All of these are
		 * per-IP-stack, so the lock on the thread list is as well.
		 */
		rw_enter(&ip_thread_rwlock, RW_WRITER);
		list_insert_tail(&ip_thread_list, thh);
		rw_exit(&ip_thread_rwlock);
		retv = tsd_set(ip_thread_data, thh);
		ASSERT(retv == 0);
	}
	return (thh != NULL ? thh->thh_hash : NULL);
}

boolean_t
th_trace_ref(const void *obj, ip_stack_t *ipst)
{
	th_trace_t *th_trace;
	mod_hash_t *mh;
	mod_hash_val_t val;

	if ((mh = th_trace_gethash(ipst)) == NULL)
		return (B_FALSE);

	/*
	 * Attempt to locate the trace buffer for this obj and thread.
	 * If it does not exist, then allocate a new trace buffer and
	 * insert into the hash.
	 */
	if (mod_hash_find(mh, (mod_hash_key_t)obj, &val) == MH_ERR_NOTFOUND) {
		th_trace = kmem_zalloc(sizeof (th_trace_t), KM_NOSLEEP);
		if (th_trace == NULL)
			return (B_FALSE);

		th_trace->th_id = curthread;
		if (mod_hash_insert(mh, (mod_hash_key_t)obj,
		    (mod_hash_val_t)th_trace) != 0) {
			kmem_free(th_trace, sizeof (th_trace_t));
			return (B_FALSE);
		}
	} else {
		th_trace = (th_trace_t *)val;
	}

	ASSERT(th_trace->th_refcnt >= 0 &&
	    th_trace->th_refcnt < TR_BUF_MAX - 1);

	th_trace->th_refcnt++;
	th_trace_rrecord(th_trace);
	return (B_TRUE);
}

/*
 * For the purpose of tracing a reference release, we assume that global
 * tracing is always on and that the same thread initiated the reference hold
 * is releasing.
 */
void
th_trace_unref(const void *obj)
{
	int retv;
	mod_hash_t *mh;
	th_trace_t *th_trace;
	mod_hash_val_t val;

	mh = th_trace_gethash(NULL);
	retv = mod_hash_find(mh, (mod_hash_key_t)obj, &val);
	ASSERT(retv == 0);
	th_trace = (th_trace_t *)val;

	ASSERT(th_trace->th_refcnt > 0);
	th_trace->th_refcnt--;
	th_trace_rrecord(th_trace);
}

/*
 * If tracing has been disabled, then we assume that the reference counts are
 * now useless, and we clear them out before destroying the entries.
 */
void
th_trace_cleanup(const void *obj, boolean_t trace_disable)
{
	th_hash_t	*thh;
	mod_hash_t	*mh;
	mod_hash_val_t	val;
	th_trace_t	*th_trace;
	int		retv;

	rw_enter(&ip_thread_rwlock, RW_READER);
	for (thh = list_head(&ip_thread_list); thh != NULL;
	    thh = list_next(&ip_thread_list, thh)) {
		if (mod_hash_find(mh = thh->thh_hash, (mod_hash_key_t)obj,
		    &val) == 0) {
			th_trace = (th_trace_t *)val;
			if (trace_disable)
				th_trace->th_refcnt = 0;
			retv = mod_hash_destroy(mh, (mod_hash_key_t)obj);
			ASSERT(retv == 0);
		}
	}
	rw_exit(&ip_thread_rwlock);
}

void
ipif_trace_ref(ipif_t *ipif)
{
	ASSERT(MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	if (ipif->ipif_trace_disable)
		return;

	if (!th_trace_ref(ipif, ipif->ipif_ill->ill_ipst)) {
		ipif->ipif_trace_disable = B_TRUE;
		ipif_trace_cleanup(ipif);
	}
}

void
ipif_untrace_ref(ipif_t *ipif)
{
	ASSERT(MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	if (!ipif->ipif_trace_disable)
		th_trace_unref(ipif);
}

void
ill_trace_ref(ill_t *ill)
{
	ASSERT(MUTEX_HELD(&ill->ill_lock));

	if (ill->ill_trace_disable)
		return;

	if (!th_trace_ref(ill, ill->ill_ipst)) {
		ill->ill_trace_disable = B_TRUE;
		ill_trace_cleanup(ill);
	}
}

void
ill_untrace_ref(ill_t *ill)
{
	ASSERT(MUTEX_HELD(&ill->ill_lock));

	if (!ill->ill_trace_disable)
		th_trace_unref(ill);
}

/*
 * Called when ipif is unplumbed or when memory alloc fails.  Note that on
 * failure, ipif_trace_disable is set.
 */
static void
ipif_trace_cleanup(const ipif_t *ipif)
{
	th_trace_cleanup(ipif, ipif->ipif_trace_disable);
}

/*
 * Called when ill is unplumbed or when memory alloc fails.  Note that on
 * failure, ill_trace_disable is set.
 */
static void
ill_trace_cleanup(const ill_t *ill)
{
	th_trace_cleanup(ill, ill->ill_trace_disable);
}
#endif /* DEBUG */

void
ipif_refhold_locked(ipif_t *ipif)
{
	ASSERT(MUTEX_HELD(&ipif->ipif_ill->ill_lock));
	ipif->ipif_refcnt++;
	IPIF_TRACE_REF(ipif);
}

void
ipif_refhold(ipif_t *ipif)
{
	ill_t	*ill;

	ill = ipif->ipif_ill;
	mutex_enter(&ill->ill_lock);
	ipif->ipif_refcnt++;
	IPIF_TRACE_REF(ipif);
	mutex_exit(&ill->ill_lock);
}

/*
 * Must not be called while holding any locks. Otherwise if this is
 * the last reference to be released there is a chance of recursive mutex
 * panic due to ipif_refrele -> ipif_ill_refrele_tail -> qwriter_ip trying
 * to restart an ioctl.
 */
void
ipif_refrele(ipif_t *ipif)
{
	ill_t	*ill;

	ill = ipif->ipif_ill;

	mutex_enter(&ill->ill_lock);
	ASSERT(ipif->ipif_refcnt != 0);
	ipif->ipif_refcnt--;
	IPIF_UNTRACE_REF(ipif);
	if (ipif->ipif_refcnt != 0) {
		mutex_exit(&ill->ill_lock);
		return;
	}

	/* Drops the ill_lock */
	ipif_ill_refrele_tail(ill);
}

ipif_t *
ipif_get_next_ipif(ipif_t *curr, ill_t *ill)
{
	ipif_t	*ipif;

	mutex_enter(&ill->ill_lock);
	for (ipif = (curr == NULL ? ill->ill_ipif : curr->ipif_next);
	    ipif != NULL; ipif = ipif->ipif_next) {
		if (!IPIF_CAN_LOOKUP(ipif))
			continue;
		ipif_refhold_locked(ipif);
		mutex_exit(&ill->ill_lock);
		return (ipif);
	}
	mutex_exit(&ill->ill_lock);
	return (NULL);
}

/*
 * TODO: make this table extendible at run time
 * Return a pointer to the mac type info for 'mac_type'
 */
static ip_m_t *
ip_m_lookup(t_uscalar_t mac_type)
{
	ip_m_t	*ipm;

	for (ipm = ip_m_tbl; ipm < A_END(ip_m_tbl); ipm++)
		if (ipm->ip_m_mac_type == mac_type)
			return (ipm);
	return (NULL);
}

/*
 * ip_rt_add is called to add an IPv4 route to the forwarding table.
 * ipif_arg is passed in to associate it with the correct interface.
 * We may need to restart this operation if the ipif cannot be looked up
 * due to an exclusive operation that is currently in progress. The restart
 * entry point is specified by 'func'
 */
int
ip_rt_add(ipaddr_t dst_addr, ipaddr_t mask, ipaddr_t gw_addr,
    ipaddr_t src_addr, int flags, ipif_t *ipif_arg, ire_t **ire_arg,
    boolean_t ioctl_msg, queue_t *q, mblk_t *mp, ipsq_func_t func,
    struct rtsa_s *sp, ip_stack_t *ipst)
{
	ire_t	*ire;
	ire_t	*gw_ire = NULL;
	ipif_t	*ipif = NULL;
	boolean_t ipif_refheld = B_FALSE;
	uint_t	type;
	int	match_flags = MATCH_IRE_TYPE;
	int	error;
	tsol_gc_t *gc = NULL;
	tsol_gcgrp_t *gcgrp = NULL;
	boolean_t gcgrp_xtraref = B_FALSE;

	ip1dbg(("ip_rt_add:"));

	if (ire_arg != NULL)
		*ire_arg = NULL;

	/*
	 * If this is the case of RTF_HOST being set, then we set the netmask
	 * to all ones (regardless if one was supplied).
	 */
	if (flags & RTF_HOST)
		mask = IP_HOST_MASK;

	/*
	 * Prevent routes with a zero gateway from being created (since
	 * interfaces can currently be plumbed and brought up no assigned
	 * address).
	 */
	if (gw_addr == 0)
		return (ENETUNREACH);
	/*
	 * Get the ipif, if any, corresponding to the gw_addr
	 */
	ipif = ipif_lookup_interface(gw_addr, dst_addr, q, mp, func, &error,
	    ipst);
	if (ipif != NULL) {
		if (IS_VNI(ipif->ipif_ill)) {
			ipif_refrele(ipif);
			return (EINVAL);
		}
		ipif_refheld = B_TRUE;
	} else if (error == EINPROGRESS) {
		ip1dbg(("ip_rt_add: null and EINPROGRESS"));
		return (EINPROGRESS);
	} else {
		error = 0;
	}

	if (ipif != NULL) {
		ip1dbg(("ip_rt_add: ipif_lookup_interface done ipif nonnull"));
		ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));
	} else {
		ip1dbg(("ip_rt_add: ipif_lookup_interface done ipif is null"));
	}

	/*
	 * GateD will attempt to create routes with a loopback interface
	 * address as the gateway and with RTF_GATEWAY set.  We allow
	 * these routes to be added, but create them as interface routes
	 * since the gateway is an interface address.
	 */
	if ((ipif != NULL) && (ipif->ipif_ire_type == IRE_LOOPBACK)) {
		flags &= ~RTF_GATEWAY;
		if (gw_addr == INADDR_LOOPBACK && dst_addr == INADDR_LOOPBACK &&
		    mask == IP_HOST_MASK) {
			ire = ire_ctable_lookup(dst_addr, 0, IRE_LOOPBACK, ipif,
			    ALL_ZONES, NULL, match_flags, ipst);
			if (ire != NULL) {
				ire_refrele(ire);
				if (ipif_refheld)
					ipif_refrele(ipif);
				return (EEXIST);
			}
			ip1dbg(("ipif_up_done: 0x%p creating IRE 0x%x"
			    "for 0x%x\n", (void *)ipif,
			    ipif->ipif_ire_type,
			    ntohl(ipif->ipif_lcl_addr)));
			ire = ire_create(
			    (uchar_t *)&dst_addr,	/* dest address */
			    (uchar_t *)&mask,		/* mask */
			    (uchar_t *)&ipif->ipif_src_addr,
			    NULL,			/* no gateway */
			    &ipif->ipif_mtu,
			    NULL,
			    ipif->ipif_rq,		/* recv-from queue */
			    NULL,			/* no send-to queue */
			    ipif->ipif_ire_type,	/* LOOPBACK */
			    ipif,
			    0,
			    0,
			    0,
			    (ipif->ipif_flags & IPIF_PRIVATE) ?
			    RTF_PRIVATE : 0,
			    &ire_uinfo_null,
			    NULL,
			    NULL,
			    ipst);

			if (ire == NULL) {
				if (ipif_refheld)
					ipif_refrele(ipif);
				return (ENOMEM);
			}
			error = ire_add(&ire, q, mp, func, B_FALSE);
			if (error == 0)
				goto save_ire;
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (error);

		}
	}

	/*
	 * Traditionally, interface routes are ones where RTF_GATEWAY isn't set
	 * and the gateway address provided is one of the system's interface
	 * addresses.  By using the routing socket interface and supplying an
	 * RTA_IFP sockaddr with an interface index, an alternate method of
	 * specifying an interface route to be created is available which uses
	 * the interface index that specifies the outgoing interface rather than
	 * the address of an outgoing interface (which may not be able to
	 * uniquely identify an interface).  When coupled with the RTF_GATEWAY
	 * flag, routes can be specified which not only specify the next-hop to
	 * be used when routing to a certain prefix, but also which outgoing
	 * interface should be used.
	 *
	 * Previously, interfaces would have unique addresses assigned to them
	 * and so the address assigned to a particular interface could be used
	 * to identify a particular interface.  One exception to this was the
	 * case of an unnumbered interface (where IPIF_UNNUMBERED was set).
	 *
	 * With the advent of IPv6 and its link-local addresses, this
	 * restriction was relaxed and interfaces could share addresses between
	 * themselves.  In fact, typically all of the link-local interfaces on
	 * an IPv6 node or router will have the same link-local address.  In
	 * order to differentiate between these interfaces, the use of an
	 * interface index is necessary and this index can be carried inside a
	 * RTA_IFP sockaddr (which is actually a sockaddr_dl).  One restriction
	 * of using the interface index, however, is that all of the ipif's that
	 * are part of an ill have the same index and so the RTA_IFP sockaddr
	 * cannot be used to differentiate between ipif's (or logical
	 * interfaces) that belong to the same ill (physical interface).
	 *
	 * For example, in the following case involving IPv4 interfaces and
	 * logical interfaces
	 *
	 *	192.0.2.32	255.255.255.224	192.0.2.33	U	if0
	 *	192.0.2.32	255.255.255.224	192.0.2.34	U	if0:1
	 *	192.0.2.32	255.255.255.224	192.0.2.35	U	if0:2
	 *
	 * the ipif's corresponding to each of these interface routes can be
	 * uniquely identified by the "gateway" (actually interface address).
	 *
	 * In this case involving multiple IPv6 default routes to a particular
	 * link-local gateway, the use of RTA_IFP is necessary to specify which
	 * default route is of interest:
	 *
	 *	default		fe80::123:4567:89ab:cdef	U	if0
	 *	default		fe80::123:4567:89ab:cdef	U	if1
	 */

	/* RTF_GATEWAY not set */
	if (!(flags & RTF_GATEWAY)) {
		queue_t	*stq;

		if (sp != NULL) {
			ip2dbg(("ip_rt_add: gateway security attributes "
			    "cannot be set with interface route\n"));
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (EINVAL);
		}

		/*
		 * As the interface index specified with the RTA_IFP sockaddr is
		 * the same for all ipif's off of an ill, the matching logic
		 * below uses MATCH_IRE_ILL if such an index was specified.
		 * This means that routes sharing the same prefix when added
		 * using a RTA_IFP sockaddr must have distinct interface
		 * indices (namely, they must be on distinct ill's).
		 *
		 * On the other hand, since the gateway address will usually be
		 * different for each ipif on the system, the matching logic
		 * uses MATCH_IRE_IPIF in the case of a traditional interface
		 * route.  This means that interface routes for the same prefix
		 * can be created if they belong to distinct ipif's and if a
		 * RTA_IFP sockaddr is not present.
		 */
		if (ipif_arg != NULL) {
			if (ipif_refheld)  {
				ipif_refrele(ipif);
				ipif_refheld = B_FALSE;
			}
			ipif = ipif_arg;
			match_flags |= MATCH_IRE_ILL;
		} else {
			/*
			 * Check the ipif corresponding to the gw_addr
			 */
			if (ipif == NULL)
				return (ENETUNREACH);
			match_flags |= MATCH_IRE_IPIF;
		}
		ASSERT(ipif != NULL);

		/*
		 * We check for an existing entry at this point.
		 *
		 * Since a netmask isn't passed in via the ioctl interface
		 * (SIOCADDRT), we don't check for a matching netmask in that
		 * case.
		 */
		if (!ioctl_msg)
			match_flags |= MATCH_IRE_MASK;
		ire = ire_ftable_lookup(dst_addr, mask, 0, IRE_INTERFACE, ipif,
		    NULL, ALL_ZONES, 0, NULL, match_flags, ipst);
		if (ire != NULL) {
			ire_refrele(ire);
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (EEXIST);
		}

		stq = (ipif->ipif_net_type == IRE_IF_RESOLVER)
		    ? ipif->ipif_rq : ipif->ipif_wq;

		/*
		 * Create a copy of the IRE_LOOPBACK,
		 * IRE_IF_NORESOLVER or IRE_IF_RESOLVER with
		 * the modified address and netmask.
		 */
		ire = ire_create(
		    (uchar_t *)&dst_addr,
		    (uint8_t *)&mask,
		    (uint8_t *)&ipif->ipif_src_addr,
		    NULL,
		    &ipif->ipif_mtu,
		    NULL,
		    NULL,
		    stq,
		    ipif->ipif_net_type,
		    ipif,
		    0,
		    0,
		    0,
		    flags,
		    &ire_uinfo_null,
		    NULL,
		    NULL,
		    ipst);
		if (ire == NULL) {
			if (ipif_refheld)
				ipif_refrele(ipif);
			return (ENOMEM);
		}

		/*
		 * Some software (for example, GateD and Sun Cluster) attempts
		 * to create (what amount to) IRE_PREFIX routes with the
		 * loopback address as the gateway.  This is primarily done to
		 * set up prefixes with the RTF_REJECT flag set (for example,
		 * when generating aggregate routes.)
		 *
		 * If the IRE type (as defined by ipif->ipif_net_type) is
		 * IRE_LOOPBACK, then we map the request into a
		 * IRE_IF_NORESOLVER. We also OR in the RTF_BLACKHOLE flag as
		 * these interface routes, by definition, can only be that.
		 *
		 * Needless to say, the real IRE_LOOPBACK is NOT created by this
		 * routine, but rather using ire_create() directly.
		 *
		 */
		if (ipif->ipif_net_type == IRE_LOOPBACK) {
			ire->ire_type = IRE_IF_NORESOLVER;
			ire->ire_flags |= RTF_BLACKHOLE;
		}

		error = ire_add(&ire, q, mp, func, B_FALSE);
		if (error == 0)
			goto save_ire;

		/*
		 * In the result of failure, ire_add() will have already
		 * deleted the ire in question, so there is no need to
		 * do that here.
		 */
		if (ipif_refheld)
			ipif_refrele(ipif);
		return (error);
	}
	if (ipif_refheld) {
		ipif_refrele(ipif);
		ipif_refheld = B_FALSE;
	}

	/*
	 * Get an interface IRE for the specified gateway.
	 * If we don't have an IRE_IF_NORESOLVER or IRE_IF_RESOLVER for the
	 * gateway, it is currently unreachable and we fail the request
	 * accordingly.
	 */
	ipif = ipif_arg;
	if (ipif_arg != NULL)
		match_flags |= MATCH_IRE_ILL;
again:
	gw_ire = ire_ftable_lookup(gw_addr, 0, 0, IRE_INTERFACE, ipif_arg, NULL,
	    ALL_ZONES, 0, NULL, match_flags, ipst);
	if (gw_ire == NULL) {
		/*
		 * With IPMP, we allow host routes to influence in.mpathd's
		 * target selection.  However, if the test addresses are on
		 * their own network, the above lookup will fail since the
		 * underlying IRE_INTERFACEs are marked hidden.  So allow
		 * hidden test IREs to be found and try again.
		 */
		if (!(match_flags & MATCH_IRE_MARK_TESTHIDDEN))  {
			match_flags |= MATCH_IRE_MARK_TESTHIDDEN;
			goto again;
		}
		return (ENETUNREACH);
	}

	/*
	 * We create one of three types of IREs as a result of this request
	 * based on the netmask.  A netmask of all ones (which is automatically
	 * assumed when RTF_HOST is set) results in an IRE_HOST being created.
	 * An all zeroes netmask implies a default route so an IRE_DEFAULT is
	 * created.  Otherwise, an IRE_PREFIX route is created for the
	 * destination prefix.
	 */
	if (mask == IP_HOST_MASK)
		type = IRE_HOST;
	else if (mask == 0)
		type = IRE_DEFAULT;
	else
		type = IRE_PREFIX;

	/* check for a duplicate entry */
	ire = ire_ftable_lookup(dst_addr, mask, gw_addr, type, ipif_arg,
	    NULL, ALL_ZONES, 0, NULL,
	    match_flags | MATCH_IRE_MASK | MATCH_IRE_GW, ipst);
	if (ire != NULL) {
		ire_refrele(gw_ire);
		ire_refrele(ire);
		return (EEXIST);
	}

	/* Security attribute exists */
	if (sp != NULL) {
		tsol_gcgrp_addr_t ga;

		/* find or create the gateway credentials group */
		ga.ga_af = AF_INET;
		IN6_IPADDR_TO_V4MAPPED(gw_addr, &ga.ga_addr);

		/* we hold reference to it upon success */
		gcgrp = gcgrp_lookup(&ga, B_TRUE);
		if (gcgrp == NULL) {
			ire_refrele(gw_ire);
			return (ENOMEM);
		}

		/*
		 * Create and add the security attribute to the group; a
		 * reference to the group is made upon allocating a new
		 * entry successfully.  If it finds an already-existing
		 * entry for the security attribute in the group, it simply
		 * returns it and no new reference is made to the group.
		 */
		gc = gc_create(sp, gcgrp, &gcgrp_xtraref);
		if (gc == NULL) {
			/* release reference held by gcgrp_lookup */
			GCGRP_REFRELE(gcgrp);
			ire_refrele(gw_ire);
			return (ENOMEM);
		}
	}

	/* Create the IRE. */
	ire = ire_create(
	    (uchar_t *)&dst_addr,		/* dest address */
	    (uchar_t *)&mask,			/* mask */
	    /* src address assigned by the caller? */
	    (uchar_t *)(((src_addr != INADDR_ANY) &&
	    (flags & RTF_SETSRC)) ?  &src_addr : NULL),
	    (uchar_t *)&gw_addr,		/* gateway address */
	    &gw_ire->ire_max_frag,
	    NULL,				/* no src nce */
	    NULL,				/* no recv-from queue */
	    NULL,				/* no send-to queue */
	    (ushort_t)type,			/* IRE type */
	    ipif_arg,
	    0,
	    0,
	    0,
	    flags,
	    &gw_ire->ire_uinfo,			/* Inherit ULP info from gw */
	    gc,					/* security attribute */
	    NULL,
	    ipst);

	/*
	 * The ire holds a reference to the 'gc' and the 'gc' holds a
	 * reference to the 'gcgrp'. We can now release the extra reference
	 * the 'gcgrp' acquired in the gcgrp_lookup, if it was not used.
	 */
	if (gcgrp_xtraref)
		GCGRP_REFRELE(gcgrp);
	if (ire == NULL) {
		if (gc != NULL)
			GC_REFRELE(gc);
		ire_refrele(gw_ire);
		return (ENOMEM);
	}

	/*
	 * POLICY: should we allow an RTF_HOST with address INADDR_ANY?
	 * SUN/OS socket stuff does but do we really want to allow 0.0.0.0?
	 */

	/* Add the new IRE. */
	error = ire_add(&ire, q, mp, func, B_FALSE);
	if (error != 0) {
		/*
		 * In the result of failure, ire_add() will have already
		 * deleted the ire in question, so there is no need to
		 * do that here.
		 */
		ire_refrele(gw_ire);
		return (error);
	}

	if (flags & RTF_MULTIRT) {
		/*
		 * Invoke the CGTP (multirouting) filtering module
		 * to add the dst address in the filtering database.
		 * Replicated inbound packets coming from that address
		 * will be filtered to discard the duplicates.
		 * It is not necessary to call the CGTP filter hook
		 * when the dst address is a broadcast or multicast,
		 * because an IP source address cannot be a broadcast
		 * or a multicast.
		 */
		ire_t *ire_dst = ire_ctable_lookup(ire->ire_addr, 0,
		    IRE_BROADCAST, NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
		if (ire_dst != NULL) {
			ip_cgtp_bcast_add(ire, ire_dst, ipst);
			ire_refrele(ire_dst);
			goto save_ire;
		}
		if (ipst->ips_ip_cgtp_filter_ops != NULL &&
		    !CLASSD(ire->ire_addr)) {
			int res = ipst->ips_ip_cgtp_filter_ops->cfo_add_dest_v4(
			    ipst->ips_netstack->netstack_stackid,
			    ire->ire_addr,
			    ire->ire_gateway_addr,
			    ire->ire_src_addr,
			    gw_ire->ire_src_addr);
			if (res != 0) {
				ire_refrele(gw_ire);
				ire_delete(ire);
				return (res);
			}
		}
	}

	/*
	 * Now that the prefix IRE entry has been created, delete any
	 * existing gateway IRE cache entries as well as any IRE caches
	 * using the gateway, and force them to be created through
	 * ip_newroute.
	 */
	if (gc != NULL) {
		ASSERT(gcgrp != NULL);
		ire_clookup_delete_cache_gw(gw_addr, ALL_ZONES, ipst);
	}

save_ire:
	if (gw_ire != NULL) {
		ire_refrele(gw_ire);
	}
	if (ipif != NULL) {
		/*
		 * Save enough information so that we can recreate the IRE if
		 * the interface goes down and then up.  The metrics associated
		 * with the route will be saved as well when rts_setmetrics() is
		 * called after the IRE has been created.  In the case where
		 * memory cannot be allocated, none of this information will be
		 * saved.
		 */
		ipif_save_ire(ipif, ire);
	}
	if (ioctl_msg)
		ip_rts_rtmsg(RTM_OLDADD, ire, 0, ipst);
	if (ire_arg != NULL) {
		/*
		 * Store the ire that was successfully added into where ire_arg
		 * points to so that callers don't have to look it up
		 * themselves (but they are responsible for ire_refrele()ing
		 * the ire when they are finished with it).
		 */
		*ire_arg = ire;
	} else {
		ire_refrele(ire);		/* Held in ire_add */
	}
	if (ipif_refheld)
		ipif_refrele(ipif);
	return (0);
}

/*
 * ip_rt_delete is called to delete an IPv4 route.
 * ipif_arg is passed in to associate it with the correct interface.
 * We may need to restart this operation if the ipif cannot be looked up
 * due to an exclusive operation that is currently in progress. The restart
 * entry point is specified by 'func'
 */
/* ARGSUSED4 */
int
ip_rt_delete(ipaddr_t dst_addr, ipaddr_t mask, ipaddr_t gw_addr,
    uint_t rtm_addrs, int flags, ipif_t *ipif_arg, boolean_t ioctl_msg,
    queue_t *q, mblk_t *mp, ipsq_func_t func, ip_stack_t *ipst)
{
	ire_t	*ire = NULL;
	ipif_t	*ipif;
	boolean_t ipif_refheld = B_FALSE;
	uint_t	type;
	uint_t	match_flags = MATCH_IRE_TYPE;
	int	err = 0;

	ip1dbg(("ip_rt_delete:"));
	/*
	 * If this is the case of RTF_HOST being set, then we set the netmask
	 * to all ones.  Otherwise, we use the netmask if one was supplied.
	 */
	if (flags & RTF_HOST) {
		mask = IP_HOST_MASK;
		match_flags |= MATCH_IRE_MASK;
	} else if (rtm_addrs & RTA_NETMASK) {
		match_flags |= MATCH_IRE_MASK;
	}

	/*
	 * Note that RTF_GATEWAY is never set on a delete, therefore
	 * we check if the gateway address is one of our interfaces first,
	 * and fall back on RTF_GATEWAY routes.
	 *
	 * This makes it possible to delete an original
	 * IRE_IF_NORESOLVER/IRE_IF_RESOLVER - consistent with SunOS 4.1.
	 *
	 * As the interface index specified with the RTA_IFP sockaddr is the
	 * same for all ipif's off of an ill, the matching logic below uses
	 * MATCH_IRE_ILL if such an index was specified.  This means a route
	 * sharing the same prefix and interface index as the the route
	 * intended to be deleted might be deleted instead if a RTA_IFP sockaddr
	 * is specified in the request.
	 *
	 * On the other hand, since the gateway address will usually be
	 * different for each ipif on the system, the matching logic
	 * uses MATCH_IRE_IPIF in the case of a traditional interface
	 * route.  This means that interface routes for the same prefix can be
	 * uniquely identified if they belong to distinct ipif's and if a
	 * RTA_IFP sockaddr is not present.
	 *
	 * For more detail on specifying routes by gateway address and by
	 * interface index, see the comments in ip_rt_add().
	 */
	ipif = ipif_lookup_interface(gw_addr, dst_addr, q, mp, func, &err,
	    ipst);
	if (ipif != NULL)
		ipif_refheld = B_TRUE;
	else if (err == EINPROGRESS)
		return (err);
	else
		err = 0;
	if (ipif != NULL) {
		if (ipif_arg != NULL) {
			if (ipif_refheld) {
				ipif_refrele(ipif);
				ipif_refheld = B_FALSE;
			}
			ipif = ipif_arg;
			match_flags |= MATCH_IRE_ILL;
		} else {
			match_flags |= MATCH_IRE_IPIF;
		}
		if (ipif->ipif_ire_type == IRE_LOOPBACK) {
			ire = ire_ctable_lookup(dst_addr, 0, IRE_LOOPBACK, ipif,
			    ALL_ZONES, NULL, match_flags, ipst);
		}
		if (ire == NULL) {
			ire = ire_ftable_lookup(dst_addr, mask, 0,
			    IRE_INTERFACE, ipif, NULL, ALL_ZONES, 0, NULL,
			    match_flags, ipst);
		}
	}

	if (ire == NULL) {
		/*
		 * At this point, the gateway address is not one of our own
		 * addresses or a matching interface route was not found.  We
		 * set the IRE type to lookup based on whether
		 * this is a host route, a default route or just a prefix.
		 *
		 * If an ipif_arg was passed in, then the lookup is based on an
		 * interface index so MATCH_IRE_ILL is added to match_flags.
		 * In any case, MATCH_IRE_IPIF is cleared and MATCH_IRE_GW is
		 * set as the route being looked up is not a traditional
		 * interface route.
		 */
		match_flags &= ~MATCH_IRE_IPIF;
		match_flags |= MATCH_IRE_GW;
		if (ipif_arg != NULL)
			match_flags |= MATCH_IRE_ILL;
		if (mask == IP_HOST_MASK)
			type = IRE_HOST;
		else if (mask == 0)
			type = IRE_DEFAULT;
		else
			type = IRE_PREFIX;
		ire = ire_ftable_lookup(dst_addr, mask, gw_addr, type, ipif_arg,
		    NULL, ALL_ZONES, 0, NULL, match_flags, ipst);
	}

	if (ipif_refheld)
		ipif_refrele(ipif);

	/* ipif is not refheld anymore */
	if (ire == NULL)
		return (ESRCH);

	if (ire->ire_flags & RTF_MULTIRT) {
		/*
		 * Invoke the CGTP (multirouting) filtering module
		 * to remove the dst address from the filtering database.
		 * Packets coming from that address will no longer be
		 * filtered to remove duplicates.
		 */
		if (ipst->ips_ip_cgtp_filter_ops != NULL) {
			err = ipst->ips_ip_cgtp_filter_ops->cfo_del_dest_v4(
			    ipst->ips_netstack->netstack_stackid,
			    ire->ire_addr, ire->ire_gateway_addr);
		}
		ip_cgtp_bcast_delete(ire, ipst);
	}

	ipif = ire->ire_ipif;
	if (ipif != NULL)
		ipif_remove_ire(ipif, ire);
	if (ioctl_msg)
		ip_rts_rtmsg(RTM_OLDDEL, ire, 0, ipst);
	ire_delete(ire);
	ire_refrele(ire);
	return (err);
}

/*
 * ip_siocaddrt is called to complete processing of an SIOCADDRT IOCTL.
 */
/* ARGSUSED */
int
ip_siocaddrt(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_if_req)
{
	ipaddr_t dst_addr;
	ipaddr_t gw_addr;
	ipaddr_t mask;
	int error = 0;
	mblk_t *mp1;
	struct rtentry *rt;
	ipif_t *ipif = NULL;
	ip_stack_t	*ipst;

	ASSERT(q->q_next == NULL);
	ipst = CONNQ_TO_IPST(q);

	ip1dbg(("ip_siocaddrt:"));
	/* Existence of mp1 verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	rt = (struct rtentry *)mp1->b_rptr;

	dst_addr = ((sin_t *)&rt->rt_dst)->sin_addr.s_addr;
	gw_addr = ((sin_t *)&rt->rt_gateway)->sin_addr.s_addr;

	/*
	 * If the RTF_HOST flag is on, this is a request to assign a gateway
	 * to a particular host address.  In this case, we set the netmask to
	 * all ones for the particular destination address.  Otherwise,
	 * determine the netmask to be used based on dst_addr and the interfaces
	 * in use.
	 */
	if (rt->rt_flags & RTF_HOST) {
		mask = IP_HOST_MASK;
	} else {
		/*
		 * Note that ip_subnet_mask returns a zero mask in the case of
		 * default (an all-zeroes address).
		 */
		mask = ip_subnet_mask(dst_addr, &ipif, ipst);
	}

	error = ip_rt_add(dst_addr, mask, gw_addr, 0, rt->rt_flags, NULL, NULL,
	    B_TRUE, q, mp, ip_process_ioctl, NULL, ipst);
	if (ipif != NULL)
		ipif_refrele(ipif);
	return (error);
}

/*
 * ip_siocdelrt is called to complete processing of an SIOCDELRT IOCTL.
 */
/* ARGSUSED */
int
ip_siocdelrt(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_if_req)
{
	ipaddr_t dst_addr;
	ipaddr_t gw_addr;
	ipaddr_t mask;
	int error;
	mblk_t *mp1;
	struct rtentry *rt;
	ipif_t *ipif = NULL;
	ip_stack_t	*ipst;

	ASSERT(q->q_next == NULL);
	ipst = CONNQ_TO_IPST(q);

	ip1dbg(("ip_siocdelrt:"));
	/* Existence of mp1 verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	rt = (struct rtentry *)mp1->b_rptr;

	dst_addr = ((sin_t *)&rt->rt_dst)->sin_addr.s_addr;
	gw_addr = ((sin_t *)&rt->rt_gateway)->sin_addr.s_addr;

	/*
	 * If the RTF_HOST flag is on, this is a request to delete a gateway
	 * to a particular host address.  In this case, we set the netmask to
	 * all ones for the particular destination address.  Otherwise,
	 * determine the netmask to be used based on dst_addr and the interfaces
	 * in use.
	 */
	if (rt->rt_flags & RTF_HOST) {
		mask = IP_HOST_MASK;
	} else {
		/*
		 * Note that ip_subnet_mask returns a zero mask in the case of
		 * default (an all-zeroes address).
		 */
		mask = ip_subnet_mask(dst_addr, &ipif, ipst);
	}

	error = ip_rt_delete(dst_addr, mask, gw_addr,
	    RTA_DST | RTA_GATEWAY | RTA_NETMASK, rt->rt_flags, NULL, B_TRUE, q,
	    mp, ip_process_ioctl, ipst);
	if (ipif != NULL)
		ipif_refrele(ipif);
	return (error);
}

/*
 * Enqueue the mp onto the ipsq, chained by b_next.
 * b_prev stores the function to be executed later, and b_queue the queue
 * where this mp originated.
 */
void
ipsq_enq(ipsq_t *ipsq, queue_t *q, mblk_t *mp, ipsq_func_t func, int type,
    ill_t *pending_ill)
{
	conn_t	*connp;
	ipxop_t *ipx = ipsq->ipsq_xop;

	ASSERT(MUTEX_HELD(&ipsq->ipsq_lock));
	ASSERT(MUTEX_HELD(&ipx->ipx_lock));
	ASSERT(func != NULL);

	mp->b_queue = q;
	mp->b_prev = (void *)func;
	mp->b_next = NULL;

	switch (type) {
	case CUR_OP:
		if (ipx->ipx_mptail != NULL) {
			ASSERT(ipx->ipx_mphead != NULL);
			ipx->ipx_mptail->b_next = mp;
		} else {
			ASSERT(ipx->ipx_mphead == NULL);
			ipx->ipx_mphead = mp;
		}
		ipx->ipx_mptail = mp;
		break;

	case NEW_OP:
		if (ipsq->ipsq_xopq_mptail != NULL) {
			ASSERT(ipsq->ipsq_xopq_mphead != NULL);
			ipsq->ipsq_xopq_mptail->b_next = mp;
		} else {
			ASSERT(ipsq->ipsq_xopq_mphead == NULL);
			ipsq->ipsq_xopq_mphead = mp;
		}
		ipsq->ipsq_xopq_mptail = mp;
		ipx->ipx_ipsq_queued = B_TRUE;
		break;

	case SWITCH_OP:
		ASSERT(ipsq->ipsq_swxop != NULL);
		/* only one switch operation is currently allowed */
		ASSERT(ipsq->ipsq_switch_mp == NULL);
		ipsq->ipsq_switch_mp = mp;
		ipx->ipx_ipsq_queued = B_TRUE;
		break;
	default:
		cmn_err(CE_PANIC, "ipsq_enq %d type \n", type);
	}

	if (CONN_Q(q) && pending_ill != NULL) {
		connp = Q_TO_CONN(q);
		ASSERT(MUTEX_HELD(&connp->conn_lock));
		connp->conn_oper_pending_ill = pending_ill;
	}
}

/*
 * Dequeue the next message that requested exclusive access to this IPSQ's
 * xop.  Specifically:
 *
 *  1. If we're still processing the current operation on `ipsq', then
 *     dequeue the next message for the operation (from ipx_mphead), or
 *     return NULL if there are no queued messages for the operation.
 *     These messages are queued via CUR_OP to qwriter_ip() and friends.
 *
 *  2. If the current operation on `ipsq' has completed (ipx_current_ipif is
 *     not set) see if the ipsq has requested an xop switch.  If so, switch
 *     `ipsq' to a different xop.  Xop switches only happen when joining or
 *     leaving IPMP groups and require a careful dance -- see the comments
 *     in-line below for details.  If we're leaving a group xop or if we're
 *     joining a group xop and become writer on it, then we proceed to (3).
 *     Otherwise, we return NULL and exit the xop.
 *
 *  3. For each IPSQ in the xop, return any switch operation stored on
 *     ipsq_switch_mp (set via SWITCH_OP); these must be processed before
 *     any other messages queued on the IPSQ.  Otherwise, dequeue the next
 *     exclusive operation (queued via NEW_OP) stored on ipsq_xopq_mphead.
 *     Note that if the phyint tied to `ipsq' is not using IPMP there will
 *     only be one IPSQ in the xop.  Otherwise, there will be one IPSQ for
 *     each phyint in the group, including the IPMP meta-interface phyint.
 */
static mblk_t *
ipsq_dq(ipsq_t *ipsq)
{
	ill_t	*illv4, *illv6;
	mblk_t	*mp;
	ipsq_t	*xopipsq;
	ipsq_t	*leftipsq = NULL;
	ipxop_t *ipx;
	phyint_t *phyi = ipsq->ipsq_phyint;
	ip_stack_t *ipst = ipsq->ipsq_ipst;
	boolean_t emptied = B_FALSE;

	/*
	 * Grab all the locks we need in the defined order (ill_g_lock ->
	 * ipsq_lock -> ipx_lock); ill_g_lock is needed to use ipsq_next.
	 */
	rw_enter(&ipst->ips_ill_g_lock,
	    ipsq->ipsq_swxop != NULL ? RW_WRITER : RW_READER);
	mutex_enter(&ipsq->ipsq_lock);
	ipx = ipsq->ipsq_xop;
	mutex_enter(&ipx->ipx_lock);

	/*
	 * Dequeue the next message associated with the current exclusive
	 * operation, if any.
	 */
	if ((mp = ipx->ipx_mphead) != NULL) {
		ipx->ipx_mphead = mp->b_next;
		if (ipx->ipx_mphead == NULL)
			ipx->ipx_mptail = NULL;
		mp->b_next = (void *)ipsq;
		goto out;
	}

	if (ipx->ipx_current_ipif != NULL)
		goto empty;

	if (ipsq->ipsq_swxop != NULL) {
		/*
		 * The exclusive operation that is now being completed has
		 * requested a switch to a different xop.  This happens
		 * when an interface joins or leaves an IPMP group.  Joins
		 * happen through SIOCSLIFGROUPNAME (ip_sioctl_groupname()).
		 * Leaves happen via SIOCSLIFGROUPNAME, interface unplumb
		 * (phyint_free()), or interface plumb for an ill type
		 * not in the IPMP group (ip_rput_dlpi_writer()).
		 *
		 * Xop switches are not allowed on the IPMP meta-interface.
		 */
		ASSERT(phyi == NULL || !(phyi->phyint_flags & PHYI_IPMP));
		ASSERT(RW_WRITE_HELD(&ipst->ips_ill_g_lock));
		DTRACE_PROBE1(ipsq__switch, (ipsq_t *), ipsq);

		if (ipsq->ipsq_swxop == &ipsq->ipsq_ownxop) {
			/*
			 * We're switching back to our own xop, so we have two
			 * xop's to drain/exit: our own, and the group xop
			 * that we are leaving.
			 *
			 * First, pull ourselves out of the group ipsq list.
			 * This is safe since we're writer on ill_g_lock.
			 */
			ASSERT(ipsq->ipsq_xop != &ipsq->ipsq_ownxop);

			xopipsq = ipx->ipx_ipsq;
			while (xopipsq->ipsq_next != ipsq)
				xopipsq = xopipsq->ipsq_next;

			xopipsq->ipsq_next = ipsq->ipsq_next;
			ipsq->ipsq_next = ipsq;
			ipsq->ipsq_xop = ipsq->ipsq_swxop;
			ipsq->ipsq_swxop = NULL;

			/*
			 * Second, prepare to exit the group xop.  The actual
			 * ipsq_exit() is done at the end of this function
			 * since we cannot hold any locks across ipsq_exit().
			 * Note that although we drop the group's ipx_lock, no
			 * threads can proceed since we're still ipx_writer.
			 */
			leftipsq = xopipsq;
			mutex_exit(&ipx->ipx_lock);

			/*
			 * Third, set ipx to point to our own xop (which was
			 * inactive and therefore can be entered).
			 */
			ipx = ipsq->ipsq_xop;
			mutex_enter(&ipx->ipx_lock);
			ASSERT(ipx->ipx_writer == NULL);
			ASSERT(ipx->ipx_current_ipif == NULL);
		} else {
			/*
			 * We're switching from our own xop to a group xop.
			 * The requestor of the switch must ensure that the
			 * group xop cannot go away (e.g. by ensuring the
			 * phyint associated with the xop cannot go away).
			 *
			 * If we can become writer on our new xop, then we'll
			 * do the drain.  Otherwise, the current writer of our
			 * new xop will do the drain when it exits.
			 *
			 * First, splice ourselves into the group IPSQ list.
			 * This is safe since we're writer on ill_g_lock.
			 */
			ASSERT(ipsq->ipsq_xop == &ipsq->ipsq_ownxop);

			xopipsq = ipsq->ipsq_swxop->ipx_ipsq;
			while (xopipsq->ipsq_next != ipsq->ipsq_swxop->ipx_ipsq)
				xopipsq = xopipsq->ipsq_next;

			xopipsq->ipsq_next = ipsq;
			ipsq->ipsq_next = ipsq->ipsq_swxop->ipx_ipsq;
			ipsq->ipsq_xop = ipsq->ipsq_swxop;
			ipsq->ipsq_swxop = NULL;

			/*
			 * Second, exit our own xop, since it's now unused.
			 * This is safe since we've got the only reference.
			 */
			ASSERT(ipx->ipx_writer == curthread);
			ipx->ipx_writer = NULL;
			VERIFY(--ipx->ipx_reentry_cnt == 0);
			ipx->ipx_ipsq_queued = B_FALSE;
			mutex_exit(&ipx->ipx_lock);

			/*
			 * Third, set ipx to point to our new xop, and check
			 * if we can become writer on it.  If we cannot, then
			 * the current writer will drain the IPSQ group when
			 * it exits.  Our ipsq_xop is guaranteed to be stable
			 * because we're still holding ipsq_lock.
			 */
			ipx = ipsq->ipsq_xop;
			mutex_enter(&ipx->ipx_lock);
			if (ipx->ipx_writer != NULL ||
			    ipx->ipx_current_ipif != NULL) {
				goto out;
			}
		}

		/*
		 * Fourth, become writer on our new ipx before we continue
		 * with the drain.  Note that we never dropped ipsq_lock
		 * above, so no other thread could've raced with us to
		 * become writer first.  Also, we're holding ipx_lock, so
		 * no other thread can examine the ipx right now.
		 */
		ASSERT(ipx->ipx_current_ipif == NULL);
		ASSERT(ipx->ipx_mphead == NULL && ipx->ipx_mptail == NULL);
		VERIFY(ipx->ipx_reentry_cnt++ == 0);
		ipx->ipx_writer = curthread;
		ipx->ipx_forced = B_FALSE;
#ifdef DEBUG
		ipx->ipx_depth = getpcstack(ipx->ipx_stack, IPX_STACK_DEPTH);
#endif
	}

	xopipsq = ipsq;
	do {
		/*
		 * So that other operations operate on a consistent and
		 * complete phyint, a switch message on an IPSQ must be
		 * handled prior to any other operations on that IPSQ.
		 */
		if ((mp = xopipsq->ipsq_switch_mp) != NULL) {
			xopipsq->ipsq_switch_mp = NULL;
			ASSERT(mp->b_next == NULL);
			mp->b_next = (void *)xopipsq;
			goto out;
		}

		if ((mp = xopipsq->ipsq_xopq_mphead) != NULL) {
			xopipsq->ipsq_xopq_mphead = mp->b_next;
			if (xopipsq->ipsq_xopq_mphead == NULL)
				xopipsq->ipsq_xopq_mptail = NULL;
			mp->b_next = (void *)xopipsq;
			goto out;
		}
	} while ((xopipsq = xopipsq->ipsq_next) != ipsq);
empty:
	/*
	 * There are no messages.  Further, we are holding ipx_lock, hence no
	 * new messages can end up on any IPSQ in the xop.
	 */
	ipx->ipx_writer = NULL;
	ipx->ipx_forced = B_FALSE;
	VERIFY(--ipx->ipx_reentry_cnt == 0);
	ipx->ipx_ipsq_queued = B_FALSE;
	emptied = B_TRUE;
#ifdef	DEBUG
	ipx->ipx_depth = 0;
#endif
out:
	mutex_exit(&ipx->ipx_lock);
	mutex_exit(&ipsq->ipsq_lock);

	/*
	 * If we completely emptied the xop, then wake up any threads waiting
	 * to enter any of the IPSQ's associated with it.
	 */
	if (emptied) {
		xopipsq = ipsq;
		do {
			if ((phyi = xopipsq->ipsq_phyint) == NULL)
				continue;

			illv4 = phyi->phyint_illv4;
			illv6 = phyi->phyint_illv6;

			GRAB_ILL_LOCKS(illv4, illv6);
			if (illv4 != NULL)
				cv_broadcast(&illv4->ill_cv);
			if (illv6 != NULL)
				cv_broadcast(&illv6->ill_cv);
			RELEASE_ILL_LOCKS(illv4, illv6);
		} while ((xopipsq = xopipsq->ipsq_next) != ipsq);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	/*
	 * Now that all locks are dropped, exit the IPSQ we left.
	 */
	if (leftipsq != NULL)
		ipsq_exit(leftipsq);

	return (mp);
}

/*
 * Enter the ipsq corresponding to ill, by waiting synchronously till
 * we can enter the ipsq exclusively. Unless 'force' is used, the ipsq
 * will have to drain completely before ipsq_enter returns success.
 * ipx_current_ipif will be set if some exclusive op is in progress,
 * and the ipsq_exit logic will start the next enqueued op after
 * completion of the current op. If 'force' is used, we don't wait
 * for the enqueued ops. This is needed when a conn_close wants to
 * enter the ipsq and abort an ioctl that is somehow stuck. Unplumb
 * of an ill can also use this option. But we dont' use it currently.
 */
#define	ENTER_SQ_WAIT_TICKS 100
boolean_t
ipsq_enter(ill_t *ill, boolean_t force, int type)
{
	ipsq_t	*ipsq;
	ipxop_t *ipx;
	boolean_t waited_enough = B_FALSE;

	/*
	 * Note that the relationship between ill and ipsq is fixed as long as
	 * the ill is not ILL_CONDEMNED.  Holding ipsq_lock ensures the
	 * relationship between the IPSQ and xop cannot change.  However,
	 * since we cannot hold ipsq_lock across the cv_wait(), it may change
	 * while we're waiting.  We wait on ill_cv and rely on ipsq_exit()
	 * waking up all ills in the xop when it becomes available.
	 */
	mutex_enter(&ill->ill_lock);
	for (;;) {
		if (ill->ill_state_flags & ILL_CONDEMNED) {
			mutex_exit(&ill->ill_lock);
			return (B_FALSE);
		}

		ipsq = ill->ill_phyint->phyint_ipsq;
		mutex_enter(&ipsq->ipsq_lock);
		ipx = ipsq->ipsq_xop;
		mutex_enter(&ipx->ipx_lock);

		if (ipx->ipx_writer == NULL && (type == CUR_OP ||
		    ipx->ipx_current_ipif == NULL || waited_enough))
			break;

		if (!force || ipx->ipx_writer != NULL) {
			mutex_exit(&ipx->ipx_lock);
			mutex_exit(&ipsq->ipsq_lock);
			cv_wait(&ill->ill_cv, &ill->ill_lock);
		} else {
			mutex_exit(&ipx->ipx_lock);
			mutex_exit(&ipsq->ipsq_lock);
			(void) cv_timedwait(&ill->ill_cv,
			    &ill->ill_lock, lbolt + ENTER_SQ_WAIT_TICKS);
			waited_enough = B_TRUE;
		}
	}

	ASSERT(ipx->ipx_mphead == NULL && ipx->ipx_mptail == NULL);
	ASSERT(ipx->ipx_reentry_cnt == 0);
	ipx->ipx_writer = curthread;
	ipx->ipx_forced = (ipx->ipx_current_ipif != NULL);
	ipx->ipx_reentry_cnt++;
#ifdef DEBUG
	ipx->ipx_depth = getpcstack(ipx->ipx_stack, IPX_STACK_DEPTH);
#endif
	mutex_exit(&ipx->ipx_lock);
	mutex_exit(&ipsq->ipsq_lock);
	mutex_exit(&ill->ill_lock);
	return (B_TRUE);
}

boolean_t
ill_perim_enter(ill_t *ill)
{
	return (ipsq_enter(ill, B_FALSE, CUR_OP));
}

void
ill_perim_exit(ill_t *ill)
{
	ipsq_exit(ill->ill_phyint->phyint_ipsq);
}

/*
 * The ipsq_t (ipsq) is the synchronization data structure used to serialize
 * certain critical operations like plumbing (i.e. most set ioctls), multicast
 * joins, igmp/mld timers, etc.  There is one ipsq per phyint. The ipsq
 * serializes exclusive ioctls issued by applications on a per ipsq basis in
 * ipsq_xopq_mphead. It also protects against multiple threads executing in
 * the ipsq. Responses from the driver pertain to the current ioctl (say a
 * DL_BIND_ACK in response to a DL_BIND_REQ initiated as part of bringing
 * up the interface) and are enqueued in ipx_mphead.
 *
 * If a thread does not want to reenter the ipsq when it is already writer,
 * it must make sure that the specified reentry point to be called later
 * when the ipsq is empty, nor any code path starting from the specified reentry
 * point must never ever try to enter the ipsq again. Otherwise it can lead
 * to an infinite loop. The reentry point ip_rput_dlpi_writer is an example.
 * When the thread that is currently exclusive finishes, it (ipsq_exit)
 * dequeues the requests waiting to become exclusive in ipx_mphead and calls
 * the reentry point. When the list at ipx_mphead becomes empty ipsq_exit
 * proceeds to dequeue the next ioctl in ipsq_xopq_mphead and start the next
 * ioctl if the current ioctl has completed. If the current ioctl is still
 * in progress it simply returns. The current ioctl could be waiting for
 * a response from another module (arp or the driver or could be waiting for
 * the ipif/ill/ire refcnts to drop to zero. In such a case the ipx_pending_mp
 * and ipx_pending_ipif are set. ipx_current_ipif is set throughout the
 * execution of the ioctl and ipsq_exit does not start the next ioctl unless
 * ipx_current_ipif is NULL which happens only once the ioctl is complete and
 * all associated DLPI operations have completed.
 */

/*
 * Try to enter the IPSQ corresponding to `ipif' or `ill' exclusively (`ipif'
 * and `ill' cannot both be specified).  Returns a pointer to the entered IPSQ
 * on success, or NULL on failure.  The caller ensures ipif/ill is valid by
 * refholding it as necessary.  If the IPSQ cannot be entered and `func' is
 * non-NULL, then `func' will be called back with `q' and `mp' once the IPSQ
 * can be entered.  If `func' is NULL, then `q' and `mp' are ignored.
 */
ipsq_t *
ipsq_try_enter(ipif_t *ipif, ill_t *ill, queue_t *q, mblk_t *mp,
    ipsq_func_t func, int type, boolean_t reentry_ok)
{
	ipsq_t	*ipsq;
	ipxop_t	*ipx;

	/* Only 1 of ipif or ill can be specified */
	ASSERT((ipif != NULL) ^ (ill != NULL));
	if (ipif != NULL)
		ill = ipif->ipif_ill;

	/*
	 * lock ordering: conn_lock -> ill_lock -> ipsq_lock -> ipx_lock.
	 * ipx of an ipsq can't change when ipsq_lock is held.
	 */
	GRAB_CONN_LOCK(q);
	mutex_enter(&ill->ill_lock);
	ipsq = ill->ill_phyint->phyint_ipsq;
	mutex_enter(&ipsq->ipsq_lock);
	ipx = ipsq->ipsq_xop;
	mutex_enter(&ipx->ipx_lock);

	/*
	 * 1. Enter the ipsq if we are already writer and reentry is ok.
	 *    (Note: If the caller does not specify reentry_ok then neither
	 *    'func' nor any of its callees must ever attempt to enter the ipsq
	 *    again. Otherwise it can lead to an infinite loop
	 * 2. Enter the ipsq if there is no current writer and this attempted
	 *    entry is part of the current operation
	 * 3. Enter the ipsq if there is no current writer and this is a new
	 *    operation and the operation queue is empty and there is no
	 *    operation currently in progress
	 */
	if ((ipx->ipx_writer == curthread && reentry_ok) ||
	    (ipx->ipx_writer == NULL && (type == CUR_OP || (type == NEW_OP &&
	    !ipx->ipx_ipsq_queued && ipx->ipx_current_ipif == NULL)))) {
		/* Success. */
		ipx->ipx_reentry_cnt++;
		ipx->ipx_writer = curthread;
		ipx->ipx_forced = B_FALSE;
		mutex_exit(&ipx->ipx_lock);
		mutex_exit(&ipsq->ipsq_lock);
		mutex_exit(&ill->ill_lock);
		RELEASE_CONN_LOCK(q);
#ifdef DEBUG
		ipx->ipx_depth = getpcstack(ipx->ipx_stack, IPX_STACK_DEPTH);
#endif
		return (ipsq);
	}

	if (func != NULL)
		ipsq_enq(ipsq, q, mp, func, type, ill);

	mutex_exit(&ipx->ipx_lock);
	mutex_exit(&ipsq->ipsq_lock);
	mutex_exit(&ill->ill_lock);
	RELEASE_CONN_LOCK(q);
	return (NULL);
}

/*
 * Try to enter the IPSQ corresponding to `ill' as writer.  The caller ensures
 * ill is valid by refholding it if necessary; we will refrele.  If the IPSQ
 * cannot be entered, the mp is queued for completion.
 */
void
qwriter_ip(ill_t *ill, queue_t *q, mblk_t *mp, ipsq_func_t func, int type,
    boolean_t reentry_ok)
{
	ipsq_t	*ipsq;

	ipsq = ipsq_try_enter(NULL, ill, q, mp, func, type, reentry_ok);

	/*
	 * Drop the caller's refhold on the ill.  This is safe since we either
	 * entered the IPSQ (and thus are exclusive), or failed to enter the
	 * IPSQ, in which case we return without accessing ill anymore.  This
	 * is needed because func needs to see the correct refcount.
	 * e.g. removeif can work only then.
	 */
	ill_refrele(ill);
	if (ipsq != NULL) {
		(*func)(ipsq, q, mp, NULL);
		ipsq_exit(ipsq);
	}
}

/*
 * Exit the specified IPSQ.  If this is the final exit on it then drain it
 * prior to exiting.  Caller must be writer on the specified IPSQ.
 */
void
ipsq_exit(ipsq_t *ipsq)
{
	mblk_t *mp;
	ipsq_t *mp_ipsq;
	queue_t	*q;
	phyint_t *phyi;
	ipsq_func_t func;

	ASSERT(IAM_WRITER_IPSQ(ipsq));

	ASSERT(ipsq->ipsq_xop->ipx_reentry_cnt >= 1);
	if (ipsq->ipsq_xop->ipx_reentry_cnt != 1) {
		ipsq->ipsq_xop->ipx_reentry_cnt--;
		return;
	}

	for (;;) {
		phyi = ipsq->ipsq_phyint;
		mp = ipsq_dq(ipsq);
		mp_ipsq = (mp == NULL) ? NULL : (ipsq_t *)mp->b_next;

		/*
		 * If we've changed to a new IPSQ, and the phyint associated
		 * with the old one has gone away, free the old IPSQ.  Note
		 * that this cannot happen while the IPSQ is in a group.
		 */
		if (mp_ipsq != ipsq && phyi == NULL) {
			ASSERT(ipsq->ipsq_next == ipsq);
			ASSERT(ipsq->ipsq_xop == &ipsq->ipsq_ownxop);
			ipsq_delete(ipsq);
		}

		if (mp == NULL)
			break;

		q = mp->b_queue;
		func = (ipsq_func_t)mp->b_prev;
		ipsq = mp_ipsq;
		mp->b_next = mp->b_prev = NULL;
		mp->b_queue = NULL;

		/*
		 * If 'q' is an conn queue, it is valid, since we did a
		 * a refhold on the conn at the start of the ioctl.
		 * If 'q' is an ill queue, it is valid, since close of an
		 * ill will clean up its IPSQ.
		 */
		(*func)(ipsq, q, mp, NULL);
	}
}

/*
 * Start the current exclusive operation on `ipsq'; associate it with `ipif'
 * and `ioccmd'.
 */
void
ipsq_current_start(ipsq_t *ipsq, ipif_t *ipif, int ioccmd)
{
	ipxop_t *ipx = ipsq->ipsq_xop;

	ASSERT(IAM_WRITER_IPSQ(ipsq));
	ASSERT(ipx->ipx_current_ipif == NULL);
	ASSERT(ipx->ipx_current_ioctl == 0);

	ipx->ipx_current_done = B_FALSE;
	ipx->ipx_current_ioctl = ioccmd;
	mutex_enter(&ipx->ipx_lock);
	ipx->ipx_current_ipif = ipif;
	mutex_exit(&ipx->ipx_lock);
}

/*
 * Finish the current exclusive operation on `ipsq'.  Usually, this will allow
 * the next exclusive operation to begin once we ipsq_exit().  However, if
 * pending DLPI operations remain, then we will wait for the queue to drain
 * before allowing the next exclusive operation to begin.  This ensures that
 * DLPI operations from one exclusive operation are never improperly processed
 * as part of a subsequent exclusive operation.
 */
void
ipsq_current_finish(ipsq_t *ipsq)
{
	ipxop_t	*ipx = ipsq->ipsq_xop;
	t_uscalar_t dlpi_pending = DL_PRIM_INVAL;
	ipif_t	*ipif = ipx->ipx_current_ipif;

	ASSERT(IAM_WRITER_IPSQ(ipsq));

	/*
	 * For SIOCLIFREMOVEIF, the ipif has been already been blown away
	 * (but in that case, IPIF_CHANGING will already be clear and no
	 * pending DLPI messages can remain).
	 */
	if (ipx->ipx_current_ioctl != SIOCLIFREMOVEIF) {
		ill_t *ill = ipif->ipif_ill;

		mutex_enter(&ill->ill_lock);
		dlpi_pending = ill->ill_dlpi_pending;
		ipif->ipif_state_flags &= ~IPIF_CHANGING;
		mutex_exit(&ill->ill_lock);
	}

	ASSERT(!ipx->ipx_current_done);
	ipx->ipx_current_done = B_TRUE;
	ipx->ipx_current_ioctl = 0;
	if (dlpi_pending == DL_PRIM_INVAL) {
		mutex_enter(&ipx->ipx_lock);
		ipx->ipx_current_ipif = NULL;
		mutex_exit(&ipx->ipx_lock);
	}
}

/*
 * The ill is closing. Flush all messages on the ipsq that originated
 * from this ill. Usually there wont' be any messages on the ipsq_xopq_mphead
 * for this ill since ipsq_enter could not have entered until then.
 * New messages can't be queued since the CONDEMNED flag is set.
 */
static void
ipsq_flush(ill_t *ill)
{
	queue_t	*q;
	mblk_t	*prev;
	mblk_t	*mp;
	mblk_t	*mp_next;
	ipxop_t	*ipx = ill->ill_phyint->phyint_ipsq->ipsq_xop;

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Flush any messages sent up by the driver.
	 */
	mutex_enter(&ipx->ipx_lock);
	for (prev = NULL, mp = ipx->ipx_mphead; mp != NULL; mp = mp_next) {
		mp_next = mp->b_next;
		q = mp->b_queue;
		if (q == ill->ill_rq || q == ill->ill_wq) {
			/* dequeue mp */
			if (prev == NULL)
				ipx->ipx_mphead = mp->b_next;
			else
				prev->b_next = mp->b_next;
			if (ipx->ipx_mptail == mp) {
				ASSERT(mp_next == NULL);
				ipx->ipx_mptail = prev;
			}
			inet_freemsg(mp);
		} else {
			prev = mp;
		}
	}
	mutex_exit(&ipx->ipx_lock);
	(void) ipsq_pending_mp_cleanup(ill, NULL);
	ipsq_xopq_mp_cleanup(ill, NULL);
	ill_pending_mp_cleanup(ill);
}

/*
 * Parse an iftun_req structure coming down SIOC[GS]TUNPARAM ioctls,
 * refhold and return the associated ipif
 */
/* ARGSUSED */
int
ip_extract_tunreq(queue_t *q, mblk_t *mp, const ip_ioctl_cmd_t *ipip,
    cmd_info_t *ci, ipsq_func_t func)
{
	boolean_t exists;
	struct iftun_req *ta;
	ipif_t  *ipif;
	ill_t   *ill;
	boolean_t isv6;
	mblk_t  *mp1;
	int error;
	conn_t  *connp;
	ip_stack_t  *ipst;

	/* Existence verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	ta = (struct iftun_req *)mp1->b_rptr;
	/*
	 * Null terminate the string to protect against buffer
	 * overrun. String was generated by user code and may not
	 * be trusted.
	 */
	ta->ifta_lifr_name[LIFNAMSIZ - 1] = '\0';

	connp = Q_TO_CONN(q);
	isv6 = connp->conn_af_isv6;
	ipst = connp->conn_netstack->netstack_ip;

	/* Disallows implicit create */
	ipif = ipif_lookup_on_name(ta->ifta_lifr_name,
	    mi_strlen(ta->ifta_lifr_name), B_FALSE, &exists, isv6,
	    connp->conn_zoneid, CONNP_TO_WQ(connp), mp, func, &error, ipst);
	if (ipif == NULL)
		return (error);

	if (ipif->ipif_id != 0) {
		/*
		 * We really don't want to set/get tunnel parameters
		 * on virtual tunnel interfaces.  Only allow the
		 * base tunnel to do these.
		 */
		ipif_refrele(ipif);
		return (EINVAL);
	}

	/*
	 * Send down to tunnel mod for ioctl processing.
	 * Will finish ioctl in ip_rput_other().
	 */
	ill = ipif->ipif_ill;
	if (ill->ill_net_type == IRE_LOOPBACK) {
		ipif_refrele(ipif);
		return (EOPNOTSUPP);
	}

	if (ill->ill_wq == NULL) {
		ipif_refrele(ipif);
		return (ENXIO);
	}
	/*
	 * Mark the ioctl as coming from an IPv6 interface for
	 * tun's convenience.
	 */
	if (ill->ill_isv6)
		ta->ifta_flags |= 0x80000000;
	ci->ci_ipif = ipif;
	return (0);
}

/*
 * Parse an ifreq or lifreq struct coming down ioctls and refhold
 * and return the associated ipif.
 * Return value:
 *	Non zero: An error has occurred. ci may not be filled out.
 *	zero : ci is filled out with the ioctl cmd in ci.ci_name, and
 *	a held ipif in ci.ci_ipif.
 */
int
ip_extract_lifreq(queue_t *q, mblk_t *mp, const ip_ioctl_cmd_t *ipip,
    cmd_info_t *ci, ipsq_func_t func)
{
	char		*name;
	struct ifreq    *ifr;
	struct lifreq    *lifr;
	ipif_t		*ipif = NULL;
	ill_t		*ill;
	conn_t		*connp;
	boolean_t	isv6;
	boolean_t	exists;
	int		err;
	mblk_t		*mp1;
	zoneid_t	zoneid;
	ip_stack_t	*ipst;

	if (q->q_next != NULL) {
		ill = (ill_t *)q->q_ptr;
		isv6 = ill->ill_isv6;
		connp = NULL;
		zoneid = ALL_ZONES;
		ipst = ill->ill_ipst;
	} else {
		ill = NULL;
		connp = Q_TO_CONN(q);
		isv6 = connp->conn_af_isv6;
		zoneid = connp->conn_zoneid;
		if (zoneid == GLOBAL_ZONEID) {
			/* global zone can access ipifs in all zones */
			zoneid = ALL_ZONES;
		}
		ipst = connp->conn_netstack->netstack_ip;
	}

	/* Has been checked in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;

	if (ipip->ipi_cmd_type == IF_CMD) {
		/* This a old style SIOC[GS]IF* command */
		ifr = (struct ifreq *)mp1->b_rptr;
		/*
		 * Null terminate the string to protect against buffer
		 * overrun. String was generated by user code and may not
		 * be trusted.
		 */
		ifr->ifr_name[IFNAMSIZ - 1] = '\0';
		name = ifr->ifr_name;
		ci->ci_sin = (sin_t *)&ifr->ifr_addr;
		ci->ci_sin6 = NULL;
		ci->ci_lifr = (struct lifreq *)ifr;
	} else {
		/* This a new style SIOC[GS]LIF* command */
		ASSERT(ipip->ipi_cmd_type == LIF_CMD);
		lifr = (struct lifreq *)mp1->b_rptr;
		/*
		 * Null terminate the string to protect against buffer
		 * overrun. String was generated by user code and may not
		 * be trusted.
		 */
		lifr->lifr_name[LIFNAMSIZ - 1] = '\0';
		name = lifr->lifr_name;
		ci->ci_sin = (sin_t *)&lifr->lifr_addr;
		ci->ci_sin6 = (sin6_t *)&lifr->lifr_addr;
		ci->ci_lifr = lifr;
	}

	if (ipip->ipi_cmd == SIOCSLIFNAME) {
		/*
		 * The ioctl will be failed if the ioctl comes down
		 * an conn stream
		 */
		if (ill == NULL) {
			/*
			 * Not an ill queue, return EINVAL same as the
			 * old error code.
			 */
			return (ENXIO);
		}
		ipif = ill->ill_ipif;
		ipif_refhold(ipif);
	} else {
		ipif = ipif_lookup_on_name(name, mi_strlen(name), B_FALSE,
		    &exists, isv6, zoneid,
		    (connp == NULL) ? q : CONNP_TO_WQ(connp), mp, func, &err,
		    ipst);
		if (ipif == NULL) {
			if (err == EINPROGRESS)
				return (err);
			err = 0;	/* Ensure we don't use it below */
		}
	}

	/*
	 * Old style [GS]IFCMD does not admit IPv6 ipif
	 */
	if (ipif != NULL && ipif->ipif_isv6 && ipip->ipi_cmd_type == IF_CMD) {
		ipif_refrele(ipif);
		return (ENXIO);
	}

	if (ipif == NULL && ill != NULL && ill->ill_ipif != NULL &&
	    name[0] == '\0') {
		/*
		 * Handle a or a SIOC?IF* with a null name
		 * during plumb (on the ill queue before the I_PLINK).
		 */
		ipif = ill->ill_ipif;
		ipif_refhold(ipif);
	}

	if (ipif == NULL)
		return (ENXIO);

	ci->ci_ipif = ipif;
	return (0);
}

/*
 * Return the total number of ipifs.
 */
static uint_t
ip_get_numifs(zoneid_t zoneid, ip_stack_t *ipst)
{
	uint_t numifs = 0;
	ill_t	*ill;
	ill_walk_context_t	ctx;
	ipif_t	*ipif;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (IS_UNDER_IPMP(ill))
			continue;
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (ipif->ipif_zoneid == zoneid ||
			    ipif->ipif_zoneid == ALL_ZONES)
				numifs++;
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);
	return (numifs);
}

/*
 * Return the total number of ipifs.
 */
static uint_t
ip_get_numlifs(int family, int lifn_flags, zoneid_t zoneid, ip_stack_t *ipst)
{
	uint_t numifs = 0;
	ill_t	*ill;
	ipif_t	*ipif;
	ill_walk_context_t	ctx;

	ip1dbg(("ip_get_numlifs(%d %u %d)\n", family, lifn_flags, (int)zoneid));

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (family == AF_INET)
		ill = ILL_START_WALK_V4(&ctx, ipst);
	else if (family == AF_INET6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_ALL(&ctx, ipst);

	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (IS_UNDER_IPMP(ill) && !(lifn_flags & LIFC_UNDER_IPMP))
			continue;

		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if ((ipif->ipif_flags & IPIF_NOXMIT) &&
			    !(lifn_flags & LIFC_NOXMIT))
				continue;
			if ((ipif->ipif_flags & IPIF_TEMPORARY) &&
			    !(lifn_flags & LIFC_TEMPORARY))
				continue;
			if (((ipif->ipif_flags &
			    (IPIF_NOXMIT|IPIF_NOLOCAL|
			    IPIF_DEPRECATED)) ||
			    IS_LOOPBACK(ill) ||
			    !(ipif->ipif_flags & IPIF_UP)) &&
			    (lifn_flags & LIFC_EXTERNAL_SOURCE))
				continue;

			if (zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES &&
			    (zoneid != GLOBAL_ZONEID ||
			    !(lifn_flags & LIFC_ALLZONES)))
				continue;

			numifs++;
		}
	}
	rw_exit(&ipst->ips_ill_g_lock);
	return (numifs);
}

uint_t
ip_get_lifsrcofnum(ill_t *ill)
{
	uint_t numifs = 0;
	ill_t	*ill_head = ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	/*
	 * ill_g_usesrc_lock protects ill_usesrc_grp_next, for example, some
	 * other thread may be trying to relink the ILLs in this usesrc group
	 * and adjusting the ill_usesrc_grp_next pointers
	 */
	rw_enter(&ipst->ips_ill_g_usesrc_lock, RW_READER);
	if ((ill->ill_usesrc_ifindex == 0) &&
	    (ill->ill_usesrc_grp_next != NULL)) {
		for (; (ill != NULL) && (ill->ill_usesrc_grp_next != ill_head);
		    ill = ill->ill_usesrc_grp_next)
			numifs++;
	}
	rw_exit(&ipst->ips_ill_g_usesrc_lock);

	return (numifs);
}

/* Null values are passed in for ipif, sin, and ifreq */
/* ARGSUSED */
int
ip_sioctl_get_ifnum(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q,
    mblk_t *mp, ip_ioctl_cmd_t *ipip, void *ifreq)
{
	int *nump;
	conn_t *connp = Q_TO_CONN(q);

	ASSERT(q->q_next == NULL); /* not a valid ioctl for ip as a module */

	/* Existence of b_cont->b_cont checked in ip_wput_nondata */
	nump = (int *)mp->b_cont->b_cont->b_rptr;

	*nump = ip_get_numifs(connp->conn_zoneid,
	    connp->conn_netstack->netstack_ip);
	ip1dbg(("ip_sioctl_get_ifnum numifs %d", *nump));
	return (0);
}

/* Null values are passed in for ipif, sin, and ifreq */
/* ARGSUSED */
int
ip_sioctl_get_lifnum(ipif_t *dummy_ipif, sin_t *dummy_sin,
    queue_t *q, mblk_t *mp, ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct lifnum *lifn;
	mblk_t	*mp1;
	conn_t *connp = Q_TO_CONN(q);

	ASSERT(q->q_next == NULL); /* not a valid ioctl for ip as a module */

	/* Existence checked in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;

	lifn = (struct lifnum *)mp1->b_rptr;
	switch (lifn->lifn_family) {
	case AF_UNSPEC:
	case AF_INET:
	case AF_INET6:
		break;
	default:
		return (EAFNOSUPPORT);
	}

	lifn->lifn_count = ip_get_numlifs(lifn->lifn_family, lifn->lifn_flags,
	    connp->conn_zoneid, connp->conn_netstack->netstack_ip);
	ip1dbg(("ip_sioctl_get_lifnum numifs %d", lifn->lifn_count));
	return (0);
}

/* ARGSUSED */
int
ip_sioctl_get_ifconf(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q,
    mblk_t *mp, ip_ioctl_cmd_t *ipip, void *ifreq)
{
	STRUCT_HANDLE(ifconf, ifc);
	mblk_t *mp1;
	struct iocblk *iocp;
	struct ifreq *ifr;
	ill_walk_context_t	ctx;
	ill_t	*ill;
	ipif_t	*ipif;
	struct sockaddr_in *sin;
	int32_t	ifclen;
	zoneid_t zoneid;
	ip_stack_t *ipst = CONNQ_TO_IPST(q);

	ASSERT(q->q_next == NULL); /* not valid ioctls for ip as a module */

	ip1dbg(("ip_sioctl_get_ifconf"));
	/* Existence verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	iocp = (struct iocblk *)mp->b_rptr;
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/*
	 * The original SIOCGIFCONF passed in a struct ifconf which specified
	 * the user buffer address and length into which the list of struct
	 * ifreqs was to be copied.  Since AT&T Streams does not seem to
	 * allow M_COPYOUT to be used in conjunction with I_STR IOCTLS,
	 * the SIOCGIFCONF operation was redefined to simply provide
	 * a large output buffer into which we are supposed to jam the ifreq
	 * array.  The same ioctl command code was used, despite the fact that
	 * both the applications and the kernel code had to change, thus making
	 * it impossible to support both interfaces.
	 *
	 * For reasons not good enough to try to explain, the following
	 * algorithm is used for deciding what to do with one of these:
	 * If the IOCTL comes in as an I_STR, it is assumed to be of the new
	 * form with the output buffer coming down as the continuation message.
	 * If it arrives as a TRANSPARENT IOCTL, it is assumed to be old style,
	 * and we have to copy in the ifconf structure to find out how big the
	 * output buffer is and where to copy out to.  Sure no problem...
	 *
	 */
	STRUCT_SET_HANDLE(ifc, iocp->ioc_flag, NULL);
	if ((mp1->b_wptr - mp1->b_rptr) == STRUCT_SIZE(ifc)) {
		int numifs = 0;
		size_t ifc_bufsize;

		/*
		 * Must be (better be!) continuation of a TRANSPARENT
		 * IOCTL.  We just copied in the ifconf structure.
		 */
		STRUCT_SET_HANDLE(ifc, iocp->ioc_flag,
		    (struct ifconf *)mp1->b_rptr);

		/*
		 * Allocate a buffer to hold requested information.
		 *
		 * If ifc_len is larger than what is needed, we only
		 * allocate what we will use.
		 *
		 * If ifc_len is smaller than what is needed, return
		 * EINVAL.
		 *
		 * XXX: the ill_t structure can hava 2 counters, for
		 * v4 and v6 (not just ill_ipif_up_count) to store the
		 * number of interfaces for a device, so we don't need
		 * to count them here...
		 */
		numifs = ip_get_numifs(zoneid, ipst);

		ifclen = STRUCT_FGET(ifc, ifc_len);
		ifc_bufsize = numifs * sizeof (struct ifreq);
		if (ifc_bufsize > ifclen) {
			if (iocp->ioc_cmd == O_SIOCGIFCONF) {
				/* old behaviour */
				return (EINVAL);
			} else {
				ifc_bufsize = ifclen;
			}
		}

		mp1 = mi_copyout_alloc(q, mp,
		    STRUCT_FGETP(ifc, ifc_buf), ifc_bufsize, B_FALSE);
		if (mp1 == NULL)
			return (ENOMEM);

		mp1->b_wptr = mp1->b_rptr + ifc_bufsize;
	}
	bzero(mp1->b_rptr, mp1->b_wptr - mp1->b_rptr);
	/*
	 * the SIOCGIFCONF ioctl only knows about
	 * IPv4 addresses, so don't try to tell
	 * it about interfaces with IPv6-only
	 * addresses. (Last parm 'isv6' is B_FALSE)
	 */

	ifr = (struct ifreq *)mp1->b_rptr;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (IS_UNDER_IPMP(ill))
			continue;
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			if ((uchar_t *)&ifr[1] > mp1->b_wptr) {
				if (iocp->ioc_cmd == O_SIOCGIFCONF) {
					/* old behaviour */
					rw_exit(&ipst->ips_ill_g_lock);
					return (EINVAL);
				} else {
					goto if_copydone;
				}
			}
			ipif_get_name(ipif, ifr->ifr_name,
			    sizeof (ifr->ifr_name));
			sin = (sin_t *)&ifr->ifr_addr;
			*sin = sin_null;
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = ipif->ipif_lcl_addr;
			ifr++;
		}
	}
if_copydone:
	rw_exit(&ipst->ips_ill_g_lock);
	mp1->b_wptr = (uchar_t *)ifr;

	if (STRUCT_BUF(ifc) != NULL) {
		STRUCT_FSET(ifc, ifc_len,
		    (int)((uchar_t *)ifr - mp1->b_rptr));
	}
	return (0);
}

/*
 * Get the interfaces using the address hosted on the interface passed in,
 * as a source adddress
 */
/* ARGSUSED */
int
ip_sioctl_get_lifsrcof(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q,
    mblk_t *mp, ip_ioctl_cmd_t *ipip, void *ifreq)
{
	mblk_t *mp1;
	ill_t	*ill, *ill_head;
	ipif_t	*ipif, *orig_ipif;
	int	numlifs = 0;
	size_t	lifs_bufsize, lifsmaxlen;
	struct	lifreq *lifr;
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	uint_t	ifindex;
	zoneid_t zoneid;
	int err = 0;
	boolean_t isv6 = B_FALSE;
	struct	sockaddr_in	*sin;
	struct	sockaddr_in6	*sin6;
	STRUCT_HANDLE(lifsrcof, lifs);
	ip_stack_t		*ipst;

	ipst = CONNQ_TO_IPST(q);

	ASSERT(q->q_next == NULL);

	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/* Existence verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;

	/*
	 * Must be (better be!) continuation of a TRANSPARENT
	 * IOCTL.  We just copied in the lifsrcof structure.
	 */
	STRUCT_SET_HANDLE(lifs, iocp->ioc_flag,
	    (struct lifsrcof *)mp1->b_rptr);

	if (MBLKL(mp1) != STRUCT_SIZE(lifs))
		return (EINVAL);

	ifindex = STRUCT_FGET(lifs, lifs_ifindex);
	isv6 = (Q_TO_CONN(q))->conn_af_isv6;
	ipif = ipif_lookup_on_ifindex(ifindex, isv6, zoneid, q, mp,
	    ip_process_ioctl, &err, ipst);
	if (ipif == NULL) {
		ip1dbg(("ip_sioctl_get_lifsrcof: no ipif for ifindex %d\n",
		    ifindex));
		return (err);
	}

	/* Allocate a buffer to hold requested information */
	numlifs = ip_get_lifsrcofnum(ipif->ipif_ill);
	lifs_bufsize = numlifs * sizeof (struct lifreq);
	lifsmaxlen =  STRUCT_FGET(lifs, lifs_maxlen);
	/* The actual size needed is always returned in lifs_len */
	STRUCT_FSET(lifs, lifs_len, lifs_bufsize);

	/* If the amount we need is more than what is passed in, abort */
	if (lifs_bufsize > lifsmaxlen || lifs_bufsize == 0) {
		ipif_refrele(ipif);
		return (0);
	}

	mp1 = mi_copyout_alloc(q, mp,
	    STRUCT_FGETP(lifs, lifs_buf), lifs_bufsize, B_FALSE);
	if (mp1 == NULL) {
		ipif_refrele(ipif);
		return (ENOMEM);
	}

	mp1->b_wptr = mp1->b_rptr + lifs_bufsize;
	bzero(mp1->b_rptr, lifs_bufsize);

	lifr = (struct lifreq *)mp1->b_rptr;

	ill = ill_head = ipif->ipif_ill;
	orig_ipif = ipif;

	/* ill_g_usesrc_lock protects ill_usesrc_grp_next */
	rw_enter(&ipst->ips_ill_g_usesrc_lock, RW_READER);
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);

	ill = ill->ill_usesrc_grp_next; /* start from next ill */
	for (; (ill != NULL) && (ill != ill_head);
	    ill = ill->ill_usesrc_grp_next) {

		if ((uchar_t *)&lifr[1] > mp1->b_wptr)
			break;

		ipif = ill->ill_ipif;
		ipif_get_name(ipif, lifr->lifr_name, sizeof (lifr->lifr_name));
		if (ipif->ipif_isv6) {
			sin6 = (sin6_t *)&lifr->lifr_addr;
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = ipif->ipif_v6lcl_addr;
			lifr->lifr_addrlen = ip_mask_to_plen_v6(
			    &ipif->ipif_v6net_mask);
		} else {
			sin = (sin_t *)&lifr->lifr_addr;
			*sin = sin_null;
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = ipif->ipif_lcl_addr;
			lifr->lifr_addrlen = ip_mask_to_plen(
			    ipif->ipif_net_mask);
		}
		lifr++;
	}
	rw_exit(&ipst->ips_ill_g_usesrc_lock);
	rw_exit(&ipst->ips_ill_g_lock);
	ipif_refrele(orig_ipif);
	mp1->b_wptr = (uchar_t *)lifr;
	STRUCT_FSET(lifs, lifs_len, (int)((uchar_t *)lifr - mp1->b_rptr));

	return (0);
}

/* ARGSUSED */
int
ip_sioctl_get_lifconf(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q,
    mblk_t *mp, ip_ioctl_cmd_t *ipip, void *ifreq)
{
	mblk_t *mp1;
	int	list;
	ill_t	*ill;
	ipif_t	*ipif;
	int	flags;
	int	numlifs = 0;
	size_t	lifc_bufsize;
	struct	lifreq *lifr;
	sa_family_t	family;
	struct	sockaddr_in	*sin;
	struct	sockaddr_in6	*sin6;
	ill_walk_context_t	ctx;
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	int32_t	lifclen;
	zoneid_t zoneid;
	STRUCT_HANDLE(lifconf, lifc);
	ip_stack_t *ipst = CONNQ_TO_IPST(q);

	ip1dbg(("ip_sioctl_get_lifconf"));

	ASSERT(q->q_next == NULL);

	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/* Existence verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;

	/*
	 * An extended version of SIOCGIFCONF that takes an
	 * additional address family and flags field.
	 * AF_UNSPEC retrieve both IPv4 and IPv6.
	 * Unless LIFC_NOXMIT is specified the IPIF_NOXMIT
	 * interfaces are omitted.
	 * Similarly, IPIF_TEMPORARY interfaces are omitted
	 * unless LIFC_TEMPORARY is specified.
	 * If LIFC_EXTERNAL_SOURCE is specified, IPIF_NOXMIT,
	 * IPIF_NOLOCAL, PHYI_LOOPBACK, IPIF_DEPRECATED and
	 * not IPIF_UP interfaces are omitted. LIFC_EXTERNAL_SOURCE
	 * has priority over LIFC_NOXMIT.
	 */
	STRUCT_SET_HANDLE(lifc, iocp->ioc_flag, NULL);

	if ((mp1->b_wptr - mp1->b_rptr) != STRUCT_SIZE(lifc))
		return (EINVAL);

	/*
	 * Must be (better be!) continuation of a TRANSPARENT
	 * IOCTL.  We just copied in the lifconf structure.
	 */
	STRUCT_SET_HANDLE(lifc, iocp->ioc_flag, (struct lifconf *)mp1->b_rptr);

	family = STRUCT_FGET(lifc, lifc_family);
	flags = STRUCT_FGET(lifc, lifc_flags);

	switch (family) {
	case AF_UNSPEC:
		/*
		 * walk all ILL's.
		 */
		list = MAX_G_HEADS;
		break;
	case AF_INET:
		/*
		 * walk only IPV4 ILL's.
		 */
		list = IP_V4_G_HEAD;
		break;
	case AF_INET6:
		/*
		 * walk only IPV6 ILL's.
		 */
		list = IP_V6_G_HEAD;
		break;
	default:
		return (EAFNOSUPPORT);
	}

	/*
	 * Allocate a buffer to hold requested information.
	 *
	 * If lifc_len is larger than what is needed, we only
	 * allocate what we will use.
	 *
	 * If lifc_len is smaller than what is needed, return
	 * EINVAL.
	 */
	numlifs = ip_get_numlifs(family, flags, zoneid, ipst);
	lifc_bufsize = numlifs * sizeof (struct lifreq);
	lifclen = STRUCT_FGET(lifc, lifc_len);
	if (lifc_bufsize > lifclen) {
		if (iocp->ioc_cmd == O_SIOCGLIFCONF)
			return (EINVAL);
		else
			lifc_bufsize = lifclen;
	}

	mp1 = mi_copyout_alloc(q, mp,
	    STRUCT_FGETP(lifc, lifc_buf), lifc_bufsize, B_FALSE);
	if (mp1 == NULL)
		return (ENOMEM);

	mp1->b_wptr = mp1->b_rptr + lifc_bufsize;
	bzero(mp1->b_rptr, mp1->b_wptr - mp1->b_rptr);

	lifr = (struct lifreq *)mp1->b_rptr;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ill_first(list, list, &ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (IS_UNDER_IPMP(ill) && !(flags & LIFC_UNDER_IPMP))
			continue;

		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if ((ipif->ipif_flags & IPIF_NOXMIT) &&
			    !(flags & LIFC_NOXMIT))
				continue;

			if ((ipif->ipif_flags & IPIF_TEMPORARY) &&
			    !(flags & LIFC_TEMPORARY))
				continue;

			if (((ipif->ipif_flags &
			    (IPIF_NOXMIT|IPIF_NOLOCAL|
			    IPIF_DEPRECATED)) ||
			    IS_LOOPBACK(ill) ||
			    !(ipif->ipif_flags & IPIF_UP)) &&
			    (flags & LIFC_EXTERNAL_SOURCE))
				continue;

			if (zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES &&
			    (zoneid != GLOBAL_ZONEID ||
			    !(flags & LIFC_ALLZONES)))
				continue;

			if ((uchar_t *)&lifr[1] > mp1->b_wptr) {
				if (iocp->ioc_cmd == O_SIOCGLIFCONF) {
					rw_exit(&ipst->ips_ill_g_lock);
					return (EINVAL);
				} else {
					goto lif_copydone;
				}
			}

			ipif_get_name(ipif, lifr->lifr_name,
			    sizeof (lifr->lifr_name));
			lifr->lifr_type = ill->ill_type;
			if (ipif->ipif_isv6) {
				sin6 = (sin6_t *)&lifr->lifr_addr;
				*sin6 = sin6_null;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_addr =
				    ipif->ipif_v6lcl_addr;
				lifr->lifr_addrlen =
				    ip_mask_to_plen_v6(
				    &ipif->ipif_v6net_mask);
			} else {
				sin = (sin_t *)&lifr->lifr_addr;
				*sin = sin_null;
				sin->sin_family = AF_INET;
				sin->sin_addr.s_addr =
				    ipif->ipif_lcl_addr;
				lifr->lifr_addrlen =
				    ip_mask_to_plen(
				    ipif->ipif_net_mask);
			}
			lifr++;
		}
	}
lif_copydone:
	rw_exit(&ipst->ips_ill_g_lock);

	mp1->b_wptr = (uchar_t *)lifr;
	if (STRUCT_BUF(lifc) != NULL) {
		STRUCT_FSET(lifc, lifc_len,
		    (int)((uchar_t *)lifr - mp1->b_rptr));
	}
	return (0);
}

static void
ip_sioctl_ip6addrpolicy(queue_t *q, mblk_t *mp)
{
	ip6_asp_t *table;
	size_t table_size;
	mblk_t *data_mp;
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	ip_stack_t	*ipst;

	if (q->q_next == NULL)
		ipst = CONNQ_TO_IPST(q);
	else
		ipst = ILLQ_TO_IPST(q);

	/* These two ioctls are I_STR only */
	if (iocp->ioc_count == TRANSPARENT) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	data_mp = mp->b_cont;
	if (data_mp == NULL) {
		/* The user passed us a NULL argument */
		table = NULL;
		table_size = iocp->ioc_count;
	} else {
		/*
		 * The user provided a table.  The stream head
		 * may have copied in the user data in chunks,
		 * so make sure everything is pulled up
		 * properly.
		 */
		if (MBLKL(data_mp) < iocp->ioc_count) {
			mblk_t *new_data_mp;
			if ((new_data_mp = msgpullup(data_mp, -1)) ==
			    NULL) {
				miocnak(q, mp, 0, ENOMEM);
				return;
			}
			freemsg(data_mp);
			data_mp = new_data_mp;
			mp->b_cont = data_mp;
		}
		table = (ip6_asp_t *)data_mp->b_rptr;
		table_size = iocp->ioc_count;
	}

	switch (iocp->ioc_cmd) {
	case SIOCGIP6ADDRPOLICY:
		iocp->ioc_rval = ip6_asp_get(table, table_size, ipst);
		if (iocp->ioc_rval == -1)
			iocp->ioc_error = EINVAL;
#if defined(_SYSCALL32_IMPL) && _LONG_LONG_ALIGNMENT_32 == 4
		else if (table != NULL &&
		    (iocp->ioc_flag & IOC_MODELS) == IOC_ILP32) {
			ip6_asp_t *src = table;
			ip6_asp32_t *dst = (void *)table;
			int count = table_size / sizeof (ip6_asp_t);
			int i;

			/*
			 * We need to do an in-place shrink of the array
			 * to match the alignment attributes of the
			 * 32-bit ABI looking at it.
			 */
			/* LINTED: logical expression always true: op "||" */
			ASSERT(sizeof (*src) > sizeof (*dst));
			for (i = 1; i < count; i++)
				bcopy(src + i, dst + i, sizeof (*dst));
		}
#endif
		break;

	case SIOCSIP6ADDRPOLICY:
		ASSERT(mp->b_prev == NULL);
		mp->b_prev = (void *)q;
#if defined(_SYSCALL32_IMPL) && _LONG_LONG_ALIGNMENT_32 == 4
		/*
		 * We pass in the datamodel here so that the ip6_asp_replace()
		 * routine can handle converting from 32-bit to native formats
		 * where necessary.
		 *
		 * A better way to handle this might be to convert the inbound
		 * data structure here, and hang it off a new 'mp'; thus the
		 * ip6_asp_replace() logic would always be dealing with native
		 * format data structures..
		 *
		 * (An even simpler way to handle these ioctls is to just
		 * add a 32-bit trailing 'pad' field to the ip6_asp_t structure
		 * and just recompile everything that depends on it.)
		 */
#endif
		ip6_asp_replace(mp, table, table_size, B_FALSE, ipst,
		    iocp->ioc_flag & IOC_MODELS);
		return;
	}

	DB_TYPE(mp) =  (iocp->ioc_error == 0) ? M_IOCACK : M_IOCNAK;
	qreply(q, mp);
}

static void
ip_sioctl_dstinfo(queue_t *q, mblk_t *mp)
{
	mblk_t 		*data_mp;
	struct dstinforeq	*dir;
	uint8_t		*end, *cur;
	in6_addr_t	*daddr, *saddr;
	ipaddr_t	v4daddr;
	ire_t		*ire;
	char		*slabel, *dlabel;
	boolean_t	isipv4;
	int		match_ire;
	ill_t		*dst_ill;
	ipif_t		*src_ipif, *ire_ipif;
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	zoneid_t	zoneid;
	ip_stack_t	*ipst = CONNQ_TO_IPST(q);

	ASSERT(q->q_next == NULL); /* this ioctl not allowed if ip is module */
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/*
	 * This ioctl is I_STR only, and must have a
	 * data mblk following the M_IOCTL mblk.
	 */
	data_mp = mp->b_cont;
	if (iocp->ioc_count == TRANSPARENT || data_mp == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	if (MBLKL(data_mp) < iocp->ioc_count) {
		mblk_t *new_data_mp;

		if ((new_data_mp = msgpullup(data_mp, -1)) == NULL) {
			miocnak(q, mp, 0, ENOMEM);
			return;
		}
		freemsg(data_mp);
		data_mp = new_data_mp;
		mp->b_cont = data_mp;
	}
	match_ire = MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT | MATCH_IRE_PARENT;

	for (cur = data_mp->b_rptr, end = data_mp->b_wptr;
	    end - cur >= sizeof (struct dstinforeq);
	    cur += sizeof (struct dstinforeq)) {
		dir = (struct dstinforeq *)cur;
		daddr = &dir->dir_daddr;
		saddr = &dir->dir_saddr;

		/*
		 * ip_addr_scope_v6() and ip6_asp_lookup() handle
		 * v4 mapped addresses; ire_ftable_lookup[_v6]()
		 * and ipif_select_source[_v6]() do not.
		 */
		dir->dir_dscope = ip_addr_scope_v6(daddr);
		dlabel = ip6_asp_lookup(daddr, &dir->dir_precedence, ipst);

		isipv4 = IN6_IS_ADDR_V4MAPPED(daddr);
		if (isipv4) {
			IN6_V4MAPPED_TO_IPADDR(daddr, v4daddr);
			ire = ire_ftable_lookup(v4daddr, NULL, NULL,
			    0, NULL, NULL, zoneid, 0, NULL, match_ire, ipst);
		} else {
			ire = ire_ftable_lookup_v6(daddr, NULL, NULL,
			    0, NULL, NULL, zoneid, 0, NULL, match_ire, ipst);
		}
		if (ire == NULL) {
			dir->dir_dreachable = 0;

			/* move on to next dst addr */
			continue;
		}
		dir->dir_dreachable = 1;

		ire_ipif = ire->ire_ipif;
		if (ire_ipif == NULL)
			goto next_dst;

		/*
		 * We expect to get back an interface ire or a
		 * gateway ire cache entry.  For both types, the
		 * output interface is ire_ipif->ipif_ill.
		 */
		dst_ill = ire_ipif->ipif_ill;
		dir->dir_dmactype = dst_ill->ill_mactype;

		if (isipv4) {
			src_ipif = ipif_select_source(dst_ill, v4daddr, zoneid);
		} else {
			src_ipif = ipif_select_source_v6(dst_ill,
			    daddr, B_FALSE, IPV6_PREFER_SRC_DEFAULT, zoneid);
		}
		if (src_ipif == NULL)
			goto next_dst;

		*saddr = src_ipif->ipif_v6lcl_addr;
		dir->dir_sscope = ip_addr_scope_v6(saddr);
		slabel = ip6_asp_lookup(saddr, NULL, ipst);
		dir->dir_labelmatch = ip6_asp_labelcmp(dlabel, slabel);
		dir->dir_sdeprecated =
		    (src_ipif->ipif_flags & IPIF_DEPRECATED) ? 1 : 0;
		ipif_refrele(src_ipif);
next_dst:
		ire_refrele(ire);
	}
	miocack(q, mp, iocp->ioc_count, 0);
}

/*
 * Check if this is an address assigned to this machine.
 * Skips interfaces that are down by using ire checks.
 * Translates mapped addresses to v4 addresses and then
 * treats them as such, returning true if the v4 address
 * associated with this mapped address is configured.
 * Note: Applications will have to be careful what they do
 * with the response; use of mapped addresses limits
 * what can be done with the socket, especially with
 * respect to socket options and ioctls - neither IPv4
 * options nor IPv6 sticky options/ancillary data options
 * may be used.
 */
/* ARGSUSED */
int
ip_sioctl_tmyaddr(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	struct sioc_addrreq *sia;
	sin_t *sin;
	ire_t *ire;
	mblk_t *mp1;
	zoneid_t zoneid;
	ip_stack_t	*ipst;

	ip1dbg(("ip_sioctl_tmyaddr"));

	ASSERT(q->q_next == NULL); /* this ioctl not allowed if ip is module */
	zoneid = Q_TO_CONN(q)->conn_zoneid;
	ipst = CONNQ_TO_IPST(q);

	/* Existence verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	sia = (struct sioc_addrreq *)mp1->b_rptr;
	sin = (sin_t *)&sia->sa_addr;
	switch (sin->sin_family) {
	case AF_INET6: {
		sin6_t *sin6 = (sin6_t *)sin;

		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			ipaddr_t v4_addr;

			IN6_V4MAPPED_TO_IPADDR(&sin6->sin6_addr,
			    v4_addr);
			ire = ire_ctable_lookup(v4_addr, 0,
			    IRE_LOCAL|IRE_LOOPBACK, NULL, zoneid,
			    NULL, MATCH_IRE_TYPE | MATCH_IRE_ZONEONLY, ipst);
		} else {
			in6_addr_t v6addr;

			v6addr = sin6->sin6_addr;
			ire = ire_ctable_lookup_v6(&v6addr, 0,
			    IRE_LOCAL|IRE_LOOPBACK, NULL, zoneid,
			    NULL, MATCH_IRE_TYPE | MATCH_IRE_ZONEONLY, ipst);
		}
		break;
	}
	case AF_INET: {
		ipaddr_t v4addr;

		v4addr = sin->sin_addr.s_addr;
		ire = ire_ctable_lookup(v4addr, 0,
		    IRE_LOCAL|IRE_LOOPBACK, NULL, zoneid,
		    NULL, MATCH_IRE_TYPE | MATCH_IRE_ZONEONLY, ipst);
		break;
	}
	default:
		return (EAFNOSUPPORT);
	}
	if (ire != NULL) {
		sia->sa_res = 1;
		ire_refrele(ire);
	} else {
		sia->sa_res = 0;
	}
	return (0);
}

/*
 * Check if this is an address assigned on-link i.e. neighbor,
 * and makes sure it's reachable from the current zone.
 * Returns true for my addresses as well.
 * Translates mapped addresses to v4 addresses and then
 * treats them as such, returning true if the v4 address
 * associated with this mapped address is configured.
 * Note: Applications will have to be careful what they do
 * with the response; use of mapped addresses limits
 * what can be done with the socket, especially with
 * respect to socket options and ioctls - neither IPv4
 * options nor IPv6 sticky options/ancillary data options
 * may be used.
 */
/* ARGSUSED */
int
ip_sioctl_tonlink(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *duymmy_ifreq)
{
	struct sioc_addrreq *sia;
	sin_t *sin;
	mblk_t	*mp1;
	ire_t *ire = NULL;
	zoneid_t zoneid;
	ip_stack_t	*ipst;

	ip1dbg(("ip_sioctl_tonlink"));

	ASSERT(q->q_next == NULL); /* this ioctl not allowed if ip is module */
	zoneid = Q_TO_CONN(q)->conn_zoneid;
	ipst = CONNQ_TO_IPST(q);

	/* Existence verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	sia = (struct sioc_addrreq *)mp1->b_rptr;
	sin = (sin_t *)&sia->sa_addr;

	/*
	 * Match addresses with a zero gateway field to avoid
	 * routes going through a router.
	 * Exclude broadcast and multicast addresses.
	 */
	switch (sin->sin_family) {
	case AF_INET6: {
		sin6_t *sin6 = (sin6_t *)sin;

		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			ipaddr_t v4_addr;

			IN6_V4MAPPED_TO_IPADDR(&sin6->sin6_addr,
			    v4_addr);
			if (!CLASSD(v4_addr)) {
				ire = ire_route_lookup(v4_addr, 0, 0, 0,
				    NULL, NULL, zoneid, NULL,
				    MATCH_IRE_GW, ipst);
			}
		} else {
			in6_addr_t v6addr;
			in6_addr_t v6gw;

			v6addr = sin6->sin6_addr;
			v6gw = ipv6_all_zeros;
			if (!IN6_IS_ADDR_MULTICAST(&v6addr)) {
				ire = ire_route_lookup_v6(&v6addr, 0,
				    &v6gw, 0, NULL, NULL, zoneid,
				    NULL, MATCH_IRE_GW, ipst);
			}
		}
		break;
	}
	case AF_INET: {
		ipaddr_t v4addr;

		v4addr = sin->sin_addr.s_addr;
		if (!CLASSD(v4addr)) {
			ire = ire_route_lookup(v4addr, 0, 0, 0,
			    NULL, NULL, zoneid, NULL,
			    MATCH_IRE_GW, ipst);
		}
		break;
	}
	default:
		return (EAFNOSUPPORT);
	}
	sia->sa_res = 0;
	if (ire != NULL) {
		if (ire->ire_type & (IRE_INTERFACE|IRE_CACHE|
		    IRE_LOCAL|IRE_LOOPBACK)) {
			sia->sa_res = 1;
		}
		ire_refrele(ire);
	}
	return (0);
}

/*
 * TBD: implement when kernel maintaines a list of site prefixes.
 */
/* ARGSUSED */
int
ip_sioctl_tmysite(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	return (ENXIO);
}

/* ARGSUSED */
int
ip_sioctl_tunparam(ipif_t *ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	ill_t		*ill;
	mblk_t		*mp1;
	conn_t		*connp;
	boolean_t	success;

	ip1dbg(("ip_sioctl_tunparam(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	/* ioctl comes down on an conn */
	ASSERT(!(q->q_flag & QREADR) && q->q_next == NULL);
	connp = Q_TO_CONN(q);

	mp->b_datap->db_type = M_IOCTL;

	/*
	 * Send down a copy. (copymsg does not copy b_next/b_prev).
	 * The original mp contains contaminated b_next values due to 'mi',
	 * which is needed to do the mi_copy_done. Unfortunately if we
	 * send down the original mblk itself and if we are popped due to an
	 * an unplumb before the response comes back from tunnel,
	 * the streamhead (which does a freemsg) will see this contaminated
	 * message and the assertion in freemsg about non-null b_next/b_prev
	 * will panic a DEBUG kernel.
	 */
	mp1 = copymsg(mp);
	if (mp1 == NULL)
		return (ENOMEM);

	ill = ipif->ipif_ill;
	mutex_enter(&connp->conn_lock);
	mutex_enter(&ill->ill_lock);
	if (ipip->ipi_cmd == SIOCSTUNPARAM || ipip->ipi_cmd == OSIOCSTUNPARAM) {
		success = ipsq_pending_mp_add(connp, ipif, CONNP_TO_WQ(connp),
		    mp, 0);
	} else {
		success = ill_pending_mp_add(ill, connp, mp);
	}
	mutex_exit(&ill->ill_lock);
	mutex_exit(&connp->conn_lock);

	if (success) {
		ip1dbg(("sending down tunparam request "));
		putnext(ill->ill_wq, mp1);
		return (EINPROGRESS);
	} else {
		/* The conn has started closing */
		freemsg(mp1);
		return (EINTR);
	}
}

/*
 * ARP IOCTLs.
 * How does IP get in the business of fronting ARP configuration/queries?
 * Well it's like this, the Berkeley ARP IOCTLs (SIOCGARP, SIOCDARP, SIOCSARP)
 * are by tradition passed in through a datagram socket.  That lands in IP.
 * As it happens, this is just as well since the interface is quite crude in
 * that it passes in no information about protocol or hardware types, or
 * interface association.  After making the protocol assumption, IP is in
 * the position to look up the name of the ILL, which ARP will need, and
 * format a request that can be handled by ARP.  The request is passed up
 * stream to ARP, and the original IOCTL is completed by IP when ARP passes
 * back a response.  ARP supports its own set of more general IOCTLs, in
 * case anyone is interested.
 */
/* ARGSUSED */
int
ip_sioctl_arp(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	mblk_t *mp1;
	mblk_t *mp2;
	mblk_t *pending_mp;
	ipaddr_t ipaddr;
	area_t *area;
	struct iocblk *iocp;
	conn_t *connp;
	struct arpreq *ar;
	struct xarpreq *xar;
	int flags, alength;
	uchar_t *lladdr;
	ire_t *ire;
	ip_stack_t *ipst;
	ill_t *ill = ipif->ipif_ill;
	ill_t *proxy_ill = NULL;
	ipmp_arpent_t *entp = NULL;
	boolean_t if_arp_ioctl = B_FALSE;
	boolean_t proxyarp = B_FALSE;

	ASSERT(!(q->q_flag & QREADR) && q->q_next == NULL);
	connp = Q_TO_CONN(q);
	ipst = connp->conn_netstack->netstack_ip;

	if (ipip->ipi_cmd_type == XARP_CMD) {
		/* We have a chain - M_IOCTL-->MI_COPY_MBLK-->XARPREQ_MBLK */
		xar = (struct xarpreq *)mp->b_cont->b_cont->b_rptr;
		ar = NULL;

		flags = xar->xarp_flags;
		lladdr = (uchar_t *)LLADDR(&xar->xarp_ha);
		if_arp_ioctl = (xar->xarp_ha.sdl_nlen != 0);
		/*
		 * Validate against user's link layer address length
		 * input and name and addr length limits.
		 */
		alength = ill->ill_phys_addr_length;
		if (ipip->ipi_cmd == SIOCSXARP) {
			if (alength != xar->xarp_ha.sdl_alen ||
			    (alength + xar->xarp_ha.sdl_nlen >
			    sizeof (xar->xarp_ha.sdl_data)))
				return (EINVAL);
		}
	} else {
		/* We have a chain - M_IOCTL-->MI_COPY_MBLK-->ARPREQ_MBLK */
		ar = (struct arpreq *)mp->b_cont->b_cont->b_rptr;
		xar = NULL;

		flags = ar->arp_flags;
		lladdr = (uchar_t *)ar->arp_ha.sa_data;
		/*
		 * Theoretically, the sa_family could tell us what link
		 * layer type this operation is trying to deal with. By
		 * common usage AF_UNSPEC means ethernet. We'll assume
		 * any attempt to use the SIOC?ARP ioctls is for ethernet,
		 * for now. Our new SIOC*XARP ioctls can be used more
		 * generally.
		 *
		 * If the underlying media happens to have a non 6 byte
		 * address, arp module will fail set/get, but the del
		 * operation will succeed.
		 */
		alength = 6;
		if ((ipip->ipi_cmd != SIOCDARP) &&
		    (alength != ill->ill_phys_addr_length)) {
			return (EINVAL);
		}
	}

	ipaddr = sin->sin_addr.s_addr;

	/*
	 * IPMP ARP special handling:
	 *
	 * 1. Since ARP mappings must appear consistent across the group,
	 *    prohibit changing ARP mappings on the underlying interfaces.
	 *
	 * 2. Since ARP mappings for IPMP data addresses are maintained by
	 *    IP itself, prohibit changing them.
	 *
	 * 3. For proxy ARP, use a functioning hardware address in the group,
	 *    provided one exists.  If one doesn't, just add the entry as-is;
	 *    ipmp_illgrp_refresh_arpent() will refresh it if things change.
	 */
	if (IS_UNDER_IPMP(ill)) {
		if (ipip->ipi_cmd != SIOCGARP && ipip->ipi_cmd != SIOCGXARP)
			return (EPERM);
	}
	if (IS_IPMP(ill)) {
		ipmp_illgrp_t *illg = ill->ill_grp;

		switch (ipip->ipi_cmd) {
		case SIOCSARP:
		case SIOCSXARP:
			proxy_ill = ipmp_illgrp_find_ill(illg, lladdr, alength);
			if (proxy_ill != NULL) {
				proxyarp = B_TRUE;
				if (!ipmp_ill_is_active(proxy_ill))
					proxy_ill = ipmp_illgrp_next_ill(illg);
				if (proxy_ill != NULL)
					lladdr = proxy_ill->ill_phys_addr;
			}
			/* FALLTHRU */
		case SIOCDARP:
		case SIOCDXARP:
			ire = ire_ctable_lookup(ipaddr, 0, IRE_LOCAL, NULL,
			    ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (ire != NULL) {
				ire_refrele(ire);
				return (EPERM);
			}
		}
	}

	/*
	 * We are going to pass up to ARP a packet chain that looks
	 * like:
	 *
	 * M_IOCTL-->ARP_op_MBLK-->ORIG_M_IOCTL-->MI_COPY_MBLK-->[X]ARPREQ_MBLK
	 *
	 * Get a copy of the original IOCTL mblk to head the chain,
	 * to be sent up (in mp1). Also get another copy to store
	 * in the ill_pending_mp list, for matching the response
	 * when it comes back from ARP.
	 */
	mp1 = copyb(mp);
	pending_mp = copymsg(mp);
	if (mp1 == NULL || pending_mp == NULL) {
		if (mp1 != NULL)
			freeb(mp1);
		if (pending_mp != NULL)
			inet_freemsg(pending_mp);
		return (ENOMEM);
	}

	mp2 = ill_arp_alloc(ill, (uchar_t *)&ip_area_template,
	    (caddr_t)&ipaddr);
	if (mp2 == NULL) {
		freeb(mp1);
		inet_freemsg(pending_mp);
		return (ENOMEM);
	}
	/* Put together the chain. */
	mp1->b_cont = mp2;
	mp1->b_datap->db_type = M_IOCTL;
	mp2->b_cont = mp;
	mp2->b_datap->db_type = M_DATA;

	iocp = (struct iocblk *)mp1->b_rptr;

	/*
	 * An M_IOCDATA's payload (struct copyresp) is mostly the same as an
	 * M_IOCTL's payload (struct iocblk), but 'struct copyresp' has a
	 * cp_private field (or cp_rval on 32-bit systems) in place of the
	 * ioc_count field; set ioc_count to be correct.
	 */
	iocp->ioc_count = MBLKL(mp1->b_cont);

	/*
	 * Set the proper command in the ARP message.
	 * Convert the SIOC{G|S|D}ARP calls into our
	 * AR_ENTRY_xxx calls.
	 */
	area = (area_t *)mp2->b_rptr;
	switch (iocp->ioc_cmd) {
	case SIOCDARP:
	case SIOCDXARP:
		/*
		 * We defer deleting the corresponding IRE until
		 * we return from arp.
		 */
		area->area_cmd = AR_ENTRY_DELETE;
		area->area_proto_mask_offset = 0;
		break;
	case SIOCGARP:
	case SIOCGXARP:
		area->area_cmd = AR_ENTRY_SQUERY;
		area->area_proto_mask_offset = 0;
		break;
	case SIOCSARP:
	case SIOCSXARP:
		/*
		 * Delete the corresponding ire to make sure IP will
		 * pick up any change from arp.
		 */
		if (!if_arp_ioctl) {
			(void) ip_ire_clookup_and_delete(ipaddr, NULL, ipst);
		} else {
			ipif_t *ipif = ipif_get_next_ipif(NULL, ill);
			if (ipif != NULL) {
				(void) ip_ire_clookup_and_delete(ipaddr, ipif,
				    ipst);
				ipif_refrele(ipif);
			}
		}
		break;
	}
	iocp->ioc_cmd = area->area_cmd;

	/*
	 * Fill in the rest of the ARP operation fields.
	 */
	area->area_hw_addr_length = alength;
	bcopy(lladdr, (char *)area + area->area_hw_addr_offset, alength);

	/* Translate the flags. */
	if (flags & ATF_PERM)
		area->area_flags |= ACE_F_PERMANENT;
	if (flags & ATF_PUBL)
		area->area_flags |= ACE_F_PUBLISH;
	if (flags & ATF_AUTHORITY)
		area->area_flags |= ACE_F_AUTHORITY;

	/*
	 * If this is a permanent AR_ENTRY_ADD on the IPMP interface, track it
	 * so that IP can update ARP as the active ills in the group change.
	 */
	if (IS_IPMP(ill) && area->area_cmd == AR_ENTRY_ADD &&
	    (area->area_flags & ACE_F_PERMANENT)) {
		entp = ipmp_illgrp_create_arpent(ill->ill_grp, mp2, proxyarp);

		/*
		 * The second part of the conditional below handles a corner
		 * case: if this is proxy ARP and the IPMP group has no active
		 * interfaces, we can't send the request to ARP now since it
		 * won't be able to build an ACE.  So we return success and
		 * notify ARP about the proxy ARP entry once an interface
		 * becomes active.
		 */
		if (entp == NULL || (proxyarp && proxy_ill == NULL)) {
			mp2->b_cont = NULL;
			inet_freemsg(mp1);
			inet_freemsg(pending_mp);
			return (entp == NULL ? ENOMEM : 0);
		}
	}

	/*
	 * Before sending 'mp' to ARP, we have to clear the b_next
	 * and b_prev. Otherwise if STREAMS encounters such a message
	 * in freemsg(), (because ARP can close any time) it can cause
	 * a panic. But mi code needs the b_next and b_prev values of
	 * mp->b_cont, to complete the ioctl. So we store it here
	 * in pending_mp->bcont, and restore it in ip_sioctl_iocack()
	 * when the response comes down from ARP.
	 */
	pending_mp->b_cont->b_next = mp->b_cont->b_next;
	pending_mp->b_cont->b_prev = mp->b_cont->b_prev;
	mp->b_cont->b_next = NULL;
	mp->b_cont->b_prev = NULL;

	mutex_enter(&connp->conn_lock);
	mutex_enter(&ill->ill_lock);
	/* conn has not yet started closing, hence this can't fail */
	if (ipip->ipi_flags & IPI_WR) {
		VERIFY(ipsq_pending_mp_add(connp, ipif, CONNP_TO_WQ(connp),
		    pending_mp, 0) != 0);
	} else {
		VERIFY(ill_pending_mp_add(ill, connp, pending_mp) != 0);
	}
	mutex_exit(&ill->ill_lock);
	mutex_exit(&connp->conn_lock);

	/*
	 * Up to ARP it goes.  The response will come back in ip_wput() as an
	 * M_IOCACK, and will be handed to ip_sioctl_iocack() for completion.
	 */
	putnext(ill->ill_rq, mp1);

	/*
	 * If we created an IPMP ARP entry, mark that we've notified ARP.
	 */
	if (entp != NULL)
		ipmp_illgrp_mark_arpent(ill->ill_grp, entp);

	return (EINPROGRESS);
}

/*
 * Parse an [x]arpreq structure coming down SIOC[GSD][X]ARP ioctls, identify
 * the associated sin and refhold and return the associated ipif via `ci'.
 */
int
ip_extract_arpreq(queue_t *q, mblk_t *mp, const ip_ioctl_cmd_t *ipip,
    cmd_info_t *ci, ipsq_func_t func)
{
	mblk_t	*mp1;
	int	err;
	sin_t	*sin;
	conn_t	*connp;
	ipif_t	*ipif;
	ire_t	*ire = NULL;
	ill_t	*ill = NULL;
	boolean_t exists;
	ip_stack_t *ipst;
	struct arpreq *ar;
	struct xarpreq *xar;
	struct sockaddr_dl *sdl;

	/* ioctl comes down on a conn */
	ASSERT(!(q->q_flag & QREADR) && q->q_next == NULL);
	connp = Q_TO_CONN(q);
	if (connp->conn_af_isv6)
		return (ENXIO);

	ipst = connp->conn_netstack->netstack_ip;

	/* Verified in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;

	if (ipip->ipi_cmd_type == XARP_CMD) {
		ASSERT(MBLKL(mp1) >= sizeof (struct xarpreq));
		xar = (struct xarpreq *)mp1->b_rptr;
		sin = (sin_t *)&xar->xarp_pa;
		sdl = &xar->xarp_ha;

		if (sdl->sdl_family != AF_LINK || sin->sin_family != AF_INET)
			return (ENXIO);
		if (sdl->sdl_nlen >= LIFNAMSIZ)
			return (EINVAL);
	} else {
		ASSERT(ipip->ipi_cmd_type == ARP_CMD);
		ASSERT(MBLKL(mp1) >= sizeof (struct arpreq));
		ar = (struct arpreq *)mp1->b_rptr;
		sin = (sin_t *)&ar->arp_pa;
	}

	if (ipip->ipi_cmd_type == XARP_CMD && sdl->sdl_nlen != 0) {
		ipif = ipif_lookup_on_name(sdl->sdl_data, sdl->sdl_nlen,
		    B_FALSE, &exists, B_FALSE, ALL_ZONES, CONNP_TO_WQ(connp),
		    mp, func, &err, ipst);
		if (ipif == NULL)
			return (err);
		if (ipif->ipif_id != 0) {
			ipif_refrele(ipif);
			return (ENXIO);
		}
	} else {
		/*
		 * Either an SIOC[DGS]ARP or an SIOC[DGS]XARP with an sdl_nlen
		 * of 0: use the IP address to find the ipif.  If the IP
		 * address is an IPMP test address, ire_ftable_lookup() will
		 * find the wrong ill, so we first do an ipif_lookup_addr().
		 */
		ipif = ipif_lookup_addr(sin->sin_addr.s_addr, NULL, ALL_ZONES,
		    CONNP_TO_WQ(connp), mp, func, &err, ipst);
		if (ipif == NULL) {
			ire = ire_ftable_lookup(sin->sin_addr.s_addr, 0, 0,
			    IRE_IF_RESOLVER, NULL, NULL, ALL_ZONES, 0, NULL,
			    MATCH_IRE_TYPE, ipst);
			if (ire == NULL || ((ill = ire_to_ill(ire)) == NULL)) {
				if (ire != NULL)
					ire_refrele(ire);
				return (ENXIO);
			}
			ipif = ill->ill_ipif;
			ipif_refhold(ipif);
			ire_refrele(ire);
		}
	}

	if (ipif->ipif_net_type != IRE_IF_RESOLVER) {
		ipif_refrele(ipif);
		return (ENXIO);
	}

	ci->ci_sin = sin;
	ci->ci_ipif = ipif;
	return (0);
}

/*
 * Link or unlink the illgrp on IPMP meta-interface `ill' depending on the
 * value of `ioccmd'.  While an illgrp is linked to an ipmp_grp_t, it is
 * accessible from that ipmp_grp_t, which means SIOCSLIFGROUPNAME can look it
 * up and thus an ill can join that illgrp.
 *
 * We use I_PLINK/I_PUNLINK to do the link/unlink operations rather than
 * open()/close() primarily because close() is not allowed to fail or block
 * forever.  On the other hand, I_PUNLINK *can* fail, and there's no reason
 * why anyone should ever need to I_PUNLINK an in-use IPMP stream.  To ensure
 * symmetric behavior (e.g., doing an I_PLINK after and I_PUNLINK undoes the
 * I_PUNLINK) we defer linking to I_PLINK.  Separately, we also fail attempts
 * to I_LINK since I_UNLINK is optional and we'd end up in an inconsistent
 * state if I_UNLINK didn't occur.
 *
 * Note that for each plumb/unplumb operation, we may end up here more than
 * once because of the way ifconfig works.  However, it's OK to link the same
 * illgrp more than once, or unlink an illgrp that's already unlinked.
 */
static int
ip_sioctl_plink_ipmp(ill_t *ill, int ioccmd)
{
	int err;
	ip_stack_t *ipst = ill->ill_ipst;

	ASSERT(IS_IPMP(ill));
	ASSERT(IAM_WRITER_ILL(ill));

	switch (ioccmd) {
	case I_LINK:
		return (ENOTSUP);

	case I_PLINK:
		rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
		ipmp_illgrp_link_grp(ill->ill_grp, ill->ill_phyint->phyint_grp);
		rw_exit(&ipst->ips_ipmp_lock);
		break;

	case I_PUNLINK:
		/*
		 * Require all UP ipifs be brought down prior to unlinking the
		 * illgrp so any associated IREs (and other state) is torched.
		 */
		if (ill->ill_ipif_up_count + ill->ill_ipif_dup_count > 0)
			return (EBUSY);

		/*
		 * NOTE: We hold ipmp_lock across the unlink to prevent a race
		 * with an SIOCSLIFGROUPNAME request from an ill trying to
		 * join this group.  Specifically: ills trying to join grab
		 * ipmp_lock and bump a "pending join" counter checked by
		 * ipmp_illgrp_unlink_grp().  During the unlink no new pending
		 * joins can occur (since we have ipmp_lock).  Once we drop
		 * ipmp_lock, subsequent SIOCSLIFGROUPNAME requests will not
		 * find the illgrp (since we unlinked it) and will return
		 * EAFNOSUPPORT.  This will then take them back through the
		 * IPMP meta-interface plumbing logic in ifconfig, and thus
		 * back through I_PLINK above.
		 */
		rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
		err = ipmp_illgrp_unlink_grp(ill->ill_grp);
		rw_exit(&ipst->ips_ipmp_lock);
		return (err);
	default:
		break;
	}
	return (0);
}

/*
 * Do I_PLINK/I_LINK or I_PUNLINK/I_UNLINK with consistency checks and also
 * atomically set/clear the muxids. Also complete the ioctl by acking or
 * naking it.  Note that the code is structured such that the link type,
 * whether it's persistent or not, is treated equally.  ifconfig(1M) and
 * its clones use the persistent link, while pppd(1M) and perhaps many
 * other daemons may use non-persistent link.  When combined with some
 * ill_t states, linking and unlinking lower streams may be used as
 * indicators of dynamic re-plumbing events [see PSARC/1999/348].
 */
/* ARGSUSED */
void
ip_sioctl_plink(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	mblk_t		*mp1, *mp2;
	struct linkblk	*li;
	struct ipmx_s	*ipmxp;
	ill_t		*ill;
	int		ioccmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
	int		err = 0;
	boolean_t	entered_ipsq = B_FALSE;
	boolean_t	islink;
	ip_stack_t	*ipst;

	if (CONN_Q(q))
		ipst = CONNQ_TO_IPST(q);
	else
		ipst = ILLQ_TO_IPST(q);

	ASSERT(ioccmd == I_PLINK || ioccmd == I_PUNLINK ||
	    ioccmd == I_LINK || ioccmd == I_UNLINK);

	islink = (ioccmd == I_PLINK || ioccmd == I_LINK);

	mp1 = mp->b_cont;	/* This is the linkblk info */
	li = (struct linkblk *)mp1->b_rptr;

	/*
	 * ARP has added this special mblk, and the utility is asking us
	 * to perform consistency checks, and also atomically set the
	 * muxid. Ifconfig is an example.  It achieves this by using
	 * /dev/arp as the mux to plink the arp stream, and pushes arp on
	 * to /dev/udp[6] stream for use as the mux when plinking the IP
	 * stream. SIOCSLIFMUXID is not required.  See ifconfig.c, arp.c
	 * and other comments in this routine for more details.
	 */
	mp2 = mp1->b_cont;	/* This is added by ARP */

	/*
	 * If I_{P}LINK/I_{P}UNLINK is issued by a utility other than
	 * ifconfig which didn't push ARP on top of the dummy mux, we won't
	 * get the special mblk above.  For backward compatibility, we
	 * request ip_sioctl_plink_ipmod() to skip the consistency checks.
	 * The utility will use SIOCSLIFMUXID to store the muxids.  This is
	 * not atomic, and can leave the streams unplumbable if the utility
	 * is interrupted before it does the SIOCSLIFMUXID.
	 */
	if (mp2 == NULL) {
		err = ip_sioctl_plink_ipmod(ipsq, q, mp, ioccmd, li, B_FALSE);
		if (err == EINPROGRESS)
			return;
		goto done;
	}

	/*
	 * This is an I_{P}LINK sent down by ifconfig through the ARP module;
	 * ARP has appended this last mblk to tell us whether the lower stream
	 * is an arp-dev stream or an IP module stream.
	 */
	ipmxp = (struct ipmx_s *)mp2->b_rptr;
	if (ipmxp->ipmx_arpdev_stream) {
		/*
		 * The lower stream is the arp-dev stream.
		 */
		ill = ill_lookup_on_name(ipmxp->ipmx_name, B_FALSE, B_FALSE,
		    q, mp, ip_sioctl_plink, &err, NULL, ipst);
		if (ill == NULL) {
			if (err == EINPROGRESS)
				return;
			err = EINVAL;
			goto done;
		}

		if (ipsq == NULL) {
			ipsq = ipsq_try_enter(NULL, ill, q, mp, ip_sioctl_plink,
			    NEW_OP, B_FALSE);
			if (ipsq == NULL) {
				ill_refrele(ill);
				return;
			}
			entered_ipsq = B_TRUE;
		}
		ASSERT(IAM_WRITER_ILL(ill));
		ill_refrele(ill);

		/*
		 * To ensure consistency between IP and ARP, the following
		 * LIFO scheme is used in plink/punlink. (IP first, ARP last).
		 * This is because the muxid's are stored in the IP stream on
		 * the ill.
		 *
		 * I_{P}LINK: ifconfig plinks the IP stream before plinking
		 * the ARP stream. On an arp-dev stream, IP checks that it is
		 * not yet plinked, and it also checks that the corresponding
		 * IP stream is already plinked.
		 *
		 * I_{P}UNLINK: ifconfig punlinks the ARP stream before
		 * punlinking the IP stream. IP does not allow punlink of the
		 * IP stream unless the arp stream has been punlinked.
		 */
		if ((islink &&
		    (ill->ill_arp_muxid != 0 || ill->ill_ip_muxid == 0)) ||
		    (!islink && ill->ill_arp_muxid != li->l_index)) {
			err = EINVAL;
			goto done;
		}

		if (IS_IPMP(ill) &&
		    (err = ip_sioctl_plink_ipmp(ill, ioccmd)) != 0)
			goto done;

		ill->ill_arp_muxid = islink ? li->l_index : 0;
	} else {
		/*
		 * The lower stream is probably an IP module stream.  Do
		 * consistency checking.
		 */
		err = ip_sioctl_plink_ipmod(ipsq, q, mp, ioccmd, li, B_TRUE);
		if (err == EINPROGRESS)
			return;
	}
done:
	if (err == 0)
		miocack(q, mp, 0, 0);
	else
		miocnak(q, mp, 0, err);

	/* Conn was refheld in ip_sioctl_copyin_setup */
	if (CONN_Q(q))
		CONN_OPER_PENDING_DONE(Q_TO_CONN(q));
	if (entered_ipsq)
		ipsq_exit(ipsq);
}

/*
 * Process I_{P}LINK and I_{P}UNLINK requests named by `ioccmd' and pointed to
 * by `mp' and `li' for the IP module stream (if li->q_bot is in fact an IP
 * module stream).  If `doconsist' is set, then do the extended consistency
 * checks requested by ifconfig(1M) and (atomically) set ill_ip_muxid here.
 * Returns zero on success, EINPROGRESS if the operation is still pending, or
 * an error code on failure.
 */
static int
ip_sioctl_plink_ipmod(ipsq_t *ipsq, queue_t *q, mblk_t *mp, int ioccmd,
    struct linkblk *li, boolean_t doconsist)
{
	int		err = 0;
	ill_t  		*ill;
	queue_t		*ipwq, *dwq;
	const char	*name;
	struct qinit	*qinfo;
	boolean_t	islink = (ioccmd == I_PLINK || ioccmd == I_LINK);
	boolean_t	entered_ipsq = B_FALSE;

	/*
	 * Walk the lower stream to verify it's the IP module stream.
	 * The IP module is identified by its name, wput function,
	 * and non-NULL q_next.  STREAMS ensures that the lower stream
	 * (li->l_qbot) will not vanish until this ioctl completes.
	 */
	for (ipwq = li->l_qbot; ipwq != NULL; ipwq = ipwq->q_next) {
		qinfo = ipwq->q_qinfo;
		name = qinfo->qi_minfo->mi_idname;
		if (name != NULL && strcmp(name, ip_mod_info.mi_idname) == 0 &&
		    qinfo->qi_putp != (pfi_t)ip_lwput && ipwq->q_next != NULL) {
			break;
		}
	}

	/*
	 * If this isn't an IP module stream, bail.
	 */
	if (ipwq == NULL)
		return (0);

	ill = ipwq->q_ptr;
	ASSERT(ill != NULL);

	if (ipsq == NULL) {
		ipsq = ipsq_try_enter(NULL, ill, q, mp, ip_sioctl_plink,
		    NEW_OP, B_FALSE);
		if (ipsq == NULL)
			return (EINPROGRESS);
		entered_ipsq = B_TRUE;
	}
	ASSERT(IAM_WRITER_ILL(ill));

	if (doconsist) {
		/*
		 * Consistency checking requires that I_{P}LINK occurs
		 * prior to setting ill_ip_muxid, and that I_{P}UNLINK
		 * occurs prior to clearing ill_arp_muxid.
		 */
		if ((islink && ill->ill_ip_muxid != 0) ||
		    (!islink && ill->ill_arp_muxid != 0)) {
			err = EINVAL;
			goto done;
		}
	}

	if (IS_IPMP(ill) && (err = ip_sioctl_plink_ipmp(ill, ioccmd)) != 0)
		goto done;

	/*
	 * As part of I_{P}LINKing, stash the number of downstream modules and
	 * the read queue of the module immediately below IP in the ill.
	 * These are used during the capability negotiation below.
	 */
	ill->ill_lmod_rq = NULL;
	ill->ill_lmod_cnt = 0;
	if (islink && ((dwq = ipwq->q_next) != NULL)) {
		ill->ill_lmod_rq = RD(dwq);
		for (; dwq != NULL; dwq = dwq->q_next)
			ill->ill_lmod_cnt++;
	}

	if (doconsist)
		ill->ill_ip_muxid = islink ? li->l_index : 0;

	/*
	 * Mark the ipsq busy until the capability operations initiated below
	 * complete. The PLINK/UNLINK ioctl itself completes when our caller
	 * returns, but the capability operation may complete asynchronously
	 * much later.
	 */
	ipsq_current_start(ipsq, ill->ill_ipif, ioccmd);
	/*
	 * If there's at least one up ipif on this ill, then we're bound to
	 * the underlying driver via DLPI.  In that case, renegotiate
	 * capabilities to account for any possible change in modules
	 * interposed between IP and the driver.
	 */
	if (ill->ill_ipif_up_count > 0) {
		if (islink)
			ill_capability_probe(ill);
		else
			ill_capability_reset(ill, B_FALSE);
	}
	ipsq_current_finish(ipsq);
done:
	if (entered_ipsq)
		ipsq_exit(ipsq);

	return (err);
}

/*
 * Search the ioctl command in the ioctl tables and return a pointer
 * to the ioctl command information. The ioctl command tables are
 * static and fully populated at compile time.
 */
ip_ioctl_cmd_t *
ip_sioctl_lookup(int ioc_cmd)
{
	int index;
	ip_ioctl_cmd_t *ipip;
	ip_ioctl_cmd_t *ipip_end;

	if (ioc_cmd == IPI_DONTCARE)
		return (NULL);

	/*
	 * Do a 2 step search. First search the indexed table
	 * based on the least significant byte of the ioctl cmd.
	 * If we don't find a match, then search the misc table
	 * serially.
	 */
	index = ioc_cmd & 0xFF;
	if (index < ip_ndx_ioctl_count) {
		ipip = &ip_ndx_ioctl_table[index];
		if (ipip->ipi_cmd == ioc_cmd) {
			/* Found a match in the ndx table */
			return (ipip);
		}
	}

	/* Search the misc table */
	ipip_end = &ip_misc_ioctl_table[ip_misc_ioctl_count];
	for (ipip = ip_misc_ioctl_table; ipip < ipip_end; ipip++) {
		if (ipip->ipi_cmd == ioc_cmd)
			/* Found a match in the misc table */
			return (ipip);
	}

	return (NULL);
}

/*
 * Wrapper function for resuming deferred ioctl processing
 * Used for SIOCGDSTINFO, SIOCGIP6ADDRPOLICY, SIOCGMSFILTER,
 * SIOCSMSFILTER, SIOCGIPMSFILTER, and SIOCSIPMSFILTER currently.
 */
/* ARGSUSED */
void
ip_sioctl_copyin_resume(ipsq_t *dummy_ipsq, queue_t *q, mblk_t *mp,
    void *dummy_arg)
{
	ip_sioctl_copyin_setup(q, mp);
}

/*
 * ip_sioctl_copyin_setup is called by ip_wput with any M_IOCTL message
 * that arrives.  Most of the IOCTLs are "socket" IOCTLs which we handle
 * in either I_STR or TRANSPARENT form, using the mi_copy facility.
 * We establish here the size of the block to be copied in.  mi_copyin
 * arranges for this to happen, an processing continues in ip_wput with
 * an M_IOCDATA message.
 */
void
ip_sioctl_copyin_setup(queue_t *q, mblk_t *mp)
{
	int	copyin_size;
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	ip_ioctl_cmd_t *ipip;
	cred_t *cr;
	ip_stack_t	*ipst;

	if (CONN_Q(q))
		ipst = CONNQ_TO_IPST(q);
	else
		ipst = ILLQ_TO_IPST(q);

	ipip = ip_sioctl_lookup(iocp->ioc_cmd);
	if (ipip == NULL) {
		/*
		 * The ioctl is not one we understand or own.
		 * Pass it along to be processed down stream,
		 * if this is a module instance of IP, else nak
		 * the ioctl.
		 */
		if (q->q_next == NULL) {
			goto nak;
		} else {
			putnext(q, mp);
			return;
		}
	}

	/*
	 * If this is deferred, then we will do all the checks when we
	 * come back.
	 */
	if ((iocp->ioc_cmd == SIOCGDSTINFO ||
	    iocp->ioc_cmd == SIOCGIP6ADDRPOLICY) && !ip6_asp_can_lookup(ipst)) {
		ip6_asp_pending_op(q, mp, ip_sioctl_copyin_resume);
		return;
	}

	/*
	 * Only allow a very small subset of IP ioctls on this stream if
	 * IP is a module and not a driver. Allowing ioctls to be processed
	 * in this case may cause assert failures or data corruption.
	 * Typically G[L]IFFLAGS, SLIFNAME/IF_UNITSEL are the only few
	 * ioctls allowed on an IP module stream, after which this stream
	 * normally becomes a multiplexor (at which time the stream head
	 * will fail all ioctls).
	 */
	if ((q->q_next != NULL) && !(ipip->ipi_flags & IPI_MODOK)) {
		if (ipip->ipi_flags & IPI_PASS_DOWN) {
			/*
			 * Pass common Streams ioctls which the IP
			 * module does not own or consume along to
			 * be processed down stream.
			 */
			putnext(q, mp);
			return;
		} else {
			goto nak;
		}
	}

	/* Make sure we have ioctl data to process. */
	if (mp->b_cont == NULL && !(ipip->ipi_flags & IPI_NULL_BCONT))
		goto nak;

	/*
	 * Prefer dblk credential over ioctl credential; some synthesized
	 * ioctls have kcred set because there's no way to crhold()
	 * a credential in some contexts.  (ioc_cr is not crfree() by
	 * the framework; the caller of ioctl needs to hold the reference
	 * for the duration of the call).
	 */
	cr = DB_CREDDEF(mp, iocp->ioc_cr);

	/* Make sure normal users don't send down privileged ioctls */
	if ((ipip->ipi_flags & IPI_PRIV) &&
	    (cr != NULL) && secpolicy_ip_config(cr, B_TRUE) != 0) {
		/* We checked the privilege earlier but log it here */
		miocnak(q, mp, 0, secpolicy_ip_config(cr, B_FALSE));
		return;
	}

	/*
	 * The ioctl command tables can only encode fixed length
	 * ioctl data. If the length is variable, the table will
	 * encode the length as zero. Such special cases are handled
	 * below in the switch.
	 */
	if (ipip->ipi_copyin_size != 0) {
		mi_copyin(q, mp, NULL, ipip->ipi_copyin_size);
		return;
	}

	switch (iocp->ioc_cmd) {
	case O_SIOCGIFCONF:
	case SIOCGIFCONF:
		/*
		 * This IOCTL is hilarious.  See comments in
		 * ip_sioctl_get_ifconf for the story.
		 */
		if (iocp->ioc_count == TRANSPARENT)
			copyin_size = SIZEOF_STRUCT(ifconf,
			    iocp->ioc_flag);
		else
			copyin_size = iocp->ioc_count;
		mi_copyin(q, mp, NULL, copyin_size);
		return;

	case O_SIOCGLIFCONF:
	case SIOCGLIFCONF:
		copyin_size = SIZEOF_STRUCT(lifconf, iocp->ioc_flag);
		mi_copyin(q, mp, NULL, copyin_size);
		return;

	case SIOCGLIFSRCOF:
		copyin_size = SIZEOF_STRUCT(lifsrcof, iocp->ioc_flag);
		mi_copyin(q, mp, NULL, copyin_size);
		return;
	case SIOCGIP6ADDRPOLICY:
		ip_sioctl_ip6addrpolicy(q, mp);
		ip6_asp_table_refrele(ipst);
		return;

	case SIOCSIP6ADDRPOLICY:
		ip_sioctl_ip6addrpolicy(q, mp);
		return;

	case SIOCGDSTINFO:
		ip_sioctl_dstinfo(q, mp);
		ip6_asp_table_refrele(ipst);
		return;

	case I_PLINK:
	case I_PUNLINK:
	case I_LINK:
	case I_UNLINK:
		/*
		 * We treat non-persistent link similarly as the persistent
		 * link case, in terms of plumbing/unplumbing, as well as
		 * dynamic re-plumbing events indicator.  See comments
		 * in ip_sioctl_plink() for more.
		 *
		 * Request can be enqueued in the 'ipsq' while waiting
		 * to become exclusive. So bump up the conn ref.
		 */
		if (CONN_Q(q))
			CONN_INC_REF(Q_TO_CONN(q));
		ip_sioctl_plink(NULL, q, mp, NULL);
		return;

	case ND_GET:
	case ND_SET:
		/*
		 * Use of the nd table requires holding the reader lock.
		 * Modifying the nd table thru nd_load/nd_unload requires
		 * the writer lock.
		 */
		rw_enter(&ipst->ips_ip_g_nd_lock, RW_READER);
		if (nd_getset(q, ipst->ips_ip_g_nd, mp)) {
			rw_exit(&ipst->ips_ip_g_nd_lock);

			if (iocp->ioc_error)
				iocp->ioc_count = 0;
			mp->b_datap->db_type = M_IOCACK;
			qreply(q, mp);
			return;
		}
		rw_exit(&ipst->ips_ip_g_nd_lock);
		/*
		 * We don't understand this subioctl of ND_GET / ND_SET.
		 * Maybe intended for some driver / module below us
		 */
		if (q->q_next) {
			putnext(q, mp);
		} else {
			iocp->ioc_error = ENOENT;
			mp->b_datap->db_type = M_IOCNAK;
			iocp->ioc_count = 0;
			qreply(q, mp);
		}
		return;

	case IP_IOCTL:
		ip_wput_ioctl(q, mp);
		return;
	default:
		cmn_err(CE_PANIC, "should not happen ");
	}
nak:
	if (mp->b_cont != NULL) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
	iocp->ioc_error = EINVAL;
	mp->b_datap->db_type = M_IOCNAK;
	iocp->ioc_count = 0;
	qreply(q, mp);
}

/* ip_wput hands off ARP IOCTL responses to us */
/* ARGSUSED3 */
void
ip_sioctl_iocack(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy_arg)
{
	struct arpreq *ar;
	struct xarpreq *xar;
	area_t	*area;
	mblk_t	*area_mp;
	struct iocblk *iocp;
	mblk_t	*orig_ioc_mp, *tmp;
	struct iocblk	*orig_iocp;
	ill_t *ill;
	conn_t *connp = NULL;
	mblk_t *pending_mp;
	int x_arp_ioctl = B_FALSE, ifx_arp_ioctl = B_FALSE;
	int *flagsp;
	char *storage = NULL;
	sin_t *sin;
	ipaddr_t addr;
	int err;
	ip_stack_t *ipst;

	ASSERT(ipsq == NULL || IAM_WRITER_IPSQ(ipsq));
	ill = q->q_ptr;
	ASSERT(ill != NULL);
	ipst = ill->ill_ipst;

	/*
	 * We should get back from ARP a packet chain that looks like:
	 * M_IOCACK-->ARP_op_MBLK-->ORIG_M_IOCTL-->MI_COPY_MBLK-->[X]ARPREQ_MBLK
	 */
	if (!(area_mp = mp->b_cont) ||
	    (area_mp->b_wptr - area_mp->b_rptr) < sizeof (ip_sock_ar_t) ||
	    !(orig_ioc_mp = area_mp->b_cont) ||
	    !orig_ioc_mp->b_cont || !orig_ioc_mp->b_cont->b_cont) {
		freemsg(mp);
		return;
	}

	orig_iocp = (struct iocblk *)orig_ioc_mp->b_rptr;

	tmp = (orig_ioc_mp->b_cont)->b_cont;
	if ((orig_iocp->ioc_cmd == SIOCGXARP) ||
	    (orig_iocp->ioc_cmd == SIOCSXARP) ||
	    (orig_iocp->ioc_cmd == SIOCDXARP)) {
		x_arp_ioctl = B_TRUE;
		xar = (struct xarpreq *)tmp->b_rptr;
		sin = (sin_t *)&xar->xarp_pa;
		flagsp = &xar->xarp_flags;
		storage = xar->xarp_ha.sdl_data;
		if (xar->xarp_ha.sdl_nlen != 0)
			ifx_arp_ioctl = B_TRUE;
	} else {
		ar = (struct arpreq *)tmp->b_rptr;
		sin = (sin_t *)&ar->arp_pa;
		flagsp = &ar->arp_flags;
		storage = ar->arp_ha.sa_data;
	}

	iocp = (struct iocblk *)mp->b_rptr;

	/*
	 * Find the pending message; if we're exclusive, it'll be on our IPSQ.
	 * Otherwise, we can find it from our ioc_id.
	 */
	if (ipsq != NULL)
		pending_mp = ipsq_pending_mp_get(ipsq, &connp);
	else
		pending_mp = ill_pending_mp_get(ill, &connp, iocp->ioc_id);

	if (pending_mp == NULL) {
		ASSERT(connp == NULL);
		inet_freemsg(mp);
		return;
	}
	ASSERT(connp != NULL);
	q = CONNP_TO_WQ(connp);

	/* Uncouple the internally generated IOCTL from the original one */
	area = (area_t *)area_mp->b_rptr;
	area_mp->b_cont = NULL;

	/*
	 * Restore the b_next and b_prev used by mi code. This is needed
	 * to complete the ioctl using mi* functions. We stored them in
	 * the pending mp prior to sending the request to ARP.
	 */
	orig_ioc_mp->b_cont->b_next = pending_mp->b_cont->b_next;
	orig_ioc_mp->b_cont->b_prev = pending_mp->b_cont->b_prev;
	inet_freemsg(pending_mp);

	/*
	 * We're done if there was an error or if this is not an SIOCG{X}ARP
	 * Catch the case where there is an IRE_CACHE by no entry in the
	 * arp table.
	 */
	addr = sin->sin_addr.s_addr;
	if (iocp->ioc_error && iocp->ioc_cmd == AR_ENTRY_SQUERY) {
		ire_t			*ire;
		dl_unitdata_req_t	*dlup;
		mblk_t			*llmp;
		int			addr_len;
		ill_t			*ipsqill = NULL;

		if (ifx_arp_ioctl) {
			/*
			 * There's no need to lookup the ill, since
			 * we've already done that when we started
			 * processing the ioctl and sent the message
			 * to ARP on that ill.  So use the ill that
			 * is stored in q->q_ptr.
			 */
			ipsqill = ill;
			ire = ire_ctable_lookup(addr, 0, IRE_CACHE,
			    ipsqill->ill_ipif, ALL_ZONES,
			    NULL, MATCH_IRE_TYPE | MATCH_IRE_ILL, ipst);
		} else {
			ire = ire_ctable_lookup(addr, 0, IRE_CACHE,
			    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
			if (ire != NULL)
				ipsqill = ire_to_ill(ire);
		}

		if ((x_arp_ioctl) && (ipsqill != NULL))
			storage += ill_xarp_info(&xar->xarp_ha, ipsqill);

		if (ire != NULL) {
			/*
			 * Since the ire obtained from cachetable is used for
			 * mac addr copying below, treat an incomplete ire as if
			 * as if we never found it.
			 */
			if (ire->ire_nce != NULL &&
			    ire->ire_nce->nce_state != ND_REACHABLE) {
				ire_refrele(ire);
				ire = NULL;
				ipsqill = NULL;
				goto errack;
			}
			*flagsp = ATF_INUSE;
			llmp = (ire->ire_nce != NULL ?
			    ire->ire_nce->nce_res_mp : NULL);
			if (llmp != NULL && ipsqill != NULL) {
				uchar_t *macaddr;

				addr_len = ipsqill->ill_phys_addr_length;
				if (x_arp_ioctl && ((addr_len +
				    ipsqill->ill_name_length) >
				    sizeof (xar->xarp_ha.sdl_data))) {
					ire_refrele(ire);
					freemsg(mp);
					ip_ioctl_finish(q, orig_ioc_mp,
					    EINVAL, NO_COPYOUT, ipsq);
					return;
				}
				*flagsp |= ATF_COM;
				dlup = (dl_unitdata_req_t *)llmp->b_rptr;
				if (ipsqill->ill_sap_length < 0)
					macaddr = llmp->b_rptr +
					    dlup->dl_dest_addr_offset;
				else
					macaddr = llmp->b_rptr +
					    dlup->dl_dest_addr_offset +
					    ipsqill->ill_sap_length;
				/*
				 * For SIOCGARP, MAC address length
				 * validation has already been done
				 * before the ioctl was issued to ARP to
				 * allow it to progress only on 6 byte
				 * addressable (ethernet like) media. Thus
				 * the mac address copying can not overwrite
				 * the sa_data area below.
				 */
				bcopy(macaddr, storage, addr_len);
			}
			/* Ditch the internal IOCTL. */
			freemsg(mp);
			ire_refrele(ire);
			ip_ioctl_finish(q, orig_ioc_mp, 0, COPYOUT, ipsq);
			return;
		}
	}

	/*
	 * If this was a failed AR_ENTRY_ADD or a successful AR_ENTRY_DELETE
	 * on the IPMP meta-interface, ensure any ARP entries added in
	 * ip_sioctl_arp() are deleted.
	 */
	if (IS_IPMP(ill) &&
	    ((iocp->ioc_error != 0 && iocp->ioc_cmd == AR_ENTRY_ADD) ||
	    ((iocp->ioc_error == 0 && iocp->ioc_cmd == AR_ENTRY_DELETE)))) {
		ipmp_illgrp_t *illg = ill->ill_grp;
		ipmp_arpent_t *entp;

		if ((entp = ipmp_illgrp_lookup_arpent(illg, &addr)) != NULL)
			ipmp_illgrp_destroy_arpent(illg, entp);
	}

	/*
	 * Delete the coresponding IRE_CACHE if any.
	 * Reset the error if there was one (in case there was no entry
	 * in arp.)
	 */
	if (iocp->ioc_cmd == AR_ENTRY_DELETE) {
		ipif_t *ipintf = NULL;

		if (ifx_arp_ioctl) {
			/*
			 * There's no need to lookup the ill, since
			 * we've already done that when we started
			 * processing the ioctl and sent the message
			 * to ARP on that ill.  So use the ill that
			 * is stored in q->q_ptr.
			 */
			ipintf = ill->ill_ipif;
		}
		if (ip_ire_clookup_and_delete(addr, ipintf, ipst)) {
			/*
			 * The address in "addr" may be an entry for a
			 * router. If that's true, then any off-net
			 * IRE_CACHE entries that go through the router
			 * with address "addr" must be clobbered. Use
			 * ire_walk to achieve this goal.
			 */
			if (ifx_arp_ioctl)
				ire_walk_ill_v4(MATCH_IRE_ILL, 0,
				    ire_delete_cache_gw, (char *)&addr, ill);
			else
				ire_walk_v4(ire_delete_cache_gw, (char *)&addr,
				    ALL_ZONES, ipst);
			iocp->ioc_error = 0;
		}
	}
errack:
	if (iocp->ioc_error || iocp->ioc_cmd != AR_ENTRY_SQUERY) {
		err = iocp->ioc_error;
		freemsg(mp);
		ip_ioctl_finish(q, orig_ioc_mp, err, NO_COPYOUT, ipsq);
		return;
	}

	/*
	 * Completion of an SIOCG{X}ARP.  Translate the information from
	 * the area_t into the struct {x}arpreq.
	 */
	if (x_arp_ioctl) {
		storage += ill_xarp_info(&xar->xarp_ha, ill);
		if ((ill->ill_phys_addr_length + ill->ill_name_length) >
		    sizeof (xar->xarp_ha.sdl_data)) {
			freemsg(mp);
			ip_ioctl_finish(q, orig_ioc_mp, EINVAL, NO_COPYOUT,
			    ipsq);
			return;
		}
	}
	*flagsp = ATF_INUSE;
	if (area->area_flags & ACE_F_PERMANENT)
		*flagsp |= ATF_PERM;
	if (area->area_flags & ACE_F_PUBLISH)
		*flagsp |= ATF_PUBL;
	if (area->area_flags & ACE_F_AUTHORITY)
		*flagsp |= ATF_AUTHORITY;
	if (area->area_hw_addr_length != 0) {
		*flagsp |= ATF_COM;
		/*
		 * For SIOCGARP, MAC address length validation has
		 * already been done before the ioctl was issued to ARP
		 * to allow it to progress only on 6 byte addressable
		 * (ethernet like) media. Thus the mac address copying
		 * can not overwrite the sa_data area below.
		 */
		bcopy((char *)area + area->area_hw_addr_offset,
		    storage, area->area_hw_addr_length);
	}

	/* Ditch the internal IOCTL. */
	freemsg(mp);
	/* Complete the original. */
	ip_ioctl_finish(q, orig_ioc_mp, 0, COPYOUT, ipsq);
}

/*
 * Create a new logical interface. If ipif_id is zero (i.e. not a logical
 * interface) create the next available logical interface for this
 * physical interface.
 * If ipif is NULL (i.e. the lookup didn't find one) attempt to create an
 * ipif with the specified name.
 *
 * If the address family is not AF_UNSPEC then set the address as well.
 *
 * If ip_sioctl_addr returns EINPROGRESS then the ioctl (the copyout)
 * is completed when the DL_BIND_ACK arrive in ip_rput_dlpi_writer.
 *
 * Executed as a writer on the ill.
 * So no lock is needed to traverse the ipif chain, or examine the
 * phyint flags.
 */
/* ARGSUSED */
int
ip_sioctl_addif(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *dummy_ipip, void *dummy_ifreq)
{
	mblk_t	*mp1;
	struct lifreq *lifr;
	boolean_t	isv6;
	boolean_t	exists;
	char 	*name;
	char	*endp;
	char	*cp;
	int	namelen;
	ipif_t	*ipif;
	long	id;
	ipsq_t	*ipsq;
	ill_t	*ill;
	sin_t	*sin;
	int	err = 0;
	boolean_t found_sep = B_FALSE;
	conn_t	*connp;
	zoneid_t zoneid;
	ip_stack_t *ipst = CONNQ_TO_IPST(q);

	ASSERT(q->q_next == NULL);
	ip1dbg(("ip_sioctl_addif\n"));
	/* Existence of mp1 has been checked in ip_wput_nondata */
	mp1 = mp->b_cont->b_cont;
	/*
	 * Null terminate the string to protect against buffer
	 * overrun. String was generated by user code and may not
	 * be trusted.
	 */
	lifr = (struct lifreq *)mp1->b_rptr;
	lifr->lifr_name[LIFNAMSIZ - 1] = '\0';
	name = lifr->lifr_name;
	ASSERT(CONN_Q(q));
	connp = Q_TO_CONN(q);
	isv6 = connp->conn_af_isv6;
	zoneid = connp->conn_zoneid;
	namelen = mi_strlen(name);
	if (namelen == 0)
		return (EINVAL);

	exists = B_FALSE;
	if ((namelen + 1 == sizeof (ipif_loopback_name)) &&
	    (mi_strcmp(name, ipif_loopback_name) == 0)) {
		/*
		 * Allow creating lo0 using SIOCLIFADDIF.
		 * can't be any other writer thread. So can pass null below
		 * for the last 4 args to ipif_lookup_name.
		 */
		ipif = ipif_lookup_on_name(lifr->lifr_name, namelen, B_TRUE,
		    &exists, isv6, zoneid, NULL, NULL, NULL, NULL, ipst);
		/* Prevent any further action */
		if (ipif == NULL) {
			return (ENOBUFS);
		} else if (!exists) {
			/* We created the ipif now and as writer */
			ipif_refrele(ipif);
			return (0);
		} else {
			ill = ipif->ipif_ill;
			ill_refhold(ill);
			ipif_refrele(ipif);
		}
	} else {
		/* Look for a colon in the name. */
		endp = &name[namelen];
		for (cp = endp; --cp > name; ) {
			if (*cp == IPIF_SEPARATOR_CHAR) {
				found_sep = B_TRUE;
				/*
				 * Reject any non-decimal aliases for plumbing
				 * of logical interfaces. Aliases with leading
				 * zeroes are also rejected as they introduce
				 * ambiguity in the naming of the interfaces.
				 * Comparing with "0" takes care of all such
				 * cases.
				 */
				if ((strncmp("0", cp+1, 1)) == 0)
					return (EINVAL);

				if (ddi_strtol(cp+1, &endp, 10, &id) != 0 ||
				    id <= 0 || *endp != '\0') {
					return (EINVAL);
				}
				*cp = '\0';
				break;
			}
		}
		ill = ill_lookup_on_name(name, B_FALSE, isv6,
		    CONNP_TO_WQ(connp), mp, ip_process_ioctl, &err, NULL, ipst);
		if (found_sep)
			*cp = IPIF_SEPARATOR_CHAR;
		if (ill == NULL)
			return (err);
	}

	ipsq = ipsq_try_enter(NULL, ill, q, mp, ip_process_ioctl, NEW_OP,
	    B_TRUE);

	/*
	 * Release the refhold due to the lookup, now that we are excl
	 * or we are just returning
	 */
	ill_refrele(ill);

	if (ipsq == NULL)
		return (EINPROGRESS);

	/* We are now exclusive on the IPSQ */
	ASSERT(IAM_WRITER_ILL(ill));

	if (found_sep) {
		/* Now see if there is an IPIF with this unit number. */
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (ipif->ipif_id == id) {
				err = EEXIST;
				goto done;
			}
		}
	}

	/*
	 * We use IRE_LOCAL for lo0:1 etc. for "receive only" use
	 * of lo0.  Plumbing for lo0:0 happens in ipif_lookup_on_name()
	 * instead.
	 */
	if ((ipif = ipif_allocate(ill, found_sep ? id : -1, IRE_LOCAL,
	    B_TRUE, B_TRUE)) == NULL) {
		err = ENOBUFS;
		goto done;
	}

	/* Return created name with ioctl */
	(void) sprintf(lifr->lifr_name, "%s%c%d", ill->ill_name,
	    IPIF_SEPARATOR_CHAR, ipif->ipif_id);
	ip1dbg(("created %s\n", lifr->lifr_name));

	/* Set address */
	sin = (sin_t *)&lifr->lifr_addr;
	if (sin->sin_family != AF_UNSPEC) {
		err = ip_sioctl_addr(ipif, sin, q, mp,
		    &ip_ndx_ioctl_table[SIOCLIFADDR_NDX], lifr);
	}

done:
	ipsq_exit(ipsq);
	return (err);
}

/*
 * Remove an existing logical interface. If ipif_id is zero (i.e. not a logical
 * interface) delete it based on the IP address (on this physical interface).
 * Otherwise delete it based on the ipif_id.
 * Also, special handling to allow a removeif of lo0.
 */
/* ARGSUSED */
int
ip_sioctl_removeif(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_if_req)
{
	conn_t		*connp;
	ill_t		*ill = ipif->ipif_ill;
	boolean_t	 success;
	ip_stack_t	*ipst;

	ipst = CONNQ_TO_IPST(q);

	ASSERT(q->q_next == NULL);
	ip1dbg(("ip_sioctl_remove_if(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ASSERT(IAM_WRITER_IPIF(ipif));

	connp = Q_TO_CONN(q);
	/*
	 * Special case for unplumbing lo0 (the loopback physical interface).
	 * If unplumbing lo0, the incoming address structure has been
	 * initialized to all zeros. When unplumbing lo0, all its logical
	 * interfaces must be removed too.
	 *
	 * Note that this interface may be called to remove a specific
	 * loopback logical interface (eg, lo0:1). But in that case
	 * ipif->ipif_id != 0 so that the code path for that case is the
	 * same as any other interface (meaning it skips the code directly
	 * below).
	 */
	if (ipif->ipif_id == 0 && ipif->ipif_net_type == IRE_LOOPBACK) {
		if (sin->sin_family == AF_UNSPEC &&
		    (IN6_IS_ADDR_UNSPECIFIED(&((sin6_t *)sin)->sin6_addr))) {
			/*
			 * Mark it condemned. No new ref. will be made to ill.
			 */
			mutex_enter(&ill->ill_lock);
			ill->ill_state_flags |= ILL_CONDEMNED;
			for (ipif = ill->ill_ipif; ipif != NULL;
			    ipif = ipif->ipif_next) {
				ipif->ipif_state_flags |= IPIF_CONDEMNED;
			}
			mutex_exit(&ill->ill_lock);

			ipif = ill->ill_ipif;
			/* unplumb the loopback interface */
			ill_delete(ill);
			mutex_enter(&connp->conn_lock);
			mutex_enter(&ill->ill_lock);

			/* Are any references to this ill active */
			if (ill_is_freeable(ill)) {
				mutex_exit(&ill->ill_lock);
				mutex_exit(&connp->conn_lock);
				ill_delete_tail(ill);
				mi_free(ill);
				return (0);
			}
			success = ipsq_pending_mp_add(connp, ipif,
			    CONNP_TO_WQ(connp), mp, ILL_FREE);
			mutex_exit(&connp->conn_lock);
			mutex_exit(&ill->ill_lock);
			if (success)
				return (EINPROGRESS);
			else
				return (EINTR);
		}
	}

	if (ipif->ipif_id == 0) {
		ipsq_t *ipsq;

		/* Find based on address */
		if (ipif->ipif_isv6) {
			sin6_t *sin6;

			if (sin->sin_family != AF_INET6)
				return (EAFNOSUPPORT);

			sin6 = (sin6_t *)sin;
			/* We are a writer, so we should be able to lookup */
			ipif = ipif_lookup_addr_exact_v6(&sin6->sin6_addr, ill,
			    ipst);
		} else {
			if (sin->sin_family != AF_INET)
				return (EAFNOSUPPORT);

			/* We are a writer, so we should be able to lookup */
			ipif = ipif_lookup_addr_exact(sin->sin_addr.s_addr, ill,
			    ipst);
		}
		if (ipif == NULL) {
			return (EADDRNOTAVAIL);
		}

		/*
		 * It is possible for a user to send an SIOCLIFREMOVEIF with
		 * lifr_name of the physical interface but with an ip address
		 * lifr_addr of a logical interface plumbed over it.
		 * So update ipx_current_ipif now that ipif points to the
		 * correct one.
		 */
		ipsq = ipif->ipif_ill->ill_phyint->phyint_ipsq;
		ipsq->ipsq_xop->ipx_current_ipif = ipif;

		/* This is a writer */
		ipif_refrele(ipif);
	}

	/*
	 * Can not delete instance zero since it is tied to the ill.
	 */
	if (ipif->ipif_id == 0)
		return (EBUSY);

	mutex_enter(&ill->ill_lock);
	ipif->ipif_state_flags |= IPIF_CONDEMNED;
	mutex_exit(&ill->ill_lock);

	ipif_free(ipif);

	mutex_enter(&connp->conn_lock);
	mutex_enter(&ill->ill_lock);


	/* Are any references to this ipif active */
	if (ipif_is_freeable(ipif)) {
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		ipif_non_duplicate(ipif);
		ipif_down_tail(ipif);
		ipif_free_tail(ipif); /* frees ipif */
		return (0);
	}
	success = ipsq_pending_mp_add(connp, ipif, CONNP_TO_WQ(connp), mp,
	    IPIF_FREE);
	mutex_exit(&ill->ill_lock);
	mutex_exit(&connp->conn_lock);
	if (success)
		return (EINPROGRESS);
	else
		return (EINTR);
}

/*
 * Restart the removeif ioctl. The refcnt has gone down to 0.
 * The ipif is already condemned. So can't find it thru lookups.
 */
/* ARGSUSED */
int
ip_sioctl_removeif_restart(ipif_t *ipif, sin_t *dummy_sin, queue_t *q,
    mblk_t *mp, ip_ioctl_cmd_t *ipip, void *dummy_if_req)
{
	ill_t *ill = ipif->ipif_ill;

	ASSERT(IAM_WRITER_IPIF(ipif));
	ASSERT(ipif->ipif_state_flags & IPIF_CONDEMNED);

	ip1dbg(("ip_sioctl_removeif_restart(%s:%u %p)\n",
	    ill->ill_name, ipif->ipif_id, (void *)ipif));

	if (ipif->ipif_id == 0 && ipif->ipif_net_type == IRE_LOOPBACK) {
		ASSERT(ill->ill_state_flags & ILL_CONDEMNED);
		ill_delete_tail(ill);
		mi_free(ill);
		return (0);
	}

	ipif_non_duplicate(ipif);
	ipif_down_tail(ipif);
	ipif_free_tail(ipif);

	ILL_UNMARK_CHANGING(ill);
	return (0);
}

/*
 * Set the local interface address.
 * Allow an address of all zero when the interface is down.
 */
/* ARGSUSED */
int
ip_sioctl_addr(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *dummy_ipip, void *dummy_ifreq)
{
	int err = 0;
	in6_addr_t v6addr;
	boolean_t need_up = B_FALSE;

	ip1dbg(("ip_sioctl_addr(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (ipif->ipif_isv6) {
		sin6_t *sin6;
		ill_t *ill;
		phyint_t *phyi;

		if (sin->sin_family != AF_INET6)
			return (EAFNOSUPPORT);

		sin6 = (sin6_t *)sin;
		v6addr = sin6->sin6_addr;
		ill = ipif->ipif_ill;
		phyi = ill->ill_phyint;

		/*
		 * Enforce that true multicast interfaces have a link-local
		 * address for logical unit 0.
		 */
		if (ipif->ipif_id == 0 &&
		    (ill->ill_flags & ILLF_MULTICAST) &&
		    !(ipif->ipif_flags & (IPIF_POINTOPOINT)) &&
		    !(phyi->phyint_flags & (PHYI_LOOPBACK)) &&
		    !IN6_IS_ADDR_LINKLOCAL(&v6addr)) {
			return (EADDRNOTAVAIL);
		}

		/*
		 * up interfaces shouldn't have the unspecified address
		 * unless they also have the IPIF_NOLOCAL flags set and
		 * have a subnet assigned.
		 */
		if ((ipif->ipif_flags & IPIF_UP) &&
		    IN6_IS_ADDR_UNSPECIFIED(&v6addr) &&
		    (!(ipif->ipif_flags & IPIF_NOLOCAL) ||
		    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6subnet))) {
			return (EADDRNOTAVAIL);
		}

		if (!ip_local_addr_ok_v6(&v6addr, &ipif->ipif_v6net_mask))
			return (EADDRNOTAVAIL);
	} else {
		ipaddr_t addr;

		if (sin->sin_family != AF_INET)
			return (EAFNOSUPPORT);

		addr = sin->sin_addr.s_addr;

		/* Allow 0 as the local address. */
		if (addr != 0 && !ip_addr_ok_v4(addr, ipif->ipif_net_mask))
			return (EADDRNOTAVAIL);

		IN6_IPADDR_TO_V4MAPPED(addr, &v6addr);
	}

	/*
	 * Even if there is no change we redo things just to rerun
	 * ipif_set_default.
	 */
	if (ipif->ipif_flags & IPIF_UP) {
		/*
		 * Setting a new local address, make sure
		 * we have net and subnet bcast ire's for
		 * the old address if we need them.
		 */
		if (!ipif->ipif_isv6)
			ipif_check_bcast_ires(ipif);
		/*
		 * If the interface is already marked up,
		 * we call ipif_down which will take care
		 * of ditching any IREs that have been set
		 * up based on the old interface address.
		 */
		err = ipif_logical_down(ipif, q, mp);
		if (err == EINPROGRESS)
			return (err);
		ipif_down_tail(ipif);
		need_up = 1;
	}

	err = ip_sioctl_addr_tail(ipif, sin, q, mp, need_up);
	return (err);
}

int
ip_sioctl_addr_tail(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    boolean_t need_up)
{
	in6_addr_t v6addr;
	in6_addr_t ov6addr;
	ipaddr_t addr;
	sin6_t	*sin6;
	int	sinlen;
	int	err = 0;
	ill_t	*ill = ipif->ipif_ill;
	boolean_t need_dl_down;
	boolean_t need_arp_down;
	struct iocblk *iocp;

	iocp = (mp != NULL) ? (struct iocblk *)mp->b_rptr : NULL;

	ip1dbg(("ip_sioctl_addr_tail(%s:%u %p)\n",
	    ill->ill_name, ipif->ipif_id, (void *)ipif));
	ASSERT(IAM_WRITER_IPIF(ipif));

	/* Must cancel any pending timer before taking the ill_lock */
	if (ipif->ipif_recovery_id != 0)
		(void) untimeout(ipif->ipif_recovery_id);
	ipif->ipif_recovery_id = 0;

	if (ipif->ipif_isv6) {
		sin6 = (sin6_t *)sin;
		v6addr = sin6->sin6_addr;
		sinlen = sizeof (struct sockaddr_in6);
	} else {
		addr = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(addr, &v6addr);
		sinlen = sizeof (struct sockaddr_in);
	}
	mutex_enter(&ill->ill_lock);
	ov6addr = ipif->ipif_v6lcl_addr;
	ipif->ipif_v6lcl_addr = v6addr;
	sctp_update_ipif_addr(ipif, ov6addr);
	if (ipif->ipif_flags & (IPIF_ANYCAST | IPIF_NOLOCAL)) {
		ipif->ipif_v6src_addr = ipv6_all_zeros;
	} else {
		ipif->ipif_v6src_addr = v6addr;
	}
	ipif->ipif_addr_ready = 0;

	/*
	 * If the interface was previously marked as a duplicate, then since
	 * we've now got a "new" address, it should no longer be considered a
	 * duplicate -- even if the "new" address is the same as the old one.
	 * Note that if all ipifs are down, we may have a pending ARP down
	 * event to handle.  This is because we want to recover from duplicates
	 * and thus delay tearing down ARP until the duplicates have been
	 * removed or disabled.
	 */
	need_dl_down = need_arp_down = B_FALSE;
	if (ipif->ipif_flags & IPIF_DUPLICATE) {
		need_arp_down = !need_up;
		ipif->ipif_flags &= ~IPIF_DUPLICATE;
		if (--ill->ill_ipif_dup_count == 0 && !need_up &&
		    ill->ill_ipif_up_count == 0 && ill->ill_dl_up) {
			need_dl_down = B_TRUE;
		}
	}

	if (ipif->ipif_isv6 && IN6_IS_ADDR_6TO4(&v6addr) &&
	    !ill->ill_is_6to4tun) {
		queue_t *wqp = ill->ill_wq;

		/*
		 * The local address of this interface is a 6to4 address,
		 * check if this interface is in fact a 6to4 tunnel or just
		 * an interface configured with a 6to4 address.  We are only
		 * interested in the former.
		 */
		if (wqp != NULL) {
			while ((wqp->q_next != NULL) &&
			    (wqp->q_next->q_qinfo != NULL) &&
			    (wqp->q_next->q_qinfo->qi_minfo != NULL)) {

				if (wqp->q_next->q_qinfo->qi_minfo->mi_idnum
				    == TUN6TO4_MODID) {
					/* set for use in IP */
					ill->ill_is_6to4tun = 1;
					break;
				}
				wqp = wqp->q_next;
			}
		}
	}

	ipif_set_default(ipif);

	/*
	 * When publishing an interface address change event, we only notify
	 * the event listeners of the new address.  It is assumed that if they
	 * actively care about the addresses assigned that they will have
	 * already discovered the previous address assigned (if there was one.)
	 *
	 * Don't attach nic event message for SIOCLIFADDIF ioctl.
	 */
	if (iocp != NULL && iocp->ioc_cmd != SIOCLIFADDIF) {
		ill_nic_event_dispatch(ill, MAP_IPIF_ID(ipif->ipif_id),
		    NE_ADDRESS_CHANGE, sin, sinlen);
	}

	mutex_exit(&ill->ill_lock);

	if (need_up) {
		/*
		 * Now bring the interface back up.  If this
		 * is the only IPIF for the ILL, ipif_up
		 * will have to re-bind to the device, so
		 * we may get back EINPROGRESS, in which
		 * case, this IOCTL will get completed in
		 * ip_rput_dlpi when we see the DL_BIND_ACK.
		 */
		err = ipif_up(ipif, q, mp);
	}

	if (need_dl_down)
		ill_dl_down(ill);
	if (need_arp_down)
		ipif_resolver_down(ipif);

	return (err);
}


/*
 * Restart entry point to restart the address set operation after the
 * refcounts have dropped to zero.
 */
/* ARGSUSED */
int
ip_sioctl_addr_restart(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	ip1dbg(("ip_sioctl_addr_restart(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ASSERT(IAM_WRITER_IPIF(ipif));
	ipif_down_tail(ipif);
	return (ip_sioctl_addr_tail(ipif, sin, q, mp, B_TRUE));
}

/* ARGSUSED */
int
ip_sioctl_get_addr(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	sin6_t *sin6 = (struct sockaddr_in6 *)sin;
	struct lifreq *lifr = (struct lifreq *)if_req;

	ip1dbg(("ip_sioctl_get_addr(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	/*
	 * The net mask and address can't change since we have a
	 * reference to the ipif. So no lock is necessary.
	 */
	if (ipif->ipif_isv6) {
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = ipif->ipif_v6lcl_addr;
		ASSERT(ipip->ipi_cmd_type == LIF_CMD);
		lifr->lifr_addrlen =
		    ip_mask_to_plen_v6(&ipif->ipif_v6net_mask);
	} else {
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ipif->ipif_lcl_addr;
		if (ipip->ipi_cmd_type == LIF_CMD) {
			lifr->lifr_addrlen =
			    ip_mask_to_plen(ipif->ipif_net_mask);
		}
	}
	return (0);
}

/*
 * Set the destination address for a pt-pt interface.
 */
/* ARGSUSED */
int
ip_sioctl_dstaddr(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	int err = 0;
	in6_addr_t v6addr;
	boolean_t need_up = B_FALSE;

	ip1dbg(("ip_sioctl_dstaddr(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ASSERT(IAM_WRITER_IPIF(ipif));

	if (ipif->ipif_isv6) {
		sin6_t *sin6;

		if (sin->sin_family != AF_INET6)
			return (EAFNOSUPPORT);

		sin6 = (sin6_t *)sin;
		v6addr = sin6->sin6_addr;

		if (!ip_remote_addr_ok_v6(&v6addr, &ipif->ipif_v6net_mask))
			return (EADDRNOTAVAIL);
	} else {
		ipaddr_t addr;

		if (sin->sin_family != AF_INET)
			return (EAFNOSUPPORT);

		addr = sin->sin_addr.s_addr;
		if (!ip_addr_ok_v4(addr, ipif->ipif_net_mask))
			return (EADDRNOTAVAIL);

		IN6_IPADDR_TO_V4MAPPED(addr, &v6addr);
	}

	if (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6pp_dst_addr, &v6addr))
		return (0);	/* No change */

	if (ipif->ipif_flags & IPIF_UP) {
		/*
		 * If the interface is already marked up,
		 * we call ipif_down which will take care
		 * of ditching any IREs that have been set
		 * up based on the old pp dst address.
		 */
		err = ipif_logical_down(ipif, q, mp);
		if (err == EINPROGRESS)
			return (err);
		ipif_down_tail(ipif);
		need_up = B_TRUE;
	}
	/*
	 * could return EINPROGRESS. If so ioctl will complete in
	 * ip_rput_dlpi_writer
	 */
	err = ip_sioctl_dstaddr_tail(ipif, sin, q, mp, need_up);
	return (err);
}

static int
ip_sioctl_dstaddr_tail(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    boolean_t need_up)
{
	in6_addr_t v6addr;
	ill_t	*ill = ipif->ipif_ill;
	int	err = 0;
	boolean_t need_dl_down;
	boolean_t need_arp_down;

	ip1dbg(("ip_sioctl_dstaddr_tail(%s:%u %p)\n", ill->ill_name,
	    ipif->ipif_id, (void *)ipif));

	/* Must cancel any pending timer before taking the ill_lock */
	if (ipif->ipif_recovery_id != 0)
		(void) untimeout(ipif->ipif_recovery_id);
	ipif->ipif_recovery_id = 0;

	if (ipif->ipif_isv6) {
		sin6_t *sin6;

		sin6 = (sin6_t *)sin;
		v6addr = sin6->sin6_addr;
	} else {
		ipaddr_t addr;

		addr = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(addr, &v6addr);
	}
	mutex_enter(&ill->ill_lock);
	/* Set point to point destination address. */
	if ((ipif->ipif_flags & IPIF_POINTOPOINT) == 0) {
		/*
		 * Allow this as a means of creating logical
		 * pt-pt interfaces on top of e.g. an Ethernet.
		 * XXX Undocumented HACK for testing.
		 * pt-pt interfaces are created with NUD disabled.
		 */
		ipif->ipif_flags |= IPIF_POINTOPOINT;
		ipif->ipif_flags &= ~IPIF_BROADCAST;
		if (ipif->ipif_isv6)
			ill->ill_flags |= ILLF_NONUD;
	}

	/*
	 * If the interface was previously marked as a duplicate, then since
	 * we've now got a "new" address, it should no longer be considered a
	 * duplicate -- even if the "new" address is the same as the old one.
	 * Note that if all ipifs are down, we may have a pending ARP down
	 * event to handle.
	 */
	need_dl_down = need_arp_down = B_FALSE;
	if (ipif->ipif_flags & IPIF_DUPLICATE) {
		need_arp_down = !need_up;
		ipif->ipif_flags &= ~IPIF_DUPLICATE;
		if (--ill->ill_ipif_dup_count == 0 && !need_up &&
		    ill->ill_ipif_up_count == 0 && ill->ill_dl_up) {
			need_dl_down = B_TRUE;
		}
	}

	/* Set the new address. */
	ipif->ipif_v6pp_dst_addr = v6addr;
	/* Make sure subnet tracks pp_dst */
	ipif->ipif_v6subnet = ipif->ipif_v6pp_dst_addr;
	mutex_exit(&ill->ill_lock);

	if (need_up) {
		/*
		 * Now bring the interface back up.  If this
		 * is the only IPIF for the ILL, ipif_up
		 * will have to re-bind to the device, so
		 * we may get back EINPROGRESS, in which
		 * case, this IOCTL will get completed in
		 * ip_rput_dlpi when we see the DL_BIND_ACK.
		 */
		err = ipif_up(ipif, q, mp);
	}

	if (need_dl_down)
		ill_dl_down(ill);
	if (need_arp_down)
		ipif_resolver_down(ipif);

	return (err);
}

/*
 * Restart entry point to restart the dstaddress set operation after the
 * refcounts have dropped to zero.
 */
/* ARGSUSED */
int
ip_sioctl_dstaddr_restart(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	ip1dbg(("ip_sioctl_dstaddr_restart(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ipif_down_tail(ipif);
	return (ip_sioctl_dstaddr_tail(ipif, sin, q, mp, B_TRUE));
}

/* ARGSUSED */
int
ip_sioctl_get_dstaddr(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	sin6_t	*sin6 = (struct sockaddr_in6 *)sin;

	ip1dbg(("ip_sioctl_get_dstaddr(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	/*
	 * Get point to point destination address. The addresses can't
	 * change since we hold a reference to the ipif.
	 */
	if ((ipif->ipif_flags & IPIF_POINTOPOINT) == 0)
		return (EADDRNOTAVAIL);

	if (ipif->ipif_isv6) {
		ASSERT(ipip->ipi_cmd_type == LIF_CMD);
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = ipif->ipif_v6pp_dst_addr;
	} else {
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ipif->ipif_pp_dst_addr;
	}
	return (0);
}

/*
 * Set interface flags.  Many flags require special handling (e.g.,
 * bringing the interface down); see below for details.
 *
 * NOTE : We really don't enforce that ipif_id zero should be used
 *	  for setting any flags other than IFF_LOGINT_FLAGS. This
 *	  is because applications generally does SICGLIFFLAGS and
 *	  ORs in the new flags (that affects the logical) and does a
 *	  SIOCSLIFFLAGS. Thus, "flags" below could contain bits other
 *	  than IFF_LOGINT_FLAGS. One could check whether "turn_on" - the
 *	  flags that will be turned on is correct with respect to
 *	  ipif_id 0. For backward compatibility reasons, it is not done.
 */
/* ARGSUSED */
int
ip_sioctl_flags(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	uint64_t turn_on;
	uint64_t turn_off;
	int	err = 0;
	phyint_t *phyi;
	ill_t *ill;
	uint64_t intf_flags, cantchange_flags;
	boolean_t phyint_flags_modified = B_FALSE;
	uint64_t flags;
	struct ifreq *ifr;
	struct lifreq *lifr;
	boolean_t set_linklocal = B_FALSE;
	boolean_t zero_source = B_FALSE;

	ip1dbg(("ip_sioctl_flags(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	ASSERT(IAM_WRITER_IPIF(ipif));

	ill = ipif->ipif_ill;
	phyi = ill->ill_phyint;

	if (ipip->ipi_cmd_type == IF_CMD) {
		ifr = (struct ifreq *)if_req;
		flags = (uint64_t)(ifr->ifr_flags & 0x0000ffff);
	} else {
		lifr = (struct lifreq *)if_req;
		flags = lifr->lifr_flags;
	}

	intf_flags = ipif->ipif_flags | ill->ill_flags | phyi->phyint_flags;

	/*
	 * Have the flags been set correctly until now?
	 */
	ASSERT((phyi->phyint_flags & ~(IFF_PHYINT_FLAGS)) == 0);
	ASSERT((ill->ill_flags & ~(IFF_PHYINTINST_FLAGS)) == 0);
	ASSERT((ipif->ipif_flags & ~(IFF_LOGINT_FLAGS)) == 0);
	/*
	 * Compare the new flags to the old, and partition
	 * into those coming on and those going off.
	 * For the 16 bit command keep the bits above bit 16 unchanged.
	 */
	if (ipip->ipi_cmd == SIOCSIFFLAGS)
		flags |= intf_flags & ~0xFFFF;

	/*
	 * Explicitly fail attempts to change flags that are always invalid on
	 * an IPMP meta-interface.
	 */
	if (IS_IPMP(ill) && ((flags ^ intf_flags) & IFF_IPMP_INVALID))
		return (EINVAL);

	/*
	 * Check which flags will change; silently ignore flags which userland
	 * is not allowed to control.  (Because these flags may change between
	 * SIOCGLIFFLAGS and SIOCSLIFFLAGS, and that's outside of userland's
	 * control, we need to silently ignore them rather than fail.)
	 */
	cantchange_flags = IFF_CANTCHANGE;
	if (IS_IPMP(ill))
		cantchange_flags |= IFF_IPMP_CANTCHANGE;

	turn_on = (flags ^ intf_flags) & ~cantchange_flags;
	if (turn_on == 0)
		return (0);	/* No change */

	turn_off = intf_flags & turn_on;
	turn_on ^= turn_off;

	/*
	 * All test addresses must be IFF_DEPRECATED (to ensure source address
	 * selection avoids them) -- so force IFF_DEPRECATED on, and do not
	 * allow it to be turned off.
	 */
	if ((turn_off & (IFF_DEPRECATED|IFF_NOFAILOVER)) == IFF_DEPRECATED &&
	    (turn_on|intf_flags) & IFF_NOFAILOVER)
		return (EINVAL);

	if (turn_on & IFF_NOFAILOVER) {
		turn_on |= IFF_DEPRECATED;
		flags |= IFF_DEPRECATED;
	}

	/*
	 * On underlying interfaces, only allow applications to manage test
	 * addresses -- otherwise, they may get confused when the address
	 * moves as part of being brought up.  Likewise, prevent an
	 * application-managed test address from being converted to a data
	 * address.  To prevent migration of administratively up addresses in
	 * the kernel, we don't allow them to be converted either.
	 */
	if (IS_UNDER_IPMP(ill)) {
		const uint64_t appflags = IFF_DHCPRUNNING | IFF_ADDRCONF;

		if ((turn_on & appflags) && !(flags & IFF_NOFAILOVER))
			return (EINVAL);

		if ((turn_off & IFF_NOFAILOVER) &&
		    (flags & (appflags | IFF_UP | IFF_DUPLICATE)))
			return (EINVAL);
	}

	/*
	 * Only allow the IFF_XRESOLV and IFF_TEMPORARY flags to be set on
	 * IPv6 interfaces.
	 */
	if ((turn_on & (IFF_XRESOLV|IFF_TEMPORARY)) && !(ipif->ipif_isv6))
		return (EINVAL);

	/*
	 * cannot turn off IFF_NOXMIT on  VNI interfaces.
	 */
	if ((turn_off & IFF_NOXMIT) && IS_VNI(ipif->ipif_ill))
		return (EINVAL);

	/*
	 * Don't allow the IFF_ROUTER flag to be turned on on loopback
	 * interfaces.  It makes no sense in that context.
	 */
	if ((turn_on & IFF_ROUTER) && (phyi->phyint_flags & PHYI_LOOPBACK))
		return (EINVAL);

	if (flags & (IFF_NOLOCAL|IFF_ANYCAST))
		zero_source = B_TRUE;

	/*
	 * For IPv6 ipif_id 0, don't allow the interface to be up without
	 * a link local address if IFF_NOLOCAL or IFF_ANYCAST are not set.
	 * If the link local address isn't set, and can be set, it will get
	 * set later on in this function.
	 */
	if (ipif->ipif_id == 0 && ipif->ipif_isv6 &&
	    (flags & IFF_UP) && !zero_source &&
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr)) {
		if (ipif_cant_setlinklocal(ipif))
			return (EINVAL);
		set_linklocal = B_TRUE;
	}

	/*
	 * If we modify physical interface flags, we'll potentially need to
	 * send up two routing socket messages for the changes (one for the
	 * IPv4 ill, and another for the IPv6 ill).  Note that here.
	 */
	if ((turn_on|turn_off) & IFF_PHYINT_FLAGS)
		phyint_flags_modified = B_TRUE;

	/*
	 * All functioning PHYI_STANDBY interfaces start life PHYI_INACTIVE
	 * (otherwise, we'd immediately use them, defeating standby).  Also,
	 * since PHYI_INACTIVE has a separate meaning when PHYI_STANDBY is not
	 * set, don't allow PHYI_STANDBY to be set if PHYI_INACTIVE is already
	 * set, and clear PHYI_INACTIVE if PHYI_STANDBY is being cleared.  We
	 * also don't allow PHYI_STANDBY if VNI is enabled since its semantics
	 * will not be honored.
	 */
	if (turn_on & PHYI_STANDBY) {
		/*
		 * No need to grab ill_g_usesrc_lock here; see the
		 * synchronization notes in ip.c.
		 */
		if (ill->ill_usesrc_grp_next != NULL ||
		    intf_flags & PHYI_INACTIVE)
			return (EINVAL);
		if (!(flags & PHYI_FAILED)) {
			flags |= PHYI_INACTIVE;
			turn_on |= PHYI_INACTIVE;
		}
	}

	if (turn_off & PHYI_STANDBY) {
		flags &= ~PHYI_INACTIVE;
		turn_off |= PHYI_INACTIVE;
	}

	/*
	 * PHYI_FAILED and PHYI_INACTIVE are mutually exclusive; fail if both
	 * would end up on.
	 */
	if ((flags & (PHYI_FAILED | PHYI_INACTIVE)) ==
	    (PHYI_FAILED | PHYI_INACTIVE))
		return (EINVAL);

	/*
	 * If ILLF_ROUTER changes, we need to change the ip forwarding
	 * status of the interface.
	 */
	if ((turn_on | turn_off) & ILLF_ROUTER)
		(void) ill_forward_set(ill, ((turn_on & ILLF_ROUTER) != 0));

	/*
	 * If the interface is not UP and we are not going to
	 * bring it UP, record the flags and return. When the
	 * interface comes UP later, the right actions will be
	 * taken.
	 */
	if (!(ipif->ipif_flags & IPIF_UP) &&
	    !(turn_on & IPIF_UP)) {
		/* Record new flags in their respective places. */
		mutex_enter(&ill->ill_lock);
		mutex_enter(&ill->ill_phyint->phyint_lock);
		ipif->ipif_flags |= (turn_on & IFF_LOGINT_FLAGS);
		ipif->ipif_flags &= (~turn_off & IFF_LOGINT_FLAGS);
		ill->ill_flags |= (turn_on & IFF_PHYINTINST_FLAGS);
		ill->ill_flags &= (~turn_off & IFF_PHYINTINST_FLAGS);
		phyi->phyint_flags |= (turn_on & IFF_PHYINT_FLAGS);
		phyi->phyint_flags &= (~turn_off & IFF_PHYINT_FLAGS);
		mutex_exit(&ill->ill_lock);
		mutex_exit(&ill->ill_phyint->phyint_lock);

		/*
		 * PHYI_FAILED, PHYI_INACTIVE, and PHYI_OFFLINE are all the
		 * same to the kernel: if any of them has been set by
		 * userland, the interface cannot be used for data traffic.
		 */
		if ((turn_on|turn_off) &
		    (PHYI_FAILED | PHYI_INACTIVE | PHYI_OFFLINE)) {
			ASSERT(!IS_IPMP(ill));
			/*
			 * It's possible the ill is part of an "anonymous"
			 * IPMP group rather than a real group.  In that case,
			 * there are no other interfaces in the group and thus
			 * no need to call ipmp_phyint_refresh_active().
			 */
			if (IS_UNDER_IPMP(ill))
				ipmp_phyint_refresh_active(phyi);
		}

		if (phyint_flags_modified) {
			if (phyi->phyint_illv4 != NULL) {
				ip_rts_ifmsg(phyi->phyint_illv4->
				    ill_ipif, RTSQ_DEFAULT);
			}
			if (phyi->phyint_illv6 != NULL) {
				ip_rts_ifmsg(phyi->phyint_illv6->
				    ill_ipif, RTSQ_DEFAULT);
			}
		}
		return (0);
	} else if (set_linklocal || zero_source) {
		mutex_enter(&ill->ill_lock);
		if (set_linklocal)
			ipif->ipif_state_flags |= IPIF_SET_LINKLOCAL;
		if (zero_source)
			ipif->ipif_state_flags |= IPIF_ZERO_SOURCE;
		mutex_exit(&ill->ill_lock);
	}

	/*
	 * Disallow IPv6 interfaces coming up that have the unspecified address,
	 * or point-to-point interfaces with an unspecified destination. We do
	 * allow the address to be unspecified for IPIF_NOLOCAL interfaces that
	 * have a subnet assigned, which is how in.ndpd currently manages its
	 * onlink prefix list when no addresses are configured with those
	 * prefixes.
	 */
	if (ipif->ipif_isv6 &&
	    ((IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr) &&
	    (!(ipif->ipif_flags & IPIF_NOLOCAL) && !(turn_on & IPIF_NOLOCAL) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6subnet))) ||
	    ((ipif->ipif_flags & IPIF_POINTOPOINT) &&
	    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6pp_dst_addr)))) {
		return (EINVAL);
	}

	/*
	 * Prevent IPv4 point-to-point interfaces with a 0.0.0.0 destination
	 * from being brought up.
	 */
	if (!ipif->ipif_isv6 &&
	    ((ipif->ipif_flags & IPIF_POINTOPOINT) &&
	    ipif->ipif_pp_dst_addr == INADDR_ANY)) {
		return (EINVAL);
	}

	/*
	 * The only flag changes that we currently take specific action on are
	 * IPIF_UP, IPIF_DEPRECATED, IPIF_NOXMIT, IPIF_NOLOCAL, ILLF_NOARP,
	 * ILLF_NONUD, IPIF_PRIVATE, IPIF_ANYCAST, IPIF_PREFERRED, and
	 * IPIF_NOFAILOVER.  This is done by bring the ipif down, changing the
	 * flags and bringing it back up again.  For IPIF_NOFAILOVER, the act
	 * of bringing it back up will trigger the address to be moved.
	 */
	if ((turn_on|turn_off) &
	    (IPIF_UP|IPIF_DEPRECATED|IPIF_NOXMIT|IPIF_NOLOCAL|ILLF_NOARP|
	    ILLF_NONUD|IPIF_PRIVATE|IPIF_ANYCAST|IPIF_PREFERRED|
	    IPIF_NOFAILOVER)) {
		/*
		 * Taking this ipif down, make sure we have
		 * valid net and subnet bcast ire's for other
		 * logical interfaces, if we need them.
		 */
		if (!ipif->ipif_isv6)
			ipif_check_bcast_ires(ipif);

		if (((ipif->ipif_flags | turn_on) & IPIF_UP) &&
		    !(turn_off & IPIF_UP)) {
			if (ipif->ipif_flags & IPIF_UP)
				ill->ill_logical_down = 1;
			turn_on &= ~IPIF_UP;
		}
		err = ipif_down(ipif, q, mp);
		ip1dbg(("ipif_down returns %d err ", err));
		if (err == EINPROGRESS)
			return (err);
		ipif_down_tail(ipif);
	}
	return (ip_sioctl_flags_tail(ipif, flags, q, mp));
}

static int
ip_sioctl_flags_tail(ipif_t *ipif, uint64_t flags, queue_t *q, mblk_t *mp)
{
	ill_t	*ill;
	phyint_t *phyi;
	uint64_t turn_on, turn_off;
	uint64_t intf_flags, cantchange_flags;
	boolean_t phyint_flags_modified = B_FALSE;
	int	err = 0;
	boolean_t set_linklocal = B_FALSE;
	boolean_t zero_source = B_FALSE;

	ip1dbg(("ip_sioctl_flags_tail(%s:%u)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id));

	ASSERT(IAM_WRITER_IPIF(ipif));

	ill = ipif->ipif_ill;
	phyi = ill->ill_phyint;

	intf_flags = ipif->ipif_flags | ill->ill_flags | phyi->phyint_flags;
	cantchange_flags = IFF_CANTCHANGE | IFF_UP;
	if (IS_IPMP(ill))
		cantchange_flags |= IFF_IPMP_CANTCHANGE;

	turn_on = (flags ^ intf_flags) & ~cantchange_flags;
	turn_off = intf_flags & turn_on;
	turn_on ^= turn_off;

	if ((turn_on|turn_off) & IFF_PHYINT_FLAGS)
		phyint_flags_modified = B_TRUE;

	/*
	 * Now we change the flags. Track current value of
	 * other flags in their respective places.
	 */
	mutex_enter(&ill->ill_lock);
	mutex_enter(&phyi->phyint_lock);
	ipif->ipif_flags |= (turn_on & IFF_LOGINT_FLAGS);
	ipif->ipif_flags &= (~turn_off & IFF_LOGINT_FLAGS);
	ill->ill_flags |= (turn_on & IFF_PHYINTINST_FLAGS);
	ill->ill_flags &= (~turn_off & IFF_PHYINTINST_FLAGS);
	phyi->phyint_flags |= (turn_on & IFF_PHYINT_FLAGS);
	phyi->phyint_flags &= (~turn_off & IFF_PHYINT_FLAGS);
	if (ipif->ipif_state_flags & IPIF_SET_LINKLOCAL) {
		set_linklocal = B_TRUE;
		ipif->ipif_state_flags &= ~IPIF_SET_LINKLOCAL;
	}
	if (ipif->ipif_state_flags & IPIF_ZERO_SOURCE) {
		zero_source = B_TRUE;
		ipif->ipif_state_flags &= ~IPIF_ZERO_SOURCE;
	}
	mutex_exit(&ill->ill_lock);
	mutex_exit(&phyi->phyint_lock);

	if (set_linklocal)
		(void) ipif_setlinklocal(ipif);

	if (zero_source)
		ipif->ipif_v6src_addr = ipv6_all_zeros;
	else
		ipif->ipif_v6src_addr = ipif->ipif_v6lcl_addr;

	/*
	 * PHYI_FAILED, PHYI_INACTIVE, and PHYI_OFFLINE are all the same to
	 * the kernel: if any of them has been set by userland, the interface
	 * cannot be used for data traffic.
	 */
	if ((turn_on|turn_off) & (PHYI_FAILED | PHYI_INACTIVE | PHYI_OFFLINE)) {
		ASSERT(!IS_IPMP(ill));
		/*
		 * It's possible the ill is part of an "anonymous" IPMP group
		 * rather than a real group.  In that case, there are no other
		 * interfaces in the group and thus no need for us to call
		 * ipmp_phyint_refresh_active().
		 */
		if (IS_UNDER_IPMP(ill))
			ipmp_phyint_refresh_active(phyi);
	}

	if ((flags & IFF_UP) && !(ipif->ipif_flags & IPIF_UP)) {
		/*
		 * XXX ipif_up really does not know whether a phyint flags
		 * was modified or not. So, it sends up information on
		 * only one routing sockets message. As we don't bring up
		 * the interface and also set PHYI_ flags simultaneously
		 * it should be okay.
		 */
		err = ipif_up(ipif, q, mp);
	} else {
		/*
		 * Make sure routing socket sees all changes to the flags.
		 * ipif_up_done* handles this when we use ipif_up.
		 */
		if (phyint_flags_modified) {
			if (phyi->phyint_illv4 != NULL) {
				ip_rts_ifmsg(phyi->phyint_illv4->
				    ill_ipif, RTSQ_DEFAULT);
			}
			if (phyi->phyint_illv6 != NULL) {
				ip_rts_ifmsg(phyi->phyint_illv6->
				    ill_ipif, RTSQ_DEFAULT);
			}
		} else {
			ip_rts_ifmsg(ipif, RTSQ_DEFAULT);
		}
		/*
		 * Update the flags in SCTP's IPIF list, ipif_up() will do
		 * this in need_up case.
		 */
		sctp_update_ipif(ipif, SCTP_IPIF_UPDATE);
	}
	return (err);
}

/*
 * Restart the flags operation now that the refcounts have dropped to zero.
 */
/* ARGSUSED */
int
ip_sioctl_flags_restart(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	uint64_t flags;
	struct ifreq *ifr = if_req;
	struct lifreq *lifr = if_req;

	ip1dbg(("ip_sioctl_flags_restart(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	ipif_down_tail(ipif);
	if (ipip->ipi_cmd_type == IF_CMD) {
		/* cast to uint16_t prevents unwanted sign extension */
		flags = (uint16_t)ifr->ifr_flags;
	} else {
		flags = lifr->lifr_flags;
	}
	return (ip_sioctl_flags_tail(ipif, flags, q, mp));
}

/*
 * Can operate on either a module or a driver queue.
 */
/* ARGSUSED */
int
ip_sioctl_get_flags(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	/*
	 * Has the flags been set correctly till now ?
	 */
	ill_t *ill = ipif->ipif_ill;
	phyint_t *phyi = ill->ill_phyint;

	ip1dbg(("ip_sioctl_get_flags(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ASSERT((phyi->phyint_flags & ~(IFF_PHYINT_FLAGS)) == 0);
	ASSERT((ill->ill_flags & ~(IFF_PHYINTINST_FLAGS)) == 0);
	ASSERT((ipif->ipif_flags & ~(IFF_LOGINT_FLAGS)) == 0);

	/*
	 * Need a lock since some flags can be set even when there are
	 * references to the ipif.
	 */
	mutex_enter(&ill->ill_lock);
	if (ipip->ipi_cmd_type == IF_CMD) {
		struct ifreq *ifr = (struct ifreq *)if_req;

		/* Get interface flags (low 16 only). */
		ifr->ifr_flags = ((ipif->ipif_flags |
		    ill->ill_flags | phyi->phyint_flags) & 0xffff);
	} else {
		struct lifreq *lifr = (struct lifreq *)if_req;

		/* Get interface flags. */
		lifr->lifr_flags = ipif->ipif_flags |
		    ill->ill_flags | phyi->phyint_flags;
	}
	mutex_exit(&ill->ill_lock);
	return (0);
}

/* ARGSUSED */
int
ip_sioctl_mtu(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	int mtu;
	int ip_min_mtu;
	struct ifreq	*ifr;
	struct lifreq *lifr;
	ire_t	*ire;
	ip_stack_t *ipst;

	ip1dbg(("ip_sioctl_mtu(%s:%u %p)\n", ipif->ipif_ill->ill_name,
	    ipif->ipif_id, (void *)ipif));
	if (ipip->ipi_cmd_type == IF_CMD) {
		ifr = (struct ifreq *)if_req;
		mtu = ifr->ifr_metric;
	} else {
		lifr = (struct lifreq *)if_req;
		mtu = lifr->lifr_mtu;
	}

	if (ipif->ipif_isv6)
		ip_min_mtu = IPV6_MIN_MTU;
	else
		ip_min_mtu = IP_MIN_MTU;

	if (mtu > ipif->ipif_ill->ill_max_frag || mtu < ip_min_mtu)
		return (EINVAL);

	/*
	 * Change the MTU size in all relevant ire's.
	 * Mtu change Vs. new ire creation - protocol below.
	 * First change ipif_mtu and the ire_max_frag of the
	 * interface ire. Then do an ire walk and change the
	 * ire_max_frag of all affected ires. During ire_add
	 * under the bucket lock, set the ire_max_frag of the
	 * new ire being created from the ipif/ire from which
	 * it is being derived. If an mtu change happens after
	 * the ire is added, the new ire will be cleaned up.
	 * Conversely if the mtu change happens before the ire
	 * is added, ire_add will see the new value of the mtu.
	 */
	ipif->ipif_mtu = mtu;
	ipif->ipif_flags |= IPIF_FIXEDMTU;

	if (ipif->ipif_isv6)
		ire = ipif_to_ire_v6(ipif);
	else
		ire = ipif_to_ire(ipif);
	if (ire != NULL) {
		ire->ire_max_frag = ipif->ipif_mtu;
		ire_refrele(ire);
	}
	ipst = ipif->ipif_ill->ill_ipst;
	if (ipif->ipif_flags & IPIF_UP) {
		if (ipif->ipif_isv6)
			ire_walk_v6(ipif_mtu_change, (char *)ipif, ALL_ZONES,
			    ipst);
		else
			ire_walk_v4(ipif_mtu_change, (char *)ipif, ALL_ZONES,
			    ipst);
	}
	/* Update the MTU in SCTP's list */
	sctp_update_ipif(ipif, SCTP_IPIF_UPDATE);
	return (0);
}

/* Get interface MTU. */
/* ARGSUSED */
int
ip_sioctl_get_mtu(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
	ip_ioctl_cmd_t *ipip, void *if_req)
{
	struct ifreq	*ifr;
	struct lifreq	*lifr;

	ip1dbg(("ip_sioctl_get_mtu(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	if (ipip->ipi_cmd_type == IF_CMD) {
		ifr = (struct ifreq *)if_req;
		ifr->ifr_metric = ipif->ipif_mtu;
	} else {
		lifr = (struct lifreq *)if_req;
		lifr->lifr_mtu = ipif->ipif_mtu;
	}
	return (0);
}

/* Set interface broadcast address. */
/* ARGSUSED2 */
int
ip_sioctl_brdaddr(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
	ip_ioctl_cmd_t *ipip, void *if_req)
{
	ipaddr_t addr;
	ire_t	*ire;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ip1dbg(("ip_sioctl_brdaddr(%s:%u)\n", ipif->ipif_ill->ill_name,
	    ipif->ipif_id));

	ASSERT(IAM_WRITER_IPIF(ipif));
	if (!(ipif->ipif_flags & IPIF_BROADCAST))
		return (EADDRNOTAVAIL);

	ASSERT(!(ipif->ipif_isv6));	/* No IPv6 broadcast */

	if (sin->sin_family != AF_INET)
		return (EAFNOSUPPORT);

	addr = sin->sin_addr.s_addr;
	if (ipif->ipif_flags & IPIF_UP) {
		/*
		 * If we are already up, make sure the new
		 * broadcast address makes sense.  If it does,
		 * there should be an IRE for it already.
		 * Don't match on ipif, only on the ill
		 * since we are sharing these now.
		 */
		ire = ire_ctable_lookup(addr, 0, IRE_BROADCAST,
		    ipif, ALL_ZONES, NULL,
		    (MATCH_IRE_ILL | MATCH_IRE_TYPE), ipst);
		if (ire == NULL) {
			return (EINVAL);
		} else {
			ire_refrele(ire);
		}
	}
	/*
	 * Changing the broadcast addr for this ipif.
	 * Make sure we have valid net and subnet bcast
	 * ire's for other logical interfaces, if needed.
	 */
	if (addr != ipif->ipif_brd_addr)
		ipif_check_bcast_ires(ipif);
	IN6_IPADDR_TO_V4MAPPED(addr, &ipif->ipif_v6brd_addr);
	return (0);
}

/* Get interface broadcast address. */
/* ARGSUSED */
int
ip_sioctl_get_brdaddr(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	ip1dbg(("ip_sioctl_get_brdaddr(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	if (!(ipif->ipif_flags & IPIF_BROADCAST))
		return (EADDRNOTAVAIL);

	/* IPIF_BROADCAST not possible with IPv6 */
	ASSERT(!ipif->ipif_isv6);
	*sin = sin_null;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ipif->ipif_brd_addr;
	return (0);
}

/*
 * This routine is called to handle the SIOCS*IFNETMASK IOCTL.
 */
/* ARGSUSED */
int
ip_sioctl_netmask(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	int err = 0;
	in6_addr_t v6mask;

	ip1dbg(("ip_sioctl_netmask(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (ipif->ipif_isv6) {
		sin6_t *sin6;

		if (sin->sin_family != AF_INET6)
			return (EAFNOSUPPORT);

		sin6 = (sin6_t *)sin;
		v6mask = sin6->sin6_addr;
	} else {
		ipaddr_t mask;

		if (sin->sin_family != AF_INET)
			return (EAFNOSUPPORT);

		mask = sin->sin_addr.s_addr;
		V4MASK_TO_V6(mask, v6mask);
	}

	/*
	 * No big deal if the interface isn't already up, or the mask
	 * isn't really changing, or this is pt-pt.
	 */
	if (!(ipif->ipif_flags & IPIF_UP) ||
	    IN6_ARE_ADDR_EQUAL(&v6mask, &ipif->ipif_v6net_mask) ||
	    (ipif->ipif_flags & IPIF_POINTOPOINT)) {
		ipif->ipif_v6net_mask = v6mask;
		if ((ipif->ipif_flags & IPIF_POINTOPOINT) == 0) {
			V6_MASK_COPY(ipif->ipif_v6lcl_addr,
			    ipif->ipif_v6net_mask,
			    ipif->ipif_v6subnet);
		}
		return (0);
	}
	/*
	 * Make sure we have valid net and subnet broadcast ire's
	 * for the old netmask, if needed by other logical interfaces.
	 */
	if (!ipif->ipif_isv6)
		ipif_check_bcast_ires(ipif);

	err = ipif_logical_down(ipif, q, mp);
	if (err == EINPROGRESS)
		return (err);
	ipif_down_tail(ipif);
	err = ip_sioctl_netmask_tail(ipif, sin, q, mp);
	return (err);
}

static int
ip_sioctl_netmask_tail(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp)
{
	in6_addr_t v6mask;
	int err = 0;

	ip1dbg(("ip_sioctl_netmask_tail(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	if (ipif->ipif_isv6) {
		sin6_t *sin6;

		sin6 = (sin6_t *)sin;
		v6mask = sin6->sin6_addr;
	} else {
		ipaddr_t mask;

		mask = sin->sin_addr.s_addr;
		V4MASK_TO_V6(mask, v6mask);
	}

	ipif->ipif_v6net_mask = v6mask;
	if ((ipif->ipif_flags & IPIF_POINTOPOINT) == 0) {
		V6_MASK_COPY(ipif->ipif_v6lcl_addr, ipif->ipif_v6net_mask,
		    ipif->ipif_v6subnet);
	}
	err = ipif_up(ipif, q, mp);

	if (err == 0 || err == EINPROGRESS) {
		/*
		 * The interface must be DL_BOUND if this packet has to
		 * go out on the wire. Since we only go through a logical
		 * down and are bound with the driver during an internal
		 * down/up that is satisfied.
		 */
		if (!ipif->ipif_isv6 && ipif->ipif_ill->ill_wq != NULL) {
			/* Potentially broadcast an address mask reply. */
			ipif_mask_reply(ipif);
		}
	}
	return (err);
}

/* ARGSUSED */
int
ip_sioctl_netmask_restart(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	ip1dbg(("ip_sioctl_netmask_restart(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ipif_down_tail(ipif);
	return (ip_sioctl_netmask_tail(ipif, sin, q, mp));
}

/* Get interface net mask. */
/* ARGSUSED */
int
ip_sioctl_get_netmask(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	struct lifreq *lifr = (struct lifreq *)if_req;
	struct sockaddr_in6 *sin6 = (sin6_t *)sin;

	ip1dbg(("ip_sioctl_get_netmask(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	/*
	 * net mask can't change since we have a reference to the ipif.
	 */
	if (ipif->ipif_isv6) {
		ASSERT(ipip->ipi_cmd_type == LIF_CMD);
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = ipif->ipif_v6net_mask;
		lifr->lifr_addrlen =
		    ip_mask_to_plen_v6(&ipif->ipif_v6net_mask);
	} else {
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ipif->ipif_net_mask;
		if (ipip->ipi_cmd_type == LIF_CMD) {
			lifr->lifr_addrlen =
			    ip_mask_to_plen(ipif->ipif_net_mask);
		}
	}
	return (0);
}

/* ARGSUSED */
int
ip_sioctl_metric(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	ip1dbg(("ip_sioctl_metric(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	/*
	 * Since no applications should ever be setting metrics on underlying
	 * interfaces, we explicitly fail to smoke 'em out.
	 */
	if (IS_UNDER_IPMP(ipif->ipif_ill))
		return (EINVAL);

	/*
	 * Set interface metric.  We don't use this for
	 * anything but we keep track of it in case it is
	 * important to routing applications or such.
	 */
	if (ipip->ipi_cmd_type == IF_CMD) {
		struct ifreq    *ifr;

		ifr = (struct ifreq *)if_req;
		ipif->ipif_metric = ifr->ifr_metric;
	} else {
		struct lifreq   *lifr;

		lifr = (struct lifreq *)if_req;
		ipif->ipif_metric = lifr->lifr_metric;
	}
	return (0);
}

/* ARGSUSED */
int
ip_sioctl_get_metric(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	/* Get interface metric. */
	ip1dbg(("ip_sioctl_get_metric(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	if (ipip->ipi_cmd_type == IF_CMD) {
		struct ifreq    *ifr;

		ifr = (struct ifreq *)if_req;
		ifr->ifr_metric = ipif->ipif_metric;
	} else {
		struct lifreq   *lifr;

		lifr = (struct lifreq *)if_req;
		lifr->lifr_metric = ipif->ipif_metric;
	}

	return (0);
}

/* ARGSUSED */
int
ip_sioctl_muxid(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{

	ip1dbg(("ip_sioctl_muxid(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	/*
	 * Set the muxid returned from I_PLINK.
	 */
	if (ipip->ipi_cmd_type == IF_CMD) {
		struct ifreq *ifr = (struct ifreq *)if_req;

		ipif->ipif_ill->ill_ip_muxid = ifr->ifr_ip_muxid;
		ipif->ipif_ill->ill_arp_muxid = ifr->ifr_arp_muxid;
	} else {
		struct lifreq *lifr = (struct lifreq *)if_req;

		ipif->ipif_ill->ill_ip_muxid = lifr->lifr_ip_muxid;
		ipif->ipif_ill->ill_arp_muxid = lifr->lifr_arp_muxid;
	}
	return (0);
}

/* ARGSUSED */
int
ip_sioctl_get_muxid(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{

	ip1dbg(("ip_sioctl_get_muxid(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	/*
	 * Get the muxid saved in ill for I_PUNLINK.
	 */
	if (ipip->ipi_cmd_type == IF_CMD) {
		struct ifreq *ifr = (struct ifreq *)if_req;

		ifr->ifr_ip_muxid = ipif->ipif_ill->ill_ip_muxid;
		ifr->ifr_arp_muxid = ipif->ipif_ill->ill_arp_muxid;
	} else {
		struct lifreq *lifr = (struct lifreq *)if_req;

		lifr->lifr_ip_muxid = ipif->ipif_ill->ill_ip_muxid;
		lifr->lifr_arp_muxid = ipif->ipif_ill->ill_arp_muxid;
	}
	return (0);
}

/*
 * Set the subnet prefix. Does not modify the broadcast address.
 */
/* ARGSUSED */
int
ip_sioctl_subnet(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	int err = 0;
	in6_addr_t v6addr;
	in6_addr_t v6mask;
	boolean_t need_up = B_FALSE;
	int addrlen;

	ip1dbg(("ip_sioctl_subnet(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	ASSERT(IAM_WRITER_IPIF(ipif));
	addrlen = ((struct lifreq *)if_req)->lifr_addrlen;

	if (ipif->ipif_isv6) {
		sin6_t *sin6;

		if (sin->sin_family != AF_INET6)
			return (EAFNOSUPPORT);

		sin6 = (sin6_t *)sin;
		v6addr = sin6->sin6_addr;
		if (!ip_remote_addr_ok_v6(&v6addr, &ipv6_all_ones))
			return (EADDRNOTAVAIL);
	} else {
		ipaddr_t addr;

		if (sin->sin_family != AF_INET)
			return (EAFNOSUPPORT);

		addr = sin->sin_addr.s_addr;
		if (!ip_addr_ok_v4(addr, 0xFFFFFFFF))
			return (EADDRNOTAVAIL);
		IN6_IPADDR_TO_V4MAPPED(addr, &v6addr);
		/* Add 96 bits */
		addrlen += IPV6_ABITS - IP_ABITS;
	}

	if (ip_plen_to_mask_v6(addrlen, &v6mask) == NULL)
		return (EINVAL);

	/* Check if bits in the address is set past the mask */
	if (!V6_MASK_EQ(v6addr, v6mask, v6addr))
		return (EINVAL);

	if (IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6subnet, &v6addr) &&
	    IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6net_mask, &v6mask))
		return (0);	/* No change */

	if (ipif->ipif_flags & IPIF_UP) {
		/*
		 * If the interface is already marked up,
		 * we call ipif_down which will take care
		 * of ditching any IREs that have been set
		 * up based on the old interface address.
		 */
		err = ipif_logical_down(ipif, q, mp);
		if (err == EINPROGRESS)
			return (err);
		ipif_down_tail(ipif);
		need_up = B_TRUE;
	}

	err = ip_sioctl_subnet_tail(ipif, v6addr, v6mask, q, mp, need_up);
	return (err);
}

static int
ip_sioctl_subnet_tail(ipif_t *ipif, in6_addr_t v6addr, in6_addr_t v6mask,
    queue_t *q, mblk_t *mp, boolean_t need_up)
{
	ill_t	*ill = ipif->ipif_ill;
	int	err = 0;

	ip1dbg(("ip_sioctl_subnet_tail(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	/* Set the new address. */
	mutex_enter(&ill->ill_lock);
	ipif->ipif_v6net_mask = v6mask;
	if ((ipif->ipif_flags & IPIF_POINTOPOINT) == 0) {
		V6_MASK_COPY(v6addr, ipif->ipif_v6net_mask,
		    ipif->ipif_v6subnet);
	}
	mutex_exit(&ill->ill_lock);

	if (need_up) {
		/*
		 * Now bring the interface back up.  If this
		 * is the only IPIF for the ILL, ipif_up
		 * will have to re-bind to the device, so
		 * we may get back EINPROGRESS, in which
		 * case, this IOCTL will get completed in
		 * ip_rput_dlpi when we see the DL_BIND_ACK.
		 */
		err = ipif_up(ipif, q, mp);
		if (err == EINPROGRESS)
			return (err);
	}
	return (err);
}

/* ARGSUSED */
int
ip_sioctl_subnet_restart(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	int	addrlen;
	in6_addr_t v6addr;
	in6_addr_t v6mask;
	struct lifreq *lifr = (struct lifreq *)if_req;

	ip1dbg(("ip_sioctl_subnet_restart(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ipif_down_tail(ipif);

	addrlen = lifr->lifr_addrlen;
	if (ipif->ipif_isv6) {
		sin6_t *sin6;

		sin6 = (sin6_t *)sin;
		v6addr = sin6->sin6_addr;
	} else {
		ipaddr_t addr;

		addr = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(addr, &v6addr);
		addrlen += IPV6_ABITS - IP_ABITS;
	}
	(void) ip_plen_to_mask_v6(addrlen, &v6mask);

	return (ip_sioctl_subnet_tail(ipif, v6addr, v6mask, q, mp, B_TRUE));
}

/* ARGSUSED */
int
ip_sioctl_get_subnet(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	struct lifreq *lifr = (struct lifreq *)if_req;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sin;

	ip1dbg(("ip_sioctl_get_subnet(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ASSERT(ipip->ipi_cmd_type == LIF_CMD);

	if (ipif->ipif_isv6) {
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = ipif->ipif_v6subnet;
		lifr->lifr_addrlen =
		    ip_mask_to_plen_v6(&ipif->ipif_v6net_mask);
	} else {
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ipif->ipif_subnet;
		lifr->lifr_addrlen = ip_mask_to_plen(ipif->ipif_net_mask);
	}
	return (0);
}

/*
 * Set the IPv6 address token.
 */
/* ARGSUSED */
int
ip_sioctl_token(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipi, void *if_req)
{
	ill_t *ill = ipif->ipif_ill;
	int err;
	in6_addr_t v6addr;
	in6_addr_t v6mask;
	boolean_t need_up = B_FALSE;
	int i;
	sin6_t *sin6 = (sin6_t *)sin;
	struct lifreq *lifr = (struct lifreq *)if_req;
	int addrlen;

	ip1dbg(("ip_sioctl_token(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	ASSERT(IAM_WRITER_IPIF(ipif));

	addrlen = lifr->lifr_addrlen;
	/* Only allow for logical unit zero i.e. not on "le0:17" */
	if (ipif->ipif_id != 0)
		return (EINVAL);

	if (!ipif->ipif_isv6)
		return (EINVAL);

	if (addrlen > IPV6_ABITS)
		return (EINVAL);

	v6addr = sin6->sin6_addr;

	/*
	 * The length of the token is the length from the end.  To get
	 * the proper mask for this, compute the mask of the bits not
	 * in the token; ie. the prefix, and then xor to get the mask.
	 */
	if (ip_plen_to_mask_v6(IPV6_ABITS - addrlen, &v6mask) == NULL)
		return (EINVAL);
	for (i = 0; i < 4; i++) {
		v6mask.s6_addr32[i] ^= (uint32_t)0xffffffff;
	}

	if (V6_MASK_EQ(v6addr, v6mask, ill->ill_token) &&
	    ill->ill_token_length == addrlen)
		return (0);	/* No change */

	if (ipif->ipif_flags & IPIF_UP) {
		err = ipif_logical_down(ipif, q, mp);
		if (err == EINPROGRESS)
			return (err);
		ipif_down_tail(ipif);
		need_up = B_TRUE;
	}
	err = ip_sioctl_token_tail(ipif, sin6, addrlen, q, mp, need_up);
	return (err);
}

static int
ip_sioctl_token_tail(ipif_t *ipif, sin6_t *sin6, int addrlen, queue_t *q,
    mblk_t *mp, boolean_t need_up)
{
	in6_addr_t v6addr;
	in6_addr_t v6mask;
	ill_t	*ill = ipif->ipif_ill;
	int	i;
	int	err = 0;

	ip1dbg(("ip_sioctl_token_tail(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	v6addr = sin6->sin6_addr;
	/*
	 * The length of the token is the length from the end.  To get
	 * the proper mask for this, compute the mask of the bits not
	 * in the token; ie. the prefix, and then xor to get the mask.
	 */
	(void) ip_plen_to_mask_v6(IPV6_ABITS - addrlen, &v6mask);
	for (i = 0; i < 4; i++)
		v6mask.s6_addr32[i] ^= (uint32_t)0xffffffff;

	mutex_enter(&ill->ill_lock);
	V6_MASK_COPY(v6addr, v6mask, ill->ill_token);
	ill->ill_token_length = addrlen;
	mutex_exit(&ill->ill_lock);

	if (need_up) {
		/*
		 * Now bring the interface back up.  If this
		 * is the only IPIF for the ILL, ipif_up
		 * will have to re-bind to the device, so
		 * we may get back EINPROGRESS, in which
		 * case, this IOCTL will get completed in
		 * ip_rput_dlpi when we see the DL_BIND_ACK.
		 */
		err = ipif_up(ipif, q, mp);
		if (err == EINPROGRESS)
			return (err);
	}
	return (err);
}

/* ARGSUSED */
int
ip_sioctl_get_token(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipi, void *if_req)
{
	ill_t *ill;
	sin6_t *sin6 = (sin6_t *)sin;
	struct lifreq *lifr = (struct lifreq *)if_req;

	ip1dbg(("ip_sioctl_get_token(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	if (ipif->ipif_id != 0)
		return (EINVAL);

	ill = ipif->ipif_ill;
	if (!ill->ill_isv6)
		return (ENXIO);

	*sin6 = sin6_null;
	sin6->sin6_family = AF_INET6;
	ASSERT(!IN6_IS_ADDR_V4MAPPED(&ill->ill_token));
	sin6->sin6_addr = ill->ill_token;
	lifr->lifr_addrlen = ill->ill_token_length;
	return (0);
}

/*
 * Set (hardware) link specific information that might override
 * what was acquired through the DL_INFO_ACK.
 * The logic is as follows.
 *
 * become exclusive
 * set CHANGING flag
 * change mtu on affected IREs
 * clear CHANGING flag
 *
 * An ire add that occurs before the CHANGING flag is set will have its mtu
 * changed by the ip_sioctl_lnkinfo.
 *
 * During the time the CHANGING flag is set, no new ires will be added to the
 * bucket, and ire add will fail (due the CHANGING flag).
 *
 * An ire add that occurs after the CHANGING flag is set will have the right mtu
 * before it is added to the bucket.
 *
 * Obviously only 1 thread can set the CHANGING flag and we need to become
 * exclusive to set the flag.
 */
/* ARGSUSED */
int
ip_sioctl_lnkinfo(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipi, void *if_req)
{
	ill_t		*ill = ipif->ipif_ill;
	ipif_t		*nipif;
	int		ip_min_mtu;
	boolean_t	mtu_walk = B_FALSE;
	struct lifreq	*lifr = (struct lifreq *)if_req;
	lif_ifinfo_req_t *lir;
	ire_t		*ire;

	ip1dbg(("ip_sioctl_lnkinfo(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	lir = &lifr->lifr_ifinfo;
	ASSERT(IAM_WRITER_IPIF(ipif));

	/* Only allow for logical unit zero i.e. not on "le0:17" */
	if (ipif->ipif_id != 0)
		return (EINVAL);

	/* Set interface MTU. */
	if (ipif->ipif_isv6)
		ip_min_mtu = IPV6_MIN_MTU;
	else
		ip_min_mtu = IP_MIN_MTU;

	/*
	 * Verify values before we set anything. Allow zero to
	 * mean unspecified.
	 */
	if (lir->lir_maxmtu != 0 &&
	    (lir->lir_maxmtu > ill->ill_max_frag ||
	    lir->lir_maxmtu < ip_min_mtu))
		return (EINVAL);
	if (lir->lir_reachtime != 0 &&
	    lir->lir_reachtime > ND_MAX_REACHTIME)
		return (EINVAL);
	if (lir->lir_reachretrans != 0 &&
	    lir->lir_reachretrans > ND_MAX_REACHRETRANSTIME)
		return (EINVAL);

	mutex_enter(&ill->ill_lock);
	ill->ill_state_flags |= ILL_CHANGING;
	for (nipif = ill->ill_ipif; nipif != NULL;
	    nipif = nipif->ipif_next) {
		nipif->ipif_state_flags |= IPIF_CHANGING;
	}

	if (lir->lir_maxmtu != 0) {
		ill->ill_max_mtu = lir->lir_maxmtu;
		ill->ill_user_mtu = lir->lir_maxmtu;
		mtu_walk = B_TRUE;
	}
	mutex_exit(&ill->ill_lock);

	if (lir->lir_reachtime != 0)
		ill->ill_reachable_time = lir->lir_reachtime;

	if (lir->lir_reachretrans != 0)
		ill->ill_reachable_retrans_time = lir->lir_reachretrans;

	ill->ill_max_hops = lir->lir_maxhops;

	ill->ill_max_buf = ND_MAX_Q;

	if (mtu_walk) {
		/*
		 * Set the MTU on all ipifs associated with this ill except
		 * for those whose MTU was fixed via SIOCSLIFMTU.
		 */
		for (nipif = ill->ill_ipif; nipif != NULL;
		    nipif = nipif->ipif_next) {
			if (nipif->ipif_flags & IPIF_FIXEDMTU)
				continue;

			nipif->ipif_mtu = ill->ill_max_mtu;

			if (!(nipif->ipif_flags & IPIF_UP))
				continue;

			if (nipif->ipif_isv6)
				ire = ipif_to_ire_v6(nipif);
			else
				ire = ipif_to_ire(nipif);
			if (ire != NULL) {
				ire->ire_max_frag = ipif->ipif_mtu;
				ire_refrele(ire);
			}

			ire_walk_ill(MATCH_IRE_ILL, 0, ipif_mtu_change,
			    nipif, ill);
		}
	}

	mutex_enter(&ill->ill_lock);
	for (nipif = ill->ill_ipif; nipif != NULL;
	    nipif = nipif->ipif_next) {
		nipif->ipif_state_flags &= ~IPIF_CHANGING;
	}
	ILL_UNMARK_CHANGING(ill);
	mutex_exit(&ill->ill_lock);

	/*
	 * Refresh IPMP meta-interface MTU if necessary.
	 */
	if (IS_UNDER_IPMP(ill))
		ipmp_illgrp_refresh_mtu(ill->ill_grp);

	return (0);
}

/* ARGSUSED */
int
ip_sioctl_get_lnkinfo(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipi, void *if_req)
{
	struct lif_ifinfo_req *lir;
	ill_t *ill = ipif->ipif_ill;

	ip1dbg(("ip_sioctl_get_lnkinfo(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	if (ipif->ipif_id != 0)
		return (EINVAL);

	lir = &((struct lifreq *)if_req)->lifr_ifinfo;
	lir->lir_maxhops = ill->ill_max_hops;
	lir->lir_reachtime = ill->ill_reachable_time;
	lir->lir_reachretrans = ill->ill_reachable_retrans_time;
	lir->lir_maxmtu = ill->ill_max_mtu;

	return (0);
}

/*
 * Return best guess as to the subnet mask for the specified address.
 * Based on the subnet masks for all the configured interfaces.
 *
 * We end up returning a zero mask in the case of default, multicast or
 * experimental.
 */
static ipaddr_t
ip_subnet_mask(ipaddr_t addr, ipif_t **ipifp, ip_stack_t *ipst)
{
	ipaddr_t net_mask;
	ill_t	*ill;
	ipif_t	*ipif;
	ill_walk_context_t ctx;
	ipif_t	*fallback_ipif = NULL;

	net_mask = ip_net_mask(addr);
	if (net_mask == 0) {
		*ipifp = NULL;
		return (0);
	}

	/* Let's check to see if this is maybe a local subnet route. */
	/* this function only applies to IPv4 interfaces */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (!IPIF_CAN_LOOKUP(ipif))
				continue;
			if (!(ipif->ipif_flags & IPIF_UP))
				continue;
			if ((ipif->ipif_subnet & net_mask) ==
			    (addr & net_mask)) {
				/*
				 * Don't trust pt-pt interfaces if there are
				 * other interfaces.
				 */
				if (ipif->ipif_flags & IPIF_POINTOPOINT) {
					if (fallback_ipif == NULL) {
						ipif_refhold_locked(ipif);
						fallback_ipif = ipif;
					}
					continue;
				}

				/*
				 * Fine. Just assume the same net mask as the
				 * directly attached subnet interface is using.
				 */
				ipif_refhold_locked(ipif);
				mutex_exit(&ill->ill_lock);
				rw_exit(&ipst->ips_ill_g_lock);
				if (fallback_ipif != NULL)
					ipif_refrele(fallback_ipif);
				*ipifp = ipif;
				return (ipif->ipif_net_mask);
			}
		}
		mutex_exit(&ill->ill_lock);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	*ipifp = fallback_ipif;
	return ((fallback_ipif != NULL) ?
	    fallback_ipif->ipif_net_mask : net_mask);
}

/*
 * ip_sioctl_copyin_setup calls ip_wput_ioctl to process the IP_IOCTL ioctl.
 */
static void
ip_wput_ioctl(queue_t *q, mblk_t *mp)
{
	IOCP	iocp;
	ipft_t	*ipft;
	ipllc_t	*ipllc;
	mblk_t	*mp1;
	cred_t	*cr;
	int	error = 0;
	conn_t	*connp;

	ip1dbg(("ip_wput_ioctl"));
	iocp = (IOCP)mp->b_rptr;
	mp1 = mp->b_cont;
	if (mp1 == NULL) {
		iocp->ioc_error = EINVAL;
		mp->b_datap->db_type = M_IOCNAK;
		iocp->ioc_count = 0;
		qreply(q, mp);
		return;
	}

	/*
	 * These IOCTLs provide various control capabilities to
	 * upstream agents such as ULPs and processes.	There
	 * are currently two such IOCTLs implemented.  They
	 * are used by TCP to provide update information for
	 * existing IREs and to forcibly delete an IRE for a
	 * host that is not responding, thereby forcing an
	 * attempt at a new route.
	 */
	iocp->ioc_error = EINVAL;
	if (!pullupmsg(mp1, sizeof (ipllc->ipllc_cmd)))
		goto done;

	ipllc = (ipllc_t *)mp1->b_rptr;
	for (ipft = ip_ioctl_ftbl; ipft->ipft_pfi; ipft++) {
		if (ipllc->ipllc_cmd == ipft->ipft_cmd)
			break;
	}
	/*
	 * prefer credential from mblk over ioctl;
	 * see ip_sioctl_copyin_setup
	 */
	cr = DB_CREDDEF(mp, iocp->ioc_cr);

	/*
	 * Refhold the conn in case the request gets queued up in some lookup
	 */
	ASSERT(CONN_Q(q));
	connp = Q_TO_CONN(q);
	CONN_INC_REF(connp);
	if (ipft->ipft_pfi &&
	    ((mp1->b_wptr - mp1->b_rptr) >= ipft->ipft_min_size ||
	    pullupmsg(mp1, ipft->ipft_min_size))) {
		error = (*ipft->ipft_pfi)(q,
		    (ipft->ipft_flags & IPFT_F_SELF_REPLY) ? mp : mp1, cr);
	}
	if (ipft->ipft_flags & IPFT_F_SELF_REPLY) {
		/*
		 * CONN_OPER_PENDING_DONE happens in the function called
		 * through ipft_pfi above.
		 */
		return;
	}

	CONN_OPER_PENDING_DONE(connp);
	if (ipft->ipft_flags & IPFT_F_NO_REPLY) {
		freemsg(mp);
		return;
	}
	iocp->ioc_error = error;

done:
	mp->b_datap->db_type = M_IOCACK;
	if (iocp->ioc_error)
		iocp->ioc_count = 0;
	qreply(q, mp);
}

/*
 * Lookup an ipif using the sequence id (ipif_seqid)
 */
ipif_t *
ipif_lookup_seqid(ill_t *ill, uint_t seqid)
{
	ipif_t *ipif;

	ASSERT(MUTEX_HELD(&ill->ill_lock));

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (ipif->ipif_seqid == seqid && IPIF_CAN_LOOKUP(ipif))
			return (ipif);
	}
	return (NULL);
}

/*
 * Assign a unique id for the ipif. This is used later when we send
 * IRES to ARP for resolution where we initialize ire_ipif_seqid
 * to the value pointed by ire_ipif->ipif_seqid. Later when the
 * IRE is added, we verify that ipif has not disappeared.
 */

static void
ipif_assign_seqid(ipif_t *ipif)
{
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ipif->ipif_seqid = atomic_add_64_nv(&ipst->ips_ipif_g_seqid, 1);
}

/*
 * Clone the contents of `sipif' to `dipif'.  Requires that both ipifs are
 * administratively down (i.e., no DAD), of the same type, and locked.  Note
 * that the clone is complete -- including the seqid -- and the expectation is
 * that the caller will either free or overwrite `sipif' before it's unlocked.
 */
static void
ipif_clone(const ipif_t *sipif, ipif_t *dipif)
{
	ASSERT(MUTEX_HELD(&sipif->ipif_ill->ill_lock));
	ASSERT(MUTEX_HELD(&dipif->ipif_ill->ill_lock));
	ASSERT(!(sipif->ipif_flags & (IPIF_UP|IPIF_DUPLICATE)));
	ASSERT(!(dipif->ipif_flags & (IPIF_UP|IPIF_DUPLICATE)));
	ASSERT(sipif->ipif_ire_type == dipif->ipif_ire_type);
	ASSERT(sipif->ipif_arp_del_mp == NULL);
	ASSERT(dipif->ipif_arp_del_mp == NULL);
	ASSERT(sipif->ipif_igmp_rpt == NULL);
	ASSERT(dipif->ipif_igmp_rpt == NULL);
	ASSERT(sipif->ipif_multicast_up == 0);
	ASSERT(dipif->ipif_multicast_up == 0);
	ASSERT(sipif->ipif_joined_allhosts == 0);
	ASSERT(dipif->ipif_joined_allhosts == 0);

	dipif->ipif_mtu = sipif->ipif_mtu;
	dipif->ipif_flags = sipif->ipif_flags;
	dipif->ipif_metric = sipif->ipif_metric;
	dipif->ipif_zoneid = sipif->ipif_zoneid;
	dipif->ipif_v6subnet = sipif->ipif_v6subnet;
	dipif->ipif_v6lcl_addr = sipif->ipif_v6lcl_addr;
	dipif->ipif_v6src_addr = sipif->ipif_v6src_addr;
	dipif->ipif_v6net_mask = sipif->ipif_v6net_mask;
	dipif->ipif_v6brd_addr = sipif->ipif_v6brd_addr;
	dipif->ipif_v6pp_dst_addr = sipif->ipif_v6pp_dst_addr;

	/*
	 * While dipif is down right now, it might've been up before.  Since
	 * it's changing identity, its packet counters need to be reset.
	 */
	dipif->ipif_ib_pkt_count = 0;
	dipif->ipif_ob_pkt_count = 0;
	dipif->ipif_fo_pkt_count = 0;

	/*
	 * As per the comment atop the function, we assume that these sipif
	 * fields will be changed before sipif is unlocked.
	 */
	dipif->ipif_seqid = sipif->ipif_seqid;
	dipif->ipif_saved_ire_mp = sipif->ipif_saved_ire_mp;
	dipif->ipif_saved_ire_cnt = sipif->ipif_saved_ire_cnt;
	dipif->ipif_state_flags = sipif->ipif_state_flags;
}

/*
 * Transfer the contents of `sipif' to `dipif', and then free (if `virgipif'
 * is NULL) or overwrite `sipif' with `virgipif', which must be a virgin
 * (unreferenced) ipif.  Also, if `sipif' is used by the current xop, then
 * transfer the xop to `dipif'.  Requires that all ipifs are administratively
 * down (i.e., no DAD), of the same type, and unlocked.
 */
static void
ipif_transfer(ipif_t *sipif, ipif_t *dipif, ipif_t *virgipif)
{
	ipsq_t *ipsq = sipif->ipif_ill->ill_phyint->phyint_ipsq;
	int ipx_current_ioctl;

	ASSERT(sipif != dipif);
	ASSERT(sipif != virgipif);

	/*
	 * Grab all of the locks that protect the ipif in a defined order.
	 */
	GRAB_ILL_LOCKS(sipif->ipif_ill, dipif->ipif_ill);
	if (sipif > dipif) {
		mutex_enter(&sipif->ipif_saved_ire_lock);
		mutex_enter(&dipif->ipif_saved_ire_lock);
	} else {
		mutex_enter(&dipif->ipif_saved_ire_lock);
		mutex_enter(&sipif->ipif_saved_ire_lock);
	}

	ipif_clone(sipif, dipif);
	if (virgipif != NULL) {
		ipif_clone(virgipif, sipif);
		mi_free(virgipif);
	}

	mutex_exit(&sipif->ipif_saved_ire_lock);
	mutex_exit(&dipif->ipif_saved_ire_lock);
	RELEASE_ILL_LOCKS(sipif->ipif_ill, dipif->ipif_ill);

	/*
	 * Transfer ownership of the current xop, if necessary.
	 */
	if (ipsq->ipsq_xop->ipx_current_ipif == sipif) {
		ASSERT(ipsq->ipsq_xop->ipx_pending_ipif == NULL);
		ipx_current_ioctl = ipsq->ipsq_xop->ipx_current_ioctl;
		ipsq_current_finish(ipsq);
		ipsq_current_start(ipsq, dipif, ipx_current_ioctl);
	}

	if (virgipif == NULL)
		mi_free(sipif);
}

/*
 * Insert the ipif, so that the list of ipifs on the ill will be sorted
 * with respect to ipif_id. Note that an ipif with an ipif_id of -1 will
 * be inserted into the first space available in the list. The value of
 * ipif_id will then be set to the appropriate value for its position.
 */
static int
ipif_insert(ipif_t *ipif, boolean_t acquire_g_lock)
{
	ill_t *ill;
	ipif_t *tipif;
	ipif_t **tipifp;
	int id;
	ip_stack_t	*ipst;

	ASSERT(ipif->ipif_ill->ill_net_type == IRE_LOOPBACK ||
	    IAM_WRITER_IPIF(ipif));

	ill = ipif->ipif_ill;
	ASSERT(ill != NULL);
	ipst = ill->ill_ipst;

	/*
	 * In the case of lo0:0 we already hold the ill_g_lock.
	 * ill_lookup_on_name (acquires ill_g_lock) -> ipif_allocate ->
	 * ipif_insert.
	 */
	if (acquire_g_lock)
		rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	mutex_enter(&ill->ill_lock);
	id = ipif->ipif_id;
	tipifp = &(ill->ill_ipif);
	if (id == -1) {	/* need to find a real id */
		id = 0;
		while ((tipif = *tipifp) != NULL) {
			ASSERT(tipif->ipif_id >= id);
			if (tipif->ipif_id != id)
				break; /* non-consecutive id */
			id++;
			tipifp = &(tipif->ipif_next);
		}
		/* limit number of logical interfaces */
		if (id >= ipst->ips_ip_addrs_per_if) {
			mutex_exit(&ill->ill_lock);
			if (acquire_g_lock)
				rw_exit(&ipst->ips_ill_g_lock);
			return (-1);
		}
		ipif->ipif_id = id; /* assign new id */
	} else if (id < ipst->ips_ip_addrs_per_if) {
		/* we have a real id; insert ipif in the right place */
		while ((tipif = *tipifp) != NULL) {
			ASSERT(tipif->ipif_id != id);
			if (tipif->ipif_id > id)
				break; /* found correct location */
			tipifp = &(tipif->ipif_next);
		}
	} else {
		mutex_exit(&ill->ill_lock);
		if (acquire_g_lock)
			rw_exit(&ipst->ips_ill_g_lock);
		return (-1);
	}

	ASSERT(tipifp != &(ill->ill_ipif) || id == 0);

	ipif->ipif_next = tipif;
	*tipifp = ipif;
	mutex_exit(&ill->ill_lock);
	if (acquire_g_lock)
		rw_exit(&ipst->ips_ill_g_lock);

	return (0);
}

static void
ipif_remove(ipif_t *ipif)
{
	ipif_t	**ipifp;
	ill_t	*ill = ipif->ipif_ill;

	ASSERT(RW_WRITE_HELD(&ill->ill_ipst->ips_ill_g_lock));

	mutex_enter(&ill->ill_lock);
	ipifp = &ill->ill_ipif;
	for (; *ipifp != NULL; ipifp = &ipifp[0]->ipif_next) {
		if (*ipifp == ipif) {
			*ipifp = ipif->ipif_next;
			break;
		}
	}
	mutex_exit(&ill->ill_lock);
}

/*
 * Allocate and initialize a new interface control structure.  (Always
 * called as writer.)
 * When ipif_allocate() is called from ip_ll_subnet_defaults, the ill
 * is not part of the global linked list of ills. ipif_seqid is unique
 * in the system and to preserve the uniqueness, it is assigned only
 * when ill becomes part of the global list. At that point ill will
 * have a name. If it doesn't get assigned here, it will get assigned
 * in ipif_set_values() as part of SIOCSLIFNAME processing.
 * Aditionally, if we come here from ip_ll_subnet_defaults, we don't set
 * the interface flags or any other information from the DL_INFO_ACK for
 * DL_STYLE2 drivers (initialize == B_FALSE), since we won't have them at
 * this point. The flags etc. will be set in ip_ll_subnet_defaults when the
 * second DL_INFO_ACK comes in from the driver.
 */
static ipif_t *
ipif_allocate(ill_t *ill, int id, uint_t ire_type, boolean_t initialize,
    boolean_t insert)
{
	ipif_t	*ipif;
	phyint_t *phyi = ill->ill_phyint;
	ip_stack_t *ipst = ill->ill_ipst;

	ip1dbg(("ipif_allocate(%s:%d ill %p)\n",
	    ill->ill_name, id, (void *)ill));
	ASSERT(ire_type == IRE_LOOPBACK || IAM_WRITER_ILL(ill));

	if ((ipif = (ipif_t *)mi_alloc(sizeof (ipif_t), BPRI_MED)) == NULL)
		return (NULL);
	*ipif = ipif_zero;	/* start clean */

	ipif->ipif_ill = ill;
	ipif->ipif_id = id;	/* could be -1 */
	/*
	 * Inherit the zoneid from the ill; for the shared stack instance
	 * this is always the global zone
	 */
	ipif->ipif_zoneid = ill->ill_zoneid;

	mutex_init(&ipif->ipif_saved_ire_lock, NULL, MUTEX_DEFAULT, NULL);

	ipif->ipif_refcnt = 0;
	ipif->ipif_saved_ire_cnt = 0;

	if (insert) {
		if (ipif_insert(ipif, ire_type != IRE_LOOPBACK) != 0) {
			mi_free(ipif);
			return (NULL);
		}
		/* -1 id should have been replaced by real id */
		id = ipif->ipif_id;
		ASSERT(id >= 0);
	}

	if (ill->ill_name[0] != '\0')
		ipif_assign_seqid(ipif);

	/*
	 * If this is ipif zero, configure ill/phyint-wide information.
	 * Defer most configuration until we're guaranteed we're attached.
	 */
	if (id == 0) {
		if (ill->ill_mactype == SUNW_DL_IPMP) {
			/*
			 * Set PHYI_IPMP and also set PHYI_FAILED since there
			 * are no active interfaces.  Similarly, PHYI_RUNNING
			 * isn't set until the group has an active interface.
			 */
			mutex_enter(&phyi->phyint_lock);
			phyi->phyint_flags |= (PHYI_IPMP | PHYI_FAILED);
			mutex_exit(&phyi->phyint_lock);

			/*
			 * Create the illgrp (which must not exist yet because
			 * the zeroth ipif is created once per ill).  However,
			 * do not not link it to the ipmp_grp_t until I_PLINK
			 * is called; see ip_sioctl_plink_ipmp() for details.
			 */
			if (ipmp_illgrp_create(ill) == NULL) {
				if (insert) {
					rw_enter(&ipst->ips_ill_g_lock,
					    RW_WRITER);
					ipif_remove(ipif);
					rw_exit(&ipst->ips_ill_g_lock);
				}
				mi_free(ipif);
				return (NULL);
			}
		} else {
			/*
			 * By default, PHYI_RUNNING is set when the zeroth
			 * ipif is created.  For other ipifs, we don't touch
			 * it since DLPI notifications may have changed it.
			 */
			mutex_enter(&phyi->phyint_lock);
			phyi->phyint_flags |= PHYI_RUNNING;
			mutex_exit(&phyi->phyint_lock);
		}
	}

	/*
	 * We grab the ill_lock and phyint_lock to protect the flag changes.
	 * The ipif is still not up and can't be looked up until the
	 * ioctl completes and the IPIF_CHANGING flag is cleared.
	 */
	mutex_enter(&ill->ill_lock);
	mutex_enter(&phyi->phyint_lock);

	ipif->ipif_ire_type = ire_type;

	if (ipif->ipif_isv6) {
		ill->ill_flags |= ILLF_IPV6;
	} else {
		ipaddr_t inaddr_any = INADDR_ANY;

		ill->ill_flags |= ILLF_IPV4;

		/* Keep the IN6_IS_ADDR_V4MAPPED assertions happy */
		IN6_IPADDR_TO_V4MAPPED(inaddr_any,
		    &ipif->ipif_v6lcl_addr);
		IN6_IPADDR_TO_V4MAPPED(inaddr_any,
		    &ipif->ipif_v6src_addr);
		IN6_IPADDR_TO_V4MAPPED(inaddr_any,
		    &ipif->ipif_v6subnet);
		IN6_IPADDR_TO_V4MAPPED(inaddr_any,
		    &ipif->ipif_v6net_mask);
		IN6_IPADDR_TO_V4MAPPED(inaddr_any,
		    &ipif->ipif_v6brd_addr);
		IN6_IPADDR_TO_V4MAPPED(inaddr_any,
		    &ipif->ipif_v6pp_dst_addr);
	}

	/*
	 * Don't set the interface flags etc. now, will do it in
	 * ip_ll_subnet_defaults.
	 */
	if (!initialize)
		goto out;

	ipif->ipif_mtu = ill->ill_max_mtu;

	/*
	 * NOTE: The IPMP meta-interface is special-cased because it starts
	 * with no underlying interfaces (and thus an unknown broadcast
	 * address length), but all interfaces that can be placed into an IPMP
	 * group are required to be broadcast-capable.
	 */
	if (ill->ill_bcast_addr_length != 0 || IS_IPMP(ill)) {
		/*
		 * Later detect lack of DLPI driver multicast
		 * capability by catching DL_ENABMULTI errors in
		 * ip_rput_dlpi.
		 */
		ill->ill_flags |= ILLF_MULTICAST;
		if (!ipif->ipif_isv6)
			ipif->ipif_flags |= IPIF_BROADCAST;
	} else {
		if (ill->ill_net_type != IRE_LOOPBACK) {
			if (ipif->ipif_isv6)
				/*
				 * Note: xresolv interfaces will eventually need
				 * NOARP set here as well, but that will require
				 * those external resolvers to have some
				 * knowledge of that flag and act appropriately.
				 * Not to be changed at present.
				 */
				ill->ill_flags |= ILLF_NONUD;
			else
				ill->ill_flags |= ILLF_NOARP;
		}
		if (ill->ill_phys_addr_length == 0) {
			if (ill->ill_mactype == SUNW_DL_VNI) {
				ipif->ipif_flags |= IPIF_NOXMIT;
				phyi->phyint_flags |= PHYI_VIRTUAL;
			} else {
				/* pt-pt supports multicast. */
				ill->ill_flags |= ILLF_MULTICAST;
				if (ill->ill_net_type == IRE_LOOPBACK) {
					phyi->phyint_flags |=
					    (PHYI_LOOPBACK | PHYI_VIRTUAL);
				} else {
					ipif->ipif_flags |= IPIF_POINTOPOINT;
				}
			}
		}
	}
out:
	mutex_exit(&phyi->phyint_lock);
	mutex_exit(&ill->ill_lock);
	return (ipif);
}

/*
 * If appropriate, send a message up to the resolver delete the entry
 * for the address of this interface which is going out of business.
 * (Always called as writer).
 *
 * NOTE : We need to check for NULL mps as some of the fields are
 *	  initialized only for some interface types. See ipif_resolver_up()
 *	  for details.
 */
void
ipif_resolver_down(ipif_t *ipif)
{
	mblk_t	*mp;
	ill_t	*ill = ipif->ipif_ill;

	ip1dbg(("ipif_resolver_down(%s:%u)\n", ill->ill_name, ipif->ipif_id));
	ASSERT(IAM_WRITER_IPIF(ipif));

	if (ill->ill_isv6 && !(ill->ill_flags & ILLF_XRESOLV))
		return;

	/* Delete the mapping for the local address */
	mp = ipif->ipif_arp_del_mp;
	if (mp != NULL) {
		ip1dbg(("ipif_resolver_down: arp cmd %x for %s:%u\n",
		    *(unsigned *)mp->b_rptr, ill->ill_name, ipif->ipif_id));
		putnext(ill->ill_rq, mp);
		ipif->ipif_arp_del_mp = NULL;
	}

	/*
	 * Make IPMP aware of the deleted data address.
	 */
	if (IS_IPMP(ill))
		ipmp_illgrp_del_ipif(ill->ill_grp, ipif);

	/*
	 * If this is the last ipif that is going down and there are no
	 * duplicate addresses we may yet attempt to re-probe, then we need to
	 * clean up ARP completely.
	 */
	if (ill->ill_ipif_up_count == 0 && ill->ill_ipif_dup_count == 0) {
		/*
		 * If this was the last ipif on an IPMP interface, purge any
		 * IPMP ARP entries associated with it.
		 */
		if (IS_IPMP(ill))
			ipmp_illgrp_refresh_arpent(ill->ill_grp);

		/* Send up AR_INTERFACE_DOWN message */
		mp = ill->ill_arp_down_mp;
		if (mp != NULL) {
			ip1dbg(("ipif_resolver_down: arp cmd %x for %s:%u\n",
			    *(unsigned *)mp->b_rptr, ill->ill_name,
			    ipif->ipif_id));
			putnext(ill->ill_rq, mp);
			ill->ill_arp_down_mp = NULL;
		}

		/* Tell ARP to delete the multicast mappings */
		mp = ill->ill_arp_del_mapping_mp;
		if (mp != NULL) {
			ip1dbg(("ipif_resolver_down: arp cmd %x for %s:%u\n",
			    *(unsigned *)mp->b_rptr, ill->ill_name,
			    ipif->ipif_id));
			putnext(ill->ill_rq, mp);
			ill->ill_arp_del_mapping_mp = NULL;
		}
	}
}

/*
 * This function sets up the multicast mappings in ARP. When ipif_resolver_up
 * calls this function, it passes a non-NULL arp_add_mapping_mp indicating
 * that it wants the add_mp allocated in this function to be returned
 * wihtout sending it to arp. When ip_rput_dlpi_writer calls this to
 * just re-do the multicast, it wants us to send the add_mp to ARP also.
 * ipif_resolver_up does not want us to do the "add" i.e sending to ARP,
 * as it does a ipif_arp_down after calling this function - which will
 * remove what we add here.
 *
 * Returns -1 on failures and 0 on success.
 */
int
ipif_arp_setup_multicast(ipif_t *ipif, mblk_t **arp_add_mapping_mp)
{
	mblk_t	*del_mp = NULL;
	mblk_t *add_mp = NULL;
	mblk_t *mp;
	ill_t	*ill = ipif->ipif_ill;
	phyint_t *phyi = ill->ill_phyint;
	ipaddr_t addr, mask, extract_mask = 0;
	arma_t	*arma;
	uint8_t *maddr, *bphys_addr;
	uint32_t hw_start;
	dl_unitdata_req_t *dlur;

	ASSERT(IAM_WRITER_IPIF(ipif));
	if (ipif->ipif_flags & IPIF_POINTOPOINT)
		return (0);

	/*
	 * IPMP meta-interfaces don't have any inherent multicast mappings,
	 * and instead use the ones on the underlying interfaces.
	 */
	if (IS_IPMP(ill))
		return (0);

	/*
	 * Delete the existing mapping from ARP. Normally ipif_down
	 * -> ipif_arp_down should send this up to ARP. The only
	 * reason we would find this when we are switching from
	 * Multicast to Broadcast where we did not do a down.
	 */
	mp = ill->ill_arp_del_mapping_mp;
	if (mp != NULL) {
		ip1dbg(("ipif_arp_down: arp cmd %x for %s:%u\n",
		    *(unsigned *)mp->b_rptr, ill->ill_name, ipif->ipif_id));
		putnext(ill->ill_rq, mp);
		ill->ill_arp_del_mapping_mp = NULL;
	}

	if (arp_add_mapping_mp != NULL)
		*arp_add_mapping_mp = NULL;

	/*
	 * Check that the address is not to long for the constant
	 * length reserved in the template arma_t.
	 */
	if (ill->ill_phys_addr_length > IP_MAX_HW_LEN)
		return (-1);

	/* Add mapping mblk */
	addr = (ipaddr_t)htonl(INADDR_UNSPEC_GROUP);
	mask = (ipaddr_t)htonl(IN_CLASSD_NET);
	add_mp = ill_arp_alloc(ill, (uchar_t *)&ip_arma_multi_template,
	    (caddr_t)&addr);
	if (add_mp == NULL)
		return (-1);
	arma = (arma_t *)add_mp->b_rptr;
	maddr = (uint8_t *)arma + arma->arma_hw_addr_offset;
	bcopy(&mask, (char *)arma + arma->arma_proto_mask_offset, IP_ADDR_LEN);
	arma->arma_hw_addr_length = ill->ill_phys_addr_length;

	/*
	 * Determine the broadcast address.
	 */
	dlur = (dl_unitdata_req_t *)ill->ill_bcast_mp->b_rptr;
	if (ill->ill_sap_length < 0)
		bphys_addr = (uchar_t *)dlur + dlur->dl_dest_addr_offset;
	else
		bphys_addr = (uchar_t *)dlur +
		    dlur->dl_dest_addr_offset + ill->ill_sap_length;
	/*
	 * Check PHYI_MULTI_BCAST and length of physical
	 * address to determine if we use the mapping or the
	 * broadcast address.
	 */
	if (!(phyi->phyint_flags & PHYI_MULTI_BCAST))
		if (!MEDIA_V4MINFO(ill->ill_media, ill->ill_phys_addr_length,
		    bphys_addr, maddr, &hw_start, &extract_mask))
			phyi->phyint_flags |= PHYI_MULTI_BCAST;

	if ((phyi->phyint_flags & PHYI_MULTI_BCAST) ||
	    (ill->ill_flags & ILLF_MULTICAST)) {
		/* Make sure this will not match the "exact" entry. */
		addr = (ipaddr_t)htonl(INADDR_ALLHOSTS_GROUP);
		del_mp = ill_arp_alloc(ill, (uchar_t *)&ip_ared_template,
		    (caddr_t)&addr);
		if (del_mp == NULL) {
			freemsg(add_mp);
			return (-1);
		}
		bcopy(&extract_mask, (char *)arma +
		    arma->arma_proto_extract_mask_offset, IP_ADDR_LEN);
		if (phyi->phyint_flags & PHYI_MULTI_BCAST) {
			/* Use link-layer broadcast address for MULTI_BCAST */
			bcopy(bphys_addr, maddr, ill->ill_phys_addr_length);
			ip2dbg(("ipif_arp_setup_multicast: adding"
			    " MULTI_BCAST ARP setup for %s\n", ill->ill_name));
		} else {
			arma->arma_hw_mapping_start = hw_start;
			ip2dbg(("ipif_arp_setup_multicast: adding multicast"
			    " ARP setup for %s\n", ill->ill_name));
		}
	} else {
		freemsg(add_mp);
		ASSERT(del_mp == NULL);
		/* It is neither MULTICAST nor MULTI_BCAST */
		return (0);
	}
	ASSERT(add_mp != NULL && del_mp != NULL);
	ASSERT(ill->ill_arp_del_mapping_mp == NULL);
	ill->ill_arp_del_mapping_mp = del_mp;
	if (arp_add_mapping_mp != NULL) {
		/* The caller just wants the mblks allocated */
		*arp_add_mapping_mp = add_mp;
	} else {
		/* The caller wants us to send it to arp */
		putnext(ill->ill_rq, add_mp);
	}
	return (0);
}

/*
 * Get the resolver set up for a new IP address.  (Always called as writer.)
 * Called both for IPv4 and IPv6 interfaces, though it only sets up the
 * resolver for v6 if it's an ILLF_XRESOLV interface.  Honors ILLF_NOARP.
 *
 * The enumerated value res_act tunes the behavior:
 * 	* Res_act_initial: set up all the resolver structures for a new
 *	  IP address.
 *	* Res_act_defend: tell ARP that it needs to send a single gratuitous
 *	  ARP message in defense of the address.
 *	* Res_act_rebind: tell ARP to change the hardware address for an IP
 *	  address (and issue gratuitous ARPs).  Used by ipmp_ill_bind_ipif().
 *
 * Returns error on failure.
 */
int
ipif_resolver_up(ipif_t *ipif, enum ip_resolver_action res_act)
{
	mblk_t	*arp_up_mp = NULL;
	mblk_t	*arp_down_mp = NULL;
	mblk_t	*arp_add_mp = NULL;
	mblk_t	*arp_del_mp = NULL;
	mblk_t	*arp_add_mapping_mp = NULL;
	mblk_t	*arp_del_mapping_mp = NULL;
	ill_t	*ill = ipif->ipif_ill;
	int	err = ENOMEM;
	boolean_t added_ipif = B_FALSE;
	boolean_t publish;
	boolean_t was_dup;

	ip1dbg(("ipif_resolver_up(%s:%u) flags 0x%x\n",
	    ill->ill_name, ipif->ipif_id, (uint_t)ipif->ipif_flags));
	ASSERT(IAM_WRITER_IPIF(ipif));

	was_dup = B_FALSE;
	if (res_act == Res_act_initial) {
		ipif->ipif_addr_ready = 0;
		/*
		 * We're bringing an interface up here.  There's no way that we
		 * should need to shut down ARP now.
		 */
		mutex_enter(&ill->ill_lock);
		if (ipif->ipif_flags & IPIF_DUPLICATE) {
			ipif->ipif_flags &= ~IPIF_DUPLICATE;
			ill->ill_ipif_dup_count--;
			was_dup = B_TRUE;
		}
		mutex_exit(&ill->ill_lock);
	}
	if (ipif->ipif_recovery_id != 0)
		(void) untimeout(ipif->ipif_recovery_id);
	ipif->ipif_recovery_id = 0;
	if (ill->ill_net_type != IRE_IF_RESOLVER) {
		ipif->ipif_addr_ready = 1;
		return (0);
	}
	/* NDP will set the ipif_addr_ready flag when it's ready */
	if (ill->ill_isv6 && !(ill->ill_flags & ILLF_XRESOLV))
		return (0);

	if (ill->ill_isv6) {
		/*
		 * External resolver for IPv6
		 */
		ASSERT(res_act == Res_act_initial);
		publish = !IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr);
	} else {
		/*
		 * IPv4 arp case. If the ARP stream has already started
		 * closing, fail this request for ARP bringup. Else
		 * record the fact that an ARP bringup is pending.
		 */
		mutex_enter(&ill->ill_lock);
		if (ill->ill_arp_closing) {
			mutex_exit(&ill->ill_lock);
			err = EINVAL;
			goto failed;
		} else {
			if (ill->ill_ipif_up_count == 0 &&
			    ill->ill_ipif_dup_count == 0 && !was_dup)
				ill->ill_arp_bringup_pending = 1;
			mutex_exit(&ill->ill_lock);
		}
		publish = (ipif->ipif_lcl_addr != INADDR_ANY);
	}

	if (IS_IPMP(ill) && publish) {
		/*
		 * If we're here via ipif_up(), then the ipif won't be bound
		 * yet -- add it to the group, which will bind it if possible.
		 * (We would add it in ipif_up(), but deleting on failure
		 * there is gruesome.)  If we're here via ipmp_ill_bind_ipif(),
		 * then the ipif has already been added to the group and we
		 * just need to use the binding.
		 */
		if (ipmp_ipif_bound_ill(ipif) == NULL) {
			if (ipmp_illgrp_add_ipif(ill->ill_grp, ipif) == NULL) {
				/*
				 * We couldn't bind the ipif to an ill yet,
				 * so we have nothing to publish.
				 */
				publish = B_FALSE;
			}
			added_ipif = B_TRUE;
		}
	}

	/*
	 * Add an entry for the local address in ARP only if it
	 * is not UNNUMBERED and it is suitable for publishing.
	 */
	if (!(ipif->ipif_flags & IPIF_UNNUMBERED) && publish) {
		if (res_act == Res_act_defend) {
			arp_add_mp = ipif_area_alloc(ipif, ACE_F_DEFEND);
			if (arp_add_mp == NULL)
				goto failed;
			/*
			 * If we're just defending our address now, then
			 * there's no need to set up ARP multicast mappings.
			 * The publish command is enough.
			 */
			goto done;
		}

		/*
		 * Allocate an ARP add message and an ARP delete message (the
		 * latter is saved for use when the address goes down).
		 */
		if ((arp_add_mp = ipif_area_alloc(ipif, 0)) == NULL)
			goto failed;

		if ((arp_del_mp = ipif_ared_alloc(ipif)) == NULL)
			goto failed;

		if (res_act != Res_act_initial)
			goto arp_setup_multicast;
	} else {
		if (res_act != Res_act_initial)
			goto done;
	}
	/*
	 * Need to bring up ARP or setup multicast mapping only
	 * when the first interface is coming UP.
	 */
	if (ill->ill_ipif_up_count + ill->ill_ipif_dup_count > 0 || was_dup)
		goto done;

	/*
	 * Allocate an ARP down message (to be saved) and an ARP up message.
	 */
	arp_down_mp = ill_arp_alloc(ill, (uchar_t *)&ip_ard_template, 0);
	if (arp_down_mp == NULL)
		goto failed;

	arp_up_mp = ill_arp_alloc(ill, (uchar_t *)&ip_aru_template, 0);
	if (arp_up_mp == NULL)
		goto failed;

	if (ipif->ipif_flags & IPIF_POINTOPOINT)
		goto done;

arp_setup_multicast:
	/*
	 * Setup the multicast mappings. This function initializes
	 * ill_arp_del_mapping_mp also. This does not need to be done for
	 * IPv6, or for the IPMP interface (since it has no link-layer).
	 */
	if (!ill->ill_isv6 && !IS_IPMP(ill)) {
		err = ipif_arp_setup_multicast(ipif, &arp_add_mapping_mp);
		if (err != 0)
			goto failed;
		ASSERT(ill->ill_arp_del_mapping_mp != NULL);
		ASSERT(arp_add_mapping_mp != NULL);
	}
done:
	if (arp_up_mp != NULL) {
		ip1dbg(("ipif_resolver_up: ARP_UP for %s:%u\n",
		    ill->ill_name, ipif->ipif_id));
		putnext(ill->ill_rq, arp_up_mp);
		arp_up_mp = NULL;
	}
	if (arp_add_mp != NULL) {
		ip1dbg(("ipif_resolver_up: ARP_ADD for %s:%u\n",
		    ill->ill_name, ipif->ipif_id));
		/*
		 * If it's an extended ARP implementation, then we'll wait to
		 * hear that DAD has finished before using the interface.
		 */
		if (!ill->ill_arp_extend)
			ipif->ipif_addr_ready = 1;
		putnext(ill->ill_rq, arp_add_mp);
		arp_add_mp = NULL;
	} else {
		ipif->ipif_addr_ready = 1;
	}
	if (arp_add_mapping_mp != NULL) {
		ip1dbg(("ipif_resolver_up: MAPPING_ADD for %s:%u\n",
		    ill->ill_name, ipif->ipif_id));
		putnext(ill->ill_rq, arp_add_mapping_mp);
		arp_add_mapping_mp = NULL;
	}

	if (res_act == Res_act_initial) {
		if (ill->ill_flags & ILLF_NOARP)
			err = ill_arp_off(ill);
		else
			err = ill_arp_on(ill);
		if (err != 0) {
			ip0dbg(("ipif_resolver_up: arp_on/off failed %d\n",
			    err));
			goto failed;
		}
	}

	if (arp_del_mp != NULL) {
		ASSERT(ipif->ipif_arp_del_mp == NULL);
		ipif->ipif_arp_del_mp = arp_del_mp;
	}
	if (arp_down_mp != NULL) {
		ASSERT(ill->ill_arp_down_mp == NULL);
		ill->ill_arp_down_mp = arp_down_mp;
	}
	if (arp_del_mapping_mp != NULL) {
		ASSERT(ill->ill_arp_del_mapping_mp == NULL);
		ill->ill_arp_del_mapping_mp = arp_del_mapping_mp;
	}

	return ((ill->ill_ipif_up_count != 0 || was_dup ||
	    ill->ill_ipif_dup_count != 0) ? 0 : EINPROGRESS);
failed:
	ip1dbg(("ipif_resolver_up: FAILED\n"));
	if (added_ipif)
		ipmp_illgrp_del_ipif(ill->ill_grp, ipif);
	freemsg(arp_add_mp);
	freemsg(arp_del_mp);
	freemsg(arp_add_mapping_mp);
	freemsg(arp_up_mp);
	freemsg(arp_down_mp);
	ill->ill_arp_bringup_pending = 0;
	return (err);
}

/*
 * This routine restarts IPv4 duplicate address detection (DAD) when a link has
 * just gone back up.
 */
static void
ipif_arp_start_dad(ipif_t *ipif)
{
	ill_t *ill = ipif->ipif_ill;
	mblk_t *arp_add_mp;

	/* ACE_F_UNVERIFIED restarts DAD */
	if (ill->ill_net_type != IRE_IF_RESOLVER || ill->ill_arp_closing ||
	    (ipif->ipif_flags & IPIF_UNNUMBERED) ||
	    ipif->ipif_lcl_addr == INADDR_ANY ||
	    (arp_add_mp = ipif_area_alloc(ipif, ACE_F_UNVERIFIED)) == NULL) {
		/*
		 * If we can't contact ARP for some reason, that's not really a
		 * problem.  Just send out the routing socket notification that
		 * DAD completion would have done, and continue.
		 */
		ipif_mask_reply(ipif);
		ipif_up_notify(ipif);
		ipif->ipif_addr_ready = 1;
		return;
	}

	putnext(ill->ill_rq, arp_add_mp);
}

static void
ipif_ndp_start_dad(ipif_t *ipif)
{
	nce_t *nce;

	nce = ndp_lookup_v6(ipif->ipif_ill, B_TRUE, &ipif->ipif_v6lcl_addr,
	    B_FALSE);
	if (nce == NULL)
		return;

	if (!ndp_restart_dad(nce)) {
		/*
		 * If we can't restart DAD for some reason, that's not really a
		 * problem.  Just send out the routing socket notification that
		 * DAD completion would have done, and continue.
		 */
		ipif_up_notify(ipif);
		ipif->ipif_addr_ready = 1;
	}
	NCE_REFRELE(nce);
}

/*
 * Restart duplicate address detection on all interfaces on the given ill.
 *
 * This is called when an interface transitions from down to up
 * (DL_NOTE_LINK_UP) or up to down (DL_NOTE_LINK_DOWN).
 *
 * Note that since the underlying physical link has transitioned, we must cause
 * at least one routing socket message to be sent here, either via DAD
 * completion or just by default on the first ipif.  (If we don't do this, then
 * in.mpathd will see long delays when doing link-based failure recovery.)
 */
void
ill_restart_dad(ill_t *ill, boolean_t went_up)
{
	ipif_t *ipif;

	if (ill == NULL)
		return;

	/*
	 * If layer two doesn't support duplicate address detection, then just
	 * send the routing socket message now and be done with it.
	 */
	if ((ill->ill_isv6 && (ill->ill_flags & ILLF_XRESOLV)) ||
	    (!ill->ill_isv6 && !ill->ill_arp_extend)) {
		ip_rts_ifmsg(ill->ill_ipif, RTSQ_DEFAULT);
		return;
	}

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (went_up) {
			if (ipif->ipif_flags & IPIF_UP) {
				if (ill->ill_isv6)
					ipif_ndp_start_dad(ipif);
				else
					ipif_arp_start_dad(ipif);
			} else if (ill->ill_isv6 &&
			    (ipif->ipif_flags & IPIF_DUPLICATE)) {
				/*
				 * For IPv4, the ARP module itself will
				 * automatically start the DAD process when it
				 * sees DL_NOTE_LINK_UP.  We respond to the
				 * AR_CN_READY at the completion of that task.
				 * For IPv6, we must kick off the bring-up
				 * process now.
				 */
				ndp_do_recovery(ipif);
			} else {
				/*
				 * Unfortunately, the first ipif is "special"
				 * and represents the underlying ill in the
				 * routing socket messages.  Thus, when this
				 * one ipif is down, we must still notify so
				 * that the user knows the IFF_RUNNING status
				 * change.  (If the first ipif is up, then
				 * we'll handle eventual routing socket
				 * notification via DAD completion.)
				 */
				if (ipif == ill->ill_ipif) {
					ip_rts_ifmsg(ill->ill_ipif,
					    RTSQ_DEFAULT);
				}
			}
		} else {
			/*
			 * After link down, we'll need to send a new routing
			 * message when the link comes back, so clear
			 * ipif_addr_ready.
			 */
			ipif->ipif_addr_ready = 0;
		}
	}

	/*
	 * If we've torn down links, then notify the user right away.
	 */
	if (!went_up)
		ip_rts_ifmsg(ill->ill_ipif, RTSQ_DEFAULT);
}

static void
ipsq_delete(ipsq_t *ipsq)
{
	ipxop_t *ipx = ipsq->ipsq_xop;

	ipsq->ipsq_ipst = NULL;
	ASSERT(ipsq->ipsq_phyint == NULL);
	ASSERT(ipsq->ipsq_xop != NULL);
	ASSERT(ipsq->ipsq_xopq_mphead == NULL && ipx->ipx_mphead == NULL);
	ASSERT(ipx->ipx_pending_mp == NULL);
	kmem_free(ipsq, sizeof (ipsq_t));
}

static int
ill_up_ipifs_on_ill(ill_t *ill, queue_t *q, mblk_t *mp)
{
	int err;
	ipif_t *ipif;

	if (ill == NULL)
		return (0);

	/*
	 * Except for ipif_state_flags and ill_state_flags the other
	 * fields of the ipif/ill that are modified below are protected
	 * implicitly since we are a writer. We would have tried to down
	 * even an ipif that was already down, in ill_down_ipifs. So we
	 * just blindly clear the IPIF_CHANGING flag here on all ipifs.
	 */
	ASSERT(IAM_WRITER_ILL(ill));

	ill->ill_up_ipifs = B_TRUE;
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		mutex_enter(&ill->ill_lock);
		ipif->ipif_state_flags &= ~IPIF_CHANGING;
		mutex_exit(&ill->ill_lock);
		if (ipif->ipif_was_up) {
			if (!(ipif->ipif_flags & IPIF_UP))
				err = ipif_up(ipif, q, mp);
			ipif->ipif_was_up = B_FALSE;
			if (err != 0) {
				ASSERT(err == EINPROGRESS);
				return (err);
			}
		}
	}
	mutex_enter(&ill->ill_lock);
	ill->ill_state_flags &= ~ILL_CHANGING;
	mutex_exit(&ill->ill_lock);
	ill->ill_up_ipifs = B_FALSE;
	return (0);
}

/*
 * This function is called to bring up all the ipifs that were up before
 * bringing the ill down via ill_down_ipifs().
 */
int
ill_up_ipifs(ill_t *ill, queue_t *q, mblk_t *mp)
{
	int err;

	ASSERT(IAM_WRITER_ILL(ill));

	err = ill_up_ipifs_on_ill(ill->ill_phyint->phyint_illv4, q, mp);
	if (err != 0)
		return (err);

	return (ill_up_ipifs_on_ill(ill->ill_phyint->phyint_illv6, q, mp));
}

/*
 * Bring down any IPIF_UP ipifs on ill.
 */
static void
ill_down_ipifs(ill_t *ill)
{
	ipif_t *ipif;

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Except for ipif_state_flags the other fields of the ipif/ill that
	 * are modified below are protected implicitly since we are a writer
	 */
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		/*
		 * We go through the ipif_down logic even if the ipif
		 * is already down, since routes can be added based
		 * on down ipifs. Going through ipif_down once again
		 * will delete any IREs created based on these routes.
		 */
		if (ipif->ipif_flags & IPIF_UP)
			ipif->ipif_was_up = B_TRUE;

		mutex_enter(&ill->ill_lock);
		ipif->ipif_state_flags |= IPIF_CHANGING;
		mutex_exit(&ill->ill_lock);

		/*
		 * Need to re-create net/subnet bcast ires if
		 * they are dependent on ipif.
		 */
		if (!ipif->ipif_isv6)
			ipif_check_bcast_ires(ipif);
		(void) ipif_logical_down(ipif, NULL, NULL);
		ipif_non_duplicate(ipif);
		ipif_down_tail(ipif);
	}
}

void
ill_lock_ills(ill_t **list, int cnt)
{
	int	i;

	if (cnt > 1) {
		boolean_t try_again;
		do {
			try_again = B_FALSE;
			for (i = 0; i < cnt - 1; i++) {
				if (list[i] < list[i + 1]) {
					ill_t	*tmp;

					/* swap the elements */
					tmp = list[i];
					list[i] = list[i + 1];
					list[i + 1] = tmp;
					try_again = B_TRUE;
				}
			}
		} while (try_again);
	}

	for (i = 0; i < cnt; i++) {
		if (i == 0) {
			if (list[i] != NULL)
				mutex_enter(&list[i]->ill_lock);
			else
				return;
		} else if ((list[i-1] != list[i]) && (list[i] != NULL)) {
			mutex_enter(&list[i]->ill_lock);
		}
	}
}

void
ill_unlock_ills(ill_t **list, int cnt)
{
	int	i;

	for (i = 0; i < cnt; i++) {
		if ((i == 0) && (list[i] != NULL)) {
			mutex_exit(&list[i]->ill_lock);
		} else if ((list[i-1] != list[i]) && (list[i] != NULL)) {
			mutex_exit(&list[i]->ill_lock);
		}
	}
}

/*
 * Redo source address selection.  This is called when a
 * non-NOLOCAL/DEPRECATED/ANYCAST ipif comes up.
 */
void
ill_update_source_selection(ill_t *ill)
{
	ipif_t *ipif;

	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Underlying interfaces are only used for test traffic and thus
	 * should always send with their (deprecated) source addresses.
	 */
	if (IS_UNDER_IPMP(ill))
		return;

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (ill->ill_isv6)
			ipif_recreate_interface_routes_v6(NULL, ipif);
		else
			ipif_recreate_interface_routes(NULL, ipif);
	}
}

/*
 * Finish the group join started in ip_sioctl_groupname().
 */
/* ARGSUSED */
static void
ip_join_illgrps(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *dummy)
{
	ill_t		*ill = q->q_ptr;
	phyint_t	*phyi = ill->ill_phyint;
	ipmp_grp_t	*grp = phyi->phyint_grp;
	ip_stack_t	*ipst = ill->ill_ipst;

	/* IS_UNDER_IPMP() won't work until ipmp_ill_join_illgrp() is called */
	ASSERT(!IS_IPMP(ill) && grp != NULL);
	ASSERT(IAM_WRITER_IPSQ(ipsq));

	if (phyi->phyint_illv4 != NULL) {
		rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
		VERIFY(grp->gr_pendv4-- > 0);
		rw_exit(&ipst->ips_ipmp_lock);
		ipmp_ill_join_illgrp(phyi->phyint_illv4, grp->gr_v4);
	}
	if (phyi->phyint_illv6 != NULL) {
		rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
		VERIFY(grp->gr_pendv6-- > 0);
		rw_exit(&ipst->ips_ipmp_lock);
		ipmp_ill_join_illgrp(phyi->phyint_illv6, grp->gr_v6);
	}
	freemsg(mp);
}

/*
 * Process an SIOCSLIFGROUPNAME request.
 */
/* ARGSUSED */
int
ip_sioctl_groupname(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct lifreq	*lifr = ifreq;
	ill_t		*ill = ipif->ipif_ill;
	ip_stack_t	*ipst = ill->ill_ipst;
	phyint_t	*phyi = ill->ill_phyint;
	ipmp_grp_t	*grp = phyi->phyint_grp;
	mblk_t		*ipsq_mp;
	int		err = 0;

	/*
	 * Note that phyint_grp can only change here, where we're exclusive.
	 */
	ASSERT(IAM_WRITER_ILL(ill));

	if (ipif->ipif_id != 0 || ill->ill_usesrc_grp_next != NULL ||
	    (phyi->phyint_flags & PHYI_VIRTUAL))
		return (EINVAL);

	lifr->lifr_groupname[LIFGRNAMSIZ - 1] = '\0';

	rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);

	/*
	 * If the name hasn't changed, there's nothing to do.
	 */
	if (grp != NULL && strcmp(grp->gr_name, lifr->lifr_groupname) == 0)
		goto unlock;

	/*
	 * Handle requests to rename an IPMP meta-interface.
	 *
	 * Note that creation of the IPMP meta-interface is handled in
	 * userland through the standard plumbing sequence.  As part of the
	 * plumbing the IPMP meta-interface, its initial groupname is set to
	 * the name of the interface (see ipif_set_values_tail()).
	 */
	if (IS_IPMP(ill)) {
		err = ipmp_grp_rename(grp, lifr->lifr_groupname);
		goto unlock;
	}

	/*
	 * Handle requests to add or remove an IP interface from a group.
	 */
	if (lifr->lifr_groupname[0] != '\0') {			/* add */
		/*
		 * Moves are handled by first removing the interface from
		 * its existing group, and then adding it to another group.
		 * So, fail if it's already in a group.
		 */
		if (IS_UNDER_IPMP(ill)) {
			err = EALREADY;
			goto unlock;
		}

		grp = ipmp_grp_lookup(lifr->lifr_groupname, ipst);
		if (grp == NULL) {
			err = ENOENT;
			goto unlock;
		}

		/*
		 * Check if the phyint and its ills are suitable for
		 * inclusion into the group.
		 */
		if ((err = ipmp_grp_vet_phyint(grp, phyi)) != 0)
			goto unlock;

		/*
		 * Checks pass; join the group, and enqueue the remaining
		 * illgrp joins for when we've become part of the group xop
		 * and are exclusive across its IPSQs.  Since qwriter_ip()
		 * requires an mblk_t to scribble on, and since `mp' will be
		 * freed as part of completing the ioctl, allocate another.
		 */
		if ((ipsq_mp = allocb(0, BPRI_MED)) == NULL) {
			err = ENOMEM;
			goto unlock;
		}

		/*
		 * Before we drop ipmp_lock, bump gr_pend* to ensure that the
		 * IPMP meta-interface ills needed by `phyi' cannot go away
		 * before ip_join_illgrps() is called back.  See the comments
		 * in ip_sioctl_plink_ipmp() for more.
		 */
		if (phyi->phyint_illv4 != NULL)
			grp->gr_pendv4++;
		if (phyi->phyint_illv6 != NULL)
			grp->gr_pendv6++;

		rw_exit(&ipst->ips_ipmp_lock);

		ipmp_phyint_join_grp(phyi, grp);
		ill_refhold(ill);
		qwriter_ip(ill, ill->ill_rq, ipsq_mp, ip_join_illgrps,
		    SWITCH_OP, B_FALSE);
		return (0);
	} else {
		/*
		 * Request to remove the interface from a group.  If the
		 * interface is not in a group, this trivially succeeds.
		 */
		rw_exit(&ipst->ips_ipmp_lock);
		if (IS_UNDER_IPMP(ill))
			ipmp_phyint_leave_grp(phyi);
		return (0);
	}
unlock:
	rw_exit(&ipst->ips_ipmp_lock);
	return (err);
}

/*
 * Process an SIOCGLIFBINDING request.
 */
/* ARGSUSED */
int
ip_sioctl_get_binding(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	ill_t		*bound_ill;
	struct lifreq	*lifr = ifreq;

	if (!IS_IPMP(ipif->ipif_ill))
		return (EINVAL);

	if ((bound_ill = ipmp_ipif_hold_bound_ill(ipif)) == NULL) {
		lifr->lifr_binding[0] = '\0';
		return (0);
	}

	(void) strlcpy(lifr->lifr_binding, bound_ill->ill_name, LIFNAMSIZ);
	ill_refrele(bound_ill);
	return (0);
}

/*
 * Process an SIOCGLIFGROUPNAME request.
 */
/* ARGSUSED */
int
ip_sioctl_get_groupname(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	ipmp_grp_t	*grp;
	struct lifreq	*lifr = ifreq;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	rw_enter(&ipst->ips_ipmp_lock, RW_READER);
	if ((grp = ipif->ipif_ill->ill_phyint->phyint_grp) == NULL)
		lifr->lifr_groupname[0] = '\0';
	else
		(void) strlcpy(lifr->lifr_groupname, grp->gr_name, LIFGRNAMSIZ);
	rw_exit(&ipst->ips_ipmp_lock);
	return (0);
}

/*
 * Process an SIOCGLIFGROUPINFO request.
 */
/* ARGSUSED */
int
ip_sioctl_groupinfo(ipif_t *dummy_ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy)
{
	lifgroupinfo_t	*lifgr;
	ipmp_grp_t	*grp;
	ip_stack_t	*ipst = CONNQ_TO_IPST(q);

	/* ip_wput_nondata() verified mp->b_cont->b_cont */
	lifgr = (lifgroupinfo_t *)mp->b_cont->b_cont->b_rptr;
	lifgr->gi_grname[LIFGRNAMSIZ - 1] = '\0';

	rw_enter(&ipst->ips_ipmp_lock, RW_READER);
	if ((grp = ipmp_grp_lookup(lifgr->gi_grname, ipst)) == NULL) {
		rw_exit(&ipst->ips_ipmp_lock);
		return (ENOENT);
	}
	ipmp_grp_info(grp, lifgr);
	rw_exit(&ipst->ips_ipmp_lock);
	return (0);
}

static void
ill_dl_down(ill_t *ill)
{
	/*
	 * The ill is down; unbind but stay attached since we're still
	 * associated with a PPA. If we have negotiated DLPI capabilites
	 * with the data link service provider (IDS_OK) then reset them.
	 * The interval between unbinding and rebinding is potentially
	 * unbounded hence we cannot assume things will be the same.
	 * The DLPI capabilities will be probed again when the data link
	 * is brought up.
	 */
	mblk_t	*mp = ill->ill_unbind_mp;

	ip1dbg(("ill_dl_down(%s)\n", ill->ill_name));

	ill->ill_unbind_mp = NULL;
	if (mp != NULL) {
		ip1dbg(("ill_dl_down: %s (%u) for %s\n",
		    dl_primstr(*(int *)mp->b_rptr), *(int *)mp->b_rptr,
		    ill->ill_name));
		mutex_enter(&ill->ill_lock);
		ill->ill_state_flags |= ILL_DL_UNBIND_IN_PROGRESS;
		mutex_exit(&ill->ill_lock);
		/*
		 * ip_rput does not pass up normal (M_PROTO) DLPI messages
		 * after ILL_CONDEMNED is set. So in the unplumb case, we call
		 * ill_capability_dld_disable disable rightaway. If this is not
		 * an unplumb operation then the disable happens on receipt of
		 * the capab ack via ip_rput_dlpi_writer ->
		 * ill_capability_ack_thr. In both cases the order of
		 * the operations seen by DLD is capability disable followed
		 * by DL_UNBIND. Also the DLD capability disable needs a
		 * cv_wait'able context.
		 */
		if (ill->ill_state_flags & ILL_CONDEMNED)
			ill_capability_dld_disable(ill);
		ill_capability_reset(ill, B_FALSE);
		ill_dlpi_send(ill, mp);
	}

	/*
	 * Toss all of our multicast memberships.  We could keep them, but
	 * then we'd have to do bookkeeping of any joins and leaves performed
	 * by the application while the the interface is down (we can't just
	 * issue them because arp cannot currently process AR_ENTRY_SQUERY's
	 * on a downed interface).
	 */
	ill_leave_multicast(ill);

	mutex_enter(&ill->ill_lock);
	ill->ill_dl_up = 0;
	ill_nic_event_dispatch(ill, 0, NE_DOWN, NULL, 0);
	mutex_exit(&ill->ill_lock);
}

static void
ill_dlpi_dispatch(ill_t *ill, mblk_t *mp)
{
	union DL_primitives *dlp;
	t_uscalar_t prim;

	ASSERT(DB_TYPE(mp) == M_PROTO || DB_TYPE(mp) == M_PCPROTO);

	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;

	ip1dbg(("ill_dlpi_dispatch: sending %s (%u) to %s\n",
	    dl_primstr(prim), prim, ill->ill_name));

	switch (prim) {
	case DL_PHYS_ADDR_REQ:
	{
		dl_phys_addr_req_t *dlpap = (dl_phys_addr_req_t *)mp->b_rptr;
		ill->ill_phys_addr_pend = dlpap->dl_addr_type;
		break;
	}
	case DL_BIND_REQ:
		mutex_enter(&ill->ill_lock);
		ill->ill_state_flags &= ~ILL_DL_UNBIND_IN_PROGRESS;
		mutex_exit(&ill->ill_lock);
		break;
	}

	/*
	 * Except for the ACKs for the M_PCPROTO messages, all other ACKs
	 * are dropped by ip_rput() if ILL_CONDEMNED is set. Therefore
	 * we only wait for the ACK of the DL_UNBIND_REQ.
	 */
	mutex_enter(&ill->ill_lock);
	if (!(ill->ill_state_flags & ILL_CONDEMNED) || (prim == DL_UNBIND_REQ))
		ill->ill_dlpi_pending = prim;

	mutex_exit(&ill->ill_lock);
	putnext(ill->ill_wq, mp);
}

/*
 * Helper function for ill_dlpi_send().
 */
/* ARGSUSED */
static void
ill_dlpi_send_writer(ipsq_t *ipsq, queue_t *q, mblk_t *mp, void *arg)
{
	ill_dlpi_send(q->q_ptr, mp);
}

/*
 * Send a DLPI control message to the driver but make sure there
 * is only one outstanding message. Uses ill_dlpi_pending to tell
 * when it must queue. ip_rput_dlpi_writer calls ill_dlpi_done()
 * when an ACK or a NAK is received to process the next queued message.
 */
void
ill_dlpi_send(ill_t *ill, mblk_t *mp)
{
	mblk_t **mpp;

	ASSERT(DB_TYPE(mp) == M_PROTO || DB_TYPE(mp) == M_PCPROTO);

	/*
	 * To ensure that any DLPI requests for current exclusive operation
	 * are always completely sent before any DLPI messages for other
	 * operations, require writer access before enqueuing.
	 */
	if (!IAM_WRITER_ILL(ill)) {
		ill_refhold(ill);
		/* qwriter_ip() does the ill_refrele() */
		qwriter_ip(ill, ill->ill_wq, mp, ill_dlpi_send_writer,
		    NEW_OP, B_TRUE);
		return;
	}

	mutex_enter(&ill->ill_lock);
	if (ill->ill_dlpi_pending != DL_PRIM_INVAL) {
		/* Must queue message. Tail insertion */
		mpp = &ill->ill_dlpi_deferred;
		while (*mpp != NULL)
			mpp = &((*mpp)->b_next);

		ip1dbg(("ill_dlpi_send: deferring request for %s\n",
		    ill->ill_name));

		*mpp = mp;
		mutex_exit(&ill->ill_lock);
		return;
	}
	mutex_exit(&ill->ill_lock);
	ill_dlpi_dispatch(ill, mp);
}

static void
ill_capability_send(ill_t *ill, mblk_t *mp)
{
	ill->ill_capab_pending_cnt++;
	ill_dlpi_send(ill, mp);
}

void
ill_capability_done(ill_t *ill)
{
	ASSERT(ill->ill_capab_pending_cnt != 0);

	ill_dlpi_done(ill, DL_CAPABILITY_REQ);

	ill->ill_capab_pending_cnt--;
	if (ill->ill_capab_pending_cnt == 0 &&
	    ill->ill_dlpi_capab_state == IDCS_OK)
		ill_capability_reset_alloc(ill);
}

/*
 * Send all deferred DLPI messages without waiting for their ACKs.
 */
void
ill_dlpi_send_deferred(ill_t *ill)
{
	mblk_t *mp, *nextmp;

	/*
	 * Clear ill_dlpi_pending so that the message is not queued in
	 * ill_dlpi_send().
	 */
	mutex_enter(&ill->ill_lock);
	ill->ill_dlpi_pending = DL_PRIM_INVAL;
	mp = ill->ill_dlpi_deferred;
	ill->ill_dlpi_deferred = NULL;
	mutex_exit(&ill->ill_lock);

	for (; mp != NULL; mp = nextmp) {
		nextmp = mp->b_next;
		mp->b_next = NULL;
		ill_dlpi_send(ill, mp);
	}
}

/*
 * Check if the DLPI primitive `prim' is pending; print a warning if not.
 */
boolean_t
ill_dlpi_pending(ill_t *ill, t_uscalar_t prim)
{
	t_uscalar_t pending;

	mutex_enter(&ill->ill_lock);
	if (ill->ill_dlpi_pending == prim) {
		mutex_exit(&ill->ill_lock);
		return (B_TRUE);
	}

	/*
	 * During teardown, ill_dlpi_dispatch() will send DLPI requests
	 * without waiting, so don't print any warnings in that case.
	 */
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		return (B_FALSE);
	}
	pending = ill->ill_dlpi_pending;
	mutex_exit(&ill->ill_lock);

	if (pending == DL_PRIM_INVAL) {
		(void) mi_strlog(ill->ill_rq, 1, SL_CONSOLE|SL_ERROR|SL_TRACE,
		    "received unsolicited ack for %s on %s\n",
		    dl_primstr(prim), ill->ill_name);
	} else {
		(void) mi_strlog(ill->ill_rq, 1, SL_CONSOLE|SL_ERROR|SL_TRACE,
		    "received unexpected ack for %s on %s (expecting %s)\n",
		    dl_primstr(prim), ill->ill_name, dl_primstr(pending));
	}
	return (B_FALSE);
}

/*
 * Complete the current DLPI operation associated with `prim' on `ill' and
 * start the next queued DLPI operation (if any).  If there are no queued DLPI
 * operations and the ill's current exclusive IPSQ operation has finished
 * (i.e., ipsq_current_finish() was called), then clear ipsq_current_ipif to
 * allow the next exclusive IPSQ operation to begin upon ipsq_exit().  See
 * the comments above ipsq_current_finish() for details.
 */
void
ill_dlpi_done(ill_t *ill, t_uscalar_t prim)
{
	mblk_t *mp;
	ipsq_t *ipsq = ill->ill_phyint->phyint_ipsq;
	ipxop_t *ipx = ipsq->ipsq_xop;

	ASSERT(IAM_WRITER_IPSQ(ipsq));
	mutex_enter(&ill->ill_lock);

	ASSERT(prim != DL_PRIM_INVAL);
	ASSERT(ill->ill_dlpi_pending == prim);

	ip1dbg(("ill_dlpi_done: %s has completed %s (%u)\n", ill->ill_name,
	    dl_primstr(ill->ill_dlpi_pending), ill->ill_dlpi_pending));

	if ((mp = ill->ill_dlpi_deferred) == NULL) {
		ill->ill_dlpi_pending = DL_PRIM_INVAL;
		if (ipx->ipx_current_done) {
			mutex_enter(&ipx->ipx_lock);
			ipx->ipx_current_ipif = NULL;
			mutex_exit(&ipx->ipx_lock);
		}
		cv_signal(&ill->ill_cv);
		mutex_exit(&ill->ill_lock);
		return;
	}

	ill->ill_dlpi_deferred = mp->b_next;
	mp->b_next = NULL;
	mutex_exit(&ill->ill_lock);

	ill_dlpi_dispatch(ill, mp);
}

void
conn_delete_ire(conn_t *connp, caddr_t arg)
{
	ipif_t	*ipif = (ipif_t *)arg;
	ire_t	*ire;

	/*
	 * Look at the cached ires on conns which has pointers to ipifs.
	 * We just call ire_refrele which clears up the reference
	 * to ire. Called when a conn closes. Also called from ipif_free
	 * to cleanup indirect references to the stale ipif via the cached ire.
	 */
	mutex_enter(&connp->conn_lock);
	ire = connp->conn_ire_cache;
	if (ire != NULL && (ipif == NULL || ire->ire_ipif == ipif)) {
		connp->conn_ire_cache = NULL;
		mutex_exit(&connp->conn_lock);
		IRE_REFRELE_NOTR(ire);
		return;
	}
	mutex_exit(&connp->conn_lock);

}

/*
 * Some operations (e.g., ipif_down()) conditionally delete a number
 * of IREs. Those IREs may have been previously cached in the conn structure.
 * This ipcl_walk() walker function releases all references to such IREs based
 * on the condemned flag.
 */
/* ARGSUSED */
void
conn_cleanup_stale_ire(conn_t *connp, caddr_t arg)
{
	ire_t	*ire;

	mutex_enter(&connp->conn_lock);
	ire = connp->conn_ire_cache;
	if (ire != NULL && (ire->ire_marks & IRE_MARK_CONDEMNED)) {
		connp->conn_ire_cache = NULL;
		mutex_exit(&connp->conn_lock);
		IRE_REFRELE_NOTR(ire);
		return;
	}
	mutex_exit(&connp->conn_lock);
}

/*
 * Take down a specific interface, but don't lose any information about it.
 * (Always called as writer.)
 * This function goes through the down sequence even if the interface is
 * already down. There are 2 reasons.
 * a. Currently we permit interface routes that depend on down interfaces
 *    to be added. This behaviour itself is questionable. However it appears
 *    that both Solaris and 4.3 BSD have exhibited this behaviour for a long
 *    time. We go thru the cleanup in order to remove these routes.
 * b. The bringup of the interface could fail in ill_dl_up i.e. we get
 *    DL_ERROR_ACK in response to the the DL_BIND request. The interface is
 *    down, but we need to cleanup i.e. do ill_dl_down and
 *    ip_rput_dlpi_writer (DL_ERROR_ACK) -> ipif_down.
 *
 * IP-MT notes:
 *
 * Model of reference to interfaces.
 *
 * The following members in ipif_t track references to the ipif.
 *	int     ipif_refcnt;    Active reference count
 *	uint_t  ipif_ire_cnt;   Number of ire's referencing this ipif
 *	uint_t  ipif_ilm_cnt;   Number of ilms's references this ipif.
 *
 * The following members in ill_t track references to the ill.
 *	int             ill_refcnt;     active refcnt
 *	uint_t          ill_ire_cnt;	Number of ires referencing ill
 *	uint_t          ill_nce_cnt;	Number of nces referencing ill
 *	uint_t          ill_ilm_cnt;	Number of ilms referencing ill
 *
 * Reference to an ipif or ill can be obtained in any of the following ways.
 *
 * Through the lookup functions ipif_lookup_* / ill_lookup_* functions
 * Pointers to ipif / ill from other data structures viz ire and conn.
 * Implicit reference to the ipif / ill by holding a reference to the ire.
 *
 * The ipif/ill lookup functions return a reference held ipif / ill.
 * ipif_refcnt and ill_refcnt track the reference counts respectively.
 * This is a purely dynamic reference count associated with threads holding
 * references to the ipif / ill. Pointers from other structures do not
 * count towards this reference count.
 *
 * ipif_ire_cnt/ill_ire_cnt is the number of ire's
 * associated with the ipif/ill. This is incremented whenever a new
 * ire is created referencing the ipif/ill. This is done atomically inside
 * ire_add_v[46] where the ire is actually added to the ire hash table.
 * The count is decremented in ire_inactive where the ire is destroyed.
 *
 * nce's reference ill's thru nce_ill and the count of nce's associated with
 * an ill is recorded in ill_nce_cnt. This is incremented atomically in
 * ndp_add_v4()/ndp_add_v6() where the nce is actually added to the
 * table. Similarly it is decremented in ndp_inactive() where the nce
 * is destroyed.
 *
 * ilm's reference to the ipif (for IPv4 ilm's) or the ill (for IPv6 ilm's)
 * is incremented in ilm_add_v6() and decremented before the ilm is freed
 * in ilm_walker_cleanup() or ilm_delete().
 *
 * Flow of ioctls involving interface down/up
 *
 * The following is the sequence of an attempt to set some critical flags on an
 * up interface.
 * ip_sioctl_flags
 * ipif_down
 * wait for ipif to be quiescent
 * ipif_down_tail
 * ip_sioctl_flags_tail
 *
 * All set ioctls that involve down/up sequence would have a skeleton similar
 * to the above. All the *tail functions are called after the refcounts have
 * dropped to the appropriate values.
 *
 * The mechanism to quiesce an ipif is as follows.
 *
 * Mark the ipif as IPIF_CHANGING. No more lookups will be allowed
 * on the ipif. Callers either pass a flag requesting wait or the lookup
 *  functions will return NULL.
 *
 * Delete all ires referencing this ipif
 *
 * Any thread attempting to do an ipif_refhold on an ipif that has been
 * obtained thru a cached pointer will first make sure that
 * the ipif can be refheld using the macro IPIF_CAN_LOOKUP and only then
 * increment the refcount.
 *
 * The above guarantees that the ipif refcount will eventually come down to
 * zero and the ipif will quiesce, once all threads that currently hold a
 * reference to the ipif refrelease the ipif. The ipif is quiescent after the
 * ipif_refcount has dropped to zero and all ire's associated with this ipif
 * have also been ire_inactive'd. i.e. when ipif_{ire, ill}_cnt and
 * ipif_refcnt both drop to zero. See also: comments above IPIF_DOWN_OK()
 * in ip.h
 *
 * Lookups during the IPIF_CHANGING/ILL_CHANGING interval.
 *
 * Threads trying to lookup an ipif or ill can pass a flag requesting
 * wait and restart if the ipif / ill cannot be looked up currently.
 * For eg. bind, and route operations (Eg. route add / delete) cannot return
 * failure if the ipif is currently undergoing an exclusive operation, and
 * hence pass the flag. The mblk is then enqueued in the ipsq and the operation
 * is restarted by ipsq_exit() when the current exclusive operation completes.
 * The lookup and enqueue is atomic using the ill_lock and ipsq_lock. The
 * lookup is done holding the ill_lock. Hence the ill/ipif state flags can't
 * change while the ill_lock is held. Before dropping the ill_lock we acquire
 * the ipsq_lock and call ipsq_enq. This ensures that ipsq_exit can't finish
 * until we release the ipsq_lock, even though the the ill/ipif state flags
 * can change after we drop the ill_lock.
 *
 * An attempt to send out a packet using an ipif that is currently
 * IPIF_CHANGING will fail. No attempt is made in this case to enqueue this
 * operation and restart it later when the exclusive condition on the ipif ends.
 * This is an example of not passing the wait flag to the lookup functions. For
 * example an attempt to refhold and use conn->conn_multicast_ipif and send
 * out a multicast packet on that ipif will fail while the ipif is
 * IPIF_CHANGING. An attempt to create an IRE_CACHE using an ipif that is
 * currently IPIF_CHANGING will also fail.
 */
int
ipif_down(ipif_t *ipif, queue_t *q, mblk_t *mp)
{
	ill_t		*ill = ipif->ipif_ill;
	conn_t		*connp;
	boolean_t	success;
	boolean_t	ipif_was_up = B_FALSE;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_IPIF(ipif));

	ip1dbg(("ipif_down(%s:%u)\n", ill->ill_name, ipif->ipif_id));

	if (ipif->ipif_flags & IPIF_UP) {
		mutex_enter(&ill->ill_lock);
		ipif->ipif_flags &= ~IPIF_UP;
		ASSERT(ill->ill_ipif_up_count > 0);
		--ill->ill_ipif_up_count;
		mutex_exit(&ill->ill_lock);
		ipif_was_up = B_TRUE;
		/* Update status in SCTP's list */
		sctp_update_ipif(ipif, SCTP_IPIF_DOWN);
		ill_nic_event_dispatch(ipif->ipif_ill,
		    MAP_IPIF_ID(ipif->ipif_id), NE_LIF_DOWN, NULL, 0);
	}

	/*
	 * Blow away memberships we established in ipif_multicast_up().
	 */
	ipif_multicast_down(ipif);

	/*
	 * Remove from the mapping for __sin6_src_id. We insert only
	 * when the address is not INADDR_ANY. As IPv4 addresses are
	 * stored as mapped addresses, we need to check for mapped
	 * INADDR_ANY also.
	 */
	if (ipif_was_up && !IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr) &&
	    !IN6_IS_ADDR_V4MAPPED_ANY(&ipif->ipif_v6lcl_addr) &&
	    !(ipif->ipif_flags & IPIF_NOLOCAL)) {
		int err;

		err = ip_srcid_remove(&ipif->ipif_v6lcl_addr,
		    ipif->ipif_zoneid, ipst);
		if (err != 0) {
			ip0dbg(("ipif_down: srcid_remove %d\n", err));
		}
	}

	/*
	 * Delete all IRE's pointing at this ipif or its source address.
	 */
	if (ipif->ipif_isv6) {
		ire_walk_v6(ipif_down_delete_ire, (char *)ipif, ALL_ZONES,
		    ipst);
	} else {
		ire_walk_v4(ipif_down_delete_ire, (char *)ipif, ALL_ZONES,
		    ipst);
	}

	if (ipif_was_up && ill->ill_ipif_up_count == 0) {
		/*
		 * Since the interface is now down, it may have just become
		 * inactive.  Note that this needs to be done even for a
		 * lll_logical_down(), or ARP entries will not get correctly
		 * restored when the interface comes back up.
		 */
		if (IS_UNDER_IPMP(ill))
			ipmp_ill_refresh_active(ill);
	}

	/*
	 * Cleaning up the conn_ire_cache or conns must be done only after the
	 * ires have been deleted above. Otherwise a thread could end up
	 * caching an ire in a conn after we have finished the cleanup of the
	 * conn. The caching is done after making sure that the ire is not yet
	 * condemned. Also documented in the block comment above ip_output
	 */
	ipcl_walk(conn_cleanup_stale_ire, NULL, ipst);
	/* Also, delete the ires cached in SCTP */
	sctp_ire_cache_flush(ipif);

	/*
	 * Update any other ipifs which have used "our" local address as
	 * a source address. This entails removing and recreating IRE_INTERFACE
	 * entries for such ipifs.
	 */
	if (ipif->ipif_isv6)
		ipif_update_other_ipifs_v6(ipif);
	else
		ipif_update_other_ipifs(ipif);

	/*
	 * neighbor-discovery or arp entries for this interface.
	 */
	ipif_ndp_down(ipif);

	/*
	 * If mp is NULL the caller will wait for the appropriate refcnt.
	 * Eg. ip_sioctl_removeif -> ipif_free  -> ipif_down
	 * and ill_delete -> ipif_free -> ipif_down
	 */
	if (mp == NULL) {
		ASSERT(q == NULL);
		return (0);
	}

	if (CONN_Q(q)) {
		connp = Q_TO_CONN(q);
		mutex_enter(&connp->conn_lock);
	} else {
		connp = NULL;
	}
	mutex_enter(&ill->ill_lock);
	/*
	 * Are there any ire's pointing to this ipif that are still active ?
	 * If this is the last ipif going down, are there any ire's pointing
	 * to this ill that are still active ?
	 */
	if (ipif_is_quiescent(ipif)) {
		mutex_exit(&ill->ill_lock);
		if (connp != NULL)
			mutex_exit(&connp->conn_lock);
		return (0);
	}

	ip1dbg(("ipif_down: need to wait, adding pending mp %s ill %p",
	    ill->ill_name, (void *)ill));
	/*
	 * Enqueue the mp atomically in ipsq_pending_mp. When the refcount
	 * drops down, the operation will be restarted by ipif_ill_refrele_tail
	 * which in turn is called by the last refrele on the ipif/ill/ire.
	 */
	success = ipsq_pending_mp_add(connp, ipif, q, mp, IPIF_DOWN);
	if (!success) {
		/* The conn is closing. So just return */
		ASSERT(connp != NULL);
		mutex_exit(&ill->ill_lock);
		mutex_exit(&connp->conn_lock);
		return (EINTR);
	}

	mutex_exit(&ill->ill_lock);
	if (connp != NULL)
		mutex_exit(&connp->conn_lock);
	return (EINPROGRESS);
}

void
ipif_down_tail(ipif_t *ipif)
{
	ill_t	*ill = ipif->ipif_ill;

	/*
	 * Skip any loopback interface (null wq).
	 * If this is the last logical interface on the ill
	 * have ill_dl_down tell the driver we are gone (unbind)
	 * Note that lun 0 can ipif_down even though
	 * there are other logical units that are up.
	 * This occurs e.g. when we change a "significant" IFF_ flag.
	 */
	if (ill->ill_wq != NULL && !ill->ill_logical_down &&
	    ill->ill_ipif_up_count == 0 && ill->ill_ipif_dup_count == 0 &&
	    ill->ill_dl_up) {
		ill_dl_down(ill);
	}
	ill->ill_logical_down = 0;

	/*
	 * Has to be after removing the routes in ipif_down_delete_ire.
	 */
	ipif_resolver_down(ipif);

	ip_rts_ifmsg(ipif, RTSQ_DEFAULT);
	ip_rts_newaddrmsg(RTM_DELETE, 0, ipif, RTSQ_DEFAULT);
}

/*
 * Bring interface logically down without bringing the physical interface
 * down e.g. when the netmask is changed. This avoids long lasting link
 * negotiations between an ethernet interface and a certain switches.
 */
static int
ipif_logical_down(ipif_t *ipif, queue_t *q, mblk_t *mp)
{
	/*
	 * The ill_logical_down flag is a transient flag. It is set here
	 * and is cleared once the down has completed in ipif_down_tail.
	 * This flag does not indicate whether the ill stream is in the
	 * DL_BOUND state with the driver. Instead this flag is used by
	 * ipif_down_tail to determine whether to DL_UNBIND the stream with
	 * the driver. The state of the ill stream i.e. whether it is
	 * DL_BOUND with the driver or not is indicated by the ill_dl_up flag.
	 */
	ipif->ipif_ill->ill_logical_down = 1;
	return (ipif_down(ipif, q, mp));
}

/*
 * This is called when the SIOCSLIFUSESRC ioctl is processed in IP.
 * If the usesrc client ILL is already part of a usesrc group or not,
 * in either case a ire_stq with the matching usesrc client ILL will
 * locate the IRE's that need to be deleted. We want IREs to be created
 * with the new source address.
 */
static void
ipif_delete_cache_ire(ire_t *ire, char *ill_arg)
{
	ill_t	*ucill = (ill_t *)ill_arg;

	ASSERT(IAM_WRITER_ILL(ucill));

	if (ire->ire_stq == NULL)
		return;

	if ((ire->ire_type == IRE_CACHE) &&
	    ((ill_t *)ire->ire_stq->q_ptr == ucill))
		ire_delete(ire);
}

/*
 * ire_walk routine to delete every IRE dependent on the interface
 * address that is going down.	(Always called as writer.)
 * Works for both v4 and v6.
 * In addition for checking for ire_ipif matches it also checks for
 * IRE_CACHE entries which have the same source address as the
 * disappearing ipif since ipif_select_source might have picked
 * that source. Note that ipif_down/ipif_update_other_ipifs takes
 * care of any IRE_INTERFACE with the disappearing source address.
 */
static void
ipif_down_delete_ire(ire_t *ire, char *ipif_arg)
{
	ipif_t	*ipif = (ipif_t *)ipif_arg;

	ASSERT(IAM_WRITER_IPIF(ipif));
	if (ire->ire_ipif == NULL)
		return;

	if (ire->ire_ipif != ipif) {
		/*
		 * Look for a matching source address.
		 */
		if (ire->ire_type != IRE_CACHE)
			return;
		if (ipif->ipif_flags & IPIF_NOLOCAL)
			return;

		if (ire->ire_ipversion == IPV4_VERSION) {
			if (ire->ire_src_addr != ipif->ipif_src_addr)
				return;
		} else {
			if (!IN6_ARE_ADDR_EQUAL(&ire->ire_src_addr_v6,
			    &ipif->ipif_v6lcl_addr))
				return;
		}
		ire_delete(ire);
		return;
	}
	/*
	 * ire_delete() will do an ire_flush_cache which will delete
	 * all ire_ipif matches
	 */
	ire_delete(ire);
}

/*
 * ire_walk_ill function for deleting all IRE_CACHE entries for an ill when
 * 1) an ipif (on that ill) changes the IPIF_DEPRECATED flags, or
 * 2) when an interface is brought up or down (on that ill).
 * This ensures that the IRE_CACHE entries don't retain stale source
 * address selection results.
 */
void
ill_ipif_cache_delete(ire_t *ire, char *ill_arg)
{
	ill_t	*ill = (ill_t *)ill_arg;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(ire->ire_type == IRE_CACHE);

	/*
	 * We are called for IRE_CACHEs whose ire_stq or ire_ipif matches
	 * ill, but we only want to delete the IRE if ire_ipif matches.
	 */
	ASSERT(ire->ire_ipif != NULL);
	if (ill == ire->ire_ipif->ipif_ill)
		ire_delete(ire);
}

/*
 * Delete all the IREs whose ire_stq's reference `ill_arg'.  IPMP uses this
 * instead of ill_ipif_cache_delete() because ire_ipif->ipif_ill references
 * the IPMP ill.
 */
void
ill_stq_cache_delete(ire_t *ire, char *ill_arg)
{
	ill_t	*ill = (ill_t *)ill_arg;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(ire->ire_type == IRE_CACHE);

	/*
	 * We are called for IRE_CACHEs whose ire_stq or ire_ipif matches
	 * ill, but we only want to delete the IRE if ire_stq matches.
	 */
	if (ire->ire_stq->q_ptr == ill_arg)
		ire_delete(ire);
}

/*
 * Delete all broadcast IREs with a source address on `ill_arg'.
 */
static void
ill_broadcast_delete(ire_t *ire, char *ill_arg)
{
	ill_t *ill = (ill_t *)ill_arg;

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(ire->ire_type == IRE_BROADCAST);

	if (ire->ire_ipif->ipif_ill == ill)
		ire_delete(ire);
}

/*
 * Initiate deallocate of an IPIF. Always called as writer. Called by
 * ill_delete or ip_sioctl_removeif.
 */
static void
ipif_free(ipif_t *ipif)
{
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(IAM_WRITER_IPIF(ipif));

	if (ipif->ipif_recovery_id != 0)
		(void) untimeout(ipif->ipif_recovery_id);
	ipif->ipif_recovery_id = 0;

	/* Remove conn references */
	reset_conn_ipif(ipif);

	/*
	 * Make sure we have valid net and subnet broadcast ire's for the
	 * other ipif's which share them with this ipif.
	 */
	if (!ipif->ipif_isv6)
		ipif_check_bcast_ires(ipif);

	/*
	 * Take down the interface. We can be called either from ill_delete
	 * or from ip_sioctl_removeif.
	 */
	(void) ipif_down(ipif, NULL, NULL);

	/*
	 * Now that the interface is down, there's no chance it can still
	 * become a duplicate.  Cancel any timer that may have been set while
	 * tearing down.
	 */
	if (ipif->ipif_recovery_id != 0)
		(void) untimeout(ipif->ipif_recovery_id);
	ipif->ipif_recovery_id = 0;

	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	/* Remove pointers to this ill in the multicast routing tables */
	reset_mrt_vif_ipif(ipif);
	/* If necessary, clear the cached source ipif rotor. */
	if (ipif->ipif_ill->ill_src_ipif == ipif)
		ipif->ipif_ill->ill_src_ipif = NULL;
	rw_exit(&ipst->ips_ill_g_lock);
}

static void
ipif_free_tail(ipif_t *ipif)
{
	mblk_t	*mp;
	ip_stack_t *ipst = ipif->ipif_ill->ill_ipst;

	/*
	 * Free state for addition IRE_IF_[NO]RESOLVER ire's.
	 */
	mutex_enter(&ipif->ipif_saved_ire_lock);
	mp = ipif->ipif_saved_ire_mp;
	ipif->ipif_saved_ire_mp = NULL;
	mutex_exit(&ipif->ipif_saved_ire_lock);
	freemsg(mp);

	/*
	 * Need to hold both ill_g_lock and ill_lock while
	 * inserting or removing an ipif from the linked list
	 * of ipifs hanging off the ill.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);

	ASSERT(ilm_walk_ipif(ipif) == 0);

#ifdef DEBUG
	ipif_trace_cleanup(ipif);
#endif

	/* Ask SCTP to take it out of it list */
	sctp_update_ipif(ipif, SCTP_IPIF_REMOVE);

	/* Get it out of the ILL interface list. */
	ipif_remove(ipif);
	rw_exit(&ipst->ips_ill_g_lock);

	mutex_destroy(&ipif->ipif_saved_ire_lock);

	ASSERT(!(ipif->ipif_flags & (IPIF_UP | IPIF_DUPLICATE)));
	ASSERT(ipif->ipif_recovery_id == 0);

	/* Free the memory. */
	mi_free(ipif);
}

/*
 * Sets `buf' to an ipif name of the form "ill_name:id", or "ill_name" if "id"
 * is zero.
 */
void
ipif_get_name(const ipif_t *ipif, char *buf, int len)
{
	char	lbuf[LIFNAMSIZ];
	char	*name;
	size_t	name_len;

	buf[0] = '\0';
	name = ipif->ipif_ill->ill_name;
	name_len = ipif->ipif_ill->ill_name_length;
	if (ipif->ipif_id != 0) {
		(void) sprintf(lbuf, "%s%c%d", name, IPIF_SEPARATOR_CHAR,
		    ipif->ipif_id);
		name = lbuf;
		name_len = mi_strlen(name) + 1;
	}
	len -= 1;
	buf[len] = '\0';
	len = MIN(len, name_len);
	bcopy(name, buf, len);
}

/*
 * Find an IPIF based on the name passed in.  Names can be of the
 * form <phys> (e.g., le0), <phys>:<#> (e.g., le0:1),
 * The <phys> string can have forms like <dev><#> (e.g., le0),
 * <dev><#>.<module> (e.g. le0.foo), or <dev>.<module><#> (e.g. ip.tun3).
 * When there is no colon, the implied unit id is zero. <phys> must
 * correspond to the name of an ILL.  (May be called as writer.)
 */
static ipif_t *
ipif_lookup_on_name(char *name, size_t namelen, boolean_t do_alloc,
    boolean_t *exists, boolean_t isv6, zoneid_t zoneid, queue_t *q,
    mblk_t *mp, ipsq_func_t func, int *error, ip_stack_t *ipst)
{
	char	*cp;
	char	*endp;
	long	id;
	ill_t	*ill;
	ipif_t	*ipif;
	uint_t	ire_type;
	boolean_t did_alloc = B_FALSE;
	ipsq_t	*ipsq;

	if (error != NULL)
		*error = 0;

	/*
	 * If the caller wants to us to create the ipif, make sure we have a
	 * valid zoneid
	 */
	ASSERT(!do_alloc || zoneid != ALL_ZONES);

	if (namelen == 0) {
		if (error != NULL)
			*error = ENXIO;
		return (NULL);
	}

	*exists = B_FALSE;
	/* Look for a colon in the name. */
	endp = &name[namelen];
	for (cp = endp; --cp > name; ) {
		if (*cp == IPIF_SEPARATOR_CHAR)
			break;
	}

	if (*cp == IPIF_SEPARATOR_CHAR) {
		/*
		 * Reject any non-decimal aliases for logical
		 * interfaces. Aliases with leading zeroes
		 * are also rejected as they introduce ambiguity
		 * in the naming of the interfaces.
		 * In order to confirm with existing semantics,
		 * and to not break any programs/script relying
		 * on that behaviour, if<0>:0 is considered to be
		 * a valid interface.
		 *
		 * If alias has two or more digits and the first
		 * is zero, fail.
		 */
		if (&cp[2] < endp && cp[1] == '0') {
			if (error != NULL)
				*error = EINVAL;
			return (NULL);
		}
	}

	if (cp <= name) {
		cp = endp;
	} else {
		*cp = '\0';
	}

	/*
	 * Look up the ILL, based on the portion of the name
	 * before the slash. ill_lookup_on_name returns a held ill.
	 * Temporary to check whether ill exists already. If so
	 * ill_lookup_on_name will clear it.
	 */
	ill = ill_lookup_on_name(name, do_alloc, isv6,
	    q, mp, func, error, &did_alloc, ipst);
	if (cp != endp)
		*cp = IPIF_SEPARATOR_CHAR;
	if (ill == NULL)
		return (NULL);

	/* Establish the unit number in the name. */
	id = 0;
	if (cp < endp && *endp == '\0') {
		/* If there was a colon, the unit number follows. */
		cp++;
		if (ddi_strtol(cp, NULL, 0, &id) != 0) {
			ill_refrele(ill);
			if (error != NULL)
				*error = ENXIO;
			return (NULL);
		}
	}

	GRAB_CONN_LOCK(q);
	mutex_enter(&ill->ill_lock);
	/* Now see if there is an IPIF with this unit number. */
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (ipif->ipif_id == id) {
			if (zoneid != ALL_ZONES &&
			    zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES) {
				mutex_exit(&ill->ill_lock);
				RELEASE_CONN_LOCK(q);
				ill_refrele(ill);
				if (error != NULL)
					*error = ENXIO;
				return (NULL);
			}
			/*
			 * The block comment at the start of ipif_down
			 * explains the use of the macros used below
			 */
			if (IPIF_CAN_LOOKUP(ipif)) {
				ipif_refhold_locked(ipif);
				mutex_exit(&ill->ill_lock);
				if (!did_alloc)
					*exists = B_TRUE;
				/*
				 * Drop locks before calling ill_refrele
				 * since it can potentially call into
				 * ipif_ill_refrele_tail which can end up
				 * in trying to acquire any lock.
				 */
				RELEASE_CONN_LOCK(q);
				ill_refrele(ill);
				return (ipif);
			} else if (IPIF_CAN_WAIT(ipif, q)) {
				ipsq = ill->ill_phyint->phyint_ipsq;
				mutex_enter(&ipsq->ipsq_lock);
				mutex_enter(&ipsq->ipsq_xop->ipx_lock);
				mutex_exit(&ill->ill_lock);
				ipsq_enq(ipsq, q, mp, func, NEW_OP, ill);
				mutex_exit(&ipsq->ipsq_xop->ipx_lock);
				mutex_exit(&ipsq->ipsq_lock);
				RELEASE_CONN_LOCK(q);
				ill_refrele(ill);
				if (error != NULL)
					*error = EINPROGRESS;
				return (NULL);
			}
		}
	}
	RELEASE_CONN_LOCK(q);

	if (!do_alloc) {
		mutex_exit(&ill->ill_lock);
		ill_refrele(ill);
		if (error != NULL)
			*error = ENXIO;
		return (NULL);
	}

	/*
	 * If none found, atomically allocate and return a new one.
	 * Historically, we used IRE_LOOPBACK only for lun 0, and IRE_LOCAL
	 * to support "receive only" use of lo0:1 etc. as is still done
	 * below as an initial guess.
	 * However, this is now likely to be overriden later in ipif_up_done()
	 * when we know for sure what address has been configured on the
	 * interface, since we might have more than one loopback interface
	 * with a loopback address, e.g. in the case of zones, and all the
	 * interfaces with loopback addresses need to be marked IRE_LOOPBACK.
	 */
	if (ill->ill_net_type == IRE_LOOPBACK && id == 0)
		ire_type = IRE_LOOPBACK;
	else
		ire_type = IRE_LOCAL;
	ipif = ipif_allocate(ill, id, ire_type, B_TRUE, B_TRUE);
	if (ipif != NULL)
		ipif_refhold_locked(ipif);
	else if (error != NULL)
		*error = ENOMEM;
	mutex_exit(&ill->ill_lock);
	ill_refrele(ill);
	return (ipif);
}

/*
 * This routine is called whenever a new address comes up on an ipif.  If
 * we are configured to respond to address mask requests, then we are supposed
 * to broadcast an address mask reply at this time.  This routine is also
 * called if we are already up, but a netmask change is made.  This is legal
 * but might not make the system manager very popular.	(May be called
 * as writer.)
 */
void
ipif_mask_reply(ipif_t *ipif)
{
	icmph_t	*icmph;
	ipha_t	*ipha;
	mblk_t	*mp;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

#define	REPLY_LEN	(sizeof (icmp_ipha) + sizeof (icmph_t) + IP_ADDR_LEN)

	if (!ipst->ips_ip_respond_to_address_mask_broadcast)
		return;

	/* ICMP mask reply is IPv4 only */
	ASSERT(!ipif->ipif_isv6);
	/* ICMP mask reply is not for a loopback interface */
	ASSERT(ipif->ipif_ill->ill_wq != NULL);

	mp = allocb(REPLY_LEN, BPRI_HI);
	if (mp == NULL)
		return;
	mp->b_wptr = mp->b_rptr + REPLY_LEN;

	ipha = (ipha_t *)mp->b_rptr;
	bzero(ipha, REPLY_LEN);
	*ipha = icmp_ipha;
	ipha->ipha_ttl = ipst->ips_ip_broadcast_ttl;
	ipha->ipha_src = ipif->ipif_src_addr;
	ipha->ipha_dst = ipif->ipif_brd_addr;
	ipha->ipha_length = htons(REPLY_LEN);
	ipha->ipha_ident = 0;

	icmph = (icmph_t *)&ipha[1];
	icmph->icmph_type = ICMP_ADDRESS_MASK_REPLY;
	bcopy(&ipif->ipif_net_mask, &icmph[1], IP_ADDR_LEN);
	icmph->icmph_checksum = IP_CSUM(mp, sizeof (ipha_t), 0);

	put(ipif->ipif_wq, mp);

#undef	REPLY_LEN
}

/*
 * When the mtu in the ipif changes, we call this routine through ire_walk
 * to update all the relevant IREs.
 * Skip IRE_LOCAL and "loopback" IRE_BROADCAST by checking ire_stq.
 */
static void
ipif_mtu_change(ire_t *ire, char *ipif_arg)
{
	ipif_t *ipif = (ipif_t *)ipif_arg;

	if (ire->ire_stq == NULL || ire->ire_ipif != ipif)
		return;
	ire->ire_max_frag = MIN(ipif->ipif_mtu, IP_MAXPACKET);
}

/*
 * When the mtu in the ill changes, we call this routine through ire_walk
 * to update all the relevant IREs.
 * Skip IRE_LOCAL and "loopback" IRE_BROADCAST by checking ire_stq.
 */
void
ill_mtu_change(ire_t *ire, char *ill_arg)
{
	ill_t	*ill = (ill_t *)ill_arg;

	if (ire->ire_stq == NULL || ire->ire_ipif->ipif_ill != ill)
		return;
	ire->ire_max_frag = ire->ire_ipif->ipif_mtu;
}

/*
 * Join the ipif specific multicast groups.
 * Must be called after a mapping has been set up in the resolver.  (Always
 * called as writer.)
 */
void
ipif_multicast_up(ipif_t *ipif)
{
	int err;
	ill_t *ill;

	ASSERT(IAM_WRITER_IPIF(ipif));

	ill = ipif->ipif_ill;

	ip1dbg(("ipif_multicast_up\n"));
	if (!(ill->ill_flags & ILLF_MULTICAST) || ipif->ipif_multicast_up)
		return;

	if (ipif->ipif_isv6) {
		in6_addr_t v6allmc = ipv6_all_hosts_mcast;
		in6_addr_t v6solmc = ipv6_solicited_node_mcast;

		v6solmc.s6_addr32[3] |= ipif->ipif_v6lcl_addr.s6_addr32[3];

		if (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr))
			return;

		ip1dbg(("ipif_multicast_up - addmulti\n"));

		/*
		 * Join the all hosts multicast address.  We skip this for
		 * underlying IPMP interfaces since they should be invisible.
		 */
		if (!IS_UNDER_IPMP(ill)) {
			err = ip_addmulti_v6(&v6allmc, ill, ipif->ipif_zoneid,
			    ILGSTAT_NONE, MODE_IS_EXCLUDE, NULL);
			if (err != 0) {
				ip0dbg(("ipif_multicast_up: "
				    "all_hosts_mcast failed %d\n", err));
				return;
			}
			ipif->ipif_joined_allhosts = 1;
		}

		/*
		 * Enable multicast for the solicited node multicast address
		 */
		if (!(ipif->ipif_flags & IPIF_NOLOCAL)) {
			err = ip_addmulti_v6(&v6solmc, ill, ipif->ipif_zoneid,
			    ILGSTAT_NONE, MODE_IS_EXCLUDE, NULL);
			if (err != 0) {
				ip0dbg(("ipif_multicast_up: solicited MC"
				    " failed %d\n", err));
				if (ipif->ipif_joined_allhosts) {
					(void) ip_delmulti_v6(&v6allmc, ill,
					    ipif->ipif_zoneid, B_TRUE, B_TRUE);
					ipif->ipif_joined_allhosts = 0;
				}
				return;
			}
		}
	} else {
		if (ipif->ipif_lcl_addr == INADDR_ANY || IS_UNDER_IPMP(ill))
			return;

		/* Join the all hosts multicast address */
		ip1dbg(("ipif_multicast_up - addmulti\n"));
		err = ip_addmulti(htonl(INADDR_ALLHOSTS_GROUP), ipif,
		    ILGSTAT_NONE, MODE_IS_EXCLUDE, NULL);
		if (err) {
			ip0dbg(("ipif_multicast_up: failed %d\n", err));
			return;
		}
	}
	ipif->ipif_multicast_up = 1;
}

/*
 * Blow away any multicast groups that we joined in ipif_multicast_up().
 * (Explicit memberships are blown away in ill_leave_multicast() when the
 * ill is brought down.)
 */
void
ipif_multicast_down(ipif_t *ipif)
{
	int err;

	ASSERT(IAM_WRITER_IPIF(ipif));

	ip1dbg(("ipif_multicast_down\n"));
	if (!ipif->ipif_multicast_up)
		return;

	ip1dbg(("ipif_multicast_down - delmulti\n"));

	if (!ipif->ipif_isv6) {
		err = ip_delmulti(htonl(INADDR_ALLHOSTS_GROUP), ipif, B_TRUE,
		    B_TRUE);
		if (err != 0)
			ip0dbg(("ipif_multicast_down: failed %d\n", err));

		ipif->ipif_multicast_up = 0;
		return;
	}

	/*
	 * Leave the all-hosts multicast address.
	 */
	if (ipif->ipif_joined_allhosts) {
		err = ip_delmulti_v6(&ipv6_all_hosts_mcast, ipif->ipif_ill,
		    ipif->ipif_zoneid, B_TRUE, B_TRUE);
		if (err != 0) {
			ip0dbg(("ipif_multicast_down: all_hosts_mcast "
			    "failed %d\n", err));
		}
		ipif->ipif_joined_allhosts = 0;
	}

	/*
	 * Disable multicast for the solicited node multicast address
	 */
	if (!(ipif->ipif_flags & IPIF_NOLOCAL)) {
		in6_addr_t ipv6_multi = ipv6_solicited_node_mcast;

		ipv6_multi.s6_addr32[3] |=
		    ipif->ipif_v6lcl_addr.s6_addr32[3];

		err = ip_delmulti_v6(&ipv6_multi, ipif->ipif_ill,
		    ipif->ipif_zoneid, B_TRUE, B_TRUE);
		if (err != 0) {
			ip0dbg(("ipif_multicast_down: sol MC failed %d\n",
			    err));
		}
	}

	ipif->ipif_multicast_up = 0;
}

/*
 * Used when an interface comes up to recreate any extra routes on this
 * interface.
 */
static ire_t **
ipif_recover_ire(ipif_t *ipif)
{
	mblk_t	*mp;
	ire_t	**ipif_saved_irep;
	ire_t	**irep;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ip1dbg(("ipif_recover_ire(%s:%u)", ipif->ipif_ill->ill_name,
	    ipif->ipif_id));

	mutex_enter(&ipif->ipif_saved_ire_lock);
	ipif_saved_irep = (ire_t **)kmem_zalloc(sizeof (ire_t *) *
	    ipif->ipif_saved_ire_cnt, KM_NOSLEEP);
	if (ipif_saved_irep == NULL) {
		mutex_exit(&ipif->ipif_saved_ire_lock);
		return (NULL);
	}

	irep = ipif_saved_irep;
	for (mp = ipif->ipif_saved_ire_mp; mp != NULL; mp = mp->b_cont) {
		ire_t		*ire;
		queue_t		*rfq;
		queue_t		*stq;
		ifrt_t		*ifrt;
		uchar_t		*src_addr;
		uchar_t		*gateway_addr;
		ushort_t	type;

		/*
		 * When the ire was initially created and then added in
		 * ip_rt_add(), it was created either using ipif->ipif_net_type
		 * in the case of a traditional interface route, or as one of
		 * the IRE_OFFSUBNET types (with the exception of
		 * IRE_HOST types ire which is created by icmp_redirect() and
		 * which we don't need to save or recover).  In the case where
		 * ipif->ipif_net_type was IRE_LOOPBACK, ip_rt_add() will update
		 * the ire_type to IRE_IF_NORESOLVER before calling ire_add()
		 * to satisfy software like GateD and Sun Cluster which creates
		 * routes using the the loopback interface's address as a
		 * gateway.
		 *
		 * As ifrt->ifrt_type reflects the already updated ire_type,
		 * ire_create() will be called in the same way here as
		 * in ip_rt_add(), namely using ipif->ipif_net_type when
		 * the route looks like a traditional interface route (where
		 * ifrt->ifrt_type & IRE_INTERFACE is true) and otherwise using
		 * the saved ifrt->ifrt_type.  This means that in the case where
		 * ipif->ipif_net_type is IRE_LOOPBACK, the ire created by
		 * ire_create() will be an IRE_LOOPBACK, it will then be turned
		 * into an IRE_IF_NORESOLVER and then added by ire_add().
		 */
		ifrt = (ifrt_t *)mp->b_rptr;
		ASSERT(ifrt->ifrt_type != IRE_CACHE);
		if (ifrt->ifrt_type & IRE_INTERFACE) {
			rfq = NULL;
			stq = (ipif->ipif_net_type == IRE_IF_RESOLVER)
			    ? ipif->ipif_rq : ipif->ipif_wq;
			src_addr = (ifrt->ifrt_flags & RTF_SETSRC)
			    ? (uint8_t *)&ifrt->ifrt_src_addr
			    : (uint8_t *)&ipif->ipif_src_addr;
			gateway_addr = NULL;
			type = ipif->ipif_net_type;
		} else if (ifrt->ifrt_type & IRE_BROADCAST) {
			/* Recover multiroute broadcast IRE. */
			rfq = ipif->ipif_rq;
			stq = ipif->ipif_wq;
			src_addr = (ifrt->ifrt_flags & RTF_SETSRC)
			    ? (uint8_t *)&ifrt->ifrt_src_addr
			    : (uint8_t *)&ipif->ipif_src_addr;
			gateway_addr = (uint8_t *)&ifrt->ifrt_gateway_addr;
			type = ifrt->ifrt_type;
		} else {
			rfq = NULL;
			stq = NULL;
			src_addr = (ifrt->ifrt_flags & RTF_SETSRC)
			    ? (uint8_t *)&ifrt->ifrt_src_addr : NULL;
			gateway_addr = (uint8_t *)&ifrt->ifrt_gateway_addr;
			type = ifrt->ifrt_type;
		}

		/*
		 * Create a copy of the IRE with the saved address and netmask.
		 */
		ip1dbg(("ipif_recover_ire: creating IRE %s (%d) for "
		    "0x%x/0x%x\n",
		    ip_nv_lookup(ire_nv_tbl, ifrt->ifrt_type), ifrt->ifrt_type,
		    ntohl(ifrt->ifrt_addr),
		    ntohl(ifrt->ifrt_mask)));
		ire = ire_create(
		    (uint8_t *)&ifrt->ifrt_addr,
		    (uint8_t *)&ifrt->ifrt_mask,
		    src_addr,
		    gateway_addr,
		    &ifrt->ifrt_max_frag,
		    NULL,
		    rfq,
		    stq,
		    type,
		    ipif,
		    0,
		    0,
		    0,
		    ifrt->ifrt_flags,
		    &ifrt->ifrt_iulp_info,
		    NULL,
		    NULL,
		    ipst);

		if (ire == NULL) {
			mutex_exit(&ipif->ipif_saved_ire_lock);
			kmem_free(ipif_saved_irep,
			    ipif->ipif_saved_ire_cnt * sizeof (ire_t *));
			return (NULL);
		}

		/*
		 * Some software (for example, GateD and Sun Cluster) attempts
		 * to create (what amount to) IRE_PREFIX routes with the
		 * loopback address as the gateway.  This is primarily done to
		 * set up prefixes with the RTF_REJECT flag set (for example,
		 * when generating aggregate routes.)
		 *
		 * If the IRE type (as defined by ipif->ipif_net_type) is
		 * IRE_LOOPBACK, then we map the request into a
		 * IRE_IF_NORESOLVER.
		 */
		if (ipif->ipif_net_type == IRE_LOOPBACK)
			ire->ire_type = IRE_IF_NORESOLVER;
		/*
		 * ire held by ire_add, will be refreled' towards the
		 * the end of ipif_up_done
		 */
		(void) ire_add(&ire, NULL, NULL, NULL, B_FALSE);
		*irep = ire;
		irep++;
		ip1dbg(("ipif_recover_ire: added ire %p\n", (void *)ire));
	}
	mutex_exit(&ipif->ipif_saved_ire_lock);
	return (ipif_saved_irep);
}

/*
 * Used to set the netmask and broadcast address to default values when the
 * interface is brought up.  (Always called as writer.)
 */
static void
ipif_set_default(ipif_t *ipif)
{
	ASSERT(MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	if (!ipif->ipif_isv6) {
		/*
		 * Interface holds an IPv4 address. Default
		 * mask is the natural netmask.
		 */
		if (!ipif->ipif_net_mask) {
			ipaddr_t	v4mask;

			v4mask = ip_net_mask(ipif->ipif_lcl_addr);
			V4MASK_TO_V6(v4mask, ipif->ipif_v6net_mask);
		}
		if (ipif->ipif_flags & IPIF_POINTOPOINT) {
			/* ipif_subnet is ipif_pp_dst_addr for pt-pt */
			ipif->ipif_v6subnet = ipif->ipif_v6pp_dst_addr;
		} else {
			V6_MASK_COPY(ipif->ipif_v6lcl_addr,
			    ipif->ipif_v6net_mask, ipif->ipif_v6subnet);
		}
		/*
		 * NOTE: SunOS 4.X does this even if the broadcast address
		 * has been already set thus we do the same here.
		 */
		if (ipif->ipif_flags & IPIF_BROADCAST) {
			ipaddr_t	v4addr;

			v4addr = ipif->ipif_subnet | ~ipif->ipif_net_mask;
			IN6_IPADDR_TO_V4MAPPED(v4addr, &ipif->ipif_v6brd_addr);
		}
	} else {
		/*
		 * Interface holds an IPv6-only address.  Default
		 * mask is all-ones.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6net_mask))
			ipif->ipif_v6net_mask = ipv6_all_ones;
		if (ipif->ipif_flags & IPIF_POINTOPOINT) {
			/* ipif_subnet is ipif_pp_dst_addr for pt-pt */
			ipif->ipif_v6subnet = ipif->ipif_v6pp_dst_addr;
		} else {
			V6_MASK_COPY(ipif->ipif_v6lcl_addr,
			    ipif->ipif_v6net_mask, ipif->ipif_v6subnet);
		}
	}
}

/*
 * Return 0 if this address can be used as local address without causing
 * duplicate address problems. Otherwise, return EADDRNOTAVAIL if the address
 * is already up on a different ill, and EADDRINUSE if it's up on the same ill.
 * Note that the same IPv6 link-local address is allowed as long as the ills
 * are not on the same link.
 */
int
ip_addr_availability_check(ipif_t *new_ipif)
{
	in6_addr_t our_v6addr;
	ill_t *ill;
	ipif_t *ipif;
	ill_walk_context_t ctx;
	ip_stack_t	*ipst = new_ipif->ipif_ill->ill_ipst;

	ASSERT(IAM_WRITER_IPIF(new_ipif));
	ASSERT(MUTEX_HELD(&ipst->ips_ip_addr_avail_lock));
	ASSERT(RW_READ_HELD(&ipst->ips_ill_g_lock));

	new_ipif->ipif_flags &= ~IPIF_UNNUMBERED;
	if (IN6_IS_ADDR_UNSPECIFIED(&new_ipif->ipif_v6lcl_addr) ||
	    IN6_IS_ADDR_V4MAPPED_ANY(&new_ipif->ipif_v6lcl_addr))
		return (0);

	our_v6addr = new_ipif->ipif_v6lcl_addr;

	if (new_ipif->ipif_isv6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_V4(&ctx, ipst);

	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if ((ipif == new_ipif) ||
			    !(ipif->ipif_flags & IPIF_UP) ||
			    (ipif->ipif_flags & IPIF_UNNUMBERED) ||
			    !IN6_ARE_ADDR_EQUAL(&ipif->ipif_v6lcl_addr,
			    &our_v6addr))
				continue;

			if (new_ipif->ipif_flags & IPIF_POINTOPOINT)
				new_ipif->ipif_flags |= IPIF_UNNUMBERED;
			else if (ipif->ipif_flags & IPIF_POINTOPOINT)
				ipif->ipif_flags |= IPIF_UNNUMBERED;
			else if ((IN6_IS_ADDR_LINKLOCAL(&our_v6addr) ||
			    IN6_IS_ADDR_SITELOCAL(&our_v6addr)) &&
			    !IS_ON_SAME_LAN(ill, new_ipif->ipif_ill))
				continue;
			else if (new_ipif->ipif_zoneid != ipif->ipif_zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES && IS_LOOPBACK(ill))
				continue;
			else if (new_ipif->ipif_ill == ill)
				return (EADDRINUSE);
			else
				return (EADDRNOTAVAIL);
		}
	}

	return (0);
}

/*
 * Bring up an ipif: bring up arp/ndp, bring up the DLPI stream, and add
 * IREs for the ipif.
 * When the routine returns EINPROGRESS then mp has been consumed and
 * the ioctl will be acked from ip_rput_dlpi.
 */
int
ipif_up(ipif_t *ipif, queue_t *q, mblk_t *mp)
{
	ill_t		*ill = ipif->ipif_ill;
	boolean_t 	isv6 = ipif->ipif_isv6;
	int		err = 0;
	boolean_t	success;
	uint_t		ipif_orig_id;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(IAM_WRITER_IPIF(ipif));

	ip1dbg(("ipif_up(%s:%u)\n", ill->ill_name, ipif->ipif_id));

	/* Shouldn't get here if it is already up. */
	if (ipif->ipif_flags & IPIF_UP)
		return (EALREADY);

	/*
	 * If this is a request to bring up a data address on an interface
	 * under IPMP, then move the address to its IPMP meta-interface and
	 * try to bring it up.  One complication is that the zeroth ipif for
	 * an ill is special, in that every ill always has one, and that code
	 * throughout IP deferences ill->ill_ipif without holding any locks.
	 */
	if (IS_UNDER_IPMP(ill) && ipmp_ipif_is_dataaddr(ipif) &&
	    (!ipif->ipif_isv6 || !V6_IPIF_LINKLOCAL(ipif))) {
		ipif_t	*stubipif = NULL, *moveipif = NULL;
		ill_t	*ipmp_ill = ipmp_illgrp_ipmp_ill(ill->ill_grp);

		/*
		 * The ipif being brought up should be quiesced.  If it's not,
		 * something has gone amiss and we need to bail out.  (If it's
		 * quiesced, we know it will remain so via IPIF_CHANGING.)
		 */
		mutex_enter(&ill->ill_lock);
		if (!ipif_is_quiescent(ipif)) {
			mutex_exit(&ill->ill_lock);
			return (EINVAL);
		}
		mutex_exit(&ill->ill_lock);

		/*
		 * If we're going to need to allocate ipifs, do it prior
		 * to starting the move (and grabbing locks).
		 */
		if (ipif->ipif_id == 0) {
			moveipif = ipif_allocate(ill, 0, IRE_LOCAL, B_TRUE,
			    B_FALSE);
			stubipif = ipif_allocate(ill, 0, IRE_LOCAL, B_TRUE,
			    B_FALSE);
			if (moveipif == NULL || stubipif == NULL) {
				mi_free(moveipif);
				mi_free(stubipif);
				return (ENOMEM);
			}
		}

		/*
		 * Grab or transfer the ipif to move.  During the move, keep
		 * ill_g_lock held to prevent any ill walker threads from
		 * seeing things in an inconsistent state.
		 */
		rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
		if (ipif->ipif_id != 0) {
			ipif_remove(ipif);
		} else {
			ipif_transfer(ipif, moveipif, stubipif);
			ipif = moveipif;
		}

		/*
		 * Place the ipif on the IPMP ill.  If the zeroth ipif on
		 * the IPMP ill is a stub (0.0.0.0 down address) then we
		 * replace that one.  Otherwise, pick the next available slot.
		 */
		ipif->ipif_ill = ipmp_ill;
		ipif_orig_id = ipif->ipif_id;

		if (ipmp_ipif_is_stubaddr(ipmp_ill->ill_ipif)) {
			ipif_transfer(ipif, ipmp_ill->ill_ipif, NULL);
			ipif = ipmp_ill->ill_ipif;
		} else {
			ipif->ipif_id = -1;
			if (ipif_insert(ipif, B_FALSE) != 0) {
				/*
				 * No more available ipif_id's -- put it back
				 * on the original ill and fail the operation.
				 * Since we're writer on the ill, we can be
				 * sure our old slot is still available.
				 */
				ipif->ipif_id = ipif_orig_id;
				ipif->ipif_ill = ill;
				if (ipif_orig_id == 0) {
					ipif_transfer(ipif, ill->ill_ipif,
					    NULL);
				} else {
					VERIFY(ipif_insert(ipif, B_FALSE) == 0);
				}
				rw_exit(&ipst->ips_ill_g_lock);
				return (ENOMEM);
			}
		}
		rw_exit(&ipst->ips_ill_g_lock);

		/*
		 * Tell SCTP that the ipif has moved.  Note that even if we
		 * had to allocate a new ipif, the original sequence id was
		 * preserved and therefore SCTP won't know.
		 */
		sctp_move_ipif(ipif, ill, ipmp_ill);

		/*
		 * If the ipif being brought up was on slot zero, then we
		 * first need to bring up the placeholder we stuck there.  In
		 * ip_rput_dlpi_writer(), ip_arp_done(), or the recursive call
		 * to ipif_up() itself, if we successfully bring up the
		 * placeholder, we'll check ill_move_ipif and bring it up too.
		 */
		if (ipif_orig_id == 0) {
			ASSERT(ill->ill_move_ipif == NULL);
			ill->ill_move_ipif = ipif;
			if ((err = ipif_up(ill->ill_ipif, q, mp)) == 0)
				ASSERT(ill->ill_move_ipif == NULL);
			if (err != EINPROGRESS)
				ill->ill_move_ipif = NULL;
			return (err);
		}

		/*
		 * Bring it up on the IPMP ill.
		 */
		return (ipif_up(ipif, q, mp));
	}

	/* Skip arp/ndp for any loopback interface. */
	if (ill->ill_wq != NULL) {
		conn_t *connp = CONN_Q(q) ? Q_TO_CONN(q) : NULL;
		ipsq_t	*ipsq = ill->ill_phyint->phyint_ipsq;

		if (!ill->ill_dl_up) {
			/*
			 * ill_dl_up is not yet set. i.e. we are yet to
			 * DL_BIND with the driver and this is the first
			 * logical interface on the ill to become "up".
			 * Tell the driver to get going (via DL_BIND_REQ).
			 * Note that changing "significant" IFF_ flags
			 * address/netmask etc cause a down/up dance, but
			 * does not cause an unbind (DL_UNBIND) with the driver
			 */
			return (ill_dl_up(ill, ipif, mp, q));
		}

		/*
		 * ipif_resolver_up may end up sending an
		 * AR_INTERFACE_UP message to ARP, which would, in
		 * turn send a DLPI message to the driver. ioctls are
		 * serialized and so we cannot send more than one
		 * interface up message at a time. If ipif_resolver_up
		 * does send an interface up message to ARP, we get
		 * EINPROGRESS and we will complete in ip_arp_done.
		 */

		ASSERT(connp != NULL || !CONN_Q(q));
		if (connp != NULL)
			mutex_enter(&connp->conn_lock);
		mutex_enter(&ill->ill_lock);
		success = ipsq_pending_mp_add(connp, ipif, q, mp, 0);
		mutex_exit(&ill->ill_lock);
		if (connp != NULL)
			mutex_exit(&connp->conn_lock);
		if (!success)
			return (EINTR);

		/*
		 * Crank up the resolver.  For IPv6, this cranks up the
		 * external resolver if one is configured, but even if an
		 * external resolver isn't configured, it must be called to
		 * reset DAD state.  For IPv6, if an external resolver is not
		 * being used, ipif_resolver_up() will never return
		 * EINPROGRESS, so we can always call ipif_ndp_up() here.
		 * Note that if an external resolver is being used, there's no
		 * need to call ipif_ndp_up() since it will do nothing.
		 */
		err = ipif_resolver_up(ipif, Res_act_initial);
		if (err == EINPROGRESS) {
			/* We will complete it in ip_arp_done() */
			return (err);
		}

		if (isv6 && err == 0)
			err = ipif_ndp_up(ipif, B_TRUE);

		ASSERT(err != EINPROGRESS);
		mp = ipsq_pending_mp_get(ipsq, &connp);
		ASSERT(mp != NULL);
		if (err != 0)
			return (err);
	} else {
		/*
		 * Interfaces without underlying hardware don't do duplicate
		 * address detection.
		 */
		ASSERT(!(ipif->ipif_flags & IPIF_DUPLICATE));
		ipif->ipif_addr_ready = 1;
	}

	err = isv6 ? ipif_up_done_v6(ipif) : ipif_up_done(ipif);
	if (err == 0 && ill->ill_move_ipif != NULL) {
		ipif = ill->ill_move_ipif;
		ill->ill_move_ipif = NULL;
		return (ipif_up(ipif, q, mp));
	}
	return (err);
}

/*
 * Perform a bind for the physical device.
 * When the routine returns EINPROGRESS then mp has been consumed and
 * the ioctl will be acked from ip_rput_dlpi.
 * Allocate an unbind message and save it until ipif_down.
 */
static int
ill_dl_up(ill_t *ill, ipif_t *ipif, mblk_t *mp, queue_t *q)
{
	areq_t	*areq;
	mblk_t	*areq_mp = NULL;
	mblk_t	*bind_mp = NULL;
	mblk_t	*unbind_mp = NULL;
	conn_t	*connp;
	boolean_t success;
	uint16_t sap_addr;

	ip1dbg(("ill_dl_up(%s)\n", ill->ill_name));
	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(mp != NULL);

	/* Create a resolver cookie for ARP */
	if (!ill->ill_isv6 && ill->ill_net_type == IRE_IF_RESOLVER) {
		areq_mp = ill_arp_alloc(ill, (uchar_t *)&ip_areq_template, 0);
		if (areq_mp == NULL)
			return (ENOMEM);

		freemsg(ill->ill_resolver_mp);
		ill->ill_resolver_mp = areq_mp;
		areq = (areq_t *)areq_mp->b_rptr;
		sap_addr = ill->ill_sap;
		bcopy(&sap_addr, areq->areq_sap, sizeof (sap_addr));
	}
	bind_mp = ip_dlpi_alloc(sizeof (dl_bind_req_t) + sizeof (long),
	    DL_BIND_REQ);
	if (bind_mp == NULL)
		goto bad;
	((dl_bind_req_t *)bind_mp->b_rptr)->dl_sap = ill->ill_sap;
	((dl_bind_req_t *)bind_mp->b_rptr)->dl_service_mode = DL_CLDLS;

	unbind_mp = ip_dlpi_alloc(sizeof (dl_unbind_req_t), DL_UNBIND_REQ);
	if (unbind_mp == NULL)
		goto bad;

	/*
	 * Record state needed to complete this operation when the
	 * DL_BIND_ACK shows up.  Also remember the pre-allocated mblks.
	 */
	ASSERT(WR(q)->q_next == NULL);
	connp = Q_TO_CONN(q);

	mutex_enter(&connp->conn_lock);
	mutex_enter(&ipif->ipif_ill->ill_lock);
	success = ipsq_pending_mp_add(connp, ipif, q, mp, 0);
	mutex_exit(&ipif->ipif_ill->ill_lock);
	mutex_exit(&connp->conn_lock);
	if (!success)
		goto bad;

	/*
	 * Save the unbind message for ill_dl_down(); it will be consumed when
	 * the interface goes down.
	 */
	ASSERT(ill->ill_unbind_mp == NULL);
	ill->ill_unbind_mp = unbind_mp;

	ill_dlpi_send(ill, bind_mp);
	/* Send down link-layer capabilities probe if not already done. */
	ill_capability_probe(ill);

	/*
	 * Sysid used to rely on the fact that netboots set domainname
	 * and the like. Now that miniroot boots aren't strictly netboots
	 * and miniroot network configuration is driven from userland
	 * these things still need to be set. This situation can be detected
	 * by comparing the interface being configured here to the one
	 * dhcifname was set to reference by the boot loader. Once sysid is
	 * converted to use dhcp_ipc_getinfo() this call can go away.
	 */
	if ((ipif->ipif_flags & IPIF_DHCPRUNNING) &&
	    (strcmp(ill->ill_name, dhcifname) == 0) &&
	    (strlen(srpc_domain) == 0)) {
		if (dhcpinit() != 0)
			cmn_err(CE_WARN, "no cached dhcp response");
	}

	/*
	 * This operation will complete in ip_rput_dlpi with either
	 * a DL_BIND_ACK or DL_ERROR_ACK.
	 */
	return (EINPROGRESS);
bad:
	ip1dbg(("ill_dl_up(%s) FAILED\n", ill->ill_name));

	freemsg(bind_mp);
	freemsg(unbind_mp);
	return (ENOMEM);
}

uint_t ip_loopback_mtuplus = IP_LOOPBACK_MTU + IP_SIMPLE_HDR_LENGTH + 20;

/*
 * DLPI and ARP is up.
 * Create all the IREs associated with an interface bring up multicast.
 * Set the interface flag and finish other initialization
 * that potentially had to be differed to after DL_BIND_ACK.
 */
int
ipif_up_done(ipif_t *ipif)
{
	ire_t	*ire_array[20];
	ire_t	**irep = ire_array;
	ire_t	**irep1;
	ipaddr_t net_mask = 0;
	ipaddr_t subnet_mask, route_mask;
	ill_t	*ill = ipif->ipif_ill;
	queue_t	*stq;
	ipif_t	 *src_ipif;
	ipif_t   *tmp_ipif;
	boolean_t	flush_ire_cache = B_TRUE;
	int	err = 0;
	ire_t	**ipif_saved_irep = NULL;
	int ipif_saved_ire_cnt;
	int	cnt;
	boolean_t	src_ipif_held = B_FALSE;
	boolean_t	loopback = B_FALSE;
	ip_stack_t	*ipst = ill->ill_ipst;

	ip1dbg(("ipif_up_done(%s:%u)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id));
	/* Check if this is a loopback interface */
	if (ipif->ipif_ill->ill_wq == NULL)
		loopback = B_TRUE;

	ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));
	/*
	 * If all other interfaces for this ill are down or DEPRECATED,
	 * or otherwise unsuitable for source address selection, remove
	 * any IRE_CACHE entries for this ill to make sure source
	 * address selection gets to take this new ipif into account.
	 * No need to hold ill_lock while traversing the ipif list since
	 * we are writer
	 */
	for (tmp_ipif = ill->ill_ipif; tmp_ipif;
	    tmp_ipif = tmp_ipif->ipif_next) {
		if (((tmp_ipif->ipif_flags &
		    (IPIF_NOXMIT|IPIF_ANYCAST|IPIF_NOLOCAL|IPIF_DEPRECATED)) ||
		    !(tmp_ipif->ipif_flags & IPIF_UP)) ||
		    (tmp_ipif == ipif))
			continue;
		/* first useable pre-existing interface */
		flush_ire_cache = B_FALSE;
		break;
	}
	if (flush_ire_cache)
		ire_walk_ill_v4(MATCH_IRE_ILL | MATCH_IRE_TYPE,
		    IRE_CACHE, ill_ipif_cache_delete, (char *)ill, ill);

	/*
	 * Figure out which way the send-to queue should go.  Only
	 * IRE_IF_RESOLVER or IRE_IF_NORESOLVER or IRE_LOOPBACK
	 * should show up here.
	 */
	switch (ill->ill_net_type) {
	case IRE_IF_RESOLVER:
		stq = ill->ill_rq;
		break;
	case IRE_IF_NORESOLVER:
	case IRE_LOOPBACK:
		stq = ill->ill_wq;
		break;
	default:
		return (EINVAL);
	}

	if (IS_LOOPBACK(ill)) {
		/*
		 * lo0:1 and subsequent ipifs were marked IRE_LOCAL in
		 * ipif_lookup_on_name(), but in the case of zones we can have
		 * several loopback addresses on lo0. So all the interfaces with
		 * loopback addresses need to be marked IRE_LOOPBACK.
		 */
		if (V4_PART_OF_V6(ipif->ipif_v6lcl_addr) ==
		    htonl(INADDR_LOOPBACK))
			ipif->ipif_ire_type = IRE_LOOPBACK;
		else
			ipif->ipif_ire_type = IRE_LOCAL;
	}

	if (ipif->ipif_flags & (IPIF_NOLOCAL|IPIF_ANYCAST) ||
	    ((ipif->ipif_flags & IPIF_DEPRECATED) &&
	    !(ipif->ipif_flags & IPIF_NOFAILOVER))) {
		/*
		 * Can't use our source address. Select a different
		 * source address for the IRE_INTERFACE and IRE_LOCAL
		 */
		src_ipif = ipif_select_source(ipif->ipif_ill,
		    ipif->ipif_subnet, ipif->ipif_zoneid);
		if (src_ipif == NULL)
			src_ipif = ipif;	/* Last resort */
		else
			src_ipif_held = B_TRUE;
	} else {
		src_ipif = ipif;
	}

	/* Create all the IREs associated with this interface */
	if ((ipif->ipif_lcl_addr != INADDR_ANY) &&
	    !(ipif->ipif_flags & IPIF_NOLOCAL)) {

		/*
		 * If we're on a labeled system then make sure that zone-
		 * private addresses have proper remote host database entries.
		 */
		if (is_system_labeled() &&
		    ipif->ipif_ire_type != IRE_LOOPBACK &&
		    !tsol_check_interface_address(ipif))
			return (EINVAL);

		/* Register the source address for __sin6_src_id */
		err = ip_srcid_insert(&ipif->ipif_v6lcl_addr,
		    ipif->ipif_zoneid, ipst);
		if (err != 0) {
			ip0dbg(("ipif_up_done: srcid_insert %d\n", err));
			return (err);
		}

		/* If the interface address is set, create the local IRE. */
		ip1dbg(("ipif_up_done: 0x%p creating IRE 0x%x for 0x%x\n",
		    (void *)ipif,
		    ipif->ipif_ire_type,
		    ntohl(ipif->ipif_lcl_addr)));
		*irep++ = ire_create(
		    (uchar_t *)&ipif->ipif_lcl_addr,	/* dest address */
		    (uchar_t *)&ip_g_all_ones,		/* mask */
		    (uchar_t *)&src_ipif->ipif_src_addr, /* source address */
		    NULL,				/* no gateway */
		    &ip_loopback_mtuplus,		/* max frag size */
		    NULL,
		    ipif->ipif_rq,			/* recv-from queue */
		    NULL,				/* no send-to queue */
		    ipif->ipif_ire_type,		/* LOCAL or LOOPBACK */
		    ipif,
		    0,
		    0,
		    0,
		    (ipif->ipif_flags & IPIF_PRIVATE) ?
		    RTF_PRIVATE : 0,
		    &ire_uinfo_null,
		    NULL,
		    NULL,
		    ipst);
	} else {
		ip1dbg((
		    "ipif_up_done: not creating IRE %d for 0x%x: flags 0x%x\n",
		    ipif->ipif_ire_type,
		    ntohl(ipif->ipif_lcl_addr),
		    (uint_t)ipif->ipif_flags));
	}
	if ((ipif->ipif_lcl_addr != INADDR_ANY) &&
	    !(ipif->ipif_flags & IPIF_NOLOCAL)) {
		net_mask = ip_net_mask(ipif->ipif_lcl_addr);
	} else {
		net_mask = htonl(IN_CLASSA_NET);	/* fallback */
	}

	subnet_mask = ipif->ipif_net_mask;

	/*
	 * If mask was not specified, use natural netmask of
	 * interface address. Also, store this mask back into the
	 * ipif struct.
	 */
	if (subnet_mask == 0) {
		subnet_mask = net_mask;
		V4MASK_TO_V6(subnet_mask, ipif->ipif_v6net_mask);
		V6_MASK_COPY(ipif->ipif_v6lcl_addr, ipif->ipif_v6net_mask,
		    ipif->ipif_v6subnet);
	}

	/* Set up the IRE_IF_RESOLVER or IRE_IF_NORESOLVER, as appropriate. */
	if (stq != NULL && !(ipif->ipif_flags & IPIF_NOXMIT) &&
	    ipif->ipif_subnet != INADDR_ANY) {
		/* ipif_subnet is ipif_pp_dst_addr for pt-pt */

		if (ipif->ipif_flags & IPIF_POINTOPOINT) {
			route_mask = IP_HOST_MASK;
		} else {
			route_mask = subnet_mask;
		}

		ip1dbg(("ipif_up_done: ipif 0x%p ill 0x%p "
		    "creating if IRE ill_net_type 0x%x for 0x%x\n",
		    (void *)ipif, (void *)ill,
		    ill->ill_net_type,
		    ntohl(ipif->ipif_subnet)));
		*irep++ = ire_create(
		    (uchar_t *)&ipif->ipif_subnet,	/* dest address */
		    (uchar_t *)&route_mask,		/* mask */
		    (uchar_t *)&src_ipif->ipif_src_addr, /* src addr */
		    NULL,				/* no gateway */
		    &ipif->ipif_mtu,			/* max frag */
		    NULL,
		    NULL,				/* no recv queue */
		    stq,				/* send-to queue */
		    ill->ill_net_type,			/* IF_[NO]RESOLVER */
		    ipif,
		    0,
		    0,
		    0,
		    (ipif->ipif_flags & IPIF_PRIVATE) ? RTF_PRIVATE: 0,
		    &ire_uinfo_null,
		    NULL,
		    NULL,
		    ipst);
	}

	/*
	 * Create any necessary broadcast IREs.
	 */
	if (ipif->ipif_flags & IPIF_BROADCAST)
		irep = ipif_create_bcast_ires(ipif, irep);

	ASSERT(!MUTEX_HELD(&ipif->ipif_ill->ill_lock));

	/* If an earlier ire_create failed, get out now */
	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		if (*irep1 == NULL) {
			ip1dbg(("ipif_up_done: NULL ire found in ire_array\n"));
			err = ENOMEM;
			goto bad;
		}
	}

	/*
	 * Need to atomically check for IP address availability under
	 * ip_addr_avail_lock.  ill_g_lock is held as reader to ensure no new
	 * ills or new ipifs can be added while we are checking availability.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	mutex_enter(&ipst->ips_ip_addr_avail_lock);
	/* Mark it up, and increment counters. */
	ipif->ipif_flags |= IPIF_UP;
	ill->ill_ipif_up_count++;
	err = ip_addr_availability_check(ipif);
	mutex_exit(&ipst->ips_ip_addr_avail_lock);
	rw_exit(&ipst->ips_ill_g_lock);

	if (err != 0) {
		/*
		 * Our address may already be up on the same ill. In this case,
		 * the ARP entry for our ipif replaced the one for the other
		 * ipif. So we don't want to delete it (otherwise the other ipif
		 * would be unable to send packets).
		 * ip_addr_availability_check() identifies this case for us and
		 * returns EADDRINUSE; we need to turn it into EADDRNOTAVAIL
		 * which is the expected error code.
		 */
		if (err == EADDRINUSE) {
			freemsg(ipif->ipif_arp_del_mp);
			ipif->ipif_arp_del_mp = NULL;
			err = EADDRNOTAVAIL;
		}
		ill->ill_ipif_up_count--;
		ipif->ipif_flags &= ~IPIF_UP;
		goto bad;
	}

	/*
	 * Add in all newly created IREs.  ire_create_bcast() has
	 * already checked for duplicates of the IRE_BROADCAST type.
	 */
	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		ASSERT(!MUTEX_HELD(&((*irep1)->ire_ipif->ipif_ill->ill_lock)));
		/*
		 * refheld by ire_add. refele towards the end of the func
		 */
		(void) ire_add(irep1, NULL, NULL, NULL, B_FALSE);
	}

	/* Recover any additional IRE_IF_[NO]RESOLVER entries for this ipif */
	ipif_saved_ire_cnt = ipif->ipif_saved_ire_cnt;
	ipif_saved_irep = ipif_recover_ire(ipif);

	if (!loopback) {
		/*
		 * If the broadcast address has been set, make sure it makes
		 * sense based on the interface address.
		 * Only match on ill since we are sharing broadcast addresses.
		 */
		if ((ipif->ipif_brd_addr != INADDR_ANY) &&
		    (ipif->ipif_flags & IPIF_BROADCAST)) {
			ire_t	*ire;

			ire = ire_ctable_lookup(ipif->ipif_brd_addr, 0,
			    IRE_BROADCAST, ipif, ALL_ZONES,
			    NULL, (MATCH_IRE_TYPE | MATCH_IRE_ILL), ipst);

			if (ire == NULL) {
				/*
				 * If there isn't a matching broadcast IRE,
				 * revert to the default for this netmask.
				 */
				ipif->ipif_v6brd_addr = ipv6_all_zeros;
				mutex_enter(&ipif->ipif_ill->ill_lock);
				ipif_set_default(ipif);
				mutex_exit(&ipif->ipif_ill->ill_lock);
			} else {
				ire_refrele(ire);
			}
		}

	}

	if (ill->ill_need_recover_multicast) {
		/*
		 * Need to recover all multicast memberships in the driver.
		 * This had to be deferred until we had attached.  The same
		 * code exists in ipif_up_done_v6() to recover IPv6
		 * memberships.
		 *
		 * Note that it would be preferable to unconditionally do the
		 * ill_recover_multicast() in ill_dl_up(), but we cannot do
		 * that since ill_join_allmulti() depends on ill_dl_up being
		 * set, and it is not set until we receive a DL_BIND_ACK after
		 * having called ill_dl_up().
		 */
		ill_recover_multicast(ill);
	}

	if (ill->ill_ipif_up_count == 1) {
		/*
		 * Since the interface is now up, it may now be active.
		 */
		if (IS_UNDER_IPMP(ill))
			ipmp_ill_refresh_active(ill);

		/*
		 * If this is an IPMP interface, we may now be able to
		 * establish ARP entries.
		 */
		if (IS_IPMP(ill))
			ipmp_illgrp_refresh_arpent(ill->ill_grp);
	}

	/* Join the allhosts multicast address */
	ipif_multicast_up(ipif);

	/*
	 * See if anybody else would benefit from our new ipif.
	 */
	if (!loopback &&
	    !(ipif->ipif_flags & (IPIF_NOLOCAL|IPIF_ANYCAST|IPIF_DEPRECATED))) {
		ill_update_source_selection(ill);
	}

	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		if (*irep1 != NULL) {
			/* was held in ire_add */
			ire_refrele(*irep1);
		}
	}

	cnt = ipif_saved_ire_cnt;
	for (irep1 = ipif_saved_irep; cnt > 0; irep1++, cnt--) {
		if (*irep1 != NULL) {
			/* was held in ire_add */
			ire_refrele(*irep1);
		}
	}

	if (!loopback && ipif->ipif_addr_ready) {
		/* Broadcast an address mask reply. */
		ipif_mask_reply(ipif);
	}
	if (ipif_saved_irep != NULL) {
		kmem_free(ipif_saved_irep,
		    ipif_saved_ire_cnt * sizeof (ire_t *));
	}
	if (src_ipif_held)
		ipif_refrele(src_ipif);

	/*
	 * This had to be deferred until we had bound.  Tell routing sockets and
	 * others that this interface is up if it looks like the address has
	 * been validated.  Otherwise, if it isn't ready yet, wait for
	 * duplicate address detection to do its thing.
	 */
	if (ipif->ipif_addr_ready)
		ipif_up_notify(ipif);
	return (0);

bad:
	ip1dbg(("ipif_up_done: FAILED \n"));

	while (irep > ire_array) {
		irep--;
		if (*irep != NULL)
			ire_delete(*irep);
	}
	(void) ip_srcid_remove(&ipif->ipif_v6lcl_addr, ipif->ipif_zoneid, ipst);

	if (ipif_saved_irep != NULL) {
		kmem_free(ipif_saved_irep,
		    ipif_saved_ire_cnt * sizeof (ire_t *));
	}
	if (src_ipif_held)
		ipif_refrele(src_ipif);

	ipif_resolver_down(ipif);
	return (err);
}

/*
 * Turn off the ARP with the ILLF_NOARP flag.
 */
static int
ill_arp_off(ill_t *ill)
{
	mblk_t	*arp_off_mp = NULL;
	mblk_t	*arp_on_mp = NULL;

	ip1dbg(("ill_arp_off(%s)\n", ill->ill_name));

	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT(ill->ill_net_type == IRE_IF_RESOLVER);

	/*
	 * If the on message is still around we've already done
	 * an arp_off without doing an arp_on thus there is no
	 * work needed.
	 */
	if (ill->ill_arp_on_mp != NULL)
		return (0);

	/*
	 * Allocate an ARP on message (to be saved) and an ARP off message
	 */
	arp_off_mp = ill_arp_alloc(ill, (uchar_t *)&ip_aroff_template, 0);
	if (!arp_off_mp)
		return (ENOMEM);

	arp_on_mp = ill_arp_alloc(ill, (uchar_t *)&ip_aron_template, 0);
	if (!arp_on_mp)
		goto failed;

	ASSERT(ill->ill_arp_on_mp == NULL);
	ill->ill_arp_on_mp = arp_on_mp;

	/* Send an AR_INTERFACE_OFF request */
	putnext(ill->ill_rq, arp_off_mp);
	return (0);
failed:

	if (arp_off_mp)
		freemsg(arp_off_mp);
	return (ENOMEM);
}

/*
 * Turn on ARP by turning off the ILLF_NOARP flag.
 */
static int
ill_arp_on(ill_t *ill)
{
	mblk_t	*mp;

	ip1dbg(("ipif_arp_on(%s)\n", ill->ill_name));

	ASSERT(ill->ill_net_type == IRE_IF_RESOLVER);

	ASSERT(IAM_WRITER_ILL(ill));
	/*
	 * Send an AR_INTERFACE_ON request if we have already done
	 * an arp_off (which allocated the message).
	 */
	if (ill->ill_arp_on_mp != NULL) {
		mp = ill->ill_arp_on_mp;
		ill->ill_arp_on_mp = NULL;
		putnext(ill->ill_rq, mp);
	}
	return (0);
}

/*
 * Checks for availbility of a usable source address (if there is one) when the
 * destination ILL has the ill_usesrc_ifindex pointing to another ILL. Note
 * this selection is done regardless of the destination.
 */
boolean_t
ipif_usesrc_avail(ill_t *ill, zoneid_t zoneid)
{
	uint_t	ifindex;
	ipif_t	*ipif = NULL;
	ill_t	*uill;
	boolean_t isv6;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(ill != NULL);

	isv6 = ill->ill_isv6;
	ifindex = ill->ill_usesrc_ifindex;
	if (ifindex != 0) {
		uill = ill_lookup_on_ifindex(ifindex, isv6, NULL, NULL, NULL,
		    NULL, ipst);
		if (uill == NULL)
			return (NULL);
		mutex_enter(&uill->ill_lock);
		for (ipif = uill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (!IPIF_CAN_LOOKUP(ipif))
				continue;
			if (ipif->ipif_flags & (IPIF_NOLOCAL|IPIF_ANYCAST))
				continue;
			if (!(ipif->ipif_flags & IPIF_UP))
				continue;
			if (ipif->ipif_zoneid != zoneid)
				continue;
			if ((isv6 &&
			    IN6_IS_ADDR_UNSPECIFIED(&ipif->ipif_v6lcl_addr)) ||
			    (ipif->ipif_lcl_addr == INADDR_ANY))
				continue;
			mutex_exit(&uill->ill_lock);
			ill_refrele(uill);
			return (B_TRUE);
		}
		mutex_exit(&uill->ill_lock);
		ill_refrele(uill);
	}
	return (B_FALSE);
}

/*
 * IP source address type, sorted from worst to best.  For a given type,
 * always prefer IP addresses on the same subnet.  All-zones addresses are
 * suboptimal because they pose problems with unlabeled destinations.
 */
typedef enum {
	IPIF_NONE,
	IPIF_DIFFNET_DEPRECATED, 	/* deprecated and different subnet */
	IPIF_SAMENET_DEPRECATED, 	/* deprecated and same subnet */
	IPIF_DIFFNET_ALLZONES,		/* allzones and different subnet */
	IPIF_SAMENET_ALLZONES,		/* allzones and same subnet */
	IPIF_DIFFNET,			/* normal and different subnet */
	IPIF_SAMENET			/* normal and same subnet */
} ipif_type_t;

/*
 * Pick the optimal ipif on `ill' for sending to destination `dst' from zone
 * `zoneid'.  We rate usable ipifs from low -> high as per the ipif_type_t
 * enumeration, and return the highest-rated ipif.  If there's a tie, we pick
 * the first one, unless IPMP is used in which case we round-robin among them;
 * see below for more.
 *
 * Returns NULL if there is no suitable source address for the ill.
 * This only occurs when there is no valid source address for the ill.
 */
ipif_t *
ipif_select_source(ill_t *ill, ipaddr_t dst, zoneid_t zoneid)
{
	ill_t	*usill = NULL;
	ill_t	*ipmp_ill = NULL;
	ipif_t	*start_ipif, *next_ipif, *ipif, *best_ipif;
	ipif_type_t type, best_type;
	tsol_tpc_t *src_rhtp, *dst_rhtp;
	ip_stack_t *ipst = ill->ill_ipst;
	boolean_t samenet;

	if (ill->ill_usesrc_ifindex != 0) {
		usill = ill_lookup_on_ifindex(ill->ill_usesrc_ifindex,
		    B_FALSE, NULL, NULL, NULL, NULL, ipst);
		if (usill != NULL)
			ill = usill;	/* Select source from usesrc ILL */
		else
			return (NULL);
	}

	/*
	 * Test addresses should never be used for source address selection,
	 * so if we were passed one, switch to the IPMP meta-interface.
	 */
	if (IS_UNDER_IPMP(ill)) {
		if ((ipmp_ill = ipmp_ill_hold_ipmp_ill(ill)) != NULL)
			ill = ipmp_ill;	/* Select source from IPMP ill */
		else
			return (NULL);
	}

	/*
	 * If we're dealing with an unlabeled destination on a labeled system,
	 * make sure that we ignore source addresses that are incompatible with
	 * the destination's default label.  That destination's default label
	 * must dominate the minimum label on the source address.
	 */
	dst_rhtp = NULL;
	if (is_system_labeled()) {
		dst_rhtp = find_tpc(&dst, IPV4_VERSION, B_FALSE);
		if (dst_rhtp == NULL)
			return (NULL);
		if (dst_rhtp->tpc_tp.host_type != UNLABELED) {
			TPC_RELE(dst_rhtp);
			dst_rhtp = NULL;
		}
	}

	/*
	 * Hold the ill_g_lock as reader. This makes sure that no ipif/ill
	 * can be deleted. But an ipif/ill can get CONDEMNED any time.
	 * After selecting the right ipif, under ill_lock make sure ipif is
	 * not condemned, and increment refcnt. If ipif is CONDEMNED,
	 * we retry. Inside the loop we still need to check for CONDEMNED,
	 * but not under a lock.
	 */
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
retry:
	/*
	 * For source address selection, we treat the ipif list as circular
	 * and continue until we get back to where we started.  This allows
	 * IPMP to vary source address selection (which improves inbound load
	 * spreading) by caching its last ending point and starting from
	 * there.  NOTE: we don't have to worry about ill_src_ipif changing
	 * ills since that can't happen on the IPMP ill.
	 */
	start_ipif = ill->ill_ipif;
	if (IS_IPMP(ill) && ill->ill_src_ipif != NULL)
		start_ipif = ill->ill_src_ipif;

	ipif = start_ipif;
	best_ipif = NULL;
	best_type = IPIF_NONE;
	do {
		if ((next_ipif = ipif->ipif_next) == NULL)
			next_ipif = ill->ill_ipif;

		if (!IPIF_CAN_LOOKUP(ipif))
			continue;
		/* Always skip NOLOCAL and ANYCAST interfaces */
		if (ipif->ipif_flags & (IPIF_NOLOCAL|IPIF_ANYCAST))
			continue;
		if (!(ipif->ipif_flags & IPIF_UP) || !ipif->ipif_addr_ready)
			continue;
		if (ipif->ipif_zoneid != zoneid &&
		    ipif->ipif_zoneid != ALL_ZONES)
			continue;

		/*
		 * Interfaces with 0.0.0.0 address are allowed to be UP, but
		 * are not valid as source addresses.
		 */
		if (ipif->ipif_lcl_addr == INADDR_ANY)
			continue;

		/*
		 * Check compatibility of local address for destination's
		 * default label if we're on a labeled system.	Incompatible
		 * addresses can't be used at all.
		 */
		if (dst_rhtp != NULL) {
			boolean_t incompat;

			src_rhtp = find_tpc(&ipif->ipif_lcl_addr,
			    IPV4_VERSION, B_FALSE);
			if (src_rhtp == NULL)
				continue;
			incompat = src_rhtp->tpc_tp.host_type != SUN_CIPSO ||
			    src_rhtp->tpc_tp.tp_doi !=
			    dst_rhtp->tpc_tp.tp_doi ||
			    (!_blinrange(&dst_rhtp->tpc_tp.tp_def_label,
			    &src_rhtp->tpc_tp.tp_sl_range_cipso) &&
			    !blinlset(&dst_rhtp->tpc_tp.tp_def_label,
			    src_rhtp->tpc_tp.tp_sl_set_cipso));
			TPC_RELE(src_rhtp);
			if (incompat)
				continue;
		}

		samenet = ((ipif->ipif_net_mask & dst) == ipif->ipif_subnet);

		if (ipif->ipif_flags & IPIF_DEPRECATED) {
			type = samenet ? IPIF_SAMENET_DEPRECATED :
			    IPIF_DIFFNET_DEPRECATED;
		} else if (ipif->ipif_zoneid == ALL_ZONES) {
			type = samenet ? IPIF_SAMENET_ALLZONES :
			    IPIF_DIFFNET_ALLZONES;
		} else {
			type = samenet ? IPIF_SAMENET : IPIF_DIFFNET;
		}

		if (type > best_type) {
			best_type = type;
			best_ipif = ipif;
			if (best_type == IPIF_SAMENET)
				break; /* can't get better */
		}
	} while ((ipif = next_ipif) != start_ipif);

	if ((ipif = best_ipif) != NULL) {
		mutex_enter(&ipif->ipif_ill->ill_lock);
		if (!IPIF_CAN_LOOKUP(ipif)) {
			mutex_exit(&ipif->ipif_ill->ill_lock);
			goto retry;
		}
		ipif_refhold_locked(ipif);

		/*
		 * For IPMP, update the source ipif rotor to the next ipif,
		 * provided we can look it up.  (We must not use it if it's
		 * IPIF_CONDEMNED since we may have grabbed ill_g_lock after
		 * ipif_free() checked ill_src_ipif.)
		 */
		if (IS_IPMP(ill) && ipif != NULL) {
			next_ipif = ipif->ipif_next;
			if (next_ipif != NULL && IPIF_CAN_LOOKUP(next_ipif))
				ill->ill_src_ipif = next_ipif;
			else
				ill->ill_src_ipif = NULL;
		}
		mutex_exit(&ipif->ipif_ill->ill_lock);
	}

	rw_exit(&ipst->ips_ill_g_lock);
	if (usill != NULL)
		ill_refrele(usill);
	if (ipmp_ill != NULL)
		ill_refrele(ipmp_ill);
	if (dst_rhtp != NULL)
		TPC_RELE(dst_rhtp);

#ifdef DEBUG
	if (ipif == NULL) {
		char buf1[INET6_ADDRSTRLEN];

		ip1dbg(("ipif_select_source(%s, %s) -> NULL\n",
		    ill->ill_name,
		    inet_ntop(AF_INET, &dst, buf1, sizeof (buf1))));
	} else {
		char buf1[INET6_ADDRSTRLEN];
		char buf2[INET6_ADDRSTRLEN];

		ip1dbg(("ipif_select_source(%s, %s) -> %s\n",
		    ipif->ipif_ill->ill_name,
		    inet_ntop(AF_INET, &dst, buf1, sizeof (buf1)),
		    inet_ntop(AF_INET, &ipif->ipif_lcl_addr,
		    buf2, sizeof (buf2))));
	}
#endif /* DEBUG */
	return (ipif);
}


/*
 * If old_ipif is not NULL, see if ipif was derived from old
 * ipif and if so, recreate the interface route by re-doing
 * source address selection. This happens when ipif_down ->
 * ipif_update_other_ipifs calls us.
 *
 * If old_ipif is NULL, just redo the source address selection
 * if needed. This happens when ipif_up_done calls us.
 */
static void
ipif_recreate_interface_routes(ipif_t *old_ipif, ipif_t *ipif)
{
	ire_t *ire;
	ire_t *ipif_ire;
	queue_t *stq;
	ipif_t *nipif;
	ill_t *ill;
	boolean_t need_rele = B_FALSE;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(old_ipif == NULL || IAM_WRITER_IPIF(old_ipif));
	ASSERT(IAM_WRITER_IPIF(ipif));

	ill = ipif->ipif_ill;
	if (!(ipif->ipif_flags &
	    (IPIF_NOLOCAL|IPIF_ANYCAST|IPIF_DEPRECATED))) {
		/*
		 * Can't possibly have borrowed the source
		 * from old_ipif.
		 */
		return;
	}

	/*
	 * Is there any work to be done? No work if the address
	 * is INADDR_ANY, loopback or NOLOCAL or ANYCAST (
	 * ipif_select_source() does not borrow addresses from
	 * NOLOCAL and ANYCAST interfaces).
	 */
	if ((old_ipif != NULL) &&
	    ((old_ipif->ipif_lcl_addr == INADDR_ANY) ||
	    (old_ipif->ipif_ill->ill_wq == NULL) ||
	    (old_ipif->ipif_flags &
	    (IPIF_NOLOCAL|IPIF_ANYCAST)))) {
		return;
	}

	/*
	 * Perform the same checks as when creating the
	 * IRE_INTERFACE in ipif_up_done.
	 */
	if (!(ipif->ipif_flags & IPIF_UP))
		return;

	if ((ipif->ipif_flags & IPIF_NOXMIT) ||
	    (ipif->ipif_subnet == INADDR_ANY))
		return;

	ipif_ire = ipif_to_ire(ipif);
	if (ipif_ire == NULL)
		return;

	/*
	 * We know that ipif uses some other source for its
	 * IRE_INTERFACE. Is it using the source of this
	 * old_ipif?
	 */
	if (old_ipif != NULL &&
	    old_ipif->ipif_lcl_addr != ipif_ire->ire_src_addr) {
		ire_refrele(ipif_ire);
		return;
	}
	if (ip_debug > 2) {
		/* ip1dbg */
		pr_addr_dbg("ipif_recreate_interface_routes: deleting IRE for"
		    " src %s\n", AF_INET, &ipif_ire->ire_src_addr);
	}

	stq = ipif_ire->ire_stq;

	/*
	 * Can't use our source address. Select a different
	 * source address for the IRE_INTERFACE.
	 */
	nipif = ipif_select_source(ill, ipif->ipif_subnet, ipif->ipif_zoneid);
	if (nipif == NULL) {
		/* Last resort - all ipif's have IPIF_NOLOCAL */
		nipif = ipif;
	} else {
		need_rele = B_TRUE;
	}

	ire = ire_create(
	    (uchar_t *)&ipif->ipif_subnet,	/* dest pref */
	    (uchar_t *)&ipif->ipif_net_mask,	/* mask */
	    (uchar_t *)&nipif->ipif_src_addr,	/* src addr */
	    NULL,				/* no gateway */
	    &ipif->ipif_mtu,			/* max frag */
	    NULL,				/* no src nce */
	    NULL,				/* no recv from queue */
	    stq,				/* send-to queue */
	    ill->ill_net_type,			/* IF_[NO]RESOLVER */
	    ipif,
	    0,
	    0,
	    0,
	    0,
	    &ire_uinfo_null,
	    NULL,
	    NULL,
	    ipst);

	if (ire != NULL) {
		ire_t *ret_ire;
		int error;

		/*
		 * We don't need ipif_ire anymore. We need to delete
		 * before we add so that ire_add does not detect
		 * duplicates.
		 */
		ire_delete(ipif_ire);
		ret_ire = ire;
		error = ire_add(&ret_ire, NULL, NULL, NULL, B_FALSE);
		ASSERT(error == 0);
		ASSERT(ire == ret_ire);
		/* Held in ire_add */
		ire_refrele(ret_ire);
	}
	/*
	 * Either we are falling through from above or could not
	 * allocate a replacement.
	 */
	ire_refrele(ipif_ire);
	if (need_rele)
		ipif_refrele(nipif);
}

/*
 * This old_ipif is going away.
 *
 * Determine if any other ipif's are using our address as
 * ipif_lcl_addr (due to those being IPIF_NOLOCAL, IPIF_ANYCAST, or
 * IPIF_DEPRECATED).
 * Find the IRE_INTERFACE for such ipifs and recreate them
 * to use an different source address following the rules in
 * ipif_up_done.
 */
static void
ipif_update_other_ipifs(ipif_t *old_ipif)
{
	ipif_t	*ipif;
	ill_t	*ill;
	char	buf[INET6_ADDRSTRLEN];

	ASSERT(IAM_WRITER_IPIF(old_ipif));

	ill = old_ipif->ipif_ill;

	ip1dbg(("ipif_update_other_ipifs(%s, %s)\n", ill->ill_name,
	    inet_ntop(AF_INET, &old_ipif->ipif_lcl_addr, buf, sizeof (buf))));

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (ipif == old_ipif)
			continue;
		ipif_recreate_interface_routes(old_ipif, ipif);
	}
}

/* ARGSUSED */
int
if_unitsel_restart(ipif_t *ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
	ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	/*
	 * ill_phyint_reinit merged the v4 and v6 into a single
	 * ipsq.  We might not have been able to complete the
	 * operation in ipif_set_values, if we could not become
	 * exclusive.  If so restart it here.
	 */
	return (ipif_set_values_tail(ipif->ipif_ill, ipif, mp, q));
}

/*
 * Can operate on either a module or a driver queue.
 * Returns an error if not a module queue.
 */
/* ARGSUSED */
int
if_unitsel(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	queue_t		*q1 = q;
	char 		*cp;
	char		interf_name[LIFNAMSIZ];
	uint_t		ppa = *(uint_t *)mp->b_cont->b_cont->b_rptr;

	if (q->q_next == NULL) {
		ip1dbg((
		    "if_unitsel: IF_UNITSEL: no q_next\n"));
		return (EINVAL);
	}

	if (((ill_t *)(q->q_ptr))->ill_name[0] != '\0')
		return (EALREADY);

	do {
		q1 = q1->q_next;
	} while (q1->q_next);
	cp = q1->q_qinfo->qi_minfo->mi_idname;
	(void) sprintf(interf_name, "%s%d", cp, ppa);

	/*
	 * Here we are not going to delay the ioack until after
	 * ACKs from DL_ATTACH_REQ/DL_BIND_REQ. So no need to save the
	 * original ioctl message before sending the requests.
	 */
	return (ipif_set_values(q, mp, interf_name, &ppa));
}

/* ARGSUSED */
int
ip_sioctl_sifname(ipif_t *dummy_ipif, sin_t *dummy_sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *dummy_ifreq)
{
	return (ENXIO);
}

/*
 * Refresh all IRE_BROADCAST entries associated with `ill' to ensure the
 * minimum (but complete) set exist.  This is necessary when adding or
 * removing an interface to/from an IPMP group, since interfaces in an
 * IPMP group use the IRE_BROADCAST entries for the IPMP group (whenever
 * its test address subnets overlap with IPMP data addresses).	It's also
 * used to refresh the IRE_BROADCAST entries associated with the IPMP
 * interface when the nominated broadcast interface changes.
 */
void
ill_refresh_bcast(ill_t *ill)
{
	ire_t *ire_array[12];	/* max ipif_create_bcast_ires() can create */
	ire_t **irep;
	ipif_t *ipif;

	ASSERT(!ill->ill_isv6);
	ASSERT(IAM_WRITER_ILL(ill));

	/*
	 * Remove any old broadcast IREs.
	 */
	ire_walk_ill_v4(MATCH_IRE_ILL | MATCH_IRE_TYPE, IRE_BROADCAST,
	    ill_broadcast_delete, ill, ill);

	/*
	 * Create new ones for any ipifs that are up and broadcast-capable.
	 */
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if ((ipif->ipif_flags & (IPIF_UP|IPIF_BROADCAST)) !=
		    (IPIF_UP|IPIF_BROADCAST))
			continue;

		irep = ipif_create_bcast_ires(ipif, ire_array);
		while (irep-- > ire_array) {
			(void) ire_add(irep, NULL, NULL, NULL, B_FALSE);
			if (*irep != NULL)
				ire_refrele(*irep);
		}
	}
}

/*
 * Create any IRE_BROADCAST entries for `ipif', and store those entries in
 * `irep'.  Returns a pointer to the next free `irep' entry (just like
 * ire_check_and_create_bcast()).
 */
static ire_t **
ipif_create_bcast_ires(ipif_t *ipif, ire_t **irep)
{
	ipaddr_t addr;
	ipaddr_t netmask = ip_net_mask(ipif->ipif_lcl_addr);
	ipaddr_t subnetmask = ipif->ipif_net_mask;
	int flags = MATCH_IRE_TYPE | MATCH_IRE_ILL;

	ip1dbg(("ipif_create_bcast_ires: creating broadcast IREs\n"));

	ASSERT(ipif->ipif_flags & IPIF_BROADCAST);

	if (ipif->ipif_lcl_addr == INADDR_ANY ||
	    (ipif->ipif_flags & IPIF_NOLOCAL))
		netmask = htonl(IN_CLASSA_NET);		/* fallback */

	irep = ire_check_and_create_bcast(ipif, 0, irep, flags);
	irep = ire_check_and_create_bcast(ipif, INADDR_BROADCAST, irep, flags);

	/*
	 * For backward compatibility, we create net broadcast IREs based on
	 * the old "IP address class system", since some old machines only
	 * respond to these class derived net broadcast.  However, we must not
	 * create these net broadcast IREs if the subnetmask is shorter than
	 * the IP address class based derived netmask.  Otherwise, we may
	 * create a net broadcast address which is the same as an IP address
	 * on the subnet -- and then TCP will refuse to talk to that address.
	 */
	if (netmask < subnetmask) {
		addr = netmask & ipif->ipif_subnet;
		irep = ire_check_and_create_bcast(ipif, addr, irep, flags);
		irep = ire_check_and_create_bcast(ipif, ~netmask | addr, irep,
		    flags);
	}

	/*
	 * Don't create IRE_BROADCAST IREs for the interface if the subnetmask
	 * is 0xFFFFFFFF, as an IRE_LOCAL for that interface is already
	 * created.  Creating these broadcast IREs will only create confusion
	 * as `addr' will be the same as the IP address.
	 */
	if (subnetmask != 0xFFFFFFFF) {
		addr = ipif->ipif_subnet;
		irep = ire_check_and_create_bcast(ipif, addr, irep, flags);
		irep = ire_check_and_create_bcast(ipif, ~subnetmask | addr,
		    irep, flags);
	}

	return (irep);
}

/*
 * Broadcast IRE info structure used in the functions below.  Since we
 * allocate BCAST_COUNT of them on the stack, keep the bit layout compact.
 */
typedef struct bcast_ireinfo {
	uchar_t		bi_type;	/* BCAST_* value from below */
	uchar_t		bi_willdie:1, 	/* will this IRE be going away? */
			bi_needrep:1,	/* do we need to replace it? */
			bi_haverep:1,	/* have we replaced it? */
			bi_pad:5;
	ipaddr_t	bi_addr;	/* IRE address */
	ipif_t		*bi_backup;	/* last-ditch ipif to replace it on */
} bcast_ireinfo_t;

enum { BCAST_ALLONES, BCAST_ALLZEROES, BCAST_NET, BCAST_SUBNET, BCAST_COUNT };

/*
 * Check if `ipif' needs the dying broadcast IRE described by `bireinfop', and
 * return B_TRUE if it should immediately be used to recreate the IRE.
 */
static boolean_t
ipif_consider_bcast(ipif_t *ipif, bcast_ireinfo_t *bireinfop)
{
	ipaddr_t addr;

	ASSERT(!bireinfop->bi_haverep && bireinfop->bi_willdie);

	switch (bireinfop->bi_type) {
	case BCAST_NET:
		addr = ipif->ipif_subnet & ip_net_mask(ipif->ipif_subnet);
		if (addr != bireinfop->bi_addr)
			return (B_FALSE);
		break;
	case BCAST_SUBNET:
		if (ipif->ipif_subnet != bireinfop->bi_addr)
			return (B_FALSE);
		break;
	}

	bireinfop->bi_needrep = 1;
	if (ipif->ipif_flags & (IPIF_DEPRECATED|IPIF_NOLOCAL|IPIF_ANYCAST)) {
		if (bireinfop->bi_backup == NULL)
			bireinfop->bi_backup = ipif;
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Create the broadcast IREs described by `bireinfop' on `ipif', and return
 * them ala ire_check_and_create_bcast().
 */
static ire_t **
ipif_create_bcast(ipif_t *ipif, bcast_ireinfo_t *bireinfop, ire_t **irep)
{
	ipaddr_t mask, addr;

	ASSERT(!bireinfop->bi_haverep && bireinfop->bi_needrep);

	addr = bireinfop->bi_addr;
	irep = ire_create_bcast(ipif, addr, irep);

	switch (bireinfop->bi_type) {
	case BCAST_NET:
		mask = ip_net_mask(ipif->ipif_subnet);
		irep = ire_create_bcast(ipif, addr | ~mask, irep);
		break;
	case BCAST_SUBNET:
		mask = ipif->ipif_net_mask;
		irep = ire_create_bcast(ipif, addr | ~mask, irep);
		break;
	}

	bireinfop->bi_haverep = 1;
	return (irep);
}

/*
 * Walk through all of the ipifs on `ill' that will be affected by `test_ipif'
 * going away, and determine if any of the broadcast IREs (named by `bireinfop')
 * that are going away are still needed.  If so, have ipif_create_bcast()
 * recreate them (except for the deprecated case, as explained below).
 */
static ire_t **
ill_create_bcast(ill_t *ill, ipif_t *test_ipif, bcast_ireinfo_t *bireinfo,
    ire_t **irep)
{
	int i;
	ipif_t *ipif;

	ASSERT(!ill->ill_isv6);
	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		/*
		 * Skip this ipif if it's (a) the one being taken down, (b)
		 * not in the same zone, or (c) has no valid local address.
		 */
		if (ipif == test_ipif ||
		    ipif->ipif_zoneid != test_ipif->ipif_zoneid ||
		    ipif->ipif_subnet == 0 ||
		    (ipif->ipif_flags & (IPIF_UP|IPIF_BROADCAST|IPIF_NOXMIT)) !=
		    (IPIF_UP|IPIF_BROADCAST))
			continue;

		/*
		 * For each dying IRE that hasn't yet been replaced, see if
		 * `ipif' needs it and whether the IRE should be recreated on
		 * `ipif'.  If `ipif' is deprecated, ipif_consider_bcast()
		 * will return B_FALSE even if `ipif' needs the IRE on the
		 * hopes that we'll later find a needy non-deprecated ipif.
		 * However, the ipif is recorded in bi_backup for possible
		 * subsequent use by ipif_check_bcast_ires().
		 */
		for (i = 0; i < BCAST_COUNT; i++) {
			if (!bireinfo[i].bi_willdie || bireinfo[i].bi_haverep)
				continue;
			if (!ipif_consider_bcast(ipif, &bireinfo[i]))
				continue;
			irep = ipif_create_bcast(ipif, &bireinfo[i], irep);
		}

		/*
		 * If we've replaced all of the broadcast IREs that are going
		 * to be taken down, we know we're done.
		 */
		for (i = 0; i < BCAST_COUNT; i++) {
			if (bireinfo[i].bi_willdie && !bireinfo[i].bi_haverep)
				break;
		}
		if (i == BCAST_COUNT)
			break;
	}
	return (irep);
}

/*
 * Check if `test_ipif' (which is going away) is associated with any existing
 * broadcast IREs, and whether any other ipifs (e.g., on the same ill) were
 * using those broadcast IREs.  If so, recreate the broadcast IREs on one or
 * more of those other ipifs.  (The old IREs will be deleted in ipif_down().)
 *
 * This is necessary because broadcast IREs are shared.  In particular, a
 * given ill has one set of all-zeroes and all-ones broadcast IREs (for every
 * zone), plus one set of all-subnet-ones, all-subnet-zeroes, all-net-ones,
 * and all-net-zeroes for every net/subnet (and every zone) it has IPIF_UP
 * ipifs on.  Thus, if there are two IPIF_UP ipifs on the same subnet with the
 * same zone, they will share the same set of broadcast IREs.
 *
 * Note: the upper bound of 12 IREs comes from the worst case of replacing all
 * six pairs (loopback and non-loopback) of broadcast IREs (all-zeroes,
 * all-ones, subnet-zeroes, subnet-ones, net-zeroes, and net-ones).
 */
static void
ipif_check_bcast_ires(ipif_t *test_ipif)
{
	ill_t		*ill = test_ipif->ipif_ill;
	ire_t		*ire, *ire_array[12]; 		/* see note above */
	ire_t		**irep1, **irep = &ire_array[0];
	uint_t 		i, willdie;
	ipaddr_t	mask = ip_net_mask(test_ipif->ipif_subnet);
	bcast_ireinfo_t	bireinfo[BCAST_COUNT];

	ASSERT(!test_ipif->ipif_isv6);
	ASSERT(IAM_WRITER_IPIF(test_ipif));

	/*
	 * No broadcast IREs for the LOOPBACK interface
	 * or others such as point to point and IPIF_NOXMIT.
	 */
	if (!(test_ipif->ipif_flags & IPIF_BROADCAST) ||
	    (test_ipif->ipif_flags & IPIF_NOXMIT))
		return;

	bzero(bireinfo, sizeof (bireinfo));
	bireinfo[0].bi_type = BCAST_ALLZEROES;
	bireinfo[0].bi_addr = 0;

	bireinfo[1].bi_type = BCAST_ALLONES;
	bireinfo[1].bi_addr = INADDR_BROADCAST;

	bireinfo[2].bi_type = BCAST_NET;
	bireinfo[2].bi_addr = test_ipif->ipif_subnet & mask;

	if (test_ipif->ipif_net_mask != 0)
		mask = test_ipif->ipif_net_mask;
	bireinfo[3].bi_type = BCAST_SUBNET;
	bireinfo[3].bi_addr = test_ipif->ipif_subnet & mask;

	/*
	 * Figure out what (if any) broadcast IREs will die as a result of
	 * `test_ipif' going away.  If none will die, we're done.
	 */
	for (i = 0, willdie = 0; i < BCAST_COUNT; i++) {
		ire = ire_ctable_lookup(bireinfo[i].bi_addr, 0, IRE_BROADCAST,
		    test_ipif, ALL_ZONES, NULL,
		    (MATCH_IRE_TYPE | MATCH_IRE_IPIF), ill->ill_ipst);
		if (ire != NULL) {
			willdie++;
			bireinfo[i].bi_willdie = 1;
			ire_refrele(ire);
		}
	}

	if (willdie == 0)
		return;

	/*
	 * Walk through all the ipifs that will be affected by the dying IREs,
	 * and recreate the IREs as necessary. Note that all interfaces in an
	 * IPMP illgrp share the same broadcast IREs, and thus the entire
	 * illgrp must be walked, starting with the IPMP meta-interface (so
	 * that broadcast IREs end up on it whenever possible).
	 */
	if (IS_UNDER_IPMP(ill))
		ill = ipmp_illgrp_ipmp_ill(ill->ill_grp);

	irep = ill_create_bcast(ill, test_ipif, bireinfo, irep);

	if (IS_IPMP(ill) || IS_UNDER_IPMP(ill)) {
		ipmp_illgrp_t *illg = ill->ill_grp;

		ill = list_head(&illg->ig_if);
		for (; ill != NULL; ill = list_next(&illg->ig_if, ill)) {
			for (i = 0; i < BCAST_COUNT; i++) {
				if (bireinfo[i].bi_willdie &&
				    !bireinfo[i].bi_haverep)
					break;
			}
			if (i == BCAST_COUNT)
				break;

			irep = ill_create_bcast(ill, test_ipif, bireinfo, irep);
		}
	}

	/*
	 * Scan through the set of broadcast IREs and see if there are any
	 * that we need to replace that have not yet been replaced.  If so,
	 * replace them using the appropriate backup ipif.
	 */
	for (i = 0; i < BCAST_COUNT; i++) {
		if (bireinfo[i].bi_needrep && !bireinfo[i].bi_haverep)
			irep = ipif_create_bcast(bireinfo[i].bi_backup,
			    &bireinfo[i], irep);
	}

	/*
	 * If we can't create all of them, don't add any of them.  (Code in
	 * ip_wput_ire() and ire_to_ill() assumes that we always have a
	 * non-loopback copy and loopback copy for a given address.)
	 */
	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		if (*irep1 == NULL) {
			ip0dbg(("ipif_check_bcast_ires: can't create "
			    "IRE_BROADCAST, memory allocation failure\n"));
			while (irep > ire_array) {
				irep--;
				if (*irep != NULL)
					ire_delete(*irep);
			}
			return;
		}
	}

	for (irep1 = irep; irep1 > ire_array; ) {
		irep1--;
		if (ire_add(irep1, NULL, NULL, NULL, B_FALSE) == 0)
			ire_refrele(*irep1);		/* Held in ire_add */
	}
}

/*
 * Extract both the flags (including IFF_CANTCHANGE) such as IFF_IPV*
 * from lifr_flags and the name from lifr_name.
 * Set IFF_IPV* and ill_isv6 prior to doing the lookup
 * since ipif_lookup_on_name uses the _isv6 flags when matching.
 * Returns EINPROGRESS when mp has been consumed by queueing it on
 * ill_pending_mp and the ioctl will complete in ip_rput.
 *
 * Can operate on either a module or a driver queue.
 * Returns an error if not a module queue.
 */
/* ARGSUSED */
int
ip_sioctl_slifname(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	ill_t	*ill = q->q_ptr;
	phyint_t *phyi;
	ip_stack_t *ipst;
	struct lifreq *lifr = if_req;

	ASSERT(ipif != NULL);
	ip1dbg(("ip_sioctl_slifname %s\n", lifr->lifr_name));

	if (q->q_next == NULL) {
		ip1dbg(("if_sioctl_slifname: SIOCSLIFNAME: no q_next\n"));
		return (EINVAL);
	}

	/*
	 * If we are not writer on 'q' then this interface exists already
	 * and previous lookups (ip_extract_lifreq()) found this ipif --
	 * so return EALREADY.
	 */
	if (ill != ipif->ipif_ill)
		return (EALREADY);

	if (ill->ill_name[0] != '\0')
		return (EALREADY);

	/*
	 * Set all the flags. Allows all kinds of override. Provide some
	 * sanity checking by not allowing IFF_BROADCAST and IFF_MULTICAST
	 * unless there is either multicast/broadcast support in the driver
	 * or it is a pt-pt link.
	 */
	if (lifr->lifr_flags & (IFF_PROMISC|IFF_ALLMULTI)) {
		/* Meaningless to IP thus don't allow them to be set. */
		ip1dbg(("ip_setname: EINVAL 1\n"));
		return (EINVAL);
	}

	/*
	 * If there's another ill already with the requested name, ensure
	 * that it's of the same type.  Otherwise, ill_phyint_reinit() will
	 * fuse together two unrelated ills, which will cause chaos.
	 */
	ipst = ill->ill_ipst;
	phyi = avl_find(&ipst->ips_phyint_g_list->phyint_list_avl_by_name,
	    lifr->lifr_name, NULL);
	if (phyi != NULL) {
		ill_t *ill_mate = phyi->phyint_illv4;

		if (ill_mate == NULL)
			ill_mate = phyi->phyint_illv6;
		ASSERT(ill_mate != NULL);

		if (ill_mate->ill_media->ip_m_mac_type !=
		    ill->ill_media->ip_m_mac_type) {
			ip1dbg(("if_sioctl_slifname: SIOCSLIFNAME: attempt to "
			    "use the same ill name on differing media\n"));
			return (EINVAL);
		}
	}

	/*
	 * For a DL_STYLE2 driver (ill_needs_attach), we would not have the
	 * ill_bcast_addr_length info.
	 */
	if (!ill->ill_needs_attach &&
	    ((lifr->lifr_flags & IFF_MULTICAST) &&
	    !(lifr->lifr_flags & IFF_POINTOPOINT) &&
	    ill->ill_bcast_addr_length == 0)) {
		/* Link not broadcast/pt-pt capable i.e. no multicast */
		ip1dbg(("ip_setname: EINVAL 2\n"));
		return (EINVAL);
	}
	if ((lifr->lifr_flags & IFF_BROADCAST) &&
	    ((lifr->lifr_flags & IFF_IPV6) ||
	    (!ill->ill_needs_attach && ill->ill_bcast_addr_length == 0))) {
		/* Link not broadcast capable or IPv6 i.e. no broadcast */
		ip1dbg(("ip_setname: EINVAL 3\n"));
		return (EINVAL);
	}
	if (lifr->lifr_flags & IFF_UP) {
		/* Can only be set with SIOCSLIFFLAGS */
		ip1dbg(("ip_setname: EINVAL 4\n"));
		return (EINVAL);
	}
	if ((lifr->lifr_flags & (IFF_IPV6|IFF_IPV4)) != IFF_IPV6 &&
	    (lifr->lifr_flags & (IFF_IPV6|IFF_IPV4)) != IFF_IPV4) {
		ip1dbg(("ip_setname: EINVAL 5\n"));
		return (EINVAL);
	}
	/*
	 * Only allow the IFF_XRESOLV flag to be set on IPv6 interfaces.
	 */
	if ((lifr->lifr_flags & IFF_XRESOLV) &&
	    !(lifr->lifr_flags & IFF_IPV6) &&
	    !(ipif->ipif_isv6)) {
		ip1dbg(("ip_setname: EINVAL 6\n"));
		return (EINVAL);
	}

	/*
	 * The user has done SIOCGLIFFLAGS prior to this ioctl and hence
	 * we have all the flags here. So, we assign rather than we OR.
	 * We can't OR the flags here because we don't want to set
	 * both IFF_IPV4 and IFF_IPV6. We start off as IFF_IPV4 in
	 * ipif_allocate and become IFF_IPV4 or IFF_IPV6 here depending
	 * on lifr_flags value here.
	 */
	/*
	 * This ill has not been inserted into the global list.
	 * So we are still single threaded and don't need any lock
	 */
	ipif->ipif_flags = lifr->lifr_flags & IFF_LOGINT_FLAGS & ~IFF_DUPLICATE;
	ill->ill_flags = lifr->lifr_flags & IFF_PHYINTINST_FLAGS;
	ill->ill_phyint->phyint_flags = lifr->lifr_flags & IFF_PHYINT_FLAGS;

	/* We started off as V4. */
	if (ill->ill_flags & ILLF_IPV6) {
		ill->ill_phyint->phyint_illv6 = ill;
		ill->ill_phyint->phyint_illv4 = NULL;
	}

	return (ipif_set_values(q, mp, lifr->lifr_name, &lifr->lifr_ppa));
}

/* ARGSUSED */
int
ip_sioctl_slifname_restart(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	/*
	 * ill_phyint_reinit merged the v4 and v6 into a single
	 * ipsq.  We might not have been able to complete the
	 * slifname in ipif_set_values, if we could not become
	 * exclusive.  If so restart it here
	 */
	return (ipif_set_values_tail(ipif->ipif_ill, ipif, mp, q));
}

/*
 * Return a pointer to the ipif which matches the index, IP version type and
 * zoneid.
 */
ipif_t *
ipif_lookup_on_ifindex(uint_t index, boolean_t isv6, zoneid_t zoneid,
    queue_t *q, mblk_t *mp, ipsq_func_t func, int *err, ip_stack_t *ipst)
{
	ill_t	*ill;
	ipif_t	*ipif = NULL;

	ASSERT((q == NULL && mp == NULL && func == NULL && err == NULL) ||
	    (q != NULL && mp != NULL && func != NULL && err != NULL));

	if (err != NULL)
		*err = 0;

	ill = ill_lookup_on_ifindex(index, isv6, q, mp, func, err, ipst);
	if (ill != NULL) {
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (IPIF_CAN_LOOKUP(ipif) && (zoneid == ALL_ZONES ||
			    zoneid == ipif->ipif_zoneid ||
			    ipif->ipif_zoneid == ALL_ZONES)) {
				ipif_refhold_locked(ipif);
				break;
			}
		}
		mutex_exit(&ill->ill_lock);
		ill_refrele(ill);
		if (ipif == NULL && err != NULL)
			*err = ENXIO;
	}
	return (ipif);
}

/*
 * We first need to ensure that the new index is unique, and
 * then carry the change across both v4 and v6 ill representation
 * of the physical interface.
 */
/* ARGSUSED */
int
ip_sioctl_slifindex(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	ill_t		*ill;
	phyint_t	*phyi;
	struct ifreq	*ifr = (struct ifreq *)ifreq;
	struct lifreq	*lifr = (struct lifreq *)ifreq;
	uint_t	old_index, index;
	ill_t	*ill_v4;
	ill_t	*ill_v6;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	if (ipip->ipi_cmd_type == IF_CMD)
		index = ifr->ifr_index;
	else
		index = lifr->lifr_index;

	/*
	 * Only allow on physical interface. Also, index zero is illegal.
	 */
	ill = ipif->ipif_ill;
	phyi = ill->ill_phyint;
	if (ipif->ipif_id != 0 || index == 0) {
		return (EINVAL);
	}

	/* If the index is not changing, no work to do */
	if (phyi->phyint_ifindex == index)
		return (0);

	/*
	 * Use ill_lookup_on_ifindex to determine if the
	 * new index is unused and if so allow the change.
	 */
	ill_v6 = ill_lookup_on_ifindex(index, B_TRUE, NULL, NULL, NULL, NULL,
	    ipst);
	ill_v4 = ill_lookup_on_ifindex(index, B_FALSE, NULL, NULL, NULL, NULL,
	    ipst);
	if (ill_v6 != NULL || ill_v4 != NULL) {
		if (ill_v4 != NULL)
			ill_refrele(ill_v4);
		if (ill_v6 != NULL)
			ill_refrele(ill_v6);
		return (EBUSY);
	}

	/* The new index is unused. Set it in the phyint. */
	old_index = phyi->phyint_ifindex;
	phyi->phyint_ifindex = index;

	/* Update SCTP's ILL list */
	sctp_ill_reindex(ill, old_index);

	/* Send the routing sockets message */
	ip_rts_ifmsg(ipif, RTSQ_DEFAULT);
	if (ILL_OTHER(ill))
		ip_rts_ifmsg(ILL_OTHER(ill)->ill_ipif, RTSQ_DEFAULT);

	return (0);
}

/* ARGSUSED */
int
ip_sioctl_get_lifindex(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct ifreq	*ifr = (struct ifreq *)ifreq;
	struct lifreq	*lifr = (struct lifreq *)ifreq;

	ip1dbg(("ip_sioctl_get_lifindex(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	/* Get the interface index */
	if (ipip->ipi_cmd_type == IF_CMD) {
		ifr->ifr_index = ipif->ipif_ill->ill_phyint->phyint_ifindex;
	} else {
		lifr->lifr_index = ipif->ipif_ill->ill_phyint->phyint_ifindex;
	}
	return (0);
}

/* ARGSUSED */
int
ip_sioctl_get_lifzone(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct lifreq	*lifr = (struct lifreq *)ifreq;

	ip1dbg(("ip_sioctl_get_lifzone(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	/* Get the interface zone */
	ASSERT(ipip->ipi_cmd_type == LIF_CMD);
	lifr->lifr_zoneid = ipif->ipif_zoneid;
	return (0);
}

/*
 * Set the zoneid of an interface.
 */
/* ARGSUSED */
int
ip_sioctl_slifzone(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct lifreq	*lifr = (struct lifreq *)ifreq;
	int err = 0;
	boolean_t need_up = B_FALSE;
	zone_t *zptr;
	zone_status_t status;
	zoneid_t zoneid;

	ASSERT(ipip->ipi_cmd_type == LIF_CMD);
	if ((zoneid = lifr->lifr_zoneid) == ALL_ZONES) {
		if (!is_system_labeled())
			return (ENOTSUP);
		zoneid = GLOBAL_ZONEID;
	}

	/* cannot assign instance zero to a non-global zone */
	if (ipif->ipif_id == 0 && zoneid != GLOBAL_ZONEID)
		return (ENOTSUP);

	/*
	 * Cannot assign to a zone that doesn't exist or is shutting down.  In
	 * the event of a race with the zone shutdown processing, since IP
	 * serializes this ioctl and SIOCGLIFCONF/SIOCLIFREMOVEIF, we know the
	 * interface will be cleaned up even if the zone is shut down
	 * immediately after the status check. If the interface can't be brought
	 * down right away, and the zone is shut down before the restart
	 * function is called, we resolve the possible races by rechecking the
	 * zone status in the restart function.
	 */
	if ((zptr = zone_find_by_id(zoneid)) == NULL)
		return (EINVAL);
	status = zone_status_get(zptr);
	zone_rele(zptr);

	if (status != ZONE_IS_READY && status != ZONE_IS_RUNNING)
		return (EINVAL);

	if (ipif->ipif_flags & IPIF_UP) {
		/*
		 * If the interface is already marked up,
		 * we call ipif_down which will take care
		 * of ditching any IREs that have been set
		 * up based on the old interface address.
		 */
		err = ipif_logical_down(ipif, q, mp);
		if (err == EINPROGRESS)
			return (err);
		ipif_down_tail(ipif);
		need_up = B_TRUE;
	}

	err = ip_sioctl_slifzone_tail(ipif, lifr->lifr_zoneid, q, mp, need_up);
	return (err);
}

static int
ip_sioctl_slifzone_tail(ipif_t *ipif, zoneid_t zoneid,
    queue_t *q, mblk_t *mp, boolean_t need_up)
{
	int	err = 0;
	ip_stack_t	*ipst;

	ip1dbg(("ip_sioctl_zoneid_tail(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	if (CONN_Q(q))
		ipst = CONNQ_TO_IPST(q);
	else
		ipst = ILLQ_TO_IPST(q);

	/*
	 * For exclusive stacks we don't allow a different zoneid than
	 * global.
	 */
	if (ipst->ips_netstack->netstack_stackid != GLOBAL_NETSTACKID &&
	    zoneid != GLOBAL_ZONEID)
		return (EINVAL);

	/* Set the new zone id. */
	ipif->ipif_zoneid = zoneid;

	/* Update sctp list */
	sctp_update_ipif(ipif, SCTP_IPIF_UPDATE);

	if (need_up) {
		/*
		 * Now bring the interface back up.  If this
		 * is the only IPIF for the ILL, ipif_up
		 * will have to re-bind to the device, so
		 * we may get back EINPROGRESS, in which
		 * case, this IOCTL will get completed in
		 * ip_rput_dlpi when we see the DL_BIND_ACK.
		 */
		err = ipif_up(ipif, q, mp);
	}
	return (err);
}

/* ARGSUSED */
int
ip_sioctl_slifzone_restart(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *if_req)
{
	struct lifreq *lifr = (struct lifreq *)if_req;
	zoneid_t zoneid;
	zone_t *zptr;
	zone_status_t status;

	ASSERT(ipif->ipif_id != 0);
	ASSERT(ipip->ipi_cmd_type == LIF_CMD);
	if ((zoneid = lifr->lifr_zoneid) == ALL_ZONES)
		zoneid = GLOBAL_ZONEID;

	ip1dbg(("ip_sioctl_slifzone_restart(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));

	/*
	 * We recheck the zone status to resolve the following race condition:
	 * 1) process sends SIOCSLIFZONE to put hme0:1 in zone "myzone";
	 * 2) hme0:1 is up and can't be brought down right away;
	 * ip_sioctl_slifzone() returns EINPROGRESS and the request is queued;
	 * 3) zone "myzone" is halted; the zone status switches to
	 * 'shutting_down' and the zones framework sends SIOCGLIFCONF to list
	 * the interfaces to remove - hme0:1 is not returned because it's not
	 * yet in "myzone", so it won't be removed;
	 * 4) the restart function for SIOCSLIFZONE is called; without the
	 * status check here, we would have hme0:1 in "myzone" after it's been
	 * destroyed.
	 * Note that if the status check fails, we need to bring the interface
	 * back to its state prior to ip_sioctl_slifzone(), hence the call to
	 * ipif_up_done[_v6]().
	 */
	status = ZONE_IS_UNINITIALIZED;
	if ((zptr = zone_find_by_id(zoneid)) != NULL) {
		status = zone_status_get(zptr);
		zone_rele(zptr);
	}
	if (status != ZONE_IS_READY && status != ZONE_IS_RUNNING) {
		if (ipif->ipif_isv6) {
			(void) ipif_up_done_v6(ipif);
		} else {
			(void) ipif_up_done(ipif);
		}
		return (EINVAL);
	}

	ipif_down_tail(ipif);

	return (ip_sioctl_slifzone_tail(ipif, lifr->lifr_zoneid, q, mp,
	    B_TRUE));
}

/*
 * Return the number of addresses on `ill' with one or more of the values
 * in `set' set and all of the values in `clear' clear.
 */
static uint_t
ill_flagaddr_cnt(const ill_t *ill, uint64_t set, uint64_t clear)
{
	ipif_t	*ipif;
	uint_t	cnt = 0;

	ASSERT(IAM_WRITER_ILL(ill));

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next)
		if ((ipif->ipif_flags & set) && !(ipif->ipif_flags & clear))
			cnt++;

	return (cnt);
}

/*
 * Return the number of migratable addresses on `ill' that are under
 * application control.
 */
uint_t
ill_appaddr_cnt(const ill_t *ill)
{
	return (ill_flagaddr_cnt(ill, IPIF_DHCPRUNNING | IPIF_ADDRCONF,
	    IPIF_NOFAILOVER));
}

/*
 * Return the number of point-to-point addresses on `ill'.
 */
uint_t
ill_ptpaddr_cnt(const ill_t *ill)
{
	return (ill_flagaddr_cnt(ill, IPIF_POINTOPOINT, 0));
}

/* ARGSUSED */
int
ip_sioctl_get_lifusesrc(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
	ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct lifreq	*lifr = ifreq;

	ASSERT(q->q_next == NULL);
	ASSERT(CONN_Q(q));

	ip1dbg(("ip_sioctl_get_lifusesrc(%s:%u %p)\n",
	    ipif->ipif_ill->ill_name, ipif->ipif_id, (void *)ipif));
	lifr->lifr_index = ipif->ipif_ill->ill_usesrc_ifindex;
	ip1dbg(("ip_sioctl_get_lifusesrc:lifr_index = %d\n", lifr->lifr_index));

	return (0);
}

/* Find the previous ILL in this usesrc group */
static ill_t *
ill_prev_usesrc(ill_t *uill)
{
	ill_t *ill;

	for (ill = uill->ill_usesrc_grp_next;
	    ASSERT(ill), ill->ill_usesrc_grp_next != uill;
	    ill = ill->ill_usesrc_grp_next)
		/* do nothing */;
	return (ill);
}

/*
 * Release all members of the usesrc group. This routine is called
 * from ill_delete when the interface being unplumbed is the
 * group head.
 */
static void
ill_disband_usesrc_group(ill_t *uill)
{
	ill_t *next_ill, *tmp_ill;
	ip_stack_t	*ipst = uill->ill_ipst;

	ASSERT(RW_WRITE_HELD(&ipst->ips_ill_g_usesrc_lock));
	next_ill = uill->ill_usesrc_grp_next;

	do {
		ASSERT(next_ill != NULL);
		tmp_ill = next_ill->ill_usesrc_grp_next;
		ASSERT(tmp_ill != NULL);
		next_ill->ill_usesrc_grp_next = NULL;
		next_ill->ill_usesrc_ifindex = 0;
		next_ill = tmp_ill;
	} while (next_ill->ill_usesrc_ifindex != 0);
	uill->ill_usesrc_grp_next = NULL;
}

/*
 * Remove the client usesrc ILL from the list and relink to a new list
 */
int
ill_relink_usesrc_ills(ill_t *ucill, ill_t *uill, uint_t ifindex)
{
	ill_t *ill, *tmp_ill;
	ip_stack_t	*ipst = ucill->ill_ipst;

	ASSERT((ucill != NULL) && (ucill->ill_usesrc_grp_next != NULL) &&
	    (uill != NULL) && RW_WRITE_HELD(&ipst->ips_ill_g_usesrc_lock));

	/*
	 * Check if the usesrc client ILL passed in is not already
	 * in use as a usesrc ILL i.e one whose source address is
	 * in use OR a usesrc ILL is not already in use as a usesrc
	 * client ILL
	 */
	if ((ucill->ill_usesrc_ifindex == 0) ||
	    (uill->ill_usesrc_ifindex != 0)) {
		return (-1);
	}

	ill = ill_prev_usesrc(ucill);
	ASSERT(ill->ill_usesrc_grp_next != NULL);

	/* Remove from the current list */
	if (ill->ill_usesrc_grp_next->ill_usesrc_grp_next == ill) {
		/* Only two elements in the list */
		ASSERT(ill->ill_usesrc_ifindex == 0);
		ill->ill_usesrc_grp_next = NULL;
	} else {
		ill->ill_usesrc_grp_next = ucill->ill_usesrc_grp_next;
	}

	if (ifindex == 0) {
		ucill->ill_usesrc_ifindex = 0;
		ucill->ill_usesrc_grp_next = NULL;
		return (0);
	}

	ucill->ill_usesrc_ifindex = ifindex;
	tmp_ill = uill->ill_usesrc_grp_next;
	uill->ill_usesrc_grp_next = ucill;
	ucill->ill_usesrc_grp_next =
	    (tmp_ill != NULL) ? tmp_ill : uill;
	return (0);
}

/*
 * Set the ill_usesrc and ill_usesrc_head fields. See synchronization notes in
 * ip.c for locking details.
 */
/* ARGSUSED */
int
ip_sioctl_slifusesrc(ipif_t *ipif, sin_t *sin, queue_t *q, mblk_t *mp,
    ip_ioctl_cmd_t *ipip, void *ifreq)
{
	struct lifreq *lifr = (struct lifreq *)ifreq;
	boolean_t isv6 = B_FALSE, reset_flg = B_FALSE,
	    ill_flag_changed = B_FALSE;
	ill_t *usesrc_ill, *usesrc_cli_ill = ipif->ipif_ill;
	int err = 0, ret;
	uint_t ifindex;
	ipsq_t *ipsq = NULL;
	ip_stack_t	*ipst = ipif->ipif_ill->ill_ipst;

	ASSERT(IAM_WRITER_IPIF(ipif));
	ASSERT(q->q_next == NULL);
	ASSERT(CONN_Q(q));

	isv6 = (Q_TO_CONN(q))->conn_af_isv6;

	ifindex = lifr->lifr_index;
	if (ifindex == 0) {
		if (usesrc_cli_ill->ill_usesrc_grp_next == NULL) {
			/* non usesrc group interface, nothing to reset */
			return (0);
		}
		ifindex = usesrc_cli_ill->ill_usesrc_ifindex;
		/* valid reset request */
		reset_flg = B_TRUE;
	}

	usesrc_ill = ill_lookup_on_ifindex(ifindex, isv6, q, mp,
	    ip_process_ioctl, &err, ipst);
	if (usesrc_ill == NULL) {
		return (err);
	}

	ipsq = ipsq_try_enter(NULL, usesrc_ill, q, mp, ip_process_ioctl,
	    NEW_OP, B_TRUE);
	if (ipsq == NULL) {
		err = EINPROGRESS;
		/* Operation enqueued on the ipsq of the usesrc ILL */
		goto done;
	}

	/* USESRC isn't currently supported with IPMP */
	if (IS_IPMP(usesrc_ill) || IS_UNDER_IPMP(usesrc_ill)) {
		err = ENOTSUP;
		goto done;
	}

	/*
	 * USESRC isn't compatible with the STANDBY flag.  (STANDBY is only
	 * used by IPMP underlying interfaces, but someone might think it's
	 * more general and try to use it independently with VNI.)
	 */
	if (usesrc_ill->ill_phyint->phyint_flags & PHYI_STANDBY) {
		err = ENOTSUP;
		goto done;
	}

	/*
	 * If the client is already in use as a usesrc_ill or a usesrc_ill is
	 * already a client then return EINVAL
	 */
	if (IS_USESRC_ILL(usesrc_cli_ill) || IS_USESRC_CLI_ILL(usesrc_ill)) {
		err = EINVAL;
		goto done;
	}

	/*
	 * If the ill_usesrc_ifindex field is already set to what it needs to
	 * be then this is a duplicate operation.
	 */
	if (!reset_flg && usesrc_cli_ill->ill_usesrc_ifindex == ifindex) {
		err = 0;
		goto done;
	}

	ip1dbg(("ip_sioctl_slifusesrc: usesrc_cli_ill %s, usesrc_ill %s,"
	    " v6 = %d", usesrc_cli_ill->ill_name, usesrc_ill->ill_name,
	    usesrc_ill->ill_isv6));

	/*
	 * The next step ensures that no new ires will be created referencing
	 * the client ill, until the ILL_CHANGING flag is cleared. Then
	 * we go through an ire walk deleting all ire caches that reference
	 * the client ill. New ires referencing the client ill that are added
	 * to the ire table before the ILL_CHANGING flag is set, will be
	 * cleaned up by the ire walk below. Attempt to add new ires referencing
	 * the client ill while the ILL_CHANGING flag is set will be failed
	 * during the ire_add in ire_atomic_start. ire_atomic_start atomically
	 * checks (under the ill_g_usesrc_lock) that the ire being added
	 * is not stale, i.e the ire_stq and ire_ipif are consistent and
	 * belong to the same usesrc group.
	 */
	mutex_enter(&usesrc_cli_ill->ill_lock);
	usesrc_cli_ill->ill_state_flags |= ILL_CHANGING;
	mutex_exit(&usesrc_cli_ill->ill_lock);
	ill_flag_changed = B_TRUE;

	if (ipif->ipif_isv6)
		ire_walk_v6(ipif_delete_cache_ire, (char *)usesrc_cli_ill,
		    ALL_ZONES, ipst);
	else
		ire_walk_v4(ipif_delete_cache_ire, (char *)usesrc_cli_ill,
		    ALL_ZONES, ipst);

	/*
	 * ill_g_usesrc_lock global lock protects the ill_usesrc_grp_next
	 * and the ill_usesrc_ifindex fields
	 */
	rw_enter(&ipst->ips_ill_g_usesrc_lock, RW_WRITER);

	if (reset_flg) {
		ret = ill_relink_usesrc_ills(usesrc_cli_ill, usesrc_ill, 0);
		if (ret != 0) {
			err = EINVAL;
		}
		rw_exit(&ipst->ips_ill_g_usesrc_lock);
		goto done;
	}

	/*
	 * Four possibilities to consider:
	 * 1. Both usesrc_ill and usesrc_cli_ill are not part of any usesrc grp
	 * 2. usesrc_ill is part of a group but usesrc_cli_ill isn't
	 * 3. usesrc_cli_ill is part of a group but usesrc_ill isn't
	 * 4. Both are part of their respective usesrc groups
	 */
	if ((usesrc_ill->ill_usesrc_grp_next == NULL) &&
	    (usesrc_cli_ill->ill_usesrc_grp_next == NULL)) {
		ASSERT(usesrc_ill->ill_usesrc_ifindex == 0);
		usesrc_cli_ill->ill_usesrc_ifindex = ifindex;
		usesrc_ill->ill_usesrc_grp_next = usesrc_cli_ill;
		usesrc_cli_ill->ill_usesrc_grp_next = usesrc_ill;
	} else if ((usesrc_ill->ill_usesrc_grp_next != NULL) &&
	    (usesrc_cli_ill->ill_usesrc_grp_next == NULL)) {
		usesrc_cli_ill->ill_usesrc_ifindex = ifindex;
		/* Insert at head of list */
		usesrc_cli_ill->ill_usesrc_grp_next =
		    usesrc_ill->ill_usesrc_grp_next;
		usesrc_ill->ill_usesrc_grp_next = usesrc_cli_ill;
	} else {
		ret = ill_relink_usesrc_ills(usesrc_cli_ill, usesrc_ill,
		    ifindex);
		if (ret != 0)
			err = EINVAL;
	}
	rw_exit(&ipst->ips_ill_g_usesrc_lock);

done:
	if (ill_flag_changed) {
		mutex_enter(&usesrc_cli_ill->ill_lock);
		usesrc_cli_ill->ill_state_flags &= ~ILL_CHANGING;
		mutex_exit(&usesrc_cli_ill->ill_lock);
	}
	if (ipsq != NULL)
		ipsq_exit(ipsq);
	/* The refrele on the lifr_name ipif is done by ip_process_ioctl */
	ill_refrele(usesrc_ill);
	return (err);
}

/*
 * comparison function used by avl.
 */
static int
ill_phyint_compare_index(const void *index_ptr, const void *phyip)
{

	uint_t index;

	ASSERT(phyip != NULL && index_ptr != NULL);

	index = *((uint_t *)index_ptr);
	/*
	 * let the phyint with the lowest index be on top.
	 */
	if (((phyint_t *)phyip)->phyint_ifindex < index)
		return (1);
	if (((phyint_t *)phyip)->phyint_ifindex > index)
		return (-1);
	return (0);
}

/*
 * comparison function used by avl.
 */
static int
ill_phyint_compare_name(const void *name_ptr, const void *phyip)
{
	ill_t *ill;
	int res = 0;

	ASSERT(phyip != NULL && name_ptr != NULL);

	if (((phyint_t *)phyip)->phyint_illv4)
		ill = ((phyint_t *)phyip)->phyint_illv4;
	else
		ill = ((phyint_t *)phyip)->phyint_illv6;
	ASSERT(ill != NULL);

	res = strcmp(ill->ill_name, (char *)name_ptr);
	if (res > 0)
		return (1);
	else if (res < 0)
		return (-1);
	return (0);
}

/*
 * This function is called on the unplumb path via ill_glist_delete() when
 * there are no ills left on the phyint and thus the phyint can be freed.
 */
static void
phyint_free(phyint_t *phyi)
{
	ip_stack_t *ipst = PHYINT_TO_IPST(phyi);

	ASSERT(phyi->phyint_illv4 == NULL && phyi->phyint_illv6 == NULL);

	/*
	 * If this phyint was an IPMP meta-interface, blow away the group.
	 * This is safe to do because all of the illgrps have already been
	 * removed by I_PUNLINK, and thus SIOCSLIFGROUPNAME cannot find us.
	 * If we're cleaning up as a result of failed initialization,
	 * phyint_grp may be NULL.
	 */
	if ((phyi->phyint_flags & PHYI_IPMP) && (phyi->phyint_grp != NULL)) {
		rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
		ipmp_grp_destroy(phyi->phyint_grp);
		phyi->phyint_grp = NULL;
		rw_exit(&ipst->ips_ipmp_lock);
	}

	/*
	 * If this interface was under IPMP, take it out of the group.
	 */
	if (phyi->phyint_grp != NULL)
		ipmp_phyint_leave_grp(phyi);

	/*
	 * Delete the phyint and disassociate its ipsq.  The ipsq itself
	 * will be freed in ipsq_exit().
	 */
	phyi->phyint_ipsq->ipsq_phyint = NULL;
	phyi->phyint_name[0] = '\0';

	mi_free(phyi);
}

/*
 * Attach the ill to the phyint structure which can be shared by both
 * IPv4 and IPv6 ill. ill_init allocates a phyint to just hold flags. This
 * function is called from ipif_set_values and ill_lookup_on_name (for
 * loopback) where we know the name of the ill. We lookup the ill and if
 * there is one present already with the name use that phyint. Otherwise
 * reuse the one allocated by ill_init.
 */
static void
ill_phyint_reinit(ill_t *ill)
{
	boolean_t isv6 = ill->ill_isv6;
	phyint_t *phyi_old;
	phyint_t *phyi;
	avl_index_t where = 0;
	ill_t	*ill_other = NULL;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(RW_WRITE_HELD(&ipst->ips_ill_g_lock));

	phyi_old = ill->ill_phyint;
	ASSERT(isv6 || (phyi_old->phyint_illv4 == ill &&
	    phyi_old->phyint_illv6 == NULL));
	ASSERT(!isv6 || (phyi_old->phyint_illv6 == ill &&
	    phyi_old->phyint_illv4 == NULL));
	ASSERT(phyi_old->phyint_ifindex == 0);

	/*
	 * Now that our ill has a name, set it in the phyint.
	 */
	(void) strlcpy(ill->ill_phyint->phyint_name, ill->ill_name, LIFNAMSIZ);

	phyi = avl_find(&ipst->ips_phyint_g_list->phyint_list_avl_by_name,
	    ill->ill_name, &where);

	/*
	 * 1. We grabbed the ill_g_lock before inserting this ill into
	 *    the global list of ills. So no other thread could have located
	 *    this ill and hence the ipsq of this ill is guaranteed to be empty.
	 * 2. Now locate the other protocol instance of this ill.
	 * 3. Now grab both ill locks in the right order, and the phyint lock of
	 *    the new ipsq. Holding ill locks + ill_g_lock ensures that the ipsq
	 *    of neither ill can change.
	 * 4. Merge the phyint and thus the ipsq as well of this ill onto the
	 *    other ill.
	 * 5. Release all locks.
	 */

	/*
	 * Look for IPv4 if we are initializing IPv6 or look for IPv6 if
	 * we are initializing IPv4.
	 */
	if (phyi != NULL) {
		ill_other = (isv6) ? phyi->phyint_illv4 : phyi->phyint_illv6;
		ASSERT(ill_other->ill_phyint != NULL);
		ASSERT((isv6 && !ill_other->ill_isv6) ||
		    (!isv6 && ill_other->ill_isv6));
		GRAB_ILL_LOCKS(ill, ill_other);
		/*
		 * We are potentially throwing away phyint_flags which
		 * could be different from the one that we obtain from
		 * ill_other->ill_phyint. But it is okay as we are assuming
		 * that the state maintained within IP is correct.
		 */
		mutex_enter(&phyi->phyint_lock);
		if (isv6) {
			ASSERT(phyi->phyint_illv6 == NULL);
			phyi->phyint_illv6 = ill;
		} else {
			ASSERT(phyi->phyint_illv4 == NULL);
			phyi->phyint_illv4 = ill;
		}

		/*
		 * Delete the old phyint and make its ipsq eligible
		 * to be freed in ipsq_exit().
		 */
		phyi_old->phyint_illv4 = NULL;
		phyi_old->phyint_illv6 = NULL;
		phyi_old->phyint_ipsq->ipsq_phyint = NULL;
		phyi_old->phyint_name[0] = '\0';
		mi_free(phyi_old);
	} else {
		mutex_enter(&ill->ill_lock);
		/*
		 * We don't need to acquire any lock, since
		 * the ill is not yet visible globally  and we
		 * have not yet released the ill_g_lock.
		 */
		phyi = phyi_old;
		mutex_enter(&phyi->phyint_lock);
		/* XXX We need a recovery strategy here. */
		if (!phyint_assign_ifindex(phyi, ipst))
			cmn_err(CE_PANIC, "phyint_assign_ifindex() failed");

		avl_insert(&ipst->ips_phyint_g_list->phyint_list_avl_by_name,
		    (void *)phyi, where);

		(void) avl_find(&ipst->ips_phyint_g_list->
		    phyint_list_avl_by_index,
		    &phyi->phyint_ifindex, &where);
		avl_insert(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
		    (void *)phyi, where);
	}

	/*
	 * Reassigning ill_phyint automatically reassigns the ipsq also.
	 * pending mp is not affected because that is per ill basis.
	 */
	ill->ill_phyint = phyi;

	/*
	 * Now that the phyint's ifindex has been assigned, complete the
	 * remaining
	 */

	ill->ill_ip_mib->ipIfStatsIfIndex = ill->ill_phyint->phyint_ifindex;
	if (ill->ill_isv6) {
		ill->ill_icmp6_mib->ipv6IfIcmpIfIndex =
		    ill->ill_phyint->phyint_ifindex;
		ill->ill_mcast_type = ipst->ips_mld_max_version;
	} else {
		ill->ill_mcast_type = ipst->ips_igmp_max_version;
	}

	/*
	 * Generate an event within the hooks framework to indicate that
	 * a new interface has just been added to IP.  For this event to
	 * be generated, the network interface must, at least, have an
	 * ifindex assigned to it.
	 *
	 * This needs to be run inside the ill_g_lock perimeter to ensure
	 * that the ordering of delivered events to listeners matches the
	 * order of them in the kernel.
	 *
	 * This function could be called from ill_lookup_on_name. In that case
	 * the interface is loopback "lo", which will not generate a NIC event.
	 */
	if (ill->ill_name_length <= 2 ||
	    ill->ill_name[0] != 'l' || ill->ill_name[1] != 'o') {
		ill_nic_event_dispatch(ill, 0, NE_PLUMB, ill->ill_name,
		    ill->ill_name_length);
	}
	RELEASE_ILL_LOCKS(ill, ill_other);
	mutex_exit(&phyi->phyint_lock);
}

/*
 * Notify any downstream modules of the name of this interface.
 * An M_IOCTL is used even though we don't expect a successful reply.
 * Any reply message from the driver (presumably an M_IOCNAK) will
 * eventually get discarded somewhere upstream.  The message format is
 * simply an SIOCSLIFNAME ioctl just as might be sent from ifconfig
 * to IP.
 */
static void
ip_ifname_notify(ill_t *ill, queue_t *q)
{
	mblk_t *mp1, *mp2;
	struct iocblk *iocp;
	struct lifreq *lifr;

	mp1 = mkiocb(SIOCSLIFNAME);
	if (mp1 == NULL)
		return;
	mp2 = allocb(sizeof (struct lifreq), BPRI_HI);
	if (mp2 == NULL) {
		freeb(mp1);
		return;
	}

	mp1->b_cont = mp2;
	iocp = (struct iocblk *)mp1->b_rptr;
	iocp->ioc_count = sizeof (struct lifreq);

	lifr = (struct lifreq *)mp2->b_rptr;
	mp2->b_wptr += sizeof (struct lifreq);
	bzero(lifr, sizeof (struct lifreq));

	(void) strncpy(lifr->lifr_name, ill->ill_name, LIFNAMSIZ);
	lifr->lifr_ppa = ill->ill_ppa;
	lifr->lifr_flags = (ill->ill_flags & (ILLF_IPV4|ILLF_IPV6));

	putnext(q, mp1);
}

static int
ipif_set_values_tail(ill_t *ill, ipif_t *ipif, mblk_t *mp, queue_t *q)
{
	int		err;
	ip_stack_t	*ipst = ill->ill_ipst;
	phyint_t	*phyi = ill->ill_phyint;

	/* Set the obsolete NDD per-interface forwarding name. */
	err = ill_set_ndd_name(ill);
	if (err != 0) {
		cmn_err(CE_WARN, "ipif_set_values: ill_set_ndd_name (%d)\n",
		    err);
	}

	/*
	 * Now that ill_name is set, the configuration for the IPMP
	 * meta-interface can be performed.
	 */
	if (IS_IPMP(ill)) {
		rw_enter(&ipst->ips_ipmp_lock, RW_WRITER);
		/*
		 * If phyi->phyint_grp is NULL, then this is the first IPMP
		 * meta-interface and we need to create the IPMP group.
		 */
		if (phyi->phyint_grp == NULL) {
			/*
			 * If someone has renamed another IPMP group to have
			 * the same name as our interface, bail.
			 */
			if (ipmp_grp_lookup(ill->ill_name, ipst) != NULL) {
				rw_exit(&ipst->ips_ipmp_lock);
				return (EEXIST);
			}
			phyi->phyint_grp = ipmp_grp_create(ill->ill_name, phyi);
			if (phyi->phyint_grp == NULL) {
				rw_exit(&ipst->ips_ipmp_lock);
				return (ENOMEM);
			}
		}
		rw_exit(&ipst->ips_ipmp_lock);
	}

	/* Tell downstream modules where they are. */
	ip_ifname_notify(ill, q);

	/*
	 * ill_dl_phys returns EINPROGRESS in the usual case.
	 * Error cases are ENOMEM ...
	 */
	err = ill_dl_phys(ill, ipif, mp, q);

	/*
	 * If there is no IRE expiration timer running, get one started.
	 * igmp and mld timers will be triggered by the first multicast
	 */
	if (ipst->ips_ip_ire_expire_id == 0) {
		/*
		 * acquire the lock and check again.
		 */
		mutex_enter(&ipst->ips_ip_trash_timer_lock);
		if (ipst->ips_ip_ire_expire_id == 0) {
			ipst->ips_ip_ire_expire_id = timeout(
			    ip_trash_timer_expire, ipst,
			    MSEC_TO_TICK(ipst->ips_ip_timer_interval));
		}
		mutex_exit(&ipst->ips_ip_trash_timer_lock);
	}

	if (ill->ill_isv6) {
		mutex_enter(&ipst->ips_mld_slowtimeout_lock);
		if (ipst->ips_mld_slowtimeout_id == 0) {
			ipst->ips_mld_slowtimeout_id = timeout(mld_slowtimo,
			    (void *)ipst,
			    MSEC_TO_TICK(MCAST_SLOWTIMO_INTERVAL));
		}
		mutex_exit(&ipst->ips_mld_slowtimeout_lock);
	} else {
		mutex_enter(&ipst->ips_igmp_slowtimeout_lock);
		if (ipst->ips_igmp_slowtimeout_id == 0) {
			ipst->ips_igmp_slowtimeout_id = timeout(igmp_slowtimo,
			    (void *)ipst,
			    MSEC_TO_TICK(MCAST_SLOWTIMO_INTERVAL));
		}
		mutex_exit(&ipst->ips_igmp_slowtimeout_lock);
	}

	return (err);
}

/*
 * Common routine for ppa and ifname setting. Should be called exclusive.
 *
 * Returns EINPROGRESS when mp has been consumed by queueing it on
 * ill_pending_mp and the ioctl will complete in ip_rput.
 *
 * NOTE : If ppa is UNIT_MAX, we assign the next valid ppa and return
 * the new name and new ppa in lifr_name and lifr_ppa respectively.
 * For SLIFNAME, we pass these values back to the userland.
 */
static int
ipif_set_values(queue_t *q, mblk_t *mp, char *interf_name, uint_t *new_ppa_ptr)
{
	ill_t	*ill;
	ipif_t	*ipif;
	ipsq_t	*ipsq;
	char	*ppa_ptr;
	char	*old_ptr;
	char	old_char;
	int	error;
	ip_stack_t	*ipst;

	ip1dbg(("ipif_set_values: interface %s\n", interf_name));
	ASSERT(q->q_next != NULL);
	ASSERT(interf_name != NULL);

	ill = (ill_t *)q->q_ptr;
	ipst = ill->ill_ipst;

	ASSERT(ill->ill_ipst != NULL);
	ASSERT(ill->ill_name[0] == '\0');
	ASSERT(IAM_WRITER_ILL(ill));
	ASSERT((mi_strlen(interf_name) + 1) <= LIFNAMSIZ);
	ASSERT(ill->ill_ppa == UINT_MAX);

	/* The ppa is sent down by ifconfig or is chosen */
	if ((ppa_ptr = ill_get_ppa_ptr(interf_name)) == NULL) {
		return (EINVAL);
	}

	/*
	 * make sure ppa passed in is same as ppa in the name.
	 * This check is not made when ppa == UINT_MAX in that case ppa
	 * in the name could be anything. System will choose a ppa and
	 * update new_ppa_ptr and inter_name to contain the choosen ppa.
	 */
	if (*new_ppa_ptr != UINT_MAX) {
		/* stoi changes the pointer */
		old_ptr = ppa_ptr;
		/*
		 * ifconfig passed in 0 for the ppa for DLPI 1 style devices
		 * (they don't have an externally visible ppa).  We assign one
		 * here so that we can manage the interface.  Note that in
		 * the past this value was always 0 for DLPI 1 drivers.
		 */
		if (*new_ppa_ptr == 0)
			*new_ppa_ptr = stoi(&old_ptr);
		else if (*new_ppa_ptr != (uint_t)stoi(&old_ptr))
			return (EINVAL);
	}
	/*
	 * terminate string before ppa
	 * save char at that location.
	 */
	old_char = ppa_ptr[0];
	ppa_ptr[0] = '\0';

	ill->ill_ppa = *new_ppa_ptr;
	/*
	 * Finish as much work now as possible before calling ill_glist_insert
	 * which makes the ill globally visible and also merges it with the
	 * other protocol instance of this phyint. The remaining work is
	 * done after entering the ipsq which may happen sometime later.
	 * ill_set_ndd_name occurs after the ill has been made globally visible.
	 */
	ipif = ill->ill_ipif;

	/* We didn't do this when we allocated ipif in ip_ll_subnet_defaults */
	ipif_assign_seqid(ipif);

	if (!(ill->ill_flags & (ILLF_IPV4|ILLF_IPV6)))
		ill->ill_flags |= ILLF_IPV4;

	ASSERT(ipif->ipif_next == NULL);	/* Only one ipif on ill */
	ASSERT((ipif->ipif_flags & IPIF_UP) == 0);

	if (ill->ill_flags & ILLF_IPV6) {

		ill->ill_isv6 = B_TRUE;
		if (ill->ill_rq != NULL) {
			ill->ill_rq->q_qinfo = &iprinitv6;
			ill->ill_wq->q_qinfo = &ipwinitv6;
		}

		/* Keep the !IN6_IS_ADDR_V4MAPPED assertions happy */
		ipif->ipif_v6lcl_addr = ipv6_all_zeros;
		ipif->ipif_v6src_addr = ipv6_all_zeros;
		ipif->ipif_v6subnet = ipv6_all_zeros;
		ipif->ipif_v6net_mask = ipv6_all_zeros;
		ipif->ipif_v6brd_addr = ipv6_all_zeros;
		ipif->ipif_v6pp_dst_addr = ipv6_all_zeros;
		/*
		 * point-to-point or Non-mulicast capable
		 * interfaces won't do NUD unless explicitly
		 * configured to do so.
		 */
		if (ipif->ipif_flags & IPIF_POINTOPOINT ||
		    !(ill->ill_flags & ILLF_MULTICAST)) {
			ill->ill_flags |= ILLF_NONUD;
		}
		/* Make sure IPv4 specific flag is not set on IPv6 if */
		if (ill->ill_flags & ILLF_NOARP) {
			/*
			 * Note: xresolv interfaces will eventually need
			 * NOARP set here as well, but that will require
			 * those external resolvers to have some
			 * knowledge of that flag and act appropriately.
			 * Not to be changed at present.
			 */
			ill->ill_flags &= ~ILLF_NOARP;
		}
		/*
		 * Set the ILLF_ROUTER flag according to the global
		 * IPv6 forwarding policy.
		 */
		if (ipst->ips_ipv6_forward != 0)
			ill->ill_flags |= ILLF_ROUTER;
	} else if (ill->ill_flags & ILLF_IPV4) {
		ill->ill_isv6 = B_FALSE;
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &ipif->ipif_v6lcl_addr);
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &ipif->ipif_v6src_addr);
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &ipif->ipif_v6subnet);
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &ipif->ipif_v6net_mask);
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &ipif->ipif_v6brd_addr);
		IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &ipif->ipif_v6pp_dst_addr);
		/*
		 * Set the ILLF_ROUTER flag according to the global
		 * IPv4 forwarding policy.
		 */
		if (ipst->ips_ip_g_forward != 0)
			ill->ill_flags |= ILLF_ROUTER;
	}

	ASSERT(ill->ill_phyint != NULL);

	/*
	 * The ipIfStatsIfindex and ipv6IfIcmpIfIndex assignments will
	 * be completed in ill_glist_insert -> ill_phyint_reinit
	 */
	if (!ill_allocate_mibs(ill))
		return (ENOMEM);

	/*
	 * Pick a default sap until we get the DL_INFO_ACK back from
	 * the driver.
	 */
	if (ill->ill_sap == 0) {
		if (ill->ill_isv6)
			ill->ill_sap = IP6_DL_SAP;
		else
			ill->ill_sap = IP_DL_SAP;
	}

	ill->ill_ifname_pending = 1;
	ill->ill_ifname_pending_err = 0;

	/*
	 * When the first ipif comes up in ipif_up_done(), multicast groups
	 * that were joined while this ill was not bound to the DLPI link need
	 * to be recovered by ill_recover_multicast().
	 */
	ill->ill_need_recover_multicast = 1;

	ill_refhold(ill);
	rw_enter(&ipst->ips_ill_g_lock, RW_WRITER);
	if ((error = ill_glist_insert(ill, interf_name,
	    (ill->ill_flags & ILLF_IPV6) == ILLF_IPV6)) > 0) {
		ill->ill_ppa = UINT_MAX;
		ill->ill_name[0] = '\0';
		/*
		 * undo null termination done above.
		 */
		ppa_ptr[0] = old_char;
		rw_exit(&ipst->ips_ill_g_lock);
		ill_refrele(ill);
		return (error);
	}

	ASSERT(ill->ill_name_length <= LIFNAMSIZ);

	/*
	 * When we return the buffer pointed to by interf_name should contain
	 * the same name as in ill_name.
	 * If a ppa was choosen by the system (ppa passed in was UINT_MAX)
	 * the buffer pointed to by new_ppa_ptr would not contain the right ppa
	 * so copy full name and update the ppa ptr.
	 * When ppa passed in != UINT_MAX all values are correct just undo
	 * null termination, this saves a bcopy.
	 */
	if (*new_ppa_ptr == UINT_MAX) {
		bcopy(ill->ill_name, interf_name, ill->ill_name_length);
		*new_ppa_ptr = ill->ill_ppa;
	} else {
		/*
		 * undo null termination done above.
		 */
		ppa_ptr[0] = old_char;
	}

	/* Let SCTP know about this ILL */
	sctp_update_ill(ill, SCTP_ILL_INSERT);

	ipsq = ipsq_try_enter(NULL, ill, q, mp, ip_reprocess_ioctl, NEW_OP,
	    B_TRUE);

	rw_exit(&ipst->ips_ill_g_lock);
	ill_refrele(ill);
	if (ipsq == NULL)
		return (EINPROGRESS);

	/*
	 * If ill_phyint_reinit() changed our ipsq, then start on the new ipsq.
	 */
	if (ipsq->ipsq_xop->ipx_current_ipif == NULL)
		ipsq_current_start(ipsq, ipif, SIOCSLIFNAME);
	else
		ASSERT(ipsq->ipsq_xop->ipx_current_ipif == ipif);

	error = ipif_set_values_tail(ill, ipif, mp, q);
	ipsq_exit(ipsq);
	if (error != 0 && error != EINPROGRESS) {
		/*
		 * restore previous values
		 */
		ill->ill_isv6 = B_FALSE;
	}
	return (error);
}


void
ipif_init(ip_stack_t *ipst)
{
	int i;

	for (i = 0; i < MAX_G_HEADS; i++) {
		ipst->ips_ill_g_heads[i].ill_g_list_head =
		    (ill_if_t *)&ipst->ips_ill_g_heads[i];
		ipst->ips_ill_g_heads[i].ill_g_list_tail =
		    (ill_if_t *)&ipst->ips_ill_g_heads[i];
	}

	avl_create(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
	    ill_phyint_compare_index,
	    sizeof (phyint_t),
	    offsetof(struct phyint, phyint_avl_by_index));
	avl_create(&ipst->ips_phyint_g_list->phyint_list_avl_by_name,
	    ill_phyint_compare_name,
	    sizeof (phyint_t),
	    offsetof(struct phyint, phyint_avl_by_name));
}

/*
 * Lookup the ipif corresponding to the onlink destination address. For
 * point-to-point interfaces, it matches with remote endpoint destination
 * address. For point-to-multipoint interfaces it only tries to match the
 * destination with the interface's subnet address. The longest, most specific
 * match is found to take care of such rare network configurations like -
 * le0: 129.146.1.1/16
 * le1: 129.146.2.2/24
 *
 * This is used by SO_DONTROUTE and IP_NEXTHOP.  Since neither of those are
 * supported on underlying interfaces in an IPMP group, underlying interfaces
 * are ignored when looking up a match.  (If we didn't ignore them, we'd
 * risk using a test address as a source for outgoing traffic.)
 */
ipif_t *
ipif_lookup_onlink_addr(ipaddr_t addr, zoneid_t zoneid, ip_stack_t *ipst)
{
	ipif_t	*ipif, *best_ipif;
	ill_t	*ill;
	ill_walk_context_t ctx;

	ASSERT(zoneid != ALL_ZONES);
	best_ipif = NULL;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (IS_UNDER_IPMP(ill))
			continue;
		mutex_enter(&ill->ill_lock);
		for (ipif = ill->ill_ipif; ipif != NULL;
		    ipif = ipif->ipif_next) {
			if (!IPIF_CAN_LOOKUP(ipif))
				continue;
			if (ipif->ipif_zoneid != zoneid &&
			    ipif->ipif_zoneid != ALL_ZONES)
				continue;
			/*
			 * Point-to-point case. Look for exact match with
			 * destination address.
			 */
			if (ipif->ipif_flags & IPIF_POINTOPOINT) {
				if (ipif->ipif_pp_dst_addr == addr) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					if (best_ipif != NULL)
						ipif_refrele(best_ipif);
					return (ipif);
				}
			} else if (ipif->ipif_subnet == (addr &
			    ipif->ipif_net_mask)) {
				/*
				 * Point-to-multipoint case. Looping through to
				 * find the most specific match. If there are
				 * multiple best match ipif's then prefer ipif's
				 * that are UP. If there is only one best match
				 * ipif and it is DOWN we must still return it.
				 */
				if ((best_ipif == NULL) ||
				    (ipif->ipif_net_mask >
				    best_ipif->ipif_net_mask) ||
				    ((ipif->ipif_net_mask ==
				    best_ipif->ipif_net_mask) &&
				    ((ipif->ipif_flags & IPIF_UP) &&
				    (!(best_ipif->ipif_flags & IPIF_UP))))) {
					ipif_refhold_locked(ipif);
					mutex_exit(&ill->ill_lock);
					rw_exit(&ipst->ips_ill_g_lock);
					if (best_ipif != NULL)
						ipif_refrele(best_ipif);
					best_ipif = ipif;
					rw_enter(&ipst->ips_ill_g_lock,
					    RW_READER);
					mutex_enter(&ill->ill_lock);
				}
			}
		}
		mutex_exit(&ill->ill_lock);
	}
	rw_exit(&ipst->ips_ill_g_lock);
	return (best_ipif);
}

/*
 * Save enough information so that we can recreate the IRE if
 * the interface goes down and then up.
 */
static void
ipif_save_ire(ipif_t *ipif, ire_t *ire)
{
	mblk_t	*save_mp;

	save_mp = allocb(sizeof (ifrt_t), BPRI_MED);
	if (save_mp != NULL) {
		ifrt_t	*ifrt;

		save_mp->b_wptr += sizeof (ifrt_t);
		ifrt = (ifrt_t *)save_mp->b_rptr;
		bzero(ifrt, sizeof (ifrt_t));
		ifrt->ifrt_type = ire->ire_type;
		ifrt->ifrt_addr = ire->ire_addr;
		ifrt->ifrt_gateway_addr = ire->ire_gateway_addr;
		ifrt->ifrt_src_addr = ire->ire_src_addr;
		ifrt->ifrt_mask = ire->ire_mask;
		ifrt->ifrt_flags = ire->ire_flags;
		ifrt->ifrt_max_frag = ire->ire_max_frag;
		mutex_enter(&ipif->ipif_saved_ire_lock);
		save_mp->b_cont = ipif->ipif_saved_ire_mp;
		ipif->ipif_saved_ire_mp = save_mp;
		ipif->ipif_saved_ire_cnt++;
		mutex_exit(&ipif->ipif_saved_ire_lock);
	}
}

static void
ipif_remove_ire(ipif_t *ipif, ire_t *ire)
{
	mblk_t	**mpp;
	mblk_t	*mp;
	ifrt_t	*ifrt;

	/* Remove from ipif_saved_ire_mp list if it is there */
	mutex_enter(&ipif->ipif_saved_ire_lock);
	for (mpp = &ipif->ipif_saved_ire_mp; *mpp != NULL;
	    mpp = &(*mpp)->b_cont) {
		/*
		 * On a given ipif, the triple of address, gateway and
		 * mask is unique for each saved IRE (in the case of
		 * ordinary interface routes, the gateway address is
		 * all-zeroes).
		 */
		mp = *mpp;
		ifrt = (ifrt_t *)mp->b_rptr;
		if (ifrt->ifrt_addr == ire->ire_addr &&
		    ifrt->ifrt_gateway_addr == ire->ire_gateway_addr &&
		    ifrt->ifrt_mask == ire->ire_mask) {
			*mpp = mp->b_cont;
			ipif->ipif_saved_ire_cnt--;
			freeb(mp);
			break;
		}
	}
	mutex_exit(&ipif->ipif_saved_ire_lock);
}

/*
 * IP multirouting broadcast routes handling
 * Append CGTP broadcast IREs to regular ones created
 * at ifconfig time.
 */
static void
ip_cgtp_bcast_add(ire_t *ire, ire_t *ire_dst, ip_stack_t *ipst)
{
	ire_t *ire_prim;

	ASSERT(ire != NULL);
	ASSERT(ire_dst != NULL);

	ire_prim = ire_ctable_lookup(ire->ire_gateway_addr, 0,
	    IRE_BROADCAST, NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	if (ire_prim != NULL) {
		/*
		 * We are in the special case of broadcasts for
		 * CGTP. We add an IRE_BROADCAST that holds
		 * the RTF_MULTIRT flag, the destination
		 * address of ire_dst and the low level
		 * info of ire_prim. In other words, CGTP
		 * broadcast is added to the redundant ipif.
		 */
		ipif_t *ipif_prim;
		ire_t  *bcast_ire;

		ipif_prim = ire_prim->ire_ipif;

		ip2dbg(("ip_cgtp_filter_bcast_add: "
		    "ire_dst %p, ire_prim %p, ipif_prim %p\n",
		    (void *)ire_dst, (void *)ire_prim,
		    (void *)ipif_prim));

		bcast_ire = ire_create(
		    (uchar_t *)&ire->ire_addr,
		    (uchar_t *)&ip_g_all_ones,
		    (uchar_t *)&ire_dst->ire_src_addr,
		    (uchar_t *)&ire->ire_gateway_addr,
		    &ipif_prim->ipif_mtu,
		    NULL,
		    ipif_prim->ipif_rq,
		    ipif_prim->ipif_wq,
		    IRE_BROADCAST,
		    ipif_prim,
		    0,
		    0,
		    0,
		    ire->ire_flags,
		    &ire_uinfo_null,
		    NULL,
		    NULL,
		    ipst);

		if (bcast_ire != NULL) {

			if (ire_add(&bcast_ire, NULL, NULL, NULL,
			    B_FALSE) == 0) {
				ip2dbg(("ip_cgtp_filter_bcast_add: "
				    "added bcast_ire %p\n",
				    (void *)bcast_ire));

				ipif_save_ire(bcast_ire->ire_ipif,
				    bcast_ire);
				ire_refrele(bcast_ire);
			}
		}
		ire_refrele(ire_prim);
	}
}


/*
 * IP multirouting broadcast routes handling
 * Remove the broadcast ire
 */
static void
ip_cgtp_bcast_delete(ire_t *ire, ip_stack_t *ipst)
{
	ire_t *ire_dst;

	ASSERT(ire != NULL);
	ire_dst = ire_ctable_lookup(ire->ire_addr, 0, IRE_BROADCAST,
	    NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
	if (ire_dst != NULL) {
		ire_t *ire_prim;

		ire_prim = ire_ctable_lookup(ire->ire_gateway_addr, 0,
		    IRE_BROADCAST, NULL, ALL_ZONES, NULL, MATCH_IRE_TYPE, ipst);
		if (ire_prim != NULL) {
			ipif_t *ipif_prim;
			ire_t  *bcast_ire;

			ipif_prim = ire_prim->ire_ipif;

			ip2dbg(("ip_cgtp_filter_bcast_delete: "
			    "ire_dst %p, ire_prim %p, ipif_prim %p\n",
			    (void *)ire_dst, (void *)ire_prim,
			    (void *)ipif_prim));

			bcast_ire = ire_ctable_lookup(ire->ire_addr,
			    ire->ire_gateway_addr,
			    IRE_BROADCAST,
			    ipif_prim, ALL_ZONES,
			    NULL,
			    MATCH_IRE_TYPE | MATCH_IRE_GW | MATCH_IRE_IPIF |
			    MATCH_IRE_MASK, ipst);

			if (bcast_ire != NULL) {
				ip2dbg(("ip_cgtp_filter_bcast_delete: "
				    "looked up bcast_ire %p\n",
				    (void *)bcast_ire));
				ipif_remove_ire(bcast_ire->ire_ipif,
				    bcast_ire);
				ire_delete(bcast_ire);
				ire_refrele(bcast_ire);
			}
			ire_refrele(ire_prim);
		}
		ire_refrele(ire_dst);
	}
}

/*
 * IPsec hardware acceleration capabilities related functions.
 */

/*
 * Free a per-ill IPsec capabilities structure.
 */
static void
ill_ipsec_capab_free(ill_ipsec_capab_t *capab)
{
	if (capab->auth_hw_algs != NULL)
		kmem_free(capab->auth_hw_algs, capab->algs_size);
	if (capab->encr_hw_algs != NULL)
		kmem_free(capab->encr_hw_algs, capab->algs_size);
	if (capab->encr_algparm != NULL)
		kmem_free(capab->encr_algparm, capab->encr_algparm_size);
	kmem_free(capab, sizeof (ill_ipsec_capab_t));
}

/*
 * Allocate a new per-ill IPsec capabilities structure. This structure
 * is specific to an IPsec protocol (AH or ESP). It is implemented as
 * an array which specifies, for each algorithm, whether this algorithm
 * is supported by the ill or not.
 */
static ill_ipsec_capab_t *
ill_ipsec_capab_alloc(void)
{
	ill_ipsec_capab_t *capab;
	uint_t nelems;

	capab = kmem_zalloc(sizeof (ill_ipsec_capab_t), KM_NOSLEEP);
	if (capab == NULL)
		return (NULL);

	/* we need one bit per algorithm */
	nelems = MAX_IPSEC_ALGS / BITS(ipsec_capab_elem_t);
	capab->algs_size = nelems * sizeof (ipsec_capab_elem_t);

	/* allocate memory to store algorithm flags */
	capab->encr_hw_algs = kmem_zalloc(capab->algs_size, KM_NOSLEEP);
	if (capab->encr_hw_algs == NULL)
		goto nomem;
	capab->auth_hw_algs = kmem_zalloc(capab->algs_size, KM_NOSLEEP);
	if (capab->auth_hw_algs == NULL)
		goto nomem;
	/*
	 * Leave encr_algparm NULL for now since we won't need it half
	 * the time
	 */
	return (capab);

nomem:
	ill_ipsec_capab_free(capab);
	return (NULL);
}

/*
 * Resize capability array.  Since we're exclusive, this is OK.
 */
static boolean_t
ill_ipsec_capab_resize_algparm(ill_ipsec_capab_t *capab, int algid)
{
	ipsec_capab_algparm_t *nalp, *oalp;
	uint32_t olen, nlen;

	oalp = capab->encr_algparm;
	olen = capab->encr_algparm_size;

	if (oalp != NULL) {
		if (algid < capab->encr_algparm_end)
			return (B_TRUE);
	}

	nlen = (algid + 1) * sizeof (*nalp);
	nalp = kmem_zalloc(nlen, KM_NOSLEEP);
	if (nalp == NULL)
		return (B_FALSE);

	if (oalp != NULL) {
		bcopy(oalp, nalp, olen);
		kmem_free(oalp, olen);
	}
	capab->encr_algparm = nalp;
	capab->encr_algparm_size = nlen;
	capab->encr_algparm_end = algid + 1;

	return (B_TRUE);
}

/*
 * Compare the capabilities of the specified ill with the protocol
 * and algorithms specified by the SA passed as argument.
 * If they match, returns B_TRUE, B_FALSE if they do not match.
 *
 * The ill can be passed as a pointer to it, or by specifying its index
 * and whether it is an IPv6 ill (ill_index and ill_isv6 arguments).
 *
 * Called by ipsec_out_is_accelerated() do decide whether an outbound
 * packet is eligible for hardware acceleration, and by
 * ill_ipsec_capab_send_all() to decide whether a SA must be sent down
 * to a particular ill.
 */
boolean_t
ipsec_capab_match(ill_t *ill, uint_t ill_index, boolean_t ill_isv6,
    ipsa_t *sa, netstack_t *ns)
{
	boolean_t sa_isv6;
	uint_t algid;
	struct ill_ipsec_capab_s *cpp;
	boolean_t need_refrele = B_FALSE;
	ip_stack_t	*ipst = ns->netstack_ip;

	if (ill == NULL) {
		ill = ill_lookup_on_ifindex(ill_index, ill_isv6, NULL,
		    NULL, NULL, NULL, ipst);
		if (ill == NULL) {
			ip0dbg(("ipsec_capab_match: ill doesn't exist\n"));
			return (B_FALSE);
		}
		need_refrele = B_TRUE;
	}

	/*
	 * Use the address length specified by the SA to determine
	 * if it corresponds to a IPv6 address, and fail the matching
	 * if the isv6 flag passed as argument does not match.
	 * Note: this check is used for SADB capability checking before
	 * sending SA information to an ill.
	 */
	sa_isv6 = (sa->ipsa_addrfam == AF_INET6);
	if (sa_isv6 != ill_isv6)
		/* protocol mismatch */
		goto done;

	/*
	 * Check if the ill supports the protocol, algorithm(s) and
	 * key size(s) specified by the SA, and get the pointers to
	 * the algorithms supported by the ill.
	 */
	switch (sa->ipsa_type) {

	case SADB_SATYPE_ESP:
		if (!(ill->ill_capabilities & ILL_CAPAB_ESP))
			/* ill does not support ESP acceleration */
			goto done;
		cpp = ill->ill_ipsec_capab_esp;
		algid = sa->ipsa_auth_alg;
		if (!IPSEC_ALG_IS_ENABLED(algid, cpp->auth_hw_algs))
			goto done;
		algid = sa->ipsa_encr_alg;
		if (!IPSEC_ALG_IS_ENABLED(algid, cpp->encr_hw_algs))
			goto done;
		if (algid < cpp->encr_algparm_end) {
			ipsec_capab_algparm_t *alp = &cpp->encr_algparm[algid];
			if (sa->ipsa_encrkeybits < alp->minkeylen)
				goto done;
			if (sa->ipsa_encrkeybits > alp->maxkeylen)
				goto done;
		}
		break;

	case SADB_SATYPE_AH:
		if (!(ill->ill_capabilities & ILL_CAPAB_AH))
			/* ill does not support AH acceleration */
			goto done;
		if (!IPSEC_ALG_IS_ENABLED(sa->ipsa_auth_alg,
		    ill->ill_ipsec_capab_ah->auth_hw_algs))
			goto done;
		break;
	}

	if (need_refrele)
		ill_refrele(ill);
	return (B_TRUE);
done:
	if (need_refrele)
		ill_refrele(ill);
	return (B_FALSE);
}

/*
 * Add a new ill to the list of IPsec capable ills.
 * Called from ill_capability_ipsec_ack() when an ACK was received
 * indicating that IPsec hardware processing was enabled for an ill.
 *
 * ill must point to the ill for which acceleration was enabled.
 * dl_cap must be set to DL_CAPAB_IPSEC_AH or DL_CAPAB_IPSEC_ESP.
 */
static void
ill_ipsec_capab_add(ill_t *ill, uint_t dl_cap, boolean_t sadb_resync)
{
	ipsec_capab_ill_t **ills, *cur_ill, *new_ill;
	uint_t sa_type;
	uint_t ipproto;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT((dl_cap == DL_CAPAB_IPSEC_AH) ||
	    (dl_cap == DL_CAPAB_IPSEC_ESP));

	switch (dl_cap) {
	case DL_CAPAB_IPSEC_AH:
		sa_type = SADB_SATYPE_AH;
		ills = &ipst->ips_ipsec_capab_ills_ah;
		ipproto = IPPROTO_AH;
		break;
	case DL_CAPAB_IPSEC_ESP:
		sa_type = SADB_SATYPE_ESP;
		ills = &ipst->ips_ipsec_capab_ills_esp;
		ipproto = IPPROTO_ESP;
		break;
	}

	rw_enter(&ipst->ips_ipsec_capab_ills_lock, RW_WRITER);

	/*
	 * Add ill index to list of hardware accelerators. If
	 * already in list, do nothing.
	 */
	for (cur_ill = *ills; cur_ill != NULL &&
	    (cur_ill->ill_index != ill->ill_phyint->phyint_ifindex ||
	    cur_ill->ill_isv6 != ill->ill_isv6); cur_ill = cur_ill->next)
		;

	if (cur_ill == NULL) {
		/* if this is a new entry for this ill */
		new_ill = kmem_zalloc(sizeof (ipsec_capab_ill_t), KM_NOSLEEP);
		if (new_ill == NULL) {
			rw_exit(&ipst->ips_ipsec_capab_ills_lock);
			return;
		}

		new_ill->ill_index = ill->ill_phyint->phyint_ifindex;
		new_ill->ill_isv6 = ill->ill_isv6;
		new_ill->next = *ills;
		*ills = new_ill;
	} else if (!sadb_resync) {
		/* not resync'ing SADB and an entry exists for this ill */
		rw_exit(&ipst->ips_ipsec_capab_ills_lock);
		return;
	}

	rw_exit(&ipst->ips_ipsec_capab_ills_lock);

	if (ipst->ips_ipcl_proto_fanout_v6[ipproto].connf_head != NULL)
		/*
		 * IPsec module for protocol loaded, initiate dump
		 * of the SADB to this ill.
		 */
		sadb_ill_download(ill, sa_type);
}

/*
 * Remove an ill from the list of IPsec capable ills.
 */
static void
ill_ipsec_capab_delete(ill_t *ill, uint_t dl_cap)
{
	ipsec_capab_ill_t **ills, *cur_ill, *prev_ill;
	ip_stack_t	*ipst = ill->ill_ipst;

	ASSERT(dl_cap == DL_CAPAB_IPSEC_AH ||
	    dl_cap == DL_CAPAB_IPSEC_ESP);

	ills = (dl_cap == DL_CAPAB_IPSEC_AH) ? &ipst->ips_ipsec_capab_ills_ah :
	    &ipst->ips_ipsec_capab_ills_esp;

	rw_enter(&ipst->ips_ipsec_capab_ills_lock, RW_WRITER);

	prev_ill = NULL;
	for (cur_ill = *ills; cur_ill != NULL && (cur_ill->ill_index !=
	    ill->ill_phyint->phyint_ifindex || cur_ill->ill_isv6 !=
	    ill->ill_isv6); prev_ill = cur_ill, cur_ill = cur_ill->next)
		;
	if (cur_ill == NULL) {
		/* entry not found */
		rw_exit(&ipst->ips_ipsec_capab_ills_lock);
		return;
	}
	if (prev_ill == NULL) {
		/* entry at front of list */
		*ills = NULL;
	} else {
		prev_ill->next = cur_ill->next;
	}
	kmem_free(cur_ill, sizeof (ipsec_capab_ill_t));
	rw_exit(&ipst->ips_ipsec_capab_ills_lock);
}

/*
 * Called by SADB to send a DL_CONTROL_REQ message to every ill
 * supporting the specified IPsec protocol acceleration.
 * sa_type must be SADB_SATYPE_AH or SADB_SATYPE_ESP.
 * We free the mblk and, if sa is non-null, release the held referece.
 */
void
ill_ipsec_capab_send_all(uint_t sa_type, mblk_t *mp, ipsa_t *sa,
    netstack_t *ns)
{
	ipsec_capab_ill_t *ici, *cur_ici;
	ill_t *ill;
	mblk_t *nmp, *mp_ship_list = NULL, *next_mp;
	ip_stack_t	*ipst = ns->netstack_ip;

	ici = (sa_type == SADB_SATYPE_AH) ? ipst->ips_ipsec_capab_ills_ah :
	    ipst->ips_ipsec_capab_ills_esp;

	rw_enter(&ipst->ips_ipsec_capab_ills_lock, RW_READER);

	for (cur_ici = ici; cur_ici != NULL; cur_ici = cur_ici->next) {
		ill = ill_lookup_on_ifindex(cur_ici->ill_index,
		    cur_ici->ill_isv6, NULL, NULL, NULL, NULL, ipst);

		/*
		 * Handle the case where the ill goes away while the SADB is
		 * attempting to send messages.  If it's going away, it's
		 * nuking its shadow SADB, so we don't care..
		 */

		if (ill == NULL)
			continue;

		if (sa != NULL) {
			/*
			 * Make sure capabilities match before
			 * sending SA to ill.
			 */
			if (!ipsec_capab_match(ill, cur_ici->ill_index,
			    cur_ici->ill_isv6, sa, ipst->ips_netstack)) {
				ill_refrele(ill);
				continue;
			}

			mutex_enter(&sa->ipsa_lock);
			sa->ipsa_flags |= IPSA_F_HW;
			mutex_exit(&sa->ipsa_lock);
		}

		/*
		 * Copy template message, and add it to the front
		 * of the mblk ship list. We want to avoid holding
		 * the ipsec_capab_ills_lock while sending the
		 * message to the ills.
		 *
		 * The b_next and b_prev are temporarily used
		 * to build a list of mblks to be sent down, and to
		 * save the ill to which they must be sent.
		 */
		nmp = copymsg(mp);
		if (nmp == NULL) {
			ill_refrele(ill);
			continue;
		}
		ASSERT(nmp->b_next == NULL && nmp->b_prev == NULL);
		nmp->b_next = mp_ship_list;
		mp_ship_list = nmp;
		nmp->b_prev = (mblk_t *)ill;
	}

	rw_exit(&ipst->ips_ipsec_capab_ills_lock);

	for (nmp = mp_ship_list; nmp != NULL; nmp = next_mp) {
		/* restore the mblk to a sane state */
		next_mp = nmp->b_next;
		nmp->b_next = NULL;
		ill = (ill_t *)nmp->b_prev;
		nmp->b_prev = NULL;

		ill_dlpi_send(ill, nmp);
		ill_refrele(ill);
	}

	if (sa != NULL)
		IPSA_REFRELE(sa);
	freemsg(mp);
}

/*
 * Derive an interface id from the link layer address.
 * Knows about IEEE 802 and IEEE EUI-64 mappings.
 */
static boolean_t
ip_ether_v6intfid(ill_t *ill, in6_addr_t *v6addr)
{
	char		*addr;

	if (ill->ill_phys_addr_length != ETHERADDRL)
		return (B_FALSE);

	/* Form EUI-64 like address */
	addr = (char *)&v6addr->s6_addr32[2];
	bcopy(ill->ill_phys_addr, addr, 3);
	addr[0] ^= 0x2;		/* Toggle Universal/Local bit */
	addr[3] = (char)0xff;
	addr[4] = (char)0xfe;
	bcopy(ill->ill_phys_addr + 3, addr + 5, 3);
	return (B_TRUE);
}

/* ARGSUSED */
static boolean_t
ip_nodef_v6intfid(ill_t *ill, in6_addr_t *v6addr)
{
	return (B_FALSE);
}

typedef struct ipmp_ifcookie {
	uint32_t	ic_hostid;
	char		ic_ifname[LIFNAMSIZ];
	char		ic_zonename[ZONENAME_MAX];
} ipmp_ifcookie_t;

/*
 * Construct a pseudo-random interface ID for the IPMP interface that's both
 * predictable and (almost) guaranteed to be unique.
 */
static boolean_t
ip_ipmp_v6intfid(ill_t *ill, in6_addr_t *v6addr)
{
	zone_t		*zp;
	uint8_t		*addr;
	uchar_t		hash[16];
	ulong_t 	hostid;
	MD5_CTX		ctx;
	ipmp_ifcookie_t	ic = { 0 };

	ASSERT(IS_IPMP(ill));

	(void) ddi_strtoul(hw_serial, NULL, 10, &hostid);
	ic.ic_hostid = htonl((uint32_t)hostid);

	(void) strlcpy(ic.ic_ifname, ill->ill_name, LIFNAMSIZ);

	if ((zp = zone_find_by_id(ill->ill_zoneid)) != NULL) {
		(void) strlcpy(ic.ic_zonename, zp->zone_name, ZONENAME_MAX);
		zone_rele(zp);
	}

	MD5Init(&ctx);
	MD5Update(&ctx, &ic, sizeof (ic));
	MD5Final(hash, &ctx);

	/*
	 * Map the hash to an interface ID per the basic approach in RFC3041.
	 */
	addr = &v6addr->s6_addr8[8];
	bcopy(hash + 8, addr, sizeof (uint64_t));
	addr[0] &= ~0x2;				/* set local bit */

	return (B_TRUE);
}

/* ARGSUSED */
static boolean_t
ip_ether_v6mapinfo(uint_t lla_length, uint8_t *bphys_addr, uint8_t *maddr,
    uint32_t *hw_start, in6_addr_t *v6_extract_mask)
{
	/*
	 * Multicast address mappings used over Ethernet/802.X.
	 * This address is used as a base for mappings.
	 */
	static uint8_t ipv6_g_phys_multi_addr[] = {0x33, 0x33, 0x00,
	    0x00, 0x00, 0x00};

	/*
	 * Extract low order 32 bits from IPv6 multicast address.
	 * Or that into the link layer address, starting from the
	 * second byte.
	 */
	*hw_start = 2;
	v6_extract_mask->s6_addr32[0] = 0;
	v6_extract_mask->s6_addr32[1] = 0;
	v6_extract_mask->s6_addr32[2] = 0;
	v6_extract_mask->s6_addr32[3] = 0xffffffffU;
	bcopy(ipv6_g_phys_multi_addr, maddr, lla_length);
	return (B_TRUE);
}

/*
 * Indicate by return value whether multicast is supported. If not,
 * this code should not touch/change any parameters.
 */
/* ARGSUSED */
static boolean_t
ip_ether_v4mapinfo(uint_t phys_length, uint8_t *bphys_addr, uint8_t *maddr,
    uint32_t *hw_start, ipaddr_t *extract_mask)
{
	/*
	 * Multicast address mappings used over Ethernet/802.X.
	 * This address is used as a base for mappings.
	 */
	static uint8_t ip_g_phys_multi_addr[] = { 0x01, 0x00, 0x5e,
	    0x00, 0x00, 0x00 };

	if (phys_length != ETHERADDRL)
		return (B_FALSE);

	*extract_mask = htonl(0x007fffff);
	*hw_start = 2;
	bcopy(ip_g_phys_multi_addr, maddr, ETHERADDRL);
	return (B_TRUE);
}

/*
 * Derive IPoIB interface id from the link layer address.
 */
static boolean_t
ip_ib_v6intfid(ill_t *ill, in6_addr_t *v6addr)
{
	char		*addr;

	if (ill->ill_phys_addr_length != 20)
		return (B_FALSE);
	addr = (char *)&v6addr->s6_addr32[2];
	bcopy(ill->ill_phys_addr + 12, addr, 8);
	/*
	 * In IBA 1.1 timeframe, some vendors erroneously set the u/l bit
	 * in the globally assigned EUI-64 GUID to 1, in violation of IEEE
	 * rules. In these cases, the IBA considers these GUIDs to be in
	 * "Modified EUI-64" format, and thus toggling the u/l bit is not
	 * required; vendors are required not to assign global EUI-64's
	 * that differ only in u/l bit values, thus guaranteeing uniqueness
	 * of the interface identifier. Whether the GUID is in modified
	 * or proper EUI-64 format, the ipv6 identifier must have the u/l
	 * bit set to 1.
	 */
	addr[0] |= 2;			/* Set Universal/Local bit to 1 */
	return (B_TRUE);
}

/*
 * Note on mapping from multicast IP addresses to IPoIB multicast link
 * addresses. IPoIB multicast link addresses are based on IBA link addresses.
 * The format of an IPoIB multicast address is:
 *
 *  4 byte QPN      Scope Sign.  Pkey
 * +--------------------------------------------+
 * | 00FFFFFF | FF | 1X | X01B | Pkey | GroupID |
 * +--------------------------------------------+
 *
 * The Scope and Pkey components are properties of the IBA port and
 * network interface. They can be ascertained from the broadcast address.
 * The Sign. part is the signature, and is 401B for IPv4 and 601B for IPv6.
 */

static boolean_t
ip_ib_v6mapinfo(uint_t lla_length, uint8_t *bphys_addr, uint8_t *maddr,
    uint32_t *hw_start, in6_addr_t *v6_extract_mask)
{
	/*
	 * Base IPoIB IPv6 multicast address used for mappings.
	 * Does not contain the IBA scope/Pkey values.
	 */
	static uint8_t ipv6_g_phys_ibmulti_addr[] = { 0x00, 0xff, 0xff, 0xff,
	    0xff, 0x10, 0x60, 0x1b, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	/*
	 * Extract low order 80 bits from IPv6 multicast address.
	 * Or that into the link layer address, starting from the
	 * sixth byte.
	 */
	*hw_start = 6;
	bcopy(ipv6_g_phys_ibmulti_addr, maddr, lla_length);

	/*
	 * Now fill in the IBA scope/Pkey values from the broadcast address.
	 */
	*(maddr + 5) = *(bphys_addr + 5);
	*(maddr + 8) = *(bphys_addr + 8);
	*(maddr + 9) = *(bphys_addr + 9);

	v6_extract_mask->s6_addr32[0] = 0;
	v6_extract_mask->s6_addr32[1] = htonl(0x0000ffff);
	v6_extract_mask->s6_addr32[2] = 0xffffffffU;
	v6_extract_mask->s6_addr32[3] = 0xffffffffU;
	return (B_TRUE);
}

static boolean_t
ip_ib_v4mapinfo(uint_t phys_length, uint8_t *bphys_addr, uint8_t *maddr,
    uint32_t *hw_start, ipaddr_t *extract_mask)
{
	/*
	 * Base IPoIB IPv4 multicast address used for mappings.
	 * Does not contain the IBA scope/Pkey values.
	 */
	static uint8_t ipv4_g_phys_ibmulti_addr[] = { 0x00, 0xff, 0xff, 0xff,
	    0xff, 0x10, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (phys_length != sizeof (ipv4_g_phys_ibmulti_addr))
		return (B_FALSE);

	/*
	 * Extract low order 28 bits from IPv4 multicast address.
	 * Or that into the link layer address, starting from the
	 * sixteenth byte.
	 */
	*extract_mask = htonl(0x0fffffff);
	*hw_start = 16;
	bcopy(ipv4_g_phys_ibmulti_addr, maddr, phys_length);

	/*
	 * Now fill in the IBA scope/Pkey values from the broadcast address.
	 */
	*(maddr + 5) = *(bphys_addr + 5);
	*(maddr + 8) = *(bphys_addr + 8);
	*(maddr + 9) = *(bphys_addr + 9);
	return (B_TRUE);
}

/*
 * Returns B_TRUE if an ipif is present in the given zone, matching some flags
 * (typically IPIF_UP). If ipifp is non-null, the held ipif is returned there.
 * This works for both IPv4 and IPv6; if the passed-in ill is v6, the ipif with
 * the link-local address is preferred.
 */
boolean_t
ipif_lookup_zoneid(ill_t *ill, zoneid_t zoneid, int flags, ipif_t **ipifp)
{
	ipif_t	*ipif;
	ipif_t	*maybe_ipif = NULL;

	mutex_enter(&ill->ill_lock);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		if (ipifp != NULL)
			*ipifp = NULL;
		return (B_FALSE);
	}

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (!IPIF_CAN_LOOKUP(ipif))
			continue;
		if (zoneid != ALL_ZONES && ipif->ipif_zoneid != zoneid &&
		    ipif->ipif_zoneid != ALL_ZONES)
			continue;
		if ((ipif->ipif_flags & flags) != flags)
			continue;

		if (ipifp == NULL) {
			mutex_exit(&ill->ill_lock);
			ASSERT(maybe_ipif == NULL);
			return (B_TRUE);
		}
		if (!ill->ill_isv6 ||
		    IN6_IS_ADDR_LINKLOCAL(&ipif->ipif_v6src_addr)) {
			ipif_refhold_locked(ipif);
			mutex_exit(&ill->ill_lock);
			*ipifp = ipif;
			return (B_TRUE);
		}
		if (maybe_ipif == NULL)
			maybe_ipif = ipif;
	}
	if (ipifp != NULL) {
		if (maybe_ipif != NULL)
			ipif_refhold_locked(maybe_ipif);
		*ipifp = maybe_ipif;
	}
	mutex_exit(&ill->ill_lock);
	return (maybe_ipif != NULL);
}

/*
 * Return a pointer to an ipif_t given a combination of (ill_idx,ipif_id)
 * If a pointer to an ipif_t is returned then the caller will need to do
 * an ill_refrele().
 */
ipif_t *
ipif_getby_indexes(uint_t ifindex, uint_t lifidx, boolean_t isv6,
    ip_stack_t *ipst)
{
	ipif_t *ipif;
	ill_t *ill;

	ill = ill_lookup_on_ifindex(ifindex, isv6, NULL, NULL, NULL, NULL,
	    ipst);
	if (ill == NULL)
		return (NULL);

	mutex_enter(&ill->ill_lock);
	if (ill->ill_state_flags & ILL_CONDEMNED) {
		mutex_exit(&ill->ill_lock);
		ill_refrele(ill);
		return (NULL);
	}

	for (ipif = ill->ill_ipif; ipif != NULL; ipif = ipif->ipif_next) {
		if (!IPIF_CAN_LOOKUP(ipif))
			continue;
		if (lifidx == ipif->ipif_id) {
			ipif_refhold_locked(ipif);
			break;
		}
	}

	mutex_exit(&ill->ill_lock);
	ill_refrele(ill);
	return (ipif);
}

/*
 * Flush the fastpath by deleting any nce's that are waiting for the fastpath,
 * There is one exceptions IRE_BROADCAST are difficult to recreate,
 * so instead we just nuke their nce_fp_mp's; see ndp_fastpath_flush()
 * for details.
 */
void
ill_fastpath_flush(ill_t *ill)
{
	ip_stack_t *ipst = ill->ill_ipst;

	nce_fastpath_list_dispatch(ill, NULL, NULL);
	ndp_walk_common((ill->ill_isv6 ? ipst->ips_ndp6 : ipst->ips_ndp4),
	    ill, (pfi_t)ndp_fastpath_flush, NULL, B_TRUE);
}

/*
 * Set the physical address information for `ill' to the contents of the
 * dl_notify_ind_t pointed to by `mp'.  Must be called as writer, and will be
 * asynchronous if `ill' cannot immediately be quiesced -- in which case
 * EINPROGRESS will be returned.
 */
int
ill_set_phys_addr(ill_t *ill, mblk_t *mp)
{
	ipsq_t *ipsq = ill->ill_phyint->phyint_ipsq;
	dl_notify_ind_t	*dlindp = (dl_notify_ind_t *)mp->b_rptr;

	ASSERT(IAM_WRITER_IPSQ(ipsq));

	if (dlindp->dl_data != DL_IPV6_LINK_LAYER_ADDR &&
	    dlindp->dl_data != DL_CURR_PHYS_ADDR) {
		/* Changing DL_IPV6_TOKEN is not yet supported */
		return (0);
	}

	/*
	 * We need to store up to two copies of `mp' in `ill'.  Due to the
	 * design of ipsq_pending_mp_add(), we can't pass them as separate
	 * arguments to ill_set_phys_addr_tail().  Instead, chain them
	 * together here, then pull 'em apart in ill_set_phys_addr_tail().
	 */
	if ((mp = copyb(mp)) == NULL || (mp->b_cont = copyb(mp)) == NULL) {
		freemsg(mp);
		return (ENOMEM);
	}

	ipsq_current_start(ipsq, ill->ill_ipif, 0);

	/*
	 * If we can quiesce the ill, then set the address.  If not, then
	 * ill_set_phys_addr_tail() will be called from ipif_ill_refrele_tail().
	 */
	ill_down_ipifs(ill);
	mutex_enter(&ill->ill_lock);
	if (!ill_is_quiescent(ill)) {
		/* call cannot fail since `conn_t *' argument is NULL */
		(void) ipsq_pending_mp_add(NULL, ill->ill_ipif, ill->ill_rq,
		    mp, ILL_DOWN);
		mutex_exit(&ill->ill_lock);
		return (EINPROGRESS);
	}
	mutex_exit(&ill->ill_lock);

	ill_set_phys_addr_tail(ipsq, ill->ill_rq, mp, NULL);
	return (0);
}

/*
 * Once the ill associated with `q' has quiesced, set its physical address
 * information to the values in `addrmp'.  Note that two copies of `addrmp'
 * are passed (linked by b_cont), since we sometimes need to save two distinct
 * copies in the ill_t, and our context doesn't permit sleeping or allocation
 * failure (we'll free the other copy if it's not needed).  Since the ill_t
 * is quiesced, we know any stale IREs with the old address information have
 * already been removed, so we don't need to call ill_fastpath_flush().
 */
/* ARGSUSED */
static void
ill_set_phys_addr_tail(ipsq_t *ipsq, queue_t *q, mblk_t *addrmp, void *dummy)
{
	ill_t		*ill = q->q_ptr;
	mblk_t		*addrmp2 = unlinkb(addrmp);
	dl_notify_ind_t	*dlindp = (dl_notify_ind_t *)addrmp->b_rptr;
	uint_t		addrlen, addroff;

	ASSERT(IAM_WRITER_IPSQ(ipsq));

	addroff	= dlindp->dl_addr_offset;
	addrlen = dlindp->dl_addr_length - ABS(ill->ill_sap_length);

	switch (dlindp->dl_data) {
	case DL_IPV6_LINK_LAYER_ADDR:
		ill_set_ndmp(ill, addrmp, addroff, addrlen);
		freemsg(addrmp2);
		break;

	case DL_CURR_PHYS_ADDR:
		freemsg(ill->ill_phys_addr_mp);
		ill->ill_phys_addr = addrmp->b_rptr + addroff;
		ill->ill_phys_addr_mp = addrmp;
		ill->ill_phys_addr_length = addrlen;

		if (ill->ill_isv6 && !(ill->ill_flags & ILLF_XRESOLV))
			ill_set_ndmp(ill, addrmp2, addroff, addrlen);
		else
			freemsg(addrmp2);
		break;
	default:
		ASSERT(0);
	}

	/*
	 * If there are ipifs to bring up, ill_up_ipifs() will return
	 * EINPROGRESS, and ipsq_current_finish() will be called by
	 * ip_rput_dlpi_writer() or ip_arp_done() when the last ipif is
	 * brought up.
	 */
	if (ill_up_ipifs(ill, q, addrmp) != EINPROGRESS)
		ipsq_current_finish(ipsq);
}

/*
 * Helper routine for setting the ill_nd_lla fields.
 */
void
ill_set_ndmp(ill_t *ill, mblk_t *ndmp, uint_t addroff, uint_t addrlen)
{
	freemsg(ill->ill_nd_lla_mp);
	ill->ill_nd_lla = ndmp->b_rptr + addroff;
	ill->ill_nd_lla_mp = ndmp;
	ill->ill_nd_lla_len = addrlen;
}

major_t IP_MAJ;
#define	IP	"ip"

#define	UDP6DEV		"/devices/pseudo/udp6@0:udp6"
#define	UDPDEV		"/devices/pseudo/udp@0:udp"

/*
 * Issue REMOVEIF ioctls to have the loopback interfaces
 * go away.  Other interfaces are either I_LINKed or I_PLINKed;
 * the former going away when the user-level processes in the zone
 * are killed  * and the latter are cleaned up by the stream head
 * str_stack_shutdown callback that undoes all I_PLINKs.
 */
void
ip_loopback_cleanup(ip_stack_t *ipst)
{
	int error;
	ldi_handle_t	lh = NULL;
	ldi_ident_t	li = NULL;
	int		rval;
	cred_t		*cr;
	struct strioctl iocb;
	struct lifreq	lifreq;

	IP_MAJ = ddi_name_to_major(IP);

#ifdef NS_DEBUG
	(void) printf("ip_loopback_cleanup() stackid %d\n",
	    ipst->ips_netstack->netstack_stackid);
#endif

	bzero(&lifreq, sizeof (lifreq));
	(void) strcpy(lifreq.lifr_name, ipif_loopback_name);

	error = ldi_ident_from_major(IP_MAJ, &li);
	if (error) {
#ifdef DEBUG
		printf("ip_loopback_cleanup: lyr ident get failed error %d\n",
		    error);
#endif
		return;
	}

	cr = zone_get_kcred(netstackid_to_zoneid(
	    ipst->ips_netstack->netstack_stackid));
	ASSERT(cr != NULL);
	error = ldi_open_by_name(UDP6DEV, FREAD|FWRITE, cr, &lh, li);
	if (error) {
#ifdef DEBUG
		printf("ip_loopback_cleanup: open of UDP6DEV failed error %d\n",
		    error);
#endif
		goto out;
	}
	iocb.ic_cmd = SIOCLIFREMOVEIF;
	iocb.ic_timout = 15;
	iocb.ic_len = sizeof (lifreq);
	iocb.ic_dp = (char *)&lifreq;

	error = ldi_ioctl(lh, I_STR, (intptr_t)&iocb, FKIOCTL, cr, &rval);
	/* LINTED - statement has no consequent */
	if (error) {
#ifdef NS_DEBUG
		printf("ip_loopback_cleanup: ioctl SIOCLIFREMOVEIF failed on "
		    "UDP6 error %d\n", error);
#endif
	}
	(void) ldi_close(lh, FREAD|FWRITE, cr);
	lh = NULL;

	error = ldi_open_by_name(UDPDEV, FREAD|FWRITE, cr, &lh, li);
	if (error) {
#ifdef NS_DEBUG
		printf("ip_loopback_cleanup: open of UDPDEV failed error %d\n",
		    error);
#endif
		goto out;
	}

	iocb.ic_cmd = SIOCLIFREMOVEIF;
	iocb.ic_timout = 15;
	iocb.ic_len = sizeof (lifreq);
	iocb.ic_dp = (char *)&lifreq;

	error = ldi_ioctl(lh, I_STR, (intptr_t)&iocb, FKIOCTL, cr, &rval);
	/* LINTED - statement has no consequent */
	if (error) {
#ifdef NS_DEBUG
		printf("ip_loopback_cleanup: ioctl SIOCLIFREMOVEIF failed on "
		    "UDP error %d\n", error);
#endif
	}
	(void) ldi_close(lh, FREAD|FWRITE, cr);
	lh = NULL;

out:
	/* Close layered handles */
	if (lh)
		(void) ldi_close(lh, FREAD|FWRITE, cr);
	if (li)
		ldi_ident_release(li);

	crfree(cr);
}

/*
 * This needs to be in-sync with nic_event_t definition
 */
static const char *
ill_hook_event2str(nic_event_t event)
{
	switch (event) {
	case NE_PLUMB:
		return ("PLUMB");
	case NE_UNPLUMB:
		return ("UNPLUMB");
	case NE_UP:
		return ("UP");
	case NE_DOWN:
		return ("DOWN");
	case NE_ADDRESS_CHANGE:
		return ("ADDRESS_CHANGE");
	case NE_LIF_UP:
		return ("LIF_UP");
	case NE_LIF_DOWN:
		return ("LIF_DOWN");
	default:
		return ("UNKNOWN");
	}
}

void
ill_nic_event_dispatch(ill_t *ill, lif_if_t lif, nic_event_t event,
    nic_event_data_t data, size_t datalen)
{
	ip_stack_t		*ipst = ill->ill_ipst;
	hook_nic_event_int_t	*info;
	const char		*str = NULL;

	/* create a new nic event info */
	if ((info = kmem_alloc(sizeof (*info), KM_NOSLEEP)) == NULL)
		goto fail;

	info->hnei_event.hne_nic = ill->ill_phyint->phyint_ifindex;
	info->hnei_event.hne_lif = lif;
	info->hnei_event.hne_event = event;
	info->hnei_event.hne_protocol = ill->ill_isv6 ?
	    ipst->ips_ipv6_net_data : ipst->ips_ipv4_net_data;
	info->hnei_event.hne_data = NULL;
	info->hnei_event.hne_datalen = 0;
	info->hnei_stackid = ipst->ips_netstack->netstack_stackid;

	if (data != NULL && datalen != 0) {
		info->hnei_event.hne_data = kmem_alloc(datalen, KM_NOSLEEP);
		if (info->hnei_event.hne_data == NULL)
			goto fail;
		bcopy(data, info->hnei_event.hne_data, datalen);
		info->hnei_event.hne_datalen = datalen;
	}

	if (ddi_taskq_dispatch(eventq_queue_nic, ip_ne_queue_func, info,
	    DDI_NOSLEEP) == DDI_SUCCESS)
		return;

fail:
	if (info != NULL) {
		if (info->hnei_event.hne_data != NULL) {
			kmem_free(info->hnei_event.hne_data,
			    info->hnei_event.hne_datalen);
		}
		kmem_free(info, sizeof (hook_nic_event_t));
	}
	str = ill_hook_event2str(event);
	ip2dbg(("ill_nic_event_dispatch: could not dispatch %s nic event "
	    "information for %s (ENOMEM)\n", str, ill->ill_name));
}

void
ipif_up_notify(ipif_t *ipif)
{
	ip_rts_ifmsg(ipif, RTSQ_DEFAULT);
	ip_rts_newaddrmsg(RTM_ADD, 0, ipif, RTSQ_DEFAULT);
	sctp_update_ipif(ipif, SCTP_IPIF_UP);
	ill_nic_event_dispatch(ipif->ipif_ill, MAP_IPIF_ID(ipif->ipif_id),
	    NE_LIF_UP, NULL, 0);
}
