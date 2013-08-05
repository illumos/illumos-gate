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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef _LIBIPADM_IMPL_H
#define	_LIBIPADM_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <net/if.h>
#include <libipadm.h>
#include <libdladm.h>
#include <ipadm_ipmgmt.h>
#include <inet/tunables.h>
#include <netinet/in.h>
#include <pthread.h>
#include <libinetutil.h>
#include <libsocket_priv.h>

#define	IPADM_STRSIZE		256
#define	IPADM_ONSTR		"on"
#define	IPADM_OFFSTR		"off"
#define	ARP_MOD_NAME		"arp"
#define	IPADM_LOGICAL_SEP	':'
#define	IPV6_MIN_MTU		1280	/* rfc2460 */

/* mask for flags accepted by libipadm functions */
#define	IPADM_COMMON_OPT_MASK	(IPADM_OPT_ACTIVE | IPADM_OPT_PERSIST)

/* Opaque library handle */
struct ipadm_handle {
	int		iph_sock;	/* socket to interface */
	int		iph_sock6;	/* socket to interface */
	int		iph_door_fd;	/* door descriptor to ipmgmtd */
	int		iph_rtsock;	/* routing socket */
	dladm_handle_t	iph_dlh;	/* handle to libdladm library */
	uint32_t	iph_flags;	/* internal flags */
	pthread_mutex_t	iph_lock;	/* lock to set door_fd */
	zoneid_t	iph_zoneid;	/* zoneid where handle was opened */
};

struct ipadm_addrobj_s {
	char 			ipadm_ifname[LIFNAMSIZ];
	int32_t			ipadm_lifnum;
	char			ipadm_aobjname[IPADM_AOBJSIZ];
	ipadm_addr_type_t	ipadm_atype;
	uint32_t		ipadm_flags;
	sa_family_t		ipadm_af;
	union {
		struct {
			char			ipadm_ahname[MAXNAMELEN];
			struct sockaddr_storage	ipadm_addr;
			uint32_t		ipadm_prefixlen;
			char			ipadm_dhname[MAXNAMELEN];
			struct sockaddr_storage ipadm_dstaddr;
		} ipadm_static_addr_s;
		struct {
			struct sockaddr_in6	ipadm_intfid;
			uint32_t		ipadm_intfidlen;
			boolean_t		ipadm_stateless;
			boolean_t		ipadm_stateful;
		} ipadm_ipv6_intfid_s;
		struct {
			boolean_t		ipadm_primary;
			int32_t			ipadm_wait;
		} ipadm_dhcp_s;
	} ipadm_addr_u;
};

#define	ipadm_static_addr	ipadm_addr_u.ipadm_static_addr_s.ipadm_addr
#define	ipadm_static_aname	ipadm_addr_u.ipadm_static_addr_s.ipadm_ahname
#define	ipadm_static_prefixlen	ipadm_addr_u.ipadm_static_addr_s.ipadm_prefixlen
#define	ipadm_static_dst_addr	ipadm_addr_u.ipadm_static_addr_s.ipadm_dstaddr
#define	ipadm_static_dname	ipadm_addr_u.ipadm_static_addr_s.ipadm_dhname
#define	ipadm_intfid		ipadm_addr_u.ipadm_ipv6_intfid_s.ipadm_intfid
#define	ipadm_intfidlen		ipadm_addr_u.ipadm_ipv6_intfid_s.ipadm_intfidlen
#define	ipadm_stateless		ipadm_addr_u.ipadm_ipv6_intfid_s.ipadm_stateless
#define	ipadm_stateful		ipadm_addr_u.ipadm_ipv6_intfid_s.ipadm_stateful
#define	ipadm_primary		ipadm_addr_u.ipadm_dhcp_s.ipadm_primary
#define	ipadm_wait		ipadm_addr_u.ipadm_dhcp_s.ipadm_wait

/*
 * Data structures and callback functions related to property management
 */
struct ipadm_prop_desc;
typedef struct ipadm_prop_desc ipadm_prop_desc_t;

/* property set() callback */
typedef ipadm_status_t	ipadm_pd_setf_t(ipadm_handle_t, const void *,
    ipadm_prop_desc_t *, const void *, uint_t, uint_t);

/* property get() callback */
typedef ipadm_status_t	ipadm_pd_getf_t(ipadm_handle_t, const void *,
    ipadm_prop_desc_t *, char *, uint_t *, uint_t, uint_t);

struct ipadm_prop_desc {
	char		*ipd_name;	/* property name */
	char		*ipd_old_name;	/* for backward compatibility */
	uint_t		ipd_class;	/* prop. class - global/perif/both */
	uint_t		ipd_proto;	/* protocol to which property belongs */
	uint_t		ipd_flags;	/* see below */
	ipadm_pd_setf_t	*ipd_set;	/* set callback function */
	ipadm_pd_getf_t	*ipd_get_range;	/* get range callback function */
	ipadm_pd_getf_t	*ipd_get;	/* get value callback function */
};

/* ipd_flags values */
#define	IPADMPROP_MULVAL	0x00000001	/* property multi-valued */

extern ipadm_prop_desc_t	ipadm_addrprop_table[];
extern ipadm_pd_getf_t		i_ipadm_get_onoff;

/* libipadm.c */
extern ipadm_status_t	i_ipadm_get_flags(ipadm_handle_t, const char *,
			    sa_family_t, uint64_t *);
extern ipadm_status_t	i_ipadm_set_flags(ipadm_handle_t, const char *,
			    sa_family_t, uint64_t, uint64_t);
extern ipadm_status_t	i_ipadm_init_ifs(ipadm_handle_t, const char *,
			    nvlist_t **);
extern ipadm_status_t	i_ipadm_init_ifobj(ipadm_handle_t, const char *,
			    nvlist_t *);
extern ipadm_status_t	i_ipadm_init_addrobj(ipadm_handle_t, nvlist_t *);
extern ipadm_status_t	i_ipadm_addr_persist(ipadm_handle_t,
			    const ipadm_addrobj_t, boolean_t, uint32_t);
extern ipadm_status_t	i_ipadm_delete_addr(ipadm_handle_t, ipadm_addrobj_t);
extern int		i_ipadm_strioctl(int, int, char *, int);
extern boolean_t	i_ipadm_is_loopback(const char *);
extern boolean_t	i_ipadm_is_vni(const char *);
extern boolean_t	i_ipadm_is_ipmp(ipadm_handle_t, const char *);
extern boolean_t	i_ipadm_is_under_ipmp(ipadm_handle_t, const char *);
extern boolean_t	i_ipadm_is_6to4(ipadm_handle_t, char *);
extern boolean_t	i_ipadm_validate_ifname(ipadm_handle_t, const char *);
extern ipadm_status_t	ipadm_errno2status(int);
extern int		ipadm_door_call(ipadm_handle_t, void *, size_t, void **,
			    size_t, boolean_t);
extern boolean_t 	ipadm_if_enabled(ipadm_handle_t, const char *,
			    sa_family_t);

/* ipadm_ndpd.c */
extern	ipadm_status_t	i_ipadm_create_ipv6addrs(ipadm_handle_t,
			    ipadm_addrobj_t, uint32_t);
extern ipadm_status_t	i_ipadm_delete_ipv6addrs(ipadm_handle_t,
			    ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_disable_autoconf(const char *);
extern ipadm_status_t	i_ipadm_enable_autoconf(const char *);

/* ipadm_persist.c */
extern ipadm_status_t	i_ipadm_add_ipaddr2nvl(nvlist_t *, ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_add_ip6addr2nvl(nvlist_t *, ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_add_intfid2nvl(nvlist_t *, ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_add_dhcp2nvl(nvlist_t *, boolean_t, int32_t);

/* ipadm_prop.c */
extern ipadm_status_t	i_ipadm_persist_propval(ipadm_handle_t,
			    ipadm_prop_desc_t *, const char *, const void *,
			    uint_t);
extern ipadm_status_t	i_ipadm_get_persist_propval(ipadm_handle_t,
			    ipadm_prop_desc_t *, char *, uint_t *,
			    const void *);

/* ipadm_addr.c */
extern void		i_ipadm_init_addr(ipadm_addrobj_t, const char *,
			    const char *, ipadm_addr_type_t);
extern ipadm_status_t	i_ipadm_merge_prefixlen_from_nvl(nvlist_t *, nvlist_t *,
			    const char *);
extern ipadm_status_t	i_ipadm_get_addrobj(ipadm_handle_t, ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_enable_static(ipadm_handle_t, const char *,
			    nvlist_t *, sa_family_t);
extern ipadm_status_t	i_ipadm_enable_dhcp(ipadm_handle_t, const char *,
			    nvlist_t *);
extern ipadm_status_t	i_ipadm_enable_addrconf(ipadm_handle_t, const char *,
			    nvlist_t *);
extern void		i_ipadm_addrobj2lifname(ipadm_addrobj_t, char *, int);
extern ipadm_status_t	i_ipadm_nvl2in6_addr(nvlist_t *, char *,
			    in6_addr_t *);
extern ipadm_status_t	i_ipadm_get_lif2addrobj(ipadm_handle_t,
			    ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_lookupadd_addrobj(ipadm_handle_t,
			    ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_setlifnum_addrobj(ipadm_handle_t,
			    ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_do_addif(ipadm_handle_t, ipadm_addrobj_t);
extern ipadm_status_t	i_ipadm_delete_addrobj(ipadm_handle_t,
			    const ipadm_addrobj_t, uint32_t);
extern boolean_t	i_ipadm_name2atype(const char *, sa_family_t *,
			    ipadm_addr_type_t *);
extern ipadm_status_t	i_ipadm_resolve_addr(const char *, sa_family_t,
			    struct sockaddr_storage *);

/* ipadm_if.c */
extern ipadm_status_t	i_ipadm_create_if(ipadm_handle_t, char *,  sa_family_t,
			    uint32_t);
extern ipadm_status_t	i_ipadm_delete_if(ipadm_handle_t, const char *,
			    sa_family_t, uint32_t);
extern ipadm_status_t	i_ipadm_plumb_if(ipadm_handle_t, char *, sa_family_t,
			    uint32_t);
extern ipadm_status_t	i_ipadm_unplumb_if(ipadm_handle_t, const char *,
			    sa_family_t);
extern ipadm_status_t	i_ipadm_if_pexists(ipadm_handle_t, const char *,
			    sa_family_t, boolean_t *);
extern ipadm_status_t	i_ipadm_delete_ifobj(ipadm_handle_t, const char *,
			    sa_family_t, boolean_t);
extern int		i_ipadm_get_lnum(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBIPADM_IMPL_H */
