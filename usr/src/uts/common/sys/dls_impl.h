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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DLS_IMPL_H
#define	_SYS_DLS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stream.h>
#include <sys/dls.h>
#include <sys/mac.h>
#include <sys/modhash.h>
#include <sys/kstat.h>
#include <net/if.h>
#include <sys/dlpi.h>
#include <sys/dls_soft_ring.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dls_multicst_addr_s	dls_multicst_addr_t;

struct dls_multicst_addr_s {
	dls_multicst_addr_t	*dma_nextp;
	uint8_t			dma_addr[MAXMACADDRLEN];
};

typedef	struct dls_link_s	dls_link_t;

struct dls_link_s {
	char			dl_name[MAXNAMELEN];
	mac_handle_t		dl_mh;
	const mac_info_t	*dl_mip;
	mac_rx_handle_t		dl_mrh;
	mac_txloop_handle_t	dl_mth;
	uint_t			dl_ref;
	uint_t			dl_macref;
	mod_hash_t		*dl_impl_hash;
	krwlock_t		dl_impl_lock;
	uint_t			dl_impl_count;
	kmutex_t		dl_promisc_lock;
	uint_t			dl_npromisc;
	uint_t			dl_nactive;
	uint32_t		dl_unknowns;
	kmutex_t		dl_lock;
};

typedef struct dls_impl_s dls_impl_t;
typedef struct dls_head_s dls_head_t;

typedef struct dls_vlan_s {
	char			dv_name[IFNAMSIZ];
	uint_t			dv_ref;
	dls_link_t		*dv_dlp;
	uint16_t		dv_id;
	kstat_t			*dv_ksp;
	minor_t			dv_minor;
	t_uscalar_t		dv_ppa;
	zoneid_t		dv_zid;
	dls_impl_t		*dv_impl_list;
} dls_vlan_t;

struct dls_impl_s {
	dls_impl_t			*di_nextp;
	dls_head_t			*di_headp;
	dls_vlan_t			*di_dvp;
	mac_handle_t			di_mh;
	mac_notify_handle_t		di_mnh;
	const mac_info_t		*di_mip;
	krwlock_t			di_lock;
	uint16_t			di_sap;
	uint_t				di_promisc;
	dls_multicst_addr_t		*di_dmap;
	dls_rx_t			di_rx;
	void				*di_rx_arg;
	mac_resource_add_t		di_ring_add;
	const mac_txinfo_t		*di_txinfo;
	boolean_t			di_bound;
	boolean_t			di_removing;
	boolean_t			di_active;
	uint8_t				di_unicst_addr[MAXMACADDRLEN];
	soft_ring_t			**di_soft_ring_list;
	uint_t				di_soft_ring_size;
	zoneid_t			di_zid;
	dls_impl_t			*di_next_impl;
};

struct dls_head_s {
	dls_impl_t			*dh_list;
	uint_t				dh_ref;
	mod_hash_key_t			dh_key;
};

extern void		dls_link_init(void);
extern int		dls_link_fini(void);
extern int		dls_link_hold(const char *, dls_link_t **);
extern void		dls_link_rele(dls_link_t *);
extern void		dls_link_add(dls_link_t *, uint32_t, dls_impl_t *);
extern void		dls_link_remove(dls_link_t *, dls_impl_t *);
extern int		dls_link_header_info(dls_link_t *, mblk_t *,
    mac_header_info_t *);
extern int		dls_mac_hold(dls_link_t *);
extern void		dls_mac_rele(dls_link_t *);

extern void		dls_mac_stat_create(dls_vlan_t *);
extern void		dls_mac_stat_destroy(dls_vlan_t *);

extern void		dls_vlan_init(void);
extern int		dls_vlan_fini(void);
extern int		dls_vlan_create(const char *, const char *, uint16_t);
extern int		dls_vlan_destroy(const char *);
extern int		dls_vlan_hold(const char *, dls_vlan_t **, boolean_t);
extern void		dls_vlan_rele(dls_vlan_t *);
extern int		dls_vlan_walk(int (*)(dls_vlan_t *, void *), void *);
extern dev_info_t	*dls_vlan_finddevinfo(dev_t);
extern int		dls_vlan_ppa_from_minor(minor_t, t_uscalar_t *);
extern int		dls_vlan_rele_by_name(const char *);
extern minor_t		dls_minor_hold(boolean_t);
extern void		dls_minor_rele(minor_t);
extern int		dls_vlan_setzoneid(char *, zoneid_t, boolean_t);
extern int		dls_vlan_getzoneid(char *, zoneid_t *);
extern void		dls_vlan_add_impl(dls_vlan_t *, dls_impl_t *);
extern void		dls_vlan_remove_impl(dls_vlan_t *, dls_impl_t *);

extern void		dls_init(void);
extern int		dls_fini(void);
extern void		dls_link_txloop(void *, mblk_t *);
extern boolean_t	dls_accept(dls_impl_t *, mac_header_info_t *,
    dls_rx_t *, void **);
extern boolean_t	dls_accept_loopback(dls_impl_t *, mac_header_info_t *,
    dls_rx_t *, void **);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLS_IMPL_H */
