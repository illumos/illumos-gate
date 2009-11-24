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

#ifndef	_SYS_DLS_IMPL_H
#define	_SYS_DLS_IMPL_H

#include <sys/stream.h>
#include <sys/dls.h>
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>
#include <sys/modhash.h>
#include <sys/kstat.h>
#include <net/if.h>
#include <sys/dlpi.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dls_multicst_addr_s {
	struct dls_multicst_addr_s	*dma_nextp;		/* ds_rw_lock */
	uint8_t				dma_addr[MAXMACADDRLEN];
} dls_multicst_addr_t;

struct dls_link_s {				/* Protected by */
	char			dl_name[MAXNAMELEN];	/* SL */
	uint_t			dl_ddi_instance;	/* SL */
	mac_handle_t		dl_mh;			/* SL */
	mac_client_handle_t	dl_mch;			/* SL */
	mac_unicast_handle_t	dl_mah;			/* SL */
	const mac_info_t	*dl_mip;		/* SL */
	uint_t			dl_ref;			/* SL */
	mod_hash_t		*dl_str_hash;		/* SL, modhash lock */
	uint_t			dl_impl_count;		/* SL */
	uint_t			dl_nactive;		/* SL */
	uint32_t		dl_unknowns;		/* atomic */
	zoneid_t		dl_zid;
	uint_t			dl_zone_ref;
	link_tagmode_t		dl_tagmode;		/* atomic */
	uint_t			dl_nonip_cnt;		/* SL */
};

typedef struct dls_head_s {
	kmutex_t		dh_lock;
	struct dld_str_s	*dh_list;		/* dh_ref */
	uint_t			dh_ref;			/* dh_lock */
	mod_hash_key_t		dh_key;			/* SL */
	kcondvar_t		dh_cv;			/* dh_lock */
	uint_t			dh_removing;		/* dh_lock */
} dls_head_t;

extern mod_hash_t	*i_dls_link_hash;

extern void		dls_link_init(void);
extern int		dls_link_fini(void);
extern int		dls_link_hold(const char *, dls_link_t **);
extern int		dls_link_hold_create(const char *, dls_link_t **);
extern int		dls_link_hold_by_dev(dev_t, dls_link_t **);
extern void		dls_link_rele(dls_link_t *);
extern int		dls_link_rele_by_name(const char *);
extern void		dls_link_add(dls_link_t *, uint32_t, dld_str_t *);
extern void		dls_link_remove(dls_link_t *, dld_str_t *);
extern int		dls_link_getzid(const char *, zoneid_t *);
extern int		dls_link_setzid(const char *, zoneid_t);
extern dev_info_t	*dls_link_devinfo(dev_t);
extern dev_t		dls_link_dev(dls_link_t *);

extern void		i_dls_head_rele(dls_head_t *);
extern int		dls_mac_active_set(dls_link_t *i);
extern void		dls_mac_active_clear(dls_link_t *);

extern void		dls_create_str_kstats(dld_str_t *);
extern int		dls_stat_update(kstat_t *, dls_link_t *, int);
extern int		dls_stat_create(const char *, int, const char *,
			    zoneid_t, int (*)(struct kstat *, int), void *,
			    kstat_t **);

extern int		dls_devnet_open_by_dev(dev_t, dls_link_t **,
			    dls_dl_handle_t *);
extern int		dls_devnet_hold_link(datalink_id_t, dls_dl_handle_t *,
			    dls_link_t **);
extern void		dls_devnet_rele_link(dls_dl_handle_t, dls_link_t *);

extern void		dls_init(void);
extern int		dls_fini(void);
extern void		dls_link_txloop(void *, mblk_t *);
extern boolean_t	dls_accept(dld_str_t *, mac_header_info_t *,
			    dls_rx_t *, void **);
extern boolean_t	dls_accept_loopback(dld_str_t *, mac_header_info_t *,
			    dls_rx_t *, void **);
extern boolean_t	dls_accept_promisc(dld_str_t *, mac_header_info_t *,
			    dls_rx_t *, void **, boolean_t);
extern void		i_dls_link_rx(void *, mac_resource_handle_t, mblk_t *,
			    boolean_t);
extern void		dls_rx_promisc(void *, mac_resource_handle_t, mblk_t *,
			    boolean_t);
extern void		dls_rx_vlan_promisc(void *, mac_resource_handle_t,
			    mblk_t *, boolean_t);
extern int		dls_active_set(dld_str_t *);
extern void		dls_active_clear(dld_str_t *, boolean_t);

extern void		dls_mgmt_init(void);
extern void		dls_mgmt_fini(void);

extern int		dls_mgmt_get_phydev(datalink_id_t, dev_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLS_IMPL_H */
