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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DLS_IMPL_H
#define	_SYS_DLS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stream.h>
#include <sys/dls.h>
#include <sys/mac.h>
#include <sys/ght.h>
#include <sys/kstat.h>
#include <net/if.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dls_multicst_addr_s	dls_multicst_addr_t;

struct dls_multicst_addr_s {
	dls_multicst_addr_t	*dma_nextp;
	uint8_t			dma_addr[MAXADDRLEN];
};

typedef	struct dls_link_s	dls_link_t;

struct dls_link_s {
	char			dl_name[MAXNAMELEN];
	char			dl_dev[MAXNAMELEN];
	uint_t			dl_port;
	mac_handle_t		dl_mh;
	const mac_info_t	*dl_mip;
	mac_rx_handle_t		dl_mrh;
	mac_txloop_handle_t	dl_mth;
	ghte_t			dl_hte;
	uint_t			dl_ref;
	uint_t			dl_macref;
	ght_t			dl_impl_hash;
	mac_txloop_t		dl_loopback;
	uint_t			dl_npromisc;
	uint_t			dl_nactive;
	uint32_t		dl_unknowns;
	kmutex_t		dl_lock;
};

typedef struct dls_vlan_s {
	char			dv_name[IFNAMSIZ];
	ghte_t			dv_hte;
	uint_t			dv_ref;
	dls_link_t		*dv_dlp;
	uint16_t		dv_id;
	kstat_t			*dv_ksp;
} dls_vlan_t;

typedef struct dls_impl_s dls_impl_t;

typedef mblk_t		*(*dls_priv_header_t)(dls_impl_t *,
    const uint8_t *, uint16_t, uint_t);
typedef void		(*dls_priv_header_info_t)(dls_impl_t *,
    mblk_t *, dls_header_info_t *);

struct dls_impl_s {
	dls_impl_t			*di_nextp;
	dls_vlan_t			*di_dvp;
	mac_handle_t			di_mh;
	mac_notify_handle_t		di_mnh;
	const mac_info_t		*di_mip;
	krwlock_t			di_lock;
	uint16_t			di_sap;
	ghte_t				di_hte;
	uint_t				di_promisc;
	dls_multicst_addr_t		*di_dmap;
	dls_rx_t			di_rx;
	void				*di_rx_arg;
	dls_tx_t			di_tx;
	void				*di_tx_arg;
	boolean_t			di_bound;
	boolean_t			di_removing;
	boolean_t			di_active;
	uint8_t				di_unicst_addr[MAXADDRLEN];
	dls_priv_header_t		di_header;
	dls_priv_header_info_t		di_header_info;
};

extern void		dls_link_init(void);
extern int		dls_link_fini(void);
extern int		dls_link_hold(const char *, uint_t, dls_link_t **);
extern void		dls_link_rele(dls_link_t *);
extern void		dls_link_add(dls_link_t *, uint32_t, dls_impl_t *);
extern void		dls_link_remove(dls_link_t *, dls_impl_t *);
extern int		dls_mac_hold(dls_link_t *);
extern void		dls_mac_rele(dls_link_t *);

extern void		dls_stat_create(dls_vlan_t *);
extern void		dls_stat_destroy(dls_vlan_t *);

extern void		dls_vlan_init(void);
extern int		dls_vlan_fini(void);
extern int		dls_vlan_create(const char *, const char *, uint_t,
    uint16_t);
extern int		dls_vlan_destroy(const char *);
extern int		dls_vlan_hold(const char *, dls_vlan_t **);
extern void		dls_vlan_rele(dls_vlan_t *);

extern void		dls_init(void);
extern int		dls_fini(void);
extern boolean_t	dls_accept(dls_impl_t *, const uint8_t *);
extern boolean_t	dls_accept_loopback(dls_impl_t *, const uint8_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLS_IMPL_H */
