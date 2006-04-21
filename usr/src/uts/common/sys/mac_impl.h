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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MAC_IMPL_H
#define	_SYS_MAC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mac.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mac_multicst_addr_s	mac_multicst_addr_t;

struct mac_multicst_addr_s {
	mac_multicst_addr_t	*mma_nextp;
	uint_t			mma_ref;
	uint8_t			mma_addr[MAXADDRLEN];
};

typedef struct mac_notify_fn_s		mac_notify_fn_t;

struct mac_notify_fn_s {
	mac_notify_fn_t		*mnf_nextp;
	mac_notify_t		mnf_fn;
	void			*mnf_arg;
};

typedef struct mac_rx_fn_s		mac_rx_fn_t;

struct mac_rx_fn_s {
	mac_rx_fn_t		*mrf_nextp;
	mac_rx_t		mrf_fn;
	void			*mrf_arg;
};

typedef struct mac_txloop_fn_s		mac_txloop_fn_t;

struct mac_txloop_fn_s {
	mac_txloop_fn_t		*mtf_nextp;
	mac_txloop_t		mtf_fn;
	void			*mtf_arg;
};

typedef boolean_t	(*mac_unicst_verify_t)(mac_impl_t *,
    const uint8_t *);
typedef boolean_t	(*mac_multicst_verify_t)(mac_impl_t *,
    const uint8_t *);

struct mac_impl_s {
	mac_t			*mi_mp;
	char			mi_dev[MAXNAMELEN];
	uint_t			mi_port;
	char			mi_name[MAXNAMELEN];

	uint32_t		mi_ref;
	boolean_t		mi_disabled;

	krwlock_t		mi_state_lock;
	uint_t			mi_active;

	krwlock_t		mi_data_lock;
	link_state_t		mi_link;
	uint_t			mi_promisc;
	uint_t			mi_devpromisc;
	uint8_t			mi_addr[MAXADDRLEN];
	mac_multicst_addr_t	*mi_mmap;

	uint_t			mi_addr_length;

	krwlock_t		mi_notify_lock;
	mac_notify_fn_t		*mi_mnfp;

	kmutex_t		mi_notify_ref_lock;
	uint32_t		mi_notify_ref;
	kcondvar_t		mi_notify_cv;

	krwlock_t		mi_rx_lock;
	mac_rx_fn_t		*mi_mrfp;

	krwlock_t		mi_txloop_lock;
	mac_txloop_fn_t		*mi_mtfp;

	krwlock_t		mi_resource_lock;
	mac_resource_add_t	mi_resource_add;
	void			*mi_resource_add_arg;

	kstat_t			*mi_ksp;

	mac_unicst_verify_t	mi_unicst_verify;
	mac_multicst_verify_t	mi_multicst_verify;

	kmutex_t		mi_activelink_lock;
	boolean_t		mi_activelink;

	mac_txinfo_t		mi_txinfo;
	mac_txinfo_t		mi_txloopinfo;
};

typedef struct mac_notify_task_arg {
	mac_impl_t		*mnt_mip;
	mac_notify_type_t	mnt_type;
} mac_notify_task_arg_t;

extern void	mac_init(void);
extern int	mac_fini(void);

extern void	mac_stat_create(mac_impl_t *);
extern void	mac_stat_destroy(mac_impl_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MAC_IMPL_H */
