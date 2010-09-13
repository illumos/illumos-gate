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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DAMAP_IMPL_H
#define	_SYS_DAMAP_IMPL_H

#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ddi_isa.h>
#include <sys/model.h>
#include <sys/devctl.h>
#include <sys/nvpair.h>
#include <sys/sysevent.h>
#include <sys/bitset.h>
#include <sys/sdt.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dam dam_t;

/*
 * activate_cb:		Provider callback when reported address is activated
 * deactivate_cb:	Provider callback when address has been released
 *
 * configure_cb:	Class callout to configure newly activated addresses
 * unconfig_cb:		Class callout to unconfigure deactivated addresses
 */
typedef void (*activate_cb_t)(void *, char *addr, int idx, void **privp);
typedef void (*deactivate_cb_t)(void *, char *addr, int idx, void *priv,
    damap_deact_rsn_t deact_rsn);

typedef int (*configure_cb_t)(void *, dam_t *mapp, id_t map_id);
typedef int (*unconfig_cb_t)(void *, dam_t *mapp, id_t map_id);


struct dam {
	char		*dam_name;
	int		dam_flags;		/* map state and cv flags */
	int		dam_options;		/* map options */
	int		dam_rptmode;		/* report mode */
	clock_t		dam_stable_ticks;	/* stabilization */
	uint_t		dam_size;		/* max index for addr hash */
	id_t		dam_high;		/* highest index allocated */
	timeout_id_t	dam_tid;		/* timeout(9F) ID */

	void		*dam_activate_arg;	/* activation private */
	activate_cb_t	dam_activate_cb;	/* activation callback */
	deactivate_cb_t	dam_deactivate_cb;	/* deactivation callback */

	void		*dam_config_arg;	/* config-private */
	configure_cb_t	dam_configure_cb;	/* configure callout */
	unconfig_cb_t	dam_unconfig_cb;	/* unconfigure callout */

	ddi_strid	*dam_addr_hash;		/* addresss to ID hash */
	bitset_t	dam_active_set;		/* activated address set */
	bitset_t	dam_stable_set;		/* stable address set */
	bitset_t	dam_report_set;		/* reported address set */
	void		*dam_da;		/* per-address soft state */
	hrtime_t	dam_last_update;	/* last map update */
	hrtime_t	dam_last_stable;	/* last map stable */
	int		dam_stable_cnt;		/* # of times map stabilized */
	int		dam_stable_overrun;
	kcondvar_t	dam_sync_cv;
	kmutex_t	dam_lock;
	kstat_t		*dam_kstatsp;
	int		dam_sync_to_cnt;
};

#define	DAM_SPEND		0x10	/* stable pending */
#define	DAM_DESTROYPEND		0x20	/* in process of being destroyed */
#define	DAM_SETADD		0x100	/* fullset update pending */

/*
 * per address softstate stucture
 */
typedef struct {
	uint_t		da_flags;	/* flags */
	int		da_jitter;	/* address re-report count */
	int		da_ref;		/* refcount on address */
	void		*da_ppriv;	/* stable provider private */
	void		*da_cfg_priv;	/* config/unconfig private */
	nvlist_t	*da_nvl;	/* stable nvlist */
	void		*da_ppriv_rpt;	/* reported provider-private */
	nvlist_t	*da_nvl_rpt;	/* reported nvlist */
	int64_t		da_deadline;	/* ddi_get_lbolt64 value when stable */
	hrtime_t	da_last_report;	/* timestamp of last report */
	int		da_report_cnt;	/* # of times address reported */
	hrtime_t	da_last_stable;	/* timestamp of last stable address */
	int		da_stable_cnt;	/* # of times address has stabilized */
	char		*da_addr;	/* string in dam_addr_hash (for mdb) */
} dam_da_t;

/*
 * dam_da_t.da_flags
 */
#define	DA_INIT			0x1	/* address initizized */
#define	DA_FAILED_CONFIG	0x2	/* address failed configure */
#define	DA_RELE			0x4	/* adddress released */


/*
 * report type
 */
#define	RPT_ADDR_ADD		0
#define	RPT_ADDR_DEL		1

#define	DAM_IN_REPORT(m, i)	(bitset_in_set(&(m)->dam_report_set, (i)))
#define	DAM_IS_STABLE(m, i)	(bitset_in_set(&(m)->dam_active_set, (i)))

/*
 * DAM statistics
 */
struct dam_kstats {
	struct kstat_named dam_cycles;
	struct kstat_named dam_overrun;
	struct kstat_named dam_jitter;
	struct kstat_named dam_active;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DAMAP_IMPL_H */
