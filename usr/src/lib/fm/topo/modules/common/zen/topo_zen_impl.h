/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer company
 */

#ifndef _TOPO_ZEN_IMPL_H
#define	_TOPO_ZEN_IMPL_H

/*
 * Internal implementation details of the topo_zen module.
 */

#include <fm/topo_mod.h>
#include <amdzen_topo.h>
#include <fm/fmd_agent.h>
#include <libnvpair.h>
#include <kstat.h>

#include "topo_zen.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Global data related to our module.
 */
typedef struct zen_topo {
	int zt_fd;
	amdzen_topo_base_t zt_base;
	amdzen_topo_df_t *zt_dfs;
} zen_topo_t;

typedef struct zen_topo_enum_core {
	tnode_t *ztcore_tn;
	tnode_t *ztcore_l1i_tn;
	tnode_t *ztcore_l1d_tn;
	tnode_t *ztcore_l2_tn;
	nvlist_t *ztcore_l1i;
	nvlist_t *ztcore_l1d;
	nvlist_t *ztcore_l2;
	nvlist_t *ztcore_nvls[AMDZEN_TOPO_CORE_MAX_THREADS];
	tnode_t *ztcore_thr_tn[AMDZEN_TOPO_CORE_MAX_THREADS];
} zen_topo_enum_core_t;

typedef struct zen_topo_enum_ccx {
	tnode_t *ztccx_tn;
	tnode_t *ztccx_l3_tn;
	nvlist_t *ztccx_l3;
	zen_topo_enum_core_t ztccx_core[AMDZEN_TOPO_CCX_MAX_CORES];
} zen_topo_enum_ccx_t;

typedef struct zen_topo_enum_ccd {
	tnode_t *ztccd_tn;
	zen_topo_enum_ccx_t ztccd_ccx[AMDZEN_TOPO_CCD_MAX_CCX];
} zen_topo_enum_ccd_t;

typedef struct zen_topo_enum_sock {
	uint32_t ztes_sockid;
	uint32_t ztes_nccd;
	uint32_t ztes_nccd_valid;
	const amdzen_topo_df_t *ztes_df;
	amdzen_topo_ccd_t *ztes_ccd;
	zen_topo_enum_ccd_t *ztes_tn_ccd;
	fmd_agent_hdl_t *ztes_fm_agent;
	kstat_ctl_t *ztes_kstat;
	uint_t ztes_ncpus;
	nvlist_t **ztes_cpus;
	fmd_agent_cpu_cache_list_t ztes_cache;
	tnode_t *ztes_tn;
	/*
	 * These strings come from the CPU and kstat memory. Their lifetime
	 * cannot outlive that of our underlying data sources.
	 */
	const char *ztes_cpu_serial;
	const char *ztes_cpu_rev;
	const char *ztes_cpu_brand;
	const char *ztes_cpu_sock;
	int32_t ztes_cpu_fam;
	int32_t ztes_cpu_model;
	int32_t ztes_cpu_step;
} zen_topo_enum_sock_t;

extern int topo_zen_build_chip(topo_mod_t *, tnode_t *, topo_instance_t,
    zen_topo_enum_sock_t *);
extern int topo_zen_create_tctl(topo_mod_t *, tnode_t *,
    const amdzen_topo_df_t *);
extern int topo_zen_create_tdie(topo_mod_t *, tnode_t *,
    const amdzen_topo_ccd_t *);

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_ZEN_IMPL_H */
