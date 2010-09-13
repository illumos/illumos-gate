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
 */

#ifndef _RDSV3_AF_THR_IMPL_H
#define	_RDSV3_AF_THR_IMPL_H

/*
 * This file is only present in Solaris
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ddi_intr_set_affinity set_intr_affinity
#include <sys/ib/clients/rdsv3/rdsv3_af_thr.h>
#define	SCQ_BIND_CPU (SCQ_HCA_BIND_CPU | SCQ_WRK_BIND_CPU)

#define	RDSV3_AFT_MAX_CONN 4
#define	RDSV3_AFT_PER_CONN_CPU 1
#define	RDSV3_AFT_CONN_CPU_POOL (RDSV3_AFT_MAX_CONN * RDSV3_AFT_PER_CONN_CPU)

#define	RDSV3_CPUID_POOL_MAX 128
static uint32_t rdsv3_cpuid_pool[RDSV3_CPUID_POOL_MAX];
static int rdsv3_cpuid_pool_cnt;
#define	RDSV3_MSIX_POOL_MAX 128
static uint32_t rdsv3_msix_pool[RDSV3_MSIX_POOL_MAX];
static int rdsv3_msix_pool_cnt;

#define	RDSV3_CPUFLAGS_ON 		0x0001
#define	RDSV3_CPUFLAGS_OFF 		0x0002
#define	RDSV3_CPUFLAGS_ASSIGNED		0x0004
#define	RDSV3_CPUFLAGS_INTR		0x0008
#define	RDSV3_CPUFLAGS_HCA		0x0010

#define	RDSV3_CPUFLAGS_UNAVAIL (RDSV3_CPUFLAGS_OFF | RDSV3_CPUFLAGS_INTR)

struct rdsv3_af_grp_s {
	ibt_hca_hdl_t		g_hca_hdl;
	ibt_sched_hdl_t		g_sched_hdl;
	processorid_t		g_hca_cpuid;
	processorid_t		g_conn_cpuid_pool[RDSV3_AFT_CONN_CPU_POOL];
	int			g_conn_cpuid_idx;
};

struct rdsv3_af_thr_s {
	/* Keep the most used members 64bytes cache aligned */
	kmutex_t	aft_lock;	/* lock before using any member */
	kcondvar_t	aft_async;	/* async thread blocks on */
	kthread_t	*aft_worker;	/* kernel thread id */
	void		*aft_data;	/* argument of cq_drain_func */
	processorid_t	aft_cpuid;	/* processor to bind to */
	uint16_t	aft_state;	/* state flags */
	uint16_t	aft_cflag;	/* creation flags */
	rdsv3_af_thr_drain_func_t aft_drain_func;
	rdsv3_af_grp_t	*aft_grp;
	ddi_intr_handle_t aft_intr;	/* intr cookie */
};

/*
 * State flags.
 */
#define	AFT_PROC		0x0001	/* being processed */
#define	AFT_BOUND		0x0002	/* Worker thread is bound to a cpu */
#define	AFT_ARMED		0x0004	/* armed worker thread */
#define	AFT_CONDEMNED		0x0100	/* Being torn down */

static void rdsv3_af_thr_worker(rdsv3_af_thr_t *ringp);
static cpu_t *rdsv3_af_thr_bind(rdsv3_af_thr_t *ringp, processorid_t cpuid);
static void rdsv3_af_thr_unbind(rdsv3_af_thr_t *ringp);

#ifdef	__cplusplus
}
#endif

#endif /* _RDSV3_AF_THR_IMPL_H */
