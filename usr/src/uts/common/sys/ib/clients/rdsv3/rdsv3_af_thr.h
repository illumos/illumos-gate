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

#ifndef _RDSV3_AF_THR_H
#define	_RDSV3_AF_THR_H

/*
 * This file is only present in Solaris
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/callb.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/processor.h>

typedef struct rdsv3_af_grp_s rdsv3_af_grp_t;
typedef struct rdsv3_af_thr_s rdsv3_af_thr_t;
typedef void (*rdsv3_af_thr_drain_func_t)(void *);

void rdsv3_af_init(dev_info_t *dip);
/*
 * create flags.
 */
#define	SCQ_DEFAULT		0x0000
#define	SCQ_HCA_BIND_CPU	0x0001	/* bind hca to a cpu */
#define	SCQ_INTR_BIND_CPU	0x0002	/* bind soft cq to a cpu */
#define	SCQ_WRK_BIND_CPU	0x0004	/* bind worker to a cpu */

rdsv3_af_grp_t *rdsv3_af_grp_create(ibt_hca_hdl_t hca, uint64_t id);
void rdsv3_af_grp_destroy(rdsv3_af_grp_t *hcagp);
void rdsv3_af_grp_draw(rdsv3_af_grp_t *hcagp);
ibt_sched_hdl_t rdsv3_af_grp_get_sched(rdsv3_af_grp_t *hcagp);

rdsv3_af_thr_t *rdsv3_af_thr_create(rdsv3_af_thr_drain_func_t fn, void *data,
    uint_t flag, rdsv3_af_grp_t *hcagp);
rdsv3_af_thr_t *rdsv3_af_intr_thr_create(rdsv3_af_thr_drain_func_t fn,
    void *data, uint_t flag, rdsv3_af_grp_t *hcagp, ibt_cq_hdl_t ibt_cq_hdl);

void rdsv3_af_thr_destroy(rdsv3_af_thr_t *ringp);
void rdsv3_af_thr_fire(rdsv3_af_thr_t *ringp);

#ifdef	__cplusplus
}
#endif

#endif /* _RDSV3_AF_THR_H */
