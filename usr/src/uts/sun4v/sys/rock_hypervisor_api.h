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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ROCK_HYPERVISOR_API_H
#define	_SYS_ROCK_HYPERVISOR_API_H

/*
 * sun4v rock Hypervisor API
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function numbers for performance counters
 */
#define	HV_RK_PERF_COUNT_INIT		0x108
#define	HV_RK_PERF_COUNT_RELEASE	0x109
#define	HV_RK_PERF_COUNT_SET		0x10A
#define	HV_RK_PERF_COUNT_GET		0x10B
#define	HV_RK_PERF_COUNT_START		0x10C
#define	HV_RK_PERF_COUNT_OVERFLOW	0x10D
#define	HV_RK_PERF_COUNT_STOP		0x10E

#define	HV_RK_PERF_SAMPLE_INIT		0x135
#define	HV_RK_PERF_SAMPLE_RELEASE	0x136
#define	HV_RK_PERF_SAMPLE_CONFIG	0x137
#define	HV_RK_PERF_SAMPLE_START		0x138
#define	HV_RK_PERF_SAMPLE_PENDING	0x139
#define	HV_RK_PERF_SAMPLE_STOP		0x13A

#define	HV_RK_PERF_SRC_STRAND		0x1	/* Local Strand */
#define	HV_RK_PERF_SRC_STRAND_M		0x2	/* Multiple Strands */
#define	HV_RK_PERF_SRC_SIU		0x4	/* L2 txn source */
#define	HV_RK_PERF_SRC_MMU		0x8	/* L2 txn source */
#define	HV_RK_PERF_SRC_MASK		0xF

#define	ROCK_HSVC_MAJOR		1
#define	ROCK_HSVC_MINOR		0

#ifndef	_ASM

/* Performance Counter API */
extern uint64_t hv_rk_perf_count_init(uint64_t counter);
extern uint64_t hv_rk_perf_count_release(uint64_t counter);
extern uint64_t hv_rk_perf_count_set(uint64_t counter, uint64_t value);
extern uint64_t hv_rk_perf_count_get(uint64_t counter, uint64_t *value);
extern uint64_t hv_rk_perf_count_start(uint64_t counter, uint64_t value);
extern uint64_t hv_rk_perf_count_overflow(uint64_t counter, uint64_t *ovf_cnt);
extern uint64_t hv_rk_perf_count_stop(uint64_t counter);

/* Performance Sampler API */
extern uint64_t hv_rk_perf_sample_init(uint64_t sampler, uint64_t ringbuf_pa);
extern uint64_t hv_rk_perf_sample_release(uint64_t sampler);
extern uint64_t hv_rk_perf_sample_config(uint64_t sampler, uint64_t reg_va,
							uint64_t reg_value);
extern uint64_t hv_rk_perf_sample_start(uint64_t sampler, uint64_t freq,
					uint64_t list_size, uint64_t valist_pa);
extern uint64_t hv_rk_perf_sample_pending(uint64_t sampler, uint64_t *pend_cnt);
extern uint64_t hv_rk_perf_sample_stop(uint64_t counter);
#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ROCK_HYPERVISOR_API_H */
