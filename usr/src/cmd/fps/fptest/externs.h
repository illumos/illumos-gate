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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EXTERNS_H
#define	_EXTERNS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <fps_ereport.h>

/* Register handling routines */
extern uint32_t register_test(int, uint32_t);
extern uint64_t get_gsr(void);
extern uint64_t move_regs_dp(uint64_t);
extern uint64_t register_test_dp(int, uint64_t);
extern unsigned long get_fsr(void);
extern unsigned long move_regs(unsigned long);
extern void init_regs(uint32_t);
extern void init_regs_dp(uint64_t);
extern void set_fsr(unsigned long);
extern void set_gsr(uint64_t);

/* FP arithmetic routines */
extern uint64_t absolute_value_dp(uint64_t);
extern uint64_t add_dp(uint64_t, uint64_t);
extern uint64_t div_dp(uint64_t, uint64_t);
extern uint64_t fcmps_fcc(unsigned int, unsigned int,
				    unsigned int);
extern uint64_t fcmpd_fcc(uint64_t, uint64_t, unsigned int);
extern uint64_t mult_dp(uint64_t, uint64_t);
extern uint64_t negate_value_dp(uint64_t);
extern uint64_t sqrt_sp(unsigned long);
extern uint64_t sqrt_dp(uint64_t);
extern uint64_t sub_dp(uint64_t, uint64_t);
extern uint64_t wadd_sp(unsigned long, unsigned long);
extern uint64_t wadd_dp(unsigned long, unsigned long,
				    unsigned long, unsigned long);
extern uint64_t wdiv_sp(unsigned long, unsigned long);
extern uint64_t wdiv_dp(unsigned long, unsigned long,
				    unsigned long, unsigned long);
extern uint64_t wmult_sp(unsigned long, unsigned long);
extern uint64_t wmult_dp(unsigned long, unsigned long,
				    unsigned long, unsigned long);
extern uint64_t wsqrt_sp(unsigned long);
extern uint64_t wsqrt_dp(uint64_t);
extern unsigned long absolute_value_sp(unsigned long);
extern unsigned long add_sp(unsigned long, unsigned long);
extern unsigned long div_sp(unsigned long, unsigned long);
extern unsigned long mult_sp(unsigned long, unsigned long);
extern unsigned long negate_value_sp(unsigned long);
extern unsigned long sub_sp(unsigned long, unsigned long);

/* Compare routines */
extern unsigned long cmp_d_ex(unsigned long, unsigned long);
extern unsigned long cmp_s_ex(unsigned long, unsigned long);

/* Conversion routines */
extern int fsr_test(struct fps_test_ereport *report);
extern int restore_signals();
extern int winitfp(void);
extern uint64_t convert_sp_dp(unsigned long);
extern uint64_t float_long_d(uint64_t);
extern uint64_t float_long_s(unsigned long);
extern uint64_t long_float_d(uint64_t);
extern uint64_t timing_add_dp(void);
extern uint64_t timing_mult_dp(void);
extern unsigned long branches(unsigned long, unsigned long, unsigned long);
extern unsigned long chain_dp(int);
extern unsigned long chain_sp(int);
extern unsigned long convert_dp_sp(uint64_t);
extern unsigned long datap_add(unsigned long);
extern unsigned long datap_add_dp(unsigned long, unsigned long);
extern unsigned long datap_mult(unsigned long);
extern unsigned long datap_mult_dp(unsigned long, unsigned long);
extern unsigned long float_int_d(uint64_t);
extern unsigned long float_int_s(unsigned long);
extern unsigned long int_float_d(int);
extern unsigned long int_float_s(int);
extern unsigned long long_float_s(uint64_t);
extern unsigned long timing_add_sp(void);
extern unsigned long timing_mult_sp(void);
extern void read_fpreg(unsigned int *, int);
extern void read_fpreg_dp(unsigned long *, int);
extern void write_fpreg(unsigned int *, int);

/* verbose messaging */
extern void fps_msg(int msg_enable, const char *fmt, ...);

/* benchmarks */
extern int align_data(int loop, int unit,
			    struct fps_test_ereport *report);
extern int fpu_fdivd(int rloop,
			    struct fps_test_ereport *report);
extern int fpu_fmuld(int rloop,
			    struct fps_test_ereport *report);
extern int fpu_fmulx(int rloop,
			    struct fps_test_ereport *report);
extern int vis_test(int unit, struct fps_test_ereport *report);

/* cbbcopy */
extern int cbbcopy(struct fps_test_ereport *report);

/* cheetah sdc */
extern int cheetah_sdc_test(int limit,
			    struct fps_test_ereport *report);

/* fpu sys diag */
extern int fpu_sysdiag(struct fps_test_ereport *report);

/* linpack */
extern int dlinpack_test(int, int, struct fps_test_ereport *report,
			    int fps_verbose_msg);
extern int slinpack_test(int, int, struct fps_test_ereport *report,
			    int fps_verbose_msg);


/* Global traps */
extern uint_t trap_flag;
extern uint64_t fsr_at_trap;

#ifdef __cplusplus
}
#endif

#endif /* _EXTERNS_H */
