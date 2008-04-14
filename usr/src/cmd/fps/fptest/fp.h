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

#ifndef _FP_H
#define	_FP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <libintl.h>
#include <sys/fsr.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Co-Processor Types */

#define	FABS		30	/* FABS */
#define	INVALID		-1	/* Invalid device code */
#define	MC68881		20	/* Motorola family	68881 */
#define	MEIKO		100	/* Meiko LSIL L64804 */
#define	NONE		111	/* No FPU installed */
#define	SUNRAY_FPC	40	/* Sunray - uses the TI8847 */
#define	TI8847		10	/* TI family 8847 */
#define	WEITEK		0	/* Weitek family */
#define	WTL3170		11	/* Weitek WTL3170/2 */

#define	CPU_TYPE_SHIFT	24	/* bits to shift to get the cpu type */
#define	CPU_TYPE_MASK	0xff	/* 1 byte indicates cpu type	 */

/* True and False */

#ifndef FALSE
#define	FALSE 0
#endif

#ifndef TRUE
#define	TRUE 1
#endif

/* Return Codes */

#define	FPU_UNSUPPORT		-1
#define	FPU_OK			0
#define	FPU_FOROFFLINE		1
#define	FPU_BIND_FAIL		2
#define	FPU_INVALID_ARG		3
#define	FPU_SIG_SEGV		4
#define	FPU_SIG_BUS		5
#define	FPU_SIG_FPE		6
#define	FPU_SIG_ILL		7
#define	FPU_SYSCALL_TRYAGAIN	8
#define	FPU_SYSCALL_FAIL	9
#define	FPU_EREPORT_INCOM	10
#define	FPU_EREPORT_FAIL	11

/* Math constants */

#define	DPMARGIN		0.000000000000001
#define	MARGIN			0.0000000010
#define	pi			3.141592654
#define	SPMARGIN		0.0000001

#define	denorm_sp		0x00000001
#define	denorm_lsw		0x00000001
#define	denorm_msw		0x00000000

#define	half_sp			0x3f000000
#define	half_lsw		0x00000000
#define	half_msw		0x3fe00000

#define	maxn_lsw		0xffffffff
#define	maxn_msw		0x7fefffff
#define	maxn_sp			0x7f7fffff

#define	nan_dp			0x7ff7ffffffffffff
#define	nan_sp			0x7fbfffff
#define	nan_lsw			0xffffffff
#define	nan_msw			0x7ff7ffff

#define	one_sp			0x3f800000
#define	one_lsw			0x00000000
#define	one_msw			0x3ff00000

#define	two_sp			0x40000000
#define	two_lsw			0x00000000
#define	two_msw			0x40000000

#define	zero_sp			0x00000000
#define	zero_lsw		0x00000000
#define	zero_msw		0x00000000

/* -1 */

#define	m_one_sp		0xbf800000
#define	m_one_lsw		0x00000000
#define	m_one_msw		0xbff00000

#define	pi_dp			0x400921fb54442d18UL
#define	pi_lsw			0x54442d18
#define	pi_msw			0x400921fb
#define	pi_sp			0x40490fdb

#define	pi_4_sp			0x3f490fdb
#define	pi_4_lsw		0x54442d18
#define	pi_4_msw		0x3fe921fb

/* +infinity */

#define	p_inf_lsw		0x00000000
#define	p_inf_msw		0x7ff00000
#define	p_inf_sp		0x7f800000

/* -infinity */

#define	n_inf_lsw		0x00000000
#define	n_inf_msw		0xfff00000
#define	n_inf_sp		0xff800000


/* pow(2, -126). Smallest SP normalized number */
#define	minn_sp			0x00800000

/* pow(2, -1022). Smallest DP normalized number */
#define	minn_lsw		0x00000000
#define	minn_msw		0x00100000

#define	min1_lsw		0x00010001
#define	min1_msw		0x00100001
#define	min1_sp			0x00800001

#define	maxd_lsw		0xffffffff
#define	maxd_msw		0x000fffff
#define	maxd_sp			0x007fffff

#define	maxm_lsw		0x55554000
#define	maxm_msw		0x7fd55555
#define	maxm_sp			0x7eaaaa00

#define	nn_lsw			0x00000000
#define	nn_msw			0x7ff00080
#define	nn_sp			0x7f800400
#define	nocare			0

/* FP operations */

#define	op_add_sp		1
#define	op_add_dp		2
#define	op_div_sp		3
#define	op_div_dp		4
#define	op_div_dp_c2sp		5 /* After DP division, convert to SP */
#define	op_fxtos		6
#define	op_sub_sp		7
#define	op_sub_dp		8
#define	op_mul_sp		9
#define	op_mul_dp		10
#define	op_fstod		11
#define	op_fdtos		12
#define	op_fsqrts		13
#define	op_fsqrtd		14

struct testws {

	unsigned long		a_msw;
	unsigned long		a_lsw;
	unsigned long		b_msw;
	unsigned long		b_lsw;
	unsigned long		instr;
	unsigned long		fsr_tem0_ieee754_exc;
	unsigned long		fsr_tem1_ieee754_exc;
	unsigned long		ecode;
};

/* The values of cexc and aexc when FSR.TEM = 0 */
#define	FSR_TEM0_NX		(FSR_CEXC_NX | FSR_AEXC_NX)
#define	FSR_TEM0_DZ		(FSR_CEXC_DZ | FSR_AEXC_DZ)
#define	FSR_TEM0_UF		(FSR_CEXC_UF | FSR_AEXC_UF)
#define	FSR_TEM0_OF		(FSR_CEXC_OF | FSR_AEXC_OF)
#define	FSR_TEM0_NV		(FSR_CEXC_NV | FSR_AEXC_NV)

/* When FSR.TEM=1, the FSR.aexc field will be untouched */
#define	FSR_TEM1_NX		FSR_CEXC_NX
#define	FSR_TEM1_DZ		FSR_CEXC_DZ
#define	FSR_TEM1_UF		FSR_CEXC_UF
#define	FSR_TEM1_OF		FSR_CEXC_OF
#define	FSR_TEM1_NV		FSR_CEXC_NV

/*
 * To enable/disable TEM bits in FSR use the following flags Steps: 1.
 * unsigned long val; 2. val=get_fsr(); 3-1. val = val | FSR_ENABLE_TEM_NV
 * (for enabling) 3-2. val = val & FSR_DISABLE_TEM_NV (for disabling) 4.
 * set_fsr(val);
 */

#define	FSR_ENABLE_TEM_NX	0x800000
#define	FSR_ENABLE_TEM_DZ	0x1000000
#define	FSR_ENABLE_TEM_UF	0x2000000
#define	FSR_ENABLE_TEM_OF	0x4000000
#define	FSR_ENABLE_TEM_NV	0x8000000
#define	FSR_ENABLE_TEM		0xF800000

#define	FSR_DISABLE_TEM_NX	0xFFFFFFFFFF7FFFFF
#define	FSR_DISABLE_TEM_DZ	0xFFFFFFFFFEFFFFFF
#define	FSR_DISABLE_TEM_UF	0xFFFFFFFFFDFFFFFF
#define	FSR_DISABLE_TEM_OF	0xFFFFFFFFFBFFFFFF
#define	FSR_DISABLE_TEM_NV	0xFFFFFFFFF7FFFFFF
#define	FSR_DISABLE_TEM		0xFFFFFFFFF07FFFFF


/*
 * There is no TEM1 equivalent for these. That is because if
 * trap is enabled, the NX bit will not be set. See Section
 * 5.1.7.9 "FSR_current_exception (cexc)" in the SPARC V9
 * Architecture Manual
 */

#define	FSR_TEM0_UF_NX		(FSR_TEM0_UF | FSR_TEM0_NX)
#define	FSR_TEM0_OF_NX		(FSR_TEM0_OF | FSR_TEM0_NX)

#define	GSR_IM_ZERO		0xFFFFFFFFF7FFFFFF	/* GSR.IM = 0 */

/* Values for 'ecode' of 'struct testws' */

#define	E_NX			0
#define	E_DZ			1
#define	E_UF			2
#define	E_OF			3
#define	E_NV			4
#define	E_UF_NX			5
#define	E_OF_NX			6

#define	SIGN_FLAG_SP		0x80000000
#define	SIGN_FLAG_DP		0x8000000000000000

#define	ZERO_SP			0x00000000
#define	ZERO_DP			0x0000000000000000
#define	PLUS_ZERO_SP		0x00000000
#define	MINUS_ZERO_SP		0x80000000
#define	PLUS_ZERO_DP		0x0000000000000000
#define	MINUS_ZERO_DP		0x8000000000000000
#define	PLUS_INF_SP		0x7F800000
#define	MINUS_INF_SP		0xFF800000
#define	PLUS_INF_DP		0x7FF0000000000000
#define	MINUS_INF_DP		0xFFF0000000000000

#define	ALLZEROES_DP		0x0000000000000000UL
#define	ALLZEROES_SP		0x00000000U
#define	ALLONES_DP		0xFFFFFFFFFFFFFFFFUL
#define	ALLONES_SP		0xFFFFFFFFU

#define	TRAP_SOLICITED		1
#define	TRAP_UNSOLICITED	2

#ifdef __cplusplus
}
#endif

#endif /* _FP_H */
