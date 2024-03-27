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
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _SIMD_H
#define	_SIMD_H

#if defined(__amd64__) || defined(__i386__)

#define	kfpu_initialize(tsk)	do {} while (0)
#define	kfpu_init()		(0)
#define	kfpu_fini()		do {} while (0)

#ifdef _KERNEL
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/kfpu.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/cpuvar.h>

static inline int
kfpu_allowed(void)
{
	extern int zfs_fpu_enabled;

	return (zfs_fpu_enabled != 0 ? 1 : 0);
}

static inline void
kfpu_begin(void)
{
	if (curthread->t_lwp != NULL && (curthread->t_procp->p_flag & SSYS)) {
		kernel_fpu_begin(NULL, KFPU_USE_LWP);
	} else {
		kpreempt_disable();
		kernel_fpu_begin(NULL, KFPU_NO_STATE);
	}
}

static inline void
kfpu_end(void)
{
	if (curthread->t_lwp != NULL && (curthread->t_procp->p_flag & SSYS)) {
		kernel_fpu_end(NULL, KFPU_USE_LWP);
	} else {
		kernel_fpu_end(NULL, KFPU_NO_STATE);
		kpreempt_enable();
	}
}

/*
 * Check if various vector instruction sets are available.
 */

static inline boolean_t
zfs_sse_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_SSE));
}

static inline boolean_t
zfs_sse2_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_SSE2));
}

static inline boolean_t
zfs_sse3_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_SSE3));
}

static inline boolean_t
zfs_ssse3_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_SSSE3));
}

static inline boolean_t
zfs_avx_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_AVX));
}

static inline boolean_t
zfs_avx2_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_AVX2));
}

static inline boolean_t
zfs_avx512f_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_AVX512F));
}

static inline boolean_t
zfs_avx512bw_available(void)
{
	return (is_x86_feature(x86_featureset, X86FSET_AVX512BW));
}

#else	/* ! _KERNEL */

#include <sys/auxv.h>
#include <sys/auxv_386.h>

#define	kfpu_allowed()		1
#define	kfpu_begin()		do {} while (0)
#define	kfpu_end()		do {} while (0)

/*
 * User-level check if various vector instruction sets are available.
 */

static inline boolean_t
zfs_sse_available(void)
{
	uint32_t u = 0;

	(void) getisax(&u, 1);
	return ((u & AV_386_SSE) != 0);
}

static inline boolean_t
zfs_sse2_available(void)
{
	uint32_t u = 0;

	(void) getisax(&u, 1);
	return ((u & AV_386_SSE2) != 0);
}

static inline boolean_t
zfs_sse3_available(void)
{
	uint32_t u = 0;

	(void) getisax(&u, 1);
	return ((u & AV_386_SSE3) != 0);
}

static inline boolean_t
zfs_ssse3_available(void)
{
	uint32_t u = 0;

	(void) getisax(&u, 1);
	return ((u & AV_386_SSSE3) != 0);
}

static inline boolean_t
zfs_avx_available(void)
{
	uint_t u = 0;

	(void) getisax(&u, 1);
	return ((u & AV_386_AVX) != 0);
}

static inline boolean_t
zfs_avx2_available(void)
{
	uint32_t u[2] = { 0 };

	(void) getisax((uint32_t *)&u, 2);
	return ((u[1] & AV_386_2_AVX2) != 0);
}

static inline boolean_t
zfs_avx512f_available(void)
{
	uint32_t u[2] = { 0 };

	(void) getisax((uint32_t *)&u, 2);
	return ((u[1] & AV_386_2_AVX512F) != 0);
}

static inline boolean_t
zfs_avx512bw_available(void)
{
	uint32_t u[2] = { 0 };

	(void) getisax((uint32_t *)&u, 2);
	return ((u[1] & AV_386_2_AVX512BW) != 0);
}

#endif	/* _KERNEL */


#else

/* Non-x86 CPUs currently always disallow kernel FPU support */
#define	kfpu_allowed()		0
#define	kfpu_initialize(tsk)	do {} while (0)
#define	kfpu_begin()		do {} while (0)
#define	kfpu_end()		do {} while (0)
#define	kfpu_init()		(0)
#define	kfpu_fini()		do {} while (0)
#endif

#endif /* _SIMD_H */
