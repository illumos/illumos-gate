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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _PROC_X86UTIL_H
#define	_PROC_X86UTIL_H

#include <mdb/mdb.h>

#include <procfs.h>
#include <sys/frame.h>
#include <sys/ucontext.h>
#include <sys/fp.h>
#include <ieeefp.h>

/*
 * Common routines used for x86 proc targets.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	XMM,
	YMM,
	ZMM
} x86_vector_type_t;

typedef struct x86_xregs_info {
	x86_vector_type_t xri_type;
	const prxregset_xcr_t *xri_xcr;
	const prxregset_xsave_t *xri_xsave;
	const prxregset_ymm_t *xri_ymm;
	const prxregset_opmask_t *xri_opmask;
	const prxregset_zmm_t *xri_zmm;
	const prxregset_hi_zmm_t *xri_hi_zmm;
} x86_xregs_info_t;

extern int x86_pt_fpregs_common(uintptr_t, uint_t, int, fpregset_t *);
extern void x86_pt_fpregs_sse_ctl(uint32_t, uint32_t, char *, size_t);

/*
 * Utility functions for printing x87 / SSE state.
 */
extern const char *fpcw2str(uint32_t, char *, size_t);
extern const char *fpsw2str(uint32_t, char *, size_t);
extern const char *fpmxcsr2str(uint32_t, char *, size_t);
extern const char *fptag2str(uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _PROC_X86UTIL_H */
