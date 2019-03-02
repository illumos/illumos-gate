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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#ifndef _HYPERV_ILLUMOS_H
#define	_HYPERV_ILLUMOS_H

#include <sys/mutex.h>
#include <sys/semaphore.h>
#include <sys/queue.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>


#ifdef  __cplusplus
extern "C" {
#endif

#include <sys/ccompile.h>
#include <sys/param.h>
#include <sys/dditypes.h>

#define	PAGE_SIZE	PAGESIZE
#define	PAGE_SHIFT	PAGESHIFT
/*
 * hyperv driver's soft state structure
 */
typedef struct hyperv_state {
	dev_info_t	*dip;	/* dev_info */
} hv_state_t;


#define	CACHE_LINE_SIZE	64

/*
 * GNU C version 2.96 adds explicit branch prediction so that
 * the CPU back-end can hint the processor and also so that
 * code blocks can be reordered such that the predicted path
 * sees a more linear flow, thus improving cache behavior, etc.
 *
 * The following two macros provide us with a way to utilize this
 * compiler feature.  Use __predict_true() if you expect the expression
 * to evaluate to true, and __predict_false() if you expect the
 * expression to evaluate to false.
 *
 * A few notes about usage:
 *
 *	* Generally, __predict_false() error condition checks (unless
 *	  you have some _strong_ reason to do otherwise, in which case
 *	  document it), and/or __predict_true() `no-error' condition
 *	  checks, assuming you want to optimize for the no-error case.
 *
 *	* Other than that, if you don't know the likelihood of a test
 *	  succeeding from empirical or other `hard' evidence, don't
 *	  make predictions.
 *
 *	* These are meant to be used in places that are run `a lot'.
 *	  It is wasteful to make predictions in code that is run
 *	  seldomly (e.g. at subsystem initialization time) as the
 *	  basic block reordering that this affects can often generate
 *	  larger code.
 */
#if defined(__GNUC__)
#define	__predict_true(exp)	__builtin_expect((exp), 1)
#define	__predict_false(exp)	__builtin_expect((exp), 0)
#define	__compiler_membar()	__asm__ __volatile__(" " : : : "memory")
#else
#define	__predict_true(exp)	(exp)
#define	__predict_false(exp)	(exp)
#define	__compiler_membar()
#endif

#ifdef  __cplusplus
}
#endif

#endif	/* _HYPERV_ILLUMOS_H */
