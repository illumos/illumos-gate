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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_XPV_SUPPORT_H
#define	_SYS_XPV_SUPPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#define	__XEN_INTERFACE_VERSION__	__XEN_LATEST_INTERFACE_VERSION__

#if !defined(_ASM)

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/dditypes.h>
#include <sys/xpv_impl.h>
#include <sys/xen_mmu.h>

#define	IPL_DEBUG	15	/* domain debug interrupt */
#define	IPL_CONS	9
#define	IPL_VIF		6
#define	IPL_VBD		5
#define	IPL_EVTCHN	1

#define	INVALID_EVTCHN 0

typedef uint_t (*ec_handler_fcn_t)();

extern int ec_init(void);
extern void ec_fini();
extern void ec_bind_evtchn_to_handler(int, pri_t, ec_handler_fcn_t, void *);
extern void ec_unbind_evtchn(int);
extern void ec_notify_via_evtchn(uint_t);
extern void hypervisor_mask_event(uint_t);
extern void hypervisor_unmask_event(uint_t);

extern void xen_hvm_init(void);
extern int xen_bind_interdomain(int, int, int *);
extern int xen_alloc_unbound_evtchn(int, int *);
extern int xen_xlate_errcode(int error);
extern void *xen_alloc_pages(pgcnt_t cnt);
extern void kbm_map_ma(maddr_t ma, uintptr_t va, uint_t level);

/*
 * Stub functions to allow the FE drivers to build without littering them
 * with #ifdefs
 */
extern void balloon_drv_added(int64_t);
extern long balloon_free_pages(uint_t, mfn_t *, caddr_t, pfn_t *);
extern void xen_release_pfn(pfn_t);
extern void reassign_pfn(pfn_t, mfn_t);

extern shared_info_t *HYPERVISOR_shared_info;
extern pfn_t xen_shared_info_frame;

/*
 * Argument to xpv_feature(). This function will return -1 if a feature
 * is not available, 1 if a boolean feature is available, and a value >= 0
 * if a numeric value is requested.
 */
#define	XPVF_BITS		0	/* numeric (32 or 64) */
#define	XPVF_VERSION_MAJOR	1	/* numeric */
#define	XPVF_VERSION_MINOR	2	/* numeric */
#define	XPVF_HYPERCALLS		3	/* boolean (hypercalls work) */
#define	XPVF_SHARED_INFO	4	/* boolean (shared info is valid) */
#define	XPVF_TLB_FLUSH		5	/* boolean (tlb flush call present) */

extern int xpv_feature(int);

#define	IN_XPV_PANIC()	(__lintzero)

#ifdef __cplusplus
}
#endif

#endif	/* __ASM */
#endif	/* _SYS_XPV_SUPPORT_H */
