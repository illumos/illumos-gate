/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PMEM_H
#define	_SYS_PMEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PMEM - Direct mapping physical memory pages to userland process
 *
 * Provide consolidation private functions used for directly (w/o occupying
 * kernel virtual address space) allocating and exporting physical memory pages
 * to userland.
 */

/*
 * Flags to pass to pmem_alloc
 */
#define	PMEM_SLEEP	0x1
#define	PMEM_NOSLEEP	0x2

/*
 * Called by driver devmap routine to pass physical memory mapping info to
 * seg_dev framework, used only for physical memory allocated from
 * devmap_pmem_alloc().
 */
int	devmap_pmem_setup(devmap_cookie_t, dev_info_t *dip,
    struct devmap_callback_ctl *, devmap_pmem_cookie_t, offset_t,
    size_t, uint_t, uint_t, ddi_device_acc_attr_t *);

/*
 * Replace existing mapping using a new cookie, mainly gets called when doing
 * fork(). Should be called in pertinent devmap_dup(9E).
 */
int	devmap_pmem_remap(devmap_cookie_t, dev_info_t *dip,
    devmap_pmem_cookie_t, offset_t, size_t, uint_t, uint_t,
    ddi_device_acc_attr_t *);

/*
 * Directly (i.e., without occupying kernel virtual address space) allocate
 * 'npages' physical memory pages for exporting to user land. The allocated
 * page_t pointer will be recorded in cookie.
 */
int	devmap_pmem_alloc(size_t, uint_t, devmap_pmem_cookie_t *);

void	devmap_pmem_free(devmap_pmem_cookie_t);

int	devmap_pmem_getpfns(devmap_pmem_cookie_t, uint_t, pgcnt_t, pfn_t *);

void    pmem_init();

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PMEM_H */
