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

#ifndef	_VM_HMENT_H
#define	_VM_HMENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


struct hment;
typedef struct hment hment_t;

#if defined(_KERNEL)

/*
 * Remove a page mapping, finds the matching mapping and unlinks it from
 * the page_t. If it returns a non-NULL pointer, the pointer must be
 * freed via hment_free() after doing x86_hm_exit().
 */
extern hment_t *hment_remove(page_t *, htable_t *ht, uint_t entry);
extern void hment_free(hment_t *);

/*
 * Iterator to walk through all mappings of a page.
 */
extern hment_t *hment_walk(page_t *, htable_t **, uint_t *, hment_t *);

/*
 * Prepare a page for a new mapping
 */
extern hment_t *hment_prepare(htable_t *ht, uint_t entry, page_t *);

/*
 * Add a mapping to a page's mapping list
 */
extern void hment_assign(htable_t *ht, uint_t entry, page_t *, hment_t *);

/*
 * initialize hment data structures
 */
extern void hment_init(void);

/*
 * lock/unlock a page_t's mapping list/pte entry
 */
extern void x86_hm_enter(page_t *);
extern void x86_hm_exit(page_t *);
extern int x86_hm_held(page_t *pp);

/*
 * Called to allocate additional hments for reserve.
 *
 * The hment_reserve_count is exported for use by htable_hment_steal()
 */
extern void hment_reserve(uint_t);
extern uint_t hment_reserve_count;

/*
 * Used to readjust the hment reserve after the reserve list has been used.
 * Also called after boot to release left over boot reserves.
 */
extern void hment_adjust_reserve(void);

/*
 * Return the number of mappings of a page_t
 */
extern uint_t hment_mapcnt(page_t *);

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HMENT_H */
