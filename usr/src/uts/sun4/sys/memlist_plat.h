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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MEMLIST_PLAT_H
#define	_SYS_MEMLIST_PLAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Boot time configuration information objects
 */

#include <sys/types.h>
#include <sys/memlist.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int check_boot_version(int);
extern int check_memexp(struct memlist *, uint_t);
extern void copy_memlist(u_longlong_t *, size_t, struct memlist **);
extern int copy_physavail(u_longlong_t *, size_t, struct memlist **,
    uint_t, uint_t);
extern void size_physavail(u_longlong_t *physavail, size_t size,
    pgcnt_t *npages, int *memblocks);
extern pgcnt_t size_virtalloc(u_longlong_t *avail, size_t size);
extern void installed_top_size_memlist_array(u_longlong_t *, size_t, pfn_t *,
    pgcnt_t *);
extern void installed_top_size(struct memlist *, pfn_t *, pgcnt_t *);
extern void fix_prom_pages(struct memlist *, struct memlist *);
extern void copy_boot_memlists(u_longlong_t **physinstalled,
    size_t *physinstalled_len, u_longlong_t **physavail, size_t *physavail_len,
    u_longlong_t **virtavail, size_t *virtavail_len);
extern void phys_install_has_changed(void);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_MEMLIST_PLAT_H */
