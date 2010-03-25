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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SYS_MEMLIST_PLAT_H
#define	_SYS_MEMLIST_PLAT_H

/*
 * Boot time configuration information objects
 */

#include <sys/types.h>
#include <sys/memlist.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int check_boot_version(int);
extern void copy_memlist_filter(struct memlist *, struct memlist **,
    void (*filter)(uint64_t *, uint64_t *));
extern void installed_top_size(struct memlist *, pfn_t *, pgcnt_t *);
extern void installed_top_size_ex(struct memlist *, pfn_t *, pgcnt_t *, int *);
extern void phys_install_has_changed(void);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_MEMLIST_PLAT_H */
