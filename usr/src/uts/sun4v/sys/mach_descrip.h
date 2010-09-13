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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MACH_DESCRIP_H
#define	_MACH_DESCRIP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/kstat.h>
#include <sys/ksynch.h>
#include <sys/mdesc.h>

/*
 * MD memory operations (memops) are of two types:
 * buf:
 * 	Buffer allocator routines used to allocate the MD buffer.
 *	Allocator must support an alignment argument.
 *
 * meta:
 *	Meta allocator routines to allocate meta data strcutures.
 *	These allocations are small and don't have alignment
 *	requirements. Examples, md_t handles and the machine_descrip_t
 *	structure.
 */
typedef struct machine_descrip_memops {
	void 		*(*buf_allocp)(size_t size, size_t align);
	void 		(*buf_freep)(void *, size_t size);
	void 		*(*meta_allocp)(size_t size);
	void 		(*meta_freep)(void *, size_t size);
} machine_descrip_memops_t;

/*
 * Common structure/list between kernel and mdesc driver enabling
 * the current machine description to be retrieved or updated.
 *
 * Locks:
 * The current global MD is protected by the curr_mach_descrip_lock.
 * Each Machine description has a lock to synchronize its ref count.
 * The Obsolete MD list is protected by the obs_list_lock.
 */
typedef struct machine_descrip_s {
	uint64_t	gen;		/* Generation number for MD */
	kmutex_t	lock;		/* synchronize access to MD */
	void		*va;		/* virtual address */
	uint64_t	size;		/* size of MD */
	uint64_t	space;		/* space allocated for MD */
	int		refcnt;		/* MD ref count */
	struct machine_descrip_s *next;	/* Next MD in list */
	machine_descrip_memops_t *memops; /* Memory operations for MD */
} machine_descrip_t;

/*
 * Utility wrappers to get/fini a handle to the current MD.
 */
extern md_t *md_get_handle(void);
extern int md_fini_handle(md_t *);
extern caddr_t md_get_md_raw(md_t *);
extern int md_alloc_scan_dag(md_t *, mde_cookie_t, char *, char *,
	    mde_cookie_t **);
extern void md_free_scan_dag(md_t *, mde_cookie_t **);
extern uint64_t md_get_current_gen(void);

#ifdef __cplusplus
}
#endif

#endif	/* _MACH_DESCRIP_H */
