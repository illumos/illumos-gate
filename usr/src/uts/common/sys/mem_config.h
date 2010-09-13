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

#ifndef	_SYS_MEM_CONFIG_H
#define	_SYS_MEM_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Memory add/delete interfaces.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Memory add/delete client interface.
 */

extern int kphysm_add_memory_dynamic(pfn_t base, pgcnt_t npgs);

typedef void *memhandle_t;

/*
 * Managed pages have associated page structures ('page_t's).
 * The difference between phys_pages and managed is accounted for by
 * boot time memory allocation for the kernel text and data, and also
 * for page structures.
 */
typedef struct {
	pgcnt_t	phys_pages;	/* total physical pages */
	pgcnt_t	managed;	/* providing this many managed pages */
	pgcnt_t	nonrelocatable;	/* of which this many non-relocatable */
	pfn_t	first_nonrelocatable;
	pfn_t	last_nonrelocatable;
} memquery_t;

typedef struct {
	pgcnt_t	phys_pages;	/* total physical pages */
	pgcnt_t	managed;	/* providing this many managed pages */
	pgcnt_t	collected; 	/* done when == managed */
} memdelstat_t;

extern int kphysm_del_gethandle(memhandle_t *);

extern int kphysm_del_span(memhandle_t, pfn_t base, pgcnt_t npgs);

extern int kphysm_del_span_query(pfn_t base, pgcnt_t npgs, memquery_t *);

extern int kphysm_del_start(memhandle_t,
	void (*complete)(void *, int error), void *arg);

extern int kphysm_del_release(memhandle_t);

extern int kphysm_del_cancel(memhandle_t);

extern int kphysm_del_status(memhandle_t, memdelstat_t *);

/*
 * Error returns.
 */

#define	KPHYSM_OK		0	/* Success */
#define	KPHYSM_ESPAN		1	/* Memory already in use (add) */
#define	KPHYSM_EFAULT		2	/* Memory access test failed (add) */
#define	KPHYSM_ERESOURCE	3	/* Some resource was not available */
#define	KPHYSM_ENOTSUP		4	/* Operation not supported */
#define	KPHYSM_ENOHANDLES	5	/* Cannot allocate any more handles */
#define	KPHYSM_ENONRELOC	6	/* Non-relocatable pages in span */
#define	KPHYSM_EHANDLE		7	/* Bad handle supplied */
#define	KPHYSM_EBUSY		8	/* Memory in span is being deleted */
#define	KPHYSM_ENOTVIABLE	9	/* VM viability test failed */
#define	KPHYSM_ESEQUENCE	10	/* Function called out of sequence */
#define	KPHYSM_ENOWORK		11	/* No pages to delete */
#define	KPHYSM_ECANCELLED	12	/* kphysm_del_cancel (for complete) */
#define	KPHYSM_EREFUSED		13	/* kphysm_pre_del fail (for complete) */
#define	KPHYSM_ENOTFINISHED	14	/* Thread not finished */
#define	KPHYSM_ENOTRUNNING	15	/* Thread not running */
#define	KPHYSM_EDUP		16	/* Memory span duplicate (delete) */

/*
 * Memory system change call-back interface.
 */

#define	KPHYSM_SETUP_VECTOR_VERSION	1
typedef struct {
	uint_t		version;
	void		(*post_add)(void *arg, pgcnt_t delta_pages);
	int		(*pre_del)(void *arg, pgcnt_t delta_pages);
	void		(*post_del)(void *arg, pgcnt_t delta_pages,
			    int cancelled);
} kphysm_setup_vector_t;

/*
 * The register function returns 0 if the vector/arg pair is recorded
 * successfully.
 * The error returns are:
 *	EEXIST	if the vector/arg pair is already registered.
 *	EINVAL	if the vector version is not supported.
 *	ENOMEM	if the registration could not be stored.
 *
 * A return of EEXIST should be considered a program logic error by
 * the caller.
 */
extern int kphysm_setup_func_register(kphysm_setup_vector_t *, void *arg);

extern void kphysm_setup_func_unregister(kphysm_setup_vector_t *, void *arg);


/*
 * Memory add/delete architecture (lower) interfaces.
 * These interfaces should not be used by drivers.
 */

extern int arch_kphysm_del_span_ok(pfn_t, pgcnt_t);
extern int arch_kphysm_relocate(pfn_t, pgcnt_t);
extern int arch_kphysm_del_supported(void);

extern int pfn_is_being_deleted(pfn_t);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MEM_CONFIG_H */
