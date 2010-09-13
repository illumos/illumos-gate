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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_POOL_PSET_H
#define	_SYS_POOL_PSET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cpupart.h>
#include <sys/procset.h>
#include <sys/nvpair.h>
#include <sys/exacct.h>
#include <sys/time.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

struct zone;

typedef struct pool_pset {
	psetid_t		pset_id;	/* pset ID */
	uint_t			pset_npools;	/* # of pools we belong to */
	list_node_t		pset_link;	/* link to next/prev pset */
	nvlist_t		*pset_props;	/* pset properties */
} pool_pset_t;

extern pool_pset_t *pool_pset_default;		/* default pset */
extern hrtime_t pool_pset_mod;			/* pset modification time */
extern hrtime_t pool_cpu_mod;			/* cpu modification time */

extern void pool_pset_init(void);
extern int pool_pset_enable(void);
extern int pool_pset_disable(void);
extern int pool_pset_create(psetid_t *);
extern int pool_pset_destroy(psetid_t);
extern int pool_pset_assoc(poolid_t, psetid_t);
extern void pool_pset_bind(proc_t *, psetid_t, void *, void *);
extern int pool_pset_xtransfer(id_t, id_t, size_t, id_t *);
extern int pool_pset_proprm(psetid_t, char *);
extern int pool_pset_propput(psetid_t, nvpair_t *);
extern int pool_pset_propget(psetid_t, char *, nvlist_t *);
extern int pool_cpu_proprm(processorid_t, char *);
extern int pool_cpu_propput(processorid_t, nvpair_t *);
extern int pool_cpu_propget(processorid_t, char *, nvlist_t *);
extern int pool_pset_pack(ea_object_t *);

extern int pset_bind_start(struct proc **, struct pool *);
extern void pset_bind_abort(struct proc **, struct pool *);
extern void pset_bind_finish(void);

extern boolean_t pool_pset_enabled(void);

extern void pool_pset_visibility_add(psetid_t, struct zone *);
extern void pool_pset_visibility_remove(psetid_t, struct zone *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_POOL_PSET_H */
