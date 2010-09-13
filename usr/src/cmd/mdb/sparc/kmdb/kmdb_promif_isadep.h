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

#ifndef _KMDB_PROMIF_ISADEP_H
#define	_KMDB_PROMIF_ISADEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/obpdefs.h>
#include <sys/termios.h>

#include <mdb/mdb_target.h>
#include <kmdb/kmdb_promif.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void kmdb_prom_walk_cpus(int (*)(pnode_t, void *, void *),
    void *, void *);
extern void kmdb_prom_enter_mon(void);
extern void kmdb_prom_exit_to_mon(void);
extern void kmdb_prom_interpret(const char *);
extern int kmdb_prom_getprop(pnode_t, char *, caddr_t);

#ifndef	sun4v
extern pnode_t kmdb_prom_getcpu_propnode(pnode_t);
extern void kmdb_prom_preserve_kctx_init(void);
#endif	/* sun4v */

/* private to promif */
extern int kmdb_prom_translate_virt(uintptr_t, physaddr_t *);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_PROMIF_ISADEP_H */
