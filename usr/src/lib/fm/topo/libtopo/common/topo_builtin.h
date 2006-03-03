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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TOPO_BUILTIN_H
#define	_TOPO_BUILTIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <topo_tree.h>
#include <topo_module.h>

/*
 * topo_builtin.h
 *
 * This header file provides prototypes for any built-in scheme enumerators
 * that are compiled directly into topo.  Prototypes for their init and
 * fini routines can be added here and corresponding linkage information to
 * these functions should be added to the table found in topo_builtin.c.
 */

typedef struct topo_builtin {
	const char *bltin_name;
	void (*bltin_init)(topo_mod_t *);
	void (*bltin_fini)(topo_mod_t *);
} topo_builtin_t;

extern int topo_builtin_create(topo_hdl_t *, const char *);

extern void hc_init(topo_mod_t *);	/* see hc.c */
extern void hc_fini(topo_mod_t *);	/* see hc.c */
extern void cpu_init(topo_mod_t *);	/* see cpu.c */
extern void cpu_fini(topo_mod_t *);	/* see cpu.c */
extern void dev_init(topo_mod_t *);	/* see dev.c */
extern void dev_fini(topo_mod_t *);	/* see dev.c */
extern void mem_init(topo_mod_t *);	/* see mem.c */
extern void mem_fini(topo_mod_t *);	/* see mem.c */
extern void mod_init(topo_mod_t *);	/* see mod.c */
extern void mod_fini(topo_mod_t *);	/* see mod.c */
extern void pkg_init(topo_mod_t *);	/* see pkg.c */
extern void pkg_fini(topo_mod_t *);	/* see pkg.c */

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_BUILTIN_H */
