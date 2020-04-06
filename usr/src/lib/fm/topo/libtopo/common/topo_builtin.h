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
/*
 * Copyright 2020 Joyent, Inc.
 */

#ifndef	_TOPO_BUILTIN_H
#define	_TOPO_BUILTIN_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <topo_tree.h>
#include <topo_module.h>
#include <topo_digraph.h>

#define	TOPO_BLTIN_TYPE_TREE		1
#define	TOPO_BLTIN_TYPE_DIGRAPH		2
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
	topo_version_t bltin_version;
	int (*bltin_init)(topo_mod_t *, topo_version_t version);
	void (*bltin_fini)(topo_mod_t *);
	uint_t bltin_type;
} topo_builtin_t;

extern int topo_builtin_create(topo_hdl_t *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_BUILTIN_H */
