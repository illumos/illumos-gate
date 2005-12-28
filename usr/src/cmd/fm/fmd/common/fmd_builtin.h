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

#ifndef	_FMD_BUILTIN_H
#define	_FMD_BUILTIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_module.h>
#include <fmd_api.h>

/*
 * fmd_builtin.h
 *
 * This header file provides prototypes for any built-in diagnosis engines and
 * agents that are compiled directly into fmd.  Prototypes for their init and
 * fini routines can be added here and corresponding linkage information to
 * these functions should be added to the table found in fmd_builtin.c.
 */

typedef struct fmd_builtin {
	const char *bltin_name;
	void (*bltin_init)(fmd_hdl_t *);
	void (*bltin_fini)(fmd_hdl_t *);
} fmd_builtin_t;

extern int fmd_builtin_loadall(fmd_modhash_t *);

extern void self_init(fmd_hdl_t *);	/* see fmd_self.c */
extern void self_fini(fmd_hdl_t *);	/* see fmd_self.c */

extern void sysev_init(fmd_hdl_t *);	/* see fmd_transport.c */
extern void sysev_fini(fmd_hdl_t *);	/* see fmd_transport.c */

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_BUILTIN_H */
