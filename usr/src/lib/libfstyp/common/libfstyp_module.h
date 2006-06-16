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

#ifndef	_LIBFSTYP_MODULE_H
#define	_LIBFSTYP_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * libfstyp: module interface
 */
#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/types.h>
#include <libnvpair.h>
#include <libfstyp.h>

typedef struct fstyp_mod_handle *fstyp_mod_handle_t;

/*
 * Modules are must to export these functions.
 * fstyp_mod_dump() is optional.
 */
int fstyp_mod_init(int fd, off64_t offset, fstyp_mod_handle_t *handle);
void fstyp_mod_fini(fstyp_mod_handle_t handle);
int fstyp_mod_ident(fstyp_mod_handle_t handle);
int fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attr);
int fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr);

#ifdef __cplusplus
}
#endif

#endif /* _LIBFSTYP_MODULE_H */
