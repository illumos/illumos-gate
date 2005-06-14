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
 * Copyright (c) 1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_IDTAB_H
#define	_IDTAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * We need to typedef idkey_t so it can safely deal with how pid_t, uid_t,
 * gid_t, and dev_t are defined in a 64-bit compilation environment and
 * avoid sign-extension problems.
 */

typedef unsigned long idkey_t;

typedef struct idtab {
	idkey_t *id_data;
	size_t id_nelems;
	size_t id_size;
} idtab_t;

extern void idtab_create(idtab_t *);
extern void idtab_destroy(idtab_t *);
extern void idtab_append(idtab_t *, idkey_t);
extern void idtab_sort(idtab_t *);
extern int idtab_search(idtab_t *, idkey_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _IDTAB_H */
