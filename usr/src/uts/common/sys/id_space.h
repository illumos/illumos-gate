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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_ID_SPACE_H
#define	_ID_SPACE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/vmem.h>

#ifdef _KERNEL

typedef vmem_t id_space_t;

id_space_t *id_space_create(const char *, id_t, id_t);
void id_space_destroy(id_space_t *);
void id_space_extend(id_space_t *, id_t, id_t);
id_t id_alloc(id_space_t *);
id_t id_alloc_nosleep(id_space_t *);
id_t id_allocff(id_space_t *);
id_t id_allocff_nosleep(id_space_t *);
id_t id_alloc_specific_nosleep(id_space_t *, id_t);
void id_free(id_space_t *, id_t);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _ID_SPACE_H */
