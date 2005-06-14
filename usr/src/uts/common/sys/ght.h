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

#ifndef _SYS_GHT_H
#define	_SYS_GHT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/types.h>

typedef struct __ght_key	*ght_key_t;
typedef struct __ght_val	*ght_val_t;

#define	GHT_SCALAR_TO_KEY(scalar)	((ght_key_t)(uintptr_t)(scalar))
#define	GHT_PTR_TO_KEY(ptr)		((ght_key_t)(ptr))

#define	GHT_SCALAR_TO_VAL(scalar)	((ght_val_t)(uintptr_t)(scalar))
#define	GHT_PTR_TO_VAL(ptr)		((ght_val_t)(ptr))

typedef	struct __ght	*ght_t;
typedef struct __ghte	*ghte_t;

struct ghte_reveal {
	ght_key_t	key;
	ght_val_t	val;
};

#define	GHT_KEY(ghte)	((struct ghte_reveal *)ghte)->key
#define	GHT_VAL(ghte)	((struct ghte_reveal *)ghte)->val

extern int		ght_str_create(char *, uint_t, ght_t *);
extern int		ght_scalar_create(char *, uint_t, ght_t *);
extern int		ght_destroy(ght_t);
extern uint_t		ght_count(ght_t);

extern ghte_t		ght_alloc(ght_t, int);
extern void		ght_free(ghte_t);

#define			GHT_READ	0
#define			GHT_WRITE	1

extern void		ght_lock(ght_t, int);
extern void		ght_unlock(ght_t);

extern int		ght_insert(ghte_t);
extern int		ght_find(ght_t, ght_key_t, ghte_t *);
extern void		ght_remove(ghte_t);

extern void		ght_hold(ghte_t);
extern void		ght_rele(ghte_t);
extern uint_t		ght_ref(ghte_t);

extern void		ght_walk(ght_t, boolean_t (*)(void *, ghte_t), void *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GHT_H */
