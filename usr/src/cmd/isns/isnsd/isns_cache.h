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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISNS_CACHE_H
#define	_ISNS_CACHE_H

#include <synch.h>
#include <isns_htab.h>
#include <isns_dd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CACHE_FLAG_UPDATED	0x1

#define	SET_CACHE_UPDATED()	(cache_flag |= CACHE_FLAG_UPDATED)
#define	RESET_CACHE_UPDATED()	(cache_flag &= ~CACHE_FLAG_UPDATED)

#define	IS_CACHE_UPDATED()	(cache_flag & CACHE_FLAG_UPDATED)

#define	CACHE_NO_ACTION	(0)
#define	CACHE_READ	(1)
#define	CACHE_TRY_READ	(2)
#define	CACHE_WRITE	(3)

typedef struct cache {
	rwlock_t l;
	htab_t **t;
	matrix_t **x;
	uint32_t (*get_hval)(void *, uint16_t, uint32_t *);
	uint32_t (*get_uid)(const void *);
	uint32_t (*set_uid)(void *, uint32_t);
	uint32_t (*timestamp)(void);
	int (*add_hook)(void *);
	int (*replace_hook)(void *, void *, uint32_t *, int);
	int (*cmp)(void *, void *, int);
	void *(*clone)(void *, int);
	int (*ddd)(void *, const uchar_t);
#ifdef DEBUG
	void (*dump)(void *);
#endif
} cache_t;

int cache_init(void);
void cache_destroy(void);
int cache_lock(int);
int cache_unlock(int, int);
int cache_lock_read(void);
int cache_lock_write(void);
int cache_unlock_sync(int);
int cache_unlock_nosync(void);
htab_t *cache_get_htab(isns_type_t);
matrix_t *cache_get_matrix(isns_type_t);
int cache_lookup(lookup_ctrl_t *, uint32_t *, int (*)(void *, void *));
int cache_rekey(lookup_ctrl_t *, uint32_t *, int (*)(void *, void *));
int cache_add(isns_obj_t *, int, uint32_t *, int *);
isns_obj_t *cache_remove(lookup_ctrl_t *, int);

#ifdef DEBUG
void cache_dump_htab(isns_type_t);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_CACHE_H */
