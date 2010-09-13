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

#ifndef	_NIS_HASHITEM_H
#define	_NIS_HASHITEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <rpcsvc/nis.h>

#include "nisdb_rw.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* Private versions of the various NIS_HASH_ITEM functions */
typedef struct __nis_item_item {
	pthread_cond_t		lock;
	nis_name		name;
	int			keychain;
	uint32_t		readers;
	pthread_t		last_reader_id;
	uint32_t		writer;
	pthread_t		writer_id;
	struct __nis_item_item	*next;
	struct __nis_item_item	*prv_item;
	struct __nis_item_item	*nxt_item;
} __nis_hash_item_mt;

typedef struct {
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	pthread_mutex_t		traverser_id_lock;
							/*
							 * Protects 'traversed'
							 * and 'traverser_id'.
							 */
	uint32_t		traversed;
	pthread_t		traverser_id;
	uint32_t		locked_items;
	__nis_hash_item_mt	*keys[64];
	__nis_hash_item_mt	*first;
	void			(*destroyItem)(void *);
} __nis_hash_table_mt;

#define	NIS_HASH_TABLE_MT_INIT	{ \
					PTHREAD_MUTEX_INITIALIZER, \
					{0}, \
					PTHREAD_MUTEX_INITIALIZER \
					/* Zero is fine for the rest */ \
				}

#define	LOCK_LIST(list, msg)	(void) __nis_lock_hash_table(list, 1, msg)
#define	ULOCK_LIST(list, msg)	(void) __nis_ulock_hash_table(list, 1, msg)


extern void	__nis_init_hash_table(__nis_hash_table_mt *, void (*)(void *));
extern int	__nis_lock_hash_table(__nis_hash_table_mt *, int, char *);
extern int	__nis_ulock_hash_table(__nis_hash_table_mt *, int, char *);
extern int	__nis_insert_item_mt(void *, __nis_hash_table_mt *, int);
extern void	__nis_insert_name_mt(nis_name, __nis_hash_table_mt *);
extern void	*__nis_find_item_mt(nis_name, __nis_hash_table_mt *, int,
					int *);
extern void	*__nis_pop_item_mt(__nis_hash_table_mt *);
extern void	*__nis_remove_item_mt(nis_name, __nis_hash_table_mt *);
extern int	__nis_release_item(void *, __nis_hash_table_mt *, int);
extern int	__nis_item_access(void *);
extern void	__nis_scan_table_mt(__nis_hash_table_mt *,
			bool_t (*)(__nis_hash_item_mt *, void *), void *);

/* Define-magic */
#define	NIS_HASH_ITEM			__nis_hash_item_mt
#define	NIS_HASH_TABLE			__nis_hash_table_mt
#define	nis_insert_item(i, t)		__nis_insert_item_mt(i, t, -1)
#define	nis_insert_item_rw(i, t, rw)	__nis_insert_item_mt(i, t, rw)
#define	nis_insert_name(n, t)		__nis_insert_name_mt(n, t)
#define	nis_find_item(i, t)		__nis_find_item_mt(i, t, -1, 0)
#define	nis_find_item_rw(i, t, rw)	__nis_find_item_mt(i, t, rw, 0)
#define	nis_pop_item			__nis_pop_item_mt
#define	nis_remove_item			__nis_remove_item_mt
#define	nis_scan_table			__nis_scan_table_mt

#define	MT_LOCK_TYPE(type)		(type < 0)?"W":(type > 0)?"R":"N"

#ifdef	NIS_MT_DEBUG
#define	MT_LOG(condition, syslogarg)	if (condition) syslog ## syslogarg
#else
#define	MT_LOG(condition, syslogarg)
#endif	/* NIS_MT_DEBUG */

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _NIS_HASHITEM_H */
