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

#ifndef	_SYS_DMU_TX_H
#define	_SYS_DMU_TX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/inttypes.h>
#include <sys/dmu.h>
#include <sys/txg.h>
#include <sys/refcount.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct dmu_buf_impl;
struct dnode_link;
struct dsl_pool;
struct dnode;
struct dsl_dir;

struct dmu_tx {
	/*
	 * No synchronization is needed because a tx can only be handled
	 * by one thread.
	 */
	list_t tx_holds; /* list of dmu_tx_hold_t */
	objset_t *tx_objset;
	struct dsl_dir *tx_dir;
	struct dsl_pool *tx_pool;
	uint64_t tx_txg;
	txg_handle_t tx_txgh;
	uint64_t tx_space_towrite;
	refcount_t tx_space_written;
	uint64_t tx_space_tofree;
	refcount_t tx_space_freed;
	uint64_t tx_space_tooverwrite;
	void *tx_tempreserve_cookie;
	uint8_t tx_anyobj;
	uint8_t tx_privateobj;
#ifdef ZFS_DEBUG
	char *tx_debug_buf;
	int tx_debug_len;
#endif
};

enum dmu_tx_hold_type {
	THT_NEWOBJECT,
	THT_WRITE,
	THT_BONUS,
	THT_FREE,
	THT_ZAP,
	THT_SPACE,
	THT_NUMTYPES
};

typedef void (*dmu_tx_hold_func_t)(dmu_tx_t *tx, struct dnode *dn,
    uint64_t arg1, uint64_t arg2);


typedef struct dmu_tx_hold {
	list_node_t dth_node;
	struct dnode *dth_dnode;
	enum dmu_tx_hold_type dth_type;
	dmu_tx_hold_func_t dth_func;
	uint64_t dth_arg1;
	uint64_t dth_arg2;
	/* XXX track what the actual estimates were for this hold */
} dmu_tx_hold_t;


/*
 * These routines are defined in dmu.h, and are called by the user.
 */
dmu_tx_t *dmu_tx_create(objset_t *dd);
int dmu_tx_assign(dmu_tx_t *tx, uint64_t txg_how);
void dmu_tx_commit(dmu_tx_t *tx);
void dmu_tx_abort(dmu_tx_t *tx);
uint64_t dmu_tx_get_txg(dmu_tx_t *tx);

/*
 * These routines are defined in dmu_spa.h, and are called by the SPA.
 */
extern dmu_tx_t *dmu_tx_create_assigned(struct dsl_pool *dp, uint64_t txg);

/*
 * These routines are only called by the DMU.
 */
dmu_tx_t *dmu_tx_create_ds(dsl_dir_t *dd);
int dmu_tx_is_syncing(dmu_tx_t *tx);
int dmu_tx_private_ok(dmu_tx_t *tx);
void dmu_tx_add_new_object(dmu_tx_t *tx, objset_t *os, uint64_t object);
void dmu_tx_willuse_space(dmu_tx_t *tx, int64_t delta);
void dmu_tx_dirty_buf(dmu_tx_t *tx, struct dmu_buf_impl *db);
int dmu_tx_holds(dmu_tx_t *tx, uint64_t object);
void dmu_tx_hold_space(dmu_tx_t *tx, uint64_t space);

#ifdef ZFS_DEBUG

extern int dmu_use_tx_debug_bufs;

#define	dprintf_tx(tx, fmt, ...) \
	if (dmu_use_tx_debug_bufs) \
	do { \
	char *__bufp; \
	int __len; \
	if (tx->tx_debug_buf == NULL) { \
		__bufp = kmem_zalloc(4096, KM_SLEEP); \
		tx->tx_debug_buf = __bufp; \
		tx->tx_debug_len = __len = 4096; \
	} else { \
		__len = tx->tx_debug_len; \
		__bufp = &tx->tx_debug_buf[4096-__len]; \
	} \
	tx->tx_debug_len -= snprintf(__bufp, __len, fmt, __VA_ARGS__); \
_NOTE(CONSTCOND) } while (0); \
	else dprintf(fmt, __VA_ARGS__)

#define	DMU_TX_DIRTY_BUF(tx, db)	dmu_tx_dirty_buf(tx, db)

#else

#define	dprintf_tx(tx, fmt, ...)
#define	DMU_TX_DIRTY_BUF(tx, db)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DMU_TX_H */
