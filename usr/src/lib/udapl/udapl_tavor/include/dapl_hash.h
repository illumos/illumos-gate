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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_hash.h
 *
 * PURPOSE: Utility defs & routines for the hash data structure
 *
 * $Id: dapl_hash.h,v 1.4 2003/06/13 12:21:09 sjs2 Exp $
 */

#ifndef _DAPL_HASH_H_
#define	_DAPL_HASH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"


/*
 *
 * Defines
 *
 */

/*
 * Hash table size.
 *
 * Default is small; use the larger sample values for hash tables
 * known to be heavily used.  The sample values chosen are the
 * largest primes below 2^8, 2^9, and 2^10.
 */
#define	DAPL_DEF_HASHSIZE	251
#define	DAPL_MED_HASHSIZE	509
#define	DAPL_LRG_HASHSIZE	1021

#define	DAPL_HASH_TABLE_DEFAULT_CAPACITY	DAPL_DEF_HASHSIZE

typedef enum {
	DAPL_HASH_ITERATE_INIT = 1,
	DAPL_HASH_ITERATE_NEXT
} DAPL_HASH_ITERATOR;


/*
 *
 * Function Prototypes
 *
 */

extern DAT_RETURN
dapls_hash_create(
    IN DAT_COUNT capacity,
    IN DAT_BOOLEAN locking_required,
    OUT DAPL_HASH_TABLE **pp_table);

extern DAT_RETURN
dapls_hash_free(
    IN DAPL_HASH_TABLE *p_table);

extern DAT_RETURN
dapls_hash_size(
    IN DAPL_HASH_TABLE *p_table,
    OUT DAT_COUNT *p_size);

extern DAT_RETURN
dapls_hash_insert(
    IN DAPL_HASH_TABLE *p_table,
    IN DAPL_HASH_KEY key,
    IN DAPL_HASH_DATA data);

extern DAT_RETURN
dapls_hash_search(
    IN DAPL_HASH_TABLE *p_table,
    IN DAPL_HASH_KEY key,
    OUT DAPL_HASH_DATA *p_data);

extern DAT_RETURN
dapls_hash_remove(
    IN DAPL_HASH_TABLE *p_table,
    IN DAPL_HASH_KEY key,
    OUT DAPL_HASH_DATA *p_data);

extern DAT_RETURN
dapls_hash_iterate(
    IN DAPL_HASH_TABLE *p_table,
    IN DAPL_HASH_ITERATOR op,
    OUT DAPL_HASH_DATA *p_data);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_HASH_H_ */
