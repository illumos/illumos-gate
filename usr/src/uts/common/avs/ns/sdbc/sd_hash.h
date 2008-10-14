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

#ifndef _SD_HASH_H
#define	_SD_HASH_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nsctl/nsctl.h>

#if defined(_KERNEL) || defined(_KMEMUSER)

typedef struct _sd_hash_hd {
	unsigned short hh_hashed;		/* Is this block in hash */
	unsigned short hh_cd;			/* The cache descriptor */
	nsc_off_t hh_blk_num;			/* Cache block number 	*/
	struct _sd_hash_hd *hh_prev;		/* for chaining withing */
	struct _sd_hash_hd *hh_next;		/* hash table 		*/
} _sd_hash_hd_t;


typedef struct _sd_hash_bucket {
	struct _sd_hash_hd *hb_head;
	struct _sd_hash_hd *hb_tail;
	kmutex_t *hb_lock;
	unsigned short hb_inlist;
	volatile unsigned int hb_seq;
} _sd_hash_bucket_t;


typedef struct _sd_hash_table  {
	int ht_size;
	int ht_bits;
	int ht_mask;
	int ht_nmask;
	struct _sd_hash_bucket *ht_buckets;
} _sd_hash_table_t;


#endif /* _KERNEL && _KMEMUSER */


#if defined(_KERNEL)

#define	HASH(cd, blk, table) \
	(((cd << 6) ^ ((blk) ^ ((blk) >> table->ht_bits)))	\
	    & (table->ht_mask))

#define	HT_SEARCH	0
#define	HT_NOSEARCH	1

extern int _sdbc_hash_load(void);
extern void _sdbc_hash_unload(void);
extern _sd_hash_table_t *_sdbc_hash_configure(int num_ents);
extern void _sdbc_hash_deconfigure(_sd_hash_table_t *hash_table);
extern _sd_hash_hd_t *_sd_hash_search(int cd, nsc_off_t block_num,
    _sd_hash_table_t *table);
extern _sd_hash_hd_t *_sd_hash_insert(int cd, nsc_off_t block_num,
    _sd_hash_hd_t *hptr, _sd_hash_table_t *table);
extern int _sd_hash_delete(_sd_hash_hd_t *hptr, _sd_hash_table_t *table);
extern _sd_hash_hd_t *_sd_hash_replace(_sd_hash_hd_t *old, _sd_hash_hd_t *new,
    _sd_hash_table_t *table);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SD_HASH_H */
