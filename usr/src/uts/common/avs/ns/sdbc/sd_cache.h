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

#ifndef _SD_CACHE_H
#define	_SD_CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include	<sys/debug.h>
#include <sys/nsctl/nsctl.h>

/*
 * Compiler defines
 */

#define	_SD_FAULT_RES		/* Enable Fault tolerance		*/

#define	_SD_USE_THREADS		/* Use own threadset			*/
#define	_SD_LRU_OPTIMIZE	/* Enable LRU queue optimizations  	*/
#define	_SD_HASH_OPTIMIZE	/* Enable Hash optimizations		*/

#if !defined(_SD_NO_GENERIC)
#define	_SD_MULTIUSER		/* Block locking (concurrent/dual copy) */
#endif /* (_SD_NO_GENERIC) */

#if defined(_SD_OPTIM_ALLOC)
#define	_SD_NOCHECKS		/* Disable handle allocation checks	*/
#define	_SD_NOTRACE		/* Disable SDTRACE() macro		*/
#undef	_SD_MULTIUSER		/* Disable Block locking		*/
#if (_SD_OPTIM_ALLOC+0 > 1)
#define	_SD_NOSTATS		/* Disable read/write counts		*/
#endif
#endif /* (_SD_OPTIM_ALLOC) */

#if defined(_SD_CHECKS)		/* Enable checks, stats, and tracing	*/
#undef	_SD_NOCHECKS
#undef	_SD_NOTRACE
#undef	_SD_NOSTATS
#define	_SD_STATS		/* Enable cache hits/longevity stats	*/
#if (_SD_CHECKS+0 > 1)
#define	_SD_DEBUG		/* Extra debugging checks		*/
#endif
#endif /* (_SD_CHECKS) */

#if defined(_SD_NOTRACE) && defined(_SD_STATS)
#undef _SD_STATS		/* _SD_STATS requires SDTRACE() macro	*/
#endif

/*
 * Other compiler defines currently not enabled.
 * 	#define	_SD_FBA_DATA_LOG  Enable data logging per 512 bytes.
 * Other compiler defines enabled in the Makefile.
 *	#define	_SD_8K_BLKSIZE	  Allow 8K cache block size
 */

extern	int	_sd_cblock_shift;
#define	BLK_SHFT	(_sd_cblock_shift)
#define	BLK_MASK	((1 << BLK_SHFT) - 1)
#define	BLK_SIZE(x)	((x) << BLK_SHFT)
#define	BLK_NUM(x)	((x) >> BLK_SHFT)
#define	BLK_LEN(x)	((x + BLK_MASK) >> BLK_SHFT)
#define	BLK_OFF(x)	((x) & BLK_MASK)



#define	BLK_FBA_SHFT	(BLK_SHFT - FBA_SHFT)
#define	BLK_FBA_MASK	((1 << BLK_FBA_SHFT) - 1)
#define	BLK_TO_FBA_NUM(x) \
			((x) << BLK_FBA_SHFT)	/* block_num to fba_num */
#define	BLK_FBA_OFF(x)	((x) & BLK_FBA_MASK)	/* fba offset within */
						/* a cache block */

#define	FBA_TO_BLK_NUM(x) \
			((x) >> BLK_FBA_SHFT)	/* fba_num to a */
						/* block_num */

/* fba_num to the next higher block_num */
#define	FBA_TO_BLK_LEN(x)	((x + BLK_FBA_MASK) >> BLK_FBA_SHFT)

/*
 * This is the set of flags that are valid. Anything else set in the
 * handle is invalid and the handle should be rejected during an allocation.
 */

#define	_SD_VALID_FLAGS (NSC_RDWRBUF | NSC_NOBLOCK | NSC_WRTHRU | NSC_NOCACHE\
			| NSC_HALLOCATED | NSC_BCOPY | NSC_PAGEIO \
			| NSC_PINNABLE | NSC_MIXED | NSC_FORCED_WRTHRU \
			| NSC_METADATA)


#define	_SD_FLAG_MASK   	(NSC_FLAGS)
#define	_SD_HINT_MASK		(NSC_HINTS)
#define	_SD_WRTHRU_MASK		(NSC_WRTHRU | NSC_FORCED_WRTHRU)
#define	_SD_NOCACHE_MASK	(NSC_NOCACHE)



#define	_SD_INVALID_CD(cd)	((cd) > sdbc_max_devs)

#define	_INFSD_NODE_UP(i)	(nsc_node_up(i))

#ifdef m88k
#define	_sd_cache_initialized	_INFSD_cache_initialized
#endif

#define	_SD_MAX_FBAS	1024
/*
 * Allow one entry for null terminator and another to handle
 * requests that are not cache block aligned.
 */
#if defined(_SD_8K_BLKSIZE)
#define	_SD_MAX_BLKS	(2 + ((_SD_MAX_FBAS) >> 4))
#else
#define	_SD_MAX_BLKS	(2 + ((_SD_MAX_FBAS) >> 3))
#endif

/* cd to use for _sd_centry_alloc to avoid entering hash table */

#define	_CD_NOHASH	-1

#if defined(_KERNEL) || defined(_KMEMUSER)

struct _sd_buf_handle;
typedef void (*sdbc_callback_fn_t)(struct _sd_buf_handle *);

typedef struct _sd_buf_handle {
	nsc_buf_t bh_buf;		/* Generic buffer - must be first */
	nsc_vec_t bh_bufvec[_SD_MAX_BLKS]; /* Scatter gather list */
	int bh_cd;
	sdbc_callback_fn_t bh_disconnect_cb;
	sdbc_callback_fn_t bh_read_cb;
	sdbc_callback_fn_t bh_write_cb;
	struct _sd_cctl *bh_centry;
	struct _sd_buf_handle *bh_next;
	struct _sd_buf_handle *bh_prev;
	void *bh_alloc_thread; /* debug: kthread that alloc'd this handle */
	void *bh_busy_thread; /* debug: kthread that is using this handle */
	void *bh_param;
} _sd_buf_handle_t;

#define	bh_fba_pos	bh_buf.sb_pos
#define	bh_fba_len	bh_buf.sb_len
#define	bh_flag		bh_buf.sb_flag
#define	bh_error	bh_buf.sb_error
#define	bh_vec		bh_buf.sb_vec

#define	_sd_bufvec_t	nsc_vec_t
#define	buflen		sv_len
#define	bufaddr		sv_addr
#define	bufvmeaddr	sv_vme

#endif /* _KERNEL || _KMEMUSER */

#ifdef __cplusplus
}
#endif

#endif /* _SD_CACHE_H */
