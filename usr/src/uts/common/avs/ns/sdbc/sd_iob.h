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


#ifndef	_SD_IOB_H
#define	_SD_IOB_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_HOOK_LOCKS	32
typedef int (*dcb_t)(struct buf *);	/* driver callback type */

/*
 * order of end action calls:
 * driver callback (iob_drv_iodone) is stuffed in b_iodone and called by
 * the device driver when i/o completes.  It calls the hook end action
 * (iob_hook_iodone) which maintains the completion count (iob_hook.count)
 * and calls the clients end action (iob_hook.func) when the chain is complete.
 */
typedef struct iob_hook {
		struct iob_hook *next_hook;
		struct buf	*chain;	/* all the buffers for this iob */
		struct buf	*tail;	/* tail of buffer chain */
		int	count;		/* number of bufs on the chain */
		nsc_off_t start_fba;	/* initial disk block for the xfer */
		nsc_off_t last_fba;	/* last disk block for the xfer */
		nsc_size_t size;	/* # bytes for entire transfer */
		unsigned char *last_vaddr; /* ending addr of last i/o request */
		sdbc_ea_fn_t func;	/* clients end action routine */
		int	(* iob_hook_iodone)(struct buf *, struct iob_hook *);
		dcb_t	iob_drv_iodone; /* driver call back */
		blind_t	param;		/* param for clnt end action routine */
		int	flags;		/* flags for each buffer */
		int	error;		/* any error */
		int	skipped;	/* this iob used sd_add_mem */
		kmutex_t *lockp;	/* mutex for releasing buffers */
		kcondvar_t wait;	/* sync for sleeping on synch i/o */
#ifdef _SD_BIO_STATS
		int	PAGE_IO, NORM_IO, SKIP_IO;
		int	PAGE_COMBINED;
		nsc_size_t NORM_IO_SIZE;
#endif /* _SD_BIO_STATS */
	} iob_hook_t;

typedef struct _sd_buf_list {
	iob_hook_t	*hooks;		/* all of the iob hooks */
	iob_hook_t	*hook_head;	/* free iob hook */
	int		bl_init_count;  /* total count */
	int		bl_hooks_avail;  /* monitor available hook count */
	int 		bl_hook_lowmark; /* record if ever run out of hooks */
	int		hook_waiters;	/* count of waiters */
	int		max_hook_waiters; /* record max ever waiters */
	kcondvar_t	hook_wait;	/* sync for sleeping on synch i/o */
	kmutex_t	hook_locks[MAX_HOOK_LOCKS];
} _sd_buf_list_t;

/*
 * NOTE: if you change this, then also make changes to the generation
 * of sd_iob_impl*.c in src/uts/common/Makefile.files and Makefile.rules!
 */
#define	_SD_DEFAULT_IOBUFS 4096

/* define driver callback and driver callback function table */

#define	IOB_DCBP(i) (sd_iob_dcb ## i)

#define	IOB_DCB(i)	\
	int	\
	IOB_DCBP(i)(struct buf *bp)	\
	{		\
		return ((*_sd_buflist.hooks[i].iob_hook_iodone)	\
				(bp, &_sd_buflist.hooks[i]));	\
	}

extern _sd_buf_list_t _sd_buflist;

#ifdef	__cplusplus
}
#endif

#endif	/* _SD_IOB_H */
