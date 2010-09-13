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

#ifndef	_SD_SAFESTORE_IMPL_H
#define	_SD_SAFESTORE_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/* ss config stages */
#define	SD_WR_SLP_Q_MAX	256

/*
 * Global fields for cache LRU entry. Fault tolerant structure in RMS.
 */

#define	INCX(x) (x = (x + 1 + SD_WR_SLP_Q_MAX) % SD_WR_SLP_Q_MAX)
#define	DECX(x) (x = (x - 1 + SD_WR_SLP_Q_MAX) % SD_WR_SLP_Q_MAX)

typedef struct _sd_wr_slp_queue {
	kcondvar_t	slp_wqcv;
	int	slp_wqneed;
} _sd_wr_slp_queue_t;

typedef struct _sd_wr_queue {
	struct ss_wr_cctl *wq_qtop;	/* Top of write control blocks */
	kmutex_t   wq_qlock;		/* allocation spinlock */
	int 	wq_inq;		/* number of write blocks available in q */
	int	wq_nentries;	/* total Number of write blocks in q */
	unsigned int	wq_slp_top;
	unsigned int	wq_slp_index;
	unsigned int	wq_slp_inq;
	_sd_wr_slp_queue_t wq_slp[SD_WR_SLP_Q_MAX];
} _sd_writeq_t;

#define	WQ_SET_NEED(q, need, i) {			\
	(q->wq_slp[i].slp_wqneed = need);			\
}

#define	WQ_SVWAIT_BOTTOM(q, need)				\
{ 								\
	int ix = q->wq_slp_index;				\
	INCX(q->wq_slp_index);					\
	WQ_SET_NEED(q, need, ix);				\
	cv_wait(&q->wq_slp[ix].slp_wqcv, &q->wq_qlock);	\
	mutex_exit(&q->wq_qlock); \
}

#define	WQ_SVWAIT_TOP(q, need)					\
{									\
	DECX(q->wq_slp_top);						\
	WQ_SET_NEED(q, need, q->wq_slp_top);			\
	cv_wait(&q->wq_slp[q->wq_slp_top].slp_wqcv, &q->wq_qlock);\
	mutex_exit(&q->wq_qlock); \
}

#define	WQ_NEED_SIG(q) \
	(q->wq_slp_inq && (q->wq_slp[q->wq_slp_top].slp_wqneed <= q->wq_inq))

#define	WQ_SVSIG(q) 						\
{								\
	int tp = q->wq_slp_top;					\
	INCX(q->wq_slp_top);					\
	q->wq_slp[tp].slp_wqneed = 0;				\
	cv_signal(&q->wq_slp[tp].slp_wqcv);			\
}

/*
 * cache entry information
 * note -- this structure is a identical to the first 4 words of
 * the exported ss_centry_info_t.  internal copies depened on this
 * fact.  changes to this structure may require changes to the
 * *getcentry() and *setcentry() functions.
 *
 */
typedef struct ss_centry_info_impl_s {
	int sci_cd;		/* Cache descriptor */
	nsc_off_t sci_fpos;	/* File position    */
	int sci_dirty;		/* Dirty mask	    */
	int sci_flag;		/* CC_PINNABLE | CC_PINNED */
} ss_centry_info_impl_t;

/*
 * The write control structure has information about the remote page that
 * will mirror a write.
 */
typedef struct ss_wr_cctl {
	struct ss_wr_cctl	*wc_next;	/* chaining queue entries */
	caddr_t			wc_addr;	/* points to data address */
	ss_centry_info_impl_t	*wc_gl_info;	/* information for the page */
	unsigned char		wc_flag;	/* flag	*/
} ss_wr_cctl_t;

/* volume information */
typedef struct ss_voldata_impl_s {
	char svi_volname[NSC_MAXPATH];	/* Filename in RMS for failover */
	int  svi_cd;			/* NOTE may need dual node map info */
	int  svi_pinned;		/* Device has failed/pinned blocks */
	int  svi_attached;		/* Node which has device attached */
	int  svi_devidsz;		/* unique dev id length */
	uchar_t svi_devid[NSC_MAXPATH];	/* wwn id - physical devs only */
	int  svi_reserved[13];		/* Reserved global space */
} ss_voldata_impl_t;

extern int _sd_fill_pattern(caddr_t addr, uint_t pat, uint_t size);
extern int _sdbc_writeq_configure(_sd_writeq_t *);
extern void _sdbc_writeq_deconfigure(_sd_writeq_t *);
extern void ss_release_write(ss_wr_cctl_t *, _sd_writeq_t *);
extern ss_wr_cctl_t *ss_alloc_write(int, int *, _sd_writeq_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SD_SAFESTORE_IMPL_H */
