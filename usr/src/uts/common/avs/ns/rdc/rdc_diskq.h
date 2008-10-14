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

#ifndef _RDC_DISKQ_H
#define	_RDC_DISKQ_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	RDC_DISKQ_HEADER_OFF	0		/* beginning of disk */
#define	RDC_DISKQ_DATA_OFF	FBA_LEN(1024)	/* beginning of queue */

typedef struct qentry {
	int		magic;
	int		type; 	/* special data ? io? bitmap? */
	nsc_off_t	pos;	/* position it will be in the rdc_aio_t */
	nsc_off_t	hpos;	/* starting pos of orig nsc_buf_t */
	nsc_off_t	qpos;	/* where this info is in the queue */
	nsc_size_t	len;	/* len */
	int		flag;
	int		iostatus;
	uint32_t	setid;	/* krdc */
	time_t		time;
	void		*next;
} q_data;

typedef union io_dat {
	q_data	dat;
	char	dummy[512];
} io_hdr;

#define	RDC_IOHDR_MAGIC		0x494F4844 /* IOHD */
#define	RDC_IOHDR_DONE  	0xDEADCAFE /* this q entry has been flushed */
#define	RDC_IOHDR_WAITING  	0xBEEFCAFE /* this q entry is waiting for ack */

/* type */
#define	RDC_QUEUEIO	0x02

#define	RDC_DISKQ_MAGIC	0x44534B51
#define	RDC_DISKQ_VER_ORIG	0x01
#define	RDC_DISKQ_VER_64BIT	0x02

#ifdef	NSC_MULTI_TERABYTE
#define	RDC_DISKQ_VERS	RDC_DISKQ_VER_64BIT
#else
#define	RDC_DISKQ_VERS	RDC_DISKQ_VER_ORIG
#endif

typedef struct diskqheader1 {
	int	magic;
	int	vers;
	int	state;
	int	head_offset; /* offset of meta-info of head (fbas) */
	int	tail_offset; /* addr of next write (fbas) */
	int	disk_size; /* allow growing ? (fbas) */
	long 	nitems; /* items */
	long	blocks; /* fbas */
	int	qwrap; /* where the tail wrapped */
	int	auxqwrap; /* if the tail wraps again, before head wraps once */
	uint_t	seq_last; /* last sequence before suspend */
	uint_t	ack_last; /* last ack before suspend */
} diskq_header1;

typedef struct diskqheader2 {
	int	magic;
	int	vers;
	int	state;
	uint64_t head_offset; /* offset of meta-info of head (fbas) */
	uint64_t tail_offset; /* addr of next write (fbas) */
	uint64_t disk_size; /* allow growing ? (fbas) */
	uint64_t nitems; /* items */
	uint64_t blocks; /* fbas */
	uint64_t qwrap; /* where the tail wrapped */
	uint64_t auxqwrap; /* if the tail wraps again, before head wraps once */
	uint_t	seq_last; /* last sequence before suspend */
	uint_t	ack_last; /* last ack before suspend */
} diskq_header2;

#ifdef	NSC_MULTI_TERABYTE
typedef diskq_header2 diskq_header;
#ifdef _LP64
#define	RDC_DQFMT	"lu"
#else
#define	RDC_DQFMT	"llu"
#endif
#else
typedef diskq_header1 diskq_header;
#define	RDC_DQFMT	"ld"
#endif
typedef union headr {
	diskq_header h;
	char	dummy[512];
} dqheader;

/* flags for the state field in the header */

#define	RDC_SHUTDOWN_OK		0x01
#define	RDC_SHUTDOWN_BAD	0x02
#define	QNXTIOWRAPD		0x04
#define	QHEADWRAPD		0x08
#define	QTAILBUSY		0x10 /* tell flusher not to grab, incomplete */
#define	RDC_QNOBLOCK		0x10000 /* can also be passed out by status */
#define	RDC_QBADRESUME		0x20 /* don't resume bit ref */
#define	RDC_QFULL		0x40 /* the queue is in a full delay loop */
#define	RDC_STOPPINGFLUSH	0x80

#define	RDC_QFILLSTOP		0x01 /* diskq->memq flusher kill switch */
#define	RDC_QFILLSLEEP		0x02 /* explicit diskq->memq flusher sleep */

#define	RDC_MAX_DISKQREAD	0x1000 /* max 2 mb q read */

typedef struct diskqueue { /* the incore info about the diskq */
	dqheader	disk_hdr; /* info about the queue */
	long		nitems_hwm;
	long		blocks_hwm;
	long		throttle_delay;
	nsc_off_t	last_tail;	/* pos of the last tail write */
	volatile int	inflbls;	/* number of inflight blocks */
	volatile int	inflitems;	/* number of inflight blocks */

	kmutex_t	disk_qlock; 	/* protects all things in diskq */
					/* and all things in dqheader */

	kmutex_t	head_lock;
	kcondvar_t	busycv;
	int		busycnt;
	nsc_off_t	nxt_io;		/* flushers head pointer */
	int		hdrcnt;		/* number of io_hdrs on list */
	nsc_off_t	coalesc_bounds;	/* don't coalesce below this offset */
	rdc_aio_t	*lastio;	/* cached copy of the last write on q */
	io_hdr		*iohdrs;	/* flushed, not ack'd on queue */
	io_hdr		*hdr_last;	/* tail of iohdr list */
	kcondvar_t	qfullcv;	/* block, queue is full */
} disk_queue;

/* diskq macros  (gets) */

#define	QHEAD(q) 		q->disk_hdr.h.head_offset
#define	QNXTIO(q)		q->nxt_io
#define	QTAIL(q)		q->disk_hdr.h.tail_offset
#define	QNITEMS(q)		q->disk_hdr.h.nitems
#define	QBLOCKS(q)		q->disk_hdr.h.blocks
#define	QSTATE(q)		q->disk_hdr.h.state
#define	IS_QSTATE(q, s)		(q->disk_hdr.h.state & s)
#define	QSIZE(q)		q->disk_hdr.h.disk_size
#define	QMAGIC(q)		q->disk_hdr.h.magic
#define	QVERS(q)		q->disk_hdr.h.vers
#define	QSEQ(q)			q->disk_hdr.h.seq_last
#define	QACK(q)			q->disk_hdr.h.ack_last
#define	QEMPTY(q)		((QTAIL(q) == QHEAD(q))&&(!(QNITEMS(q))))
#define	QWRAP(q)		q->disk_hdr.h.qwrap
#define	AUXQWRAP(q)		q->disk_hdr.h.auxqwrap
#define	LASTQTAIL(q)		q->last_tail
#define	QCOALBOUNDS(q)		q->coalesc_bounds

/* diskq macros	(sets) */

#define	INC_QHEAD(q, n)		q->disk_hdr.h.head_offset += n
#define	INC_QNXTIO(q, n)	q->nxt_io += n
#define	DEC_QNXTIO(q, n)	q->nxt_io -= n
#define	DEC_QHEAD(q, n)		q->disk_hdr.h.head_offset -= n
#define	INC_QTAIL(q, n)		q->disk_hdr.h.tail_offset += n
#define	DEC_QTAIL(q, n)		q->disk_hdr.h.tail_offset -= n
#define	INC_QNITEMS(q, n)	q->disk_hdr.h.nitems += n
#define	DEC_QNITEMS(q, n)	q->disk_hdr.h.nitems -= n
#define	INC_QBLOCKS(q, n)	q->disk_hdr.h.blocks += n
#define	DEC_QBLOCKS(q, n)	q->disk_hdr.h.blocks -= n

#define	SET_QMAGIC(q, n)	q->disk_hdr.h.magic = n
#define	SET_QSTATE(q, n)	q->disk_hdr.h.state |= n
#define	CLR_QSTATE(q, n)	q->disk_hdr.h.state &= ~n
#define	SET_QHEAD(q, n)		q->disk_hdr.h.head_offset = n
#define	SET_QNXTIO(q, n)	q->nxt_io = n
#define	SET_QHDRCNT(q, n)	q->hdrcnt = n
#define	SET_QTAIL(q, n)		q->disk_hdr.h.tail_offset = n
#define	SET_LASTQTAIL(q, n)	q->last_tail = n
#define	SET_LASTQWRITE(q, w)	q->last_qwrite = w
#define	SET_QSIZE(q, n)		q->disk_hdr.h.disk_size = n
#define	SET_QNITEMS(q, n)	q->disk_hdr.h.nitems = n
#define	SET_QBLOCKS(q, n)	q->disk_hdr.h.blocks = n

#define	SET_QWRAP(q, n)		q->disk_hdr.h.qwrap = n
#define	CLR_QWRAP(q)		q->disk_hdr.h.qwrap = 0
#define	SET_AUXQWRAP(q, n)	q->disk_hdr.h.auxqwrap = n
#define	CLR_AUXQWRAP(q)		q->disk_hdr.h.auxqwrap = 0
#define	SET_QCOALBOUNDS(q, n)	q->coalesc_bounds = n

#define	WRAPQTAIL(q) \
	do { \
		if (QWRAP(q)) { \
			SET_AUXQWRAP(q, QTAIL(q)); \
		} else { \
			SET_QWRAP(q, QTAIL(q)); \
		} \
		SET_QTAIL(q, RDC_DISKQ_DATA_OFF); \
	} while (0)

#define	DO_AUXQWRAP(q) \
	do { \
		SET_QWRAP(q, AUXQWRAP(q)); \
		SET_AUXQWRAP(q, 0); \
	} while (0)

/* these can be wrapped by different threads, avoid the race */
#define	WRAPQHEAD(q) \
	do { \
		if (IS_QSTATE(q, QNXTIOWRAPD)) { \
			if (AUXQWRAP(q)) { \
				DO_AUXQWRAP(q); \
			} else { \
				SET_QWRAP(q, 0); \
			} \
			CLR_QSTATE(q, QNXTIOWRAPD); \
		} else { \
			SET_QSTATE(q, QHEADWRAPD); \
		} \
		SET_QHEAD(q, RDC_DISKQ_DATA_OFF); \
	} while (0)

#define	WRAPQNXTIO(q)	\
	do { \
		if (IS_QSTATE(q, QHEADWRAPD)) { \
			if (AUXQWRAP(q)) { \
				DO_AUXQWRAP(q); \
			} else { \
				SET_QWRAP(q, 0); \
			} \
			CLR_QSTATE(q, QHEADWRAPD); \
		} else { \
			SET_QSTATE(q, QNXTIOWRAPD); \
		} \
		SET_QNXTIO(q, RDC_DISKQ_DATA_OFF); \
	} while (0)

#define	DQEND(q) (QWRAP(q)?QWRAP(q):QSIZE(q))

#define	FITSONQ(q, n) \
	(((QBLOCKS(q)+QNITEMS(q)+RDC_DISKQ_DATA_OFF+n) >= \
		(uint64_t)DQEND(q))?0:1)

/* diskq defines/macros (non-specific) */

#define	RDC_NOLOG		0x00
#define	RDC_WAIT		0x01
#define	RDC_NOWAIT		0x02
#define	RDC_DOLOG		0x04 /* put the group into logging */
#define	RDC_NOFAIL		0x08 /* don't fail the queue, just init */
#define	RDC_GROUP_LOCKED	0x10 /* trust me, I have the group lock */

#define	RDC_WRITTEN		0x10 /* data has been commited to queue */
#define	RDC_LAST		0x20 /* end of dequeued buffer, discard */

/* CSTYLED */
#define	RDC_BETWEEN(a,b,c)	(a<b?((c>=a)&&(c<=b)):((a!=b)&&((c<b)||(c>=a))))
/* CSTYLED */

#define	QHEADSHLDWRAP(q)	(QWRAP(q) && (QHEAD(q) >= QWRAP(q)))
#define	QNXTIOSHLDWRAP(q)	(QWRAP(q) && (QNXTIO(q) >= QWRAP(q)))
#define	QTAILSHLDWRAP(q, size)	(QTAIL(q) + size > QSIZE(q))
#define	QCOALESCEOK(q, dec) ((q->lastio->iostatus & RDC_WRITTEN) && \
	((QTAIL(q) > QNXTIO(q)) ? \
	(((QTAIL(q) - dec) > QNXTIO(q)) && ((QTAIL(q) - dec) > \
	QCOALBOUNDS(q))):\
	(QNXTIOSHLDWRAP(q) && QTAIL(q) > RDC_DISKQ_DATA_OFF)))

#define	QLOCK(q)		&q->disk_qlock
#define	QTAILLOCK(q)		&q->tail_lock
#define	QHEADLOCK(q)		&q->head_lock

#define	QDISPLAY(q)		"qmagic: %x qvers: %d qstate: %x qhead: %" \
	NSC_SZFMT " qnxtio: %" NSC_SZFMT " qtail: %" NSC_SZFMT " qtaillast: %" \
	NSC_SZFMT " qsize: %" NSC_SZFMT " qnitems: %" RDC_DQFMT \
	" qblocks: %" RDC_DQFMT " coalbounds %" NSC_SZFMT, QMAGIC(q), \
	QVERS(q), QSTATE(q), QHEAD(q), QNXTIO(q), QTAIL(q), LASTQTAIL(q), \
	QSIZE(q), QNITEMS(q), QBLOCKS(q), QCOALBOUNDS(q)

#define	QDISPLAYND(q)		"m: %x v: %d s: %d h: %" NSC_SZFMT " n: %" \
	NSC_SZFMT " t: %" NSC_SZFMT " l: %" NSC_SZFMT " z: %" NSC_SZFMT \
	" i: %" RDC_DQFMT " b: %" RDC_DQFMT " w: %" NSC_SZFMT \
	" a: %" NSC_SZFMT, \
	QMAGIC(q), QVERS(q), QSTATE(q), QHEAD(q), \
	QNXTIO(q), QTAIL(q), LASTQTAIL(q), QSIZE(q), QNITEMS(q), \
	QBLOCKS(q), QWRAP(q), AUXQWRAP(q)

/* Disk queue flusher state */
#define	RDC_QFILL_AWAKE		(0)
#define	RDC_QFILL_ASLEEP	(1)
#define	RDC_QFILL_DEAD		(-1)

/* functions */

int rdc_add_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus);
int rdc_rem_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus);
int rdc_kill_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus);
int rdc_init_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus);
int rdc_lookup_diskq(char *path);
int rdc_diskq_inuse(rdc_set_t *set, char *diskq);
void rdc_dump_iohdrs(disk_queue *q);
extern void rdc_fixlen(rdc_aio_t *aio);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _RDC_DISKQ_H */
