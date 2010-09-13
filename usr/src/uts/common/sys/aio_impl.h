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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_AIO_IMPL_H
#define	_SYS_AIO_IMPL_H

#include <sys/aio_req.h>
#include <sys/aio.h>
#include <sys/aiocb.h>
#include <sys/uio.h>
#include <sys/dditypes.h>
#include <sys/siginfo.h>
#include <sys/port.h>
#include <sys/port_kernel.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	AIO_HASHSZ		8192L		/* power of 2 */
#define	AIO_HASH(cookie)	(((uintptr_t)(cookie) >> 3) & (AIO_HASHSZ-1))
#define	DUPLICATE 1

/*
 * an aio_list_t is the head of a list. a group of requests are in
 * the same list if their aio_req_list field point to the same list
 * head.
 *
 * a list head is used for notification. a group of requests that
 * should only notify a process when they are done will have a
 * list head. notification is sent when the group of requests are
 * done.
 */
typedef struct aio_lio {
	int 		lio_nent;		/* number of requests in list */
	int 		lio_refcnt;		/* number of requests active */
	struct aio_lio	*lio_next;		/* free list pointer */
	kcondvar_t	lio_notify;		/* list notification */
	sigqueue_t	*lio_sigqp;		/* sigqueue_t pointer */
	int		lio_port;		/* port number notification */
	port_kevent_t	*lio_portkev;		/* port event structure */
} aio_lio_t;

/*
 * async I/O request struct - one per I/O request.
 */

/*
 * Clustering: The aio_req_t structure is used by the PXFS module
 * as a contract private interface.
 */

typedef struct aio_req_t {
	struct aio_req	aio_req;
	int		aio_req_fd;		/* aio's file descriptor */
	int		aio_req_flags;		/* flags */
	aio_result_t	*aio_req_resultp;	/* pointer to user's results */
	int		(*aio_req_cancel)();	/* driver's cancel cb. */
	struct aio_req_t *aio_req_next;		/* doneq and pollq pointers */
	struct aio_req_t *aio_req_prev;		/* doubly linked list */
	struct aio_req_t *aio_hash_next;	/* next in a hash bucket */
	aio_lio_t 	*aio_req_lio;		/* head of list IO chain */
	struct uio	aio_req_uio;		/* uio struct */
	struct iovec	aio_req_iov;		/* iovec struct */
	struct buf	aio_req_buf;		/* buf struct */
	sigqueue_t	*aio_req_sigqp;		/* sigqueue_t pointer */
	union {
		caddr_t 	iocb;		/* ptr to aiocb: 32-32, 64-64 */
		caddr32_t	iocb32;		/* ptr to aiocb: 32-64 */
	} aio_req_iocb;
	port_kevent_t	*aio_req_portkev;	/* port event structure */
	int		aio_req_port;		/* port id */
} aio_req_t;

/*
 * Struct for asynchronous I/O (aio) information per process.
 * Each proc stucture has a field pointing to this struct.
 * The field will be null if no aio is used.
 */
typedef struct aio {
	int		aio_pending;		/* # uncompleted requests */
	int		aio_outstanding;	/* total # of requests */
	int		aio_ok;			/* everything ok when set */
	int		aio_flags;		/* flags */
	int		aio_rqclnup;		/* cleanup request used by DR */
	int		aio_portpendcnt;	/* # pending req. per port */
	aio_req_t	*aio_portq;  		/* port queue head */
	aio_req_t	*aio_portcleanupq;	/* port cleanup queue head */
	aio_req_t	*aio_portpending;	/* list of pending requests */
	aio_req_t	*aio_free;  		/* freelist of aio requests */
	aio_lio_t	*aio_lio_free;		/* freelist of lio heads */
	aio_req_t	*aio_doneq;		/* done queue head */
	aio_req_t	*aio_pollq;		/* poll queue head */
	aio_req_t	*aio_notifyq;		/* notify queue head */
	aio_req_t	*aio_cleanupq;		/* cleanup queue head */
	kmutex_t    	aio_mutex;		/* mutex for aio struct */
	kmutex_t	aio_cleanupq_mutex;	/* cleanupq processing */
	kcondvar_t  	aio_waitcv;		/* cv for aiowait()'ers */
	kcondvar_t  	aio_cleanupcv;		/* notify cleanup, aio_done */
	kcondvar_t  	aio_waitncv;		/* cv for further aiowaitn() */
	kcondvar_t  	aio_portcv;		/* cv for port events */
	aiocb_t		**aio_iocb;		/* list of 32 & 64 bit ptrs */
	size_t		aio_iocbsz;		/* reserved space for iocbs */
	uint_t		aio_waitncnt;		/* # requests for aiowaitn */
	int 		aio_notifycnt;		/* # user-level notifications */
	kmutex_t	aio_portq_mutex;	/* mutex for aio_portq */
	aio_req_t 	*aio_hash[AIO_HASHSZ];	/* hash list of requests */
} aio_t;

/*
 * aio_flags for an aio_t.
 */
#define	AIO_CLEANUP		0x0001	/* do aio cleanup processing */
#define	AIO_WAITN		0x0002	/* aiowaitn in progress */
#define	AIO_WAITN_PENDING	0x0004	/* aiowaitn requests pending */
#define	AIO_REQ_BLOCK		0x0008	/* block new requests */
#define	AIO_CLEANUP_PORT	0x0010
#define	AIO_DONE_ACTIVE		0x0020	/* aio_done call in progress */
#define	AIO_SOLARIS_REQ		0x0040	/* an old solaris aio req was issued */

/*
 * aio_req_flags for an aio_req_t
 */
#define	AIO_POLL	0x0001		/* AIO_INPROGRESS is set */
#define	AIO_PENDING	0x0002		/* aio is in progress */
#define	AIO_PHYSIODONE	0x0004		/* unlocked phys pages */
#define	AIO_COPYOUTDONE	0x0008		/* result copied to userland */
#define	AIO_NOTIFYQ	0x0010		/* aio req is on the notifyq */
#define	AIO_CLEANUPQ	0x0020		/* aio req is on the cleanupq */
#define	AIO_POLLQ	0x0040		/* aio req is on the pollq */
#define	AIO_DONEQ	0x0080		/* aio req is on the doneq */
#define	AIO_ZEROLEN	0x0100		/* aio req is zero length */
#define	AIO_PAGELOCKDONE 0x0200		/* aio called as_pagelock() */
#define	AIO_CLOSE_PORT	0x0400		/* port is being closed */
#define	AIO_SIGNALLED	0x0800		/* process signalled by this req */
#define	AIO_SOLARIS	0x1000		/* this is an old solaris aio req */

/* flag argument of aio_cleanup() */

#define	AIO_CLEANUP_POLL	0	/* check kaio poll queue */
#define	AIO_CLEANUP_EXIT	1	/* aio_cleanup_exit() */
#define	AIO_CLEANUP_THREAD	2	/* aio_cleanup_thread() */

/* functions exported by common/os/aio_subr.c */

extern int aphysio(int (*)(), int (*)(), dev_t, int, void (*)(),
		struct aio_req *);
extern void aphysio_unlock(aio_req_t *);
extern void aio_cleanup(int);
extern void aio_cleanup_exit(void);
extern void aio_zerolen(aio_req_t *);
extern void aio_req_free(aio_t *, aio_req_t *);
extern void aio_cleanupq_concat(aio_t *, aio_req_t *, int);
extern void aio_copyout_result(aio_req_t *);
extern void aio_copyout_result_port(struct iovec *, struct buf *, void *);
extern void aio_req_remove_portq(aio_t *, aio_req_t *);
extern void aio_enq(aio_req_t **, aio_req_t *, int);
extern void aio_deq(aio_req_t **, aio_req_t *);
/* Clustering: PXFS module uses this interface */
extern void aio_done(struct buf *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_AIO_IMPL_H */
