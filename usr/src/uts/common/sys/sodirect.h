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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_SODIRECT_H
#define	_SYS_SODIRECT_H

/*
 * Sodirect ...
 *
 * Currently the sodirect_t uses the sockfs streamhead STREAMS Q directly,
 * in the future when we have STREAMless sockets a sonode Q will have to
 * be implemented however the sodirect KPI shouldn't need to change.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef int (*sod_enq_func)();
typedef void (*sod_wakeup_func)();

typedef struct sodirect_s {
	uint32_t	sod_state;	/* State bits */
	uint32_t	sod_want;	/* Pending read byte count or 0 */
	queue_t		*sod_q;		/* Socket Q */
	sod_enq_func	sod_enqueue;	/* Call to enqueue an mblk_t */
	sod_wakeup_func	sod_wakeup;	/* Call to awkake a read()er, if any */
	mblk_t		*sod_uioafh;	/* To be freed list head, or NULL */
	mblk_t		*sod_uioaft;	/* To be freed list tail */
	kmutex_t	*sod_lockp;	/* Pointer to the lock needed */
					/* to protect all members */
	uioa_t		sod_uioa;	/* Pending uio_t for uioa_t use */
} sodirect_t;

/*
 * sod_state bits:
 */

#define	SOD_DISABLED	0		/* No more sodirect */

#define	SOD_ENABLED	0x0001		/* sodirect_t enabled */

#define	SOD_WAKE_NOT	0x0010		/* Wakeup not needed */
#define	SOD_WAKE_NEED   0x0020		/* Wakeup needed */
#define	SOD_WAKE_DONE	0x0040		/* Wakeup done */
#define	SOD_WAKE_CLR	~(SOD_WAKE_NOT|SOD_WAKE_NEED|SOD_WAKE_DONE)

/*
 * Usefull macros:
 */

#define	SOD_QSETBE(p) {				\
	queue_t *q = (p)->sod_q;		\
						\
	ASSERT(MUTEX_HELD((p)->sod_lockp));	\
						\
	mutex_enter(QLOCK(q));			\
	if (q->q_flag & QFULL)			\
		q->q_flag |= QWANTW;		\
	mutex_exit(QLOCK(q));			\
}

#define	SOD_QCLRBE(p) {				\
	queue_t *q = (p)->sod_q;		\
						\
	ASSERT(MUTEX_HELD((p)->sod_lockp));	\
						\
	mutex_enter(QLOCK(q));			\
	q->q_flag &= ~QWANTW;			\
	mutex_exit(QLOCK(q));			\
}

#define	SOD_QEMPTY(p) ((p)->sod_q->q_first == NULL)
#define	SOD_QFULL(p) ((p)->sod_q->q_flag & QFULL)
#define	SOD_QCNT(p) ((p)->sod_q->q_count)

#define	SOD_DISABLE(p) {			\
	if ((p) != NULL)			\
		(p)->sod_state &= ~SOD_ENABLED;	\
}

#define	SOD_QTOSODP(q) (q)->q_stream->sd_sodirect
#define	SOD_SOTOSODP(so) ((sonode_t *)so)->so_direct

#define	SOD_UIOAFINI(sodp) {						\
	if ((sodp) && (sodp)->sod_uioa.uioa_state & UIOA_ENABLED) {	\
		(sodp)->sod_uioa.uioa_state &= UIOA_CLR;		\
		(sodp)->sod_uioa.uioa_state |= UIOA_FINI;		\
	}								\
}

struct sonode;
struct sodirect_s;

extern uio_t	*sod_rcv_init(struct sonode *, int, struct uio **);
extern int	sod_rcv_done(struct sonode *, struct uio *, struct uio *);

extern mblk_t	*sod_uioa_mblk_init(struct sodirect_s *, mblk_t *, size_t);
extern void	sod_uioa_so_init(struct sonode *, struct sodirect_s *,
    struct uio *);
extern ssize_t	sod_uioa_mblk(struct sonode *, mblk_t *);
extern void	sod_uioa_mblk_done(struct sodirect_s *, mblk_t *);

extern void	sod_init();
extern void	sod_sock_init(struct sonode *, struct stdata *, sod_enq_func,
    sod_wakeup_func, kmutex_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SODIRECT_H */
