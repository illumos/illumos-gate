/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DLS_SOFT_RING_H
#define	_SYS_DLS_SOFT_RING_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/stream.h>
#include <sys/squeue.h>
#include <sys/mac.h>

#define	S_RING_NAMELEN 64

typedef void (*s_ring_proc_t)(void *, void *, mblk_t *, mac_header_info_t *);

typedef struct soft_ring_s {
	/* Keep the most used members 64bytes cache aligned */
	kmutex_t	s_ring_lock;	/* lock before using any member */
	uint16_t	s_ring_type;	/* processing model of the sq */
	uint16_t	s_ring_state;	/* state flags and message count */
	int		s_ring_count;	/* # of mblocks in soft_ring */
	mblk_t		*s_ring_first;	/* first mblk chain or NULL */
	mblk_t		*s_ring_last;	/* last mblk chain or NULL */
	s_ring_proc_t	s_ring_upcall;	/* Upcall func pointer */
	void		*s_ring_upcall_arg1; /* upcall argument 1 */
	void		*s_ring_upcall_arg2; /* upcall argument 2 */
	clock_t		s_ring_awaken;	/* time async thread was awakened */

	kthread_t	*s_ring_run;	/* Current thread processing sq */
	processorid_t	s_ring_bind;	/* processor to bind to */
	kcondvar_t	s_ring_async;	/* async thread blocks on */
	clock_t		s_ring_wait;	/* lbolts to wait after a fill() */
	timeout_id_t	s_ring_tid;	/* timer id of pending timeout() */
	kthread_t	*s_ring_worker;	/* kernel thread id */
	char		s_ring_name[S_RING_NAMELEN + 1];
	uint32_t	s_ring_total_inpkt;
} soft_ring_t;


/*
 * type flags - combination allowed to process and drain the queue
 */
#define	S_RING_WORKER_ONLY  	0x0001	/* Worker thread only */
#define	S_RING_ANY		0x0002	/* Any thread can process the queue */

/*
 * State flags.
 */
#define	S_RING_PROC	0x0001	/* being processed */
#define	S_RING_WORKER	0x0002	/* worker thread */
#define	S_RING_BOUND	0x0004	/* Worker thread is bound */
#define	S_RING_DESTROY	0x0008	/* Ring is being destroyed */
#define	S_RING_DEAD		0x0010	/* Worker thread is no more */

/*
 * arguments for processors to bind to
 */
#define	S_RING_BIND_NONE	-1

/*
 * Structure for dls statistics
 */
struct dls_kstats {
	kstat_named_t	dlss_soft_ring_pkt_drop;
};

extern struct dls_kstats dls_kstat;

#define	DLS_BUMP_STAT(x, y)	(dls_kstat.x.value.ui32 += y)

extern void soft_ring_init(void);
extern soft_ring_t *soft_ring_create(char *, processorid_t, clock_t,
    uint_t, pri_t);
extern soft_ring_t **soft_ring_set_create(char *, processorid_t, clock_t,
    uint_t, pri_t, int);
extern void soft_ring_bind(void *, processorid_t);
extern void soft_ring_unbind(void *);
extern void dls_soft_ring_fanout(void *, void *, mblk_t *, mac_header_info_t *);
extern boolean_t dls_soft_ring_enable(dls_channel_t, dl_capab_dls_t *);
extern void dls_soft_ring_disable(dls_channel_t);
extern boolean_t dls_soft_ring_workers(dls_channel_t);
extern void dls_soft_ring_rx_set(dls_channel_t, dls_rx_t, void *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DLS_SOFT_RING_H */
