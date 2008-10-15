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

#ifndef	_FMD_XPRT_H
#define	_FMD_XPRT_H


#include <pthread.h>
#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_module.h>
#include <fmd_list.h>

struct fmd_eventq;			/* see <fmd_eventq.h> */
struct fmd_thread;			/* see <fmd_thread.h> */
struct fmd_idspace;			/* see <fmd_idspace.h> */
struct fmd_log;				/* see <fmd_log.h> */

struct fmd_xprt_impl;			/* see below */

typedef void fmd_xprt_rule_f(struct fmd_xprt_impl *, nvlist_t *);

extern fmd_xprt_rule_f fmd_xprt_event_syn;
extern fmd_xprt_rule_f fmd_xprt_event_ack;
extern fmd_xprt_rule_f fmd_xprt_event_run;
extern fmd_xprt_rule_f fmd_xprt_event_sub;
extern fmd_xprt_rule_f fmd_xprt_event_unsub;
extern fmd_xprt_rule_f fmd_xprt_event_unsuback;
extern fmd_xprt_rule_f fmd_xprt_event_uuclose;
extern fmd_xprt_rule_f fmd_xprt_event_error;
extern fmd_xprt_rule_f fmd_xprt_event_drop;

typedef struct fmd_xprt_rule {
	const char *xr_class;		/* pattern to match */
	fmd_xprt_rule_f *xr_func;	/* action to invoke */
} fmd_xprt_rule_t;

extern const fmd_xprt_rule_t _fmd_xprt_state_syn[];
extern const fmd_xprt_rule_t _fmd_xprt_state_ack[];
extern const fmd_xprt_rule_t _fmd_xprt_state_err[];
extern const fmd_xprt_rule_t _fmd_xprt_state_sub[];
extern const fmd_xprt_rule_t _fmd_xprt_state_run[];

typedef struct fmd_xprt_stat {
	fmd_eventqstat_t xs_evqstat;	/* statistics for xprt event queue */
	fmd_stat_t xs_module;		/* module name associated with xprt */
	fmd_stat_t xs_authority;	/* authority associated with xprt */
	fmd_stat_t xs_state;		/* state name associated with xprt */
	fmd_stat_t xs_received;		/* number of events received by xprt */
	fmd_stat_t xs_discarded;	/* number of events discarded by xprt */
	fmd_stat_t xs_retried;		/* number of events retried by xprt */
	fmd_stat_t xs_replayed;		/* number of events replayed by xprt */
	fmd_stat_t xs_lost;		/* number of events lost by xprt */
	fmd_stat_t xs_timeouts;		/* number of events recv'd with ttl=0 */
	fmd_stat_t xs_subscriptions;	/* number of active subscriptions */
} fmd_xprt_stat_t;

typedef struct fmd_xprt_class {
	char *xc_class;			/* class string for subscription */
	uint_t xc_refs;			/* reference count for subscription */
	struct fmd_xprt_class *xc_next;	/* next class on xi_subhash chain */
} fmd_xprt_class_t;

typedef struct fmd_xprt_class_hash {
	fmd_eventq_t *xch_queue;	/* associated event queue (or NULL) */
	fmd_xprt_class_t **xch_hash;	/* subscription hash bucket array */
	uint_t xch_hashlen;		/* size of xch_hash bucket array */
} fmd_xprt_class_hash_t;

typedef struct fmd_xprt_impl {
	fmd_list_t xi_list;		/* linked list next/prev pointers */
	uint_t xi_version;		/* transport protocol version */
	uint_t xi_id;			/* transport identifier */
	struct fmd_eventq *xi_queue;	/* event queue for outbound events */
	struct fmd_thread *xi_thread;	/* thread associated with transport */
	const fmd_xprt_rule_t *xi_state; /* rules for the current state */
	nvlist_t *xi_auth;		/* authority for peer endpoint */
	void *xi_data;			/* data for xprt_get/setspecific */
	struct fmd_log *xi_log;		/* log for received events (optional) */
	pthread_mutex_t xi_stats_lock;	/* lock protecting xi_stats data */
	fmd_xprt_stat_t *xi_stats;	/* built-in per-transport statistics */
	pthread_mutex_t xi_lock;	/* lock for modifying members below */
	pthread_cond_t xi_cv;		/* condition variable for xi_flags */
	uint_t xi_flags;		/* flags (see below) */
	uint_t xi_busy;			/* active threads in xprt_recv() */
	fmd_xprt_class_hash_t xi_lsub;	/* subscriptions in local dispq */
	fmd_xprt_class_hash_t xi_rsub;	/* subscriptions in remote peer */
	fmd_xprt_class_hash_t xi_usub;	/* pending remote unsubscriptions */
} fmd_xprt_impl_t;

/*
 * Flags for fmd_xprt_create() and xi_flags.  NOTE: Any public API flags must
 * exactly match the corresponding definitions in <fmd_api.h>.
 */
#define	FMD_XPRT_RDONLY		0x1	/* xprt is read-only */
#define	FMD_XPRT_RDWR		0x3	/* xprt is read-write */
#define	FMD_XPRT_ACCEPT		0x4	/* xprt is accepting connection */
#define	FMD_XPRT_SUSPENDED	0x8	/* xprt is suspended by user */
#define	FMD_XPRT_CMASK		0xF	/* xprt create flag mask */
#define	FMD_XPRT_SUBSCRIBER	0x10	/* xprt is actively subscribing */
#define	FMD_XPRT_ISUSPENDED	0x20	/* xprt is waiting for _fmd_init */
#define	FMD_XPRT_DSUSPENDED	0x40	/* xprt is suspended by fmd mechanism */

#define	FMD_XPRT_SMASK	\
	(FMD_XPRT_SUSPENDED | FMD_XPRT_ISUSPENDED | FMD_XPRT_DSUSPENDED)

extern fmd_xprt_t *fmd_xprt_create(fmd_module_t *, uint_t, nvlist_t *, void *);
extern void fmd_xprt_destroy(fmd_xprt_t *);
extern void fmd_xprt_xsuspend(fmd_xprt_t *, uint_t);
extern void fmd_xprt_xresume(fmd_xprt_t *, uint_t);
extern void fmd_xprt_send(fmd_xprt_t *);
extern void fmd_xprt_recv(fmd_xprt_t *, nvlist_t *, hrtime_t, boolean_t);
extern void fmd_xprt_uuclose(fmd_xprt_t *, const char *);

extern void fmd_xprt_subscribe(fmd_xprt_t *, const char *);
extern void fmd_xprt_unsubscribe(fmd_xprt_t *, const char *);
extern void fmd_xprt_subscribe_all(const char *);
extern void fmd_xprt_unsubscribe_all(const char *);
extern void fmd_xprt_suspend_all(void);
extern void fmd_xprt_resume_all(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_XPRT_H */
