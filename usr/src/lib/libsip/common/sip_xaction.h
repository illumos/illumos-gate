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

#ifndef	_SIP_XACTION_H
#define	_SIP_XACTION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <sip.h>
#include <sys/types.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"

/* Various transaction timers */
typedef enum sip_timer_type_s {
	SIP_XACTION_TIMER_A = 0,
	SIP_XACTION_TIMER_B,
	SIP_XACTION_TIMER_D,
	SIP_XACTION_TIMER_E,
	SIP_XACTION_TIMER_F,
	SIP_XACTION_TIMER_G,
	SIP_XACTION_TIMER_H,
	SIP_XACTION_TIMER_I,
	SIP_XACTION_TIMER_J,
	SIP_XACTION_TIMER_K
} sip_xaction_timer_type_t;


/* Increment transaction reference count */
#define	SIP_XACTION_REFCNT_INCR(trans)	\
	(trans)->sip_xaction_ref_cnt++;

/* Decrement transaction reference count */
#define	SIP_XACTION_REFCNT_DECR(trans)	{				\
	(void) pthread_mutex_lock(&((trans)->sip_xaction_mutex));	\
	assert((trans)->sip_xaction_ref_cnt > 0);			\
	(trans)->sip_xaction_ref_cnt--;					\
	if ((trans)->sip_xaction_ref_cnt == 0 && 			\
	    SIP_IS_XACTION_TERMINATED((trans)->sip_xaction_state)) {	\
		(void) pthread_mutex_unlock(&((trans)->sip_xaction_mutex));\
		sip_xaction_delete(trans);				\
	} else {							\
		(void) pthread_mutex_unlock(&((trans)->sip_xaction_mutex));\
	}								\
}

/* True if transaction is in the terminated state */
#define	SIP_IS_XACTION_TERMINATED(trans_state)				\
	((trans_state) == SIP_CLNT_INV_TERMINATED ||			\
	(trans_state) == SIP_CLNT_NONINV_TERMINATED	||		\
	(trans_state) == SIP_SRV_INV_TERMINATED ||			\
	(trans_state) == SIP_SRV_NONINV_TERMINATED)

/* Transaction structure */
typedef struct sip_xaction {
	char			*sip_xaction_branch_id;	/* Transaction id */
	uint16_t		sip_xaction_hash_digest[8];
	_sip_msg_t		*sip_xaction_orig_msg;	/* orig request msg. */
	_sip_msg_t		*sip_xaction_last_msg;	/* last msg sent */
	sip_conn_object_t	sip_xaction_conn_obj;
	int			sip_xaction_state;  /* Transaction State */
	sip_method_t		sip_xaction_method;
	uint32_t		sip_xaction_ref_cnt;
	pthread_mutex_t		sip_xaction_mutex;
	sip_timer_t		sip_xaction_TA;
	sip_timer_t		sip_xaction_TB;
	sip_timer_t		sip_xaction_TD;
	sip_timer_t		sip_xaction_TE;
	sip_timer_t		sip_xaction_TF;
	sip_timer_t		sip_xaction_TG;
	sip_timer_t		sip_xaction_TH;
	sip_timer_t		sip_xaction_TI;
	sip_timer_t		sip_xaction_TJ;
	sip_timer_t		sip_xaction_TK;
	void			*sip_xaction_ctxt;	/* currently unused */
	int			sip_xaction_msgcnt;
	sip_log_t		sip_xaction_log[SIP_SRV_NONINV_TERMINATED + 1];
} sip_xaction_t;

extern void		sip_xaction_init(int (*ulp_trans_err)(sip_transaction_t,
			    int, void *), void (*ulp_state_cb)
			    (sip_transaction_t, sip_msg_t, int, int));
extern int		sip_xaction_output(sip_conn_object_t, sip_xaction_t *,
			    _sip_msg_t *);
extern int		sip_xaction_input(sip_conn_object_t, sip_xaction_t *,
			    _sip_msg_t **);
extern sip_xaction_t	*sip_xaction_get(sip_conn_object_t, sip_msg_t,
			    boolean_t, int, int *);
extern void		sip_xaction_delete(sip_xaction_t *);
extern char		*sip_get_xaction_state(int);
extern int 		(*sip_xaction_ulp_trans_err)(sip_transaction_t, int,
			    void *);
extern void 		(*sip_xaction_ulp_state_cb)(sip_transaction_t,
			    sip_msg_t, int, int);
extern void		sip_del_conn_obj_cache(sip_conn_object_t, void *);
extern int		sip_add_conn_obj_cache(sip_conn_object_t, void *);
extern void		sip_xaction_terminate(sip_xaction_t *, _sip_msg_t *,
			    int);
#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_XACTION_H */
