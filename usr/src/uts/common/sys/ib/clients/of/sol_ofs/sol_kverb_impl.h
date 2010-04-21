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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_CLIENTS_OF_SOL_OFS_SOL_KVERB_IMPL_H
#define	_SYS_IB_CLIENTS_OF_SOL_OFS_SOL_KVERB_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/ibtl/ibvti.h>

/*
 * If there is yet an active async event, hdl is not freed. However,
 * if the device state is IB_DEV_CLOSE, the device is about to be closed
 * so that the event should be discarded.
 */
#define	FIRE_QP_EVENT(clnt, hdl, ib_event, qpp, type)			\
		rw_enter(&clnt->lock, RW_READER);			\
		if (qpp && qpp->event_handler &&			\
		    qpp->device->reg_state == IB_DEV_OPEN) {		\
			ib_event.device = qpp->device;			\
			ib_event.event = type;				\
			ib_event.element.qp = qpp;			\
			qpp->event_handler(&ib_event, qpp->qp_context);	\
		}							\
		rw_exit(&clnt->lock)

#define	FIRE_CQ_EVENT(clnt, hdl, ib_event, cqp, type)			\
		rw_enter(&clnt->lock, RW_READER);			\
		if (cqp && cqp->event_handler &&			\
		    cqp->device->reg_state == IB_DEV_OPEN) {		\
			ib_event.device = cqp->device;			\
			ib_event.event = type;				\
			ib_event.element.cq = cqp;			\
			cqp->event_handler(&ib_event, cqp->cq_context);	\
		}							\
		rw_exit(&clnt->lock)

#define	IBTF2OF_PGSZ(hca_page_sz)	((hca_page_sz) << 10)
#define	OF2IBTF_STATE(s)		((enum ibt_cep_state_e)(s))
#define	OF2IBTF_SRATE(r)		((enum ibt_srate_e)(r))
#define	OF2IBTF_PATH_MIG_STATE(s)	((ibt_cep_cmstate_t)((s)+1))
#define	OF2IBTF_PATH_MTU(m)		((ib_mtu_t)(m))

typedef unsigned int gfp_t;

typedef struct sol_ofs_client_s {
	ib_client_t		*ib_client;
	ibt_clnt_modinfo_t	ibt_client;
	ibt_clnt_hdl_t		ibt_hdl;
	uint_t			hca_num;
	uint_t			hca_open_num;
	llist_head_t		device_list;
	llist_head_t		client_list;
	krwlock_t		lock;
	enum {
				IB_OFS_CLNT_UNINITIALIZED,
				IB_OFS_CLNT_INITIALIZED
	} state;
} ofs_client_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IB_CLIENTS_OF_SOL_OFS_SOL_KVERB_IMPL_H */
