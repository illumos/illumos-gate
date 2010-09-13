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

/*
 * etm_iosvc.h
 *
 * Header file of the support for io service ldom
 *
 */

#ifndef _ETM_IO_SVC_H
#define	_ETM_IO_SVC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ------------------------------ includes -----------------------------------
 */

#include <sys/fm/protocol.h>
#include <sys/libds.h>
#include <sys/fm/ldom.h>
#include <fm/fmd_api.h>
#include "etm_xport_api.h"
#include "etm_etm_proto.h"

#include <libnvpair.h>

#include <pthread.h>

#define	FORWARDING_FAULTS_TO_CONTROL 0	/* not to forward faults to control */
#define	ASYNC_EVENT_Q_SIZE 	100	/* size of the async event q */
#define	NUM_OF_ROOT_DOMAINS 	8	/* size of iosvc_list structure array */
#define	MAXLEN 			0x6000	/* max size of an FMA event */
#define	FMD_EVN_TTL		"__ttl"	/* name-value pair for ev_ttl */

typedef enum {

	ETM_ASYNC_EVENT_TOO_LOW = 0,	/* range check place holder */
	ETM_ASYNC_EVENT_LDOM_BIND,	/* async event type: ldom event */
	ETM_ASYNC_EVENT_LDOM_UNBIND,	/* async event type: ldom event */
	ETM_ASYNC_EVENT_LDOM_ADD,	/* async event type: ldom event */
	ETM_ASYNC_EVENT_LDOM_REMOVE,	/* async event type: ldom event */
	ETM_ASYNC_EVENT_DS_REG_CB,	/* async event type: DS reg callback */
	ETM_ASYNC_EVENT_DS_UNREG_CB,	/* async event type: DS unreg cllback */
	ETM_ASYNC_EVENT_TOO_BIG		/* range check place holder */

} etm_async_event_type_t;		/* async etm event type */


typedef enum {

	SP_MSG = 0,			/* msg for ereports from SP */
	FMD_XPRT_OTHER_MSG,		/* fmd all other xprt msg */
	FMD_XPRT_RUN_MSG		/* fmd xprt run msg */

} etm_pack_msg_type_t;			/* msg type for etm_pack_ds_msg() */

typedef struct etm_iosvc_q_ele {

	char			*msg;		/* ptr to ETM io svc msg */
	size_t			msg_size;	/* sizeof ETM io svc msg */
	uint_t			ckpt_flag;	/* checkpoint flags */

	struct etm_iosvc_q_ele	*msg_nextp;	/* PRIVATE - next ele ptr */

} etm_iosvc_q_ele_t;			/* out-going etm msg queue element */



typedef struct etm_iosvc {
	char 		ldom_name[MAX_LDOM_NAME];	/* ldom_name */
	pthread_cond_t	msg_q_cv;	/* nudges send msg func more to send  */
	pthread_mutex_t	msg_q_lock;	/* protects iosvc msg Q */
	etm_iosvc_q_ele_t
			*msg_q_head;
					/* ptr to cur head of the msg Q */
	etm_iosvc_q_ele_t
			*msg_q_tail;
					/* ptr to cur tail of the msg Q */
	uint32_t	msg_q_cur_len;
					/* cur len of the msg Q */
	uint32_t	msg_q_max_len;
					/* max len of the msg Q */
	uint32_t	cur_send_xid;	/* current trnsaction id for io svc q */
	uint32_t	xid_posted_ev;	/* xid of last event posted ok to fmd */
	ds_hdl_t	ds_hdl;		/* the ds hdl for this io svc ldom */
	fmd_xprt_t	*fmd_xprt;	/* fmd transport layer handle */
	pthread_t	send_tid;	/* tid of sending msgs 2 remote iosvc */
	pthread_t	recv_tid;	/* tid of recving msgs frm rmte iosvc */
	pthread_cond_t	msg_ack_cv;	/* ready 2 send nxt or resend cur one */
	pthread_mutex_t	msg_ack_lock;	/* protects msg_ack_cv */
	int		thr_is_dying;	/* flag to exit the thread */
	uint32_t	start_sending_Q;	/* flag to strt sending msg Q */
	uint32_t	ack_ok;		/* indicate if the ACK has come  */
} etm_iosvc_t;		/* structure to support io service ldom */


typedef struct etm_async_event_ele {

	etm_async_event_type_t	event_type;	/* async event type */
	ds_hdl_t		ds_hdl;		/* ds handle */
	char 			ldom_name[MAX_LDOM_NAME];	/* ldom name */
	ds_domain_hdl_t		dhdl;		/* ldom handle */

	struct etm_async_event_ele	*async_event_nextp;
						/* next ele ptr */

} etm_async_event_ele_t;	/* etm async event queue element */


/*
 * This function
 */
extern etm_iosvc_t *etm_iosvc_lookup(fmd_hdl_t *fmd_hdl, char *ldom_name,
    ds_hdl_t ds_hdl, boolean_t iosvc_create);


/*
 * extern etm_iosvc_t *etm_lookup_iosvc(char *ldom_name);
 */
extern int etm_pack_ds_msg(fmd_hdl_t *fmd_hdl, etm_iosvc_t *iosvc,
    etm_proto_v1_ev_hdr_t *ev_hdrp, size_t hdr_sz, nvlist_t *evp,
    etm_pack_msg_type_t msg_type, uint_t ckpt_opt);

#ifdef __cplusplus
}
#endif

#endif /* _ETM_IO_SVC_H */
