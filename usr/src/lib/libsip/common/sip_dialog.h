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

#ifndef	_SIP_DIALOG_H
#define	_SIP_DIALOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <sip.h>
#include <sys/types.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"

/*
 * Dialogs are linked in their own list.
 */


/* This is always done within sip_dlg_mutex */
#define	SIP_DLG_REFCNT_INCR(dialog)					\
	(dialog)->sip_dlg_ref_cnt++;

#define	SIP_DLG_REFCNT_DECR(dialog)	 {				\
	(void) pthread_mutex_lock(&((dialog)->sip_dlg_mutex));		\
	assert((dialog)->sip_dlg_ref_cnt > 0);				\
	(dialog)->sip_dlg_ref_cnt--;					\
	if ((dialog)->sip_dlg_ref_cnt == 0 &&				\
	    (dialog)->sip_dlg_state == SIP_DLG_DESTROYED) {		\
		(void) pthread_mutex_unlock(&((dialog)->sip_dlg_mutex)); \
		sip_dialog_delete(dialog);				\
	} else {							\
		(void) pthread_mutex_unlock(&((dialog)->sip_dlg_mutex));\
	}								\
}

/* The dialog structure */
typedef struct sip_dialog
{
	_sip_header_t		*sip_dlg_remote_uri_tag;
	_sip_header_t		*sip_dlg_local_uri_tag;
	_sip_header_t		*sip_dlg_remote_target;
	_sip_header_t		*sip_dlg_local_contact;
	_sip_header_t		*sip_dlg_new_local_contact; /* for re-INVITE */
	_sip_header_t		*sip_dlg_route_set;
	_sip_header_t		*sip_dlg_event;
	sip_str_t		sip_dlg_rset;
	sip_str_t		sip_dlg_req_uri;
	_sip_header_t		*sip_dlg_call_id;
	uint32_t		sip_dlg_local_cseq;
	uint32_t		sip_dlg_remote_cseq;
	uint16_t		sip_dlg_id[8];
	boolean_t		sip_dlg_secure;
	dialog_state_t		sip_dlg_state;
	int			sip_dlg_type;	/* CALLEE or CALLER */
	pthread_mutex_t		sip_dlg_mutex;
	uint32_t		sip_dlg_ref_cnt;
	sip_timer_t		sip_dlg_timer;	/* to delete partial dialogs */
	boolean_t		sip_dlg_on_fork;
	sip_method_t		sip_dlg_method;
	void			*sip_dlg_ctxt;	/* currently unused */
	int			sip_dlg_msgcnt;
	sip_log_t		sip_dlg_log[SIP_DLG_DESTROYED + 1];
} _sip_dialog_t;

void			sip_dialog_init(void (*sip_ulp_dlg_del)(sip_dialog_t,
			    sip_msg_t, void *),
			    void (*ulp_dlg_state)(sip_dialog_t, sip_msg_t,
			    int, int));
sip_dialog_t		sip_dialog_create(_sip_msg_t *, _sip_msg_t *, int);
sip_dialog_t		sip_dialog_find(_sip_msg_t *);
int			sip_dialog_process(_sip_msg_t *, sip_dialog_t *);
sip_dialog_t		sip_update_dialog(sip_dialog_t, _sip_msg_t *);
void			sip_dialog_add_new_contact(sip_dialog_t, _sip_msg_t *);
void			sip_dialog_terminate(sip_dialog_t, sip_msg_t);
sip_dialog_t		sip_seed_dialog(sip_conn_object_t, _sip_msg_t *,
			    boolean_t, int);
char			*sip_dialog_req_uri(sip_dialog_t);
void			sip_dialog_delete(_sip_dialog_t *);
extern char		*sip_get_dialog_state_str(int);
extern boolean_t	sip_incomplete_dialog(sip_dialog_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_DIALOG_H */
