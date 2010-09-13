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

#ifndef _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_EVENT_H
#define	_SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 * NAME: sol_uverbs_event.h
 *
 * DESC: Solaris User Verbs Kernel Async Event structures and definitions.
 *
 */


/*
 * Functions - See sol_uverbs_event.c for descriptions.
 */
uverbs_ufile_uobj_t *uverbs_alloc_event_file(uverbs_uctxt_uobj_t *uctxt,
    int is_async);

void uverbs_release_event_file(sol_ofs_uobj_t *uobj);

void uverbs_async_event_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event);

void uverbs_release_ucq_channel(uverbs_uctxt_uobj_t *uctxt,
    uverbs_ufile_uobj_t *comp_chan, uverbs_ucq_uobj_t *ucq);

void uverbs_release_ucq_uevents(uverbs_ufile_uobj_t *ev_file,
    uverbs_ucq_uobj_t *ucq);

void uverbs_release_uqp_uevents(uverbs_ufile_uobj_t *ev_file,
    uverbs_uqp_uobj_t *uqp);

void uverbs_release_usrq_uevents(uverbs_ufile_uobj_t *ev_file,
    uverbs_usrq_uobj_t *usrq);

void sol_uverbs_event_file_close(uverbs_ufile_uobj_t *);

int sol_uverbs_event_file_read(uverbs_ufile_uobj_t *, struct uio *uiop,
    cred_t *cred);

int sol_uverbs_event_file_poll(uverbs_ufile_uobj_t *, short events, int anyyet,
    short *reventsp, pollhead_t **phpp);

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_EVENT_H */
