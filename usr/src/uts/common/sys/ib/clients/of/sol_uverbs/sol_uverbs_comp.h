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

#ifndef _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_COMP_H
#define	_SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_COMP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 * NAME: sol_uverbs_comp.h
 *
 * DESC: OFED User Verbs Kernel Completion Queue related defines and structures.
 *
 */


/*
 * Definitions
 */

/*
 * Structures
 */

/*
 * Functions - See sol_uverbs_comp.c for descriptions.
 */
int
sol_uverbs_create_cq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int
sol_uverbs_destroy_cq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int
sol_uverbs_resize_cq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int
sol_uverbs_req_notify_cq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int
sol_uverbs_poll_cq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

void
sol_uverbs_comp_event_handler(ibt_cq_hdl_t ibt_cq, void *arg);

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_COMP_H */
