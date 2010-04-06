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

#ifndef _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_QP_H
#define	_SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_QP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NAME: sol_uverbs_qp.h
 *
 * DESC: OFED User Verbs Kernel Queue Pair structures and definitions
 *
 */

/*
 * Definitions
 */
#define	IBT_TO_OFA_QP_STATE(_state)  ((_state) < IBT_STATE_SQDRAIN ?   \
						(_state) : IBT_STATE_SQD)

/*
 * Structures
 */

/*
 * Functions - See sol_uverbs_qp.c for descriptions
 */
int sol_uverbs_create_qp(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_destroy_qp(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_modify_qp(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_query_qp(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_create_srq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_modify_srq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_query_srq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_destroy_srq(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_attach_mcast(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

int sol_uverbs_detach_mcast(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
								int out_len);

void uverbs_detach_uqp_mcast_entries(uverbs_uqp_uobj_t *uqp);

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_QP_H */
