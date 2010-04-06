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

/*
 * This header file contains definations for APIs which are exported by
 * sol_uverbs for use by sol_ucma
 */
#ifndef	_SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS2UCMA_H
#define	_SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS2UCMA_H

#ifdef __cplusplus
extern "C" {
#endif

#define	SOL_UCMA_UVERBS_PATH	"/ib/sol_uverbs@0:ucma"

/*
 * This API returns the IB & iWARP client handles that sol_uverbs uses
 * to interact with Solaris IBTF and iWARP frameworks.
 */
#define	SOL_UVERBS_GET_CLNT_HDL	"sol_uverbs_get_clnt_hdl"
typedef void	(*uverbs_get_clnt_hdl_t) (void **, void **);

/*
 * This API returns the QP handle used by Solaris IBTF / iWARP framework
 * for an QP. The QP number is the input for this API. NULL is returned
 * for QP not allocated by sol_uverbs.
 */
#define	SOL_UVERBS_QPNUM2QPHDL	"sol_uverbs_qpnum2qphdl"
typedef void	*(*uverbs_qpnum2qphdl_t) (uint32_t);

/*
 * This API disables user QP modifies for an QP specified by the input
 * QP number. It returns 0 on succcess and non-0 on failure.
 */
#define	SOL_UVERBS_DISABLE_UQPN_MODIFY	"sol_uverbs_disable_uqpn_modify"
typedef int	(*uverbs_disable_uqpn_mod_t)(uint32_t);

/*
 * This API enables / disables CQ notification for all CQs assosiated
 * with the QP. This is done to ensure that the first completion event
 * is send to userland *after* connection is established.
 */
typedef enum {
	SOL_UVERBS2UCMA_CQ_NOTIFY_NOT_SET = 0,
	SOL_UVERBS2UCMA_CQ_NOTIFY_ENABLE,
	SOL_UVERBS2UCMA_CQ_NOTIFY_DISABLE
} sol_uverbs_cq_ctrl_t;
#define	SOL_UVERBS_UQPN_CQ_CTRL	"sol_uverbs_uqpn_cq_ctrl"
typedef int	(*uverbs_uqpn_cq_ctrl_t)(uint32_t, sol_uverbs_cq_ctrl_t);

/*
 * This API sets the QP free state. The uint32_t uqpid is passed for
 * disabling QP free and void *qphdl is passed for enabling QP free.
 */
typedef enum {
	SOL_UVERBS2UCMA_ENABLE_QP_FREE,
	SOL_UVERBS2UCMA_DISABLE_QP_FREE,
	SOL_UVERBS2UCMA_FREE_PENDING
} sol_uverbs_qp_free_state_t;
#define	SOL_UVERBS_SET_QPFREE_STATE	"sol_uverbs_set_qp_free_state"
typedef void	(*uverbs_set_qp_free_state_t)(sol_uverbs_qp_free_state_t,
    uint32_t, void *);

/*
 * This API flushes the QP specified by the QP num
 */
#define	SOL_UVERBS_FLUSH_QP		"sol_uverbs_flush_qp"
typedef void	(*uverbs_flush_qp_t)(uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS2UCMA_H */
