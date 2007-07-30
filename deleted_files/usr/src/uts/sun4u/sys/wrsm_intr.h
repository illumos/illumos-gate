/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_WRSM_INTR_H
#define	_WRSM_INTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM

#include <sys/wrsm_common.h>
#include <sys/wrsm_cmmu.h>
#include <sys/processor.h>
#include <sys/rsm/rsmpi.h>

#endif /* _ASM */

#ifdef __cplusplus
extern "C" {
#endif

/* Limit for rsm_intr_t */
#define	WRSM_INTR_TYPE_MAX	RSM_INTR_T_NSVC
#define	WRSM_TL_INTR_TYPE	(RSM_INTR_T_DRV_BASE + 1) /* transport */
#define	WRSM_SMPUT_INTR_TYPE	(RSM_INTR_T_DRV_BASE + 2) /* small put */

/* Flags for wrsm_intr_create_recvq */
#define	WRSM_CREATE_RECVQ_NOFLAGS	0x0
#define	WRSM_CREATE_RECVQ_SLEEP		0x1
#define	WRSM_CREATE_RECVQ_USER		0x2
#define	WRSM_CREATE_RECVQ_INVALID	0x4

/* Default value for is_wait in wrsm_intr_send() */
#define	WRSM_INTR_WAIT_DEFAULT	-1

#ifndef _ASM

/*
 * Receive Queue structures
 */
struct wrsm_intr_recvq;
typedef struct wrsm_intr_recvq wrsm_intr_recvq_t;

/*
 * Client functions
 */

/* Initialize the interrupt component for this network */
int wrsm_intr_init(wrsm_network_t *);

/* Destroy the interrupt component for this network */
void wrsm_intr_fini(wrsm_network_t *);

/* The following prints all intr data structures, for debug only */
void wrsm_intr_print(wrsm_network_t *);

/*
 * WCI Functions
 */

/* Inform the interrupt component of a new WCI. Returns -1 if add_intr fails */
int wrsm_intr_newwci(wrsm_network_t *, lcwci_handle_t);

/* Inform the interrupt component that a WCI is going away */
void wrsm_intr_delwci(wrsm_network_t *, lcwci_handle_t);

/*
 * Handler Management Functions
 */

/* Registers a handler for a specific interrupt type - rsmpi function */
int wrsmrsm_register_handler(rsm_controller_handle_t,
    rsm_controller_object_t *controller_obj, rsm_intr_t type, rsm_intr_hand_t,
    rsm_intr_hand_arg_t, rsm_addr_t senders_list[],
    uint_t senders_list_length);

/* Registers a handler for a specific interrupt type - driver function */
int wrsm_register_handler(wrsm_network_t *,
    rsm_controller_object_t *controller_obj, rsm_intr_t type, rsm_intr_hand_t,
    rsm_intr_hand_arg_t, rsm_addr_t senders_list[],
    uint_t senders_list_length);

/* Unregisters a handler - rsmpi function */
int wrsmrsm_unregister_handler(rsm_controller_handle_t, rsm_intr_t type,
    rsm_intr_hand_t, rsm_intr_hand_arg_t);

/* Unregisters a handler - driver function */
int wrsm_unregister_handler(wrsm_network_t *, rsm_intr_t type, rsm_intr_hand_t,
    rsm_intr_hand_arg_t);

/*
 * Receive Queue Functions
 */

/*
 * Creates a receive queue of a given type. User must have allocated a
 * CMMU tuple in advance.
 */
int wrsm_intr_create_recvq(wrsm_network_t *, rsm_intr_t type,
    size_t num_packets, wrsm_cmmu_index_t cmmu_index, wrsm_intr_recvq_t **,
    cnodeid_t from_cnode, void *exportseg, int flags);

/* Destroys the receive queue. Caller must free the CMMU tuple. */
void wrsm_intr_destroy_recvq(wrsm_network_t *, wrsm_intr_recvq_t *);

/* Flushes in progress interrupts for the receive queue. */
void wrsm_intr_flush_recvq(wrsm_intr_recvq_t *);

/* Sends a message */
int wrsm_intr_send(wrsm_network_t *, void *remote_addr, cnodeid_t remote_cnode,
    void *aligned_buf, int is_flags, clock_t is_wait, int sendq_flags);

/*
 * RSMPI Functions
 */

/* Initializes RSMPI portions of intr */
void wrsm_intr_rsminit(wrsm_network_t *);

/* Cleans-up RSMPI portions of intr */
void wrsm_intr_rsmfini(wrsm_network_t *);

/* Creates a send queue */
int wrsm_sendq_create(rsm_controller_handle_t, rsm_addr_t, rsm_intr_t,
    rsm_intr_pri_t, size_t qdepth, uint_t flags, rsm_resource_callback_t,
    rsm_resource_callback_arg_t, rsm_send_q_handle_t *);

/* Reconfigure some of the attributes of an interrupt queue */
int wrsm_sendq_config(rsm_send_q_handle_t, rsm_intr_pri_t, size_t qdepth,
    uint_t flags, rsm_resource_callback_t, rsm_resource_callback_arg_t);

/* Destroys an interrupt queue, freeing all resources allocated */
int wrsm_sendq_destroy(rsm_send_q_handle_t);

/* Enqueues a datagram on an interrupt queue */
int wrsm_send(rsm_send_q_handle_t, rsm_send_t *, rsm_barrier_t *);

/*
 * Performs a 64-byte block remote read.
 * Assumes source addressis 64-byte aligned, and does no checking.
 */
void wrsm_blkread(void *src, void *dst, size_t num_blocks);
/*
 * Performs a 64-byte block write.
 * Assumes destination address is 64-byte aligned, and does no checking.
 */
void wrsm_blkwrite(void *src, void *dst, size_t num_blocks);

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_INTR_H */
