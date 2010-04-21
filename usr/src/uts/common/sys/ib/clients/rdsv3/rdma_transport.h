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

#ifndef _RDSV3_RDMA_TRANSPORT_H
#define	_RDSV3_RDMA_TRANSPORT_H

#include "rdsv3.h"

#define	RDSV3_RDMA_RESOLVE_TIMEOUT_MS	5000

int rdsv3_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
    struct rdma_cm_event *event);

/* from rdma_transport.c */
void rdsv3_rdma_init();
void rdsv3_rdma_exit(void *);

/* from ib.c */
extern struct rdsv3_transport rdsv3_ib_transport;
int rdsv3_ib_init(void);
void rdsv3_ib_exit(void);

#endif /* _RDSV3_RDMA_TRANSPORT_H */
