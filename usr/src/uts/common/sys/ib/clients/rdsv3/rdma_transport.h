/*
 * This file contains definitions imported from the OFED rds header
 * rdma_transport.h. Oracle elects to have and use the contents of
 * rdma_transport.h under and governed by the OpenIB.org BSD license.
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
