/*
 * This file contains definitions imported from the OFED rds header loop.h.
 * Oracle elects to have and use the contents of loop.h under and
 * governed by the OpenIB.org BSD license.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _RDSV3_LOOP_H
#define	_RDSV3_LOOP_H

/* loop.c */
extern struct rdsv3_transport rdsv3_loop_transport;

void rdsv3_loop_exit(void);

#endif /* _RDSV3_LOOP_H */
