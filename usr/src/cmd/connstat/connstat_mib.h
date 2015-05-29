/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#ifndef	_CONNSTAT_MIB_H
#define	_CONNSTAT_MIB_H

#include "connstat.h"

#ifdef	__cplusplus
extern "C" {
#endif

int mibopen(const char *);
int conn_walk(int, connstat_proto_t *, conn_walk_state_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _CONNSTAT_MIB_H */
