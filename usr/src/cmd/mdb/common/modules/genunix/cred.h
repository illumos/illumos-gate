/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_MDB_CRED_H
#define	_MDB_CRED_H

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

int cmd_cred(uintptr_t, uint_t, int, const mdb_arg_t *);
int cmd_credgrp(uintptr_t, uint_t, int, const mdb_arg_t *);
int cmd_credsid(uintptr_t, uint_t, int, const mdb_arg_t *);
int cmd_ksidlist(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_CRED_H */
