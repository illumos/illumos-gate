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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef	_MDB_GCORE_H
#define	_MDB_GCORE_H

#ifdef __cplusplus
extern "C" {
#endif

extern void gcore_init(void);
extern int gcore_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef __cplusplus
}
#endif

#endif /* _MDB_GCORE_H */
