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
 * Copyright 2015 Gary Mills
 */

#ifndef _STUBS_H
#define	_STUBS_H

/*
 * Functions defined in yptol/stubs.c needed elsewhere
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Put your definitions in here */
extern bool
init_lock_map();
extern int
lock_core(int);
extern int
unlock_core(int);

#ifdef __cplusplus
}
#endif

#endif /* _STUBS_H */
