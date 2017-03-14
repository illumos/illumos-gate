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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_CP_DEFS_H_
#define	_CP_DEFS_H_

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct comm_page;
typedef struct comm_page comm_page_t;

extern uint_t __cp_can_gettime(comm_page_t *);
extern hrtime_t __cp_gethrtime(comm_page_t *);
extern int __cp_clock_gettime_realtime(comm_page_t *, timespec_t *);
extern int __cp_clock_gettime_monotonic(comm_page_t *, timespec_t *);
extern uint_t __cp_getcpu(comm_page_t *cp);

#ifdef	__cplusplus
}
#endif
#endif /* _CP_DEFS_H_ */
