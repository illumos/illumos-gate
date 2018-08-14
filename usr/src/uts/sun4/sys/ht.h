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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_SYS_HT_H
#define	_SYS_HT_H

#include <sys/types.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ht_init() {}

#define	ht_should_run(t, c) (B_TRUE)
#define	ht_adjust_cpu_score(t, c, p) (p)
#define	ht_begin_unsafe(void) {}
#define	ht_end_unsafe(void) {}
#define	ht_end_intr(void) {}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HT_H */
