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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_SYS_SMT_H
#define	_SYS_SMT_H

#include <sys/types.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	smt_init() {}
#define	smt_late_init() {}
#define	smt_disable() (ENOTSUP)
#define	smt_can_enable(c, f) (0)
#define	smt_force_enabled() {}

#define	smt_should_run(t, c) (B_TRUE)
#define	smt_adjust_cpu_score(t, c, p) (p)
#define	smt_begin_unsafe(void) {}
#define	smt_end_unsafe(void) {}
#define	smt_end_intr(void) {}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SMT_H */
