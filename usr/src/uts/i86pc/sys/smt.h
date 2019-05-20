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

struct cpu;

extern int smt_boot_disable;

extern void smt_init(void);
extern void smt_late_init(void);
extern int smt_disable(void);
extern boolean_t smt_can_enable(struct cpu *, int);
extern void smt_force_enabled(void);

extern void smt_intr_alloc_pil(uint_t);

extern int smt_acquire(void);
extern void smt_release(void);
extern void smt_mark(void);
extern void smt_begin_unsafe(void);
extern void smt_end_unsafe(void);
extern void smt_begin_intr(uint_t);
extern void smt_end_intr(void);
extern void smt_mark_as_vcpu(void);

extern boolean_t smt_should_run(kthread_t *, struct cpu *);
extern pri_t smt_adjust_cpu_score(kthread_t *, struct cpu *, pri_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SMT_H */
