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

struct cpu;

extern void ht_init(void);
extern void ht_intr_alloc_pil(uint_t);

extern int ht_acquire(void);
extern void ht_release(void);
extern void ht_mark(void);
extern void ht_begin_unsafe(void);
extern void ht_end_unsafe(void);
extern void ht_begin_intr(uint_t);
extern void ht_end_intr(void);
extern void ht_mark_as_vcpu(void);

extern boolean_t ht_should_run(kthread_t *, struct cpu *);
extern pri_t ht_adjust_cpu_score(kthread_t *, struct cpu *, pri_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HT_H */
