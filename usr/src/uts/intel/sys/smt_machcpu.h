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
 * Copyright 2022 Oxide Computer Company
 */

#ifndef	_SYS_SMT_MACHCPU_H
#define	_SYS_SMT_MACHCPU_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The SMT exclusion logic requires `struct cpu_smt` be present in
 * `struct machcpu` as the field `mcpu_smt`.  It is defined here, on its own, so
 * it may be easily included by the relevant machine architecture(s).
 */
typedef struct cpu_smt {
	lock_t cs_lock;
	char cs_pad[56];
	struct cpu *cs_sib;
	volatile uint64_t cs_intr_depth;
	volatile uint64_t cs_state;
	volatile uint64_t cs_sibstate;
} cpu_smt_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SMT_MACHCPU_H */
