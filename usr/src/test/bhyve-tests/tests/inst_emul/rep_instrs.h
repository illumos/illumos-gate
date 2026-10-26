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
 * Copyright 2026 Edgecast Cloud LLC.
 */

#ifndef _REP_INSTRS_H_
#define	_REP_INSTRS_H_

/*
 * Guest addresses, each at the start of a 2MiB page, which the test runner
 * marks not-present so that rep-prefixed instructions fault part-way through
 * their iterations.  A separate page is used for each instruction so that no
 * stale guest TLB state can carry from one test to the next.
 */
#define	INS_FAULT_ADDR	0x1000000
#define	MOVS_FAULT_ADDR	0x1200000

#define	PF_VECTOR	14

#endif	/* _REP_INSTRS_H_ */
