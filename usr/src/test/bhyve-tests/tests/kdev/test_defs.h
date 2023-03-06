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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _TEST_DEFS_H_
#define	_TEST_DEFS_H_

#define	IOP_PMTMR	0x408
#define	IOP_ATPIT_C0	0x40
#define	IOP_ATPIT_CMD	0x43

#define	MMIO_HPET_BASE	0xfed00000UL
#define	MMIO_LAPIC_BASE	0xfee00000UL

#define	PMTMR_FREQ		3579545
#define	PMTMR_TARGET_TICKS	(PMTMR_FREQ / 10)

#define	HPET_FREQ		(1 << 24)
#define	HPET_TARGET_TICKS	(HPET_FREQ / 10)

#define	LAPIC_FREQ		(128 * 1024 * 1024)
#define	LAPIC_TARGET_TICKS	(LAPIC_FREQ / 50)

#define	ATPIT_FREQ		1193182
#define	ATPIT_TARGET_TICKS	(ATPIT_FREQ / 50)

#define	TSC_TARGET_WRVAL	500000000000

#endif /* _TEST_DEFS_H_ */
