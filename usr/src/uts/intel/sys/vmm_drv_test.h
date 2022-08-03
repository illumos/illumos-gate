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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _VMM_DRV_TEST_H_
#define	_VMM_DRV_TEST_H_

#define	VDT_IOC_BASE		(('V' << 16) | ('D' << 8))

#define	VDT_IOC_HOLD		(VDT_IOC_BASE | 0x01)
#define	VDT_IOC_RELE		(VDT_IOC_BASE | 0x02)

#endif /* _VMM_DRV_TEST_H_ */
