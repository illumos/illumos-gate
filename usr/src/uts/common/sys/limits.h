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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LIMITS_H
#define	_SYS_LIMITS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	IOV_MAX	1024

#ifdef _KERNEL
#define	IOV_MAX_STACK	16	/* max. IOV on-stack allocation */
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LIMITS_H */
