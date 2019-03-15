/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_SDT_H
#define	_SYS_SDT_H

#include <sys/stdint.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DTrace SDT probes have different signatures in userland than they do in
 * kernel.  If we're compiling for user mode (libfksmbsrv) define them as
 * either no-op (for the SMB dtrace provider) or libfksmbsrv functions for
 * the other SDT probe sites.
 */
#ifndef	_KERNEL

extern void smb_dtrace1(const char *, long);
extern void smb_dtrace2(const char *, long, long);
extern void smb_dtrace3(const char *, long, long, long);

/*
 * These are for the few (specialized) dtrace SDT probes sprinkled
 * through the smbclnt code.  In libfknsmb map these to functions.
 */

#undef	DTRACE_PROBE1
#define	DTRACE_PROBE1(n, t1, a1) \
	smb_dtrace1(#n, (long)a1)

#undef	DTRACE_PROBE2
#define	DTRACE_PROBE2(n, t1, a1, t2, a2) \
	smb_dtrace2(#n, (long)a1, (long)a2)

#undef	DTRACE_PROBE3
#define	DTRACE_PROBE3(n, t1, a1, t2, a2, t3, a3) \
	smb_dtrace3(#n, (long)a1, (long)a2, (long)a3)

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif
#endif	/* _SYS_SDT_H */
