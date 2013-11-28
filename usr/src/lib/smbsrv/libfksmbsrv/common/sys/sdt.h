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
#include <fksmb_dt.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#error "libfksmbsrv/common/sys/sdt.h in kernel?"
#endif

/*
 * DTrace SDT probes have different signatures in userland than they do in
 * the kernel.  This file is strictly for libfksmbsrv, where we compile the
 * smbsrv kernel code for user space.  In "fksmbd", we can use the probes
 * defined for the (real, in-kernel) "smb" and "smb2" SDT provider by
 * mapping them onto the USDT proviver defined in ../fksmb_dt.d
 *
 * An example of how to use these probes can be found in:
 *	$SRC/cmd/smbsrv/fksmbd/Watch-fksmb.d
 */

/*
 * Map "smb" provider probes.
 */

#define	DTRACE_SMB_START(name, type1, arg1) \
	FKSMB_SMB_START(#name, (unsigned long)arg1)
#define	DTRACE_SMB_DONE(name, type1, arg1) \
	FKSMB_SMB_DONE(#name, (unsigned long)arg1)

/*
 * Map "smb2" provider probes.
 */

#define	DTRACE_SMB2_START(name, type1, arg1) \
	FKSMB_SMB2_START(#name, (unsigned long)arg1)
#define	DTRACE_SMB2_DONE(name, type1, arg1) \
	FKSMB_SMB2_DONE(#name, (unsigned long)arg1)

/*
 * These are for the other (specialized) dtrace SDT probes sprinkled
 * through the smbsrv code.  These are less often used.
 */

#define	DTRACE_PROBE(name, type1, arg1) \
	FKSMB_PROBE0(#name)

#define	DTRACE_PROBE1(name, type1, arg1) \
	FKSMB_PROBE1(#name, (unsigned long)arg1)

#define	DTRACE_PROBE2(name, type1, arg1, type2, arg2) \
	FKSMB_PROBE2(#name, (unsigned long)arg1, (unsigned long)arg2)

#define	DTRACE_PROBE3(name, type1, arg1, type2, arg2, type3, arg3) \
	FKSMB_PROBE3(#name, (unsigned long)arg1, (unsigned long)arg2, \
		(unsigned long)arg3)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SDT_H */
