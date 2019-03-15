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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_STRFT_H
#define	_SYS_STRFT_H

#include <sys/sdt.h>

#ifdef	__cplusplus
extern "C" {
#endif


#define	FTEV_ALLOCB	0x0000
#define	FTEV_ESBALLOC	0x0001
#define	FTEV_DESBALLOC	0x0002
#define	FTEV_ESBALLOCA	0x0003
#define	FTEV_DESBALLOCA	0x0004
#define	FTEV_ALLOCBIG	0x0005
#define	FTEV_ALLOCBW	0x0006
#define	FTEV_BCALLOCB	0x0007
#define	FTEV_FREEB	0x0008
#define	FTEV_DUPB	0x0009
#define	FTEV_COPYB	0x000A

#define	STR_FTALLOC(hpp, e, d)	\
	DTRACE_PROBE3(str__ftalloc, void *, hpp, ushort_t, e, ushort_t, d)

/* Skip the 2nd arg (p) which is: caller() */
#define	STR_FTEVENT_MBLK(mp, p, e, d)	\
	DTRACE_PROBE3(str__ftevent, void *, mp, ushort_t, e, ushort_t, d)

#define	str_ftfree(dbp)	((void)(dbp))

extern int str_ftnever, str_ftstack;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STRFT_H */
