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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_TSOL_TSYSCALL_H
#define	_SYS_TSOL_TSYSCALL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * the defines for subcode of labelsys system call.
 */

#define	TSOL_SYSLABELING	1
#define	TSOL_TNRH		2
#define	TSOL_TNRHTP		3
#define	TSOL_TNMLP		4
#define	TSOL_GETLABEL		5
#define	TSOL_FGETLABEL		6

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TSOL_TSYSCALL_H */
