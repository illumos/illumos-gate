/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MSACCT_H
#define	_SYS_MSACCT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* LWP microstates */
#define	LMS_USER	0	/* running in user mode */
#define	LMS_SYSTEM	1	/* running in sys call or page fault */
#define	LMS_TRAP	2	/* running in other trap */
#define	LMS_TFAULT	3	/* asleep in user text page fault */
#define	LMS_DFAULT	4	/* asleep in user data page fault */
#define	LMS_KFAULT	5	/* asleep in kernel page fault */
#define	LMS_USER_LOCK	6	/* asleep waiting for user-mode lock */
#define	LMS_SLEEP	7	/* asleep for any other reason */
#define	LMS_WAIT_CPU	8	/* waiting for CPU (latency) */
#define	LMS_STOPPED	9	/* stopped (/proc, jobcontrol, lwp_suspend) */

/*
 * NMSTATES must never exceed 17 because of the size restriction
 * of 128 bytes imposed on struct siginfo (see <sys/siginfo.h>).
 */
#define	NMSTATES	10	/* number of microstates */

/*
 * CPU Microstates
 *
 * The following define the implemented CPU microstates
 */

#define	CMS_USER	0
#define	CMS_SYSTEM	1
#define	CMS_IDLE	2
#define	CMS_DISABLED	3

/*
 * NCMSTATES is set to NMSTATES - 1, because CMS_DISABLED is not a state for
 * which accounting information is kept.  CPUs that are offline but remain in
 * the system are kept in the CMS_IDLE state until they are brought back online,
 * or unconfigured and deleted from the system.  Only when a cpu is unconfigured
 * and about to be deleted is the CMS_DISABLED state entered.  It is a
 * placeholder state to ensure that our behavior is sane.  ASSERT()s exist to
 * verify this.
 */

#define	NCMSTATES	3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MSACCT_H */
