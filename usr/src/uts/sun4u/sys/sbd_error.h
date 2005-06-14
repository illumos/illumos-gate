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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SBD_ERROR_H
#define	_SYS_SBD_ERROR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SBD_TEST_BOARD_PSEUDO_ERR	1
#define	SBD_ASSIGN_BOARD_PSEUDO_ERR	2
#define	SBD_UNASSIGN_BOARD_PSEUDO_ERR	3
#define	SBD_POWERON_BOARD_PSEUDO_ERR	4
#define	SBD_POWEROFF_BOARD_PSEUDO_ERR	5
#define	SBD_PROBE_BOARD_PSEUDO_ERR	6
#define	SBD_DEPROBE_BOARD_PSEUDO_ERR	7
#define	SBD_CONNECT_BOARD_PSEUDO_ERR	8
#define	SBD_DISCONNECT_BOARD_PSEUDO_ERR	9
#define	SBD_OFFLINE_CPU_PSEUDO_ERR	10
#define	SBD_ONLINE_CPU_PSEUDO_ERR	11
#define	SBD_POWEROFF_CPU_PSEUDO_ERR	12
#define	SBD_POWERON_CPU_PSEUDO_ERR	13

#ifdef DEBUG
/* comment out the next line to turn off compilation of error injection */
#define	SBD_DEBUG_ERRS

#ifdef SBD_DEBUG_ERRS

extern void sbd_inject_err(int error, sbderror_t *ep, int Errno, int ecode,
	char *src);

#define	SBD_DBG_ERRNO	0x00000001
#define	SBD_DBG_CODE	0x00000002
#define	SBD_DBG_RSC	0x00000004
#define	SBD_DBG_ALL	0x0000000f

#define	PR_ERR_ALL	if (sbd_print_errs & SBD_DBG_ALL)	printf
#define	PR_ERR_ERRNO	if (sbd_print_errs & SBD_DBG_ERRNO)	printf
#define	PR_ERR_ECODE	if (sbd_print_errs & SBD_DBG_CODE)	printf
#define	PR_ERR_RSC	if (sbd_print_errs & SBD_DBG_RSC)	printf

#define	SBD_INJECT_ERR	sbd_inject_err



#else	/* SBD_DEBUG_ERRS */

#define	SBD_INJECT_ERR
#define	PR_ERR_ALL		if (0) printf
#define	SBD_DBG_CODE	PR_ERR_ALL
#define	SBD_DBG_ALL	PR_ERR_ALL

#endif	/* SBD_DEBUG_ERRS */

#else	/* DEBUG */

#define	SBD_INJECT_ERR
#define	PR_ERR_ALL		if (0) printf
#define	PR_ERR_ERRNO		PR_ERR_ALL
#define	PR_ERR_ECODE		PR_ERR_ALL
#define	PR_ERR_RSC		PR_ERR_ALL

#endif	/* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBD_ERROR_H */
