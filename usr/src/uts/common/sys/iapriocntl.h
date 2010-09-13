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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_IAPRIOCNTL_H
#define	_SYS_IAPRIOCNTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interactive class specific structures for the priocntl system call.
 */

/*
 * Beginning of iaparms structure must match tsparms structure so they
 * can be used interchangeably.
 */

typedef struct iaparms {
	pri_t	ia_uprilim;		/* user priority limit */
	pri_t	ia_upri;		/* user priority */
	int	ia_mode;		/* interactive on/off */
} iaparms_t;

typedef struct iaclass {
	id_t	pc_cid;
	int	pc_clparms[PC_CLPARMSZ];
} iaclass_t;

typedef struct iainfo {
	pri_t	ia_maxupri;	/* configured limits of user priority range */
} iainfo_t;

#define	IA_NOCHANGE	-32768
#define	IAMAXUPRI	60
#define	IAOFFUPRI	29
#define	IANPROCS	60
#define	IA_INTERACTIVE_OFF	0x00	/* thread is not interactive */
#define	IA_SET_INTERACTIVE	0x01	/* thread is interactive */
#define	IA_BOOST	10		/* value for boost */

/*
 * Interactive class specific keys for the priocntl system call
 * varargs interface.
 */
#define	IA_KY_UPRILIM	1	/* user priority limit */
#define	IA_KY_UPRI	2	/* user priority */
#define	IA_KY_MODE	3	/* interactive on/off */

/*
 * The following is used by the dispadmin(1M) command for
 * scheduler administration and is not for general use.
 */

#ifdef _SYSCALL32
/* Data structure for ILP32 clients */
typedef struct iaadmin32 {
	caddr32_t	ia_dpents;
	int16_t		ia_ndpents;
	int16_t		ia_cmd;
} iaadmin32_t;
#endif /* _SYSCALL32 */

typedef struct iaadmin {
	struct iadpent	*ia_dpents;
	short		ia_ndpents;
	short		ia_cmd;
} iaadmin_t;

#define	IA_GETDPSIZE	1
#define	IA_GETDPTBL	2
#define	IA_SETDPTBL	3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IAPRIOCNTL_H */
