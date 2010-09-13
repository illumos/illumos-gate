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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _PARMS_H
#define	_PARMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Solaris is a SVR4 based system and will never be anything else
 * Removed all the dead and never to be resurrected options
 */

/*
 * Owner of setud files running on behalf of uucp.  Needed in case
 * root runs uucp and euid is not honored by kernel.
 * GID is needed for some chown() calls.
 * Also used if guinfo() cannot find the current users ID in the
 * password file.
 */
#define	UUCPUID		5	/* */
#define	UUCPGID		5	/* */

/* definitions for the types of networks and dialers that are available */
/* used to depend on STANDALONE, but now done at runtime via Sysfiles	*/
#define	TCP		/* TCP (bsd systems) */

#define	TLI		/* for AT&T Transport Layer Interface networks */
#define	TLIS		/* for AT&T Transport Layer Interface networks */
			/* with streams module "tirdwr" */

#define	MAXCALLTRIES	2 /* maximum call attempts per Systems file line */

/* define DEFAULT_BAUDRATE to be the baud rate you want to use when both */
/* Systems file and Devices file allow Any */
#define	DEFAULT_BAUDRATE "9600"	/* */

/* define permission modes for the device */
#define	M_DEVICEMODE (mode_t)0600	/* MASTER device mode */
#define	S_DEVICEMODE (mode_t)0600	/* SLAVE device mode */
#define	R_DEVICEMODE (mode_t)0600	/* default mode to restore */

/* initial wait time after failure before retry */
#define	RETRYTIME 300		/* 5 minutes */
/*
 * MAXRETRYTIME is for exponential backoff  limit.
 * NOTE - this should not be 24 hours so that
 * retry is not always at the same time each day
 */
#define	MAXRETRYTIME 82800	/* 23 hours */
#define	ASSERT_RETRYTIME 86400	/* retry time for ASSERT errors */

/*
 * define USRSPOOLLOCKS if you like your lock files in /var/spool/locks
 * be sure other programs such as 'cu' and 'ct' know about this
 *
 * WARNING: if you do not define USRSPOOLLOCKS, then $LOCK in
 * uudemon.cleanup must be changed.
 */
#define	USRSPOOLLOCKS  /* define to use /var/spool/locks for LCK files */

#ifdef	__cplusplus
}
#endif

#endif /* _PARMS_H */
