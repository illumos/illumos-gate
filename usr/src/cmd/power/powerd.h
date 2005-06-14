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

/* Copyright (c) 1994 - 2001 by Sun Microsystems, Inc.	*/
/* All rights reserved.					*/

#ifndef _POWERD_H
#define	_POWERD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * path shared by powerd and pmconfig
 */
#define	PIDPATH	"/var/run/powerd.pid"

/*
 * AutoShutdown configuration data
 */
struct pwr_info {
	int	pd_flags;		/* Status of powerd */
	int	pd_idle_time;		/* in minutes */
	int	pd_start_time;		/* in minutes since midnight */
	int	pd_finish_time;		/* in minutes since midnight */

	int	pd_autoresume;		/* Autoresume active */
	int	pd_autoshutdown;	/* Autoshutdown active */

	int	pd_ttychars_idle;	/* Tty chars idle time */
	int	pd_ttychars_sum;	/* Sum of tty chars */
	int	pd_loadaverage_idle;	/* Load average idle time */
	float	pd_loadaverage;		/* Load average */
	int	pd_diskreads_idle;	/* Disk reads idle time */
	int	pd_diskreads_sum;	/* Sum of disk reads */
	int	pd_nfsreqs_idle;	/* NFS requests idle time */
	int	pd_nfsreqs_sum;		/* Sum of NFS requests */
};
typedef struct pwr_info pwr_info_t;

/* Various status flags for pd_flags */
#define	PD_AC		0x02
#define	PD_AUTORESUME	0x04
#define	PD_RESUME_ON	0x08

#ifdef	__cplusplus
}
#endif

#endif	/* _POWERD_H */
