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

#ifndef	_RCAPD_STAT_H
#define	_RCAPD_STAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Default path to statistics file
 */
#define	STAT_FILE_DIR	"/var/run/daemon"
#define	STAT_FILE_DEFAULT	STAT_FILE_DIR	"/rcap.stat"

/*
 * Statistics file header.
 */
#define	RC_MODE_LEN	16
typedef struct rcapd_stat_hdr {
	/*
	 * sizeof pid_t can vary, so we use a fixed 64-bit quantity.
	 */
	uint64_t	rs_pid;			/* pid of producer */
	hrtime_t	rs_time;		/* time recorded */

	/*
	 * Physical memory pressure statistics, in percent.
	 */
	uint32_t	rs_pressure_cur;	/* current memory pressure */
	uint32_t	rs_pressure_cap;	/* minimum cap enforcement p. */

	uint64_t	rs_pressure_sample;	/* count of pr. samplings */
	char		rs_mode[RC_MODE_LEN];	/* mode ("project" only) */
} rcapd_stat_hdr_t;

extern pid_t stat_get_rcapd_pid(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _RCAPD_STAT_H */
