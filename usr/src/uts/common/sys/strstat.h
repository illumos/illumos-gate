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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_STRSTAT_H
#define	_SYS_STRSTAT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Streams Statistics header file.  This file defines the counters
 * which are maintained for statistics gathering under Streams.
 */

/*
 * per-module statistics structure
 */
struct module_stat {
	long ms_pcnt;		/* count of calls to put proc */
	long ms_scnt;		/* count of calls to service proc */
	long ms_ocnt;		/* count of calls to open proc */
	long ms_ccnt;		/* count of calls to close proc */
	long ms_acnt;		/* count of calls to admin proc */
	char *ms_xptr;		/* pointer to private statistics */
	short ms_xsize;		/* length of private statistics buffer */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STRSTAT_H */
