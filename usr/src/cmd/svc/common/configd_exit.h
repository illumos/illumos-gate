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

#ifndef	_CONFIGD_EXIT_H
#define	_CONFIGD_EXIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

enum configd_exit_codes {
	CONFIGD_EXIT_OKAY		= 0,
	CONFIGD_EXIT_BAD_ARGS		= 2,
	CONFIGD_EXIT_INIT_FAILED	= 100,
	CONFIGD_EXIT_DOOR_INIT_FAILED,
	CONFIGD_EXIT_DATABASE_INIT_FAILED,
	CONFIGD_EXIT_DATABASE_LOCKED,
	CONFIGD_EXIT_DATABASE_BAD,
	CONFIGD_EXIT_NO_THREADS,
	CONFIGD_EXIT_LOST_MAIN_DOOR
};

#ifdef	__cplusplus
}
#endif

#endif	/* _CONFIGD_EXIT_H */
