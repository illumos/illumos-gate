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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _TRACE_H_
#define _TRACE_H_


/***** GLOBAL CONSTANTS *****/

#define TRACE_LEVEL_MAX		4

#define TRACE_TRAFFIC		0x1
#define TRACE_PACKET		0x2
#define TRACE_PDU		0x4


/***** GLOBAL VARIABLES *****/

extern int trace_level;		/* 0 ... TRACE_LEVEL_MAX */
extern uint32_t trace_flags;


/***** GLOBAL FUNCTIONS *****/

extern void trace(char *, ...);
extern int trace_set(int level, char *error_label);
extern void trace_reset();
extern void trace_increment();
extern void trace_decrement();

#endif
