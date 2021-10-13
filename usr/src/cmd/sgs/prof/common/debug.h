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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
*	file: debug.h
*	desc: Debug macros for the profiler.
*	date: 11/09/88
*/
#include "stdio.h"


#ifdef DEBUG

#ifndef PROF_DEBUG
#define PROF_DEBUG 2
#endif

#define DEBUG_EXP(exp)	exp; fflush(stdout)
#define DEBUG_LOC(name)	printf("Location: %s\n",name); fflush(stdout)

#define NO_DEBUG(exp)
#define NO_DEBUG_LOC(name)

#else

#define DEBUG_EXP(exp)
#define DEBUG_LOC(name)

#define NO_DEBUG(exp)
#define NO_DEBUG_LOC(name)
#endif

