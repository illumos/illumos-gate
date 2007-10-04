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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FB_MISC_H
#define	_FB_MISC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <sys/times.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DATE_VAR "date"
#define	SCRIPT_VAR "scriptname"
#define	HOST_VAR "hostname"

#ifndef HAVE_HRTIME
uint64_t gethrtime();
#define	hrtime_t uint64_t
#endif
#define	FSECS (double)1000000000.0

#define	LOG_INFO 1
#define	LOG_VERBOSE 2
#define	LOG_DEBUG_SCRIPT 3
#define	LOG_DEBUG_IMPL 5
#define	LOG_DEBUG_NEVER 10
#define	LOG_LOG 1000
#define	LOG_DUMP 1001
#define	LOG_FATAL 999
#define	LOG_ERROR 0

var_t *date_var(var_t *var);
var_t *script_var(var_t *var);
var_t *host_var(var_t *var);

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_MISC_H */
