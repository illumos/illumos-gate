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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SORT_INITIALIZE_H
#define	_SORT_INITIALIZE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <locale.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <strings.h>
#include <wchar.h>

#include "statistics.h"
#include "streams.h"
#include "types.h"
#include "utility.h"

extern void initialize_pre(sort_t *);
extern void initialize_post(sort_t *);

extern const char *filename_stdout;

#ifdef	__cplusplus
}
#endif

#endif	/* _SORT_INITIALIZE_H */
