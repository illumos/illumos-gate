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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TRACE_H
#define	_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "symtab.h"

#define	TRACE_VERSION "1.1.1"

/* Return codes from back- to front-end. */
enum retcode_t { SUCCESS_RC = 0, ERROR_RC = -1, SKIP_RC = 1};

/* Kinds of code-generation to do. */
typedef enum {AUDIT, PRELOAD} CODE;

/* Global functions. */
extern void stats_add_warning(void);
extern void stats_add_error(void);
extern void generate_interceptor(ENTRY *);
extern void print_function_signature(char *, char *, char *);
extern void generate_linkage(ENTRY *function);

/* Global variables */
extern CODE Generate;

/* Defines. */
#define	YES	1
#define	NO	0
#define	ERR (-1)

#define	MAXLINE 1024

#ifdef	__cplusplus
}
#endif

#endif /* _TRACE_H */
