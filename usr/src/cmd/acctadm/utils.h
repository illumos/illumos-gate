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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_UTILS_H
#define	_UTILS_H

#include <libintl.h>
#include <libdllink.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	E_SUCCESS	0		/* Exit status for success */
#define	E_ERROR		1		/* Exit status for error */
#define	E_USAGE		2		/* Exit status for usage error */

/* handle for libdladm calls */
extern dladm_handle_t dld_handle;

extern void warn(const char *, ...);
extern void die(char *, ...) __NORETURN;
extern char *setpname(char *);
extern const char *ac_type_name(int);
extern int open_exacct_file(const char *, int);
extern boolean_t verify_exacct_file(const char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTILS_H */
