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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UTILS_H
#define	_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	E_SUCCESS	0		/* Exit status for success */
#define	E_ERROR		1		/* Exit status for error */
#define	E_USAGE		2		/* Exit status for usage error */

extern void warn(const char *, ...);
extern void die(char *, ...);
extern char *setprogname(char *);
extern const char *ac_type_name(int);
extern int open_exacct_file(const char *, int);
extern boolean_t verify_exacct_file(const char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTILS_H */
