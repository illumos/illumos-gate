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
 * Copyright (c) 1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PGREP_H
#define	_PGREP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	E_MATCH		0	/* Exit status for match */
#define	E_NOMATCH	1	/* Exit status for no match */
#define	E_USAGE		2	/* Exit status for usage error */
#define	E_ERROR		3	/* Exit status for other error */

typedef int (*opt_cb_t)(char, char *);

typedef struct optdesc {
	ushort_t o_opts;	/* Flags indicating how to process option */
	ushort_t o_bits;	/* Bits to set or clear in *o_ptr */
	opt_cb_t o_func;	/* Function to call */
	void *o_ptr;		/* Address of flags or string */
} optdesc_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _PGREP_H */
