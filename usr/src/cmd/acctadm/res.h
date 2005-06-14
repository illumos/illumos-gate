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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_RES_H
#define	_RES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/acctctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ac_resname {
	int	ar_type;
	int	ar_id;
	char	*ar_name;
} ac_resname_t;

typedef struct ac_group {
	int	ag_type;
	char	*ag_name;
	int	ag_mem[AC_MAX_RES + 1];
} ac_group_t;

#define	AC_BUFSIZE	(sizeof (ac_res_t) * (AC_MAX_RES + 1))

extern void str2buf(ac_res_t *, char *, int, int);
extern char *buf2str(ac_res_t *, size_t, int, int);
extern void printgroups(int);

#ifdef __cplusplus
}
#endif

#endif	/* _RES_H */
