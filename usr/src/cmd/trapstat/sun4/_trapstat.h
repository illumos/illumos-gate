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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	__TRAPSTAT_DOT_H
#define	__TRAPSTAT_DOT_H

#include <sys/trapstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	TSTAT_ENT_USED			0
#define	TSTAT_ENT_RESERVED		1
#define	TSTAT_ENT_UNUSED		2
#define	TSTAT_ENT_CONTINUED		3

typedef struct {
	char	*tent_name;
	char	*tent_descr;
	int	tent_type;
} tstat_ent_t;

extern	tstat_ent_t *get_trap_ent(int);

#ifdef	__cplusplus
}
#endif

#endif /* __TRAPSTAT_DOT_H */
