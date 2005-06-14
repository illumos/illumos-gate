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

#ifndef __ACTION_H
#define	__ACTION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct reap {
	struct q	q;
	uint_t		r_act;
	struct vol	*r_v;
	pid_t		r_pid;
	char		*r_hint;
	dev_t		r_dev;
};

extern struct q reapq;

typedef struct actprog {
	char	*ap_prog;
	char	*ap_matched;
	char	**ap_args;
	uid_t	ap_uid;
	gid_t	ap_gid;
	uint_t	ap_line;
	uint_t	ap_maptty;
} actprog_t;

#define	ACT_INSERT	1
#define	ACT_EJECT	2
#define	ACT_NOTIFY	3
#define	ACT_ERROR	4
#define	ACT_REMOUNT	5
#define	ACT_CLOSE	6

extern int	action(uint_t, struct vol *);

extern char	*actnames[];

#define	MAXARGC		100

#ifdef	__cplusplus
}
#endif

#endif /* __ACTION_H */
