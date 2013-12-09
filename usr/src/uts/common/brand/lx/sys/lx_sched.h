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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LINUX_SCHED_H
#define	_SYS_LINUX_SCHED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/procset.h>
#include <sys/priocntl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Linux scheduler policies.
 */
#define	LX_SCHED_OTHER		0
#define	LX_SCHED_FIFO		1
#define	LX_SCHED_RR		2

#define	LX_PRI_MAX		99

typedef	int l_pid_t;

struct lx_sched_param {
	int	lx_sched_prio;
};

extern int sched_setprocset(procset_t *, l_pid_t);
extern long do_priocntlsys(int, procset_t *, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LINUX_SCHED_H */
