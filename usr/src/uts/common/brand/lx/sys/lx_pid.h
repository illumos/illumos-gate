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

#ifndef _SYS_LX_PID_H
#define	_SYS_LX_PID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
struct lx_pid {
	pid_t	s_pid;			/* the solaris pid and ... */
	id_t	s_tid;			/* ... tid pair */
	pid_t	l_pid;			/* the corresponding linux pid */
	time_t	l_start;		/* birthday of this pid */
	struct pid *l_pidp;
	struct lx_pid *stol_next;	/* link in stol hash table */
	struct lx_pid *ltos_next;	/* link in ltos hash table */
};

extern int lx_pid_assign(kthread_t *);
extern void lx_pid_reassign(kthread_t *);
extern void lx_pid_rele(pid_t, id_t);
extern pid_t lx_lpid_to_spair(pid_t, pid_t *, id_t *);
extern pid_t lx_lwp_ppid(klwp_t *, pid_t *, id_t *);
extern void lx_pid_init(void);
extern void lx_pid_fini(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_PID_H */
