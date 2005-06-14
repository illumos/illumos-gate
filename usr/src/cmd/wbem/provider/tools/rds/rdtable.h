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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_RDTABLE_H
#define	_RDTABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <limits.h>

#include "rdimpl.h"

#define	LWPID_TBL_SZ	4096		/* hash table of lwpid_t structures */
#define	LWP_ACTIVE	1

typedef struct {
	size_t		t_size;
	size_t		t_nent;
	long		*t_list;
} table_t;

typedef struct {
	uid_t		u_id;
	char		u_name[LOGNAME_MAX+1];
} name_t;

typedef struct {
	size_t		n_size;
	size_t		n_nent;
	name_t		*n_list;
} nametbl_t;

typedef struct lwpid {			/* linked list of pointers to lwps */
	pid_t		l_pid;
	id_t		l_lwpid;
	int		l_active;
	lwp_info_t	*l_lwp;
	struct lwpid	*l_next;
} lwpid_t;


extern void 		lwpid_init();
extern void 		lwpid_add(lwp_info_t *lwp, pid_t pid, id_t lwpid);
extern void 		lwpid_del(pid_t pid, id_t lwpid);
extern lwp_info_t 	*lwpid_get(pid_t pid, id_t lwpid);
extern int 		lwpid_pidcheck(pid_t pid);

#ifdef	__cplusplus
}
#endif

#endif	/* _RDTABLE_H */
