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
 *
 * Copyright 2026 Oxide Computer Company
 */

#ifndef	_NSCD_SELFCRED_H
#define	_NSCD_SELFCRED_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <door.h>
#include "nscd_door.h"

/*
 * structure used for door call NSCD_IMHERE
 */
typedef struct nscd_imhere {
	int	slot;
} nscd_imhere_t;

/*
 * structure used for door call NSCD_FORK
 */
typedef struct nscd_fork {
	int	slot;
	uid_t	uid;
	gid_t	gid;
} nscd_fork_t;

/*
 * prototypes
 */
int _nscd_is_self_cred_on(int, char **);
void _nscd_set_forker_pid(pid_t);
void _nscd_free_cslots(void);
void _nscd_kill_forker(void);
void _nscd_kill_all_children(void);
boolean_t _nscd_proc_iamhere(void *, door_desc_t *, uint_t, int);
void _nscd_proc_pulse(void *, int);
void _nscd_proc_fork(void *, int);
void _nscd_proc_alt_get(void *, int *);
void _nscd_start_forker(char *, int, char **);
void _nscd_peruser_getadmin(void *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_SELFCRED_H */
