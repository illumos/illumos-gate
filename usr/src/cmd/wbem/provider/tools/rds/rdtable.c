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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <stdlib.h>

#include "rdutil.h"
#include "rdtable.h"

static lwpid_t	*lwpid_tbl[LWPID_TBL_SZ];

void
lwpid_init()
{
	(void) memset(&lwpid_tbl, 0, sizeof (lwpid_t *) * LWPID_TBL_SZ);
}

void
lwpid_add(lwp_info_t *lwp, pid_t pid, id_t lwpid)
{
	lwpid_t	*elm = Zalloc(sizeof (lwpid_t));
	int hash = pid % LWPID_TBL_SZ;

	elm->l_pid = pid;
	elm->l_lwpid = lwpid;
	elm->l_lwp = lwp;
	elm->l_next = lwpid_tbl[hash]; /* add in front of chain */
	lwpid_tbl[hash] = elm;
}

void
lwpid_del(pid_t pid, id_t lwpid)
{
	lwpid_t	*elm, *elm_prev;
	int hash = pid % LWPID_TBL_SZ;

	elm = lwpid_tbl[hash];
	elm_prev = NULL;

	while (elm) {
		if ((elm->l_pid == pid) && (elm->l_lwpid == lwpid)) {
			if (!elm_prev)	/* first chain element */
				lwpid_tbl[hash] = elm->l_next;
			else
				elm_prev->l_next = elm->l_next;
			free(elm);
			break;
		} else {
			elm_prev = elm;
			elm = elm->l_next;
		}
	}
}

static lwpid_t *
lwpid_getptr(pid_t pid, id_t lwpid)
{
	lwpid_t *elm = lwpid_tbl[pid % LWPID_TBL_SZ];
	while (elm) {
		if ((elm->l_pid == pid) && (elm->l_lwpid == lwpid))
			return (elm);
		else
			elm = elm->l_next;
	}
	return (NULL);
}

lwp_info_t *
lwpid_get(pid_t pid, id_t lwpid)
{
	lwpid_t	*elm = lwpid_getptr(pid, lwpid);
	if (elm)
		return (elm->l_lwp);
	else
		return (NULL);
}

int
lwpid_pidcheck(pid_t pid)
{
	lwpid_t *elm;
	elm = lwpid_tbl[pid % LWPID_TBL_SZ];
	while (elm) {
		if (elm->l_pid == pid)
			return (1);
		else
			elm = elm->l_next;
	}
	return (0);
}
