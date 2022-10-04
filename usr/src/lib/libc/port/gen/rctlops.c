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

#include "lint.h"
#include <sys/rctl_impl.h>
#include <stdlib.h>
#include <string.h>
#include <rctl.h>

/*
 * Resource control routines
 *
 * rctl_walk(3C)
 *
 * Resource control block manipulation routines
 *   The setrctl(2) and getrctl(2) interfaces are accessed via opaque resource
 *   control blocks, the characteristics of which are in turn set and fetched
 *   using the following functions.  Applications using the following interfaces
 *   will be binary compatible across enhancements to the resource control
 *   subsystem that involve modification of the control block.
 */
int
rctl_walk(int (*callback)(const char *rctlname, void *walk_data),
    void *init_data)
{
	int ret = 0;
	char *ctl_names, *curr_name;
	size_t sz = rctllist(NULL, 0);

	if ((ctl_names = malloc(sz)) == NULL)
		return (-1);

	(void) rctllist(ctl_names, sz);

	for (curr_name = ctl_names;
	    curr_name < ctl_names + sz;
	    curr_name += strlen(curr_name) + 1) {
		ret = callback(curr_name, init_data);
		if (ret != 0) {
			free(ctl_names);
			return (ret);
		}
	}

	free(ctl_names);
	return (ret);
}

uint_t
rctlblk_get_global_action(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;

	return (ropaque->rcq_global_flagaction & (~RCTL_GLOBAL_ACTION_MASK));
}

uint_t
rctlblk_get_local_action(rctlblk_t *rblk, int *signal)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;

	if (signal != NULL)
		*signal = ropaque->rcq_local_signal;
	return (ropaque->rcq_local_flagaction & (~RCTL_LOCAL_ACTION_MASK));
}

uint_t
rctlblk_get_global_flags(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;

	return (ropaque->rcq_global_flagaction & RCTL_GLOBAL_ACTION_MASK);
}

uint_t
rctlblk_get_local_flags(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;

	return (ropaque->rcq_local_flagaction & RCTL_LOCAL_ACTION_MASK);
}

hrtime_t
rctlblk_get_firing_time(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;

	return (ropaque->rcq_firing_time);
}

id_t
rctlblk_get_recipient_pid(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;

	return (ropaque->rcq_local_recipient_pid);
}

rctl_priv_t
rctlblk_get_privilege(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	return (ropaque->rcq_privilege);
}

rctl_qty_t
rctlblk_get_value(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	return (ropaque->rcq_value);
}

rctl_qty_t
rctlblk_get_enforced_value(rctlblk_t *rblk)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	return (ropaque->rcq_enforced_value);
}

void
rctlblk_set_local_action(rctlblk_t *rblk, uint_t action, int signal)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	ropaque->rcq_local_signal = signal;
	ropaque->rcq_local_flagaction = (ropaque->rcq_local_flagaction &
	    RCTL_LOCAL_ACTION_MASK) | (action & ~RCTL_LOCAL_ACTION_MASK);
}

void
rctlblk_set_local_flags(rctlblk_t *rblk, uint_t flags)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	ropaque->rcq_local_flagaction = (ropaque->rcq_local_flagaction &
	    ~RCTL_LOCAL_ACTION_MASK) | (flags & RCTL_LOCAL_ACTION_MASK);
}

void
rctlblk_set_recipient_pid(rctlblk_t *rblk, id_t pid)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	ropaque->rcq_local_recipient_pid = pid;
}

void
rctlblk_set_privilege(rctlblk_t *rblk, rctl_priv_t privilege)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	ropaque->rcq_privilege = privilege;
}

void
rctlblk_set_value(rctlblk_t *rblk, rctl_qty_t value)
{
	rctl_opaque_t *ropaque = (rctl_opaque_t *)rblk;
	ropaque->rcq_value = value;
}

size_t
rctlblk_size(void)
{
	return (sizeof (rctl_opaque_t));
}
