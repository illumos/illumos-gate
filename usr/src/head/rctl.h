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

#ifndef	_RCTL_H
#define	_RCTL_H

#include <sys/rctl.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

int rctl_walk(int (*)(const char *, void *), void *);

hrtime_t rctlblk_get_firing_time(rctlblk_t *);
uint_t rctlblk_get_global_action(rctlblk_t *);
uint_t rctlblk_get_global_flags(rctlblk_t *);
uint_t rctlblk_get_local_action(rctlblk_t *, int *);
uint_t rctlblk_get_local_flags(rctlblk_t *);
id_t rctlblk_get_recipient_pid(rctlblk_t *);
rctl_priv_t rctlblk_get_privilege(rctlblk_t *);
rctl_qty_t rctlblk_get_value(rctlblk_t *);
rctl_qty_t rctlblk_get_enforced_value(rctlblk_t *);

void rctlblk_set_local_action(rctlblk_t *, uint_t, int);
void rctlblk_set_local_flags(rctlblk_t *, uint_t);
void rctlblk_set_recipient_pid(rctlblk_t *, id_t);
void rctlblk_set_privilege(rctlblk_t *, rctl_priv_t);
void rctlblk_set_value(rctlblk_t *, rctl_qty_t);

size_t rctlblk_size(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _RCTL_H */
