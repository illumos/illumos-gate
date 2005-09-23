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

#ifndef _CMD_LIST_H
#define	_CMD_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmd_list {
	struct cmd_list *l_prev;
	struct cmd_list *l_next;
} cmd_list_t;

#define	cmd_list_prev(elem)	((void *)(((cmd_list_t *)(elem))->l_prev))
#define	cmd_list_next(elem)	((void *)(((cmd_list_t *)(elem))->l_next))

extern void cmd_list_append(cmd_list_t *, void *);
extern void cmd_list_prepend(cmd_list_t *, void *);
extern void cmd_list_insert_before(cmd_list_t *, void *, void *);
extern void cmd_list_insert_after(cmd_list_t *, void *, void *);
extern void cmd_list_delete(cmd_list_t *, void *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_LIST_H */
