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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ZTREE_H
#define	_ZTREE_H

#include <zdoor.h>
#include <zone.h>
#include "zdoor-int.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dtree_entry;

typedef void (*ztree_door_visitor)(struct dtree_entry *entry);

typedef struct ztree_entry {
	char *zte_zonename;
	zdoor_action_t zte_action;
	int zte_num_doors;
	void *zte_door_tree;
	ztree_door_visitor zte_visitor;
	struct zdoor_handle *zte_parent;
} ztree_entry_t;

typedef struct dtree_entry {
	char *dte_service;
	int dte_door;
	zdoor_callback dte_callback;
	zdoor_cookie_t *dte_cookie;
	ztree_entry_t *dte_parent;
} dtree_entry_t;

#define	ZTREE_SUCCESS		0
#define	ZTREE_ERROR		-1
#define	ZTREE_ARGUMENT_ERROR	-2
#define	ZTREE_ALREADY_EXISTS	-3
#define	ZTREE_NOT_FOUND		-4

extern int ztree_zone_add(struct zdoor_handle *handle,
	const char *zonename, ztree_door_visitor visitor);

extern ztree_entry_t *ztree_zone_find(struct zdoor_handle *handle,
	const char *zonename);

extern void ztree_zone_remove(struct zdoor_handle *handle,
	ztree_entry_t *entry);

extern int ztree_door_add(struct zdoor_handle *handle, const char *zonename,
	const char *service, zdoor_callback callback, zdoor_cookie_t *cookie);

extern dtree_entry_t *ztree_door_find(struct zdoor_handle *handle,
	const char *zonename, const char *service);

extern zdoor_cookie_t *ztree_door_remove(struct zdoor_handle *handle,
	dtree_entry_t *entry);

extern void ztree_walk_doors(struct zdoor_handle *handle, const char *zonename);

#ifdef __cplusplus
}
#endif

#endif /* _ZTREE_H */
