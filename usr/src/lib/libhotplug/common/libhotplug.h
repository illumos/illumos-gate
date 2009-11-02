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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBHOTPLUG_H
#define	_LIBHOTPLUG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Define node types in hotplug snapshot.
 */
#define	HP_NODE_NONE		0
#define	HP_NODE_DEVICE		1
#define	HP_NODE_CONNECTOR	2
#define	HP_NODE_PORT		3
#define	HP_NODE_USAGE		4

/*
 * Define flags for hp_init().
 */
#define	HPINFOUSAGE		0x1
#define	HPINFOSEARCH		0x2	/* private flag */

/*
 * Define flags for hp_set_state().
 */
#define	HPFORCE			0x1
#define	HPQUERY			0x2

/*
 * Define private flags.
 */

/*
 * Define return values for hp_traverse() callbacks.
 */
#define	HP_WALK_CONTINUE	0
#define	HP_WALK_PRUNECHILD	1
#define	HP_WALK_PRUNESIBLING	2
#define	HP_WALK_TERMINATE	3

/*
 * Define opaque handle to hotplug nodes.
 */
typedef struct hp_node *hp_node_t;

/*
 * Interface prototypes.
 */
hp_node_t	hp_init(const char *path, const char *connection, uint_t flags);
void		hp_fini(hp_node_t root);
int		hp_traverse(hp_node_t root, void *arg,
		    int (*hp_callback)(hp_node_t, void *arg));
int		hp_type(hp_node_t node);
char		*hp_name(hp_node_t node);
char		*hp_usage(hp_node_t node);
int		hp_state(hp_node_t node);
char		*hp_description(hp_node_t node);
time_t		hp_last_change(hp_node_t node);
hp_node_t	hp_parent(hp_node_t node);
hp_node_t	hp_child(hp_node_t node);
hp_node_t	hp_sibling(hp_node_t node);
int		hp_path(hp_node_t node, char *path, char *connection);
int		hp_set_state(hp_node_t node, uint_t flags, int state,
		    hp_node_t *resultsp);
int		hp_set_private(hp_node_t node, const char *options,
		    char **resultsp);
int		hp_get_private(hp_node_t node, const char *options,
		    char **resultsp);
int		hp_pack(hp_node_t root, char **bufp, size_t *lenp);
int		hp_unpack(char *packed_buf, size_t packed_len, hp_node_t *retp);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBHOTPLUG_H */
