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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBFRUDS_H
#define	_LIBFRUDS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

#include "libfru.h"
#include "fru_tag.h"

#define	LIBFRU_DS_VER 1

/* Tree handle specific to the datasource */
typedef uint64_t fru_treehdl_t;
typedef uint64_t fru_treeseghdl_t;

typedef struct
{
	int version;

/* init */
fru_errno_t (*initialize)(int argc, char **argv);
fru_errno_t (*shutdown)(void);

/* Tree ops */
fru_errno_t (*get_root)(fru_treehdl_t *root);
fru_errno_t (*get_child)(fru_treehdl_t parent, fru_treehdl_t *child);
fru_errno_t (*get_peer)(fru_treehdl_t sibling, fru_treehdl_t *peer);
fru_errno_t (*get_parent)(fru_treehdl_t child, fru_treehdl_t *parent);

/* Node ops */
fru_errno_t (*get_name_from_hdl)(fru_treehdl_t node, char **name);
fru_errno_t (*get_node_type)(fru_treehdl_t node, fru_node_t *type);

/* Segment ops */
fru_errno_t (*get_seg_list)(fru_treehdl_t container, fru_strlist_t *list);
fru_errno_t (*get_seg_def)(fru_treehdl_t container, const char *seg_name,
		fru_segdef_t *def);
fru_errno_t (*add_seg)(fru_treehdl_t container, fru_segdef_t *def);
fru_errno_t (*delete_seg)(fru_treehdl_t container, const char *seg_name);
fru_errno_t (*for_each_segment)(fru_treehdl_t node,
				int (*function)(fru_treeseghdl_t segment,
						void *args),
				void *args);
fru_errno_t (*get_segment_name)(fru_treeseghdl_t segment, char **name);

/* Tag ops */
fru_errno_t (*add_tag_to_seg)(fru_treehdl_t container, const char *seg_name,
		fru_tag_t tag, uint8_t *data, size_t data_len);
fru_errno_t (*get_tag_list)(fru_treehdl_t container, const char *seg_name,
		fru_tag_t **tags, int *number);
fru_errno_t (*get_tag_data)(fru_treehdl_t container, const char *seg_name,
		fru_tag_t tag, int instance,
		uint8_t **data, size_t *data_len);
fru_errno_t (*set_tag_data)(fru_treehdl_t container, const char *seg_name,
		fru_tag_t tag, int instance,
		uint8_t *data, size_t data_len);
fru_errno_t (*delete_tag)(fru_treehdl_t container, const char *seg_name,
		fru_tag_t tag, int instance);
fru_errno_t (*for_each_packet)(fru_treeseghdl_t segment,
				int (*function)(fru_tag_t *tag,
						uint8_t *payload,
						size_t length, void *args),
				void *args);

} fru_datasource_t;

#ifdef __cplusplus
}
#endif

#endif /* _LIBFRUDS_H */
