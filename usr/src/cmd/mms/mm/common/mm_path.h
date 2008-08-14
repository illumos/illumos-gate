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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MM_PATH_H
#define	_MM_PATH_H


#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mm_pkey mm_pkey_t;
struct mm_pkey {
	char		*mm_obj;
	char		**mm_att;
	int		mm_att_num;
};

typedef struct mm_att mm_att_t;
struct mm_att {
	char		*mm_att;
	char		*mm_ref_att;
};

typedef struct mm_node mm_node_t;
struct mm_node {
	char		*mm_obj;
	mm_pkey_t	*mm_pkey;

	mm_att_t	**mm_edge;
	int		mm_edge_num;

	char		*mm_ref_obj;
};

typedef struct mm_path mm_path_t;
struct mm_path {
	char		*mm_id;
	mm_node_t	**mm_node;
	int		mm_node_num;
};

int mm_init_paths(char *fn);
mm_path_t *mm_get_path(char *obj_1, char *obj_2);
void mm_print_path(mm_path_t *path);
mm_pkey_t *mm_get_pkey(char *obj_1);

#ifdef	__cplusplus
}
#endif

#endif	/* _MM_PATH_H */
