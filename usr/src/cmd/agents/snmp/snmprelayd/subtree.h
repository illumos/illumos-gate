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
 *
 * Copyright 1996 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

/*
 * HISTORY
 * 5-21-96	Jerry Yeung	support MIB
 * 6-4-96	Jerry Yeung	support table
 */

#ifndef _SUBTREE_H_
#define _SUBTREE_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _SH_TABLE_H_
#include "sh_table.h"
#endif

#define TBL_TAG_TYPE_UNKNOWN 0
#define TBL_TAG_TYPE_COL 1
#define TBL_TAG_TYPE_LEAF 2

typedef struct _TblTag {
	int entry_index; /* lowest row index of the table */
	int type; /* col or leaf */
	Table *table;
} TblTag;

typedef struct _MirrorTag {
	Table *table;
} MirrorTag;

typedef struct _Subtree {
        Integer regTreeIndex;
        Integer regTreeAgentID;
	Oid		name;
/* rename regTreeOID to name, which has already used
        Oid regTreeOID;
*/
        Integer regTreeStatus;
	String regTreeView;
        Integer regTreePriority;
	struct _Subtree	*next_subtree;
	struct _Agent	*agent;
	struct _Subtree	*next_agent_subtree;
	struct _TblTag *tbl_tag;
	struct _MirrorTag *mirror_tag;

/* things to be addeded 
 * char view_selected;
 * char bulk_selected;
 * int priority;
 */

} Subtree;

extern Subtree *first_subtree;

extern int sap_reg_tree_index;

int subtree_add(Agent *agent, Subid *subids, int len, TblTag *tbl_tag);

/* if the the oid doesn't find, it will be created and inserted */
Subtree* subtree_find(Subid *subids, int len);

Subtree *subtree_match(u_char type, Oid *oid);

void subtree_list_delete();

void subtree_free(Subtree *sp); /* to be modified */

void subtree_detach(Subtree *sp);

void trace_subtrees();

void subtree_remove_from_agent_list(Subtree *subtree);

int subtree_is_valid(Subtree *subtree);

Subtree* subtree_next(Subtree *subtree);

void delete_all_subtree_from_agent(Agent* agent);

int subtree_purge(Subid *subids, int len);

int sync_subtrees_with_agent(Agent *agent);

#endif
