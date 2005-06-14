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

#ifndef _SH_TABLE_H_
#define _SH_TABLE_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "pdu.h"

#include "snmprelay_msg.h"
#include "agent.h"
/*
#ifndef _SUBTREE_H_
#include "subtree.h"
#endif
*/

#define TABLE_TO_OID_TRY 0
#define TABLE_TO_OID_GO  1

typedef struct _Table {
	Integer regTblIndex;
	Integer	regTblAgentID;
        Oid name;
        Subid first_column_subid; /* Subid may convert to Integer */
        Subid last_column_subid;
        Subid first_index_subid;
        Subid last_index_subid;
	Integer	regTblStatus;
	String	regTblView;
        Agent *agent;
        struct _Table *next_table;
	int mirror_flag;
} Table;

extern int is_first_entry(Table *table);
extern void table_free(Table *tp);
extern void table_list_delete();
extern void trace_tables();
extern void delete_all_tables_for_agent(Agent *agent);
extern void table_detach(Table *tp);
extern int activate_table(Table *tp);
extern int delete_table(Table *tp);
extern int activate_table_for_agent(Agent* agent);

extern Table *first_table;
extern Table *last_table;

extern int single_table_to_subtrees(int pass,Table *tp, char* error_label);

extern void delete_all_table_from_agent(Agent *agent);

extern void create_mirror_table_from_subtree();

#endif
