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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "impl.h"
#include "error.h"
#include "trace.h"

#include "agent_msg.h"
#include "node.h"


/***** STATIC VARIABLES ******/

static Node *root_node = &node_table[0];


/*****************************************************************/

Node *node_find(int search_type, Oid *name, Oid *suffix)
{
	int i;
	Node *parent;
	Node *previous;
	Node *node;


	if( (name == NULL)
		|| (name->len < 1)
		|| (name->subids[0] != root_node->subid) )
	{
		suffix->subids = NULL;
		suffix->len = 0;

		if(trace_level > 0)
		{
			trace("node_find() returned NULL\n\n");
		}

		return NULL;
	}

	parent = root_node;
	for(i = 1; i < name->len; i++)
	{
		previous = NULL;

		for(node = parent->first_child; node; node = node->next_peer)
		{
			if(node->subid > name->subids[i])
			{
				switch(search_type)
				{
					case NEXT_ENTRY:
						suffix->len = 0;
						suffix->subids = NULL;

						if(trace_level > 0)
						{
							trace("node_find() returned %s with no suffix\n\n",
								node->label);
						}

						return node;

					case EXACT_ENTRY:
						node = NULL;
						break;
				}

				break;
			}

			if(node->subid == name->subids[i])
			{
				parent = node;
				break;
			}

			previous = node;
		}

		if(node == NULL)
		{
			switch(search_type)
			{
				case NEXT_ENTRY:
					suffix->subids = NULL;
					suffix->len = 0;

					if(previous)
					{
						if(trace_level > 0)
						{
							if(previous->next)
							{
								trace("node_find() returned %s with no suffix\n\n",
									previous->next->label);
							}
							else
							{
								trace("node_find() returned NULL\n\n");
							}
						}

						return previous->next;
					}
					else
					{
						if(trace_level > 0)
						{
							if(parent->next)
							{
								trace("node_find() returned %s with no suffix\n\n",
									parent->next->label);
							}
							else
							{
								trace("node_find() returned NULL\n\n");
							}
						}

						return parent->next;
					}

				case EXACT_ENTRY:
					suffix->subids = NULL;
					suffix->len = 0;

					if(trace_level > 0)
					{
						trace("node_find() returned NULL\n\n");
					}

					return NULL;
			}
		}

		if( (node->type == COLUMN)
			|| (node->type == OBJECT) ) {
			suffix->len = name->len - (i + 1);
			if (suffix->len) {
				suffix->subids = (Subid *) malloc(suffix->len *
					(int32_t)sizeof(Subid));
				if (suffix->subids == NULL) {
					error(ERR_MSG_ALLOC);
					return NULL;
				}

				(void)memcpy(suffix->subids, &(name->subids[i + 1]),
					suffix->len * (int32_t)sizeof(Subid));
			} else
				suffix->subids = NULL;

			if(trace_level > 0) {
				trace("node_find() returned %s with suffix %s\n\n",
					parent->label, SSAOidString(suffix));
			}

			return node;
		}
	}

	suffix->len = 0;
	suffix->subids = NULL;

	if(trace_level > 0)
	{
		trace("node_find() returned %s with no suffix\n\n",
			node->label);
	}

	return node;
}


/*****************************************************************/




