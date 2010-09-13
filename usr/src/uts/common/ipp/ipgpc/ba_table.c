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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/errno.h>
#include <ipp/ipgpc/classifier.h>

/* Implementation file for behavior aggregate (BA) lookup table */

/*
 * ba_insert(bataid, filter_id, val, mask)
 *
 * inserts filter_id into element list of bataid->table->masked_values
 * at position val& mask, mask is inserted into the mask list.
 * filter_id shouldn't already exist in element list at
 * bataid->table->masked_values[val], an error message is printed if this
 * occurs.
 * return DONTCARE_VALUE if mask == 0, NORMAL_VALUE otherwise
 */
int
ba_insert(ba_table_id_t *bataid, int filter_id, uint8_t val, uint8_t mask)
{
	uint8_t mskd_val = val & mask;
	ba_table_t *table = &bataid->table;

	/* dontcares are not inserted */
	if (mask == 0) {
		++bataid->stats.num_dontcare;
		return (DONTCARE_VALUE);
	}

	if (bataid->info.dontcareonly == B_TRUE) {
		bataid->info.dontcareonly = B_FALSE;
	}

	if (ipgpc_list_insert(&table->masked_values[mskd_val].filter_list,
	    filter_id) == EEXIST) {
		ipgpc0dbg(("ba_insert():filter_id %d EEXIST in ba_table",
		    filter_id));
	} else {
		/* insert mask */
		(void) ipgpc_list_insert(&table->masks, mask);
		/* update stats */
		++table->masked_values[mskd_val].info;
		++bataid->stats.num_inserted;
	}
	return (NORMAL_VALUE);
}

/*
 * ba_retrieve(bataid, value, fid_table)
 *
 * searches for all filters matching value in bataid->table
 * search is performed by appling each mask in bataid->table->masks list
 * to value and then looking value up in bataid->table->masked_values.
 * Each filter id that is matched, is inserted into fid_table
 * returns number of matched filters or (-1) if memory error
 */
int
ba_retrieve(ba_table_id_t *bataid, uint8_t value, ht_match_t *fid_table)
{
	element_node_t *p;
	element_node_t *filter_list;
	int num_found = 0;
	int ret;
	int masked_value = 0;
	ba_table_t *table = &bataid->table;

	/* special case, if value == 0, no need to apply masks */
	if (value == 0) {
		/* masked value will always be 0 for this case */
		filter_list =
		    table->masked_values[0].filter_list;
		if ((num_found = ipgpc_mark_found(bataid->info.mask,
		    filter_list, fid_table)) == -1) {
			return (-1); /* signifies a memory error */
		}
		return (num_found);
	}

	/* apply each mask to the value and do the look up in the ba table */
	for (p = table->masks; p != NULL; p = p->next) {
		masked_value = (uint8_t)(p->id) & value;
		if (bataid->table.masked_values[masked_value].info == 0) {
			/* masked_value has 0 filters associated with it */
			continue;
		}
		filter_list =
		    table->masked_values[masked_value].filter_list;
		if ((ret = ipgpc_mark_found(bataid->info.mask, filter_list,
		    fid_table)) == -1) {
			return (-1); /* signifies a memory error */
		}
		num_found += ret; /* increment num_found */
	}

	return (num_found);
}

/*
 * ba_remove(bataid, filter_id, value, mask)
 *
 * removes filter_id from bataid->table->masked_values[mask & value]
 * mask is removed from bataid->table->masks if refcnt == 0 for that list
 */
void
ba_remove(ba_table_id_t *bataid, int filter_id, uint8_t value, uint8_t mask)
{
	uint8_t masked_value = value & mask;
	ba_table_t *table = &bataid->table;

	/* dontcares are not inserted */
	if (mask == 0) {
		--bataid->stats.num_dontcare;
		return;
	}

	if (ipgpc_list_remove(&table->masked_values[masked_value].filter_list,
	    filter_id) == B_TRUE) {
		/* update stats */
		--table->masked_values[masked_value].info;
		--bataid->stats.num_inserted;
		/*
		 * check to see if removing this entry will result in
		 * don't cares only inserted in the table
		 */
		if (bataid->stats.num_inserted <= 0) {
			bataid->info.dontcareonly = B_TRUE;
		}
		/* remove mask if refcnt == 0 */
		(void) ipgpc_list_remove(&table->masks, mask);
	}
}
