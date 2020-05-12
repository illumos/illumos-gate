/*
 * Copyright (C) 2017 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 */

/*
 * This basically stores when a pointer is stored as a struct member.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static void match_assign(struct expression *expr)
{
	struct expression *left, *right;
	mtag_t right_tag, left_tag;
	int right_offset, left_offset;
	sval_t sval;

	if (expr->op != '=')
		return;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	if (!type_is_ptr(get_type(right)))
		return;
	if (!get_implied_value(right, &sval))
		return;
	if (sval_cmp(sval, valid_ptr_min_sval) < 0 ||
	    sval_cmp(sval, valid_ptr_max_sval) > 0)
		return;
	right_tag = sval.uvalue & ~MTAG_OFFSET_MASK;
	right_offset = sval.uvalue & MTAG_OFFSET_MASK;

	if (!expr_to_mtag_offset(left, &left_tag, &left_offset) ||
	    left_offset >= MTAG_OFFSET_MASK)
		return;

	sql_insert_mtag_map(left_tag, left_offset, right_tag, right_offset);
}

void register_mtag_map(int id)
{
	my_id = id;

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_assign, GLOBAL_ASSIGNMENT_HOOK);
}
