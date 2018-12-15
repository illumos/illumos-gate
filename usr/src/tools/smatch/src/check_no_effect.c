/*
 * Copyright (C) 2010 Dan Carpenter.
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

#include "smatch.h"

static int my_id;

static void match_stmt(struct statement *stmt)
{
	struct expression *expr;

	if (stmt->type != STMT_EXPRESSION)
		return;
	expr = stmt->expression;
	if (!expr)
		return;
	switch(expr->type) {
	case EXPR_PREOP:
		if (expr->op == '!')
			break;
		if (expr->op == '~')
			break;
	case EXPR_POSTOP:
	case EXPR_STATEMENT:
	case EXPR_ASSIGNMENT:
	case EXPR_CALL:
	case EXPR_CONDITIONAL:
	case EXPR_SELECT:
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_COMMA:
		return;
	}
	if (in_expression_statement())
		return;
	sm_warning("statement has no effect %d", expr->type);
}

void check_no_effect(int id)
{
	my_id = id;
	add_hook(&match_stmt, STMT_HOOK);
}
