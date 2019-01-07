/*
 * Copyright (C) 2013 Oracle.
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

#define RECURSE_LIMIT 10

static int recurse(struct expression *expr,
		   int (func)(struct expression *expr, void *p),
		   void *param, int nr)
{
	int ret;

	if (!expr)
		return 0;

	ret = func(expr, param);
	if (ret)
		return ret;

	if (nr > RECURSE_LIMIT)
		return -1;
	nr++;

	switch (expr->type) {
	case EXPR_PREOP:
		ret = recurse(expr->unop, func, param, nr);
		break;
	case EXPR_POSTOP:
		ret = recurse(expr->unop, func, param, nr);
		break;
	case EXPR_STATEMENT:
		return -1;
		break;
	case EXPR_LOGICAL:
	case EXPR_COMPARE:
	case EXPR_BINOP:
	case EXPR_COMMA:
		ret = recurse(expr->left, func, param, nr);
		if (ret)
			return ret;
		ret = recurse(expr->right, func, param, nr);
		break;
	case EXPR_ASSIGNMENT:
		ret = recurse(expr->right, func, param, nr);
		if (ret)
			return ret;
		ret = recurse(expr->left, func, param, nr);
		break;
	case EXPR_DEREF:
		ret = recurse(expr->deref, func, param, nr);
		break;
	case EXPR_SLICE:
		ret = recurse(expr->base, func, param, nr);
		break;
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
		ret = recurse(expr->cast_expression, func, param, nr);
		break;
	case EXPR_SIZEOF:
	case EXPR_OFFSETOF:
	case EXPR_ALIGNOF:
		break;
	case EXPR_CONDITIONAL:
	case EXPR_SELECT:
		ret = recurse(expr->conditional, func, param, nr);
		if (ret)
			return ret;
		ret = recurse(expr->cond_true, func, param, nr);
		if (ret)
			return ret;
		ret = recurse(expr->cond_false, func, param, nr);
		break;
	case EXPR_CALL:
		return -1;
		break;
	case EXPR_INITIALIZER:
		return -1;
		break;
	case EXPR_IDENTIFIER:
		ret = recurse(expr->ident_expression, func, param, nr);
		break;
	case EXPR_INDEX:
		ret = recurse(expr->idx_expression, func, param, nr);
		break;
	case EXPR_POS:
		ret = recurse(expr->init_expr, func, param, nr);
		break;
	case EXPR_SYMBOL:
	case EXPR_STRING:
	case EXPR_VALUE:
		break;
	default:
		return -1;
		break;
	};
	return ret;
}

static int has_symbol_helper(struct expression *expr, void *_sym)
{
	struct symbol *sym = _sym;

	if (!expr || expr->type != EXPR_SYMBOL)
		return 0;
	if (expr->symbol == sym)
		return 1;
	return 0;
}

int has_symbol(struct expression *expr, struct symbol *sym)
{
	return recurse(expr, has_symbol_helper, sym, 0);
}

struct expr_name_sym {
	struct expression *expr;
	char *name;
	struct symbol *sym;
};

static int has_var_helper(struct expression *expr, void *_var)
{
	struct expr_name_sym *xns = _var;
	char *name;
	struct symbol *sym;
	int matched = 0;

	if (!expr)
		return 0;
	if (expr->type != xns->expr->type)
		return 0;
	// I hope this is defined for everything?  It should work, right?
	if (expr->op != xns->expr->op)
		return 0;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	if (sym == xns->sym && strcmp(name, xns->name) == 0)
		matched = 1;
free:
	free_string(name);
	return matched;
}

int has_variable(struct expression *expr, struct expression *var)
{
	struct expr_name_sym xns;
	int ret = -1;

	xns.expr = var;
	xns.name = expr_to_var_sym(var, &xns.sym);
	if (!xns.name || !xns.sym)
		goto free;
	ret = recurse(expr, has_var_helper, &xns, 0);
free:
	free_string(xns.name);
	return ret;
}

static int has_inc_dec_helper(struct expression *expr, void *unused)
{
	if (!expr)
		return 0;
	if (expr->type != EXPR_PREOP && expr->type != EXPR_POSTOP)
		return 0;
	if (expr->op == SPECIAL_INCREMENT || expr->op == SPECIAL_DECREMENT)
		return 1;
	return 0;
}

int has_inc_dec(struct expression *expr)
{
	return recurse(expr, has_inc_dec_helper, NULL, 0);
}

