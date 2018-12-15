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

ALLOCATOR(var_sym, "var_sym structs");

struct var_sym *alloc_var_sym(const char *var, struct symbol *sym)
{
	struct var_sym *tmp;

	tmp = __alloc_var_sym(0);
	tmp->var = alloc_string(var);
	tmp->sym = sym;
	return tmp;
}

struct var_sym_list *expr_to_vsl(struct expression *expr)
{
	struct expression *unop;
	struct var_sym_list *ret = NULL;
	char *var;
	struct symbol *sym;

	expr = strip_expr(expr);
	if (!expr)
		return NULL;

	if ((expr->type == EXPR_PREOP && expr->op == '*')) {
		unop = strip_expr(expr->unop);

		if (unop->type == EXPR_SYMBOL)
			goto one_var;
		return expr_to_vsl(unop);
	}

	if (expr->type == EXPR_BINOP ||
	    expr->type == EXPR_LOGICAL ||
	    expr->type == EXPR_COMPARE) {
		struct var_sym_list *left, *right;

		left = expr_to_vsl(expr->left);
		right = expr_to_vsl(expr->right);
		ret = combine_var_sym_lists(left, right);
		free_var_syms_and_list(&left);
		free_var_syms_and_list(&right);
		return ret;
	}

	if (expr->type == EXPR_DEREF)
		return expr_to_vsl(expr->deref);

one_var:
	var = expr_to_var_sym(expr, &sym);
	if (!var || !sym) {
		free_string(var);
		return NULL;
	}
	add_var_sym(&ret, var, sym);
	return ret;
}

int cmp_var_sym(const struct var_sym *a, const struct var_sym *b)
{
	int ret;

	if (a == b)
		return 0;
	if (!b)
		return -1;
	if (!a)
		return 1;

	ret = strcmp(a->var, b->var);
	if (ret < 0)
		return -1;
	if (ret > 0)
		return 1;

	if (!b->sym && a->sym)
		return -1;
	if (!a->sym && b->sym)
		return 1;
	if (a->sym < b->sym)
		return -1;
	if (a->sym > b->sym)
		return 1;

	return 0;
}

void add_var_sym(struct var_sym_list **list, const char *var, struct symbol *sym)
{
	struct var_sym *tmp, *new;

	if (in_var_sym_list(*list, var, sym))
		return;
	new = alloc_var_sym(var, sym);

	FOR_EACH_PTR(*list, tmp) {
		if (cmp_var_sym(tmp, new) < 0)
			continue;
		else if (cmp_var_sym(tmp, new) == 0) {
			return;
		} else {
			INSERT_CURRENT(new, tmp);
			return;
		}
	} END_FOR_EACH_PTR(tmp);
	add_ptr_list(list, new);
}

void add_var_sym_expr(struct var_sym_list **list, struct expression *expr)
{
	char *var;
	struct symbol *sym;

	var = expr_to_var_sym(expr, &sym);
	if (!var || !sym)
		goto free;
	add_var_sym(list, var, sym);
free:
	free_string(var);
}

static void free_var_sym(struct var_sym *vs)
{
	free_string(vs->var);
	__free_var_sym(vs);
}

void del_var_sym(struct var_sym_list **list, const char *var, struct symbol *sym)
{
	struct var_sym *tmp;

	FOR_EACH_PTR(*list, tmp) {
		if (tmp->sym == sym && strcmp(tmp->var, var) == 0) {
			DELETE_CURRENT_PTR(tmp);
			free_var_sym(tmp);
			return;
		}
	} END_FOR_EACH_PTR(tmp);
}

int in_var_sym_list(struct var_sym_list *list, const char *var, struct symbol *sym)
{
	struct var_sym *tmp;

	FOR_EACH_PTR(list, tmp) {
		if (tmp->sym == sym && strcmp(tmp->var, var) == 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

struct var_sym_list *clone_var_sym_list(struct var_sym_list *from_vsl)
{
	struct var_sym *tmp, *clone_vs;
	struct var_sym_list *to_vsl = NULL;

	FOR_EACH_PTR(from_vsl, tmp) {
		clone_vs = alloc_var_sym(tmp->var, tmp->sym);
		add_ptr_list(&to_vsl, clone_vs);
	} END_FOR_EACH_PTR(tmp);
	return to_vsl;
}

void merge_var_sym_list(struct var_sym_list **dest, struct var_sym_list *src)
{
	struct var_sym *tmp;

	FOR_EACH_PTR(src, tmp) {
		add_var_sym(dest, tmp->var, tmp->sym);
	} END_FOR_EACH_PTR(tmp);
}

struct var_sym_list *combine_var_sym_lists(struct var_sym_list *one, struct var_sym_list *two)
{
	struct var_sym_list *to_vsl;

	to_vsl = clone_var_sym_list(one);
	merge_var_sym_list(&to_vsl, two);
	return to_vsl;
}

int var_sym_lists_equiv(struct var_sym_list *one, struct var_sym_list *two)
{
	struct var_sym *one_tmp, *two_tmp;

	if (one == two)
		return 1;

	if (ptr_list_size((struct ptr_list *)one) != ptr_list_size((struct ptr_list *)two))
		return 0;

	PREPARE_PTR_LIST(one, one_tmp);
	PREPARE_PTR_LIST(two, two_tmp);
	for (;;) {
		if (!one_tmp && !two_tmp)
			return 1;
		if (one_tmp->sym != two_tmp->sym)
			return 0;
		if (strcmp(one_tmp->var, two_tmp->var) != 0)
			return 0;
		NEXT_PTR_LIST(one_tmp);
		NEXT_PTR_LIST(two_tmp);
	}
	FINISH_PTR_LIST(two_tmp);
	FINISH_PTR_LIST(one_tmp);

	return 1;
}

void free_var_sym_list(struct var_sym_list **list)
{
	__free_ptr_list((struct ptr_list **)list);
}

void free_var_syms_and_list(struct var_sym_list **list)
{
	struct var_sym *tmp;

	FOR_EACH_PTR(*list, tmp) {
		free_var_sym(tmp);
	} END_FOR_EACH_PTR(tmp);
	free_var_sym_list(list);
}

