/*
 * Copyright (C) 2009 Dan Carpenter.
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
 * The idea behind this test is that if we have:
 * void foo(int bar)
 * {
 *         baz(1, bar);
 * }
 *
 * Passing "bar" to foo() really means passing "bar" to baz();
 * 
 * In this case it would print:
 * info: param_mapper 0 => bar 1
 *
 */

#include "smatch.h"

static int my_id;

STATE(argument);

static struct symbol *func_sym;

static void delete(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &undefined);
}

static void match_function_def(struct symbol *sym)
{
	struct symbol *arg;

	func_sym = sym;
	FOR_EACH_PTR(func_sym->ctype.base_type->arguments, arg) {
		if (!arg->ident) {
			continue;
		}
		set_state(my_id, arg->ident->name, arg, &argument);
	} END_FOR_EACH_PTR(arg);
}

static int get_arg_num(struct expression *expr)
{
	struct smatch_state *state;
	struct symbol *arg;
	struct symbol *this_arg;
	int i;

	expr = strip_expr(expr);
	if (expr->type != EXPR_SYMBOL)
		return -1;
	this_arg = expr->symbol;

	state = get_state_expr(my_id, expr);
	if (!state || state != &argument)
		return -1;
	
	i = 0;
	FOR_EACH_PTR(func_sym->ctype.base_type->arguments, arg) {
		if (arg == this_arg)
			return i;
		i++;
	} END_FOR_EACH_PTR(arg);

	return -1;
}

static void match_call(struct expression *expr)
{
	struct expression *tmp;
	char *func;
	int arg_num;
	int i;

	if (expr->fn->type != EXPR_SYMBOL)
		return;

	func = expr->fn->symbol_name->name;

	i = 0;
	FOR_EACH_PTR(expr->args, tmp) {
		tmp = strip_expr(tmp);
		arg_num = get_arg_num(tmp);
		if (arg_num >= 0)
			sm_msg("info: param_mapper %d => %s %d", arg_num, func, i);
		i++;
	} END_FOR_EACH_PTR(tmp);
}

void check_param_mapper(int id)
{
	if (!option_param_mapper)
		return;
	my_id = id;
	add_modification_hook(my_id, &delete);
	add_hook(&match_function_def, FUNC_DEF_HOOK);
	add_hook(&match_call, FUNCTION_CALL_HOOK);
}
