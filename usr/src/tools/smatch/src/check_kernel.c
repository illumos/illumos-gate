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

/*
 * This is kernel specific stuff for smatch_extra.
 */

#include "scope.h"
#include "smatch.h"
#include "smatch_extra.h"

static int implied_err_cast_return(struct expression *call, void *unused, struct range_list **rl)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(call->args, 0);
	if (!get_implied_rl(arg, rl))
		*rl = alloc_rl(ll_to_sval(-4095), ll_to_sval(-1));
	return 1;
}

static void hack_ERR_PTR(struct symbol *sym)
{
	struct symbol *arg;
	struct smatch_state *estate;
	struct range_list *after;
	sval_t low_error;
	sval_t minus_one;
	sval_t zero;

	low_error.type = &long_ctype;
	low_error.value = -4095;

	minus_one.type = &long_ctype;
	minus_one.value = -1;

	zero.type = &long_ctype;
	zero.value = 0;

	if (!sym || !sym->ident)
		return;
	if (strcmp(sym->ident->name, "ERR_PTR") != 0)
		return;

	arg = first_ptr_list((struct ptr_list *)sym->ctype.base_type->arguments);
	if (!arg || !arg->ident)
		return;

	estate = get_state(SMATCH_EXTRA, arg->ident->name, arg);
	if (!estate) {
		after = alloc_rl(low_error, minus_one);
	} else {
		after = rl_intersection(estate_rl(estate), alloc_rl(low_error, zero));
		if (rl_equiv(estate_rl(estate), after))
			return;
	}
	set_state(SMATCH_EXTRA, arg->ident->name, arg, alloc_estate_rl(after));
}

static void match_param_valid_ptr(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *_param)
{
	int param = PTR_INT(_param);
	struct expression *arg;
	struct smatch_state *pre_state;
	struct smatch_state *end_state;

	arg = get_argument_from_call_expr(call_expr->args, param);
	pre_state = get_state_expr(SMATCH_EXTRA, arg);
	end_state = estate_filter_range(pre_state, ll_to_sval(-4095), ll_to_sval(0));
	set_extra_expr_nomod(arg, end_state);
}

static void match_param_err_or_null(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *_param)
{
	int param = PTR_INT(_param);
	struct expression *arg;
	struct range_list *rl;
	struct smatch_state *pre_state;
	struct smatch_state *end_state;

	arg = get_argument_from_call_expr(call_expr->args, param);
	pre_state = get_state_expr(SMATCH_EXTRA, arg);
	rl = alloc_rl(ll_to_sval(-4095), ll_to_sval(0));
	rl = rl_intersection(estate_rl(pre_state), rl);
	rl = cast_rl(estate_type(pre_state), rl);
	end_state = alloc_estate_rl(rl);
	set_extra_expr_nomod(arg, end_state);
}

static void match_not_err(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	struct expression *arg;
	struct smatch_state *pre_state;
	struct smatch_state *new_state;

	arg = get_argument_from_call_expr(call_expr->args, 0);
	pre_state = get_state_expr(SMATCH_EXTRA, arg);
	new_state = estate_filter_range(pre_state, sval_type_min(&long_ctype), ll_to_sval(-1));
	set_extra_expr_nomod(arg, new_state);
}

static void match_err(const char *fn, struct expression *call_expr,
			struct expression *assign_expr, void *unused)
{
	struct expression *arg;
	struct smatch_state *pre_state;
	struct smatch_state *new_state;

	arg = get_argument_from_call_expr(call_expr->args, 0);
	pre_state = get_state_expr(SMATCH_EXTRA, arg);
	new_state = estate_filter_range(pre_state, sval_type_min(&long_ctype), ll_to_sval(-4096));
	new_state = estate_filter_range(new_state, ll_to_sval(0), sval_type_max(&long_ctype));
	set_extra_expr_nomod(arg, new_state);
}

static void match_container_of_macro(const char *fn, struct expression *expr, void *unused)
{
	set_extra_expr_mod(expr->left, alloc_estate_range(valid_ptr_min_sval, valid_ptr_max_sval));
}

static void match_container_of(struct expression *expr)
{
	struct expression *right = expr->right;
	char *macro;

	/*
	 * The problem here is that sometimes the container_of() macro is itself
	 * inside a macro and get_macro() only returns the name of the outside
	 * macro.
	 */

	/*
	 * This actually an expression statement assignment but smatch_flow
	 * pre-mangles it for us so we only get the last chunk:
	 * sk = (typeof(sk))((char *)__mptr - offsetof(...))
	 */

	macro = get_macro_name(right->pos);
	if (!macro)
		return;
	if (right->type != EXPR_CAST)
		return;
	right = strip_expr(right);
	if (right->type != EXPR_BINOP || right->op != '-' ||
	    right->left->type != EXPR_CAST)
		return;
	right = strip_expr(right->left);
	if (right->type != EXPR_SYMBOL)
		return;
	if (!right->symbol->ident ||
	    strcmp(right->symbol->ident->name, "__mptr") != 0)
		return;
	set_extra_expr_mod(expr->left, alloc_estate_range(valid_ptr_min_sval, valid_ptr_max_sval));
}

static int match_next_bit(struct expression *call, void *unused, struct range_list **rl)
{
	struct expression *start_arg;
	struct expression *size_arg;
	struct symbol *type;
	sval_t min, max, tmp;

	size_arg = get_argument_from_call_expr(call->args, 1);
	/* btw. there isn't a start_arg for find_first_bit() */
	start_arg = get_argument_from_call_expr(call->args, 2);

	type = get_type(call);
	min = sval_type_val(type, 0);
	max = sval_type_val(type, sizeof(long long) * 8);

	if (get_implied_max(size_arg, &tmp) && tmp.uvalue < max.value)
		max = tmp;
	if (start_arg && get_implied_min(start_arg, &tmp) && !sval_is_negative(tmp))
		min = tmp;
	if (sval_cmp(min, max) > 0)
		max = min;
	min = sval_cast(type, min);
	max = sval_cast(type, max);
	*rl = alloc_rl(min, max);
	return 1;
}

static int match_fls(struct expression *call, void *unused, struct range_list **rl)
{
	struct expression *arg;
	struct range_list *arg_rl;
	sval_t zero = {};
	sval_t start, end, sval;

	start.type = &int_ctype;
	start.value = 0;
	end.type = &int_ctype;
	end.value = 32;

	arg = get_argument_from_call_expr(call->args, 0);
	if (!get_implied_rl(arg, &arg_rl))
		return 0;
	if (rl_to_sval(arg_rl, &sval)) {
		int i;

		for (i = 63; i >= 0; i--) {
			if (sval.uvalue & 1ULL << i)
				break;
		}
		sval.value = i + 1;
		*rl = alloc_rl(sval, sval);
		return 1;
	}
	zero.type = rl_type(arg_rl);
	if (!rl_has_sval(arg_rl, zero))
		start.value = 1;
	*rl = alloc_rl(start, end);
	return 1;
}



static void find_module_init_exit(struct symbol_list *sym_list)
{
	struct symbol *sym;
	struct symbol *fn;
	struct statement *stmt;
	char *name;
	int init;
	int count;

	/*
	 * This is more complicated because Sparse ignores the "alias"
	 * attribute.  I search backwards because module_init() is normally at
	 * the end of the file.
	 */
	count = 0;
	FOR_EACH_PTR_REVERSE(sym_list, sym) {
		if (sym->type != SYM_NODE)
			continue;
		if (!(sym->ctype.modifiers & MOD_STATIC))
			continue;
		fn = get_base_type(sym);
		if (!fn)
			continue;
		if (fn->type != SYM_FN)
			continue;
		if (!sym->ident)
			continue;
		if (!fn->inline_stmt)
			continue;
		if (strcmp(sym->ident->name, "__inittest") == 0)
			init = 1;
		else if (strcmp(sym->ident->name, "__exittest") == 0)
			init = 0;
		else
			continue;

		count++;

		stmt = first_ptr_list((struct ptr_list *)fn->inline_stmt->stmts);
		if (!stmt || stmt->type != STMT_RETURN)
			continue;
		name = expr_to_var(stmt->ret_value);
		if (!name)
			continue;
		if (init)
			sql_insert_function_ptr(name, "(struct module)->init");
		else
			sql_insert_function_ptr(name, "(struct module)->exit");
		free_string(name);
		if (count >= 2)
			return;
	} END_FOR_EACH_PTR_REVERSE(sym);
}

static void match_end_file(struct symbol_list *sym_list)
{
	struct symbol *sym;

	/* find the last static symbol in the file */
	FOR_EACH_PTR_REVERSE(sym_list, sym) {
		if (!(sym->ctype.modifiers & MOD_STATIC))
			continue;
		if (!sym->scope)
			continue;
		find_module_init_exit(sym->scope->symbols);
		return;
	} END_FOR_EACH_PTR_REVERSE(sym);
}

static struct expression *get_val_expr(struct expression *expr)
{
	struct symbol *sym, *val;

	if (expr->type != EXPR_DEREF)
		return NULL;
	expr = expr->deref;
	if (expr->type != EXPR_SYMBOL)
		return NULL;
	if (strcmp(expr->symbol_name->name, "__u") != 0)
		return NULL;
	sym = get_base_type(expr->symbol);
	val = first_ptr_list((struct ptr_list *)sym->symbol_list);
	if (!val || strcmp(val->ident->name, "__val") != 0)
		return NULL;
	return member_expression(expr, '.', val->ident);
}

static void match__write_once_size(const char *fn, struct expression *call,
			       void *unused)
{
	struct expression *dest, *data, *assign;
	struct range_list *rl;

	dest = get_argument_from_call_expr(call->args, 0);
	if (dest->type != EXPR_PREOP || dest->op != '&')
		return;
	dest = strip_expr(dest->unop);

	data = get_argument_from_call_expr(call->args, 1);
	data = get_val_expr(data);
	if (!data)
		return;
	get_absolute_rl(data, &rl);
	assign = assign_expression(dest, '=', data);

	__in_fake_assign++;
	__split_expr(assign);
	__in_fake_assign--;
}

static void match__read_once_size(const char *fn, struct expression *call,
			       void *unused)
{
	struct expression *dest, *data, *assign;
	struct symbol *type, *val_sym;

	/*
	 * We want to change:
	 *	__read_once_size_nocheck(&(x), __u.__c, sizeof(x));
	 * into a fake assignment:
	 *	__u.val = x;
	 *
	 */

	data = get_argument_from_call_expr(call->args, 0);
	if (data->type != EXPR_PREOP || data->op != '&')
		return;
	data = strip_parens(data->unop);

	dest = get_argument_from_call_expr(call->args, 1);
	if (dest->type != EXPR_DEREF || dest->op != '.')
		return;
	if (!dest->member || strcmp(dest->member->name, "__c") != 0)
		return;
	dest = dest->deref;
	type = get_type(dest);
	if (!type)
		return;
	val_sym = first_ptr_list((struct ptr_list *)type->symbol_list);
	dest = member_expression(dest, '.', val_sym->ident);

	assign = assign_expression(dest, '=', data);
	__in_fake_assign++;
	__split_expr(assign);
	__in_fake_assign--;
}

void check_kernel(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	add_implied_return_hook("ERR_PTR", &implied_err_cast_return, NULL);
	add_implied_return_hook("ERR_CAST", &implied_err_cast_return, NULL);
	add_implied_return_hook("PTR_ERR", &implied_err_cast_return, NULL);
	add_hook(hack_ERR_PTR, AFTER_DEF_HOOK);
	return_implies_state("IS_ERR_OR_NULL", 0, 0, &match_param_valid_ptr, (void *)0);
	return_implies_state("IS_ERR_OR_NULL", 1, 1, &match_param_err_or_null, (void *)0);
	return_implies_state("IS_ERR", 0, 0, &match_not_err, NULL);
	return_implies_state("IS_ERR", 1, 1, &match_err, NULL);
	return_implies_state("tomoyo_memory_ok", 1, 1, &match_param_valid_ptr, (void *)0);

	add_macro_assign_hook_extra("container_of", &match_container_of_macro, NULL);
	add_hook(match_container_of, ASSIGNMENT_HOOK);

	add_implied_return_hook("find_next_bit", &match_next_bit, NULL);
	add_implied_return_hook("find_next_zero_bit", &match_next_bit, NULL);
	add_implied_return_hook("find_first_bit", &match_next_bit, NULL);
	add_implied_return_hook("find_first_zero_bit", &match_next_bit, NULL);

	add_implied_return_hook("fls", &match_fls, NULL);
	add_implied_return_hook("fls64", &match_fls, NULL);

	add_function_hook("__ftrace_bad_type", &__match_nullify_path_hook, NULL);
	add_function_hook("__write_once_size", &match__write_once_size, NULL);

	add_function_hook("__read_once_size", &match__read_once_size, NULL);
	add_function_hook("__read_once_size_nocheck", &match__read_once_size, NULL);

	if (option_info)
		add_hook(match_end_file, END_FILE_HOOK);
}
