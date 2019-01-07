/*
 * Copyright (C) 2012 Oracle.
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
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

struct {
	const char *func;
	int param;
} alloc_functions[] = {
	{"kmalloc", 0},
	{"kzalloc", 0},
	{"__kmalloc", 0},
	{"vmalloc", 0},
	{"__vmalloc", 0},
	{"__vmalloc_node", 0},
};

static struct range_list_stack *rl_stack;
static struct string_list *op_list;

static void push_op(char c)
{
	char *p;

	p = malloc(1);
	p[0] = c;
	add_ptr_list(&op_list, p);
}

static char pop_op(void)
{
	char *p;
	char c;

	if (!op_list) {
		sm_perror("%s: no op_list", __func__);
		return '\0';
	}

	p = last_ptr_list((struct ptr_list *)op_list);

	delete_ptr_list_last((struct ptr_list **)&op_list);
	c = p[0];
	free(p);

	return c;
}

static int op_precedence(char c)
{
	switch (c) {
	case '+':
	case '-':
		return 1;
	case '*':
	case '/':
		return 2;
	default:
		return 0;
	}
}

static int top_op_precedence(void)
{
	char *p;

	if (!op_list)
		return 0;

	p = last_ptr_list((struct ptr_list *)op_list);
	return op_precedence(p[0]);
}

static void rl_pop_until(char c)
{
	char op;
	struct range_list *left, *right;
	struct range_list *res;

	while (top_op_precedence() && op_precedence(c) <= top_op_precedence()) {
		op = pop_op();
		right = pop_rl(&rl_stack);
		left = pop_rl(&rl_stack);
		res = rl_binop(left, op, right);
		if (!res)
			res = alloc_whole_rl(&llong_ctype);
		push_rl(&rl_stack, res);
	}
}

static void rl_discard_stacks(void)
{
	while (op_list)
		pop_op();
	while (rl_stack)
		pop_rl(&rl_stack);
}

static int read_rl_from_var(struct expression *call, char *p, char **end, struct range_list **rl)
{
	struct expression *arg;
	struct smatch_state *state;
	long param;
	char *name;
	struct symbol *sym;
	char buf[256];
	int star;

	p++;
	param = strtol(p, &p, 10);

	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return 0;

	if (*p != '-' && *p != '.') {
		get_absolute_rl(arg, rl);
		*end = p;
		return 1;
	}

	*end = strchr(p, ' ');

	if (arg->type == EXPR_PREOP && arg->op == '&') {
		arg = strip_expr(arg->unop);
		star = 0;
		p++;
	} else {
		star = 1;
		p += 2;
	}

	name = expr_to_var_sym(arg, &sym);
	if (!name)
		return 0;
	snprintf(buf, sizeof(buf), "%s%s", name, star ? "->" : ".");
	free_string(name);

	if (*end - p + strlen(buf) >= sizeof(buf))
		return 0;
	strncat(buf, p, *end - p);

	state = get_state(SMATCH_EXTRA, buf, sym);
	if (!state)
		return 0;
	*rl = estate_rl(state);
	return 1;
}

static int read_var_num(struct expression *call, char *p, char **end, struct range_list **rl)
{
	sval_t sval;

	while (*p == ' ')
		p++;

	if (*p == '$')
		return read_rl_from_var(call, p, end, rl);

	sval.type = &llong_ctype;
	sval.value = strtoll(p, end, 10);
	if (*end == p)
		return 0;
	*rl = alloc_rl(sval, sval);
	return 1;
}

static char *read_op(char *p)
{
	while (*p == ' ')
		p++;

	switch (*p) {
	case '+':
	case '-':
	case '*':
	case '/':
		return p;
	default:
		return NULL;
	}
}

int parse_call_math_rl(struct expression *call, char *math, struct range_list **rl)
{
	struct range_list *tmp;
	char *c;

	/* try to implement shunting yard algorithm. */

	c = (char *)math;
	while (1) {
		if (option_debug)
			sm_msg("parsing %s", c);

		/* read a number and push it onto the number stack */
		if (!read_var_num(call, c, &c, &tmp))
			goto fail;
		push_rl(&rl_stack, tmp);

		if (option_debug)
			sm_msg("val = %s remaining = %s", show_rl(tmp), c);

		if (!*c)
			break;
		if (*c == ']' && *(c + 1) == '\0')
			break;

		c = read_op(c);
		if (!c)
			goto fail;

		if (option_debug)
			sm_msg("op = %c remaining = %s", *c, c);

		rl_pop_until(*c);
		push_op(*c);
		c++;
	}

	rl_pop_until(0);
	*rl = pop_rl(&rl_stack);
	return 1;
fail:
	rl_discard_stacks();
	return 0;
}

int parse_call_math(struct expression *call, char *math, sval_t *sval)
{
	struct range_list *rl;

	if (!parse_call_math_rl(call, math, &rl))
		return 0;
	if (!rl_to_sval(rl, sval))
		return 0;
	return 1;
}

static struct smatch_state *alloc_state_sname(char *sname)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	state->name = sname;
	state->data = INT_PTR(1);
	return state;
}

static int get_arg_number(struct expression *expr)
{
	struct symbol *sym;
	struct symbol *arg;
	int i;

	expr = strip_expr(expr);
	if (expr->type != EXPR_SYMBOL)
		return -1;
	sym = expr->symbol;

	i = 0;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		if (arg == sym)
			return i;
		i++;
	} END_FOR_EACH_PTR(arg);

	return -1;
}

static int format_name_sym_helper(char *buf, int remaining, char *name, struct symbol *sym)
{
	int ret = 0;
	int arg;
	char *param_name;
	int name_len;

	if (!name || !sym || !sym->ident)
		goto free;
	arg = get_param_num_from_sym(sym);
	if (arg < 0)
		goto free;
	if (param_was_set_var_sym(name, sym))
		goto free;

	param_name = sym->ident->name;
	name_len = strlen(param_name);

	if (name[name_len] == '\0')
		ret = snprintf(buf, remaining, "$%d", arg);
	else if (name[name_len] == '-')
		ret = snprintf(buf, remaining, "$%d%s", arg, name + name_len);
	else
		goto free;

	remaining -= ret;
	if (remaining <= 0)
		ret = 0;

free:
	free_string(name);

	return ret;

}

static int format_variable_helper(char *buf, int remaining, struct expression *expr)
{
	char *name;
	struct symbol *sym;

	name = expr_to_var_sym(expr, &sym);
	if (param_was_set_var_sym(name, sym))
		return 0;
	return format_name_sym_helper(buf, remaining, name, sym);
}

static int format_call_to_param_mapping(char *buf, int remaining, struct expression *expr)
{
	char *name;
	struct symbol *sym;

	name = map_call_to_param_name_sym(expr, &sym);
	if (param_was_set_var_sym(name, sym))
		return 0;
	return format_name_sym_helper(buf, remaining, name, sym);
}

static int format_expr_helper(char *buf, int remaining, struct expression *expr)
{
	sval_t sval;
	int ret;
	char *cur;

	if (!expr)
		return 0;

	cur = buf;

	if (expr->type == EXPR_BINOP) {
		ret = format_expr_helper(cur, remaining, expr->left);
		if (ret == 0)
			return 0;
		remaining -= ret;
		if (remaining <= 0)
			return 0;
		cur += ret;

		ret = snprintf(cur, remaining, " %s ", show_special(expr->op));
		remaining -= ret;
		if (remaining <= 0)
			return 0;
		cur += ret;

		ret = format_expr_helper(cur, remaining, expr->right);
		if (ret == 0)
			return 0;
		remaining -= ret;
		if (remaining <= 0)
			return 0;
		cur += ret;
		return cur - buf;
	}

	if (get_implied_value(expr, &sval)) {
		ret = snprintf(cur, remaining, "%s", sval_to_str(sval));
		remaining -= ret;
		if (remaining <= 0)
			return 0;
		return ret;
	}

	if (expr->type == EXPR_CALL)
		return format_call_to_param_mapping(cur, remaining, expr);

	return format_variable_helper(cur, remaining, expr);
}

static char *format_expr(struct expression *expr)
{
	char buf[256] = "";
	int ret;

	ret = format_expr_helper(buf, sizeof(buf), expr);
	if (ret == 0)
		return NULL;

	return alloc_sname(buf);
}

char *get_value_in_terms_of_parameter_math(struct expression *expr)
{
	struct expression *tmp;
	char buf[256] = "";
	sval_t dummy;
	int ret;

	tmp = get_assigned_expr(expr);
	if (tmp)
		expr = tmp;
	if (param_was_set(expr))
		return NULL;

	if (get_implied_value(expr, &dummy))
		return NULL;

	ret = format_expr_helper(buf, sizeof(buf), expr);
	if (ret == 0)
		return NULL;

	return alloc_sname(buf);
}

char *get_value_in_terms_of_parameter_math_var_sym(const char *name, struct symbol *sym)
{
	struct expression *tmp, *expr;
	char buf[256] = "";
	int ret;
	int cnt = 0;

	expr = get_assigned_expr_name_sym(name, sym);
	if (!expr)
		return NULL;
	while ((tmp = get_assigned_expr(expr))) {
		expr = strip_expr(tmp);
		if (++cnt > 3)
			break;
	}

	ret = format_expr_helper(buf, sizeof(buf), expr);
	if (ret == 0)
		return NULL;

	return alloc_sname(buf);

}

static void match_alloc(const char *fn, struct expression *expr, void *_size_arg)
{
	int size_arg = PTR_INT(_size_arg);
	struct expression *right;
	struct expression *size_expr;
	char *sname;

	right = strip_expr(expr->right);
	size_expr = get_argument_from_call_expr(right->args, size_arg);

	sname = format_expr(size_expr);
	if (!sname)
		return;
	set_state_expr(my_id, expr->left, alloc_state_sname(sname));
}

static char *swap_format(struct expression *call, char *format)
{
	char buf[256];
	sval_t sval;
	long param;
	struct expression *arg;
	char *p;
	char *out;
	int ret;

	if (format[0] == '$' && format[2] == '\0') {
		param = strtol(format + 1, NULL, 10);
		arg = get_argument_from_call_expr(call->args, param);
		if (!arg)
			return NULL;
		return format_expr(arg);
	}

	buf[0] = '\0';
	p = format;
	out = buf;
	while (*p) {
		if (*p == '$') {
			p++;
			param = strtol(p, &p, 10);
			arg = get_argument_from_call_expr(call->args, param);
			if (!arg)
				return NULL;
			param = get_arg_number(arg);
			if (param >= 0) {
				ret = snprintf(out, buf + sizeof(buf) - out, "$%ld", param);
				out += ret;
				if (out >= buf + sizeof(buf))
					return NULL;
			} else if (get_implied_value(arg, &sval)) {
				ret = snprintf(out, buf + sizeof(buf) - out, "%s", sval_to_str(sval));
				out += ret;
				if (out >= buf + sizeof(buf))
					return NULL;
			} else {
				return NULL;
			}
		}
		*out = *p;
		p++;
		out++;
	}
	if (buf[0] == '\0')
		return NULL;
	*out = '\0';
	return alloc_sname(buf);
}

static char *buf_size_recipe;
static int db_buf_size_callback(void *unused, int argc, char **argv, char **azColName)
{
	if (argc != 1)
		return 0;

	if (!buf_size_recipe)
		buf_size_recipe = alloc_sname(argv[0]);
	else if (strcmp(buf_size_recipe, argv[0]) != 0)
		buf_size_recipe = alloc_sname("invalid");
	return 0;
}

static char *get_allocation_recipe_from_call(struct expression *expr)
{
	struct symbol *sym;
	static char sql_filter[1024];
	int i;

	if (is_fake_call(expr))
		return NULL;
	expr = strip_expr(expr);
	if (expr->fn->type != EXPR_SYMBOL)
		return NULL;
	sym = expr->fn->symbol;
	if (!sym)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(alloc_functions); i++) {
		if (strcmp(sym->ident->name, alloc_functions[i].func) == 0) {
			char buf[32];

			snprintf(buf, sizeof(buf), "$%d", alloc_functions[i].param);
			buf_size_recipe = alloc_sname(buf);
			return swap_format(expr, buf_size_recipe);
		}
	}

	if (sym->ctype.modifiers & MOD_STATIC) {
		snprintf(sql_filter, 1024, "file = '%s' and function = '%s';",
			 get_filename(), sym->ident->name);
	} else {
		snprintf(sql_filter, 1024, "function = '%s' and static = 0;",
				sym->ident->name);
	}

	buf_size_recipe = NULL;
	run_sql(db_buf_size_callback, NULL,
		"select value from return_states where type=%d and %s",
		BUF_SIZE, sql_filter);
	if (!buf_size_recipe || strcmp(buf_size_recipe, "invalid") == 0)
		return NULL;
	return swap_format(expr, buf_size_recipe);
}

static void match_call_assignment(struct expression *expr)
{
	char *sname;

	sname = get_allocation_recipe_from_call(expr->right);
	if (!sname)
		return;
	set_state_expr(my_id, expr->left, alloc_state_sname(sname));
}

static void match_returns_call(int return_id, char *return_ranges, struct expression *call)
{
	char *sname;

	sname = get_allocation_recipe_from_call(call);
	if (option_debug)
		sm_msg("sname = %s", sname);
	if (!sname)
		return;

	sql_insert_return_states(return_id, return_ranges, BUF_SIZE, -1, "",
			sname);
}

static void print_returned_allocations(int return_id, char *return_ranges, struct expression *expr)
{
	struct expression *tmp;
	struct smatch_state *state;
	struct symbol *sym;
	char *name;
	int cnt = 0;

	expr = strip_expr(expr);
	while ((tmp = get_assigned_expr(expr))) {
		if (cnt++ > 5)  /* assignments to self cause infinite loops */
			break;
		expr = strip_expr(tmp);
	}
	if (!expr)
		return;

	if (expr->type == EXPR_CALL) {
		match_returns_call(return_id, return_ranges, expr);
		return;
	}

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	state = get_state(my_id, name, sym);
	if (!state || !state->data)
		goto free;

	sql_insert_return_states(return_id, return_ranges, BUF_SIZE, -1, "",
			state->name);
free:
	free_string(name);
}

void register_parse_call_math(int id)
{
	int i;

	my_id = id;

	for (i = 0; i < ARRAY_SIZE(alloc_functions); i++)
		add_function_assign_hook(alloc_functions[i].func, &match_alloc,
				         INT_PTR(alloc_functions[i].param));
	add_hook(&match_call_assignment, CALL_ASSIGNMENT_HOOK);
	add_split_return_callback(print_returned_allocations);
}

