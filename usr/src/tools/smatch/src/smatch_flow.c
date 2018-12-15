/*
 * Copyright (C) 2006,2008 Dan Carpenter.
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

#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdio.h>
#include "token.h"
#include "scope.h"
#include "smatch.h"
#include "smatch_expression_stacks.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

int __in_fake_assign;
int __in_fake_struct_assign;
int in_fake_env;
int final_pass;
int __inline_call;
struct expression  *__inline_fn;

static int __smatch_lineno = 0;

static char *base_file;
static const char *filename;
static char *pathname;
static char *full_filename;
static char *full_base_file;
static char *cur_func;
static unsigned int loop_count;
static int last_goto_statement_handled;
int __expr_stmt_count;
int __in_function_def;
static struct expression_list *switch_expr_stack = NULL;
static struct expression_list *post_op_stack = NULL;

static struct ptr_list *backup;

struct expression_list *big_expression_stack;
struct statement_list *big_statement_stack;
struct statement *__prev_stmt;
struct statement *__cur_stmt;
struct statement *__next_stmt;
int __in_pre_condition = 0;
int __bail_on_rest_of_function = 0;
static struct timeval fn_start_time;
static struct timeval outer_fn_start_time;
char *get_function(void) { return cur_func; }
int get_lineno(void) { return __smatch_lineno; }
int inside_loop(void) { return !!loop_count; }
int definitely_inside_loop(void) { return !!(loop_count & ~0x08000000); }
struct expression *get_switch_expr(void) { return top_expression(switch_expr_stack); }
int in_expression_statement(void) { return !!__expr_stmt_count; }

static void split_symlist(struct symbol_list *sym_list);
static void split_declaration(struct symbol_list *sym_list);
static void split_expr_list(struct expression_list *expr_list, struct expression *parent);
static void add_inline_function(struct symbol *sym);
static void parse_inline(struct expression *expr);

int option_assume_loops = 0;
int option_two_passes = 0;
struct symbol *cur_func_sym = NULL;
struct stree *global_states;

long long valid_ptr_min = 4096;
long long valid_ptr_max = 2117777777;
sval_t valid_ptr_min_sval = {
	.type = &ptr_ctype,
	{.value = 4096},
};
sval_t valid_ptr_max_sval = {
	.type = &ptr_ctype,
	{.value = LONG_MAX - 100000},
};
struct range_list *valid_ptr_rl;

static void set_valid_ptr_max(void)
{
	if (type_bits(&ptr_ctype) == 32)
		valid_ptr_max = 2117777777;
	else if (type_bits(&ptr_ctype) == 64)
		valid_ptr_max = 2117777777777777777LL;

	valid_ptr_max_sval.value = valid_ptr_max;
}

static void alloc_valid_ptr_rl(void)
{
	valid_ptr_rl = alloc_rl(valid_ptr_min_sval, valid_ptr_max_sval);
	valid_ptr_rl = cast_rl(&ptr_ctype, valid_ptr_rl);
	valid_ptr_rl = clone_rl_permanent(valid_ptr_rl);
}

int outside_of_function(void)
{
	return cur_func_sym == NULL;
}

const char *get_filename(void)
{
	if (option_info && option_full_path)
		return full_base_file;
	if (option_info)
		return base_file;
	if (option_full_path)
		return full_filename;
	return filename;
}

const char *get_base_file(void)
{
	if (option_full_path)
		return full_base_file;
	return base_file;
}

static void set_position(struct position pos)
{
	int len;
	static int prev_stream = -1;

	if (in_fake_env)
		return;

	if (pos.stream == 0 && pos.line == 0)
		return;

	__smatch_lineno = pos.line;

	if (pos.stream == prev_stream)
		return;

	filename = stream_name(pos.stream);

	free(full_filename);
	pathname = getcwd(NULL, 0);
	if (pathname) {
		len = strlen(pathname) + 1 + strlen(filename) + 1;
		full_filename = malloc(len);
		snprintf(full_filename, len, "%s/%s", pathname, filename);
	} else {
		full_filename = alloc_string(filename);
	}
	free(pathname);
}

int is_assigned_call(struct expression *expr)
{
	struct expression *parent = expr_get_parent_expr(expr);

	if (parent &&
	    parent->type == EXPR_ASSIGNMENT &&
	    parent->op == '=' &&
	    strip_expr(parent->right) == expr)
		return 1;

	return 0;
}

static int is_inline_func(struct expression *expr)
{
	if (expr->type != EXPR_SYMBOL || !expr->symbol)
		return 0;
	if (expr->symbol->ctype.modifiers & MOD_INLINE)
		return 1;
	return 0;
}

static int is_noreturn_func(struct expression *expr)
{
	if (expr->type != EXPR_SYMBOL || !expr->symbol)
		return 0;
	if (expr->symbol->ctype.modifiers & MOD_NORETURN)
		return 1;
	return 0;
}

static int inline_budget = 20;

int inlinable(struct expression *expr)
{
	struct symbol *sym;
	struct statement *last_stmt = NULL;

	if (__inline_fn)  /* don't nest */
		return 0;

	if (expr->type != EXPR_SYMBOL || !expr->symbol)
		return 0;
	if (is_no_inline_function(expr->symbol->ident->name))
		return 0;
	sym = get_base_type(expr->symbol);
	if (sym->stmt && sym->stmt->type == STMT_COMPOUND) {
		if (ptr_list_size((struct ptr_list *)sym->stmt->stmts) > 10)
			return 0;
		if (sym->stmt->type != STMT_COMPOUND)
			return 0;
		last_stmt = last_ptr_list((struct ptr_list *)sym->stmt->stmts);
	}
	if (sym->inline_stmt && sym->inline_stmt->type == STMT_COMPOUND) {
		if (ptr_list_size((struct ptr_list *)sym->inline_stmt->stmts) > 10)
			return 0;
		if (sym->inline_stmt->type != STMT_COMPOUND)
			return 0;
		last_stmt = last_ptr_list((struct ptr_list *)sym->inline_stmt->stmts);
	}

	if (!last_stmt)
		return 0;

	/* the magic numbers in this function are pulled out of my bum. */
	if (last_stmt->pos.line > sym->pos.line + inline_budget)
		return 0;

	return 1;
}

void __process_post_op_stack(void)
{
	struct expression *expr;

	FOR_EACH_PTR(post_op_stack, expr) {
		__pass_to_client(expr, OP_HOOK);
	} END_FOR_EACH_PTR(expr);

	__free_ptr_list((struct ptr_list **)&post_op_stack);
}

static int handle_comma_assigns(struct expression *expr)
{
	struct expression *right;
	struct expression *assign;

	right = strip_expr(expr->right);
	if (right->type != EXPR_COMMA)
		return 0;

	__split_expr(right->left);
	__process_post_op_stack();

	assign = assign_expression(expr->left, '=', right->right);
	__split_expr(assign);

	return 1;
}

/* This is to handle *p++ = foo; assignments */
static int handle_postop_assigns(struct expression *expr)
{
	struct expression *left, *fake_left;
	struct expression *assign;

	left = strip_expr(expr->left);
	if (left->type != EXPR_PREOP || left->op != '*')
		return 0;
	left = strip_expr(left->unop);
	if (left->type != EXPR_POSTOP)
		return 0;

	fake_left = deref_expression(strip_expr(left->unop));
	assign = assign_expression(fake_left, '=', expr->right);

	__split_expr(assign);
	__split_expr(expr->left);

	return 1;
}

static int prev_expression_is_getting_address(struct expression *expr)
{
	struct expression *parent;

	do {
		parent = expr_get_parent_expr(expr);

		if (!parent)
			return 0;
		if (parent->type == EXPR_PREOP && parent->op == '&')
			return 1;
		if (parent->type == EXPR_PREOP && parent->op == '(')
			goto next;
		if (parent->type == EXPR_DEREF && parent->op == '.')
			goto next;

		return 0;
next:
		expr = parent;
	} while (1);
}

static void handle_builtin_overflow_func(struct expression *expr)
{
	struct expression *a, *b, *res, *assign;
	int op;

	if (sym_name_is("__builtin_add_overflow", expr->fn))
		op = '+';
	else if (sym_name_is("__builtin_sub_overflow", expr->fn))
		op = '-';
	else if (sym_name_is("__builtin_mul_overflow", expr->fn))
		op = '*';
	else
		return;

	a = get_argument_from_call_expr(expr->args, 0);
	b = get_argument_from_call_expr(expr->args, 1);
	res = get_argument_from_call_expr(expr->args, 2);

	assign = assign_expression(deref_expression(res), '=', binop_expression(a, op, b));
	__split_expr(assign);
}

static int handle__builtin_choose_expr(struct expression *expr)
{
	struct expression *const_expr, *expr1, *expr2;
	sval_t sval;

	if (!sym_name_is("__builtin_choose_expr", expr->fn))
		return 0;

	const_expr = get_argument_from_call_expr(expr->args, 0);
	expr1 = get_argument_from_call_expr(expr->args, 1);
	expr2 = get_argument_from_call_expr(expr->args, 2);

	if (!get_value(const_expr, &sval) || !expr1 || !expr2)
		return 0;
	if (sval.value)
		__split_expr(expr1);
	else
		__split_expr(expr2);
	return 1;
}

static int handle__builtin_choose_expr_assigns(struct expression *expr)
{
	struct expression *const_expr, *right, *expr1, *expr2, *fake;
	sval_t sval;

	right = strip_expr(expr->right);
	if (right->type != EXPR_CALL)
		return 0;
	if (!sym_name_is("__builtin_choose_expr", right->fn))
		return 0;

	const_expr = get_argument_from_call_expr(right->args, 0);
	expr1 = get_argument_from_call_expr(right->args, 1);
	expr2 = get_argument_from_call_expr(right->args, 2);

	if (!get_value(const_expr, &sval) || !expr1 || !expr2)
		return 0;

	fake = assign_expression(expr->left, '=', sval.value ? expr1 : expr2);
	__split_expr(fake);
	return 1;
}

void __split_expr(struct expression *expr)
{
	if (!expr)
		return;

	// sm_msg(" Debug expr_type %d %s", expr->type, show_special(expr->op));

	if (__in_fake_assign && expr->type != EXPR_ASSIGNMENT)
		return;
	if (__in_fake_assign >= 4)  /* don't allow too much nesting */
		return;

	push_expression(&big_expression_stack, expr);
	set_position(expr->pos);
	__pass_to_client(expr, EXPR_HOOK);

	switch (expr->type) {
	case EXPR_PREOP:
		expr_set_parent_expr(expr->unop, expr);

		if (expr->op == '*' &&
		    !prev_expression_is_getting_address(expr))
			__pass_to_client(expr, DEREF_HOOK);
		__split_expr(expr->unop);
		__pass_to_client(expr, OP_HOOK);
		break;
	case EXPR_POSTOP:
		expr_set_parent_expr(expr->unop, expr);

		__split_expr(expr->unop);
		push_expression(&post_op_stack, expr);
		break;
	case EXPR_STATEMENT:
		__expr_stmt_count++;
		if (expr->statement && !expr->statement) {
			stmt_set_parent_stmt(expr->statement,
					last_ptr_list((struct ptr_list *)big_statement_stack));
		}
		__split_stmt(expr->statement);
		__expr_stmt_count--;
		break;
	case EXPR_LOGICAL:
	case EXPR_COMPARE:
		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);

		__pass_to_client(expr, LOGIC_HOOK);
		__handle_logic(expr);
		break;
	case EXPR_BINOP:
		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);

		__pass_to_client(expr, BINOP_HOOK);
	case EXPR_COMMA:
		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);

		__split_expr(expr->left);
		__process_post_op_stack();
		__split_expr(expr->right);
		break;
	case EXPR_ASSIGNMENT: {
		struct expression *right;

		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);

		right = strip_expr(expr->right);
		if (!right)
			break;

		__pass_to_client(expr, RAW_ASSIGNMENT_HOOK);

		/* foo = !bar() */
		if (__handle_condition_assigns(expr))
			break;
		/* foo = (x < 5 ? foo : 5); */
		if (__handle_select_assigns(expr))
			break;
		/* foo = ({frob(); frob(); frob(); 1;}) */
		if (__handle_expr_statement_assigns(expr))
			break;
		/* foo = (3, 4); */
		if (handle_comma_assigns(expr))
			break;
		if (handle_postop_assigns(expr))
			break;
		if (handle__builtin_choose_expr_assigns(expr))
			break;

		__split_expr(expr->right);
		if (outside_of_function())
			__pass_to_client(expr, GLOBAL_ASSIGNMENT_HOOK);
		else
			__pass_to_client(expr, ASSIGNMENT_HOOK);

		__fake_struct_member_assignments(expr);

		if (expr->op == '=' && right->type == EXPR_CALL)
			__pass_to_client(expr, CALL_ASSIGNMENT_HOOK);

		if (get_macro_name(right->pos) &&
		    get_macro_name(expr->pos) != get_macro_name(right->pos))
			__pass_to_client(expr, MACRO_ASSIGNMENT_HOOK);

		__pass_to_client(expr, ASSIGNMENT_HOOK_AFTER);

		__split_expr(expr->left);
		break;
	}
	case EXPR_DEREF:
		expr_set_parent_expr(expr->deref, expr);

		__pass_to_client(expr, DEREF_HOOK);
		__split_expr(expr->deref);
		break;
	case EXPR_SLICE:
		expr_set_parent_expr(expr->base, expr);

		__split_expr(expr->base);
		break;
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
		expr_set_parent_expr(expr->cast_expression, expr);

		__pass_to_client(expr, CAST_HOOK);
		__split_expr(expr->cast_expression);
		break;
	case EXPR_SIZEOF:
		if (expr->cast_expression)
			__pass_to_client(strip_parens(expr->cast_expression),
					 SIZEOF_HOOK);
		break;
	case EXPR_OFFSETOF:
	case EXPR_ALIGNOF:
		evaluate_expression(expr);
		break;
	case EXPR_CONDITIONAL:
	case EXPR_SELECT:
		expr_set_parent_expr(expr->conditional, expr);
		expr_set_parent_expr(expr->cond_true, expr);
		expr_set_parent_expr(expr->cond_false, expr);

		if (known_condition_true(expr->conditional)) {
			__split_expr(expr->cond_true);
			break;
		}
		if (known_condition_false(expr->conditional)) {
			__split_expr(expr->cond_false);
			break;
		}
		__pass_to_client(expr, SELECT_HOOK);
		__split_whole_condition(expr->conditional);
		__split_expr(expr->cond_true);
		__push_true_states();
		__use_false_states();
		__split_expr(expr->cond_false);
		__merge_true_states();
		break;
	case EXPR_CALL:
		expr_set_parent_expr(expr->fn, expr);

		if (sym_name_is("__builtin_constant_p", expr->fn))
			break;
		if (handle__builtin_choose_expr(expr))
			break;
		split_expr_list(expr->args, expr);
		__split_expr(expr->fn);
		if (is_inline_func(expr->fn))
			add_inline_function(expr->fn->symbol);
		if (inlinable(expr->fn))
			__inline_call = 1;
		__process_post_op_stack();
		__pass_to_client(expr, FUNCTION_CALL_HOOK_BEFORE);
		__pass_to_client(expr, FUNCTION_CALL_HOOK);
		__inline_call = 0;
		if (inlinable(expr->fn)) {
			parse_inline(expr);
		}
		__pass_to_client(expr, CALL_HOOK_AFTER_INLINE);
		if (is_noreturn_func(expr->fn))
			nullify_path();
		handle_builtin_overflow_func(expr);
		break;
	case EXPR_INITIALIZER:
		split_expr_list(expr->expr_list, expr);
		break;
	case EXPR_IDENTIFIER:
		expr_set_parent_expr(expr->ident_expression, expr);
		__split_expr(expr->ident_expression);
		break;
	case EXPR_INDEX:
		expr_set_parent_expr(expr->idx_expression, expr);
		__split_expr(expr->idx_expression);
		break;
	case EXPR_POS:
		expr_set_parent_expr(expr->init_expr, expr);
		__split_expr(expr->init_expr);
		break;
	case EXPR_SYMBOL:
		__pass_to_client(expr, SYM_HOOK);
		break;
	case EXPR_STRING:
		__pass_to_client(expr, STRING_HOOK);
		break;
	default:
		break;
	};
	pop_expression(&big_expression_stack);
}

static int is_forever_loop(struct statement *stmt)
{
	struct expression *expr;
	sval_t sval;

	expr = strip_expr(stmt->iterator_pre_condition);
	if (!expr)
		expr = stmt->iterator_post_condition;
	if (!expr) {
		/* this is a for(;;) loop... */
		return 1;
	}

	if (get_value(expr, &sval) && sval.value != 0)
		return 1;

	return 0;
}

static int loop_num;
static char *get_loop_name(int num)
{
	char buf[256];

	snprintf(buf, 255, "-loop%d", num);
	buf[255] = '\0';
	return alloc_sname(buf);
}

/*
 * Pre Loops are while and for loops.
 */
static void handle_pre_loop(struct statement *stmt)
{
	int once_through; /* we go through the loop at least once */
	struct sm_state *extra_sm = NULL;
	int unchanged = 0;
	char *loop_name;
	struct stree *stree = NULL;
	struct sm_state *sm = NULL;

	loop_name = get_loop_name(loop_num);
	loop_num++;

	__split_stmt(stmt->iterator_pre_statement);
	__prev_stmt = stmt->iterator_pre_statement;

	once_through = implied_condition_true(stmt->iterator_pre_condition);

	loop_count++;
	__push_continues();
	__push_breaks();

	__merge_gotos(loop_name, NULL);

	extra_sm = __extra_handle_canonical_loops(stmt, &stree);
	__in_pre_condition++;
	__pass_to_client(stmt, PRELOOP_HOOK);
	__split_whole_condition(stmt->iterator_pre_condition);
	__in_pre_condition--;
	FOR_EACH_SM(stree, sm) {
		set_state(sm->owner, sm->name, sm->sym, sm->state);
	} END_FOR_EACH_SM(sm);
	free_stree(&stree);
	if (extra_sm)
		extra_sm = get_sm_state(extra_sm->owner, extra_sm->name, extra_sm->sym);

	if (option_assume_loops)
		once_through = 1;

	__split_stmt(stmt->iterator_statement);
	if (is_forever_loop(stmt)) {
		__merge_continues();
		__save_gotos(loop_name, NULL);

		__push_fake_cur_stree();
		__split_stmt(stmt->iterator_post_statement);
		stree = __pop_fake_cur_stree();

		__discard_false_states();
		__use_breaks();

		if (!__path_is_null())
			__merge_stree_into_cur(stree);
		free_stree(&stree);
	} else {
		__merge_continues();
		unchanged = __iterator_unchanged(extra_sm);
		__split_stmt(stmt->iterator_post_statement);
		__prev_stmt = stmt->iterator_post_statement;
		__cur_stmt = stmt;

		__save_gotos(loop_name, NULL);
		__in_pre_condition++;
		__split_whole_condition(stmt->iterator_pre_condition);
		__in_pre_condition--;
		nullify_path();
		__merge_false_states();
		if (once_through)
			__discard_false_states();
		else
			__merge_false_states();

		if (extra_sm && unchanged)
			__extra_pre_loop_hook_after(extra_sm,
						stmt->iterator_post_statement,
						stmt->iterator_pre_condition);
		__merge_breaks();
	}
	loop_count--;
}

/*
 * Post loops are do {} while();
 */
static void handle_post_loop(struct statement *stmt)
{
	char *loop_name;

	loop_name = get_loop_name(loop_num);
	loop_num++;
	loop_count++;

	__push_continues();
	__push_breaks();
	__merge_gotos(loop_name, NULL);
	__split_stmt(stmt->iterator_statement);
	__merge_continues();
	if (!is_zero(stmt->iterator_post_condition))
		__save_gotos(loop_name, NULL);

	if (is_forever_loop(stmt)) {
		__use_breaks();
	} else {
		__split_whole_condition(stmt->iterator_post_condition);
		__use_false_states();
		__merge_breaks();
	}
	loop_count--;
}

static int empty_statement(struct statement *stmt)
{
	if (!stmt)
		return 0;
	if (stmt->type == STMT_EXPRESSION && !stmt->expression)
		return 1;
	return 0;
}

static int last_stmt_on_same_line(void)
{
	struct statement *stmt;
	int i = 0;

	FOR_EACH_PTR_REVERSE(big_statement_stack, stmt) {
		if (!i++)
			continue;
		if  (stmt->pos.line == get_lineno())
			return 1;
		return 0;
	} END_FOR_EACH_PTR_REVERSE(stmt);
	return 0;
}

static void split_asm_constraints(struct expression_list *expr_list)
{
	struct expression *expr;
	int state = 0;

	FOR_EACH_PTR(expr_list, expr) {
		switch (state) {
		case 0: /* identifier */
		case 1: /* constraint */
			state++;
			continue;
		case 2: /* expression */
			state = 0;
			__split_expr(expr);
			continue;
		}
	} END_FOR_EACH_PTR(expr);
}

static int is_case_val(struct statement *stmt, sval_t sval)
{
	sval_t case_sval;

	if (stmt->type != STMT_CASE)
		return 0;
	if (!stmt->case_expression) {
		__set_default();
		return 1;
	}
	if (!get_value(stmt->case_expression, &case_sval))
		return 0;
	if (case_sval.value == sval.value)
		return 1;
	return 0;
}

static struct range_list *get_case_rl(struct expression *switch_expr,
				      struct expression *case_expr,
				      struct expression *case_to)
{
	sval_t start, end;
	struct range_list *rl = NULL;
	struct symbol *switch_type;

	switch_type = get_type(switch_expr);
	if (get_value(case_to, &end) && get_value(case_expr, &start)) {
		start = sval_cast(switch_type, start);
		end = sval_cast(switch_type, end);
		add_range(&rl, start, end);
	} else if (get_value(case_expr, &start)) {
		start = sval_cast(switch_type, start);
		add_range(&rl, start, start);
	}

	return rl;
}

static void split_known_switch(struct statement *stmt, sval_t sval)
{
	struct statement *tmp;
	struct range_list *rl;

	__split_expr(stmt->switch_expression);
	sval = sval_cast(get_type(stmt->switch_expression), sval);

	push_expression(&switch_expr_stack, stmt->switch_expression);
	__save_switch_states(top_expression(switch_expr_stack));
	nullify_path();
	__push_default();
	__push_breaks();

	stmt = stmt->switch_statement;

	__push_scope_hooks();
	FOR_EACH_PTR(stmt->stmts, tmp) {
		__smatch_lineno = tmp->pos.line;
		if (is_case_val(tmp, sval)) {
			rl = alloc_rl(sval, sval);
			__merge_switches(top_expression(switch_expr_stack), rl);
			__pass_case_to_client(top_expression(switch_expr_stack), rl);
		}
		if (__path_is_null())
			continue;
		__split_stmt(tmp);
		if (__path_is_null()) {
			__set_default();
			goto out;
		}
	} END_FOR_EACH_PTR(tmp);
out:
	__call_scope_hooks();
	if (!__pop_default())
		__merge_switches(top_expression(switch_expr_stack), NULL);
	__discard_switches();
	__merge_breaks();
	pop_expression(&switch_expr_stack);
}

static void split_case(struct statement *stmt)
{
	struct range_list *rl = NULL;

	expr_set_parent_stmt(stmt->case_expression, stmt);
	expr_set_parent_stmt(stmt->case_to, stmt);

	rl = get_case_rl(top_expression(switch_expr_stack),
			 stmt->case_expression, stmt->case_to);
	while (stmt->case_statement->type == STMT_CASE) {
		struct range_list *tmp;

		tmp = get_case_rl(top_expression(switch_expr_stack),
				  stmt->case_statement->case_expression,
				  stmt->case_statement->case_to);
		if (!tmp)
			break;
		rl = rl_union(rl, tmp);
		if (!stmt->case_expression)
			__set_default();
		stmt = stmt->case_statement;
	}

	__merge_switches(top_expression(switch_expr_stack), rl);

	if (!stmt->case_expression)
		__set_default();
	__split_stmt(stmt->case_statement);
}

int time_parsing_function(void)
{
	return ms_since(&fn_start_time) / 1000;
}

static int taking_too_long(void)
{
	if ((ms_since(&outer_fn_start_time) / 1000) > 60 * 5) /* five minutes */
		return 1;
	return 0;
}

static int is_last_stmt(struct statement *cur_stmt)
{
	struct symbol *fn;
	struct statement *stmt;

	if (!cur_func_sym)
		return 0;
	fn = get_base_type(cur_func_sym);
	if (!fn)
		return 0;
	stmt = fn->stmt;
	if (!stmt)
		stmt = fn->inline_stmt;
	if (!stmt || stmt->type != STMT_COMPOUND)
		return 0;
	stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (stmt && stmt->type == STMT_LABEL)
		stmt = stmt->label_statement;
	if (stmt == cur_stmt)
		return 1;
	return 0;
}

static void handle_backward_goto(struct statement *goto_stmt)
{
	const char *goto_name, *label_name;
	struct statement *func_stmt;
	struct symbol *base_type = get_base_type(cur_func_sym);
	struct statement *tmp;
	int found = 0;

	if (!option_info)
		return;
	if (last_goto_statement_handled)
		return;
	last_goto_statement_handled = 1;

	if (!goto_stmt->goto_label ||
	    goto_stmt->goto_label->type != SYM_LABEL ||
	    !goto_stmt->goto_label->ident)
		return;
	goto_name = goto_stmt->goto_label->ident->name;

	func_stmt = base_type->stmt;
	if (!func_stmt)
		func_stmt = base_type->inline_stmt;
	if (!func_stmt)
		return;
	if (func_stmt->type != STMT_COMPOUND)
		return;

	FOR_EACH_PTR(func_stmt->stmts, tmp) {
		if (!found) {
			if (tmp->type != STMT_LABEL)
				continue;
			if (!tmp->label_identifier ||
			    tmp->label_identifier->type != SYM_LABEL ||
			    !tmp->label_identifier->ident)
				continue;
			label_name = tmp->label_identifier->ident->name;
			if (strcmp(goto_name, label_name) != 0)
				continue;
			found = 1;
		}
		__split_stmt(tmp);
	} END_FOR_EACH_PTR(tmp);
}

static void fake_a_return(void)
{
	struct symbol *return_type;

	nullify_path();
	__unnullify_path();

	return_type = get_real_base_type(cur_func_sym);
	return_type = get_real_base_type(return_type);
	if (return_type != &void_ctype) {
		__pass_to_client(unknown_value_expression(NULL), RETURN_HOOK);
		nullify_path();
	}
}

static void fake_an_empty_default(struct position pos)
{
	static struct statement none = {};

	none.pos = pos;
	none.type = STMT_NONE;
	__merge_switches(top_expression(switch_expr_stack), NULL);
	__split_stmt(&none);
}

static void split_compound(struct statement *stmt)
{
	struct statement *prev = NULL;
	struct statement *cur = NULL;
	struct statement *next;

	__push_scope_hooks();

	FOR_EACH_PTR(stmt->stmts, next) {
		/* just set them all ahead of time */
		stmt_set_parent_stmt(next, stmt);

		if (cur) {
			__prev_stmt = prev;
			__next_stmt = next;
			__cur_stmt = cur;
			__split_stmt(cur);
		}
		prev = cur;
		cur = next;
	} END_FOR_EACH_PTR(next);
	if (cur) {
		__prev_stmt = prev;
		__cur_stmt = cur;
		__next_stmt = NULL;
		__split_stmt(cur);
	}

	/*
	 * For function scope, then delay calling the scope hooks until the
	 * end of function hooks can run.  I'm not positive this is the right
	 * thing...
	 */
	if (!is_last_stmt(cur))
		__call_scope_hooks();
}

/*
 * This is a hack, work around for detecting empty functions.
 */
static int need_delayed_scope_hooks(void)
{
	struct symbol *fn = get_base_type(cur_func_sym);
	struct statement *stmt;

	if (!fn)
		return 0;
	stmt = fn->stmt;
	if (!stmt)
		stmt = fn->inline_stmt;
	if (stmt && stmt->type == STMT_COMPOUND)
		return 1;
	return 0;
}

void __split_label_stmt(struct statement *stmt)
{
	if (stmt->label_identifier &&
	    stmt->label_identifier->type == SYM_LABEL &&
	    stmt->label_identifier->ident) {
		loop_count |= 0x0800000;
		__merge_gotos(stmt->label_identifier->ident->name, stmt->label_identifier);
	}
}

static void find_asm_gotos(struct statement *stmt)
{
	struct symbol *sym;

	FOR_EACH_PTR(stmt->asm_labels, sym) {
		__save_gotos(sym->ident->name, sym);
	} END_FOR_EACH_PTR(sym);
}

void __split_stmt(struct statement *stmt)
{
	sval_t sval;

	if (!stmt)
		goto out;

	if (!__in_fake_assign)
		__silence_warnings_for_stmt = false;

	if (__bail_on_rest_of_function || is_skipped_function())
		return;

	if (out_of_memory() || taking_too_long()) {
		struct timeval stop;

		gettimeofday(&stop, NULL);

		__bail_on_rest_of_function = 1;
		final_pass = 1;
		sm_perror("Function too hairy.  Giving up. %lu seconds",
		       stop.tv_sec - fn_start_time.tv_sec);
		fake_a_return();
		final_pass = 0;  /* turn off sm_msg() from here */
		return;
	}

	add_ptr_list(&big_statement_stack, stmt);
	free_expression_stack(&big_expression_stack);
	set_position(stmt->pos);
	__pass_to_client(stmt, STMT_HOOK);

	switch (stmt->type) {
	case STMT_DECLARATION:
		split_declaration(stmt->declaration);
		break;
	case STMT_RETURN:
		expr_set_parent_stmt(stmt->ret_value, stmt);

		__split_expr(stmt->ret_value);
		__pass_to_client(stmt->ret_value, RETURN_HOOK);
		__process_post_op_stack();
		nullify_path();
		break;
	case STMT_EXPRESSION:
		expr_set_parent_stmt(stmt->expression, stmt);
		expr_set_parent_stmt(stmt->context, stmt);

		__split_expr(stmt->expression);
		break;
	case STMT_COMPOUND:
		split_compound(stmt);
		break;
	case STMT_IF:
		stmt_set_parent_stmt(stmt->if_true, stmt);
		stmt_set_parent_stmt(stmt->if_false, stmt);
		expr_set_parent_stmt(stmt->if_conditional, stmt);

		if (known_condition_true(stmt->if_conditional)) {
			__split_stmt(stmt->if_true);
			break;
		}
		if (known_condition_false(stmt->if_conditional)) {
			__split_stmt(stmt->if_false);
			break;
		}
		__split_whole_condition(stmt->if_conditional);
		__split_stmt(stmt->if_true);
		if (empty_statement(stmt->if_true) &&
			last_stmt_on_same_line() &&
			!get_macro_name(stmt->if_true->pos))
			sm_warning("if();");
		__push_true_states();
		__use_false_states();
		__split_stmt(stmt->if_false);
		__merge_true_states();
		break;
	case STMT_ITERATOR:
		stmt_set_parent_stmt(stmt->iterator_pre_statement, stmt);
		stmt_set_parent_stmt(stmt->iterator_statement, stmt);
		stmt_set_parent_stmt(stmt->iterator_post_statement, stmt);
		expr_set_parent_stmt(stmt->iterator_pre_condition, stmt);
		expr_set_parent_stmt(stmt->iterator_post_condition, stmt);

		if (stmt->iterator_pre_condition)
			handle_pre_loop(stmt);
		else if (stmt->iterator_post_condition)
			handle_post_loop(stmt);
		else {
			// these are for(;;) type loops.
			handle_pre_loop(stmt);
		}
		break;
	case STMT_SWITCH:
		stmt_set_parent_stmt(stmt->switch_statement, stmt);
		expr_set_parent_stmt(stmt->switch_expression, stmt);

		if (get_value(stmt->switch_expression, &sval)) {
			split_known_switch(stmt, sval);
			break;
		}
		__split_expr(stmt->switch_expression);
		push_expression(&switch_expr_stack, stmt->switch_expression);
		__save_switch_states(top_expression(switch_expr_stack));
		nullify_path();
		__push_default();
		__push_breaks();
		__split_stmt(stmt->switch_statement);
		if (!__pop_default() && have_remaining_cases())
			fake_an_empty_default(stmt->pos);
		__discard_switches();
		__merge_breaks();
		pop_expression(&switch_expr_stack);
		break;
	case STMT_CASE:
		split_case(stmt);
		break;
	case STMT_LABEL:
		__split_label_stmt(stmt);
		__split_stmt(stmt->label_statement);
		break;
	case STMT_GOTO:
		expr_set_parent_stmt(stmt->goto_expression, stmt);

		__split_expr(stmt->goto_expression);
		if (stmt->goto_label && stmt->goto_label->type == SYM_NODE) {
			if (!strcmp(stmt->goto_label->ident->name, "break")) {
				__process_breaks();
			} else if (!strcmp(stmt->goto_label->ident->name,
					   "continue")) {
				__process_continues();
			}
		} else if (stmt->goto_label &&
			   stmt->goto_label->type == SYM_LABEL &&
			   stmt->goto_label->ident) {
			__save_gotos(stmt->goto_label->ident->name, stmt->goto_label);
		}
		nullify_path();
		if (is_last_stmt(stmt))
			handle_backward_goto(stmt);
		break;
	case STMT_NONE:
		break;
	case STMT_ASM:
		expr_set_parent_stmt(stmt->asm_string, stmt);

		find_asm_gotos(stmt);
		__pass_to_client(stmt, ASM_HOOK);
		__split_expr(stmt->asm_string);
		split_asm_constraints(stmt->asm_outputs);
		split_asm_constraints(stmt->asm_inputs);
		split_asm_constraints(stmt->asm_clobbers);
		break;
	case STMT_CONTEXT:
		break;
	case STMT_RANGE:
		__split_expr(stmt->range_expression);
		__split_expr(stmt->range_low);
		__split_expr(stmt->range_high);
		break;
	}
	__pass_to_client(stmt, STMT_HOOK_AFTER);
out:
	__process_post_op_stack();
}

static void split_expr_list(struct expression_list *expr_list, struct expression *parent)
{
	struct expression *expr;

	FOR_EACH_PTR(expr_list, expr) {
		expr_set_parent_expr(expr, parent);
		__split_expr(expr);
		__process_post_op_stack();
	} END_FOR_EACH_PTR(expr);
}

static void split_sym(struct symbol *sym)
{
	if (!sym)
		return;
	if (!(sym->namespace & NS_SYMBOL))
		return;

	__split_stmt(sym->stmt);
	__split_expr(sym->array_size);
	split_symlist(sym->arguments);
	split_symlist(sym->symbol_list);
	__split_stmt(sym->inline_stmt);
	split_symlist(sym->inline_symbol_list);
}

static void split_symlist(struct symbol_list *sym_list)
{
	struct symbol *sym;

	FOR_EACH_PTR(sym_list, sym) {
		split_sym(sym);
	} END_FOR_EACH_PTR(sym);
}

typedef void (fake_cb)(struct expression *expr);

static int member_to_number(struct expression *expr, struct ident *member)
{
	struct symbol *type, *tmp;
	char *name;
	int i;

	if (!member)
		return -1;
	name = member->name;

	type = get_type(expr);
	if (!type || type->type != SYM_STRUCT)
		return -1;

	i = -1;
	FOR_EACH_PTR(type->symbol_list, tmp) {
		i++;
		if (!tmp->ident)
			continue;
		if (strcmp(name, tmp->ident->name) == 0)
			return i;
	} END_FOR_EACH_PTR(tmp);
	return -1;
}

static struct ident *number_to_member(struct expression *expr, int num)
{
	struct symbol *type, *member;
	int i = 0;

	type = get_type(expr);
	if (!type || type->type != SYM_STRUCT)
		return NULL;

	FOR_EACH_PTR(type->symbol_list, member) {
		if (i == num)
			return member->ident;
		i++;
	} END_FOR_EACH_PTR(member);
	return NULL;
}

static void fake_element_assigns_helper(struct expression *array, struct expression_list *expr_list, fake_cb *fake_cb);

static void set_inner_struct_members(struct expression *expr, struct symbol *member)
{
	struct expression *edge_member, *assign;
	struct symbol *base = get_real_base_type(member);
	struct symbol *tmp;

	if (member->ident)
		expr = member_expression(expr, '.', member->ident);

	FOR_EACH_PTR(base->symbol_list, tmp) {
		struct symbol *type;

		type = get_real_base_type(tmp);
		if (!type)
			continue;

		edge_member = member_expression(expr, '.', tmp->ident);
		if (get_extra_state(edge_member))
			continue;

		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			set_inner_struct_members(expr, tmp);
			continue;
		}

		if (!tmp->ident)
			continue;

		assign = assign_expression(edge_member, '=', zero_expr());
		__split_expr(assign);
	} END_FOR_EACH_PTR(tmp);


}

static void set_unset_to_zero(struct symbol *type, struct expression *expr)
{
	struct symbol *tmp;
	struct expression *member = NULL;
	struct expression *assign;
	int op = '*';

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_expr(expr->unop);
		op = '.';
	}

	FOR_EACH_PTR(type->symbol_list, tmp) {
		type = get_real_base_type(tmp);
		if (!type)
			continue;

		if (tmp->ident) {
			member = member_expression(expr, op, tmp->ident);
			if (get_extra_state(member))
				continue;
		}

		if (type->type == SYM_UNION || type->type == SYM_STRUCT) {
			set_inner_struct_members(expr, tmp);
			continue;
		}
		if (type->type == SYM_ARRAY)
			continue;
		if (!tmp->ident)
			continue;

		assign = assign_expression(member, '=', zero_expr());
		__split_expr(assign);
	} END_FOR_EACH_PTR(tmp);
}

static void fake_member_assigns_helper(struct expression *symbol, struct expression_list *members, fake_cb *fake_cb)
{
	struct expression *deref, *assign, *tmp, *right;
	struct symbol *struct_type, *type;
	struct ident *member;
	int member_idx;

	struct_type = get_type(symbol);
	if (!struct_type ||
	    (struct_type->type != SYM_STRUCT && struct_type->type != SYM_UNION))
		return;

	/*
	 * We're parsing an initializer that could look something like this:
	 * struct foo foo = {
	 *	42,
	 *	.whatever.xxx = 11,
	 *	.zzz = 12,
	 * };
	 *
	 * So what we have here is a list with 42, .whatever, and .zzz.  We need
	 * to break it up into left and right sides of the assignments.
	 *
	 */
	member_idx = 0;
	FOR_EACH_PTR(members, tmp) {
		deref = NULL;
		if (tmp->type == EXPR_IDENTIFIER) {
			member_idx = member_to_number(symbol, tmp->expr_ident);
			while (tmp->type == EXPR_IDENTIFIER) {
				member = tmp->expr_ident;
				tmp = tmp->ident_expression;
				if (deref)
					deref = member_expression(deref, '.', member);
				else
					deref = member_expression(symbol, '.', member);
			}
		} else {
			member = number_to_member(symbol, member_idx);
			deref = member_expression(symbol, '.', member);
		}
		right = tmp;
		member_idx++;
		if (right->type == EXPR_INITIALIZER) {
			type = get_type(deref);
			if (type && type->type == SYM_ARRAY)
				fake_element_assigns_helper(deref, right->expr_list, fake_cb);
			else
				fake_member_assigns_helper(deref, right->expr_list, fake_cb);
		} else {
			assign = assign_expression(deref, '=', right);
			fake_cb(assign);
		}
	} END_FOR_EACH_PTR(tmp);

	set_unset_to_zero(struct_type, symbol);
}

static void fake_member_assigns(struct symbol *sym, fake_cb *fake_cb)
{
	fake_member_assigns_helper(symbol_expression(sym),
				   sym->initializer->expr_list, fake_cb);
}

static void fake_element_assigns_helper(struct expression *array, struct expression_list *expr_list, fake_cb *fake_cb)
{
	struct expression *offset, *binop, *assign, *tmp;
	struct symbol *type;
	int idx;

	if (ptr_list_size((struct ptr_list *)expr_list) > 1000)
		return;

	idx = 0;
	FOR_EACH_PTR(expr_list, tmp) {
		if (tmp->type == EXPR_INDEX) {
			if (tmp->idx_from != tmp->idx_to)
				return;
			idx = tmp->idx_from;
			if (!tmp->idx_expression)
				goto next;
			tmp = tmp->idx_expression;
		}
		offset = value_expr(idx);
		binop = array_element_expression(array, offset);
		if (tmp->type == EXPR_INITIALIZER) {
			type = get_type(binop);
			if (type && type->type == SYM_ARRAY)
				fake_element_assigns_helper(binop, tmp->expr_list, fake_cb);
			else
				fake_member_assigns_helper(binop, tmp->expr_list, fake_cb);
		} else {
			assign = assign_expression(binop, '=', tmp);
			fake_cb(assign);
		}
next:
		idx++;
	} END_FOR_EACH_PTR(tmp);
}

static void fake_element_assigns(struct symbol *sym, fake_cb *fake_cb)
{
	fake_element_assigns_helper(symbol_expression(sym), sym->initializer->expr_list, fake_cb);
}

static void fake_assign_expr(struct symbol *sym)
{
	struct expression *assign, *symbol;

	symbol = symbol_expression(sym);
	assign = assign_expression(symbol, '=', sym->initializer);
	__split_expr(assign);
}

static void do_initializer_stuff(struct symbol *sym)
{
	if (!sym->initializer)
		return;

	if (sym->initializer->type == EXPR_INITIALIZER) {
		if (get_real_base_type(sym)->type == SYM_ARRAY)
			fake_element_assigns(sym, __split_expr);
		else
			fake_member_assigns(sym, __split_expr);
	} else {
		fake_assign_expr(sym);
	}
}

static void split_declaration(struct symbol_list *sym_list)
{
	struct symbol *sym;

	FOR_EACH_PTR(sym_list, sym) {
		__pass_to_client(sym, DECLARATION_HOOK);
		do_initializer_stuff(sym);
		split_sym(sym);
	} END_FOR_EACH_PTR(sym);
}

static void call_global_assign_hooks(struct expression *assign)
{
	__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
}

static void fake_global_assign(struct symbol *sym)
{
	struct expression *assign, *symbol;

	if (get_real_base_type(sym)->type == SYM_ARRAY) {
		if (sym->initializer && sym->initializer->type == EXPR_INITIALIZER) {
			fake_element_assigns(sym, call_global_assign_hooks);
		} else if (sym->initializer) {
			symbol = symbol_expression(sym);
			assign = assign_expression(symbol, '=', sym->initializer);
			__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
		} else {
			fake_element_assigns_helper(symbol_expression(sym), NULL, call_global_assign_hooks);
		}
	} else if (get_real_base_type(sym)->type == SYM_STRUCT) {
		if (sym->initializer && sym->initializer->type == EXPR_INITIALIZER) {
			fake_member_assigns(sym, call_global_assign_hooks);
		} else if (sym->initializer) {
			symbol = symbol_expression(sym);
			assign = assign_expression(symbol, '=', sym->initializer);
			__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
		} else {
			fake_member_assigns_helper(symbol_expression(sym), NULL, call_global_assign_hooks);
		}
	} else {
		symbol = symbol_expression(sym);
		if (sym->initializer) {
			assign = assign_expression(symbol, '=', sym->initializer);
			__split_expr(assign);
		} else {
			assign = assign_expression(symbol, '=', zero_expr());
		}
		__pass_to_client(assign, GLOBAL_ASSIGNMENT_HOOK);
	}
}

static void start_function_definition(struct symbol *sym)
{
	__in_function_def = 1;
	__pass_to_client(sym, FUNC_DEF_HOOK);
	__in_function_def = 0;
	__pass_to_client(sym, AFTER_DEF_HOOK);

}

static void split_function(struct symbol *sym)
{
	struct symbol *base_type = get_base_type(sym);
	struct timeval stop;

	if (!base_type->stmt && !base_type->inline_stmt)
		return;

	gettimeofday(&outer_fn_start_time, NULL);
	gettimeofday(&fn_start_time, NULL);
	cur_func_sym = sym;
	if (sym->ident)
		cur_func = sym->ident->name;
	set_position(sym->pos);
	loop_count = 0;
	last_goto_statement_handled = 0;
	sm_debug("new function:  %s\n", cur_func);
	__stree_id = 0;
	if (option_two_passes) {
		__unnullify_path();
		loop_num = 0;
		final_pass = 0;
		start_function_definition(sym);
		__split_stmt(base_type->stmt);
		__split_stmt(base_type->inline_stmt);
		nullify_path();
	}
	__unnullify_path();
	loop_num = 0;
	final_pass = 1;
	start_function_definition(sym);
	__split_stmt(base_type->stmt);
	__split_stmt(base_type->inline_stmt);
	__pass_to_client(sym, END_FUNC_HOOK);
	if (need_delayed_scope_hooks())
		__call_scope_hooks();
	__pass_to_client(sym, AFTER_FUNC_HOOK);

	clear_all_states();

	gettimeofday(&stop, NULL);
	if (option_time && stop.tv_sec - fn_start_time.tv_sec > 2) {
		final_pass++;
		sm_msg("func_time: %lu", stop.tv_sec - fn_start_time.tv_sec);
		final_pass--;
	}
	cur_func_sym = NULL;
	cur_func = NULL;
	free_data_info_allocs();
	free_expression_stack(&switch_expr_stack);
	__free_ptr_list((struct ptr_list **)&big_statement_stack);
	__bail_on_rest_of_function = 0;
}

static void save_flow_state(void)
{
	__add_ptr_list(&backup, INT_PTR(loop_num << 2), 0);
	__add_ptr_list(&backup, INT_PTR(loop_count << 2), 0);
	__add_ptr_list(&backup, INT_PTR(final_pass << 2), 0);

	__add_ptr_list(&backup, big_statement_stack, 0);
	__add_ptr_list(&backup, big_expression_stack, 0);
	__add_ptr_list(&backup, big_condition_stack, 0);
	__add_ptr_list(&backup, switch_expr_stack, 0);

	__add_ptr_list(&backup, cur_func_sym, 0);

	__add_ptr_list(&backup, __prev_stmt, 0);
	__add_ptr_list(&backup, __cur_stmt, 0);
	__add_ptr_list(&backup, __next_stmt, 0);

}

static void *pop_backup(void)
{
	void *ret;

	ret = last_ptr_list(backup);
	delete_ptr_list_last(&backup);
	return ret;
}

static void restore_flow_state(void)
{
	__next_stmt = pop_backup();
	__cur_stmt = pop_backup();
	__prev_stmt = pop_backup();

	cur_func_sym = pop_backup();
	switch_expr_stack = pop_backup();
	big_condition_stack = pop_backup();
	big_expression_stack = pop_backup();
	big_statement_stack = pop_backup();
	final_pass = PTR_INT(pop_backup()) >> 2;
	loop_count = PTR_INT(pop_backup()) >> 2;
	loop_num = PTR_INT(pop_backup()) >> 2;
}

static void parse_inline(struct expression *call)
{
	struct symbol *base_type;
	char *cur_func_bak = cur_func;  /* not aligned correctly for backup */
	struct timeval time_backup = fn_start_time;
	struct expression *orig_inline = __inline_fn;
	int orig_budget;

	if (out_of_memory() || taking_too_long())
		return;

	save_flow_state();

	__pass_to_client(call, INLINE_FN_START);
	final_pass = 0;  /* don't print anything */
	__inline_fn = call;
	orig_budget = inline_budget;
	inline_budget = inline_budget - 5;

	base_type = get_base_type(call->fn->symbol);
	cur_func_sym = call->fn->symbol;
	if (call->fn->symbol->ident)
		cur_func = call->fn->symbol->ident->name;
	else
		cur_func = NULL;
	set_position(call->fn->symbol->pos);

	save_all_states();
	big_statement_stack = NULL;
	big_expression_stack = NULL;
	big_condition_stack = NULL;
	switch_expr_stack = NULL;

	sm_debug("inline function:  %s\n", cur_func);
	__unnullify_path();
	loop_num = 0;
	loop_count = 0;
	start_function_definition(call->fn->symbol);
	__split_stmt(base_type->stmt);
	__split_stmt(base_type->inline_stmt);
	__pass_to_client(call->fn->symbol, END_FUNC_HOOK);
	__pass_to_client(call->fn->symbol, AFTER_FUNC_HOOK);

	free_expression_stack(&switch_expr_stack);
	__free_ptr_list((struct ptr_list **)&big_statement_stack);
	nullify_path();
	free_goto_stack();

	restore_flow_state();
	fn_start_time = time_backup;
	cur_func = cur_func_bak;

	restore_all_states();
	set_position(call->pos);
	__inline_fn = orig_inline;
	inline_budget = orig_budget;
	__pass_to_client(call, INLINE_FN_END);
}

static struct symbol_list *inlines_called;
static void add_inline_function(struct symbol *sym)
{
	static struct symbol_list *already_added;
	struct symbol *tmp;

	FOR_EACH_PTR(already_added, tmp) {
		if (tmp == sym)
			return;
	} END_FOR_EACH_PTR(tmp);

	add_ptr_list(&already_added, sym);
	add_ptr_list(&inlines_called, sym);
}

static void process_inlines(void)
{
	struct symbol *tmp;

	FOR_EACH_PTR(inlines_called, tmp) {
		split_function(tmp);
	} END_FOR_EACH_PTR(tmp);
	free_ptr_list(&inlines_called);
}

static struct symbol *get_last_scoped_symbol(struct symbol_list *big_list, int use_static)
{
	struct symbol *sym;

	FOR_EACH_PTR_REVERSE(big_list, sym) {
		if (!sym->scope)
			continue;
		if (use_static && sym->ctype.modifiers & MOD_STATIC)
			return sym;
		if (!use_static && !(sym->ctype.modifiers & MOD_STATIC))
			return sym;
	} END_FOR_EACH_PTR_REVERSE(sym);

	return NULL;
}

static bool interesting_function(struct symbol *sym)
{
	static int prev_stream = -1;
	static bool prev_answer;
	const char *filename;
	int len;

	if (!(sym->ctype.modifiers & MOD_INLINE))
		return true;

	if (sym->pos.stream == prev_stream)
		return prev_answer;

	prev_stream = sym->pos.stream;
	prev_answer = false;

	filename = stream_name(sym->pos.stream);
	len = strlen(filename);
	if (len > 0 && filename[len - 1] == 'c')
		prev_answer = true;
	return prev_answer;
}

static void split_inlines_in_scope(struct symbol *sym)
{
	struct symbol *base;
	struct symbol_list *scope_list;
	int stream;

	scope_list = sym->scope->symbols;
	stream = sym->pos.stream;

	/* find the last static symbol in the file */
	FOR_EACH_PTR_REVERSE(scope_list, sym) {
		if (sym->pos.stream != stream)
			continue;
		if (sym->type != SYM_NODE)
			continue;
		base = get_base_type(sym);
		if (!base)
			continue;
		if (base->type != SYM_FN)
			continue;
		if (!base->inline_stmt)
			continue;
		if (!interesting_function(sym))
			continue;
		add_inline_function(sym);
	} END_FOR_EACH_PTR_REVERSE(sym);

	process_inlines();
}

static void split_inlines(struct symbol_list *sym_list)
{
	struct symbol *sym;

	sym = get_last_scoped_symbol(sym_list, 0);
	if (sym)
		split_inlines_in_scope(sym);
	sym = get_last_scoped_symbol(sym_list, 1);
	if (sym)
		split_inlines_in_scope(sym);
}

static struct stree *clone_estates_perm(struct stree *orig)
{
	struct stree *ret = NULL;
	struct sm_state *tmp;

	FOR_EACH_SM(orig, tmp) {
		set_state_stree_perm(&ret, tmp->owner, tmp->name, tmp->sym, clone_estate_perm(tmp->state));
	} END_FOR_EACH_SM(tmp);

	return ret;
}

struct position last_pos;
static void split_c_file_functions(struct symbol_list *sym_list)
{
	struct symbol *sym;

	__unnullify_path();
	FOR_EACH_PTR(sym_list, sym) {
		set_position(sym->pos);
		if (sym->type != SYM_NODE || get_base_type(sym)->type != SYM_FN) {
			__pass_to_client(sym, BASE_HOOK);
			fake_global_assign(sym);
		}
	} END_FOR_EACH_PTR(sym);
	global_states = clone_estates_perm(get_all_states_stree(SMATCH_EXTRA));
	nullify_path();

	FOR_EACH_PTR(sym_list, sym) {
		set_position(sym->pos);
		last_pos = sym->pos;
		if (!interesting_function(sym))
			continue;
		if (sym->type == SYM_NODE && get_base_type(sym)->type == SYM_FN) {
			split_function(sym);
			process_inlines();
		}
		last_pos = sym->pos;
	} END_FOR_EACH_PTR(sym);
	split_inlines(sym_list);
	__pass_to_client(sym_list, END_FILE_HOOK);
}

static int final_before_fake;
void init_fake_env(void)
{
	if (!in_fake_env)
		final_before_fake = final_pass;
	in_fake_env++;
	__push_fake_cur_stree();
	final_pass = 0;
}

void end_fake_env(void)
{
	__pop_fake_cur_stree();
	in_fake_env--;
	if (!in_fake_env)
		final_pass = final_before_fake;
}

static void open_output_files(char *base_file)
{
	char buf[256];

	snprintf(buf, sizeof(buf), "%s.smatch", base_file);
	sm_outfd = fopen(buf, "w");
	if (!sm_outfd)
		sm_fatal("Cannot open %s", buf);

	if (!option_info)
		return;

	snprintf(buf, sizeof(buf), "%s.smatch.sql", base_file);
	sql_outfd = fopen(buf, "w");
	if (!sql_outfd)
		sm_fatal("Error:  Cannot open %s", buf);

	snprintf(buf, sizeof(buf), "%s.smatch.caller_info", base_file);
	caller_info_fd = fopen(buf, "w");
	if (!caller_info_fd)
		sm_fatal("Error:  Cannot open %s", buf);
}

void smatch(int argc, char **argv)
{
	struct string_list *filelist = NULL;
	struct symbol_list *sym_list;
	struct timeval stop, start;
	char *path;
	int len;

	gettimeofday(&start, NULL);

	sparse_initialize(argc, argv, &filelist);
	set_valid_ptr_max();
	alloc_valid_ptr_rl();
	FOR_EACH_PTR_NOTAG(filelist, base_file) {
		path = getcwd(NULL, 0);
		free(full_base_file);
		if (path) {
			len = strlen(path) + 1 + strlen(base_file) + 1;
			full_base_file = malloc(len);
			snprintf(full_base_file, len, "%s/%s", path, base_file);
		} else {
			full_base_file = alloc_string(base_file);
		}
		if (option_file_output)
			open_output_files(base_file);
		sym_list = sparse_keep_tokens(base_file);
		split_c_file_functions(sym_list);
	} END_FOR_EACH_PTR_NOTAG(base_file);

	gettimeofday(&stop, NULL);

	set_position(last_pos);
	if (option_time)
		sm_msg("time: %lu", stop.tv_sec - start.tv_sec);
	if (option_mem)
		sm_msg("mem: %luKb", get_max_memory());
}
