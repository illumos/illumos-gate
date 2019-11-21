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

/*
 * The simplest type of condition is
 * if (a) { ...
 *
 * The next simplest kind of conditions is
 * if (a && b) { c;
 * In that case 'a' is true when we get to 'b' and both are true
 * when we get to c.
 *
 * Or's are a little more complicated.
 * if (a || b) { c;
 * We know 'a' is not true when we get to 'b' but it may be true
 * when we get to c.
 *
 * If we mix and's and or's that's even more complicated.
 * if (a && b && c || a && d) { d ;
 * 'a' is true when we evaluate 'b', and 'd'.
 * 'b' is true when we evaluate 'c' but otherwise we don't.
 *
 * The other thing that complicates matters is if we negate
 * some if conditions.
 * if (!a) { ...
 * Smatch has passes the un-negated version to the client and flip
 * the true and false values internally.  This makes it easier
 * to write checks.
 *
 * And negations can be part of a compound.
 * if (a && !(b || c)) { d;
 * In that situation we multiply the negative through to simplify
 * stuff so that we can remove the parens like this:
 * if (a && !b && !c) { d;
 *
 * One other thing is that:
 * if ((a) != 0){ ...
 * that's basically the same as testing for just 'a' and we simplify
 * comparisons with zero before passing it to the script.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"
#include "smatch_expression_stacks.h"

extern int __expr_stmt_count;

struct expression_list *big_condition_stack;

static void split_conditions(struct expression *expr);

static int is_logical_and(struct expression *expr)
{
	if (expr->op == SPECIAL_LOGICAL_AND)
		return 1;
	return 0;
}

static int handle_zero_comparisons(struct expression *expr)
{
	struct expression *tmp = NULL;
	struct expression *zero;

	// if left is zero or right is zero
	if (expr_is_zero(expr->left)) {
		zero = strip_expr(expr->left);
		if (zero->type != EXPR_VALUE)
			__split_expr(expr->left);
		tmp = expr->right;
	} else if (expr_is_zero(expr->right)) {
		zero = strip_expr(expr->left);
		if (zero->type != EXPR_VALUE)
			__split_expr(expr->right);
		tmp = expr->left;
	} else {
		return 0;
	}

	// "if (foo != 0)" is the same as "if (foo)"
	if (expr->op == SPECIAL_NOTEQUAL) {
		split_conditions(tmp);
		return 1;
	}

	// "if (foo == 0)" is the same as "if (!foo)"
	if (expr->op == SPECIAL_EQUAL) {
		split_conditions(tmp);
		__negate_cond_stacks();
		return 1;
	}

	return 0;
}

/*
 * This function is for handling calls to likely/unlikely
 */

static int ignore_builtin_expect(struct expression *expr)
{
	if (sym_name_is("__builtin_expect", expr->fn)) {
		split_conditions(first_ptr_list((struct ptr_list *) expr->args));
		return 1;
	}
	return 0;
}

/*
 * handle_compound_stmt() is for: foo = ({blah; blah; blah; 1})
 */

static void handle_compound_stmt(struct statement *stmt)
{
	struct expression *expr = NULL;
	struct statement *last;
	struct statement *s;

	last = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (last->type == STMT_LABEL) {
		if (last->label_statement &&
		    last->label_statement->type == STMT_EXPRESSION)
			expr = last->label_statement->expression;
		else
			last = NULL;
	} else if (last->type != STMT_EXPRESSION) {
		last = NULL;
	} else {
		expr = last->expression;
	}

	FOR_EACH_PTR(stmt->stmts, s) {
		if (s != last)
			__split_stmt(s);
	} END_FOR_EACH_PTR(s);
	if (last && last->type == STMT_LABEL)
		__split_label_stmt(last);
	split_conditions(expr);
}

static int handle_preop(struct expression *expr)
{
	struct statement *stmt;

	if (expr->op == '!') {
		split_conditions(expr->unop);
		__negate_cond_stacks();
		return 1;
	}
	stmt = get_expression_statement(expr);
	if (stmt) {
		handle_compound_stmt(stmt);
		return 1;
	}
	return 0;
}

static void handle_logical(struct expression *expr)
{
	/*
	 * If we come to an "and" expr then:
	 * We split the left side.
	 * We keep all the current states.
	 * We split the right side.
	 * We keep all the states from both true sides.
	 *
	 * If it's an "or" expr then:
	 * We save the current slist.
	 * We split the left side.
	 * We use the false states for the right side.
	 * We split the right side.
	 * We save all the states that are the same on both sides.
	 */

	split_conditions(expr->left);

	if (is_logical_and(expr))
		__use_cond_true_states();
	else
		__use_cond_false_states();

	__push_cond_stacks();

	__save_pre_cond_states();
	split_conditions(expr->right);
	__discard_pre_cond_states();

	if (is_logical_and(expr))
		__and_cond_states();
	else
		__or_cond_states();

	__use_cond_true_states();
}

static struct stree *combine_strees(struct stree *orig, struct stree *fake, struct stree *new)
{
	struct stree *ret = NULL;

	overwrite_stree(orig, &ret);
	overwrite_stree(fake, &ret);
	overwrite_stree(new, &ret);
	free_stree(&new);

	return ret;
}

/*
 * handle_select()
 * if ((aaa()?bbb():ccc())) { ...
 *
 * This is almost the same as:
 * if ((aaa() && bbb()) || (!aaa() && ccc())) { ...
 *
 * It's a bit complicated because we shouldn't pass aaa()
 * to the clients more than once.
 */

static void handle_select(struct expression *expr)
{
	struct stree *a_T = NULL;
	struct stree *a_F = NULL;
	struct stree *a_T_b_T = NULL;
	struct stree *a_T_b_F = NULL;
	struct stree *a_T_b_fake = NULL;
	struct stree *a_F_c_T = NULL;
	struct stree *a_F_c_F = NULL;
	struct stree *a_F_c_fake = NULL;
	struct stree *tmp;
	struct sm_state *sm;

	/*
	 * Imagine we have this:  if (a ? b : c) { ...
	 *
	 * The condition is true if "a" is true and "b" is true or
	 * "a" is false and "c" is true.  It's false if "a" is true
	 * and "b" is false or "a" is false and "c" is false.
	 *
	 * The variable name "a_T_b_T" stands for "a true b true" etc.
	 *
	 * But if we know "b" is true then we can simpilify things.
	 * The condition is true if "a" is true or if "a" is false and
	 * "c" is true.  The only way the condition can be false is if
	 * "a" is false and "c" is false.
	 *
	 * The remaining thing is the "a_T_b_fake".  When we simplify
	 * the equations we have to take into consideration that other
	 * states may have changed that don't play into the true false
	 * equation.  Take the following example:
	 * if ({
	 *         (flags) = __raw_local_irq_save();
	 *         _spin_trylock(lock) ? 1 :
	 *                 ({ raw_local_irq_restore(flags);  0; });
	 *    })
	 * Smatch has to record that the irq flags were restored on the
	 * false path.
	 *
	 */

	__save_pre_cond_states();

	split_conditions(expr->conditional);

	a_T = __copy_cond_true_states();
	a_F = __copy_cond_false_states();

	__use_cond_true_states();

	__push_cond_stacks();
	__push_fake_cur_stree();
	split_conditions(expr->cond_true);
	__process_post_op_stack();
	a_T_b_fake = __pop_fake_cur_stree();
	a_T_b_T = combine_strees(a_T, a_T_b_fake, __pop_cond_true_stack());
	a_T_b_F = combine_strees(a_T, a_T_b_fake, __pop_cond_false_stack());

	__use_cond_false_states();

	__push_cond_stacks();
	__push_fake_cur_stree();
	split_conditions(expr->cond_false);
	a_F_c_fake = __pop_fake_cur_stree();
	a_F_c_T = combine_strees(a_F, a_F_c_fake, __pop_cond_true_stack());
	a_F_c_F = combine_strees(a_F, a_F_c_fake, __pop_cond_false_stack());

	/* We have to restore the pre condition states so that
	   implied_condition_true() will use the right cur_stree */
	__use_pre_cond_states();

	if (implied_condition_true(expr->cond_true)) {
		free_stree(&a_T_b_T);
		free_stree(&a_T_b_F);
		a_T_b_T = clone_stree(a_T);
		overwrite_stree(a_T_b_fake, &a_T_b_T);
	}
	if (implied_condition_false(expr->cond_true)) {
		free_stree(&a_T_b_T);
		free_stree(&a_T_b_F);
		a_T_b_F = clone_stree(a_T);
		overwrite_stree(a_T_b_fake, &a_T_b_F);
	}
	if (implied_condition_true(expr->cond_false)) {
		free_stree(&a_F_c_T);
		free_stree(&a_F_c_F);
		a_F_c_T = clone_stree(a_F);
		overwrite_stree(a_F_c_fake, &a_F_c_T);
	}
	if (implied_condition_false(expr->cond_false)) {
		free_stree(&a_F_c_T);
		free_stree(&a_F_c_F);
		a_F_c_F = clone_stree(a_F);
		overwrite_stree(a_F_c_fake, &a_F_c_F);
	}

	merge_stree(&a_T_b_T, a_F_c_T);
	merge_stree(&a_T_b_F, a_F_c_F);

	tmp = __pop_cond_true_stack();
	free_stree(&tmp);
	tmp = __pop_cond_false_stack();
	free_stree(&tmp);

	__push_cond_stacks();
	FOR_EACH_SM(a_T_b_T, sm) {
		__set_true_false_sm(sm, NULL);
	} END_FOR_EACH_SM(sm);
	FOR_EACH_SM(a_T_b_F, sm) {
		__set_true_false_sm(NULL, sm);
	} END_FOR_EACH_SM(sm);
	__free_set_states();

	free_stree(&a_T_b_fake);
	free_stree(&a_F_c_fake);
	free_stree(&a_F_c_T);
	free_stree(&a_F_c_F);
	free_stree(&a_T_b_T);
	free_stree(&a_T_b_F);
	free_stree(&a_T);
	free_stree(&a_F);
}

static void handle_comma(struct expression *expr)
{
	__split_expr(expr->left);
	split_conditions(expr->right);
}

static int make_op_unsigned(int op)
{
	switch (op) {
	case '<':
		return SPECIAL_UNSIGNED_LT;
	case SPECIAL_LTE:
		return SPECIAL_UNSIGNED_LTE;
	case '>':
		return SPECIAL_UNSIGNED_GT;
	case SPECIAL_GTE:
		return SPECIAL_UNSIGNED_GTE;
	}
	return op;
}

static void hackup_unsigned_compares(struct expression *expr)
{
	if (expr->type != EXPR_COMPARE)
		return;

	if (type_unsigned(get_type(expr)))
		expr->op = make_op_unsigned(expr->op);
}

static void do_condition(struct expression *expr)
{
	__fold_in_set_states();
	__push_fake_cur_stree();
	__pass_to_client(expr, CONDITION_HOOK);
	__fold_in_set_states();
}

static void split_conditions(struct expression *expr)
{
	if (option_debug) {
		char *cond = expr_to_str(expr);

		sm_msg("%d in split_conditions (%s)", get_lineno(), cond);
		free_string(cond);
	}

	expr = strip_expr_set_parent(expr);
	if (!expr) {
		__fold_in_set_states();
		return;
	}

	/*
	 * On fast paths (and also I guess some people think it's cool) people
	 * sometimes use | instead of ||.  It works the same basically except
	 * that || implies a memory barrier between conditions.  The easiest way
	 * to handle it is by pretending that | also has a barrier and re-using
	 * all the normal condition code.  This potentially hides some bugs, but
	 * people who write code like this should just be careful or they
	 * deserve bugs.
	 *
	 * We could potentially treat boolean bitwise & this way but that seems
	 * too complicated to deal with.
	 */
	if (expr->type == EXPR_BINOP && expr->op == '|') {
		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);
		handle_logical(expr);
		return;
	}

	switch (expr->type) {
	case EXPR_LOGICAL:
		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);
		__pass_to_client(expr, LOGIC_HOOK);
		handle_logical(expr);
		return;
	case EXPR_COMPARE:
		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);
		hackup_unsigned_compares(expr);
		if (handle_zero_comparisons(expr))
			return;
		break;
	case EXPR_CALL:
		if (ignore_builtin_expect(expr))
			return;
		break;
	case EXPR_PREOP:
		expr_set_parent_expr(expr->unop, expr);
		if (handle_preop(expr))
			return;
		break;
	case EXPR_CONDITIONAL:
	case EXPR_SELECT:
		expr_set_parent_expr(expr->conditional, expr);
		expr_set_parent_expr(expr->cond_true, expr);
		expr_set_parent_expr(expr->cond_false, expr);
		handle_select(expr);
		return;
	case EXPR_COMMA:
		expr_set_parent_expr(expr->left, expr);
		expr_set_parent_expr(expr->right, expr);
		handle_comma(expr);
		return;
	}

	/* fixme: this should be in smatch_flow.c
	   but because of the funny stuff we do with conditions
	   it's awkward to put it there.  We would need to
	   call CONDITION_HOOK in smatch_flow as well.
	*/
	push_expression(&big_expression_stack, expr);
	push_expression(&big_condition_stack, expr);

	if (expr->type == EXPR_COMPARE) {
		if (expr->left->type != EXPR_POSTOP)
			__split_expr(expr->left);
		if (expr->right->type != EXPR_POSTOP)
			__split_expr(expr->right);
	} else if (expr->type != EXPR_POSTOP) {
		__split_expr(expr);
	}
	do_condition(expr);
	if (expr->type == EXPR_COMPARE) {
		if (expr->left->type == EXPR_POSTOP)
			__split_expr(expr->left);
		if (expr->right->type == EXPR_POSTOP)
			__split_expr(expr->right);
	} else if (expr->type == EXPR_POSTOP) {
		__split_expr(expr);
	}
	__push_fake_cur_stree();
	__process_post_op_stack();
	__fold_in_set_states();
	pop_expression(&big_condition_stack);
	pop_expression(&big_expression_stack);
}

static int inside_condition;
void __split_whole_condition(struct expression *expr)
{
	sm_debug("%d in __split_whole_condition\n", get_lineno());
	inside_condition++;
	__save_pre_cond_states();
	__push_cond_stacks();
	/* it's a hack, but it's sometimes handy to have this stuff
	   on the big_expression_stack.  */
	push_expression(&big_expression_stack, expr);
	split_conditions(expr);
	__use_cond_states();
	__pass_to_client(expr, WHOLE_CONDITION_HOOK);
	pop_expression(&big_expression_stack);
	inside_condition--;
	sm_debug("%d done __split_whole_condition\n", get_lineno());
}

void __handle_logic(struct expression *expr)
{
	sm_debug("%d in __handle_logic\n", get_lineno());
	inside_condition++;
	__save_pre_cond_states();
	__push_cond_stacks();
	/* it's a hack, but it's sometimes handy to have this stuff
	   on the big_expression_stack.  */
	push_expression(&big_expression_stack, expr);
	if (expr)
		split_conditions(expr);
	__use_cond_states();
	__pass_to_client(expr, WHOLE_CONDITION_HOOK);
	pop_expression(&big_expression_stack);
	__merge_false_states();
	inside_condition--;
	sm_debug("%d done __handle_logic\n", get_lineno());
}

int is_condition(struct expression *expr)
{

	expr = strip_expr(expr);
	if (!expr)
		return 0;

	switch (expr->type) {
	case EXPR_LOGICAL:
	case EXPR_COMPARE:
		return 1;
	case EXPR_PREOP:
		if (expr->op == '!')
			return 1;
	}
	return 0;
}

int __handle_condition_assigns(struct expression *expr)
{
	struct expression *right;
	struct stree *true_stree, *false_stree, *fake_stree;
	struct sm_state *sm;

	if (expr->op != '=')
		return 0;
	right = strip_expr(expr->right);
	if (!is_condition(expr->right))
		return 0;

	sm_debug("%d in __handle_condition_assigns\n", get_lineno());
	inside_condition++;
	__save_pre_cond_states();
	__push_cond_stacks();
	/* it's a hack, but it's sometimes handy to have this stuff
	   on the big_expression_stack.  */
	push_expression(&big_expression_stack, right);
	split_conditions(right);
	true_stree = __get_true_states();
	false_stree = __get_false_states();
	__use_cond_states();
	__push_fake_cur_stree();
	set_extra_expr_mod(expr->left, alloc_estate_sval(sval_type_val(get_type(expr->left), 1)));
	__pass_to_client(right, WHOLE_CONDITION_HOOK);

	fake_stree = __pop_fake_cur_stree();
	FOR_EACH_SM(fake_stree, sm) {
		overwrite_sm_state_stree(&true_stree, sm);
	} END_FOR_EACH_SM(sm);
	free_stree(&fake_stree);

	pop_expression(&big_expression_stack);
	inside_condition--;

	__push_true_states();

	__use_false_states();
	__push_fake_cur_stree();
	set_extra_expr_mod(expr->left, alloc_estate_sval(sval_type_val(get_type(expr->left), 0)));

	fake_stree = __pop_fake_cur_stree();
	FOR_EACH_SM(fake_stree, sm) {
		overwrite_sm_state_stree(&false_stree, sm);
	} END_FOR_EACH_SM(sm);
	free_stree(&fake_stree);

	__merge_true_states();
	merge_fake_stree(&true_stree, false_stree);
	free_stree(&false_stree);
	FOR_EACH_SM(true_stree, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	__pass_to_client(expr, ASSIGNMENT_HOOK);
	sm_debug("%d done __handle_condition_assigns\n", get_lineno());
	return 1;
}

static int is_select_assign(struct expression *expr)
{
	struct expression *right;

	if (expr->op != '=')
		return 0;
	right = strip_expr(expr->right);
	if (right->type == EXPR_CONDITIONAL)
		return 1;
	if (right->type == EXPR_SELECT)
		return 1;
	return 0;
}

int __handle_select_assigns(struct expression *expr)
{
	struct expression *right;
	struct stree *final_states = NULL;
	struct sm_state *sm;
	int is_true;
	int is_false;

	if (!is_select_assign(expr))
		return 0;
	sm_debug("%d in __handle_ternary_assigns\n", get_lineno());
	right = strip_expr(expr->right);
	__pass_to_client(right, SELECT_HOOK);

	is_true = implied_condition_true(right->conditional);
	is_false = implied_condition_false(right->conditional);

	/* hah hah.  the ultra fake out */
	__save_pre_cond_states();
	__split_whole_condition(right->conditional);

	if (!is_false) {
		struct expression *fake_expr;

		if (right->cond_true)
			fake_expr = assign_expression(expr->left, expr->op, right->cond_true);
		else
			fake_expr = assign_expression(expr->left, expr->op, right->conditional);
		__split_expr(fake_expr);
		final_states = clone_stree(__get_cur_stree());
	}

	__use_false_states();
	if (!is_true) {
		struct expression *fake_expr;

		fake_expr = assign_expression(expr->left, expr->op, right->cond_false);
		__split_expr(fake_expr);
		merge_stree(&final_states, __get_cur_stree());
	}

	__use_pre_cond_states();

	FOR_EACH_SM(final_states, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&final_states);

	sm_debug("%d done __handle_ternary_assigns\n", get_lineno());

	return 1;
}

static struct statement *split_then_return_last(struct statement *stmt)
{
	struct statement *tmp;
	struct statement *last_stmt;

	last_stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (!last_stmt)
		return NULL;

	__push_scope_hooks();
	FOR_EACH_PTR(stmt->stmts, tmp) {
		if (tmp == last_stmt) {
			if (tmp->type == STMT_LABEL) {
				__split_label_stmt(tmp);
				return tmp->label_statement;
			}
			return last_stmt;
		}
		__split_stmt(tmp);
	} END_FOR_EACH_PTR(tmp);
	return NULL;
}

int __handle_expr_statement_assigns(struct expression *expr)
{
	struct expression *right;
	struct statement *stmt;

	right = expr->right;
	if (right->type == EXPR_PREOP && right->op == '(')
		right = right->unop;
	if (right->type != EXPR_STATEMENT)
		return 0;

	__expr_stmt_count++;
	stmt = right->statement;
	if (stmt->type == STMT_COMPOUND) {
		struct statement *last_stmt;
		struct expression *fake_assign;
		struct expression fake_expr_stmt = { .smatch_flags = Fake, };

		last_stmt = split_then_return_last(stmt);
		if (!last_stmt) {
			__expr_stmt_count--;
			return 0;
		}

		fake_expr_stmt.pos = last_stmt->pos;
		fake_expr_stmt.type = EXPR_STATEMENT;
		fake_expr_stmt.op = 0;
		fake_expr_stmt.statement = last_stmt;

		fake_assign = assign_expression(expr->left, expr->op, &fake_expr_stmt);
		__split_expr(fake_assign);

		__pass_to_client(stmt, STMT_HOOK_AFTER);
		__call_scope_hooks();
	} else if (stmt->type == STMT_EXPRESSION) {
		struct expression *fake_assign;

		fake_assign = assign_expression(expr->left, expr->op, stmt->expression);
		__split_expr(fake_assign);

	} else {
		__split_stmt(stmt);
	}
	__expr_stmt_count--;
	return 1;
}

int in_condition(void)
{
	return inside_condition;
}
