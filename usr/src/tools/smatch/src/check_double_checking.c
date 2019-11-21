/*
 * Copyright (C) 2014 Oracle.
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

#define _GNU_SOURCE
#include <string.h>
#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

STATE(checked);
STATE(modified);

struct stree *to_check;

static struct statement *get_cur_stmt(void)
{
	return last_ptr_list((struct ptr_list *)big_statement_stack);
}

static void set_modified(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, &modified);
}

static struct expression *strip_condition(struct expression *expr)
{
	expr = strip_expr(expr);

	if (expr->type == EXPR_PREOP && expr->op == '!')
		return strip_condition(expr->unop);

	if (expr->type == EXPR_COMPARE &&
	    (expr->op == SPECIAL_EQUAL ||
	     expr->op == SPECIAL_NOTEQUAL)) {
		if (expr_is_zero(expr->left))
			return strip_condition(expr->right);
		if (expr_is_zero(expr->right))
			return strip_condition(expr->left);
	}

	return expr;
}

static int conditions_match(struct expression *cond, struct expression *prev)
{
	prev = strip_condition(prev);

	if (prev == cond)
		return 1;

	if (prev->type == EXPR_LOGICAL) {
		if (conditions_match(cond, prev->left) ||
		    conditions_match(cond, prev->right))
			return 1;
	}

	return 0;
}

/*
 * People like to do "if (foo) { ... } else if (!foo) { ... }".  Don't
 * complain when they do that even though it is nonsense.
 */
static int is_obvious_else(struct expression *cond)
{
	struct statement *parent;
	struct expression *prev;

	if (!get_cur_stmt())
		return 0;
	parent = get_cur_stmt()->parent;
	if (!parent)
		return 0;

	if (parent->type != STMT_IF)
		return 0;

	if (!parent->if_false)
		return 0;
	if (parent->if_false != get_cur_stmt())
		return 0;

	prev = strip_condition(parent->if_conditional);

	return conditions_match(cond, prev);
}

static int name_means_synchronize(const char *name)
{
	if (!name)
		return 0;

	if (strcasestr(name, "wait"))
		return 1;
	if (strcasestr(name, "down"))
		return 1;
	if (strcasestr(name, "lock") && !strcasestr(name, "unlock"))
		return 1;
	if (strcasestr(name, "delay"))
		return 1;
	if (strcasestr(name, "schedule"))
		return 1;
	if (strcmp(name, "smp_rmb") == 0)
		return 1;
	if (strcmp(name, "mb") == 0)
		return 1;
	if (strcmp(name, "barrier") == 0)
		return 1;
	return 0;
}

static int previous_statement_was_synchronize(void)
{
	struct statement *stmt;
	struct position pos;
	struct position prev_pos;
	char *ident;

	if (!__cur_stmt)
		return 0;

	if (__prev_stmt) {
		prev_pos = __prev_stmt->pos;
		prev_pos.line -= 3;
	} else {
		prev_pos = __cur_stmt->pos;
		prev_pos.line -= 5;
	}

	FOR_EACH_PTR_REVERSE(big_statement_stack, stmt) {
		if (stmt->pos.line < prev_pos.line)
			return 0;
		pos = stmt->pos;
		ident = get_macro_name(pos);
		if (name_means_synchronize(ident))
			return 1;
		ident = pos_ident(pos);
		if (!ident)
			continue;
		if (strcmp(ident, "if") == 0) {
			pos.pos += 4;
			ident = pos_ident(pos);
			if (!ident)
				continue;
		}
		if (name_means_synchronize(ident))
			return 1;
	} END_FOR_EACH_PTR_REVERSE(stmt);
	return 0;
}

static void match_condition(struct expression *expr)
{
	struct smatch_state *state;
	sval_t dummy;
	char *name;

	if (inside_loop())
		return;

	if (get_value(expr, &dummy))
		return;

	if (get_macro_name(expr->pos))
		return;

	state = get_stored_condition(expr);
	if (!state || !state->data)
		return;
	if (get_macro_name(((struct expression *)state->data)->pos))
		return;

	/*
	 * we allow double checking for NULL because people do this all the time
	 * and trying to stop them is a losers' battle.
	 */
	if (is_pointer(expr) && implied_condition_true(expr))
		return;

	if (definitely_inside_loop()) {
		struct symbol *sym;

		if (__inline_fn)
			return;

		name = expr_to_var_sym(expr, &sym);
		if (!name)
			return;
		set_state_expr(my_id, expr, &checked);
		set_state_stree(&to_check, my_id, name, sym, &checked);
		free_string(name);
		return;
	}

	if (is_obvious_else(state->data))
		return;

	/*
	 * It's common to test something, then take a lock and test if it is
	 * still true.
	 */
	if (previous_statement_was_synchronize())
		return;

	name = expr_to_str(expr);
	sm_warning("we tested '%s' before and it was '%s'", name, state->name);
	free_string(name);
}

int get_check_line(struct sm_state *sm)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->state == &checked)
			return tmp->line;
	} END_FOR_EACH_PTR(tmp);

	return get_lineno();
}

static void after_loop(struct statement *stmt)
{
	struct sm_state *check, *sm;

	if (!stmt || stmt->type != STMT_ITERATOR)
		return;
	if (definitely_inside_loop())
		return;
	if (__inline_fn)
		return;

	FOR_EACH_SM(to_check, check) {
		continue;
		sm = get_sm_state(my_id, check->name, check->sym);
		continue;
		if (!sm)
			continue;
		if (slist_has_state(sm->possible, &modified))
			continue;

		sm_printf("%s:%d %s() ", get_filename(), get_check_line(sm), get_function());
		sm_printf("warn: we tested '%s' already\n", check->name);
	} END_FOR_EACH_SM(check);

	free_stree(&to_check);
}

static void match_func_end(struct symbol *sym)
{
	if (__inline_fn)
		return;
	if (to_check)
		sm_msg("debug: odd...  found an function without an end.");
	free_stree(&to_check);
}

void check_double_checking(int id)
{
	my_id = id;

	if (!option_spammy)
		return;

	add_hook(&match_condition, CONDITION_HOOK);
	add_modification_hook(my_id, &set_modified);
	add_hook(after_loop, STMT_HOOK_AFTER);
	add_hook(&match_func_end, AFTER_FUNC_HOOK);
}
