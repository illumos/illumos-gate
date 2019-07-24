/*
 * Copyright (C) 2015 Oracle.
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
 * Say we have a line like:
 * foo = bar / 8;
 * Assume we don't know anything about bar.  Well, now we know that foo is less
 * than UINT_MAX / 8.  Which might be useful, but it probably is misleading
 * useless knowledge.  Up to now we have ignored those but now we have said to
 * store them.
 *
 * It also works if you have something like "foo = (int)(char)unknown_var;".
 *
 * I feel like this data doesn't have to be perfect, it just has to be better
 * than nothing and that will help eliminate some false positives.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

static void pre_merge_hook(struct sm_state *sm)
{
	struct smatch_state *abs;
	struct smatch_state *extra;
	struct range_list *rl;

	extra = get_state(SMATCH_EXTRA, sm->name, sm->sym);
	if (!extra || !estate_rl(extra))
		return;
	abs = get_state(my_id, sm->name, sm->sym);
	if (!abs || !estate_rl(abs)) {
		set_state(my_id, sm->name, sm->sym, clone_estate(extra));
		return;
	}
	rl = rl_intersection(estate_rl(abs), estate_rl(extra));
	set_state(my_id, sm->name, sm->sym, alloc_estate_rl(clone_rl(rl)));
}

static struct smatch_state *empty_state(struct sm_state *sm)
{
	return alloc_estate_empty();
}

static void reset(struct sm_state *sm, struct expression *mod_expr)
{
	set_state(my_id, sm->name, sm->sym, alloc_estate_whole(estate_type(sm->state)));
}

static int in_iterator_pre_statement(void)
{
	struct statement *stmt;

	/*
	 * we can't use __cur_stmt because that isn't set for
	 * iterator_pre_statement.  Kind of a mess.
	 *
	 */

	stmt = last_ptr_list((struct ptr_list *)big_statement_stack);

	if (!stmt || !stmt->parent)
		return 0;
	if (stmt->parent->type != STMT_ITERATOR)
		return 0;
	if (stmt->parent->iterator_pre_statement != stmt)
		return 0;
	return 1;
}

static void match_assign(struct expression *expr)
{
	struct range_list *rl;
	struct symbol *type;
	sval_t sval;

	if (expr->op != '=')
		return;
	if (is_fake_call(expr->right))
		return;
	if (in_iterator_pre_statement())
		return;

	get_real_absolute_rl(expr->right, &rl);

	type = get_type(expr->left);
	if (!type)
		return;
	if (type->type != SYM_PTR && type->type != SYM_BASETYPE &&
	    type->type != SYM_ENUM)
		return;

	rl = cast_rl(type, rl);
	if (is_whole_rl(rl) && !get_state_expr(my_id, expr->left))
		return;
	/* These are handled by smatch_extra.c */
	if (rl_to_sval(rl, &sval) && !get_state_expr(my_id, expr->left))
		return;

	set_state_expr(my_id, expr->left, alloc_estate_rl(clone_rl(rl)));
}

struct smatch_state *get_real_absolute_state(struct expression *expr)
{
	return get_state_expr(my_id, expr);
}

struct smatch_state *get_real_absolute_state_var_sym(const char *name, struct symbol *sym)
{
	return get_state(my_id, name, sym);
}

void register_real_absolute(int id)
{
	my_id = id;

	set_dynamic_states(my_id);
	add_pre_merge_hook(my_id, &pre_merge_hook);
	add_unmatched_state_hook(my_id, &empty_state);
	add_merge_hook(my_id, &merge_estates);
	add_modification_hook(my_id, &reset);

	add_hook(&match_assign, ASSIGNMENT_HOOK);
}

