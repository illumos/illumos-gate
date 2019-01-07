/*
 * Copyright (C) 2017 Oracle.  All rights reserved.
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
 * One problem that I have is that it's really hard to track how pointers are
 * passed around.  For example, it would be nice to know that the probe() and
 * remove() functions get the same pci_dev pointer.  It would be good to know
 * what pointers we're passing to the open() and close() functions.  But that
 * information gets lost in a call tree full of function pointer calls.
 *
 * I think the first step is to start naming specific pointers.  So when a
 * pointer is allocated, then it gets a tag.  So calls to kmalloc() generate a
 * tag.  But we might not use that, because there might be a better name like
 * framebuffer_alloc(). The framebuffer_alloc() is interesting because there is
 * one per driver and it's passed around to all the file operations.
 *
 * Perhaps we could make a list of functions like framebuffer_alloc() which take
 * a size and say that those are the interesting alloc functions.
 *
 * Another place where we would maybe name the pointer is when they are passed
 * to the probe().  Because that's an important pointer, since there is one
 * per driver (sort of).
 *
 * My vision is that you could take a pointer and trace it back to a global.  So
 * I'm going to track that pointer_tag - 28 bytes takes you to another pointer
 * tag.  You could follow that one back and so on.  Also when we pass a pointer
 * to a function that would be recorded as sort of a link or path or something.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

#include <openssl/md5.h>

static int my_id;

static struct smatch_state *alloc_tag_state(mtag_t tag)
{
	struct smatch_state *state;
	char buf[64];

	state = __alloc_smatch_state(0);
	snprintf(buf, sizeof(buf), "%lld", tag);
	state->name = alloc_sname(buf);
	state->data = malloc(sizeof(mtag_t));
	*(mtag_t *)state->data = tag;

	return state;
}

static mtag_t str_to_tag(const char *str)
{
	unsigned char c[MD5_DIGEST_LENGTH];
	unsigned long long *tag = (unsigned long long *)&c;
	MD5_CTX mdContext;
	int len;

	len = strlen(str);
	MD5_Init(&mdContext);
	MD5_Update(&mdContext, str, len);
	MD5_Final(c, &mdContext);

	*tag &= ~MTAG_ALIAS_BIT;
	*tag &= ~MTAG_OFFSET_MASK;

	return *tag;
}

static void alloc_assign(const char *fn, struct expression *expr, void *unused)
{
	struct expression *left, *right;
	char *left_name, *right_name;
	struct symbol *left_sym;
	char buf[256];
	mtag_t tag;


	// FIXME:  This should only happen when the size is not a paramter of
	// the caller
	return;

	if (expr->type != EXPR_ASSIGNMENT || expr->op != '=')
		return;
	left = strip_expr(expr->left);
	right = strip_expr(expr->right);
	if (right->type != EXPR_CALL || right->fn->type != EXPR_SYMBOL)
		return;

	left_name = expr_to_str_sym(left, &left_sym);
	right_name = expr_to_str(right);

	snprintf(buf, sizeof(buf), "%s %s %s %s", get_filename(), get_function(),
		 left_name, right_name);
	tag = str_to_tag(buf);

	sql_insert_mtag_about(tag, left_name, right_name);

	if (left_name && left_sym)
		set_state(my_id, left_name, left_sym, alloc_tag_state(tag));

	free_string(left_name);
	free_string(right_name);
}

int get_string_mtag(struct expression *expr, mtag_t *tag)
{
	mtag_t xor;

	if (expr->type != EXPR_STRING || !expr->string)
		return 0;

	/* I was worried about collisions so I added a xor */
	xor = str_to_tag("__smatch string");
	*tag = str_to_tag(expr->string->data);
	*tag = *tag ^ xor;

	return 1;
}

int get_toplevel_mtag(struct symbol *sym, mtag_t *tag)
{
	char buf[256];

	if (!sym)
		return 0;

	if (!sym->ident ||
	    !(sym->ctype.modifiers & MOD_TOPLEVEL))
		return 0;

	snprintf(buf, sizeof(buf), "%s %s",
		 (sym->ctype.modifiers & MOD_STATIC) ? get_filename() : "extern",
		 sym->ident->name);
	*tag = str_to_tag(buf);
	return 1;
}

int get_deref_mtag(struct expression *expr, mtag_t *tag)
{
	mtag_t container_tag, member_tag;
	int offset;

	/*
	 * I'm not totally sure what I'm doing...
	 *
	 * This is supposed to get something like "global_var->ptr", but I don't
	 * feel like it's complete at all.
	 *
	 */

	if (!get_mtag(expr->unop, &container_tag))
		return 0;

	offset = get_member_offset_from_deref(expr);
	if (offset < 0)
		return 0;

	if (!mtag_map_select_tag(container_tag, -offset, &member_tag))
		return 0;

	*tag = member_tag;
	return 1;
}

static void global_variable(struct symbol *sym)
{
	mtag_t tag;

	if (!get_toplevel_mtag(sym, &tag))
		return;

	sql_insert_mtag_about(tag,
			      sym->ident->name,
			      (sym->ctype.modifiers & MOD_STATIC) ? get_filename() : "extern");
}

static void db_returns_buf_size(struct expression *expr, int param, char *unused, char *math)
{
	struct expression *call;
	struct range_list *rl;

	if (expr->type != EXPR_ASSIGNMENT)
		return;
	call = strip_expr(expr->right);

	if (!parse_call_math_rl(call, math, &rl))
		return;
//	rl = cast_rl(&int_ctype, rl);
//	set_state_expr(my_size_id, expr->left, alloc_estate_rl(rl));
}

static void db_returns_memory_tag(struct expression *expr, int param, char *key, char *value)
{
	struct expression *call, *arg;
	mtag_t tag, alias;
	char *name;
	struct symbol *sym;

	call = strip_expr(expr);
	while (call->type == EXPR_ASSIGNMENT)
		call = strip_expr(call->right);
	if (call->type != EXPR_CALL)
		return;

	tag = strtoul(value, NULL, 10);

	if (!create_mtag_alias(tag, call, &alias))
		return;

	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return;

	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	set_state(my_id, name, sym, alloc_tag_state(alias));
free:
	free_string(name);
}

static void match_call_info(struct expression *expr)
{
	struct smatch_state *state;
	struct expression *arg;
	int i = -1;

	FOR_EACH_PTR(expr->args, arg) {
		i++;
		state = get_state_expr(my_id, arg);
		if (!state || !state->data)
			continue;
		sql_insert_caller_info(expr, MEMORY_TAG, i, "$", state->name);
	} END_FOR_EACH_PTR(arg);
}

static void save_caller_info(const char *name, struct symbol *sym, char *key, char *value)
{
	struct smatch_state *state;
	char fullname[256];
	mtag_t tag;

	if (strncmp(key, "$", 1) != 0)
		return;

	tag = atoll(value);
	snprintf(fullname, 256, "%s%s", name, key + 1);
	state = alloc_tag_state(tag);
	set_state(my_id, fullname, sym, state);
}

static int get_array_mtag_offset(struct expression *expr, mtag_t *tag, int *offset)
{
	struct expression *array, *offset_expr;
	struct symbol *type;
	sval_t sval;

	if (!is_array(expr))
		return 0;

	array = get_array_base(expr);
	if (!array)
		return 0;
	type = get_type(array);
	if (!type || type->type != SYM_ARRAY)
		return 0;
	type = get_real_base_type(type);
	if (!type_bytes(type))
		return 0;

	if (!get_mtag(array, tag))
		return 0;

	offset_expr = get_array_offset(expr);
	if (!get_value(offset_expr, &sval))
		return 0;
	*offset = sval.value * type_bytes(type);

	return 1;
}

static int get_implied_mtag_offset(struct expression *expr, mtag_t *tag, int *offset)
{
	struct smatch_state *state;
	struct symbol *type;
	sval_t sval;

	type = get_type(expr);
	if (!type_is_ptr(type))
		return 0;
	state = get_extra_state(expr);
	if (!state || !estate_get_single_value(state, &sval) || sval.value == 0)
		return 0;

	*tag = sval.uvalue & ~MTAG_OFFSET_MASK;
	*offset = sval.uvalue & MTAG_OFFSET_MASK;
	return 1;
}

static int get_mtag_cnt;
int get_mtag(struct expression *expr, mtag_t *tag)
{
	struct smatch_state *state;
	int ret = 0;

	expr = strip_expr(expr);
	if (!expr)
		return 0;

	if (get_mtag_cnt > 0)
		return 0;

	get_mtag_cnt++;

	switch (expr->type) {
	case EXPR_STRING:
		if (get_string_mtag(expr, tag)) {
			ret = 1;
			goto dec_cnt;
		}
		break;
	case EXPR_SYMBOL:
		if (get_toplevel_mtag(expr->symbol, tag)) {
			ret = 1;
			goto dec_cnt;
		}
		break;
	case EXPR_DEREF:
		if (get_deref_mtag(expr, tag)) {
			ret = 1;
			goto dec_cnt;
		}
		break;
	}

	state = get_state_expr(my_id, expr);
	if (!state)
		goto dec_cnt;
	if (state->data) {
		*tag = *(mtag_t *)state->data;
		ret = 1;
		goto dec_cnt;
	}

dec_cnt:
	get_mtag_cnt--;
	return ret;
}

int get_mtag_offset(struct expression *expr, mtag_t *tag, int *offset)
{
	int val;

	if (!expr)
		return 0;
	if (expr->type == EXPR_PREOP && expr->op == '*')
		return get_mtag_offset(expr->unop, tag, offset);
	if (get_implied_mtag_offset(expr, tag, offset))
		return 1;
	if (!get_mtag(expr, tag))
		return 0;
	expr = strip_expr(expr);
	if (expr->type == EXPR_SYMBOL) {
		*offset = 0;
		return 1;
	}
	val = get_member_offset_from_deref(expr);
	if (val < 0)
		return 0;
	*offset = val;
	return 1;
}

int create_mtag_alias(mtag_t tag, struct expression *expr, mtag_t *new)
{
	char buf[256];
	int lines_from_start;
	char *str;

	/*
	 * We need the alias to be unique.  It's not totally required that it
	 * be the same from one DB build to then next, but it makes debugging
	 * a bit simpler.
	 *
	 */

	if (!cur_func_sym)
		return 0;

	lines_from_start = expr->pos.line - cur_func_sym->pos.line;
	str = expr_to_str(expr);
	snprintf(buf, sizeof(buf), "%lld %d %s", tag, lines_from_start, str);
	free_string(str);

	*new = str_to_tag(buf);
	sql_insert_mtag_alias(tag, *new);

	return 1;
}

int expr_to_mtag_offset(struct expression *expr, mtag_t *tag, int *offset)
{
	*offset = 0;

	expr = strip_expr(expr);
	if (!expr)
		return 0;

	if (is_array(expr))
		return get_array_mtag_offset(expr, tag, offset);

	if (expr->type ==  EXPR_DEREF) {
		*offset = get_member_offset_from_deref(expr);
		if (*offset < 0)
			return 0;
		return get_mtag(expr->deref, tag);
	}

	if (get_implied_mtag_offset(expr, tag, offset))
		return 1;

	return get_mtag(expr, tag);
}

int get_mtag_sval(struct expression *expr, sval_t *sval)
{
	struct symbol *type;
	mtag_t tag;
	int offset = 0;

	if (bits_in_pointer != 64)
		return 0;

	expr = strip_expr(expr);

	type = get_type(expr);
	if (!type_is_ptr(type))
		return 0;
	/*
	 * There are only three options:
	 *
	 * 1) An array address:
	 *    p = array;
	 * 2) An address like so:
	 *    p = &my_struct->member;
	 * 3) A pointer:
	 *    p = pointer;
	 *
	 */

	if (expr->type == EXPR_STRING && get_string_mtag(expr, &tag))
		goto found;

	if (type->type == SYM_ARRAY && get_toplevel_mtag(expr->symbol, &tag))
		goto found;

	if (get_implied_mtag_offset(expr, &tag, &offset))
		goto found;

	if (expr->type != EXPR_PREOP || expr->op != '&')
		return 0;
	expr = strip_expr(expr->unop);

	if (!expr_to_mtag_offset(expr, &tag, &offset))
		return 0;
	if (offset > MTAG_OFFSET_MASK)
		offset = MTAG_OFFSET_MASK;

found:
	sval->type = type;
	sval->uvalue = tag | offset;

	return 1;
}

static struct expression *remove_dereference(struct expression *expr)
{
	expr = strip_expr(expr);

	if (expr->type == EXPR_PREOP && expr->op == '*')
		return strip_expr(expr->unop);
	return preop_expression(expr, '&');
}

int get_mtag_addr_sval(struct expression *expr, sval_t *sval)
{
	return get_mtag_sval(remove_dereference(expr), sval);
}

static void print_stored_to_mtag(int return_id, char *return_ranges, struct expression *expr)
{
	struct sm_state *sm;
	char buf[256];
	const char *param_name;
	int param;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (!sm->state->data)
			continue;

		param = get_param_num_from_sym(sm->sym);
		if (param < 0)
			continue;
		param_name = get_param_name(sm);
		if (!param_name)
			continue;
		if (strcmp(param_name, "$") == 0)
			continue;

		snprintf(buf, sizeof(buf), "%lld", *(mtag_t *)sm->state->data);
		sql_insert_return_states(return_id, return_ranges, MEMORY_TAG, param, param_name, buf);
	} END_FOR_EACH_SM(sm);
}

void register_mtag(int id)
{
	my_id = id;


	/*
	 * The mtag stuff only works on 64 systems because we store the
	 * information in the pointer itself.
	 * bit 63   : set for alias mtags
	 * bit 62-12: mtag hash
	 * bit 11-0 : offset
	 *
	 */
	if (bits_in_pointer != 64)
		return;

	add_hook(&global_variable, BASE_HOOK);

	add_function_assign_hook("kmalloc", &alloc_assign, NULL);
	add_function_assign_hook("kzalloc", &alloc_assign, NULL);

	select_return_states_hook(BUF_SIZE, &db_returns_buf_size);

	add_hook(&match_call_info, FUNCTION_CALL_HOOK);
	select_caller_info_hook(save_caller_info, MEMORY_TAG);
	add_split_return_callback(&print_stored_to_mtag);
	select_return_states_hook(MEMORY_TAG, db_returns_memory_tag);
}
