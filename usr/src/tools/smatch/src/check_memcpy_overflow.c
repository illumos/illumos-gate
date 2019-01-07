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

#include <stdlib.h>
#include "parse.h"
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

struct limiter {
	int buf_arg;
	int limit_arg;
};
static struct limiter b0_l2 = {0, 2};
static struct limiter b1_l2 = {1, 2};

struct string_list *ignored_structs;

static int get_the_max(struct expression *expr, sval_t *sval)
{
	struct range_list *rl;

	if (get_hard_max(expr, sval))
		return 1;
	if (!option_spammy)
		return 0;
	if (get_fuzzy_max(expr, sval))
		return 1;
	if (!get_user_rl(expr, &rl))
		return 0;
	*sval = rl_max(rl);
	return 1;
}

static int bytes_to_end_of_struct(struct expression *expr)
{
	struct expression *deref;
	struct symbol *type;
	int struct_bytes;
	int offset;

	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = strip_parens(expr->unop);
	else {
		type = get_type(expr);
		if (!type || type->type != SYM_ARRAY)
			return 0;
	}
	if (expr->type != EXPR_DEREF || !expr->member)
		return 0;
	deref = expr->deref;
	if (deref->type == EXPR_PREOP && deref->op == '*')
		deref = deref->unop;
	struct_bytes = get_array_size_bytes_max(deref);
	if (struct_bytes <= 0) {
		type = get_type(expr->deref);
		struct_bytes = type_bytes(type);
	}
	offset = get_member_offset_from_deref(expr);
	if (offset <= 0)
		return 0;
	return struct_bytes - expr->member_offset;
}

static int size_of_union(struct expression *expr)
{
	struct symbol *type;

	if (expr->type != EXPR_PREOP || expr->op != '&')
		return 0;
	expr = strip_parens(expr->unop);
	if (expr->type != EXPR_DEREF || !expr->member)
		return 0;
	expr = expr->unop;
	type = get_type(expr);
	if (!type || type->type != SYM_UNION)
		return 0;
	return type_bytes(type);
}

static int is_likely_multiple(int has, int needed, struct expression *limit)
{
	sval_t mult;

	limit = strip_parens(limit);
	if (limit->type != EXPR_BINOP || limit->op != '*')
		return 0;
	if (!get_value(limit->left, &mult))
		return 0;
	if (has * mult.value == needed)
		return 1;
	if (!get_value(limit->right, &mult))
		return 0;
	if (has * mult.value == needed)
		return 1;

	return 0;
}

static int name_in_union(struct symbol *type, const char *name)
{
	struct symbol *tmp;

	if (type->type == SYM_NODE)
		type = get_real_base_type(type);
	if (!type || type->type != SYM_UNION)
		return 0;

	FOR_EACH_PTR(type->symbol_list, tmp) {
		if (tmp->ident &&
		    strcmp(name, tmp->ident->name) == 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

static int ends_on_struct_member_boundary(struct expression *expr, int needed)
{
	struct symbol *type, *tmp;
	int offset;
	int size;
	int found = 0;

	expr = strip_expr(expr);
	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_parens(expr->unop);
	} else {
		type = get_type(expr);
		if (!type || type->type != SYM_ARRAY)
			return 0;
	}
	if (expr->type != EXPR_DEREF || !expr->member)
		return 0;

	type = get_type(expr->unop);
	if (!type)
		return 0;
	if (type->type == SYM_UNION) {
		struct expression *unop = strip_expr(expr->unop);

		if (unop->type != EXPR_DEREF)
			return 0;
		type = get_type(unop->unop);
		if (!type)
			return 0;
	}
	if (type->type != SYM_STRUCT)
		return 0;

	offset = 0;
	FOR_EACH_PTR(type->symbol_list, tmp) {
		if (!found) {
			if ((tmp->ident &&
			     strcmp(expr->member->name, tmp->ident->name) == 0) ||
			    name_in_union(tmp, expr->member->name))
				found = 1;

			offset = ALIGN(offset, tmp->ctype.alignment);

			offset += type_bytes(tmp);
			size = type_bytes(tmp);
			continue;
		}

		/* if there is a hole then fail. */
		if (offset != ALIGN(offset, tmp->ctype.alignment))
			return 0;
		offset += type_bytes(tmp);
		size += type_bytes(tmp);

		if (size == needed)
			return 1;
		if (size > needed)
			return 0;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static int is_one_element_array(struct expression *expr)
{
	struct symbol *type;
	sval_t sval;

	if (expr->type == EXPR_PREOP && expr->op == '&')
		expr = expr->unop;
	if (expr->type == EXPR_BINOP) /* array elements foo[5] */
		return 0;

	type = get_type(expr);
	if (!type)
		return 0;
	if (!type || type->type != SYM_ARRAY)
		return 0;

	if (!get_implied_value(type->array_size, &sval))
		return 0;

	if (sval.value == 1)
		return 1;
	return 0;
}

static int is_ignored_struct(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type)
		return 0;
	if (type->type == SYM_PTR)
		type = get_real_base_type(type);
	if (type->type != SYM_STRUCT)
		return 0;
	if (!type->ident)
		return 0;
	if (list_has_string(ignored_structs, type->ident->name))
		return 1;
	return 0;
}

static void match_limited(const char *fn, struct expression *expr, void *_limiter)
{
	struct limiter *limiter = (struct limiter *)_limiter;
	struct expression *dest;
	struct expression *limit;
	char *dest_name = NULL;
	sval_t needed;
	int has;

	dest = get_argument_from_call_expr(expr->args, limiter->buf_arg);
	limit = get_argument_from_call_expr(expr->args, limiter->limit_arg);
	if (!get_the_max(limit, &needed))
		return;
	has = get_array_size_bytes_max(dest);
	if (!has)
		return;
	if (has >= needed.value)
		return;

	if (needed.value == bytes_to_end_of_struct(dest))
		return;

	if (needed.value <= size_of_union(dest))
		return;

	if (is_likely_multiple(has, needed.value, limit))
		return;

	if (ends_on_struct_member_boundary(dest, needed.value))
		return;

	if (is_one_element_array(dest))
		return;

	if (is_ignored_struct(dest))
		return;

	dest_name = expr_to_str(dest);
	sm_error("%s() '%s' too small (%d vs %s)", fn, dest_name, has, sval_to_str(needed));
	free_string(dest_name);
}

static void register_funcs_from_file(void)
{
	char name[256];
	struct token *token;
	const char *func;
	int size, buf;
	struct limiter *limiter;

	snprintf(name, 256, "%s.sizeof_param", option_project_str);
	name[255] = '\0';
	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			break;
		func = show_ident(token->ident);

		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			break;
		size = atoi(token->number);

		token = token->next;
		if (token_type(token) == TOKEN_SPECIAL) {
			if (token->special != '-')
				break;
			token = token->next;
			if (token_type(token) != TOKEN_NUMBER)
				break;
			token = token->next;
			continue;

		}
		if (token_type(token) != TOKEN_NUMBER)
			break;
		buf = atoi(token->number);

		limiter = malloc(sizeof(*limiter));
		limiter->limit_arg = size;
		limiter->buf_arg = buf;

		add_function_hook(func, &match_limited, limiter);

		token = token->next;
	}
	if (token_type(token) != TOKEN_STREAMEND)
		sm_perror("parsing '%s'", name);
	clear_token_alloc();
}

static void register_ignored_structs_from_file(void)
{
	char name[256];
	struct token *token;
	const char *struct_type;

	snprintf(name, 256, "%s.ignore_memcpy_struct_overflows", option_project_str);
	name[255] = '\0';
	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;

		struct_type = show_ident(token->ident);
		insert_string(&ignored_structs, alloc_string(struct_type));

		token = token->next;
	}
	clear_token_alloc();
}

void check_memcpy_overflow(int id)
{
	register_funcs_from_file();
	register_ignored_structs_from_file();
	add_function_hook("memcmp", &match_limited, &b0_l2);
	add_function_hook("memcmp", &match_limited, &b1_l2);
	if (option_project == PROJ_KERNEL) {
		add_function_hook("copy_to_user", &match_limited, &b1_l2);
		add_function_hook("_copy_to_user", &match_limited, &b1_l2);
		add_function_hook("__copy_to_user", &match_limited, &b1_l2);
		add_function_hook("copy_from_user", &match_limited, &b0_l2);
		add_function_hook("_copy_from_user", &match_limited, &b0_l2);
		add_function_hook("__copy_from_user", &match_limited, &b0_l2);
	}
}
