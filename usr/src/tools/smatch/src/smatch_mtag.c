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

const struct {
	const char *name;
	int size_arg;
} allocator_info[] = {
	{ "kmalloc", 0 },
	{ "kzalloc", 0 },
	{ "devm_kmalloc", 1},
	{ "devm_kzalloc", 1},
};

static bool is_mtag_call(struct expression *expr)
{
	struct expression *arg;
	int i;
	sval_t sval;

	if (expr->type != EXPR_CALL ||
	    expr->fn->type != EXPR_SYMBOL ||
	    !expr->fn->symbol)
		return false;

	for (i = 0; i < ARRAY_SIZE(allocator_info); i++) {
		if (strcmp(expr->fn->symbol->ident->name, allocator_info[i].name) == 0)
			break;
	}
	if (i == ARRAY_SIZE(allocator_info))
		return false;

	arg = get_argument_from_call_expr(expr->args, allocator_info[i].size_arg);
	if (!get_implied_value(arg, &sval))
		return false;

	return true;
}

struct smatch_state *swap_mtag_return(struct expression *expr, struct smatch_state *state)
{
	struct expression *left, *right;
	char *left_name, *right_name;
	struct symbol *left_sym;
	struct range_list *rl;
	char buf[256];
	mtag_t tag;
	sval_t tag_sval;

	if (!expr || expr->type != EXPR_ASSIGNMENT || expr->op != '=')
		return state;

	if (!estate_rl(state) || strcmp(state->name, "0,4096-ptr_max") != 0)
		return state;

	left = strip_expr(expr->left);
	right = strip_expr(expr->right);

	if (!is_mtag_call(right))
		return state;

	left_name = expr_to_str_sym(left, &left_sym);
	if (!left_name || !left_sym)
		return state;
	right_name = expr_to_str(right);

	snprintf(buf, sizeof(buf), "%s %s %s %s", get_filename(), get_function(),
		 left_name, right_name);
	tag = str_to_tag(buf);
	tag_sval.type = estate_type(state);
	tag_sval.uvalue = tag;

	rl = rl_filter(estate_rl(state), valid_ptr_rl);
	rl = clone_rl(rl);
	add_range(&rl, tag_sval, tag_sval);

	sql_insert_mtag_about(tag, left_name, buf);

	free_string(left_name);
	free_string(right_name);

	return alloc_estate_rl(rl);
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

bool get_symbol_mtag(struct symbol *sym, mtag_t *tag)
{
	char buf[256];

	if (!sym || !sym->ident)
		return false;

	if (get_toplevel_mtag(sym, tag))
		return true;

	if (get_param_num_from_sym(sym) >= 0)
		return false;

	snprintf(buf, sizeof(buf), "%s %s %s",
		 get_filename(), get_function(), sym->ident->name);
	*tag = str_to_tag(buf);
	return true;
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

static int get_array_mtag_offset(struct expression *expr, mtag_t *tag, int *offset)
{
	struct expression *array, *offset_expr;
	struct symbol *type;
	sval_t sval;
	int start_offset;

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

	if (!expr_to_mtag_offset(array, tag, &start_offset))
		return 0;

	offset_expr = get_array_offset(expr);
	if (!get_value(offset_expr, &sval))
		return 0;
	*offset = start_offset + sval.value * type_bytes(type);

	return 1;
}

struct range_list *swap_mtag_seed(struct expression *expr, struct range_list *rl)
{
	char buf[256];
	char *name;
	sval_t sval;
	mtag_t tag;

	if (!rl_to_sval(rl, &sval))
		return rl;
	if (sval.type->type != SYM_PTR || sval.uvalue != MTAG_SEED)
		return rl;

	name = expr_to_str(expr);
	snprintf(buf, sizeof(buf), "%s %s %s", get_filename(), get_function(), name);
	free_string(name);
	tag = str_to_tag(buf);
	sval.value = tag;
	return alloc_rl(sval, sval);
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

/*
 * The point of this function is to give you the mtag and the offset so
 * you can look up the data in the DB.  It takes an expression.
 *
 * So say you give it "foo->bar".  Then it would give you the offset of "bar"
 * and the implied value of "foo".  Or if you lookup "*foo" then the offset is
 * zero and we look up the implied value of "foo.  But if the expression is
 * foo, then if "foo" is a global variable, then we get the mtag and the offset
 * is zero.  If "foo" is a local variable, then there is nothing to look up in
 * the mtag_data table because that's handled by smatch_extra.c to this returns
 * false.
 *
 */
int expr_to_mtag_offset(struct expression *expr, mtag_t *tag, int *offset)
{
	*tag = 0;
	*offset = 0;

	if (bits_in_pointer != 64)
		return 0;

	expr = strip_expr(expr);
	if (!expr)
		return 0;

	if (is_array(expr))
		return get_array_mtag_offset(expr, tag, offset);

	if (expr->type == EXPR_PREOP && expr->op == '*') {
		expr = strip_expr(expr->unop);
		return get_implied_mtag_offset(expr, tag, offset);
	} else if (expr->type == EXPR_DEREF) {
		int tmp, tmp_offset = 0;

		while (expr->type == EXPR_DEREF) {
			tmp = get_member_offset_from_deref(expr);
			if (tmp < 0)
				return 0;
			tmp_offset += tmp;
			expr = expr->deref;
		}
		*offset = tmp_offset;
		if (expr->type == EXPR_PREOP && expr->op == '*') {
			expr = strip_expr(expr->unop);

			if (get_implied_mtag_offset(expr, tag, &tmp_offset)) {
				// FIXME:  look it up recursively?
				if (tmp_offset)
					return 0;
				return 1;
			}
			return 0;
		} else if (expr->type == EXPR_SYMBOL) {
			return get_symbol_mtag(expr->symbol, tag);
		}
		return 0;
	} else if (expr->type == EXPR_SYMBOL) {
		return get_symbol_mtag(expr->symbol, tag);
	}
	return 0;
}

/*
 * This function takes an address and returns an sval.  Let's take some
 * example things you might pass to it:
 * foo->bar:
 *   If we were only called from smatch_math, we wouldn't need to bother with
 *   this because it's already been looked up in smatch_extra.c but this is
 *   also called from other places so we have to check smatch_extra.c.
 * &foo
 *   If "foo" is global return the mtag for "foo".
 * &foo.bar
 *   If "foo" is global return the mtag for "foo" + the offset of ".bar".
 * It also handles string literals.
 *
 */
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
	 * There are several options:
	 *
	 * If the expr is a string literal, that's an address/mtag.
	 * SYM_ARRAY and SYM_FN are mtags.  There are "&foo" type addresses.
	 * And there are saved pointers "p = &foo;"
	 *
	 */

	if (expr->type == EXPR_STRING && get_string_mtag(expr, &tag))
		goto found;

	if (expr->type == EXPR_SYMBOL &&
	    (type->type == SYM_ARRAY || type->type == SYM_FN) &&
	    get_toplevel_mtag(expr->symbol, &tag))
		goto found;

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_expr(expr->unop);
		if (expr_to_mtag_offset(expr, &tag, &offset))
			goto found;
		return 0;
	}

	if (get_implied_mtag_offset(expr, &tag, &offset))
		goto found;

	return 0;
found:
	if (offset >= MTAG_OFFSET_MASK)
		return 0;

	sval->type = type;
	sval->uvalue = tag | offset;

	return 1;
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

	add_hook(&global_variable, BASE_HOOK);
}
