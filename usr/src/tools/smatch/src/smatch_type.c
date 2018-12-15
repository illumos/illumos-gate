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
 * The idea here is that you have an expression and you
 * want to know what the type is for that.
 */

#include "smatch.h"
#include "smatch_slist.h"

struct symbol *get_real_base_type(struct symbol *sym)
{
	struct symbol *ret;

	if (!sym)
		return NULL;
	ret = get_base_type(sym);
	if (!ret)
		return NULL;
	if (ret->type == SYM_RESTRICT || ret->type == SYM_NODE)
		return get_real_base_type(ret);
	return ret;
}

int type_bytes(struct symbol *type)
{
	int bits;

	if (type && type->type == SYM_ARRAY)
		return array_bytes(type);

	bits = type_bits(type);
	if (bits < 0)
		return 0;
	return bits_to_bytes(bits);
}

int array_bytes(struct symbol *type)
{
	if (!type || type->type != SYM_ARRAY)
		return 0;
	return bits_to_bytes(type->bit_size);
}

static struct symbol *get_binop_type(struct expression *expr)
{
	struct symbol *left, *right;

	left = get_type(expr->left);
	if (!left)
		return NULL;

	if (expr->op == SPECIAL_LEFTSHIFT ||
	    expr->op == SPECIAL_RIGHTSHIFT) {
		if (type_positive_bits(left) < 31)
			return &int_ctype;
		return left;
	}
	right = get_type(expr->right);
	if (!right)
		return NULL;

	if (left->type == SYM_PTR || left->type == SYM_ARRAY)
		return left;
	if (right->type == SYM_PTR || right->type == SYM_ARRAY)
		return right;

	if (type_positive_bits(left) < 31 && type_positive_bits(right) < 31)
		return &int_ctype;

	if (type_positive_bits(left) > type_positive_bits(right))
		return left;
	return right;
}

static struct symbol *get_type_symbol(struct expression *expr)
{
	if (!expr || expr->type != EXPR_SYMBOL || !expr->symbol)
		return NULL;

	return get_real_base_type(expr->symbol);
}

static struct symbol *get_member_symbol(struct symbol_list *symbol_list, struct ident *member)
{
	struct symbol *tmp, *sub;

	FOR_EACH_PTR(symbol_list, tmp) {
		if (!tmp->ident) {
			sub = get_real_base_type(tmp);
			sub = get_member_symbol(sub->symbol_list, member);
			if (sub)
				return sub;
			continue;
		}
		if (tmp->ident == member)
			return tmp;
	} END_FOR_EACH_PTR(tmp);

	return NULL;
}

static struct symbol *get_symbol_from_deref(struct expression *expr)
{
	struct ident *member;
	struct symbol *sym;

	if (!expr || expr->type != EXPR_DEREF)
		return NULL;

	member = expr->member;
	sym = get_type(expr->deref);
	if (!sym) {
		// sm_msg("could not find struct type");
		return NULL;
	}
	if (sym->type == SYM_PTR)
		sym = get_real_base_type(sym);
	sym = get_member_symbol(sym->symbol_list, member);
	if (!sym)
		return NULL;
	return get_real_base_type(sym);
}

static struct symbol *get_return_type(struct expression *expr)
{
	struct symbol *tmp;

	tmp = get_type(expr->fn);
	if (!tmp)
		return NULL;
	/* this is to handle __builtin_constant_p() */
	if (tmp->type != SYM_FN)
		tmp = get_base_type(tmp);
	return get_real_base_type(tmp);
}

static struct symbol *get_expr_stmt_type(struct statement *stmt)
{
	if (stmt->type != STMT_COMPOUND)
		return NULL;
	stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (stmt->type == STMT_LABEL)
		stmt = stmt->label_statement;
	if (stmt->type != STMT_EXPRESSION)
		return NULL;
	return get_type(stmt->expression);
}

static struct symbol *get_select_type(struct expression *expr)
{
	struct symbol *one, *two;

	one = get_type(expr->cond_true);
	two = get_type(expr->cond_false);
	if (!one || !two)
		return NULL;
	/*
	 * This is a hack.  If the types are not equiv then we
	 * really don't know the type.  But I think guessing is
	 *  probably Ok here.
	 */
	if (type_positive_bits(one) > type_positive_bits(two))
		return one;
	return two;
}

struct symbol *get_pointer_type(struct expression *expr)
{
	struct symbol *sym;

	sym = get_type(expr);
	if (!sym)
		return NULL;
	if (sym->type == SYM_NODE) {
		sym = get_real_base_type(sym);
		if (!sym)
			return NULL;
	}
	if (sym->type != SYM_PTR && sym->type != SYM_ARRAY)
		return NULL;
	return get_real_base_type(sym);
}

static struct symbol *fake_pointer_sym(struct expression *expr)
{
	struct symbol *sym;
	struct symbol *base;

	sym = alloc_symbol(expr->pos, SYM_PTR);
	expr = expr->unop;
	base = get_type(expr);
	if (!base)
		return NULL;
	sym->ctype.base_type = base;
	return sym;
}

static struct symbol *get_type_helper(struct expression *expr)
{
	struct symbol *ret;

	expr = strip_parens(expr);
	if (!expr)
		return NULL;

	if (expr->ctype)
		return expr->ctype;

	switch (expr->type) {
	case EXPR_STRING:
		ret = &string_ctype;
		break;
	case EXPR_SYMBOL:
		ret = get_type_symbol(expr);
		break;
	case EXPR_DEREF:
		ret = get_symbol_from_deref(expr);
		break;
	case EXPR_PREOP:
	case EXPR_POSTOP:
		if (expr->op == '&')
			ret = fake_pointer_sym(expr);
		else if (expr->op == '*')
			ret = get_pointer_type(expr->unop);
		else
			ret = get_type(expr->unop);
		break;
	case EXPR_ASSIGNMENT:
		ret = get_type(expr->left);
		break;
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		ret = get_real_base_type(expr->cast_type);
		break;
	case EXPR_COMPARE:
	case EXPR_BINOP:
		ret = get_binop_type(expr);
		break;
	case EXPR_CALL:
		ret = get_return_type(expr);
		break;
	case EXPR_STATEMENT:
		ret = get_expr_stmt_type(expr->statement);
		break;
	case EXPR_CONDITIONAL:
	case EXPR_SELECT:
		ret = get_select_type(expr);
		break;
	case EXPR_SIZEOF:
		ret = &ulong_ctype;
		break;
	case EXPR_LOGICAL:
		ret = &int_ctype;
		break;
	default:
		return NULL;
	}

	if (ret && ret->type == SYM_TYPEOF)
		ret = get_type(ret->initializer);

	expr->ctype = ret;
	return ret;
}

static struct symbol *get_final_type_helper(struct expression *expr)
{
	/*
	 * I'm not totally positive I understand types...
	 *
	 * So, when you're doing pointer math, and you do a subtraction, then
	 * the sval_binop() and whatever need to know the type of the pointer
	 * so they can figure out the alignment.  But the result is going to be
	 * and ssize_t.  So get_operation_type() gives you the pointer type
	 * and get_type() gives you ssize_t.
	 *
	 * Most of the time the operation type and the final type are the same
	 * but this just handles the few places where they are different.
	 *
	 */

	expr = strip_parens(expr);
	if (!expr)
		return NULL;

	switch (expr->type) {
	case EXPR_COMPARE:
		return &int_ctype;
	case EXPR_BINOP: {
		struct symbol *left, *right;

		if (expr->op != '-')
			return NULL;

		left = get_type(expr->left);
		right = get_type(expr->right);
		if (type_is_ptr(left) || type_is_ptr(right))
			return ssize_t_ctype;
		}
	}

	return NULL;
}

struct symbol *get_type(struct expression *expr)
{
	return get_type_helper(expr);
}

struct symbol *get_final_type(struct expression *expr)
{
	struct symbol *ret;

	ret = get_final_type_helper(expr);
	if (ret)
		return ret;
	return get_type_helper(expr);
}

struct symbol *get_promoted_type(struct symbol *left, struct symbol *right)
{
	struct symbol *ret = &int_ctype;

	if (type_positive_bits(left) > type_positive_bits(ret))
		ret = left;
	if (type_positive_bits(right) > type_positive_bits(ret))
		ret = right;

	if (type_is_ptr(left))
		ret = left;
	if (type_is_ptr(right))
		ret = right;

	return ret;
}

int type_signed(struct symbol *base_type)
{
	if (!base_type)
		return 0;
	if (base_type->ctype.modifiers & MOD_SIGNED)
		return 1;
	return 0;
}

int expr_unsigned(struct expression *expr)
{
	struct symbol *sym;

	sym = get_type(expr);
	if (!sym)
		return 0;
	if (type_unsigned(sym))
		return 1;
	return 0;
}

int expr_signed(struct expression *expr)
{
	struct symbol *sym;

	sym = get_type(expr);
	if (!sym)
		return 0;
	if (type_signed(sym))
		return 1;
	return 0;
}

int returns_unsigned(struct symbol *sym)
{
	if (!sym)
		return 0;
	sym = get_base_type(sym);
	if (!sym || sym->type != SYM_FN)
		return 0;
	sym = get_base_type(sym);
	return type_unsigned(sym);
}

int is_pointer(struct expression *expr)
{
	struct symbol *sym;

	sym = get_type(expr);
	if (!sym)
		return 0;
	if (sym == &string_ctype)
		return 0;
	if (sym->type == SYM_PTR)
		return 1;
	return 0;
}

int returns_pointer(struct symbol *sym)
{
	if (!sym)
		return 0;
	sym = get_base_type(sym);
	if (!sym || sym->type != SYM_FN)
		return 0;
	sym = get_base_type(sym);
	if (sym->type == SYM_PTR)
		return 1;
	return 0;
}

sval_t sval_type_max(struct symbol *base_type)
{
	sval_t ret;

	if (!base_type || !type_bits(base_type))
		base_type = &llong_ctype;
	ret.type = base_type;

	ret.value = (~0ULL) >> (64 - type_positive_bits(base_type));
	return ret;
}

sval_t sval_type_min(struct symbol *base_type)
{
	sval_t ret;

	if (!base_type || !type_bits(base_type))
		base_type = &llong_ctype;
	ret.type = base_type;

	if (type_unsigned(base_type)) {
		ret.value = 0;
		return ret;
	}

	ret.value = (~0ULL) << type_positive_bits(base_type);

	return ret;
}

int nr_bits(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type)
		return 0;
	return type_bits(type);
}

int is_void_pointer(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (type == &void_ctype)
		return 1;
	return 0;
}

int is_char_pointer(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (type == &char_ctype)
		return 1;
	return 0;
}

int is_string(struct expression *expr)
{
	expr = strip_expr(expr);
	if (!expr || expr->type != EXPR_STRING)
		return 0;
	if (expr->string)
		return 1;
	return 0;
}

int is_static(struct expression *expr)
{
	char *name;
	struct symbol *sym;
	int ret = 0;

	name = expr_to_str_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	if (sym->ctype.modifiers & MOD_STATIC)
		ret = 1;
free:
	free_string(name);
	return ret;
}

int is_local_variable(struct expression *expr)
{
	struct symbol *sym;
	char *name;

	name = expr_to_var_sym(expr, &sym);
	free_string(name);
	if (!sym || !sym->scope || !sym->scope->token || !cur_func_sym)
		return 0;
	if (cmp_pos(sym->scope->token->pos, cur_func_sym->pos) < 0)
		return 0;
	if (is_static(expr))
		return 0;
	return 1;
}

int types_equiv(struct symbol *one, struct symbol *two)
{
	if (!one && !two)
		return 1;
	if (!one || !two)
		return 0;
	if (one->type != two->type)
		return 0;
	if (one->type == SYM_PTR)
		return types_equiv(get_real_base_type(one), get_real_base_type(two));
	if (type_positive_bits(one) != type_positive_bits(two))
		return 0;
	return 1;
}

int fn_static(void)
{
	return !!(cur_func_sym->ctype.modifiers & MOD_STATIC);
}

const char *global_static(void)
{
	if (cur_func_sym->ctype.modifiers & MOD_STATIC)
		return "static";
	else
		return "global";
}

struct symbol *cur_func_return_type(void)
{
	struct symbol *sym;

	sym = get_real_base_type(cur_func_sym);
	if (!sym || sym->type != SYM_FN)
		return NULL;
	sym = get_real_base_type(sym);
	return sym;
}

struct symbol *get_arg_type(struct expression *fn, int arg)
{
	struct symbol *fn_type;
	struct symbol *tmp;
	struct symbol *arg_type;
	int i;

	fn_type = get_type(fn);
	if (!fn_type)
		return NULL;
	if (fn_type->type == SYM_PTR)
		fn_type = get_real_base_type(fn_type);
	if (fn_type->type != SYM_FN)
		return NULL;

	i = 0;
	FOR_EACH_PTR(fn_type->arguments, tmp) {
		arg_type = get_real_base_type(tmp);
		if (i == arg) {
			return arg_type;
		}
		i++;
	} END_FOR_EACH_PTR(tmp);

	return NULL;
}

static struct symbol *get_member_from_string(struct symbol_list *symbol_list, const char *name)
{
	struct symbol *tmp, *sub;
	int chunk_len;

	if (strncmp(name, ".", 1) == 0)
		name += 1;
	if (strncmp(name, "->", 2) == 0)
		name += 2;

	FOR_EACH_PTR(symbol_list, tmp) {
		if (!tmp->ident) {
			sub = get_real_base_type(tmp);
			sub = get_member_from_string(sub->symbol_list, name);
			if (sub)
				return sub;
			continue;
		}

		if (strcmp(tmp->ident->name, name) == 0)
			return tmp;

		chunk_len = strlen(tmp->ident->name);
		if (strncmp(tmp->ident->name, name, chunk_len) == 0 &&
		    (name[chunk_len] == '.' || name[chunk_len] == '-')) {
			sub = get_real_base_type(tmp);
			return get_member_from_string(sub->symbol_list, name + chunk_len);
		}

	} END_FOR_EACH_PTR(tmp);

	return NULL;
}

struct symbol *get_member_type_from_key(struct expression *expr, const char *key)
{
	struct symbol *sym;

	if (strcmp(key, "$") == 0)
		return get_type(expr);

	if (strcmp(key, "*$") == 0) {
		sym = get_type(expr);
		if (!sym || sym->type != SYM_PTR)
			return NULL;
		return get_real_base_type(sym);
	}

	sym = get_type(expr);
	if (!sym)
		return NULL;
	if (sym->type == SYM_PTR)
		sym = get_real_base_type(sym);

	key = key + 1;
	sym = get_member_from_string(sym->symbol_list, key);
	if (!sym)
		return NULL;
	return get_real_base_type(sym);
}

struct symbol *get_arg_type_from_key(struct expression *fn, int param, struct expression *arg, const char *key)
{
	struct symbol *type;

	if (!key)
		return NULL;
	if (strcmp(key, "$") == 0)
		return get_arg_type(fn, param);
	if (strcmp(key, "*$") == 0) {
		type = get_arg_type(fn, param);
		if (!type || type->type != SYM_PTR)
			return NULL;
		return get_real_base_type(type);
	}
	return get_member_type_from_key(arg, key);
}

int is_struct(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr);
	if (type && type->type == SYM_STRUCT)
		return 1;
	return 0;
}

static struct {
	struct symbol *sym;
	const char *name;
} base_types[] = {
	{&bool_ctype, "bool"},
	{&void_ctype, "void"},
	{&type_ctype, "type"},
	{&char_ctype, "char"},
	{&schar_ctype, "schar"},
	{&uchar_ctype, "uchar"},
	{&short_ctype, "short"},
	{&sshort_ctype, "sshort"},
	{&ushort_ctype, "ushort"},
	{&int_ctype, "int"},
	{&sint_ctype, "sint"},
	{&uint_ctype, "uint"},
	{&long_ctype, "long"},
	{&slong_ctype, "slong"},
	{&ulong_ctype, "ulong"},
	{&llong_ctype, "llong"},
	{&sllong_ctype, "sllong"},
	{&ullong_ctype, "ullong"},
	{&lllong_ctype, "lllong"},
	{&slllong_ctype, "slllong"},
	{&ulllong_ctype, "ulllong"},
	{&float_ctype, "float"},
	{&double_ctype, "double"},
	{&ldouble_ctype, "ldouble"},
	{&string_ctype, "string"},
	{&ptr_ctype, "ptr"},
	{&lazy_ptr_ctype, "lazy_ptr"},
	{&incomplete_ctype, "incomplete"},
	{&label_ctype, "label"},
	{&bad_ctype, "bad"},
	{&null_ctype, "null"},
};

static const char *base_type_str(struct symbol *sym)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(base_types); i++) {
		if (sym == base_types[i].sym)
			return base_types[i].name;
	}
	return "<unknown>";
}

static int type_str_helper(char *buf, int size, struct symbol *type)
{
	int n;

	if (!type)
		return snprintf(buf, size, "<unknown>");

	if (type->type == SYM_BASETYPE) {
		return snprintf(buf, size, base_type_str(type));
	} else if (type->type == SYM_PTR) {
		type = get_real_base_type(type);
		n = type_str_helper(buf, size, type);
		if (n > size)
			return n;
		return n + snprintf(buf + n, size - n, "*");
	} else if (type->type == SYM_ARRAY) {
		type = get_real_base_type(type);
		n = type_str_helper(buf, size, type);
		if (n > size)
			return n;
		return n + snprintf(buf + n, size - n, "[]");
	} else if (type->type == SYM_STRUCT) {
		return snprintf(buf, size, "struct %s", type->ident ? type->ident->name : "");
	} else if (type->type == SYM_UNION) {
		if (type->ident)
			return snprintf(buf, size, "union %s", type->ident->name);
		else
			return snprintf(buf, size, "anonymous union");
	} else if (type->type == SYM_FN) {
		struct symbol *arg, *return_type, *arg_type;
		int i;

		return_type = get_real_base_type(type);
		n = type_str_helper(buf, size, return_type);
		if (n > size)
			return n;
		n += snprintf(buf + n, size - n, "(*)(");
		if (n > size)
			return n;

		i = 0;
		FOR_EACH_PTR(type->arguments, arg) {
			if (i++)
				n += snprintf(buf + n, size - n, ", ");
			if (n > size)
				return n;
			arg_type = get_real_base_type(arg);
			n += type_str_helper(buf + n, size - n, arg_type);
			if (n > size)
				return n;
		} END_FOR_EACH_PTR(arg);

		return n + snprintf(buf + n, size - n, ")");
	} else if (type->type == SYM_NODE) {
		n = snprintf(buf, size, "node {");
		if (n > size)
			return n;
		type = get_real_base_type(type);
		n += type_str_helper(buf + n, size - n, type);
		if (n > size)
			return n;
		return n + snprintf(buf + n, size - n, "}");
	} else {
		return snprintf(buf, size, "<type %d>", type->type);
	}
}

char *type_to_str(struct symbol *type)
{
	static char buf[256];

	buf[0] = '\0';
	type_str_helper(buf, sizeof(buf), type);
	return buf;
}
