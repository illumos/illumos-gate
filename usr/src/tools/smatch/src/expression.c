/*
 * sparse/expression.c
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003-2004 Linus Torvalds
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * This is the expression parsing part of parsing C.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "scope.h"
#include "expression.h"
#include "target.h"
#include "char.h"

static int match_oplist(int op, ...)
{
	va_list args;
	int nextop;

	va_start(args, op);
	do {
		nextop = va_arg(args, int);
	} while (nextop != 0 && nextop != op);
	va_end(args);

	return nextop != 0;
}

static struct token *comma_expression(struct token *, struct expression **);

struct token *parens_expression(struct token *token, struct expression **expr, const char *where)
{
	struct token *p;

	token = expect(token, '(', where);
	p = token;
	if (match_op(token, '{')) {
		struct expression *e = alloc_expression(token->pos, EXPR_STATEMENT);
		struct statement *stmt = alloc_statement(token->pos, STMT_COMPOUND);
		*expr = e;
		e->statement = stmt;
		start_symbol_scope(e->pos);
		token = compound_statement(token->next, stmt);
		end_symbol_scope();
		token = expect(token, '}', "at end of statement expression");
	} else
		token = parse_expression(token, expr);

	if (token == p)
		sparse_error(token->pos, "an expression is expected before ')'");
	return expect(token, ')', where);
}

/*
 * Handle __func__, __FUNCTION__ and __PRETTY_FUNCTION__ token
 * conversion
 */
static struct symbol *handle_func(struct token *token)
{
	struct ident *ident = token->ident;
	struct symbol *decl, *array;
	struct string *string;
	int len;

	if (ident != &__func___ident &&
	    ident != &__FUNCTION___ident &&
	    ident != &__PRETTY_FUNCTION___ident)
		return NULL;

	if (!current_fn || !current_fn->ident)
		return NULL;

	/* OK, it's one of ours */
	array = alloc_symbol(token->pos, SYM_ARRAY);
	array->ctype.base_type = &char_ctype;
	array->ctype.alignment = 1;
	array->endpos = token->pos;
	decl = alloc_symbol(token->pos, SYM_NODE);
	decl->ctype.base_type = array;
	decl->ctype.alignment = 1;
	decl->ctype.modifiers = MOD_STATIC;
	decl->endpos = token->pos;

	/* function-scope, but in NS_SYMBOL */
	bind_symbol(decl, ident, NS_LABEL);
	decl->namespace = NS_SYMBOL;

	len = current_fn->ident->len;
	string = __alloc_string(len + 1);
	memcpy(string->data, current_fn->ident->name, len);
	string->data[len] = 0;
	string->length = len + 1;

	decl->initializer = alloc_expression(token->pos, EXPR_STRING);
	decl->initializer->string = string;
	decl->initializer->ctype = decl;
	decl->array_size = alloc_const_expression(token->pos, len + 1);
	array->array_size = decl->array_size;
	decl->bit_size = array->bit_size = bytes_to_bits(len + 1);

	return decl;
}

static struct token *parse_type(struct token *token, struct expression **tree)
{
	struct symbol *sym;
	*tree = alloc_expression(token->pos, EXPR_TYPE);
	token = typename(token, &sym, NULL);
	if (sym->ident)
		sparse_error(token->pos,
			     "type expression should not include identifier "
			     "\"%s\"", sym->ident->name);
	(*tree)->symbol = sym;
	return token;
}

static struct token *builtin_types_compatible_p_expr(struct token *token,
						     struct expression **tree)
{
	struct expression *expr = alloc_expression(
		token->pos, EXPR_COMPARE);
	expr->op = SPECIAL_EQUAL;
	token = token->next;
	if (!match_op(token, '('))
		return expect(token, '(',
			      "after __builtin_types_compatible_p");
	token = token->next;
	token = parse_type(token, &expr->left);
	if (!match_op(token, ','))
		return expect(token, ',',
			      "in __builtin_types_compatible_p");
	token = token->next;
	token = parse_type(token, &expr->right);
	if (!match_op(token, ')'))
		return expect(token, ')',
			      "at end of __builtin_types_compatible_p");
	token = token->next;
	
	*tree = expr;
	return token;
}

static struct token *builtin_offsetof_expr(struct token *token,
					   struct expression **tree)
{
	struct expression *expr = NULL;
	struct expression **p = &expr;
	struct symbol *sym;
	int op = '.';

	token = token->next;
	if (!match_op(token, '('))
		return expect(token, '(', "after __builtin_offset");

	token = token->next;
	token = typename(token, &sym, NULL);
	if (sym->ident)
		sparse_error(token->pos,
			     "type expression should not include identifier "
			     "\"%s\"", sym->ident->name);

	if (!match_op(token, ','))
		return expect(token, ',', "in __builtin_offset");

	while (1) {
		struct expression *e;
		switch (op) {
		case ')':
			expr->in = sym;
			*tree = expr;
		default:
			return expect(token, ')', "at end of __builtin_offset");
		case SPECIAL_DEREFERENCE:
			e = alloc_expression(token->pos, EXPR_OFFSETOF);
			e->op = '[';
			*p = e;
			p = &e->down;
			/* fall through */
		case '.':
			token = token->next;
			e = alloc_expression(token->pos, EXPR_OFFSETOF);
			e->op = '.';
			if (token_type(token) != TOKEN_IDENT) {
				sparse_error(token->pos, "Expected member name");
				return token;
			}
			e->ident = token->ident;
			token = token->next;
			break;
		case '[':
			token = token->next;
			e = alloc_expression(token->pos, EXPR_OFFSETOF);
			e->op = '[';
			token = parse_expression(token, &e->index);
			token = expect(token, ']',
					"at end of array dereference");
			if (!e->index)
				return token;
		}
		*p = e;
		p = &e->down;
		op = token_type(token) == TOKEN_SPECIAL ? token->special : 0;
	}
}

#ifndef ULLONG_MAX
#define ULLONG_MAX (~0ULL)
#endif

static unsigned long long parse_num(const char *nptr, char **end)
{
	if (nptr[0] == '0' && tolower((unsigned char)nptr[1]) == 'b')
		return strtoull(&nptr[2], end, 2);
	return strtoull(nptr, end, 0);
}

static void get_number_value(struct expression *expr, struct token *token)
{
	const char *str = token->number;
	unsigned long long value;
	char *end;
	int size = 0, want_unsigned = 0;
	int overflow = 0, do_warn = 0;
	int try_unsigned = 1;
	int bits;

	errno = 0;
	value = parse_num(str, &end);
	if (end == str)
		goto Float;
	if (value == ULLONG_MAX && errno == ERANGE)
		overflow = 1;
	while (1) {
		char c = *end++;
		if (!c) {
			break;
		} else if (c == 'u' || c == 'U') {
			if (want_unsigned)
				goto Enoint;
			want_unsigned = 1;
		} else if (c == 'l' || c == 'L') {
			if (size)
				goto Enoint;
			size = 1;
			if (*end == c) {
				size = 2;
				end++;
			}
		} else
			goto Float;
	}
	if (overflow)
		goto Eoverflow;
	/* OK, it's a valid integer */
	/* decimals can be unsigned only if directly specified as such */
	if (str[0] != '0' && !want_unsigned)
		try_unsigned = 0;
	if (!size) {
		bits = bits_in_int - 1;
		if (!(value & (~1ULL << bits))) {
			if (!(value & (1ULL << bits))) {
				goto got_it;
			} else if (try_unsigned) {
				want_unsigned = 1;
				goto got_it;
			}
		}
		size = 1;
		do_warn = 1;
	}
	if (size < 2) {
		bits = bits_in_long - 1;
		if (!(value & (~1ULL << bits))) {
			if (!(value & (1ULL << bits))) {
				goto got_it;
			} else if (try_unsigned) {
				want_unsigned = 1;
				goto got_it;
			}
			do_warn |= 2;
		}
		size = 2;
		do_warn |= 1;
	}
	bits = bits_in_longlong - 1;
	if (value & (~1ULL << bits))
		goto Eoverflow;
	if (!(value & (1ULL << bits)))
		goto got_it;
	if (!try_unsigned)
		warning(expr->pos, "decimal constant %s is too big for long long",
			show_token(token));
	want_unsigned = 1;
got_it:
	if (do_warn && Wconstant_suffix)
		warning(expr->pos, "constant %s is so big it is%s%s%s",
			show_token(token),
			want_unsigned ? " unsigned":"",
			size > 0 ? " long":"",
			size > 1 ? " long":"");
	if (do_warn & 2)
		warning(expr->pos,
			"decimal constant %s is between LONG_MAX and ULONG_MAX."
			" For C99 that means long long, C90 compilers are very "
			"likely to produce unsigned long (and a warning) here",
			show_token(token));
        expr->type = EXPR_VALUE;
	expr->flags = CEF_SET_INT;
        expr->ctype = ctype_integer(size, want_unsigned);
        expr->value = value;
	return;
Eoverflow:
	error_die(expr->pos, "constant %s is too big even for unsigned long long",
			show_token(token));
	return;
Float:
	expr->fvalue = string_to_ld(str, &end);
	if (str == end)
		goto Enoint;

	if (*end && end[1])
		goto Enoint;

	if (*end == 'f' || *end == 'F')
		expr->ctype = &float_ctype;
	else if (*end == 'l' || *end == 'L')
		expr->ctype = &ldouble_ctype;
	else if (!*end)
		expr->ctype = &double_ctype;
	else
		goto Enoint;

	expr->flags = CEF_SET_FLOAT;
	expr->type = EXPR_FVALUE;
	return;

Enoint:
	error_die(expr->pos, "constant %s is not a valid number", show_token(token));
}

struct token *primary_expression(struct token *token, struct expression **tree)
{
	struct expression *expr = NULL;

	switch (token_type(token)) {
	case TOKEN_CHAR ... TOKEN_WIDE_CHAR_EMBEDDED_3:
		expr = alloc_expression(token->pos, EXPR_VALUE);
		expr->flags = CEF_SET_CHAR;
		expr->ctype = token_type(token) < TOKEN_WIDE_CHAR ? &int_ctype : &long_ctype;
		get_char_constant(token, &expr->value);
		token = token->next;
		break;

	case TOKEN_NUMBER:
		expr = alloc_expression(token->pos, EXPR_VALUE);
		get_number_value(expr, token); /* will see if it's an integer */
		token = token->next;
		break;

	case TOKEN_ZERO_IDENT: {
		expr = alloc_expression(token->pos, EXPR_SYMBOL);
		expr->flags = CEF_SET_INT;
		expr->ctype = &int_ctype;
		expr->symbol = &zero_int;
		expr->symbol_name = token->ident;
		token = token->next;
		break;
	}

	case TOKEN_IDENT: {
		struct symbol *sym = lookup_symbol(token->ident, NS_SYMBOL | NS_TYPEDEF);
		struct token *next = token->next;

		if (!sym) {
			sym = handle_func(token);
			if (token->ident == &__builtin_types_compatible_p_ident) {
				token = builtin_types_compatible_p_expr(token, &expr);
				break;
			}
			if (token->ident == &__builtin_offsetof_ident) {
				token = builtin_offsetof_expr(token, &expr);
				break;
			}
		} else if (sym->enum_member) {
			expr = alloc_expression(token->pos, EXPR_VALUE);
			*expr = *sym->initializer;
			/* we want the right position reported, thus the copy */
			expr->pos = token->pos;
			expr->flags = CEF_SET_ENUM;
			token = next;
			break;
		}

		expr = alloc_expression(token->pos, EXPR_SYMBOL);

		/*
		 * We support types as real first-class citizens, with type
		 * comparisons etc:
		 *
		 *	if (typeof(a) == int) ..
		 */
		if (sym && sym->namespace == NS_TYPEDEF) {
			sparse_error(token->pos, "typename in expression");
			sym = NULL;
		}
		expr->symbol_name = token->ident;
		expr->symbol = sym;

		/*
		 * A pointer to an lvalue designating a static storage
		 * duration object is an address constant [6.6(9)].
		 */
		if (sym && (sym->ctype.modifiers & (MOD_TOPLEVEL | MOD_STATIC)))
			expr->flags = CEF_ADDR;

		token = next;
		break;
	}

	case TOKEN_STRING:
	case TOKEN_WIDE_STRING:
		expr = alloc_expression(token->pos, EXPR_STRING);
		token = get_string_constant(token, expr);
		break;

	case TOKEN_SPECIAL:
		if (token->special == '(') {
			expr = alloc_expression(token->pos, EXPR_PREOP);
			expr->op = '(';
			token = parens_expression(token, &expr->unop, "in expression");
			break;
		}
		if (token->special == '[' && lookup_type(token->next)) {
			expr = alloc_expression(token->pos, EXPR_TYPE);
			token = typename(token->next, &expr->symbol, NULL);
			token = expect(token, ']', "in type expression");
			break;
		}
			
	default:
		;
	}
	*tree = expr;
	return token;
}

static struct token *expression_list(struct token *token, struct expression_list **list)
{
	while (!match_op(token, ')')) {
		struct expression *expr = NULL;
		token = assignment_expression(token, &expr);
		if (!expr)
			break;
		add_expression(list, expr);
		if (!match_op(token, ','))
			break;
		token = token->next;
	}
	return token;
}

/*
 * extend to deal with the ambiguous C grammar for parsing
 * a cast expressions followed by an initializer.
 */
static struct token *postfix_expression(struct token *token, struct expression **tree, struct expression *cast_init_expr)
{
	struct expression *expr = cast_init_expr;

	if (!expr)
		token = primary_expression(token, &expr);

	while (expr && token_type(token) == TOKEN_SPECIAL) {
		switch (token->special) {
		case '[': {			/* Array dereference */
			struct expression *deref = alloc_expression(token->pos, EXPR_PREOP);
			struct expression *add = alloc_expression(token->pos, EXPR_BINOP);

			deref->op = '*';
			deref->unop = add;

			add->op = '+';
			add->left = expr;
			token = parse_expression(token->next, &add->right);
			token = expect(token, ']', "at end of array dereference");
			expr = deref;
			continue;
		}
		case SPECIAL_INCREMENT:		/* Post-increment */
		case SPECIAL_DECREMENT:	{	/* Post-decrement */
			struct expression *post = alloc_expression(token->pos, EXPR_POSTOP);
			post->op = token->special;
			post->unop = expr;
			expr = post;
			token = token->next;
			continue;
		}
		case SPECIAL_DEREFERENCE: {	/* Structure pointer member dereference */
			/* "x->y" is just shorthand for "(*x).y" */
			struct expression *inner = alloc_expression(token->pos, EXPR_PREOP);
			inner->op = '*';
			inner->unop = expr;
			expr = inner;
		}
		/* Fall through!! */
		case '.': {			/* Structure member dereference */
			struct expression *deref = alloc_expression(token->pos, EXPR_DEREF);
			deref->op = '.';
			deref->deref = expr;
			token = token->next;
			if (token_type(token) != TOKEN_IDENT) {
				sparse_error(token->pos, "Expected member name");
				break;
			}
			deref->member = token->ident;
			deref->member_offset = -1;
			token = token->next;
			expr = deref;
			continue;
		}

		case '(': {			/* Function call */
			struct expression *call = alloc_expression(token->pos, EXPR_CALL);
			call->op = '(';
			call->fn = expr;
			token = expression_list(token->next, &call->args);
			token = expect(token, ')', "in function call");
			expr = call;
			continue;
		}

		default:
			break;
		}
		break;
	}
	*tree = expr;
	return token;
}

static struct token *cast_expression(struct token *token, struct expression **tree);
static struct token *unary_expression(struct token *token, struct expression **tree);

static struct token *type_info_expression(struct token *token,
	struct expression **tree, int type)
{
	struct expression *expr = alloc_expression(token->pos, type);
	struct token *p;

	*tree = expr;
	expr->flags = CEF_SET_ICE; /* XXX: VLA support will need that changed */
	token = token->next;
	if (!match_op(token, '(') || !lookup_type(token->next))
		return unary_expression(token, &expr->cast_expression);
	p = token;
	token = typename(token->next, &expr->cast_type, NULL);

	if (!match_op(token, ')')) {
		static const char * error[] = {
			[EXPR_SIZEOF] = "at end of sizeof",
			[EXPR_ALIGNOF] = "at end of __alignof__",
			[EXPR_PTRSIZEOF] = "at end of __sizeof_ptr__"
		};
		return expect(token, ')', error[type]);
	}

	token = token->next;
	/*
	 * C99 ambiguity: the typename might have been the beginning
	 * of a typed initializer expression..
	 */
	if (match_op(token, '{')) {
		struct expression *cast = alloc_expression(p->pos, EXPR_CAST);
		cast->cast_type = expr->cast_type;
		expr->cast_type = NULL;
		expr->cast_expression = cast;
		token = initializer(&cast->cast_expression, token);
		token = postfix_expression(token, &expr->cast_expression, cast);
	}
	return token;
}

static struct token *unary_expression(struct token *token, struct expression **tree)
{
	if (token_type(token) == TOKEN_IDENT) {
		struct ident *ident = token->ident;
		if (ident->reserved) {
			static const struct {
				struct ident *id;
				int type;
			} type_information[] = {
				{ &sizeof_ident, EXPR_SIZEOF },
				{ &__alignof___ident, EXPR_ALIGNOF },
				{ &__alignof_ident, EXPR_ALIGNOF },
				{ &_Alignof_ident, EXPR_ALIGNOF },
				{ &__sizeof_ptr___ident, EXPR_PTRSIZEOF },
			};
			int i;
			for (i = 0; i < ARRAY_SIZE(type_information); i++) {
				if (ident == type_information[i].id)
					return type_info_expression(token, tree, type_information[i].type);
			}
		}
	}

	if (token_type(token) == TOKEN_SPECIAL) {
		if (match_oplist(token->special,
		    SPECIAL_INCREMENT, SPECIAL_DECREMENT,
		    '&', '*', 0)) {
		    	struct expression *unop;
			struct expression *unary;
			struct token *next;

			next = cast_expression(token->next, &unop);
			if (!unop) {
				sparse_error(token->pos, "Syntax error in unary expression");
				*tree = NULL;
				return next;
			}
			unary = alloc_expression(token->pos, EXPR_PREOP);
			unary->op = token->special;
			unary->unop = unop;
			*tree = unary;
			return next;
		}
		/* possibly constant ones */
		if (match_oplist(token->special, '+', '-', '~', '!', 0)) {
		    	struct expression *unop;
			struct expression *unary;
			struct token *next;

			next = cast_expression(token->next, &unop);
			if (!unop) {
				sparse_error(token->pos, "Syntax error in unary expression");
				*tree = NULL;
				return next;
			}
			unary = alloc_expression(token->pos, EXPR_PREOP);
			unary->op = token->special;
			unary->unop = unop;
			*tree = unary;
			return next;
		}
		/* Gcc extension: &&label gives the address of a label */
		if (match_op(token, SPECIAL_LOGICAL_AND) &&
		    token_type(token->next) == TOKEN_IDENT) {
			struct expression *label = alloc_expression(token->pos, EXPR_LABEL);
			struct symbol *sym = label_symbol(token->next);
			if (!(sym->ctype.modifiers & MOD_ADDRESSABLE)) {
				sym->ctype.modifiers |= MOD_ADDRESSABLE;
				add_symbol(&function_computed_target_list, sym);
			}
			label->flags = CEF_ADDR;
			label->label_symbol = sym;
			*tree = label;
			return token->next->next;
		}
						
	}
			
	return postfix_expression(token, tree, NULL);
}

/*
 * Ambiguity: a '(' can be either a cast-expression or
 * a primary-expression depending on whether it is followed
 * by a type or not. 
 *
 * additional ambiguity: a "cast expression" followed by
 * an initializer is really a postfix-expression.
 */
static struct token *cast_expression(struct token *token, struct expression **tree)
{
	if (match_op(token, '(')) {
		struct token *next = token->next;
		if (lookup_type(next)) {
			struct expression *cast = alloc_expression(next->pos, EXPR_CAST);
			struct expression *v;
			struct symbol *sym;
			int is_force;

			token = typename(next, &sym, &is_force);
			cast->cast_type = sym;
			token = expect(token, ')', "at end of cast operator");
			if (match_op(token, '{')) {
				if (toplevel(block_scope))
					sym->ctype.modifiers |= MOD_TOPLEVEL;
				if (is_force)
					warning(sym->pos,
						"[force] in compound literal");
				token = initializer(&cast->cast_expression, token);
				return postfix_expression(token, tree, cast);
			}
			*tree = cast;
			if (is_force)
				cast->type = EXPR_FORCE_CAST;
			token = cast_expression(token, &v);
			if (!v)
				return token;
			cast->cast_expression = v;
			return token;
		}
	}
	return unary_expression(token, tree);
}

/*
 * Generic left-to-right binop parsing
 *
 * This _really_ needs to be inlined, because that makes the inner
 * function call statically deterministic rather than a totally
 * unpredictable indirect call. But gcc-3 is so "clever" that it
 * doesn't do so by default even when you tell it to inline it.
 *
 * Making it a macro avoids the inlining problem, and also means
 * that we can pass in the op-comparison as an expression rather
 * than create a data structure for it.
 */

#define LR_BINOP_EXPRESSION(__token, tree, type, inner, compare)	\
	struct expression *left = NULL;					\
	struct token * next = inner(__token, &left);			\
									\
	if (left) {							\
		while (token_type(next) == TOKEN_SPECIAL) {		\
			struct expression *top, *right = NULL;		\
			int op = next->special;				\
									\
			if (!(compare))					\
				goto out;				\
			top = alloc_expression(next->pos, type);	\
			next = inner(next->next, &right);		\
			if (!right) {					\
				sparse_error(next->pos, "No right hand side of '%s'-expression", show_special(op));	\
				break;					\
			}						\
			top->op = op;					\
			top->left = left;				\
			top->right = right;				\
			left = top;					\
		}							\
	}								\
out:									\
	*tree = left;							\
	return next;							\

static struct token *multiplicative_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_BINOP, cast_expression,
		(op == '*') || (op == '/') || (op == '%')
	);
}

static struct token *additive_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_BINOP, multiplicative_expression,
		(op == '+') || (op == '-')
	);
}

static struct token *shift_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_BINOP, additive_expression,
		(op == SPECIAL_LEFTSHIFT) || (op == SPECIAL_RIGHTSHIFT)
	);
}

static struct token *relational_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_COMPARE, shift_expression,
		(op == '<') || (op == '>') ||
		(op == SPECIAL_LTE) || (op == SPECIAL_GTE)
	);
}

static struct token *equality_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_COMPARE, relational_expression,
		(op == SPECIAL_EQUAL) || (op == SPECIAL_NOTEQUAL)
	);
}

static struct token *bitwise_and_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_BINOP, equality_expression,
		(op == '&')
	);
}

static struct token *bitwise_xor_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_BINOP, bitwise_and_expression,
		(op == '^')
	);
}

static struct token *bitwise_or_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_BINOP, bitwise_xor_expression,
		(op == '|')
	);
}

static struct token *logical_and_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_LOGICAL, bitwise_or_expression,
		(op == SPECIAL_LOGICAL_AND)
	);
}

static struct token *logical_or_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_LOGICAL, logical_and_expression,
		(op == SPECIAL_LOGICAL_OR)
	);
}

struct token *conditional_expression(struct token *token, struct expression **tree)
{
	token = logical_or_expression(token, tree);
	if (*tree && match_op(token, '?')) {
		struct expression *expr = alloc_expression(token->pos, EXPR_CONDITIONAL);
		expr->op = token->special;
		expr->left = *tree;
		*tree = expr;
		token = parse_expression(token->next, &expr->cond_true);
		token = expect(token, ':', "in conditional expression");
		token = conditional_expression(token, &expr->cond_false);
	}
	return token;
}

struct token *assignment_expression(struct token *token, struct expression **tree)
{
	token = conditional_expression(token, tree);
	if (*tree && token_type(token) == TOKEN_SPECIAL) {
		static const int assignments[] = {
			'=',
			SPECIAL_ADD_ASSIGN, SPECIAL_SUB_ASSIGN,
			SPECIAL_MUL_ASSIGN, SPECIAL_DIV_ASSIGN,
			SPECIAL_MOD_ASSIGN, SPECIAL_SHL_ASSIGN,
			SPECIAL_SHR_ASSIGN, SPECIAL_AND_ASSIGN,
			SPECIAL_OR_ASSIGN,  SPECIAL_XOR_ASSIGN };
		int i, op = token->special;
		for (i = 0; i < ARRAY_SIZE(assignments); i++)
			if (assignments[i] == op) {
				struct expression * expr = alloc_expression(token->pos, EXPR_ASSIGNMENT);
				expr->left = *tree;
				expr->op = op;
				*tree = expr;
				return assignment_expression(token->next, &expr->right);
			}
	}
	return token;
}

static struct token *comma_expression(struct token *token, struct expression **tree)
{
	LR_BINOP_EXPRESSION(
		token, tree, EXPR_COMMA, assignment_expression,
		(op == ',')
	);
}

struct token *parse_expression(struct token *token, struct expression **tree)
{
	return comma_expression(token,tree);
}


