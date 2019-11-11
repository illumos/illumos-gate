/*
 * sparse/expand.c
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
 * expand constant expressions.
 */
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include "lib.h"
#include "allocate.h"
#include "parse.h"
#include "token.h"
#include "symbol.h"
#include "target.h"
#include "expression.h"
#include "evaluate.h"
#include "expand.h"


static int expand_expression(struct expression *);
static int expand_statement(struct statement *);

// If set, don't issue a warning on divide-by-0, invalid shift, ...
// and don't mark the expression as erroneous but leave it as-is.
// This allows testing some characteristics of the expression
// without creating any side-effects (e.g.: is_zero_constant()).
static int conservative;

static int expand_symbol_expression(struct expression *expr)
{
	struct symbol *sym = expr->symbol;

	if (sym == &zero_int) {
		if (Wundef)
			warning(expr->pos, "undefined preprocessor identifier '%s'", show_ident(expr->symbol_name));
		expr->type = EXPR_VALUE;
		expr->value = 0;
		expr->taint = 0;
		return 0;
	}
	/* The cost of a symbol expression is lower for on-stack symbols */
	return (sym->ctype.modifiers & (MOD_STATIC | MOD_EXTERN)) ? 2 : 1;
}

static long long get_longlong(struct expression *expr)
{
	int no_expand = expr->ctype->ctype.modifiers & MOD_UNSIGNED;
	long long mask = 1ULL << (expr->ctype->bit_size - 1);
	long long value = expr->value;
	long long ormask, andmask;

	if (!(value & mask))
		no_expand = 1;
	andmask = mask | (mask-1);
	ormask = ~andmask;
	if (no_expand)
		ormask = 0;
	return (value & andmask) | ormask;
}

void cast_value(struct expression *expr, struct symbol *newtype,
		struct expression *old, struct symbol *oldtype)
{
	int old_size = oldtype->bit_size;
	int new_size = newtype->bit_size;
	long long value, mask, signmask;
	long long oldmask, oldsignmask, dropped;

	if (is_float_type(newtype) || is_float_type(oldtype))
		goto Float;

	// For pointers and integers, we can just move the value around
	expr->type = EXPR_VALUE;
	expr->taint = old->taint;
	if (old_size == new_size) {
		expr->value = old->value;
		return;
	}

	// expand it to the full "long long" value
	value = get_longlong(old);

Int:
	// _Bool requires a zero test rather than truncation.
	if (is_bool_type(newtype)) {
		expr->value = !!value;
		if (!conservative && value != 0 && value != 1)
			warning(old->pos, "odd constant _Bool cast (%llx becomes 1)", value);
		return;
	}

	// Truncate it to the new size
	signmask = 1ULL << (new_size-1);
	mask = signmask | (signmask-1);
	expr->value = value & mask;

	// Stop here unless checking for truncation
	if (!Wcast_truncate || conservative)
		return;
	
	// Check if we dropped any bits..
	oldsignmask = 1ULL << (old_size-1);
	oldmask = oldsignmask | (oldsignmask-1);
	dropped = oldmask & ~mask;

	// OK if the bits were (and still are) purely sign bits
	if (value & dropped) {
		if (!(value & oldsignmask) || !(value & signmask) || (value & dropped) != dropped)
			warning(old->pos, "cast truncates bits from constant value (%llx becomes %llx)",
				value & oldmask,
				value & mask);
	}
	return;

Float:
	if (!is_float_type(newtype)) {
		value = (long long)old->fvalue;
		expr->type = EXPR_VALUE;
		expr->taint = 0;
		goto Int;
	}

	if (!is_float_type(oldtype))
		expr->fvalue = (long double)get_longlong(old);
	else
		expr->fvalue = old->fvalue;

	if (!(newtype->ctype.modifiers & MOD_LONGLONG) && \
	    !(newtype->ctype.modifiers & MOD_LONGLONGLONG)) {
		if ((newtype->ctype.modifiers & MOD_LONG))
			expr->fvalue = (double)expr->fvalue;
		else
			expr->fvalue = (float)expr->fvalue;
	}
	expr->type = EXPR_FVALUE;
}

static void warn_shift_count(struct expression *expr, struct symbol *ctype, long long count)
{
	if (count < 0) {
		if (!Wshift_count_negative)
			return;
		warning(expr->pos, "shift count is negative (%lld)", count);
		return;
	}
	if (ctype->type == SYM_NODE)
		ctype = ctype->ctype.base_type;

	if (!Wshift_count_overflow)
		return;
	warning(expr->pos, "shift too big (%llu) for type %s", count, show_typename(ctype));
}

/* Return true if constant shift size is valid */
static bool check_shift_count(struct expression *expr, struct expression *right)
{
	struct symbol *ctype = expr->ctype;
	long long count = get_longlong(right);

	if (count >= 0 && count < ctype->bit_size)
		return true;
	if (!conservative)
		warn_shift_count(expr, ctype, count);
	return false;
}

/*
 * CAREFUL! We need to get the size and sign of the
 * result right!
 */
#define CONVERT(op,s)	(((op)<<1)+(s))
#define SIGNED(op)	CONVERT(op, 1)
#define UNSIGNED(op)	CONVERT(op, 0)
static int simplify_int_binop(struct expression *expr, struct symbol *ctype)
{
	struct expression *left = expr->left, *right = expr->right;
	unsigned long long v, l, r, mask;
	signed long long sl, sr;
	int is_signed;

	if (right->type != EXPR_VALUE)
		return 0;
	r = right->value;
	if (expr->op == SPECIAL_LEFTSHIFT || expr->op == SPECIAL_RIGHTSHIFT) {
		if (!check_shift_count(expr, right))
			return 0;
	}
	if (left->type != EXPR_VALUE)
		return 0;
	l = left->value; r = right->value;
	is_signed = !(ctype->ctype.modifiers & MOD_UNSIGNED);
	mask = 1ULL << (ctype->bit_size-1);
	sl = l; sr = r;
	if (is_signed && (sl & mask))
		sl |= ~(mask-1);
	if (is_signed && (sr & mask))
		sr |= ~(mask-1);
	
	switch (CONVERT(expr->op,is_signed)) {
	case SIGNED('+'):
	case UNSIGNED('+'):
		v = l + r;
		break;

	case SIGNED('-'):
	case UNSIGNED('-'):
		v = l - r;
		break;

	case SIGNED('&'):
	case UNSIGNED('&'):
		v = l & r;
		break;

	case SIGNED('|'):
	case UNSIGNED('|'):
		v = l | r;
		break;

	case SIGNED('^'):
	case UNSIGNED('^'):
		v = l ^ r;
		break;

	case SIGNED('*'):
		v = sl * sr;
		break;

	case UNSIGNED('*'):
		v = l * r;
		break;

	case SIGNED('/'):
		if (!r)
			goto Div;
		if (l == mask && sr == -1)
			goto Overflow;
		v = sl / sr;
		break;

	case UNSIGNED('/'):
		if (!r) goto Div;
		v = l / r; 
		break;

	case SIGNED('%'):
		if (!r)
			goto Div;
		if (l == mask && sr == -1)
			goto Overflow;
		v = sl % sr;
		break;

	case UNSIGNED('%'):
		if (!r) goto Div;
		v = l % r;
		break;

	case SIGNED(SPECIAL_LEFTSHIFT):
	case UNSIGNED(SPECIAL_LEFTSHIFT):
		v = l << r;
		break; 

	case SIGNED(SPECIAL_RIGHTSHIFT):
		v = sl >> r;
		break;

	case UNSIGNED(SPECIAL_RIGHTSHIFT):
		v = l >> r;
		break;

	default:
		return 0;
	}
	mask = mask | (mask-1);
	expr->value = v & mask;
	expr->type = EXPR_VALUE;
	expr->taint = left->taint | right->taint;
	return 1;
Div:
	if (!conservative)
		warning(expr->pos, "division by zero");
	return 0;
Overflow:
	if (!conservative)
		warning(expr->pos, "constant integer operation overflow");
	return 0;
}

static int simplify_cmp_binop(struct expression *expr, struct symbol *ctype)
{
	struct expression *left = expr->left, *right = expr->right;
	unsigned long long l, r, mask;
	signed long long sl, sr;

	if (left->type != EXPR_VALUE || right->type != EXPR_VALUE)
		return 0;
	l = left->value; r = right->value;
	mask = 1ULL << (ctype->bit_size-1);
	sl = l; sr = r;
	if (sl & mask)
		sl |= ~(mask-1);
	if (sr & mask)
		sr |= ~(mask-1);
	switch (expr->op) {
	case '<':		expr->value = sl < sr; break;
	case '>':		expr->value = sl > sr; break;
	case SPECIAL_LTE:	expr->value = sl <= sr; break;
	case SPECIAL_GTE:	expr->value = sl >= sr; break;
	case SPECIAL_EQUAL:	expr->value = l == r; break;
	case SPECIAL_NOTEQUAL:	expr->value = l != r; break;
	case SPECIAL_UNSIGNED_LT:expr->value = l < r; break;
	case SPECIAL_UNSIGNED_GT:expr->value = l > r; break;
	case SPECIAL_UNSIGNED_LTE:expr->value = l <= r; break;
	case SPECIAL_UNSIGNED_GTE:expr->value = l >= r; break;
	}
	expr->type = EXPR_VALUE;
	expr->taint = left->taint | right->taint;
	return 1;
}

static int simplify_float_binop(struct expression *expr)
{
	struct expression *left = expr->left, *right = expr->right;
	unsigned long mod = expr->ctype->ctype.modifiers;
	long double l, r, res;

	if (left->type != EXPR_FVALUE || right->type != EXPR_FVALUE)
		return 0;

	l = left->fvalue;
	r = right->fvalue;

	if (mod & MOD_LONGLONG) {
		switch (expr->op) {
		case '+':	res = l + r; break;
		case '-':	res = l - r; break;
		case '*':	res = l * r; break;
		case '/':	if (!r) goto Div;
				res = l / r; break;
		default: return 0;
		}
	} else if (mod & MOD_LONG) {
		switch (expr->op) {
		case '+':	res = (double) l + (double) r; break;
		case '-':	res = (double) l - (double) r; break;
		case '*':	res = (double) l * (double) r; break;
		case '/':	if (!r) goto Div;
				res = (double) l / (double) r; break;
		default: return 0;
		}
	} else {
		switch (expr->op) {
		case '+':	res = (float)l + (float)r; break;
		case '-':	res = (float)l - (float)r; break;
		case '*':	res = (float)l * (float)r; break;
		case '/':	if (!r) goto Div;
				res = (float)l / (float)r; break;
		default: return 0;
		}
	}
	expr->type = EXPR_FVALUE;
	expr->fvalue = res;
	return 1;
Div:
	if (!conservative)
		warning(expr->pos, "division by zero");
	return 0;
}

static int simplify_float_cmp(struct expression *expr, struct symbol *ctype)
{
	struct expression *left = expr->left, *right = expr->right;
	long double l, r;

	if (left->type != EXPR_FVALUE || right->type != EXPR_FVALUE)
		return 0;

	l = left->fvalue;
	r = right->fvalue;
	switch (expr->op) {
	case '<':		expr->value = l < r; break;
	case '>':		expr->value = l > r; break;
	case SPECIAL_LTE:	expr->value = l <= r; break;
	case SPECIAL_GTE:	expr->value = l >= r; break;
	case SPECIAL_EQUAL:	expr->value = l == r; break;
	case SPECIAL_NOTEQUAL:	expr->value = l != r; break;
	}
	expr->type = EXPR_VALUE;
	expr->taint = 0;
	return 1;
}

static int expand_binop(struct expression *expr)
{
	int cost;

	cost = expand_expression(expr->left);
	cost += expand_expression(expr->right);
	if (simplify_int_binop(expr, expr->ctype))
		return 0;
	if (simplify_float_binop(expr))
		return 0;
	return cost + 1;
}

static int expand_logical(struct expression *expr)
{
	struct expression *left = expr->left;
	struct expression *right;
	int cost, rcost;

	/* Do immediate short-circuiting ... */
	cost = expand_expression(left);
	if (left->type == EXPR_VALUE) {
		if (expr->op == SPECIAL_LOGICAL_AND) {
			if (!left->value) {
				expr->type = EXPR_VALUE;
				expr->value = 0;
				expr->taint = left->taint;
				return 0;
			}
		} else {
			if (left->value) {
				expr->type = EXPR_VALUE;
				expr->value = 1;
				expr->taint = left->taint;
				return 0;
			}
		}
	}

	right = expr->right;
	rcost = expand_expression(right);
	if (left->type == EXPR_VALUE && right->type == EXPR_VALUE) {
		/*
		 * We know the left value doesn't matter, since
		 * otherwise we would have short-circuited it..
		 */
		expr->type = EXPR_VALUE;
		expr->value = right->value != 0;
		expr->taint = left->taint | right->taint;
		return 0;
	}

	/*
	 * If the right side is safe and cheaper than a branch,
	 * just avoid the branch and turn it into a regular binop
	 * style SAFELOGICAL.
	 */
	if (rcost < BRANCH_COST) {
		expr->type = EXPR_BINOP;
		rcost -= BRANCH_COST - 1;
	}

	return cost + BRANCH_COST + rcost;
}

static int expand_comma(struct expression *expr)
{
	int cost;

	cost = expand_expression(expr->left);
	cost += expand_expression(expr->right);
	if (expr->left->type == EXPR_VALUE || expr->left->type == EXPR_FVALUE) {
		unsigned flags = expr->flags;
		unsigned taint;
		taint = expr->left->type == EXPR_VALUE ? expr->left->taint : 0;
		*expr = *expr->right;
		expr->flags = flags;
		if (expr->type == EXPR_VALUE)
			expr->taint |= Taint_comma | taint;
	}
	return cost;
}

#define MOD_IGN (MOD_QUALIFIER)

static int compare_types(int op, struct symbol *left, struct symbol *right)
{
	struct ctype c1 = {.base_type = left};
	struct ctype c2 = {.base_type = right};
	switch (op) {
	case SPECIAL_EQUAL:
		return !type_difference(&c1, &c2, MOD_IGN, MOD_IGN);
	case SPECIAL_NOTEQUAL:
		return type_difference(&c1, &c2, MOD_IGN, MOD_IGN) != NULL;
	case '<':
		return left->bit_size < right->bit_size;
	case '>':
		return left->bit_size > right->bit_size;
	case SPECIAL_LTE:
		return left->bit_size <= right->bit_size;
	case SPECIAL_GTE:
		return left->bit_size >= right->bit_size;
	}
	return 0;
}

static int expand_compare(struct expression *expr)
{
	struct expression *left = expr->left, *right = expr->right;
	int cost;

	cost = expand_expression(left);
	cost += expand_expression(right);

	if (left && right) {
		/* Type comparison? */
		if (left->type == EXPR_TYPE && right->type == EXPR_TYPE) {
			int op = expr->op;
			expr->type = EXPR_VALUE;
			expr->value = compare_types(op, left->symbol, right->symbol);
			expr->taint = 0;
			return 0;
		}
		if (simplify_cmp_binop(expr, left->ctype))
			return 0;
		if (simplify_float_cmp(expr, left->ctype))
			return 0;
	}
	return cost + 1;
}

static int expand_conditional(struct expression *expr)
{
	struct expression *cond = expr->conditional;
	struct expression *valt = expr->cond_true;
	struct expression *valf = expr->cond_false;
	int cost, cond_cost;

	cond_cost = expand_expression(cond);
	if (cond->type == EXPR_VALUE) {
		unsigned flags = expr->flags;
		if (!cond->value)
			valt = valf;
		if (!valt)
			valt = cond;
		cost = expand_expression(valt);
		*expr = *valt;
		expr->flags = flags;
		if (expr->type == EXPR_VALUE)
			expr->taint |= cond->taint;
		return cost;
	}

	cost = expand_expression(valt);
	cost += expand_expression(valf);

	if (cost < SELECT_COST) {
		expr->type = EXPR_SELECT;
		cost -= BRANCH_COST - 1;
	}

	return cost + cond_cost + BRANCH_COST;
}

static void check_assignment(struct expression *expr)
{
	struct expression *right;

	switch (expr->op) {
	case SPECIAL_SHL_ASSIGN:
	case SPECIAL_SHR_ASSIGN:
		right = expr->right;
		if (right->type != EXPR_VALUE)
			break;
		check_shift_count(expr, right);
		break;
	}
	return;
}

static int expand_assignment(struct expression *expr)
{
	expand_expression(expr->left);
	expand_expression(expr->right);

	if (!conservative)
		check_assignment(expr);
	return SIDE_EFFECTS;
}

static int expand_addressof(struct expression *expr)
{
	return expand_expression(expr->unop);
}

/*
 * Look up a trustable initializer value at the requested offset.
 *
 * Return NULL if no such value can be found or statically trusted.
 *
 * FIXME!! We should check that the size is right!
 */
static struct expression *constant_symbol_value(struct symbol *sym, int offset)
{
	struct expression *value;

	if (sym->ctype.modifiers & MOD_ACCESS)
		return NULL;
	value = sym->initializer;
	if (!value)
		return NULL;
	if (value->type == EXPR_INITIALIZER) {
		struct expression *entry;
		FOR_EACH_PTR(value->expr_list, entry) {
			if (entry->type != EXPR_POS) {
				if (offset)
					continue;
				return entry;
			}
			if (entry->init_offset < offset)
				continue;
			if (entry->init_offset > offset)
				return NULL;
			return entry->init_expr;
		} END_FOR_EACH_PTR(entry);
		return NULL;
	}
	return value;
}

static int expand_dereference(struct expression *expr)
{
	struct expression *unop = expr->unop;
	unsigned int offset;

	expand_expression(unop);

	/*
	 * NOTE! We get a bogus warning right now for some special
	 * cases: apparently I've screwed up the optimization of
	 * a zero-offset dereference, and the ctype is wrong.
	 *
	 * Leave the warning in anyway, since this is also a good
	 * test for me to get the type evaluation right..
	 */
	if (expr->ctype->ctype.modifiers & MOD_NODEREF)
		warning(unop->pos, "dereference of noderef expression");

	/*
	 * Is it "symbol" or "symbol + offset"?
	 */
	offset = 0;
	if (unop->type == EXPR_BINOP && unop->op == '+') {
		struct expression *right = unop->right;
		if (right->type == EXPR_VALUE) {
			offset = right->value;
			unop = unop->left;
		}
	}

	if (unop->type == EXPR_SYMBOL) {
		struct symbol *sym = unop->symbol;
		struct expression *value = constant_symbol_value(sym, offset);

		/* Const symbol with a constant initializer? */
		if (value) {
			/* FIXME! We should check that the size is right! */
			if (value->type == EXPR_VALUE) {
				if (is_bitfield_type(value->ctype))
					return UNSAFE;
				expr->type = EXPR_VALUE;
				expr->value = value->value;
				expr->taint = 0;
				return 0;
			} else if (value->type == EXPR_FVALUE) {
				expr->type = EXPR_FVALUE;
				expr->fvalue = value->fvalue;
				return 0;
			}
		}

		/* Direct symbol dereference? Cheap and safe */
		return (sym->ctype.modifiers & (MOD_STATIC | MOD_EXTERN)) ? 2 : 1;
	}

	return UNSAFE;
}

static int simplify_preop(struct expression *expr)
{
	struct expression *op = expr->unop;
	unsigned long long v, mask;

	if (op->type != EXPR_VALUE)
		return 0;

	mask = 1ULL << (expr->ctype->bit_size-1);
	v = op->value;
	switch (expr->op) {
	case '+': break;
	case '-':
		if (v == mask && !(expr->ctype->ctype.modifiers & MOD_UNSIGNED))
			goto Overflow;
		v = -v;
		break;
	case '!': v = !v; break;
	case '~': v = ~v; break;
	default: return 0;
	}
	mask = mask | (mask-1);
	expr->value = v & mask;
	expr->type = EXPR_VALUE;
	expr->taint = op->taint;
	return 1;

Overflow:
	if (!conservative)
		warning(expr->pos, "constant integer operation overflow");
	return 0;
}

static int simplify_float_preop(struct expression *expr)
{
	struct expression *op = expr->unop;
	long double v;

	if (op->type != EXPR_FVALUE)
		return 0;
	v = op->fvalue;
	switch (expr->op) {
	case '+': break;
	case '-': v = -v; break;
	default: return 0;
	}
	expr->fvalue = v;
	expr->type = EXPR_FVALUE;
	return 1;
}

/*
 * Unary post-ops: x++ and x--
 */
static int expand_postop(struct expression *expr)
{
	expand_expression(expr->unop);
	return SIDE_EFFECTS;
}

static int expand_preop(struct expression *expr)
{
	int cost;

	switch (expr->op) {
	case '*':
		return expand_dereference(expr);

	case '&':
		return expand_addressof(expr);

	case SPECIAL_INCREMENT:
	case SPECIAL_DECREMENT:
		/*
		 * From a type evaluation standpoint the preops are
		 * the same as the postops
		 */
		return expand_postop(expr);

	default:
		break;
	}
	cost = expand_expression(expr->unop);

	if (simplify_preop(expr))
		return 0;
	if (simplify_float_preop(expr))
		return 0;
	return cost + 1;
}

static int expand_arguments(struct expression_list *head)
{
	int cost = 0;
	struct expression *expr;

	FOR_EACH_PTR (head, expr) {
		cost += expand_expression(expr);
	} END_FOR_EACH_PTR(expr);
	return cost;
}

static int expand_cast(struct expression *expr)
{
	int cost;
	struct expression *target = expr->cast_expression;

	cost = expand_expression(target);

	/* Simplify normal integer casts.. */
	if (target->type == EXPR_VALUE || target->type == EXPR_FVALUE) {
		cast_value(expr, expr->ctype, target, target->ctype);
		return 0;
	}
	return cost + 1;
}

/*
 * expand a call expression with a symbol. This
 * should expand builtins.
 */
static int expand_symbol_call(struct expression *expr, int cost)
{
	struct expression *fn = expr->fn;
	struct symbol *ctype = fn->ctype;

	expand_expression(fn);

	if (fn->type != EXPR_PREOP)
		return SIDE_EFFECTS;

	if (ctype->op && ctype->op->expand)
		return ctype->op->expand(expr, cost);

	if (ctype->ctype.modifiers & MOD_PURE)
		return cost + 1;

	return SIDE_EFFECTS;
}

static int expand_call(struct expression *expr)
{
	int cost;
	struct symbol *sym;
	struct expression *fn = expr->fn;

	cost = expand_arguments(expr->args);
	sym = fn->ctype;
	if (!sym) {
		expression_error(expr, "function has no type");
		return SIDE_EFFECTS;
	}
	if (sym->type == SYM_NODE)
		return expand_symbol_call(expr, cost);

	return SIDE_EFFECTS;
}

static int expand_expression_list(struct expression_list *list)
{
	int cost = 0;
	struct expression *expr;

	FOR_EACH_PTR(list, expr) {
		cost += expand_expression(expr);
	} END_FOR_EACH_PTR(expr);
	return cost;
}

/* 
 * We can simplify nested position expressions if
 * this is a simple (single) positional expression.
 */
static int expand_pos_expression(struct expression *expr)
{
	struct expression *nested = expr->init_expr;
	unsigned long offset = expr->init_offset;
	int nr = expr->init_nr;

	if (nr == 1) {
		switch (nested->type) {
		case EXPR_POS:
			offset += nested->init_offset;
			*expr = *nested;
			expr->init_offset = offset;
			nested = expr;
			break;

		case EXPR_INITIALIZER: {
			struct expression *reuse = nested, *entry;
			*expr = *nested;
			FOR_EACH_PTR(expr->expr_list, entry) {
				if (entry->type == EXPR_POS) {
					entry->init_offset += offset;
				} else {
					if (!reuse) {
						/*
						 * This happens rarely, but it can happen
						 * with bitfields that are all at offset
						 * zero..
						 */
						reuse = alloc_expression(entry->pos, EXPR_POS);
					}
					reuse->type = EXPR_POS;
					reuse->ctype = entry->ctype;
					reuse->init_offset = offset;
					reuse->init_nr = 1;
					reuse->init_expr = entry;
					REPLACE_CURRENT_PTR(entry, reuse);
					reuse = NULL;
				}
			} END_FOR_EACH_PTR(entry);
			nested = expr;
			break;
		}

		default:
			break;
		}
	}
	return expand_expression(nested);
}

static unsigned long bit_offset(const struct expression *expr)
{
	unsigned long offset = 0;
	while (expr->type == EXPR_POS) {
		offset += bytes_to_bits(expr->init_offset);
		expr = expr->init_expr;
	}
	if (expr && expr->ctype)
		offset += expr->ctype->bit_offset;
	return offset;
}

static unsigned long bit_range(const struct expression *expr)
{
	unsigned long range = 0;
	unsigned long size = 0;
	while (expr->type == EXPR_POS) {
		unsigned long nr = expr->init_nr;
		size = expr->ctype->bit_size;
		range += (nr - 1) * size;
		expr = expr->init_expr;
	}
	range += size;
	return range;
}

static int compare_expressions(const void *_a, const void *_b)
{
	const struct expression *a = _a;
	const struct expression *b = _b;
	unsigned long a_pos = bit_offset(a);
	unsigned long b_pos = bit_offset(b);

	return (a_pos < b_pos) ? -1 : (a_pos == b_pos) ? 0 : 1;
}

static void sort_expression_list(struct expression_list **list)
{
	sort_list((struct ptr_list **)list, compare_expressions);
}

static void verify_nonoverlapping(struct expression_list **list, struct expression *expr)
{
	struct expression *a = NULL;
	unsigned long max = 0;
	unsigned long whole = expr->ctype->bit_size;
	struct expression *b;

	if (!Woverride_init)
		return;

	FOR_EACH_PTR(*list, b) {
		unsigned long off, end;
		if (!b->ctype || !b->ctype->bit_size)
			continue;
		off = bit_offset(b);
		if (a && off < max) {
			warning(a->pos, "Initializer entry defined twice");
			info(b->pos, "  also defined here");
			if (!Woverride_init_all)
				return;
		}
		end = off + bit_range(b);
		if (!a && !Woverride_init_whole_range) {
			// If first entry is the whole range, do not let
			// any warning about it (this allow to initialize
			// an array with some default value and then override
			// some specific entries).
			if (off == 0 && end == whole)
				continue;
		}
		if (end > max) {
			max = end;
			a = b;
		}
	} END_FOR_EACH_PTR(b);
}

static int expand_expression(struct expression *expr)
{
	if (!expr)
		return 0;
	if (!expr->ctype || expr->ctype == &bad_ctype)
		return UNSAFE;

	switch (expr->type) {
	case EXPR_VALUE:
	case EXPR_FVALUE:
	case EXPR_STRING:
		return 0;
	case EXPR_TYPE:
	case EXPR_SYMBOL:
		return expand_symbol_expression(expr);
	case EXPR_BINOP:
		return expand_binop(expr);

	case EXPR_LOGICAL:
		return expand_logical(expr);

	case EXPR_COMMA:
		return expand_comma(expr);

	case EXPR_COMPARE:
		return expand_compare(expr);

	case EXPR_ASSIGNMENT:
		return expand_assignment(expr);

	case EXPR_PREOP:
		return expand_preop(expr);

	case EXPR_POSTOP:
		return expand_postop(expr);

	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		return expand_cast(expr);

	case EXPR_CALL:
		return expand_call(expr);

	case EXPR_DEREF:
		warning(expr->pos, "we should not have an EXPR_DEREF left at expansion time");
		return UNSAFE;

	case EXPR_SELECT:
	case EXPR_CONDITIONAL:
		return expand_conditional(expr);

	case EXPR_STATEMENT: {
		struct statement *stmt = expr->statement;
		int cost = expand_statement(stmt);

		if (stmt->type == STMT_EXPRESSION && stmt->expression)
			*expr = *stmt->expression;
		return cost;
	}

	case EXPR_LABEL:
		return 0;

	case EXPR_INITIALIZER:
		sort_expression_list(&expr->expr_list);
		verify_nonoverlapping(&expr->expr_list, expr);
		return expand_expression_list(expr->expr_list);

	case EXPR_IDENTIFIER:
		return UNSAFE;

	case EXPR_INDEX:
		return UNSAFE;

	case EXPR_SLICE:
		return expand_expression(expr->base) + 1;

	case EXPR_POS:
		return expand_pos_expression(expr);

	case EXPR_SIZEOF:
	case EXPR_PTRSIZEOF:
	case EXPR_ALIGNOF:
	case EXPR_OFFSETOF:
		expression_error(expr, "internal front-end error: sizeof in expansion?");
		return UNSAFE;
	case EXPR_ASM_OPERAND:
		expression_error(expr, "internal front-end error: ASM_OPERAND in expansion?");
		return UNSAFE;
	}
	return SIDE_EFFECTS;
}

static void expand_const_expression(struct expression *expr, const char *where)
{
	if (expr) {
		expand_expression(expr);
		if (expr->type != EXPR_VALUE)
			expression_error(expr, "Expected constant expression in %s", where);
	}
}

int expand_symbol(struct symbol *sym)
{
	int retval;
	struct symbol *base_type;

	if (!sym)
		return 0;
	base_type = sym->ctype.base_type;
	if (!base_type)
		return 0;

	retval = expand_expression(sym->initializer);
	/* expand the body of the symbol */
	if (base_type->type == SYM_FN) {
		if (base_type->stmt)
			expand_statement(base_type->stmt);
	}
	return retval;
}

static void expand_return_expression(struct statement *stmt)
{
	expand_expression(stmt->expression);
}

static int expand_if_statement(struct statement *stmt)
{
	struct expression *expr = stmt->if_conditional;

	if (!expr || !expr->ctype || expr->ctype == &bad_ctype)
		return UNSAFE;

	expand_expression(expr);

/* This is only valid if nobody jumps into the "dead" side */
#if 0
	/* Simplify constant conditionals without even evaluating the false side */
	if (expr->type == EXPR_VALUE) {
		struct statement *simple;
		simple = expr->value ? stmt->if_true : stmt->if_false;

		/* Nothing? */
		if (!simple) {
			stmt->type = STMT_NONE;
			return 0;
		}
		expand_statement(simple);
		*stmt = *simple;
		return SIDE_EFFECTS;
	}
#endif
	expand_statement(stmt->if_true);
	expand_statement(stmt->if_false);
	return SIDE_EFFECTS;
}

/*
 * Expanding a compound statement is really just
 * about adding up the costs of each individual
 * statement.
 *
 * We also collapse a simple compound statement:
 * this would trigger for simple inline functions,
 * except we would have to check the "return"
 * symbol usage. Next time.
 */
static int expand_compound(struct statement *stmt)
{
	struct statement *s, *last;
	int cost, statements;

	if (stmt->ret)
		expand_symbol(stmt->ret);

	last = stmt->args;
	cost = expand_statement(last);
	statements = last != NULL;
	FOR_EACH_PTR(stmt->stmts, s) {
		statements++;
		last = s;
		cost += expand_statement(s);
	} END_FOR_EACH_PTR(s);

	if (statements == 1 && !stmt->ret)
		*stmt = *last;

	return cost;
}

static int expand_statement(struct statement *stmt)
{
	if (!stmt)
		return 0;

	switch (stmt->type) {
	case STMT_DECLARATION: {
		struct symbol *sym;
		FOR_EACH_PTR(stmt->declaration, sym) {
			expand_symbol(sym);
		} END_FOR_EACH_PTR(sym);
		return SIDE_EFFECTS;
	}

	case STMT_RETURN:
		expand_return_expression(stmt);
		return SIDE_EFFECTS;

	case STMT_EXPRESSION:
		return expand_expression(stmt->expression);

	case STMT_COMPOUND:
		return expand_compound(stmt);

	case STMT_IF:
		return expand_if_statement(stmt);

	case STMT_ITERATOR:
		expand_expression(stmt->iterator_pre_condition);
		expand_expression(stmt->iterator_post_condition);
		expand_statement(stmt->iterator_pre_statement);
		expand_statement(stmt->iterator_statement);
		expand_statement(stmt->iterator_post_statement);
		return SIDE_EFFECTS;

	case STMT_SWITCH:
		expand_expression(stmt->switch_expression);
		expand_statement(stmt->switch_statement);
		return SIDE_EFFECTS;

	case STMT_CASE:
		expand_const_expression(stmt->case_expression, "case statement");
		expand_const_expression(stmt->case_to, "case statement");
		expand_statement(stmt->case_statement);
		return SIDE_EFFECTS;

	case STMT_LABEL:
		expand_statement(stmt->label_statement);
		return SIDE_EFFECTS;

	case STMT_GOTO:
		expand_expression(stmt->goto_expression);
		return SIDE_EFFECTS;

	case STMT_NONE:
		break;
	case STMT_ASM:
		/* FIXME! Do the asm parameter evaluation! */
		break;
	case STMT_CONTEXT:
		expand_expression(stmt->expression);
		break;
	case STMT_RANGE:
		expand_expression(stmt->range_expression);
		expand_expression(stmt->range_low);
		expand_expression(stmt->range_high);
		break;
	}
	return SIDE_EFFECTS;
}

static inline int bad_integer_constant_expression(struct expression *expr)
{
	if (!(expr->flags & CEF_ICE))
		return 1;
	if (expr->taint & Taint_comma)
		return 1;
	return 0;
}

static long long __get_expression_value(struct expression *expr, int strict)
{
	long long value, mask;
	struct symbol *ctype;

	if (!expr)
		return 0;
	ctype = evaluate_expression(expr);
	if (!ctype) {
		expression_error(expr, "bad constant expression type");
		return 0;
	}
	expand_expression(expr);
	if (expr->type != EXPR_VALUE) {
		if (strict != 2)
			expression_error(expr, "bad constant expression");
		return 0;
	}
#if 0	// This complains about "1 ? 1 :__bits_per()" which the kernel use
	if ((strict == 1) && bad_integer_constant_expression(expr)) {
		expression_error(expr, "bad integer constant expression");
		return 0;
	}
#endif

	value = expr->value;
	mask = 1ULL << (ctype->bit_size-1);

	if (value & mask) {
		while (ctype->type != SYM_BASETYPE)
			ctype = ctype->ctype.base_type;
		if (!(ctype->ctype.modifiers & MOD_UNSIGNED))
			value = value | mask | ~(mask-1);
	}
	return value;
}

long long get_expression_value(struct expression *expr)
{
	return __get_expression_value(expr, 0);
}

long long const_expression_value(struct expression *expr)
{
	return __get_expression_value(expr, 1);
}

long long get_expression_value_silent(struct expression *expr)
{

	return __get_expression_value(expr, 2);
}

int expr_truth_value(struct expression *expr)
{
	const int saved = conservative;
	struct symbol *ctype;

	if (!expr)
		return 0;

	ctype = evaluate_expression(expr);
	if (!ctype)
		return -1;

	conservative = 1;
	expand_expression(expr);
	conservative = saved;

redo:
	switch (expr->type) {
	case EXPR_COMMA:
		expr = expr->right;
		goto redo;
	case EXPR_VALUE:
		return expr->value != 0;
	case EXPR_FVALUE:
		return expr->fvalue != 0;
	default:
		return -1;
	}
}

int is_zero_constant(struct expression *expr)
{
	const int saved = conservative;
	conservative = 1;
	expand_expression(expr);
	conservative = saved;
	return expr->type == EXPR_VALUE && !expr->value;
}
