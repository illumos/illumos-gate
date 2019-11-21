/*
 * sparse/evaluate.c
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
 * Evaluate constant expressions.
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

#include "evaluate.h"
#include "lib.h"
#include "allocate.h"
#include "parse.h"
#include "token.h"
#include "symbol.h"
#include "target.h"
#include "expression.h"

struct symbol *current_fn;

struct ident bad_address_space = { .len = 6, .name = "bad AS", };

static struct symbol *degenerate(struct expression *expr);
static struct symbol *evaluate_symbol(struct symbol *sym);

static inline int valid_expr_type(struct expression *expr)
{
	return expr && valid_type(expr->ctype);
}

static inline int valid_subexpr_type(struct expression *expr)
{
	return valid_expr_type(expr->left)
	    && valid_expr_type(expr->right);
}

static struct symbol *evaluate_symbol_expression(struct expression *expr)
{
	struct expression *addr;
	struct symbol *sym = expr->symbol;
	struct symbol *base_type;

	if (!sym) {
		expression_error(expr, "undefined identifier '%s'", show_ident(expr->symbol_name));
		return NULL;
	}

	examine_symbol_type(sym);

	base_type = get_base_type(sym);
	if (!base_type) {
		expression_error(expr, "identifier '%s' has no type", show_ident(expr->symbol_name));
		return NULL;
	}

	addr = alloc_expression(expr->pos, EXPR_SYMBOL);
	addr->symbol = sym;
	addr->symbol_name = expr->symbol_name;
	addr->ctype = &lazy_ptr_ctype;	/* Lazy evaluation: we need to do a proper job if somebody does &sym */
	addr->flags = expr->flags;
	expr->type = EXPR_PREOP;
	expr->op = '*';
	expr->unop = addr;
	expr->flags = CEF_NONE;

	/* The type of a symbol is the symbol itself! */
	expr->ctype = sym;
	return sym;
}

static struct symbol *evaluate_string(struct expression *expr)
{
	struct symbol *sym = alloc_symbol(expr->pos, SYM_NODE);
	struct symbol *array = alloc_symbol(expr->pos, SYM_ARRAY);
	struct expression *addr = alloc_expression(expr->pos, EXPR_SYMBOL);
	struct expression *initstr = alloc_expression(expr->pos, EXPR_STRING);
	unsigned int length = expr->string->length;

	sym->array_size = alloc_const_expression(expr->pos, length);
	sym->bit_size = bytes_to_bits(length);
	sym->ctype.alignment = 1;
	sym->string = 1;
	sym->ctype.modifiers = MOD_STATIC;
	sym->ctype.base_type = array;
	sym->initializer = initstr;

	initstr->ctype = sym;
	initstr->string = expr->string;

	array->array_size = sym->array_size;
	array->bit_size = bytes_to_bits(length);
	array->ctype.alignment = 1;
	array->ctype.modifiers = MOD_STATIC;
	array->ctype.base_type = &char_ctype;
	
	addr->symbol = sym;
	addr->ctype = &lazy_ptr_ctype;
	addr->flags = CEF_ADDR;

	expr->type = EXPR_PREOP;
	expr->op = '*';
	expr->unop = addr;  
	expr->ctype = sym;
	return sym;
}

/* type has come from classify_type and is an integer type */
static inline struct symbol *integer_promotion(struct symbol *type)
{
	unsigned long mod =  type->ctype.modifiers;
	int width = type->bit_size;

	/*
	 * Bitfields always promote to the base type,
	 * even if the bitfield might be bigger than
	 * an "int".
	 */
	if (type->type == SYM_BITFIELD) {
		type = type->ctype.base_type;
	}
	mod = type->ctype.modifiers;
	if (width < bits_in_int)
		return &int_ctype;

	/* If char/short has as many bits as int, it still gets "promoted" */
	if (mod & (MOD_CHAR | MOD_SHORT)) {
		if (mod & MOD_UNSIGNED)
			return &uint_ctype;
		return &int_ctype;
	}
	return type;
}

/*
 * integer part of usual arithmetic conversions:
 *	integer promotions are applied
 *	if left and right are identical, we are done
 *	if signedness is the same, convert one with lower rank
 *	unless unsigned argument has rank lower than signed one, convert the
 *	signed one.
 *	if signed argument is bigger than unsigned one, convert the unsigned.
 *	otherwise, convert signed.
 *
 * Leaving aside the integer promotions, that is equivalent to
 *	if identical, don't convert
 *	if left is bigger than right, convert right
 *	if right is bigger than left, convert right
 *	otherwise, if signedness is the same, convert one with lower rank
 *	otherwise convert the signed one.
 */
static struct symbol *bigger_int_type(struct symbol *left, struct symbol *right)
{
	unsigned long lmod, rmod;

	left = integer_promotion(left);
	right = integer_promotion(right);

	if (left == right)
		goto left;

	if (left->bit_size > right->bit_size)
		goto left;

	if (right->bit_size > left->bit_size)
		goto right;

	lmod = left->ctype.modifiers;
	rmod = right->ctype.modifiers;
	if ((lmod ^ rmod) & MOD_UNSIGNED) {
		if (lmod & MOD_UNSIGNED)
			goto left;
	} else if ((lmod & ~rmod) & (MOD_LONG_ALL))
		goto left;
right:
	left = right;
left:
	return left;
}

static int same_cast_type(struct symbol *orig, struct symbol *new)
{
	return orig->bit_size == new->bit_size &&
	       orig->bit_offset == new->bit_offset;
}

static struct symbol *base_type(struct symbol *node, unsigned long *modp, struct ident **asp)
{
	unsigned long mod = 0;
	struct ident *as = NULL;

	while (node) {
		mod |= node->ctype.modifiers;
		combine_address_space(node->pos, &as, node->ctype.as);
		if (node->type == SYM_NODE) {
			node = node->ctype.base_type;
			continue;
		}
		break;
	}
	*modp = mod & ~MOD_IGNORE;
	*asp = as;
	return node;
}

static int is_same_type(struct expression *expr, struct symbol *new)
{
	struct symbol *old = expr->ctype;
	unsigned long oldmod, newmod;
	struct ident *oldas, *newas;

	old = base_type(old, &oldmod, &oldas);
	new = base_type(new, &newmod, &newas);

	/* Same base type, same address space? */
	if (old == new && oldas == newas) {
		unsigned long difmod;

		/* Check the modifier bits. */
		difmod = (oldmod ^ newmod) & ~MOD_NOCAST;

		/* Exact same type? */
		if (!difmod)
			return 1;

		/*
		 * Not the same type, but differs only in "const".
		 * Don't warn about MOD_NOCAST.
		 */
		if (difmod == MOD_CONST)
			return 0;
	}
	if ((oldmod | newmod) & MOD_NOCAST) {
		const char *tofrom = "to/from";
		if (!(newmod & MOD_NOCAST))
			tofrom = "from";
		if (!(oldmod & MOD_NOCAST))
			tofrom = "to";
		warning(expr->pos, "implicit cast %s nocast type", tofrom);
	}
	return 0;
}

static void
warn_for_different_enum_types (struct position pos,
			       struct symbol *typea,
			       struct symbol *typeb)
{
	if (!Wenum_mismatch)
		return;
	if (typea->type == SYM_NODE)
		typea = typea->ctype.base_type;
	if (typeb->type == SYM_NODE)
		typeb = typeb->ctype.base_type;

	if (typea == typeb)
		return;

	if (typea->type == SYM_ENUM && typeb->type == SYM_ENUM) {
		warning(pos, "mixing different enum types");
		info(pos, "    %s versus", show_typename(typea));
		info(pos, "    %s", show_typename(typeb));
	}
}

static int cast_flags(struct expression *expr, struct expression *target);
static struct symbol *cast_to_bool(struct expression *expr);

/*
 * This gets called for implicit casts in assignments and
 * integer promotion. We often want to try to move the
 * cast down, because the ops involved may have been
 * implicitly cast up, and we can get rid of the casts
 * early.
 */
static struct expression * cast_to(struct expression *old, struct symbol *type)
{
	struct expression *expr;

	warn_for_different_enum_types (old->pos, old->ctype, type);

	if (old->ctype != &null_ctype && is_same_type(old, type))
		return old;

	/*
	 * See if we can simplify the op. Move the cast down.
	 */
	switch (old->type) {
	case EXPR_PREOP:
		if (old->ctype->bit_size < type->bit_size)
			break;
		if (old->op == '~') {
			old->ctype = type;
			old->unop = cast_to(old->unop, type);
			return old;
		}
		break;

	case EXPR_IMPLIED_CAST:
		warn_for_different_enum_types(old->pos, old->ctype, type);

		if (old->ctype->bit_size >= type->bit_size) {
			struct expression *orig = old->cast_expression;
			if (same_cast_type(orig->ctype, type))
				return orig;
			if (old->ctype->bit_offset == type->bit_offset) {
				old->ctype = type;
				old->cast_type = type;
				return old;
			}
		}
		break;

	default:
		/* nothing */;
	}

	expr = alloc_expression(old->pos, EXPR_IMPLIED_CAST);
	expr->ctype = type;
	expr->cast_type = type;
	expr->cast_expression = old;
	expr->flags = cast_flags(expr, old);

	if (is_bool_type(type))
		cast_to_bool(expr);

	return expr;
}

enum {
	TYPE_NUM = 1,
	TYPE_BITFIELD = 2,
	TYPE_RESTRICT = 4,
	TYPE_FLOAT = 8,
	TYPE_PTR = 16,
	TYPE_COMPOUND = 32,
	TYPE_FOULED = 64,
	TYPE_FN = 128,
};

static inline int classify_type(struct symbol *type, struct symbol **base)
{
	static int type_class[SYM_BAD + 1] = {
		[SYM_PTR] = TYPE_PTR,
		[SYM_FN] = TYPE_PTR | TYPE_FN,
		[SYM_ARRAY] = TYPE_PTR | TYPE_COMPOUND,
		[SYM_STRUCT] = TYPE_COMPOUND,
		[SYM_UNION] = TYPE_COMPOUND,
		[SYM_BITFIELD] = TYPE_NUM | TYPE_BITFIELD,
		[SYM_RESTRICT] = TYPE_NUM | TYPE_RESTRICT,
		[SYM_FOULED] = TYPE_NUM | TYPE_RESTRICT | TYPE_FOULED,
	};
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	if (type->type == SYM_TYPEOF) {
		type = evaluate_expression(type->initializer);
		if (!type)
			type = &bad_ctype;
		else if (type->type == SYM_NODE)
			type = type->ctype.base_type;
	}
	if (type->type == SYM_ENUM)
		type = type->ctype.base_type;
	*base = type;
	if (type->type == SYM_BASETYPE) {
		if (type->ctype.base_type == &int_type)
			return TYPE_NUM;
		if (type->ctype.base_type == &fp_type)
			return TYPE_NUM | TYPE_FLOAT;
	}
	return type_class[type->type];
}

#define is_int(class) ((class & (TYPE_NUM | TYPE_FLOAT)) == TYPE_NUM)

static inline int is_string_type(struct symbol *type)
{
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	return type->type == SYM_ARRAY && is_byte_type(type->ctype.base_type);
}

static struct symbol *bad_expr_type(struct expression *expr)
{
	switch (expr->type) {
	case EXPR_BINOP:
	case EXPR_COMPARE:
		if (!valid_subexpr_type(expr))
			break;
		sparse_error(expr->pos, "incompatible types for operation (%s)", show_special(expr->op));
		info(expr->pos, "   left side has type %s", show_typename(expr->left->ctype));
		info(expr->pos, "   right side has type %s", show_typename(expr->right->ctype));
		break;
	case EXPR_PREOP:
	case EXPR_POSTOP:
		if (!valid_expr_type(expr->unop))
			break;
		sparse_error(expr->pos, "incompatible types for operation (%s)", show_special(expr->op));
		info(expr->pos, "   argument has type %s", show_typename(expr->unop->ctype));
		break;
	default:
		break;
	}

	expr->flags = CEF_NONE;
	return expr->ctype = &bad_ctype;
}

static int restricted_value(struct expression *v, struct symbol *type)
{
	if (v->type != EXPR_VALUE)
		return 1;
	if (v->value != 0)
		return 1;
	return 0;
}

static int restricted_binop(int op, struct symbol *type)
{
	switch (op) {
		case '&':
		case '=':
		case SPECIAL_AND_ASSIGN:
		case SPECIAL_OR_ASSIGN:
		case SPECIAL_XOR_ASSIGN:
			return 1;	/* unfoul */
		case '|':
		case '^':
		case '?':
			return 2;	/* keep fouled */
		case SPECIAL_EQUAL:
		case SPECIAL_NOTEQUAL:
			return 3;	/* warn if fouled */
		default:
			return 0;	/* warn */
	}
}

static int restricted_unop(int op, struct symbol **type)
{
	if (op == '~') {
		if ((*type)->bit_size < bits_in_int)
			*type = befoul(*type);
		return 0;
	} if (op == '+')
		return 0;
	return 1;
}

/* type should be SYM_FOULED */
static inline struct symbol *unfoul(struct symbol *type)
{
	return type->ctype.base_type;
}

static struct symbol *restricted_binop_type(int op,
					struct expression *left,
					struct expression *right,
					int lclass, int rclass,
					struct symbol *ltype,
					struct symbol *rtype)
{
	struct symbol *ctype = NULL;
	if (lclass & TYPE_RESTRICT) {
		if (rclass & TYPE_RESTRICT) {
			if (ltype == rtype) {
				ctype = ltype;
			} else if (lclass & TYPE_FOULED) {
				if (unfoul(ltype) == rtype)
					ctype = ltype;
			} else if (rclass & TYPE_FOULED) {
				if (unfoul(rtype) == ltype)
					ctype = rtype;
			}
		} else {
			if (!restricted_value(right, ltype))
				ctype = ltype;
		}
	} else if (!restricted_value(left, rtype))
		ctype = rtype;

	if (ctype) {
		switch (restricted_binop(op, ctype)) {
		case 1:
			if ((lclass ^ rclass) & TYPE_FOULED)
				ctype = unfoul(ctype);
			break;
		case 3:
			if (!(lclass & rclass & TYPE_FOULED))
				break;
		case 0:
			ctype = NULL;
		default:
			break;
		}
	}

	return ctype;
}

static inline void unrestrict(struct expression *expr,
			      int class, struct symbol **ctype)
{
	if (class & TYPE_RESTRICT) {
		if (class & TYPE_FOULED)
			*ctype = unfoul(*ctype);
		warning(expr->pos, "%s degrades to integer",
			show_typename(*ctype));
		*ctype = (*ctype)->ctype.base_type; /* get to arithmetic type */
	}
}

static struct symbol *usual_conversions(int op,
					struct expression *left,
					struct expression *right,
					int lclass, int rclass,
					struct symbol *ltype,
					struct symbol *rtype)
{
	struct symbol *ctype;

	warn_for_different_enum_types(right->pos, left->ctype, right->ctype);

	if ((lclass | rclass) & TYPE_RESTRICT)
		goto Restr;

Normal:
	if (!(lclass & TYPE_FLOAT)) {
		if (!(rclass & TYPE_FLOAT))
			return bigger_int_type(ltype, rtype);
		else
			return rtype;
	} else if (rclass & TYPE_FLOAT) {
		unsigned long lmod = ltype->ctype.modifiers;
		unsigned long rmod = rtype->ctype.modifiers;
		if (rmod & ~lmod & (MOD_LONG_ALL))
			return rtype;
		else
			return ltype;
	} else
		return ltype;

Restr:
	ctype = restricted_binop_type(op, left, right,
				      lclass, rclass, ltype, rtype);
	if (ctype)
		return ctype;

	unrestrict(left, lclass, &ltype);
	unrestrict(right, rclass, &rtype);

	goto Normal;
}

static inline int lvalue_expression(struct expression *expr)
{
	return expr->type == EXPR_PREOP && expr->op == '*';
}

static struct symbol *evaluate_ptr_add(struct expression *expr, struct symbol *itype)
{
	struct expression *index = expr->right;
	struct symbol *ctype, *base;
	int multiply;

	classify_type(degenerate(expr->left), &ctype);
	base = examine_pointer_target(ctype);

	/*
	 * An address constant +/- an integer constant expression
	 * yields an address constant again [6.6(7)].
	 */
	if ((expr->left->flags & CEF_ADDR) && (expr->right->flags & CEF_ICE))
		expr->flags = CEF_ADDR;

	if (!base) {
		expression_error(expr, "missing type information");
		return NULL;
	}
	if (is_function(base)) {
		expression_error(expr, "arithmetics on pointers to functions");
		return NULL;
	}

	/* Get the size of whatever the pointer points to */
	multiply = is_void_type(base) ? 1 : bits_to_bytes(base->bit_size);

	if (ctype == &null_ctype)
		ctype = &ptr_ctype;
	expr->ctype = ctype;

	if (multiply == 1 && itype->bit_size >= bits_in_pointer)
		return ctype;

	if (index->type == EXPR_VALUE) {
		struct expression *val = alloc_expression(expr->pos, EXPR_VALUE);
		unsigned long long v = index->value, mask;
		mask = 1ULL << (itype->bit_size - 1);
		if (v & mask)
			v |= -mask;
		else
			v &= mask - 1;
		v *= multiply;
		mask = 1ULL << (bits_in_pointer - 1);
		v &= mask | (mask - 1);
		val->value = v;
		val->ctype = ssize_t_ctype;
		expr->right = val;
		return ctype;
	}

	if (itype->bit_size < bits_in_pointer)
		index = cast_to(index, ssize_t_ctype);

	if (multiply > 1) {
		struct expression *val = alloc_expression(expr->pos, EXPR_VALUE);
		struct expression *mul = alloc_expression(expr->pos, EXPR_BINOP);

		val->ctype = ssize_t_ctype;
		val->value = multiply;

		mul->op = '*';
		mul->ctype = ssize_t_ctype;
		mul->left = index;
		mul->right = val;
		index = mul;
	}

	expr->right = index;
	return ctype;
}

static void examine_fn_arguments(struct symbol *fn);

#define MOD_IGN (MOD_QUALIFIER | MOD_PURE)

const char *type_difference(struct ctype *c1, struct ctype *c2,
	unsigned long mod1, unsigned long mod2)
{
	struct ident *as1 = c1->as, *as2 = c2->as;
	struct symbol *t1 = c1->base_type;
	struct symbol *t2 = c2->base_type;
	int move1 = 1, move2 = 1;
	mod1 |= c1->modifiers;
	mod2 |= c2->modifiers;
	for (;;) {
		unsigned long diff;
		int type;
		struct symbol *base1 = t1->ctype.base_type;
		struct symbol *base2 = t2->ctype.base_type;

		/*
		 * FIXME! Collect alignment and context too here!
		 */
		if (move1) {
			if (t1 && t1->type != SYM_PTR) {
				mod1 |= t1->ctype.modifiers;
				combine_address_space(t1->pos, &as1, t1->ctype.as);
			}
			move1 = 0;
		}

		if (move2) {
			if (t2 && t2->type != SYM_PTR) {
				mod2 |= t2->ctype.modifiers;
				combine_address_space(t2->pos, &as2, t2->ctype.as);
			}
			move2 = 0;
		}

		if (t1 == t2)
			break;
		if (!t1 || !t2)
			return "different types";

		if (t1->type == SYM_NODE || t1->type == SYM_ENUM) {
			t1 = base1;
			move1 = 1;
			if (!t1)
				return "bad types";
			continue;
		}

		if (t2->type == SYM_NODE || t2->type == SYM_ENUM) {
			t2 = base2;
			move2 = 1;
			if (!t2)
				return "bad types";
			continue;
		}

		move1 = move2 = 1;
		type = t1->type;
		if (type != t2->type)
			return "different base types";

		switch (type) {
		default:
			sparse_error(t1->pos,
				     "internal error: bad type in derived(%d)",
				     type);
			return "bad types";
		case SYM_RESTRICT:
			return "different base types";
		case SYM_UNION:
		case SYM_STRUCT:
			/* allow definition of incomplete structs and unions */
			if (t1->ident == t2->ident)
			  return NULL;
			return "different base types";
		case SYM_ARRAY:
			/* XXX: we ought to compare sizes */
			break;
		case SYM_PTR:
			if (as1 != as2)
				return "different address spaces";
			/* MOD_SPECIFIER is due to idiocy in parse.c */
			if ((mod1 ^ mod2) & ~MOD_IGNORE & ~MOD_SPECIFIER)
				return "different modifiers";
			/* we could be lazier here */
			base1 = examine_pointer_target(t1);
			base2 = examine_pointer_target(t2);
			mod1 = t1->ctype.modifiers;
			as1 = t1->ctype.as;
			mod2 = t2->ctype.modifiers;
			as2 = t2->ctype.as;
			break;
		case SYM_FN: {
			struct symbol *arg1, *arg2;
			int i;

			if (as1 != as2)
				return "different address spaces";
			if ((mod1 ^ mod2) & ~MOD_IGNORE & ~MOD_SIGNEDNESS)
				return "different modifiers";
			mod1 = t1->ctype.modifiers;
			as1 = t1->ctype.as;
			mod2 = t2->ctype.modifiers;
			as2 = t2->ctype.as;

			if (t1->variadic != t2->variadic)
				return "incompatible variadic arguments";
			examine_fn_arguments(t1);
			examine_fn_arguments(t2);
			PREPARE_PTR_LIST(t1->arguments, arg1);
			PREPARE_PTR_LIST(t2->arguments, arg2);
			i = 1;
			for (;;) {
				const char *diffstr;
				if (!arg1 && !arg2)
					break;
				if (!arg1 || !arg2)
					return "different argument counts";
				diffstr = type_difference(&arg1->ctype,
							  &arg2->ctype,
							  MOD_IGN, MOD_IGN);
				if (diffstr) {
					static char argdiff[80];
					sprintf(argdiff, "incompatible argument %d (%s)", i, diffstr);
					return argdiff;
				}
				NEXT_PTR_LIST(arg1);
				NEXT_PTR_LIST(arg2);
				i++;
			}
			FINISH_PTR_LIST(arg2);
			FINISH_PTR_LIST(arg1);
			break;
		}
		case SYM_BASETYPE:
			if (as1 != as2)
				return "different address spaces";
			if (base1 != base2)
				return "different base types";
			diff = (mod1 ^ mod2) & ~MOD_IGNORE;
			if (!diff)
				return NULL;
			if (diff & MOD_SIZE)
				return "different type sizes";
			else if (diff & ~MOD_SIGNEDNESS)
				return "different modifiers";
			else
				return "different signedness";
		}
		t1 = base1;
		t2 = base2;
	}
	if (as1 != as2)
		return "different address spaces";
	if ((mod1 ^ mod2) & ~MOD_IGNORE & ~MOD_SIGNEDNESS)
		return "different modifiers";
	return NULL;
}

static void bad_null(struct expression *expr)
{
	if (Wnon_pointer_null)
		warning(expr->pos, "Using plain integer as NULL pointer");
}

static unsigned long target_qualifiers(struct symbol *type)
{
	unsigned long mod = type->ctype.modifiers & MOD_IGN;
	if (type->ctype.base_type && type->ctype.base_type->type == SYM_ARRAY)
		mod = 0;
	return mod;
}

static struct symbol *evaluate_ptr_sub(struct expression *expr)
{
	const char *typediff;
	struct symbol *ltype, *rtype;
	struct expression *l = expr->left;
	struct expression *r = expr->right;
	struct symbol *lbase;

	classify_type(degenerate(l), &ltype);
	classify_type(degenerate(r), &rtype);

	lbase = examine_pointer_target(ltype);
	examine_pointer_target(rtype);
	typediff = type_difference(&ltype->ctype, &rtype->ctype,
				   target_qualifiers(rtype),
				   target_qualifiers(ltype));
	if (typediff)
		expression_error(expr, "subtraction of different types can't work (%s)", typediff);

	if (is_function(lbase)) {
		expression_error(expr, "subtraction of functions? Share your drugs");
		return NULL;
	}

	expr->ctype = ssize_t_ctype;
	if (lbase->bit_size > bits_in_char) {
		struct expression *sub = alloc_expression(expr->pos, EXPR_BINOP);
		struct expression *div = expr;
		struct expression *val = alloc_expression(expr->pos, EXPR_VALUE);
		unsigned long value = bits_to_bytes(lbase->bit_size);

		val->ctype = size_t_ctype;
		val->value = value;

		if (value & (value-1)) {
			if (Wptr_subtraction_blows) {
				warning(expr->pos, "potentially expensive pointer subtraction");
				info(expr->pos, "    '%s' has a non-power-of-2 size: %lu", show_typename(lbase), value);
			}
		}

		sub->op = '-';
		sub->ctype = ssize_t_ctype;
		sub->left = l;
		sub->right = r;

		div->op = '/';
		div->left = sub;
		div->right = val;
	}
		
	return ssize_t_ctype;
}

#define is_safe_type(type) ((type)->ctype.modifiers & MOD_SAFE)

static struct symbol *evaluate_conditional(struct expression *expr, int iterator)
{
	struct symbol *ctype;

	if (!expr)
		return NULL;

	if (!iterator && expr->type == EXPR_ASSIGNMENT && expr->op == '=')
		warning(expr->pos, "assignment expression in conditional");

	ctype = evaluate_expression(expr);
	if (!valid_type(ctype))
		return NULL;
	if (is_safe_type(ctype))
		warning(expr->pos, "testing a 'safe expression'");
	if (is_func_type(ctype)) {
		if (Waddress)
			warning(expr->pos, "the address of %s will always evaluate as true", "a function");
	} else if (is_array_type(ctype)) {
		if (Waddress)
			warning(expr->pos, "the address of %s will always evaluate as true", "an array");
	} else if (!is_scalar_type(ctype)) {
		sparse_error(expr->pos, "incorrect type in conditional (non-scalar type)");
		info(expr->pos, "   got %s", show_typename(ctype));
		return NULL;
	}

	ctype = degenerate(expr);
	return ctype;
}

static struct symbol *evaluate_logical(struct expression *expr)
{
	if (!evaluate_conditional(expr->left, 0))
		return NULL;
	if (!evaluate_conditional(expr->right, 0))
		return NULL;

	/* the result is int [6.5.13(3), 6.5.14(3)] */
	expr->ctype = &int_ctype;
	expr->flags = expr->left->flags & expr->right->flags;
	expr->flags &= ~(CEF_CONST_MASK | CEF_ADDR);
	return &int_ctype;
}

static struct symbol *evaluate_binop(struct expression *expr)
{
	struct symbol *ltype, *rtype, *ctype;
	int lclass = classify_type(expr->left->ctype, &ltype);
	int rclass = classify_type(expr->right->ctype, &rtype);
	int op = expr->op;

	/* number op number */
	if (lclass & rclass & TYPE_NUM) {
		expr->flags = expr->left->flags & expr->right->flags;
		expr->flags &= ~CEF_CONST_MASK;

		if ((lclass | rclass) & TYPE_FLOAT) {
			switch (op) {
			case '+': case '-': case '*': case '/':
				break;
			default:
				return bad_expr_type(expr);
			}
		}

		if (op == SPECIAL_LEFTSHIFT || op == SPECIAL_RIGHTSHIFT) {
			// shifts do integer promotions, but that's it.
			unrestrict(expr->left, lclass, &ltype);
			unrestrict(expr->right, rclass, &rtype);
			ctype = ltype = integer_promotion(ltype);
			rtype = integer_promotion(rtype);
		} else {
			// The rest do usual conversions
			const unsigned left_not  = expr->left->type == EXPR_PREOP
			                           && expr->left->op == '!';
			const unsigned right_not = expr->right->type == EXPR_PREOP
			                           && expr->right->op == '!';
			if ((op == '&' || op == '|') && (left_not || right_not))
				warning(expr->pos, "dubious: %sx %c %sy",
				        left_not ? "!" : "",
					op,
					right_not ? "!" : "");

			ltype = usual_conversions(op, expr->left, expr->right,
						  lclass, rclass, ltype, rtype);
			ctype = rtype = ltype;
		}

		expr->left = cast_to(expr->left, ltype);
		expr->right = cast_to(expr->right, rtype);
		expr->ctype = ctype;
		return ctype;
	}

	/* pointer (+|-) integer */
	if (lclass & TYPE_PTR && is_int(rclass) && (op == '+' || op == '-')) {
		unrestrict(expr->right, rclass, &rtype);
		return evaluate_ptr_add(expr, rtype);
	}

	/* integer + pointer */
	if (rclass & TYPE_PTR && is_int(lclass) && op == '+') {
		struct expression *index = expr->left;
		unrestrict(index, lclass, &ltype);
		expr->left = expr->right;
		expr->right = index;
		return evaluate_ptr_add(expr, ltype);
	}

	/* pointer - pointer */
	if (lclass & rclass & TYPE_PTR && expr->op == '-')
		return evaluate_ptr_sub(expr);

	return bad_expr_type(expr);
}

static struct symbol *evaluate_comma(struct expression *expr)
{
	expr->ctype = degenerate(expr->right);
	if (expr->ctype == &null_ctype)
		expr->ctype = &ptr_ctype;
	expr->flags &= expr->left->flags & expr->right->flags;
	return expr->ctype;
}

static int modify_for_unsigned(int op)
{
	if (op == '<')
		op = SPECIAL_UNSIGNED_LT;
	else if (op == '>')
		op = SPECIAL_UNSIGNED_GT;
	else if (op == SPECIAL_LTE)
		op = SPECIAL_UNSIGNED_LTE;
	else if (op == SPECIAL_GTE)
		op = SPECIAL_UNSIGNED_GTE;
	return op;
}

enum null_constant_type {
	NON_NULL,
	NULL_PTR,
	NULL_ZERO,
};

static inline int is_null_pointer_constant(struct expression *e)
{
	if (e->ctype == &null_ctype)
		return NULL_PTR;
	if (!(e->flags & CEF_ICE))
		return NON_NULL;
	return is_zero_constant(e) ? NULL_ZERO : NON_NULL;
}

static struct symbol *evaluate_compare(struct expression *expr)
{
	struct expression *left = expr->left, *right = expr->right;
	struct symbol *ltype, *rtype, *lbase, *rbase;
	int lclass = classify_type(degenerate(left), &ltype);
	int rclass = classify_type(degenerate(right), &rtype);
	struct symbol *ctype;
	const char *typediff;

	/* Type types? */
	if (is_type_type(ltype) && is_type_type(rtype)) {
		/*
		 * __builtin_types_compatible_p() yields an integer
		 * constant expression
		 */
		expr->flags = CEF_SET_ICE;
		goto OK;
	}

	if (is_safe_type(left->ctype) || is_safe_type(right->ctype))
		warning(expr->pos, "testing a 'safe expression'");

	expr->flags = left->flags & right->flags & ~CEF_CONST_MASK & ~CEF_ADDR;

	/* number on number */
	if (lclass & rclass & TYPE_NUM) {
		ctype = usual_conversions(expr->op, expr->left, expr->right,
					  lclass, rclass, ltype, rtype);
		expr->left = cast_to(expr->left, ctype);
		expr->right = cast_to(expr->right, ctype);
		if (ctype->ctype.modifiers & MOD_UNSIGNED)
			expr->op = modify_for_unsigned(expr->op);
		goto OK;
	}

	/* at least one must be a pointer */
	if (!((lclass | rclass) & TYPE_PTR))
		return bad_expr_type(expr);

	/* equality comparisons can be with null pointer constants */
	if (expr->op == SPECIAL_EQUAL || expr->op == SPECIAL_NOTEQUAL) {
		int is_null1 = is_null_pointer_constant(left);
		int is_null2 = is_null_pointer_constant(right);
		if (is_null1 == NULL_ZERO)
			bad_null(left);
		if (is_null2 == NULL_ZERO)
			bad_null(right);
		if (is_null1 && is_null2) {
			int positive = expr->op == SPECIAL_EQUAL;
			expr->type = EXPR_VALUE;
			expr->value = positive;
			goto OK;
		}
		if (is_null1 && (rclass & TYPE_PTR)) {
			left = cast_to(left, rtype);
			goto OK;
		}
		if (is_null2 && (lclass & TYPE_PTR)) {
			right = cast_to(right, ltype);
			goto OK;
		}
	}
	/* both should be pointers */
	if (!(lclass & rclass & TYPE_PTR))
		return bad_expr_type(expr);
	expr->op = modify_for_unsigned(expr->op);

	lbase = examine_pointer_target(ltype);
	rbase = examine_pointer_target(rtype);

	/* they also have special treatment for pointers to void */
	if (expr->op == SPECIAL_EQUAL || expr->op == SPECIAL_NOTEQUAL) {
		if (ltype->ctype.as == rtype->ctype.as) {
			if (lbase == &void_ctype) {
				right = cast_to(right, ltype);
				goto OK;
			}
			if (rbase == &void_ctype) {
				left = cast_to(left, rtype);
				goto OK;
			}
		}
	}

	typediff = type_difference(&ltype->ctype, &rtype->ctype,
				   target_qualifiers(rtype),
				   target_qualifiers(ltype));
	if (!typediff)
		goto OK;

	expression_error(expr, "incompatible types in comparison expression (%s):", typediff);
	info(expr->pos, "   %s", show_typename(ltype));
	info(expr->pos, "   %s", show_typename(rtype));
	return NULL;

OK:
	/* the result is int [6.5.8(6), 6.5.9(3)]*/
	expr->ctype = &int_ctype;
	return &int_ctype;
}

/*
 * NOTE! The degenerate case of "x ? : y", where we don't
 * have a true case, this will possibly promote "x" to the
 * same type as "y", and thus _change_ the conditional
 * test in the expression. But since promotion is "safe"
 * for testing, that's OK.
 */
static struct symbol *evaluate_conditional_expression(struct expression *expr)
{
	struct expression **cond;
	struct symbol *ctype, *ltype, *rtype, *lbase, *rbase;
	int lclass, rclass;
	const char * typediff;
	int qual;

	if (!evaluate_conditional(expr->conditional, 0))
		return NULL;
	if (!evaluate_expression(expr->cond_false))
		return NULL;

	ctype = degenerate(expr->conditional);
	rtype = degenerate(expr->cond_false);

	cond = &expr->conditional;
	ltype = ctype;
	if (expr->cond_true) {
		if (!evaluate_expression(expr->cond_true))
			return NULL;
		ltype = degenerate(expr->cond_true);
		cond = &expr->cond_true;
	}

	expr->flags = (expr->conditional->flags & (*cond)->flags &
			expr->cond_false->flags & ~CEF_CONST_MASK);
	/*
	 * A conditional operator yields a particular constant
	 * expression type only if all of its three subexpressions are
	 * of that type [6.6(6), 6.6(8)].
	 * As an extension, relax this restriction by allowing any
	 * constant expression type for the condition expression.
	 *
	 * A conditional operator never yields an address constant
	 * [6.6(9)].
	 * However, as an extension, if the condition is any constant
	 * expression, and the true and false expressions are both
	 * address constants, mark the result as an address constant.
	 */
	if (expr->conditional->flags & (CEF_ACE | CEF_ADDR))
		expr->flags = (*cond)->flags & expr->cond_false->flags & ~CEF_CONST_MASK;

	lclass = classify_type(ltype, &ltype);
	rclass = classify_type(rtype, &rtype);
	if (lclass & rclass & TYPE_NUM) {
		ctype = usual_conversions('?', *cond, expr->cond_false,
					  lclass, rclass, ltype, rtype);
		*cond = cast_to(*cond, ctype);
		expr->cond_false = cast_to(expr->cond_false, ctype);
		goto out;
	}

	if ((lclass | rclass) & TYPE_PTR) {
		int is_null1 = is_null_pointer_constant(*cond);
		int is_null2 = is_null_pointer_constant(expr->cond_false);

		if (is_null1 && is_null2) {
			*cond = cast_to(*cond, &ptr_ctype);
			expr->cond_false = cast_to(expr->cond_false, &ptr_ctype);
			ctype = &ptr_ctype;
			goto out;
		}
		if (is_null1 && (rclass & TYPE_PTR)) {
			if (is_null1 == NULL_ZERO)
				bad_null(*cond);
			*cond = cast_to(*cond, rtype);
			ctype = rtype;
			goto out;
		}
		if (is_null2 && (lclass & TYPE_PTR)) {
			if (is_null2 == NULL_ZERO)
				bad_null(expr->cond_false);
			expr->cond_false = cast_to(expr->cond_false, ltype);
			ctype = ltype;
			goto out;
		}
		if (!(lclass & rclass & TYPE_PTR)) {
			typediff = "different types";
			goto Err;
		}
		/* OK, it's pointer on pointer */
		if (ltype->ctype.as != rtype->ctype.as) {
			typediff = "different address spaces";
			goto Err;
		}

		/* need to be lazier here */
		lbase = examine_pointer_target(ltype);
		rbase = examine_pointer_target(rtype);
		qual = target_qualifiers(ltype) | target_qualifiers(rtype);

		if (lbase == &void_ctype) {
			/* XXX: pointers to function should warn here */
			ctype = ltype;
			goto Qual;

		}
		if (rbase == &void_ctype) {
			/* XXX: pointers to function should warn here */
			ctype = rtype;
			goto Qual;
		}
		/* XXX: that should be pointer to composite */
		ctype = ltype;
		typediff = type_difference(&ltype->ctype, &rtype->ctype,
					   qual, qual);
		if (!typediff)
			goto Qual;
		goto Err;
	}

	/* void on void, struct on same struct, union on same union */
	if (ltype == rtype) {
		ctype = ltype;
		goto out;
	}
	typediff = "different base types";

Err:
	expression_error(expr, "incompatible types in conditional expression (%s):", typediff);
	info(expr->pos, "   %s", show_typename(ltype));
	info(expr->pos, "   %s", show_typename(rtype));
	/*
	 * if the condition is constant, the type is in fact known
	 * so use it, as gcc & clang do.
	 */
	switch (expr_truth_value(expr->conditional)) {
	case 1:	expr->ctype = ltype;
		break;
	case 0: expr->ctype = rtype;
		break;
	default:
		break;
	}
	return NULL;

out:
	expr->ctype = ctype;
	return ctype;

Qual:
	if (qual & ~ctype->ctype.modifiers) {
		struct symbol *sym = alloc_symbol(ctype->pos, SYM_PTR);
		*sym = *ctype;
		sym->ctype.modifiers |= qual;
		ctype = sym;
	}
	*cond = cast_to(*cond, ctype);
	expr->cond_false = cast_to(expr->cond_false, ctype);
	goto out;
}

/* FP assignments can not do modulo or bit operations */
static int compatible_float_op(int op)
{
	return	op == SPECIAL_ADD_ASSIGN ||
		op == SPECIAL_SUB_ASSIGN ||
		op == SPECIAL_MUL_ASSIGN ||
		op == SPECIAL_DIV_ASSIGN;
}

static int evaluate_assign_op(struct expression *expr)
{
	struct symbol *target = expr->left->ctype;
	struct symbol *source = expr->right->ctype;
	struct symbol *t, *s;
	int tclass = classify_type(target, &t);
	int sclass = classify_type(source, &s);
	int op = expr->op;

	if (tclass & sclass & TYPE_NUM) {
		if (tclass & TYPE_FLOAT && !compatible_float_op(op)) {
			expression_error(expr, "invalid assignment");
			return 0;
		}
		if (tclass & TYPE_RESTRICT) {
			if (!restricted_binop(op, t)) {
				warning(expr->pos, "bad assignment (%s) to %s",
					show_special(op), show_typename(t));
				expr->right = cast_to(expr->right, target);
				return 0;
			}
			/* allowed assignments unfoul */
			if (sclass & TYPE_FOULED && unfoul(s) == t)
				goto Cast;
			if (!restricted_value(expr->right, t))
				return 1;
		} else if (op == SPECIAL_SHR_ASSIGN || op == SPECIAL_SHL_ASSIGN) {
			// shifts do integer promotions, but that's it.
			unrestrict(expr->right, sclass, &s);
			target = integer_promotion(s);
			goto Cast;
		} else if (!(sclass & TYPE_RESTRICT))
			goto usual;
		/* source and target would better be identical restricted */
		if (t == s)
			return 1;
		warning(expr->pos, "invalid assignment: %s", show_special(op));
		info(expr->pos, "   left side has type %s", show_typename(t));
		info(expr->pos, "   right side has type %s", show_typename(s));
		expr->right = cast_to(expr->right, target);
		return 0;
	}
	if (tclass == TYPE_PTR && is_int(sclass)) {
		if (op == SPECIAL_ADD_ASSIGN || op == SPECIAL_SUB_ASSIGN) {
			unrestrict(expr->right, sclass, &s);
			evaluate_ptr_add(expr, s);
			return 1;
		}
		expression_error(expr, "invalid pointer assignment");
		return 0;
	}

	expression_error(expr, "invalid assignment");
	return 0;

usual:
	target = usual_conversions(op, expr->left, expr->right,
				tclass, sclass, target, source);
Cast:
	expr->right = cast_to(expr->right, target);
	return 1;
}

static int whitelist_pointers(struct symbol *t1, struct symbol *t2)
{
	if (t1 == t2)
		return 0;	/* yes, 0 - we don't want a cast_to here */
	if (t1 == &void_ctype)
		return 1;
	if (t2 == &void_ctype)
		return 1;
	if (classify_type(t1, &t1) != TYPE_NUM)
		return 0;
	if (classify_type(t2, &t2) != TYPE_NUM)
		return 0;
	if (t1 == t2)
		return 1;
	if (t1->ctype.modifiers & t2->ctype.modifiers & MOD_CHAR)
		return 1;
	if ((t1->ctype.modifiers ^ t2->ctype.modifiers) & MOD_SIZE)
		return 0;
	return !Wtypesign;
}

static int check_assignment_types(struct symbol *target, struct expression **rp,
	const char **typediff)
{
	struct symbol *source = degenerate(*rp);
	struct symbol *t, *s;
	int tclass = classify_type(target, &t);
	int sclass = classify_type(source, &s);

	if (tclass & sclass & TYPE_NUM) {
		if (tclass & TYPE_RESTRICT) {
			/* allowed assignments unfoul */
			if (sclass & TYPE_FOULED && unfoul(s) == t)
				goto Cast;
			if (!restricted_value(*rp, target))
				return 1;
			if (s == t)
				return 1;
		} else if (!(sclass & TYPE_RESTRICT))
			goto Cast;
                if (t == &bool_ctype) {
                        if (is_fouled_type(s))
                                warning((*rp)->pos, "%s degrades to integer",
                                        show_typename(s->ctype.base_type));
                        goto Cast;
                }
		*typediff = "different base types";
		return 0;
	}

	if (tclass == TYPE_PTR) {
		unsigned long mod1, mod2;
		struct symbol *b1, *b2;
		// NULL pointer is always OK
		int is_null = is_null_pointer_constant(*rp);
		if (is_null) {
			if (is_null == NULL_ZERO)
				bad_null(*rp);
			goto Cast;
		}
		if (!(sclass & TYPE_PTR)) {
			*typediff = "different base types";
			return 0;
		}
		b1 = examine_pointer_target(t);
		b2 = examine_pointer_target(s);
		mod1 = target_qualifiers(t);
		mod2 = target_qualifiers(s);
		if (whitelist_pointers(b1, b2)) {
			/*
			 * assignments to/from void * are OK, provided that
			 * we do not remove qualifiers from pointed to [C]
			 * or mix address spaces [sparse].
			 */
			if (t->ctype.as != s->ctype.as) {
				*typediff = "different address spaces";
				return 0;
			}
			/*
			 * If this is a function pointer assignment, it is
			 * actually fine to assign a pointer to const data to
			 * it, as a function pointer points to const data
			 * implicitly, i.e., dereferencing it does not produce
			 * an lvalue.
			 */
			if (b1->type == SYM_FN)
				mod1 |= MOD_CONST;
			if (mod2 & ~mod1) {
				*typediff = "different modifiers";
				return 0;
			}
			goto Cast;
		}
		/* It's OK if the target is more volatile or const than the source */
		*typediff = type_difference(&t->ctype, &s->ctype, 0, mod1);
		if (*typediff)
			return 0;
		return 1;
	}

	if ((tclass & TYPE_COMPOUND) && s == t)
		return 1;

	if (tclass & TYPE_NUM) {
		/* XXX: need to turn into comparison with NULL */
		if (t == &bool_ctype && (sclass & TYPE_PTR))
			goto Cast;
		*typediff = "different base types";
		return 0;
	}
	*typediff = "invalid types";
	return 0;

Cast:
	*rp = cast_to(*rp, target);
	return 1;
}

static int compatible_assignment_types(struct expression *expr, struct symbol *target,
	struct expression **rp, const char *where)
{
	const char *typediff;
	struct symbol *source = degenerate(*rp);

	if (!check_assignment_types(target, rp, &typediff)) {
		warning(expr->pos, "incorrect type in %s (%s)", where, typediff);
		info(expr->pos, "   expected %s", show_typename(target));
		info(expr->pos, "   got %s", show_typename(source));
		*rp = cast_to(*rp, target);
		return 0;
	}

	return 1;
}

static int compatible_transparent_union(struct symbol *target,
	struct expression **rp)
{
	struct symbol *t, *member;
	classify_type(target, &t);
	if (t->type != SYM_UNION || !t->transparent_union)
		return 0;

	FOR_EACH_PTR(t->symbol_list, member) {
		const char *typediff;
		if (check_assignment_types(member, rp, &typediff))
			return 1;
	} END_FOR_EACH_PTR(member);

	return 0;
}

static int compatible_argument_type(struct expression *expr, struct symbol *target,
	struct expression **rp, const char *where)
{
	if (compatible_transparent_union(target, rp))
		return 1;

	return compatible_assignment_types(expr, target, rp, where);
}

static void mark_assigned(struct expression *expr)
{
	struct symbol *sym;

	if (!expr)
		return;
	switch (expr->type) {
	case EXPR_SYMBOL:
		sym = expr->symbol;
		if (!sym)
			return;
		if (sym->type != SYM_NODE)
			return;
		sym->ctype.modifiers |= MOD_ASSIGNED;
		return;

	case EXPR_BINOP:
		mark_assigned(expr->left);
		mark_assigned(expr->right);
		return;
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
		mark_assigned(expr->cast_expression);
		return;
	case EXPR_SLICE:
		mark_assigned(expr->base);
		return;
	default:
		/* Hmm? */
		return;
	}
}

static void evaluate_assign_to(struct expression *left, struct symbol *type)
{
	if (type->ctype.modifiers & MOD_CONST)
		expression_error(left, "assignment to const expression");

	/* We know left is an lvalue, so it's a "preop-*" */
	mark_assigned(left->unop);
}

static struct symbol *evaluate_assignment(struct expression *expr)
{
	struct expression *left = expr->left;
	struct symbol *ltype;

	if (!lvalue_expression(left)) {
		expression_error(expr, "not an lvalue");
		return NULL;
	}

	ltype = left->ctype;

	if (expr->op != '=') {
		if (!evaluate_assign_op(expr))
			return NULL;
	} else {
		if (!compatible_assignment_types(expr, ltype, &expr->right, "assignment"))
			return NULL;
	}

	evaluate_assign_to(left, ltype);

	expr->ctype = ltype;
	return ltype;
}

static void examine_fn_arguments(struct symbol *fn)
{
	struct symbol *s;

	FOR_EACH_PTR(fn->arguments, s) {
		struct symbol *arg = evaluate_symbol(s);
		/* Array/function arguments silently degenerate into pointers */
		if (arg) {
			struct symbol *ptr;
			switch(arg->type) {
			case SYM_ARRAY:
			case SYM_FN:
				ptr = alloc_symbol(s->pos, SYM_PTR);
				if (arg->type == SYM_ARRAY)
					ptr->ctype = arg->ctype;
				else
					ptr->ctype.base_type = arg;
				combine_address_space(s->pos, &ptr->ctype.as, s->ctype.as);
				ptr->ctype.modifiers |= s->ctype.modifiers & MOD_PTRINHERIT;

				s->ctype.base_type = ptr;
				s->ctype.as = NULL;
				s->ctype.modifiers &= ~MOD_PTRINHERIT;
				s->bit_size = 0;
				s->examined = 0;
				examine_symbol_type(s);
				break;
			default:
				/* nothing */
				break;
			}
		}
	} END_FOR_EACH_PTR(s);
}

static struct symbol *convert_to_as_mod(struct symbol *sym, struct ident *as, int mod)
{
	/* Take the modifiers of the pointer, and apply them to the member */
	mod |= sym->ctype.modifiers;
	if (sym->ctype.as != as || sym->ctype.modifiers != mod) {
		struct symbol *newsym = alloc_symbol(sym->pos, SYM_NODE);
		*newsym = *sym;
		newsym->ctype.as = as;
		newsym->ctype.modifiers = mod;
		sym = newsym;
	}
	return sym;
}

static struct symbol *create_pointer(struct expression *expr, struct symbol *sym, int degenerate)
{
	struct symbol *node = alloc_symbol(expr->pos, SYM_NODE);
	struct symbol *ptr = alloc_symbol(expr->pos, SYM_PTR);

	node->ctype.base_type = ptr;
	ptr->bit_size = bits_in_pointer;
	ptr->ctype.alignment = pointer_alignment;

	node->bit_size = bits_in_pointer;
	node->ctype.alignment = pointer_alignment;

	access_symbol(sym);
	if (sym->ctype.modifiers & MOD_REGISTER) {
		warning(expr->pos, "taking address of 'register' variable '%s'", show_ident(sym->ident));
		sym->ctype.modifiers &= ~MOD_REGISTER;
	}
	if (sym->type == SYM_NODE) {
		combine_address_space(sym->pos, &ptr->ctype.as, sym->ctype.as);
		ptr->ctype.modifiers |= sym->ctype.modifiers & MOD_PTRINHERIT;
		sym = sym->ctype.base_type;
	}
	if (degenerate && sym->type == SYM_ARRAY) {
		combine_address_space(sym->pos, &ptr->ctype.as, sym->ctype.as);
		ptr->ctype.modifiers |= sym->ctype.modifiers & MOD_PTRINHERIT;
		sym = sym->ctype.base_type;
	}
	ptr->ctype.base_type = sym;

	return node;
}

/* Arrays degenerate into pointers on pointer arithmetic */
static struct symbol *degenerate(struct expression *expr)
{
	struct symbol *ctype, *base;

	if (!expr)
		return NULL;
	ctype = expr->ctype;
	if (!ctype)
		return NULL;
	base = examine_symbol_type(ctype);
	if (ctype->type == SYM_NODE)
		base = ctype->ctype.base_type;
	/*
	 * Arrays degenerate into pointers to the entries, while
	 * functions degenerate into pointers to themselves.
	 * If array was part of non-lvalue compound, we create a copy
	 * of that compound first and then act as if we were dealing with
	 * the corresponding field in there.
	 */
	switch (base->type) {
	case SYM_ARRAY:
		if (expr->type == EXPR_SLICE) {
			struct symbol *a = alloc_symbol(expr->pos, SYM_NODE);
			struct expression *e0, *e1, *e2, *e3, *e4;

			a->ctype.base_type = expr->base->ctype;
			a->bit_size = expr->base->ctype->bit_size;
			a->array_size = expr->base->ctype->array_size;

			e0 = alloc_expression(expr->pos, EXPR_SYMBOL);
			e0->symbol = a;
			e0->ctype = &lazy_ptr_ctype;

			e1 = alloc_expression(expr->pos, EXPR_PREOP);
			e1->unop = e0;
			e1->op = '*';
			e1->ctype = expr->base->ctype;	/* XXX */

			e2 = alloc_expression(expr->pos, EXPR_ASSIGNMENT);
			e2->left = e1;
			e2->right = expr->base;
			e2->op = '=';
			e2->ctype = expr->base->ctype;

			if (expr->r_bitpos) {
				e3 = alloc_expression(expr->pos, EXPR_BINOP);
				e3->op = '+';
				e3->left = e0;
				e3->right = alloc_const_expression(expr->pos,
							bits_to_bytes(expr->r_bitpos));
				e3->ctype = &lazy_ptr_ctype;
			} else {
				e3 = e0;
			}

			e4 = alloc_expression(expr->pos, EXPR_COMMA);
			e4->left = e2;
			e4->right = e3;
			e4->ctype = &lazy_ptr_ctype;

			expr->unop = e4;
			expr->type = EXPR_PREOP;
			expr->op = '*';
		}
	case SYM_FN:
		if (expr->op != '*' || expr->type != EXPR_PREOP) {
			expression_error(expr, "strange non-value function or array");
			return &bad_ctype;
		}
		*expr = *expr->unop;
		ctype = create_pointer(expr, ctype, 1);
		expr->ctype = ctype;
	default:
		/* nothing */;
	}
	return ctype;
}

static struct symbol *evaluate_addressof(struct expression *expr)
{
	struct expression *op = expr->unop;
	struct symbol *ctype;

	if (op->op != '*' || op->type != EXPR_PREOP) {
		expression_error(expr, "not addressable");
		return NULL;
	}
	ctype = op->ctype;
	*expr = *op->unop;

	if (expr->type == EXPR_SYMBOL) {
		struct symbol *sym = expr->symbol;
		sym->ctype.modifiers |= MOD_ADDRESSABLE;
	}

	/*
	 * symbol expression evaluation is lazy about the type
	 * of the sub-expression, so we may have to generate
	 * the type here if so..
	 */
	if (expr->ctype == &lazy_ptr_ctype) {
		ctype = create_pointer(expr, ctype, 0);
		expr->ctype = ctype;
	}
	return expr->ctype;
}


static struct symbol *evaluate_dereference(struct expression *expr)
{
	struct expression *op = expr->unop;
	struct symbol *ctype = op->ctype, *node, *target;

	/* Simplify: *&(expr) => (expr) */
	if (op->type == EXPR_PREOP && op->op == '&') {
		*expr = *op->unop;
		expr->flags = CEF_NONE;
		return expr->ctype;
	}

	examine_symbol_type(ctype);

	/* Dereferencing a node drops all the node information. */
	if (ctype->type == SYM_NODE)
		ctype = ctype->ctype.base_type;

	target = ctype->ctype.base_type;
	examine_symbol_type(target);

	switch (ctype->type) {
	default:
		expression_error(expr, "cannot dereference this type");
		return NULL;
	case SYM_FN:
		*expr = *op;
		return expr->ctype;
	case SYM_PTR:
		node = alloc_symbol(expr->pos, SYM_NODE);
		node->ctype.modifiers = target->ctype.modifiers & MOD_SPECIFIER;
		merge_type(node, ctype);
		break;

	case SYM_ARRAY:
		if (!lvalue_expression(op)) {
			expression_error(op, "non-lvalue array??");
			return NULL;
		}

		/* Do the implied "addressof" on the array */
		*op = *op->unop;

		/*
		 * When an array is dereferenced, we need to pick
		 * up the attributes of the original node too..
		 */
		node = alloc_symbol(expr->pos, SYM_NODE);
		merge_type(node, op->ctype);
		merge_type(node, ctype);
		break;
	}

	node->bit_size = target->bit_size;
	node->array_size = target->array_size;

	expr->ctype = node;
	return node;
}

/*
 * Unary post-ops: x++ and x--
 */
static struct symbol *evaluate_postop(struct expression *expr)
{
	struct expression *op = expr->unop;
	struct symbol *ctype = op->ctype;
	int class = classify_type(ctype, &ctype);
	int multiply = 0;

	if (!class || class & TYPE_COMPOUND) {
		expression_error(expr, "need scalar for ++/--");
		return NULL;
	}
	if (!lvalue_expression(expr->unop)) {
		expression_error(expr, "need lvalue expression for ++/--");
		return NULL;
	}

	if ((class & TYPE_RESTRICT) && restricted_unop(expr->op, &ctype))
		unrestrict(expr, class, &ctype);

	if (class & TYPE_NUM) {
		multiply = 1;
	} else if (class == TYPE_PTR) {
		struct symbol *target = examine_pointer_target(ctype);
		if (!is_function(target))
			multiply = bits_to_bytes(target->bit_size);
	}

	if (multiply) {
		evaluate_assign_to(op, op->ctype);
		expr->op_value = multiply;
		expr->ctype = ctype;
		return ctype;
	}

	expression_error(expr, "bad argument type for ++/--");
	return NULL;
}

static struct symbol *evaluate_sign(struct expression *expr)
{
	struct symbol *ctype = expr->unop->ctype;
	int class = classify_type(ctype, &ctype);
	unsigned char flags = expr->unop->flags & ~CEF_CONST_MASK;

	/* should be an arithmetic type */
	if (!(class & TYPE_NUM))
		return bad_expr_type(expr);
	if (class & TYPE_RESTRICT)
		goto Restr;
Normal:
	if (!(class & TYPE_FLOAT)) {
		ctype = integer_promotion(ctype);
		expr->unop = cast_to(expr->unop, ctype);
	} else if (expr->op != '~') {
		/* no conversions needed */
	} else {
		return bad_expr_type(expr);
	}
	if (expr->op == '+')
		*expr = *expr->unop;
	expr->flags = flags;
	expr->ctype = ctype;
	return ctype;
Restr:
	if (restricted_unop(expr->op, &ctype))
		unrestrict(expr, class, &ctype);
	goto Normal;
}

static struct symbol *evaluate_preop(struct expression *expr)
{
	struct symbol *ctype = expr->unop->ctype;

	switch (expr->op) {
	case '(':
		*expr = *expr->unop;
		return ctype;

	case '+':
	case '-':
	case '~':
		return evaluate_sign(expr);

	case '*':
		return evaluate_dereference(expr);

	case '&':
		return evaluate_addressof(expr);

	case SPECIAL_INCREMENT:
	case SPECIAL_DECREMENT:
		/*
		 * From a type evaluation standpoint the preops are
		 * the same as the postops
		 */
		return evaluate_postop(expr);

	case '!':
		ctype = degenerate(expr->unop);
		expr->flags = expr->unop->flags & ~CEF_CONST_MASK;
		/*
		 * A logical negation never yields an address constant
		 * [6.6(9)].
		 */
		expr->flags &= ~CEF_ADDR;

		if (is_safe_type(ctype))
			warning(expr->pos, "testing a 'safe expression'");
		if (is_float_type(ctype)) {
			struct expression *arg = expr->unop;
			expr->type = EXPR_COMPARE;
			expr->op = SPECIAL_EQUAL;
			expr->left = arg;
			expr->right = alloc_expression(expr->pos, EXPR_FVALUE);
			expr->right->ctype = ctype;
			expr->right->fvalue = 0;
		} else if (is_fouled_type(ctype)) {
			warning(expr->pos, "%s degrades to integer",
				show_typename(ctype->ctype.base_type));
		}
		/* the result is int [6.5.3.3(5)]*/
		ctype = &int_ctype;
		break;

	default:
		break;
	}
	expr->ctype = ctype;
	return ctype;
}

struct symbol *find_identifier(struct ident *ident, struct symbol_list *_list, int *offset)
{
	struct ptr_list *head = (struct ptr_list *)_list;
	struct ptr_list *list = head;

	if (!head)
		return NULL;
	do {
		int i;
		for (i = 0; i < list->nr; i++) {
			struct symbol *sym = (struct symbol *) list->list[i];
			if (sym->ident) {
				if (sym->ident != ident)
					continue;
				*offset = sym->offset;
				return sym;
			} else {
				struct symbol *ctype = sym->ctype.base_type;
				struct symbol *sub;
				if (!ctype)
					continue;
				if (ctype->type != SYM_UNION && ctype->type != SYM_STRUCT)
					continue;
				sub = find_identifier(ident, ctype->symbol_list, offset);
				if (!sub)
					continue;
				*offset += sym->offset;
				return sub;
			}	
		}
	} while ((list = list->next) != head);
	return NULL;
}

static struct expression *evaluate_offset(struct expression *expr, unsigned long offset)
{
	struct expression *add;

	/*
	 * Create a new add-expression
	 *
	 * NOTE! Even if we just add zero, we need a new node
	 * for the member pointer, since it has a different
	 * type than the original pointer. We could make that
	 * be just a cast, but the fact is, a node is a node,
	 * so we might as well just do the "add zero" here.
	 */
	add = alloc_expression(expr->pos, EXPR_BINOP);
	add->op = '+';
	add->left = expr;
	add->right = alloc_expression(expr->pos, EXPR_VALUE);
	add->right->ctype = &int_ctype;
	add->right->value = offset;

	/*
	 * The ctype of the pointer will be lazily evaluated if
	 * we ever take the address of this member dereference..
	 */
	add->ctype = &lazy_ptr_ctype;
	/*
	 * The resulting address of a member access through an address
	 * constant is an address constant again [6.6(9)].
	 */
	add->flags = expr->flags;

	return add;
}

/* structure/union dereference */
static struct symbol *evaluate_member_dereference(struct expression *expr)
{
	int offset;
	struct symbol *ctype, *member;
	struct expression *deref = expr->deref, *add;
	struct ident *ident = expr->member;
	struct ident *address_space;
	unsigned int mod;

	if (!evaluate_expression(deref))
		return NULL;
	if (!ident) {
		expression_error(expr, "bad member name");
		return NULL;
	}

	ctype = deref->ctype;
	examine_symbol_type(ctype);
	address_space = ctype->ctype.as;
	mod = ctype->ctype.modifiers;
	if (ctype->type == SYM_NODE) {
		ctype = ctype->ctype.base_type;
		combine_address_space(deref->pos, &address_space, ctype->ctype.as);
		mod |= ctype->ctype.modifiers;
	}
	if (!ctype || (ctype->type != SYM_STRUCT && ctype->type != SYM_UNION)) {
		expression_error(expr, "expected structure or union");
		return NULL;
	}
	offset = 0;
	member = find_identifier(ident, ctype->symbol_list, &offset);
	if (!member) {
		const char *type = ctype->type == SYM_STRUCT ? "struct" : "union";
		const char *name = "<unnamed>";
		int namelen = 9;
		if (ctype->ident) {
			name = ctype->ident->name;
			namelen = ctype->ident->len;
		}
		if (ctype->symbol_list)
			expression_error(expr, "no member '%s' in %s %.*s",
				show_ident(ident), type, namelen, name);
		else
			expression_error(expr, "using member '%s' in "
				"incomplete %s %.*s", show_ident(ident),
				type, namelen, name);
		return NULL;
	}

	/*
	 * The member needs to take on the address space and modifiers of
	 * the "parent" type.
	 */
	member = convert_to_as_mod(member, address_space, mod);
	ctype = get_base_type(member);

	if (!lvalue_expression(deref)) {
		if (deref->type != EXPR_SLICE) {
			expr->base = deref;
			expr->r_bitpos = 0;
		} else {
			expr->base = deref->base;
			expr->r_bitpos = deref->r_bitpos;
		}
		expr->r_bitpos += bytes_to_bits(offset);
		expr->type = EXPR_SLICE;
		expr->r_nrbits = member->bit_size;
		expr->r_bitpos += member->bit_offset;
		expr->ctype = member;
		return member;
	}

	deref = deref->unop;
	expr->deref = deref;

	add = evaluate_offset(deref, offset);
	expr->type = EXPR_PREOP;
	expr->op = '*';
	expr->unop = add;

	expr->ctype = member;
	return member;
}

static int is_promoted(struct expression *expr)
{
	while (1) {
		switch (expr->type) {
		case EXPR_BINOP:
		case EXPR_SELECT:
		case EXPR_CONDITIONAL:
			return 1;
		case EXPR_COMMA:
			expr = expr->right;
			continue;
		case EXPR_PREOP:
			switch (expr->op) {
			case '(':
				expr = expr->unop;
				continue;
			case '+':
			case '-':
			case '~':
				return 1;
			default:
				return 0;
			}
		default:
			return 0;
		}
	}
}


static struct symbol *evaluate_cast(struct expression *);

static struct symbol *evaluate_type_information(struct expression *expr)
{
	struct symbol *sym = expr->cast_type;
	if (!sym) {
		sym = evaluate_expression(expr->cast_expression);
		if (!sym)
			return NULL;
		/*
		 * Expressions of restricted types will possibly get
		 * promoted - check that here
		 */
		if (is_restricted_type(sym)) {
			if (sym->bit_size < bits_in_int && is_promoted(expr))
				sym = &int_ctype;
		} else if (is_fouled_type(sym)) {
			sym = &int_ctype;
		}
	}
	examine_symbol_type(sym);
	if (is_bitfield_type(sym)) {
		expression_error(expr, "trying to examine bitfield type");
		return NULL;
	}
	return sym;
}

static struct symbol *evaluate_sizeof(struct expression *expr)
{
	struct symbol *type;
	int size;

	type = evaluate_type_information(expr);
	if (!type)
		return NULL;

	size = type->bit_size;

	if (size < 0 && is_void_type(type)) {
		if (Wpointer_arith)
			warning(expr->pos, "expression using sizeof(void)");
		size = bits_in_char;
	}

	if (is_bool_type(type)) {
		if (Wsizeof_bool)
			warning(expr->pos, "expression using sizeof _Bool");
		size = bits_to_bytes(bits_in_bool) * bits_in_char;
	}

	if (is_function(type->ctype.base_type)) {
		if (Wpointer_arith)
			warning(expr->pos, "expression using sizeof on a function");
		size = bits_in_char;
	}

	if (is_array_type(type) && size < 0) {	// VLA, 1-dimension only
		struct expression *base, *size;
		struct symbol *base_type;

		if (type->type == SYM_NODE)
			type = type->ctype.base_type;	// strip the SYM_NODE
		base_type = get_base_type(type);
		if (!base_type)
			goto error;
		if (base_type->bit_size <= 0) {
			base = alloc_expression(expr->pos, EXPR_SIZEOF);
			base->cast_type = base_type;
			if (!evaluate_sizeof(base))
				goto error;
		} else {
			base = alloc_expression(expr->pos, EXPR_VALUE);
			base->value = bits_to_bytes(base_type->bit_size);
			base->ctype = size_t_ctype;
		}
		size = alloc_expression(expr->pos, EXPR_CAST);
		size->cast_type = size_t_ctype;
		size->cast_expression = type->array_size;
		if (!evaluate_expression(size))
			goto error;
		expr->left = size;
		expr->right = base;
		expr->type = EXPR_BINOP;
		expr->op = '*';
		return expr->ctype = size_t_ctype;
	}

error:
	if ((size < 0) || (size & (bits_in_char - 1)))
		expression_error(expr, "cannot size expression");

	expr->type = EXPR_VALUE;
	expr->value = bits_to_bytes(size);
	expr->taint = 0;
	expr->ctype = size_t_ctype;
	return size_t_ctype;
}

static struct symbol *evaluate_ptrsizeof(struct expression *expr)
{
	struct symbol *type;
	int size;

	type = evaluate_type_information(expr);
	if (!type)
		return NULL;

	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	if (!type)
		return NULL;
	switch (type->type) {
	case SYM_ARRAY:
		break;
	case SYM_PTR:
		type = get_base_type(type);
		if (type)
			break;
	default:
		expression_error(expr, "expected pointer expression");
		return NULL;
	}
	size = type->bit_size;
	if (size & (bits_in_char-1))
		size = 0;
	expr->type = EXPR_VALUE;
	expr->value = bits_to_bytes(size);
	expr->taint = 0;
	expr->ctype = size_t_ctype;
	return size_t_ctype;
}

static struct symbol *evaluate_alignof(struct expression *expr)
{
	struct symbol *type;

	type = evaluate_type_information(expr);
	if (!type)
		return NULL;

	expr->type = EXPR_VALUE;
	expr->value = type->ctype.alignment;
	expr->taint = 0;
	expr->ctype = size_t_ctype;
	return size_t_ctype;
}

static int evaluate_arguments(struct symbol *fn, struct expression_list *head)
{
	struct expression *expr;
	struct symbol_list *argument_types = fn->arguments;
	struct symbol *argtype;
	int i = 1;

	PREPARE_PTR_LIST(argument_types, argtype);
	FOR_EACH_PTR (head, expr) {
		struct expression **p = THIS_ADDRESS(expr);
		struct symbol *ctype, *target;
		ctype = evaluate_expression(expr);

		if (!ctype)
			return 0;

		target = argtype;
		if (!target) {
			struct symbol *type;
			int class = classify_type(ctype, &type);
			if (is_int(class)) {
				*p = cast_to(expr, integer_promotion(type));
			} else if (class & TYPE_FLOAT) {
				unsigned long mod = type->ctype.modifiers;
				if (!(mod & (MOD_LONG_ALL)))
					*p = cast_to(expr, &double_ctype);
			} else if (class & TYPE_PTR) {
				if (expr->ctype == &null_ctype)
					*p = cast_to(expr, &ptr_ctype);
				else
					degenerate(expr);
			}
		} else if (!target->forced_arg){
			static char where[30];
			examine_symbol_type(target);
			sprintf(where, "argument %d", i);
			compatible_argument_type(expr, target, p, where);
		}

		i++;
		NEXT_PTR_LIST(argtype);
	} END_FOR_EACH_PTR(expr);
	FINISH_PTR_LIST(argtype);
	return 1;
}

static void convert_index(struct expression *e)
{
	struct expression *child = e->idx_expression;
	unsigned from = e->idx_from;
	unsigned to = e->idx_to + 1;
	e->type = EXPR_POS;
	e->init_offset = from * bits_to_bytes(e->ctype->bit_size);
	e->init_nr = to - from;
	e->init_expr = child;
}

static void convert_ident(struct expression *e)
{
	struct expression *child = e->ident_expression;
	int offset = e->offset;

	e->type = EXPR_POS;
	e->init_offset = offset;
	e->init_nr = 1;
	e->init_expr = child;
}

static void convert_designators(struct expression *e)
{
	while (e) {
		if (e->type == EXPR_INDEX)
			convert_index(e);
		else if (e->type == EXPR_IDENTIFIER)
			convert_ident(e);
		else
			break;
		e = e->init_expr;
	}
}

static void excess(struct expression *e, const char *s)
{
	warning(e->pos, "excessive elements in %s initializer", s);
}

/*
 * implicit designator for the first element
 */
static struct expression *first_subobject(struct symbol *ctype, int class,
					  struct expression **v)
{
	struct expression *e = *v, *new;

	if (ctype->type == SYM_NODE)
		ctype = ctype->ctype.base_type;

	if (class & TYPE_PTR) { /* array */
		if (!ctype->bit_size)
			return NULL;
		new = alloc_expression(e->pos, EXPR_INDEX);
		new->idx_expression = e;
		new->ctype = ctype->ctype.base_type;
	} else  {
		struct symbol *field, *p;
		PREPARE_PTR_LIST(ctype->symbol_list, p);
		while (p && !p->ident && is_bitfield_type(p))
			NEXT_PTR_LIST(p);
		field = p;
		FINISH_PTR_LIST(p);
		if (!field)
			return NULL;
		new = alloc_expression(e->pos, EXPR_IDENTIFIER);
		new->ident_expression = e;
		new->field = new->ctype = field;
		new->offset = field->offset;
	}
	*v = new;
	return new;
}

/*
 * sanity-check explicit designators; return the innermost one or NULL
 * in case of error.  Assign types.
 */
static struct expression *check_designators(struct expression *e,
					    struct symbol *ctype)
{
	struct expression *last = NULL;
	const char *err;
	while (1) {
		if (ctype->type == SYM_NODE)
			ctype = ctype->ctype.base_type;
		if (e->type == EXPR_INDEX) {
			struct symbol *type;
			if (ctype->type != SYM_ARRAY) {
				err = "array index in non-array";
				break;
			}
			type = ctype->ctype.base_type;
			if (ctype->bit_size >= 0 && type->bit_size >= 0) {
				unsigned offset = array_element_offset(type->bit_size, e->idx_to);
				if (offset >= ctype->bit_size) {
					err = "index out of bounds in";
					break;
				}
			}
			e->ctype = ctype = type;
			ctype = type;
			last = e;
			if (!e->idx_expression) {
				err = "invalid";
				break;
			}
			e = e->idx_expression;
		} else if (e->type == EXPR_IDENTIFIER) {
			int offset = 0;
			if (ctype->type != SYM_STRUCT && ctype->type != SYM_UNION) {
				err = "field name not in struct or union";
				break;
			}
			ctype = find_identifier(e->expr_ident, ctype->symbol_list, &offset);
			if (!ctype) {
				err = "unknown field name in";
				break;
			}
			e->offset = offset;
			e->field = e->ctype = ctype;
			last = e;
			if (!e->ident_expression) {
				err = "invalid";
				break;
			}
			e = e->ident_expression;
		} else if (e->type == EXPR_POS) {
			err = "internal front-end error: EXPR_POS in";
			break;
		} else
			return last;
	}
	expression_error(e, "%s initializer", err);
	return NULL;
}

/*
 * choose the next subobject to initialize.
 *
 * Get designators for next element, switch old ones to EXPR_POS.
 * Return the resulting expression or NULL if we'd run out of subobjects.
 * The innermost designator is returned in *v.  Designators in old
 * are assumed to be already sanity-checked.
 */
static struct expression *next_designators(struct expression *old,
			     struct symbol *ctype,
			     struct expression *e, struct expression **v)
{
	struct expression *new = NULL;

	if (!old)
		return NULL;
	if (old->type == EXPR_INDEX) {
		struct expression *copy;
		unsigned n;

		copy = next_designators(old->idx_expression,
					old->ctype, e, v);
		if (!copy) {
			n = old->idx_to + 1;
			if (array_element_offset(old->ctype->bit_size, n) == ctype->bit_size) {
				convert_index(old);
				return NULL;
			}
			copy = e;
			*v = new = alloc_expression(e->pos, EXPR_INDEX);
		} else {
			n = old->idx_to;
			new = alloc_expression(e->pos, EXPR_INDEX);
		}

		new->idx_from = new->idx_to = n;
		new->idx_expression = copy;
		new->ctype = old->ctype;
		convert_index(old);
	} else if (old->type == EXPR_IDENTIFIER) {
		struct expression *copy;
		struct symbol *field;
		int offset = 0;

		copy = next_designators(old->ident_expression,
					old->ctype, e, v);
		if (!copy) {
			field = old->field->next_subobject;
			if (!field) {
				convert_ident(old);
				return NULL;
			}
			copy = e;
			*v = new = alloc_expression(e->pos, EXPR_IDENTIFIER);
			/*
			 * We can't necessarily trust "field->offset",
			 * because the field might be in an anonymous
			 * union, and the field offset is then the offset
			 * within that union.
			 *
			 * The "old->offset - old->field->offset"
			 * would be the offset of such an anonymous
			 * union.
			 */
			offset = old->offset - old->field->offset;
		} else {
			field = old->field;
			new = alloc_expression(e->pos, EXPR_IDENTIFIER);
		}

		new->field = field;
		new->expr_ident = field->ident;
		new->ident_expression = copy;
		new->ctype = field;
		new->offset = field->offset + offset;
		convert_ident(old);
	}
	return new;
}

static int handle_initializer(struct expression **ep, int nested,
		int class, struct symbol *ctype, unsigned long mods);

/*
 * deal with traversing subobjects [6.7.8(17,18,20)]
 */
static void handle_list_initializer(struct expression *expr,
		int class, struct symbol *ctype, unsigned long mods)
{
	struct expression *e, *last = NULL, *top = NULL, *next;
	int jumped = 0;

	FOR_EACH_PTR(expr->expr_list, e) {
		struct expression **v;
		struct symbol *type;
		int lclass;

		if (e->type != EXPR_INDEX && e->type != EXPR_IDENTIFIER) {
			struct symbol *struct_sym;
			if (!top) {
				top = e;
				last = first_subobject(ctype, class, &top);
			} else {
				last = next_designators(last, ctype, e, &top);
			}
			if (!last) {
				excess(e, class & TYPE_PTR ? "array" :
							"struct or union");
				DELETE_CURRENT_PTR(e);
				continue;
			}
			struct_sym = ctype->type == SYM_NODE ? ctype->ctype.base_type : ctype;
			if (Wdesignated_init && struct_sym->designated_init)
				warning(e->pos, "%s%.*s%spositional init of field in %s %s, declared with attribute designated_init",
					ctype->ident ? "in initializer for " : "",
					ctype->ident ? ctype->ident->len : 0,
					ctype->ident ? ctype->ident->name : "",
					ctype->ident ? ": " : "",
					get_type_name(struct_sym->type),
					show_ident(struct_sym->ident));
			if (jumped) {
				warning(e->pos, "advancing past deep designator");
				jumped = 0;
			}
			REPLACE_CURRENT_PTR(e, last);
		} else {
			next = check_designators(e, ctype);
			if (!next) {
				DELETE_CURRENT_PTR(e);
				continue;
			}
			top = next;
			/* deeper than one designator? */
			jumped = top != e;
			convert_designators(last);
			last = e;
		}

found:
		lclass = classify_type(top->ctype, &type);
		if (top->type == EXPR_INDEX)
			v = &top->idx_expression;
		else
			v = &top->ident_expression;

		mods |= ctype->ctype.modifiers & MOD_STORAGE;
		if (handle_initializer(v, 1, lclass, top->ctype, mods))
			continue;

		if (!(lclass & TYPE_COMPOUND)) {
			warning(e->pos, "bogus scalar initializer");
			DELETE_CURRENT_PTR(e);
			continue;
		}

		next = first_subobject(type, lclass, v);
		if (next) {
			warning(e->pos, "missing braces around initializer");
			top = next;
			goto found;
		}

		DELETE_CURRENT_PTR(e);
		excess(e, lclass & TYPE_PTR ? "array" : "struct or union");

	} END_FOR_EACH_PTR(e);

	convert_designators(last);
	expr->ctype = ctype;
}

static int is_string_literal(struct expression **v)
{
	struct expression *e = *v;
	while (e && e->type == EXPR_PREOP && e->op == '(')
		e = e->unop;
	if (!e || e->type != EXPR_STRING)
		return 0;
	if (e != *v && Wparen_string)
		warning(e->pos,
			"array initialized from parenthesized string constant");
	*v = e;
	return 1;
}

/*
 * We want a normal expression, possibly in one layer of braces.  Warn
 * if the latter happens inside a list (it's legal, but likely to be
 * an effect of screwup).  In case of anything not legal, we are definitely
 * having an effect of screwup, so just fail and let the caller warn.
 */
static struct expression *handle_scalar(struct expression *e, int nested)
{
	struct expression *v = NULL, *p;
	int count = 0;

	/* normal case */
	if (e->type != EXPR_INITIALIZER)
		return e;

	FOR_EACH_PTR(e->expr_list, p) {
		if (!v)
			v = p;
		count++;
	} END_FOR_EACH_PTR(p);
	if (count != 1)
		return NULL;
	switch(v->type) {
	case EXPR_INITIALIZER:
	case EXPR_INDEX:
	case EXPR_IDENTIFIER:
		return NULL;
	default:
		break;
	}
	if (nested)
		warning(e->pos, "braces around scalar initializer");
	return v;
}

/*
 * deal with the cases that don't care about subobjects:
 * scalar <- assignment expression, possibly in braces [6.7.8(11)]
 * character array <- string literal, possibly in braces [6.7.8(14)]
 * struct or union <- assignment expression of compatible type [6.7.8(13)]
 * compound type <- initializer list in braces [6.7.8(16)]
 * The last one punts to handle_list_initializer() which, in turn will call
 * us for individual elements of the list.
 *
 * We do not handle 6.7.8(15) (wide char array <- wide string literal) for
 * the lack of support of wide char stuff in general.
 *
 * One note: we need to take care not to evaluate a string literal until
 * we know that we *will* handle it right here.  Otherwise we would screw
 * the cases like struct { struct {char s[10]; ...} ...} initialized with
 * { "string", ...} - we need to preserve that string literal recognizable
 * until we dig into the inner struct.
 */
static int handle_initializer(struct expression **ep, int nested,
		int class, struct symbol *ctype, unsigned long mods)
{
	int is_string = is_string_type(ctype);
	struct expression *e = *ep, *p;
	struct symbol *type;

	if (!e)
		return 0;

	/* scalar */
	if (!(class & TYPE_COMPOUND)) {
		e = handle_scalar(e, nested);
		if (!e)
			return 0;
		*ep = e;
		if (!evaluate_expression(e))
			return 1;
		compatible_assignment_types(e, ctype, ep, "initializer");
		/*
		 * Initializers for static storage duration objects
		 * shall be constant expressions or a string literal [6.7.8(4)].
		 */
		mods |= ctype->ctype.modifiers;
		mods &= (MOD_TOPLEVEL | MOD_STATIC);
		if (mods && !(e->flags & (CEF_ACE | CEF_ADDR)))
			if (Wconstexpr_not_const)
				warning(e->pos, "non-constant initializer for static object");

		return 1;
	}

	/*
	 * sublist; either a string, or we dig in; the latter will deal with
	 * pathologies, so we don't need anything fancy here.
	 */
	if (e->type == EXPR_INITIALIZER) {
		if (is_string) {
			struct expression *v = NULL;
			int count = 0;

			FOR_EACH_PTR(e->expr_list, p) {
				if (!v)
					v = p;
				count++;
			} END_FOR_EACH_PTR(p);
			if (count == 1 && is_string_literal(&v)) {
				*ep = e = v;
				goto String;
			}
		}
		handle_list_initializer(e, class, ctype, mods);
		return 1;
	}

	/* string */
	if (is_string_literal(&e)) {
		/* either we are doing array of char, or we'll have to dig in */
		if (is_string) {
			*ep = e;
			goto String;
		}
		return 0;
	}
	/* struct or union can be initialized by compatible */
	if (class != TYPE_COMPOUND)
		return 0;
	type = evaluate_expression(e);
	if (!type)
		return 0;
	if (ctype->type == SYM_NODE)
		ctype = ctype->ctype.base_type;
	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	if (ctype == type)
		return 1;
	return 0;

String:
	p = alloc_expression(e->pos, EXPR_STRING);
	*p = *e;
	type = evaluate_expression(p);
	if (ctype->bit_size != -1) {
		if (ctype->bit_size + bits_in_char < type->bit_size)
			warning(e->pos,
				"too long initializer-string for array of char");
		else if (Winit_cstring && ctype->bit_size + bits_in_char == type->bit_size) {
			warning(e->pos,
				"too long initializer-string for array of char(no space for nul char)");
		}
	}
	*ep = p;
	return 1;
}

static void evaluate_initializer(struct symbol *ctype, struct expression **ep)
{
	struct symbol *type;
	int class = classify_type(ctype, &type);
	if (!handle_initializer(ep, 0, class, ctype, 0))
		expression_error(*ep, "invalid initializer");
}

static struct symbol *cast_to_bool(struct expression *expr)
{
	struct expression *old = expr->cast_expression;
	struct expression *zero;
	struct symbol *otype;
	int oclass = classify_type(degenerate(old), &otype);
	struct symbol *ctype;

	if (oclass & TYPE_COMPOUND)
		return NULL;

	zero = alloc_const_expression(expr->pos, 0);
	expr->op = SPECIAL_NOTEQUAL;
	ctype = usual_conversions(expr->op, old, zero,
			oclass, TYPE_NUM, otype, zero->ctype);
	expr->type = EXPR_COMPARE;
	expr->left = cast_to(old, ctype);
	expr->right = cast_to(zero, ctype);

	return expr->ctype;
}

static int cast_flags(struct expression *expr, struct expression *old)
{
	struct symbol *t;
	int class;
	int flags = CEF_NONE;

	class = classify_type(expr->ctype, &t);
	if (class & TYPE_NUM) {
		flags = old->flags & ~CEF_CONST_MASK;
		/*
		 * Casts to numeric types never result in address
		 * constants [6.6(9)].
		 */
		flags &= ~CEF_ADDR;

		/*
		 * As an extension, treat address constants cast to
		 * integer type as an arithmetic constant.
		 */
		if (old->flags & CEF_ADDR)
			flags = CEF_ACE;

		/*
		 * Cast to float type -> not an integer constant
		 * expression [6.6(6)].
		 */
		if (class & TYPE_FLOAT)
			flags &= ~CEF_CLR_ICE;
		/*
		 * Casts of float literals to integer type results in
		 * a constant integer expression [6.6(6)].
		 */
		else if (old->flags & CEF_FLOAT)
			flags = CEF_SET_ICE;
	} else if (class & TYPE_PTR) {
		/*
		 * Casts of integer literals to pointer type yield
		 * address constants [6.6(9)].
		 *
		 * As an extension, treat address constants cast to a
		 * different pointer type as address constants again.
		 *
		 * As another extension, treat integer constant
		 * expressions (in contrast to literals) cast to
		 * pointer type as address constants.
		 */
		if (old->flags & (CEF_ICE | CEF_ADDR))
			flags = CEF_ADDR;
	}

	return flags;
}

static struct symbol *evaluate_cast(struct expression *expr)
{
	struct expression *source = expr->cast_expression;
	struct symbol *ctype;
	struct symbol *ttype, *stype;
	int tclass, sclass;
	struct ident *tas = NULL, *sas = NULL;

	if (!source)
		return NULL;

	/*
	 * Special case: a cast can be followed by an
	 * initializer, in which case we need to pass
	 * the type value down to that initializer rather
	 * than trying to evaluate it as an expression
	 *
	 * A more complex case is when the initializer is
	 * dereferenced as part of a post-fix expression.
	 * We need to produce an expression that can be dereferenced.
	 */
	if (source->type == EXPR_INITIALIZER) {
		struct symbol *sym = expr->cast_type;
		struct expression *addr = alloc_expression(expr->pos, EXPR_SYMBOL);

		sym->initializer = source;
		evaluate_symbol(sym);

		addr->ctype = &lazy_ptr_ctype;	/* Lazy eval */
		addr->symbol = sym;
		if (sym->ctype.modifiers & MOD_TOPLEVEL)
			addr->flags |= CEF_ADDR;

		expr->type = EXPR_PREOP;
		expr->op = '*';
		expr->unop = addr;
		expr->ctype = sym;

		return sym;
	}

	ctype = examine_symbol_type(expr->cast_type);
	expr->ctype = ctype;
	expr->cast_type = ctype;

	evaluate_expression(source);
	degenerate(source);

	tclass = classify_type(ctype, &ttype);

	expr->flags = cast_flags(expr, source);

	/*
	 * You can always throw a value away by casting to
	 * "void" - that's an implicit "force". Note that
	 * the same is _not_ true of "void *".
	 */
	if (ttype == &void_ctype)
		goto out;

	stype = source->ctype;
	if (!stype) {
		expression_error(expr, "cast from unknown type");
		goto out;
	}
	sclass = classify_type(stype, &stype);

	if (expr->type == EXPR_FORCE_CAST)
		goto out;

	if (tclass & (TYPE_COMPOUND | TYPE_FN))
		warning(expr->pos, "cast to non-scalar");

	if (sclass & TYPE_COMPOUND)
		warning(expr->pos, "cast from non-scalar");

	/* allowed cast unfouls */
	if (sclass & TYPE_FOULED)
		stype = unfoul(stype);

	if (ttype != stype) {
		if ((tclass & TYPE_RESTRICT) && restricted_value(source, ttype))
			warning(expr->pos, "cast to %s",
				show_typename(ttype));
		if (sclass & TYPE_RESTRICT) {
			if (ttype == &bool_ctype) {
				if (sclass & TYPE_FOULED)
					warning(expr->pos, "%s degrades to integer",
						show_typename(stype));
			} else {
				warning(expr->pos, "cast from %s",
					show_typename(stype));
			}
		}
	}

	if ((ttype == &ulong_ctype || ttype == uintptr_ctype) && !Wcast_from_as)
		tas = &bad_address_space;
	else if (tclass == TYPE_PTR) {
		examine_pointer_target(ttype);
		tas = ttype->ctype.as;
	}

	if ((stype == &ulong_ctype || stype == uintptr_ctype))
		sas = &bad_address_space;
	else if (sclass == TYPE_PTR) {
		examine_pointer_target(stype);
		sas = stype->ctype.as;
	}

	if (!tas && valid_as(sas))
		warning(expr->pos, "cast removes address space '%s' of expression", show_as(sas));
	if (valid_as(tas) && valid_as(sas) && tas != sas)
		warning(expr->pos, "cast between address spaces (%s -> %s)", show_as(sas), show_as(tas));
	if (valid_as(tas) && !sas &&
	    !is_null_pointer_constant(source) && Wcast_to_as)
		warning(expr->pos,
			"cast adds address space '%s' to expression", show_as(tas));

	if (!(ttype->ctype.modifiers & MOD_PTRINHERIT) && tclass == TYPE_PTR &&
	    !tas && (source->flags & CEF_ICE)) {
		if (ttype->ctype.base_type == &void_ctype) {
			if (is_zero_constant(source)) {
				/* NULL */
				expr->type = EXPR_VALUE;
				expr->ctype = &null_ctype;
				expr->value = 0;
				return expr->ctype;
			}
		}
	}

	if (ttype == &bool_ctype)
		cast_to_bool(expr);

	// checks pointers to restricted
	while (Wbitwise_pointer && tclass == TYPE_PTR && sclass == TYPE_PTR) {
		tclass = classify_type(ttype->ctype.base_type, &ttype);
		sclass = classify_type(stype->ctype.base_type, &stype);
		if (ttype == stype)
			break;
		if (!ttype || !stype)
			break;
		if (ttype == &void_ctype || stype == &void_ctype)
			break;
		if (tclass & TYPE_RESTRICT) {
			warning(expr->pos, "cast to %s", show_typename(ctype));
			break;
		}
		if (sclass & TYPE_RESTRICT) {
			warning(expr->pos, "cast from %s", show_typename(source->ctype));
			break;
		}
	}
out:
	return ctype;
}

/*
 * Evaluate a call expression with a symbol. This
 * should expand inline functions, and evaluate
 * builtins.
 */
static int evaluate_symbol_call(struct expression *expr)
{
	struct expression *fn = expr->fn;
	struct symbol *ctype = fn->ctype;

	if (fn->type != EXPR_PREOP)
		return 0;

	if (ctype->op && ctype->op->evaluate)
		return ctype->op->evaluate(expr);

	if (ctype->ctype.modifiers & MOD_INLINE) {
		int ret;
		struct symbol *curr = current_fn;

		if (ctype->definition)
			ctype = ctype->definition;

		current_fn = ctype->ctype.base_type;

		ret = inline_function(expr, ctype);

		/* restore the old function */
		current_fn = curr;
		return ret;
	}

	return 0;
}

static struct symbol *evaluate_call(struct expression *expr)
{
	int args, fnargs;
	struct symbol *ctype, *sym;
	struct expression *fn = expr->fn;
	struct expression_list *arglist = expr->args;

	if (!evaluate_expression(fn))
		return NULL;
	sym = ctype = fn->ctype;
	if (ctype->type == SYM_NODE)
		ctype = ctype->ctype.base_type;
	if (ctype->type == SYM_PTR)
		ctype = get_base_type(ctype);

	if (ctype->type != SYM_FN) {
		struct expression *arg;
		expression_error(expr, "not a function %s",
			     show_ident(sym->ident));
		/* do typechecking in arguments */
		FOR_EACH_PTR (arglist, arg) {
			evaluate_expression(arg);
		} END_FOR_EACH_PTR(arg);
		return NULL;
	}

	examine_fn_arguments(ctype);
        if (sym->type == SYM_NODE && fn->type == EXPR_PREOP &&
	    sym->op && sym->op->args) {
		if (!sym->op->args(expr))
			return NULL;
	} else {
		if (!evaluate_arguments(ctype, arglist))
			return NULL;
		args = expression_list_size(expr->args);
		fnargs = symbol_list_size(ctype->arguments);
		if (args < fnargs) {
			expression_error(expr,
				     "not enough arguments for function %s",
				     show_ident(sym->ident));
			return NULL;
		}
		if (args > fnargs && !ctype->variadic)
			expression_error(expr,
				     "too many arguments for function %s",
				     show_ident(sym->ident));
	}
	expr->ctype = ctype->ctype.base_type;
	if (sym->type == SYM_NODE) {
		if (evaluate_symbol_call(expr))
			return expr->ctype;
	}
	return expr->ctype;
}

static struct symbol *evaluate_offsetof(struct expression *expr)
{
	struct expression *e = expr->down;
	struct symbol *ctype = expr->in;
	int class;

	if (expr->op == '.') {
		struct symbol *field;
		int offset = 0;
		if (!ctype) {
			expression_error(expr, "expected structure or union");
			return NULL;
		}
		examine_symbol_type(ctype);
		class = classify_type(ctype, &ctype);
		if (class != TYPE_COMPOUND) {
			expression_error(expr, "expected structure or union");
			return NULL;
		}

		field = find_identifier(expr->ident, ctype->symbol_list, &offset);
		if (!field) {
			expression_error(expr, "unknown member");
			return NULL;
		}
		ctype = field;
		expr->type = EXPR_VALUE;
		expr->flags = CEF_SET_ICE;
		expr->value = offset;
		expr->taint = 0;
		expr->ctype = size_t_ctype;
	} else {
		if (!ctype) {
			expression_error(expr, "expected structure or union");
			return NULL;
		}
		examine_symbol_type(ctype);
		class = classify_type(ctype, &ctype);
		if (class != (TYPE_COMPOUND | TYPE_PTR)) {
			expression_error(expr, "expected array");
			return NULL;
		}
		ctype = ctype->ctype.base_type;
		if (!expr->index) {
			expr->type = EXPR_VALUE;
			expr->flags = CEF_SET_ICE;
			expr->value = 0;
			expr->taint = 0;
			expr->ctype = size_t_ctype;
		} else {
			struct expression *idx = expr->index, *m;
			struct symbol *i_type = evaluate_expression(idx);
			unsigned old_idx_flags;
			int i_class = classify_type(i_type, &i_type);

			if (!is_int(i_class)) {
				expression_error(expr, "non-integer index");
				return NULL;
			}
			unrestrict(idx, i_class, &i_type);
			old_idx_flags = idx->flags;
			idx = cast_to(idx, size_t_ctype);
			idx->flags = old_idx_flags;
			m = alloc_const_expression(expr->pos,
						   bits_to_bytes(ctype->bit_size));
			m->ctype = size_t_ctype;
			m->flags = CEF_SET_INT;
			expr->type = EXPR_BINOP;
			expr->left = idx;
			expr->right = m;
			expr->op = '*';
			expr->ctype = size_t_ctype;
			expr->flags = m->flags & idx->flags & ~CEF_CONST_MASK;
		}
	}
	if (e) {
		struct expression *copy = __alloc_expression(0);
		*copy = *expr;
		if (e->type == EXPR_OFFSETOF)
			e->in = ctype;
		if (!evaluate_expression(e))
			return NULL;
		expr->type = EXPR_BINOP;
		expr->flags = e->flags & copy->flags & ~CEF_CONST_MASK;
		expr->op = '+';
		expr->ctype = size_t_ctype;
		expr->left = copy;
		expr->right = e;
	}
	return size_t_ctype;
}

struct symbol *evaluate_expression(struct expression *expr)
{
	if (!expr)
		return NULL;
	if (expr->ctype)
		return expr->ctype;

	switch (expr->type) {
	case EXPR_VALUE:
	case EXPR_FVALUE:
		expression_error(expr, "value expression without a type");
		return NULL;
	case EXPR_STRING:
		return evaluate_string(expr);
	case EXPR_SYMBOL:
		return evaluate_symbol_expression(expr);
	case EXPR_BINOP:
		evaluate_expression(expr->left);
		evaluate_expression(expr->right);
		if (!valid_subexpr_type(expr))
			return NULL;
		return evaluate_binop(expr);
	case EXPR_LOGICAL:
		return evaluate_logical(expr);
	case EXPR_COMMA:
		evaluate_expression(expr->left);
		if (!evaluate_expression(expr->right))
			return NULL;
		return evaluate_comma(expr);
	case EXPR_COMPARE:
		evaluate_expression(expr->left);
		evaluate_expression(expr->right);
		if (!valid_subexpr_type(expr))
			return NULL;
		return evaluate_compare(expr);
	case EXPR_ASSIGNMENT:
		evaluate_expression(expr->left);
		evaluate_expression(expr->right);
		if (!valid_subexpr_type(expr))
			return NULL;
		return evaluate_assignment(expr);
	case EXPR_PREOP:
		if (!evaluate_expression(expr->unop))
			return NULL;
		return evaluate_preop(expr);
	case EXPR_POSTOP:
		if (!evaluate_expression(expr->unop))
			return NULL;
		return evaluate_postop(expr);
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		return evaluate_cast(expr);
	case EXPR_SIZEOF:
		return evaluate_sizeof(expr);
	case EXPR_PTRSIZEOF:
		return evaluate_ptrsizeof(expr);
	case EXPR_ALIGNOF:
		return evaluate_alignof(expr);
	case EXPR_DEREF:
		return evaluate_member_dereference(expr);
	case EXPR_CALL:
		return evaluate_call(expr);
	case EXPR_SELECT:
	case EXPR_CONDITIONAL:
		return evaluate_conditional_expression(expr);
	case EXPR_STATEMENT:
		expr->ctype = evaluate_statement(expr->statement);
		return expr->ctype;

	case EXPR_LABEL:
		expr->ctype = &ptr_ctype;
		return &ptr_ctype;

	case EXPR_TYPE:
		/* Evaluate the type of the symbol .. */
		evaluate_symbol(expr->symbol);
		/* .. but the type of the _expression_ is a "type" */
		expr->ctype = &type_ctype;
		return &type_ctype;

	case EXPR_OFFSETOF:
		return evaluate_offsetof(expr);

	/* These can not exist as stand-alone expressions */
	case EXPR_INITIALIZER:
	case EXPR_IDENTIFIER:
	case EXPR_INDEX:
	case EXPR_POS:
		expression_error(expr, "internal front-end error: initializer in expression");
		return NULL;
	case EXPR_SLICE:
		expression_error(expr, "internal front-end error: SLICE re-evaluated");
		return NULL;
	case EXPR_ASM_OPERAND:
		expression_error(expr, "internal front-end error: ASM_OPERAND evaluated");
		return NULL;
	}
	return NULL;
}

void check_duplicates(struct symbol *sym)
{
	int declared = 0;
	struct symbol *next = sym;
	int initialized = sym->initializer != NULL;

	while ((next = next->same_symbol) != NULL) {
		const char *typediff;
		evaluate_symbol(next);
		if (initialized && next->initializer) {
			sparse_error(sym->pos, "symbol '%s' has multiple initializers (originally initialized at %s:%d)",
				show_ident(sym->ident),
				stream_name(next->pos.stream), next->pos.line);
			/* Only warn once */
			initialized = 0;
		}
		declared++;
		typediff = type_difference(&sym->ctype, &next->ctype, 0, 0);
		if (typediff) {
			sparse_error(sym->pos, "symbol '%s' redeclared with different type (originally declared at %s:%d) - %s",
				show_ident(sym->ident),
				stream_name(next->pos.stream), next->pos.line, typediff);
			return;
		}
	}
	if (!declared) {
		unsigned long mod = sym->ctype.modifiers;
		if (mod & (MOD_STATIC | MOD_REGISTER | MOD_EXT_VISIBLE))
			return;
		if (!(mod & MOD_TOPLEVEL))
			return;
		if (!Wdecl)
			return;
		if (sym->ident == &main_ident)
			return;
		warning(sym->pos, "symbol '%s' was not declared. Should it be static?", show_ident(sym->ident));
	}
}

static struct symbol *evaluate_symbol(struct symbol *sym)
{
	struct symbol *base_type;

	if (!sym)
		return sym;
	if (sym->evaluated)
		return sym;
	sym->evaluated = 1;

	sym = examine_symbol_type(sym);
	base_type = get_base_type(sym);
	if (!base_type)
		return NULL;

	/* Evaluate the initializers */
	if (sym->initializer)
		evaluate_initializer(sym, &sym->initializer);

	/* And finally, evaluate the body of the symbol too */
	if (base_type->type == SYM_FN) {
		struct symbol *curr = current_fn;

		if (sym->definition && sym->definition != sym)
			return evaluate_symbol(sym->definition);

		current_fn = base_type;

		examine_fn_arguments(base_type);
		if (!base_type->stmt && base_type->inline_stmt)
			uninline(sym);
		if (base_type->stmt)
			evaluate_statement(base_type->stmt);

		current_fn = curr;
	}

	return base_type;
}

void evaluate_symbol_list(struct symbol_list *list)
{
	struct symbol *sym;

	FOR_EACH_PTR(list, sym) {
		has_error &= ~ERROR_CURR_PHASE;
		evaluate_symbol(sym);
		check_duplicates(sym);
	} END_FOR_EACH_PTR(sym);
}

static struct symbol *evaluate_return_expression(struct statement *stmt)
{
	struct expression *expr = stmt->expression;
	struct symbol *fntype;

	evaluate_expression(expr);
	fntype = current_fn->ctype.base_type;
	if (!fntype || fntype == &void_ctype) {
		if (expr && expr->ctype != &void_ctype)
			expression_error(expr, "return expression in %s function", fntype?"void":"typeless");
		if (expr && Wreturn_void)
			warning(stmt->pos, "returning void-valued expression");
		return NULL;
	}

	if (!expr) {
		sparse_error(stmt->pos, "return with no return value");
		return NULL;
	}
	if (!expr->ctype)
		return NULL;
	compatible_assignment_types(expr, fntype, &stmt->expression, "return expression");
	return NULL;
}

static void evaluate_if_statement(struct statement *stmt)
{
	if (!stmt->if_conditional)
		return;

	evaluate_conditional(stmt->if_conditional, 0);
	evaluate_statement(stmt->if_true);
	evaluate_statement(stmt->if_false);
}

static void evaluate_iterator(struct statement *stmt)
{
	evaluate_symbol_list(stmt->iterator_syms);
	evaluate_conditional(stmt->iterator_pre_condition, 1);
	evaluate_conditional(stmt->iterator_post_condition,1);
	evaluate_statement(stmt->iterator_pre_statement);
	evaluate_statement(stmt->iterator_statement);
	evaluate_statement(stmt->iterator_post_statement);
}

static void verify_output_constraint(struct expression *expr, const char *constraint)
{
	switch (*constraint) {
	case '=':	/* Assignment */
	case '+':	/* Update */
		break;
	default:
		expression_error(expr, "output constraint is not an assignment constraint (\"%s\")", constraint);
	}
}

static void verify_input_constraint(struct expression *expr, const char *constraint)
{
	switch (*constraint) {
	case '=':	/* Assignment */
	case '+':	/* Update */
		expression_error(expr, "input constraint with assignment (\"%s\")", constraint);
	}
}

static void evaluate_asm_statement(struct statement *stmt)
{
	struct expression *expr;
	struct expression *op;
	struct symbol *sym;

	expr = stmt->asm_string;
	if (!expr || expr->type != EXPR_STRING) {
		sparse_error(stmt->pos, "need constant string for inline asm");
		return;
	}

	FOR_EACH_PTR(stmt->asm_outputs, op) {
		/* Identifier */

		/* Constraint */
		expr = op->constraint;
		if (!expr || expr->type != EXPR_STRING) {
			sparse_error(expr ? expr->pos : stmt->pos, "asm output constraint is not a string");
			op->constraint = NULL;
		} else
			verify_output_constraint(expr, expr->string->data);

		/* Expression */
		expr = op->expr;
		if (!evaluate_expression(expr))
			return;
		if (!lvalue_expression(expr))
			warning(expr->pos, "asm output is not an lvalue");
		evaluate_assign_to(expr, expr->ctype);
	} END_FOR_EACH_PTR(op);

	FOR_EACH_PTR(stmt->asm_inputs, op) {
		/* Identifier */

		/* Constraint */
		expr = op->constraint;
		if (!expr || expr->type != EXPR_STRING) {
			sparse_error(expr ? expr->pos : stmt->pos, "asm input constraint is not a string");
			op->constraint = NULL;
		} else
			verify_input_constraint(expr, expr->string->data);

		/* Expression */
		if (!evaluate_expression(op->expr))
			return;
	} END_FOR_EACH_PTR(op);

	FOR_EACH_PTR(stmt->asm_clobbers, expr) {
		if (!expr) {
			sparse_error(stmt->pos, "bad asm clobbers");
			return;
		}
		if (expr->type == EXPR_STRING)
			continue;
		expression_error(expr, "asm clobber is not a string");
	} END_FOR_EACH_PTR(expr);

	FOR_EACH_PTR(stmt->asm_labels, sym) {
		if (!sym || sym->type != SYM_LABEL) {
			sparse_error(stmt->pos, "bad asm label");
			return;
		}
	} END_FOR_EACH_PTR(sym);
}

static void evaluate_case_statement(struct statement *stmt)
{
	evaluate_expression(stmt->case_expression);
	evaluate_expression(stmt->case_to);
	evaluate_statement(stmt->case_statement);
}

static void check_case_type(struct expression *switch_expr,
			    struct expression *case_expr,
			    struct expression **enumcase)
{
	struct symbol *switch_type, *case_type;
	int sclass, cclass;

	if (!case_expr)
		return;

	switch_type = switch_expr->ctype;
	case_type = evaluate_expression(case_expr);

	if (!switch_type || !case_type)
		goto Bad;
	if (enumcase) {
		if (*enumcase)
			warn_for_different_enum_types(case_expr->pos, case_type, (*enumcase)->ctype);
		else if (is_enum_type(case_type))
			*enumcase = case_expr;
	}

	sclass = classify_type(switch_type, &switch_type);
	cclass = classify_type(case_type, &case_type);

	/* both should be arithmetic */
	if (!(sclass & cclass & TYPE_NUM))
		goto Bad;

	/* neither should be floating */
	if ((sclass | cclass) & TYPE_FLOAT)
		goto Bad;

	/* if neither is restricted, we are OK */
	if (!((sclass | cclass) & TYPE_RESTRICT))
		return;

	if (!restricted_binop_type(SPECIAL_EQUAL, case_expr, switch_expr,
				   cclass, sclass, case_type, switch_type)) {
		unrestrict(case_expr, cclass, &case_type);
		unrestrict(switch_expr, sclass, &switch_type);
	}
	return;

Bad:
	expression_error(case_expr, "incompatible types for 'case' statement");
}

static void evaluate_switch_statement(struct statement *stmt)
{
	struct symbol *sym;
	struct expression *enumcase = NULL;
	struct expression **enumcase_holder = &enumcase;
	struct expression *sel = stmt->switch_expression;

	evaluate_expression(sel);
	evaluate_statement(stmt->switch_statement);
	if (!sel)
		return;
	if (sel->ctype && is_enum_type(sel->ctype))
		enumcase_holder = NULL; /* Only check cases against switch */

	FOR_EACH_PTR(stmt->switch_case->symbol_list, sym) {
		struct statement *case_stmt = sym->stmt;
		check_case_type(sel, case_stmt->case_expression, enumcase_holder);
		check_case_type(sel, case_stmt->case_to, enumcase_holder);
	} END_FOR_EACH_PTR(sym);
}

static void evaluate_goto_statement(struct statement *stmt)
{
	struct symbol *label = stmt->goto_label;

	if (label && !label->stmt && label->ident && !lookup_keyword(label->ident, NS_KEYWORD))
		sparse_error(stmt->pos, "label '%s' was not declared", show_ident(label->ident));

	evaluate_expression(stmt->goto_expression);
}

struct symbol *evaluate_statement(struct statement *stmt)
{
	if (!stmt)
		return NULL;

	switch (stmt->type) {
	case STMT_DECLARATION: {
		struct symbol *s;
		FOR_EACH_PTR(stmt->declaration, s) {
			evaluate_symbol(s);
		} END_FOR_EACH_PTR(s);
		return NULL;
	}

	case STMT_RETURN:
		return evaluate_return_expression(stmt);

	case STMT_EXPRESSION:
		if (!evaluate_expression(stmt->expression))
			return NULL;
		if (stmt->expression->ctype == &null_ctype)
			stmt->expression = cast_to(stmt->expression, &ptr_ctype);
		return degenerate(stmt->expression);

	case STMT_COMPOUND: {
		struct statement *s;
		struct symbol *type = NULL;

		/* Evaluate the return symbol in the compound statement */
		evaluate_symbol(stmt->ret);

		/*
		 * Then, evaluate each statement, making the type of the
		 * compound statement be the type of the last statement
		 */
		type = evaluate_statement(stmt->args);
		FOR_EACH_PTR(stmt->stmts, s) {
			type = evaluate_statement(s);
		} END_FOR_EACH_PTR(s);
		if (!type)
			type = &void_ctype;
		return type;
	}
	case STMT_IF:
		evaluate_if_statement(stmt);
		return NULL;
	case STMT_ITERATOR:
		evaluate_iterator(stmt);
		return NULL;
	case STMT_SWITCH:
		evaluate_switch_statement(stmt);
		return NULL;
	case STMT_CASE:
		evaluate_case_statement(stmt);
		return NULL;
	case STMT_LABEL:
		return evaluate_statement(stmt->label_statement);
	case STMT_GOTO:
		evaluate_goto_statement(stmt);
		return NULL;
	case STMT_NONE:
		break;
	case STMT_ASM:
		evaluate_asm_statement(stmt);
		return NULL;
	case STMT_CONTEXT:
		evaluate_expression(stmt->expression);
		return NULL;
	case STMT_RANGE:
		evaluate_expression(stmt->range_expression);
		evaluate_expression(stmt->range_low);
		evaluate_expression(stmt->range_high);
		return NULL;
	}
	return NULL;
}
