/*
 * builtin evaluation & expansion.
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
 */

#include "expression.h"
#include "expand.h"
#include "symbol.h"
#include "compat/bswap.h"

static int evaluate_to_int_const_expr(struct expression *expr)
{
	expr->ctype = &int_ctype;
	expr->flags |= CEF_SET_ICE;
	return 1;
}

static int evaluate_pure_unop(struct expression *expr)
{
	struct expression *arg = first_expression(expr->args);
	int flags = arg->flags;

	/*
	 * Allow such functions with a constant integer expression
	 * argument to be treated as a *constant* integer.
	 * This allow us to use them in switch() { case ...:
	 */
	flags |= (flags & CEF_ICE) ? CEF_SET_INT : 0;
	expr->flags = flags;
	return 1;
}


static int evaluate_expect(struct expression *expr)
{
	/* Should we evaluate it to return the type of the first argument? */
	expr->ctype = &int_ctype;
	return 1;
}

static int arguments_choose(struct expression *expr)
{
	struct expression_list *arglist = expr->args;
	struct expression *arg;
	int i = 0;

	FOR_EACH_PTR (arglist, arg) {
		if (!evaluate_expression(arg))
			return 0;
		i++;
	} END_FOR_EACH_PTR(arg);
	if (i < 3) {
		sparse_error(expr->pos,
			     "not enough arguments for __builtin_choose_expr");
		return 0;
	} if (i > 3) {
		sparse_error(expr->pos,
			     "too many arguments for __builtin_choose_expr");
		return 0;
	}
	return 1;
}

static int evaluate_choose(struct expression *expr)
{
	struct expression_list *list = expr->args;
	struct expression *arg, *args[3];
	int n = 0;

	/* there will be exactly 3; we'd already verified that */
	FOR_EACH_PTR(list, arg) {
		args[n++] = arg;
	} END_FOR_EACH_PTR(arg);

	*expr = get_expression_value(args[0]) ? *args[1] : *args[2];

	return 1;
}

static int expand_expect(struct expression *expr, int cost)
{
	struct expression *arg = first_ptr_list((struct ptr_list *) expr->args);

	if (arg)
		*expr = *arg;
	return 0;
}

/*
 * __builtin_warning() has type "int" and always returns 1,
 * so that you can use it in conditionals or whatever
 */
static int expand_warning(struct expression *expr, int cost)
{
	struct expression *arg;
	struct expression_list *arglist = expr->args;

	FOR_EACH_PTR (arglist, arg) {
		/*
		 * Constant strings get printed out as a warning. By the
		 * time we get here, the EXPR_STRING has been fully 
		 * evaluated, so by now it's an anonymous symbol with a
		 * string initializer.
		 *
		 * Just for the heck of it, allow any constant string
		 * symbol.
		 */
		if (arg->type == EXPR_SYMBOL) {
			struct symbol *sym = arg->symbol;
			if (sym->initializer && sym->initializer->type == EXPR_STRING) {
				struct string *string = sym->initializer->string;
				warning(expr->pos, "%*s", string->length-1, string->data);
			}
			continue;
		}

		/*
		 * Any other argument is a conditional. If it's
		 * non-constant, or it is false, we exit and do
		 * not print any warning.
		 */
		if (arg->type != EXPR_VALUE)
			goto out;
		if (!arg->value)
			goto out;
	} END_FOR_EACH_PTR(arg);
out:
	expr->type = EXPR_VALUE;
	expr->value = 1;
	expr->taint = 0;
	return 0;
}

/* The arguments are constant if the cost of all of them is zero */
static int expand_constant_p(struct expression *expr, int cost)
{
	expr->type = EXPR_VALUE;
	expr->value = !cost;
	expr->taint = 0;
	return 0;
}

/* The arguments are safe, if their cost is less than SIDE_EFFECTS */
static int expand_safe_p(struct expression *expr, int cost)
{
	expr->type = EXPR_VALUE;
	expr->value = (cost < SIDE_EFFECTS);
	expr->taint = 0;
	return 0;
}

static struct symbol_op constant_p_op = {
	.evaluate = evaluate_to_int_const_expr,
	.expand = expand_constant_p
};

static struct symbol_op safe_p_op = {
	.evaluate = evaluate_to_int_const_expr,
	.expand = expand_safe_p
};

static struct symbol_op warning_op = {
	.evaluate = evaluate_to_int_const_expr,
	.expand = expand_warning
};

static struct symbol_op expect_op = {
	.evaluate = evaluate_expect,
	.expand = expand_expect
};

static struct symbol_op choose_op = {
	.evaluate = evaluate_choose,
	.args = arguments_choose,
};

/* The argument is constant and valid if the cost is zero */
static int expand_bswap(struct expression *expr, int cost)
{
	struct expression *arg;
	long long val;

	if (cost)
		return cost;

	/* the arguments number & type have already been checked */
	arg = first_expression(expr->args);
	val = get_expression_value_silent(arg);
	switch (expr->ctype->bit_size) {
	case 16: expr->value = bswap16(val); break;
	case 32: expr->value = bswap32(val); break;
	case 64: expr->value = bswap64(val); break;
	default: /* impossible error */
		return SIDE_EFFECTS;
	}

	expr->type = EXPR_VALUE;
	expr->taint = 0;
	return 0;
}

static struct symbol_op bswap_op = {
	.evaluate = evaluate_pure_unop,
	.expand = expand_bswap,
};


/*
 * Builtin functions
 */
static struct symbol builtin_fn_type = { .type = SYM_FN /* , .variadic =1 */ };
static struct sym_init {
	const char *name;
	struct symbol *base_type;
	unsigned int modifiers;
	struct symbol_op *op;
} builtins_table[] = {
	{ "__builtin_constant_p", &builtin_fn_type, MOD_TOPLEVEL, &constant_p_op },
	{ "__builtin_safe_p", &builtin_fn_type, MOD_TOPLEVEL, &safe_p_op },
	{ "__builtin_warning", &builtin_fn_type, MOD_TOPLEVEL, &warning_op },
	{ "__builtin_expect", &builtin_fn_type, MOD_TOPLEVEL, &expect_op },
	{ "__builtin_choose_expr", &builtin_fn_type, MOD_TOPLEVEL, &choose_op },
	{ "__builtin_bswap16", NULL, MOD_TOPLEVEL, &bswap_op },
	{ "__builtin_bswap32", NULL, MOD_TOPLEVEL, &bswap_op },
	{ "__builtin_bswap64", NULL, MOD_TOPLEVEL, &bswap_op },
	{ NULL,		NULL,		0 }
};

void init_builtins(int stream)
{
	struct sym_init *ptr;

	builtin_fn_type.variadic = 1;
	for (ptr = builtins_table; ptr->name; ptr++) {
		struct symbol *sym;
		sym = create_symbol(stream, ptr->name, SYM_NODE, NS_SYMBOL);
		sym->ctype.base_type = ptr->base_type;
		sym->ctype.modifiers = ptr->modifiers;
		sym->op = ptr->op;
	}
}
