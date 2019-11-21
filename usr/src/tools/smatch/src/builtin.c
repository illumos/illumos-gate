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
#include "evaluate.h"
#include "expand.h"
#include "symbol.h"
#include "compat/bswap.h"
#include <stdarg.h>

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

/*
 * eval_args - check the number of arguments and evaluate them.
 */
static int eval_args(struct expression *expr, int n)
{
	struct expression *arg;
	struct symbol *sym;
	const char *msg;
	int rc = 1;

	FOR_EACH_PTR(expr->args, arg) {
		if (n-- == 0) {
			msg = "too many arguments";
			goto error;
		}
		if (!evaluate_expression(arg))
			rc = 0;
	} END_FOR_EACH_PTR(arg);
	if (n > 0) {
		msg = "not enough arguments";
		goto error;
	}
	return rc;

error:
	sym = expr->fn->ctype;
	expression_error(expr, "%s for %s", msg, show_ident(sym->ident));
	return 0;
}

static int args_triadic(struct expression *expr)
{
	return eval_args(expr, 3);
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
	.expand = expand_expect
};

static struct symbol_op choose_op = {
	.args = args_triadic,
	.evaluate = evaluate_choose,
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


static int evaluate_fp_unop(struct expression *expr)
{
	struct expression *arg;

	if (!eval_args(expr, 1))
		return 0;

	arg = first_expression(expr->args);
	if (!is_float_type(arg->ctype)) {
		expression_error(expr, "non-floating-point argument in call to %s()",
			show_ident(expr->fn->ctype->ident));
		return 0;
	}
	return 1;
}

static struct symbol_op fp_unop_op = {
	.evaluate = evaluate_fp_unop,
};


static int evaluate_overflow_gen(struct expression *expr, int ptr)
{
	struct expression *arg;
	int n = 0;

	/* there will be exactly 3; we'd already verified that */
	FOR_EACH_PTR(expr->args, arg) {
		struct symbol *type;

		n++;
		if (!arg || !(type = arg->ctype))
			return 0;
		// 1st & 2nd args must be a basic integer type
		// 3rd arg must be a pointer to such a type.
		if (n == 3 && ptr) {
			if (type->type == SYM_NODE)
				type = type->ctype.base_type;
			if (!type)
				return 0;
			if (type->type != SYM_PTR)
				goto err;
			type = type->ctype.base_type;
			if (!type)
				return 0;
		}
		if (type->type == SYM_NODE)
			type = type->ctype.base_type;
		if (!type)
			return 0;
		if (type->ctype.base_type != &int_type || type == &bool_ctype)
			goto err;
	} END_FOR_EACH_PTR(arg);

	// the builtin returns a bool
	expr->ctype = &bool_ctype;
	return 1;

err:
	sparse_error(arg->pos, "invalid type for argument %d:", n);
	info(arg->pos, "        %s", show_typename(arg->ctype));
	expr->ctype = &bad_ctype;
	return 0;
}

static int evaluate_overflow(struct expression *expr)
{
	return evaluate_overflow_gen(expr, 1);
}

static struct symbol_op overflow_op = {
	.args = args_triadic,
	.evaluate = evaluate_overflow,
};

static int evaluate_overflow_p(struct expression *expr)
{
	return evaluate_overflow_gen(expr, 0);
}

static struct symbol_op overflow_p_op = {
	.args = args_triadic,
	.evaluate = evaluate_overflow_p,
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
	{ "__builtin_bswap16", &builtin_fn_type, MOD_TOPLEVEL, &bswap_op },
	{ "__builtin_bswap32", &builtin_fn_type, MOD_TOPLEVEL, &bswap_op },
	{ "__builtin_bswap64", &builtin_fn_type, MOD_TOPLEVEL, &bswap_op },
	{ "__builtin_isfinite", &builtin_fn_type, MOD_TOPLEVEL, &fp_unop_op },
	{ "__builtin_isinf", &builtin_fn_type, MOD_TOPLEVEL, &fp_unop_op },
	{ "__builtin_isinf_sign", &builtin_fn_type, MOD_TOPLEVEL, &fp_unop_op },
	{ "__builtin_isnan", &builtin_fn_type, MOD_TOPLEVEL, &fp_unop_op },
	{ "__builtin_isnormal", &builtin_fn_type, MOD_TOPLEVEL, &fp_unop_op },
	{ "__builtin_signbit", &builtin_fn_type, MOD_TOPLEVEL, &fp_unop_op },
	{ "__builtin_add_overflow", &builtin_fn_type, MOD_TOPLEVEL, &overflow_op },
	{ "__builtin_sub_overflow", &builtin_fn_type, MOD_TOPLEVEL, &overflow_op },
	{ "__builtin_mul_overflow", &builtin_fn_type, MOD_TOPLEVEL, &overflow_op },
	{ "__builtin_add_overflow_p", &builtin_fn_type, MOD_TOPLEVEL, &overflow_p_op },
	{ "__builtin_sub_overflow_p", &builtin_fn_type, MOD_TOPLEVEL, &overflow_p_op },
	{ "__builtin_mul_overflow_p", &builtin_fn_type, MOD_TOPLEVEL, &overflow_p_op },
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
		sym->builtin = 1;
	}
}

static void declare_builtin(const char *name, struct symbol *rtype, int variadic, ...)
{
	int stream = 0;			// FIXME
	struct symbol *sym = create_symbol(stream, name, SYM_NODE, NS_SYMBOL);
	struct symbol *fun = alloc_symbol(sym->pos, SYM_FN);
	struct symbol *arg;
	va_list args;

	sym->ctype.base_type = fun;
	sym->ctype.modifiers = MOD_TOPLEVEL;
	sym->builtin = 1;

	fun->ctype.base_type = rtype;
	fun->variadic = variadic;

	va_start(args, variadic);
	while ((arg = va_arg(args, struct symbol *))) {
		struct symbol *anode = alloc_symbol(sym->pos, SYM_NODE);
		anode->ctype.base_type = arg;
		add_symbol(&fun->arguments, anode);
	}
	va_end(args);
}

void declare_builtins(void)
{
	struct symbol *va_list_ctype = &ptr_ctype;

	declare_builtin("__builtin_abort", &void_ctype, 0, NULL);
	declare_builtin("__builtin_abs", &int_ctype , 0, &int_ctype, NULL);
	declare_builtin("__builtin_alloca", &ptr_ctype, 0, size_t_ctype, NULL);
	declare_builtin("__builtin_alpha_cmpbge", &long_ctype, 0, &long_ctype, &long_ctype, NULL);
	declare_builtin("__builtin_alpha_extbl", &long_ctype, 0, &long_ctype, &long_ctype, NULL);
	declare_builtin("__builtin_alpha_extwl", &long_ctype, 0, &long_ctype, &long_ctype, NULL);
	declare_builtin("__builtin_alpha_insbl", &long_ctype, 0, &long_ctype, &long_ctype, NULL);
	declare_builtin("__builtin_alpha_inslh", &long_ctype, 0, &long_ctype, &long_ctype, NULL);
	declare_builtin("__builtin_alpha_insql", &long_ctype, 0, &long_ctype, &long_ctype, NULL);
	declare_builtin("__builtin_alpha_inswl", &long_ctype, 0, &long_ctype, &long_ctype, NULL);
	declare_builtin("__builtin_bcmp", &int_ctype , 0, &const_ptr_ctype, &const_ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_bcopy", &void_ctype, 0, &const_ptr_ctype, &ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_bswap16", &ushort_ctype, 0, &ushort_ctype, NULL);
	declare_builtin("__builtin_bswap32", &uint_ctype, 0, &uint_ctype, NULL);
	declare_builtin("__builtin_bswap64", &ullong_ctype, 0, &ullong_ctype, NULL);
	declare_builtin("__builtin_bzero", &void_ctype, 0, &ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_calloc", &ptr_ctype, 0, size_t_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_clrsb", &int_ctype, 0, &int_ctype, NULL);
	declare_builtin("__builtin_clrsbl", &int_ctype, 0, &long_ctype, NULL);
	declare_builtin("__builtin_clrsbll", &int_ctype, 0, &llong_ctype, NULL);
	declare_builtin("__builtin_clz", &int_ctype, 0, &int_ctype, NULL);
	declare_builtin("__builtin_clzl", &int_ctype, 0, &long_ctype, NULL);
	declare_builtin("__builtin_clzll", &int_ctype, 0, &llong_ctype, NULL);
	declare_builtin("__builtin_ctz", &int_ctype, 0, &int_ctype, NULL);
	declare_builtin("__builtin_ctzl", &int_ctype, 0, &long_ctype, NULL);
	declare_builtin("__builtin_ctzll", &int_ctype, 0, &llong_ctype, NULL);
	declare_builtin("__builtin_exit", &void_ctype, 0, &int_ctype, NULL);
	declare_builtin("__builtin_expect", &long_ctype, 0, &long_ctype ,&long_ctype, NULL);
	declare_builtin("__builtin_extract_return_addr", &ptr_ctype, 0, &ptr_ctype, NULL);
	declare_builtin("__builtin_fabs", &double_ctype, 0, &double_ctype, NULL);
	declare_builtin("__builtin_ffs", &int_ctype, 0, &int_ctype, NULL);
	declare_builtin("__builtin_ffsl", &int_ctype, 0, &long_ctype, NULL);
	declare_builtin("__builtin_ffsll", &int_ctype, 0, &llong_ctype, NULL);
	declare_builtin("__builtin_frame_address", &ptr_ctype, 0, &uint_ctype, NULL);
	declare_builtin("__builtin_free", &void_ctype, 0, &ptr_ctype, NULL);
	declare_builtin("__builtin_huge_val", &double_ctype, 0, NULL);
	declare_builtin("__builtin_huge_valf", &float_ctype, 0, NULL);
	declare_builtin("__builtin_huge_vall", &ldouble_ctype, 0, NULL);
	declare_builtin("__builtin_index", &string_ctype, 0, &const_string_ctype, &int_ctype, NULL);
	declare_builtin("__builtin_inf", &double_ctype, 0, NULL);
	declare_builtin("__builtin_inff", &float_ctype, 0, NULL);
	declare_builtin("__builtin_infl", &ldouble_ctype, 0, NULL);
	declare_builtin("__builtin_isfinite", &int_ctype, 1, NULL);
	declare_builtin("__builtin_isgreater", &int_ctype, 0, &float_ctype, &float_ctype, NULL);
	declare_builtin("__builtin_isgreaterequal", &int_ctype, 0, &float_ctype, &float_ctype, NULL);
	declare_builtin("__builtin_isinf", &int_ctype, 1, NULL);
	declare_builtin("__builtin_isinf_sign", &int_ctype, 1, NULL);
	declare_builtin("__builtin_isless", &int_ctype, 0, &float_ctype, &float_ctype, NULL);
	declare_builtin("__builtin_islessequal", &int_ctype, 0, &float_ctype, &float_ctype, NULL);
	declare_builtin("__builtin_islessgreater", &int_ctype, 0, &float_ctype, &float_ctype, NULL);
	declare_builtin("__builtin_isnan", &int_ctype, 1, NULL);
	declare_builtin("__builtin_isnormal", &int_ctype, 1, NULL);
	declare_builtin("__builtin_isunordered", &int_ctype, 0, &float_ctype, &float_ctype, NULL);
	declare_builtin("__builtin_labs", &long_ctype, 0, &long_ctype, NULL);
	declare_builtin("__builtin_llabs", &llong_ctype, 0, &llong_ctype, NULL);
	declare_builtin("__builtin_malloc", &ptr_ctype, 0, size_t_ctype, NULL);
	declare_builtin("__builtin_memchr", &ptr_ctype, 0, &const_ptr_ctype, &int_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_memcmp", &int_ctype, 0, &const_ptr_ctype, &const_ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_memcpy", &ptr_ctype, 0, &ptr_ctype, &const_ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_memmove", &ptr_ctype, 0, &ptr_ctype, &const_ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_mempcpy", &ptr_ctype, 0, &ptr_ctype, &const_ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_memset", &ptr_ctype, 0, &ptr_ctype, &int_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_nan", &double_ctype, 0, &const_string_ctype, NULL);
	declare_builtin("__builtin_nanf", &float_ctype, 0, &const_string_ctype, NULL);
	declare_builtin("__builtin_nanl", &ldouble_ctype, 0, &const_string_ctype, NULL);
	declare_builtin("__builtin_object_size", size_t_ctype, 0, &const_ptr_ctype, &int_ctype, NULL);
	declare_builtin("__builtin_parity", &int_ctype, 0, &uint_ctype, NULL);
	declare_builtin("__builtin_parityl", &int_ctype, 0, &ulong_ctype, NULL);
	declare_builtin("__builtin_parityll", &int_ctype, 0, &ullong_ctype, NULL);
	declare_builtin("__builtin_popcount", &int_ctype, 0, &uint_ctype, NULL);
	declare_builtin("__builtin_popcountl", &int_ctype, 0, &ulong_ctype, NULL);
	declare_builtin("__builtin_popcountll", &int_ctype, 0, &ullong_ctype, NULL);
	declare_builtin("__builtin_prefetch", &void_ctype, 1, &const_ptr_ctype, NULL);
	declare_builtin("__builtin_printf", &int_ctype, 1, &const_string_ctype, NULL);
	declare_builtin("__builtin_puts", &int_ctype, 0, &const_string_ctype, NULL);
	declare_builtin("__builtin_realloc", &ptr_ctype, 0, &ptr_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_return_address", &ptr_ctype, 0, &uint_ctype, NULL);
	declare_builtin("__builtin_rindex", &string_ctype, 0, &const_string_ctype, &int_ctype, NULL);
	declare_builtin("__builtin_sadd_overflow", &bool_ctype, 0, &int_ctype, &int_ctype, &int_ptr_ctype, NULL);
	declare_builtin("__builtin_saddl_overflow", &bool_ctype, 0, &long_ctype, &long_ctype, &long_ptr_ctype, NULL);
	declare_builtin("__builtin_saddll_overflow", &bool_ctype, 0, &llong_ctype, &llong_ctype, &llong_ptr_ctype, NULL);
	declare_builtin("__builtin_signbit", &int_ctype, 1, NULL);
	declare_builtin("__builtin_smul_overflow", &bool_ctype, 0, &int_ctype, &int_ctype, &int_ptr_ctype, NULL);
	declare_builtin("__builtin_smull_overflow", &bool_ctype, 0, &long_ctype, &long_ctype, &long_ptr_ctype, NULL);
	declare_builtin("__builtin_smulll_overflow", &bool_ctype, 0, &llong_ctype, &llong_ctype, &llong_ptr_ctype, NULL);
	declare_builtin("__builtin_snprintf", &int_ctype, 1, &string_ctype, size_t_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_sprintf", &int_ctype, 1, &string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_ssub_overflow", &bool_ctype, 0, &int_ctype, &int_ctype, &int_ptr_ctype, NULL);
	declare_builtin("__builtin_ssubl_overflow", &bool_ctype, 0, &long_ctype, &long_ctype, &long_ptr_ctype, NULL);
	declare_builtin("__builtin_ssubll_overflow", &bool_ctype, 0, &llong_ctype, &llong_ctype, &llong_ptr_ctype, NULL);
	declare_builtin("__builtin_stpcpy", &string_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_stpncpy", &string_ctype, 0, &const_string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_strcasecmp", &int_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strcasestr", &string_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strcat", &string_ctype, 0, &string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strchr", &string_ctype, 0, &const_string_ctype, &int_ctype, NULL);
	declare_builtin("__builtin_strcmp", &int_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strcpy", &string_ctype, 0, &string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strcspn", size_t_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strdup", &string_ctype, 0, &const_string_ctype, NULL);
	declare_builtin("__builtin_strlen", size_t_ctype, 0, &const_string_ctype, NULL);
	declare_builtin("__builtin_strncasecmp", &int_ctype, 0, &const_string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_strncat", &string_ctype, 0, &string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_strncmp", &int_ctype, 0, &const_string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_strncpy", &string_ctype, 0, &string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_strndup", &string_ctype, 0, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_strnstr", &string_ctype, 0, &const_string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin_strpbrk", &string_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strrchr", &string_ctype, 0, &const_string_ctype, &int_ctype, NULL);
	declare_builtin("__builtin_strspn", size_t_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_strstr", &string_ctype, 0, &const_string_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin_trap", &void_ctype, 0, NULL);
	declare_builtin("__builtin_uadd_overflow", &bool_ctype, 0, &uint_ctype, &uint_ctype, &uint_ptr_ctype, NULL);
	declare_builtin("__builtin_uaddl_overflow", &bool_ctype, 0, &ulong_ctype, &ulong_ctype, &ulong_ptr_ctype, NULL);
	declare_builtin("__builtin_uaddll_overflow", &bool_ctype, 0, &ullong_ctype, &ullong_ctype, &ullong_ptr_ctype, NULL);
	declare_builtin("__builtin_umul_overflow", &bool_ctype, 0, &uint_ctype, &uint_ctype, &uint_ptr_ctype, NULL);
	declare_builtin("__builtin_umull_overflow", &bool_ctype, 0, &ulong_ctype, &ulong_ctype, &ulong_ptr_ctype, NULL);
	declare_builtin("__builtin_umulll_overflow", &bool_ctype, 0, &ullong_ctype, &ullong_ctype, &ullong_ptr_ctype, NULL);
	declare_builtin("__builtin_unreachable", &void_ctype, 0, NULL);
	declare_builtin("__builtin_usub_overflow", &bool_ctype, 0, &uint_ctype, &uint_ctype, &uint_ptr_ctype, NULL);
	declare_builtin("__builtin_usubl_overflow", &bool_ctype, 0, &ulong_ctype, &ulong_ctype, &ulong_ptr_ctype, NULL);
	declare_builtin("__builtin_usubll_overflow", &bool_ctype, 0, &ullong_ctype, &ullong_ctype, &ullong_ptr_ctype, NULL);
	declare_builtin("__builtin_va_arg_pack_len", size_t_ctype, 0, NULL);
	declare_builtin("__builtin_vprintf", &int_ctype, 0, &const_string_ctype, va_list_ctype, NULL);
	declare_builtin("__builtin_vsnprintf", &int_ctype, 0, &string_ctype, size_t_ctype, &const_string_ctype, va_list_ctype, NULL);
	declare_builtin("__builtin_vsprintf", &int_ctype, 0, &string_ctype, &const_string_ctype, va_list_ctype, NULL);

	declare_builtin("__builtin___memcpy_chk", &ptr_ctype, 0, &ptr_ctype, &const_ptr_ctype, size_t_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___memmove_chk", &ptr_ctype, 0, &ptr_ctype, &const_ptr_ctype, size_t_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___mempcpy_chk", &ptr_ctype, 0, &ptr_ctype, &const_ptr_ctype, size_t_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___memset_chk", &ptr_ctype, 0, &ptr_ctype, &int_ctype, size_t_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___snprintf_chk", &int_ctype, 1, &string_ctype, size_t_ctype, &int_ctype , size_t_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin___sprintf_chk", &int_ctype, 1, &string_ctype, &int_ctype, size_t_ctype, &const_string_ctype, NULL);
	declare_builtin("__builtin___stpcpy_chk", &string_ctype, 0, &string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___strcat_chk", &string_ctype, 0, &string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___strcpy_chk", &string_ctype, 0, &string_ctype, &const_string_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___strncat_chk", &string_ctype, 0, &string_ctype, &const_string_ctype, size_t_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___strncpy_chk", &string_ctype, 0, &string_ctype, &const_string_ctype, size_t_ctype, size_t_ctype, NULL);
	declare_builtin("__builtin___vsnprintf_chk", &int_ctype, 0, &string_ctype, size_t_ctype, &int_ctype, size_t_ctype, &const_string_ctype, va_list_ctype, NULL);
	declare_builtin("__builtin___vsprintf_chk", &int_ctype, 0, &string_ctype, &int_ctype, size_t_ctype, &const_string_ctype, va_list_ctype, NULL);

	declare_builtin("__sync_add_and_fetch", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_and_and_fetch", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_bool_compare_and_swap", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_fetch_and_add", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_fetch_and_and", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_fetch_and_nand", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_fetch_and_or", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_fetch_and_sub", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_fetch_and_xor", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_lock_release", &void_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_lock_test_and_set", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_nand_and_fetch", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_or_and_fetch", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_sub_and_fetch", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_synchronize", &void_ctype, 0, NULL);
	declare_builtin("__sync_val_compare_and_swap", &int_ctype, 1, &ptr_ctype, NULL);
	declare_builtin("__sync_xor_and_fetch", &int_ctype, 1, &ptr_ctype, NULL);

	// Blackfin-specific stuff
	declare_builtin("__builtin_bfin_csync", &void_ctype, 0, NULL);
	declare_builtin("__builtin_bfin_ssync", &void_ctype, 0, NULL);
	declare_builtin("__builtin_bfin_norm_fr1x32", &int_ctype, 0, &int_ctype, NULL);
}
