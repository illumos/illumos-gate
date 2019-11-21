/*
 * Copyright (C) 2019 ARM.
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

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_function_hashtable.h"

static bool expr_has_memory_addr(struct expression *expr);

static DEFINE_HASHTABLE_SEARCH(search_symbol, char, char);
static DEFINE_HASHTABLE_INSERT(insert_symbol, char, char);
static struct hashtable *symbols;

static void match_assign(struct expression *expr)
{
	char *left_name;
	struct symbol *left_sym;

	left_name = expr_to_var_sym(expr->left, &left_sym);
	if (!left_name || !left_sym)
		return;

	/*
	 * Once we have spotted a symbol of interest (one that may hold
	 * an untagged memory address), we keep track of any assignments
	 * made, such that we can also treat the assigned symbol as something
	 * of interest. This tracking is limited in scope to the function.
	 */
	if (expr_has_memory_addr(expr->right))
		insert_symbol(symbols, left_name, left_name);
}

static void match_endfunc(struct symbol *sym)
{
	destroy_function_hashtable(symbols);
	symbols = create_function_hashtable(4000);
}

static bool expr_has_untagged_symbol(struct expression *expr)
{
	char *name;
	struct symbol *sym;

	if (expr->type != EXPR_SYMBOL)
		return false;

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		return false;

	/* See if this is something we already know is of interest */
	if (search_symbol(symbols, name))
		return true;

	return false;
}

static bool expr_has_untagged_member(struct expression *expr)
{
	if (expr->type != EXPR_DEREF)
		return false;

	if (!strcmp(expr->member->name, "vm_start") ||
	    !strcmp(expr->member->name, "vm_end") ||
	    !strcmp(expr->member->name, "addr_limit"))
		return true;

	return false;
}

static bool expr_has_macro_with_name(struct expression *expr, const char *macro_name)
{
	char *name;

	name = get_macro_name(expr->pos);
	return (name && !strcmp(name, macro_name));
}

static bool expr_has_untagged_macro(struct expression *expr)
{
	if (expr_has_macro_with_name(expr, "PAGE_SIZE") ||
	    expr_has_macro_with_name(expr, "PAGE_MASK") ||
	    expr_has_macro_with_name(expr, "TASK_SIZE"))
		return true;

	/**
	 * We can't detect a marco (such as PAGE_MASK) inside another macro
	 * such as offset_in_page, therefore we have to detect the outer macro
	 * instead.
	 */
	if (expr_has_macro_with_name(expr, "offset_in_page"))
		return true;

	return false;
}

/*
 * Identify expressions that contain memory addresses, in the future
 * we may use annotations on symbols or function parameters.
 */
static bool expr_has_memory_addr(struct expression *expr)
{
	if (expr->type == EXPR_PREOP || expr->type == EXPR_POSTOP)
		expr = strip_expr(expr->unop);

	if (expr_has_untagged_member(expr))
		return true;

	if (expr_has_untagged_macro(expr))
		return true;

	if (expr_has_untagged_symbol(expr))
		return true;

	return false;
}

int rl_is_larger_or_equal(struct range_list *rl, sval_t sval)
{
	struct data_range *tmp;

	FOR_EACH_PTR(rl, tmp) {
		if (sval_cmp(tmp->max, sval) >= 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

int rl_range_has_min_value(struct range_list *rl, sval_t sval)
{
	struct data_range *tmp;

	FOR_EACH_PTR(rl, tmp) {
		if (!sval_cmp(tmp->min, sval)) {
			return 1;
		}
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

static bool rl_is_tagged(struct range_list *rl)
{
	sval_t invalid = { .type = &ullong_ctype, .value = (1ULL << 56) };
	sval_t invalid_kernel = { .type = &ullong_ctype, .value = (0xff8ULL << 52) };

	/*
	 * We only care for tagged addresses, thus ignore anything where the
	 * ranges of potential values cannot possibly have any of the top byte
	 * bits set.
	 */
	if (!rl_is_larger_or_equal(rl, invalid))
		return false;

	/*
	 * Tagged addresses are untagged in the kernel by using sign_extend64 in
	 * the untagged_addr macro. For userspace addresses bit 55 will always
	 * be 0 and thus this has the effect of clearing the top byte. However
	 * for kernel addresses this is not true and the top bits end up set to
	 * all 1s. The untagged_addr macro results in leaving a gap in the range
	 * of possible values which can exist, thus let's look for a tell-tale
	 * range which starts from (0xff8ULL << 52).
	 */
	if (rl_range_has_min_value(rl, invalid_kernel))
		return false;

	return true;
}

static void match_condition(struct expression *expr)
{
	struct range_list *rl = NULL;
	struct expression *val = NULL;
        struct symbol *type;
	char *var_name;

	/*
	 * Match instances where something is compared against something
	 * else - we include binary operators as these are commonly used
	 * to make a comparison, e.g. if (start & ~PAGE_MASK).
	 */
	if (expr->type != EXPR_COMPARE &&
	    expr->type != EXPR_BINOP)
		return;

	/*
	 * Look on both sides of the comparison for something that shouldn't
	 * be compared with a tagged address, e.g. macros such as PAGE_MASK
	 * or struct members named .vm_start. 
	 */
	if (expr_has_memory_addr(expr->left))
		val = expr->right;

	/*
	 * The macro 'offset_in_page' has the PAGE_MASK macro inside it, this
	 * results in 'expr_has_memory_addr' returning true for both sides. To
	 * work around this we assume PAGE_MASK (or similar) is on the right
	 * side, thus we do the following test last.
	 */
	if (expr_has_memory_addr(expr->right))
		val = expr->left;

	if (!val)
		return;

	/* We only care about memory addresses which are 64 bits */
        type = get_type(val);
	if (!type || type_bits(type) != 64)
		return;

	/* We only care for comparison against user originated data */
	if (!get_user_rl(val, &rl))
		return;

	/* We only care for tagged addresses */
	if (!rl_is_tagged(rl))
		return;

	/* Finally, we believe we may have spotted a risky comparison */
	var_name = expr_to_var(val);
	if (var_name)
		sm_warning("comparison of a potentially tagged address (%s, %d, %s)", get_function(), get_param_num(val), var_name);
}

void check_arm64_tagged(int id)
{
	char *arch;

	if (option_project != PROJ_KERNEL)
		return;

	/* Limit to aarch64 */
	arch = getenv("ARCH");
	if (!arch || strcmp(arch, "arm64"))
		return;

	symbols = create_function_hashtable(4000);

	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_endfunc, END_FUNC_HOOK);
}
