/*
 * Copyright (C) 2015 Oracle.
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
#include "smatch_slist.h"
#include "smatch_extra.h"

static bool is_non_null_array(struct expression *expr)
{
	struct symbol *type;
	struct symbol *sym;
	struct symbol *tmp;
	int i;

	type = get_type(expr);
	if (!type || type->type != SYM_ARRAY)
		return 0;
	if (expr->type == EXPR_SYMBOL)
		return 1;
	if (implied_not_equal(expr, 0))
		return 1;

	/* verify that it's not the first member of the struct */
	if (expr->type != EXPR_DEREF || !expr->member)
		return 0;
	sym = expr_to_sym(expr);
	if (!sym)
		return 0;
	type = get_real_base_type(sym);
	if (!type || type->type != SYM_PTR)
		return 0;
	type = get_real_base_type(type);
	if (type->type != SYM_STRUCT)
		return 0;

	i = 0;
	FOR_EACH_PTR(type->symbol_list, tmp) {
		i++;
		if (!tmp->ident)
			continue;
		if (strcmp(expr->member->name, tmp->ident->name) == 0) {
			if (i == 1)
				return 0;
			return 1;
		}
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

int get_member_offset(struct symbol *type, const char *member_name)
{
	struct symbol *tmp;
	int offset;

	if (!type || type->type != SYM_STRUCT)
		return -1;

	offset = 0;
	FOR_EACH_PTR(type->symbol_list, tmp) {
		offset = ALIGN(offset, tmp->ctype.alignment);
		if (tmp->ident &&
		    strcmp(member_name, tmp->ident->name) == 0) {
			return offset;
		}
		offset += type_bytes(tmp);
	} END_FOR_EACH_PTR(tmp);
	return -1;
}

int get_member_offset_from_deref(struct expression *expr)
{
	struct symbol *type;
	struct ident *member;
	int offset;

	if (expr->type != EXPR_DEREF)  /* hopefully, this doesn't happen */
		return -1;

	if (expr->member_offset >= 0)
		return expr->member_offset;

	member = expr->member;
	if (!member)
		return -1;

	type = get_type(expr->deref);
	if (!type || type->type != SYM_STRUCT)
		return -1;

	offset = get_member_offset(type, member->name);
	if (offset >= 0)
		expr->member_offset = offset;
	return offset;
}

static struct range_list *filter_unknown_negatives(struct range_list *rl)
{
	struct data_range *first;
	struct range_list *filter = NULL;

	first = first_ptr_list((struct ptr_list *)rl);

	if (sval_is_min(first->min) &&
	    sval_is_negative(first->max) &&
	    first->max.value == -1) {
		add_ptr_list(&filter, first);
		return rl_filter(rl, filter);
	}

	return rl;
}

static void add_offset_to_pointer(struct range_list **rl, int offset)
{
	sval_t min, max, remove, sval;
	struct range_list *orig = *rl;

	/*
	 * Ha ha.  Treating zero as a special case means I'm correct at least a
	 * tiny fraction of the time.  Which is better than nothing.
	 *
	 */
	if (offset == 0)
		return;

	/*
	 * This function doesn't necessarily work how you might expect...
	 *
	 * Say you have s64min-(-1),1-s64max and you add 8 then I guess what
	 * we want to say is maybe something like 9-s64max.  This shows that the
	 * min it could be is 9 which is potentially useful information.  But
	 * if we start with (-12),5000000-57777777 and we add 8 then we'd want
	 * the result to be (-4),5000008-57777777 but (-4),5000000-57777777 is
	 * also probably acceptable.  If you start with s64min-s64max then the
	 * result should be 8-s64max.
	 *
	 */

	/* We do the math on void pointer type, because this isn't "&v + 16" it
	 * is &v->sixteenth_byte.
	 */
	orig = cast_rl(&ptr_ctype, orig);
	min = sval_type_min(&ptr_ctype);
	min.value = offset;
	max = sval_type_max(&ptr_ctype);

	if (!orig || is_whole_rl(orig)) {
		*rl = alloc_rl(min, max);
		return;
	}

	orig = filter_unknown_negatives(orig);
	/*
	 * FIXME:  This is not really accurate but we're a bit screwed anyway
	 * when we start doing pointer math with error pointers so it's probably
	 * not important.
	 *
	 */
	if (sval_is_negative(rl_min(orig)))
		return;

	/* no wrap around */
	max.uvalue = rl_max(orig).uvalue;
	if (max.uvalue > sval_type_max(&ptr_ctype).uvalue - offset) {
		remove = sval_type_max(&ptr_ctype);
		remove.uvalue -= offset;
		orig = remove_range(orig, remove, max);
	}

	sval.type = &int_ctype;
	sval.value = offset;

	*rl = rl_binop(orig, '+', alloc_rl(sval, sval));
}

static struct range_list *where_allocated_rl(struct symbol *sym)
{
	if (!sym)
		return NULL;

	if (sym->ctype.modifiers & (MOD_TOPLEVEL | MOD_STATIC)) {
		if (sym->initializer)
			return alloc_rl(data_seg_min, data_seg_max);
		else
			return alloc_rl(bss_seg_min, bss_seg_max);
	}
	return alloc_rl(stack_seg_min, stack_seg_max);
}

int get_address_rl(struct expression *expr, struct range_list **rl)
{
	expr = strip_expr(expr);
	if (!expr)
		return 0;

	if (expr->type == EXPR_STRING) {
		*rl = alloc_rl(text_seg_min, text_seg_max);
		return 1;
	}

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		struct expression *unop;

		unop = strip_expr(expr->unop);
		if (unop->type == EXPR_SYMBOL) {
			*rl = where_allocated_rl(unop->symbol);
			return 1;
		}

		if (unop->type == EXPR_DEREF) {
			int offset = get_member_offset_from_deref(unop);

			unop = strip_expr(unop->unop);
			if (unop->type == EXPR_SYMBOL) {
				*rl = where_allocated_rl(unop->symbol);
			} else if (unop->type == EXPR_PREOP && unop->op == '*') {
				unop = strip_expr(unop->unop);
				get_absolute_rl(unop, rl);
			} else {
				return 0;
			}

			add_offset_to_pointer(rl, offset);
			return 1;
		}

		return 0;
	}

	if (is_non_null_array(expr)) {
		*rl = alloc_rl(array_min_sval, array_max_sval);
		return 1;
	}

	return 0;
}
