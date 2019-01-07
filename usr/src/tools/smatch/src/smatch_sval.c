/*
 * Copyright (C) 2012 Oracle.
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
 * Basically the point of sval is that it can hold both ULLONG_MAX and
 * LLONG_MIN.  If it is an unsigned type then we use sval.uvalue or if it is
 * signed we use sval.value.
 *
 * I considered just using one bit to store whether the value was signed vs
 * unsigned but I think it might help to have the type information so we know
 * how to do type promotion.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

__ALLOCATOR(sval_t, "svals", sval);

sval_t *sval_alloc(sval_t sval)
{
	sval_t *ret;

	ret = __alloc_sval(0);
	*ret = sval;
	return ret;
}

sval_t *sval_alloc_permanent(sval_t sval)
{
	sval_t *ret;

	ret = malloc(sizeof(*ret));
	*ret = sval;
	return ret;
}

sval_t sval_blank(struct expression *expr)
{
	sval_t ret;

	ret.type = get_type(expr);
	if (!ret.type)
		ret.type = &int_ctype;
	ret.value = 123456789;

	return ret;
}

sval_t sval_type_val(struct symbol *type, long long val)
{
	sval_t ret;

	if (!type)
		type = &int_ctype;

	ret.type = type;
	ret.value = val;
	return ret;
}

sval_t sval_from_val(struct expression *expr, long long val)
{
	sval_t ret;

	ret = sval_blank(expr);
	ret.value = val;
	ret = sval_cast(get_type(expr), ret);

	return ret;
}

int sval_is_ptr(sval_t sval)
{
	if (!sval.type)
		return 0;
	return (sval.type->type == SYM_PTR || sval.type->type == SYM_ARRAY);
}

int sval_unsigned(sval_t sval)
{
	return type_unsigned(sval.type);
}

int sval_signed(sval_t sval)
{
	return !type_unsigned(sval.type);
}

int sval_bits(sval_t sval)
{
	return type_bits(sval.type);
}

int sval_bits_used(sval_t sval)
{
	int i;

	for (i = 64; i >= 1; i--) {
		if (sval.uvalue & (1ULL << (i - 1)))
			return i;
	}
	return 0;
}

int sval_is_negative(sval_t sval)
{
	if (type_unsigned(sval.type))
		return 0;
	if (sval.value < 0)
		return 1;
	return 0;
}

int sval_is_positive(sval_t sval)
{
	return !sval_is_negative(sval);
}

int sval_is_min(sval_t sval)
{
	sval_t min = sval_type_min(sval.type);

	if (sval_unsigned(sval)) {
		if (sval.uvalue == 0)
			return 1;
		return 0;
	}
	/* return true for less than min as well */
	return (sval.value <= min.value);
}

int sval_is_max(sval_t sval)
{
	sval_t max = sval_type_max(sval.type);

	if (sval_unsigned(sval))
		return (sval.uvalue >= max.value);
	return (sval.value >= max.value);
}

int sval_is_a_min(sval_t sval)
{
	if (sval_is_min(sval))
		return 1;
	if (sval_signed(sval) && sval.value == SHRT_MIN)
		return 1;
	if (sval_signed(sval) && sval.value == INT_MIN)
		return 1;
	if (sval_signed(sval) && sval.value == LLONG_MIN)
		return 1;
	return 0;
}

int sval_is_a_max(sval_t sval)
{
	if (sval_is_max(sval))
		return 1;
	if (sval.uvalue == SHRT_MAX)
		return 1;
	if (sval.uvalue == INT_MAX)
		return 1;
	if (sval.uvalue == LLONG_MAX)
		return 1;
	if (sval.uvalue == USHRT_MAX)
		return 1;
	if (sval.uvalue == UINT_MAX)
		return 1;
	if (sval_unsigned(sval) && sval.uvalue == ULLONG_MAX)
		return 1;
	if (sval.value > valid_ptr_max - 1000 &&
	    sval.value < valid_ptr_max + 1000)
		return 1;
	return 0;
}

int sval_is_negative_min(sval_t sval)
{
	if (!sval_is_negative(sval))
		return 0;
	return sval_is_min(sval);
}

int sval_cmp_t(struct symbol *type, sval_t one, sval_t two)
{
	sval_t one_cast, two_cast;

	one_cast = sval_cast(type, one);
	two_cast = sval_cast(type, two);
	return sval_cmp(one_cast, two_cast);
}

int sval_cmp_val(sval_t one, long long val)
{
	sval_t sval;

	sval = sval_type_val(&llong_ctype, val);
	return sval_cmp(one, sval);
}

sval_t sval_min(sval_t one, sval_t two)
{
	if (sval_cmp(one, two) > 0)
		return two;
	return one;
}

sval_t sval_max(sval_t one, sval_t two)
{
	if (sval_cmp(one, two) < 0)
		return two;
	return one;
}

int sval_too_low(struct symbol *type, sval_t sval)
{
	if (sval_is_negative(sval) && type_unsigned(type))
		return 1;
	if (type_signed(type) &&  sval_unsigned(sval))
		return 0;
	if (type_signed(sval.type) &&
	    sval.value < sval_type_min(type).value)
		return 1;
	if (sval_cmp(sval, sval_type_min(type)) < 0)
		return 1;
	return 0;
}

int sval_too_high(struct symbol *type, sval_t sval)
{
	if (sval_is_negative(sval))
		return 0;
	if (sval.uvalue > sval_type_max(type).uvalue)
		return 1;
	return 0;
}

int sval_fits(struct symbol *type, sval_t sval)
{
	if (sval_too_low(type, sval))
		return 0;
	if (sval_too_high(type, sval))
		return 0;
	return 1;
}

sval_t sval_cast(struct symbol *type, sval_t sval)
{
	sval_t ret;

	if (!type)
		type = &int_ctype;

	ret.type = type;
	switch (sval_bits(ret)) {
	case 1:
		ret.value = !!sval.value;
		break;
	case 8:
		if (sval_unsigned(ret))
			ret.value = (long long)(unsigned char)sval.value;
		else
			ret.value = (long long)(char)sval.value;
		break;
	case 16:
		if (sval_unsigned(ret))
			ret.value = (long long)(unsigned short)sval.value;
		else
			ret.value = (long long)(short)sval.value;
		break;
	case 32:
		if (sval_unsigned(ret))
			ret.value = (long long)(unsigned int)sval.value;
		else
			ret.value = (long long)(int)sval.value;
		break;
	default:
		ret.value = sval.value;
	}
	return ret;

}

sval_t sval_preop(sval_t sval, int op)
{
	switch (op) {
	case '!':
		sval.value = !sval.value;
		break;
	case '~':
		sval.value = ~sval.value;
		sval = sval_cast(sval.type, sval);
		break;
	case '-':
		sval.value = -sval.value;
		sval = sval_cast(sval.type, sval);
		break;
	}
	return sval;
}

static sval_t sval_binop_unsigned(struct symbol *type, sval_t left, int op, sval_t right)
{
	sval_t ret;

	ret.type = type;
	switch (op) {
	case '*':
		ret.uvalue =  left.uvalue * right.uvalue;
		break;
	case '/':
		if (right.uvalue == 0) {
			sm_debug("%s: divide by zero", __func__);
			ret.uvalue = 123456789;
		} else {
			ret.uvalue = left.uvalue / right.uvalue;
		}
		break;
	case '+':
		ret.uvalue = left.uvalue + right.uvalue;
		break;
	case '-':
		ret.uvalue = left.uvalue - right.uvalue;
		break;
	case '%':
		if (right.uvalue == 0) {
			sm_perror(" %s: MOD by zero", __func__);
			ret.uvalue = 123456789;
		} else {
			ret.uvalue = left.uvalue % right.uvalue;
		}
		break;
	case '|':
		ret.uvalue = left.uvalue | right.uvalue;
		break;
	case '&':
		ret.uvalue = left.uvalue & right.uvalue;
		break;
	case SPECIAL_RIGHTSHIFT:
		ret.uvalue = left.uvalue >> right.uvalue;
		break;
	case SPECIAL_LEFTSHIFT:
		ret.uvalue = left.uvalue << right.uvalue;
		break;
	case '^':
		ret.uvalue = left.uvalue ^ right.uvalue;
		break;
	default:
		sm_perror(" %s: unhandled binop %s", __func__,
		       show_special(op));
		ret.uvalue = 1234567;
	}
	return ret;
}


static sval_t sval_binop_signed(struct symbol *type, sval_t left, int op, sval_t right)
{
	sval_t ret;

	ret.type = type;
	switch (op) {
	case '*':
		ret.value =  left.value * right.value;
		break;
	case '/':
		if (right.value == 0) {
			sm_debug("%s: divide by zero", __func__);
			ret.value = 123456789;
		} else if (left.value == LLONG_MIN && right.value == -1) {
			sm_debug("%s: invalid divide LLONG_MIN/-1", __func__);
			ret.value = 12345678;
		} else {
			ret.value = left.value / right.value;
		}
		break;
	case '+':
		ret.value = left.value + right.value;
		break;
	case '-':
		ret.value = left.value - right.value;
		break;
	case '%':
		if (right.value == 0) {
			sm_perror(" %s: MOD by zero", __func__);
			ret.value = 123456789;
		} else {
			ret.value = left.value % right.value;
		}
		break;
	case '|':
		ret.value = left.value | right.value;
		break;
	case '&':
		ret.value = left.value & right.value;
		break;
	case SPECIAL_RIGHTSHIFT:
		ret.value = left.value >> right.value;
		break;
	case SPECIAL_LEFTSHIFT:
		ret.value = left.value << right.value;
		break;
	case '^':
		ret.value = left.value ^ right.value;
		break;
	default:
		sm_perror(" %s: unhandled binop %s", __func__,
		       show_special(op));
		ret.value = 1234567;
	}
	return ret;
}

static sval_t ptr_binop(struct symbol *type, sval_t left, int op, sval_t right)
{
	sval_t ret;
	int align;

	if (op != '+' && op != '-')
		return sval_binop_unsigned(type, left, op, right);

	ret.type = type;
	if (type->type == SYM_PTR)
		type = get_real_base_type(type);
	align = type->ctype.alignment;
	if (align <= 0)
		align = 1;

	if (op == '+') {
		if (type_is_ptr(left.type))
			ret.value = left.value + right.value * align;
		else
			ret.value = left.value * align + right.value;
	} else {
		if (!type_is_ptr(left.type)) {
			left.value = -left.value;
			ret = ptr_binop(type, left, '+', right);
		} else if (!type_is_ptr(right.type)) {
			right.value = -right.value;
			ret = ptr_binop(type, left, '+', right);
		} else {
			ret.value = (left.value - right.value) / align;
		}
	}

	return ret;
}

sval_t sval_binop(sval_t left, int op, sval_t right)
{
	struct symbol *type;
	sval_t ret;

	type = get_promoted_type(left.type, right.type);

	if (type_is_ptr(type))
		ret = ptr_binop(type, left, op, right);
	else if (type_unsigned(type))
		ret = sval_binop_unsigned(type, left, op, right);
	else
		ret = sval_binop_signed(type, left, op, right);
	return sval_cast(type, ret);
}

int sval_unop_overflows(sval_t sval, int op)
{
	if (op != '-')
		return 0;
	if (sval_positive_bits(sval) == 32 && sval.value == INT_MIN)
		return 1;
	if (sval_positive_bits(sval) == 64 && sval.value == LLONG_MIN)
		return 1;
	if (sval_is_negative(sval))
		return 0;
	if (sval_signed(sval))
		return 0;
	if (sval_bits(sval) == 32 && sval.uvalue > INT_MAX)
		return 1;
	if (sval_bits(sval) == 64 && sval.uvalue > LLONG_MAX)
		return 1;
	return 0;
}

int sval_binop_overflows(sval_t left, int op, sval_t right)
{
	struct symbol *type;
	sval_t max, min;

	type = left.type;
	if (type_positive_bits(right.type) > type_positive_bits(left.type))
		type = right.type;
	if (type_positive_bits(type) < 31)
		type = &int_ctype;

	max = sval_type_max(type);
	min = sval_type_min(type);

	switch (op) {
	case '+':
		if (sval_is_negative(left) && sval_is_negative(right)) {
			if (left.value < min.value + right.value)
				return 1;
			return 0;
		}
		if (sval_is_negative(left) || sval_is_negative(right))
			return 0;
		if (left.uvalue > max.uvalue - right.uvalue)
				return 1;
		return 0;
	case '*':
		if (type_signed(type)) {
			if (left.value == 0 || right.value == 0)
				return 0;
			if (left.value > max.value / right.value)
				return 1;
			if (left.value == -1 || right.value == -1)
				return 0;
			return left.value != left.value * right.value / right.value;

		}
		return right.uvalue != 0 && left.uvalue > max.uvalue / right.uvalue;
	case '-':
		if (type_unsigned(type)) {
			if (sval_cmp(left, right) < 0)
				return 1;
			return 0;
		}
		if (sval_is_negative(left) && sval_is_negative(right))
			return 0;

		if (sval_is_negative(left)) {
			if (left.value < min.value + right.value)
				return 1;
			return 0;
		}
		if (sval_is_negative(right)) {
			if (right.value == min.value)
				return 1;
			right = sval_preop(right, '-');
			if (sval_binop_overflows(left, '+', right))
				return 1;
			return 0;
		}
		return 0;
	case SPECIAL_LEFTSHIFT:
		if (sval_cmp(left, sval_binop(max, invert_op(op), right)) > 0)
			return 1;
		return 0;
	}
	return 0;
}

int sval_binop_overflows_no_sign(sval_t left, int op, sval_t right)
{

	struct symbol *type;

	type = left.type;
	if (type_positive_bits(right.type) > type_positive_bits(left.type))
		type = right.type;
	if (type_positive_bits(type) <= 31)
		type = &uint_ctype;
	else
		type = &ullong_ctype;

	left = sval_cast(type, left);
	right = sval_cast(type, right);
	return sval_binop_overflows(left, op, right);
}

unsigned long long fls_mask(unsigned long long uvalue)
{
	unsigned long long high_bit = 0;

	while (uvalue) {
		uvalue >>= 1;
		high_bit++;
	}

	if (high_bit == 0)
		return 0;

	return ((unsigned long long)-1) >> (64 - high_bit);
}

unsigned long long sval_fls_mask(sval_t sval)
{
	return fls_mask(sval.uvalue);
}

const char *sval_to_str(sval_t sval)
{
	char buf[30];

	if (sval_unsigned(sval) && sval.value == ULLONG_MAX)
		return "u64max";
	if (sval_unsigned(sval) && sval.value == UINT_MAX)
		return "u32max";
	if (sval.value == USHRT_MAX)
		return "u16max";

	if (sval_signed(sval) && sval.value == LLONG_MAX)
		return "s64max";
	if (sval.value == INT_MAX)
		return "s32max";
	if (sval.value == SHRT_MAX)
		return "s16max";

	if (sval_signed(sval) && sval.value == SHRT_MIN)
		return "s16min";
	if (sval_signed(sval) && sval.value == INT_MIN)
		return "s32min";
	if (sval_signed(sval) && sval.value == LLONG_MIN)
		return "s64min";

	if (sval_unsigned(sval))
		snprintf(buf, sizeof(buf), "%llu", sval.value);
	else if (sval.value < 0)
		snprintf(buf, sizeof(buf), "(%lld)", sval.value);
	else
		snprintf(buf, sizeof(buf), "%lld", sval.value);

	return alloc_sname(buf);
}

const char *sval_to_numstr(sval_t sval)
{
	char buf[30];

	if (sval_unsigned(sval))
		snprintf(buf, sizeof(buf), "%llu", sval.value);
	else if (sval.value < 0)
		snprintf(buf, sizeof(buf), "(%lld)", sval.value);
	else
		snprintf(buf, sizeof(buf), "%lld", sval.value);

	return alloc_sname(buf);
}

sval_t ll_to_sval(long long val)
{
	sval_t ret;

	ret.type = &llong_ctype;
	ret.value = val;
	return ret;
}

static void free_svals(struct symbol *sym)
{
	if (__inline_fn)
		return;
	clear_sval_alloc();
}

void register_sval(int my_id)
{
	add_hook(&free_svals, AFTER_FUNC_HOOK);
}
