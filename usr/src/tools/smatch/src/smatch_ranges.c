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

#include "parse.h"
#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

ALLOCATOR(data_info, "smatch extra data");
ALLOCATOR(data_range, "data range");
__DO_ALLOCATOR(struct data_range, sizeof(struct data_range), __alignof__(struct data_range),
			 "permanent ranges", perm_data_range);
__DECLARE_ALLOCATOR(struct ptr_list, rl_ptrlist);

bool is_err_ptr(sval_t sval)
{
	if (option_project != PROJ_KERNEL)
		return false;
	if (!type_is_ptr(sval.type))
		return false;
	if (sval.uvalue < -4095ULL)
		return false;
	return true;
}

static char *get_err_pointer_str(struct data_range *drange)
{
	static char buf[20];

	/*
	 * The kernel has error pointers where you do essentially:
	 *
	 * return (void *)(unsigned long)-12;
	 *
	 * But what I want here is to print -12 instead of the unsigned version
	 * of that.
	 *
	 */
	if (!is_err_ptr(drange->min))
		return NULL;

	if (drange->min.value == drange->max.value)
		snprintf(buf, sizeof(buf), "(%lld)", drange->min.value);
	else
		snprintf(buf, sizeof(buf), "(%lld)-(%lld)", drange->min.value, drange->max.value);
	return buf;
}

char *show_rl(struct range_list *list)
{
	struct data_range *prev_drange = NULL;
	struct data_range *tmp;
	char full[255];
	char *p = full;
	char *prev = full;
	char *err_ptr;
	int remain;
	int i = 0;

	full[0] = '\0';

	FOR_EACH_PTR(list, tmp) {
		remain = full + sizeof(full) - p;
		if (remain < 48) {
			snprintf(prev, full + sizeof(full) - prev, ",%s-%s",
				 sval_to_str(prev_drange->min),
				 sval_to_str(sval_type_max(prev_drange->min.type)));
			break;
		}
		prev_drange = tmp;
		prev = p;

		err_ptr = get_err_pointer_str(tmp);
		if (err_ptr) {
			p += snprintf(p, remain, "%s%s", i++ ? "," : "", err_ptr);
		} else if (sval_cmp(tmp->min, tmp->max) == 0) {
			p += snprintf(p, remain, "%s%s", i++ ? "," : "",
				      sval_to_str(tmp->min));
		} else {
			p += snprintf(p, remain, "%s%s-%s", i++ ? "," : "",
				      sval_to_str(tmp->min),
				      sval_to_str(tmp->max));
		}
	} END_FOR_EACH_PTR(tmp);

	return alloc_sname(full);
}

void free_all_rl(void)
{
	clear_rl_ptrlist_alloc();
}

static int sval_too_big(struct symbol *type, sval_t sval)
{
	if (type_bits(type) >= 32 &&
	    type_bits(sval.type) <= type_bits(type))
		return 0;
	if (sval.uvalue <= ((1ULL << type_bits(type)) - 1))
		return 0;
	if (type_signed(sval.type)) {
		if (type_unsigned(type)) {
			unsigned long long neg = ~sval.uvalue;
			if (neg <= sval_type_max(type).uvalue)
				return 0;
		}
		if (sval.value < sval_type_min(type).value)
			return 1;
		if (sval.value > sval_type_max(type).value)
			return 1;
		return 0;
	}
	if (sval.uvalue > sval_type_max(type).uvalue)
		return 1;
	return 0;
}

static int truncates_nicely(struct symbol *type, sval_t min, sval_t max)
{
	unsigned long long mask;
	int bits = type_bits(type);

	if (type_is_fp(min.type) && !type_is_fp(type))
		return 0;

	if (bits >= type_bits(min.type))
		return 0;

	mask = -1ULL << bits;
	return (min.uvalue & mask) == (max.uvalue & mask);
}

static void add_range_t(struct symbol *type, struct range_list **rl, sval_t min, sval_t max)
{
	/* If we're just adding a number, cast it and add it */
	if (sval_cmp(min, max) == 0) {
		add_range(rl, sval_cast(type, min), sval_cast(type, max));
		return;
	}

	/* If the range is within the type range then add it */
	if (sval_fits(type, min) && sval_fits(type, max)) {
		add_range(rl, sval_cast(type, min), sval_cast(type, max));
		return;
	}

	if (truncates_nicely(type, min, max)) {
		add_range(rl, sval_cast(type, min), sval_cast(type, max));
		return;
	}

	/*
	 * If the range we are adding has more bits than the range type then
	 * add the whole range type.  Eg:
	 * 0x8000000000000000 - 0xf000000000000000 -> cast to int
	 *
	 */
	if (sval_too_big(type, min) || sval_too_big(type, max)) {
		add_range(rl, sval_type_min(type), sval_type_max(type));
		return;
	}

	/* Cast negative values to high positive values */
	if (sval_is_negative(min) && type_unsigned(type)) {
		if (sval_is_positive(max)) {
			if (sval_too_high(type, max)) {
				add_range(rl, sval_type_min(type), sval_type_max(type));
				return;
			}
			add_range(rl, sval_type_val(type, 0), sval_cast(type, max));
			max = sval_type_max(type);
		} else {
			max = sval_cast(type, max);
		}
		min = sval_cast(type, min);
		add_range(rl, min, max);
	}

	/* Cast high positive numbers to negative */
	if (sval_unsigned(max) && sval_is_negative(sval_cast(type, max))) {
		if (!sval_is_negative(sval_cast(type, min))) {
			add_range(rl, sval_cast(type, min), sval_type_max(type));
			min = sval_type_min(type);
		} else {
			min = sval_cast(type, min);
		}
		max = sval_cast(type, max);
		add_range(rl, min, max);
	}

	add_range(rl, sval_cast(type, min), sval_cast(type, max));
	return;
}

static int str_to_comparison_arg_helper(const char *str,
		struct expression *call, int *comparison,
		struct expression **arg, const char **endp)
{
	int param;
	const char *c = str;

	if (*c != '[')
		return 0;
	c++;

	if (*c == '<') {
		c++;
		if (*c == '=') {
			*comparison = SPECIAL_LTE;
			c++;
		} else {
			*comparison = '<';
		}
	} else if (*c == '=') {
		c++;
		c++;
		*comparison = SPECIAL_EQUAL;
	} else if (*c == '>') {
		c++;
		if (*c == '=') {
			*comparison = SPECIAL_GTE;
			c++;
		} else {
			*comparison = '>';
		}
	} else if (*c == '!') {
		c++;
		c++;
		*comparison = SPECIAL_NOTEQUAL;
	} else if (*c == '$') {
		*comparison = SPECIAL_EQUAL;
	} else {
		return 0;
	}

	if (*c != '$')
		return 0;
	c++;

	param = strtoll(c, (char **)&c, 10);
	/*
	 * FIXME: handle parameter math.  [==$1 + 100]
	 *
	 */
	if (*c == ' ')
		return 0;

	if (*c == ',' || *c == ']')
		c++; /* skip the ']' character */
	if (endp)
		*endp = (char *)c;

	if (!call)
		return 0;
	*arg = get_argument_from_call_expr(call->args, param);
	if (!*arg)
		return 0;
	if (*c == '-' && *(c + 1) == '>') {
		char buf[256];
		int n;

		n = snprintf(buf, sizeof(buf), "$%s", c);
		if (n >= sizeof(buf))
			return 0;
		if (buf[n - 1] == ']')
			buf[n - 1] = '\0';
		*arg = gen_expression_from_key(*arg, buf);
		while (*c && *c != ']')
			c++;
	}
	return 1;
}

int str_to_comparison_arg(const char *str, struct expression *call, int *comparison, struct expression **arg)
{
	while (1) {
		if (!*str)
			return 0;
		if (*str == '[')
			break;
		str++;
	}
	return str_to_comparison_arg_helper(str, call, comparison, arg, NULL);
}

static int get_val_from_key(int use_max, struct symbol *type, const char *c, struct expression *call, const char **endp, sval_t *sval)
{
	struct expression *arg;
	int comparison;
	sval_t ret, tmp;

	if (use_max)
		ret = sval_type_max(type);
	else
		ret = sval_type_min(type);

	if (!str_to_comparison_arg_helper(c, call, &comparison, &arg, endp)) {
		*sval = ret;
		return 0;
	}

	if (use_max && get_implied_max(arg, &tmp)) {
		ret = tmp;
		if (comparison == '<') {
			tmp.value = 1;
			ret = sval_binop(ret, '-', tmp);
		}
	}
	if (!use_max && get_implied_min(arg, &tmp)) {
		ret = tmp;
		if (comparison == '>') {
			tmp.value = 1;
			ret = sval_binop(ret, '+', tmp);
		}
	}

	*sval = ret;
	return 1;
}

static sval_t add_one(sval_t sval)
{
	sval.value++;
	return sval;
}

static sval_t sub_one(sval_t sval)
{
	sval.value--;
	return sval;
}

void filter_by_comparison(struct range_list **rl, int comparison, struct range_list *right)
{
	struct range_list *left_orig = *rl;
	struct range_list *right_orig = right;
	struct range_list *ret_rl = *rl;
	struct symbol *cast_type;
	sval_t min, max;

	if (comparison == UNKNOWN_COMPARISON)
		return;

	cast_type = rl_type(left_orig);
	if (sval_type_max(rl_type(left_orig)).uvalue < sval_type_max(rl_type(right_orig)).uvalue)
		cast_type = rl_type(right_orig);
	if (sval_type_max(cast_type).uvalue < INT_MAX)
		cast_type = &int_ctype;

	min = sval_type_min(cast_type);
	max = sval_type_max(cast_type);
	left_orig = cast_rl(cast_type, left_orig);
	right_orig = cast_rl(cast_type, right_orig);

	switch (comparison) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
		ret_rl = remove_range(left_orig, rl_max(right_orig), max);
		break;
	case SPECIAL_LTE:
	case SPECIAL_UNSIGNED_LTE:
		if (!sval_is_max(rl_max(right_orig)))
			ret_rl = remove_range(left_orig, add_one(rl_max(right_orig)), max);
		break;
	case SPECIAL_EQUAL:
		ret_rl = rl_intersection(left_orig, right_orig);
		break;
	case SPECIAL_GTE:
	case SPECIAL_UNSIGNED_GTE:
		if (!sval_is_min(rl_min(right_orig)))
			ret_rl = remove_range(left_orig, min, sub_one(rl_min(right_orig)));
		break;
	case '>':
	case SPECIAL_UNSIGNED_GT:
		ret_rl = remove_range(left_orig, min, rl_min(right_orig));
		break;
	case SPECIAL_NOTEQUAL:
		if (sval_cmp(rl_min(right_orig), rl_max(right_orig)) == 0)
			ret_rl = remove_range(left_orig, rl_min(right_orig), rl_min(right_orig));
		break;
	default:
		sm_perror("unhandled comparison %s", show_special(comparison));
		return;
	}

	*rl = cast_rl(rl_type(*rl), ret_rl);
}

static struct range_list *filter_by_comparison_call(const char *c, struct expression *call, const char **endp, struct range_list *start_rl)
{
	struct symbol *type;
	struct expression *arg;
	struct range_list *casted_start, *right_orig;
	int comparison;

	/* For when we have a function that takes a function pointer. */
	if (!call || call->type != EXPR_CALL)
		return start_rl;

	if (!str_to_comparison_arg_helper(c, call, &comparison, &arg, endp))
		return start_rl;

	if (!get_implied_rl(arg, &right_orig))
		return start_rl;

	type = &int_ctype;
	if (type_positive_bits(rl_type(start_rl)) > type_positive_bits(type))
		type = rl_type(start_rl);
	if (type_positive_bits(rl_type(right_orig)) > type_positive_bits(type))
		type = rl_type(right_orig);

	casted_start = cast_rl(type, start_rl);
	right_orig = cast_rl(type, right_orig);

	filter_by_comparison(&casted_start, comparison, right_orig);
	return cast_rl(rl_type(start_rl), casted_start);
}

static sval_t parse_val(int use_max, struct expression *call, struct symbol *type, const char *c, const char **endp)
{
	const char *start = c;
	sval_t ret;

	if (type == &float_ctype)
		return sval_type_fval(type, strtof(start, (char **)endp));
	else if (type == &double_ctype)
		return sval_type_fval(type, strtod(start, (char **)endp));
	else if (type == &ldouble_ctype)
		return sval_type_fval(type, strtold(start, (char **)endp));

	if (!strncmp(start, "max", 3)) {
		ret = sval_type_max(type);
		c += 3;
	} else if (!strncmp(start, "u64max", 6)) {
		ret = sval_type_val(type, ULLONG_MAX);
		c += 6;
	} else if (!strncmp(start, "s64max", 6)) {
		ret = sval_type_val(type, LLONG_MAX);
		c += 6;
	} else if (!strncmp(start, "u32max", 6)) {
		ret = sval_type_val(type, UINT_MAX);
		c += 6;
	} else if (!strncmp(start, "s32max", 6)) {
		ret = sval_type_val(type, INT_MAX);
		c += 6;
	} else if (!strncmp(start, "u16max", 6)) {
		ret = sval_type_val(type, USHRT_MAX);
		c += 6;
	} else if (!strncmp(start, "s16max", 6)) {
		ret = sval_type_val(type, SHRT_MAX);
		c += 6;
	} else if (!strncmp(start, "min", 3)) {
		ret = sval_type_min(type);
		c += 3;
	} else if (!strncmp(start, "s64min", 6)) {
		ret = sval_type_val(type, LLONG_MIN);
		c += 6;
	} else if (!strncmp(start, "s32min", 6)) {
		ret = sval_type_val(type, INT_MIN);
		c += 6;
	} else if (!strncmp(start, "s16min", 6)) {
		ret = sval_type_val(type, SHRT_MIN);
		c += 6;
	} else if (!strncmp(start, "long_min", 8)) {
		ret = sval_type_val(type, LONG_MIN);
		c += 8;
	} else if (!strncmp(start, "long_max", 8)) {
		ret = sval_type_val(type, LONG_MAX);
		c += 8;
	} else if (!strncmp(start, "ulong_max", 9)) {
		ret = sval_type_val(type, ULONG_MAX);
		c += 9;
	} else if (!strncmp(start, "ptr_max", 7)) {
		ret = sval_type_val(type, valid_ptr_max);
		c += 7;
	} else if (start[0] == '[') {
		/* this parses [==p0] comparisons */
		get_val_from_key(1, type, start, call, &c, &ret);
	} else if (type_positive_bits(type) == 64) {
		ret = sval_type_val(type, strtoull(start, (char **)&c, 0));
	} else {
		ret = sval_type_val(type, strtoll(start, (char **)&c, 0));
	}
	*endp = c;
	return ret;
}

static const char *jump_to_call_math(const char *value)
{
	const char *c = value;

	while (*c && *c != '[')
		c++;

	if (!*c)
		return NULL;
	c++;
	if (*c == '<' || *c == '=' || *c == '>' || *c == '!')
		return NULL;

	return c;
}

static struct range_list *get_param_return_rl(struct expression *call, const char *call_math)
{
	struct expression *arg;
	int param;

	call_math += 3;
	param = atoi(call_math);

	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return NULL;

	return db_return_vals_no_args(arg);
}

static void str_to_rl_helper(struct expression *call, struct symbol *type, const char *str, const char **endp, struct range_list **rl)
{
	struct range_list *rl_tmp = NULL;
	sval_t prev_min, min, max;
	const char *c;

	prev_min = sval_type_min(type);
	min = sval_type_min(type);
	max = sval_type_max(type);
	c = str;
	while (*c != '\0' && *c != '[') {
		if (*c == '+') {
			if (sval_cmp(min, sval_type_min(type)) != 0)
				min = max;
			max = sval_type_max(type);
			add_range_t(type, &rl_tmp, min, max);
			break;
		}
		if (*c == '(')
			c++;
		min = parse_val(0, call, type, c, &c);
		if (!sval_fits(type, min))
			min = sval_type_min(type);
		max = min;
		if (*c == ')')
			c++;
		if (*c == '\0' || *c == '[') {
			add_range_t(type, &rl_tmp, min, min);
			break;
		}
		if (*c == ',') {
			add_range_t(type, &rl_tmp, min, min);
			c++;
			continue;
		}
		if (*c == '+') {
			min = prev_min;
			max = sval_type_max(type);
			add_range_t(type, &rl_tmp, min, max);
			c++;
			if (*c == '[' || *c == '\0')
				break;
		}
		if (*c != '-') {
			sm_debug("XXX: trouble parsing %s c = %s", str, c);
			break;
		}
		c++;
		if (*c == '(')
			c++;
		max = parse_val(1, call, type, c, &c);
		if (!sval_fits(type, max))
			max = sval_type_max(type);
		if (*c == '+') {
			max = sval_type_max(type);
			add_range_t(type, &rl_tmp, min, max);
			c++;
			if (*c == '[' || *c == '\0')
				break;
		}
		prev_min = max;
		add_range_t(type, &rl_tmp, min, max);
		if (*c == ')')
			c++;
		if (*c == ',')
			c++;
	}

	*rl = rl_tmp;
	*endp = c;
}

static void str_to_dinfo(struct expression *call, struct symbol *type, const char *value, struct data_info *dinfo)
{
	struct range_list *math_rl;
	const char *call_math;
	const char *c;
	struct range_list *rl = NULL;

	if (!type)
		type = &llong_ctype;

	if (strcmp(value, "empty") == 0)
		return;

	if (strncmp(value, "[==$", 4) == 0) {
		struct expression *arg;
		int comparison;

		if (!str_to_comparison_arg(value, call, &comparison, &arg))
			return;
		if (!get_implied_rl(arg, &rl))
			return;
		goto cast;
	}

	str_to_rl_helper(call, type, value, &c, &rl);
	if (*c == '\0')
		goto cast;

	call_math = jump_to_call_math(value);
	if (call_math && call_math[0] == 'r') {
		math_rl = get_param_return_rl(call, call_math);
		if (math_rl)
			rl = rl_intersection(rl, math_rl);
		goto cast;
	}
	if (call_math && parse_call_math_rl(call, call_math, &math_rl)) {
		rl = rl_intersection(rl, math_rl);
		goto cast;
	}

	/*
	 * For now if we already tried to handle the call math and couldn't
	 * figure it out then bail.
	 */
	if (jump_to_call_math(c) == c + 1)
		goto cast;

	rl = filter_by_comparison_call(c, call, &c, rl);

cast:
	rl = cast_rl(type, rl);
	dinfo->value_ranges = rl;
}

static int rl_is_sane(struct range_list *rl)
{
	struct data_range *tmp;
	struct symbol *type;

	type = rl_type(rl);
	FOR_EACH_PTR(rl, tmp) {
		if (!sval_fits(type, tmp->min))
			return 0;
		if (!sval_fits(type, tmp->max))
			return 0;
		if (sval_cmp(tmp->min, tmp->max) > 0)
			return 0;
	} END_FOR_EACH_PTR(tmp);

	return 1;
}

void str_to_rl(struct symbol *type, char *value, struct range_list **rl)
{
	struct data_info dinfo = {};

	str_to_dinfo(NULL, type, value, &dinfo);
	if (!rl_is_sane(dinfo.value_ranges))
		dinfo.value_ranges = alloc_whole_rl(type);
	*rl = dinfo.value_ranges;
}

void call_results_to_rl(struct expression *expr, struct symbol *type, const char *value, struct range_list **rl)
{
	struct data_info dinfo = {};

	str_to_dinfo(strip_expr(expr), type, value, &dinfo);
	*rl = dinfo.value_ranges;
}

int is_whole_rl(struct range_list *rl)
{
	struct data_range *drange;

	if (ptr_list_empty((struct ptr_list *)rl))
		return 0;
	drange = first_ptr_list((struct ptr_list *)rl);
	if (sval_is_min(drange->min) && sval_is_max(drange->max))
		return 1;
	return 0;
}

int is_unknown_ptr(struct range_list *rl)
{
	struct data_range *drange;
	int cnt = 0;

	if (is_whole_rl(rl))
		return 1;

	FOR_EACH_PTR(rl, drange) {
		if (++cnt >= 3)
			return 0;
		if (sval_cmp(drange->min, valid_ptr_min_sval) == 0 &&
		    sval_cmp(drange->max, valid_ptr_max_sval) == 0)
			return 1;
	} END_FOR_EACH_PTR(drange);

	return 0;
}

int is_whole_rl_non_zero(struct range_list *rl)
{
	struct data_range *drange;

	if (ptr_list_empty((struct ptr_list *)rl))
		return 0;
	drange = first_ptr_list((struct ptr_list *)rl);
	if (sval_unsigned(drange->min) &&
	    drange->min.value == 1 &&
	    sval_is_max(drange->max))
		return 1;
	if (!sval_is_min(drange->min) || drange->max.value != -1)
		return 0;
	drange = last_ptr_list((struct ptr_list *)rl);
	if (drange->min.value != 1 || !sval_is_max(drange->max))
		return 0;
	return 1;
}

sval_t rl_min(struct range_list *rl)
{
	struct data_range *drange;
	sval_t ret;

	ret.type = &llong_ctype;
	ret.value = LLONG_MIN;
	if (ptr_list_empty((struct ptr_list *)rl))
		return ret;
	drange = first_ptr_list((struct ptr_list *)rl);
	return drange->min;
}

sval_t rl_max(struct range_list *rl)
{
	struct data_range *drange;
	sval_t ret;

	ret.type = &llong_ctype;
	ret.value = LLONG_MAX;
	if (ptr_list_empty((struct ptr_list *)rl))
		return ret;
	drange = last_ptr_list((struct ptr_list *)rl);
	return drange->max;
}

int rl_to_sval(struct range_list *rl, sval_t *sval)
{
	sval_t min, max;

	if (!rl)
		return 0;

	min = rl_min(rl);
	max = rl_max(rl);
	if (sval_cmp(min, max) != 0)
		return 0;
	*sval = min;
	return 1;
}

struct symbol *rl_type(struct range_list *rl)
{
	if (!rl)
		return NULL;
	return rl_min(rl).type;
}

static struct data_range *alloc_range_helper_sval(sval_t min, sval_t max, int perm)
{
	struct data_range *ret;

	if (perm)
		ret = __alloc_perm_data_range(0);
	else
		ret = __alloc_data_range(0);
	ret->min = min;
	ret->max = max;
	return ret;
}

struct data_range *alloc_range(sval_t min, sval_t max)
{
	return alloc_range_helper_sval(min, max, 0);
}

struct data_range *alloc_range_perm(sval_t min, sval_t max)
{
	return alloc_range_helper_sval(min, max, 1);
}

struct range_list *alloc_rl(sval_t min, sval_t max)
{
	struct range_list *rl = NULL;

	if (sval_cmp(min, max) > 0)
		return alloc_whole_rl(min.type);

	add_range(&rl, min, max);
	return rl;
}

struct range_list *alloc_whole_rl(struct symbol *type)
{
	if (!type || type_positive_bits(type) < 0)
		type = &llong_ctype;
	if (type->type == SYM_ARRAY)
		type = &ptr_ctype;

	return alloc_rl(sval_type_min(type), sval_type_max(type));
}

static bool collapse_pointer_rl(struct range_list **rl, sval_t min, sval_t max)
{
	struct range_list *new_rl = NULL;
	struct data_range *tmp;
	static bool recurse;
	bool ret = false;
	int cnt = 0;

	/*
	 * With the mtag work, then we end up getting huge lists of mtags.
	 * That seems cool, but the problem is that we can only store about
	 * 8-10 mtags in the DB before we truncate the list.  Also the mtags
	 * aren't really used at all so it's a waste of resources for now...
	 * In the future, we maybe will revisit this code.
	 *
	 */

	if (recurse)
		return false;
	recurse = true;
	if (!type_is_ptr(min.type))
		goto out;

	if (ptr_list_size((struct ptr_list *)*rl) < 8)
		goto out;
	FOR_EACH_PTR(*rl, tmp) {
		if (!is_err_ptr(tmp->min))
			cnt++;
	} END_FOR_EACH_PTR(tmp);
	if (cnt < 8)
		goto out;

	FOR_EACH_PTR(*rl, tmp) {
		if (sval_cmp(tmp->min, valid_ptr_min_sval) >= 0 &&
		    sval_cmp(tmp->max, valid_ptr_max_sval) <= 0)
			add_range(&new_rl, valid_ptr_min_sval, valid_ptr_max_sval);
		else
			add_range(&new_rl, tmp->min, tmp->max);
	} END_FOR_EACH_PTR(tmp);

	add_range(&new_rl, min, max);

	*rl = new_rl;
	ret = true;
out:
	recurse = false;
	return ret;
}

extern int rl_ptrlist_hack;
void add_range(struct range_list **list, sval_t min, sval_t max)
{
	struct data_range *tmp;
	struct data_range *new = NULL;
	int check_next = 0;

	/*
	 * There is at least on valid reason why the types might be confusing
	 * and that's when you have a void pointer and on some paths you treat
	 * it as a u8 pointer and on other paths you treat it as a u16 pointer.
	 * This case is hard to deal with.
	 *
	 * There are other cases where we probably should be more specific about
	 * the types than we are.  For example, we end up merging a lot of ulong
	 * with pointers and I have not figured out why we do that.
	 *
	 * But this hack works for both cases, I think.  We cast it to pointers
	 * or we use the bigger size.
	 *
	 */
	if (*list && rl_type(*list) != min.type) {
		if (rl_type(*list)->type == SYM_PTR) {
			min = sval_cast(rl_type(*list), min);
			max = sval_cast(rl_type(*list), max);
		} else if (min.type->type == SYM_PTR) {
			*list = cast_rl(min.type, *list);
		} else if (type_bits(rl_type(*list)) >= type_bits(min.type)) {
			min = sval_cast(rl_type(*list), min);
			max = sval_cast(rl_type(*list), max);
		} else {
			*list = cast_rl(min.type, *list);
		}
	}

	if (sval_cmp(min, max) > 0) {
		min = sval_type_min(min.type);
		max = sval_type_max(min.type);
	}

	if (collapse_pointer_rl(list, min, max))
		return;

	/*
	 * FIXME:  This has a problem merging a range_list like: min-0,3-max
	 * with a range like 1-2.  You end up with min-2,3-max instead of
	 * just min-max.
	 */
	FOR_EACH_PTR(*list, tmp) {
		if (check_next) {
			/* Sometimes we overlap with more than one range
			   so we have to delete or modify the next range. */
			if (!sval_is_max(max) && max.value + 1 == tmp->min.value) {
				/* join 2 ranges here */
				new->max = tmp->max;
				DELETE_CURRENT_PTR(tmp);
				return;
			}

			/* Doesn't overlap with the next one. */
			if (sval_cmp(max, tmp->min) < 0)
				return;

			if (sval_cmp(max, tmp->max) <= 0) {
				/* Partially overlaps the next one. */
				new->max = tmp->max;
				DELETE_CURRENT_PTR(tmp);
				return;
			} else {
				/* Completely overlaps the next one. */
				DELETE_CURRENT_PTR(tmp);
				/* there could be more ranges to delete */
				continue;
			}
		}
		if (!sval_is_max(max) && max.value + 1 == tmp->min.value) {
			/* join 2 ranges into a big range */
			new = alloc_range(min, tmp->max);
			REPLACE_CURRENT_PTR(tmp, new);
			return;
		}
		if (sval_cmp(max, tmp->min) < 0) { /* new range entirely below */
			new = alloc_range(min, max);
			INSERT_CURRENT(new, tmp);
			return;
		}
		if (sval_cmp(min, tmp->min) < 0) { /* new range partially below */
			if (sval_cmp(max, tmp->max) < 0)
				max = tmp->max;
			else
				check_next = 1;
			new = alloc_range(min, max);
			REPLACE_CURRENT_PTR(tmp, new);
			if (!check_next)
				return;
			continue;
		}
		if (sval_cmp(max, tmp->max) <= 0) /* new range already included */
			return;
		if (sval_cmp(min, tmp->max) <= 0) { /* new range partially above */
			min = tmp->min;
			new = alloc_range(min, max);
			REPLACE_CURRENT_PTR(tmp, new);
			check_next = 1;
			continue;
		}
		if (!sval_is_min(min) && min.value - 1 == tmp->max.value) {
			/* join 2 ranges into a big range */
			new = alloc_range(tmp->min, max);
			REPLACE_CURRENT_PTR(tmp, new);
			check_next = 1;
			continue;
		}
		/* the new range is entirely above the existing ranges */
	} END_FOR_EACH_PTR(tmp);
	if (check_next)
		return;
	new = alloc_range(min, max);

	rl_ptrlist_hack = 1;
	add_ptr_list(list, new);
	rl_ptrlist_hack = 0;
}

struct range_list *clone_rl(struct range_list *list)
{
	struct data_range *tmp;
	struct range_list *ret = NULL;

	FOR_EACH_PTR(list, tmp) {
		add_ptr_list(&ret, tmp);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

struct range_list *clone_rl_permanent(struct range_list *list)
{
	struct data_range *tmp;
	struct data_range *new;
	struct range_list *ret = NULL;

	FOR_EACH_PTR(list, tmp) {
		new = alloc_range_perm(tmp->min, tmp->max);
		add_ptr_list(&ret, new);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

struct range_list *rl_union(struct range_list *one, struct range_list *two)
{
	struct data_range *tmp;
	struct range_list *ret = NULL;

	FOR_EACH_PTR(one, tmp) {
		add_range(&ret, tmp->min, tmp->max);
	} END_FOR_EACH_PTR(tmp);
	FOR_EACH_PTR(two, tmp) {
		add_range(&ret, tmp->min, tmp->max);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

struct range_list *remove_range(struct range_list *list, sval_t min, sval_t max)
{
	struct data_range *tmp;
	struct range_list *ret = NULL;

	if (!list)
		return NULL;

	min = sval_cast(rl_type(list), min);
	max = sval_cast(rl_type(list), max);
	if (sval_cmp(min, max) > 0) {
		sval_t tmp = min;
		min = max;
		max = tmp;
	}

	FOR_EACH_PTR(list, tmp) {
		if (sval_cmp(tmp->max, min) < 0) {
			add_range(&ret, tmp->min, tmp->max);
			continue;
		}
		if (sval_cmp(tmp->min, max) > 0) {
			add_range(&ret, tmp->min, tmp->max);
			continue;
		}
		if (sval_cmp(tmp->min, min) >= 0 && sval_cmp(tmp->max, max) <= 0)
			continue;
		if (sval_cmp(tmp->min, min) >= 0) {
			max.value++;
			add_range(&ret, max, tmp->max);
		} else if (sval_cmp(tmp->max, max) <= 0) {
			min.value--;
			add_range(&ret, tmp->min, min);
		} else {
			min.value--;
			max.value++;
			add_range(&ret, tmp->min, min);
			add_range(&ret, max, tmp->max);
		}
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

int ranges_equiv(struct data_range *one, struct data_range *two)
{
	if (!one && !two)
		return 1;
	if (!one || !two)
		return 0;
	if (sval_cmp(one->min, two->min) != 0)
		return 0;
	if (sval_cmp(one->max, two->max) != 0)
		return 0;
	return 1;
}

int rl_equiv(struct range_list *one, struct range_list *two)
{
	struct data_range *one_range;
	struct data_range *two_range;

	if (one == two)
		return 1;

	PREPARE_PTR_LIST(one, one_range);
	PREPARE_PTR_LIST(two, two_range);
	for (;;) {
		if (!one_range && !two_range)
			return 1;
		if (!ranges_equiv(one_range, two_range))
			return 0;
		NEXT_PTR_LIST(one_range);
		NEXT_PTR_LIST(two_range);
	}
	FINISH_PTR_LIST(two_range);
	FINISH_PTR_LIST(one_range);

	return 1;
}

int true_comparison_range(struct data_range *left, int comparison, struct data_range *right)
{
	switch (comparison) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
		if (sval_cmp(left->min, right->max) < 0)
			return 1;
		return 0;
	case SPECIAL_UNSIGNED_LTE:
	case SPECIAL_LTE:
		if (sval_cmp(left->min, right->max) <= 0)
			return 1;
		return 0;
	case SPECIAL_EQUAL:
		if (sval_cmp(left->max, right->min) < 0)
			return 0;
		if (sval_cmp(left->min, right->max) > 0)
			return 0;
		return 1;
	case SPECIAL_UNSIGNED_GTE:
	case SPECIAL_GTE:
		if (sval_cmp(left->max, right->min) >= 0)
			return 1;
		return 0;
	case '>':
	case SPECIAL_UNSIGNED_GT:
		if (sval_cmp(left->max, right->min) > 0)
			return 1;
		return 0;
	case SPECIAL_NOTEQUAL:
		if (sval_cmp(left->min, left->max) != 0)
			return 1;
		if (sval_cmp(right->min, right->max) != 0)
			return 1;
		if (sval_cmp(left->min, right->min) != 0)
			return 1;
		return 0;
	default:
		sm_perror("unhandled comparison %d", comparison);
		return 0;
	}
	return 0;
}

int true_comparison_range_LR(int comparison, struct data_range *var, struct data_range *val, int left)
{
	if (left)
		return true_comparison_range(var, comparison, val);
	else
		return true_comparison_range(val, comparison, var);
}

static int false_comparison_range_sval(struct data_range *left, int comparison, struct data_range *right)
{
	switch (comparison) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
		if (sval_cmp(left->max, right->min) >= 0)
			return 1;
		return 0;
	case SPECIAL_UNSIGNED_LTE:
	case SPECIAL_LTE:
		if (sval_cmp(left->max, right->min) > 0)
			return 1;
		return 0;
	case SPECIAL_EQUAL:
		if (sval_cmp(left->min, left->max) != 0)
			return 1;
		if (sval_cmp(right->min, right->max) != 0)
			return 1;
		if (sval_cmp(left->min, right->min) != 0)
			return 1;
		return 0;
	case SPECIAL_UNSIGNED_GTE:
	case SPECIAL_GTE:
		if (sval_cmp(left->min, right->max) < 0)
			return 1;
		return 0;
	case '>':
	case SPECIAL_UNSIGNED_GT:
		if (sval_cmp(left->min, right->max) <= 0)
			return 1;
		return 0;
	case SPECIAL_NOTEQUAL:
		if (sval_cmp(left->max, right->min) < 0)
			return 0;
		if (sval_cmp(left->min, right->max) > 0)
			return 0;
		return 1;
	default:
		sm_perror("unhandled comparison %d", comparison);
		return 0;
	}
	return 0;
}

int false_comparison_range_LR(int comparison, struct data_range *var, struct data_range *val, int left)
{
	if (left)
		return false_comparison_range_sval(var, comparison, val);
	else
		return false_comparison_range_sval(val, comparison, var);
}

int possibly_true(struct expression *left, int comparison, struct expression *right)
{
	struct range_list *rl_left, *rl_right;
	struct data_range *tmp_left, *tmp_right;
	struct symbol *type;

	if (comparison == UNKNOWN_COMPARISON)
		return 1;
	if (!get_implied_rl(left, &rl_left))
		return 1;
	if (!get_implied_rl(right, &rl_right))
		return 1;

	type = rl_type(rl_left);
	if (type_positive_bits(type) < type_positive_bits(rl_type(rl_right)))
		type = rl_type(rl_right);
	if (type_positive_bits(type) < 31)
		type = &int_ctype;

	rl_left = cast_rl(type, rl_left);
	rl_right = cast_rl(type, rl_right);

	FOR_EACH_PTR(rl_left, tmp_left) {
		FOR_EACH_PTR(rl_right, tmp_right) {
			if (true_comparison_range(tmp_left, comparison, tmp_right))
				return 1;
		} END_FOR_EACH_PTR(tmp_right);
	} END_FOR_EACH_PTR(tmp_left);
	return 0;
}

int possibly_false(struct expression *left, int comparison, struct expression *right)
{
	struct range_list *rl_left, *rl_right;
	struct data_range *tmp_left, *tmp_right;
	struct symbol *type;

	if (!get_implied_rl(left, &rl_left))
		return 1;
	if (!get_implied_rl(right, &rl_right))
		return 1;

	type = rl_type(rl_left);
	if (type_positive_bits(type) < type_positive_bits(rl_type(rl_right)))
		type = rl_type(rl_right);
	if (type_positive_bits(type) < 31)
		type = &int_ctype;

	rl_left = cast_rl(type, rl_left);
	rl_right = cast_rl(type, rl_right);

	FOR_EACH_PTR(rl_left, tmp_left) {
		FOR_EACH_PTR(rl_right, tmp_right) {
			if (false_comparison_range_sval(tmp_left, comparison, tmp_right))
				return 1;
		} END_FOR_EACH_PTR(tmp_right);
	} END_FOR_EACH_PTR(tmp_left);
	return 0;
}

int possibly_true_rl(struct range_list *left_ranges, int comparison, struct range_list *right_ranges)
{
	struct data_range *left_tmp, *right_tmp;
	struct symbol *type;

	if (!left_ranges || !right_ranges || comparison == UNKNOWN_COMPARISON)
		return 1;

	type = rl_type(left_ranges);
	if (type_positive_bits(type) < type_positive_bits(rl_type(right_ranges)))
		type = rl_type(right_ranges);
	if (type_positive_bits(type) < 31)
		type = &int_ctype;

	left_ranges = cast_rl(type, left_ranges);
	right_ranges = cast_rl(type, right_ranges);

	FOR_EACH_PTR(left_ranges, left_tmp) {
		FOR_EACH_PTR(right_ranges, right_tmp) {
			if (true_comparison_range(left_tmp, comparison, right_tmp))
				return 1;
		} END_FOR_EACH_PTR(right_tmp);
	} END_FOR_EACH_PTR(left_tmp);
	return 0;
}

int possibly_false_rl(struct range_list *left_ranges, int comparison, struct range_list *right_ranges)
{
	struct data_range *left_tmp, *right_tmp;
	struct symbol *type;

	if (!left_ranges || !right_ranges || comparison == UNKNOWN_COMPARISON)
		return 1;

	type = rl_type(left_ranges);
	if (type_positive_bits(type) < type_positive_bits(rl_type(right_ranges)))
		type = rl_type(right_ranges);
	if (type_positive_bits(type) < 31)
		type = &int_ctype;

	left_ranges = cast_rl(type, left_ranges);
	right_ranges = cast_rl(type, right_ranges);

	FOR_EACH_PTR(left_ranges, left_tmp) {
		FOR_EACH_PTR(right_ranges, right_tmp) {
			if (false_comparison_range_sval(left_tmp, comparison, right_tmp))
				return 1;
		} END_FOR_EACH_PTR(right_tmp);
	} END_FOR_EACH_PTR(left_tmp);
	return 0;
}

/* FIXME: the _rl here stands for right left so really it should be _lr */
int possibly_true_rl_LR(int comparison, struct range_list *a, struct range_list *b, int left)
{
	if (left)
		return possibly_true_rl(a, comparison, b);
	else
		return possibly_true_rl(b, comparison, a);
}

int possibly_false_rl_LR(int comparison, struct range_list *a, struct range_list *b, int left)
{
	if (left)
		return possibly_false_rl(a, comparison, b);
	else
		return possibly_false_rl(b, comparison, a);
}

int rl_has_sval(struct range_list *rl, sval_t sval)
{
	struct data_range *tmp;

	FOR_EACH_PTR(rl, tmp) {
		if (sval_cmp(tmp->min, sval) <= 0 &&
		    sval_cmp(tmp->max, sval) >= 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);
	return 0;
}

void tack_on(struct range_list **list, struct data_range *drange)
{
	add_ptr_list(list, drange);
}

void push_rl(struct range_list_stack **rl_stack, struct range_list *rl)
{
	add_ptr_list(rl_stack, rl);
}

struct range_list *pop_rl(struct range_list_stack **rl_stack)
{
	struct range_list *rl;

	rl = last_ptr_list((struct ptr_list *)*rl_stack);
	delete_ptr_list_last((struct ptr_list **)rl_stack);
	return rl;
}

struct range_list *top_rl(struct range_list_stack *rl_stack)
{
	struct range_list *rl;

	rl = last_ptr_list((struct ptr_list *)rl_stack);
	return rl;
}

void filter_top_rl(struct range_list_stack **rl_stack, struct range_list *filter)
{
	struct range_list *rl;

	rl = pop_rl(rl_stack);
	rl = rl_filter(rl, filter);
	push_rl(rl_stack, rl);
}

struct range_list *rl_truncate_cast(struct symbol *type, struct range_list *rl)
{
	struct data_range *tmp;
	struct range_list *ret = NULL;
	sval_t min, max;

	if (!rl)
		return NULL;

	if (!type || type == rl_type(rl))
		return rl;

	FOR_EACH_PTR(rl, tmp) {
		min = tmp->min;
		max = tmp->max;
		if (type_bits(type) < type_bits(rl_type(rl))) {
			min.uvalue = tmp->min.uvalue & ((1ULL << type_bits(type)) - 1);
			max.uvalue = tmp->max.uvalue & ((1ULL << type_bits(type)) - 1);
		}
		if (sval_cmp(min, max) > 0) {
			min = sval_cast(type, min);
			max = sval_cast(type, max);
		}
		add_range_t(type, &ret, min, max);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

int rl_fits_in_type(struct range_list *rl, struct symbol *type)
{
	if (type_bits(rl_type(rl)) <= type_bits(type))
		return 1;
	if (sval_cmp(rl_max(rl), sval_type_max(type)) > 0)
		return 0;
	if (sval_is_negative(rl_min(rl)) &&
	    sval_cmp(rl_min(rl), sval_type_min(type)) < 0)
		return 0;
	return 1;
}

static int rl_type_consistent(struct range_list *rl)
{
	struct data_range *tmp;
	struct symbol *type;

	type = rl_type(rl);
	FOR_EACH_PTR(rl, tmp) {
		if (type != tmp->min.type || type != tmp->max.type)
			return 0;
	} END_FOR_EACH_PTR(tmp);
	return 1;
}

static struct range_list *cast_to_bool(struct range_list *rl)
{
	struct data_range *tmp;
	struct range_list *ret = NULL;
	int has_one = 0;
	int has_zero = 0;
	sval_t min = { .type = &bool_ctype };
	sval_t max = { .type = &bool_ctype };

	FOR_EACH_PTR(rl, tmp) {
		if (tmp->min.value || tmp->max.value)
			has_one = 1;
		if (sval_is_negative(tmp->min) &&
		    sval_is_negative(tmp->max))
			continue;
		if (tmp->min.value == 0 ||
		    tmp->max.value == 0)
			has_zero = 1;
		if (sval_is_negative(tmp->min) &&
		    tmp->max.value > 0)
			has_zero = 1;
	} END_FOR_EACH_PTR(tmp);

	if (!has_zero)
		min.value = 1;
	if (has_one)
		max.value = 1;

	add_range(&ret, min, max);
	return ret;
}

struct range_list *cast_rl(struct symbol *type, struct range_list *rl)
{
	struct data_range *tmp;
	struct range_list *ret = NULL;

	if (!rl)
		return NULL;

	if (!type)
		return rl;
	if (!rl_is_sane(rl))
		return alloc_whole_rl(type);
	if (type == rl_type(rl) && rl_type_consistent(rl))
		return rl;

	if (type == &bool_ctype)
		return cast_to_bool(rl);

	FOR_EACH_PTR(rl, tmp) {
		add_range_t(type, &ret, tmp->min, tmp->max);
	} END_FOR_EACH_PTR(tmp);

	if (!ret)
		return alloc_whole_rl(type);

	return ret;
}

struct range_list *rl_filter(struct range_list *rl, struct range_list *filter)
{
	struct data_range *tmp;

	FOR_EACH_PTR(filter, tmp) {
		rl = remove_range(rl, tmp->min, tmp->max);
	} END_FOR_EACH_PTR(tmp);

	return rl;
}

struct range_list *do_intersection(struct range_list *one_rl, struct range_list *two_rl)
{
	struct data_range *one, *two;
	struct range_list *ret = NULL;


	PREPARE_PTR_LIST(one_rl, one);
	PREPARE_PTR_LIST(two_rl, two);

	while (true) {
		if (!one || !two)
			break;
		if (sval_cmp(one->max, two->min) < 0) {
			NEXT_PTR_LIST(one);
			continue;
		}
		if (sval_cmp(one->min, two->min) < 0 && sval_cmp(one->max, two->max) <= 0) {
			add_range(&ret, two->min, one->max);
			NEXT_PTR_LIST(one);
			continue;
		}
		if (sval_cmp(one->min, two->min) >= 0 && sval_cmp(one->max, two->max) <= 0) {
			add_range(&ret, one->min, one->max);
			NEXT_PTR_LIST(one);
			continue;
		}
		if (sval_cmp(one->min, two->min) < 0 && sval_cmp(one->max, two->max) > 0) {
			add_range(&ret, two->min, two->max);
			NEXT_PTR_LIST(two);
			continue;
		}
		if (sval_cmp(one->min, two->max) <= 0 && sval_cmp(one->max, two->max) > 0) {
			add_range(&ret, one->min, two->max);
			NEXT_PTR_LIST(two);
			continue;
		}
		if (sval_cmp(one->min, two->max) <= 0) {
			sm_fatal("error calculating intersection of '%s' and '%s'", show_rl(one_rl), show_rl(two_rl));
			return NULL;
		}
		NEXT_PTR_LIST(two);
	}

	FINISH_PTR_LIST(two);
	FINISH_PTR_LIST(one);

	return ret;
}

struct range_list *rl_intersection(struct range_list *one, struct range_list *two)
{
	struct range_list *ret;
	struct symbol *ret_type;
	struct symbol *small_type;
	struct symbol *large_type;

	if (!one || !two)
		return NULL;

	ret_type = rl_type(one);
	small_type = rl_type(one);
	large_type = rl_type(two);

	if (type_bits(rl_type(two)) < type_bits(small_type)) {
		small_type = rl_type(two);
		large_type = rl_type(one);
	}

	one = cast_rl(large_type, one);
	two = cast_rl(large_type, two);

	ret = do_intersection(one, two);
	return cast_rl(ret_type, ret);
}

static struct range_list *handle_mod_rl(struct range_list *left, struct range_list *right)
{
	sval_t zero;
	sval_t max;

	max = rl_max(right);
	if (sval_is_max(max))
		return left;
	if (max.value == 0)
		return NULL;
	max.value--;
	if (sval_is_negative(max))
		return NULL;
	if (sval_cmp(rl_max(left), max) < 0)
		return left;
	zero = max;
	zero.value = 0;
	return alloc_rl(zero, max);
}

static struct range_list *get_neg_rl(struct range_list *rl)
{
	struct data_range *tmp;
	struct data_range *new;
	struct range_list *ret = NULL;

	if (!rl)
		return NULL;
	if (sval_is_positive(rl_min(rl)))
		return NULL;

	FOR_EACH_PTR(rl, tmp) {
		if (sval_is_positive(tmp->min))
			break;
		if (sval_is_positive(tmp->max)) {
			new = alloc_range(tmp->min, tmp->max);
			new->max.value = -1;
			add_range(&ret, new->min, new->max);
			break;
		}
		add_range(&ret, tmp->min, tmp->max);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

static struct range_list *get_pos_rl(struct range_list *rl)
{
	struct data_range *tmp;
	struct data_range *new;
	struct range_list *ret = NULL;

	if (!rl)
		return NULL;
	if (sval_is_negative(rl_max(rl)))
		return NULL;

	FOR_EACH_PTR(rl, tmp) {
		if (sval_is_negative(tmp->max))
			continue;
		if (sval_is_positive(tmp->min)) {
			add_range(&ret, tmp->min, tmp->max);
			continue;
		}
		new = alloc_range(tmp->min, tmp->max);
		new->min.value = 0;
		add_range(&ret, new->min, new->max);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

static struct range_list *divide_rl_helper(struct range_list *left, struct range_list *right)
{
	sval_t right_min, right_max;
	sval_t min, max;

	if (!left || !right)
		return NULL;

	/* let's assume we never divide by zero */
	right_min = rl_min(right);
	right_max = rl_max(right);
	if (right_min.value == 0 && right_max.value == 0)
		return NULL;
	if (right_min.value == 0)
		right_min.value = 1;
	if (right_max.value == 0)
		right_max.value = -1;

	max = sval_binop(rl_max(left), '/', right_min);
	min = sval_binop(rl_min(left), '/', right_max);

	return alloc_rl(min, max);
}

static struct range_list *handle_divide_rl(struct range_list *left, struct range_list *right)
{
	struct range_list *left_neg, *left_pos, *right_neg, *right_pos;
	struct range_list *neg_neg, *neg_pos, *pos_neg, *pos_pos;
	struct range_list *ret;

	if (is_whole_rl(right))
		return NULL;

	left_neg = get_neg_rl(left);
	left_pos = get_pos_rl(left);
	right_neg = get_neg_rl(right);
	right_pos = get_pos_rl(right);

	neg_neg = divide_rl_helper(left_neg, right_neg);
	neg_pos = divide_rl_helper(left_neg, right_pos);
	pos_neg = divide_rl_helper(left_pos, right_neg);
	pos_pos = divide_rl_helper(left_pos, right_pos);

	ret = rl_union(neg_neg, neg_pos);
	ret = rl_union(ret, pos_neg);
	return rl_union(ret, pos_pos);
}

static struct range_list *ptr_add_mult(struct range_list *left, int op, struct range_list *right)
{
	struct range_list *ret;
	sval_t l_sval, r_sval, res;

	/*
	 * This function is sort of the wrong API because it takes two pointer
	 * and adds them together.  The caller is expected to figure out
	 * alignment.  Neither of those are the correct things to do.
	 *
	 * Really this function is quite bogus...
	 */

	if (rl_to_sval(left, &l_sval) && rl_to_sval(right, &r_sval)) {
		res = sval_binop(l_sval, op, r_sval);
		return alloc_rl(res, res);
	}

	if (rl_min(left).value != 0 || rl_max(right).value != 0) {
		ret = alloc_rl(valid_ptr_min_sval, valid_ptr_max_sval);
		return cast_rl(rl_type(left), ret);
	}

	return alloc_whole_rl(rl_type(left));
}

static struct range_list *handle_add_mult_rl(struct range_list *left, int op, struct range_list *right)
{
	sval_t min, max;

	if (type_is_ptr(rl_type(left)) || type_is_ptr(rl_type(right)))
		return ptr_add_mult(left, op, right);

	if (sval_binop_overflows(rl_min(left), op, rl_min(right)))
		return NULL;
	min = sval_binop(rl_min(left), op, rl_min(right));

	if (sval_binop_overflows(rl_max(left), op, rl_max(right)))
		return NULL;
	max = sval_binop(rl_max(left), op, rl_max(right));

	return alloc_rl(min, max);
}

static struct range_list *handle_sub_rl(struct range_list *left_orig, struct range_list *right_orig)
{
	struct range_list *left_rl, *right_rl;
	struct symbol *type;
	sval_t min, max;
	sval_t min_ll, max_ll, res_ll;
	sval_t tmp;

	/* TODO:  These things should totally be using dranges where possible */

	if (!left_orig || !right_orig)
		return NULL;

	type = &int_ctype;
	if (type_positive_bits(rl_type(left_orig)) > type_positive_bits(type))
		type = rl_type(left_orig);
	if (type_positive_bits(rl_type(right_orig)) > type_positive_bits(type))
		type = rl_type(right_orig);

	left_rl = cast_rl(type, left_orig);
	right_rl = cast_rl(type, right_orig);

	max = rl_max(left_rl);
	min = sval_type_min(type);

	min_ll = rl_min(left_rl);
	min_ll.type = &llong_ctype;
	max_ll = rl_max(right_rl);
	max_ll.type = &llong_ctype;
	res_ll = min_ll;
	res_ll.value = min_ll.value - max_ll.value;

	if (!sval_binop_overflows(rl_min(left_rl), '-', rl_max(right_rl))) {
		tmp = sval_binop(rl_min(left_rl), '-', rl_max(right_rl));
		if (sval_cmp(tmp, min) > 0)
			min = tmp;
	} else if (type_positive_bits(type) < 63 &&
		   !sval_binop_overflows(min_ll, '-', max_ll) &&
		   (min.value != 0 && sval_cmp(res_ll, min) >= 0)) {
		struct range_list *left_casted, *right_casted, *result;

		left_casted = cast_rl(&llong_ctype, left_orig);
		right_casted = cast_rl(&llong_ctype, right_orig);
		result = handle_sub_rl(left_casted, right_casted);
		return cast_rl(type, result);
	}

	if (!sval_is_max(rl_max(left_rl))) {
		tmp = sval_binop(rl_max(left_rl), '-', rl_min(right_rl));
		if (sval_cmp(tmp, max) < 0)
			max = tmp;
	}

	if (sval_is_min(min) && sval_is_max(max))
		return NULL;

	return alloc_rl(min, max);
}

static unsigned long long rl_bits_always_set(struct range_list *rl)
{
	return sval_fls_mask(rl_min(rl));
}

static unsigned long long rl_bits_maybe_set(struct range_list *rl)
{
	return sval_fls_mask(rl_max(rl));
}

static struct range_list *handle_OR_rl(struct range_list *left, struct range_list *right)
{
	unsigned long long left_min, left_max, right_min, right_max;
	sval_t min, max;
	sval_t sval;

	if ((rl_to_sval(left, &sval) || rl_to_sval(right, &sval)) &&
	    !sval_binop_overflows(rl_max(left), '+', rl_max(right)))
		return rl_binop(left, '+', right);

	left_min = rl_bits_always_set(left);
	left_max = rl_bits_maybe_set(left);
	right_min = rl_bits_always_set(right);
	right_max = rl_bits_maybe_set(right);

	min.type = max.type = &ullong_ctype;
	min.uvalue = left_min | right_min;
	max.uvalue = left_max | right_max;

	return cast_rl(rl_type(left), alloc_rl(min, max));
}

static struct range_list *handle_XOR_rl(struct range_list *left, struct range_list *right)
{
	unsigned long long left_set, left_maybe;
	unsigned long long right_set, right_maybe;
	sval_t zero, max;

	left_set = rl_bits_always_set(left);
	left_maybe = rl_bits_maybe_set(left);

	right_set = rl_bits_always_set(right);
	right_maybe = rl_bits_maybe_set(right);

	zero = max = rl_min(left);
	zero.uvalue = 0;
	max.uvalue = fls_mask((left_maybe | right_maybe) ^ (left_set & right_set));

	return cast_rl(rl_type(left), alloc_rl(zero, max));
}

static sval_t sval_lowest_set_bit(sval_t sval)
{
	sval_t ret = { .type = sval.type };
	int i;

	for (i = 0; i < 64; i++) {
		if (sval.uvalue & 1ULL << i) {
			ret.uvalue = (1ULL << i);
			return ret;
		}
	}
	return ret;
}

static struct range_list *handle_AND_rl(struct range_list *left, struct range_list *right)
{
	struct bit_info *one, *two;
	struct range_list *rl;
	sval_t min, max, zero;
	unsigned long long bits;

	one = rl_to_binfo(left);
	two = rl_to_binfo(right);
	bits = one->possible & two->possible;

	max = rl_max(left);
	max.uvalue = bits;
	min = sval_lowest_set_bit(max);

	rl = alloc_rl(min, max);

	zero = rl_min(rl);
	zero.value = 0;
	add_range(&rl, zero, zero);

	return rl;
}

static struct range_list *handle_lshift(struct range_list *left_orig, struct range_list *right_orig)
{
	struct range_list *left;
	struct data_range *tmp;
	struct range_list *ret = NULL;
	sval_t zero = { .type = rl_type(left_orig), };
	sval_t shift, min, max;
	bool add_zero = false;

	if (!rl_to_sval(right_orig, &shift) || sval_is_negative(shift))
		return NULL;
	if (shift.value == 0)
		return left_orig;

	/* Cast to unsigned for easier left shift math */
	if (type_positive_bits(rl_type(left_orig)) < 32)
		left = cast_rl(&uint_ctype, left_orig);
	else if(type_positive_bits(rl_type(left_orig)) == 63)
		left = cast_rl(&ullong_ctype, left_orig);
	else
		left = left_orig;

	FOR_EACH_PTR(left, tmp) {
		min = tmp->min;
		max = tmp->max;

		if (min.value == 0 || max.value > sval_type_max(max.type).uvalue >> shift.uvalue)
			add_zero = true;
		if (min.value == 0 && max.value == 0)
			continue;
		if (min.value == 0)
			min.value = 1;
		min = sval_binop(min, SPECIAL_LEFTSHIFT, shift);
		max = sval_binop(max, SPECIAL_LEFTSHIFT, shift);
		add_range(&ret, min, max);
	} END_FOR_EACH_PTR(tmp);

	if (!rl_fits_in_type(ret, rl_type(left_orig)))
		add_zero = true;
	ret = cast_rl(rl_type(left_orig), ret);
	if (add_zero)
		add_range(&ret, zero, zero);

	return ret;
}

static struct range_list *handle_rshift(struct range_list *left_orig, struct range_list *right_orig)
{
	struct data_range *tmp;
	struct range_list *ret = NULL;
	sval_t shift, min, max;

	if (!rl_to_sval(right_orig, &shift) || sval_is_negative(shift))
		return NULL;
	if (shift.value == 0)
		return left_orig;

	FOR_EACH_PTR(left_orig, tmp) {
		min = sval_binop(tmp->min, SPECIAL_RIGHTSHIFT, shift);
		max = sval_binop(tmp->max, SPECIAL_RIGHTSHIFT, shift);
		add_range(&ret, min, max);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

struct range_list *rl_binop(struct range_list *left, int op, struct range_list *right)
{
	struct symbol *cast_type;
	sval_t left_sval, right_sval;
	struct range_list *ret = NULL;

	cast_type = rl_type(left);
	if (sval_type_max(rl_type(left)).uvalue < sval_type_max(rl_type(right)).uvalue)
		cast_type = rl_type(right);
	if (sval_type_max(cast_type).uvalue < INT_MAX)
		cast_type = &int_ctype;

	left = cast_rl(cast_type, left);
	right = cast_rl(cast_type, right);

	if (!left && !right)
		return NULL;

	if (rl_to_sval(left, &left_sval) && rl_to_sval(right, &right_sval)) {
		sval_t val = sval_binop(left_sval, op, right_sval);
		return alloc_rl(val, val);
	}

	switch (op) {
	case '%':
		ret = handle_mod_rl(left, right);
		break;
	case '/':
		ret = handle_divide_rl(left, right);
		break;
	case '*':
	case '+':
		ret = handle_add_mult_rl(left, op, right);
		break;
	case '|':
		ret = handle_OR_rl(left, right);
		break;
	case '^':
		ret = handle_XOR_rl(left, right);
		break;
	case '&':
		ret = handle_AND_rl(left, right);
		break;
	case '-':
		ret = handle_sub_rl(left, right);
		break;
	case SPECIAL_RIGHTSHIFT:
		return handle_rshift(left, right);
	case SPECIAL_LEFTSHIFT:
		return handle_lshift(left, right);
	}

	return ret;
}

void free_data_info_allocs(void)
{
	struct allocator_struct *desc = &data_info_allocator;
	struct allocation_blob *blob = desc->blobs;

	free_all_rl();
	clear_math_cache();

	desc->blobs = NULL;
	desc->allocations = 0;
	desc->total_bytes = 0;
	desc->useful_bytes = 0;
	desc->freelist = NULL;
	while (blob) {
		struct allocation_blob *next = blob->next;
		blob_free(blob, desc->chunking);
		blob = next;
	}
	clear_data_range_alloc();
}

void split_comparison_rl(struct range_list *left_orig, int op, struct range_list *right_orig,
		struct range_list **left_true_rl, struct range_list **left_false_rl,
		struct range_list **right_true_rl, struct range_list **right_false_rl)
{
	struct range_list *left_true, *left_false;
	struct range_list *right_true, *right_false;
	sval_t min, max;

	min = sval_type_min(rl_type(left_orig));
	max = sval_type_max(rl_type(left_orig));

	left_true = clone_rl(left_orig);
	left_false = clone_rl(left_orig);
	right_true = clone_rl(right_orig);
	right_false = clone_rl(right_orig);

	switch (op) {
	case '<':
	case SPECIAL_UNSIGNED_LT:
		left_true = remove_range(left_orig, rl_max(right_orig), max);
		if (!sval_is_min(rl_min(right_orig))) {
			left_false = remove_range(left_orig, min, sub_one(rl_min(right_orig)));
		}

		right_true = remove_range(right_orig, min, rl_min(left_orig));
		if (!sval_is_max(rl_max(left_orig)))
			right_false = remove_range(right_orig, add_one(rl_max(left_orig)), max);
		break;
	case SPECIAL_UNSIGNED_LTE:
	case SPECIAL_LTE:
		if (!sval_is_max(rl_max(right_orig)))
			left_true = remove_range(left_orig, add_one(rl_max(right_orig)), max);
		left_false = remove_range(left_orig, min, rl_min(right_orig));

		if (!sval_is_min(rl_min(left_orig)))
			right_true = remove_range(right_orig, min, sub_one(rl_min(left_orig)));
		right_false = remove_range(right_orig, rl_max(left_orig), max);

		if (sval_cmp(rl_min(left_orig), rl_min(right_orig)) == 0)
			left_false = remove_range(left_false, rl_min(left_orig), rl_min(left_orig));
		if (sval_cmp(rl_max(left_orig), rl_max(right_orig)) == 0)
			right_false = remove_range(right_false, rl_max(left_orig), rl_max(left_orig));
		break;
	case SPECIAL_EQUAL:
		left_true = rl_intersection(left_orig, right_orig);
		right_true = clone_rl(left_true);

		if (sval_cmp(rl_min(right_orig), rl_max(right_orig)) == 0)
			left_false = remove_range(left_orig, rl_min(right_orig), rl_min(right_orig));
		if (sval_cmp(rl_min(left_orig), rl_max(left_orig)) == 0)
			right_false = remove_range(right_orig, rl_min(left_orig), rl_min(left_orig));
		break;
	case SPECIAL_UNSIGNED_GTE:
	case SPECIAL_GTE:
		if (!sval_is_min(rl_min(right_orig)))
			left_true = remove_range(left_orig, min, sub_one(rl_min(right_orig)));
		left_false = remove_range(left_orig, rl_max(right_orig), max);

		if (!sval_is_max(rl_max(left_orig)))
			right_true = remove_range(right_orig, add_one(rl_max(left_orig)), max);
		right_false = remove_range(right_orig, min, rl_min(left_orig));

		if (sval_cmp(rl_min(left_orig), rl_min(right_orig)) == 0)
			right_false = remove_range(right_false, rl_min(left_orig), rl_min(left_orig));
		if (sval_cmp(rl_max(left_orig), rl_max(right_orig)) == 0)
			left_false = remove_range(left_false, rl_max(left_orig), rl_max(left_orig));
		break;
	case '>':
	case SPECIAL_UNSIGNED_GT:
		left_true = remove_range(left_orig, min, rl_min(right_orig));
		if (!sval_is_max(rl_max(right_orig)))
			left_false = remove_range(left_orig, add_one(rl_max(right_orig)), max);

		right_true = remove_range(right_orig, rl_max(left_orig), max);
		if (!sval_is_min(rl_min(left_orig)))
			right_false = remove_range(right_orig, min, sub_one(rl_min(left_orig)));
		break;
	case SPECIAL_NOTEQUAL:
		left_false = rl_intersection(left_orig, right_orig);
		right_false = clone_rl(left_false);

		if (sval_cmp(rl_min(right_orig), rl_max(right_orig)) == 0)
			left_true = remove_range(left_orig, rl_min(right_orig), rl_min(right_orig));
		if (sval_cmp(rl_min(left_orig), rl_max(left_orig)) == 0)
			right_true = remove_range(right_orig, rl_min(left_orig), rl_min(left_orig));
		break;
	default:
		sm_perror(" unhandled comparison %d", op);
	}

	if (left_true_rl) {
		*left_true_rl = left_true;
		*left_false_rl = left_false;
	}
	if (right_true_rl) {
		*right_true_rl = right_true;
		*right_false_rl = right_false;
	}
}
